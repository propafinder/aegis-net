//! Installed-service recovery adapter. This is not called by the native probe.
//! Never kills a process, deletes an interface, or adopts a tuple from kernel
//! output. Any uncertain owner remains blocked with its journal retained.
use super::{build_source_stamp, command, ensure, json, OperationBudget};
use crate::relay_geneva::{
    installed_guard::{verify_observation, PublicGuardPolicy, TABLE as GUARD_TABLE},
    linux_policy,
    recovery::{reconstruct, RecoveryPlan, RecoveryTrust},
    RelayOuterGenevaSettings,
};
use serde_json::{json as value, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    net::SocketAddrV4,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const ROOT: &str = "/run/aegis-relay-geneva";
#[path = "teardown_linux.rs"]
pub mod teardown;
fn bounded(path: &Path, max: usize, private: bool) -> io::Result<Vec<u8>> {
    super::operation_live()?;
    let before = std::fs::symlink_metadata(path)?;
    ensure(
        before.is_file()
            && !before.file_type().is_symlink()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o022 == 0
            && (!private || before.mode() & 0o777 == 0o600)
            && before.len() <= max as u64,
        "untrusted recovery input",
    )?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let opened = file.metadata()?;
    ensure(
        opened.ino() == before.ino() && opened.dev() == before.dev(),
        "recovery file replacement",
    )?;
    let mut bytes = Vec::new();
    file.take(max as u64 + 1).read_to_end(&mut bytes)?;
    ensure(bytes.len() <= max, "recovery input bound")?;
    Ok(bytes)
}
fn directory(path: &Path, private: bool) -> io::Result<(u64, u64)> {
    super::operation_live()?;
    let st = std::fs::symlink_metadata(path)?;
    ensure(
        st.is_dir()
            && !st.file_type().is_symlink()
            && st.uid() == 0
            && st.mode() & 0o022 == 0
            && (!private || st.mode() & 0o777 == 0o700),
        "untrusted recovery directory",
    )?;
    Ok((st.dev(), st.ino()))
}
fn records(path: &Path, identity: (u64, u64)) -> io::Result<Vec<(String, Vec<u8>)>> {
    ensure(
        directory(path, true)? == identity,
        "recovery journal directory drift",
    )?;
    let mut rows = Vec::new();
    let mut total = 0usize;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| io::Error::other("journal name refused"))?;
        ensure(rows.len() < 8200, "journal record count exceeded")?;
        let data = bounded(&entry.path(), 65536, true)?;
        total = total
            .checked_add(data.len())
            .ok_or_else(|| io::Error::other("journal size overflow"))?;
        ensure(total <= 18 * 1048576, "journal total bound exceeded")?;
        rows.push((name, data));
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    ensure(
        directory(path, true)? == identity,
        "recovery journal changed",
    )?;
    Ok(rows)
}
fn current_namespace() -> io::Result<(u64, u64)> {
    let namespace = File::open("/proc/self/ns/net")?.metadata()?;
    Ok((namespace.dev(), namespace.ino()))
}
fn current_boot() -> io::Result<String> {
    Ok(std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .into())
}
fn old_process_absent(plan: &RecoveryPlan) -> io::Result<()> {
    let path = PathBuf::from(format!("/proc/{}/stat", plan.intent.process_identity.pid));
    match std::fs::read_to_string(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
        Ok(stat) => {
            // Parenthesized comm may itself contain spaces or parentheses.
            let after = stat
                .rsplit_once(')')
                .map(|(_, s)| s)
                .ok_or_else(|| io::Error::other("process stat refused"))?;
            let ticks = after
                .split_whitespace()
                .nth(19)
                .and_then(|s| s.parse::<u64>().ok())
                .ok_or_else(|| io::Error::other("process start ticks refused"))?;
            ensure(
                ticks != plan.intent.process_identity.start_ticks,
                "original native owner is still alive",
            )
        }
    }
}
fn inode_inventory() -> io::Result<BTreeSet<u64>> {
    let mut inodes = BTreeSet::new();
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        // Proc files report st_size=0; enforce the actual read limit.
        let file = File::open(path)?;
        let mut bytes = Vec::new();
        file.take(1048577).read_to_end(&mut bytes)?;
        ensure(bytes.len() <= 1048576, "socket inventory bound")?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| io::Error::other("socket inventory encoding"))?;
        for line in text.lines().skip(1) {
            let cols = line.split_whitespace().collect::<Vec<_>>();
            ensure(cols.len() >= 10, "socket inventory row refused")?;
            let inode = cols[9]
                .parse::<u64>()
                .map_err(|_| io::Error::other("socket inode refused"))?;
            if inode != 0 {
                inodes.insert(inode);
            }
        }
    }
    Ok(inodes)
}
fn owner_quiet(plan: &RecoveryPlan) -> io::Result<()> {
    old_process_absent(plan)?;
    ensure(
        plan.socket_inodes.is_disjoint(&inode_inventory()?),
        "a recorded socket inode still exists",
    )?;
    match std::fs::symlink_metadata(format!("/sys/class/net/{}", plan.intent.tun)) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "recorded TUN remains; recovery refuses interface deletion",
        )),
    }
}
fn table_present(ruleset: &Value, name: &str) -> io::Result<bool> {
    let rows = ruleset
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or_else(|| io::Error::other("table inventory refused"))?;
    ensure(rows.len() <= 65536, "table inventory bound")?;
    let mut found = 0;
    for row in rows {
        if let Some(table) = row.get("table") {
            if table.get("name").and_then(Value::as_str) == Some(name) {
                ensure(
                    table.get("family").and_then(Value::as_str) == Some("ip"),
                    "journal table name used by different family",
                )?;
                found += 1;
            }
        }
    }
    ensure(found <= 1, "duplicate owned table inventory")?;
    Ok(found == 1)
}
fn observed_owned_table(
    plan: &RecoveryPlan,
    request: &RelayOuterGenevaSettings,
) -> io::Result<Option<Value>> {
    let tables = json("nft", &["-j", "-n", "-y", "-p", "list", "tables"])?;
    if !table_present(&tables, &plan.intent.table)? {
        return Ok(None);
    }
    ensure(
        !plan.terminal_quiesced_recorded,
        "terminal journal contradicts residual kernel table",
    )?;
    let actual = json(
        "nft",
        &[
            "-j",
            "-n",
            "-y",
            "-p",
            "list",
            "table",
            "ip",
            &plan.intent.table,
        ],
    )?;
    let observed = linux_policy::observed_flows(&actual)?;
    for flow in &observed {
        ensure(
            plan.unresolved_flows.contains(flow),
            "kernel tuple has no unresolved prior arm intent",
        )?;
    }
    linux_policy::validate(
        &actual,
        &plan.intent.table,
        &plan.intent.tun,
        request,
        &observed,
    )?;
    Ok(Some(actual))
}
fn write_receipt(plan: &RecoveryPlan, removed: bool) -> io::Result<Value> {
    let path = Path::new(ROOT).join("recovery-receipts");
    match std::fs::DirBuilder::new().mode(0o700).create(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    directory(&path, true)?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| io::Error::other("receipt clock refused"))?
        .as_nanos();
    let row = value!({"schema":"aegis_relay_geneva_owned_recovery_v1","instance":plan.intent.instance,"source_commit":plan.intent.source_stamp,"journal_sha256":hex::encode(plan.journal_sha256),"status":"PASS_OWNED_RECOVERY_ONLY","old_process_absent":true,"all_recorded_socket_inodes_absent":true,"recorded_tun_absent":true,"owned_table_absent":true,"removed_exact_table":removed,"kernel_installed_guard_acceptance":false});
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path.join(format!("{}-{stamp}.json", plan.intent.instance)))?;
    file.write_all(&serde_json::to_vec(&row)?)?;
    file.sync_all()?;
    File::open(path)?.sync_all()?;
    Ok(row)
}
/// Exact selected table observation, never a prefix/table-family exemption.
pub fn observe_installed_guard() -> io::Result<Option<Value>> {
    let _budget = OperationBudget::until(Instant::now() + Duration::from_secs(3));
    let tables = json("nft", &["-j", "-n", "-y", "-p", "list", "tables"])?;
    if !crate::relay_geneva::installed_guard::selected_table_present(&tables)? {
        Ok(None)
    } else {
        json(
            "nft",
            &[
                "-j",
                "-n",
                "-y",
                "-p",
                "list",
                "table",
                "netdev",
                GUARD_TABLE,
            ],
        )
        .map(Some)
    }
}
fn blocked_guard(
    policy: &PublicGuardPolicy,
    request: &RelayOuterGenevaSettings,
    endpoints: &[SocketAddrV4],
) -> io::Result<()> {
    let actual = observe_installed_guard()?
        .ok_or_else(|| io::Error::other("selected egress block missing"))?;
    verify_observation(
        &actual,
        policy,
        None,
        build_source_stamp()?,
        request,
        endpoints,
    )?;
    Ok(())
}
/// Must run inside the selected service cgroup before any new native worker.
/// The caller keeps the existing persistent guard blocked throughout recovery.
pub fn recover(
    request: &RelayOuterGenevaSettings,
    endpoints: &[SocketAddrV4],
    policy: &PublicGuardPolicy,
) -> io::Result<Vec<Value>> {
    ensure(
        unsafe { libc::geteuid() } == 0,
        "installed recovery requires root",
    )?;
    let _budget = OperationBudget::until(Instant::now() + Duration::from_secs(10));
    blocked_guard(policy, request, endpoints)?;
    // The existing device helper uses the same lock for every v2 transaction.
    // Administrative pre-start recovery must never race a bind/block operation.
    let lock_path = Path::new("/var/lib/aegis-install/client/device-guard.conf.lock");
    for parent in lock_path.ancestors().skip(1) {
        directory(parent, false)?;
    }
    let lock = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(lock_path)?;
    let metadata = lock.metadata()?;
    ensure(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.nlink() == 1
            && metadata.mode() & 0o777 == 0o600,
        "recovery administrative lock refused",
    )?;
    use std::os::fd::AsRawFd;
    let lock_deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            break;
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EWOULDBLOCK) {
            return Err(error);
        }
        ensure(
            Instant::now() < lock_deadline,
            "recovery administrative lock deadline",
        )?;
        std::thread::sleep(Duration::from_millis(5));
    }
    directory(Path::new("/run"), false)?;
    match std::fs::symlink_metadata(ROOT) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
        Ok(_) => {}
    }
    let root_identity = directory(Path::new(ROOT), true)?;
    let ns = current_namespace()?;
    let boot = current_boot()?;
    let cgroup = std::fs::read_to_string("/proc/self/cgroup")?;
    ensure(
        cgroup.trim() == "0::/system.slice/aegis-client.service",
        "recovery must execute inside the selected client service",
    )?;
    let source = build_source_stamp()?;
    let exe = File::open("/proc/self/exe")?;
    let mut bytes = Vec::new();
    exe.take(128 * 1048576 + 1).read_to_end(&mut bytes)?;
    ensure(
        bytes.len() <= 128 * 1048576,
        "recovery executable size bound",
    )?;
    let exe_sha = hex::encode(Sha256::digest(&bytes));
    drop(bytes);
    let trust = RecoveryTrust {
        source,
        executable_sha256: &exe_sha,
        request,
        endpoints,
        boot_id: &boot,
        network_namespace_inode: ns.1,
        network_namespace_device: ns.0,
        cgroup_path: "/system.slice/aegis-client.service",
    };
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(ROOT)? {
        let entry = entry?;
        let token = entry
            .file_name()
            .into_string()
            .map_err(|_| io::Error::other("recovery directory name refused"))?;
        if token == "recovery-receipts" {
            directory(&entry.path(), true)?;
            continue;
        }
        ensure(
            token.len() == 8
                && token
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                && paths.len() < 128,
            "unknown native evidence owner",
        )?;
        paths.push(entry.path());
    }
    paths.sort();
    let mut receipts = Vec::new();
    for path in paths {
        let identity = directory(&path, true)?;
        let input = records(&path, identity)?;
        let plan = reconstruct(&input, &trust)?;
        ensure(
            path.file_name().and_then(|v| v.to_str()) == Some(plan.intent.instance.as_str()),
            "journal path/instance mismatch",
        )?;
        owner_quiet(&plan)?;
        blocked_guard(policy, request, endpoints)?;
        let observed = observed_owned_table(&plan, request)?;
        ensure(
            input == records(&path, identity)?
                && directory(Path::new(ROOT), true)? == root_identity,
            "recovery input drift",
        )?;
        ensure(
            current_namespace()? == ns && current_boot()? == boot,
            "recovery namespace or boot changed",
        )?;
        owner_quiet(&plan)?;
        // Revalidate identical actual table immediately before destructive action.
        ensure(
            observed == observed_owned_table(&plan, request)?,
            "owned policy drift before recovery",
        )?;
        if observed.is_some() {
            command("nft", &["delete", "table", "ip", &plan.intent.table], None)?;
        }
        ensure(
            !table_present(
                &json("nft", &["-j", "-n", "-y", "-p", "list", "tables"])?,
                &plan.intent.table,
            )?,
            "recovery table deletion not confirmed",
        )?;
        owner_quiet(&plan)?;
        ensure(
            input == records(&path, identity)?,
            "journal changed during recovery",
        )?;
        receipts.push(write_receipt(&plan, observed.is_some())?);
    }
    Ok(receipts)
}
