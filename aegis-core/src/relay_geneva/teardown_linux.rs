//! Administrative selected teardown adapter. Existing service recovery is unchanged.
//! Callers must hold fresh strict stopped-role proofs and retain the INET block.
use super::super::{
    build_source_stamp, command, ensure, finite_deadline, json, operation_live, OperationBudget,
};
use super::{
    blocked_guard, current_boot, current_namespace, directory, observed_owned_table, owner_quiet,
    records, ROOT,
};
use crate::relay_geneva::{
    installed_guard::{PublicGuardPolicy, TABLE},
    recovery::{reconstruct, RecoveryPlan, RecoveryTrust},
    teardown::{DeviceBlockPolicy, OriginalGuardBinding},
    RelayOuterGenevaSettings,
};
use serde_json::Value;
use std::{
    fs::{File, OpenOptions},
    io,
    net::SocketAddrV4,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub struct GuardLease {
    _file: File,
    _budget: OperationBudget,
}
impl GuardLease {
    pub fn acquire() -> io::Result<Self> {
        ensure(unsafe { libc::geteuid() } == 0, "teardown requires root")?;
        let budget = OperationBudget::until(Instant::now() + Duration::from_secs(80));
        let path = Path::new("/var/lib/aegis-install/client/device-guard.conf.lock");
        for p in path.ancestors().skip(1) {
            directory(p, false)?;
        }
        let f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let m = f.metadata()?;
        let s = std::fs::symlink_metadata(path)?;
        ensure(
            m.is_file()
                && m.uid() == 0
                && m.nlink() == 1
                && m.mode() & 0o777 == 0o600
                && m.dev() == s.dev()
                && m.ino() == s.ino(),
            "teardown lock identity",
        )?;
        let d = finite_deadline(Duration::from_secs(2));
        loop {
            operation_live()?;
            if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                break;
            }
            let e = io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EWOULDBLOCK) {
                return Err(e);
            }
            ensure(Instant::now() < d, "teardown lock timeout")?;
            std::thread::sleep(
                Duration::from_millis(5).min(d.saturating_duration_since(Instant::now())),
            );
        }
        operation_live()?;
        Ok(Self {
            _file: f,
            _budget: budget,
        })
    }
    pub fn verify_inet(&self, p: &DeviceBlockPolicy) -> io::Result<[u8; 32]> {
        p.verify(&json(
            "nft",
            &[
                "-j",
                "-n",
                "-y",
                "-p",
                "list",
                "table",
                "inet",
                "aegis_device_guard",
            ],
        )?)
    }
    pub fn observe_inet(&self) -> io::Result<Value> {
        json(
            "nft",
            &[
                "-j",
                "-n",
                "-y",
                "-p",
                "list",
                "table",
                "inet",
                "aegis_device_guard",
            ],
        )
    }
    pub fn verify_initial(
        &self,
        p: &DeviceBlockPolicy,
        binding: Option<&OriginalGuardBinding>,
    ) -> io::Result<([u8; 32], bool)> {
        let actual = self.observe_inet()?;
        if let Ok(digest) = p.verify(&actual) {
            return Ok((digest, false));
        }
        let binding = binding.ok_or_else(|| io::Error::other("unknown original INET policy"))?;
        Ok((p.verify_manager(&actual, binding)?, true))
    }
    /// Revocation only: independently verified manager ownership must be fresh
    /// both before check and immediately before apply. No manager service change.
    pub fn revoke_inet_initial(
        &self,
        p: &DeviceBlockPolicy,
        binding: Option<&OriginalGuardBinding>,
        mut manager_current: impl FnMut() -> io::Result<()>,
    ) -> io::Result<[u8; 32]> {
        let (_, bound) = self.verify_initial(p, binding)?;
        if bound {
            manager_current()?;
        }
        let bytes = serde_json::to_vec(&p.block_transaction())?;
        command("nft", &["-j", "--check", "--file", "-"], Some(&bytes))?;
        let (before, bound) = self.verify_initial(p, binding)?;
        if bound {
            manager_current()?;
        }
        let (fresh, fresh_bound) = self.verify_initial(p, binding)?;
        ensure(
            before == fresh && bound == fresh_bound,
            "original INET drift before owned transition",
        )?;
        command("nft", &["-j", "--file", "-"], Some(&bytes))?;
        self.verify_inet(p)
    }
    pub fn revoke_inet(&self, p: &DeviceBlockPolicy) -> io::Result<[u8; 32]> {
        // A trusted state file alone never authorizes overwriting same-name policy.
        // Only the complete already-unbound owned block is currently supported.
        self.verify_inet(p)?;
        let bytes = serde_json::to_vec(&p.block_transaction())?;
        command("nft", &["-j", "--check", "--file", "-"], Some(&bytes))?;
        self.verify_inet(p)?;
        command("nft", &["-j", "--file", "-"], Some(&bytes))?;
        self.verify_inet(p)
    }
    pub fn selected_block(
        &self,
        p: &PublicGuardPolicy,
        r: &RelayOuterGenevaSettings,
        e: &[SocketAddrV4],
    ) -> io::Result<()> {
        blocked_guard(p, r, e)
    }
    pub fn delete_selected_last(
        &self,
        p: &PublicGuardPolicy,
        r: &RelayOuterGenevaSettings,
        e: &[SocketAddrV4],
        inet: &DeviceBlockPolicy,
        mut admission_and_quiet: impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        admission_and_quiet()?;
        self.verify_inet(inet)?;
        self.selected_block(p, r, e)?;
        admission_and_quiet()?;
        self.verify_inet(inet)?;
        command("nft", &["delete", "table", "netdev", TABLE], None)?;
        ensure(
            !crate::relay_geneva::installed_guard::selected_table_present(&json(
                "nft",
                &["-j", "-n", "-y", "-p", "list", "tables"],
            )?)?,
            "selected gate delete readback",
        )?;
        self.verify_inet(inet)?;
        admission_and_quiet()
    }
}
struct NativeOwner {
    plan: RecoveryPlan,
    path: PathBuf,
    identity: (u64, u64),
    input: Vec<(String, Vec<u8>)>,
}
fn owners(
    request: &RelayOuterGenevaSettings,
    endpoints: &[SocketAddrV4],
    exe_sha: &str,
) -> io::Result<Vec<NativeOwner>> {
    ensure(
        exe_sha.len() == 64
            && exe_sha
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "teardown executable pin",
    )?;
    directory(Path::new("/run"), false)?;
    match std::fs::symlink_metadata(ROOT) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e),
        Ok(_) => {}
    }
    let root = directory(Path::new(ROOT), true)?;
    let ns = current_namespace()?;
    let boot = current_boot()?;
    let source = build_source_stamp()?;
    let trust = RecoveryTrust {
        source,
        executable_sha256: exe_sha,
        request,
        endpoints,
        boot_id: &boot,
        network_namespace_inode: ns.1,
        network_namespace_device: ns.0,
        cgroup_path: "/system.slice/aegis-client.service",
    };
    let mut result = vec![];
    let mut aggregate = 0usize;
    let mut record_count = 0usize;
    for entry in std::fs::read_dir(ROOT)? {
        let entry = entry?;
        let token = entry
            .file_name()
            .into_string()
            .map_err(|_| io::Error::other("native owner token"))?;
        if token == "recovery-receipts" {
            directory(&entry.path(), true)?;
            continue;
        }
        ensure(
            token.len() == 8
                && token
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && result.len() < 128,
            "unknown native directory",
        )?;
        let path = entry.path();
        let identity = directory(&path, true)?;
        let input = records(&path, identity)?;
        aggregate += input.iter().map(|(_, v)| v.len()).sum::<usize>();
        record_count += input.len();
        ensure(
            aggregate <= 24 * 1048576 && record_count <= 8500,
            "native total archive bound",
        )?;
        let plan = reconstruct(&input, &trust)?;
        ensure(plan.intent.instance == token, "native archive instance")?;
        owner_quiet(&plan)?;
        result.push(NativeOwner {
            plan,
            path,
            identity,
            input,
        });
    }
    ensure(
        directory(Path::new(ROOT), true)? == root,
        "native root drift",
    )?;
    result.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(result)
}
/// Collect exact public records only, after reconstructing every native journal
/// against independent product/role source trust. No unknown evidence is adopted.
pub fn public_paths(
    request: &RelayOuterGenevaSettings,
    endpoints: &[SocketAddrV4],
    exe_sha: &str,
) -> io::Result<Vec<PathBuf>> {
    let all = owners(request, endpoints, exe_sha)?;
    let instances = all
        .iter()
        .map(|o| o.plan.intent.instance.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let mut paths = vec![];
    for owner in all {
        for (name, _) in &owner.input {
            paths.push(owner.path.join(name));
        }
    }
    let receipt = Path::new(ROOT).join("recovery-receipts");
    match std::fs::symlink_metadata(&receipt) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
        Ok(_) => {
            directory(&receipt, true)?;
            for entry in std::fs::read_dir(&receipt)? {
                let p = entry?.path();
                let b = super::bounded(&p, 65536, true)?;
                let value = crate::relay_geneva::recovery::parse_unique_public_metadata(&b)?;
                crate::relay_geneva::teardown::validate_recovery_receipt(
                    &value,
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .ok_or_else(|| io::Error::other("receipt name"))?,
                    build_source_stamp()?,
                )?;
                ensure(
                    value
                        .get("instance")
                        .and_then(Value::as_str)
                        .is_some_and(|t| instances.contains(t)),
                    "unpaired native recovery receipt",
                )?;
                paths.push(p);
                ensure(paths.len() <= 8500, "native archive entries")?;
            }
        }
    }
    paths.sort();
    Ok(paths)
}
/// A separate administrative path; it never relaxes service-cgroup recovery.
/// Fresh stopped-role and INET proofs are mandatory before each owned deletion.
pub fn recover_stopped(
    lease: &GuardLease,
    request: &RelayOuterGenevaSettings,
    endpoints: &[SocketAddrV4],
    policy: &PublicGuardPolicy,
    inet: &DeviceBlockPolicy,
    exe_sha: &str,
    mut strict_stopped: impl FnMut() -> io::Result<()>,
) -> io::Result<Vec<Value>> {
    strict_stopped()?;
    lease.verify_inet(inet)?;
    lease.selected_block(policy, request, endpoints)?;
    let all = owners(request, endpoints, exe_sha)?;
    let mut receipts = vec![];
    for owner in all {
        strict_stopped()?;
        lease.verify_inet(inet)?;
        lease.selected_block(policy, request, endpoints)?;
        owner_quiet(&owner.plan)?;
        let actual = strict_owned_table(&owner.plan, request)?;
        ensure(
            owner.input == records(&owner.path, owner.identity)?,
            "journal drift before teardown recovery",
        )?;
        owner_quiet(&owner.plan)?;
        ensure(
            actual == strict_owned_table(&owner.plan, request)?,
            "owned native policy drift",
        )?;
        if actual.is_some() {
            command(
                "nft",
                &["delete", "table", "ip", &owner.plan.intent.table],
                None,
            )?;
        }
        ensure(
            strict_owned_table(&owner.plan, request)?.is_none(),
            "native table delete confirmation",
        )?;
        owner_quiet(&owner.plan)?;
        strict_stopped()?;
        lease.verify_inet(inet)?;
        ensure(
            owner.input == records(&owner.path, owner.identity)?,
            "journal drift after stopped recovery",
        )?;
        // Keep each confirmed deletion durable even if a later owner refuses.
        super::write_receipt(&owner.plan, actual.is_some())?;
        operation_live()?;
        receipts.push(serde_json::json!({"schema":"aegis_selected_teardown_native_quiet_v1","instance":owner.plan.intent.instance,"source_commit":owner.plan.intent.source_stamp,"journal_sha256":hex::encode(owner.plan.journal_sha256),"old_process_absent":true,"all_recorded_socket_inodes_absent":true,"recorded_tun_absent":true,"owned_table_absent":true,"removed_exact_table":actual.is_some(),"installed_lifecycle_acceptance":false}));
    }
    Ok(receipts)
}
pub fn quiet(
    request: &RelayOuterGenevaSettings,
    endpoints: &[SocketAddrV4],
    exe_sha: &str,
) -> io::Result<()> {
    for owner in owners(request, endpoints, exe_sha)? {
        ensure(
            strict_owned_table(&owner.plan, request)?.is_none(),
            "old native policy remains",
        )?;
        owner_quiet(&owner.plan)?;
    }
    Ok(())
}

fn strict_owned_table(
    plan: &RecoveryPlan,
    request: &RelayOuterGenevaSettings,
) -> io::Result<Option<Value>> {
    let inventory = json("nft", &["-j", "-n", "-y", "-p", "list", "tables"])?;
    if !crate::relay_geneva::teardown::exact_table_present(&inventory, "ip", &plan.intent.table)? {
        return Ok(None);
    }
    let actual = observed_owned_table(plan, request)?;
    ensure(actual.is_some(), "owned table inventory drift")?;
    Ok(actual)
}
/// After source journals are archived/removed, quiet proof still checks EVERY
/// original owner/socket/TUN from their exact saved public records.
pub fn quiet_archived(
    request: &RelayOuterGenevaSettings,
    endpoints: &[SocketAddrV4],
    exe_sha: &str,
    archived: &std::collections::BTreeMap<PathBuf, Vec<u8>>,
) -> io::Result<()> {
    let ns = current_namespace()?;
    let boot = current_boot()?;
    let source = build_source_stamp()?;
    let trust = RecoveryTrust {
        source,
        executable_sha256: exe_sha,
        request,
        endpoints,
        boot_id: &boot,
        network_namespace_inode: ns.1,
        network_namespace_device: ns.0,
        cgroup_path: "/system.slice/aegis-client.service",
    };
    let mut groups = std::collections::BTreeMap::<String, Vec<(String, Vec<u8>)>>::new();
    let mut total = 0usize;
    for (path, bytes) in archived {
        let Ok(rel) = path.strip_prefix(ROOT) else {
            continue;
        };
        let parts = rel.components().collect::<Vec<_>>();
        ensure(parts.len() == 2, "archived native path depth")?;
        let token = parts[0]
            .as_os_str()
            .to_str()
            .ok_or_else(|| io::Error::other("archived token"))?;
        if token == "recovery-receipts" {
            continue;
        }
        ensure(
            token.len() == 8
                && token
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "archived instance",
        )?;
        let name = parts[1]
            .as_os_str()
            .to_str()
            .ok_or_else(|| io::Error::other("archived record name"))?;
        total += bytes.len();
        ensure(
            total <= 24 * 1048576 && groups.len() <= 128,
            "archived native aggregate bound",
        )?;
        ensure(
            groups.contains_key(token) || groups.len() < 128,
            "archived native instance bound",
        )?;
        groups
            .entry(token.into())
            .or_default()
            .push((name.into(), bytes.clone()));
    }
    for (token, mut records) in groups {
        records.sort_by(|a, b| a.0.cmp(&b.0));
        let plan = reconstruct(&records, &trust)?;
        ensure(
            plan.intent.instance == token,
            "archive path instance mismatch",
        )?;
        owner_quiet(&plan)?;
        ensure(
            strict_owned_table(&plan, request)?.is_none(),
            "archived owned table remains",
        )?;
        owner_quiet(&plan)?;
    }
    Ok(())
}

pub fn super_selected_exists() -> io::Result<bool> {
    crate::relay_geneva::installed_guard::selected_table_present(&json(
        "nft",
        &["-j", "-n", "-y", "-p", "list", "tables"],
    )?)
}
