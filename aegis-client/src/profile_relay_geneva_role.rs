//! Fresh administrative role attestation; no per-packet cgroup authorization.
//! The caller supplies independently verified installed-profile file pins.
use aegis_core::relay_geneva::installed_guard::CurrentClientBinding;
#[cfg(any(target_os = "linux", test))]
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io, path::PathBuf};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExpectedRole {
    pub executable_path: PathBuf,
    pub executable_argument_path: PathBuf,
    pub executable_sha256: String,
    pub config_argument_path: PathBuf,
    pub config_file_path: PathBuf,
    pub config_sha256: String,
    pub runtime_events_argument_path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub online_bundle: Option<OnlineBundleExpectation>,
    pub fragment_path: PathBuf,
    pub fragment_sha256: String,
    pub drop_in_paths_to_sha256: BTreeMap<PathBuf, String>,
    pub control_helper_path: PathBuf,
    pub control_helper_sha256: String,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OnlineBundleExpectation {
    pub argument_path: PathBuf,
    pub members_sha256: BTreeMap<String, String>,
}
#[cfg(any(target_os = "linux", test))]
const ONLINE_BUNDLE_MEMBERS: [&str; 4] = [
    "bundle.json",
    "outer-ca.pem",
    "inner-ca.pem",
    "device-ca.pem",
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RoleMode {
    CurrentControlParent,
    RunningMain,
    /// Runtime self only: permits the qualified systemd READY handoff.
    StartingOrRunningMain,
}

/// A fresh administrative identity for a caller-owned pidfd stop transaction.
/// No signal is sent here; callers must re-attest after opening their pidfd.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RunningIdentity {
    pub binding: CurrentClientBinding,
    pub pid: u32,
    pub start_ticks: u64,
    pub executable_device: u64,
    pub executable_inode: u64,
}

#[cfg(any(target_os = "linux", test))]
fn refuse(text: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, text)
}
#[cfg(any(target_os = "linux", test))]
fn ensure(ok: bool, text: &'static str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(refuse(text))
    }
}
#[cfg(any(target_os = "linux", test))]
fn hex(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}
#[cfg(any(target_os = "linux", test))]
fn safe_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.contains(['\n', '\r', '\0', ' ', '\\'])
        && !path.split('/').any(|s| s == ".." || s == ".")
}

#[cfg(any(target_os = "linux", test))]
fn digest_opened(
    mut reader: impl std::io::Read,
    deadline: std::time::Instant,
) -> io::Result<String> {
    let mut hash = Sha256::new();
    let mut buf = [0u8; 32768];
    let mut bytes = 0u64;
    loop {
        ensure(
            std::time::Instant::now() < deadline,
            "role file hashing deadline",
        )?;
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        bytes += n as u64;
        ensure(bytes <= 67108864, "role file hash bound")?;
        hash.update(&buf[..n]);
    }
    Ok(hex::encode(hash.finalize()))
}

#[cfg(any(target_os = "linux", test))]
const KEYS: &[&str] = &[
    "LoadState",
    "ActiveState",
    "SubState",
    "MainPID",
    "ControlPID",
    "ControlGroup",
    "InvocationID",
    "FragmentPath",
    "DropInPaths",
    "ExecStart",
    "ExecStartPre",
    "NeedDaemonReload",
];
#[cfg(any(target_os = "linux", test))]
fn parse_unit(bytes: &[u8]) -> io::Result<BTreeMap<String, String>> {
    ensure(bytes.len() <= 32768, "unit readback bound")?;
    let text = std::str::from_utf8(bytes).map_err(|_| refuse("unit readback encoding"))?;
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| refuse("unit property frame"))?;
        ensure(
            KEYS.contains(&k)
                && !v.contains('\0')
                && map.insert(k.to_owned(), v.to_owned()).is_none(),
            "duplicate or unknown unit property",
        )?;
    }
    ensure(map.len() == KEYS.len(), "incomplete unit properties")?;
    Ok(map)
}
#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct Process {
    pid: u32,
    start: u64,
    executable: PathBuf,
    executable_sha256: String,
    executable_device: u64,
    executable_inode: u64,
    argv: Vec<String>,
    cgroup: String,
    root_owned: bool,
}
#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct Snapshot {
    unit: BTreeMap<String, String>,
    role: Process,
    caller: Process,
    caller_parent: u32,
    boot: String,
    invocation_env: Option<String>,
    cgroup_inode: u64,
    files: BTreeMap<PathBuf, String>,
    config_resolved: PathBuf,
    executable_argument_resolved: PathBuf,
    systemctl_sha256: String,
}
#[cfg(any(target_os = "linux", test))]
fn value<'a>(unit: &'a BTreeMap<String, String>, key: &str) -> io::Result<&'a str> {
    unit.get(key)
        .map(String::as_str)
        .ok_or_else(|| refuse("missing unit field"))
}
#[cfg(any(target_os = "linux", test))]
fn integer(unit: &BTreeMap<String, String>, key: &str) -> io::Result<u32> {
    let s = value(unit, key)?;
    ensure(
        !s.is_empty() && s.bytes().all(|x| x.is_ascii_digit()),
        "unit PID type",
    )?;
    s.parse().map_err(|_| refuse("unit PID range"))
}
#[cfg(any(target_os = "linux", test))]
fn expected_files(e: &ExpectedRole) -> io::Result<BTreeMap<PathBuf, String>> {
    let mut files = e.drop_in_paths_to_sha256.clone();
    for (p, h) in [
        (&e.executable_path, &e.executable_sha256),
        (&e.config_file_path, &e.config_sha256),
        (&e.fragment_path, &e.fragment_sha256),
        (&e.control_helper_path, &e.control_helper_sha256),
    ] {
        ensure(
            files.insert(p.clone(), h.clone()).is_none(),
            "duplicate role file pin",
        )?;
    }
    if let Some(bundle) = &e.online_bundle {
        let path = bundle
            .argument_path
            .to_str()
            .ok_or_else(|| refuse("online bundle path encoding"))?;
        ensure(
            safe_path(path) && path != "/" && !path.ends_with('/') && !path.contains("//"),
            "online bundle argument path schema",
        )?;
        ensure(
            bundle.members_sha256.len() == ONLINE_BUNDLE_MEMBERS.len()
                && ONLINE_BUNDLE_MEMBERS
                    .iter()
                    .all(|name| bundle.members_sha256.get(*name).is_some_and(|h| hex(h, 64))),
            "online bundle requires exactly four public member pins",
        )?;
        // Each named file follows the same protected canonical file/ancestor
        // custody as the other role pins in both native snapshots. The bundle
        // directory cannot be an unresolved argument alias or symlink.
        // This is a Linux path schema even when pure validation runs on a
        // different host; host-native join must not introduce backslashes.
        for name in ONLINE_BUNDLE_MEMBERS {
            ensure(
                files
                    .insert(
                        PathBuf::from(format!("{path}/{name}")),
                        bundle.members_sha256[name].clone(),
                    )
                    .is_none(),
                "duplicate online bundle role file pin",
            )?;
        }
    }
    ensure(
        files.len() <= 36
            && files
                .iter()
                .all(|(p, h)| p.to_str().is_some_and(safe_path) && hex(h, 64)),
        "role file pin schema",
    )?;
    ensure(
        e.executable_argument_path.to_str().is_some_and(safe_path)
            && e.config_argument_path.to_str().is_some_and(safe_path)
            && e.runtime_events_argument_path
                .to_str()
                .is_some_and(safe_path),
        "role argument path schema",
    )?;
    Ok(files)
}

/// Pure proposed schema validation; it does not inspect or grant a live role.
#[cfg(any(target_os = "linux", test))]
pub(super) fn validate_expected_schema(expected: &ExpectedRole) -> io::Result<()> {
    expected_files(expected).map(|_| ())
}
#[cfg(any(target_os = "linux", test))]
fn validate_unit_files(
    e: &ExpectedRole,
    u: &BTreeMap<String, String>,
    files: &BTreeMap<PathBuf, String>,
    config_resolved: &std::path::Path,
    executable_argument_resolved: &std::path::Path,
) -> io::Result<()> {
    ensure(
        value(u, "LoadState")? == "loaded" && value(u, "NeedDaemonReload")? == "no",
        "unit unloaded or stale",
    )?;
    ensure(
        value(u, "FragmentPath")?
            == e.fragment_path
                .to_str()
                .ok_or_else(|| refuse("fragment encoding"))?,
        "foreign unit fragment",
    )?;
    let observed: Vec<_> = value(u, "DropInPaths")?
        .split_whitespace()
        .map(PathBuf::from)
        .collect();
    let wanted: Vec<_> = e.drop_in_paths_to_sha256.keys().cloned().collect();
    ensure(
        observed == wanted,
        "foreign, missing or reordered unit drop-in",
    )?;
    ensure(
        *files == expected_files(e)?
            && *config_resolved == e.config_file_path
            && *executable_argument_resolved == e.executable_path,
        "role files differ from trusted profile",
    )?;
    Ok(())
}
#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct InstallableSnapshot {
    unit: BTreeMap<String, String>,
    files: BTreeMap<PathBuf, String>,
    config_resolved: PathBuf,
    executable_argument_resolved: PathBuf,
    systemctl_sha256: String,
}
#[cfg(any(target_os = "linux", test))]
fn validate_installable(e: &ExpectedRole, s: &InstallableSnapshot) -> io::Result<()> {
    validate_unit_files(
        e,
        &s.unit,
        &s.files,
        &s.config_resolved,
        &s.executable_argument_resolved,
    )?;
    ensure(
        value(&s.unit, "ActiveState")? == "inactive"
            && value(&s.unit, "SubState")? == "dead"
            && integer(&s.unit, "MainPID")? == 0
            && integer(&s.unit, "ControlPID")? == 0,
        "installed role is not inactive with no processes",
    )
}
#[cfg(any(target_os = "linux", test))]
fn validate_installable_pair(
    e: &ExpectedRole,
    before: &InstallableSnapshot,
    after: &InstallableSnapshot,
) -> io::Result<()> {
    validate_installable(e, before)?;
    validate_installable(e, after)?;
    ensure(before == after, "inactive role changed during verification")
}
#[cfg(any(target_os = "linux", test))]
fn validate(e: &ExpectedRole, mode: RoleMode, s: &Snapshot) -> io::Result<CurrentClientBinding> {
    let u = &s.unit;
    validate_unit_files(
        e,
        u,
        &s.files,
        &s.config_resolved,
        &s.executable_argument_resolved,
    )?;
    let invocation = value(u, "InvocationID")?;
    let cg = value(u, "ControlGroup")?;
    ensure(
        hex(invocation, 32)
            && s.boot.len() == 36
            && s.boot.bytes().enumerate().all(|(i, c)| {
                if [8, 13, 18, 23].contains(&i) {
                    c == b'-'
                } else {
                    c.is_ascii_hexdigit() && !c.is_ascii_uppercase()
                }
            }),
        "role boot or invocation schema",
    )?;
    ensure(
        cg == "/system.slice/aegis-client.service" && s.cgroup_inode > 0 && s.role.cgroup == cg,
        "current role cgroup differs",
    )?;
    ensure(
        s.role.root_owned
            && s.caller.root_owned
            && s.role.start > 0
            && s.caller.start > 0
            && s.role.executable_inode > 0
            && s.caller.executable_inode > 0,
        "role process ownership absent",
    )?;
    ensure(
        s.caller.executable == e.executable_path
            && s.caller.executable_sha256 == e.executable_sha256,
        "caller is not pinned client",
    )?;
    match mode {
        RoleMode::RunningMain | RoleMode::StartingOrRunningMain => {
            let active = value(u, "ActiveState")? == "active" && value(u, "SubState")? == "running";
            let starting =
                value(u, "ActiveState")? == "activating" && value(u, "SubState")? == "start";
            ensure(
                (active || mode == RoleMode::StartingOrRunningMain && starting)
                    && integer(u, "MainPID")? == s.role.pid
                    && s.role.pid > 0,
                "main role is not in its permitted state",
            )?;
            if mode == RoleMode::StartingOrRunningMain {
                ensure(
                    integer(u, "ControlPID")? == 0
                        && s.role == s.caller
                        && s.invocation_env.as_deref() == Some(invocation),
                    "runtime caller is not the exact current main invocation",
                )?;
            }
            ensure(
                s.role.executable == e.executable_path
                    && s.role.executable_sha256 == e.executable_sha256,
                "main executable differs",
            )?;
            let mut expected_argv = vec![e.executable_argument_path.to_string_lossy().into_owned()];
            if let Some(bundle) = &e.online_bundle {
                expected_argv.push("--device-online-bundle".into());
                expected_argv.push(bundle.argument_path.to_string_lossy().into_owned());
            }
            expected_argv.extend([
                "--config".into(),
                e.config_argument_path.to_string_lossy().into_owned(),
                "--runtime-events-jsonl".into(),
                e.runtime_events_argument_path
                    .to_string_lossy()
                    .into_owned(),
            ]);
            ensure(
                s.role.argv == expected_argv,
                "main argv differs from installed role",
            )?;
        }
        RoleMode::CurrentControlParent => {
            ensure(
                s.caller.cgroup == cg,
                "control caller is not in current role cgroup",
            )?;
            ensure(
                value(u, "ActiveState")? == "activating"
                    && value(u, "SubState")? == "start-pre"
                    && integer(u, "MainPID")? == 0
                    && integer(u, "ControlPID")? == s.role.pid
                    && s.role.pid == s.caller_parent
                    && s.role.pid > 0,
                "preflight parent is not current control role",
            )?;
            ensure(
                s.invocation_env.as_deref() == Some(invocation),
                "control invocation does not match caller environment",
            )?;
            ensure(
                s.role.argv
                    == [
                        "/bin/bash".to_owned(),
                        e.control_helper_path.to_string_lossy().into_owned(),
                        "bind".to_owned(),
                    ]
                    && s.role.executable.as_path() == std::path::Path::new("/usr/bin/bash"),
                "control helper argv or interpreter differs",
            )?;
        }
    }
    Ok(CurrentClientBinding {
        boot_id: s.boot.clone(),
        invocation_id: invocation.to_owned(),
        cgroup_path: cg.to_owned(),
        cgroup_inode: s.cgroup_inode,
    })
}
#[cfg(any(target_os = "linux", test))]
fn validate_pair(
    e: &ExpectedRole,
    mode: RoleMode,
    before: &Snapshot,
    after: &Snapshot,
) -> io::Result<CurrentClientBinding> {
    let binding = validate(e, mode, before)?;
    validate(e, mode, after)?;
    if before != after {
        ensure(
            mode == RoleMode::StartingOrRunningMain
                && value(&before.unit, "ActiveState")? == "activating"
                && value(&before.unit, "SubState")? == "start"
                && value(&after.unit, "ActiveState")? == "active"
                && value(&after.unit, "SubState")? == "running",
            "current role changed during attestation",
        )?;
        let mut qualified = before.clone();
        qualified.unit.insert("ActiveState".into(), "active".into());
        qualified.unit.insert("SubState".into(), "running".into());
        ensure(
            &qualified == after,
            "READY handoff changed current role identity or pins",
        )?;
    }
    Ok(binding)
}

#[cfg(any(target_os = "linux", test))]
fn identity_pair(
    e: &ExpectedRole,
    before: &Snapshot,
    after: &Snapshot,
) -> io::Result<RunningIdentity> {
    let binding = validate_pair(e, RoleMode::RunningMain, before, after)?;
    Ok(RunningIdentity {
        binding,
        pid: after.role.pid,
        start_ticks: after.role.start,
        executable_device: after.role.executable_device,
        executable_inode: after.role.executable_inode,
    })
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{
        fs,
        io::Read,
        os::unix::{
            fs::{MetadataExt, OpenOptionsExt},
            io::AsRawFd,
        },
        path::Path,
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    fn live(deadline: Instant) -> io::Result<()> {
        ensure(Instant::now() < deadline, "role attestation deadline")
    }
    fn protected_ancestors(path: &Path, deadline: Instant) -> io::Result<()> {
        ensure(path.is_absolute(), "role path is not absolute")?;
        for ancestor in path.ancestors().skip(1) {
            live(deadline)?;
            let meta = fs::symlink_metadata(ancestor)?;
            ensure(
                meta.is_dir()
                    && !meta.file_type().is_symlink()
                    && meta.uid() == 0
                    && meta.mode() & 0o022 == 0,
                "role path ancestor is not root protected",
            )?;
        }
        Ok(())
    }
    fn same_file(before: &fs::Metadata, after: &fs::Metadata) -> bool {
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.mode() == after.mode()
            && before.uid() == after.uid()
            && before.gid() == after.gid()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec()
    }
    fn protected_hash(path: &Path, deadline: Instant) -> io::Result<String> {
        live(deadline)?;
        ensure(
            fs::canonicalize(path)? == path,
            "role pin must be canonical",
        )?;
        protected_ancestors(path, deadline)?;
        let meta = fs::symlink_metadata(path)?;
        ensure(
            meta.is_file()
                && !meta.file_type().is_symlink()
                && meta.uid() == 0
                && meta.mode() & 0o022 == 0
                && meta.len() <= 67108864,
            "role file is not protected regular root file",
        )?;
        let mut f = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)?;
        let opened = f.metadata()?;
        ensure(
            same_file(&meta, &opened),
            "role file replaced while opening",
        )?;
        let digest = digest_opened(&mut f, deadline)?;
        let after = f.metadata()?;
        let named = fs::symlink_metadata(path)?;
        protected_ancestors(path, deadline)?;
        ensure(
            same_file(&meta, &after)
                && same_file(&after, &named)
                && after.is_file()
                && !named.file_type().is_symlink(),
            "role file changed while hashing",
        )?;
        Ok(digest)
    }
    fn read(path: &Path, limit: u64, deadline: Instant) -> io::Result<Vec<u8>> {
        live(deadline)?;
        let mut bytes = Vec::new();
        fs::File::open(path)?
            .take(limit + 1)
            .read_to_end(&mut bytes)?;
        ensure(bytes.len() as u64 <= limit, "role metadata bound")?;
        live(deadline)?;
        Ok(bytes)
    }
    fn text(path: &Path, limit: u64, deadline: Instant) -> io::Result<String> {
        String::from_utf8(read(path, limit, deadline)?)
            .map_err(|_| refuse("role metadata encoding"))
    }
    fn process(pid: u32, deadline: Instant) -> io::Result<Process> {
        ensure(pid > 0, "role PID absent")?;
        let base = PathBuf::from(format!("/proc/{pid}"));
        let stat = text(&base.join("stat"), 8192, deadline)?;
        let end = stat.rfind(')').ok_or_else(|| refuse("role stat frame"))?;
        let start = stat[end + 1..]
            .split_whitespace()
            .nth(19)
            .ok_or_else(|| refuse("role stat missing ticks"))?
            .parse()
            .map_err(|_| refuse("role ticks type"))?;
        let uid = text(&base.join("status"), 16384, deadline)?;
        let root = uid
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .is_some_and(|v| v.split_whitespace().collect::<Vec<_>>() == ["0", "0", "0", "0"]);
        let cg = text(&base.join("cgroup"), 8192, deadline)?;
        let groups: Vec<_> = cg.lines().filter_map(|l| l.strip_prefix("0::")).collect();
        ensure(groups.len() == 1, "unified process cgroup absent")?;
        let exe = fs::read_link(base.join("exe"))?;
        ensure(
            fs::canonicalize(&exe)? == exe,
            "process executable path is not canonical",
        )?;
        protected_ancestors(&exe, deadline)?;
        let target = fs::symlink_metadata(&exe)?;
        let mut executable_fd = fs::File::open(base.join("exe"))?;
        let metadata = executable_fd.metadata()?;
        ensure(
            target.is_file()
                && !target.file_type().is_symlink()
                && metadata.is_file()
                && metadata.uid() == 0
                && metadata.mode() & 0o022 == 0
                && metadata.len() <= 67108864
                && target.dev() == metadata.dev()
                && target.ino() == metadata.ino(),
            "process executable fd differs from protected canonical target",
        )?;
        let digest = digest_opened(&mut executable_fd, deadline)?;
        let after = executable_fd.metadata()?;
        let target_after = fs::symlink_metadata(&exe)?;
        let proc_after = fs::metadata(base.join("exe"))?;
        protected_ancestors(&exe, deadline)?;
        ensure(
            same_file(&metadata, &after)
                && same_file(&after, &target_after)
                && after.uid() == 0
                && after.mode() & 0o022 == 0
                && target_after.uid() == 0
                && target_after.mode() & 0o022 == 0
                && !target_after.file_type().is_symlink()
                && target_after.is_file()
                && after.dev() == metadata.dev()
                && after.ino() == metadata.ino()
                && after.len() == metadata.len()
                && after.mtime() == metadata.mtime()
                && after.mtime_nsec() == metadata.mtime_nsec()
                && target_after.dev() == metadata.dev()
                && target_after.ino() == metadata.ino()
                && proc_after.dev() == metadata.dev()
                && proc_after.ino() == metadata.ino(),
            "process executable identity changed while hashing opened fd",
        )?;
        let raw = read(&base.join("cmdline"), 16384, deadline)?;
        ensure(raw.ends_with(&[0]), "role argv frame")?;
        let argv = raw[..raw.len() - 1]
            .split(|x| *x == 0)
            .map(|b| String::from_utf8(b.to_vec()).map_err(|_| refuse("role argv encoding")))
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Process {
            pid,
            start,
            executable: exe,
            executable_sha256: digest,
            executable_device: metadata.dev(),
            executable_inode: metadata.ino(),
            argv,
            cgroup: groups[0].to_owned(),
            root_owned: root,
        })
    }
    fn unit(deadline: Instant) -> io::Result<(BTreeMap<String, String>, String)> {
        let binary = Path::new("/usr/bin/systemctl");
        let pin = protected_hash(binary, deadline)?;
        let mut child = Command::new(binary)
            .arg("show")
            .arg("aegis-client.service")
            .arg(format!("--property={}", KEYS.join(",")))
            .arg("--no-pager")
            .env("LC_ALL", "C")
            .env("SYSTEMD_PAGER", "")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let result = (|| -> io::Result<_> {
            let mut output = child
                .stdout
                .take()
                .ok_or_else(|| refuse("unit pipe absent"))?;
            let fd = output.as_raw_fd();
            let old = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            ensure(
                old >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, old | libc::O_NONBLOCK) } == 0,
                "unit pipe nonblocking failed",
            )?;
            let mut bytes = Vec::new();
            let mut buffer = [0u8; 4096];
            loop {
                live(deadline)?;
                match output.read(&mut buffer) {
                    Ok(0) => {}
                    Ok(n) => {
                        bytes.extend_from_slice(&buffer[..n]);
                        ensure(bytes.len() <= 32768, "unit output bound")?
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e),
                }
                if let Some(status) = child.try_wait()? {
                    ensure(status.success(), "systemctl did not confirm unit")?;
                    loop {
                        match output.read(&mut buffer) {
                            Ok(0) => break,
                            Ok(n) => {
                                bytes.extend_from_slice(&buffer[..n]);
                                ensure(bytes.len() <= 32768, "unit output bound")?
                            }
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(e) => return Err(e),
                        }
                    }
                    break;
                }
                thread::sleep(Duration::from_millis(5));
            }
            ensure(
                protected_hash(binary, deadline)? == pin,
                "systemctl changed during readback",
            )?;
            Ok((parse_unit(&bytes)?, pin))
        })();
        if result.is_err() {
            let _ = child.kill();
            let until = Instant::now() + Duration::from_millis(100);
            while Instant::now() < until {
                if child.try_wait().ok().flatten().is_some() {
                    break;
                }
                thread::sleep(Duration::from_millis(5));
            }
        }
        result
    }
    fn snapshot(e: &ExpectedRole, mode: RoleMode, deadline: Instant) -> io::Result<Snapshot> {
        let (u, systemctl_sha256) = unit(deadline)?;
        let pid = integer(
            &u,
            if mode != RoleMode::CurrentControlParent {
                "MainPID"
            } else {
                "ControlPID"
            },
        )?;
        let role = process(pid, deadline)?;
        let caller = process(std::process::id(), deadline)?;
        let cgroup = value(&u, "ControlGroup")?;
        ensure(
            cgroup == "/system.slice/aegis-client.service",
            "foreign cgroup path",
        )?;
        let cgpath = PathBuf::from("/sys/fs/cgroup").join(cgroup.trim_start_matches('/'));
        ensure(
            fs::canonicalize(&cgpath)? == cgpath,
            "cgroup path is not canonical",
        )?;
        let meta = fs::symlink_metadata(&cgpath)?;
        ensure(
            meta.is_dir() && meta.uid() == 0 && !meta.file_type().is_symlink(),
            "cgroup ownership absent",
        )?;
        let mut files = BTreeMap::new();
        for (p, _) in expected_files(e)? {
            files.insert(p.clone(), protected_hash(&p, deadline)?);
        }
        Ok(Snapshot {
            unit: u,
            role,
            caller,
            caller_parent: unsafe { libc::getppid() } as u32,
            boot: text(Path::new("/proc/sys/kernel/random/boot_id"), 64, deadline)?
                .trim()
                .to_owned(),
            invocation_env: std::env::var("INVOCATION_ID").ok(),
            cgroup_inode: meta.ino(),
            files,
            config_resolved: argument_target(&e.config_argument_path, deadline)?,
            executable_argument_resolved: argument_target(&e.executable_argument_path, deadline)?,
            systemctl_sha256,
        })
    }
    /// Resolve administrator-controlled aliases while protecting every entry
    /// in the resolution chain, including intermediate directory/file symlinks.
    fn argument_target(path: &Path, deadline: Instant) -> io::Result<PathBuf> {
        use std::collections::VecDeque;
        ensure(path.is_absolute(), "role argument path is not absolute")?;
        let mut pending: VecDeque<_> = path.iter().map(|part| part.to_os_string()).collect();
        let mut resolved = PathBuf::from("/");
        let mut retained = Vec::new();
        let mut links = 0;
        let mut steps = 0;
        while let Some(part) = pending.pop_front() {
            live(deadline)?;
            steps += 1;
            ensure(steps <= 256, "role argument resolution bound")?;
            if part == "/" {
                resolved = PathBuf::from("/");
                continue;
            }
            if part == "." {
                continue;
            }
            if part == ".." {
                resolved.pop();
                if resolved.as_os_str().is_empty() {
                    resolved = PathBuf::from("/");
                }
                continue;
            }
            // The root and every containing directory are canonical/protected;
            // a leaf symlink is admitted only with the same root ownership.
            protected_ancestors(&resolved.join(&part), deadline)?;
            let candidate = resolved.join(&part);
            let meta = fs::symlink_metadata(&candidate)?;
            ensure(meta.uid() == 0, "role argument entry is not root owned")?;
            if meta.file_type().is_symlink() {
                links += 1;
                ensure(links <= 40, "role argument symlink bound")?;
                let target = fs::read_link(&candidate)?;
                ensure(
                    same_file(&meta, &fs::symlink_metadata(&candidate)?),
                    "role argument alias changed",
                )?;
                retained.push((candidate, meta));
                for component in target.iter().rev() {
                    pending.push_front(component.to_os_string());
                }
            } else {
                ensure(
                    meta.mode() & 0o022 == 0
                        && if pending.is_empty() {
                            meta.is_file()
                        } else {
                            meta.is_dir()
                        },
                    "role argument entry is not protected",
                )?;
                retained.push((candidate.clone(), meta));
                resolved = candidate;
            }
        }
        ensure(
            fs::canonicalize(path)? == resolved,
            "role argument target changed",
        )?;
        let final_meta = fs::symlink_metadata(&resolved)?;
        ensure(
            final_meta.is_file() && final_meta.uid() == 0 && final_meta.mode() & 0o022 == 0,
            "role argument target is not a protected regular file",
        )?;
        protected_ancestors(&resolved, deadline)?;
        for (entry, before) in retained {
            live(deadline)?;
            let after = fs::symlink_metadata(entry)?;
            // Unrelated file creation can change a shared directory timestamp.
            // Its actual directory identity, owner and protection still must match.
            let unchanged = if before.is_dir() {
                after.is_dir()
                    && before.dev() == after.dev()
                    && before.ino() == after.ino()
                    && before.uid() == after.uid()
                    && before.gid() == after.gid()
                    && before.mode() == after.mode()
            } else {
                same_file(&before, &after)
            };
            ensure(unchanged, "role argument resolution custody changed")?;
        }
        live(deadline)?;
        Ok(resolved)
    }

    fn installable_snapshot(
        e: &ExpectedRole,
        deadline: Instant,
    ) -> io::Result<InstallableSnapshot> {
        let (unit, systemctl_sha256) = unit(deadline)?;
        let mut files = BTreeMap::new();
        for (p, _) in expected_files(e)? {
            files.insert(p.clone(), protected_hash(&p, deadline)?);
        }
        Ok(InstallableSnapshot {
            unit,
            files,
            systemctl_sha256,
            config_resolved: argument_target(&e.config_argument_path, deadline)?,
            executable_argument_resolved: argument_target(&e.executable_argument_path, deadline)?,
        })
    }
    pub(super) fn installable(e: &ExpectedRole) -> io::Result<()> {
        ensure(
            unsafe { libc::geteuid() } == 0,
            "installed role verification requires root",
        )?;
        let deadline =
            aegis_core::relay_geneva::operation_deadline::bounded(Duration::from_secs(3));
        let first = installable_snapshot(e, deadline)?;
        let last = installable_snapshot(e, deadline)?;
        live(deadline)?;
        validate_installable_pair(e, &first, &last)
    }
    pub(super) fn identity(e: &ExpectedRole) -> io::Result<RunningIdentity> {
        ensure(
            unsafe { libc::geteuid() } == 0,
            "installed role attestation requires root",
        )?;
        let deadline = Instant::now() + Duration::from_secs(3);
        let first = snapshot(e, RoleMode::RunningMain, deadline)?;
        let last = snapshot(e, RoleMode::RunningMain, deadline)?;
        live(deadline)?;
        identity_pair(e, &first, &last)
    }
    pub(super) fn attest(e: &ExpectedRole, mode: RoleMode) -> io::Result<CurrentClientBinding> {
        ensure(
            unsafe { libc::geteuid() } == 0,
            "installed role attestation requires root",
        )?;
        let deadline = Instant::now() + Duration::from_secs(3);
        let first = snapshot(e, mode, deadline)?;
        let last = snapshot(e, mode, deadline)?;
        live(deadline)?;
        validate_pair(e, mode, &first, &last)
    }
    #[cfg(test)]
    mod native_tests {
        use super::*;
        use std::os::unix::fs::{symlink, PermissionsExt};

        fn fixture() -> tempfile::TempDir {
            assert_eq!(
                unsafe { libc::geteuid() },
                0,
                "native custody test requires root"
            );
            tempfile::Builder::new()
                .prefix("aegis-role-custody-")
                .tempdir_in("/run")
                .unwrap()
        }
        fn deadline() -> Instant {
            Instant::now() + Duration::from_secs(3)
        }
        fn directory(root: &Path, name: &str, mode: u32) -> PathBuf {
            let path = root.join(name);
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            path
        }
        fn ordinary(parent: &Path) -> PathBuf {
            let path = parent.join("owned-file");
            fs::write(&path, b"owned custody regression bytes").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            path
        }
        fn change_owner(path: &Path, uid: u32) {
            use std::os::unix::ffi::OsStrExt;
            let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::chown(path.as_ptr(), uid, 0) }, 0);
        }
        struct OwnedChild(std::process::Child);
        impl Drop for OwnedChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        struct SleeperImage {
            path: PathBuf,
            device: u64,
            inode: u64,
            argv: Vec<u8>,
        }
        struct SleeperObservation {
            image: SleeperImage,
            state: String,
        }
        fn sleeper_ready(
            expected: &SleeperImage,
            observed: &SleeperObservation,
            deadline: Instant,
        ) -> io::Result<bool> {
            live(deadline)?;
            ensure(
                matches!(
                    observed.state.as_str(),
                    "R" | "S" | "D" | "T" | "t" | "Z" | "X" | "I" | "P"
                ),
                "owned sleeper state frame",
            )?;
            ensure(
                !matches!(observed.state.as_str(), "Z" | "X"),
                "owned sleeper exited before readiness",
            )?;
            // A Child handle does not attest that /proc has published the new image.
            if observed.image.path != expected.path {
                return Ok(false);
            }
            ensure(
                observed.image.device == expected.device && observed.image.inode == expected.inode,
                "owned sleeper executable identity mismatch",
            )?;
            if observed.image.argv.is_empty() {
                return Ok(false);
            }
            ensure(
                observed.image.argv == expected.argv,
                "owned sleeper argv mismatch",
            )?;
            live(deadline)?;
            Ok(observed.state == "S")
        }
        fn sleeper_observation(
            pid: u32,
            deadline: Instant,
        ) -> io::Result<Option<SleeperObservation>> {
            live(deadline)?;
            let base = PathBuf::from(format!("/proc/{pid}"));
            let read_observation = || -> io::Result<SleeperObservation> {
                let path = fs::read_link(base.join("exe"))?;
                let image = fs::metadata(base.join("exe"))?;
                let argv = read(&base.join("cmdline"), 16384, deadline)?;
                let stat = text(&base.join("stat"), 8192, deadline)?;
                let end = stat
                    .rfind(')')
                    .ok_or_else(|| refuse("owned sleeper stat frame"))?;
                let state = stat[end + 1..]
                    .split_whitespace()
                    .next()
                    .ok_or_else(|| refuse("owned sleeper state absent"))?
                    .to_owned();
                Ok(SleeperObservation {
                    image: SleeperImage {
                        path,
                        device: image.dev(),
                        inode: image.ino(),
                        argv,
                    },
                    state,
                })
            };
            match read_observation() {
                Ok(row) => Ok(Some(row)),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error),
            }
        }
        fn sleeper(parent: &Path) -> (OwnedChild, Instant) {
            let deadline = deadline();
            let path = parent.join("owned-sleep");
            fs::copy(fs::canonicalize("/usr/bin/sleep").unwrap(), &path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            let metadata = fs::metadata(&path).unwrap();
            use std::os::unix::ffi::OsStrExt;
            let mut argv = path.as_os_str().as_bytes().to_vec();
            argv.extend_from_slice(b"\x0020\0");
            let expected = SleeperImage {
                path: path.clone(),
                device: metadata.dev(),
                inode: metadata.ino(),
                argv,
            };
            let mut child = OwnedChild(Command::new(&path).arg("20").spawn().unwrap());
            let wait = || -> io::Result<()> {
                loop {
                    live(deadline)?;
                    ensure(
                        child.0.try_wait()?.is_none(),
                        "owned sleeper exited before readiness",
                    )?;
                    if let Some(observation) = sleeper_observation(child.0.id(), deadline)? {
                        if sleeper_ready(&expected, &observation, deadline)? {
                            ensure(
                                child.0.try_wait()?.is_none(),
                                "owned sleeper exited at readiness",
                            )?;
                            live(deadline)?;
                            return Ok(());
                        }
                    }
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    ensure(!remaining.is_zero(), "owned sleeper readiness deadline")?;
                    thread::sleep(Duration::from_millis(1).min(remaining));
                }
            };
            let mut wait = wait;
            wait().expect("owned sleeper did not reach its exact prepared image and argv");
            (child, deadline)
        }

        #[test]
        fn sleeper_readiness_refuses_unready_or_wrong_observations() {
            let expected = SleeperImage {
                path: "/run/owned-sleep".into(),
                device: 7,
                inode: 9,
                argv: b"/run/owned-sleep\x0020\0".to_vec(),
            };
            let mut observed = SleeperObservation {
                image: SleeperImage {
                    path: expected.path.clone(),
                    device: 7,
                    inode: 9,
                    argv: expected.argv.clone(),
                },
                state: "S".into(),
            };
            assert!(sleeper_ready(&expected, &observed, deadline()).unwrap());
            observed.image.path = "/untrusted/inherited-image".into();
            assert!(!sleeper_ready(&expected, &observed, deadline()).unwrap());
            observed.image.path = expected.path.clone();
            observed.image.argv.clear();
            assert!(!sleeper_ready(&expected, &observed, deadline()).unwrap());
            observed.image.argv = expected.argv.clone();
            observed.state = "R".into();
            assert!(!sleeper_ready(&expected, &observed, deadline()).unwrap());
            observed.state = "Z".into();
            assert!(sleeper_ready(&expected, &observed, deadline()).is_err());
            observed.state = "S".into();
            observed.image.inode += 1;
            assert!(sleeper_ready(&expected, &observed, deadline()).is_err());
            observed.image.inode = expected.inode;
            observed.image.argv = b"wrong\0".to_vec();
            assert!(sleeper_ready(&expected, &observed, deadline()).is_err());
            observed.image.argv = expected.argv.clone();
            assert!(sleeper_ready(
                &expected,
                &observed,
                Instant::now() - Duration::from_millis(1)
            )
            .is_err());
        }

        #[test]
        #[ignore = "authorized disposable Linux runner, root, harmless owned files/processes only"]
        fn file_ancestry() {
            let root = fixture();
            let trusted = directory(root.path(), "trusted", 0o700);
            let file = ordinary(&trusted);
            assert!(protected_hash(&file, deadline()).is_ok());
            fs::set_permissions(&trusted, fs::Permissions::from_mode(0o777)).unwrap();
            assert!(
                protected_hash(&file, deadline()).is_err(),
                "root leaf cannot authorize writable ancestors"
            );
            fs::set_permissions(&trusted, fs::Permissions::from_mode(0o755)).unwrap();
            change_owner(&trusted, 65534);
            assert!(
                protected_hash(&file, deadline()).is_err(),
                "root leaf cannot authorize a foreign directory owner"
            );
        }

        #[test]
        #[ignore = "authorized disposable Linux runner, root, harmless owned files/processes only"]
        fn process_ancestry() {
            let root = fixture();
            let trusted = directory(root.path(), "trusted", 0o700);
            let (child, positive_deadline) = sleeper(&trusted);
            let bound = process(child.0.id(), positive_deadline)
                .expect("protected owned sleeper process attestation failed");
            assert_eq!(bound.executable, trusted.join("owned-sleep"));
            assert!(bound.root_owned);
            fs::set_permissions(&trusted, fs::Permissions::from_mode(0o777)).unwrap();
            assert!(
                process(child.0.id(), deadline()).is_err(),
                "proc image fd does not authorize writable pathname ancestors"
            );
            fs::set_permissions(&trusted, fs::Permissions::from_mode(0o755)).unwrap();
            change_owner(&trusted, 65534);
            assert!(process(child.0.id(), deadline()).is_err());
        }

        #[test]
        #[ignore = "authorized disposable Linux runner, root, harmless owned files/processes only"]
        fn argument_ancestry() {
            let root = fixture();
            let trusted = directory(root.path(), "trusted", 0o700);
            let file = ordinary(&trusted);
            let alias_dir = directory(root.path(), "aliases", 0o700);
            let alias = alias_dir.join("client");
            symlink(&file, &alias).unwrap();
            assert_eq!(argument_target(&alias, deadline()).unwrap(), file);
            let relative = alias_dir.join("relative");
            symlink("../trusted/owned-file", &relative).unwrap();
            assert_eq!(argument_target(&relative, deadline()).unwrap(), file);
            let directory_alias = alias_dir.join("directory");
            symlink(&trusted, &directory_alias).unwrap();
            assert_eq!(
                argument_target(&directory_alias.join("owned-file"), deadline()).unwrap(),
                file
            );
            let nested = alias_dir.join("nested");
            symlink("relative", &nested).unwrap();
            assert_eq!(argument_target(&nested, deadline()).unwrap(), file);
            let directory_only = alias_dir.join("directory-only");
            symlink("../trusted/..", &directory_only).unwrap();
            assert!(argument_target(&directory_only, deadline()).is_err());
            let cycle = alias_dir.join("cycle");
            symlink("cycle", &cycle).unwrap();
            assert!(argument_target(&cycle, deadline()).is_err());
            for n in 0..41 {
                let link = alias_dir.join(format!("chain-{n}"));
                let target = if n == 40 {
                    file.clone()
                } else {
                    format!("chain-{}", n + 1).into()
                };
                symlink(target, link).unwrap();
            }
            assert!(argument_target(&alias_dir.join("chain-0"), deadline()).is_err());
            assert!(argument_target(&alias, Instant::now() - Duration::from_millis(1)).is_err());
            fs::set_permissions(&trusted, fs::Permissions::from_mode(0o777)).unwrap();
            assert!(argument_target(&alias, deadline()).is_err());
            fs::set_permissions(&trusted, fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(&alias_dir, fs::Permissions::from_mode(0o777)).unwrap();
            assert!(
                argument_target(&alias, deadline()).is_err(),
                "canonical target does not protect a writable alias ancestor"
            );
            fs::set_permissions(&alias_dir, fs::Permissions::from_mode(0o755)).unwrap();
            change_owner(&alias_dir, 65534);
            assert!(argument_target(&alias, deadline()).is_err());
        }
    }
}
pub(super) fn attest_current_client(
    expected: &ExpectedRole,
    mode: RoleMode,
) -> io::Result<CurrentClientBinding> {
    #[cfg(target_os = "linux")]
    {
        linux::attest(expected, mode)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (expected, mode);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "installed role attestation requires Linux",
        ))
    }
}

pub(super) fn attest_running_identity(expected: &ExpectedRole) -> io::Result<RunningIdentity> {
    #[cfg(target_os = "linux")]
    {
        linux::identity(expected)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = expected;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "installed role attestation requires Linux",
        ))
    }
}
/// Checks only pinned files and a stable loaded, inactive service; no grants or mutations.
pub(super) fn verify_installable(expected: &ExpectedRole) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::installable(expected)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = expected;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "installed role verification requires Linux",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(mode: RoleMode) -> (ExpectedRole, Snapshot) {
        let h = "1".repeat(64);
        let e = ExpectedRole {
            executable_path: "/opt/aegis/client".into(),
            executable_argument_path: "/usr/local/bin/aegis-client".into(),
            executable_sha256: h.clone(),
            config_argument_path: "/etc/aegis/client.toml".into(),
            config_file_path: "/opt/aegis/config".into(),
            config_sha256: h.clone(),
            runtime_events_argument_path: "/var/log/aegis-client/events.jsonl".into(),
            online_bundle: None,
            fragment_path: "/etc/systemd/system/aegis-client.service".into(),
            fragment_sha256: h.clone(),
            drop_in_paths_to_sha256: BTreeMap::from([(
                "/etc/systemd/system/aegis-client.service.d/guard.conf".into(),
                h.clone(),
            )]),
            control_helper_path: "/usr/local/lib/aegis/aegis-device-egress-guard.sh".into(),
            control_helper_sha256: h.clone(),
        };
        let mut u = BTreeMap::new();
        for k in KEYS {
            u.insert(k.to_string(), String::new());
        }
        for (k, v) in [
            ("LoadState", "loaded"),
            ("NeedDaemonReload", "no"),
            ("MainPID", "100"),
            ("ControlPID", "200"),
            ("ControlGroup", "/system.slice/aegis-client.service"),
            ("InvocationID", "0123456789abcdef0123456789abcdef"),
            ("FragmentPath", "/etc/systemd/system/aegis-client.service"),
            (
                "DropInPaths",
                "/etc/systemd/system/aegis-client.service.d/guard.conf",
            ),
        ] {
            u.insert(k.to_owned(), v.to_owned());
        }
        if mode == RoleMode::CurrentControlParent {
            u.insert("MainPID".into(), "0".into());
        }
        u.insert(
            "ActiveState".into(),
            if mode == RoleMode::RunningMain {
                "active"
            } else {
                "activating"
            }
            .into(),
        );
        u.insert(
            "SubState".into(),
            if mode == RoleMode::RunningMain {
                "running"
            } else {
                "start-pre"
            }
            .into(),
        );
        let mut caller = Process {
            pid: 100,
            start: 55,
            executable: e.executable_path.clone(),
            executable_sha256: h.clone(),
            executable_device: 10,
            executable_inode: 20,
            argv: vec![
                e.executable_argument_path.to_string_lossy().into_owned(),
                "--config".into(),
                e.config_argument_path.to_string_lossy().into_owned(),
                "--runtime-events-jsonl".into(),
                e.runtime_events_argument_path
                    .to_string_lossy()
                    .into_owned(),
            ],
            cgroup: "/system.slice/aegis-client.service".into(),
            root_owned: true,
        };
        let mut role = caller.clone();
        if mode == RoleMode::CurrentControlParent {
            caller.pid = 201;
            role.pid = 200;
            role.executable = "/usr/bin/bash".into();
            role.argv = vec![
                "/bin/bash".into(),
                e.control_helper_path.to_string_lossy().into_owned(),
                "bind".into(),
            ];
        }
        let s = Snapshot {
            unit: u,
            role,
            caller,
            caller_parent: 200,
            boot: "01234567-89ab-cdef-0123-456789abcdef".into(),
            invocation_env: Some("0123456789abcdef0123456789abcdef".into()),
            cgroup_inode: 1000,
            files: expected_files(&e).unwrap(),
            config_resolved: e.config_file_path.clone(),
            executable_argument_resolved: e.executable_path.clone(),
            systemctl_sha256: h,
        };
        (e, s)
    }
    fn online_expectation() -> OnlineBundleExpectation {
        OnlineBundleExpectation {
            argument_path: "/etc/aegis/client/device-bundle".into(),
            members_sha256: ONLINE_BUNDLE_MEMBERS
                .into_iter()
                .map(|name| (name.into(), "3".repeat(64)))
                .collect(),
        }
    }
    fn with_online_bundle(mut e: ExpectedRole, mut s: Snapshot) -> (ExpectedRole, Snapshot) {
        let bundle = online_expectation();
        for process in [&mut s.role, &mut s.caller] {
            if process.executable == e.executable_path {
                process
                    .argv
                    .insert(1, bundle.argument_path.to_string_lossy().into_owned());
                process.argv.insert(1, "--device-online-bundle".into());
            }
        }
        e.online_bundle = Some(bundle);
        s.files = expected_files(&e).unwrap();
        (e, s)
    }
    #[test]
    fn online_bundle_member_paths_keep_exact_linux_schema_on_every_host() {
        let (mut expected, _) = fixture(RoleMode::RunningMain);
        expected.online_bundle = Some(online_expectation());
        let files = expected_files(&expected).unwrap();
        for member in ONLINE_BUNDLE_MEMBERS {
            let exact = format!("/etc/aegis/client/device-bundle/{member}");
            let (path, pin) = files
                .iter()
                .find(|(path, _)| path.to_str() == Some(exact.as_str()))
                .expect("each Linux-schema member path must preserve its exact lexical bytes");
            assert!(!path.to_str().unwrap().contains('\\'));
            assert_eq!(pin, &"3".repeat(64));
        }
        for invalid in [
            r"/etc/aegis\client/device-bundle",
            r"C:\etc\aegis\client\device-bundle",
        ] {
            expected.online_bundle.as_mut().unwrap().argument_path = invalid.into();
            assert!(expected_files(&expected).is_err());
        }
    }
    #[test]
    fn online_bundle_exact_standard_argv_and_all_current_role_modes_pass() {
        for mode in [RoleMode::RunningMain, RoleMode::CurrentControlParent] {
            let (e, s) = fixture(mode);
            let (e, s) = with_online_bundle(e, s);
            assert_eq!(s.files.len(), expected_files(&e).unwrap().len());
            assert!(validate_pair(&e, mode, &s, &s).is_ok());
            if mode == RoleMode::RunningMain {
                assert_eq!(s.role.argv.len(), 7);
                assert_eq!(s.role.argv[1], "--device-online-bundle");
                assert_eq!(s.role.argv[2], "/etc/aegis/client/device-bundle");
                assert_eq!(s.role.argv[3], "--config");
            }
        }
        let (e, s) = starting_runtime_fixture();
        let (e, s) = with_online_bundle(e, s);
        assert!(validate_pair(&e, RoleMode::StartingOrRunningMain, &s, &s).is_ok());
        let after = active_after(&s);
        assert!(validate_pair(&e, RoleMode::StartingOrRunningMain, &s, &after).is_ok());
    }
    #[test]
    fn online_bundle_absent_wrong_duplicate_reordered_or_trailing_argv_refused() {
        for starting in [false, true] {
            let (e, s) = if starting {
                starting_runtime_fixture()
            } else {
                fixture(RoleMode::RunningMain)
            };
            let (e, s) = with_online_bundle(e, s);
            let mode = if starting {
                RoleMode::StartingOrRunningMain
            } else {
                RoleMode::RunningMain
            };
            for case in 0..7 {
                let mut bad = s.clone();
                match case {
                    0 => {
                        drop(bad.role.argv.drain(1..3));
                    }
                    1 => bad.role.argv[2] = "/etc/aegis/foreign-bundle".into(),
                    2 => bad.role.argv.extend([
                        "--device-online-bundle".into(),
                        "/etc/aegis/client/device-bundle".into(),
                    ]),
                    3 => {
                        let pair: Vec<_> = bad.role.argv.drain(1..3).collect();
                        bad.role.argv.extend(pair);
                    }
                    4 => bad.role.argv.push("--diagnostic-logs".into()),
                    5 => {
                        bad.role.argv.remove(2);
                    }
                    _ => bad.role.argv[1] = "--device-online-bundle-alias".into(),
                }
                if starting {
                    bad.caller = bad.role.clone();
                }
                assert!(validate(&e, mode, &bad).is_err(), "argv case {case}");
            }
        }
    }
    #[test]
    fn online_bundle_schema_requires_exact_canonical_four_member_pin_set() {
        let (e, _) = fixture(RoleMode::RunningMain);
        for case in 0..9 {
            let mut bad = e.clone();
            let mut bundle = online_expectation();
            match case {
                0 => {
                    bundle.members_sha256.remove("inner-ca.pem");
                }
                1 => {
                    bundle
                        .members_sha256
                        .insert("device.key".into(), "3".repeat(64));
                }
                2 => {
                    bundle
                        .members_sha256
                        .insert("bundle.json".into(), "A".repeat(64));
                }
                3 => bundle.argument_path = "etc/aegis/client/device-bundle".into(),
                4 => bundle.argument_path = "/etc/aegis/../device-bundle".into(),
                5 => bundle.argument_path = "/etc//aegis/device-bundle".into(),
                6 => bundle.argument_path = "/etc/aegis/device-bundle/".into(),
                7 => bundle.argument_path = "/".into(),
                _ => {
                    bad.config_file_path = PathBuf::from(format!(
                        "{}/bundle.json",
                        bundle.argument_path.to_str().unwrap()
                    ));
                }
            }
            bad.online_bundle = Some(bundle);
            assert!(expected_files(&bad).is_err(), "bundle schema case {case}");
        }
    }
    #[test]
    fn online_bundle_each_file_pin_and_snapshot_drift_refused() {
        for mode in [
            RoleMode::RunningMain,
            RoleMode::CurrentControlParent,
            RoleMode::StartingOrRunningMain,
        ] {
            let (e, s) = if mode == RoleMode::StartingOrRunningMain {
                starting_runtime_fixture()
            } else {
                fixture(mode)
            };
            let (e, s) = with_online_bundle(e, s);
            for member in ONLINE_BUNDLE_MEMBERS {
                let path = PathBuf::from(format!(
                    "{}/{member}",
                    e.online_bundle
                        .as_ref()
                        .unwrap()
                        .argument_path
                        .to_str()
                        .unwrap()
                ));
                let mut bad = s.clone();
                bad.files.insert(path.clone(), "4".repeat(64));
                assert!(validate(&e, mode, &bad).is_err(), "changed {member}");
                assert!(validate_pair(&e, mode, &s, &bad).is_err());
                bad.files.remove(&path);
                assert!(validate(&e, mode, &bad).is_err(), "absent {member}");
            }
            let mut drift = s.clone();
            drift
                .unit
                .insert("ExecStart".into(), "changed online command".into());
            assert!(validate_pair(&e, mode, &s, &drift).is_err());
            drift
                .files
                .insert("/etc/aegis/foreign".into(), "4".repeat(64));
            assert!(validate(&e, mode, &drift).is_err());
        }
    }
    #[test]
    fn online_bundle_optional_v1_and_unknown_fields_are_strict() {
        let (e, s) = fixture(RoleMode::RunningMain);
        let offline = serde_json::to_value(&e).unwrap();
        assert!(offline.get("online_bundle").is_none());
        let decoded: ExpectedRole = serde_json::from_value(offline).unwrap();
        assert!(decoded.online_bundle.is_none());
        assert!(validate(&decoded, RoleMode::RunningMain, &s).is_ok());
        let (_, online) = with_online_bundle(e.clone(), s.clone());
        assert!(validate(&decoded, RoleMode::RunningMain, &online).is_err());
        let (e, _) = with_online_bundle(e, s);
        let mut raw = serde_json::to_value(&e).unwrap();
        raw["online_bundle"]["foreign_authority"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ExpectedRole>(raw).is_err());
    }
    #[test]
    fn main_and_control_exact_fresh_roles_pass() {
        for mode in [RoleMode::RunningMain, RoleMode::CurrentControlParent] {
            let (e, s) = fixture(mode);
            assert!(validate_pair(&e, mode, &s, &s).is_ok());
        }
    }
    #[test]
    fn control_requires_exact_parent_helper_and_invocation() {
        let (e, s) = fixture(RoleMode::CurrentControlParent);
        for i in 0..4 {
            let mut bad = s.clone();
            match i {
                0 => bad.caller_parent += 1,
                1 => bad.role.argv[2] = "status".into(),
                2 => bad.invocation_env = None,
                _ => {
                    bad.unit.insert("ActiveState".into(), "active".into());
                }
            }
            assert!(validate(&e, RoleMode::CurrentControlParent, &bad).is_err());
        }
    }
    #[test]
    fn same_pid_different_ticks_inode_or_invocation_refused() {
        let (e, s) = fixture(RoleMode::RunningMain);
        for i in 0..4 {
            let mut bad = s.clone();
            match i {
                0 => bad.role.start += 1,
                1 => bad.role.executable_inode += 1,
                2 => bad.cgroup_inode += 1,
                _ => {
                    bad.unit.insert("InvocationID".into(), "2".repeat(32));
                }
            }
            assert!(validate_pair(&e, RoleMode::RunningMain, &s, &bad).is_err());
        }
    }
    #[test]
    fn foreign_dropin_files_config_argv_and_executable_refused() {
        let (e, s) = fixture(RoleMode::RunningMain);
        for i in 0..5 {
            let mut bad = s.clone();
            match i {
                0 => {
                    bad.unit
                        .insert("DropInPaths".into(), "/etc/foreign.conf".into());
                }
                1 => {
                    bad.files.insert(e.fragment_path.clone(), "2".repeat(64));
                }
                2 => bad.config_resolved = "/tmp/config".into(),
                3 => bad.role.argv.push("--diagnostic-logs".into()),
                _ => bad.role.executable_sha256 = "2".repeat(64),
            }
            assert!(validate(&e, RoleMode::RunningMain, &bad).is_err());
        }
    }
    #[test]
    fn administrative_caller_cgroup_can_attest_exact_running_main_only() {
        let (e, mut s) = fixture(RoleMode::RunningMain);
        s.caller.cgroup = "/system.slice/NetworkManager.service".into();
        assert!(validate_pair(&e, RoleMode::RunningMain, &s, &s).is_ok());
        let (e, mut s) = fixture(RoleMode::CurrentControlParent);
        s.caller.cgroup = "/system.slice/NetworkManager.service".into();
        assert!(validate(&e, RoleMode::CurrentControlParent, &s).is_err());
    }
    #[test]
    fn manifest_unknown_fields_and_argv_symlink_target_refused() {
        let (e, s) = fixture(RoleMode::RunningMain);
        let mut json = serde_json::to_value(&e).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("foreign_authority".into(), serde_json::json!(true));
        assert!(serde_json::from_value::<ExpectedRole>(json).is_err());
        let mut bad = s.clone();
        bad.executable_argument_resolved = "/opt/foreign/client".into();
        assert!(validate(&e, RoleMode::RunningMain, &bad).is_err());
        for bad_pid in ["-1", "+100", "100x", "4294967296"] {
            let mut bad = s.clone();
            bad.unit.insert("MainPID".into(), bad_pid.into());
            assert!(validate(&e, RoleMode::RunningMain, &bad).is_err());
        }
    }
    #[test]
    fn executable_digest_follows_opened_fd_even_after_path_replacement() {
        use std::io::Write;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("executable-INERT");
        std::fs::write(&path, b"OLD_EXECUTABLE_INERT").unwrap();
        let fd = std::fs::File::open(&path).unwrap();
        let replacement = directory.path().join("replacement-INERT");
        let mut output = std::fs::File::create(&replacement).unwrap();
        output.write_all(b"NEW_PATH_EXECUTABLE_INERT").unwrap();
        drop(output);
        std::fs::rename(replacement, &path).unwrap();
        let digest = digest_opened(
            fd,
            std::time::Instant::now() + std::time::Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(digest, hex::encode(Sha256::digest(b"OLD_EXECUTABLE_INERT")));
        assert_ne!(
            digest,
            hex::encode(Sha256::digest(std::fs::read(&path).unwrap()))
        );
        assert!(digest_opened(&b"INERT"[..], std::time::Instant::now()).is_err());
    }
    #[test]
    fn malformed_missing_duplicate_unit_properties_refused() {
        let (_, s) = fixture(RoleMode::RunningMain);
        let raw = s
            .unit
            .iter()
            .map(|(k, v)| format!("{k}={v}\n"))
            .collect::<String>();
        assert!(parse_unit(raw.as_bytes()).is_ok());
        assert!(parse_unit(format!("{raw}MainPID=100\n").as_bytes()).is_err());
        assert!(parse_unit(raw.replace("LoadState=loaded\n", "").as_bytes()).is_err());
        assert!(parse_unit(format!("{raw}Unexpected=1\n").as_bytes()).is_err());
    }
    #[test]
    fn stale_unit_or_unowned_process_and_foreign_cgroup_refused() {
        let (e, s) = fixture(RoleMode::RunningMain);
        for i in 0..4 {
            let mut bad = s.clone();
            match i {
                0 => {
                    bad.unit.insert("NeedDaemonReload".into(), "yes".into());
                }
                1 => bad.role.root_owned = false,
                2 => bad.role.cgroup = "/other".into(),
                _ => {
                    bad.unit.insert("MainPID".into(), "0".into());
                }
            }
            assert!(validate(&e, RoleMode::RunningMain, &bad).is_err());
        }
    }
    #[test]
    fn running_identity_returns_exact_validated_process_and_refuses_reuse() {
        let (e, s) = fixture(RoleMode::RunningMain);
        let id = identity_pair(&e, &s, &s).unwrap();
        assert_eq!(id.pid, s.role.pid);
        assert_eq!(id.start_ticks, s.role.start);
        assert_eq!(id.executable_device, s.role.executable_device);
        assert_eq!(id.executable_inode, s.role.executable_inode);
        assert_eq!(id.binding.invocation_id, s.unit["InvocationID"]);
        assert_eq!(id.binding.cgroup_inode, s.cgroup_inode);
        for n in 0..5 {
            let mut changed = s.clone();
            match n {
                0 => {
                    changed.role.pid += 1;
                    changed
                        .unit
                        .insert("MainPID".into(), changed.role.pid.to_string());
                }
                1 => changed.role.start += 1,
                2 => changed.role.executable_device += 1,
                3 => changed.role.executable_inode += 1,
                _ => changed.role.executable_sha256 = "2".repeat(64),
            }
            assert!(identity_pair(&e, &s, &changed).is_err());
        }
    }
    fn inactive_fixture() -> (ExpectedRole, InstallableSnapshot) {
        let (e, s) = fixture(RoleMode::RunningMain);
        let mut unit = s.unit;
        for (k, v) in [
            ("ActiveState", "inactive"),
            ("SubState", "dead"),
            ("MainPID", "0"),
            ("ControlPID", "0"),
            ("ControlGroup", ""),
            ("InvocationID", ""),
        ] {
            unit.insert(k.into(), v.into());
        }
        (
            e,
            InstallableSnapshot {
                unit,
                files: s.files,
                config_resolved: s.config_resolved,
                executable_argument_resolved: s.executable_argument_resolved,
                systemctl_sha256: s.systemctl_sha256,
            },
        )
    }
    #[test]
    fn inactive_installable_does_not_require_live_role_but_rejects_any_process() {
        let (e, s) = inactive_fixture();
        assert!(validate_installable_pair(&e, &s, &s).is_ok());
        for (key, val) in [
            ("MainPID", "1"),
            ("ControlPID", "2"),
            ("MainPID", "-1"),
            ("ControlPID", "4294967296"),
            ("ActiveState", "activating"),
            ("SubState", "failed"),
            ("LoadState", "not-found"),
            ("NeedDaemonReload", "yes"),
        ] {
            let mut bad = s.clone();
            bad.unit.insert(key.into(), val.into());
            assert!(
                validate_installable_pair(&e, &bad, &bad).is_err(),
                "{key}={val}"
            );
        }
    }
    #[test]
    fn inactive_installable_refuses_foreign_files_and_readback_drift() {
        let (e, s) = inactive_fixture();
        for n in 0..6 {
            let mut bad = s.clone();
            match n {
                0 => {
                    bad.files.insert(e.fragment_path.clone(), "2".repeat(64));
                }
                1 => {
                    bad.unit
                        .insert("DropInPaths".into(), "/etc/foreign.conf".into());
                }
                2 => bad.config_resolved = "/etc/foreign.toml".into(),
                3 => bad.executable_argument_resolved = "/opt/foreign/client".into(),
                4 => {
                    bad.unit
                        .insert("ExecStart".into(), "opaque changed unit readback".into());
                }
                _ => bad.systemctl_sha256 = "2".repeat(64),
            }
            assert!(validate_installable_pair(&e, &s, &bad).is_err());
        }
    }
    fn starting_runtime_fixture() -> (ExpectedRole, Snapshot) {
        let (e, mut s) = fixture(RoleMode::RunningMain);
        s.unit.insert("ActiveState".into(), "activating".into());
        s.unit.insert("SubState".into(), "start".into());
        s.unit.insert("ControlPID".into(), "0".into());
        (e, s)
    }
    fn active_after(s: &Snapshot) -> Snapshot {
        let mut active = s.clone();
        active.unit.insert("ActiveState".into(), "active".into());
        active.unit.insert("SubState".into(), "running".into());
        active
    }
    #[test]
    fn runtime_self_start_or_running_and_only_forward_ready_handoff_pass() {
        let (e, start) = starting_runtime_fixture();
        let active = active_after(&start);
        for (before, after) in [(&start, &start), (&active, &active), (&start, &active)] {
            assert!(validate_pair(&e, RoleMode::StartingOrRunningMain, before, after).is_ok());
        }
        assert!(validate_pair(&e, RoleMode::StartingOrRunningMain, &active, &start).is_err());
        assert!(validate(&e, RoleMode::RunningMain, &start).is_err());
        assert!(identity_pair(&e, &start, &start).is_err());
    }
    #[test]
    fn startpost_control_process_and_foreign_main_or_caller_refused() {
        let (e, start) = starting_runtime_fixture();
        for n in 0..7 {
            let mut bad = start.clone();
            match n {
                0 => {
                    bad.unit.insert("SubState".into(), "start-post".into());
                }
                1 => {
                    bad.unit.insert("SubState".into(), "start-pre".into());
                }
                2 => {
                    bad.unit.insert("ControlPID".into(), "200".into());
                }
                3 => {
                    bad.unit.insert("MainPID".into(), "0".into());
                }
                4 => bad.caller.pid += 1,
                5 => bad.caller.cgroup = "/system.slice/NetworkManager.service".into(),
                _ => bad.invocation_env = None,
            }
            assert!(validate(&e, RoleMode::StartingOrRunningMain, &bad).is_err());
        }
    }
    #[test]
    fn forward_handoff_never_adopts_new_identity_files_or_invocation() {
        let (e, start) = starting_runtime_fixture();
        for n in 0..8 {
            let mut after = active_after(&start);
            match n {
                0 => {
                    after.role.pid += 1;
                    after.caller.pid += 1;
                    after
                        .unit
                        .insert("MainPID".into(), after.role.pid.to_string());
                }
                1 => {
                    after.role.start += 1;
                    after.caller.start += 1;
                }
                2 => {
                    after.role.executable_inode += 1;
                    after.caller.executable_inode += 1;
                }
                3 => {
                    after.unit.insert("InvocationID".into(), "2".repeat(32));
                    after.invocation_env = Some("2".repeat(32));
                }
                4 => {
                    after
                        .files
                        .insert(e.config_file_path.clone(), "2".repeat(64));
                }
                5 => after.boot = "11234567-89ab-cdef-0123-456789abcdef".into(),
                6 => after.cgroup_inode += 1,
                _ => {
                    after
                        .unit
                        .insert("ExecStart".into(), "opaque foreign unit command".into());
                }
            }
            assert!(validate_pair(&e, RoleMode::StartingOrRunningMain, &start, &after).is_err());
        }
    }
}
