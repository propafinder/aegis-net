//! Durable readback of an actually finalized generation for a later boot.
//!
//! This is historical evidence, never an old StageGuard or activation lease.
//! Only immutable configuration/metadata and the mutable state root are kept;
//! file contents are represented by hashes, not copied into a journal.
#![cfg(target_os = "linux")]

use super::{
    authority, digest, recovery_chain, recovery_directory, recovery_file_hash, recovery_open_at,
    recovery_stat, refuse, Result,
};
use crate::profile_auto_stopped_service::InstallLock;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ffi::{CStr, CString, OsStr},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Path, PathBuf},
};

const SNAPSHOT_DIRECTORY: &str = "boot-snapshots";
const MAX_SNAPSHOT: usize = 1024 * 1024;
const MAX_ENTRIES: usize = 1024;
const MAX_DEPTH: usize = 8;
const MAX_FILE: u64 = 16 * 1024 * 1024;
const MAX_TREE: u64 = 64 * 1024 * 1024;

// A fixed, value-free label for a rejected fresh-boot observation. The
// coordinator admits only this closed vocabulary and never copies an error
// string, path, PID, digest or guardian reply into the journal.
fn refuse_boot_phase(phase: &'static str) -> String {
    eprintln!("AEGIS_AUTO_BOOT_REFUSED phase={phase}");
    refuse()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Node {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    size: i64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
    content_sha256: Option<String>,
}

fn node(s: &libc::stat, content_sha256: Option<String>) -> Node {
    #[allow(clippy::useless_conversion)]
    let links = u64::from(s.st_nlink);
    Node {
        device: s.st_dev,
        inode: s.st_ino,
        mode: s.st_mode,
        uid: s.st_uid,
        gid: s.st_gid,
        links,
        size: s.st_size,
        mtime: s.st_mtime,
        mtime_ns: s.st_mtime_nsec,
        ctime: s.st_ctime,
        ctime_ns: s.st_ctime_nsec,
        content_sha256,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClosedTree {
    path: PathBuf,
    entries: BTreeMap<PathBuf, Node>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateRoot {
    path: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootSnapshot {
    schema: String,
    active_report_sha256: String,
    predecessor_boot_id: String,
    machine_id_sha256: String,
    config: ClosedTree,
    metadata: ClosedTree,
    state: StateRoot,
    current_fixed: serde_json::Value,
    source: serde_json::Value,
    boot_controller: Node,
}

fn names(raw: RawFd) -> Result<Vec<CString>> {
    let copy = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 3) };
    if copy < 0 {
        return Err(refuse());
    }
    let stream = unsafe { libc::fdopendir(copy) };
    if stream.is_null() {
        unsafe { libc::close(copy) };
        return Err(refuse());
    }
    struct Entries(*mut libc::DIR);
    impl Drop for Entries {
        fn drop(&mut self) {
            unsafe { libc::closedir(self.0) };
        }
    }
    let held = Entries(stream);
    unsafe { libc::rewinddir(held.0) };
    let mut result = Vec::new();
    loop {
        unsafe { *libc::__errno_location() = 0 };
        let entry = unsafe { libc::readdir(held.0) };
        if entry.is_null() {
            if std::io::Error::last_os_error().raw_os_error() != Some(0) {
                return Err(refuse());
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_bytes() != b"." && name.to_bytes() != b".." {
            if name.to_bytes().is_empty()
                || name.to_bytes().len() > 255
                || result.len() >= MAX_ENTRIES
                || name.to_str().is_err()
            {
                return Err(refuse());
            }
            result.push(name.to_owned());
        }
    }
    result.sort();
    Ok(result)
}

fn path_stat(parent: RawFd, name: &CStr) -> Result<libc::stat> {
    let mut value = std::mem::MaybeUninit::uninit();
    if unsafe {
        libc::fstatat(
            parent,
            name.as_ptr(),
            value.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(refuse());
    }
    Ok(unsafe { value.assume_init() })
}

fn open_child(parent: RawFd, name: &CStr, directory: bool) -> Result<OwnedFd> {
    let flags = libc::O_RDONLY
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK
        | libc::O_CLOEXEC
        | if directory { libc::O_DIRECTORY } else { 0 };
    let raw = unsafe { libc::openat(parent, name.as_ptr(), flags) };
    if raw < 0 {
        return Err(refuse());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn walk(
    raw: RawFd,
    relative: &Path,
    depth: usize,
    entries: &mut BTreeMap<PathBuf, Node>,
    total: &mut u64,
) -> Result<()> {
    if depth > MAX_DEPTH || entries.len() >= MAX_ENTRIES {
        return Err(refuse());
    }
    let before = recovery_stat(raw)?;
    if before.st_mode & libc::S_IFMT != libc::S_IFDIR || before.st_mode & 0o022 != 0 {
        return Err(refuse());
    }
    entries.insert(relative.to_owned(), node(&before, None));
    let listed = names(raw)?;
    for name in &listed {
        if entries.len() >= MAX_ENTRIES {
            return Err(refuse());
        }
        let before = path_stat(raw, name)?;
        let path = relative.join(OsStr::from_bytes(name.to_bytes()));
        match before.st_mode & libc::S_IFMT {
            libc::S_IFDIR => {
                let child = open_child(raw, name, true)?;
                if node(&recovery_stat(child.as_raw_fd())?, None) != node(&before, None) {
                    return Err(refuse());
                }
                walk(child.as_raw_fd(), &path, depth + 1, entries, total)?;
            }
            libc::S_IFREG => {
                if before.st_nlink != 1
                    || before.st_size < 0
                    || before.st_size as u64 > MAX_FILE
                    || before.st_mode & 0o022 != 0
                {
                    return Err(refuse());
                }
                *total = total
                    .checked_add(before.st_size as u64)
                    .ok_or_else(refuse)?;
                if *total > MAX_TREE {
                    return Err(refuse());
                }
                let child = open_child(raw, name, false)?;
                if node(&recovery_stat(child.as_raw_fd())?, None) != node(&before, None) {
                    return Err(refuse());
                }
                let (size, hash) = recovery_file_hash(child.as_raw_fd(), MAX_FILE)?;
                if size != before.st_size as u64
                    || node(&recovery_stat(child.as_raw_fd())?, None) != node(&before, None)
                    || node(&path_stat(raw, name)?, None) != node(&before, None)
                {
                    return Err(refuse());
                }
                entries.insert(path, node(&before, Some(hash)));
            }
            _ => return Err(refuse()),
        }
    }
    if listed != names(raw)? || node(&before, None) != node(&recovery_stat(raw)?, None) {
        return Err(refuse());
    }
    Ok(())
}

fn target(path: &Path) -> Result<(OwnedFd, CString)> {
    let parent = path.parent().ok_or_else(refuse)?;
    let components: Vec<_> = parent
        .components()
        .skip(1)
        .map(|part| part.as_os_str().to_str().ok_or_else(refuse))
        .collect::<Result<_>>()?;
    let held = recovery_chain(&components, None)?;
    let leaf =
        CString::new(path.file_name().ok_or_else(refuse)?.as_bytes()).map_err(|_| refuse())?;
    Ok((held, leaf))
}

fn closed_tree(path: &Path) -> Result<ClosedTree> {
    let (parent, leaf) = target(path)?;
    let root = open_child(parent.as_raw_fd(), &leaf, true)?;
    let mut entries = BTreeMap::new();
    let mut total = 0;
    walk(root.as_raw_fd(), Path::new(""), 0, &mut entries, &mut total)?;
    if entries.get(Path::new("")) != Some(&node(&path_stat(parent.as_raw_fd(), &leaf)?, None)) {
        return Err(refuse());
    }
    Ok(ClosedTree {
        path: path.to_owned(),
        entries,
    })
}

fn state_root(path: &Path) -> Result<StateRoot> {
    let (parent, leaf) = target(path)?;
    let root = open_child(parent.as_raw_fd(), &leaf, true)?;
    let before = recovery_stat(root.as_raw_fd())?;
    let named = path_stat(parent.as_raw_fd(), &leaf)?;
    if before.st_mode & libc::S_IFMT != libc::S_IFDIR
        || before.st_mode & 0o7777 != 0o700
        || (
            before.st_dev,
            before.st_ino,
            before.st_uid,
            before.st_gid,
            before.st_mode,
        ) != (
            named.st_dev,
            named.st_ino,
            named.st_uid,
            named.st_gid,
            named.st_mode,
        )
    {
        return Err(refuse());
    }
    Ok(StateRoot {
        path: path.to_owned(),
        device: before.st_dev,
        inode: before.st_ino,
        uid: before.st_uid,
        gid: before.st_gid,
        mode: before.st_mode,
    })
}

fn machine_hash() -> Result<String> {
    let etc = recovery_chain(&["etc"], None)?;
    let raw = recovery_open_at(etc.as_raw_fd(), "machine-id", libc::O_RDONLY, 0)?;
    let before = recovery_stat(raw.as_raw_fd())?;
    if before.st_mode & libc::S_IFMT != libc::S_IFREG
        || before.st_uid != 0
        || before.st_nlink != 1
        || before.st_mode & 0o022 != 0
        || !(32..=33).contains(&before.st_size)
    {
        return Err(refuse());
    }
    let mut file = std::fs::File::from(raw);
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(34)
        .read_to_end(&mut bytes)
        .map_err(|_| refuse())?;
    if node(&recovery_stat(file.as_raw_fd())?, None) != node(&before, None)
        || node(&path_stat(etc.as_raw_fd(), c"machine-id")?, None) != node(&before, None)
        || bytes.len() != before.st_size as usize
    {
        return Err(refuse());
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if bytes.len() != 32
        || !bytes
            .iter()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(refuse());
    }
    Ok(digest(&bytes))
}

fn boot_controller() -> Result<Node> {
    let parent = recovery_chain(&["etc", "systemd", "system"], None)?;
    let raw = recovery_open_at(
        parent.as_raw_fd(),
        "aegis-auto-config.service",
        libc::O_RDONLY,
        0,
    )?;
    let before = recovery_stat(raw.as_raw_fd())?;
    if before.st_mode != libc::S_IFREG | 0o644
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
    {
        return Err(refuse());
    }
    let (size, sha) = recovery_file_hash(raw.as_raw_fd(), 16384)?;
    if size != before.st_size as u64
        || sha
            != digest(include_bytes!(
                "../../../packaging/systemd/aegis-auto-config.service"
            ))
        || node(&recovery_stat(raw.as_raw_fd())?, None) != node(&before, None)
        || node(
            &path_stat(parent.as_raw_fd(), c"aegis-auto-config.service")?,
            None,
        ) != node(&before, None)
    {
        return Err(refuse());
    }
    Ok(node(&before, Some(sha)))
}

fn current_report(stage: &authority::StageGuard, report: &serde_json::Value) -> Result<()> {
    // This public readback performs its own sealed-stage checks before each
    // publication record and again after all three current roots are read.
    let actual = stage.inspect_current_published_roots_with_metadata()?;
    if serde_json::to_value(actual).map_err(|_| refuse())?
        != report["published_paths"]["current_publications"]
    {
        return Err(refuse());
    }
    Ok(())
}

fn read_snapshot(parent: RawFd, leaf: &str) -> Result<Vec<u8>> {
    let raw = recovery_open_at(parent, leaf, libc::O_RDONLY, 0)?;
    let before = recovery_stat(raw.as_raw_fd())?;
    if before.st_mode != libc::S_IFREG | 0o600
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
        || before.st_size <= 0
        || before.st_size as usize > MAX_SNAPSHOT
    {
        return Err(refuse());
    }
    let mut file = std::fs::File::from(raw);
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((MAX_SNAPSHOT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| refuse())?;
    let name = CString::new(leaf).map_err(|_| refuse())?;
    if bytes.len() != before.st_size as usize
        || node(&recovery_stat(file.as_raw_fd())?, None) != node(&before, None)
        || node(&path_stat(parent, &name)?, None) != node(&before, None)
    {
        return Err(refuse());
    }
    Ok(bytes)
}

/// Only a content-addressed, protected capsule can enter boot lineage. The
/// caller cannot substitute a historical stage or supply capsule contents.
pub(super) fn reopen_snapshot_bytes(sha: &str) -> Result<Vec<u8>> {
    if sha.len() != 64
        || !sha
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(refuse());
    }
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    let snapshots = recovery_directory(control.as_raw_fd(), SNAPSHOT_DIRECTORY, Some(0o700))?;
    let bytes = read_snapshot(snapshots.as_raw_fd(), &format!("snapshot-{sha}.json"))?;
    if digest(&bytes) != sha {
        return Err(refuse());
    }
    Ok(bytes)
}

/// This type has no public constructor: its existence proves a fresh boot,
/// intact installed roots/source, fixed service namespace and current deny.
/// The original guard OFD and namespace handles remain held through lineage
/// publication. It grants no activation or reuse of the predecessor lease.
pub(super) struct VerifiedBootObservation {
    report: serde_json::Value,
    snapshot_sha256: String,
    current_boot_id: String,
    verified: Vec<u8>,
    _guard: Option<crate::profile_auto_guardian::BootGuardLease>,
    _namespace: crate::profile_auto_unit_namespace::UnitNamespaceSnapshot,
}

impl VerifiedBootObservation {
    pub(super) fn report(&self) -> &serde_json::Value {
        &self.report
    }
    pub(super) fn snapshot_sha256(&self) -> &str {
        &self.snapshot_sha256
    }
    pub(super) fn current_boot_id(&self) -> &str {
        &self.current_boot_id
    }
    pub(super) fn verified_bytes(&self) -> &[u8] {
        &self.verified
    }
    pub(super) fn revalidate(&self, lock: &InstallLock) -> Result<()> {
        lock.revalidate().map_err(|_| refuse())?;
        if let Some(lease) = &self._guard {
            lease.revalidate_ready().map_err(|_| refuse())?;
        }
        let snapshot: BootSnapshot =
            serde_json::from_slice(&reopen_snapshot_bytes(&self.snapshot_sha256)?)
                .map_err(|_| refuse())?;
        let verified: serde_json::Value =
            serde_json::from_slice(&self.verified).map_err(|_| refuse())?;
        let stage = Path::new(self.report["stage"]["path"].as_str().ok_or_else(refuse)?);
        if boot_id()? != self.current_boot_id
            || machine_hash()? != snapshot.machine_id_sha256
            || snapshot.active_report_sha256
                != digest(&serde_json::to_vec(&self.report).map_err(|_| refuse())?)
            || old_stage_absent(stage).is_err()
            || closed_tree(&snapshot.config.path)? != snapshot.config
            || closed_tree(&snapshot.metadata.path)? != snapshot.metadata
            || state_root(&snapshot.state.path)? != snapshot.state
            || boot_controller()? != snapshot.boot_controller
            || boot_deny(lock, self._guard.as_ref().map(|lease| lease.guard_fd()))?
                != verified["deny"]
        {
            return Err(refuse());
        }
        self._namespace.revalidate(lock).map_err(|_| refuse())?;
        super::installer_v2_generation::verify_boot_source(&self.report)?;
        if let Some(lease) = &self._guard {
            lease.revalidate_ready().map_err(|_| refuse())?;
        }
        lock.revalidate().map_err(|_| refuse())
    }
}

fn boot_id() -> Result<String> {
    let value = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|_| refuse())?;
    let value = value.strip_suffix('\n').ok_or_else(refuse)?;
    if value.len() != 36
        || !value.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
            }
        })
    {
        return Err(refuse());
    }
    Ok(value.into())
}

fn old_stage_absent(stage: &Path) -> Result<()> {
    if stage.parent() != Some(Path::new("/run/aegis-installer-config-snapshots")) {
        return Err(refuse());
    }
    let name = stage
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(refuse)?;
    let run = recovery_chain(&["run"], None)?;
    let parent_name = c"aegis-installer-config-snapshots";
    let mut metadata = std::mem::MaybeUninit::uninit();
    if unsafe {
        libc::fstatat(
            run.as_raw_fd(),
            parent_name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Ok(())
        } else {
            Err(refuse())
        };
    }
    let metadata = unsafe { metadata.assume_init() };
    if metadata.st_mode != libc::S_IFDIR | 0o700 || metadata.st_uid != 0 || metadata.st_gid != 0 {
        return Err(refuse());
    }
    let parent = recovery_directory(
        run.as_raw_fd(),
        "aegis-installer-config-snapshots",
        Some(0o700),
    )?;
    super::recovery_absent(parent.as_raw_fd(), name)?;
    if node(&path_stat(run.as_raw_fd(), parent_name)?, None) != node(&metadata, None) {
        return Err(refuse());
    }
    Ok(())
}

fn boot_deny(lock: &InstallLock, guard: Option<&OwnedFd>) -> Result<serde_json::Value> {
    use std::{
        io::{Seek, SeekFrom},
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let install = lock.duplicate_held_fd().map_err(|_| refuse())?;
    let passed_guard = guard
        .map(|fd| fd.try_clone())
        .transpose()
        .map_err(|_| refuse())?;
    for fd in
        std::iter::once(install.as_raw_fd()).chain(passed_guard.as_ref().map(AsRawFd::as_raw_fd))
    {
        if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } != 0 {
            return Err(refuse());
        }
    }
    let raw = unsafe { libc::memfd_create(c"aegis-boot-deny-read".as_ptr(), libc::MFD_CLOEXEC) };
    if raw < 0 {
        return Err(refuse());
    }
    let mut output = unsafe { std::fs::File::from_raw_fd(raw) };
    let mut command = Command::new("/usr/bin/python3");
    command
        .args([
            "-I",
            "-B",
            "/usr/local/lib/aegis/helpers/lib/aegis_auto_guardian.py",
        ])
        .arg(if passed_guard.is_some() {
            "boot-denied-readback"
        } else {
            "boot-passive-readback"
        })
        .arg(install.as_raw_fd().to_string());
    if let Some(guard) = &passed_guard {
        command.arg(guard.as_raw_fd().to_string());
    }
    let mut child = command
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::from(output.try_clone().map_err(|_| refuse())?))
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| refuse())?;
    let deadline = Instant::now() + Duration::from_secs(35);
    loop {
        if output.metadata().map_err(|_| refuse())?.len() > 8192 || Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(refuse());
        }
        if let Some(status) = child.try_wait().map_err(|_| refuse())? {
            if !status.success() {
                return Err(refuse());
            }
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    lock.revalidate().map_err(|_| refuse())?;
    output.seek(SeekFrom::Start(0)).map_err(|_| refuse())?;
    let mut bytes = Vec::new();
    output
        .take(8193)
        .read_to_end(&mut bytes)
        .map_err(|_| refuse())?;
    if bytes.len() > 8192 {
        return Err(refuse());
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| refuse())?;
    let phase_ok = if guard.is_some() {
        value["schema"] == "aegis_auto_guard_boot_denied_readback_v1"
            && value["no_client_grant"] == true
    } else {
        value["schema"] == "aegis_auto_guard_boot_passive_readback_v1" && value["passive"] == true
    };
    if !phase_ok
        || value["boot_id"] != boot_id()?
        || value["no_private_owner"] != true
        || value["fixed_client_stopped"] != true
    {
        return Err(refuse());
    }
    Ok(value)
}

fn host_assessment(
    report: &serde_json::Value,
    snapshot: &BootSnapshot,
    lock: &InstallLock,
    guard: &OwnedFd,
) -> Result<serde_json::Value> {
    use std::{
        io::{Seek, SeekFrom},
        os::unix::process::CommandExt,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let root = Path::new(
        report["input"]["public_payload_root"]
            .as_str()
            .ok_or_else(refuse)?,
    );
    let capture_profile = report["stage"]["mode"]
        .as_str()
        .filter(|mode| matches!(*mode, "full-wide-tun" | "wide-redirect-safe"))
        .ok_or_else(refuse)?;
    let install = lock.duplicate_held_fd().map_err(|_| refuse())?;
    let passed_guard = guard.try_clone().map_err(|_| refuse())?;
    for fd in [install.as_raw_fd(), passed_guard.as_raw_fd()] {
        if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } != 0 {
            return Err(refuse());
        }
    }
    let raw = unsafe { libc::memfd_create(c"aegis-boot-host-read".as_ptr(), libc::MFD_CLOEXEC) };
    if raw < 0 {
        return Err(refuse());
    }
    let mut output = unsafe { std::fs::File::from_raw_fd(raw) };
    let mut child = Command::new("/bin/bash")
        .arg(root.join("install.sh"))
        .args([
            "client",
            "--verify-v2-boot-host",
            &install.as_raw_fd().to_string(),
            &passed_guard.as_raw_fd().to_string(),
            capture_profile,
        ])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::from(output.try_clone().map_err(|_| refuse())?))
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|_| refuse())?;
    // This new boot-only supervisor includes the unchanged 45-second initrd
    // assessment and bounded host/manager reads. It changes no V2 deadline.
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        if output.metadata().map_err(|_| refuse())?.len() > 8192 || Instant::now() >= deadline {
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.kill();
            let _ = child.wait();
            return Err(refuse());
        }
        if let Some(status) = child.try_wait().map_err(|_| refuse())? {
            if !status.success() {
                return Err(refuse());
            }
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    output.seek(SeekFrom::Start(0)).map_err(|_| refuse())?;
    let mut bytes = Vec::new();
    output
        .take(8193)
        .read_to_end(&mut bytes)
        .map_err(|_| refuse())?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| refuse())?;
    let keys = [
        "schema",
        "boot_id",
        "public_payload_root",
        "installer_sha256",
        "source_config_sha256",
        "assessment_sha256",
        "initrd_sha256",
        "kernel",
        "current_policy_unchanged",
        "capture_profile",
    ];
    let config_sha = snapshot
        .config
        .entries
        .get(Path::new("aegis.toml"))
        .and_then(|n| n.content_sha256.as_deref())
        .ok_or_else(refuse)?;
    if bytes.len() > 8192
        || value
            .as_object()
            .is_none_or(|v| v.len() != keys.len() || keys.iter().any(|k| !v.contains_key(*k)))
        || value["schema"] != "aegis_auto_v2_boot_host_assessment_v1"
        || value["boot_id"] != boot_id()?
        || value["public_payload_root"] != report["input"]["public_payload_root"]
        || value["installer_sha256"] != digest(include_bytes!("../../../install.sh"))
        || value["source_config_sha256"] != config_sha
        || value["current_policy_unchanged"] != true
        || value["capture_profile"] != capture_profile
        || !["initrd_sha256", "assessment_sha256"].iter().all(|k| {
            value[k].as_str().is_some_and(|s| {
                s.len() == 64
                    && s.bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            })
        })
        || value["kernel"].as_str().is_none_or(|s| {
            s.is_empty()
                || s.len() > 256
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'+' | b'-'))
        })
    {
        return Err(refuse());
    }
    lock.revalidate().map_err(|_| refuse())?;
    Ok(value)
}

pub(super) fn observe_current(lock: &InstallLock) -> Result<VerifiedBootObservation> {
    observe_current_with_mode(lock, false)
}

pub(super) fn observe_uninstall_current(lock: &InstallLock) -> Result<VerifiedBootObservation> {
    observe_current_with_mode(lock, true)
}

fn observe_current_with_mode(
    lock: &InstallLock,
    uninstall_recovery: bool,
) -> Result<VerifiedBootObservation> {
    use super::installer_v2_generation;
    use crate::profile_auto_unit_namespace as namespace;
    lock.revalidate().map_err(|_| refuse())?;
    let (report, snapshot_sha256) = if uninstall_recovery {
        installer_v2_generation::boot_history_for_uninstall()?
    } else {
        installer_v2_generation::boot_history()?
    };
    let bytes = reopen_snapshot_bytes(&snapshot_sha256)?;
    let snapshot: BootSnapshot = serde_json::from_slice(&bytes).map_err(|_| refuse())?;
    let current_boot_id = boot_id()?;
    let old_stage = Path::new(report["stage"]["path"].as_str().ok_or_else(refuse)?);
    // /run must have been cleared. Even a same-name replacement of the old
    // stage is ambiguous and cannot become a fresh-boot authority.
    if old_stage.parent() != Some(Path::new("/run/aegis-installer-config-snapshots"))
        || old_stage_absent(old_stage).is_err()
        || snapshot.schema != "aegis_auto_v2_boot_snapshot_v1"
        || snapshot.active_report_sha256
            != digest(&serde_json::to_vec(&report).map_err(|_| refuse())?)
        || snapshot.predecessor_boot_id
            != report["terminal"]["boot_id"].as_str().ok_or_else(refuse)?
        || snapshot.predecessor_boot_id == current_boot_id
        || snapshot.machine_id_sha256 != machine_hash()?
        || snapshot.source != report["input"]
        || snapshot.current_fixed != report["current_fixed"]
        || snapshot.config.path != Path::new("/etc/aegis/client")
        || snapshot.metadata.path != Path::new("/var/lib/aegis-install/auto-client")
        || snapshot.state.path != Path::new("/var/lib/aegis-client")
        || closed_tree(&snapshot.config.path)? != snapshot.config
        || closed_tree(&snapshot.metadata.path)? != snapshot.metadata
        || state_root(&snapshot.state.path)? != snapshot.state
        || boot_controller()? != snapshot.boot_controller
    {
        return Err(refuse());
    }
    installer_v2_generation::verify_boot_source(&report)?;
    let fixed = namespace::UnitNamespaceSnapshot::capture(lock).map_err(|_| refuse())?;
    let roles = namespace::inspect_record_roles(fixed.record()).map_err(|_| refuse())?;
    if serde_json::to_value(roles).map_err(|_| refuse())? != snapshot.current_fixed {
        return Err(refuse());
    }
    let mut guard = match report["stage"]["mode"].as_str() {
        Some("socks-only") => None,
        Some("wide-redirect-safe" | "full-wide-tun") => {
            let candidate_sha256 = report["input"]["candidate_sha256"]
                .as_str()
                .ok_or_else(refuse)?;
            Some(
                crate::profile_auto_guardian::BootGuardLease::acquire(
                    lock.duplicate_held_fd().map_err(|_| refuse())?,
                    crate::profile_auto_guardian::BootGuardBinding {
                        boot_id: &current_boot_id,
                        netns_ino: std::fs::metadata("/proc/self/ns/net")
                            .map_err(|_| refuse())?
                            .ino(),
                        boot_snapshot_sha256: &snapshot_sha256,
                        active_report_sha256: &snapshot.active_report_sha256,
                        predecessor_boot_id: &snapshot.predecessor_boot_id,
                        candidate_sha256,
                        private_unit: report["terminal"]["private_unit"]
                            .as_str()
                            .ok_or_else(refuse)?,
                        prior_invocation_id: report["terminal"]["invocation_id"]
                            .as_str()
                            .ok_or_else(refuse)?,
                    },
                )
                .map_err(|_| refuse())?,
            )
        }
        _ => return Err(refuse()),
    };
    let denied = boot_deny(lock, guard.as_ref().map(|lease| lease.guard_fd()))?;
    if denied["candidate_sha256"] != snapshot.source["candidate_sha256"] {
        return Err(refuse());
    }
    let host = if let Some(guard) = &guard {
        let host = host_assessment(&report, &snapshot, lock, guard.guard_fd())?;
        if host["assessment_sha256"] != denied["state_sha256"] {
            return Err(refuse());
        }
        Some(host)
    } else {
        None
    };
    // Repeat immutable and runtime observations while both real locks are
    // held, so an in-flight actor cannot pass on a stale first observation.
    let final_deny = boot_deny(lock, guard.as_ref().map(|lease| lease.guard_fd()))
        .map_err(|_| refuse_boot_phase("deny_readback"))?;
    if final_deny != denied {
        return Err(refuse_boot_phase("deny_changed"));
    }
    if boot_id().map_err(|_| refuse_boot_phase("boot_id_readback"))? != current_boot_id {
        return Err(refuse_boot_phase("boot_id_changed"));
    }
    if closed_tree(&snapshot.config.path).map_err(|_| refuse_boot_phase("config_readback"))?
        != snapshot.config
    {
        return Err(refuse_boot_phase("config_changed"));
    }
    if closed_tree(&snapshot.metadata.path).map_err(|_| refuse_boot_phase("metadata_readback"))?
        != snapshot.metadata
    {
        return Err(refuse_boot_phase("metadata_changed"));
    }
    if state_root(&snapshot.state.path).map_err(|_| refuse_boot_phase("state_readback"))?
        != snapshot.state
    {
        return Err(refuse_boot_phase("state_changed"));
    }
    if boot_controller().map_err(|_| refuse_boot_phase("controller_readback"))?
        != snapshot.boot_controller
    {
        return Err(refuse_boot_phase("controller_changed"));
    }
    if machine_hash().map_err(|_| refuse_boot_phase("machine_readback"))?
        != snapshot.machine_id_sha256
    {
        return Err(refuse_boot_phase("machine_changed"));
    }
    fixed
        .revalidate(lock)
        .map_err(|_| refuse_boot_phase("namespace_changed"))?;
    installer_v2_generation::verify_boot_source(&report)
        .map_err(|_| refuse_boot_phase("source_changed"))?;
    if let Some(lease) = &mut guard {
        lease.ack_ready().map_err(|_| refuse())?;
    }
    let verified = serde_json::to_vec(&serde_json::json!({
        "schema":"aegis_auto_v2_verified_boot_v1","old_report_sha256":snapshot.active_report_sha256,
        "snapshot_sha256":snapshot_sha256,"old_boot_id":snapshot.predecessor_boot_id,
        "new_boot_id":current_boot_id,"deny":denied,"host_assessment":host
    }))
    .map_err(|_| refuse())?;
    Ok(VerifiedBootObservation {
        report,
        snapshot_sha256,
        current_boot_id,
        verified,
        _guard: guard,
        _namespace: fixed,
    })
}

pub(super) fn capture_and_seal_current(
    report: &serde_json::Value,
    lock: &InstallLock,
    stage: &authority::StageGuard,
) -> Result<String> {
    lock.revalidate().map_err(|_| refuse())?;
    current_report(stage, report)?;
    let paths = &report["published_paths"];
    let config = Path::new(paths["config_root"].as_str().ok_or_else(refuse)?);
    let metadata = Path::new(paths["metadata_dir"].as_str().ok_or_else(refuse)?);
    let state = Path::new(paths["state_dir"].as_str().ok_or_else(refuse)?);
    if config != Path::new("/etc/aegis/client")
        || metadata != Path::new("/var/lib/aegis-install/auto-client")
        || state != Path::new("/var/lib/aegis-client")
    {
        return Err(refuse());
    }
    let observed = BootSnapshot {
        schema: "aegis_auto_v2_boot_snapshot_v1".into(),
        active_report_sha256: digest(&serde_json::to_vec(report).map_err(|_| refuse())?),
        predecessor_boot_id: report["terminal"]["boot_id"]
            .as_str()
            .ok_or_else(refuse)?
            .into(),
        machine_id_sha256: machine_hash()?,
        config: closed_tree(config)?,
        metadata: closed_tree(metadata)?,
        state: state_root(state)?,
        current_fixed: report["current_fixed"].clone(),
        source: report["input"].clone(),
        boot_controller: boot_controller()?,
    };
    current_report(stage, report)?;
    if closed_tree(config)? != observed.config
        || closed_tree(metadata)? != observed.metadata
        || state_root(state)? != observed.state
        || machine_hash()? != observed.machine_id_sha256
        || boot_controller()? != observed.boot_controller
    {
        return Err(refuse());
    }
    let bytes = serde_json::to_vec(&observed).map_err(|_| refuse())?;
    if bytes.is_empty() || bytes.len() > MAX_SNAPSHOT {
        return Err(refuse());
    }
    let hash = digest(&bytes);
    let control = recovery_chain(&["var", "lib", "aegis-auto", "control"], Some(0o700))?;
    let created = unsafe { libc::mkdirat(control.as_raw_fd(), c"boot-snapshots".as_ptr(), 0o700) };
    if created != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
        return Err(refuse());
    }
    if created == 0 && unsafe { libc::fsync(control.as_raw_fd()) } != 0 {
        return Err(refuse());
    }
    let snapshots = recovery_directory(control.as_raw_fd(), SNAPSHOT_DIRECTORY, Some(0o700))?;
    let leaf = format!("snapshot-{hash}.json");
    let name = CString::new(leaf.as_str()).map_err(|_| refuse())?;
    let raw = unsafe {
        libc::openat(
            snapshots.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if raw < 0 {
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
            || read_snapshot(snapshots.as_raw_fd(), &leaf)? != bytes
        {
            return Err(refuse());
        }
    } else {
        let mut file = unsafe { std::fs::File::from_raw_fd(raw) };
        file.write_all(&bytes).map_err(|_| refuse())?;
        file.sync_all().map_err(|_| refuse())?;
        if unsafe { libc::fsync(snapshots.as_raw_fd()) } != 0 {
            return Err(refuse());
        }
    }
    if read_snapshot(snapshots.as_raw_fd(), &leaf)? != bytes {
        return Err(refuse());
    }
    current_report(stage, report)?;
    lock.revalidate().map_err(|_| refuse())?;
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::{
            fs::{symlink, PermissionsExt},
            io::AsRawFd,
        },
    };

    fn snapshot(path: &Path) -> Result<BTreeMap<PathBuf, Node>> {
        let root = fs::File::open(path).unwrap();
        let mut entries = BTreeMap::new();
        walk(root.as_raw_fd(), Path::new(""), 0, &mut entries, &mut 0)?;
        Ok(entries)
    }

    #[test]
    fn immutable_tree_binds_contents_and_detects_replacement() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let leaf = root.path().join("config.toml");
        fs::write(&leaf, b"original").unwrap();
        fs::set_permissions(&leaf, fs::Permissions::from_mode(0o600)).unwrap();
        let before = snapshot(root.path()).unwrap();
        assert_eq!(
            before[Path::new("config.toml")].content_sha256,
            Some(digest(b"original"))
        );
        fs::write(&leaf, b"changed!").unwrap();
        assert_ne!(snapshot(root.path()).unwrap(), before);
        let retained_original = fs::File::open(&leaf).unwrap();
        fs::remove_file(&leaf).unwrap();
        fs::write(&leaf, b"original").unwrap();
        fs::set_permissions(&leaf, fs::Permissions::from_mode(0o600)).unwrap();
        assert_ne!(snapshot(root.path()).unwrap(), before);
        drop(retained_original);
    }

    #[test]
    fn foreign_link_and_fifo_refuse_without_reading_target() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let leaf = root.path().join("unexpected");
        symlink("/dev/zero", &leaf).unwrap();
        assert!(snapshot(root.path()).is_err());
        fs::remove_file(&leaf).unwrap();
        fs::write(&leaf, b"retained").unwrap();
        fs::hard_link(&leaf, root.path().join("second")).unwrap();
        assert!(snapshot(root.path()).is_err());
        fs::remove_file(root.path().join("second")).unwrap();
        fs::remove_file(&leaf).unwrap();
        let name = CString::new(leaf.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(snapshot(root.path()).is_err());
    }

    #[test]
    fn mutable_state_descendants_are_not_immutable_configuration() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let directory = fs::File::open(root.path()).unwrap();
        let before = recovery_stat(directory.as_raw_fd()).unwrap();
        fs::write(root.path().join("brain.json"), b"mutable runtime data").unwrap();
        let after = recovery_stat(directory.as_raw_fd()).unwrap();
        assert_eq!(
            (
                before.st_dev,
                before.st_ino,
                before.st_uid,
                before.st_gid,
                before.st_mode
            ),
            (
                after.st_dev,
                after.st_ino,
                after.st_uid,
                after.st_gid,
                after.st_mode
            )
        );
    }
}
