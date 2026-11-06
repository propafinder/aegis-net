//! Fixed Linux read-only stopped-unit observation under a cooperative install lock.
//! No unit actions; independent root/systemd actions remain outside exclusion.
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::File,
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::process::CommandExt,
    },
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
pub(crate) type Result<T> = std::result::Result<T, &'static str>;
use crate::profile_auto_unit_namespace::{
    capture_checked_policy_namespace, CompletePolicyPreparation, ManagedRole, NamespaceRecord,
    OwnedRestoration, OwnedTransition, RestorationAuthority, RestoredNamespaceView,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::PathBuf;
const REFUSED: &str = "Administrative AUTO stopped-service admission refused";
const UNIT: &str = "aegis-client.service";
const LIMIT: usize = 8192;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RunnerStage {
    ExeAdmission,
    ExeOpen,
    ExeMetadata,
    ExeMagic,
    ExeIdentity,
    Spawn,
    Pipes,
    Wait,
    Drain,
    Stderr,
    Cleanup,
    ProcFs,
    ProcScan,
    ProcOpen,
    ProcRead,
    ProcGone,
    ProcParse,
    ProcIdentity,
    GroupClosed,
    Reap,
    ExitStatus,
    Stdout,
    ExeReadback,
    Accepted,
}
thread_local! {
    static RELOAD_RUNNER_STAGE: std::cell::Cell<Option<RunnerStage>> =
        const { std::cell::Cell::new(None) };
}
fn reload_runner_mark(stage: RunnerStage) {
    RELOAD_RUNNER_STAGE.with(|current| current.set(Some(stage)));
}
fn reload_runner_stage() -> Option<RunnerStage> {
    RELOAD_RUNNER_STAGE.with(std::cell::Cell::get)
}
fn reload_runner_failure() -> &'static str {
    use RunnerStage::*;
    match reload_runner_stage() {
        Some(ExeAdmission | ExeOpen | ExeMetadata | ExeMagic | ExeIdentity) => {
            "reload_native_fixed_executable"
        }
        Some(Spawn) => "reload_native_fixed_spawn",
        Some(Pipes) => "reload_native_fixed_pipes",
        Some(Wait) => "reload_native_fixed_wait",
        Some(Drain) => "reload_native_fixed_drain",
        Some(Stderr) => "reload_native_fixed_stderr",
        Some(
            Cleanup | ProcFs | ProcScan | ProcOpen | ProcRead | ProcGone | ProcParse | ProcIdentity
            | GroupClosed | Reap,
        ) => "reload_native_fixed_cleanup",
        Some(ExitStatus) => "reload_native_fixed_exit",
        Some(ExeReadback) => "reload_native_fixed_readback",
        Some(Stdout) => "reload_native_fixed_stdout",
        Some(Accepted) | None => "reload_native_fixed_command",
    }
}
#[cfg(test)]
thread_local! {
    static RUNNER_TRACE: std::cell::RefCell<RunnerTrace> =
        std::cell::RefCell::new(RunnerTrace::default());
}
#[cfg(test)]
#[derive(Clone, Debug, Default)]
struct RunnerTrace {
    stage: Option<RunnerStage>,
    first_failure: Option<RunnerStage>,
    cleanup_failure: Option<RunnerStage>,
    returned_failure: Option<RunnerStage>,
    proc_errno: Option<i32>,
    proc_benign_enoent_count: usize,
    proc_benign_esrch_count: usize,
    stdout_count: usize,
    stderr_count: usize,
    stdout_sha256: Option<[u8; 32]>,
    stderr_sha256: Option<[u8; 32]>,
    output_complete: bool,
    exit_code: Option<i32>,
    exit_signal: Option<i32>,
}
#[cfg(test)]
fn runner_reset() {
    RUNNER_TRACE.with(|trace| *trace.borrow_mut() = RunnerTrace::default());
}
#[cfg(test)]
fn runner_mark(stage: RunnerStage) {
    RUNNER_TRACE.with(|trace| trace.borrow_mut().stage = Some(stage));
}
#[cfg(test)]
fn runner_stage() -> RunnerStage {
    RUNNER_TRACE.with(|trace| trace.borrow().stage.unwrap())
}
#[cfg(test)]
fn runner_snapshot() -> RunnerTrace {
    RUNNER_TRACE.with(|trace| trace.borrow().clone())
}
#[cfg(test)]
fn runner_first_failure(stage: RunnerStage) {
    RUNNER_TRACE.with(|trace| {
        let mut trace = trace.borrow_mut();
        if trace.first_failure.is_none() {
            trace.first_failure = Some(stage);
        }
    });
}
#[cfg(test)]
fn runner_cleanup_failure(stage: RunnerStage) {
    RUNNER_TRACE.with(|trace| trace.borrow_mut().cleanup_failure = Some(stage));
}
#[cfg(test)]
fn runner_returned_failure(stage: RunnerStage) {
    RUNNER_TRACE.with(|trace| trace.borrow_mut().returned_failure = Some(stage));
}
#[cfg(test)]
fn runner_proc_errno(error: Option<i32>) {
    RUNNER_TRACE.with(|trace| trace.borrow_mut().proc_errno = error);
}
#[cfg(test)]
fn runner_proc_benign_enoent() {
    RUNNER_TRACE.with(|trace| trace.borrow_mut().proc_benign_enoent_count += 1);
}
#[cfg(test)]
fn runner_output(stdout: &[u8], stderr: &[u8], complete: bool) {
    use sha2::Digest;
    fn digest(raw: &[u8]) -> [u8; 32] {
        let mut result = [0; 32];
        result.copy_from_slice(&sha2::Sha256::digest(raw));
        result
    }
    RUNNER_TRACE.with(|trace| {
        let mut trace = trace.borrow_mut();
        trace.stdout_count = stdout.len();
        trace.stderr_count = stderr.len();
        trace.stdout_sha256 = Some(digest(stdout));
        trace.stderr_sha256 = Some(digest(stderr));
        trace.output_complete = complete;
    });
}
#[cfg(test)]
fn runner_exit(status: &std::process::ExitStatus) {
    use std::os::unix::process::ExitStatusExt;
    RUNNER_TRACE.with(|trace| {
        let mut trace = trace.borrow_mut();
        trace.exit_code = status.code();
        trace.exit_signal = status.signal();
    });
}
#[cfg(test)]
struct ProcStatAfterOpenHook {
    selected_pid: u32,
    action: Box<dyn FnOnce()>,
}
#[cfg(test)]
thread_local! {
    static PROC_STAT_AFTER_OPEN_HOOK: std::cell::RefCell<Option<ProcStatAfterOpenHook>> =
        const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
fn run_selected_proc_stat_after_open_hook(pid: u32) {
    let action = PROC_STAT_AFTER_OPEN_HOOK.with(|hook| {
        let mut hook = hook.borrow_mut();
        if hook.as_ref().is_some_and(|held| held.selected_pid == pid) {
            hook.take().map(|held| held.action)
        } else {
            None
        }
    });
    if let Some(action) = action {
        action();
    }
}
// Runtime marks feed only the closed refusal coordinate; test builds also
// retain their detailed trace. Arguments, limits and return values are unchanged.
macro_rules! test_runner_mark {
    ($stage:ident) => {
        reload_runner_mark(RunnerStage::$stage);
        #[cfg(test)]
        runner_mark(RunnerStage::$stage);
    };
}
#[path = "profile_auto_pid1.rs"]
pub(crate) mod pid1;
fn err<T>(_: T) -> &'static str {
    REFUSED
}
fn need(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(REFUSED)
    }
}
fn c(value: &str) -> Result<CString> {
    CString::new(value).map_err(err)
}
fn fd(value: i32) -> Result<OwnedFd> {
    if value < 0 {
        Err(REFUSED)
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(value) })
    }
}
fn meta(fd: &OwnedFd) -> Result<libc::stat> {
    let mut s = std::mem::MaybeUninit::uninit();
    need(unsafe { libc::fstat(fd.as_raw_fd(), s.as_mut_ptr()) } == 0)?;
    Ok(unsafe { s.assume_init() })
}
fn directory(parent: i32, leaf: &str) -> Result<OwnedFd> {
    fd(unsafe {
        libc::openat(
            parent,
            c(leaf)?.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    })
}
fn trusted_dir(fd: &OwnedFd) -> Result<()> {
    let s = meta(fd)?;
    need(s.st_uid == 0 && s.st_mode & 0o022 == 0)
}
fn root_dir() -> Result<OwnedFd> {
    directory(libc::AT_FDCWD, "/")
}
/// The persistent retirement barrier is outside control/ because that tree is
/// itself retired before package handoff. Missing means ordinary operation;
/// any malformed or aliased namespace is a refusal, never an absent intent.
fn uninstall_intent_file() -> Result<Option<OwnedFd>> {
    let root = root_dir()?;
    trusted_dir(&root)?;
    let var = directory(root.as_raw_fd(), "var")?;
    trusted_dir(&var)?;
    let lib = directory(var.as_raw_fd(), "lib")?;
    trusted_dir(&lib)?;
    let journal_fd = unsafe {
        libc::openat(
            lib.as_raw_fd(),
            c("aegis-auto-uninstall")?.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if journal_fd < 0 {
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(REFUSED);
    }
    let journal = fd(journal_fd)?;
    trusted_dir(&journal)?;
    let directory_stat = meta(&journal)?;
    need(directory_stat.st_gid == 0 && directory_stat.st_mode & 0o777 == 0o700)?;
    let intent_fd = unsafe {
        libc::openat(
            journal.as_raw_fd(),
            c("intent.json")?.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if intent_fd < 0 {
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            // An interrupted intent publication leaves a pending sibling.
            // Keep every ordinary Rust mutator closed until Python replays it.
            return Err(REFUSED);
        }
        return Err(REFUSED);
    }
    let intent = fd(intent_fd)?;
    let s = meta(&intent)?;
    need(
        s.st_uid == 0
            && s.st_gid == 0
            && s.st_nlink == 1
            && s.st_mode & libc::S_IFMT == libc::S_IFREG
            && s.st_mode & 0o777 == 0o600
            && (1..=8192).contains(&s.st_size),
    )?;
    let named = leaf(&journal, "intent.json", libc::O_RDONLY)?;
    need(identity(&named)? == identity(&intent)?)?;
    Ok(Some(intent))
}

pub(crate) fn uninstall_intent_bytes() -> Result<Option<Vec<u8>>> {
    let Some(intent) = uninstall_intent_file()? else {
        return Ok(None);
    };
    let size = meta(&intent)?.st_size as usize;
    let mut bytes = Vec::new();
    File::from(intent)
        .take(8193)
        .read_to_end(&mut bytes)
        .map_err(err)?;
    need(bytes.len() == size)?;
    Ok(Some(bytes))
}
fn leaf(parent: &OwnedFd, name: &str, flags: i32) -> Result<OwnedFd> {
    fd(unsafe {
        libc::openat(
            parent.as_raw_fd(),
            c(name)?.as_ptr(),
            flags | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    })
}
fn identity(fd: &OwnedFd) -> Result<(u64, u64)> {
    let s = meta(fd)?;
    Ok((s.st_dev, s.st_ino))
}
fn held_flock_line(info: &str, inode: u64, owner_pid: u32) -> bool {
    let inode = inode.to_string();
    let owner_pid = owner_pid.to_string();
    let mut inode_seen = false;
    let mut lock_count = 0usize;
    for line in info.lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        match fields.first().copied() {
            Some("ino:") => {
                if fields.len() != 2 || fields[1] != inode || inode_seen {
                    return false;
                }
                inode_seen = true;
            }
            Some("lock:") => {
                if fields.len() != 9
                    || fields[2] != "FLOCK"
                    || fields[3] != "ADVISORY"
                    || fields[4] != "WRITE"
                    || fields[5] != owner_pid
                    || fields[6].rsplit(':').next() != Some(inode.as_str())
                    || fields[7] != "0"
                    || fields[8] != "EOF"
                {
                    return false;
                }
                lock_count += 1;
            }
            _ => {}
        }
    }
    inode_seen && lock_count == 1
}
/// fdinfo for a transferred flock can report PID 0 after the originating
/// process exits. Bind the exact exclusive whole-file FLOCK record to this
/// descriptor's device/inode without inferring ownership from whitespace.
pub(crate) fn held_transferred_flock_line(info: &str, device: u64, inode: u64) -> bool {
    let mut inode_seen = false;
    let mut lock_count = 0usize;
    for line in info.lines() {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        match fields.first().copied() {
            Some("ino:") => {
                if fields.len() != 2 || fields[1].parse::<u64>() != Ok(inode) || inode_seen {
                    return false;
                }
                inode_seen = true;
            }
            Some("lock:") => {
                if fields.len() != 9
                    || !fields[1]
                        .strip_suffix(':')
                        .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
                    || fields[2..5] != ["FLOCK", "ADVISORY", "WRITE"]
                    || fields[5].parse::<u32>().is_err()
                    || fields[7..9] != ["0", "EOF"]
                {
                    return false;
                }
                let mut identity = fields[6].split(':');
                let (Some(major), Some(minor), Some(locked_inode), None) = (
                    identity.next(),
                    identity.next(),
                    identity.next(),
                    identity.next(),
                ) else {
                    return false;
                };
                if u32::from_str_radix(major, 16) != Ok(libc::major(device))
                    || u32::from_str_radix(minor, 16) != Ok(libc::minor(device))
                    || locked_inode.parse::<u64>() != Ok(inode)
                {
                    return false;
                }
                lock_count += 1;
            }
            _ => {}
        }
    }
    inode_seen && lock_count == 1
}
fn held_install_flock(file: &OwnedFd, inode: u64) -> Result<()> {
    let pid = unsafe { libc::getpid() };
    need(pid >= 2 && file.as_raw_fd() >= 3)?;
    let path = format!("/proc/self/fdinfo/{}", file.as_raw_fd());
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(err)?
        .take(16 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(err)?;
    need(bytes.len() <= 16 * 1024)?;
    let info = std::str::from_utf8(&bytes).map_err(err)?;
    need(held_flock_line(info, inode, pid as u32))
}
#[cfg(test)]
mod held_flock_tests {
    use super::{held_flock_line, held_install_flock, held_transferred_flock_line};
    use std::{
        fs::OpenOptions,
        os::{
            fd::AsRawFd,
            unix::fs::{MetadataExt, OpenOptionsExt},
        },
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn exact_fdinfo_lock_owner_and_inode_required() {
        let valid = "pos:\t0\nino:\t7123\nlock:\t1: FLOCK  ADVISORY  WRITE 4321 00:25:7123 0 EOF\n";
        assert!(held_flock_line(valid, 7123, 4321));
        assert!(!held_flock_line(valid, 7124, 4321));
        assert!(!held_flock_line(valid, 7123, 4322));
        assert!(!held_flock_line("pos: 0\nino: 7123\n", 7123, 4321));
        assert!(!held_flock_line(
            &format!("{valid}lock: 2: FLOCK ADVISORY WRITE 4321 00:25:7123 0 EOF\n"),
            7123,
            4321
        ));
        assert!(!held_flock_line(
            "ino: 7123\nlock: 1: POSIX ADVISORY WRITE 4321 00:25:7123 0 EOF\n",
            7123,
            4321
        ));
        assert!(!held_flock_line(
            &format!("{valid}lock: 2: POSIX ADVISORY WRITE 4321 00:25:7123 0 EOF\n"),
            7123,
            4321
        ));
    }
    #[test]
    fn transferred_flock_requires_exact_device_inode_and_whole_write_range() {
        let device = libc::makedev(0, 0x25);
        let valid = "ino:\t7123\nlock:\t1: FLOCK  ADVISORY  WRITE 0 00:25:7123 0 EOF\n";
        assert!(held_transferred_flock_line(valid, device, 7123));
        for invalid in [
            valid.replace("FLOCK  ADVISORY", "POSIX  ADVISORY"),
            valid.replace("WRITE", "READ"),
            valid.replace("0 EOF", "1 EOF"),
            valid.replace("00:25:7123", "00:26:7123"),
            valid.replace("00:25:7123", "00:25:7124"),
            format!("{valid}lock:\t2: FLOCK ADVISORY WRITE 0 00:25:7123 0 EOF\n"),
        ] {
            assert!(!held_transferred_flock_line(&invalid, device, 7123));
        }
    }

    #[test]
    fn actual_temporary_flock_loss_refuses_revalidation() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "aegis-auto-install-lock-proof-{}-{stamp:x}",
            std::process::id()
        ));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let file: std::os::fd::OwnedFd = file.into();
        let inode = super::meta(&file).unwrap().st_ino as u64;
        assert_eq!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        assert!(held_install_flock(&file, inode).is_ok());
        let duplicate = file.try_clone().unwrap();
        let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", duplicate.as_raw_fd()))
            .unwrap();
        assert!(held_transferred_flock_line(
            &info,
            std::fs::metadata(&path).unwrap().dev(),
            inode
        ));
        assert_eq!(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) }, 0);
        assert!(held_install_flock(&file, inode).is_err());
        let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", duplicate.as_raw_fd()))
            .unwrap();
        assert!(!held_transferred_flock_line(
            &info,
            std::fs::metadata(&path).unwrap().dev(),
            inode
        ));
        drop(file);
        std::fs::remove_file(path).unwrap();
    }
}
/// Must live in the single Rust transaction worker from admission to exit.
/// Never acquire/drop one per shell phase and call that full-install exclusion.
pub(crate) struct InstallLock {
    file: OwnedFd,
    run: OwnedFd,
    id: (u64, u64),
}
impl InstallLock {
    /// Duplicates the held open file description for SCM_RIGHTS handoff. The
    /// original worker continues owning the same exclusion lock.
    pub(crate) fn duplicate_held_fd(&self) -> Result<OwnedFd> {
        self.revalidate()?;
        self.file.try_clone().map_err(err)
    }
    pub(crate) fn acquire() -> Result<Self> {
        Self::acquire_inner(false)
    }
    /// Recovery-only authority after the persistent uninstall intent. Unlike
    /// ordinary Prepare/Update/Capture, it must be able to recreate /run's
    /// original lock pathname after a reboot.
    pub(crate) fn acquire_for_uninstall() -> Result<Self> {
        need(uninstall_intent_file()?.is_some())?;
        let lock = Self::acquire_inner(true)?;
        need(uninstall_intent_file()?.is_some())?;
        Ok(lock)
    }
    fn acquire_inner(allow_uninstall: bool) -> Result<Self> {
        need(unsafe { libc::geteuid() } == 0)?;
        let root = root_dir()?;
        trusted_dir(&root)?;
        let run = directory(root.as_raw_fd(), "run")?;
        trusted_dir(&run)?;
        let file = fd(unsafe {
            libc::openat(
                run.as_raw_fd(),
                c("aegis-auto-install.lock")?.as_ptr(),
                libc::O_RDWR
                    | libc::O_CREAT
                    | libc::O_NONBLOCK
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC,
                0o600,
            )
        })?;
        let s = meta(&file)?;
        need(
            s.st_uid == 0
                && s.st_gid == 0
                && s.st_nlink == 1
                && s.st_mode & libc::S_IFMT == libc::S_IFREG
                && s.st_mode & 0o777 == 0o600,
        )?;
        need(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0)?;
        let id = identity(&file)?;
        let value = Self { file, run, id };
        value.revalidate()?;
        if !allow_uninstall {
            need(uninstall_intent_file()?.is_none())?;
        }
        Ok(value)
    }
    /// Read-only postterminal inspector exclusion. The installed lock must
    /// already exist; this path cannot mint it or any stage authority.
    pub(crate) fn acquire_existing_read_only() -> Result<Self> {
        Self::acquire_existing(libc::O_RDONLY, false)
    }
    /// Explicit recovery mutation authority over the original installed lock.
    /// Unlike acquire(), a missing lock is a refusal, never a new lock inode.
    pub(crate) fn acquire_existing_for_recovery() -> Result<Self> {
        Self::acquire_existing(libc::O_RDWR, false)
    }
    fn acquire_existing(access: libc::c_int, allow_uninstall: bool) -> Result<Self> {
        need(unsafe { libc::geteuid() } == 0)?;
        let root = root_dir()?;
        trusted_dir(&root)?;
        let run = directory(root.as_raw_fd(), "run")?;
        trusted_dir(&run)?;
        let file = leaf(&run, "aegis-auto-install.lock", access)?;
        let s = meta(&file)?;
        need(
            s.st_uid == 0
                && s.st_gid == 0
                && s.st_nlink == 1
                && s.st_mode & libc::S_IFMT == libc::S_IFREG
                && s.st_mode & 0o777 == 0o600,
        )?;
        need(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0)?;
        let id = identity(&file)?;
        let value = Self { file, run, id };
        value.revalidate()?;
        if !allow_uninstall {
            need(uninstall_intent_file()?.is_none())?;
        }
        Ok(value)
    }
    pub(crate) fn revalidate(&self) -> Result<()> {
        trusted_dir(&self.run)?;
        let root = root_dir()?;
        let current_run = directory(root.as_raw_fd(), "run")?;
        need(identity(&current_run)? == identity(&self.run)?)?;
        let current = leaf(&self.run, "aegis-auto-install.lock", libc::O_RDONLY)?;
        need(identity(&current)? == self.id && identity(&self.file)? == self.id)?;
        let s = meta(&current)?;
        need(
            s.st_uid == 0
                && s.st_gid == 0
                && s.st_nlink == 1
                && s.st_mode & libc::S_IFMT == libc::S_IFREG
                && s.st_mode & 0o777 == 0o600,
        )?;
        // A matching pathname and inode do not prove that this worker still
        // holds the exclusion lock. Refuse before a phase if its exact FD has
        // lost the FLOCK record. This is a sampled worker check, not a
        // supervisor-owned lifetime grant.
        held_install_flock(&self.file, self.id.1)
    }
}

/// Read-only observation of the *parent shell's* install flock. This type is
/// deliberately distinct from InstallLock: it cannot be passed to workers or
/// publication APIs, cannot acquire a lock, and never unlocks the shared OFD.
pub(crate) struct InheritedInstallReadLock {
    file: OwnedFd,
    run: OwnedFd,
    id: (u64, u64),
    parent_pid: u32,
    parent_pidfd: OwnedFd,
    parent_start_tick: u64,
    parent_fd: RawFd,
}

/// A second inherited, read-only OFD proof for the V2 guard retirement
/// observer. This type cannot be passed to InstallLock, StageGuard or PID1
/// mutators; closing it never unlocks the parent's original guard OFD.
pub(crate) struct InheritedGuardReadFd {
    file: OwnedFd,
    parent_fd: RawFd,
    id: (u64, u64),
}

fn bounded_fdinfo(path: String) -> Result<String> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(err)?
        .take(16 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(err)?;
    need(bytes.len() <= 16 * 1024)?;
    String::from_utf8(bytes).map_err(err)
}

fn exclusive_lock_line(info: &str, device: u64, inode: u64) -> Result<String> {
    need(held_transferred_flock_line(info, device, inode))?;
    let lines: Vec<_> = info
        .lines()
        .filter(|line| line.starts_with("lock:"))
        .collect();
    need(lines.len() == 1)?;
    Ok(lines[0].to_owned())
}

fn parent_start_tick(pid: u32) -> Result<u64> {
    let bytes = std::fs::read(format!("/proc/{pid}/stat")).map_err(err)?;
    need(bytes.len() <= 4096)?;
    let value = std::str::from_utf8(&bytes).map_err(err)?;
    let (name, rest) = value.rsplit_once(") ").ok_or(REFUSED)?;
    need(name.starts_with(&format!("{pid} (")))?;
    let fields: Vec<_> = rest.split_ascii_whitespace().collect();
    need(fields.len() >= 20 && matches!(fields[0], "R" | "S" | "D"))?;
    let tick = fields[19].parse::<u64>().map_err(err)?;
    need(tick > 0)?;
    Ok(tick)
}

fn root_parent_identity(pid: u32) -> Result<()> {
    let bytes = std::fs::read(format!("/proc/{pid}/status")).map_err(err)?;
    need(bytes.len() <= 16 * 1024)?;
    let value = std::str::from_utf8(&bytes).map_err(err)?;
    let uid: Vec<_> = value
        .lines()
        .filter(|line| line.starts_with("Uid:"))
        .collect();
    let gid: Vec<_> = value
        .lines()
        .filter(|line| line.starts_with("Gid:"))
        .collect();
    need(uid.len() == 1 && gid.len() == 1)?;
    for line in [uid[0], gid[0]] {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        need(fields.len() == 5 && fields[1..].iter().all(|value| *value == "0"))?;
    }
    Ok(())
}

impl InheritedInstallReadLock {
    /// Duplicate the original parent's exclusive install OFD for a read-only
    /// guardian stopped-guard request. This does not mint a new flock.
    pub(crate) fn duplicate_held_fd(&self) -> Result<OwnedFd> {
        self.revalidate()?;
        fd(unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) })
    }
    pub(crate) fn admit_guard_read_fd(&self, raw_fd: RawFd) -> Result<InheritedGuardReadFd> {
        self.revalidate()?;
        need(raw_fd >= 3 && raw_fd != self.parent_fd)?;
        let duplicate = fd(unsafe { libc::fcntl(raw_fd, libc::F_DUPFD_CLOEXEC, 3) })?;
        let root = root_dir()?;
        trusted_dir(&root)?;
        let var = directory(root.as_raw_fd(), "var")?;
        trusted_dir(&var)?;
        let lib = directory(var.as_raw_fd(), "lib")?;
        trusted_dir(&lib)?;
        let install = directory(lib.as_raw_fd(), "aegis-install")?;
        trusted_dir(&install)?;
        let client = directory(install.as_raw_fd(), "client")?;
        trusted_dir(&client)?;
        let named = leaf(&client, "device-guard.conf.lock", libc::O_RDONLY)?;
        let id = identity(&named)?;
        let stat = meta(&named)?;
        need(
            identity(&duplicate)? == id
                && stat.st_uid == 0
                && stat.st_gid == 0
                && stat.st_nlink == 1
                && stat.st_mode == libc::S_IFREG | 0o600,
        )?;
        let value = InheritedGuardReadFd {
            file: duplicate,
            parent_fd: raw_fd,
            id,
        };
        value.revalidate(self)?;
        Ok(value)
    }
    pub(crate) fn admit(raw_fd: RawFd) -> Result<Self> {
        need(unsafe { libc::geteuid() } == 0 && raw_fd >= 3)?;
        let parent = unsafe { libc::getppid() };
        need(parent > 1)?;
        let parent_pid = parent as u32;
        let parent_pidfd = fd(unsafe { libc::syscall(libc::SYS_pidfd_open, parent, 0) as i32 })?;
        let parent_start_tick = parent_start_tick(parent_pid)?;
        root_parent_identity(parent_pid)?;
        let duplicate = fd(unsafe { libc::fcntl(raw_fd, libc::F_DUPFD_CLOEXEC, 3) })?;
        let root = root_dir()?;
        trusted_dir(&root)?;
        let run = directory(root.as_raw_fd(), "run")?;
        trusted_dir(&run)?;
        let named = leaf(&run, "aegis-auto-install.lock", libc::O_RDONLY)?;
        let id = identity(&named)?;
        need(identity(&duplicate)? == id)?;
        let value = Self {
            file: duplicate,
            run,
            id,
            parent_pid,
            parent_pidfd,
            parent_start_tick,
            parent_fd: raw_fd,
        };
        value.revalidate()?;
        Ok(value)
    }

    pub(crate) fn revalidate(&self) -> Result<()> {
        need(unsafe { libc::getppid() } == self.parent_pid as i32)?;
        need(parent_start_tick(self.parent_pid)? == self.parent_start_tick)?;
        root_parent_identity(self.parent_pid)?;
        let mut status = libc::pollfd {
            fd: self.parent_pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        need(unsafe { libc::poll(&mut status, 1, 0) } == 0 && status.revents == 0)?;
        trusted_dir(&self.run)?;
        let root = root_dir()?;
        let current_run = directory(root.as_raw_fd(), "run")?;
        need(identity(&current_run)? == identity(&self.run)?)?;
        let named = leaf(&self.run, "aegis-auto-install.lock", libc::O_RDONLY)?;
        let stat = meta(&named)?;
        need(
            identity(&named)? == self.id
                && identity(&self.file)? == self.id
                && stat.st_uid == 0
                && stat.st_gid == 0
                && stat.st_nlink == 1
                && stat.st_mode == libc::S_IFREG | 0o600,
        )?;
        let child = bounded_fdinfo(format!("/proc/self/fdinfo/{}", self.file.as_raw_fd()))?;
        let parent = bounded_fdinfo(format!(
            "/proc/{}/fdinfo/{}",
            self.parent_pid, self.parent_fd
        ))?;
        let child_line = exclusive_lock_line(&child, self.id.0, self.id.1)?;
        let parent_line = exclusive_lock_line(&parent, self.id.0, self.id.1)?;
        need(child_line == parent_line)?;
        // A freshly opened descriptor for the same inode has no FLOCK line.
        // Both live fdinfo views sharing this lock line are the paired OFD
        // proof; neither descriptor is unlocked by this read-only observer.
        let independent = leaf(&self.run, "aegis-auto-install.lock", libc::O_RDONLY)?;
        let foreign = bounded_fdinfo(format!("/proc/self/fdinfo/{}", independent.as_raw_fd()))?;
        need(!foreign.lines().any(|line| line.starts_with("lock:")))
    }
}

impl InheritedGuardReadFd {
    pub(crate) fn revalidate(&self, install: &InheritedInstallReadLock) -> Result<()> {
        install.revalidate()?;
        let root = root_dir()?;
        let var = directory(root.as_raw_fd(), "var")?;
        let lib = directory(var.as_raw_fd(), "lib")?;
        let install_dir = directory(lib.as_raw_fd(), "aegis-install")?;
        let client = directory(install_dir.as_raw_fd(), "client")?;
        let named = leaf(&client, "device-guard.conf.lock", libc::O_RDONLY)?;
        let stat = meta(&named)?;
        need(
            identity(&named)? == self.id
                && identity(&self.file)? == self.id
                && stat.st_uid == 0
                && stat.st_gid == 0
                && stat.st_nlink == 1
                && stat.st_mode == libc::S_IFREG | 0o600,
        )?;
        let child = bounded_fdinfo(format!("/proc/self/fdinfo/{}", self.file.as_raw_fd()))?;
        let parent = bounded_fdinfo(format!(
            "/proc/{}/fdinfo/{}",
            install.parent_pid, self.parent_fd
        ))?;
        need(
            exclusive_lock_line(&child, self.id.0, self.id.1)?
                == exclusive_lock_line(&parent, self.id.0, self.id.1)?,
        )?;
        let independent = leaf(&client, "device-guard.conf.lock", libc::O_RDONLY)?;
        let foreign = bounded_fdinfo(format!("/proc/self/fdinfo/{}", independent.as_raw_fd()))?;
        need(!foreign.lines().any(|line| line.starts_with("lock:")))?;
        install.revalidate()
    }

    /// Only a duplicate of the proven OFD may cross into the bounded
    /// installed guardian readback subprocess. It has no mutation API here.
    pub(crate) fn duplicate_for_child(
        &self,
        install: &InheritedInstallReadLock,
    ) -> Result<OwnedFd> {
        self.revalidate(install)?;
        fd(unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_DUPFD, 3) })
    }
}

#[cfg(test)]
mod inherited_install_read_lock_tests {
    use super::*;
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    /// Run only inside the disposable offline Linux root container. The test
    /// uses the exact fixed /run lock and never touches a host installation.
    #[test]
    #[ignore = "requires disposable Linux root filesystem and /bin/bash with flock"]
    fn inherited_shell_lock_kernel_control() {
        let lock_path = "/run/aegis-auto-install.lock";
        if let Ok(mode) = std::env::var("AEGIS_INHERITED_LOCK_TEST_CHILD") {
            if mode == "positive" {
                let admitted = InheritedInstallReadLock::admit(9).unwrap();
                admitted.revalidate().unwrap();
                let moved = "/run/aegis-auto-install.lock.moved-test";
                assert!(!PathBuf::from(moved).exists());
                fs::rename(lock_path, moved).unwrap();
                let replacement = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(lock_path)
                    .unwrap();
                fs::set_permissions(lock_path, fs::Permissions::from_mode(0o600)).unwrap();
                assert!(admitted.revalidate().is_err());
                drop(replacement);
                fs::remove_file(lock_path).unwrap();
                fs::rename(moved, lock_path).unwrap();
                admitted.revalidate().unwrap();
            } else if mode == "parent-exited" {
                std::thread::sleep(Duration::from_millis(500));
                let refused = InheritedInstallReadLock::admit(9).is_err();
                let receipt = std::env::var("AEGIS_INHERITED_LOCK_TEST_RECEIPT").unwrap();
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(receipt)
                    .unwrap();
                use std::io::Write;
                file.write_all(if refused { b"refused\n" } else { b"accepted\n" })
                    .unwrap();
                assert!(refused);
            } else {
                panic!("unknown inherited lock control mode");
            }
            return;
        }
        assert_eq!(unsafe { libc::geteuid() }, 0);
        assert!(!PathBuf::from(lock_path).exists());
        let executable = std::env::current_exe().unwrap();
        let positive = Command::new("/bin/bash")
            .arg("-c")
            .arg("umask 077; exec 9>/run/aegis-auto-install.lock; flock -x 9; \"$AEGIS_INHERITED_LOCK_TEST_BIN\" --ignored inherited_shell_lock_kernel_control --nocapture; status=$?; exit \"$status\"")
            .env("AEGIS_INHERITED_LOCK_TEST_BIN", &executable)
            .env("AEGIS_INHERITED_LOCK_TEST_CHILD", "positive")
            .status()
            .unwrap();
        fs::remove_file(lock_path).unwrap();
        assert!(positive.success());
        let receipt = format!("/tmp/aegis-inherited-lock-{}.receipt", std::process::id());
        assert!(!PathBuf::from(&receipt).exists());
        let exited = Command::new("/bin/bash")
            .arg("-c")
            .arg("umask 077; exec 9>/run/aegis-auto-install.lock; flock -x 9; \"$AEGIS_INHERITED_LOCK_TEST_BIN\" --ignored inherited_shell_lock_kernel_control --nocapture & sleep 0.1")
            .env("AEGIS_INHERITED_LOCK_TEST_BIN", &executable)
            .env("AEGIS_INHERITED_LOCK_TEST_CHILD", "parent-exited")
            .env("AEGIS_INHERITED_LOCK_TEST_RECEIPT", &receipt)
            .status()
            .unwrap();
        assert!(exited.success());
        let mut observed = None;
        for _ in 0..100 {
            if let Ok(bytes) = fs::read(&receipt) {
                observed = Some(bytes);
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = fs::remove_file(lock_path);
        let _ = fs::remove_file(&receipt);
        assert_eq!(observed.as_deref(), Some(&b"refused\n"[..]));
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Epoch {
    pub(crate) transaction_nonce: String,
    pub(crate) original_generation: String,
    pub(crate) planned_generation: String,
    pub(crate) phase: String,
    pub(crate) old_uid: u32,
    pub(crate) old_gid: u32,
}
fn hex(value: &str, n: usize) -> bool {
    value.len() == n && value.bytes().all(|b| b.is_ascii_hexdigit())
}
impl Epoch {
    fn validate(&self) -> Result<()> {
        need(
            hex(&self.transaction_nonce, 32)
                && hex(&self.original_generation, 64)
                && hex(&self.planned_generation, 64)
                && !self.phase.is_empty()
                && self.phase.len() <= 64
                && self
                    .phase
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
        )
    }
}
/// Implement only from freshly revalidated protected StageGuard/Header data.
pub(crate) trait StopAuthority: RestorationAuthority {
    fn revalidate(&self) -> Result<()>;
    fn epoch(&self) -> Result<Epoch>;
    fn install_lock(&self) -> Result<&InstallLock>;
    fn sealed_unit_namespace_record(&self) -> Result<NamespaceRecord>;
    fn sealed_owned_unit_transitions(&self) -> Result<Vec<OwnedTransition>>;
    fn sealed_owned_unit_restorations(&self) -> Result<Vec<OwnedRestoration>>;
}
/// Event-driven bounded wait on a spawned child that this process has not
/// reaped (S9). `pidfd_open` runs while the child is unreaped, so its pid
/// cannot have been reused; the descriptor only wakes the caller early. Exit
/// status, group closure, output bounds and every deadline remain the caller's
/// own checks. Without a pidfd the previous fixed-interval poll is used.
pub(crate) struct ChildExitWait {
    pidfd: Option<OwnedFd>,
    fallback: Duration,
}
impl ChildExitWait {
    pub(crate) fn open(child: &Child, fallback: Duration) -> Self {
        let raw =
            unsafe { libc::syscall(libc::SYS_pidfd_open, child.id() as libc::pid_t, 0) } as RawFd;
        Self {
            pidfd: (raw >= 0).then(|| unsafe { OwnedFd::from_raw_fd(raw) }),
            fallback,
        }
    }
    #[cfg(test)]
    pub(crate) fn event_driven(&self) -> bool {
        self.pidfd.is_some()
    }
    /// Return once the child has exited, an `extra` descriptor is readable,
    /// or `until` passes, whichever is first. Never reaps and never decides.
    pub(crate) fn wait(&self, extra: &[RawFd], until: Instant) {
        let remaining = until.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return;
        }
        let span = if self.pidfd.is_some() {
            remaining
        } else {
            remaining.min(self.fallback)
        };
        let mut fds: Vec<libc::pollfd> = self
            .pidfd
            .iter()
            .map(|fd| fd.as_raw_fd())
            .chain(extra.iter().copied())
            .map(|fd| libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        if fds.is_empty() {
            thread::sleep(span);
            return;
        }
        let millis = span.as_millis().clamp(1, i32::MAX as u128) as i32;
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, millis) };
        if ready < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            // A poll failure is never acceptance; keep the old cadence.
            thread::sleep(self.fallback.min(span));
        }
    }
}
struct ChildOwner {
    child: Child,
    reserved: bool,
    signalled: bool,
    exit: ChildExitWait,
}
impl ChildOwner {
    fn new(child: Child) -> Self {
        let exit = ChildExitWait::open(&child, Duration::from_millis(5));
        Self {
            child,
            reserved: true,
            signalled: false,
            exit,
        }
    }
    fn exited(&mut self) -> Result<bool> {
        let mut s: libc::siginfo_t = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::waitid(
                libc::P_PID,
                self.child.id(),
                &mut s,
                libc::WNOHANG | libc::WEXITED | libc::WNOWAIT,
            )
        } < 0
        {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
                self.reserved = false;
            }
            return Err(REFUSED);
        }
        Ok(s.si_signo != 0)
    }
    fn kill(&mut self) -> Result<()> {
        if !self.reserved || self.signalled {
            return Ok(());
        }
        // Every actual signal requires a fresh nonreaping observation. The
        // owned helper is the exclusive reaper; a stale initial flag is not
        // custody when early pipe admission failed before its first poll.
        self.exited()?;
        need(self.reserved)?;
        let r = unsafe { libc::kill(-(self.child.id() as i32), libc::SIGKILL) };
        if r < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
            return Err(REFUSED);
        }
        self.signalled = true;
        Ok(())
    }
    fn finish(&mut self) -> Result<std::process::ExitStatus> {
        test_runner_mark!(Cleanup);
        need(self.reserved)?;
        self.kill()?;
        let until = Instant::now() + Duration::from_secs(2);
        loop {
            let members = group_members(self.child.id(), until)?;
            let closed = members
                .iter()
                .all(|(pid, state)| *pid == self.child.id() && *state == b'Z');
            let leader_exited = self.exited()?;
            if closed && leader_exited {
                test_runner_mark!(GroupClosed);
                break;
            }
            need(Instant::now() < until)?;
            if leader_exited {
                // Only other group members remain; the /proc scan decides.
                thread::sleep(Duration::from_millis(5));
            } else {
                self.exit.wait(&[], until);
            }
        }
        loop {
            test_runner_mark!(Reap);
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    self.reserved = false;
                    return Ok(status);
                }
                Ok(None) => {}
                Err(e) if e.raw_os_error() == Some(libc::ECHILD) => {
                    self.reserved = false;
                    return Err(REFUSED);
                }
                Err(_) => return Err(REFUSED),
            }
            need(Instant::now() < until)?;
            self.exit.wait(&[], until);
        }
    }
}
impl Drop for ChildOwner {
    fn drop(&mut self) {
        // Emergency fallback never supplies positive acceptance. Do not reap before
        // actual group closure even after an explicit cleanup failure.
        if self.reserved && self.finish().is_err() {
            eprintln!("Administrative AUTO owned command cleanup incomplete");
        }
    }
}
fn proc_member(bytes: &[u8]) -> Result<(u32, u8, u32)> {
    let text = std::str::from_utf8(bytes).map_err(err)?;
    let (pid, _) = text.split_once(' ').ok_or(REFUSED)?;
    let (_, after) = text.rsplit_once(')').ok_or(REFUSED)?;
    let fields: Vec<_> = after.split_whitespace().collect();
    need(fields.len() >= 3 && fields[0].len() == 1)?;
    Ok((
        pid.parse().map_err(err)?,
        fields[0].as_bytes()[0],
        fields[2].parse().map_err(err)?,
    ))
}
fn vanished_proc_stat(
    error: &std::io::Error,
    bytes: &[u8],
    proc: &OwnedFd,
    name: &str,
    deadline: Instant,
) -> Result<()> {
    let errno = error.raw_os_error();
    #[cfg(test)]
    runner_proc_errno(errno);
    // An unrelated process can be reaped after stat was opened. Only an
    // empty ESRCH read plus a fresh absence proof is disappearance, not a
    // partial/malformed observation or an unavailable live process.
    need(errno == Some(libc::ESRCH) && bytes.is_empty() && Instant::now() < deadline)?;
    need(!name.is_empty() && name.bytes().all(|byte| byte.is_ascii_digit()))?;
    test_runner_mark!(ProcGone);
    let raw = unsafe {
        libc::openat(
            proc.as_raw_fd(),
            c(name)?.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw >= 0 {
        drop(fd(raw)?);
        return Err(REFUSED); // Still present, including a reused PID name.
    }
    let errno = std::io::Error::last_os_error().raw_os_error();
    #[cfg(test)]
    if errno != Some(libc::ENOENT) {
        runner_proc_errno(errno);
    }
    need(errno == Some(libc::ENOENT) && Instant::now() < deadline)?;
    #[cfg(test)]
    RUNNER_TRACE.with(|trace| {
        let mut trace = trace.borrow_mut();
        trace.proc_errno = None;
        trace.proc_benign_esrch_count += 1;
    });
    Ok(())
}
fn group_members(group: u32, deadline: Instant) -> Result<Vec<(u32, u8)>> {
    test_runner_mark!(ProcScan);
    let root = root_dir()?;
    let proc = directory(root.as_raw_fd(), "proc")?;
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    test_runner_mark!(ProcFs);
    need(
        unsafe { libc::fstatfs(proc.as_raw_fd(), &mut fs) } == 0
            && fs.f_type == libc::PROC_SUPER_MAGIC,
    )?;
    let mut members = Vec::new();
    let mut count = 0usize;
    test_runner_mark!(ProcScan);
    for item in std::fs::read_dir("/proc").map_err(err)? {
        test_runner_mark!(ProcScan);
        count += 1;
        need(count <= 32768 && Instant::now() < deadline)?;
        let item = item.map_err(err)?;
        let name = item.file_name();
        let Some(name) = name.to_str() else {
            return Err(REFUSED);
        };
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let raw = unsafe {
            test_runner_mark!(ProcOpen);
            libc::openat(
                proc.as_raw_fd(),
                c(name)?.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error();
            #[cfg(test)]
            if errno == Some(libc::ENOENT) {
                runner_proc_benign_enoent();
            } else {
                runner_proc_errno(errno);
            }
            need(errno == Some(libc::ENOENT))?;
            continue;
        }
        let process = fd(raw)?;
        let raw = unsafe {
            test_runner_mark!(ProcOpen);
            libc::openat(
                process.as_raw_fd(),
                c("stat")?.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error();
            #[cfg(test)]
            if errno == Some(libc::ENOENT) {
                runner_proc_benign_enoent();
            } else {
                runner_proc_errno(errno);
            }
            need(errno == Some(libc::ENOENT))?;
            continue;
        }
        let mut value = Vec::new();
        let stat_file = File::from(fd(raw)?);
        #[cfg(test)]
        run_selected_proc_stat_after_open_hook(name.parse().map_err(err)?);
        test_runner_mark!(ProcRead);
        if let Err(error) = stat_file.take(4097).read_to_end(&mut value) {
            vanished_proc_stat(&error, &value, &proc, name, deadline)?;
            continue;
        }
        need(value.len() <= 4096)?;
        test_runner_mark!(ProcParse);
        let (pid, state, pgrp) = proc_member(&value)?;
        need(pid.to_string() == name)?;
        if pgrp == group {
            members.push((pid, state));
        }
    }
    test_runner_mark!(ProcIdentity);
    need(identity(&directory(root.as_raw_fd(), "proc")?)? == identity(&proc)?)?;
    Ok(members)
}
fn nonblock(fd: i32) -> Result<()> {
    let f = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    need(f >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, f | libc::O_NONBLOCK) } == 0)
}
fn drain<R: Read>(reader: &mut R, bytes: &mut Vec<u8>) -> Result<bool> {
    let mut b = [0u8; 1024];
    for _ in 0..8 {
        let available = (LIMIT + 1 - bytes.len()).min(b.len());
        need(available > 0)?;
        match reader.read(&mut b[..available]) {
            Ok(0) => return Ok(true),
            Ok(n) => {
                bytes.extend_from_slice(&b[..n]);
                need(bytes.len() <= LIMIT)?
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(REFUSED),
        }
    }
    Ok(false)
}
fn capture_owned(owner: &mut ChildOwner) -> Result<Vec<u8>> {
    test_runner_mark!(Pipes);
    let observed = (|| {
        let mut out = owner.child.stdout.take().ok_or(REFUSED)?;
        let mut errors = owner.child.stderr.take().ok_or(REFUSED)?;
        nonblock(out.as_raw_fd())?;
        nonblock(errors.as_raw_fd())?;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(3);
        let open = |closed: bool, fd: RawFd| (!closed).then_some(fd);
        loop {
            test_runner_mark!(Drain);
            let oe = drain(&mut out, &mut stdout);
            #[cfg(test)]
            runner_output(&stdout, &stderr, false);
            let oe = oe?;
            let ee = drain(&mut errors, &mut stderr);
            #[cfg(test)]
            runner_output(&stdout, &stderr, false);
            let ee = ee?;
            test_runner_mark!(Wait);
            if owner.exited()? {
                break;
            }
            need(Instant::now() < deadline)?;
            // Wake on exit or on pipe data; a pipe at EOF is not polled again.
            let pipes: Vec<RawFd> = [open(oe, out.as_raw_fd()), open(ee, errors.as_raw_fd())]
                .into_iter()
                .flatten()
                .collect();
            owner.exit.wait(&pipes, deadline);
        }
        owner.kill()?;
        // Reserve the exited leader with WNOWAIT throughout bounded pipe drain.
        // EOF alone is not group closure; finish separately observes /proc.
        let cleanup = Instant::now() + Duration::from_secs(2);
        loop {
            test_runner_mark!(Drain);
            let oe = drain(&mut out, &mut stdout);
            #[cfg(test)]
            runner_output(&stdout, &stderr, false);
            let oe = oe?;
            let ee = drain(&mut errors, &mut stderr);
            #[cfg(test)]
            runner_output(&stdout, &stderr, false);
            let ee = ee?;
            if oe && ee {
                #[cfg(test)]
                runner_output(&stdout, &stderr, true);
                break;
            }
            need(Instant::now() < cleanup)?;
            let pipes: Vec<RawFd> = [open(oe, out.as_raw_fd()), open(ee, errors.as_raw_fd())]
                .into_iter()
                .flatten()
                .collect();
            let pause = ChildExitWait {
                pidfd: None,
                fallback: Duration::from_millis(5),
            };
            pause.wait(&pipes, cleanup);
        }
        test_runner_mark!(Stderr);
        need(stderr.is_empty())?;
        Ok(stdout)
    })();
    let observed_stage = observed.as_ref().err().and_then(|_| reload_runner_stage());
    #[cfg(test)]
    if observed.is_err() {
        runner_first_failure(runner_stage());
    }
    // Explicit closure is required even on a timeout/output/read error. Unknown
    // ownership, signal, membership or reap failure cannot become acceptance.
    let finished = owner.finish();
    if finished.is_err() {
        reload_runner_mark(RunnerStage::Cleanup);
    }
    #[cfg(test)]
    if finished.is_err() {
        runner_first_failure(runner_stage());
        runner_cleanup_failure(runner_stage());
        runner_returned_failure(runner_stage());
    }
    let status = finished.map_err(|_| "Administrative AUTO owned command cleanup refused")?;
    #[cfg(test)]
    runner_exit(&status);
    match observed {
        Ok(bytes) => {
            test_runner_mark!(ExitStatus);
            #[cfg(test)]
            {
                if !status.success() {
                    runner_first_failure(RunnerStage::ExitStatus);
                    runner_returned_failure(RunnerStage::ExitStatus);
                }
            }
            need(status.success())?;
            Ok(bytes)
        }
        Err(e) => {
            if let Some(stage) = observed_stage {
                reload_runner_mark(stage);
            }
            #[cfg(test)]
            runner_returned_failure(runner_snapshot().first_failure.unwrap());
            Err(e)
        }
    }
}
fn capture(mut owner: ChildOwner) -> Result<Vec<u8>> {
    capture_owned(&mut owner)
}
pub(crate) enum ManagerQuery {
    Stopped,
    SearchPaths,
    UnitNamespace,
    Active,
}
fn systemctl_command(args: &[&str]) -> Result<(Vec<u8>, (u64, u64))> {
    RELOAD_RUNNER_STAGE.with(|current| current.set(None));
    systemctl_command_inner(args).map_err(|_| reload_runner_failure())
}
fn systemctl_command_inner(args: &[&str]) -> Result<(Vec<u8>, (u64, u64))> {
    test_runner_mark!(ExeAdmission);
    // Only the fixed daemon-reload uses this runner: a manager effect.
    pid1::manager_effect_boundary("daemon-reload");
    let root = root_dir()?;
    trusted_dir(&root)?;
    let usr = directory(root.as_raw_fd(), "usr")?;
    trusted_dir(&usr)?;
    let bin = directory(usr.as_raw_fd(), "bin")?;
    trusted_dir(&bin)?;
    test_runner_mark!(ExeOpen);
    let exe = leaf(&bin, "systemctl", libc::O_RDONLY)?;
    test_runner_mark!(ExeMetadata);
    let s = meta(&exe)?;
    need(
        s.st_uid == 0
            && s.st_nlink == 1
            && s.st_mode & libc::S_IFMT == libc::S_IFREG
            && s.st_mode & 0o022 == 0
            && s.st_mode & 0o111 != 0,
    )?;
    test_runner_mark!(ExeMagic);
    let mut magic = [0u8; 4];
    let mut copy = File::from(exe.try_clone().map_err(err)?);
    copy.read_exact(&mut magic).map_err(err)?;
    need(magic == *b"\x7fELF")?;
    test_runner_mark!(ExeIdentity);
    let before = identity(&exe)?;
    let command = format!("/proc/self/fd/{}", exe.as_raw_fd());
    test_runner_mark!(Spawn);
    let child = Command::new(command)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(err)?;
    let stdout = capture(ChildOwner::new(child))?;
    test_runner_mark!(ExeReadback);
    need(
        identity(&exe)? == before && identity(&leaf(&bin, "systemctl", libc::O_RDONLY)?)? == before,
    )?;
    test_runner_mark!(Accepted);
    Ok((stdout, before))
}
#[cfg(test)]
fn diagnosed_daemon_reload() -> Result<()> {
    runner_reset();
    let result = systemctl_command(&["daemon-reload"]).and_then(|(stdout, _)| {
        runner_mark(RunnerStage::Stdout);
        need(stdout.is_empty())?;
        runner_mark(RunnerStage::Accepted);
        Ok(())
    });
    if result.is_err() {
        let stage = runner_stage();
        runner_first_failure(stage);
        if runner_snapshot().returned_failure.is_none() {
            runner_returned_failure(stage);
        }
    }
    result
}
pub(crate) fn manager_query(query: ManagerQuery) -> Result<Vec<u8>> {
    pid1::query(query).map_err(err)
}
pub(crate) fn observed_account_identity(user: &str, group: &str) -> Result<(u32, u32)> {
    unix_identity(user, group)
}
fn systemctl() -> Result<Vec<u8>> {
    manager_query(ManagerQuery::Stopped)
}
fn account_file(name: &str) -> Result<Vec<u8>> {
    let root = root_dir()?;
    trusted_dir(&root)?;
    let etc = directory(root.as_raw_fd(), "etc")?;
    trusted_dir(&etc)?;
    let file = leaf(&etc, name, libc::O_RDONLY | libc::O_NONBLOCK)?;
    let m = meta(&file)?;
    need(
        m.st_uid == 0
            && m.st_nlink == 1
            && m.st_mode & libc::S_IFMT == libc::S_IFREG
            && m.st_mode & 0o022 == 0
            && m.st_size >= 0
            && m.st_size <= 1048576,
    )?;
    let mut bytes = Vec::new();
    File::from(file)
        .take(1048577)
        .read_to_end(&mut bytes)
        .map_err(err)?;
    need(bytes.len() == m.st_size as usize)?;
    Ok(bytes)
}
fn unix_identity(user: &str, group: &str) -> Result<(u32, u32)> {
    let name = if user.is_empty() { "root" } else { user };
    need(matches!(name, "root" | "aegis" | "aegis-svc"))?;
    let passwd = account_file("passwd")?;
    let mut selected = None;
    for line in std::str::from_utf8(&passwd).map_err(err)?.lines() {
        let fields: Vec<_> = line.split(':').collect();
        if fields.first() == Some(&name) {
            need(fields.len() == 7 && selected.is_none())?;
            selected = Some((
                fields[2].parse::<u32>().map_err(err)?,
                fields[3].parse::<u32>().map_err(err)?,
            ));
        }
    }
    let (uid, default_gid) = selected.ok_or(REFUSED)?;
    if group.is_empty() {
        return Ok((uid, default_gid));
    }
    need(matches!(group, "root" | "aegis" | "aegis-svc"))?;
    let groups = account_file("group")?;
    let mut gid = None;
    for line in std::str::from_utf8(&groups).map_err(err)?.lines() {
        let fields: Vec<_> = line.split(':').collect();
        if fields.first() == Some(&group) {
            need(fields.len() == 4 && gid.is_none())?;
            gid = Some(fields[2].parse::<u32>().map_err(err)?);
        }
    }
    Ok((uid, gid.ok_or(REFUSED)?))
}
#[derive(Debug, PartialEq, Eq)]
struct Unit {
    load: String,
    invocation: String,
    inactive: String,
    user: String,
    group: String,
    cgroup: String,
}
fn parse_unit(bytes: &[u8]) -> Result<Unit> {
    need(bytes.len() <= LIMIT)?;
    let text = std::str::from_utf8(bytes).map_err(err)?;
    let mut m = BTreeMap::new();
    for line in text.lines() {
        let (k, v) = line.split_once('=').ok_or(REFUSED)?;
        need(m.insert(k, v).is_none())?;
    }
    const KEYS: [&str; 11] = [
        "Id",
        "LoadState",
        "ActiveState",
        "SubState",
        "MainPID",
        "ControlPID",
        "ControlGroup",
        "InvocationID",
        "InactiveEnterTimestampMonotonic",
        "User",
        "Group",
    ];
    need(m.len() == KEYS.len() && KEYS.iter().all(|k| m.contains_key(k)))?;
    need(
        m["Id"] == UNIT
            && matches!(m["LoadState"], "loaded" | "not-found")
            && m["ActiveState"] == "inactive"
            && m["SubState"] == "dead"
            && m["MainPID"] == "0"
            && m["ControlPID"] == "0",
    )?;
    if m["LoadState"] == "not-found" {
        need(
            m["User"].is_empty()
                && m["Group"].is_empty()
                && m["ControlGroup"].is_empty()
                && m["InvocationID"].is_empty()
                && m["InactiveEnterTimestampMonotonic"] == "0",
        )?;
    }
    need(
        m["ControlGroup"].is_empty() || m["ControlGroup"] == "/system.slice/aegis-client.service",
    )?;
    need(m["InvocationID"].is_empty() || hex(m["InvocationID"], 32))?;
    need(
        !m["InactiveEnterTimestampMonotonic"].is_empty()
            && m["InactiveEnterTimestampMonotonic"]
                .bytes()
                .all(|b| b.is_ascii_digit()),
    )?;
    need(m["User"].is_empty() || matches!(m["User"], "root" | "aegis" | "aegis-svc"))?;
    need(m["Group"].is_empty() || matches!(m["Group"], "root" | "aegis" | "aegis-svc"))?;
    Ok(Unit {
        load: m["LoadState"].into(),
        invocation: m["InvocationID"].into(),
        inactive: m["InactiveEnterTimestampMonotonic"].into(),
        user: m["User"].into(),
        group: m["Group"].into(),
        cgroup: m["ControlGroup"].into(),
    })
}
fn cgroup_root() -> Result<OwnedFd> {
    let root = root_dir()?;
    trusted_dir(&root)?;
    let sys = directory(root.as_raw_fd(), "sys")?;
    trusted_dir(&sys)?;
    let fs = directory(sys.as_raw_fd(), "fs")?;
    trusted_dir(&fs)?;
    let group = directory(fs.as_raw_fd(), "cgroup")?;
    trusted_dir(&group)?;
    Ok(group)
}
fn empty_events(bytes: &[u8]) -> Result<()> {
    let mut values = BTreeMap::new();
    for line in std::str::from_utf8(bytes).map_err(err)?.lines() {
        let (k, v) = line.split_once(' ').ok_or(REFUSED)?;
        need(values.insert(k, v).is_none())?;
    }
    need(
        values.get("populated") == Some(&"0")
            && values.len() <= 2
            && values.keys().all(|k| matches!(*k, "populated" | "frozen"))
            && values.get("frozen").is_none_or(|v| matches!(*v, "0" | "1")),
    )
}
struct Cgroup {
    root: OwnedFd,
    parent: OwnedFd,
    group: Option<OwnedFd>,
}
impl Cgroup {
    fn capture() -> Result<Self> {
        let root = cgroup_root()?;
        trusted_dir(&root)?;
        let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
        need(
            unsafe { libc::fstatfs(root.as_raw_fd(), &mut fs) } == 0
                && fs.f_type == libc::CGROUP2_SUPER_MAGIC,
        )?;
        let parent = directory(root.as_raw_fd(), "system.slice")?;
        trusted_dir(&parent)?;
        let name = c(UNIT)?;
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        let group = if raw < 0 {
            need(std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT))?;
            None
        } else {
            Some(fd(raw)?)
        };
        let result = Self {
            root,
            parent,
            group,
        };
        result.revalidate()?;
        Ok(result)
    }
    fn revalidate(&self) -> Result<()> {
        let current = cgroup_root()?;
        need(identity(&current)? == identity(&self.root)?)?;
        let parent = directory(self.root.as_raw_fd(), "system.slice")?;
        need(identity(&parent)? == identity(&self.parent)?)?;
        let raw = unsafe {
            libc::openat(
                self.parent.as_raw_fd(),
                c(UNIT)?.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        match &self.group {
            None => {
                if raw >= 0 {
                    let _unexpected = fd(raw)?;
                    return Err(REFUSED);
                }
                need(std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT))
            }
            Some(group) => {
                let current = fd(raw)?;
                trusted_dir(&current)?;
                need(identity(&current)? == identity(group)?)?;
                let events = leaf(group, "cgroup.events", libc::O_RDONLY | libc::O_NONBLOCK)?;
                let procs = leaf(group, "cgroup.procs", libc::O_RDONLY | libc::O_NONBLOCK)?;
                let mut bytes = Vec::new();
                File::from(events)
                    .take(1025)
                    .read_to_end(&mut bytes)
                    .map_err(err)?;
                need(bytes.len() <= 1024)?;
                empty_events(&bytes)?;
                let mut b = [0u8; 1];
                need(File::from(procs).read(&mut b).map_err(err)? == 0)
            }
        }
    }
}
/// Read-only fixed-unit/cgroup proof for the first packaged, pre-Bind
/// recovery. The caller retains its own original InstallLock throughout the
/// subsequent Header transition; this observer grants no service action.
pub(crate) fn verify_fixed_stopped_for_fresh_prebind(lock: &InstallLock) -> Result<()> {
    let _burst = pid1::QueryBurst::begin();
    lock.revalidate()?;
    let mut pin = pid1::FixedUnitPin::acquire().map_err(err)?;
    let before = parse_unit(&systemctl()?)?;
    need(pin.is_some() == (before.load == "loaded"))?;
    if let Some(pin) = pin.as_mut() {
        pin.revalidate().map_err(err)?;
    }
    let cgroup = Cgroup::capture()?;
    if before.load == "not-found" {
        need(cgroup.group.is_none())?;
    }
    need(parse_unit(&systemctl()?)? == before)?;
    cgroup.revalidate()?;
    if let Some(pin) = pin.as_mut() {
        pin.revalidate().map_err(err)?;
    }
    lock.revalidate()
}
/// Mutation executes while the cooperative worker lock and captured cgroup FDs
/// remain held. Observations are sampled, never an anti-root activation barrier.
fn execute_identity<A: StopAuthority, T>(
    authority: &A,
    epoch: Epoch,
    record: NamespaceRecord,
    history: (Vec<OwnedTransition>, Vec<OwnedRestoration>),
    expected: (u32, u32),
    mutate: impl FnOnce() -> Result<T>,
) -> Result<T> {
    // One query burst for this stopped proof; it ends before the mutation.
    let burst = pid1::QueryBurst::begin();
    authority.install_lock()?.revalidate()?;
    authority.revalidate()?;
    epoch.validate()?;
    need(authority.epoch()? == epoch)?;
    let namespace = RestoredNamespaceView::reopen(
        &record,
        &history.0,
        &history.1,
        authority,
        authority.install_lock()?,
    )?;
    let first = parse_unit(&systemctl()?)?;
    if namespace.current_actor_absent() {
        need(first.load == "not-found" && first.user.is_empty() && first.group.is_empty())?;
    } else {
        need(first.load == "loaded" && unix_identity(&first.user, &first.group)? == expected)?;
    }
    let cgroup = Cgroup::capture()?;
    if namespace.current_actor_absent() {
        need(cgroup.group.is_none())?;
    }
    let second = parse_unit(&systemctl()?)?;
    need(first == second)?;
    authority.revalidate()?;
    need(authority.epoch()? == epoch)?;
    authority.install_lock()?.revalidate()?;
    namespace.revalidate(authority, authority.install_lock()?)?;
    cgroup.revalidate()?;
    // Namespace/epoch/account checks precede the final fixed-unit observation;
    // only held cgroup/authority checks then separate it from the callback.
    authority.install_lock()?.revalidate()?;
    namespace.revalidate(authority, authority.install_lock()?)?;
    authority.revalidate()?;
    need(authority.epoch()? == epoch)?;
    if !namespace.current_actor_absent() {
        need(unix_identity(&first.user, &first.group)? == expected)?;
    }
    need(parse_unit(&systemctl()?)? == first)?;
    cgroup.revalidate()?;
    authority.revalidate()?;
    need(authority.epoch()? == epoch)?;
    drop(burst);
    mutate()
}
pub(crate) trait PendingUnitAuthority: StopAuthority {
    fn authenticated_pending_unit_namespace(
        &self,
    ) -> Result<crate::profile_auto_unit_namespace::PendingSingletonNamespaceView>;
    fn revalidate_pending_unit_namespace(
        &self,
        view: &crate::profile_auto_unit_namespace::PendingSingletonNamespaceView,
    ) -> Result<()>;
}
pub(crate) fn execute_pending_unit_stopped<A: PendingUnitAuthority, T>(
    authority: &A,
    mutate: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let burst = pid1::QueryBurst::begin();
    authority.install_lock()?.revalidate()?;
    authority.revalidate()?;
    let epoch = authority.epoch()?;
    epoch.validate()?;
    need(epoch.phase == "Config")?;
    let namespace = authority.authenticated_pending_unit_namespace()?;
    let first = parse_unit(&systemctl()?)?;
    if namespace.current_actor_absent() {
        need(first.load == "not-found" && first.user.is_empty() && first.group.is_empty())?;
    } else {
        need(
            first.load == "loaded"
                && unix_identity(&first.user, &first.group)? == (epoch.old_uid, epoch.old_gid),
        )?;
    }
    let cgroup = Cgroup::capture()?;
    if namespace.current_actor_absent() {
        need(cgroup.group.is_none())?;
    }
    need(parse_unit(&systemctl()?)? == first)?;
    authority.revalidate_pending_unit_namespace(&namespace)?;
    cgroup.revalidate()?;
    authority.install_lock()?.revalidate()?;
    authority.revalidate()?;
    need(authority.epoch()? == epoch)?;
    authority.revalidate_pending_unit_namespace(&namespace)?;
    need(parse_unit(&systemctl()?)? == first)?;
    cgroup.revalidate()?;
    authority.revalidate()?;
    need(authority.epoch()? == epoch)?;
    drop(burst);
    mutate()
}
pub(crate) fn execute_stopped<A: StopAuthority, T>(
    authority: &A,
    mutate: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let burst = pid1::QueryBurst::begin();
    authority.revalidate()?;
    let epoch = authority.epoch()?;
    let identity = (epoch.old_uid, epoch.old_gid);
    let record = authority.sealed_unit_namespace_record()?;
    let pinned = record.clone();
    let transitions = authority.sealed_owned_unit_transitions()?;
    let restorations = authority.sealed_owned_unit_restorations()?;
    let history = (transitions, restorations);
    let pinned_history = history.clone();
    execute_identity(authority, epoch, record, history, identity, move || {
        need(
            authority.sealed_unit_namespace_record()? == pinned
                && authority.sealed_owned_unit_transitions()? == pinned_history.0
                && authority.sealed_owned_unit_restorations()? == pinned_history.1,
        )?;
        drop(burst);
        mutate()
    })
}
/// New policy identity is admitted ONLY from protected runtime binding, before
/// activation. Original service IDs remain unmodified in Epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PreparedOperation {
    PublishMetadata,
    StaticRollback,
    BeforeActivation,
}
fn prepared_phase_admitted(phase: &str, operation: PreparedOperation) -> Result<()> {
    need(match operation {
        PreparedOperation::PublishMetadata => matches!(phase, "Config" | "Metadata"),
        PreparedOperation::StaticRollback => matches!(phase, "Config" | "Metadata" | "Finalized"),
        PreparedOperation::BeforeActivation => phase == "Metadata",
    })
}
pub(crate) trait RuntimeAuthority: StopAuthority {
    /// Actual closed backend command equality + protected phase, pre-capture
    /// state and accepted-policy/installed candidate proof. No default or flag.
    fn admit_prepared_operation(&self, operation: PreparedOperation) -> Result<()>;
    fn prepared_runtime_identity(&self) -> Result<(u32, u32)>;
    fn sealed_prepared_unit_namespace_record(&self) -> Result<NamespaceRecord>;
}
pub(crate) fn execute_prepared_runtime_stopped<A: RuntimeAuthority, T>(
    authority: &A,
    operation: PreparedOperation,
    mutate: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let burst = pid1::QueryBurst::begin();
    authority.revalidate()?;
    let epoch = authority.epoch()?;
    prepared_phase_admitted(&epoch.phase, operation)?;
    authority.admit_prepared_operation(operation)?;
    let identity = authority.prepared_runtime_identity()?;
    let accepted = authority.sealed_prepared_unit_namespace_record()?;
    need(!accepted.is_absent())?;
    let pinned = accepted.clone();
    let (record, history) = if operation == PreparedOperation::StaticRollback {
        (
            authority.sealed_unit_namespace_record()?,
            (
                authority.sealed_owned_unit_transitions()?,
                authority.sealed_owned_unit_restorations()?,
            ),
        )
    } else {
        (accepted, (Vec::new(), Vec::new()))
    };
    let pinned_source = record.clone();
    let pinned_history = history.clone();
    execute_identity(authority, epoch, record, history, identity, move || {
        authority.revalidate()?;
        need(authority.sealed_prepared_unit_namespace_record()? == pinned)?;
        if operation == PreparedOperation::StaticRollback {
            need(
                authority.sealed_unit_namespace_record()? == pinned_source
                    && authority.sealed_owned_unit_transitions()? == pinned_history.0
                    && authority.sealed_owned_unit_restorations()? == pinned_history.1,
            )?;
        }
        prepared_phase_admitted(&authority.epoch()?.phase, operation)?;
        authority.admit_prepared_operation(operation)?;
        need(authority.prepared_runtime_identity()? == identity)?;
        drop(burst);
        mutate()
    })
}

pub(crate) trait CompletePolicyAuthority: RuntimeAuthority {
    /// Actual live 2 singleton/whole dropin receipts, compiled bytes, retained
    /// unknown files, protected source/epoch and installed/binding readback.
    fn authenticate_complete_published_policy(&self, records: &[OwnedTransition]) -> Result<()>;
    fn expected_dropin_paths(&self) -> Result<BTreeSet<PathBuf>>;
    fn policy_identity(&self) -> Result<String>;
    fn admit_reload_operation(&self) -> Result<()>;
    /// Exact closed Base publication callback, actual protected incoming receipt
    /// and previous Env/Dropins records, never a caller scope boolean.
    fn admit_final_base_publication(&self, incoming: &OwnedTransition) -> Result<()>;
}
/// Ephemeral non-serializable capability; only the actual checked owned command
/// producer in this module can construct it.
pub(crate) struct ReloadCompleted {
    epoch: [u8; 32],
    source: Epoch,
    policy_identity: String,
    executable: (u64, u64),
}
impl ReloadCompleted {
    pub(crate) fn validate<A: CompletePolicyAuthority>(&self, authority: &A) -> Result<()> {
        authority.revalidate()?;
        authority.install_lock()?.revalidate()?;
        need(
            self.epoch == authority.transaction_epoch()?
                && self.source == authority.epoch()?
                && self.source.phase == "Config"
                && self.policy_identity == authority.policy_identity()?
                && hex(&self.policy_identity, 64)
                && self.executable.1 != 0,
        )
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DaemonReloadReceipt {
    schema: u32,
    epoch: [u8; 32],
    source: Epoch,
    policy_identity: String,
    executable: (u64, u64),
    original_namespace: String,
    forward: BTreeMap<ManagedRole, String>,
    accepted: NamespaceRecord,
    runtime_uid: u32,
    runtime_gid: u32,
    generation: String,
}
impl DaemonReloadReceipt {
    fn compute(&self) -> Result<String> {
        use sha2::{Digest, Sha256};
        let bytes = serde_json::to_vec(&(
            self.schema,
            self.epoch,
            &self.source,
            &self.policy_identity,
            self.executable,
            &self.original_namespace,
            &self.forward,
            &self.accepted,
            self.runtime_uid,
            self.runtime_gid,
        ))
        .map_err(err)?;
        Ok(::hex::encode(Sha256::digest(bytes)))
    }
    pub(crate) fn generation(&self) -> &str {
        &self.generation
    }
    pub(crate) fn accepted_namespace(&self) -> &NamespaceRecord {
        &self.accepted
    }
    pub(crate) fn policy_identity(&self) -> &str {
        &self.policy_identity
    }
    pub(crate) fn runtime_identity(&self) -> (u32, u32) {
        (self.runtime_uid, self.runtime_gid)
    }
    pub(crate) fn validate_namespace_binding(
        &self,
        original: &NamespaceRecord,
        records: &[OwnedTransition],
        epoch: [u8; 32],
    ) -> Result<()> {
        self.source.validate()?;
        self.accepted.check_generation()?;
        need(
            self.schema == 1
                && self.epoch == epoch
                && self.source.phase == "Config"
                && self.compute()? == self.generation
                && hex(&self.policy_identity, 64)
                && hex(&self.original_namespace, 64)
                && self.forward.values().all(|v| hex(v, 64))
                && self.executable.1 != 0
                && self.forward.len() == 3,
        )?;
        need(
            self.forward.keys().copied().collect::<BTreeSet<_>>()
                == BTreeSet::from([
                    ManagedRole::BaseUnit,
                    ManagedRole::Environment,
                    ManagedRole::Dropins,
                ]),
        )?;
        if original.generation() == self.original_namespace {
            need(
                records.len() == 3
                    && records
                        .iter()
                        .map(|r| (r.role(), r.generation().to_owned()))
                        .collect::<BTreeMap<_, _>>()
                        == self.forward,
            )?;
        } else {
            need(records.is_empty() && original.generation() == self.accepted.generation())?;
        }
        Ok(())
    }
}
#[derive(Clone, Copy)]
enum StoppedGate {
    Precheck,
    Authority,
    Pid1First,
    Cgroup,
    Pid1Second,
    Postcheck,
    CgroupRevalidate,
    Pid1Final,
}
#[derive(Clone, Copy)]
enum ReloadStoppedPass {
    First,
    Second,
    Final,
}
fn reload_stopped_label(pass: ReloadStoppedPass, gate: StoppedGate) -> &'static str {
    use ReloadStoppedPass::{Final, First, Second};
    use StoppedGate::*;
    match (pass, gate) {
        (First, Precheck) => "reload_first_precheck",
        (First, Authority) => "reload_first_authority",
        (First, Pid1First) => "reload_first_pid1_first",
        (First, Cgroup) => "reload_first_cgroup",
        (First, Pid1Second) => "reload_first_pid1_second",
        (First, Postcheck) => "reload_first_postcheck",
        (First, CgroupRevalidate) => "reload_first_cgroup_revalidate",
        (First, Pid1Final) => "reload_first_pid1_final",
        (Second, Precheck) => "reload_second_precheck",
        (Second, Authority) => "reload_second_authority",
        (Second, Pid1First) => "reload_second_pid1_first",
        (Second, Cgroup) => "reload_second_cgroup",
        (Second, Pid1Second) => "reload_second_pid1_second",
        (Second, Postcheck) => "reload_second_postcheck",
        (Second, CgroupRevalidate) => "reload_second_cgroup_revalidate",
        (Second, Pid1Final) => "reload_second_pid1_final",
        (Final, Precheck) => "reload_final_precheck",
        (Final, Authority) => "reload_final_authority",
        (Final, Pid1First) => "reload_final_pid1_first",
        (Final, Cgroup) => "reload_final_cgroup",
        (Final, Pid1Second) => "reload_final_pid1_second",
        (Final, Postcheck) => "reload_final_postcheck",
        (Final, CgroupRevalidate) => "reload_final_cgroup_revalidate",
        (Final, Pid1Final) => "reload_final_pid1_final",
    }
}
/// Closed diagnostic vocabulary only. This never proves that reload ran.
pub(crate) fn reload_failure_label(error: &str) -> bool {
    if matches!(
        error,
        "reload_native_preflight"
            | "reload_native_preparation"
            | "reload_native_revalidate"
            | "reload_native_fixed_command"
            | "reload_native_fixed_executable"
            | "reload_native_fixed_spawn"
            | "reload_native_fixed_pipes"
            | "reload_native_fixed_wait"
            | "reload_native_fixed_drain"
            | "reload_native_fixed_stderr"
            | "reload_native_fixed_cleanup"
            | "reload_native_fixed_exit"
            | "reload_native_fixed_readback"
            | "reload_native_fixed_stdout"
            | "reload_native_acceptance"
            | "reload_native_completed_binding"
            | "reload_native_acceptance_lock"
            | "reload_native_namespace_capture"
            | "reload_native_receipt"
    ) {
        return true;
    }
    let Some(rest) = error.strip_prefix("reload_") else {
        return false;
    };
    let Some((pass, gate)) = rest.split_once('_') else {
        return false;
    };
    matches!(pass, "first" | "second" | "final")
        && matches!(
            gate,
            "precheck"
                | "authority"
                | "pid1_first"
                | "cgroup"
                | "pid1_second"
                | "postcheck"
                | "cgroup_revalidate"
                | "pid1_final"
        )
}
#[cfg(test)]
mod reload_closed_diagnostic_tests {
    use super::{reload_failure_label, reload_stopped_label, ReloadStoppedPass, StoppedGate};

    #[test]
    fn all_stopped_gates_are_closed_labels() {
        for pass in [
            ReloadStoppedPass::First,
            ReloadStoppedPass::Second,
            ReloadStoppedPass::Final,
        ] {
            for gate in [
                StoppedGate::Precheck,
                StoppedGate::Authority,
                StoppedGate::Pid1First,
                StoppedGate::Cgroup,
                StoppedGate::Pid1Second,
                StoppedGate::Postcheck,
                StoppedGate::CgroupRevalidate,
                StoppedGate::Pid1Final,
            ] {
                assert!(reload_failure_label(reload_stopped_label(pass, gate)));
            }
        }
        for unknown in [
            "reload_third_pid1_first",
            "reload_first_pid1_second_secret",
            "reload_native_fixed_command: stderr",
        ] {
            assert!(!reload_failure_label(unknown));
        }
    }
}
fn complete_actor_stopped_checked<A: StopAuthority>(
    authority: &A,
    expected: (u32, u32),
    check: impl Fn() -> Result<()>,
    label: impl Fn(StoppedGate) -> &'static str,
) -> Result<()> {
    // One query burst per stopped pass; a reload or effect runs only between
    // passes, after this guard has ended.
    let _burst = pid1::QueryBurst::begin();
    check().map_err(|_| label(StoppedGate::Precheck))?;
    authority
        .revalidate()
        .map_err(|_| label(StoppedGate::Authority))?;
    authority
        .install_lock()
        .and_then(|lock| lock.revalidate())
        .map_err(|_| label(StoppedGate::Authority))?;
    let first = systemctl()
        .and_then(|bytes| parse_unit(&bytes))
        .map_err(|_| label(StoppedGate::Pid1First))?;
    need(first.load == "loaded").map_err(|_| label(StoppedGate::Pid1First))?;
    let observed_identity =
        unix_identity(&first.user, &first.group).map_err(|_| label(StoppedGate::Pid1First))?;
    need(observed_identity == expected).map_err(|_| label(StoppedGate::Pid1First))?;
    let cgroup = Cgroup::capture().map_err(|_| label(StoppedGate::Cgroup))?;
    let second = systemctl()
        .and_then(|bytes| parse_unit(&bytes))
        .map_err(|_| label(StoppedGate::Pid1Second))?;
    need(first == second).map_err(|_| label(StoppedGate::Pid1Second))?;
    check().map_err(|_| label(StoppedGate::Postcheck))?;
    cgroup
        .revalidate()
        .map_err(|_| label(StoppedGate::CgroupRevalidate))?;
    authority
        .revalidate()
        .map_err(|_| label(StoppedGate::Authority))?;
    authority
        .install_lock()
        .and_then(|lock| lock.revalidate())
        .map_err(|_| label(StoppedGate::Authority))?;
    need(
        systemctl()
            .and_then(|bytes| parse_unit(&bytes))
            .map_err(|_| label(StoppedGate::Pid1Final))?
            == first,
    )
    .map_err(|_| label(StoppedGate::Pid1Final))?;
    Ok(())
}
fn complete_actor_stopped<A: StopAuthority>(
    authority: &A,
    expected: (u32, u32),
    check: impl Fn() -> Result<()>,
) -> Result<()> {
    complete_actor_stopped_checked(authority, expected, check, |_| REFUSED)
}
fn complete_actor_stopped_reload<A: StopAuthority>(
    authority: &A,
    expected: (u32, u32),
    check: impl Fn() -> Result<()>,
    pass: ReloadStoppedPass,
) -> Result<()> {
    complete_actor_stopped_checked(authority, expected, check, |gate| {
        reload_stopped_label(pass, gate)
    })
}
/// Fixed daemon-reload only. No caller argv, shell-success receipt or generic
/// root command. Only source implementation; tests never invoke this action.
pub(crate) trait ManagerRestorationAuthority: RuntimeAuthority {
    fn authenticated_restoration_manager_epoch(
        &self,
    ) -> Result<crate::profile_auto_unit_namespace::RestorationManagerEpoch>;
    fn revalidate_restoration_manager_epoch(
        &self,
        epoch: &crate::profile_auto_unit_namespace::RestorationManagerEpoch,
    ) -> Result<()>;
    fn admit_manager_restore_reload(&self) -> Result<()>;
    fn authenticate_complete_restored_policy(&self) -> Result<()>;
}
/// Non-serializable completion of this exact owned manager restoration reload.
/// It is minted only after the bounded native command returns successfully.
pub(crate) struct RestoreReloadCompleted {
    epoch: [u8; 32],
    source: Epoch,
    original_namespace: String,
    accepted_generation: String,
    forward: Vec<OwnedTransition>,
    restored: Vec<OwnedRestoration>,
    executable: (u64, u64),
}
impl RestoreReloadCompleted {
    pub(crate) fn validate<A: ManagerRestorationAuthority>(
        &self,
        authority: &A,
        original: &NamespaceRecord,
        forward: &[OwnedTransition],
        restored: &[OwnedRestoration],
    ) -> Result<()> {
        authority.revalidate()?;
        let accepted = authority.sealed_daemon_reload_receipt()?.ok_or(REFUSED)?;
        authority.authenticate_daemon_reload_receipt(&accepted)?;
        accepted.validate_namespace_binding(original, forward, self.epoch)?;
        need(
            self.epoch == authority.transaction_epoch()?
                && self.source == authority.epoch()?
                && self.original_namespace == original.generation()
                && self.accepted_generation == accepted.generation()
                && self.forward == forward
                && self.restored == restored
                && self.executable.0 != 0
                && self.executable.1 != 0
                && authority.sealed_unit_namespace_record()? == *original
                && authority.sealed_owned_unit_transitions()? == forward
                && authority.sealed_owned_unit_restorations()? == restored,
        )?;
        authority.install_lock()?.revalidate()
    }
}
pub(crate) fn execute_accepted_manager_stopped<A: ManagerRestorationAuthority, T>(
    authority: &A,
    mutate: impl FnOnce() -> Result<T>,
) -> Result<T> {
    authority.revalidate()?;
    let source = authority.epoch()?;
    need(matches!(
        source.phase.as_str(),
        "Config" | "Metadata" | "Finalized"
    ))?;
    let epoch = authority.authenticated_restoration_manager_epoch()?;
    let runtime = epoch.runtime_identity();
    complete_actor_stopped(authority, runtime, || {
        authority.revalidate_restoration_manager_epoch(&epoch)
    })?;
    authority.install_lock()?.revalidate()?;
    authority.revalidate()?;
    need(authority.epoch()? == source)?;
    complete_actor_stopped(authority, runtime, || {
        authority.revalidate_restoration_manager_epoch(&epoch)
    })?;
    mutate()
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RestoredManagerReceipt {
    schema: u32,
    epoch: [u8; 32],
    source: Epoch,
    accepted_generation: String,
    original_namespace: String,
    forward: BTreeMap<ManagedRole, String>,
    restored: BTreeMap<ManagedRole, String>,
    executable: (u64, u64),
    namespace: NamespaceRecord,
    generation: String,
}
impl RestoredManagerReceipt {
    fn compute(&self) -> Result<String> {
        use sha2::{Digest, Sha256};
        Ok(hex::encode(Sha256::digest(
            serde_json::to_vec(&(
                self.schema,
                self.epoch,
                &self.source,
                &self.accepted_generation,
                &self.original_namespace,
                &self.forward,
                &self.restored,
                self.executable,
                &self.namespace,
            ))
            .map_err(err)?,
        )))
    }
    pub(crate) fn restored_namespace(&self) -> &NamespaceRecord {
        &self.namespace
    }
    pub(crate) fn old_identity(&self) -> (u32, u32) {
        (self.source.old_uid, self.source.old_gid)
    }
    pub(crate) fn validate_current_source(&self, current: &Epoch) -> Result<()> {
        current.validate()?;
        need(
            self.source.transaction_nonce == current.transaction_nonce
                && self.source.original_generation == current.original_generation
                && self.source.planned_generation == current.planned_generation
                && self.source.old_uid == current.old_uid
                && self.source.old_gid == current.old_gid
                && matches!(
                    self.source.phase.as_str(),
                    "Config" | "Metadata" | "Finalized"
                ),
        )
    }
    pub(crate) fn validate_source_binding(
        &self,
        original: &NamespaceRecord,
        accepted: &DaemonReloadReceipt,
        forward: &[OwnedTransition],
        restored: &[OwnedRestoration],
        epoch: [u8; 32],
    ) -> Result<()> {
        self.source.validate()?;
        accepted.validate_namespace_binding(original, forward, epoch)?;
        self.namespace.matches_original_manager(original)?;
        need(
            self.schema == 1
                && self.epoch == epoch
                && self.accepted_generation == accepted.generation()
                && self.original_namespace == original.generation()
                && self.source.transaction_nonce == accepted.source.transaction_nonce
                && self.source.original_generation == accepted.source.original_generation
                && self.source.planned_generation == accepted.source.planned_generation
                && matches!(
                    self.source.phase.as_str(),
                    "Config" | "Metadata" | "Finalized"
                )
                && self.source.old_uid == accepted.source.old_uid
                && self.source.old_gid == accepted.source.old_gid
                && self.executable.0 != 0
                && self.executable.1 != 0
                && forward.len() == 3
                && restored.len() == 3
                && self.forward
                    == forward
                        .iter()
                        .map(|r| (r.role(), r.generation().to_owned()))
                        .collect()
                && self.restored
                    == restored
                        .iter()
                        .map(|r| (r.role(), r.generation().to_owned()))
                        .collect()
                && self.generation == self.compute()?,
        )
    }
}
pub(crate) trait RestoredManagerAuthority: StopAuthority {
    fn sealed_restored_manager_receipt(&self) -> Result<RestoredManagerReceipt>;
    fn authenticate_restored_manager_receipt(&self, receipt: &RestoredManagerReceipt)
        -> Result<()>;
}
/// Read-only actual restored manager/old actor observation used to converge
/// the fixed protected native completion receipt before its Header pointer.
pub(crate) fn admit_restored_manager_readback<A: StopAuthority>(
    authority: &A,
    receipt: &RestoredManagerReceipt,
) -> Result<()> {
    authority.revalidate()?;
    let source = authority.epoch()?;
    need(receipt.old_identity() == (source.old_uid, source.old_gid))?;
    complete_actor_stopped(authority, receipt.old_identity(), || {
        crate::profile_auto_unit_namespace::UnitNamespaceSnapshot::reopen(
            receipt.restored_namespace(),
            authority.install_lock()?,
        )
        .and_then(|snapshot| snapshot.revalidate(authority.install_lock()?))
    })?;
    authority.revalidate()?;
    need(authority.epoch()? == source)?;
    authority.install_lock()?.revalidate()
}
pub(crate) fn execute_restored_manager_stopped<A: RestoredManagerAuthority, T>(
    authority: &A,
    mutate: impl FnOnce() -> Result<T>,
) -> Result<T> {
    authority.revalidate()?;
    let source = authority.epoch()?;
    let receipt = authority.sealed_restored_manager_receipt()?;
    authority.authenticate_restored_manager_receipt(&receipt)?;
    need(receipt.old_identity() == (source.old_uid, source.old_gid))?;
    complete_actor_stopped(authority, receipt.old_identity(), || {
        authority.authenticate_restored_manager_receipt(&receipt)?;
        crate::profile_auto_unit_namespace::UnitNamespaceSnapshot::reopen(
            receipt.restored_namespace(),
            authority.install_lock()?,
        )
        .and_then(|s| s.revalidate(authority.install_lock()?))
    })?;
    authority.revalidate()?;
    need(authority.epoch()? == source)?;
    authority.install_lock()?.revalidate()?;
    mutate()
}
/// Actual owned fixed daemon-reload. A durable attempt is required by authority;
/// an ambiguous interrupted command is never replayed merely from manager state.
pub(crate) fn restore_service_manager<A: ManagerRestorationAuthority>(
    authority: &A,
) -> Result<RestoredManagerReceipt> {
    authority.revalidate()?;
    authority.admit_manager_restore_reload()?;
    authority.authenticate_complete_restored_policy()?;
    let source = authority.epoch()?;
    let epoch = authority.transaction_epoch()?;
    let original = authority.sealed_unit_namespace_record()?;
    let forward = authority.sealed_owned_unit_transitions()?;
    let restored = authority.sealed_owned_unit_restorations()?;
    let custody = authority.authenticated_restoration_manager_epoch()?;
    let accepted = custody.accepted_receipt().clone();
    complete_actor_stopped(authority, custody.runtime_identity(), || {
        authority.revalidate_restoration_manager_epoch(&custody)
    })?;
    authority.admit_manager_restore_reload()?;
    authority.authenticate_complete_restored_policy()?;
    need(authority.epoch()? == source && authority.transaction_epoch()? == epoch)?;
    let (stdout, executable) = systemctl_command(&["daemon-reload"])?;
    need(stdout.is_empty())?;
    let completed = RestoreReloadCompleted {
        epoch,
        source: source.clone(),
        original_namespace: original.generation().to_owned(),
        accepted_generation: accepted.generation().to_owned(),
        forward: forward.clone(),
        restored: restored.clone(),
        executable,
    };
    authority.revalidate()?;
    need(
        authority.epoch()? == source
            && authority.transaction_epoch()? == epoch
            && authority.sealed_unit_namespace_record()? == original
            && authority.sealed_owned_unit_transitions()? == forward
            && authority.sealed_owned_unit_restorations()? == restored,
    )?;
    completed.validate(authority, &original, &forward, &restored)?;
    let namespace = crate::profile_auto_unit_namespace::capture_restored_manager_namespace(
        &original,
        &forward,
        &restored,
        authority,
        &completed,
        authority.install_lock()?,
    )?;
    complete_actor_stopped(authority, (source.old_uid, source.old_gid), || {
        crate::profile_auto_unit_namespace::UnitNamespaceSnapshot::reopen(
            &namespace,
            authority.install_lock()?,
        )
        .and_then(|s| s.revalidate(authority.install_lock()?))
    })?;
    let mut receipt = RestoredManagerReceipt {
        schema: 1,
        epoch,
        source,
        accepted_generation: accepted.generation().to_owned(),
        original_namespace: original.generation().to_owned(),
        forward: forward
            .iter()
            .map(|r| (r.role(), r.generation().to_owned()))
            .collect(),
        restored: restored
            .iter()
            .map(|r| (r.role(), r.generation().to_owned()))
            .collect(),
        executable,
        namespace,
        generation: String::new(),
    };
    receipt.generation = receipt.compute()?;
    receipt.validate_source_binding(&original, &accepted, &forward, &restored, epoch)?;
    authority.admit_manager_restore_reload()?;
    Ok(receipt)
}
pub(crate) fn reload_service_policy<A: CompletePolicyAuthority>(
    authority: &A,
) -> Result<DaemonReloadReceipt> {
    authority
        .revalidate()
        .map_err(|_| "reload_native_preflight")?;
    authority
        .admit_reload_operation()
        .map_err(|_| "reload_native_preflight")?;
    let source = authority.epoch().map_err(|_| "reload_native_preflight")?;
    need(source.phase == "Config").map_err(|_| "reload_native_preflight")?;
    let epoch = authority
        .transaction_epoch()
        .map_err(|_| "reload_native_preflight")?;
    let original = authority
        .sealed_unit_namespace_record()
        .map_err(|_| "reload_native_preflight")?;
    let records = authority
        .sealed_owned_unit_transitions()
        .map_err(|_| "reload_native_preflight")?;
    need(
        authority
            .sealed_owned_unit_restorations()
            .map_err(|_| "reload_native_preflight")?
            .is_empty(),
    )
    .map_err(|_| "reload_native_preflight")?;
    authority
        .authenticate_complete_published_policy(&records)
        .map_err(|_| "reload_native_preflight")?;
    let policy_identity = authority
        .policy_identity()
        .map_err(|_| "reload_native_preflight")?;
    need(hex(&policy_identity, 64)).map_err(|_| "reload_native_preflight")?;
    let runtime = authority
        .prepared_runtime_identity()
        .map_err(|_| "reload_native_preflight")?;
    let preparation = CompletePolicyPreparation::reopen(
        authority,
        &original,
        &records,
        authority
            .install_lock()
            .map_err(|_| "reload_native_preparation")?,
    )
    .map_err(|_| "reload_native_preparation")?;
    let before_identity = if preparation.is_fresh() {
        runtime
    } else {
        (source.old_uid, source.old_gid)
    };
    complete_actor_stopped_reload(
        authority,
        before_identity,
        || preparation.revalidate(authority, authority.install_lock()?),
        ReloadStoppedPass::First,
    )?;
    authority
        .admit_reload_operation()
        .map_err(|_| "reload_native_revalidate")?;
    authority
        .authenticate_complete_published_policy(&records)
        .map_err(|_| "reload_native_revalidate")?;
    let stable = (|| -> Result<bool> {
        Ok(authority.epoch()? == source
            && authority.transaction_epoch()? == epoch
            && authority.sealed_unit_namespace_record()? == original
            && authority.sealed_owned_unit_transitions()? == records
            && authority.sealed_owned_unit_restorations()?.is_empty())
    })()
    .map_err(|_| "reload_native_revalidate")?;
    need(stable).map_err(|_| "reload_native_revalidate")?;
    // Command admission is directly after the fixed actor/source observations.
    // The real owned runner preserves its original finite limits and cleanup.
    complete_actor_stopped_reload(
        authority,
        before_identity,
        || preparation.revalidate(authority, authority.install_lock()?),
        ReloadStoppedPass::Second,
    )?;
    let (stdout, executable) = systemctl_command(&["daemon-reload"])?;
    test_runner_mark!(Stdout);
    need(stdout.is_empty()).map_err(|_| "reload_native_fixed_stdout")?;
    let completed = ReloadCompleted {
        epoch,
        source: source.clone(),
        policy_identity: policy_identity.clone(),
        executable,
    };
    completed
        .validate(authority)
        .map_err(|_| "reload_native_completed_binding")?;
    let accepted = capture_checked_policy_namespace(
        authority,
        &original,
        &records,
        &completed,
        authority
            .install_lock()
            .map_err(|_| "reload_native_acceptance_lock")?,
    )
    .map_err(|_| "reload_native_namespace_capture")?;
    complete_actor_stopped_reload(
        authority,
        runtime,
        || {
            crate::profile_auto_unit_namespace::UnitNamespaceSnapshot::reopen(
                &accepted,
                authority.install_lock()?,
            )
            .map(|_| ())
        },
        ReloadStoppedPass::Final,
    )?;
    completed
        .validate(authority)
        .map_err(|_| "reload_native_receipt")?;
    authority
        .admit_reload_operation()
        .map_err(|_| "reload_native_receipt")?;
    let stable = (|| -> Result<bool> {
        Ok(authority.sealed_unit_namespace_record()? == original
            && authority.sealed_owned_unit_transitions()? == records
            && authority.sealed_owned_unit_restorations()?.is_empty())
    })()
    .map_err(|_| "reload_native_receipt")?;
    need(stable).map_err(|_| "reload_native_receipt")?;
    let mut receipt = DaemonReloadReceipt {
        schema: 1,
        epoch,
        source,
        policy_identity,
        executable,
        original_namespace: original.generation().to_owned(),
        forward: records
            .iter()
            .map(|r| (r.role(), r.generation().to_owned()))
            .collect(),
        accepted,
        runtime_uid: runtime.0,
        runtime_gid: runtime.1,
        generation: String::new(),
    };
    receipt.generation = receipt.compute().map_err(|_| "reload_native_receipt")?;
    receipt
        .validate_namespace_binding(&original, &records, epoch)
        .map_err(|_| "reload_native_receipt")?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reload_runner_coordinates_are_closed_and_refusal_only() {
        use RunnerStage::*;
        for (stage, label) in [
            (ExeAdmission, "reload_native_fixed_executable"),
            (ExeOpen, "reload_native_fixed_executable"),
            (ExeMetadata, "reload_native_fixed_executable"),
            (ExeMagic, "reload_native_fixed_executable"),
            (ExeIdentity, "reload_native_fixed_executable"),
            (Spawn, "reload_native_fixed_spawn"),
            (Pipes, "reload_native_fixed_pipes"),
            (Wait, "reload_native_fixed_wait"),
            (Drain, "reload_native_fixed_drain"),
            (Stderr, "reload_native_fixed_stderr"),
            (Cleanup, "reload_native_fixed_cleanup"),
            (ExitStatus, "reload_native_fixed_exit"),
            (ExeReadback, "reload_native_fixed_readback"),
            (Stdout, "reload_native_fixed_stdout"),
        ] {
            reload_runner_mark(stage);
            assert_eq!(reload_runner_failure(), label);
            assert!(reload_failure_label(label));
        }
        reload_runner_mark(Accepted);
        assert_eq!(reload_runner_failure(), "reload_native_fixed_command");
        assert!(!reload_failure_label("reload_native_fixed_stderr: secret"));
    }
    fn sample() -> Vec<u8> {
        b"Id=aegis-client.service\nLoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nControlGroup=\nInvocationID=\nInactiveEnterTimestampMonotonic=123\nUser=root\nGroup=root\n".to_vec()
    }
    #[test]
    fn exact_fixed_inactive_unit_identity() {
        let v = parse_unit(&sample()).unwrap();
        assert_eq!((v.user.as_str(), v.group.as_str()), ("root", "root"));
    }
    #[test]
    fn active_main_control_and_unknown_units_refuse() {
        for (a, b) in [
            ("ActiveState=inactive", "ActiveState=active"),
            ("MainPID=0", "MainPID=7"),
            ("ControlPID=0", "ControlPID=8"),
            ("LoadState=loaded", "LoadState=not-found"),
            ("Id=aegis-client.service", "Id=other.service"),
        ] {
            assert!(parse_unit(
                String::from_utf8(sample())
                    .unwrap()
                    .replace(a, b)
                    .as_bytes()
            )
            .is_err());
        }
    }
    #[test]
    fn duplicate_missing_extra_and_foreign_cgroup_refuse() {
        let s = String::from_utf8(sample()).unwrap();
        for value in [
            format!("{s}MainPID=0\n"),
            s.replace("ControlPID=0\n", ""),
            format!("{s}Foreign=0\n"),
            s.replace("ControlGroup=\n", "ControlGroup=/foreign\n"),
        ] {
            assert!(parse_unit(value.as_bytes()).is_err());
        }
    }
    #[test]
    fn unknown_generation_and_epoch_refuse() {
        let s = String::from_utf8(sample()).unwrap();
        assert_eq!(
            parse_unit(
                s.replace(
                    "InactiveEnterTimestampMonotonic=123",
                    "InactiveEnterTimestampMonotonic=0"
                )
                .as_bytes()
            )
            .unwrap()
            .inactive,
            "0"
        );
        let e = Epoch {
            transaction_nonce: "x".into(),
            original_generation: "0".repeat(64),
            planned_generation: "0".repeat(64),
            phase: "Prepared".into(),
            old_uid: 0,
            old_gid: 0,
        };
        assert!(e.validate().is_err());
    }
    #[test]
    fn bounded_capture_rejects_extra_byte() {
        let mut r = std::io::Cursor::new(vec![7u8; LIMIT + 1]);
        let mut bytes = Vec::new();
        assert_eq!(drain(&mut r, &mut bytes), Ok(false));
        assert_eq!(bytes.len(), LIMIT);
        assert!(drain(&mut r, &mut bytes).is_err());
        assert_eq!(bytes.len(), LIMIT + 1);
    }
    #[test]
    fn empty_cgroup_requires_single_populated_zero() {
        assert!(empty_events(b"populated 0\nfrozen 0\n").is_ok());
        for s in [
            b"populated 1\n".as_slice(),
            b"populated 0\npopulated 1\n",
            b"populated 0\nforeign 0\n",
            b"frozen 0\n",
        ] {
            assert!(empty_events(s).is_err());
        }
    }
    #[test]
    #[ignore = "Owned child fixture; only invoked explicitly by runner controls"]
    fn owned_child_worker() {
        use std::io::Write;
        match std::env::var("AEGIS_STOPPED_TEST_WORKER").unwrap().as_str() {
            "normal" => std::io::stdout().write_all(b"owned-normal\n").unwrap(),
            "timeout" => thread::sleep(Duration::from_secs(10)),
            "outlives" => {
                let pid = unsafe { libc::fork() };
                assert!(pid >= 0);
                if pid == 0 {
                    unsafe {
                        libc::close(1);
                        libc::close(2);
                    }
                    thread::sleep(Duration::from_secs(10));
                    unsafe {
                        libc::_exit(0);
                    }
                }
                std::fs::write(
                    std::env::var("AEGIS_STOPPED_TEST_PID_FILE").unwrap(),
                    pid.to_string(),
                )
                .unwrap();
            }
            "flood" => {
                let mut out = std::io::stdout().lock();
                for _ in 0..100 {
                    out.write_all(&[3u8; 4096]).unwrap();
                }
            }
            _ => panic!("unadmitted worker"),
        }
    }
    fn actual_child(mode: &str) -> (ChildOwner, u32) {
        let name = "profile_auto_stopped_service::tests::owned_child_worker";
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--ignored", "--nocapture"])
            .env_clear()
            .env("AEGIS_STOPPED_TEST_WORKER", mode)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .unwrap();
        let id = child.id();
        (ChildOwner::new(child), id)
    }
    fn group_absent(pid: u32) {
        assert_eq!(unsafe { libc::kill(-(pid as i32), 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }
    #[test]
    fn actual_owned_child_normal_is_bounded_and_reaped() {
        let (child, id) = actual_child("normal");
        let value = capture(child).unwrap();
        assert!(value
            .windows(b"owned-normal".len())
            .any(|x| x == b"owned-normal"));
        group_absent(id);
    }
    #[test]
    fn actual_owned_child_timeout_is_refused_and_reaped() {
        let (child, id) = actual_child("timeout");
        assert!(capture(child).is_err());
        group_absent(id);
    }
    #[test]
    fn actual_owned_child_flood_is_refused_and_reaped() {
        let (child, id) = actual_child("flood");
        assert!(capture(child).is_err());
        assert!(
            !runner_snapshot().output_complete,
            "partial captured bytes must be labeled"
        );
        group_absent(id);
    }
    #[test]
    fn proc_read_error_requires_empty_esrch_and_fresh_absence() {
        let root = root_dir().unwrap();
        let proc = directory(root.as_raw_fd(), "proc").unwrap();
        let esrch = std::io::Error::from_raw_os_error(libc::ESRCH);
        let deadline = Instant::now() + Duration::from_secs(2);
        let current = std::process::id().to_string();
        // A live/reused numeric entry cannot be called gone even if a prior
        // held stat read reported ESRCH.
        assert!(vanished_proc_stat(&esrch, b"", &proc, &current, deadline).is_err());
        let missing = u32::MAX.to_string();
        assert!(directory(proc.as_raw_fd(), &missing).is_err());
        for errno in [
            libc::ENOENT,
            libc::EIO,
            libc::EACCES,
            libc::EPERM,
            libc::EINTR,
        ] {
            let error = std::io::Error::from_raw_os_error(errno);
            assert!(vanished_proc_stat(&error, b"", &proc, &missing, deadline).is_err());
        }
        assert!(vanished_proc_stat(&esrch, b"partial", &proc, &missing, deadline).is_err());
        assert!(vanished_proc_stat(&esrch, b"", &proc, "../self", deadline).is_err());
        assert!(vanished_proc_stat(&esrch, b"", &proc, &missing, Instant::now()).is_err());
    }
    fn shell(script: &str) -> Child {
        Command::new("/bin/sh")
            .args(["-c", script])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }
    #[test]
    fn child_exit_wait_wakes_on_exit_without_reaping() {
        let mut child = shell("exit 7");
        let exit = ChildExitWait::open(&child, Duration::from_millis(20));
        assert!(exit.event_driven(), "pidfd_open of an unreaped child");
        let started = Instant::now();
        exit.wait(&[], started + Duration::from_secs(20));
        assert!(started.elapsed() < Duration::from_secs(10));
        // The wait only wakes the caller: the status is still ours to reap.
        let status = child.wait().unwrap();
        assert_eq!(status.code(), Some(7));
    }
    #[test]
    fn child_exit_wait_never_outlasts_its_deadline_for_a_live_child() {
        let mut child = shell("sleep 30");
        let exit = ChildExitWait::open(&child, Duration::from_millis(20));
        let started = Instant::now();
        exit.wait(&[], started + Duration::from_millis(150));
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(140), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
        assert!(
            child.try_wait().unwrap().is_none(),
            "a live child is not an exit"
        );
        // An elapsed deadline returns at once; the caller refuses.
        let started = Instant::now();
        exit.wait(&[], started);
        assert!(started.elapsed() < Duration::from_millis(100));
        child.kill().unwrap();
        child.wait().unwrap();
    }
    #[test]
    fn child_exit_wait_without_pidfd_keeps_the_fixed_cadence() {
        let exit = ChildExitWait {
            pidfd: None,
            fallback: Duration::from_millis(20),
        };
        assert!(!exit.event_driven());
        let started = Instant::now();
        exit.wait(&[], started + Duration::from_secs(5));
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(19) && elapsed < Duration::from_secs(2));
    }
    #[test]
    fn actual_owned_child_exit_is_observed_without_the_old_poll_cadence() {
        // Event-driven custody still requires the full group closure, the
        // stderr-empty check and a successful status before acceptance.
        let (child, id) = actual_child("normal");
        assert!(child.exit.event_driven());
        let value = capture(child).unwrap();
        assert!(value
            .windows(b"owned-normal".len())
            .any(|x| x == b"owned-normal"));
        group_absent(id);
        runner_reset();
        let mut failing = ChildOwner::new(
            Command::new("/bin/sh")
                .args(["-c", "echo diagnostic >&2"])
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .process_group(0)
                .spawn()
                .unwrap(),
        );
        let failing_id = failing.child.id();
        assert!(capture_owned(&mut failing).is_err(), "stderr bytes refuse");
        assert_eq!(reload_runner_failure(), "reload_native_fixed_stderr");
        assert_eq!(runner_snapshot().first_failure, Some(RunnerStage::Stderr));
        assert_eq!(
            runner_snapshot().returned_failure,
            Some(RunnerStage::Stderr)
        );
        assert_eq!(runner_snapshot().exit_code, Some(0));
        assert!(runner_snapshot().output_complete && runner_snapshot().stderr_count > 0);
        assert!(!failing.reserved);
        group_absent(failing_id);
        runner_reset();
        let status = ChildOwner::new(
            Command::new("/bin/sh")
                .args(["-c", "exit 3"])
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .process_group(0)
                .spawn()
                .unwrap(),
        );
        let pid = status.child.id();
        assert!(capture(status).is_err(), "a nonzero exit refuses");
        assert_eq!(reload_runner_failure(), "reload_native_fixed_exit");
        assert_eq!(runner_stage(), RunnerStage::ExitStatus);
        assert_eq!(runner_snapshot().exit_code, Some(3));
        group_absent(pid);
    }

    #[test]
    fn actual_fifo_replacement_regular_open_is_nonblocking_refusal() {
        let root = std::env::temp_dir().join(format!(
            "aegis-stopped-fifo-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let parent = directory(libc::AT_FDCWD, root.to_str().unwrap()).unwrap();
        let path = root.join("lock");
        std::fs::write(&path, b"original").unwrap();
        std::fs::rename(&path, root.join("old")).unwrap();
        assert_eq!(
            unsafe { libc::mkfifo(c(path.to_str().unwrap()).unwrap().as_ptr(), 0o600) },
            0
        );
        let before = Instant::now();
        let opened = leaf(&parent, "lock", libc::O_RDONLY).unwrap();
        assert!(before.elapsed() < Duration::from_secs(1));
        assert_ne!(meta(&opened).unwrap().st_mode & libc::S_IFMT, libc::S_IFREG);
        drop(opened);
        drop(parent);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn actual_reaped_child_custody_loss_cannot_accept() {
        let (mut owner, _) = actual_child("normal");
        let output = owner.child.wait().unwrap();
        assert!(output.success());
        assert!(capture(owner).is_err());
        assert_ne!(runner_stage(), RunnerStage::Accepted);
    }
    #[test]
    fn actual_outliving_closed_pipe_child_is_not_eof_group_proof() {
        let root = std::env::temp_dir().join(format!(
            "aegis-stopped-child-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let file = root.join("child.pid");
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "profile_auto_stopped_service::tests::owned_child_worker",
                "--ignored",
                "--nocapture",
            ])
            .env_clear()
            .env("AEGIS_STOPPED_TEST_WORKER", "outlives")
            .env("AEGIS_STOPPED_TEST_PID_FILE", &file)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .unwrap();
        let id = child.id();
        let result = capture(ChildOwner::new(child));
        let pid = std::fs::read_to_string(&file)
            .unwrap()
            .parse::<u32>()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let members = group_members(id, deadline).unwrap();
        // Some init implementations retain an orphan zombie: refusal is required
        // then; neither pipe EOF nor the reaped leader may accept a live child.
        assert!(!members
            .iter()
            .any(|(member, state)| *member == pid && *state != b'Z'));
        if members.iter().any(|(member, _)| *member == pid) {
            assert!(result.is_err());
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn actual_reaped_child_missing_pipe_refuses_without_signal() {
        let (mut owner, id) = actual_child("normal");
        assert!(owner.child.wait().unwrap().success());
        drop(owner.child.stdout.take()); // Actual early admission failure path.
        assert!(capture_owned(&mut owner).is_err());
        assert_ne!(runner_stage(), RunnerStage::Accepted);
        assert!(
            !owner.reserved,
            "actual WNOWAIT ECHILD must revoke stale custody"
        );
        assert!(
            !owner.signalled,
            "no kill syscall admission after external reap"
        );
        group_absent(id);
    }
    fn admit_pid1_runner_test() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        assert_eq!(
            std::fs::read_to_string("/proc/1/comm").unwrap().trim(),
            "systemd"
        );
        assert_eq!(std::env::var("AEGIS_TEST_PID1_RUNNER").unwrap(), "1");
    }
    #[test]
    #[ignore = "Only on an isolated real Linux systemd PID1 fixture; explicit admission required"]
    fn actual_pid1_daemon_reload_no_churn_baseline() {
        admit_pid1_runner_test();
        for index in 0..4 {
            let result = diagnosed_daemon_reload();
            let trace = runner_snapshot();
            assert!(
                result.is_ok() && trace.stage == Some(RunnerStage::Accepted),
                "baseline {index}: closed trace {trace:?}"
            );
        }
    }
    struct ChurnGuard {
        running: std::sync::Arc<std::sync::atomic::AtomicBool>,
        child: Option<std::thread::JoinHandle<()>>,
    }
    impl ChurnGuard {
        fn stop(&mut self) {
            use std::sync::atomic::Ordering;
            self.running.store(false, Ordering::Relaxed);
            if let Some(child) = self.child.take() {
                child.join().unwrap();
            }
        }
    }
    impl Drop for ChurnGuard {
        fn drop(&mut self) {
            use std::sync::atomic::Ordering;
            self.running.store(false, Ordering::Relaxed);
            if let Some(child) = self.child.take() {
                let _ = child.join();
            }
        }
    }
    #[test]
    #[ignore = "Only on an isolated real Linux systemd PID1 fixture; explicit admission required"]
    fn actual_pid1_daemon_reload_with_unrelated_child_churn() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;
        admit_pid1_runner_test();
        let running = Arc::new(AtomicBool::new(true));
        let churned = Arc::new(AtomicUsize::new(0));
        let thread_running = running.clone();
        let thread_churned = churned.clone();
        let churn_child = thread::spawn(move || {
            while thread_running.load(Ordering::Relaxed) {
                let status = Command::new("/bin/true")
                    .env_clear()
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .unwrap();
                assert!(status.success());
                thread_churned.fetch_add(1, Ordering::Relaxed);
            }
        });
        let mut churn = ChurnGuard {
            running,
            child: Some(churn_child),
        };
        let mut first_failure = None;
        let deadline = Instant::now() + Duration::from_secs(360);
        for index in 0..64 {
            if Instant::now() >= deadline {
                first_failure = Some((index, runner_snapshot()));
                break;
            }
            match diagnosed_daemon_reload() {
                Ok(()) if runner_stage() == RunnerStage::Accepted => {}
                _ => {
                    first_failure = Some((index, runner_snapshot()));
                    break;
                }
            }
        }
        churn.stop();
        assert!(
            churned.load(Ordering::Relaxed) > 0,
            "unrelated /proc churn was absent"
        );
        assert!(
            first_failure.is_none(),
            "closed runner coordinate {first_failure:?}; no raw output"
        );
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum SigchldDisposition {
        Default,
        Ignored,
        Handler,
    }
    fn sigchld_state() -> (SigchldDisposition, bool) {
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) },
            0
        );
        let disposition = if action.sa_sigaction == libc::SIG_DFL {
            SigchldDisposition::Default
        } else if action.sa_sigaction == libc::SIG_IGN {
            SigchldDisposition::Ignored
        } else {
            SigchldDisposition::Handler
        };
        (disposition, action.sa_flags & libc::SA_NOCLDWAIT != 0)
    }
    fn assert_owned_sigchld_reaping(stage: &'static str) {
        let state = sigchld_state();
        eprintln!("closed SIGCHLD state {stage}={state:?}");
        assert_ne!(
            state.0,
            SigchldDisposition::Ignored,
            "SIGCHLD ignored at {stage}"
        );
        assert!(!state.1, "SA_NOCLDWAIT at {stage}");
    }
    fn own_reaper_probe() {
        let mut child = Command::new("/bin/true")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut observed = false;
        let mut error = None;
        while Instant::now() < deadline {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let rc = unsafe {
                libc::waitid(
                    libc::P_PID,
                    child.id(),
                    &mut info,
                    libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
                )
            };
            if rc < 0 {
                error = std::io::Error::last_os_error().raw_os_error();
                break;
            }
            if info.si_signo == libc::SIGCHLD {
                observed = true;
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        // A timed-out owned probe must be stopped. ECHILD indicates that
        // ownership has already been lost, so do not signal a possibly reused PID.
        if !observed && error.is_none() {
            if let Ok(None) = child.try_wait() {
                let _ = child.kill();
            }
        }
        let status = child.wait(); // Always attempt the owned reap, even on refusal.
        assert_eq!(error, None, "external reaper or WNOWAIT refusal");
        assert!(
            observed && status.is_ok_and(|s| s.success()),
            "owned child reaping unavailable"
        );
    }
    fn exact_production_tokio_profile_context(run: impl FnOnce()) {
        admit_pid1_runner_test();
        assert_owned_sigchld_reaping("before");
        own_reaper_probe();
        // Same runtime construction and synchronous profile dispatch as
        // main.rs:6283 and main.rs:6512. No synthetic Tokio scheduling model.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            assert_owned_sigchld_reaping("inside");
            own_reaper_probe();
            run();
            own_reaper_probe();
            assert_owned_sigchld_reaping("inside-after-run");
        });
        drop(runtime);
        assert_owned_sigchld_reaping("after-runtime");
        own_reaper_probe();
    }
    #[test]
    #[ignore = "Explicit new root/systemd PID1 fixture with external timeout and rollback only"]
    fn actual_pid1_tokio_profile_context_no_churn_baseline() {
        exact_production_tokio_profile_context(actual_pid1_daemon_reload_no_churn_baseline);
    }
    #[test]
    #[ignore = "Only after Tokio no-churn baseline; bounded 64 reloads on new PID1 fixture"]
    fn actual_pid1_tokio_profile_context_unrelated_child_churn() {
        exact_production_tokio_profile_context(
            actual_pid1_daemon_reload_with_unrelated_child_churn,
        );
    }

    struct SelectedRaceChild(std::sync::Arc<std::sync::Mutex<Option<Child>>>);
    impl Drop for SelectedRaceChild {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.lock().unwrap().take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
    struct ProcHookReset;
    impl Drop for ProcHookReset {
        fn drop(&mut self) {
            PROC_STAT_AFTER_OPEN_HOOK.with(|hook| {
                hook.borrow_mut().take();
            });
        }
    }
    #[test]
    #[ignore = "Red real /proc race regression on isolated root/systemd PID1 fixture"]
    fn actual_pid1_unrelated_proc_stat_reap_must_not_refuse_owned_reload() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Mutex};
        admit_pid1_runner_test();
        assert_owned_sigchld_reaping("race-before");
        own_reaper_probe();
        let child = Command::new("/bin/sleep")
            .arg("30")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        let selected = child.id();
        let owned = SelectedRaceChild(Arc::new(Mutex::new(Some(child))));
        assert_eq!(
            unsafe { libc::getpgid(selected as i32) },
            selected as i32,
            "selected child must own a group distinct from systemctl"
        );
        let fired = Arc::new(AtomicBool::new(false));
        let fired_for_hook = fired.clone();
        let child_for_hook = owned.0.clone();
        let _reset = ProcHookReset;
        PROC_STAT_AFTER_OPEN_HOOK.with(|hook| {
            let mut hook = hook.borrow_mut();
            assert!(hook.is_none());
            *hook = Some(ProcStatAfterOpenHook {
                selected_pid: selected,
                action: Box::new(move || {
                    let mut child = child_for_hook.lock().unwrap().take().unwrap();
                    let killed = child.kill();
                    let reaped = child.wait(); // Always reap, even if signal refused.
                    assert!(
                        killed.is_ok() && reaped.is_ok(),
                        "selected child ownership refused"
                    );
                    fired_for_hook.store(true, Ordering::Release);
                }),
            });
        });
        let result = diagnosed_daemon_reload();
        let trace = runner_snapshot();
        assert!(
            fired.load(Ordering::Acquire),
            "selected /proc stat FD was never opened"
        );
        if result.is_err() {
            assert_eq!(
                trace.first_failure,
                Some(RunnerStage::ProcRead),
                "actual race failed at a different coordinate: {trace:?}"
            );
            assert_eq!(
                trace.proc_errno,
                Some(libc::ESRCH),
                "held stat read did not produce ESRCH: {trace:?}"
            );
        }
        assert!(
            result.is_ok(),
            "RED: unrelated reaped stat FD refused owned reload: {trace:?}"
        );
        assert!(
            trace.proc_benign_esrch_count >= 1,
            "no fresh disappearance proof: {trace:?}"
        );
        assert_eq!(
            trace.proc_errno, None,
            "benign ESRCH must not become fatal evidence"
        );
        assert_eq!(
            trace.exit_code,
            Some(0),
            "owned command still needs successful exit"
        );
    }

    #[test]
    fn prepared_operation_has_closed_phase_matrix() {
        for phase in [
            "Prepared",
            "Config",
            "Metadata",
            "Finalized",
            "Captured",
            "Unknown",
            "",
        ] {
            for operation in [
                PreparedOperation::PublishMetadata,
                PreparedOperation::StaticRollback,
                PreparedOperation::BeforeActivation,
            ] {
                let expected = match operation {
                    PreparedOperation::PublishMetadata => matches!(phase, "Config" | "Metadata"),
                    PreparedOperation::StaticRollback => {
                        matches!(phase, "Config" | "Metadata" | "Finalized")
                    }
                    PreparedOperation::BeforeActivation => phase == "Metadata",
                };
                assert_eq!(
                    prepared_phase_admitted(phase, operation).is_ok(),
                    expected,
                    "{phase}/{operation:?}"
                );
            }
        }
        assert!(prepared_phase_admitted("Finalized", PreparedOperation::PublishMetadata).is_err());
        assert!(prepared_phase_admitted("Finalized", PreparedOperation::BeforeActivation).is_err());
    }

    fn structural_reload_receipt() -> (NamespaceRecord, Vec<OwnedTransition>, DaemonReloadReceipt) {
        let (original, records, accepted) =
            crate::profile_auto_unit_namespace::structural_reload_receipt_model();
        let mut receipt = DaemonReloadReceipt {
            schema: 1,
            epoch: [4; 32],
            source: Epoch {
                transaction_nonce: "1".repeat(32),
                original_generation: "2".repeat(64),
                planned_generation: "3".repeat(64),
                phase: "Config".into(),
                old_uid: 0,
                old_gid: 0,
            },
            policy_identity: "a".repeat(64),
            executable: (1, 2),
            original_namespace: original.generation().to_owned(),
            forward: records
                .iter()
                .map(|r| (r.role(), r.generation().to_owned()))
                .collect(),
            accepted,
            runtime_uid: 1000,
            runtime_gid: 1000,
            generation: String::new(),
        };
        receipt.generation = receipt.compute().unwrap();
        (original, records, receipt)
    }
    #[test]
    fn restored_manager_protocol_denies_incomplete_foreign_or_new_identity_bindings() {
        let (original, forward, accepted) = structural_reload_receipt();
        let restored = crate::profile_auto_unit_namespace::structural_restoration_records_model(
            &original, &forward,
        );
        let mut receipt = RestoredManagerReceipt {
            schema: 1,
            epoch: [4; 32],
            source: accepted.source.clone(),
            accepted_generation: accepted.generation().into(),
            original_namespace: original.generation().into(),
            forward: forward
                .iter()
                .map(|r| (r.role(), r.generation().into()))
                .collect(),
            restored: restored
                .iter()
                .map(|r| (r.role(), r.generation().into()))
                .collect(),
            executable: (1, 2),
            namespace: original.clone(),
            generation: String::new(),
        };
        receipt.generation = receipt.compute().unwrap();
        // Structural protocol linkage only: no fixture asserts actual command,
        // live namespace, descriptor generation or protected Store authority.
        receipt
            .validate_source_binding(&original, &accepted, &forward, &restored, [4; 32])
            .unwrap();
        receipt.validate_current_source(&accepted.source).unwrap();
        let mut foreign_current = accepted.source.clone();
        foreign_current.transaction_nonce = "f".repeat(32);
        assert!(receipt.validate_current_source(&foreign_current).is_err());
        assert!(receipt
            .validate_source_binding(&original, &accepted, &forward, &restored[..2], [4; 32])
            .is_err());
        assert!(receipt
            .validate_source_binding(&original, &accepted, &forward, &restored, [5; 32])
            .is_err());
        let mut wrong = receipt.clone();
        wrong.source.old_uid = accepted.runtime_identity().0;
        wrong.source.old_gid = accepted.runtime_identity().1;
        wrong.generation = wrong.compute().unwrap();
        assert!(wrong
            .validate_source_binding(&original, &accepted, &forward, &restored, [4; 32])
            .is_err());
        let mut wrong = receipt.clone();
        wrong.accepted_generation = "d".repeat(64);
        wrong.generation = wrong.compute().unwrap();
        assert!(wrong
            .validate_source_binding(&original, &accepted, &forward, &restored, [4; 32])
            .is_err());
        for field in ["nonce", "original", "planned", "phase"] {
            let mut wrong = receipt.clone();
            match field {
                "nonce" => wrong.source.transaction_nonce = "a".repeat(32),
                "original" => wrong.source.original_generation = "b".repeat(64),
                "planned" => wrong.source.planned_generation = "c".repeat(64),
                _ => wrong.source.phase = "NativeRecoveryRequired".into(),
            }
            wrong.generation = wrong.compute().unwrap();
            assert!(wrong
                .validate_source_binding(&original, &accepted, &forward, &restored, [4; 32])
                .is_err());
        }
        let mut wrong = receipt;
        wrong.namespace = accepted.accepted_namespace().clone();
        wrong.generation = wrong.compute().unwrap();
        assert!(wrong
            .validate_source_binding(&original, &accepted, &forward, &restored, [4; 32])
            .is_err());
    }
    #[test]
    fn reload_receipt_structure_binds_origin_forward_map_and_original_epoch() {
        let (original, records, receipt) = structural_reload_receipt();
        assert!(receipt
            .validate_namespace_binding(&original, &records, [4; 32])
            .is_ok());
        assert!(receipt
            .validate_namespace_binding(&original, &records, [5; 32])
            .is_err());
        assert!(receipt
            .validate_namespace_binding(&original, &records[..2], [4; 32])
            .is_err());
        assert!(receipt
            .validate_namespace_binding(receipt.accepted_namespace(), &[], [4; 32])
            .is_ok());
        assert!(receipt
            .validate_namespace_binding(receipt.accepted_namespace(), &records, [4; 32])
            .is_err());
    }
    #[test]
    fn reload_receipt_structure_rejects_tampering_even_when_rehashed() {
        let (original, records, receipt) = structural_reload_receipt();
        for change in 0..4 {
            let mut bad = receipt.clone();
            match change {
                0 => bad.source.phase = "Metadata".into(),
                1 => {
                    bad.forward.remove(&ManagedRole::Dropins);
                }
                2 => bad.executable.1 = 0,
                _ => bad.original_namespace = "f".repeat(64),
            };
            bad.generation = bad.compute().unwrap();
            assert!(bad
                .validate_namespace_binding(&original, &records, [4; 32])
                .is_err());
        }
        let mut bad = receipt;
        bad.policy_identity = "b".repeat(64);
        assert!(bad
            .validate_namespace_binding(&original, &records, [4; 32])
            .is_err());
    }
}
