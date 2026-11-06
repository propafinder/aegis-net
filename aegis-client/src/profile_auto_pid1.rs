//! Direct, peer-verified PID1 observations for administrative AUTO.
//! Query replies come from the same held connection whose SO_PEERCRED is PID1.
//! Readback alone cannot authorize StartUnit, capture, or finalization.

#![cfg(target_os = "linux")]

use std::ffi::{CString, OsStr};
use std::fs;
use std::io;
use std::mem::{self, MaybeUninit};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

const PRIVATE_SOCKET: &str = "/run/systemd/private";
const SYSTEM_BUS_SOCKET: &str = "/run/dbus/system_bus_socket";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

// Closed, diagnostic-only coordinates. No error payload, unit name, path or
// manager reply is exposed, and these values confer no retry authority.
const START_PHASES: &[&str] = &[
    "identity",
    "pre_marker",
    "subscribe",
    "claim",
    "post_claim",
    "submit",
    "submitted_receipt",
    "post_submit",
    "wait_job",
    "lookup",
    "invocation",
    "hold_main",
    "manager_recheck",
    "post_ready",
    "completed_receipt",
    "job_id_mismatch",
    "job_identity_after",
    "job_identity_before",
    "job_identity_mismatch",
    "job_path_decode",
    "job_path_mismatch",
    "job_process",
    "job_result_assert",
    "job_result_canceled",
    "job_result_decode",
    "job_result_dependency",
    "job_result_failed",
    "job_result_invalid",
    "job_result_once",
    "job_result_other",
    "job_result_skipped",
    "job_result_timeout",
    "job_result_unsupported",
    "job_signal_budget",
    "job_signal_kind",
    "job_signal_path",
    "job_signal_shape",
    "job_unit_decode",
    "job_unit_mismatch",
    "job_wait",
];
const START_CAUSES: &[&str] = &[
    "deny_lease",
    "launch_lease",
    "installed_source",
    "owner",
    "manager",
    "commitment",
    "claim_once",
    "submitted_receipt",
    "completed_receipt",
    "timeout",
    "permission",
    "io",
];
const START_FAILURE_PREFIX: &str = "AUTO PID1 start requires recovery:";

fn start_failure(phase: &str, error: &io::Error) -> String {
    let cause = match error.to_string().as_str() {
        "AUTO native deny lease changed"
        | "AUTO native deny lease changed after marker"
        | "AUTO native deny manager binding changed"
        | "AUTO wide mode lacks native deny lease" => "deny_lease",
        "AUTO launch lease changed" | "AUTO launch lease changed after marker" => "launch_lease",
        "AUTO installed source changed" | "AUTO installed source changed after marker" => {
            "installed_source"
        }
        "AUTO original stage owner changed" => "owner",
        "AUTO PID1 host identity changed" | "AUTO PID1 identity changed after marker" => "manager",
        "AUTO product commitment refused" => "commitment",
        "AUTO one-use activation marker requires recovery" => "claim_once",
        "AUTO submitted job receipt requires recovery" => "submitted_receipt",
        "AUTO completed job receipt requires recovery" => "completed_receipt",
        _ => match error.kind() {
            io::ErrorKind::TimedOut => "timeout",
            io::ErrorKind::PermissionDenied => "permission",
            _ => "io",
        },
    };
    let phase = if START_PHASES.contains(&phase) {
        phase
    } else {
        "identity"
    };
    let errno = error
        .raw_os_error()
        .filter(|n| (1..=4095).contains(n))
        .unwrap_or(0);
    format!("{START_FAILURE_PREFIX}{phase}:{cause}:{errno}")
}

pub(crate) fn start_failure_diagnostic(error: &str) -> Option<serde_json::Value> {
    let mut fields = error.strip_prefix(START_FAILURE_PREFIX)?.split(':');
    let phase = fields.next()?;
    let cause = fields.next()?;
    let raw_errno = fields.next()?;
    let errno: u16 = raw_errno.parse().ok()?;
    if fields.next().is_some()
        || !START_PHASES.contains(&phase)
        || !START_CAUSES.contains(&cause)
        || errno > 4095
        || errno.to_string() != raw_errno
    {
        return None;
    }
    Some(serde_json::json!({"phase":phase,"cause":cause,"errno":errno}))
}

/// Ignore only a completely unrelated manager job. Any collision with this
/// owner's ID, path or unpredictable unit must retain all three exact checks.
fn job_removed_relevant(
    expected_id: u32,
    expected_path: &str,
    expected_unit: &str,
    id: u32,
    path: &str,
    unit: &str,
) -> bool {
    id == expected_id || path == expected_path || unit == expected_unit
}

fn owned_job_notice(
    expected_id: u32,
    expected_path: &str,
    expected_unit: &str,
    id: u32,
    path: &str,
    unit: &str,
) -> io::Result<bool> {
    if !job_removed_relevant(expected_id, expected_path, expected_unit, id, path, unit) {
        return Ok(false);
    }
    if id != expected_id || path != expected_path || unit != expected_unit {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "PID1 owned job signal binding changed",
        ));
    }
    Ok(true)
}

/// Unpredictable actual unit identity. Only the verified PID1 preparation path
/// can mint it; no JSON, path or caller string constructor exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PrivateUnit {
    name: String,
}

impl PrivateUnit {
    fn mint() -> io::Result<Self> {
        let mut bytes = [0u8; 32];
        let mut offset = 0;
        while offset < bytes.len() {
            let read = unsafe {
                libc::getrandom(bytes[offset..].as_mut_ptr().cast(), bytes.len() - offset, 0)
            };
            if read < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if read <= 0 {
                return Err(io::Error::last_os_error());
            }
            offset += read as usize;
        }
        let token: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(Self {
            name: format!("aegis-auto@{token}.service"),
        })
    }
    pub(crate) fn name(&self) -> &str {
        &self.name
    }
}

fn private_unit_name(name: &str) -> bool {
    name.strip_prefix("aegis-auto@")
        .and_then(|name| name.strip_suffix(".service"))
        .is_some_and(|token| {
            token.len() == 64
                && token
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
}

#[derive(Debug)]
pub(super) struct VerifiedSocketPeer {
    _stream: UnixStream,
    _parent: OwnedFd,
    _pidfd: OwnedFd,
    boot_id: String,
}

#[derive(Debug)]
struct HeldCgroup {
    directory: OwnedFd,
    parent: OwnedFd,
    basename: CString,
    path: PathBuf,
    identity: (u64, u64),
}

impl VerifiedSocketPeer {
    pub(super) fn boot_id(&self) -> &str {
        &self.boot_id
    }
}

/// Verifies an actual PID1 peer on the fixed private manager socket.
/// The resulting value cannot authorize a manager operation by itself.
pub(super) fn connect_pid1_readonly() -> io::Result<VerifiedSocketPeer> {
    connect_checked(Path::new(PRIVATE_SOCKET), 1, 0, true)
}

fn refuse(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason)
}

fn cstring(os: &OsStr) -> io::Result<CString> {
    CString::new(os.as_bytes()).map_err(|_| refuse("NUL in socket path"))
}

fn open_dir(parent: i32, component: &OsStr) -> io::Result<OwnedFd> {
    let name = cstring(component)?;
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_CLOEXEC | libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn stat_leaf(parent: i32, leaf: &OsStr) -> io::Result<libc::stat> {
    let name = cstring(leaf)?;
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    let rc = unsafe {
        libc::fstatat(
            parent,
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { stat.assume_init() })
}

fn dir_identity(fd: i32) -> io::Result<(u64, u64)> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let stat = unsafe { stat.assume_init() };
    Ok((stat.st_dev, stat.st_ino))
}

fn open_held_parent(names: &[&OsStr], strict: bool) -> io::Result<OwnedFd> {
    let root = CString::new("/").unwrap();
    let raw = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut parent = unsafe { OwnedFd::from_raw_fd(raw) };
    check_dir(parent.as_raw_fd(), strict)?;
    for name in names {
        parent = open_dir(parent.as_raw_fd(), name)?;
        check_dir(parent.as_raw_fd(), strict)?;
    }
    Ok(parent)
}

fn connect_checked(
    path: &Path,
    expected_pid: u32,
    expected_uid: u32,
    strict: bool,
) -> io::Result<VerifiedSocketPeer> {
    connect_checked_with_hook(path, expected_pid, expected_uid, strict, || {})
}

fn connect_checked_with_hook(
    path: &Path,
    expected_pid: u32,
    expected_uid: u32,
    strict: bool,
    after_snapshot: impl FnOnce(),
) -> io::Result<VerifiedSocketPeer> {
    if !path.is_absolute() {
        return Err(refuse("socket path is not absolute"));
    }
    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Err(refuse("socket path has no root"));
    }
    let mut names = Vec::new();
    for component in components {
        match component {
            Component::Normal(name) => names.push(name),
            _ => return Err(refuse("socket path contains noncanonical component")),
        }
    }
    let leaf = names.pop().ok_or_else(|| refuse("socket leaf missing"))?;
    let parent = open_held_parent(&names, strict)?;
    let parent_identity = dir_identity(parent.as_raw_fd())?;
    let before = stat_leaf(parent.as_raw_fd(), leaf)?;
    if before.st_mode & libc::S_IFMT != libc::S_IFSOCK || before.st_uid != expected_uid {
        return Err(refuse("private socket identity mismatch"));
    }
    after_snapshot();
    // AF_UNIX has no connectat. The procfd magic-link path resolves through
    // the exact held directory, even if the original pathname is replaced.
    let held_path = PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd())).join(leaf);
    let stream = connect_bounded(&held_path, CONNECT_TIMEOUT)?;
    let after = stat_leaf(parent.as_raw_fd(), leaf)?;
    if before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_mode != after.st_mode
        || before.st_uid != after.st_uid
    {
        return Err(refuse("private socket replaced during connect"));
    }
    let named_parent = open_held_parent(&names, strict)?;
    if dir_identity(named_parent.as_raw_fd())? != parent_identity {
        return Err(refuse("private socket parent replaced during connect"));
    }
    let peer = peercred(stream.as_raw_fd())?;
    // The fixed, protected system-bus listener may be socket activated by
    // PID1 or owned by the distro bus daemon. It is used only for a RefUnit
    // lease whose unique destination is separately verified as PID1/UID0.
    // Every private-manager caller still requires exact PID1 credentials.
    let pin_bus =
        expected_pid == 0 && expected_uid == 0 && strict && path == Path::new(SYSTEM_BUS_SOCKET);
    if peer.pid <= 0
        || (!pin_bus && peer.pid as u32 != expected_pid)
        || (!pin_bus && peer.uid != expected_uid)
        || (!pin_bus && strict && peer.gid != 0)
    {
        return Err(refuse("connected manager peer identity mismatch"));
    }
    let raw_pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, peer.pid, 0) as i32 };
    if raw_pidfd < 0 {
        return Err(io::Error::last_os_error());
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw_pidfd) };
    let mut event = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&mut event, 1, 0) } != 0 || event.revents != 0 {
        return Err(refuse("manager peer already exited"));
    }
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let boot_id = boot_id.trim().to_owned();
    if boot_id.len() != 36 || !boot_id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        return Err(refuse("boot identity invalid"));
    }
    Ok(VerifiedSocketPeer {
        _stream: stream,
        _parent: parent,
        _pidfd: pidfd,
        boot_id,
    })
}

fn check_dir(fd: i32, strict: bool) -> io::Result<()> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let stat = unsafe { stat.assume_init() };
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(refuse("socket ancestor is not a directory"));
    }
    if strict && (stat.st_uid != 0 || stat.st_mode & 0o022 != 0) {
        return Err(refuse("socket ancestor is not root owned and stable"));
    }
    Ok(())
}

fn peercred(fd: i32) -> io::Result<libc::ucred> {
    let mut peer = MaybeUninit::<libc::ucred>::uninit();
    let mut len = mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            peer.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != mem::size_of::<libc::ucred>() {
        return Err(refuse("short peer credentials"));
    }
    Ok(unsafe { peer.assume_init() })
}

fn connect_bounded(path: &Path, timeout: Duration) -> io::Result<UnixStream> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= 108 || bytes.contains(&0) {
        return Err(refuse("private socket path invalid"));
    }
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut address: libc::sockaddr_un = unsafe { mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (slot, byte) in address.sun_path.iter_mut().zip(bytes.iter()) {
        *slot = *byte as libc::c_char;
    }
    let len = (mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1) as libc::socklen_t;
    let rc = unsafe {
        libc::connect(
            socket.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            len,
        )
    };
    if rc < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS)
            && error.raw_os_error() != Some(libc::EAGAIN)
        {
            return Err(error);
        }
        let start = Instant::now();
        loop {
            let remaining = timeout.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "private socket connect timed out",
                ));
            }
            let mut event = libc::pollfd {
                fd: socket.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            let millis = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
            let rc = unsafe { libc::poll(&mut event, 1, millis) };
            if rc < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            if rc == 0 {
                continue;
            }
            let mut error: libc::c_int = 0;
            let mut size = mem::size_of_val(&error) as libc::socklen_t;
            if unsafe {
                libc::getsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    (&mut error as *mut libc::c_int).cast(),
                    &mut size,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            if error != 0 {
                return Err(io::Error::from_raw_os_error(error));
            }
            break;
        }
    }
    let stream = UnixStream::from(socket);
    stream.set_nonblocking(false)?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn start_diagnostics_keep_closed_coordinates_and_drop_private_payloads() {
        let error = io::Error::other("secret invitation /private/source 192.0.2.1");
        let encoded = start_failure("post_submit", &error);
        assert!(!encoded.contains("secret"));
        assert_eq!(
            start_failure_diagnostic(&encoded).unwrap(),
            serde_json::json!({"phase":"post_submit","cause":"io","errno":0})
        );
        let encoded = start_failure(
            "post_submit",
            &io::Error::other("AUTO native deny lease changed after marker"),
        );
        assert_eq!(
            start_failure_diagnostic(&encoded).unwrap()["cause"],
            "deny_lease"
        );
        for suffix in [
            "private:io:0",
            "submit:private:0",
            "submit:io:4096",
            "submit:io:01",
            "submit:io:0:private",
        ] {
            assert!(start_failure_diagnostic(&format!("{START_FAILURE_PREFIX}{suffix}")).is_none());
        }
    }

    #[test]
    fn unrelated_pid1_jobs_cannot_consume_the_owned_job() {
        for id in 1..10_000 {
            if id == 42 {
                continue;
            }
            assert!(!owned_job_notice(
                42,
                "/job/42",
                "owned.service",
                id,
                &format!("/job/{id}"),
                "background.service"
            )
            .unwrap());
        }
        assert!(owned_job_notice(
            42,
            "/job/42",
            "owned.service",
            42,
            "/job/42",
            "owned.service"
        )
        .unwrap());
        for (id, path, unit) in [
            (41, "/job/42", "owned.service"),
            (42, "/job/41", "owned.service"),
            (42, "/job/42", "background.service"),
            (41, "/job/41", "owned.service"),
        ] {
            assert!(owned_job_notice(42, "/job/42", "owned.service", id, path, unit).is_err());
        }
    }

    #[test]
    fn same_unit_with_new_job_identity_requires_recovery() {
        // PID1 may replace a queued job. A matching unit is related even when
        // both the numeric ID and object path differ from the submitted job.
        assert!(job_removed_relevant(
            42,
            "/job/42",
            "owned.service",
            77,
            "/job/77",
            "owned.service"
        ));
        assert!(owned_job_notice(
            42,
            "/job/42",
            "owned.service",
            77,
            "/job/77",
            "owned.service"
        )
        .is_err());
    }

    fn fixture() -> (std::path::PathBuf, UnixListener) {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "aegis-b02-pid1-peer-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&dir).unwrap();
        let socket = dir.join("private");
        let listener = UnixListener::bind(&socket).unwrap();
        (socket, listener)
    }

    #[test]
    fn real_peer_custody_and_wrong_pid_refusal() {
        let (socket, listener) = fixture();
        let uid = unsafe { libc::geteuid() };
        let peer = connect_checked(&socket, std::process::id(), uid, false).unwrap();
        assert!(!peer.boot_id().is_empty());
        assert!(peer._stream.as_raw_fd() >= 0);
        assert!(connect_checked(&socket, std::process::id() + 1, uid, false).is_err());
        assert!(connect_checked(&socket, std::process::id(), uid + 1, false).is_err());
        drop(peer);
        drop(listener);
        fs::remove_file(&socket).unwrap();
        fs::remove_dir(socket.parent().unwrap()).unwrap();
    }

    #[test]
    fn symlink_socket_refused_before_connect() {
        let (socket, listener) = fixture();
        let link = socket.parent().unwrap().join("link");
        std::os::unix::fs::symlink(&socket, &link).unwrap();
        let uid = unsafe { libc::geteuid() };
        assert!(connect_checked(&link, std::process::id(), uid, false).is_err());
        drop(listener);
        fs::remove_file(&link).unwrap();
        fs::remove_file(&socket).unwrap();
        fs::remove_dir(socket.parent().unwrap()).unwrap();
    }

    #[test]
    fn absent_socket_refused() {
        let dir = std::env::temp_dir().join(format!("aegis-b02-absent-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        assert!(connect_checked(
            &dir.join("private"),
            std::process::id(),
            unsafe { libc::geteuid() },
            false
        )
        .is_err());
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn symlink_ancestor_and_parent_component_refused() {
        let (socket, listener) = fixture();
        let parent = socket.parent().unwrap();
        let linked_parent = parent.with_extension("link");
        std::os::unix::fs::symlink(parent, &linked_parent).unwrap();
        let uid = unsafe { libc::geteuid() };
        assert!(connect_checked(
            &linked_parent.join("private"),
            std::process::id(),
            uid,
            false
        )
        .is_err());
        assert!(connect_checked(
            &parent
                .join("..")
                .join(parent.file_name().unwrap())
                .join("private"),
            std::process::id(),
            uid,
            false
        )
        .is_err());
        drop(listener);
        fs::remove_file(linked_parent).unwrap();
        fs::remove_file(&socket).unwrap();
        fs::remove_dir(parent).unwrap();
    }

    #[test]
    fn replaced_named_parent_cannot_redirect_held_connection() {
        let (socket, original_listener) = fixture();
        original_listener.set_nonblocking(true).unwrap();
        let parent = socket.parent().unwrap().to_path_buf();
        let moved = parent.with_extension("moved");
        let mut rogue_listener = None;
        let uid = unsafe { libc::geteuid() };
        let result = connect_checked_with_hook(&socket, std::process::id(), uid, false, || {
            fs::rename(&parent, &moved).unwrap();
            fs::create_dir(&parent).unwrap();
            let listener = UnixListener::bind(parent.join("private")).unwrap();
            listener.set_nonblocking(true).unwrap();
            rogue_listener = Some(listener);
        });
        assert!(result.is_err());
        assert!(original_listener.accept().is_ok());
        assert_eq!(
            rogue_listener
                .as_ref()
                .unwrap()
                .accept()
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        drop(rogue_listener);
        drop(original_listener);
        fs::remove_file(parent.join("private")).unwrap();
        fs::remove_dir(&parent).unwrap();
        fs::remove_file(moved.join("private")).unwrap();
        fs::remove_dir(moved).unwrap();
    }

    #[test]
    #[ignore = "requires an isolated root container with private /run"]
    fn strict_root_owned_ancestor_and_peer_path() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let parent = PathBuf::from(format!("/run/aegis-b02-pid1-r30-{}", std::process::id()));
        fs::create_dir(&parent).unwrap();
        let socket = parent.join("private");
        let listener = UnixListener::bind(&socket).unwrap();
        assert!(connect_checked(&socket, std::process::id(), 0, true).is_ok());
        drop(listener);
        fs::remove_file(socket).unwrap();
        fs::remove_dir(parent).unwrap();
    }

    #[test]
    #[ignore = "actual disposable Ubuntu PID1; creates only a private runtime no-network unit"]
    fn actual_pid1_start_stop_jobs_are_correlated_on_one_verified_connection() {
        bus::native_job_control();
    }

    #[test]
    #[ignore = "actual disposable Ubuntu system manager; never a container stub"]
    fn actual_pid1_queries_use_verified_peer_and_preserve_manager_state() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let read = || {
            std::process::Command::new("/usr/bin/systemctl")
                .args(["show", "--property=Version,UnitPath"])
                .env_clear()
                .env("LC_ALL", "C")
                .output()
                .unwrap()
        };
        let before = read();
        assert!(before.status.success());
        let direct = query(super::super::ManagerQuery::SearchPaths).unwrap();
        let fields = |bytes: &[u8]| {
            let mut fields: Vec<String> = std::str::from_utf8(bytes)
                .unwrap()
                .lines()
                .map(str::to_owned)
                .collect();
            fields.sort();
            fields
        };
        assert_eq!(fields(&before.stdout), fields(&direct));
        let namespace = query(super::super::ManagerQuery::UnitNamespace).unwrap();
        assert!(std::str::from_utf8(&namespace)
            .unwrap()
            .lines()
            .any(|line| line == "Id=aegis-client.service"));
        let stopped = query(super::super::ManagerQuery::Stopped).unwrap();
        assert!(std::str::from_utf8(&stopped)
            .unwrap()
            .lines()
            .any(|line| line == "ActiveState=inactive"));
        let after = read();
        assert!(after.status.success());
        assert_eq!(fields(&before.stdout), fields(&after.stdout));
    }

    #[test]
    #[ignore = "actual disposable Ubuntu system manager; never a container stub"]
    fn actual_pid1_query_burst_shares_one_verified_connection_and_never_spans_a_reload() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let fresh = query(super::super::ManagerQuery::SearchPaths).unwrap();
        let burst = QueryBurst::begin();
        for _ in 0..8 {
            // Every reused query re-reads every property and still matches
            // today's fresh-connection answer.
            assert_eq!(
                query(super::super::ManagerQuery::SearchPaths).unwrap(),
                fresh
            );
            assert!(query(super::super::ManagerQuery::UnitNamespace).is_ok());
        }
        // On a bare host the guardian unit is absent and this read refuses;
        // a refused read drops the held link and the next query opens
        // today's fresh connection and still answers.
        let _ = guardian_service_identity();
        assert_eq!(
            query(super::super::ManagerQuery::SearchPaths).unwrap(),
            fresh
        );
        drop(burst);
        // Without a burst, a reload boundary is silent and today's path holds.
        manager_effect_boundary("daemon-reload");
        assert_eq!(
            query(super::super::ManagerQuery::SearchPaths).unwrap(),
            fresh
        );
    }
}

// systemd255 ABI: https://github.com/systemd/systemd/blob/v255/src/systemd/sd-bus.h
// Dynamic loading preserves ordinary client operation on hosts without systemd.
// Only the fixed native system library is admitted; no PATH or bus address input.
mod bus {
    use super::*;
    use std::cell::RefCell;
    use std::ffi::{c_char, c_int, c_void, CStr};
    use std::os::fd::IntoRawFd;
    use std::ptr;
    use std::rc::Rc;

    type Bus = c_void;
    type Message = c_void;
    #[repr(C)]
    struct Error {
        name: *const c_char,
        message: *const c_char,
        need_free: c_int,
    }
    type New = unsafe extern "C" fn(*mut *mut Bus) -> c_int;
    type SetFd = unsafe extern "C" fn(*mut Bus, c_int, c_int) -> c_int;
    type SetTimeout = unsafe extern "C" fn(*mut Bus, u64) -> c_int;
    type SetClient = unsafe extern "C" fn(*mut Bus, c_int) -> c_int;
    type BusInt = unsafe extern "C" fn(*mut Bus) -> c_int;
    type Process = unsafe extern "C" fn(*mut Bus, *mut *mut Message) -> c_int;
    type Wait = unsafe extern "C" fn(*mut Bus, u64) -> c_int;
    type Close = unsafe extern "C" fn(*mut Bus) -> *mut Bus;
    type Get = unsafe extern "C" fn(
        *mut Bus,
        *const c_char,
        *const c_char,
        *const c_char,
        *const c_char,
        *mut Error,
        *mut *mut Message,
        *const c_char,
    ) -> c_int;
    type Call = unsafe extern "C" fn(
        *mut Bus,
        *const c_char,
        *const c_char,
        *const c_char,
        *const c_char,
        *mut Error,
        *mut *mut Message,
        *const c_char,
        ...
    ) -> c_int;
    type Read = unsafe extern "C" fn(*mut Message, *const c_char, ...) -> c_int;
    type Array =
        unsafe extern "C" fn(*mut Message, c_char, *mut *const c_void, *mut usize) -> c_int;
    type Container = unsafe extern "C" fn(*mut Message, c_char, *const c_char) -> c_int;
    type Unref = unsafe extern "C" fn(*mut Message) -> *mut Message;
    type FreeError = unsafe extern "C" fn(*mut Error) -> *mut Error;
    type IsSignal = unsafe extern "C" fn(*mut Message, *const c_char, *const c_char) -> c_int;
    type MessagePath = unsafe extern "C" fn(*mut Message) -> *const c_char;
    type NewMethod = unsafe extern "C" fn(
        *mut Bus,
        *mut *mut Message,
        *const c_char,
        *const c_char,
        *const c_char,
        *const c_char,
    ) -> c_int;
    type AppendBasic = unsafe extern "C" fn(*mut Message, c_char, *const c_void) -> c_int;
    type CloseContainer = unsafe extern "C" fn(*mut Message) -> c_int;
    type CallMessage =
        unsafe extern "C" fn(*mut Bus, *mut Message, u64, *mut Error, *mut *mut Message) -> c_int;

    struct Api {
        handle: *mut c_void,
        _library: OwnedFd,
        new: New,
        set_fd: SetFd,
        set_client: SetClient,
        timeout: SetTimeout,
        start: BusInt,
        ready: BusInt,
        process: Process,
        wait: Wait,
        close: Close,
        get: Get,
        call: Call,
        read: Read,
        array: Array,
        enter: Container,
        unref: Unref,
        free_error: FreeError,
        is_signal: IsSignal,
        message_path: MessagePath,
        new_method: NewMethod,
        append_basic: AppendBasic,
        open_container: Container,
        close_container: CloseContainer,
        call_message: CallMessage,
    }
    impl Drop for Api {
        fn drop(&mut self) {
            // Every Bus/Message is dropped before its borrowed API.
            unsafe {
                libc::dlclose(self.handle);
            }
        }
    }
    fn checked(rc: c_int) -> io::Result<c_int> {
        if rc < 0 {
            Err(io::Error::from_raw_os_error(-rc))
        } else {
            Ok(rc)
        }
    }
    /// The loader-environment check, the held-parent walk of /usr/lib/<arch>,
    /// the openat of the distro SONAME and its root-owned regular-file check.
    /// Every Api::load and every QueryBurst query run exactly this code.
    fn open_library() -> io::Result<OwnedFd> {
        if std::env::vars_os().any(|(key, _)| key.as_encoded_bytes().starts_with(b"LD_")) {
            return Err(refuse("dynamic loader environment refused"));
        }
        let arch = match std::env::consts::ARCH {
            "aarch64" => OsStr::new("aarch64-linux-gnu"),
            "x86_64" => OsStr::new("x86_64-linux-gnu"),
            _ => return Err(refuse("unsupported native systemd architecture")),
        };
        let parent = open_held_parent(&[OsStr::new("usr"), OsStr::new("lib"), arch], true)?;
        let name = CString::new("libsystemd.so.0").unwrap();
        // The distro SONAME is a root-owned symlink. Open its resolved
        // regular inode through the held trusted directory, then hold it
        // through dlopen and every symbol use; never execute a caller path.
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let library = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        checked(unsafe { libc::fstat(library.as_raw_fd(), stat.as_mut_ptr()) })?;
        let stat = unsafe { stat.assume_init() };
        if stat.st_uid != 0
            || stat.st_mode & 0o022 != 0
            || stat.st_mode & libc::S_IFMT != libc::S_IFREG
        {
            return Err(refuse("untrusted native systemd library"));
        }
        Ok(library)
    }
    impl Api {
        fn load() -> io::Result<Self> {
            let library = open_library()?;
            let path = CString::new(format!("/proc/self/fd/{}", library.as_raw_fd())).unwrap();
            let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
            if handle.is_null() {
                return Err(refuse("native systemd library unavailable"));
            }
            macro_rules! symbol {
                ($name:literal, $kind:ty) => {{
                    let p = unsafe { libc::dlsym(handle, concat!($name, "\0").as_ptr().cast()) };
                    if p.is_null() {
                        unsafe {
                            libc::dlclose(handle);
                        }
                        return Err(refuse("native systemd ABI unavailable"));
                    }
                    // Exact ABI prototypes are fixed above, not caller data.
                    unsafe { mem::transmute::<*mut c_void, $kind>(p) }
                }};
            }
            Ok(Self {
                handle,
                _library: library,
                new: symbol!("sd_bus_new", New),
                set_fd: symbol!("sd_bus_set_fd", SetFd),
                set_client: symbol!("sd_bus_set_bus_client", SetClient),
                timeout: symbol!("sd_bus_set_method_call_timeout", SetTimeout),
                start: symbol!("sd_bus_start", BusInt),
                ready: symbol!("sd_bus_is_ready", BusInt),
                process: symbol!("sd_bus_process", Process),
                wait: symbol!("sd_bus_wait", Wait),
                close: symbol!("sd_bus_close_unref", Close),
                get: symbol!("sd_bus_get_property", Get),
                call: symbol!("sd_bus_call_method", Call),
                read: symbol!("sd_bus_message_read", Read),
                array: symbol!("sd_bus_message_read_array", Array),
                enter: symbol!("sd_bus_message_enter_container", Container),
                unref: symbol!("sd_bus_message_unref", Unref),
                free_error: symbol!("sd_bus_error_free", FreeError),
                is_signal: symbol!("sd_bus_message_is_signal", IsSignal),
                message_path: symbol!("sd_bus_message_get_path", MessagePath),
                new_method: symbol!("sd_bus_message_new_method_call", NewMethod),
                append_basic: symbol!("sd_bus_message_append_basic", AppendBasic),
                open_container: symbol!("sd_bus_message_open_container", Container),
                close_container: symbol!("sd_bus_message_close_container", CloseContainer),
                call_message: symbol!("sd_bus_call", CallMessage),
            })
        }
    }
    struct Reply<'a> {
        raw: *mut Message,
        api: &'a Api,
    }
    impl Drop for Reply<'_> {
        fn drop(&mut self) {
            unsafe {
                (self.api.unref)(self.raw);
            }
        }
    }

    struct Builder<'a>(Reply<'a>);
    impl Builder<'_> {
        fn open(&self, kind: u8, signature: &CStr) -> io::Result<()> {
            checked(unsafe {
                (self.0.api.open_container)(self.0.raw, kind as c_char, signature.as_ptr())
            })?;
            Ok(())
        }
        fn close(&self) -> io::Result<()> {
            checked(unsafe { (self.0.api.close_container)(self.0.raw) })?;
            Ok(())
        }
        fn text(&self, value: &str) -> io::Result<()> {
            if value.len() > 8192 {
                return Err(refuse("transient string exceeds bound"));
            }
            let value = CString::new(value).map_err(|_| refuse("NUL in transient string"))?;
            checked(unsafe {
                (self.0.api.append_basic)(self.0.raw, b's' as c_char, value.as_ptr().cast())
            })?;
            Ok(())
        }
        fn scalar<T>(&self, kind: u8, value: &T) -> io::Result<()> {
            checked(unsafe {
                (self.0.api.append_basic)(self.0.raw, kind as c_char, (value as *const T).cast())
            })?;
            Ok(())
        }
        fn strings(&self, values: &[String]) -> io::Result<()> {
            if values.len() > 128 {
                return Err(refuse("transient array exceeds bound"));
            }
            self.open(b'a', c"s")?;
            for value in values {
                self.text(value)?;
            }
            self.close()
        }
        fn property(
            &self,
            property: &crate::profile_auto_unit_policy::linux::TransientProperty,
        ) -> io::Result<()> {
            use crate::profile_auto_unit_policy::linux::TransientProperty as P;
            let (name, signature) = match property {
                P::String(name, _) => (*name, c"s"),
                P::Bool(name, _) => (*name, c"b"),
                P::U32(name, _) => (*name, c"u"),
                P::U64(name, _) => (*name, c"t"),
                P::StringArray(name, _) => (*name, c"as"),
                P::Exec(name, _) => (*name, c"a(sasb)"),
            };
            self.open(b'r', c"sv")?;
            self.text(name)?;
            self.open(b'v', signature)?;
            match property {
                P::String(_, value) => self.text(value)?,
                P::Bool(_, value) => self.scalar(b'b', &i32::from(*value))?,
                P::U32(_, value) => self.scalar(b'u', value)?,
                P::U64(_, value) => self.scalar(b't', value)?,
                P::StringArray(_, values) => self.strings(values)?,
                P::Exec(_, commands) => {
                    if commands.is_empty() || commands.len() > 8 {
                        return Err(refuse("transient command count refused"));
                    }
                    self.open(b'a', c"(sasb)")?;
                    for command in commands {
                        let executable = command
                            .first()
                            .ok_or_else(|| refuse("empty transient command"))?;
                        if !Path::new(executable).is_absolute() {
                            return Err(refuse("transient executable is not absolute"));
                        }
                        self.open(b'r', c"sasb")?;
                        self.text(executable)?;
                        self.strings(command)?;
                        self.scalar(b'b', &0i32)?;
                        self.close()?;
                    }
                    self.close()?;
                }
            }
            self.close()?;
            self.close()
        }
    }
    struct Connection {
        raw: *mut Bus,
        api: Rc<Api>,
        peer: VerifiedSocketPeer,
        expected_peer: libc::ucred,
        namespaces: [(OwnedFd, OwnedFd); 4],
        roots: (OwnedFd, OwnedFd),
        deadline: Instant,
    }
    impl Drop for Connection {
        fn drop(&mut self) {
            unsafe {
                (self.api.close)(self.raw);
            }
        }
    }
    fn string(raw: *const c_char) -> io::Result<String> {
        if raw.is_null() {
            return Err(refuse("missing bus string"));
        }
        // sd-bus validates a NUL-terminated D-Bus string before exposing it.
        let value = unsafe { CStr::from_ptr(raw) }
            .to_str()
            .map_err(|_| refuse("non UTF8 bus string"))?;
        if value.len() > 8192 || value.chars().any(char::is_control) {
            return Err(refuse("unbounded bus field"));
        }
        Ok(value.to_owned())
    }

    fn hold_unit_cgroup(path: &str) -> io::Result<HeldCgroup> {
        if !path.starts_with('/')
            || !path
                .rsplit('/')
                .next()
                .is_some_and(super::private_unit_name)
            || path.len() > 4096
        {
            return Err(refuse("invalid owned cgroup path"));
        }
        let path = Path::new(path);
        if !path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
        {
            return Err(refuse("noncanonical owned cgroup path"));
        }
        let full = Path::new("/sys/fs/cgroup").join(
            path.strip_prefix("/")
                .map_err(|_| refuse("invalid cgroup root"))?,
        );
        let names: Vec<&OsStr> = full
            .components()
            .filter_map(|part| {
                if let Component::Normal(name) = part {
                    Some(name)
                } else {
                    None
                }
            })
            .collect();
        let (basename, parents) = names
            .split_last()
            .ok_or_else(|| refuse("owned cgroup has no basename"))?;
        let parent = open_held_parent(parents, true)?;
        let fd = open_dir(parent.as_raw_fd(), basename)?;
        check_dir(fd.as_raw_fd(), true)?;
        let identity = dir_identity(fd.as_raw_fd())?;
        let named = stat_leaf(parent.as_raw_fd(), basename)?;
        if identity != (named.st_dev, named.st_ino) {
            return Err(refuse("owned cgroup path changed"));
        }
        let mut kind = MaybeUninit::<libc::statfs>::uninit();
        if unsafe { libc::fstatfs(fd.as_raw_fd(), kind.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { kind.assume_init() }.f_type != 0x6367_7270 {
            return Err(refuse("owned cgroup is not cgroup v2"));
        }
        Ok(HeldCgroup {
            directory: fd,
            parent,
            basename: cstring(basename)?,
            path: full,
            identity,
        })
    }

    fn verify_held_cgroup(cgroup: &HeldCgroup) -> io::Result<()> {
        let mut value = MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(cgroup.directory.as_raw_fd(), value.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let value = unsafe { value.assume_init() };
        if (value.st_dev, value.st_ino) != cgroup.identity {
            return Err(refuse("held cgroup identity changed"));
        }
        let mut kind = MaybeUninit::<libc::statfs>::uninit();
        if unsafe { libc::fstatfs(cgroup.directory.as_raw_fd(), kind.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { kind.assume_init() }.f_type != 0x6367_7270 {
            return Err(refuse("held cgroup filesystem changed"));
        }
        Ok(())
    }

    fn verify_named_cgroup(cgroup: &HeldCgroup) -> io::Result<()> {
        let mut leaf = MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                cgroup.parent.as_raw_fd(),
                cgroup.basename.as_ptr(),
                leaf.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let leaf = unsafe { leaf.assume_init() };
        if (leaf.st_dev, leaf.st_ino) != cgroup.identity {
            return Err(refuse("owned cgroup path changed"));
        }
        Ok(())
    }

    pub(super) fn cgroup_empty(cgroup: &HeldCgroup) -> io::Result<()> {
        use std::io::Read;
        verify_held_cgroup(cgroup)?;
        let events_missing = || -> io::Result<bool> {
            let raw = unsafe {
                libc::openat(
                    cgroup.directory.as_raw_fd(),
                    c"cgroup.events".as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW,
                )
            };
            if raw >= 0 {
                drop(unsafe { OwnedFd::from_raw_fd(raw) });
                return Ok(false);
            }
            match io::Error::last_os_error().raw_os_error() {
                Some(libc::ENOENT) => Ok(true),
                _ => Err(io::Error::last_os_error()),
            }
        };
        let removed = || -> io::Result<bool> {
            let named = || -> io::Result<bool> {
                let mut leaf = MaybeUninit::<libc::stat>::uninit();
                if unsafe {
                    libc::fstatat(
                        cgroup.parent.as_raw_fd(),
                        cgroup.basename.as_ptr(),
                        leaf.as_mut_ptr(),
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                } == 0
                {
                    return Ok(false);
                }
                match io::Error::last_os_error().raw_os_error() {
                    Some(libc::ENOENT) => Ok(true),
                    _ => Err(io::Error::last_os_error()),
                }
            };
            if !named()? {
                return Ok(false);
            }
            let procfd = format!("/proc/self/fd/{}", cgroup.directory.as_raw_fd());
            let procfd = CString::new(procfd).map_err(|_| refuse("invalid held cgroup fd"))?;
            let mut target = [0u8; 8192];
            let length = unsafe {
                libc::readlink(procfd.as_ptr(), target.as_mut_ptr().cast(), target.len())
            };
            if length < 0 {
                return Err(io::Error::last_os_error());
            }
            let length = length as usize;
            let expected = cgroup.path.as_os_str().as_bytes();
            let exact_deleted = length == expected.len() + b" (deleted)".len()
                && target[..length].starts_with(expected)
                && target[expected.len()..length] == b" (deleted)"[..];
            if !exact_deleted || !named()? {
                return Ok(false);
            }
            verify_held_cgroup(cgroup)?;
            Ok(true)
        };
        let raw = unsafe {
            libc::openat(
                cgroup.directory.as_raw_fd(),
                c"cgroup.events".as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW,
            )
        };
        if raw < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOENT) && removed()? {
                return Ok(());
            }
            return Err(error);
        }
        let mut bytes = Vec::new();
        let read = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(raw) })
            .take(4097)
            .read_to_end(&mut bytes);
        if let Err(error) = read {
            if matches!(
                error.raw_os_error(),
                Some(libc::ENOENT) | Some(libc::ENODEV)
            ) && events_missing()?
                && removed()?
            {
                return Ok(());
            }
            return Err(error);
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| refuse("invalid cgroup event text"))?;
        if bytes.len() > 4096
            || text
                .lines()
                .filter(|line| line.starts_with("populated "))
                .collect::<Vec<_>>()
                != ["populated 0"]
        {
            return Err(refuse("owned cgroup or descendants remain populated"));
        }
        verify_held_cgroup(cgroup)?;
        match verify_named_cgroup(cgroup) {
            Ok(()) => Ok(()),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                if events_missing()? && removed()? {
                    Ok(())
                } else {
                    Err(error)
                }
            }
            Err(error) => Err(error),
        }
    }
    pub(super) fn pid_state(fd: &OwnedFd, exited: bool) -> io::Result<()> {
        let mut event = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut event, 1, 0) };
        if ready < 0 {
            return Err(io::Error::last_os_error());
        }
        if (exited
            && (ready != 1
                || event.revents & libc::POLLIN == 0
                || event.revents & !(libc::POLLIN | libc::POLLHUP) != 0))
            || (!exited && (ready != 0 || event.revents != 0))
        {
            return Err(refuse("owned process liveness changed"));
        }
        Ok(())
    }

    fn hold_main_pid(
        connection: &Connection,
        path: &CStr,
        invocation: &str,
    ) -> io::Result<(OwnedFd, u32)> {
        let value = connection.field(path, c"org.freedesktop.systemd1.Service", "MainPID", c"u")?;
        let pid = value
            .parse::<u32>()
            .map_err(|_| refuse("invalid owned MainPID"))?;
        if pid <= 1 || pid > i32::MAX as u32 {
            return Err(refuse("invalid owned MainPID"));
        }
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as i32, 0) as i32 };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        pid_state(&fd, false)?;
        let cgroup = connection.field(
            path,
            c"org.freedesktop.systemd1.Service",
            "ControlGroup",
            c"s",
        )?;
        if connection.field(path, c"org.freedesktop.systemd1.Service", "MainPID", c"u")? != value
            || connection.field(
                path,
                c"org.freedesktop.systemd1.Unit",
                "InvocationID",
                c"ay",
            )? != invocation
            || fs::read_to_string(format!("/proc/{pid}/cgroup"))? != format!("0::{cgroup}\n")
        {
            return Err(refuse("owned MainPID identity changed"));
        }
        pid_state(&fd, false)?;
        Ok((fd, pid))
    }

    fn stopped_postcondition(
        connection: &Connection,
        name: &str,
        pid: &OwnedFd,
        cgroup: &HeldCgroup,
    ) -> io::Result<bool> {
        let mut ignored_phase = "";
        stopped_postcondition_traced(connection, name, pid, cgroup, &mut ignored_phase)
    }

    fn stopped_postcondition_traced(
        connection: &Connection,
        name: &str,
        pid: &OwnedFd,
        cgroup: &HeldCgroup,
        phase: &mut &'static str,
    ) -> io::Result<bool> {
        *phase = "pidfd_exited";
        pid_state(pid, true)?;
        // Kernel cgroup-v2 removal requires no live tasks or descendants;
        // a renamed/replaced group does not remove this exact held inode.
        *phase = "cgroup_empty";
        cgroup_empty(cgroup)?;
        *phase = "get_unit";
        let collected = match connection.get_unit(name)? {
            None => true,
            Some(path) => {
                *phase = "active_state";
                if connection.field(&path, c"org.freedesktop.systemd1.Unit", "ActiveState", c"s")?
                    != "inactive"
                {
                    return Err(refuse("owned stop has not quiesced"));
                }
                *phase = "main_pid";
                if connection.field(&path, c"org.freedesktop.systemd1.Service", "MainPID", c"u")?
                    != "0"
                {
                    return Err(refuse("owned stop has not quiesced"));
                }
                *phase = "control_pid";
                if connection.field(
                    &path,
                    c"org.freedesktop.systemd1.Service",
                    "ControlPID",
                    c"u",
                )? != "0"
                {
                    return Err(refuse("owned stop has not quiesced"));
                }
                false
            }
        };
        *phase = "pidfd_exited_recheck";
        pid_state(pid, true)?;
        *phase = "cgroup_empty_recheck";
        cgroup_empty(cgroup)?;
        *phase = "pid1_bound_recheck";
        connection.bound()?;
        Ok(collected)
    }
    impl Connection {
        fn new(api: Rc<Api>) -> io::Result<Self> {
            Self::from_peer(api, connect_pid1_readonly()?, false)
        }
        fn pin_bus(api: Rc<Api>) -> io::Result<Self> {
            Self::from_peer(
                api,
                connect_checked(Path::new(SYSTEM_BUS_SOCKET), 0, 0, true)?,
                true,
            )
        }
        fn from_peer(api: Rc<Api>, peer: VerifiedSocketPeer, bus_client: bool) -> io::Result<Self> {
            let expected_peer = peercred(peer._stream.as_raw_fd())?;
            // Hold both ends of every namespace/root comparison. These local
            // identities must additionally match the installed host anchor at
            // the guardian boundary before they can authorize an effect.
            let open = |path: &str| -> io::Result<OwnedFd> {
                let path =
                    CString::new(path).map_err(|_| refuse("invalid native identity path"))?;
                let raw = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
                if raw < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(unsafe { OwnedFd::from_raw_fd(raw) })
            };
            let pair = |name: &str| -> io::Result<(OwnedFd, OwnedFd)> {
                Ok((
                    open(&format!("/proc/thread-self/ns/{name}"))?,
                    open(&format!("/proc/1/ns/{name}"))?,
                ))
            };
            let namespaces = [pair("pid")?, pair("user")?, pair("mnt")?, pair("net")?];
            let roots = (open("/")?, open("/proc/1/root")?);
            for (local, manager) in namespaces.iter().chain(std::iter::once(&roots)) {
                if dir_identity(local.as_raw_fd())? != dir_identity(manager.as_raw_fd())? {
                    return Err(refuse("AUTO manager and worker native identities differ"));
                }
            }
            let mut raw = ptr::null_mut();
            checked(unsafe { (api.new)(&mut raw) })?;
            let result = Self {
                raw,
                api: api.clone(),
                peer,
                expected_peer,
                namespaces,
                roots,
                deadline: Instant::now() + Duration::from_secs(3),
            };
            // A duplicate of the already authenticated connection is transferred
            // to sd-bus; the original stays held for peer revalidation.
            let fd = result.peer._stream.try_clone()?.into_raw_fd();
            if let Err(error) = checked(unsafe { (api.set_fd)(raw, fd, fd) }) {
                unsafe {
                    libc::close(fd);
                }
                return Err(error);
            }
            result.bound()?;
            checked(unsafe { (api.set_client)(raw, i32::from(bus_client)) })?;
            checked(unsafe { (api.start)(raw) })?;
            while checked(unsafe { (api.ready)(raw) })? == 0 {
                result.bound()?;
                if checked(unsafe { (api.process)(raw, ptr::null_mut()) })? == 0 {
                    checked(unsafe { (api.wait)(raw, 10_000) })?;
                }
            }
            result.bound()?;
            Ok(result)
        }
        fn bound(&self) -> io::Result<()> {
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "PID1 query bound expired",
                ));
            }
            let p = peercred(self.peer._stream.as_raw_fd())?;
            if p.pid != self.expected_peer.pid
                || p.uid != self.expected_peer.uid
                || p.gid != self.expected_peer.gid
            {
                return Err(refuse("PID1 peer changed"));
            }
            let mut event = libc::pollfd {
                fd: self.peer._pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut event, 1, 0) } != 0
                || event.revents != 0
                || fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim()
                    != self.peer.boot_id()
            {
                return Err(refuse("PID1 boot or liveness changed"));
            }
            for (name, (local, manager)) in
                ["pid", "user", "mnt", "net"].iter().zip(&self.namespaces)
            {
                use std::os::unix::fs::MetadataExt;
                let held = dir_identity(local.as_raw_fd())?;
                let current = fs::metadata(format!("/proc/thread-self/ns/{name}"))?;
                let peer = fs::metadata(format!("/proc/1/ns/{name}"))?;
                if held != dir_identity(manager.as_raw_fd())?
                    || held != (current.dev(), current.ino())
                    || held != (peer.dev(), peer.ino())
                {
                    return Err(refuse("PID1 namespace identity changed"));
                }
            }
            {
                use std::os::unix::fs::MetadataExt;
                let held = dir_identity(self.roots.0.as_raw_fd())?;
                let current = fs::metadata("/")?;
                let peer = fs::metadata("/proc/1/root")?;
                if held != dir_identity(self.roots.1.as_raw_fd())?
                    || held != (current.dev(), current.ino())
                    || held != (peer.dev(), peer.ino())
                {
                    return Err(refuse("PID1 root identity changed"));
                }
            }
            checked(unsafe {
                (self.api.timeout)(self.raw, remaining.as_micros().min(2_000_000) as u64)
            })?;
            Ok(())
        }
        fn property(
            &self,
            path: &CStr,
            interface: &CStr,
            key: &CStr,
            kind: &CStr,
        ) -> io::Result<Reply<'_>> {
            self.bound()?;
            let mut raw = ptr::null_mut();
            let mut error: Error = unsafe { mem::zeroed() };
            let rc = unsafe {
                (self.api.get)(
                    self.raw,
                    ptr::null(),
                    path.as_ptr(),
                    interface.as_ptr(),
                    key.as_ptr(),
                    &mut error,
                    &mut raw,
                    kind.as_ptr(),
                )
            };
            unsafe {
                (self.api.free_error)(&mut error);
            }
            checked(rc)?;
            let reply = Reply {
                raw,
                api: &self.api,
            };
            self.bound()?;
            Ok(reply)
        }
        fn field(
            &self,
            path: &CStr,
            interface: &CStr,
            key: &str,
            kind: &CStr,
        ) -> io::Result<String> {
            let key = CString::new(key).map_err(|_| refuse("invalid fixed bus key"))?;
            let reply = self.property(path, interface, &key, kind)?;
            match kind.to_bytes() {
                b"s" => {
                    let mut v = ptr::null();
                    if checked(unsafe { (self.api.read)(reply.raw, c"s".as_ptr(), &mut v) })? != 1 {
                        return Err(refuse("bus field absent"));
                    }
                    string(v)
                }
                b"u" => {
                    let mut v: u32 = 0;
                    if checked(unsafe { (self.api.read)(reply.raw, c"u".as_ptr(), &mut v) })? != 1 {
                        return Err(refuse("bus field absent"));
                    }
                    Ok(v.to_string())
                }
                b"t" => {
                    let mut v: u64 = 0;
                    if checked(unsafe { (self.api.read)(reply.raw, c"t".as_ptr(), &mut v) })? != 1 {
                        return Err(refuse("bus field absent"));
                    }
                    Ok(v.to_string())
                }
                b"ay" => self.invocation_value(&reply, false),
                b"as" => {
                    checked(unsafe { (self.api.enter)(reply.raw, b'a' as c_char, c"s".as_ptr()) })?;
                    let mut values = Vec::new();
                    loop {
                        let mut v = ptr::null();
                        if checked(unsafe { (self.api.read)(reply.raw, c"s".as_ptr(), &mut v) })?
                            == 0
                        {
                            break;
                        }
                        let value = string(v)?;
                        if value.bytes().any(|b| b.is_ascii_whitespace()) || values.len() >= 128 {
                            return Err(refuse("ambiguous bus list"));
                        }
                        values.push(value);
                    }
                    Ok(values.join(" "))
                }
                _ => Err(refuse("unknown fixed bus field type")),
            }
        }
        fn invocation_value(&self, reply: &Reply<'_>, allow_absent: bool) -> io::Result<String> {
            let mut bytes = ptr::null();
            let mut size = 0;
            checked(unsafe { (self.api.array)(reply.raw, b'y' as c_char, &mut bytes, &mut size) })?;
            // A loaded service that has never run reports an empty array on
            // systemd 255. Only the stopped observer admits that absence;
            // every active/start/stop ownership read still requires 16 bytes.
            if allow_absent && size == 0 {
                return Ok(String::new());
            }
            if size != 16 || bytes.is_null() {
                return Err(refuse("invalid invocation ID"));
            }
            let bytes = unsafe { std::slice::from_raw_parts(bytes.cast::<u8>(), size) };
            if bytes.iter().all(|value| *value == 0) {
                Ok(String::new())
            } else {
                Ok(bytes.iter().map(|v| format!("{v:02x}")).collect())
            }
        }
        fn stopped_invocation(&self, path: &CStr) -> io::Result<String> {
            let reply = self.property(
                path,
                c"org.freedesktop.systemd1.Unit",
                c"InvocationID",
                c"ay",
            )?;
            self.invocation_value(&reply, true)
        }
        fn unit_named(&self, name: &str) -> io::Result<Option<CString>> {
            self.unit_lookup(name, c"LoadUnit")
        }
        fn get_unit(&self, name: &str) -> io::Result<Option<CString>> {
            self.unit_lookup(name, c"GetUnit")
        }
        fn unit_lookup(&self, name: &str, method: &CStr) -> io::Result<Option<CString>> {
            self.bound()?;
            let name_c = CString::new(name).map_err(|_| refuse("invalid unit name"))?;
            let mut raw = ptr::null_mut();
            let mut error: Error = unsafe { mem::zeroed() };
            let rc = unsafe {
                (self.api.call)(
                    self.raw,
                    ptr::null(),
                    c"/org/freedesktop/systemd1".as_ptr(),
                    c"org.freedesktop.systemd1.Manager".as_ptr(),
                    method.as_ptr(),
                    &mut error,
                    &mut raw,
                    c"s".as_ptr(),
                    name_c.as_ptr(),
                )
            };
            let absent = !error.name.is_null()
                && unsafe { CStr::from_ptr(error.name) } == c"org.freedesktop.systemd1.NoSuchUnit";
            unsafe {
                (self.api.free_error)(&mut error);
            }
            if rc < 0 && absent {
                self.bound()?;
                return Ok(None);
            }
            checked(rc)?;
            let reply = Reply {
                raw,
                api: &self.api,
            };
            let mut value = ptr::null();
            if checked(unsafe { (self.api.read)(reply.raw, c"o".as_ptr(), &mut value) })? != 1 {
                return Err(refuse("unit path missing"));
            }
            let value = string(value)?;
            let encoded: String = name
                .bytes()
                .map(|byte| {
                    if byte.is_ascii_alphanumeric() {
                        char::from(byte).to_string()
                    } else {
                        format!("_{byte:02x}")
                    }
                })
                .collect();
            if value != format!("/org/freedesktop/systemd1/unit/{encoded}") {
                return Err(refuse("unexpected unit path"));
            }
            let path = CString::new(value).unwrap();
            // LoadUnit may return a cached not-found object. Service-specific
            // properties on that object return EBADR; only the actual Unit
            // LoadState can establish the original absent-service epoch.
            if self.field(&path, c"org.freedesktop.systemd1.Unit", "LoadState", c"s")?
                == "not-found"
            {
                if method == c"GetUnit" {
                    return Err(refuse("cached not-found private unit is not a GC receipt"));
                }
                return Ok(None);
            }
            self.bound()?;
            Ok(Some(path))
        }
    }
    impl Connection {
        fn method(&self, member: &CStr, unit: Option<&CStr>) -> io::Result<Reply<'_>> {
            self.bound()?;
            let mut raw = ptr::null_mut();
            let mut error: Error = unsafe { mem::zeroed() };
            let rc = unsafe {
                if let Some(unit) = unit {
                    (self.api.call)(
                        self.raw,
                        ptr::null(),
                        c"/org/freedesktop/systemd1".as_ptr(),
                        c"org.freedesktop.systemd1.Manager".as_ptr(),
                        member.as_ptr(),
                        &mut error,
                        &mut raw,
                        c"ss".as_ptr(),
                        unit.as_ptr(),
                        c"fail".as_ptr(),
                    )
                } else {
                    (self.api.call)(
                        self.raw,
                        ptr::null(),
                        c"/org/freedesktop/systemd1".as_ptr(),
                        c"org.freedesktop.systemd1.Manager".as_ptr(),
                        member.as_ptr(),
                        &mut error,
                        &mut raw,
                        c"".as_ptr(),
                    )
                }
            };
            unsafe {
                (self.api.free_error)(&mut error);
            }
            checked(rc)?;
            let reply = Reply {
                raw,
                api: &self.api,
            };
            self.bound()?;
            Ok(reply)
        }
        fn submitted(&self, method: &CStr, unit: &CStr) -> io::Result<super::SubmittedJob> {
            super::manager_effect_boundary("StartUnit/StopUnit");
            let reply = self.method(method, Some(unit))?;
            self.job_from_reply(&reply, unit)
        }
        fn job_from_reply(
            &self,
            reply: &Reply<'_>,
            unit: &CStr,
        ) -> io::Result<super::SubmittedJob> {
            let mut path = ptr::null();
            if checked(unsafe { (self.api.read)(reply.raw, c"o".as_ptr(), &mut path) })? != 1 {
                return Err(refuse("PID1 returned no job"));
            }
            let path = string(path)?;
            let number = path
                .strip_prefix("/org/freedesktop/systemd1/job/")
                .ok_or_else(|| refuse("PID1 returned invalid job path"))?;
            if number.is_empty() || number.len() > 10 || !number.bytes().all(|b| b.is_ascii_digit())
            {
                return Err(refuse("PID1 returned invalid job ID"));
            }
            let id = number
                .parse::<u32>()
                .map_err(|_| refuse("PID1 job ID overflow"))?;
            if id == 0 || id.to_string() != number {
                return Err(refuse("PID1 job ID is not canonical"));
            }
            Ok(super::SubmittedJob {
                id,
                path,
                unit: unit
                    .to_str()
                    .map_err(|_| refuse("invalid fixed unit"))?
                    .into(),
                identity: self.identity()?,
            })
        }
        fn start_transient(
            &self,
            unit: &super::PrivateUnit,
            policy: &crate::profile_auto_unit_policy::linux::TransientPolicy,
            launch: &OwnedFd,
        ) -> io::Result<super::SubmittedJob> {
            super::manager_effect_boundary("StartTransientUnit");
            self.bound()?;
            let properties = policy.bind_unit(unit).map_err(refuse)?;
            if properties.len() > 96 {
                return Err(refuse("transient property count exceeds bound"));
            }
            let mut raw = ptr::null_mut();
            checked(unsafe {
                (self.api.new_method)(
                    self.raw,
                    &mut raw,
                    ptr::null(),
                    c"/org/freedesktop/systemd1".as_ptr(),
                    c"org.freedesktop.systemd1.Manager".as_ptr(),
                    c"StartTransientUnit".as_ptr(),
                )
            })?;
            let request = Builder(Reply {
                raw,
                api: &self.api,
            });
            request.text(unit.name())?;
            request.text("fail")?;
            request.open(b'a', c"(sv)")?;
            for property in &properties {
                request.property(property)?;
            }
            request.open(b'r', c"sv")?;
            request.text("StandardInputFileDescriptor")?;
            request.open(b'v', c"h")?;
            request.scalar(b'h', &launch.as_raw_fd())?;
            request.close()?;
            request.close()?;
            request.close()?;
            request.open(b'a', c"(sa(sv))")?;
            request.close()?;
            // Namespace admission is immediately adjacent to send; no arbitrary
            // files or unit identities are accepted between this check and call.
            drop(policy.bind_unit(unit).map_err(refuse)?);
            self.bound()?;
            let mut reply_raw = ptr::null_mut();
            let mut error: Error = unsafe { mem::zeroed() };
            let rc = unsafe {
                (self.api.call_message)(self.raw, request.0.raw, 0, &mut error, &mut reply_raw)
            };
            unsafe {
                (self.api.free_error)(&mut error);
            }
            checked(rc)?;
            let reply = Reply {
                raw: reply_raw,
                api: &self.api,
            };
            self.bound()?;
            let name = CString::new(unit.name()).map_err(|_| refuse("invalid private unit"))?;
            self.job_from_reply(&reply, &name)
        }
        fn identity(&self) -> io::Result<super::ManagerIdentity> {
            use std::os::unix::fs::MetadataExt;
            self.bound()?;
            let mut socket = MaybeUninit::<libc::stat>::uninit();
            checked(unsafe { libc::fstat(self.peer._stream.as_raw_fd(), socket.as_mut_ptr()) })?;
            let socket = unsafe { socket.assume_init() };
            let ns = fs::metadata("/proc/thread-self/ns/net")?;
            if fs::metadata("/proc/1/ns/net")?.ino() != ns.ino() {
                return Err(refuse("AUTO manager and worker network namespaces differ"));
            }
            Ok(super::ManagerIdentity {
                boot_id: self.peer.boot_id().into(),
                socket: (socket.st_dev, socket.st_ino),
                netns: (ns.dev(), ns.ino()),
                namespaces: [
                    dir_identity(self.namespaces[0].0.as_raw_fd())?,
                    dir_identity(self.namespaces[1].0.as_raw_fd())?,
                    dir_identity(self.namespaces[2].0.as_raw_fd())?,
                    dir_identity(self.namespaces[3].0.as_raw_fd())?,
                ],
                root: dir_identity(self.roots.0.as_raw_fd())?,
            })
        }
        fn wait_job(&self, job: &super::SubmittedJob) -> io::Result<()> {
            let mut ignored_phase = "";
            self.wait_job_traced(job, &mut ignored_phase)
        }
        fn wait_job_traced(
            &self,
            job: &super::SubmittedJob,
            phase: &mut &'static str,
        ) -> io::Result<()> {
            super::manager_effect_boundary("job wait");
            loop {
                // identity() calls bound() on every drain iteration: irrelevant
                // Subscribe traffic cannot renew the absolute owner deadline.
                *phase = "job_identity_before";
                if self.identity()? != job.identity {
                    return Err(refuse("PID1 job connection identity changed"));
                }
                let mut raw = ptr::null_mut();
                *phase = "job_process";
                if checked(unsafe { (self.api.process)(self.raw, &mut raw) })? == 0 {
                    *phase = "job_wait";
                    checked(unsafe { (self.api.wait)(self.raw, 10_000) })?;
                    continue;
                }
                if raw.is_null() {
                    continue;
                }
                let reply = Reply {
                    raw,
                    api: &self.api,
                };
                *phase = "job_signal_kind";
                let signal = unsafe {
                    (self.api.is_signal)(
                        raw,
                        c"org.freedesktop.systemd1.Manager".as_ptr(),
                        c"JobRemoved".as_ptr(),
                    )
                };
                checked(signal)?;
                if signal == 0 {
                    continue;
                }
                *phase = "job_signal_path";
                if string(unsafe { (self.api.message_path)(raw) })? != "/org/freedesktop/systemd1" {
                    return Err(refuse("PID1 job signal path changed"));
                }
                let mut id: u32 = 0;
                let mut path = ptr::null();
                let mut unit = ptr::null();
                let mut result = ptr::null();
                *phase = "job_signal_shape";
                if checked(unsafe {
                    (self.api.read)(
                        reply.raw,
                        c"uoss".as_ptr(),
                        &mut id,
                        &mut path,
                        &mut unit,
                        &mut result,
                    )
                })? != 1
                {
                    return Err(refuse("PID1 job signal shape changed"));
                }
                *phase = "job_path_decode";
                let path = string(path)?;
                *phase = "job_unit_decode";
                let unit = string(unit)?;
                *phase = "job_result_decode";
                let result = string(result)?;
                if !super::job_removed_relevant(job.id, &job.path, &job.unit, id, &path, &unit) {
                    continue;
                }
                *phase = "job_identity_mismatch";
                if !super::owned_job_notice(job.id, &job.path, &job.unit, id, &path, &unit)? {
                    continue;
                }
                *phase = match result.as_str() {
                    "canceled" => "job_result_canceled",
                    "timeout" => "job_result_timeout",
                    "failed" => "job_result_failed",
                    "dependency" => "job_result_dependency",
                    "skipped" => "job_result_skipped",
                    "invalid" => "job_result_invalid",
                    "assert" => "job_result_assert",
                    "unsupported" => "job_result_unsupported",
                    "once" => "job_result_once",
                    _ => "job_result_other",
                };
                if result != "done" {
                    return Err(refuse("owned PID1 job did not complete successfully"));
                }
                *phase = "job_identity_after";
                if self.identity()? != job.identity {
                    return Err(refuse("PID1 job connection identity changed"));
                }
                return Ok(());
            }
        }
    }

    /// Source-owned boundary used by the retained transaction owner. There is
    /// no caller unit name and no serialization/reconstruction of a session.
    /// The owner must retain its real stage, InstallLock and native deny lease
    /// while these callbacks persist and consume the durable may-send claim.
    pub(crate) struct PreparedStart {
        connection: Connection,
        unit: super::PrivateUnit,
        policy: crate::profile_auto_unit_policy::linux::TransientPolicy,
        launch_actor: OwnedFd,
        launch_child: OwnedFd,
    }

    pub(super) fn prepare_owned(
        policy: crate::profile_auto_unit_policy::linux::TransientPolicy,
    ) -> Result<PreparedStart, &'static str> {
        let operation = || -> io::Result<PreparedStart> {
            let connection = Connection::new(Rc::new(Api::load()?))?;
            let unit = super::PrivateUnit::mint()?;
            drop(policy.bind_unit(&unit).map_err(refuse)?);
            let mut fds = [-1i32; 2];
            if unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                    0,
                    fds.as_mut_ptr(),
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            let launch_actor = unsafe { OwnedFd::from_raw_fd(fds[0]) };
            let launch_child = unsafe { OwnedFd::from_raw_fd(fds[1]) };
            let flags = unsafe { libc::fcntl(launch_child.as_raw_fd(), libc::F_GETFL) };
            if flags < 0
                || unsafe {
                    libc::fcntl(
                        launch_child.as_raw_fd(),
                        libc::F_SETFL,
                        flags & !libc::O_NONBLOCK,
                    )
                } < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(PreparedStart {
                connection,
                unit,
                policy,
                launch_actor,
                launch_child,
            })
        };
        operation().map_err(|_| "AUTO PID1 preparation refused")
    }

    impl PreparedStart {
        pub(crate) fn duplicate_launch_fd(&self) -> Result<OwnedFd, &'static str> {
            self.launch_actor
                .try_clone()
                .map_err(|_| "AUTO launch capsule duplication refused")
        }
        pub(crate) fn unit(&self) -> &super::PrivateUnit {
            &self.unit
        }
        pub(crate) fn manager(&mut self) -> Result<super::ManagerIdentity, &'static str> {
            self.connection.deadline = Instant::now() + Duration::from_secs(3);
            self.connection
                .identity()
                .map_err(|_| "AUTO PID1 manager identity refused")
        }
        pub(crate) fn start<A: super::StartAuthority>(
            self,
            authority: &mut A,
        ) -> Result<OwnedStart, String> {
            let mut phase = "identity";
            let operation = || -> io::Result<OwnedStart> {
                let Self {
                    mut connection,
                    unit,
                    policy,
                    launch_actor: _launch_actor,
                    launch_child,
                } = self;
                connection.deadline = Instant::now() + Duration::from_secs(3);
                phase = "identity";
                let identity = connection.identity()?;
                phase = "pre_marker";
                authority
                    .admit_pre_marker(&identity, &unit)
                    .map_err(refuse)?;
                // Subscribe before the request, so even an immediately completed
                // job is already queued on this same authenticated connection.
                phase = "subscribe";
                drop(connection.method(c"Subscribe", None)?);
                phase = "claim";
                authority.claim_may_send(&identity, &unit).map_err(refuse)?;
                phase = "post_claim";
                authority
                    .admit_post_marker(&identity, &unit)
                    .map_err(refuse)?;
                // This bound includes constructing/submitting the transient unit,
                // original-owner readbacks, BIND prestart and Main/READY.
                // The independent native deny lease remains held throughout.
                connection.deadline = Instant::now()
                    + Duration::from_secs(if authority.requires_terminal_host_source_proof() {
                        35
                    } else {
                        20
                    });
                phase = "submit";
                let submitted = connection.start_transient(&unit, &policy, &launch_child)?;
                phase = "submitted_receipt";
                authority.record_submitted(&submitted).map_err(refuse)?;
                phase = "post_submit";
                authority
                    .admit_post_marker(&identity, &unit)
                    .map_err(refuse)?;
                connection.wait_job_traced(&submitted, &mut phase)?;
                phase = "lookup";
                let path = connection
                    .unit_named(unit.name())?
                    .ok_or_else(|| refuse("owned service disappeared"))?;
                phase = "invocation";
                let invocation = connection.field(
                    &path,
                    c"org.freedesktop.systemd1.Unit",
                    "InvocationID",
                    c"ay",
                )?;
                if invocation.len() != 32 {
                    return Err(refuse("owned service has no invocation"));
                }
                phase = "hold_main";
                let (main_pidfd, _) = hold_main_pid(&connection, &path, &invocation)?;
                let completed = super::CompletedStart {
                    submitted,
                    invocation,
                };
                let (job, invocation) = completed.facts();
                phase = "manager_recheck";
                if job.identity != connection.identity()? || invocation.len() != 32 {
                    return Err(refuse("completed PID1 job binding changed"));
                }
                phase = "post_ready";
                authority
                    .admit_post_marker(&identity, &unit)
                    .map_err(refuse)?;
                phase = "completed_receipt";
                authority.record_completed(&completed).map_err(refuse)?;
                Ok(OwnedStart {
                    connection,
                    completed,
                    unit,
                    main_pidfd,
                })
            };
            // No exception after an ambiguous send can grant a retry. The retained
            // owner/guardian decides recovery with deny left armed.
            operation().map_err(|error| super::start_failure(phase, &error))
        }
    }

    /// Retains the authenticated manager connection as well as the exact
    /// completed job. An observation reconstructed from JSON cannot mint this.
    pub(crate) struct OwnedStart {
        connection: Connection,
        completed: super::CompletedStart,
        unit: super::PrivateUnit,
        main_pidfd: OwnedFd,
    }

    impl OwnedStart {
        pub(crate) fn completed(&self) -> &super::CompletedStart {
            &self.completed
        }

        pub(crate) fn active_unit_readback(&mut self) -> Result<Vec<u8>, &'static str> {
            self.revalidate()?;
            self.connection.deadline = Instant::now() + Duration::from_secs(3);
            query_on(
                &self.connection,
                super::super::ManagerQuery::Active,
                self.unit.name(),
            )
            .map_err(|_| "AUTO owned active unit readback refused")
        }

        pub(crate) fn revalidate(&mut self) -> Result<(), &'static str> {
            let operation = || -> io::Result<()> {
                pid_state(&self.main_pidfd, false)?;
                self.connection.deadline = Instant::now() + Duration::from_secs(3);
                if self.connection.identity()? != self.completed.submitted.identity {
                    return Err(refuse("owned PID1 connection changed"));
                }
                let path = self
                    .connection
                    .unit_named(self.unit.name())?
                    .ok_or_else(|| refuse("owned unit missing"))?;
                let invocation = self.connection.field(
                    &path,
                    c"org.freedesktop.systemd1.Unit",
                    "InvocationID",
                    c"ay",
                )?;
                let active = self.connection.field(
                    &path,
                    c"org.freedesktop.systemd1.Unit",
                    "ActiveState",
                    c"s",
                )?;
                if invocation != self.completed.invocation || active != "active" {
                    return Err(refuse("owned PID1 invocation changed"));
                }
                Ok(())
            };
            let mut operation = operation;
            operation().map_err(|_| "AUTO owned PID1 invocation requires native recovery")
        }

        /// Compensates only this connection's exact still-current invocation.
        /// The owner must keep its native deny lease armed around the call.
        pub(crate) fn stop_owned<A: super::StopAuthority>(
            mut self,
            authority: &mut A,
        ) -> Result<super::CompletedStop, &'static str> {
            let operation = || -> io::Result<super::CompletedStop> {
                self.revalidate().map_err(refuse)?;
                authority
                    .admit_compensation(&self.completed)
                    .map_err(refuse)?;
                // Two fixed stop hooks each have TimeoutStopSec=15s. Keep
                // enough bounded time for both plus PID1 signal/readback.
                self.connection.deadline = Instant::now() + Duration::from_secs(35);
                let path = self
                    .connection
                    .unit_named(self.unit.name())?
                    .ok_or_else(|| refuse("owned unit missing before stop"))?;
                if self.connection.field(
                    &path,
                    c"org.freedesktop.systemd1.Unit",
                    "InvocationID",
                    c"ay",
                )? != self.completed.invocation
                {
                    return Err(refuse("owned invocation changed before compensation"));
                }
                let cgroup = hold_unit_cgroup(&self.connection.field(
                    &path,
                    c"org.freedesktop.systemd1.Service",
                    "ControlGroup",
                    c"s",
                )?)?;
                let submitted = self.connection.submitted(
                    c"StopUnit",
                    &CString::new(self.unit.name())
                        .map_err(|_| refuse("invalid private stop unit"))?,
                )?;
                authority
                    .record_stop_submitted(&submitted)
                    .map_err(refuse)?;
                self.connection.wait_job(&submitted)?;
                let unit_collected = stopped_postcondition(
                    &self.connection,
                    self.unit.name(),
                    &self.main_pidfd,
                    &cgroup,
                )?;
                let stopped = super::CompletedStop {
                    submitted,
                    prior_invocation: self.completed.invocation.clone(),
                    main_pidfd: self.main_pidfd,
                    cgroup,
                    unit_collected,
                };
                stopped.quiescent_unit_collected().map_err(refuse)?;
                authority.record_stop_completed(&stopped).map_err(refuse)?;
                Ok(stopped)
            };
            operation().map_err(|_| "AUTO owned PID1 compensation requires native recovery")
        }
    }

    /// A later owner may deactivate a finalized transaction, but never start
    /// it again. Its protected terminal receipt must bind this invocation.
    pub(super) fn stop_finalized<A: super::FinalizedStopAuthority>(
        authority: &mut A,
    ) -> Result<super::CompletedStop, &'static str> {
        let mut phase = "setup";
        let operation = || -> io::Result<super::CompletedStop> {
            let mut connection = Connection::new(Rc::new(Api::load()?))?;
            let identity = connection.identity()?;
            let name = authority.unit().to_owned();
            if !super::private_unit_name(&name) {
                return Err(refuse("invalid finalized private unit"));
            }
            let unit_name =
                CString::new(name.clone()).map_err(|_| refuse("invalid finalized unit"))?;
            let path = connection
                .unit_named(&name)?
                .ok_or_else(|| refuse("finalized unit missing"))?;
            let invocation = connection.field(
                &path,
                c"org.freedesktop.systemd1.Unit",
                "InvocationID",
                c"ay",
            )?;
            if invocation.len() != 32
                || connection.field(&path, c"org.freedesktop.systemd1.Unit", "ActiveState", c"s")?
                    != "active"
            {
                return Err(refuse("finalized invocation is not active"));
            }
            authority
                .admit_current(&identity, &invocation)
                .map_err(refuse)?;
            let (main_pidfd, _) = hold_main_pid(&connection, &path, &invocation)?;
            let cgroup = hold_unit_cgroup(&connection.field(
                &path,
                c"org.freedesktop.systemd1.Service",
                "ControlGroup",
                c"s",
            )?)?;
            drop(connection.method(c"Subscribe", None)?);
            authority
                .claim_before_send(&identity, &invocation)
                .map_err(refuse)?;
            if connection.identity()? != identity
                || connection.field(
                    &path,
                    c"org.freedesktop.systemd1.Unit",
                    "InvocationID",
                    c"ay",
                )? != invocation
            {
                return Err(refuse("finalized invocation changed before stop"));
            }
            connection.deadline = Instant::now() + Duration::from_secs(35);
            phase = "stop_submit";
            let submitted = connection.submitted(c"StopUnit", &unit_name)?;
            phase = "stop_submitted_receipt";
            authority
                .record_stop_submitted(&submitted)
                .map_err(refuse)?;
            phase = "job_removed";
            connection.wait_job_traced(&submitted, &mut phase)?;
            let unit_collected =
                stopped_postcondition_traced(&connection, &name, &main_pidfd, &cgroup, &mut phase)?;
            let completed = super::CompletedStop {
                submitted,
                prior_invocation: invocation,
                main_pidfd,
                cgroup,
                unit_collected,
            };
            phase = "completed_quiescence";
            completed.quiescent_unit_collected().map_err(refuse)?;
            phase = "stop_completed_receipt";
            authority
                .record_stop_completed(&completed)
                .map_err(refuse)?;
            Ok(completed)
        };
        let mut operation = operation;
        operation().map_err(|error| {
            eprintln!(
                "AUTO_FINALIZED_STOP_DIAGNOSTIC phase={phase} errno={}",
                error.raw_os_error().unwrap_or(0)
            );
            "AUTO finalized deactivation requires native recovery"
        })
    }

    #[cfg(test)]
    #[test]
    #[ignore = "actual writable cgroup-v2 filesystem in disposable root guest"]
    fn held_cgroup_v2_removal_requires_original_deleted_fd() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let unit = super::PrivateUnit::mint().unwrap();
        let path = Path::new("/sys/fs/cgroup").join(unit.name());
        let moved = path.with_extension("moved");
        fs::create_dir(&path).unwrap();
        struct Cleanup {
            path: PathBuf,
            moved: PathBuf,
            child: Option<std::process::Child>,
        }
        impl Drop for Cleanup {
            fn drop(&mut self) {
                if let Some(mut child) = self.child.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                let _ = fs::remove_dir(self.path.join("descendant"));
                let _ = fs::remove_dir(self.moved.join("descendant"));
                let _ = fs::remove_dir(&self.path);
                let _ = fs::remove_dir(&self.moved);
            }
        }
        let mut cleanup = Cleanup {
            path: path.clone(),
            moved: moved.clone(),
            child: None,
        };
        let held = hold_unit_cgroup(&format!("/{}", unit.name())).unwrap();
        fs::create_dir(path.join("descendant")).unwrap();
        let child = std::process::Command::new("/usr/bin/sleep")
            .arg("30")
            .env_clear()
            .spawn()
            .unwrap();
        cleanup.child = Some(child);
        fs::write(
            path.join("descendant/cgroup.procs"),
            cleanup.child.as_ref().unwrap().id().to_string(),
        )
        .unwrap();
        assert!(cgroup_empty(&held).is_err(), "live descendant must refuse");
        cleanup.child.as_mut().unwrap().kill().unwrap();
        cleanup.child.as_mut().unwrap().wait().unwrap();
        cleanup.child = None;
        let until = Instant::now() + Duration::from_secs(3);
        while cgroup_empty(&held).is_err() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(10));
        }
        cgroup_empty(&held).unwrap();
        fs::remove_dir(path.join("descendant")).unwrap();
        if fs::rename(&path, &moved).is_ok() {
            assert!(cgroup_empty(&held).is_err(), "renamed cgroup must refuse");
            fs::rename(&moved, &path).unwrap();
        }
        fs::remove_dir(&path).unwrap();
        cgroup_empty(&held).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(cgroup_empty(&held).is_err(), "replacement must refuse");
    }

    #[cfg(test)]
    pub(super) fn native_job_control() {
        use std::io::Write;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        use std::time::{SystemTime, UNIX_EPOCH};
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!(
            "aegis-auto-pid1-check-{}-{nonce:x}.service",
            std::process::id()
        );
        let path = Path::new("/run/systemd/system").join(&name);
        let bytes=b"[Unit]\nDescription=Aegis isolated PID1 job protocol control\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/true\nPrivateNetwork=yes\nNoNewPrivileges=yes\nProtectSystem=strict\n";
        let command = |args: &[&str]| {
            std::process::Command::new("/usr/bin/timeout")
                .args([
                    "--signal=TERM",
                    "--kill-after=1s",
                    "3s",
                    "/usr/bin/systemctl",
                ])
                .args(args)
                .env_clear()
                .env("LC_ALL", "C")
                .output()
                .unwrap()
        };
        struct UnitCleanup<'a> {
            path: PathBuf,
            bytes: &'a [u8],
            name: String,
            id: (u64, u64),
        }
        impl Drop for UnitCleanup<'_> {
            fn drop(&mut self) {
                let safe = fs::symlink_metadata(&self.path)
                    .is_ok_and(|m| (m.dev(), m.ino()) == self.id && m.is_file())
                    && fs::read(&self.path).is_ok_and(|b| b == self.bytes);
                if !safe {
                    return;
                }
                let status = std::process::Command::new("/usr/bin/timeout")
                    .args([
                        "--signal=TERM",
                        "--kill-after=1s",
                        "3s",
                        "/usr/bin/systemctl",
                        "stop",
                        &self.name,
                    ])
                    .env_clear()
                    .env("LC_ALL", "C")
                    .status();
                if !status.is_ok_and(|s| s.success()) {
                    return;
                }
                if fs::remove_file(&self.path).is_err() {
                    return;
                }
                let _ = std::process::Command::new("/usr/bin/timeout")
                    .args([
                        "--signal=TERM",
                        "--kill-after=1s",
                        "3s",
                        "/usr/bin/systemctl",
                        "daemon-reload",
                    ])
                    .env_clear()
                    .env("LC_ALL", "C")
                    .status();
            }
        }
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let m = file.metadata().unwrap();
        let cleanup = UnitCleanup {
            path: path.clone(),
            bytes,
            name: name.clone(),
            id: (m.dev(), m.ino()),
        };
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert!(command(&["daemon-reload"]).status.success());
        let mut bus = Connection::new(Rc::new(Api::load().unwrap())).unwrap();
        drop(bus.method(c"Subscribe", None).unwrap());
        let unit = CString::new(name.clone()).unwrap();
        let job = bus.submitted(c"StartUnit", &unit).unwrap();
        bus.wait_job(&job).unwrap();
        let encoded: String = name
            .bytes()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    char::from(c).to_string()
                } else {
                    format!("_{c:02x}")
                }
            })
            .collect();
        let object = CString::new(format!("/org/freedesktop/systemd1/unit/{encoded}")).unwrap();
        let invocation = bus
            .field(
                &object,
                c"org.freedesktop.systemd1.Unit",
                "InvocationID",
                c"ay",
            )
            .unwrap();
        assert_eq!(invocation.len(), 32);
        assert_eq!(
            bus.field(
                &object,
                c"org.freedesktop.systemd1.Unit",
                "ActiveState",
                c"s"
            )
            .unwrap(),
            "active"
        );
        bus.deadline = Instant::now() + Duration::from_secs(3);
        let stopped = bus.submitted(c"StopUnit", &unit).unwrap();
        assert_ne!(stopped.id, job.id);
        bus.wait_job(&stopped).unwrap();
        assert_eq!(
            bus.field(
                &object,
                c"org.freedesktop.systemd1.Unit",
                "ActiveState",
                c"s"
            )
            .unwrap(),
            "inactive"
        );
        eprintln!("actual_pid1_jobs start_id={} stop_id={} same_verified_connection=true invocation={} fixture_only=true auto_selectors=0",job.id,stopped.id,invocation);
        drop(bus);
        drop(cleanup);
        assert!(!path.try_exists().unwrap());
    }

    /// Holds the fixed unit in PID1's loaded cache across policy publication.
    /// systemd's RefUnit tracks a system-bus sender, so the pin uses a separate
    /// fixed system-bus connection. All observations and effects retain the
    /// independently verified direct PID1 connection; this value grants no
    /// Start/Stop authority. Closing the pin connection releases its reference.
    pub(crate) struct FixedUnitPin {
        direct: Connection,
        reference: Connection,
        owner: CString,
        path: CString,
    }
    impl FixedUnitPin {
        pub(crate) fn acquire() -> io::Result<Option<Self>> {
            let api = Rc::new(Api::load()?);
            let direct = Connection::new(api.clone())?;
            let Some(path) = direct.unit_named("aegis-client.service")? else {
                return Ok(None);
            };
            let reference = Connection::pin_bus(api)?;
            let owner = reference.pid1_bus_owner()?;
            reference.pin_call(
                &owner,
                c"/org/freedesktop/systemd1",
                c"org.freedesktop.systemd1.Manager",
                c"RefUnit",
                c"aegis-client.service",
            )?;
            let mut pin = Self {
                direct,
                reference,
                owner,
                path,
            };
            pin.revalidate()?;
            Ok(Some(pin))
        }
        pub(crate) fn revalidate(&mut self) -> io::Result<()> {
            let deadline = Instant::now() + Duration::from_secs(3);
            self.direct.deadline = deadline;
            self.reference.deadline = deadline;
            self.direct.bound()?;
            if self.reference.pid1_bus_owner()? != self.owner {
                return Err(refuse("fixed unit reference owner changed"));
            }
            let path = self
                .direct
                .get_unit("aegis-client.service")?
                .ok_or_else(|| refuse("referenced fixed unit disappeared"))?;
            if path != self.path
                || self
                    .direct
                    .field(&path, c"org.freedesktop.systemd1.Unit", "Id", c"s")?
                    != "aegis-client.service"
                || self
                    .direct
                    .field(&path, c"org.freedesktop.systemd1.Unit", "LoadState", c"s")?
                    != "loaded"
            {
                return Err(refuse("referenced fixed unit identity changed"));
            }
            self.direct.bound()?;
            self.reference.bound()
        }
    }
    impl Connection {
        // This single-string method is private to the fixed reference path.
        // In particular it cannot encode StartUnit/StopUnit's required `ss`.
        fn pin_call(
            &self,
            destination: &CStr,
            path: &CStr,
            interface: &CStr,
            member: &CStr,
            argument: &CStr,
        ) -> io::Result<Reply<'_>> {
            self.bound()?;
            let mut raw = ptr::null_mut();
            let mut error: Error = unsafe { mem::zeroed() };
            let rc = unsafe {
                (self.api.call)(
                    self.raw,
                    destination.as_ptr(),
                    path.as_ptr(),
                    interface.as_ptr(),
                    member.as_ptr(),
                    &mut error,
                    &mut raw,
                    c"s".as_ptr(),
                    argument.as_ptr(),
                )
            };
            unsafe {
                (self.api.free_error)(&mut error);
            }
            checked(rc)?;
            let reply = Reply {
                raw,
                api: &self.api,
            };
            self.bound()?;
            Ok(reply)
        }
        fn daemon_field(&self, member: &CStr, argument: &CStr) -> io::Result<Reply<'_>> {
            self.pin_call(
                c"org.freedesktop.DBus",
                c"/org/freedesktop/DBus",
                c"org.freedesktop.DBus",
                member,
                argument,
            )
        }
        fn pid1_bus_owner(&self) -> io::Result<CString> {
            let reply = self.daemon_field(c"GetNameOwner", c"org.freedesktop.systemd1")?;
            let mut raw = ptr::null();
            if checked(unsafe { (self.api.read)(reply.raw, c"s".as_ptr(), &mut raw) })? != 1 {
                return Err(refuse("system manager bus owner missing"));
            }
            let name = string(raw)?;
            let valid = name
                .strip_prefix(':')
                .and_then(|name| name.split_once('.'))
                .is_some_and(|(a, b)| {
                    !a.is_empty()
                        && !b.is_empty()
                        && a.bytes().all(|v| v.is_ascii_digit())
                        && b.bytes().all(|v| v.is_ascii_digit())
                });
            if name.len() > 128 || !valid {
                return Err(refuse("system manager bus owner is not unique"));
            }
            let name = CString::new(name).unwrap();
            for (method, expected) in [
                (c"GetConnectionUnixProcessID", 1u32),
                (c"GetConnectionUnixUser", 0u32),
            ] {
                let reply = self.daemon_field(method, &name)?;
                let mut value = u32::MAX;
                if checked(unsafe { (self.api.read)(reply.raw, c"u".as_ptr(), &mut value) })? != 1
                    || value != expected
                {
                    return Err(refuse("system manager bus owner is not PID1/UID0"));
                }
            }
            self.bound()?;
            Ok(name)
        }
    }

    /// Outcome of the per-query renewal of a held QueryBurst link.
    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum Renewal {
        /// Same peer, namespaces, boot and library inode; signal queue drained.
        Reuse,
        /// Drain bound exceeded or library inode changed: this query takes
        /// today's path on a fresh link.
        Replace,
    }
    /// One held manager link of a QueryBurst. `open` is exactly today's
    /// per-query path (Api::load plus Connection::new).
    pub(super) trait BurstLink: Sized {
        fn open() -> io::Result<Self>;
        fn renew(&mut self) -> io::Result<Renewal>;
    }
    pub(super) struct BurstSlot<L> {
        pub(super) depth: usize,
        pub(super) held: Option<L>,
    }
    impl<L> Default for BurstSlot<L> {
        fn default() -> Self {
            Self {
                depth: 0,
                held: None,
            }
        }
    }
    impl<L> BurstSlot<L> {
        fn active(&self) -> bool {
            self.depth > 0
        }
        pub(super) fn begin(&mut self) {
            self.depth = self.depth.saturating_add(1);
        }
        /// The link to close once the outermost burst scope ends.
        pub(super) fn end(&mut self) -> Option<L> {
            self.depth = self.depth.saturating_sub(1);
            if self.depth == 0 {
                self.held.take()
            } else {
                None
            }
        }
        /// A manager effect: whether a burst spans it, and the link that
        /// must be closed so that it never lives across the effect.
        pub(super) fn boundary(&mut self) -> (bool, Option<L>) {
            (self.active(), self.held.take())
        }
    }
    /// Run one read-only manager query on this thread's burst link, or on a
    /// fresh link (today's path) when no burst is live. An error while renewing
    /// or using the held link drops it and refuses; there is no retry.
    pub(super) fn with_link<L: BurstLink, T>(
        slot: &RefCell<BurstSlot<L>>,
        query: impl FnOnce(&mut L) -> io::Result<T>,
    ) -> io::Result<T> {
        if !slot.borrow().active() {
            return query(&mut L::open()?);
        }
        let held = slot.borrow_mut().held.take();
        let mut link = match held {
            None => L::open()?,
            Some(mut held) => match held.renew()? {
                Renewal::Reuse => held,
                Renewal::Replace => {
                    drop(held);
                    L::open()?
                }
            },
        };
        let result = query(&mut link);
        if result.is_ok() {
            let mut slot = slot.borrow_mut();
            if slot.active() && slot.held.is_none() {
                slot.held = Some(link);
            }
        }
        result
    }
    pub(super) const BURST_DRAIN_BOUND: usize = 256;
    /// Discard the manager signals PID1 queued on a held direct connection
    /// since its previous query. With no handlers, sd_bus_process drops each
    /// one. False when more than BURST_DRAIN_BOUND remain; an error refuses.
    pub(super) fn drain_queued(mut process: impl FnMut() -> io::Result<c_int>) -> io::Result<bool> {
        for _ in 0..BURST_DRAIN_BOUND {
            if process()? == 0 {
                return Ok(true);
            }
        }
        Ok(process()? == 0)
    }
    pub(super) struct HeldBurst {
        connection: Connection,
        library: (u64, u64),
    }
    impl BurstLink for HeldBurst {
        fn open() -> io::Result<Self> {
            let api = Rc::new(Api::load()?);
            let library = dir_identity(api._library.as_raw_fd())?;
            Ok(Self {
                connection: Connection::new(api)?,
                library,
            })
        }
        fn renew(&mut self) -> io::Result<Renewal> {
            // A fresh 3 s bound per query, exactly as a new connection has.
            self.connection.deadline = Instant::now() + Duration::from_secs(3);
            // Repeat the loader-environment check, the trusted /usr/lib walk,
            // the SONAME openat and its owner/mode/type check. Only dlopen and
            // dlsym are skipped: while this burst holds the handle, glibc maps
            // the same (st_dev, st_ino) to the already loaded link_map, so a
            // fresh dlopen would return this identical handle and symbols.
            let current = open_library()?;
            if dir_identity(current.as_raw_fd())? != self.library {
                return Ok(Renewal::Replace);
            }
            drop(current);
            // Peer credentials, PID1 pidfd liveness, boot id, all four
            // namespace pairs and the root are re-proved before and after.
            self.connection.bound()?;
            let (api, raw) = (&self.connection.api, self.connection.raw);
            let drained = drain_queued(|| checked(unsafe { (api.process)(raw, ptr::null_mut()) }))?;
            self.connection.bound()?;
            Ok(if drained {
                Renewal::Reuse
            } else {
                Renewal::Replace
            })
        }
    }
    thread_local! {
        static BURST: RefCell<BurstSlot<HeldBurst>> = RefCell::new(BurstSlot::default());
    }
    pub(super) fn burst_begin() {
        BURST.with(|slot| slot.borrow_mut().begin());
    }
    pub(super) fn burst_end() {
        // Thread teardown may already have destroyed the slot (and its link).
        let held = BURST
            .try_with(|slot| slot.borrow_mut().end())
            .ok()
            .flatten();
        drop(held);
    }
    pub(super) fn burst_boundary() -> bool {
        let observed = BURST.try_with(|slot| slot.borrow_mut().boundary());
        match observed {
            Ok((spanned, held)) => {
                drop(held);
                spanned
            }
            Err(_) => false,
        }
    }
    pub(super) fn query(query: super::super::ManagerQuery) -> io::Result<Vec<u8>> {
        BURST.with(|slot| {
            with_link(slot, |link: &mut HeldBurst| {
                query_on(&link.connection, query, "aegis-client.service")
            })
        })
    }
    /// MainPID, ControlGroup and InvocationID of the fixed guardian unit,
    /// the three properties `systemctl show -p` reports, read from PID1 over
    /// the verified direct connection with bound() around every read (S8).
    pub(super) fn guardian_service_identity() -> io::Result<super::ServiceIdentity> {
        BURST.with(|slot| {
            with_link(slot, |link: &mut HeldBurst| {
                let bus = &link.connection;
                let path = bus
                    .unit_named(super::GUARDIAN_UNIT)?
                    .ok_or_else(|| refuse("fixed guardian unit missing"))?;
                let service = c"org.freedesktop.systemd1.Service";
                let identity = super::ServiceIdentity {
                    main_pid: bus.field(&path, service, "MainPID", c"u")?,
                    control_group: bus.field(&path, service, "ControlGroup", c"s")?,
                    invocation_id: bus.field(
                        &path,
                        c"org.freedesktop.systemd1.Unit",
                        "InvocationID",
                        c"ay",
                    )?,
                };
                bus.bound()?;
                Ok(identity)
            })
        })
    }
    pub(super) fn inspect_active_private(name: &str) -> io::Result<super::ActivePrivateReadback> {
        if !super::private_unit_name(name) {
            return Err(refuse("invalid private unit"));
        }
        let bus = Connection::new(Rc::new(Api::load()?))?;
        let manager = bus.identity()?;
        let path = bus
            .unit_named(name)?
            .ok_or_else(|| refuse("owned private unit missing"))?;
        let unit = c"org.freedesktop.systemd1.Unit";
        let service = c"org.freedesktop.systemd1.Service";
        let invocation_id = bus.field(&path, unit, "InvocationID", c"ay")?;
        if invocation_id.len() != 32
            || !invocation_id.bytes().all(|byte| byte.is_ascii_hexdigit())
            || bus.field(&path, unit, "ActiveState", c"s")? != "active"
            || bus.field(&path, unit, "Id", c"s")? != name
            || bus.field(&path, service, "ControlPID", c"u")? != "0"
            || bus.field(&path, service, "NFileDescriptorStore", c"u")? != "0"
        {
            return Err(refuse("owned private unit not active"));
        }
        let (pidfd, main_pid) = hold_main_pid(&bus, &path, &invocation_id)?;
        let cgroup = bus.field(&path, service, "ControlGroup", c"s")?;
        if cgroup != format!("/system.slice/{name}")
            || bus.field(&path, unit, "InvocationID", c"ay")? != invocation_id
            || bus.field(&path, unit, "ActiveState", c"s")? != "active"
            || bus.field(&path, service, "MainPID", c"u")? != main_pid.to_string()
            || bus.field(&path, service, "ControlPID", c"u")? != "0"
            || bus.field(&path, service, "NFileDescriptorStore", c"u")? != "0"
            || bus.identity()? != manager
        {
            return Err(refuse("owned private unit changed"));
        }
        pid_state(&pidfd, false)?;
        Ok(super::ActivePrivateReadback {
            boot_id: manager.boot_id().into(),
            unit: name.into(),
            invocation_id,
            main_pid,
            cgroup,
            pid1_socket: manager.socket_identity(),
            pid1_netns: manager.netns_identity(),
        })
    }
    pub(super) fn inspect_stopped_private(
        name: &str,
        prior_invocation: &str,
        boot_id: &str,
    ) -> io::Result<super::StoppedPrivateReadback> {
        if !super::private_unit_name(name)
            || prior_invocation.len() != 32
            || !prior_invocation
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(refuse("invalid stopped private unit identity"));
        }
        let bus = Connection::new(Rc::new(Api::load()?))?;
        let manager = bus.identity()?;
        if manager.boot_id() != boot_id {
            return Err(refuse("stopped private unit boot changed"));
        }
        let unit = c"org.freedesktop.systemd1.Unit";
        let service = c"org.freedesktop.systemd1.Service";
        let collected = match bus.get_unit(name)? {
            None => true,
            Some(path) => {
                let admitted = || -> io::Result<()> {
                    let invocation = bus.field(&path, unit, "InvocationID", c"ay")?;
                    if bus.field(&path, unit, "Id", c"s")? != name
                        || bus.field(&path, unit, "ActiveState", c"s")? != "inactive"
                        || bus.field(&path, service, "MainPID", c"u")? != "0"
                        || bus.field(&path, service, "ControlPID", c"u")? != "0"
                        || bus.field(&path, service, "NFileDescriptorStore", c"u")? != "0"
                        || !(invocation.is_empty() || invocation == prior_invocation)
                    {
                        return Err(refuse("stopped private unit is not quiescent"));
                    }
                    Ok(())
                };
                admitted()?;
                admitted()?;
                false
            }
        };
        if bus.identity()? != manager {
            return Err(refuse("stopped private unit manager changed"));
        }
        Ok(super::StoppedPrivateReadback {
            boot_id: manager.boot_id().into(),
            unit: name.into(),
            prior_invocation: prior_invocation.into(),
            unit_collected: collected,
            fdstore_empty_verified: true,
            pid1_socket: manager.socket_identity(),
            pid1_netns: manager.netns_identity(),
        })
    }
    pub(super) fn inspect_idle_guardian(
        expected_pid: u32,
        expected_invocation: &str,
        boot_id: &str,
    ) -> io::Result<super::IdleGuardianReadback> {
        if expected_pid <= 1
            || expected_invocation.len() != 32
            || !expected_invocation
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(refuse("invalid idle guardian identity"));
        }
        let bus = Connection::new(Rc::new(Api::load()?))?;
        let manager = bus.identity()?;
        if manager.boot_id() != boot_id {
            return Err(refuse("idle guardian boot changed"));
        }
        let unit = c"org.freedesktop.systemd1.Unit";
        let service = c"org.freedesktop.systemd1.Service";
        let inspect = |name: &str, expected: Option<(u32, &str)>| -> io::Result<(OwnedFd, u32)> {
            let path = bus
                .unit_named(name)?
                .ok_or_else(|| refuse("idle guardian unit missing"))?;
            let invocation = bus.field(&path, unit, "InvocationID", c"ay")?;
            if invocation.len() != 32
                || !invocation.bytes().all(|byte| byte.is_ascii_hexdigit())
                || bus.field(&path, unit, "Id", c"s")? != name
                || bus.field(&path, unit, "ActiveState", c"s")? != "active"
                || bus.field(&path, unit, "SubState", c"s")? != "running"
                || bus.field(&path, service, "ControlPID", c"u")? != "0"
                || bus.field(&path, service, "NFileDescriptorStore", c"u")? != "0"
            {
                return Err(refuse("idle guardian unit changed"));
            }
            let (pidfd, pid) = hold_main_pid(&bus, &path, &invocation)?;
            if bus.field(&path, service, "ControlGroup", c"s")? != format!("/system.slice/{name}")
                || expected.is_some_and(|(wanted_pid, wanted_invocation)| {
                    pid != wanted_pid || invocation != wanted_invocation
                })
                || bus.field(&path, service, "NFileDescriptorStore", c"u")? != "0"
                || bus.field(&path, service, "ControlPID", c"u")? != "0"
            {
                return Err(refuse("idle guardian owner changed"));
            }
            Ok((pidfd, pid))
        };
        let (guardian_pidfd, _) = inspect(
            "aegis-auto-guardian.service",
            Some((expected_pid, expected_invocation)),
        )?;
        let (watchdog_pidfd, watchdog_pid) = inspect("aegis-auto-guardian-watchdog.service", None)?;
        if bus.identity()? != manager {
            return Err(refuse("idle guardian manager changed"));
        }
        pid_state(&guardian_pidfd, false)?;
        pid_state(&watchdog_pidfd, false)?;
        Ok(super::IdleGuardianReadback {
            boot_id: manager.boot_id().into(),
            guardian_pid: expected_pid,
            guardian_invocation_id: expected_invocation.into(),
            watchdog_pid,
            fdstore_empty_verified: true,
            pid1_socket: manager.socket_identity(),
            pid1_netns: manager.netns_identity(),
        })
    }
    fn query_on(
        bus: &Connection,
        query: super::super::ManagerQuery,
        name: &str,
    ) -> io::Result<Vec<u8>> {
        use super::super::ManagerQuery;
        let manager = c"org.freedesktop.systemd1.Manager";
        let unit = c"org.freedesktop.systemd1.Unit";
        let service = c"org.freedesktop.systemd1.Service";
        let mut output = String::new();
        if matches!(query, ManagerQuery::SearchPaths) {
            for (name, kind) in [("UnitPath", c"as"), ("Version", c"s")] {
                output.push_str(&format!(
                    "{name}={}\n",
                    bus.field(c"/org/freedesktop/systemd1", manager, name, kind)?
                ));
            }
        } else if let Some(path) = bus.unit_named(name)? {
            let mut fields = match query {
                ManagerQuery::UnitNamespace => vec![
                    ("Id", unit, c"s"),
                    ("LoadState", unit, c"s"),
                    ("FragmentPath", unit, c"s"),
                    ("DropInPaths", unit, c"as"),
                    ("Names", unit, c"as"),
                ],
                ManagerQuery::Stopped | ManagerQuery::Active => vec![
                    ("Id", unit, c"s"),
                    ("LoadState", unit, c"s"),
                    ("ActiveState", unit, c"s"),
                    ("SubState", unit, c"s"),
                    ("MainPID", service, c"u"),
                    ("ControlPID", service, c"u"),
                    ("ControlGroup", service, c"s"),
                    ("InvocationID", unit, c"ay"),
                    ("User", service, c"s"),
                    ("Group", service, c"s"),
                ],
                ManagerQuery::SearchPaths => unreachable!(),
            };
            if matches!(query, ManagerQuery::Stopped) {
                fields.push(("InactiveEnterTimestampMonotonic", unit, c"t"));
            }
            if matches!(query, ManagerQuery::Active) {
                fields.extend([
                    ("ExecMainStartTimestampMonotonic", service, c"t"),
                    ("Type", service, c"s"),
                    ("NotifyAccess", service, c"s"),
                    ("StatusText", service, c"s"),
                ]);
            }
            for (name, interface, kind) in fields {
                let value = if matches!(query, ManagerQuery::Stopped) && name == "InvocationID" {
                    bus.stopped_invocation(&path)?
                } else {
                    bus.field(&path, interface, name, kind)?
                };
                output.push_str(&format!("{name}={value}\n"));
            }
        } else {
            if name != "aegis-client.service" {
                return Err(refuse("owned private unit missing"));
            }
            match query {
                ManagerQuery::UnitNamespace=>output.push_str("Id=aegis-client.service\nLoadState=not-found\nFragmentPath=\nDropInPaths=\nNames=aegis-client.service\n"),
                // NoSuchUnit comes from this actual PID1 connection. The
                // existing stopped parser separately requires an absent
                // accepted unit namespace and an absent kernel cgroup.
                ManagerQuery::Stopped=>output.push_str("Id=aegis-client.service\nLoadState=not-found\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nControlGroup=\nInvocationID=\nInactiveEnterTimestampMonotonic=0\nUser=\nGroup=\n"),
                _=>return Err(refuse("fixed service not installed")),
            }
        }
        bus.bound()?;
        if output.len() > 8192 {
            return Err(refuse("PID1 aggregate exceeded bound"));
        }
        Ok(output.into_bytes())
    }
}
pub(super) fn query(query: super::ManagerQuery) -> io::Result<Vec<u8>> {
    bus::query(query)
}

const GUARDIAN_UNIT: &str = "aegis-auto-guardian.service";

/// The fixed guardian unit's identity as PID1 reports it (S8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServiceIdentity {
    pub(crate) main_pid: String,
    pub(crate) control_group: String,
    pub(crate) invocation_id: String,
}

/// Root-worker read of the guardian's MainPID, ControlGroup and InvocationID
/// over the verified direct PID1 connection, in place of spawning
/// `/usr/bin/timeout /usr/bin/systemctl show` (S8). Callers keep their own
/// comparisons, the /proc cgroup check and the held guardian pidfd check.
pub(crate) fn guardian_service_identity() -> io::Result<ServiceIdentity> {
    bus::guardian_service_identity()
}

/// A burst of read-only PID1 manager queries for one stopped proof, one
/// prepared proof or one accepted-policy epoch validation (S7, R8).
///
/// While a burst is live on this thread, manager queries and the guardian
/// identity read share one verified direct PID1 connection instead of a new
/// connection and handshake per query. Every query still gets a fresh 3 s
/// bound, the trusted library walk and inode check, `bound()` (peer
/// credentials, PID1 pidfd, boot id, all namespace pairs, root) before and
/// after a bounded drain of queued manager signals, and fresh property reads
/// with `bound()` around each. More than 256 queued signals or a changed
/// library inode makes that query take today's path; any error on the held
/// socket refuses with no retry.
///
/// A burst never lives across a manager effect. daemon-reload, StartUnit,
/// StopUnit and job waits never receive the burst link (only the read-only
/// query paths can reach it) and each calls `manager_effect_boundary`, which
/// closes any held link and debug-asserts that no burst is live. The guard
/// is !Send, so a burst cannot leave its thread.
#[must_use = "the burst ends when this guard is dropped"]
pub(crate) struct QueryBurst {
    _thread_bound: std::marker::PhantomData<*const ()>,
}
impl QueryBurst {
    pub(crate) fn begin() -> Self {
        bus::burst_begin();
        Self {
            _thread_bound: std::marker::PhantomData,
        }
    }
}
impl Drop for QueryBurst {
    fn drop(&mut self) {
        bus::burst_end();
    }
}

/// Called before every manager effect of this process. A held burst link is
/// closed here in every build; a burst still live is a scoping defect.
pub(crate) fn manager_effect_boundary(effect: &'static str) {
    let spanned = bus::burst_boundary();
    debug_assert!(
        !spanned,
        "PID1 query burst spans a manager effect: {effect}"
    );
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivePrivateReadback {
    pub(crate) boot_id: String,
    pub(crate) unit: String,
    pub(crate) invocation_id: String,
    pub(crate) main_pid: u32,
    pub(crate) cgroup: String,
    pub(crate) pid1_socket: (u64, u64),
    pub(crate) pid1_netns: (u64, u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoppedPrivateReadback {
    pub(crate) boot_id: String,
    pub(crate) unit: String,
    pub(crate) prior_invocation: String,
    pub(crate) unit_collected: bool,
    pub(crate) fdstore_empty_verified: bool,
    pub(crate) pid1_socket: (u64, u64),
    pub(crate) pid1_netns: (u64, u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IdleGuardianReadback {
    pub(crate) boot_id: String,
    pub(crate) guardian_pid: u32,
    pub(crate) guardian_invocation_id: String,
    pub(crate) watchdog_pid: u32,
    pub(crate) fdstore_empty_verified: bool,
    pub(crate) pid1_socket: (u64, u64),
    pub(crate) pid1_netns: (u64, u64),
}

/// Read-only observation. The returned fields do not authorize StartUnit or
/// StopUnit; callers must separately authenticate their StageGuard receipts.
pub(crate) fn inspect_active_private(name: &str) -> io::Result<ActivePrivateReadback> {
    bus::inspect_active_private(name)
}

/// Fresh same-boot PID1 observation after a separately authenticated Stop.
/// This does not replace the historical pidfd/cgroup Stop receipt and grants
/// no StartUnit or StopUnit authority.
pub(crate) fn inspect_stopped_private(
    name: &str,
    prior_invocation: &str,
    boot_id: &str,
) -> io::Result<StoppedPrivateReadback> {
    bus::inspect_stopped_private(name, prior_invocation, boot_id)
}

/// Confirm passive fixed guardian and watchdog units remain live while both
/// PID1 descriptor stores are empty after the authenticated private Stop.
pub(crate) fn inspect_idle_guardian(
    expected_pid: u32,
    expected_invocation: &str,
    boot_id: &str,
) -> io::Result<IdleGuardianReadback> {
    bus::inspect_idle_guardian(expected_pid, expected_invocation, boot_id)
}

#[cfg(test)]
mod active_private_readback_tests {
    use super::*;

    #[test]
    fn private_readback_refuses_unowned_unit_names_before_manager_connection() {
        for name in [
            "aegis-client.service",
            "aegis-auto@short.service",
            "aegis-auto@ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdef0123456789abcdef.service",
            "aegis-auto@0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.service/extra",
        ] {
            assert!(inspect_active_private(name).is_err());
        }
    }
}

#[cfg(test)]
mod query_burst_tests {
    use super::bus::{drain_queued, with_link, BurstLink, BurstSlot, Renewal, BURST_DRAIN_BOUND};
    use super::{manager_effect_boundary, QueryBurst};
    use std::cell::{Cell, RefCell};
    use std::io;

    thread_local! {
        static OPENS: Cell<usize> = const { Cell::new(0) };
        static RENEWS: Cell<usize> = const { Cell::new(0) };
        static CLOSED: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
        static SCRIPT: RefCell<Vec<io::Result<Renewal>>> = const { RefCell::new(Vec::new()) };
    }
    /// A recording link: `open` is today's fresh connection, `renew` is the
    /// per-query re-proof and drain of a held one.
    #[derive(Debug)]
    struct Link(usize);
    impl BurstLink for Link {
        fn open() -> io::Result<Self> {
            Ok(Link(OPENS.with(|count| {
                count.set(count.get() + 1);
                count.get()
            })))
        }
        fn renew(&mut self) -> io::Result<Renewal> {
            RENEWS.with(|count| count.set(count.get() + 1));
            SCRIPT.with(|script| {
                let mut script = script.borrow_mut();
                if script.is_empty() {
                    Ok(Renewal::Reuse)
                } else {
                    script.remove(0)
                }
            })
        }
    }
    impl Drop for Link {
        fn drop(&mut self) {
            CLOSED.with(|closed| closed.borrow_mut().push(self.0));
        }
    }
    fn reset(script: Vec<io::Result<Renewal>>) -> RefCell<BurstSlot<Link>> {
        OPENS.with(|count| count.set(0));
        RENEWS.with(|count| count.set(0));
        CLOSED.with(|closed| closed.borrow_mut().clear());
        SCRIPT.with(|value| *value.borrow_mut() = script);
        RefCell::new(BurstSlot::default())
    }
    fn counts() -> (usize, usize, Vec<usize>) {
        (
            OPENS.with(Cell::get),
            RENEWS.with(Cell::get),
            CLOSED.with(|closed| closed.borrow().clone()),
        )
    }
    fn ask(slot: &RefCell<BurstSlot<Link>>) -> io::Result<usize> {
        with_link(slot, |link: &mut Link| Ok(link.0))
    }

    #[test]
    fn without_a_burst_every_query_takes_todays_fresh_connection() {
        let slot = reset(Vec::new());
        assert_eq!(ask(&slot).unwrap(), 1);
        assert_eq!(ask(&slot).unwrap(), 2);
        assert_eq!(counts(), (2, 0, vec![1, 2]));
    }

    #[test]
    fn a_burst_reuses_one_link_and_re_proves_it_on_every_query() {
        let slot = reset(Vec::new());
        slot.borrow_mut().begin();
        for _ in 0..3 {
            assert_eq!(ask(&slot).unwrap(), 1);
        }
        // One connection, renewed (deadline, library, bound, drain, bound)
        // for every query after the first; nothing closed yet.
        assert_eq!(counts(), (1, 2, vec![]));
        drop(slot.borrow_mut().end());
        assert_eq!(counts(), (1, 2, vec![1]), "the link is closed at burst end");
        assert_eq!(
            ask(&slot).unwrap(),
            2,
            "after the burst: today's path again"
        );
    }

    #[test]
    fn an_error_on_the_held_link_refuses_with_no_retry() {
        for error in [
            io::Error::new(io::ErrorKind::PermissionDenied, "PID1 peer changed"),
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "PID1 namespace identity changed",
            ),
            io::Error::new(io::ErrorKind::TimedOut, "PID1 query bound expired"),
            io::Error::from_raw_os_error(libc::ECONNRESET),
        ] {
            let slot = reset(vec![Err(error)]);
            slot.borrow_mut().begin();
            assert_eq!(ask(&slot).unwrap(), 1);
            assert!(ask(&slot).is_err(), "a held-link failure is a refusal");
            // No fresh connection was opened to retry that query, and the
            // failed link is gone.
            assert_eq!(counts(), (1, 1, vec![1]));
            assert!(slot.borrow().held.is_none());
            // The next, separate query opens today's fresh connection.
            assert_eq!(ask(&slot).unwrap(), 2);
            drop(slot.borrow_mut().end());
        }
    }

    #[test]
    fn a_full_signal_queue_or_new_library_inode_takes_todays_path() {
        let slot = reset(vec![Ok(Renewal::Replace)]);
        slot.borrow_mut().begin();
        assert_eq!(ask(&slot).unwrap(), 1);
        assert_eq!(ask(&slot).unwrap(), 2);
        // The old link is closed before the replacement is opened.
        assert_eq!(counts(), (2, 1, vec![1]));
        assert_eq!(ask(&slot).unwrap(), 2);
        drop(slot.borrow_mut().end());
        assert_eq!(counts().2, vec![1, 2]);
    }

    #[test]
    fn a_failed_query_never_leaves_its_link_for_the_next_one() {
        let slot = reset(Vec::new());
        slot.borrow_mut().begin();
        let failed: io::Result<()> = with_link(&slot, |_link: &mut Link| {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unexpected unit path",
            ))
        });
        assert!(failed.is_err());
        assert_eq!(counts(), (1, 0, vec![1]));
        assert_eq!(ask(&slot).unwrap(), 2);
        drop(slot.borrow_mut().end());
    }

    #[test]
    fn nested_scopes_share_one_link_until_the_outermost_ends() {
        let slot = reset(Vec::new());
        slot.borrow_mut().begin();
        assert_eq!(ask(&slot).unwrap(), 1);
        slot.borrow_mut().begin();
        assert_eq!(ask(&slot).unwrap(), 1);
        assert!(
            slot.borrow_mut().end().is_none(),
            "inner end keeps the link"
        );
        assert_eq!(ask(&slot).unwrap(), 1);
        drop(slot.borrow_mut().end());
        assert_eq!(counts(), (1, 2, vec![1]));
    }

    #[test]
    fn a_manager_effect_closes_any_held_link() {
        let slot = reset(Vec::new());
        assert!(matches!(slot.borrow_mut().boundary(), (false, None)));
        slot.borrow_mut().begin();
        assert_eq!(ask(&slot).unwrap(), 1);
        let (spanned, held) = slot.borrow_mut().boundary();
        assert!(spanned);
        drop(held);
        assert_eq!(counts().2, vec![1], "no link lives across the effect");
        assert_eq!(ask(&slot).unwrap(), 2);
        drop(slot.borrow_mut().end());
    }

    #[test]
    fn effects_outside_a_burst_pass_the_boundary() {
        manager_effect_boundary("daemon-reload");
        let burst = QueryBurst::begin();
        drop(burst);
        manager_effect_boundary("StartUnit/StopUnit");
        manager_effect_boundary("job wait");
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "PID1 query burst spans a manager effect: daemon-reload")]
    fn a_burst_spanning_a_daemon_reload_is_a_debug_assertion() {
        let _burst = QueryBurst::begin();
        manager_effect_boundary("daemon-reload");
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "PID1 query burst spans a manager effect: job wait")]
    fn a_nested_burst_spanning_a_job_wait_is_a_debug_assertion() {
        let _outer = QueryBurst::begin();
        drop(QueryBurst::begin());
        manager_effect_boundary("job wait");
    }

    #[test]
    fn a_burst_is_confined_to_its_thread() {
        let _burst = QueryBurst::begin();
        let other = std::thread::spawn(super::bus::burst_boundary)
            .join()
            .unwrap();
        assert!(
            !other,
            "another thread sees no burst and takes today's path"
        );
    }

    #[test]
    fn the_signal_drain_is_bounded_and_refuses_errors() {
        let drained = |queued: usize| {
            let mut left = queued;
            let mut calls = 0usize;
            let result = drain_queued(|| {
                calls += 1;
                Ok(if left == 0 {
                    0
                } else {
                    left -= 1;
                    1
                })
            })
            .unwrap();
            (result, calls)
        };
        assert_eq!(drained(0), (true, 1));
        assert_eq!(drained(27), (true, 28));
        assert_eq!(drained(BURST_DRAIN_BOUND), (true, BURST_DRAIN_BOUND + 1));
        // G0b: 1308 messages were queued on a connection held across a
        // daemon-reload; such a link is replaced, never drained unbounded.
        assert_eq!(
            drained(BURST_DRAIN_BOUND + 1),
            (false, BURST_DRAIN_BOUND + 1)
        );
        assert_eq!(drained(1308), (false, BURST_DRAIN_BOUND + 1));
        let mut calls = 0;
        assert!(drain_queued(|| {
            calls += 1;
            if calls == 3 {
                Err(io::Error::from_raw_os_error(libc::ECONNRESET))
            } else {
                Ok(1)
            }
        })
        .is_err());
        assert_eq!(calls, 3);
    }
}

pub(crate) use bus::{FixedUnitPin, OwnedStart, PreparedStart};

pub(crate) fn prepare_owned(
    policy: crate::profile_auto_unit_policy::linux::TransientPolicy,
) -> Result<PreparedStart, &'static str> {
    bus::prepare_owned(policy)
}

pub(crate) fn stop_finalized<A: FinalizedStopAuthority>(
    authority: &mut A,
) -> Result<CompletedStop, &'static str> {
    bus::stop_finalized(authority)
}

/// Native identity minted by the retained, peer-verified connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManagerIdentity {
    boot_id: String,
    socket: (u64, u64),
    netns: (u64, u64),
    namespaces: [(u64, u64); 4],
    root: (u64, u64),
}
#[derive(Debug)]
pub(crate) struct SubmittedJob {
    id: u32,
    path: String,
    unit: String,
    identity: ManagerIdentity,
}
#[derive(Debug)]
pub(crate) struct CompletedStart {
    submitted: SubmittedJob,
    invocation: String,
}

#[derive(Debug)]
pub(crate) struct CompletedStop {
    submitted: SubmittedJob,
    prior_invocation: String,
    main_pidfd: OwnedFd,
    cgroup: HeldCgroup,
    unit_collected: bool,
}
// Trait implementations belong to the real retained stage/guardian owner,
// never to a caller JSON record or a hash-only receipt.
#[allow(dead_code)]
pub(crate) trait StartAuthority {
    fn requires_terminal_host_source_proof(&self) -> bool {
        false
    }
    fn admit_pre_marker(
        &self,
        manager: &ManagerIdentity,
        unit: &PrivateUnit,
    ) -> Result<(), &'static str>;
    fn claim_may_send(
        &mut self,
        manager: &ManagerIdentity,
        unit: &PrivateUnit,
    ) -> Result<(), &'static str>;
    fn admit_post_marker(
        &self,
        manager: &ManagerIdentity,
        unit: &PrivateUnit,
    ) -> Result<(), &'static str>;
    fn record_submitted(&mut self, job: &SubmittedJob) -> Result<(), &'static str>;
    fn record_completed(&mut self, job: &CompletedStart) -> Result<(), &'static str>;
}

pub(crate) trait StopAuthority {
    fn admit_compensation(&self, start: &CompletedStart) -> Result<(), &'static str>;
    fn record_stop_submitted(&mut self, job: &SubmittedJob) -> Result<(), &'static str>;
    fn record_stop_completed(&mut self, job: &CompletedStop) -> Result<(), &'static str>;
}

pub(crate) trait FinalizedStopAuthority {
    fn unit(&self) -> &str;
    fn admit_current(
        &self,
        manager: &ManagerIdentity,
        invocation: &str,
    ) -> Result<(), &'static str>;
    fn claim_before_send(
        &mut self,
        manager: &ManagerIdentity,
        invocation: &str,
    ) -> Result<(), &'static str>;
    fn record_stop_submitted(&mut self, job: &SubmittedJob) -> Result<(), &'static str>;
    fn record_stop_completed(&mut self, job: &CompletedStop) -> Result<(), &'static str>;
}

impl ManagerIdentity {
    pub(crate) fn namespace_identities(&self) -> [(u64, u64); 4] {
        self.namespaces
    }
    pub(crate) fn root_identity(&self) -> (u64, u64) {
        self.root
    }
    pub(crate) fn boot_id(&self) -> &str {
        &self.boot_id
    }
    pub(crate) fn socket_identity(&self) -> (u64, u64) {
        self.socket
    }
    pub(crate) fn netns_identity(&self) -> (u64, u64) {
        self.netns
    }
}

impl SubmittedJob {
    pub(crate) fn id(&self) -> u32 {
        self.id
    }
    pub(crate) fn path(&self) -> &str {
        &self.path
    }
    pub(crate) fn unit(&self) -> &str {
        &self.unit
    }
    pub(crate) fn manager(&self) -> &ManagerIdentity {
        &self.identity
    }
}

impl CompletedStart {
    pub(crate) fn facts(&self) -> (&SubmittedJob, &str) {
        (&self.submitted, &self.invocation)
    }
}

impl CompletedStop {
    pub(crate) fn quiescent_unit_collected(&self) -> Result<bool, &'static str> {
        bus::pid_state(&self.main_pidfd, true).map_err(|_| "AUTO stopped MainPID is not exited")?;
        bus::cgroup_empty(&self.cgroup).map_err(|_| "AUTO stopped cgroup is not empty")?;
        Ok(self.unit_collected)
    }
    pub(crate) fn facts(&self) -> (&SubmittedJob, &str) {
        (&self.submitted, &self.prior_invocation)
    }
}
