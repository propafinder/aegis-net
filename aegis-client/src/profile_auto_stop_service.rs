//! Fixed systemd lifecycle clients for an installed AUTO FullTun service.
//!
//! This command has no pathname or action arguments.  It is deliberately a
//! client of the installed guardian: the service process must never mutate
//! routes or nftables from an unconstrained shell stop hook.  The guardian
//! authenticates our PID, executable, ControlPID, invocation and cgroup, then
//! persists the stop intent before applying and reading back a deny policy.
#![cfg(target_os = "linux")]

use serde::Deserialize;
use std::{
    fs, io,
    mem::{size_of, zeroed},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    os::unix::process::CommandExt,
    process::Command,
    time::{Duration, Instant},
};

const SOCKET_DIR: &str = "/run/aegis-auto-guard";
const SOCKET: &str = "/run/aegis-auto-guard/authority.sock";
const REFUSED: &str = "AUTO guarded service lifecycle requires native guardian recovery";
const DEADLINE: Duration = Duration::from_secs(12);
const BIND_HANDOFF_DEADLINE: Duration = Duration::from_secs(14);
const GUARD_LOCK: &str = "/var/lib/aegis-install/client/device-guard.conf.lock";
const GUARD_HELPER: &str = "/usr/local/lib/aegis/helpers/aegis-device-egress-guard.sh";
const GUARD_STATE: &str = "/var/lib/aegis-install/client/device-guard.conf";
const INHERITED_BIND_SOCKET_FD: i32 = 8;
const INHERITED_GUARD_FD: i32 = 9;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StopResult {
    schema: String,
    deny_retained: bool,
    intent_retained: bool,
    policy_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BindHandoff {
    schema: String,
    boot_id: String,
    invocation_id: String,
    unit: String,
    current_boot_source_verified: bool,
}

impl BindHandoff {
    fn matches(&self, boot: &str, invocation: &str, unit: &str) -> bool {
        self.schema == "aegis_auto_guardian_bind_handoff_v2"
            && self.current_boot_source_verified
            && self.boot_id == boot
            && self.invocation_id == invocation
            && self.unit == unit
    }
}

fn trusted_socket() -> Result<(u64, u64), &'static str> {
    let parent = fs::symlink_metadata(SOCKET_DIR).map_err(|_| REFUSED)?;
    let leaf = fs::symlink_metadata(SOCKET).map_err(|_| REFUSED)?;
    if !parent.is_dir()
        || parent.uid() != 0
        || parent.permissions().mode() & 0o7777 != 0o700
        || !leaf.file_type().is_socket()
        || leaf.uid() != 0
        || leaf.permissions().mode() & 0o7777 != 0o600
    {
        return Err(REFUSED);
    }
    Ok((leaf.dev(), leaf.ino()))
}

struct GuardianPeer {
    socket: OwnedFd,
    pidfd: OwnedFd,
    pid: i32,
}

impl GuardianPeer {
    fn revalidate(&self) -> Result<(), &'static str> {
        let mut item = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        };
        if unsafe { libc::poll(&raw mut item, 1, 0) } != 0 {
            return Err(REFUSED);
        }
        let actual =
            fs::read_to_string(format!("/proc/{}/cgroup", self.pid)).map_err(|_| REFUSED)?;
        if actual != "0::/system.slice/aegis-auto-guardian.service\n" {
            return Err(REFUSED);
        }
        item.revents = 0;
        if unsafe { libc::poll(&raw mut item, 1, 0) } != 0 {
            return Err(REFUSED);
        }
        Ok(())
    }
}

fn guardian_unit_identity() -> Result<(i32, String), &'static str> {
    // A bounded, fixed-argv PID 1 query ties the socket peer to the installed
    // guardian unit.  No ambient PATH, user-supplied unit or shell is involved.
    let output = Command::new("/usr/bin/timeout")
        .args([
            "-k",
            "1s",
            "2s",
            "/usr/bin/systemctl",
            "show",
            "aegis-auto-guardian.service",
            "-p",
            "MainPID",
            "-p",
            "ControlGroup",
            "-p",
            "InvocationID",
            "--no-pager",
        ])
        .env_clear()
        .env("LANG", "C")
        .output()
        .map_err(|_| REFUSED)?;
    if !output.status.success() || output.stdout.len() > 1024 || output.stderr.len() > 1024 {
        return Err(REFUSED);
    }
    let mut pid = None;
    let mut cgroup = None;
    let mut invocation = None;
    for line in std::str::from_utf8(&output.stdout)
        .map_err(|_| REFUSED)?
        .lines()
    {
        let (key, value) = line.split_once('=').ok_or(REFUSED)?;
        match key {
            "MainPID" if pid.is_none() => {
                pid = Some(value.parse::<i32>().map_err(|_| REFUSED)?);
            }
            "ControlGroup" if cgroup.is_none() => cgroup = Some(value),
            "InvocationID" if invocation.is_none() => invocation = Some(value),
            _ => return Err(REFUSED),
        }
    }
    let pid = pid.ok_or(REFUSED)?;
    let cgroup = cgroup.ok_or(REFUSED)?;
    let invocation = invocation.ok_or(REFUSED)?;
    if pid <= 1
        || cgroup != "/system.slice/aegis-auto-guardian.service"
        || !exact_hex(invocation, 32)
    {
        return Err(REFUSED);
    }
    let actual = fs::read_to_string(format!("/proc/{pid}/cgroup")).map_err(|_| REFUSED)?;
    if actual != format!("0::{cgroup}\n") {
        return Err(REFUSED);
    }
    Ok((pid, invocation.to_owned()))
}

fn connect(deadline: Instant) -> Result<GuardianPeer, &'static str> {
    let socket_id = trusted_socket()?;
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(REFUSED);
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut address: libc::sockaddr_un = unsafe { zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let path = SOCKET.as_bytes();
    if path.len() >= address.sun_path.len() {
        return Err(REFUSED);
    }
    for (target, byte) in address.sun_path.iter_mut().zip(path) {
        *target = *byte as libc::c_char;
    }
    let status = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&raw const address).cast(),
            size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    if status != 0 {
        if io::Error::last_os_error().raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(REFUSED);
        }
        ready(fd.as_raw_fd(), libc::POLLOUT, deadline)?;
        let mut error = 0i32;
        let mut len = size_of::<i32>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&raw mut error).cast(),
                &raw mut len,
            )
        } != 0
            || len as usize != size_of::<i32>()
            || error != 0
        {
            return Err(REFUSED);
        }
    }
    if trusted_socket()? != socket_id {
        return Err(REFUSED);
    }
    let mut credential: libc::ucred = unsafe { zeroed() };
    let mut len = size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut credential).cast(),
            &raw mut len,
        )
    } != 0
        || len as usize != size_of::<libc::ucred>()
        || credential.pid <= 1
        || credential.uid != 0
        || credential.gid != 0
    {
        return Err(REFUSED);
    }
    // SO_PEERPIDFD is tied to the connected peer itself.  Opening a pidfd by
    // numeric SO_PEERCRED PID would permit reuse between the two syscalls.
    let mut pidfd_raw = -1i32;
    let mut pidfd_len = size_of::<i32>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERPIDFD,
            (&raw mut pidfd_raw).cast(),
            &raw mut pidfd_len,
        )
    } != 0
        || pidfd_len as usize != size_of::<i32>()
        || pidfd_raw < 0
    {
        return Err(REFUSED);
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd_raw) };
    if unsafe { libc::fcntl(pidfd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        return Err(REFUSED);
    }
    let (pid, _invocation) = guardian_unit_identity()?;
    if pid != credential.pid {
        return Err(REFUSED);
    }
    let peer = GuardianPeer {
        socket: fd,
        pidfd,
        pid,
    };
    peer.revalidate()?;
    Ok(peer)
}

fn ready(fd: i32, events: i16, deadline: Instant) -> Result<(), &'static str> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(REFUSED);
    }
    let timeout = remaining.as_millis().min(i32::MAX as u128) as i32;
    let mut item = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    if unsafe { libc::poll(&raw mut item, 1, timeout) } != 1
        || item.revents & events == 0
        || item.revents & (libc::POLLERR | libc::POLLNVAL) != 0
        || (events == libc::POLLOUT && item.revents & libc::POLLHUP != 0)
    {
        return Err(REFUSED);
    }
    Ok(())
}

fn exact_hex(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn private_unit(unit: &str) -> bool {
    unit.len() == "aegis-auto@".len() + 64 + ".service".len()
        && unit.starts_with("aegis-auto@")
        && unit.ends_with(".service")
        && unit["aegis-auto@".len()..unit.len() - ".service".len()]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn request(
    schema: &str,
    command: &str,
    unit: &str,
) -> Result<(Vec<u8>, String, String), &'static str> {
    if unsafe { libc::geteuid() } != 0 || !private_unit(unit) {
        return Err(REFUSED);
    }
    let invocation = std::env::var("INVOCATION_ID").map_err(|_| REFUSED)?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|_| REFUSED)?;
    let boot = boot.trim_end_matches('\n');
    if !exact_hex(&invocation, 32)
        || boot.len() != 36
        || boot.as_bytes()[8] != b'-'
        || boot.as_bytes()[13] != b'-'
        || boot.as_bytes()[18] != b'-'
        || boot.as_bytes()[23] != b'-'
        || !boot
            .bytes()
            .filter(|b| *b != b'-')
            .all(|b| b.is_ascii_hexdigit())
    {
        return Err(REFUSED);
    }
    let value = serde_json::to_vec(&serde_json::json!({
        "schema": schema,
        "command": command,
        "unit": unit,
        "boot_id": boot,
        "invocation_id": invocation,
    }))
    .map_err(|_| REFUSED)?;
    Ok((value, boot.to_owned(), invocation))
}

/// Called only for the fixed, argument-free hidden main command.
pub(crate) fn run(unit: &str) -> Result<(), &'static str> {
    run_inner(unit, false)
}

/// Only the PID 1 ExecStop slot may request a clean terminal receipt.
/// ExecStopPost retains the deny-only STOP_BEGIN command.
pub(crate) fn run_clean(unit: &str) -> Result<(), &'static str> {
    if std::env::var("SERVICE_RESULT").as_deref() != Ok("success") {
        return Err(REFUSED);
    }
    run_inner(unit, true)
}

fn run_inner(unit: &str, clean: bool) -> Result<(), &'static str> {
    let (request, _, _) = request(
        "aegis_auto_guardian_stop_v1",
        if clean { "STOP_CLEAN" } else { "STOP_BEGIN" },
        unit,
    )?;
    let deadline = Instant::now() + DEADLINE;
    let peer = connect(deadline)?;
    ready(peer.socket.as_raw_fd(), libc::POLLOUT, deadline)?;
    let sent = unsafe {
        libc::send(
            peer.socket.as_raw_fd(),
            request.as_ptr().cast(),
            request.len(),
            libc::MSG_NOSIGNAL,
        )
    };
    if sent != request.len() as isize {
        return Err(REFUSED);
    }
    ready(peer.socket.as_raw_fd(), libc::POLLIN, deadline)?;
    let mut bytes = [0u8; 512];
    let received = unsafe {
        libc::recv(
            peer.socket.as_raw_fd(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
            libc::MSG_TRUNC,
        )
    };
    if received <= 0 || received as usize > bytes.len() {
        return Err(REFUSED);
    }
    peer.revalidate()?;
    let result: StopResult =
        serde_json::from_slice(&bytes[..received as usize]).map_err(|_| REFUSED)?;
    if result.schema != "aegis_auto_guardian_stop_result_v1"
        || !result.deny_retained
        || !result.intent_retained
        || !exact_hex(&result.policy_sha256, 64)
    {
        return Err(REFUSED);
    }
    Ok(())
}

fn trusted_guard_lock(fd: &OwnedFd) -> Result<(), &'static str> {
    let path = fs::symlink_metadata(GUARD_LOCK).map_err(|_| REFUSED)?;
    let mut stat: libc::stat = unsafe { zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &raw mut stat) } != 0
        || !path.file_type().is_file()
        || path.uid() != 0
        || path.nlink() != 1
        || path.permissions().mode() & 0o7777 != 0o600
        || stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_uid != 0
        || stat.st_nlink != 1
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_dev != path.dev()
        || stat.st_ino != path.ino()
    {
        return Err(REFUSED);
    }
    let info =
        fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd())).map_err(|_| REFUSED)?;
    if !crate::profile_auto_stopped_service::held_transferred_flock_line(
        &info,
        stat.st_dev,
        stat.st_ino,
    ) {
        return Err(REFUSED);
    }
    Ok(())
}

fn bind_handoff(
    peer: &GuardianPeer,
    deadline: Instant,
) -> Result<(BindHandoff, OwnedFd), &'static str> {
    ready(peer.socket.as_raw_fd(), libc::POLLIN, deadline)?;
    let mut bytes = [0u8; 512];
    // Aligned storage for the one SCM_RIGHTS FD. Even an invalid ancillary
    // packet is drained into OwnedFd values so a refusal cannot leak FDs.
    let mut control = [0usize; 8];
    let mut vector = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &raw mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = std::mem::size_of_val(&control);
    let received = unsafe {
        libc::recvmsg(
            peer.socket.as_raw_fd(),
            &raw mut message,
            libc::MSG_CMSG_CLOEXEC | libc::MSG_TRUNC,
        )
    };
    if received <= 0 {
        return Err(REFUSED);
    }
    let mut passed = Vec::new();
    let mut valid_ancillary = true;
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&raw const message) };
    while !header.is_null() {
        let entry = unsafe { &*header };
        let base_len = unsafe { libc::CMSG_LEN(0) as usize };
        if entry.cmsg_level != libc::SOL_SOCKET
            || entry.cmsg_type != libc::SCM_RIGHTS
            || entry.cmsg_len < base_len
            || (entry.cmsg_len - base_len) % size_of::<i32>() != 0
        {
            valid_ancillary = false;
            break;
        }
        let count = (entry.cmsg_len - base_len) / size_of::<i32>();
        for index in 0..count {
            let raw = unsafe {
                std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<i32>().add(index))
            };
            if raw < 0 {
                valid_ancillary = false;
                break;
            }
            passed.push(unsafe { OwnedFd::from_raw_fd(raw) });
        }
        header = unsafe { libc::CMSG_NXTHDR(&raw const message, header) };
    }
    if !valid_ancillary
        || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        || received as usize > bytes.len()
        || passed.len() != 1
    {
        return Err(REFUSED);
    }
    peer.revalidate()?;
    let handoff: BindHandoff =
        serde_json::from_slice(&bytes[..received as usize]).map_err(|_| REFUSED)?;
    Ok((handoff, passed.pop().ok_or(REFUSED)?))
}

/// Called only as PID 1's fixed, argument-free ExecStartPre command. The
/// guardian hands us the original held OFD, then this process execs the exact
/// installed guard helper without changing PID or the ControlPID cgroup.
pub(crate) fn run_bind(unit: &str) -> Result<(), &'static str> {
    let (request, boot, invocation) = request("aegis_auto_guardian_bind_v1", "BIND_BEGIN", unit)?;
    let deadline = Instant::now() + BIND_HANDOFF_DEADLINE;
    let peer = connect(deadline)?;
    ready(peer.socket.as_raw_fd(), libc::POLLOUT, deadline)?;
    let sent = unsafe {
        libc::send(
            peer.socket.as_raw_fd(),
            request.as_ptr().cast(),
            request.len(),
            libc::MSG_NOSIGNAL,
        )
    };
    if sent != request.len() as isize {
        return Err(REFUSED);
    }
    let (reply, held) = bind_handoff(&peer, deadline)?;
    if !reply.matches(&boot, &invocation, unit) {
        return Err(REFUSED);
    }
    trusted_guard_lock(&held)?;
    let helper = fs::symlink_metadata(GUARD_HELPER).map_err(|_| REFUSED)?;
    if !helper.file_type().is_file()
        || helper.uid() != 0
        || helper.nlink() != 1
        || helper.permissions().mode() & 0o022 != 0
    {
        return Err(REFUSED);
    }
    peer.revalidate()?;
    // Save both sources above the fixed exec slots before replacing either
    // one: the received guard and connected socket may themselves occupy 8/9.
    let socket_copy = unsafe { libc::fcntl(peer.socket.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
    if socket_copy < 0 {
        return Err(REFUSED);
    }
    let socket_copy = unsafe { OwnedFd::from_raw_fd(socket_copy) };
    let guard_copy = unsafe { libc::fcntl(held.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
    if guard_copy < 0 {
        return Err(REFUSED);
    }
    let guard_copy = unsafe { OwnedFd::from_raw_fd(guard_copy) };
    drop(held);
    drop(peer);
    if unsafe { libc::dup2(socket_copy.as_raw_fd(), INHERITED_BIND_SOCKET_FD) }
        != INHERITED_BIND_SOCKET_FD
    {
        return Err(REFUSED);
    }
    let bind_socket = unsafe { OwnedFd::from_raw_fd(INHERITED_BIND_SOCKET_FD) };
    if unsafe { libc::dup2(guard_copy.as_raw_fd(), INHERITED_GUARD_FD) } != INHERITED_GUARD_FD {
        return Err(REFUSED);
    }
    let bind_guard = unsafe { OwnedFd::from_raw_fd(INHERITED_GUARD_FD) };
    if unsafe { libc::fcntl(bind_socket.as_raw_fd(), libc::F_SETFD, 0) } != 0
        || unsafe { libc::fcntl(bind_guard.as_raw_fd(), libc::F_SETFD, 0) } != 0
    {
        return Err(REFUSED);
    }
    // CommandExt::exec performs execve in this ControlPID. No child is
    // created, so the helper's own PID 1 ControlPID and cgroup checks apply.
    let error = Command::new("/bin/bash")
        .arg(GUARD_HELPER)
        .arg("bind")
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C")
        .env("AEGIS_DEVICE_GUARD_STATE", GUARD_STATE)
        .env("AEGIS_AUTO_HELD_BIND_SOCKET_FD", "8")
        .env("AEGIS_AUTO_HELD_GUARD_FD", "9")
        .env("AEGIS_AUTO_PRIVATE_UNIT", unit)
        .env("INVOCATION_ID", invocation)
        .exec();
    let _ = error;
    Err(REFUSED)
}

#[cfg(test)]
mod host_bind_source_proof_tests {
    use super::*;

    #[test]
    fn v2_handoff_requires_exact_authenticated_host_source_proof() {
        let unit = format!("aegis-auto@{}.service", "a".repeat(64));
        let value = serde_json::json!({
            "schema":"aegis_auto_guardian_bind_handoff_v2",
            "boot_id":"12345678-1234-1234-1234-123456789abc",
            "invocation_id":"a".repeat(32), "unit":unit,
            "current_boot_source_verified":true
        });
        let valid: BindHandoff = serde_json::from_value(value.clone()).unwrap();
        assert!(valid.matches(
            "12345678-1234-1234-1234-123456789abc",
            &"a".repeat(32),
            &unit
        ));
        for (field, wrong) in [
            (
                "schema",
                serde_json::json!("aegis_auto_guardian_bind_handoff_v1"),
            ),
            ("current_boot_source_verified", serde_json::json!(false)),
            ("unit", serde_json::json!("aegis-auto@foreign.service")),
            ("invocation_id", serde_json::json!("b".repeat(32))),
            (
                "boot_id",
                serde_json::json!("00000000-1234-1234-1234-123456789abc"),
            ),
        ] {
            let mut changed = value.clone();
            changed[field] = wrong;
            let decoded: BindHandoff = serde_json::from_value(changed).unwrap();
            assert!(!decoded.matches(
                "12345678-1234-1234-1234-123456789abc",
                &"a".repeat(32),
                &unit
            ));
        }
        let mut missing = value;
        missing
            .as_object_mut()
            .unwrap()
            .remove("current_boot_source_verified");
        assert!(serde_json::from_value::<BindHandoff>(missing).is_err());
    }
}
