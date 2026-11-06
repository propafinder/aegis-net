//! Process-held private AUTO activation lease.
//!
//! PID 1 gives the main process one end of a SOCK_SEQPACKET pair as stdin.
//! The installed guardian holds the actor end after the worker transferred it.
//! Per-message kernel credentials and pidfd identify the actual sender;
//! SO_PEERCRED on this inherited pair would identify its creator instead.

#![cfg(target_os = "linux")]

use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    mem::{size_of, zeroed},
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const SO_PASSPIDFD: libc::c_int = 76;
const SCM_PIDFD: libc::c_int = 4;
const LIMIT: usize = 256;
const GUARDIAN: &str = "aegis-auto-guardian.service";
const GUARDIAN_SOCKET: &str = "/run/aegis-auto-guard/authority.sock";
const GUARDIAN_RUNTIME: &str = "/run/aegis-auto-guard";

fn refused() -> &'static str {
    "AUTO private launch lease refused"
}

fn hex(raw: &str, len: usize) -> bool {
    raw.len() == len
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn private_unit(unit: &str) -> bool {
    unit.strip_prefix("aegis-auto@")
        .and_then(|value| value.strip_suffix(".service"))
        .is_some_and(|value| hex(value, 64))
}

fn boot_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}

fn set_option(fd: RawFd, option: libc::c_int) -> Result<(), &'static str> {
    let enabled: libc::c_int = 1;
    if unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            (&raw const enabled).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    } == 0
    {
        Ok(())
    } else {
        Err(refused())
    }
}

fn socket_option(fd: RawFd, option: libc::c_int) -> Result<libc::c_int, &'static str> {
    let mut value: libc::c_int = 0;
    let mut length = size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            (&raw mut value).cast(),
            &raw mut length,
        )
    } == 0
        && length as usize == size_of::<libc::c_int>()
    {
        Ok(value)
    } else {
        Err(refused())
    }
}

fn pidfd_live(fd: RawFd) -> Result<(), &'static str> {
    let mut item = libc::pollfd {
        fd,
        events: libc::POLLIN | libc::POLLERR | libc::POLLHUP,
        revents: 0,
    };
    if unsafe { libc::poll(&raw mut item, 1, 0) } == 0 && item.revents == 0 {
        Ok(())
    } else {
        Err(refused())
    }
}

fn send(fd: RawFd, packet: &[u8]) -> Result<(), &'static str> {
    if packet.is_empty() || packet.len() >= 4096 {
        return Err(refused());
    }
    let sent = unsafe { libc::send(fd, packet.as_ptr().cast(), packet.len(), libc::MSG_NOSIGNAL) };
    if sent == packet.len() as isize {
        Ok(())
    } else {
        Err(refused())
    }
}

struct Packet {
    payload: Vec<u8>,
    sender: u32,
    pidfd: OwnedFd,
}

fn receive(fd: RawFd) -> Result<Packet, &'static str> {
    let mut payload = [0u8; LIMIT];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let control_len = unsafe {
        libc::CMSG_SPACE(size_of::<libc::ucred>() as u32)
            + libc::CMSG_SPACE(size_of::<RawFd>() as u32)
    } as usize;
    let mut control = vec![0usize; control_len.div_ceil(size_of::<usize>())];
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &raw mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control_len;
    let deadline = Instant::now() + Duration::from_secs(10);
    let count = loop {
        message.msg_controllen = control_len;
        message.msg_flags = 0;
        let count = unsafe { libc::recvmsg(fd, &raw mut message, libc::MSG_CMSG_CLOEXEC) };
        if count >= 0 {
            break count;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if error.kind() != std::io::ErrorKind::WouldBlock {
            return Err(refused());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(refused());
        }
        let mut wait = libc::pollfd {
            fd,
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        };
        let millis = remaining.as_millis().min(10_000) as libc::c_int;
        if unsafe { libc::poll(&raw mut wait, 1, millis) } <= 0
            || wait.revents & (libc::POLLHUP | libc::POLLERR) != 0
        {
            return Err(refused());
        }
    };
    let mut credential = None;
    let mut owned_fds = Vec::<OwnedFd>::new();
    let mut invalid_control = false;
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&raw const message);
        while !header.is_null() {
            if (*header).cmsg_level != libc::SOL_SOCKET {
                invalid_control = true;
            } else if (*header).cmsg_type == libc::SCM_CREDENTIALS
                && (*header).cmsg_len == libc::CMSG_LEN(size_of::<libc::ucred>() as u32) as usize
                && credential.is_none()
            {
                credential = Some(std::ptr::read_unaligned(
                    libc::CMSG_DATA(header).cast::<libc::ucred>(),
                ));
            } else if (*header).cmsg_type == SCM_PIDFD || (*header).cmsg_type == libc::SCM_RIGHTS {
                let minimum = libc::CMSG_LEN(0) as usize;
                if (*header).cmsg_len < minimum {
                    invalid_control = true;
                } else {
                    let bytes = (*header).cmsg_len - minimum;
                    if bytes == 0 || !bytes.is_multiple_of(size_of::<RawFd>()) {
                        invalid_control = true;
                    } else {
                        for index in 0..bytes / size_of::<RawFd>() {
                            let raw = std::ptr::read_unaligned(
                                libc::CMSG_DATA(header)
                                    .add(index * size_of::<RawFd>())
                                    .cast::<RawFd>(),
                            );
                            if raw < 0 {
                                invalid_control = true;
                            } else {
                                owned_fds.push(OwnedFd::from_raw_fd(raw));
                            }
                        }
                    }
                }
                if (*header).cmsg_type != SCM_PIDFD || bytes_ne_one((*header).cmsg_len) {
                    invalid_control = true;
                }
            } else {
                invalid_control = true;
            }
            header = libc::CMSG_NXTHDR(&raw const message, header);
        }
    }
    if count == 0
        || count as usize >= LIMIT
        || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        || invalid_control
        || owned_fds.len() != 1
    {
        return Err(refused());
    }
    let credential = credential.ok_or_else(refused)?;
    let pidfd = owned_fds.pop().ok_or_else(refused)?;
    if credential.pid <= 1 || credential.uid != 0 || credential.gid != 0 {
        return Err(refused());
    }
    pidfd_live(pidfd.as_raw_fd())?;
    let sender = u32::try_from(credential.pid).map_err(|_| refused())?;
    let fdinfo = fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()))
        .map_err(|_| refused())?;
    if !fdinfo.lines().any(|line| line == format!("Pid:\t{sender}")) {
        return Err(refused());
    }
    Ok(Packet {
        payload: payload[..count as usize].to_vec(),
        sender,
        pidfd,
    })
}

fn bytes_ne_one(cmsg_len: usize) -> bool {
    cmsg_len != unsafe { libc::CMSG_LEN(size_of::<RawFd>() as u32) } as usize
}

/// The private runtime's guardian read. It runs as the unit's own (possibly
/// unprivileged) user in the unit's mount namespace, so it keeps `systemctl
/// show`, which may ask PID1 through the system bus.
fn guardian_identity(pid: u32) -> Result<String, &'static str> {
    let output = Command::new("/usr/bin/timeout")
        .args([
            "-k",
            "1s",
            "2s",
            "/usr/bin/systemctl",
            "show",
            GUARDIAN,
            "-p",
            "MainPID",
            "-p",
            "ControlGroup",
            "-p",
            "InvocationID",
            "--no-pager",
        ])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin")
        .env("LANG", "C")
        .output()
        .map_err(|_| refused())?;
    if !output.status.success() || output.stdout.len() > 4096 || output.stderr.len() > 4096 {
        return Err(refused());
    }
    let raw = std::str::from_utf8(&output.stdout).map_err(|_| refused())?;
    let mut main = None;
    let mut cgroup = None;
    let mut invocation = None;
    for line in raw.lines() {
        let (key, value) = line.split_once('=').ok_or_else(refused)?;
        match key {
            "MainPID" if main.replace(value).is_none() => (),
            "ControlGroup" if cgroup.replace(value).is_none() => (),
            "InvocationID" if invocation.replace(value).is_none() => (),
            _ => return Err(refused()),
        }
    }
    guardian_identity_checked(pid, main, cgroup, invocation)
}

/// The root worker's guardian read (S8): PID1 reports MainPID, ControlGroup
/// and InvocationID over the verified direct connection instead of a spawned
/// `/usr/bin/timeout /usr/bin/systemctl show`. The comparisons are the same.
fn guardian_identity_root_worker(pid: u32) -> Result<String, &'static str> {
    let facts = crate::profile_auto_stopped_service::pid1::guardian_service_identity()
        .map_err(|_| refused())?;
    guardian_identity_checked(
        pid,
        Some(&facts.main_pid),
        Some(&facts.control_group),
        Some(&facts.invocation_id),
    )
}

fn guardian_identity_checked(
    pid: u32,
    main: Option<&str>,
    cgroup: Option<&str>,
    invocation: Option<&str>,
) -> Result<String, &'static str> {
    let expected = "/system.slice/aegis-auto-guardian.service";
    if main != Some(pid.to_string().as_str())
        || cgroup != Some(expected)
        || !invocation.is_some_and(|value| hex(value, 32))
        || fs::read_to_string(format!("/proc/{pid}/cgroup")).map_err(|_| refused())?
            != format!("0::{expected}\n")
    {
        return Err(refused());
    }
    Ok(invocation.ok_or_else(refused)?.to_owned())
}

fn nonce() -> Result<[u8; 32], &'static str> {
    let mut result = [0u8; 32];
    let mut source = fs::File::open("/dev/urandom").map_err(|_| refused())?;
    source.read_exact(&mut result).map_err(|_| refused())?;
    Ok(result)
}

fn encode(raw: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(raw.len() * 2);
    for byte in raw {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 15) as usize] as char);
    }
    result
}

fn decode32(raw: &str) -> Result<[u8; 32], &'static str> {
    if !hex(raw, 64) {
        return Err(refused());
    }
    let mut result = [0u8; 32];
    for (index, pair) in raw.as_bytes().chunks_exact(2).enumerate() {
        result[index] = u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| refused())?, 16)
            .map_err(|_| refused())?;
    }
    Ok(result)
}

fn decode16(raw: &str) -> Result<[u8; 16], &'static str> {
    if !hex(raw, 32) {
        return Err(refused());
    }
    let mut result = [0u8; 16];
    for (index, pair) in raw.as_bytes().chunks_exact(2).enumerate() {
        result[index] = u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| refused())?, 16)
            .map_err(|_| refused())?;
    }
    Ok(result)
}

/// Ownership of this FD is the process-held lease. Dropping it closes the
/// guardian channel; the guardian independently watches this PID and channel.
pub(crate) struct LaunchLease {
    channel: OwnedFd,
    guardian_pidfd: OwnedFd,
    guardian_pid: u32,
    guardian_invocation: String,
    monitor: Option<RuntimeMonitor>,
}

struct RuntimeMonitor {
    cancelled: Arc<AtomicBool>,
    stop: OwnedFd,
    worker: Option<JoinHandle<()>>,
}

impl RuntimeMonitor {
    fn start(lease: &LaunchLease) -> Result<Self, &'static str> {
        let channel = lease.channel.try_clone().map_err(|_| refused())?;
        let guardian_pidfd = lease.guardian_pidfd.try_clone().map_err(|_| refused())?;
        let raw = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if raw < 0 {
            return Err(refused());
        }
        let stop = unsafe { OwnedFd::from_raw_fd(raw) };
        let stop_watch = stop.try_clone().map_err(|_| refused())?;
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancelled_watch = Arc::clone(&cancelled);
        let pid = lease.guardian_pid;
        let invocation = lease.guardian_invocation.clone();
        let worker = thread::Builder::new()
            .name("aegis-auto-launch-watchdog".into())
            .spawn(move || {
                let mut last_identity = Instant::now();
                loop {
                    let mut checks = [
                        libc::pollfd {
                            fd: stop_watch.as_raw_fd(),
                            events: libc::POLLIN,
                            revents: 0,
                        },
                        libc::pollfd {
                            fd: guardian_pidfd.as_raw_fd(),
                            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                            revents: 0,
                        },
                        libc::pollfd {
                            fd: channel.as_raw_fd(),
                            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                            revents: 0,
                        },
                    ];
                    let ready = unsafe { libc::poll(checks.as_mut_ptr(), checks.len() as _, 250) };
                    if cancelled_watch.load(Ordering::Acquire) || checks[0].revents != 0 {
                        return;
                    }
                    if ready < 0
                        && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                    {
                        continue;
                    }
                    let lost = ready < 0
                        || checks[1].revents != 0
                        || checks[2].revents != 0
                        || (last_identity.elapsed() >= Duration::from_secs(1)
                            && guardian_identity(pid).map_or(true, |value| value != invocation));
                    if last_identity.elapsed() >= Duration::from_secs(1) {
                        last_identity = Instant::now();
                    }
                    if lost && !cancelled_watch.load(Ordering::Acquire) {
                        // This is the private service's own PID. On a lost
                        // guardian lease it must stop running immediately;
                        // the independent host watchdog retains deny.
                        unsafe {
                            libc::kill(libc::getpid(), libc::SIGTERM);
                        }
                        thread::sleep(Duration::from_millis(250));
                        unsafe { libc::_exit(1) };
                    }
                }
            })
            .map_err(|_| refused())?;
        Ok(Self {
            cancelled,
            stop,
            worker: Some(worker),
        })
    }

    fn stop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        let one = 1u64.to_ne_bytes();
        unsafe {
            libc::write(self.stop.as_raw_fd(), one.as_ptr().cast(), one.len());
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for LaunchLease {
    fn drop(&mut self) {
        if let Some(mut monitor) = self.monitor.take() {
            monitor.stop();
        }
    }
}

impl LaunchLease {
    pub(crate) fn revalidate(&self) -> Result<(), &'static str> {
        let mut item = libc::pollfd {
            fd: self.channel.as_raw_fd(),
            events: libc::POLLHUP | libc::POLLERR,
            revents: 0,
        };
        if unsafe { libc::poll(&raw mut item, 1, 0) } < 0 || item.revents != 0 {
            return Err(refused());
        }
        pidfd_live(self.guardian_pidfd.as_raw_fd())?;
        if guardian_identity(self.guardian_pid)? != self.guardian_invocation {
            return Err(refused());
        }
        Ok(())
    }
}

/// Called only on the private unit's main path before argument parsing.
/// Standard input must be the exact descriptor sent through PID 1.
pub(crate) fn acquire(unit: &str) -> Result<LaunchLease, &'static str> {
    if !private_unit(unit) {
        return Err("AUTO runtime launch private unit refused");
    }
    let cgroup = fs::read_to_string("/proc/self/cgroup")
        .map_err(|_| "AUTO runtime launch cgroup refused")?;
    if cgroup != format!("0::/system.slice/{unit}\n") {
        return Err("AUTO runtime launch cgroup refused");
    }
    let invocation =
        std::env::var("INVOCATION_ID").map_err(|_| "AUTO runtime launch invocation refused")?;
    if !hex(&invocation, 32) {
        return Err("AUTO runtime launch invocation refused");
    }
    let socket = unsafe { OwnedFd::from_raw_fd(libc::STDIN_FILENO) };
    if socket_option(socket.as_raw_fd(), libc::SO_TYPE)
        .map_err(|_| "AUTO runtime launch stdin type refused")?
        != libc::SOCK_SEQPACKET
        || socket_option(socket.as_raw_fd(), libc::SO_DOMAIN)
            .map_err(|_| "AUTO runtime launch stdin domain refused")?
            != libc::AF_UNIX
    {
        return Err("AUTO runtime launch stdin socket refused");
    }
    let flags = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_GETFD) };
    if flags < 0
        || unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
    {
        return Err("AUTO runtime launch stdin fd refused");
    }
    set_option(socket.as_raw_fd(), libc::SO_PASSCRED)
        .map_err(|_| "AUTO runtime launch passcred refused")?;
    set_option(socket.as_raw_fd(), SO_PASSPIDFD)
        .map_err(|_| "AUTO runtime launch passpidfd refused")?;
    let timeout = libc::timeval {
        tv_sec: 10,
        tv_usec: 0,
    };
    for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
        if unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                (&raw const timeout).cast(),
                size_of::<libc::timeval>() as libc::socklen_t,
            )
        } != 0
        {
            return Err("AUTO runtime launch socket timeout refused");
        }
    }
    let main_nonce = nonce().map_err(|_| "AUTO runtime launch nonce refused")?;
    send(
        socket.as_raw_fd(),
        format!("HELLO 1 {unit} {invocation} {}", encode(&main_nonce)).as_bytes(),
    )
    .map_err(|_| "AUTO runtime launch hello refused")?;
    let challenge =
        receive(socket.as_raw_fd()).map_err(|_| "AUTO runtime launch challenge refused")?;
    let guardian_invocation = guardian_identity(challenge.sender)
        .map_err(|_| "AUTO runtime launch guardian identity refused")?;
    let response = std::str::from_utf8(&challenge.payload)
        .map_err(|_| "AUTO runtime launch challenge response refused")?;
    let mut fields = response.split(' ');
    if fields.next() != Some("CHALLENGE") || fields.next() != Some("1") {
        return Err("AUTO runtime launch challenge response refused");
    }
    let challenge_nonce = decode32(
        fields
            .next()
            .ok_or("AUTO runtime launch challenge response refused")?,
    )
    .map_err(|_| "AUTO runtime launch challenge response refused")?;
    let ticket = decode32(
        fields
            .next()
            .ok_or("AUTO runtime launch challenge response refused")?,
    )
    .map_err(|_| "AUTO runtime launch challenge response refused")?;
    if fields.next().is_some() {
        return Err("AUTO runtime launch challenge response refused");
    }
    let mut h = Sha256::new();
    h.update(ticket);
    h.update(challenge_nonce);
    h.update(main_nonce);
    h.update(decode16(&invocation).map_err(|_| "AUTO runtime launch invocation refused")?);
    h.update(unit.as_bytes());
    let proof = encode(&h.finalize());
    send(socket.as_raw_fd(), format!("CONFIRM 1 {proof}").as_bytes())
        .map_err(|_| "AUTO runtime launch confirm refused")?;
    let lease =
        receive(socket.as_raw_fd()).map_err(|_| "AUTO runtime launch lease reply refused")?;
    if lease.sender != challenge.sender
        || guardian_identity(lease.sender)
            .map_err(|_| "AUTO runtime launch lease identity refused")?
            != guardian_invocation
        || lease.payload != format!("LEASE 1 {}", encode(&challenge_nonce)).as_bytes()
    {
        return Err("AUTO runtime launch lease identity refused");
    }
    pidfd_live(challenge.pidfd.as_raw_fd())
        .map_err(|_| "AUTO runtime launch lease identity refused")?;
    pidfd_live(lease.pidfd.as_raw_fd())
        .map_err(|_| "AUTO runtime launch lease identity refused")?;
    let result = LaunchLease {
        channel: socket,
        guardian_pidfd: challenge.pidfd,
        guardian_pid: challenge.sender,
        guardian_invocation,
        monitor: None,
    };
    result
        .revalidate()
        .map_err(|_| "AUTO runtime launch final revalidation refused")?;
    let mut result = result;
    result.monitor =
        Some(RuntimeMonitor::start(&result).map_err(|_| "AUTO runtime launch monitor refused")?);
    Ok(result)
}

/// Source-bound request assembled while the original owner holds Stage,
/// publication/mutation scopes and InstallLock. The private name itself is
/// minted by PID 1 preparation, never deserialized from a receipt.
pub(crate) struct LaunchBinding<'a> {
    pub(crate) private_unit: &'a crate::profile_auto_stopped_service::pid1::PrivateUnit,
    pub(crate) mode: &'a str,
    pub(crate) header_sha256: &'a str,
    pub(crate) transaction_nonce: &'a str,
    pub(crate) planned_generation: &'a str,
    pub(crate) boot_id: &'a str,
    pub(crate) netns_ino: u64,
}

fn fd_identity(fd: RawFd) -> Result<(u64, u64), &'static str> {
    let mut value = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, value.as_mut_ptr()) } != 0 {
        return Err(refused());
    }
    let value = unsafe { value.assume_init() };
    Ok((value.st_dev, value.st_ino))
}

fn guardian_connection() -> Result<(OwnedFd, OwnedFd, u32, String), &'static str> {
    let parent = fs::symlink_metadata(GUARDIAN_RUNTIME).map_err(|_| refused())?;
    let leaf = fs::symlink_metadata(GUARDIAN_SOCKET).map_err(|_| refused())?;
    if !parent.file_type().is_dir()
        || parent.uid() != 0
        || parent.permissions().mode() & 0o777 != 0o700
        || !leaf.file_type().is_socket()
        || leaf.uid() != 0
        || leaf.permissions().mode() & 0o777 != 0o600
    {
        return Err(refused());
    }
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(refused());
    }
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut address: libc::sockaddr_un = unsafe { zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = GUARDIAN_SOCKET.as_bytes();
    if bytes.len() + 1 > address.sun_path.len() {
        return Err(refused());
    }
    for (destination, source) in address.sun_path.iter_mut().zip(bytes) {
        *destination = *source as libc::c_char;
    }
    let length = (size_of::<libc::sa_family_t>() + bytes.len() + 1) as libc::socklen_t;
    if unsafe { libc::connect(socket.as_raw_fd(), (&raw const address).cast(), length) } != 0 {
        return Err(refused());
    }
    let timeout = libc::timeval {
        tv_sec: 10,
        tv_usec: 0,
    };
    for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
        if unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                (&raw const timeout).cast(),
                size_of::<libc::timeval>() as libc::socklen_t,
            )
        } != 0
        {
            return Err(refused());
        }
    }
    let mut credentials: libc::ucred = unsafe { zeroed() };
    let mut credential_length = size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut credentials).cast(),
            &raw mut credential_length,
        )
    } != 0
        || credential_length as usize != size_of::<libc::ucred>()
        || credentials.pid <= 1
        || credentials.uid != 0
        || credentials.gid != 0
    {
        return Err(refused());
    }
    let pid = u32::try_from(credentials.pid).map_err(|_| refused())?;
    const SO_PEERPIDFD: libc::c_int = 77;
    let mut pidfd_raw: RawFd = -1;
    let mut pidfd_length = size_of::<RawFd>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_PEERPIDFD,
            (&raw mut pidfd_raw).cast(),
            &raw mut pidfd_length,
        )
    } != 0
        || pidfd_length as usize != size_of::<RawFd>()
        || pidfd_raw < 0
    {
        return Err(refused());
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd_raw) };
    pidfd_live(pidfd.as_raw_fd())?;
    let fdinfo = fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()))
        .map_err(|_| refused())?;
    if !fdinfo.lines().any(|line| line == format!("Pid:\t{pid}")) {
        return Err(refused());
    }
    let invocation = guardian_identity_root_worker(pid)?;
    Ok((socket, pidfd, pid, invocation))
}

fn send_fds(fd: RawFd, payload: &[u8], fds: [RawFd; 3]) -> Result<(), &'static str> {
    if payload.is_empty() || payload.len() > 4096 {
        return Err(refused());
    }
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: payload.len(),
    };
    let size = unsafe { libc::CMSG_SPACE((3 * size_of::<RawFd>()) as u32) } as usize;
    let mut storage = vec![0usize; size.div_ceil(size_of::<usize>())];
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &raw mut iov;
    message.msg_iovlen = 1;
    message.msg_control = storage.as_mut_ptr().cast();
    message.msg_controllen = size;
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&raw const message);
        if header.is_null() {
            return Err(refused());
        }
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN((3 * size_of::<RawFd>()) as u32) as usize;
        std::ptr::copy_nonoverlapping(
            fds.as_ptr().cast::<u8>(),
            libc::CMSG_DATA(header),
            3 * size_of::<RawFd>(),
        );
    }
    if unsafe { libc::sendmsg(fd, &raw const message, libc::MSG_NOSIGNAL) }
        == payload.len() as isize
    {
        Ok(())
    } else {
        Err(refused())
    }
}

fn receive_reply(fd: RawFd) -> Result<Vec<u8>, &'static str> {
    let mut buffer = [0u8; 4096];
    let count = unsafe { libc::recv(fd, buffer.as_mut_ptr().cast(), buffer.len(), 0) };
    if count <= 0 || count as usize >= buffer.len() {
        return Err(refused());
    }
    Ok(buffer[..count as usize].to_vec())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registered {
    schema: String,
    actor_challenge: String,
    ticket_sha256: String,
    guardian_pid: u32,
    guardian_invocation_id: String,
    private_unit: String,
    stage_dev: u64,
    stage_ino: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Held {
    schema: String,
    actor_challenge: String,
    ticket_sha256: String,
    guardian_pid: u32,
    guardian_invocation_id: String,
    private_unit: String,
    pid: u32,
    start_tick: u64,
    invocation: String,
    cgroup: String,
    lease_alive: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalHeld {
    schema: String,
    actor_challenge: String,
    ticket_sha256: String,
    guardian_pid: u32,
    guardian_invocation_id: String,
    private_unit: String,
    stage_dev: u64,
    stage_ino: u64,
    terminal_sha256: String,
    pid: u32,
    start_tick: u64,
    invocation: String,
    cgroup: String,
    lease_alive: bool,
}

/// A registered, nonserializable guardian channel. The ticket is minted by
/// the installed actor; this owner receives its commitment only.
pub(crate) struct LaunchOwnerLease {
    socket: OwnedFd,
    guardian_pidfd: OwnedFd,
    guardian_pid: u32,
    guardian_invocation: String,
    actor_challenge: String,
    ticket_sha256: String,
    private_unit: String,
    stage_identity: (u64, u64),
    boot_id: String,
}

impl LaunchOwnerLease {
    pub(crate) fn register(
        binding: &LaunchBinding<'_>,
        stage_fd: RawFd,
        install_fd: RawFd,
        actor_fd: OwnedFd,
    ) -> Result<Self, &'static str> {
        let unit = binding.private_unit.name();
        if !private_unit(unit)
            || !matches!(
                binding.mode,
                "socks-only" | "wide-redirect-safe" | "full-wide-tun"
            )
            || !hex(binding.header_sha256, 64)
            || !hex(binding.transaction_nonce, 32)
            || !hex(binding.planned_generation, 64)
            || !boot_uuid(binding.boot_id)
            || binding.netns_ino == 0
        {
            return Err(refused());
        }
        let actual_boot =
            fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|_| refused())?;
        if actual_boot.trim() != binding.boot_id {
            return Err(refused());
        }
        let stage_identity = fd_identity(stage_fd)?;
        fd_identity(install_fd)?;
        let (socket, guardian_pidfd, guardian_pid, guardian_invocation) = guardian_connection()?;
        let actor_challenge = encode(&nonce()?);
        let request = json!({
            "schema": "aegis_auto_guardian_launch_register_v1",
            "command": "REGISTER_LAUNCH",
            "private_unit": unit,
            "mode": binding.mode,
            "header_sha256": binding.header_sha256,
            "transaction_nonce": binding.transaction_nonce,
            "planned_generation": binding.planned_generation,
            "boot_id": binding.boot_id,
            "netns_ino": binding.netns_ino,
            "actor_challenge": actor_challenge,
        });
        let payload = serde_json::to_vec(&request).map_err(|_| refused())?;
        send_fds(
            socket.as_raw_fd(),
            &payload,
            [stage_fd, install_fd, actor_fd.as_raw_fd()],
        )?;
        drop(actor_fd); // Guardian received its own duplicate before reply.
        let registered: Registered =
            serde_json::from_slice(&receive_reply(socket.as_raw_fd())?).map_err(|_| refused())?;
        if registered.schema != "aegis_auto_guardian_launch_registered_v1"
            || registered.actor_challenge != actor_challenge
            || registered.guardian_pid != guardian_pid
            || registered.guardian_invocation_id != guardian_invocation
            || registered.private_unit != unit
            || (registered.stage_dev, registered.stage_ino) != stage_identity
            || !hex(&registered.ticket_sha256, 64)
        {
            return Err(refused());
        }
        pidfd_live(guardian_pidfd.as_raw_fd())?;
        Ok(Self {
            socket,
            guardian_pidfd,
            guardian_pid,
            guardian_invocation,
            actor_challenge,
            ticket_sha256: registered.ticket_sha256,
            private_unit: unit.to_owned(),
            stage_identity,
            boot_id: binding.boot_id.to_owned(),
        })
    }

    pub(crate) fn ticket_sha256(&self) -> &str {
        &self.ticket_sha256
    }
    pub(crate) fn guardian_pid(&self) -> u32 {
        self.guardian_pid
    }
    pub(crate) fn guardian_invocation(&self) -> &str {
        &self.guardian_invocation
    }
    pub(crate) fn stage_identity(&self) -> (u64, u64) {
        self.stage_identity
    }
    pub(crate) fn unit(&self) -> &str {
        &self.private_unit
    }
    pub(crate) fn boot_id(&self) -> &str {
        &self.boot_id
    }
    pub(crate) fn revalidate(&self) -> Result<(), &'static str> {
        pidfd_live(self.guardian_pidfd.as_raw_fd())?;
        if guardian_identity_root_worker(self.guardian_pid)? != self.guardian_invocation {
            return Err(refused());
        }
        Ok(())
    }

    fn probe(&self, command: &str) -> Result<Held, &'static str> {
        self.revalidate()?;
        let request = json!({
            "schema": "aegis_auto_guardian_launch_probe_v1",
            "command": command,
            "actor_challenge": self.actor_challenge,
            "ticket_sha256": self.ticket_sha256,
            "private_unit": self.private_unit,
        });
        let payload = serde_json::to_vec(&request).map_err(|_| refused())?;
        send(self.socket.as_raw_fd(), &payload)?;
        let held: Held = serde_json::from_slice(&receive_reply(self.socket.as_raw_fd())?)
            .map_err(|_| refused())?;
        if held.schema != "aegis_auto_guardian_launch_held_v1"
            || held.actor_challenge != self.actor_challenge
            || held.ticket_sha256 != self.ticket_sha256
            || held.guardian_pid != self.guardian_pid
            || held.guardian_invocation_id != self.guardian_invocation
            || held.private_unit != self.private_unit
            || held.pid <= 1
            || held.start_tick == 0
            || !hex(&held.invocation, 32)
            || held.cgroup != format!("/system.slice/{}", self.private_unit)
            || !held.lease_alive
        {
            return Err(refused());
        }
        self.revalidate()?;
        Ok(held)
    }

    pub(crate) fn prove(
        self,
        completed: &crate::profile_auto_stopped_service::pid1::CompletedStart,
    ) -> Result<LaunchProof, &'static str> {
        let held = self.probe("LAUNCH_PROOF")?;
        let (job, invocation) = completed.facts();
        if job.unit() != self.private_unit || invocation != held.invocation {
            return Err(refused());
        }
        let proof = LaunchProof {
            lease: self,
            pid: held.pid,
            start_tick: held.start_tick,
            invocation: held.invocation,
            cgroup: held.cgroup,
            terminal_finished: false,
        };
        proof.revalidate()?;
        Ok(proof)
    }
}

/// A positive activation proof retaining the authenticated guardian channel
/// and PIDFD. No JSON record can construct this type.
pub(crate) struct LaunchProof {
    lease: LaunchOwnerLease,
    pid: u32,
    start_tick: u64,
    invocation: String,
    cgroup: String,
    terminal_finished: bool,
}

impl LaunchProof {
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }
    pub(crate) fn start_tick(&self) -> u64 {
        self.start_tick
    }
    pub(crate) fn invocation(&self) -> &str {
        &self.invocation
    }
    pub(crate) fn unit(&self) -> &str {
        self.lease.unit()
    }
    pub(crate) fn ticket_sha256(&self) -> &str {
        self.lease.ticket_sha256()
    }
    pub(crate) fn guardian_pid(&self) -> u32 {
        self.lease.guardian_pid()
    }
    pub(crate) fn guardian_invocation(&self) -> &str {
        self.lease.guardian_invocation()
    }
    pub(crate) fn stage_identity(&self) -> (u64, u64) {
        self.lease.stage_identity()
    }
    pub(crate) fn boot_id(&self) -> &str {
        self.lease.boot_id()
    }
    pub(crate) fn revalidate(&self) -> Result<(), &'static str> {
        if self.terminal_finished {
            return Err(refused());
        }
        let held = self.lease.probe("LAUNCH_REVALIDATE")?;
        if held.pid != self.pid
            || held.start_tick != self.start_tick
            || held.invocation != self.invocation
            || held.cgroup != self.cgroup
        {
            return Err(refused());
        }
        Ok(())
    }

    /// A successful terminal is handed to the installed actor before the
    /// worker returns. Its ACK means the actor closed its Stage/InstallLock
    /// duplicates while retaining the authenticated running Main lease.
    pub(crate) fn finish_terminal(&mut self, terminal_sha256: &str) -> Result<(), &'static str> {
        if self.terminal_finished || !hex(terminal_sha256, 64) {
            return Err(refused());
        }
        // The owner has already retired the v3 markers. Ordinary launch
        // revalidation requires those markers, while LAUNCH_TERMINAL checks
        // the sealed terminal, handoff, exact Main and retained PID 1 facts.
        self.lease.revalidate()?;
        let request = json!({
            "schema": "aegis_auto_guardian_launch_probe_v1",
            "command": "LAUNCH_TERMINAL",
            "actor_challenge": self.lease.actor_challenge,
            "ticket_sha256": self.lease.ticket_sha256,
            "private_unit": self.lease.private_unit,
            "terminal_sha256": terminal_sha256,
        });
        let payload = serde_json::to_vec(&request).map_err(|_| refused())?;
        send(self.lease.socket.as_raw_fd(), &payload)?;
        let held: TerminalHeld =
            serde_json::from_slice(&receive_reply(self.lease.socket.as_raw_fd())?)
                .map_err(|_| refused())?;
        if held.schema != "aegis_auto_guardian_launch_terminal_held_v1"
            || held.actor_challenge != self.lease.actor_challenge
            || held.ticket_sha256 != self.lease.ticket_sha256
            || held.guardian_pid != self.lease.guardian_pid
            || held.guardian_invocation_id != self.lease.guardian_invocation
            || held.private_unit != self.lease.private_unit
            || (held.stage_dev, held.stage_ino) != self.lease.stage_identity
            || held.terminal_sha256 != terminal_sha256
            || held.pid != self.pid
            || held.start_tick != self.start_tick
            || held.invocation != self.invocation
            || held.cgroup != self.cgroup
            || !held.lease_alive
        {
            return Err(refused());
        }
        self.lease.revalidate()?;
        self.terminal_finished = true;
        Ok(())
    }
}

#[cfg(test)]
mod guardian_identity_tests {
    use super::guardian_identity_checked;

    const CGROUP: &str = "/system.slice/aegis-auto-guardian.service";
    const INVOCATION: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn root_worker_and_systemctl_reads_share_every_comparison() {
        let pid = std::process::id();
        let text = pid.to_string();
        // Both sources feed the same checks; any missing or foreign value
        // refuses before /proc is read.
        for (main, cgroup, invocation) in [
            (None, Some(CGROUP), Some(INVOCATION)),
            (Some("1"), Some(CGROUP), Some(INVOCATION)),
            (Some(text.as_str()), None, Some(INVOCATION)),
            (
                Some(text.as_str()),
                Some("/system.slice/other.service"),
                Some(INVOCATION),
            ),
            (Some(text.as_str()), Some(CGROUP), None),
            (Some(text.as_str()), Some(CGROUP), Some("")),
            (Some(text.as_str()), Some(CGROUP), Some(&INVOCATION[1..])),
            (
                Some(text.as_str()),
                Some(CGROUP),
                Some("0123456789abcdef0123456789abcdeg"),
            ),
        ] {
            assert!(guardian_identity_checked(pid, main, cgroup, invocation).is_err());
        }
        // Matching PID1 facts still need the kernel cgroup of that exact PID:
        // this test process is not in the guardian's cgroup.
        assert!(
            guardian_identity_checked(pid, Some(&text), Some(CGROUP), Some(INVOCATION)).is_err()
        );
    }
}
