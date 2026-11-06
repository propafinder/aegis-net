//! Bounded descriptor transfer for the controlled macOS laboratory.
//! Kernel credentials bind peers; this does not install or authorize a helper.
use std::{
    io, mem,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::net::UnixStream,
    },
};

const MAX_RECEIVED_FDS: usize = 64;
// One-shot lab receive only: never allocate beyond this independent hard cap.
const MAX_CONTROL_BYTES: usize = 32 * 1024 * 1024;
const MAX_IFNAME: usize = 15;
const HEADER: &[u8; 5] = b"AEFD\x01";

#[repr(C)]
struct Control {
    alignment: [libc::cmsghdr; 0],
    bytes: [u8; 512],
}

impl Control {
    fn new() -> Self {
        Self {
            alignment: [],
            bytes: [0; 512],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PeerIdentity {
    pub(super) uid: libc::uid_t,
    pub(super) pid: libc::pid_t,
}

pub(super) fn peer_identity(stream: &UnixStream) -> io::Result<PeerIdentity> {
    let mut uid = 0;
    let mut gid = 0;
    // SAFETY: the owned connected socket and both output objects are live;
    // getpeereid reports kernel connection credentials without transferring FD.
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut pid: libc::pid_t = 0;
    let mut length = mem::size_of_val(&pid) as libc::socklen_t;
    // SAFETY: pid is writable for the supplied length and remains live. The
    // socket option reads kernel peer PID, not a process-supplied claim.
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut length,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if length as usize != mem::size_of_val(&pid) || pid <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing kernel peer PID",
        ));
    }
    Ok(PeerIdentity { uid, pid })
}

pub(super) fn verify_peer(
    stream: &UnixStream,
    expected_uid: libc::uid_t,
    expected_pid: Option<libc::pid_t>,
) -> io::Result<()> {
    let peer = peer_identity(stream)?;
    if peer.uid != expected_uid || expected_pid.is_some_and(|pid| pid <= 0 || pid != peer.pid) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "kernel IPC peer identity does not match the expected process",
        ));
    }
    Ok(())
}

pub(super) fn send_fd_to_peer(
    stream: &UnixStream,
    fd: RawFd,
    name: &[u8],
    expected: PeerIdentity,
) -> io::Result<()> {
    verify_peer(stream, expected.uid, Some(expected.pid))?;
    send_fd(stream, fd, name)
}

pub(super) fn recv_fd_from_peer(
    stream: &UnixStream,
    expected_uid: libc::uid_t,
) -> io::Result<(OwnedFd, String)> {
    verify_peer(stream, expected_uid, None)?;
    recv_fd(stream)
}

fn valid_name(name: &[u8]) -> bool {
    name.len() <= MAX_IFNAME
        && name
            .strip_prefix(b"utun")
            .is_some_and(|suffix| !suffix.is_empty() && suffix.iter().all(u8::is_ascii_digit))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn send_fd(stream: &UnixStream, fd: RawFd, name: &[u8]) -> io::Result<()> {
    if !valid_name(name) {
        return Err(invalid("invalid utun interface name"));
    }
    let mut data = [0; 6 + MAX_IFNAME];
    data[..5].copy_from_slice(HEADER);
    data[5] = name.len() as u8;
    data[6..6 + name.len()].copy_from_slice(name);
    let length = 6 + name.len();
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: length,
    };
    let mut control = Control::new();
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.bytes.as_mut_ptr().cast();
    message.msg_controllen = unsafe { libc::CMSG_SPACE(mem::size_of::<RawFd>() as u32) } as _;
    // SAFETY: Control supplies cmsghdr alignment and enough storage for one
    // header and RawFd. sendmsg only borrows the original descriptor.
    let written = unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(mem::size_of::<RawFd>() as u32) as _;
        libc::CMSG_DATA(header).cast::<RawFd>().write(fd);
        libc::sendmsg(stream.as_raw_fd(), &message, libc::MSG_NOSIGNAL)
    };
    if written < 0 {
        return Err(io::Error::last_os_error());
    }
    if written as usize != length {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short descriptor metadata transfer",
        ));
    }
    Ok(())
}

fn receive_capacity_for_limit(soft_limit: libc::rlim_t) -> io::Result<usize> {
    if soft_limit == 0 || soft_limit == libc::RLIM_INFINITY {
        return Err(invalid("finite descriptor process limit is required"));
    }
    let count = usize::try_from(soft_limit)
        .map_err(|_| invalid("descriptor process limit is unsupported"))?;
    // Bound every descriptor the kernel can install, even when each arrives in
    // its own rights header. Include one additional control framing header.
    let per_fd = unsafe { libc::CMSG_SPACE(mem::size_of::<RawFd>() as u32) } as usize;
    let framing = unsafe { libc::CMSG_SPACE(0) } as usize;
    let capacity = count
        .checked_mul(per_fd)
        .and_then(|bytes| bytes.checked_add(framing))
        .ok_or_else(|| invalid("descriptor control capacity overflow"))?;
    let aligned = capacity
        .checked_add(mem::size_of::<libc::cmsghdr>() - 1)
        .map(|bytes| bytes / mem::size_of::<libc::cmsghdr>())
        .and_then(|headers| headers.checked_mul(mem::size_of::<libc::cmsghdr>()))
        .ok_or_else(|| invalid("aligned descriptor control capacity overflow"))?;
    if aligned > MAX_CONTROL_BYTES {
        return Err(invalid(
            "descriptor process limit exceeds the bounded IPC receive capacity",
        ));
    }
    Ok(capacity)
}

fn recv_fd(stream: &UnixStream) -> io::Result<(OwnedFd, String)> {
    let mut limit: libc::rlimit = unsafe { mem::zeroed() };
    // SAFETY: getrlimit only writes the live output object. No process limit is
    // changed; unsupported capacity is refused before receiving descriptors.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } < 0 {
        return Err(io::Error::last_os_error());
    }
    recv_fd_for_limit(stream, limit.rlim_cur)
}

fn recv_fd_for_limit(
    stream: &UnixStream,
    soft_limit: libc::rlim_t,
) -> io::Result<(OwnedFd, String)> {
    let capacity = receive_capacity_for_limit(soft_limit)?;
    let units = capacity.div_ceil(mem::size_of::<libc::cmsghdr>());
    let mut control = Vec::<libc::cmsghdr>::new();
    control
        .try_reserve_exact(units)
        .map_err(|_| invalid("bounded IPC control allocation failed"))?;
    control.resize(units, unsafe { mem::zeroed() });
    let mut data = [0; 64];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = capacity as _;
    // SAFETY: the owned socket, iovec, and aligned control region remain live;
    // both receive lengths are bounded by their backing storage.
    let count = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, 0) };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    let returned = message.msg_controllen as usize;
    let mut refused =
        returned > capacity || message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0;
    // SAFETY: initialized cmsghdr elements supply native alignment and backing
    // storage for at least capacity bytes. The kernel writes only this region.
    let control = unsafe {
        std::slice::from_raw_parts(control.as_ptr().cast::<u8>(), returned.min(capacity))
    };
    let header_length = unsafe { libc::CMSG_LEN(0) } as usize;
    let mut received = Vec::<OwnedFd>::new();
    let mut offset = 0;
    let mut rights_messages = 0;
    while offset < control.len() {
        let remaining = &control[offset..];
        if remaining.len() < mem::size_of::<libc::cmsghdr>() {
            return Err(invalid("short ancillary header"));
        }
        // SAFETY: the complete header is present; unaligned read also makes
        // the boundary validation independent of each record's padding.
        let header = unsafe { remaining.as_ptr().cast::<libc::cmsghdr>().read_unaligned() };
        let length = header.cmsg_len as usize;
        if length < header_length || remaining.len() < header_length {
            return Err(invalid("invalid ancillary length"));
        }
        let truncated = length > remaining.len();
        let payload = &remaining[header_length..length.min(remaining.len())];
        if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == libc::SCM_RIGHTS {
            rights_messages += 1;
            if payload.is_empty() || payload.len() % mem::size_of::<RawFd>() != 0 {
                refused = true;
            }
            for bytes in payload.chunks_exact(mem::size_of::<RawFd>()) {
                let raw = RawFd::from_ne_bytes(bytes.try_into().unwrap());
                if raw < 0 || received.iter().any(|fd| fd.as_raw_fd() == raw) {
                    refused = true;
                    continue;
                }
                // SAFETY: this trusted kernel SCM_RIGHTS record installed a
                // fresh descriptor for this receive; immediately take sole
                // ownership before validating metadata or any fallible work.
                let fd = unsafe { OwnedFd::from_raw_fd(raw) };
                if received.len() < MAX_RECEIVED_FDS {
                    received.push(fd);
                } else {
                    // Extra kernel-installed rights are closed immediately;
                    // retained ownership metadata has an independent quota.
                    refused = true;
                    drop(fd);
                }
            }
        } else {
            refused = true;
        }
        if truncated {
            // Darwin can preserve the original cmsg_len on MSG_CTRUNC while
            // installing descriptors in the bounded available prefix. Own all
            // complete rights above before refusing the truncated record.
            refused = true;
            break;
        }
        let step = unsafe { libc::CMSG_SPACE(payload.len() as u32) } as usize;
        if step < length {
            return Err(invalid("invalid ancillary alignment"));
        }
        offset += step;
    }
    if refused || rights_messages != 1 || received.len() != 1 {
        return Err(invalid(
            "descriptor transfer must contain exactly one complete SCM_RIGHTS descriptor",
        ));
    }
    // All received descriptors are already owned; any error below closes them.
    let fd = received.pop().unwrap();
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    if flags < 0
        || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let data = data
        .get(..count as usize)
        .ok_or_else(|| invalid("descriptor metadata exceeds receive storage"))?;
    if data.len() < 6 || &data[..5] != HEADER || data.len() != 6 + usize::from(data[5]) {
        return Err(invalid("short or unsupported descriptor metadata frame"));
    }
    let name = &data[6..];
    if !valid_name(name) {
        return Err(invalid("invalid utun interface name"));
    }
    Ok((
        fd,
        String::from_utf8(name.to_vec()).map_err(|_| invalid("invalid interface encoding"))?,
    ))
}

#[cfg(test)]
#[path = "fd_ipc_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "fd_ipc_peer_tests.rs"]
mod peer_tests;
