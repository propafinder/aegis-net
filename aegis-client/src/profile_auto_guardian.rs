//! B-02 installed native deny guardian lease.  A digest is evidence, never a
//! capability: the socket, peer PIDFD and the original held descriptors remain
//! live through the authorized effect.  The installed guardian itself must
//! prove the native packet and independent sink before it sends a grant.

#![cfg(target_os = "linux")]

use std::fs;
use std::io::{self, Read};
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};

use serde::Deserialize;

const SOCKET: &str = "/run/aegis-auto-guard/authority.sock";
const RUNTIME: &str = "/run/aegis-auto-guard";
const MAX_REPLY: usize = 4096;
const GUARD_LOCK: &str = "/var/lib/aegis-install/client/device-guard.conf.lock";
const SPLIT: &str = "/var/lib/aegis-install/client/device-guard.conf.auto-lease-split";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GuardianRefusal {
    Unavailable,
    Untrusted,
    Stale,
    CaptureFailed {
        reason: &'static str,
        source: &'static str,
        line: u32,
    },
}

impl GuardianRefusal {
    pub(crate) fn capture_coordinate(self) -> Option<(&'static str, &'static str, u32)> {
        match self {
            Self::CaptureFailed {
                reason,
                source,
                line,
            } => Some((reason, source, line)),
            _ => None,
        }
    }
}

pub(crate) type Result<T> = std::result::Result<T, GuardianRefusal>;

pub(crate) struct GuardianBinding {
    pub(crate) mode: String,
    pub(crate) private_unit: String,
    pub(crate) header_sha256: String,
    pub(crate) transaction_nonce: String,
    pub(crate) planned_generation: String,
    pub(crate) boot_id: String,
    pub(crate) netns_ino: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    schema: String,
    nonce: String,
    actor_challenge: String,
    native_receipt_sha256: String,
    pid: u32,
    boot_id: String,
    netns_ino: u64,
    stage_dev: u64,
    stage_ino: u64,
    policy_sha256: String,
    private_unit: String,
    guardian_invocation_id: String,
    guardian_cgroup: String,
    guardian_source_sha256: String,
    guard_drop_handle: u64,
    guard_output_drop_delta: u64,
    trace_id: String,
    trace_sha256: String,
    sink_pid: u32,
    sink_netns_ino: u64,
    sink_session: String,
    sink_received: u64,
    baseline_sha256: String,
    baseline_method: String,
    topology_inverse_proven: bool,
    ipv6_trace_sha256: String,
    ipv6_sink_received: u64,
    ipv6_guard_drop_delta: u64,
    foreign_policy_class: String,
    foreign_policy_backend: String,
    foreign_projection_sha256: String,
}

impl Grant {
    fn dual_stack_native_policy_proven(&self) -> bool {
        hex(&self.ipv6_trace_sha256, 64)
            && self.ipv6_sink_received == 0
            && self.ipv6_guard_drop_delta > 0
            && self.foreign_policy_class == "filter_only"
            && self.foreign_policy_backend == "nf_tables"
            && hex(&self.foreign_projection_sha256, 64)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureReply {
    schema: String,
    guardian_nonce: String,
    mode: String,
    boot_id: String,
    netns_ino: u64,
    stage_dev: u64,
    stage_ino: u64,
    policy_sha256: String,
    native_receipt_sha256: String,
    pid1_job_id: u32,
    pid1_job_path: String,
    pid1_unit: String,
    pid1_invocation_id: String,
    native_capture_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureRefusalReply {
    schema: String,
    guardian_nonce: String,
    mode: String,
    boot_id: String,
    netns_ino: u64,
    stage_dev: u64,
    stage_ino: u64,
    policy_sha256: String,
    native_receipt_sha256: String,
    command: String,
    pid1_job_id: u32,
    pid1_job_path: String,
    pid1_unit: String,
    pid1_invocation_id: String,
    reason: String,
    source: String,
    line: u32,
}

struct CaptureExpected<'a> {
    command: &'a str,
    guardian_nonce: &'a str,
    mode: &'a str,
    boot_id: &'a str,
    netns_ino: u64,
    stage_identity: (u64, u64),
    policy_sha256: &'a str,
    native_receipt_sha256: &'a str,
    pid1_job_id: u32,
    pid1_job_path: &'a str,
    pid1_unit: &'a str,
    private_unit: &'a str,
    pid1_invocation_id: &'a str,
}

impl CaptureRefusalReply {
    fn coordinate(&self) -> Option<(&'static str, &'static str, u32)> {
        let reason = match self.reason.as_str() {
            "refused" => "refused",
            "timeout" => "timeout",
            "os_error" => "os_error",
            "value_error" => "value_error",
            "subprocess_error" => "subprocess_error",
            "runtime_error" => "runtime_error",
            "unexpected_exception" => "unexpected_exception",
            _ => return None,
        };
        let source = match self.source.as_str() {
            "unknown" => "unknown",
            "guardian" => "guardian",
            "witness" => "witness",
            "topology" => "topology",
            "rollback" => "rollback",
            "policy" => "policy",
            "endpoint" => "endpoint",
            "capture" => "capture",
            "capture_topology" => "capture_topology",
            _ => return None,
        };
        if !((source == "unknown" && self.line == 0)
            || (source != "unknown" && (1..=10_000).contains(&self.line)))
        {
            return None;
        }
        Some((reason, source, self.line))
    }

    fn matches(&self, expected: &CaptureExpected<'_>) -> bool {
        self.schema == "aegis_auto_capture_refused_v1"
            && self.command == expected.command
            && self.guardian_nonce == expected.guardian_nonce
            && self.mode == expected.mode
            && self.boot_id == expected.boot_id
            && self.netns_ino == expected.netns_ino
            && (self.stage_dev, self.stage_ino) == expected.stage_identity
            && self.policy_sha256 == expected.policy_sha256
            && self.native_receipt_sha256 == expected.native_receipt_sha256
            && self.pid1_job_id == expected.pid1_job_id
            && self.pid1_job_path == expected.pid1_job_path
            && self.pid1_unit == expected.pid1_unit
            && self.pid1_unit == expected.private_unit
            && self.pid1_invocation_id == expected.pid1_invocation_id
            && self.coordinate().is_some()
    }
}

/// Minted only from a retained PID1 OwnedStart, held guardian connection and
/// source-backed native capture reply. A serialized receipt cannot create it.
pub(crate) struct CaptureReady {
    guardian_nonce: String,
    mode: String,
    boot_id: String,
    netns_ino: u64,
    stage_identity: (u64, u64),
    policy_sha256: String,
    native_receipt_sha256: String,
    pid1_job_id: u32,
    pid1_job_path: String,
    pid1_unit: String,
    pid1_invocation_id: String,
    native_capture_sha256: String,
}

fn retain_ready_before_postcheck<F>(
    retained: &mut Option<CaptureReady>,
    ready: CaptureReady,
    postcheck: F,
) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    if retained.is_some() {
        return Err(GuardianRefusal::Untrusted);
    }
    // This authenticated hash is retained for an exact inverse even if a
    // later live check fails. It is not an activation or Header success.
    *retained = Some(ready);
    postcheck()
}

fn compensation_capture_reference(ready: Option<&CaptureReady>) -> serde_json::Value {
    ready
        .map(|value| serde_json::Value::String(value.native_capture_sha256.clone()))
        .unwrap_or(serde_json::Value::Null)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InverseReply {
    schema: String,
    guardian_nonce: String,
    mode: String,
    boot_id: String,
    netns_ino: u64,
    stage_dev: u64,
    stage_ino: u64,
    prior_invocation_id: String,
    stop_job_id: u32,
    stop_job_path: String,
    stop_unit: String,
    post_deny_policy_sha256: String,
    native_inverse_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FreshStopInverseReply {
    schema: String,
    actor_challenge: String,
    guardian_nonce: String,
    mode: String,
    boot_id: String,
    netns_ino: u64,
    stage_dev: u64,
    stage_ino: u64,
    unit: String,
    prior_invocation_id: String,
    stop_job_id: u32,
    stop_job_path: String,
    post_deny_policy_sha256: String,
    native_inverse_sha256: String,
}

/// One completed native compensation. It cannot be constructed from PID1
/// scalars or a saved JSON record outside this module.
pub(crate) struct CompletedCaptureInverse {
    prior_invocation_id: String,
    stop_job_id: u32,
    stop_job_path: String,
    stop_unit: String,
    boot_id: String,
    netns_ino: u64,
    stage_identity: (u64, u64),
    guardian_nonce: String,
    post_deny_policy_sha256: String,
    native_inverse_sha256: String,
    hold: Option<InverseHold>,
}

struct InverseHold {
    socket: OwnedFd,
    peer_pidfd: OwnedFd,
    stage: OwnedFd,
    install_lock: OwnedFd,
    guard_lock: OwnedFd,
    stage_identity: (u64, u64),
    install_identity: (u64, u64),
    guard_identity: (u64, u64),
    guardian_pid: u32,
    completed: bool,
}

/// Cannot be cloned, serialized, or recreated from a receipt.  The caller's
/// borrowed FDs must outlive the transaction and remain in their original
/// Store/InstallLock/guard ownership scopes.
pub(crate) struct GuardDenyLease {
    socket: OwnedFd,
    peer_pidfd: OwnedFd,
    stage: OwnedFd,
    install_lock: OwnedFd,
    guard_lock: OwnedFd,
    stage_identity: (u64, u64),
    install_identity: (u64, u64),
    guard_identity: (u64, u64),
    grant: Grant,
    mode: String,
    private_unit: String,
    prepared: bool,
    awaiting_handoff: bool,
    completed: bool,
}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn fd_identity(fd: RawFd) -> Result<(u64, u64)> {
    let mut value = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, value.as_mut_ptr()) } != 0 {
        return Err(GuardianRefusal::Stale);
    }
    let value = unsafe { value.assume_init() };
    Ok((value.st_dev, value.st_ino))
}

fn owned_socket_path() -> Result<()> {
    let runtime = fs::symlink_metadata(RUNTIME).map_err(|_| GuardianRefusal::Unavailable)?;
    let socket = fs::symlink_metadata(SOCKET).map_err(|_| GuardianRefusal::Unavailable)?;
    if !runtime.file_type().is_dir()
        || runtime.uid() != 0
        || runtime.mode() & 0o777 != 0o700
        || !socket.file_type().is_socket()
        || socket.uid() != 0
        || socket.mode() & 0o777 != 0o600
    {
        return Err(GuardianRefusal::Untrusted);
    }
    Ok(())
}

fn connect_seqpacket() -> Result<OwnedFd> {
    owned_socket_path()?;
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(GuardianRefusal::Unavailable);
    }
    // SAFETY: a successful socket() returns an owned, fresh descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut address: libc::sockaddr_un = unsafe { zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = SOCKET.as_bytes();
    if bytes.len() + 1 > address.sun_path.len() {
        return Err(GuardianRefusal::Untrusted);
    }
    for (slot, byte) in address.sun_path.iter_mut().zip(bytes.iter()) {
        *slot = *byte as libc::c_char;
    }
    let length = (size_of::<libc::sa_family_t>() + bytes.len() + 1) as libc::socklen_t;
    if unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&raw const address).cast::<libc::sockaddr>(),
            length,
        )
    } != 0
    {
        return Err(GuardianRefusal::Unavailable);
    }
    let timeout = libc::timeval {
        tv_sec: 60,
        tv_usec: 0,
    };
    for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
        if unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                (&raw const timeout).cast::<libc::c_void>(),
                size_of::<libc::timeval>() as libc::socklen_t,
            )
        } != 0
        {
            return Err(GuardianRefusal::Unavailable);
        }
    }
    Ok(fd)
}

fn peer_pid(socket: RawFd) -> Result<u32> {
    let mut value: libc::ucred = unsafe { zeroed() };
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            socket,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut value).cast::<libc::c_void>(),
            &raw mut length,
        )
    } != 0
        || length as usize != size_of::<libc::ucred>()
        || value.pid <= 1
        || value.uid != 0
    {
        return Err(GuardianRefusal::Untrusted);
    }
    u32::try_from(value.pid).map_err(|_| GuardianRefusal::Untrusted)
}

fn peer_pidfd(socket: RawFd, pid: u32) -> Result<OwnedFd> {
    // Linux SO_PEERPIDFD returns an fd tied to the accepted socket peer.
    // pidfd_open(SO_PEERCRED.pid) can instead bind a recycled numeric PID.
    const SO_PEERPIDFD: libc::c_int = 77;
    let mut raw: libc::c_int = -1;
    let mut length = size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            socket,
            libc::SOL_SOCKET,
            SO_PEERPIDFD,
            (&raw mut raw).cast::<libc::c_void>(),
            &raw mut length,
        )
    } != 0
        || length as usize != size_of::<libc::c_int>()
        || raw < 0
    {
        return Err(GuardianRefusal::Untrusted);
    }
    // SAFETY: getsockopt(SO_PEERPIDFD) returns an owned descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let fdinfo = fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd()))
        .map_err(|_| GuardianRefusal::Untrusted)?;
    if !fdinfo.lines().any(|line| line == format!("Pid:\t{pid}")) {
        return Err(GuardianRefusal::Untrusted);
    }
    Ok(fd)
}

fn pidfd_live(fd: RawFd) -> Result<()> {
    let mut poll = libc::pollfd {
        fd,
        events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
        revents: 0,
    };
    let result = unsafe { libc::poll(&raw mut poll, 1, 0) };
    if result != 0 || poll.revents != 0 {
        return Err(GuardianRefusal::Stale);
    }
    Ok(())
}

/// Every caller is a root worker, installer or boot owner in PID1's own
/// namespaces (the guardian socket is root 0600). The guardian unit's
/// MainPID, ControlGroup and InvocationID come from PID1 over the verified
/// direct connection (S8) instead of a spawned `/usr/bin/timeout
/// /usr/bin/systemctl show`; the comparisons below are unchanged.
pub(crate) fn verify_guardian_peer(pid: u32) -> Result<String> {
    let facts = crate::profile_auto_stopped_service::pid1::guardian_service_identity()
        .map_err(|_| GuardianRefusal::Unavailable)?;
    let main = Some(facts.main_pid.as_str());
    let cgroup = Some(facts.control_group.as_str());
    let invocation = Some(facts.invocation_id.as_str());
    let expected_cgroup = "/system.slice/aegis-auto-guardian.service";
    let pid_text = pid.to_string();
    if main != Some(pid_text.as_str())
        || cgroup != Some(expected_cgroup)
        || !invocation.is_some_and(|v| hex(v, 32))
        || fs::read_to_string(format!("/proc/{pid}/cgroup")).map_err(|_| GuardianRefusal::Stale)?
            != format!("0::{expected_cgroup}\n")
    {
        return Err(GuardianRefusal::Untrusted);
    }
    Ok(invocation.ok_or(GuardianRefusal::Untrusted)?.to_owned())
}

pub(crate) struct LiveNativeGuard<'a> {
    pub(crate) guardian_nonce: &'a str,
    pub(crate) guardian_receipt_sha256: &'a str,
    pub(crate) policy_sha256: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LiveInspectionReply {
    schema: String,
    guardian_pid: u32,
    guardian_invocation_id: String,
    private_unit: String,
    main_pid: u32,
    invocation_id: String,
    boot_id: String,
    policy_sha256: Option<String>,
    manager_binding_sha256: Option<String>,
}

/// Read the live guardian's typed owner and manager binding without minting a
/// new grant. The server retains its original stage and guard descriptors.
pub(crate) fn inspect_live_guardian(
    guardian_pid: u32,
    guardian_invocation_id: &str,
    private_unit: &str,
    main_pid: u32,
    invocation_id: &str,
    boot_id: &str,
    native: Option<LiveNativeGuard<'_>>,
) -> Result<Option<String>> {
    if guardian_pid <= 1
        || main_pid <= 1
        || !hex(guardian_invocation_id, 32)
        || !hex(invocation_id, 32)
        || !valid_private_unit(private_unit)
        || boot_id
            != fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .map_err(|_| GuardianRefusal::Unavailable)?
                .trim()
        || native.as_ref().is_some_and(|guard| {
            !hex(guard.guardian_nonce, 64)
                || !hex(guard.guardian_receipt_sha256, 64)
                || !hex(guard.policy_sha256, 64)
        })
    {
        return Err(GuardianRefusal::Untrusted);
    }
    let socket = connect_seqpacket()?;
    let peer = peer_pid(socket.as_raw_fd())?;
    if peer != guardian_pid || verify_guardian_peer(peer)? != guardian_invocation_id {
        return Err(GuardianRefusal::Untrusted);
    }
    let peer_fd = peer_pidfd(socket.as_raw_fd(), peer)?;
    pidfd_live(peer_fd.as_raw_fd())?;
    let timeout = libc::timeval {
        tv_sec: 12,
        tv_usec: 0,
    };
    for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
        if unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                (&raw const timeout).cast::<libc::c_void>(),
                size_of::<libc::timeval>() as libc::socklen_t,
            )
        } != 0
        {
            return Err(GuardianRefusal::Unavailable);
        }
    }
    let guarded = native.is_some();
    let native_json = native.map(|guard| {
        serde_json::json!({
            "guardian_nonce": guard.guardian_nonce,
            "guardian_receipt_sha256": guard.guardian_receipt_sha256,
            "policy_sha256": guard.policy_sha256,
        })
    });
    let packet = serde_json::to_vec(&serde_json::json!({
        "schema": "aegis_auto_guardian_live_inspection_v1",
        "command": "INSPECT_LIVE",
        "guardian_invocation_id": guardian_invocation_id,
        "private_unit": private_unit,
        "main_pid": main_pid,
        "invocation_id": invocation_id,
        "boot_id": boot_id,
        "native_guard": native_json,
    }))
    .map_err(|_| GuardianRefusal::Untrusted)?;
    if unsafe {
        libc::send(
            socket.as_raw_fd(),
            packet.as_ptr().cast::<libc::c_void>(),
            packet.len(),
            libc::MSG_NOSIGNAL,
        )
    } != packet.len() as isize
    {
        return Err(GuardianRefusal::Unavailable);
    }
    let reply: LiveInspectionReply = serde_json::from_slice(&recv_packet(socket.as_raw_fd())?)
        .map_err(|_| GuardianRefusal::Untrusted)?;
    pidfd_live(peer_fd.as_raw_fd())?;
    if reply.schema != "aegis_auto_guardian_live_inspection_reply_v1"
        || reply.guardian_pid != peer
        || reply.guardian_invocation_id != guardian_invocation_id
        || reply.private_unit != private_unit
        || reply.main_pid != main_pid
        || reply.invocation_id != invocation_id
        || reply.boot_id != boot_id
        || (guarded
            && (!reply
                .policy_sha256
                .as_deref()
                .is_some_and(|value| hex(value, 64))
                || !reply
                    .manager_binding_sha256
                    .as_deref()
                    .is_some_and(|value| hex(value, 64))))
        || (!guarded && (reply.policy_sha256.is_some() || reply.manager_binding_sha256.is_some()))
        || verify_guardian_peer(peer)? != guardian_invocation_id
    {
        return Err(GuardianRefusal::Untrusted);
    }
    Ok(reply.manager_binding_sha256)
}

fn guard_lock_identity(fd: RawFd) -> Result<(u64, u64)> {
    let held = fd_identity(fd)?;
    let named = fs::symlink_metadata(GUARD_LOCK).map_err(|_| GuardianRefusal::Stale)?;
    if !named.file_type().is_file()
        || named.uid() != 0
        || named.nlink() != 1
        || named.mode() & 0o777 != 0o600
        || (named.dev(), named.ino()) != held
        || fs::symlink_metadata(SPLIT).is_ok()
    {
        return Err(GuardianRefusal::Stale);
    }
    Ok(held)
}

fn verify_guard_lock(fd: RawFd) -> Result<(u64, u64)> {
    let held = guard_lock_identity(fd)?;
    let fdinfo = fs::read_to_string(format!("/proc/self/fdinfo/{fd}"))
        .map_err(|_| GuardianRefusal::Stale)?;
    if !crate::profile_auto_stopped_service::held_transferred_flock_line(&fdinfo, held.0, held.1) {
        return Err(GuardianRefusal::Stale);
    }
    Ok(held)
}

fn send_with_fds<const N: usize>(socket: RawFd, payload: &[u8], fds: [RawFd; N]) -> Result<()> {
    if N == 0 || N > 3 {
        return Err(GuardianRefusal::Untrusted);
    }
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast::<libc::c_void>(),
        iov_len: payload.len(),
    };
    let capacity = unsafe { libc::CMSG_SPACE((N * size_of::<RawFd>()) as u32) as usize };
    let mut control = vec![0u8; capacity];
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &raw mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
    message.msg_controllen = control.len();
    // SAFETY: control is CMSG_SPACE-sized and msg_control points to it.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&raw const message);
        if cmsg.is_null() {
            return Err(GuardianRefusal::Untrusted);
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN((N * size_of::<RawFd>()) as u32) as usize;
        std::ptr::copy_nonoverlapping(
            fds.as_ptr().cast::<u8>(),
            libc::CMSG_DATA(cmsg),
            N * size_of::<RawFd>(),
        );
    }
    let written = unsafe { libc::sendmsg(socket, &raw const message, libc::MSG_NOSIGNAL) };
    if written != payload.len() as isize {
        return Err(GuardianRefusal::Unavailable);
    }
    Ok(())
}

fn recv_packet(socket: RawFd) -> Result<Vec<u8>> {
    let mut payload = vec![0u8; MAX_REPLY];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: payload.len(),
    };
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &raw mut iov;
    message.msg_iovlen = 1;
    let read = unsafe { libc::recvmsg(socket, &raw mut message, 0) };
    if read <= 0 || read as usize >= MAX_REPLY || message.msg_flags & libc::MSG_TRUNC != 0 {
        return Err(GuardianRefusal::Unavailable);
    }
    payload.truncate(read as usize);
    Ok(payload)
}

/// The fresh-stop guardian returns proof and a duplicate of its original
/// locked guard OFD in one kernel packet. Own every received descriptor before
/// checking flags or the JSON body so malformed/truncated packets cannot leak
/// descriptors or accidentally release custody outside this scope.
fn recv_packet_one_guard_fd(socket: RawFd) -> Result<(Vec<u8>, OwnedFd)> {
    let mut payload = vec![0u8; MAX_REPLY];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: payload.len(),
    };
    let control_len = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) as usize };
    let mut control = vec![0usize; control_len.div_ceil(size_of::<usize>())];
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &raw mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
    message.msg_controllen = control_len;
    let read = unsafe { libc::recvmsg(socket, &raw mut message, libc::MSG_CMSG_CLOEXEC) };
    if read < 0 {
        return Err(GuardianRefusal::Unavailable);
    }
    let mut received = Vec::<OwnedFd>::new();
    let mut control_count = 0usize;
    let mut invalid = false;
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&raw const message);
        while !header.is_null() {
            control_count += 1;
            let minimum = libc::CMSG_LEN(0) as usize;
            let length = (*header).cmsg_len;
            let start = header as usize;
            let control_end = message.msg_control as usize + message.msg_controllen;
            if length < minimum || start > control_end || length > control_end - start {
                invalid = true;
                break;
            } else if (*header).cmsg_level == libc::SOL_SOCKET
                && (*header).cmsg_type == libc::SCM_RIGHTS
            {
                let bytes = length - minimum;
                if bytes == 0 || !bytes.is_multiple_of(size_of::<RawFd>()) {
                    invalid = true;
                } else {
                    for index in 0..bytes / size_of::<RawFd>() {
                        let raw = std::ptr::read_unaligned(
                            libc::CMSG_DATA(header)
                                .add(index * size_of::<RawFd>())
                                .cast::<RawFd>(),
                        );
                        if raw < 0 {
                            invalid = true;
                        } else {
                            received.push(OwnedFd::from_raw_fd(raw));
                        }
                    }
                }
            } else {
                invalid = true;
            }
            header = libc::CMSG_NXTHDR(&raw const message, header);
        }
    }
    if read == 0
        || read as usize >= MAX_REPLY
        || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        || invalid
        || control_count != 1
        || received.len() != 1
    {
        return Err(GuardianRefusal::Untrusted);
    }
    let guard_fd = received.pop().ok_or(GuardianRefusal::Untrusted)?;
    let flags = unsafe { libc::fcntl(guard_fd.as_raw_fd(), libc::F_GETFD) };
    if flags < 0 || flags & libc::FD_CLOEXEC == 0 {
        return Err(GuardianRefusal::Untrusted);
    }
    payload.truncate(read as usize);
    Ok((payload, guard_fd))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoppedGuardReply {
    schema: String,
    actor_challenge: String,
    guardian_nonce: String,
    guardian_invocation_id: String,
    boot_id: String,
    unit: String,
    prior_invocation_id: String,
    stage_dev: u64,
    stage_ino: u64,
    guard_dev: u64,
    guard_ino: u64,
    stop_terminal_sha256: String,
    post_deny_policy_sha256: String,
}

struct StoppedGuardExpected<'a> {
    challenge: &'a str,
    guardian_invocation: &'a str,
    boot_id: &'a str,
    unit: &'a str,
    prior_invocation_id: &'a str,
    stage_identity: (u64, u64),
    guard_identity: (u64, u64),
    stop_terminal_sha256: &'a str,
    post_deny_policy_sha256: &'a str,
}

impl StoppedGuardReply {
    fn matches(&self, expected: &StoppedGuardExpected<'_>) -> bool {
        self.schema == "aegis_auto_guardian_stopped_guard_held_v1"
            && self.actor_challenge == expected.challenge
            && hex(&self.guardian_nonce, 64)
            && self.guardian_invocation_id == expected.guardian_invocation
            && self.boot_id == expected.boot_id
            && self.unit == expected.unit
            && self.prior_invocation_id == expected.prior_invocation_id
            && (self.stage_dev, self.stage_ino) == expected.stage_identity
            && (self.guard_dev, self.guard_ino) == expected.guard_identity
            && self.stop_terminal_sha256 == expected.stop_terminal_sha256
            && self.post_deny_policy_sha256 == expected.post_deny_policy_sha256
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoppedGuardCompleteReply {
    schema: String,
    actor_challenge: String,
    guardian_nonce: String,
}

impl StoppedGuardCompleteReply {
    fn matches(&self, challenge: &str, nonce: &str) -> bool {
        self.schema == "aegis_auto_guardian_stopped_guard_complete_reply_v1"
            && self.actor_challenge == challenge
            && self.guardian_nonce == nonce
    }
}

/// Read-only stopped observation under the guardian's original guard OFD.
/// The guardian retains its original until our socket closes. Drop order is
/// significant: close our duplicate first, then the socket last.
pub(crate) struct StoppedGuardLease {
    guard: OwnedFd,
    stage: OwnedFd,
    install: OwnedFd,
    peer_pidfd: OwnedFd,
    socket: OwnedFd,
    stage_identity: (u64, u64),
    install_identity: (u64, u64),
    guard_identity: (u64, u64),
    guardian_pid: u32,
    guardian_invocation: String,
    challenge: String,
    nonce: String,
    ready: bool,
}

/// Values bound to the exact stopped PID1 and finalized stage observation.
/// The received FDs remain independent of these scalar facts.
pub(crate) struct StoppedGuardBinding<'a> {
    pub(crate) guardian_pid: u32,
    pub(crate) guardian_invocation: &'a str,
    pub(crate) boot_id: &'a str,
    pub(crate) netns_ino: u64,
    pub(crate) unit: &'a str,
    pub(crate) prior_invocation_id: &'a str,
    pub(crate) stop_terminal_sha256: &'a str,
    pub(crate) post_deny_policy_sha256: &'a str,
}

impl StoppedGuardLease {
    pub(crate) fn acquire(
        stage: OwnedFd,
        install: OwnedFd,
        binding: StoppedGuardBinding<'_>,
    ) -> Result<Self> {
        let StoppedGuardBinding {
            guardian_pid,
            guardian_invocation,
            boot_id,
            netns_ino,
            unit,
            prior_invocation_id,
            stop_terminal_sha256,
            post_deny_policy_sha256,
        } = binding;
        if guardian_pid <= 1
            || netns_ino == 0
            || fs::metadata("/proc/self/ns/net")
                .map_err(|_| GuardianRefusal::Unavailable)?
                .ino()
                != netns_ino
            || !hex(guardian_invocation, 32)
            || !hex(prior_invocation_id, 32)
            || !hex(stop_terminal_sha256, 64)
            || !hex(post_deny_policy_sha256, 64)
            || !valid_private_unit(unit)
            || boot_id
                != fs::read_to_string("/proc/sys/kernel/random/boot_id")
                    .map_err(|_| GuardianRefusal::Unavailable)?
                    .trim()
        {
            return Err(GuardianRefusal::Untrusted);
        }
        let stage_identity = fd_identity(stage.as_raw_fd())?;
        let install_identity = fd_identity(install.as_raw_fd())?;
        let socket = connect_seqpacket()?;
        let peer = peer_pid(socket.as_raw_fd())?;
        if peer != guardian_pid || verify_guardian_peer(peer)? != guardian_invocation {
            return Err(GuardianRefusal::Untrusted);
        }
        let peer_pidfd = peer_pidfd(socket.as_raw_fd(), peer)?;
        pidfd_live(peer_pidfd.as_raw_fd())?;
        let mut random = [0u8; 32];
        fs::File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut random))
            .map_err(|_| GuardianRefusal::Unavailable)?;
        let challenge = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let request = serde_json::json!({
            "schema": "aegis_auto_guardian_stopped_guard_v1",
            "command": "SEAL_STOPPED_GUARD",
            "actor_challenge": challenge.as_str(),
            "boot_id": boot_id,
            "netns_ino": netns_ino,
            "unit": unit,
            "prior_invocation_id": prior_invocation_id,
            "stage_dev": stage_identity.0,
            "stage_ino": stage_identity.1,
            "stop_terminal_sha256": stop_terminal_sha256,
            "post_deny_policy_sha256": post_deny_policy_sha256,
        });
        let payload = serde_json::to_vec(&request).map_err(|_| GuardianRefusal::Untrusted)?;
        if payload.is_empty() || payload.len() >= MAX_REPLY {
            return Err(GuardianRefusal::Untrusted);
        }
        send_with_fds(
            socket.as_raw_fd(),
            &payload,
            [stage.as_raw_fd(), install.as_raw_fd()],
        )?;
        let (reply_bytes, guard) = recv_packet_one_guard_fd(socket.as_raw_fd())?;
        let reply: StoppedGuardReply =
            serde_json::from_slice(&reply_bytes).map_err(|_| GuardianRefusal::Untrusted)?;
        let guard_identity = verify_guard_lock(guard.as_raw_fd())?;
        let expected = StoppedGuardExpected {
            challenge: &challenge,
            guardian_invocation,
            boot_id,
            unit,
            prior_invocation_id,
            stage_identity,
            guard_identity,
            stop_terminal_sha256,
            post_deny_policy_sha256,
        };
        if !reply.matches(&expected) {
            return Err(GuardianRefusal::Untrusted);
        }
        pidfd_live(peer_pidfd.as_raw_fd())?;
        if verify_guardian_peer(peer)? != guardian_invocation
            || fd_identity(stage.as_raw_fd())? != stage_identity
            || fd_identity(install.as_raw_fd())? != install_identity
            || verify_guard_lock(guard.as_raw_fd())? != guard_identity
        {
            return Err(GuardianRefusal::Stale);
        }
        Ok(Self {
            socket,
            peer_pidfd,
            stage,
            install,
            guard,
            stage_identity,
            install_identity,
            guard_identity,
            guardian_pid: peer,
            guardian_invocation: guardian_invocation.to_owned(),
            challenge,
            nonce: reply.guardian_nonce,
            ready: false,
        })
    }

    pub(crate) fn revalidate(&self) -> Result<()> {
        pidfd_live(self.peer_pidfd.as_raw_fd())?;
        stopped_guard_socket_live(self.socket.as_raw_fd())?;
        if peer_pid(self.socket.as_raw_fd())? != self.guardian_pid
            || verify_guardian_peer(self.guardian_pid)? != self.guardian_invocation
            || fd_identity(self.stage.as_raw_fd())? != self.stage_identity
            || fd_identity(self.install.as_raw_fd())? != self.install_identity
            || verify_guard_lock(self.guard.as_raw_fd())? != self.guard_identity
        {
            return Err(GuardianRefusal::Stale);
        }
        Ok(())
    }

    /// Acknowledge only after the caller completed all stopped PID1 and deny
    /// observations. This does not release either guard OFD: the guardian's
    /// original stays held until this lease's socket is closed.
    pub(crate) fn ack_ready(&mut self) -> Result<()> {
        if self.ready {
            return Err(GuardianRefusal::Untrusted);
        }
        self.revalidate()?;
        send_json(
            self.socket.as_raw_fd(),
            &serde_json::json!({
                "schema": "aegis_auto_guardian_stopped_guard_complete_v1",
                "command": "SEAL_DONE",
                "actor_challenge": self.challenge.as_str(),
                "guardian_nonce": self.nonce.as_str(),
            }),
        )?;
        let reply: StoppedGuardCompleteReply =
            serde_json::from_slice(&recv_packet(self.socket.as_raw_fd())?)
                .map_err(|_| GuardianRefusal::Untrusted)?;
        if !reply.matches(&self.challenge, &self.nonce) {
            return Err(GuardianRefusal::Untrusted);
        }
        self.revalidate()?;
        self.ready = true;
        Ok(())
    }

    pub(crate) fn revalidate_ready(&self) -> Result<()> {
        if !self.ready {
            return Err(GuardianRefusal::Untrusted);
        }
        self.revalidate()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootGuardReply {
    schema: String,
    actor_challenge: String,
    guardian_nonce: String,
    guardian_invocation_id: String,
    boot_id: String,
    netns_ino: u64,
    boot_snapshot_sha256: String,
    active_report_sha256: String,
    predecessor_boot_id: String,
    candidate_sha256: String,
    private_unit: String,
    prior_invocation_id: String,
    guard_dev: u64,
    guard_ino: u64,
}

struct BootGuardExpected<'a> {
    challenge: &'a str,
    guardian_invocation: &'a str,
    binding: BootGuardBinding<'a>,
    guard_identity: (u64, u64),
}

impl BootGuardReply {
    fn matches(&self, expected: &BootGuardExpected<'_>) -> bool {
        self.schema == "aegis_auto_guardian_boot_guard_held_v1"
            && self.actor_challenge == expected.challenge
            && hex(&self.guardian_nonce, 64)
            && self.guardian_invocation_id == expected.guardian_invocation
            && self.boot_id == expected.binding.boot_id
            && self.netns_ino == expected.binding.netns_ino
            && self.boot_snapshot_sha256 == expected.binding.boot_snapshot_sha256
            && self.active_report_sha256 == expected.binding.active_report_sha256
            && self.predecessor_boot_id == expected.binding.predecessor_boot_id
            && self.candidate_sha256 == expected.binding.candidate_sha256
            && self.private_unit == expected.binding.private_unit
            && self.prior_invocation_id == expected.binding.prior_invocation_id
            && (self.guard_dev, self.guard_ino) == expected.guard_identity
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootGuardCompleteReply {
    schema: String,
    actor_challenge: String,
    guardian_nonce: String,
}

impl BootGuardCompleteReply {
    fn matches(&self, challenge: &str, nonce: &str) -> bool {
        self.schema == "aegis_auto_guardian_boot_guard_complete_reply_v1"
            && self.actor_challenge == challenge
            && self.guardian_nonce == nonce
    }
}

pub(crate) struct BootGuardBinding<'a> {
    pub(crate) boot_id: &'a str,
    pub(crate) netns_ino: u64,
    pub(crate) boot_snapshot_sha256: &'a str,
    pub(crate) active_report_sha256: &'a str,
    pub(crate) predecessor_boot_id: &'a str,
    pub(crate) candidate_sha256: &'a str,
    pub(crate) private_unit: &'a str,
    pub(crate) prior_invocation_id: &'a str,
}

/// Read-only fresh-boot observation under the guardian's original OFD.
/// No old stage exists on this boot; the original held InstallLock is the
/// sole transferred input FD. The guardian keeps its OFD through socket EOF.
pub(crate) struct BootGuardLease {
    guard: OwnedFd,
    install: OwnedFd,
    peer_pidfd: OwnedFd,
    socket: OwnedFd,
    install_identity: (u64, u64),
    guard_identity: (u64, u64),
    guardian_pid: u32,
    guardian_invocation: String,
    challenge: String,
    nonce: String,
    ready: bool,
}

impl BootGuardLease {
    pub(crate) fn acquire(install: OwnedFd, binding: BootGuardBinding<'_>) -> Result<Self> {
        if binding.netns_ino == 0
            || fs::metadata("/proc/self/ns/net")
                .map_err(|_| GuardianRefusal::Unavailable)?
                .ino()
                != binding.netns_ino
            || !hex(binding.boot_snapshot_sha256, 64)
            || !hex(binding.active_report_sha256, 64)
            || !hex(binding.candidate_sha256, 64)
            || !valid_private_unit(binding.private_unit)
            || !hex(binding.prior_invocation_id, 32)
            || binding.predecessor_boot_id == binding.boot_id
            || binding.boot_id
                != fs::read_to_string("/proc/sys/kernel/random/boot_id")
                    .map_err(|_| GuardianRefusal::Unavailable)?
                    .trim()
        {
            return Err(GuardianRefusal::Untrusted);
        }
        let install_identity = fd_identity(install.as_raw_fd())?;
        let socket = connect_seqpacket()?;
        let peer = peer_pid(socket.as_raw_fd())?;
        let guardian_invocation = verify_guardian_peer(peer)?;
        let peer_pidfd = peer_pidfd(socket.as_raw_fd(), peer)?;
        pidfd_live(peer_pidfd.as_raw_fd())?;
        let mut random = [0u8; 32];
        fs::File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut random))
            .map_err(|_| GuardianRefusal::Unavailable)?;
        let challenge = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let request = serde_json::json!({
            "schema": "aegis_auto_guardian_boot_guard_v1",
            "command": "SEAL_BOOT_GUARD",
            "actor_challenge": challenge.as_str(),
            "boot_id": binding.boot_id,
            "netns_ino": binding.netns_ino,
            "boot_snapshot_sha256": binding.boot_snapshot_sha256,
            "active_report_sha256": binding.active_report_sha256,
            "predecessor_boot_id": binding.predecessor_boot_id,
            "candidate_sha256": binding.candidate_sha256,
            "private_unit": binding.private_unit,
            "prior_invocation_id": binding.prior_invocation_id,
        });
        let payload = serde_json::to_vec(&request).map_err(|_| GuardianRefusal::Untrusted)?;
        if payload.is_empty() || payload.len() >= MAX_REPLY {
            return Err(GuardianRefusal::Untrusted);
        }
        send_with_fds(socket.as_raw_fd(), &payload, [install.as_raw_fd()])?;
        let (reply_bytes, guard) = recv_packet_one_guard_fd(socket.as_raw_fd())?;
        let reply: BootGuardReply =
            serde_json::from_slice(&reply_bytes).map_err(|_| GuardianRefusal::Untrusted)?;
        let guard_identity = verify_guard_lock(guard.as_raw_fd())?;
        let expected = BootGuardExpected {
            challenge: &challenge,
            guardian_invocation: &guardian_invocation,
            binding,
            guard_identity,
        };
        if !reply.matches(&expected) {
            return Err(GuardianRefusal::Untrusted);
        }
        pidfd_live(peer_pidfd.as_raw_fd())?;
        if verify_guardian_peer(peer)? != guardian_invocation
            || fd_identity(install.as_raw_fd())? != install_identity
            || verify_guard_lock(guard.as_raw_fd())? != guard_identity
        {
            return Err(GuardianRefusal::Stale);
        }
        Ok(Self {
            guard,
            install,
            peer_pidfd,
            socket,
            install_identity,
            guard_identity,
            guardian_pid: peer,
            guardian_invocation,
            challenge,
            nonce: reply.guardian_nonce,
            ready: false,
        })
    }

    pub(crate) fn guard_fd(&self) -> &OwnedFd {
        &self.guard
    }

    pub(crate) fn revalidate(&self) -> Result<()> {
        pidfd_live(self.peer_pidfd.as_raw_fd())?;
        stopped_guard_socket_live(self.socket.as_raw_fd())?;
        if peer_pid(self.socket.as_raw_fd())? != self.guardian_pid
            || verify_guardian_peer(self.guardian_pid)? != self.guardian_invocation
            || fd_identity(self.install.as_raw_fd())? != self.install_identity
            || verify_guard_lock(self.guard.as_raw_fd())? != self.guard_identity
        {
            return Err(GuardianRefusal::Stale);
        }
        Ok(())
    }

    pub(crate) fn ack_ready(&mut self) -> Result<()> {
        if self.ready {
            eprintln!("AEGIS_AUTO_BOOT_REFUSED phase=guard_ack_repeated");
            return Err(GuardianRefusal::Untrusted);
        }
        self.revalidate().inspect_err(|_| {
            eprintln!("AEGIS_AUTO_BOOT_REFUSED phase=guard_ack_preflight");
        })?;
        send_json(
            self.socket.as_raw_fd(),
            &serde_json::json!({
                "schema": "aegis_auto_guardian_boot_guard_complete_v1",
                "command": "SEAL_DONE",
                "actor_challenge": self.challenge.as_str(),
                "guardian_nonce": self.nonce.as_str(),
            }),
        )
        .inspect_err(|_| {
            eprintln!("AEGIS_AUTO_BOOT_REFUSED phase=guard_ack_send");
        })?;
        let reply_bytes = recv_packet(self.socket.as_raw_fd()).inspect_err(|_| {
            eprintln!("AEGIS_AUTO_BOOT_REFUSED phase=guard_ack_receive");
        })?;
        let reply: BootGuardCompleteReply = serde_json::from_slice(&reply_bytes).map_err(|_| {
            eprintln!("AEGIS_AUTO_BOOT_REFUSED phase=guard_ack_reply_shape");
            GuardianRefusal::Untrusted
        })?;
        if !reply.matches(&self.challenge, &self.nonce) {
            eprintln!("AEGIS_AUTO_BOOT_REFUSED phase=guard_ack_reply_mismatch");
            return Err(GuardianRefusal::Untrusted);
        }
        self.revalidate().inspect_err(|_| {
            eprintln!("AEGIS_AUTO_BOOT_REFUSED phase=guard_ack_postflight");
        })?;
        self.ready = true;
        Ok(())
    }

    pub(crate) fn revalidate_ready(&self) -> Result<()> {
        if !self.ready {
            return Err(GuardianRefusal::Untrusted);
        }
        self.revalidate()
    }
}

/// Detect a guardian that ended this lease while its PID1 process survived.
/// An authenticated ACK is not enough once the original guard owner has gone.
fn stopped_guard_socket_live(socket: RawFd) -> Result<()> {
    let mut byte = 0u8;
    let result = unsafe {
        libc::recv(
            socket,
            (&mut byte as *mut u8).cast::<libc::c_void>(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    if result == -1 {
        let error = std::io::Error::last_os_error().raw_os_error();
        if error == Some(libc::EAGAIN) || error == Some(libc::EWOULDBLOCK) {
            return Ok(());
        }
    }
    Err(GuardianRefusal::Stale)
}

fn send_json(socket: RawFd, value: &serde_json::Value) -> Result<()> {
    let payload = serde_json::to_vec(value).map_err(|_| GuardianRefusal::Untrusted)?;
    if payload.is_empty() || payload.len() >= MAX_REPLY {
        return Err(GuardianRefusal::Untrusted);
    }
    let written = unsafe {
        libc::send(
            socket,
            payload.as_ptr().cast::<libc::c_void>(),
            payload.len(),
            libc::MSG_NOSIGNAL,
        )
    };
    if written != payload.len() as isize {
        return Err(GuardianRefusal::Unavailable);
    }
    Ok(())
}

fn valid_job(job: &crate::profile_auto_stopped_service::pid1::SubmittedJob) -> bool {
    job.id() > 0
        && valid_private_unit(job.unit())
        && job.path() == format!("/org/freedesktop/systemd1/job/{}", job.id())
}

fn valid_invocation(value: &str) -> bool {
    hex(value, 32)
}

fn valid_private_unit(value: &str) -> bool {
    value
        .strip_prefix("aegis-auto@")
        .and_then(|part| part.strip_suffix(".service"))
        .is_some_and(|generation| hex(generation, 64))
}

impl GuardDenyLease {
    /// Fresh finalized-stop inverse. The anchor borrows the protected
    /// terminal and both completed PID1 stop receipts under its original
    /// owner locks. The actor returns its original locked guard OFD with the
    /// inverse proof; no saved scalar record can call this path by itself.
    pub(crate) fn acquire_stop_inverse(
        anchor: &crate::profile_auto_transaction::FinalizedGuardAnchor<'_, '_, '_>,
    ) -> Result<CompletedCaptureInverse> {
        anchor.revalidate().map_err(|_| GuardianRefusal::Stale)?;
        let stage = anchor
            .duplicate_stage_fd()
            .map_err(|_| GuardianRefusal::Stale)?;
        let install_lock = anchor
            .duplicate_install_lock_fd()
            .map_err(|_| GuardianRefusal::Stale)?;
        let stage_identity = fd_identity(stage.as_raw_fd())?;
        let install_identity = fd_identity(install_lock.as_raw_fd())?;
        let mode = anchor.mode();
        let unit = anchor.unit();
        let stop_id = anchor.stop_job_id();
        let stop_path = anchor.stop_job_path();
        if stage_identity != anchor.stage_identity()
            || !matches!(mode, "full-wide-tun" | "wide-redirect-safe")
            || !valid_private_unit(unit)
            || stop_id == 0
            || stop_path != format!("/org/freedesktop/systemd1/job/{stop_id}")
            || anchor.original_guardian_pid() <= 1
            || !hex(anchor.original_guardian_nonce(), 64)
            || !hex(anchor.original_guardian_receipt_sha256(), 64)
            || !hex(anchor.original_guardian_policy_sha256(), 64)
            || !hex(anchor.native_capture_sha256(), 64)
            || !hex(anchor.terminal_sha256(), 64)
            || !hex(anchor.stop_intent_sha256(), 64)
            || !hex(anchor.stop_submitted_sha256(), 64)
            || !hex(anchor.stop_completed_sha256(), 64)
            || !hex(anchor.prior_invocation_id(), 32)
            || !hex(anchor.installed_generation_sha256(), 64)
            || !hex(anchor.installed_manifest_sha256(), 64)
            || !hex(anchor.policy_generation(), 64)
            || anchor.netns_ino() == 0
        {
            return Err(GuardianRefusal::Untrusted);
        }
        let socket = connect_seqpacket()?;
        let pid = peer_pid(socket.as_raw_fd())?;
        let peer_pidfd = peer_pidfd(socket.as_raw_fd(), pid)?;
        let _guardian_invocation_id = verify_guardian_peer(pid)?;
        pidfd_live(peer_pidfd.as_raw_fd())?;
        let mut challenge_bytes = [0u8; 32];
        fs::File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut challenge_bytes))
            .map_err(|_| GuardianRefusal::Unavailable)?;
        let actor_challenge = challenge_bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let request = serde_json::json!({
            "schema": "aegis_auto_guardian_stop_inverse_request_v1",
            "command": "STOP_INVERSE",
            "actor_challenge": actor_challenge.as_str(),
            "mode": mode,
            "boot_id": anchor.boot_id(),
            "netns_ino": anchor.netns_ino(),
            "stage_dev": stage_identity.0,
            "stage_ino": stage_identity.1,
            "unit": unit,
            "original_guardian_pid": anchor.original_guardian_pid(),
            "original_guardian_nonce": anchor.original_guardian_nonce(),
            "original_guardian_receipt_sha256": anchor.original_guardian_receipt_sha256(),
            "original_guardian_policy_sha256": anchor.original_guardian_policy_sha256(),
            "native_capture_sha256": anchor.native_capture_sha256(),
            "original_terminal_sha256": anchor.terminal_sha256(),
            "stop_intent_sha256": anchor.stop_intent_sha256(),
            "stop_submitted_sha256": anchor.stop_submitted_sha256(),
            "stop_completed_sha256": anchor.stop_completed_sha256(),
            "prior_invocation_id": anchor.prior_invocation_id(),
            "stop_job_id": stop_id,
            "stop_job_path": stop_path,
            "installed_generation_sha256": anchor.installed_generation_sha256(),
            "installed_manifest_sha256": anchor.installed_manifest_sha256(),
            "policy_generation": anchor.policy_generation(),
        });
        let payload = serde_json::to_vec(&request).map_err(|_| GuardianRefusal::Untrusted)?;
        if payload.is_empty() || payload.len() >= MAX_REPLY {
            return Err(GuardianRefusal::Untrusted);
        }
        send_with_fds(
            socket.as_raw_fd(),
            &payload,
            [stage.as_raw_fd(), install_lock.as_raw_fd()],
        )?;
        let (reply_bytes, guard_fd) = recv_packet_one_guard_fd(socket.as_raw_fd())?;
        let guard_identity = verify_guard_lock(guard_fd.as_raw_fd())?;
        let reply: FreshStopInverseReply =
            serde_json::from_slice(&reply_bytes).map_err(|_| GuardianRefusal::Untrusted)?;
        if reply.schema != "aegis_auto_fresh_stop_inverse_v1"
            || reply.actor_challenge != actor_challenge
            || reply.guardian_nonce != anchor.original_guardian_nonce()
            || reply.mode != mode
            || reply.boot_id != anchor.boot_id()
            || reply.netns_ino != anchor.netns_ino()
            || (reply.stage_dev, reply.stage_ino) != stage_identity
            || reply.unit != unit
            || reply.prior_invocation_id != anchor.prior_invocation_id()
            || reply.stop_job_id != stop_id
            || reply.stop_job_path != stop_path
            || !hex(&reply.post_deny_policy_sha256, 64)
            || !hex(&reply.native_inverse_sha256, 64)
            || peer_pid(socket.as_raw_fd())? != pid
        {
            return Err(GuardianRefusal::Untrusted);
        }
        anchor.revalidate().map_err(|_| GuardianRefusal::Stale)?;
        if fd_identity(stage.as_raw_fd())? != stage_identity
            || fd_identity(install_lock.as_raw_fd())? != install_identity
            || verify_guard_lock(guard_fd.as_raw_fd())? != guard_identity
        {
            return Err(GuardianRefusal::Stale);
        }
        pidfd_live(peer_pidfd.as_raw_fd())?;
        Ok(CompletedCaptureInverse {
            prior_invocation_id: reply.prior_invocation_id,
            stop_job_id: reply.stop_job_id,
            stop_job_path: reply.stop_job_path,
            stop_unit: reply.unit,
            boot_id: reply.boot_id,
            netns_ino: reply.netns_ino,
            stage_identity: (reply.stage_dev, reply.stage_ino),
            guardian_nonce: reply.guardian_nonce,
            post_deny_policy_sha256: reply.post_deny_policy_sha256,
            native_inverse_sha256: reply.native_inverse_sha256,
            hold: Some(InverseHold {
                socket,
                peer_pidfd,
                stage,
                install_lock,
                guard_lock: guard_fd,
                stage_identity,
                install_identity,
                guard_identity,
                guardian_pid: pid,
                completed: false,
            }),
        })
    }

    /// The original worker must keep its own InstallLock and StageGuard.  The
    /// returned OFD stays unlocked until the authenticated PID1 guardian
    /// receives it. The worker never becomes an anonymous guard writer.
    pub(crate) fn open_guard_for_handoff() -> Result<OwnedFd> {
        let parent = fs::symlink_metadata("/var/lib/aegis-install/client")
            .map_err(|_| GuardianRefusal::Unavailable)?;
        if !parent.file_type().is_dir() || parent.uid() != 0 || parent.mode() & 0o022 != 0 {
            return Err(GuardianRefusal::Untrusted);
        }
        let name = std::ffi::CString::new(GUARD_LOCK).map_err(|_| GuardianRefusal::Untrusted)?;
        let raw = unsafe {
            libc::open(
                name.as_ptr(),
                libc::O_RDWR | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(GuardianRefusal::Unavailable);
        }
        // SAFETY: open() returned one owned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        guard_lock_identity(fd.as_raw_fd())?;
        Ok(fd)
    }

    pub(crate) fn acquire(
        stage: OwnedFd,
        install_lock: OwnedFd,
        guard_lock: OwnedFd,
        binding: GuardianBinding,
    ) -> Result<Self> {
        if !hex(&binding.header_sha256, 64)
            || !hex(&binding.transaction_nonce, 32)
            || !hex(&binding.planned_generation, 64)
            || binding.netns_ino == 0
            || !matches!(
                binding.mode.as_str(),
                "full-wide-tun" | "wide-redirect-safe"
            )
            || !valid_private_unit(&binding.private_unit)
        {
            return Err(GuardianRefusal::Untrusted);
        }
        let stage_identity = fd_identity(stage.as_raw_fd())?;
        let install_identity = fd_identity(install_lock.as_raw_fd())?;
        let guard_identity = guard_lock_identity(guard_lock.as_raw_fd())?;
        let socket = connect_seqpacket()?;
        let pid = peer_pid(socket.as_raw_fd())?;
        let peer_pidfd = peer_pidfd(socket.as_raw_fd(), pid)?;
        let guardian_invocation_id = verify_guardian_peer(pid)?;
        pidfd_live(peer_pidfd.as_raw_fd())?;
        let mut challenge_bytes = [0u8; 32];
        fs::File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut challenge_bytes))
            .map_err(|_| GuardianRefusal::Unavailable)?;
        let actor_challenge = challenge_bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let request = serde_json::json!({
            "schema": "aegis_auto_guardian_request_v1",
            "command": "prove_deny",
            "mode": binding.mode.as_str(),
            "private_unit": binding.private_unit.as_str(),
            "header_sha256": binding.header_sha256.as_str(),
            "transaction_nonce": binding.transaction_nonce.as_str(),
            "planned_generation": binding.planned_generation.as_str(),
            "boot_id": binding.boot_id.as_str(),
            "netns_ino": binding.netns_ino,
            "actor_challenge": actor_challenge,
        });
        let payload = serde_json::to_vec(&request).map_err(|_| GuardianRefusal::Untrusted)?;
        send_with_fds(
            socket.as_raw_fd(),
            &payload,
            [
                stage.as_raw_fd(),
                install_lock.as_raw_fd(),
                guard_lock.as_raw_fd(),
            ],
        )?;
        let reply = recv_packet(socket.as_raw_fd())?;
        let grant: Grant =
            serde_json::from_slice(&reply).map_err(|_| GuardianRefusal::Untrusted)?;
        if grant.schema != "aegis_auto_guardian_grant_v1"
            || grant.pid != pid
            || grant.boot_id != request["boot_id"]
            || grant.actor_challenge != request["actor_challenge"]
            || grant.netns_ino != binding.netns_ino
            || (grant.stage_dev, grant.stage_ino) != stage_identity
            || !hex(&grant.nonce, 64)
            || !hex(&grant.native_receipt_sha256, 64)
            || !hex(&grant.policy_sha256, 64)
            || grant.private_unit != binding.private_unit
            || grant.guardian_invocation_id != guardian_invocation_id
            || grant.guardian_cgroup != "/system.slice/aegis-auto-guardian.service"
            || !hex(&grant.guardian_source_sha256, 64)
            || grant.guard_drop_handle == 0
            || grant.guard_output_drop_delta == 0
            || grant.trace_id.is_empty()
            || grant.trace_id.len() > 16
            || !grant
                .trace_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || !hex(&grant.trace_sha256, 64)
            || grant.sink_pid <= 1
            || grant.sink_pid == pid
            || grant.sink_netns_ino == 0
            || grant.sink_netns_ino == grant.netns_ino
            || !hex(&grant.sink_session, 32)
            || grant.sink_received != 0
            || !hex(&grant.baseline_sha256, 64)
            || grant.baseline_method != "af_packet_l2"
            || !grant.topology_inverse_proven
            || !grant.dual_stack_native_policy_proven()
        {
            return Err(GuardianRefusal::Untrusted);
        }
        let lease = Self {
            socket,
            peer_pidfd,
            stage,
            install_lock,
            guard_lock,
            stage_identity,
            install_identity,
            guard_identity,
            grant,
            mode: binding.mode,
            private_unit: binding.private_unit,
            prepared: false,
            awaiting_handoff: false,
            completed: false,
        };
        lease.revalidate()?;
        Ok(lease)
    }

    pub(crate) fn boot_id(&self) -> &str {
        &self.grant.boot_id
    }
    pub(crate) fn netns_ino(&self) -> u64 {
        self.grant.netns_ino
    }
    pub(crate) fn stage_identity(&self) -> (u64, u64) {
        self.stage_identity
    }
    pub(crate) fn guardian_pid(&self) -> u32 {
        self.grant.pid
    }
    pub(crate) fn nonce(&self) -> &str {
        &self.grant.nonce
    }
    pub(crate) fn native_receipt_sha256(&self) -> &str {
        &self.grant.native_receipt_sha256
    }
    pub(crate) fn policy_sha256(&self) -> &str {
        &self.grant.policy_sha256
    }
    pub(crate) fn private_unit(&self) -> &str {
        &self.private_unit
    }

    pub(crate) fn revalidate(&self) -> Result<()> {
        if self.completed
            || fd_identity(self.stage.as_raw_fd())? != self.stage_identity
            || fd_identity(self.install_lock.as_raw_fd())? != self.install_identity
            || verify_guard_lock(self.guard_lock.as_raw_fd())? != self.guard_identity
            || peer_pid(self.socket.as_raw_fd())? != self.grant.pid
        {
            return Err(GuardianRefusal::Stale);
        }
        pidfd_live(self.peer_pidfd.as_raw_fd())
    }

    fn effect_request(&self, command: &str) -> serde_json::Value {
        serde_json::json!({
            "schema": "aegis_auto_guardian_effect_request_v1",
            "command": command,
            "guardian_nonce": self.grant.nonce.as_str(),
            "mode": self.mode.as_str(),
            "private_unit": self.private_unit.as_str(),
            "boot_id": self.grant.boot_id.as_str(),
            "netns_ino": self.grant.netns_ino,
            "stage_dev": self.stage_identity.0,
            "stage_ino": self.stage_identity.1,
            "policy_sha256": self.grant.policy_sha256.as_str(),
            "native_receipt_sha256": self.grant.native_receipt_sha256.as_str(),
        })
    }

    fn capture_reply_matches(
        &self,
        reply: &CaptureReply,
        schema: &str,
        start: &crate::profile_auto_stopped_service::pid1::CompletedStart,
    ) -> bool {
        let (job, invocation) = start.facts();
        reply.schema == schema
            && reply.guardian_nonce == self.grant.nonce
            && reply.mode == self.mode
            && reply.boot_id == self.grant.boot_id
            && reply.netns_ino == self.grant.netns_ino
            && (reply.stage_dev, reply.stage_ino) == self.stage_identity
            && reply.policy_sha256 == self.grant.policy_sha256
            && reply.native_receipt_sha256 == self.grant.native_receipt_sha256
            && reply.pid1_job_id == job.id()
            && reply.pid1_job_path == job.path()
            && reply.pid1_unit == job.unit()
            && reply.pid1_unit == self.private_unit
            && reply.pid1_invocation_id == invocation
            && hex(&reply.native_capture_sha256, 64)
    }

    fn decode_capture_reply(
        &self,
        packet: &[u8],
        expected_schema: &str,
        command: &str,
        start: &crate::profile_auto_stopped_service::pid1::CompletedStart,
    ) -> Result<CaptureReply> {
        let schema = serde_json::from_slice::<serde_json::Value>(packet)
            .map_err(|_| GuardianRefusal::Untrusted)?;
        if schema.get("schema").and_then(serde_json::Value::as_str)
            == Some("aegis_auto_capture_refused_v1")
        {
            let refusal: CaptureRefusalReply =
                serde_json::from_slice(packet).map_err(|_| GuardianRefusal::Untrusted)?;
            let (job, invocation) = start.facts();
            let expected = CaptureExpected {
                command,
                guardian_nonce: &self.grant.nonce,
                mode: &self.mode,
                boot_id: &self.grant.boot_id,
                netns_ino: self.grant.netns_ino,
                stage_identity: self.stage_identity,
                policy_sha256: &self.grant.policy_sha256,
                native_receipt_sha256: &self.grant.native_receipt_sha256,
                pid1_job_id: job.id(),
                pid1_job_path: job.path(),
                pid1_unit: job.unit(),
                private_unit: &self.private_unit,
                pid1_invocation_id: invocation,
            };
            if !refusal.matches(&expected) {
                return Err(GuardianRefusal::Untrusted);
            }
            let (reason, source, line) = refusal.coordinate().ok_or(GuardianRefusal::Untrusted)?;
            return Err(GuardianRefusal::CaptureFailed {
                reason,
                source,
                line,
            });
        }
        let reply: CaptureReply =
            serde_json::from_slice(packet).map_err(|_| GuardianRefusal::Untrusted)?;
        if !self.capture_reply_matches(&reply, expected_schema, start) {
            return Err(GuardianRefusal::Untrusted);
        }
        Ok(reply)
    }

    pub(crate) fn capture_ready(
        &mut self,
        start: &mut crate::profile_auto_stopped_service::pid1::OwnedStart,
        mode: &str,
        retained: &mut Option<CaptureReady>,
    ) -> Result<()> {
        if retained.is_some() {
            return Err(GuardianRefusal::Untrusted);
        }
        self.revalidate()?;
        start.revalidate().map_err(|_| GuardianRefusal::Stale)?;
        let (job, invocation) = start.completed().facts();
        if mode != self.mode
            || !valid_job(job)
            || job.unit() != self.private_unit
            || !valid_invocation(invocation)
            || job.manager().boot_id() != self.grant.boot_id
            || job.manager().netns_identity().1 != self.grant.netns_ino
        {
            return Err(GuardianRefusal::Untrusted);
        }
        let mut request = self.effect_request("CAPTURE_READY");
        request["pid1_job_id"] = job.id().into();
        request["pid1_job_path"] = job.path().into();
        request["pid1_unit"] = job.unit().into();
        request["pid1_invocation_id"] = invocation.into();
        send_json(self.socket.as_raw_fd(), &request)?;
        let reply = self.decode_capture_reply(
            &recv_packet(self.socket.as_raw_fd())?,
            "aegis_auto_capture_ready_v1",
            "CAPTURE_READY",
            start.completed(),
        )?;
        let ready = CaptureReady {
            guardian_nonce: reply.guardian_nonce,
            mode: reply.mode,
            boot_id: reply.boot_id,
            netns_ino: reply.netns_ino,
            stage_identity: (reply.stage_dev, reply.stage_ino),
            policy_sha256: reply.policy_sha256,
            native_receipt_sha256: reply.native_receipt_sha256,
            pid1_job_id: reply.pid1_job_id,
            pid1_job_path: reply.pid1_job_path,
            pid1_unit: reply.pid1_unit,
            pid1_invocation_id: reply.pid1_invocation_id,
            native_capture_sha256: reply.native_capture_sha256,
        };
        retain_ready_before_postcheck(retained, ready, || {
            start.revalidate().map_err(|_| GuardianRefusal::Stale)?;
            self.revalidate()
        })
    }

    pub(crate) fn complete_compensated_failure(
        &mut self,
        stop: &crate::profile_auto_stopped_service::pid1::CompletedStop,
        ready: Option<&CaptureReady>,
    ) -> Result<CompletedCaptureInverse> {
        self.revalidate()?;
        let (job, prior_invocation) = stop.facts();
        if !valid_job(job)
            || job.unit() != self.private_unit
            || !valid_invocation(prior_invocation)
            || job.manager().boot_id() != self.grant.boot_id
            || job.manager().netns_identity().1 != self.grant.netns_ino
        {
            return Err(GuardianRefusal::Untrusted);
        }
        if let Some(ready) = ready {
            ready.matches_lease(self)?;
            if ready.pid1_invocation_id != prior_invocation || ready.pid1_unit != job.unit() {
                return Err(GuardianRefusal::Untrusted);
            }
        }
        let mut request = self.effect_request("COMPENSATED_STOP");
        request["prior_invocation_id"] = prior_invocation.into();
        request["stop_job_id"] = job.id().into();
        request["stop_job_path"] = job.path().into();
        request["stop_unit"] = job.unit().into();
        request["native_capture_sha256"] = compensation_capture_reference(ready);
        send_json(self.socket.as_raw_fd(), &request)?;
        let reply: InverseReply = serde_json::from_slice(&recv_packet(self.socket.as_raw_fd())?)
            .map_err(|_| GuardianRefusal::Untrusted)?;
        if reply.schema != "aegis_auto_capture_inverse_v1"
            || reply.guardian_nonce != self.grant.nonce
            || reply.mode != self.mode
            || reply.boot_id != self.grant.boot_id
            || reply.netns_ino != self.grant.netns_ino
            || (reply.stage_dev, reply.stage_ino) != self.stage_identity
            || reply.prior_invocation_id != prior_invocation
            || reply.stop_job_id != job.id()
            || reply.stop_job_path != job.path()
            || reply.stop_unit != job.unit()
            || !hex(&reply.post_deny_policy_sha256, 64)
            || !hex(&reply.native_inverse_sha256, 64)
        {
            return Err(GuardianRefusal::Untrusted);
        }
        self.revalidate()?;
        let hold = InverseHold {
            socket: self
                .socket
                .try_clone()
                .map_err(|_| GuardianRefusal::Stale)?,
            peer_pidfd: self
                .peer_pidfd
                .try_clone()
                .map_err(|_| GuardianRefusal::Stale)?,
            stage: self.stage.try_clone().map_err(|_| GuardianRefusal::Stale)?,
            install_lock: self
                .install_lock
                .try_clone()
                .map_err(|_| GuardianRefusal::Stale)?,
            guard_lock: self
                .guard_lock
                .try_clone()
                .map_err(|_| GuardianRefusal::Stale)?,
            stage_identity: self.stage_identity,
            install_identity: self.install_identity,
            guard_identity: self.guard_identity,
            guardian_pid: self.grant.pid,
            completed: false,
        };
        Ok(CompletedCaptureInverse {
            prior_invocation_id: reply.prior_invocation_id,
            stop_job_id: reply.stop_job_id,
            stop_job_path: reply.stop_job_path,
            stop_unit: reply.stop_unit,
            boot_id: reply.boot_id,
            netns_ino: reply.netns_ino,
            stage_identity: (reply.stage_dev, reply.stage_ino),
            guardian_nonce: reply.guardian_nonce,
            post_deny_policy_sha256: reply.post_deny_policy_sha256,
            native_inverse_sha256: reply.native_inverse_sha256,
            hold: Some(hold),
        })
    }

    /// Read back the native effect while retaining the original held lease.
    /// A failed owner terminal/marker transition may still compensate it.
    pub(crate) fn prepare_complete(&mut self) -> Result<()> {
        self.revalidate()?;
        if self.prepared {
            return Err(GuardianRefusal::Stale);
        }
        let sent = unsafe {
            libc::send(
                self.socket.as_raw_fd(),
                b"PREPARE_COMPLETE\n".as_ptr().cast(),
                b"PREPARE_COMPLETE\n".len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if sent != b"PREPARE_COMPLETE\n".len() as isize {
            return Err(GuardianRefusal::Unavailable);
        }
        if recv_packet(self.socket.as_raw_fd())? != b"PREPARED\n" {
            return Err(GuardianRefusal::Stale);
        }
        self.prepared = true;
        self.revalidate()
    }

    /// Called only after the protected owner terminal and exact marker
    /// retirement have been synced and read back under the original locks.
    pub(crate) fn commit_done(&mut self) -> Result<()> {
        self.revalidate()?;
        if !self.prepared || self.awaiting_handoff {
            return Err(GuardianRefusal::Stale);
        }
        let sent = unsafe {
            libc::send(
                self.socket.as_raw_fd(),
                b"COMMIT_DONE\n".as_ptr().cast(),
                b"COMMIT_DONE\n".len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if sent != b"COMMIT_DONE\n".len() as isize {
            return Err(GuardianRefusal::Unavailable);
        }
        if recv_packet(self.socket.as_raw_fd())? != b"PREPARED_HANDOFF\n" {
            return Err(GuardianRefusal::Stale);
        }
        self.awaiting_handoff = true;
        Ok(())
    }

    /// After the owner removes its protected handoff marker under the same
    /// held Store locks, the guardian transfers custody to the independent
    /// private-main watchdog and releases worker-death monitoring.
    pub(crate) fn finish_handoff(&mut self) -> Result<()> {
        self.revalidate()?;
        if !self.awaiting_handoff {
            return Err(GuardianRefusal::Stale);
        }
        let sent = unsafe {
            libc::send(
                self.socket.as_raw_fd(),
                b"HANDOFF_CLEARED\n".as_ptr().cast(),
                b"HANDOFF_CLEARED\n".len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if sent != b"HANDOFF_CLEARED\n".len() as isize {
            return Err(GuardianRefusal::Unavailable);
        }
        if recv_packet(self.socket.as_raw_fd())? != b"COMPLETE\n" {
            return Err(GuardianRefusal::Stale);
        }
        self.completed = true;
        Ok(())
    }
}

impl CaptureReady {
    fn matches_lease(&self, lease: &GuardDenyLease) -> Result<()> {
        lease.revalidate()?;
        if self.guardian_nonce != lease.grant.nonce
            || self.mode != lease.mode
            || self.pid1_unit != lease.private_unit
            || self.boot_id != lease.grant.boot_id
            || self.netns_ino != lease.grant.netns_ino
            || self.stage_identity != lease.stage_identity
            || self.policy_sha256 != lease.grant.policy_sha256
            || self.native_receipt_sha256 != lease.grant.native_receipt_sha256
            || !hex(&self.native_capture_sha256, 64)
        {
            return Err(GuardianRefusal::Stale);
        }
        Ok(())
    }

    pub(crate) fn revalidate(
        &self,
        lease: &GuardDenyLease,
        start: &mut crate::profile_auto_stopped_service::pid1::OwnedStart,
    ) -> Result<()> {
        self.matches_lease(lease)?;
        start.revalidate().map_err(|_| GuardianRefusal::Stale)?;
        let (job, invocation) = start.completed().facts();
        if !valid_job(job)
            || job.id() != self.pid1_job_id
            || job.path() != self.pid1_job_path
            || job.unit() != self.pid1_unit
            || invocation != self.pid1_invocation_id
            || job.manager().boot_id() != self.boot_id
            || job.manager().netns_identity().1 != self.netns_ino
        {
            return Err(GuardianRefusal::Stale);
        }
        let mut request = lease.effect_request("CAPTURE_REVALIDATE");
        request["pid1_job_id"] = self.pid1_job_id.into();
        request["pid1_job_path"] = self.pid1_job_path.as_str().into();
        request["pid1_unit"] = self.pid1_unit.as_str().into();
        request["pid1_invocation_id"] = self.pid1_invocation_id.as_str().into();
        request["native_capture_sha256"] = self.native_capture_sha256.as_str().into();
        send_json(lease.socket.as_raw_fd(), &request)?;
        let reply = lease.decode_capture_reply(
            &recv_packet(lease.socket.as_raw_fd())?,
            "aegis_auto_capture_revalidated_v1",
            "CAPTURE_REVALIDATE",
            start.completed(),
        )?;
        if reply.native_capture_sha256 != self.native_capture_sha256 {
            return Err(GuardianRefusal::Stale);
        }
        start.revalidate().map_err(|_| GuardianRefusal::Stale)?;
        lease.revalidate()
    }

    pub(crate) fn native_capture_sha256(&self) -> &str {
        &self.native_capture_sha256
    }
}

impl CompletedCaptureInverse {
    pub(crate) fn revalidate(&self) -> Result<()> {
        let hold = self.hold.as_ref().ok_or(GuardianRefusal::Stale)?;
        if hold.completed
            || fd_identity(hold.stage.as_raw_fd())? != hold.stage_identity
            || fd_identity(hold.install_lock.as_raw_fd())? != hold.install_identity
            || verify_guard_lock(hold.guard_lock.as_raw_fd())? != hold.guard_identity
            || peer_pid(hold.socket.as_raw_fd())? != hold.guardian_pid
        {
            return Err(GuardianRefusal::Stale);
        }
        pidfd_live(hold.peer_pidfd.as_raw_fd())
    }

    /// Called only after the owner has fsynced and read back the exact final
    /// terminal. The guardian independently verifies that native inverse and
    /// durable state before releasing its deny hold.
    pub(crate) fn complete_effect(&mut self) -> Result<()> {
        self.revalidate()?;
        let hold = self.hold.as_mut().ok_or(GuardianRefusal::Stale)?;
        let payload = b"INVERSE_COMPLETE\n";
        let sent = unsafe {
            libc::send(
                hold.socket.as_raw_fd(),
                payload.as_ptr().cast::<libc::c_void>(),
                payload.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if sent != payload.len() as isize {
            return Err(GuardianRefusal::Unavailable);
        }
        if recv_packet(hold.socket.as_raw_fd())? != b"COMPLETE\n" {
            return Err(GuardianRefusal::Stale);
        }
        hold.completed = true;
        Ok(())
    }
    pub(crate) fn prior_invocation_id(&self) -> &str {
        &self.prior_invocation_id
    }
    pub(crate) fn stop_job_id(&self) -> u32 {
        self.stop_job_id
    }
    pub(crate) fn stop_job_path(&self) -> &str {
        &self.stop_job_path
    }
    pub(crate) fn stop_unit(&self) -> &str {
        &self.stop_unit
    }
    pub(crate) fn boot_id(&self) -> &str {
        &self.boot_id
    }
    pub(crate) fn netns_ino(&self) -> u64 {
        self.netns_ino
    }
    pub(crate) fn stage_identity(&self) -> (u64, u64) {
        self.stage_identity
    }
    pub(crate) fn guardian_nonce(&self) -> &str {
        &self.guardian_nonce
    }
    pub(crate) fn post_deny_policy_sha256(&self) -> &str {
        &self.post_deny_policy_sha256
    }
    pub(crate) fn native_inverse_sha256(&self) -> &str {
        &self.native_inverse_sha256
    }
}

impl From<io::Error> for GuardianRefusal {
    fn from(_: io::Error) -> Self {
        Self::Unavailable
    }
}

#[cfg(test)]
mod capture_refusal_tests {
    use super::{
        compensation_capture_reference, retain_ready_before_postcheck, CaptureExpected,
        CaptureReady, CaptureRefusalReply, GuardianRefusal,
    };

    #[test]
    fn authenticated_first_ready_remains_available_after_postcheck_failure() {
        let ready = CaptureReady {
            guardian_nonce: "a".repeat(64),
            mode: "wide-redirect-safe".into(),
            boot_id: "boot".into(),
            netns_ino: 11,
            stage_identity: (12, 13),
            policy_sha256: "b".repeat(64),
            native_receipt_sha256: "c".repeat(64),
            pid1_job_id: 14,
            pid1_job_path: "/org/freedesktop/systemd1/job/14".into(),
            pid1_unit: "aegis-auto@private.service".into(),
            pid1_invocation_id: "d".repeat(32),
            native_capture_sha256: "e".repeat(64),
        };
        let mut retained = None;
        assert!(matches!(
            retain_ready_before_postcheck(&mut retained, ready, || Err(GuardianRefusal::Stale)),
            Err(GuardianRefusal::Stale)
        ));
        assert_eq!(
            retained.as_ref().unwrap().native_capture_sha256,
            "e".repeat(64)
        );
        assert_eq!(
            retained.as_ref().unwrap().pid1_invocation_id,
            "d".repeat(32)
        );
        assert_eq!(
            compensation_capture_reference(retained.as_ref()),
            serde_json::Value::String("e".repeat(64))
        );
        assert_eq!(
            compensation_capture_reference(None),
            serde_json::Value::Null
        );
    }

    #[test]
    fn capture_refusal_requires_exact_retained_owner_and_bounded_reason() {
        let expected = CaptureExpected {
            command: "CAPTURE_READY",
            guardian_nonce: "nonce",
            mode: "wide-redirect-safe",
            boot_id: "boot",
            netns_ino: 11,
            stage_identity: (12, 13),
            policy_sha256: "policy",
            native_receipt_sha256: "receipt",
            pid1_job_id: 14,
            pid1_job_path: "/org/freedesktop/systemd1/job/14",
            pid1_unit: "aegis-auto@private.service",
            private_unit: "aegis-auto@private.service",
            pid1_invocation_id: "invocation",
        };
        let accepted = serde_json::json!({
            "schema": "aegis_auto_capture_refused_v1",
            "command": "CAPTURE_READY",
            "guardian_nonce": "nonce",
            "mode": "wide-redirect-safe",
            "boot_id": "boot",
            "netns_ino": 11,
            "stage_dev": 12,
            "stage_ino": 13,
            "policy_sha256": "policy",
            "native_receipt_sha256": "receipt",
            "pid1_job_id": 14,
            "pid1_job_path": "/org/freedesktop/systemd1/job/14",
            "pid1_unit": "aegis-auto@private.service",
            "pid1_invocation_id": "invocation",
            "reason": "os_error",
            "source": "guardian",
            "line": 42,
        });
        let parse = |value: &serde_json::Value| {
            serde_json::from_value::<CaptureRefusalReply>(value.clone())
        };
        let admitted = parse(&accepted).unwrap();
        assert!(admitted.matches(&expected));
        let (reason, source, line) = admitted.coordinate().unwrap();
        let refusal = GuardianRefusal::CaptureFailed {
            reason,
            source,
            line,
        };
        assert_eq!(
            refusal.capture_coordinate(),
            Some(("os_error", "guardian", 42))
        );
        assert_eq!(GuardianRefusal::Untrusted.capture_coordinate(), None);
        for (field, replacement) in [
            ("command", "CAPTURE_REVALIDATE"),
            ("guardian_nonce", "foreign"),
            ("pid1_job_path", "/org/freedesktop/systemd1/job/15"),
            ("pid1_invocation_id", "foreign"),
            ("reason", "private error text"),
        ] {
            let mut altered = accepted.clone();
            altered[field] = replacement.into();
            assert!(!parse(&altered).unwrap().matches(&expected), "{field}");
        }
        let mut extra = accepted.clone();
        extra["private_path"] = "/secret".into();
        assert!(parse(&extra).is_err());
        let mut bad_source = accepted.clone();
        bad_source["source"] = "../../private".into();
        assert!(!parse(&bad_source).unwrap().matches(&expected));
        assert!(parse(&bad_source).unwrap().coordinate().is_none());
        let mut bad_line = accepted.clone();
        bad_line["line"] = 10_001.into();
        assert!(!parse(&bad_line).unwrap().matches(&expected));
    }
}

#[cfg(test)]
mod dual_stack_grant_tests {
    use super::Grant;
    use serde_json::{json, Value};

    fn fixture() -> Value {
        let mut v = json!({});
        for key in [
            "schema",
            "nonce",
            "actor_challenge",
            "native_receipt_sha256",
            "boot_id",
            "policy_sha256",
            "private_unit",
            "guardian_invocation_id",
            "guardian_cgroup",
            "guardian_source_sha256",
            "trace_id",
            "trace_sha256",
            "sink_session",
            "baseline_sha256",
            "baseline_method",
            "ipv6_trace_sha256",
            "foreign_projection_sha256",
        ] {
            v[key] = json!("a".repeat(64));
        }
        for key in [
            "pid",
            "netns_ino",
            "stage_dev",
            "stage_ino",
            "guard_drop_handle",
            "guard_output_drop_delta",
            "sink_pid",
            "sink_netns_ino",
            "ipv6_guard_drop_delta",
        ] {
            v[key] = json!(1);
        }
        v["sink_received"] = json!(0);
        v["ipv6_sink_received"] = json!(0);
        v["topology_inverse_proven"] = json!(true);
        v["foreign_policy_class"] = json!("filter_only");
        v["foreign_policy_backend"] = json!("nf_tables");
        v
    }

    #[test]
    fn dual_stack_proof_and_foreign_policy_are_mandatory_typed_fields() {
        let valid = fixture();
        assert!(serde_json::from_value::<Grant>(valid.clone())
            .unwrap()
            .dual_stack_native_policy_proven());
        for (key, wrong) in [
            ("ipv6_trace_sha256", json!("A".repeat(64))),
            ("ipv6_trace_sha256", json!("a".repeat(63))),
            ("ipv6_sink_received", json!(1)),
            ("ipv6_guard_drop_delta", json!(0)),
            ("foreign_policy_class", json!("unknown")),
            ("foreign_policy_backend", json!("legacy")),
            ("foreign_projection_sha256", json!("x".repeat(64))),
        ] {
            let mut changed = valid.clone();
            changed[key] = wrong;
            assert!(
                !serde_json::from_value::<Grant>(changed)
                    .unwrap()
                    .dual_stack_native_policy_proven(),
                "{key}"
            );
        }
        for key in [
            "ipv6_trace_sha256",
            "ipv6_sink_received",
            "ipv6_guard_drop_delta",
            "foreign_policy_class",
            "foreign_policy_backend",
            "foreign_projection_sha256",
        ] {
            let mut changed = valid.clone();
            changed.as_object_mut().unwrap().remove(key);
            assert!(serde_json::from_value::<Grant>(changed).is_err(), "{key}");
            let mut changed = valid.clone();
            changed[key] = Value::Null;
            assert!(serde_json::from_value::<Grant>(changed).is_err(), "{key}");
        }
        let mut changed = valid;
        changed["untrusted_extra"] = json!(true);
        assert!(serde_json::from_value::<Grant>(changed).is_err());
    }
}

#[cfg(test)]
mod stopped_guard_protocol_tests {
    use super::{
        stopped_guard_socket_live, GuardianRefusal, StoppedGuardCompleteReply,
        StoppedGuardExpected, StoppedGuardReply,
    };
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    fn socket_pair() -> (OwnedFd, OwnedFd) {
        let mut raw = [-1; 2];
        let rc = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                raw.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0);
        (unsafe { OwnedFd::from_raw_fd(raw[0]) }, unsafe {
            OwnedFd::from_raw_fd(raw[1])
        })
    }

    #[test]
    fn live_guardian_session_then_noise_and_eof_fail_closed() {
        let (client, guardian) = socket_pair();
        assert!(stopped_guard_socket_live(client.as_raw_fd()).is_ok());
        assert_eq!(
            unsafe { libc::send(guardian.as_raw_fd(), b"x".as_ptr().cast(), 1, 0) },
            1
        );
        assert_eq!(
            stopped_guard_socket_live(client.as_raw_fd()),
            Err(GuardianRefusal::Stale)
        );
        let mut byte = 0u8;
        assert_eq!(
            unsafe { libc::recv(client.as_raw_fd(), (&mut byte as *mut u8).cast(), 1, 0) },
            1
        );
        assert!(stopped_guard_socket_live(client.as_raw_fd()).is_ok());
        drop(guardian);
        assert_eq!(
            stopped_guard_socket_live(client.as_raw_fd()),
            Err(GuardianRefusal::Stale)
        );
    }

    #[test]
    fn stopped_guard_replies_reject_replay_and_extra_fields() {
        let challenge = "a".repeat(64);
        let nonce = "b".repeat(64);
        let invocation = "c".repeat(32);
        let prior = "d".repeat(32);
        let terminal = "e".repeat(64);
        let policy = "f".repeat(64);
        let unit = format!("aegis-auto@{}.service", "1".repeat(64));
        let expected = StoppedGuardExpected {
            challenge: &challenge,
            guardian_invocation: &invocation,
            boot_id: "boot",
            unit: &unit,
            prior_invocation_id: &prior,
            stage_identity: (11, 12),
            guard_identity: (21, 22),
            stop_terminal_sha256: &terminal,
            post_deny_policy_sha256: &policy,
        };
        let held = serde_json::json!({
            "schema":"aegis_auto_guardian_stopped_guard_held_v1",
            "actor_challenge":challenge,"guardian_nonce":nonce,
            "guardian_invocation_id":invocation,"boot_id":"boot","unit":unit,
            "prior_invocation_id":prior,"stage_dev":11,"stage_ino":12,
            "guard_dev":21,"guard_ino":22,
            "stop_terminal_sha256":terminal,"post_deny_policy_sha256":policy,
        });
        let parsed: StoppedGuardReply = serde_json::from_value(held.clone()).unwrap();
        assert!(parsed.matches(&expected));
        for (field, replacement) in [
            ("actor_challenge", serde_json::json!("0".repeat(64))),
            ("guardian_nonce", serde_json::json!("short")),
            ("guardian_invocation_id", serde_json::json!("0".repeat(32))),
            ("stage_ino", serde_json::json!(13)),
            ("guard_dev", serde_json::json!(23)),
            ("post_deny_policy_sha256", serde_json::json!("0".repeat(64))),
        ] {
            let mut changed = held.clone();
            changed[field] = replacement;
            assert!(
                !serde_json::from_value::<StoppedGuardReply>(changed)
                    .unwrap()
                    .matches(&expected),
                "{field}"
            );
        }
        let mut injected = held.clone();
        injected["private_path"] = "/secret".into();
        assert!(serde_json::from_value::<StoppedGuardReply>(injected).is_err());
        let complete = serde_json::json!({
            "schema":"aegis_auto_guardian_stopped_guard_complete_reply_v1",
            "actor_challenge":challenge,"guardian_nonce":nonce,
        });
        let parsed: StoppedGuardCompleteReply = serde_json::from_value(complete.clone()).unwrap();
        assert!(parsed.matches(&challenge, &nonce));
        assert!(!parsed.matches(&"0".repeat(64), &nonce));
        let mut injected = complete;
        injected["private_path"] = "/secret".into();
        assert!(serde_json::from_value::<StoppedGuardCompleteReply>(injected).is_err());
    }
}

#[cfg(test)]
mod boot_guard_protocol_tests {
    use super::{BootGuardBinding, BootGuardCompleteReply, BootGuardExpected, BootGuardReply};

    #[test]
    fn held_reply_binds_boot_lineage_and_denies_replayed_fields() {
        let challenge = "a".repeat(64);
        let nonce = "b".repeat(64);
        let invocation = "c".repeat(32);
        let snapshot = "d".repeat(64);
        let report = "e".repeat(64);
        let candidate = "f".repeat(64);
        let prior = "1".repeat(32);
        let unit = format!("aegis-auto@{}.service", "2".repeat(64));
        let expected = BootGuardExpected {
            challenge: &challenge,
            guardian_invocation: &invocation,
            binding: BootGuardBinding {
                boot_id: "new-boot",
                netns_ino: 17,
                boot_snapshot_sha256: &snapshot,
                active_report_sha256: &report,
                predecessor_boot_id: "old-boot",
                candidate_sha256: &candidate,
                private_unit: &unit,
                prior_invocation_id: &prior,
            },
            guard_identity: (21, 22),
        };
        let held = serde_json::json!({
            "schema":"aegis_auto_guardian_boot_guard_held_v1",
            "actor_challenge":challenge,"guardian_nonce":nonce,
            "guardian_invocation_id":invocation,"boot_id":"new-boot",
            "netns_ino":17,"boot_snapshot_sha256":snapshot,
            "active_report_sha256":report,"predecessor_boot_id":"old-boot",
            "candidate_sha256":candidate,"private_unit":unit,
            "prior_invocation_id":prior,"guard_dev":21,"guard_ino":22,
        });
        assert!(serde_json::from_value::<BootGuardReply>(held.clone())
            .unwrap()
            .matches(&expected));
        for (field, replacement) in [
            ("actor_challenge", serde_json::json!("0".repeat(64))),
            ("guardian_nonce", serde_json::json!("short")),
            ("guardian_invocation_id", serde_json::json!("0".repeat(32))),
            ("boot_id", serde_json::json!("wrong-boot")),
            ("netns_ino", serde_json::json!(18)),
            ("boot_snapshot_sha256", serde_json::json!("0".repeat(64))),
            ("active_report_sha256", serde_json::json!("0".repeat(64))),
            ("predecessor_boot_id", serde_json::json!("wrong-old-boot")),
            ("candidate_sha256", serde_json::json!("0".repeat(64))),
            (
                "private_unit",
                serde_json::json!(format!("aegis-auto@{}.service", "3".repeat(64))),
            ),
            ("prior_invocation_id", serde_json::json!("0".repeat(32))),
            ("guard_ino", serde_json::json!(23)),
        ] {
            let mut changed = held.clone();
            changed[field] = replacement;
            assert!(
                !serde_json::from_value::<BootGuardReply>(changed)
                    .unwrap()
                    .matches(&expected),
                "{field}"
            );
        }
        let mut injected = held;
        injected["private_path"] = "/secret".into();
        assert!(serde_json::from_value::<BootGuardReply>(injected).is_err());
    }

    #[test]
    fn completion_reply_requires_both_nonces_and_no_extra_fields() {
        let challenge = "a".repeat(64);
        let nonce = "b".repeat(64);
        let complete = serde_json::json!({
            "schema":"aegis_auto_guardian_boot_guard_complete_reply_v1",
            "actor_challenge":challenge,"guardian_nonce":nonce,
        });
        let parsed: BootGuardCompleteReply = serde_json::from_value(complete.clone()).unwrap();
        assert!(parsed.matches(&challenge, &nonce));
        assert!(!parsed.matches(&"0".repeat(64), &nonce));
        assert!(!parsed.matches(&challenge, &"0".repeat(64)));
        let mut injected = complete;
        injected["private_path"] = "/secret".into();
        assert!(serde_json::from_value::<BootGuardCompleteReply>(injected).is_err());
    }
}
