//! Bidirectional generic-UDP transparent proxy: REDIRECT capture + policy-
//! ordered datagram carry + transparent reply back to the local application.
//!
//! ## Why this exists (honest architecture)
//!
//! The NFQUEUE [`super::udp_masque_bridge`] is **verdict-only**: it can carry a
//! UDP datagram's *send* leg over MASQUE direct but cannot inject the relay's
//! response back into the originating application socket, so it is honestly
//! send-only. This module closes that gap for ordinary local apps **without**
//! turning NFQUEUE into a relay and **without** raw-socket injection:
//!
//!  1. A firewall REDIRECT rule (`nat OUTPUT -p udp -j REDIRECT --to-ports P`)
//!     diverts generic outbound UDP to this proxy's listener (the original
//!     packet is DNAT'd to the loopback target, so it never egresses natively).
//!  2. The **original destination** the app was reaching is recovered from
//!     netfilter conntrack — `IP_RECVORIGDSTADDR` only yields the post-DNAT
//!     loopback target for a REDIRECT, so the real pre-NAT destination is read
//!     from the conntrack ORIGINAL tuple (via `/proc/net/nf_conntrack` when
//!     present, else over ctnetlink — both pure, no external tools).
//!  3. The datagram body is carried by the configured UDP transport plan:
//!     direct MASQUE when available, otherwise fronted gRPC/H2 datagrams.
//!  4. The response is delivered back to the app over the **conntrack-reverse**
//!     path: it is sent from this same listener socket (bound to the REDIRECT
//!     target) straight to the app peer; netfilter recognises it as the reply
//!     direction of the captured flow and rewrites the source back to the
//!     original destination, so the app's connected socket accepts it. No
//!     `IP_TRANSPARENT` and no fight with the DNAT mapping.
//!
//! Live-proven end to end on real Ubuntu 26.04 (a no-proxy app `recv`s its
//! echoed datagram back through the configured relay transport).
//!
//! ## Fail-closed
//!
//! The original packet is DNAT'd off the native path by REDIRECT before it can
//! leak. If conntrack cannot resolve the destination, or the relay
//! send/receive leg errors, or the reply cannot be sent, the flow stays
//! fail-closed — there is **no** native UDP fallback under any outcome.

#![cfg(target_os = "linux")]

use super::ancillary::{self, cmsg_space, ControlBuffer};
use super::udp_conntrack::Lookup;
#[cfg(test)]
use super::udp_conntrack::{
    orig_dst_from_attrs, parse_conntrack_original_dst_v4, CTA_IP_V4_DST, CTA_IP_V4_SRC,
    CTA_PROTO_DST_PORT, CTA_PROTO_SRC_PORT, CTA_TUPLE_IP, CTA_TUPLE_ORIG, CTA_TUPLE_PROTO,
};
use super::udp_conntrack_lookup;
use crate::runtime_event_stream as runtime_jsonl;
use crate::runtime_events::RuntimeEventCode;
use aegis_core::RelaySettings;
use serde_json::json;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::mem::{size_of, zeroed};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket as StdUdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// `IP_RECVORIGDSTADDR` / `IP_ORIGDSTADDR` share the value 20 on Linux (the
/// setsockopt that enables the cmsg and the cmsg_type that carries it).
const IP_RECVORIGDSTADDR: libc::c_int = 20;
const IP_ORIGDSTADDR: libc::c_int = 20;

/// Identifies one captured generic-UDP flow: the local application peer and the
/// original destination it was trying to reach (preserved by REDIRECT).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub peer: SocketAddr,
    pub orig_dst: SocketAddr,
}

/// One datagram recovered from the REDIRECT listener.
#[derive(Debug, Clone)]
pub struct CapturedDatagram {
    pub peer: SocketAddr,
    pub orig_dst: SocketAddr,
    pub payload: Vec<u8>,
}

/// Configuration for the bidirectional UDP redirect proxy.
pub struct UdpRedirectProxyConfig {
    /// Local address the REDIRECT rule diverts generic UDP to.
    pub listen_addr: SocketAddr,
    /// Relay settings used to open the policy-ordered UDP carry.
    pub settings: RelaySettings,
    /// The same map owned by the DNS/TCP backend, never a second allocator.
    pub fake_ip_map: Option<Arc<super::dns_preview::FakeIpMap>>,
    /// A flow with no datagram for this long is reaped (`wide_udp_flow_closed`).
    pub idle_timeout: Duration,
    /// Maximum datagram body accepted from the listener.
    pub max_datagram: usize,
    /// Maximum concurrent persistent relay flows. New flows beyond this are
    /// dropped (fail-closed, never native) — bounds fd/port/memory against a
    /// datagram flood.
    pub max_flows: usize,
    /// Explicit controlled startup; closed input is discarded, revoke is permanent.
    pub(crate) forward_gate: Option<super::forward_gate::ForwardGate>,
}

impl UdpRedirectProxyConfig {
    pub fn new(listen_addr: SocketAddr, settings: RelaySettings) -> Self {
        Self {
            listen_addr,
            settings,
            fake_ip_map: None,
            idle_timeout: Duration::from_secs(30),
            max_datagram: 65_535,
            max_flows: 512,
            forward_gate: None,
        }
    }
}

#[cfg(test)]
fn relay_target_for_flow(
    key: &FlowKey,
    map: Option<&super::dns_preview::FakeIpMap>,
) -> std::io::Result<crate::socks5::ConnectTarget> {
    Ok(crate::socks5::ConnectTarget {
        host: super::dns_preview::resolve_target_host(key.orig_dst, map)?,
        port: key.orig_dst.port(),
    })
}

fn lease_relay_target_for_flow(
    key: &FlowKey,
    map: Option<&super::dns_preview::FakeIpMap>,
) -> std::io::Result<(
    crate::socks5::ConnectTarget,
    Option<super::dns_preview::FakeIpLease>,
)> {
    let (host, lease) = super::dns_preview::lease_target_host(key.orig_dst, map)?;
    Ok((
        crate::socks5::ConnectTarget {
            host,
            port: key.orig_dst.port(),
        },
        lease,
    ))
}

/// Bound per-tuple retries when a relay session fails immediately. Closed flows
/// stay in the already-bounded session map until this opening deadline passes.
const UDP_FLOW_RECONNECT_COOLDOWN: Duration = Duration::from_secs(1);

/// A persistent relay UDP session (or cooling-down retry entry). Datagrams
/// are fed into `outbound_tx`; a spawned forwarder injects replies back to the app
/// peer via the conntrack-reverse path. Dropping this handle closes `outbound_tx`,
/// which ends the session task (and, transitively, its reply forwarder).
struct ProxyUdpFlow {
    outbound_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    last_active: Instant,
    next_open_at: Instant,
    _mapping_lease: Option<super::dns_preview::FakeIpLease>,
}

impl ProxyUdpFlow {
    fn new(outbound_tx: tokio::sync::mpsc::Sender<Vec<u8>>, opened_at: Instant) -> Self {
        Self {
            outbound_tx,
            last_active: opened_at,
            next_open_at: opened_at + UDP_FLOW_RECONNECT_COOLDOWN,
            _mapping_lease: None,
        }
    }

    fn with_mapping_lease(mut self, lease: Option<super::dns_preview::FakeIpLease>) -> Self {
        self._mapping_lease = lease;
        self
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ExistingFlowSend {
    Queued,
    QueueFull,
    RetryCooldown,
    Missing(Vec<u8>),
    Closed(Vec<u8>),
}

/// Only the capture loop owns the session map. A relay task signals completion
/// by dropping its receiver; it never removes a possibly newer entry by key.
fn send_to_existing_flow(
    sessions: &mut HashMap<FlowKey, ProxyUdpFlow>,
    key: &FlowKey,
    payload: Vec<u8>,
    now: Instant,
) -> ExistingFlowSend {
    let Some(flow) = sessions.get_mut(key) else {
        return ExistingFlowSend::Missing(payload);
    };
    match flow.outbound_tx.try_send(payload) {
        Ok(()) => {
            flow.last_active = now;
            ExistingFlowSend::Queued
        }
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            // Backpressure is UDP loss, not a dead transport. Keep the live
            // session rather than reconnecting on every packet in a burst.
            flow.last_active = now;
            ExistingFlowSend::QueueFull
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(payload)) => {
            if now < flow.next_open_at {
                // Fail closed without refreshing either timestamp: continuous
                // packets must neither hammer the relay nor postpone retry forever.
                return ExistingFlowSend::RetryCooldown;
            }
            // The receiver may close after the sweep. Preserve this datagram
            // for a new relay session instead of refreshing the dead entry.
            sessions.remove(key);
            ExistingFlowSend::Closed(payload)
        }
    }
}

/// Bind the capture socket: a UDP socket on `listen_addr` with
/// `IP_RECVORIGDSTADDR` enabled so each `recvmsg` carries the pre-REDIRECT
/// destination as a control message.
fn bind_capture_socket_v4(listen_addr: SocketAddr) -> std::io::Result<StdUdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    // This service must exclusively own its capture port. UDP has no TIME_WAIT
    // and SO_REUSEADDR would allow a second proxy to steal diverted datagrams.
    enable_recv_original_dst_v4(&socket)?;
    socket.bind(&listen_addr.into())?;
    socket.set_nonblocking(false)?;
    Ok(socket.into())
}

fn enable_recv_original_dst_v4(socket: &Socket) -> std::io::Result<()> {
    let fd = socket.as_raw_fd();
    let enabled: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_IP,
            IP_RECVORIGDSTADDR,
            &enabled as *const libc::c_int as *const libc::c_void,
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Receive one redirected datagram, recovering the original destination from
/// the `IP_ORIGDSTADDR` control message.
#[allow(clippy::unnecessary_cast)] // glibc usize vs musl socklen_t(u32)
fn recv_redirected_datagram_v4(
    socket: &StdUdpSocket,
    max_datagram: usize,
) -> std::io::Result<CapturedDatagram> {
    let fd = socket.as_raw_fd();
    let mut payload = vec![0u8; max_datagram.max(1)];
    let mut peer_addr: libc::sockaddr_storage = unsafe { zeroed() };
    let mut control = ControlBuffer::<{ cmsg_space(size_of::<libc::sockaddr_in>()) }>::new();
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_name = &mut peer_addr as *mut libc::sockaddr_storage as *mut libc::c_void;
    msg.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr();
    msg.msg_controllen = control.len() as _;

    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        let e = std::io::Error::last_os_error();
        if !runtime_jsonl::private_logs_enabled()
            && std::env::var_os("AEGIS_UDP_PROXY_DEBUG").is_some()
            && !matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            )
        {
            eprintln!(
                "[udp-proxy-debug] recvmsg err kind={:?} raw={}",
                e.kind(),
                e
            );
        }
        return Err(e);
    }
    if !runtime_jsonl::private_logs_enabled() && std::env::var_os("AEGIS_UDP_PROXY_DEBUG").is_some()
    {
        eprintln!(
            "[udp-proxy-debug] recvmsg n={n} controllen={} namelen={} flags={}",
            msg.msg_controllen, msg.msg_namelen, msg.msg_flags
        );
    }
    let peer = parse_peer_v4(&peer_addr, msg.msg_namelen)?;
    let orig_dst = parse_origdst_v4(control.received(msg.msg_controllen as usize, msg.msg_flags)?)?;
    Ok(CapturedDatagram {
        peer: SocketAddr::V4(peer),
        orig_dst: SocketAddr::V4(orig_dst),
        payload: payload[..n as usize].to_vec(),
    })
}

fn parse_peer_v4(
    peer_addr: &libc::sockaddr_storage,
    name_len: libc::socklen_t,
) -> std::io::Result<SocketAddrV4> {
    if name_len < size_of::<libc::sockaddr_in>() as libc::socklen_t
        || peer_addr.ss_family as libc::c_int != libc::AF_INET
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "generic-udp capture expects an IPv4 peer",
        ));
    }
    // SAFETY: the initialized storage and checked name length contain a complete
    // integer-only IPv4 sockaddr; the copy creates no reference into C storage.
    let addr = unsafe {
        (peer_addr as *const libc::sockaddr_storage)
            .cast::<libc::sockaddr_in>()
            .read_unaligned()
    };
    Ok(SocketAddrV4::new(
        Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)),
        u16::from_be(addr.sin_port),
    ))
}

/// Walk the control buffer for the `IP_ORIGDSTADDR` cmsg and decode the
/// preserved original destination. Pure and unit-testable.
fn parse_origdst_v4(control: &[u8]) -> std::io::Result<SocketAddrV4> {
    ancillary::original_destination_v4(control, libc::SOL_IP, IP_ORIGDSTADDR)
}

/// Acquire only a complete bounded proc snapshot. Partial input is a refusal,
/// never a reason to choose a second destination from the native dump.
fn read_conntrack_proc(
    control: &udp_conntrack_lookup::Control<'_>,
) -> udp_conntrack_lookup::ProcSnapshot {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    use udp_conntrack_lookup::ProcSnapshot;

    if !control.permitted() {
        return ProcSnapshot::Refused;
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open("/proc/net/nf_conntrack");
    let mut file = match file {
        Ok(file) => file,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
            ) =>
        {
            return ProcSnapshot::Unavailable;
        }
        Err(_) => return ProcSnapshot::Refused,
    };
    if !control.permitted() || !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
        return ProcSnapshot::Refused;
    }
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if !control.permitted() {
            return ProcSnapshot::Refused;
        }
        let read_size = (udp_conntrack_lookup::MAX_LOOKUP_BYTES + 1 - bytes.len()).min(chunk.len());
        match file.read(&mut chunk[..read_size]) {
            Ok(0) => {
                return if control.permitted() {
                    ProcSnapshot::Complete(bytes)
                } else {
                    ProcSnapshot::Refused
                };
            }
            Ok(count) => {
                bytes.extend_from_slice(&chunk[..count]);
                if bytes.len() > udp_conntrack_lookup::MAX_LOOKUP_BYTES || !control.permitted() {
                    return ProcSnapshot::Refused;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return ProcSnapshot::Refused,
        }
    }
}

/// One newly captured lookup cutoff covers proc acquisition and native I/O.
fn conntrack_original_dst_v4(
    peer: SocketAddrV4,
    control: &udp_conntrack_lookup::Control<'_>,
) -> Option<SocketAddrV4> {
    udp_conntrack_lookup::resolve_sources(
        peer,
        control,
        || read_conntrack_proc(control),
        |peer| conntrack_original_dst_v4_netlink(peer, control),
    )
}

const NETLINK_NETFILTER: libc::c_int = 12;
const NFNL_SUBSYS_CTNETLINK: u16 = 1;
const IPCTNL_MSG_CT_GET: u16 = 1;
const NLM_F_DUMP: u16 = 0x100 | 0x200;

struct FdGuard(libc::c_int);
impl Drop for FdGuard {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

/// Poll in short stop-observing slices, always against the caller's one cutoff.
/// Kernel scheduling can delay return; the caller refuses every late result.
fn wait_conntrack_fd(
    fd: libc::c_int,
    events: libc::c_short,
    control: &udp_conntrack_lookup::Control<'_>,
) -> Result<(), ()> {
    loop {
        let remaining = control.remaining().ok_or(())?;
        let timeout_ms = remaining.as_millis().clamp(1, 20) as libc::c_int;
        let mut poll = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut poll, 1, timeout_ms) };
        if !control.permitted() {
            return Err(());
        }
        if result > 0 {
            if poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                return Err(());
            }
            if poll.revents & events != 0 {
                return Ok(());
            }
        } else if result < 0
            && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
        {
            return Err(());
        }
    }
}

/// The descriptor is owned here, nonblocking, kernel-connected and closed on
/// every terminal result. No worker or reusable numeric descriptor escapes.
fn conntrack_original_dst_v4_netlink(
    peer: SocketAddrV4,
    control: &udp_conntrack_lookup::Control<'_>,
) -> Lookup {
    if !control.permitted() {
        return Lookup::Refused;
    }
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            NETLINK_NETFILTER,
        )
    };
    if fd < 0 {
        return Lookup::Refused;
    }
    let _guard = FdGuard(fd);
    let mut local: libc::sockaddr_nl = unsafe { zeroed() };
    local.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let address_size = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
    if !control.permitted()
        || unsafe {
            libc::bind(
                fd,
                (&local as *const libc::sockaddr_nl).cast(),
                address_size,
            )
        } != 0
    {
        return Lookup::Refused;
    }
    let kernel = local;
    if !control.permitted()
        || unsafe {
            libc::connect(
                fd,
                (&kernel as *const libc::sockaddr_nl).cast(),
                address_size,
            )
        } != 0
    {
        return Lookup::Refused;
    }

    const SEQUENCE: u32 = 1;
    let mut request = Vec::with_capacity(20);
    request.extend_from_slice(&20u32.to_ne_bytes());
    request.extend_from_slice(&((NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET).to_ne_bytes());
    request.extend_from_slice(&((libc::NLM_F_REQUEST as u16) | NLM_F_DUMP).to_ne_bytes());
    request.extend_from_slice(&SEQUENCE.to_ne_bytes());
    request.extend_from_slice(&0u32.to_ne_bytes());
    request.push(libc::AF_INET as u8);
    request.push(0);
    request.extend_from_slice(&0u16.to_be_bytes());
    loop {
        if !control.permitted() {
            return Lookup::Refused;
        }
        let sent = unsafe {
            libc::send(
                fd,
                request.as_ptr().cast(),
                request.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if sent == request.len() as isize {
            break;
        }
        if sent >= 0 {
            return Lookup::Refused;
        }
        match std::io::Error::last_os_error().kind() {
            std::io::ErrorKind::Interrupted => {}
            std::io::ErrorKind::WouldBlock => {
                if wait_conntrack_fd(fd, libc::POLLOUT, control).is_err() {
                    return Lookup::Refused;
                }
            }
            _ => return Lookup::Refused,
        }
    }

    udp_conntrack_lookup::lookup_dump(peer, SEQUENCE, control, |buffer, control| loop {
        if !control.permitted() {
            return Err(());
        }
        let mut sender: libc::sockaddr_nl = unsafe { zeroed() };
        let mut iov = libc::iovec {
            iov_base: buffer.as_mut_ptr().cast(),
            iov_len: buffer.len(),
        };
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_name = (&mut sender as *mut libc::sockaddr_nl).cast();
        message.msg_namelen = address_size;
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        let count = unsafe { libc::recvmsg(fd, &mut message, libc::MSG_DONTWAIT) };
        if count >= 0 {
            return Ok(udp_conntrack_lookup::Received {
                len: count as usize,
                kernel_peer: message.msg_namelen >= address_size
                    && sender.nl_family as libc::c_int == libc::AF_NETLINK
                    && sender.nl_pid == 0
                    && sender.nl_groups == 0,
                truncated: message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0,
            });
        }
        match std::io::Error::last_os_error().kind() {
            std::io::ErrorKind::Interrupted => {}
            std::io::ErrorKind::WouldBlock => wait_conntrack_fd(fd, libc::POLLIN, control)?,
            _ => return Err(()),
        }
    })
}

/// Reap ended relay sessions once retry is allowed, as well as idle live flows.
/// Closed entries must survive the sweep during cooldown, or a following packet
/// would bypass the rate bound by looking like a new flow. Polling the current
/// sender also means a late-finishing old task cannot remove its replacement.
fn sweep_finished(
    sessions: &mut HashMap<FlowKey, ProxyUdpFlow>,
    now: Instant,
    idle: Duration,
) -> Vec<(FlowKey, &'static str)> {
    let expired: Vec<_> = sessions
        .iter()
        .filter_map(|(key, flow)| {
            if flow.outbound_tx.is_closed() {
                (now >= flow.next_open_at).then_some((*key, "relay_session_closed"))
            } else if now.duration_since(flow.last_active) >= idle {
                Some((*key, "idle_timeout"))
            } else {
                None
            }
        })
        .collect();
    for (k, _) in &expired {
        sessions.remove(k);
    }
    expired
}

/// Resolve each datagram independently. This new 400ms lookup cutoff includes
/// both proc acquisition and the complete native dump; it is not the socket's
/// existing 400ms receive interval and is never renewed by a receive wake.
fn resolve_orig_dst_fresh(
    peer: SocketAddr,
    now: Instant,
    stop: &AtomicBool,
    owner: &mut udp_conntrack_lookup::Resolver,
) -> Option<SocketAddr> {
    let control = udp_conntrack_lookup::Control::new(stop);
    owner.resolve(peer, now, &control, conntrack_original_dst_v4)
}

/// Emit the once-per-flow `WideUdpFlowObserved` event (per-datagram send/receive
/// transport selection is emitted by `relay::run_relay_udp_flow`).
fn emit_flow_observed(key: &FlowKey, first_payload_len: usize) {
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::WideUdpFlowObserved,
        "wide udp flow observed (redirect proxy, persistent bidirectional)",
        json!({
            "peer": key.peer.to_string(),
            "orig_dst": key.orig_dst.to_string(),
            "first_payload_len": first_payload_len,
            "carry": "policy_ordered_persistent_datagram",
            "no_native_fallback": true,
        }),
    );
}

/// Guard against a self-inflicted loop: never carry a datagram whose recovered
/// original destination is the proxy's own listener.
fn is_self_target(orig_dst: SocketAddr, listen_addr: SocketAddr) -> bool {
    orig_dst.port() == listen_addr.port() && orig_dst.ip().is_loopback()
}

fn emit_session_created(key: &FlowKey) {
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::WideUdpSessionCreated,
        "wide udp redirect proxy session created (bidirectional carry)",
        json!({
            "peer": key.peer.to_string(),
            "orig_dst": key.orig_dst.to_string(),
            "carry": "policy_ordered_bidirectional_datagram",
            "transport_evidence": "relay_transport_selected",
        }),
    );
}

fn emit_flow_closed(key: &FlowKey, reason: &str) {
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::WideUdpFlowClosed,
        "wide udp redirect proxy flow closed",
        json!({
            "peer": key.peer.to_string(),
            "orig_dst": key.orig_dst.to_string(),
            "reason": reason,
        }),
    );
}

/// Deliver the relay response back to the app via the **conntrack-reverse**
/// return path: send from the proxy's listener socket (bound to the REDIRECT
/// DNAT target) directly to the app peer. netfilter conntrack recognises this
/// as the reply direction of the captured flow and rewrites the source back to
/// the original destination the app sent to, so the app's (connected) socket
/// accepts it. No `IP_TRANSPARENT` needed — and unlike a transparent reply from
/// the original tuple, this does not fight the DNAT mapping.
///
/// If the send fails the flow stays fail-closed (no native fallback).
fn deliver_response(reply_fd: RawFd, key: &FlowKey, response: &[u8]) {
    let dbg = !runtime_jsonl::private_logs_enabled()
        && std::env::var_os("AEGIS_UDP_PROXY_DEBUG").is_some();
    let SocketAddr::V4(peer) = key.peer else {
        emit_reply_fail_closed(key, "reply_peer_not_ipv4", "ipv6 peer unsupported");
        return;
    };
    match sendto_v4(reply_fd, peer, response) {
        Ok(_) => {
            if dbg {
                eprintln!(
                    "[udp-proxy-debug] reply DELIVERED (conntrack-reverse) orig_dst={} -> peer={} len={}",
                    key.orig_dst,
                    key.peer,
                    response.len()
                );
            }
            runtime_jsonl::emit(
                "info",
                RuntimeEventCode::WideUdpResponseDelivered,
                "wide udp response delivered to local app (bidirectional)",
                json!({
                    "peer": key.peer.to_string(),
                    "orig_dst": key.orig_dst.to_string(),
                    "response_len": response.len(),
                    "delivered_to_app": true,
                    "return_path": "conntrack_reverse_from_redirect_target",
                }),
            );
        }
        Err(e) => {
            if dbg {
                eprintln!("[udp-proxy-debug] reply SEND failed: {e}");
            }
            emit_reply_fail_closed(key, "conntrack_reverse_reply_send_failed", &e.to_string());
        }
    }
}

/// Send `data` to `peer` from `fd` (the listener socket bound to the REDIRECT
/// target). Source stays the DNAT target so conntrack reverse-NATs it.
fn sendto_v4(fd: RawFd, peer: SocketAddrV4, data: &[u8]) -> std::io::Result<usize> {
    let mut sa: libc::sockaddr_in = unsafe { zeroed() };
    sa.sin_family = libc::AF_INET as libc::sa_family_t;
    sa.sin_port = peer.port().to_be();
    sa.sin_addr.s_addr = u32::from(*peer.ip()).to_be();
    let n = unsafe {
        libc::sendto(
            fd,
            data.as_ptr() as *const libc::c_void,
            data.len(),
            0,
            &sa as *const libc::sockaddr_in as *const libc::sockaddr,
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

fn emit_reply_fail_closed(key: &FlowKey, reason: &str, error: &str) {
    runtime_jsonl::emit(
        "warn",
        RuntimeEventCode::WideUdpFailClosed,
        "wide udp response could not be delivered (stays fail-closed)",
        json!({
            "peer": key.peer.to_string(),
            "orig_dst": key.orig_dst.to_string(),
            "reason": reason,
            "error": error,
            "no_native_fallback": true,
        }),
    );
}

/// Run the bidirectional UDP redirect proxy until `stop` is set. Blocking entry
/// point (owns its own multi-thread Tokio runtime); intended to run on its own
/// thread alongside the REDIRECT TCP backend, like the NFQUEUE lifecycle.
pub fn run_udp_redirect_proxy(
    cfg: UdpRedirectProxyConfig,
    stop: Arc<AtomicBool>,
) -> std::io::Result<()> {
    run_udp_redirect_proxy_with_ready(cfg, stop, None)
}

pub(crate) fn run_udp_redirect_proxy_with_ready(
    cfg: UdpRedirectProxyConfig,
    stop: Arc<AtomicBool>,
    ready: Option<crate::wide_workers::WorkerReady>,
) -> std::io::Result<()> {
    run_udp_redirect_proxy_with_receiver(cfg, stop, ready, recv_redirected_datagram_v4)
}

fn run_udp_redirect_proxy_with_receiver(
    cfg: UdpRedirectProxyConfig,
    stop: Arc<AtomicBool>,
    ready: Option<crate::wide_workers::WorkerReady>,
    receive: impl Fn(&StdUdpSocket, usize) -> std::io::Result<CapturedDatagram>,
) -> std::io::Result<()> {
    // Declare the socket BEFORE its runtime: reverse local drop order then
    // cancels/joins every reply task before closing the fd they borrow, even on
    // fatal receive errors or an unwinding panic.
    let socket = Arc::new(bind_capture_socket_v4(cfg.listen_addr)?);
    socket.set_read_timeout(Some(Duration::from_millis(400)))?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let settings = Arc::new(cfg.settings);
    let fake_ip_map = cfg.fake_ip_map;
    let mut sessions: HashMap<FlowKey, ProxyUdpFlow> = HashMap::new();
    // Destination ownership is fresh for every captured datagram.
    let mut destination_lookup = udp_conntrack_lookup::Resolver::default();
    let listen_addr = cfg.listen_addr;
    // The reply is sent from this same listener socket so conntrack reverse-NATs
    // the source back to the original destination (see `deliver_response`).

    if let Some(ready) = ready {
        ready.signal()?;
    }

    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::WideUdpSessionCreated,
        "wide udp redirect proxy started (bidirectional generic UDP carry)",
        json!({
            "listen_addr": listen_addr.to_string(),
            "carry": "policy_ordered_bidirectional_datagram",
            "transport_evidence": "relay_transport_selected",
            "idle_timeout_secs": cfg.idle_timeout.as_secs(),
            "event": "backend_started",
        }),
    );

    while !stop.load(Ordering::SeqCst) {
        let now = Instant::now();
        for (key, reason) in sweep_finished(&mut sessions, now, cfg.idle_timeout) {
            emit_flow_closed(&key, reason);
        }
        match receive(&socket, cfg.max_datagram) {
            Ok(d) => {
                if cfg
                    .forward_gate
                    .as_ref()
                    .is_some_and(|gate| !gate.is_open())
                {
                    sessions.clear();
                    continue;
                }
                // REDIRECT/DNAT hands us the post-NAT loopback dst in the cmsg;
                // recover the real pre-NAT destination from conntrack. If that
                // fails we cannot know the target, so fail-closed (drop) — never
                // native.
                let orig_dst = if is_self_target(d.orig_dst, listen_addr) {
                    match resolve_orig_dst_fresh(d.peer, now, &stop, &mut destination_lookup) {
                        Some(real) => real,
                        None => {
                            emit_reply_fail_closed(
                                &FlowKey {
                                    peer: d.peer,
                                    orig_dst: d.orig_dst,
                                },
                                "conntrack_original_dst_not_found",
                                "original destination lookup absent or refused",
                            );
                            continue;
                        }
                    }
                } else {
                    d.orig_dst
                };
                if !runtime_jsonl::private_logs_enabled()
                    && std::env::var_os("AEGIS_UDP_PROXY_DEBUG").is_some()
                {
                    eprintln!(
                        "[udp-proxy-debug] captured peer={} cmsg_dst={} resolved_dst={} len={}",
                        d.peer,
                        d.orig_dst,
                        orig_dst,
                        d.payload.len()
                    );
                }
                let key = FlowKey {
                    peer: d.peer,
                    orig_dst,
                };
                // Closed queues retry after cooldown even under continuous traffic.
                // Full, live queues retain ordinary UDP backpressure/drop semantics.
                let payload =
                    match send_to_existing_flow(&mut sessions, &key, d.payload, Instant::now()) {
                        ExistingFlowSend::Queued
                        | ExistingFlowSend::QueueFull
                        | ExistingFlowSend::RetryCooldown => continue,
                        ExistingFlowSend::Missing(payload) => payload,
                        ExistingFlowSend::Closed(payload) => {
                            emit_flow_closed(&key, "relay_session_closed");
                            payload
                        }
                    };
                // New flow: at the concurrency cap -> drop (fail-closed), never
                // native. This bounds fd/port/memory against a datagram flood.
                if sessions.len() >= cfg.max_flows {
                    emit_reply_fail_closed(
                        &key,
                        "max_flows_saturated",
                        "concurrent MASQUE flow cap reached",
                    );
                    continue;
                }
                let (target, mapping_lease) =
                    match lease_relay_target_for_flow(&key, fake_ip_map.as_deref()) {
                        Ok(target) => target,
                        Err(error) => {
                            emit_reply_fail_closed(
                                &key,
                                "fake_ip_mapping_missing",
                                &error.to_string(),
                            );
                            continue;
                        }
                    };
                emit_session_created(&key);
                emit_flow_observed(&key, payload.len());
                // ONE persistent relay session per flow (real multi-datagram
                // carry incl. QUIC/443, not one connection per datagram).
                // Policy prefers MASQUE and falls back to fronted gRPC/H2.
                let (out_tx, out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
                let (in_tx, mut in_rx) =
                    tokio::sync::mpsc::channel::<crate::socks5::UdpPacket>(256);
                let reply_lease = mapping_lease.clone();
                // The reply task owns its socket, not merely a reusable fd
                // number. Fatal capture errors cannot invalidate this handle.
                let reply_socket = Arc::clone(&socket);
                let reply_gate = cfg.forward_gate.clone();
                let packet_gate = reply_gate.clone();
                rt.spawn(async move {
                    let _ = super::forward_gate::run_optional(reply_gate.as_ref(), async move {
                        // A reaped flow may still have queued replies. Keep the IP
                        // meaning pinned until their forwarder has drained too.
                        let _mapping_lease = reply_lease;
                        while let Some(pkt) = in_rx.recv().await {
                            if packet_gate.as_ref().is_some_and(|gate| !gate.is_open()) {
                                break;
                            }
                            deliver_response(reply_socket.as_raw_fd(), &key, &pkt.payload);
                        }
                    })
                    .await;
                });
                let host = target.host;
                let port = target.port;
                let flow_settings = settings.clone();
                let relay_lease = mapping_lease.clone();
                let relay_gate = cfg.forward_gate.clone();
                rt.spawn(async move {
                    let _mapping_lease = relay_lease;
                    let _ = super::forward_gate::run_optional(relay_gate.as_ref(), async move {
                        // Dropping out_rx on completion lets the capture loop reap
                        // this session. There is still no native egress path.
                        let _ = crate::relay::run_relay_udp_flow(
                            &flow_settings,
                            &host,
                            port,
                            out_rx,
                            in_tx,
                        )
                        .await;
                    })
                    .await;
                });
                let _ = out_tx.try_send(payload);
                sessions.insert(
                    key,
                    ProxyUdpFlow::new(out_tx, Instant::now()).with_mapping_lease(mapping_lease),
                );
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                        | std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::ConnectionReset
                ) =>
            {
                continue;
            }
            Err(e) => {
                runtime_jsonl::emit(
                    "warn",
                    RuntimeEventCode::WideNfqueueBackendError,
                    "wide udp redirect proxy recv error",
                    json!({ "error": e.to_string() }),
                );
                // A dead/invalid capture descriptor cannot keep the service
                // nominally healthy or spin indefinitely. The supervisor exits
                // the client; persistent firewall policy survives that exit.
                return Err(e);
            }
        }
    }

    // Drain: emit a close for every still-open flow so the artifact shows clean
    // teardown with no leaked session state.
    for key in sessions.keys() {
        emit_flow_closed(key, "proxy_shutdown");
    }
    let _ = &sessions; // sessions dropped here
    drop(rt);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fatal_capture_read_error_reaches_supervisor_after_readiness() {
        let cfg =
            UdpRedirectProxyConfig::new("127.0.0.1:0".parse().unwrap(), RelaySettings::default());
        let mut workers = crate::wide_workers::WideWorkers::new();
        let (tx, rx) = tokio::sync::oneshot::channel();
        workers
            .start("udp-fatal", Duration::from_secs(2), move |stop, ready| {
                let error = run_udp_redirect_proxy_with_receiver(cfg, stop, Some(ready), |_, _| {
                    Err(std::io::Error::from_raw_os_error(libc::EBADF))
                })
                .unwrap_err();
                tx.send(error.raw_os_error()).unwrap();
            })
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), workers.failure())
                .await
                .unwrap(),
            "udp-fatal"
        );
        assert_eq!(rx.await.unwrap(), Some(libc::EBADF));
    }

    #[tokio::test]
    async fn capture_readiness_refuses_an_already_bound_udp_port() {
        let occupied = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        let cfg =
            UdpRedirectProxyConfig::new(occupied.local_addr().unwrap(), RelaySettings::default());
        let mut workers = crate::wide_workers::WideWorkers::new();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let startup = workers
            .start("udp-capture", Duration::from_secs(2), move |stop, ready| {
                let error = run_udp_redirect_proxy_with_ready(cfg, stop, Some(ready)).unwrap_err();
                tx.send(error.kind()).unwrap();
            })
            .await;
        assert!(startup.is_err(), "occupied listener cannot report ready");
        assert_eq!(rx.await.unwrap(), std::io::ErrorKind::AddrInUse);
    }

    #[tokio::test]
    async fn ready_capture_owns_its_port_until_supervisor_cleanup() {
        let probe = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        let cfg = UdpRedirectProxyConfig::new(addr, RelaySettings::default());
        let mut workers = crate::wide_workers::WideWorkers::new();
        let (tx, rx) = tokio::sync::oneshot::channel();
        workers
            .start("udp-capture", Duration::from_secs(2), move |stop, ready| {
                tx.send(run_udp_redirect_proxy_with_ready(cfg, stop, Some(ready)))
                    .unwrap();
            })
            .await
            .unwrap();
        assert_eq!(
            bind_capture_socket_v4(addr).unwrap_err().kind(),
            std::io::ErrorKind::AddrInUse
        );
        drop(workers);
        tokio::time::timeout(Duration::from_secs(2), rx)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let _new_owner = bind_capture_socket_v4(addr).unwrap();
    }

    #[test]
    fn live_udp_tuple_pins_mapping_and_reuse_waits_for_flow_and_reply_owners() {
        let map =
            super::super::dns_preview::FakeIpMap::new("198.19.255.252/30", Duration::from_secs(60))
                .unwrap();
        let (ip, _) = map.assign("old-flow.test").unwrap();
        let key = FlowKey {
            peer: "127.0.0.1:43111".parse().unwrap(),
            orig_dst: SocketAddr::from((ip, 443)),
        };
        let (target, lease) = lease_relay_target_for_flow(&key, Some(&map)).unwrap();
        assert_eq!(target.host, "old-flow.test");
        let pending_reply_lease = lease.clone();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let mut sessions = HashMap::from([(
            key,
            ProxyUdpFlow::new(tx, Instant::now()).with_mapping_lease(lease),
        )]);
        map.expire_mapping_for_test(ip);
        assert!(map.assign("different-host.test").is_none());
        assert_eq!(
            send_to_existing_flow(&mut sessions, &key, b"same tuple".to_vec(), Instant::now()),
            ExistingFlowSend::Queued
        );
        assert_eq!(rx.try_recv().unwrap(), b"same tuple");
        assert_eq!(
            map.lookup_hostname(ip).as_deref(),
            Some(target.host.as_str())
        );
        sessions.remove(&key);
        map.expire_mapping_for_test(ip);
        assert!(
            map.assign("different-host.test").is_none(),
            "old replies still carry the original IP meaning"
        );
        drop(pending_reply_lease);
        assert!(
            map.assign("different-host.test").is_none(),
            "the last owner's end restarts the binding's idle time"
        );
        map.expire_mapping_for_test(ip);
        assert_eq!(
            lease_relay_target_for_flow(&key, Some(&map))
                .unwrap()
                .0
                .host,
            "old-flow.test",
            "an idle numeric synthetic target resolves only to its own name"
        );
        map.expire_mapping_for_test(ip);
        assert_eq!(map.assign("different-host.test").unwrap().0, ip);
        assert_eq!(
            lease_relay_target_for_flow(&key, Some(&map))
                .unwrap()
                .0
                .host,
            "different-host.test"
        );
        assert_eq!(
            key.orig_dst,
            SocketAddr::from((ip, 443)),
            "original tuple never changes"
        );
    }

    #[test]
    fn udp_target_recovery_preserves_original_tuple_and_fails_closed_without_owner() {
        let map =
            super::super::dns_preview::FakeIpMap::new("198.18.0.0/24", Duration::from_secs(60))
                .unwrap();
        let (ip, _) = map.assign("udp.example.test").unwrap();
        let key = FlowKey {
            peer: "127.0.0.1:12345".parse().unwrap(),
            orig_dst: SocketAddr::from((ip, 443)),
        };
        let original = key;
        let target = relay_target_for_flow(&key, Some(&map)).unwrap();
        assert_eq!(target.host, "udp.example.test");
        assert_eq!(target.port, 443);
        assert_eq!(
            key, original,
            "response tuple is not rewritten to a logical name"
        );
        assert_eq!(
            relay_target_for_flow(&key, None).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        let unknown = FlowKey {
            orig_dst: "198.18.0.99:443".parse().unwrap(),
            ..key
        };
        assert!(relay_target_for_flow(&unknown, Some(&map)).is_err());
        let numeric = FlowKey {
            orig_dst: "127.0.0.2:443".parse().unwrap(),
            ..key
        };
        assert_eq!(
            relay_target_for_flow(&numeric, None).unwrap().host,
            "127.0.0.2"
        );
    }

    #[tokio::test]
    async fn real_dns_answer_and_udp_target_share_the_same_mapping() {
        use super::super::dns_preview::spawn_dns_preview;
        let wide = aegis_core::WideIngressSettings {
            dns_preview_listen: Some("127.0.0.1:0".parse().unwrap()),
            ..Default::default()
        };
        let listener = spawn_dns_preview(&wide, None).await.unwrap().unwrap();
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let query = [
            0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, b'u', b'd', b'p', 4, b't', b'e', b's', b't', 0,
            0, 1, 0, 1,
        ];
        socket.send_to(&query, listener.listen).await.unwrap();
        let mut response = [0u8; 512];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut response))
            .await
            .unwrap()
            .unwrap();
        let fake = Ipv4Addr::new(
            response[n - 4],
            response[n - 3],
            response[n - 2],
            response[n - 1],
        );
        let key = FlowKey {
            peer: socket.local_addr().unwrap(),
            orig_dst: SocketAddr::from((fake, 443)),
        };
        assert_eq!(
            relay_target_for_flow(&key, Some(&listener.map))
                .unwrap()
                .host,
            "udp.test"
        );
        assert_eq!(key.orig_dst.ip(), std::net::IpAddr::V4(fake));
        listener.shutdown().await;
    }
    use std::net::IpAddr;

    /// Build a synthetic `IP_ORIGDSTADDR` control buffer exactly as the kernel
    /// would lay it out, so the parser can be tested without a real socket.
    fn build_origdst_control_v4(dst: SocketAddrV4) -> Vec<u8> {
        ancillary::tests::control_v4(dst, libc::SOL_IP, IP_ORIGDSTADDR)
    }

    #[test]
    fn parse_origdst_v4_round_trips() {
        let dst = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 4433);
        let control = build_origdst_control_v4(dst);
        let parsed = parse_origdst_v4(&control).expect("parse origdst");
        assert_eq!(parsed, dst);
    }

    #[test]
    fn parse_origdst_v4_missing_is_error() {
        // No control messages at all (REDIRECT/IP_RECVORIGDSTADDR not active) ->
        // the walk finds nothing and reports NotFound rather than a leak.
        let err = parse_origdst_v4(&[]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn parse_origdst_v4_truncated_is_error() {
        let dst = SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 1), 53);
        let control = build_origdst_control_v4(dst);
        // Cut the buffer so the cmsg header claims more than is present.
        let truncated = &control[..size_of::<libc::cmsghdr>() + 2];
        assert!(parse_origdst_v4(truncated).is_err());
    }

    #[test]
    fn sweep_finished_reaps_only_expired_live_flows() {
        let mut sessions: HashMap<FlowKey, ProxyUdpFlow> = HashMap::new();
        let now = Instant::now();
        let mk = |at: Instant| {
            let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
            (ProxyUdpFlow::new(tx, at), rx)
        };
        let fresh = FlowKey {
            peer: "127.0.0.1:5000".parse().unwrap(),
            orig_dst: "203.0.113.1:443".parse().unwrap(),
        };
        let stale = FlowKey {
            peer: "127.0.0.1:5001".parse().unwrap(),
            orig_dst: "203.0.113.2:443".parse().unwrap(),
        };
        let (fresh_flow, _fresh_rx) = mk(now);
        let (stale_flow, _stale_rx) = mk(now - Duration::from_secs(60));
        sessions.insert(fresh, fresh_flow);
        sessions.insert(stale, stale_flow);
        let expired = sweep_finished(&mut sessions, now, Duration::from_secs(30));
        assert_eq!(expired, vec![(stale, "idle_timeout")]);
        assert!(sessions.contains_key(&fresh));
        assert!(!sessions.contains_key(&stale));
    }

    fn sample_flow_key() -> FlowKey {
        FlowKey {
            peer: "127.0.0.1:5000".parse().unwrap(),
            orig_dst: "203.0.113.1:443".parse().unwrap(),
        }
    }

    #[test]
    fn closed_flow_reopens_under_continuous_datagrams_without_idle_pause() {
        let key = sample_flow_key();
        let now = Instant::now();
        let idle = Duration::from_secs(30);
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let mut sessions = HashMap::from([(key, ProxyUdpFlow::new(tx, now))]);

        for index in 0..4 {
            let at = now + UDP_FLOW_RECONNECT_COOLDOWN * (index + 1);
            // Model the relay task ending after the capture loop's sweep.
            assert!(sweep_finished(&mut sessions, at, idle).is_empty());
            drop(rx);
            let payload = vec![index as u8; 16];
            assert_eq!(
                send_to_existing_flow(&mut sessions, &key, payload.clone(), at),
                ExistingFlowSend::Closed(payload.clone())
            );
            assert!(!sessions.contains_key(&key));

            // After the bounded cooldown the caller can open a replacement
            // using this datagram, without a 30-second pause from the app.
            let (next_tx, next_rx) = tokio::sync::mpsc::channel(1);
            rx = next_rx;
            sessions.insert(key, ProxyUdpFlow::new(next_tx, at));
            assert_eq!(
                send_to_existing_flow(&mut sessions, &key, payload.clone(), at),
                ExistingFlowSend::Queued
            );
            assert_eq!(rx.try_recv().unwrap(), payload);
        }
    }

    #[test]
    fn full_live_queue_drops_burst_without_reopening_session() {
        let key = sample_flow_key();
        let now = Instant::now();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let original_tx = tx.clone();
        let mut sessions = HashMap::from([(key, ProxyUdpFlow::new(tx, now))]);
        assert_eq!(
            send_to_existing_flow(&mut sessions, &key, vec![1], now),
            ExistingFlowSend::Queued
        );
        for index in 1..64 {
            let at = now + Duration::from_secs(index);
            assert_eq!(
                send_to_existing_flow(&mut sessions, &key, vec![2], at),
                ExistingFlowSend::QueueFull
            );
            assert!(sweep_finished(&mut sessions, at, Duration::from_secs(30)).is_empty());
            assert!(sessions[&key].outbound_tx.same_channel(&original_tx));
        }
        assert_eq!(sessions.len(), 1);
        assert_eq!(rx.try_recv().unwrap(), vec![1]);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn fast_failures_bound_burst_retries_then_recover_with_continuous_packets() {
        let key = sample_flow_key();
        let now = Instant::now();
        let idle = Duration::from_secs(30);
        let mut sessions = HashMap::new();
        let mut opened_at = Vec::new();
        let mut recovered_rx = None;

        // 100 datagrams/second, with the first three session receivers ending
        // immediately. The fourth stays alive; no idle gap precedes recovery.
        for tick in 0..=310 {
            let at = now + Duration::from_millis(tick * 10);
            let _ = sweep_finished(&mut sessions, at, idle);
            let payload = vec![(tick % 256) as u8];
            match send_to_existing_flow(&mut sessions, &key, payload.clone(), at) {
                ExistingFlowSend::Missing(first) | ExistingFlowSend::Closed(first) => {
                    opened_at.push(at);
                    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
                    tx.try_send(first.clone()).unwrap();
                    sessions.insert(key, ProxyUdpFlow::new(tx, at));
                    if opened_at.len() <= 3 {
                        drop(rx);
                    } else {
                        assert_eq!(rx.try_recv().unwrap(), first);
                        recovered_rx = Some(rx);
                    }
                }
                ExistingFlowSend::RetryCooldown => {
                    assert!(recovered_rx.is_none());
                    let last_open = *opened_at.last().unwrap();
                    assert_eq!(sessions[&key].last_active, last_open);
                    assert_eq!(
                        sessions[&key].next_open_at,
                        last_open + UDP_FLOW_RECONNECT_COOLDOWN
                    );
                }
                ExistingFlowSend::Queued => {
                    assert_eq!(recovered_rx.as_mut().unwrap().try_recv().unwrap(), payload);
                }
                ExistingFlowSend::QueueFull => panic!("healthy receiver drains every datagram"),
            }
        }
        assert_eq!(opened_at.len(), 4);
        for (index, at) in opened_at.iter().enumerate() {
            assert_eq!(*at, now + UDP_FLOW_RECONNECT_COOLDOWN * index as u32);
        }
        assert!(recovered_rx.is_some());
    }

    #[test]
    fn receiver_closing_after_sweep_cannot_bypass_or_extend_cooldown() {
        let key = sample_flow_key();
        let now = Instant::now();
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let mut sessions = HashMap::from([(key, ProxyUdpFlow::new(tx, now))]);
        assert!(sweep_finished(&mut sessions, now, Duration::from_secs(30)).is_empty());
        drop(rx);
        assert_eq!(
            send_to_existing_flow(&mut sessions, &key, vec![1], now),
            ExistingFlowSend::RetryCooldown
        );
        let before_retry = now + UDP_FLOW_RECONNECT_COOLDOWN - Duration::from_nanos(1);
        // Even a shorter idle policy must not reap a closed cooling-down entry.
        assert!(sweep_finished(&mut sessions, before_retry, Duration::ZERO).is_empty());
        assert_eq!(
            send_to_existing_flow(&mut sessions, &key, vec![2], before_retry),
            ExistingFlowSend::RetryCooldown
        );
        assert_eq!(sessions[&key].last_active, now);
        assert_eq!(
            send_to_existing_flow(
                &mut sessions,
                &key,
                vec![3],
                now + UDP_FLOW_RECONNECT_COOLDOWN
            ),
            ExistingFlowSend::Closed(vec![3])
        );
        assert!(sessions.is_empty());
    }

    #[test]
    fn sweep_finished_reaps_ended_session_without_waiting_for_idle() {
        let key = sample_flow_key();
        let now = Instant::now();
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let mut sessions = HashMap::from([(key, ProxyUdpFlow::new(tx, now))]);
        drop(rx);
        assert!(sweep_finished(&mut sessions, now, Duration::from_secs(30)).is_empty());
        assert_eq!(
            sweep_finished(
                &mut sessions,
                now + UDP_FLOW_RECONNECT_COOLDOWN,
                Duration::from_secs(30)
            ),
            vec![(key, "relay_session_closed")]
        );
        assert!(sessions.is_empty());
    }

    #[test]
    fn old_task_completion_cannot_reap_replacement_flow() {
        let key = sample_flow_key();
        let now = Instant::now();
        let (old_tx, old_rx) = tokio::sync::mpsc::channel(1);
        let mut sessions = HashMap::from([(
            key,
            ProxyUdpFlow::new(old_tx, now - Duration::from_secs(60)),
        )]);
        assert_eq!(
            sweep_finished(&mut sessions, now, Duration::from_secs(30)),
            vec![(key, "idle_timeout")]
        );
        let (new_tx, mut new_rx) = tokio::sync::mpsc::channel(1);
        sessions.insert(key, ProxyUdpFlow::new(new_tx, now));

        // The old task can finish after a new task for this tuple has started.
        // Reaping consults only the current sender, not a stale key callback.
        drop(old_rx);
        assert!(sweep_finished(&mut sessions, now, Duration::from_secs(30)).is_empty());
        assert_eq!(
            send_to_existing_flow(&mut sessions, &key, vec![3], now),
            ExistingFlowSend::Queued
        );
        assert_eq!(new_rx.try_recv().unwrap(), vec![3]);
    }

    #[test]
    fn conntrack_fresh_lookup_never_reuses_peer_destination() {
        let peer: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let first = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 443);
        let second = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 10), 443);
        let now = Instant::now();
        let stop = AtomicBool::new(false);
        let control = udp_conntrack_lookup::Control::new(&stop);
        let mut owner = udp_conntrack_lookup::Resolver::default();
        let mut calls = 0;
        assert_eq!(
            owner.resolve(peer, now, &control, |_, _| {
                calls += 1;
                Some(first)
            }),
            Some(SocketAddr::V4(first))
        );
        assert_eq!(
            owner.resolve(peer, now, &control, |_, _| {
                calls += 1;
                Some(second)
            }),
            Some(SocketAddr::V4(second))
        );
        assert_eq!(calls, 2);
    }

    #[test]
    fn is_self_target_detects_loopback_listener_loop() {
        let listen: SocketAddr = "127.0.0.1:8472".parse().unwrap();
        assert!(is_self_target("127.0.0.1:8472".parse().unwrap(), listen));
        // A real destination on the same port but non-loopback is NOT a loop.
        assert!(!is_self_target("203.0.113.5:8472".parse().unwrap(), listen));
        // Loopback but different port is not our listener.
        assert!(!is_self_target("127.0.0.1:9999".parse().unwrap(), listen));
    }

    #[test]
    fn proxy_binds_and_stops_cleanly() {
        // No root / REDIRECT rule needed: bind the loopback listener on an
        // ephemeral port, let the loop spin once on the recv timeout, then stop.
        // Proves the runner binds, polls the stop flag, and tears down without
        // leaking the runtime — even with no traffic and no MASQUE carry.
        use std::net::SocketAddr;
        let socket = StdUdpSocket::bind("127.0.0.1:0").expect("probe bind");
        let port = socket.local_addr().unwrap().port();
        drop(socket);
        let listen: SocketAddr = SocketAddr::from(([127, 0, 0, 1], port));
        let cfg = UdpRedirectProxyConfig::new(listen, RelaySettings::default());
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = stop.clone();
        let handle = std::thread::spawn(move || run_udp_redirect_proxy(cfg, stop_for_thread));
        std::thread::sleep(Duration::from_millis(120));
        stop.store(true, Ordering::SeqCst);
        handle
            .join()
            .expect("proxy thread joins")
            .expect("proxy stops Ok");
    }

    #[test]
    fn conntrack_parse_recovers_original_dst_for_redirected_udp() {
        // Real-shaped /proc/net/nf_conntrack row for a REDIRECT'd UDP flow:
        // ORIGINAL tuple keeps the pre-NAT dst (10.200.0.2:34567); the reply
        // tuple shows the DNAT to the loopback proxy (127.0.0.1:15090).
        let table = "\
ipv4 2 tcp 6 100 ESTABLISHED src=1.2.3.4 dst=5.6.7.8 sport=1 dport=2 src=5.6.7.8 dst=1.2.3.4 sport=2 dport=1 mark=0 use=1
ipv4 2 udp 17 29 src=10.200.0.1 dst=10.200.0.2 sport=59642 dport=34567 [UNREPLIED] src=127.0.0.1 dst=10.200.0.1 sport=15090 dport=59642 mark=0 use=1
";
        let peer = "10.200.0.1:59642".parse().unwrap();
        let got = parse_conntrack_original_dst_v4(table, peer).expect("resolve");
        assert_eq!(got, "10.200.0.2:34567".parse::<SocketAddrV4>().unwrap());
        // A peer with no row resolves to None (caller fail-closes).
        assert!(parse_conntrack_original_dst_v4(table, "10.0.0.9:1234".parse().unwrap()).is_none());
    }

    fn nla(atype: u16, payload: &[u8]) -> Vec<u8> {
        let len = 4 + payload.len();
        let mut v = Vec::new();
        v.extend_from_slice(&(len as u16).to_ne_bytes());
        v.extend_from_slice(&atype.to_ne_bytes());
        v.extend_from_slice(payload);
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v
    }

    #[test]
    fn ctnetlink_attrs_recover_original_dst() {
        const NESTED: u16 = 0x8000;
        let src = Ipv4Addr::new(10, 200, 0, 1);
        let dst = Ipv4Addr::new(10, 200, 0, 2);
        let (sport, dport) = (59642u16, 34567u16);

        let mut ip_inner = nla(CTA_IP_V4_SRC, &src.octets());
        ip_inner.extend(nla(CTA_IP_V4_DST, &dst.octets()));
        let ip_nest = nla(CTA_TUPLE_IP | NESTED, &ip_inner);

        let mut proto_inner = nla(1 /*CTA_PROTO_NUM*/, &[17u8]);
        proto_inner.extend(nla(CTA_PROTO_SRC_PORT, &sport.to_be_bytes()));
        proto_inner.extend(nla(CTA_PROTO_DST_PORT, &dport.to_be_bytes()));
        let proto_nest = nla(CTA_TUPLE_PROTO | NESTED, &proto_inner);

        let mut orig_inner = ip_nest;
        orig_inner.extend(proto_nest);
        let attrs = nla(CTA_TUPLE_ORIG | NESTED, &orig_inner);

        let got =
            orig_dst_from_attrs(&attrs, "10.200.0.1:59642".parse().unwrap()).expect("resolve");
        assert_eq!(got, SocketAddrV4::new(dst, dport));
        // Non-matching source -> None.
        assert!(orig_dst_from_attrs(&attrs, "10.200.0.9:1111".parse().unwrap()).is_none());
    }

    #[test]
    fn flow_key_distinguishes_by_peer_and_dst() {
        let a = FlowKey {
            peer: "127.0.0.1:5000".parse().unwrap(),
            orig_dst: "203.0.113.1:443".parse().unwrap(),
        };
        let b = FlowKey {
            peer: "127.0.0.1:5000".parse().unwrap(),
            orig_dst: "203.0.113.2:443".parse().unwrap(),
        };
        assert_ne!(a, b);
        let mut m = HashMap::new();
        m.insert(a, 1);
        m.insert(b, 2);
        assert_eq!(m.len(), 2);
        assert!(matches!(a.peer.ip(), IpAddr::V4(_)));
    }
}
