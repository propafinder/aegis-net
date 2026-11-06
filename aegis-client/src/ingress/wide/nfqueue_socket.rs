//! NFQUEUE socket runtime (Linux): the nfnetlink consumer that drives the
//! observer backend. Opens a `NETLINK_NETFILTER` socket, binds a queue,
//! receives diverted packets, decodes the IPv4/IPv6 TCP 5-tuple, emits a
//! witness runtime event, and ACCEPTs every packet back to the kernel.
//!
//! Observer semantics: this NEVER terminates a connection. Every packet is
//! ACCEPTed, so connectivity is preserved whether or not decoding succeeds —
//! the queue is a passive witness tap. The divert rules (nft/iptables) that
//! feed the queue are installed/removed by the wide setup helper, not here.
//!
//! The per-message logic ([`handle_message`]) is split out as a pure function
//! so it is unit-tested without root: feed it a synthetic NFQNL_MSG_PACKET,
//! assert the decoded flow and the ACCEPT verdict bytes. The socket I/O
//! ([`NfqueueObserver`]) is the only part that needs root + a live kernel.

#![cfg(target_os = "linux")]
// This consumer IS wired into the runtime: the full-wide-nfqueue product mode
// reaches it via `aegis-client --nfqueue-observe <q> --nfqueue-enforce ...`
// (run_nfqueue_observer -> nfqueue_lifecycle -> NfqueueObserver::run). The
// module-level allow now covers only a few intentionally-retained surface items
// (the `bind` back-compat wrapper, a couple of UAPI constants) kept for API
// symmetry and ABI tests, rather than churn-annotating each.
#![allow(dead_code)]

use super::linux_nfqueue::{decode_packet, udp_payload, DecodedPacket};
use super::nfqueue_proto as proto;
use super::udp_masque_bridge::WideUdpMasqueBridge;
use crate::runtime_events::RuntimeEventCode;
use crate::runtime_jsonl;
use serde_json::json;
use std::io;

/// How the NFQUEUE consumer decides verdicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfqueueMode {
    /// Pure witness: decode + emit, ACCEPT every packet (the `--nfqueue-observe`
    /// validation path; never terminates a connection).
    ObserveOnly,
    /// Fail-closed policy enforcement (full-wide-nfqueue): DROP the classes the
    /// resolved product policy blocks; an undecodable packet is also DROPped so
    /// nothing leaks unparsed.
    Enforce,
}

/// Per-class verdict policy for the NFQUEUE backend. TCP IPv4 is always ACCEPTed
/// (carried out-of-band by the REDIRECT relay); this layer fail-closes the
/// classes REDIRECT cannot safely carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NfqueuePolicy {
    pub mode: NfqueueMode,
    /// DROP generic (non-DNS) UDP (udp_policy = block / masque_direct / preview).
    pub udp_block: bool,
    /// DROP DNS UDP/53 (dns_policy = block).
    pub dns_block: bool,
    /// DROP every IPv6 packet — TCP or UDP (ipv6_policy = block, or = capture
    /// fail-closed when no IPv6-capable relay target exists).
    pub ipv6_block: bool,
}

impl NfqueuePolicy {
    /// Witness-only: ACCEPT everything (back-compat with the observer path).
    pub fn observe_only() -> Self {
        Self {
            mode: NfqueueMode::ObserveOnly,
            udp_block: false,
            dns_block: false,
            ipv6_block: false,
        }
    }

    /// Decide ACCEPT (`true`) vs DROP (`false`) for a decoded packet.
    pub fn accept(&self, pkt: &DecodedPacket) -> bool {
        if self.mode == NfqueueMode::ObserveOnly {
            return true;
        }
        // IPv6 fail-closed first: covers both TCP and UDP over v6.
        if pkt.is_ipv6() && self.ipv6_block {
            return false;
        }
        match pkt {
            // TCP carried out-of-band by REDIRECT; ACCEPT here (belt-and-braces).
            DecodedPacket::Tcp(_) => true,
            DecodedPacket::Udp(u) => {
                if u.is_dns() {
                    !self.dns_block
                } else {
                    !self.udp_block
                }
            }
        }
    }
}

/// NETLINK_NETFILTER protocol number (linux/netlink.h).
const NETLINK_NETFILTER: i32 = 12;
/// Generous receive buffer: an NFQNL_MSG_PACKET with a full copied packet
/// plus attributes fits comfortably; jumbo frames are bounded by copy_range.
const RECV_BUF: usize = 0x1_0000;
/// copy_range for NFQNL_COPY_PACKET — enough to carry L3+L4 headers we decode.
const COPY_RANGE: u32 = 0x1_0000;

/// Outcome of handling one received netlink message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleOutcome {
    /// Decoded packet, if the message was an NFQNL_MSG_PACKET carrying a
    /// decodable IPv4/IPv6 TCP or UDP payload. `None` for non-packet messages
    /// or undecodable payloads.
    pub decoded: Option<DecodedPacket>,
    /// Verdict bytes to send back, or `None` if the message was not an
    /// NFQUEUE packet (nothing to verdict).
    pub verdict: Option<Vec<u8>>,
    /// True when the verdict was DROP (fail-closed enforcement).
    pub dropped: bool,
}

/// Pure per-message handler: parse the netlink message, decode the L3/L4
/// payload, and build the verdict per `policy`. In `ObserveOnly` every packet
/// is ACCEPTed; in `Enforce` blocked classes (and any undecodable payload) are
/// DROPped so nothing leaks unparsed.
pub fn handle_message(
    buf: &[u8],
    queue_num: u16,
    seq: u32,
    policy: &NfqueuePolicy,
) -> HandleOutcome {
    match proto::parse_packet_message(buf) {
        Ok(pkt) => {
            let decoded = decode_packet(pkt.payload).ok();
            let accept = match &decoded {
                Some(p) => policy.accept(p),
                // Undecodable: witness-tap ACCEPTs to preserve connectivity;
                // enforcement fail-closes (DROP) so an unparsed packet never
                // becomes a silent native leak.
                None => policy.mode == NfqueueMode::ObserveOnly,
            };
            let code = if accept {
                proto::NF_ACCEPT
            } else {
                proto::NF_DROP
            };
            let verdict = proto::build_verdict(queue_num, seq, pkt.packet_id, code);
            HandleOutcome {
                decoded,
                verdict: Some(verdict),
                dropped: !accept,
            }
        }
        Err(_) => HandleOutcome {
            decoded: None,
            verdict: None,
            dropped: false,
        },
    }
}

/// Best-effort: return the raw IP packet bytes (`NFQA_PAYLOAD`) carried by a
/// netlink message, for the `masque_direct` send bridge to extract the UDP
/// body. Returns an empty slice on parse failure (the caller's `udp_payload`
/// then yields `None` and the flow stays a plain DROP).
fn nfq_ip_payload(buf: &[u8]) -> &[u8] {
    match proto::parse_packet_message(buf) {
        Ok(pkt) => pkt.payload,
        Err(_) => &[],
    }
}

fn verdict_str(dropped: bool) -> &'static str {
    if dropped {
        "drop"
    } else {
        "accept"
    }
}

/// Emit the per-class witness event (+ an IPv6 event for v6 packets, + a
/// dedicated verdict event on DROP). The class event already carries the
/// verdict, so verdict_emitted is reserved for the security-relevant DROP to
/// bound event volume on high-rate ACCEPT traffic.
fn emit_packet(queue_num: u16, pkt: &DecodedPacket, dropped: bool) {
    let is_v6 = pkt.is_ipv6();
    let base = json!({
        "queue_num": queue_num,
        "ip_version": if is_v6 { 6 } else { 4 },
        "src": pkt.src().to_string(),
        "dst": pkt.dst().to_string(),
        "src_port": pkt.src_port(),
        "dst_port": pkt.dst_port(),
        "verdict": verdict_str(dropped),
    });
    let (code, msg) = match pkt {
        DecodedPacket::Tcp(_) => (
            RuntimeEventCode::WideNfqueueFlowObserved,
            "wide nfqueue tcp flow observed",
        ),
        DecodedPacket::Udp(u) if u.is_dns() => (
            RuntimeEventCode::WideNfqueueDnsObserved,
            "wide nfqueue dns observed",
        ),
        DecodedPacket::Udp(_) => (
            RuntimeEventCode::WideNfqueueUdpObserved,
            "wide nfqueue udp observed",
        ),
    };
    runtime_jsonl::emit("info", code, msg, base.clone());
    if is_v6 {
        runtime_jsonl::emit(
            "info",
            RuntimeEventCode::WideNfqueueIpv6Observed,
            "wide nfqueue ipv6 observed",
            base.clone(),
        );
    }
    if dropped {
        runtime_jsonl::emit(
            "info",
            RuntimeEventCode::WideNfqueueVerdictEmitted,
            "wide nfqueue verdict emitted (drop)",
            base,
        );
    }
}

/// Emit a backend-error event (socket failure). In enforce mode the divert
/// rules drop on no-consumer, so an error never silently opens a leak.
fn emit_backend_error(queue_num: u16, err: &io::Error) {
    runtime_jsonl::emit(
        "warn",
        RuntimeEventCode::WideNfqueueBackendError,
        "wide nfqueue backend error",
        json!({ "queue_num": queue_num, "error": err.to_string() }),
    );
}

/// Emit the backend-started event with the active policy.
fn emit_backend_started(queue_num: u16, policy: &NfqueuePolicy) {
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::WideNfqueueBackendStarted,
        "wide nfqueue backend started",
        json!({
            "queue_num": queue_num,
            "mode": match policy.mode {
                NfqueueMode::ObserveOnly => "observe_only",
                NfqueueMode::Enforce => "enforce",
            },
            "udp_block": policy.udp_block,
            "dns_block": policy.dns_block,
            "ipv6_block": policy.ipv6_block,
        }),
    );
}

/// Live NFQUEUE consumer bound to one queue number, driving verdicts per its
/// [`NfqueuePolicy`].
pub struct NfqueueObserver {
    fd: i32,
    queue_num: u16,
    seq: u32,
    policy: NfqueuePolicy,
    /// Present only when `udp_policy = masque_direct`: a generic UDP packet the
    /// verdict layer DROPs is additionally carried over MASQUE direct (send
    /// leg). DROP still stands — the bridge never causes a native fallback.
    udp_masque_bridge: Option<WideUdpMasqueBridge>,
}

impl NfqueueObserver {
    /// Open + bind + configure the queue in witness-only mode (ACCEPT all).
    /// Back-compat entry point for the `--nfqueue-observe` validation path.
    pub fn bind(queue_num: u16) -> io::Result<Self> {
        Self::bind_with_policy(queue_num, NfqueuePolicy::observe_only())
    }

    /// Open the netlink socket, bind it, and configure the queue:
    /// PF unbind/bind + queue BIND + COPY_PACKET mode, with the given policy.
    /// Requires root.
    pub fn bind_with_policy(queue_num: u16, policy: NfqueuePolicy) -> io::Result<Self> {
        Self::bind_with_policy_and_bridge(queue_num, policy, None)
    }

    /// Same as [`bind_with_policy`], but also attaches the MASQUE direct UDP
    /// send bridge used when `udp_policy = masque_direct`. When `bridge` is
    /// `Some`, generic UDP is still DROPped by the verdict layer (fail-closed)
    /// and *additionally* carried over MASQUE direct (send-only). When `None`,
    /// generic UDP is a plain fail-closed DROP (`udp_policy = block`).
    pub fn bind_with_policy_and_bridge(
        queue_num: u16,
        policy: NfqueuePolicy,
        bridge: Option<WideUdpMasqueBridge>,
    ) -> io::Result<Self> {
        // SAFETY: standard socket(2) with constant args.
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_NETFILTER) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut obs = Self {
            fd,
            queue_num,
            seq: 1,
            policy,
            udp_masque_bridge: bridge,
        };
        // Bound receive timeout so the run loop wakes periodically to check the
        // shutdown flag even when no packets are arriving — without this, a
        // blocking recv() never observes SIGINT/SIGTERM and clean teardown
        // (and the watchdog) cannot run.
        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 400_000,
        };
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }
        if let Err(e) = obs.bind_and_configure() {
            obs.close();
            return Err(e);
        }
        Ok(obs)
    }

    fn bind_and_configure(&mut self) -> io::Result<()> {
        // bind(sockaddr_nl { family=AF_NETLINK, pid=0, groups=0 })
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        let rc = unsafe {
            libc::bind(
                self.fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        // PF (un)bind is per-family on the queue subsystem. Unbind then bind
        // both AF_INET and AF_INET6 so the queue receives v4 and v6 packets.
        let queue = self.queue_num;
        for (cmd, pf) in [
            (proto::NFQNL_CFG_CMD_UNBIND, proto::AF_INET),
            (proto::NFQNL_CFG_CMD_BIND, proto::AF_INET),
            (proto::NFQNL_CFG_CMD_BIND, proto::AF_INET6),
        ] {
            let seq = self.next_seq();
            let msg = proto::build_config_cmd(queue, seq, cmd, pf);
            self.send(&msg)?;
        }
        // Set copy mode so the kernel delivers the packet bytes we decode.
        let seq = self.next_seq();
        let params = proto::build_config_params(queue, seq, proto::NFQNL_COPY_PACKET, COPY_RANGE);
        self.send(&params)?;
        Ok(())
    }

    fn next_seq(&mut self) -> u32 {
        let s = self.seq;
        self.seq = self.seq.wrapping_add(1);
        s
    }

    fn send(&self, msg: &[u8]) -> io::Result<()> {
        let n = unsafe { libc::send(self.fd, msg.as_ptr() as *const libc::c_void, msg.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Run the consumer loop until the socket errors or `should_continue`
    /// returns false. Each diverted packet is decoded, witnessed, and given a
    /// verdict per the policy (ACCEPT in observe-only; ACCEPT/DROP in enforce).
    /// Blocking; intended to run on its own thread.
    pub fn run(&mut self, mut should_continue: impl FnMut() -> bool) -> io::Result<()> {
        emit_backend_started(self.queue_num, &self.policy);
        let mut buf = vec![0u8; RECV_BUF];
        while should_continue() {
            let n =
                unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n < 0 {
                let err = io::Error::last_os_error();
                // Interrupted (EINTR) or the SO_RCVTIMEO timeout (EAGAIN /
                // EWOULDBLOCK / TimedOut): no data this round — loop back and
                // re-check the shutdown flag so SIGINT/SIGTERM stop cleanly.
                if matches!(
                    err.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                ) {
                    continue;
                }
                emit_backend_error(self.queue_num, &err);
                return Err(err);
            }
            if n == 0 {
                break;
            }
            // A single recv may carry multiple stacked netlink messages.
            let mut off = 0usize;
            let got = n as usize;
            while off + proto::NLMSGHDR_LEN <= got {
                let len = u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
                    as usize;
                if len < proto::NLMSGHDR_LEN || off + len > got {
                    break;
                }
                let outcome = handle_message(
                    &buf[off..off + len],
                    self.queue_num,
                    self.next_seq(),
                    &self.policy,
                );
                if let Some(pkt) = &outcome.decoded {
                    emit_packet(self.queue_num, pkt, outcome.dropped);
                }
                // udp_policy = masque_direct: a DROPped generic (non-DNS) UDP
                // packet is additionally carried over MASQUE direct (send leg).
                // The verdict is unchanged (still DROP — no native leak); the
                // bridge only adds the out-of-band carry + its own events.
                if let (Some(bridge), Some(DecodedPacket::Udp(u))) =
                    (&self.udp_masque_bridge, &outcome.decoded)
                {
                    if outcome.dropped && !u.is_dns() {
                        if let Some(payload) = udp_payload(nfq_ip_payload(&buf[off..off + len])) {
                            bridge.observe_and_forward(u, payload);
                        }
                    }
                }
                if let Some(verdict) = &outcome.verdict {
                    // Best-effort: a failed verdict send is logged but does not
                    // abort the loop (kernel re-queues/times out on its own).
                    let _ = self.send(verdict);
                }
                off += proto::nl_align(len);
            }
        }
        Ok(())
    }

    fn close(&mut self) {
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
            self.fd = -1;
        }
    }
}

impl Drop for NfqueueObserver {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // Rebuild the framing test helper locally to synthesize a packet message.
    fn synth_packet(packet_id: u32, payload: &[u8]) -> Vec<u8> {
        // NFQA_PACKET_HDR + NFQA_PAYLOAD, via the proto builders' layout.
        // Reuse proto by hand-rolling the same structure the kernel emits.
        fn push_attr(out: &mut Vec<u8>, t: u16, v: &[u8]) {
            let len = 4 + v.len();
            out.extend_from_slice(&(len as u16).to_ne_bytes());
            out.extend_from_slice(&t.to_ne_bytes());
            out.extend_from_slice(v);
            out.extend(std::iter::repeat_n(0u8, proto::nl_align(len) - len));
        }
        let mut attrs = Vec::new();
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&packet_id.to_be_bytes());
        hdr.extend_from_slice(&0x0800u16.to_be_bytes());
        hdr.push(0);
        push_attr(&mut attrs, proto::NFQA_PACKET_HDR, &hdr);
        push_attr(&mut attrs, proto::NFQA_PAYLOAD, payload);
        // nlmsghdr + nfgenmsg
        let total = proto::NLMSGHDR_LEN + proto::NFGENMSG_LEN + attrs.len();
        let mut m = Vec::new();
        m.extend_from_slice(&(total as u32).to_ne_bytes());
        m.extend_from_slice(&proto::nfqnl_type(proto::NFQNL_MSG_PACKET).to_ne_bytes());
        m.extend_from_slice(&0u16.to_ne_bytes());
        m.extend_from_slice(&0u32.to_ne_bytes());
        m.extend_from_slice(&0u32.to_ne_bytes());
        m.push(proto::AF_INET);
        m.push(proto::NFNETLINK_V0);
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&attrs);
        m
    }

    fn ipv4_syn(dst: Ipv4Addr, dport: u16) -> Vec<u8> {
        let mut p = vec![0x45u8, 0]; // ver+ihl, dscp
        let total: u16 = 40;
        p.extend_from_slice(&total.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0x40, 0, 64, 6, 0, 0]); // id, flags, ttl, proto=tcp, csum
        p.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 9).octets());
        p.extend_from_slice(&dst.octets());
        // tcp
        p.extend_from_slice(&40000u16.to_be_bytes());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0]); // seq, ack
        p.push(5 << 4); // data offset
        p.push(0x02); // SYN
        p.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]);
        p
    }

    /// Build an IPv4 UDP datagram to `dst:dport` (src 10.0.0.9:40000).
    fn ipv4_udp(dst: Ipv4Addr, dport: u16) -> Vec<u8> {
        let mut p = vec![0x45u8, 0, 0, 28, 0, 0, 0x40, 0, 64, 17, 0, 0];
        p.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 9).octets());
        p.extend_from_slice(&dst.octets());
        p.extend_from_slice(&40000u16.to_be_bytes());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&8u16.to_be_bytes()); // udp len
        p.extend_from_slice(&0u16.to_be_bytes()); // csum
        p
    }

    fn verdict_code(out: &HandleOutcome) -> u32 {
        let v = out.verdict.as_ref().expect("verdict");
        u32::from_be_bytes([v[24], v[25], v[26], v[27]])
    }

    #[test]
    fn observe_only_decodes_and_accepts_tcp() {
        let msg = synth_packet(0xabcd, &ipv4_syn(Ipv4Addr::new(1, 1, 1, 1), 443));
        let out = handle_message(&msg, 7, 100, &NfqueuePolicy::observe_only());
        let pkt = out.decoded.expect("decoded packet");
        assert_eq!(pkt.dst(), std::net::IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(pkt.dst_port(), 443);
        assert!(!out.dropped);
        assert_eq!(verdict_code(&out), proto::NF_ACCEPT);
        let v = out.verdict.unwrap();
        assert_eq!(u32::from_be_bytes([v[28], v[29], v[30], v[31]]), 0xabcd);
    }

    #[test]
    fn observe_only_accepts_udp() {
        let msg = synth_packet(5, &ipv4_udp(Ipv4Addr::new(8, 8, 4, 4), 12345));
        let out = handle_message(&msg, 1, 1, &NfqueuePolicy::observe_only());
        assert!(out.decoded.is_some());
        assert!(!out.dropped);
        assert_eq!(verdict_code(&out), proto::NF_ACCEPT);
    }

    fn enforce_block_all() -> NfqueuePolicy {
        NfqueuePolicy {
            mode: NfqueueMode::Enforce,
            udp_block: true,
            dns_block: false,
            ipv6_block: true,
        }
    }

    #[test]
    fn enforce_drops_generic_udp_but_keeps_tcp() {
        let pol = enforce_block_all();
        // generic UDP -> DROP
        let udp = synth_packet(1, &ipv4_udp(Ipv4Addr::new(8, 8, 4, 4), 51000));
        let out = handle_message(&udp, 1, 1, &pol);
        assert!(out.dropped, "generic UDP must be dropped under enforce");
        assert_eq!(verdict_code(&out), proto::NF_DROP);
        // TCP v4 -> ACCEPT (carried by REDIRECT out-of-band)
        let tcp = synth_packet(2, &ipv4_syn(Ipv4Addr::new(1, 1, 1, 1), 443));
        let out = handle_message(&tcp, 1, 2, &pol);
        assert!(!out.dropped);
        assert_eq!(verdict_code(&out), proto::NF_ACCEPT);
    }

    #[test]
    fn enforce_dns_policy_independent_of_generic_udp() {
        // udp_block=true but dns_block=false: DNS ACCEPT, generic UDP DROP.
        let pol = NfqueuePolicy {
            mode: NfqueueMode::Enforce,
            udp_block: true,
            dns_block: false,
            ipv6_block: false,
        };
        let dns = synth_packet(1, &ipv4_udp(Ipv4Addr::new(8, 8, 8, 8), 53));
        let out = handle_message(&dns, 1, 1, &pol);
        assert!(!out.dropped, "DNS must survive when dns_block=false");
        assert!(out.decoded.unwrap().is_dns());
        // and DROP when dns_block=true
        let pol2 = NfqueuePolicy {
            dns_block: true,
            ..pol
        };
        let out2 = handle_message(&dns, 1, 1, &pol2);
        assert!(out2.dropped, "DNS must drop when dns_block=true");
    }

    #[test]
    fn enforce_drops_undecodable_failclosed() {
        // ICMP (proto 1): undecodable. Enforce must DROP (fail-closed).
        let mut icmp = vec![0x45u8, 0, 0, 28, 0, 0, 0x40, 0, 64, 1, 0, 0];
        icmp.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 9).octets());
        icmp.extend_from_slice(&Ipv4Addr::new(8, 8, 8, 8).octets());
        icmp.extend_from_slice(&[0; 8]);
        let msg = synth_packet(9, &icmp);
        let out = handle_message(&msg, 1, 1, &enforce_block_all());
        assert!(out.decoded.is_none());
        assert!(
            out.dropped,
            "undecodable must fail-closed (DROP) under enforce"
        );
        assert_eq!(verdict_code(&out), proto::NF_DROP);
        // ...but observe-only ACCEPTs it (witness tap preserves connectivity).
        let out2 = handle_message(&msg, 1, 1, &NfqueuePolicy::observe_only());
        assert!(!out2.dropped);
        assert_eq!(verdict_code(&out2), proto::NF_ACCEPT);
    }

    /// Minimal IPv6 UDP datagram to `dport` (for the v6 fail-closed test).
    fn ipv6_udp(dport: u16) -> Vec<u8> {
        let mut p = vec![0x60u8, 0, 0, 0]; // version 6
        p.extend_from_slice(&8u16.to_be_bytes()); // payload len
        p.push(17); // next header = UDP
        p.push(64); // hop limit
        p.extend_from_slice(&std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
        p.extend_from_slice(
            &std::net::Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111).octets(),
        );
        p.extend_from_slice(&40000u16.to_be_bytes());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&8u16.to_be_bytes());
        p.extend_from_slice(&[0, 0]);
        p
    }

    #[test]
    fn enforce_failcloses_ipv6_and_witnesses_it() {
        // ipv6_block=true: a v6 UDP datagram is decoded (witnessed) AND DROPped.
        let pol = NfqueuePolicy {
            mode: NfqueueMode::Enforce,
            udp_block: false, // even with UDP allowed, IPv6 fail-closes first
            dns_block: false,
            ipv6_block: true,
        };
        let msg = synth_packet(0x77, &ipv6_udp(51820));
        let out = handle_message(&msg, 1, 1, &pol);
        let pkt = out.decoded.expect("v6 packet decoded (witnessed)");
        assert!(pkt.is_ipv6());
        assert!(out.dropped, "IPv6 must fail-closed (DROP) under ipv6_block");
        assert_eq!(verdict_code(&out), proto::NF_DROP);
        // With ipv6_block=false the same v6 UDP is ACCEPTed (no leak claim — that
        // combination is only used by wide-compat, never a safe mode).
        let pol2 = NfqueuePolicy {
            ipv6_block: false,
            ..pol
        };
        assert!(!handle_message(&msg, 1, 1, &pol2).dropped);
    }

    #[test]
    fn handle_message_ignores_non_packet_message() {
        let verdict_msg = proto::build_verdict(1, 1, 1, proto::NF_ACCEPT);
        let out = handle_message(&verdict_msg, 1, 1, &NfqueuePolicy::observe_only());
        assert!(out.decoded.is_none());
        assert!(out.verdict.is_none());
        assert!(!out.dropped);
    }
}
