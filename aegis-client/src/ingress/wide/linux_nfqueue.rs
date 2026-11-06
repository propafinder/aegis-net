//! NFQUEUE observer backend for Linux wide ingress.
//!
//! Scope (decoder layer): a pure-Rust IPv4 **and IPv6** TCP packet decoder
//! that extracts the pre-NAT 5-tuple plus a small set of TCP flags. IPv6
//! decoding walks the transparent extension-header chain (hop-by-hop,
//! routing, fragment, destination-options) to reach the TCP segment, which
//! is what lets the observer capture IPv6 flows rather than only block them.
//! `decode_tcp` dispatches on the IP version nibble so a single decode path
//! serves both families. The decoder is transport-agnostic and can be driven
//! from any packet-source — NFQUEUE, pcap, raw socket.
//!
//! Consumer status: the nfnetlink socket consumer now ships in
//! `nfqueue_socket` (socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER) + NFQNL_*
//! framing in `nfqueue_proto` + recv/verdict loop), live-validated for IPv4
//! and IPv6 (evidence-archive/live/2026-05-31/nfqueue-ipv6-capture-live). The runtime
//! backend ID is `linux_nfqueue_observer_runtime`; full selection through the
//! ingress preflight/lifecycle is the remaining wiring.
//!
//! Why a separate observer-mode backend at all (vs. just relying on the
//! existing TPROXY/REDIRECT path)?
//!
//! 1. Hosts where TPROXY is policy-blocked (hardened containers, jails,
//!    certain mainline-but-trimmed Android kernels) can still divert via
//!    NFQUEUE and recover original-dst from the packet header itself,
//!    without depending on `getsockopt(SO_ORIGINAL_DST)` or cmsghdr
//!    `IP_RECVORIGDSTADDR`.
//! 2. The packet bytes themselves are the witness — useful for the
//!    adversarial DPI testbed and for operator-side mirroring without
//!    standing up pcap.
//! 3. The decoder is small enough to unit-test exhaustively against
//!    synthetic byte fixtures: no kernel, no root, no integration setup.

#![cfg(any(target_os = "linux", target_os = "macos", windows))]
// The decoder IS wired into the runtime: the NFQUEUE consumer
// (`nfqueue_socket`) calls `decode_packet` (TCP+UDP, v4+v6, DNS) per diverted
// packet in the full-wide-nfqueue product path. The module-level allow now
// covers only intentionally-retained surface items (a few UAPI/flag constants,
// `closes_flow`, `RUNTIME_STAGE`) kept for completeness and ABI/decoder tests,
// rather than churn-annotating each.
#![allow(dead_code)]

use std::net::Ipv4Addr;

/// Minimum IPv4 header length: 5 × 32-bit words.
const IPV4_MIN_HEADER_WORDS: u8 = 5;
const IPV4_MIN_HEADER_BYTES: usize = (IPV4_MIN_HEADER_WORDS as usize) * 4;
/// Maximum IPv4 header length: 15 × 32-bit words (4-bit field).
const IPV4_MAX_HEADER_BYTES: usize = 15 * 4;
/// Minimum TCP header length: 5 × 32-bit words.
const TCP_MIN_HEADER_WORDS: u8 = 5;
const TCP_MIN_HEADER_BYTES: usize = (TCP_MIN_HEADER_WORDS as usize) * 4;

const IPV4_VERSION: u8 = 4;
const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;
/// Minimum UDP header length (RFC 768): src/dst port + length + checksum.
const UDP_HEADER_BYTES: usize = 8;
/// Well-known DNS port (UDP/53).
const DNS_PORT: u16 = 53;

/// IP version nibble for IPv6.
const IPV6_VERSION: u8 = 6;
/// Fixed IPv6 main header length (RFC 8200 §3): 40 octets.
const IPV6_HEADER_BYTES: usize = 40;
/// Maximum IPv6 extension headers we walk before giving up. A legitimate
/// stack never chains this many; a deeper chain is treated as hostile/
/// malformed rather than parsed, to bound work per packet.
const IPV6_MAX_EXT_HEADERS: usize = 8;

/// IPv6 Next Header values for the extension headers we transparently skip
/// to reach the upper-layer TCP segment (RFC 8200). AH (51) and ESP (50) are
/// deliberately NOT skipped — ESP is opaque and AH uses a different length
/// unit; both terminate the walk as "not TCP".
mod ipv6_next {
    pub const HOP_BY_HOP: u8 = 0;
    pub const ROUTING: u8 = 43;
    pub const FRAGMENT: u8 = 44;
    pub const DEST_OPTIONS: u8 = 60;
    /// No Next Header (RFC 8200 §4.7) — chain ends with no upper layer.
    pub const NO_NEXT: u8 = 59;
}

/// TCP control-bit flag values (RFC 793 + RFC 3168 ECN). Defined as a
/// complete set so callers can match on raw `tcp_flags`; the
/// observer-mode backend itself only currently inspects SYN/ACK/FIN/RST.
#[allow(dead_code)]
pub mod tcp_flag {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
    pub const ECE: u8 = 0x40;
    pub const CWR: u8 = 0x80;
}

/// Parsed view of a single IPv4 TCP segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedFlow {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub tcp_flags: u8,
    /// Total length declared in the IPv4 header.
    pub ipv4_total_len: u16,
    /// True for SYN-without-ACK packets — i.e. connection initiation.
    pub is_initial_syn: bool,
}

impl DecodedFlow {
    /// Convenience: this packet opens a new flow (SYN, no ACK).
    pub fn opens_flow(&self) -> bool {
        self.is_initial_syn
    }

    /// Convenience: this packet closes a flow (FIN or RST).
    pub fn closes_flow(&self) -> bool {
        (self.tcp_flags & (tcp_flag::FIN | tcp_flag::RST)) != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    TooShortForIpv4Header,
    NotIpv4 {
        version: u8,
    },
    Ipv4HeaderShorterThanMinimum {
        ihl: u8,
    },
    Ipv4HeaderLongerThanBuffer {
        ihl_bytes: usize,
        buf_len: usize,
    },
    NotTcp {
        protocol: u8,
    },
    NotUdp {
        protocol: u8,
    },
    UdpSegmentShorterThanMinimum {
        remaining: usize,
    },
    TcpSegmentShorterThanMinimum {
        remaining: usize,
    },
    TcpDataOffsetShorterThanMinimum {
        data_offset: u8,
    },
    TcpDataOffsetLongerThanBuffer {
        data_offset_bytes: usize,
        remaining: usize,
    },
    TooShortForIpv6Header,
    NotIpv6 {
        version: u8,
    },
    /// Neither IPv4 nor IPv6 in the version nibble.
    UnknownIpVersion {
        version: u8,
    },
    /// An IPv6 extension header ran past the end of the buffer.
    Ipv6ExtensionHeaderTruncated {
        next_header: u8,
    },
    /// More than [`IPV6_MAX_EXT_HEADERS`] extension headers chained.
    Ipv6ExtensionChainTooDeep,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShortForIpv4Header => write!(f, "packet shorter than minimum IPv4 header"),
            Self::NotIpv4 { version } => write!(f, "not IPv4 (version field = {version})"),
            Self::Ipv4HeaderShorterThanMinimum { ihl } => {
                write!(f, "IPv4 IHL field {ihl} < minimum 5")
            }
            Self::Ipv4HeaderLongerThanBuffer { ihl_bytes, buf_len } => write!(
                f,
                "IPv4 IHL says {ihl_bytes} header bytes but buffer is only {buf_len}"
            ),
            Self::NotTcp { protocol } => write!(f, "IP protocol {protocol} != TCP (6)"),
            Self::NotUdp { protocol } => write!(f, "IP protocol {protocol} != UDP (17)"),
            Self::UdpSegmentShorterThanMinimum { remaining } => {
                write!(f, "remaining {remaining} bytes < minimum UDP header (8)")
            }
            Self::TcpSegmentShorterThanMinimum { remaining } => {
                write!(f, "remaining {remaining} bytes < minimum TCP header (20)")
            }
            Self::TcpDataOffsetShorterThanMinimum { data_offset } => {
                write!(f, "TCP data offset {data_offset} < minimum 5")
            }
            Self::TcpDataOffsetLongerThanBuffer {
                data_offset_bytes,
                remaining,
            } => write!(
                f,
                "TCP data offset says {data_offset_bytes} header bytes but only {remaining} remain"
            ),
            Self::TooShortForIpv6Header => {
                write!(f, "packet shorter than fixed 40-byte IPv6 header")
            }
            Self::NotIpv6 { version } => write!(f, "not IPv6 (version field = {version})"),
            Self::UnknownIpVersion { version } => {
                write!(f, "unknown IP version field = {version}")
            }
            Self::Ipv6ExtensionHeaderTruncated { next_header } => write!(
                f,
                "IPv6 extension header (next_header={next_header}) runs past end of buffer"
            ),
            Self::Ipv6ExtensionChainTooDeep => {
                write!(f, "IPv6 extension header chain deeper than supported limit")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// Decode an IPv4 TCP segment from its raw on-wire bytes.
///
/// The input is the IPv4 header followed by the IPv4 payload (i.e. exactly
/// what NFQUEUE delivers in `NFQA_PAYLOAD`). The decoder validates lengths
/// strictly: any malformed or truncated input produces an error rather
/// than a partial result.
pub fn decode_ipv4_tcp(buf: &[u8]) -> Result<DecodedFlow, DecodeError> {
    if buf.len() < IPV4_MIN_HEADER_BYTES {
        return Err(DecodeError::TooShortForIpv4Header);
    }

    let version = buf[0] >> 4;
    if version != IPV4_VERSION {
        return Err(DecodeError::NotIpv4 { version });
    }

    let ihl = buf[0] & 0x0f;
    if ihl < IPV4_MIN_HEADER_WORDS {
        return Err(DecodeError::Ipv4HeaderShorterThanMinimum { ihl });
    }
    let ipv4_header_len = (ihl as usize) * 4;
    debug_assert!(ipv4_header_len <= IPV4_MAX_HEADER_BYTES);
    if buf.len() < ipv4_header_len {
        return Err(DecodeError::Ipv4HeaderLongerThanBuffer {
            ihl_bytes: ipv4_header_len,
            buf_len: buf.len(),
        });
    }

    let ipv4_total_len = u16::from_be_bytes([buf[2], buf[3]]);
    let protocol = buf[9];
    if protocol != IP_PROTO_TCP {
        return Err(DecodeError::NotTcp { protocol });
    }

    let src_ip = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    let dst_ip = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);

    let tcp = parse_tcp_header(&buf[ipv4_header_len..])?;

    Ok(DecodedFlow {
        src_ip,
        dst_ip,
        src_port: tcp.src_port,
        dst_port: tcp.dst_port,
        seq: tcp.seq,
        ack: tcp.ack,
        tcp_flags: tcp.tcp_flags,
        ipv4_total_len,
        is_initial_syn: tcp.is_initial_syn,
    })
}

/// Parsed TCP header fields shared by the IPv4 and IPv6 decoders.
struct ParsedTcp {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    tcp_flags: u8,
    is_initial_syn: bool,
}

/// Decode the leading TCP header from `tcp` (bytes positioned at the start of
/// the TCP segment). Shared by both IP version decoders so the segment-level
/// validation and flag extraction live in exactly one place.
fn parse_tcp_header(tcp: &[u8]) -> Result<ParsedTcp, DecodeError> {
    if tcp.len() < TCP_MIN_HEADER_BYTES {
        return Err(DecodeError::TcpSegmentShorterThanMinimum {
            remaining: tcp.len(),
        });
    }
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
    let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    let data_offset = tcp[12] >> 4;
    if data_offset < TCP_MIN_HEADER_WORDS {
        return Err(DecodeError::TcpDataOffsetShorterThanMinimum { data_offset });
    }
    let tcp_header_len = (data_offset as usize) * 4;
    if tcp.len() < tcp_header_len {
        return Err(DecodeError::TcpDataOffsetLongerThanBuffer {
            data_offset_bytes: tcp_header_len,
            remaining: tcp.len(),
        });
    }
    let tcp_flags = tcp[13];
    let is_initial_syn = (tcp_flags & tcp_flag::SYN) != 0 && (tcp_flags & tcp_flag::ACK) == 0;
    Ok(ParsedTcp {
        src_port,
        dst_port,
        seq,
        ack,
        tcp_flags,
        is_initial_syn,
    })
}

/// Parsed view of a single IPv6 TCP segment. Mirrors [`DecodedFlow`] but with
/// 128-bit addresses and the IPv6 payload length (which, unlike IPv4
/// `total_len`, excludes the 40-byte main header).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedFlow6 {
    pub src_ip: std::net::Ipv6Addr,
    pub dst_ip: std::net::Ipv6Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub tcp_flags: u8,
    /// IPv6 payload length (header field), i.e. bytes after the 40-byte main
    /// header including any extension headers.
    pub ipv6_payload_len: u16,
    pub is_initial_syn: bool,
}

impl DecodedFlow6 {
    pub fn opens_flow(&self) -> bool {
        self.is_initial_syn
    }
    pub fn closes_flow(&self) -> bool {
        (self.tcp_flags & (tcp_flag::FIN | tcp_flag::RST)) != 0
    }
}

/// Decode an IPv6 TCP segment, walking transparent extension headers
/// (hop-by-hop, routing, fragment, destination-options) until the TCP
/// upper layer is reached. ESP/AH and unknown next-headers terminate the
/// walk as [`DecodeError::NotTcp`].
pub fn decode_ipv6_tcp(buf: &[u8]) -> Result<DecodedFlow6, DecodeError> {
    if buf.len() < IPV6_HEADER_BYTES {
        return Err(DecodeError::TooShortForIpv6Header);
    }
    let version = buf[0] >> 4;
    if version != IPV6_VERSION {
        return Err(DecodeError::NotIpv6 { version });
    }
    let ipv6_payload_len = u16::from_be_bytes([buf[4], buf[5]]);
    let mut next_header = buf[6];
    let src_ip = ipv6_addr_at(buf, 8);
    let dst_ip = ipv6_addr_at(buf, 24);

    // Walk the extension-header chain to the TCP segment.
    let mut offset = IPV6_HEADER_BYTES;
    for _ in 0..IPV6_MAX_EXT_HEADERS {
        match next_header {
            IP_PROTO_TCP => {
                let tcp = parse_tcp_header(&buf[offset.min(buf.len())..])?;
                return Ok(DecodedFlow6 {
                    src_ip,
                    dst_ip,
                    src_port: tcp.src_port,
                    dst_port: tcp.dst_port,
                    seq: tcp.seq,
                    ack: tcp.ack,
                    tcp_flags: tcp.tcp_flags,
                    ipv6_payload_len,
                    is_initial_syn: tcp.is_initial_syn,
                });
            }
            ipv6_next::HOP_BY_HOP | ipv6_next::ROUTING | ipv6_next::DEST_OPTIONS => {
                // Generic extension header: [next_header u8][hdr_ext_len u8]...
                // hdr_ext_len is in 8-octet units NOT counting the first 8.
                if buf.len() < offset + 2 {
                    return Err(DecodeError::Ipv6ExtensionHeaderTruncated { next_header });
                }
                let ext_len = (buf[offset + 1] as usize + 1) * 8;
                next_header = buf[offset];
                offset += ext_len;
                if offset > buf.len() {
                    return Err(DecodeError::Ipv6ExtensionHeaderTruncated { next_header });
                }
            }
            ipv6_next::FRAGMENT => {
                // Fragment header is a fixed 8 octets.
                if buf.len() < offset + 8 {
                    return Err(DecodeError::Ipv6ExtensionHeaderTruncated { next_header });
                }
                next_header = buf[offset];
                offset += 8;
            }
            other => {
                return Err(DecodeError::NotTcp { protocol: other });
            }
        }
    }
    Err(DecodeError::Ipv6ExtensionChainTooDeep)
}

fn ipv6_addr_at(buf: &[u8], at: usize) -> std::net::Ipv6Addr {
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&buf[at..at + 16]);
    std::net::Ipv6Addr::from(octets)
}

/// Version-agnostic decoded TCP flow: either IPv4 or IPv6. Produced by
/// [`decode_tcp`], which dispatches on the IP version nibble so the NFQUEUE
/// consumer can run a single decode path regardless of address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodedTcp {
    V4(DecodedFlow),
    V6(DecodedFlow6),
}

impl DecodedTcp {
    pub fn src(&self) -> std::net::IpAddr {
        match self {
            Self::V4(f) => std::net::IpAddr::V4(f.src_ip),
            Self::V6(f) => std::net::IpAddr::V6(f.src_ip),
        }
    }
    pub fn dst(&self) -> std::net::IpAddr {
        match self {
            Self::V4(f) => std::net::IpAddr::V4(f.dst_ip),
            Self::V6(f) => std::net::IpAddr::V6(f.dst_ip),
        }
    }
    pub fn dst_port(&self) -> u16 {
        match self {
            Self::V4(f) => f.dst_port,
            Self::V6(f) => f.dst_port,
        }
    }
    pub fn src_port(&self) -> u16 {
        match self {
            Self::V4(f) => f.src_port,
            Self::V6(f) => f.src_port,
        }
    }
    pub fn tcp_flags(&self) -> u8 {
        match self {
            Self::V4(f) => f.tcp_flags,
            Self::V6(f) => f.tcp_flags,
        }
    }
    pub fn is_initial_syn(&self) -> bool {
        match self {
            Self::V4(f) => f.is_initial_syn,
            Self::V6(f) => f.is_initial_syn,
        }
    }
    pub fn opens_flow(&self) -> bool {
        self.is_initial_syn()
    }
    pub fn closes_flow(&self) -> bool {
        (self.tcp_flags() & (tcp_flag::FIN | tcp_flag::RST)) != 0
    }
    pub fn is_ipv6(&self) -> bool {
        matches!(self, Self::V6(_))
    }
}

/// Decode a TCP segment of either IP version, dispatching on the version
/// nibble of the first byte. Empty buffers and unknown versions are rejected.
pub fn decode_tcp(buf: &[u8]) -> Result<DecodedTcp, DecodeError> {
    let version = buf.first().map(|b| b >> 4);
    match version {
        Some(IPV4_VERSION) => decode_ipv4_tcp(buf).map(DecodedTcp::V4),
        Some(IPV6_VERSION) => decode_ipv6_tcp(buf).map(DecodedTcp::V6),
        Some(other) => Err(DecodeError::UnknownIpVersion { version: other }),
        None => Err(DecodeError::TooShortForIpv4Header),
    }
}

/// Parsed view of a single UDP datagram (either IP version). DNS is identified
/// by port 53 on either end. `udp_len` is the UDP header length field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedUdp {
    pub src: std::net::IpAddr,
    pub dst: std::net::IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub udp_len: u16,
    pub is_ipv6: bool,
}

impl DecodedUdp {
    /// True when either endpoint is the well-known DNS port (UDP/53).
    pub fn is_dns(&self) -> bool {
        self.dst_port == DNS_PORT || self.src_port == DNS_PORT
    }
}

/// Decode the leading UDP header: (src_port, dst_port, udp_len).
fn parse_udp_header(udp: &[u8]) -> Result<(u16, u16, u16), DecodeError> {
    if udp.len() < UDP_HEADER_BYTES {
        return Err(DecodeError::UdpSegmentShorterThanMinimum {
            remaining: udp.len(),
        });
    }
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]);
    Ok((src_port, dst_port, udp_len))
}

/// Decode an IPv4 UDP datagram from raw on-wire bytes (IPv4 header + payload).
pub fn decode_ipv4_udp(buf: &[u8]) -> Result<DecodedUdp, DecodeError> {
    if buf.len() < IPV4_MIN_HEADER_BYTES {
        return Err(DecodeError::TooShortForIpv4Header);
    }
    let version = buf[0] >> 4;
    if version != IPV4_VERSION {
        return Err(DecodeError::NotIpv4 { version });
    }
    let ihl = buf[0] & 0x0f;
    if ihl < IPV4_MIN_HEADER_WORDS {
        return Err(DecodeError::Ipv4HeaderShorterThanMinimum { ihl });
    }
    let header_len = (ihl as usize) * 4;
    if buf.len() < header_len {
        return Err(DecodeError::Ipv4HeaderLongerThanBuffer {
            ihl_bytes: header_len,
            buf_len: buf.len(),
        });
    }
    let protocol = buf[9];
    if protocol != IP_PROTO_UDP {
        return Err(DecodeError::NotUdp { protocol });
    }
    let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    let dst = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
    let (src_port, dst_port, udp_len) = parse_udp_header(&buf[header_len..])?;
    Ok(DecodedUdp {
        src: src.into(),
        dst: dst.into(),
        src_port,
        dst_port,
        udp_len,
        is_ipv6: false,
    })
}

/// Offset of the UDP header within a raw IPv6 packet, walking transparent
/// extension headers (mirrors the UDP arm of [`decode_ipv6_tcp`]). Shared by
/// [`decode_ipv6_udp`] and [`udp_payload`] so the two never disagree on where
/// the datagram body starts.
fn ipv6_udp_header_offset(buf: &[u8]) -> Result<usize, DecodeError> {
    if buf.len() < IPV6_HEADER_BYTES {
        return Err(DecodeError::TooShortForIpv6Header);
    }
    let version = buf[0] >> 4;
    if version != IPV6_VERSION {
        return Err(DecodeError::NotIpv6 { version });
    }
    let mut next_header = buf[6];
    let mut offset = IPV6_HEADER_BYTES;
    for _ in 0..IPV6_MAX_EXT_HEADERS {
        match next_header {
            IP_PROTO_UDP => return Ok(offset),
            ipv6_next::HOP_BY_HOP | ipv6_next::ROUTING | ipv6_next::DEST_OPTIONS => {
                if buf.len() < offset + 2 {
                    return Err(DecodeError::Ipv6ExtensionHeaderTruncated { next_header });
                }
                let ext_len = (buf[offset + 1] as usize + 1) * 8;
                next_header = buf[offset];
                offset += ext_len;
                if offset > buf.len() {
                    return Err(DecodeError::Ipv6ExtensionHeaderTruncated { next_header });
                }
            }
            ipv6_next::FRAGMENT => {
                if buf.len() < offset + 8 {
                    return Err(DecodeError::Ipv6ExtensionHeaderTruncated { next_header });
                }
                next_header = buf[offset];
                offset += 8;
            }
            other => {
                return Err(DecodeError::NotUdp { protocol: other });
            }
        }
    }
    Err(DecodeError::Ipv6ExtensionChainTooDeep)
}

/// Decode an IPv6 UDP datagram, walking transparent extension headers to the
/// UDP datagram (mirrors [`decode_ipv6_tcp`]).
pub fn decode_ipv6_udp(buf: &[u8]) -> Result<DecodedUdp, DecodeError> {
    let src = ipv6_addr_at(buf, 8);
    let dst = ipv6_addr_at(buf, 24);
    let offset = ipv6_udp_header_offset(buf)?;
    let (src_port, dst_port, udp_len) = parse_udp_header(&buf[offset.min(buf.len())..])?;
    Ok(DecodedUdp {
        src: src.into(),
        dst: dst.into(),
        src_port,
        dst_port,
        udp_len,
        is_ipv6: true,
    })
}

/// Extract the UDP **payload** (bytes after the 8-byte UDP header) from a raw
/// IPv4/IPv6 packet (`NFQA_PAYLOAD`). Returns `None` for anything that is not a
/// decodable IPv4/IPv6 UDP packet. Used only on the `udp_policy=masque_direct`
/// DROP path to hand the datagram body to the MASQUE direct send bridge; the
/// pure decode/verdict layer ([`DecodedUdp`]) deliberately stays `Copy` and
/// payload-free, so this re-derives the body offset on demand.
pub fn udp_payload(buf: &[u8]) -> Option<Vec<u8>> {
    let header_offset = match buf.first().map(|b| b >> 4) {
        Some(IPV4_VERSION) => {
            // Validate it is a well-formed IPv4 UDP packet before trusting IHL.
            decode_ipv4_udp(buf).ok()?;
            (buf[0] & 0x0f) as usize * 4
        }
        Some(IPV6_VERSION) => ipv6_udp_header_offset(buf).ok()?,
        _ => return None,
    };
    let body_start = header_offset + UDP_HEADER_BYTES;
    // A zero-length UDP payload is valid (e.g. an empty datagram); represent it
    // as an empty body rather than failing the forward.
    Some(
        buf.get(body_start..)
            .map(<[u8]>::to_vec)
            .unwrap_or_default(),
    )
}

/// A fully-decoded L4 packet: TCP flow or UDP datagram, either IP version.
/// This is what the NFQUEUE consumer matches on to choose a per-packet verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodedPacket {
    Tcp(DecodedTcp),
    Udp(DecodedUdp),
}

impl DecodedPacket {
    pub fn is_ipv6(&self) -> bool {
        match self {
            Self::Tcp(t) => t.is_ipv6(),
            Self::Udp(u) => u.is_ipv6,
        }
    }
    pub fn is_udp(&self) -> bool {
        matches!(self, Self::Udp(_))
    }
    pub fn is_dns(&self) -> bool {
        matches!(self, Self::Udp(u) if u.is_dns())
    }
    pub fn src(&self) -> std::net::IpAddr {
        match self {
            Self::Tcp(t) => t.src(),
            Self::Udp(u) => u.src,
        }
    }
    pub fn dst(&self) -> std::net::IpAddr {
        match self {
            Self::Tcp(t) => t.dst(),
            Self::Udp(u) => u.dst,
        }
    }
    pub fn src_port(&self) -> u16 {
        match self {
            Self::Tcp(t) => t.src_port(),
            Self::Udp(u) => u.src_port,
        }
    }
    pub fn dst_port(&self) -> u16 {
        match self {
            Self::Tcp(t) => t.dst_port(),
            Self::Udp(u) => u.dst_port,
        }
    }
}

/// Decode any IPv4/IPv6 TCP or UDP packet from `NFQA_PAYLOAD` bytes. Dispatches
/// on the version nibble and, for each family, on the transport protocol so a
/// single call serves the NFQUEUE consumer regardless of class. Malformed or
/// non-TCP/UDP packets return an error (the consumer fail-closes on those).
pub fn decode_packet(buf: &[u8]) -> Result<DecodedPacket, DecodeError> {
    match buf.first().map(|b| b >> 4) {
        Some(IPV4_VERSION) => {
            if buf.len() < IPV4_MIN_HEADER_BYTES {
                return Err(DecodeError::TooShortForIpv4Header);
            }
            match buf[9] {
                IP_PROTO_TCP => decode_ipv4_tcp(buf).map(|f| DecodedPacket::Tcp(DecodedTcp::V4(f))),
                IP_PROTO_UDP => decode_ipv4_udp(buf).map(DecodedPacket::Udp),
                protocol => Err(DecodeError::NotTcp { protocol }),
            }
        }
        Some(IPV6_VERSION) => match decode_ipv6_tcp(buf) {
            Ok(f) => Ok(DecodedPacket::Tcp(DecodedTcp::V6(f))),
            // The v6 TCP walker reports NotUdp/NotTcp when it reaches a UDP
            // upper layer; retry as UDP before giving up.
            Err(DecodeError::NotTcp { .. }) | Err(DecodeError::NotUdp { .. }) => {
                decode_ipv6_udp(buf).map(DecodedPacket::Udp)
            }
            Err(e) => Err(e),
        },
        Some(other) => Err(DecodeError::UnknownIpVersion { version: other }),
        None => Err(DecodeError::TooShortForIpv4Header),
    }
}

/// Static identifier for the NFQUEUE backend stage that is currently live.
/// `runtime`: the nfnetlink socket consumer is implemented and live-validated
/// (decode + witness + ACCEPT for IPv4 and IPv6; see
/// evidence-archive/live/2026-05-31/nfqueue-ipv6-capture-live). Selection through the
/// ingress preflight/lifecycle (WidePlatformBackend::LinuxNfqueue end-to-end)
/// is the remaining wiring; until then the consumer is reachable via the
/// `--nfqueue-observe` validation entrypoint.
pub const RUNTIME_STAGE: &str = "linux_nfqueue_observer_runtime";

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a controlled IPv4 + TCP SYN packet with the given fields.
    /// Returns the raw on-wire bytes that NFQUEUE would deliver. Used by
    /// the tests below to exercise every decoder branch without root.
    fn build_ipv4_tcp_syn(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
    ) -> Vec<u8> {
        let total_len: u16 = (IPV4_MIN_HEADER_BYTES + TCP_MIN_HEADER_BYTES) as u16;
        let mut p = Vec::with_capacity(total_len as usize);

        // ---- IPv4 header ----
        p.push((IPV4_VERSION << 4) | IPV4_MIN_HEADER_WORDS); // ver+ihl
        p.push(0); // DSCP/ECN
        p.extend_from_slice(&total_len.to_be_bytes()); // total length
        p.extend_from_slice(&[0xab, 0xcd]); // ident
        p.extend_from_slice(&[0x40, 0x00]); // flags=DF, frag offset=0
        p.push(64); // TTL
        p.push(IP_PROTO_TCP); // protocol
        p.extend_from_slice(&[0, 0]); // header checksum (decoder ignores)
        p.extend_from_slice(&src.octets());
        p.extend_from_slice(&dst.octets());

        // ---- TCP header ----
        p.extend_from_slice(&src_port.to_be_bytes());
        p.extend_from_slice(&dst_port.to_be_bytes());
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&ack.to_be_bytes());
        p.push(TCP_MIN_HEADER_WORDS << 4); // data offset=5, reserved=0
        p.push(flags);
        p.extend_from_slice(&[0xff, 0xff]); // window
        p.extend_from_slice(&[0, 0]); // checksum
        p.extend_from_slice(&[0, 0]); // urgent pointer
        p
    }

    #[test]
    fn decode_initial_syn_extracts_pre_nat_dst() {
        let pkt = build_ipv4_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(93, 184, 216, 34), // example.com
            45123,
            443,
            0x1234_5678,
            0,
            tcp_flag::SYN,
        );
        let flow = decode_ipv4_tcp(&pkt).expect("decode SYN");
        assert_eq!(flow.src_ip, Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(flow.dst_ip, Ipv4Addr::new(93, 184, 216, 34));
        assert_eq!(flow.src_port, 45123);
        assert_eq!(flow.dst_port, 443);
        assert_eq!(flow.seq, 0x1234_5678);
        assert_eq!(flow.ack, 0);
        assert_eq!(flow.tcp_flags, tcp_flag::SYN);
        assert!(flow.is_initial_syn);
        assert!(flow.opens_flow());
        assert!(!flow.closes_flow());
    }

    #[test]
    fn decode_syn_ack_is_not_initial_syn() {
        let pkt = build_ipv4_tcp_syn(
            Ipv4Addr::new(93, 184, 216, 34),
            Ipv4Addr::new(10, 0, 0, 5),
            443,
            45123,
            0xdead_beef,
            0x1234_5679,
            tcp_flag::SYN | tcp_flag::ACK,
        );
        let flow = decode_ipv4_tcp(&pkt).expect("decode SYN-ACK");
        assert!(!flow.is_initial_syn);
        assert!(!flow.opens_flow());
        assert_eq!(flow.tcp_flags, tcp_flag::SYN | tcp_flag::ACK);
    }

    #[test]
    fn decode_fin_or_rst_is_close() {
        let fin = build_ipv4_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(1, 1, 1, 1),
            45123,
            443,
            10,
            20,
            tcp_flag::FIN | tcp_flag::ACK,
        );
        assert!(decode_ipv4_tcp(&fin).unwrap().closes_flow());

        let rst = build_ipv4_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(1, 1, 1, 1),
            45123,
            443,
            10,
            20,
            tcp_flag::RST,
        );
        assert!(decode_ipv4_tcp(&rst).unwrap().closes_flow());
    }

    #[test]
    fn decode_rejects_short_buffer() {
        let short = vec![0u8; IPV4_MIN_HEADER_BYTES - 1];
        assert_eq!(
            decode_ipv4_tcp(&short),
            Err(DecodeError::TooShortForIpv4Header)
        );
    }

    #[test]
    fn decode_rejects_ipv6_version_field() {
        let mut pkt = build_ipv4_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(1, 1, 1, 1),
            45123,
            443,
            0,
            0,
            tcp_flag::SYN,
        );
        pkt[0] = (6 << 4) | IPV4_MIN_HEADER_WORDS; // pretend IPv6 version
        assert_eq!(
            decode_ipv4_tcp(&pkt),
            Err(DecodeError::NotIpv4 { version: 6 })
        );
    }

    #[test]
    fn decode_rejects_non_tcp_protocol() {
        let mut pkt = build_ipv4_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(1, 1, 1, 1),
            45123,
            443,
            0,
            0,
            tcp_flag::SYN,
        );
        pkt[9] = 17; // UDP
        assert_eq!(
            decode_ipv4_tcp(&pkt),
            Err(DecodeError::NotTcp { protocol: 17 })
        );
    }

    #[test]
    fn decode_rejects_truncated_tcp_header() {
        let pkt = build_ipv4_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(1, 1, 1, 1),
            45123,
            443,
            0,
            0,
            tcp_flag::SYN,
        );
        // Truncate so only 19 TCP bytes remain (1 short of minimum 20).
        let truncated = &pkt[..IPV4_MIN_HEADER_BYTES + TCP_MIN_HEADER_BYTES - 1];
        assert_eq!(
            decode_ipv4_tcp(truncated),
            Err(DecodeError::TcpSegmentShorterThanMinimum { remaining: 19 })
        );
    }

    #[test]
    fn decode_rejects_ipv4_ihl_below_minimum() {
        let mut pkt = build_ipv4_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(1, 1, 1, 1),
            45123,
            443,
            0,
            0,
            tcp_flag::SYN,
        );
        pkt[0] = (IPV4_VERSION << 4) | 4; // ihl=4 (16 bytes — invalid)
        assert_eq!(
            decode_ipv4_tcp(&pkt),
            Err(DecodeError::Ipv4HeaderShorterThanMinimum { ihl: 4 })
        );
    }

    #[test]
    fn decode_rejects_tcp_data_offset_below_minimum() {
        let mut pkt = build_ipv4_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::new(1, 1, 1, 1),
            45123,
            443,
            0,
            0,
            tcp_flag::SYN,
        );
        // TCP data offset is the high nibble at offset 12 of the TCP header.
        pkt[IPV4_MIN_HEADER_BYTES + 12] = 4 << 4; // data_offset=4 (16 bytes — invalid)
        assert_eq!(
            decode_ipv4_tcp(&pkt),
            Err(DecodeError::TcpDataOffsetShorterThanMinimum { data_offset: 4 })
        );
    }

    #[test]
    fn runtime_stage_is_observer_runtime() {
        assert_eq!(RUNTIME_STAGE, "linux_nfqueue_observer_runtime");
    }

    // ---- IPv6 decode ----

    use std::net::Ipv6Addr;

    /// Build an IPv6 + TCP packet. `ext` is a list of (next_header_value,
    /// ext_header_bytes) inserted between the main header and the TCP segment,
    /// in order; the main header's Next Header points at the first ext (or TCP
    /// if empty), and each ext's first byte points at the following one.
    fn build_ipv6_tcp(
        src: Ipv6Addr,
        dst: Ipv6Addr,
        src_port: u16,
        dst_port: u16,
        flags: u8,
        ext: &[(u8, Vec<u8>)],
    ) -> Vec<u8> {
        // TCP segment.
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&src_port.to_be_bytes());
        tcp.extend_from_slice(&dst_port.to_be_bytes());
        tcp.extend_from_slice(&0x1111_2222u32.to_be_bytes()); // seq
        tcp.extend_from_slice(&0u32.to_be_bytes()); // ack
        tcp.push(TCP_MIN_HEADER_WORDS << 4);
        tcp.push(flags);
        tcp.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]);

        // Build the extension-header chain. Each block's byte[0] is its own
        // Next Header field, pointing at the following block (or TCP for the
        // last). The main header's Next Header points at the first block.
        let main_next = ext.first().map(|e| e.0).unwrap_or(IP_PROTO_TCP);
        let mut chain = Vec::new();
        for (i, (_nh, bytes)) in ext.iter().enumerate() {
            let mut b = bytes.clone();
            b[0] = if i + 1 < ext.len() {
                ext[i + 1].0
            } else {
                IP_PROTO_TCP
            };
            chain.extend_from_slice(&b);
        }

        let payload_len = (chain.len() + tcp.len()) as u16;
        let mut p = Vec::with_capacity(IPV6_HEADER_BYTES + payload_len as usize);
        p.push((IPV6_VERSION << 4) | 0x06); // version + traffic class hi
        p.extend_from_slice(&[0x00, 0x00, 0x00]); // tc lo + flow label
        p.extend_from_slice(&payload_len.to_be_bytes());
        p.push(main_next);
        p.push(64); // hop limit
        p.extend_from_slice(&src.octets());
        p.extend_from_slice(&dst.octets());
        p.extend_from_slice(&chain);
        p.extend_from_slice(&tcp);
        p
    }

    #[test]
    fn decode_ipv6_initial_syn_extracts_tuple() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10);
        let dst = Ipv6Addr::new(0x2606, 0x2800, 0x220, 1, 0x248, 0x1893, 0x25c8, 0x1946);
        let pkt = build_ipv6_tcp(src, dst, 51000, 443, tcp_flag::SYN, &[]);
        let flow = decode_ipv6_tcp(&pkt).expect("decode v6 SYN");
        assert_eq!(flow.src_ip, src);
        assert_eq!(flow.dst_ip, dst);
        assert_eq!(flow.src_port, 51000);
        assert_eq!(flow.dst_port, 443);
        assert!(flow.is_initial_syn);
        assert!(flow.opens_flow());
        assert!(!flow.closes_flow());
    }

    #[test]
    fn decode_ipv6_walks_extension_headers_to_tcp() {
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0x2606, 0x2800, 0, 0, 0, 0, 0, 1);
        // hop-by-hop (8 bytes) then destination-options (16 bytes) then TCP.
        let hbh = (ipv6_next::DEST_OPTIONS, vec![0u8; 8]); // byte0 fixed by builder; hdr_ext_len=0 -> 8 bytes
        let dst_opts = (0u8, {
            let mut v = vec![0u8; 16];
            v[1] = 1; // hdr_ext_len=1 -> (1+1)*8 = 16 bytes
            v
        });
        let pkt = build_ipv6_tcp(src, dst, 40000, 8443, tcp_flag::SYN, &[hbh, dst_opts]);
        let flow = decode_ipv6_tcp(&pkt).expect("decode v6 with ext headers");
        assert_eq!(flow.dst_port, 8443);
        assert!(flow.is_initial_syn);
    }

    #[test]
    fn decode_ipv6_fin_closes_flow() {
        let pkt = build_ipv6_tcp(
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::LOCALHOST,
            443,
            40000,
            tcp_flag::FIN | tcp_flag::ACK,
            &[],
        );
        let flow = decode_ipv6_tcp(&pkt).expect("decode v6 FIN");
        assert!(!flow.is_initial_syn);
        assert!(flow.closes_flow());
    }

    #[test]
    fn decode_ipv6_rejects_short_header() {
        assert_eq!(
            decode_ipv6_tcp(&[0x60; 20]),
            Err(DecodeError::TooShortForIpv6Header)
        );
    }

    #[test]
    fn decode_ipv6_rejects_ipv4_version() {
        let mut buf = vec![0u8; IPV6_HEADER_BYTES + TCP_MIN_HEADER_BYTES];
        buf[0] = 0x45; // IPv4 version nibble
        assert!(matches!(
            decode_ipv6_tcp(&buf),
            Err(DecodeError::NotIpv6 { version: 4 })
        ));
    }

    #[test]
    fn decode_ipv6_non_tcp_next_header_is_not_tcp() {
        // UDP (17) directly after the main header.
        let mut buf = vec![0u8; IPV6_HEADER_BYTES + 8];
        buf[0] = IPV6_VERSION << 4;
        buf[6] = 17; // next header = UDP
        assert_eq!(
            decode_ipv6_tcp(&buf),
            Err(DecodeError::NotTcp { protocol: 17 })
        );
    }

    #[test]
    fn decode_tcp_dispatches_on_version() {
        let v4 = build_ipv4_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(1, 1, 1, 1),
            33000,
            443,
            1,
            0,
            tcp_flag::SYN,
        );
        let v6 = build_ipv6_tcp(
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1),
            33001,
            443,
            tcp_flag::SYN,
            &[],
        );
        let d4 = decode_tcp(&v4).expect("v4");
        let d6 = decode_tcp(&v6).expect("v6");
        assert!(!d4.is_ipv6());
        assert!(d6.is_ipv6());
        assert_eq!(d4.dst(), std::net::IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(
            d6.dst(),
            std::net::IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1))
        );
        assert!(d4.opens_flow() && d6.opens_flow());
    }

    #[test]
    fn decode_tcp_rejects_unknown_version() {
        assert!(matches!(
            decode_tcp(&[0x70; 40]),
            Err(DecodeError::UnknownIpVersion { version: 7 })
        ));
        assert_eq!(decode_tcp(&[]), Err(DecodeError::TooShortForIpv4Header));
    }

    // ---- UDP / DNS / IPv6 / unified packet decode ----

    fn build_ipv4_udp(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> Vec<u8> {
        let total: u16 = (IPV4_MIN_HEADER_BYTES + UDP_HEADER_BYTES) as u16;
        let mut p = Vec::new();
        p.push((IPV4_VERSION << 4) | IPV4_MIN_HEADER_WORDS);
        p.push(0);
        p.extend_from_slice(&total.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0x40, 0, 64, IP_PROTO_UDP, 0, 0]);
        p.extend_from_slice(&src.octets());
        p.extend_from_slice(&dst.octets());
        p.extend_from_slice(&sport.to_be_bytes());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&(UDP_HEADER_BYTES as u16).to_be_bytes());
        p.extend_from_slice(&[0, 0]);
        p
    }

    fn build_ipv6_udp(dport: u16) -> Vec<u8> {
        let mut p = Vec::new();
        p.push(IPV6_VERSION << 4); // version nibble, tc high bits zero
        p.extend_from_slice(&[0, 0, 0]); // tc/flowlabel
        p.extend_from_slice(&(UDP_HEADER_BYTES as u16).to_be_bytes()); // payload len
        p.push(IP_PROTO_UDP); // next header
        p.push(64); // hop limit
        p.extend_from_slice(&std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
        p.extend_from_slice(
            &std::net::Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111).octets(),
        );
        p.extend_from_slice(&5353u16.to_be_bytes()); // sport
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&(UDP_HEADER_BYTES as u16).to_be_bytes());
        p.extend_from_slice(&[0, 0]);
        p
    }

    #[test]
    fn decode_ipv4_udp_extracts_tuple_and_dns() {
        let p = build_ipv4_udp(
            Ipv4Addr::new(10, 0, 0, 9),
            Ipv4Addr::new(8, 8, 8, 8),
            40000,
            53,
        );
        let u = decode_ipv4_udp(&p).expect("udp");
        assert_eq!(u.dst, std::net::IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(u.dst_port, 53);
        assert!(u.is_dns());
        assert!(!u.is_ipv6);
        // a non-53 datagram is not DNS
        let g = build_ipv4_udp(
            Ipv4Addr::new(10, 0, 0, 9),
            Ipv4Addr::new(1, 1, 1, 1),
            40000,
            51820,
        );
        assert!(!decode_ipv4_udp(&g).unwrap().is_dns());
    }

    #[test]
    fn decode_ipv6_udp_extracts_tuple() {
        let p = build_ipv6_udp(443);
        let u = decode_ipv6_udp(&p).expect("v6 udp");
        assert!(u.is_ipv6);
        assert_eq!(u.dst_port, 443);
        assert!(!u.is_dns());
    }

    #[test]
    fn udp_payload_extracts_ipv4_body() {
        let mut p = build_ipv4_udp(
            Ipv4Addr::new(10, 0, 0, 9),
            Ipv4Addr::new(8, 8, 8, 8),
            5353,
            53,
        );
        let body = b"\x12\x34hello-dns";
        p.extend_from_slice(body);
        let got = udp_payload(&p).expect("v4 udp payload");
        assert_eq!(got, body);
    }

    #[test]
    fn udp_payload_extracts_ipv6_body() {
        let mut p = build_ipv6_udp(443);
        let body = b"quic-initial-bytes";
        p.extend_from_slice(body);
        let got = udp_payload(&p).expect("v6 udp payload");
        assert_eq!(got, body);
    }

    #[test]
    fn udp_payload_empty_for_zero_length_body() {
        // The 8-byte-header-only fixture has no body: an empty (not None) result.
        let p = build_ipv4_udp(
            Ipv4Addr::new(10, 0, 0, 9),
            Ipv4Addr::new(8, 8, 8, 8),
            5353,
            53,
        );
        assert_eq!(udp_payload(&p), Some(Vec::new()));
    }

    #[test]
    fn udp_payload_none_for_tcp_and_garbage() {
        let tcp = build_ipv4_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(1, 1, 1, 1),
            1234,
            443,
            0,
            0,
            tcp_flag::SYN,
        );
        assert_eq!(udp_payload(&tcp), None);
        assert_eq!(udp_payload(&[0xff, 0x00, 0x01]), None);
    }

    #[test]
    fn decode_packet_dispatches_all_classes() {
        // IPv4 TCP
        let tcp4 = build_ipv4_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(1, 1, 1, 1),
            1234,
            443,
            1,
            0,
            tcp_flag::SYN,
        );
        assert!(matches!(decode_packet(&tcp4), Ok(DecodedPacket::Tcp(_))));
        // IPv4 UDP/DNS
        let dns4 = build_ipv4_udp(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(8, 8, 8, 8),
            40000,
            53,
        );
        let d = decode_packet(&dns4).expect("dns");
        assert!(d.is_udp() && d.is_dns() && !d.is_ipv6());
        // IPv6 UDP
        let udp6 = build_ipv6_udp(51820);
        let g = decode_packet(&udp6).expect("v6 udp");
        assert!(g.is_udp() && g.is_ipv6() && !g.is_dns());
    }

    #[test]
    fn decode_packet_rejects_malformed_and_nonl4() {
        // truncated IPv4
        assert!(decode_packet(&[0x45, 0, 0]).is_err());
        // ICMP (proto 1) is neither TCP nor UDP
        let mut icmp = build_ipv4_udp(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(8, 8, 8, 8), 1, 1);
        icmp[9] = 1; // protocol = ICMP
        assert!(matches!(
            decode_packet(&icmp),
            Err(DecodeError::NotTcp { protocol: 1 })
        ));
        // empty + unknown version
        assert!(decode_packet(&[]).is_err());
        assert!(matches!(
            decode_packet(&[0x70; 48]),
            Err(DecodeError::UnknownIpVersion { version: 7 })
        ));
    }

    #[test]
    fn decode_ipv4_udp_rejects_short_udp_header() {
        // valid IPv4 header, proto UDP, but no room for the 8-byte UDP header
        let mut p = vec![(IPV4_VERSION << 4) | IPV4_MIN_HEADER_WORDS, 0, 0, 24];
        p.extend_from_slice(&[0, 0, 0x40, 0, 64, IP_PROTO_UDP, 0, 0]);
        p.extend_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets());
        p.extend_from_slice(&Ipv4Addr::new(8, 8, 8, 8).octets());
        p.extend_from_slice(&[0, 0, 0, 0]); // only 4 bytes of UDP (need 8)
        assert!(matches!(
            decode_ipv4_udp(&p),
            Err(DecodeError::UdpSegmentShorterThanMinimum { .. })
        ));
    }
}
