//! Pure-Rust nfnetlink / NFQUEUE message framing.
//!
//! This module encodes the netlink messages the NFQUEUE backend must send
//! (bind the queue, set copy mode, issue per-packet verdicts) and decodes the
//! `NFQNL_MSG_PACKET` messages the kernel delivers (extracting the packet id
//! and the raw L3 payload). It deliberately contains **no socket I/O** — that
//! lives in the runtime consumer (next batch) — so every byte-layout decision
//! here is exhaustively unit-testable without root or a kernel.
//!
//! Wire references: `linux/netlink.h` (nlmsghdr, nlattr), `linux/netfilter/
//! nfnetlink.h` (nfgenmsg, subsys/type packing) and `linux/netfilter/
//! nfnetlink_queue.h` (NFQNL_* commands and attributes). Netlink struct fields
//! are host-endian; nfnetlink payload fields (res_id, the config/verdict
//! sub-structs and attributes) are network byte order.

#![cfg(target_os = "linux")]
#![allow(dead_code)]

/// netlink message header length (struct nlmsghdr) — 16 bytes.
pub const NLMSGHDR_LEN: usize = 16;
/// nfgenmsg length (family u8 + version u8 + res_id u16) — 4 bytes.
pub const NFGENMSG_LEN: usize = 4;
/// nlattr header length (len u16 + type u16) — 4 bytes.
pub const NLATTR_HDR_LEN: usize = 4;

/// netlink message flags.
pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_ACK: u16 = 0x04;

/// nfnetlink subsystem id for the packet queue.
pub const NFNL_SUBSYS_QUEUE: u16 = 3;
/// NFQNL message types (low byte of the netlink message type).
pub const NFQNL_MSG_PACKET: u8 = 0;
pub const NFQNL_MSG_VERDICT: u8 = 1;
pub const NFQNL_MSG_CONFIG: u8 = 2;

/// Address families used in the nfgenmsg / config command.
pub const AF_UNSPEC: u8 = 0;
pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;
pub const NFNETLINK_V0: u8 = 0;

/// Config commands (nfqnl_msg_config_cmd.command).
pub const NFQNL_CFG_CMD_BIND: u8 = 1;
pub const NFQNL_CFG_CMD_UNBIND: u8 = 2;
/// Config attribute types.
pub const NFQA_CFG_CMD: u16 = 1;
pub const NFQA_CFG_PARAMS: u16 = 2;
/// Copy modes (nfqnl_msg_config_params.copy_mode).
pub const NFQNL_COPY_NONE: u8 = 0;
pub const NFQNL_COPY_META: u8 = 1;
pub const NFQNL_COPY_PACKET: u8 = 2;

/// Packet-message attribute types.
pub const NFQA_PACKET_HDR: u16 = 1;
pub const NFQA_PAYLOAD: u16 = 10;
/// Verdict attribute type. NOTE: this is 2 in the kernel's nfqnl_attr_type
/// enum (NFQA_UNSPEC=0, NFQA_PACKET_HDR=1, NFQA_VERDICT_HDR=2) — distinct from
/// the config-attribute enum where NFQA_CFG_CMD=1. Getting this wrong makes the
/// kernel silently ignore the verdict and the queued packet stalls.
pub const NFQA_VERDICT_HDR: u16 = 2;

/// netfilter verdicts (linux/netfilter.h).
pub const NF_DROP: u32 = 0;
pub const NF_ACCEPT: u32 = 1;

/// Compose the full netlink message type for an NFQNL message:
/// `(subsys << 8) | msg_type`.
pub fn nfqnl_type(msg: u8) -> u16 {
    (NFNL_SUBSYS_QUEUE << 8) | (msg as u16)
}

/// Round a length up to the 4-byte netlink alignment (NLMSG_ALIGN / NLA_ALIGN).
pub fn nl_align(len: usize) -> usize {
    (len + 3) & !3
}

/// Build one netlink message: 16-byte nlmsghdr + nfgenmsg + the supplied
/// attribute blob. `nlmsghdr.len` covers the whole (unaligned) message.
fn build_message(
    msg_type: u8,
    flags: u16,
    seq: u32,
    family: u8,
    res_id: u16,
    attrs: &[u8],
) -> Vec<u8> {
    let total = NLMSGHDR_LEN + NFGENMSG_LEN + attrs.len();
    let mut m = Vec::with_capacity(nl_align(total));
    // struct nlmsghdr (host endian)
    m.extend_from_slice(&(total as u32).to_ne_bytes());
    m.extend_from_slice(&nfqnl_type(msg_type).to_ne_bytes());
    m.extend_from_slice(&flags.to_ne_bytes());
    m.extend_from_slice(&seq.to_ne_bytes());
    m.extend_from_slice(&0u32.to_ne_bytes()); // pid = 0 (kernel fills)
                                              // struct nfgenmsg: family u8, version u8, res_id u16 (network order)
    m.push(family);
    m.push(NFNETLINK_V0);
    m.extend_from_slice(&res_id.to_be_bytes());
    m.extend_from_slice(attrs);
    m
}

/// Encode one nlattr (TLV), 4-byte aligned with zero padding. `attr_len`
/// in the header is the unpadded length including the 4-byte header.
fn push_attr(out: &mut Vec<u8>, attr_type: u16, payload: &[u8]) {
    let len = NLATTR_HDR_LEN + payload.len();
    out.extend_from_slice(&(len as u16).to_ne_bytes());
    out.extend_from_slice(&attr_type.to_ne_bytes());
    out.extend_from_slice(payload);
    let pad = nl_align(len) - len;
    out.extend(std::iter::repeat_n(0u8, pad));
}

/// Build an NFQNL_MSG_CONFIG message that (un)binds the given protocol family
/// to the queue subsystem. `pf` is AF_INET / AF_INET6 / AF_UNSPEC.
pub fn build_config_cmd(queue_num: u16, seq: u32, command: u8, pf: u8) -> Vec<u8> {
    // nfqnl_msg_config_cmd { command u8, _pad u8, pf u16 (BE) }
    let mut cmd = Vec::with_capacity(4);
    cmd.push(command);
    cmd.push(0); // _pad
    cmd.extend_from_slice(&(pf as u16).to_be_bytes());
    let mut attrs = Vec::new();
    push_attr(&mut attrs, NFQA_CFG_CMD, &cmd);
    build_message(
        NFQNL_MSG_CONFIG,
        NLM_F_REQUEST,
        seq,
        AF_UNSPEC,
        queue_num,
        &attrs,
    )
}

/// Build an NFQNL_MSG_CONFIG message that sets the queue copy mode/range.
/// For an observer we want NFQNL_COPY_PACKET with a range large enough to
/// carry the L3/L4 headers we decode (full packet by default).
pub fn build_config_params(queue_num: u16, seq: u32, copy_mode: u8, copy_range: u32) -> Vec<u8> {
    // nfqnl_msg_config_params { copy_range u32 (BE), copy_mode u8 } (packed)
    let mut params = Vec::with_capacity(5);
    params.extend_from_slice(&copy_range.to_be_bytes());
    params.push(copy_mode);
    let mut attrs = Vec::new();
    push_attr(&mut attrs, NFQA_CFG_PARAMS, &params);
    build_message(
        NFQNL_MSG_CONFIG,
        NLM_F_REQUEST,
        seq,
        AF_UNSPEC,
        queue_num,
        &attrs,
    )
}

/// Build an NFQNL_MSG_VERDICT message resolving packet `packet_id` with
/// `verdict` (e.g. NF_ACCEPT). The observer always ACCEPTs.
pub fn build_verdict(queue_num: u16, seq: u32, packet_id: u32, verdict: u32) -> Vec<u8> {
    // nfqnl_msg_verdict_hdr { verdict u32 (BE), id u32 (BE) }
    let mut vh = Vec::with_capacity(8);
    vh.extend_from_slice(&verdict.to_be_bytes());
    vh.extend_from_slice(&packet_id.to_be_bytes());
    let mut attrs = Vec::new();
    push_attr(&mut attrs, NFQA_VERDICT_HDR, &vh);
    build_message(
        NFQNL_MSG_VERDICT,
        NLM_F_REQUEST,
        seq,
        AF_UNSPEC,
        queue_num,
        &attrs,
    )
}

/// Result of parsing one `NFQNL_MSG_PACKET` message from the kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPacket<'a> {
    /// Packet id to echo back in the verdict.
    pub packet_id: u32,
    /// Raw L3 payload (IPv4/IPv6 packet) to feed to the decoder. Empty if the
    /// kernel was not configured to copy the packet.
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    TooShortForHeader,
    NotNfqueuePacket { msg_type: u16 },
    TruncatedAttribute,
    MissingPacketHdr,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShortForHeader => write!(f, "buffer shorter than nlmsghdr+nfgenmsg"),
            Self::NotNfqueuePacket { msg_type } => {
                write!(
                    f,
                    "netlink message type {msg_type} is not an NFQUEUE packet"
                )
            }
            Self::TruncatedAttribute => write!(f, "nlattr runs past end of message"),
            Self::MissingPacketHdr => write!(f, "NFQNL_MSG_PACKET without NFQA_PACKET_HDR"),
        }
    }
}
impl std::error::Error for ParseError {}

/// Parse a single `NFQNL_MSG_PACKET` netlink message, returning the packet id
/// (for the verdict) and the raw L3 payload (for the decoder).
pub fn parse_packet_message(buf: &[u8]) -> Result<ParsedPacket<'_>, ParseError> {
    if buf.len() < NLMSGHDR_LEN + NFGENMSG_LEN {
        return Err(ParseError::TooShortForHeader);
    }
    let msg_type = u16::from_ne_bytes([buf[4], buf[5]]);
    if msg_type != nfqnl_type(NFQNL_MSG_PACKET) {
        return Err(ParseError::NotNfqueuePacket { msg_type });
    }
    // Skip nlmsghdr (16) + nfgenmsg (4) to reach the attribute stream.
    let mut off = NLMSGHDR_LEN + NFGENMSG_LEN;
    let mut packet_id: Option<u32> = None;
    let mut payload: &[u8] = &[];
    while off + NLATTR_HDR_LEN <= buf.len() {
        let attr_len = u16::from_ne_bytes([buf[off], buf[off + 1]]) as usize;
        let attr_type = u16::from_ne_bytes([buf[off + 2], buf[off + 3]]);
        if attr_len < NLATTR_HDR_LEN || off + attr_len > buf.len() {
            return Err(ParseError::TruncatedAttribute);
        }
        let val = &buf[off + NLATTR_HDR_LEN..off + attr_len];
        // NLA_TYPE_MASK: strip the nested/byteorder flag bits.
        match attr_type & 0x3fff {
            NFQA_PACKET_HDR => {
                if val.len() >= 4 {
                    packet_id = Some(u32::from_be_bytes([val[0], val[1], val[2], val[3]]));
                }
            }
            NFQA_PAYLOAD => {
                payload = val;
            }
            _ => {}
        }
        off += nl_align(attr_len);
    }
    match packet_id {
        Some(packet_id) => Ok(ParsedPacket { packet_id, payload }),
        None => Err(ParseError::MissingPacketHdr),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nl_align_rounds_to_four() {
        assert_eq!(nl_align(0), 0);
        assert_eq!(nl_align(1), 4);
        assert_eq!(nl_align(4), 4);
        assert_eq!(nl_align(5), 8);
        assert_eq!(nl_align(13), 16);
    }

    #[test]
    fn kernel_abi_attribute_values_are_pinned() {
        // These are kernel UAPI constants (linux/netfilter/nfnetlink_queue.h).
        // The verdict and config enums are SEPARATE: NFQA_VERDICT_HDR=2 lives
        // in nfqnl_attr_type while NFQA_CFG_CMD=1 lives in the config enum.
        assert_eq!(NFQA_PACKET_HDR, 1);
        assert_eq!(NFQA_VERDICT_HDR, 2);
        assert_eq!(NFQA_PAYLOAD, 10);
        assert_eq!(NFQA_CFG_CMD, 1);
        assert_eq!(NFQA_CFG_PARAMS, 2);
        assert_eq!(NFQNL_COPY_PACKET, 2);
        assert_eq!(NF_ACCEPT, 1);
    }

    #[test]
    fn nfqnl_type_packs_subsys() {
        assert_eq!(nfqnl_type(NFQNL_MSG_VERDICT), (3u16 << 8) | 1);
        assert_eq!(nfqnl_type(NFQNL_MSG_CONFIG), (3u16 << 8) | 2);
    }

    #[test]
    fn config_cmd_layout() {
        let m = build_config_cmd(7, 42, NFQNL_CFG_CMD_BIND, AF_INET);
        // nlmsghdr.len covers whole message
        assert_eq!(
            u32::from_ne_bytes([m[0], m[1], m[2], m[3]]) as usize,
            m.len()
        );
        assert_eq!(
            u16::from_ne_bytes([m[4], m[5]]),
            nfqnl_type(NFQNL_MSG_CONFIG)
        );
        // nfgenmsg.res_id (queue) is big-endian at offset 18
        assert_eq!(u16::from_be_bytes([m[18], m[19]]), 7);
        // attr: NFQA_CFG_CMD with command + pf(BE)
        let attr_type = u16::from_ne_bytes([m[22], m[23]]);
        assert_eq!(attr_type, NFQA_CFG_CMD);
        assert_eq!(m[24], NFQNL_CFG_CMD_BIND);
        assert_eq!(u16::from_be_bytes([m[26], m[27]]), AF_INET as u16);
    }

    #[test]
    fn config_params_sets_copy_packet() {
        let m = build_config_params(7, 1, NFQNL_COPY_PACKET, 0xffff);
        let attr_type = u16::from_ne_bytes([m[22], m[23]]);
        assert_eq!(attr_type, NFQA_CFG_PARAMS);
        assert_eq!(u32::from_be_bytes([m[24], m[25], m[26], m[27]]), 0xffff);
        assert_eq!(m[28], NFQNL_COPY_PACKET);
    }

    #[test]
    fn verdict_layout_is_accept() {
        let m = build_verdict(7, 9, 0xdead_beef, NF_ACCEPT);
        assert_eq!(
            u16::from_ne_bytes([m[4], m[5]]),
            nfqnl_type(NFQNL_MSG_VERDICT)
        );
        let attr_type = u16::from_ne_bytes([m[22], m[23]]);
        assert_eq!(attr_type, NFQA_VERDICT_HDR);
        assert_eq!(u32::from_be_bytes([m[24], m[25], m[26], m[27]]), NF_ACCEPT);
        assert_eq!(
            u32::from_be_bytes([m[28], m[29], m[30], m[31]]),
            0xdead_beef
        );
    }

    /// Build a synthetic NFQNL_MSG_PACKET like the kernel would, then parse it.
    fn synth_packet_message(packet_id: u32, payload: &[u8]) -> Vec<u8> {
        let mut attrs = Vec::new();
        // NFQA_PACKET_HDR { packet_id BE, hw_protocol BE, hook u8 }
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&packet_id.to_be_bytes());
        hdr.extend_from_slice(&0x0800u16.to_be_bytes()); // ETH_P_IP
        hdr.push(0); // hook
        push_attr(&mut attrs, NFQA_PACKET_HDR, &hdr);
        push_attr(&mut attrs, NFQA_PAYLOAD, payload);
        build_message(NFQNL_MSG_PACKET, 0, 0, AF_INET, 0, &attrs)
    }

    #[test]
    fn parse_round_trip_extracts_id_and_payload() {
        let payload = b"\x45\x00\x00\x28 some ipv4 bytes";
        let m = synth_packet_message(0x1234_5678, payload);
        let parsed = parse_packet_message(&m).expect("parse");
        assert_eq!(parsed.packet_id, 0x1234_5678);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn parse_rejects_wrong_message_type() {
        let m = build_verdict(1, 1, 1, NF_ACCEPT);
        assert!(matches!(
            parse_packet_message(&m),
            Err(ParseError::NotNfqueuePacket { .. })
        ));
    }

    #[test]
    fn parse_rejects_short_buffer() {
        assert_eq!(
            parse_packet_message(&[0u8; 8]),
            Err(ParseError::TooShortForHeader)
        );
    }

    #[test]
    fn parse_missing_packet_hdr_errors() {
        // Message with only a payload attr, no NFQA_PACKET_HDR.
        let mut attrs = Vec::new();
        push_attr(&mut attrs, NFQA_PAYLOAD, b"x");
        let m = build_message(NFQNL_MSG_PACKET, 0, 0, AF_INET, 0, &attrs);
        assert_eq!(parse_packet_message(&m), Err(ParseError::MissingPacketHdr));
    }

    #[test]
    fn parse_handles_payload_with_padding() {
        // 3-byte payload forces 1 byte of NLA padding before end-of-message.
        let m = synth_packet_message(7, &[0xaa, 0xbb, 0xcc]);
        let parsed = parse_packet_message(&m).expect("parse");
        assert_eq!(parsed.payload, &[0xaa, 0xbb, 0xcc]);
        assert_eq!(parsed.packet_id, 7);
    }
}
