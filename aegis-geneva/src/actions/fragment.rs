//! `fragment`: split one packet into two at a byte offset.
//!
//! At the IP layer this models IP fragmentation (the second piece carries no
//! TCP header, and the first is marked more-fragments); at the TCP layer it
//! models segmentation (both pieces are full segments, the second's sequence
//! number advanced). The distinction matters: censors that reassemble one layer
//! but not the other are exactly what this primitive is for.

use crate::packet::field::Proto;
use crate::packet::model::{Packet, IP_FLAG_MORE_FRAGMENTS};
use crate::syntax::action::FragmentOrder;

/// Split `packet` at `offset` bytes into its payload.
///
/// The offset is clamped to the payload length, so an offset past the end
/// yields an empty second piece rather than an error — evolution generates
/// out-of-range offsets constantly and they must stay harmless.
pub fn apply(packet: &Packet, proto: Proto, offset: u16, order: FragmentOrder) -> (Packet, Packet) {
    let split = (offset as usize).min(packet.payload.len());

    let mut first = packet.clone();
    let mut second = packet.clone();
    first.payload = packet.payload[..split].to_vec();
    second.payload = packet.payload[split..].to_vec();

    match proto {
        Proto::Ip => {
            // IP fragments: only the first carries the transport header, and
            // it is marked "more fragments". The tail keeps whatever MF the
            // original had, so splitting an already-split packet still
            // describes one datagram.
            let original_mf = packet.ip.flags & IP_FLAG_MORE_FRAGMENTS;
            first.ip.flags |= IP_FLAG_MORE_FRAGMENTS;
            second.tcp = None;
            second.ip.flags = (second.ip.flags & !IP_FLAG_MORE_FRAGMENTS) | original_mf;
            // Where this piece sits in the original datagram — without it a
            // receiver cannot put the datagram back together.
            second.ip.frag_offset = packet.ip.frag_offset + split as u16;
        }
        Proto::Udp => {
            // UDP segmentation is not a grammar primitive. Parser/live executor refuse it.
            return (packet.clone(), packet.clone());
        }
        Proto::Tcp => {
            // TCP segments: the second continues the sequence space.
            if let Some(tcp) = second.tcp.as_mut() {
                tcp.seq = tcp.seq.wrapping_add(split as u32);
            }
        }
    }

    match order {
        FragmentOrder::InOrder => (first, second),
        FragmentOrder::Reversed => (second, first),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_split_divides_the_payload_and_advances_seq() {
        let p = Packet::tcp_data(b"abcdefgh");
        let (a, b) = apply(&p, Proto::Tcp, 3, FragmentOrder::InOrder);
        assert_eq!(a.payload, b"abc");
        assert_eq!(b.payload, b"defgh");
        assert_eq!(b.tcp.as_ref().unwrap().seq, p.tcp.as_ref().unwrap().seq + 3);
    }

    #[test]
    fn ip_split_drops_the_transport_header_from_the_tail() {
        let p = Packet::tcp_data(b"abcdefgh");
        let (a, b) = apply(&p, Proto::Ip, 4, FragmentOrder::InOrder);
        assert!(a.tcp.is_some());
        assert!(b.tcp.is_none(), "IP fragments repeat no TCP header");
        assert_ne!(a.ip.flags & IP_FLAG_MORE_FRAGMENTS, 0);
        assert_eq!(b.ip.flags & IP_FLAG_MORE_FRAGMENTS, 0);
    }

    #[test]
    fn ip_split_records_the_fragment_offset() {
        let p = Packet::tcp_data(b"abcdefgh");
        let (a, b) = apply(&p, Proto::Ip, 4, FragmentOrder::InOrder);
        assert_eq!(a.ip.frag_offset, 0);
        assert_eq!(b.ip.frag_offset, 4);
        assert_eq!(a.ip.id, b.ip.id, "fragments of one datagram share an id");
        assert!(a.is_ip_fragment() && b.is_ip_fragment());
    }

    #[test]
    fn nested_ip_splits_keep_offsets_absolute() {
        let p = Packet::tcp_data(b"abcdefgh");
        let (head, tail) = apply(&p, Proto::Ip, 2, FragmentOrder::InOrder);
        let (mid, last) = apply(&tail, Proto::Ip, 3, FragmentOrder::InOrder);
        assert_eq!(head.ip.frag_offset, 0);
        assert_eq!(mid.ip.frag_offset, 2);
        assert_eq!(last.ip.frag_offset, 5);
        // Only the final piece ends the datagram.
        assert_ne!(mid.ip.flags & IP_FLAG_MORE_FRAGMENTS, 0);
        assert_eq!(last.ip.flags & IP_FLAG_MORE_FRAGMENTS, 0);
    }

    #[test]
    fn reversed_order_emits_the_tail_first() {
        let p = Packet::tcp_data(b"abcdefgh");
        let (a, b) = apply(&p, Proto::Tcp, 3, FragmentOrder::Reversed);
        assert_eq!(a.payload, b"defgh");
        assert_eq!(b.payload, b"abc");
    }

    #[test]
    fn offsets_past_the_end_are_clamped() {
        let p = Packet::tcp_data(b"abc");
        let (a, b) = apply(&p, Proto::Tcp, 9000, FragmentOrder::InOrder);
        assert_eq!(a.payload, b"abc");
        assert!(b.payload.is_empty());
    }

    #[test]
    fn splitting_preserves_every_byte() {
        let p = Packet::tcp_data(b"abcdefgh");
        for offset in 0..12u16 {
            let (a, b) = apply(&p, Proto::Tcp, offset, FragmentOrder::InOrder);
            let mut joined = a.payload.clone();
            joined.extend_from_slice(&b.payload);
            assert_eq!(
                joined, p.payload,
                "offset {offset} lost or duplicated bytes"
            );
        }
    }
}
