//! How a censor looks at the packets it sees.
//!
//! Real censors differ in exactly the ways that decide whether an evasion
//! works: whether they reassemble a TCP stream or scan each packet alone,
//! whether they trust a packet with a bad checksum, whether they follow a
//! stream after a RST. Each of those is a knob here, so a strategy can be
//! evolved against one model and then honestly re-scored against another.

use crate::packet::model::{tcp_flags, Packet, IP_FLAG_MORE_FRAGMENTS};

/// Whether the censor joins packets into a stream before searching.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reassembly {
    /// Order by sequence number and search the joined bytes.
    Stream,
    /// Search each packet's payload on its own.
    PerPacket,
}

#[derive(Clone, Debug)]
pub struct Inspector {
    /// The content that gets a flow blocked.
    pub keyword: Vec<u8>,
    pub reassembly: Reassembly,
    /// If true, packets whose TCP checksum is non-zero (our model of "wrong")
    /// are ignored, as a strict middlebox would.
    pub validates_checksum: bool,
    /// If true, a RST makes the censor stop following the flow — so anything
    /// after an injected RST is invisible to it.
    pub gives_up_after_rst: bool,
    /// If true, the censor puts IP fragments back together before looking.
    /// Many middleboxes do not — which is precisely why IP fragmentation is an
    /// evasion at all. The *server* always does (see [`reassemble`]).
    pub reassembles_ip: bool,
}

impl Inspector {
    pub fn reassembling(keyword: &[u8]) -> Self {
        Inspector {
            keyword: keyword.to_vec(),
            reassembly: Reassembly::Stream,
            validates_checksum: false,
            gives_up_after_rst: false,
            reassembles_ip: true,
        }
    }

    pub fn per_packet(keyword: &[u8]) -> Self {
        Inspector {
            reassembly: Reassembly::PerPacket,
            reassembles_ip: false,
            ..Inspector::reassembling(keyword)
        }
    }

    /// How much of the keyword the censor sees contiguously, as a fraction.
    ///
    /// `1.0` means the whole keyword is visible in one place — detection. Lower
    /// values say how *close* the censor came, which is what makes the search
    /// landscape climbable: with a bare yes/no, every not-quite strategy scores
    /// the same as doing nothing and evolution degenerates into random search.
    /// Measured: with a binary signal the trainer never beat the baseline.
    pub fn exposure(&self, packets: &[&Packet]) -> f64 {
        if self.keyword.is_empty() {
            return 0.0;
        }
        let chunks = self.visible_chunks(packets);
        let longest = chunks
            .iter()
            .map(|bytes| longest_prefix_present(bytes, &self.keyword))
            .max()
            .unwrap_or(0);
        longest as f64 / self.keyword.len() as f64
    }

    fn visible_chunks(&self, packets: &[&Packet]) -> Vec<Vec<u8>> {
        let visible = self.visible(packets);
        match self.reassembly {
            Reassembly::PerPacket => {
                if self.reassembles_ip {
                    ip_reassemble(&visible)
                        .iter()
                        .map(|p| p.payload.clone())
                        .collect()
                } else {
                    visible.iter().map(|p| p.payload.clone()).collect()
                }
            }
            Reassembly::Stream => vec![reassemble_with(&visible, self.reassembles_ip)],
        }
    }

    fn visible<'p>(&self, packets: &[&'p Packet]) -> Vec<&'p Packet> {
        let mut visible: Vec<&Packet> = Vec::new();
        for packet in packets {
            if self.gives_up_after_rst && packet.has_flag(tcp_flags::RST) {
                break;
            }
            if self.validates_checksum && packet.tcp.as_ref().is_some_and(|t| t.checksum != 0) {
                continue;
            }
            visible.push(packet);
        }
        visible
    }

    /// Does the censor spot the keyword in what it can see?
    pub fn detects(&self, packets: &[&Packet]) -> bool {
        self.visible_chunks(packets)
            .iter()
            .any(|bytes| contains(bytes, &self.keyword))
    }
}

/// Put IP fragments back into whole datagrams.
///
/// Fragments of one datagram share an `ip.id` and are ordered by
/// `ip.frag_offset`; only the piece at offset 0 carries the transport header,
/// so the rebuilt datagram takes its headers from that piece. Packets that are
/// not fragments pass through untouched.
///
/// Without this step the tail of every IP fragmentation is silently discarded —
/// it has no TCP header, so stream reassembly skips it — and every
/// IP-fragmenting strategy looks like broken delivery. That would leave half
/// the action set unusable to the search while appearing to work.
pub fn ip_reassemble(packets: &[&Packet]) -> Vec<Packet> {
    let mut out: Vec<Packet> = Vec::new();
    let mut groups: Vec<(u16, Vec<Packet>)> = Vec::new();

    for packet in packets {
        if !packet.is_ip_fragment() {
            out.push((*packet).clone());
            continue;
        }
        match groups.iter_mut().find(|(id, _)| *id == packet.ip.id) {
            Some((_, pieces)) => pieces.push((*packet).clone()),
            None => groups.push((packet.ip.id, vec![(*packet).clone()])),
        }
    }

    for (_, mut pieces) in groups {
        pieces.sort_by_key(|p| p.ip.frag_offset);
        // The head carries the transport header; without it the datagram
        // cannot be delivered to TCP at all.
        let Some(head) = pieces.iter().find(|p| p.ip.frag_offset == 0).cloned() else {
            continue;
        };
        let mut whole = head;
        whole.payload = pieces.iter().flat_map(|p| p.payload.clone()).collect();
        whole.ip.flags &= !IP_FLAG_MORE_FRAGMENTS;
        whole.ip.frag_offset = 0;
        out.push(whole);
    }
    out
}

/// Rebuild the byte stream from packets, ordered by sequence number.
///
/// IP fragments are reassembled first, as a real stack does.
///
/// Overlapping segments are resolved first-writer-wins, which is what most
/// stacks do and — crucially — what makes overlapping-segment evasions
/// behave differently on a censor that resolves them the other way.
pub fn reassemble(packets: &[&Packet]) -> Vec<u8> {
    reassemble_with(packets, true)
}

/// As [`reassemble`], but able to model a receiver that does not put IP
/// fragments back together.
pub fn reassemble_with(packets: &[&Packet], reassemble_ip: bool) -> Vec<u8> {
    let owned: Vec<Packet>;
    let refs: Vec<&Packet> = if reassemble_ip {
        owned = ip_reassemble(packets);
        owned.iter().collect()
    } else {
        packets.to_vec()
    };
    reassemble_tcp(&refs)
}

fn reassemble_tcp(packets: &[&Packet]) -> Vec<u8> {
    let base = packets
        .iter()
        .filter_map(|p| p.tcp.as_ref().map(|t| t.seq))
        .min();
    let Some(base) = base else {
        // No TCP layer anywhere: concatenate in arrival order.
        return packets.iter().flat_map(|p| p.payload.clone()).collect();
    };

    let mut out: Vec<u8> = Vec::new();
    let mut written: Vec<bool> = Vec::new();
    for packet in packets {
        let Some(tcp) = packet.tcp.as_ref() else {
            continue;
        };
        let start = tcp.seq.wrapping_sub(base) as usize;
        let end = start + packet.payload.len();
        if out.len() < end {
            out.resize(end, 0);
            written.resize(end, false);
        }
        for (i, byte) in packet.payload.iter().enumerate() {
            if !written[start + i] {
                out[start + i] = *byte;
                written[start + i] = true;
            }
        }
    }

    // Truncate at the first gap: a stack cannot deliver past missing bytes.
    let end = written.iter().position(|w| !*w).unwrap_or(written.len());
    out.truncate(end);
    out
}

/// The length of the longest keyword *prefix* that appears anywhere in
/// `haystack` — how far the censor got towards a full match.
fn longest_prefix_present(haystack: &[u8], needle: &[u8]) -> usize {
    let mut best = 0;
    for len in (1..=needle.len()).rev() {
        if contains(haystack, &needle[..len]) {
            best = len;
            break;
        }
    }
    best
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(seq: u32, payload: &[u8]) -> Packet {
        let mut p = Packet::tcp_data(payload);
        p.tcp.as_mut().unwrap().seq = seq;
        p
    }

    #[test]
    fn reassembly_orders_by_sequence_number() {
        let a = seg(100, b"world");
        let b = seg(95, b"hello");
        assert_eq!(reassemble(&[&a, &b]), b"helloworld");
    }

    #[test]
    fn reassembly_stops_at_a_gap() {
        let a = seg(100, b"hello");
        let c = seg(200, b"world");
        assert_eq!(
            reassemble(&[&a, &c]),
            b"hello",
            "must not deliver past a gap"
        );
    }

    #[test]
    fn overlapping_segments_resolve_first_writer_wins() {
        let first = seg(100, b"AAAA");
        let overlap = seg(100, b"BBBB");
        assert_eq!(reassemble(&[&first, &overlap]), b"AAAA");
    }

    #[test]
    fn per_packet_inspection_misses_a_split_keyword() {
        let a = seg(100, b"GET /sec");
        let b = seg(108, b"ret");
        let per_packet = Inspector::per_packet(b"secret");
        let stream = Inspector::reassembling(b"secret");
        assert!(!per_packet.detects(&[&a, &b]));
        assert!(stream.detects(&[&a, &b]), "a stream censor joins them up");
    }

    #[test]
    fn checksum_validation_makes_bad_packets_invisible() {
        let mut bad = seg(100, b"secret");
        bad.tcp.as_mut().unwrap().checksum = 0xdead;

        let lax = Inspector::per_packet(b"secret");
        let strict = Inspector {
            validates_checksum: true,
            ..Inspector::per_packet(b"secret")
        };
        assert!(lax.detects(&[&bad]), "a lax censor still reads it");
        assert!(!strict.detects(&[&bad]), "a strict censor discards it");
    }

    #[test]
    fn an_injected_rst_can_blind_a_censor_that_follows_it() {
        let mut rst = seg(100, b"");
        rst.tcp.as_mut().unwrap().flags = tcp_flags::RST;
        let payload = seg(100, b"secret");

        let follows = Inspector {
            gives_up_after_rst: true,
            ..Inspector::per_packet(b"secret")
        };
        let ignores = Inspector::per_packet(b"secret");
        assert!(!follows.detects(&[&rst, &payload]));
        assert!(ignores.detects(&[&rst, &payload]));
    }

    #[test]
    fn ip_fragments_are_put_back_together() {
        use crate::actions::fragment;
        use crate::packet::field::Proto;
        use crate::syntax::action::FragmentOrder;

        let original = Packet::tcp_data(b"GET /secret HTTP/1.1");
        let (head, tail) = fragment::apply(&original, Proto::Ip, 8, FragmentOrder::InOrder);
        assert!(tail.tcp.is_none(), "the tail carries no transport header");

        // Reassembled: the whole payload comes back.
        assert_eq!(reassemble(&[&head, &tail]), original.payload);
        // A receiver that does not reassemble IP only sees the head.
        assert_eq!(reassemble_with(&[&head, &tail], false), b"GET /sec");
    }

    #[test]
    fn ip_reassembly_survives_reordering() {
        use crate::actions::fragment;
        use crate::packet::field::Proto;
        use crate::syntax::action::FragmentOrder;

        let original = Packet::tcp_data(b"GET /secret HTTP/1.1");
        let (tail, head) = fragment::apply(&original, Proto::Ip, 8, FragmentOrder::Reversed);
        assert_eq!(reassemble(&[&tail, &head]), original.payload);
    }

    #[test]
    fn unrelated_datagrams_are_not_spliced_together() {
        let a = seg(100, b"hello");
        let b = seg(105, b"world");
        assert!(!a.is_ip_fragment() && !b.is_ip_fragment());
        assert_eq!(reassemble(&[&a, &b]), b"helloworld");
    }

    #[test]
    fn ip_fragmentation_evades_a_censor_that_does_not_reassemble_ip() {
        use crate::actions::fragment;
        use crate::packet::field::Proto;
        use crate::syntax::action::FragmentOrder;

        let original = Packet::tcp_data(b"GET /secret HTTP/1.1");
        let (head, tail) = fragment::apply(&original, Proto::Ip, 8, FragmentOrder::InOrder);

        let blind = Inspector::per_packet(b"secret"); // reassembles_ip = false
        let thorough = Inspector {
            reassembles_ip: true,
            ..Inspector::per_packet(b"secret")
        };
        assert!(!blind.detects(&[&head, &tail]), "split across IP fragments");
        assert!(
            thorough.detects(&[&head, &tail]),
            "a thorough censor rejoins them"
        );
    }

    #[test]
    fn exposure_grades_how_close_the_censor_got() {
        let inspector = Inspector::per_packet(b"secret");
        let none = seg(100, b"nothing here");
        let partial = seg(100, b"GET /sec");
        let full = seg(100, b"GET /secret");

        assert_eq!(inspector.exposure(&[&none]), 0.0);
        assert_eq!(inspector.exposure(&[&full]), 1.0);
        let mid = inspector.exposure(&[&partial]);
        assert!(
            mid > 0.0 && mid < 1.0,
            "expected a partial score, got {mid}"
        );
        assert!(
            inspector.exposure(&[&partial]) > inspector.exposure(&[&none]),
            "closer must score higher"
        );
    }

    #[test]
    fn exposure_agrees_with_detection_at_the_extremes() {
        let inspector = Inspector::per_packet(b"secret");
        let full = seg(100, b"GET /secret");
        assert!(inspector.detects(&[&full]));
        assert_eq!(inspector.exposure(&[&full]), 1.0);

        let split_a = seg(100, b"GET /sec");
        let split_b = seg(108, b"ret");
        assert!(!inspector.detects(&[&split_a, &split_b]));
        assert!(inspector.exposure(&[&split_a, &split_b]) < 1.0);
    }

    #[test]
    fn an_empty_keyword_never_matches() {
        let p = seg(100, b"anything");
        assert!(!Inspector::per_packet(b"").detects(&[&p]));
    }
}
