//! Resolve only an exact IPv4 UDP ORIGINAL source tuple.
//!
//! A known malformed or ambiguous matching tuple is a refusal, not a missing
//! entry that permits a second lookup to choose a different destination.

use std::net::{Ipv4Addr, SocketAddrV4};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Lookup {
    Absent,
    Found(SocketAddrV4),
    Refused,
}

/// This is the production proc-to-netlink decision, including refusal custody.
pub(super) fn resolve_proc_or_else(
    table: Option<&str>,
    peer: SocketAddrV4,
    fallback: impl FnOnce(SocketAddrV4) -> Option<SocketAddrV4>,
) -> Option<SocketAddrV4> {
    match table
        .map(|table| parse_proc(table, peer))
        .unwrap_or(Lookup::Absent)
    {
        Lookup::Found(dst) => Some(dst),
        Lookup::Refused => None,
        Lookup::Absent => fallback(peer),
    }
}

pub(super) fn parse_proc(table: &str, peer: SocketAddrV4) -> Lookup {
    let mut result = Lookup::Absent;
    for line in table.lines() {
        match original_row(line, peer) {
            Lookup::Absent => {}
            Lookup::Refused => return Lookup::Refused,
            Lookup::Found(dst) => {
                if let Lookup::Found(prior) = result {
                    if prior != dst {
                        return Lookup::Refused;
                    }
                }
                result = Lookup::Found(dst);
            }
        }
    }
    result
}

fn original_row(line: &str, peer: SocketAddrV4) -> Lookup {
    let mut tokens = line.split_whitespace();
    let mut udp = false;
    let source = loop {
        let Some(token) = tokens.next() else {
            return Lookup::Absent;
        };
        if token == "udp" {
            if tokens.next() != Some("17") {
                return Lookup::Absent;
            }
            udp = true;
        } else if let Some(value) = token.strip_prefix("src=") {
            if !udp {
                return Lookup::Absent;
            }
            break value;
        }
    };
    if source.parse::<Ipv4Addr>().ok() != Some(*peer.ip()) {
        return Lookup::Absent;
    }
    let mut destination = None;
    let mut source_port = None;
    let mut destination_port = None;
    let mut duplicate = false;
    for token in tokens {
        // A second src= begins REPLY. No field from that tuple participates.
        if token.starts_with("src=") {
            break;
        }
        let field = if let Some(value) = token.strip_prefix("dst=") {
            Some((&mut destination, value))
        } else if let Some(value) = token.strip_prefix("sport=") {
            Some((&mut source_port, value))
        } else {
            token
                .strip_prefix("dport=")
                .map(|value| (&mut destination_port, value))
        };
        if let Some((slot, value)) = field {
            if slot.replace(value).is_some() {
                duplicate = true;
            }
        }
    }
    if duplicate {
        return Lookup::Refused;
    }
    let Some(port) = source_port.and_then(|value| value.parse::<u16>().ok()) else {
        return Lookup::Refused;
    };
    if port != peer.port() {
        return Lookup::Absent;
    }
    let (Some(ip), Some(port)) = (
        destination.and_then(|value| value.parse::<Ipv4Addr>().ok()),
        destination_port.and_then(|value| value.parse::<u16>().ok()),
    ) else {
        return Lookup::Refused;
    };
    Lookup::Found(SocketAddrV4::new(ip, port))
}

#[cfg(all(test, target_os = "linux"))]
pub(super) fn parse_conntrack_original_dst_v4(
    table: &str,
    peer: SocketAddrV4,
) -> Option<SocketAddrV4> {
    match parse_proc(table, peer) {
        Lookup::Found(dst) => Some(dst),
        Lookup::Absent | Lookup::Refused => None,
    }
}

pub(super) const CTA_TUPLE_ORIG: u16 = 1;
pub(super) const CTA_TUPLE_IP: u16 = 1;
pub(super) const CTA_TUPLE_PROTO: u16 = 2;
pub(super) const CTA_IP_V4_SRC: u16 = 1;
pub(super) const CTA_IP_V4_DST: u16 = 2;
const CTA_PROTO_NUM: u16 = 1;
pub(super) const CTA_PROTO_SRC_PORT: u16 = 2;
pub(super) const CTA_PROTO_DST_PORT: u16 = 3;
const NLA_TYPE_MASK: u16 = 0x3fff;

/// Parse one entry, requiring UDP and a unique matching ORIGINAL destination.
/// This does not establish uniqueness across a multipart conntrack dump.
pub(super) fn parse_entry(attrs: &[u8], peer: SocketAddrV4) -> Lookup {
    let mut result = Lookup::Absent;
    for attribute in NlAttrs::new(attrs) {
        let Ok((atype, payload)) = attribute else {
            return Lookup::Refused;
        };
        if atype & NLA_TYPE_MASK != CTA_TUPLE_ORIG {
            continue;
        }
        match original_tuple(payload, peer) {
            Lookup::Absent => {}
            Lookup::Refused => return Lookup::Refused,
            Lookup::Found(dst) => {
                if let Lookup::Found(prior) = result {
                    if prior != dst {
                        return Lookup::Refused;
                    }
                }
                result = Lookup::Found(dst);
            }
        }
    }
    result
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), ()> {
    if slot.replace(value).is_some() {
        Err(())
    } else {
        Ok(())
    }
}

struct OriginalTuple {
    source: Option<Ipv4Addr>,
    destination: Option<Ipv4Addr>,
    source_port: Option<u16>,
    destination_port: Option<u16>,
    protocol: Option<u8>,
}

fn tuple_fields(payload: &[u8]) -> Result<OriginalTuple, ()> {
    let (mut source, mut destination, mut source_port, mut destination_port, mut protocol) =
        (None, None, None, None, None);
    let (mut saw_ip, mut saw_protocol) = (false, false);
    for attribute in NlAttrs::new(payload) {
        let (atype, payload) = attribute?;
        match atype & NLA_TYPE_MASK {
            CTA_TUPLE_IP => {
                if saw_ip {
                    return Err(());
                }
                saw_ip = true;
                for attribute in NlAttrs::new(payload) {
                    let (atype, value) = attribute?;
                    match atype & NLA_TYPE_MASK {
                        CTA_IP_V4_SRC | CTA_IP_V4_DST => {
                            let bytes: [u8; 4] = value.try_into().map_err(|_| ())?;
                            let address = Ipv4Addr::from(bytes);
                            if atype & NLA_TYPE_MASK == CTA_IP_V4_SRC {
                                set_once(&mut source, address)?;
                            } else {
                                set_once(&mut destination, address)?;
                            }
                        }
                        _ => {}
                    }
                }
            }
            CTA_TUPLE_PROTO => {
                if saw_protocol {
                    return Err(());
                }
                saw_protocol = true;
                for attribute in NlAttrs::new(payload) {
                    let (atype, value) = attribute?;
                    match atype & NLA_TYPE_MASK {
                        CTA_PROTO_NUM => {
                            let [value]: [u8; 1] = value.try_into().map_err(|_| ())?;
                            set_once(&mut protocol, value)?;
                        }
                        CTA_PROTO_SRC_PORT | CTA_PROTO_DST_PORT => {
                            let bytes: [u8; 2] = value.try_into().map_err(|_| ())?;
                            let port = u16::from_be_bytes(bytes);
                            if atype & NLA_TYPE_MASK == CTA_PROTO_SRC_PORT {
                                set_once(&mut source_port, port)?;
                            } else {
                                set_once(&mut destination_port, port)?;
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    Ok(OriginalTuple {
        source,
        destination,
        source_port,
        destination_port,
        protocol,
    })
}

fn original_tuple(payload: &[u8], peer: SocketAddrV4) -> Lookup {
    let Ok(tuple) = tuple_fields(payload) else {
        return Lookup::Refused;
    };
    if tuple.protocol != Some(17) {
        return Lookup::Absent;
    }
    if tuple.source != Some(*peer.ip()) || tuple.source_port != Some(peer.port()) {
        return Lookup::Absent;
    }
    match (tuple.destination, tuple.destination_port) {
        (Some(ip), Some(port)) => Lookup::Found(SocketAddrV4::new(ip, port)),
        _ => Lookup::Refused,
    }
}

#[cfg(test)]
pub(super) fn orig_dst_from_attrs(attrs: &[u8], peer: SocketAddrV4) -> Option<SocketAddrV4> {
    match parse_entry(attrs, peer) {
        Lookup::Found(dst) => Some(dst),
        Lookup::Absent | Lookup::Refused => None,
    }
}

struct NlAttrs<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> NlAttrs<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, off: 0 }
    }
}

impl<'a> Iterator for NlAttrs<'a> {
    type Item = Result<(u16, &'a [u8]), ()>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.off == self.buf.len() {
            return None;
        }
        if self.buf.len() - self.off < 4 {
            self.off = self.buf.len();
            return Some(Err(()));
        }
        let len = u16::from_ne_bytes([self.buf[self.off], self.buf[self.off + 1]]) as usize;
        let atype = u16::from_ne_bytes([self.buf[self.off + 2], self.buf[self.off + 3]]);
        if len < 4 || len > self.buf.len() - self.off {
            self.off = self.buf.len();
            return Some(Err(()));
        }
        let payload = &self.buf[self.off + 4..self.off + len];
        self.off = self.off.saturating_add((len + 3) & !3).min(self.buf.len());
        Some(Ok((atype, payload)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn peer() -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 1200)
    }

    fn dst() -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 1), 443)
    }

    fn other_dst() -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 2), 444)
    }

    fn row(source: Ipv4Addr, sport: u16, destination: SocketAddrV4) -> String {
        format!(
            "ipv4 2 udp 17 29 src={source} dst={} sport={sport} dport={} [UNREPLIED] src=203.0.113.1 dst=203.0.113.2 sport=9000 dport=9001 mark=0 use=1\n",
            destination.ip(), destination.port()
        )
    }

    fn resolve_without_fallback(table: &str) -> Option<SocketAddrV4> {
        resolve_proc_or_else(Some(table), peer(), |_| None)
    }

    #[test]
    fn proc_source_address_prefix_does_not_select_original() {
        let table = row(Ipv4Addr::new(192, 0, 2, 10), peer().port(), dst());
        assert_eq!(resolve_without_fallback(&table), None);
    }

    #[test]
    fn proc_source_port_prefix_does_not_select_original() {
        let table = row(*peer().ip(), 12001, dst());
        assert_eq!(resolve_without_fallback(&table), None);
    }

    #[test]
    fn proc_reply_source_does_not_select_original() {
        let table = "ipv4 2 udp 17 29 src=203.0.113.1 dst=198.51.100.1 sport=9000 dport=443 src=192.0.2.1 dst=198.51.100.2 sport=1200 dport=444 mark=0 use=1\n";
        assert_eq!(resolve_without_fallback(table), None);
    }

    #[test]
    fn proc_original_source_cannot_borrow_reply_port() {
        let table = "ipv4 2 udp 17 29 src=192.0.2.1 dst=198.51.100.1 sport=9000 dport=443 src=203.0.113.1 dst=198.51.100.2 sport=1200 dport=444 mark=0 use=1\n";
        assert_eq!(resolve_without_fallback(table), None);
    }

    #[test]
    fn proc_ambiguous_destination_refuses_without_netlink_fallback() {
        let table = row(*peer().ip(), peer().port(), dst())
            + &row(*peer().ip(), peer().port(), other_dst());
        let calls = Cell::new(0);
        let result = resolve_proc_or_else(Some(&table), peer(), |_| {
            calls.set(calls.get() + 1);
            Some(other_dst())
        });
        assert_eq!(result, None);
        assert_eq!(calls.get(), 0);
        assert_eq!(parse_proc(&table, peer()), Lookup::Refused);
    }

    #[test]
    fn proc_malformed_matching_original_refuses_without_fallback() {
        let table = "ipv4 2 udp 17 29 src=192.0.2.1 dst=invalid sport=1200 dport=443 src=203.0.113.1 dst=203.0.113.2 sport=9000 dport=9001\n";
        let calls = Cell::new(0);
        let result = resolve_proc_or_else(Some(table), peer(), |_| {
            calls.set(calls.get() + 1);
            Some(other_dst())
        });
        assert_eq!(result, None);
        assert_eq!(calls.get(), 0);
        assert_eq!(parse_proc(table, peer()), Lookup::Refused);
    }

    #[test]
    fn proc_repeated_same_destination_retains_original() {
        let original = row(*peer().ip(), peer().port(), dst());
        let table = original.clone() + &original;
        let calls = Cell::new(0);
        let result = resolve_proc_or_else(Some(&table), peer(), |_| {
            calls.set(calls.get() + 1);
            None
        });
        assert_eq!(result, Some(dst()));
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn proc_absent_or_unavailable_uses_original_fallback_once() {
        let calls = Cell::new(0);
        for table in [
            None,
            Some(""),
            Some("ipv4 2 tcp 6 29 src=192.0.2.1 dst=198.51.100.1 sport=1200 dport=443\n"),
        ] {
            assert_eq!(
                resolve_proc_or_else(table, peer(), |actual_peer| {
                    assert_eq!(actual_peer, peer());
                    calls.set(calls.get() + 1);
                    Some(dst())
                }),
                Some(dst())
            );
        }
        assert_eq!(calls.get(), 3);
    }

    fn nla(kind: u16, payload: &[u8]) -> Vec<u8> {
        let len = 4 + payload.len();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(len as u16).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(payload);
        while bytes.len() % 4 != 0 {
            bytes.push(0);
        }
        bytes
    }

    fn tuple(
        protocol: Option<u8>,
        destination: SocketAddrV4,
        second_dst: Option<Ipv4Addr>,
    ) -> Vec<u8> {
        const NESTED: u16 = 0x8000;
        let mut ip = nla(CTA_IP_V4_SRC, &peer().ip().octets());
        ip.extend(nla(CTA_IP_V4_DST, &destination.ip().octets()));
        if let Some(second) = second_dst {
            ip.extend(nla(CTA_IP_V4_DST, &second.octets()));
        }
        let mut proto = Vec::new();
        if let Some(protocol) = protocol {
            proto.extend(nla(1, &[protocol]));
        }
        proto.extend(nla(CTA_PROTO_SRC_PORT, &peer().port().to_be_bytes()));
        proto.extend(nla(CTA_PROTO_DST_PORT, &destination.port().to_be_bytes()));
        let mut original = nla(CTA_TUPLE_IP | NESTED, &ip);
        original.extend(nla(CTA_TUPLE_PROTO | NESTED, &proto));
        nla(CTA_TUPLE_ORIG | NESTED, &original)
    }

    #[test]
    fn netlink_tcp_tuple_does_not_select_udp_destination() {
        let attrs = tuple(Some(6), dst(), None);
        assert_eq!(parse_entry(&attrs, peer()), Lookup::Absent);
    }

    #[test]
    fn netlink_missing_protocol_does_not_select_udp_destination() {
        let attrs = tuple(None, dst(), None);
        assert_eq!(parse_entry(&attrs, peer()), Lookup::Absent);
    }

    #[test]
    fn netlink_duplicate_destination_refuses_instead_of_overwriting() {
        let attrs = tuple(Some(17), dst(), Some(*other_dst().ip()));
        assert_eq!(parse_entry(&attrs, peer()), Lookup::Refused);
    }

    #[test]
    fn netlink_conflicting_originals_refuse_instead_of_first_match() {
        let mut attrs = tuple(Some(17), dst(), None);
        attrs.extend(tuple(Some(17), other_dst(), None));
        assert_eq!(parse_entry(&attrs, peer()), Lookup::Refused);
    }

    #[test]
    fn netlink_original_udp_positive_preserves_destination() {
        let attrs = tuple(Some(17), dst(), None);
        assert_eq!(parse_entry(&attrs, peer()), Lookup::Found(dst()));
        assert_eq!(orig_dst_from_attrs(&attrs, peer()), Some(dst()));
    }

    #[test]
    fn netlink_nonmatching_original_cannot_become_reply_match() {
        let attrs = tuple(Some(17), dst(), None);
        let unrelated = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 2), peer().port());
        assert_eq!(parse_entry(&attrs, unrelated), Lookup::Absent);
    }
}
