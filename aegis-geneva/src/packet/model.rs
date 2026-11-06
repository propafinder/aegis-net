//! The packet model actions operate on.
//!
//! Deliberately a *model*, not a wire buffer: an IP header, an optional TCP
//! header, and a payload, with typed field access. Evolution and the engine
//! never touch raw bytes, so the whole trainer runs offline and every action is
//! unit-testable. Serialising a model back to the wire is the job of whatever
//! transport eventually executes a strategy.

use super::field::Field;

/// TCP flag bits, in the wire order.
pub mod tcp_flags {
    pub const FIN: u16 = 0x01;
    pub const SYN: u16 = 0x02;
    pub const RST: u16 = 0x04;
    pub const PSH: u16 = 0x08;
    pub const ACK: u16 = 0x10;
    pub const URG: u16 = 0x20;

    /// Parse Geneva's letter form, e.g. `"SA"` -> SYN|ACK.
    pub fn parse(text: &str) -> Option<u16> {
        let mut bits = 0u16;
        for c in text.chars() {
            bits |= match c.to_ascii_uppercase() {
                'F' => FIN,
                'S' => SYN,
                'R' => RST,
                'P' => PSH,
                'A' => ACK,
                'U' => URG,
                'E' => 0x40,
                'C' => 0x80,
                'N' => 0x100,
                _ => return None,
            };
        }
        Some(bits)
    }

    /// Every bit the letter form can express.
    pub const KNOWN: u16 = FIN | SYN | RST | PSH | ACK | URG | 0x1c0;

    /// Render to the letter form only if every set bit has a letter.
    ///
    /// A value carrying an unnamed bit (evolution produces these constantly)
    /// has no exact letter form, and rendering it anyway would silently drop
    /// the bit — the text would then parse back to a *different* value.
    pub fn render_exact(bits: u16) -> Option<String> {
        (bits & !KNOWN == 0).then(|| render(bits))
    }

    /// Render back to the letter form, in wire-bit order.
    pub fn render(bits: u16) -> String {
        let mut out = String::new();
        for (bit, letter) in [
            (FIN, 'F'),
            (SYN, 'S'),
            (RST, 'R'),
            (PSH, 'P'),
            (ACK, 'A'),
            (URG, 'U'),
            (0x40, 'E'),
            (0x80, 'C'),
            (0x100, 'N'),
        ] {
            if bits & bit != 0 {
                out.push(letter);
            }
        }
        out
    }
}

/// IP "more fragments" flag bit.
pub const IP_FLAG_MORE_FRAGMENTS: u16 = 0x2000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpHeader {
    pub ttl: u8,
    pub flags: u16,
    /// Datagram identifier. Fragments of one datagram share it; unrelated
    /// datagrams must not, or reassembly will splice them together.
    pub id: u16,
    pub checksum: u16,
    /// Offset of this fragment's payload within the original datagram.
    pub frag_offset: u16,
}

impl Default for IpHeader {
    fn default() -> Self {
        IpHeader {
            ttl: 64,
            flags: 0,
            // Non-zero so two unfragmented packets are never mistaken for
            // fragments of one datagram.
            id: 1,
            checksum: 0,
            frag_offset: 0,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TcpHeader {
    pub flags: u16,
    pub seq: u32,
    pub ack: u32,
    pub window: u16,
    pub checksum: u16,
    pub data_offset: u8,
}

/// Which way a packet is travelling, which selects the strategy half that
/// applies to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Outbound,
    Inbound,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    /// Extended wire fields, populated only when the corresponding real layer exists.
    pub wire_fields: std::collections::BTreeMap<Field, u32>,
    pub ip: IpHeader,
    pub tcp: Option<TcpHeader>,
    pub payload: Vec<u8>,
    pub direction: Direction,
}

impl Packet {
    /// True if this packet is one piece of a fragmented IP datagram.
    pub fn is_ip_fragment(&self) -> bool {
        self.ip.flags & IP_FLAG_MORE_FRAGMENTS != 0 || self.ip.frag_offset > 0
    }

    /// A plain outbound TCP data packet — the common starting point in tests.
    pub fn tcp_data(payload: &[u8]) -> Self {
        Packet {
            wire_fields: Default::default(),
            ip: IpHeader::default(),
            tcp: Some(TcpHeader {
                flags: tcp_flags::PSH | tcp_flags::ACK,
                seq: 1,
                ack: 1,
                window: 65535,
                checksum: 0,
                data_offset: 5,
            }),
            payload: payload.to_vec(),
            direction: Direction::Outbound,
        }
    }

    /// Read a field, or `None` if the packet has no such layer.
    pub fn get(&self, field: Field) -> Option<u32> {
        match field {
            Field::Ttl => Some(u32::from(self.ip.ttl)),
            Field::IpFlags => Some(u32::from(self.ip.flags)),
            Field::IpId => Some(u32::from(self.ip.id)),
            Field::IpChecksum => Some(u32::from(self.ip.checksum)),
            Field::TcpFlags => self.tcp.as_ref().map(|t| u32::from(t.flags)),
            Field::Seq => self.tcp.as_ref().map(|t| t.seq),
            Field::Ack => self.tcp.as_ref().map(|t| t.ack),
            Field::Window => self.tcp.as_ref().map(|t| u32::from(t.window)),
            Field::TcpChecksum => self.tcp.as_ref().map(|t| u32::from(t.checksum)),
            Field::DataOffset => self.tcp.as_ref().map(|t| u32::from(t.data_offset)),
            _ => self.wire_fields.get(&field).copied(),
        }
    }

    /// Write a field. Returns false if the packet has no such layer; values are
    /// truncated to the field's width rather than rejected, because a censor
    /// sees whatever ends up on the wire.
    pub fn set(&mut self, field: Field, value: u32) -> bool {
        if let Some(mask) = field.wire_mask() {
            if let Some(slot) = self.wire_fields.get_mut(&field) {
                *slot = value & mask;
                return true;
            }
            return false;
        }
        match field {
            Field::Ttl => {
                self.ip.ttl = value as u8;
                true
            }
            Field::IpFlags => {
                self.ip.flags = value as u16;
                true
            }
            Field::IpId => {
                self.ip.id = value as u16;
                true
            }
            Field::IpChecksum => {
                self.ip.checksum = value as u16;
                true
            }
            _ => match self.tcp.as_mut() {
                None => false,
                Some(tcp) => {
                    match field {
                        Field::TcpFlags => tcp.flags = value as u16,
                        Field::Seq => tcp.seq = value,
                        Field::Ack => tcp.ack = value,
                        Field::Window => tcp.window = value as u16,
                        Field::TcpChecksum => tcp.checksum = value as u16,
                        Field::DataOffset => tcp.data_offset = value as u8,
                        _ => unreachable!("IP fields handled above"),
                    }
                    true
                }
            },
        }
    }

    pub fn has_flag(&self, flag: u16) -> bool {
        self.tcp.as_ref().is_some_and(|t| t.flags & flag != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYN_ACK: u16 = tcp_flags::SYN | tcp_flags::ACK;

    #[test]
    fn flag_letters_round_trip() {
        assert_eq!(tcp_flags::parse("S"), Some(tcp_flags::SYN));
        assert_eq!(
            tcp_flags::parse("SA"),
            Some(tcp_flags::SYN | tcp_flags::ACK)
        );
        assert_eq!(tcp_flags::render(tcp_flags::SYN | tcp_flags::ACK), "SA");
        assert_eq!(tcp_flags::parse("Z"), None);
    }

    #[test]
    fn unknown_flag_bits_have_no_letter_form() {
        assert_eq!(tcp_flags::render_exact(SYN_ACK), Some("SA".to_string()));
        assert_eq!(tcp_flags::render_exact(0x0240), None, "0x40 has no letter");
    }

    #[test]
    fn field_access_round_trips() {
        let mut p = Packet::tcp_data(b"hello");
        assert_eq!(p.get(Field::Ttl), Some(64));
        assert!(p.set(Field::Ttl, 3));
        assert_eq!(p.get(Field::Ttl), Some(3));
        assert!(p.set(Field::Seq, 4242));
        assert_eq!(p.get(Field::Seq), Some(4242));
    }

    #[test]
    fn tcp_fields_are_absent_without_a_tcp_layer() {
        let mut p = Packet::tcp_data(b"x");
        p.tcp = None;
        assert_eq!(p.get(Field::Seq), None);
        assert!(
            !p.set(Field::Seq, 1),
            "must refuse to write a missing layer"
        );
        // IP fields still work.
        assert!(p.set(Field::Ttl, 9));
    }

    #[test]
    fn oversized_values_truncate_to_field_width() {
        let mut p = Packet::tcp_data(b"x");
        p.set(Field::Ttl, 0x1ff);
        assert_eq!(p.get(Field::Ttl), Some(0xff));
        p.set(Field::Window, 0x1_0001);
        assert_eq!(p.get(Field::Window), Some(1));
    }
}
