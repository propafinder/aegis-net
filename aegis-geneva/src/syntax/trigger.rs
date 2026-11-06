//! What makes a rule fire: a match on one header field.
//!
//! Geneva writes this as `[TCP:flags:S]` — protocol, field, value. A trigger is
//! deliberately narrow (one field, one value): expressiveness comes from
//! evolving many rules, not from complex predicates that would be hard to
//! mutate sensibly.

use crate::error::{Error, Result};
use crate::packet::field::{Field, Proto};
use crate::packet::model::{tcp_flags, Packet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trigger {
    pub field: Field,
    pub value: u32,
}

impl Trigger {
    pub fn new(field: Field, value: u32) -> Self {
        Trigger { field, value }
    }

    /// Same as [`Self::new`]; kept as an intention-revealing name at call sites
    /// that are choosing a TCP flag combination.
    ///
    /// There is no stored "print me as letters" flag: whether the letter form
    /// is used is decided from the value itself when printing, so it can never
    /// go stale after a mutation changes the value.
    pub fn flags(field: Field, value: u32) -> Self {
        Trigger::new(field, value)
    }

    /// Parse the inside of `[...]`, i.e. `PROTO:field:value`.
    pub fn parse(body: &str) -> Result<Self> {
        let mut parts = body.splitn(3, ':');
        let proto = parts
            .next()
            .ok_or_else(|| Error::Syntax("trigger is missing a protocol".into()))?;
        let name = parts
            .next()
            .ok_or_else(|| Error::Syntax("trigger is missing a field".into()))?;
        let value = parts
            .next()
            .ok_or_else(|| Error::Syntax("trigger is missing a value".into()))?;

        let proto = Proto::parse(proto.trim())?;
        let field = Field::parse(proto, name.trim())?;
        let value = value.trim();

        // TCP flags may be given as letters; everything else is numeric.
        if field == Field::TcpFlags {
            if let Some(bits) = tcp_flags::parse(value) {
                return Ok(Trigger::new(field, u32::from(bits)));
            }
        }
        if matches!(field, Field::IpSource | Field::IpDestination) && value.contains('.') {
            return value
                .parse::<std::net::Ipv4Addr>()
                .map(|ip| Trigger::new(field, u32::from(ip)))
                .map_err(|_| Error::BadFieldValue(field.to_string(), value.to_string()));
        }
        let parsed = if let Some(hex) = value.strip_prefix("0x") {
            u32::from_str_radix(hex, 16)
        } else {
            value.parse::<u32>()
        };
        parsed
            .map(|v| Trigger::new(field, v))
            .map_err(|_| Error::BadFieldValue(field.to_string(), value.to_string()))
    }

    /// Does this trigger fire on `packet`?
    ///
    /// A packet without the trigger's layer never matches — it cannot, and
    /// treating "absent" as "zero" would fire rules on packets they were never
    /// written for.
    pub fn matches(&self, packet: &Packet) -> bool {
        packet.get(self.field) == Some(self.value)
    }

    fn value_text(&self) -> String {
        // See `Action`'s printer: a value with an unnamed flag bit has no exact
        // letter form and must be printed numerically.
        if self.field == Field::TcpFlags {
            if let Some(letters) = tcp_flags::render_exact(self.value as u16) {
                return letters;
            }
        }
        self.value.to_string()
    }
}

impl std::fmt::Display for Trigger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}:{}]", self.field, self.value_text())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_flag_letters_and_numbers() {
        let t = Trigger::parse("TCP:flags:S").unwrap();
        assert_eq!(t.field, Field::TcpFlags);
        assert_eq!(t.value, u32::from(tcp_flags::SYN));
        assert_eq!(Trigger::parse("IP:ttl:64").unwrap().value, 64);
        assert_eq!(Trigger::parse("IP:ttl:0x10").unwrap().value, 16);
    }

    #[test]
    fn display_round_trips() {
        for text in ["[TCP:flags:SA]", "[IP:ttl:64]", "[TCP:seq:100]"] {
            let body = text.trim_start_matches('[').trim_end_matches(']');
            let t = Trigger::parse(body).unwrap();
            assert_eq!(t.to_string(), text);
        }
    }

    #[test]
    fn a_flag_value_with_an_unnamed_bit_prints_numerically() {
        let t = Trigger::flags(Field::TcpFlags, 0x240);
        assert_eq!(t.to_string(), "[TCP:flags:576]");
        let body = "TCP:flags:576";
        assert_eq!(Trigger::parse(body).unwrap().value, 0x240);
    }

    #[test]
    fn matches_only_the_named_layer_and_value() {
        let mut packet = Packet::tcp_data(b"x");
        packet.tcp.as_mut().unwrap().flags = tcp_flags::SYN;

        assert!(Trigger::parse("TCP:flags:S").unwrap().matches(&packet));
        assert!(!Trigger::parse("TCP:flags:A").unwrap().matches(&packet));
        assert!(Trigger::parse("IP:ttl:64").unwrap().matches(&packet));
    }

    #[test]
    fn a_missing_layer_never_matches() {
        let mut packet = Packet::tcp_data(b"x");
        packet.tcp = None;
        // Not even against value 0 — absent is not zero.
        assert!(!Trigger::parse("TCP:flags:0").unwrap().matches(&packet));
        assert!(!Trigger::parse("TCP:seq:0").unwrap().matches(&packet));
    }

    #[test]
    fn rejects_malformed_triggers() {
        assert!(Trigger::parse("TCP:flags").is_err());
        assert!(Trigger::parse("UDP:flags:S").is_err());
        assert!(Trigger::parse("TCP:nope:1").is_err());
        assert!(Trigger::parse("IP:ttl:notanumber").is_err());
    }
}
