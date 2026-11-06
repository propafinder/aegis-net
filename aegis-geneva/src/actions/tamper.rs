//! `tamper`: overwrite one header field, either with a fixed value or with a
//! random one.
//!
//! `corrupt` is what finds evasions nobody predicted — a checksum or offset the
//! censor validates but the endpoint tolerates (or the reverse).

use rand::Rng;

use crate::packet::field::Field;
use crate::packet::model::Packet;
use crate::syntax::action::TamperMode;

/// Apply the tamper in place. Returns false if the packet lacks the field's
/// layer, in which case the packet is left untouched.
pub fn apply<R: Rng + ?Sized>(
    packet: &mut Packet,
    field: Field,
    mode: &TamperMode,
    rng: &mut R,
) -> bool {
    let value = match mode {
        TamperMode::Replace(v) => *v,
        TamperMode::Corrupt => rng.gen::<u32>(),
        TamperMode::Add(delta) => match packet.get(field) {
            Some(value) => value.wrapping_add(*delta as u32),
            None => return false,
        },
    };
    packet.set(field, value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn rng() -> StdRng {
        StdRng::seed_from_u64(7)
    }

    #[test]
    fn replace_writes_the_given_value() {
        let mut p = Packet::tcp_data(b"x");
        assert!(apply(
            &mut p,
            Field::Ttl,
            &TamperMode::Replace(3),
            &mut rng()
        ));
        assert_eq!(p.ip.ttl, 3);
    }

    #[test]
    fn corrupt_changes_the_field() {
        let mut p = Packet::tcp_data(b"x");
        let before = p.tcp.as_ref().unwrap().seq;
        apply(&mut p, Field::Seq, &TamperMode::Corrupt, &mut rng());
        assert_ne!(p.tcp.as_ref().unwrap().seq, before);
    }

    #[test]
    fn corrupt_is_deterministic_for_a_seeded_rng() {
        let mut a = Packet::tcp_data(b"x");
        let mut b = Packet::tcp_data(b"x");
        apply(&mut a, Field::Seq, &TamperMode::Corrupt, &mut rng());
        apply(&mut b, Field::Seq, &TamperMode::Corrupt, &mut rng());
        assert_eq!(a, b, "a seeded run must be reproducible");
    }

    #[test]
    fn a_missing_layer_leaves_the_packet_untouched() {
        let mut p = Packet::tcp_data(b"x");
        p.tcp = None;
        let before = p.clone();
        assert!(!apply(
            &mut p,
            Field::Seq,
            &TamperMode::Replace(9),
            &mut rng()
        ));
        assert_eq!(p, before);
    }
}
