//! Payload tampering — the primitive that lets a censor and a server disagree.
//!
//! Header tampering alone cannot defeat a censor that reassembles the stream
//! exactly like the server does: both see the same bytes, so whatever the
//! server accepts, the censor reads. The classic evasions all work by making
//! the censor accept *different content* — a decoy segment carrying garbage
//! that expires before it reaches the server, or an overlapping segment the two
//! ends resolve differently. Both need the payload itself to be changeable.

use rand::Rng;

use crate::packet::model::Packet;

/// How a payload tamper rewrites the bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PayloadMode {
    /// Overwrite with fixed bytes.
    Replace(Vec<u8>),
    /// Overwrite with random bytes of the same length.
    Corrupt,
    /// Keep only the first `n` bytes.
    Truncate(u16),
}

/// Apply the tamper in place.
pub fn apply<R: Rng + ?Sized>(packet: &mut Packet, mode: &PayloadMode, rng: &mut R) {
    match mode {
        PayloadMode::Replace(bytes) => packet.payload = bytes.clone(),
        PayloadMode::Corrupt => {
            // Same length: a decoy that changes the segment's size would not
            // line up with the real one in a receiver's reassembly, which is
            // the whole point of sending it.
            for byte in packet.payload.iter_mut() {
                *byte = rng.gen();
            }
        }
        PayloadMode::Truncate(n) => packet.payload.truncate(*n as usize),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn rng() -> StdRng {
        StdRng::seed_from_u64(4)
    }

    #[test]
    fn replace_sets_exact_bytes() {
        let mut p = Packet::tcp_data(b"GET /secret");
        apply(
            &mut p,
            &PayloadMode::Replace(b"harmless".to_vec()),
            &mut rng(),
        );
        assert_eq!(p.payload, b"harmless");
    }

    #[test]
    fn corrupt_changes_content_but_keeps_length() {
        let mut p = Packet::tcp_data(b"GET /secret");
        let before = p.payload.clone();
        apply(&mut p, &PayloadMode::Corrupt, &mut rng());
        assert_eq!(p.payload.len(), before.len(), "length must not move");
        assert_ne!(p.payload, before);
    }

    #[test]
    fn truncate_keeps_a_prefix_and_never_grows() {
        let mut p = Packet::tcp_data(b"GET /secret");
        apply(&mut p, &PayloadMode::Truncate(4), &mut rng());
        assert_eq!(p.payload, b"GET ");

        let mut p = Packet::tcp_data(b"abc");
        apply(&mut p, &PayloadMode::Truncate(9000), &mut rng());
        assert_eq!(p.payload, b"abc", "truncating past the end is a no-op");
    }

    #[test]
    fn corrupt_is_reproducible_from_a_seed() {
        let mut a = Packet::tcp_data(b"GET /secret");
        let mut b = Packet::tcp_data(b"GET /secret");
        apply(&mut a, &PayloadMode::Corrupt, &mut rng());
        apply(&mut b, &PayloadMode::Corrupt, &mut rng());
        assert_eq!(a, b);
    }
}
