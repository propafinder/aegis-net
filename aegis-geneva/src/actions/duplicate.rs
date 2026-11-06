//! `duplicate`: emit two copies of the packet, one down each branch.
//!
//! This is the primitive behind most real evasions: send the censor one packet
//! and the server another, so the two disagree about the stream.

use crate::packet::model::Packet;

pub fn apply(packet: &Packet) -> (Packet, Packet) {
    (packet.clone(), packet.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_copies_equal_the_original() {
        let p = Packet::tcp_data(b"payload");
        let (a, b) = apply(&p);
        assert_eq!(a, p);
        assert_eq!(b, p);
    }

    #[test]
    fn copies_are_independent() {
        let p = Packet::tcp_data(b"payload");
        let (mut a, b) = apply(&p);
        a.ip.ttl = 1;
        assert_eq!(
            b.ip.ttl, p.ip.ttl,
            "mutating one copy must not touch the other"
        );
    }
}
