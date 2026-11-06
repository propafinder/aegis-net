//! A censor on the path, modelled by distance.
//!
//! The censor sits `censor_hops` away and the server `server_hops` away, with
//! the censor nearer. That single fact is what makes TTL tricks work: a packet
//! whose TTL expires between the two is seen by the censor and never by the
//! server. Modelling distance rather than hand-waving "the censor sees some
//! packets" is what lets evolution rediscover the trick on its own.

use crate::packet::model::Packet;

use super::inspection::Inspector;
use super::model::{Censor, Outcome};

pub struct PathCensor {
    pub name: String,
    /// Hops to the censor. A packet needs `ttl > censor_hops` to reach it.
    pub censor_hops: u8,
    /// Hops to the server, always greater than `censor_hops`.
    pub server_hops: u8,
    pub inspector: Inspector,
}

impl PathCensor {
    /// A censor three hops out, server ten hops out, reassembling TCP.
    pub fn typical(keyword: &[u8]) -> Self {
        PathCensor {
            name: "path-censor".to_string(),
            censor_hops: 3,
            server_hops: 10,
            inspector: Inspector::reassembling(keyword),
        }
    }

    fn reaches(&self, packet: &Packet, hops: u8) -> bool {
        packet.ip.ttl > hops
    }
}

impl Censor for PathCensor {
    fn evaluate(&self, packets: &[Packet]) -> Outcome {
        let seen_by_censor: Vec<&Packet> = packets
            .iter()
            .filter(|p| self.reaches(p, self.censor_hops))
            .collect();
        let seen_by_server: Vec<&Packet> = packets
            .iter()
            .filter(|p| self.reaches(p, self.server_hops))
            .collect();

        // Bytes shown to the censor but not to the server: packets that
        // outlive the censor's distance yet die before the server's.
        let decoy_bytes = packets
            .iter()
            .filter(|p| self.reaches(p, self.censor_hops) && !self.reaches(p, self.server_hops))
            .map(|p| p.payload.len())
            .sum();

        Outcome {
            censored: self.inspector.detects(&seen_by_censor),
            exposure: self.inspector.exposure(&seen_by_censor),
            decoy_bytes,
            // The server is a normal stack: it reassembles IP fragments and
            // then the TCP stream.
            delivered: super::inspection::reassemble(&seen_by_server),
        }
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::model::Packet;

    fn packet_with_ttl(ttl: u8, payload: &[u8]) -> Packet {
        let mut p = Packet::tcp_data(payload);
        p.ip.ttl = ttl;
        p
    }

    #[test]
    fn a_plain_send_is_caught() {
        let censor = PathCensor::typical(b"secret");
        let out = censor.evaluate(&[packet_with_ttl(64, b"GET /secret")]);
        assert!(out.censored);
        assert_eq!(out.delivered, b"GET /secret");
    }

    #[test]
    fn a_packet_that_expires_before_the_censor_is_invisible_to_it() {
        let censor = PathCensor::typical(b"secret");
        let out = censor.evaluate(&[packet_with_ttl(2, b"GET /secret")]);
        assert!(!out.censored);
        assert!(
            out.delivered.is_empty(),
            "it never reached the server either"
        );
    }

    #[test]
    fn a_packet_that_dies_between_censor_and_server_is_seen_only_by_the_censor() {
        let censor = PathCensor::typical(b"secret");
        let out = censor.evaluate(&[packet_with_ttl(5, b"GET /secret")]);
        assert!(out.censored, "the censor is nearer, so it still sees this");
        assert!(out.delivered.is_empty(), "the server does not");
    }

    #[test]
    fn decoy_bytes_count_only_what_the_server_never_sees() {
        let censor = PathCensor::typical(b"secret");
        // Reaches both: not a decoy.
        assert_eq!(
            censor.evaluate(&[packet_with_ttl(64, b"abcd")]).decoy_bytes,
            0
        );
        // Dies before the censor: nobody saw it.
        assert_eq!(
            censor.evaluate(&[packet_with_ttl(2, b"abcd")]).decoy_bytes,
            0
        );
        // Dies between the two: this is a decoy.
        assert_eq!(
            censor.evaluate(&[packet_with_ttl(5, b"abcd")]).decoy_bytes,
            4
        );
    }

    #[test]
    fn the_ttl_decoy_evasion_works_against_a_non_reassembling_censor() {
        // Decoy carries the keyword but expires early; the real packet carries
        // a payload the censor never joins up with it.
        let censor = PathCensor {
            name: "per-packet".into(),
            censor_hops: 3,
            server_hops: 10,
            inspector: Inspector::per_packet(b"secret"),
        };
        let decoy = packet_with_ttl(4, b"harmless");
        let real = packet_with_ttl(64, b"GET /secret");
        // Sanity: sending the real packet alone is caught.
        assert!(censor.evaluate(std::slice::from_ref(&real)).censored);
        // Splitting the keyword across two packets defeats a per-packet censor.
        let mut first = packet_with_ttl(64, b"GET /sec");
        let mut second = packet_with_ttl(64, b"ret");
        second.tcp.as_mut().unwrap().seq = first.tcp.as_ref().unwrap().seq + 8;
        first.payload = b"GET /sec".to_vec();
        let out = censor.evaluate(&[decoy, first, second]);
        assert!(
            !out.censored,
            "a per-packet censor cannot see across a split"
        );
        assert_eq!(out.delivered, b"GET /secret");
    }

    #[test]
    fn a_reassembling_censor_defeats_a_plain_split() {
        let censor = PathCensor::typical(b"secret");
        let mut first = packet_with_ttl(64, b"GET /sec");
        let mut second = packet_with_ttl(64, b"ret");
        second.tcp.as_mut().unwrap().seq = first.tcp.as_ref().unwrap().seq + 8;
        first.payload = b"GET /sec".to_vec();
        assert!(censor.evaluate(&[first, second]).censored);
    }
}
