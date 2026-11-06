//! Reserved destinations for one authenticated AUTO capture exchange.
//!
//! These are protocol identifiers, never addresses to resolve or dial. The
//! relay recognizes them only after the ordinary tunnel authentication and
//! returns one bounded challenge through that same carrier.

pub const TCP_HOST: &str = "192.0.2.251";
pub const UDP_HOST: &str = "100::ae91";
/// IPv4 generic-UDP REDIRECT uses a separate reserved target from TCP.
pub const UDP_IPV4_HOST: &str = "192.0.2.252";
pub const PORT: u16 = 18080;
pub const CHALLENGE_BYTES: usize = 32;
pub const MAX_SECONDS: u64 = 5;

pub fn tcp_target(host: &str, port: u16) -> bool {
    host == TCP_HOST && port == PORT
}

pub fn udp_target(host: &str, port: u16) -> bool {
    (host == UDP_HOST || host == UDP_IPV4_HOST) && port == PORT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exact_transport_specific_numeric_target_is_reserved() {
        assert!(tcp_target(TCP_HOST, PORT));
        assert!(udp_target(UDP_HOST, PORT));
        assert!(udp_target(UDP_IPV4_HOST, PORT));
        for (host, port) in [
            (TCP_HOST, PORT - 1),
            (UDP_HOST, PORT + 1),
            (UDP_IPV4_HOST, PORT - 1),
            ("192.0.2.250", PORT),
            ("100::ae90", PORT),
            ("aegis-auto-proof.invalid", PORT),
        ] {
            assert!(!tcp_target(host, port));
            assert!(!udp_target(host, port));
        }
        assert!(!tcp_target(UDP_HOST, PORT));
        assert!(!tcp_target(UDP_IPV4_HOST, PORT));
        assert!(!udp_target(TCP_HOST, PORT));
    }
}
