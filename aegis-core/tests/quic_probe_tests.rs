//! QUIC helpers и probe.

use aegis_core::probe::RstProbe;
use aegis_core::protocols::quic::{
    coalesce_datagrams, looks_like_quic_long_header, pad_initial_datagram,
};

#[test]
fn rst_ttl_heuristic() {
    assert_eq!(
        RstProbe::from_ttl_pair(Some(120), 64),
        RstProbe::LikelyRemote
    );
    assert_eq!(
        RstProbe::from_ttl_pair(Some(10), 64),
        RstProbe::PossiblyMiddlebox
    );
    assert_eq!(RstProbe::from_ttl_pair(None, 64), RstProbe::Unknown);
}

#[test]
fn quic_pad_and_coalesce() {
    let mut p = vec![0x80, 0, 0, 0, 0, 0, 0, 0x39]; // long header-ish
    pad_initial_datagram(&mut p, 1200);
    assert_eq!(p.len(), 1200);
    let c = coalesce_datagrams(&[1, 2, 3], &[4, 5], 2000);
    assert!(c.len() >= 5);
}

#[test]
fn quic_long_header_detection() {
    // Long Header: бит 0x80 + версия != 0 (0 — только Version Negotiation).
    let pkt = vec![0x80u8, 0, 0, 0, 1, 0, 0, 0x39];
    assert!(looks_like_quic_long_header(&pkt));
    assert!(!looks_like_quic_long_header(&[0x10]));
}
