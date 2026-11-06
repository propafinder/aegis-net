//! End-to-end check on the ClientHello this crate actually emits.
//!
//! The session is driven far enough to produce its first flight, the CRYPTO
//! bytes are parsed back, and the result is asserted to be Chrome-shaped:
//! TLS 1.3-only, Chrome's three suites, GREASE, X25519MLKEM768 first, ALPN h3,
//! and the QUIC transport-parameters extension. The JA4 is printed so it can be
//! diffed against a live Chrome capture (the M1 DONE gate).

#![cfg(feature = "boring")]

use std::sync::Arc;

use aegis_quic_boring::config::ctx::Trust;
use aegis_quic_boring::fingerprint::clienthello::{ext, parse};
use aegis_quic_boring::fingerprint::ja4::{compute, Transport};
use aegis_quic_boring::session::client_config::ChromeQuicClientConfig;
use quinn_proto::crypto::ClientConfig;
use quinn_proto::transport_parameters::TransportParameters;

/// Drive a fresh session and return its first-flight CRYPTO bytes.
fn client_hello_bytes(server_name: &str) -> Vec<u8> {
    let config = Arc::new(
        ChromeQuicClientConfig::new(vec![b"h3".to_vec()], Trust::System)
            .expect("build Chrome QUIC client config"),
    );
    // `TransportParameters::default()` is crate-private, so decode a minimal
    // real block: initial_max_data (id 0x04) = 1000. It must be non-empty —
    // BoringSSL rejects an empty parameter block.
    let encoded: &[u8] = &[0x04, 0x02, 0x43, 0xe8];
    let params = TransportParameters::read(quinn_proto::Side::Server, &mut &encoded[..])
        .expect("decode transport parameters");
    let mut session = config
        .start_session(1, server_name, &params)
        .expect("start session");

    let mut buf = Vec::new();
    session.write_handshake(&mut buf);
    assert!(!buf.is_empty(), "session produced no ClientHello");
    buf
}

#[test]
fn emits_a_chrome_shaped_quic_client_hello() {
    let bytes = client_hello_bytes("example.com");
    let hello = parse(&bytes).expect("parse our own ClientHello");

    // TLS 1.3 only — QUIC forbids anything older (RFC 9001 §4.2).
    assert_eq!(hello.max_version(), 0x0304, "must offer TLS 1.3");
    assert!(
        !hello.supported_versions.contains(&0x0303),
        "must not offer TLS 1.2 on QUIC: {:04x?}",
        hello.supported_versions
    );

    // Chrome's three TLS 1.3 suites, in Chrome's order.
    let profile = aegis_chrome_profile::chrome_stable();
    let cipher_ids = profile
        .quic
        .tls13_ciphers
        .iter()
        .map(|name| aegis_chrome_profile::cipher_id(name).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        hello.real_cipher_suites(),
        cipher_ids,
        "cipher suites/order differ from the profile"
    );

    // No GREASE: live Chrome does not GREASE its QUIC ClientHello (unlike its
    // TCP one). Measured in tests/chrome_live_ja4.rs.
    assert_eq!(
        hello.uses_grease(),
        profile.quic.grease,
        "GREASE does not match the QUIC profile: ciphers={:04x?} exts={:04x?}",
        hello.cipher_suites,
        hello.extensions
    );

    // Chrome's group order, post-quantum first.
    let group_ids = profile
        .quic
        .groups
        .iter()
        .map(|name| aegis_chrome_profile::group_id(name).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        hello.supported_groups, group_ids,
        "supported groups differ from the Chrome profile"
    );

    // Chrome's signature algorithms, in order.
    assert_eq!(
        hello.signature_algorithms, profile.quic.signature_algorithms,
        "signature algorithms differ from the Chrome profile"
    );

    // HTTP/3 and the QUIC transport parameters extension.
    assert_eq!(hello.alpn, vec![b"h3".to_vec()], "ALPN must be h3");
    assert!(
        hello.has_extension(ext::QUIC_TRANSPORT_PARAMETERS),
        "quic_transport_parameters (57) missing: {:?}",
        hello.extensions
    );
    assert_eq!(hello.server_name.as_deref(), Some("example.com"));

    let ja4 = compute(&hello, Transport::Quic);
    println!("AEGIS QUIC JA4  = {ja4}");
    println!("  ciphers  = {}", ja4.cipher_input);
    println!("  ext+sig  = {}", ja4.extension_input);

    // The `a` segment is fully determined by the profile, so pin it here; the
    // b/c hashes are compared against a live Chrome capture separately.
    assert!(ja4.a.starts_with("q13d"), "JA4_a = {}", ja4.a);
    assert!(ja4.a.ends_with("h3"), "JA4_a = {}", ja4.a);
}

/// Extension order must vary between connections (Chrome permutes), while the
/// order-independent parts of the fingerprint stay identical.
#[test]
fn extension_order_is_permuted_but_ja4_is_stable() {
    let mut orders = std::collections::HashSet::new();
    let mut ja4s = std::collections::HashSet::new();

    for _ in 0..12 {
        let hello = parse(&client_hello_bytes("example.com")).unwrap();
        orders.insert(hello.real_extensions());
        ja4s.insert(compute(&hello, Transport::Quic).to_string());
    }

    if aegis_chrome_profile::chrome_stable()
        .quic
        .permute_extensions
    {
        assert!(
            orders.len() > 1,
            "extension order never changed — permute_extensions is not in effect"
        );
    }
    assert_eq!(
        ja4s.len(),
        1,
        "JA4 must be stable across permutations, got {ja4s:?}"
    );
}

/// A literal IP destination must not carry SNI (browsers omit it), which JA4
/// records as `i`.
#[test]
fn ip_destination_omits_sni() {
    let hello = parse(&client_hello_bytes("192.0.2.10")).unwrap();
    assert_eq!(hello.server_name, None, "SNI must be omitted for an IP");
    assert!(compute(&hello, Transport::Quic).a.starts_with("q13i"));
}

/// Locked AWS-LC serializes custom extensions outside its built-in permutation.
/// The production context therefore omits this hint on every supported target.
#[test]
fn actual_quic_first_flight_omits_custom_trust_anchor_hint() {
    let hello = parse(&client_hello_bytes("example.com")).unwrap();
    assert!(hello.has_extension(ext::QUIC_TRANSPORT_PARAMETERS));
    assert_eq!(hello.alpn, vec![b"h3".to_vec()]);
    assert!(
        !hello.has_extension(0xca34),
        "custom TrustAnchorID must be omitted on every platform"
    );
}
