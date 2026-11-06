//! Тесты tls_parse (общая фикстура в common).

mod common;

use aegis_core::protocols::ja3::{
    ja3_client_fingerprint_string, ja3_client_md5_hex, ja3s_server_fingerprint_string,
    ja3s_server_md5_hex,
};
use aegis_core::protocols::tls::{
    client_hello_alpn_protocols, client_hello_signature_algorithms, client_hello_supported_versions,
};
use aegis_core::protocols::tls_parse::{
    parse_client_hello, parse_client_hello_core, patch_sni_same_length,
};

#[test]
fn ja3s_minimal_matches_known_md5() {
    let pkt = common::server_hello_minimal();
    assert!(aegis_core::protocols::tls::is_likely_tls_server_hello(&pkt));
    assert_eq!(
        ja3s_server_fingerprint_string(&pkt).as_deref(),
        Some("771,47,")
    );
    assert_eq!(
        ja3s_server_md5_hex(&pkt).as_deref(),
        Some("5397c414a9ebeaff1bf18b70ca22eaa0")
    );
}

#[test]
fn ja3_synthetic_matches_known_md5() {
    let pkt = common::client_hello_with_sni("x.example");
    assert_eq!(
        ja3_client_fingerprint_string(&pkt).as_deref(),
        Some("771,47,0,,")
    );
    assert_eq!(
        ja3_client_md5_hex(&pkt).as_deref(),
        Some("6169fabc98e3e6c9690301eaf306d632")
    );
}

#[test]
fn parse_supported_versions_from_fixture() {
    let pkt = common::client_hello_with_sni_and_supported_versions("v.example");
    assert_eq!(
        client_hello_supported_versions(&pkt),
        Some(vec![0x0304u16, 0x0303])
    );
}

#[test]
fn parse_alpn_and_sigalgs_from_fixture() {
    let pkt = common::client_hello_with_sni_alpn_sigalgs("x.example", "h2");
    assert_eq!(
        client_hello_signature_algorithms(&pkt).as_deref(),
        Some(&[0x0401u16, 0x0403][..])
    );
    assert_eq!(
        client_hello_alpn_protocols(&pkt),
        Some(vec!["h2".to_string()])
    );
}

#[test]
fn parse_client_hello_core_fixture() {
    let pkt = common::client_hello_with_sni("x.example");
    let c = parse_client_hello_core(&pkt).expect("core");
    assert_eq!(c.legacy_version, 0x0303);
    assert_eq!(c.cipher_suites, vec![0x002fu16]);
    assert_eq!(c.compression_methods, vec![0u8]);
    assert_eq!(c.extension_types, vec![0u16]);
}

#[test]
fn parse_multi_sni_lists_all_hostnames() {
    let pkt = common::client_hello_with_sni_two("a.example", "b.example");
    let v = parse_client_hello(&pkt).expect("parse");
    assert_eq!(v.sni_hostnames.len(), 2);
    let n0 = std::str::from_utf8(
        &pkt[v.sni_hostnames[0].0..v.sni_hostnames[0].0 + v.sni_hostnames[0].1],
    )
    .unwrap();
    let n1 = std::str::from_utf8(
        &pkt[v.sni_hostnames[1].0..v.sni_hostnames[1].0 + v.sni_hostnames[1].1],
    )
    .unwrap();
    assert_eq!(n0, "a.example");
    assert_eq!(n1, "b.example");
}

#[test]
fn parse_and_patch_same_len() {
    let mut pkt = common::client_hello_with_sni("abc.example.com");
    let v = parse_client_hello(&pkt).expect("parse");
    let r = v.sni_hostname_range.expect("range");
    patch_sni_same_length(&mut pkt, r, "xyz.example.com").expect("patch");
    let v2 = parse_client_hello(&pkt).expect("parse2");
    assert_eq!(v2.sni.as_deref(), Some("xyz.example.com"));
}
