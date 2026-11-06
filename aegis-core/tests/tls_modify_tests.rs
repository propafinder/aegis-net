//! GREASE / obfuscation / opaque на синтетическом ClientHello.

mod common;
use common::{client_hello_with_sni, client_hello_with_sni_two};

use aegis_core::protocols::tls::sni_hostname_range;
use aegis_core::protocols::tls_modify::{
    inject_grease_extension, inject_opaque_extension, obfuscate_sni_case, replace_sni_hostname,
};

// Exact harmless 52-byte fixture from the frozen audit #37: record/body lengths
// fit the buffer, but the extension vector claims 16 bytes after the buffer ends.
fn audit37_lying_extension_length_client_hello() -> Vec<u8> {
    hex::decode("160301002f0100002b03030000000000000000000000000000000000000000000000000000000000000000000002130101000010")
        .expect("fixed synthetic ClientHello hex")
}

#[test]
fn audit37_lying_extensions_rejected_without_mutation_grease() {
    let original = audit37_lying_extension_length_client_hello();
    assert_eq!(original.len(), 52);
    let mut buf = original.clone();
    assert!(inject_grease_extension(&mut buf).is_err());
    assert_eq!(buf, original);
}

#[test]
fn audit37_lying_extensions_rejected_without_mutation_opaque() {
    let original = audit37_lying_extension_length_client_hello();
    let mut buf = original.clone();
    assert!(inject_opaque_extension(&mut buf, b"audit37").is_err());
    assert_eq!(buf, original);
}

#[test]
fn audit37_lying_extensions_rejected_without_mutation_sni() {
    let original = audit37_lying_extension_length_client_hello();
    let mut buf = original.clone();
    assert!(replace_sni_hostname(&mut buf, "benign.example").is_err());
    assert_eq!(buf, original);
}

fn audit37_assert_rejected_unchanged(original: &[u8]) {
    for mutation in ["grease", "opaque", "sni"] {
        let mut buf = original.to_vec();
        let result = match mutation {
            "grease" => inject_grease_extension(&mut buf),
            "opaque" => inject_opaque_extension(&mut buf, b"audit37"),
            "sni" => replace_sni_hostname(&mut buf, "benign.example"),
            _ => unreachable!(),
        };
        assert!(result.is_err(), "{mutation} accepted malformed ClientHello");
        assert_eq!(buf, original, "{mutation} changed a rejected ClientHello");
    }
}

fn audit37_write_outer_lengths(buf: &mut [u8]) {
    let record_len = buf.len() - 5;
    buf[3..5].copy_from_slice(&(record_len as u16).to_be_bytes());
    let handshake_len = buf.len() - 9;
    buf[6] = ((handshake_len >> 16) & 0xff) as u8;
    buf[7] = ((handshake_len >> 8) & 0xff) as u8;
    buf[8] = (handshake_len & 0xff) as u8;
}

#[test]
fn audit37_malformed_vector_bounds_rejected_without_mutation() {
    let valid = client_hello_with_sni("benign.example");
    let mut cases = Vec::new();
    let mut buf = valid.clone();
    buf[3..5].copy_from_slice(&((valid.len() - 4) as u16).to_be_bytes());
    cases.push(buf); // record extends past the available bytes
    let mut buf = valid.clone();
    buf[3..5].copy_from_slice(&((valid.len() - 6) as u16).to_be_bytes());
    cases.push(buf); // body extends past the first record
    let mut buf = valid.clone();
    buf[43] = u8::MAX;
    cases.push(buf); // session ID vector
    let mut buf = valid.clone();
    buf[44..46].copy_from_slice(&u16::MAX.to_be_bytes());
    cases.push(buf); // cipher suites vector
    let mut buf = valid.clone();
    buf[48] = u8::MAX;
    cases.push(buf); // compression methods vector
    let mut buf = valid.clone();
    buf[50..52].copy_from_slice(&u16::MAX.to_be_bytes());
    cases.push(buf); // extension vector
    let mut buf = valid.clone();
    buf[50..52].copy_from_slice(&0u16.to_be_bytes());
    cases.push(buf); // bytes outside the declared extension vector
    let mut buf = valid.clone();
    buf[54..56].copy_from_slice(&u16::MAX.to_be_bytes());
    cases.push(buf); // extension value exceeds the validated vector
    let mut buf = valid.clone();
    buf.push(0);
    audit37_write_outer_lengths(&mut buf);
    let extension_len = buf.len() - 52;
    buf[50..52].copy_from_slice(&(extension_len as u16).to_be_bytes());
    cases.push(buf); // incomplete extension header after an otherwise valid SNI
    let mut buf = valid;
    buf.extend_from_slice(&[0x00, 0x15, 0x00, 0x01]);
    audit37_write_outer_lengths(&mut buf);
    let extension_len = buf.len() - 52;
    buf[50..52].copy_from_slice(&(extension_len as u16).to_be_bytes());
    cases.push(buf); // malformed extension body after the first SNI
    for buf in cases {
        audit37_assert_rejected_unchanged(&buf);
    }
}

#[test]
fn audit37_fragmented_client_hello_rejected_without_mutation() {
    let valid = client_hello_with_sni("benign.example");
    let split = 42;
    let mut fragmented = valid[..split].to_vec();
    fragmented[3..5].copy_from_slice(&((split - 5) as u16).to_be_bytes());
    fragmented.extend_from_slice(&[0x16, 0x03, 0x03]);
    fragmented.extend_from_slice(&((valid.len() - split) as u16).to_be_bytes());
    fragmented.extend_from_slice(&valid[split..]);
    audit37_assert_rejected_unchanged(&fragmented);
}

#[test]
fn audit37_extra_handshake_in_first_record_rejected_without_mutation() {
    let mut buf = client_hello_with_sni("benign.example");
    buf.extend_from_slice(&[0x0e, 0x00, 0x00, 0x00]);
    let record_len = buf.len() - 5;
    buf[3..5].copy_from_slice(&(record_len as u16).to_be_bytes());
    audit37_assert_rejected_unchanged(&buf);
}

#[test]
fn audit37_every_truncated_prefix_rejected_without_mutation() {
    let valid = client_hello_with_sni("benign.example");
    for len in 0..valid.len() {
        audit37_assert_rejected_unchanged(&valid[..len]);
    }
}

#[test]
fn audit37_record_growth_overflow_rejected_without_mutation() {
    let mut buf = client_hello_with_sni("x.ex");
    let padding_len = usize::from(u16::MAX) + 5 - buf.len() - 4;
    buf.extend_from_slice(&[0x00, 0x15]);
    buf.extend_from_slice(&(padding_len as u16).to_be_bytes());
    buf.resize(buf.len() + padding_len, 0);
    audit37_write_outer_lengths(&mut buf);
    let extension_len = buf.len() - 52;
    buf[50..52].copy_from_slice(&(extension_len as u16).to_be_bytes());
    assert_eq!(buf.len(), usize::from(u16::MAX) + 5);
    audit37_assert_rejected_unchanged(&buf);
}

#[test]
fn audit37_oversized_opaque_payload_rejected_without_mutation() {
    let original = client_hello_with_sni("benign.example");
    let mut buf = original.clone();
    assert!(inject_opaque_extension(&mut buf, &vec![0; usize::from(u16::MAX) + 1]).is_err());
    assert_eq!(buf, original);
}

#[test]
fn audit37_complete_hello_preserves_following_record_for_each_mutation() {
    let trailing_record = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
    for mutation in ["grease", "opaque", "sni"] {
        let mut buf = client_hello_with_sni("x.ex");
        buf.extend_from_slice(&trailing_record);
        match mutation {
            "grease" => inject_grease_extension(&mut buf),
            "opaque" => inject_opaque_extension(&mut buf, b"audit37"),
            "sni" => replace_sni_hostname(&mut buf, "benign.example"),
            _ => unreachable!(),
        }
        .expect("complete first-record mutation");
        assert!(buf.ends_with(&trailing_record));
        let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        assert_eq!(5 + record_len + trailing_record.len(), buf.len());
        let handshake_len = ((buf[6] as usize) << 16) | ((buf[7] as usize) << 8) | buf[8] as usize;
        assert_eq!(4 + handshake_len, record_len);
        let parsed = aegis_core::protocols::tls_parse::parse_client_hello(&buf)
            .expect("rewritten ClientHello remains parseable");
        assert_eq!(parsed.sni_hostnames.len(), 1);
    }
}

#[test]
fn obfuscate_preserves_length() {
    let mut v = client_hello_with_sni("AbCdEfGh.example.com");
    let r = sni_hostname_range(&v).unwrap();
    let before = v[r.0..r.0 + r.1].to_vec();
    obfuscate_sni_case(&mut v, r);
    let after = v[r.0..r.0 + r.1].to_vec();
    assert_eq!(before.len(), after.len());
    assert_ne!(before, after);
}

#[test]
fn inject_grease_extends_record() {
    let mut v = client_hello_with_sni("t.example");
    let len_before = v.len();
    inject_grease_extension(&mut v).expect("grease");
    assert!(v.len() > len_before);
    assert!(aegis_core::protocols::tls::is_likely_tls_client_hello(&v));
}

#[test]
fn inject_opaque_extends() {
    let mut v = client_hello_with_sni("x.example");
    let lb = v.len();
    inject_opaque_extension(&mut v, &[1, 2, 3, 4]).expect("opaque");
    assert!(v.len() > lb);
}

#[test]
fn garbage_not_client_hello() {
    let mut v = vec![0u8; 20];
    assert!(inject_grease_extension(&mut v).is_err());
}

#[test]
fn replace_sni_shorter_hostname() {
    let mut v = client_hello_with_sni("verylong.subdomain.example.com");
    let lb = v.len();
    replace_sni_hostname(&mut v, "a.co").expect("replace");
    assert!(v.len() < lb);
    let r = sni_hostname_range(&v).expect("sni");
    let name = std::str::from_utf8(&v[r.0..r.0 + r.1]).unwrap();
    assert_eq!(name, "a.co");
}

#[test]
fn replace_sni_longer_hostname() {
    let mut v = client_hello_with_sni("x.ex");
    let lb = v.len();
    replace_sni_hostname(&mut v, "much.longer.host.name.example.org").expect("replace");
    assert!(v.len() > lb);
    let r = sni_hostname_range(&v).expect("sni");
    let name = std::str::from_utf8(&v[r.0..r.0 + r.1]).unwrap();
    assert_eq!(name, "much.longer.host.name.example.org");
}

#[test]
fn replace_sni_collapses_multi_to_single() {
    let mut v = client_hello_with_sni_two("first.internal", "second.internal");
    replace_sni_hostname(&mut v, "front.example").expect("replace");
    let r = sni_hostname_range(&v).expect("sni");
    let name = std::str::from_utf8(&v[r.0..r.0 + r.1]).unwrap();
    assert_eq!(name, "front.example");
    let pv = aegis_core::protocols::tls_parse::parse_client_hello(&v).expect("parse");
    assert_eq!(pv.sni_hostnames.len(), 1);
}
