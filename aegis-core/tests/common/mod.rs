//! Общие фикстуры для интеграционных тестов.

/// Минимальный ClientHello с одним расширением SNI (RFC 6066).
pub fn client_hello_with_sni(hostname: &str) -> Vec<u8> {
    let host = hostname.as_bytes();
    assert!(host.len() <= 255);

    let mut inner = Vec::new();
    inner.push(0x00);
    inner.extend_from_slice(&(host.len() as u16).to_be_bytes());
    inner.extend_from_slice(host);

    let mut ext_data = Vec::new();
    ext_data.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    ext_data.extend_from_slice(&inner);

    let mut ext = Vec::new();
    ext.extend_from_slice(&[0x00, 0x00]);
    ext.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
    ext.extend_from_slice(&ext_data);

    let ext_total_len = ext.len();

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0x00);
    body.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]);
    body.extend_from_slice(&[0x01, 0x00]);
    body.extend_from_slice(&(ext_total_len as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    let hs_body_len = body.len();
    let mut hs = vec![
        0x01,
        ((hs_body_len >> 16) & 0xff) as u8,
        ((hs_body_len >> 8) & 0xff) as u8,
        (hs_body_len & 0xff) as u8,
    ];
    hs.extend_from_slice(&body);

    let rec_payload_len = hs.len();
    let mut rec = Vec::new();
    rec.push(0x16);
    rec.extend_from_slice(&[0x03, 0x01]);
    rec.extend_from_slice(&(rec_payload_len as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

/// ClientHello: SNI + `signature_algorithms` (13) + ALPN (16).
#[allow(dead_code)]
pub fn client_hello_with_sni_alpn_sigalgs(hostname: &str, alpn: &str) -> Vec<u8> {
    let host = hostname.as_bytes();
    let ap = alpn.as_bytes();
    assert!(host.len() <= 255 && ap.len() <= 255);

    let mut sni_inner = Vec::new();
    sni_inner.push(0x00);
    sni_inner.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sni_inner.extend_from_slice(host);
    let mut sni_ed = Vec::new();
    sni_ed.extend_from_slice(&(sni_inner.len() as u16).to_be_bytes());
    sni_ed.extend_from_slice(&sni_inner);
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&[0x00, 0x00]);
    sni_ext.extend_from_slice(&(sni_ed.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(&sni_ed);

    let sig_body = [0u8, 4, 0x04, 0x01, 0x04, 0x03];
    let mut sig_ext = Vec::new();
    sig_ext.extend_from_slice(&[0x00, 0x0d]);
    sig_ext.extend_from_slice(&(sig_body.len() as u16).to_be_bytes());
    sig_ext.extend_from_slice(&sig_body);

    let mut alpn_list = Vec::new();
    alpn_list.push(ap.len() as u8);
    alpn_list.extend_from_slice(ap);
    let mut alpn_val = Vec::new();
    alpn_val.extend_from_slice(&(alpn_list.len() as u16).to_be_bytes());
    alpn_val.extend_from_slice(&alpn_list);
    let mut alpn_ext = Vec::new();
    alpn_ext.extend_from_slice(&[0x00, 0x10]);
    alpn_ext.extend_from_slice(&(alpn_val.len() as u16).to_be_bytes());
    alpn_ext.extend_from_slice(&alpn_val);

    let mut ext = Vec::new();
    ext.extend_from_slice(&sni_ext);
    ext.extend_from_slice(&sig_ext);
    ext.extend_from_slice(&alpn_ext);

    let ext_total_len = ext.len();

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0x00);
    body.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]);
    body.extend_from_slice(&[0x01, 0x00]);
    body.extend_from_slice(&(ext_total_len as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    let hs_body_len = body.len();
    let mut hs = vec![
        0x01,
        ((hs_body_len >> 16) & 0xff) as u8,
        ((hs_body_len >> 8) & 0xff) as u8,
        (hs_body_len & 0xff) as u8,
    ];
    hs.extend_from_slice(&body);

    let rec_payload_len = hs.len();
    let mut rec = Vec::new();
    rec.push(0x16);
    rec.extend_from_slice(&[0x03, 0x01]);
    rec.extend_from_slice(&(rec_payload_len as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

/// ClientHello: SNI + `supported_versions` (43), TLS 1.3 + TLS 1.2.
#[allow(dead_code)]
pub fn client_hello_with_sni_and_supported_versions(hostname: &str) -> Vec<u8> {
    let host = hostname.as_bytes();
    assert!(host.len() <= 255);

    let mut sni_inner = Vec::new();
    sni_inner.push(0x00);
    sni_inner.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sni_inner.extend_from_slice(host);
    let mut sni_ed = Vec::new();
    sni_ed.extend_from_slice(&(sni_inner.len() as u16).to_be_bytes());
    sni_ed.extend_from_slice(&sni_inner);
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&[0x00, 0x00]);
    sni_ext.extend_from_slice(&(sni_ed.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(&sni_ed);

    let sv_val = [4u8, 0x03, 0x04, 0x03, 0x03];
    let mut sv_ext = Vec::new();
    sv_ext.extend_from_slice(&[0x00, 0x2b]);
    sv_ext.extend_from_slice(&(sv_val.len() as u16).to_be_bytes());
    sv_ext.extend_from_slice(&sv_val);

    let mut ext = Vec::new();
    ext.extend_from_slice(&sni_ext);
    ext.extend_from_slice(&sv_ext);

    let ext_total_len = ext.len();

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0x00);
    body.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]);
    body.extend_from_slice(&[0x01, 0x00]);
    body.extend_from_slice(&(ext_total_len as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    let hs_body_len = body.len();
    let mut hs = vec![
        0x01,
        ((hs_body_len >> 16) & 0xff) as u8,
        ((hs_body_len >> 8) & 0xff) as u8,
        (hs_body_len & 0xff) as u8,
    ];
    hs.extend_from_slice(&body);

    let rec_payload_len = hs.len();
    let mut rec = Vec::new();
    rec.push(0x16);
    rec.extend_from_slice(&[0x03, 0x01]);
    rec.extend_from_slice(&(rec_payload_len as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

/// ClientHello с **двумя** `host_name` в одном расширении SNI (редко, но допустимо по RFC 6066).
pub fn client_hello_with_sni_two(a: &str, b: &str) -> Vec<u8> {
    let h1 = a.as_bytes();
    let h2 = b.as_bytes();
    assert!(h1.len() <= 255 && h2.len() <= 255);

    let mut inner = Vec::new();
    inner.push(0x00);
    inner.extend_from_slice(&(h1.len() as u16).to_be_bytes());
    inner.extend_from_slice(h1);
    inner.push(0x00);
    inner.extend_from_slice(&(h2.len() as u16).to_be_bytes());
    inner.extend_from_slice(h2);

    let mut ext_data = Vec::new();
    ext_data.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    ext_data.extend_from_slice(&inner);

    let mut ext = Vec::new();
    ext.extend_from_slice(&[0x00, 0x00]);
    ext.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
    ext.extend_from_slice(&ext_data);

    let ext_total_len = ext.len();

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0x00);
    body.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]);
    body.extend_from_slice(&[0x01, 0x00]);
    body.extend_from_slice(&(ext_total_len as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    let hs_body_len = body.len();
    let mut hs = vec![
        0x01,
        ((hs_body_len >> 16) & 0xff) as u8,
        ((hs_body_len >> 8) & 0xff) as u8,
        (hs_body_len & 0xff) as u8,
    ];
    hs.extend_from_slice(&body);

    let rec_payload_len = hs.len();
    let mut rec = Vec::new();
    rec.push(0x16);
    rec.extend_from_slice(&[0x03, 0x01]);
    rec.extend_from_slice(&(rec_payload_len as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

/// Минимальный ServerHello (TLS 1.2, шифр `0x002f`, список расширений пустой).
// Используется в `tls_parse_tests`; другие интеграционные крейты тянут `common` целиком.
#[allow(dead_code)]
pub fn server_hello_minimal() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&[0x00, 0x2f]);
    body.push(0);
    body.extend_from_slice(&[0x00, 0x00]);

    let hs_body_len = body.len();
    let mut hs = vec![
        0x02,
        ((hs_body_len >> 16) & 0xff) as u8,
        ((hs_body_len >> 8) & 0xff) as u8,
        (hs_body_len & 0xff) as u8,
    ];
    hs.extend_from_slice(&body);

    let rec_payload_len = hs.len();
    let mut rec = Vec::new();
    rec.push(0x16);
    rec.extend_from_slice(&[0x03, 0x01]);
    rec.extend_from_slice(&(rec_payload_len as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

#[test]
fn common_synthetic_sni_parseable() {
    let v = client_hello_with_sni("example.com");
    assert!(aegis_core::protocols::tls::is_likely_tls_client_hello(&v));
    let r = aegis_core::protocols::tls::sni_hostname_range(&v).expect("sni");
    let name = std::str::from_utf8(&v[r.0..r.0 + r.1]).unwrap();
    assert_eq!(name, "example.com");
}
