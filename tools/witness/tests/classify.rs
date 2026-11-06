use aegis_witness::{
    classify_tls::classify_tls_record, report::WitnessEvent, score::score_tls_classification,
};

fn client_hello_with_sni_alpn(hostname: &str, alpn: &str) -> Vec<u8> {
    let host = hostname.as_bytes();
    let ap = alpn.as_bytes();
    assert!(host.len() <= 255 && ap.len() <= 255);

    let mut sni_inner = Vec::new();
    sni_inner.push(0x00);
    sni_inner.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sni_inner.extend_from_slice(host);
    let mut sni_value = Vec::new();
    sni_value.extend_from_slice(&(sni_inner.len() as u16).to_be_bytes());
    sni_value.extend_from_slice(&sni_inner);
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&[0x00, 0x00]);
    sni_ext.extend_from_slice(&(sni_value.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(&sni_value);

    let mut alpn_list = Vec::new();
    alpn_list.push(ap.len() as u8);
    alpn_list.extend_from_slice(ap);
    let mut alpn_value = Vec::new();
    alpn_value.extend_from_slice(&(alpn_list.len() as u16).to_be_bytes());
    alpn_value.extend_from_slice(&alpn_list);
    let mut alpn_ext = Vec::new();
    alpn_ext.extend_from_slice(&[0x00, 0x10]);
    alpn_ext.extend_from_slice(&(alpn_value.len() as u16).to_be_bytes());
    alpn_ext.extend_from_slice(&alpn_value);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&sni_ext);
    extensions.extend_from_slice(&alpn_ext);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0x00);
    body.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]);
    body.extend_from_slice(&[0x01, 0x00]);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = vec![
        0x01,
        ((body.len() >> 16) & 0xff) as u8,
        ((body.len() >> 8) & 0xff) as u8,
        (body.len() & 0xff) as u8,
    ];
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

#[test]
fn classify_aegis_tls_fixture() {
    let pkt = client_hello_with_sni_alpn("relay.example", "h2");
    let classification = classify_tls_record(&pkt);

    assert!(classification.is_tls_client_hello);
    assert_eq!(classification.sni.as_deref(), Some("relay.example"));
    assert_eq!(classification.alpn, vec!["h2"]);
    assert_eq!(classification.ja3.as_deref(), Some("771,47,0-16,,"));
    assert_eq!(classification.ja3_md5.as_deref().unwrap().len(), 32);

    let score = score_tls_classification(&classification);
    assert_eq!(score.combined, 1.0);
}

#[test]
fn classify_curl_like_fixture_without_alpn() {
    let pkt = client_hello_with_sni_alpn("curl.example", "http/1.1");
    let classification = classify_tls_record(&pkt);
    let score = score_tls_classification(&classification);

    assert!(classification.is_tls_client_hello);
    assert_eq!(classification.sni.as_deref(), Some("curl.example"));
    assert_eq!(classification.alpn, vec!["http/1.1"]);
    assert_eq!(score.alpn_match, 1.0);
}

#[test]
fn classify_non_tls_as_not_client_hello() {
    let classification = classify_tls_record(b"GET / HTTP/1.1\r\n\r\n");
    let score = score_tls_classification(&classification);

    assert!(!classification.is_tls_client_hello);
    assert_eq!(score.combined, 0.0);
}

#[test]
fn report_serializes_jsonl_shape() {
    let pkt = client_hello_with_sni_alpn("relay.example", "h2");
    let classification = classify_tls_record(&pkt);
    let score = score_tls_classification(&classification);
    let event = WitnessEvent::new("fixture".to_string(), None, classification, score);
    let json = serde_json::to_string(&event).expect("json");

    assert!(json.contains("\"event\":\"witness_tls_classification\""));
    assert!(json.contains("\"label\":\"fixture\""));
    assert!(json.contains("\"ja3_md5\""));
}
