//! Rust-native witness fixtures for contract evidence.

pub fn client_hello_with_sni_alpn(hostname: &str, alpn: &str) -> Result<Vec<u8>, &'static str> {
    let host = hostname.as_bytes();
    let proto = alpn.as_bytes();
    if host.len() > 255 || proto.len() > 255 {
        return Err("hostname and alpn must each fit in one byte");
    }

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
    alpn_list.push(proto.len() as u8);
    alpn_list.extend_from_slice(proto);

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
    Ok(record)
}
