//! Shared TLS ClientHello parsing and fingerprint helpers used by witness tooling.
//!
//! This facade does not provide a calibration corpus or a runtime calibration adapter.
//!
//! This crate is a thin facade over the shared `aegis-core` TLS parsing
//! surface. Witness consumers can depend on this crate without
//! reaching into relay/session code.

pub mod grease;
pub mod legacy_tls12_audit;

use serde::{Deserialize, Serialize};

/// Parsed TLS ClientHello fingerprint material relevant to witness scoring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsClientHelloFingerprint {
    pub legacy_version: u16,
    pub cipher_suites: Vec<u16>,
    pub extension_types: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub ja3: String,
    pub ja3_md5: String,
}

/// Parse a TLS ClientHello record into fingerprint material.
pub fn classify_tls_client_hello(buf: &[u8]) -> Option<TlsClientHelloFingerprint> {
    let core = aegis_core::protocols::tls::parse_client_hello_core(buf)?;
    let supported_groups =
        aegis_core::protocols::tls::client_hello_supported_groups(buf).unwrap_or_default();
    let sni = aegis_core::protocols::tls_parse::parse_client_hello(buf).and_then(|view| view.sni);
    let alpn = aegis_core::protocols::tls::client_hello_alpn_protocols(buf).unwrap_or_default();
    let ja3 = aegis_core::protocols::ja3::ja3_client_fingerprint_string(buf)?;
    let ja3_md5 = aegis_core::protocols::ja3::ja3_client_md5_hex(buf)?;

    Some(TlsClientHelloFingerprint {
        legacy_version: core.legacy_version,
        cipher_suites: core.cipher_suites,
        extension_types: core.extension_types,
        supported_groups,
        sni,
        alpn,
        ja3,
        ja3_md5,
    })
}

/// Return true when the first record looks like a TLS ClientHello.
pub fn is_tls_client_hello(buf: &[u8]) -> bool {
    aegis_core::protocols::tls::is_likely_tls_client_hello(buf)
}

pub use aegis_core::protocols::ja3::{
    ja3_client_fingerprint_string, ja3_client_md5_hex, ja3s_server_fingerprint_string,
    ja3s_server_md5_hex,
};

#[cfg(test)]
mod tests {
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
    fn classifies_client_hello_fingerprint_material() {
        let pkt = client_hello_with_sni_alpn("example.com", "h2");
        let fp = super::classify_tls_client_hello(&pkt).expect("fingerprint");

        assert_eq!(fp.legacy_version, 0x0303);
        assert_eq!(fp.sni.as_deref(), Some("example.com"));
        assert_eq!(fp.alpn, vec!["h2"]);
        assert_eq!(fp.cipher_suites, vec![0x002f]);
        assert_eq!(fp.extension_types, vec![0, 16]);
        assert_eq!(fp.ja3, "771,47,0-16,,");
        assert_eq!(fp.ja3_md5.len(), 32);
    }
}
