//! TLS classification for witness events.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TlsWitnessClassification {
    pub is_tls_client_hello: bool,
    pub legacy_version: Option<u16>,
    pub cipher_suites: Vec<u16>,
    pub extension_types: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub ja3: Option<String>,
    pub ja3_md5: Option<String>,
}

pub fn classify_tls_record(buf: &[u8]) -> TlsWitnessClassification {
    let Some(fp) = aegis_fingerprint::classify_tls_client_hello(buf) else {
        return TlsWitnessClassification {
            is_tls_client_hello: false,
            legacy_version: None,
            cipher_suites: Vec::new(),
            extension_types: Vec::new(),
            supported_groups: Vec::new(),
            sni: None,
            alpn: Vec::new(),
            ja3: None,
            ja3_md5: None,
        };
    };

    TlsWitnessClassification {
        is_tls_client_hello: true,
        legacy_version: Some(fp.legacy_version),
        cipher_suites: fp.cipher_suites,
        extension_types: fp.extension_types,
        supported_groups: fp.supported_groups,
        sni: fp.sni,
        alpn: fp.alpn,
        ja3: Some(fp.ja3),
        ja3_md5: Some(fp.ja3_md5),
    }
}
