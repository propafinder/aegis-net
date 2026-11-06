//! Initial structural scoring for witness output.

use serde::{Deserialize, Serialize};

use crate::{
    baseline::{has_browser_like_alpn, has_dns_like_sni},
    classify_tls::TlsWitnessClassification,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WitnessScore {
    pub ja3_present: f32,
    pub alpn_match: f32,
    pub sni_structure: f32,
    pub extension_structure: f32,
    pub combined: f32,
}

pub fn score_tls_classification(classification: &TlsWitnessClassification) -> WitnessScore {
    if !classification.is_tls_client_hello {
        return WitnessScore {
            ja3_present: 0.0,
            alpn_match: 0.0,
            sni_structure: 0.0,
            extension_structure: 0.0,
            combined: 0.0,
        };
    }

    let ja3_present = f32::from(classification.ja3_md5.is_some());
    let alpn_match = f32::from(has_browser_like_alpn(&classification.alpn));
    let sni_structure = f32::from(has_dns_like_sni(classification.sni.as_deref()));
    let extension_structure = f32::from(!classification.extension_types.is_empty());
    let combined = (ja3_present + alpn_match + sni_structure + extension_structure) / 4.0;

    WitnessScore {
        ja3_present,
        alpn_match,
        sni_structure,
        extension_structure,
        combined,
    }
}
