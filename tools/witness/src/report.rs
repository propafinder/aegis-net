//! JSONL report shape for witness events.

use serde::{Deserialize, Serialize};

use crate::{classify_tls::TlsWitnessClassification, score::WitnessScore};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WitnessEvent {
    pub event: String,
    pub schema_version: u8,
    pub label: String,
    pub record: Option<String>,
    pub classification: TlsWitnessClassification,
    pub score: WitnessScore,
}

impl WitnessEvent {
    pub fn new(
        label: String,
        record: Option<String>,
        classification: TlsWitnessClassification,
        score: WitnessScore,
    ) -> Self {
        Self {
            event: "witness_tls_classification".to_string(),
            schema_version: 1,
            label,
            record,
            classification,
            score,
        }
    }
}
