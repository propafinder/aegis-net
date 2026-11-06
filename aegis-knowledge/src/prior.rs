use serde::{Deserialize, Serialize};
use std::fmt;

use crate::corpus::Knowledge;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub enum TargetClass {
    LegacyTls,
    HttpsWebSocket,
    GrpcStream,
    MasqueDerived,
    Unknown(String),
}

impl TargetClass {
    pub fn as_str(&self) -> &str {
        match self {
            Self::LegacyTls => "legacy_tls",
            Self::HttpsWebSocket => "https_ws",
            Self::GrpcStream => "grpc_stream",
            Self::MasqueDerived => "masque_derived",
            Self::Unknown(value) => value.as_str(),
        }
    }
}

impl From<&str> for TargetClass {
    fn from(value: &str) -> Self {
        match value {
            "legacy_tls" => Self::LegacyTls,
            "https_ws" => Self::HttpsWebSocket,
            "grpc_stream" => Self::GrpcStream,
            "masque_derived" => Self::MasqueDerived,
            other => Self::Unknown(other.to_string()),
        }
    }
}

impl fmt::Display for TargetClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct StrategyDescriptor {
    pub target_class: TargetClass,
    pub region_id: Option<String>,
    pub alpn: Vec<String>,
    pub ja3_hash: Option<String>,
}

impl StrategyDescriptor {
    pub fn new(target_class: impl Into<TargetClass>) -> Self {
        Self {
            target_class: target_class.into(),
            region_id: None,
            alpn: Vec::new(),
            ja3_hash: None,
        }
    }

    pub fn with_region(mut self, region_id: impl Into<String>) -> Self {
        self.region_id = Some(region_id.into());
        self
    }

    pub fn with_alpn(mut self, alpn: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.alpn = alpn.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_ja3_hash(mut self, ja3_hash: impl Into<String>) -> Self {
        self.ja3_hash = Some(ja3_hash.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct PriorScore {
    pub score: f64,
    pub confidence: f64,
    pub hard_excluded: bool,
    pub reasons: Vec<String>,
}

impl PriorScore {
    pub fn from_knowledge(knowledge: &Knowledge, strategy: &StrategyDescriptor) -> Self {
        let mut reasons = Vec::new();
        let class = strategy.target_class.as_str();
        let mut score = base_transport_score(class);
        let mut confidence: f64 = 0.35;
        let mut hard_excluded = false;

        let browser_weight = knowledge
            .browser_corpus
            .fingerprints
            .iter()
            .filter(|fingerprint| fingerprint.target_class == class)
            .map(|fingerprint| fingerprint.weight)
            .sum::<f64>();
        if browser_weight > 0.0 {
            score = (score + browser_weight).min(1.0);
            confidence = confidence.max(0.55);
            reasons.push(format!("browser-corpus-match:{class}"));
        } else {
            reasons.push(format!("browser-corpus-miss:{class}"));
        }

        if let Some(region_id) = &strategy.region_id {
            if let Some(signature) = knowledge.signature_for_region(region_id) {
                confidence = confidence.max(0.65);
                reasons.push(format!("regional-signature-doc:{}", signature.source_label));

                if hard_blocks(&signature.document, class) {
                    hard_excluded = true;
                    score = 0.0;
                    reasons.push(format!("hard-block-prior:{region_id}:{class}"));
                } else if let Some(penalty) = penalty_for(&signature.document, class) {
                    score = (score - penalty).max(0.0);
                    reasons.push(format!("regional-penalty:{region_id}:{class}:{penalty:.2}"));
                }
            } else {
                reasons.push(format!("regional-signature-miss:{region_id}"));
            }
        }

        if strategy.ja3_hash.as_ref().is_some_and(|ja3| {
            knowledge
                .browser_corpus
                .fingerprints
                .iter()
                .any(|fp| &fp.ja3_hash == ja3)
        }) {
            score = (score + 0.08).min(1.0);
            confidence = confidence.max(0.7);
            reasons.push("exact-ja3-corpus-match".to_string());
        }

        if !strategy.alpn.is_empty()
            && knowledge.browser_corpus.fingerprints.iter().any(|fp| {
                fp.target_class == class
                    && strategy
                        .alpn
                        .iter()
                        .any(|alpn| fp.alpn.iter().any(|known| known == alpn))
            })
        {
            score = (score + 0.05).min(1.0);
            reasons.push("alpn-corpus-overlap".to_string());
        }

        Self {
            score: round_score(score),
            confidence: round_score(confidence),
            hard_excluded,
            reasons,
        }
    }
}

fn base_transport_score(class: &str) -> f64 {
    match class {
        "https_ws" => 0.28,
        "masque_derived" => 0.30,
        "grpc_stream" => 0.22,
        "legacy_tls" => 0.18,
        _ => 0.20,
    }
}

fn hard_blocks(document: &str, class: &str) -> bool {
    let mut in_hard_block_section = false;
    for line in document.lines().map(str::trim) {
        if line.starts_with("hard_block_classes:") {
            in_hard_block_section = true;
            continue;
        }
        if in_hard_block_section && line.starts_with("- ") {
            if line.trim_start_matches("- ").trim() == class {
                return true;
            }
            continue;
        }
        if in_hard_block_section && !line.is_empty() && !line.starts_with("- ") {
            in_hard_block_section = false;
        }
    }
    false
}

fn penalty_for(document: &str, class: &str) -> Option<f64> {
    let mut matched_class = false;
    for line in document.lines().map(str::trim) {
        if line == format!("target_class: {class}") || line == format!("- target_class: {class}") {
            matched_class = true;
            continue;
        }

        if matched_class {
            if let Some(value) = line.strip_prefix("penalty:") {
                return value.trim().parse::<f64>().ok();
            }
            if line.starts_with("- target_class:") {
                matched_class = false;
            }
        }
    }
    None
}

fn round_score(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}
