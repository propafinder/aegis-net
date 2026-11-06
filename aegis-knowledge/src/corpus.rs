use serde::{Deserialize, Serialize};

use crate::error::{KnowledgeError, Result};
use crate::integrity::verify_manifest_files;
use crate::manifest::Manifest;
use crate::prior::{PriorScore, StrategyDescriptor};
use crate::{
    EMBEDDED_DPI_SIGNATURES_CN, EMBEDDED_DPI_SIGNATURES_IR, EMBEDDED_DPI_SIGNATURES_RU,
    EMBEDDED_JA3_BROWSER_CORPUS, EMBEDDED_MANIFEST, EMBEDDED_REFERENCE_TIMING,
};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct BrowserCorpus {
    pub version: String,
    pub fingerprints: Vec<BrowserFingerprint>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct BrowserFingerprint {
    pub id: String,
    pub browser_family: String,
    pub target_class: String,
    pub ja3_hash: String,
    pub alpn: Vec<String>,
    pub weight: f64,
    pub source_label: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ReferenceTiming {
    pub version: String,
    pub histograms: serde_json::Value,
    pub source_label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureCorpus {
    pub region_id: String,
    pub source_label: String,
    pub document: String,
}

#[derive(Debug, Clone)]
pub struct Knowledge {
    pub manifest: Manifest,
    pub browser_corpus: BrowserCorpus,
    pub reference_timing: ReferenceTiming,
    pub signatures: Vec<SignatureCorpus>,
}

impl Knowledge {
    pub fn load_embedded() -> Result<Self> {
        let manifest = Manifest::parse_embedded(EMBEDDED_MANIFEST)?;
        let browser_corpus = parse_browser_corpus(EMBEDDED_JA3_BROWSER_CORPUS)?;
        let reference_timing = parse_reference_timing(EMBEDDED_REFERENCE_TIMING)?;
        let signatures = vec![
            SignatureCorpus::from_document(EMBEDDED_DPI_SIGNATURES_CN),
            SignatureCorpus::from_document(EMBEDDED_DPI_SIGNATURES_RU),
            SignatureCorpus::from_document(EMBEDDED_DPI_SIGNATURES_IR),
        ];

        let knowledge = Self {
            manifest,
            browser_corpus,
            reference_timing,
            signatures,
        };
        knowledge.verify_integrity()?;
        Ok(knowledge)
    }

    pub fn verify_integrity(&self) -> Result<()> {
        verify_manifest_files(
            &self.manifest,
            &[
                (
                    "ja3-browser-corpus.json",
                    EMBEDDED_JA3_BROWSER_CORPUS.as_bytes(),
                ),
                (
                    "dpi-signatures-cn.yaml",
                    EMBEDDED_DPI_SIGNATURES_CN.as_bytes(),
                ),
                (
                    "dpi-signatures-ru.yaml",
                    EMBEDDED_DPI_SIGNATURES_RU.as_bytes(),
                ),
                (
                    "dpi-signatures-ir.yaml",
                    EMBEDDED_DPI_SIGNATURES_IR.as_bytes(),
                ),
                (
                    "reference-timing.json",
                    EMBEDDED_REFERENCE_TIMING.as_bytes(),
                ),
            ],
        )
    }

    pub fn priors_for(&self, strategy: &StrategyDescriptor) -> PriorScore {
        PriorScore::from_knowledge(self, strategy)
    }

    pub fn signature_for_region(&self, region_id: &str) -> Option<&SignatureCorpus> {
        self.signatures
            .iter()
            .find(|signature| signature.region_id == region_id)
    }
}

impl SignatureCorpus {
    pub fn from_document(document: &str) -> Self {
        Self {
            region_id: extract_yaml_scalar(document, "region_id")
                .unwrap_or("unknown")
                .to_string(),
            source_label: extract_yaml_scalar(document, "source_label")
                .unwrap_or("unknown")
                .to_string(),
            document: document.to_string(),
        }
    }
}

fn parse_browser_corpus(input: &'static str) -> Result<BrowserCorpus> {
    serde_json::from_str(input).map_err(|source| KnowledgeError::ParseJson {
        path: "ja3-browser-corpus.json",
        source,
    })
}

fn parse_reference_timing(input: &'static str) -> Result<ReferenceTiming> {
    serde_json::from_str(input).map_err(|source| KnowledgeError::ParseJson {
        path: "reference-timing.json",
        source,
    })
}

fn extract_yaml_scalar<'a>(document: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}:");
    document.lines().find_map(|line| {
        let trimmed = line.trim();
        trimmed
            .strip_prefix(&prefix)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    })
}
