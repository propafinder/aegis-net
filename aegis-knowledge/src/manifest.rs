use serde::{Deserialize, Serialize};

use crate::error::{KnowledgeError, Result};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Manifest {
    pub version: String,
    pub files: Vec<ManifestFile>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ManifestFile {
    pub path: String,
    pub sha256: String,
    pub source_kind: String,
    pub source_label: String,
}

impl Manifest {
    pub fn parse_embedded(input: &'static str) -> Result<Self> {
        serde_json::from_str(input).map_err(|source| KnowledgeError::ParseJson {
            path: "manifest.json",
            source,
        })
    }

    pub fn file(&self, path: &str) -> Option<&ManifestFile> {
        self.files.iter().find(|entry| entry.path == path)
    }
}
