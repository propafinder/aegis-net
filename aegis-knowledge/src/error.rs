use thiserror::Error;

pub type Result<T> = std::result::Result<T, KnowledgeError>;

#[derive(Debug, Error)]
pub enum KnowledgeError {
    #[error("failed to parse {path}: {source}")]
    ParseJson {
        path: &'static str,
        source: serde_json::Error,
    },

    #[error("manifest is missing entry for {path}")]
    MissingManifestEntry { path: String },

    #[error("manifest hash mismatch for {path}: expected {expected}, got {actual}")]
    ManifestHashMismatch {
        path: String,
        expected: String,
        actual: String,
    },
}
