//! Static prior corpus for AEGIS strategy selection.
//!
//! The crate is deliberately independent from `aegis-core`: Brain integration
//! should map core strategy keys into `StrategyDescriptor` in a later adapter.

pub mod corpus;
pub mod integrity;
pub mod manifest;
pub mod prior;

mod error;

pub use corpus::{BrowserCorpus, BrowserFingerprint, Knowledge, ReferenceTiming, SignatureCorpus};
pub use error::{KnowledgeError, Result};
pub use manifest::{Manifest, ManifestFile};
pub use prior::{PriorScore, StrategyDescriptor, TargetClass};

pub const EMBEDDED_JA3_BROWSER_CORPUS: &str = include_str!("../data/ja3-browser-corpus.json");
pub const EMBEDDED_DPI_SIGNATURES_CN: &str = include_str!("../data/dpi-signatures-cn.yaml");
pub const EMBEDDED_DPI_SIGNATURES_RU: &str = include_str!("../data/dpi-signatures-ru.yaml");
pub const EMBEDDED_DPI_SIGNATURES_IR: &str = include_str!("../data/dpi-signatures-ir.yaml");
pub const EMBEDDED_REFERENCE_TIMING: &str = include_str!("../data/reference-timing.json");
pub const EMBEDDED_MANIFEST: &str = include_str!("../data/manifest.json");

pub fn load_embedded() -> Result<Knowledge> {
    Knowledge::load_embedded()
}
