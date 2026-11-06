use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::error::{KnowledgeError, Result};
use crate::manifest::Manifest;

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub fn verify_manifest_files(manifest: &Manifest, files: &[(&str, &[u8])]) -> Result<()> {
    let hashes: HashMap<&str, String> = files
        .iter()
        .map(|(path, bytes)| (*path, sha256_hex(bytes)))
        .collect();

    for entry in &manifest.files {
        let actual = hashes.get(entry.path.as_str()).ok_or_else(|| {
            KnowledgeError::MissingManifestEntry {
                path: entry.path.clone(),
            }
        })?;

        if actual != &entry.sha256 {
            return Err(KnowledgeError::ManifestHashMismatch {
                path: entry.path.clone(),
                expected: entry.sha256.clone(),
                actual: actual.clone(),
            });
        }
    }

    Ok(())
}
