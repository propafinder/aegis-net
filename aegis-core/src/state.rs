//! Персистентное состояние Brain.

use crate::error::Result;
use crate::state_secret::{maybe_decrypt_state_blob, seal_state_blob, write_private_file};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StrategyStats {
    pub success_rate: f64,
    pub avg_handshake_ms: f64,
    pub last_rst_source: Option<String>,
    pub confidence: f64,
}

impl StrategyStats {
    pub fn score(&self) -> f64 {
        self.success_rate * 0.7 + self.confidence * 0.3
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StateFile {
    pub entries: HashMap<String, HashMap<String, StrategyStats>>,
}

#[derive(Debug, Clone)]
pub struct StateStore {
    pub path: std::path::PathBuf,
    pub data: HashMap<String, HashMap<String, StrategyStats>>,
}

impl StateStore {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let data = if path.exists() {
            let bytes = fs::read(&path)?;
            if let Some(plaintext) = maybe_decrypt_state_blob(&path, &bytes)? {
                let f: StateFile = serde_json::from_slice(&plaintext)?;
                f.entries
            } else {
                let f: StateFile = serde_json::from_slice(&bytes)?;
                f.entries
            }
        } else {
            HashMap::new()
        };
        Ok(StateStore { path, data })
    }

    pub fn save(&self) -> Result<()> {
        let sf = StateFile {
            entries: self.data.clone(),
        };
        let json = serde_json::to_vec_pretty(&sf)?;
        let sealed = seal_state_blob(&self.path, &json)?;
        write_private_file(&self.path, &sealed)?;
        Ok(())
    }

    pub fn get(&self, key: &str) -> Option<&HashMap<String, StrategyStats>> {
        self.data.get(key)
    }
}
