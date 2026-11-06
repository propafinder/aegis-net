use std::{fs, path::Path};

use serde_json::Value;

pub(super) fn doc_status(path: Option<&Path>) -> &'static str {
    if path.is_some_and(|path| path.is_file() && path.metadata().is_ok_and(|m| m.len() > 0)) {
        "PASS"
    } else {
        "MISSING"
    }
}

pub(super) fn read_json(path: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

pub(super) fn read_jsonl(path: &Path) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    let mut records = Vec::new();
    for (index, line) in fs::read_to_string(path)?.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        records.push(
            serde_json::from_str::<Value>(line)
                .map_err(|err| format!("{}:{} invalid JSONL: {err}", path.display(), index + 1))?,
        );
    }
    Ok(records)
}
