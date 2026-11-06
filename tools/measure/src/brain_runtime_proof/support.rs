use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;

pub(super) fn candidate_f64(trace: &Value, strategy: &str, field: &str) -> Option<f64> {
    trace["ranked_candidates"]
        .as_array()?
        .iter()
        .find(|candidate| candidate["strategy"].as_str() == Some(strategy))?
        .get(field)?
        .as_f64()
}

pub(super) fn candidate_bool(trace: &Value, strategy: &str, field: &str) -> Option<bool> {
    trace["ranked_candidates"]
        .as_array()?
        .iter()
        .find(|candidate| candidate["strategy"].as_str() == Some(strategy))?
        .get(field)?
        .as_bool()
}

pub(super) fn string_array(value: &Value) -> Vec<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| item.as_str().map(ToString::to_string))
        .collect()
}

pub(super) fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub(super) fn write_json(path: &Path, value: &Value) -> Result<(), Box<dyn std::error::Error>> {
    write_text(path, &(serde_json::to_string_pretty(value)? + "\n"))
}

pub(super) fn write_text(path: &Path, text: &str) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, text)?;
    Ok(())
}
