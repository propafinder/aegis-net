use std::path::Path;

use serde_json::{json, Value};

pub(super) fn placeholder_free(value: &str) -> bool {
    // Templates can occur inside an argument or before punctuation. Match named
    // placeholders in one pass without mistaking ordinary shell redirection for one.
    let mut named = None;
    for byte in value.bytes() {
        if byte == b'<' {
            named = Some(false);
        } else if byte == b'>' {
            if named.is_some() {
                return false;
            }
            named = None;
        } else if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/' | b':') {
            if named.is_some() {
                named = Some(true);
            }
        } else {
            named = None;
        }
    }
    true
}

pub(super) fn release_latest_parity_gate_result(artifact_dir: &Path) -> String {
    artifact_dir
        .parent()
        .unwrap_or(artifact_dir)
        .join("release-latest-parity-gate")
        .join("result.json")
        .to_slash_string()
}

pub(super) trait SlashPath {
    fn to_slash_string(&self) -> String;
}

impl SlashPath for Path {
    fn to_slash_string(&self) -> String {
        self.to_string_lossy().replace('\\', "/")
    }
}

impl SlashPath for std::path::PathBuf {
    fn to_slash_string(&self) -> String {
        self.as_path().to_slash_string()
    }
}

pub(super) fn value_string_array(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn phase_c_artifact_or_placeholder(
    gate: &Value,
    key: &str,
    placeholder: &str,
) -> String {
    gate["artifacts"][key]
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(placeholder)
        .to_string()
}

pub(super) fn handoff_path_prerequisite(value: &str) -> Value {
    let placeholder = value.starts_with('<') && value.ends_with('>');
    json!({
        "path": value,
        "placeholder": placeholder,
        "exists": !placeholder && handoff_path_exists(value),
    })
}

pub(super) fn handoff_external_input(description: &str) -> Value {
    json!({
        "required": true,
        "provided_by_repo": false,
        "description": description,
    })
}

pub(super) fn handoff_phase_c_prerequisites_ready_value(prerequisites: &Value) -> bool {
    prerequisites
        .as_object()
        .map(|items| {
            items.values().all(|item| {
                item["placeholder"].as_bool() == Some(false)
                    && item["exists"].as_bool() == Some(true)
            })
        })
        .unwrap_or(false)
}

pub(super) fn handoff_phase_c_prerequisites_ready(handoff: &Value) -> bool {
    handoff["prerequisites"]["phase_c_fronted_followup"]
        .as_object()
        .map(|items| {
            items.values().all(|item| {
                item["placeholder"].as_bool() == Some(false)
                    && item["exists"].as_bool() == Some(true)
            })
        })
        .unwrap_or(false)
}

pub(super) fn join_strings(value: &Value) -> String {
    let values = value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    if values.is_empty() {
        "none".to_string()
    } else {
        values.join(", ")
    }
}

pub(super) fn join_object_keys(value: &Value) -> String {
    let Some(object) = value.as_object() else {
        return "none".to_string();
    };
    if object.is_empty() {
        "none".to_string()
    } else {
        object.keys().cloned().collect::<Vec<_>>().join(", ")
    }
}

pub(super) fn ensure(condition: bool, message: &str) -> Result<(), Box<dyn std::error::Error>> {
    if condition {
        Ok(())
    } else {
        Err(format!("contract assertion failed: {message}").into())
    }
}

fn handoff_path_exists(value: &str) -> bool {
    let path = Path::new(value);
    if path.is_file() {
        return true;
    }

    #[cfg(windows)]
    {
        if let Some(rest) = value.strip_prefix("/tmp/") {
            if let Ok(temp_dir) = std::env::var("TEMP") {
                return Path::new(&temp_dir).join(rest).is_file();
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::placeholder_free;

    #[test]
    fn named_placeholders_are_detected_with_punctuation_and_embedding() {
        for command in [
            "observe <reference-origin-address>, then continue",
            "--authority=<reference-authority>:443",
            "https://<reference-authority>/probe",
            "<observer>,<observer>;(<reference-authority>)",
            "--input=<phase-c.json>",
            "empty <> marker",
        ] {
            assert!(
                !placeholder_free(command),
                "template was admitted: {command}"
            );
        }
    }

    #[test]
    fn resolved_commands_and_redirection_remain_placeholder_free() {
        for command in [
            "probe --authority=example.invalid:443 --observer=observer.invalid",
            "cat < input.json > output.json",
            "",
            "plain command",
            "unfinished <token",
        ] {
            assert!(
                placeholder_free(command),
                "resolved text rejected: {command}"
            );
        }
    }
}
