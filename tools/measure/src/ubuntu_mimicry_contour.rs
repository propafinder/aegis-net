use std::path::Path;

use serde_json::{json, Value};

use crate::artifact::{read_json, write_json, write_text};

pub fn build_ubuntu_mimicry_next_contour(
    output_dir: &Path,
    stealth_summary_path: Option<&Path>,
    wire_contract_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let stealth_summary = match stealth_summary_path {
        Some(path) => Some(read_json(path)?),
        None => None,
    };
    let wire_contract = read_json(wire_contract_path)?;

    let (contour_status, next_required_action) = match stealth_summary.as_ref() {
        None => (
            "blocked_on_stealth_summary".to_string(),
            "build_post_release_stealth_summary_first".to_string(),
        ),
        Some(summary)
            if summary
                .get("current_milestone_state")
                .and_then(Value::as_str)
                == Some("blocked_on_ubuntu_release_prerequisite") =>
        {
            (
                "blocked_on_ubuntu_release_prerequisite".to_string(),
                next_action_or(summary, "complete_fully_proven_ubuntu_release_wave_first"),
            )
        }
        Some(summary)
            if summary
                .get("current_milestone_state")
                .and_then(Value::as_str)
                == Some("ready_to_collect_witness_evidence") =>
        {
            (
                "blocked_on_witness_maturity_evidence".to_string(),
                next_action_or(
                    summary,
                    "collect_wire_acceptance_summary_for_witness_maturity",
                ),
            )
        }
        Some(summary)
            if summary
                .get("current_milestone_state")
                .and_then(Value::as_str)
                == Some("witness_evidence_degraded") =>
        {
            (
                "blocked_on_witness_correlation_discipline".to_string(),
                next_action_or(
                    summary,
                    "tighten_witness_correlation_and_acceptance_discipline",
                ),
            )
        }
        Some(summary)
            if summary
                .get("current_milestone_state")
                .and_then(Value::as_str)
                == Some("witness_evidence_red") =>
        {
            (
                "blocked_on_wire_acceptance".to_string(),
                next_action_or(summary, "fix_wire_acceptance_before_mimicry_execution"),
            )
        }
        Some(_) => (
            "ready_for_linux_wire_execution_contour".to_string(),
            "implement_linux_wire_execution_contour_in_runtime".to_string(),
        ),
    };

    let payload = json!({
        "artifact_schema": "ubuntu_mimicry_next_contour_v1",
        "supported_product_contour": "ubuntu_post_release_wire_mimicry_planning",
        "supported_operator_scope": "ubuntu_linux_wire_mimicry_execution_planning",
        "stealth_summary_json": stealth_summary_path.map(display_path),
        "wire_validation_contract_json": display_path(wire_contract_path),
        "current_focus": "linux_wire_mimicry_execution_contour",
        "contour_status": contour_status,
        "next_required_action": next_required_action,
        "validation_strategy": wire_contract.get("validation_strategy").cloned().unwrap_or(Value::Null),
        "stable_userspace_boundary": wire_contract.get("stable_userspace_boundary").cloned().unwrap_or(Value::Null),
        "execution_ladder": [
            wire_contract.get("first_runtime_slice").cloned().unwrap_or(Value::Null),
            wire_contract.get("expanded_runtime_slice").cloned().unwrap_or(Value::Null),
            wire_contract.get("options_runtime_slice").cloned().unwrap_or(Value::Null),
            wire_contract.get("negotiated_options_runtime_slice").cloned().unwrap_or(Value::Null),
            wire_contract.get("fragment_choreography_runtime_slice").cloned().unwrap_or(Value::Null),
        ],
        "primary_entrypoints": [
            "scripts/build-mimicry-wire-witness-summary.sh",
            "scripts/validate-mimicry-wire-host.sh",
            "scripts/mimicry-wire-validation-contract.sh",
        ],
        "primary_code_paths": [
            "aegis-core/src/mimicry.rs",
            "aegis-client/src/direct.rs",
        ],
        "claim_boundary_note": "This contour stays post-release and Linux-first; it must not be read as Debian/multi-family expansion or as a retroactive Ubuntu release blocker",
    });

    write_json(
        &output_dir.join("ubuntu-mimicry-next-contour.json"),
        &payload,
    )?;
    write_text(
        &output_dir.join("ubuntu-mimicry-next-contour.md"),
        &render_markdown(&payload),
    )?;
    Ok(())
}

fn render_markdown(payload: &Value) -> String {
    let mut lines = vec![
        "# Ubuntu Mimicry Next Contour".to_string(),
        String::new(),
        format!(
            "- Current focus: `{}`",
            payload["current_focus"].as_str().unwrap_or("")
        ),
        format!(
            "- Contour status: `{}`",
            payload["contour_status"].as_str().unwrap_or("")
        ),
        format!(
            "- Next required action: `{}`",
            payload["next_required_action"].as_str().unwrap_or("")
        ),
        format!(
            "- Validation strategy: `{}`",
            payload["validation_strategy"].as_str().unwrap_or("")
        ),
        String::new(),
        "## Execution Ladder".to_string(),
        String::new(),
    ];
    if let Some(items) = payload["execution_ladder"].as_array() {
        for item in items {
            lines.push(format!("- `{}`", item.as_str().unwrap_or("")));
        }
    }
    lines.extend([
        String::new(),
        "## Primary Code Paths".to_string(),
        String::new(),
    ]);
    if let Some(items) = payload["primary_code_paths"].as_array() {
        for item in items {
            lines.push(format!("- `{}`", item.as_str().unwrap_or("")));
        }
    }
    lines.join("\n") + "\n"
}

fn next_action_or(summary: &Value, fallback: &str) -> String {
    summary
        .get("current_milestone_next_action")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_string()
}

fn display_path(path: &Path) -> String {
    path.display().to_string()
}
