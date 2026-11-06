use std::path::Path;

use serde_json::{json, Value};

use crate::artifact::{read_json, write_json, write_text};

pub fn build_linux_release_program_bundle(
    output_dir: &Path,
    ubuntu_wave_manifest_path: &Path,
    next_expansion_status_path: Option<&Path>,
    stealth_summary_path: Option<&Path>,
    mimicry_next_contour_path: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ubuntu_wave_manifest = read_json(ubuntu_wave_manifest_path)?;
    let ubuntu_wave_status_path = ubuntu_wave_manifest["wave_status_json"]
        .as_str()
        .ok_or("ubuntu wave manifest does not define wave_status_json")?;
    let ubuntu_wave_status = read_json(Path::new(ubuntu_wave_status_path))?;
    let next_expansion_status = read_optional(next_expansion_status_path)?;
    let stealth_summary = read_optional(stealth_summary_path)?;
    let mimicry_next_contour = read_optional(mimicry_next_contour_path)?;

    let ubuntu_wave_status_code = ubuntu_wave_status
        .get("wave_status")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let (program_status, next_required_action) = classify_program_status(
        ubuntu_wave_status_code,
        &ubuntu_wave_status,
        next_expansion_status.as_ref(),
        stealth_summary.as_ref(),
        mimicry_next_contour.as_ref(),
    );

    let status_path = output_dir.join("linux-release-program-status.json");
    let payload = json!({
        "artifact_schema": "linux_release_program_bundle_v1",
        "supported_product_contour": "linux_release_program_status",
        "supported_operator_scope": "linux_release_and_growth_tracking",
        "ubuntu_wave_manifest_json": display_path(ubuntu_wave_manifest_path),
        "ubuntu_wave_status_json": ubuntu_wave_manifest.get("wave_status_json").cloned().unwrap_or(Value::Null),
        "ubuntu_wave_status": ubuntu_wave_status_code,
        "ubuntu_ship_ready": ubuntu_wave_status.get("ship_ready").cloned().unwrap_or(Value::Null),
        "ubuntu_ship_decision": ubuntu_wave_status.get("ship_decision").cloned().unwrap_or(Value::Null),
        "next_expansion_status_json": next_expansion_status_path.map(display_path),
        "next_expansion_status": next_expansion_status.as_ref().and_then(|value| value.get("expansion_status")).cloned().unwrap_or(Value::Null),
        "next_expansion_candidate": next_expansion_status.as_ref().and_then(|value| value.get("next_expansion_candidate")).cloned().unwrap_or(Value::Null),
        "stealth_summary_json": stealth_summary_path.map(display_path),
        "stealth_status": stealth_summary.as_ref().and_then(|value| value.get("status")).cloned().unwrap_or(Value::Null),
        "stealth_current_milestone": stealth_summary.as_ref().and_then(|value| value.get("current_milestone")).cloned().unwrap_or(Value::Null),
        "stealth_current_milestone_state": stealth_summary.as_ref().and_then(|value| value.get("current_milestone_state")).cloned().unwrap_or(Value::Null),
        "mimicry_next_contour_json": mimicry_next_contour_path.map(display_path),
        "mimicry_contour_status": mimicry_next_contour.as_ref().and_then(|value| value.get("contour_status")).cloned().unwrap_or(Value::Null),
        "program_status": program_status,
        "claim_boundary_note": "Ubuntu release remains the primary ship-ready claim; next-family evidence and stealth tracks stay visible without rewriting that boundary",
        "next_required_action": next_required_action,
    });
    write_json(&status_path, &payload)?;

    let manifest = json!({
        "artifact_schema": "linux_release_program_manifest_v1",
        "supported_product_contour": "linux_release_program_status",
        "supported_operator_scope": "linux_release_and_growth_tracking",
        "linux_release_program_status_json": display_path(&status_path),
        "ubuntu_wave_manifest_json": display_path(ubuntu_wave_manifest_path),
        "next_expansion_status_json": next_expansion_status_path.map(display_path),
        "stealth_summary_json": stealth_summary_path.map(display_path),
        "mimicry_next_contour_json": mimicry_next_contour_path.map(display_path),
        "program_status": program_status,
        "next_required_action": next_required_action,
    });
    write_json(
        &output_dir.join("linux-release-program.manifest.json"),
        &manifest,
    )?;
    write_text(
        &output_dir.join("linux-release-program.md"),
        &render_markdown(&payload),
    )?;
    Ok(())
}

fn classify_program_status(
    ubuntu_wave_status_code: &str,
    ubuntu_wave_status: &Value,
    next_expansion_status: Option<&Value>,
    stealth_summary: Option<&Value>,
    mimicry_next_contour: Option<&Value>,
) -> (String, String) {
    if ubuntu_wave_status_code == "baseline_ship_ready" {
        return (
            "ubuntu_release_needs_hostile_proof".to_string(),
            value_str_or(
                ubuntu_wave_status,
                "next_required_action",
                "collect_hostile_path_proof_to_reach_fully_proven",
            ),
        );
    }
    if !matches!(
        ubuntu_wave_status_code,
        "fully_proven_hostile_path" | "ship_ready"
    ) {
        return (
            "ubuntu_release_blocked".to_string(),
            value_str_or(
                ubuntu_wave_status,
                "next_required_action",
                "inspect_ubuntu_release_wave",
            ),
        );
    }

    let Some(next_expansion_status) = next_expansion_status else {
        if let Some(stealth_summary) = stealth_summary {
            return (
                "ubuntu_post_release_tracks_visible".to_string(),
                value_str_or(
                    stealth_summary,
                    "current_milestone_next_action",
                    "execute_post_release_stealth_program",
                ),
            );
        }
        if let Some(mimicry_next_contour) = mimicry_next_contour {
            return (
                "ubuntu_post_release_mimicry_visible".to_string(),
                value_str_or(
                    mimicry_next_contour,
                    "next_required_action",
                    "inspect_mimicry_next_contour",
                ),
            );
        }
        return (
            "ubuntu_release_ready_next_family_untracked".to_string(),
            "collect_next_family_status".to_string(),
        );
    };

    match next_expansion_status
        .get("expansion_status")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
    {
        "latest_review_blocked" | "matrix_has_failed_families" => (
            "ubuntu_release_ready_next_family_blocked".to_string(),
            value_str_or(
                next_expansion_status,
                "next_required_action",
                "inspect_next_family_wave",
            ),
        ),
        "pending_next_family"
        | "target_validated_next_candidate_pending"
        | "pending_families_without_next_candidate" => (
            "ubuntu_release_ready_next_family_in_progress".to_string(),
            value_str_or(
                next_expansion_status,
                "next_required_action",
                "continue_next_family_wave",
            ),
        ),
        "all_documented_families_validated" => {
            if stealth_summary.is_some() {
                (
                    "post_release_growth_tracks_visible".to_string(),
                    "execute_post_release_stealth_program".to_string(),
                )
            } else {
                (
                    "multi_family_validated_stealth_untracked".to_string(),
                    "build_post_release_stealth_summary".to_string(),
                )
            }
        }
        _ => (
            "next_family_status_unknown".to_string(),
            value_str_or(
                next_expansion_status,
                "next_required_action",
                "inspect_next_family_status",
            ),
        ),
    }
}

fn render_markdown(payload: &Value) -> String {
    [
        "# Linux Release Program".to_string(),
        String::new(),
        format!(
            "- Ubuntu wave status: `{}`",
            payload["ubuntu_wave_status"].as_str().unwrap_or("")
        ),
        format!(
            "- Next-family status: `{}`",
            payload["next_expansion_status"]
                .as_str()
                .unwrap_or("untracked")
        ),
        format!(
            "- Stealth status: `{}`",
            payload["stealth_status"].as_str().unwrap_or("untracked")
        ),
        format!(
            "- Mimicry contour status: `{}`",
            payload["mimicry_contour_status"]
                .as_str()
                .unwrap_or("untracked")
        ),
        format!(
            "- Program status: `{}`",
            payload["program_status"].as_str().unwrap_or("")
        ),
        format!(
            "- Next required action: `{}`",
            payload["next_required_action"].as_str().unwrap_or("")
        ),
    ]
    .join("\n")
        + "\n"
}

fn read_optional(path: Option<&Path>) -> Result<Option<Value>, Box<dyn std::error::Error>> {
    path.map(read_json).transpose()
}

fn value_str_or(value: &Value, key: &str, fallback: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback)
        .to_string()
}

fn display_path(path: &Path) -> String {
    path.display().to_string()
}
