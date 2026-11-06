use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::artifact::{read_json, write_json};

pub fn build_ubuntu_release_wave_status(
    pilot_inputs_path: &Path,
    pilot_review_manifest_path: &Path,
    output_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let pilot_inputs = read_json(pilot_inputs_path)?;
    let pilot_review = read_json(pilot_review_manifest_path)?;
    let release_handoff = read_json(Path::new(required_str(
        &pilot_inputs,
        "release_gate_handoff_json",
    )?))?;
    let release_summary = read_json(Path::new(required_str(
        &pilot_inputs,
        "release_summary_json",
    )?))?;
    let release_review = read_json(Path::new(required_str(
        &pilot_review,
        "release_review_json",
    )?))?;

    let (wave_status, next_required_action) = if release_handoff["ship_ready"].as_bool()
        == Some(true)
        && release_review["ship_decision"].as_str() == Some("ship")
        && release_review["bypass_ready"].as_bool() == Some(true)
    {
        if release_review["fully_proven"].as_bool() == Some(true) {
            ("fully_proven_hostile_path", "none".to_string())
        } else {
            (
                "baseline_ship_ready",
                "collect_hostile_path_proof_to_reach_fully_proven".to_string(),
            )
        }
    } else if release_review["bypass_ready"].as_bool() != Some(true) {
        (
            "bypass_proof_missing",
            first_array_string(&release_review["blocking_reasons"])
                .unwrap_or_else(|| "collect_live_bypass_proof".to_string()),
        )
    } else if release_handoff["ship_ready"].as_bool() != Some(true) {
        (
            "release_gate_blocked",
            release_handoff["next_required_action"]
                .as_str()
                .unwrap_or("inspect_release_gate")
                .to_string(),
        )
    } else if release_review["review_verdict"].as_str() != Some("ready") {
        (
            "pilot_review_blocked",
            pilot_review["next_required_action"]
                .as_str()
                .unwrap_or("inspect_pilot_review")
                .to_string(),
        )
    } else {
        (
            "needs_operator_review",
            "inspect_release_wave_status".to_string(),
        )
    };

    let payload = json!({
        "artifact_schema": "ubuntu_release_wave_status_v1",
        "supported_product_contour": "ubuntu_first_release_wave",
        "supported_operator_scope": "ubuntu_release_evidence_collection",
        "pilot_inputs_json": display_path(pilot_inputs_path),
        "release_handoff_json": pilot_inputs.get("release_gate_handoff_json").cloned().unwrap_or(Value::Null),
        "release_summary_json": pilot_inputs.get("release_summary_json").cloned().unwrap_or(Value::Null),
        "pilot_review_manifest_json": display_path(pilot_review_manifest_path),
        "release_readiness": release_handoff.get("release_readiness").or_else(|| release_summary.get("release_readiness")).cloned().unwrap_or(Value::Null),
        "ship_ready": release_handoff.get("ship_ready").cloned().unwrap_or(Value::Null),
        "ship_decision": release_review.get("ship_decision").cloned().unwrap_or(Value::Null),
        "review_verdict": release_review.get("review_verdict").cloned().unwrap_or(Value::Null),
        "service_health_verdict": release_summary.get("service_health_verdict").cloned().unwrap_or(Value::Null),
        "bypass_verdict": release_review.get("bypass_verdict").or_else(|| release_summary.get("bypass_verdict")).cloned().unwrap_or(Value::Null),
        "bypass_ready": release_review.get("bypass_ready").cloned().unwrap_or(Value::Null),
        "bypass_support_tier": release_review.get("bypass_support_tier").or_else(|| release_summary.get("bypass_support_tier")).cloned().unwrap_or(Value::Null),
        "baseline_bypass_ready": release_review.get("baseline_bypass_ready").cloned().unwrap_or(Value::Null),
        "hostile_path_verdict": release_review.get("hostile_path_verdict").or_else(|| release_summary.get("hostile_path_verdict")).cloned().unwrap_or(Value::Null),
        "hostile_path_ready": release_review.get("hostile_path_ready").cloned().unwrap_or(Value::Null),
        "fully_proven": release_review.get("fully_proven").and_then(Value::as_bool) == Some(true),
        "product_proof_status": release_review.get("product_proof_status").cloned().unwrap_or(Value::Null),
        "mimicry_closure_scope": release_review.get("mimicry_closure_scope").cloned().unwrap_or(Value::Null),
        "mimicry_program_boundary": release_review.get("mimicry_program_boundary").cloned().unwrap_or(Value::Null),
        "wire_mimicry_verdict": release_review.get("wire_mimicry_verdict").cloned().unwrap_or(Value::Null),
        "wire_mimicry_verdict_reason": release_review.get("wire_mimicry_verdict_reason").cloned().unwrap_or(Value::Null),
        "wire_hostile_path_support_ready": release_review.get("wire_hostile_path_support_ready").cloned().unwrap_or(Value::Null),
        "wire_hostile_path_support_tier": release_review.get("wire_hostile_path_support_tier").cloned().unwrap_or(Value::Null),
        "independent_witness_correlation_status": release_review.get("independent_witness_correlation_status").cloned().unwrap_or(Value::Null),
        "independent_witness_records_matched": release_review.get("independent_witness_records_matched").cloned().unwrap_or(Value::Null),
        "independent_witness_records_mismatched": release_review.get("independent_witness_records_mismatched").cloned().unwrap_or(Value::Null),
        "pilot_verdict": pilot_review.get("pilot_verdict").cloned().unwrap_or(Value::Null),
        "operator_canary_verdict": pilot_review.get("operator_canary_verdict").cloned().unwrap_or(Value::Null),
        "restart_canary_ready": pilot_review.get("restart_canary_ready").cloned().unwrap_or(Value::Null),
        "rollback_canary_ready": pilot_review.get("rollback_canary_ready").cloned().unwrap_or(Value::Null),
        "reapply_canary_ready": pilot_review.get("reapply_canary_ready").cloned().unwrap_or(Value::Null),
        "must_pass_verdict": release_review.get("must_pass_verdict").cloned().unwrap_or(Value::Null),
        "must_pass_failures": release_review.get("must_pass_failures").cloned().unwrap_or_else(|| json!([])),
        "advisory_verdict": release_review.get("advisory_verdict").cloned().unwrap_or(Value::Null),
        "advisory_followups": release_review.get("advisory_followups").cloned().unwrap_or_else(|| json!([])),
        "wave_status": wave_status,
        "claim_boundary_note": "Ubuntu-first release wave stays primary; ship-ready now requires live bypass proof, while wire mimicry raises confidence from baseline transport/runtime toward wire-level support",
        "next_required_action": next_required_action,
    });
    write_json(output_path, &payload)?;
    Ok(())
}

fn required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str, Box<dyn std::error::Error>> {
    value[field]
        .as_str()
        .ok_or_else(|| format!("{field} missing").into())
}

fn first_array_string(value: &Value) -> Option<String> {
    value
        .as_array()
        .and_then(|items| items.first())
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn display_path(path: &Path) -> String {
    path.components().collect::<PathBuf>().display().to_string()
}
