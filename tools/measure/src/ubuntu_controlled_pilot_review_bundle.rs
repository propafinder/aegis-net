use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::artifact::{read_json, write_json, write_text};
use crate::ubuntu_controlled_pilot_playbook::BundleInput;

pub fn print_ubuntu_pilot_inputs_release_summary(
    pilot_inputs: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = read_json(pilot_inputs)?;
    println!("{}", payload["release_summary_json"].as_str().unwrap_or(""));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn build_ubuntu_controlled_pilot_review_bundle_manifest(
    output_dir: &Path,
    pilot_inputs: &Path,
    playbook_json: &Path,
    operator_canary_json: &Path,
    pilot_summary_json: &Path,
    release_review_json: &Path,
    matrix_manifest: Option<&Path>,
    wire_witness_summary: Option<&Path>,
    wire_acceptance_summary: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let pilot_inputs_payload = read_json(pilot_inputs)?;
    let playbook = read_json(playbook_json)?;
    let bundle_input = BundleInput::from_artifact(&playbook)?;
    let operator_canary = read_json(operator_canary_json)?;
    let pilot_summary = read_json(pilot_summary_json)?;
    let release_review = read_json(release_review_json)?;

    let ship_decision = release_review
        .get("ship_decision")
        .cloned()
        .unwrap_or(Value::Null);
    let next_required_action =
        if operator_canary["operator_canary_verdict"].as_str() != Some("green") {
            operator_canary["next_required_action"]
                .as_str()
                .unwrap_or("inspect_operator_canary")
                .to_string()
        } else if ship_decision.as_str() == Some("ship")
            && release_review["fully_proven"].as_bool() == Some(true)
        {
            "none".to_string()
        } else if ship_decision.as_str() == Some("ship") {
            "collect_hostile_path_proof_to_reach_fully_proven".to_string()
        } else if pilot_summary["bypass_ready"].as_bool() != Some(true) {
            "collect_live_bypass_proof".to_string()
        } else if pilot_summary["pilot_verdict"].as_str() != Some("green") {
            "inspect_pilot_summary_and_fix_blockers".to_string()
        } else {
            "inspect_release_review_blockers".to_string()
        };

    let manifest = json!({
        "artifact_schema": "ubuntu_controlled_pilot_review_bundle_v1",
        "supported_product_contour": "ubuntu_first_controlled_pilot_review",
        "supported_operator_scope": "ubuntu_release_evidence_collection",
        "pilot_inputs_json": display_path(pilot_inputs),
        "release_summary_json": value_or_null(&pilot_inputs_payload, "release_summary_json"),
        "playbook_json": display_path(playbook_json),
        "playbook_md": display_path(&playbook_json.with_extension("md")),
        "operator_reapply_canary_json": display_path(operator_canary_json),
        "operator_reapply_canary_md": display_path(&operator_canary_json.with_extension("md")),
        "pilot_summary_json": display_path(pilot_summary_json),
        "pilot_summary_md": display_path(&pilot_summary_json.with_extension("md")),
        "release_review_json": display_path(release_review_json),
        "release_review_md": display_path(&release_review_json.with_extension("md")),
        "matrix_manifest_json": matrix_manifest.map(display_path),
        "wire_witness_summary_json": wire_witness_summary.map(display_path),
        "wire_acceptance_summary_json": wire_acceptance_summary.map(display_path),
        "relay_host_label": value_or_null(&playbook, "relay_host_label"),
        "client_host_label": value_or_null(&playbook, "client_host_label"),
        "blocked_shape_label": value_or_null(&playbook, "blocked_shape_label"),
        "bundle_url_example": null,
        "bundle_input": bundle_input,
        "service_health_verdict": value_or_null(&pilot_summary, "service_health_verdict"),
        "operator_canary_verdict": value_or_null(&operator_canary, "operator_canary_verdict"),
        "restart_canary_ready": value_or_null(&operator_canary, "restart_canary_ready"),
        "rollback_canary_ready": value_or_null(&operator_canary, "rollback_canary_ready"),
        "reapply_canary_ready": value_or_null(&operator_canary, "reapply_canary_ready"),
        "baseline_bypass_ready": value_or_null(&release_review, "baseline_bypass_ready"),
        "bypass_verdict": value_or_fallback(&release_review, &pilot_summary, "bypass_verdict"),
        "bypass_ready": value_or_null(&release_review, "bypass_ready"),
        "bypass_support_tier": value_or_fallback(&release_review, &pilot_summary, "bypass_support_tier"),
        "hostile_path_verdict": value_or_fallback(&release_review, &pilot_summary, "hostile_path_verdict"),
        "hostile_path_ready": value_or_null(&release_review, "hostile_path_ready"),
        "fully_proven": value_or_null(&release_review, "fully_proven"),
        "product_proof_status": value_or_null(&release_review, "product_proof_status"),
        "mimicry_closure_scope": value_or_null(&release_review, "mimicry_closure_scope"),
        "mimicry_program_boundary": value_or_null(&release_review, "mimicry_program_boundary"),
        "wire_mimicry_verdict": value_or_null(&release_review, "wire_mimicry_verdict"),
        "wire_mimicry_verdict_reason": value_or_null(&release_review, "wire_mimicry_verdict_reason"),
        "wire_hostile_path_support_ready": value_or_null(&release_review, "wire_hostile_path_support_ready"),
        "wire_hostile_path_support_tier": value_or_null(&release_review, "wire_hostile_path_support_tier"),
        "independent_witness_correlation_status": value_or_null(&release_review, "independent_witness_correlation_status"),
        "independent_witness_records_matched": value_or_null(&release_review, "independent_witness_records_matched"),
        "independent_witness_records_mismatched": value_or_null(&release_review, "independent_witness_records_mismatched"),
        "pilot_verdict": value_or_null(&pilot_summary, "pilot_verdict"),
        "review_verdict": value_or_null(&release_review, "review_verdict"),
        "ship_decision": ship_decision,
        "canonical_steps": ["pilot_playbook", "operator_reapply_canary", "pilot_bundle", "release_review"],
        "next_required_action": next_required_action,
    });

    write_json(&output_dir.join("pilot-review.manifest.json"), &manifest)?;
    write_text(
        &output_dir.join("pilot-review.md"),
        &render_markdown(&manifest),
    )?;
    Ok(())
}

fn value_or_null(value: &Value, key: &str) -> Value {
    value.get(key).cloned().unwrap_or(Value::Null)
}

fn value_or_fallback(primary: &Value, fallback: &Value, key: &str) -> Value {
    primary
        .get(key)
        .or_else(|| fallback.get(key))
        .cloned()
        .unwrap_or(Value::Null)
}

fn display_path(path: &Path) -> String {
    path.components().collect::<PathBuf>().display().to_string()
}

fn render_markdown(manifest: &Value) -> String {
    let mut lines = vec![
        "# Ubuntu Controlled Pilot Review Bundle".to_string(),
        String::new(),
        markdown_field(manifest, "Relay host", "relay_host_label"),
        markdown_field(manifest, "Client host", "client_host_label"),
        markdown_field(manifest, "Blocked shape", "blocked_shape_label"),
        markdown_field(manifest, "Service health verdict", "service_health_verdict"),
        markdown_field(
            manifest,
            "Operator canary verdict",
            "operator_canary_verdict",
        ),
        markdown_field(manifest, "Bypass verdict", "bypass_verdict"),
        markdown_field(manifest, "Bypass support tier", "bypass_support_tier"),
        markdown_field(manifest, "Product proof status", "product_proof_status"),
        markdown_field(manifest, "Hostile-path verdict", "hostile_path_verdict"),
        markdown_field(
            manifest,
            "Independent witness correlation",
            "independent_witness_correlation_status",
        ),
        markdown_field(manifest, "Pilot verdict", "pilot_verdict"),
        markdown_field(manifest, "Review verdict", "review_verdict"),
        markdown_field(manifest, "Ship decision", "ship_decision"),
        markdown_field(manifest, "Next required action", "next_required_action"),
        String::new(),
        "## Artifacts".to_string(),
        String::new(),
        markdown_field(manifest, "Playbook", "playbook_json"),
        markdown_field(manifest, "Operator canary", "operator_reapply_canary_json"),
        markdown_field(manifest, "Pilot summary", "pilot_summary_json"),
        markdown_field(manifest, "Release review", "release_review_json"),
    ];
    if manifest["matrix_manifest_json"].is_string() {
        lines.push(markdown_field(
            manifest,
            "Matrix manifest",
            "matrix_manifest_json",
        ));
    }
    if manifest["wire_witness_summary_json"].is_string() {
        lines.push(markdown_field(
            manifest,
            "Wire witness summary",
            "wire_witness_summary_json",
        ));
    }
    if manifest["wire_acceptance_summary_json"].is_string() {
        lines.push(markdown_field(
            manifest,
            "Wire acceptance summary",
            "wire_acceptance_summary_json",
        ));
    }
    lines.push(String::new());
    lines.join("\n")
}

fn markdown_field(payload: &Value, label: &str, key: &str) -> String {
    format!("- {label}: `{}`", payload[key].as_str().unwrap_or("null"))
}
