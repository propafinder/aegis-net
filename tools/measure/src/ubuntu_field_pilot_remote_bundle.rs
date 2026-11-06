use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::artifact::{read_json, write_json, write_text};
use crate::ubuntu_controlled_pilot_playbook::BundleInput;

pub fn build_ubuntu_field_pilot_remote_bundle_manifest(
    output_dir: &Path,
    pilot_inputs: &Path,
    pilot_review_manifest: &Path,
    release_wave_status: &Path,
    release_wave_manifest: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let _pilot_inputs_payload = read_json(pilot_inputs)?;
    let pilot_review = read_json(pilot_review_manifest)?;
    let bundle_input = BundleInput::from_artifact(&pilot_review)?;
    let release_wave_status_payload = read_json(release_wave_status)?;
    let _release_wave_manifest_payload = read_json(release_wave_manifest)?;

    let (field_pilot_status, next_required_action) =
        if pilot_review["operator_canary_verdict"].as_str() == Some("green")
            && release_wave_status_payload["bypass_ready"].as_bool() == Some(true)
        {
            let next = if release_wave_status_payload["fully_proven"].as_bool() != Some(true) {
                "collect_blocked_shape_wire_proof_to_reach_fully_proven"
            } else {
                "none"
            };
            ("remote_shape_ready_for_live_evidence", next.to_string())
        } else if pilot_review["operator_canary_verdict"].as_str() == Some("green") {
            (
                "operator_canary_green_but_bypass_not_proven",
                release_wave_status_payload["next_required_action"]
                    .as_str()
                    .unwrap_or("collect_live_bypass_proof")
                    .to_string(),
            )
        } else {
            (
                "operator_canary_not_green",
                pilot_review["next_required_action"]
                    .as_str()
                    .unwrap_or("inspect_operator_canary")
                    .to_string(),
            )
        };

    let payload = json!({
        "artifact_schema": "ubuntu_field_pilot_remote_bundle_v1",
        "supported_product_contour": "ubuntu_first_field_pilot_remote_bundle",
        "supported_operator_scope": "ubuntu_release_evidence_collection",
        "pilot_inputs_json": display_path(pilot_inputs),
        "pilot_review_manifest_json": display_path(pilot_review_manifest),
        "release_wave_status_json": display_path(release_wave_status),
        "release_wave_manifest_json": display_path(release_wave_manifest),
        "operator_reapply_canary_json": value_or_null(&pilot_review, "operator_reapply_canary_json"),
        "relay_host_label": value_or_null(&pilot_review, "relay_host_label"),
        "client_host_label": value_or_null(&pilot_review, "client_host_label"),
        "blocked_shape_label": value_or_null(&pilot_review, "blocked_shape_label"),
        "bundle_url_example": null,
        "bundle_input": bundle_input,
        "service_health_verdict": value_or_null(&pilot_review, "service_health_verdict"),
        "operator_canary_verdict": value_or_null(&pilot_review, "operator_canary_verdict"),
        "restart_canary_ready": value_or_null(&pilot_review, "restart_canary_ready"),
        "rollback_canary_ready": value_or_null(&pilot_review, "rollback_canary_ready"),
        "reapply_canary_ready": value_or_null(&pilot_review, "reapply_canary_ready"),
        "bypass_verdict": value_or_null(&release_wave_status_payload, "bypass_verdict"),
        "bypass_ready": value_or_null(&release_wave_status_payload, "bypass_ready"),
        "bypass_support_tier": value_or_null(&release_wave_status_payload, "bypass_support_tier"),
        "hostile_path_verdict": value_or_null(&release_wave_status_payload, "hostile_path_verdict"),
        "hostile_path_ready": value_or_null(&release_wave_status_payload, "hostile_path_ready"),
        "fully_proven": value_or_null(&release_wave_status_payload, "fully_proven"),
        "product_proof_status": value_or_null(&release_wave_status_payload, "product_proof_status"),
        "wave_status": value_or_null(&release_wave_status_payload, "wave_status"),
        "field_pilot_status": field_pilot_status,
        "canonical_bundle_steps": [
            "validate_debian_package_host_run",
            "operator_reapply_canary",
            "pilot_review_bundle",
            "release_wave_bundle",
        ],
        "next_required_action": next_required_action,
    });

    write_json(&output_dir.join("field-pilot-remote-bundle.json"), &payload)?;
    write_text(
        &output_dir.join("field-pilot-remote-bundle.md"),
        &render_markdown(&payload),
    )?;
    Ok(())
}

fn value_or_null(value: &Value, key: &str) -> Value {
    value.get(key).cloned().unwrap_or(Value::Null)
}

fn display_path(path: &Path) -> String {
    path.components().collect::<PathBuf>().display().to_string()
}

fn render_markdown(payload: &Value) -> String {
    let lines = [
        "# Ubuntu Field Pilot Remote Bundle".to_string(),
        String::new(),
        markdown_field(payload, "Relay host", "relay_host_label"),
        markdown_field(payload, "Client host", "client_host_label"),
        markdown_field(payload, "Field-pilot status", "field_pilot_status"),
        markdown_field(
            payload,
            "Operator canary verdict",
            "operator_canary_verdict",
        ),
        markdown_field(payload, "Bypass support tier", "bypass_support_tier"),
        markdown_field(payload, "Wave status", "wave_status"),
        markdown_field(payload, "Product proof status", "product_proof_status"),
        markdown_field(payload, "Next required action", "next_required_action"),
        String::new(),
        "## Artifacts".to_string(),
        String::new(),
        markdown_field(
            payload,
            "Pilot review manifest",
            "pilot_review_manifest_json",
        ),
        markdown_field(payload, "Release wave status", "release_wave_status_json"),
        markdown_field(payload, "Operator canary", "operator_reapply_canary_json"),
        String::new(),
    ];
    lines.join("\n")
}

fn markdown_field(payload: &Value, label: &str, key: &str) -> String {
    format!("- {label}: `{}`", payload[key].as_str().unwrap_or("null"))
}
