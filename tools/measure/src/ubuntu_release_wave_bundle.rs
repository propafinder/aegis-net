use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::artifact::{read_json, write_json};

pub fn build_ubuntu_release_wave_bundle_manifest(
    output_dir: &Path,
    pilot_review_manifest: &Path,
    wave_status: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let status = read_json(wave_status)?;
    let manifest = json!({
        "artifact_schema": "ubuntu_release_wave_bundle_v1",
        "supported_product_contour": "ubuntu_first_release_wave",
        "supported_operator_scope": "ubuntu_release_evidence_collection",
        "pilot_review_manifest_json": display_path(pilot_review_manifest),
        "pilot_review_md": display_path(&pilot_review_manifest.with_file_name("pilot-review.md")),
        "wave_status_json": display_path(wave_status),
        "service_health_verdict": status.get("service_health_verdict").cloned().unwrap_or(Value::Null),
        "bypass_verdict": status.get("bypass_verdict").cloned().unwrap_or(Value::Null),
        "bypass_ready": status.get("bypass_ready").cloned().unwrap_or(Value::Null),
        "bypass_support_tier": status.get("bypass_support_tier").cloned().unwrap_or(Value::Null),
        "hostile_path_verdict": status.get("hostile_path_verdict").cloned().unwrap_or(Value::Null),
        "hostile_path_ready": status.get("hostile_path_ready").cloned().unwrap_or(Value::Null),
        "fully_proven": status.get("fully_proven").cloned().unwrap_or(Value::Null),
        "product_proof_status": status.get("product_proof_status").cloned().unwrap_or(Value::Null),
        "wire_mimicry_verdict": status.get("wire_mimicry_verdict").cloned().unwrap_or(Value::Null),
        "operator_canary_verdict": status.get("operator_canary_verdict").cloned().unwrap_or(Value::Null),
        "restart_canary_ready": status.get("restart_canary_ready").cloned().unwrap_or(Value::Null),
        "rollback_canary_ready": status.get("rollback_canary_ready").cloned().unwrap_or(Value::Null),
        "reapply_canary_ready": status.get("reapply_canary_ready").cloned().unwrap_or(Value::Null),
        "must_pass_verdict": status.get("must_pass_verdict").cloned().unwrap_or(Value::Null),
        "must_pass_failures": status.get("must_pass_failures").cloned().unwrap_or(Value::Null),
        "advisory_verdict": status.get("advisory_verdict").cloned().unwrap_or(Value::Null),
        "advisory_followups": status.get("advisory_followups").cloned().unwrap_or(Value::Null),
        "ship_ready": required_value(&status, "ship_ready")?,
        "ship_decision": required_value(&status, "ship_decision")?,
        "wave_status": required_value(&status, "wave_status")?,
        "next_required_action": required_value(&status, "next_required_action")?,
    });
    write_json(
        &output_dir.join("ubuntu-release-wave.manifest.json"),
        &manifest,
    )?;
    Ok(())
}

fn required_value(value: &Value, key: &str) -> Result<Value, Box<dyn std::error::Error>> {
    value
        .get(key)
        .cloned()
        .ok_or_else(|| format!("{key} missing from release wave status").into())
}

fn display_path(path: &Path) -> String {
    path.components().collect::<PathBuf>().display().to_string()
}
