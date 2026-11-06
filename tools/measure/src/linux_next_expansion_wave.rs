use std::path::Path;

use serde_json::{json, Value};

use crate::artifact::{read_json, write_json};

pub fn build_linux_next_expansion_wave_manifest(
    output: &Path,
    mode: &str,
    source_json: &Path,
    status_json: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let source = read_json(source_json)?;
    let status = read_json(status_json)?;

    let (
        playbook_json,
        playbook_md,
        review_bundle_manifest_json,
        target_family_id,
        target_wave_role,
    ) = match mode {
        "plan_only" => (
            Value::String(display_path(source_json)),
            Value::String(display_path(&source_json.with_extension("md"))),
            Value::Null,
            source
                .get("target_family_id")
                .cloned()
                .unwrap_or(Value::Null),
            source
                .get("target_wave_role")
                .cloned()
                .unwrap_or(Value::Null),
        ),
        "review_with_evidence" => (
            source.get("playbook_json").cloned().unwrap_or(Value::Null),
            source.get("playbook_md").cloned().unwrap_or(Value::Null),
            Value::String(display_path(source_json)),
            source
                .get("target_family_id")
                .cloned()
                .unwrap_or(Value::Null),
            source
                .get("target_wave_role")
                .cloned()
                .unwrap_or(Value::Null),
        ),
        _ => return Err(format!("unsupported linux next expansion wave mode: {mode}").into()),
    };

    let manifest = json!({
        "artifact_schema": "linux_next_expansion_wave_bundle_v1",
        "supported_product_contour": "linux_multi_family_evidence_expansion",
        "supported_operator_scope": "next_non_ubuntu_host_evidence_wave",
        "mode": mode,
        "playbook_json": playbook_json,
        "playbook_md": playbook_md,
        "status_json": display_path(status_json),
        "review_bundle_manifest_json": review_bundle_manifest_json,
        "target_family_id": target_family_id,
        "target_wave_role": target_wave_role,
        "expansion_status": status.get("expansion_status").cloned().unwrap_or(Value::Null),
        "next_required_action": status.get("next_required_action").cloned().unwrap_or(Value::Null),
    });
    write_json(output, &manifest)?;
    Ok(())
}

fn display_path(path: &Path) -> String {
    path.display().to_string()
}
