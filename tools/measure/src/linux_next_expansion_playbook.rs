use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::artifact::{read_json, write_json, write_text};

pub fn build_linux_next_expansion_playbook(
    output_dir: &Path,
    matrix_manifest_path: &Path,
    requested_target_family: Option<&str>,
    host_label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = read_json(matrix_manifest_path)?;
    let results_path = manifest["matrix_results_artifact"]
        .as_str()
        .ok_or("matrix manifest does not define matrix_results_artifact")?;
    let results = read_json(Path::new(results_path))?;
    let targets = manifest
        .get("documented_host_family_matrix")
        .and_then(Value::as_array)
        .ok_or("matrix manifest does not define documented_host_family_matrix")?;

    let target_family = requested_target_family
        .filter(|value| !value.is_empty())
        .or_else(|| {
            manifest
                .get("next_expansion_candidate")
                .and_then(Value::as_str)
        })
        .ok_or("Matrix manifest does not define a next expansion candidate")?;

    let target = targets
        .iter()
        .find(|item| item.get("host_family_id").and_then(Value::as_str) == Some(target_family))
        .ok_or_else(|| {
            format!("Target family is not present in matrix manifest: {target_family}")
        })?;

    let target_wave_role = if Some(target_family)
        == manifest
            .get("canonical_release_family")
            .and_then(Value::as_str)
    {
        "canonical_first_non_ubuntu_family"
    } else {
        "subsequent_non_ubuntu_family"
    };

    let existing_evidence_paths = results
        .as_array()
        .ok_or("matrix results artifact must be a JSON array")?
        .iter()
        .filter_map(|item| item.get("evidence_path").and_then(Value::as_str))
        .map(str::to_string)
        .collect::<Vec<_>>();

    let target_evidence_dir = format!("dist/linux-family-evidence/{target_family}");
    let target_evidence_json = format!("{target_evidence_dir}/host-validation.json");
    let target_artifact_dir = format!("{target_evidence_dir}/artifacts");
    let mut matrix_refresh_evidence = existing_evidence_paths.clone();
    matrix_refresh_evidence.push(target_evidence_json.clone());
    let matrix_refresh_command = format!(
        "bash scripts/build-linux-package-acceptance-matrix.sh <output-dir> {}",
        matrix_refresh_evidence
            .iter()
            .map(|path| format!("--evidence {path}"))
            .collect::<Vec<_>>()
            .join(" ")
    );

    let claim_boundary_note = if target_wave_role == "canonical_first_non_ubuntu_family" {
        "Debian 13 / debian-apt is the first canonical non-Ubuntu evidence contour; passing it expands live package-validation coverage without widening the Ubuntu-first ship-ready claim"
    } else {
        "successful additional non-Ubuntu evidence expands validation coverage but does not widen the Ubuntu-first ship-ready claim by itself"
    };

    let playbook = json!({
        "artifact_schema": "linux_next_expansion_playbook_v1",
        "supported_product_contour": "linux_multi_family_evidence_expansion",
        "supported_operator_scope": "next_non_ubuntu_host_evidence_collection",
        "matrix_manifest_json": display_path(matrix_manifest_path),
        "matrix_results_json": results_path,
        "release_claim_boundary": manifest.get("release_claim_boundary").cloned().unwrap_or(Value::Null),
        "canonical_release_family": manifest.get("canonical_release_family").cloned().unwrap_or(Value::Null),
        "target_wave_role": target_wave_role,
        "target_family_id": required_str(target, "host_family_id")?,
        "target_package_family": required_str(target, "package_family")?,
        "target_validation_tier": required_str(target, "validation_tier")?,
        "target_status": required_str(target, "status")?,
        "target_host_label": host_label,
        "target_helper_script": target.get("helper_script").cloned().unwrap_or(Value::Null),
        "target_evidence_json": target_evidence_json,
        "target_artifact_dir": target_artifact_dir,
        "claim_boundary_note": claim_boundary_note,
        "existing_evidence_paths": existing_evidence_paths,
        "steps": [
            {
                "phase": "host_check",
                "host": host_label,
                "command": required_str(target, "helper_check_command")?,
            },
            {
                "phase": "collect_live_evidence",
                "host": host_label,
                "command": required_str(target, "helper_run_json_command")?,
            },
            {
                "phase": "refresh_matrix",
                "host": "repo_or_artifact_aggregator",
                "command": matrix_refresh_command,
            },
        ],
    });

    write_json(&output_dir.join("next-expansion-playbook.json"), &playbook)?;
    write_text(
        &output_dir.join("next-expansion-playbook.md"),
        &render_markdown(&playbook),
    )?;

    Ok(())
}

fn render_markdown(playbook: &Value) -> String {
    let mut lines = vec![
        "# Linux Next Expansion Playbook".to_string(),
        String::new(),
        format!(
            "- Target host label: `{}`",
            playbook["target_host_label"].as_str().unwrap_or("")
        ),
        format!(
            "- Target family: `{}`",
            playbook["target_family_id"].as_str().unwrap_or("")
        ),
        format!(
            "- Target wave role: `{}`",
            playbook["target_wave_role"].as_str().unwrap_or("")
        ),
        format!(
            "- Target package family: `{}`",
            playbook["target_package_family"].as_str().unwrap_or("")
        ),
        format!(
            "- Release claim boundary: `{}`",
            playbook["release_claim_boundary"].as_str().unwrap_or("")
        ),
        format!(
            "- Canonical release family: `{}`",
            playbook["canonical_release_family"].as_str().unwrap_or("")
        ),
        format!(
            "- Evidence JSON: `{}`",
            playbook["target_evidence_json"].as_str().unwrap_or("")
        ),
        format!(
            "- Artifact dir: `{}`",
            playbook["target_artifact_dir"].as_str().unwrap_or("")
        ),
        String::new(),
        "## Boundary".to_string(),
        String::new(),
        format!(
            "- {}",
            playbook["claim_boundary_note"].as_str().unwrap_or("")
        ),
        String::new(),
        "## Steps".to_string(),
        String::new(),
    ];

    if let Some(steps) = playbook["steps"].as_array() {
        for step in steps {
            lines.push(format!(
                "- `{}` on `{}`: `{}`",
                step["phase"].as_str().unwrap_or(""),
                step["host"].as_str().unwrap_or(""),
                step["command"].as_str().unwrap_or("")
            ));
        }
    }

    lines.join("\n") + "\n"
}

fn required_str<'a>(value: &'a Value, key: &str) -> Result<&'a str, Box<dyn std::error::Error>> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("target.{key} missing").into())
}

fn display_path(path: &Path) -> String {
    path.components().collect::<PathBuf>().display().to_string()
}
