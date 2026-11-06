use std::path::Path;

use serde_json::{json, Value};

use crate::artifact::{read_json, write_json, write_text};

pub fn print_linux_next_expansion_review_inputs(
    matrix_manifest_path: &Path,
    target_evidence_path: &Path,
    requested_target_family: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = read_json(matrix_manifest_path)?;
    let target_evidence = read_json(target_evidence_path)?;
    let results_path = manifest["matrix_results_artifact"]
        .as_str()
        .ok_or("matrix manifest does not define matrix_results_artifact")?;
    let results = read_json(Path::new(results_path))?;
    let target_family = requested_target_family
        .filter(|value| !value.is_empty())
        .or_else(|| {
            manifest
                .get("next_expansion_candidate")
                .and_then(Value::as_str)
        })
        .ok_or("Matrix manifest does not define a next expansion candidate")?;

    let evidence_family = target_evidence
        .get("host_family_id")
        .and_then(Value::as_str);
    if evidence_family != Some(target_family) {
        return Err(format!(
            "Target evidence host family mismatch: expected {}, got {}",
            target_family,
            evidence_family.unwrap_or("<missing>")
        )
        .into());
    }

    for item in results
        .as_array()
        .ok_or("matrix results artifact must be a JSON array")?
    {
        if let Some(evidence_path) = item.get("evidence_path").and_then(Value::as_str) {
            println!("{evidence_path}");
        }
    }
    println!("__TARGET_FAMILY__={target_family}");
    Ok(())
}

pub fn build_linux_next_expansion_review_bundle_artifacts(
    output_dir: &Path,
    previous_matrix_manifest_path: &Path,
    target_evidence_path: &Path,
    playbook_path: &Path,
    refreshed_matrix_manifest_path: &Path,
    host_label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let previous_manifest = read_json(previous_matrix_manifest_path)?;
    let playbook = read_json(playbook_path)?;
    let refreshed_manifest = read_json(refreshed_matrix_manifest_path)?;
    let refreshed_results_path = refreshed_manifest["matrix_results_artifact"]
        .as_str()
        .ok_or("refreshed matrix manifest does not define matrix_results_artifact")?;
    let refreshed_results = read_json(Path::new(refreshed_results_path))?;

    let target_family = playbook["target_family_id"]
        .as_str()
        .ok_or("playbook.target_family_id missing")?;
    let target_result = refreshed_results
        .as_array()
        .ok_or("refreshed matrix results artifact must be a JSON array")?
        .iter()
        .find(|item| item.get("host_family_id").and_then(Value::as_str) == Some(target_family))
        .ok_or("target family missing from refreshed matrix results")?;

    let mut blockers = Vec::new();
    if target_result.get("status").and_then(Value::as_str) != Some("passed") {
        blockers.push("target_family_evidence_not_passed");
    }

    let review_verdict = if blockers.is_empty() {
        "ready"
    } else {
        "blocked"
    };
    let claim_boundary_note = if playbook.get("target_wave_role").and_then(Value::as_str)
        == Some("canonical_first_non_ubuntu_family")
    {
        "Debian 13 / debian-apt is the first canonical non-Ubuntu evidence contour; passing it expands validation coverage without changing the Ubuntu-first ship-ready boundary"
    } else {
        "additional non-Ubuntu family evidence expands validation coverage but does not change the Ubuntu-first ship-ready boundary"
    };

    let review = json!({
        "artifact_schema": "linux_next_expansion_review_v1",
        "supported_product_contour": "linux_multi_family_evidence_expansion",
        "supported_operator_scope": "next_non_ubuntu_host_evidence_review",
        "previous_matrix_manifest_json": display_path(previous_matrix_manifest_path),
        "refreshed_matrix_manifest_json": display_path(refreshed_matrix_manifest_path),
        "playbook_json": display_path(playbook_path),
        "target_evidence_json": display_path(target_evidence_path),
        "target_family_id": target_family,
        "target_wave_role": playbook.get("target_wave_role").cloned().unwrap_or(Value::Null),
        "target_host_label": host_label,
        "target_package_family": playbook.get("target_package_family").cloned().unwrap_or(Value::Null),
        "target_os_pretty_name": target_result.get("os_pretty_name").cloned().unwrap_or(Value::Null),
        "target_package_manager": target_result.get("package_manager").cloned().unwrap_or(Value::Null),
        "target_result_status": target_result.get("status").cloned().unwrap_or(Value::Null),
        "target_result_notes": target_result.get("notes").cloned().unwrap_or(Value::Null),
        "review_verdict": review_verdict,
        "blocking_reasons": blockers,
        "release_claim_boundary": refreshed_manifest.get("release_claim_boundary").cloned().unwrap_or(Value::Null),
        "canonical_release_family": refreshed_manifest.get("canonical_release_family").cloned().unwrap_or(Value::Null),
        "next_expansion_candidate_before_refresh": previous_manifest.get("next_expansion_candidate").cloned().unwrap_or(Value::Null),
        "next_expansion_candidate_after_refresh": refreshed_manifest.get("next_expansion_candidate").cloned().unwrap_or(Value::Null),
        "claim_boundary_note": claim_boundary_note,
        "next_required_action": if review_verdict == "ready" { "none" } else { "inspect_refreshed_matrix_results" },
    });

    let review_json = output_dir.join("next-expansion-review.json");
    let review_md = output_dir.join("next-expansion-review.md");
    let manifest_json = output_dir.join("next-expansion-review.manifest.json");
    write_json(&review_json, &review)?;
    write_text(&review_md, &render_review_markdown(&review))?;

    let manifest = json!({
        "artifact_schema": "linux_next_expansion_review_bundle_v1",
        "supported_product_contour": "linux_multi_family_evidence_expansion",
        "supported_operator_scope": "next_non_ubuntu_host_evidence_review",
        "playbook_json": display_path(playbook_path),
        "playbook_md": display_path(&playbook_path.with_extension("md")),
        "refreshed_matrix_manifest_json": display_path(refreshed_matrix_manifest_path),
        "refreshed_matrix_summary_md": refreshed_manifest.get("matrix_summary_artifact").cloned().unwrap_or(Value::Null),
        "next_expansion_review_json": display_path(&review_json),
        "next_expansion_review_md": display_path(&review_md),
        "target_family_id": review["target_family_id"].clone(),
        "target_wave_role": review["target_wave_role"].clone(),
        "target_result_status": review["target_result_status"].clone(),
        "review_verdict": review["review_verdict"].clone(),
        "next_required_action": review["next_required_action"].clone(),
    });
    write_json(&manifest_json, &manifest)?;
    Ok(())
}

fn render_review_markdown(review: &Value) -> String {
    let blockers = review["blocking_reasons"]
        .as_array()
        .map(|items| {
            if items.is_empty() {
                "none".to_string()
            } else {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        })
        .unwrap_or_else(|| "none".to_string());
    let before = review["next_expansion_candidate_before_refresh"]
        .as_str()
        .unwrap_or("none");
    let after = review["next_expansion_candidate_after_refresh"]
        .as_str()
        .unwrap_or("none");

    [
        "# Linux Next Expansion Review".to_string(),
        String::new(),
        format!(
            "- Target host label: `{}`",
            review["target_host_label"].as_str().unwrap_or("")
        ),
        format!(
            "- Target family: `{}`",
            review["target_family_id"].as_str().unwrap_or("")
        ),
        format!(
            "- Target result status: `{}`",
            review["target_result_status"].as_str().unwrap_or("")
        ),
        format!(
            "- Review verdict: `{}`",
            review["review_verdict"].as_str().unwrap_or("")
        ),
        format!("- Blocking reasons: `{blockers}`"),
        format!("- Next expansion candidate before refresh: `{before}`"),
        format!("- Next expansion candidate after refresh: `{after}`"),
        format!(
            "- Claim boundary: `{}`",
            review["release_claim_boundary"].as_str().unwrap_or("")
        ),
        String::new(),
        "## Boundary".to_string(),
        String::new(),
        format!("- {}", review["claim_boundary_note"].as_str().unwrap_or("")),
    ]
    .join("\n")
        + "\n"
}

fn display_path(path: &Path) -> String {
    path.display().to_string()
}
