use std::path::Path;
use std::path::PathBuf;

use serde_json::{json, Value};

use crate::artifact::{read_json, read_optional_json_path, write_json};

pub fn build_linux_next_expansion_status(
    matrix_manifest_path: &Path,
    output_path: &Path,
    review_json_path: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let matrix_manifest = read_json(matrix_manifest_path)?;
    let matrix_results_path = matrix_manifest["matrix_results_artifact"]
        .as_str()
        .ok_or("matrix_manifest.matrix_results_artifact missing")?;
    let matrix_results = read_json(Path::new(matrix_results_path))?;
    let review = read_optional_json_path(review_json_path)?;

    let next_candidate = matrix_manifest
        .get("next_expansion_candidate")
        .cloned()
        .unwrap_or(Value::Null);
    let canonical_release_family = matrix_manifest
        .get("canonical_release_family")
        .cloned()
        .unwrap_or(Value::Null);
    let next_expansion_wave_role =
        if !next_candidate.is_null() && next_candidate == canonical_release_family {
            Value::String("canonical_first_non_ubuntu_family".to_string())
        } else if !next_candidate.is_null() {
            Value::String("subsequent_non_ubuntu_family".to_string())
        } else {
            Value::Null
        };

    let pending_families = matrix_manifest
        .get("pending_families")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let failed_families = matrix_manifest
        .get("failed_families")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let passed_families = matrix_manifest
        .get("passed_families")
        .cloned()
        .unwrap_or_else(|| json!([]));

    let latest_review_family = review
        .as_ref()
        .and_then(|review| review.get("target_family_id"))
        .cloned()
        .unwrap_or(Value::Null);
    let latest_review_verdict = review
        .as_ref()
        .and_then(|review| review.get("review_verdict"))
        .cloned()
        .unwrap_or(Value::Null);
    let latest_review_result_status = review
        .as_ref()
        .and_then(|review| review.get("target_result_status"))
        .cloned()
        .unwrap_or(Value::Null);
    let latest_review_applied = review.as_ref().is_some_and(|_| {
        matrix_results.as_array().is_some_and(|items| {
            items.iter().any(|item| {
                item.get("host_family_id") == Some(&latest_review_family)
                    && item.get("status") == Some(&latest_review_result_status)
            })
        })
    });

    let failed_non_empty = failed_families
        .as_array()
        .is_some_and(|items| !items.is_empty());
    let pending_non_empty = pending_families
        .as_array()
        .is_some_and(|items| !items.is_empty());
    let next_candidate_present = !next_candidate.is_null();

    let (expansion_status, next_required_action) = if latest_review_verdict.as_str()
        == Some("blocked")
    {
        (
            "latest_review_blocked".to_string(),
            review
                .as_ref()
                .and_then(|review| review["next_required_action"].as_str())
                .unwrap_or("inspect_latest_review")
                .to_string(),
        )
    } else if failed_non_empty {
        (
            "matrix_has_failed_families".to_string(),
            "inspect_matrix_results".to_string(),
        )
    } else if next_candidate_present {
        let status = if latest_review_verdict.as_str() == Some("ready") && latest_review_applied {
            "target_validated_next_candidate_pending"
        } else {
            "pending_next_family"
        };
        (
                status.to_string(),
                format!(
                    "bash scripts/build-linux-next-expansion-playbook.sh <output-dir> --matrix-manifest {}",
                    display_path(matrix_manifest_path)
                ),
            )
    } else if pending_non_empty {
        (
            "pending_families_without_next_candidate".to_string(),
            "inspect_matrix_manifest".to_string(),
        )
    } else {
        (
            "all_documented_families_validated".to_string(),
            "none".to_string(),
        )
    };

    let claim_boundary_note = if next_expansion_wave_role.as_str()
        == Some("canonical_first_non_ubuntu_family")
    {
        "Debian 13 / debian-apt remains the first canonical non-Ubuntu evidence contour; that live evidence expands validation coverage without widening the Ubuntu-first ship-ready boundary"
    } else {
        "non-Ubuntu family evidence expands validation coverage but does not widen the Ubuntu-first ship-ready boundary"
    };

    let payload = json!({
        "artifact_schema": "linux_next_expansion_status_v1",
        "supported_product_contour": "linux_multi_family_evidence_expansion",
        "supported_operator_scope": "next_non_ubuntu_host_evidence_status",
        "matrix_manifest_json": display_path(matrix_manifest_path),
        "matrix_results_json": matrix_manifest.get("matrix_results_artifact").cloned().unwrap_or(Value::Null),
        "release_claim_boundary": matrix_manifest.get("release_claim_boundary").cloned().unwrap_or(Value::Null),
        "canonical_release_family": canonical_release_family,
        "passed_families": passed_families,
        "failed_families": failed_families,
        "pending_families": pending_families,
        "next_expansion_candidate": next_candidate,
        "next_expansion_wave_role": next_expansion_wave_role,
        "latest_review_json": review_json_path.map(display_path),
        "latest_review_applied": latest_review_applied,
        "latest_review_family": latest_review_family,
        "latest_review_verdict": latest_review_verdict,
        "latest_review_result_status": latest_review_result_status,
        "expansion_status": expansion_status,
        "claim_boundary_note": claim_boundary_note,
        "next_required_action": next_required_action,
    });
    write_json(output_path, &payload)?;
    Ok(())
}

fn display_path(path: &Path) -> String {
    path.components().collect::<PathBuf>().display().to_string()
}
