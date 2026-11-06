use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::artifact::{read_json, write_json, write_text};

pub fn build_ubuntu_release_review(
    output_dir: &Path,
    release_summary_path: &Path,
    pilot_bundle_path: &Path,
    matrix_manifest_path: Option<&Path>,
    wire_acceptance_summary_path: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let release_summary = read_json(release_summary_path)?;
    let pilot_summary = read_json(pilot_bundle_path)?;
    let matrix_manifest = read_optional_json(matrix_manifest_path)?;
    let wire_summary = read_optional_json(wire_acceptance_summary_path)?;

    let mut blockers = Vec::new();
    let mut notes = Vec::new();

    let mut wire_verdict: Option<String> = None;
    let mut wire_verdict_reason = Value::Null;
    let mut wire_hostile_path_ready = false;
    let mut wire_hostile_path_tier = "not_proven".to_string();
    let mut wire_witness_correlation_status = "not_provided".to_string();
    let mut wire_witness_records_matched = 0;
    let mut wire_witness_records_mismatched = 0;

    if let Some(wire_summary) = &wire_summary {
        wire_verdict = value_string(wire_summary, "verdict")
            .or_else(|| value_string(wire_summary, "product_verdict"));
        wire_verdict_reason = wire_summary
            .get("verdict_reason")
            .cloned()
            .unwrap_or(Value::Null);
        wire_hostile_path_ready =
            wire_summary["hostile_path_support_ready"].as_bool() == Some(true);
        wire_hostile_path_tier = value_string(wire_summary, "hostile_path_support_tier")
            .unwrap_or_else(|| {
                if wire_hostile_path_ready {
                    "wire_level_supported_hostile_path".to_string()
                } else {
                    "not_proven".to_string()
                }
            });
        wire_witness_correlation_status =
            value_string(wire_summary, "independent_witness_correlation_status")
                .unwrap_or_else(|| "unknown".to_string());
        wire_witness_records_matched =
            value_u64_or(wire_summary, "independent_witness_records_matched", 0);
        wire_witness_records_mismatched =
            value_u64_or(wire_summary, "independent_witness_records_mismatched", 0);
    }

    let wire_degraded = matches!(
        wire_verdict
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "degraded" | "yellow"
    );

    let rollout_acceptance = pilot_summary
        .get("rollout_acceptance")
        .and_then(Value::as_object);
    let must_pass_verdict = value_string(&pilot_summary, "must_pass_verdict").or_else(|| {
        rollout_acceptance
            .and_then(|rollout| rollout.get("must_pass_verdict"))
            .and_then(Value::as_str)
            .map(ToString::to_string)
    });
    let must_pass_failures = value_array_strings(&pilot_summary, "must_pass_failures")
        .or_else(|| {
            rollout_acceptance
                .and_then(|rollout| rollout.get("must_pass_failures"))
                .and_then(array_strings)
        })
        .unwrap_or_default();
    let advisory_verdict = value_string(&pilot_summary, "advisory_verdict").or_else(|| {
        rollout_acceptance
            .and_then(|rollout| rollout.get("advisory_verdict"))
            .and_then(Value::as_str)
            .map(ToString::to_string)
    });
    let advisory_followups = value_array_strings(&pilot_summary, "advisory_followups")
        .or_else(|| {
            rollout_acceptance
                .and_then(|rollout| rollout.get("advisory_followups"))
                .and_then(array_strings)
        })
        .unwrap_or_default();

    if bool_with_fallback(&release_summary, "baseline_bypass_ready", "bypass_ready") != Some(true) {
        blockers.push(
            value_string(&release_summary, "baseline_bypass_blocker_reason")
                .or_else(|| value_string(&release_summary, "bypass_blocker_reason"))
                .unwrap_or_else(|| "ubuntu_release_bypass_not_proven".to_string()),
        );
    }
    if bool_with_fallback(&pilot_summary, "baseline_bypass_ready", "bypass_ready") != Some(true) {
        blockers.push(
            value_string(&pilot_summary, "baseline_bypass_blocker_reason")
                .or_else(|| value_string(&pilot_summary, "bypass_blocker_reason"))
                .unwrap_or_else(|| "pilot_live_bypass_not_proven".to_string()),
        );
    }
    if pilot_summary["pilot_verdict"].as_str() != Some("green") {
        blockers.push(format!(
            "pilot_verdict_{}",
            pilot_summary["pilot_verdict"].as_str().unwrap_or("unknown")
        ));
    }
    if must_pass_verdict.as_deref() == Some("fail") {
        blockers.extend(must_pass_failures.iter().cloned());
    }

    if let Some(matrix_manifest) = &matrix_manifest {
        if let Some(next_expansion) = value_string(matrix_manifest, "next_expansion_candidate") {
            notes.push(format!("next_linux_expansion_candidate={next_expansion}"));
        }
        notes.push("multi_family_evidence_is_visible_but_non_blocking_for_ubuntu_release".into());
    }

    if wire_summary.is_some() {
        notes.push(format!(
            "wire_proof_verdict={}",
            wire_verdict.as_deref().unwrap_or("unknown")
        ));
        notes.push(format!(
            "wire_hostile_path_support_ready={}",
            if wire_hostile_path_ready {
                "true"
            } else {
                "false"
            }
        ));
        notes.push(format!(
            "wire_witness_correlation_status={wire_witness_correlation_status}"
        ));
        if wire_degraded {
            notes.push("wire_contour_degraded_but_baseline_bypass_may_still_be_proven".into());
        }
    } else if blockers.is_empty() {
        notes.push("wire_proof_unavailable_falling_back_to_baseline_transport_runtime".into());
    }

    let baseline_bypass_ready =
        bool_with_fallback(&release_summary, "baseline_bypass_ready", "bypass_ready") == Some(true)
            && bool_with_fallback(&pilot_summary, "baseline_bypass_ready", "bypass_ready")
                == Some(true)
            && blockers.is_empty();
    let hostile_path_ready = pilot_summary["hostile_path_ready"].as_bool() == Some(true);
    let fully_proven = pilot_summary["fully_proven"].as_bool() == Some(true) && hostile_path_ready;
    let wire_hostile_claim_ready = wire_hostile_path_ready
        || (wire_summary.is_none()
            && pilot_summary["fully_proven"].as_bool() == Some(true)
            && pilot_summary["bypass_support_tier"].as_str()
                == Some("wire_level_supported_hostile_path"));

    let (
        review_verdict,
        ship_decision,
        bypass_support_tier,
        bypass_confidence,
        product_proof_status,
    ) = if !blockers.is_empty() || !baseline_bypass_ready {
        (
            "hold",
            "do_not_ship",
            "not_proven",
            "wire_contour_degraded_or_non_proven",
            "not_proven",
        )
    } else if fully_proven && wire_hostile_claim_ready {
        (
            "ready",
            "ship",
            "wire_level_supported_hostile_path",
            "bypass_succeeded_with_correlated_wire_backed_hostile_path_support",
            "fully_proven_hostile_path",
        )
    } else {
        notes.push(
            "hostile_path_proof_missing_or_not_correlated_full_product_proof_not_reached".into(),
        );
        (
            "ready",
            "ship",
            "baseline_transport_runtime",
            "bypass_succeeded_with_baseline_transport_runtime",
            "baseline_only_not_fully_proven",
        )
    };

    let payload = json!({
        "artifact_schema": "ubuntu_release_review_v1",
        "supported_product_contour": "ubuntu_first_release_review",
        "supported_operator_scope": "ubuntu_release_candidate_review",
        "release_summary_json": display_path(release_summary_path),
        "pilot_summary_json": display_path(pilot_bundle_path),
        "matrix_manifest_json": matrix_manifest_path.map(display_path),
        "wire_acceptance_summary_json": wire_acceptance_summary_path.map(display_path),
        "review_verdict": review_verdict,
        "ship_decision": ship_decision,
        "blocking_reasons": blockers,
        "non_blocking_notes": notes,
        "release_readiness": release_summary.get("release_readiness").cloned().unwrap_or(Value::Null),
        "service_health_verdict": release_summary.get("service_health_verdict").cloned().unwrap_or(Value::Null),
        "baseline_bypass_verdict": release_summary.get("baseline_bypass_verdict").or_else(|| release_summary.get("bypass_verdict")).cloned().unwrap_or(Value::Null),
        "baseline_bypass_ready": baseline_bypass_ready,
        "bypass_verdict": release_summary.get("bypass_verdict").cloned().unwrap_or(Value::Null),
        "bypass_ready": baseline_bypass_ready,
        "bypass_support_tier": bypass_support_tier,
        "bypass_confidence": bypass_confidence,
        "hostile_path_verdict": value_string(&pilot_summary, "hostile_path_verdict").unwrap_or_else(|| "missing_evidence".to_string()),
        "hostile_path_ready": hostile_path_ready,
        "hostile_path_blocker_reason": pilot_summary.get("hostile_path_blocker_reason").cloned().unwrap_or(Value::Null),
        "fully_proven": fully_proven && bypass_support_tier == "wire_level_supported_hostile_path",
        "product_proof_status": product_proof_status,
        "mimicry_closure_scope": "ubuntu_witness_correlated_hostile_path_release_boundary",
        "mimicry_program_boundary": "full_packet_level_impersonation_remains_post_release_program",
        "wire_mimicry_verdict": wire_verdict.as_deref().unwrap_or("unavailable"),
        "wire_mimicry_verdict_reason": wire_verdict_reason,
        "wire_hostile_path_support_ready": wire_hostile_path_ready,
        "wire_hostile_path_support_tier": wire_hostile_path_tier,
        "independent_witness_correlation_status": wire_witness_correlation_status,
        "independent_witness_records_matched": wire_witness_records_matched,
        "independent_witness_records_mismatched": wire_witness_records_mismatched,
        "pilot_verdict": pilot_summary.get("pilot_verdict").cloned().unwrap_or(Value::Null),
        "must_pass_verdict": must_pass_verdict,
        "must_pass_failures": must_pass_failures,
        "advisory_verdict": advisory_verdict,
        "advisory_followups": advisory_followups,
    });

    write_json(&output_dir.join("release-review.json"), &payload)?;
    write_text(
        &output_dir.join("release-review.md"),
        &render_markdown(&payload),
    )?;
    Ok(())
}

fn read_optional_json(path: Option<&Path>) -> Result<Option<Value>, Box<dyn std::error::Error>> {
    path.map(read_json).transpose()
}

fn bool_with_fallback(value: &Value, primary: &str, fallback: &str) -> Option<bool> {
    value
        .get(primary)
        .and_then(Value::as_bool)
        .or_else(|| value.get(fallback).and_then(Value::as_bool))
}

fn value_string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn value_u64_or(value: &Value, key: &str, fallback: u64) -> u64 {
    match value.get(key) {
        Some(Value::Number(number)) => number.as_u64().unwrap_or(fallback),
        Some(Value::String(text)) => text.parse().unwrap_or(fallback),
        _ => fallback,
    }
}

fn value_array_strings(value: &Value, key: &str) -> Option<Vec<String>> {
    value.get(key).and_then(array_strings)
}

fn array_strings(value: &Value) -> Option<Vec<String>> {
    value.as_array().map(|items| {
        items
            .iter()
            .filter_map(Value::as_str)
            .map(ToString::to_string)
            .collect()
    })
}

fn display_path(path: &Path) -> String {
    path.components().collect::<PathBuf>().display().to_string()
}

fn render_markdown(payload: &Value) -> String {
    let notes = payload["non_blocking_notes"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join("; ")
        })
        .unwrap_or_default();
    let blockers = payload["blocking_reasons"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| "none".to_string());

    let mut lines = vec![
        "# Ubuntu Release Review".to_string(),
        String::new(),
        markdown_field(payload, "Review verdict", "review_verdict"),
        markdown_field(payload, "Ship decision", "ship_decision"),
        markdown_field(payload, "Release readiness", "release_readiness"),
        markdown_field(payload, "Pilot verdict", "pilot_verdict"),
        markdown_field(payload, "Bypass support tier", "bypass_support_tier"),
        markdown_field(payload, "Product proof status", "product_proof_status"),
        markdown_field(payload, "Hostile-path verdict", "hostile_path_verdict"),
        markdown_field(payload, "Wire mimicry verdict", "wire_mimicry_verdict"),
        markdown_field_or(payload, "Must-pass verdict", "must_pass_verdict", "unknown"),
        markdown_field_or(payload, "Advisory verdict", "advisory_verdict", "unknown"),
        markdown_bool_field(
            payload,
            "Wire hostile-path support ready",
            "wire_hostile_path_support_ready",
        ),
        markdown_field(
            payload,
            "Independent witness correlation",
            "independent_witness_correlation_status",
        ),
        format!("- Blocking reasons: `{blockers}`"),
    ];
    if !notes.is_empty() {
        lines.push(format!("- Non-blocking notes: `{notes}`"));
    }
    lines.push(String::new());
    lines.join("\n")
}

fn markdown_field(payload: &Value, label: &str, key: &str) -> String {
    markdown_field_or(payload, label, key, "null")
}

fn markdown_field_or(payload: &Value, label: &str, key: &str, fallback: &str) -> String {
    format!("- {label}: `{}`", payload[key].as_str().unwrap_or(fallback))
}

fn markdown_bool_field(payload: &Value, label: &str, key: &str) -> String {
    format!(
        "- {label}: `{}`",
        if payload[key].as_bool() == Some(true) {
            "true"
        } else {
            "false"
        }
    )
}
