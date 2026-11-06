mod reviews;
mod support;

use std::path::Path;

use serde_json::{json, Value};

use reviews::{
    phase_b_http_like_scope_review, phase_b_observation_parity_review, phase_b_score_target_review,
    phase_b_witness_wire_correlation_review,
};
use support::join_strings;

const PRIMARY_TRANSPORTS: [&str; 3] = ["legacy_tls", "https_ws", "masque_derived"];
const WITNESS_TARGET: f64 = 0.70;
const ADVERSARIAL_TARGET: f64 = 0.85;

pub struct PhaseBScoreParityGateInputs<'a> {
    pub baseline_json: &'a Path,
    pub runtime_manifest_json: &'a Path,
    pub transport_camouflage_validation_json: &'a Path,
    pub witness_wire_correlation_json: &'a Path,
    pub two_vps_parity_json: &'a Path,
    pub classifier_summary_json: &'a Path,
    pub live_manifest_json: &'a Path,
}

pub struct PhaseBScoreParityGateEvidence<'a> {
    pub baseline: &'a Value,
    pub runtime_manifest: &'a Value,
    pub transport_camouflage: &'a Value,
    pub witness_wire: &'a Value,
    pub two_vps_parity: &'a Value,
    pub classifier_summary: &'a Value,
    pub live_manifest: &'a Value,
}

pub fn phase_b_score_parity_gate(
    evidence: PhaseBScoreParityGateEvidence<'_>,
    inputs: PhaseBScoreParityGateInputs<'_>,
) -> Value {
    let baseline = evidence.baseline;
    let runtime_manifest = evidence.runtime_manifest;
    let transport_camouflage = evidence.transport_camouflage;
    let witness_wire = evidence.witness_wire;
    let two_vps_parity = evidence.two_vps_parity;
    let classifier_summary = evidence.classifier_summary;
    let live_manifest = evidence.live_manifest;
    let baseline_ready = baseline["status"].as_str() == Some("BASELINE_READY")
        && baseline["acceptance_degraded"].as_bool() == Some(false);
    let runtime_ready = runtime_manifest["status"].as_str() == Some("BUNDLE_READY")
        && runtime_manifest["acceptance_degraded"].as_bool() == Some(false);
    let transport_ready = transport_camouflage["status"].as_str() == Some("READY")
        && transport_camouflage["checks"]["hostile_classifier_pass"]
            .as_bool()
            .unwrap_or(false);
    let classifier_pass = classifier_summary["status"].as_str() == Some("PASS")
        && classifier_summary["acceptance_degraded"].as_bool() == Some(false)
        && classifier_summary
            .pointer("/verdict_counts/fail")
            .and_then(Value::as_u64)
            == Some(0)
        && classifier_summary
            .pointer("/verdict_counts/unknown")
            .and_then(Value::as_u64)
            == Some(0);
    let live_green = live_manifest
        .pointer("/acceptance_overview/overall_status")
        .and_then(Value::as_str)
        == Some("acceptance_green");
    let witness_correlation = phase_b_witness_wire_correlation_review(witness_wire);
    let witness_correlation_ready = witness_correlation["status"].as_str() == Some("PASS");
    let active_probe_ready = runtime_manifest["reviews"]["active_probe"]["status"].as_str()
        == Some("PASS")
        && runtime_manifest["reviews"]["active_probe"]["counts"]["finished"]
            .as_u64()
            .unwrap_or(0)
            > 0;

    let score_review = phase_b_score_target_review(baseline);
    let score_ready = score_review["status"].as_str() == Some("PASS");
    let parity_review = phase_b_observation_parity_review(live_manifest, two_vps_parity);
    let parity_ready = parity_review["status"].as_str() == Some("PASS");
    let legacy_scope_review = phase_b_http_like_scope_review(two_vps_parity);
    let legacy_scope_ready = legacy_scope_review["status"].as_str() == Some("PASS");
    let no_hidden_degraded = baseline["acceptance_degraded"].as_bool() == Some(false)
        && runtime_manifest["acceptance_degraded"].as_bool() == Some(false)
        && classifier_summary["acceptance_degraded"].as_bool() == Some(false)
        && transport_camouflage["blockers"]
            .as_array()
            .is_none_or(Vec::is_empty)
        && witness_wire["acceptance_status"].as_str() == Some("passed")
        && parity_review["blockers"]
            .as_array()
            .is_some_and(Vec::is_empty);

    let mut blockers = Vec::new();
    if !baseline_ready {
        blockers.push("phase_b_baseline_not_ready");
    }
    if !runtime_ready {
        blockers.push("phase_b_runtime_manifest_not_ready");
    }
    if !transport_ready {
        blockers.push("transport_camouflage_not_ready");
    }
    if !classifier_pass {
        blockers.push("hostile_classifier_summary_not_pass");
    }
    if !live_green {
        blockers.push("live_acceptance_not_green");
    }
    if !witness_correlation_ready {
        blockers.push("witness_wire_correlation_not_present");
    }
    if !active_probe_ready {
        blockers.push("active_probe_evidence_not_present");
    }
    if !score_ready {
        blockers.push("phase_b_score_targets_not_met");
    }
    if !parity_ready {
        blockers.push("phase_b_observation_parity_not_met");
    }
    if !legacy_scope_ready {
        blockers.push("legacy_tls_counted_in_http_like_camouflage_gate");
    }
    if !no_hidden_degraded {
        blockers.push("degraded_or_blocked_evidence_present");
    }

    let status = if blockers.is_empty() {
        "PHASE_B_SCORE_PARITY_READY"
    } else {
        "PHASE_B_SCORE_PARITY_BLOCKED"
    };
    let next_action = if !transport_ready {
        "restore_transport_camouflage_validation"
    } else if !classifier_pass {
        "restore_hostile_classifier_pass_summary"
    } else if !witness_correlation_ready {
        "restore_witness_wire_correlation"
    } else if !active_probe_ready {
        "restore_active_probe_runtime_evidence"
    } else if !runtime_ready || !live_green {
        "restore_phase_b_runtime_live_evidence"
    } else if !score_ready {
        "tune_mimicry_scores_without_manual_weight_override"
    } else if !parity_ready {
        "collect_cross_platform_observation_parity_evidence"
    } else if !legacy_scope_ready {
        "split_legacy_tls_from_http_like_transport_camouflage_gate"
    } else if !no_hidden_degraded {
        "inspect_degraded_or_blocked_evidence"
    } else if !baseline_ready {
        "restore_phase_b_baseline_review"
    } else {
        "phase_b_exit_ready_open_next_master_plan_phase"
    };

    json!({
        "event": "phase_b_score_parity_gate",
        "schema_version": 1,
        "status": status,
        "phase_b_exit_status": if blockers.is_empty() { "EXIT_READY" } else { "EXIT_NOT_READY" },
        "acceptance_degraded": !blockers.is_empty(),
        "next_action": next_action,
        "blockers": blockers,
        "checks": {
            "baseline_ready": baseline_ready,
            "runtime_manifest_ready": runtime_ready,
            "transport_camouflage_ready": transport_ready,
            "hostile_classifier_summary_pass": classifier_pass,
            "live_acceptance_green": live_green,
            "witness_wire_correlation_ready": witness_correlation_ready,
            "active_probe_evidence_present": active_probe_ready,
            "score_targets_ready": score_ready,
            "observation_parity_ready": parity_ready,
            "legacy_tls_excluded_from_http_like_gate": legacy_scope_ready,
            "no_degraded_or_blocked_evidence_hidden": no_hidden_degraded,
        },
        "scoring_policy": {
            "formula_override": false,
            "external_calibration_role": "baseline_evidence_feature_not_manual_weight",
            "witness_combined_min": WITNESS_TARGET,
            "adversarial_pass_rate_min": ADVERSARIAL_TARGET,
        },
        "score_targets": score_review,
        "witness_wire_correlation": witness_correlation,
        "observation_parity": parity_review,
        "http_like_transport_scope": legacy_scope_review,
        "runtime_manifest": {
            "status": runtime_manifest["status"].clone(),
            "acceptance_degraded": runtime_manifest["acceptance_degraded"].clone(),
            "reviews": runtime_manifest["reviews"].clone(),
        },
        "classifier_summary": {
            "status": classifier_summary["status"].clone(),
            "acceptance_degraded": classifier_summary["acceptance_degraded"].clone(),
            "verdict_counts": classifier_summary["verdict_counts"].clone(),
            "classifiers": classifier_summary["classifiers"].clone(),
        },
        "transport_camouflage": {
            "status": transport_camouflage["status"].clone(),
            "next_action": transport_camouflage["next_action"].clone(),
            "checks": transport_camouflage["checks"].clone(),
        },
        "live_acceptance": live_manifest.pointer("/acceptance_overview").cloned().unwrap_or(Value::Null),
        "artifacts": {
            "baseline_json": inputs.baseline_json,
            "runtime_manifest_json": inputs.runtime_manifest_json,
            "transport_camouflage_validation_json": inputs.transport_camouflage_validation_json,
            "witness_wire_correlation_json": inputs.witness_wire_correlation_json,
            "two_vps_parity_json": inputs.two_vps_parity_json,
            "classifier_summary_json": inputs.classifier_summary_json,
            "live_manifest_json": inputs.live_manifest_json,
        },
    })
}

pub fn phase_b_score_parity_gate_markdown(gate: &Value) -> String {
    format!(
        "# Phase B Score And Parity Gate\n\n\
         - Status: `{}`\n\
         - Phase B exit: `{}`\n\
         - Acceptance degraded: `{}`\n\
         - Next action: `{}`\n\
         - Blockers: `{}`\n\
         - Score targets: `{}`\n\
         - Observation parity: `{}`\n\
         - Witness correlation: `{}`\n\
         - LegacyTls excluded from HTTP-like gate: `{}`\n\
         - Formula override: `{}`\n\
         - Classifier summary: `{}`\n\
         - Transport camouflage: `{}`\n",
        gate["status"].as_str().unwrap_or("UNKNOWN"),
        gate["phase_b_exit_status"].as_str().unwrap_or("UNKNOWN"),
        gate["acceptance_degraded"].as_bool().unwrap_or(false),
        gate["next_action"].as_str().unwrap_or("unknown"),
        join_strings(&gate["blockers"]),
        gate["score_targets"]["status"]
            .as_str()
            .unwrap_or("UNKNOWN"),
        gate["observation_parity"]["status"]
            .as_str()
            .unwrap_or("UNKNOWN"),
        gate["witness_wire_correlation"]["status"]
            .as_str()
            .unwrap_or("UNKNOWN"),
        gate["checks"]["legacy_tls_excluded_from_http_like_gate"]
            .as_bool()
            .unwrap_or(false),
        gate["scoring_policy"]["formula_override"]
            .as_bool()
            .unwrap_or(true),
        gate["classifier_summary"]["status"]
            .as_str()
            .unwrap_or("UNKNOWN"),
        gate["transport_camouflage"]["status"]
            .as_str()
            .unwrap_or("UNKNOWN"),
    )
}
