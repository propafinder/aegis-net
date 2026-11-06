use std::{fs, path::Path};

use serde_json::{json, Value};

mod android;
mod android_output;
mod macos;
mod macos_output;
mod macos_predicates;
mod windows;
mod windows_optional;
mod windows_output;

use android::phase_d_android_reach_review;
pub use android::{phase_d_android_reach_evidence, PhaseDAndroidReachEvidenceInputs};
pub use android_output::phase_d_android_reach_evidence_markdown;
use macos::phase_d_macos_reach_review;
pub use macos::{phase_d_macos_reach_evidence, PhaseDMacosReachEvidenceInputs};
pub use macos_output::phase_d_macos_reach_evidence_markdown;
use windows::phase_d_windows_reach_review;
pub use windows::{phase_d_windows_reach_evidence, PhaseDWindowsReachEvidenceInputs};
pub use windows_output::phase_d_windows_reach_evidence_markdown;

pub struct PhaseDReachGateInputs<'a> {
    pub phase_c_resilience_json: &'a Path,
    pub windows_reach_json: Option<&'a Path>,
    pub macos_reach_json: Option<&'a Path>,
    pub android_reach_json: Option<&'a Path>,
}

pub fn phase_d_reach_gate(
    phase_c_resilience: &Value,
    windows_reach: Option<&Value>,
    macos_reach: Option<&Value>,
    android_reach: Option<&Value>,
    inputs: PhaseDReachGateInputs<'_>,
) -> Value {
    let phase_c_ready = phase_c_resilience["status"].as_str() == Some("PHASE_C_RESILIENCE_READY")
        && phase_c_resilience["phase_c_exit_status"].as_str() == Some("EXIT_READY")
        && phase_c_resilience["acceptance_degraded"].as_bool() == Some(false);
    let windows_review = phase_d_windows_reach_review(windows_reach);
    let macos_review = phase_d_macos_reach_review(macos_reach);
    let android_review = phase_d_android_reach_review(android_reach);

    let prep_ready = windows_review["prep_ready"].as_bool() == Some(true)
        && macos_review["prep_ready"].as_bool() == Some(true)
        && android_review["prep_ready"].as_bool() == Some(true)
        && !phase_d_any_overclaim(&windows_review, &macos_review, &android_review);
    let exit_ready = phase_c_ready
        && windows_review["exit_ready"].as_bool() == Some(true)
        && macos_review["exit_ready"].as_bool() == Some(true)
        && android_review["exit_ready"].as_bool() == Some(true)
        && !phase_d_any_overclaim(&windows_review, &macos_review, &android_review);

    let mut blockers = Vec::new();
    if !phase_c_ready {
        blockers.push("phase_c_resilience_not_ready".to_string());
    }
    collect_phase_d_blocker("windows_reach", &windows_review, &mut blockers);
    collect_phase_d_blocker("macos_reach", &macos_review, &mut blockers);
    collect_phase_d_blocker("android_reach", &android_review, &mut blockers);

    let next_action = if !phase_c_ready {
        "finish_phase_c_cdn_fronted_transport"
    } else if windows_review["exit_ready"].as_bool() != Some(true) {
        "continue_windows_reach_gates_without_broad_capture_claim"
    } else if macos_review["exit_ready"].as_bool() != Some(true) {
        "continue_macos_networkextension_reach_gate"
    } else if android_review["exit_ready"].as_bool() != Some(true) {
        "continue_android_vpnservice_poc_gate"
    } else {
        "phase_d_reach_ready_open_next_master_plan_phase"
    };

    json!({
        "event": "phase_d_reach_gate",
        "schema_version": 1,
        "status": if exit_ready {
            "PHASE_D_EXIT_READY"
        } else if prep_ready {
            "PHASE_D_PREP_READY"
        } else {
            "PHASE_D_REACH_BLOCKED"
        },
        "phase_d_exit_status": if exit_ready { "EXIT_READY" } else { "EXIT_NOT_READY" },
        "phase_d_prep_status": if prep_ready { "PREP_READY" } else { "PREP_NOT_READY" },
        "acceptance_degraded": !exit_ready,
        "next_action": next_action,
        "blockers": blockers,
        "checks": {
            "phase_c_resilience_ready": phase_c_ready,
            "windows_prep_ready": windows_review["prep_ready"].as_bool() == Some(true),
            "macos_prep_ready": macos_review["prep_ready"].as_bool() == Some(true),
            "android_prep_ready": android_review["prep_ready"].as_bool() == Some(true),
            "no_overstated_reach_claims": !phase_d_any_overclaim(&windows_review, &macos_review, &android_review),
        },
        "phase_c_resilience": {
            "status": phase_c_resilience["status"].clone(),
            "phase_c_exit_status": phase_c_resilience["phase_c_exit_status"].clone(),
            "acceptance_degraded": phase_c_resilience["acceptance_degraded"].clone(),
        },
        "windows_reach": windows_review,
        "macos_reach": macos_review,
        "android_reach": android_review,
        "artifacts": {
            "phase_c_resilience_json": inputs.phase_c_resilience_json,
            "windows_reach_json": inputs.windows_reach_json,
            "macos_reach_json": inputs.macos_reach_json,
            "android_reach_json": inputs.android_reach_json,
        },
    })
}

pub fn phase_d_reach_gate_markdown(gate: &Value) -> String {
    format!(
        "# Phase D Reach Gate\n\n\
         - Status: `{}`\n\
         - Phase D exit: `{}`\n\
         - Phase D prep: `{}`\n\
         - Acceptance degraded: `{}`\n\
         - Next action: `{}`\n\
         - Blockers: `{}`\n\
         - Phase C ready: `{}`\n\
         - Windows reach: `{}`\n\
         - macOS reach: `{}`\n\
         - Android reach: `{}`\n",
        gate["status"].as_str().unwrap_or("UNKNOWN"),
        gate["phase_d_exit_status"].as_str().unwrap_or("UNKNOWN"),
        gate["phase_d_prep_status"].as_str().unwrap_or("UNKNOWN"),
        gate["acceptance_degraded"].as_bool().unwrap_or(false),
        gate["next_action"].as_str().unwrap_or("unknown"),
        join_strings(&gate["blockers"]),
        gate["checks"]["phase_c_resilience_ready"]
            .as_bool()
            .unwrap_or(false),
        gate["windows_reach"]["status"]
            .as_str()
            .unwrap_or("UNKNOWN"),
        gate["macos_reach"]["status"].as_str().unwrap_or("UNKNOWN"),
        gate["android_reach"]["status"]
            .as_str()
            .unwrap_or("UNKNOWN"),
    )
}

fn collect_phase_d_blocker(prefix: &str, review: &Value, blockers: &mut Vec<String>) {
    if let Some(items) = review["blockers"].as_array() {
        for item in items {
            if let Some(item) = item.as_str() {
                blockers.push(format!("{prefix}:{item}"));
            }
        }
    }
}

fn phase_d_any_overclaim(windows: &Value, macos: &Value, android: &Value) -> bool {
    windows["overstated_claim_detected"].as_bool() == Some(true)
        || macos["overstated_claim_detected"].as_bool() == Some(true)
        || android["overstated_claim_detected"].as_bool() == Some(true)
}

fn phase_d_bool(evidence: &Value, key: &str) -> bool {
    evidence[key].as_bool() == Some(true)
}

fn read_artifact_result_json(artifact: &Path) -> Value {
    let result_path = if artifact.is_dir() {
        artifact.join("result.json")
    } else {
        artifact.to_path_buf()
    };
    read_json(&result_path).unwrap_or_else(|_| json!({}))
}

fn read_json(path: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    Ok(serde_json::from_str(
        content.trim_start_matches('\u{feff}'),
    )?)
}

fn result_has_pass(result: &Value) -> bool {
    result["status"].as_str() == Some("PASS") || result["verdict"].as_str() == Some("PASS")
}

fn result_claim_not_wide(result: &Value) -> bool {
    result["wide_claim"]
        .as_str()
        .is_none_or(|claim| claim != "claimed")
}

fn read_optional_result(path: Option<&Path>) -> Option<Value> {
    path.map(read_artifact_result_json)
}

fn join_strings(value: &Value) -> String {
    let values = value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    if values.is_empty() {
        "none".to_string()
    } else {
        values.join(", ")
    }
}
