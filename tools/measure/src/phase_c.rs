use std::path::Path;

use serde_json::{json, Value};

mod evidence;
mod evidence_output;
mod evidence_support;
mod reviews;
mod support;

pub use evidence::{phase_c_bundle_mirrors_evidence, phase_c_multi_relay_evidence};
pub use evidence_output::{
    phase_c_bundle_mirrors_evidence_markdown, phase_c_multi_relay_evidence_markdown,
};
use reviews::{
    phase_c_bundle_mirrors_review, phase_c_fronted_transport_review, phase_c_multi_relay_review,
};
use support::join_strings;

pub struct PhaseCResilienceGateInputs<'a> {
    pub phase_b_score_parity_json: &'a Path,
    pub multi_relay_json: Option<&'a Path>,
    pub bundle_mirrors_json: Option<&'a Path>,
    pub fronted_transport_json: Option<&'a Path>,
}

pub fn phase_c_resilience_gate(
    phase_b_score_parity: &Value,
    multi_relay: Option<&Value>,
    bundle_mirrors: Option<&Value>,
    fronted_transport: Option<&Value>,
    inputs: PhaseCResilienceGateInputs<'_>,
) -> Value {
    let phase_b_ready = phase_b_score_parity["status"].as_str()
        == Some("PHASE_B_SCORE_PARITY_READY")
        && phase_b_score_parity["phase_b_exit_status"].as_str() == Some("EXIT_READY")
        && phase_b_score_parity["acceptance_degraded"].as_bool() == Some(false);
    let multi_relay_review = phase_c_multi_relay_review(multi_relay);
    let bundle_mirrors_review = phase_c_bundle_mirrors_review(bundle_mirrors);
    let fronted_transport_review = phase_c_fronted_transport_review(fronted_transport);

    let mut blockers = Vec::new();
    if !phase_b_ready {
        blockers.push("phase_b_exit_not_ready".to_string());
    }
    collect_phase_c_blocker("multi_relay_pool", &multi_relay_review, &mut blockers);
    collect_phase_c_blocker(
        "bundle_mirrors_voucher_flow",
        &bundle_mirrors_review,
        &mut blockers,
    );
    collect_phase_c_blocker(
        "cdn_fronted_transport",
        &fronted_transport_review,
        &mut blockers,
    );

    let next_action = if !phase_b_ready {
        "restore_phase_b_score_parity_exit_ready"
    } else if multi_relay_review["status"].as_str() != Some("PASS") {
        "implement_and_measure_multi_relay_pool"
    } else if bundle_mirrors_review["status"].as_str() != Some("PASS") {
        "implement_and_measure_bundle_mirrors_voucher_flow"
    } else if fronted_transport_review["status"].as_str() != Some("PASS") {
        "implement_and_measure_cdn_fronted_transport"
    } else {
        "phase_c_resilience_ready_open_next_master_plan_phase"
    };

    json!({
        "event": "phase_c_resilience_gate",
        "schema_version": 1,
        "status": if blockers.is_empty() { "PHASE_C_RESILIENCE_READY" } else { "PHASE_C_RESILIENCE_BLOCKED" },
        "phase_c_exit_status": if blockers.is_empty() { "EXIT_READY" } else { "EXIT_NOT_READY" },
        "acceptance_degraded": !blockers.is_empty(),
        "next_action": next_action,
        "blockers": blockers,
        "checks": {
            "phase_b_exit_ready": phase_b_ready,
            "multi_relay_pool_ready": multi_relay_review["status"].as_str() == Some("PASS"),
            "bundle_mirrors_voucher_flow_ready": bundle_mirrors_review["status"].as_str() == Some("PASS"),
            "cdn_fronted_transport_ready": fronted_transport_review["status"].as_str() == Some("PASS"),
        },
        "phase_b_score_parity": {
            "status": phase_b_score_parity["status"].clone(),
            "phase_b_exit_status": phase_b_score_parity["phase_b_exit_status"].clone(),
            "acceptance_degraded": phase_b_score_parity["acceptance_degraded"].clone(),
        },
        "multi_relay_pool": multi_relay_review,
        "bundle_mirrors_voucher_flow": bundle_mirrors_review,
        "cdn_fronted_transport": fronted_transport_review,
        "artifacts": {
            "phase_b_score_parity_json": inputs.phase_b_score_parity_json,
            "multi_relay_json": inputs.multi_relay_json,
            "bundle_mirrors_json": inputs.bundle_mirrors_json,
            "fronted_transport_json": inputs.fronted_transport_json,
        },
    })
}

pub fn phase_c_resilience_gate_markdown(gate: &Value) -> String {
    format!(
        "# Phase C Resilience Gate\n\n\
         - Status: `{}`\n\
         - Phase C exit: `{}`\n\
         - Acceptance degraded: `{}`\n\
         - Next action: `{}`\n\
         - Blockers: `{}`\n\
         - Phase B exit ready: `{}`\n\
         - Multi-relay pool: `{}`\n\
         - Bundle mirrors/voucher flow: `{}`\n\
         - CDN/fronted transport: `{}`\n",
        gate["status"].as_str().unwrap_or("UNKNOWN"),
        gate["phase_c_exit_status"].as_str().unwrap_or("UNKNOWN"),
        gate["acceptance_degraded"].as_bool().unwrap_or(false),
        gate["next_action"].as_str().unwrap_or("unknown"),
        join_strings(&gate["blockers"]),
        gate["checks"]["phase_b_exit_ready"]
            .as_bool()
            .unwrap_or(false),
        gate["multi_relay_pool"]["status"]
            .as_str()
            .unwrap_or("UNKNOWN"),
        gate["bundle_mirrors_voucher_flow"]["status"]
            .as_str()
            .unwrap_or("UNKNOWN"),
        gate["cdn_fronted_transport"]["status"]
            .as_str()
            .unwrap_or("UNKNOWN"),
    )
}

fn collect_phase_c_blocker(prefix: &str, review: &Value, blockers: &mut Vec<String>) {
    if review["status"].as_str() == Some("PASS") {
        return;
    }
    if let Some(items) = review["blockers"].as_array() {
        for item in items {
            if let Some(item) = item.as_str() {
                blockers.push(format!("{prefix}:{item}"));
            }
        }
    } else {
        blockers.push(format!("{prefix}:not_ready"));
    }
}
