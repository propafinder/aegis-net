use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::phase_a::PRIMARY_TRANSPORTS;

pub fn phase_b_baseline_review(
    phase_a_exit: &Value,
    calibration: &Value,
    gate: &Value,
    classifier: &Value,
) -> Value {
    const WITNESS_FIRST_PASS_TARGET: f64 = 0.50;
    const ADVERSARIAL_FIRST_PASS_TARGET: f64 = 0.70;

    let mut reasons = Vec::new();
    if phase_a_exit["status"].as_str() != Some("EXIT_READY") {
        reasons.push("phase-a-not-exit-ready");
    }
    if gate["a3_brain_integration"]["status"].as_str() != Some("APPLIED") {
        reasons.push("brain-calibration-not-applied");
    }
    if classifier["status"].as_str() != Some("PASS") {
        reasons.push("hostile-classifier-not-pass");
    }

    let witness_labels = calibration["witness"]["labels"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| Some((entry["label"].as_str()?.to_string(), entry.clone())))
        .collect::<BTreeMap<_, _>>();
    let adversarial = calibration["adversarial"]["transports"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| Some((entry["transport"].as_str()?.to_string(), entry.clone())))
        .collect::<BTreeMap<_, _>>();

    let mut witness = Vec::new();
    let mut adversarial_rates = Vec::new();
    for transport in PRIMARY_TRANSPORTS {
        let witness_score = witness_labels
            .get(transport)
            .and_then(|entry| entry["combined_avg"].as_f64());
        let witness_status =
            if witness_score.is_some_and(|score| score >= WITNESS_FIRST_PASS_TARGET) {
                "PASS"
            } else {
                reasons.push("phase-b-first-pass-witness-below-target");
                "FAIL"
            };
        witness.push(json!({
            "transport": transport,
            "combined_avg": witness_score,
            "target": WITNESS_FIRST_PASS_TARGET,
            "status": witness_status,
        }));

        let entry = adversarial.get(transport);
        let pass_rate = entry.and_then(|entry| entry["pass_rate"].as_f64());
        let measured = entry
            .and_then(|entry| entry["measured"].as_u64())
            .unwrap_or(0);
        let adversarial_status = if measured > 0
            && pass_rate.is_some_and(|rate| rate >= ADVERSARIAL_FIRST_PASS_TARGET)
        {
            "PASS"
        } else {
            reasons.push("phase-b-first-pass-adversarial-below-target");
            "FAIL"
        };
        adversarial_rates.push(json!({
            "transport": transport,
            "measured": measured,
            "pass_rate": pass_rate,
            "target": ADVERSARIAL_FIRST_PASS_TARGET,
            "status": adversarial_status,
        }));
    }
    reasons.sort_unstable();
    reasons.dedup();

    json!({
        "event": "phase_b_baseline_review",
        "schema_version": 1,
        "status": if reasons.is_empty() { "BASELINE_READY" } else { "BASELINE_BLOCKED" },
        "acceptance_degraded": !reasons.is_empty(),
        "reasons": reasons,
        "targets": {
            "primary_transports": PRIMARY_TRANSPORTS,
            "first_pass_witness_combined_min": WITNESS_FIRST_PASS_TARGET,
            "first_pass_adversarial_pass_rate_min": ADVERSARIAL_FIRST_PASS_TARGET,
        },
        "phase_a_exit": {
            "status": phase_a_exit["status"].clone(),
            "acceptance_degraded": phase_a_exit["acceptance_degraded"].clone(),
        },
        "witness": witness,
        "adversarial": adversarial_rates,
        "hostile_classifier": {
            "status": classifier["status"].clone(),
            "classifier_records": classifier["classifier_records"].clone(),
            "verdict_counts": classifier["verdict_counts"].clone(),
        },
        "a3_brain_integration": {
            "status": gate["a3_brain_integration"]["status"].clone(),
            "calibration_status": gate["a3_brain_integration"]["calibration_status"].clone(),
        },
    })
}

pub fn phase_b_baseline_markdown(review: &Value) -> String {
    format!(
        "# Phase B Baseline Review\n\n\
         - Status: `{}`\n\
         - Acceptance degraded: `{}`\n\
         - Reasons: `{}`\n\
         - Phase A exit: `{}`\n\
         - A3 Brain integration: `{}`\n\
         - Hostile classifier: `{}` records={}\n\
         - Witness: `{}`\n\
         - Adversarial: `{}`\n",
        review["status"].as_str().unwrap_or("UNKNOWN"),
        review["acceptance_degraded"].as_bool().unwrap_or(false),
        join_strings(&review["reasons"]),
        review["phase_a_exit"]["status"]
            .as_str()
            .unwrap_or("UNKNOWN"),
        review["a3_brain_integration"]["status"]
            .as_str()
            .unwrap_or("UNKNOWN"),
        review["hostile_classifier"]["status"]
            .as_str()
            .unwrap_or("UNKNOWN"),
        review["hostile_classifier"]["classifier_records"]
            .as_u64()
            .unwrap_or(0),
        compact_statuses(&review["witness"]),
        compact_statuses(&review["adversarial"]),
    )
}

fn compact_statuses(value: &Value) -> String {
    let values = value
        .as_array()
        .into_iter()
        .flatten()
        .map(|entry| {
            format!(
                "{}={}",
                entry["transport"].as_str().unwrap_or("unknown"),
                entry["status"].as_str().unwrap_or("UNKNOWN"),
            )
        })
        .collect::<Vec<_>>();
    if values.is_empty() {
        "none".to_string()
    } else {
        values.join(", ")
    }
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
