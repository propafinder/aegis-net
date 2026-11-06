use std::{collections::BTreeMap, path::Path};

use serde_json::{json, Value};

mod input;
mod output;

use input::{doc_status, read_json, read_jsonl};
pub use output::{phase_a_exit_markdown, phase_a_measure_gate_markdown};

pub const PRIMARY_TRANSPORTS: [&str; 3] = ["legacy_tls", "https_ws", "masque_derived"];
pub const WITNESS_TARGET: f64 = 0.70;
pub const ADVERSARIAL_TARGET: f64 = 0.85;

pub fn phase_a_exit_review(
    gate: &Value,
    calibration: &Value,
    classifier: &Value,
    threat_model: Option<&Path>,
    knowledge_architecture: Option<&Path>,
) -> Value {
    let witness_labels = calibration["witness"]["labels"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| Some((entry["label"].as_str()?.to_string(), entry.clone())))
        .collect::<BTreeMap<_, _>>();

    let mut witness_missing = Vec::new();
    let mut witness_below = Vec::new();
    for transport in PRIMARY_TRANSPORTS {
        match witness_labels.get(transport) {
            Some(entry) => {
                let score = entry["combined_avg"].as_f64().unwrap_or(0.0);
                if score < WITNESS_TARGET {
                    witness_below.push(json!({"transport": transport, "combined_avg": score}));
                }
            }
            None => witness_missing.push(transport),
        }
    }

    let adversarial = calibration["adversarial"]["transports"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| Some((entry["transport"].as_str()?.to_string(), entry.clone())))
        .collect::<BTreeMap<_, _>>();
    let mut adversarial_missing = Vec::new();
    let mut adversarial_below = Vec::new();
    for transport in PRIMARY_TRANSPORTS {
        match adversarial.get(transport) {
            Some(entry) => {
                let measured = entry["measured"].as_u64().unwrap_or(0);
                let pass_rate = entry["pass_rate"].as_f64();
                let target = entry["threshold"]
                    .as_f64()
                    .unwrap_or(ADVERSARIAL_TARGET)
                    .max(ADVERSARIAL_TARGET);
                if measured == 0 || pass_rate.is_none_or(|value| value < target) {
                    adversarial_below.push(json!({
                        "transport": transport,
                        "measured": measured,
                        "pass_rate": pass_rate,
                        "target": target,
                    }));
                }
            }
            None => adversarial_missing.push(transport),
        }
    }

    let mut reasons = Vec::new();
    if !witness_missing.is_empty() {
        reasons.push("missing-primary-witness-scores");
    }
    if !witness_below.is_empty() {
        reasons.push("primary-witness-score-below-target");
    }
    if !adversarial_missing.is_empty() {
        reasons.push("missing-primary-adversarial-pass-rates");
    }
    if !adversarial_below.is_empty() {
        reasons.push("primary-adversarial-pass-rate-below-target");
    }
    if classifier["status"].as_str() != Some("PASS") {
        reasons.push("hostile-classifier-not-pass");
    }
    let knowledge_status = gate["a25_knowledge"]["status"]
        .as_str()
        .unwrap_or("UNKNOWN");
    if knowledge_status != "PASS" {
        reasons.push("knowledge-corpus-not-pass");
    }
    let brain_status = gate["a3_brain_integration"]["status"]
        .as_str()
        .unwrap_or("UNKNOWN");
    if brain_status != "APPLIED" {
        reasons.push("brain-calibration-not-applied-in-gate");
    }
    let threat_status = doc_status(threat_model);
    let knowledge_arch_status = doc_status(knowledge_architecture);
    if threat_status != "PASS" {
        reasons.push("threat-model-document-missing");
    }
    if knowledge_arch_status != "PASS" {
        reasons.push("knowledge-architecture-document-missing");
    }

    json!({
        "event": "phase_a_exit_review",
        "schema_version": 1,
        "status": if reasons.is_empty() { "EXIT_READY" } else { "NOT_EXIT_READY" },
        "acceptance_degraded": !reasons.is_empty(),
        "reasons": reasons,
        "targets": {
            "primary_transports": PRIMARY_TRANSPORTS,
            "witness_combined_min": WITNESS_TARGET,
            "adversarial_pass_rate_min": ADVERSARIAL_TARGET,
        },
        "a1_witness": {
            "status": if witness_missing.is_empty() && witness_below.is_empty() { "PASS" } else { "FAIL" },
            "missing_primary_transports": witness_missing,
            "below_target": witness_below,
        },
        "a2_adversarial": {
            "status": if adversarial_missing.is_empty() && adversarial_below.is_empty() { "PASS" } else { "FAIL" },
            "missing_primary_transports": adversarial_missing,
            "below_target": adversarial_below,
            "packet_evidence_records": gate["a2_adversarial"]["packet_evidence_records"].clone(),
        },
        "a2_hostile_classifier": {
            "status": classifier["status"].clone(),
            "classifier_records": classifier["classifier_records"].clone(),
            "verdict_counts": classifier["verdict_counts"].clone(),
        },
        "a25_knowledge": {"status": knowledge_status},
        "a3_brain_integration": {"status": brain_status},
        "documents": {
            "threat_model": threat_status,
            "knowledge_architecture": knowledge_arch_status,
        },
    })
}

pub fn phase_a_measure_gate_review(
    output_dir: &Path,
    skip_knowledge: bool,
    applied: bool,
) -> Result<Value, Box<dyn std::error::Error>> {
    let calibration = read_json(&output_dir.join("calibration/summary.json"))?;
    let classifier = read_json(&output_dir.join("classifier/summary.json"))?;
    let witness = read_json(&output_dir.join("witness/summary.json"))?;
    let adversarial = read_jsonl(&output_dir.join("adversarial/events.jsonl"))?;

    let witness_groups = witness["groups"].as_array().cloned().unwrap_or_default();
    let witness_records = witness_groups
        .iter()
        .map(|group| group["total_records"].as_u64().unwrap_or(0))
        .sum::<u64>();
    let adversarial_events = adversarial.len();
    let adversarial_measured = calibration["adversarial"]["measured_records"]
        .as_u64()
        .unwrap_or(0);
    let packet_evidence = adversarial
        .iter()
        .filter(|record| record["packet_evidence_status"].as_str() == Some("present"))
        .count();
    let adversarial_status = if adversarial_measured > 0 {
        "MEASURED_PASS"
    } else if adversarial_events > 0 {
        "DRY_RUN_PASS"
    } else {
        "FAIL"
    };
    let boundary = if adversarial_measured > 0 && packet_evidence > 0 {
        "measured adversarial evidence includes archived packet/runtime evidence; hostile DPI classifier verdicts are still a separate gate"
    } else if adversarial_measured > 0 {
        "bounded measured adversarial command recorded; stronger live claims require a real AEGIS traffic path and archived packet/runtime evidence"
    } else {
        "adversarial runner emitted planned-only dry-run events"
    };

    Ok(json!({
        "event": "phase_a_measure_gate_review",
        "schema_version": 1,
        "status": "CONTRACT",
        "boundary": boundary,
        "a1_witness": {
            "status": if witness_groups.is_empty() { "FAIL" } else { "PASS" },
            "records": witness_records,
            "labels": witness_groups.iter().filter_map(|group| group["label"].as_str()).collect::<Vec<_>>(),
        },
        "a2_adversarial": {
            "status": adversarial_status,
            "events": adversarial_events,
            "measured_records": adversarial_measured,
            "packet_evidence_records": packet_evidence,
        },
        "a2_hostile_classifier": {
            "status": classifier["status"].clone(),
            "classifier_records": classifier["classifier_records"].clone(),
            "acceptance_degraded": classifier["acceptance_degraded"].clone(),
            "reasons": classifier["reasons"].clone(),
        },
        "a25_knowledge": {
            "status": if skip_knowledge { "SKIPPED" } else { "PASS" },
        },
        "a3_brain_integration": {
            "status": if applied { "APPLIED" } else { "CALIBRATION_SUMMARY_READY" },
            "calibration_status": calibration["verdict"]["status"].clone(),
            "acceptance_degraded": calibration["verdict"]["acceptance_degraded"].clone(),
        },
    }))
}

pub fn phase_a_measure_gate_contract_check(
    gate: &Path,
    measured_gate: &Path,
    matrix_gate: &Path,
    imported_gate: &Path,
    imported_witness_gate: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let review = read_json(&gate.join("phase-a-gate-review.json"))?;
    let calibration = read_json(&gate.join("calibration/summary.json"))?;
    let measured_review = read_json(&measured_gate.join("phase-a-gate-review.json"))?;
    let measured_calibration = read_json(&measured_gate.join("calibration/summary.json"))?;
    let matrix_review = read_json(&matrix_gate.join("phase-a-gate-review.json"))?;
    let imported_review = read_json(&imported_gate.join("phase-a-gate-review.json"))?;
    let imported_witness_review =
        read_json(&imported_witness_gate.join("phase-a-gate-review.json"))?;
    let imported_witness_summary = read_json(&imported_witness_gate.join("witness/summary.json"))?;
    let matrix_events = read_jsonl(&matrix_gate.join("adversarial/events.jsonl"))?;

    expect_path_str(
        &review,
        &["event"],
        "phase_a_measure_gate_review",
        "unexpected review event",
    )?;
    expect_path_str(&review, &["status"], "CONTRACT", "unexpected review status")?;
    expect_path_str(
        &review,
        &["a1_witness", "status"],
        "PASS",
        "unexpected witness status",
    )?;
    expect_path_u64(
        &review,
        &["a1_witness", "records"],
        1,
        "unexpected witness records",
    )?;
    expect_path_str(
        &review,
        &["a2_adversarial", "status"],
        "DRY_RUN_PASS",
        "unexpected adversarial status",
    )?;
    expect_path_str(
        &review,
        &["a2_hostile_classifier", "status"],
        "NOT_RUN",
        "unexpected classifier status",
    )?;
    expect_path_contains(
        &review,
        &["boundary"],
        "planned-only",
        "unexpected planned boundary",
    )?;
    expect_path_u64_at_least(
        &review,
        &["a2_adversarial", "events"],
        1,
        "unexpected adversarial event count",
    )?;
    expect_path_str(
        &review,
        &["a25_knowledge", "status"],
        "SKIPPED",
        "unexpected knowledge status",
    )?;
    expect_path_str(
        &review,
        &["a3_brain_integration", "status"],
        "CALIBRATION_SUMMARY_READY",
        "unexpected brain status",
    )?;
    expect_path_str(
        &calibration,
        &["event"],
        "external_calibration_summary",
        "unexpected calibration event",
    )?;
    expect_file_exists(&gate.join("phase-a-gate-review.md"))?;
    expect_file_exists(&gate.join("commands.txt"))?;

    expect_path_str(
        &measured_review,
        &["a2_adversarial", "status"],
        "MEASURED_PASS",
        "unexpected measured adversarial status",
    )?;
    expect_path_contains(
        &measured_review,
        &["boundary"],
        "bounded measured",
        "unexpected measured boundary",
    )?;
    expect_path_u64(
        &measured_review,
        &["a2_adversarial", "measured_records"],
        1,
        "unexpected measured records",
    )?;
    expect_path_str(
        &measured_review,
        &["a3_brain_integration", "calibration_status"],
        "MEASURED",
        "unexpected measured calibration status",
    )?;
    expect_path_bool(
        &measured_calibration,
        &["verdict", "acceptance_degraded"],
        false,
        "unexpected measured calibration degradation",
    )?;

    expect_path_str(
        &matrix_review,
        &["a2_adversarial", "status"],
        "MEASURED_PASS",
        "unexpected matrix status",
    )?;
    expect_path_u64(
        &matrix_review,
        &["a2_adversarial", "measured_records"],
        16,
        "unexpected matrix measured records",
    )?;
    if matrix_events.len() != 16 {
        return Err(format!("unexpected matrix event count: {}", matrix_events.len()).into());
    }

    expect_path_str(
        &imported_review,
        &["a2_adversarial", "status"],
        "MEASURED_PASS",
        "unexpected imported adversarial status",
    )?;
    expect_path_u64(
        &imported_review,
        &["a2_adversarial", "measured_records"],
        1,
        "unexpected imported measured records",
    )?;
    expect_path_u64(
        &imported_review,
        &["a2_adversarial", "packet_evidence_records"],
        1,
        "unexpected imported packet evidence records",
    )?;
    expect_path_str(
        &imported_review,
        &["a2_hostile_classifier", "status"],
        "PASS",
        "unexpected imported classifier status",
    )?;
    expect_path_u64(
        &imported_review,
        &["a2_hostile_classifier", "classifier_records"],
        1,
        "unexpected imported classifier records",
    )?;
    expect_path_contains(
        &imported_review,
        &["boundary"],
        "packet/runtime evidence",
        "unexpected imported boundary",
    )?;
    expect_file_exists(&imported_gate.join("classifier/summary.json"))?;

    expect_path_u64(
        &imported_witness_review,
        &["a1_witness", "records"],
        2,
        "unexpected imported witness records",
    )?;
    expect_path_str_array(
        &imported_witness_review,
        &["a1_witness", "labels"],
        &["https_ws", "legacy_tls"],
        "unexpected imported witness labels",
    )?;
    expect_path_f64(
        &imported_witness_summary,
        &["groups", "0", "combined_avg"],
        1.0,
        "unexpected imported witness average",
    )?;
    Ok(())
}

fn expect_file_exists(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if path.is_file() {
        Ok(())
    } else {
        Err(format!("missing expected file {}", path.display()).into())
    }
}

fn expect_path_str(
    value: &Value,
    path: &[&str],
    expected: &str,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if value_at_path(value, path).and_then(Value::as_str) == Some(expected) {
        Ok(())
    } else {
        Err(format!("{message}: {value}").into())
    }
}

fn expect_path_contains(
    value: &Value,
    path: &[&str],
    expected_substring: &str,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if value_at_path(value, path)
        .and_then(Value::as_str)
        .is_some_and(|actual| actual.contains(expected_substring))
    {
        Ok(())
    } else {
        Err(format!("{message}: {value}").into())
    }
}

fn expect_path_u64(
    value: &Value,
    path: &[&str],
    expected: u64,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if value_at_path(value, path).and_then(Value::as_u64) == Some(expected) {
        Ok(())
    } else {
        Err(format!("{message}: {value}").into())
    }
}

fn expect_path_u64_at_least(
    value: &Value,
    path: &[&str],
    expected_min: u64,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if value_at_path(value, path)
        .and_then(Value::as_u64)
        .is_some_and(|actual| actual >= expected_min)
    {
        Ok(())
    } else {
        Err(format!("{message}: {value}").into())
    }
}

fn expect_path_bool(
    value: &Value,
    path: &[&str],
    expected: bool,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if value_at_path(value, path).and_then(Value::as_bool) == Some(expected) {
        Ok(())
    } else {
        Err(format!("{message}: {value}").into())
    }
}

fn expect_path_f64(
    value: &Value,
    path: &[&str],
    expected: f64,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if value_at_path(value, path)
        .and_then(Value::as_f64)
        .is_some_and(|actual| (actual - expected).abs() < f64::EPSILON)
    {
        Ok(())
    } else {
        Err(format!("{message}: {value}").into())
    }
}

fn expect_path_str_array(
    value: &Value,
    path: &[&str],
    expected: &[&str],
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = value_at_path(value, path)
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect::<Vec<_>>());
    if actual.as_deref() == Some(expected) {
        Ok(())
    } else {
        Err(format!("{message}: {value}").into())
    }
}

fn value_at_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for segment in path {
        current = if let Ok(index) = segment.parse::<usize>() {
            current.as_array()?.get(index)?
        } else {
            current.get(*segment)?
        };
    }
    Some(current)
}
