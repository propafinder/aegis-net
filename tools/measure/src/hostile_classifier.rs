use std::{collections::BTreeSet, path::Path};

use serde_json::{json, Value};

pub fn hostile_summary(adversarial: &[Value], classifier: &[Value]) -> Value {
    let measured = adversarial
        .iter()
        .filter(|record| {
            record
                .get("event")
                .and_then(Value::as_str)
                .is_some_and(|event| event.starts_with("adversarial_"))
                && !matches!(
                    record
                        .get("status")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_ascii_uppercase()
                        .as_str(),
                    "" | "PLANNED"
                )
        })
        .collect::<Vec<_>>();
    let packet_backed = measured
        .iter()
        .filter(|record| {
            record.get("packet_evidence_status").and_then(Value::as_str) == Some("present")
        })
        .count();
    let classifier_records = classifier
        .iter()
        .filter(|record| {
            record
                .get("event")
                .and_then(Value::as_str)
                .is_some_and(|event| {
                    event.starts_with("hostile_classifier_") || event.starts_with("dpi_classifier_")
                })
        })
        .collect::<Vec<_>>();

    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut unknown = 0usize;
    let mut classifiers = BTreeSet::new();
    for record in &classifier_records {
        classifiers.insert(
            record
                .get("classifier")
                .or_else(|| record.get("engine"))
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
        );
        match classifier_status(record) {
            "PASS" => pass += 1,
            "FAIL" => fail += 1,
            _ => unknown += 1,
        }
    }

    let mut reasons = Vec::new();
    if measured.is_empty() {
        reasons.push("missing-measured-adversarial-events");
    }
    if !measured.is_empty() && packet_backed == 0 {
        reasons.push("missing-packet-backed-adversarial-events");
    }
    if classifier_records.is_empty() {
        reasons.push("missing-hostile-classifier-events");
    }
    if fail > 0 {
        reasons.push("hostile-classifier-detected-or-blocked");
    }
    if unknown > 0 {
        reasons.push("hostile-classifier-verdict-unknown");
    }

    let status = if classifier_records.is_empty() {
        "NOT_RUN"
    } else if reasons.is_empty() {
        "PASS"
    } else {
        "FAIL"
    };

    json!({
        "event": "hostile_classifier_summary",
        "schema_version": 1,
        "status": status,
        "acceptance_degraded": !reasons.is_empty(),
        "reasons": reasons,
        "adversarial_measured_records": measured.len(),
        "packet_evidence_records": packet_backed,
        "classifier_records": classifier_records.len(),
        "classifiers": classifiers.into_iter().collect::<Vec<_>>(),
        "verdict_counts": {"pass": pass, "fail": fail, "unknown": unknown},
    })
}

pub fn classifier_status(record: &Value) -> &'static str {
    match record
        .get("status")
        .or_else(|| record.get("verdict"))
        .and_then(Value::as_str)
        .unwrap_or("UNKNOWN")
        .to_ascii_uppercase()
        .as_str()
    {
        "PASS" | "PASSED" | "ALLOWED" | "CLEAN" | "NO_MATCH" | "NO_ALERT" => "PASS",
        "FAIL" | "FAILED" | "BLOCKED" | "DETECTED" | "ALERT" | "MATCH" => "FAIL",
        _ => "UNKNOWN",
    }
}

pub struct ClassifierVerdictInputs<'a> {
    pub classifier: &'a str,
    pub status: &'a str,
    pub scenario: &'a str,
    pub transport: &'a str,
    pub pcap: &'a Path,
    pub reason: &'a str,
    pub alert_count: Option<u64>,
    pub risk_count: Option<u64>,
    pub json_output: Option<&'a Path>,
    pub ndpi_input_pcap: Option<&'a Path>,
}

pub fn classifier_verdict(inputs: ClassifierVerdictInputs<'_>) -> Value {
    let normalized_classifier = inputs.classifier.to_ascii_lowercase();
    let mut status = inputs.status.to_string();
    let mut reason = inputs.reason.to_string();
    if normalized_classifier == "ndpi"
        && inputs.risk_count.unwrap_or(0) > 0
        && classifier_status(&json!({ "status": status })) == "PASS"
    {
        status = "DETECTED".to_string();
        reason = "ndpi-risk-stats-detected".to_string();
    }
    let mut payload = json!({
        "event": "hostile_classifier_verdict",
        "schema_version": 1,
        "classifier": inputs.classifier,
        "status": status,
        "scenario": inputs.scenario,
        "transport": inputs.transport,
        "pcap": inputs.pcap,
        "reason": reason,
    });
    if let Some(alert_count) = inputs.alert_count {
        payload["alert_count"] = json!(alert_count);
    }
    if let Some(risk_count) = inputs.risk_count {
        payload["risk_count"] = json!(risk_count);
    }
    if let Some(json_output) = inputs.json_output {
        payload["json_output"] = json!(json_output);
    }
    if let Some(ndpi_input_pcap) = inputs.ndpi_input_pcap {
        payload["ndpi_input_pcap"] = json!(ndpi_input_pcap);
    }
    payload
}

pub fn hostile_summary_markdown(summary: &Value) -> String {
    let counts = &summary["verdict_counts"];
    format!(
        "# Hostile Classifier Summary\n\n\
         - Status: `{}`\n\
         - Acceptance degraded: `{}`\n\
         - Reasons: `{}`\n\
         - Adversarial measured records: `{}`\n\
         - Packet evidence records: `{}`\n\
         - Classifier records: `{}`\n\
         - Classifiers: `{}`\n\
         - Verdict pass/fail/unknown: `{}/{}/{}`\n",
        summary["status"].as_str().unwrap_or("UNKNOWN"),
        summary["acceptance_degraded"].as_bool().unwrap_or(false),
        join_strings(&summary["reasons"]),
        summary["adversarial_measured_records"]
            .as_u64()
            .unwrap_or(0),
        summary["packet_evidence_records"].as_u64().unwrap_or(0),
        summary["classifier_records"].as_u64().unwrap_or(0),
        join_strings(&summary["classifiers"]),
        counts["pass"].as_u64().unwrap_or(0),
        counts["fail"].as_u64().unwrap_or(0),
        counts["unknown"].as_u64().unwrap_or(0),
    )
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
