use serde_json::Value;

pub fn phase_a_exit_markdown(review: &Value) -> String {
    format!(
        "# Phase A Exit Review\n\n\
         - Status: `{}`\n\
         - Acceptance degraded: `{}`\n\
         - Reasons: `{}`\n\
         - A1 witness: `{}` missing={} below_target={}\n\
         - A2 adversarial: `{}` missing={} below_target={}\n\
         - A2 hostile classifier: `{}` records={}\n\
         - A2.5 knowledge: `{}`\n\
         - A3 Brain integration: `{}`\n\
         - Threat model: `{}`\n\
         - Knowledge architecture: `{}`\n",
        review["status"].as_str().unwrap_or("UNKNOWN"),
        review["acceptance_degraded"].as_bool().unwrap_or(false),
        join_strings(&review["reasons"]),
        review["a1_witness"]["status"].as_str().unwrap_or("UNKNOWN"),
        review["a1_witness"]["missing_primary_transports"],
        review["a1_witness"]["below_target"],
        review["a2_adversarial"]["status"]
            .as_str()
            .unwrap_or("UNKNOWN"),
        review["a2_adversarial"]["missing_primary_transports"],
        review["a2_adversarial"]["below_target"],
        review["a2_hostile_classifier"]["status"]
            .as_str()
            .unwrap_or("UNKNOWN"),
        review["a2_hostile_classifier"]["classifier_records"]
            .as_u64()
            .unwrap_or(0),
        review["a25_knowledge"]["status"]
            .as_str()
            .unwrap_or("UNKNOWN"),
        review["a3_brain_integration"]["status"]
            .as_str()
            .unwrap_or("UNKNOWN"),
        review["documents"]["threat_model"]
            .as_str()
            .unwrap_or("UNKNOWN"),
        review["documents"]["knowledge_architecture"]
            .as_str()
            .unwrap_or("UNKNOWN"),
    )
}

pub fn phase_a_measure_gate_markdown(review: &Value) -> String {
    format!(
        "# Phase A Measure Gate Review\n\n\
         - Status: `{}`\n\
         - Boundary: {}\n\
         - A1 witness: `{}` records={}\n\
         - A2 adversarial: `{}` events={} measured={}\n\
         - A2 packet evidence records: `{}`\n\
         - A2 hostile classifier: `{}` records={}\n\
         - A2.5 knowledge: `{}`\n\
         - A3 Brain integration: `{}`\n\
         - Calibration verdict: `{}`\n\
         - Acceptance degraded: `{}`\n",
        review["status"].as_str().unwrap_or("UNKNOWN"),
        review["boundary"].as_str().unwrap_or(""),
        review["a1_witness"]["status"].as_str().unwrap_or("UNKNOWN"),
        review["a1_witness"]["records"].as_u64().unwrap_or(0),
        review["a2_adversarial"]["status"]
            .as_str()
            .unwrap_or("UNKNOWN"),
        review["a2_adversarial"]["events"].as_u64().unwrap_or(0),
        review["a2_adversarial"]["measured_records"]
            .as_u64()
            .unwrap_or(0),
        review["a2_adversarial"]["packet_evidence_records"]
            .as_u64()
            .unwrap_or(0),
        review["a2_hostile_classifier"]["status"]
            .as_str()
            .unwrap_or("UNKNOWN"),
        review["a2_hostile_classifier"]["classifier_records"]
            .as_u64()
            .unwrap_or(0),
        review["a25_knowledge"]["status"]
            .as_str()
            .unwrap_or("UNKNOWN"),
        review["a3_brain_integration"]["status"]
            .as_str()
            .unwrap_or("UNKNOWN"),
        review["a3_brain_integration"]["calibration_status"]
            .as_str()
            .unwrap_or("UNKNOWN"),
        review["a3_brain_integration"]["acceptance_degraded"]
            .as_bool()
            .unwrap_or(false),
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
