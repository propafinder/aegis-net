use serde_json::Value;

pub fn transport_camouflage_validation_markdown(validation: &Value) -> String {
    format!(
        "# Transport Camouflage Validation\n\n\
         - Status: `{}`\n\
         - Next action: `{}`\n\
         - Blockers: `{}`\n\
         - Live acceptance green: `{}`\n\
         - Stealth acceptance ready: `{}`\n\
         - Wire witness-correlated: `{}`\n\
         - Relay surface green: `{}`\n\
         - Hostile classifier pass: `{}`\n\
         - Witness pcap present: `{}`\n\
         - Classifier status: `{}`\n\
         - Classifier records: `{}`\n\
         - Witness pcap: `{}`\n",
        validation["status"].as_str().unwrap_or("UNKNOWN"),
        validation["next_action"].as_str().unwrap_or("unknown"),
        join_strings(&validation["blockers"]),
        validation["checks"]["live_acceptance_green"]
            .as_bool()
            .unwrap_or(false),
        validation["checks"]["stealth_acceptance_ready"]
            .as_bool()
            .unwrap_or(false),
        validation["checks"]["wire_acceptance_witness_correlated"]
            .as_bool()
            .unwrap_or(false),
        validation["checks"]["relay_surface_runtime_green"]
            .as_bool()
            .unwrap_or(false),
        validation["checks"]["hostile_classifier_pass"]
            .as_bool()
            .unwrap_or(false),
        validation["checks"]["witness_pcap_present"]
            .as_bool()
            .unwrap_or(false),
        validation["classifier"]["status"]
            .as_str()
            .unwrap_or("unknown"),
        validation["classifier"]["classifier_records"]
            .as_u64()
            .unwrap_or(0),
        validation["witness_pcap"]["path"]
            .as_str()
            .unwrap_or("unknown"),
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
