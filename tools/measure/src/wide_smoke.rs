use std::{fs, path::Path};

use serde_json::{json, Value};

pub struct WideSmokeAdversarialEventInputs<'a> {
    pub contract: &'a Value,
    pub runtime_events: &'a [Value],
    pub contract_json: &'a Path,
    pub runtime_events_jsonl: &'a Path,
    pub scenario: &'a str,
    pub transport: &'a str,
    pub network_profile: &'a str,
    pub artifact_dir: &'a str,
    pub packet_capture: Option<&'a Path>,
    pub tcpdump_log: Option<&'a Path>,
}

pub fn wide_smoke_adversarial_event(
    inputs: WideSmokeAdversarialEventInputs<'_>,
) -> Result<Value, Box<dyn std::error::Error>> {
    let packet_capture_size = inputs.packet_capture.and_then(|path| {
        path.metadata()
            .ok()
            .and_then(|metadata| metadata.is_file().then_some(metadata.len()))
    });
    let tcpdump_text = match inputs.tcpdump_log {
        Some(path) if path.is_file() => fs::read_to_string(path).unwrap_or_default(),
        _ => String::new(),
    };
    let tcpdump_packets_captured = parse_tcpdump_count(&tcpdump_text, "packets captured");
    let tcpdump_packets_dropped = parse_tcpdump_count(&tcpdump_text, "packets dropped by kernel");
    let completed = latest_event(inputs.runtime_events, "ingress_udp_datagram_completed");
    let relay_success = latest_event(inputs.runtime_events, "relay_session_succeeded");
    let observed = latest_event(inputs.runtime_events, "ingress_udp_datagram_observed");

    let mut reasons = Vec::new();
    if inputs.contract["runtime_health_status"].as_str() != Some("healthy") {
        reasons.push("runtime-health-not-healthy");
    }
    if inputs.contract["runtime_transport_status"].as_str() != Some("completed") {
        reasons.push("runtime-transport-not-completed");
    }
    if inputs.contract["runtime_delivery_stage"].as_str() != Some("completed_return_delivery_tail")
    {
        reasons.push("runtime-delivery-not-complete");
    }
    if completed.is_none() {
        reasons.push("missing-ingress-udp-completed");
    }
    if relay_success.is_none() {
        reasons.push("missing-relay-session-succeeded");
    }
    if observed.is_none() {
        reasons.push("missing-ingress-udp-observed");
    }
    if let Some(path) = inputs.packet_capture {
        if !path.is_file() {
            reasons.push("missing-packet-capture");
        } else if packet_capture_size.is_some_and(|size| size <= 24) {
            reasons.push("packet-capture-has-no-packets");
        }
    }
    if inputs.tcpdump_log.is_some_and(|path| !path.is_file()) {
        reasons.push("missing-tcpdump-log");
    }

    let status = if reasons.is_empty() { "PASS" } else { "FAIL" };
    let completed_fields = completed
        .and_then(|event| event.get("fields"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    let relay_fields = relay_success
        .and_then(|event| event.get("fields"))
        .cloned()
        .unwrap_or_else(|| json!({}));

    Ok(json!({
        "event": "adversarial_scenario_measured",
        "schema_version": 1,
        "mode": "live_aegis_runtime_artifact",
        "scenario": inputs.scenario,
        "transport": inputs.transport,
        "network_profile": inputs.network_profile,
        "threshold": transport_threshold(inputs.transport),
        "status": status,
        "reason": if status == "PASS" {
            "artifact-backed-aegis-runtime-probe-succeeded".to_string()
        } else {
            reasons.join(",")
        },
        "artifact_dir": inputs.artifact_dir,
        "contract_json": inputs.contract_json,
        "runtime_events_jsonl": inputs.runtime_events_jsonl,
        "packet_capture": inputs.packet_capture,
        "packet_capture_size_bytes": packet_capture_size,
        "packet_evidence_status": if packet_capture_size.is_some_and(|size| size > 24) {
            "present"
        } else {
            "not_attached"
        },
        "tcpdump_log": inputs.tcpdump_log,
        "tcpdump_packets_captured": tcpdump_packets_captured,
        "tcpdump_packets_dropped_by_kernel": tcpdump_packets_dropped,
        "runtime_health_status": inputs.contract["runtime_health_status"].clone(),
        "runtime_transport_status": inputs.contract["runtime_transport_status"].clone(),
        "runtime_delivery_stage": inputs.contract["runtime_delivery_stage"].clone(),
        "runtime_response_action": inputs.contract["runtime_response_action"].clone(),
        "runtime_response_stage": inputs.contract["runtime_response_stage"].clone(),
        "runtime_target_host": inputs.contract.get("runtime_target_host").cloned().filter(not_null)
            .or_else(|| completed_fields.get("target_host").cloned()),
        "runtime_target_port": inputs.contract.get("runtime_target_port").cloned().filter(not_null)
            .or_else(|| completed_fields.get("target_port").cloned()),
        "wide_udp_capture_contract": inputs.contract.get("udp_capture_contract").cloned().filter(not_null)
            .or_else(|| completed_fields.get("wide_udp_capture_contract").cloned()),
        "wide_udp_capture_support_tier": inputs.contract.get("wide_udp_capture_support_tier").cloned().filter(not_null)
            .or_else(|| completed_fields.get("wide_udp_capture_support_tier").cloned()),
        "wide_udp_capture_policy": inputs.contract.get("wide_udp_capture_policy").cloned().filter(not_null)
            .or_else(|| completed_fields.get("wide_udp_capture_policy").cloned()),
        "wide_udp_capture_runtime_scope": inputs.contract.get("wide_udp_capture_runtime_scope").cloned().filter(not_null)
            .or_else(|| completed_fields.get("wide_udp_capture_runtime_scope").cloned()),
        "relay_chosen_transport": relay_fields.get("chosen_transport").cloned(),
        "runtime_event_count": inputs.runtime_events.len(),
        "ts_unix_ms": unix_ms(),
    }))
}

fn latest_event<'a>(events: &'a [Value], code: &str) -> Option<&'a Value> {
    events
        .iter()
        .rev()
        .find(|event| event["event_code"].as_str() == Some(code))
}

fn parse_tcpdump_count(text: &str, label: &str) -> Option<u64> {
    for line in text.lines() {
        let Some((count, suffix)) = line.trim().split_once(' ') else {
            continue;
        };
        if suffix == label || (label.ends_with("packets captured") && suffix == "packet captured") {
            if let Ok(count) = count.parse() {
                return Some(count);
            }
        }
    }
    None
}

fn transport_threshold(transport: &str) -> Option<f64> {
    match transport {
        "legacy_tls" | "https_ws" | "masque_derived" => Some(0.85),
        "grpc_stream" => Some(0.60),
        _ => None,
    }
}

fn not_null(value: &Value) -> bool {
    !value.is_null()
}

fn unix_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}
