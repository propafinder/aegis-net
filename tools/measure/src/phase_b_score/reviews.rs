use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::{ADVERSARIAL_TARGET, PRIMARY_TRANSPORTS, WITNESS_TARGET};

pub(super) fn phase_b_score_target_review(baseline: &Value) -> Value {
    let witness_by_transport = baseline["witness"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| Some((entry["transport"].as_str()?.to_string(), entry.clone())))
        .collect::<BTreeMap<_, _>>();
    let adversarial_by_transport = baseline["adversarial"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| Some((entry["transport"].as_str()?.to_string(), entry.clone())))
        .collect::<BTreeMap<_, _>>();

    let mut witness = Vec::new();
    let mut adversarial = Vec::new();
    let mut blockers = Vec::new();
    for transport in PRIMARY_TRANSPORTS {
        let witness_score = witness_by_transport
            .get(transport)
            .and_then(|entry| entry["combined_avg"].as_f64());
        let witness_pass = witness_score.is_some_and(|score| score >= WITNESS_TARGET);
        if !witness_pass {
            blockers.push(format!("{transport}:witness_combined_below_target"));
        }
        witness.push(json!({
            "transport": transport,
            "combined_avg": witness_score,
            "target": WITNESS_TARGET,
            "status": if witness_pass { "PASS" } else { "FAIL" },
        }));

        let entry = adversarial_by_transport.get(transport);
        let measured = entry
            .and_then(|entry| entry["measured"].as_u64())
            .unwrap_or(0);
        let pass_rate = entry.and_then(|entry| entry["pass_rate"].as_f64());
        let adversarial_pass =
            measured > 0 && pass_rate.is_some_and(|rate| rate >= ADVERSARIAL_TARGET);
        if !adversarial_pass {
            blockers.push(format!("{transport}:adversarial_pass_rate_below_target"));
        }
        adversarial.push(json!({
            "transport": transport,
            "measured": measured,
            "pass_rate": pass_rate,
            "target": ADVERSARIAL_TARGET,
            "status": if adversarial_pass { "PASS" } else { "FAIL" },
        }));
    }

    json!({
        "status": if blockers.is_empty() { "PASS" } else { "FAIL" },
        "blockers": blockers,
        "primary_transports": PRIMARY_TRANSPORTS,
        "witness": witness,
        "adversarial": adversarial,
    })
}

pub(super) fn phase_b_observation_parity_review(
    live_manifest: &Value,
    two_vps_parity: &Value,
) -> Value {
    let server_host = live_manifest
        .get("server_host")
        .and_then(Value::as_str)
        .unwrap_or("");
    let client_host = live_manifest
        .get("client_host")
        .and_then(Value::as_str)
        .unwrap_or("");
    let server_platform = two_vps_parity
        .pointer("/server/platform")
        .and_then(Value::as_str)
        .unwrap_or("");
    let client_platform = two_vps_parity
        .pointer("/client/platform")
        .and_then(Value::as_str)
        .unwrap_or("");
    let parity_status = two_vps_parity.get("status").and_then(Value::as_str) == Some("PASS");
    let two_distinct_hosts =
        !server_host.is_empty() && !client_host.is_empty() && server_host != client_host;
    let platform_evidence_present = !server_platform.is_empty() && !client_platform.is_empty();
    let distinct_platforms = platform_evidence_present && server_platform != client_platform;
    let wire_green = live_manifest
        .get("wire_host_acceptance_product_verdict")
        .and_then(Value::as_str)
        == Some("green")
        && live_manifest
            .get("wire_host_acceptance_status")
            .and_then(Value::as_str)
            == Some("passed")
        && live_manifest
            .get("wire_host_acceptance_witness_correlation_status")
            .and_then(Value::as_str)
            == Some("matched");
    let stealth_ready = live_manifest
        .get("stealth_live_acceptance_bundle_verdict")
        .and_then(Value::as_str)
        == Some("green")
        && live_manifest
            .get("stealth_live_acceptance_bundle_status")
            .and_then(Value::as_str)
            == Some("ready_for_runtime_surface_hostile_path_validation");

    let mut blockers = Vec::new();
    if !parity_status {
        blockers.push("two_vps_parity_status_not_pass");
    }
    if !two_distinct_hosts {
        blockers.push("two_distinct_vps_hosts_not_proven");
    }
    if !platform_evidence_present {
        blockers.push("server_client_platform_evidence_missing");
    }
    if platform_evidence_present && !distinct_platforms {
        blockers.push("server_client_platforms_not_distinct");
    }
    if !wire_green {
        blockers.push("wire_witness_observation_not_green");
    }
    if !stealth_ready {
        blockers.push("stealth_observation_not_ready");
    }

    json!({
        "status": if blockers.is_empty() { "PASS" } else { "FAIL" },
        "scope": "linux_two_vps_server_client_observation_parity",
        "non_linux_parity_claimed": false,
        "blockers": blockers,
        "server": {
            "host": server_host,
            "platform": server_platform,
        },
        "client": {
            "host": client_host,
            "platform": client_platform,
        },
        "checks": {
            "two_vps_parity_status_pass": parity_status,
            "two_distinct_hosts": two_distinct_hosts,
            "platform_evidence_present": platform_evidence_present,
            "distinct_platforms": distinct_platforms,
            "wire_witness_green": wire_green,
            "stealth_ready": stealth_ready,
        },
    })
}

pub(super) fn phase_b_witness_wire_correlation_review(witness_wire: &Value) -> Value {
    let product_green =
        witness_wire.get("product_verdict").and_then(Value::as_str) == Some("green");
    let acceptance_passed = witness_wire
        .get("acceptance_status")
        .and_then(Value::as_str)
        == Some("passed");
    let witness_matched = witness_wire
        .get("independent_witness_correlation_status")
        .and_then(Value::as_str)
        == Some("matched");
    let hostile_path_ready = witness_wire
        .get("hostile_path_support_ready")
        .and_then(Value::as_bool)
        == Some(true);
    let matched_records = witness_wire
        .get("independent_witness_records_matched")
        .and_then(Value::as_u64)
        .unwrap_or(0);

    let mut blockers = Vec::new();
    if !product_green {
        blockers.push("wire_product_verdict_not_green");
    }
    if !acceptance_passed {
        blockers.push("wire_acceptance_not_passed");
    }
    if !witness_matched || matched_records == 0 {
        blockers.push("independent_witness_not_matched");
    }
    if !hostile_path_ready {
        blockers.push("hostile_path_support_not_ready");
    }

    json!({
        "status": if blockers.is_empty() { "PASS" } else { "FAIL" },
        "blockers": blockers,
        "product_verdict": witness_wire.get("product_verdict").cloned().unwrap_or(Value::Null),
        "acceptance_status": witness_wire.get("acceptance_status").cloned().unwrap_or(Value::Null),
        "independent_witness_correlation_status": witness_wire.get("independent_witness_correlation_status").cloned().unwrap_or(Value::Null),
        "independent_witness_records_matched": matched_records,
        "hostile_path_support_ready": hostile_path_ready,
    })
}

pub(super) fn phase_b_http_like_scope_review(two_vps_parity: &Value) -> Value {
    let transport_scope = two_vps_parity
        .get("transport_scope")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let legacy_tls_included = two_vps_parity
        .get("legacy_tls_included")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let transports = two_vps_parity
        .get("transport_priority")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let contains_legacy = transports
        .iter()
        .any(|transport| transport.as_str() == Some("legacy_tls"));
    let http_like_scope = transport_scope == "http_like";

    let mut blockers = Vec::new();
    if !http_like_scope {
        blockers.push("transport_scope_not_http_like");
    }
    if legacy_tls_included || contains_legacy {
        blockers.push("legacy_tls_present_in_http_like_scope");
    }

    json!({
        "status": if blockers.is_empty() { "PASS" } else { "FAIL" },
        "blockers": blockers,
        "transport_scope": transport_scope,
        "transport_priority": transports,
        "legacy_tls_included": legacy_tls_included,
    })
}
