use std::{collections::BTreeSet, path::Path};

use serde_json::{json, Value};

mod output;

pub use output::transport_camouflage_validation_markdown;

pub struct TransportCamouflageValidationPaths<'a> {
    pub live_manifest_json: &'a Path,
    pub stealth_bundle_json: &'a Path,
    pub wire_acceptance_json: &'a Path,
    pub relay_surface_json: &'a Path,
    pub classifier_summary_json: &'a Path,
    pub witness_pcap: &'a Path,
}

pub fn transport_camouflage_validation(
    live_manifest: &Value,
    stealth_bundle: &Value,
    wire_acceptance: &Value,
    relay_surface: &Value,
    classifier_summary: &Value,
    witness_pcap: &Path,
    paths: TransportCamouflageValidationPaths<'_>,
) -> Value {
    let pcap_size = witness_pcap
        .metadata()
        .ok()
        .and_then(|metadata| metadata.is_file().then_some(metadata.len()));
    let live_green = live_manifest
        .pointer("/acceptance_overview/overall_status")
        .and_then(Value::as_str)
        == Some("acceptance_green");
    let stealth_ready = stealth_bundle
        .get("active_blockers")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
        && stealth_bundle
            .pointer("/blocking_requirements/live_wire_green")
            .and_then(Value::as_bool)
            == Some(true)
        && stealth_bundle
            .pointer("/blocking_requirements/independent_witness_matched")
            .and_then(Value::as_bool)
            == Some(true)
        && stealth_bundle
            .pointer("/blocking_requirements/runtime_relay_surface_green")
            .and_then(Value::as_bool)
            == Some(true)
        && stealth_bundle
            .pointer("/blocking_requirements/wire_hostile_path_ready")
            .and_then(Value::as_bool)
            == Some(true);
    let wire_green = wire_acceptance
        .get("product_verdict")
        .and_then(Value::as_str)
        == Some("green")
        && wire_acceptance
            .get("acceptance_status")
            .and_then(Value::as_str)
            == Some("passed")
        && wire_acceptance
            .get("hostile_path_support_ready")
            .and_then(Value::as_bool)
            == Some(true)
        && wire_acceptance
            .get("independent_witness_correlation_status")
            .and_then(Value::as_str)
            == Some("matched");
    let relay_green = relay_surface.get("verdict").and_then(Value::as_str) == Some("green")
        && relay_surface.get("status").and_then(Value::as_str) == Some("runtime_surface_green")
        && relay_surface
            .pointer("/checks/surface_fields_complete_on_all_relay_events")
            .and_then(Value::as_bool)
            == Some(true);
    let classifier_pass = classifier_summary.get("status").and_then(Value::as_str) == Some("PASS")
        && classifier_summary
            .get("acceptance_degraded")
            .and_then(Value::as_bool)
            == Some(false);
    let pcap_present = pcap_size.is_some_and(|size| size > 24);

    let mut blockers = Vec::new();
    if !live_green {
        blockers.push("live_acceptance_not_green");
    }
    if !stealth_ready {
        blockers.push("stealth_acceptance_not_ready");
    }
    if !wire_green {
        blockers.push("wire_acceptance_not_witness_correlated");
    }
    if !relay_green {
        blockers.push("relay_surface_runtime_not_green");
    }
    if !classifier_pass {
        blockers.push("hostile_classifier_not_pass");
    }
    if !pcap_present {
        blockers.push("witness_pcap_missing_or_empty");
    }

    let status = if blockers.is_empty() {
        "READY"
    } else {
        "BLOCKED"
    };
    let classifier_reasons = classifier_summary
        .get("reasons")
        .and_then(Value::as_array)
        .map(|reasons| {
            reasons
                .iter()
                .filter_map(Value::as_str)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let classifier_detected_or_blocked =
        classifier_reasons.contains("hostile-classifier-detected-or-blocked");
    let classifier_unknown_or_missing = classifier_reasons
        .iter()
        .any(|reason| reason.contains("unknown") || reason.contains("missing"));

    let next_action = if !classifier_pass && classifier_detected_or_blocked {
        "tune_transport_camouflage_until_hostile_classifiers_pass"
    } else if !classifier_pass && classifier_unknown_or_missing {
        "run_or_install_hostile_classifiers_for_witness_pcap"
    } else if !classifier_pass {
        "inspect_hostile_classifier_failure"
    } else if !pcap_present {
        "collect_packet_capture_for_transport_camouflage"
    } else if !relay_green {
        "restore_relay_surface_runtime_evidence"
    } else if !wire_green || !stealth_ready || !live_green {
        "restore_witness_correlated_live_acceptance"
    } else {
        "open_next_phase_b_score_and_parity_gate"
    };

    json!({
        "artifact_schema": "transport_camouflage_validation_v1",
        "status": status,
        "next_action": next_action,
        "blockers": blockers,
        "checks": {
            "live_acceptance_green": live_green,
            "stealth_acceptance_ready": stealth_ready,
            "wire_acceptance_witness_correlated": wire_green,
            "relay_surface_runtime_green": relay_green,
            "hostile_classifier_pass": classifier_pass,
            "witness_pcap_present": pcap_present,
        },
        "classifier": {
            "status": classifier_summary.get("status").cloned().unwrap_or(Value::Null),
            "acceptance_degraded": classifier_summary.get("acceptance_degraded").cloned().unwrap_or(Value::Null),
            "classifier_records": classifier_summary.get("classifier_records").cloned().unwrap_or(Value::Null),
            "classifiers": classifier_summary.get("classifiers").cloned().unwrap_or_else(|| json!([])),
            "verdict_counts": classifier_summary.get("verdict_counts").cloned().unwrap_or_else(|| json!({})),
            "reasons": classifier_summary.get("reasons").cloned().unwrap_or_else(|| json!([])),
        },
        "live_acceptance": live_manifest.pointer("/acceptance_overview").cloned().unwrap_or(Value::Null),
        "wire_acceptance": {
            "product_verdict": wire_acceptance.get("product_verdict").cloned().unwrap_or(Value::Null),
            "acceptance_status": wire_acceptance.get("acceptance_status").cloned().unwrap_or(Value::Null),
            "hostile_path_support_ready": wire_acceptance.get("hostile_path_support_ready").cloned().unwrap_or(Value::Null),
            "independent_witness_correlation_status": wire_acceptance.get("independent_witness_correlation_status").cloned().unwrap_or(Value::Null),
        },
        "relay_surface_runtime": {
            "verdict": relay_surface.get("verdict").cloned().unwrap_or(Value::Null),
            "status": relay_surface.get("status").cloned().unwrap_or(Value::Null),
            "relay_events_scanned": relay_surface.get("relay_events_scanned").cloned().unwrap_or(Value::Null),
            "relay_events_missing_surface": relay_surface.get("relay_events_missing_surface").cloned().unwrap_or(Value::Null),
        },
        "witness_pcap": {
            "path": witness_pcap,
            "size_bytes": pcap_size,
        },
        "artifacts": {
            "live_manifest_json": paths.live_manifest_json,
            "stealth_bundle_json": paths.stealth_bundle_json,
            "wire_acceptance_json": paths.wire_acceptance_json,
            "relay_surface_json": paths.relay_surface_json,
            "classifier_summary_json": paths.classifier_summary_json,
            "witness_pcap": paths.witness_pcap,
        },
    })
}
