use std::{collections::BTreeSet, fs, path::Path};

use serde_json::{json, Value};

pub fn phase_c_fronted_transport_evidence(attempts: &[Value], provider_doc: &Path) -> Value {
    let measured_attempts: Vec<&Value> = attempts
        .iter()
        .filter(|record| {
            record["scenario"]
                .as_str()
                .is_some_and(|scenario| !scenario.trim().is_empty())
        })
        .collect();
    let total = measured_attempts.len();
    let passed = measured_attempts
        .iter()
        .filter(|record| record["status"].as_str() == Some("PASS"))
        .count();
    let pass_rate = if total == 0 {
        0.0
    } else {
        passed as f64 / total as f64
    };
    let scenario_names: BTreeSet<String> = measured_attempts
        .iter()
        .filter_map(|record| record["scenario"].as_str().map(str::to_string))
        .collect();
    let normal_fronted_scenario_covered = scenario_names.contains("normal_fronted_https_ws")
        || scenario_names.contains("normal_fronted_grpc_stream")
        || scenario_names.contains("normal_fronted_masque");
    let adversarial_scenario_coverage = normal_fronted_scenario_covered
        && scenario_names.contains("primary_path_blocked")
        && scenario_names.contains("provider_edge_rotation");
    let fronted_metadata_present = measured_attempts.iter().all(|record| {
        non_empty_str(record, "front_authority")
            && non_empty_str_any(record, &["front_edge_server", "front_masque_server"])
            && non_empty_str(record, "origin_relay_address")
    });
    let front_authority_not_raw_ip = measured_attempts.iter().all(|record| {
        record["front_authority"]
            .as_str()
            .and_then(authority_host)
            .is_some_and(|host| !is_ip_literal(&host))
    });
    let fronted_endpoint_not_origin = measured_attempts.iter().all(|record| {
        let front_host =
            str_any(record, &["front_edge_server", "front_masque_server"]).and_then(authority_host);
        let origin_host = record["origin_relay_address"]
            .as_str()
            .and_then(authority_host);
        front_host
            .zip(origin_host)
            .is_some_and(|(front, origin)| front != origin)
    });
    let provider_boundary_evidence =
        fronted_metadata_present && front_authority_not_raw_ip && fronted_endpoint_not_origin;

    let provider_doc_text = fs::read_to_string(provider_doc)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let operator_provider_constraints_documented = provider_doc.is_file()
        && provider_doc_text.contains("provider")
        && provider_doc_text.contains("fronted")
        && (provider_doc_text.contains("https_ws")
            || provider_doc_text.contains("grpc_stream")
            || provider_doc_text.contains("masque"))
        && provider_doc_text.contains("constraint");

    let mut blockers = Vec::new();
    if pass_rate < 0.95 {
        blockers.push("fronted_transport_pass_rate_below_0_95");
    }
    if !operator_provider_constraints_documented {
        blockers.push("operator_provider_constraints_not_documented");
    }
    if !adversarial_scenario_coverage {
        blockers.push("adversarial_scenario_coverage_missing");
    }
    if !fronted_metadata_present {
        blockers.push("fronted_provider_metadata_missing");
    }
    if !front_authority_not_raw_ip {
        blockers.push("front_authority_raw_ip_or_missing");
    }
    if !fronted_endpoint_not_origin {
        blockers.push("fronted_endpoint_matches_origin");
    }

    json!({
        "status": if blockers.is_empty() { "PASS" } else { "FAIL" },
        "blockers": blockers,
        "fronted_transport_pass_rate": pass_rate,
        "fronted_masque_pass_rate": pass_rate,
        "operator_provider_constraints_documented": operator_provider_constraints_documented,
        "adversarial_scenario_coverage": adversarial_scenario_coverage,
        "normal_fronted_scenario_covered": normal_fronted_scenario_covered,
        "provider_boundary_evidence": provider_boundary_evidence,
        "fronted_metadata_present": fronted_metadata_present,
        "front_authority_not_raw_ip": front_authority_not_raw_ip,
        "fronted_endpoint_not_origin": fronted_endpoint_not_origin,
        "attempts": {
            "total": total,
            "passed": passed,
            "failed": total.saturating_sub(passed),
            "scenarios": scenario_names.into_iter().collect::<Vec<_>>(),
        },
        "artifacts": {
            "provider_doc": provider_doc,
        },
    })
}

pub struct PhaseCFrontedBlockedResult<'a> {
    pub classification: &'a str,
    pub detail: &'a str,
    pub front_authority: &'a str,
    pub front_edge_server: &'a str,
    pub front_transport_scope: &'a str,
    pub origin_relay_address: &'a str,
}

pub fn phase_c_fronted_blocked_result(input: PhaseCFrontedBlockedResult<'_>) -> Value {
    json!({
        "status": "BLOCKED",
        "classification": input.classification,
        "detail": input.detail,
        "front_authority": input.front_authority,
        "front_edge_server": input.front_edge_server,
        "front_transport_scope": input.front_transport_scope,
        "origin_relay_address": input.origin_relay_address,
    })
}

pub struct PhaseCFrontedProbeAttempt<'a> {
    pub scenario: &'a str,
    pub status: &'a str,
    pub front_authority: &'a str,
    pub front_edge_server: &'a str,
    pub front_transport_scope: &'a str,
    pub origin_relay_address: &'a str,
    pub blocked_relay_address: &'a str,
    pub probe_url: &'a str,
    pub started_ms: u64,
    pub finished_ms: u64,
    pub detail: &'a str,
}

pub fn phase_c_fronted_probe_attempt(input: PhaseCFrontedProbeAttempt<'_>) -> Value {
    json!({
        "scenario": input.scenario,
        "status": input.status,
        "provider": input.front_authority,
        "front_authority": input.front_authority,
        "front_edge_server": input.front_edge_server,
        "front_masque_server": input.front_edge_server,
        "front_transport_scope": input.front_transport_scope,
        "origin_relay_address": input.origin_relay_address,
        "blocked_relay_address": input.blocked_relay_address,
        "probe_url": input.probe_url,
        "started_ms": input.started_ms,
        "finished_ms": input.finished_ms,
        "detail": input.detail,
    })
}

pub fn phase_c_fronted_provider_preflight(
    front_authority: &str,
    front_masque_server: &str,
    origin_relay_address: &str,
    provider_doc: &Path,
) -> Value {
    let front_authority_host = authority_host(front_authority);
    let front_masque_host = authority_host(front_masque_server);
    let origin_host = authority_host(origin_relay_address);
    let front_authority_placeholder = has_placeholder(front_authority);
    let front_masque_placeholder = has_placeholder(front_masque_server);
    let origin_placeholder = has_placeholder(origin_relay_address);
    let provider_doc_text = fs::read_to_string(provider_doc)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let provider_doc_ready = provider_doc.is_file()
        && provider_doc_text.contains("provider")
        && provider_doc_text.contains("fronted")
        && provider_doc_text.contains("masque")
        && provider_doc_text.contains("constraint");
    let front_authority_not_raw_ip = front_authority_host
        .as_deref()
        .is_some_and(|host| !is_ip_literal(host));
    let fronted_endpoint_not_origin = front_masque_host
        .as_ref()
        .zip(origin_host.as_ref())
        .is_some_and(|(front, origin)| front != origin);

    let mut blockers = Vec::new();
    if front_authority_host.is_none() {
        blockers.push("front_authority_missing_or_invalid");
    }
    if front_masque_host.is_none() {
        blockers.push("front_masque_server_missing_or_invalid");
    }
    if origin_host.is_none() {
        blockers.push("origin_relay_address_missing_or_invalid");
    }
    if !front_authority_not_raw_ip {
        blockers.push("front_authority_raw_ip_or_missing");
    }
    if !fronted_endpoint_not_origin {
        blockers.push("fronted_endpoint_matches_origin");
    }
    if front_authority_placeholder {
        blockers.push("front_authority_placeholder_value");
    }
    if front_masque_placeholder {
        blockers.push("front_masque_server_placeholder_value");
    }
    if origin_placeholder {
        blockers.push("origin_relay_address_placeholder_value");
    }
    if !provider_doc_ready {
        blockers.push("operator_provider_constraints_not_documented");
    }

    json!({
        "event": "phase_c_fronted_provider_preflight",
        "schema_version": 1,
        "status": if blockers.is_empty() { "PASS" } else { "FAIL" },
        "blockers": blockers,
        "front_authority_host": front_authority_host,
        "front_masque_server_host": front_masque_host,
        "origin_relay_host": origin_host,
        "front_authority_not_raw_ip": front_authority_not_raw_ip,
        "fronted_endpoint_not_origin": fronted_endpoint_not_origin,
        "placeholder_free": !(front_authority_placeholder || front_masque_placeholder || origin_placeholder),
        "operator_provider_constraints_documented": provider_doc_ready,
        "artifacts": {
            "provider_doc": provider_doc,
        },
    })
}

pub fn phase_c_fronted_provider_preflight_markdown(preflight: &Value) -> String {
    format!(
        "# Phase C Fronted Provider Preflight\n\n\
         - Status: `{}`\n\
         - Blockers: `{}`\n\
         - Front authority host: `{}`\n\
         - Front MASQUE server host: `{}`\n\
         - Origin relay host: `{}`\n\
         - Front authority not raw IP: `{}`\n\
         - Fronted endpoint not origin: `{}`\n\
         - Placeholder free: `{}`\n\
         - Provider constraints documented: `{}`\n",
        preflight["status"].as_str().unwrap_or("UNKNOWN"),
        join_strings(&preflight["blockers"]),
        preflight["front_authority_host"]
            .as_str()
            .unwrap_or("UNKNOWN"),
        preflight["front_masque_server_host"]
            .as_str()
            .unwrap_or("UNKNOWN"),
        preflight["origin_relay_host"].as_str().unwrap_or("UNKNOWN"),
        preflight["front_authority_not_raw_ip"]
            .as_bool()
            .unwrap_or(false),
        preflight["fronted_endpoint_not_origin"]
            .as_bool()
            .unwrap_or(false),
        preflight["placeholder_free"].as_bool().unwrap_or(false),
        preflight["operator_provider_constraints_documented"]
            .as_bool()
            .unwrap_or(false),
    )
}

pub fn phase_c_fronted_transport_evidence_markdown(evidence: &Value) -> String {
    format!(
        "# Phase C Fronted Transport Evidence\n\n\
         - Status: `{}`\n\
         - Blockers: `{}`\n\
         - Fronted transport pass rate: `{}`\n\
         - Provider constraints documented: `{}`\n\
         - Adversarial scenario coverage: `{}`\n\
         - Provider boundary evidence: `{}`\n\
         - Attempts: `{}` passed of `{}`\n",
        evidence["status"].as_str().unwrap_or("UNKNOWN"),
        join_strings(&evidence["blockers"]),
        evidence["fronted_transport_pass_rate"]
            .as_f64()
            .or_else(|| evidence["fronted_masque_pass_rate"].as_f64())
            .unwrap_or(0.0),
        evidence["operator_provider_constraints_documented"]
            .as_bool()
            .unwrap_or(false),
        evidence["adversarial_scenario_coverage"]
            .as_bool()
            .unwrap_or(false),
        evidence["provider_boundary_evidence"]
            .as_bool()
            .unwrap_or(false),
        evidence["attempts"]["passed"].as_u64().unwrap_or(0),
        evidence["attempts"]["total"].as_u64().unwrap_or(0),
    )
}

fn non_empty_str(value: &Value, key: &str) -> bool {
    value[key]
        .as_str()
        .is_some_and(|text| !text.trim().is_empty())
}

fn non_empty_str_any(value: &Value, keys: &[&str]) -> bool {
    str_any(value, keys).is_some_and(|text| !text.trim().is_empty())
}

fn str_any<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|key| value[*key].as_str())
}

fn authority_host(authority: &str) -> Option<String> {
    let trimmed = authority.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix('[') {
        let (host, _) = rest.split_once(']')?;
        return Some(host.to_ascii_lowercase());
    }
    let colon_count = trimmed.matches(':').count();
    let host = if colon_count == 1 {
        trimmed
            .rsplit_once(':')
            .map(|(host, _)| host)
            .unwrap_or(trimmed)
    } else {
        trimmed
    };
    let host = host.trim().trim_end_matches('.');
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

fn has_placeholder(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.starts_with('<') && trimmed.ends_with('>')
}

fn is_ip_literal(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
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
