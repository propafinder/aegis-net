use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::artifact::{read_json, write_json, write_text};

const PILOT_INPUT_FIELDS: [&str; 10] = [
    "validation_summary_json",
    "release_summary_json",
    "operator_loop_summary_json",
    "release_gate_handoff_json",
    "server_systemctl_status_log",
    "server_journal_log",
    "client_preflight_json",
    "client_startup_probe_json",
    "client_runtime_events_summary_json",
    "client_operator_evidence_json",
];

pub fn print_ubuntu_controlled_pilot_input_fields(
    pilot_inputs: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = read_json(pilot_inputs)?;
    for field in PILOT_INPUT_FIELDS {
        println!("{}", payload[field].as_str().unwrap_or(""));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn build_ubuntu_controlled_pilot_bundle(
    output_dir: &Path,
    server_status: &Path,
    server_journal: &Path,
    client_preflight: &Path,
    client_startup_probe: &Path,
    client_runtime_events_summary: &Path,
    client_operator_evidence: &Path,
    validation_summary: Option<&Path>,
    release_summary: Option<&Path>,
    operator_loop_summary: Option<&Path>,
    release_handoff: Option<&Path>,
    pilot_inputs: Option<&Path>,
    wire_witness_summary: Option<&Path>,
    wire_acceptance_summary: Option<&Path>,
    server_host_label: &str,
    client_host_label: &str,
    blocked_shape_label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let preflight = read_json_maybe_wrapped(client_preflight)?;
    let startup_probe = read_json_maybe_wrapped(client_startup_probe)?;
    let runtime_summary = read_json(client_runtime_events_summary)?;
    let operator_evidence = read_json(client_operator_evidence)?;
    let _validation_summary_payload = read_optional_json(validation_summary)?;
    let release_summary_payload = read_optional_json(release_summary)?;
    let operator_loop_payload = read_optional_json(operator_loop_summary)?;
    let _release_handoff_payload = read_optional_json(release_handoff)?;
    let _pilot_inputs_payload = read_optional_json(pilot_inputs)?;
    let wire_witness_payload = read_optional_json(wire_witness_summary)?;
    let wire_acceptance_payload = read_optional_json(wire_acceptance_summary)?;

    let server_status_text = fs::read_to_string(server_status)?;
    let server_journal_text = fs::read_to_string(server_journal)?;
    let server_active = server_status_text.to_ascii_lowercase().contains("active");
    let server_journal_present = !server_journal_text.trim().is_empty();
    let preflight_ok = preflight["status"].as_str() == Some("ok");
    let startup_ok = startup_probe["status"].as_str() == Some("ok");
    let runtime_ok = runtime_summary["startup_health"].as_str() == Some("healthy");
    let operator_green = operator_evidence["product_verdict"].as_str() == Some("green");
    let runtime_degradation_count =
        value_i64_or(&operator_evidence, "runtime_degradation_count", 0);
    let failover_count = value_i64_or(&operator_evidence, "failover_count", 0);
    let terminal_failure_count = value_i64_or(&operator_evidence, "terminal_failure_count", 0);
    let backend = operator_evidence["backend"].as_str().unwrap_or("");

    let mut service_blockers = Vec::new();
    push_if(
        &mut service_blockers,
        !server_active,
        "server_service_not_active",
    );
    push_if(
        &mut service_blockers,
        !server_journal_present,
        "server_journal_missing",
    );
    push_if(
        &mut service_blockers,
        !preflight_ok,
        "client_preflight_not_ok",
    );
    push_if(
        &mut service_blockers,
        !startup_ok,
        "client_startup_probe_not_ok",
    );
    push_if(
        &mut service_blockers,
        !runtime_ok,
        "client_runtime_summary_not_healthy",
    );
    push_if(
        &mut service_blockers,
        !operator_green,
        "client_operator_verdict_not_green",
    );

    let service_health_verdict = if service_blockers.is_empty() {
        "green"
    } else if service_blockers.iter().any(|item| {
        matches!(
            item.as_str(),
            "server_service_not_active"
                | "client_preflight_not_ok"
                | "client_startup_probe_not_ok"
                | "client_operator_verdict_not_green"
        )
    }) {
        "red"
    } else {
        "degraded"
    };

    let fallback_bypass_blocker_reason = fallback_bypass_blocker_reason(
        preflight_ok,
        startup_ok,
        backend,
        terminal_failure_count,
        failover_count,
        runtime_degradation_count,
        &runtime_summary,
        &operator_evidence,
    );
    let fallback_bypass_ready = preflight_ok
        && startup_ok
        && !backend.is_empty()
        && runtime_summary["startup_health"].as_str() == Some("healthy")
        && operator_evidence["runtime_status"].as_str() == Some("healthy")
        && operator_evidence["product_verdict"].as_str() == Some("green")
        && runtime_degradation_count == 0
        && failover_count == 0
        && terminal_failure_count == 0;
    let fallback_bypass_verdict = if fallback_bypass_ready {
        "proven"
    } else if operator_evidence["product_verdict"].as_str() == Some("red")
        || terminal_failure_count > 0
    {
        "blocked"
    } else {
        "degraded"
    };

    let bypass_source = operator_loop_payload
        .as_ref()
        .or(release_summary_payload.as_ref());
    let mut bypass_verdict = string_field(bypass_source, "bypass_verdict")
        .unwrap_or_else(|| fallback_bypass_verdict.to_string());
    let mut bypass_ready =
        bool_field(bypass_source, "bypass_ready").unwrap_or(fallback_bypass_ready);
    let bypass_blocker_reason = string_field(bypass_source, "bypass_blocker_reason")
        .or(fallback_bypass_blocker_reason.map(ToString::to_string));

    let mut baseline_bypass_verdict =
        string_field(operator_loop_payload.as_ref(), "baseline_bypass_verdict")
            .or_else(|| string_field(release_summary_payload.as_ref(), "baseline_bypass_verdict"))
            .unwrap_or_else(|| bypass_verdict.clone());
    let baseline_bypass_ready = bool_field(operator_loop_payload.as_ref(), "baseline_bypass_ready")
        .or_else(|| bool_field(release_summary_payload.as_ref(), "baseline_bypass_ready"))
        .unwrap_or(bypass_ready);
    let baseline_bypass_blocker_reason = string_field(
        operator_loop_payload.as_ref(),
        "baseline_bypass_blocker_reason",
    )
    .or_else(|| {
        string_field(
            release_summary_payload.as_ref(),
            "baseline_bypass_blocker_reason",
        )
    })
    .or_else(|| bypass_blocker_reason.clone());

    if baseline_bypass_verdict.is_empty() {
        baseline_bypass_verdict = bypass_verdict.clone();
    }

    let dns_support_tier = string_field(operator_loop_payload.as_ref(), "dns_support_tier")
        .or_else(|| string_field(release_summary_payload.as_ref(), "dns_support_tier"));
    let dns_runtime_verdict = string_field(operator_loop_payload.as_ref(), "dns_runtime_verdict")
        .or_else(|| string_field(release_summary_payload.as_ref(), "dns_runtime_verdict"));
    let dns_runtime_ready = bool_field(operator_loop_payload.as_ref(), "dns_runtime_ready")
        .or_else(|| bool_field(release_summary_payload.as_ref(), "dns_runtime_ready"));
    let dns_runtime_blocker_reason =
        string_field(operator_loop_payload.as_ref(), "dns_runtime_blocker_reason").or_else(|| {
            string_field(
                release_summary_payload.as_ref(),
                "dns_runtime_blocker_reason",
            )
        });
    let dns_requested = !matches!(
        dns_support_tier.as_deref(),
        None | Some("disabled") | Some("not_requested")
    );

    let wire_verdict = wire_acceptance_payload
        .as_ref()
        .and_then(|value| {
            value["verdict"]
                .as_str()
                .or(value["product_verdict"].as_str())
        })
        .map(ToString::to_string);
    let witness_correlation_status = string_field(
        wire_acceptance_payload.as_ref(),
        "independent_witness_correlation_status",
    );
    let matched_witness_records = wire_acceptance_payload
        .as_ref()
        .map(|value| value_i64_or(value, "independent_witness_records_matched", 0))
        .unwrap_or(0);

    let wire_witness_records = wire_witness_payload
        .as_ref()
        .and_then(|value| value["records"].as_array())
        .map(Vec::len)
        .unwrap_or(0);
    let hostile_path_ready = baseline_bypass_ready
        && !blocked_shape_label.is_empty()
        && wire_witness_records > 0
        && wire_acceptance_payload.is_some()
        && matches!(
            wire_verdict
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase()
                .as_str(),
            "green" | "ready" | "proven"
        )
        && witness_correlation_status.as_deref() == Some("matched")
        && matched_witness_records > 0;

    let (hostile_path_verdict, hostile_path_blocker_reason) = if hostile_path_ready {
        ("proven".to_string(), None)
    } else if !baseline_bypass_ready {
        (
            "not_proven".to_string(),
            baseline_bypass_blocker_reason
                .clone()
                .or_else(|| bypass_blocker_reason.clone()),
        )
    } else if wire_acceptance_payload.is_none() {
        (
            "missing_evidence".to_string(),
            Some("wire_acceptance_summary_missing".to_string()),
        )
    } else if wire_witness_payload.is_none() {
        (
            "missing_evidence".to_string(),
            Some("wire_witness_summary_missing".to_string()),
        )
    } else if witness_correlation_status.as_deref() != Some("matched") {
        (
            "degraded".to_string(),
            Some("independent_witness_not_correlated_with_runtime".to_string()),
        )
    } else {
        (
            "degraded".to_string(),
            Some("wire_host_acceptance_not_green".to_string()),
        )
    };

    let fully_proven = hostile_path_ready;
    let bypass_support_tier = if fully_proven {
        "wire_level_supported_hostile_path".to_string()
    } else if baseline_bypass_ready {
        "baseline_transport_runtime".to_string()
    } else {
        "not_proven".to_string()
    };
    if bypass_verdict.is_empty() {
        bypass_verdict = fallback_bypass_verdict.to_string();
    }
    if !bypass_ready && baseline_bypass_ready {
        bypass_ready = true;
    }

    let mut pilot_blockers = service_blockers.clone();
    if !bypass_ready {
        pilot_blockers.push(
            bypass_blocker_reason
                .clone()
                .unwrap_or_else(|| "ubuntu_live_bypass_not_proven".to_string()),
        );
    }
    if !fully_proven {
        pilot_blockers.push(
            hostile_path_blocker_reason
                .clone()
                .unwrap_or_else(|| "hostile_path_evidence_missing".to_string()),
        );
    }

    let pilot_verdict = if service_health_verdict == "green" && bypass_ready {
        "green"
    } else if service_health_verdict == "red" || bypass_verdict == "blocked" {
        "red"
    } else {
        "degraded"
    };

    let mut must_pass_checks = BTreeMap::new();
    must_pass_checks.insert(
        "server_service_active",
        check_entry(
            server_active,
            "aegis-server.service must be active on the relay host",
            "server_service_not_active",
        ),
    );
    must_pass_checks.insert(
        "server_journal_present",
        check_entry(
            server_journal_present,
            "server journal evidence must be collected for the rollout window",
            "server_journal_missing",
        ),
    );
    must_pass_checks.insert(
        "client_preflight_ok",
        check_entry(
            preflight_ok,
            "client preflight must return status=ok",
            "client_preflight_not_ok",
        ),
    );
    must_pass_checks.insert(
        "client_startup_probe_ok",
        check_entry(
            startup_ok,
            "client startup probe must return status=ok",
            "client_startup_probe_not_ok",
        ),
    );
    must_pass_checks.insert(
        "client_runtime_summary_healthy",
        check_entry(
            runtime_ok,
            "client runtime summary must stay healthy",
            "client_runtime_summary_not_healthy",
        ),
    );
    must_pass_checks.insert(
        "client_operator_verdict_green",
        check_entry(
            operator_green,
            "client operator evidence must stay green",
            "client_operator_verdict_not_green",
        ),
    );
    must_pass_checks.insert(
        "baseline_bypass_ready",
        check_entry(
            baseline_bypass_ready,
            "baseline Ubuntu bypass proof must be present for the pilot window",
            baseline_bypass_blocker_reason
                .as_deref()
                .unwrap_or("baseline_bypass_not_ready"),
        ),
    );
    must_pass_checks.insert(
        "runtime_degradation_count_zero",
        check_entry(
            runtime_degradation_count == 0,
            "runtime_degradation_count must stay zero during the accepted pilot window",
            &format!("runtime_degradation_count={runtime_degradation_count}"),
        ),
    );
    must_pass_checks.insert(
        "failover_count_zero",
        check_entry(
            failover_count == 0,
            "failover_count must stay zero during the accepted pilot window",
            &format!("failover_count={failover_count}"),
        ),
    );
    must_pass_checks.insert(
        "terminal_failure_count_zero",
        check_entry(
            terminal_failure_count == 0,
            "terminal_failure_count must stay zero during the accepted pilot window",
            &format!("terminal_failure_count={terminal_failure_count}"),
        ),
    );

    let mut advisory_checks = BTreeMap::new();
    advisory_checks.insert(
        "dns_runtime_ready_when_requested",
        check_entry(
            !dns_requested || dns_runtime_ready == Some(true),
            "if the selected pilot profile requests DNS support, DNS runtime evidence should also be ready",
            dns_runtime_blocker_reason
                .as_deref()
                .unwrap_or(&format!(
                    "dns_runtime_not_ready_for_tier={}",
                    dns_support_tier.as_deref().unwrap_or("unknown")
                )),
        ),
    );
    advisory_checks.insert(
        "hostile_path_ready",
        check_entry(
            hostile_path_ready,
            "blocked-shape hostile-path evidence should be present for stronger pilot confidence",
            hostile_path_blocker_reason
                .as_deref()
                .unwrap_or("hostile_path_not_ready"),
        ),
    );
    advisory_checks.insert(
        "fully_proven",
        check_entry(
            fully_proven,
            "correlated witness plus green wire acceptance upgrades the pilot to fully_proven",
            hostile_path_blocker_reason
                .as_deref()
                .unwrap_or("fully_proven_not_reached"),
        ),
    );

    let must_pass_failures = failed_check_ids(&must_pass_checks);
    let advisory_followups = failed_check_ids(&advisory_checks);
    let must_pass_verdict = if must_pass_failures.is_empty() {
        "pass"
    } else {
        "fail"
    };
    let advisory_verdict = if advisory_followups.is_empty() {
        "pass"
    } else {
        "follow_up_required"
    };

    let summary_path = output_dir.join("pilot-summary.json");
    let summary_md_path = output_dir.join("pilot-summary.md");
    let summary = json!({
        "artifact_schema": "ubuntu_controlled_pilot_bundle_v1",
        "generated_at": format!("unix:{}", current_unix_secs()),
        "supported_product_contour": "ubuntu_first_controlled_pilot",
        "supported_operator_scope": "ubuntu_release_evidence_collection",
        "server_host_label": server_host_label,
        "client_host_label": client_host_label,
        "blocked_shape_label": blocked_shape_label,
        "service_health_verdict": service_health_verdict,
        "service_health_blockers": service_blockers,
        "baseline_bypass_verdict": baseline_bypass_verdict,
        "baseline_bypass_ready": baseline_bypass_ready,
        "baseline_bypass_blocker_reason": baseline_bypass_blocker_reason,
        "bypass_verdict": bypass_verdict,
        "bypass_ready": bypass_ready,
        "bypass_support_tier": bypass_support_tier,
        "bypass_blocker_reason": bypass_blocker_reason,
        "dns_support_tier": dns_support_tier,
        "dns_runtime_verdict": dns_runtime_verdict,
        "dns_runtime_ready": dns_runtime_ready,
        "dns_runtime_blocker_reason": dns_runtime_blocker_reason,
        "hostile_path_verdict": hostile_path_verdict,
        "hostile_path_ready": hostile_path_ready,
        "hostile_path_blocker_reason": hostile_path_blocker_reason,
        "hostile_path_evidence_required": true,
        "fully_proven": fully_proven,
        "wire_mimicry_verdict": wire_verdict.as_deref().unwrap_or("unavailable"),
        "independent_witness_correlation_status": witness_correlation_status.unwrap_or_else(|| {
            if wire_witness_payload.is_none() {
                "not_provided".to_string()
            } else {
                "unknown".to_string()
            }
        }),
        "pilot_verdict": pilot_verdict,
        "pilot_blockers": pilot_blockers,
        "rollout_acceptance": {
            "must_pass_verdict": must_pass_verdict,
            "must_pass_failures": must_pass_failures,
            "must_pass_checks": must_pass_checks,
            "advisory_verdict": advisory_verdict,
            "advisory_followups": advisory_followups,
            "advisory_checks": advisory_checks,
        },
        "server": {
            "systemctl_status_log": display_path(server_status),
            "journal_log": display_path(server_journal),
            "service_active": server_active,
            "journal_present": server_journal_present,
        },
        "client": {
            "preflight_json": display_path(client_preflight),
            "startup_probe_json": display_path(client_startup_probe),
            "runtime_events_summary_json": display_path(client_runtime_events_summary),
            "operator_evidence_json": display_path(client_operator_evidence),
            "operator_loop_summary_json": operator_loop_summary.map(display_path),
            "preflight_status": value_or_null(&preflight, "status"),
            "startup_probe_status": value_or_null(&startup_probe, "status"),
            "runtime_startup_health": value_or_null(&runtime_summary, "startup_health"),
            "operator_product_verdict": value_or_null(&operator_evidence, "product_verdict"),
            "operator_runtime_status": value_or_null(&operator_evidence, "runtime_status"),
            "runtime_degradation_count": runtime_degradation_count,
            "failover_count": failover_count,
            "terminal_failure_count": terminal_failure_count,
            "backend": backend,
            "dns_support_tier": dns_support_tier,
            "dns_runtime_verdict": dns_runtime_verdict,
            "dns_runtime_ready": dns_runtime_ready,
            "dns_runtime_blocker_reason": dns_runtime_blocker_reason,
            "operator_loop_overall_status": operator_loop_payload.as_ref().and_then(|value| value["overall_status"].as_str()),
        },
        "validation_summary_json": validation_summary.map(display_path),
        "release_summary_json": release_summary.map(display_path),
        "release_gate_handoff_json": release_handoff.map(display_path),
        "pilot_inputs_json": pilot_inputs.map(display_path),
        "wire_witness_summary_json": wire_witness_summary.map(display_path),
        "wire_witness_schema": wire_witness_payload.as_ref().and_then(|value| value["artifact_schema"].as_str()),
        "wire_acceptance_summary_json": wire_acceptance_summary.map(display_path),
        "next_required_action": if fully_proven { "none" } else { "collect_or_fix_live_bypass_proof" },
    });

    write_json(&summary_path, &summary)?;
    write_text(&summary_md_path, &render_summary_markdown(&summary))?;

    let manifest = json!({
        "artifact_schema": "ubuntu_controlled_pilot_manifest_v1",
        "bundle_dir": display_path(output_dir),
        "pilot_summary_json": display_path(&summary_path),
        "pilot_summary_md": display_path(&summary_md_path),
        "blocked_shape_label": blocked_shape_label,
        "baseline_bypass_ready": baseline_bypass_ready,
        "hostile_path_ready": hostile_path_ready,
        "fully_proven": fully_proven,
        "service_health_verdict": service_health_verdict,
        "bypass_verdict": summary["bypass_verdict"].clone(),
        "bypass_ready": bypass_ready,
        "bypass_support_tier": summary["bypass_support_tier"].clone(),
        "dns_support_tier": summary["dns_support_tier"].clone(),
        "dns_runtime_verdict": summary["dns_runtime_verdict"].clone(),
        "dns_runtime_ready": summary["dns_runtime_ready"].clone(),
        "pilot_verdict": pilot_verdict,
        "pilot_blockers": summary["pilot_blockers"].clone(),
        "must_pass_verdict": must_pass_verdict,
        "must_pass_failures": summary["rollout_acceptance"]["must_pass_failures"].clone(),
        "advisory_verdict": advisory_verdict,
        "advisory_followups": summary["rollout_acceptance"]["advisory_followups"].clone(),
    });
    write_json(&output_dir.join("bundle.manifest.json"), &manifest)?;
    Ok(())
}

fn read_optional_json(path: Option<&Path>) -> Result<Option<Value>, Box<dyn std::error::Error>> {
    path.map(read_json).transpose()
}

fn read_json_maybe_wrapped(path: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    let raw = fs::read_to_string(path)?;
    match serde_json::from_str(&raw) {
        Ok(value) => Ok(value),
        Err(original_error) => {
            let start = raw.find('{');
            let end = raw.rfind('}');
            if let (Some(start), Some(end)) = (start, end) {
                if end > start {
                    return Ok(serde_json::from_str(&raw[start..=end])?);
                }
            }
            Err(original_error.into())
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn fallback_bypass_blocker_reason<'a>(
    preflight_ok: bool,
    startup_ok: bool,
    backend: &'a str,
    terminal_failure_count: i64,
    failover_count: i64,
    runtime_degradation_count: i64,
    runtime_summary: &Value,
    operator_evidence: &Value,
) -> Option<&'a str> {
    if !preflight_ok {
        Some("preflight_not_ok")
    } else if !startup_ok {
        Some("startup_probe_not_ok")
    } else if backend.is_empty() {
        Some("runtime_backend_not_observed")
    } else if terminal_failure_count > 0 {
        Some("terminal_failure_seen")
    } else if failover_count > 0 {
        Some("runtime_failover_seen")
    } else if runtime_degradation_count > 0 {
        Some("runtime_degradation_seen")
    } else if runtime_summary["startup_health"].as_str() != Some("healthy") {
        Some("runtime_startup_health_not_healthy")
    } else if operator_evidence["runtime_status"].as_str() != Some("healthy") {
        Some("runtime_status_not_healthy")
    } else if operator_evidence["product_verdict"].as_str() != Some("green") {
        Some("operator_product_verdict_not_green")
    } else {
        None
    }
}

fn check_entry(passed: bool, rule: &str, failure_reason: &str) -> Value {
    json!({
        "passed": passed,
        "rule": rule,
        "failure_reason": if passed { Value::Null } else { json!(failure_reason) },
    })
}

fn failed_check_ids(checks: &BTreeMap<&'static str, Value>) -> Vec<&'static str> {
    checks
        .iter()
        .filter_map(|(key, value)| {
            if value["passed"].as_bool() == Some(true) {
                None
            } else {
                Some(*key)
            }
        })
        .collect()
}

fn push_if(items: &mut Vec<String>, condition: bool, value: &str) {
    if condition {
        items.push(value.to_string());
    }
}

fn string_field(value: Option<&Value>, key: &str) -> Option<String> {
    value
        .and_then(|value| value[key].as_str())
        .map(ToString::to_string)
}

fn bool_field(value: Option<&Value>, key: &str) -> Option<bool> {
    value.and_then(|value| value[key].as_bool())
}

fn value_i64_or(value: &Value, key: &str, fallback: i64) -> i64 {
    match value.get(key) {
        Some(Value::Number(number)) => number.as_i64().unwrap_or(fallback),
        Some(Value::String(text)) => text.parse().unwrap_or(fallback),
        _ => fallback,
    }
}

fn value_or_null(value: &Value, key: &str) -> Value {
    value.get(key).cloned().unwrap_or(Value::Null)
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn display_path(path: &Path) -> String {
    path.components().collect::<PathBuf>().display().to_string()
}

fn render_summary_markdown(summary: &Value) -> String {
    let pilot_blockers = join_string_array(&summary["pilot_blockers"], "none");
    let must_pass_failures =
        join_string_array(&summary["rollout_acceptance"]["must_pass_failures"], "none");
    let advisory_followups =
        join_string_array(&summary["rollout_acceptance"]["advisory_followups"], "none");
    let mut lines = vec![
        "# Ubuntu Controlled Pilot Bundle".to_string(),
        String::new(),
        markdown_field(summary, "Server host", "server_host_label"),
        markdown_field(summary, "Client host", "client_host_label"),
        markdown_field(summary, "Blocked shape", "blocked_shape_label"),
        markdown_field(summary, "Service health verdict", "service_health_verdict"),
        markdown_field(summary, "Bypass verdict", "bypass_verdict"),
        markdown_field(summary, "Bypass support tier", "bypass_support_tier"),
        markdown_field(summary, "DNS support tier", "dns_support_tier"),
        markdown_field(summary, "DNS runtime verdict", "dns_runtime_verdict"),
        markdown_field(summary, "Hostile-path verdict", "hostile_path_verdict"),
        markdown_bool_field(summary, "Fully proven", "fully_proven"),
        markdown_field(summary, "Pilot verdict", "pilot_verdict"),
        format!("- Pilot blockers: `{pilot_blockers}`"),
        markdown_field(
            &summary["rollout_acceptance"],
            "Must-pass verdict",
            "must_pass_verdict",
        ),
        format!("- Must-pass failures: `{must_pass_failures}`"),
        markdown_field(
            &summary["rollout_acceptance"],
            "Advisory verdict",
            "advisory_verdict",
        ),
        format!("- Advisory follow-ups: `{advisory_followups}`"),
        markdown_bool_field(
            &summary["server"],
            "Server service active",
            "service_active",
        ),
        markdown_field(&summary["client"], "Client preflight", "preflight_status"),
        markdown_field(
            &summary["client"],
            "Client startup probe",
            "startup_probe_status",
        ),
        markdown_field(
            &summary["client"],
            "Client runtime startup health",
            "runtime_startup_health",
        ),
        markdown_field(
            &summary["client"],
            "Client operator verdict",
            "operator_product_verdict",
        ),
        format!(
            "- Release handoff included: `{}`",
            !summary["release_gate_handoff_json"].is_null()
        ),
        format!(
            "- Wire witness included: `{}`",
            !summary["wire_witness_summary_json"].is_null()
        ),
        String::new(),
        "## Evidence Paths".to_string(),
        String::new(),
        markdown_field(
            &summary["server"],
            "Server systemctl status",
            "systemctl_status_log",
        ),
        markdown_field(&summary["server"], "Server journal", "journal_log"),
        markdown_field(&summary["client"], "Client preflight", "preflight_json"),
        markdown_field(
            &summary["client"],
            "Client startup probe",
            "startup_probe_json",
        ),
        markdown_field(
            &summary["client"],
            "Client runtime events summary",
            "runtime_events_summary_json",
        ),
        markdown_field(
            &summary["client"],
            "Client operator evidence",
            "operator_evidence_json",
        ),
    ];
    if !summary["release_gate_handoff_json"].is_null() {
        lines.push(markdown_field(
            summary,
            "Release handoff",
            "release_gate_handoff_json",
        ));
    }
    if !summary["wire_witness_summary_json"].is_null() {
        lines.push(markdown_field(
            summary,
            "Wire witness summary",
            "wire_witness_summary_json",
        ));
    }
    if !summary["wire_acceptance_summary_json"].is_null() {
        lines.push(markdown_field(
            summary,
            "Wire acceptance summary",
            "wire_acceptance_summary_json",
        ));
    }
    lines.push(String::new());
    lines.join("\n")
}

fn join_string_array(value: &Value, fallback: &str) -> String {
    let joined = value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    if joined.is_empty() {
        fallback.to_string()
    } else {
        joined
    }
}

fn markdown_field(payload: &Value, label: &str, key: &str) -> String {
    format!("- {label}: `{}`", payload[key].as_str().unwrap_or("None"))
}

fn markdown_bool_field(payload: &Value, label: &str, key: &str) -> String {
    format!(
        "- {label}: `{}`",
        if payload[key].as_bool() == Some(true) {
            "True"
        } else {
            "False"
        }
    )
}
