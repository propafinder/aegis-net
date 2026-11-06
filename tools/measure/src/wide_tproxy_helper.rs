use std::collections::BTreeSet;
use std::path::Path;
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};

#[cfg(all(test, unix))]
#[path = "wide_tproxy_helper_file_tests.rs"]
mod file_tests;

pub fn print_tproxy_client_contract(config: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let data: toml::Value = std::fs::read_to_string(config)?.parse()?;
    let ingress = data.get("ingress");
    let empty_wide = toml::Value::Table(Default::default());
    let wide = ingress
        .and_then(|value| value.get("wide"))
        .unwrap_or(&empty_wide)
        .clone();

    match ingress.and_then(|value| value.get("primary")) {
        None => emit("CFG_INGRESS_PRIMARY", "wide"),
        Some(toml::Value::String(primary)) => emit("CFG_INGRESS_PRIMARY", primary),
        _ => return Err("invalid ingress primary".into()),
    }
    match wide.get("enabled") {
        None => emit("CFG_WIDE_ENABLED", "1"),
        Some(toml::Value::Boolean(enabled)) => {
            emit("CFG_WIDE_ENABLED", if *enabled { "1" } else { "0" });
        }
        _ => return Err("invalid wide enablement".into()),
    }

    emit_toml("CFG_WIDE_BACKEND", wide.get("platform_backend"));
    emit_toml("CFG_WIDE_PROFILE", wide.get("rollout_profile"));
    emit_toml("CFG_WIDE_INTERFACE", wide.get("prerouting_interface"));

    let mut listen_family = None;
    if let Some(listen_text) = wide.get("listen").and_then(toml::Value::as_str) {
        listen_family = Some(if listen_text.starts_with('[') {
            "ipv6"
        } else {
            "ipv4"
        });
        emit("CFG_WIDE_LISTEN_FAMILY", listen_family.unwrap());
        if let Some(port) = listen_text
            .strip_prefix('[')
            .and_then(|text| text.rsplit_once("]:"))
        {
            emit("CFG_WIDE_LISTEN_PORT", port.1);
        } else if let Some((_, port)) = listen_text.rsplit_once(':') {
            emit("CFG_WIDE_LISTEN_PORT", port);
        }
    }

    let capture_dns = wide.get("capture_dns").and_then(toml::Value::as_bool);
    if let Some(capture_dns) = capture_dns {
        emit("CFG_CAPTURE_DNS", if capture_dns { "1" } else { "0" });
    }

    let udp_capture_contract = wide
        .get("udp_capture_contract")
        .and_then(toml::Value::as_str)
        .unwrap_or("preview_allowlist_only");
    emit("CFG_UDP_CAPTURE_CONTRACT", udp_capture_contract);

    if capture_dns == Some(true) {
        if udp_capture_contract == "generic_capture_unstable" {
            emit("CFG_UDP_CAPTURE_SUPPORT_TIER", "guarded_unstable");
            match listen_family {
                Some("ipv6") => {
                    emit(
                        "CFG_UDP_CAPTURE_POLICY",
                        "any_target_port_linux_ipv6_unstable",
                    );
                    emit("CFG_UDP_CAPTURE_RUNTIME_SCOPE", "linux_ipv6_only");
                }
                Some("ipv4") => {
                    emit(
                        "CFG_UDP_CAPTURE_POLICY",
                        "any_target_port_linux_ipv4_unstable",
                    );
                    emit("CFG_UDP_CAPTURE_RUNTIME_SCOPE", "linux_ipv4_only");
                }
                _ => {}
            }
        } else {
            emit("CFG_UDP_CAPTURE_SUPPORT_TIER", "supported_preview");
            emit("CFG_UDP_CAPTURE_POLICY", "allowlist_ports");
            match listen_family {
                Some("ipv6") => emit("CFG_UDP_CAPTURE_RUNTIME_SCOPE", "linux_ipv6_only"),
                Some("ipv4") => emit("CFG_UDP_CAPTURE_RUNTIME_SCOPE", "linux_ipv4_only"),
                _ => {}
            }
        }
    }

    let dns_port = wide.get("dns_port").and_then(number_to_i64);
    if let Some(dns_port) = dns_port {
        emit("CFG_DNS_PORT", &dns_port.to_string());
    }

    let mut normalized_udp_preview_ports = Vec::new();
    if let Some(ports) = wide
        .get("udp_preview_ports")
        .and_then(toml::Value::as_array)
    {
        for port in ports.iter().filter_map(number_to_i64) {
            if Some(port) == dns_port || normalized_udp_preview_ports.contains(&port) {
                continue;
            }
            normalized_udp_preview_ports.push(port);
        }
    }
    if !normalized_udp_preview_ports.is_empty() {
        let ports = normalized_udp_preview_ports
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        emit("CFG_UDP_PREVIEW_PORTS", &ports);
    }

    emit_toml("CFG_DEFAULT_MARK", wide.get("default_mark"));
    Ok(())
}

pub fn print_tproxy_startup_probe_fields(
    stdout: &Path,
    stderr: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let stdout_text = std::fs::read_to_string(stdout).unwrap_or_default();
    let stderr_text = std::fs::read_to_string(stderr).unwrap_or_default();
    let combined = format!("{stdout_text}\n{stderr_text}");
    for candidate in [&stdout_text, &stderr_text, &combined] {
        let Some(report) = extract_json_object(candidate) else {
            continue;
        };
        let Some(startup) = report.get("startup").and_then(serde_json::Value::as_object) else {
            continue;
        };
        emit_json("PROBE_STATUS", report.get("status"));
        emit_json("PROBE_CODE", startup.get("code"));
        emit_json("PROBE_STARTED_BACKEND", startup.get("started_backend"));
        emit_json("PROBE_FAILURE_CODE", startup.get("failure_code"));
        emit_json("PROBE_HINT_CODE", startup.get("hint_code"));
        emit_json("PROBE_MESSAGE", startup.get("message"));
        emit_json("PROBE_HINT", startup.get("hint"));
        emit_json(
            "PROBE_DNS_STATUS",
            startup.get("wide_dns_capture_preview_status"),
        );
        emit_json(
            "PROBE_UDP_CAPTURE_CONTRACT",
            startup.get("wide_udp_capture_contract"),
        );
        emit_json(
            "PROBE_UDP_CAPTURE_SUPPORT_TIER",
            startup.get("wide_udp_capture_support_tier"),
        );
        emit_json(
            "PROBE_UDP_CAPTURE_POLICY",
            startup.get("wide_udp_capture_policy"),
        );
        emit_json(
            "PROBE_UDP_CAPTURE_RUNTIME_SCOPE",
            startup.get("wide_udp_capture_runtime_scope"),
        );
        return Ok(());
    }
    Err("missing startup probe JSON".into())
}

pub fn print_tproxy_runtime_events_summary(
    runtime_events_jsonl: &Path,
    limit: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let records = read_jsonl_lenient(runtime_events_jsonl)?;
    emit("EVENTS_TOTAL", &records.len().to_string());
    if records.is_empty() {
        return Ok(());
    }

    let latest = records.last().unwrap();
    emit_json("EVENTS_LATEST_CODE", latest.get("event_code"));
    emit_json("EVENTS_LATEST_LEVEL", latest.get("level"));
    emit_json("EVENTS_LATEST_MESSAGE", latest.get("message"));

    let backend = records.iter().rev().find(|record| {
        record.get("event_code").and_then(Value::as_str) == Some("ingress_backend_started")
    });
    if let Some(fields) = backend
        .and_then(|record| record.get("fields"))
        .and_then(Value::as_object)
    {
        emit_json("EVENTS_BACKEND", fields.get("backend"));
        emit_json(
            "EVENTS_BACKEND_RUNTIME_ID",
            fields.get("backend_runtime_id"),
        );
        emit_json(
            "EVENTS_BACKEND_DNS_STATUS",
            fields.get("wide_dns_capture_preview_status"),
        );
        emit_json(
            "EVENTS_BACKEND_UDP_CAPTURE_CONTRACT",
            fields.get("wide_udp_capture_contract"),
        );
        emit_json(
            "EVENTS_BACKEND_UDP_CAPTURE_SUPPORT_TIER",
            fields.get("wide_udp_capture_support_tier"),
        );
        emit_json(
            "EVENTS_BACKEND_UDP_CAPTURE_POLICY",
            fields.get("wide_udp_capture_policy"),
        );
        emit_json(
            "EVENTS_BACKEND_UDP_CAPTURE_RUNTIME_SCOPE",
            fields.get("wide_udp_capture_runtime_scope"),
        );
    }

    let has = |code: &str| {
        records
            .iter()
            .any(|record| record.get("event_code").and_then(Value::as_str) == Some(code))
    };
    let startup_health = if has("ingress_startup_selection_failed") {
        "failed"
    } else if has("ingress_wide_bind_fallback") {
        "degraded_fallback"
    } else if backend.is_some() {
        "healthy"
    } else {
        "unknown"
    };
    emit("EVENTS_STARTUP_HEALTH", startup_health);

    let runtime_degradation_codes = [
        "ingress_udp_datagram_dropped",
        "direct_active_stall_probe_retry_selected",
        "relay_transport_failed",
    ];
    let failover_codes = ["direct_relay_failover_triggered"];
    let terminal_failure_codes = ["ingress_session_failed", "ingress_session_broker_failed"];
    let runtime_degradation_count = count_codes(&records, &runtime_degradation_codes);
    let failover_count = count_codes(&records, &failover_codes);
    let terminal_failure_count = count_codes(&records, &terminal_failure_codes);
    emit(
        "EVENTS_RUNTIME_DEGRADATION_COUNT",
        &runtime_degradation_count.to_string(),
    );
    emit("EVENTS_FAILOVER_COUNT", &failover_count.to_string());
    emit(
        "EVENTS_TERMINAL_FAILURE_COUNT",
        &terminal_failure_count.to_string(),
    );

    let runtime_status = if terminal_failure_count > 0 {
        "terminal_failure_seen"
    } else if failover_count > 0 {
        "degraded_failover_seen"
    } else if runtime_degradation_count > 0 {
        "degraded_runtime_seen"
    } else {
        "healthy"
    };
    emit("EVENTS_RUNTIME_STATUS", runtime_status);

    let product_verdict = if terminal_failure_count > 0
        || matches!(startup_health, "failed" | "unknown")
    {
        "red"
    } else if failover_count > 0 || runtime_degradation_count > 0 || startup_health != "healthy" {
        "degraded"
    } else {
        "green"
    };
    emit("EVENTS_PRODUCT_VERDICT", product_verdict);

    let problem_codes = [
        "ingress_startup_selection_failed",
        "ingress_wide_bind_fallback",
        "ingress_accept_failed",
        "ingress_session_failed",
        "ingress_session_broker_failed",
        "relay_transport_failed",
        "ingress_udp_datagram_dropped",
    ];
    let start = records.len().saturating_sub(limit);
    let problem = records[start..].iter().rev().find(|record| {
        record
            .get("event_code")
            .and_then(Value::as_str)
            .is_some_and(|code| problem_codes.contains(&code))
            || record.get("level").and_then(Value::as_str) == Some("error")
    });
    if let Some(problem) = problem {
        let fields = problem.get("fields").and_then(Value::as_object);
        emit_json("EVENTS_PROBLEM_CODE", problem.get("event_code"));
        emit_json("EVENTS_PROBLEM_LEVEL", problem.get("level"));
        emit_json("EVENTS_PROBLEM_MESSAGE", problem.get("message"));
        for (key, field) in [
            ("EVENTS_PROBLEM_BIND_ERROR_CODE", "bind_error_code"),
            ("EVENTS_PROBLEM_BIND_HINT_CODE", "bind_hint_code"),
            (
                "EVENTS_PROBLEM_SELECTION_ERROR_CODE",
                "selection_error_code",
            ),
            ("EVENTS_PROBLEM_SELECTION_HINT_CODE", "selection_hint_code"),
            ("EVENTS_PROBLEM_DROP_REASON_CODE", "drop_reason_code"),
            (
                "EVENTS_PROBLEM_CAPTURE_DROP_STAGE",
                "wide_udp_capture_drop_stage",
            ),
            (
                "EVENTS_PROBLEM_CAPTURE_DROP_REASON_CODE",
                "wide_udp_capture_drop_reason_code",
            ),
            (
                "EVENTS_PROBLEM_UDP_CAPTURE_CONTRACT",
                "wide_udp_capture_contract",
            ),
            (
                "EVENTS_PROBLEM_UDP_CAPTURE_SUPPORT_TIER",
                "wide_udp_capture_support_tier",
            ),
            (
                "EVENTS_PROBLEM_UDP_CAPTURE_POLICY",
                "wide_udp_capture_policy",
            ),
            (
                "EVENTS_PROBLEM_UDP_CAPTURE_RUNTIME_SCOPE",
                "wide_udp_capture_runtime_scope",
            ),
            (
                "EVENTS_PROBLEM_UDP_PREVIEW_POLICY",
                "wide_udp_preview_policy",
            ),
            ("EVENTS_PROBLEM_HINT", "hint"),
            ("EVENTS_PROBLEM_TRANSPORT", "transport"),
            ("EVENTS_PROBLEM_RELAY_SERVER", "relay_server"),
            ("EVENTS_PROBLEM_RELAY_ERROR_KIND", "relay_error_kind"),
            ("EVENTS_PROBLEM_SESSION_ERROR_KIND", "session_error_kind"),
            ("EVENTS_PROBLEM_ERROR", "error"),
            ("EVENTS_PROBLEM_BACKEND", "backend"),
            (
                "EVENTS_PROBLEM_RELAY_LAST_TRANSPORT",
                "relay_last_transport",
            ),
            ("EVENTS_PROBLEM_ATTEMPT_INDEX", "attempt_index"),
            ("EVENTS_PROBLEM_ATTEMPTS_TOTAL", "attempts_total"),
            ("EVENTS_PROBLEM_EXPECTED_DNS_PORT", "expected_dns_port"),
            (
                "EVENTS_PROBLEM_EXPECTED_UDP_PREVIEW_PORTS",
                "expected_udp_preview_ports",
            ),
        ] {
            emit_json(key, fields.and_then(|fields| fields.get(field)));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn write_tproxy_operator_evidence(
    output: &Path,
    client_config: Option<&str>,
    runtime_events_jsonl: &str,
    events_total: u64,
    backend: Option<&str>,
    backend_runtime_id: Option<&str>,
    startup_health: &str,
    runtime_status: &str,
    product_verdict: &str,
    runtime_degradation_count: u64,
    failover_count: u64,
    terminal_failure_count: u64,
    latest_code: Option<&str>,
    latest_level: Option<&str>,
    latest_message: Option<&str>,
    problem_code: Option<&str>,
    problem_level: Option<&str>,
    problem_message: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = json!({
        "artifact_schema": "wide_linux_operator_evidence_v1",
        "helper_action": "events",
        "client_config": empty_to_null(client_config),
        "runtime_events_jsonl": runtime_events_jsonl,
        "records_scanned": events_total,
        "backend": empty_to_null(backend),
        "backend_runtime_id": empty_to_null(backend_runtime_id),
        "startup_health": startup_health,
        "runtime_status": runtime_status,
        "product_verdict": product_verdict,
        "runtime_degradation_count": runtime_degradation_count,
        "failover_count": failover_count,
        "terminal_failure_count": terminal_failure_count,
        "latest_event": {
            "code": empty_to_null(latest_code),
            "level": empty_to_null(latest_level),
            "message": empty_to_null(latest_message),
        },
        "latest_problem_event": {
            "code": empty_to_null(problem_code),
            "level": empty_to_null(problem_level),
            "message": empty_to_null(problem_message),
        },
        "canonical_operator_loop": [
            "doctor",
            "probe",
            "launch_or_run",
            "events",
            "evidence",
        ],
    });
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(output, serde_json::to_string_pretty(&payload)? + "\n")?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn write_tproxy_smoke_contract_artifact(
    helper_apply_log: &Path,
    runtime_events_jsonl: &Path,
    output: &Path,
    smoke_protocol: &str,
    ip_family: &str,
    host_shape: &str,
    firewall_backend: &str,
    udp_capture_contract: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let summary_fields = tproxy_apply_summary_fields(helper_apply_log)?;
    let mut records = Vec::new();
    for _ in 0..30 {
        records = if runtime_events_jsonl.exists() {
            read_jsonl_lenient(runtime_events_jsonl)?
        } else {
            Vec::new()
        };
        if records.iter().any(|record| {
            record
                .get("event_code")
                .and_then(Value::as_str)
                .is_some_and(|code| {
                    matches!(
                        code,
                        "ingress_udp_datagram_completed"
                            | "ingress_udp_datagram_dropped"
                            | "direct_session_succeeded"
                            | "relay_transport_failed"
                            | "ingress_session_failed"
                    )
                })
        }) {
            break;
        }
        if records.is_empty() && !runtime_events_jsonl.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    let response_stage = records.iter().rev().find_map(|record| {
        if record.get("event_code").and_then(Value::as_str)
            == Some("ingress_udp_datagram_response_stage")
        {
            record
                .get("fields")
                .and_then(|fields| fields.get("stage"))
                .cloned()
        } else {
            None
        }
    });

    let latest_direct_success = latest_event(&records, "direct_session_succeeded");
    let latest_direct_success_index = latest_event_index(&records, "direct_session_succeeded");
    let latest_completed_index = latest_event_index(&records, "ingress_udp_datagram_completed");
    let latest_transport_failure_index = latest_event_index(&records, "relay_transport_failed");
    let latest_session_failure_index = latest_event_index(&records, "ingress_session_failed");

    let mut runtime_delivery_stage = None;
    let mut runtime_response_action = None;
    let mut runtime_target_host = None;
    let mut runtime_target_port = None;

    for (event_code, stage) in [
        (
            "ingress_udp_datagram_completed",
            "completed_return_delivery_tail",
        ),
        (
            "ingress_udp_datagram_observed",
            "observed_before_response_completion",
        ),
        (
            "ingress_udp_datagram_dropped",
            "dropped_before_response_delivery",
        ),
    ] {
        if let Some(record) = latest_event(&records, event_code) {
            let fields = record.get("fields");
            runtime_delivery_stage = Some(Value::String(stage.to_owned()));
            runtime_response_action = fields
                .and_then(|fields| fields.get("response_action"))
                .cloned();
            runtime_target_host = fields.and_then(|fields| fields.get("target_host")).cloned();
            runtime_target_port = fields.and_then(|fields| fields.get("target_port")).cloned();
            break;
        }
    }

    let transport_failure_is_terminal = latest_transport_failure_index
        .is_some_and(|index| latest_completed_index.is_none_or(|completed| index > completed));
    let session_failure_is_terminal = latest_session_failure_index.is_some_and(|index| {
        latest_completed_index.is_none_or(|completed| index > completed)
            && latest_direct_success_index.is_none_or(|success| index > success)
    });

    let (runtime_health_status, runtime_transport_status) =
        if runtime_delivery_stage.as_ref().and_then(Value::as_str)
            == Some("completed_return_delivery_tail")
        {
            ("healthy", "completed")
        } else if let Some(record) = latest_direct_success {
            let fields = record.get("fields");
            runtime_delivery_stage = Some(Value::String("completed_session_success".to_owned()));
            runtime_response_action = Some(Value::String("stream_response".to_owned()));
            runtime_target_host = fields.and_then(|fields| fields.get("target")).cloned();
            runtime_target_port = fields.and_then(|fields| fields.get("port")).cloned();
            ("healthy", "completed")
        } else if transport_failure_is_terminal {
            ("transport_unhealthy", "terminal_transport_failure")
        } else if session_failure_is_terminal {
            ("session_unhealthy", "terminal_session_failure")
        } else if runtime_delivery_stage.as_ref().and_then(Value::as_str)
            == Some("observed_before_response_completion")
        {
            ("degraded_response_pending", "response_pending")
        } else if runtime_delivery_stage.as_ref().and_then(Value::as_str)
            == Some("dropped_before_response_delivery")
        {
            ("degraded_capture_drop", "capture_rejected")
        } else if records.iter().any(|record| {
            record.get("event_code").and_then(Value::as_str) == Some("ingress_backend_started")
        }) {
            ("startup_only", "not_attempted")
        } else {
            ("", "")
        };

    let smoke_class = match smoke_protocol {
        "http" => "http_tcp",
        "dns" | "dns_ipv6" => "dns_preview",
        "udp_preview" => "udp_preview",
        "udp_preview_drop" => "udp_preview_drop",
        "generic_udp" => "generic_udp",
        _ => "custom",
    };

    let payload = json!({
        "smoke_class": smoke_class,
        "smoke_protocol": smoke_protocol,
        "ip_family": ip_family,
        "host_shape": host_shape,
        "firewall_backend_requested": firewall_backend,
        "firewall_backend_effective": summary_fields.firewall_backend_effective,
        "udp_capture_contract": udp_capture_contract,
        "wide_udp_capture_support_tier": summary_fields.wide_udp_capture_support_tier,
        "wide_udp_capture_policy": summary_fields.wide_udp_capture_policy,
        "wide_udp_capture_runtime_scope": summary_fields.wide_udp_capture_runtime_scope,
        "runtime_delivery_stage": runtime_delivery_stage.unwrap_or(Value::Null),
        "runtime_response_action": runtime_response_action.unwrap_or(Value::Null),
        "runtime_response_stage": response_stage.unwrap_or(Value::Null),
        "runtime_health_status": empty_string_to_null(runtime_health_status),
        "runtime_transport_status": empty_string_to_null(runtime_transport_status),
        "runtime_target_host": runtime_target_host.unwrap_or(Value::Null),
        "runtime_target_port": runtime_target_port.unwrap_or(Value::Null),
    });

    write_smoke_artifact(
        output,
        (serde_json::to_string_pretty(&payload)? + "\n").as_bytes(),
    )?;
    Ok(())
}

pub fn print_tproxy_runtime_delivery_hint(
    runtime_events_jsonl: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let records = read_jsonl_lenient(runtime_events_jsonl)?;
    let response_stage = latest_response_stage(&records);

    if let Some(completed) = latest_event(&records, "ingress_udp_datagram_completed") {
        let fields = completed.get("fields");
        println!("Runtime hint: delivery_stage=completed_return_delivery_tail");
        println!("Runtime hint: ingress completed the UDP datagram, so this failure likely sits on the return-delivery path between host local send and the namespace peer.");
        println!("Runtime hint: check namespace/veth delivery, host firewall return traffic, and whether the smoke host needs a longer request timeout than the current happy-path default.");
        println!(
            "Runtime hint: target={}:{} response_action={} response_stage={}",
            display_field(fields, "target_host"),
            display_field(fields, "target_port"),
            display_field(fields, "response_action"),
            display_value(response_stage.as_ref()),
        );
        println!("Runtime hint: health_status=healthy transport_status=completed");
        return Ok(());
    }

    if let Some(failed_transport) = latest_event(&records, "relay_transport_failed") {
        let fields = failed_transport.get("fields");
        println!(
            "Runtime hint: health_status=transport_unhealthy transport_status=terminal_transport_failure"
        );
        println!("Runtime hint: relay transport failed before the product path reached completion; inspect relay transport choice, relay credentials, and retry/failover policy.");
        println!(
            "Runtime hint: transport={} attempt={}/{} relay_error_kind={}",
            display_field(fields, "transport"),
            display_field(fields, "attempt_index"),
            display_field(fields, "attempts_total"),
            display_field(fields, "relay_error_kind"),
        );
        return Ok(());
    }

    if let Some(observed) = latest_event(&records, "ingress_udp_datagram_observed") {
        let fields = observed.get("fields");
        println!("Runtime hint: delivery_stage=observed_before_response_completion");
        println!("Runtime hint: ingress observed the UDP datagram but did not finish the response path before the smoke timed out.");
        println!("Runtime hint: inspect relay response stages, UDP preview/generic capture policy, and host-local routing before retrying.");
        println!(
            "Runtime hint: target={}:{} match_kind={} response_stage={}",
            display_field(fields, "target_host"),
            display_field(fields, "target_port"),
            display_field(fields, "wide_udp_capture_match_kind"),
            display_value(response_stage.as_ref()),
        );
        println!(
            "Runtime hint: health_status=degraded_response_pending transport_status=response_pending"
        );
    }
    Ok(())
}

pub fn verify_tproxy_generic_udp_runtime_contract(
    runtime_events_jsonl: &Path,
    target_port: u16,
    ip_family: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let records = read_jsonl_strict(runtime_events_jsonl)?;
    let expected_policy = if ip_family == "ipv6" {
        "any_target_port_linux_ipv6_unstable"
    } else {
        "any_target_port_linux_ipv4_unstable"
    };
    let expected_scope = if ip_family == "ipv6" {
        "linux_ipv6_only"
    } else {
        "linux_ipv4_only"
    };

    let backend_started = latest_event(&records, "ingress_backend_started")
        .ok_or("missing ingress_backend_started in runtime JSONL")?;
    let backend_fields = event_fields(backend_started);
    expect_str(
        backend_fields,
        "wide_udp_capture_contract",
        "generic_capture_unstable",
        "unexpected backend contract",
    )?;
    expect_str(
        backend_fields,
        "wide_udp_capture_support_tier",
        "guarded_unstable",
        "unexpected backend support tier",
    )?;
    expect_str(
        backend_fields,
        "wide_udp_capture_policy",
        expected_policy,
        "unexpected backend policy",
    )?;
    expect_str(
        backend_fields,
        "wide_udp_capture_runtime_scope",
        expected_scope,
        "unexpected backend runtime scope",
    )?;
    expect_null(
        backend_fields,
        "wide_udp_preview_policy",
        "unexpected backend preview policy",
    )?;

    for event_code in [
        "ingress_udp_datagram_observed",
        "ingress_udp_datagram_completed",
    ] {
        let record = latest_event_for_port(&records, event_code, target_port)
            .ok_or_else(|| format!("missing {event_code} for target_port={target_port}"))?;
        let fields = event_fields(record);
        expect_str(
            fields,
            "wide_udp_capture_contract",
            "generic_capture_unstable",
            &format!("unexpected {event_code} contract"),
        )?;
        expect_str(
            fields,
            "wide_udp_capture_support_tier",
            "guarded_unstable",
            &format!("unexpected {event_code} support tier"),
        )?;
        expect_str(
            fields,
            "wide_udp_capture_policy",
            expected_policy,
            &format!("unexpected {event_code} policy"),
        )?;
        expect_str(
            fields,
            "wide_udp_capture_runtime_scope",
            expected_scope,
            &format!("unexpected {event_code} runtime scope"),
        )?;
        expect_str(
            fields,
            "wide_udp_capture_match_kind",
            "generic_capture_contract",
            &format!("unexpected {event_code} capture match kind"),
        )?;
        expect_str(
            fields,
            "wide_udp_capture_accept_reason_code",
            "matched_generic_udp_capture_contract",
            &format!("unexpected {event_code} capture accept reason"),
        )?;
        expect_null(
            fields,
            "wide_udp_preview_policy",
            &format!("unexpected {event_code} preview policy"),
        )?;
        expect_null(
            fields,
            "wide_udp_preview_match_kind",
            &format!("unexpected {event_code} preview match kind"),
        )?;
        expect_null(
            fields,
            "wide_udp_preview_accept_reason_code",
            &format!("unexpected {event_code} preview accept reason"),
        )?;
    }
    Ok(())
}

pub fn verify_tproxy_udp_preview_drop_runtime_contract(
    runtime_events_jsonl: &Path,
    target_port: u16,
    dns_port: u16,
    udp_preview_ports: &str,
    ip_family: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let records = read_jsonl_strict(runtime_events_jsonl)?;
    let expected_scope = if ip_family == "ipv6" {
        "linux_ipv6_only"
    } else {
        "linux_ipv4_only"
    };
    let mut preview_ports = vec![u64::from(dns_port)];
    for item in udp_preview_ports
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        preview_ports.push(item.parse::<u64>()?);
    }

    let record = latest_event_for_port(&records, "ingress_udp_datagram_dropped", target_port)
        .ok_or("missing ingress_udp_datagram_dropped for UDP preview drop scenario")?;
    let fields = event_fields(record);
    expect_str(
        fields,
        "wide_udp_capture_contract",
        "preview_allowlist_only",
        "unexpected dropped contract",
    )?;
    expect_str(
        fields,
        "wide_udp_capture_support_tier",
        "supported_preview",
        "unexpected dropped support tier",
    )?;
    expect_str(
        fields,
        "wide_udp_capture_policy",
        "allowlist_ports",
        "unexpected dropped policy",
    )?;
    expect_str(
        fields,
        "wide_udp_capture_runtime_scope",
        expected_scope,
        "unexpected dropped runtime scope",
    )?;
    expect_str(
        fields,
        "wide_udp_capture_drop_stage",
        "capture_policy_gate",
        "unexpected dropped stage",
    )?;
    expect_str(
        fields,
        "wide_udp_capture_drop_reason_code",
        "target_port_outside_capture_policy",
        "unexpected dropped reason",
    )?;
    expect_str(
        fields,
        "wide_udp_preview_policy",
        "allowlist_ports",
        "unexpected preview policy",
    )?;
    expect_u64(
        fields,
        "expected_dns_port",
        u64::from(dns_port),
        "unexpected expected_dns_port",
    )?;
    expect_u64_array(
        fields,
        "expected_udp_preview_ports",
        &preview_ports,
        "unexpected expected_udp_preview_ports",
    )?;
    expect_str(
        fields,
        "drop_reason_code",
        "target_port_not_udp_preview",
        "unexpected drop_reason_code",
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn tproxy_preflight_exit(
    preflight_json: &Path,
    preflight_log: &Path,
    status: i32,
    exit_needs_cap_net_admin: i32,
    exit_listener_conflict: i32,
    exit_listener_busy: i32,
    exit_unsupported_adapter: i32,
    exit_socks_bind_failed: i32,
    exit_rollout_prerequisites: i32,
    expected_interface: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let report = load_json_report(preflight_json, preflight_log)?;
    let selection = report.get("selection").unwrap_or(&Value::Null);
    let checks = report
        .get("runtime_checks")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let codes = checks
        .iter()
        .filter_map(|check| check.get("code").and_then(Value::as_str))
        .collect::<Vec<_>>();
    let backend_notes = selection
        .get("backend_notes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|note| note.get("code").and_then(Value::as_str))
        .collect::<Vec<_>>();
    let configured_interface = selection
        .get("wide_prerouting_interface")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let selection_error_code = selection
        .get("selection_error_code")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let platform_family_supported = selection.get("wide_platform_family_supported");
    let runtime_readiness_value = selection.get("wide_runtime_readiness");
    let runtime_readiness = selection
        .get("wide_runtime_readiness")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let selected_backend = selection.get("selected_backend");

    println!(
        "Preflight backend={} family_supported={} readiness={} codes={}",
        display_value(selected_backend),
        display_value(platform_family_supported),
        display_value(runtime_readiness_value),
        codes.join(","),
    );
    if !backend_notes.is_empty() {
        println!("Preflight backend_notes={}", backend_notes.join(","));
    }
    if !configured_interface.is_empty() {
        println!("Preflight prerouting_interface={configured_interface}");
    }

    let mapped = if status == 0 {
        if configured_interface != expected_interface {
            eprintln!("Preflight failed: config/helper prerouting interface scope mismatch");
            eprintln!(
                "Remediation: keep ingress.wide.prerouting_interface ({configured_interface:?}) aligned with AEGIS_WIDE_INTERFACE ({expected_interface:?})"
            );
            exit_rollout_prerequisites
        } else {
            0
        }
    } else if runtime_readiness == "config_error"
        || selection_error_code == "rollout_profile_prerequisites"
    {
        eprintln!("Preflight failed: rollout profile prerequisites are not satisfied");
        eprintln!("Remediation: keep transparent smoke on platform_backend=linux_tproxy with rollout_profile=transparent_privileged and matching prerouting interface scope");
        exit_rollout_prerequisites
    } else if codes.contains(&"needs_cap_net_admin") {
        eprintln!("Preflight failed: linux_tproxy needs CAP_NET_ADMIN/root for IP_TRANSPARENT");
        eprintln!(
            "Remediation: run the client as root or grant CAP_NET_ADMIN before retrying the smoke"
        );
        exit_needs_cap_net_admin
    } else if codes.contains(&"listener_conflict") {
        eprintln!("Preflight failed: wide.listen conflicts with socks.listen");
        eprintln!("Remediation: choose different AEGIS_WIDE_PORT and AEGIS_SOCKS_PORT values");
        exit_listener_conflict
    } else if codes.contains(&"listener_busy") {
        eprintln!("Preflight failed: requested wide.listen is already busy");
        eprintln!("Remediation: free the requested wide port or set a different AEGIS_WIDE_PORT");
        exit_listener_busy
    } else if codes.contains(&"socks_bind_failed") {
        eprintln!("Preflight failed: SOCKS5 fallback listener could not bind");
        eprintln!("Remediation: choose a different AEGIS_SOCKS_PORT");
        exit_socks_bind_failed
    } else if runtime_readiness == "needs_privilege" {
        eprintln!("Preflight indicates this transparent path needs privilege before startup");
        eprintln!("Remediation: run the client as root or grant CAP_NET_ADMIN so linux_tproxy can set IP_TRANSPARENT before retrying the smoke");
        exit_needs_cap_net_admin
    } else if runtime_readiness == "unsupported_adapter" {
        eprintln!("Preflight failed: selected wide backend has no supported runtime adapter here");
        eprintln!("Remediation: verify the expected Linux transparent path is available on this runner/host before attempting TPROXY smoke");
        exit_unsupported_adapter
    } else {
        eprintln!("Preflight failed; inspect JSON report for details");
        status
    };
    std::process::exit(mapped);
}

#[allow(clippy::too_many_arguments)]
pub fn write_tproxy_contract_self_test_events(
    output: &Path,
    smoke_protocol: &str,
    target_host: &str,
    target_port: u16,
    dns_port: u16,
    udp_preview_ports: &str,
    support_tier: &str,
    capture_policy: &str,
    runtime_scope: &str,
    preview_policy: Option<&str>,
    variant: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let contract = if smoke_protocol == "generic_udp" {
        "generic_capture_unstable"
    } else {
        "preview_allowlist_only"
    };
    let preview_policy_value = empty_to_null(preview_policy);
    let mut records = vec![json!({
        "ts_unix_ms": 1,
        "level": "info",
        "event_code": "ingress_backend_started",
        "message": "client ingress backend started",
        "fields": {
            "backend": "wide_primary",
            "wide_udp_capture_contract": contract,
            "wide_udp_capture_support_tier": support_tier,
            "wide_udp_capture_policy": capture_policy,
            "wide_udp_capture_runtime_scope": runtime_scope,
            "wide_udp_preview_policy": preview_policy_value,
        },
    })];

    match (smoke_protocol, variant.unwrap_or_default()) {
        ("http", _) => records.push(json!({
            "ts_unix_ms": 2,
            "level": "info",
            "event_code": "direct_session_succeeded",
            "message": "direct session succeeded",
            "fields": {
                "target": "example.com",
                "port": 80,
                "strategy": "passthrough",
                "signal": "Success",
                "probe_outcome_class": "success",
                "cross_session_reuse_weight": 0.55,
            },
        })),
        ("generic_udp", "transport_failure") => {
            records.push(generic_udp_observed_record(
                2,
                target_host,
                target_port,
                contract,
                support_tier,
                capture_policy,
                runtime_scope,
            ));
            records.push(json!({
                "ts_unix_ms": 3,
                "level": "warn",
                "event_code": "relay_transport_failed",
                "message": "relay transport failed",
                "fields": {
                    "transport": "MasqueDerived",
                    "target": target_host,
                    "port": target_port,
                    "relay_server": "127.0.0.1:8443",
                    "relay_server_name": "localhost",
                    "attempt_index": 1,
                    "attempts_total": 1,
                    "planned_transports": ["MasqueDerived"],
                    "relay_error_kind": "connection_refused",
                    "error": "connection refused",
                },
            }));
            records.push(json!({
                "ts_unix_ms": 4,
                "level": "error",
                "event_code": "ingress_session_failed",
                "message": "ingress session failed",
                "fields": {
                    "backend": "wide_primary",
                    "backend_runtime_id": "wide_primary_linux",
                    "backend_kind": "WidePrimary",
                    "backend_kind_code": "wide_primary",
                    "requested_primary": "Wide",
                    "requested_primary_code": "wide",
                    "mode": "Relay",
                    "mode_code": "relay",
                    "wide_supported": true,
                    "wide_platform_family_supported": true,
                    "wide_runtime_readiness": "ready",
                    "rollout_profile": "TransparentPrivileged",
                    "rollout_profile_code": "transparent_privileged",
                    "prerouting_interface": "aegisvh1",
                    "startup_path_code": "wide_primary_started",
                    "relay_terminal": true,
                    "relay_target": target_host,
                    "relay_port": target_port,
                    "relay_server": "127.0.0.1:8443",
                    "relay_server_name": "localhost",
                    "relay_attempts_total": 1,
                    "relay_planned_transports": ["MasqueDerived"],
                    "relay_last_transport": "MasqueDerived",
                    "session_error_kind": "connection_refused",
                    "error": "relay terminal failure",
                },
            }));
        }
        ("generic_udp", "transport_recovered") => {
            records.push(generic_udp_observed_record(
                2,
                target_host,
                target_port,
                contract,
                support_tier,
                capture_policy,
                runtime_scope,
            ));
            records.push(json!({
                "ts_unix_ms": 3,
                "level": "warn",
                "event_code": "relay_transport_failed",
                "message": "relay transport failed",
                "fields": {
                    "transport": "MasqueDerived",
                    "target": target_host,
                    "port": target_port,
                    "relay_server": "127.0.0.1:8443",
                    "relay_server_name": "localhost",
                    "attempt_index": 1,
                    "attempts_total": 2,
                    "planned_transports": ["MasqueDerived", "MasqueDerived"],
                    "relay_error_kind": "timed_out",
                    "error": "timed out",
                },
            }));
            records.push(generic_udp_response_stage_record(
                4,
                target_host,
                target_port,
                "local_udp_send_done",
                contract,
                support_tier,
                capture_policy,
                runtime_scope,
            ));
            records.push(generic_udp_completed_record(
                5,
                target_host,
                target_port,
                contract,
                support_tier,
                capture_policy,
                runtime_scope,
            ));
        }
        ("generic_udp", _) => {
            records.push(generic_udp_observed_record(
                2,
                target_host,
                target_port,
                contract,
                support_tier,
                capture_policy,
                runtime_scope,
            ));
            records.push(generic_udp_response_stage_record(
                3,
                target_host,
                target_port,
                "local_udp_send_start",
                contract,
                support_tier,
                capture_policy,
                runtime_scope,
            ));
            records.push(generic_udp_response_stage_record(
                4,
                target_host,
                target_port,
                "local_udp_send_done",
                contract,
                support_tier,
                capture_policy,
                runtime_scope,
            ));
            records.push(generic_udp_completed_record(
                5,
                target_host,
                target_port,
                contract,
                support_tier,
                capture_policy,
                runtime_scope,
            ));
        }
        ("udp_preview_drop", _) => {
            let mut preview_ports = vec![u64::from(dns_port)];
            for item in udp_preview_ports
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
            {
                preview_ports.push(item.parse::<u64>()?);
            }
            records.push(json!({
                "ts_unix_ms": 2,
                "level": "warn",
                "event_code": "ingress_udp_datagram_dropped",
                "message": "udp preview drop",
                "fields": {
                    "target_host": target_host,
                    "target_port": target_port,
                    "wide_udp_capture_contract": contract,
                    "wide_udp_capture_support_tier": support_tier,
                    "wide_udp_capture_policy": capture_policy,
                    "wide_udp_capture_runtime_scope": runtime_scope,
                    "wide_udp_capture_drop_stage": "capture_policy_gate",
                    "wide_udp_capture_drop_reason_code": "target_port_outside_capture_policy",
                    "wide_udp_preview_policy": "allowlist_ports",
                    "expected_dns_port": dns_port,
                    "expected_udp_preview_ports": preview_ports,
                    "drop_reason_code": "target_port_not_udp_preview",
                },
            }));
        }
        _ => {}
    }

    let mut payload = String::new();
    for record in records {
        payload.push_str(&serde_json::to_string(&record)?);
        payload.push('\n');
    }
    std::fs::write(output, payload)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn verify_tproxy_smoke_contract_self_test(
    contract_artifact: &Path,
    runtime_events_jsonl: &Path,
    smoke_protocol: &str,
    ip_family: &str,
    firewall_backend_requested: &str,
    expected_effective: &str,
    expected_tier: &str,
    expected_policy: &str,
    expected_scope: &str,
    target_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let contract = read_json_object(contract_artifact)?;
    let records = read_jsonl_strict(runtime_events_jsonl)?;

    expect_top_str(
        &contract,
        "smoke_protocol",
        smoke_protocol,
        "unexpected smoke_protocol",
    )?;
    expect_top_str(&contract, "ip_family", ip_family, "unexpected ip_family")?;
    expect_top_str(
        &contract,
        "host_shape",
        "github_hosted",
        "unexpected host_shape",
    )?;
    expect_top_str(
        &contract,
        "firewall_backend_requested",
        firewall_backend_requested,
        "unexpected firewall_backend_requested",
    )?;
    expect_top_str(
        &contract,
        "firewall_backend_effective",
        expected_effective,
        "unexpected firewall_backend_effective",
    )?;
    expect_top_str(
        &contract,
        "wide_udp_capture_support_tier",
        expected_tier,
        "unexpected wide_udp_capture_support_tier",
    )?;
    expect_top_str(
        &contract,
        "wide_udp_capture_policy",
        expected_policy,
        "unexpected wide_udp_capture_policy",
    )?;
    expect_top_str(
        &contract,
        "wide_udp_capture_runtime_scope",
        expected_scope,
        "unexpected wide_udp_capture_runtime_scope",
    )?;

    let backend_started = latest_event(&records, "ingress_backend_started")
        .ok_or("missing ingress_backend_started in runtime JSONL")?;
    let fields = event_fields(backend_started);
    let expected_contract = if smoke_protocol == "generic_udp" {
        "generic_capture_unstable"
    } else {
        "preview_allowlist_only"
    };
    expect_str(
        fields,
        "wide_udp_capture_contract",
        expected_contract,
        "unexpected backend contract",
    )?;
    expect_str(
        fields,
        "wide_udp_capture_support_tier",
        expected_tier,
        "unexpected backend support tier",
    )?;
    expect_str(
        fields,
        "wide_udp_capture_policy",
        expected_policy,
        "unexpected backend policy",
    )?;
    expect_str(
        fields,
        "wide_udp_capture_runtime_scope",
        expected_scope,
        "unexpected backend runtime scope",
    )?;

    match smoke_protocol {
        "generic_udp" => {
            verify_tproxy_smoke_generic_udp_self_test(&contract, &records, target_port)
        }
        "http" => verify_tproxy_smoke_http_self_test(&contract, &records),
        "udp_preview_drop" => {
            verify_tproxy_smoke_udp_preview_drop_self_test(&contract, &records, target_port)
        }
        _ => Ok(()),
    }
}

pub fn verify_tproxy_transport_failure_self_test(
    contract_artifact: &Path,
    runtime_events_jsonl: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let contract = read_json_object(contract_artifact)?;
    let records = read_jsonl_strict(runtime_events_jsonl)?;

    expect_top_str(
        &contract,
        "smoke_protocol",
        "generic_udp",
        "unexpected smoke_protocol",
    )?;
    expect_top_str(
        &contract,
        "runtime_delivery_stage",
        "observed_before_response_completion",
        "unexpected delivery stage",
    )?;
    expect_top_str(
        &contract,
        "runtime_health_status",
        "transport_unhealthy",
        "unexpected health status",
    )?;
    expect_top_str(
        &contract,
        "runtime_transport_status",
        "terminal_transport_failure",
        "unexpected transport status",
    )?;
    expect_top_null(
        &contract,
        "runtime_response_stage",
        "unexpected response stage",
    )?;

    let relay_failed =
        latest_event(&records, "relay_transport_failed").ok_or("missing relay_transport_failed")?;
    expect_str(
        event_fields(relay_failed),
        "relay_error_kind",
        "connection_refused",
        "unexpected relay_error_kind",
    )?;

    let session_failed =
        latest_event(&records, "ingress_session_failed").ok_or("missing ingress_session_failed")?;
    expect_bool(
        event_fields(session_failed),
        "relay_terminal",
        true,
        "unexpected relay_terminal",
    )?;
    expect_str(
        event_fields(session_failed),
        "relay_last_transport",
        "MasqueDerived",
        "unexpected relay_last_transport",
    )?;
    Ok(())
}

pub fn verify_tproxy_transport_recovered_self_test(
    contract_artifact: &Path,
    runtime_events_jsonl: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let contract = read_json_object(contract_artifact)?;
    let records = read_jsonl_strict(runtime_events_jsonl)?;

    expect_top_str(
        &contract,
        "smoke_protocol",
        "generic_udp",
        "unexpected smoke_protocol",
    )?;
    expect_top_str(
        &contract,
        "runtime_delivery_stage",
        "completed_return_delivery_tail",
        "unexpected delivery stage",
    )?;
    expect_top_str(
        &contract,
        "runtime_health_status",
        "healthy",
        "unexpected health status",
    )?;
    expect_top_str(
        &contract,
        "runtime_transport_status",
        "completed",
        "unexpected transport status",
    )?;
    expect_top_str(
        &contract,
        "runtime_response_stage",
        "local_udp_send_done",
        "unexpected response stage",
    )?;

    let relay_failed =
        latest_event(&records, "relay_transport_failed").ok_or("missing relay_transport_failed")?;
    expect_u64(
        event_fields(relay_failed),
        "attempts_total",
        2,
        "unexpected attempts_total",
    )?;

    latest_event_for_port(&records, "ingress_udp_datagram_completed", 54321)
        .ok_or("missing ingress_udp_datagram_completed for port 54321")?;
    Ok(())
}

pub fn verify_tproxy_loopback_idempotent_log(
    ip_log: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let lines = std::fs::read_to_string(ip_log)?
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let expected_prefix = [
        "addr del 198.18.0.53/32 dev lo",
        "addr add 198.18.0.53/32 dev lo",
        "addr del 198.18.0.53/32 dev lo",
        "addr add 198.18.0.53/32 dev lo",
    ];
    if lines.len() < expected_prefix.len() {
        return Err(format!("ip log too short: {lines:?}").into());
    }
    for (actual, expected) in lines.iter().zip(expected_prefix) {
        if actual != expected {
            return Err(format!("unexpected ip log prefix: {lines:?}").into());
        }
    }
    let add_count = lines
        .iter()
        .filter(|line| line.as_str() == "addr add 198.18.0.53/32 dev lo")
        .count();
    let del_count = lines
        .iter()
        .filter(|line| line.as_str() == "addr del 198.18.0.53/32 dev lo")
        .count();
    if add_count != 2 || del_count < 2 {
        return Err(format!("unexpected loopback add/del counts: {lines:?}").into());
    }
    Ok(())
}

pub fn validate_rich_host_bootstrap(
    artifact: &Path,
    bootstrap_status: i32,
) -> Result<(), Box<dyn std::error::Error>> {
    let default_remediation = "bash scripts/bootstrap-wide-linux-validation-host.sh --install";
    let mut error_code = None;
    let raw_text = std::fs::read_to_string(artifact).unwrap_or_default();
    let parsed = if raw_text.trim().is_empty() {
        error_code = Some("bootstrap_helper_missing_json");
        None
    } else {
        match serde_json::from_str::<Value>(raw_text.trim()) {
            Ok(Value::Object(map)) => Some(Value::Object(map)),
            Ok(_) => {
                error_code = Some("bootstrap_helper_non_object_json");
                None
            }
            Err(_) => {
                error_code = Some("bootstrap_helper_invalid_json");
                None
            }
        }
    };

    let mut payload = parsed.unwrap_or_else(|| {
        json!({
            "artifact_schema": "wide_linux_validation_host_bootstrap_v1",
            "mode": "check",
            "os_pretty_name": null,
            "os_id": null,
            "os_version_id": null,
            "package_manager": null,
            "supported_product_contour": "linux_first_local_binary_operator",
            "supported_operator_scope": "supported_linux_tproxy_operator_path",
            "host_family_id": "unknown-linux",
            "host_family_validation_tier": "manual_only",
            "install_rustup": true,
            "ready": false,
            "commands": [],
            "missing_commands": [],
            "sudo": {
                "status": "unknown",
                "detail": "bootstrap helper did not return a valid JSON readiness report",
            },
            "remediation_command": default_remediation,
            "bootstrap_check_command": "bash scripts/bootstrap-wide-linux-validation-host.sh --check",
            "bootstrap_install_command": default_remediation,
            "validation_command": "sudo env HOME=\"$HOME\" PATH=\"$HOME/.cargo/bin:$PATH\" bash scripts/validate-wide-linux-tproxy-rich-host.sh",
            "upgrade_reapply_command": "bash scripts/bootstrap-wide-linux-validation-host.sh --install && sudo env HOME=\"$HOME\" PATH=\"$HOME/.cargo/bin:$PATH\" bash scripts/validate-wide-linux-tproxy-rich-host.sh",
            "error_code": error_code,
            "helper_exit_code": bootstrap_status,
        })
    });

    set_default(
        &mut payload,
        "artifact_schema",
        json!("wide_linux_validation_host_bootstrap_v1"),
    );
    set_default(&mut payload, "mode", json!("check"));
    set_default(&mut payload, "os_pretty_name", Value::Null);
    set_default(&mut payload, "os_id", Value::Null);
    set_default(&mut payload, "os_version_id", Value::Null);
    set_default(&mut payload, "package_manager", Value::Null);
    set_default(
        &mut payload,
        "supported_product_contour",
        json!("linux_first_local_binary_operator"),
    );
    set_default(
        &mut payload,
        "supported_operator_scope",
        json!("supported_linux_tproxy_operator_path"),
    );
    set_default(&mut payload, "host_family_id", json!("unknown-linux"));
    set_default(
        &mut payload,
        "host_family_validation_tier",
        json!("manual_only"),
    );
    set_default(&mut payload, "install_rustup", json!(true));
    set_default(&mut payload, "commands", json!([]));
    set_default(&mut payload, "missing_commands", json!([]));
    set_default(
        &mut payload,
        "sudo",
        json!({"status": "unknown", "detail": ""}),
    );
    set_default(
        &mut payload,
        "remediation_command",
        json!(default_remediation),
    );
    set_default(
        &mut payload,
        "bootstrap_check_command",
        json!("bash scripts/bootstrap-wide-linux-validation-host.sh --check"),
    );
    set_default(
        &mut payload,
        "bootstrap_install_command",
        json!(default_remediation),
    );
    set_default(
        &mut payload,
        "validation_command",
        json!("sudo env HOME=\"$HOME\" PATH=\"$HOME/.cargo/bin:$PATH\" bash scripts/validate-wide-linux-tproxy-rich-host.sh"),
    );
    set_default(
        &mut payload,
        "upgrade_reapply_command",
        json!("bash scripts/bootstrap-wide-linux-validation-host.sh --install && sudo env HOME=\"$HOME\" PATH=\"$HOME/.cargo/bin:$PATH\" bash scripts/validate-wide-linux-tproxy-rich-host.sh"),
    );
    set_value(&mut payload, "helper_exit_code", json!(bootstrap_status));

    if bootstrap_status == 0 && payload.get("ready").and_then(Value::as_bool) != Some(true) {
        set_value(&mut payload, "ready", json!(false));
        set_default(
            &mut payload,
            "error_code",
            json!("bootstrap_helper_inconsistent_ready_state"),
        );
    } else if bootstrap_status != 0 {
        set_value(&mut payload, "ready", json!(false));
    }

    std::fs::write(artifact, serde_json::to_string_pretty(&payload)? + "\n")?;
    if bootstrap_status == 0 && payload.get("ready").and_then(Value::as_bool) == Some(true) {
        return Ok(());
    }

    let missing = payload
        .get("missing_commands")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    let missing_text = if missing.is_empty() {
        payload
            .get("error_code")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned()
    } else {
        missing.join(" ")
    };
    eprintln!("Missing richer-host validation prerequisites: {missing_text}");
    eprintln!(
        "Remediation: {}",
        payload
            .get("remediation_command")
            .and_then(Value::as_str)
            .unwrap_or(default_remediation)
    );
    std::process::exit(1);
}

pub struct WideLinuxValidationHostBootstrapReportInputs<'a> {
    pub mode: &'a str,
    pub os_pretty_name: &'a str,
    pub os_id: &'a str,
    pub os_version_id: Option<&'a str>,
    pub package_manager: Option<&'a str>,
    pub supported_product_contour: &'a str,
    pub supported_operator_scope: &'a str,
    pub host_family_id: &'a str,
    pub host_family_validation_tier: &'a str,
    pub install_rustup: bool,
    pub ready: bool,
    pub command: &'a [String],
    pub missing_command: &'a [String],
    pub sudo_status: &'a str,
    pub sudo_detail: &'a str,
    pub remediation_command: &'a str,
    pub bootstrap_check_command: &'a str,
    pub bootstrap_install_command: &'a str,
    pub validation_command: &'a str,
    pub upgrade_reapply_command: &'a str,
    pub helper_exit_code: Option<i32>,
    pub error_code: Option<&'a str>,
}

pub fn build_wide_linux_validation_host_bootstrap_report(
    inputs: WideLinuxValidationHostBootstrapReportInputs<'_>,
) -> Result<Value, Box<dyn std::error::Error>> {
    let commands = inputs
        .command
        .iter()
        .map(|entry| parse_bootstrap_command_entry(entry))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(json!({
        "artifact_schema": "wide_linux_validation_host_bootstrap_v1",
        "mode": inputs.mode,
        "os_pretty_name": inputs.os_pretty_name,
        "os_id": inputs.os_id,
        "os_version_id": non_empty_or_null(inputs.os_version_id),
        "package_manager": non_empty_or_null(inputs.package_manager),
        "supported_product_contour": inputs.supported_product_contour,
        "supported_operator_scope": inputs.supported_operator_scope,
        "host_family_id": inputs.host_family_id,
        "host_family_validation_tier": inputs.host_family_validation_tier,
        "install_rustup": inputs.install_rustup,
        "ready": inputs.ready,
        "commands": commands,
        "missing_commands": inputs.missing_command,
        "sudo": {
            "status": inputs.sudo_status,
            "detail": inputs.sudo_detail,
        },
        "remediation_command": inputs.remediation_command,
        "bootstrap_check_command": inputs.bootstrap_check_command,
        "bootstrap_install_command": inputs.bootstrap_install_command,
        "validation_command": inputs.validation_command,
        "upgrade_reapply_command": inputs.upgrade_reapply_command,
        "helper_exit_code": inputs.helper_exit_code,
        "error_code": non_empty_or_null(inputs.error_code),
    }))
}

#[allow(clippy::too_many_arguments)]
pub fn check_wide_linux_validation_host_bootstrap_contract_case(
    case_id: &str,
    output_json: &Path,
    status: i32,
    command_log: Option<&Path>,
    expected_cargo: Option<&str>,
    package_manager: Option<&str>,
    command_snippet: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = read_json_object(output_json)?;
    match case_id {
        "json_missing_cargo" => {
            expect_top_bool(&payload, "ready", false, "unexpected ready")?;
            expect_top_string_array(
                &payload,
                "missing_commands",
                &["cargo"],
                "unexpected missing",
            )?;
            expect_top_error_code_none(&payload)?;
            expect_top_i64(
                &payload,
                "helper_exit_code",
                i64::from(status),
                "unexpected exit",
            )?;
            expect_status(status, 1)?;
            expect_command(
                &payload,
                "cargo",
                Some("missing"),
                None,
                "missing cargo command",
            )?;
            expect_command(
                &payload,
                "cargo",
                None,
                Some("required for richer-host validation"),
                "missing cargo detail",
            )?;
            expect_top_str_ends_with(
                &payload,
                "remediation_command",
                "--install",
                "bad remediation",
            )?;
        }
        "json_check_missing_sudo" => {
            expect_top_bool(&payload, "ready", false, "unexpected ready")?;
            expect_top_string_array(
                &payload,
                "missing_commands",
                &["sudo"],
                "unexpected missing",
            )?;
            expect_top_error_code_none(&payload)?;
            expect_top_i64(&payload, "helper_exit_code", 1, "unexpected exit")?;
            expect_status(status, 1)?;
            expect_sudo(&payload, "status", "missing")?;
            expect_sudo(
                &payload,
                "detail",
                "required unless validation runs as root",
            )?;
            expect_command(
                &payload,
                "sudo",
                Some("missing"),
                None,
                "missing sudo command",
            )?;
        }
        "install_skip_rustup_missing_cargo" => {
            expect_top_bool(&payload, "ready", false, "unexpected ready")?;
            expect_top_str(
                &payload,
                "error_code",
                "cargo_missing_skip_rustup",
                "bad error",
            )?;
            expect_top_i64(&payload, "helper_exit_code", 1, "unexpected exit")?;
            expect_status(status, 1)?;
            expect_top_str_ends_with(
                &payload,
                "remediation_command",
                "--install",
                "bad remediation",
            )?;
        }
        "json" => {
            expect_top_str(
                &payload,
                "artifact_schema",
                "wide_linux_validation_host_bootstrap_v1",
                "bad schema",
            )?;
            expect_top_str(&payload, "mode", "check", "bad mode")?;
            expect_top_non_empty_str(&payload, "os_pretty_name", "missing os")?;
            expect_top_bool(&payload, "ready", true, "unexpected ready")?;
            expect_top_i64(&payload, "helper_exit_code", 0, "unexpected exit")?;
            expect_status(status, 0)?;
            expect_top_null(&payload, "package_manager", "unexpected package manager")?;
            expect_top_string_array(&payload, "missing_commands", &[], "unexpected missing")?;
            expect_command(&payload, "cargo", Some("ok"), None, "missing cargo ok")?;
            expect_sudo(&payload, "status", "ok")?;
            expect_top_str_ends_with(
                &payload,
                "remediation_command",
                "--install",
                "bad remediation",
            )?;
        }
        "json_cargo_in_home_bin" => {
            expect_status(status, 0)?;
            expect_top_bool(&payload, "ready", true, "unexpected ready")?;
            expect_top_string_array(&payload, "missing_commands", &[], "unexpected missing")?;
            expect_command(
                &payload,
                "cargo",
                Some("ok"),
                expected_cargo,
                "missing cargo home-bin detail",
            )?;
            expect_top_i64(&payload, "helper_exit_code", 0, "unexpected exit")?;
        }
        "json_interactive_sudo_warning" => {
            expect_top_bool(&payload, "ready", true, "unexpected ready")?;
            expect_top_string_array(&payload, "missing_commands", &[], "unexpected missing")?;
            expect_top_error_code_none(&payload)?;
            expect_top_i64(&payload, "helper_exit_code", 0, "unexpected exit")?;
            expect_status(status, 0)?;
            expect_sudo(&payload, "status", "warn")?;
            expect_sudo(
                &payload,
                "detail",
                "interactive sudo required; validation can still run from a root shell",
            )?;
            expect_command(&payload, "sudo -n", Some("warn"), None, "missing sudo warn")?;
        }
        "json_unsupported_platform" => {
            expect_top_bool(&payload, "ready", false, "unexpected ready")?;
            expect_top_str(&payload, "error_code", "unsupported_platform", "bad error")?;
            expect_top_i64(&payload, "helper_exit_code", 1, "unexpected exit")?;
            expect_status(status, 1)?;
            expect_top_str_ends_with(
                &payload,
                "remediation_command",
                "--install",
                "bad remediation",
            )?;
        }
        "json_unknown_argument" | "json_unknown_argument_before_json" => {
            expect_top_bool(&payload, "ready", false, "unexpected ready")?;
            expect_top_str(&payload, "error_code", "unknown_argument", "bad error")?;
            expect_top_i64(&payload, "helper_exit_code", 1, "unexpected exit")?;
            expect_status(status, 1)?;
            expect_sudo(&payload, "status", "unknown")?;
            expect_sudo_detail_contains(&payload, "Unknown argument: --bogus")?;
        }
        "install_unsupported_package_manager" => {
            expect_top_bool(&payload, "ready", false, "unexpected ready")?;
            expect_top_str(
                &payload,
                "error_code",
                "unsupported_package_manager",
                "bad error",
            )?;
            expect_top_i64(&payload, "helper_exit_code", 1, "unexpected exit")?;
            expect_status(status, 1)?;
            expect_top_null(&payload, "package_manager", "unexpected package manager")?;
            expect_top_str_ends_with(
                &payload,
                "remediation_command",
                "--install",
                "bad remediation",
            )?;
        }
        "install_missing_curl" => {
            expect_top_bool(&payload, "ready", false, "unexpected ready")?;
            expect_top_str(
                &payload,
                "error_code",
                "curl_missing_for_rustup",
                "bad error",
            )?;
            expect_top_i64(&payload, "helper_exit_code", 1, "unexpected exit")?;
            expect_status(status, 1)?;
            expect_top_str(
                &payload,
                "package_manager",
                "apt-get",
                "bad package manager",
            )?;
        }
        "install_missing_sudo" => {
            expect_top_bool(&payload, "ready", false, "unexpected ready")?;
            expect_top_str(
                &payload,
                "error_code",
                "sudo_missing_for_install",
                "bad error",
            )?;
            expect_top_i64(&payload, "helper_exit_code", 1, "unexpected exit")?;
            expect_status(status, 1)?;
            expect_sudo(&payload, "status", "missing")?;
            expect_top_str(
                &payload,
                "package_manager",
                "apt-get",
                "bad package manager",
            )?;
        }
        "install_package_update_failed" => {
            expect_top_bool(&payload, "ready", false, "unexpected ready")?;
            expect_top_str(
                &payload,
                "error_code",
                "os_package_update_failed",
                "bad error",
            )?;
            expect_top_i64(&payload, "helper_exit_code", 33, "unexpected exit")?;
            expect_status(status, 33)?;
            expect_top_str(
                &payload,
                "package_manager",
                "apt-get",
                "bad package manager",
            )?;
            expect_top_str_ends_with(
                &payload,
                "remediation_command",
                "--install",
                "bad remediation",
            )?;
        }
        "install_package_install_failed" => {
            expect_top_bool(&payload, "ready", false, "unexpected ready")?;
            expect_top_str(
                &payload,
                "error_code",
                "os_package_install_failed",
                "bad error",
            )?;
            expect_top_i64(&payload, "helper_exit_code", 42, "unexpected exit")?;
            expect_status(status, 42)?;
            expect_top_str(
                &payload,
                "package_manager",
                "apt-get",
                "bad package manager",
            )?;
            expect_top_str_ends_with(
                &payload,
                "remediation_command",
                "--install",
                "bad remediation",
            )?;
        }
        "install_rustup_download_failed" => {
            expect_top_bool(&payload, "ready", false, "unexpected ready")?;
            expect_top_str(
                &payload,
                "error_code",
                "rustup_download_failed",
                "bad error",
            )?;
            expect_top_i64(&payload, "helper_exit_code", 17, "unexpected exit")?;
            expect_status(status, 17)?;
            expect_top_str(
                &payload,
                "package_manager",
                "apt-get",
                "bad package manager",
            )?;
            expect_top_str_ends_with(
                &payload,
                "remediation_command",
                "--install",
                "bad remediation",
            )?;
        }
        "install_rustup_install_failed" => {
            expect_top_bool(&payload, "ready", false, "unexpected ready")?;
            expect_top_str(&payload, "error_code", "rustup_install_failed", "bad error")?;
            expect_top_i64(&payload, "helper_exit_code", 9, "unexpected exit")?;
            expect_status(status, 9)?;
            expect_top_str(
                &payload,
                "package_manager",
                "apt-get",
                "bad package manager",
            )?;
            expect_top_str_ends_with(
                &payload,
                "remediation_command",
                "--install",
                "bad remediation",
            )?;
        }
        "install_happy" | "install_alt_package_manager_happy" | "install_skip_rustup_happy" => {
            let expected_package = package_manager.unwrap_or("apt-get");
            expect_top_str(
                &payload,
                "artifact_schema",
                "wide_linux_validation_host_bootstrap_v1",
                "bad schema",
            )?;
            expect_top_str(&payload, "mode", "install", "bad mode")?;
            expect_top_non_empty_str(&payload, "os_pretty_name", "missing os")?;
            expect_top_bool(&payload, "ready", true, "unexpected ready")?;
            expect_top_i64(&payload, "helper_exit_code", 0, "unexpected exit")?;
            expect_status(status, 0)?;
            expect_top_str(
                &payload,
                "package_manager",
                expected_package,
                "bad package manager",
            )?;
            expect_top_bool(
                &payload,
                "install_rustup",
                case_id != "install_skip_rustup_happy",
                "unexpected rustup flag",
            )?;
            expect_top_string_array(&payload, "missing_commands", &[], "unexpected missing")?;
            expect_top_error_code_none(&payload)?;
            expect_sudo(&payload, "status", "ok")?;
            expect_command(&payload, "cargo", Some("ok"), None, "missing cargo ok")?;
            if case_id == "install_happy" {
                expect_top_non_empty_str(&payload, "os_id", "missing os id")?;
                expect_top_str_or_null(&payload, "os_version_id", "bad os version")?;
                expect_top_non_empty_str(&payload, "host_family_id", "missing host family")?;
                expect_top_non_empty_str(
                    &payload,
                    "host_family_validation_tier",
                    "missing validation tier",
                )?;
                expect_top_non_empty_str(
                    &payload,
                    "supported_product_contour",
                    "missing product contour",
                )?;
                expect_top_non_empty_str(
                    &payload,
                    "supported_operator_scope",
                    "missing operator scope",
                )?;
                expect_top_non_empty_str(
                    &payload,
                    "bootstrap_check_command",
                    "missing check command",
                )?;
                expect_top_non_empty_str(
                    &payload,
                    "bootstrap_install_command",
                    "missing install command",
                )?;
                expect_top_non_empty_str(&payload, "validation_command", "missing validation")?;
                expect_top_non_empty_str(
                    &payload,
                    "upgrade_reapply_command",
                    "missing upgrade command",
                )?;
            }
            let log = command_log
                .map(std::fs::read_to_string)
                .transpose()?
                .unwrap_or_default();
            if let Some(snippet) = command_snippet {
                expect_contains(&log, snippet, "missing package-manager command")?;
            } else {
                expect_contains(&log, "apt-get update", "missing apt update")?;
                expect_contains(
                    &log,
                    "apt-get install -y --no-install-recommends",
                    "missing apt install",
                )?;
            }
        }
        other => return Err(format!("unknown bootstrap contract case: {other}").into()),
    }
    Ok(())
}

pub fn check_wide_linux_validation_host_bootstrap_coverage(
    repo_root: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let helper =
        std::fs::read_to_string(repo_root.join("scripts/bootstrap-wide-linux-validation-host.sh"))?;
    let rust_helper =
        std::fs::read_to_string(repo_root.join("tools/measure/src/wide_tproxy_helper.rs"))?;
    let contract = std::fs::read_to_string(
        repo_root.join("scripts/test-bootstrap-wide-linux-validation-host-contract.sh"),
    )?;

    let mut helper_codes = collect_between(&helper, "fail_helper \"", "\"");
    helper_codes.extend(collect_between(&helper, "run_checked_command \"", "\""));
    helper_codes.retain(|code| !code.contains('$'));
    expect_all_text_present("helper_codes", &helper_codes, &[&rust_helper, &contract])?;

    let helper_sudo_statuses = collect_between(&helper, "SUDO_STATUS=\"", "\"");
    expect_all_text_present(
        "helper_sudo_statuses",
        &helper_sudo_statuses,
        &[&rust_helper, &contract],
    )?;

    let mut helper_command_statuses = collect_between(&helper, "record_command_status \"", "\"")
        .into_iter()
        .filter_map(|entry| {
            helper
                .split(&format!("record_command_status \"{entry}\" \""))
                .nth(1)
                .and_then(|tail| tail.split('"').next())
                .map(str::to_owned)
        })
        .collect::<BTreeSet<_>>();
    helper_command_statuses.extend(
        helper_sudo_statuses
            .iter()
            .filter(|status| status.as_str() != "unknown")
            .cloned(),
    );
    helper_command_statuses.retain(|status| !status.contains('$'));
    expect_all_text_present(
        "helper_command_statuses",
        &helper_command_statuses,
        &[&rust_helper, &contract],
    )?;

    let helper_package_managers = helper
        .split_once("for candidate in ")
        .and_then(|(_, tail)| tail.split_once("; do"))
        .map(|(items, _)| {
            items
                .split_whitespace()
                .map(str::to_owned)
                .collect::<BTreeSet<_>>()
        })
        .ok_or("missing package manager candidate loop")?;
    expect_all_text_present(
        "helper_package_managers",
        &helper_package_managers,
        &[&rust_helper, &contract],
    )?;

    for key in [
        "artifact_schema",
        "bootstrap_check_command",
        "bootstrap_install_command",
        "commands",
        "error_code",
        "helper_exit_code",
        "host_family_id",
        "host_family_validation_tier",
        "install_rustup",
        "missing_commands",
        "mode",
        "os_id",
        "os_pretty_name",
        "os_version_id",
        "package_manager",
        "ready",
        "remediation_command",
        "sudo",
        "supported_operator_scope",
        "supported_product_contour",
        "upgrade_reapply_command",
        "validation_command",
    ] {
        if !rust_helper.contains(&format!("\"{key}\"")) && !contract.contains(&format!("\"{key}\""))
        {
            return Err(format!("missing bootstrap top-level key coverage: {key}").into());
        }
    }

    for key in ["status", "detail"] {
        if !rust_helper.contains(&format!("\"{key}\"")) && !contract.contains(&format!("\"{key}\""))
        {
            return Err(format!("missing bootstrap sudo key coverage: {key}").into());
        }
    }
    for key in ["name", "status", "detail"] {
        if !rust_helper.contains(&format!("\"{key}\"")) && !contract.contains(&format!("\"{key}\""))
        {
            return Err(format!("missing bootstrap command entry key coverage: {key}").into());
        }
    }

    Ok(())
}

fn collect_between(text: &str, prefix: &str, suffix: &str) -> BTreeSet<String> {
    text.match_indices(prefix)
        .filter_map(|(index, _)| {
            let start = index + prefix.len();
            let tail = &text[start..];
            let end = tail.find(suffix)?;
            Some(tail[..end].to_owned())
        })
        .collect()
}

fn expect_all_text_present(
    label: &str,
    expected: &BTreeSet<String>,
    haystacks: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    let missing = expected
        .iter()
        .filter(|item| {
            !haystacks
                .iter()
                .any(|haystack| haystack.contains(item.as_str()))
        })
        .cloned()
        .collect::<Vec<_>>();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!("{label} missing coverage: {missing:?}").into())
    }
}

fn parse_bootstrap_command_entry(entry: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let mut parts = entry.splitn(3, '\t');
    let name = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| format!("invalid command entry missing name: {entry:?}"))?;
    let status = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| format!("invalid command entry missing status: {entry:?}"))?;
    let detail = parts
        .next()
        .ok_or_else(|| format!("invalid command entry missing detail: {entry:?}"))?;

    Ok(json!({
        "name": name,
        "status": status,
        "detail": detail,
    }))
}

fn expect_status(actual: i32, expected: i32) -> Result<(), Box<dyn std::error::Error>> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("unexpected status: expected={expected} actual={actual}").into())
    }
}

fn expect_contains(
    haystack: &str,
    needle: &str,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if haystack.contains(needle) {
        Ok(())
    } else {
        Err(format!("{message}: missing {needle:?} in {haystack:?}").into())
    }
}

fn expect_top_str(
    value: &Value,
    field: &str,
    expected: &str,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if value.get(field).and_then(Value::as_str) == Some(expected) {
        Ok(())
    } else {
        Err(format!("{message}: {}", display_value(Some(value))).into())
    }
}

fn expect_top_non_empty_str(
    value: &Value,
    field: &str,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if value
        .get(field)
        .and_then(Value::as_str)
        .is_some_and(|text| !text.is_empty())
    {
        Ok(())
    } else {
        Err(format!("{message}: {}", display_value(Some(value))).into())
    }
}

fn expect_top_str_or_null(
    value: &Value,
    field: &str,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match value.get(field) {
        Some(Value::Null) => Ok(()),
        Some(Value::String(_)) => Ok(()),
        _ => Err(format!("{message}: {}", display_value(Some(value))).into()),
    }
}

fn expect_top_str_ends_with(
    value: &Value,
    field: &str,
    suffix: &str,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if value
        .get(field)
        .and_then(Value::as_str)
        .is_some_and(|text| text.ends_with(suffix))
    {
        Ok(())
    } else {
        Err(format!("{message}: {}", display_value(Some(value))).into())
    }
}

fn expect_top_bool(
    value: &Value,
    field: &str,
    expected: bool,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if value.get(field).and_then(Value::as_bool) == Some(expected) {
        Ok(())
    } else {
        Err(format!("{message}: {}", display_value(Some(value))).into())
    }
}

fn expect_top_i64(
    value: &Value,
    field: &str,
    expected: i64,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if value.get(field).and_then(Value::as_i64) == Some(expected) {
        Ok(())
    } else {
        Err(format!("{message}: {}", display_value(Some(value))).into())
    }
}

fn expect_top_null(
    value: &Value,
    field: &str,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(()),
        _ => Err(format!("{message}: {}", display_value(Some(value))).into()),
    }
}

fn expect_top_error_code_none(value: &Value) -> Result<(), Box<dyn std::error::Error>> {
    match value.get("error_code") {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(text)) if text.is_empty() => Ok(()),
        _ => Err(format!("unexpected error_code: {}", display_value(Some(value))).into()),
    }
}

fn expect_top_string_array(
    value: &Value,
    field: &str,
    expected: &[&str],
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = value
        .get(field)
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect::<Vec<_>>());
    if actual.as_deref() == Some(expected) {
        Ok(())
    } else {
        Err(format!("{message}: {}", display_value(Some(value))).into())
    }
}

fn expect_sudo(
    payload: &Value,
    key: &str,
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if payload
        .get("sudo")
        .and_then(|sudo| sudo.get(key))
        .and_then(Value::as_str)
        == Some(expected)
    {
        Ok(())
    } else {
        Err(format!("unexpected sudo.{key}: {}", display_value(Some(payload))).into())
    }
}

fn expect_sudo_detail_contains(
    payload: &Value,
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if payload
        .get("sudo")
        .and_then(|sudo| sudo.get("detail"))
        .and_then(Value::as_str)
        .is_some_and(|detail| detail.contains(expected))
    {
        Ok(())
    } else {
        Err(format!("unexpected sudo.detail: {}", display_value(Some(payload))).into())
    }
}

fn expect_command(
    payload: &Value,
    name: &str,
    status: Option<&str>,
    detail: Option<&str>,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let found = payload
        .get("commands")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|item| {
            item.get("name").and_then(Value::as_str) == Some(name)
                && status.is_none_or(|expected| {
                    item.get("status").and_then(Value::as_str) == Some(expected)
                })
                && detail.is_none_or(|expected| {
                    item.get("detail").and_then(Value::as_str) == Some(expected)
                })
        });
    if found {
        Ok(())
    } else {
        Err(format!("{message}: {}", display_value(Some(payload))).into())
    }
}

fn non_empty_or_null(value: Option<&str>) -> Value {
    value
        .filter(|value| !value.is_empty())
        .map(Value::from)
        .unwrap_or(Value::Null)
}

pub fn write_rich_host_matrix_targets(output: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let targets = json!([
        {
            "case_id": "dns-xtables",
            "smoke_protocol": "dns",
            "smoke_class": "dns_preview",
            "backend": "xtables",
            "ip_family": "ipv4",
            "host_shape": "rich_linux_host",
            "support_tier": "supported_preview",
            "product_release_gate": "product_required",
            "capability_probe": "xtables_tproxy",
            "documented_operator_shape": true,
            "hosted_must_pass": true,
        },
        {
            "case_id": "dns-nft",
            "smoke_protocol": "dns",
            "smoke_class": "dns_preview",
            "backend": "nft",
            "ip_family": "ipv4",
            "host_shape": "rich_linux_host",
            "support_tier": "supported_preview",
            "product_release_gate": "product_required",
            "capability_probe": "nft_tproxy",
            "documented_operator_shape": true,
            "hosted_must_pass": true,
        },
        {
            "case_id": "generic-udp-xtables",
            "smoke_protocol": "generic_udp",
            "smoke_class": "generic_udp",
            "backend": "xtables",
            "ip_family": "ipv4",
            "host_shape": "rich_linux_host",
            "support_tier": "guarded_unstable",
            "product_release_gate": "guarded_evidence_only",
            "capability_probe": "xtables_tproxy",
            "documented_operator_shape": true,
            "hosted_must_pass": true,
        },
        {
            "case_id": "generic-udp-nft",
            "smoke_protocol": "generic_udp",
            "smoke_class": "generic_udp",
            "backend": "nft",
            "ip_family": "ipv4",
            "host_shape": "rich_linux_host",
            "support_tier": "guarded_unstable",
            "product_release_gate": "guarded_evidence_only",
            "capability_probe": "nft_tproxy",
            "documented_operator_shape": true,
            "hosted_must_pass": true,
        },
        {
            "case_id": "dns-ipv6",
            "smoke_protocol": "dns_ipv6",
            "smoke_class": "dns_preview",
            "backend": "xtables",
            "ip_family": "ipv6",
            "host_shape": "rich_linux_host",
            "support_tier": "supported_preview",
            "product_release_gate": "product_required",
            "capability_probe": "ipv6_ip6tables_tproxy",
            "documented_operator_shape": true,
            "hosted_must_pass": true,
        },
        {
            "case_id": "dns-ipv6-nft",
            "smoke_protocol": "dns_ipv6",
            "smoke_class": "dns_preview",
            "backend": "nft",
            "ip_family": "ipv6",
            "host_shape": "rich_linux_host",
            "support_tier": "supported_preview",
            "product_release_gate": "rich_host_candidate",
            "capability_probe": "ipv6_nft_tproxy",
            "documented_operator_shape": true,
            "hosted_must_pass": false,
        },
        {
            "case_id": "generic-udp-ipv6",
            "smoke_protocol": "generic_udp",
            "smoke_class": "generic_udp",
            "backend": "xtables",
            "ip_family": "ipv6",
            "host_shape": "rich_linux_host",
            "support_tier": "guarded_unstable",
            "product_release_gate": "guarded_evidence_only",
            "capability_probe": "ipv6_ip6tables_tproxy",
            "documented_operator_shape": true,
            "hosted_must_pass": true,
        },
        {
            "case_id": "generic-udp-ipv6-nft",
            "smoke_protocol": "generic_udp",
            "smoke_class": "generic_udp",
            "backend": "nft",
            "ip_family": "ipv6",
            "host_shape": "rich_linux_host",
            "support_tier": "guarded_unstable",
            "product_release_gate": "rich_host_candidate",
            "capability_probe": "ipv6_nft_tproxy",
            "documented_operator_shape": true,
            "hosted_must_pass": false,
        },
    ]);
    std::fs::write(output, serde_json::to_string_pretty(&targets)? + "\n")?;
    Ok(())
}

fn emit_toml(key: &str, value: Option<&toml::Value>) {
    match value {
        Some(toml::Value::String(value)) => emit(key, value),
        Some(toml::Value::Integer(value)) => emit(key, &value.to_string()),
        Some(toml::Value::Float(value)) => emit(key, &value.to_string()),
        Some(toml::Value::Boolean(value)) => emit(key, if *value { "true" } else { "false" }),
        Some(value) => emit(key, &value.to_string()),
        None => {}
    }
}

fn emit(key: &str, value: &str) {
    println!("{key}\t{}", sanitize_tsv(value));
}

fn emit_json(key: &str, value: Option<&serde_json::Value>) {
    match value {
        Some(serde_json::Value::Bool(value)) => emit(key, if *value { "true" } else { "false" }),
        Some(serde_json::Value::String(value)) => emit(key, value),
        Some(serde_json::Value::Number(value)) => emit(key, &value.to_string()),
        Some(value) if !value.is_null() => emit(key, &value.to_string()),
        _ => {}
    }
}

fn sanitize_tsv(value: &str) -> String {
    value.replace(['\t', '\n'], " ")
}

fn number_to_i64(value: &toml::Value) -> Option<i64> {
    match value {
        toml::Value::Integer(value) => Some(*value),
        toml::Value::Float(value) => Some(*value as i64),
        toml::Value::String(value) => value.parse().ok(),
        _ => None,
    }
}

fn extract_json_object(text: &str) -> Option<serde_json::Value> {
    let trimmed = text.trim();
    let start = trimmed.find('{')?;
    let end = trimmed.rfind('}')?;
    if end <= start {
        return None;
    }
    serde_json::from_str(&trimmed[start..=end]).ok()
}

fn read_jsonl_lenient(path: &Path) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    let mut records = Vec::new();
    for line in std::fs::read_to_string(path)?.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
            records.push(value);
        }
    }
    Ok(records)
}

fn read_jsonl_strict(path: &Path) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    let mut records = Vec::new();
    for line in std::fs::read_to_string(path)?.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        records.push(serde_json::from_str::<Value>(trimmed)?);
    }
    Ok(records)
}

fn read_json_object(path: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    let value = serde_json::from_str::<Value>(&std::fs::read_to_string(path)?)?;
    if value.is_object() {
        Ok(value)
    } else {
        Err(format!("expected JSON object in {}", path.display()).into())
    }
}

fn load_json_report(
    stdout_path: &Path,
    stderr_path: &Path,
) -> Result<Value, Box<dyn std::error::Error>> {
    let stdout = std::fs::read_to_string(stdout_path).unwrap_or_default();
    let stderr = std::fs::read_to_string(stderr_path).unwrap_or_default();
    for stream in [&stdout, &stderr, &format!("{stdout}\n{stderr}")] {
        let payload = stream.trim();
        if payload.is_empty() {
            continue;
        }
        let Some(start) = payload.find('{') else {
            continue;
        };
        let Some(end) = payload.rfind('}') else {
            continue;
        };
        if end <= start {
            continue;
        }
        if let Ok(value) = serde_json::from_str(&payload[start..=end]) {
            return Ok(value);
        }
    }
    Err(format!("missing_json_report stdout={stdout:?} stderr={stderr:?}").into())
}

fn count_codes(records: &[Value], codes: &[&str]) -> usize {
    records
        .iter()
        .filter(|record| {
            record
                .get("event_code")
                .and_then(Value::as_str)
                .is_some_and(|code| codes.contains(&code))
        })
        .count()
}

fn empty_to_null(value: Option<&str>) -> Value {
    value
        .filter(|value| !value.is_empty())
        .map(|value| Value::String(value.to_owned()))
        .unwrap_or(Value::Null)
}

#[derive(Default)]
struct TproxyApplySummaryFields {
    firewall_backend_effective: Value,
    wide_udp_capture_support_tier: Value,
    wide_udp_capture_policy: Value,
    wide_udp_capture_runtime_scope: Value,
}

fn tproxy_apply_summary_fields(
    path: &Path,
) -> Result<TproxyApplySummaryFields, Box<dyn std::error::Error>> {
    let mut fields = TproxyApplySummaryFields {
        firewall_backend_effective: Value::Null,
        wide_udp_capture_support_tier: Value::Null,
        wide_udp_capture_policy: Value::Null,
        wide_udp_capture_runtime_scope: Value::Null,
    };
    for raw in std::fs::read_to_string(path)?.lines() {
        let stripped = raw.trim();
        if fields.firewall_backend_effective.is_null() {
            fields.firewall_backend_effective = extract_marker(
                stripped,
                &["firewall_backend_effective", "firewall_backend"],
            );
        }
        if fields.wide_udp_capture_support_tier.is_null() {
            fields.wide_udp_capture_support_tier =
                extract_marker(stripped, &["wide_udp_capture_support_tier"]);
        }
        if fields.wide_udp_capture_policy.is_null() {
            fields.wide_udp_capture_policy = extract_marker(stripped, &["wide_udp_capture_policy"]);
        }
        if fields.wide_udp_capture_runtime_scope.is_null() {
            fields.wide_udp_capture_runtime_scope =
                extract_marker(stripped, &["wide_udp_capture_runtime_scope"]);
        }
    }
    Ok(fields)
}

fn extract_marker(line: &str, aliases: &[&str]) -> Value {
    aliases
        .iter()
        .find_map(|alias| {
            line.split_once(&format!("{alias}="))
                .map(|(_, value)| Value::String(value.trim().to_owned()))
        })
        .unwrap_or(Value::Null)
}

fn latest_event<'a>(records: &'a [Value], code: &str) -> Option<&'a Value> {
    records
        .iter()
        .rev()
        .find(|record| record.get("event_code").and_then(Value::as_str) == Some(code))
}

fn latest_event_index(records: &[Value], code: &str) -> Option<usize> {
    records
        .iter()
        .rposition(|record| record.get("event_code").and_then(Value::as_str) == Some(code))
}

fn empty_string_to_null(value: &str) -> Value {
    if value.is_empty() {
        Value::Null
    } else {
        Value::String(value.to_owned())
    }
}

#[cfg(unix)]
fn write_smoke_artifact(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::{self, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};

    // Reuse the existing operator-owned ancestry policy. In particular, root
    // must not publish below another user's directory. Callers prepare the
    // artifact directory; silently creating or chmodding it would weaken this.
    let parent = aegis_core::secret_file::trusted_parent(path)?;
    let owner = std::fs::metadata(&parent)?.uid();
    let output = parent.join(path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "smoke artifact needs a file name",
        )
    })?);
    let check_output = || match std::fs::symlink_metadata(&output) {
        Ok(metadata)
            if metadata.is_file()
                && metadata.nlink() == 1
                && metadata.uid() == owner
                && metadata.mode() & 0o022 == 0 =>
        {
            Ok(())
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "smoke artifact must be an operator-owned regular file without links or shared writes",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    };
    check_output()?;

    static NEXT_STAGING_ID: AtomicU64 = AtomicU64::new(0);
    for _ in 0..32 {
        let staging = parent.join(format!(
            ".aegis-smoke-contract-{}-{}.tmp",
            std::process::id(),
            NEXT_STAGING_ID.fetch_add(1, Ordering::Relaxed)
        ));
        // create_new atomically refuses every existing entry, including a
        // symlink. The supplied output is never opened or truncated at all.
        let mut file = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&staging)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        };
        let result = (|| {
            file.write_all(bytes)?;
            // Smoke summaries are intentionally readable after sudo by the
            // invoking operator. Sharing grants reads, never writes; change
            // permissions only through the newly created descriptor.
            file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
            file.sync_all()?;
            check_output()?;
            // Rename replaces a directory entry without following it, so a
            // swapped final symlink/hardlink cannot modify its target inode.
            // Atomic publication also preserves repeated smoke-result updates.
            std::fs::rename(&staging, &output)?;
            aegis_core::secret_file::sync_directory(&parent)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&staging);
        }
        return result;
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "smoke artifact staging names exhausted",
    ))
}

#[cfg(not(unix))]
fn write_smoke_artifact(_path: &Path, _bytes: &[u8]) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Linux smoke artifact publication requires Unix permissions",
    ))
}

fn latest_response_stage(records: &[Value]) -> Option<Value> {
    records.iter().rev().find_map(|record| {
        if record.get("event_code").and_then(Value::as_str)
            == Some("ingress_udp_datagram_response_stage")
        {
            record
                .get("fields")
                .and_then(|fields| fields.get("stage"))
                .cloned()
        } else {
            None
        }
    })
}

fn display_field(fields: Option<&Value>, field: &str) -> String {
    display_value(fields.and_then(|fields| fields.get(field)))
}

fn display_value(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(value)) => value.clone(),
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::Bool(value)) => value.to_string(),
        Some(Value::Null) | None => "None".to_owned(),
        Some(value) => value.to_string(),
    }
}

fn generic_udp_observed_record(
    ts_unix_ms: u64,
    target_host: &str,
    target_port: u16,
    contract: &str,
    support_tier: &str,
    capture_policy: &str,
    runtime_scope: &str,
) -> Value {
    json!({
        "ts_unix_ms": ts_unix_ms,
        "level": "info",
        "event_code": "ingress_udp_datagram_observed",
        "message": "ingress_udp_datagram_observed",
        "fields": generic_udp_fields(
            target_host,
            target_port,
            Value::Null,
            contract,
            support_tier,
            capture_policy,
            runtime_scope,
        ),
    })
}

#[allow(clippy::too_many_arguments)]
fn generic_udp_response_stage_record(
    ts_unix_ms: u64,
    target_host: &str,
    target_port: u16,
    stage: &str,
    contract: &str,
    support_tier: &str,
    capture_policy: &str,
    runtime_scope: &str,
) -> Value {
    json!({
        "ts_unix_ms": ts_unix_ms,
        "level": "info",
        "event_code": "ingress_udp_datagram_response_stage",
        "message": "ingress_udp_datagram_response_stage",
        "fields": generic_udp_fields(
            target_host,
            target_port,
            Value::String(stage.to_owned()),
            contract,
            support_tier,
            capture_policy,
            runtime_scope,
        ),
    })
}

fn generic_udp_completed_record(
    ts_unix_ms: u64,
    target_host: &str,
    target_port: u16,
    contract: &str,
    support_tier: &str,
    capture_policy: &str,
    runtime_scope: &str,
) -> Value {
    json!({
        "ts_unix_ms": ts_unix_ms,
        "level": "info",
        "event_code": "ingress_udp_datagram_completed",
        "message": "ingress_udp_datagram_completed",
        "fields": generic_udp_fields(
            target_host,
            target_port,
            Value::Null,
            contract,
            support_tier,
            capture_policy,
            runtime_scope,
        ),
    })
}

fn generic_udp_fields(
    target_host: &str,
    target_port: u16,
    stage: Value,
    contract: &str,
    support_tier: &str,
    capture_policy: &str,
    runtime_scope: &str,
) -> Value {
    json!({
        "target_host": target_host,
        "target_port": target_port,
        "response_action": "local_udp",
        "stage": stage,
        "wide_udp_capture_contract": contract,
        "wide_udp_capture_support_tier": support_tier,
        "wide_udp_capture_policy": capture_policy,
        "wide_udp_capture_runtime_scope": runtime_scope,
        "wide_udp_capture_match_kind": "generic_capture_contract",
        "wide_udp_capture_accept_reason_code": "matched_generic_udp_capture_contract",
        "wide_udp_preview_policy": null,
        "wide_udp_preview_match_kind": null,
        "wide_udp_preview_accept_reason_code": null,
    })
}

fn set_default(payload: &mut Value, key: &str, value: Value) {
    if let Some(map) = payload.as_object_mut() {
        map.entry(key.to_owned()).or_insert(value);
    }
}

fn set_value(payload: &mut Value, key: &str, value: Value) {
    if let Some(map) = payload.as_object_mut() {
        map.insert(key.to_owned(), value);
    }
}

fn latest_event_for_port<'a>(records: &'a [Value], code: &str, port: u16) -> Option<&'a Value> {
    records.iter().rev().find(|record| {
        record.get("event_code").and_then(Value::as_str) == Some(code)
            && record
                .get("fields")
                .and_then(|fields| fields.get("target_port"))
                .and_then(Value::as_u64)
                == Some(u64::from(port))
    })
}

fn event_fields(record: &Value) -> Option<&Value> {
    record.get("fields")
}

fn verify_tproxy_smoke_generic_udp_self_test(
    contract: &Value,
    records: &[Value],
    target_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    expect_top_str(
        contract,
        "runtime_delivery_stage",
        "completed_return_delivery_tail",
        "unexpected generic_udp delivery stage",
    )?;
    expect_top_str(
        contract,
        "runtime_response_action",
        "local_udp",
        "unexpected generic_udp response action",
    )?;
    expect_top_str(
        contract,
        "runtime_response_stage",
        "local_udp_send_done",
        "unexpected generic_udp response stage",
    )?;
    expect_top_str(
        contract,
        "runtime_health_status",
        "healthy",
        "unexpected generic_udp health status",
    )?;
    expect_top_str(
        contract,
        "runtime_transport_status",
        "completed",
        "unexpected generic_udp transport status",
    )?;
    expect_top_u64(
        contract,
        "runtime_target_port",
        u64::from(target_port),
        "unexpected generic_udp target port",
    )?;

    latest_event_for_port(records, "ingress_udp_datagram_observed", target_port)
        .ok_or_else(|| format!("missing ingress_udp_datagram_observed for port {target_port}"))?;
    latest_event_for_port(records, "ingress_udp_datagram_completed", target_port)
        .ok_or_else(|| format!("missing ingress_udp_datagram_completed for port {target_port}"))?;
    Ok(())
}

fn verify_tproxy_smoke_http_self_test(
    contract: &Value,
    records: &[Value],
) -> Result<(), Box<dyn std::error::Error>> {
    expect_top_str(
        contract,
        "runtime_delivery_stage",
        "completed_session_success",
        "unexpected http delivery stage",
    )?;
    expect_top_str(
        contract,
        "runtime_response_action",
        "stream_response",
        "unexpected http response action",
    )?;
    expect_top_null(
        contract,
        "runtime_response_stage",
        "unexpected http response stage",
    )?;
    expect_top_str(
        contract,
        "runtime_health_status",
        "healthy",
        "unexpected http health status",
    )?;
    expect_top_str(
        contract,
        "runtime_transport_status",
        "completed",
        "unexpected http transport status",
    )?;

    let success = latest_event(records, "direct_session_succeeded")
        .ok_or("missing direct_session_succeeded")?;
    let fields = event_fields(success);
    expect_str(
        fields,
        "strategy",
        "passthrough",
        "unexpected http strategy",
    )?;
    if fields
        .and_then(|fields| fields.get("cross_session_reuse_weight"))
        .and_then(Value::as_f64)
        .is_some_and(|weight| weight > 0.0)
    {
        Ok(())
    } else {
        Err(format!(
            "unexpected cross_session_reuse_weight: {}",
            display_value(fields)
        )
        .into())
    }
}

fn verify_tproxy_smoke_udp_preview_drop_self_test(
    contract: &Value,
    records: &[Value],
    target_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    expect_top_str(
        contract,
        "runtime_delivery_stage",
        "dropped_before_response_delivery",
        "unexpected udp_preview_drop delivery stage",
    )?;
    expect_top_null(
        contract,
        "runtime_response_stage",
        "unexpected udp_preview_drop response stage",
    )?;
    expect_top_str(
        contract,
        "runtime_health_status",
        "degraded_capture_drop",
        "unexpected udp_preview_drop health status",
    )?;
    expect_top_str(
        contract,
        "runtime_transport_status",
        "capture_rejected",
        "unexpected udp_preview_drop transport status",
    )?;
    expect_top_u64(
        contract,
        "runtime_target_port",
        u64::from(target_port),
        "unexpected udp_preview_drop target port",
    )?;

    let dropped = latest_event(records, "ingress_udp_datagram_dropped")
        .ok_or("missing ingress_udp_datagram_dropped")?;
    let fields = event_fields(dropped);
    expect_str(
        fields,
        "wide_udp_capture_drop_stage",
        "capture_policy_gate",
        "unexpected drop stage",
    )?;
    expect_str(
        fields,
        "wide_udp_capture_drop_reason_code",
        "target_port_outside_capture_policy",
        "unexpected drop reason code",
    )?;
    expect_u64_array(
        fields,
        "expected_udp_preview_ports",
        &[53, 5353],
        "unexpected expected_udp_preview_ports",
    )?;
    Ok(())
}

fn expect_top_u64(
    value: &Value,
    field: &str,
    expected: u64,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if value.get(field).and_then(Value::as_u64) == Some(expected) {
        Ok(())
    } else {
        Err(format!("{message}: {}", display_value(Some(value))).into())
    }
}

fn expect_str(
    fields: Option<&Value>,
    field: &str,
    expected: &str,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if fields
        .and_then(|fields| fields.get(field))
        .and_then(Value::as_str)
        == Some(expected)
    {
        Ok(())
    } else {
        Err(format!("{message}: {}", display_value(fields)).into())
    }
}

fn expect_null(
    fields: Option<&Value>,
    field: &str,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match fields.and_then(|fields| fields.get(field)) {
        None | Some(Value::Null) => Ok(()),
        _ => Err(format!("{message}: {}", display_value(fields)).into()),
    }
}

fn expect_bool(
    fields: Option<&Value>,
    field: &str,
    expected: bool,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if fields
        .and_then(|fields| fields.get(field))
        .and_then(Value::as_bool)
        == Some(expected)
    {
        Ok(())
    } else {
        Err(format!("{message}: {}", display_value(fields)).into())
    }
}

fn expect_u64(
    fields: Option<&Value>,
    field: &str,
    expected: u64,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if fields
        .and_then(|fields| fields.get(field))
        .and_then(Value::as_u64)
        == Some(expected)
    {
        Ok(())
    } else {
        Err(format!("{message}: {}", display_value(fields)).into())
    }
}

fn expect_u64_array(
    fields: Option<&Value>,
    field: &str,
    expected: &[u64],
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = fields
        .and_then(|fields| fields.get(field))
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_u64).collect::<Vec<u64>>());
    if actual.as_deref() == Some(expected) {
        Ok(())
    } else {
        Err(format!("{message}: {}", display_value(fields)).into())
    }
}
