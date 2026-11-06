use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

use super::support::{
    compact_named_statuses, event_field, event_field_value, join_strings, require_array_field,
    require_string_field, require_u64_field, string_array_opt,
};

pub fn phase_b_tls_wire_review(events: &[Value]) -> Value {
    let mut adapter_counts = BTreeMap::<String, u64>::new();
    let mut checked_events = 0_u64;
    let mut mismatches = Vec::new();

    for event in events {
        let Some(adapter) =
            event_field(event, "relay_surface_tls_wire_adapter").and_then(Value::as_str)
        else {
            continue;
        };
        checked_events += 1;
        *adapter_counts.entry(adapter.to_string()).or_default() += 1;

        let target_class =
            event_field(event, "relay_surface_tls_profile_target_class").and_then(Value::as_str);
        let target_alpn =
            string_array_opt(event_field(event, "relay_surface_tls_profile_target_alpn"));
        let wire_alpn = string_array_opt(event_field(event, "relay_surface_tls_wire_alpn"));

        let missing_from_target = wire_alpn
            .iter()
            .filter(|alpn| !target_alpn.contains(alpn))
            .cloned()
            .collect::<Vec<_>>();
        if !target_alpn.is_empty() && !missing_from_target.is_empty() {
            mismatches.push(json!({
                "reason": "wire-alpn-not-in-target-alpn",
                "event_code": event_field_value(event, "event_code"),
                "transport": event_field(event, "transport").or_else(|| event_field(event, "chosen_transport")).cloned(),
                "target_class": target_class,
                "target_alpn": target_alpn,
                "wire_adapter": adapter,
                "wire_alpn": wire_alpn,
                "missing_from_target": missing_from_target,
            }));
        }

        if target_class == Some("legacy_tls") && wire_alpn.is_empty() {
            mismatches.push(json!({
                "reason": "legacy-target-without-wire-alpn",
                "event_code": event_field_value(event, "event_code"),
                "transport": event_field(event, "transport").or_else(|| event_field(event, "chosen_transport")).cloned(),
                "target_class": target_class,
                "target_alpn": target_alpn,
                "wire_adapter": adapter,
                "wire_alpn": wire_alpn,
            }));
        }
    }

    let mut reasons = Vec::new();
    if checked_events == 0 {
        reasons.push("no-tls-wire-events");
    }
    if !mismatches.is_empty() {
        reasons.push("tls-wire-target-mismatch");
    }

    json!({
        "event": "phase_b_tls_wire_review",
        "schema_version": 1,
        "status": if reasons.is_empty() { "PASS" } else { "FAIL" },
        "checked_events": checked_events,
        "adapter_counts": adapter_counts,
        "reasons": reasons,
        "mismatches": mismatches,
    })
}

pub fn phase_b_tls_wire_markdown(review: &Value) -> String {
    format!(
        "# Phase B TLS Wire Review\n\n\
         - Status: `{}`\n\
         - Checked events: `{}`\n\
         - Reasons: `{}`\n",
        review["status"].as_str().unwrap_or("UNKNOWN"),
        review["checked_events"].as_u64().unwrap_or(0),
        join_strings(&review["reasons"]),
    )
}

pub fn phase_b_relay_shape_review(events: &[Value], require_diversity: bool) -> Value {
    const MIN_CHUNK_SIZE: u64 = 512;
    const MAX_CHUNK_SIZE: u64 = 1 << 20;
    const MAX_DELAY_MS: u64 = 250;

    let mut checked_events = 0_u64;
    let mut profile_ids = BTreeSet::<String>::new();
    let mut chunk_sizes = BTreeSet::<u64>::new();
    let mut delays = BTreeSet::<u64>::new();
    let mut violations = Vec::new();

    for event in events {
        let has_surface = event_field(event, "relay_surface_profile_id").is_some()
            || event_field(event, "relay_surface_write_chunk_size").is_some()
            || event_field(event, "relay_surface_inter_chunk_delay_ms").is_some();
        if !has_surface {
            continue;
        }
        checked_events += 1;

        if let Some(profile_id) =
            event_field(event, "relay_surface_profile_id").and_then(Value::as_str)
        {
            profile_ids.insert(profile_id.to_string());
        }

        let chunk_size =
            event_field(event, "relay_surface_write_chunk_size").and_then(Value::as_u64);
        let delay_ms =
            event_field(event, "relay_surface_inter_chunk_delay_ms").and_then(Value::as_u64);
        match chunk_size {
            Some(value) if (MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&value) => {
                chunk_sizes.insert(value);
            }
            Some(value) => violations.push(json!({
                "reason": "chunk-size-out-of-range",
                "event_code": event_field_value(event, "event_code"),
                "profile_id": event_field_value(event, "relay_surface_profile_id"),
                "value": value,
                "min": MIN_CHUNK_SIZE,
                "max": MAX_CHUNK_SIZE,
            })),
            None => violations.push(json!({
                "reason": "missing-chunk-size",
                "event_code": event_field_value(event, "event_code"),
                "profile_id": event_field_value(event, "relay_surface_profile_id"),
            })),
        }
        match delay_ms {
            Some(value) if value <= MAX_DELAY_MS => {
                delays.insert(value);
            }
            Some(value) => violations.push(json!({
                "reason": "inter-chunk-delay-out-of-range",
                "event_code": event_field_value(event, "event_code"),
                "profile_id": event_field_value(event, "relay_surface_profile_id"),
                "value": value,
                "max": MAX_DELAY_MS,
            })),
            None => violations.push(json!({
                "reason": "missing-inter-chunk-delay",
                "event_code": event_field_value(event, "event_code"),
                "profile_id": event_field_value(event, "relay_surface_profile_id"),
            })),
        }
    }

    let mut reasons = Vec::new();
    if checked_events == 0 {
        reasons.push("no-relay-surface-shape-events");
    }
    if !violations.is_empty() {
        reasons.push("relay-surface-shape-violation");
    }
    if require_diversity && (profile_ids.len() < 2 || chunk_sizes.len() < 2) {
        reasons.push("relay-surface-shape-diversity-missing");
    }

    json!({
        "event": "phase_b_relay_shape_review",
        "schema_version": 1,
        "status": if reasons.is_empty() { "PASS" } else { "FAIL" },
        "checked_events": checked_events,
        "require_diversity": require_diversity,
        "profile_ids": profile_ids.into_iter().collect::<Vec<_>>(),
        "chunk_sizes": chunk_sizes.into_iter().collect::<Vec<_>>(),
        "inter_chunk_delay_ms": delays.into_iter().collect::<Vec<_>>(),
        "limits": {
            "min_chunk_size": MIN_CHUNK_SIZE,
            "max_chunk_size": MAX_CHUNK_SIZE,
            "max_inter_chunk_delay_ms": MAX_DELAY_MS,
        },
        "reasons": reasons,
        "violations": violations,
    })
}

pub fn phase_b_relay_shape_markdown(review: &Value) -> String {
    format!(
        "# Phase B Relay Shape Review\n\n\
         - Status: `{}`\n\
         - Checked events: `{}`\n\
         - Require diversity: `{}`\n\
         - Reasons: `{}`\n",
        review["status"].as_str().unwrap_or("UNKNOWN"),
        review["checked_events"].as_u64().unwrap_or(0),
        review["require_diversity"].as_bool().unwrap_or(false),
        join_strings(&review["reasons"]),
    )
}

pub fn phase_b_active_probe_review(events: &[Value], require_finished_probe: bool) -> Value {
    let mut launched = 0_u64;
    let mut finished = 0_u64;
    let mut retry_selected = 0_u64;
    let mut retry_skipped = 0_u64;
    let mut retry_budget_exhausted = 0_u64;
    let mut failover_after_probe = 0_u64;
    let mut violations = Vec::new();

    for event in events {
        match event["event_code"].as_str() {
            Some("direct_active_stall_probe_launched") => {
                launched += 1;
                require_u64_field(event, "planned_probe_preferred_ttl", &mut violations);
                require_u64_field(event, "planned_probe_budget", &mut violations);
                require_array_field(event, "planned_probe_ttl_candidates", &mut violations);
            }
            Some("direct_active_stall_probe_finished") => {
                finished += 1;
                require_string_field(event, "probe_outcome_class", &mut violations);
                require_string_field(event, "observation_contract", &mut violations);
                require_string_field(event, "capture_status", &mut violations);
                require_u64_field(event, "planned_probe_preferred_ttl", &mut violations);
                require_u64_field(event, "planned_probe_budget", &mut violations);
                require_array_field(event, "planned_probe_ttl_candidates", &mut violations);
                require_u64_field(event, "latency_ms", &mut violations);
            }
            Some("direct_active_stall_probe_retry_selected") => {
                retry_selected += 1;
            }
            Some("direct_active_stall_probe_retry_skipped") => {
                retry_skipped += 1;
            }
            Some("direct_active_stall_probe_retry_budget_exhausted") => {
                retry_budget_exhausted += 1;
            }
            Some("direct_relay_failover_triggered")
                if event["active_stall_probe_retry_attempted"].as_bool() == Some(true)
                    || !event["probe_terminal_stage"].is_null() =>
            {
                failover_after_probe += 1;
            }
            _ => {}
        }
    }

    let mut reasons = Vec::new();
    if require_finished_probe && finished == 0 {
        reasons.push("no-finished-active-probe");
    }
    if launched > 0 && finished == 0 {
        reasons.push("active-probe-launched-without-finish");
    }
    if finished > launched && launched > 0 {
        reasons.push("active-probe-finish-count-exceeds-launch-count");
    }
    if !violations.is_empty() {
        reasons.push("active-probe-field-violation");
    }

    json!({
        "event": "phase_b_active_probe_review",
        "schema_version": 1,
        "status": if reasons.is_empty() { "PASS" } else { "FAIL" },
        "require_finished_probe": require_finished_probe,
        "counts": {
            "launched": launched,
            "finished": finished,
            "retry_selected": retry_selected,
            "retry_skipped": retry_skipped,
            "retry_budget_exhausted": retry_budget_exhausted,
            "failover_after_probe": failover_after_probe,
        },
        "reasons": reasons,
        "violations": violations,
    })
}

pub fn phase_b_active_probe_markdown(review: &Value) -> String {
    format!(
        "# Phase B Active Probe Review\n\n\
         - Status: `{}`\n\
         - Require finished probe: `{}`\n\
         - Finished probes: `{}`\n\
         - Reasons: `{}`\n",
        review["status"].as_str().unwrap_or("UNKNOWN"),
        review["require_finished_probe"].as_bool().unwrap_or(false),
        review["counts"]["finished"].as_u64().unwrap_or(0),
        join_strings(&review["reasons"]),
    )
}

pub fn phase_b_live_evidence_review(
    baseline: &Value,
    tls_wire: &Value,
    relay_shape: &Value,
    active_probe: &Value,
) -> Value {
    let checks = vec![
        phase_b_check(
            "baseline",
            "BASELINE_READY",
            baseline["status"].as_str(),
            &baseline["reasons"],
        ),
        phase_b_check(
            "tls_wire",
            "PASS",
            tls_wire["status"].as_str(),
            &tls_wire["reasons"],
        ),
        phase_b_check(
            "relay_shape",
            "PASS",
            relay_shape["status"].as_str(),
            &relay_shape["reasons"],
        ),
        phase_b_check(
            "active_probe",
            "PASS",
            active_probe["status"].as_str(),
            &active_probe["reasons"],
        ),
    ];
    let mut reasons = checks
        .iter()
        .filter(|check| check["status"].as_str() != check["expected_status"].as_str())
        .filter_map(|check| check["reason_code"].as_str())
        .collect::<Vec<_>>();
    reasons.sort_unstable();
    reasons.dedup();

    json!({
        "event": "phase_b_live_evidence_review",
        "schema_version": 1,
        "status": if reasons.is_empty() { "LIVE_EVIDENCE_READY" } else { "LIVE_EVIDENCE_BLOCKED" },
        "acceptance_degraded": !reasons.is_empty(),
        "reasons": reasons,
        "checks": checks,
        "baseline": {
            "status": baseline["status"].clone(),
            "acceptance_degraded": baseline["acceptance_degraded"].clone(),
        },
        "tls_wire": {
            "status": tls_wire["status"].clone(),
            "checked_events": tls_wire["checked_events"].clone(),
        },
        "relay_shape": {
            "status": relay_shape["status"].clone(),
            "checked_events": relay_shape["checked_events"].clone(),
            "require_diversity": relay_shape["require_diversity"].clone(),
        },
        "active_probe": {
            "status": active_probe["status"].clone(),
            "counts": active_probe["counts"].clone(),
        },
    })
}

pub fn phase_b_live_evidence_markdown(review: &Value) -> String {
    format!(
        "# Phase B Live Evidence Review\n\n\
         - Status: `{}`\n\
         - Acceptance degraded: `{}`\n\
         - Reasons: `{}`\n\
         - Checks: `{}`\n",
        review["status"].as_str().unwrap_or("UNKNOWN"),
        review["acceptance_degraded"].as_bool().unwrap_or(false),
        join_strings(&review["reasons"]),
        compact_named_statuses(&review["checks"]),
    )
}

fn phase_b_check(
    name: &str,
    expected_status: &str,
    actual_status: Option<&str>,
    reasons: &Value,
) -> Value {
    let actual_status = actual_status.unwrap_or("UNKNOWN");
    json!({
        "name": name,
        "expected_status": expected_status,
        "status": actual_status,
        "ok": actual_status == expected_status,
        "reason_code": if actual_status == expected_status {
            Value::Null
        } else {
            Value::String(format!("phase-b-{name}-not-ready"))
        },
        "source_reasons": reasons.clone(),
    })
}
