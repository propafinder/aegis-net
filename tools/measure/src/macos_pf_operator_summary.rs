use std::path::Path;

use serde_json::{json, Map, Value};

use crate::artifact::{read_json, read_jsonl, write_json, write_text};

pub fn build_macos_pf_operator_acceptance_summary(
    output_dir: &Path,
    rooted_live_dir: &Path,
    phase4_dir: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let phase1_dir = rooted_live_dir.join("phase1");
    let phase2_dir = rooted_live_dir.join("phase2");
    let phase3_dir = rooted_live_dir.join("phase3-boundary");

    let phase1_check = load_json(&phase1_dir.join("helper-check.json"), "phase1 helper check")?;
    let phase1_apply = load_json(&phase1_dir.join("helper-apply.json"), "phase1 helper apply")?;
    let phase1_evidence = load_json(
        &phase1_dir.join("helper-evidence.json"),
        "phase1 helper evidence",
    )?;
    let phase1_runtime = load_jsonl(
        &phase1_dir.join("runtime-events.jsonl"),
        "phase1 runtime events",
    )?;

    let phase2_apply = load_json(&phase2_dir.join("helper-apply.json"), "phase2 helper apply")?;
    let phase2_evidence = load_json(
        &phase2_dir.join("helper-evidence.json"),
        "phase2 helper evidence",
    )?;
    let phase2_udp_probe = load_json(&phase2_dir.join("udp-probe.json"), "phase2 UDP probe")?;
    let phase2_runtime = load_jsonl(
        &phase2_dir.join("runtime-events.jsonl"),
        "phase2 runtime events",
    )?;

    let phase3_boundary = load_json(
        &phase3_dir.join("boundary-summary.json"),
        "phase3 boundary summary",
    )?;
    let phase3_evidence = load_json(
        &phase3_dir.join("helper-evidence.json"),
        "phase3 helper evidence",
    )?;

    let phase3_runtime_claim = str_field(&phase3_boundary, "helper_apply_runtime_claim");
    let phase3_prepared_boundary = phase3_runtime_claim
        == Some("system_wide_phase3_prepared_boundary_only")
        || str_field(&phase3_boundary, "helper_status_runtime_claim")
            == Some("system_wide_phase3_prepared_boundary_only")
        || str_field(&phase3_evidence, "current_verdict")
            == Some("system_wide_phase3_prepared_boundary_materialized");

    let phase1_backend_started = first_event(&phase1_runtime, "ingress_backend_started")?;
    let phase2_backend_started = first_event(&phase2_runtime, "ingress_backend_started")?;

    let phase1_checks = map_checks(vec![
        (
            "helper_check_ready_for_apply",
            check_entry(
                str_field(&phase1_check, "reason_code") == Some("ready_for_apply"),
                "rooted phase-1 helper check must say ready_for_apply on the Mac host",
                phase1_check.get("reason_code").cloned(),
                Some(format!(
                    "phase1_helper_check_reason={:?}",
                    str_field(&phase1_check, "reason_code")
                )),
            ),
        ),
        (
            "helper_apply_tcp_only_active",
            check_entry(
                str_field(&phase1_apply, "runtime_claim") == Some("tcp_only_phase1_active")
                    && bool_field(&phase1_apply, "runtime_active") == Some(true),
                "phase-1 helper apply must materialize the active tcp_only contour",
                phase1_apply.get("runtime_claim").cloned(),
                Some("phase1_helper_apply_not_tcp_only_active".to_string()),
            ),
        ),
        (
            "helper_evidence_tcp_only_materialized",
            check_entry(
                str_field(&phase1_evidence, "current_verdict")
                    == Some("tcp_only_phase1_helper_materialized"),
                "phase-1 evidence must stay on the tcp_only helper-materialized verdict",
                phase1_evidence.get("current_verdict").cloned(),
                Some("phase1_helper_evidence_not_materialized".to_string()),
            ),
        ),
        (
            "runtime_backend_started_wide_primary",
            check_entry(
                event_field(phase1_backend_started, "backend_runtime_id")
                    == Some("wide_primary_macos")
                    && event_field(phase1_backend_started, "wide_backend_current_stage")
                        == Some("tcp_only_phase1_live")
                    && event_field(phase1_backend_started, "wide_runtime_readiness")
                        == Some("ready"),
                "phase-1 runtime JSONL must show a bind-capable wide_primary_macos contour",
                phase1_backend_started.get("fields").cloned(),
                Some("phase1_runtime_not_active_wide_primary_macos".to_string()),
            ),
        ),
    ]);

    let phase2_checks = map_checks(vec![
        (
            "helper_apply_dns_preview_active",
            check_entry(
                str_field(&phase2_apply, "runtime_claim") == Some("dns_preview_phase2_active")
                    && bool_field(&phase2_apply, "runtime_active") == Some(true),
                "phase-2 helper apply must materialize the active dns_preview contour",
                phase2_apply.get("runtime_claim").cloned(),
                Some("phase2_helper_apply_not_dns_preview_active".to_string()),
            ),
        ),
        (
            "helper_evidence_dns_preview_materialized",
            check_entry(
                str_field(&phase2_evidence, "current_verdict")
                    == Some("dns_preview_phase2_helper_materialized"),
                "phase-2 evidence must stay on the dns_preview helper-materialized verdict",
                phase2_evidence.get("current_verdict").cloned(),
                Some("phase2_helper_evidence_not_materialized".to_string()),
            ),
        ),
        (
            "udp_probe_matches",
            check_entry(
                bool_field(&phase2_udp_probe, "matched") == Some(true),
                "phase-2 UDP probe must echo the same payload through the local MASQUE loop",
                phase2_udp_probe.get("matched").cloned(),
                Some("phase2_udp_probe_not_matched".to_string()),
            ),
        ),
        (
            "runtime_backend_started_dns_preview",
            check_entry(
                event_field(phase2_backend_started, "backend_runtime_id")
                    == Some("wide_primary_macos")
                    && event_field(phase2_backend_started, "wide_backend_current_stage")
                        == Some("dns_preview_phase2_live")
                    && event_field(phase2_backend_started, "wide_udp_capture_runtime_scope")
                        == Some("macos_ipv4_loopback_preview"),
                "phase-2 runtime JSONL must show the active DNS preview loopback contour",
                phase2_backend_started.get("fields").cloned(),
                Some("phase2_runtime_not_dns_preview_active".to_string()),
            ),
        ),
    ]);

    let phase3_checks = map_checks(vec![
        (
            "boundary_summary_claims_boundary_only",
            check_entry(
                matches!(
                    str_field(&phase3_boundary, "helper_apply_runtime_claim"),
                    Some(
                        "system_wide_phase3_boundary_only"
                            | "system_wide_phase3_prepared_boundary_only"
                    )
                ) && matches!(
                    str_field(&phase3_boundary, "helper_status_runtime_claim"),
                    Some(
                        "system_wide_phase3_boundary_only"
                            | "system_wide_phase3_prepared_boundary_only"
                    )
                ),
                "phase-3 helper apply/status must stay boundary-only or prepared-boundary-only instead of claiming a broader runtime",
                phase3_boundary.get("helper_apply_runtime_claim").cloned(),
                Some("phase3_runtime_claim_not_boundary_only".to_string()),
            ),
        ),
        (
            "boundary_summary_strict_path_fails_honestly",
            check_entry(
                str_field(&phase3_boundary, "strict_event_code")
                    == Some("ingress_startup_selection_failed")
                    && str_field(&phase3_boundary, "strict_selection_error_code")
                        == Some("wide_backend_boundary_only")
                    && matches!(
                        str_field(&phase3_boundary, "strict_wide_runtime_readiness"),
                        Some("boundary_only" | "prepared_boundary")
                    ),
                "phase-3 strict runtime path must reject startup with boundary-only semantics",
                Some(json!({
                    "strict_event_code": phase3_boundary.get("strict_event_code").cloned().unwrap_or(Value::Null),
                    "strict_selection_error_code": phase3_boundary.get("strict_selection_error_code").cloned().unwrap_or(Value::Null),
                    "strict_wide_runtime_readiness": phase3_boundary.get("strict_wide_runtime_readiness").cloned().unwrap_or(Value::Null),
                })),
                Some("phase3_strict_boundary_semantics_missing".to_string()),
            ),
        ),
        (
            "boundary_summary_fallback_path_falls_back_honestly",
            check_entry(
                str_field(&phase3_boundary, "fallback_event_code")
                    == Some("ingress_backend_started")
                    && str_field(&phase3_boundary, "fallback_backend_runtime_id")
                        == Some("socks5_fallback")
                    && str_field(&phase3_boundary, "fallback_startup_fallback_reason_code")
                        == Some("wide_backend_boundary_only"),
                "phase-3 fallback runtime path must stay on socks5_fallback with boundary-only reason code",
                Some(json!({
                    "fallback_event_code": phase3_boundary.get("fallback_event_code").cloned().unwrap_or(Value::Null),
                    "fallback_backend_runtime_id": phase3_boundary.get("fallback_backend_runtime_id").cloned().unwrap_or(Value::Null),
                    "fallback_startup_fallback_reason_code": phase3_boundary.get("fallback_startup_fallback_reason_code").cloned().unwrap_or(Value::Null),
                })),
                Some("phase3_fallback_boundary_semantics_missing".to_string()),
            ),
        ),
        (
            "helper_evidence_boundary_materialized",
            check_entry(
                matches!(
                    str_field(&phase3_evidence, "current_verdict"),
                    Some(
                        "system_wide_phase3_boundary_materialized"
                            | "system_wide_phase3_prepared_boundary_materialized"
                    )
                ),
                "phase-3 evidence must stay on the boundary-materialized verdict family",
                phase3_evidence.get("current_verdict").cloned(),
                Some("phase3_helper_evidence_not_boundary_materialized".to_string()),
            ),
        ),
    ]);

    let mut phase4_apply = Value::Null;
    let mut phase4_backend_started = Value::Null;
    let mut phase4_resolution = Value::Null;
    let phase4_checks = if let Some(phase4_dir) = phase4_dir {
        phase4_apply = load_json(&phase4_dir.join("helper-apply.json"), "phase4 helper apply")?;
        let phase4_evidence = load_json(
            &phase4_dir.join("helper-evidence.json"),
            "phase4 helper evidence",
        )?;
        let phase4_runtime = load_jsonl(
            &phase4_dir.join("runtime-events.jsonl"),
            "phase4 runtime events",
        )?;
        phase4_resolution = load_json(
            &phase4_dir.join("resolution-summary.json"),
            "phase4 resolution summary",
        )?;
        phase4_backend_started = first_event(&phase4_runtime, "ingress_backend_started")?.clone();

        Some(map_checks(vec![
            (
                "helper_apply_system_wide_phase4_active",
                check_entry(
                    str_field(&phase4_apply, "runtime_claim") == Some("system_wide_phase4_active")
                        && bool_field(&phase4_apply, "runtime_active") == Some(true),
                    "phase-4 helper apply must materialize the active system_wide contour",
                    phase4_apply.get("runtime_claim").cloned(),
                    Some("phase4_helper_apply_not_system_wide_phase4_active".to_string()),
                ),
            ),
            (
                "helper_evidence_system_wide_phase4_materialized",
                check_entry(
                    str_field(&phase4_evidence, "current_verdict")
                        == Some("system_wide_phase4_helper_materialized"),
                    "phase-4 evidence must stay on the system_wide helper-materialized verdict",
                    phase4_evidence.get("current_verdict").cloned(),
                    Some("phase4_helper_evidence_not_materialized".to_string()),
                ),
            ),
            (
                "runtime_backend_started_system_wide_phase4_bind_capable",
                check_entry(
                    event_field(&phase4_backend_started, "backend_runtime_id")
                        == Some("wide_primary_macos")
                        && event_field(&phase4_backend_started, "wide_backend_current_stage")
                            == Some("system_wide_phase4_live")
                        && event_field(&phase4_backend_started, "wide_runtime_readiness")
                            == Some("ready"),
                    "phase-4 runtime JSONL must show a bind-capable wide_primary_macos system-wide contour (no boundary_only, no socks5_fallback)",
                    phase4_backend_started.get("fields").cloned(),
                    Some("phase4_runtime_not_active_system_wide_bind_capable".to_string()),
                ),
            ),
            (
                "resolution_strict_path_succeeds",
                check_entry(
                    str_field(&phase4_resolution, "strict_event_code")
                        == Some("ingress_backend_started")
                        && str_field(&phase4_resolution, "strict_wide_runtime_readiness")
                            == Some("ready")
                        && phase4_resolution
                            .get("strict_selection_error_code")
                            .is_none_or(Value::is_null)
                        && matches!(
                            str_field(&phase4_resolution, "fallback_startup_fallback_reason_code"),
                            None | Some("")
                        ),
                    "phase-4 strict path must reach ingress_backend_started without boundary_only selection error and without fallback reason code",
                    Some(json!({
                        "strict_event_code": phase4_resolution.get("strict_event_code").cloned().unwrap_or(Value::Null),
                        "strict_wide_runtime_readiness": phase4_resolution.get("strict_wide_runtime_readiness").cloned().unwrap_or(Value::Null),
                        "strict_selection_error_code": phase4_resolution.get("strict_selection_error_code").cloned().unwrap_or(Value::Null),
                        "fallback_startup_fallback_reason_code": phase4_resolution.get("fallback_startup_fallback_reason_code").cloned().unwrap_or(Value::Null),
                    })),
                    Some("phase4_strict_path_did_not_succeed_bind_capable".to_string()),
                ),
            ),
        ]))
    } else {
        None
    };

    let mut failed_checks = failed_check_ids(&phase1_checks);
    failed_checks.extend(failed_check_ids(&phase2_checks));
    failed_checks.extend(failed_check_ids(&phase3_checks));
    if let Some(checks) = phase4_checks.as_ref() {
        failed_checks.extend(failed_check_ids(checks));
    }

    let (operator_acceptance_verdict, next_required_action) =
        if let Some(first) = failed_checks.first() {
            ("degraded".to_string(), first.clone())
        } else if phase4_checks.is_some() {
            (
                "green".to_string(),
                "phase4_live_hostile_path_validation_or_broader_release_claim".to_string(),
            )
        } else {
            (
                "green".to_string(),
                if phase3_prepared_boundary {
                    "broader_runtime_still_not_opened".to_string()
                } else {
                    "phase4_implementation_wave_or_broader_operator_acceptance".to_string()
                },
            )
        };

    let (schema_version, broader_claim, broader_status) = if phase4_checks.is_none() {
        (
            "macos_pf_operator_acceptance_summary_v1",
            "not_proven",
            "not_opened",
        )
    } else if failed_checks.is_empty() {
        ("macos_pf_operator_acceptance_summary_v2", "proven", "green")
    } else {
        (
            "macos_pf_operator_acceptance_summary_v2",
            "not_proven",
            "degraded",
        )
    };

    let phase3_milestone = if phase3_prepared_boundary {
        "system_wide_phase3_prepared_boundary_only"
    } else {
        "system_wide_phase3_boundary_only"
    };
    let mut accepted_milestones = vec![
        json!("tcp_only_phase1"),
        json!("dns_preview_phase2"),
        json!(phase3_milestone),
    ];
    if phase4_checks.is_some() && failed_checks.is_empty() {
        accepted_milestones.push(json!("system_wide_phase4_bind_capable"));
    }

    let acceptance_scope = if phase4_checks.is_some() {
        "rooted_local_phase1_phase2_phase3_plus_phase4_bind_capable"
    } else if phase3_prepared_boundary {
        "rooted_local_phase1_phase2_plus_phase3_prepared_boundary_only"
    } else {
        "rooted_local_phase1_phase2_plus_phase3_boundary_only"
    };

    let payload = json!({
        "artifact_schema": schema_version,
        "supported_platform_track": "macos_pf_epic",
        "supported_acceptance_scope": acceptance_scope,
        "rooted_live_artifact_dir": rooted_live_dir.display().to_string(),
        "operator_acceptance_verdict": operator_acceptance_verdict,
        "next_required_action": next_required_action,
        "broader_system_wide_runtime_claim": broader_claim,
        "broader_system_wide_runtime_claim_status": broader_status,
        "accepted_milestones": accepted_milestones,
        "phase1_artifact_dir": phase1_dir.display().to_string(),
        "phase2_artifact_dir": phase2_dir.display().to_string(),
        "phase3_boundary_artifact_dir": phase3_dir.display().to_string(),
        "phase1_helper_check_reason_code": phase1_check.get("reason_code").cloned().unwrap_or(Value::Null),
        "phase1_helper_apply_runtime_claim": phase1_apply.get("runtime_claim").cloned().unwrap_or(Value::Null),
        "phase1_runtime_backend_id": event_field_value(phase1_backend_started, "backend_runtime_id"),
        "phase2_helper_apply_runtime_claim": phase2_apply.get("runtime_claim").cloned().unwrap_or(Value::Null),
        "phase2_udp_probe_matched": phase2_udp_probe.get("matched").cloned().unwrap_or(Value::Null),
        "phase2_runtime_backend_id": event_field_value(phase2_backend_started, "backend_runtime_id"),
        "phase2_runtime_udp_scope": event_field_value(phase2_backend_started, "wide_udp_capture_runtime_scope"),
        "phase3_helper_apply_runtime_claim": phase3_boundary.get("helper_apply_runtime_claim").cloned().unwrap_or(Value::Null),
        "phase3_prepared_boundary": phase3_prepared_boundary,
        "phase3_strict_selection_error_code": phase3_boundary.get("strict_selection_error_code").cloned().unwrap_or(Value::Null),
        "phase3_fallback_backend_runtime_id": phase3_boundary.get("fallback_backend_runtime_id").cloned().unwrap_or(Value::Null),
        "phase3_fallback_reason_code": phase3_boundary.get("fallback_startup_fallback_reason_code").cloned().unwrap_or(Value::Null),
        "phase1_checks": phase1_checks,
        "phase2_checks": phase2_checks,
        "phase3_boundary_checks": phase3_checks,
        "phase4_artifact_dir": phase4_dir.map(|path| path.display().to_string()),
        "phase4_helper_apply_runtime_claim": phase4_apply.get("runtime_claim").cloned().unwrap_or(Value::Null),
        "phase4_runtime_backend_id": event_field_value(&phase4_backend_started, "backend_runtime_id"),
        "phase4_runtime_backend_current_stage": event_field_value(&phase4_backend_started, "wide_backend_current_stage"),
        "phase4_runtime_wide_runtime_readiness": event_field_value(&phase4_backend_started, "wide_runtime_readiness"),
        "phase4_resolution_strict_event_code": phase4_resolution.get("strict_event_code").cloned().unwrap_or(Value::Null),
        "phase4_resolution_fallback_fallback_reason_code": phase4_resolution.get("fallback_startup_fallback_reason_code").cloned().unwrap_or(Value::Null),
        "phase4_checks": phase4_checks,
        "failed_checks": failed_checks,
    });

    write_json(
        &output_dir.join("macos-pf-operator-acceptance-summary.json"),
        &payload,
    )?;
    write_text(
        &output_dir.join("macos-pf-operator-acceptance-summary.md"),
        &render_markdown(&payload),
    )?;
    Ok(())
}

fn load_json(path: &Path, label: &str) -> Result<Value, Box<dyn std::error::Error>> {
    if !path.is_file() {
        return Err(format!("Missing required {label}: {}", path.display()).into());
    }
    read_json(path)
}

fn load_jsonl(path: &Path, label: &str) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    if !path.is_file() {
        return Err(format!("Missing required {label}: {}", path.display()).into());
    }
    let records = read_jsonl(path)?;
    if records.is_empty() {
        return Err(format!("Empty required {label}: {}", path.display()).into());
    }
    Ok(records)
}

fn first_event<'a>(
    records: &'a [Value],
    code: &str,
) -> Result<&'a Value, Box<dyn std::error::Error>> {
    records
        .iter()
        .find(|record| str_field(record, "event_code") == Some(code))
        .ok_or_else(|| format!("Missing event_code={code}").into())
}

fn check_entry(
    passed: bool,
    rule: &str,
    detail: Option<Value>,
    failure_reason: Option<String>,
) -> Value {
    json!({
        "passed": passed,
        "rule": rule,
        "detail": detail.unwrap_or(Value::Null),
        "failure_reason": if passed {
            Value::Null
        } else {
            json!(failure_reason.unwrap_or_else(|| "check_failed".to_string()))
        },
    })
}

fn map_checks(entries: Vec<(&'static str, Value)>) -> Value {
    let mut map = Map::new();
    for (key, value) in entries {
        map.insert(key.to_string(), value);
    }
    Value::Object(map)
}

fn failed_check_ids(checks: &Value) -> Vec<String> {
    checks
        .as_object()
        .into_iter()
        .flat_map(|map| map.iter())
        .filter(|(_, data)| data.get("passed").and_then(Value::as_bool) != Some(true))
        .map(|(key, _)| key.clone())
        .collect()
}

fn render_markdown(payload: &Value) -> String {
    let mut lines = vec![
        "# macOS PF Operator Acceptance Summary".to_string(),
        String::new(),
        format!(
            "- Operator acceptance verdict: `{}`",
            str_field(payload, "operator_acceptance_verdict").unwrap_or("")
        ),
        format!(
            "- Accepted milestones: `{}`",
            payload
                .get("accepted_milestones")
                .and_then(Value::as_array)
                .map(|items| items
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", "))
                .unwrap_or_default()
        ),
        format!(
            "- Broader system-wide runtime claim: `{}`",
            str_field(payload, "broader_system_wide_runtime_claim_status").unwrap_or("")
        ),
        format!(
            "- Next required action: `{}`",
            str_field(payload, "next_required_action").unwrap_or("")
        ),
        String::new(),
        "## Phase 1 Checks".to_string(),
        String::new(),
    ];

    append_checks(&mut lines, payload.get("phase1_checks"));
    lines.extend([
        String::new(),
        "## Phase 2 Checks".to_string(),
        String::new(),
    ]);
    append_checks(&mut lines, payload.get("phase2_checks"));
    lines.extend([
        String::new(),
        "## Phase 3 Boundary Checks".to_string(),
        String::new(),
    ]);
    append_checks(&mut lines, payload.get("phase3_boundary_checks"));

    if !payload.get("phase4_checks").is_none_or(Value::is_null) {
        lines.extend([
            String::new(),
            "## Phase 4 Bind-Capable Checks (B1 gate)".to_string(),
            String::new(),
        ]);
        append_checks(&mut lines, payload.get("phase4_checks"));
    }

    if let Some(failed) = payload.get("failed_checks").and_then(Value::as_array) {
        if !failed.is_empty() {
            lines.extend([String::new(), "## Failed Checks".to_string(), String::new()]);
            lines.extend(
                failed
                    .iter()
                    .filter_map(Value::as_str)
                    .map(|check_id| format!("- `{check_id}`")),
            );
        }
    }

    lines.join("\n") + "\n"
}

fn append_checks(lines: &mut Vec<String>, checks: Option<&Value>) {
    if let Some(map) = checks.and_then(Value::as_object) {
        for (check_id, data) in map {
            lines.push(format!(
                "- `{}`: passed=`{}` detail=`{}`",
                check_id,
                data.get("passed").and_then(Value::as_bool).unwrap_or(false),
                detail_for_markdown(data.get("detail").unwrap_or(&Value::Null))
            ));
        }
    }
}

fn detail_for_markdown(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Null => "None".to_string(),
        other => other.to_string(),
    }
}

fn event_field<'a>(event: &'a Value, field: &str) -> Option<&'a str> {
    event.get("fields")?.get(field)?.as_str()
}

fn event_field_value(event: &Value, field: &str) -> Value {
    event
        .get("fields")
        .and_then(|fields| fields.get(field))
        .cloned()
        .unwrap_or(Value::Null)
}

fn str_field<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field)?.as_str()
}

fn bool_field(value: &Value, field: &str) -> Option<bool> {
    value.get(field)?.as_bool()
}
