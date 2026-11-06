use std::path::Path;

use serde_json::{json, Value};

use crate::artifact::{read_json, write_json, write_text};

pub fn build_stealth_hostile_path_acceptance_summary(
    output_dir: &Path,
    wire_acceptance_summary: &Path,
    polymorphism_acceptance_summary: &Path,
    relay_surface_runtime_summary: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let wire = read_json(wire_acceptance_summary)?;
    let polymorphism = read_json(polymorphism_acceptance_summary)?;
    let relay_surface_runtime = relay_surface_runtime_summary.map(read_json).transpose()?;

    let wire_verdict = lower_first(&wire, &["product_verdict", "verdict"]);
    let wire_status = lower_first(&wire, &["acceptance_status", "status"]);
    let wire_hostile_path_ready = wire["hostile_path_support_ready"].as_bool() == Some(true);
    let wire_witness_matched =
        lower_first(&wire, &["independent_witness_correlation_status"]) == "matched";
    let wire_green =
        wire_verdict == "green" && matches!(wire_status.as_str(), "passed" | "green" | "ready");

    let poly_verdict = lower_first(&polymorphism, &["verdict"]);
    let poly_status = lower_first(&polymorphism, &["status"]);
    let poly_green = poly_verdict == "green"
        && matches!(poly_status.as_str(), "acceptance_green" | "green" | "ready");

    let relay_runtime_verdict = relay_surface_runtime
        .as_ref()
        .map(|value| lower_first(value, &["verdict"]))
        .unwrap_or_default();
    let relay_runtime_status = relay_surface_runtime
        .as_ref()
        .map(|value| lower_first(value, &["status"]))
        .unwrap_or_default();
    let relay_runtime_green = relay_surface_runtime.is_some()
        && relay_runtime_verdict == "green"
        && matches!(
            relay_runtime_status.as_str(),
            "runtime_surface_green" | "green" | "ready" | "passed"
        );

    let (verdict, status, next_action) = if wire_green
        && wire_hostile_path_ready
        && wire_witness_matched
        && poly_green
        && relay_surface_runtime.is_some()
        && relay_runtime_green
    {
        (
            "green",
            "ready_for_runtime_surface_hostile_path_validation",
            "open_runtime_surface_correlated_transport_camouflage_validation",
        )
    } else if wire_green
        && wire_hostile_path_ready
        && wire_witness_matched
        && poly_green
        && relay_surface_runtime.is_some()
        && !relay_runtime_green
    {
        (
            "yellow",
            "blocked_on_runtime_relay_surface_evidence",
            "restore_green_runtime_relay_surface_summary",
        )
    } else if wire_green && wire_hostile_path_ready && wire_witness_matched && poly_green {
        (
            "green",
            "ready_for_transport_camouflage_live_acceptance",
            "open_transport_camouflage_and_stronger_live_anti_dpi_acceptance",
        )
    } else if !wire_green {
        (
            "yellow",
            "blocked_on_live_wire_acceptance",
            "restore_green_live_wire_host_acceptance_first",
        )
    } else if !wire_hostile_path_ready || !wire_witness_matched {
        (
            "yellow",
            "blocked_on_witness_correlated_hostile_path_proof",
            "collect_or_fix_independent_witness_correlation",
        )
    } else if !poly_green {
        (
            "yellow",
            "blocked_on_repo_side_polymorphism_acceptance",
            "restore_green_polymorphism_acceptance_summary",
        )
    } else {
        (
            "yellow",
            "acceptance_degraded",
            "inspect_wire_and_polymorphism_acceptance_inputs",
        )
    };

    let payload = json!({
        "artifact_schema": "stealth_hostile_path_acceptance_summary_v1",
        "verdict": verdict,
        "status": status,
        "scope": "post_release_stealth_live_plus_repo_acceptance",
        "wire_acceptance_summary_json": wire_acceptance_summary.display().to_string(),
        "polymorphism_acceptance_summary_json": polymorphism_acceptance_summary.display().to_string(),
        "relay_surface_runtime_summary_json": relay_surface_runtime_summary.map(|path| path.display().to_string()),
        "wire": {
            "product_verdict": wire.get("product_verdict").cloned().unwrap_or(Value::Null),
            "acceptance_status": wire.get("acceptance_status").cloned().unwrap_or(Value::Null),
            "hostile_path_support_ready": wire.get("hostile_path_support_ready").cloned().unwrap_or(Value::Null),
            "hostile_path_support_tier": wire.get("hostile_path_support_tier").cloned().unwrap_or(Value::Null),
            "independent_witness_correlation_status": wire.get("independent_witness_correlation_status").cloned().unwrap_or(Value::Null),
            "active_runtime_records_with_required_ready_fields": wire.get("active_runtime_records_with_required_ready_fields").cloned().unwrap_or(Value::Null),
            "active_runtime_records_missing_required_ready_fields": wire.get("active_runtime_records_missing_required_ready_fields").cloned().unwrap_or(Value::Null),
        },
        "polymorphism": {
            "verdict": polymorphism.get("verdict").cloned().unwrap_or(Value::Null),
            "status": polymorphism.get("status").cloned().unwrap_or(Value::Null),
            "checks": polymorphism.get("checks").cloned().unwrap_or(Value::Null),
        },
        "relay_surface_runtime": {
            "verdict": optional_field(&relay_surface_runtime, "verdict"),
            "status": optional_field(&relay_surface_runtime, "status"),
            "relay_events_scanned": optional_field(&relay_surface_runtime, "relay_events_scanned"),
            "relay_events_with_complete_surface": optional_field(&relay_surface_runtime, "relay_events_with_complete_surface"),
            "relay_events_missing_surface": optional_field(&relay_surface_runtime, "relay_events_missing_surface"),
            "checks": optional_field(&relay_surface_runtime, "checks"),
        },
        "combined_requirements": {
            "live_wire_green": wire_green,
            "wire_hostile_path_ready": wire_hostile_path_ready,
            "independent_witness_matched": wire_witness_matched,
            "repo_side_polymorphism_green": poly_green,
            "runtime_relay_surface_green": relay_surface_runtime.as_ref().map(|_| relay_runtime_green),
        },
        "next_action": next_action,
    });

    write_json(
        &output_dir.join("stealth-hostile-path-acceptance-summary.json"),
        &payload,
    )?;
    write_text(
        &output_dir.join("stealth-hostile-path-acceptance-summary.md"),
        &markdown(&payload),
    )?;
    Ok(())
}

fn lower_first(value: &Value, fields: &[&str]) -> String {
    fields
        .iter()
        .find_map(|field| value.get(field).and_then(Value::as_str))
        .unwrap_or("")
        .to_lowercase()
}

fn optional_field(value: &Option<Value>, field: &str) -> Value {
    value
        .as_ref()
        .and_then(|value| value.get(field))
        .cloned()
        .unwrap_or(Value::Null)
}

fn markdown(payload: &Value) -> String {
    let combined = &payload["combined_requirements"];
    let mut lines = vec![
        "# Stealth Hostile-Path Acceptance".to_string(),
        "".to_string(),
        format!("- Verdict: `{}`", s(&payload["verdict"])),
        format!("- Status: `{}`", s(&payload["status"])),
        format!("- Scope: `{}`", s(&payload["scope"])),
        format!(
            "- Wire product verdict: `{}`",
            s(&payload["wire"]["product_verdict"])
        ),
        format!(
            "- Hostile-path support tier: `{}`",
            s(&payload["wire"]["hostile_path_support_tier"])
        ),
        format!(
            "- Witness correlation: `{}`",
            s(&payload["wire"]["independent_witness_correlation_status"])
        ),
        format!(
            "- Polymorphism verdict: `{}`",
            s(&payload["polymorphism"]["verdict"])
        ),
        format!(
            "- Runtime relay surface verdict: `{}`",
            s(&payload["relay_surface_runtime"]["verdict"])
        ),
        format!("- Next action: `{}`", s(&payload["next_action"])),
        "".to_string(),
        "## Combined Requirements".to_string(),
        "".to_string(),
    ];
    for key in [
        "live_wire_green",
        "wire_hostile_path_ready",
        "independent_witness_matched",
        "repo_side_polymorphism_green",
        "runtime_relay_surface_green",
    ] {
        lines.push(format!("- `{key}`: `{}`", s(&combined[key])));
    }
    lines.extend([
        "".to_string(),
        "## Inputs".to_string(),
        "".to_string(),
        format!(
            "- `wire_acceptance_summary_json`: `{}`",
            s(&payload["wire_acceptance_summary_json"])
        ),
        format!(
            "- `polymorphism_acceptance_summary_json`: `{}`",
            s(&payload["polymorphism_acceptance_summary_json"])
        ),
        format!(
            "- `relay_surface_runtime_summary_json`: `{}`",
            s(&payload["relay_surface_runtime_summary_json"])
        ),
    ]);
    lines.join("\n") + "\n"
}

fn s(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::Null => "none".to_string(),
        _ => value.to_string(),
    }
}
