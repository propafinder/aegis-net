use std::path::Path;

use serde_json::{json, Value};

use crate::artifact::{read_json, write_json, write_text};

pub struct StealthLiveBundleInputs<'a> {
    pub output_dir: &'a Path,
    pub wire_acceptance_summary: &'a Path,
    pub runtime_events: &'a Path,
    pub relay_runtime_events: &'a Path,
    pub config: &'a Path,
    pub polymorphism_summary: &'a Path,
    pub relay_surface_runtime_summary: &'a Path,
    pub hostile_path_summary: &'a Path,
}

pub fn build_stealth_live_acceptance_bundle(
    inputs: StealthLiveBundleInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let polymorphism = read_json(inputs.polymorphism_summary)?;
    let relay_surface_runtime = read_json(inputs.relay_surface_runtime_summary)?;
    let hostile_path = read_json(inputs.hostile_path_summary)?;
    let combined = hostile_path
        .get("combined_requirements")
        .and_then(Value::as_object)
        .ok_or("hostile_path.combined_requirements missing")?;

    let mut active_blockers = Vec::new();
    if combined.get("live_wire_green").and_then(Value::as_bool) == Some(false) {
        active_blockers.push(blocker(
            "live_wire_acceptance",
            "blocked_on_live_wire_acceptance",
            "restore_green_live_wire_host_acceptance_first",
            "wire-host acceptance summary is not green",
        ));
    }
    if combined
        .get("wire_hostile_path_ready")
        .and_then(Value::as_bool)
        == Some(false)
        || combined
            .get("independent_witness_matched")
            .and_then(Value::as_bool)
            == Some(false)
    {
        active_blockers.push(blocker(
            "witness_correlated_hostile_path_proof",
            "blocked_on_witness_correlated_hostile_path_proof",
            "collect_or_fix_independent_witness_correlation",
            "wire hostile-path proof is not witness-correlated and ready",
        ));
    }
    if combined
        .get("repo_side_polymorphism_green")
        .and_then(Value::as_bool)
        == Some(false)
    {
        active_blockers.push(blocker(
            "repo_side_polymorphism_acceptance",
            "blocked_on_repo_side_polymorphism_acceptance",
            "restore_green_polymorphism_acceptance_summary",
            "repo-side polymorphism acceptance summary is not green",
        ));
    }
    if combined
        .get("runtime_relay_surface_green")
        .and_then(Value::as_bool)
        == Some(false)
    {
        active_blockers.push(blocker(
            "runtime_relay_surface_evidence",
            "blocked_on_runtime_relay_surface_evidence",
            "restore_green_runtime_relay_surface_summary",
            "runtime relay surface summary is not green",
        ));
    }

    let (primary_blocker, bundle_status, next_action) = if active_blockers.is_empty() {
        (
            Value::Null,
            hostile_path
                .get("status")
                .cloned()
                .unwrap_or(Value::String("acceptance_degraded".to_string())),
            hostile_path
                .get("next_action")
                .cloned()
                .unwrap_or(Value::String("inspect_acceptance_inputs".to_string())),
        )
    } else {
        let primary = active_blockers[0].clone();
        if active_blockers.len() == 1 {
            (
                primary.clone(),
                primary["status"].clone(),
                primary["next_action"].clone(),
            )
        } else {
            (
                primary,
                Value::String("blocked_on_multiple_acceptance_gaps".to_string()),
                Value::String("resolve_active_acceptance_blockers_in_priority_order".to_string()),
            )
        }
    };

    let payload = json!({
        "artifact_schema": "stealth_live_acceptance_bundle_v1",
        "supported_product_contour": "post_release_stealth_live_acceptance",
        "supported_operator_scope": "live_runtime_plus_repo_acceptance_collection",
        "wire_acceptance_summary_json": inputs.wire_acceptance_summary.display().to_string(),
        "runtime_events_jsonl": inputs.runtime_events.display().to_string(),
        "relay_runtime_events_jsonl": inputs.relay_runtime_events.display().to_string(),
        "config_path": inputs.config.display().to_string(),
        "polymorphism_acceptance_summary_json": inputs.polymorphism_summary.display().to_string(),
        "relay_surface_runtime_summary_json": inputs.relay_surface_runtime_summary.display().to_string(),
        "stealth_hostile_path_acceptance_summary_json": inputs.hostile_path_summary.display().to_string(),
        "polymorphism": {
            "verdict": polymorphism.get("verdict").cloned().unwrap_or(Value::Null),
            "status": polymorphism.get("status").cloned().unwrap_or(Value::Null),
        },
        "relay_surface_runtime": {
            "verdict": relay_surface_runtime.get("verdict").cloned().unwrap_or(Value::Null),
            "status": relay_surface_runtime.get("status").cloned().unwrap_or(Value::Null),
            "relay_events_scanned": relay_surface_runtime.get("relay_events_scanned").cloned().unwrap_or(Value::Null),
            "relay_events_missing_surface": relay_surface_runtime.get("relay_events_missing_surface").cloned().unwrap_or(Value::Null),
        },
        "hostile_path_acceptance": {
            "verdict": hostile_path.get("verdict").cloned().unwrap_or(Value::Null),
            "status": hostile_path.get("status").cloned().unwrap_or(Value::Null),
            "next_action": hostile_path.get("next_action").cloned().unwrap_or(Value::Null),
        },
        "blocking_requirements": combined,
        "active_blockers": active_blockers,
        "primary_blocker": primary_blocker,
        "bundle_status": bundle_status,
        "bundle_verdict": hostile_path.get("verdict").cloned().unwrap_or(Value::Null),
        "next_action": next_action,
    });

    let bundle_json = inputs
        .output_dir
        .join("stealth-live-acceptance-bundle.json");
    write_json(&bundle_json, &payload)?;

    let manifest = json!({
        "artifact_schema": "stealth_live_acceptance_bundle_manifest_v1",
        "supported_product_contour": payload["supported_product_contour"].clone(),
        "supported_operator_scope": payload["supported_operator_scope"].clone(),
        "bundle_json": bundle_json.display().to_string(),
        "wire_acceptance_summary_json": payload["wire_acceptance_summary_json"].clone(),
        "runtime_events_jsonl": payload["runtime_events_jsonl"].clone(),
        "relay_runtime_events_jsonl": payload["relay_runtime_events_jsonl"].clone(),
        "polymorphism_acceptance_summary_json": payload["polymorphism_acceptance_summary_json"].clone(),
        "relay_surface_runtime_summary_json": payload["relay_surface_runtime_summary_json"].clone(),
        "stealth_hostile_path_acceptance_summary_json": payload["stealth_hostile_path_acceptance_summary_json"].clone(),
        "active_blockers": payload["active_blockers"].clone(),
        "primary_blocker": payload["primary_blocker"].clone(),
        "bundle_status": payload["bundle_status"].clone(),
        "bundle_verdict": payload["bundle_verdict"].clone(),
        "next_action": payload["next_action"].clone(),
    });
    write_json(
        &inputs
            .output_dir
            .join("stealth-live-acceptance.manifest.json"),
        &manifest,
    )?;
    write_text(
        &inputs.output_dir.join("stealth-live-acceptance-bundle.md"),
        &markdown(&payload),
    )?;
    Ok(())
}

fn blocker(id: &str, status: &str, next_action: &str, detail: &str) -> Value {
    json!({
        "id": id,
        "status": status,
        "next_action": next_action,
        "detail": detail,
    })
}

fn markdown(payload: &Value) -> String {
    let mut lines = vec![
        "# Stealth Live Acceptance Bundle".to_string(),
        "".to_string(),
        format!("- Bundle verdict: `{}`", s(&payload["bundle_verdict"])),
        format!("- Bundle status: `{}`", s(&payload["bundle_status"])),
        format!(
            "- Polymorphism verdict: `{}`",
            s(&payload["polymorphism"]["verdict"])
        ),
        format!(
            "- Relay runtime verdict: `{}`",
            s(&payload["relay_surface_runtime"]["verdict"])
        ),
        format!(
            "- Hostile-path acceptance verdict: `{}`",
            s(&payload["hostile_path_acceptance"]["verdict"])
        ),
        format!("- Next action: `{}`", s(&payload["next_action"])),
        "".to_string(),
        "## Active Blockers".to_string(),
        "".to_string(),
    ];
    if let Some(blockers) = payload["active_blockers"].as_array() {
        if blockers.is_empty() {
            lines.push("- `none`".to_string());
        } else {
            for blocker in blockers {
                lines.push(format!(
                    "- `{}`: `{}` -> `{}`",
                    s(&blocker["id"]),
                    s(&blocker["status"]),
                    s(&blocker["next_action"])
                ));
            }
        }
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
            "- `runtime_events_jsonl`: `{}`",
            s(&payload["runtime_events_jsonl"])
        ),
        format!("- `config_path`: `{}`", s(&payload["config_path"])),
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
