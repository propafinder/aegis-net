use std::path::Path;

use serde_json::{json, Value};

use crate::artifact::{read_optional_json_path, write_json, write_text};

const CURRENT_ENTRYPOINTS: &[&str] = &[
    "scripts/validate-mimicry-wire-host.sh",
    "scripts/build-mimicry-wire-witness-summary.sh",
    "scripts/build-relay-surface-runtime-summary.sh",
    "scripts/build-stealth-polymorphism-acceptance-summary.sh",
    "scripts/build-stealth-hostile-path-acceptance-summary.sh",
    "scripts/build-stealth-live-acceptance-bundle.sh",
    "scripts/mimicry-wire-validation-contract.sh",
];

const NEXT_TRACKS: &[&str] = &[
    "witness_maturity_and_correlation_discipline",
    "linux_wire_mimicry_execution_contour",
    "transport_camouflage_and_stronger_anti_dpi_behaviors",
    "later_capture_unification_af_packet_or_libpcap_sidecar",
];

const NOT_RELEASE_BLOCKERS: &[&str] = &[
    "full_packet_impersonation",
    "universal_linux_family_coverage",
    "macos_windows_client_parity",
    "deep_research_bypass_tracks",
];

pub fn build_post_release_stealth_wave_summary(
    output_dir: &Path,
    ubuntu_release_wave_status: Option<&Path>,
    wire_acceptance_summary: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let release_wave_status = read_optional_json_path(ubuntu_release_wave_status)?;
    let wire_acceptance = read_optional_json_path(wire_acceptance_summary)?;

    let wire_verdict = wire_acceptance
        .as_ref()
        .map(|value| first_string(value, &["verdict", "product_verdict"]).to_lowercase())
        .unwrap_or_default();
    let wire_ready = matches!(wire_verdict.as_str(), "green" | "ready" | "proven");
    let wire_degraded = matches!(wire_verdict.as_str(), "degraded" | "yellow");
    let release_ready = bool_field(&release_wave_status, "ship_ready");
    let bypass_ready = bool_field(&release_wave_status, "bypass_ready");
    let fully_proven = bool_field(&release_wave_status, "fully_proven");

    let current_milestone = "witness_maturity_and_correlation_discipline";
    let (current_milestone_state, current_milestone_next_action) =
        if !(release_ready && bypass_ready && fully_proven) {
            (
                "blocked_on_ubuntu_release_prerequisite",
                "complete_fully_proven_ubuntu_release_wave_first",
            )
        } else if wire_acceptance.is_none() {
            (
                "ready_to_collect_witness_evidence",
                "collect_wire_acceptance_summary_for_witness_maturity",
            )
        } else if wire_ready {
            (
                "witness_evidence_green",
                "open_linux_wire_mimicry_execution_contour",
            )
        } else if wire_degraded {
            (
                "witness_evidence_degraded",
                "tighten_witness_correlation_and_acceptance_discipline",
            )
        } else {
            (
                "witness_evidence_red",
                "fix_wire_acceptance_before_stealth_execution",
            )
        };

    let bypass_support_tier = release_wave_status
        .as_ref()
        .and_then(|value| value["bypass_support_tier"].as_str())
        .unwrap_or("");
    let prerequisite_satisfied = release_ready
        && bypass_ready
        && fully_proven
        && (wire_ready || bypass_support_tier == "wire_level_supported_hostile_path");
    let (status, prereq_state) = if prerequisite_satisfied {
        ("ready_after_proven_ubuntu_bypass_and_wire", "satisfied")
    } else {
        ("blocked_on_ubuntu_bypass_and_wire", "missing_or_degraded")
    };

    let payload = json!({
        "artifact_schema": "post_release_stealth_wave_v1",
        "supported_product_contour": "post_release_stealth_growth",
        "supported_operator_scope": "post_release_mimicry_and_anti_dpi_planning",
        "release_prerequisite": "ubuntu_live_bypass_proven_with_working_wire_support",
        "ubuntu_release_wave_status_json": ubuntu_release_wave_status.map(|path| path.display().to_string()),
        "wire_acceptance_summary_json": wire_acceptance_summary.map(|path| path.display().to_string()),
        "prerequisite_state": prereq_state,
        "release_boundary": {
            "not_release_blockers": NOT_RELEASE_BLOCKERS,
            "separate_truth_layer": true,
        },
        "current_entrypoints": CURRENT_ENTRYPOINTS,
        "current_milestone": current_milestone,
        "current_milestone_state": current_milestone_state,
        "current_milestone_next_action": current_milestone_next_action,
        "next_tracks": NEXT_TRACKS,
        "status": status,
    });

    write_json(&output_dir.join("stealth-wave-summary.json"), &payload)?;
    write_text(
        &output_dir.join("stealth-wave-summary.md"),
        &markdown(&payload),
    )?;
    Ok(())
}

fn bool_field(value: &Option<Value>, field: &str) -> bool {
    value.as_ref().and_then(|value| value[field].as_bool()) == Some(true)
}

fn first_string(value: &Value, fields: &[&str]) -> String {
    fields
        .iter()
        .find_map(|field| value.get(field).and_then(Value::as_str))
        .unwrap_or("")
        .to_string()
}

fn markdown(payload: &Value) -> String {
    let mut lines = vec![
        "# Post-Release Stealth Wave".to_string(),
        "".to_string(),
        format!(
            "- Release prerequisite: `{}`",
            s(&payload["release_prerequisite"])
        ),
        format!(
            "- Prerequisite state: `{}`",
            s(&payload["prerequisite_state"])
        ),
        format!("- Status: `{}`", s(&payload["status"])),
        format!(
            "- Current milestone: `{}`",
            s(&payload["current_milestone"])
        ),
        format!(
            "- Milestone state: `{}`",
            s(&payload["current_milestone_state"])
        ),
        format!(
            "- Milestone next action: `{}`",
            s(&payload["current_milestone_next_action"])
        ),
        "".to_string(),
        "## Current Entrypoints".to_string(),
        "".to_string(),
    ];
    extend_string_list(&mut lines, &payload["current_entrypoints"]);
    lines.extend(["".to_string(), "## Next Tracks".to_string(), "".to_string()]);
    extend_string_list(&mut lines, &payload["next_tracks"]);
    lines.extend([
        "".to_string(),
        "## Release Boundary".to_string(),
        "".to_string(),
    ]);
    extend_string_list(
        &mut lines,
        &payload["release_boundary"]["not_release_blockers"],
    );
    lines.join("\n") + "\n"
}

fn extend_string_list(lines: &mut Vec<String>, value: &Value) {
    if let Some(items) = value.as_array() {
        for item in items {
            lines.push(format!("- `{}`", s(item)));
        }
    }
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
