use serde_json::Value;

use super::support::{ensure, handoff_phase_c_prerequisites_ready, join_object_keys, join_strings};

pub fn master_plan_handoff_markdown(handoff: &Value) -> String {
    format!(
        "# Master Plan Handoff\n\n\
         - Status: `{}`\n\
         - Phase C ready: `{}`\n\
         - Phase D ready: `{}`\n\
         - Primary layer: `{}`\n\
         - Next action: `{}`\n\
         - Reason: `{}`\n\
         - Command: `{}`\n\
         - Expected artifact: `{}`\n\
         - Follow-up command: `{}`\n\
         - Expected follow-up artifact: `{}`\n\
         - Phase C follow-up prerequisites ready: `{}`\n\
         - Ready for live command after external inputs: `{}`\n\
         - Command placeholder free: `{}`\n\
         - Follow-up command placeholder free: `{}`\n\
         - Android status: `{}`\n\
         - macOS NetworkExtension status: `{}`\n\
         - Desktop/core completion allowed: `{}`\n\
         - Ubuntu wide latest/stable: `{}`\n\
         - Full mimicry score/matrix: `{}`\n\
         - Brain operational loop: `{}`\n\
         - External inputs: `{}`\n\
         - Phase C blockers: `{}`\n\
         - Phase D blockers: `{}`\n",
        handoff["status"].as_str().unwrap_or("UNKNOWN"),
        handoff["phase_c_ready"].as_bool().unwrap_or(false),
        handoff["phase_d_ready"].as_bool().unwrap_or(false),
        handoff["primary_layer"].as_str().unwrap_or("unknown"),
        handoff["next_action"]["id"].as_str().unwrap_or("unknown"),
        handoff["next_action"]["reason"]
            .as_str()
            .unwrap_or("unknown"),
        handoff["next_action"]["command"]
            .as_str()
            .unwrap_or("unknown"),
        handoff["next_action"]["expected_artifact"]
            .as_str()
            .unwrap_or("unknown"),
        handoff["next_action"]["followup_command"]
            .as_str()
            .unwrap_or(""),
        handoff["next_action"]["expected_followup_artifact"]
            .as_str()
            .unwrap_or(""),
        handoff_phase_c_prerequisites_ready(handoff),
        handoff["ready_for_live_command"].as_bool().unwrap_or(false),
        handoff["next_action"]["command_placeholder_free"]
            .as_bool()
            .unwrap_or(false),
        handoff["next_action"]["followup_command_placeholder_free"]
            .as_bool()
            .unwrap_or(false),
        handoff["platform_reach_policy"]["android"]["status"]
            .as_str()
            .unwrap_or("UNKNOWN"),
        handoff["platform_reach_policy"]["macos_networkextension"]["status"]
            .as_str()
            .unwrap_or("UNKNOWN"),
        handoff["desktop_core_completion"]["allowed"]
            .as_bool()
            .unwrap_or(false),
        handoff["desktop_core_completion"]["ubuntu_wide_latest_stable"]
            .as_str()
            .unwrap_or("UNKNOWN"),
        handoff["desktop_core_completion"]["full_mimicry_score_matrix"]
            .as_str()
            .unwrap_or("UNKNOWN"),
        handoff["desktop_core_completion"]["brain_operational_loop"]
            .as_str()
            .unwrap_or("UNKNOWN"),
        join_object_keys(&handoff["external_inputs"]["phase_c_fronted_live"]),
        join_strings(&handoff["phase_c_blockers"]),
        join_strings(&handoff["phase_d_blockers"]),
    )
}

pub fn master_plan_handoff_check(handoff: &Value) -> Result<(), Box<dyn std::error::Error>> {
    ensure(
        handoff["event"].as_str() == Some("master_plan_handoff"),
        "handoff event",
    )?;
    ensure(
        handoff["schema_version"].as_u64() == Some(1),
        "handoff schema_version",
    )?;
    ensure(
        matches!(
            handoff["status"].as_str(),
            Some("ACTION_REQUIRED") | Some("READY_FOR_NEXT_PHASE")
        ),
        "handoff status",
    )?;
    ensure(
        handoff["next_action"]["id"]
            .as_str()
            .is_some_and(|value| !value.trim().is_empty()),
        "handoff next action id",
    )?;
    ensure(
        handoff["next_action"]["command"]
            .as_str()
            .is_some_and(|value| !value.trim().is_empty()),
        "handoff next action command",
    )?;

    if handoff["next_action"]["id"].as_str()
        == Some("run_fronted_provider_preflight_then_two_vps_live")
    {
        ensure(
            handoff_phase_c_prerequisites_ready(handoff),
            "phase c follow-up prerequisites ready",
        )?;
        let followup = handoff["next_action"]["followup_command"]
            .as_str()
            .unwrap_or("");
        ensure(
            followup.contains("scripts/run-phase-c-fronted-transport-two-vps-live.sh"),
            "phase c fronted follow-up command",
        )?;
        ensure(
            handoff["next_action"]["command_placeholder_free"].as_bool() == Some(false),
            "phase c fronted command is template",
        )?;
        ensure(
            handoff["next_action"]["followup_command_placeholder_free"].as_bool() == Some(false),
            "phase c fronted follow-up command is template",
        )?;
        ensure(
            handoff["next_action"]["requires_external_inputs"].as_bool() == Some(true),
            "phase c fronted requires external inputs",
        )?;
        ensure(
            followup.contains("--phase-b-score-parity-json")
                && followup.contains("--multi-relay-json")
                && followup.contains("--bundle-mirrors-json"),
            "phase c fronted follow-up gate inputs",
        )?;
        ensure(
            handoff["next_action"]["expected_followup_artifact"]
                .as_str()
                .is_some_and(|value| value.ends_with("phase-c-fronted-transport-evidence.json")),
            "phase c fronted expected follow-up artifact",
        )?;
        let Some(external_inputs) = handoff["external_inputs"]["phase_c_fronted_live"].as_object()
        else {
            return Err("contract assertion failed: phase c external inputs".into());
        };
        for key in [
            "relay_vps",
            "client_vps",
            "ssh_user",
            "bundle_archive",
            "provider_fronted_authority",
            "provider_edge_host",
            "provider_constraints_doc",
            "origin_relay_address",
        ] {
            let Some(input) = external_inputs.get(key) else {
                return Err(
                    format!("contract assertion failed: missing external input {key}").into(),
                );
            };
            ensure(
                input["required"].as_bool() == Some(true),
                &format!("external input required: {key}"),
            )?;
            ensure(
                input["provided_by_repo"].as_bool() == Some(false),
                &format!("external input not repo-provided: {key}"),
            )?;
        }
    }
    if handoff["next_action"]["id"].as_str() == Some("windows_service_reboot_verify_after_reboot") {
        ensure(
            handoff["next_action"]["expected_followup_artifact"]
                .as_str()
                .is_some_and(|value| value.ends_with("release-latest-parity-gate/result.json")),
            "windows reboot follow-up points to release latest parity gate",
        )?;
    }
    ensure(
        handoff["desktop_core_completion"]["allowed"].as_bool() == Some(false),
        "desktop/core completion must remain false until required next gates close",
    )?;
    Ok(())
}
