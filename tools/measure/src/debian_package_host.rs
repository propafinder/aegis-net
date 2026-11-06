use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};

use crate::artifact::{read_json, read_jsonl, write_json};

pub struct DebianPackageHostRunSummaryInputs<'a> {
    pub output: &'a Path,
    pub operator_loop_summary: Option<&'a Path>,
    pub validation_root: &'a str,
    pub upgrade_reapply_mode: &'a str,
    pub phase: &'a [String],
}

pub struct DebianPackageHostOperatorLoopSummaryInputs<'a> {
    pub output: &'a Path,
    pub client_config: &'a Path,
    pub runtime_events: &'a str,
    pub preflight_json: &'a Path,
    pub startup_probe_json: &'a Path,
    pub events_summary_json: &'a Path,
    pub operator_evidence_json: &'a Path,
    pub operator_evidence_txt: &'a str,
}

pub struct DebianPackageHostReleaseGateHandoffInputs<'a> {
    pub output: &'a Path,
    pub host_summary: &'a Path,
}

pub struct DebianPackageHostReleaseSummaryInputs<'a> {
    pub output: &'a Path,
    pub host_summary: &'a Path,
    pub release_handoff: &'a Path,
    pub operator_loop_summary: &'a Path,
}

pub struct DebianPackageHostPilotInputsInputs<'a> {
    pub output: &'a Path,
    pub validation_summary: &'a Path,
    pub runtime_artifacts_dir: &'a Path,
    pub release_handoff: &'a Path,
    pub release_summary: &'a Path,
    pub operator_loop_summary: &'a Path,
}

pub struct DebianPackageHostDpkgStateInputs<'a> {
    pub dpkg_query: &'a Path,
    pub validation_root: &'a Path,
}

pub struct DebianPackageHostClientJsonArtifactInputs<'a> {
    pub artifact: &'a Path,
    pub exit_status: i32,
}

pub struct DebianPackageHostRuntimeEventsSummaryInputs<'a> {
    pub runtime_events: &'a Path,
    pub output: &'a Path,
}

pub struct DebianPackageHostContractJsonCaseInputs<'a> {
    pub scenario: &'a str,
    pub output: &'a Path,
    pub exit_status: i32,
}

pub struct DebianPackageHostContractRunModeInputs<'a> {
    pub output: &'a Path,
    pub validation_summary: &'a Path,
    pub release_handoff: &'a Path,
    pub release_summary: &'a Path,
    pub pilot_inputs: &'a Path,
    pub operator_loop: &'a Path,
    pub dpkg_log: &'a Path,
    pub helper_log: &'a Path,
    pub exit_status: i32,
    pub validation_root: &'a Path,
}

pub struct DebianPackageHostContractScriptInputs<'a> {
    pub script: &'a Path,
}

pub struct DpkgLifecycleSmokeStateInputs<'a> {
    pub phase: &'a str,
    pub rootdir: &'a Path,
    pub status_path: &'a Path,
    pub hook_log: &'a Path,
}

pub struct DebianPackageHostValidationReportInputs<'a> {
    pub mode: &'a str,
    pub os_pretty_name: &'a str,
    pub os_id: &'a str,
    pub os_version_id: Option<&'a str>,
    pub package_manager: Option<&'a str>,
    pub supported_product_contour: &'a str,
    pub supported_operator_scope: &'a str,
    pub release_gate_name: &'a str,
    pub release_gate_scope: &'a str,
    pub host_family_id: &'a str,
    pub host_family_validation_tier: &'a str,
    pub ready: bool,
    pub release_gate_required_phase: &'a [String],
    pub command: &'a [String],
    pub missing_command: &'a [String],
    pub remediation_command: &'a str,
    pub run_command: &'a str,
    pub artifact_dir: Option<&'a str>,
    pub release_handoff_artifact: Option<&'a str>,
    pub release_summary_artifact: Option<&'a str>,
    pub operator_loop_summary_artifact: Option<&'a str>,
    pub pilot_inputs_artifact: Option<&'a str>,
    pub validation_root: &'a str,
    pub helper_exit_code: Option<i32>,
    pub error_code: Option<&'a str>,
}

pub fn build_debian_package_host_validation_report(
    inputs: DebianPackageHostValidationReportInputs<'_>,
) -> Result<Value, Box<dyn std::error::Error>> {
    let commands = inputs
        .command
        .iter()
        .map(|entry| parse_command_status_entry(entry))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(json!({
        "artifact_schema": "debian_package_host_validation_v1",
        "mode": inputs.mode,
        "os_pretty_name": inputs.os_pretty_name,
        "os_id": inputs.os_id,
        "os_version_id": non_empty_or_null(inputs.os_version_id),
        "package_manager": non_empty_or_null(inputs.package_manager),
        "supported_product_contour": inputs.supported_product_contour,
        "supported_operator_scope": inputs.supported_operator_scope,
        "release_gate_name": inputs.release_gate_name,
        "release_gate_scope": inputs.release_gate_scope,
        "release_gate_blocks_release": true,
        "host_family_id": inputs.host_family_id,
        "host_family_validation_tier": inputs.host_family_validation_tier,
        "ready": inputs.ready,
        "release_gate_required_phases": inputs.release_gate_required_phase,
        "commands": commands,
        "missing_commands": inputs.missing_command,
        "remediation_command": inputs.remediation_command,
        "run_command": inputs.run_command,
        "artifact_dir": non_empty_or_null(inputs.artifact_dir),
        "release_handoff_artifact": non_empty_or_null(inputs.release_handoff_artifact),
        "release_summary_artifact": non_empty_or_null(inputs.release_summary_artifact),
        "operator_loop_summary_artifact": non_empty_or_null(inputs.operator_loop_summary_artifact),
        "pilot_inputs_artifact": non_empty_or_null(inputs.pilot_inputs_artifact),
        "validation_root": inputs.validation_root,
        "helper_exit_code": inputs.helper_exit_code,
        "error_code": non_empty_or_null(inputs.error_code),
    }))
}

pub fn build_debian_package_host_run_summary(
    inputs: DebianPackageHostRunSummaryInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let phases = inputs
        .phase
        .iter()
        .map(parse_phase_entry)
        .collect::<Result<Vec<_>, _>>()?;
    let operator_loop = inputs
        .operator_loop_summary
        .filter(|path| path.is_file())
        .map(read_json)
        .transpose()?
        .unwrap_or_else(|| json!({}));

    let service_health_verdict = string_field(&operator_loop, "service_health_verdict")
        .or_else(|| string_field(&operator_loop, "overall_status"))
        .unwrap_or_else(|| "unknown".to_owned());
    let bypass_ready = bool_field(&operator_loop, "bypass_ready");
    let bypass_verdict = string_field(&operator_loop, "bypass_verdict")
        .unwrap_or_else(|| if bypass_ready { "proven" } else { "not_proven" }.to_owned());
    let bypass_support_tier = string_field(&operator_loop, "bypass_support_tier")
        .unwrap_or_else(|| "not_proven".to_owned());
    let bypass_blocker_reason = value_or_null(&operator_loop, "bypass_blocker_reason");
    let baseline_bypass_verdict = string_field(&operator_loop, "baseline_bypass_verdict")
        .unwrap_or_else(|| bypass_verdict.clone());
    let baseline_bypass_ready = operator_loop
        .get("baseline_bypass_ready")
        .and_then(Value::as_bool)
        .unwrap_or(bypass_ready);
    let baseline_bypass_blocker_reason = operator_loop
        .get("baseline_bypass_blocker_reason")
        .cloned()
        .filter(|value| !value.is_null())
        .unwrap_or_else(|| bypass_blocker_reason.clone());
    let hostile_path_verdict = string_field(&operator_loop, "hostile_path_verdict")
        .unwrap_or_else(|| "missing_evidence".to_owned());
    let hostile_path_ready = bool_field(&operator_loop, "hostile_path_ready");
    let hostile_path_blocker_reason = operator_loop
        .get("hostile_path_blocker_reason")
        .cloned()
        .filter(|value| !value.is_null())
        .unwrap_or_else(|| json!("hostile_path_evidence_missing"));
    let dns_runtime_ready = bool_field(&operator_loop, "dns_runtime_ready");

    let payload = json!({
        "artifact_schema": "debian_package_host_run_summary_v2",
        "release_gate_name": "ubuntu_first_product_release_gate",
        "release_gate_scope": "ubuntu_first_product_candidate",
        "release_gate_blocks_release": true,
        "release_gate_status": "passed",
        "ship_decision": if bypass_ready { "ship" } else { "hold" },
        "product_verdict": service_health_verdict,
        "service_health_verdict": service_health_verdict,
        "operator_loop_summary_json": inputs.operator_loop_summary.filter(|path| path.is_file()).map(display_path),
        "bypass_verdict": bypass_verdict,
        "bypass_ready": bypass_ready,
        "bypass_support_tier": bypass_support_tier,
        "bypass_blocker_reason": bypass_blocker_reason,
        "baseline_bypass_verdict": baseline_bypass_verdict,
        "baseline_bypass_ready": baseline_bypass_ready,
        "baseline_bypass_blocker_reason": baseline_bypass_blocker_reason,
        "hostile_path_verdict": hostile_path_verdict,
        "hostile_path_ready": hostile_path_ready,
        "hostile_path_blocker_reason": hostile_path_blocker_reason,
        "hostile_path_evidence_required": true,
        "fully_proven": bool_field(&operator_loop, "fully_proven"),
        "dns_support_tier": value_or_null(&operator_loop, "dns_support_tier"),
        "dns_runtime_verdict": value_or_null(&operator_loop, "dns_runtime_verdict"),
        "dns_runtime_ready": dns_runtime_ready,
        "dns_runtime_blocker_reason": value_or_null(&operator_loop, "dns_runtime_blocker_reason"),
        "lifecycle_phases": phases.iter().map(|phase| phase["name"].clone()).collect::<Vec<_>>(),
        "required_lifecycle_phases": required_lifecycle_phases(),
        "required_runtime_artifacts": required_runtime_artifacts(),
        "related_release_artifacts": [
            "ubuntu-release-gate-handoff.json",
            "ubuntu-product-release-summary.json",
            "ubuntu-controlled-pilot-inputs.json",
        ],
        "phase_results": phases,
        "expected_units": ["aegis-server.service", "aegis-client.service"],
        "expected_packages": ["aegis-server", "aegis-client"],
        "validation_root": inputs.validation_root,
        "upgrade_reapply_mode": inputs.upgrade_reapply_mode,
    });
    write_json(inputs.output, &payload)?;
    Ok(())
}

pub fn build_debian_package_host_operator_loop_summary(
    inputs: DebianPackageHostOperatorLoopSummaryInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let preflight = read_json_maybe_wrapped(inputs.preflight_json)?;
    let startup_probe = read_json_maybe_wrapped(inputs.startup_probe_json)?;
    let events_summary = read_json(inputs.events_summary_json)?;
    let operator_evidence = read_json(inputs.operator_evidence_json)?;
    let client_cfg: toml::Value = toml::from_str(&std::fs::read_to_string(inputs.client_config)?)?;
    let wide_cfg = client_cfg
        .get("ingress")
        .and_then(|value| value.get("wide"))
        .cloned()
        .unwrap_or(toml::Value::Table(Default::default()));

    let preflight_ok = preflight.get("status").and_then(Value::as_str) == Some("ok");
    let startup_ok = startup_probe.get("status").and_then(Value::as_str) == Some("ok");
    let product_verdict = string_field(&operator_evidence, "product_verdict");
    let runtime_status = string_field(&operator_evidence, "runtime_status");
    let startup_health = string_field(&operator_evidence, "startup_health");
    let runtime_degradation_count = int_field(&operator_evidence, "runtime_degradation_count");
    let failover_count = int_field(&operator_evidence, "failover_count");
    let terminal_failure_count = int_field(&operator_evidence, "terminal_failure_count");
    let backend = string_field(&operator_evidence, "backend");

    let overall_status =
        if preflight_ok && startup_ok && product_verdict.as_deref() == Some("green") {
            "green"
        } else if product_verdict.as_deref() == Some("red") {
            "red"
        } else {
            "degraded"
        };

    let mut bypass_blocker_reason = None;
    if !preflight_ok {
        bypass_blocker_reason = Some("preflight_not_ok");
    } else if !startup_ok {
        bypass_blocker_reason = Some("startup_probe_not_ok");
    } else if backend.is_none() {
        bypass_blocker_reason = Some("runtime_backend_not_observed");
    } else if terminal_failure_count > 0 {
        bypass_blocker_reason = Some("terminal_failure_seen");
    } else if failover_count > 0 {
        bypass_blocker_reason = Some("runtime_failover_seen");
    } else if runtime_degradation_count > 0 {
        bypass_blocker_reason = Some("runtime_degradation_seen");
    } else if startup_health.as_deref() != Some("healthy") {
        bypass_blocker_reason = Some("startup_health_not_healthy");
    } else if runtime_status.as_deref() != Some("healthy") {
        bypass_blocker_reason = Some("runtime_status_not_healthy");
    } else if product_verdict.as_deref() != Some("green") {
        bypass_blocker_reason = Some("operator_product_verdict_not_green");
    }

    let bypass_ready = preflight_ok
        && startup_ok
        && backend.is_some()
        && startup_health.as_deref() == Some("healthy")
        && runtime_status.as_deref() == Some("healthy")
        && product_verdict.as_deref() == Some("green")
        && runtime_degradation_count == 0
        && failover_count == 0
        && terminal_failure_count == 0;
    let (bypass_verdict, bypass_support_tier, bypass_blocker_reason) = if bypass_ready {
        ("proven", "baseline_transport_runtime", Value::Null)
    } else if product_verdict.as_deref() == Some("red")
        || terminal_failure_count > 0
        || matches!(startup_health.as_deref(), Some("failed" | "unknown"))
    {
        (
            "blocked",
            "not_proven",
            bypass_blocker_reason
                .map(|reason| Value::String(reason.to_owned()))
                .unwrap_or(Value::Null),
        )
    } else {
        (
            "degraded",
            "not_proven",
            bypass_blocker_reason
                .map(|reason| Value::String(reason.to_owned()))
                .unwrap_or(Value::Null),
        )
    };

    let client_platform_backend = toml_string(&wide_cfg, "platform_backend");
    let client_rollout_profile = toml_string(&wide_cfg, "rollout_profile");
    let client_prerouting_interface = toml_string(&wide_cfg, "prerouting_interface");
    let client_default_mark = toml_value_or_null(&wide_cfg, "default_mark");
    let client_capture_dns = toml_bool(&wide_cfg, "capture_dns");
    let (dns_support_tier, dns_runtime_verdict, dns_runtime_ready, dns_runtime_blocker_reason) =
        dns_runtime_status(
            client_capture_dns,
            client_platform_backend.as_deref(),
            client_rollout_profile.as_deref(),
            bypass_ready,
            product_verdict.as_deref(),
            terminal_failure_count,
            startup_health.as_deref(),
            &bypass_blocker_reason,
        );

    let payload = json!({
        "artifact_schema": "ubuntu_product_operator_loop_summary_v2",
        "supported_product_contour": "ubuntu_first_operator_loop",
        "supported_operator_scope": "ubuntu_first_doctor_probe_events",
        "client_config": inputs.client_config.display().to_string(),
        "runtime_events_jsonl": inputs.runtime_events,
        "preflight_json": inputs.preflight_json.display().to_string(),
        "startup_probe_json": inputs.startup_probe_json.display().to_string(),
        "runtime_events_summary_json": inputs.events_summary_json.display().to_string(),
        "operator_evidence_json": inputs.operator_evidence_json.display().to_string(),
        "operator_evidence_txt": inputs.operator_evidence_txt,
        "overall_status": overall_status,
        "service_health_verdict": overall_status,
        "preflight_status": preflight.get("status").cloned().unwrap_or(Value::Null),
        "startup_probe_status": startup_probe.get("status").cloned().unwrap_or(Value::Null),
        "startup_health": startup_health,
        "runtime_status": runtime_status,
        "product_verdict": product_verdict,
        "backend": backend,
        "client_platform_backend": client_platform_backend,
        "client_rollout_profile": client_rollout_profile,
        "client_prerouting_interface": client_prerouting_interface,
        "client_default_mark": client_default_mark,
        "client_capture_dns": client_capture_dns,
        "runtime_degradation_count": runtime_degradation_count,
        "failover_count": failover_count,
        "terminal_failure_count": terminal_failure_count,
        "baseline_bypass_verdict": bypass_verdict,
        "baseline_bypass_ready": bypass_ready,
        "baseline_bypass_blocker_reason": bypass_blocker_reason,
        "bypass_verdict": bypass_verdict,
        "bypass_ready": bypass_ready,
        "bypass_support_tier": bypass_support_tier,
        "bypass_blocker_reason": bypass_blocker_reason,
        "hostile_path_verdict": if bypass_ready { "missing_evidence" } else { "not_proven" },
        "hostile_path_ready": false,
        "hostile_path_blocker_reason": if bypass_ready {
            json!("hostile_path_evidence_missing")
        } else {
            bypass_blocker_reason.clone()
        },
        "hostile_path_evidence_required": true,
        "fully_proven": false,
        "dns_support_tier": dns_support_tier,
        "dns_runtime_verdict": dns_runtime_verdict,
        "dns_runtime_ready": dns_runtime_ready,
        "dns_runtime_blocker_reason": dns_runtime_blocker_reason,
        "records_scanned": value_or_null(&operator_evidence, "records_scanned"),
        "canonical_operator_loop": ["doctor", "probe", "events"],
        "next_recommended_action": if bypass_ready && dns_support_tier == "redirect_preview_only" {
            "switch_to_privileged_linux_tproxy_for_real_dns"
        } else if bypass_ready {
            "none"
        } else {
            "collect_live_bypass_proof"
        },
        "runtime_events_summary": events_summary,
    });
    write_json(inputs.output, &payload)?;
    Ok(())
}

pub fn build_debian_package_host_release_gate_handoff(
    inputs: DebianPackageHostReleaseGateHandoffInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let summary = read_json(inputs.host_summary)?;
    let ship_ready = string_field(&summary, "release_gate_status").as_deref() == Some("passed")
        && string_field(&summary, "ship_decision").as_deref() == Some("ship")
        && string_field(&summary, "service_health_verdict").as_deref() == Some("green")
        && bool_field(&summary, "bypass_ready");

    let (release_readiness, ship_blocker_reason, next_required_action) = if ship_ready {
        ("ship_ready", Value::Null, "none")
    } else {
        (
            "bypass_not_proven",
            fallback_reason(
                &value_or_null(&summary, "bypass_blocker_reason"),
                "ubuntu_live_bypass_not_proven",
            ),
            "collect_live_bypass_proof",
        )
    };

    let payload = json!({
        "artifact_schema": "ubuntu_release_gate_handoff_v1",
        "release_gate_name": "ubuntu_first_product_release_gate",
        "release_gate_scope": "ubuntu_first_product_candidate",
        "required_lifecycle_phases": summary.get("required_lifecycle_phases").cloned().unwrap_or_else(|| json!(required_lifecycle_phases())),
        "required_runtime_artifacts": summary.get("required_runtime_artifacts").cloned().unwrap_or_else(|| json!(required_runtime_artifacts())),
        "repo_contract_status": "passed",
        "ubuntu_host_evidence_present": true,
        "ubuntu_host_summary_path": display_path(inputs.host_summary),
        "ship_ready": ship_ready,
        "release_readiness": release_readiness,
        "service_health_verdict": value_or_null(&summary, "service_health_verdict"),
        "bypass_verdict": value_or_null(&summary, "bypass_verdict"),
        "bypass_ready": value_or_null(&summary, "bypass_ready"),
        "bypass_support_tier": value_or_null(&summary, "bypass_support_tier"),
        "baseline_bypass_verdict": value_or_null(&summary, "baseline_bypass_verdict"),
        "baseline_bypass_ready": value_or_null(&summary, "baseline_bypass_ready"),
        "dns_support_tier": value_or_null(&summary, "dns_support_tier"),
        "dns_runtime_verdict": value_or_null(&summary, "dns_runtime_verdict"),
        "dns_runtime_ready": value_or_null(&summary, "dns_runtime_ready"),
        "dns_runtime_blocker_reason": value_or_null(&summary, "dns_runtime_blocker_reason"),
        "hostile_path_verdict": value_or_null(&summary, "hostile_path_verdict"),
        "hostile_path_ready": value_or_null(&summary, "hostile_path_ready"),
        "hostile_path_evidence_required": value_or_null(&summary, "hostile_path_evidence_required"),
        "fully_proven": value_or_null(&summary, "fully_proven"),
        "ship_blocker_reason": ship_blocker_reason,
        "next_required_action": next_required_action,
    });
    write_json(inputs.output, &payload)?;
    Ok(())
}

pub fn build_debian_package_host_release_summary(
    inputs: DebianPackageHostReleaseSummaryInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let host_summary = read_json(inputs.host_summary)?;
    let release_handoff = read_json(inputs.release_handoff)?;
    let operator_loop = read_json(inputs.operator_loop_summary)?;

    let payload = json!({
        "artifact_schema": "ubuntu_product_release_summary_v2",
        "supported_product_contour": "ubuntu_first_install_to_live_bypass_contour",
        "supported_operator_scope": "ubuntu_first_product_release_validation",
        "host_validation_summary_json": display_path(inputs.host_summary),
        "release_gate_handoff_json": display_path(inputs.release_handoff),
        "operator_loop_summary_json": display_path(inputs.operator_loop_summary),
        "ship_ready": value_or_null(&release_handoff, "ship_ready"),
        "release_readiness": value_or_null(&release_handoff, "release_readiness"),
        "ship_blocker_reason": value_or_null(&release_handoff, "ship_blocker_reason"),
        "next_required_action": value_or_null(&release_handoff, "next_required_action"),
        "product_verdict": value_or_null(&host_summary, "product_verdict"),
        "service_health_verdict": value_or_fallback(&host_summary, &operator_loop, "service_health_verdict"),
        "baseline_bypass_verdict": value_or_fallback(&host_summary, &operator_loop, "baseline_bypass_verdict"),
        "baseline_bypass_ready": value_or_null(&host_summary, "baseline_bypass_ready"),
        "baseline_bypass_blocker_reason": value_or_fallback(&host_summary, &operator_loop, "baseline_bypass_blocker_reason"),
        "bypass_verdict": value_or_fallback(&host_summary, &operator_loop, "bypass_verdict"),
        "bypass_ready": value_or_null(&host_summary, "bypass_ready"),
        "bypass_support_tier": value_or_fallback(&host_summary, &operator_loop, "bypass_support_tier"),
        "bypass_blocker_reason": value_or_fallback(&host_summary, &operator_loop, "bypass_blocker_reason"),
        "dns_support_tier": value_or_fallback(&host_summary, &operator_loop, "dns_support_tier"),
        "dns_runtime_verdict": value_or_fallback(&host_summary, &operator_loop, "dns_runtime_verdict"),
        "dns_runtime_ready": value_or_null_or_fallback(&host_summary, &operator_loop, "dns_runtime_ready"),
        "dns_runtime_blocker_reason": value_or_fallback(&host_summary, &operator_loop, "dns_runtime_blocker_reason"),
        "hostile_path_verdict": value_or_fallback(&host_summary, &operator_loop, "hostile_path_verdict"),
        "hostile_path_ready": value_or_null(&host_summary, "hostile_path_ready"),
        "hostile_path_blocker_reason": value_or_fallback(&host_summary, &operator_loop, "hostile_path_blocker_reason"),
        "hostile_path_evidence_required": true,
        "fully_proven": bool_field(&host_summary, "fully_proven"),
        "operator_overall_status": value_or_null(&operator_loop, "overall_status"),
        "release_review_command": "bash scripts/build-ubuntu-release-review.sh <output-dir> --release-summary <ubuntu-product-release-summary.json> --pilot-bundle <pilot-summary.json>",
        "release_wave_status_command": "bash scripts/ubuntu-release-wave-status.sh --pilot-inputs <ubuntu-controlled-pilot-inputs.json> --pilot-review-manifest <pilot-review.manifest.json> --output <status.json>",
        "release_wave_bundle_command": "bash scripts/build-ubuntu-release-wave-bundle.sh <output-dir> --pilot-inputs <ubuntu-controlled-pilot-inputs.json>",
        "canonical_release_contour": [
            "server_install",
            "client_install",
            "preflight",
            "startup_probe",
            "systemd_runtime",
            "operator_evidence",
            "ubuntu_host_gate",
        ],
    });
    write_json(inputs.output, &payload)?;
    Ok(())
}

pub fn build_debian_package_host_pilot_inputs(
    inputs: DebianPackageHostPilotInputsInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let release_summary = read_json(inputs.release_summary)?;
    let runtime_dir = inputs.runtime_artifacts_dir;
    let output_path = display_path(inputs.output);
    let release_summary_path = display_path(inputs.release_summary);

    let payload = json!({
        "artifact_schema": "ubuntu_controlled_pilot_inputs_v1",
        "supported_product_contour": "ubuntu_first_controlled_pilot",
        "supported_operator_scope": "ubuntu_release_evidence_collection",
        "validation_summary_json": display_path(inputs.validation_summary),
        "release_gate_handoff_json": display_path(inputs.release_handoff),
        "release_summary_json": release_summary_path,
        "operator_loop_summary_json": display_path(inputs.operator_loop_summary),
        "service_health_verdict": value_or_null(&release_summary, "service_health_verdict"),
        "baseline_bypass_verdict": value_or_null(&release_summary, "baseline_bypass_verdict"),
        "baseline_bypass_ready": value_or_null(&release_summary, "baseline_bypass_ready"),
        "bypass_verdict": value_or_null(&release_summary, "bypass_verdict"),
        "bypass_ready": value_or_null(&release_summary, "bypass_ready"),
        "bypass_support_tier": value_or_null(&release_summary, "bypass_support_tier"),
        "bypass_blocker_reason": value_or_null(&release_summary, "bypass_blocker_reason"),
        "dns_support_tier": value_or_null(&release_summary, "dns_support_tier"),
        "dns_runtime_verdict": value_or_null(&release_summary, "dns_runtime_verdict"),
        "dns_runtime_ready": value_or_null(&release_summary, "dns_runtime_ready"),
        "dns_runtime_blocker_reason": value_or_null(&release_summary, "dns_runtime_blocker_reason"),
        "hostile_path_verdict": value_or_null(&release_summary, "hostile_path_verdict"),
        "hostile_path_ready": value_or_null(&release_summary, "hostile_path_ready"),
        "hostile_path_blocker_reason": value_or_null(&release_summary, "hostile_path_blocker_reason"),
        "hostile_path_evidence_required": true,
        "fully_proven": value_or_null(&release_summary, "fully_proven"),
        "server_systemctl_status_log": display_path(&runtime_dir.join("server-systemctl-status.log")),
        "server_journal_log": display_path(&runtime_dir.join("server-journal.log")),
        "client_preflight_json": display_path(&runtime_dir.join("client-preflight.json")),
        "client_startup_probe_json": display_path(&runtime_dir.join("client-startup-probe.json")),
        "client_runtime_events_summary_json": display_path(&runtime_dir.join("client-runtime-events-summary.json")),
        "client_operator_evidence_json": display_path(&runtime_dir.join("client-operator-evidence.json")),
        "pilot_playbook_command": "bash scripts/build-ubuntu-controlled-pilot-playbook.sh <output-dir>",
        "operator_reapply_canary_command": format!("bash scripts/build-ubuntu-operator-reapply-canary.sh <output-dir> --pilot-inputs {output_path}"),
        "pilot_bundle_command": format!("bash scripts/build-ubuntu-controlled-pilot-bundle.sh <output-dir> --pilot-inputs {output_path}"),
        "pilot_review_bundle_command": format!("bash scripts/build-ubuntu-controlled-pilot-review-bundle.sh <output-dir> --pilot-inputs {output_path}"),
        "release_review_command": format!("bash scripts/build-ubuntu-release-review.sh <output-dir> --release-summary {release_summary_path} --pilot-bundle <pilot-summary.json>"),
        "release_wave_status_command": format!("bash scripts/ubuntu-release-wave-status.sh --pilot-inputs {output_path} --pilot-review-manifest <pilot-review.manifest.json> --output <status.json>"),
        "release_wave_bundle_command": format!("bash scripts/build-ubuntu-release-wave-bundle.sh <output-dir> --pilot-inputs {output_path}"),
        "field_pilot_remote_bundle_command": format!("bash scripts/build-ubuntu-field-pilot-remote-bundle.sh <output-dir> --pilot-inputs {output_path}"),
        "stealth_wave_summary_command": "bash scripts/build-post-release-stealth-wave-summary.sh <output-dir> --ubuntu-release-wave-status <ubuntu-release-wave-status.json> [--wire-acceptance-summary <wire-host-acceptance-summary.json>]",
        "mimicry_next_contour_command": "bash scripts/build-ubuntu-mimicry-next-contour.sh <output-dir> --stealth-summary <stealth-wave-summary.json>",
    });
    write_json(inputs.output, &payload)?;
    Ok(())
}

pub fn verify_debian_package_host_install_state(
    inputs: DebianPackageHostDpkgStateInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    expect_package_status(inputs.dpkg_query, "aegis-server", "install ok installed")?;
    expect_package_status(inputs.dpkg_query, "aegis-client", "install ok installed")?;
    expect_path_is_file(inputs.validation_root, "/usr/local/bin/aegis-server")?;
    expect_path_is_file(inputs.validation_root, "/usr/local/bin/aegis-client")?;
    expect_path_is_file(
        inputs.validation_root,
        "/usr/lib/systemd/system-preset/90-aegis-server.preset",
    )?;
    expect_path_is_file(
        inputs.validation_root,
        "/usr/lib/systemd/system-preset/90-aegis-client.preset",
    )?;
    Ok(())
}

pub fn verify_debian_package_host_remove_state(
    inputs: DebianPackageHostDpkgStateInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    expect_package_status(
        inputs.dpkg_query,
        "aegis-server",
        "deinstall ok config-files",
    )?;
    expect_package_status(
        inputs.dpkg_query,
        "aegis-client",
        "deinstall ok config-files",
    )?;
    expect_path_absent(inputs.validation_root, "/usr/local/bin/aegis-server")?;
    expect_path_absent(inputs.validation_root, "/usr/local/bin/aegis-client")?;
    expect_path_is_file(inputs.validation_root, "/etc/default/aegis-server")?;
    expect_path_is_file(inputs.validation_root, "/etc/default/aegis-client")?;
    Ok(())
}

pub fn verify_debian_package_host_purge_state(
    inputs: DebianPackageHostDpkgStateInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    expect_package_absent(inputs.dpkg_query, "aegis-server")?;
    expect_package_absent(inputs.dpkg_query, "aegis-client")?;
    expect_path_absent(inputs.validation_root, "/etc/default/aegis-server")?;
    expect_path_absent(inputs.validation_root, "/etc/default/aegis-client")?;
    Ok(())
}

pub fn check_dpkg_lifecycle_smoke_state(
    inputs: DpkgLifecycleSmokeStateInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let status = std::fs::read_to_string(inputs.status_path)?;
    let hooks = std::fs::read_to_string(inputs.hook_log)?;
    match inputs.phase {
        "installed" => {
            expect_text_contains(&status, "Package: aegis-server")?;
            expect_text_contains(&status, "Package: aegis-client")?;
            for path in [
                "/usr/local/bin/aegis-server",
                "/usr/local/bin/aegis-client",
                "/usr/lib/systemd/system/aegis-server.service",
                "/usr/lib/systemd/system/aegis-client.service",
                "/usr/lib/sysusers.d/aegis-server.conf",
                "/usr/lib/tmpfiles.d/aegis-server.conf",
                "/usr/lib/tmpfiles.d/aegis-client.conf",
                "/etc/default/aegis-server",
                "/etc/default/aegis-client",
            ] {
                expect_path_is_file(inputs.rootdir, path)?;
            }
            for needle in [
                "systemd-sysusers /usr/lib/sysusers.d/aegis-server.conf",
                "systemd-tmpfiles --create /usr/lib/tmpfiles.d/aegis-server.conf",
                "systemd-tmpfiles --create /usr/lib/tmpfiles.d/aegis-client.conf",
                "systemctl daemon-reload",
                "systemctl preset aegis-server.service",
                "systemctl preset aegis-client.service",
            ] {
                expect_text_contains(&hooks, needle)?;
            }
        }
        "removed" => {
            expect_text_contains(&status, "deinstall ok config-files")?;
            for path in [
                "/usr/local/bin/aegis-server",
                "/usr/local/bin/aegis-client",
                "/usr/lib/systemd/system/aegis-server.service",
                "/usr/lib/systemd/system/aegis-client.service",
                "/usr/lib/sysusers.d/aegis-server.conf",
                "/usr/lib/tmpfiles.d/aegis-server.conf",
                "/usr/lib/tmpfiles.d/aegis-client.conf",
            ] {
                expect_path_absent(inputs.rootdir, path)?;
            }
            expect_path_is_file(inputs.rootdir, "/etc/default/aegis-server")?;
            expect_path_is_file(inputs.rootdir, "/etc/default/aegis-client")?;
            for needle in [
                "systemctl --no-reload disable --now aegis-server.service",
                "systemctl --no-reload disable --now aegis-client.service",
            ] {
                expect_text_contains(&hooks, needle)?;
            }
        }
        "purged" => {
            expect_text_absent(&status, "Package: aegis-server")?;
            expect_text_absent(&status, "Package: aegis-client")?;
            expect_path_absent(inputs.rootdir, "/etc/default/aegis-server")?;
            expect_path_absent(inputs.rootdir, "/etc/default/aegis-client")?;
            for needle in [
                "systemd-tmpfiles --remove /usr/lib/tmpfiles.d/aegis-server.conf",
                "systemd-tmpfiles --remove /usr/lib/tmpfiles.d/aegis-client.conf",
            ] {
                expect_text_contains(&hooks, needle)?;
            }
        }
        other => return Err(format!("unknown dpkg lifecycle smoke phase: {other}").into()),
    }
    Ok(())
}

pub fn verify_debian_package_host_client_json_artifact(
    inputs: DebianPackageHostClientJsonArtifactInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !matches!(inputs.exit_status, 0 | 1) {
        return Err(format!(
            "unexpected client command exit status {}",
            inputs.exit_status
        )
        .into());
    }
    let report = read_json_maybe_wrapped(inputs.artifact)?;
    if report.get("status").and_then(Value::as_str) != Some("ok") {
        return Err(format!("{} did not report status=ok", inputs.artifact.display()).into());
    }
    Ok(())
}

pub fn build_debian_package_host_runtime_events_summary(
    inputs: DebianPackageHostRuntimeEventsSummaryInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !inputs.runtime_events.is_file() {
        return Err(format!("{} is missing", inputs.runtime_events.display()).into());
    }
    let records = read_jsonl(inputs.runtime_events)?;
    let Some(latest) = records.last() else {
        return Err("runtime events are empty".into());
    };
    let startup_health = if records.iter().any(|record| {
        record.get("event_code").and_then(Value::as_str) == Some("ingress_backend_started")
    }) {
        "healthy"
    } else {
        "unknown"
    };
    let payload = json!({
        "record_count": records.len(),
        "latest_event_code": value_or_null(latest, "event_code"),
        "latest_level": value_or_null(latest, "level"),
        "startup_health": startup_health,
    });
    write_json(inputs.output, &payload)?;
    Ok(())
}

pub fn check_debian_package_host_contract_json_case(
    inputs: DebianPackageHostContractJsonCaseInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = read_json_maybe_wrapped(inputs.output)?;
    match inputs.scenario {
        "happy-check" => {
            expect_i32(inputs.exit_status, 0, "exit status")?;
            expect_string_field(
                &payload,
                "artifact_schema",
                "debian_package_host_validation_v1",
            )?;
            expect_string_field(&payload, "mode", "check")?;
            expect_bool_field(&payload, "ready", true)?;
            expect_i64_field(&payload, "helper_exit_code", 0)?;
            expect_string_field(&payload, "host_family_id", "debian-apt")?;
            expect_empty_array_field(&payload, "missing_commands")?;
            expect_command_status(&payload, "cargo", "ok")?;
            expect_string_field_suffix(&payload, "run_command", "--run")?;
        }
        "missing-cargo" => {
            expect_i32(inputs.exit_status, 1, "exit status")?;
            expect_bool_field(&payload, "ready", false)?;
            expect_string_array_field(&payload, "missing_commands", &["cargo"])?;
            expect_i64_field(&payload, "helper_exit_code", 1)?;
            expect_optional_empty_string_field(&payload, "error_code")?;
        }
        "prebuilt-check" => {
            expect_i32(inputs.exit_status, 0, "exit status")?;
            expect_bool_field(&payload, "ready", true)?;
            expect_i64_field(&payload, "helper_exit_code", 0)?;
            expect_command_status(&payload, "cargo", "not_required")?;
        }
        "unknown-argument" => {
            expect_i32(inputs.exit_status, 1, "exit status")?;
            expect_bool_field(&payload, "ready", false)?;
            expect_string_field(&payload, "error_code", "unknown_argument")?;
            expect_i64_field(&payload, "helper_exit_code", 1)?;
        }
        other => {
            return Err(format!("unknown debian package host contract scenario: {other}").into())
        }
    }
    Ok(())
}

pub fn check_debian_package_host_contract_run_mode(
    inputs: DebianPackageHostContractRunModeInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = read_json_maybe_wrapped(inputs.output)?;
    let summary = read_json(inputs.validation_summary)?;
    let release_handoff = read_json(inputs.release_handoff)?;
    let release_summary = read_json(inputs.release_summary)?;
    let pilot_inputs = read_json(inputs.pilot_inputs)?;
    let operator_loop = read_json(inputs.operator_loop)?;
    let dpkg_log = std::fs::read_to_string(inputs.dpkg_log)?;
    let helper_log = std::fs::read_to_string(inputs.helper_log)?;
    let helper_lines = helper_log.lines().collect::<Vec<_>>();
    let root = normalized_path_display(inputs.validation_root);

    expect_i32(inputs.exit_status, 0, "exit status")?;
    expect_string_field(&payload, "mode", "run")?;
    expect_bool_field(&payload, "ready", true)?;
    expect_i64_field(&payload, "helper_exit_code", 0)?;
    expect_string_field(&payload, "validation_root", &root)?;
    expect_string_field_suffix(
        &payload,
        "release_handoff_artifact",
        "ubuntu-release-gate-handoff.json",
    )?;
    expect_string_field_suffix(
        &payload,
        "release_summary_artifact",
        "ubuntu-product-release-summary.json",
    )?;
    expect_string_field_suffix(
        &payload,
        "operator_loop_summary_artifact",
        "runtime/client-operator-loop-summary.json",
    )?;
    expect_string_field_suffix(
        &payload,
        "pilot_inputs_artifact",
        "ubuntu-controlled-pilot-inputs.json",
    )?;

    expect_string_field(
        &summary,
        "artifact_schema",
        "debian_package_host_run_summary_v2",
    )?;
    expect_string_field(&summary, "product_verdict", "green")?;
    expect_string_field(&summary, "service_health_verdict", "green")?;
    expect_string_field(&summary, "baseline_bypass_verdict", "proven")?;
    expect_bool_field(&summary, "baseline_bypass_ready", true)?;
    expect_string_field(&summary, "bypass_verdict", "proven")?;
    expect_bool_field(&summary, "bypass_ready", true)?;
    expect_string_field(
        &summary,
        "bypass_support_tier",
        "baseline_transport_runtime",
    )?;
    expect_string_field(&summary, "dns_support_tier", "disabled")?;
    expect_string_field(&summary, "dns_runtime_verdict", "not_requested")?;
    expect_bool_field(&summary, "dns_runtime_ready", false)?;
    expect_string_field(&summary, "hostile_path_verdict", "missing_evidence")?;
    expect_bool_field(&summary, "hostile_path_ready", false)?;
    expect_bool_field(&summary, "fully_proven", false)?;
    expect_string_array_field(&summary, "lifecycle_phases", &required_lifecycle_phases())?;
    expect_string_field(&summary, "upgrade_reapply_mode", "same_version_reapply")?;
    expect_string_field(&summary, "validation_root", &root)?;
    expect_string_array_contains(
        &summary,
        "required_runtime_artifacts",
        "runtime/client-operator-loop-summary.json",
    )?;

    expect_string_field(
        &release_handoff,
        "artifact_schema",
        "ubuntu_release_gate_handoff_v1",
    )?;
    expect_bool_field(&release_handoff, "ship_ready", true)?;
    expect_bool_field(&release_handoff, "bypass_ready", true)?;
    expect_string_field(&release_handoff, "dns_support_tier", "disabled")?;
    expect_bool_field(&release_handoff, "hostile_path_ready", false)?;

    expect_string_field(
        &release_summary,
        "artifact_schema",
        "ubuntu_product_release_summary_v2",
    )?;
    expect_bool_field(&release_summary, "ship_ready", true)?;
    expect_bool_field(&release_summary, "bypass_ready", true)?;
    expect_bool_field(&release_summary, "baseline_bypass_ready", true)?;
    expect_string_field(
        &release_summary,
        "bypass_support_tier",
        "baseline_transport_runtime",
    )?;
    expect_string_field(&release_summary, "dns_support_tier", "disabled")?;
    expect_bool_field(&release_summary, "fully_proven", false)?;
    expect_string_field_contains(
        &release_summary,
        "release_review_command",
        "build-ubuntu-release-review.sh",
    )?;
    expect_string_field_contains(
        &release_summary,
        "release_wave_status_command",
        "ubuntu-release-wave-status.sh",
    )?;
    expect_string_field_contains(
        &release_summary,
        "release_wave_bundle_command",
        "build-ubuntu-release-wave-bundle.sh",
    )?;

    expect_string_field(
        &operator_loop,
        "artifact_schema",
        "ubuntu_product_operator_loop_summary_v2",
    )?;
    expect_string_field(&operator_loop, "overall_status", "green")?;
    expect_string_field(&operator_loop, "bypass_verdict", "proven")?;
    expect_bool_field(&operator_loop, "bypass_ready", true)?;
    expect_string_field(&operator_loop, "dns_support_tier", "disabled")?;
    expect_string_field(&operator_loop, "dns_runtime_verdict", "not_requested")?;
    expect_bool_field(&operator_loop, "hostile_path_ready", false)?;

    expect_string_field(
        &pilot_inputs,
        "artifact_schema",
        "ubuntu_controlled_pilot_inputs_v1",
    )?;
    expect_bool_field(&pilot_inputs, "bypass_ready", true)?;
    expect_string_field(&pilot_inputs, "dns_support_tier", "disabled")?;
    expect_bool_field(&pilot_inputs, "fully_proven", false)?;
    expect_string_field_suffix(
        &pilot_inputs,
        "release_summary_json",
        "ubuntu-product-release-summary.json",
    )?;
    for (field, command) in [
        (
            "pilot_playbook_command",
            "build-ubuntu-controlled-pilot-playbook.sh",
        ),
        (
            "operator_reapply_canary_command",
            "build-ubuntu-operator-reapply-canary.sh",
        ),
        (
            "pilot_bundle_command",
            "build-ubuntu-controlled-pilot-bundle.sh",
        ),
        (
            "pilot_review_bundle_command",
            "build-ubuntu-controlled-pilot-review-bundle.sh",
        ),
        ("release_review_command", "build-ubuntu-release-review.sh"),
        (
            "release_wave_status_command",
            "ubuntu-release-wave-status.sh",
        ),
        (
            "release_wave_bundle_command",
            "build-ubuntu-release-wave-bundle.sh",
        ),
        (
            "field_pilot_remote_bundle_command",
            "build-ubuntu-field-pilot-remote-bundle.sh",
        ),
        (
            "stealth_wave_summary_command",
            "build-post-release-stealth-wave-summary.sh",
        ),
        (
            "mimicry_next_contour_command",
            "build-ubuntu-mimicry-next-contour.sh",
        ),
    ] {
        expect_string_field_contains(&pilot_inputs, field, command)?;
    }

    expect_text_contains(&dpkg_log, "--install")?;
    expect_text_contains(&dpkg_log, "--remove aegis-client aegis-server")?;
    expect_text_contains(&dpkg_log, "--purge aegis-client aegis-server")?;
    expect_line_count(&helper_lines, "redirect:teardown", 4)?;
    expect_line_count(&helper_lines, "tproxy:teardown", 4)?;
    expect_path_is_file(
        inputs.validation_root,
        "/var/log/aegis-client/runtime-events.jsonl",
    )?;
    expect_path_absent(inputs.validation_root, "/etc/default/aegis-server")?;
    expect_path_absent(inputs.validation_root, "/etc/default/aegis-client")?;
    Ok(())
}

pub fn check_debian_package_host_contract_script(
    inputs: DebianPackageHostContractScriptInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(inputs.script)?;
    for needle in [
        "--install \"${server_deb}\" \"${client_deb}\"",
        "--remove aegis-client aegis-server",
        "--purge aegis-client aegis-server",
        "verify_disabled_units",
        "service_start",
        "upgrade_reapply",
        "validation-summary.json",
        "ubuntu-release-gate-handoff.json",
        "client-operator-loop-summary.json",
        "ubuntu-controlled-pilot-inputs.json",
        "VALIDATION_ROOT=\"${AEGIS_DEB_HOST_VALIDATION_ROOT:-/}\"",
        "--server-deb <path>",
        "using_prebuilt_split_debs()",
    ] {
        expect_text_contains(&text, needle)?;
    }
    let startup_probe = "run_client_startup_probe \"${client_config}\" \"${startup_probe_json}\"";
    let service_start = "service_ctl start \"${CLIENT_UNIT}\"";
    let startup_idx = text
        .find(startup_probe)
        .ok_or_else(|| format!("missing script marker {startup_probe:?}"))?;
    let service_idx = text
        .find(service_start)
        .ok_or_else(|| format!("missing script marker {service_start:?}"))?;
    if startup_idx >= service_idx {
        return Err("expected client startup probe before client service start".into());
    }
    Ok(())
}

fn read_json_maybe_wrapped(path: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string(path)?;
    match serde_json::from_str(&raw) {
        Ok(value) => Ok(value),
        Err(err) => {
            let Some(start) = raw.find('{') else {
                return Err(err.into());
            };
            let Some(end) = raw.rfind('}') else {
                return Err(err.into());
            };
            if end <= start {
                return Err(err.into());
            }
            Ok(serde_json::from_str(&raw[start..=end])?)
        }
    }
}

fn parse_phase_entry(entry: &String) -> Result<Value, Box<dyn std::error::Error>> {
    let parts = entry.splitn(3, '|').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(format!("invalid phase entry: {entry}").into());
    }
    Ok(json!({
        "name": parts[0],
        "status": parts[1],
        "detail": parts[2],
    }))
}

fn parse_command_status_entry(entry: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let mut parts = entry.splitn(3, '\t');
    let name = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| format!("invalid command status entry missing name: {entry:?}"))?;
    let status = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| format!("invalid command status entry missing status: {entry:?}"))?;
    let detail = parts
        .next()
        .ok_or_else(|| format!("invalid command status entry missing detail: {entry:?}"))?;

    Ok(json!({
        "name": name,
        "status": status,
        "detail": detail,
    }))
}

fn non_empty_or_null(value: Option<&str>) -> Value {
    value
        .filter(|value| !value.is_empty())
        .map(Value::from)
        .unwrap_or(Value::Null)
}

fn package_status(
    dpkg_query: &Path,
    package: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let output = Command::new(dpkg_query)
        .arg("-W")
        .arg("-f=${Status}")
        .arg(package)
        .output()?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(Some(String::from_utf8(output.stdout)?.trim().to_owned()))
}

fn expect_package_status(
    dpkg_query: &Path,
    package: &str,
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = package_status(dpkg_query, package)?;
    if actual.as_deref() != Some(expected) {
        return Err(format!("expected {package} status {expected:?}, got {actual:?}").into());
    }
    Ok(())
}

fn expect_package_absent(
    dpkg_query: &Path,
    package: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(actual) = package_status(dpkg_query, package)? {
        return Err(format!("expected {package} to be absent, got status {actual:?}").into());
    }
    Ok(())
}

fn installed_path(validation_root: &Path, relative: &str) -> std::path::PathBuf {
    validation_root.join(relative.trim_start_matches('/'))
}

fn expect_path_is_file(
    validation_root: &Path,
    relative: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = installed_path(validation_root, relative);
    if !path.is_file() {
        return Err(format!("expected {} to be a file", path.display()).into());
    }
    Ok(())
}

fn expect_path_absent(
    validation_root: &Path,
    relative: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = installed_path(validation_root, relative);
    if path.exists() {
        return Err(format!("expected {} to be absent", path.display()).into());
    }
    Ok(())
}

fn expect_text_contains(text: &str, needle: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !text.contains(needle) {
        return Err(format!("expected text to contain {needle:?}").into());
    }
    Ok(())
}

fn expect_text_absent(text: &str, needle: &str) -> Result<(), Box<dyn std::error::Error>> {
    if text.contains(needle) {
        return Err(format!("expected text not to contain {needle:?}").into());
    }
    Ok(())
}

fn expect_i32(actual: i32, expected: i32, label: &str) -> Result<(), Box<dyn std::error::Error>> {
    if actual != expected {
        return Err(format!("expected {label} {expected}, got {actual}").into());
    }
    Ok(())
}

fn expect_string_field(
    value: &Value,
    field: &str,
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = value.get(field).and_then(Value::as_str);
    if actual != Some(expected) {
        return Err(format!("expected {field}={expected:?}, got {actual:?}").into());
    }
    Ok(())
}

fn expect_string_field_contains(
    value: &Value,
    field: &str,
    needle: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = value.get(field).and_then(Value::as_str).unwrap_or("");
    if !actual.contains(needle) {
        return Err(format!("expected {field} to contain {needle:?}, got {actual:?}").into());
    }
    Ok(())
}

fn expect_string_field_suffix(
    value: &Value,
    field: &str,
    suffix: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = value.get(field).and_then(Value::as_str).unwrap_or("");
    if !actual.ends_with(suffix) {
        return Err(format!("expected {field} to end with {suffix:?}, got {actual:?}").into());
    }
    Ok(())
}

fn expect_optional_empty_string_field(
    value: &Value,
    field: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(actual)) if actual.is_empty() => Ok(()),
        Some(actual) => Err(format!("expected {field} to be null or empty, got {actual}").into()),
    }
}

fn expect_bool_field(
    value: &Value,
    field: &str,
    expected: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = value.get(field).and_then(Value::as_bool);
    if actual != Some(expected) {
        return Err(format!("expected {field}={expected}, got {actual:?}").into());
    }
    Ok(())
}

fn expect_i64_field(
    value: &Value,
    field: &str,
    expected: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = value.get(field).and_then(Value::as_i64);
    if actual != Some(expected) {
        return Err(format!("expected {field}={expected}, got {actual:?}").into());
    }
    Ok(())
}

fn expect_empty_array_field(value: &Value, field: &str) -> Result<(), Box<dyn std::error::Error>> {
    let actual = value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("expected {field} to be an array"))?;
    if !actual.is_empty() {
        return Err(format!("expected {field} to be empty, got {actual:?}").into());
    }
    Ok(())
}

fn expect_string_array_field(
    value: &Value,
    field: &str,
    expected: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("expected {field} to be an array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| format!("expected {field} entries to be strings"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if actual != expected {
        return Err(format!("expected {field}={expected:?}, got {actual:?}").into());
    }
    Ok(())
}

fn expect_string_array_contains(
    value: &Value,
    field: &str,
    needle: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("expected {field} to be an array"))?;
    if !actual.iter().any(|item| item.as_str() == Some(needle)) {
        return Err(format!("expected {field} to contain {needle:?}").into());
    }
    Ok(())
}

fn expect_command_status(
    value: &Value,
    name: &str,
    expected_status: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let commands = value
        .get("commands")
        .and_then(Value::as_array)
        .ok_or("expected commands array")?;
    if commands.iter().any(|command| {
        command.get("name").and_then(Value::as_str) == Some(name)
            && command.get("status").and_then(Value::as_str) == Some(expected_status)
    }) {
        return Ok(());
    }
    Err(format!("expected command {name:?} to have status {expected_status:?}").into())
}

fn expect_line_count(
    lines: &[&str],
    needle: &str,
    expected: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = lines.iter().filter(|line| **line == needle).count();
    if actual != expected {
        return Err(format!("expected {needle:?} line count {expected}, got {actual}").into());
    }
    Ok(())
}

fn string_field(value: &Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn bool_field(value: &Value, field: &str) -> bool {
    value.get(field).and_then(Value::as_bool).unwrap_or(false)
}

fn int_field(value: &Value, field: &str) -> i64 {
    value.get(field).and_then(Value::as_i64).unwrap_or(0)
}

fn value_or_null(value: &Value, field: &str) -> Value {
    value.get(field).cloned().unwrap_or(Value::Null)
}

fn value_or_fallback(primary: &Value, fallback: &Value, field: &str) -> Value {
    let value = value_or_null(primary, field);
    if json_truthy(&value) {
        value
    } else {
        value_or_null(fallback, field)
    }
}

fn value_or_null_or_fallback(primary: &Value, fallback: &Value, field: &str) -> Value {
    match primary.get(field) {
        Some(value) if !value.is_null() => value.clone(),
        _ => value_or_null(fallback, field),
    }
}

fn json_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_i64() != Some(0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

fn toml_string(value: &toml::Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(toml::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn toml_bool(value: &toml::Value, field: &str) -> bool {
    value
        .get(field)
        .and_then(toml::Value::as_bool)
        .unwrap_or(false)
}

fn toml_value_or_null(value: &toml::Value, field: &str) -> Value {
    match value.get(field) {
        Some(toml::Value::Integer(value)) => json!(value),
        Some(toml::Value::String(value)) => json!(value),
        Some(toml::Value::Boolean(value)) => json!(value),
        Some(other) => json!(other.to_string()),
        None => Value::Null,
    }
}

#[allow(clippy::too_many_arguments)]
fn dns_runtime_status(
    capture_dns: bool,
    platform_backend: Option<&str>,
    rollout_profile: Option<&str>,
    bypass_ready: bool,
    product_verdict: Option<&str>,
    terminal_failure_count: i64,
    startup_health: Option<&str>,
    bypass_blocker_reason: &Value,
) -> (&'static str, &'static str, bool, Value) {
    if !capture_dns {
        return (
            "disabled",
            "not_requested",
            false,
            json!("dns_capture_disabled_in_baseline"),
        );
    }
    if platform_backend == Some("linux_tproxy") && rollout_profile == Some("transparent_privileged")
    {
        if bypass_ready {
            return ("privileged_linux_tproxy", "ready", true, Value::Null);
        }
        if product_verdict == Some("red")
            || terminal_failure_count > 0
            || matches!(startup_health, Some("failed" | "unknown"))
        {
            return (
                "privileged_linux_tproxy",
                "blocked",
                false,
                fallback_reason(bypass_blocker_reason, "dns_runtime_not_ready"),
            );
        }
        return (
            "privileged_linux_tproxy",
            "degraded",
            false,
            fallback_reason(bypass_blocker_reason, "dns_runtime_not_ready"),
        );
    }
    if matches!(platform_backend, Some("auto" | "linux_redirect")) {
        return (
            "redirect_preview_only",
            "preview_only",
            false,
            json!("redirect_dns_preview_is_not_supported_product_path"),
        );
    }
    (
        "nonstandard",
        "not_proven",
        false,
        json!("dns_contract_not_in_supported_product_matrix"),
    )
}

fn fallback_reason(value: &Value, fallback: &str) -> Value {
    if value.is_null() {
        json!(fallback)
    } else {
        value.clone()
    }
}

fn display_path(path: &Path) -> String {
    path.display().to_string()
}

fn normalized_path_display(path: &Path) -> String {
    path.components().collect::<PathBuf>().display().to_string()
}

fn required_lifecycle_phases() -> Vec<&'static str> {
    vec![
        "install",
        "preset_policy",
        "service_start",
        "service_restart",
        "reboot_contract",
        "remove",
        "reinstall",
        "upgrade_reapply",
        "purge",
    ]
}

fn required_runtime_artifacts() -> Vec<&'static str> {
    vec![
        "validation-summary.json",
        "runtime/server-systemctl-status.log",
        "runtime/client-systemctl-status.log",
        "runtime/server-journal.log",
        "runtime/client-journal.log",
        "runtime/client-preflight.json",
        "runtime/client-startup-probe.json",
        "runtime/client-runtime-events-summary.json",
        "runtime/client-operator-loop-summary.json",
        "runtime/client-operator-evidence.json",
        "runtime/client-operator-evidence.txt",
    ]
}
