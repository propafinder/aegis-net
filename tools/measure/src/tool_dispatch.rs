use std::fs;

use crate::adversarial_runner::{adversarial_runner, adversarial_runner_contract_check};
use crate::artifact::{print_pretty_json, read_json, read_jsonl, write_text};
use crate::cli::Command;
use crate::debian_package_host::{
    build_debian_package_host_operator_loop_summary, build_debian_package_host_pilot_inputs,
    build_debian_package_host_release_gate_handoff, build_debian_package_host_release_summary,
    build_debian_package_host_run_summary, build_debian_package_host_runtime_events_summary,
    build_debian_package_host_validation_report, check_debian_package_host_contract_json_case,
    check_debian_package_host_contract_run_mode, check_debian_package_host_contract_script,
    check_dpkg_lifecycle_smoke_state, verify_debian_package_host_client_json_artifact,
    verify_debian_package_host_install_state, verify_debian_package_host_purge_state,
    verify_debian_package_host_remove_state, DebianPackageHostClientJsonArtifactInputs,
    DebianPackageHostContractJsonCaseInputs, DebianPackageHostContractRunModeInputs,
    DebianPackageHostContractScriptInputs, DebianPackageHostDpkgStateInputs,
    DebianPackageHostOperatorLoopSummaryInputs, DebianPackageHostPilotInputsInputs,
    DebianPackageHostReleaseGateHandoffInputs, DebianPackageHostReleaseSummaryInputs,
    DebianPackageHostRunSummaryInputs, DebianPackageHostRuntimeEventsSummaryInputs,
    DebianPackageHostValidationReportInputs, DpkgLifecycleSmokeStateInputs,
};
use crate::hostile_classifier::{classifier_verdict, ClassifierVerdictInputs};
use crate::linux_next_expansion_playbook::build_linux_next_expansion_playbook;
use crate::linux_next_expansion_review::{
    build_linux_next_expansion_review_bundle_artifacts, print_linux_next_expansion_review_inputs,
};
use crate::linux_next_expansion_status::build_linux_next_expansion_status;
use crate::linux_next_expansion_wave::build_linux_next_expansion_wave_manifest;
use crate::linux_package_acceptance_matrix::build_linux_package_acceptance_matrix;
use crate::linux_release_program::build_linux_release_program_bundle;
use crate::macos_pf_helper::{
    print_macos_pf_state_basename, print_macos_pf_state_field, print_macos_pf_state_json,
};
use crate::macos_pf_operator_summary::build_macos_pf_operator_acceptance_summary;
use crate::macos_utun_lab::{
    build_macos_utun_blocked_result, build_macos_utun_w0_blocked_result,
    build_macos_utun_w0_timeout_result, build_macos_utun_w1_result, build_macos_utun_w2_result,
    MacosUtunBlockedResultInputs, MacosUtunW0BlockedResultInputs, MacosUtunW0TimeoutResultInputs,
    MacosUtunW1ResultInputs, MacosUtunW2ResultInputs,
};
use crate::mimicry_wire_contract::build_mimicry_wire_validation_contract;
use crate::mimicry_wire_host::{
    build_mimicry_wire_host_acceptance, build_mimicry_wire_host_helper_report,
    check_mimicry_wire_host_acceptance_contract, check_mimicry_wire_host_helper_report_contract,
    MimicryWireHostAcceptanceContractInputs, MimicryWireHostAcceptanceInputs,
    MimicryWireHostHelperReportInputs,
};
use crate::mimicry_wire_witness::build_mimicry_wire_witness_summary;
use crate::pcap_tools::{ndpi_risk_count, sll2_to_rawip, suricata_alert_count};
use crate::post_release_stealth_wave::build_post_release_stealth_wave_summary;
use crate::relay_surface_runtime::build_relay_surface_runtime_summary;
use crate::rich_host::{
    build_rich_host_matrix_summary, build_rich_host_metadata, build_rich_host_validation_bundle,
    check_rich_host_validation_contract_artifacts, RichHostMatrixSummaryInputs,
    RichHostValidationBundleInputs, RichHostValidationContractInputs,
};
use crate::rpm_package_host::{
    build_rpm_package_host_run_summary, build_rpm_package_host_validation_report,
    check_rpm_package_host_contract_json_case, check_rpm_package_host_contract_run_mode,
    check_rpm_package_host_contract_script, RpmPackageHostContractJsonCaseInputs,
    RpmPackageHostContractRunModeInputs, RpmPackageHostContractScriptInputs,
    RpmPackageHostValidationReportInputs,
};
use crate::stealth_anti_anomaly::build_stealth_anti_anomaly_acceptance_summary;
use crate::stealth_hostile_path::build_stealth_hostile_path_acceptance_summary;
use crate::stealth_live_bundle::{build_stealth_live_acceptance_bundle, StealthLiveBundleInputs};
use crate::stealth_polymorphism::build_stealth_polymorphism_acceptance_summary;
use crate::ubuntu_controlled_pilot_bundle::{
    build_ubuntu_controlled_pilot_bundle, print_ubuntu_controlled_pilot_input_fields,
};
use crate::ubuntu_controlled_pilot_playbook::{
    build_ubuntu_controlled_pilot_playbook, BundleInput,
};
use crate::ubuntu_controlled_pilot_review_bundle::{
    build_ubuntu_controlled_pilot_review_bundle_manifest, print_ubuntu_pilot_inputs_release_summary,
};
use crate::ubuntu_field_pilot_remote_bundle::build_ubuntu_field_pilot_remote_bundle_manifest;
use crate::ubuntu_mimicry_contour::build_ubuntu_mimicry_next_contour;
use crate::ubuntu_operator_canary::build_ubuntu_operator_reapply_canary;
use crate::ubuntu_operator_loop::{
    build_ubuntu_operator_loop_check_report, build_ubuntu_operator_loop_summary,
    UbuntuOperatorLoopCheckReportInputs, UbuntuOperatorLoopSummaryInputs,
};
use crate::ubuntu_release_gate_status::build_ubuntu_release_gate_status;
use crate::ubuntu_release_review::build_ubuntu_release_review;
use crate::ubuntu_release_wave_bundle::build_ubuntu_release_wave_bundle_manifest;
use crate::ubuntu_release_wave_status::build_ubuntu_release_wave_status;
use crate::wide_redirect_smoke::{
    concat_text_files, reserve_tcp_port, run_with_timeout, socks_http_probe, udp_echo_client,
    udp_echo_server, validate_relay_transport_priority, wait_tcp_port, warn_runtime_event_presence,
    wide_redirect_preflight_exit, WideRedirectPreflightExitInputs,
};
use crate::wide_smoke::{wide_smoke_adversarial_event, WideSmokeAdversarialEventInputs};
use crate::wide_tproxy_helper::{
    build_wide_linux_validation_host_bootstrap_report,
    check_wide_linux_validation_host_bootstrap_contract_case,
    check_wide_linux_validation_host_bootstrap_coverage, print_tproxy_client_contract,
    print_tproxy_runtime_delivery_hint, print_tproxy_runtime_events_summary,
    print_tproxy_startup_probe_fields, tproxy_preflight_exit, validate_rich_host_bootstrap,
    verify_tproxy_generic_udp_runtime_contract, verify_tproxy_loopback_idempotent_log,
    verify_tproxy_smoke_contract_self_test, verify_tproxy_transport_failure_self_test,
    verify_tproxy_transport_recovered_self_test, verify_tproxy_udp_preview_drop_runtime_contract,
    write_rich_host_matrix_targets, write_tproxy_contract_self_test_events,
    write_tproxy_operator_evidence, write_tproxy_smoke_contract_artifact,
    WideLinuxValidationHostBootstrapReportInputs,
};

pub fn is_tooling(command: &Command) -> bool {
    matches!(
        command,
        Command::Sll2ToRawIp { .. }
            | Command::SuricataAlertCount { .. }
            | Command::NdpiRiskCount { .. }
            | Command::ClassifierVerdict { .. }
            | Command::PrettyJson { .. }
            | Command::BuildDebianPackageHostRunSummary { .. }
            | Command::BuildDebianPackageHostValidationReport { .. }
            | Command::BuildDebianPackageHostOperatorLoopSummary { .. }
            | Command::BuildDebianPackageHostReleaseGateHandoff { .. }
            | Command::BuildDebianPackageHostReleaseSummary { .. }
            | Command::BuildDebianPackageHostPilotInputs { .. }
            | Command::VerifyDebianPackageHostInstallState { .. }
            | Command::VerifyDebianPackageHostRemoveState { .. }
            | Command::VerifyDebianPackageHostPurgeState { .. }
            | Command::CheckDpkgLifecycleSmokeState { .. }
            | Command::VerifyDebianPackageHostClientJsonArtifact { .. }
            | Command::BuildDebianPackageHostRuntimeEventsSummary { .. }
            | Command::CheckDebianPackageHostContractJsonCase { .. }
            | Command::CheckDebianPackageHostContractRunMode { .. }
            | Command::CheckDebianPackageHostContractScript { .. }
            | Command::BuildRpmPackageHostValidationReport { .. }
            | Command::BuildRpmPackageHostRunSummary { .. }
            | Command::CheckRpmPackageHostContractJsonCase { .. }
            | Command::CheckRpmPackageHostContractRunMode { .. }
            | Command::CheckRpmPackageHostContractScript { .. }
            | Command::WideSmokeAdversarialEvent { .. }
            | Command::ReserveTcpPort
            | Command::WaitTcpPort { .. }
            | Command::RunWithTimeout { .. }
            | Command::ValidateRelayTransportPriority { .. }
            | Command::ConcatTextFiles { .. }
            | Command::WarnRuntimeEventPresence { .. }
            | Command::SocksHttpProbe { .. }
            | Command::UdpEchoServer { .. }
            | Command::UdpEchoClient { .. }
            | Command::TproxyClientContract { .. }
            | Command::TproxyStartupProbeFields { .. }
            | Command::TproxyRuntimeEventsSummary { .. }
            | Command::WriteTproxyOperatorEvidence { .. }
            | Command::WriteTproxySmokeContractArtifact { .. }
            | Command::TproxyRuntimeDeliveryHint { .. }
            | Command::VerifyTproxyGenericUdpRuntimeContract { .. }
            | Command::VerifyTproxyUdpPreviewDropRuntimeContract { .. }
            | Command::TproxyPreflightExit { .. }
            | Command::WriteTproxyContractSelfTestEvents { .. }
            | Command::VerifyTproxySmokeContractSelfTest { .. }
            | Command::VerifyTproxyTransportFailureSelfTest { .. }
            | Command::VerifyTproxyTransportRecoveredSelfTest { .. }
            | Command::VerifyTproxyLoopbackIdempotentLog { .. }
            | Command::ValidateRichHostBootstrap { .. }
            | Command::BuildWideLinuxValidationHostBootstrapReport { .. }
            | Command::CheckWideLinuxValidationHostBootstrapContractCase { .. }
            | Command::CheckWideLinuxValidationHostBootstrapCoverage { .. }
            | Command::WriteRichHostMatrixTargets { .. }
            | Command::BuildRichHostMetadata { .. }
            | Command::BuildRichHostMatrixSummary { .. }
            | Command::BuildRichHostValidationBundle { .. }
            | Command::CheckRichHostValidationContractArtifacts { .. }
            | Command::WideRedirectPreflightExit { .. }
            | Command::BuildRelaySurfaceRuntimeSummary { .. }
            | Command::BuildStealthHostilePathAcceptanceSummary { .. }
            | Command::BuildStealthAntiAnomalyAcceptanceSummary { .. }
            | Command::BuildStealthPolymorphismAcceptanceSummary { .. }
            | Command::BuildMimicryWireWitnessSummary { .. }
            | Command::BuildMimicryWireValidationContract { .. }
            | Command::BuildMimicryWireHostAcceptance { .. }
            | Command::BuildMimicryWireHostHelperReport { .. }
            | Command::CheckMimicryWireHostHelperReportContract { .. }
            | Command::CheckMimicryWireHostAcceptanceContract { .. }
            | Command::BuildStealthLiveAcceptanceBundle { .. }
            | Command::BuildPostReleaseStealthWaveSummary { .. }
            | Command::BuildLinuxNextExpansionStatus { .. }
            | Command::BuildLinuxNextExpansionPlaybook { .. }
            | Command::BuildLinuxNextExpansionWaveManifest { .. }
            | Command::LinuxNextExpansionReviewInputs { .. }
            | Command::BuildLinuxNextExpansionReviewBundleArtifacts { .. }
            | Command::BuildLinuxReleaseProgramBundle { .. }
            | Command::BuildLinuxPackageAcceptanceMatrix { .. }
            | Command::BuildMacosPfOperatorAcceptanceSummary { .. }
            | Command::MacosPfStateBasename { .. }
            | Command::MacosPfReadStateJson { .. }
            | Command::MacosPfReadStateField { .. }
            | Command::BuildMacosUtunBlockedResult { .. }
            | Command::BuildMacosUtunW0BlockedResult { .. }
            | Command::BuildMacosUtunW0TimeoutResult { .. }
            | Command::BuildMacosUtunW1Result { .. }
            | Command::BuildMacosUtunW2Result { .. }
            | Command::BuildUbuntuReleaseGateStatus { .. }
            | Command::BuildUbuntuOperatorReapplyCanary { .. }
            | Command::BuildUbuntuProductOperatorLoopSummary { .. }
            | Command::BuildUbuntuProductOperatorLoopCheckReport { .. }
            | Command::BuildUbuntuControlledPilotPlaybook { .. }
            | Command::BuildUbuntuMimicryNextContour { .. }
            | Command::BuildUbuntuReleaseWaveStatus { .. }
            | Command::BuildUbuntuReleaseReview { .. }
            | Command::BuildUbuntuReleaseWaveBundleManifest { .. }
            | Command::BuildUbuntuFieldPilotRemoteBundleManifest { .. }
            | Command::UbuntuPilotInputsReleaseSummary { .. }
            | Command::BuildUbuntuControlledPilotReviewBundleManifest { .. }
            | Command::UbuntuControlledPilotInputFields { .. }
            | Command::BuildUbuntuControlledPilotBundle { .. }
            | Command::AdversarialRunner { .. }
            | Command::AdversarialRunnerContractCheck { .. }
    )
}

pub fn run(command: Command) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Command::Sll2ToRawIp {
            input_pcap,
            output_pcap,
        } => {
            let converted = sll2_to_rawip(&fs::read(&input_pcap)?)?;
            if let Some(bytes) = converted {
                if let Some(parent) = output_pcap.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(output_pcap, bytes)?;
            }
        }
        Command::SuricataAlertCount { eve_json } => {
            println!("{}", suricata_alert_count(&eve_json)?);
        }
        Command::NdpiRiskCount { ndpi_output } => {
            println!("{}", ndpi_risk_count(&ndpi_output)?);
        }
        Command::ClassifierVerdict {
            classifier,
            status,
            scenario,
            transport,
            pcap,
            reason,
            alert_count,
            risk_count,
            json_output,
            ndpi_input_pcap,
        } => {
            let verdict = classifier_verdict(ClassifierVerdictInputs {
                classifier: &classifier,
                status: &status,
                scenario: &scenario,
                transport: &transport,
                pcap: &pcap,
                reason: &reason,
                alert_count,
                risk_count,
                json_output: json_output.as_deref(),
                ndpi_input_pcap: ndpi_input_pcap.as_deref(),
            });
            println!("{}", serde_json::to_string(&verdict)?);
        }
        Command::PrettyJson { input } => {
            print_pretty_json(&input)?;
        }
        Command::BuildDebianPackageHostRunSummary {
            output,
            operator_loop_summary,
            validation_root,
            upgrade_reapply_mode,
            phase,
        } => {
            build_debian_package_host_run_summary(DebianPackageHostRunSummaryInputs {
                output: &output,
                operator_loop_summary: operator_loop_summary.as_deref(),
                validation_root: &validation_root,
                upgrade_reapply_mode: &upgrade_reapply_mode,
                phase: &phase,
            })?;
        }
        Command::BuildDebianPackageHostValidationReport {
            mode,
            os_pretty_name,
            os_id,
            os_version_id,
            package_manager,
            supported_product_contour,
            supported_operator_scope,
            release_gate_name,
            release_gate_scope,
            host_family_id,
            host_family_validation_tier,
            ready,
            release_gate_required_phase,
            command,
            missing_command,
            remediation_command,
            run_command,
            artifact_dir,
            release_handoff_artifact,
            release_summary_artifact,
            operator_loop_summary_artifact,
            pilot_inputs_artifact,
            validation_root,
            helper_exit_code,
            error_code,
        } => {
            let ready = ready
                .parse::<bool>()
                .map_err(|_| format!("invalid --ready value: {ready}"))?;
            let report = build_debian_package_host_validation_report(
                DebianPackageHostValidationReportInputs {
                    mode: &mode,
                    os_pretty_name: &os_pretty_name,
                    os_id: &os_id,
                    os_version_id: os_version_id.as_deref(),
                    package_manager: package_manager.as_deref(),
                    supported_product_contour: &supported_product_contour,
                    supported_operator_scope: &supported_operator_scope,
                    release_gate_name: &release_gate_name,
                    release_gate_scope: &release_gate_scope,
                    host_family_id: &host_family_id,
                    host_family_validation_tier: &host_family_validation_tier,
                    ready,
                    release_gate_required_phase: &release_gate_required_phase,
                    command: &command,
                    missing_command: &missing_command,
                    remediation_command: &remediation_command,
                    run_command: &run_command,
                    artifact_dir: artifact_dir.as_deref(),
                    release_handoff_artifact: release_handoff_artifact.as_deref(),
                    release_summary_artifact: release_summary_artifact.as_deref(),
                    operator_loop_summary_artifact: operator_loop_summary_artifact.as_deref(),
                    pilot_inputs_artifact: pilot_inputs_artifact.as_deref(),
                    validation_root: &validation_root,
                    helper_exit_code,
                    error_code: error_code.as_deref(),
                },
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::BuildDebianPackageHostOperatorLoopSummary {
            output,
            client_config,
            runtime_events,
            preflight_json,
            startup_probe_json,
            events_summary_json,
            operator_evidence_json,
            operator_evidence_txt,
        } => {
            build_debian_package_host_operator_loop_summary(
                DebianPackageHostOperatorLoopSummaryInputs {
                    output: &output,
                    client_config: &client_config,
                    runtime_events: &runtime_events,
                    preflight_json: &preflight_json,
                    startup_probe_json: &startup_probe_json,
                    events_summary_json: &events_summary_json,
                    operator_evidence_json: &operator_evidence_json,
                    operator_evidence_txt: &operator_evidence_txt,
                },
            )?;
        }
        Command::BuildDebianPackageHostReleaseGateHandoff {
            output,
            host_summary,
        } => {
            build_debian_package_host_release_gate_handoff(
                DebianPackageHostReleaseGateHandoffInputs {
                    output: &output,
                    host_summary: &host_summary,
                },
            )?;
        }
        Command::BuildDebianPackageHostReleaseSummary {
            output,
            host_summary,
            release_handoff,
            operator_loop_summary,
        } => {
            build_debian_package_host_release_summary(DebianPackageHostReleaseSummaryInputs {
                output: &output,
                host_summary: &host_summary,
                release_handoff: &release_handoff,
                operator_loop_summary: &operator_loop_summary,
            })?;
        }
        Command::BuildDebianPackageHostPilotInputs {
            output,
            validation_summary,
            runtime_artifacts_dir,
            release_handoff,
            release_summary,
            operator_loop_summary,
        } => {
            build_debian_package_host_pilot_inputs(DebianPackageHostPilotInputsInputs {
                output: &output,
                validation_summary: &validation_summary,
                runtime_artifacts_dir: &runtime_artifacts_dir,
                release_handoff: &release_handoff,
                release_summary: &release_summary,
                operator_loop_summary: &operator_loop_summary,
            })?;
        }
        Command::VerifyDebianPackageHostInstallState {
            dpkg_query,
            validation_root,
        } => {
            verify_debian_package_host_install_state(DebianPackageHostDpkgStateInputs {
                dpkg_query: &dpkg_query,
                validation_root: &validation_root,
            })?;
        }
        Command::VerifyDebianPackageHostRemoveState {
            dpkg_query,
            validation_root,
        } => {
            verify_debian_package_host_remove_state(DebianPackageHostDpkgStateInputs {
                dpkg_query: &dpkg_query,
                validation_root: &validation_root,
            })?;
        }
        Command::VerifyDebianPackageHostPurgeState {
            dpkg_query,
            validation_root,
        } => {
            verify_debian_package_host_purge_state(DebianPackageHostDpkgStateInputs {
                dpkg_query: &dpkg_query,
                validation_root: &validation_root,
            })?;
        }
        Command::CheckDpkgLifecycleSmokeState {
            phase,
            rootdir,
            status_path,
            hook_log,
        } => {
            check_dpkg_lifecycle_smoke_state(DpkgLifecycleSmokeStateInputs {
                phase: &phase,
                rootdir: &rootdir,
                status_path: &status_path,
                hook_log: &hook_log,
            })?;
        }
        Command::VerifyDebianPackageHostClientJsonArtifact {
            artifact,
            exit_status,
        } => {
            verify_debian_package_host_client_json_artifact(
                DebianPackageHostClientJsonArtifactInputs {
                    artifact: &artifact,
                    exit_status,
                },
            )?;
        }
        Command::BuildDebianPackageHostRuntimeEventsSummary {
            runtime_events,
            output,
        } => {
            build_debian_package_host_runtime_events_summary(
                DebianPackageHostRuntimeEventsSummaryInputs {
                    runtime_events: &runtime_events,
                    output: &output,
                },
            )?;
        }
        Command::CheckDebianPackageHostContractJsonCase {
            scenario,
            output,
            exit_status,
        } => {
            check_debian_package_host_contract_json_case(
                DebianPackageHostContractJsonCaseInputs {
                    scenario: &scenario,
                    output: &output,
                    exit_status,
                },
            )?;
        }
        Command::CheckDebianPackageHostContractRunMode {
            output,
            validation_summary,
            release_handoff,
            release_summary,
            pilot_inputs,
            operator_loop,
            dpkg_log,
            helper_log,
            exit_status,
            validation_root,
        } => {
            check_debian_package_host_contract_run_mode(DebianPackageHostContractRunModeInputs {
                output: &output,
                validation_summary: &validation_summary,
                release_handoff: &release_handoff,
                release_summary: &release_summary,
                pilot_inputs: &pilot_inputs,
                operator_loop: &operator_loop,
                dpkg_log: &dpkg_log,
                helper_log: &helper_log,
                exit_status,
                validation_root: &validation_root,
            })?;
        }
        Command::CheckDebianPackageHostContractScript { script } => {
            check_debian_package_host_contract_script(DebianPackageHostContractScriptInputs {
                script: &script,
            })?;
        }
        Command::BuildRpmPackageHostValidationReport {
            mode,
            os_pretty_name,
            os_id,
            os_version_id,
            package_manager,
            supported_product_contour,
            supported_operator_scope,
            host_family_id,
            host_family_validation_tier,
            ready,
            command,
            missing_command,
            remediation_command,
            run_command,
            validation_root,
            helper_exit_code,
            error_code,
        } => {
            let ready = ready
                .parse::<bool>()
                .map_err(|_| format!("invalid --ready value: {ready}"))?;
            let report =
                build_rpm_package_host_validation_report(RpmPackageHostValidationReportInputs {
                    mode: &mode,
                    os_pretty_name: &os_pretty_name,
                    os_id: &os_id,
                    os_version_id: os_version_id.as_deref(),
                    package_manager: package_manager.as_deref(),
                    supported_product_contour: &supported_product_contour,
                    supported_operator_scope: &supported_operator_scope,
                    host_family_id: &host_family_id,
                    host_family_validation_tier: &host_family_validation_tier,
                    ready,
                    command: &command,
                    missing_command: &missing_command,
                    remediation_command: &remediation_command,
                    run_command: &run_command,
                    validation_root: &validation_root,
                    helper_exit_code,
                    error_code: error_code.as_deref(),
                })?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::BuildRpmPackageHostRunSummary { validation_root } => {
            let summary = build_rpm_package_host_run_summary(&validation_root);
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        Command::CheckRpmPackageHostContractJsonCase {
            scenario,
            output,
            exit_status,
        } => {
            check_rpm_package_host_contract_json_case(RpmPackageHostContractJsonCaseInputs {
                scenario: &scenario,
                output: &output,
                exit_status,
            })?;
        }
        Command::CheckRpmPackageHostContractRunMode {
            output,
            validation_summary,
            rpm_log,
            exit_status,
            validation_root,
        } => {
            check_rpm_package_host_contract_run_mode(RpmPackageHostContractRunModeInputs {
                output: &output,
                validation_summary: &validation_summary,
                rpm_log: &rpm_log,
                exit_status,
                validation_root: &validation_root,
            })?;
        }
        Command::CheckRpmPackageHostContractScript { script } => {
            check_rpm_package_host_contract_script(RpmPackageHostContractScriptInputs {
                script: &script,
            })?;
        }
        Command::WideSmokeAdversarialEvent {
            contract_json,
            runtime_events_jsonl,
            output_jsonl,
            scenario,
            transport,
            network_profile,
            artifact_dir,
            packet_capture,
            tcpdump_log,
        } => {
            let event = wide_smoke_adversarial_event(WideSmokeAdversarialEventInputs {
                contract: &read_json(&contract_json)?,
                runtime_events: &read_jsonl(&runtime_events_jsonl)?,
                contract_json: &contract_json,
                runtime_events_jsonl: &runtime_events_jsonl,
                scenario: &scenario,
                transport: &transport,
                network_profile: &network_profile,
                artifact_dir: &artifact_dir,
                packet_capture: packet_capture.as_deref(),
                tcpdump_log: tcpdump_log.as_deref(),
            })?;
            write_text(&output_jsonl, &(serde_json::to_string(&event)? + "\n"))?;
            if event["status"].as_str() != Some("PASS") {
                std::process::exit(1);
            }
        }
        Command::ReserveTcpPort => {
            reserve_tcp_port()?;
        }
        Command::WaitTcpPort {
            host,
            port,
            timeout_secs,
        } => {
            wait_tcp_port(&host, port, timeout_secs)?;
        }
        Command::RunWithTimeout {
            timeout_secs,
            command,
        } => {
            std::process::exit(run_with_timeout(&command, timeout_secs)?);
        }
        Command::ValidateRelayTransportPriority { priority } => {
            validate_relay_transport_priority(&priority)?;
        }
        Command::ConcatTextFiles { output, input } => {
            concat_text_files(&input, &output)?;
        }
        Command::WarnRuntimeEventPresence {
            runtime_events,
            event_code,
            field_bool,
            empty_warning,
            missing_warning,
        } => {
            warn_runtime_event_presence(
                &runtime_events,
                &event_code,
                field_bool.as_deref(),
                &empty_warning,
                &missing_warning,
            )?;
        }
        Command::SocksHttpProbe {
            socks_port,
            target_host,
            target_port,
        } => {
            socks_http_probe(socks_port, &target_host, target_port)?;
        }
        Command::UdpEchoServer {
            host,
            port,
            reuse_addr,
        } => {
            udp_echo_server(&host, port, reuse_addr)?;
        }
        Command::UdpEchoClient {
            host,
            port,
            payload,
            timeout_secs,
        } => {
            udp_echo_client(&host, port, &payload, timeout_secs)?;
        }
        Command::TproxyClientContract { config } => {
            print_tproxy_client_contract(&config)?;
        }
        Command::TproxyStartupProbeFields { stdout, stderr } => {
            print_tproxy_startup_probe_fields(&stdout, &stderr)?;
        }
        Command::TproxyRuntimeEventsSummary {
            runtime_events_jsonl,
            limit,
        } => {
            print_tproxy_runtime_events_summary(&runtime_events_jsonl, limit)?;
        }
        Command::WriteTproxyOperatorEvidence {
            output,
            client_config,
            runtime_events_jsonl,
            events_total,
            backend,
            backend_runtime_id,
            startup_health,
            runtime_status,
            product_verdict,
            runtime_degradation_count,
            failover_count,
            terminal_failure_count,
            latest_code,
            latest_level,
            latest_message,
            problem_code,
            problem_level,
            problem_message,
        } => {
            write_tproxy_operator_evidence(
                &output,
                client_config.as_deref(),
                &runtime_events_jsonl,
                events_total,
                backend.as_deref(),
                backend_runtime_id.as_deref(),
                &startup_health,
                &runtime_status,
                &product_verdict,
                runtime_degradation_count,
                failover_count,
                terminal_failure_count,
                latest_code.as_deref(),
                latest_level.as_deref(),
                latest_message.as_deref(),
                problem_code.as_deref(),
                problem_level.as_deref(),
                problem_message.as_deref(),
            )?;
        }
        Command::WriteTproxySmokeContractArtifact {
            helper_apply_log,
            runtime_events_jsonl,
            output,
            smoke_protocol,
            ip_family,
            host_shape,
            firewall_backend,
            udp_capture_contract,
        } => {
            write_tproxy_smoke_contract_artifact(
                &helper_apply_log,
                &runtime_events_jsonl,
                &output,
                &smoke_protocol,
                &ip_family,
                &host_shape,
                &firewall_backend,
                &udp_capture_contract,
            )?;
        }
        Command::TproxyRuntimeDeliveryHint {
            runtime_events_jsonl,
        } => {
            print_tproxy_runtime_delivery_hint(&runtime_events_jsonl)?;
        }
        Command::VerifyTproxyGenericUdpRuntimeContract {
            runtime_events_jsonl,
            target_port,
            ip_family,
        } => {
            verify_tproxy_generic_udp_runtime_contract(
                &runtime_events_jsonl,
                target_port,
                &ip_family,
            )?;
        }
        Command::VerifyTproxyUdpPreviewDropRuntimeContract {
            runtime_events_jsonl,
            target_port,
            dns_port,
            udp_preview_ports,
            ip_family,
        } => {
            verify_tproxy_udp_preview_drop_runtime_contract(
                &runtime_events_jsonl,
                target_port,
                dns_port,
                &udp_preview_ports,
                &ip_family,
            )?;
        }
        Command::TproxyPreflightExit {
            preflight_json,
            preflight_log,
            status,
            exit_needs_cap_net_admin,
            exit_listener_conflict,
            exit_listener_busy,
            exit_unsupported_adapter,
            exit_socks_bind_failed,
            exit_rollout_prerequisites,
            expected_interface,
        } => {
            tproxy_preflight_exit(
                &preflight_json,
                &preflight_log,
                status,
                exit_needs_cap_net_admin,
                exit_listener_conflict,
                exit_listener_busy,
                exit_unsupported_adapter,
                exit_socks_bind_failed,
                exit_rollout_prerequisites,
                &expected_interface,
            )?;
        }
        Command::WriteTproxyContractSelfTestEvents {
            output,
            smoke_protocol,
            target_host,
            target_port,
            dns_port,
            udp_preview_ports,
            support_tier,
            capture_policy,
            runtime_scope,
            preview_policy,
            variant,
        } => {
            write_tproxy_contract_self_test_events(
                &output,
                &smoke_protocol,
                &target_host,
                target_port,
                dns_port,
                &udp_preview_ports,
                &support_tier,
                &capture_policy,
                &runtime_scope,
                preview_policy.as_deref(),
                variant.as_deref(),
            )?;
        }
        Command::VerifyTproxySmokeContractSelfTest {
            contract_artifact,
            runtime_events_jsonl,
            smoke_protocol,
            ip_family,
            firewall_backend_requested,
            expected_effective,
            expected_tier,
            expected_policy,
            expected_scope,
            target_port,
        } => {
            verify_tproxy_smoke_contract_self_test(
                &contract_artifact,
                &runtime_events_jsonl,
                &smoke_protocol,
                &ip_family,
                &firewall_backend_requested,
                &expected_effective,
                &expected_tier,
                &expected_policy,
                &expected_scope,
                target_port,
            )?;
        }
        Command::VerifyTproxyTransportFailureSelfTest {
            contract_artifact,
            runtime_events_jsonl,
        } => {
            verify_tproxy_transport_failure_self_test(&contract_artifact, &runtime_events_jsonl)?;
        }
        Command::VerifyTproxyTransportRecoveredSelfTest {
            contract_artifact,
            runtime_events_jsonl,
        } => {
            verify_tproxy_transport_recovered_self_test(&contract_artifact, &runtime_events_jsonl)?;
        }
        Command::VerifyTproxyLoopbackIdempotentLog { ip_log } => {
            verify_tproxy_loopback_idempotent_log(&ip_log)?;
        }
        Command::ValidateRichHostBootstrap {
            artifact,
            bootstrap_status,
        } => {
            validate_rich_host_bootstrap(&artifact, bootstrap_status)?;
        }
        Command::BuildWideLinuxValidationHostBootstrapReport {
            mode,
            os_pretty_name,
            os_id,
            os_version_id,
            package_manager,
            supported_product_contour,
            supported_operator_scope,
            host_family_id,
            host_family_validation_tier,
            install_rustup,
            ready,
            command,
            missing_command,
            sudo_status,
            sudo_detail,
            remediation_command,
            bootstrap_check_command,
            bootstrap_install_command,
            validation_command,
            upgrade_reapply_command,
            helper_exit_code,
            error_code,
        } => {
            let install_rustup = install_rustup
                .parse::<bool>()
                .map_err(|_| format!("invalid --install-rustup value: {install_rustup}"))?;
            let ready = ready
                .parse::<bool>()
                .map_err(|_| format!("invalid --ready value: {ready}"))?;
            let report = build_wide_linux_validation_host_bootstrap_report(
                WideLinuxValidationHostBootstrapReportInputs {
                    mode: &mode,
                    os_pretty_name: &os_pretty_name,
                    os_id: &os_id,
                    os_version_id: os_version_id.as_deref(),
                    package_manager: package_manager.as_deref(),
                    supported_product_contour: &supported_product_contour,
                    supported_operator_scope: &supported_operator_scope,
                    host_family_id: &host_family_id,
                    host_family_validation_tier: &host_family_validation_tier,
                    install_rustup,
                    ready,
                    command: &command,
                    missing_command: &missing_command,
                    sudo_status: &sudo_status,
                    sudo_detail: &sudo_detail,
                    remediation_command: &remediation_command,
                    bootstrap_check_command: &bootstrap_check_command,
                    bootstrap_install_command: &bootstrap_install_command,
                    validation_command: &validation_command,
                    upgrade_reapply_command: &upgrade_reapply_command,
                    helper_exit_code,
                    error_code: error_code.as_deref(),
                },
            )?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::CheckWideLinuxValidationHostBootstrapContractCase {
            case_id,
            output_json,
            status,
            command_log,
            expected_cargo,
            package_manager,
            command_snippet,
        } => {
            check_wide_linux_validation_host_bootstrap_contract_case(
                &case_id,
                &output_json,
                status,
                command_log.as_deref(),
                expected_cargo.as_deref(),
                package_manager.as_deref(),
                command_snippet.as_deref(),
            )?;
        }
        Command::CheckWideLinuxValidationHostBootstrapCoverage { repo_root } => {
            check_wide_linux_validation_host_bootstrap_coverage(&repo_root)?;
        }
        Command::WriteRichHostMatrixTargets { output } => {
            write_rich_host_matrix_targets(&output)?;
        }
        Command::BuildRichHostMetadata {
            output,
            host_bootstrap,
        } => {
            build_rich_host_metadata(&output, &host_bootstrap)?;
        }
        Command::BuildRichHostMatrixSummary {
            status_dir,
            artifact_dir,
            matrix_targets,
            matrix_results,
            matrix_summary,
            host_metadata,
            host_bootstrap,
        } => {
            build_rich_host_matrix_summary(RichHostMatrixSummaryInputs {
                status_dir: &status_dir,
                artifact_dir: &artifact_dir,
                matrix_targets: &matrix_targets,
                matrix_results: &matrix_results,
                matrix_summary: &matrix_summary,
                host_metadata: &host_metadata,
                host_bootstrap: &host_bootstrap,
            })?;
        }
        Command::BuildRichHostValidationBundle {
            output,
            artifact_dir,
            matrix_targets,
            matrix_results,
            matrix_summary,
            host_metadata,
            host_bootstrap,
            rerun_env,
            rerun_script,
            bootstrap_helper,
            validation_script,
            cargo_target_dir,
            startup_wait_secs,
            request_timeout_secs,
            case_timeout_secs,
        } => {
            build_rich_host_validation_bundle(RichHostValidationBundleInputs {
                output: &output,
                artifact_dir: &artifact_dir,
                matrix_targets: &matrix_targets,
                matrix_results: &matrix_results,
                matrix_summary: &matrix_summary,
                host_metadata: &host_metadata,
                host_bootstrap: &host_bootstrap,
                rerun_env: &rerun_env,
                rerun_script: &rerun_script,
                bootstrap_helper: &bootstrap_helper,
                validation_script: &validation_script,
                cargo_target_dir: &cargo_target_dir,
                startup_wait_secs,
                request_timeout_secs,
                case_timeout_secs,
            })?;
        }
        Command::CheckRichHostValidationContractArtifacts {
            artifact_dir,
            repo_root,
            failed_artifact_dir,
            bootstrap_fail_artifact_dir,
            bootstrap_fail_output,
            bootstrap_broken_artifact_dir,
            bootstrap_broken_output,
        } => {
            check_rich_host_validation_contract_artifacts(RichHostValidationContractInputs {
                artifact_dir: &artifact_dir,
                repo_root: &repo_root,
                failed_artifact_dir: &failed_artifact_dir,
                bootstrap_fail_artifact_dir: &bootstrap_fail_artifact_dir,
                bootstrap_fail_output: &bootstrap_fail_output,
                bootstrap_broken_artifact_dir: &bootstrap_broken_artifact_dir,
                bootstrap_broken_output: &bootstrap_broken_output,
            })?;
        }
        Command::WideRedirectPreflightExit {
            preflight_json,
            preflight_log,
            status,
            exit_listener_conflict,
            exit_listener_busy,
            exit_unsupported_adapter,
            exit_socks_bind_failed,
            exit_rollout_prerequisites,
            expected_interface,
        } => {
            wide_redirect_preflight_exit(WideRedirectPreflightExitInputs {
                preflight_json: &preflight_json,
                preflight_log: &preflight_log,
                status,
                exit_listener_conflict,
                exit_listener_busy,
                exit_unsupported_adapter,
                exit_socks_bind_failed,
                exit_rollout_prerequisites,
                expected_interface: &expected_interface,
            })?;
        }
        Command::BuildRelaySurfaceRuntimeSummary {
            output_dir,
            runtime_events,
        } => {
            build_relay_surface_runtime_summary(&output_dir, &runtime_events)?;
        }
        Command::BuildStealthHostilePathAcceptanceSummary {
            output_dir,
            wire_acceptance_summary,
            polymorphism_acceptance_summary,
            relay_surface_runtime_summary,
        } => {
            build_stealth_hostile_path_acceptance_summary(
                &output_dir,
                &wire_acceptance_summary,
                &polymorphism_acceptance_summary,
                relay_surface_runtime_summary.as_deref(),
            )?;
        }
        Command::BuildStealthAntiAnomalyAcceptanceSummary {
            output_dir,
            repo_root,
        } => {
            build_stealth_anti_anomaly_acceptance_summary(&output_dir, &repo_root)?;
        }
        Command::BuildStealthPolymorphismAcceptanceSummary {
            output_dir,
            config,
            repo_root,
            now_secs,
        } => {
            build_stealth_polymorphism_acceptance_summary(
                &output_dir,
                &config,
                &repo_root,
                now_secs,
            )?;
        }
        Command::BuildMimicryWireWitnessSummary {
            pcap,
            runtime_events,
            output,
            tshark_bin,
            window_ms,
        } => {
            build_mimicry_wire_witness_summary(
                &pcap,
                &runtime_events,
                &output,
                &tshark_bin,
                window_ms,
            )?;
        }
        Command::BuildMimicryWireValidationContract { output, repo_root } => {
            build_mimicry_wire_validation_contract(&output, &repo_root)?;
        }
        Command::BuildMimicryWireHostAcceptance {
            runtime_events_jsonl,
            contract_json,
            capture_summary_json,
            host_summary_json,
            witness_summary_json,
        } => {
            build_mimicry_wire_host_acceptance(MimicryWireHostAcceptanceInputs {
                runtime_events_jsonl: &runtime_events_jsonl,
                contract_json: &contract_json,
                capture_summary_json: &capture_summary_json,
                host_summary_json: &host_summary_json,
                witness_summary_json: witness_summary_json.as_deref(),
            })?;
        }
        Command::BuildMimicryWireHostHelperReport {
            mode,
            supported_operator_scope,
            supported_product_contour,
            ready,
            runtime_events_jsonl,
            witness_summary_json,
            artifact_dir,
            requirement,
            missing_requirement,
            helper_exit_code,
            error_code,
        } => {
            let ready = ready
                .parse::<bool>()
                .map_err(|_| format!("invalid --ready value: {ready}"))?;
            let report =
                build_mimicry_wire_host_helper_report(MimicryWireHostHelperReportInputs {
                    mode: &mode,
                    supported_operator_scope: &supported_operator_scope,
                    supported_product_contour: &supported_product_contour,
                    ready,
                    runtime_events_jsonl: runtime_events_jsonl.as_deref(),
                    witness_summary_json: witness_summary_json.as_deref(),
                    artifact_dir: artifact_dir.as_deref(),
                    requirement: &requirement,
                    missing_requirement: &missing_requirement,
                    helper_exit_code,
                    error_code: error_code.as_deref(),
                })?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::CheckMimicryWireHostHelperReportContract { report_json } => {
            check_mimicry_wire_host_helper_report_contract(&report_json)?;
        }
        Command::CheckMimicryWireHostAcceptanceContract {
            host_summary_json,
            capture_summary_json,
            stdout_json,
            expected_product_verdict,
            expected_acceptance_status,
            expected_verdict_reason,
            expected_witness_status,
            expected_hostile_path_ready,
            expected_hostile_path_tier,
            expected_witness_matched,
            expected_witness_mismatched,
            expected_mismatch_field,
            expected_records_scanned,
            expected_complete_records,
            expected_active_ready_count,
            expected_active_missing_count,
        } => {
            check_mimicry_wire_host_acceptance_contract(MimicryWireHostAcceptanceContractInputs {
                host_summary_json: &host_summary_json,
                capture_summary_json: capture_summary_json.as_deref(),
                stdout_json: stdout_json.as_deref(),
                expected_product_verdict: &expected_product_verdict,
                expected_acceptance_status: &expected_acceptance_status,
                expected_verdict_reason: &expected_verdict_reason,
                expected_witness_status: expected_witness_status.as_deref(),
                expected_hostile_path_ready,
                expected_hostile_path_tier: expected_hostile_path_tier.as_deref(),
                expected_witness_matched,
                expected_witness_mismatched,
                expected_mismatch_field: expected_mismatch_field.as_deref(),
                expected_records_scanned,
                expected_complete_records,
                expected_active_ready_count,
                expected_active_missing_count,
            })?;
        }
        Command::BuildStealthLiveAcceptanceBundle {
            output_dir,
            wire_acceptance_summary,
            runtime_events,
            relay_runtime_events,
            config,
            polymorphism_summary,
            relay_surface_runtime_summary,
            hostile_path_summary,
        } => {
            build_stealth_live_acceptance_bundle(StealthLiveBundleInputs {
                output_dir: &output_dir,
                wire_acceptance_summary: &wire_acceptance_summary,
                runtime_events: &runtime_events,
                relay_runtime_events: &relay_runtime_events,
                config: &config,
                polymorphism_summary: &polymorphism_summary,
                relay_surface_runtime_summary: &relay_surface_runtime_summary,
                hostile_path_summary: &hostile_path_summary,
            })?;
        }
        Command::BuildPostReleaseStealthWaveSummary {
            output_dir,
            ubuntu_release_wave_status,
            wire_acceptance_summary,
        } => {
            build_post_release_stealth_wave_summary(
                &output_dir,
                ubuntu_release_wave_status.as_deref(),
                wire_acceptance_summary.as_deref(),
            )?;
        }
        Command::BuildLinuxNextExpansionStatus {
            matrix_manifest,
            output,
            review_json,
        } => {
            build_linux_next_expansion_status(&matrix_manifest, &output, review_json.as_deref())?;
        }
        Command::BuildLinuxNextExpansionPlaybook {
            output_dir,
            matrix_manifest,
            target_family,
            host_label,
        } => {
            build_linux_next_expansion_playbook(
                &output_dir,
                &matrix_manifest,
                target_family.as_deref(),
                &host_label,
            )?;
        }
        Command::BuildLinuxNextExpansionWaveManifest {
            output,
            mode,
            source_json,
            status_json,
        } => {
            build_linux_next_expansion_wave_manifest(&output, &mode, &source_json, &status_json)?;
        }
        Command::LinuxNextExpansionReviewInputs {
            matrix_manifest,
            target_evidence,
            target_family,
        } => {
            print_linux_next_expansion_review_inputs(
                &matrix_manifest,
                &target_evidence,
                target_family.as_deref(),
            )?;
        }
        Command::BuildLinuxNextExpansionReviewBundleArtifacts {
            output_dir,
            previous_matrix_manifest,
            target_evidence,
            playbook_json,
            refreshed_matrix_manifest,
            host_label,
        } => {
            build_linux_next_expansion_review_bundle_artifacts(
                &output_dir,
                &previous_matrix_manifest,
                &target_evidence,
                &playbook_json,
                &refreshed_matrix_manifest,
                &host_label,
            )?;
        }
        Command::BuildLinuxReleaseProgramBundle {
            output_dir,
            ubuntu_wave_manifest,
            next_expansion_status,
            stealth_summary,
            mimicry_next_contour,
        } => {
            build_linux_release_program_bundle(
                &output_dir,
                &ubuntu_wave_manifest,
                next_expansion_status.as_deref(),
                stealth_summary.as_deref(),
                mimicry_next_contour.as_deref(),
            )?;
        }
        Command::BuildLinuxPackageAcceptanceMatrix {
            output_dir,
            evidence,
        } => {
            build_linux_package_acceptance_matrix(&output_dir, &evidence)?;
        }
        Command::BuildMacosPfOperatorAcceptanceSummary {
            output_dir,
            rooted_live_dir,
            phase4_dir,
        } => {
            build_macos_pf_operator_acceptance_summary(
                &output_dir,
                &rooted_live_dir,
                phase4_dir.as_deref(),
            )?;
        }
        Command::MacosPfStateBasename {
            state_base_dir,
            home,
            user,
        } => {
            print_macos_pf_state_basename(&state_base_dir, home.as_deref(), user.as_deref());
        }
        Command::MacosPfReadStateJson { state_path } => {
            print_macos_pf_state_json(&state_path)?;
        }
        Command::MacosPfReadStateField { state_path, field } => {
            print_macos_pf_state_field(&state_path, &field)?;
        }
        Command::BuildMacosUtunBlockedResult {
            artifact,
            status,
            blocker,
            output_json,
        } => {
            build_macos_utun_blocked_result(MacosUtunBlockedResultInputs {
                artifact: &artifact,
                status: &status,
                blocker: &blocker,
                output_json: &output_json,
            })?;
        }
        Command::BuildMacosUtunW0BlockedResult {
            status,
            blocker,
            output_json,
        } => {
            build_macos_utun_w0_blocked_result(MacosUtunW0BlockedResultInputs {
                status: &status,
                blocker: &blocker,
                output_json: &output_json,
            })?;
        }
        Command::BuildMacosUtunW0TimeoutResult {
            helper_exit,
            main_exit,
            output_json,
        } => {
            build_macos_utun_w0_timeout_result(MacosUtunW0TimeoutResultInputs {
                helper_exit: &helper_exit,
                main_exit: &main_exit,
                output_json: &output_json,
            })?;
        }
        Command::BuildMacosUtunW1Result {
            status,
            verdict,
            helper_exit,
            main_exit,
            packet_loop_pass,
            route_proof_pass,
            controlled_peer,
            relay_ip,
            output_json,
        } => {
            build_macos_utun_w1_result(MacosUtunW1ResultInputs {
                status: &status,
                verdict: &verdict,
                helper_exit: &helper_exit,
                main_exit: &main_exit,
                packet_loop_pass: &packet_loop_pass,
                route_proof_pass: &route_proof_pass,
                controlled_peer: &controlled_peer,
                relay_ip: &relay_ip,
                output_json: &output_json,
            })?;
        }
        Command::BuildMacosUtunW2Result {
            artifact,
            status,
            verdict,
            helper_exit,
            main_exit,
            packet_loop_pass,
            route_proof_pass,
            tcp_flow_observed,
            tcp_destination_port_match,
            tcp_synack_lab_pass,
            tcp_ack_observed,
            controlled_peer,
            controlled_tcp_port,
            packet_to_flow_adapter,
            output_json,
        } => {
            build_macos_utun_w2_result(MacosUtunW2ResultInputs {
                artifact: &artifact,
                status: &status,
                verdict: &verdict,
                helper_exit: &helper_exit,
                main_exit: &main_exit,
                packet_loop_pass: &packet_loop_pass,
                route_proof_pass: &route_proof_pass,
                tcp_flow_observed: &tcp_flow_observed,
                tcp_destination_port_match: &tcp_destination_port_match,
                tcp_synack_lab_pass: tcp_synack_lab_pass.as_deref(),
                tcp_ack_observed: tcp_ack_observed.as_deref(),
                controlled_peer: &controlled_peer,
                controlled_tcp_port,
                packet_to_flow_adapter: &packet_to_flow_adapter,
                output_json: &output_json,
            })?;
        }
        Command::BuildUbuntuReleaseGateStatus {
            output,
            host_summary,
        } => {
            build_ubuntu_release_gate_status(host_summary.as_deref(), &output)?;
        }
        Command::BuildUbuntuOperatorReapplyCanary {
            output_dir,
            pilot_inputs,
        } => {
            build_ubuntu_operator_reapply_canary(&output_dir, &pilot_inputs)?;
        }
        Command::BuildUbuntuProductOperatorLoopSummary {
            output,
            client_config,
            runtime_events_jsonl,
            operator_evidence_json,
            doctor_log,
            probe_log,
            events_log,
            doctor_status,
            probe_status,
            events_status,
        } => {
            build_ubuntu_operator_loop_summary(UbuntuOperatorLoopSummaryInputs {
                output: &output,
                client_config: &client_config,
                runtime_events_jsonl: &runtime_events_jsonl,
                operator_evidence_json: &operator_evidence_json,
                doctor_log: &doctor_log,
                probe_log: &probe_log,
                events_log: &events_log,
                doctor_status,
                probe_status,
                events_status,
            })?;
        }
        Command::BuildUbuntuProductOperatorLoopCheckReport {
            mode,
            supported_product_contour,
            supported_operator_scope,
            helper_script,
            client_config,
            runtime_events_jsonl,
            operator_evidence_json,
            artifact_dir,
            ready,
            requirement,
            missing_requirement,
            helper_exit_code,
            error_code,
        } => {
            let ready = ready
                .parse::<bool>()
                .map_err(|_| format!("invalid --ready value: {ready}"))?;
            let report =
                build_ubuntu_operator_loop_check_report(UbuntuOperatorLoopCheckReportInputs {
                    mode: &mode,
                    supported_product_contour: &supported_product_contour,
                    supported_operator_scope: &supported_operator_scope,
                    helper_script: &helper_script,
                    client_config: client_config.as_deref(),
                    runtime_events_jsonl: runtime_events_jsonl.as_deref(),
                    operator_evidence_json: operator_evidence_json.as_deref(),
                    artifact_dir: artifact_dir.as_deref(),
                    ready,
                    requirement: &requirement,
                    missing_requirement: &missing_requirement,
                    helper_exit_code,
                    error_code: error_code.as_deref(),
                })?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::BuildUbuntuControlledPilotPlaybook {
            output_dir,
            relay_host,
            client_host,
            blocked_shape,
            bundle,
            bundle_url_file,
        } => {
            let bundle_input =
                BundleInput::from_paths(bundle.as_deref(), bundle_url_file.as_deref())?;
            build_ubuntu_controlled_pilot_playbook(
                &output_dir,
                &relay_host,
                &client_host,
                &blocked_shape,
                &bundle_input,
            )?;
        }
        Command::BuildUbuntuMimicryNextContour {
            output_dir,
            stealth_summary,
            wire_contract,
        } => {
            build_ubuntu_mimicry_next_contour(
                &output_dir,
                stealth_summary.as_deref(),
                &wire_contract,
            )?;
        }
        Command::BuildUbuntuReleaseWaveStatus {
            pilot_inputs,
            pilot_review_manifest,
            output,
        } => {
            build_ubuntu_release_wave_status(&pilot_inputs, &pilot_review_manifest, &output)?;
        }
        Command::BuildUbuntuReleaseReview {
            output_dir,
            release_summary,
            pilot_bundle,
            matrix_manifest,
            wire_acceptance_summary,
        } => {
            build_ubuntu_release_review(
                &output_dir,
                &release_summary,
                &pilot_bundle,
                matrix_manifest.as_deref(),
                wire_acceptance_summary.as_deref(),
            )?;
        }
        Command::BuildUbuntuReleaseWaveBundleManifest {
            output_dir,
            pilot_review_manifest,
            wave_status,
        } => {
            build_ubuntu_release_wave_bundle_manifest(
                &output_dir,
                &pilot_review_manifest,
                &wave_status,
            )?;
        }
        Command::BuildUbuntuFieldPilotRemoteBundleManifest {
            output_dir,
            pilot_inputs,
            pilot_review_manifest,
            release_wave_status,
            release_wave_manifest,
        } => {
            build_ubuntu_field_pilot_remote_bundle_manifest(
                &output_dir,
                &pilot_inputs,
                &pilot_review_manifest,
                &release_wave_status,
                &release_wave_manifest,
            )?;
        }
        Command::UbuntuPilotInputsReleaseSummary { pilot_inputs } => {
            print_ubuntu_pilot_inputs_release_summary(&pilot_inputs)?;
        }
        Command::BuildUbuntuControlledPilotReviewBundleManifest {
            output_dir,
            pilot_inputs,
            playbook_json,
            operator_canary_json,
            pilot_summary_json,
            release_review_json,
            matrix_manifest,
            wire_witness_summary,
            wire_acceptance_summary,
        } => {
            build_ubuntu_controlled_pilot_review_bundle_manifest(
                &output_dir,
                &pilot_inputs,
                &playbook_json,
                &operator_canary_json,
                &pilot_summary_json,
                &release_review_json,
                matrix_manifest.as_deref(),
                wire_witness_summary.as_deref(),
                wire_acceptance_summary.as_deref(),
            )?;
        }
        Command::UbuntuControlledPilotInputFields { pilot_inputs } => {
            print_ubuntu_controlled_pilot_input_fields(&pilot_inputs)?;
        }
        Command::BuildUbuntuControlledPilotBundle {
            output_dir,
            server_status,
            server_journal,
            client_preflight,
            client_startup_probe,
            client_runtime_events_summary,
            client_operator_evidence,
            validation_summary,
            release_summary,
            operator_loop_summary,
            release_handoff,
            pilot_inputs,
            wire_witness_summary,
            wire_acceptance_summary,
            server_host,
            client_host,
            blocked_shape,
        } => {
            build_ubuntu_controlled_pilot_bundle(
                &output_dir,
                &server_status,
                &server_journal,
                &client_preflight,
                &client_startup_probe,
                &client_runtime_events_summary,
                &client_operator_evidence,
                validation_summary.as_deref(),
                release_summary.as_deref(),
                operator_loop_summary.as_deref(),
                release_handoff.as_deref(),
                pilot_inputs.as_deref(),
                wire_witness_summary.as_deref(),
                wire_acceptance_summary.as_deref(),
                &server_host,
                &client_host,
                &blocked_shape,
            )?;
        }
        Command::AdversarialRunner {
            scenario,
            network_profile,
            output_jsonl,
            dry_run,
            live_command,
            live_matrix,
            timeout_seconds,
        } => {
            let events = adversarial_runner(
                scenario.as_deref(),
                network_profile.as_deref(),
                dry_run,
                live_command.as_deref(),
                live_matrix,
                timeout_seconds,
            )?;
            let body = events
                .iter()
                .map(serde_json::to_string)
                .collect::<Result<Vec<_>, _>>()?
                .join("\n")
                + "\n";
            if let Some(path) = output_jsonl {
                write_text(&path, &body)?;
            } else {
                print!("{body}");
            }
        }
        Command::AdversarialRunnerContractCheck { tmp_dir } => {
            adversarial_runner_contract_check(&tmp_dir)?;
        }
        _ => unreachable!("tool dispatch received non-tooling command"),
    }
    Ok(())
}
