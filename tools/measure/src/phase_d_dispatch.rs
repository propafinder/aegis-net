use crate::artifact::{read_json, read_optional_json_path, write_json, write_text};
use crate::cli::Command;
use crate::phase_d::{
    phase_d_android_reach_evidence, phase_d_android_reach_evidence_markdown,
    phase_d_macos_reach_evidence, phase_d_macos_reach_evidence_markdown, phase_d_reach_gate,
    phase_d_reach_gate_markdown, phase_d_windows_reach_evidence,
    phase_d_windows_reach_evidence_markdown, PhaseDAndroidReachEvidenceInputs,
    PhaseDMacosReachEvidenceInputs, PhaseDReachGateInputs, PhaseDWindowsReachEvidenceInputs,
};
use crate::windows_completion::{
    build_windows_dns_udp_next_layer_design, build_windows_mvp_completion_review,
};

pub fn is_phase_d(command: &Command) -> bool {
    matches!(
        command,
        Command::PhaseDReachGate { .. }
            | Command::PhaseDWindowsReachEvidence { .. }
            | Command::WindowsMvpCompletionReview { .. }
            | Command::WindowsDnsUdpNextLayerDesign { .. }
            | Command::PhaseDMacosReachEvidence { .. }
            | Command::PhaseDAndroidReachEvidence { .. }
    )
}

pub fn run(command: Command) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Command::PhaseDReachGate {
            phase_c_resilience_json,
            windows_reach_json,
            macos_reach_json,
            android_reach_json,
            output_json,
            output_markdown,
        } => {
            let windows_reach = read_optional_json_path(windows_reach_json.as_deref())?;
            let macos_reach = read_optional_json_path(macos_reach_json.as_deref())?;
            let android_reach = read_optional_json_path(android_reach_json.as_deref())?;
            let gate = phase_d_reach_gate(
                &read_json(&phase_c_resilience_json)?,
                windows_reach.as_ref(),
                macos_reach.as_ref(),
                android_reach.as_ref(),
                PhaseDReachGateInputs {
                    phase_c_resilience_json: &phase_c_resilience_json,
                    windows_reach_json: windows_reach_json.as_deref(),
                    macos_reach_json: macos_reach_json.as_deref(),
                    android_reach_json: android_reach_json.as_deref(),
                },
            );
            write_json(&output_json, &gate)?;
            if let Some(path) = output_markdown {
                write_text(&path, &phase_d_reach_gate_markdown(&gate))?;
            }
            if gate["status"].as_str() != Some("PHASE_D_EXIT_READY") {
                std::process::exit(1);
            }
        }
        Command::PhaseDWindowsReachEvidence {
            socks_client_artifact,
            service_artifact,
            controlled_wfp_artifact,
            dynamic_original_dst_artifact,
            controlled_process_artifact,
            controlled_browser_artifact,
            dns_policy_json,
            udp_policy_json,
            ipv6_policy_json,
            service_persistence_json,
            service_reboot_json,
            dns_udp_next_scope_json,
            rollback_matrix_json,
            broad_capture_claimed,
            output_json,
            output_markdown,
        } => {
            let evidence = phase_d_windows_reach_evidence(PhaseDWindowsReachEvidenceInputs {
                socks_client_artifact: &socks_client_artifact,
                service_artifact: &service_artifact,
                controlled_wfp_artifact: &controlled_wfp_artifact,
                dynamic_original_dst_artifact: &dynamic_original_dst_artifact,
                controlled_process_artifact: controlled_process_artifact.as_deref(),
                controlled_browser_artifact: controlled_browser_artifact.as_deref(),
                dns_policy_json: dns_policy_json.as_deref(),
                udp_policy_json: udp_policy_json.as_deref(),
                ipv6_policy_json: ipv6_policy_json.as_deref(),
                service_persistence_json: service_persistence_json.as_deref(),
                service_reboot_json: service_reboot_json.as_deref(),
                dns_udp_next_scope_json: dns_udp_next_scope_json.as_deref(),
                rollback_matrix_json: rollback_matrix_json.as_deref(),
                broad_capture_claimed,
            });
            write_json(&output_json, &evidence)?;
            if let Some(path) = output_markdown {
                write_text(&path, &phase_d_windows_reach_evidence_markdown(&evidence))?;
            }
            if evidence["socks_client_baseline_pass"].as_bool() != Some(true)
                || evidence["service_baseline_pass"].as_bool() != Some(true)
                || evidence["controlled_wfp_tcp_path_pass"].as_bool() != Some(true)
                || evidence["dynamic_original_destination_pass"].as_bool() != Some(true)
                || evidence["broad_capture_claimed"].as_bool() == Some(true)
            {
                std::process::exit(1);
            }
        }
        Command::WindowsMvpCompletionReview {
            windows_reach_json,
            output_dir,
        } => {
            build_windows_mvp_completion_review(&windows_reach_json, &output_dir)?;
        }
        Command::WindowsDnsUdpNextLayerDesign { output_dir } => {
            build_windows_dns_udp_next_layer_design(&output_dir)?;
        }
        Command::PhaseDMacosReachEvidence {
            pf_artifact,
            foreground_socks_artifact,
            launchdaemon_socks_artifact,
            utun_lab_artifact,
            utun_w1_artifact,
            utun_w2_artifact,
            utun_w3_artifact,
            utun_w4_artifact,
            utun_w5_artifact,
            network_extension_artifact,
            pf_system_wide_capture_claimed,
            output_json,
            output_markdown,
        } => {
            let evidence = phase_d_macos_reach_evidence(PhaseDMacosReachEvidenceInputs {
                pf_artifact: &pf_artifact,
                foreground_socks_artifact: &foreground_socks_artifact,
                launchdaemon_socks_artifact: &launchdaemon_socks_artifact,
                utun_lab_artifact: utun_lab_artifact.as_deref(),
                utun_w1_artifact: utun_w1_artifact.as_deref(),
                utun_w2_artifact: utun_w2_artifact.as_deref(),
                utun_w3_artifact: utun_w3_artifact.as_deref(),
                utun_w4_artifact: utun_w4_artifact.as_deref(),
                utun_w5_artifact: utun_w5_artifact.as_deref(),
                network_extension_artifact: &network_extension_artifact,
                pf_system_wide_capture_claimed,
            });
            write_json(&output_json, &evidence)?;
            if let Some(path) = output_markdown {
                write_text(&path, &phase_d_macos_reach_evidence_markdown(&evidence))?;
            }
            if evidence["pf_apply_cleanup_evidence"].as_bool() != Some(true)
                || evidence["foreground_socks_supported"].as_bool() != Some(true)
                || evidence["launchdaemon_socks_supported"].as_bool() != Some(true)
                || evidence["network_extension_system_wide_proven"].as_bool() != Some(true)
                || evidence["pf_system_wide_capture_claimed"].as_bool() == Some(true)
            {
                std::process::exit(1);
            }
        }
        Command::PhaseDAndroidReachEvidence {
            vpnservice_flow_json,
            production_claim,
            output_json,
            output_markdown,
        } => {
            let evidence = phase_d_android_reach_evidence(PhaseDAndroidReachEvidenceInputs {
                vpnservice_flow_json: vpnservice_flow_json.as_deref(),
                production_claim,
            });
            write_json(&output_json, &evidence)?;
            if let Some(path) = output_markdown {
                write_text(&path, &phase_d_android_reach_evidence_markdown(&evidence))?;
            }
            if evidence["rust_jni_core_compiles"].as_bool() != Some(true)
                || evidence["production_android_claimed"].as_bool() == Some(true)
            {
                std::process::exit(1);
            }
        }
        _ => unreachable!("phase d dispatch received non-phase-d command"),
    }
    Ok(())
}
