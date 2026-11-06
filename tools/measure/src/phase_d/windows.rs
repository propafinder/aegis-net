use std::path::Path;

use serde_json::{json, Value};

use super::windows_optional::{
    optional_controlled_browser_capture, optional_controlled_process_capture, optional_dns_policy,
    optional_dns_udp_next_scope, optional_ipv6_policy, optional_rollback_matrix,
    optional_service_persistence, optional_service_reboot, optional_udp_policy,
};
use super::{phase_d_bool, read_artifact_result_json, result_claim_not_wide, result_has_pass};

pub struct PhaseDWindowsReachEvidenceInputs<'a> {
    pub socks_client_artifact: &'a Path,
    pub service_artifact: &'a Path,
    pub controlled_wfp_artifact: &'a Path,
    pub dynamic_original_dst_artifact: &'a Path,
    pub controlled_process_artifact: Option<&'a Path>,
    pub controlled_browser_artifact: Option<&'a Path>,
    pub dns_policy_json: Option<&'a Path>,
    pub udp_policy_json: Option<&'a Path>,
    pub ipv6_policy_json: Option<&'a Path>,
    pub service_persistence_json: Option<&'a Path>,
    pub service_reboot_json: Option<&'a Path>,
    pub dns_udp_next_scope_json: Option<&'a Path>,
    pub rollback_matrix_json: Option<&'a Path>,
    pub broad_capture_claimed: bool,
}

pub fn phase_d_windows_reach_evidence(inputs: PhaseDWindowsReachEvidenceInputs<'_>) -> Value {
    let socks_result = read_artifact_result_json(inputs.socks_client_artifact);
    let service_result = read_artifact_result_json(inputs.service_artifact);
    let controlled_wfp_result = read_artifact_result_json(inputs.controlled_wfp_artifact);
    let dynamic_dst_result = read_artifact_result_json(inputs.dynamic_original_dst_artifact);

    let socks_client_baseline_pass = result_has_pass(&socks_result)
        && socks_result["socks_listener_verified"].as_bool() == Some(true)
        && socks_result["socks_egress_verified"].as_bool() == Some(true)
        && result_claim_not_wide(&socks_result);
    let service_baseline_pass = result_has_pass(&service_result)
        && service_result["service_installed"].as_bool() == Some(true)
        && service_result["service_started"].as_bool() == Some(true)
        && service_result["socks_listener_verified"].as_bool() == Some(true)
        && service_result["socks_egress_verified"].as_bool() == Some(true);
    let service_baseline_blocker = service_result["blocker"]
        .as_str()
        .or_else(|| service_result["blocked_reason_code"].as_str())
        .unwrap_or(if service_baseline_pass {
            ""
        } else {
            "service_baseline_missing"
        })
        .to_string();
    let service_admin_ready = service_result["administrator_shell"].as_bool() == Some(true)
        || service_result["service_installed"].as_bool() == Some(true);
    let service_whatif_pass = service_result["install_script_whatif"].as_str() == Some("PASS")
        && service_result["uninstall_script_whatif"].as_str() == Some("PASS");
    let controlled_wfp_tcp_path_pass = result_has_pass(&controlled_wfp_result)
        && controlled_wfp_result["scope"].as_str() == Some("controlled_tcp_ipv4")
        && controlled_wfp_result["flow_redirected_to_aegis"].as_bool() == Some(true)
        && controlled_wfp_result["relay_session_succeeded"].as_bool() == Some(true)
        && controlled_wfp_result["broad_capture_claim"].as_str() != Some("claimed");
    let dynamic_original_destination_pass = result_has_pass(&dynamic_dst_result)
        && dynamic_dst_result["original_dst_method"].as_str() == Some("wfp_redirect_context")
        && dynamic_dst_result["configured_original_dst_fallback"].as_bool() == Some(false)
        && dynamic_dst_result["relay_session_succeeded"].as_bool() == Some(true);

    let controlled_process_capture_pass =
        optional_controlled_process_capture(inputs.controlled_process_artifact);
    let controlled_browser_capture_pass =
        optional_controlled_browser_capture(inputs.controlled_browser_artifact);
    let dns_policy_proven = optional_dns_policy(inputs.dns_policy_json);
    let udp_policy_proven = optional_udp_policy(inputs.udp_policy_json);
    let ipv6_policy_proven = optional_ipv6_policy(inputs.ipv6_policy_json);
    let service_persistence_proven = optional_service_persistence(inputs.service_persistence_json);
    let service_reboot = optional_service_reboot(inputs.service_reboot_json);
    let dns_udp_next_scope = optional_dns_udp_next_scope(inputs.dns_udp_next_scope_json);
    let rollback_matrix_proven = optional_rollback_matrix(inputs.rollback_matrix_json);

    json!({
        "socks_client_baseline_pass": socks_client_baseline_pass,
        "socks_baseline_pass": socks_client_baseline_pass,
        "service_baseline_pass": service_baseline_pass,
        "service_baseline_blocker": service_baseline_blocker,
        "service_relay_tcp_reachable": service_result["relay_tcp_reachable"].as_bool(),
        "service_admin_ready": service_admin_ready,
        "service_whatif_pass": service_whatif_pass,
        "controlled_wfp_tcp_path_pass": controlled_wfp_tcp_path_pass,
        "controlled_tcp_wfp_pass": controlled_wfp_tcp_path_pass,
        "dynamic_original_destination_pass": dynamic_original_destination_pass,
        "dynamic_original_dst_pass": dynamic_original_destination_pass,
        "controlled_process_capture_pass": controlled_process_capture_pass,
        "process_capture_pass": controlled_process_capture_pass,
        "controlled_browser_capture_pass": controlled_browser_capture_pass,
        "browser_capture_pass": controlled_browser_capture_pass,
        "broad_capture_claimed": inputs.broad_capture_claimed,
        "broad_windows_wide_claimed": inputs.broad_capture_claimed,
        "dns_policy_proven": dns_policy_proven,
        "udp_policy_proven": udp_policy_proven,
        "ipv6_policy_proven": ipv6_policy_proven,
        "service_persistence_proven": service_persistence_proven,
        "service_restart_pass": service_persistence_proven,
        "service_reboot_pass": service_reboot.0,
        "service_reboot_status": service_reboot.1,
        "dns_udp_next_scope_status": dns_udp_next_scope.0,
        "dns_capture_claimed": dns_udp_next_scope.1,
        "udp_capture_claimed": dns_udp_next_scope.2,
        "ipv6_capture_claimed": false,
        "rollback_matrix_proven": rollback_matrix_proven,
        "rollback_matrix_pass": rollback_matrix_proven,
        "artifacts": {
            "socks_client_baseline": inputs.socks_client_artifact,
            "service_baseline": inputs.service_artifact,
            "controlled_wfp_tcp_path": inputs.controlled_wfp_artifact,
            "dynamic_original_destination": inputs.dynamic_original_dst_artifact,
            "controlled_process_capture": inputs.controlled_process_artifact,
            "controlled_browser_capture": inputs.controlled_browser_artifact,
            "dns_policy_json": inputs.dns_policy_json,
            "udp_policy_json": inputs.udp_policy_json,
            "ipv6_policy_json": inputs.ipv6_policy_json,
            "service_persistence_json": inputs.service_persistence_json,
            "service_reboot_json": inputs.service_reboot_json,
            "dns_udp_next_scope_json": inputs.dns_udp_next_scope_json,
            "rollback_matrix_json": inputs.rollback_matrix_json,
        },
    })
}

pub(super) fn phase_d_windows_reach_review(evidence: Option<&Value>) -> Value {
    let Some(evidence) = evidence else {
        return json!({
            "status": "MISSING",
            "prep_ready": false,
            "exit_ready": false,
            "overstated_claim_detected": false,
            "blockers": ["windows_reach_evidence_missing"],
        });
    };
    let socks = phase_d_bool(evidence, "socks_client_baseline_pass");
    let service = phase_d_bool(evidence, "service_baseline_pass");
    let service_blocker = evidence["service_baseline_blocker"].as_str();
    let controlled_wfp = phase_d_bool(evidence, "controlled_wfp_tcp_path_pass");
    let dynamic_dst = phase_d_bool(evidence, "dynamic_original_destination_pass");
    let controlled_process = phase_d_bool(evidence, "controlled_process_capture_pass");
    let controlled_browser = phase_d_bool(evidence, "controlled_browser_capture_pass");
    let broad_claim = phase_d_bool(evidence, "broad_capture_claimed");
    let dns = phase_d_bool(evidence, "dns_policy_proven");
    let udp = phase_d_bool(evidence, "udp_policy_proven");
    let ipv6 = phase_d_bool(evidence, "ipv6_policy_proven");
    let persistence = phase_d_bool(evidence, "service_persistence_proven");
    let service_reboot = phase_d_bool(evidence, "service_reboot_pass");
    let rollback = phase_d_bool(evidence, "rollback_matrix_proven");
    let dns_claim = phase_d_bool(evidence, "dns_capture_claimed");
    let udp_claim = phase_d_bool(evidence, "udp_capture_claimed");
    let ipv6_claim = phase_d_bool(evidence, "ipv6_capture_claimed");
    let overclaim = broad_claim || dns_claim || udp_claim || ipv6_claim;
    let prep_ready = socks && service && controlled_wfp && dynamic_dst && !overclaim;
    let exit_ready = prep_ready
        && controlled_process
        && controlled_browser
        && dns
        && udp
        && ipv6
        && persistence
        && rollback;
    let mut blockers = Vec::new();
    if !socks {
        blockers.push("socks_client_baseline_missing");
    }
    if !service {
        blockers.push(service_blocker.unwrap_or("service_baseline_missing"));
    }
    if !controlled_wfp {
        blockers.push("controlled_wfp_tcp_path_missing");
    }
    if !dynamic_dst {
        blockers.push("dynamic_original_destination_missing");
    }
    if !controlled_process {
        blockers.push("controlled_process_capture_not_proven");
    }
    if !controlled_browser {
        blockers.push("controlled_browser_capture_not_proven");
    }
    if broad_claim {
        blockers.push("broad_capture_overclaim_detected");
    }
    if dns_claim {
        blockers.push("dns_capture_overclaim_detected");
    }
    if udp_claim {
        blockers.push("udp_capture_overclaim_detected");
    }
    if ipv6_claim {
        blockers.push("ipv6_capture_overclaim_detected");
    }
    if !dns {
        blockers.push("dns_policy_not_proven");
    }
    if !udp {
        blockers.push("udp_policy_not_proven");
    }
    if !ipv6 {
        blockers.push("ipv6_policy_not_proven");
    }
    if !persistence {
        blockers.push("service_persistence_not_proven");
    }
    if !rollback {
        blockers.push("rollback_matrix_not_proven");
    }
    json!({
        "status": if exit_ready { "PASS" } else if prep_ready { "PREP" } else { "FAIL" },
        "prep_ready": prep_ready,
        "exit_ready": exit_ready,
        "service_reboot_pass": service_reboot,
        "dns_udp_next_scope_status": evidence["dns_udp_next_scope_status"].clone(),
        "overstated_claim_detected": overclaim,
        "blockers": blockers,
    })
}
