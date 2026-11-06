use std::path::Path;

use serde_json::{json, Value};

use super::macos_predicates::{
    macos_network_extension_system_wide_proven, macos_socks_artifact_pass, macos_utun_w0_lab_pass,
    macos_utun_w1_controlled_route_pass, macos_utun_w2_stateful_tcp_edge_pass,
    macos_utun_w3_local_relay_bridge_pass, macos_utun_w4_policy_cleanup_pass,
    macos_utun_w5_controlled_external_relay_path_pass,
};
use super::{phase_d_bool, read_artifact_result_json, result_has_pass};

pub struct PhaseDMacosReachEvidenceInputs<'a> {
    pub pf_artifact: &'a Path,
    pub foreground_socks_artifact: &'a Path,
    pub launchdaemon_socks_artifact: &'a Path,
    pub utun_lab_artifact: Option<&'a Path>,
    pub utun_w1_artifact: Option<&'a Path>,
    pub utun_w2_artifact: Option<&'a Path>,
    pub utun_w3_artifact: Option<&'a Path>,
    pub utun_w4_artifact: Option<&'a Path>,
    pub utun_w5_artifact: Option<&'a Path>,
    pub network_extension_artifact: &'a Path,
    pub pf_system_wide_capture_claimed: bool,
}

pub fn phase_d_macos_reach_evidence(inputs: PhaseDMacosReachEvidenceInputs<'_>) -> Value {
    let pf_result = read_artifact_result_json(inputs.pf_artifact);
    let foreground_result = read_artifact_result_json(inputs.foreground_socks_artifact);
    let launchdaemon_result = read_artifact_result_json(inputs.launchdaemon_socks_artifact);
    let utun_lab_result = inputs.utun_lab_artifact.map(read_artifact_result_json);
    let utun_w1_result = inputs.utun_w1_artifact.map(read_artifact_result_json);
    let utun_w2_result = inputs.utun_w2_artifact.map(read_artifact_result_json);
    let utun_w3_result = inputs.utun_w3_artifact.map(read_artifact_result_json);
    let utun_w4_result = inputs.utun_w4_artifact.map(read_artifact_result_json);
    let utun_w5_result = inputs.utun_w5_artifact.map(read_artifact_result_json);
    let ne_result = read_artifact_result_json(inputs.network_extension_artifact);

    let pf_apply_cleanup_evidence = result_has_pass(&pf_result)
        && pf_result["live_claim"].as_str() == Some("PF_RULE_APPLY_AND_CLEANUP_ONLY")
        && pf_result["runtime_traffic_proof"].as_bool() == Some(false)
        && pf_result["apply"]["command_result"].as_str() == Some("PASS")
        && pf_result["cleanup"]["result"].as_str() == Some("PASS")
        && pf_result["cleanup"]["aegis_rules_gone"].as_bool() == Some(true);
    let foreground_socks_supported = macos_socks_artifact_pass(&foreground_result);
    let launchdaemon_socks_supported = macos_socks_artifact_pass(&launchdaemon_result);
    let utun_w0_lab_pass = utun_lab_result.as_ref().is_some_and(macos_utun_w0_lab_pass);
    let utun_w1_controlled_route_pass = utun_w1_result
        .as_ref()
        .is_some_and(macos_utun_w1_controlled_route_pass);
    let utun_w2_stateful_tcp_edge_pass = utun_w2_result
        .as_ref()
        .is_some_and(macos_utun_w2_stateful_tcp_edge_pass);
    let utun_w3_local_relay_bridge_pass = utun_w3_result
        .as_ref()
        .is_some_and(macos_utun_w3_local_relay_bridge_pass);
    let utun_w4_policy_cleanup_pass = utun_w4_result
        .as_ref()
        .is_some_and(macos_utun_w4_policy_cleanup_pass);
    let utun_w5_controlled_external_relay_path_pass = utun_w5_result
        .as_ref()
        .is_some_and(macos_utun_w5_controlled_external_relay_path_pass);
    let network_extension_sdk_ready =
        ne_result["networkextension_sdk"]["framework_in_xcode_sdk"].as_bool() == Some(true)
            && ne_result["networkextension_sdk"]["packet_tunnel_provider_typecheck"].as_str()
                == Some("PASS");
    let network_extension_system_wide_proven =
        macos_network_extension_system_wide_proven(&ne_result);

    json!({
        "pf_apply_cleanup_evidence": pf_apply_cleanup_evidence,
        "foreground_socks_supported": foreground_socks_supported,
        "launchdaemon_socks_supported": launchdaemon_socks_supported,
        "utun_w0_lab_pass": utun_w0_lab_pass,
        "utun_w0_lab_scope": if utun_w0_lab_pass { "LAB_CONTROLLED_HELPER_FD_LOOP" } else { "NOT_PROVEN" },
        "utun_w1_controlled_route_pass": utun_w1_controlled_route_pass,
        "utun_w1_scope": if utun_w1_controlled_route_pass { "LAB_CONTROLLED_IPV4_32_ROUTE_ONLY" } else { "NOT_PROVEN" },
        "utun_w2_stateful_tcp_edge_pass": utun_w2_stateful_tcp_edge_pass,
        "utun_w2_scope": if utun_w2_stateful_tcp_edge_pass { "LAB_TCP_IPV4_SYN_SYNACK_ACK_EDGE_ONLY" } else { "NOT_PROVEN" },
        "utun_w3_local_relay_bridge_pass": utun_w3_local_relay_bridge_pass,
        "utun_w3_scope": if utun_w3_local_relay_bridge_pass { "LAB_LOCAL_AEGIS_RELAY_TRIGGER" } else { "NOT_PROVEN" },
        "utun_w4_policy_cleanup_pass": utun_w4_policy_cleanup_pass,
        "utun_w4_scope": if utun_w4_policy_cleanup_pass { "LAB_POLICY_BOUNDARY_AND_CLEANUP_MATRIX" } else { "NOT_PROVEN" },
        "utun_w5_controlled_external_relay_path_pass": utun_w5_controlled_external_relay_path_pass,
        "utun_w5_scope": if utun_w5_controlled_external_relay_path_pass { "LAB_CONTROLLED_EXTERNAL_IPV4_32_ROUTE_PLUS_HTTPS_WS_RELAY_PATH" } else { "NOT_PROVEN" },
        "network_extension_sdk_ready": network_extension_sdk_ready,
        "network_extension_system_wide_proven": network_extension_system_wide_proven,
        "pf_system_wide_capture_claimed": inputs.pf_system_wide_capture_claimed,
        "artifacts": {
            "pf_apply_cleanup": inputs.pf_artifact,
            "foreground_socks": inputs.foreground_socks_artifact,
            "launchdaemon_socks": inputs.launchdaemon_socks_artifact,
            "utun_w0_lab": inputs.utun_lab_artifact,
            "utun_w1_controlled_route": inputs.utun_w1_artifact,
            "utun_w2_stateful_tcp_edge": inputs.utun_w2_artifact,
            "utun_w3_local_relay_bridge": inputs.utun_w3_artifact,
            "utun_w4_policy_cleanup_matrix": inputs.utun_w4_artifact,
            "utun_w5_controlled_external_relay_path": inputs.utun_w5_artifact,
            "network_extension_status": inputs.network_extension_artifact,
        },
    })
}

pub(super) fn phase_d_macos_reach_review(evidence: Option<&Value>) -> Value {
    let Some(evidence) = evidence else {
        return json!({
            "status": "MISSING",
            "prep_ready": false,
            "exit_ready": false,
            "overstated_claim_detected": false,
            "blockers": ["macos_reach_evidence_missing"],
        });
    };
    let pf = phase_d_bool(evidence, "pf_apply_cleanup_evidence");
    let socks = phase_d_bool(evidence, "foreground_socks_supported");
    let launchdaemon = phase_d_bool(evidence, "launchdaemon_socks_supported");
    let utun_w0_lab = phase_d_bool(evidence, "utun_w0_lab_pass");
    let utun_w1 = phase_d_bool(evidence, "utun_w1_controlled_route_pass");
    let utun_w2 = phase_d_bool(evidence, "utun_w2_stateful_tcp_edge_pass");
    let utun_w3 = phase_d_bool(evidence, "utun_w3_local_relay_bridge_pass");
    let utun_w4 = phase_d_bool(evidence, "utun_w4_policy_cleanup_pass");
    let utun_w5 = phase_d_bool(evidence, "utun_w5_controlled_external_relay_path_pass");
    let ne = phase_d_bool(evidence, "network_extension_system_wide_proven");
    let invalid_pf_claim = phase_d_bool(evidence, "pf_system_wide_capture_claimed");
    let prep_ready = pf && socks && launchdaemon && !invalid_pf_claim;
    let exit_ready = prep_ready && ne;
    let mut blockers = Vec::new();
    if !pf {
        blockers.push("pf_apply_cleanup_evidence_missing");
    }
    if !socks {
        blockers.push("foreground_socks_support_missing");
    }
    if !launchdaemon {
        blockers.push("launchdaemon_socks_support_missing");
    }
    if !utun_w0_lab {
        blockers.push("utun_w0_lab_not_proven");
    }
    if invalid_pf_claim {
        blockers.push("pf_system_wide_overclaim_detected");
    }
    if !ne {
        blockers.push("network_extension_system_wide_not_proven");
    }
    json!({
        "status": if exit_ready { "PASS" } else if prep_ready { "PREP" } else { "FAIL" },
        "prep_ready": prep_ready,
        "exit_ready": exit_ready,
        "utun_w0_lab_pass": utun_w0_lab,
        "utun_w1_controlled_route_pass": utun_w1,
        "utun_w2_stateful_tcp_edge_pass": utun_w2,
        "utun_w3_local_relay_bridge_pass": utun_w3,
        "utun_w4_policy_cleanup_pass": utun_w4,
        "utun_w5_controlled_external_relay_path_pass": utun_w5,
        "overstated_claim_detected": invalid_pf_claim,
        "blockers": blockers,
    })
}
