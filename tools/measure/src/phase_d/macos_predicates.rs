use serde_json::Value;

use super::result_has_pass;

pub(super) fn macos_socks_artifact_pass(result: &Value) -> bool {
    result_has_pass(result)
        && result["socks_public_ipv4"].as_str().is_some()
        && result["socks_public_ipv4"].as_str() == result["socks_expected_ipv4"].as_str()
        && result["runtime_events_jsonl_valid"].as_bool() == Some(true)
}

pub(super) fn macos_utun_w0_lab_pass(result: &Value) -> bool {
    result_has_pass(result)
        && result["artifact"].as_str() == Some("macos-utun-helper-fd-loop-lab")
        && result["helper_creates_utun"].as_bool() == Some(true)
        && result["fd_passed_to_non_root_main_process"].as_bool() == Some(true)
        && result["packet_or_controlled_injected_packet_observed"].as_bool() == Some(true)
        && result["cleanup_succeeds"].as_bool() == Some(true)
        && result["broad_system_wide_claim"].as_bool() != Some(true)
        && result["packet"]["address_family"].as_i64() == Some(2)
        && result["packet"]["ip_version"].as_i64() == Some(4)
}

pub(super) fn macos_utun_w1_controlled_route_pass(result: &Value) -> bool {
    result_has_pass(result)
        && result["artifact"].as_str() == Some("macos-utun-w1-controlled-route-proof-lab")
        && result["packet_loop_pass"].as_bool() == Some(true)
        && result["route_proof_pass"].as_bool() == Some(true)
        && result["controlled_route_prefix"].as_str() == Some("/32")
        && result["relay_ip_excluded_from_utun"].as_bool() == Some(true)
        && result["default_route_claim"].as_bool() == Some(false)
        && result["broad_system_wide_claim"].as_bool() == Some(false)
        && result["dns_claimed"].as_bool() == Some(false)
        && result["udp_claimed"].as_bool() == Some(false)
        && result["ipv6_claimed"].as_bool() == Some(false)
}

pub(super) fn macos_utun_w2_stateful_tcp_edge_pass(result: &Value) -> bool {
    result_has_pass(result)
        && result["artifact"].as_str() == Some("macos-utun-w2-stateful-tcp-edge-proof-lab")
        && result["packet_loop_pass"].as_bool() == Some(true)
        && result["route_proof_pass"].as_bool() == Some(true)
        && result["tcp_flow_observed"].as_bool() == Some(true)
        && result["tcp_destination_port_match"].as_bool() == Some(true)
        && result["tcp_synack_lab_pass"].as_bool() == Some(true)
        && result["tcp_ack_observed"].as_bool() == Some(true)
        && result["relay_session_claimed"].as_bool() == Some(false)
        && result["broad_system_wide_claim"].as_bool() == Some(false)
}

pub(super) fn macos_utun_w3_local_relay_bridge_pass(result: &Value) -> bool {
    result_has_pass(result)
        && result["artifact"].as_str() == Some("macos-utun-w3-local-relay-bridge-proof-lab")
        && result["w2_stateful_tcp_edge_pass"].as_bool() == Some(true)
        && result["relay_scope"].as_str() == Some("LAB_LOCAL_AEGIS_RELAY")
        && result["relay_session_succeeded"].as_bool() == Some(true)
        && result["socks_egress_probe_exit"].as_i64() == Some(0)
        && result["utun_to_relay_bridge_linkage_proven"].as_bool() == Some(true)
        && result["cloudflare_claimed"].as_bool() == Some(false)
        && result["default_route_claim"].as_bool() == Some(false)
        && result["broad_system_wide_claim"].as_bool() == Some(false)
        && result["dns_claimed"].as_bool() == Some(false)
        && result["udp_claimed"].as_bool() == Some(false)
        && result["ipv6_claimed"].as_bool() == Some(false)
        && result["network_extension_claimed"].as_bool() == Some(false)
}

pub(super) fn macos_utun_w4_policy_cleanup_pass(result: &Value) -> bool {
    let dns_policy = result["dns_policy"].as_str();
    let udp_policy = result["udp_policy"].as_str();
    let ipv6_policy = result["ipv6_policy"].as_str();
    result_has_pass(result)
        && result["artifact"].as_str() == Some("macos-utun-w4-policy-cleanup-matrix-lab")
        && result["tcp_ipv4_controlled_route_relay_bridge_pass"].as_bool() == Some(true)
        && result["policy_matrix_explicit"].as_bool() == Some(true)
        && matches!(dns_policy, Some("CAPTURE" | "BLOCK" | "OUT_OF_SCOPE"))
        && matches!(udp_policy, Some("CAPTURE" | "BLOCK" | "OUT_OF_SCOPE"))
        && matches!(ipv6_policy, Some("CAPTURE" | "BLOCK" | "OUT_OF_SCOPE"))
        && result["relay_ip_exclusion_verified"].as_bool() == Some(true)
        && result["default_route_changed"].as_bool() == Some(false)
        && result["cleanup_only_aegis_owned_state"].as_bool() == Some(true)
        && result["cleanup_restores_baseline_route_state"].as_bool() == Some(true)
        && result["cleanup_after_simulated_helper_client_stop_verified"].as_bool() == Some(true)
        && result["default_route_claim"].as_bool() == Some(false)
        && result["broad_system_wide_claim"].as_bool() == Some(false)
        && result["dns_claimed"].as_bool() == Some(false)
        && result["udp_claimed"].as_bool() == Some(false)
        && result["ipv6_claimed"].as_bool() == Some(false)
        && result["network_extension_claimed"].as_bool() == Some(false)
        && result["product_ready_claim"].as_bool() == Some(false)
}

pub(super) fn macos_utun_w5_controlled_external_relay_path_pass(result: &Value) -> bool {
    result_has_pass(result)
        && result["artifact"].as_str() == Some("macos-utun-w5-controlled-external-relay-path-lab")
        && result["scope"].as_str()
            == Some("LAB_CONTROLLED_EXTERNAL_IPV4_32_ROUTE_PLUS_HTTPS_WS_RELAY_PATH")
        && result["baseline_direct_route_recorded"].as_bool() == Some(true)
        && result["relay_ip_exclusion_recorded"].as_bool() == Some(true)
        && result["aegis_owned_32_route_added"].as_bool() == Some(true)
        && result["controlled_route_prefix"].as_str() == Some("/32")
        && result["packet_loop_observed"].as_bool() == Some(true)
        && result["relay_session_succeeded"].as_bool() == Some(true)
        && result["selected_transport"].as_str() == Some("HttpsWs")
        && result["external_egress_proof_collected"].as_bool() == Some(true)
        && result["phase_c_provider_boundary_recorded"].as_bool() == Some(true)
        && result["macos_utun_external_relay_path_succeeded_event"].as_bool() == Some(true)
        && result["cleanup_only_aegis_owned_state"].as_bool() == Some(true)
        && result["w4_cleanup_policy_pass"].as_bool() == Some(true)
        && result["baseline_route_restored"].as_bool() == Some(true)
        && result["default_route_untouched"].as_bool() == Some(true)
        && result["default_route_claim"].as_bool() == Some(false)
        && result["broad_system_wide_claim"].as_bool() == Some(false)
        && result["dns_claimed"].as_bool() == Some(false)
        && result["udp_claimed"].as_bool() == Some(false)
        && result["ipv6_claimed"].as_bool() == Some(false)
        && result["network_extension_claimed"].as_bool() == Some(false)
        && result["product_ready_claim"].as_bool() == Some(false)
}

pub(super) fn macos_network_extension_system_wide_proven(result: &Value) -> bool {
    result_has_pass(result)
        && result["feature"].as_str() == Some("macos_networkextension_system_wide_proof")
        && result["platform"].as_str() == Some("macOS")
        && result["scope"].as_str() == Some("networkextension_packet_tunnel_ipv4_tcp")
        && result["network_extension_system_wide_proven"].as_bool() == Some(true)
        && result["packet_tunnel_runtime_proven"].as_bool() == Some(true)
        && result["signed_app_and_extension"].as_bool() == Some(true)
        && result["network_extension_entitlement_present"].as_bool() == Some(true)
        && result["vpn_configuration_approved"].as_bool() == Some(true)
        && result["no_manual_proxy_used"].as_bool() == Some(true)
        && result["relay_session_succeeded"].as_bool() == Some(true)
        && result["cleanup_restored_direct_path"].as_bool() == Some(true)
        && result["pf_system_wide_capture_claimed"].as_bool() != Some(true)
}
