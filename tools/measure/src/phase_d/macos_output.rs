use serde_json::Value;

pub fn phase_d_macos_reach_evidence_markdown(evidence: &Value) -> String {
    format!(
        "# Phase D macOS Reach Evidence\n\n\
         - PF apply/cleanup evidence: `{}`\n\
         - Foreground SOCKS supported: `{}`\n\
         - LaunchDaemon SOCKS supported: `{}`\n\
         - utun W0 lab pass: `{}`\n\
         - utun W1 controlled IPv4 /32 route pass: `{}`\n\
         - utun W2 stateful TCP edge pass: `{}`\n\
         - utun W3 local relay bridge pass: `{}`\n\
         - utun W4 policy cleanup matrix pass: `{}`\n\
         - utun W5 controlled external relay path pass: `{}`\n\
         - NetworkExtension SDK ready: `{}`\n\
         - NetworkExtension system-wide proven: `{}`\n\
         - PF system-wide capture claimed: `{}`\n",
        evidence["pf_apply_cleanup_evidence"]
            .as_bool()
            .unwrap_or(false),
        evidence["foreground_socks_supported"]
            .as_bool()
            .unwrap_or(false),
        evidence["launchdaemon_socks_supported"]
            .as_bool()
            .unwrap_or(false),
        evidence["utun_w0_lab_pass"].as_bool().unwrap_or(false),
        evidence["utun_w1_controlled_route_pass"]
            .as_bool()
            .unwrap_or(false),
        evidence["utun_w2_stateful_tcp_edge_pass"]
            .as_bool()
            .unwrap_or(false),
        evidence["utun_w3_local_relay_bridge_pass"]
            .as_bool()
            .unwrap_or(false),
        evidence["utun_w4_policy_cleanup_pass"]
            .as_bool()
            .unwrap_or(false),
        evidence["utun_w5_controlled_external_relay_path_pass"]
            .as_bool()
            .unwrap_or(false),
        evidence["network_extension_sdk_ready"]
            .as_bool()
            .unwrap_or(false),
        evidence["network_extension_system_wide_proven"]
            .as_bool()
            .unwrap_or(false),
        evidence["pf_system_wide_capture_claimed"]
            .as_bool()
            .unwrap_or(false),
    )
}
