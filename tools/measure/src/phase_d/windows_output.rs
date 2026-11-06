use serde_json::Value;

pub fn phase_d_windows_reach_evidence_markdown(evidence: &Value) -> String {
    format!(
        "# Phase D Windows Reach Evidence\n\n\
         - SOCKS client baseline: `{}`\n\
         - SOCKS baseline alias: `{}`\n\
         - Service baseline: `{}`\n\
         - Service admin ready: `{}`\n\
         - Service WhatIf: `{}`\n\
         - Controlled WFP TCP path: `{}`\n\
         - Controlled TCP WFP alias: `{}`\n\
         - Dynamic original destination: `{}`\n\
         - Dynamic original dst alias: `{}`\n\
         - Controlled process capture: `{}`\n\
         - Controlled browser capture: `{}`\n\
         - Broad capture claimed: `{}`\n\
         - DNS policy proven: `{}`\n\
         - UDP policy proven: `{}`\n\
         - IPv6 policy proven: `{}`\n\
         - Service persistence proven: `{}`\n\
         - Service restart pass: `{}`\n\
         - Service reboot pass: `{}`\n\
         - Service reboot status: `{}`\n\
         - DNS/UDP next-scope status: `{}`\n\
         - DNS capture claimed: `{}`\n\
         - UDP capture claimed: `{}`\n\
         - IPv6 capture claimed: `{}`\n\
         - Rollback matrix proven: `{}`\n",
        evidence["socks_client_baseline_pass"]
            .as_bool()
            .unwrap_or(false),
        evidence["socks_baseline_pass"].as_bool().unwrap_or(false),
        evidence["service_baseline_pass"].as_bool().unwrap_or(false),
        evidence["service_admin_ready"].as_bool().unwrap_or(false),
        evidence["service_whatif_pass"].as_bool().unwrap_or(false),
        evidence["controlled_wfp_tcp_path_pass"]
            .as_bool()
            .unwrap_or(false),
        evidence["controlled_tcp_wfp_pass"]
            .as_bool()
            .unwrap_or(false),
        evidence["dynamic_original_destination_pass"]
            .as_bool()
            .unwrap_or(false),
        evidence["dynamic_original_dst_pass"]
            .as_bool()
            .unwrap_or(false),
        evidence["controlled_process_capture_pass"]
            .as_bool()
            .unwrap_or(false),
        evidence["controlled_browser_capture_pass"]
            .as_bool()
            .unwrap_or(false),
        evidence["broad_capture_claimed"].as_bool().unwrap_or(false),
        evidence["dns_policy_proven"].as_bool().unwrap_or(false),
        evidence["udp_policy_proven"].as_bool().unwrap_or(false),
        evidence["ipv6_policy_proven"].as_bool().unwrap_or(false),
        evidence["service_persistence_proven"]
            .as_bool()
            .unwrap_or(false),
        evidence["service_restart_pass"].as_bool().unwrap_or(false),
        evidence["service_reboot_pass"].as_bool().unwrap_or(false),
        evidence["service_reboot_status"]
            .as_str()
            .unwrap_or("NOT_PROVIDED"),
        evidence["dns_udp_next_scope_status"]
            .as_str()
            .unwrap_or("NOT_PROVIDED"),
        evidence["dns_capture_claimed"].as_bool().unwrap_or(false),
        evidence["udp_capture_claimed"].as_bool().unwrap_or(false),
        evidence["ipv6_capture_claimed"].as_bool().unwrap_or(false),
        evidence["rollback_matrix_proven"]
            .as_bool()
            .unwrap_or(false),
    )
}
