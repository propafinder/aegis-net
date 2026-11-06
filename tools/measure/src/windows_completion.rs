use std::path::Path;

use serde_json::{json, Value};

use crate::artifact::{read_json, write_json, write_text};

pub fn build_windows_mvp_completion_review(
    windows_reach_json: &Path,
    output_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let evidence = read_json(windows_reach_json)?;
    let required = [
        ("socks_baseline_pass", "socks_client_baseline_pass"),
        ("service_baseline_pass", "service_baseline_pass"),
        ("service_restart_pass", "service_persistence_proven"),
        ("service_reboot_pass", "service_reboot_pass"),
        ("controlled_tcp_wfp_pass", "controlled_wfp_tcp_path_pass"),
        (
            "dynamic_original_dst_pass",
            "dynamic_original_destination_pass",
        ),
        ("process_capture_pass", "controlled_process_capture_pass"),
        ("browser_capture_pass", "controlled_browser_capture_pass"),
        ("rollback_matrix_pass", "rollback_matrix_proven"),
    ];
    let mut checks = serde_json::Map::new();
    let mut missing = Vec::new();
    for (out_key, evidence_key) in required {
        let pass = evidence[evidence_key].as_bool() == Some(true);
        checks.insert(out_key.to_string(), json!(pass));
        if !pass {
            missing.push(out_key);
        }
    }

    let no_overclaim = evidence["broad_capture_claimed"].as_bool() == Some(false)
        && evidence["dns_capture_claimed"].as_bool() == Some(false)
        && evidence["udp_capture_claimed"].as_bool() == Some(false)
        && evidence["ipv6_capture_claimed"].as_bool() == Some(false);
    checks.insert("no_overclaim".to_string(), json!(no_overclaim));
    if !no_overclaim {
        missing.push("no_overclaim");
    }

    let dns_udp_status = evidence["dns_udp_next_scope_status"]
        .as_str()
        .unwrap_or("NOT_PROVIDED");
    let verdict = if missing.is_empty() {
        "PASS"
    } else {
        "PARTIAL"
    };
    let review = json!({
        "schema_version": 1,
        "feature": "windows_current_mvp_completion_review",
        "status": verdict,
        "verdict": verdict,
        "scope": "current_scoped_windows_mvp",
        "windows_reach_json": windows_reach_json,
        "checks": checks,
        "missing_or_blocked_current_scope": missing,
        "dns_udp_next_scope_status": dns_udp_status,
        "dns_udp_capture_required_for_current_mvp": false,
        "broad_windows_wide_claimed": false,
        "dns_capture_claimed": false,
        "udp_capture_claimed": false,
        "ipv6_capture_claimed": false,
        "production_driver_support_claimed": false,
        "next_windows_blocker": "UDP/DNS capture requires a UDP-capable WFP layer/callout design",
    });

    write_json(
        &output_dir.join("windows-mvp-completion-review.json"),
        &review,
    )?;
    write_json(&output_dir.join("result.json"), &review)?;
    write_text(
        &output_dir.join("windows-mvp-completion-review.md"),
        &windows_mvp_completion_markdown(&review),
    )?;
    write_text(
        &output_dir.join("README.md"),
        &windows_mvp_completion_markdown(&review),
    )?;
    Ok(())
}

pub fn build_windows_dns_udp_next_layer_design(
    output_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let design = json!({
        "schema_version": 1,
        "feature": "windows_dns_udp_next_layer_design",
        "status": "DESIGN_READY",
        "verdict": "DESIGN_READY",
        "capture_proof": false,
        "current_path": {
            "wfp_layer": "ALE_CONNECT_REDIRECT_V4",
            "protocol": "IPPROTO_TCP",
            "scope": "controlled_tcp_only",
            "original_destination": "WFP redirect context on accepted TCP streams"
        },
        "target_sequence": [
            "controlled_connected_udp_feasibility_probe",
            "controlled_dns_udp_53_request",
            "broad_dns_udp_later_only"
        ],
        "candidate_layers": {
            "ale_connect_redirect_v4": "current TCP path; not sufficient for UDP datagram capture",
            "datagram_data_layers": "candidate for UDP packet visibility; likely callout-driver work",
            "ale_resource_assignment_or_auth_connect": "candidate for connected UDP feasibility; validate before implementation",
            "windivert_lab": "lab-only fallback if WFP UDP needs driver work"
        },
        "implementation_options": {
            "option_a": "user-mode WFP connected UDP feasibility if Windows API supports a narrow controlled redirect without a new callout",
            "option_b": "extend existing C WFP boundary minimally for UDP filter setup only",
            "option_c": "WinDivert lab-only evidence, no product claim",
            "option_d": "custom WFP callout driver later, explicit approval required"
        },
        "current_mvp_decision": "UDP/DNS capture remains BLOCKED",
        "next_slice": "implement controlled connected UDP feasibility probe only if safe; otherwise keep BLOCKED",
        "forbidden_in_current_package": [
            "broad UDP filters",
            "broad DNS filters",
            "new driver/callout implementation",
            "DNS/UDP capture claim"
        ]
    });
    write_json(
        &output_dir.join("windows-dns-udp-next-layer-design.json"),
        &design,
    )?;
    write_json(&output_dir.join("result.json"), &design)?;
    write_text(
        &output_dir.join("README.md"),
        &windows_dns_udp_design_markdown(&design),
    )?;
    Ok(())
}

fn windows_mvp_completion_markdown(review: &Value) -> String {
    format!(
        "# Windows Current MVP Completion Review\n\n\
         - Verdict: `{}`\n\
         - Scope: `current_scoped_windows_mvp`\n\
         - DNS/UDP next-scope: `{}`\n\
         - Broad Windows wide claimed: `false`\n\
         - DNS capture claimed: `false`\n\
         - UDP capture claimed: `false`\n\
         - IPv6 capture claimed: `false`\n\
         - Production driver support claimed: `false`\n",
        review["verdict"].as_str().unwrap_or("UNKNOWN"),
        review["dns_udp_next_scope_status"]
            .as_str()
            .unwrap_or("NOT_PROVIDED")
    )
}

fn windows_dns_udp_design_markdown(design: &Value) -> String {
    format!(
        "# Windows DNS/UDP Next Layer Design\n\n\
         - Verdict: `{}`\n\
         - Capture proof: `false`\n\
         - Current path: `ALE_CONNECT_REDIRECT_V4` + `IPPROTO_TCP`\n\
         - Current MVP decision: `UDP/DNS capture remains BLOCKED`\n\
         - Next slice: `{}`\n",
        design["verdict"].as_str().unwrap_or("UNKNOWN"),
        design["next_slice"].as_str().unwrap_or("unknown")
    )
}
