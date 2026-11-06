use std::path::Path;

use serde_json::Value;

use super::{read_optional_result, result_has_pass};

pub(super) fn optional_controlled_process_capture(path: Option<&Path>) -> bool {
    read_optional_result(path).is_some_and(|value| {
        optional_proof_value(&value, "controlled_process_capture_proven")
            || (result_has_pass(&value)
                && value["feature"].as_str() == Some("windows_wfp_controlled_process_capture")
                && value["scope"].as_str() == Some("controlled_process_tcp_ipv4")
                && value["process_match_method"].as_str().is_some()
                && value["original_dst_method"].as_str() == Some("wfp_redirect_context")
                && value["non_selected_process_direct"].as_bool() == Some(true)
                && value["relay_session_succeeded"].as_bool() == Some(true)
                && value["cleanup"].as_str() == Some("PASS")
                && result_broad_capture_not_claimed(&value))
    })
}

pub(super) fn optional_controlled_browser_capture(path: Option<&Path>) -> bool {
    read_optional_result(path).is_some_and(|value| {
        optional_proof_value(&value, "controlled_browser_capture_proven")
            || (result_has_pass(&value)
                && value["feature"].as_str() == Some("windows_wfp_controlled_browser_capture")
                && value["scope"].as_str() == Some("controlled_browser_tcp_ipv4")
                && value["process_match_method"].as_str() == Some("wfp_ale_app_id")
                && value["original_dst_method"].as_str() == Some("wfp_redirect_context")
                && value["non_selected_process_direct"].as_bool() == Some(true)
                && value["relay_session_succeeded"].as_bool() == Some(true)
                && value["cleanup"].as_str() == Some("PASS")
                && result_broad_capture_not_claimed(&value))
    })
}

pub(super) fn optional_dns_policy(path: Option<&Path>) -> bool {
    read_optional_result(path).is_some_and(|value| {
        optional_proof_value(&value, "dns_policy_proven")
            || (result_has_pass(&value)
                && value["feature"].as_str() == Some("windows_dns_policy_proof")
                && value["dns_policy"].as_str() == Some("explicit_out_of_scope_no_capture")
                && value["capture_dns"].as_bool() == Some(false)
                && value["wfp_dns_or_udp_filter_installed"].as_bool() == Some(false)
                && value["dns_resolve_succeeded"].as_bool() == Some(true)
                && value["runtime_dns_events_seen"].as_bool() == Some(false)
                && value["cleanup"].as_str() == Some("PASS")
                && result_broad_capture_not_claimed(&value))
    })
}

pub(super) fn optional_udp_policy(path: Option<&Path>) -> bool {
    read_optional_result(path).is_some_and(|value| {
        optional_proof_value(&value, "udp_policy_proven")
            || (result_has_pass(&value)
                && value["feature"].as_str() == Some("windows_udp_policy_proof")
                && value["udp_policy"].as_str() == Some("explicit_out_of_scope_no_capture")
                && value["udp_capture"].as_bool() == Some(false)
                && value["wfp_udp_filter_installed"].as_bool() == Some(false)
                && value["udp_probe_succeeded"].as_bool() == Some(true)
                && value["runtime_udp_events_seen"].as_bool() == Some(false)
                && value["cleanup"].as_str() == Some("PASS")
                && result_broad_capture_not_claimed(&value))
    })
}

pub(super) fn optional_ipv6_policy(path: Option<&Path>) -> bool {
    read_optional_result(path).is_some_and(|value| {
        optional_proof_value(&value, "ipv6_policy_proven")
            || (result_has_pass(&value)
                && value["feature"].as_str() == Some("windows_ipv6_policy_proof")
                && value["ipv6_policy"].as_str() == Some("explicit_not_supported_no_capture")
                && value["ipv6_capture"].as_bool() == Some(false)
                && value["wfp_ipv6_filter_installed"].as_bool() == Some(false)
                && value["ipv6_probe_succeeded"].as_bool() == Some(true)
                && value["runtime_ipv6_events_seen"].as_bool() == Some(false)
                && value["cleanup"].as_str() == Some("PASS")
                && result_broad_capture_not_claimed(&value))
    })
}

pub(super) fn optional_service_persistence(path: Option<&Path>) -> bool {
    read_optional_result(path).is_some_and(|value| {
        optional_proof_value(&value, "service_persistence_proven")
            || (result_has_pass(&value)
                && value["feature"].as_str() == Some("windows_wide_service_persistence_proof")
                && value["scope"].as_str() == Some("controlled_wfp_service_restart")
                && value["service_installed"].as_bool() == Some(true)
                && value["service_started"].as_bool() == Some(true)
                && value["service_restarted"].as_bool() == Some(true)
                && value["service_pid_changed"].as_bool() == Some(true)
                && value["wfp_reconfigured_after_restart"].as_bool() == Some(true)
                && value["cleanup"].as_str() == Some("PASS")
                && value["reboot_claim"].as_str() != Some("claimed")
                && result_broad_capture_not_claimed(&value))
    })
}

pub(super) fn optional_service_reboot(path: Option<&Path>) -> (bool, String) {
    let Some(value) = read_optional_result(path) else {
        return (false, "NOT_PROVIDED".to_string());
    };
    let status = value["status"].as_str().unwrap_or("UNKNOWN").to_string();
    let pass = result_has_pass(&value)
        && value["feature"].as_str() == Some("windows_wide_service_reboot_persistence_proof")
        && value["scope"].as_str() == Some("controlled_wfp_service_reboot")
        && value["service_started_after_reboot"].as_bool() == Some(true)
        && value["runtime_events_restarted"].as_bool() == Some(true)
        && value["wfp_reconfigured_after_reboot"].as_bool() == Some(true)
        && value["controlled_tcp_wfp_proof_after_reboot"].as_bool() == Some(true)
        && value["relay_egress_after_reboot"].as_bool() == Some(true)
        && value["cleanup"].as_str() == Some("PASS")
        && value["reboot_verified"].as_bool() == Some(true)
        && result_broad_capture_not_claimed(&value);
    (pass, status)
}

pub(super) fn optional_dns_udp_next_scope(path: Option<&Path>) -> (String, bool, bool) {
    let Some(value) = read_optional_result(path) else {
        return ("NOT_PROVIDED".to_string(), false, false);
    };
    let status = value["dns_udp_next_scope_status"]
        .as_str()
        .or_else(|| value["status"].as_str())
        .unwrap_or("UNKNOWN")
        .to_string();
    let dns_claimed = value["dns_capture_claimed"].as_bool() == Some(true);
    let udp_claimed = value["udp_capture_claimed"].as_bool() == Some(true);
    let valid_pass = result_has_pass(&value)
        && value["feature"].as_str() == Some("windows_wfp_controlled_dns_udp_next_scope")
        && value["scope"].as_str() == Some("controlled_dns_udp_only")
        && value["controlled_target_only"].as_bool() == Some(true)
        && value["controlled_udp_or_dns_captured"].as_bool() == Some(true)
        && value["cleanup"].as_str() == Some("PASS")
        && value["broad_capture_claim"].as_str() != Some("claimed");
    let valid_blocked = value["feature"].as_str()
        == Some("windows_wfp_controlled_dns_udp_next_scope")
        && matches!(
            status.as_str(),
            "UDP_CAPTURE_REQUIRES_NEW_WFP_LAYER"
                | "UDP_CAPTURE_REQUIRES_CALLOUT_DRIVER"
                | "UDP_CAPTURE_BLOCKED_FOR_MVP"
                | "BLOCKED_BY_ADMIN_REQUIRED"
        )
        && value["controlled_target_only"].as_bool() == Some(true)
        && value["broad_capture_claim"].as_str() != Some("claimed");
    if valid_pass || valid_blocked {
        (status, dns_claimed, udp_claimed)
    } else {
        (
            "INVALID_DNS_UDP_NEXT_SCOPE_ARTIFACT".to_string(),
            dns_claimed,
            udp_claimed,
        )
    }
}

pub(super) fn optional_rollback_matrix(path: Option<&Path>) -> bool {
    read_optional_result(path).is_some_and(|value| {
        optional_proof_value(&value, "rollback_matrix_proven")
            || (result_has_pass(&value)
                && value["feature"].as_str() == Some("windows_wide_rollback_matrix")
                && value["normal_cleanup"].as_bool() == Some(true)
                && value["idempotent_cleanup"].as_bool() == Some(true)
                && value["aegis_client_crash_cleanup"].as_bool() == Some(true)
                && value["driver_service_removed"].as_bool() == Some(true)
                && result_broad_capture_not_claimed(&value))
    })
}

fn optional_proof_value(value: &Value, proof_key: &str) -> bool {
    (value["status"].as_str() == Some("PASS") || value["verdict"].as_str() == Some("PASS"))
        && (value[proof_key].as_bool() == Some(true) || value[proof_key].as_str() == Some("PASS"))
}

fn result_broad_capture_not_claimed(value: &Value) -> bool {
    value["broad_capture_claim"].as_str() != Some("claimed")
        && value["broad_capture_claimed"].as_bool() != Some(true)
}
