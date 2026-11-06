use std::path::Path;

use serde_json::{json, Value};

use crate::artifact::write_json;

pub struct MacosUtunBlockedResultInputs<'a> {
    pub artifact: &'a str,
    pub status: &'a str,
    pub blocker: &'a str,
    pub output_json: &'a Path,
}

pub fn build_macos_utun_blocked_result(
    inputs: MacosUtunBlockedResultInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = json!({
        "schema_version": 1,
        "artifact": inputs.artifact,
        "status": inputs.status,
        "verdict": "NOT_PASS",
        "blocker": inputs.blocker,
        "broad_system_wide_claim": false,
    });
    write_json(inputs.output_json, &result)
}

pub struct MacosUtunW0BlockedResultInputs<'a> {
    pub status: &'a str,
    pub blocker: &'a str,
    pub output_json: &'a Path,
}

pub fn build_macos_utun_w0_blocked_result(
    inputs: MacosUtunW0BlockedResultInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = json!({
        "schema_version": 1,
        "artifact": "macos-utun-helper-fd-loop-lab",
        "status": inputs.status,
        "verdict": "NOT_PASS",
        "helper_creates_utun": false,
        "fd_passed_to_non_root_main_process": false,
        "packet_or_controlled_injected_packet_observed": false,
        "cleanup_succeeds": false,
        "broad_system_wide_claim": false,
        "blocker": inputs.blocker,
    });
    write_json(inputs.output_json, &result)
}

pub struct MacosUtunW0TimeoutResultInputs<'a> {
    pub helper_exit: &'a str,
    pub main_exit: &'a str,
    pub output_json: &'a Path,
}

pub fn build_macos_utun_w0_timeout_result(
    inputs: MacosUtunW0TimeoutResultInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = json!({
        "schema_version": 1,
        "artifact": "macos-utun-helper-fd-loop-lab",
        "status": "LOCAL_BINARY_EXECUTION_OR_HELPER_TIMEOUT",
        "verdict": "NOT_PASS",
        "helper_creates_utun": false,
        "fd_passed_to_non_root_main_process": false,
        "packet_or_controlled_injected_packet_observed": false,
        "cleanup_succeeds": false,
        "broad_system_wide_claim": false,
        "helper_exit": inputs.helper_exit,
        "main_exit": inputs.main_exit,
    });
    write_json(inputs.output_json, &result)
}

pub struct MacosUtunW1ResultInputs<'a> {
    pub status: &'a str,
    pub verdict: &'a str,
    pub helper_exit: &'a str,
    pub main_exit: &'a str,
    pub packet_loop_pass: &'a str,
    pub route_proof_pass: &'a str,
    pub controlled_peer: &'a str,
    pub relay_ip: &'a str,
    pub output_json: &'a Path,
}

pub fn build_macos_utun_w1_result(
    inputs: MacosUtunW1ResultInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = json!({
        "schema_version": 1,
        "artifact": "macos-utun-w1-controlled-route-proof-lab",
        "status": inputs.status,
        "verdict": inputs.verdict,
        "helper_exit": inputs.helper_exit,
        "main_exit": inputs.main_exit,
        "packet_loop_pass": parse_bool(inputs.packet_loop_pass)?,
        "route_proof_pass": parse_bool(inputs.route_proof_pass)?,
        "controlled_peer": inputs.controlled_peer,
        "controlled_route_prefix": "/32",
        "relay_ip": inputs.relay_ip,
        "relay_ip_excluded_from_utun": parse_bool(inputs.route_proof_pass)?,
        "default_route_claim": false,
        "broad_system_wide_claim": false,
        "dns_claimed": false,
        "udp_claimed": false,
        "ipv6_claimed": false,
    });
    write_json(inputs.output_json, &result)
}

pub struct MacosUtunW2ResultInputs<'a> {
    pub artifact: &'a str,
    pub status: &'a str,
    pub verdict: &'a str,
    pub helper_exit: &'a str,
    pub main_exit: &'a str,
    pub packet_loop_pass: &'a str,
    pub route_proof_pass: &'a str,
    pub tcp_flow_observed: &'a str,
    pub tcp_destination_port_match: &'a str,
    pub tcp_synack_lab_pass: Option<&'a str>,
    pub tcp_ack_observed: Option<&'a str>,
    pub controlled_peer: &'a str,
    pub controlled_tcp_port: u16,
    pub packet_to_flow_adapter: &'a str,
    pub output_json: &'a Path,
}

pub fn build_macos_utun_w2_result(
    inputs: MacosUtunW2ResultInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut result = json!({
        "schema_version": 1,
        "artifact": inputs.artifact,
        "status": inputs.status,
        "verdict": inputs.verdict,
        "helper_exit": inputs.helper_exit,
        "main_exit": inputs.main_exit,
        "packet_loop_pass": parse_bool(inputs.packet_loop_pass)?,
        "route_proof_pass": parse_bool(inputs.route_proof_pass)?,
        "tcp_flow_observed": parse_bool(inputs.tcp_flow_observed)?,
        "tcp_destination_port_match": parse_bool(inputs.tcp_destination_port_match)?,
        "controlled_peer": inputs.controlled_peer,
        "controlled_tcp_port": inputs.controlled_tcp_port,
        "packet_to_flow_adapter": inputs.packet_to_flow_adapter,
        "default_route_claim": false,
        "broad_system_wide_claim": false,
        "dns_claimed": false,
        "udp_claimed": false,
        "ipv6_claimed": false,
        "relay_session_claimed": false,
    });
    if let Some(tcp_synack_lab_pass) = inputs.tcp_synack_lab_pass {
        result["tcp_synack_lab_pass"] = Value::Bool(parse_bool(tcp_synack_lab_pass)?);
    }
    if let Some(tcp_ack_observed) = inputs.tcp_ack_observed {
        result["tcp_ack_observed"] = Value::Bool(parse_bool(tcp_ack_observed)?);
    }
    write_json(inputs.output_json, &result)
}

fn parse_bool(value: &str) -> Result<bool, Box<dyn std::error::Error>> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("expected boolean string true/false, got {value:?}").into()),
    }
}
