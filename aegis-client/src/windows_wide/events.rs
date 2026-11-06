use crate::runtime_event_stream as runtime_jsonl;
use serde_json::json;
use std::net::SocketAddr;

pub(crate) const BACKEND: &str = "wfp_ale_connect_redirect";
pub(crate) const SCOPE: &str = "controlled_tcp_ipv4";
pub(crate) const ORIGINAL_DST_METHOD_WFP_CONTEXT: &str = "wfp_redirect_context";

pub(crate) fn backend_started(listen: SocketAddr) {
    runtime_jsonl::emit_raw(
        "info",
        "windows_wide_backend_started",
        "windows wide backend started",
        json!({
            "event": "windows_wide_backend_started",
            "backend": BACKEND,
            "listen": listen.to_string(),
            "scope": SCOPE
        }),
    );
}

pub(crate) fn flow_accepted(peer: SocketAddr, redirected_to: SocketAddr) {
    runtime_jsonl::emit_raw(
        "info",
        "windows_wide_flow_accepted",
        "windows wide flow accepted",
        json!({
            "event": "windows_wide_flow_accepted",
            "backend": BACKEND,
            "scope": SCOPE,
            "peer": peer.to_string(),
            "redirected_to": redirected_to.to_string()
        }),
    );
}

pub(crate) fn original_dst_resolved(original_dst: SocketAddr, method: &str) {
    runtime_jsonl::emit_raw(
        "info",
        "windows_wide_original_dst_resolved",
        "windows wide original destination resolved",
        json!({
            "event": "windows_wide_original_dst_resolved",
            "backend": BACKEND,
            "scope": SCOPE,
            "original_dst": original_dst.to_string(),
            "method": method
        }),
    );
}

pub(crate) fn original_dst_dynamic_lookup_failed(error: &std::io::Error) {
    runtime_jsonl::emit_raw(
        "warn",
        "windows_wide_original_dst_dynamic_lookup_failed",
        "windows wide original destination dynamic lookup failed",
        json!({
            "event": "windows_wide_original_dst_dynamic_lookup_failed",
            "backend": BACKEND,
            "scope": SCOPE,
            "method": ORIGINAL_DST_METHOD_WFP_CONTEXT,
            "error": error.to_string()
        }),
    );
}

pub(crate) fn relay_session_started(relay_server: &str, target: SocketAddr) {
    runtime_jsonl::emit_raw(
        "info",
        "windows_wide_relay_session_started",
        "windows wide relay session started",
        json!({
            "event": "windows_wide_relay_session_started",
            "backend": BACKEND,
            "scope": SCOPE,
            "relay_server": relay_server,
            "target": target.to_string()
        }),
    );
}

pub(crate) fn relay_transport_selected(relay_server: &str, transport: &str) {
    runtime_jsonl::emit_raw(
        "info",
        "windows_wide_relay_transport_selected",
        "windows wide relay transport selected",
        json!({
            "event": "windows_wide_relay_transport_selected",
            "backend": BACKEND,
            "scope": SCOPE,
            "relay_server": relay_server,
            "transport": transport
        }),
    );
}

/// Share the TCP evidence predicate with the platform-neutral producer. Unknown
/// egress stays null; observing response bytes cannot identify the exit address.
pub(crate) fn relay_session_terminal(
    relay_server: &str,
    result: &anyhow::Result<()>,
    terminal: Option<&crate::relay::RelayOutcome>,
) {
    use crate::relay::RelayTcpCompletion;

    let completion = RelayTcpCompletion::from_result(result, terminal);
    if completion == RelayTcpCompletion::ResponseObserved {
        relay_session_succeeded(
            relay_server,
            None,
            terminal
                .expect("response evidence requires an attempt")
                .bytes_received_observed,
        );
        flow_closed_ok();
    } else if result.is_ok() {
        runtime_jsonl::emit_raw(
            "info",
            "windows_wide_relay_session_completed",
            "windows wide relay session completed without confirmed response evidence",
            json!({
                "event": "windows_wide_relay_session_completed",
                "backend": BACKEND,
                "scope": SCOPE,
                "relay_server": relay_server,
                "relay_egress_ip": null,
                "transfer_result": "ok",
                "completion_reason": completion.reason(),
                "application_response_observed": false,
                "bytes_received_observed": terminal.map_or(0, |outcome| outcome.bytes_received_observed),
                "classifier_signal": terminal.map(|outcome| &outcome.signal),
                "response_evidence_scope": "relay_response_observed_not_application_delivery",
            }),
        );
    }
}

fn relay_session_succeeded(
    relay_server: &str,
    relay_egress_ip: Option<&str>,
    bytes_received_observed: u64,
) {
    runtime_jsonl::emit_raw(
        "info",
        "windows_wide_relay_session_succeeded",
        "windows wide relay session succeeded",
        json!({
            "event": "windows_wide_relay_session_succeeded",
            "backend": BACKEND,
            "scope": SCOPE,
            "relay_server": relay_server,
            "relay_egress_ip": relay_egress_ip,
            "application_response_observed": true,
            "bytes_received_observed": bytes_received_observed,
            "response_evidence_scope": "relay_response_observed_not_application_delivery",
        }),
    );
}

fn flow_closed_ok() {
    runtime_jsonl::emit_raw(
        "info",
        "windows_wide_flow_closed",
        "windows wide flow closed",
        json!({
            "event": "windows_wide_flow_closed",
            "backend": BACKEND,
            "scope": SCOPE,
            "result": "ok"
        }),
    );
}
