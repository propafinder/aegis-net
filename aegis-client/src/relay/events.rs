use crate::anyhow_error_kind_code;
use crate::runtime_event_stream as runtime_jsonl;
use crate::runtime_events::RuntimeEventCode;
use aegis_core::{RelaySettings, TunnelTransportFamily};
use serde_json::json;

use super::policy;
use super::surface::{
    maybe_add_relay_surface_fields, maybe_add_runtime_mimicry_fields,
    maybe_add_tls_wire_adapter_fields, RelayMimicryContext,
};
use super::tls_backend::{effective_tls_backend, tls_backend_degraded};
use super::{
    relay_failure_scope, relay_tunnel_status_from_error, RelayOutcome, RelayTcpCompletion,
    RelayTransportFailureContext,
};

pub(super) fn emit_relay_tcp_session_terminal(
    context: RelayTransportFailureContext<'_>,
    terminal: Option<&RelayOutcome>,
    profile: Option<&policy::RelaySessionProfile>,
    mimicry_context: Option<RelayMimicryContext>,
) {
    let completion = RelayTcpCompletion::from_result(&Ok(()), terminal);
    if completion == RelayTcpCompletion::ResponseObserved {
        let outcome = terminal.expect("response evidence requires a terminal attempt");
        emit_relay_session_succeeded(
            context.session_kind,
            context.settings,
            context.target,
            context.port,
            context.planned_transports,
            outcome.transport,
            context.attempt_index,
            context.attempts_total,
            profile,
            mimicry_context,
            Some(outcome),
        );
        return;
    }
    let mut fields = json!({
        "relay_session_kind": context.session_kind,
        "target": context.target,
        "port": context.port,
        "relay_server": context.settings.server,
        "relay_server_name": context.settings.server_name,
        "attempt_index": context.attempt_index,
        "attempts_total": context.attempts_total,
        "planned_transports": context.planned_transports,
        "chosen_transport": terminal.map(|outcome| format!("{:?}", outcome.transport)),
        "transfer_result": "ok",
        "completion_reason": completion.reason(),
        "application_response_observed": false,
        "bytes_sent_recorded": terminal.map_or(0, |outcome| outcome.bytes_sent),
        "bytes_received_observed": terminal.map_or(0, |outcome| outcome.bytes_received_observed),
        "classifier_signal": terminal.map(|outcome| &outcome.signal),
        "response_evidence_scope": "relay_response_observed_not_application_delivery",
    });
    maybe_add_relay_surface_fields(&mut fields, profile);
    maybe_add_runtime_mimicry_fields(&mut fields, mimicry_context);
    tracing::info!(
        event_code = RuntimeEventCode::RelaySessionCompleted.as_str(),
        completion_reason = completion.reason(),
        application_response_observed = false,
        "relay TCP session completed without confirmed response evidence"
    );
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::RelaySessionCompleted,
        "relay TCP session completed without confirmed response evidence",
        fields,
    );
}

pub(super) fn emit_relay_transport_failed(
    family: TunnelTransportFamily,
    context: RelayTransportFailureContext<'_>,
    profile: Option<&policy::RelaySessionProfile>,
    mimicry_context: Option<RelayMimicryContext>,
    err: &anyhow::Error,
) {
    let relay_error_kind = anyhow_error_kind_code(err);
    let failure_scope = relay_failure_scope(err);
    let relay_tunnel_status = relay_tunnel_status_from_error(err);
    let error_chain = runtime_jsonl::privacy::error_chain(err);
    let error_message = runtime_jsonl::privacy::error_message(err);
    let error_chain_display = error_chain.join(": ");
    if failure_scope == "benign_session_end" {
        tracing::debug!(
            relay_session_kind = context.session_kind,
            transport = ?family,
            target = ?context.target,
            port = ?context.port,
            relay_server = %context.settings.server,
            relay_server_name = %context.settings.server_name,
            attempt_index = context.attempt_index,
            attempts_total = context.attempts_total,
            relay_error_kind = relay_error_kind.unwrap_or("unclassified"),
            relay_failure_scope = failure_scope,
            relay_tunnel_status = ?relay_tunnel_status,
            error = %error_message,
            error_chain = %error_chain_display,
            "relay transport closed benignly"
        );
        return;
    }
    tracing::warn!(
        event_code = RuntimeEventCode::RelayTransportFailed.as_str(),
        relay_session_kind = context.session_kind,
        transport = ?family,
        target = ?context.target,
        port = ?context.port,
        relay_server = %context.settings.server,
        relay_server_name = %context.settings.server_name,
        attempt_index = context.attempt_index,
        attempts_total = context.attempts_total,
        relay_error_kind = relay_error_kind.unwrap_or("unclassified"),
        relay_failure_scope = failure_scope,
        relay_tunnel_status = ?relay_tunnel_status,
        error = %error_message,
        error_chain = %error_chain_display,
        "relay transport failed"
    );
    let mut fields = json!({
            "relay_session_kind": context.session_kind,
            "transport": format!("{:?}", family),
            "target": context.target,
            "port": context.port,
            "relay_server": context.settings.server.clone(),
            "relay_server_name": context.settings.server_name.clone(),
            "relay_tls_backend": context.settings.tls_backend.as_str(),
            // What actually goes on the wire. A build without `chrome-like-tls`
            // degrades to the rustls ClientHello at connect time, so the
            // configured backend alone is not evidence of the wire shape.
            "relay_tls_backend_effective": effective_tls_backend(context.settings.tls_backend).as_str(),
            "relay_tls_backend_degraded": tls_backend_degraded(context.settings.tls_backend),
            "relay_tls_backend_browser_identical_claimed": context.settings.tls_backend.browser_identical_claimed()
                && !tls_backend_degraded(context.settings.tls_backend),
            "attempt_index": context.attempt_index,
            "attempts_total": context.attempts_total,
            "planned_transports": context.planned_transports,
            "relay_error_kind": relay_error_kind,
            "relay_failure_scope": failure_scope,
            "relay_tunnel_status": relay_tunnel_status,
            "error": error_message,
            "error_chain": error_chain
    });
    maybe_add_relay_surface_fields(&mut fields, profile);
    maybe_add_tls_wire_adapter_fields(&mut fields, family, profile);
    maybe_add_runtime_mimicry_fields(&mut fields, mimicry_context);
    runtime_jsonl::emit(
        "warn",
        RuntimeEventCode::RelayTransportFailed,
        "relay transport failed",
        fields,
    );
}

pub(super) struct RelaySessionStartedEvent<'a> {
    pub(super) session_kind: &'static str,
    pub(super) settings: &'a RelaySettings,
    pub(super) target: Option<&'a str>,
    pub(super) port: Option<u16>,
    pub(super) planned_transports: &'a [String],
    pub(super) attempts_total: usize,
    pub(super) profile: Option<&'a policy::RelaySessionProfile>,
    pub(super) mimicry_context: Option<RelayMimicryContext>,
}

pub(super) fn emit_relay_session_started(event: RelaySessionStartedEvent<'_>) {
    let RelaySessionStartedEvent {
        session_kind,
        settings,
        target,
        port,
        planned_transports,
        attempts_total,
        profile,
        mimicry_context,
    } = event;
    tracing::info!(
        event_code = RuntimeEventCode::RelaySessionStarted.as_str(),
        relay_session_kind = session_kind,
        target = ?target,
        port = ?port,
        relay_server = %settings.server,
        relay_server_name = %settings.server_name,
        attempts_total = attempts_total,
        planned_transports = ?planned_transports,
        "relay session started"
    );
    let mut fields = json!({
            "relay_session_kind": session_kind,
            "target": target,
            "port": port,
            "relay_server": settings.server.clone(),
            "relay_server_name": settings.server_name.clone(),
            "relay_tls_backend": settings.tls_backend.as_str(),
            // What actually goes on the wire. A build without `chrome-like-tls`
            // degrades to the rustls ClientHello at connect time, so the
            // configured backend alone is not evidence of the wire shape.
            "relay_tls_backend_effective": effective_tls_backend(settings.tls_backend).as_str(),
            "relay_tls_backend_degraded": tls_backend_degraded(settings.tls_backend),
            "relay_tls_backend_browser_identical_claimed": settings.tls_backend.browser_identical_claimed()
                && !tls_backend_degraded(settings.tls_backend),
            "attempts_total": attempts_total,
            "planned_transports": planned_transports
    });
    maybe_add_relay_surface_fields(&mut fields, profile);
    maybe_add_runtime_mimicry_fields(&mut fields, mimicry_context);
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::RelaySessionStarted,
        "relay session started",
        fields,
    );
}

#[allow(clippy::too_many_arguments)]
pub(super) fn emit_relay_transport_selected(
    session_kind: &'static str,
    settings: &RelaySettings,
    target: Option<&str>,
    port: Option<u16>,
    planned_transports: &[String],
    family: TunnelTransportFamily,
    attempt_index: usize,
    attempts_total: usize,
    profile: Option<&policy::RelaySessionProfile>,
    mimicry_context: Option<RelayMimicryContext>,
) {
    tracing::info!(
        event_code = RuntimeEventCode::RelayTransportSelected.as_str(),
        relay_session_kind = session_kind,
        transport = ?family,
        target = ?target,
        port = ?port,
        relay_server = %settings.server,
        relay_server_name = %settings.server_name,
        attempt_index = attempt_index,
        attempts_total = attempts_total,
        planned_transports = ?planned_transports,
        "relay transport selected"
    );
    let mut fields = json!({
            "relay_session_kind": session_kind,
            "transport": format!("{:?}", family),
            "target": target,
            "port": port,
            "relay_server": settings.server.clone(),
            "relay_server_name": settings.server_name.clone(),
            "relay_tls_backend": settings.tls_backend.as_str(),
            // What actually goes on the wire. A build without `chrome-like-tls`
            // degrades to the rustls ClientHello at connect time, so the
            // configured backend alone is not evidence of the wire shape.
            "relay_tls_backend_effective": effective_tls_backend(settings.tls_backend).as_str(),
            "relay_tls_backend_degraded": tls_backend_degraded(settings.tls_backend),
            "relay_tls_backend_browser_identical_claimed": settings.tls_backend.browser_identical_claimed()
                && !tls_backend_degraded(settings.tls_backend),
            "attempt_index": attempt_index,
            "attempts_total": attempts_total,
            "planned_transports": planned_transports
    });
    maybe_add_relay_surface_fields(&mut fields, profile);
    maybe_add_tls_wire_adapter_fields(&mut fields, family, profile);
    maybe_add_runtime_mimicry_fields(&mut fields, mimicry_context);
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::RelayTransportSelected,
        "relay transport selected",
        fields,
    );
    // Once per session open (first attempt): surface the sampled morphology
    // instance as a first-class event so per-session sampling is observable
    // directly (Phase 5 / morphology_profile_sampled).
    if attempt_index <= 1 {
        emit_morphology_profile_sampled(session_kind, family, profile);
    }
}

/// Emit `morphology_profile_sampled` describing the sampled morphology
/// instance for this session: family + dynamics ranges + padding policy +
/// direction summary. No raw RNG seed is logged. Sampled instance values
/// vary per session (chunk/delay), so this is not a per-user-stable id.
pub(super) fn emit_morphology_profile_sampled(
    session_kind: &'static str,
    family: TunnelTransportFamily,
    profile: Option<&policy::RelaySessionProfile>,
) {
    let Some(p) = profile else { return };
    let fields = json!({
        "relay_session_kind": session_kind,
        "transport": format!("{:?}", family),
        "family": p.profile_id,
        "sampled_profile_id": p.profile_id,
        "chunk_range_summary": format!("{}..{} (sampled {})", p.surface_chunk_size_range.0, p.surface_chunk_size_range.1, p.write_chunk_size),
        "delay_range_summary": format!("{}..{} ms (sampled {} ms)", p.surface_delay_ms_range.0, p.surface_delay_ms_range.1, p.inter_chunk_delay_ms),
        "jitter_summary": format!("0..{} ms per-chunk", p.inter_chunk_jitter_ms_window),
        "padding_policy_summary": format!("p={}/1000 split={}..{}/1000", p.padding_probability_milli, p.padding_split_ratio_milli_range.0, p.padding_split_ratio_milli_range.1),
        "direction_summary": "request/response shaped per family transport constraints",
        "surface_bias_applied": p.surface_bias_applied,
    });
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::MorphologyProfileSampled,
        "morphology profile sampled for relay session",
        fields,
    );
}

#[allow(clippy::too_many_arguments)]
pub(super) fn emit_relay_session_succeeded(
    session_kind: &'static str,
    settings: &RelaySettings,
    target: Option<&str>,
    port: Option<u16>,
    planned_transports: &[String],
    family: TunnelTransportFamily,
    attempt_index: usize,
    attempts_total: usize,
    profile: Option<&policy::RelaySessionProfile>,
    mimicry_context: Option<RelayMimicryContext>,
    tcp_outcome: Option<&RelayOutcome>,
) {
    tracing::info!(
        event_code = RuntimeEventCode::RelaySessionSucceeded.as_str(),
        relay_session_kind = session_kind,
        chosen_transport = ?family,
        target = ?target,
        port = ?port,
        relay_server = %settings.server,
        relay_server_name = %settings.server_name,
        attempt_index = attempt_index,
        attempts_total = attempts_total,
        planned_transports = ?planned_transports,
        "relay session succeeded"
    );
    let mut fields = json!({
            "relay_session_kind": session_kind,
            "chosen_transport": format!("{:?}", family),
            "target": target,
            "port": port,
            "relay_server": settings.server.clone(),
            "relay_server_name": settings.server_name.clone(),
            "relay_tls_backend": settings.tls_backend.as_str(),
            // What actually goes on the wire. A build without `chrome-like-tls`
            // degrades to the rustls ClientHello at connect time, so the
            // configured backend alone is not evidence of the wire shape.
            "relay_tls_backend_effective": effective_tls_backend(settings.tls_backend).as_str(),
            "relay_tls_backend_degraded": tls_backend_degraded(settings.tls_backend),
            "relay_tls_backend_browser_identical_claimed": settings.tls_backend.browser_identical_claimed()
                && !tls_backend_degraded(settings.tls_backend),
            "attempt_index": attempt_index,
            "attempts_total": attempts_total,
            "planned_transports": planned_transports
    });
    if let Some(outcome) = tcp_outcome {
        fields["transfer_result"] = json!("ok");
        fields["completion_reason"] = json!("response_observed");
        fields["application_response_observed"] = json!(true);
        fields["bytes_sent_recorded"] = json!(outcome.bytes_sent);
        fields["bytes_received_observed"] = json!(outcome.bytes_received_observed);
        fields["classifier_signal"] = json!(outcome.signal);
        fields["response_evidence_scope"] =
            json!("relay_response_observed_not_application_delivery");
    }
    maybe_add_relay_surface_fields(&mut fields, profile);
    maybe_add_tls_wire_adapter_fields(&mut fields, family, profile);
    maybe_add_runtime_mimicry_fields(&mut fields, mimicry_context);
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::RelaySessionSucceeded,
        "relay session succeeded",
        fields,
    );
}

/// Emits `stealth_profile_rotated` when an active relay session lasted long
/// enough that the epoch-driven catalog selection would now pick a different
/// profile id than the one the session started with. This is the C3 intra-
/// session drift signal: it only fires when drift actually happened (no
/// synthetic events, no "rotate every N seconds regardless"), so the runtime
/// log honestly reflects the polymorphism surface.
pub(super) fn emit_stealth_profile_rotated(
    session_kind: &'static str,
    target: Option<&str>,
    port: Option<u16>,
    old_profile_id: &str,
    new_profile_id: &str,
    session_duration_secs: u64,
    drift_epoch_secs: u64,
) {
    tracing::info!(
        event_code = RuntimeEventCode::StealthProfileRotated.as_str(),
        relay_session_kind = session_kind,
        target = ?target,
        port = ?port,
        old_profile_id = old_profile_id,
        new_profile_id = new_profile_id,
        session_duration_secs = session_duration_secs,
        drift_epoch_secs = drift_epoch_secs,
        "stealth profile rotated"
    );
    let fields = json!({
        "relay_session_kind": session_kind,
        "target": target,
        "port": port,
        "old_profile_id": old_profile_id,
        "new_profile_id": new_profile_id,
        "session_duration_secs": session_duration_secs,
        "drift_epoch_secs": drift_epoch_secs,
    });
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::StealthProfileRotated,
        "stealth profile rotated",
        fields,
    );
}

pub(super) fn emit_relay_endpoint_short_circuit_fast_fail(
    settings: &RelaySettings,
    target: Option<(&str, u16)>,
    failed_transport: &str,
    elapsed_ms: u64,
    transports_skipped: usize,
    error_kind: &str,
) {
    let (host, port) = target.unwrap_or(("", 0));
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::RelayEndpointShortCircuitFastFail,
        "relay endpoint declared unreachable on first transport; remaining transports on this endpoint skipped",
        json!({
            "relay_server": settings.server,
            "relay_server_name": settings.server_name,
            "target": host,
            "port": port,
            "failed_transport": failed_transport,
            "failed_error_kind": error_kind,
            "first_attempt_elapsed_ms": elapsed_ms,
            "transports_skipped_on_this_endpoint": transports_skipped,
            "policy": "first_tcp_unreachable_short_circuits_remaining_transports",
        }),
    );
}

/// Carrier failover state change (D3). Fields name the carrier endpoint, the
/// typed signal and the cooldown; never a destination or device identity.
pub(super) fn emit_relay_carrier_state_changed(
    network: &str,
    labels: &[String],
    transition: &aegis_core::brain::carrier_failover::CarrierTransition,
) {
    let mut fields = super::carrier_failover::transition_fields(labels, transition);
    fields["network"] = network.into();
    fields["carriers_total"] = labels.len().into();
    tracing::info!(
        event_code = RuntimeEventCode::RelayCarrierStateChanged.as_str(),
        transition = %fields["transition"],
        "relay carrier failover state changed"
    );
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::RelayCarrierStateChanged,
        "relay carrier failover state changed",
        fields,
    );
}

pub(super) fn emit_relay_failover_recovery_observed(
    settings: &RelaySettings,
    target: Option<(&str, u16)>,
    primary_endpoint: &str,
    elapsed_ms: u64,
    failed_attempts_on_primary: usize,
    terminal: &RelayOutcome,
) {
    if RelayTcpCompletion::from_result(&Ok(()), Some(terminal))
        != RelayTcpCompletion::ResponseObserved
    {
        return;
    }
    let (host, port) = target.unwrap_or(("", 0));
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::RelayFailoverRecoveryObserved,
        "relay failover recovery observed (this endpoint succeeded after a previous endpoint exhausted its planned transports)",
        json!({
            "relay_server": settings.server,
            "relay_server_name": settings.server_name,
            "primary_endpoint_that_failed": primary_endpoint,
            "target": host,
            "port": port,
            "time_to_recovery_ms_since_session_start": elapsed_ms,
            "failed_transport_attempts_on_primary": failed_attempts_on_primary,
            "application_response_observed": true,
            "bytes_received_observed": terminal.bytes_received_observed,
            "classifier_signal": terminal.signal,
            "response_evidence_scope": "relay_response_observed_not_application_delivery",
        }),
    );
}

pub(super) fn emit_relay_soft_wire_applied(
    settings: &RelaySettings,
    target: Option<(&str, u16)>,
    plan: aegis_core::SoftWireRelaySocketPlan,
    transport_kind: &str,
) {
    let (host, port) = target.unwrap_or(("", 0));
    // For UDP, the keep-alive override IS applied via quinn transport_config
    // even though IP_TTL is currently unavailable. Report wire_active=true
    // when at least one soft-wire dimension landed.
    let udp_keep_alive_applied = transport_kind == "udp" && plan.masque_keep_alive_ms.is_some();
    let wire_active = plan.applied || udp_keep_alive_applied;
    let activation_reason = match (transport_kind, plan.applied, udp_keep_alive_applied) {
        ("tcp", true, _) => "soft_wire_socket_options_active",
        ("tcp", false, _) => "soft_wire_setsockopt_failed",
        ("udp", true, _) => "soft_wire_udp_ttl_and_keep_alive_active",
        ("udp", false, true) => "soft_wire_udp_keep_alive_active_ttl_skipped_quinn_0_11",
        ("udp", false, false) => "soft_wire_udp_no_dimensions_applied",
        _ => "soft_wire_unknown_transport",
    };
    let runtime_slice = match transport_kind {
        "tcp" => "soft_wire_ttl_nodelay",
        "udp" => "soft_wire_udp_keep_alive",
        _ => "soft_wire_unknown_transport",
    };
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::RelaySoftWireApplied,
        "relay soft-wire socket plan applied",
        json!({
            "relay_server": settings.server,
            "relay_server_name": settings.server_name,
            "target": host,
            "port": port,
            "mimicry_capability_wire_active": wire_active,
            "mimicry_capability_wire_requested": true,
            "mimicry_capability_wire_config_mode": "soft_wire_socket_options",
            "mimicry_capability_wire_activation_reason": activation_reason,
            "mimicry_capability_wire_runtime_slice": runtime_slice,
            "mimicry_capability_wire_transport_kind": transport_kind,
            "mimicry_wire_soft_ip_ttl": plan.ip_ttl,
            "mimicry_wire_soft_nodelay": plan.nodelay,
            "mimicry_wire_soft_masque_keep_alive_ms":
                plan.masque_keep_alive_ms.map(serde_json::Value::from)
                    .unwrap_or(serde_json::Value::Null),
            "mimicry_wire_soft_burst_chunk_count": plan.burst_chunk_count,
            "mimicry_wire_soft_retry_pacing_jitter_ms": plan.retry_pacing_jitter_ms,
        }),
    );
}

#[cfg(test)]
mod privacy_tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn private_production_relay_failure_emits_code_without_destination() {
        // The production event also reaches the shared runtime sink when
        // another test initialized it. Respect that fixture's isolation.
        let _runtime_lock = crate::tests::RUNTIME_JSONL_LOCK.lock().await;
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let writer = bytes.clone();
        let subscriber = tracing_subscriber::fmt()
            .event_format(runtime_jsonl::PrivateEventFormat)
            .with_writer(move || Capture(writer.clone()))
            .finish();
        let settings = RelaySettings {
            server: "private-relay.example:443".to_owned(),
            server_name: "private-relay.example".to_owned(),
            ..Default::default()
        };
        let error = anyhow::Error::from(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "connect private-destination.example:443 refused",
        ))
        .context("DNS private-resolver.example");
        tracing::subscriber::with_default(subscriber, || {
            emit_relay_transport_failed(
                TunnelTransportFamily::GrpcStream,
                RelayTransportFailureContext {
                    session_kind: "tcp_connect",
                    target: Some("private-destination.example"),
                    port: Some(443),
                    settings: &settings,
                    attempt_index: 0,
                    attempts_total: 1,
                    planned_transports: &[],
                },
                None,
                None,
                &error,
            );
        });
        let output = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        assert!(!output.contains("private-"), "{output}");
        let record: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(record["event_code"], "relay_transport_failed");
        assert_eq!(record["relay_error_kind"], "connection_refused");
    }
}
