//! Direct Mode: Brain, TLS-модификации, Ghost-LURK, стратегии, mimicry до connect.

mod auto_resolution;
mod executor;
mod planner;

pub(crate) use aegis_client::mimicry_runtime_surface::{
    add_runtime_baseline_mimicry_fields_compact, mimicry_userspace_nodelay_hint,
    mimicry_userspace_recv_buffer_hint, mimicry_userspace_reuseaddr_hint,
    mimicry_userspace_send_buffer_hint, mimicry_userspace_wiring_mode, mimicry_wire_runtime_plan,
    MimicryCapabilitySignalOrigin,
};

pub use auto_resolution::handle_auto;

#[cfg(test)]
mod initial_read_tests;

#[cfg(test)]
pub(crate) use planner::direct_profile_family_for_time;

use crate::relay;
use crate::runtime_event_stream as runtime_jsonl;
use crate::runtime_events::RuntimeEventCode;
use crate::socks5::ConnectTarget;
use aegis_core::brain::{DirectPlannerCandidateTrace, DirectPlannerSelectionTrace};
use aegis_core::ghost_lurk::GhostLurk;
use aegis_core::mimicry::{
    negotiated_wire_options_preface, resolve_wire_mimicry_runtime, tuning_for,
    wire_fragment_choreography_plan, wire_mimicry_plan, wire_options_preface_profile,
    StackProfileId,
};
use aegis_core::protocols::tls::is_likely_tls_client_hello;
use aegis_core::protocols::tls::sni_hostname_range;
use aegis_core::protocols::tls_modify::{
    inject_grease_extension, inject_opaque_extension, obfuscate_sni_case, replace_sni_hostname,
};
use aegis_core::signals::classify::FailSignal;
use aegis_core::{
    active_stall_probe_finished_event_data, active_stall_probe_launched_event_data,
    active_stall_probe_retry_budget_exhausted_event_data, default_raw_engine,
    direct_relay_failover_event_data, direct_session_succeeded_event_data,
    ActiveStallProbeFailoverContext, ActiveStallProbeFinishContext, ActiveStallProbePlanContext,
    ActiveStallProbeRetrySuppressedReasonCode, Brain, DirectRelayFailoverReasonCode,
    DirectSessionSuccessMetrics, DirectSettings, DirectTerminalReason, HybridRouteFamily,
    ObservationContract, ObservationPathContext, ProbeHistoryDisposition, RawCapabilities,
    RelaySettings, RetryBudgetContext, RuntimeEndpoint, StrategyKey, TerminalFailureAction,
    TunnelTransportFamily, WireMimicryMode, WireMimicryRuntimePlan,
};
use anyhow::Context;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::Duration;

use self::planner::ActiveProbePlan;

const MAX_INLINE_PROBE_RETRIES_PER_SESSION: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectTerminalPolicy {
    /// Preserve the existing direct-mode behavior: return the typed direct
    /// error to the captured client session.
    PreserveDirectFailure,
    /// An explicit fallback mode may hand planning/capability terminals to a
    /// ready relay.  Without a ready relay the captured flow remains blocked.
    RelayOrFailClosed,
    /// The explicit Geneva hybrid contract additionally relays a replay-safe
    /// exhausted direct strategy ladder. Once application bytes may have been
    /// sent, it blocks instead of probing or replaying on another connection.
    HybridRelayOrFailClosed,
}

pub(crate) struct DirectFallbackContext<'a> {
    pub relay: &'a RelaySettings,
    pub terminal_policy: DirectTerminalPolicy,
}

fn direct_terminal_action(
    policy: DirectTerminalPolicy,
    reason: DirectTerminalReason,
    relay_replay_safe: bool,
    relay_ready: bool,
) -> Option<TerminalFailureAction> {
    if policy == DirectTerminalPolicy::HybridRelayOrFailClosed
        && !relay_replay_safe
        && matches!(
            reason,
            DirectTerminalReason::StrategiesExhausted
                | DirectTerminalReason::ClassifiedDirectFailure
        )
    {
        // Once the canonical application payload may have reached the target,
        // replay through a fresh relay connection can duplicate side effects.
        return Some(TerminalFailureAction::Block);
    }
    let relay_eligible = reason.requires_immediate_relay_handoff()
        || (policy == DirectTerminalPolicy::HybridRelayOrFailClosed
            && reason == DirectTerminalReason::StrategiesExhausted
            && relay_replay_safe);
    if policy == DirectTerminalPolicy::PreserveDirectFailure || !relay_eligible {
        return None;
    }
    Some(if relay_ready {
        TerminalFailureAction::RelayGrpc
    } else {
        TerminalFailureAction::Block
    })
}

fn direct_terminal_failover_reason(
    reason: DirectTerminalReason,
) -> Option<DirectRelayFailoverReasonCode> {
    match reason {
        DirectTerminalReason::NoExecutableStrategy => {
            Some(DirectRelayFailoverReasonCode::NoExecutableStrategy)
        }
        DirectTerminalReason::UnsupportedAddressFamily => {
            Some(DirectRelayFailoverReasonCode::UnsupportedAddressFamily)
        }
        DirectTerminalReason::MissingRawCapability => {
            Some(DirectRelayFailoverReasonCode::MissingRawCapability)
        }
        DirectTerminalReason::StrategiesExhausted => {
            Some(DirectRelayFailoverReasonCode::StrategiesExhausted)
        }
        DirectTerminalReason::ClassifiedDirectFailure => None,
    }
}

pub(crate) async fn run_active_stall_probe_runtime_evidence(
    dst: SocketAddr,
    direct: &DirectSettings,
) -> anyhow::Result<Value> {
    let stack = direct
        .stack_profile
        .as_deref()
        .and_then(|profile| profile.parse::<StackProfileId>().ok())
        .or(Some(StackProfileId::LinuxDesktop));
    let preferred_ttl = stack
        .and_then(|profile| tuning_for(profile).suggested_ttl)
        .unwrap_or(64)
        .clamp(1, u8::MAX as u32) as u8;
    let plan = ActiveProbePlan {
        preferred_ttl,
        budget: 2,
        candidates: vec![preferred_ttl, preferred_ttl.saturating_sub(1).max(1)],
    };
    let target_host = dst.ip().to_string();
    let payload = format!(
        "GET / HTTP/1.0\r\nHost: {}:{}\r\nUser-Agent: aegis-active-probe-evidence\r\n\r\n",
        dst.ip(),
        dst.port()
    )
    .into_bytes();
    let launch_signal = FailSignal::SessionFreeze {
        bytes_before_stall: payload.len(),
    };
    let launched = active_stall_probe_launched_event_data(
        &launch_signal,
        ObservationContract::RuntimeOnly,
        &target_host,
        dst.port(),
        plan.preferred_ttl,
        plan.budget,
        &plan.candidates,
    );
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::DirectActiveStallProbeLaunched,
        launched.message,
        {
            let mut fields = launched.runtime_fields;
            add_mimicry_capability_fields(
                &mut fields,
                None,
                MimicryCapabilitySignalOrigin::LiveRuntimeObservation,
                stack,
                direct.wire_mimicry_mode,
                dst,
            );
            fields
        },
    );

    let result = executor::run_active_stall_probe(
        dst,
        payload,
        executor::ActiveStallProbeRun {
            timeout_limit: Duration::from_millis(direct.first_chunk_timeout_ms),
            is_tls: dst.port() == 443,
            freeze_threshold_bytes: direct.freeze_threshold_bytes,
            degraded_latency_ms: direct.degraded_latency_ms,
            stack,
            wire_mode: direct.wire_mimicry_mode,
            mimicry_ttl_hint: stack.and_then(|profile| tuning_for(profile).suggested_ttl),
            wire_window_preface: None,
            wire_observation_capture_confidence: "explicit_absence",
            wire_window_profile: None,
            wire_observed_ipv4_header_shaping: None,
            wire_observed_negotiated_options: None,
            wire_observed_fragment_choreography: None,
            active_probe_plan: plan.clone(),
        },
    )
    .await;
    let finished = active_stall_probe_finished_event_data(
        &result.signal,
        &result.observation,
        RuntimeEndpoint {
            target: &target_host,
            port: dst.port(),
        },
        ActiveStallProbePlanContext {
            preferred_ttl: result.planned_probe_preferred_ttl,
            budget: result.planned_probe_budget,
            ttl_candidates: &result.planned_probe_ttl_candidates,
        },
        ActiveStallProbeFinishContext {
            latency_ms: result.latency_ms,
            first_response_bytes: result.first_response_bytes,
            terminal_stage: result.terminal_stage,
        },
    );
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::DirectActiveStallProbeFinished,
        finished.message,
        {
            let mut fields = finished.runtime_fields;
            add_mimicry_capability_fields(
                &mut fields,
                Some(&result.observation),
                MimicryCapabilitySignalOrigin::LiveActiveProbeObservation,
                stack,
                direct.wire_mimicry_mode,
                dst,
            );
            let applied_wire_runtime = active_probe_evidence_wire_runtime_plan(direct, stack, dst);
            override_mimicry_wire_runtime_fields(
                &mut fields,
                direct.wire_mimicry_mode,
                &applied_wire_runtime,
            );
            fields
        },
    );

    Ok(serde_json::json!({
        "artifact_schema": "direct_active_probe_runtime_evidence_v1",
        "status": "finished",
        "target": dst.to_string(),
        "signal": format!("{:?}", result.signal),
        "probe_outcome_class": if result.signal.is_success() { "success" } else { "failure" },
        "latency_ms": result.latency_ms,
        "first_response_bytes": result.first_response_bytes,
        "probe_terminal_stage": result.terminal_stage,
    }))
}

fn active_probe_evidence_wire_runtime_plan(
    direct: &DirectSettings,
    stack: Option<StackProfileId>,
    dst: SocketAddr,
) -> WireMimicryRuntimePlan {
    resolve_wire_mimicry_runtime(
        direct.wire_mimicry_mode,
        dst,
        default_raw_engine().capabilities(),
        stack.and_then(|profile| tuning_for(profile).suggested_ttl),
        None,
        wire_options_preface_profile(stack),
        None,
        negotiated_wire_options_preface(stack, "explicit_absence", None, None),
        wire_fragment_choreography_plan("explicit_absence", None, None),
    )
}

fn override_mimicry_wire_runtime_fields(
    fields: &mut Value,
    wire_mode: WireMimicryMode,
    wire_runtime: &WireMimicryRuntimePlan,
) {
    let Some(map) = fields.as_object_mut() else {
        return;
    };
    map.insert(
        "mimicry_capability_wire_config_mode".into(),
        Value::String(wire_mode.as_str().to_string()),
    );
    map.insert(
        "mimicry_capability_wire_requested".into(),
        Value::Bool(wire_runtime.requested),
    );
    map.insert(
        "mimicry_capability_wire_active".into(),
        Value::Bool(wire_runtime.active),
    );
    map.insert(
        "mimicry_capability_wire_activation_reason".into(),
        Value::String(wire_runtime.activation_reason.to_string()),
    );
    map.insert(
        "mimicry_capability_wire_runtime_slice".into(),
        wire_runtime
            .runtime_slice
            .map(|value| Value::String(value.to_string()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_ttl_preface".into(),
        wire_runtime
            .ttl_preface
            .map(|value| serde_json::json!(value))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_window_preface".into(),
        wire_runtime
            .window_preface
            .map(|value| serde_json::json!(value))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_options_preface_profile".into(),
        wire_runtime
            .options_preface_profile
            .map(|value| Value::String(value.to_string()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_options_preface_size".into(),
        wire_runtime
            .options_preface_size
            .map(|value| serde_json::json!(value))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_ipv4_header_shaping_profile".into(),
        wire_runtime
            .ipv4_header_shaping
            .as_ref()
            .map(|value| Value::String(value.profile.to_string()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_ipv4_header_shaping_tos".into(),
        wire_runtime
            .ipv4_header_shaping
            .as_ref()
            .map(|value| serde_json::json!(value.tos))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_ipv4_header_shaping_ip_id".into(),
        wire_runtime
            .ipv4_header_shaping
            .as_ref()
            .map(|value| serde_json::json!(value.identification))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_ipv4_header_shaping_dont_fragment".into(),
        wire_runtime
            .ipv4_header_shaping
            .as_ref()
            .map(|value| Value::Bool(value.dont_fragment))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_ipv4_header_shaping_source".into(),
        wire_runtime
            .ipv4_header_shaping
            .as_ref()
            .map(|value| Value::String(value.source.to_string()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_negotiated_options_profile".into(),
        wire_runtime
            .negotiated_options
            .as_ref()
            .map(|value| Value::String(value.profile.to_string()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_negotiated_options_size".into(),
        wire_runtime
            .negotiated_options
            .as_ref()
            .map(|value| serde_json::json!(value.size_bytes))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_negotiated_options_mss".into(),
        wire_runtime
            .negotiated_options
            .as_ref()
            .map(|value| serde_json::json!(value.mss))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_negotiated_options_window_scale".into(),
        wire_runtime
            .negotiated_options
            .as_ref()
            .map(|value| serde_json::json!(value.window_scale))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_negotiated_options_sack_permitted".into(),
        wire_runtime
            .negotiated_options
            .as_ref()
            .map(|value| Value::Bool(value.sack_permitted))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_negotiated_options_timestamp_mode".into(),
        wire_runtime
            .negotiated_options
            .as_ref()
            .map(|value| Value::String(value.timestamp_mode.to_string()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_negotiated_options_source".into(),
        wire_runtime
            .negotiated_options
            .as_ref()
            .map(|value| Value::String(value.source.to_string()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_raw_ipv4_send_ready".into(),
        Value::Bool(wire_runtime.raw_ipv4_send_ready),
    );
    map.insert(
        "mimicry_capability_wire_tcp_repair_ready".into(),
        Value::Bool(wire_runtime.tcp_repair_ready),
    );
    map.insert(
        "mimicry_capability_wire_ipv4_header_control_ready".into(),
        Value::Bool(wire_runtime.ipv4_header_control_ready),
    );
    map.insert(
        "mimicry_capability_wire_ipv4_fragmentation_ready".into(),
        Value::Bool(wire_runtime.ipv4_fragmentation_ready),
    );
    map.insert(
        "mimicry_capability_wire_fragment_choreography_profile".into(),
        wire_runtime
            .fragment_choreography
            .as_ref()
            .map(|value| Value::String(value.profile.to_string()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_fragment_choreography_steps".into(),
        wire_runtime
            .fragment_choreography
            .as_ref()
            .map(|value| Value::String(value.steps.to_string()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_fragment_choreography_first_payload_len".into(),
        wire_runtime
            .fragment_choreography
            .as_ref()
            .map(|value| serde_json::json!(value.fragment_first_payload_len))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_fragment_choreography_disorder_split_at".into(),
        wire_runtime
            .fragment_choreography
            .as_ref()
            .map(|value| serde_json::json!(value.disorder_split_at))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_fragment_choreography_overlap".into(),
        wire_runtime
            .fragment_choreography
            .as_ref()
            .map(|value| serde_json::json!(value.overlap_bytes))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_fragment_choreography_source".into(),
        wire_runtime
            .fragment_choreography
            .as_ref()
            .map(|value| Value::String(value.source.to_string()))
            .unwrap_or(Value::Null),
    );
}

struct DirectRelayHandoffContext<'a> {
    initial_payload: Option<&'a [u8]>,
    handoff_path: &'static str,
    reason_code: String,
    active_stall_probe_retry_attempted: Option<bool>,
    /// Brain-derived SurfaceBias for this handoff. Computed from the
    /// session's `BrainAdvisory` (and any classifier hints in the latest
    /// observation) so the relay's surface profile picker can respond to
    /// the same signal that drove the direct→relay handoff in the first
    /// place. Neutral when no relevant Brain hint exists.
    surface_bias: relay::SurfaceBias,
    hybrid: Option<HybridRuntimeContext>,
}

#[derive(Clone)]
struct HybridRuntimeContext {
    brain: Arc<Brain>,
    key: StrategyKey,
    strategy_fingerprint: String,
    address_family: &'static str,
    route_reason_code: &'static str,
    evidence_confidence: &'static str,
    raw_capabilities: RawCapabilities,
}

fn hybrid_strategy_fingerprint(direct: &DirectSettings) -> String {
    let strategy = direct.geneva_strategy.as_deref().unwrap_or_default();
    let digest = Sha256::digest(strategy.as_bytes());
    hex::encode(&digest[..12])
}

fn hybrid_event_fields(
    context: &HybridRuntimeContext,
    route: HybridRouteFamily,
) -> serde_json::Value {
    json!({
        "route_family": route,
        "reason_code": context.route_reason_code,
        "strategy_fingerprint": context.strategy_fingerprint,
        "address_family": context.address_family,
        "evidence_confidence": context.evidence_confidence,
        "capability_summary": {
            "ipv4_raw_send": context.raw_capabilities.ipv4_raw_send,
            "ipv4_packet_capture": context.raw_capabilities.ipv4_packet_capture,
            "tcp_repair_query": context.raw_capabilities.tcp_repair_query,
            "ipv4_header_control": context.raw_capabilities.ipv4_header_control,
            "ipv4_fragmentation": context.raw_capabilities.ipv4_fragmentation,
        }
    })
}

fn relay_transport_strategy_key(family: TunnelTransportFamily) -> &'static str {
    match family {
        TunnelTransportFamily::LegacyTls => "legacy_tls",
        TunnelTransportFamily::HttpsWs => "https_ws",
        TunnelTransportFamily::GrpcStream => "grpc_stream",
        TunnelTransportFamily::GrpcDatagram => "grpc_datagram",
        TunnelTransportFamily::MasqueDerived => "masque_derived",
    }
}

/// Phase 5 Phase 3: translate a `BrainAdvisory` into a `relay::SurfaceBias`
/// by combining multiple Brain signals into the three SurfaceBias axes.
///
/// Inputs consumed:
///   - `probe_history_disposition` — disposition code from probe history.
///   - `cross_session_signal_metrics.stall_severity` — 0..1, how badly
///     the strategy has been stalling. High → favor low-latency profiles
///     plus jitter.
///   - `cross_session_signal_metrics.relay_preference_score` — 0..1,
///     how strongly Brain wants to take the relay path. High → favor
///     low-visibility (small-payload-looking) profiles plus jitter.
///   - `cross_session_signal_metrics.confidence_score` — 0..1, how much
///     to trust the other signals. Acts as a stale-calibration decay:
///     low confidence → halve all bias weights so we don't over-bias
///     on flimsy evidence.
///   - `observation_contract` — `ExplicitAbsence` or `RuntimeOnly`
///     observation contracts further decay weights (the observation
///     wasn't deep enough to over-trust).
///
/// The mapping is intentionally additive per signal, then clamped to
/// 0..=1 per axis. No "if risk > X then static switch" — every signal
/// contributes its share and the picker still draws weighted-random
/// from the full 18-family catalog.
fn surface_bias_from_advisory(advisory: &aegis_core::DirectSessionAdvisory) -> relay::SurfaceBias {
    use aegis_core::ObservationContract;
    use aegis_core::ProbeHistoryDisposition;

    let mut bias = relay::SurfaceBias::default();

    // Axis 1: probe history disposition contributes the strongest weight
    // because Brain has already correlated multiple sessions to produce
    // this code.
    match advisory.probe_history_disposition {
        ProbeHistoryDisposition::PreferRelay => {
            bias.low_latency_preferred += 0.4;
            bias.high_jitter_preferred += 0.2;
        }
        ProbeHistoryDisposition::BiasProbeBranch => {
            bias.high_jitter_preferred += 0.15;
        }
        ProbeHistoryDisposition::None => {}
    }

    // Axis 2: cross-session stall severity — favor families that
    // present as quick-feeling (low base delay) and that widen the
    // timing signature.
    let metrics = &advisory.cross_session_signal_metrics;
    let stall_severity = metrics.stall_severity.clamp(0.0, 1.0) as f32;
    if stall_severity > 0.5 {
        let intensity = (stall_severity - 0.5) * 2.0;
        bias.low_latency_preferred += 0.2 * intensity;
        bias.high_jitter_preferred += 0.15 * intensity;
    }

    // Axis 3: Brain's accumulated preference for the relay path — favor
    // low-visibility (small-payload-shaped) families plus a little
    // jitter so a session that "looks like an RPC poll" stays in that
    // visual band.
    let relay_pref = metrics.relay_preference_score.clamp(0.0, 1.0) as f32;
    if relay_pref > 0.5 {
        let intensity = (relay_pref - 0.5) * 2.0;
        bias.low_visibility_preferred += 0.25 * intensity;
        bias.high_jitter_preferred += 0.1 * intensity;
    }

    // Stale-calibration decay: low confidence_score halves all weights.
    // The decay coefficient is in [0.5, 1.0] — at confidence=0 we trust
    // the bias half as much as at confidence=1.
    let confidence = metrics.confidence_score.clamp(0.0, 1.0) as f32;
    let mut decay = 0.5 + 0.5 * confidence;

    // Additional decay when the underlying observation was thin
    // (ExplicitAbsence = nothing observed; RuntimeOnly = no deep
    // capture). Take 80% of whatever we computed.
    if matches!(
        advisory.observation_contract,
        ObservationContract::ExplicitAbsence | ObservationContract::RuntimeOnly,
    ) {
        decay *= 0.8;
    }

    bias.low_latency_preferred = (bias.low_latency_preferred * decay).clamp(0.0, 1.0);
    bias.high_jitter_preferred = (bias.high_jitter_preferred * decay).clamp(0.0, 1.0);
    bias.low_visibility_preferred = (bias.low_visibility_preferred * decay).clamp(0.0, 1.0);

    bias
}

/// Compute the SurfaceBias from the current advisory AND emit the
/// explanation event in a single step. Callsites use this wrapper so
/// every non-neutral bias decision is observable in runtime telemetry
/// — no silent morphology changes.
fn compute_and_log_morphology_bias(
    advisory: &aegis_core::DirectSessionAdvisory,
    target_host: &str,
    target_port: u16,
) -> relay::SurfaceBias {
    let bias = surface_bias_from_advisory(advisory);
    emit_morphology_choice_explained(advisory, bias, target_host, target_port);
    bias
}

/// Emit a `brain_morphology_choice_explained` runtime event capturing the
/// inputs and the computed `SurfaceBias`. Called once per session-open
/// when the bias ends up non-neutral so reviewers can see WHICH signal
/// drove the choice. The event is `BrainCalibration` surface so it
/// joins the existing brain_* event stream.
fn emit_morphology_choice_explained(
    advisory: &aegis_core::DirectSessionAdvisory,
    bias: relay::SurfaceBias,
    target_host: &str,
    target_port: u16,
) {
    if bias.is_neutral() {
        return;
    }
    let metrics = &advisory.cross_session_signal_metrics;
    // `runtime_jsonl::emit` requires a `&'static str` message — keep the
    // narrative line static and put all dynamic numbers into the fields
    // map so structured-event consumers see everything.
    const MESSAGE: &str = "brain morphology bias applied to surface profile selection";
    let fields = serde_json::json!({
        "target_host": target_host,
        "target_port": target_port,
        "probe_history_disposition": advisory.probe_history_disposition.as_str(),
        "observation_contract": advisory.observation_contract.as_str(),
        "cross_session_confidence_score": metrics.confidence_score,
        "cross_session_stall_severity": metrics.stall_severity,
        "cross_session_relay_preference_score": metrics.relay_preference_score,
        "computed_low_latency_preferred": bias.low_latency_preferred,
        "computed_high_jitter_preferred": bias.high_jitter_preferred,
        "computed_low_visibility_preferred": bias.low_visibility_preferred,
    });
    tracing::info!(
        event_code = RuntimeEventCode::BrainMorphologyChoiceExplained.as_str(),
        target = %target_host,
        port = target_port,
        low_latency_preferred = bias.low_latency_preferred,
        high_jitter_preferred = bias.high_jitter_preferred,
        low_visibility_preferred = bias.low_visibility_preferred,
        "{}",
        MESSAGE,
    );
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::BrainMorphologyChoiceExplained,
        MESSAGE,
        fields,
    );
}

fn stage_direct_error(stage: &'static str, source: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("{stage}: {source}")
}

fn apply_direct_first_chunk_transforms(
    buf: &mut Vec<u8>,
    direct: &DirectSettings,
    ip_ver: u8,
) -> anyhow::Result<()> {
    if is_likely_tls_client_hello(buf) {
        if direct.sni_case_obfuscate {
            if let Some(r) = sni_hostname_range(buf) {
                obfuscate_sni_case(buf, r);
            }
        }
        if direct.tls_grease {
            inject_grease_extension(buf).map_err(|e| stage_direct_error("direct_tls_grease", e))?;
        }
        if direct.inject_opaque_extension {
            let secret = std::env::var("AEGIS_OPAQUE_SECRET").unwrap_or_default();
            let d = Sha256::digest(secret.as_bytes());
            inject_opaque_extension(buf, &d[..16])
                .map_err(|e| stage_direct_error("direct_tls_opaque_extension", e))?;
        }
        if let Some(ref host) = direct.tls_sni_replace {
            if !host.is_empty() {
                replace_sni_hostname(buf, host)
                    .map_err(|e| stage_direct_error("direct_tls_sni_replace", e))?;
            }
        }
    }

    if let Some(ref lua_path) = direct.lua_chunk_script {
        let path = crate::config::expand_tilde(lua_path);
        match aegis_core::lua_engine::try_apply_chunk_hook(Some(path.as_path()), buf, ip_ver) {
            Ok(Some(newb)) => *buf = newb,
            Err(e) => tracing::warn!(%e, "lua chunk hook"),
            Ok(None) => {}
        }
    }

    Ok(())
}

#[derive(Debug, Error)]
#[error("{relay}")]
pub(crate) struct DirectRelayHandoffTerminalFailure {
    handoff_path: &'static str,
    reason_code: String,
    active_stall_probe_retry_attempted: Option<bool>,
    #[source]
    relay: relay::RelayTerminalFailure,
}

impl DirectRelayHandoffTerminalFailure {
    pub(crate) fn handoff_path(&self) -> &'static str {
        self.handoff_path
    }

    pub(crate) fn reason_code(&self) -> &str {
        self.reason_code.as_str()
    }

    pub(crate) fn active_stall_probe_retry_attempted(&self) -> Option<bool> {
        self.active_stall_probe_retry_attempted
    }

    pub(crate) fn relay(&self) -> &relay::RelayTerminalFailure {
        &self.relay
    }
}

pub async fn handle_direct(
    mut client: TcpStream,
    target: ConnectTarget,
    dst: SocketAddr,
    brain: Arc<Brain>,
    direct: &DirectSettings,
    fallback: DirectFallbackContext<'_>,
    ghost: Option<Arc<GhostLurk>>,
) -> anyhow::Result<()> {
    let relay_settings = fallback.relay;
    let terminal_policy = fallback.terminal_policy;
    let mut buf = vec![0u8; 16384];
    let deadline = tokio::time::Instant::now()
        .checked_add(Duration::from_millis(direct.first_chunk_timeout_ms))
        .ok_or_else(|| {
            stage_direct_error("direct_initial_read_deadline", "invalid timeout budget")
        })?;
    let n = tokio::time::timeout_at(deadline, client.read(&mut buf))
        .await
        .map_err(|_| {
            stage_direct_error(
                "direct_initial_read_timeout",
                "client first payload did not arrive",
            )
        })?
        .context("read first chunk")?;
    buf.truncate(n);
    if buf.is_empty() {
        // A client that closes before sending any payload should not trigger
        // planner/advisory work or an outbound direct/relay dial.
        return Ok(());
    }

    let ip_ver = if dst.is_ipv4() { 4u8 } else { 6u8 };
    apply_direct_first_chunk_transforms(&mut buf, direct, ip_ver)?;

    let sni = sni_hostname_range(&buf);
    // sni_hostname_range returns (start, LENGTH) — the same contract
    // obfuscate_sni_case and the tls tests use. This site read it as
    // (start, end) and sliced buf[start..end], so any ClientHello whose SNI
    // length was smaller than its offset — i.e. essentially every real one —
    // panicked with "slice index starts at N but ends at M". The workspace
    // builds with panic = "abort", so that killed the whole client on the first
    // HTTPS request through the direct path. Indexing is now length-based and
    // bounds-checked, so a malformed hello yields None instead of aborting.
    let sni_host = sni.and_then(|(start, len)| {
        buf.get(start..start.checked_add(len)?)
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .map(|host| host.to_string())
    });
    let key = StrategyKey::for_target(
        dst,
        &target.host,
        target.port,
        sni_host.as_deref(),
        sni.is_some(),
    );
    let advisory = brain.direct_session_advisory(&key).await;
    let latest_observation = advisory.latest_observation.clone();
    let stack = direct
        .stack_profile
        .as_deref()
        .and_then(|s| s.parse::<StackProfileId>().ok());
    let wire_mode = direct.wire_mimicry_mode;
    let hybrid_runtime_context = if direct.hybrid_geneva {
        let raw_capabilities = default_raw_engine().capabilities();
        let direct_capable =
            dst.is_ipv4() && raw_capabilities.ipv4_raw_send && raw_capabilities.tcp_repair_query;
        let route = brain.select_hybrid_route(&key, direct_capable).await;
        let context = HybridRuntimeContext {
            brain: brain.clone(),
            key: key.clone(),
            strategy_fingerprint: hybrid_strategy_fingerprint(direct),
            address_family: if dst.is_ipv4() { "ipv4" } else { "ipv6" },
            route_reason_code: route.reason.as_str(),
            evidence_confidence: route.evidence_confidence.as_str(),
            raw_capabilities,
        };
        let mut fields = hybrid_event_fields(&context, route.route);
        if let Value::Object(map) = &mut fields {
            map.insert(
                "direct_failure_cooldown_remaining_ms".into(),
                json!(route.direct_failure_cooldown_remaining_ms),
            );
            map.insert(
                "external_classifier_hint_present".into(),
                json!(route.external_classifier_hint.is_some()),
            );
        }
        runtime_jsonl::emit(
            "info",
            RuntimeEventCode::HybridRouteSelected,
            "hybrid route selected",
            fields,
        );
        if route.route == HybridRouteFamily::RelayGrpc {
            let surface_bias =
                compute_and_log_morphology_bias(&advisory, &target.host, target.port);
            return run_relay_tunnel_with_direct_handoff(
                client,
                relay_settings,
                target.host,
                target.port,
                dst,
                stack,
                wire_mode,
                DirectRelayHandoffContext {
                    initial_payload: Some(&buf),
                    handoff_path: "hybrid_route_selected_relay",
                    reason_code: route.reason.as_str().to_string(),
                    active_stall_probe_retry_attempted: None,
                    surface_bias,
                    hybrid: Some(context),
                },
            )
            .await;
        }
        Some(context)
    } else {
        None
    };
    if hybrid_runtime_context.is_none()
        && relay::runtime_fallback_ready(relay_settings)
        && matches!(
            advisory.probe_history_disposition,
            ProbeHistoryDisposition::PreferRelay
        )
    {
        let event = advisory.relay_preference_event_data(&target.host, target.port);
        tracing::info!(
            event_code = RuntimeEventCode::DirectRelayPreferredFromProbeHistory.as_str(),
            target = %target.host,
            port = target.port,
            probe_history_disposition = event.trace.probe_history_disposition,
            probe_history_reason_code = event.trace.probe_history_reason_code,
            observation_contract = event.trace.observation_contract,
            stall_probe_trials = event.trace.stall_probe_trials,
            stall_probe_freezes = event.trace.stall_probe_freezes,
            stall_probe_collapses = event.trace.stall_probe_collapses,
            stall_probe_timeouts = event.trace.stall_probe_timeouts,
            last_probe_signal = ?event.trace.last_probe_signal,
            "{}",
            event.message
        );
        runtime_jsonl::emit(
            "info",
            RuntimeEventCode::DirectRelayPreferredFromProbeHistory,
            event.message,
            {
                let mut fields = event.runtime_fields;
                add_mimicry_capability_fields(
                    &mut fields,
                    advisory.latest_observation.as_ref(),
                    MimicryCapabilitySignalOrigin::AdvisoryLatestObservation,
                    stack,
                    wire_mode,
                    dst,
                );
                fields
            },
        );
        let surface_bias = compute_and_log_morphology_bias(&advisory, &target.host, target.port);
        return run_relay_tunnel_with_direct_handoff(
            client,
            relay_settings,
            target.host,
            target.port,
            dst,
            stack,
            wire_mode,
            DirectRelayHandoffContext {
                initial_payload: Some(&buf),
                handoff_path: "probe_history_prefer_relay",
                reason_code: advisory.probe_history_reason_code.as_str().to_string(),
                active_stall_probe_retry_attempted: None,
                surface_bias,
                hybrid: None,
            },
        )
        .await;
    }
    let mut planner_trace = brain.select_order_trace(&key).await;
    let active_probe_plan =
        planner::build_active_probe_plan_for_dst(dst, latest_observation.as_ref());
    let resolved_order = resolve_direct_order(
        direct,
        &advisory,
        stack,
        wire_mode,
        dst,
        &active_probe_plan,
        &target.host,
        target.port,
        ip_ver,
        &planner_trace,
        "initial_session_order",
        0,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .await;

    let initial_mimicry_capability =
        planner::build_mimicry_capability_plan(latest_observation.as_ref());
    let probe_launch = ActiveStallProbeLaunch {
        brain: brain.clone(),
        key: key.clone(),
        dst,
        buf: buf.clone(),
        is_tls: key.is_tls,
        timeout_limit: Duration::from_millis(direct.first_chunk_timeout_ms),
        freeze_threshold_bytes: direct.freeze_threshold_bytes,
        degraded_latency_ms: direct.degraded_latency_ms,
        stack,
        wire_mode,
        mimicry_ttl_hint: initial_mimicry_capability.userspace_ttl_hint,
        wire_window_preface: initial_mimicry_capability.wire_window_preface,
        wire_observation_capture_confidence: initial_mimicry_capability
            .observation_capture_confidence,
        wire_window_profile: initial_mimicry_capability.window_profile,
        wire_observed_ipv4_header_shaping: initial_mimicry_capability
            .wire_observed_ipv4_header_shaping,
        wire_observed_negotiated_options: initial_mimicry_capability
            .wire_observed_negotiated_options,
        wire_observed_fragment_choreography: initial_mimicry_capability
            .wire_observed_fragment_choreography,
        active_probe_plan: active_probe_plan.clone(),
        target_host: target.host.clone(),
        target_port: target.port,
    };

    let mut current_advisory = advisory.clone();
    let mut current_observation = latest_observation;
    let mut current_order = resolved_order.order.clone();
    let mut current_planner_trace = planner_trace.clone();
    let mut current_order_resolution = resolved_order.order_resolution;
    let mut current_lua_order_applied = resolved_order.lua_order_applied;
    let mut current_advisory_reorder_applied = resolved_order.advisory_reorder_applied;
    let mut current_probe_plan = active_probe_plan;
    let mut inline_probe_retries = 0usize;
    // Keep the latest inline-probe terminal stage so later failover events
    // remain self-contained even after the retry loop advances.
    let mut last_probe_terminal_stage = None;
    loop {
        let current_mimicry_capability =
            planner::build_mimicry_capability_plan(current_observation.as_ref());
        let plan = planner::build_direct_plan(
            current_order.clone(),
            &direct.strategies,
            dst,
            ghost.clone(),
            current_observation.as_ref(),
        );
        if let Some(context) = hybrid_runtime_context.as_ref() {
            context
                .brain
                .record_hybrid_route_attempt(&context.key, HybridRouteFamily::DirectGeneva)
                .await;
            runtime_jsonl::emit(
                "info",
                RuntimeEventCode::GenevaDirectAttemptStarted,
                "Geneva direct attempt started",
                hybrid_event_fields(context, HybridRouteFamily::DirectGeneva),
            );
        }
        let direct_result = executor::execute_direct_plan(
            &mut client,
            &plan.strategies,
            brain.clone(),
            executor::DirectExecution {
                dst,
                key: &key,
                buf: &buf,
                sni,
                sni_host: sni_host.as_deref(),
                timeout: Duration::from_millis(direct.first_chunk_timeout_ms),
                freeze_threshold_bytes: direct.freeze_threshold_bytes,
                degraded_latency_ms: direct.degraded_latency_ms,
                stack,
                wire_mode,
                mimicry_ttl_hint: current_mimicry_capability.userspace_ttl_hint,
                wire_window_preface: current_mimicry_capability.wire_window_preface,
                wire_observation_capture_confidence: current_mimicry_capability
                    .observation_capture_confidence,
                wire_window_profile: current_mimicry_capability.window_profile,
                wire_observed_ipv4_header_shaping: current_mimicry_capability
                    .wire_observed_ipv4_header_shaping,
                wire_observed_negotiated_options: current_mimicry_capability
                    .wire_observed_negotiated_options,
                wire_observed_fragment_choreography: current_mimicry_capability
                    .wire_observed_fragment_choreography,
                reference_path_hops: current_observation
                    .as_ref()
                    .and_then(|observation| observation.reference_path_hops()),
                ghost: ghost.clone(),
                ghost_jitter_before_attempt: direct.ghost_jitter_before_attempt,
                empty_plan_reason: plan
                    .empty_reason
                    .unwrap_or(DirectTerminalReason::NoExecutableStrategy),
            },
        )
        .await;
        if let Some(context) = hybrid_runtime_context.as_ref() {
            match &direct_result {
                Ok(success) => {
                    context
                        .brain
                        .record_hybrid_route_outcome(
                            &context.key,
                            HybridRouteFamily::DirectGeneva,
                            success.signal.clone(),
                        )
                        .await;
                    let mut fields = hybrid_event_fields(context, HybridRouteFamily::DirectGeneva);
                    if let Value::Object(map) = &mut fields {
                        map.insert("signal".into(), json!(format!("{:?}", success.signal)));
                    }
                    runtime_jsonl::emit(
                        "info",
                        RuntimeEventCode::GenevaDirectAttemptSucceeded,
                        "Geneva direct attempt succeeded",
                        fields,
                    );
                }
                Err(error) => {
                    context
                        .brain
                        .record_hybrid_route_outcome(
                            &context.key,
                            HybridRouteFamily::DirectGeneva,
                            error.signal.clone(),
                        )
                        .await;
                    let mut fields = hybrid_event_fields(context, HybridRouteFamily::DirectGeneva);
                    if let Value::Object(map) = &mut fields {
                        map.insert("signal".into(), json!(format!("{:?}", error.signal)));
                        map.insert(
                            "terminal_reason".into(),
                            json!(error.terminal_reason.as_str()),
                        );
                        map.insert("relay_replay_safe".into(), json!(error.relay_replay_safe));
                    }
                    runtime_jsonl::emit(
                        "warn",
                        RuntimeEventCode::GenevaDirectAttemptFailed,
                        "Geneva direct attempt failed",
                        fields,
                    );
                }
            }
        }
        match direct_result {
            Ok(success) => {
                emit_direct_session_succeeded(
                    &success,
                    &current_advisory,
                    stack,
                    wire_mode,
                    dst,
                    &target.host,
                    target.port,
                    buf.len(),
                    inline_probe_retries,
                );
                return Ok(());
            }
            Err(err)
                if direct_terminal_action(
                    terminal_policy,
                    err.terminal_reason,
                    err.relay_replay_safe,
                    relay::runtime_fallback_ready(relay_settings),
                ) == Some(TerminalFailureAction::RelayGrpc) =>
            {
                let reason_code = direct_terminal_failover_reason(err.terminal_reason)
                    .expect("relay-eligible direct terminal has a failover reason");
                emit_direct_relay_failover_triggered(
                    &err,
                    &current_advisory,
                    stack,
                    wire_mode,
                    dst,
                    &target.host,
                    target.port,
                    reason_code,
                    false,
                    None,
                );
                let surface_bias =
                    compute_and_log_morphology_bias(&current_advisory, &target.host, target.port);
                return run_relay_tunnel_with_direct_handoff(
                    client,
                    relay_settings,
                    target.host,
                    target.port,
                    dst,
                    stack,
                    wire_mode,
                    DirectRelayHandoffContext {
                        // No direct attempt wrote the first payload; the relay
                        // handoff owns exactly one initial send.
                        initial_payload: Some(&buf),
                        handoff_path: "direct_terminal_failover",
                        reason_code: reason_code.as_str().to_string(),
                        active_stall_probe_retry_attempted: Some(false),
                        surface_bias,
                        hybrid: hybrid_runtime_context.clone(),
                    },
                )
                .await;
            }
            Err(err)
                if direct_terminal_action(
                    terminal_policy,
                    err.terminal_reason,
                    err.relay_replay_safe,
                    relay::runtime_fallback_ready(relay_settings),
                ) == Some(TerminalFailureAction::Block) =>
            {
                let relay_runtime_ready = relay::runtime_fallback_ready(relay_settings);
                let event_code = if terminal_policy == DirectTerminalPolicy::HybridRelayOrFailClosed
                {
                    RuntimeEventCode::HybridFlowBlockedFailClosed
                } else {
                    RuntimeEventCode::DirectTerminalFailClosed
                };
                tracing::warn!(
                    event_code = event_code.as_str(),
                    terminal_reason = err.terminal_reason.as_str(),
                    relay_replay_safe = err.relay_replay_safe,
                    terminal_action = "block",
                    relay_runtime_ready = relay_runtime_ready,
                    no_native_fallback = true,
                    target = %target.host,
                    port = target.port,
                    "direct terminal cannot hand off safely; captured flow blocked"
                );
                let mut fields = hybrid_runtime_context
                    .as_ref()
                    .map(|context| hybrid_event_fields(context, HybridRouteFamily::Block))
                    .unwrap_or_else(|| json!({}));
                if let Value::Object(map) = &mut fields {
                    map.insert(
                        "terminal_reason".into(),
                        json!(err.terminal_reason.as_str()),
                    );
                    map.insert("terminal_action".into(), json!("block"));
                    map.insert("relay_replay_safe".into(), json!(err.relay_replay_safe));
                    map.insert("relay_runtime_ready".into(), json!(relay_runtime_ready));
                    map.insert("no_native_fallback".into(), json!(true));
                    map.insert("target".into(), json!(target.host.as_str()));
                    map.insert("port".into(), json!(target.port));
                }
                runtime_jsonl::emit(
                    "warn",
                    event_code,
                    "captured direct flow blocked fail closed",
                    fields,
                );
                return Err(err.into());
            }
            Err(err)
                if err.recommends_tunnel_failover()
                    && relay::runtime_fallback_ready(relay_settings) =>
            {
                let probe_launch = ActiveStallProbeLaunch {
                    active_probe_plan: current_probe_plan.clone(),
                    mimicry_ttl_hint: current_mimicry_capability.userspace_ttl_hint,
                    wire_window_preface: current_mimicry_capability.wire_window_preface,
                    wire_observation_capture_confidence: current_mimicry_capability
                        .observation_capture_confidence,
                    wire_window_profile: current_mimicry_capability.window_profile,
                    wire_observed_ipv4_header_shaping: current_mimicry_capability
                        .wire_observed_ipv4_header_shaping,
                    wire_observed_negotiated_options: current_mimicry_capability
                        .wire_observed_negotiated_options,
                    wire_observed_fragment_choreography: current_mimicry_capability
                        .wire_observed_fragment_choreography,
                    ..probe_launch.clone()
                };
                if !inline_probe_retry_budget_remaining(inline_probe_retries) {
                    emit_active_stall_probe_retry_budget_exhausted(
                        &err,
                        &current_advisory,
                        stack,
                        wire_mode,
                        dst,
                        &target.host,
                        target.port,
                        inline_probe_retries,
                        last_probe_terminal_stage,
                    );
                    emit_direct_relay_failover_triggered(
                        &err,
                        &current_advisory,
                        stack,
                        wire_mode,
                        dst,
                        &target.host,
                        target.port,
                        DirectRelayFailoverReasonCode::ProbeRetryBudgetExhausted,
                        inline_probe_retries > 0,
                        last_probe_terminal_stage,
                    );
                    let surface_bias = compute_and_log_morphology_bias(
                        &current_advisory,
                        &target.host,
                        target.port,
                    );
                    return run_relay_tunnel_with_direct_handoff(
                        client,
                        relay_settings,
                        target.host,
                        target.port,
                        dst,
                        stack,
                        wire_mode,
                        DirectRelayHandoffContext {
                            initial_payload: Some(&buf),
                            handoff_path: "runtime_failover",
                            reason_code: DirectRelayFailoverReasonCode::ProbeRetryBudgetExhausted
                                .as_str()
                                .to_string(),
                            active_stall_probe_retry_attempted: Some(inline_probe_retries > 0),
                            surface_bias,
                            hybrid: hybrid_runtime_context.clone(),
                        },
                    )
                    .await;
                }
                if let Some(probe_result) =
                    run_active_stall_probe_inline_if_needed(&err, probe_launch).await
                {
                    last_probe_terminal_stage = probe_result.terminal_stage;
                    let refreshed_advisory = brain.direct_session_advisory(&key).await;
                    current_advisory = refreshed_advisory.clone();
                    let relay_failover_reason_code =
                        match active_probe_cycle_decision(&probe_result, &refreshed_advisory) {
                            ActiveProbeCycleDecision::RetryDirect => {
                                emit_active_stall_probe_retry_selected(
                                    &probe_result,
                                    &refreshed_advisory,
                                    stack,
                                    wire_mode,
                                    dst,
                                    &target.host,
                                    target.port,
                                );
                                inline_probe_retries += 1;
                                current_observation = refreshed_advisory.latest_observation.clone();
                                current_probe_plan = planner::build_active_probe_plan_for_dst(
                                    dst,
                                    current_observation.as_ref(),
                                );
                                planner_trace = brain.select_order_trace(&key).await;
                                let resolved_order = resolve_direct_order(
                                    direct,
                                    &refreshed_advisory,
                                    stack,
                                    wire_mode,
                                    dst,
                                    &current_probe_plan,
                                    &target.host,
                                    target.port,
                                    ip_ver,
                                    &planner_trace,
                                    "post_probe_retry_reselect",
                                    inline_probe_retries,
                                    Some(&current_planner_trace.reward_selected_order),
                                    Some(&current_order),
                                    Some(&current_planner_trace),
                                    Some(current_order_resolution),
                                    Some(current_lua_order_applied),
                                    Some(current_advisory_reorder_applied),
                                    Some(
                                        current_order
                                            != current_planner_trace.reward_selected_order,
                                    ),
                                )
                                .await;
                                current_order = resolved_order.order;
                                current_planner_trace = planner_trace.clone();
                                current_order_resolution = resolved_order.order_resolution;
                                current_lua_order_applied = resolved_order.lua_order_applied;
                                current_advisory_reorder_applied =
                                    resolved_order.advisory_reorder_applied;
                                continue;
                            }
                            ActiveProbeCycleDecision::FallBackToRelay(reason_code) => {
                                emit_active_stall_probe_retry_skipped(
                                    &probe_result,
                                    &refreshed_advisory,
                                    stack,
                                    wire_mode,
                                    dst,
                                    &target.host,
                                    target.port,
                                    reason_code,
                                    inline_probe_retries,
                                );
                                DirectRelayFailoverReasonCode::from_retry_suppressed_reason(
                                    reason_code,
                                )
                            }
                        };
                    emit_direct_relay_failover_triggered(
                        &err,
                        &refreshed_advisory,
                        stack,
                        wire_mode,
                        dst,
                        &target.host,
                        target.port,
                        relay_failover_reason_code,
                        inline_probe_retries > 0,
                        probe_result.terminal_stage,
                    );
                    let surface_bias = compute_and_log_morphology_bias(
                        &current_advisory,
                        &target.host,
                        target.port,
                    );
                    return run_relay_tunnel_with_direct_handoff(
                        client,
                        relay_settings,
                        target.host,
                        target.port,
                        dst,
                        stack,
                        wire_mode,
                        DirectRelayHandoffContext {
                            initial_payload: Some(&buf),
                            handoff_path: "runtime_failover",
                            reason_code: relay_failover_reason_code.as_str().to_string(),
                            active_stall_probe_retry_attempted: Some(inline_probe_retries > 0),
                            surface_bias,
                            hybrid: hybrid_runtime_context.clone(),
                        },
                    )
                    .await;
                }
                emit_direct_relay_failover_triggered(
                    &err,
                    &current_advisory,
                    stack,
                    wire_mode,
                    dst,
                    &target.host,
                    target.port,
                    DirectRelayFailoverReasonCode::NoInlineProbeAttempt,
                    inline_probe_retries > 0,
                    None,
                );
                let surface_bias =
                    compute_and_log_morphology_bias(&current_advisory, &target.host, target.port);
                return run_relay_tunnel_with_direct_handoff(
                    client,
                    relay_settings,
                    target.host,
                    target.port,
                    dst,
                    stack,
                    wire_mode,
                    DirectRelayHandoffContext {
                        initial_payload: Some(&buf),
                        handoff_path: "runtime_failover",
                        reason_code: DirectRelayFailoverReasonCode::NoInlineProbeAttempt
                            .as_str()
                            .to_string(),
                        active_stall_probe_retry_attempted: Some(inline_probe_retries > 0),
                        surface_bias,
                        hybrid: hybrid_runtime_context.clone(),
                    },
                )
                .await;
            }
            Err(err) => {
                let probe_launch = ActiveStallProbeLaunch {
                    active_probe_plan: current_probe_plan.clone(),
                    ..probe_launch.clone()
                };
                launch_active_stall_probe_if_needed(&err, probe_launch);
                return Err(err.into());
            }
        }
    }
}

async fn learn_relay_handoff_outcomes(
    brain: &Brain,
    key: &StrategyKey,
    outcomes: &mut tokio::sync::mpsc::UnboundedReceiver<relay::RelayOutcome>,
    result: &anyhow::Result<()>,
) -> bool {
    let mut terminal = None;
    while let Some(outcome) = outcomes.recv().await {
        if let Some(signal) = outcome.learning_signal() {
            brain
                .record_outcome(
                    key,
                    relay_transport_strategy_key(outcome.transport),
                    signal.clone(),
                    outcome.learning_opening_latency_ms(),
                    outcome.bytes_sent as usize,
                    None,
                )
                .await;
        }
        terminal = Some(outcome);
    }
    // Only the final attempt supplies route evidence. Earlier response/error
    // samples remain transport evidence without overriding a clean empty end.
    let route_signal = match terminal.as_ref() {
        Some(outcome) => match outcome.learning_signal() {
            Some(signal) => signal.clone(),
            None if result.is_ok() => return false,
            None => FailSignal::Unknown,
        },
        None if result.is_ok() => return false,
        None => FailSignal::Unknown,
    };
    let route_succeeded = route_signal.is_success();
    brain
        .record_hybrid_route_outcome(key, HybridRouteFamily::RelayGrpc, route_signal)
        .await;
    route_succeeded
}

#[cfg(test)]
#[path = "direct/relay_learning_latency_tests.rs"]
mod relay_learning_latency_tests;
#[cfg(test)]
#[path = "direct/relay_learning_tests.rs"]
mod relay_learning_tests;
#[cfg(test)]
#[path = "direct/relay_timing_controls_tests.rs"]
mod relay_timing_controls_tests;

#[allow(clippy::too_many_arguments)]
async fn run_relay_tunnel_with_direct_handoff(
    client: TcpStream,
    relay_settings: &RelaySettings,
    target_host: String,
    target_port: u16,
    dst: SocketAddr,
    stack: Option<StackProfileId>,
    wire_mode: WireMimicryMode,
    handoff: DirectRelayHandoffContext<'_>,
) -> anyhow::Result<()> {
    if let Some(context) = handoff.hybrid.as_ref() {
        context
            .brain
            .record_hybrid_route_attempt(&context.key, HybridRouteFamily::RelayGrpc)
            .await;
        let mut fields = hybrid_event_fields(context, HybridRouteFamily::RelayGrpc);
        if let Value::Object(map) = &mut fields {
            map.insert("handoff_path".into(), json!(handoff.handoff_path));
            map.insert(
                "handoff_reason_code".into(),
                json!(handoff.reason_code.as_str()),
            );
        }
        runtime_jsonl::emit(
            "info",
            RuntimeEventCode::DirectRelayHandoffStarted,
            "direct to relay handoff started",
            fields,
        );
    }
    let (outcome_tx, mut outcome_rx) =
        tokio::sync::mpsc::unbounded_channel::<relay::RelayOutcome>();
    let result = relay::run_relay_tunnel(
        client,
        relay_settings,
        target_host,
        target_port,
        handoff.initial_payload,
        Some(relay::RelayMimicryContext {
            target_addr: dst,
            stack_profile: stack,
            wire_mode,
            surface_bias: handoff.surface_bias,
        }),
        handoff.hybrid.as_ref().map(|_| &outcome_tx),
    )
    .await;
    drop(outcome_tx);

    if let Some(context) = handoff.hybrid.as_ref() {
        let route_succeeded =
            learn_relay_handoff_outcomes(&context.brain, &context.key, &mut outcome_rx, &result)
                .await;
        if route_succeeded {
            let mut fields = hybrid_event_fields(context, HybridRouteFamily::RelayGrpc);
            if let Value::Object(map) = &mut fields {
                map.insert("handoff_path".into(), json!(handoff.handoff_path));
                map.insert(
                    "handoff_reason_code".into(),
                    json!(handoff.reason_code.as_str()),
                );
            }
            runtime_jsonl::emit(
                "info",
                RuntimeEventCode::DirectRelayHandoffSucceeded,
                "direct to relay handoff succeeded",
                fields,
            );
        }
    }

    match result {
        Ok(()) => Ok(()),
        Err(err) => match err.downcast::<relay::RelayTerminalFailure>() {
            Ok(relay) => Err(anyhow::Error::new(DirectRelayHandoffTerminalFailure {
                handoff_path: handoff.handoff_path,
                reason_code: handoff.reason_code,
                active_stall_probe_retry_attempted: handoff.active_stall_probe_retry_attempted,
                relay,
            })),
            Err(err) => Err(err),
        },
    }
}

#[derive(Clone)]
struct ActiveStallProbeLaunch {
    brain: Arc<Brain>,
    key: StrategyKey,
    dst: SocketAddr,
    buf: Vec<u8>,
    is_tls: bool,
    timeout_limit: Duration,
    freeze_threshold_bytes: usize,
    degraded_latency_ms: u64,
    stack: Option<StackProfileId>,
    wire_mode: WireMimicryMode,
    mimicry_ttl_hint: Option<u32>,
    wire_window_preface: Option<u16>,
    wire_observation_capture_confidence: &'static str,
    wire_window_profile: Option<&'static str>,
    wire_observed_ipv4_header_shaping: Option<aegis_core::ObservedWireIpv4HeaderShaping>,
    wire_observed_negotiated_options: Option<aegis_core::ObservedWireNegotiatedOptions>,
    wire_observed_fragment_choreography: Option<aegis_core::ObservedWireChoreographyHint>,
    active_probe_plan: ActiveProbePlan,
    target_host: String,
    target_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveProbeCycleDecision {
    RetryDirect,
    FallBackToRelay(ActiveStallProbeRetrySuppressedReasonCode),
}

fn inline_probe_retry_budget_remaining(inline_probe_retries: usize) -> bool {
    inline_probe_retries < MAX_INLINE_PROBE_RETRIES_PER_SESSION
}

fn allow_probe_branch(active_probe_plan: &ActiveProbePlan) -> bool {
    active_probe_plan.budget >= 2 && active_probe_plan.candidates.len() >= 2
}

fn add_mimicry_capability_fields(
    fields: &mut Value,
    observation: Option<&aegis_core::KeyObservation>,
    signal_origin: MimicryCapabilitySignalOrigin,
    stack_profile: Option<StackProfileId>,
    wire_mode: WireMimicryMode,
    dst: SocketAddr,
) {
    let capability = planner::build_mimicry_capability_plan(observation);
    let userspace_nodelay_hint = mimicry_userspace_nodelay_hint(stack_profile);
    let userspace_reuseaddr_hint = mimicry_userspace_reuseaddr_hint(stack_profile);
    let userspace_send_buffer_hint = mimicry_userspace_send_buffer_hint(stack_profile);
    let userspace_recv_buffer_hint = mimicry_userspace_recv_buffer_hint(stack_profile);
    let wire_plan = wire_mimicry_plan();
    let wire_runtime = mimicry_wire_runtime_plan(wire_mode, dst, &capability, stack_profile);
    let Some(map) = fields.as_object_mut() else {
        return;
    };
    // Keep the replay boundary machine-readable: advisory traces may reuse the
    // latest stored observation, while success/probe events must stay tied to
    // live runtime observations from the current process.
    map.insert(
        "mimicry_capability_signal_origin".into(),
        Value::String(signal_origin.as_str().to_string()),
    );
    map.insert(
        "mimicry_capability_stage".into(),
        Value::String(capability.stage.to_string()),
    );
    map.insert(
        "mimicry_capability_readiness".into(),
        Value::String(capability.readiness.to_string()),
    );
    map.insert(
        "mimicry_capability_observation_capture_confidence".into(),
        Value::String(capability.observation_capture_confidence.to_string()),
    );
    map.insert(
        "mimicry_capability_wire_stage".into(),
        Value::String(capability.wire_stage.to_string()),
    );
    map.insert(
        "mimicry_capability_wire_scope".into(),
        Value::String(capability.wire_scope.to_string()),
    );
    map.insert(
        "mimicry_capability_wire_validation_strategy".into(),
        Value::String(capability.wire_validation_strategy.to_string()),
    );
    map.insert(
        "mimicry_capability_wire_linux_only".into(),
        Value::Bool(capability.wire_linux_only),
    );
    map.insert(
        "mimicry_capability_wire_requires_raw_capabilities".into(),
        Value::Bool(capability.wire_requires_raw_capabilities),
    );
    map.insert(
        "mimicry_capability_wire_packet_profile_synthesis".into(),
        Value::String(wire_plan.packet_profile_synthesis.to_string()),
    );
    map.insert(
        "mimicry_capability_wire_policy_boundary".into(),
        Value::String(wire_plan.wire_policy_boundary.to_string()),
    );
    map.insert(
        "mimicry_capability_wire_validation_artifact".into(),
        Value::String(wire_plan.validation_artifact.to_string()),
    );
    map.insert(
        "mimicry_capability_wire_host_acceptance_contour".into(),
        Value::String(wire_plan.host_acceptance_contour.to_string()),
    );
    map.insert(
        "mimicry_capability_wire_experimental_config_path".into(),
        Value::String(wire_plan.experimental_config_path.to_string()),
    );
    map.insert(
        "mimicry_capability_wire_config_mode".into(),
        Value::String(wire_mode.as_str().to_string()),
    );
    map.insert(
        "mimicry_capability_wire_requested".into(),
        Value::Bool(wire_runtime.requested),
    );
    map.insert(
        "mimicry_capability_wire_active".into(),
        Value::Bool(wire_runtime.active),
    );
    map.insert(
        "mimicry_capability_wire_activation_reason".into(),
        Value::String(wire_runtime.activation_reason.to_string()),
    );
    map.insert(
        "mimicry_capability_wire_runtime_slice".into(),
        wire_runtime
            .runtime_slice
            .map(|value| Value::String(value.to_string()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_ttl_preface".into(),
        wire_runtime
            .ttl_preface
            .map(|value| serde_json::json!(value))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_window_preface_ready".into(),
        Value::Bool(capability.wire_window_preface_ready),
    );
    map.insert(
        "mimicry_capability_wire_window_preface".into(),
        wire_runtime
            .window_preface
            .map(|value| serde_json::json!(value))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_options_preface_ready".into(),
        Value::Bool(wire_options_preface_profile(stack_profile).is_some()),
    );
    map.insert(
        "mimicry_capability_wire_options_preface_profile".into(),
        wire_runtime
            .options_preface_profile
            .map(|value| Value::String(value.to_string()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_options_preface_size".into(),
        wire_runtime
            .options_preface_size
            .map(|value| serde_json::json!(value))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_ipv4_header_shaping_ready".into(),
        Value::Bool(capability.wire_ipv4_header_shaping_ready),
    );
    map.insert(
        "mimicry_capability_wire_ipv4_header_shaping_observed_ready".into(),
        Value::Bool(capability.wire_observed_ipv4_header_shaping_ready),
    );
    map.insert(
        "mimicry_capability_wire_ipv4_header_shaping_profile".into(),
        wire_runtime
            .ipv4_header_shaping
            .as_ref()
            .map(|value| Value::String(value.profile.to_string()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_ipv4_header_shaping_tos".into(),
        wire_runtime
            .ipv4_header_shaping
            .as_ref()
            .map(|value| serde_json::json!(value.tos))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_ipv4_header_shaping_ip_id".into(),
        wire_runtime
            .ipv4_header_shaping
            .as_ref()
            .map(|value| serde_json::json!(value.identification))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_ipv4_header_shaping_dont_fragment".into(),
        wire_runtime
            .ipv4_header_shaping
            .as_ref()
            .map(|value| Value::Bool(value.dont_fragment))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_ipv4_header_shaping_source".into(),
        wire_runtime
            .ipv4_header_shaping
            .as_ref()
            .map(|value| Value::String(value.source.to_string()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_negotiated_options_ready".into(),
        Value::Bool(
            capability.wire_negotiated_options_ready
                && (capability.wire_observed_negotiated_options_ready || stack_profile.is_some()),
        ),
    );
    map.insert(
        "mimicry_capability_wire_negotiated_options_observed_ready".into(),
        Value::Bool(capability.wire_observed_negotiated_options_ready),
    );
    map.insert(
        "mimicry_capability_wire_negotiated_options_profile".into(),
        wire_runtime
            .negotiated_options
            .as_ref()
            .map(|value| Value::String(value.profile.to_string()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_negotiated_options_size".into(),
        wire_runtime
            .negotiated_options
            .as_ref()
            .map(|value| serde_json::json!(value.size_bytes))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_negotiated_options_mss".into(),
        wire_runtime
            .negotiated_options
            .as_ref()
            .map(|value| serde_json::json!(value.mss))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_negotiated_options_window_scale".into(),
        wire_runtime
            .negotiated_options
            .as_ref()
            .map(|value| serde_json::json!(value.window_scale))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_negotiated_options_sack_permitted".into(),
        wire_runtime
            .negotiated_options
            .as_ref()
            .map(|value| Value::Bool(value.sack_permitted))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_negotiated_options_timestamp_mode".into(),
        wire_runtime
            .negotiated_options
            .as_ref()
            .map(|value| Value::String(value.timestamp_mode.to_string()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_negotiated_options_source".into(),
        wire_runtime
            .negotiated_options
            .as_ref()
            .map(|value| Value::String(value.source.to_string()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_raw_ipv4_send_ready".into(),
        Value::Bool(wire_runtime.raw_ipv4_send_ready),
    );
    map.insert(
        "mimicry_capability_wire_tcp_repair_ready".into(),
        Value::Bool(wire_runtime.tcp_repair_ready),
    );
    map.insert(
        "mimicry_capability_wire_ipv4_header_control_ready".into(),
        Value::Bool(wire_runtime.ipv4_header_control_ready),
    );
    map.insert(
        "mimicry_capability_wire_ipv4_fragmentation_ready".into(),
        Value::Bool(wire_runtime.ipv4_fragmentation_ready),
    );
    map.insert(
        "mimicry_capability_wire_fragment_choreography_ready".into(),
        Value::Bool(capability.wire_fragment_choreography_ready),
    );
    map.insert(
        "mimicry_capability_wire_fragment_choreography_observed_ready".into(),
        Value::Bool(capability.wire_observed_fragment_choreography_ready),
    );
    map.insert(
        "mimicry_capability_wire_fragment_choreography_profile".into(),
        wire_runtime
            .fragment_choreography
            .as_ref()
            .map(|value| Value::String(value.profile.to_string()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_fragment_choreography_steps".into(),
        wire_runtime
            .fragment_choreography
            .as_ref()
            .map(|value| Value::String(value.steps.to_string()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_fragment_choreography_first_payload_len".into(),
        wire_runtime
            .fragment_choreography
            .as_ref()
            .map(|value| serde_json::json!(value.fragment_first_payload_len))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_fragment_choreography_disorder_split_at".into(),
        wire_runtime
            .fragment_choreography
            .as_ref()
            .map(|value| serde_json::json!(value.disorder_split_at))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_fragment_choreography_overlap".into(),
        wire_runtime
            .fragment_choreography
            .as_ref()
            .map(|value| serde_json::json!(value.overlap_bytes))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_wire_fragment_choreography_source".into(),
        wire_runtime
            .fragment_choreography
            .as_ref()
            .map(|value| Value::String(value.source.to_string()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_userspace_scope".into(),
        Value::String("pre_connect_socket_only".to_string()),
    );
    map.insert(
        "mimicry_capability_userspace_wiring_mode".into(),
        Value::String(mimicry_userspace_wiring_mode(stack_profile, &capability).to_string()),
    );
    map.insert(
        "mimicry_capability_userspace_stack_profile".into(),
        stack_profile
            .map(|value| Value::String(value.as_str().to_string()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_userspace_ttl_hint_ready".into(),
        Value::Bool(capability.userspace_ttl_hint_ready),
    );
    map.insert(
        "mimicry_capability_userspace_nodelay_ready".into(),
        Value::Bool(userspace_nodelay_hint.is_some()),
    );
    map.insert(
        "mimicry_capability_userspace_reuseaddr_ready".into(),
        Value::Bool(userspace_reuseaddr_hint.is_some()),
    );
    map.insert(
        "mimicry_capability_userspace_send_buffer_ready".into(),
        Value::Bool(userspace_send_buffer_hint.is_some()),
    );
    map.insert(
        "mimicry_capability_userspace_recv_buffer_ready".into(),
        Value::Bool(userspace_recv_buffer_hint.is_some()),
    );
    map.insert(
        "mimicry_capability_server_hint_ready".into(),
        Value::Bool(capability.server_hint_ready),
    );
    map.insert(
        "mimicry_capability_window_profile_ready".into(),
        Value::Bool(capability.window_profile_ready),
    );
    map.insert(
        "mimicry_capability_reference_path_ready".into(),
        Value::Bool(capability.reference_path_ready),
    );
    map.insert(
        "mimicry_capability_rst_path_ready".into(),
        Value::Bool(capability.rst_path_ready),
    );
    map.insert(
        "mimicry_capability_userspace_ttl_hint".into(),
        capability
            .userspace_ttl_hint
            .map(|value| serde_json::json!(value))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_userspace_nodelay".into(),
        userspace_nodelay_hint
            .map(|value| serde_json::json!(value))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_userspace_reuseaddr".into(),
        userspace_reuseaddr_hint
            .map(|value| serde_json::json!(value))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_userspace_send_buffer".into(),
        userspace_send_buffer_hint
            .map(|value| serde_json::json!(value))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_userspace_recv_buffer".into(),
        userspace_recv_buffer_hint
            .map(|value| serde_json::json!(value))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_server_hint".into(),
        capability
            .server_hint
            .map(|value| Value::String(value.to_string()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_window_profile".into(),
        capability
            .window_profile
            .map(|value| Value::String(value.to_string()))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_reference_path_hops".into(),
        capability
            .reference_path_hops
            .map(|value| serde_json::json!(value))
            .unwrap_or(Value::Null),
    );
    map.insert(
        "mimicry_capability_rst_path_hops".into(),
        capability
            .rst_path_hops
            .map(|value| serde_json::json!(value))
            .unwrap_or(Value::Null),
    );
}

fn add_cross_session_metric_fields(
    fields: &mut Value,
    advisory: &aegis_core::DirectSessionAdvisory,
) {
    let Some(map) = fields.as_object_mut() else {
        return;
    };
    map.insert(
        "cross_session_confidence_score".into(),
        serde_json::json!(advisory.cross_session_signal_metrics.confidence_score),
    );
    map.insert(
        "cross_session_reuse_weight".into(),
        serde_json::json!(advisory.cross_session_signal_metrics.reuse_weight),
    );
    map.insert(
        "cross_session_stall_severity".into(),
        serde_json::json!(advisory.cross_session_signal_metrics.stall_severity),
    );
    map.insert(
        "cross_session_probe_branch_score".into(),
        serde_json::json!(advisory.cross_session_signal_metrics.probe_branch_score),
    );
    map.insert(
        "cross_session_relay_preference_score".into(),
        serde_json::json!(advisory.cross_session_signal_metrics.relay_preference_score),
    );
    map.insert(
        "cross_session_signal_bias".into(),
        Value::String(advisory.cross_session_signal_bias().to_string()),
    );
}

fn add_probe_history_fields(fields: &mut Value, advisory: &aegis_core::DirectSessionAdvisory) {
    let Some(map) = fields.as_object_mut() else {
        return;
    };
    map.insert(
        "probe_history_disposition".into(),
        Value::String(advisory.probe_history_disposition.as_str().to_string()),
    );
    map.insert(
        "probe_history_reason_code".into(),
        Value::String(advisory.probe_history_reason_code.as_str().to_string()),
    );
}

fn planner_order_changed(previous_order: Option<&[String]>, current_order: &[String]) -> bool {
    previous_order
        .map(|previous| previous != current_order)
        .unwrap_or(false)
}

fn planner_metric_delta(previous_value: Option<f64>, current_value: f64) -> Option<f64> {
    previous_value.map(|previous| current_value - previous)
}

fn planner_optional_metric_delta(
    previous_value: Option<f64>,
    current_value: Option<f64>,
) -> Option<f64> {
    match (previous_value, current_value) {
        (Some(previous), Some(current)) => Some(current - previous),
        _ => None,
    }
}

fn planner_rank_delta(previous_rank: Option<usize>, current_rank: usize) -> Option<i64> {
    previous_rank.map(|previous| current_rank as i64 - previous as i64)
}

fn planner_reward_selection_source(trace: &DirectPlannerSelectionTrace) -> &'static str {
    match trace.explainability_trace_source {
        "runtime_randomized_preferred_order" => "randomized_preferred_order",
        "bounded_recent_runtime_outcomes" => "bounded_recent_runtime_outcomes",
        _ => "brain_reward_loop",
    }
}

fn planner_probe_bias_effect(candidate: &DirectPlannerCandidateTrace) -> &'static str {
    if candidate.selection_score_probe_bias_component > f64::EPSILON {
        "boosted"
    } else if candidate.selection_score_probe_bias_component < -f64::EPSILON {
        "penalized"
    } else {
        "neutral"
    }
}

fn planner_selection_score_dominant_component(
    candidate: &DirectPlannerCandidateTrace,
) -> &'static str {
    if candidate.cold_start_exploration {
        return "cold_start_exploration";
    }
    let reward = candidate.selection_score_reward_component.abs();
    let ucb = candidate
        .selection_score_ucb_exploration_bonus
        .unwrap_or_default()
        .abs();
    let probe_bias = candidate.selection_score_probe_bias_component.abs();
    if probe_bias > reward && probe_bias > ucb {
        "probe_history_bias_component"
    } else if ucb > reward {
        "ucb_exploration_bonus"
    } else {
        "reward_component"
    }
}

fn planner_top_candidate_primary_reason(trace: &DirectPlannerSelectionTrace) -> &'static str {
    if let Some(recent) = &trace.recent_selection {
        return if recent.selection.order.is_empty() {
            "recent_selection_empty_fail_closed"
        } else {
            "top_candidate_recent_windowed_ucb_diversity"
        };
    }
    if trace.selector_mode == "epsilon_randomized_preferred_order" {
        return "epsilon_randomized_preferred_order";
    }
    let Some(candidate) = trace.ranked_candidates.first() else {
        return "no_ranked_candidates";
    };
    match planner_selection_score_dominant_component(candidate) {
        "cold_start_exploration" => "top_candidate_cold_start_exploration",
        "probe_history_bias_component" => "top_candidate_probe_history_bias_component",
        "ucb_exploration_bonus" => "top_candidate_ucb_exploration_bonus",
        _ => "top_candidate_reward_component",
    }
}

fn planner_resolved_order_primary_reason(order_resolution: &'static str) -> &'static str {
    match order_resolution {
        "lua_hook_only" => "lua_hook_reordered_reward_loop",
        "advisory_probe_branch" => "advisory_probe_branch_reordered_reward_loop",
        "lua_hook_and_advisory_probe_branch" => {
            "lua_hook_then_advisory_probe_branch_reordered_reward_loop"
        }
        _ => "reward_loop_preserved",
    }
}

fn planner_top_candidate_dominant_component(
    trace: &DirectPlannerSelectionTrace,
) -> Option<&'static str> {
    if let Some(recent) = &trace.recent_selection {
        return (!recent.selection.order.is_empty()).then_some("recent_windowed_ucb_diversity");
    }
    trace
        .ranked_candidates
        .first()
        .map(planner_selection_score_dominant_component)
}

fn planner_optional_str_changed(previous_value: Option<&str>, current_value: &str) -> bool {
    previous_value.is_some_and(|previous| previous != current_value)
}

fn planner_optional_bool_changed(previous_value: Option<bool>, current_value: bool) -> bool {
    previous_value.is_some_and(|previous| previous != current_value)
}

#[derive(Debug, Clone)]
struct ResolvedDirectOrder {
    order: Vec<String>,
    order_resolution: &'static str,
    lua_order_applied: bool,
    advisory_reorder_applied: bool,
}

fn planner_candidate_runtime_fields(
    current_rank: usize,
    candidate: &DirectPlannerCandidateTrace,
    previous_trace: Option<&DirectPlannerSelectionTrace>,
) -> Value {
    let previous_candidate = previous_trace.and_then(|trace| {
        trace
            .ranked_candidates
            .iter()
            .enumerate()
            .find(|(_, previous)| previous.strategy == candidate.strategy)
    });
    let previous_rank = previous_candidate.map(|(rank, _)| rank);
    let previous_candidate = previous_candidate.map(|(_, candidate)| candidate);
    let previous_estimated_reward = previous_candidate.map(|candidate| candidate.estimated_reward);
    let previous_estimated_trials = previous_candidate.map(|candidate| candidate.estimated_trials);
    let previous_total_trials = previous_candidate.map(|candidate| candidate.total_trials);
    let previous_probe_bias =
        previous_candidate.map(|candidate| candidate.probe_history_strategy_bias);
    let previous_selection_score_reward_component =
        previous_candidate.map(|candidate| candidate.selection_score_reward_component);
    let previous_selection_score_ucb_exploration_bonus =
        previous_candidate.and_then(|candidate| candidate.selection_score_ucb_exploration_bonus);
    let previous_selection_score_probe_bias_component =
        previous_candidate.map(|candidate| candidate.selection_score_probe_bias_component);
    let previous_selection_score =
        previous_candidate.and_then(|candidate| candidate.selection_score);
    serde_json::json!({
        "strategy": candidate.strategy,
        "rank": current_rank,
        "has_previous_candidate_trace": previous_candidate.is_some(),
        "previous_rank": previous_rank,
        "rank_delta": planner_rank_delta(previous_rank, current_rank),
        "estimated_reward": candidate.estimated_reward,
        "previous_estimated_reward": previous_estimated_reward,
        "estimated_reward_delta": planner_metric_delta(
            previous_estimated_reward,
            candidate.estimated_reward,
        ),
        "estimated_trials": candidate.estimated_trials,
        "previous_estimated_trials": previous_estimated_trials,
        "estimated_trials_delta": planner_metric_delta(
            previous_estimated_trials,
            candidate.estimated_trials,
        ),
        "total_trials": candidate.total_trials,
        "previous_total_trials": previous_total_trials,
        "total_trials_delta": planner_metric_delta(previous_total_trials, candidate.total_trials),
        "probe_history_strategy_bias": candidate.probe_history_strategy_bias,
        "previous_probe_history_strategy_bias": previous_probe_bias,
        "probe_history_strategy_bias_delta": planner_metric_delta(
            previous_probe_bias,
            candidate.probe_history_strategy_bias,
        ),
        "belief_alpha": candidate.belief_alpha,
        "belief_beta": candidate.belief_beta,
        "belief_detection_risk": candidate.belief_detection_risk,
        "belief_latency_cost": candidate.belief_latency_cost,
        "belief_confidence": candidate.belief_confidence,
        "belief_freshness": candidate.belief_freshness,
        "belief_hard_blocked": candidate.belief_hard_blocked,
        "belief_source": candidate.belief_source,
        // Keep the aggregate score, but also surface additive causes explicitly.
        "selection_score_reward_component": candidate.selection_score_reward_component,
        "previous_selection_score_reward_component": previous_selection_score_reward_component,
        "selection_score_reward_component_delta": planner_metric_delta(
            previous_selection_score_reward_component,
            candidate.selection_score_reward_component,
        ),
        "selection_score_ucb_exploration_bonus": candidate.selection_score_ucb_exploration_bonus,
        "previous_selection_score_ucb_exploration_bonus": previous_selection_score_ucb_exploration_bonus,
        "selection_score_ucb_exploration_bonus_delta": planner_optional_metric_delta(
            previous_selection_score_ucb_exploration_bonus,
            candidate.selection_score_ucb_exploration_bonus,
        ),
        "selection_score_probe_bias_component": candidate.selection_score_probe_bias_component,
        "previous_selection_score_probe_bias_component": previous_selection_score_probe_bias_component,
        "selection_score_probe_bias_component_delta": planner_metric_delta(
            previous_selection_score_probe_bias_component,
            candidate.selection_score_probe_bias_component,
        ),
        "selection_score": candidate.selection_score,
        "previous_selection_score": previous_selection_score,
        "selection_score_delta": planner_optional_metric_delta(
            previous_selection_score,
            candidate.selection_score,
        ),
        "cold_start_exploration": candidate.cold_start_exploration,
        "selection_score_dominant_component": planner_selection_score_dominant_component(candidate),
        "selection_score_probe_bias_effect": planner_probe_bias_effect(candidate),
    })
}

#[allow(clippy::too_many_arguments)]
fn planner_selection_runtime_fields(
    trace: &DirectPlannerSelectionTrace,
    resolved_order: &[String],
    order_resolution: &'static str,
    lua_order_configured: bool,
    lua_order_applied: bool,
    advisory_reorder_requested: bool,
    advisory_reorder_allowed: bool,
    advisory_reorder_applied: bool,
    planner_selection_stage: &'static str,
    planner_retry_attempt: usize,
    previous_reward_selected_order: Option<&[String]>,
    previous_resolved_order: Option<&[String]>,
    previous_trace: Option<&DirectPlannerSelectionTrace>,
    previous_order_resolution: Option<&'static str>,
    previous_lua_order_applied: Option<bool>,
    previous_advisory_reorder_applied: Option<bool>,
    previous_post_brain_reorder_applied: Option<bool>,
    target_host: &str,
    target_port: u16,
) -> Value {
    let top_candidate_primary_reason = planner_top_candidate_primary_reason(trace);
    let top_candidate_dominant_component = planner_top_candidate_dominant_component(trace);
    let resolved_order_primary_reason = planner_resolved_order_primary_reason(order_resolution);
    let post_brain_reorder_applied = trace.reward_selected_order != resolved_order;
    let previous_top_candidate_primary_reason =
        previous_trace.map(planner_top_candidate_primary_reason);
    let previous_top_candidate_dominant_component =
        previous_trace.and_then(planner_top_candidate_dominant_component);
    let previous_resolved_order_primary_reason =
        previous_order_resolution.map(planner_resolved_order_primary_reason);
    let mut fields = serde_json::Map::new();
    fields.insert("target".into(), serde_json::json!(target_host));
    fields.insert("port".into(), serde_json::json!(target_port));
    fields.insert(
        "planner_selector_mode".into(),
        serde_json::json!(trace.selector_mode),
    );
    fields.insert(
        "planner_recent_selection".into(),
        serde_json::json!(trace.recent_selection),
    );
    fields.insert(
        "planner_ranked_candidates_scope".into(),
        serde_json::json!(if trace.recent_selection.is_some() {
            "baseline_contextual_snapshot"
        } else {
            "selected_order_evidence"
        }),
    );
    fields.insert(
        "planner_reward_selection_source".into(),
        serde_json::json!(planner_reward_selection_source(trace)),
    );
    fields.insert(
        "planner_top_candidate_strategy".into(),
        serde_json::json!(if let Some(recent) = &trace.recent_selection {
            recent.selection.order.first().map(String::as_str)
        } else {
            trace
                .ranked_candidates
                .first()
                .map(|candidate| candidate.strategy.as_str())
        }),
    );
    fields.insert(
        "planner_top_candidate_primary_reason".into(),
        serde_json::json!(top_candidate_primary_reason),
    );
    fields.insert(
        "planner_previous_top_candidate_primary_reason".into(),
        serde_json::json!(previous_top_candidate_primary_reason),
    );
    fields.insert(
        "planner_top_candidate_primary_reason_changed".into(),
        serde_json::json!(planner_optional_str_changed(
            previous_top_candidate_primary_reason,
            top_candidate_primary_reason,
        )),
    );
    fields.insert(
        "planner_top_candidate_dominant_component".into(),
        serde_json::json!(top_candidate_dominant_component),
    );
    fields.insert(
        "planner_previous_top_candidate_dominant_component".into(),
        serde_json::json!(previous_top_candidate_dominant_component),
    );
    fields.insert(
        "planner_top_candidate_dominant_component_changed".into(),
        serde_json::json!(previous_top_candidate_dominant_component
            .is_some_and(|previous| Some(previous) != top_candidate_dominant_component)),
    );
    fields.insert(
        "planner_explainability_trace_source".into(),
        serde_json::json!(trace.explainability_trace_source),
    );
    fields.insert(
        "planner_explainability_observation_source".into(),
        serde_json::json!(trace.explainability_observation_source),
    );
    fields.insert(
        "planner_decision_context".into(),
        serde_json::json!(trace.decision_context),
    );
    // Planner selection is intentionally advisory/snapshot-oriented; live
    // current-session observation belongs to success/probe events instead.
    fields.insert(
        "planner_explainability_live_runtime_observation_used".into(),
        serde_json::json!(false),
    );
    fields.insert(
        "planner_order_resolution".into(),
        serde_json::json!(order_resolution),
    );
    fields.insert(
        "planner_previous_order_resolution".into(),
        serde_json::json!(previous_order_resolution),
    );
    fields.insert(
        "planner_order_resolution_changed".into(),
        serde_json::json!(planner_optional_str_changed(
            previous_order_resolution,
            order_resolution,
        )),
    );
    fields.insert(
        "planner_resolved_order_primary_reason".into(),
        serde_json::json!(resolved_order_primary_reason),
    );
    fields.insert(
        "planner_previous_resolved_order_primary_reason".into(),
        serde_json::json!(previous_resolved_order_primary_reason),
    );
    fields.insert(
        "planner_resolved_order_primary_reason_changed".into(),
        serde_json::json!(planner_optional_str_changed(
            previous_resolved_order_primary_reason,
            resolved_order_primary_reason,
        )),
    );
    fields.insert(
        "planner_post_brain_reorder_applied".into(),
        serde_json::json!(post_brain_reorder_applied),
    );
    fields.insert(
        "planner_previous_post_brain_reorder_applied".into(),
        serde_json::json!(previous_post_brain_reorder_applied),
    );
    fields.insert(
        "planner_post_brain_reorder_path_changed".into(),
        serde_json::json!(planner_optional_bool_changed(
            previous_post_brain_reorder_applied,
            post_brain_reorder_applied,
        )),
    );
    fields.insert(
        "planner_reward_loop_order_preserved".into(),
        serde_json::json!(!post_brain_reorder_applied),
    );
    fields.insert(
        "planner_lua_order_configured".into(),
        serde_json::json!(lua_order_configured),
    );
    fields.insert(
        "planner_lua_order_applied".into(),
        serde_json::json!(lua_order_applied),
    );
    fields.insert(
        "planner_previous_lua_order_applied".into(),
        serde_json::json!(previous_lua_order_applied),
    );
    fields.insert(
        "planner_lua_order_applied_changed".into(),
        serde_json::json!(planner_optional_bool_changed(
            previous_lua_order_applied,
            lua_order_applied,
        )),
    );
    fields.insert(
        "planner_advisory_reorder_requested".into(),
        serde_json::json!(advisory_reorder_requested),
    );
    fields.insert(
        "planner_advisory_reorder_allowed".into(),
        serde_json::json!(advisory_reorder_allowed),
    );
    fields.insert(
        "planner_advisory_reorder_applied".into(),
        serde_json::json!(advisory_reorder_applied),
    );
    fields.insert(
        "planner_previous_advisory_reorder_applied".into(),
        serde_json::json!(previous_advisory_reorder_applied),
    );
    fields.insert(
        "planner_advisory_reorder_applied_changed".into(),
        serde_json::json!(planner_optional_bool_changed(
            previous_advisory_reorder_applied,
            advisory_reorder_applied,
        )),
    );
    fields.insert(
        "planner_selection_stage".into(),
        serde_json::json!(planner_selection_stage),
    );
    fields.insert(
        "planner_retry_attempt".into(),
        serde_json::json!(planner_retry_attempt),
    );
    fields.insert(
        "planner_has_previous_selection".into(),
        serde_json::json!(previous_resolved_order.is_some()),
    );
    fields.insert(
        "planner_previous_reward_selected_order".into(),
        serde_json::json!(previous_reward_selected_order),
    );
    fields.insert(
        "planner_previous_resolved_order".into(),
        serde_json::json!(previous_resolved_order),
    );
    fields.insert(
        "planner_reward_selected_order_changed".into(),
        serde_json::json!(planner_order_changed(
            previous_reward_selected_order,
            &trace.reward_selected_order,
        )),
    );
    fields.insert(
        "planner_resolved_order_changed".into(),
        serde_json::json!(planner_order_changed(
            previous_resolved_order,
            resolved_order,
        )),
    );
    fields.insert(
        "planner_reward_selected_order".into(),
        serde_json::json!(trace.reward_selected_order),
    );
    fields.insert(
        "planner_resolved_order".into(),
        serde_json::json!(resolved_order),
    );
    fields.insert(
        "observation_contract".into(),
        serde_json::json!(trace.observation_contract),
    );
    fields.insert(
        "observation_capture_confidence".into(),
        serde_json::json!(trace.observation_capture_confidence),
    );
    fields.insert(
        "probe_history_disposition".into(),
        serde_json::json!(trace.probe_history_disposition),
    );
    fields.insert(
        "probe_history_reason_code".into(),
        serde_json::json!(trace.probe_history_reason_code),
    );
    fields.insert(
        "cross_session_signal_bias".into(),
        serde_json::json!(trace.cross_session_signal_bias),
    );
    fields.insert(
        "cross_session_confidence_score".into(),
        serde_json::json!(trace.cross_session_confidence_score),
    );
    fields.insert(
        "cross_session_reuse_weight".into(),
        serde_json::json!(trace.cross_session_reuse_weight),
    );
    fields.insert(
        "cross_session_stall_severity".into(),
        serde_json::json!(trace.cross_session_stall_severity),
    );
    fields.insert(
        "cross_session_probe_branch_score".into(),
        serde_json::json!(trace.cross_session_probe_branch_score),
    );
    fields.insert(
        "cross_session_relay_preference_score".into(),
        serde_json::json!(trace.cross_session_relay_preference_score),
    );
    fields.insert(
        "planner_ranked_candidates".into(),
        Value::Array(
            trace
                .ranked_candidates
                .iter()
                .enumerate()
                .map(|(rank, candidate)| {
                    planner_candidate_runtime_fields(rank, candidate, previous_trace)
                })
                .collect::<Vec<_>>(),
        ),
    );
    Value::Object(fields)
}

fn apply_lua_order_hook(
    direct: &DirectSettings,
    mut order: Vec<String>,
    ip_ver: u8,
) -> Vec<String> {
    if let Some(ref lua_path) = direct.lua_order_script {
        let path = crate::config::expand_tilde(lua_path);
        match aegis_core::lua_engine::try_apply_order_hook(Some(path.as_path()), &order, ip_ver) {
            Ok(Some(updated)) if !updated.is_empty() => order = updated,
            Err(e) => tracing::warn!(%e, "lua order hook"),
            Ok(_) => {}
        }
    }
    order
}

#[allow(clippy::too_many_arguments)]
async fn resolve_direct_order(
    direct: &DirectSettings,
    advisory: &aegis_core::DirectSessionAdvisory,
    stack: Option<StackProfileId>,
    wire_mode: WireMimicryMode,
    dst: SocketAddr,
    active_probe_plan: &ActiveProbePlan,
    target_host: &str,
    target_port: u16,
    ip_ver: u8,
    planner_trace: &DirectPlannerSelectionTrace,
    planner_selection_stage: &'static str,
    planner_retry_attempt: usize,
    previous_reward_selected_order: Option<&[String]>,
    previous_resolved_order: Option<&[String]>,
    previous_trace: Option<&DirectPlannerSelectionTrace>,
    previous_order_resolution: Option<&'static str>,
    previous_lua_order_applied: Option<bool>,
    previous_advisory_reorder_applied: Option<bool>,
    previous_post_brain_reorder_applied: Option<bool>,
) -> ResolvedDirectOrder {
    let reward_order = planner_trace.reward_selected_order.clone();
    let lua_order_configured = direct.lua_order_script.is_some();
    let mut order = apply_lua_order_hook(direct, reward_order.clone(), ip_ver);
    if planner_trace.recent_selection.is_some() {
        // A local hook may reorder the admitted recent set, never restore a
        // blocked/unknown strategy or turn an empty refusal into a fallback.
        let mut retained = Vec::new();
        order.retain(|strategy| {
            if reward_order.contains(strategy) && !retained.contains(strategy) {
                retained.push(strategy.clone());
                true
            } else {
                false
            }
        });
    }
    let lua_order_applied = order != reward_order;
    let advisory_reorder_allowed = allow_probe_branch(active_probe_plan);
    let advisory_reorder_requested = matches!(
        advisory.probe_history_disposition,
        ProbeHistoryDisposition::BiasProbeBranch
    );
    let branched_order = advisory.apply_to_direct_order(order.clone(), advisory_reorder_allowed);
    let advisory_reorder_applied = branched_order != order;
    let order_resolution = match (lua_order_applied, advisory_reorder_applied) {
        (false, false) => "reward_loop_only",
        (true, false) => "lua_hook_only",
        (false, true) => "advisory_probe_branch",
        (true, true) => "lua_hook_and_advisory_probe_branch",
    };
    tracing::info!(
        event_code = RuntimeEventCode::DirectPlannerOrderSelected.as_str(),
        target = %target_host,
        port = target_port,
        planner_selector_mode = planner_trace.selector_mode,
        planner_order_resolution = order_resolution,
        planner_selection_stage = planner_selection_stage,
        planner_retry_attempt = planner_retry_attempt,
        planner_reward_selection_source = planner_reward_selection_source(planner_trace),
        planner_explainability_trace_source = planner_trace.explainability_trace_source,
        planner_explainability_observation_source =
            planner_trace.explainability_observation_source,
        planner_lua_order_applied = lua_order_applied,
        planner_advisory_reorder_requested = advisory_reorder_requested,
        planner_advisory_reorder_allowed = advisory_reorder_allowed,
        planner_advisory_reorder_applied = advisory_reorder_applied,
        probe_history_disposition = planner_trace.probe_history_disposition,
        probe_history_reason_code = planner_trace.probe_history_reason_code,
        cross_session_signal_bias = planner_trace.cross_session_signal_bias,
        planner_reward_selected_order = ?planner_trace.reward_selected_order,
        planner_resolved_order = ?branched_order,
        "{}",
        "selected direct planner order"
    );
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::DirectPlannerOrderSelected,
        "selected direct planner order",
        {
            let mut fields = planner_selection_runtime_fields(
                planner_trace,
                &branched_order,
                order_resolution,
                lua_order_configured,
                lua_order_applied,
                advisory_reorder_requested,
                advisory_reorder_allowed,
                advisory_reorder_applied,
                planner_selection_stage,
                planner_retry_attempt,
                previous_reward_selected_order,
                previous_resolved_order,
                previous_trace,
                previous_order_resolution,
                previous_lua_order_applied,
                previous_advisory_reorder_applied,
                previous_post_brain_reorder_applied,
                target_host,
                target_port,
            );
            add_mimicry_capability_fields(
                &mut fields,
                advisory.latest_observation.as_ref(),
                MimicryCapabilitySignalOrigin::AdvisoryLatestObservation,
                stack,
                wire_mode,
                dst,
            );
            fields
        },
    );
    if branched_order != order {
        let event = advisory.probe_branch_event_data(
            target_host,
            target_port,
            active_probe_plan.preferred_ttl,
            active_probe_plan.budget,
            &active_probe_plan.candidates,
            &branched_order,
        );
        tracing::info!(
            event_code = RuntimeEventCode::DirectActiveProbeBranchSelected.as_str(),
            target = %target_host,
            port = target_port,
            probe_history_disposition = event.trace.probe_history_disposition,
            probe_history_reason_code = event.trace.probe_history_reason_code,
            observation_contract = event.trace.observation_contract,
            server_hint = ?event.trace.server_hint,
            fingerprint_window_hint = ?event.trace.fingerprint_window_hint,
            planned_probe_preferred_ttl = event.trace.planned_probe_preferred_ttl,
            planned_probe_budget = event.trace.planned_probe_budget,
            planned_probe_ttl_candidates = ?event.trace.planned_probe_ttl_candidates,
            branch_order = ?event.trace.branch_order,
            "{}",
            event.message
        );
        runtime_jsonl::emit(
            "info",
            RuntimeEventCode::DirectActiveProbeBranchSelected,
            event.message,
            {
                let mut fields = event.runtime_fields;
                add_mimicry_capability_fields(
                    &mut fields,
                    advisory.latest_observation.as_ref(),
                    MimicryCapabilitySignalOrigin::AdvisoryLatestObservation,
                    stack,
                    wire_mode,
                    dst,
                );
                fields
            },
        );
        return ResolvedDirectOrder {
            order: branched_order,
            order_resolution,
            lua_order_applied,
            advisory_reorder_applied,
        };
    }
    ResolvedDirectOrder {
        order,
        order_resolution,
        lua_order_applied,
        advisory_reorder_applied,
    }
}

fn should_run_active_stall_probe(
    err: &executor::DirectExecutionError,
    launch: &ActiveStallProbeLaunch,
) -> bool {
    err.recommends_active_stall_probe() && !launch.buf.is_empty()
}

fn emit_active_stall_probe_launched(
    err: &executor::DirectExecutionError,
    launch: &ActiveStallProbeLaunch,
) {
    let event = active_stall_probe_launched_event_data(
        &err.signal,
        err.observation_contract,
        &launch.target_host,
        launch.target_port,
        launch.active_probe_plan.preferred_ttl,
        launch.active_probe_plan.budget,
        &launch.active_probe_plan.candidates,
    );
    tracing::info!(
        event_code = RuntimeEventCode::DirectActiveStallProbeLaunched.as_str(),
        signal = event.trace.signal.as_str(),
        observation_contract = event.trace.observation_contract,
        target = %launch.target_host,
        port = launch.target_port,
        planned_probe_preferred_ttl = event.trace.planned_probe_preferred_ttl,
        planned_probe_budget = event.trace.planned_probe_budget,
        planned_probe_ttl_candidates = ?event.trace.planned_probe_ttl_candidates,
        "{}",
        event.message
    );
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::DirectActiveStallProbeLaunched,
        event.message,
        {
            let mut fields = event.runtime_fields;
            add_mimicry_capability_fields(
                &mut fields,
                Some(&err.observation),
                MimicryCapabilitySignalOrigin::LiveRuntimeObservation,
                launch.stack,
                launch.wire_mode,
                launch.dst,
            );
            fields
        },
    );
}

fn emit_active_stall_probe_finished(
    launch: &ActiveStallProbeLaunch,
    result: &executor::ActiveStallProbeResult,
) {
    let event = active_stall_probe_finished_event_data(
        &result.signal,
        &result.observation,
        RuntimeEndpoint {
            target: &launch.target_host,
            port: launch.target_port,
        },
        ActiveStallProbePlanContext {
            preferred_ttl: result.planned_probe_preferred_ttl,
            budget: result.planned_probe_budget,
            ttl_candidates: &result.planned_probe_ttl_candidates,
        },
        ActiveStallProbeFinishContext {
            latency_ms: result.latency_ms,
            first_response_bytes: result.first_response_bytes,
            terminal_stage: result.terminal_stage,
        },
    );
    tracing::info!(
        event_code = RuntimeEventCode::DirectActiveStallProbeFinished.as_str(),
        target = %launch.target_host,
        port = launch.target_port,
        signal = event.trace.signal.as_str(),
        probe_outcome_class = event.trace.probe_outcome_class,
        observation_contract = event.trace.observation_contract,
        latency_ms = event.trace.latency_ms,
        capture_status = event.trace.capture_status.as_str(),
        reference_path_hops = event.trace.reference_path_hops,
        rst_path_hops = event.trace.rst_path_hops,
        server_hint = ?event.trace.server_hint,
        fingerprint_window_hint = ?event.trace.fingerprint_window_hint,
        planned_probe_preferred_ttl = event.trace.planned_probe_preferred_ttl,
        planned_probe_budget = event.trace.planned_probe_budget,
        planned_probe_ttl_candidates = ?event.trace.planned_probe_ttl_candidates,
        first_response_bytes = event.trace.first_response_bytes,
        probe_terminal_stage = ?event.trace.probe_terminal_stage,
        "{}",
        event.message
    );
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::DirectActiveStallProbeFinished,
        event.message,
        {
            let mut fields = event.runtime_fields;
            add_mimicry_capability_fields(
                &mut fields,
                Some(&result.observation),
                MimicryCapabilitySignalOrigin::LiveActiveProbeObservation,
                launch.stack,
                launch.wire_mode,
                launch.dst,
            );
            fields
        },
    );
}

#[allow(clippy::too_many_arguments)]
fn emit_direct_session_succeeded(
    success: &executor::DirectExecutionSuccess,
    advisory: &aegis_core::DirectSessionAdvisory,
    stack: Option<StackProfileId>,
    wire_mode: WireMimicryMode,
    dst: SocketAddr,
    target_host: &str,
    target_port: u16,
    bytes_sent: usize,
    retry_attempts_used: usize,
) {
    let event = direct_session_succeeded_event_data(
        &success.strategy,
        &success.signal,
        &success.observation,
        advisory.probe_history_disposition,
        advisory.probe_history_reason_code,
        RuntimeEndpoint {
            target: target_host,
            port: target_port,
        },
        DirectSessionSuccessMetrics {
            latency_ms: success.latency_ms,
            bytes_sent,
            retry_attempts_used,
        },
    );
    tracing::info!(
        event_code = RuntimeEventCode::DirectSessionSucceeded.as_str(),
        strategy = event.trace.strategy.as_str(),
        target = %target_host,
        port = target_port,
        signal = event.trace.signal.as_str(),
        probe_outcome_class = event.trace.probe_outcome_class,
        observation_contract = event.trace.observation_contract,
        observation_capture_confidence = event.trace.observation_capture_confidence,
        probe_history_disposition = event.trace.probe_history_disposition,
        probe_history_reason_code = event.trace.probe_history_reason_code,
        capture_status = event.trace.capture_status.as_str(),
        reference_path_hops = event.trace.reference_path_hops,
        rst_path_hops = event.trace.rst_path_hops,
        server_hint = ?event.trace.server_hint,
        fingerprint_window_hint = ?event.trace.fingerprint_window_hint,
        first_response_bytes = event.trace.first_response_bytes,
        relay_client_to_remote_bytes = event.trace.relay_client_to_remote_bytes,
        relay_remote_to_client_bytes = event.trace.relay_remote_to_client_bytes,
        relay_lifetime_ms = event.trace.relay_lifetime_ms,
        latency_ms = event.trace.latency_ms,
        bytes_sent = event.trace.bytes_sent,
        active_stall_probe_retry_attempted = event.trace.active_stall_probe_retry_attempted,
        retry_attempts_used = event.trace.retry_attempts_used,
        "{}",
        event.message
    );
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::DirectSessionSucceeded,
        event.message,
        {
            let mut fields = event.runtime_fields;
            add_cross_session_metric_fields(&mut fields, advisory);
            add_mimicry_capability_fields(
                &mut fields,
                Some(&success.observation),
                MimicryCapabilitySignalOrigin::LiveRuntimeObservation,
                stack,
                wire_mode,
                dst,
            );
            fields
        },
    );
}

async fn execute_active_stall_probe(
    launch: ActiveStallProbeLaunch,
) -> executor::ActiveStallProbeResult {
    let result = executor::run_active_stall_probe(
        launch.dst,
        launch.buf.clone(),
        executor::ActiveStallProbeRun {
            timeout_limit: launch.timeout_limit,
            is_tls: launch.is_tls,
            freeze_threshold_bytes: launch.freeze_threshold_bytes,
            degraded_latency_ms: launch.degraded_latency_ms,
            stack: launch.stack,
            wire_mode: launch.wire_mode,
            mimicry_ttl_hint: launch.mimicry_ttl_hint,
            wire_window_preface: launch.wire_window_preface,
            wire_observation_capture_confidence: launch.wire_observation_capture_confidence,
            wire_window_profile: launch.wire_window_profile,
            wire_observed_ipv4_header_shaping: launch.wire_observed_ipv4_header_shaping,
            wire_observed_negotiated_options: launch.wire_observed_negotiated_options,
            wire_observed_fragment_choreography: launch.wire_observed_fragment_choreography,
            active_probe_plan: launch.active_probe_plan.clone(),
        },
    )
    .await;
    launch
        .brain
        .record_probe_result(
            &launch.key,
            result.signal.clone(),
            Some(result.latency_ms),
            result.observation.clone(),
        )
        .await;
    emit_active_stall_probe_finished(&launch, &result);
    result
}

fn launch_active_stall_probe_if_needed(
    err: &executor::DirectExecutionError,
    launch: ActiveStallProbeLaunch,
) {
    if !should_run_active_stall_probe(err, &launch) {
        return;
    }
    emit_active_stall_probe_launched(err, &launch);
    tokio::spawn(async move {
        let _ = execute_active_stall_probe(launch).await;
    });
}

async fn run_active_stall_probe_inline_if_needed(
    err: &executor::DirectExecutionError,
    launch: ActiveStallProbeLaunch,
) -> Option<executor::ActiveStallProbeResult> {
    if !should_run_active_stall_probe(err, &launch) {
        return None;
    }
    emit_active_stall_probe_launched(err, &launch);
    Some(execute_active_stall_probe(launch).await)
}

fn active_probe_cycle_decision(
    probe_result: &executor::ActiveStallProbeResult,
    advisory: &aegis_core::DirectSessionAdvisory,
) -> ActiveProbeCycleDecision {
    if matches!(
        advisory.probe_history_disposition,
        ProbeHistoryDisposition::PreferRelay
    ) {
        return ActiveProbeCycleDecision::FallBackToRelay(
            ActiveStallProbeRetrySuppressedReasonCode::AdvisoryPreferRelay,
        );
    }
    if !probe_result.signal.is_success() {
        return ActiveProbeCycleDecision::FallBackToRelay(
            ActiveStallProbeRetrySuppressedReasonCode::ProbeSignalNotSuccessful,
        );
    }
    let capability = planner::build_mimicry_capability_plan(Some(&probe_result.observation));
    if matches!(
        capability.observation_capture_confidence,
        "runtime_only" | "explicit_absence"
    ) {
        // A successful probe without capture-backed confidence is still useful
        // to publish, but it should not reopen another direct retry path.
        return ActiveProbeCycleDecision::FallBackToRelay(
            ActiveStallProbeRetrySuppressedReasonCode::ProbeObservationNotCaptureBacked,
        );
    }
    ActiveProbeCycleDecision::RetryDirect
}

fn emit_active_stall_probe_retry_selected(
    result: &executor::ActiveStallProbeResult,
    advisory: &aegis_core::DirectSessionAdvisory,
    stack: Option<StackProfileId>,
    wire_mode: WireMimicryMode,
    dst: SocketAddr,
    target_host: &str,
    target_port: u16,
) {
    let event = advisory.active_stall_probe_retry_event_data(
        RuntimeEndpoint {
            target: target_host,
            port: target_port,
        },
        &result.signal,
        ActiveStallProbePlanContext {
            preferred_ttl: result.planned_probe_preferred_ttl,
            budget: result.planned_probe_budget,
            ttl_candidates: &result.planned_probe_ttl_candidates,
        },
        result.terminal_stage,
    );
    tracing::info!(
        event_code = RuntimeEventCode::DirectActiveStallProbeRetrySelected.as_str(),
        target = %target_host,
        port = target_port,
        signal = event.trace.signal.as_str(),
        probe_outcome_class = event.trace.probe_outcome_class,
        observation_contract = event.trace.observation_contract,
        probe_history_disposition = event.trace.probe_history_disposition,
        probe_history_reason_code = event.trace.probe_history_reason_code,
        planned_probe_preferred_ttl = event.trace.planned_probe_preferred_ttl,
        planned_probe_budget = event.trace.planned_probe_budget,
        planned_probe_ttl_candidates = ?event.trace.planned_probe_ttl_candidates,
        probe_terminal_stage = ?event.trace.probe_terminal_stage,
        "{}",
        event.message
    );
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::DirectActiveStallProbeRetrySelected,
        event.message,
        {
            let mut fields = event.runtime_fields;
            add_cross_session_metric_fields(&mut fields, advisory);
            add_mimicry_capability_fields(
                &mut fields,
                Some(&result.observation),
                MimicryCapabilitySignalOrigin::LiveActiveProbeObservation,
                stack,
                wire_mode,
                dst,
            );
            fields
        },
    );
}

#[allow(clippy::too_many_arguments)]
fn emit_direct_relay_failover_triggered(
    err: &executor::DirectExecutionError,
    advisory: &aegis_core::DirectSessionAdvisory,
    stack: Option<StackProfileId>,
    wire_mode: WireMimicryMode,
    dst: SocketAddr,
    target_host: &str,
    target_port: u16,
    reason_code: DirectRelayFailoverReasonCode,
    active_stall_probe_retry_attempted: bool,
    probe_terminal_stage: Option<&'static str>,
) {
    let event = direct_relay_failover_event_data(
        &err.signal,
        err.observation_contract,
        err.observation_capture_confidence,
        reason_code,
        ObservationPathContext {
            reference_path_hops: err.reference_path_hops,
            rst_path_hops: err.rst_path_hops,
        },
        ActiveStallProbeFailoverContext {
            recommended: err.recommends_active_stall_probe(),
            retry_attempted: active_stall_probe_retry_attempted,
            terminal_stage: probe_terminal_stage,
        },
        RuntimeEndpoint {
            target: target_host,
            port: target_port,
        },
    );
    tracing::info!(
        event_code = RuntimeEventCode::DirectRelayFailoverTriggered.as_str(),
        signal = event.trace.signal.as_str(),
        probe_outcome_class = event.trace.probe_outcome_class,
        observation_contract = event.trace.observation_contract,
        observation_capture_confidence = event.trace.observation_capture_confidence,
        probe_history_disposition = advisory.probe_history_disposition.as_str(),
        probe_history_reason_code = advisory.probe_history_reason_code.as_str(),
        direct_relay_failover_reason_code = event.trace.direct_relay_failover_reason_code,
        reference_path_hops = event.trace.reference_path_hops,
        rst_path_hops = event.trace.rst_path_hops,
        active_stall_probe_recommended = event.trace.active_stall_probe_recommended,
        active_stall_probe_retry_attempted = event.trace.active_stall_probe_retry_attempted,
        probe_terminal_stage = ?event.trace.probe_terminal_stage,
        target = %target_host,
        port = target_port,
        "{}",
        event.message
    );
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::DirectRelayFailoverTriggered,
        event.message,
        {
            let mut fields = event.runtime_fields;
            // Keep terminal failover events self-contained so replay-safe automation
            // can see both the live failure and the advisory state behind it.
            add_probe_history_fields(&mut fields, advisory);
            add_cross_session_metric_fields(&mut fields, advisory);
            add_mimicry_capability_fields(
                &mut fields,
                Some(&err.observation),
                MimicryCapabilitySignalOrigin::LiveRuntimeObservation,
                stack,
                wire_mode,
                dst,
            );
            fields
        },
    );
}

#[allow(clippy::too_many_arguments)]
fn emit_active_stall_probe_retry_budget_exhausted(
    err: &executor::DirectExecutionError,
    advisory: &aegis_core::DirectSessionAdvisory,
    stack: Option<StackProfileId>,
    wire_mode: WireMimicryMode,
    dst: SocketAddr,
    target_host: &str,
    target_port: u16,
    retry_attempts_used: usize,
    probe_terminal_stage: Option<&'static str>,
) {
    let event = active_stall_probe_retry_budget_exhausted_event_data(
        &err.signal,
        err.observation_contract,
        err.observation_capture_confidence,
        ObservationPathContext {
            reference_path_hops: err.reference_path_hops,
            rst_path_hops: err.rst_path_hops,
        },
        RetryBudgetContext {
            attempts_used: retry_attempts_used,
            attempts_budget: MAX_INLINE_PROBE_RETRIES_PER_SESSION,
        },
        probe_terminal_stage,
        RuntimeEndpoint {
            target: target_host,
            port: target_port,
        },
    );
    tracing::info!(
        event_code = RuntimeEventCode::DirectActiveStallProbeRetryBudgetExhausted.as_str(),
        signal = event.trace.signal.as_str(),
        probe_outcome_class = event.trace.probe_outcome_class,
        observation_contract = event.trace.observation_contract,
        observation_capture_confidence = event.trace.observation_capture_confidence,
        probe_history_disposition = advisory.probe_history_disposition.as_str(),
        probe_history_reason_code = advisory.probe_history_reason_code.as_str(),
        reference_path_hops = event.trace.reference_path_hops,
        rst_path_hops = event.trace.rst_path_hops,
        retry_attempts_used = event.trace.retry_attempts_used,
        retry_attempts_budget = event.trace.retry_attempts_budget,
        probe_terminal_stage = ?event.trace.probe_terminal_stage,
        target = %target_host,
        port = target_port,
        "{}",
        event.message
    );
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::DirectActiveStallProbeRetryBudgetExhausted,
        event.message,
        {
            let mut fields = event.runtime_fields;
            // Retry-budget exhaustion is still a planner/runtime boundary, so retain
            // advisory-derived scores and reason codes on the terminal record itself.
            add_probe_history_fields(&mut fields, advisory);
            add_cross_session_metric_fields(&mut fields, advisory);
            add_mimicry_capability_fields(
                &mut fields,
                Some(&err.observation),
                MimicryCapabilitySignalOrigin::LiveRuntimeObservation,
                stack,
                wire_mode,
                dst,
            );
            fields
        },
    );
}

#[allow(clippy::too_many_arguments)]
fn emit_active_stall_probe_retry_skipped(
    result: &executor::ActiveStallProbeResult,
    advisory: &aegis_core::DirectSessionAdvisory,
    stack: Option<StackProfileId>,
    wire_mode: WireMimicryMode,
    dst: SocketAddr,
    target_host: &str,
    target_port: u16,
    reason_code: ActiveStallProbeRetrySuppressedReasonCode,
    retry_attempts_used: usize,
) {
    let event = advisory.active_stall_probe_retry_skipped_event_data(
        RuntimeEndpoint {
            target: target_host,
            port: target_port,
        },
        &result.signal,
        reason_code,
        RetryBudgetContext {
            attempts_used: retry_attempts_used,
            attempts_budget: MAX_INLINE_PROBE_RETRIES_PER_SESSION,
        },
        result.terminal_stage,
    );
    tracing::info!(
        event_code = RuntimeEventCode::DirectActiveStallProbeRetrySkipped.as_str(),
        signal = event.trace.signal.as_str(),
        probe_outcome_class = event.trace.probe_outcome_class,
        observation_contract = event.trace.observation_contract,
        probe_history_disposition = event.trace.probe_history_disposition,
        probe_history_reason_code = event.trace.probe_history_reason_code,
        retry_suppressed_reason_code = event.trace.retry_suppressed_reason_code,
        retry_attempts_used = event.trace.retry_attempts_used,
        retry_attempts_budget = event.trace.retry_attempts_budget,
        probe_terminal_stage = ?event.trace.probe_terminal_stage,
        target = %target_host,
        port = target_port,
        "{}",
        event.message
    );
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::DirectActiveStallProbeRetrySkipped,
        event.message,
        {
            let mut fields = event.runtime_fields;
            add_cross_session_metric_fields(&mut fields, advisory);
            add_mimicry_capability_fields(
                &mut fields,
                Some(&result.observation),
                MimicryCapabilitySignalOrigin::LiveActiveProbeObservation,
                stack,
                wire_mode,
                dst,
            );
            fields
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::brain::DecisionContext;
    use aegis_core::signals::classify::FailSignal;
    use aegis_core::AsyncStateStore;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::net::TcpListener;
    use tokio::time::{timeout, Duration};

    #[test]
    fn auto_policy_hands_planning_terminals_to_a_ready_relay() {
        for reason in [
            DirectTerminalReason::NoExecutableStrategy,
            DirectTerminalReason::UnsupportedAddressFamily,
            DirectTerminalReason::MissingRawCapability,
        ] {
            assert_eq!(
                direct_terminal_action(DirectTerminalPolicy::RelayOrFailClosed, reason, true, true,),
                Some(TerminalFailureAction::RelayGrpc)
            );
            assert!(direct_terminal_failover_reason(reason).is_some());
        }
    }

    #[test]
    fn auto_policy_blocks_when_planning_terminal_has_no_ready_relay() {
        assert_eq!(
            direct_terminal_action(
                DirectTerminalPolicy::RelayOrFailClosed,
                DirectTerminalReason::MissingRawCapability,
                true,
                false,
            ),
            Some(TerminalFailureAction::Block)
        );
    }

    #[test]
    fn direct_policy_preserves_existing_planning_terminal_behavior() {
        assert_eq!(
            direct_terminal_action(
                DirectTerminalPolicy::PreserveDirectFailure,
                DirectTerminalReason::NoExecutableStrategy,
                true,
                true,
            ),
            None
        );
        assert_eq!(
            direct_terminal_action(
                DirectTerminalPolicy::RelayOrFailClosed,
                DirectTerminalReason::StrategiesExhausted,
                true,
                true,
            ),
            None
        );
        assert_eq!(
            direct_terminal_action(
                DirectTerminalPolicy::HybridRelayOrFailClosed,
                DirectTerminalReason::StrategiesExhausted,
                true,
                true,
            ),
            Some(TerminalFailureAction::RelayGrpc)
        );
        assert_eq!(
            direct_terminal_action(
                DirectTerminalPolicy::HybridRelayOrFailClosed,
                DirectTerminalReason::StrategiesExhausted,
                true,
                false,
            ),
            Some(TerminalFailureAction::Block)
        );
        assert_eq!(
            direct_terminal_failover_reason(DirectTerminalReason::StrategiesExhausted),
            Some(DirectRelayFailoverReasonCode::StrategiesExhausted)
        );
        assert_eq!(
            direct_terminal_action(
                DirectTerminalPolicy::RelayOrFailClosed,
                DirectTerminalReason::ClassifiedDirectFailure,
                false,
                true,
            ),
            None
        );
        for reason in [
            DirectTerminalReason::StrategiesExhausted,
            DirectTerminalReason::ClassifiedDirectFailure,
        ] {
            assert_eq!(
                direct_terminal_action(
                    DirectTerminalPolicy::HybridRelayOrFailClosed,
                    reason,
                    false,
                    true,
                ),
                Some(TerminalFailureAction::Block),
                "an ambiguous post-send terminal must not replay application data"
            );
        }
    }

    #[test]
    fn hybrid_runtime_event_schema_is_complete_and_payload_free() {
        let key = StrategyKey::for_target(
            "203.0.113.81:443".parse().expect("dst"),
            "event-schema.example",
            443,
            Some("event-schema.example"),
            true,
        );
        let context = HybridRuntimeContext {
            brain: Arc::new(Brain::new(
                0.0,
                vec!["geneva".into()],
                aegis_core::AsyncStateStore::ephemeral(),
            )),
            key,
            strategy_fingerprint: "0123456789abcdef01234567".into(),
            address_family: "ipv4",
            route_reason_code: "cold_start_exploration",
            evidence_confidence: "none",
            raw_capabilities: RawCapabilities {
                ipv4_raw_send: true,
                ipv4_packet_capture: true,
                tcp_repair_query: true,
                ipv4_header_control: true,
                ipv4_fragmentation: true,
            },
        };

        let fields = hybrid_event_fields(&context, HybridRouteFamily::DirectGeneva);
        assert_eq!(fields["route_family"], "direct_geneva");
        assert_eq!(fields["reason_code"], "cold_start_exploration");
        assert_eq!(fields["strategy_fingerprint"], context.strategy_fingerprint);
        assert_eq!(fields["address_family"], "ipv4");
        assert_eq!(fields["evidence_confidence"], "none");
        assert_eq!(fields["capability_summary"]["ipv4_raw_send"], true);
        let encoded = serde_json::to_string(&fields).expect("event fields");
        for forbidden in ["auth_token", "request_payload", "full_url"] {
            assert!(!encoded.contains(forbidden));
        }
    }

    #[test]
    fn surface_bias_from_advisory_neutral_for_none_disposition() {
        let advisory = aegis_core::DirectSessionAdvisory {
            probe_history_disposition: aegis_core::ProbeHistoryDisposition::None,
            probe_history_reason_code: aegis_core::ProbeHistoryReasonCode::NoRecentProbeHistory,
            latest_observation: None,
            latest_probe_stats: None,
            observation_contract: aegis_core::ObservationContract::ExplicitAbsence,
            cross_session_signal_metrics: Default::default(),
        };
        let bias = surface_bias_from_advisory(&advisory);
        assert!(bias.is_neutral());
    }

    #[test]
    fn surface_bias_from_advisory_prefer_relay_biases_low_latency_and_jitter() {
        let advisory = aegis_core::DirectSessionAdvisory {
            probe_history_disposition: aegis_core::ProbeHistoryDisposition::PreferRelay,
            probe_history_reason_code: aegis_core::ProbeHistoryReasonCode::RepeatedStallPreferRelay,
            latest_observation: None,
            latest_probe_stats: None,
            observation_contract: aegis_core::ObservationContract::ExplicitAbsence,
            cross_session_signal_metrics: Default::default(),
        };
        let bias = surface_bias_from_advisory(&advisory);
        assert!(!bias.is_neutral());
        assert!(bias.low_latency_preferred > 0.0);
        assert!(bias.high_jitter_preferred > 0.0);
        // PreferRelay does not signal visibility concerns by itself.
        assert_eq!(bias.low_visibility_preferred, 0.0);
    }

    #[test]
    fn surface_bias_from_advisory_bias_probe_branch_nudges_jitter_only() {
        let advisory = aegis_core::DirectSessionAdvisory {
            probe_history_disposition: aegis_core::ProbeHistoryDisposition::BiasProbeBranch,
            probe_history_reason_code:
                aegis_core::ProbeHistoryReasonCode::SingleStallBiasProbeBranch,
            latest_observation: None,
            latest_probe_stats: None,
            observation_contract: aegis_core::ObservationContract::ExplicitAbsence,
            cross_session_signal_metrics: Default::default(),
        };
        let bias = surface_bias_from_advisory(&advisory);
        assert!(!bias.is_neutral());
        assert_eq!(bias.low_latency_preferred, 0.0);
        assert!(bias.high_jitter_preferred > 0.0);
        assert_eq!(bias.low_visibility_preferred, 0.0);
    }

    #[test]
    fn surface_bias_from_advisory_high_stall_severity_lifts_low_latency_and_jitter() {
        // Phase 5 Phase 3: stall_severity (cross-session metric) > 0.5
        // adds to low_latency_preferred + high_jitter_preferred.
        let metrics = aegis_core::CrossSessionSignalMetrics {
            stall_severity: 0.9,
            confidence_score: 1.0, // disable stale-decay
            ..Default::default()
        };
        let advisory = aegis_core::DirectSessionAdvisory {
            probe_history_disposition: aegis_core::ProbeHistoryDisposition::None,
            probe_history_reason_code: aegis_core::ProbeHistoryReasonCode::NoRecentProbeHistory,
            latest_observation: None,
            latest_probe_stats: None,
            observation_contract: aegis_core::ObservationContract::DeepObserved,
            cross_session_signal_metrics: metrics,
        };
        let bias = surface_bias_from_advisory(&advisory);
        assert!(
            !bias.is_neutral(),
            "high stall_severity must produce non-neutral bias"
        );
        assert!(
            bias.low_latency_preferred > 0.0,
            "stall_severity should contribute to low_latency_preferred",
        );
        assert!(
            bias.high_jitter_preferred > 0.0,
            "stall_severity should contribute to high_jitter_preferred",
        );
    }

    #[test]
    fn surface_bias_from_advisory_high_relay_preference_lifts_low_visibility() {
        // Phase 5 Phase 3: relay_preference_score > 0.5 adds to
        // low_visibility_preferred (favor small-payload-shaped families).
        let metrics = aegis_core::CrossSessionSignalMetrics {
            relay_preference_score: 0.9,
            confidence_score: 1.0,
            ..Default::default()
        };
        let advisory = aegis_core::DirectSessionAdvisory {
            probe_history_disposition: aegis_core::ProbeHistoryDisposition::None,
            probe_history_reason_code: aegis_core::ProbeHistoryReasonCode::NoRecentProbeHistory,
            latest_observation: None,
            latest_probe_stats: None,
            observation_contract: aegis_core::ObservationContract::DeepObserved,
            cross_session_signal_metrics: metrics,
        };
        let bias = surface_bias_from_advisory(&advisory);
        assert!(
            bias.low_visibility_preferred > 0.0,
            "relay_preference_score should contribute to low_visibility_preferred",
        );
    }

    #[test]
    fn surface_bias_from_advisory_low_confidence_decays_weights() {
        // Phase 5 Phase 3: low confidence_score halves all weights so we
        // do not over-bias on flimsy evidence.
        let metrics_high = aegis_core::CrossSessionSignalMetrics {
            stall_severity: 0.9,
            confidence_score: 1.0,
            ..Default::default()
        };
        let advisory_high = aegis_core::DirectSessionAdvisory {
            probe_history_disposition: aegis_core::ProbeHistoryDisposition::PreferRelay,
            probe_history_reason_code: aegis_core::ProbeHistoryReasonCode::RepeatedStallPreferRelay,
            latest_observation: None,
            latest_probe_stats: None,
            observation_contract: aegis_core::ObservationContract::DeepObserved,
            cross_session_signal_metrics: metrics_high,
        };
        let metrics_low = aegis_core::CrossSessionSignalMetrics {
            stall_severity: 0.9,
            confidence_score: 0.0,
            ..Default::default()
        };
        let advisory_low = aegis_core::DirectSessionAdvisory {
            probe_history_disposition: aegis_core::ProbeHistoryDisposition::PreferRelay,
            probe_history_reason_code: aegis_core::ProbeHistoryReasonCode::RepeatedStallPreferRelay,
            latest_observation: None,
            latest_probe_stats: None,
            observation_contract: aegis_core::ObservationContract::DeepObserved,
            cross_session_signal_metrics: metrics_low,
        };
        let bias_high = surface_bias_from_advisory(&advisory_high);
        let bias_low = surface_bias_from_advisory(&advisory_low);
        // The low-confidence bias should be strictly smaller on every
        // axis where the high-confidence bias was non-zero.
        assert!(
            bias_low.low_latency_preferred < bias_high.low_latency_preferred,
            "stale calibration must decay low_latency_preferred",
        );
        assert!(
            bias_low.high_jitter_preferred < bias_high.high_jitter_preferred,
            "stale calibration must decay high_jitter_preferred",
        );
    }

    #[test]
    fn surface_bias_from_advisory_thin_observation_contract_decays_further() {
        // Phase 5 Phase 3: ExplicitAbsence / RuntimeOnly observation
        // contracts apply an additional 0.8x decay.
        let metrics = aegis_core::CrossSessionSignalMetrics {
            confidence_score: 1.0,
            ..Default::default()
        };
        let advisory_deep = aegis_core::DirectSessionAdvisory {
            probe_history_disposition: aegis_core::ProbeHistoryDisposition::PreferRelay,
            probe_history_reason_code: aegis_core::ProbeHistoryReasonCode::RepeatedStallPreferRelay,
            latest_observation: None,
            latest_probe_stats: None,
            observation_contract: aegis_core::ObservationContract::DeepObserved,
            cross_session_signal_metrics: metrics,
        };
        let advisory_thin = aegis_core::DirectSessionAdvisory {
            probe_history_disposition: aegis_core::ProbeHistoryDisposition::PreferRelay,
            probe_history_reason_code: aegis_core::ProbeHistoryReasonCode::RepeatedStallPreferRelay,
            latest_observation: None,
            latest_probe_stats: None,
            observation_contract: aegis_core::ObservationContract::RuntimeOnly,
            cross_session_signal_metrics: metrics,
        };
        let bias_deep = surface_bias_from_advisory(&advisory_deep);
        let bias_thin = surface_bias_from_advisory(&advisory_thin);
        assert!(
            bias_thin.low_latency_preferred < bias_deep.low_latency_preferred,
            "thin observation contract must decay low_latency_preferred",
        );
    }

    fn test_decision_context() -> DecisionContext {
        DecisionContext {
            platform: "test".to_string(),
            target_class: "webtls".to_string(),
            network_profile: "public".to_string(),
            region_id: Some("lab".to_string()),
            recent_failures: 0,
        }
    }

    async fn test_brain() -> Arc<Brain> {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("aegis-direct-test-{unique}"));
        fs::create_dir_all(&dir).expect("create temp state dir");
        let store = AsyncStateStore::load(dir.join("state.json"))
            .await
            .expect("load state store");
        let brain = Arc::new(Brain::new(
            0.0,
            vec!["passthrough".into(), "ttl_desync".into()],
            store,
        ));
        fs::remove_dir_all(&dir).ok();
        brain
    }

    async fn tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let client = TcpStream::connect(addr).await.expect("connect client");
        let (server, _) = listener.accept().await.expect("accept server");
        (client, server)
    }

    fn sample_observation() -> aegis_core::KeyObservation {
        aegis_core::KeyObservation {
            matched_packets: 2,
            capture_status: aegis_core::PacketCaptureStatus::Active,
            capture_backend: Some(aegis_core::PacketCaptureBackendKind::LinuxAfPacket),
            capture_filter_applied: true,
            capture_wait_cycles: 1,
            syn_ack_ttl: Some(52),
            syn_ack_window: Some(64240),
            syn_ack_mss: Some(1460),
            syn_ack_window_scale: Some(8),
            syn_ack_sack_permitted: Some(true),
            syn_ack_timestamp_option: Some(true),
            first_data_ttl: Some(58),
            first_data_window: Some(65535),
            first_data_payload_len: Some(41),
            first_packet_ttl: Some(52),
            first_packet_ip_tos: Some(0x10),
            first_packet_ip_id: Some(0x1234),
            first_packet_ip_df: Some(true),
            first_data_server_hint: Some(aegis_core::ServerType::LikelyCdn),
            ..Default::default()
        }
    }

    fn runtime_only_observation() -> aegis_core::KeyObservation {
        aegis_core::KeyObservation {
            syn_ack_ttl: Some(58),
            syn_ack_window: Some(65535),
            syn_ack_server_hint: Some(aegis_core::ServerType::LikelyCdn),
            ..Default::default()
        }
    }

    fn explicit_absence_observation() -> aegis_core::KeyObservation {
        aegis_core::KeyObservation {
            capture_status: aegis_core::PacketCaptureStatus::UnsupportedPlatform,
            ..Default::default()
        }
    }

    fn sample_probe_result(
        signal: FailSignal,
        observation: aegis_core::KeyObservation,
    ) -> executor::ActiveStallProbeResult {
        executor::ActiveStallProbeResult {
            signal,
            observation,
            latency_ms: 10,
            planned_probe_preferred_ttl: 1,
            planned_probe_budget: 2,
            planned_probe_ttl_candidates: vec![1, 3],
            first_response_bytes: 128,
            terminal_stage: Some("active_probe_connect_remote"),
        }
    }

    fn sample_advisory() -> aegis_core::DirectSessionAdvisory {
        aegis_core::DirectSessionAdvisory {
            latest_observation: Some(sample_observation()),
            latest_probe_stats: Some(aegis_core::StallProbeStats {
                trials: 1,
                collapses: 1,
                consecutive_stall_failures: 1,
                last_signal: Some(FailSignal::ThroughputCollapse),
                ..Default::default()
            }),
            observation_contract: aegis_core::ObservationContract::DeepObserved,
            probe_history_disposition: ProbeHistoryDisposition::BiasProbeBranch,
            probe_history_reason_code:
                aegis_core::ProbeHistoryReasonCode::SingleStallBiasProbeBranch,
            cross_session_signal_metrics: aegis_core::CrossSessionSignalMetrics {
                confidence_score: 0.72,
                reuse_weight: 0.61,
                stall_severity: 0.37,
                probe_branch_score: 0.19,
                relay_preference_score: 0.0,
            },
        }
    }

    #[test]
    fn advisory_reorders_only_when_ladder_is_expanded() {
        let advisory = aegis_core::DirectSessionAdvisory {
            latest_observation: None,
            latest_probe_stats: None,
            observation_contract: aegis_core::ObservationContract::RuntimeOnly,
            probe_history_disposition: ProbeHistoryDisposition::BiasProbeBranch,
            probe_history_reason_code:
                aegis_core::ProbeHistoryReasonCode::SingleStallBiasProbeBranch,
            cross_session_signal_metrics: aegis_core::CrossSessionSignalMetrics::default(),
        };
        let ordered = vec!["passthrough".into(), "ttl_desync".into(), "overlap".into()];
        let unchanged = advisory.apply_to_direct_order(ordered.clone(), false);
        assert_eq!(unchanged, ordered);
    }

    #[test]
    fn active_probe_cycle_retries_direct_after_successful_probe() {
        let advisory = aegis_core::DirectSessionAdvisory {
            latest_observation: None,
            latest_probe_stats: None,
            observation_contract: aegis_core::ObservationContract::RuntimeOnly,
            probe_history_disposition: ProbeHistoryDisposition::None,
            probe_history_reason_code: aegis_core::ProbeHistoryReasonCode::NoRecentProbeHistory,
            cross_session_signal_metrics: aegis_core::CrossSessionSignalMetrics::default(),
        };
        assert_eq!(
            active_probe_cycle_decision(
                &sample_probe_result(FailSignal::Success, sample_observation()),
                &advisory
            ),
            ActiveProbeCycleDecision::RetryDirect
        );
    }

    #[test]
    fn active_probe_cycle_prefers_relay_after_repeated_stall_history() {
        let advisory = aegis_core::DirectSessionAdvisory {
            latest_observation: None,
            latest_probe_stats: None,
            observation_contract: aegis_core::ObservationContract::RuntimeOnly,
            probe_history_disposition: ProbeHistoryDisposition::PreferRelay,
            probe_history_reason_code: aegis_core::ProbeHistoryReasonCode::RepeatedStallPreferRelay,
            cross_session_signal_metrics: aegis_core::CrossSessionSignalMetrics::default(),
        };
        assert_eq!(
            active_probe_cycle_decision(
                &sample_probe_result(FailSignal::Success, sample_observation()),
                &advisory
            ),
            ActiveProbeCycleDecision::FallBackToRelay(
                ActiveStallProbeRetrySuppressedReasonCode::AdvisoryPreferRelay
            )
        );
    }

    #[test]
    fn active_probe_cycle_falls_back_when_probe_does_not_succeed() {
        let advisory = aegis_core::DirectSessionAdvisory {
            latest_observation: None,
            latest_probe_stats: None,
            observation_contract: aegis_core::ObservationContract::RuntimeOnly,
            probe_history_disposition: ProbeHistoryDisposition::None,
            probe_history_reason_code: aegis_core::ProbeHistoryReasonCode::NoRecentProbeHistory,
            cross_session_signal_metrics: aegis_core::CrossSessionSignalMetrics::default(),
        };
        assert_eq!(
            active_probe_cycle_decision(
                &sample_probe_result(FailSignal::ThroughputCollapse, sample_observation()),
                &advisory
            ),
            ActiveProbeCycleDecision::FallBackToRelay(
                ActiveStallProbeRetrySuppressedReasonCode::ProbeSignalNotSuccessful
            )
        );
    }

    #[test]
    fn active_probe_cycle_skips_retry_without_capture_backed_probe_observation() {
        let advisory = aegis_core::DirectSessionAdvisory {
            latest_observation: None,
            latest_probe_stats: None,
            observation_contract: aegis_core::ObservationContract::RuntimeOnly,
            probe_history_disposition: ProbeHistoryDisposition::None,
            probe_history_reason_code: aegis_core::ProbeHistoryReasonCode::NoRecentProbeHistory,
            cross_session_signal_metrics: aegis_core::CrossSessionSignalMetrics::default(),
        };
        assert_eq!(
            active_probe_cycle_decision(
                &sample_probe_result(FailSignal::Success, runtime_only_observation()),
                &advisory
            ),
            ActiveProbeCycleDecision::FallBackToRelay(
                ActiveStallProbeRetrySuppressedReasonCode::ProbeObservationNotCaptureBacked
            )
        );
    }

    #[test]
    fn inline_probe_retry_budget_is_strictly_bounded() {
        assert!(inline_probe_retry_budget_remaining(0));
        assert!(inline_probe_retry_budget_remaining(1));
        assert!(!inline_probe_retry_budget_remaining(2));
        assert!(!inline_probe_retry_budget_remaining(3));
    }

    #[test]
    fn helper_adds_mimicry_capability_fields_from_observation() {
        let mut fields = serde_json::json!({});
        add_mimicry_capability_fields(
            &mut fields,
            Some(&sample_observation()),
            MimicryCapabilitySignalOrigin::LiveRuntimeObservation,
            Some(StackProfileId::LinuxDesktop),
            WireMimicryMode::Disabled,
            "127.0.0.1:443".parse().expect("test dst"),
        );
        assert_eq!(
            fields["mimicry_capability_signal_origin"],
            "live_runtime_observation"
        );
        assert_eq!(
            fields["mimicry_capability_stage"],
            "early_pre_wire_capability_layer"
        );
        assert_eq!(
            fields["mimicry_capability_readiness"],
            "composite_signal_ready"
        );
        assert_eq!(
            fields["mimicry_capability_observation_capture_confidence"],
            "deep_observed"
        );
        assert_eq!(
            fields["mimicry_capability_wire_stage"],
            "architecture_scaffold_only"
        );
        assert_eq!(
            fields["mimicry_capability_wire_scope"],
            "future_packet_wire_linux_only"
        );
        assert_eq!(
            fields["mimicry_capability_wire_validation_strategy"],
            "capture_replay_plus_privileged_host_acceptance"
        );
        assert_eq!(fields["mimicry_capability_wire_linux_only"], true);
        assert_eq!(
            fields["mimicry_capability_wire_requires_raw_capabilities"],
            true
        );
        assert_eq!(
            fields["mimicry_capability_wire_packet_profile_synthesis"],
            "capture_backed_ttl_path_window_ipv4_header_plus_observed_tcp_option_inputs_with_profile_fallback"
        );
        assert_eq!(
            fields["mimicry_capability_wire_policy_boundary"],
            "best_effort_ipv4_ttl_window_and_negotiated_options_preface_before_strategy_send_first"
        );
        assert_eq!(
            fields["mimicry_capability_wire_validation_artifact"],
            "wire_mimicry_validation_contract_v1"
        );
        assert_eq!(
            fields["mimicry_capability_wire_host_acceptance_contour"],
            "privileged_linux_wire_mimicry_acceptance"
        );
        assert_eq!(
            fields["mimicry_capability_wire_experimental_config_path"],
            "direct.wire_mimicry_mode=linux_experimental_ttl_preface"
        );
        assert_eq!(fields["mimicry_capability_wire_config_mode"], "disabled");
        assert_eq!(fields["mimicry_capability_wire_requested"], false);
        assert_eq!(fields["mimicry_capability_wire_active"], false);
        assert_eq!(
            fields["mimicry_capability_wire_activation_reason"],
            "config_disabled"
        );
        assert!(fields["mimicry_capability_wire_runtime_slice"].is_null());
        assert!(fields["mimicry_capability_wire_ttl_preface"].is_null());
        assert_eq!(fields["mimicry_capability_wire_window_preface_ready"], true);
        assert!(fields["mimicry_capability_wire_window_preface"].is_null());
        assert_eq!(
            fields["mimicry_capability_wire_options_preface_ready"],
            true
        );
        assert!(fields["mimicry_capability_wire_options_preface_profile"].is_null());
        assert!(fields["mimicry_capability_wire_options_preface_size"].is_null());
        assert_eq!(
            fields["mimicry_capability_wire_ipv4_header_shaping_ready"],
            true
        );
        assert_eq!(
            fields["mimicry_capability_wire_ipv4_header_shaping_observed_ready"],
            true
        );
        assert!(fields["mimicry_capability_wire_ipv4_header_shaping_profile"].is_null());
        assert!(fields["mimicry_capability_wire_ipv4_header_shaping_tos"].is_null());
        assert!(fields["mimicry_capability_wire_ipv4_header_shaping_ip_id"].is_null());
        assert!(fields["mimicry_capability_wire_ipv4_header_shaping_dont_fragment"].is_null());
        assert!(fields["mimicry_capability_wire_ipv4_header_shaping_source"].is_null());
        assert_eq!(
            fields["mimicry_capability_wire_negotiated_options_ready"],
            true
        );
        assert_eq!(
            fields["mimicry_capability_wire_negotiated_options_observed_ready"],
            true
        );
        assert!(fields["mimicry_capability_wire_negotiated_options_profile"].is_null());
        assert!(fields["mimicry_capability_wire_negotiated_options_size"].is_null());
        assert!(fields["mimicry_capability_wire_negotiated_options_mss"].is_null());
        assert!(fields["mimicry_capability_wire_negotiated_options_window_scale"].is_null());
        assert!(fields["mimicry_capability_wire_negotiated_options_sack_permitted"].is_null());
        assert!(fields["mimicry_capability_wire_negotiated_options_timestamp_mode"].is_null());
        assert!(fields["mimicry_capability_wire_negotiated_options_source"].is_null());
        assert_eq!(
            fields["mimicry_capability_wire_ipv4_fragmentation_ready"],
            false
        );
        assert_eq!(
            fields["mimicry_capability_wire_fragment_choreography_ready"],
            true
        );
        assert_eq!(
            fields["mimicry_capability_wire_fragment_choreography_observed_ready"],
            true
        );
        assert!(fields["mimicry_capability_wire_fragment_choreography_profile"].is_null());
        assert!(fields["mimicry_capability_wire_fragment_choreography_steps"].is_null());
        assert!(
            fields["mimicry_capability_wire_fragment_choreography_first_payload_len"].is_null()
        );
        assert!(
            fields["mimicry_capability_wire_fragment_choreography_disorder_split_at"].is_null()
        );
        assert!(fields["mimicry_capability_wire_fragment_choreography_overlap"].is_null());
        assert!(fields["mimicry_capability_wire_fragment_choreography_source"].is_null());
        assert_eq!(
            fields["mimicry_capability_userspace_scope"],
            "pre_connect_socket_only"
        );
        assert_eq!(
            fields["mimicry_capability_userspace_wiring_mode"],
            "profile_plus_capture_backed_ttl"
        );
        assert_eq!(
            fields["mimicry_capability_userspace_stack_profile"],
            "linux"
        );
        assert_eq!(fields["mimicry_capability_userspace_ttl_hint_ready"], true);
        assert_eq!(fields["mimicry_capability_userspace_nodelay_ready"], true);
        assert_eq!(fields["mimicry_capability_userspace_reuseaddr_ready"], true);
        assert_eq!(
            fields["mimicry_capability_userspace_send_buffer_ready"],
            true
        );
        assert_eq!(
            fields["mimicry_capability_userspace_recv_buffer_ready"],
            true
        );
        assert_eq!(fields["mimicry_capability_server_hint_ready"], true);
        assert_eq!(fields["mimicry_capability_window_profile_ready"], true);
        assert_eq!(fields["mimicry_capability_reference_path_ready"], true);
        assert_eq!(fields["mimicry_capability_rst_path_ready"], false);
        assert_eq!(fields["mimicry_capability_userspace_ttl_hint"], 60);
        assert_eq!(fields["mimicry_capability_userspace_nodelay"], false);
        assert_eq!(fields["mimicry_capability_userspace_reuseaddr"], true);
        assert_eq!(fields["mimicry_capability_userspace_send_buffer"], 196608);
        assert_eq!(fields["mimicry_capability_userspace_recv_buffer"], 196608);
        assert_eq!(fields["mimicry_capability_server_hint"], "likely_cdn");
        assert_eq!(fields["mimicry_capability_window_profile"], "huge");
        assert_eq!(fields["mimicry_capability_reference_path_hops"], 2);
        assert!(fields["mimicry_capability_rst_path_hops"].is_null());
    }

    #[test]
    fn helper_marks_advisory_mimicry_signal_origin_separately() {
        let mut fields = serde_json::json!({});
        add_mimicry_capability_fields(
            &mut fields,
            Some(&sample_observation()),
            MimicryCapabilitySignalOrigin::AdvisoryLatestObservation,
            None,
            WireMimicryMode::Disabled,
            "127.0.0.1:443".parse().expect("test dst"),
        );
        assert_eq!(
            fields["mimicry_capability_signal_origin"],
            "advisory_latest_observation"
        );
        assert_eq!(
            fields["mimicry_capability_userspace_wiring_mode"],
            "capture_backed_ttl_only"
        );
        assert!(fields["mimicry_capability_userspace_stack_profile"].is_null());
        assert_eq!(fields["mimicry_capability_userspace_nodelay_ready"], false);
        assert_eq!(
            fields["mimicry_capability_userspace_reuseaddr_ready"],
            false
        );
        assert_eq!(
            fields["mimicry_capability_userspace_send_buffer_ready"],
            false
        );
        assert_eq!(
            fields["mimicry_capability_userspace_recv_buffer_ready"],
            false
        );
        assert!(fields["mimicry_capability_userspace_nodelay"].is_null());
        assert!(fields["mimicry_capability_userspace_reuseaddr"].is_null());
        assert!(fields["mimicry_capability_userspace_send_buffer"].is_null());
        assert!(fields["mimicry_capability_userspace_recv_buffer"].is_null());
    }

    #[test]
    fn helper_keeps_runtime_only_mimicry_on_honest_baseline() {
        let mut fields = serde_json::json!({});
        add_mimicry_capability_fields(
            &mut fields,
            Some(&runtime_only_observation()),
            MimicryCapabilitySignalOrigin::LiveActiveProbeObservation,
            None,
            WireMimicryMode::Disabled,
            "127.0.0.1:443".parse().expect("test dst"),
        );
        assert_eq!(
            fields["mimicry_capability_signal_origin"],
            "live_active_probe_observation"
        );
        assert_eq!(
            fields["mimicry_capability_stage"],
            "early_pre_wire_capability_layer"
        );
        assert_eq!(fields["mimicry_capability_readiness"], "path_signal_ready");
        assert_eq!(
            fields["mimicry_capability_observation_capture_confidence"],
            "runtime_only"
        );
        assert_eq!(
            fields["mimicry_capability_wire_stage"],
            "architecture_scaffold_only"
        );
        assert_eq!(
            fields["mimicry_capability_wire_scope"],
            "future_packet_wire_linux_only"
        );
        assert_eq!(fields["mimicry_capability_wire_config_mode"], "disabled");
        assert_eq!(fields["mimicry_capability_wire_requested"], false);
        assert_eq!(fields["mimicry_capability_wire_active"], false);
        assert_eq!(
            fields["mimicry_capability_userspace_scope"],
            "pre_connect_socket_only"
        );
        assert_eq!(
            fields["mimicry_capability_userspace_wiring_mode"],
            "telemetry_only_no_stack_profile"
        );
        assert!(fields["mimicry_capability_userspace_stack_profile"].is_null());
        assert_eq!(fields["mimicry_capability_userspace_ttl_hint_ready"], false);
        assert_eq!(fields["mimicry_capability_userspace_nodelay_ready"], false);
        assert_eq!(
            fields["mimicry_capability_userspace_reuseaddr_ready"],
            false
        );
        assert_eq!(
            fields["mimicry_capability_userspace_send_buffer_ready"],
            false
        );
        assert_eq!(
            fields["mimicry_capability_userspace_recv_buffer_ready"],
            false
        );
        assert_eq!(fields["mimicry_capability_server_hint_ready"], false);
        assert_eq!(fields["mimicry_capability_window_profile_ready"], false);
        assert_eq!(fields["mimicry_capability_reference_path_ready"], true);
        assert_eq!(fields["mimicry_capability_rst_path_ready"], false);
        assert!(fields["mimicry_capability_userspace_ttl_hint"].is_null());
        assert!(fields["mimicry_capability_userspace_nodelay"].is_null());
        assert!(fields["mimicry_capability_userspace_reuseaddr"].is_null());
        assert!(fields["mimicry_capability_userspace_send_buffer"].is_null());
        assert!(fields["mimicry_capability_userspace_recv_buffer"].is_null());
        assert!(fields["mimicry_capability_server_hint"].is_null());
        assert!(fields["mimicry_capability_window_profile"].is_null());
        assert_eq!(fields["mimicry_capability_reference_path_hops"], 2);
        assert!(fields["mimicry_capability_rst_path_hops"].is_null());
    }

    #[test]
    fn helper_marks_profile_only_userspace_wiring_without_capture_backed_ttl() {
        let mut fields = serde_json::json!({});
        add_mimicry_capability_fields(
            &mut fields,
            Some(&runtime_only_observation()),
            MimicryCapabilitySignalOrigin::LiveRuntimeObservation,
            Some(StackProfileId::Windows11),
            WireMimicryMode::Disabled,
            "127.0.0.1:443".parse().expect("test dst"),
        );
        assert_eq!(
            fields["mimicry_capability_userspace_scope"],
            "pre_connect_socket_only"
        );
        assert_eq!(
            fields["mimicry_capability_userspace_wiring_mode"],
            "profile_only"
        );
        assert_eq!(
            fields["mimicry_capability_userspace_stack_profile"],
            "windows11"
        );
        assert_eq!(fields["mimicry_capability_userspace_nodelay_ready"], true);
        assert_eq!(fields["mimicry_capability_userspace_nodelay"], true);
        assert_eq!(fields["mimicry_capability_userspace_reuseaddr_ready"], true);
        assert_eq!(fields["mimicry_capability_userspace_reuseaddr"], true);
        assert_eq!(
            fields["mimicry_capability_userspace_send_buffer_ready"],
            true
        );
        assert_eq!(
            fields["mimicry_capability_userspace_recv_buffer_ready"],
            true
        );
        assert_eq!(fields["mimicry_capability_userspace_send_buffer"], 262144);
        assert_eq!(fields["mimicry_capability_userspace_recv_buffer"], 262144);
        assert!(fields["mimicry_capability_userspace_ttl_hint"].is_null());
    }

    #[test]
    fn helper_keeps_full_wire_contract_for_live_runtime_explicit_absence_baseline() {
        let mut fields = serde_json::json!({});
        add_mimicry_capability_fields(
            &mut fields,
            Some(&explicit_absence_observation()),
            MimicryCapabilitySignalOrigin::LiveRuntimeObservation,
            Some(StackProfileId::Windows11),
            WireMimicryMode::Disabled,
            "127.0.0.1:443".parse().expect("test dst"),
        );
        assert_eq!(
            fields["mimicry_capability_signal_origin"],
            "live_runtime_observation"
        );
        assert_eq!(
            fields["mimicry_capability_readiness"],
            "runtime_only_baseline"
        );
        assert_eq!(
            fields["mimicry_capability_observation_capture_confidence"],
            "explicit_absence"
        );
        assert_eq!(fields["mimicry_capability_wire_config_mode"], "disabled");
        assert_eq!(fields["mimicry_capability_wire_requested"], false);
        assert_eq!(fields["mimicry_capability_wire_active"], false);
        assert_eq!(
            fields["mimicry_capability_wire_activation_reason"],
            "config_disabled"
        );
        assert_eq!(
            fields["mimicry_capability_userspace_scope"],
            "pre_connect_socket_only"
        );
        assert_eq!(
            fields["mimicry_capability_userspace_wiring_mode"],
            "profile_only"
        );
        assert_eq!(
            fields["mimicry_capability_userspace_stack_profile"],
            "windows11"
        );
        assert_eq!(fields["mimicry_capability_userspace_nodelay"], true);
        assert_eq!(fields["mimicry_capability_userspace_reuseaddr"], true);
        assert_eq!(fields["mimicry_capability_userspace_send_buffer"], 262144);
        assert_eq!(fields["mimicry_capability_userspace_recv_buffer"], 262144);
        assert_eq!(
            fields["mimicry_capability_wire_stage"],
            "architecture_scaffold_only"
        );
        assert_eq!(
            fields["mimicry_capability_wire_scope"],
            "future_packet_wire_linux_only"
        );
        assert!(fields["mimicry_capability_wire_runtime_slice"].is_null());
        assert_eq!(fields["mimicry_capability_wire_ttl_preface"], Value::Null);
        assert_eq!(
            fields["mimicry_capability_wire_window_preface_ready"],
            false
        );
        assert_eq!(
            fields["mimicry_capability_wire_options_preface_ready"],
            true
        );
        assert_eq!(
            fields["mimicry_capability_wire_ipv4_header_shaping_ready"],
            false
        );
        assert_eq!(
            fields["mimicry_capability_wire_negotiated_options_ready"],
            false
        );
        let raw_caps = default_raw_engine().capabilities();
        assert_eq!(
            fields["mimicry_capability_wire_raw_ipv4_send_ready"],
            raw_caps.ipv4_raw_send
        );
        assert_eq!(
            fields["mimicry_capability_wire_tcp_repair_ready"],
            raw_caps.tcp_repair_query
        );
        assert_eq!(
            fields["mimicry_capability_wire_ipv4_header_control_ready"],
            raw_caps.ipv4_header_control
        );
        assert_eq!(
            fields["mimicry_capability_wire_ipv4_fragmentation_ready"],
            raw_caps.ipv4_fragmentation
        );
        assert!(fields["mimicry_capability_server_hint"].is_null());
        assert!(fields["mimicry_capability_reference_path_hops"].is_null());
    }

    #[test]
    fn userspace_wiring_mode_invariants_cover_all_four_modes() {
        let capture_backed = planner::build_mimicry_capability_plan(Some(&sample_observation()));
        let runtime_only =
            planner::build_mimicry_capability_plan(Some(&runtime_only_observation()));

        assert_eq!(
            mimicry_userspace_wiring_mode(None, &capture_backed),
            "capture_backed_ttl_only"
        );
        assert_eq!(
            mimicry_userspace_wiring_mode(None, &runtime_only),
            "telemetry_only_no_stack_profile"
        );
        assert_eq!(
            mimicry_userspace_wiring_mode(Some(StackProfileId::Windows11), &runtime_only),
            "profile_only"
        );
        assert_eq!(
            mimicry_userspace_wiring_mode(Some(StackProfileId::LinuxDesktop), &capture_backed),
            "profile_plus_capture_backed_ttl"
        );
    }

    #[test]
    fn userspace_nodelay_hint_tracks_only_stack_profile_contract() {
        assert_eq!(mimicry_userspace_nodelay_hint(None), None);
        assert_eq!(
            mimicry_userspace_nodelay_hint(Some(StackProfileId::Windows11)),
            Some(true)
        );
        assert_eq!(
            mimicry_userspace_nodelay_hint(Some(StackProfileId::LinuxDesktop)),
            Some(false)
        );
    }

    #[test]
    fn userspace_reuseaddr_hint_tracks_only_stack_profile_contract() {
        assert_eq!(mimicry_userspace_reuseaddr_hint(None), None);
        assert_eq!(
            mimicry_userspace_reuseaddr_hint(Some(StackProfileId::Default)),
            Some(false)
        );
        assert_eq!(
            mimicry_userspace_reuseaddr_hint(Some(StackProfileId::LinuxDesktop)),
            Some(true)
        );
    }

    #[test]
    fn userspace_buffer_hints_track_only_stack_profile_contract() {
        assert_eq!(mimicry_userspace_send_buffer_hint(None), None);
        assert_eq!(mimicry_userspace_recv_buffer_hint(None), None);
        assert_eq!(
            mimicry_userspace_send_buffer_hint(Some(StackProfileId::Windows11)),
            Some(256 * 1024)
        );
        assert_eq!(
            mimicry_userspace_recv_buffer_hint(Some(StackProfileId::LinuxDesktop)),
            Some(192 * 1024)
        );
    }

    #[test]
    fn planner_selection_fields_explain_snapshot_boundary_and_reorder_steps() {
        let trace = DirectPlannerSelectionTrace {
            selector_mode: "ucb1_contextual_reward",
            explainability_trace_source: "state_snapshot_contextual_reward",
            explainability_observation_source: "advisory_state_snapshot_observation",
            decision_context: test_decision_context(),
            observation_contract: "deep_observed",
            observation_capture_confidence: "deep_observed",
            probe_history_disposition: "bias_probe_branch",
            probe_history_reason_code: "single_stall_bias_probe_branch",
            cross_session_signal_bias: "probe_branch_bias",
            cross_session_confidence_score: 0.72,
            cross_session_reuse_weight: 0.61,
            cross_session_stall_severity: 0.37,
            cross_session_probe_branch_score: 0.19,
            cross_session_relay_preference_score: 0.0,
            recent_selection: None,
            reward_selected_order: vec!["passthrough".into(), "ttl_desync".into()],
            ranked_candidates: vec![DirectPlannerCandidateTrace {
                strategy: "passthrough".into(),
                estimated_reward: 0.9,
                estimated_trials: 2.0,
                total_trials: 2.0,
                probe_history_strategy_bias: 0.0,
                belief_alpha: 1.9,
                belief_beta: 1.1,
                belief_detection_risk: 0.0,
                belief_latency_cost: 0.0,
                belief_confidence: 0.8,
                belief_freshness: 1.0,
                belief_hard_blocked: false,
                belief_source: "l3_runtime_posterior",
                selection_score_reward_component: 0.9,
                selection_score_ucb_exploration_bonus: Some(0.3),
                selection_score_probe_bias_component: 0.0,
                selection_score: Some(1.2),
                cold_start_exploration: false,
            }],
        };
        let resolved_order = vec!["ttl_desync".into(), "passthrough".into()];
        let fields = planner_selection_runtime_fields(
            &trace,
            &resolved_order,
            "advisory_probe_branch",
            false,
            false,
            true,
            true,
            true,
            "initial_session_order",
            0,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            "example.org",
            443,
        );

        assert_eq!(
            fields["planner_reward_selection_source"],
            "brain_reward_loop"
        );
        assert_eq!(fields["planner_top_candidate_strategy"], "passthrough");
        assert_eq!(
            fields["planner_top_candidate_primary_reason"],
            "top_candidate_reward_component"
        );
        assert!(fields["planner_previous_top_candidate_primary_reason"].is_null());
        assert_eq!(
            fields["planner_top_candidate_primary_reason_changed"],
            false
        );
        assert_eq!(
            fields["planner_top_candidate_dominant_component"],
            "reward_component"
        );
        assert!(fields["planner_previous_top_candidate_dominant_component"].is_null());
        assert_eq!(
            fields["planner_top_candidate_dominant_component_changed"],
            false
        );
        assert_eq!(
            fields["planner_explainability_trace_source"],
            "state_snapshot_contextual_reward"
        );
        assert_eq!(
            fields["planner_explainability_observation_source"],
            "advisory_state_snapshot_observation"
        );
        assert_eq!(
            fields["planner_explainability_live_runtime_observation_used"],
            false
        );
        assert_eq!(fields["planner_post_brain_reorder_applied"], true);
        assert_eq!(fields["planner_reward_loop_order_preserved"], false);
        assert_eq!(
            fields["planner_resolved_order_primary_reason"],
            "advisory_probe_branch_reordered_reward_loop"
        );
        assert!(fields["planner_previous_order_resolution"].is_null());
        assert_eq!(fields["planner_order_resolution_changed"], false);
        assert!(fields["planner_previous_resolved_order_primary_reason"].is_null());
        assert_eq!(
            fields["planner_resolved_order_primary_reason_changed"],
            false
        );
        assert!(fields["planner_previous_post_brain_reorder_applied"].is_null());
        assert_eq!(fields["planner_post_brain_reorder_path_changed"], false);
        assert_eq!(fields["planner_lua_order_configured"], false);
        assert_eq!(fields["planner_lua_order_applied"], false);
        assert!(fields["planner_previous_lua_order_applied"].is_null());
        assert_eq!(fields["planner_lua_order_applied_changed"], false);
        assert_eq!(fields["planner_advisory_reorder_requested"], true);
        assert_eq!(fields["planner_advisory_reorder_allowed"], true);
        assert_eq!(fields["planner_advisory_reorder_applied"], true);
        assert!(fields["planner_previous_advisory_reorder_applied"].is_null());
        assert_eq!(fields["planner_advisory_reorder_applied_changed"], false);
        assert_eq!(
            fields["planner_ranked_candidates"][0]["selection_score_dominant_component"],
            "reward_component"
        );
        assert_eq!(
            fields["planner_ranked_candidates"][0]["selection_score_probe_bias_effect"],
            "neutral"
        );
    }

    #[tokio::test]
    async fn planner_selection_fields_distinguish_recent_order_from_baseline_scores() {
        use aegis_core::brain::recent_routes::RecentRoutesSettings;
        let settings = RecentRoutesSettings {
            window_ms: 60_000,
            paper_algorithm: None,
            max_observations: 64,
            diversity_penalty: 0.0,
            failure_domains: Default::default(),
        };
        let brain = Brain::new(
            0.0,
            vec!["one".into(), "two".into()],
            AsyncStateStore::ephemeral(),
        )
        .with_recent_routes(Some(&settings))
        .unwrap();
        let key = StrategyKey::for_dst(4);
        brain
            .record_outcome(&key, "one", FailSignal::Success, None, 0, None)
            .await;
        brain
            .record_outcome(&key, "two", FailSignal::Success, None, 128, None)
            .await;
        let trace = brain.select_order_trace(&key).await;
        let fields = planner_selection_runtime_fields(
            &trace,
            &trace.reward_selected_order,
            "reward_loop_only",
            false,
            false,
            false,
            true,
            false,
            "initial_session_order",
            0,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            "example.org",
            443,
        );
        assert_eq!(fields["planner_top_candidate_strategy"], "two");
        assert_eq!(
            fields["planner_top_candidate_primary_reason"],
            "top_candidate_recent_windowed_ucb_diversity"
        );
        assert_eq!(
            fields["planner_reward_selection_source"],
            "bounded_recent_runtime_outcomes"
        );
        assert_eq!(
            fields["planner_ranked_candidates_scope"],
            "baseline_contextual_snapshot"
        );
        assert_eq!(fields["planner_ranked_candidates"][0]["strategy"], "one");
        assert_eq!(
            fields["planner_recent_selection"]["selection"]["ranked"][0]["window_reward"],
            1.0
        );
        assert_eq!(
            fields["planner_recent_selection"]["baseline_selector_mode"],
            "ucb1_contextual_reward"
        );
    }

    #[cfg(feature = "lua")]
    #[tokio::test]
    async fn recent_native_resolver_keeps_lua_inside_admitted_routes() {
        use aegis_core::brain::recent_routes::RecentRoutesSettings;
        let store = AsyncStateStore::ephemeral();
        store
            .update(|snapshot| {
                snapshot.external_calibration = Some(aegis_core::ExternalCalibrationSnapshot {
                    schema_version: 1,
                    source: "controlled_test".into(),
                    generated_at_unix_ms: None,
                    freshness_half_life_secs: None,
                    witness: Vec::new(),
                    adversarial: Vec::new(),
                    knowledge: vec![aegis_core::ExternalKnowledgePrior {
                        target_class: "https_ws".into(),
                        region_id: None,
                        score: 0.0,
                        confidence: 0.9,
                        hard_excluded: true,
                        fail_closed: true,
                        generated_at_unix_ms: None,
                    }],
                    verdict: aegis_core::ExternalCalibrationVerdict {
                        status: "MEASURED".into(),
                        acceptance_degraded: false,
                        reasons: Vec::new(),
                    },
                });
            })
            .await;
        let settings = RecentRoutesSettings {
            window_ms: 60_000,
            paper_algorithm: None,
            max_observations: 64,
            diversity_penalty: 0.0,
            failure_domains: Default::default(),
        };
        let key = StrategyKey::for_target(
            "203.0.113.9:443".parse().unwrap(),
            "example.org",
            443,
            Some("example.org"),
            true,
        );
        let brain = Brain::new(
            1.0,
            vec!["https_ws".into(), "legacy_tls".into()],
            store.clone(),
        )
        .with_recent_routes(Some(&settings))
        .unwrap();
        let trace = brain.select_order_trace(&key).await;
        assert_eq!(trace.reward_selected_order, vec!["legacy_tls"]);
        let blocked = Brain::new(1.0, vec!["https_ws".into()], store)
            .with_recent_routes(Some(&settings))
            .unwrap()
            .select_order_trace(&key)
            .await;
        assert!(blocked.reward_selected_order.is_empty());
        let mut legacy = trace.clone();
        legacy.recent_selection = None;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("order.lua");
        let direct = DirectSettings {
            lua_order_script: Some(path.clone()),
            ..Default::default()
        };
        let advisory = sample_advisory();
        let probe = ActiveProbePlan {
            preferred_ttl: 4,
            budget: 2,
            candidates: vec![3, 4],
        };
        // Execute the real Lua VM and native resolver, including the later
        // advisory branch. Legacy mode keeps its preexisting hook semantics.
        for (selected, script, expected) in [
            (
                &trace,
                "return {'https_ws','unknown','legacy_tls','legacy_tls'}",
                vec!["legacy_tls"],
            ),
            (&trace, "return {'https_ws','unknown'}", Vec::new()),
            (&blocked, "return {'legacy_tls'}", Vec::new()),
            (
                &legacy,
                "return {'https_ws','unknown','legacy_tls','legacy_tls'}",
                vec!["https_ws", "unknown", "legacy_tls", "legacy_tls"],
            ),
        ] {
            fs::write(
                &path,
                format!("function order(preferred, ip_ver) {script} end"),
            )
            .unwrap();
            let resolved = resolve_direct_order(
                &direct,
                &advisory,
                None,
                WireMimicryMode::Disabled,
                "203.0.113.9:443".parse().unwrap(),
                &probe,
                "example.org",
                443,
                4,
                selected,
                "initial_session_order",
                0,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await;
            assert_eq!(resolved.order, expected);
        }
    }

    #[test]
    fn planner_selection_fields_surface_reason_and_reorder_deltas_against_previous_selection() {
        let previous_trace = DirectPlannerSelectionTrace {
            selector_mode: "ucb1_contextual_reward",
            explainability_trace_source: "state_snapshot_contextual_reward",
            explainability_observation_source: "advisory_state_snapshot_observation",
            decision_context: test_decision_context(),
            observation_contract: "deep_observed",
            observation_capture_confidence: "deep_observed",
            probe_history_disposition: "none",
            probe_history_reason_code: "probe_signal_not_stall_like",
            cross_session_signal_bias: "neutral_advisory_bias",
            cross_session_confidence_score: 0.41,
            cross_session_reuse_weight: 0.52,
            cross_session_stall_severity: 0.0,
            cross_session_probe_branch_score: 0.0,
            cross_session_relay_preference_score: 0.0,
            recent_selection: None,
            reward_selected_order: vec!["passthrough".into(), "ttl_desync".into()],
            ranked_candidates: vec![DirectPlannerCandidateTrace {
                strategy: "passthrough".into(),
                estimated_reward: 0.9,
                estimated_trials: 3.0,
                total_trials: 3.0,
                probe_history_strategy_bias: 0.0,
                belief_alpha: 1.9,
                belief_beta: 1.1,
                belief_detection_risk: 0.0,
                belief_latency_cost: 0.0,
                belief_confidence: 0.8,
                belief_freshness: 1.0,
                belief_hard_blocked: false,
                belief_source: "l3_runtime_posterior",
                selection_score_reward_component: 0.9,
                selection_score_ucb_exploration_bonus: Some(0.2),
                selection_score_probe_bias_component: 0.0,
                selection_score: Some(1.1),
                cold_start_exploration: false,
            }],
        };
        let trace = DirectPlannerSelectionTrace {
            selector_mode: "ucb1_contextual_reward",
            explainability_trace_source: "state_snapshot_contextual_reward",
            explainability_observation_source: "advisory_state_snapshot_observation",
            decision_context: test_decision_context(),
            observation_contract: "deep_observed",
            observation_capture_confidence: "deep_observed",
            probe_history_disposition: "bias_probe_branch",
            probe_history_reason_code: "single_stall_bias_probe_branch",
            cross_session_signal_bias: "probe_branch_bias",
            cross_session_confidence_score: 0.72,
            cross_session_reuse_weight: 0.61,
            cross_session_stall_severity: 0.37,
            cross_session_probe_branch_score: 0.19,
            cross_session_relay_preference_score: 0.0,
            recent_selection: None,
            reward_selected_order: vec!["passthrough".into(), "ttl_desync".into()],
            ranked_candidates: vec![DirectPlannerCandidateTrace {
                strategy: "passthrough".into(),
                estimated_reward: 0.9,
                estimated_trials: 4.0,
                total_trials: 4.0,
                probe_history_strategy_bias: 0.8,
                belief_alpha: 1.9,
                belief_beta: 1.1,
                belief_detection_risk: 0.0,
                belief_latency_cost: 0.0,
                belief_confidence: 0.8,
                belief_freshness: 1.0,
                belief_hard_blocked: false,
                belief_source: "l3_runtime_posterior",
                selection_score_reward_component: 0.9,
                selection_score_ucb_exploration_bonus: Some(0.2),
                selection_score_probe_bias_component: 1.1,
                selection_score: Some(2.2),
                cold_start_exploration: false,
            }],
        };
        let resolved_order = vec!["ttl_desync".into(), "passthrough".into()];
        let fields = planner_selection_runtime_fields(
            &trace,
            &resolved_order,
            "advisory_probe_branch",
            false,
            false,
            true,
            true,
            true,
            "post_probe_retry_reselect",
            1,
            Some(&previous_trace.reward_selected_order),
            Some(&previous_trace.reward_selected_order),
            Some(&previous_trace),
            Some("reward_loop_only"),
            Some(false),
            Some(false),
            Some(false),
            "example.org",
            443,
        );

        assert_eq!(
            fields["planner_previous_top_candidate_primary_reason"],
            "top_candidate_reward_component"
        );
        assert_eq!(fields["planner_top_candidate_primary_reason_changed"], true);
        assert_eq!(
            fields["planner_top_candidate_dominant_component"],
            "probe_history_bias_component"
        );
        assert_eq!(
            fields["planner_previous_top_candidate_dominant_component"],
            "reward_component"
        );
        assert_eq!(
            fields["planner_top_candidate_dominant_component_changed"],
            true
        );
        assert_eq!(
            fields["planner_previous_order_resolution"],
            "reward_loop_only"
        );
        assert_eq!(fields["planner_order_resolution_changed"], true);
        assert_eq!(
            fields["planner_previous_resolved_order_primary_reason"],
            "reward_loop_preserved"
        );
        assert_eq!(
            fields["planner_resolved_order_primary_reason_changed"],
            true
        );
        assert_eq!(fields["planner_previous_post_brain_reorder_applied"], false);
        assert_eq!(fields["planner_post_brain_reorder_path_changed"], true);
        assert_eq!(fields["planner_previous_lua_order_applied"], false);
        assert_eq!(fields["planner_lua_order_applied_changed"], false);
        assert_eq!(fields["planner_previous_advisory_reorder_applied"], false);
        assert_eq!(fields["planner_advisory_reorder_applied_changed"], true);
    }

    #[test]
    fn planner_selection_fields_keep_randomized_path_off_advisory_surface() {
        let trace = DirectPlannerSelectionTrace {
            selector_mode: "epsilon_randomized_preferred_order",
            explainability_trace_source: "runtime_randomized_preferred_order",
            explainability_observation_source: "no_advisory_observation",
            decision_context: test_decision_context(),
            observation_contract: "runtime_only",
            observation_capture_confidence: "runtime_only",
            probe_history_disposition: "none",
            probe_history_reason_code: "no_recent_probe_history",
            cross_session_signal_bias: "neutral_advisory_bias",
            cross_session_confidence_score: 0.0,
            cross_session_reuse_weight: 0.0,
            cross_session_stall_severity: 0.0,
            cross_session_probe_branch_score: 0.0,
            cross_session_relay_preference_score: 0.0,
            recent_selection: None,
            reward_selected_order: vec!["ttl_desync".into(), "passthrough".into()],
            ranked_candidates: Vec::new(),
        };
        let fields = planner_selection_runtime_fields(
            &trace,
            &trace.reward_selected_order,
            "reward_loop_only",
            false,
            false,
            false,
            true,
            false,
            "initial_session_order",
            0,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            "example.org",
            443,
        );

        assert_eq!(
            fields["planner_reward_selection_source"],
            "randomized_preferred_order"
        );
        assert!(fields["planner_top_candidate_strategy"].is_null());
        assert_eq!(
            fields["planner_top_candidate_primary_reason"],
            "epsilon_randomized_preferred_order"
        );
        assert!(fields["planner_top_candidate_dominant_component"].is_null());
        assert_eq!(
            fields["planner_explainability_trace_source"],
            "runtime_randomized_preferred_order"
        );
        assert_eq!(
            fields["planner_explainability_observation_source"],
            "no_advisory_observation"
        );
        assert_eq!(fields["planner_post_brain_reorder_applied"], false);
        assert_eq!(fields["planner_reward_loop_order_preserved"], true);
        assert_eq!(
            fields["planner_resolved_order_primary_reason"],
            "reward_loop_preserved"
        );
        assert_eq!(fields["planner_advisory_reorder_requested"], false);
        assert_eq!(fields["planner_advisory_reorder_applied"], false);
    }

    #[test]
    fn planner_candidate_fields_surface_probe_bias_when_it_dominates() {
        let candidate = DirectPlannerCandidateTrace {
            strategy: "ttl_desync".into(),
            estimated_reward: 0.2,
            estimated_trials: 1.0,
            total_trials: 1.0,
            probe_history_strategy_bias: 0.6,
            belief_alpha: 1.2,
            belief_beta: 1.8,
            belief_detection_risk: 0.0,
            belief_latency_cost: 0.0,
            belief_confidence: 0.2,
            belief_freshness: 1.0,
            belief_hard_blocked: false,
            belief_source: "l3_runtime_posterior",
            selection_score_reward_component: 0.2,
            selection_score_ucb_exploration_bonus: Some(0.1),
            selection_score_probe_bias_component: 0.6,
            selection_score: Some(0.9),
            cold_start_exploration: false,
        };
        let fields = planner_candidate_runtime_fields(0, &candidate, None);

        assert_eq!(
            fields["selection_score_dominant_component"],
            "probe_history_bias_component"
        );
        assert_eq!(fields["selection_score_probe_bias_effect"], "boosted");
    }

    #[test]
    fn helper_adds_cross_session_metric_fields_from_advisory() {
        let advisory = sample_advisory();
        let mut fields = serde_json::json!({});
        add_cross_session_metric_fields(&mut fields, &advisory);
        assert_eq!(
            fields["cross_session_confidence_score"],
            serde_json::json!(0.72)
        );
        assert_eq!(
            fields["cross_session_reuse_weight"],
            serde_json::json!(0.61)
        );
        assert_eq!(
            fields["cross_session_stall_severity"],
            serde_json::json!(0.37)
        );
        assert_eq!(
            fields["cross_session_probe_branch_score"],
            serde_json::json!(0.19)
        );
        assert_eq!(
            fields["cross_session_relay_preference_score"],
            serde_json::json!(0.0)
        );
    }

    #[test]
    fn malformed_tls_grease_error_is_stage_prefixed() {
        let mut buf = vec![22, 3, 3, 0, 6, 1, 0, 0, 2, 3, 3];
        let direct = DirectSettings {
            tls_grease: true,
            ..DirectSettings::default()
        };

        let err =
            apply_direct_first_chunk_transforms(&mut buf, &direct, 4).expect_err("grease error");
        assert!(
            err.to_string().starts_with("direct_tls_grease:"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn client_eof_before_first_chunk_skips_outbound_connect() {
        let (client, server) = tcp_pair().await;
        drop(client);

        let target_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind target listener");
        let dst = target_listener.local_addr().expect("target addr");

        let result = handle_direct(
            server,
            ConnectTarget {
                host: "example.com".into(),
                port: dst.port(),
            },
            dst,
            test_brain().await,
            &DirectSettings::default(),
            DirectFallbackContext {
                relay: &RelaySettings::default(),
                terminal_policy: DirectTerminalPolicy::PreserveDirectFailure,
            },
            None,
        )
        .await;

        assert!(result.is_ok(), "unexpected direct result: {result:?}");
        assert!(
            timeout(Duration::from_millis(200), target_listener.accept())
                .await
                .is_err(),
            "target unexpectedly received an outbound connection"
        );
    }
}
