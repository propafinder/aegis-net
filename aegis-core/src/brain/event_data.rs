use serde_json::json;

use crate::signals::classify::FailSignal;
use crate::state_v2::{KeyObservation, ObservationContract};

use super::health::{
    active_probe_launch_health_decision, active_probe_result_health_decision,
    direct_failover_health_decision, direct_session_health_decision,
    retry_budget_exhausted_health_decision,
};
use super::{
    ActiveStallProbeFailoverContext, ActiveStallProbeFinishContext,
    ActiveStallProbeFinishedEventData, ActiveStallProbeFinishedTraceContext,
    ActiveStallProbeLaunchedEventData, ActiveStallProbeLaunchedTraceContext,
    ActiveStallProbeOutcomeClass, ActiveStallProbePlanContext,
    ActiveStallProbeRetryBudgetExhaustedEventData,
    ActiveStallProbeRetryBudgetExhaustedTraceContext, DirectRelayFailoverEventData,
    DirectRelayFailoverReasonCode, DirectRelayFailoverTraceContext,
    DirectSessionSucceededEventData, DirectSessionSucceededTraceContext,
    DirectSessionSuccessMetrics, ObservationPathContext, ProbeHistoryDisposition,
    ProbeHistoryReasonCode, RetryBudgetContext, RuntimeEndpoint,
};

pub fn active_stall_probe_launched_event_data(
    signal: &FailSignal,
    observation_contract: ObservationContract,
    target: &str,
    port: u16,
    planned_probe_preferred_ttl: u8,
    planned_probe_budget: usize,
    planned_probe_ttl_candidates: &[u8],
) -> ActiveStallProbeLaunchedEventData {
    let decision = active_probe_launch_health_decision();
    let trace = ActiveStallProbeLaunchedTraceContext {
        signal: format!("{signal:?}"),
        observation_contract: observation_contract.as_str(),
        direct_path_health_tier: decision.tier.as_str(),
        direct_path_health_reason_code: decision.reason_code.as_str(),
        planned_probe_preferred_ttl,
        planned_probe_budget,
        planned_probe_ttl_candidates: planned_probe_ttl_candidates.to_vec(),
    };
    ActiveStallProbeLaunchedEventData {
        message: "launching active stall probe",
        runtime_fields: json!({
            "signal": trace.signal,
            "observation_contract": trace.observation_contract,
            "direct_path_health_tier": trace.direct_path_health_tier,
            "direct_path_health_reason_code": trace.direct_path_health_reason_code,
            "target": target,
            "port": port,
            "planned_probe_preferred_ttl": trace.planned_probe_preferred_ttl,
            "planned_probe_budget": trace.planned_probe_budget,
            "planned_probe_ttl_candidates": trace.planned_probe_ttl_candidates,
        }),
        trace,
    }
}

pub fn direct_session_succeeded_event_data(
    strategy: &str,
    signal: &FailSignal,
    observation: &KeyObservation,
    probe_history_disposition: ProbeHistoryDisposition,
    probe_history_reason_code: ProbeHistoryReasonCode,
    endpoint: RuntimeEndpoint<'_>,
    metrics: DirectSessionSuccessMetrics,
) -> DirectSessionSucceededEventData {
    let decision = direct_session_health_decision(signal);
    let trace = DirectSessionSucceededTraceContext {
        strategy: strategy.to_string(),
        signal: format!("{signal:?}"),
        probe_outcome_class: ActiveStallProbeOutcomeClass::from_signal(signal).as_str(),
        direct_path_health_tier: decision.tier.as_str(),
        direct_path_health_reason_code: decision.reason_code.as_str(),
        observation_contract: observation.observation_contract().as_str(),
        observation_capture_confidence: observation.observation_capture_confidence(),
        probe_history_disposition: probe_history_disposition.as_str(),
        probe_history_reason_code: probe_history_reason_code.as_str(),
        capture_status: format!("{:?}", observation.capture_status),
        reference_path_hops: observation.reference_path_hops(),
        rst_path_hops: observation.rst_path_hops(),
        server_hint: observation.runtime_server_hint().map(|hint| hint.as_str()),
        fingerprint_window_hint: observation
            .runtime_window_profile_hint()
            .map(|hint| hint.as_str()),
        first_response_bytes: observation.first_response_bytes,
        relay_client_to_remote_bytes: observation.relay_client_to_remote_bytes,
        relay_remote_to_client_bytes: observation.relay_remote_to_client_bytes,
        relay_lifetime_ms: observation.relay_lifetime_ms,
        latency_ms: metrics.latency_ms,
        bytes_sent: metrics.bytes_sent,
        active_stall_probe_retry_attempted: metrics.retry_attempts_used > 0,
        retry_attempts_used: metrics.retry_attempts_used,
    };
    DirectSessionSucceededEventData {
        message: "direct session succeeded",
        runtime_fields: json!({
            "strategy": trace.strategy,
            "signal": trace.signal,
            "probe_outcome_class": trace.probe_outcome_class,
            "direct_path_health_tier": trace.direct_path_health_tier,
            "direct_path_health_reason_code": trace.direct_path_health_reason_code,
            "observation_contract": trace.observation_contract,
            "observation_capture_confidence": trace.observation_capture_confidence,
            "probe_history_disposition": trace.probe_history_disposition,
            "probe_history_reason_code": trace.probe_history_reason_code,
            "capture_status": trace.capture_status,
            "reference_path_hops": trace.reference_path_hops,
            "rst_path_hops": trace.rst_path_hops,
            "server_hint": trace.server_hint,
            "fingerprint_window_hint": trace.fingerprint_window_hint,
            "first_response_bytes": trace.first_response_bytes,
            "relay_client_to_remote_bytes": trace.relay_client_to_remote_bytes,
            "relay_remote_to_client_bytes": trace.relay_remote_to_client_bytes,
            "relay_lifetime_ms": trace.relay_lifetime_ms,
            "latency_ms": trace.latency_ms,
            "bytes_sent": trace.bytes_sent,
            "active_stall_probe_retry_attempted": trace.active_stall_probe_retry_attempted,
            "retry_attempts_used": trace.retry_attempts_used,
            "target": endpoint.target,
            "port": endpoint.port,
        }),
        trace,
    }
}

pub fn active_stall_probe_finished_event_data(
    signal: &FailSignal,
    observation: &KeyObservation,
    endpoint: RuntimeEndpoint<'_>,
    plan: ActiveStallProbePlanContext<'_>,
    finish: ActiveStallProbeFinishContext,
) -> ActiveStallProbeFinishedEventData {
    let decision = active_probe_result_health_decision(signal);
    let trace = ActiveStallProbeFinishedTraceContext {
        signal: format!("{signal:?}"),
        probe_outcome_class: ActiveStallProbeOutcomeClass::from_signal(signal).as_str(),
        direct_path_health_tier: decision.tier.as_str(),
        direct_path_health_reason_code: decision.reason_code.as_str(),
        observation_contract: observation.observation_contract().as_str(),
        observation_capture_confidence: observation.observation_capture_confidence(),
        capture_status: format!("{:?}", observation.capture_status),
        reference_path_hops: observation.reference_path_hops(),
        rst_path_hops: observation.rst_path_hops(),
        server_hint: observation.runtime_server_hint().map(|hint| hint.as_str()),
        fingerprint_window_hint: observation
            .runtime_window_profile_hint()
            .map(|hint| hint.as_str()),
        planned_probe_preferred_ttl: plan.preferred_ttl,
        planned_probe_budget: plan.budget,
        planned_probe_ttl_candidates: plan.ttl_candidates.to_vec(),
        first_response_bytes: finish.first_response_bytes,
        probe_terminal_stage: finish.terminal_stage,
        latency_ms: finish.latency_ms,
    };
    ActiveStallProbeFinishedEventData {
        message: "active stall probe finished",
        runtime_fields: json!({
            "target": endpoint.target,
            "port": endpoint.port,
            "signal": trace.signal,
            "probe_outcome_class": trace.probe_outcome_class,
            "direct_path_health_tier": trace.direct_path_health_tier,
            "direct_path_health_reason_code": trace.direct_path_health_reason_code,
            "observation_contract": trace.observation_contract,
            "observation_capture_confidence": trace.observation_capture_confidence,
            "latency_ms": trace.latency_ms,
            "capture_status": trace.capture_status,
            "reference_path_hops": trace.reference_path_hops,
            "rst_path_hops": trace.rst_path_hops,
            "server_hint": trace.server_hint,
            "fingerprint_window_hint": trace.fingerprint_window_hint,
            "planned_probe_preferred_ttl": trace.planned_probe_preferred_ttl,
            "planned_probe_budget": trace.planned_probe_budget,
            "planned_probe_ttl_candidates": trace.planned_probe_ttl_candidates,
            "first_response_bytes": trace.first_response_bytes,
            "probe_terminal_stage": trace.probe_terminal_stage,
        }),
        trace,
    }
}

pub fn direct_relay_failover_event_data(
    signal: &FailSignal,
    observation_contract: ObservationContract,
    observation_capture_confidence: &'static str,
    reason_code: DirectRelayFailoverReasonCode,
    path: ObservationPathContext,
    failover: ActiveStallProbeFailoverContext,
    endpoint: RuntimeEndpoint<'_>,
) -> DirectRelayFailoverEventData {
    let decision = direct_failover_health_decision();
    let trace = DirectRelayFailoverTraceContext {
        signal: format!("{signal:?}"),
        probe_outcome_class: ActiveStallProbeOutcomeClass::from_signal(signal).as_str(),
        direct_path_health_tier: decision.tier.as_str(),
        direct_path_health_reason_code: decision.reason_code.as_str(),
        direct_path_degraded_before_terminal: failover.retry_attempted,
        direct_path_unstable_before_failover: true,
        observation_contract: observation_contract.as_str(),
        observation_capture_confidence,
        direct_relay_failover_reason_code: reason_code.as_str(),
        reference_path_hops: path.reference_path_hops,
        rst_path_hops: path.rst_path_hops,
        active_stall_probe_recommended: failover.recommended,
        active_stall_probe_retry_attempted: failover.retry_attempted,
        probe_terminal_stage: failover.terminal_stage,
    };
    DirectRelayFailoverEventData {
        message: "direct session stalled, switching to relay tunnel",
        runtime_fields: json!({
            "signal": trace.signal,
            "probe_outcome_class": trace.probe_outcome_class,
            "direct_path_health_tier": trace.direct_path_health_tier,
            "direct_path_health_reason_code": trace.direct_path_health_reason_code,
            "direct_path_degraded_before_terminal": trace.direct_path_degraded_before_terminal,
            "direct_path_unstable_before_failover": trace.direct_path_unstable_before_failover,
            "observation_contract": trace.observation_contract,
            "observation_capture_confidence": trace.observation_capture_confidence,
            "direct_relay_failover_reason_code": trace.direct_relay_failover_reason_code,
            "reference_path_hops": trace.reference_path_hops,
            "rst_path_hops": trace.rst_path_hops,
            "active_stall_probe_recommended": trace.active_stall_probe_recommended,
            "active_stall_probe_retry_attempted": trace.active_stall_probe_retry_attempted,
            "probe_terminal_stage": trace.probe_terminal_stage,
            "target": endpoint.target,
            "port": endpoint.port,
        }),
        trace,
    }
}

pub fn active_stall_probe_retry_budget_exhausted_event_data(
    signal: &FailSignal,
    observation_contract: ObservationContract,
    observation_capture_confidence: &'static str,
    path: ObservationPathContext,
    retry_budget: RetryBudgetContext,
    probe_terminal_stage: Option<&'static str>,
    endpoint: RuntimeEndpoint<'_>,
) -> ActiveStallProbeRetryBudgetExhaustedEventData {
    let decision = retry_budget_exhausted_health_decision();
    let trace = ActiveStallProbeRetryBudgetExhaustedTraceContext {
        signal: format!("{signal:?}"),
        probe_outcome_class: ActiveStallProbeOutcomeClass::from_signal(signal).as_str(),
        direct_path_health_tier: decision.tier.as_str(),
        direct_path_health_reason_code: decision.reason_code.as_str(),
        direct_path_degraded_before_terminal: retry_budget.attempts_used > 0,
        direct_path_unstable_before_failover: true,
        observation_contract: observation_contract.as_str(),
        observation_capture_confidence,
        reference_path_hops: path.reference_path_hops,
        rst_path_hops: path.rst_path_hops,
        retry_attempts_used: retry_budget.attempts_used,
        retry_attempts_budget: retry_budget.attempts_budget,
        probe_terminal_stage,
    };
    ActiveStallProbeRetryBudgetExhaustedEventData {
        message: "active stall probe retry budget exhausted, falling back to relay",
        runtime_fields: json!({
            "signal": trace.signal,
            "probe_outcome_class": trace.probe_outcome_class,
            "direct_path_health_tier": trace.direct_path_health_tier,
            "direct_path_health_reason_code": trace.direct_path_health_reason_code,
            "direct_path_degraded_before_terminal": trace.direct_path_degraded_before_terminal,
            "direct_path_unstable_before_failover": trace.direct_path_unstable_before_failover,
            "observation_contract": trace.observation_contract,
            "observation_capture_confidence": trace.observation_capture_confidence,
            "reference_path_hops": trace.reference_path_hops,
            "rst_path_hops": trace.rst_path_hops,
            "retry_attempts_used": trace.retry_attempts_used,
            "retry_attempts_budget": trace.retry_attempts_budget,
            "probe_terminal_stage": trace.probe_terminal_stage,
            "target": endpoint.target,
            "port": endpoint.port,
        }),
        trace,
    }
}
