use serde_json::{json, Value};

use crate::signals::classify::FailSignal;
use crate::state_v2::KeyObservation;

use super::health::{active_probe_result_health_decision, retry_skipped_health_decision};
use super::{
    ActiveStallProbeOutcomeClass, ActiveStallProbePlanContext, ActiveStallProbeRetryEventData,
    ActiveStallProbeRetrySkippedEventData, ActiveStallProbeRetrySkippedTraceContext,
    ActiveStallProbeRetrySuppressedReasonCode, ActiveStallProbeRetryTraceContext,
    DirectProbeBranchEventData, DirectProbeBranchTraceContext, DirectRelayPreferenceEventData,
    DirectRelayPreferenceTraceContext, DirectSessionAdvisory, ProbeHistoryDisposition,
    RetryBudgetContext, RuntimeEndpoint,
};

const ACTIVE_PROBE_BRANCH_STRATEGIES: &[&str] =
    &["ttl_desync", "ip_frag", "fake_disorder", "overlap"];

impl DirectSessionAdvisory {
    pub fn cross_session_signal_bias(&self) -> &'static str {
        let probe = self.cross_session_signal_metrics.probe_branch_score;
        let relay = self.cross_session_signal_metrics.relay_preference_score;
        match (probe > f64::EPSILON, relay > f64::EPSILON) {
            (false, false) => "neutral_advisory_bias",
            (true, false) => "probe_branch_bias",
            (false, true) => "relay_preference_bias",
            (true, true) => "mixed_advisory_bias",
        }
    }

    pub fn apply_to_direct_order(
        &self,
        ordered: Vec<String>,
        allow_probe_branch: bool,
    ) -> Vec<String> {
        if !allow_probe_branch
            || !matches!(
                self.probe_history_disposition,
                ProbeHistoryDisposition::BiasProbeBranch
            )
        {
            return ordered;
        }
        let mut prioritized = Vec::with_capacity(ordered.len());
        let mut deferred = Vec::with_capacity(ordered.len());
        for id in ordered {
            if ACTIVE_PROBE_BRANCH_STRATEGIES
                .iter()
                .any(|candidate| *candidate == id)
            {
                prioritized.push(id);
            } else {
                deferred.push(id);
            }
        }
        if prioritized.is_empty() {
            return deferred;
        }
        prioritized.extend(deferred);
        prioritized
    }

    pub fn relay_preference_runtime_fields(&self, target: &str, port: u16) -> Value {
        let trace = self.relay_preference_trace_context();
        json!({
            "target": target,
            "port": port,
            "probe_history_disposition": trace.probe_history_disposition,
            "probe_history_reason_code": trace.probe_history_reason_code,
            "observation_contract": trace.observation_contract,
            "observation_capture_confidence": trace.observation_capture_confidence,
            "cross_session_signal_bias": trace.cross_session_signal_bias,
            "cross_session_confidence_score": trace.cross_session_confidence_score,
            "cross_session_reuse_weight": trace.cross_session_reuse_weight,
            "cross_session_stall_severity": trace.cross_session_stall_severity,
            "cross_session_probe_branch_score": trace.cross_session_probe_branch_score,
            "cross_session_relay_preference_score": trace.cross_session_relay_preference_score,
            "stall_probe_trials": trace.stall_probe_trials,
            "stall_probe_freezes": trace.stall_probe_freezes,
            "stall_probe_collapses": trace.stall_probe_collapses,
            "stall_probe_timeouts": trace.stall_probe_timeouts,
            "last_probe_signal": trace.last_probe_signal
        })
    }

    pub fn relay_preference_trace_context(&self) -> DirectRelayPreferenceTraceContext {
        let probe_stats = self
            .latest_probe_stats
            .as_ref()
            .expect("relay preference trace context requires probe stats");
        DirectRelayPreferenceTraceContext {
            probe_history_disposition: self.probe_history_disposition.as_str(),
            probe_history_reason_code: self.probe_history_reason_code.as_str(),
            observation_contract: self.observation_contract.as_str(),
            observation_capture_confidence: self
                .latest_observation
                .as_ref()
                .map(KeyObservation::observation_capture_confidence)
                .unwrap_or(self.observation_contract.as_str()),
            cross_session_signal_bias: self.cross_session_signal_bias(),
            cross_session_confidence_score: self.cross_session_signal_metrics.confidence_score,
            cross_session_reuse_weight: self.cross_session_signal_metrics.reuse_weight,
            cross_session_stall_severity: self.cross_session_signal_metrics.stall_severity,
            cross_session_probe_branch_score: self.cross_session_signal_metrics.probe_branch_score,
            cross_session_relay_preference_score: self
                .cross_session_signal_metrics
                .relay_preference_score,
            stall_probe_trials: probe_stats.trials,
            stall_probe_freezes: probe_stats.freezes,
            stall_probe_collapses: probe_stats.collapses,
            stall_probe_timeouts: probe_stats.timeouts,
            last_probe_signal: probe_stats
                .last_signal
                .as_ref()
                .map(|signal| format!("{signal:?}")),
        }
    }

    pub fn relay_preference_event_data(
        &self,
        target: &str,
        port: u16,
    ) -> DirectRelayPreferenceEventData {
        DirectRelayPreferenceEventData {
            message: "preferring relay tunnel from repeated stall-probe history",
            trace: self.relay_preference_trace_context(),
            runtime_fields: self.relay_preference_runtime_fields(target, port),
        }
    }

    pub fn probe_branch_runtime_fields(
        &self,
        target: &str,
        port: u16,
        planned_probe_preferred_ttl: u8,
        planned_probe_budget: usize,
        planned_probe_ttl_candidates: &[u8],
        branch_order: &[String],
    ) -> Value {
        let trace = self.probe_branch_trace_context(
            planned_probe_preferred_ttl,
            planned_probe_budget,
            planned_probe_ttl_candidates,
            branch_order,
        );
        json!({
            "target": target,
            "port": port,
            "probe_history_disposition": trace.probe_history_disposition,
            "probe_history_reason_code": trace.probe_history_reason_code,
            "observation_contract": trace.observation_contract,
            "observation_capture_confidence": trace.observation_capture_confidence,
            "cross_session_signal_bias": trace.cross_session_signal_bias,
            "cross_session_confidence_score": trace.cross_session_confidence_score,
            "cross_session_reuse_weight": trace.cross_session_reuse_weight,
            "cross_session_stall_severity": trace.cross_session_stall_severity,
            "cross_session_probe_branch_score": trace.cross_session_probe_branch_score,
            "cross_session_relay_preference_score": trace.cross_session_relay_preference_score,
            "server_hint": trace.server_hint,
            "fingerprint_window_hint": trace.fingerprint_window_hint,
            "planned_probe_preferred_ttl": trace.planned_probe_preferred_ttl,
            "planned_probe_budget": trace.planned_probe_budget,
            "planned_probe_ttl_candidates": trace.planned_probe_ttl_candidates,
            "branch_order": trace.branch_order
        })
    }

    pub fn probe_branch_trace_context(
        &self,
        planned_probe_preferred_ttl: u8,
        planned_probe_budget: usize,
        planned_probe_ttl_candidates: &[u8],
        branch_order: &[String],
    ) -> DirectProbeBranchTraceContext {
        DirectProbeBranchTraceContext {
            probe_history_disposition: self.probe_history_disposition.as_str(),
            probe_history_reason_code: self.probe_history_reason_code.as_str(),
            observation_contract: self.observation_contract.as_str(),
            observation_capture_confidence: self
                .latest_observation
                .as_ref()
                .map(KeyObservation::observation_capture_confidence)
                .unwrap_or(self.observation_contract.as_str()),
            cross_session_signal_bias: self.cross_session_signal_bias(),
            cross_session_confidence_score: self.cross_session_signal_metrics.confidence_score,
            cross_session_reuse_weight: self.cross_session_signal_metrics.reuse_weight,
            cross_session_stall_severity: self.cross_session_signal_metrics.stall_severity,
            cross_session_probe_branch_score: self.cross_session_signal_metrics.probe_branch_score,
            cross_session_relay_preference_score: self
                .cross_session_signal_metrics
                .relay_preference_score,
            server_hint: self
                .latest_observation
                .as_ref()
                .and_then(KeyObservation::runtime_server_hint)
                .map(|hint| hint.as_str()),
            fingerprint_window_hint: self
                .latest_observation
                .as_ref()
                .and_then(KeyObservation::runtime_window_profile_hint)
                .map(|hint| hint.as_str()),
            planned_probe_preferred_ttl,
            planned_probe_budget,
            planned_probe_ttl_candidates: planned_probe_ttl_candidates.to_vec(),
            branch_order: branch_order.to_vec(),
        }
    }

    pub fn probe_branch_event_data(
        &self,
        target: &str,
        port: u16,
        planned_probe_preferred_ttl: u8,
        planned_probe_budget: usize,
        planned_probe_ttl_candidates: &[u8],
        branch_order: &[String],
    ) -> DirectProbeBranchEventData {
        DirectProbeBranchEventData {
            message: "preferring probe-aligned direct branch before relay escalation",
            trace: self.probe_branch_trace_context(
                planned_probe_preferred_ttl,
                planned_probe_budget,
                planned_probe_ttl_candidates,
                branch_order,
            ),
            runtime_fields: self.probe_branch_runtime_fields(
                target,
                port,
                planned_probe_preferred_ttl,
                planned_probe_budget,
                planned_probe_ttl_candidates,
                branch_order,
            ),
        }
    }

    pub fn active_stall_probe_retry_event_data(
        &self,
        endpoint: RuntimeEndpoint<'_>,
        signal: &FailSignal,
        plan: ActiveStallProbePlanContext<'_>,
        probe_terminal_stage: Option<&'static str>,
    ) -> ActiveStallProbeRetryEventData {
        let decision = active_probe_result_health_decision(signal);
        let trace = ActiveStallProbeRetryTraceContext {
            signal: format!("{signal:?}"),
            probe_outcome_class: ActiveStallProbeOutcomeClass::from_signal(signal).as_str(),
            direct_path_health_tier: decision.tier.as_str(),
            direct_path_health_reason_code: decision.reason_code.as_str(),
            observation_contract: self.observation_contract.as_str(),
            observation_capture_confidence: self
                .latest_observation
                .as_ref()
                .map(KeyObservation::observation_capture_confidence)
                .unwrap_or(self.observation_contract.as_str()),
            probe_history_disposition: self.probe_history_disposition.as_str(),
            probe_history_reason_code: self.probe_history_reason_code.as_str(),
            cross_session_signal_bias: self.cross_session_signal_bias(),
            cross_session_confidence_score: self.cross_session_signal_metrics.confidence_score,
            cross_session_reuse_weight: self.cross_session_signal_metrics.reuse_weight,
            cross_session_stall_severity: self.cross_session_signal_metrics.stall_severity,
            cross_session_probe_branch_score: self.cross_session_signal_metrics.probe_branch_score,
            cross_session_relay_preference_score: self
                .cross_session_signal_metrics
                .relay_preference_score,
            planned_probe_preferred_ttl: plan.preferred_ttl,
            planned_probe_budget: plan.budget,
            planned_probe_ttl_candidates: plan.ttl_candidates.to_vec(),
            probe_terminal_stage,
        };
        ActiveStallProbeRetryEventData {
            message: "active stall probe recovered path confidence, retrying direct session once",
            runtime_fields: json!({
                "target": endpoint.target,
                "port": endpoint.port,
                "signal": trace.signal,
                "probe_outcome_class": trace.probe_outcome_class,
                "direct_path_health_tier": trace.direct_path_health_tier,
                "direct_path_health_reason_code": trace.direct_path_health_reason_code,
                "observation_contract": trace.observation_contract,
                "observation_capture_confidence": trace.observation_capture_confidence,
                "probe_history_disposition": trace.probe_history_disposition,
                "probe_history_reason_code": trace.probe_history_reason_code,
                "cross_session_signal_bias": trace.cross_session_signal_bias,
                "cross_session_confidence_score": trace.cross_session_confidence_score,
                "cross_session_reuse_weight": trace.cross_session_reuse_weight,
                "cross_session_stall_severity": trace.cross_session_stall_severity,
                "cross_session_probe_branch_score": trace.cross_session_probe_branch_score,
                "cross_session_relay_preference_score": trace.cross_session_relay_preference_score,
                "planned_probe_preferred_ttl": trace.planned_probe_preferred_ttl,
                "planned_probe_budget": trace.planned_probe_budget,
                "planned_probe_ttl_candidates": trace.planned_probe_ttl_candidates,
                "probe_terminal_stage": trace.probe_terminal_stage,
            }),
            trace,
        }
    }

    pub fn active_stall_probe_retry_skipped_event_data(
        &self,
        endpoint: RuntimeEndpoint<'_>,
        signal: &FailSignal,
        reason_code: ActiveStallProbeRetrySuppressedReasonCode,
        retry_budget: RetryBudgetContext,
        probe_terminal_stage: Option<&'static str>,
    ) -> ActiveStallProbeRetrySkippedEventData {
        let decision = retry_skipped_health_decision();
        let trace = ActiveStallProbeRetrySkippedTraceContext {
            signal: format!("{signal:?}"),
            probe_outcome_class: ActiveStallProbeOutcomeClass::from_signal(signal).as_str(),
            direct_path_health_tier: decision.tier.as_str(),
            direct_path_health_reason_code: decision.reason_code.as_str(),
            direct_path_degraded_before_terminal: signal.is_success(),
            direct_path_unstable_before_failover: true,
            observation_contract: self.observation_contract.as_str(),
            observation_capture_confidence: self
                .latest_observation
                .as_ref()
                .map(KeyObservation::observation_capture_confidence)
                .unwrap_or(self.observation_contract.as_str()),
            probe_history_disposition: self.probe_history_disposition.as_str(),
            probe_history_reason_code: self.probe_history_reason_code.as_str(),
            cross_session_signal_bias: self.cross_session_signal_bias(),
            cross_session_confidence_score: self.cross_session_signal_metrics.confidence_score,
            cross_session_reuse_weight: self.cross_session_signal_metrics.reuse_weight,
            cross_session_stall_severity: self.cross_session_signal_metrics.stall_severity,
            cross_session_probe_branch_score: self.cross_session_signal_metrics.probe_branch_score,
            cross_session_relay_preference_score: self
                .cross_session_signal_metrics
                .relay_preference_score,
            retry_suppressed_reason_code: reason_code.as_str(),
            retry_attempts_used: retry_budget.attempts_used,
            retry_attempts_budget: retry_budget.attempts_budget,
            probe_terminal_stage,
        };
        ActiveStallProbeRetrySkippedEventData {
            message: "active stall probe did not justify another direct retry",
            runtime_fields: json!({
                "target": endpoint.target,
                "port": endpoint.port,
                "signal": trace.signal,
                "probe_outcome_class": trace.probe_outcome_class,
                "direct_path_health_tier": trace.direct_path_health_tier,
                "direct_path_health_reason_code": trace.direct_path_health_reason_code,
                "direct_path_degraded_before_terminal": trace.direct_path_degraded_before_terminal,
                "direct_path_unstable_before_failover": trace.direct_path_unstable_before_failover,
                "observation_contract": trace.observation_contract,
                "observation_capture_confidence": trace.observation_capture_confidence,
                "probe_history_disposition": trace.probe_history_disposition,
                "probe_history_reason_code": trace.probe_history_reason_code,
                "cross_session_signal_bias": trace.cross_session_signal_bias,
                "cross_session_confidence_score": trace.cross_session_confidence_score,
                "cross_session_reuse_weight": trace.cross_session_reuse_weight,
                "cross_session_stall_severity": trace.cross_session_stall_severity,
                "cross_session_probe_branch_score": trace.cross_session_probe_branch_score,
                "cross_session_relay_preference_score": trace.cross_session_relay_preference_score,
                "retry_suppressed_reason_code": trace.retry_suppressed_reason_code,
                "retry_attempts_used": trace.retry_attempts_used,
                "retry_attempts_budget": trace.retry_attempts_budget,
                "probe_terminal_stage": trace.probe_terminal_stage,
            }),
            trace,
        }
    }
}
