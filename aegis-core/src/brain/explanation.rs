use serde_json::Value;

use crate::state_v2::{KeyObservation, ObservationContract, StallProbeStats};

use super::DecisionContext;

#[derive(Debug, Clone)]
pub struct DirectSessionAdvisory {
    pub latest_observation: Option<KeyObservation>,
    pub latest_probe_stats: Option<StallProbeStats>,
    pub observation_contract: ObservationContract,
    pub probe_history_disposition: super::ProbeHistoryDisposition,
    pub probe_history_reason_code: super::ProbeHistoryReasonCode,
    pub cross_session_signal_metrics: CrossSessionSignalMetrics,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CrossSessionSignalMetrics {
    pub confidence_score: f64,
    pub reuse_weight: f64,
    pub stall_severity: f64,
    pub probe_branch_score: f64,
    pub relay_preference_score: f64,
}

#[derive(Debug, Clone)]
pub struct DirectRelayPreferenceTraceContext {
    pub probe_history_disposition: &'static str,
    pub probe_history_reason_code: &'static str,
    pub observation_contract: &'static str,
    pub observation_capture_confidence: &'static str,
    pub cross_session_signal_bias: &'static str,
    pub cross_session_confidence_score: f64,
    pub cross_session_reuse_weight: f64,
    pub cross_session_stall_severity: f64,
    pub cross_session_probe_branch_score: f64,
    pub cross_session_relay_preference_score: f64,
    pub stall_probe_trials: u64,
    pub stall_probe_freezes: u64,
    pub stall_probe_collapses: u64,
    pub stall_probe_timeouts: u64,
    pub last_probe_signal: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DirectProbeBranchTraceContext {
    pub probe_history_disposition: &'static str,
    pub probe_history_reason_code: &'static str,
    pub observation_contract: &'static str,
    pub observation_capture_confidence: &'static str,
    pub cross_session_signal_bias: &'static str,
    pub cross_session_confidence_score: f64,
    pub cross_session_reuse_weight: f64,
    pub cross_session_stall_severity: f64,
    pub cross_session_probe_branch_score: f64,
    pub cross_session_relay_preference_score: f64,
    pub server_hint: Option<&'static str>,
    pub fingerprint_window_hint: Option<&'static str>,
    pub planned_probe_preferred_ttl: u8,
    pub planned_probe_budget: usize,
    pub planned_probe_ttl_candidates: Vec<u8>,
    pub branch_order: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DirectRelayPreferenceEventData {
    pub message: &'static str,
    pub trace: DirectRelayPreferenceTraceContext,
    pub runtime_fields: Value,
}

#[derive(Debug, Clone)]
pub struct DirectProbeBranchEventData {
    pub message: &'static str,
    pub trace: DirectProbeBranchTraceContext,
    pub runtime_fields: Value,
}

#[derive(Debug, Clone)]
pub struct DirectPlannerCandidateTrace {
    pub strategy: String,
    pub estimated_reward: f64,
    pub estimated_trials: f64,
    pub total_trials: f64,
    pub probe_history_strategy_bias: f64,
    pub belief_alpha: f64,
    pub belief_beta: f64,
    pub belief_detection_risk: f64,
    pub belief_latency_cost: f64,
    pub belief_confidence: f64,
    pub belief_freshness: f64,
    pub belief_hard_blocked: bool,
    pub belief_source: &'static str,
    pub selection_score_reward_component: f64,
    pub selection_score_ucb_exploration_bonus: Option<f64>,
    pub selection_score_probe_bias_component: f64,
    pub selection_score: Option<f64>,
    pub cold_start_exploration: bool,
}

#[derive(Debug, Clone)]
pub struct DirectPlannerSelectionTrace {
    pub selector_mode: &'static str,
    pub explainability_trace_source: &'static str,
    pub explainability_observation_source: &'static str,
    pub decision_context: DecisionContext,
    pub observation_contract: &'static str,
    pub observation_capture_confidence: &'static str,
    pub probe_history_disposition: &'static str,
    pub probe_history_reason_code: &'static str,
    pub cross_session_signal_bias: &'static str,
    pub cross_session_confidence_score: f64,
    pub cross_session_reuse_weight: f64,
    pub cross_session_stall_severity: f64,
    pub cross_session_probe_branch_score: f64,
    pub cross_session_relay_preference_score: f64,
    pub reward_selected_order: Vec<String>,
    /// Original contextual/epsilon snapshot evidence. When recent_selection is
    /// present its separate ranks explain the resulting selected order.
    pub ranked_candidates: Vec<DirectPlannerCandidateTrace>,
    pub recent_selection: Option<RecentSelectionTrace>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RecentSelectionTrace {
    pub baseline_selector_mode: &'static str,
    pub baseline_selected_order: Vec<String>,
    pub selection: super::recent_routes::RecentSelection,
    /// Generic refusal code only; never raw target/context or caller input.
    pub selection_error: Option<&'static str>,
}

#[derive(Debug, Clone)]
pub struct DirectSessionSucceededTraceContext {
    pub strategy: String,
    pub signal: String,
    pub probe_outcome_class: &'static str,
    pub direct_path_health_tier: &'static str,
    pub direct_path_health_reason_code: &'static str,
    pub observation_contract: &'static str,
    pub observation_capture_confidence: &'static str,
    pub probe_history_disposition: &'static str,
    pub probe_history_reason_code: &'static str,
    pub capture_status: String,
    pub reference_path_hops: Option<u8>,
    pub rst_path_hops: Option<u8>,
    pub server_hint: Option<&'static str>,
    pub fingerprint_window_hint: Option<&'static str>,
    pub first_response_bytes: usize,
    pub relay_client_to_remote_bytes: usize,
    pub relay_remote_to_client_bytes: usize,
    pub relay_lifetime_ms: u64,
    pub latency_ms: u64,
    pub bytes_sent: usize,
    pub active_stall_probe_retry_attempted: bool,
    pub retry_attempts_used: usize,
}

#[derive(Debug, Clone)]
pub struct DirectSessionSucceededEventData {
    pub message: &'static str,
    pub trace: DirectSessionSucceededTraceContext,
    pub runtime_fields: Value,
}

#[derive(Debug, Clone)]
pub struct ActiveStallProbeLaunchedTraceContext {
    pub signal: String,
    pub observation_contract: &'static str,
    pub direct_path_health_tier: &'static str,
    pub direct_path_health_reason_code: &'static str,
    pub planned_probe_preferred_ttl: u8,
    pub planned_probe_budget: usize,
    pub planned_probe_ttl_candidates: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ActiveStallProbeLaunchedEventData {
    pub message: &'static str,
    pub trace: ActiveStallProbeLaunchedTraceContext,
    pub runtime_fields: Value,
}

#[derive(Debug, Clone)]
pub struct ActiveStallProbeFinishedTraceContext {
    pub signal: String,
    pub probe_outcome_class: &'static str,
    pub direct_path_health_tier: &'static str,
    pub direct_path_health_reason_code: &'static str,
    pub observation_contract: &'static str,
    pub observation_capture_confidence: &'static str,
    pub capture_status: String,
    pub reference_path_hops: Option<u8>,
    pub rst_path_hops: Option<u8>,
    pub server_hint: Option<&'static str>,
    pub fingerprint_window_hint: Option<&'static str>,
    pub planned_probe_preferred_ttl: u8,
    pub planned_probe_budget: usize,
    pub planned_probe_ttl_candidates: Vec<u8>,
    pub first_response_bytes: usize,
    pub probe_terminal_stage: Option<&'static str>,
    pub latency_ms: u64,
}

#[derive(Debug, Clone)]
pub struct ActiveStallProbeFinishedEventData {
    pub message: &'static str,
    pub trace: ActiveStallProbeFinishedTraceContext,
    pub runtime_fields: Value,
}

#[derive(Debug, Clone)]
pub struct ActiveStallProbeRetryTraceContext {
    pub signal: String,
    pub probe_outcome_class: &'static str,
    pub direct_path_health_tier: &'static str,
    pub direct_path_health_reason_code: &'static str,
    pub observation_contract: &'static str,
    pub observation_capture_confidence: &'static str,
    pub probe_history_disposition: &'static str,
    pub probe_history_reason_code: &'static str,
    pub cross_session_signal_bias: &'static str,
    pub cross_session_confidence_score: f64,
    pub cross_session_reuse_weight: f64,
    pub cross_session_stall_severity: f64,
    pub cross_session_probe_branch_score: f64,
    pub cross_session_relay_preference_score: f64,
    pub planned_probe_preferred_ttl: u8,
    pub planned_probe_budget: usize,
    pub planned_probe_ttl_candidates: Vec<u8>,
    pub probe_terminal_stage: Option<&'static str>,
}

#[derive(Debug, Clone)]
pub struct ActiveStallProbeRetryEventData {
    pub message: &'static str,
    pub trace: ActiveStallProbeRetryTraceContext,
    pub runtime_fields: Value,
}

#[derive(Debug, Clone)]
pub struct DirectRelayFailoverTraceContext {
    pub signal: String,
    pub probe_outcome_class: &'static str,
    pub direct_path_health_tier: &'static str,
    pub direct_path_health_reason_code: &'static str,
    pub direct_path_degraded_before_terminal: bool,
    pub direct_path_unstable_before_failover: bool,
    pub observation_contract: &'static str,
    pub observation_capture_confidence: &'static str,
    pub direct_relay_failover_reason_code: &'static str,
    pub reference_path_hops: Option<u8>,
    pub rst_path_hops: Option<u8>,
    pub active_stall_probe_recommended: bool,
    pub active_stall_probe_retry_attempted: bool,
    pub probe_terminal_stage: Option<&'static str>,
}

#[derive(Debug, Clone)]
pub struct DirectRelayFailoverEventData {
    pub message: &'static str,
    pub trace: DirectRelayFailoverTraceContext,
    pub runtime_fields: Value,
}

#[derive(Debug, Clone)]
pub struct ActiveStallProbeRetryBudgetExhaustedTraceContext {
    pub signal: String,
    pub probe_outcome_class: &'static str,
    pub direct_path_health_tier: &'static str,
    pub direct_path_health_reason_code: &'static str,
    pub direct_path_degraded_before_terminal: bool,
    pub direct_path_unstable_before_failover: bool,
    pub observation_contract: &'static str,
    pub observation_capture_confidence: &'static str,
    pub reference_path_hops: Option<u8>,
    pub rst_path_hops: Option<u8>,
    pub retry_attempts_used: usize,
    pub retry_attempts_budget: usize,
    pub probe_terminal_stage: Option<&'static str>,
}

#[derive(Debug, Clone)]
pub struct ActiveStallProbeRetryBudgetExhaustedEventData {
    pub message: &'static str,
    pub trace: ActiveStallProbeRetryBudgetExhaustedTraceContext,
    pub runtime_fields: Value,
}

#[derive(Debug, Clone)]
pub struct ActiveStallProbeRetrySkippedTraceContext {
    pub signal: String,
    pub probe_outcome_class: &'static str,
    pub direct_path_health_tier: &'static str,
    pub direct_path_health_reason_code: &'static str,
    pub direct_path_degraded_before_terminal: bool,
    pub direct_path_unstable_before_failover: bool,
    pub observation_contract: &'static str,
    pub observation_capture_confidence: &'static str,
    pub probe_history_disposition: &'static str,
    pub probe_history_reason_code: &'static str,
    pub cross_session_signal_bias: &'static str,
    pub cross_session_confidence_score: f64,
    pub cross_session_reuse_weight: f64,
    pub cross_session_stall_severity: f64,
    pub cross_session_probe_branch_score: f64,
    pub cross_session_relay_preference_score: f64,
    pub retry_suppressed_reason_code: &'static str,
    pub retry_attempts_used: usize,
    pub retry_attempts_budget: usize,
    pub probe_terminal_stage: Option<&'static str>,
}

#[derive(Debug, Clone)]
pub struct ActiveStallProbeRetrySkippedEventData {
    pub message: &'static str,
    pub trace: ActiveStallProbeRetrySkippedTraceContext,
    pub runtime_fields: Value,
}

#[derive(Debug, Clone, Copy)]
pub struct RuntimeEndpoint<'a> {
    pub target: &'a str,
    pub port: u16,
}

#[derive(Debug, Clone, Copy)]
pub struct ActiveStallProbePlanContext<'a> {
    pub preferred_ttl: u8,
    pub budget: usize,
    pub ttl_candidates: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub struct RetryBudgetContext {
    pub attempts_used: usize,
    pub attempts_budget: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct ObservationPathContext {
    pub reference_path_hops: Option<u8>,
    pub rst_path_hops: Option<u8>,
}

#[derive(Debug, Clone, Copy)]
pub struct ActiveStallProbeFailoverContext {
    pub recommended: bool,
    pub retry_attempted: bool,
    pub terminal_stage: Option<&'static str>,
}

#[derive(Debug, Clone, Copy)]
pub struct DirectSessionSuccessMetrics {
    pub latency_ms: u64,
    pub bytes_sent: usize,
    pub retry_attempts_used: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct ActiveStallProbeFinishContext {
    pub latency_ms: u64,
    pub first_response_bytes: usize,
    pub terminal_stage: Option<&'static str>,
}
