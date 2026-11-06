use crate::state_v2::{KeyObservation, ObservationContract};
use rand::Rng;

use super::advisory::{direct_session_advisory_from_snapshot, probe_history_strategy_bias};
use super::context::decision_context_from_snapshot;
use super::estimation::estimate_strategy;
use super::explanation::{
    DirectPlannerCandidateTrace, DirectPlannerSelectionTrace, RecentSelectionTrace,
};
use super::observation::resolve_effective_key;
use super::selection::{compare_ranked, ucb1_exploration_bonus, ucb1_score, RankedStrategy};
use super::{Brain, ProbeHistoryDisposition, ProbeHistoryReasonCode, StrategyKey};

impl Brain {
    /// Возвращает порядок имён стратегий для попыток.
    ///
    /// Селектор остаётся epsilon-greedy по внешнему контуру, но exploitation-path
    /// использует UCB-подобную эвристику на базе exact + context-similar state,
    /// а не статический локальный score без учёта объёма наблюдений.
    pub async fn select_order(&self, key: &StrategyKey) -> Vec<String> {
        self.select_order_trace(key).await.reward_selected_order
    }

    pub async fn select_order_trace(&self, key: &StrategyKey) -> DirectPlannerSelectionTrace {
        let mut trace = self.select_order_trace_baseline(key).await;
        let Some(recent) = &self.recent_routes else {
            return trace;
        };
        let eligible = self
            .preferred_order
            .iter()
            .map(|strategy| super::recent_routes::EligibleRoute {
                strategy: strategy.clone(),
                failure_domain: self.recent_failure_domains.get(strategy).cloned(),
            })
            .collect::<Vec<_>>();
        let baseline_selector_mode = trace.selector_mode;
        let baseline_selected_order = trace.reward_selected_order.clone();
        let mut recent = recent.lock().await;
        let selected = self
            .select_recent_order_from_baseline(
                key,
                &mut recent,
                &eligible,
                &baseline_selected_order,
            )
            .await;
        let (selection, selection_error) = match selected {
            Ok(selection) => (selection, None),
            Err(_) => (
                super::recent_routes::RecentSelection {
                    order: Vec::new(),
                    ranked: Vec::new(),
                    scope: "recent selector refused; empty fail-closed order",
                },
                Some("recent_selection_refused"),
            ),
        };
        trace.reward_selected_order = selection.order.clone();
        trace.selector_mode = recent.mode_name();
        trace.explainability_trace_source = "bounded_recent_runtime_outcomes";
        trace.recent_selection = Some(RecentSelectionTrace {
            baseline_selector_mode,
            baseline_selected_order,
            selection,
            selection_error,
        });
        trace
    }

    /// Original selector, shared by both wrappers without recursive opt-in entry.
    pub(super) async fn select_order_trace_baseline(
        &self,
        key: &StrategyKey,
    ) -> DirectPlannerSelectionTrace {
        let snapshot = self.state.snapshot().await;
        let decision_context = decision_context_from_snapshot(&snapshot, key);
        let effective_key = resolve_effective_key(&snapshot, key, None);
        let base_key_hash = key.hash_key();
        let effective_key_hash = effective_key.hash_key();
        if rand::random::<f64>() < self.epsilon {
            let mut shuffled = self
                .preferred_order
                .iter()
                .filter(|strategy| {
                    !estimate_strategy(
                        &snapshot,
                        key,
                        &effective_key,
                        &base_key_hash,
                        &effective_key_hash,
                        strategy,
                        &decision_context,
                    )
                    .belief
                    .hard_blocked
                })
                .cloned()
                .collect::<Vec<_>>();
            {
                let mut rng = rand::thread_rng();
                for i in (1..shuffled.len()).rev() {
                    let j = rng.gen_range(0..=i);
                    shuffled.swap(i, j);
                }
            }
            return DirectPlannerSelectionTrace {
                selector_mode: "epsilon_randomized_preferred_order",
                explainability_trace_source: "runtime_randomized_preferred_order",
                explainability_observation_source: "no_advisory_observation",
                decision_context,
                observation_contract: ObservationContract::RuntimeOnly.as_str(),
                observation_capture_confidence: ObservationContract::RuntimeOnly.as_str(),
                probe_history_disposition: ProbeHistoryDisposition::None.as_str(),
                probe_history_reason_code: ProbeHistoryReasonCode::NoRecentProbeHistory.as_str(),
                cross_session_signal_bias: "neutral_advisory_bias",
                cross_session_confidence_score: 0.0,
                cross_session_reuse_weight: 0.0,
                cross_session_stall_severity: 0.0,
                cross_session_probe_branch_score: 0.0,
                cross_session_relay_preference_score: 0.0,
                reward_selected_order: shuffled,
                ranked_candidates: Vec::new(),
                recent_selection: None,
            };
        }

        let advisory = direct_session_advisory_from_snapshot(&snapshot, key);
        let mut scored: Vec<RankedStrategy> = self
            .preferred_order
            .iter()
            .enumerate()
            .map(|(index, name)| {
                let estimate = estimate_strategy(
                    &snapshot,
                    key,
                    &effective_key,
                    &base_key_hash,
                    &effective_key_hash,
                    name,
                    &decision_context,
                );
                let probe_bias = probe_history_strategy_bias(
                    advisory.cross_session_signal_metrics,
                    advisory.latest_observation.as_ref(),
                    name,
                );
                let selection_score_ucb_exploration_bonus =
                    ucb1_exploration_bonus(estimate.exploration_trials, estimate.total_trials);
                let selection_score = ucb1_score(
                    estimate.reward,
                    estimate.exploration_trials,
                    estimate.total_trials,
                ) + probe_bias;
                RankedStrategy {
                    index,
                    name: name.clone(),
                    score: selection_score,
                    trials: estimate.trials,
                    estimated_reward: estimate.reward,
                    total_trials: estimate.total_trials,
                    probe_history_strategy_bias: probe_bias,
                    belief: estimate.belief,
                    selection_score_ucb_exploration_bonus,
                }
            })
            .collect();
        scored.sort_by(compare_ranked);
        let observation_capture_confidence = advisory
            .latest_observation
            .as_ref()
            .map(KeyObservation::observation_capture_confidence)
            .unwrap_or(advisory.observation_contract.as_str());
        DirectPlannerSelectionTrace {
            selector_mode: "ucb1_contextual_reward",
            explainability_trace_source: "state_snapshot_contextual_reward",
            explainability_observation_source: if advisory.latest_observation.is_some() {
                "advisory_state_snapshot_observation"
            } else {
                "no_advisory_observation"
            },
            decision_context,
            observation_contract: advisory.observation_contract.as_str(),
            observation_capture_confidence,
            probe_history_disposition: advisory.probe_history_disposition.as_str(),
            probe_history_reason_code: advisory.probe_history_reason_code.as_str(),
            cross_session_signal_bias: advisory.cross_session_signal_bias(),
            cross_session_confidence_score: advisory.cross_session_signal_metrics.confidence_score,
            cross_session_reuse_weight: advisory.cross_session_signal_metrics.reuse_weight,
            cross_session_stall_severity: advisory.cross_session_signal_metrics.stall_severity,
            cross_session_probe_branch_score: advisory
                .cross_session_signal_metrics
                .probe_branch_score,
            cross_session_relay_preference_score: advisory
                .cross_session_signal_metrics
                .relay_preference_score,
            reward_selected_order: scored
                .iter()
                .filter(|item| !item.belief.hard_blocked)
                .map(|item| item.name.clone())
                .collect(),
            recent_selection: None,
            ranked_candidates: scored
                .into_iter()
                .map(|item| DirectPlannerCandidateTrace {
                    strategy: item.name,
                    estimated_reward: item.estimated_reward,
                    estimated_trials: item.trials,
                    total_trials: item.total_trials,
                    probe_history_strategy_bias: item.probe_history_strategy_bias,
                    belief_alpha: item.belief.alpha,
                    belief_beta: item.belief.beta,
                    belief_detection_risk: item.belief.detection_risk,
                    belief_latency_cost: item.belief.latency_cost,
                    belief_confidence: item.belief.confidence,
                    belief_freshness: item.belief.freshness,
                    belief_hard_blocked: item.belief.hard_blocked,
                    belief_source: item.belief.source,
                    selection_score_reward_component: item.estimated_reward,
                    selection_score_ucb_exploration_bonus: item
                        .selection_score_ucb_exploration_bonus,
                    selection_score_probe_bias_component: item.probe_history_strategy_bias,
                    selection_score: item.score.is_finite().then_some(item.score),
                    cold_start_exploration: item.trials <= f64::EPSILON,
                })
                .collect(),
        }
    }
}
