//! Адаптивный выбор порядка стратегий: exploration + UCB1 selector + richer StrategyKey v2.

use crate::signals::classify::FailSignal;
use crate::state_v2::{AsyncStateStore, KeyObservation, StallProbeStats};

mod advisory;
mod advisory_methods;
mod belief;
pub mod carrier_failover;
mod context;
mod estimation;
mod event_data;
mod explanation;
mod health;
mod hybrid_route_learning;
mod key;
mod observation;
mod probe;
pub mod recent_routes;
mod scoring;
mod selection;
mod selection_methods;

use advisory::direct_session_advisory_from_snapshot;
pub use belief::StrategyBelief;
pub use context::DecisionContext;
pub use event_data::{
    active_stall_probe_finished_event_data, active_stall_probe_launched_event_data,
    active_stall_probe_retry_budget_exhausted_event_data, direct_relay_failover_event_data,
    direct_session_succeeded_event_data,
};
pub use explanation::{
    ActiveStallProbeFailoverContext, ActiveStallProbeFinishContext,
    ActiveStallProbeFinishedEventData, ActiveStallProbeFinishedTraceContext,
    ActiveStallProbeLaunchedEventData, ActiveStallProbeLaunchedTraceContext,
    ActiveStallProbePlanContext, ActiveStallProbeRetryBudgetExhaustedEventData,
    ActiveStallProbeRetryBudgetExhaustedTraceContext, ActiveStallProbeRetryEventData,
    ActiveStallProbeRetrySkippedEventData, ActiveStallProbeRetrySkippedTraceContext,
    ActiveStallProbeRetryTraceContext, CrossSessionSignalMetrics, DirectPlannerCandidateTrace,
    DirectPlannerSelectionTrace, DirectProbeBranchEventData, DirectProbeBranchTraceContext,
    DirectRelayFailoverEventData, DirectRelayFailoverTraceContext, DirectRelayPreferenceEventData,
    DirectRelayPreferenceTraceContext, DirectSessionAdvisory, DirectSessionSucceededEventData,
    DirectSessionSucceededTraceContext, DirectSessionSuccessMetrics, ObservationPathContext,
    RecentSelectionTrace, RetryBudgetContext, RuntimeEndpoint,
};
#[cfg(test)]
use health::{
    active_probe_result_health_decision, direct_failover_health_decision,
    direct_session_health_decision, retry_budget_exhausted_health_decision,
    retry_skipped_health_decision,
};
pub use health::{ActiveStallProbeOutcomeClass, DirectPathHealthTier};
pub use hybrid_route_learning::{
    hybrid_route_advisory_at, HybridEvidenceConfidence, HybridRouteAdvisory,
    HybridRouteSelectionReason,
};
pub use key::{
    ModeHint, NetworkHint, PacketStageHint, PathHopHint, ResetProfileHint, StrategyKey,
    TargetClass, TargetKind,
};
use observation::{resolve_effective_key, strategy_entry_key};
pub use probe::{
    ActiveStallProbeRetrySuppressedReasonCode, DirectRelayFailoverReasonCode,
    ProbeHistoryDisposition, ProbeHistoryReasonCode,
};

#[derive(Clone)]
pub struct Brain {
    pub epsilon: f64,
    pub preferred_order: Vec<String>,
    state: AsyncStateStore,
    /// Set once the first persist failure has been reported, so an unwritable
    /// state path costs one warning rather than one per relay attempt.
    persist_failure_reported: std::sync::Arc<std::sync::atomic::AtomicBool>,
    recent_routes: Option<std::sync::Arc<tokio::sync::Mutex<recent_routes::RecentRouteSelector>>>,
    recent_failure_domains: std::collections::BTreeMap<String, String>,
}

impl Brain {
    pub fn new(epsilon: f64, preferred_order: Vec<String>, state: AsyncStateStore) -> Self {
        Self {
            epsilon,
            preferred_order,
            state,
            persist_failure_reported: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
                false,
            )),
            recent_routes: None,
            recent_failure_domains: std::collections::BTreeMap::new(),
        }
    }

    /// Enable only by explicit native configuration; observations stay in
    /// bounded RAM and do not add new authorized strategies or destinations.
    pub fn with_recent_routes(
        mut self,
        settings: Option<&recent_routes::RecentRoutesSettings>,
    ) -> Result<Self, String> {
        self.recent_routes = None;
        self.recent_failure_domains.clear();
        if let Some(settings) = settings {
            let config = settings.validate(&self.preferred_order)?;
            self.recent_routes = Some(std::sync::Arc::new(tokio::sync::Mutex::new(
                recent_routes::RecentRouteSelector::new(config)?,
            )));
            self.recent_failure_domains = settings.failure_domains.clone();
        }
        Ok(self)
    }

    pub fn recent_routes_enabled(&self) -> bool {
        self.recent_routes.is_some()
    }

    /// Persist the snapshot, and say so loudly the first time it fails.
    ///
    /// This used to be `let _ = self.state.flush().await`. The fleet client
    /// runs under a unit with `ProtectHome=yes`, which makes `/root`
    /// inaccessible to the service, so every write to the configured state
    /// path failed and every failure was discarded. The client had been
    /// throwing away everything the Brain learned on each restart, for as long
    /// as that unit had been in place, with nothing in the logs and nothing in
    /// the events. Foreground runs wrote the file normally, which is why it
    /// looked healthy whenever anyone checked by hand.
    ///
    /// Still non-fatal: an unwritable state path must not stop a client from
    /// carrying traffic. But it must not be invisible either.
    async fn persist(&self) {
        use std::sync::atomic::Ordering;
        let Err(err) = self.state.flush().await else {
            return;
        };
        if !self.persist_failure_reported.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                event_code = "brain_state_persist_failed",
                error = %err,
                "could not persist Brain state; adaptive learning will be lost on restart \
                 (check that the state path is writable by the service — ProtectHome=yes \
                 hides /root from a systemd unit)"
            );
        }
    }

    pub async fn direct_session_advisory(&self, key: &StrategyKey) -> DirectSessionAdvisory {
        let snapshot = self.state.snapshot().await;
        direct_session_advisory_from_snapshot(&snapshot, key)
    }

    pub async fn record_success(
        &self,
        key: &StrategyKey,
        strategy: &str,
        handshake_ms: u64,
        bytes_sent: usize,
    ) {
        self.record_outcome(
            key,
            strategy,
            FailSignal::Success,
            Some(handshake_ms),
            bytes_sent,
            None,
        )
        .await;
    }

    pub async fn record_fail(
        &self,
        key: &StrategyKey,
        strategy: &str,
        signal: FailSignal,
        elapsed_ms: u64,
        bytes_sent: usize,
    ) {
        self.record_outcome(key, strategy, signal, Some(elapsed_ms), bytes_sent, None)
            .await;
    }

    pub async fn record_signal(
        &self,
        key: &StrategyKey,
        strategy: &str,
        signal: FailSignal,
        latency_ms: Option<u64>,
        bytes_sent: usize,
    ) {
        self.record_outcome(key, strategy, signal, latency_ms, bytes_sent, None)
            .await;
    }

    pub async fn record_outcome(
        &self,
        key: &StrategyKey,
        strategy: &str,
        signal: FailSignal,
        latency_ms: Option<u64>,
        bytes_sent: usize,
        observation: Option<KeyObservation>,
    ) {
        if let Some(recent) = &self.recent_routes {
            let progress_reward = if signal.is_success() && bytes_sent > 0 {
                1.0
            } else {
                0.0
            };
            // Names/context were validated at configuration; unknown outcomes
            // cannot become new candidates, and the bounded store is RAM-only.
            if self.preferred_order.iter().any(|name| name == strategy) {
                let _ = recent
                    .lock()
                    .await
                    .record(&key.hash_key(), strategy, progress_reward);
            }
        }
        let snapshot = self.state.snapshot().await;
        let effective_key = resolve_effective_key(&snapshot, key, observation.as_ref());
        let base_hash = key.hash_key();
        let effective_hash = effective_key.hash_key();
        let entry_key = strategy_entry_key(&effective_hash, strategy);
        self.state
            .update_touched(|snapshot, touched| {
                touched
                    .key_registry
                    .extend([base_hash.clone(), effective_hash.clone()]);
                snapshot.key_registry.insert(base_hash.clone(), key.clone());
                snapshot
                    .key_registry
                    .insert(effective_hash.clone(), effective_key.clone());
                if let Some(obs) = observation.clone() {
                    touched
                        .key_observations
                        .extend([base_hash.clone(), effective_hash.clone()]);
                    snapshot
                        .key_observations
                        .insert(base_hash.clone(), obs.clone());
                    snapshot
                        .key_observations
                        .insert(effective_hash.clone(), obs);
                }
                touched.strategy_stats.insert(entry_key.clone());
                snapshot
                    .strategy_stats
                    .entry(entry_key)
                    .or_default()
                    .record_with_observation(&signal, latency_ms, bytes_sent, observation.as_ref());
            })
            .await;
        self.persist().await;
    }

    pub async fn record_probe_observation(&self, key: &StrategyKey, observation: KeyObservation) {
        let snapshot = self.state.snapshot().await;
        let effective_key = resolve_effective_key(&snapshot, key, Some(&observation));
        let base_hash = key.hash_key();
        let effective_hash = effective_key.hash_key();
        self.state
            .update_touched(|snapshot, touched| {
                touched
                    .key_registry
                    .extend([base_hash.clone(), effective_hash.clone()]);
                snapshot.key_registry.insert(base_hash.clone(), key.clone());
                snapshot
                    .key_registry
                    .insert(effective_hash.clone(), effective_key.clone());
                touched
                    .key_observations
                    .extend([base_hash.clone(), effective_hash.clone()]);
                snapshot
                    .key_observations
                    .insert(base_hash.clone(), observation.clone());
                snapshot
                    .key_observations
                    .insert(effective_hash.clone(), observation.clone());
            })
            .await;
        self.persist().await;
    }

    pub async fn record_probe_result(
        &self,
        key: &StrategyKey,
        signal: FailSignal,
        latency_ms: Option<u64>,
        observation: KeyObservation,
    ) {
        let snapshot = self.state.snapshot().await;
        let effective_key = resolve_effective_key(&snapshot, key, Some(&observation));
        let base_hash = key.hash_key();
        let effective_hash = effective_key.hash_key();
        self.state
            .update_touched(|snapshot, touched| {
                touched
                    .key_registry
                    .extend([base_hash.clone(), effective_hash.clone()]);
                snapshot.key_registry.insert(base_hash.clone(), key.clone());
                snapshot
                    .key_registry
                    .insert(effective_hash.clone(), effective_key.clone());
                touched
                    .key_observations
                    .extend([base_hash.clone(), effective_hash.clone()]);
                snapshot
                    .key_observations
                    .insert(base_hash.clone(), observation.clone());
                snapshot
                    .key_observations
                    .insert(effective_hash.clone(), observation.clone());
                touched.stall_probe_stats.insert(base_hash.clone());
                snapshot
                    .stall_probe_stats
                    .entry(base_hash.clone())
                    .or_default()
                    .record(&signal, latency_ms);
            })
            .await;
        self.persist().await;
    }

    pub async fn latest_probe_stats(&self, key: &StrategyKey) -> Option<StallProbeStats> {
        let snapshot = self.state.snapshot().await;
        let base_hash = key.hash_key();
        snapshot.stall_probe_stats.get(&base_hash).cloned()
    }

    pub async fn latest_observation(&self, key: &StrategyKey) -> Option<KeyObservation> {
        let snapshot = self.state.snapshot().await;
        let base_hash = key.hash_key();
        let effective_key = resolve_effective_key(&snapshot, key, None);
        let effective_hash = effective_key.hash_key();
        snapshot
            .key_observations
            .get(&effective_hash)
            .or_else(|| snapshot.key_observations.get(&base_hash))
            .cloned()
    }
}

#[cfg(test)]
mod bounds_tests;

#[cfg(test)]
mod retention_tests;

#[cfg(test)]
mod tests;
