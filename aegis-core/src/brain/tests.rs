use super::*;

#[test]
fn direct_session_health_decision_distinguishes_healthy_and_degraded_success() {
    let healthy = direct_session_health_decision(&FailSignal::Success);
    assert_eq!(healthy.tier, DirectPathHealthTier::Healthy);
    assert_eq!(healthy.reason_code.as_str(), "successful_direct_path");

    let degraded = direct_session_health_decision(&FailSignal::SuccessDegraded);
    assert_eq!(degraded.tier, DirectPathHealthTier::Degraded);
    assert_eq!(degraded.reason_code.as_str(), "success_latency_degraded");
}

#[test]
fn active_probe_health_decision_keeps_recovered_probe_off_healthy_baseline() {
    let recovered = active_probe_result_health_decision(&FailSignal::Success);
    assert_eq!(recovered.tier, DirectPathHealthTier::Degraded);
    assert_eq!(
        recovered.reason_code.as_str(),
        "active_probe_recovered_path"
    );

    let failed = active_probe_result_health_decision(&FailSignal::ThroughputCollapse);
    assert_eq!(failed.tier, DirectPathHealthTier::Unstable);
    assert_eq!(
        failed.reason_code.as_str(),
        "active_probe_signal_not_successful"
    );
}

#[test]
fn terminal_health_decisions_remain_unstable() {
    let failover = direct_failover_health_decision();
    assert_eq!(failover.tier, DirectPathHealthTier::Unstable);
    assert_eq!(
        failover.reason_code.as_str(),
        "direct_relay_failover_triggered"
    );

    let retry_budget = retry_budget_exhausted_health_decision();
    assert_eq!(retry_budget.tier, DirectPathHealthTier::Unstable);
    assert_eq!(
        retry_budget.reason_code.as_str(),
        "probe_retry_budget_exhausted"
    );

    let retry_skipped = retry_skipped_health_decision();
    assert_eq!(retry_skipped.tier, DirectPathHealthTier::Unstable);
    assert_eq!(retry_skipped.reason_code.as_str(), "probe_retry_suppressed");
}

fn reconciliation_key(host: &str) -> StrategyKey {
    StrategyKey::for_target("203.0.113.9:443".parse().unwrap(), host, 443, None, true)
}

fn reconciliation_stats(successes: u64) -> crate::state_v2::StrategyStatsV2 {
    crate::state_v2::StrategyStatsV2 {
        trials: 4,
        successes,
        fitness_score: successes as f64 / 4.0,
        ..Default::default()
    }
}

fn reconciliation_estimate(
    snapshot: &crate::state_v2::StateSnapshot,
    key: &StrategyKey,
    effective: &StrategyKey,
) -> super::selection::StrategyEstimate {
    super::estimation::estimate_strategy(
        snapshot,
        key,
        effective,
        &key.hash_key(),
        &effective.hash_key(),
        "geneva",
        &super::context::decision_context_from_snapshot(snapshot, key),
    )
}

fn reconciliation_runtime_mean(belief: &StrategyBelief) -> f64 {
    (belief.alpha - 1.0) / (belief.alpha + belief.beta - 2.0)
}

fn reconciliation_close(actual: f64, expected: f64) {
    assert!(
        (actual - expected).abs() < 1e-12,
        "actual {actual}, expected {expected}"
    );
}

#[test]
fn documentation_reconciliation_exact_trust_changes_confidence_not_success_reward() {
    let key = reconciliation_key("exact.example.invalid");
    let hash = key.hash_key();
    let mut snapshot = crate::state_v2::StateSnapshot::default();
    snapshot
        .strategy_stats
        .insert(strategy_entry_key(&hash, "geneva"), reconciliation_stats(4));
    let trusted = reconciliation_estimate(&snapshot, &key, &key);
    snapshot
        .key_observations
        .insert(hash, KeyObservation::default());
    let lower_trust = reconciliation_estimate(&snapshot, &key, &key);

    // No packet/runtime detail: packet factor 0.75 times runtime confidence 0.55.
    reconciliation_close(lower_trust.trials, 4.0 * 0.75 * 0.55);
    reconciliation_close(lower_trust.belief.confidence, lower_trust.trials / 8.0);
    assert!(lower_trust.belief.confidence < trusted.belief.confidence);
    reconciliation_close(reconciliation_runtime_mean(&trusted.belief), 1.0);
    reconciliation_close(reconciliation_runtime_mean(&lower_trust.belief), 1.0);
    reconciliation_close(lower_trust.belief.beta, 1.0);
    reconciliation_close(lower_trust.total_trials, 4.0);
}

#[test]
fn documentation_reconciliation_similar_trust_changes_confidence_not_success_reward() {
    let key = reconciliation_key("current.example.invalid");
    let similar = reconciliation_key("similar.example.invalid");
    let hash = similar.hash_key();
    let mut snapshot = crate::state_v2::StateSnapshot::default();
    snapshot.key_registry.insert(hash.clone(), similar);
    snapshot
        .strategy_stats
        .insert(strategy_entry_key(&hash, "geneva"), reconciliation_stats(4));
    snapshot
        .key_observations
        .insert(hash, KeyObservation::default());
    let estimate = reconciliation_estimate(&snapshot, &key, &key);

    // Nine of ten context fields match; only the host hash differs.
    reconciliation_close(estimate.trials, 4.0 * 0.9 * 0.75 * 0.55);
    reconciliation_close(estimate.belief.confidence, estimate.trials / 8.0);
    reconciliation_close(reconciliation_runtime_mean(&estimate.belief), 1.0);
    reconciliation_close(estimate.belief.beta, 1.0);
    reconciliation_close(estimate.total_trials, 4.0);
}

#[test]
fn documentation_reconciliation_capture_trust_does_not_inflate_exploration() {
    let key = reconciliation_key("current.example.invalid");
    let similar = reconciliation_key("similar.example.invalid");
    let hash = similar.hash_key();
    let mut snapshot = crate::state_v2::StateSnapshot::default();
    snapshot.key_registry.insert(hash.clone(), similar);
    snapshot
        .strategy_stats
        .insert(strategy_entry_key(&hash, "geneva"), reconciliation_stats(4));
    let trusted = reconciliation_estimate(&snapshot, &key, &key);
    snapshot
        .key_observations
        .insert(hash, KeyObservation::default());
    let lower_trust = reconciliation_estimate(&snapshot, &key, &key);

    // Capture trust reduces confidence mass, not the nominal exploration count.
    reconciliation_close(trusted.exploration_trials, 4.0 * 0.9);
    reconciliation_close(lower_trust.exploration_trials, trusted.exploration_trials);
    reconciliation_close(trusted.trials, 4.0 * 0.9);
    reconciliation_close(lower_trust.trials, 4.0 * 0.9 * 0.75 * 0.55);
    assert!(lower_trust.belief.confidence < trusted.belief.confidence);
    reconciliation_close(reconciliation_runtime_mean(&trusted.belief), 1.0);
    reconciliation_close(reconciliation_runtime_mean(&lower_trust.belief), 1.0);
    reconciliation_close(lower_trust.total_trials, trusted.total_trials);
    reconciliation_close(
        super::selection::ucb1_exploration_bonus(
            lower_trust.exploration_trials,
            lower_trust.total_trials,
        )
        .unwrap(),
        super::selection::ucb1_exploration_bonus(trusted.exploration_trials, trusted.total_trials)
            .unwrap(),
    );
}

#[test]
fn documentation_reconciliation_mixed_context_uses_normalized_trusted_weights() {
    let key = reconciliation_key("current.example.invalid");
    let similar = reconciliation_key("similar.example.invalid");
    let hash = similar.hash_key();
    let mut snapshot = crate::state_v2::StateSnapshot::default();
    snapshot.strategy_stats.insert(
        strategy_entry_key(&key.hash_key(), "geneva"),
        reconciliation_stats(4),
    );
    snapshot.key_registry.insert(hash.clone(), similar);
    snapshot
        .strategy_stats
        .insert(strategy_entry_key(&hash, "geneva"), reconciliation_stats(0));
    snapshot
        .key_observations
        .insert(hash, KeyObservation::default());
    let estimate = reconciliation_estimate(&snapshot, &key, &key);

    let similar_weight = 0.9 * 0.75 * 0.55;
    let expected_mean = 1.0 / (1.0 + similar_weight);
    reconciliation_close(reconciliation_runtime_mean(&estimate.belief), expected_mean);
    reconciliation_close(estimate.trials, 4.0 * (1.0 + similar_weight));
    reconciliation_close(estimate.belief.confidence, estimate.trials / 8.0);
    reconciliation_close(estimate.total_trials, 8.0);
}

#[test]
fn documentation_reconciliation_effective_key_applies_trust_to_all_accumulators() {
    let key = reconciliation_key("current.example.invalid");
    let mut effective = key.clone();
    effective.server_signature_hash = Some(1);
    let mut snapshot = crate::state_v2::StateSnapshot::default();
    for row in [&key, &effective] {
        snapshot.strategy_stats.insert(
            strategy_entry_key(&row.hash_key(), "geneva"),
            reconciliation_stats(4),
        );
    }
    snapshot
        .key_observations
        .insert(effective.hash_key(), KeyObservation::default());
    let estimate = reconciliation_estimate(&snapshot, &key, &effective);

    reconciliation_close(estimate.trials, 4.0 * (1.0 + 1.25 * 0.75 * 0.55));
    reconciliation_close(estimate.belief.confidence, estimate.trials / 8.0);
    reconciliation_close(reconciliation_runtime_mean(&estimate.belief), 1.0);
    reconciliation_close(estimate.belief.beta, 1.0);
    reconciliation_close(estimate.total_trials, 8.0);
}

async fn reconciliation_brain(
    epsilon: f64,
    prior_names: &[&str],
    confidence: f64,
    generated_at_unix_ms: Option<u64>,
) -> Brain {
    let state = AsyncStateStore::ephemeral();
    state
        .update(|snapshot| {
            snapshot.external_calibration = Some(crate::ExternalCalibrationSnapshot {
                knowledge: prior_names
                    .iter()
                    .map(|name| crate::ExternalKnowledgePrior {
                        target_class: (*name).into(),
                        score: 0.0,
                        confidence,
                        hard_excluded: true,
                        fail_closed: true,
                        generated_at_unix_ms,
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            });
        })
        .await;
    Brain::new(epsilon, vec!["blocked".into(), "allowed".into()], state)
}

#[tokio::test]
async fn documentation_reconciliation_epsilon_never_selects_hard_blocked_candidate() {
    let brain = reconciliation_brain(1.0, &["blocked"], 0.9, None).await;
    let trace = brain.select_order_trace(&StrategyKey::for_dst(4)).await;
    assert_eq!(trace.selector_mode, "epsilon_randomized_preferred_order");
    assert_eq!(trace.reward_selected_order, vec!["allowed"]);
    assert!(trace.ranked_candidates.is_empty());
    assert!(trace.recent_selection.is_none());
}

#[tokio::test]
async fn documentation_reconciliation_exploitation_excludes_block_but_retains_trace() {
    let brain = reconciliation_brain(0.0, &["blocked"], 0.9, None).await;
    let trace = brain.select_order_trace(&StrategyKey::for_dst(4)).await;
    assert_eq!(trace.selector_mode, "ucb1_contextual_reward");
    assert_eq!(trace.reward_selected_order, vec!["allowed"]);
    let blocked = trace
        .ranked_candidates
        .iter()
        .find(|candidate| candidate.strategy == "blocked")
        .unwrap();
    assert!(blocked.belief_hard_blocked);
    assert!(trace.recent_selection.is_none());
}

#[tokio::test]
async fn documentation_reconciliation_all_hard_blocked_produces_empty_order() {
    for epsilon in [0.0, 1.0] {
        let brain = reconciliation_brain(epsilon, &["blocked", "allowed"], 0.9, None).await;
        let trace = brain.select_order_trace(&StrategyKey::for_dst(4)).await;
        assert!(trace.reward_selected_order.is_empty());
        assert!(trace.recent_selection.is_none());
    }
}

#[tokio::test]
async fn documentation_reconciliation_soft_or_stale_prior_keeps_candidate_admitted() {
    for epsilon in [0.0, 1.0] {
        for (confidence, timestamp) in [(0.84, None), (0.9, Some(1))] {
            let brain = reconciliation_brain(epsilon, &["blocked"], confidence, timestamp).await;
            let trace = brain.select_order_trace(&StrategyKey::for_dst(4)).await;
            let selected = trace
                .reward_selected_order
                .iter()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(
                selected,
                std::collections::BTreeSet::from(["allowed", "blocked"])
            );
        }
    }
}

#[tokio::test]
async fn documentation_reconciliation_no_calibration_keeps_configured_candidates() {
    for epsilon in [0.0, 1.0] {
        let brain = Brain::new(
            epsilon,
            vec!["first".into(), "second".into()],
            AsyncStateStore::ephemeral(),
        );
        let trace = brain.select_order_trace(&StrategyKey::for_dst(4)).await;
        let selected = trace
            .reward_selected_order
            .iter()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            selected,
            std::collections::BTreeSet::from(["first", "second"])
        );
        if epsilon == 1.0 {
            assert!(trace.ranked_candidates.is_empty());
        }
    }
}
