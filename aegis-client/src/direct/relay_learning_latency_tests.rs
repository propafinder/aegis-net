use super::*;

#[tokio::test]
async fn actual_relay_owner_long_lifetime_does_not_become_hybrid_learning_latency() {
    let witness = relay::latency_tests::actual_held_relay_outcome().await;
    let store = aegis_core::AsyncStateStore::ephemeral();
    let brain = Brain::new(0.0, vec!["legacy_tls".into()], store.clone());
    let key = StrategyKey::for_target(
        "203.0.113.51:443".parse().unwrap(),
        "latency.fixture.invalid",
        443,
        None,
        true,
    );
    brain
        .record_hybrid_route_attempt(&key, HybridRouteFamily::RelayGrpc)
        .await;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    tx.send(witness.outcome).unwrap();
    drop(tx);
    assert!(learn_relay_handoff_outcomes(&brain, &key, &mut rx, &Ok(())).await);
    let snapshot = store.snapshot().await;
    assert_eq!(snapshot.strategy_stats.len(), 1);
    let stats = snapshot.strategy_stats.values().next().unwrap();
    assert_eq!((stats.trials, stats.successes, stats.dpi_blocks), (1, 1, 0));
    let route = snapshot.hybrid_route_stats.get(&key.hash_key()).unwrap();
    assert_eq!(
        (
            route.relay_attempts,
            route.relay_successes,
            route.relay_failures
        ),
        (1, 1, 0)
    );
    assert!(
        stats.mean_latency_ms <= witness.first_reply_upper.as_millis() as f64 * 0.1,
        "actual hybrid learner must measure opening, not held session: mean={} phase_upper={:?}",
        stats.mean_latency_ms,
        witness.first_reply_upper
    );
}
