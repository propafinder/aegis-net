use super::*;

#[tokio::test]
async fn actual_relay_owner_long_lifetime_does_not_become_normal_learning_latency() {
    let witness = relay::latency_tests::actual_held_relay_outcome().await;
    let store = AsyncStateStore::ephemeral();
    let brain = Brain::new(0.0, vec!["legacy_tls".into()], store.clone());
    let key = StrategyKey::for_target(
        "203.0.113.51:443".parse().unwrap(),
        "latency.fixture.invalid",
        443,
        None,
        true,
    );
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    tx.send(witness.outcome).unwrap();
    drop(tx);
    let terminal = learn_relay_outcomes(&brain, &key, &mut rx).await.unwrap();
    assert_eq!(terminal.signal, aegis_core::signals::FailSignal::Success);
    let snapshot = store.snapshot().await;
    assert_eq!(snapshot.strategy_stats.len(), 1);
    let stats = snapshot.strategy_stats.values().next().unwrap();
    assert_eq!((stats.trials, stats.successes, stats.dpi_blocks), (1, 1, 0));
    assert!(
        stats.mean_latency_ms <= witness.first_reply_upper.as_millis() as f64 * 0.1,
        "actual normal learner must measure opening, not held session: mean={} phase_upper={:?}",
        stats.mean_latency_ms,
        witness.first_reply_upper
    );
}
