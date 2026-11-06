use super::*;

#[tokio::test]
async fn hybrid_missing_timing_retains_history_and_real_error_evidence() {
    let store = aegis_core::AsyncStateStore::ephemeral();
    let brain = Brain::new(0.0, vec!["legacy_tls".into()], store.clone());
    let key = StrategyKey::for_target(
        "203.0.113.51:443".parse().unwrap(),
        "hybrid-history.fixture.invalid",
        443,
        None,
        true,
    );
    brain
        .record_outcome(&key, "legacy_tls", FailSignal::Success, Some(5000), 1, None)
        .await;
    brain
        .record_hybrid_route_attempt(&key, HybridRouteFamily::RelayGrpc)
        .await;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    tx.send(relay::RelayOutcome::from_attempt(
        TunnelTransportFamily::LegacyTls,
        &Ok(()),
        1,
        1,
        Duration::from_secs(9),
        Duration::from_secs(1),
    ))
    .unwrap();
    drop(tx);
    assert!(learn_relay_handoff_outcomes(&brain, &key, &mut rx, &Ok(())).await);
    let error = Err(anyhow::Error::new(std::io::Error::from(
        std::io::ErrorKind::ConnectionReset,
    )));
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    tx.send(relay::RelayOutcome::from_attempt(
        TunnelTransportFamily::LegacyTls,
        &error,
        3,
        9,
        Duration::from_secs(9),
        Duration::from_secs(1),
    ))
    .unwrap();
    drop(tx);
    assert!(!learn_relay_handoff_outcomes(&brain, &key, &mut rx, &error).await);
    let snapshot = store.snapshot().await;
    let stats = snapshot.strategy_stats.values().next().unwrap();
    assert_eq!((stats.trials, stats.successes), (3, 2));
    assert_eq!(stats.last_signal, Some(FailSignal::RemoteReset));
    assert_eq!(stats.mean_latency_ms, 500.0);
    let route = snapshot.hybrid_route_stats.get(&key.hash_key()).unwrap();
    assert_eq!(
        (
            route.relay_attempts,
            route.relay_successes,
            route.relay_failures
        ),
        (1, 1, 1)
    );
}
