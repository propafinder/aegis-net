use super::*;
use crate::hybrid_route::HybridRouteFamily;

#[tokio::test]
async fn actual_known_brain_rows_are_refreshed_before_saturation_eviction() {
    let store = AsyncStateStore::ephemeral();
    let key = StrategyKey::for_target(
        "203.0.113.19:443".parse().unwrap(),
        "synthetic-known.example.invalid",
        443,
        None,
        true,
    );
    let other = StrategyKey::for_target(
        "203.0.113.19:443".parse().unwrap(),
        "synthetic-new.example.invalid",
        443,
        None,
        true,
    );
    let hash = key.hash_key();
    let entry = strategy_entry_key(&hash, "passthrough");
    store
        .update(|snapshot| {
            for index in 0..4095 {
                let row = format!("zz-filler-{index:05}");
                snapshot.key_registry.insert(row.clone(), key.clone());
                snapshot
                    .key_observations
                    .insert(row.clone(), Default::default());
                snapshot
                    .stall_probe_stats
                    .insert(row.clone(), Default::default());
                snapshot.hybrid_route_stats.insert(row, Default::default());
            }
            for index in 0..16_383 {
                snapshot.strategy_stats.insert(
                    format!("zz-filler-{index:05}|passthrough"),
                    Default::default(),
                );
            }
            snapshot.key_registry.insert(hash.clone(), key.clone());
            snapshot
                .key_observations
                .insert(hash.clone(), Default::default());
            snapshot
                .stall_probe_stats
                .insert(hash.clone(), Default::default());
            snapshot
                .hybrid_route_stats
                .insert(hash.clone(), Default::default());
            snapshot
                .strategy_stats
                .insert(entry.clone(), Default::default());
        })
        .await;
    let brain = Brain::new(0.0, vec!["passthrough".into()], store.clone());
    brain
        .record_outcome(
            &key,
            "passthrough",
            FailSignal::Success,
            Some(12),
            64,
            Some(Default::default()),
        )
        .await;
    brain
        .record_probe_result(&key, FailSignal::Timeout, Some(30), Default::default())
        .await;
    brain
        .record_hybrid_route_attempt(&key, HybridRouteFamily::RelayGrpc)
        .await;
    brain
        .record_hybrid_route_outcome(&key, HybridRouteFamily::RelayGrpc, FailSignal::Success)
        .await;
    brain
        .record_outcome(
            &other,
            "passthrough",
            FailSignal::Success,
            Some(10),
            32,
            Some(Default::default()),
        )
        .await;
    brain
        .record_probe_result(&other, FailSignal::Timeout, Some(25), Default::default())
        .await;
    brain
        .record_hybrid_route_attempt(&other, HybridRouteFamily::RelayGrpc)
        .await;
    let snapshot = store.snapshot().await;
    assert_eq!(snapshot.key_registry.len(), 4096);
    assert_eq!(snapshot.strategy_stats.len(), 16_384);
    assert!(snapshot.key_registry.contains_key(&hash));
    assert!(snapshot.key_observations.contains_key(&hash));
    assert!(snapshot.stall_probe_stats.contains_key(&hash));
    assert_eq!(snapshot.strategy_stats[&entry].successes, 1);
    assert_eq!(snapshot.hybrid_route_stats[&hash].relay_successes, 1);
}
