//! Real Brain producers at full owner capacity; no transport or live network.
use super::*;
use crate::hybrid_route::HybridRouteFamily;

const DESTINATION_CAP: usize = 4096;
const STRATEGY_CAP: usize = 16_384;

fn key(name: &str) -> StrategyKey {
    StrategyKey::for_target(
        "203.0.113.19:443".parse().unwrap(),
        name,
        443,
        Some(name),
        true,
    )
}

async fn full_store() -> AsyncStateStore {
    let store = AsyncStateStore::ephemeral();
    store
        .update(|snapshot| {
            let filler = key("synthetic-filler.example.invalid");
            for index in 0..DESTINATION_CAP {
                let row = format!("filler-{index:05}");
                snapshot.key_registry.insert(row.clone(), filler.clone());
                snapshot
                    .key_observations
                    .insert(row.clone(), Default::default());
                snapshot
                    .stall_probe_stats
                    .insert(row.clone(), Default::default());
                snapshot.hybrid_route_stats.insert(row, Default::default());
            }
            for index in 0..STRATEGY_CAP {
                snapshot
                    .strategy_stats
                    .insert(format!("filler-{index:05}|strategy"), Default::default());
            }
        })
        .await;
    store
}

#[tokio::test]
async fn actual_brain_outcome_and_probe_keep_new_aliases_within_caps() {
    let store = full_store().await;
    let brain = Brain::new(0.0, vec!["passthrough".into()], store.clone());
    let target = key("synthetic-current.example.invalid");
    let observation = KeyObservation {
        ja3s_md5: Some("synthetic-signature".into()),
        ..Default::default()
    };
    let before = store.snapshot().await;
    let effective = resolve_effective_key(&before, &target, Some(&observation));
    let base_hash = target.hash_key();
    let effective_hash = effective.hash_key();
    assert_ne!(
        base_hash, effective_hash,
        "fixture exercises both actual aliases"
    );
    brain
        .record_outcome(
            &target,
            "passthrough",
            FailSignal::Success,
            Some(12),
            64,
            Some(observation.clone()),
        )
        .await;
    brain
        .record_probe_result(&target, FailSignal::Timeout, Some(30), observation)
        .await;
    let snapshot = store.snapshot().await;
    let counts = [
        snapshot.key_registry.len(),
        snapshot.key_observations.len(),
        snapshot.stall_probe_stats.len(),
    ];
    assert!(
        counts.iter().all(|&n| n <= DESTINATION_CAP)
            && snapshot.strategy_stats.len() <= STRATEGY_CAP,
        "actual Brain must honor caps: destination={counts:?} strategy={}",
        snapshot.strategy_stats.len()
    );
    for row in [&base_hash, &effective_hash] {
        assert!(snapshot.key_registry.contains_key(row));
        assert!(snapshot.key_observations.contains_key(row));
    }
    assert_eq!(
        snapshot.strategy_stats[&strategy_entry_key(&effective_hash, "passthrough")].successes,
        1
    );
    assert!(snapshot.stall_probe_stats.contains_key(&base_hash));
}

#[tokio::test]
async fn actual_brain_hybrid_attempt_and_outcome_are_bounded_and_retained() {
    let store = full_store().await;
    let brain = Brain::new(0.0, vec!["passthrough".into()], store.clone());
    let target = key("synthetic-hybrid.example.invalid");
    brain
        .record_hybrid_route_attempt(&target, HybridRouteFamily::RelayGrpc)
        .await;
    brain
        .record_hybrid_route_outcome(&target, HybridRouteFamily::RelayGrpc, FailSignal::Success)
        .await;
    let snapshot = store.snapshot().await;
    assert!(
        snapshot.key_registry.len() <= DESTINATION_CAP
            && snapshot.hybrid_route_stats.len() <= DESTINATION_CAP,
        "actual hybrid producer exceeded caps: registry={} hybrid={}",
        snapshot.key_registry.len(),
        snapshot.hybrid_route_stats.len()
    );
    let stats = &snapshot.hybrid_route_stats[&target.hash_key()];
    assert_eq!(stats.relay_attempts, 1);
    assert_eq!(stats.relay_successes, 1);
}
