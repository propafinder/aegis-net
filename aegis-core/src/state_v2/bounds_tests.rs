//! Actual store regression: the policy values are independent of implementation.
use super::*;
use crate::brain::StrategyKey;
use tempfile::TempDir;

const DESTINATION_CAP: usize = 4096;
const STRATEGY_CAP: usize = 16_384;
const TRANSPORT_CAP: usize = 128;
const FILE_LIMIT: usize = 16 * 1024 * 1024;

#[tokio::test]
async fn actual_store_update_bounds_all_six_maps() {
    let store = AsyncStateStore::ephemeral();
    store
        .update(|snapshot| {
            let key = StrategyKey::for_target(
                "203.0.113.19:443".parse().unwrap(),
                "synthetic-store.example.invalid",
                443,
                None,
                true,
            );
            for index in 0..=STRATEGY_CAP {
                let row = format!("synthetic-{index:05}");
                snapshot
                    .strategy_stats
                    .insert(format!("{row}|strategy"), Default::default());
                if index <= DESTINATION_CAP {
                    snapshot.key_registry.insert(row.clone(), key.clone());
                    snapshot
                        .key_observations
                        .insert(row.clone(), Default::default());
                    snapshot
                        .stall_probe_stats
                        .insert(row.clone(), Default::default());
                    snapshot
                        .hybrid_route_stats
                        .insert(row.clone(), Default::default());
                }
                if index <= TRANSPORT_CAP {
                    snapshot.transport_stats.insert(row, Default::default());
                }
            }
        })
        .await;
    let snapshot = store.snapshot().await;
    let counts = [
        ("key_registry", snapshot.key_registry.len(), DESTINATION_CAP),
        (
            "key_observations",
            snapshot.key_observations.len(),
            DESTINATION_CAP,
        ),
        (
            "strategy_stats",
            snapshot.strategy_stats.len(),
            STRATEGY_CAP,
        ),
        (
            "stall_probe_stats",
            snapshot.stall_probe_stats.len(),
            DESTINATION_CAP,
        ),
        (
            "transport_stats",
            snapshot.transport_stats.len(),
            TRANSPORT_CAP,
        ),
        (
            "hybrid_route_stats",
            snapshot.hybrid_route_stats.len(),
            DESTINATION_CAP,
        ),
    ];
    assert!(
        counts.iter().all(|(_, count, cap)| count <= cap),
        "actual public owner must bound every map: {counts:?}"
    );
    assert_eq!(store.inner.revision.load(Ordering::Relaxed), 1);
    assert!(store.is_dirty());
    store.flush().await.unwrap();
    assert!(store.is_dirty(), "RAM-only flush remains a no-op");
}

#[tokio::test]
async fn actual_v2_load_bounds_without_rewriting_or_dirtying_disk() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.json");
    let mut original = StateSnapshot::default();
    for index in 0..=STRATEGY_CAP {
        original
            .strategy_stats
            .insert(format!("orphan-{index:05}|strategy"), Default::default());
    }
    let bytes = serde_json::to_vec(&original).unwrap();
    assert!(bytes.len() < FILE_LIMIT);
    tokio::fs::write(&path, &bytes).await.unwrap();
    let store = AsyncStateStore::load(path.clone()).await.unwrap();
    let bounded = store.snapshot().await;
    assert_eq!(bounded.strategy_stats.len(), STRATEGY_CAP);
    assert!(
        bounded.key_registry.is_empty(),
        "orphan strategy rows are compatible"
    );
    assert!(!store.is_dirty());
    assert_eq!(store.inner.revision.load(Ordering::Relaxed), 0);
    store.flush().await.unwrap();
    assert_eq!(tokio::fs::read(&path).await.unwrap(), bytes);
    let again = AsyncStateStore::load(path).await.unwrap().snapshot().await;
    let mut first: Vec<_> = bounded.strategy_stats.keys().collect();
    first.sort();
    let mut second: Vec<_> = again.strategy_stats.keys().collect();
    second.sort();
    assert_eq!(first, second, "load eviction is deterministic");
}

#[tokio::test]
async fn actual_v1_load_bounds_and_preserves_orphan_strategy_compatibility() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("legacy.json");
    let mut strategies = std::collections::HashMap::new();
    for index in 0..=STRATEGY_CAP {
        strategies.insert(
            format!("strategy-{index:05}"),
            StrategyStats {
                success_rate: 0.8,
                avg_handshake_ms: 42.0,
                last_rst_source: Some("dpi".into()),
                confidence: 0.6,
            },
        );
    }
    let legacy = StateFile {
        entries: std::collections::HashMap::from([("legacy-orphan".into(), strategies)]),
    };
    let bytes = serde_json::to_vec(&legacy).unwrap();
    tokio::fs::write(&path, &bytes).await.unwrap();
    let store = AsyncStateStore::load(path.clone()).await.unwrap();
    let snapshot = store.snapshot().await;
    assert_eq!(snapshot.strategy_stats.len(), STRATEGY_CAP);
    assert!(snapshot.key_registry.is_empty());
    assert!(snapshot
        .strategy_stats
        .values()
        .all(|stats| stats.trials > 0 && stats.successes > 0 && stats.dpi_blocks == 1));
    assert!(!store.is_dirty());
    assert_eq!(tokio::fs::read(&path).await.unwrap(), bytes);
}

#[tokio::test]
async fn actual_load_refuses_over_file_limit_and_preserves_original_bytes() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("oversized.json");
    let mut bytes = serde_json::to_vec(&StateSnapshot::default()).unwrap();
    bytes.resize(FILE_LIMIT + 1, b' ');
    tokio::fs::write(&path, &bytes).await.unwrap();
    let result = AsyncStateStore::load(path.clone()).await;
    assert!(
        result.is_err(),
        "actual descriptor read must refuse limit+1 bytes"
    );
    assert_eq!(tokio::fs::read(&path).await.unwrap(), bytes);
}

#[tokio::test]
async fn actual_load_accepts_exact_file_limit_without_rewriting() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("exact.json");
    let mut bytes = serde_json::to_vec(&StateSnapshot::default()).unwrap();
    bytes.resize(FILE_LIMIT, b' ');
    tokio::fs::write(&path, &bytes).await.unwrap();
    let store = AsyncStateStore::load(path.clone()).await.unwrap();
    assert!(store.snapshot().await.strategy_stats.is_empty());
    assert!(!store.is_dirty());
    assert_eq!(tokio::fs::read(path).await.unwrap(), bytes);
}
