//! Pure load-placement regressions; no file, key provider or native operation.
use super::*;
use std::collections::HashMap;
use std::sync::Mutex;
use std::thread::ThreadId;

// The real helper consumes this owned input through its production AsRef call.
// No delay, timer, background connection or replacement parse implementation.
struct ObservedInput {
    bytes: Vec<u8>,
    observed: Arc<Mutex<Vec<ThreadId>>>,
}

impl AsRef<[u8]> for ObservedInput {
    fn as_ref(&self) -> &[u8] {
        self.observed
            .lock()
            .unwrap()
            .push(std::thread::current().id());
        &self.bytes
    }
}

async fn observe_preparation(bytes: Vec<u8>) -> (BoundedSnapshot, Vec<ThreadId>) {
    assert!(bytes.len() <= 16 * 1024 * 1024);
    let observed = Arc::new(Mutex::new(Vec::new()));
    let prepared = prepare_loaded_snapshot(ObservedInput {
        bytes,
        observed: Arc::clone(&observed),
    })
    .await
    .unwrap();
    let observations = observed.lock().unwrap().clone();
    (prepared, observations)
}

#[tokio::test(flavor = "current_thread")]
async fn v2_parse_and_initial_bounds_use_the_load_worker() {
    let caller = std::thread::current().id();
    let mut input = StateSnapshot::default();
    for index in 0..=16_384 {
        input
            .strategy_stats
            .insert(format!("load-v2-{index:05}|strategy"), Default::default());
    }
    let (prepared, observed) = observe_preparation(serde_json::to_vec(&input).unwrap()).await;
    assert_eq!(prepared.snapshot.strategy_stats.len(), 16_384);
    assert!(prepared.snapshot.key_registry.is_empty());
    assert_eq!(observed.len(), 1, "one actual owned-input borrow");
    assert_ne!(
        observed[0], caller,
        "parse entry must leave the single runtime thread"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_parse_migration_and_initial_bounds_use_the_load_worker() {
    let caller = std::thread::current().id();
    let mut strategies = HashMap::new();
    for index in 0..=16_384 {
        strategies.insert(
            format!("load-v1-{index:05}"),
            StrategyStats {
                success_rate: 0.8,
                avg_handshake_ms: 42.0,
                last_rst_source: Some("dpi".into()),
                confidence: 0.6,
            },
        );
    }
    let input = StateFile {
        entries: HashMap::from([("legacy-orphan".into(), strategies)]),
    };
    let (prepared, observed) = observe_preparation(serde_json::to_vec(&input).unwrap()).await;
    assert_eq!(prepared.snapshot.strategy_stats.len(), 16_384);
    assert!(prepared.snapshot.key_registry.is_empty());
    assert!(prepared
        .snapshot
        .strategy_stats
        .values()
        .all(|s| { s.trials > 0 && s.successes > 0 && s.dpi_blocks == 1 }));
    assert_eq!(observed.len(), 1, "one actual owned-input borrow");
    assert_ne!(
        observed[0], caller,
        "legacy parse entry must leave the single runtime thread"
    );
}
