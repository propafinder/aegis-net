use super::*;
use crate::signals::classify::FailSignal;
use crate::state_v2::KeyObservation;
use tempfile::TempDir;

#[tokio::test]
async fn actual_eviction_during_writer_keeps_new_revision_dirty_and_persistable() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.json");
    let store = AsyncStateStore::load(path.clone()).await.unwrap();
    store
        .update(|snapshot| {
            for index in 0..16_384 {
                snapshot
                    .strategy_stats
                    .insert(format!("old-{index:05}"), Default::default());
            }
        })
        .await;
    let (captured_tx, captured_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let writer_store = store.clone();
    let flushing = tokio::spawn(async move {
        writer_store
            .flush_with_writer(|path, out, lease| async move {
                captured_tx.send(()).unwrap();
                release_rx.await.unwrap();
                write_private_file_async(&path, out, lease).await
            })
            .await
    });
    captured_rx.await.unwrap();
    assert!(store.inner.flush_lock.try_lock().is_err());
    store
        .update_touched(|snapshot, touched| {
            touched.strategy_stats.insert("old-00000".into());
            snapshot
                .strategy_stats
                .get_mut("old-00000")
                .unwrap()
                .record(&FailSignal::Success, Some(12), 64);
            snapshot
                .strategy_stats
                .insert("new".into(), Default::default());
            touched.strategy_stats.insert("new".into());
        })
        .await;
    assert_eq!(store.inner.revision.load(Ordering::Relaxed), 2);
    let current = store.snapshot().await;
    assert_eq!(current.strategy_stats.len(), 16_384);
    assert!(current.strategy_stats.contains_key("old-00000"));
    assert!(!current.strategy_stats.contains_key("old-00001"));
    release_tx.send(()).unwrap();
    flushing.await.unwrap().unwrap();
    assert!(store.is_dirty());
    let old = AsyncStateStore::load(path.clone())
        .await
        .unwrap()
        .snapshot()
        .await;
    assert!(old.strategy_stats.contains_key("old-00001"));
    assert!(!old.strategy_stats.contains_key("new"));
    store.flush().await.unwrap();
    assert!(!store.is_dirty());
    let fresh = AsyncStateStore::load(path).await.unwrap().snapshot().await;
    assert_eq!(fresh.strategy_stats.len(), 16_384);
    assert_eq!(fresh.strategy_stats["old-00000"].successes, 1);
    assert!(fresh.strategy_stats.contains_key("new"));
}

#[tokio::test]
async fn actual_plaintext_output_refusal_preserves_disk_dirty_revision_and_no_seed() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.json");
    let original = serde_json::to_vec(&StateSnapshot::default()).unwrap();
    tokio::fs::write(&path, &original).await.unwrap();
    let store = AsyncStateStore::load(path.clone()).await.unwrap();
    store
        .update(|snapshot| {
            snapshot.key_observations.insert(
                "synthetic".into(),
                KeyObservation {
                    ja3s_md5: Some("x".repeat(STATE_FILE_LIMIT as usize)),
                    ..Default::default()
                },
            );
        })
        .await;
    assert!(
        matches!(store.flush().await, Err(AegisError::Config(reason)) if reason == "state_snapshot_file_too_large")
    );
    assert!(store.is_dirty());
    assert_eq!(store.inner.revision.load(Ordering::Relaxed), 1);
    assert_eq!(tokio::fs::read(&path).await.unwrap(), original);
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        1,
        "plaintext refusal precedes key/seal"
    );
    store
        .update(|snapshot| snapshot.key_observations.clear())
        .await;
    store.flush().await.unwrap();
    assert!(!store.is_dirty());
    AsyncStateStore::load(path).await.unwrap();
}

#[tokio::test]
async fn actual_envelope_output_refusal_preserves_previous_blob() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.json");
    let original = serde_json::to_vec(&StateSnapshot::default()).unwrap();
    tokio::fs::write(&path, &original).await.unwrap();
    let store = AsyncStateStore::load(path.clone()).await.unwrap();
    let mut snapshot = StateSnapshot::default();
    snapshot.key_observations.insert(
        "synthetic".into(),
        KeyObservation {
            ja3s_md5: Some(String::new()),
            ..Default::default()
        },
    );
    let overhead = serde_json::to_vec_pretty(&snapshot).unwrap().len();
    snapshot
        .key_observations
        .get_mut("synthetic")
        .unwrap()
        .ja3s_md5 = Some("x".repeat(STATE_FILE_LIMIT as usize - overhead));
    assert_eq!(
        serde_json::to_vec_pretty(&snapshot).unwrap().len(),
        STATE_FILE_LIMIT as usize
    );
    store.update(|target| *target = snapshot).await;
    assert!(
        matches!(store.flush().await, Err(AegisError::Config(reason)) if reason == "state_snapshot_file_too_large")
    );
    assert!(store.is_dirty());
    assert_eq!(store.inner.revision.load(Ordering::Relaxed), 1);
    assert_eq!(tokio::fs::read(path).await.unwrap(), original);
}

#[tokio::test]
async fn actual_bounded_reader_stops_a_nonterminating_input_at_limit_plus_one() {
    struct NeverEnds(std::sync::Arc<std::sync::atomic::AtomicU64>);
    impl tokio::io::AsyncRead for NeverEnds {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let n = buf.remaining();
            buf.initialize_unfilled().fill(b' ');
            buf.advance(n);
            self.0.fetch_add(n as u64, Ordering::Relaxed);
            std::task::Poll::Ready(Ok(()))
        }
    }
    let count = Arc::new(AtomicU64::new(0));
    assert!(read_bounded_state(NeverEnds(count.clone())).await.is_err());
    assert_eq!(count.load(Ordering::Relaxed), STATE_FILE_LIMIT + 1);
}
