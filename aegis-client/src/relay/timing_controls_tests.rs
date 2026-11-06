use super::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};

#[test]
fn shared_observations_are_once_only_and_opening_is_not_a_response() {
    let counters = RelaySessionCounters::for_attempt(Instant::now() - Duration::from_millis(20));
    let clone = counters.clone();
    counters.mark_opened();
    let opened = *counters.timing.opened_after.get().unwrap();
    assert!(opened >= Duration::from_millis(20));
    counters.add_received(0);
    assert!(counters.timing.first_response_after.get().is_none());
    clone.mark_opened();
    assert_eq!(clone.timing.opened_after.get(), Some(&opened));
    clone.add_received(1);
    let first = *counters.timing.first_response_after.get().unwrap();
    assert!(first >= opened);
    counters.add_received(7);
    assert_eq!(clone.timing.first_response_after.get(), Some(&first));
    assert_eq!(counters.received(), 8);
}

#[tokio::test]
async fn actual_byte_progress_pending_zero_and_eof_do_not_stamp_response() {
    let counters = RelaySessionCounters::default();
    counters.mark_opened();
    let (local, mut remote) = tokio::io::duplex(16);
    let mut progress = byte_progress::ByteProgress::new(local, &counters);
    let mut storage = [0; 4];
    let mut buffer = ReadBuf::new(&mut storage);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(std::pin::Pin::new(&mut progress)
        .poll_read(&mut cx, &mut buffer)
        .is_pending());
    // An empty DuplexStream read may itself remain Pending. Observe one poll;
    // either zero progress or Pending must leave the response stamp absent.
    let mut zero = ReadBuf::new(&mut []);
    assert!(matches!(
        std::pin::Pin::new(&mut progress).poll_read(&mut cx, &mut zero),
        std::task::Poll::Pending | std::task::Poll::Ready(Ok(()))
    ));
    assert!(counters.timing.first_response_after.get().is_none());
    remote.write_all(b"x").await.unwrap();
    progress.read_exact(&mut storage[..1]).await.unwrap();
    assert_eq!(storage[0], b'x');
    let first = *counters.timing.first_response_after.get().unwrap();
    remote.shutdown().await.unwrap();
    assert_eq!(progress.read(&mut storage).await.unwrap(), 0);
    assert_eq!(counters.timing.first_response_after.get(), Some(&first));

    let empty = RelaySessionCounters::default();
    empty.mark_opened();
    let (local, remote) = tokio::io::duplex(16);
    drop(remote);
    let mut progress = byte_progress::ByteProgress::new(local, &empty);
    assert_eq!(progress.read(&mut storage).await.unwrap(), 0);
    assert!(empty.timing.first_response_after.get().is_none());
}

#[test]
fn actual_byte_progress_read_error_does_not_stamp_response() {
    struct RefuseRead;
    impl AsyncRead for RefuseRead {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()))
        }
    }
    let counters = RelaySessionCounters::default();
    counters.mark_opened();
    let mut progress = byte_progress::ByteProgress::new(RefuseRead, &counters);
    let mut storage = [0; 4];
    let mut buffer = ReadBuf::new(&mut storage);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(
        matches!(std::pin::Pin::new(&mut progress).poll_read(&mut cx, &mut buffer), std::task::Poll::Ready(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionReset)
    );
    assert!(counters.timing.first_response_after.get().is_none());
    assert_eq!(counters.received(), 0);
}

#[tokio::test]
async fn actual_owner_reports_three_distinct_timing_boundaries() {
    let witness = super::latency_tests::actual_held_relay_outcome().await;
    let timing = witness.outcome.timing;
    let opened = timing.opened_after.expect("actual authenticated opening");
    let response = timing.first_response_after.expect("actual response read");
    assert!(opened <= response && response <= witness.first_reply_upper);
    assert!(timing.attempt_duration > witness.first_reply_upper + Duration::from_millis(100));
    assert_eq!(
        witness.outcome.learning_opening_latency_ms(),
        Some(opened.as_millis() as u64)
    );
}

#[test]
fn missing_opening_and_non_success_never_become_lifetime_samples() {
    let mut outcome = RelayOutcome::from_attempt(
        TunnelTransportFamily::LegacyTls,
        &Ok(()),
        1,
        1,
        Duration::from_secs(9),
        Duration::from_secs(1),
    );
    assert_eq!(outcome.learning_opening_latency_ms(), None);
    outcome.timing.opened_after = Some(Duration::ZERO);
    assert_eq!(outcome.learning_opening_latency_ms(), Some(0));
    outcome.timing.opened_after = Some(Duration::MAX);
    assert_eq!(outcome.learning_opening_latency_ms(), Some(u64::MAX));
    outcome.signal = aegis_core::signals::FailSignal::RemoteReset;
    assert_eq!(outcome.learning_opening_latency_ms(), None);
    outcome.learning = RelayLearningDisposition::NoApplicationTraffic;
    assert_eq!(outcome.learning_opening_latency_ms(), None);
}

#[tokio::test]
async fn normal_consumer_preserves_existing_mean_without_observed_opening() {
    let store = aegis_core::AsyncStateStore::ephemeral();
    let brain = crate::Brain::new(0.0, vec!["legacy_tls".into()], store.clone());
    let key = crate::StrategyKey::for_target(
        "203.0.113.51:443".parse().unwrap(),
        "timing-history.fixture.invalid",
        443,
        None,
        true,
    );
    brain
        .record_outcome(
            &key,
            "legacy_tls",
            aegis_core::signals::FailSignal::Success,
            Some(5000),
            1,
            None,
        )
        .await;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    tx.send(RelayOutcome::from_attempt(
        TunnelTransportFamily::LegacyTls,
        &Ok(()),
        1,
        1,
        Duration::from_secs(9),
        Duration::from_secs(1),
    ))
    .unwrap();
    drop(tx);
    crate::learn_relay_outcomes(&brain, &key, &mut rx)
        .await
        .unwrap();
    let snapshot = store.snapshot().await;
    let stats = snapshot.strategy_stats.values().next().unwrap();
    assert_eq!((stats.trials, stats.successes), (2, 2));
    assert_eq!(
        stats.mean_latency_ms, 500.0,
        "missing observation preserves old EMA; no fabricated zero/lifetime"
    );
}
