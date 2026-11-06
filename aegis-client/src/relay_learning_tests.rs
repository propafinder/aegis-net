use super::*;
use std::time::Duration;

#[tokio::test]
async fn normal_relay_learning_ignores_clean_empty_sessions() {
    let store = AsyncStateStore::ephemeral();
    let brain = Brain::new(0.0, vec!["grpc_stream".into()], store.clone());
    let host = "empty-session.example.invalid";
    let key = StrategyKey::for_target(
        "203.0.113.51:443".parse().unwrap(),
        host,
        443,
        Some(host),
        true,
    );
    let before = serde_json::to_value(store.snapshot().await).unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    for _ in 0..10 {
        tx.send(relay::RelayOutcome::from_attempt(
            TunnelTransportFamily::GrpcStream,
            &Ok(()),
            0,
            0,
            Duration::from_millis(20),
            Duration::from_secs(1),
        ))
        .unwrap();
    }
    drop(tx);
    let terminal = learn_relay_outcomes(&brain, &key, &mut rx).await.unwrap();
    assert_eq!(
        relay::RelayTcpCompletion::from_result(&Ok(()), Some(&terminal)),
        relay::RelayTcpCompletion::NoResponseObserved,
    );
    let after = store.snapshot().await;
    let false_dpi_blocks: u64 = after.strategy_stats.values().map(|s| s.dpi_blocks).sum();
    assert_eq!(
        false_dpi_blocks, 0,
        "clean empty sessions must not create DPI evidence"
    );
    assert_eq!(
        serde_json::to_value(after).unwrap(),
        before,
        "the production normal relay consumer must leave empty-session learning neutral"
    );
}

#[tokio::test]
async fn normal_relay_learning_retains_response_and_error_samples() {
    let store = AsyncStateStore::ephemeral();
    let brain = Brain::new(0.0, vec!["grpc_stream".into()], store.clone());
    let host = "mixed-session.example.invalid";
    let key = StrategyKey::for_target(
        "203.0.113.51:443".parse().unwrap(),
        host,
        443,
        Some(host),
        true,
    );
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    for (result, sent, received) in [
        (Ok(()), 0, 0),
        (Ok(()), 7, 9),
        (
            Err(anyhow::Error::new(std::io::Error::from(
                std::io::ErrorKind::ConnectionReset,
            ))),
            3,
            0,
        ),
    ] {
        tx.send(relay::RelayOutcome::from_attempt(
            TunnelTransportFamily::GrpcStream,
            &result,
            sent,
            received,
            Duration::from_millis(20),
            Duration::from_secs(1),
        ))
        .unwrap();
    }
    drop(tx);
    let terminal = learn_relay_outcomes(&brain, &key, &mut rx).await.unwrap();
    assert_eq!(
        terminal.signal,
        aegis_core::signals::FailSignal::HandshakeMismatch
    );
    let after = store.snapshot().await;
    assert_eq!(after.strategy_stats.len(), 1);
    let stats = after.strategy_stats.values().next().unwrap();
    assert_eq!((stats.trials, stats.successes, stats.dpi_blocks), (2, 1, 1));
}
