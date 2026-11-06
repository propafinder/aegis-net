use super::*;

#[tokio::test]
async fn hybrid_relay_learning_ignores_clean_empty_sessions() {
    let store = aegis_core::AsyncStateStore::ephemeral();
    let brain = Brain::new(0.0, vec!["grpc_stream".into()], store.clone());
    let host = "empty-handoff.example.invalid";
    let key = StrategyKey::for_target(
        "203.0.113.51:443".parse().unwrap(),
        host,
        443,
        Some(host),
        true,
    );
    brain
        .record_hybrid_route_attempt(&key, HybridRouteFamily::RelayGrpc)
        .await;
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
    assert!(
        !learn_relay_handoff_outcomes(&brain, &key, &mut rx, &Ok(())).await,
        "empty handoff must not manufacture a route success"
    );
    let after = store.snapshot().await;
    let false_dpi_blocks: u64 = after.strategy_stats.values().map(|s| s.dpi_blocks).sum();
    let route = after.hybrid_route_stats.get(&key.hash_key()).unwrap();
    assert_eq!(
        (false_dpi_blocks, route.relay_failures),
        (0, 0),
        "clean empty handoff must not demote either transport or hybrid route"
    );
    assert_eq!(
        route.relay_attempts, 1,
        "attempt accounting remains separate from rewards"
    );
    assert_eq!(
        serde_json::to_value(after).unwrap(),
        before,
        "empty handoff must not overwrite signal, timing or confidence evidence"
    );
}

#[tokio::test]
async fn hybrid_relay_learning_uses_final_evidence_and_preserves_prior_samples() {
    for (prior_error, final_kind, expected_trials, expected_successes, expected_failures) in [
        (false, "empty", 1, 0, 0),
        (true, "empty", 1, 0, 0),
        (false, "response", 2, 1, 0),
        (false, "stall", 2, 0, 1),
        (false, "error", 2, 0, 1),
    ] {
        let store = aegis_core::AsyncStateStore::ephemeral();
        let brain = Brain::new(0.0, vec!["grpc_stream".into()], store.clone());
        let host = "final-evidence.example.invalid";
        let key = StrategyKey::for_target(
            "203.0.113.51:443".parse().unwrap(),
            host,
            443,
            Some(host),
            true,
        );
        brain
            .record_hybrid_route_attempt(&key, HybridRouteFamily::RelayGrpc)
            .await;
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let prior = if prior_error {
            Err(anyhow::Error::new(std::io::Error::from(
                std::io::ErrorKind::ConnectionReset,
            )))
        } else {
            Ok(())
        };
        tx.send(relay::RelayOutcome::from_attempt(
            TunnelTransportFamily::GrpcStream,
            &prior,
            7,
            if prior_error { 0 } else { 9 },
            Duration::from_millis(20),
            Duration::from_secs(1),
        ))
        .unwrap();
        let (result, sent, received) = match final_kind {
            "empty" => (Ok(()), 0, 0),
            "response" => (Ok(()), 7, 9),
            "stall" => (Ok(()), 7, 0),
            _ => (
                Err(anyhow::Error::new(std::io::Error::from(
                    std::io::ErrorKind::ConnectionReset,
                ))),
                3,
                0,
            ),
        };
        tx.send(relay::RelayOutcome::from_attempt(
            TunnelTransportFamily::GrpcStream,
            &result,
            sent,
            received,
            Duration::from_millis(20),
            Duration::from_secs(1),
        ))
        .unwrap();
        drop(tx);
        assert_eq!(
            learn_relay_handoff_outcomes(&brain, &key, &mut rx, &result).await,
            final_kind == "response"
        );
        let after = store.snapshot().await;
        let stats = after.strategy_stats.values().next().unwrap();
        assert_eq!(
            stats.trials, expected_trials,
            "earlier genuine samples remain learned"
        );
        let route = after.hybrid_route_stats.get(&key.hash_key()).unwrap();
        assert_eq!(
            (route.relay_successes, route.relay_failures),
            (expected_successes, expected_failures)
        );
        assert_eq!(route.relay_attempts, 1);
        if final_kind == "empty" {
            assert!(route.last_relay_signal.is_none());
            assert!(route.last_relay_outcome_unix_ms.is_none());
        }
    }
}

#[tokio::test]
async fn hybrid_relay_learning_keeps_error_without_attempt_evidence() {
    for empty_terminal in [false, true] {
        let store = aegis_core::AsyncStateStore::ephemeral();
        let brain = Brain::new(0.0, vec!["grpc_stream".into()], store.clone());
        let host = "missing-error-evidence.example.invalid";
        let key = StrategyKey::for_target(
            "203.0.113.51:443".parse().unwrap(),
            host,
            443,
            Some(host),
            true,
        );
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        if empty_terminal {
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
        assert!(
            !learn_relay_handoff_outcomes(
                &brain,
                &key,
                &mut rx,
                &Err(anyhow::anyhow!("synthetic pre-attempt failure"))
            )
            .await
        );
        let after = store.snapshot().await;
        let route = after.hybrid_route_stats.get(&key.hash_key()).unwrap();
        assert_eq!((route.relay_successes, route.relay_failures), (0, 1));
        assert_eq!(route.last_relay_signal, Some(FailSignal::Unknown));
    }
}

#[tokio::test]
async fn hybrid_relay_learning_ignores_clean_unattempted_session() {
    let store = aegis_core::AsyncStateStore::ephemeral();
    let brain = Brain::new(0.0, vec!["grpc_stream".into()], store.clone());
    let host = "unattempted-handoff.example.invalid";
    let key = StrategyKey::for_target(
        "203.0.113.51:443".parse().unwrap(),
        host,
        443,
        Some(host),
        true,
    );
    brain
        .record_hybrid_route_attempt(&key, HybridRouteFamily::RelayGrpc)
        .await;
    let before = serde_json::to_value(store.snapshot().await).unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    drop(tx);
    assert!(!learn_relay_handoff_outcomes(&brain, &key, &mut rx, &Ok(())).await);
    assert_eq!(
        serde_json::to_value(store.snapshot().await).unwrap(),
        before,
        "clean local cancellation with no emitted attempt must not create Unknown route failure"
    );
}
