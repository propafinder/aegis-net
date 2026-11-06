//! Brain и состояние: детерминированный порядок при epsilon=0.

use aegis_core::brain::{
    Brain, DirectPlannerSelectionTrace, PacketStageHint, PathHopHint, ProbeHistoryDisposition,
    ProbeHistoryReasonCode, ResetProfileHint, StrategyKey,
};
use aegis_core::signals::classify::FailSignal;
use aegis_core::{
    AsyncStateStore, ExternalAdversarialCalibration, ExternalCalibrationSnapshot,
    ExternalCalibrationVerdict, ExternalKnowledgePrior, ExternalWitnessCalibration, KeyObservation,
    RstSource, WindowProfile,
};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[tokio::test]
async fn strategy_key_hash_stable() {
    let k = StrategyKey::for_target(
        "203.0.113.10:443".parse().unwrap(),
        "example.org",
        443,
        Some("example.org"),
        true,
    );
    let a = k.hash_key();
    let b = k.hash_key();
    assert_eq!(a, b);
    assert_ne!(a.len(), 0);
}

#[tokio::test]
async fn strategy_key_distinguishes_target_context() {
    let a = StrategyKey::for_target(
        "203.0.113.10:443".parse().unwrap(),
        "example.org",
        443,
        Some("example.org"),
        true,
    );
    let b = StrategyKey::for_target(
        "203.0.113.10:80".parse().unwrap(),
        "example.org",
        80,
        None,
        false,
    );
    assert_ne!(a.hash_key(), b.hash_key());
}

#[tokio::test]
async fn brain_order_by_score_epsilon_zero() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let key = StrategyKey::for_target(
        "203.0.113.1:443".parse().unwrap(),
        "example.org",
        443,
        Some("example.org"),
        true,
    );
    let hk = key.hash_key();
    store
        .update(|snap| {
            snap.key_registry.insert(hk.clone(), key.clone());
            let mut good = aegis_core::StrategyStatsV2::default();
            good.record(&FailSignal::Success, Some(10), 4096);
            good.record(&FailSignal::Success, Some(12), 4096);
            let mut bad = aegis_core::StrategyStatsV2::default();
            bad.record(&FailSignal::Timeout, None, 0);
            bad.record(&FailSignal::Unknown, None, 0);
            snap.strategy_stats
                .insert(format!("{hk}|passthrough"), good);
            snap.strategy_stats.insert(format!("{hk}|multisplit"), bad);
        })
        .await;
    let brain = Brain::new(0.0, vec!["multisplit".into(), "passthrough".into()], store);
    let order = brain.select_order(&key).await;
    assert_eq!(order[0], "passthrough");
}

#[tokio::test]
async fn brain_preserves_preferred_order_on_cold_start() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let brain = Brain::new(
        0.0,
        vec![
            "multisplit".into(),
            "passthrough".into(),
            "ttl_pattern".into(),
        ],
        store,
    );
    let key = StrategyKey::for_target(
        "198.51.100.20:443".parse().unwrap(),
        "cold.example",
        443,
        Some("cold.example"),
        true,
    );
    let order = brain.select_order(&key).await;
    assert_eq!(order, vec!["multisplit", "passthrough", "ttl_pattern"]);
}

#[tokio::test]
async fn brain_preserves_runtime_order_without_external_calibration() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let key = StrategyKey::for_target(
        "203.0.113.1:443".parse().unwrap(),
        "example.org",
        443,
        Some("example.org"),
        true,
    );
    let hk = key.hash_key();
    store
        .update(|snap| {
            snap.key_registry.insert(hk.clone(), key.clone());
            let mut https_ws = aegis_core::StrategyStatsV2::default();
            https_ws.record(&FailSignal::Timeout, None, 0);
            let mut legacy_tls = aegis_core::StrategyStatsV2::default();
            legacy_tls.record(&FailSignal::Success, Some(12), 4096);
            snap.strategy_stats
                .insert(format!("{hk}|https_ws"), https_ws);
            snap.strategy_stats
                .insert(format!("{hk}|legacy_tls"), legacy_tls);
        })
        .await;

    let brain = Brain::new(0.0, vec!["https_ws".into(), "legacy_tls".into()], store);
    let order = brain.select_order(&key).await;

    assert_eq!(order, vec!["legacy_tls", "https_ws"]);
}

#[tokio::test]
async fn brain_blends_external_calibration_into_exploitation_score() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let key = StrategyKey::for_target(
        "203.0.113.1:443".parse().unwrap(),
        "example.org",
        443,
        Some("example.org"),
        true,
    );
    let hk = key.hash_key();
    store
        .update(|snap| {
            snap.key_registry.insert(hk.clone(), key.clone());
            let mut https_ws = aegis_core::StrategyStatsV2::default();
            https_ws.record(&FailSignal::Timeout, None, 0);
            let mut legacy_tls = aegis_core::StrategyStatsV2::default();
            legacy_tls.record(&FailSignal::Unknown, None, 0);
            snap.strategy_stats
                .insert(format!("{hk}|https_ws"), https_ws);
            snap.strategy_stats
                .insert(format!("{hk}|legacy_tls"), legacy_tls);
            snap.external_calibration = Some(ExternalCalibrationSnapshot {
                schema_version: 1,
                source: "external_calibration_summary".to_string(),
                generated_at_unix_ms: None,
                freshness_half_life_secs: None,
                witness: vec![ExternalWitnessCalibration {
                    label: "https_ws".to_string(),
                    records: 4,
                    combined_avg: 0.95,
                    ja3_present_avg: 1.0,
                    alpn_match_avg: 0.95,
                    sni_structure_avg: 0.9,
                }],
                adversarial: vec![ExternalAdversarialCalibration {
                    transport: "https_ws".to_string(),
                    records: 4,
                    measured: 4,
                    planned: 0,
                    passed: 4,
                    failed: 0,
                    pass_rate: Some(1.0),
                    threshold: Some(0.85),
                }],
                knowledge: vec![ExternalKnowledgePrior {
                    target_class: "https_ws".to_string(),
                    region_id: Some("cn".to_string()),
                    score: 0.95,
                    confidence: 0.8,
                    hard_excluded: false,
                    fail_closed: false,
                    generated_at_unix_ms: None,
                }],
                verdict: ExternalCalibrationVerdict {
                    status: "MEASURED".to_string(),
                    acceptance_degraded: false,
                    reasons: Vec::new(),
                },
            });
        })
        .await;

    let brain = Brain::new(0.0, vec!["https_ws".into(), "legacy_tls".into()], store);
    let trace = brain.select_order_trace(&key).await;

    assert_eq!(trace.reward_selected_order, vec!["https_ws", "legacy_tls"]);
    assert!(
        trace.ranked_candidates[0].estimated_reward > trace.ranked_candidates[1].estimated_reward
    );
    assert!(trace.ranked_candidates[0].estimated_reward > 0.5);
    assert_eq!(
        trace.ranked_candidates[0].belief_source,
        "l1_l2_l3_adaptive_posterior"
    );
    assert_eq!(
        trace.ranked_candidates[0].selection_score_reward_component,
        trace.ranked_candidates[0].estimated_reward
    );
}

#[tokio::test]
async fn brain_honors_external_hard_exclusion() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let key = StrategyKey::for_target(
        "203.0.113.1:443".parse().unwrap(),
        "example.org",
        443,
        Some("example.org"),
        true,
    );
    let hk = key.hash_key();
    store
        .update(|snap| {
            snap.key_registry.insert(hk.clone(), key.clone());
            let mut https_ws = aegis_core::StrategyStatsV2::default();
            https_ws.record(&FailSignal::Success, Some(12), 4096);
            let mut legacy_tls = aegis_core::StrategyStatsV2::default();
            for _ in 0..10 {
                legacy_tls.record(&FailSignal::Timeout, None, 0);
            }
            snap.strategy_stats
                .insert(format!("{hk}|https_ws"), https_ws);
            snap.strategy_stats
                .insert(format!("{hk}|legacy_tls"), legacy_tls);
            snap.external_calibration = Some(ExternalCalibrationSnapshot {
                schema_version: 1,
                source: "external_calibration_summary".to_string(),
                generated_at_unix_ms: None,
                freshness_half_life_secs: None,
                witness: Vec::new(),
                adversarial: Vec::new(),
                knowledge: vec![ExternalKnowledgePrior {
                    target_class: "https_ws".to_string(),
                    region_id: Some("cn".to_string()),
                    score: 0.0,
                    confidence: 0.9,
                    hard_excluded: true,
                    fail_closed: true,
                    generated_at_unix_ms: None,
                }],
                verdict: ExternalCalibrationVerdict {
                    status: "MEASURED".to_string(),
                    acceptance_degraded: false,
                    reasons: Vec::new(),
                },
            });
        })
        .await;

    let brain = Brain::new(0.0, vec!["https_ws".into(), "legacy_tls".into()], store);
    let trace = brain.select_order_trace(&key).await;

    assert_eq!(
        trace
            .ranked_candidates
            .iter()
            .map(|candidate| candidate.strategy.as_str())
            .collect::<Vec<_>>(),
        vec!["legacy_tls", "https_ws"]
    );
    assert_eq!(trace.ranked_candidates[1].strategy, "https_ws");
    assert_eq!(trace.ranked_candidates[1].estimated_reward, 0.0);
    assert!(trace.ranked_candidates[1].belief_hard_blocked);
    assert_eq!(trace.reward_selected_order, vec!["legacy_tls"]);
    assert_eq!(brain.select_order(&key).await, vec!["legacy_tls"]);
}

#[tokio::test]
async fn adaptive_posterior_cold_start_uses_l1_priors() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let key = StrategyKey::for_target(
        "203.0.113.1:443".parse().unwrap(),
        "example.org",
        443,
        Some("example.org"),
        true,
    );
    store
        .update(|snap| {
            snap.external_calibration = Some(ExternalCalibrationSnapshot {
                schema_version: 1,
                source: "external_calibration_snapshot".to_string(),
                generated_at_unix_ms: Some(now_unix_ms()),
                freshness_half_life_secs: Some(86_400),
                witness: Vec::new(),
                adversarial: Vec::new(),
                knowledge: vec![
                    ExternalKnowledgePrior {
                        target_class: "https_ws".to_string(),
                        region_id: Some("lab".to_string()),
                        score: 0.9,
                        confidence: 0.9,
                        hard_excluded: false,
                        fail_closed: false,
                        generated_at_unix_ms: None,
                    },
                    ExternalKnowledgePrior {
                        target_class: "legacy_tls".to_string(),
                        region_id: Some("lab".to_string()),
                        score: 0.2,
                        confidence: 0.9,
                        hard_excluded: false,
                        fail_closed: false,
                        generated_at_unix_ms: None,
                    },
                ],
                verdict: ExternalCalibrationVerdict {
                    status: "MEASURED".to_string(),
                    acceptance_degraded: false,
                    reasons: Vec::new(),
                },
            });
        })
        .await;

    let brain = Brain::new(0.0, vec!["legacy_tls".into(), "https_ws".into()], store);
    let trace = brain.select_order_trace(&key).await;

    assert_eq!(trace.reward_selected_order, vec!["https_ws", "legacy_tls"]);
    assert_eq!(
        trace.ranked_candidates[0].belief_source,
        "l1_l2_l3_adaptive_posterior"
    );
    assert!(trace.ranked_candidates[0].cold_start_exploration);
}

#[tokio::test]
async fn adaptive_posterior_runtime_can_overcome_mild_prior_penalty() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let key = StrategyKey::for_target(
        "203.0.113.1:443".parse().unwrap(),
        "example.org",
        443,
        Some("example.org"),
        true,
    );
    let hk = key.hash_key();
    store
        .update(|snap| {
            snap.key_registry.insert(hk.clone(), key.clone());
            let mut https_ws = aegis_core::StrategyStatsV2::default();
            for _ in 0..100 {
                https_ws.record(&FailSignal::Success, Some(20), 4096);
            }
            let mut legacy_tls = aegis_core::StrategyStatsV2::default();
            for _ in 0..100 {
                legacy_tls.record(&FailSignal::Timeout, None, 0);
            }
            snap.strategy_stats
                .insert(format!("{hk}|https_ws"), https_ws);
            snap.strategy_stats
                .insert(format!("{hk}|legacy_tls"), legacy_tls);
            snap.external_calibration = Some(ExternalCalibrationSnapshot {
                schema_version: 1,
                source: "external_calibration_snapshot".to_string(),
                generated_at_unix_ms: Some(now_unix_ms()),
                freshness_half_life_secs: Some(86_400),
                witness: Vec::new(),
                adversarial: Vec::new(),
                knowledge: vec![ExternalKnowledgePrior {
                    target_class: "https_ws".to_string(),
                    region_id: Some("lab".to_string()),
                    score: 0.35,
                    confidence: 0.25,
                    hard_excluded: false,
                    fail_closed: false,
                    generated_at_unix_ms: Some(now_unix_ms()),
                }],
                verdict: ExternalCalibrationVerdict {
                    status: "MEASURED".to_string(),
                    acceptance_degraded: false,
                    reasons: Vec::new(),
                },
            });
        })
        .await;

    let brain = Brain::new(0.0, vec!["legacy_tls".into(), "https_ws".into()], store);
    let order = brain.select_order(&key).await;

    assert_eq!(order[0], "https_ws");
}

#[tokio::test]
async fn adaptive_posterior_stale_calibration_decays() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let key = StrategyKey::for_target(
        "203.0.113.1:443".parse().unwrap(),
        "example.org",
        443,
        Some("example.org"),
        true,
    );
    store
        .update(|snap| {
            snap.external_calibration = Some(ExternalCalibrationSnapshot {
                schema_version: 1,
                source: "external_calibration_snapshot".to_string(),
                generated_at_unix_ms: Some(1),
                freshness_half_life_secs: Some(1),
                witness: Vec::new(),
                adversarial: Vec::new(),
                knowledge: vec![ExternalKnowledgePrior {
                    target_class: "https_ws".to_string(),
                    region_id: Some("lab".to_string()),
                    score: 0.99,
                    confidence: 1.0,
                    hard_excluded: false,
                    fail_closed: false,
                    generated_at_unix_ms: Some(1),
                }],
                verdict: ExternalCalibrationVerdict {
                    status: "MEASURED".to_string(),
                    acceptance_degraded: false,
                    reasons: Vec::new(),
                },
            });
        })
        .await;

    let brain = Brain::new(0.0, vec!["legacy_tls".into(), "https_ws".into()], store);
    let trace = brain.select_order_trace(&key).await;

    assert_eq!(trace.reward_selected_order, vec!["legacy_tls", "https_ws"]);
    assert!(trace.ranked_candidates[1].belief_confidence < 0.01);
    assert_eq!(trace.ranked_candidates[1].estimated_reward, 0.5);
}

#[tokio::test]
async fn adaptive_posterior_low_confidence_block_penalizes_without_excluding() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let key = StrategyKey::for_target(
        "203.0.113.1:443".parse().unwrap(),
        "example.org",
        443,
        Some("example.org"),
        true,
    );
    let hk = key.hash_key();
    store
        .update(|snap| {
            snap.key_registry.insert(hk.clone(), key.clone());
            let mut https_ws = aegis_core::StrategyStatsV2::default();
            https_ws.record(&FailSignal::Success, Some(20), 4096);
            snap.strategy_stats
                .insert(format!("{hk}|https_ws"), https_ws);
            snap.external_calibration = Some(ExternalCalibrationSnapshot {
                schema_version: 1,
                source: "external_calibration_snapshot".to_string(),
                generated_at_unix_ms: Some(now_unix_ms()),
                freshness_half_life_secs: Some(86_400),
                witness: Vec::new(),
                adversarial: Vec::new(),
                knowledge: vec![ExternalKnowledgePrior {
                    target_class: "https_ws".to_string(),
                    region_id: Some("lab".to_string()),
                    score: 0.0,
                    confidence: 0.2,
                    hard_excluded: true,
                    fail_closed: true,
                    generated_at_unix_ms: None,
                }],
                verdict: ExternalCalibrationVerdict {
                    status: "MEASURED".to_string(),
                    acceptance_degraded: false,
                    reasons: Vec::new(),
                },
            });
        })
        .await;

    let brain = Brain::new(0.0, vec!["https_ws".into()], store);
    let trace = brain.select_order_trace(&key).await;

    assert!(!trace.ranked_candidates[0].belief_hard_blocked);
    assert!(trace.ranked_candidates[0].estimated_reward > 0.0);
}

#[tokio::test]
async fn adaptive_posterior_exploration_still_happens_within_bounds() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let key = StrategyKey::for_target(
        "203.0.113.1:443".parse().unwrap(),
        "example.org",
        443,
        Some("example.org"),
        true,
    );
    let brain = Brain::new(1.0, vec!["https_ws".into(), "grpc_stream".into()], store);
    let order = brain.select_order(&key).await;

    assert_eq!(order.len(), 2);
    assert!(order.contains(&"https_ws".to_string()));
    assert!(order.contains(&"grpc_stream".to_string()));
}

#[tokio::test]
async fn brain_reuses_similar_context_when_exact_key_is_new() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let learned_key = StrategyKey::for_target(
        "203.0.113.5:443".parse().unwrap(),
        "example.org",
        443,
        Some("example.org"),
        true,
    );
    let learned_hash = learned_key.hash_key();
    store
        .update(|snap| {
            snap.key_registry
                .insert(learned_hash.clone(), learned_key.clone());
            let mut passthrough = aegis_core::StrategyStatsV2::default();
            passthrough.record(&FailSignal::Success, Some(20), 2048);
            passthrough.record(&FailSignal::Success, Some(18), 2048);
            let mut multisplit = aegis_core::StrategyStatsV2::default();
            multisplit.record(&FailSignal::DropSuspected, None, 512);
            multisplit.record(&FailSignal::Timeout, None, 512);
            snap.strategy_stats
                .insert(format!("{learned_hash}|passthrough"), passthrough);
            snap.strategy_stats
                .insert(format!("{learned_hash}|multisplit"), multisplit);
        })
        .await;

    let brain = Brain::new(0.0, vec!["multisplit".into(), "passthrough".into()], store);
    let new_key = StrategyKey::for_target(
        "203.0.113.25:443".parse().unwrap(),
        "www.example.org",
        443,
        Some("www.example.org"),
        true,
    );
    let order = brain.select_order(&new_key).await;
    assert_eq!(order[0], "passthrough");
}

#[tokio::test]
async fn brain_select_order_trace_reports_contextual_reward_ranking() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let key = StrategyKey::for_target(
        "203.0.113.26:443".parse().unwrap(),
        "trace-ranking.example",
        443,
        Some("trace-ranking.example"),
        true,
    );
    let hk = key.hash_key();
    store
        .update(|snap| {
            snap.key_registry.insert(hk.clone(), key.clone());
            let mut good = aegis_core::StrategyStatsV2::default();
            good.record(&FailSignal::Success, Some(12), 4096);
            good.record(&FailSignal::Success, Some(15), 4096);
            let mut weak = aegis_core::StrategyStatsV2::default();
            weak.record(&FailSignal::Timeout, None, 0);
            weak.record(&FailSignal::Unknown, None, 0);
            snap.strategy_stats
                .insert(format!("{hk}|passthrough"), good);
            snap.strategy_stats.insert(format!("{hk}|multisplit"), weak);
        })
        .await;
    let brain = Brain::new(0.0, vec!["multisplit".into(), "passthrough".into()], store);
    let trace = brain.select_order_trace(&key).await;
    assert_eq!(trace.selector_mode, "ucb1_contextual_reward");
    assert_eq!(
        trace.explainability_trace_source,
        "state_snapshot_contextual_reward"
    );
    assert_eq!(
        trace.explainability_observation_source,
        "no_advisory_observation"
    );
    assert_eq!(
        trace.reward_selected_order,
        vec!["passthrough", "multisplit"]
    );
    assert_eq!(trace.probe_history_disposition, "none");
    assert_eq!(trace.probe_history_reason_code, "no_recent_probe_history");
    assert_eq!(trace.cross_session_signal_bias, "neutral_advisory_bias");
    assert_eq!(trace.ranked_candidates.len(), 2);
    assert_eq!(trace.ranked_candidates[0].strategy, "passthrough");
    assert_eq!(trace.ranked_candidates[1].strategy, "multisplit");
    assert!(
        trace.ranked_candidates[0].estimated_reward > trace.ranked_candidates[1].estimated_reward
    );
    assert_eq!(
        trace.ranked_candidates[0].selection_score_reward_component,
        trace.ranked_candidates[0].estimated_reward
    );
    assert!(trace.ranked_candidates[0]
        .selection_score_ucb_exploration_bonus
        .is_some());
    assert_eq!(
        trace.ranked_candidates[0].selection_score_probe_bias_component,
        trace.ranked_candidates[0].probe_history_strategy_bias
    );
    let score = trace.ranked_candidates[0]
        .selection_score
        .expect("aggregate selection score");
    let ucb_bonus = trace.ranked_candidates[0]
        .selection_score_ucb_exploration_bonus
        .expect("ucb exploration bonus");
    let decomposed_score = trace.ranked_candidates[0].selection_score_reward_component
        + ucb_bonus
        + trace.ranked_candidates[0].selection_score_probe_bias_component;
    assert!(
        (score - decomposed_score).abs() < 1e-9,
        "score={score}, decomposed={decomposed_score}, trace={trace:?}"
    );
    assert!(trace.ranked_candidates[0].selection_score.is_some());
    assert!(trace.ranked_candidates[1].selection_score.is_some());
}

#[tokio::test]
async fn brain_select_order_trace_surfaces_probe_bias_for_branchable_candidates() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let key = StrategyKey::for_target(
        "203.0.113.27:443".parse().unwrap(),
        "trace-probe-bias.example",
        443,
        Some("trace-probe-bias.example"),
        true,
    );
    let hk = key.hash_key();
    store
        .update(|snap| {
            snap.key_registry.insert(hk.clone(), key.clone());
            snap.key_observations.insert(
                hk.clone(),
                KeyObservation {
                    matched_packets: 2,
                    capture_status: aegis_core::PacketCaptureStatus::Active,
                    first_data_ttl: Some(58),
                    first_data_window: Some(65535),
                    first_data_server_hint: Some(aegis_core::ServerType::LikelyCdn),
                    ..Default::default()
                },
            );
            snap.stall_probe_stats.insert(
                hk.clone(),
                aegis_core::StallProbeStats {
                    trials: 1,
                    collapses: 1,
                    consecutive_stall_failures: 1,
                    last_signal: Some(FailSignal::ThroughputCollapse),
                    ..Default::default()
                },
            );
            let mut passthrough = aegis_core::StrategyStatsV2::default();
            passthrough.record(&FailSignal::Success, Some(20), 1024);
            let mut ttl_desync = aegis_core::StrategyStatsV2::default();
            ttl_desync.record(&FailSignal::Success, Some(20), 1024);
            snap.strategy_stats
                .insert(format!("{hk}|passthrough"), passthrough);
            snap.strategy_stats
                .insert(format!("{hk}|ttl_desync"), ttl_desync);
        })
        .await;
    let brain = Brain::new(0.0, vec!["passthrough".into(), "ttl_desync".into()], store);
    let trace = brain.select_order_trace(&key).await;
    assert_eq!(trace.probe_history_disposition, "bias_probe_branch");
    assert_eq!(
        trace.probe_history_reason_code,
        "single_stall_bias_probe_branch"
    );
    assert_eq!(trace.cross_session_signal_bias, "probe_branch_bias");
    assert_eq!(trace.reward_selected_order[0], "ttl_desync");
    assert_eq!(trace.ranked_candidates[0].strategy, "ttl_desync");
    assert!(
        trace.ranked_candidates[0].probe_history_strategy_bias > 0.0,
        "{trace:?}"
    );
    assert!(
        trace.ranked_candidates[0].selection_score_probe_bias_component > 0.0,
        "{trace:?}"
    );
    let positive_score = trace.ranked_candidates[0]
        .selection_score
        .expect("positive aggregate selection score");
    let positive_ucb = trace.ranked_candidates[0]
        .selection_score_ucb_exploration_bonus
        .expect("positive ucb component");
    let positive_decomposed = trace.ranked_candidates[0].selection_score_reward_component
        + positive_ucb
        + trace.ranked_candidates[0].selection_score_probe_bias_component;
    assert!(
        (positive_score - positive_decomposed).abs() < 1e-9,
        "score={positive_score}, decomposed={positive_decomposed}, trace={trace:?}"
    );
    assert!(
        trace.ranked_candidates[1].probe_history_strategy_bias < 0.0,
        "{trace:?}"
    );
    assert!(
        trace.ranked_candidates[1].selection_score_probe_bias_component < 0.0,
        "{trace:?}"
    );
    let negative_score = trace.ranked_candidates[1]
        .selection_score
        .expect("negative aggregate selection score");
    let negative_ucb = trace.ranked_candidates[1]
        .selection_score_ucb_exploration_bonus
        .expect("negative ucb component");
    let negative_decomposed = trace.ranked_candidates[1].selection_score_reward_component
        + negative_ucb
        + trace.ranked_candidates[1].selection_score_probe_bias_component;
    assert!(
        (negative_score - negative_decomposed).abs() < 1e-9,
        "score={negative_score}, decomposed={negative_decomposed}, trace={trace:?}"
    );
}

#[tokio::test]
async fn brain_enriches_key_from_saved_observation() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let brain = Brain::new(
        0.0,
        vec!["multisplit".into(), "passthrough".into()],
        store.clone(),
    );
    let key = StrategyKey::for_target(
        "203.0.113.44:443".parse().unwrap(),
        "observed.example",
        443,
        Some("observed.example"),
        true,
    );
    brain
        .record_outcome(
            &key,
            "passthrough",
            FailSignal::Success,
            Some(25),
            4096,
            Some(KeyObservation {
                first_response_bytes: 128,
                tls_server_hello_seen: true,
                ja3s_md5: Some("0123456789abcdef0123456789abcdef".into()),
                relay_client_to_remote_bytes: 0,
                relay_remote_to_client_bytes: 0,
                relay_lifetime_ms: 0,
                configured_timeout_ms: 0,
                capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
                capture_backend: None,
                capture_filter_applied: false,
                capture_ring_layout: None,
                capture_io_path: None,
                capture_wait_cycles: 0,
                downstream_dup_ack_count: 0,
                downstream_retransmit_count: 0,
                downstream_fin_after_data: false,
                matched_packets: 0,
                syn_ack_ttl: None,
                syn_ack_window: None,
                syn_ack_mss: None,
                syn_ack_window_scale: None,
                syn_ack_sack_permitted: None,
                syn_ack_timestamp_option: None,
                syn_ack_server_hint: None,
                first_data_ttl: Some(57),
                first_data_window: Some(65535),
                first_data_payload_len: None,
                first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
                first_data_server_hint: Some(aegis_core::ServerType::LikelyCdn),
                first_packet_ttl: None,
                first_packet_ip_tos: None,
                first_packet_ip_id: None,
                first_packet_ip_df: None,
                first_packet_window: None,
                first_packet_flags: None,
                server_hint: None,
                rst_ttl: None,
                rst_source: None,
            }),
        )
        .await;
    brain
        .record_fail(&key, "multisplit", FailSignal::Timeout, 250, 512)
        .await;

    let snap = store.snapshot().await;
    let base_hash = key.hash_key();
    let enriched = snap
        .key_registry
        .values()
        .find(|candidate| {
            candidate.target_host_hash == key.target_host_hash
                && candidate.target_port == key.target_port
                && candidate.server_signature_hash.is_some()
        })
        .expect("enriched key stored");
    assert!(snap.key_observations.contains_key(&base_hash));
    assert!(enriched.server_signature_hash.is_some());
    assert_eq!(
        enriched.packet_stage_hint,
        Some(aegis_core::brain::PacketStageHint::FirstDataSeen)
    );
    assert_eq!(
        enriched.server_hint,
        Some(aegis_core::ServerType::LikelyCdn)
    );
    assert_eq!(enriched.fingerprint_window_hint, Some(WindowProfile::Huge));
    assert_eq!(enriched.reference_hop_hint, Some(PathHopHint::Near));
    assert_eq!(enriched.reset_profile_hint, None);

    let order = brain.select_order(&key).await;
    assert_eq!(order[0], "passthrough");
}

#[tokio::test]
async fn brain_records_probe_result_without_strategy_stats() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let brain = Brain::new(
        0.0,
        vec!["multisplit".into(), "passthrough".into()],
        store.clone(),
    );
    let key = StrategyKey::for_target(
        "203.0.113.244:443".parse().unwrap(),
        "probe-observed.example",
        443,
        Some("probe-observed.example"),
        true,
    );
    let observation = KeyObservation {
        first_response_bytes: 64,
        tls_server_hello_seen: true,
        ja3s_md5: Some("fedcba9876543210fedcba9876543210".into()),
        configured_timeout_ms: 750,
        capture_status: aegis_core::PacketCaptureStatus::Active,
        capture_backend: Some(aegis_core::PacketCaptureBackendKind::LinuxAfPacket),
        capture_filter_applied: true,
        capture_io_path: Some(aegis_core::packet_observer::PacketCaptureIoPath::AfPacketRing),
        matched_packets: 2,
        first_data_ttl: Some(58),
        first_data_window: Some(65535),
        first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
        first_data_server_hint: Some(aegis_core::ServerType::LikelyCdn),
        ..KeyObservation::default()
    };

    brain
        .record_probe_result(
            &key,
            FailSignal::RemoteReset,
            Some(120),
            observation.clone(),
        )
        .await;

    let snap = store.snapshot().await;
    let base_hash = key.hash_key();
    let stored = snap
        .key_observations
        .get(&base_hash)
        .expect("probe observation stored");
    assert_eq!(
        stored.first_response_bytes,
        observation.first_response_bytes
    );
    assert_eq!(
        stored.tls_server_hello_seen,
        observation.tls_server_hello_seen
    );
    assert_eq!(stored.ja3s_md5, observation.ja3s_md5);
    assert_eq!(stored.capture_status, observation.capture_status);
    assert_eq!(stored.capture_backend, observation.capture_backend);
    assert_eq!(stored.first_data_ttl, observation.first_data_ttl);
    assert!(snap.strategy_stats.is_empty());
    let probe_stats = snap
        .stall_probe_stats
        .get(&base_hash)
        .expect("probe stats stored");
    assert_eq!(probe_stats.trials, 1);
    assert_eq!(probe_stats.last_signal, Some(FailSignal::RemoteReset));

    let latest = brain.latest_observation(&key).await;
    let latest = latest.expect("latest probe observation available");
    assert_eq!(
        latest.first_response_bytes,
        observation.first_response_bytes
    );
    assert_eq!(
        latest.tls_server_hello_seen,
        observation.tls_server_hello_seen
    );
    assert_eq!(latest.ja3s_md5, observation.ja3s_md5);
    assert_eq!(latest.capture_status, observation.capture_status);
    assert_eq!(latest.capture_backend, observation.capture_backend);
    assert_eq!(latest.first_data_ttl, observation.first_data_ttl);
    let latest_probe_stats = brain
        .latest_probe_stats(&key)
        .await
        .expect("latest probe stats available");
    assert_eq!(latest_probe_stats.trials, 1);
    assert_eq!(
        latest_probe_stats.last_signal,
        Some(FailSignal::RemoteReset)
    );
}

#[tokio::test]
async fn probe_history_biases_brain_toward_probe_aligned_strategies() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let key = StrategyKey::for_target(
        "203.0.113.77:443".parse().unwrap(),
        "probe-branch.example",
        443,
        Some("probe-branch.example"),
        true,
    );
    let hk = key.hash_key();
    store
        .update(|snap| {
            snap.key_registry.insert(hk.clone(), key.clone());
            snap.key_observations.insert(
                hk.clone(),
                KeyObservation {
                    matched_packets: 2,
                    capture_status: aegis_core::PacketCaptureStatus::Active,
                    first_data_ttl: Some(58),
                    first_data_window: Some(65535),
                    first_data_server_hint: Some(aegis_core::ServerType::LikelyCdn),
                    ..Default::default()
                },
            );
            snap.stall_probe_stats.insert(
                hk.clone(),
                aegis_core::StallProbeStats {
                    trials: 1,
                    collapses: 1,
                    consecutive_stall_failures: 1,
                    last_signal: Some(FailSignal::ThroughputCollapse),
                    ..Default::default()
                },
            );
            let mut passthrough = aegis_core::StrategyStatsV2::default();
            passthrough.record(&FailSignal::Success, Some(20), 2048);
            passthrough.record(&FailSignal::Success, Some(22), 2048);
            let mut ttl_desync = aegis_core::StrategyStatsV2::default();
            ttl_desync.record(&FailSignal::Success, Some(20), 2048);
            ttl_desync.record(&FailSignal::Success, Some(22), 2048);
            snap.strategy_stats
                .insert(format!("{hk}|passthrough"), passthrough);
            snap.strategy_stats
                .insert(format!("{hk}|ttl_desync"), ttl_desync);
        })
        .await;
    let brain = Brain::new(0.0, vec!["passthrough".into(), "ttl_desync".into()], store);
    let order = brain.select_order(&key).await;
    assert_eq!(order[0], "ttl_desync");
}

#[tokio::test]
async fn runtime_only_probe_history_does_not_bias_brain_order() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let key = StrategyKey::for_target(
        "203.0.113.177:443".parse().unwrap(),
        "probe-runtime-only.example",
        443,
        Some("probe-runtime-only.example"),
        true,
    );
    let hk = key.hash_key();
    store
        .update(|snap| {
            snap.key_registry.insert(hk.clone(), key.clone());
            snap.key_observations.insert(
                hk.clone(),
                KeyObservation {
                    syn_ack_ttl: Some(58),
                    syn_ack_window: Some(65535),
                    syn_ack_server_hint: Some(aegis_core::ServerType::LikelyCdn),
                    ..Default::default()
                },
            );
            snap.stall_probe_stats.insert(
                hk.clone(),
                aegis_core::StallProbeStats {
                    trials: 1,
                    collapses: 1,
                    consecutive_stall_failures: 1,
                    last_signal: Some(FailSignal::ThroughputCollapse),
                    ..Default::default()
                },
            );
            let mut passthrough = aegis_core::StrategyStatsV2::default();
            passthrough.record(&FailSignal::Success, Some(20), 2048);
            passthrough.record(&FailSignal::Success, Some(22), 2048);
            let mut ttl_desync = aegis_core::StrategyStatsV2::default();
            ttl_desync.record(&FailSignal::Success, Some(20), 2048);
            ttl_desync.record(&FailSignal::Success, Some(22), 2048);
            snap.strategy_stats
                .insert(format!("{hk}|passthrough"), passthrough);
            snap.strategy_stats
                .insert(format!("{hk}|ttl_desync"), ttl_desync);
        })
        .await;
    let brain = Brain::new(0.0, vec!["passthrough".into(), "ttl_desync".into()], store);
    let order = brain.select_order(&key).await;
    assert_eq!(order[0], "passthrough");
}

#[tokio::test]
async fn repeated_stall_history_does_not_bias_brain_order() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let key = StrategyKey::for_target(
        "203.0.113.78:443".parse().unwrap(),
        "probe-repeat.example",
        443,
        Some("probe-repeat.example"),
        true,
    );
    let hk = key.hash_key();
    store
        .update(|snap| {
            snap.key_registry.insert(hk.clone(), key.clone());
            snap.key_observations.insert(
                hk.clone(),
                KeyObservation {
                    matched_packets: 2,
                    capture_status: aegis_core::PacketCaptureStatus::Active,
                    first_data_ttl: Some(58),
                    first_data_window: Some(65535),
                    first_data_server_hint: Some(aegis_core::ServerType::LikelyCdn),
                    ..Default::default()
                },
            );
            snap.stall_probe_stats.insert(
                hk.clone(),
                aegis_core::StallProbeStats {
                    trials: 2,
                    collapses: 2,
                    consecutive_stall_failures: 2,
                    last_signal: Some(FailSignal::ThroughputCollapse),
                    ..Default::default()
                },
            );
            let mut passthrough = aegis_core::StrategyStatsV2::default();
            passthrough.record(&FailSignal::Success, Some(20), 2048);
            passthrough.record(&FailSignal::Success, Some(22), 2048);
            let mut ttl_desync = aegis_core::StrategyStatsV2::default();
            ttl_desync.record(&FailSignal::Success, Some(20), 2048);
            ttl_desync.record(&FailSignal::Success, Some(22), 2048);
            snap.strategy_stats
                .insert(format!("{hk}|passthrough"), passthrough);
            snap.strategy_stats
                .insert(format!("{hk}|ttl_desync"), ttl_desync);
        })
        .await;
    let brain = Brain::new(0.0, vec!["passthrough".into(), "ttl_desync".into()], store);
    let order = brain.select_order(&key).await;
    assert_eq!(order[0], "passthrough");
}

#[tokio::test]
async fn advisory_reuse_weight_stays_ordered_by_observation_confidence() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();

    let runtime_only_key = StrategyKey::for_target(
        "203.0.113.170:443".parse().unwrap(),
        "runtime-only-reuse.example",
        443,
        Some("runtime-only-reuse.example"),
        true,
    );
    let explicit_absence_key = StrategyKey::for_target(
        "203.0.113.171:443".parse().unwrap(),
        "explicit-absence-reuse.example",
        443,
        Some("explicit-absence-reuse.example"),
        true,
    );
    let captured_key = StrategyKey::for_target(
        "203.0.113.172:443".parse().unwrap(),
        "captured-reuse.example",
        443,
        Some("captured-reuse.example"),
        true,
    );

    let runtime_only_hash = runtime_only_key.hash_key();
    let explicit_absence_hash = explicit_absence_key.hash_key();
    let captured_hash = captured_key.hash_key();

    store
        .update(|snap| {
            snap.key_registry
                .insert(runtime_only_hash.clone(), runtime_only_key.clone());
            snap.key_registry
                .insert(explicit_absence_hash.clone(), explicit_absence_key.clone());
            snap.key_registry
                .insert(captured_hash.clone(), captured_key.clone());

            snap.key_observations.insert(
                runtime_only_hash.clone(),
                KeyObservation {
                    syn_ack_ttl: Some(58),
                    syn_ack_window: Some(65535),
                    syn_ack_server_hint: Some(aegis_core::ServerType::LikelyCdn),
                    ..Default::default()
                },
            );
            snap.key_observations.insert(
                explicit_absence_hash.clone(),
                KeyObservation {
                    capture_status: aegis_core::PacketCaptureStatus::UnsupportedPlatform,
                    capture_backend: Some(aegis_core::PacketCaptureBackendKind::LinuxAfPacket),
                    capture_filter_applied: true,
                    capture_io_path: Some(
                        aegis_core::packet_observer::PacketCaptureIoPath::AfPacketRing,
                    ),
                    matched_packets: 2,
                    syn_ack_ttl: Some(58),
                    syn_ack_window: Some(65535),
                    syn_ack_server_hint: Some(aegis_core::ServerType::LikelyCdn),
                    ..Default::default()
                },
            );
            snap.key_observations.insert(
                captured_hash.clone(),
                KeyObservation {
                    matched_packets: 2,
                    capture_status: aegis_core::PacketCaptureStatus::Active,
                    first_data_ttl: Some(58),
                    first_data_window: Some(65535),
                    first_data_server_hint: Some(aegis_core::ServerType::LikelyCdn),
                    ..Default::default()
                },
            );
        })
        .await;

    let brain = Brain::new(0.0, vec!["passthrough".into(), "ttl_desync".into()], store);

    let runtime_only = brain.direct_session_advisory(&runtime_only_key).await;
    let explicit_absence = brain.direct_session_advisory(&explicit_absence_key).await;
    let captured = brain.direct_session_advisory(&captured_key).await;

    assert!(
        captured.cross_session_signal_metrics.reuse_weight
            > runtime_only.cross_session_signal_metrics.reuse_weight
    );
    assert!(
        runtime_only.cross_session_signal_metrics.reuse_weight
            > explicit_absence.cross_session_signal_metrics.reuse_weight
    );
}

#[tokio::test]
async fn select_order_trace_reward_stays_ordered_by_observation_confidence() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();

    let runtime_only_key = StrategyKey::for_target(
        "203.0.113.173:443".parse().unwrap(),
        "runtime-only-trace.example",
        443,
        Some("runtime-only-trace.example"),
        true,
    );
    let explicit_absence_key = StrategyKey::for_target(
        "203.0.113.174:443".parse().unwrap(),
        "explicit-absence-trace.example",
        443,
        Some("explicit-absence-trace.example"),
        true,
    );
    let captured_key = StrategyKey::for_target(
        "203.0.113.175:443".parse().unwrap(),
        "captured-trace.example",
        443,
        Some("captured-trace.example"),
        true,
    );

    let runtime_only_hash = runtime_only_key.hash_key();
    let explicit_absence_hash = explicit_absence_key.hash_key();
    let captured_hash = captured_key.hash_key();

    store
        .update(|snap| {
            snap.key_registry
                .insert(runtime_only_hash.clone(), runtime_only_key.clone());
            snap.key_registry
                .insert(explicit_absence_hash.clone(), explicit_absence_key.clone());
            snap.key_registry
                .insert(captured_hash.clone(), captured_key.clone());

            snap.key_observations.insert(
                runtime_only_hash.clone(),
                KeyObservation {
                    syn_ack_ttl: Some(58),
                    syn_ack_window: Some(65535),
                    syn_ack_server_hint: Some(aegis_core::ServerType::LikelyCdn),
                    ..Default::default()
                },
            );
            snap.key_observations.insert(
                explicit_absence_hash.clone(),
                KeyObservation {
                    capture_status: aegis_core::PacketCaptureStatus::UnsupportedPlatform,
                    capture_backend: Some(aegis_core::PacketCaptureBackendKind::LinuxAfPacket),
                    capture_filter_applied: true,
                    capture_io_path: Some(
                        aegis_core::packet_observer::PacketCaptureIoPath::AfPacketRing,
                    ),
                    matched_packets: 2,
                    syn_ack_ttl: Some(58),
                    syn_ack_window: Some(65535),
                    syn_ack_server_hint: Some(aegis_core::ServerType::LikelyCdn),
                    ..Default::default()
                },
            );
            snap.key_observations.insert(
                captured_hash.clone(),
                KeyObservation {
                    matched_packets: 2,
                    capture_status: aegis_core::PacketCaptureStatus::Active,
                    first_data_ttl: Some(58),
                    first_data_window: Some(65535),
                    first_data_server_hint: Some(aegis_core::ServerType::LikelyCdn),
                    ..Default::default()
                },
            );

            for hk in [
                runtime_only_hash.clone(),
                explicit_absence_hash.clone(),
                captured_hash.clone(),
            ] {
                let mut good = aegis_core::StrategyStatsV2::default();
                good.record(&FailSignal::Success, Some(12), 4096);
                good.record(&FailSignal::Success, Some(15), 4096);
                let mut weak = aegis_core::StrategyStatsV2::default();
                weak.record(&FailSignal::Timeout, None, 0);
                weak.record(&FailSignal::Unknown, None, 0);
                snap.strategy_stats
                    .insert(format!("{hk}|passthrough"), good);
                snap.strategy_stats.insert(format!("{hk}|multisplit"), weak);
            }
        })
        .await;

    let brain = Brain::new(0.0, vec!["passthrough".into(), "multisplit".into()], store);

    let runtime_only_trace = brain.select_order_trace(&runtime_only_key).await;
    let explicit_absence_trace = brain.select_order_trace(&explicit_absence_key).await;
    let captured_trace = brain.select_order_trace(&captured_key).await;

    let reward_for = |trace: &DirectPlannerSelectionTrace, strategy: &str| {
        trace
            .ranked_candidates
            .iter()
            .find(|candidate| candidate.strategy == strategy)
            .expect("candidate trace")
            .estimated_reward
    };

    assert_eq!(
        runtime_only_trace.observation_capture_confidence,
        "runtime_only"
    );
    assert_eq!(
        runtime_only_trace.explainability_trace_source,
        "state_snapshot_contextual_reward"
    );
    assert_eq!(
        runtime_only_trace.explainability_observation_source,
        "advisory_state_snapshot_observation"
    );
    assert_eq!(
        explicit_absence_trace.observation_capture_confidence,
        "explicit_absence"
    );
    assert_eq!(
        explicit_absence_trace.explainability_trace_source,
        "state_snapshot_contextual_reward"
    );
    assert_eq!(
        explicit_absence_trace.explainability_observation_source,
        "advisory_state_snapshot_observation"
    );
    assert_eq!(
        captured_trace.observation_capture_confidence,
        "deep_observed"
    );
    assert_eq!(
        captured_trace.explainability_trace_source,
        "state_snapshot_contextual_reward"
    );
    assert_eq!(
        captured_trace.explainability_observation_source,
        "advisory_state_snapshot_observation"
    );
    assert_eq!(runtime_only_trace.reward_selected_order[0], "passthrough");
    assert_eq!(
        explicit_absence_trace.reward_selected_order[0],
        "passthrough"
    );
    assert_eq!(captured_trace.reward_selected_order[0], "passthrough");

    let runtime_only_reward = reward_for(&runtime_only_trace, "passthrough");
    let explicit_absence_reward = reward_for(&explicit_absence_trace, "passthrough");
    let captured_reward = reward_for(&captured_trace, "passthrough");

    assert!(captured_reward > runtime_only_reward);
    assert!(runtime_only_reward > explicit_absence_reward);
}

#[tokio::test]
async fn probe_history_regression_harness_covers_representative_cases() {
    struct Case {
        name: &'static str,
        observation: Option<KeyObservation>,
        consecutive_stall_failures: u64,
        last_signal: Option<FailSignal>,
        expected_first: &'static str,
        expected_disposition: ProbeHistoryDisposition,
    }

    let cases = vec![
        Case {
            name: "deep_observed_single_stall",
            observation: Some(KeyObservation {
                matched_packets: 2,
                capture_status: aegis_core::PacketCaptureStatus::Active,
                first_data_ttl: Some(58),
                first_data_window: Some(65535),
                first_data_server_hint: Some(aegis_core::ServerType::LikelyCdn),
                ..Default::default()
            }),
            consecutive_stall_failures: 1,
            last_signal: Some(FailSignal::ThroughputCollapse),
            expected_first: "ttl_desync",
            expected_disposition: ProbeHistoryDisposition::BiasProbeBranch,
        },
        Case {
            name: "runtime_only_single_stall",
            observation: Some(KeyObservation {
                syn_ack_ttl: Some(58),
                syn_ack_window: Some(65535),
                syn_ack_server_hint: Some(aegis_core::ServerType::LikelyCdn),
                ..Default::default()
            }),
            consecutive_stall_failures: 1,
            last_signal: Some(FailSignal::ThroughputCollapse),
            expected_first: "passthrough",
            expected_disposition: ProbeHistoryDisposition::None,
        },
        Case {
            name: "explicit_absence_single_stall",
            observation: Some(KeyObservation {
                capture_status: aegis_core::PacketCaptureStatus::UnsupportedPlatform,
                capture_backend: Some(aegis_core::PacketCaptureBackendKind::LinuxAfPacket),
                capture_filter_applied: true,
                capture_io_path: Some(
                    aegis_core::packet_observer::PacketCaptureIoPath::AfPacketRing,
                ),
                matched_packets: 2,
                syn_ack_ttl: Some(58),
                syn_ack_window: Some(65535),
                syn_ack_server_hint: Some(aegis_core::ServerType::LikelyCdn),
                ..Default::default()
            }),
            consecutive_stall_failures: 1,
            last_signal: Some(FailSignal::ThroughputCollapse),
            expected_first: "passthrough",
            expected_disposition: ProbeHistoryDisposition::None,
        },
        Case {
            name: "repeated_stall_prefer_relay",
            observation: Some(KeyObservation {
                matched_packets: 2,
                capture_status: aegis_core::PacketCaptureStatus::Active,
                first_data_ttl: Some(58),
                first_data_window: Some(65535),
                first_data_server_hint: Some(aegis_core::ServerType::LikelyCdn),
                ..Default::default()
            }),
            consecutive_stall_failures: 2,
            last_signal: Some(FailSignal::Timeout),
            expected_first: "passthrough",
            expected_disposition: ProbeHistoryDisposition::PreferRelay,
        },
    ];

    for case in cases {
        let dir = tempfile::tempdir().unwrap();
        let store = AsyncStateStore::load(dir.path().join("state.json"))
            .await
            .unwrap();
        let key = StrategyKey::for_target(
            "203.0.113.178:443".parse().unwrap(),
            case.name,
            443,
            Some(case.name),
            true,
        );
        let hk = key.hash_key();
        store
            .update(|snap| {
                snap.key_registry.insert(hk.clone(), key.clone());
                if let Some(observation) = case.observation.clone() {
                    snap.key_observations.insert(hk.clone(), observation);
                }
                if let Some(last_signal) = case.last_signal.clone() {
                    snap.stall_probe_stats.insert(
                        hk.clone(),
                        aegis_core::StallProbeStats {
                            trials: case.consecutive_stall_failures,
                            collapses: case.consecutive_stall_failures,
                            consecutive_stall_failures: case.consecutive_stall_failures,
                            last_signal: Some(last_signal),
                            ..Default::default()
                        },
                    );
                }
                let mut passthrough = aegis_core::StrategyStatsV2::default();
                passthrough.record(&FailSignal::Success, Some(20), 2048);
                passthrough.record(&FailSignal::Success, Some(22), 2048);
                let mut ttl_desync = aegis_core::StrategyStatsV2::default();
                ttl_desync.record(&FailSignal::Success, Some(20), 2048);
                ttl_desync.record(&FailSignal::Success, Some(22), 2048);
                snap.strategy_stats
                    .insert(format!("{hk}|passthrough"), passthrough);
                snap.strategy_stats
                    .insert(format!("{hk}|ttl_desync"), ttl_desync);
            })
            .await;

        let brain = Brain::new(0.0, vec!["passthrough".into(), "ttl_desync".into()], store);
        let advisory = brain.direct_session_advisory(&key).await;
        let order = brain.select_order(&key).await;
        assert_eq!(
            advisory.probe_history_disposition, case.expected_disposition,
            "case={}",
            case.name
        );
        assert_eq!(order[0], case.expected_first, "case={}", case.name);
    }
}

#[tokio::test]
async fn advisory_prefers_relay_after_repeated_stall_history() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let key = StrategyKey::for_target(
        "203.0.113.79:443".parse().unwrap(),
        "probe-advisory.example",
        443,
        Some("probe-advisory.example"),
        true,
    );
    let hk = key.hash_key();
    store
        .update(|snap| {
            snap.key_registry.insert(hk.clone(), key.clone());
            snap.key_observations.insert(
                hk.clone(),
                KeyObservation {
                    matched_packets: 2,
                    capture_status: aegis_core::PacketCaptureStatus::Active,
                    first_data_ttl: Some(58),
                    ..Default::default()
                },
            );
            snap.stall_probe_stats.insert(
                hk.clone(),
                aegis_core::StallProbeStats {
                    trials: 3,
                    collapses: 2,
                    timeouts: 1,
                    consecutive_stall_failures: 2,
                    last_signal: Some(FailSignal::Timeout),
                    ..Default::default()
                },
            );
        })
        .await;
    let brain = Brain::new(0.0, vec!["passthrough".into(), "ttl_desync".into()], store);
    let advisory = brain.direct_session_advisory(&key).await;
    assert_eq!(
        advisory.probe_history_disposition,
        ProbeHistoryDisposition::PreferRelay
    );
    assert_eq!(
        advisory.probe_history_reason_code,
        ProbeHistoryReasonCode::RepeatedStallPreferRelay
    );
    let payload = advisory.relay_preference_runtime_fields("probe-advisory.example", 443);
    assert_eq!(
        payload["probe_history_reason_code"],
        "repeated_stall_prefer_relay"
    );
    assert_eq!(payload["observation_contract"], "deep_observed");
    assert_eq!(payload["observation_capture_confidence"], "deep_observed");
    assert_eq!(
        payload["cross_session_signal_bias"],
        "relay_preference_bias"
    );
    assert!(
        payload["cross_session_relay_preference_score"]
            .as_f64()
            .expect("relay preference score")
            > 0.55
    );
    assert_eq!(
        payload["cross_session_probe_branch_score"],
        serde_json::json!(0.0)
    );
    assert_eq!(payload["stall_probe_timeouts"], 1);
    let trace = advisory.relay_preference_trace_context();
    assert_eq!(
        trace.probe_history_reason_code,
        "repeated_stall_prefer_relay"
    );
    assert_eq!(trace.observation_contract, "deep_observed");
    assert_eq!(trace.observation_capture_confidence, "deep_observed");
    assert_eq!(trace.cross_session_signal_bias, "relay_preference_bias");
    assert!(trace.cross_session_relay_preference_score > 0.55);
    assert_eq!(trace.cross_session_probe_branch_score, 0.0);
    assert_eq!(trace.stall_probe_timeouts, 1);
    let event = advisory.relay_preference_event_data("probe-advisory.example", 443);
    assert_eq!(
        event.message,
        "preferring relay tunnel from repeated stall-probe history"
    );
    assert_eq!(
        event.trace.probe_history_reason_code,
        "repeated_stall_prefer_relay"
    );
    assert_eq!(
        event.trace.cross_session_signal_bias,
        "relay_preference_bias"
    );
    assert_eq!(event.runtime_fields["stall_probe_timeouts"], 1);
    assert_eq!(
        event.runtime_fields["cross_session_signal_bias"],
        "relay_preference_bias"
    );
    assert!(
        event.runtime_fields["cross_session_relay_preference_score"]
            .as_f64()
            .expect("event relay preference score")
            > 0.55
    );
    assert!(
        event.runtime_fields["cross_session_confidence_score"]
            .as_f64()
            .expect("event confidence score")
            > 0.0
    );
    assert!(
        event.runtime_fields["cross_session_reuse_weight"]
            .as_f64()
            .expect("event reuse weight")
            > 0.0
    );
    let retry_event = advisory.active_stall_probe_retry_event_data(
        aegis_core::RuntimeEndpoint {
            target: "probe-advisory.example",
            port: 443,
        },
        &FailSignal::SuccessDegraded,
        aegis_core::ActiveStallProbePlanContext {
            preferred_ttl: 2,
            budget: 3,
            ttl_candidates: &[2, 1, 3],
        },
        Some("active_probe_connect_remote"),
    );
    assert_eq!(
        retry_event.message,
        "active stall probe recovered path confidence, retrying direct session once"
    );
    assert_eq!(retry_event.trace.probe_history_disposition, "prefer_relay");
    assert_eq!(
        retry_event.trace.observation_capture_confidence,
        "deep_observed"
    );
    assert_eq!(
        retry_event.trace.cross_session_signal_bias,
        "relay_preference_bias"
    );
    assert!(retry_event.trace.cross_session_relay_preference_score > 0.55);
    assert_eq!(retry_event.runtime_fields["signal"], "SuccessDegraded");
    assert_eq!(
        retry_event.runtime_fields["probe_outcome_class"],
        "success_degraded"
    );
    assert_eq!(
        retry_event.runtime_fields["observation_capture_confidence"],
        "deep_observed"
    );
    assert_eq!(
        retry_event.runtime_fields["cross_session_signal_bias"],
        "relay_preference_bias"
    );
    assert_eq!(
        retry_event.runtime_fields["probe_terminal_stage"],
        "active_probe_connect_remote"
    );
    let failover_event = aegis_core::direct_relay_failover_event_data(
        &FailSignal::ThroughputCollapse,
        aegis_core::ObservationContract::DeepObserved,
        "deep_observed",
        aegis_core::DirectRelayFailoverReasonCode::ProbeRetryBudgetExhausted,
        aegis_core::ObservationPathContext {
            reference_path_hops: Some(7),
            rst_path_hops: Some(3),
        },
        aegis_core::ActiveStallProbeFailoverContext {
            recommended: true,
            retry_attempted: true,
            terminal_stage: Some("active_probe_connect_remote"),
        },
        aegis_core::RuntimeEndpoint {
            target: "probe-advisory.example",
            port: 443,
        },
    );
    assert_eq!(
        failover_event.message,
        "direct session stalled, switching to relay tunnel"
    );
    assert_eq!(failover_event.trace.observation_contract, "deep_observed");
    assert_eq!(
        failover_event.trace.observation_capture_confidence,
        "deep_observed"
    );
    assert_eq!(
        failover_event.trace.direct_relay_failover_reason_code,
        "probe_retry_budget_exhausted"
    );
    assert_eq!(
        failover_event.trace.probe_outcome_class,
        "throughput_collapse"
    );
    assert!(failover_event.trace.active_stall_probe_retry_attempted);
    assert_eq!(failover_event.runtime_fields["reference_path_hops"], 7);
    assert_eq!(
        failover_event.runtime_fields["observation_capture_confidence"],
        "deep_observed"
    );
    assert_eq!(
        failover_event.runtime_fields["probe_outcome_class"],
        "throughput_collapse"
    );
    assert_eq!(
        failover_event.runtime_fields["probe_terminal_stage"],
        "active_probe_connect_remote"
    );
    let budget_event = aegis_core::active_stall_probe_retry_budget_exhausted_event_data(
        &FailSignal::SessionFreeze {
            bytes_before_stall: 16384,
        },
        aegis_core::ObservationContract::DeepObserved,
        "deep_observed",
        aegis_core::ObservationPathContext {
            reference_path_hops: Some(7),
            rst_path_hops: Some(3),
        },
        aegis_core::RetryBudgetContext {
            attempts_used: 2,
            attempts_budget: 2,
        },
        Some("active_probe_first_response_timeout"),
        aegis_core::RuntimeEndpoint {
            target: "probe-advisory.example",
            port: 443,
        },
    );
    assert_eq!(
        budget_event.message,
        "active stall probe retry budget exhausted, falling back to relay"
    );
    assert_eq!(budget_event.trace.retry_attempts_used, 2);
    assert_eq!(budget_event.trace.retry_attempts_budget, 2);
    assert_eq!(
        budget_event.trace.observation_capture_confidence,
        "deep_observed"
    );
    assert_eq!(budget_event.runtime_fields["rst_path_hops"], 3);
    assert_eq!(
        budget_event.runtime_fields["observation_capture_confidence"],
        "deep_observed"
    );
    assert_eq!(
        budget_event.runtime_fields["probe_outcome_class"],
        "session_freeze"
    );
    assert_eq!(
        budget_event.runtime_fields["probe_terminal_stage"],
        "active_probe_first_response_timeout"
    );
    let skipped_event = advisory.active_stall_probe_retry_skipped_event_data(
        aegis_core::RuntimeEndpoint {
            target: "probe-advisory.example",
            port: 443,
        },
        &FailSignal::ThroughputCollapse,
        aegis_core::ActiveStallProbeRetrySuppressedReasonCode::AdvisoryPreferRelay,
        aegis_core::RetryBudgetContext {
            attempts_used: 1,
            attempts_budget: 2,
        },
        Some("active_probe_first_response_timeout"),
    );
    assert_eq!(
        skipped_event.message,
        "active stall probe did not justify another direct retry"
    );
    assert_eq!(
        skipped_event.trace.retry_suppressed_reason_code,
        "advisory_prefer_relay"
    );
    assert_eq!(
        skipped_event.trace.observation_capture_confidence,
        "deep_observed"
    );
    assert_eq!(
        skipped_event.trace.cross_session_signal_bias,
        "relay_preference_bias"
    );
    assert!(skipped_event.trace.cross_session_confidence_score > 0.0);
    assert!(skipped_event.trace.cross_session_relay_preference_score > 0.55);
    assert_eq!(skipped_event.runtime_fields["retry_attempts_budget"], 2);
    assert_eq!(
        skipped_event.runtime_fields["probe_outcome_class"],
        "throughput_collapse"
    );
    assert_eq!(
        skipped_event.runtime_fields["observation_capture_confidence"],
        "deep_observed"
    );
    assert_eq!(
        skipped_event.runtime_fields["cross_session_signal_bias"],
        "relay_preference_bias"
    );
    assert!(
        skipped_event.runtime_fields["cross_session_confidence_score"]
            .as_f64()
            .expect("skipped confidence score")
            > 0.0
    );
    assert!(
        skipped_event.runtime_fields["cross_session_relay_preference_score"]
            .as_f64()
            .expect("skipped relay preference score")
            > 0.55
    );
    assert_eq!(
        skipped_event.runtime_fields["probe_terminal_stage"],
        "active_probe_first_response_timeout"
    );
}

#[test]
fn retry_suppressed_reason_maps_capture_backing_gap_to_failover_code() {
    assert_eq!(
        aegis_core::DirectRelayFailoverReasonCode::from_retry_suppressed_reason(
            aegis_core::ActiveStallProbeRetrySuppressedReasonCode::ProbeObservationNotCaptureBacked,
        ),
        aegis_core::DirectRelayFailoverReasonCode::ProbeObservationNotCaptureBackedAfterProbe
    );
}

#[tokio::test]
async fn advisory_biases_probe_branch_for_single_stall_history() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let key = StrategyKey::for_target(
        "203.0.113.80:443".parse().unwrap(),
        "probe-advisory-branch.example",
        443,
        Some("probe-advisory-branch.example"),
        true,
    );
    let hk = key.hash_key();
    store
        .update(|snap| {
            snap.key_registry.insert(hk.clone(), key.clone());
            snap.key_observations.insert(
                hk.clone(),
                KeyObservation {
                    matched_packets: 2,
                    capture_status: aegis_core::PacketCaptureStatus::Active,
                    first_data_ttl: Some(58),
                    first_data_window: Some(65535),
                    first_data_server_hint: Some(aegis_core::ServerType::LikelyCdn),
                    ..Default::default()
                },
            );
            snap.stall_probe_stats.insert(
                hk.clone(),
                aegis_core::StallProbeStats {
                    trials: 1,
                    collapses: 1,
                    consecutive_stall_failures: 1,
                    last_signal: Some(FailSignal::ThroughputCollapse),
                    ..Default::default()
                },
            );
        })
        .await;
    let brain = Brain::new(0.0, vec!["passthrough".into(), "ttl_desync".into()], store);
    let advisory = brain.direct_session_advisory(&key).await;
    assert_eq!(
        advisory.probe_history_disposition,
        ProbeHistoryDisposition::BiasProbeBranch
    );
    assert_eq!(
        advisory.probe_history_reason_code,
        ProbeHistoryReasonCode::SingleStallBiasProbeBranch
    );
    assert_eq!(
        advisory.apply_to_direct_order(
            vec![
                "passthrough".into(),
                "multisplit".into(),
                "ttl_desync".into(),
                "overlap".into(),
            ],
            true,
        ),
        vec!["ttl_desync", "overlap", "passthrough", "multisplit"]
    );
    let payload = advisory.probe_branch_runtime_fields(
        "probe-advisory-branch.example",
        443,
        2,
        3,
        &[2, 1, 3],
        &["ttl_desync".into(), "overlap".into(), "passthrough".into()],
    );
    assert_eq!(
        payload["probe_history_reason_code"],
        "single_stall_bias_probe_branch"
    );
    assert_eq!(payload["observation_contract"], "deep_observed");
    assert_eq!(payload["cross_session_signal_bias"], "probe_branch_bias");
    assert!(
        payload["cross_session_probe_branch_score"]
            .as_f64()
            .expect("probe branch score")
            > 0.0
    );
    assert_eq!(
        payload["cross_session_relay_preference_score"],
        serde_json::json!(0.0)
    );
    assert_eq!(payload["branch_order"][0], "ttl_desync");
    let trace = advisory.probe_branch_trace_context(
        2,
        3,
        &[2, 1, 3],
        &["ttl_desync".into(), "overlap".into(), "passthrough".into()],
    );
    assert_eq!(
        trace.probe_history_reason_code,
        "single_stall_bias_probe_branch"
    );
    assert_eq!(trace.observation_contract, "deep_observed");
    assert_eq!(trace.cross_session_signal_bias, "probe_branch_bias");
    assert!(trace.cross_session_probe_branch_score > 0.0);
    assert_eq!(trace.cross_session_relay_preference_score, 0.0);
    assert_eq!(trace.server_hint, Some("likely_cdn"));
    assert_eq!(trace.branch_order[0], "ttl_desync");
    let event = advisory.probe_branch_event_data(
        "probe-advisory-branch.example",
        443,
        2,
        3,
        &[2, 1, 3],
        &["ttl_desync".into(), "overlap".into(), "passthrough".into()],
    );
    assert_eq!(
        event.message,
        "preferring probe-aligned direct branch before relay escalation"
    );
    assert_eq!(
        event.trace.probe_history_reason_code,
        "single_stall_bias_probe_branch"
    );
    assert_eq!(event.trace.cross_session_signal_bias, "probe_branch_bias");
    assert!(event.trace.cross_session_probe_branch_score > 0.0);
    assert_eq!(
        event.runtime_fields["cross_session_signal_bias"],
        "probe_branch_bias"
    );
    assert_eq!(event.runtime_fields["branch_order"][0], "ttl_desync");
    let launched = aegis_core::active_stall_probe_launched_event_data(
        &FailSignal::SessionFreeze {
            bytes_before_stall: 16384,
        },
        aegis_core::ObservationContract::DeepObserved,
        "probe-advisory-branch.example",
        443,
        2,
        3,
        &[2, 1, 3],
    );
    assert_eq!(launched.message, "launching active stall probe");
    assert_eq!(launched.trace.observation_contract, "deep_observed");
    assert_eq!(launched.runtime_fields["planned_probe_budget"], 3);
    let success = aegis_core::direct_session_succeeded_event_data(
        "ttl_desync",
        &FailSignal::SuccessDegraded,
        advisory
            .latest_observation
            .as_ref()
            .expect("probe advisory observation"),
        advisory.probe_history_disposition,
        advisory.probe_history_reason_code,
        aegis_core::RuntimeEndpoint {
            target: "probe-advisory-branch.example",
            port: 443,
        },
        aegis_core::DirectSessionSuccessMetrics {
            latency_ms: 123,
            bytes_sent: 64,
            retry_attempts_used: 1,
        },
    );
    assert_eq!(success.message, "direct session succeeded");
    assert_eq!(success.trace.strategy, "ttl_desync");
    assert_eq!(success.trace.probe_outcome_class, "success_degraded");
    assert_eq!(
        success.trace.observation_capture_confidence,
        "deep_observed"
    );
    assert_eq!(success.trace.probe_history_disposition, "bias_probe_branch");
    assert_eq!(
        success.trace.probe_history_reason_code,
        "single_stall_bias_probe_branch"
    );
    assert!(success.trace.active_stall_probe_retry_attempted);
    assert_eq!(success.runtime_fields["retry_attempts_used"], 1);
    let finished = aegis_core::active_stall_probe_finished_event_data(
        &FailSignal::Success,
        advisory
            .latest_observation
            .as_ref()
            .expect("probe advisory observation"),
        aegis_core::RuntimeEndpoint {
            target: "probe-advisory-branch.example",
            port: 443,
        },
        aegis_core::ActiveStallProbePlanContext {
            preferred_ttl: 2,
            budget: 3,
            ttl_candidates: &[2, 1, 3],
        },
        aegis_core::ActiveStallProbeFinishContext {
            latency_ms: 120,
            first_response_bytes: 512,
            terminal_stage: None,
        },
    );
    assert_eq!(finished.message, "active stall probe finished");
    assert_eq!(finished.trace.signal, "Success");
    assert_eq!(finished.trace.probe_outcome_class, "success");
    assert_eq!(
        finished.trace.observation_capture_confidence,
        "deep_observed"
    );
    assert_eq!(finished.trace.server_hint, Some("likely_cdn"));
    assert_eq!(finished.runtime_fields["first_response_bytes"], 512);
    assert_eq!(
        finished.runtime_fields["probe_terminal_stage"],
        serde_json::Value::Null
    );
}

#[tokio::test]
async fn advisory_reports_missing_probe_history_reason() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let brain = Brain::new(0.0, vec!["passthrough".into(), "ttl_desync".into()], store);
    let key = StrategyKey::for_target(
        "203.0.113.81:443".parse().unwrap(),
        "probe-no-history.example",
        443,
        Some("probe-no-history.example"),
        true,
    );
    let advisory = brain.direct_session_advisory(&key).await;
    assert_eq!(
        advisory.probe_history_disposition,
        ProbeHistoryDisposition::None
    );
    assert_eq!(
        advisory.probe_history_reason_code,
        ProbeHistoryReasonCode::NoRecentProbeHistory
    );
}

#[tokio::test]
async fn brain_ignores_low_confidence_raw_basic_syn_ack_observation() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let brain = Brain::new(
        0.0,
        vec!["multisplit".into(), "passthrough".into()],
        store.clone(),
    );
    let key = StrategyKey::for_target(
        "203.0.113.45:443".parse().unwrap(),
        "low-confidence.example",
        443,
        Some("low-confidence.example"),
        true,
    );
    brain
        .record_outcome(
            &key,
            "passthrough",
            FailSignal::RemoteReset,
            Some(30),
            1024,
            Some(KeyObservation {
                first_response_bytes: 0,
                tls_server_hello_seen: false,
                ja3s_md5: None,
                relay_client_to_remote_bytes: 0,
                relay_remote_to_client_bytes: 0,
                relay_lifetime_ms: 0,
                configured_timeout_ms: 0,
                capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
                capture_backend: Some(aegis_core::PacketCaptureBackendKind::LinuxRawBasic),
                capture_filter_applied: false,
                capture_ring_layout: None,
                capture_io_path: Some(
                    aegis_core::packet_observer::PacketCaptureIoPath::RawBasicRecv,
                ),
                capture_wait_cycles: 1,
                downstream_dup_ack_count: 0,
                downstream_retransmit_count: 0,
                downstream_fin_after_data: false,
                matched_packets: 1,
                syn_ack_ttl: Some(58),
                syn_ack_window: Some(65535),
                syn_ack_mss: None,
                syn_ack_window_scale: None,
                syn_ack_sack_permitted: None,
                syn_ack_timestamp_option: None,
                syn_ack_server_hint: Some(aegis_core::ServerType::LikelyCdn),
                first_data_ttl: None,
                first_data_window: None,
                first_data_payload_len: None,
                first_data_flags: None,
                first_data_server_hint: None,
                first_packet_ttl: Some(58),
                first_packet_ip_tos: None,
                first_packet_ip_id: None,
                first_packet_ip_df: None,
                first_packet_window: Some(65535),
                first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
                server_hint: Some(aegis_core::ServerType::LikelyCdn),
                rst_ttl: None,
                rst_source: None,
            }),
        )
        .await;

    let snap = store.snapshot().await;
    let matching_candidates: Vec<_> = snap
        .key_registry
        .values()
        .filter(|candidate| {
            candidate.target_host_hash == key.target_host_hash
                && candidate.target_port == key.target_port
        })
        .collect();
    assert!(!matching_candidates.is_empty());
    assert!(matching_candidates
        .iter()
        .all(|candidate| candidate.packet_stage_hint.is_none()));
    assert!(matching_candidates
        .iter()
        .all(|candidate| candidate.server_hint.is_none()));
    assert!(matching_candidates
        .iter()
        .all(|candidate| candidate.fingerprint_window_hint.is_none()));
    assert!(matching_candidates
        .iter()
        .all(|candidate| candidate.reference_hop_hint.is_none()));
    assert!(matching_candidates
        .iter()
        .all(|candidate| candidate.reset_profile_hint.is_none()));
}

#[tokio::test]
async fn brain_ignores_shallow_hints_without_capture_backend() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let brain = Brain::new(
        0.0,
        vec!["multisplit".into(), "passthrough".into()],
        store.clone(),
    );
    let key = StrategyKey::for_target(
        "203.0.113.145:443".parse().unwrap(),
        "no-capture.example",
        443,
        Some("no-capture.example"),
        true,
    );
    brain
        .record_outcome(
            &key,
            "passthrough",
            FailSignal::RemoteReset,
            Some(30),
            1024,
            Some(KeyObservation {
                first_response_bytes: 0,
                tls_server_hello_seen: false,
                ja3s_md5: None,
                relay_client_to_remote_bytes: 0,
                relay_remote_to_client_bytes: 0,
                relay_lifetime_ms: 0,
                configured_timeout_ms: 0,
                capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
                capture_backend: None,
                capture_filter_applied: false,
                capture_ring_layout: None,
                capture_io_path: None,
                capture_wait_cycles: 0,
                downstream_dup_ack_count: 0,
                downstream_retransmit_count: 0,
                downstream_fin_after_data: false,
                matched_packets: 2,
                syn_ack_ttl: Some(58),
                syn_ack_window: Some(32768),
                syn_ack_mss: None,
                syn_ack_window_scale: None,
                syn_ack_sack_permitted: None,
                syn_ack_timestamp_option: None,
                syn_ack_server_hint: Some(aegis_core::ServerType::LikelyCdn),
                first_data_ttl: None,
                first_data_window: None,
                first_data_payload_len: None,
                first_data_flags: None,
                first_data_server_hint: None,
                first_packet_ttl: Some(58),
                first_packet_ip_tos: None,
                first_packet_ip_id: None,
                first_packet_ip_df: None,
                first_packet_window: Some(32768),
                first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
                server_hint: Some(aegis_core::ServerType::LikelyCdn),
                rst_ttl: Some(30),
                rst_source: Some(RstSource::Middlebox),
            }),
        )
        .await;

    let snap = store.snapshot().await;
    let matching_candidates: Vec<_> = snap
        .key_registry
        .values()
        .filter(|candidate| {
            candidate.target_host_hash == key.target_host_hash
                && candidate.target_port == key.target_port
        })
        .collect();
    assert!(!matching_candidates.is_empty());
    assert!(matching_candidates
        .iter()
        .all(|candidate| candidate.packet_stage_hint.is_none()));
    assert!(matching_candidates
        .iter()
        .all(|candidate| candidate.server_hint.is_none()));
    assert!(matching_candidates
        .iter()
        .all(|candidate| candidate.fingerprint_window_hint.is_none()));
    assert!(matching_candidates
        .iter()
        .all(|candidate| candidate.reference_hop_hint.is_none()));
    assert!(matching_candidates
        .iter()
        .all(|candidate| candidate.reset_profile_hint.is_none()));
}

#[tokio::test]
async fn brain_ignores_explicit_observer_absence_even_with_stale_capture_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let brain = Brain::new(
        0.0,
        vec!["multisplit".into(), "passthrough".into()],
        store.clone(),
    );
    let key = StrategyKey::for_target(
        "203.0.113.146:443".parse().unwrap(),
        "explicit-no-capture.example",
        443,
        Some("explicit-no-capture.example"),
        true,
    );
    brain
        .record_outcome(
            &key,
            "passthrough",
            FailSignal::RemoteReset,
            Some(30),
            1024,
            Some(KeyObservation {
                first_response_bytes: 0,
                tls_server_hello_seen: false,
                ja3s_md5: None,
                relay_client_to_remote_bytes: 0,
                relay_remote_to_client_bytes: 0,
                relay_lifetime_ms: 0,
                configured_timeout_ms: 0,
                capture_status: aegis_core::PacketCaptureStatus::UnsupportedPlatform,
                capture_backend: Some(aegis_core::PacketCaptureBackendKind::LinuxAfPacket),
                capture_filter_applied: true,
                capture_ring_layout: Some(aegis_core::packet_observer::PacketCaptureRingLayout {
                    block_size: 8192,
                    block_nr: 2,
                    frame_size: 4096,
                    frame_nr: 4,
                }),
                capture_io_path: Some(
                    aegis_core::packet_observer::PacketCaptureIoPath::AfPacketRing,
                ),
                capture_wait_cycles: 1,
                downstream_dup_ack_count: 0,
                downstream_retransmit_count: 0,
                downstream_fin_after_data: false,
                matched_packets: 2,
                syn_ack_ttl: Some(58),
                syn_ack_window: Some(32768),
                syn_ack_mss: None,
                syn_ack_window_scale: None,
                syn_ack_sack_permitted: None,
                syn_ack_timestamp_option: None,
                syn_ack_server_hint: Some(aegis_core::ServerType::LikelyCdn),
                first_data_ttl: None,
                first_data_window: None,
                first_data_payload_len: None,
                first_data_flags: None,
                first_data_server_hint: None,
                first_packet_ttl: Some(58),
                first_packet_ip_tos: None,
                first_packet_ip_id: None,
                first_packet_ip_df: None,
                first_packet_window: Some(32768),
                first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
                server_hint: Some(aegis_core::ServerType::LikelyCdn),
                rst_ttl: Some(30),
                rst_source: Some(RstSource::Middlebox),
            }),
        )
        .await;

    let snap = store.snapshot().await;
    let matching_candidates: Vec<_> = snap
        .key_registry
        .values()
        .filter(|candidate| {
            candidate.target_host_hash == key.target_host_hash
                && candidate.target_port == key.target_port
        })
        .collect();
    assert!(!matching_candidates.is_empty());
    assert!(matching_candidates
        .iter()
        .all(|candidate| candidate.packet_stage_hint.is_none()));
    assert!(matching_candidates
        .iter()
        .all(|candidate| candidate.server_hint.is_none()));
    assert!(matching_candidates
        .iter()
        .all(|candidate| candidate.fingerprint_window_hint.is_none()));
    assert!(matching_candidates
        .iter()
        .all(|candidate| candidate.reference_hop_hint.is_none()));
    assert!(matching_candidates
        .iter()
        .all(|candidate| candidate.reset_profile_hint.is_none()));
}

#[tokio::test]
async fn brain_enriches_high_confidence_middlebox_probe_hints() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let brain = Brain::new(
        0.0,
        vec!["multisplit".into(), "passthrough".into()],
        store.clone(),
    );
    let key = StrategyKey::for_target(
        "203.0.113.46:443".parse().unwrap(),
        "middlebox-hints.example",
        443,
        Some("middlebox-hints.example"),
        true,
    );
    brain
        .record_outcome(
            &key,
            "multisplit",
            FailSignal::DropSuspected,
            Some(30),
            1024,
            Some(KeyObservation {
                first_response_bytes: 0,
                tls_server_hello_seen: false,
                ja3s_md5: None,
                relay_client_to_remote_bytes: 0,
                relay_remote_to_client_bytes: 0,
                relay_lifetime_ms: 0,
                configured_timeout_ms: 0,
                capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
                capture_backend: Some(aegis_core::PacketCaptureBackendKind::LinuxAfPacket),
                capture_filter_applied: true,
                capture_ring_layout: None,
                capture_io_path: Some(
                    aegis_core::packet_observer::PacketCaptureIoPath::AfPacketRecv,
                ),
                capture_wait_cycles: 1,
                downstream_dup_ack_count: 0,
                downstream_retransmit_count: 0,
                downstream_fin_after_data: false,
                matched_packets: 2,
                syn_ack_ttl: Some(58),
                syn_ack_window: Some(65535),
                syn_ack_mss: None,
                syn_ack_window_scale: None,
                syn_ack_sack_permitted: None,
                syn_ack_timestamp_option: None,
                syn_ack_server_hint: Some(aegis_core::ServerType::LikelyCdn),
                first_data_ttl: None,
                first_data_window: None,
                first_data_payload_len: None,
                first_data_flags: None,
                first_data_server_hint: None,
                first_packet_ttl: Some(58),
                first_packet_ip_tos: None,
                first_packet_ip_id: None,
                first_packet_ip_df: None,
                first_packet_window: Some(65535),
                first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
                server_hint: Some(aegis_core::ServerType::LikelyCdn),
                rst_ttl: Some(30),
                rst_source: Some(RstSource::Middlebox),
            }),
        )
        .await;

    let snap = store.snapshot().await;
    let enriched = snap
        .key_registry
        .values()
        .find(|candidate| {
            candidate.target_host_hash == key.target_host_hash
                && candidate.target_port == key.target_port
                && candidate.reset_profile_hint.is_some()
        })
        .expect("enriched key with probe hints stored");
    assert_eq!(enriched.fingerprint_window_hint, Some(WindowProfile::Huge));
    assert_eq!(enriched.reference_hop_hint, Some(PathHopHint::Near));
    assert_eq!(
        enriched.reset_profile_hint,
        Some(ResetProfileHint::MiddleboxPath)
    );
}

#[tokio::test]
async fn brain_enriches_window_profile_even_when_server_type_is_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let brain = Brain::new(
        0.0,
        vec!["multisplit".into(), "passthrough".into()],
        store.clone(),
    );
    let key = StrategyKey::for_target(
        "203.0.113.47:443".parse().unwrap(),
        "window-profile.example",
        443,
        Some("window-profile.example"),
        true,
    );
    brain
        .record_outcome(
            &key,
            "passthrough",
            FailSignal::Success,
            Some(25),
            4096,
            Some(KeyObservation {
                first_response_bytes: 0,
                tls_server_hello_seen: false,
                ja3s_md5: None,
                relay_client_to_remote_bytes: 0,
                relay_remote_to_client_bytes: 0,
                relay_lifetime_ms: 0,
                configured_timeout_ms: 0,
                capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
                capture_backend: Some(aegis_core::PacketCaptureBackendKind::LinuxAfPacket),
                capture_filter_applied: true,
                capture_ring_layout: None,
                capture_io_path: Some(
                    aegis_core::packet_observer::PacketCaptureIoPath::AfPacketRecv,
                ),
                capture_wait_cycles: 1,
                downstream_dup_ack_count: 0,
                downstream_retransmit_count: 0,
                downstream_fin_after_data: false,
                matched_packets: 2,
                syn_ack_ttl: Some(58),
                syn_ack_window: Some(32768),
                syn_ack_mss: None,
                syn_ack_window_scale: None,
                syn_ack_sack_permitted: None,
                syn_ack_timestamp_option: None,
                syn_ack_server_hint: None,
                first_data_ttl: None,
                first_data_window: None,
                first_data_payload_len: None,
                first_data_flags: None,
                first_data_server_hint: None,
                first_packet_ttl: Some(58),
                first_packet_ip_tos: None,
                first_packet_ip_id: None,
                first_packet_ip_df: None,
                first_packet_window: Some(32768),
                first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
                server_hint: None,
                rst_ttl: None,
                rst_source: None,
            }),
        )
        .await;

    let snap = store.snapshot().await;
    let enriched = snap
        .key_registry
        .values()
        .find(|candidate| {
            candidate.target_host_hash == key.target_host_hash
                && candidate.target_port == key.target_port
                && candidate.fingerprint_window_hint.is_some()
        })
        .expect("enriched key with window profile stored");
    assert_eq!(enriched.server_hint, None);
    assert_eq!(enriched.fingerprint_window_hint, Some(WindowProfile::Large));
}

#[tokio::test]
async fn brain_prefers_high_confidence_capture_history_over_low_confidence_one() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();

    let low_conf_key = StrategyKey::for_target(
        "203.0.113.51:443".parse().unwrap(),
        "raw-basic-history.example",
        443,
        Some("raw-basic-history.example"),
        true,
    );
    let high_conf_key = StrategyKey::for_target(
        "203.0.113.52:443".parse().unwrap(),
        "af-packet-history.example",
        443,
        Some("af-packet-history.example"),
        true,
    );
    let low_conf_hash = low_conf_key.hash_key();
    let high_conf_hash = high_conf_key.hash_key();

    store
        .update(|snap| {
            snap.key_registry
                .insert(low_conf_hash.clone(), low_conf_key.clone());
            snap.key_registry
                .insert(high_conf_hash.clone(), high_conf_key.clone());

            snap.key_observations.insert(
                low_conf_hash.clone(),
                KeyObservation {
                    first_response_bytes: 0,
                    tls_server_hello_seen: false,
                    ja3s_md5: None,
                    relay_client_to_remote_bytes: 0,
                    relay_remote_to_client_bytes: 0,
                    relay_lifetime_ms: 0,
                    configured_timeout_ms: 0,
                    capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
                    capture_backend: Some(aegis_core::PacketCaptureBackendKind::LinuxRawBasic),
                    capture_filter_applied: false,
                    capture_ring_layout: None,
                    capture_io_path: Some(
                        aegis_core::packet_observer::PacketCaptureIoPath::RawBasicRecv,
                    ),
                    capture_wait_cycles: 1,
                    downstream_dup_ack_count: 0,
                    downstream_retransmit_count: 0,
                    downstream_fin_after_data: false,
                    matched_packets: 1,
                    syn_ack_ttl: Some(58),
                    syn_ack_window: Some(65535),
                    syn_ack_mss: None,
                    syn_ack_window_scale: None,
                    syn_ack_sack_permitted: None,
                    syn_ack_timestamp_option: None,
                    syn_ack_server_hint: Some(aegis_core::ServerType::LikelyCdn),
                    first_data_ttl: None,
                    first_data_window: None,
                    first_data_payload_len: None,
                    first_data_flags: None,
                    first_data_server_hint: None,
                    first_packet_ttl: Some(58),
                    first_packet_ip_tos: None,
                    first_packet_ip_id: None,
                    first_packet_ip_df: None,
                    first_packet_window: Some(65535),
                    first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
                    server_hint: Some(aegis_core::ServerType::LikelyCdn),
                    rst_ttl: None,
                    rst_source: None,
                },
            );
            snap.key_observations.insert(
                high_conf_hash.clone(),
                KeyObservation {
                    first_response_bytes: 0,
                    tls_server_hello_seen: false,
                    ja3s_md5: None,
                    relay_client_to_remote_bytes: 0,
                    relay_remote_to_client_bytes: 0,
                    relay_lifetime_ms: 0,
                    configured_timeout_ms: 0,
                    capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
                    capture_backend: Some(aegis_core::PacketCaptureBackendKind::LinuxAfPacket),
                    capture_filter_applied: true,
                    capture_ring_layout: Some(
                        aegis_core::packet_observer::PacketCaptureRingLayout {
                            block_size: 8192,
                            block_nr: 3,
                            frame_size: 4096,
                            frame_nr: 6,
                        },
                    ),
                    capture_io_path: Some(
                        aegis_core::packet_observer::PacketCaptureIoPath::AfPacketRing,
                    ),
                    capture_wait_cycles: 1,
                    downstream_dup_ack_count: 0,
                    downstream_retransmit_count: 0,
                    downstream_fin_after_data: false,
                    matched_packets: 2,
                    syn_ack_ttl: Some(58),
                    syn_ack_window: Some(65535),
                    syn_ack_mss: None,
                    syn_ack_window_scale: None,
                    syn_ack_sack_permitted: None,
                    syn_ack_timestamp_option: None,
                    syn_ack_server_hint: Some(aegis_core::ServerType::LikelyCdn),
                    first_data_ttl: None,
                    first_data_window: None,
                    first_data_payload_len: None,
                    first_data_flags: None,
                    first_data_server_hint: None,
                    first_packet_ttl: Some(58),
                    first_packet_ip_tos: None,
                    first_packet_ip_id: None,
                    first_packet_ip_df: None,
                    first_packet_window: Some(65535),
                    first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
                    server_hint: Some(aegis_core::ServerType::LikelyCdn),
                    rst_ttl: None,
                    rst_source: None,
                },
            );

            let mut low_conf_stats = aegis_core::StrategyStatsV2::default();
            low_conf_stats.record(&FailSignal::Success, Some(20), 2048);
            low_conf_stats.record(&FailSignal::Success, Some(18), 2048);
            snap.strategy_stats
                .insert(format!("{low_conf_hash}|passthrough"), low_conf_stats);

            let mut high_conf_stats = aegis_core::StrategyStatsV2::default();
            high_conf_stats.record(&FailSignal::Success, Some(20), 2048);
            high_conf_stats.record(&FailSignal::Success, Some(18), 2048);
            snap.strategy_stats
                .insert(format!("{high_conf_hash}|multisplit"), high_conf_stats);
        })
        .await;

    let brain = Brain::new(0.0, vec!["passthrough".into(), "multisplit".into()], store);
    let new_key = StrategyKey::for_target(
        "203.0.113.77:443".parse().unwrap(),
        "new-history.example",
        443,
        Some("new-history.example"),
        true,
    );

    let order = brain.select_order(&new_key).await;
    assert_eq!(order[0], "multisplit");
}

#[tokio::test]
async fn brain_prefers_high_confidence_packet_first_data_reset_over_low_confidence_one() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let brain = Brain::new(
        0.0,
        vec!["passthrough".into(), "multisplit".into()],
        store.clone(),
    );
    let key = StrategyKey::for_target(
        "203.0.113.53:443".parse().unwrap(),
        "first-data-confidence.example",
        443,
        Some("first-data-confidence.example"),
        true,
    );

    let low_confidence = KeyObservation {
        first_response_bytes: 0,
        tls_server_hello_seen: false,
        ja3s_md5: None,
        relay_client_to_remote_bytes: 0,
        relay_remote_to_client_bytes: 0,
        relay_lifetime_ms: 0,
        configured_timeout_ms: 0,
        capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
        capture_backend: Some(aegis_core::PacketCaptureBackendKind::LinuxRawBasic),
        capture_filter_applied: false,
        capture_ring_layout: None,
        capture_io_path: Some(aegis_core::packet_observer::PacketCaptureIoPath::RawBasicRecv),
        capture_wait_cycles: 1,
        downstream_dup_ack_count: 0,
        downstream_retransmit_count: 0,
        downstream_fin_after_data: false,
        matched_packets: 1,
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_mss: None,
        syn_ack_window_scale: None,
        syn_ack_sack_permitted: None,
        syn_ack_timestamp_option: None,
        syn_ack_server_hint: None,
        first_data_ttl: Some(58),
        first_data_window: Some(65535),
        first_data_payload_len: None,
        first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
        first_data_server_hint: None,
        first_packet_ttl: Some(58),
        first_packet_ip_tos: None,
        first_packet_ip_id: None,
        first_packet_ip_df: None,
        first_packet_window: Some(65535),
        first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
        server_hint: None,
        rst_ttl: Some(58),
        rst_source: Some(RstSource::Remote),
    };
    let high_confidence = KeyObservation {
        first_response_bytes: 0,
        tls_server_hello_seen: false,
        ja3s_md5: None,
        relay_client_to_remote_bytes: 0,
        relay_remote_to_client_bytes: 0,
        relay_lifetime_ms: 0,
        configured_timeout_ms: 0,
        capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
        capture_backend: Some(aegis_core::PacketCaptureBackendKind::LinuxAfPacket),
        capture_filter_applied: true,
        capture_ring_layout: Some(aegis_core::packet_observer::PacketCaptureRingLayout {
            block_size: 8192,
            block_nr: 3,
            frame_size: 4096,
            frame_nr: 6,
        }),
        capture_io_path: Some(aegis_core::packet_observer::PacketCaptureIoPath::AfPacketRing),
        capture_wait_cycles: 1,
        downstream_dup_ack_count: 0,
        downstream_retransmit_count: 0,
        downstream_fin_after_data: false,
        matched_packets: 2,
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_mss: None,
        syn_ack_window_scale: None,
        syn_ack_sack_permitted: None,
        syn_ack_timestamp_option: None,
        syn_ack_server_hint: None,
        first_data_ttl: Some(58),
        first_data_window: Some(65535),
        first_data_payload_len: None,
        first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
        first_data_server_hint: None,
        first_packet_ttl: Some(58),
        first_packet_ip_tos: None,
        first_packet_ip_id: None,
        first_packet_ip_df: None,
        first_packet_window: Some(65535),
        first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
        server_hint: None,
        rst_ttl: Some(58),
        rst_source: Some(RstSource::Remote),
    };

    brain
        .record_outcome(
            &key,
            "passthrough",
            FailSignal::RemoteReset,
            Some(45),
            2048,
            Some(low_confidence.clone()),
        )
        .await;
    brain
        .record_outcome(
            &key,
            "passthrough",
            FailSignal::RemoteReset,
            Some(48),
            2048,
            Some(low_confidence),
        )
        .await;

    brain
        .record_outcome(
            &key,
            "multisplit",
            FailSignal::RemoteReset,
            Some(45),
            2048,
            Some(high_confidence.clone()),
        )
        .await;
    brain
        .record_outcome(
            &key,
            "multisplit",
            FailSignal::RemoteReset,
            Some(48),
            2048,
            Some(high_confidence),
        )
        .await;

    let snap = store.snapshot().await;
    let passthrough_fitness = snap
        .strategy_stats
        .iter()
        .filter(|(entry, _)| entry.ends_with("|passthrough"))
        .map(|(_, stats)| stats.fitness_score)
        .reduce(f64::max)
        .expect("passthrough stats stored");
    let multisplit_fitness = snap
        .strategy_stats
        .iter()
        .filter(|(entry, _)| entry.ends_with("|multisplit"))
        .map(|(_, stats)| stats.fitness_score)
        .reduce(f64::max)
        .expect("multisplit stats stored");
    assert!(multisplit_fitness > passthrough_fitness);
}

#[tokio::test]
async fn brain_prefers_low_wait_capture_history_over_high_wait_one() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();

    let high_wait_key = StrategyKey::for_target(
        "203.0.113.54:443".parse().unwrap(),
        "high-wait-history.example",
        443,
        Some("high-wait-history.example"),
        true,
    );
    let low_wait_key = StrategyKey::for_target(
        "203.0.113.55:443".parse().unwrap(),
        "low-wait-history.example",
        443,
        Some("low-wait-history.example"),
        true,
    );
    let high_wait_hash = high_wait_key.hash_key();
    let low_wait_hash = low_wait_key.hash_key();

    store
        .update(|snap| {
            snap.key_registry
                .insert(high_wait_hash.clone(), high_wait_key.clone());
            snap.key_registry
                .insert(low_wait_hash.clone(), low_wait_key.clone());

            let shared_ring = aegis_core::packet_observer::PacketCaptureRingLayout {
                block_size: 8192,
                block_nr: 3,
                frame_size: 4096,
                frame_nr: 6,
            };

            snap.key_observations.insert(
                high_wait_hash.clone(),
                KeyObservation {
                    first_response_bytes: 0,
                    tls_server_hello_seen: false,
                    ja3s_md5: None,
                    relay_client_to_remote_bytes: 0,
                    relay_remote_to_client_bytes: 0,
                    relay_lifetime_ms: 0,
                    configured_timeout_ms: 0,
                    capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
                    capture_backend: Some(aegis_core::PacketCaptureBackendKind::LinuxAfPacket),
                    capture_filter_applied: true,
                    capture_ring_layout: Some(shared_ring),
                    capture_io_path: Some(
                        aegis_core::packet_observer::PacketCaptureIoPath::AfPacketRing,
                    ),
                    capture_wait_cycles: 24,
                    downstream_dup_ack_count: 0,
                    downstream_retransmit_count: 0,
                    downstream_fin_after_data: false,
                    matched_packets: 1,
                    syn_ack_ttl: Some(58),
                    syn_ack_window: Some(65535),
                    syn_ack_mss: None,
                    syn_ack_window_scale: None,
                    syn_ack_sack_permitted: None,
                    syn_ack_timestamp_option: None,
                    syn_ack_server_hint: Some(aegis_core::ServerType::LikelyCdn),
                    first_data_ttl: None,
                    first_data_window: None,
                    first_data_payload_len: None,
                    first_data_flags: None,
                    first_data_server_hint: None,
                    first_packet_ttl: Some(58),
                    first_packet_ip_tos: None,
                    first_packet_ip_id: None,
                    first_packet_ip_df: None,
                    first_packet_window: Some(65535),
                    first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
                    server_hint: Some(aegis_core::ServerType::LikelyCdn),
                    rst_ttl: None,
                    rst_source: None,
                },
            );
            snap.key_observations.insert(
                low_wait_hash.clone(),
                KeyObservation {
                    first_response_bytes: 0,
                    tls_server_hello_seen: false,
                    ja3s_md5: None,
                    relay_client_to_remote_bytes: 0,
                    relay_remote_to_client_bytes: 0,
                    relay_lifetime_ms: 0,
                    configured_timeout_ms: 0,
                    capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
                    capture_backend: Some(aegis_core::PacketCaptureBackendKind::LinuxAfPacket),
                    capture_filter_applied: true,
                    capture_ring_layout: Some(shared_ring),
                    capture_io_path: Some(
                        aegis_core::packet_observer::PacketCaptureIoPath::AfPacketRing,
                    ),
                    capture_wait_cycles: 1,
                    downstream_dup_ack_count: 0,
                    downstream_retransmit_count: 0,
                    downstream_fin_after_data: false,
                    matched_packets: 1,
                    syn_ack_ttl: Some(58),
                    syn_ack_window: Some(65535),
                    syn_ack_mss: None,
                    syn_ack_window_scale: None,
                    syn_ack_sack_permitted: None,
                    syn_ack_timestamp_option: None,
                    syn_ack_server_hint: Some(aegis_core::ServerType::LikelyCdn),
                    first_data_ttl: None,
                    first_data_window: None,
                    first_data_payload_len: None,
                    first_data_flags: None,
                    first_data_server_hint: None,
                    first_packet_ttl: Some(58),
                    first_packet_ip_tos: None,
                    first_packet_ip_id: None,
                    first_packet_ip_df: None,
                    first_packet_window: Some(65535),
                    first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
                    server_hint: Some(aegis_core::ServerType::LikelyCdn),
                    rst_ttl: None,
                    rst_source: None,
                },
            );

            let mut high_wait_stats = aegis_core::StrategyStatsV2::default();
            high_wait_stats.record(&FailSignal::Success, Some(20), 2048);
            high_wait_stats.record(&FailSignal::Success, Some(18), 2048);
            snap.strategy_stats
                .insert(format!("{high_wait_hash}|passthrough"), high_wait_stats);

            let mut low_wait_stats = aegis_core::StrategyStatsV2::default();
            low_wait_stats.record(&FailSignal::Success, Some(20), 2048);
            low_wait_stats.record(&FailSignal::Success, Some(18), 2048);
            snap.strategy_stats
                .insert(format!("{low_wait_hash}|multisplit"), low_wait_stats);
        })
        .await;

    let brain = Brain::new(0.0, vec!["passthrough".into(), "multisplit".into()], store);
    let new_key = StrategyKey::for_target(
        "203.0.113.78:443".parse().unwrap(),
        "new-wait-history.example",
        443,
        Some("new-wait-history.example"),
        true,
    );

    let order = brain.select_order(&new_key).await;
    assert_eq!(order[0], "multisplit");
}

#[tokio::test]
async fn brain_prefers_deeper_stage_histories_during_reuse() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();

    let mut syn_ack_key = StrategyKey::for_target(
        "203.0.113.11:443".parse().unwrap(),
        "syn-only.example",
        443,
        Some("syn-only.example"),
        true,
    );
    syn_ack_key.packet_stage_hint = Some(PacketStageHint::SynAckSeen);
    let syn_ack_hash = syn_ack_key.hash_key();

    let mut first_data_key = StrategyKey::for_target(
        "203.0.113.12:443".parse().unwrap(),
        "data-stage.example",
        443,
        Some("data-stage.example"),
        true,
    );
    first_data_key.packet_stage_hint = Some(PacketStageHint::FirstDataSeen);
    let first_data_hash = first_data_key.hash_key();

    store
        .update(|snap| {
            snap.key_registry
                .insert(syn_ack_hash.clone(), syn_ack_key.clone());
            snap.key_registry
                .insert(first_data_hash.clone(), first_data_key.clone());

            let mut passthrough = aegis_core::StrategyStatsV2::default();
            passthrough.record(&FailSignal::Success, Some(20), 2048);
            passthrough.record(&FailSignal::Success, Some(18), 2048);
            snap.strategy_stats
                .insert(format!("{syn_ack_hash}|passthrough"), passthrough);

            let mut multisplit = aegis_core::StrategyStatsV2::default();
            multisplit.record(&FailSignal::Success, Some(20), 2048);
            multisplit.record(&FailSignal::Success, Some(18), 2048);
            snap.strategy_stats
                .insert(format!("{first_data_hash}|multisplit"), multisplit);
        })
        .await;

    let brain = Brain::new(0.0, vec!["passthrough".into(), "multisplit".into()], store);
    let new_key = StrategyKey::for_target(
        "203.0.113.77:443".parse().unwrap(),
        "fresh.example",
        443,
        Some("fresh.example"),
        true,
    );

    let order = brain.select_order(&new_key).await;
    assert_eq!(order[0], "multisplit");
}

#[tokio::test]
async fn brain_rewards_remote_reset_after_real_progress_over_middlebox_reset() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let brain = Brain::new(
        0.0,
        vec!["passthrough".into(), "multisplit".into()],
        store.clone(),
    );
    let key = StrategyKey::for_target(
        "203.0.113.91:443".parse().unwrap(),
        "reset-shaping.example",
        443,
        Some("reset-shaping.example"),
        true,
    );

    let remote_progress = KeyObservation {
        first_response_bytes: 0,
        tls_server_hello_seen: false,
        ja3s_md5: None,
        relay_client_to_remote_bytes: 0,
        relay_remote_to_client_bytes: 0,
        relay_lifetime_ms: 0,
        configured_timeout_ms: 0,
        capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
        capture_backend: None,
        capture_filter_applied: false,
        capture_ring_layout: None,
        capture_io_path: None,
        capture_wait_cycles: 0,
        downstream_dup_ack_count: 0,
        downstream_retransmit_count: 0,
        downstream_fin_after_data: false,
        matched_packets: 1,
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_mss: None,
        syn_ack_window_scale: None,
        syn_ack_sack_permitted: None,
        syn_ack_timestamp_option: None,
        syn_ack_server_hint: None,
        first_data_ttl: Some(58),
        first_data_window: Some(65535),
        first_data_payload_len: None,
        first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
        first_data_server_hint: None,
        first_packet_ttl: Some(58),
        first_packet_ip_tos: None,
        first_packet_ip_id: None,
        first_packet_ip_df: None,
        first_packet_window: Some(65535),
        first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
        server_hint: None,
        rst_ttl: Some(58),
        rst_source: Some(RstSource::Remote),
    };
    brain
        .record_outcome(
            &key,
            "passthrough",
            FailSignal::RemoteReset,
            Some(40),
            2048,
            Some(remote_progress),
        )
        .await;

    let middlebox_reset = KeyObservation {
        first_response_bytes: 0,
        tls_server_hello_seen: false,
        ja3s_md5: None,
        relay_client_to_remote_bytes: 0,
        relay_remote_to_client_bytes: 0,
        relay_lifetime_ms: 0,
        configured_timeout_ms: 0,
        capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
        capture_backend: None,
        capture_filter_applied: false,
        capture_ring_layout: None,
        capture_io_path: None,
        capture_wait_cycles: 0,
        downstream_dup_ack_count: 0,
        downstream_retransmit_count: 0,
        downstream_fin_after_data: false,
        matched_packets: 1,
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_mss: None,
        syn_ack_window_scale: None,
        syn_ack_sack_permitted: None,
        syn_ack_timestamp_option: None,
        syn_ack_server_hint: None,
        first_data_ttl: Some(58),
        first_data_window: Some(65535),
        first_data_payload_len: None,
        first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
        first_data_server_hint: None,
        first_packet_ttl: Some(58),
        first_packet_ip_tos: None,
        first_packet_ip_id: None,
        first_packet_ip_df: None,
        first_packet_window: Some(65535),
        first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
        server_hint: None,
        rst_ttl: Some(10),
        rst_source: Some(RstSource::Middlebox),
    };
    brain
        .record_outcome(
            &key,
            "multisplit",
            FailSignal::DropSuspected,
            Some(40),
            2048,
            Some(middlebox_reset),
        )
        .await;

    let order = brain.select_order(&key).await;
    assert_eq!(order[0], "passthrough");
}

#[tokio::test]
async fn brain_prefers_timeout_after_data_over_middlebox_reset_after_data() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let brain = Brain::new(
        0.0,
        vec!["passthrough".into(), "multisplit".into()],
        store.clone(),
    );
    let key = StrategyKey::for_target(
        "203.0.113.92:443".parse().unwrap(),
        "collapse-shaping.example",
        443,
        Some("collapse-shaping.example"),
        true,
    );

    let timeout_after_data = KeyObservation {
        first_response_bytes: 0,
        tls_server_hello_seen: false,
        ja3s_md5: None,
        relay_client_to_remote_bytes: 0,
        relay_remote_to_client_bytes: 0,
        relay_lifetime_ms: 0,
        configured_timeout_ms: 0,
        capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
        capture_backend: None,
        capture_filter_applied: false,
        capture_ring_layout: None,
        capture_io_path: None,
        capture_wait_cycles: 0,
        downstream_dup_ack_count: 0,
        downstream_retransmit_count: 0,
        downstream_fin_after_data: false,
        matched_packets: 1,
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_mss: None,
        syn_ack_window_scale: None,
        syn_ack_sack_permitted: None,
        syn_ack_timestamp_option: None,
        syn_ack_server_hint: None,
        first_data_ttl: Some(58),
        first_data_window: Some(65535),
        first_data_payload_len: None,
        first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
        first_data_server_hint: None,
        first_packet_ttl: Some(58),
        first_packet_ip_tos: None,
        first_packet_ip_id: None,
        first_packet_ip_df: None,
        first_packet_window: Some(65535),
        first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
        server_hint: None,
        rst_ttl: None,
        rst_source: None,
    };
    brain
        .record_outcome(
            &key,
            "passthrough",
            FailSignal::ThroughputCollapse,
            Some(40),
            2048,
            Some(timeout_after_data),
        )
        .await;

    let middlebox_reset = KeyObservation {
        first_response_bytes: 0,
        tls_server_hello_seen: false,
        ja3s_md5: None,
        relay_client_to_remote_bytes: 0,
        relay_remote_to_client_bytes: 0,
        relay_lifetime_ms: 0,
        configured_timeout_ms: 0,
        capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
        capture_backend: None,
        capture_filter_applied: false,
        capture_ring_layout: None,
        capture_io_path: None,
        capture_wait_cycles: 0,
        downstream_dup_ack_count: 0,
        downstream_retransmit_count: 0,
        downstream_fin_after_data: false,
        matched_packets: 1,
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_mss: None,
        syn_ack_window_scale: None,
        syn_ack_sack_permitted: None,
        syn_ack_timestamp_option: None,
        syn_ack_server_hint: None,
        first_data_ttl: Some(58),
        first_data_window: Some(65535),
        first_data_payload_len: None,
        first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
        first_data_server_hint: None,
        first_packet_ttl: Some(58),
        first_packet_ip_tos: None,
        first_packet_ip_id: None,
        first_packet_ip_df: None,
        first_packet_window: Some(65535),
        first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
        server_hint: None,
        rst_ttl: Some(10),
        rst_source: Some(RstSource::Middlebox),
    };
    brain
        .record_outcome(
            &key,
            "multisplit",
            FailSignal::DropSuspected,
            Some(40),
            2048,
            Some(middlebox_reset),
        )
        .await;

    let order = brain.select_order(&key).await;
    assert_eq!(order[0], "passthrough");
}

#[tokio::test]
async fn brain_prefers_zero_window_collapse_over_plain_collapse() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let brain = Brain::new(
        0.0,
        vec!["passthrough".into(), "multisplit".into()],
        store.clone(),
    );
    let key = StrategyKey::for_target(
        "203.0.113.92:443".parse().unwrap(),
        "collapse-zero-window.example",
        443,
        Some("collapse-zero-window.example"),
        true,
    );

    let plain_collapse = KeyObservation {
        first_response_bytes: 0,
        tls_server_hello_seen: false,
        ja3s_md5: None,
        relay_client_to_remote_bytes: 0,
        relay_remote_to_client_bytes: 0,
        relay_lifetime_ms: 0,
        configured_timeout_ms: 0,
        capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
        capture_backend: None,
        capture_filter_applied: false,
        capture_ring_layout: None,
        capture_io_path: None,
        capture_wait_cycles: 0,
        downstream_dup_ack_count: 0,
        downstream_retransmit_count: 0,
        downstream_fin_after_data: false,
        matched_packets: 1,
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_mss: None,
        syn_ack_window_scale: None,
        syn_ack_sack_permitted: None,
        syn_ack_timestamp_option: None,
        syn_ack_server_hint: None,
        first_data_ttl: Some(58),
        first_data_window: Some(65535),
        first_data_payload_len: None,
        first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
        first_data_server_hint: None,
        first_packet_ttl: Some(58),
        first_packet_ip_tos: None,
        first_packet_ip_id: None,
        first_packet_ip_df: None,
        first_packet_window: Some(65535),
        first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
        server_hint: None,
        rst_ttl: None,
        rst_source: None,
    };
    brain
        .record_outcome(
            &key,
            "multisplit",
            FailSignal::ThroughputCollapse,
            Some(40),
            2048,
            Some(plain_collapse),
        )
        .await;

    let zero_window_collapse = KeyObservation {
        first_response_bytes: 0,
        tls_server_hello_seen: false,
        ja3s_md5: None,
        relay_client_to_remote_bytes: 0,
        relay_remote_to_client_bytes: 0,
        relay_lifetime_ms: 0,
        configured_timeout_ms: 0,
        capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
        capture_backend: None,
        capture_filter_applied: false,
        capture_ring_layout: None,
        capture_io_path: None,
        capture_wait_cycles: 0,
        downstream_dup_ack_count: 0,
        downstream_retransmit_count: 0,
        downstream_fin_after_data: false,
        matched_packets: 2,
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_mss: None,
        syn_ack_window_scale: None,
        syn_ack_sack_permitted: None,
        syn_ack_timestamp_option: None,
        syn_ack_server_hint: None,
        first_data_ttl: Some(58),
        first_data_window: Some(0),
        first_data_payload_len: None,
        first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
        first_data_server_hint: None,
        first_packet_ttl: Some(58),
        first_packet_ip_tos: None,
        first_packet_ip_id: None,
        first_packet_ip_df: None,
        first_packet_window: Some(65535),
        first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
        server_hint: None,
        rst_ttl: None,
        rst_source: None,
    };
    brain
        .record_outcome(
            &key,
            "passthrough",
            FailSignal::ThroughputCollapse,
            Some(40),
            2048,
            Some(zero_window_collapse),
        )
        .await;

    let order = brain.select_order(&key).await;
    assert_eq!(order[0], "passthrough");
}

#[tokio::test]
async fn brain_prefers_small_window_collapse_over_plain_collapse() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let brain = Brain::new(
        0.0,
        vec!["passthrough".into(), "multisplit".into()],
        store.clone(),
    );
    let key = StrategyKey::for_target(
        "203.0.113.93:443".parse().unwrap(),
        "collapse-small-window.example",
        443,
        Some("collapse-small-window.example"),
        true,
    );

    let plain_collapse = KeyObservation {
        first_response_bytes: 0,
        tls_server_hello_seen: false,
        ja3s_md5: None,
        relay_client_to_remote_bytes: 0,
        relay_remote_to_client_bytes: 0,
        relay_lifetime_ms: 0,
        configured_timeout_ms: 0,
        capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
        capture_backend: None,
        capture_filter_applied: false,
        capture_ring_layout: None,
        capture_io_path: None,
        capture_wait_cycles: 0,
        downstream_dup_ack_count: 0,
        downstream_retransmit_count: 0,
        downstream_fin_after_data: false,
        matched_packets: 1,
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_mss: None,
        syn_ack_window_scale: None,
        syn_ack_sack_permitted: None,
        syn_ack_timestamp_option: None,
        syn_ack_server_hint: None,
        first_data_ttl: Some(58),
        first_data_window: Some(65535),
        first_data_payload_len: None,
        first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
        first_data_server_hint: None,
        first_packet_ttl: Some(58),
        first_packet_ip_tos: None,
        first_packet_ip_id: None,
        first_packet_ip_df: None,
        first_packet_window: Some(65535),
        first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
        server_hint: None,
        rst_ttl: None,
        rst_source: None,
    };
    brain
        .record_outcome(
            &key,
            "multisplit",
            FailSignal::ThroughputCollapse,
            Some(40),
            2048,
            Some(plain_collapse),
        )
        .await;

    let small_window_collapse = KeyObservation {
        first_response_bytes: 0,
        tls_server_hello_seen: false,
        ja3s_md5: None,
        relay_client_to_remote_bytes: 0,
        relay_remote_to_client_bytes: 0,
        relay_lifetime_ms: 0,
        configured_timeout_ms: 0,
        capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
        capture_backend: None,
        capture_filter_applied: false,
        capture_ring_layout: None,
        capture_io_path: None,
        capture_wait_cycles: 0,
        downstream_dup_ack_count: 0,
        downstream_retransmit_count: 0,
        downstream_fin_after_data: false,
        matched_packets: 2,
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_mss: None,
        syn_ack_window_scale: None,
        syn_ack_sack_permitted: None,
        syn_ack_timestamp_option: None,
        syn_ack_server_hint: None,
        first_data_ttl: Some(58),
        first_data_window: Some(512),
        first_data_payload_len: None,
        first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
        first_data_server_hint: None,
        first_packet_ttl: Some(58),
        first_packet_ip_tos: None,
        first_packet_ip_id: None,
        first_packet_ip_df: None,
        first_packet_window: Some(65535),
        first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
        server_hint: None,
        rst_ttl: None,
        rst_source: None,
    };
    brain
        .record_outcome(
            &key,
            "passthrough",
            FailSignal::ThroughputCollapse,
            Some(40),
            2048,
            Some(small_window_collapse),
        )
        .await;

    let order = brain.select_order(&key).await;
    assert_eq!(order[0], "passthrough");
}

#[tokio::test]
async fn brain_prefers_dup_ack_collapse_over_plain_collapse() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let brain = Brain::new(
        0.0,
        vec!["passthrough".into(), "multisplit".into()],
        store.clone(),
    );
    let key = StrategyKey::for_target(
        "203.0.113.94:443".parse().unwrap(),
        "collapse-dup-ack.example",
        443,
        Some("collapse-dup-ack.example"),
        true,
    );

    let plain_collapse = KeyObservation {
        first_response_bytes: 0,
        tls_server_hello_seen: false,
        ja3s_md5: None,
        relay_client_to_remote_bytes: 0,
        relay_remote_to_client_bytes: 0,
        relay_lifetime_ms: 0,
        configured_timeout_ms: 0,
        capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
        capture_backend: None,
        capture_filter_applied: false,
        capture_ring_layout: None,
        capture_io_path: None,
        capture_wait_cycles: 0,
        downstream_dup_ack_count: 0,
        downstream_retransmit_count: 0,
        downstream_fin_after_data: false,
        matched_packets: 1,
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_mss: None,
        syn_ack_window_scale: None,
        syn_ack_sack_permitted: None,
        syn_ack_timestamp_option: None,
        syn_ack_server_hint: None,
        first_data_ttl: Some(58),
        first_data_window: Some(65535),
        first_data_payload_len: None,
        first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
        first_data_server_hint: None,
        first_packet_ttl: Some(58),
        first_packet_ip_tos: None,
        first_packet_ip_id: None,
        first_packet_ip_df: None,
        first_packet_window: Some(65535),
        first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
        server_hint: None,
        rst_ttl: None,
        rst_source: None,
    };
    brain
        .record_outcome(
            &key,
            "multisplit",
            FailSignal::ThroughputCollapse,
            Some(40),
            2048,
            Some(plain_collapse),
        )
        .await;

    let dup_ack_collapse = KeyObservation {
        first_response_bytes: 0,
        tls_server_hello_seen: false,
        ja3s_md5: None,
        relay_client_to_remote_bytes: 0,
        relay_remote_to_client_bytes: 0,
        relay_lifetime_ms: 0,
        configured_timeout_ms: 0,
        capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
        capture_backend: None,
        capture_filter_applied: false,
        capture_ring_layout: None,
        capture_io_path: None,
        capture_wait_cycles: 0,
        downstream_dup_ack_count: 2,
        downstream_retransmit_count: 0,
        downstream_fin_after_data: false,
        matched_packets: 3,
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_mss: None,
        syn_ack_window_scale: None,
        syn_ack_sack_permitted: None,
        syn_ack_timestamp_option: None,
        syn_ack_server_hint: None,
        first_data_ttl: Some(58),
        first_data_window: Some(65535),
        first_data_payload_len: None,
        first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
        first_data_server_hint: None,
        first_packet_ttl: Some(58),
        first_packet_ip_tos: None,
        first_packet_ip_id: None,
        first_packet_ip_df: None,
        first_packet_window: Some(65535),
        first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
        server_hint: None,
        rst_ttl: None,
        rst_source: None,
    };
    brain
        .record_outcome(
            &key,
            "passthrough",
            FailSignal::ThroughputCollapse,
            Some(40),
            2048,
            Some(dup_ack_collapse),
        )
        .await;

    let order = brain.select_order(&key).await;
    assert_eq!(order[0], "passthrough");
}

#[tokio::test]
async fn brain_prefers_retransmit_collapse_over_dup_ack_collapse() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let brain = Brain::new(
        0.0,
        vec!["passthrough".into(), "multisplit".into()],
        store.clone(),
    );
    let key = StrategyKey::for_target(
        "203.0.113.95:443".parse().unwrap(),
        "collapse-retransmit.example",
        443,
        Some("collapse-retransmit.example"),
        true,
    );

    let dup_ack_collapse = KeyObservation {
        first_response_bytes: 0,
        tls_server_hello_seen: false,
        ja3s_md5: None,
        relay_client_to_remote_bytes: 0,
        relay_remote_to_client_bytes: 0,
        relay_lifetime_ms: 0,
        configured_timeout_ms: 0,
        capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
        capture_backend: None,
        capture_filter_applied: false,
        capture_ring_layout: None,
        capture_io_path: None,
        capture_wait_cycles: 0,
        downstream_dup_ack_count: 2,
        downstream_retransmit_count: 0,
        downstream_fin_after_data: false,
        matched_packets: 3,
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_mss: None,
        syn_ack_window_scale: None,
        syn_ack_sack_permitted: None,
        syn_ack_timestamp_option: None,
        syn_ack_server_hint: None,
        first_data_ttl: Some(58),
        first_data_window: Some(65535),
        first_data_payload_len: None,
        first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
        first_data_server_hint: None,
        first_packet_ttl: Some(58),
        first_packet_ip_tos: None,
        first_packet_ip_id: None,
        first_packet_ip_df: None,
        first_packet_window: Some(65535),
        first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
        server_hint: None,
        rst_ttl: None,
        rst_source: None,
    };
    brain
        .record_outcome(
            &key,
            "multisplit",
            FailSignal::ThroughputCollapse,
            Some(40),
            2048,
            Some(dup_ack_collapse),
        )
        .await;

    let retransmit_collapse = KeyObservation {
        first_response_bytes: 0,
        tls_server_hello_seen: false,
        ja3s_md5: None,
        relay_client_to_remote_bytes: 0,
        relay_remote_to_client_bytes: 0,
        relay_lifetime_ms: 0,
        configured_timeout_ms: 0,
        capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
        capture_backend: None,
        capture_filter_applied: false,
        capture_ring_layout: None,
        capture_io_path: None,
        capture_wait_cycles: 0,
        downstream_dup_ack_count: 0,
        downstream_retransmit_count: 1,
        downstream_fin_after_data: false,
        matched_packets: 2,
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_mss: None,
        syn_ack_window_scale: None,
        syn_ack_sack_permitted: None,
        syn_ack_timestamp_option: None,
        syn_ack_server_hint: None,
        first_data_ttl: Some(58),
        first_data_window: Some(65535),
        first_data_payload_len: None,
        first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
        first_data_server_hint: None,
        first_packet_ttl: Some(58),
        first_packet_ip_tos: None,
        first_packet_ip_id: None,
        first_packet_ip_df: None,
        first_packet_window: Some(65535),
        first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
        server_hint: None,
        rst_ttl: None,
        rst_source: None,
    };
    brain
        .record_outcome(
            &key,
            "passthrough",
            FailSignal::ThroughputCollapse,
            Some(40),
            2048,
            Some(retransmit_collapse),
        )
        .await;

    let order = brain.select_order(&key).await;
    assert_eq!(order[0], "passthrough");
}

#[tokio::test]
async fn brain_prefers_fin_collapse_over_retransmit_collapse() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let brain = Brain::new(
        0.0,
        vec!["passthrough".into(), "multisplit".into()],
        store.clone(),
    );
    let key = StrategyKey::for_target(
        "203.0.113.96:443".parse().unwrap(),
        "collapse-fin.example",
        443,
        Some("collapse-fin.example"),
        true,
    );

    let retransmit_collapse = KeyObservation {
        first_response_bytes: 0,
        tls_server_hello_seen: false,
        ja3s_md5: None,
        relay_client_to_remote_bytes: 0,
        relay_remote_to_client_bytes: 0,
        relay_lifetime_ms: 0,
        configured_timeout_ms: 0,
        capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
        capture_backend: None,
        capture_filter_applied: false,
        capture_ring_layout: None,
        capture_io_path: None,
        capture_wait_cycles: 0,
        downstream_dup_ack_count: 0,
        downstream_retransmit_count: 1,
        downstream_fin_after_data: false,
        matched_packets: 2,
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_mss: None,
        syn_ack_window_scale: None,
        syn_ack_sack_permitted: None,
        syn_ack_timestamp_option: None,
        syn_ack_server_hint: None,
        first_data_ttl: Some(58),
        first_data_window: Some(65535),
        first_data_payload_len: None,
        first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
        first_data_server_hint: None,
        first_packet_ttl: Some(58),
        first_packet_ip_tos: None,
        first_packet_ip_id: None,
        first_packet_ip_df: None,
        first_packet_window: Some(65535),
        first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
        server_hint: None,
        rst_ttl: None,
        rst_source: None,
    };
    brain
        .record_outcome(
            &key,
            "multisplit",
            FailSignal::ThroughputCollapse,
            Some(40),
            2048,
            Some(retransmit_collapse),
        )
        .await;

    let fin_collapse = KeyObservation {
        first_response_bytes: 0,
        tls_server_hello_seen: false,
        ja3s_md5: None,
        relay_client_to_remote_bytes: 0,
        relay_remote_to_client_bytes: 0,
        relay_lifetime_ms: 0,
        configured_timeout_ms: 0,
        capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
        capture_backend: None,
        capture_filter_applied: false,
        capture_ring_layout: None,
        capture_io_path: None,
        capture_wait_cycles: 0,
        downstream_dup_ack_count: 0,
        downstream_retransmit_count: 0,
        downstream_fin_after_data: true,
        matched_packets: 2,
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_mss: None,
        syn_ack_window_scale: None,
        syn_ack_sack_permitted: None,
        syn_ack_timestamp_option: None,
        syn_ack_server_hint: None,
        first_data_ttl: Some(58),
        first_data_window: Some(65535),
        first_data_payload_len: None,
        first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
        first_data_server_hint: None,
        first_packet_ttl: Some(58),
        first_packet_ip_tos: None,
        first_packet_ip_id: None,
        first_packet_ip_df: None,
        first_packet_window: Some(65535),
        first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
        server_hint: None,
        rst_ttl: None,
        rst_source: None,
    };
    brain
        .record_outcome(
            &key,
            "passthrough",
            FailSignal::ThroughputCollapse,
            Some(40),
            2048,
            Some(fin_collapse),
        )
        .await;

    let order = brain.select_order(&key).await;
    assert_eq!(order[0], "passthrough");
}

#[tokio::test]
async fn brain_prefers_remote_reset_after_data_over_remote_reset_after_server_hello() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let brain = Brain::new(
        0.0,
        vec!["passthrough".into(), "multisplit".into()],
        store.clone(),
    );
    let key = StrategyKey::for_target(
        "203.0.113.93:443".parse().unwrap(),
        "remote-reset-depth.example",
        443,
        Some("remote-reset-depth.example"),
        true,
    );

    let after_server_hello = KeyObservation {
        first_response_bytes: 120,
        tls_server_hello_seen: true,
        ja3s_md5: Some("0123456789abcdef0123456789abcdef".into()),
        relay_client_to_remote_bytes: 0,
        relay_remote_to_client_bytes: 0,
        relay_lifetime_ms: 0,
        configured_timeout_ms: 0,
        capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
        capture_backend: None,
        capture_filter_applied: false,
        capture_ring_layout: None,
        capture_io_path: None,
        capture_wait_cycles: 0,
        downstream_dup_ack_count: 0,
        downstream_retransmit_count: 0,
        downstream_fin_after_data: false,
        matched_packets: 1,
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_mss: None,
        syn_ack_window_scale: None,
        syn_ack_sack_permitted: None,
        syn_ack_timestamp_option: None,
        syn_ack_server_hint: None,
        first_data_ttl: None,
        first_data_window: None,
        first_data_payload_len: None,
        first_data_flags: None,
        first_data_server_hint: None,
        first_packet_ttl: Some(58),
        first_packet_ip_tos: None,
        first_packet_ip_id: None,
        first_packet_ip_df: None,
        first_packet_window: Some(65535),
        first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
        server_hint: None,
        rst_ttl: Some(58),
        rst_source: Some(RstSource::Remote),
    };
    brain
        .record_outcome(
            &key,
            "multisplit",
            FailSignal::RemoteReset,
            Some(40),
            2048,
            Some(after_server_hello),
        )
        .await;
    brain
        .record_outcome(
            &key,
            "multisplit",
            FailSignal::RemoteReset,
            Some(42),
            2048,
            Some(KeyObservation {
                first_response_bytes: 120,
                tls_server_hello_seen: true,
                ja3s_md5: Some("0123456789abcdef0123456789abcdef".into()),
                relay_client_to_remote_bytes: 0,
                relay_remote_to_client_bytes: 0,
                relay_lifetime_ms: 0,
                configured_timeout_ms: 0,
                capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
                capture_backend: None,
                capture_filter_applied: false,
                capture_ring_layout: None,
                capture_io_path: None,
                capture_wait_cycles: 0,
                downstream_dup_ack_count: 0,
                downstream_retransmit_count: 0,
                downstream_fin_after_data: false,
                matched_packets: 1,
                syn_ack_ttl: Some(58),
                syn_ack_window: Some(65535),
                syn_ack_mss: None,
                syn_ack_window_scale: None,
                syn_ack_sack_permitted: None,
                syn_ack_timestamp_option: None,
                syn_ack_server_hint: None,
                first_data_ttl: None,
                first_data_window: None,
                first_data_payload_len: None,
                first_data_flags: None,
                first_data_server_hint: None,
                first_packet_ttl: Some(58),
                first_packet_ip_tos: None,
                first_packet_ip_id: None,
                first_packet_ip_df: None,
                first_packet_window: Some(65535),
                first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
                server_hint: None,
                rst_ttl: Some(58),
                rst_source: Some(RstSource::Remote),
            }),
        )
        .await;

    let after_data = KeyObservation {
        first_response_bytes: 0,
        tls_server_hello_seen: false,
        ja3s_md5: None,
        relay_client_to_remote_bytes: 0,
        relay_remote_to_client_bytes: 0,
        relay_lifetime_ms: 0,
        configured_timeout_ms: 0,
        capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
        capture_backend: None,
        capture_filter_applied: false,
        capture_ring_layout: None,
        capture_io_path: None,
        capture_wait_cycles: 0,
        downstream_dup_ack_count: 0,
        downstream_retransmit_count: 0,
        downstream_fin_after_data: false,
        matched_packets: 1,
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_mss: None,
        syn_ack_window_scale: None,
        syn_ack_sack_permitted: None,
        syn_ack_timestamp_option: None,
        syn_ack_server_hint: None,
        first_data_ttl: Some(58),
        first_data_window: Some(65535),
        first_data_payload_len: None,
        first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
        first_data_server_hint: None,
        first_packet_ttl: Some(58),
        first_packet_ip_tos: None,
        first_packet_ip_id: None,
        first_packet_ip_df: None,
        first_packet_window: Some(65535),
        first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
        server_hint: None,
        rst_ttl: Some(58),
        rst_source: Some(RstSource::Remote),
    };
    brain
        .record_outcome(
            &key,
            "passthrough",
            FailSignal::RemoteReset,
            Some(40),
            2048,
            Some(after_data),
        )
        .await;
    brain
        .record_outcome(
            &key,
            "passthrough",
            FailSignal::RemoteReset,
            Some(38),
            2048,
            Some(KeyObservation {
                first_response_bytes: 0,
                tls_server_hello_seen: false,
                ja3s_md5: None,
                relay_client_to_remote_bytes: 0,
                relay_remote_to_client_bytes: 0,
                relay_lifetime_ms: 0,
                configured_timeout_ms: 0,
                capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
                capture_backend: None,
                capture_filter_applied: false,
                capture_ring_layout: None,
                capture_io_path: None,
                capture_wait_cycles: 0,
                downstream_dup_ack_count: 0,
                downstream_retransmit_count: 0,
                downstream_fin_after_data: false,
                matched_packets: 1,
                syn_ack_ttl: Some(58),
                syn_ack_window: Some(65535),
                syn_ack_mss: None,
                syn_ack_window_scale: None,
                syn_ack_sack_permitted: None,
                syn_ack_timestamp_option: None,
                syn_ack_server_hint: None,
                first_data_ttl: Some(58),
                first_data_window: Some(65535),
                first_data_payload_len: None,
                first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
                first_data_server_hint: None,
                first_packet_ttl: Some(58),
                first_packet_ip_tos: None,
                first_packet_ip_id: None,
                first_packet_ip_df: None,
                first_packet_window: Some(65535),
                first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
                server_hint: None,
                rst_ttl: Some(58),
                rst_source: Some(RstSource::Remote),
            }),
        )
        .await;

    let snap = store.snapshot().await;
    let passthrough_fitness = snap
        .strategy_stats
        .iter()
        .filter(|(entry, _)| entry.ends_with("|passthrough"))
        .map(|(_, stats)| stats.fitness_score)
        .reduce(f64::max)
        .expect("passthrough stats stored");
    let multisplit_fitness = snap
        .strategy_stats
        .iter()
        .filter(|(entry, _)| entry.ends_with("|multisplit"))
        .map(|(_, stats)| stats.fitness_score)
        .reduce(f64::max)
        .expect("multisplit stats stored");
    assert!(passthrough_fitness > multisplit_fitness);
}

#[tokio::test]
async fn brain_prefers_remote_reset_after_server_hello_over_remote_reset_after_syn_ack() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let brain = Brain::new(
        0.0,
        vec!["passthrough".into(), "multisplit".into()],
        store.clone(),
    );
    let key = StrategyKey::for_target(
        "203.0.113.94:443".parse().unwrap(),
        "remote-reset-synack.example",
        443,
        Some("remote-reset-synack.example"),
        true,
    );

    let after_syn_ack = KeyObservation {
        first_response_bytes: 0,
        tls_server_hello_seen: false,
        ja3s_md5: None,
        relay_client_to_remote_bytes: 0,
        relay_remote_to_client_bytes: 0,
        relay_lifetime_ms: 0,
        configured_timeout_ms: 0,
        capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
        capture_backend: None,
        capture_filter_applied: false,
        capture_ring_layout: None,
        capture_io_path: None,
        capture_wait_cycles: 0,
        downstream_dup_ack_count: 0,
        downstream_retransmit_count: 0,
        downstream_fin_after_data: false,
        matched_packets: 1,
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_mss: None,
        syn_ack_window_scale: None,
        syn_ack_sack_permitted: None,
        syn_ack_timestamp_option: None,
        syn_ack_server_hint: None,
        first_data_ttl: None,
        first_data_window: None,
        first_data_payload_len: None,
        first_data_flags: None,
        first_data_server_hint: None,
        first_packet_ttl: Some(58),
        first_packet_ip_tos: None,
        first_packet_ip_id: None,
        first_packet_ip_df: None,
        first_packet_window: Some(65535),
        first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
        server_hint: None,
        rst_ttl: Some(58),
        rst_source: Some(RstSource::Remote),
    };
    brain
        .record_outcome(
            &key,
            "multisplit",
            FailSignal::RemoteReset,
            Some(32),
            1024,
            Some(after_syn_ack),
        )
        .await;
    brain
        .record_outcome(
            &key,
            "multisplit",
            FailSignal::RemoteReset,
            Some(35),
            1024,
            Some(KeyObservation {
                first_response_bytes: 0,
                tls_server_hello_seen: false,
                ja3s_md5: None,
                relay_client_to_remote_bytes: 0,
                relay_remote_to_client_bytes: 0,
                relay_lifetime_ms: 0,
                configured_timeout_ms: 0,
                capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
                capture_backend: None,
                capture_filter_applied: false,
                capture_ring_layout: None,
                capture_io_path: None,
                capture_wait_cycles: 0,
                downstream_dup_ack_count: 0,
                downstream_retransmit_count: 0,
                downstream_fin_after_data: false,
                matched_packets: 1,
                syn_ack_ttl: Some(58),
                syn_ack_window: Some(65535),
                syn_ack_mss: None,
                syn_ack_window_scale: None,
                syn_ack_sack_permitted: None,
                syn_ack_timestamp_option: None,
                syn_ack_server_hint: None,
                first_data_ttl: None,
                first_data_window: None,
                first_data_payload_len: None,
                first_data_flags: None,
                first_data_server_hint: None,
                first_packet_ttl: Some(58),
                first_packet_ip_tos: None,
                first_packet_ip_id: None,
                first_packet_ip_df: None,
                first_packet_window: Some(65535),
                first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
                server_hint: None,
                rst_ttl: Some(58),
                rst_source: Some(RstSource::Remote),
            }),
        )
        .await;

    let after_server_hello = KeyObservation {
        first_response_bytes: 120,
        tls_server_hello_seen: true,
        ja3s_md5: Some("fedcba9876543210fedcba9876543210".into()),
        relay_client_to_remote_bytes: 0,
        relay_remote_to_client_bytes: 0,
        relay_lifetime_ms: 0,
        configured_timeout_ms: 0,
        capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
        capture_backend: None,
        capture_filter_applied: false,
        capture_ring_layout: None,
        capture_io_path: None,
        capture_wait_cycles: 0,
        downstream_dup_ack_count: 0,
        downstream_retransmit_count: 0,
        downstream_fin_after_data: false,
        matched_packets: 1,
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_mss: None,
        syn_ack_window_scale: None,
        syn_ack_sack_permitted: None,
        syn_ack_timestamp_option: None,
        syn_ack_server_hint: None,
        first_data_ttl: None,
        first_data_window: None,
        first_data_payload_len: None,
        first_data_flags: None,
        first_data_server_hint: None,
        first_packet_ttl: Some(58),
        first_packet_ip_tos: None,
        first_packet_ip_id: None,
        first_packet_ip_df: None,
        first_packet_window: Some(65535),
        first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
        server_hint: None,
        rst_ttl: Some(58),
        rst_source: Some(RstSource::Remote),
    };
    brain
        .record_outcome(
            &key,
            "passthrough",
            FailSignal::RemoteReset,
            Some(40),
            1024,
            Some(after_server_hello),
        )
        .await;
    brain
        .record_outcome(
            &key,
            "passthrough",
            FailSignal::RemoteReset,
            Some(42),
            1024,
            Some(KeyObservation {
                first_response_bytes: 120,
                tls_server_hello_seen: true,
                ja3s_md5: Some("fedcba9876543210fedcba9876543210".into()),
                relay_client_to_remote_bytes: 0,
                relay_remote_to_client_bytes: 0,
                relay_lifetime_ms: 0,
                configured_timeout_ms: 0,
                capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
                capture_backend: None,
                capture_filter_applied: false,
                capture_ring_layout: None,
                capture_io_path: None,
                capture_wait_cycles: 0,
                downstream_dup_ack_count: 0,
                downstream_retransmit_count: 0,
                downstream_fin_after_data: false,
                matched_packets: 1,
                syn_ack_ttl: Some(58),
                syn_ack_window: Some(65535),
                syn_ack_mss: None,
                syn_ack_window_scale: None,
                syn_ack_sack_permitted: None,
                syn_ack_timestamp_option: None,
                syn_ack_server_hint: None,
                first_data_ttl: None,
                first_data_window: None,
                first_data_payload_len: None,
                first_data_flags: None,
                first_data_server_hint: None,
                first_packet_ttl: Some(58),
                first_packet_ip_tos: None,
                first_packet_ip_id: None,
                first_packet_ip_df: None,
                first_packet_window: Some(65535),
                first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
                server_hint: None,
                rst_ttl: Some(58),
                rst_source: Some(RstSource::Remote),
            }),
        )
        .await;

    let snap = store.snapshot().await;
    let passthrough_fitness = snap
        .strategy_stats
        .iter()
        .filter(|(entry, _)| entry.ends_with("|passthrough"))
        .map(|(_, stats)| stats.fitness_score)
        .reduce(f64::max)
        .expect("passthrough stats stored");
    let multisplit_fitness = snap
        .strategy_stats
        .iter()
        .filter(|(entry, _)| entry.ends_with("|multisplit"))
        .map(|(_, stats)| stats.fitness_score)
        .reduce(f64::max)
        .expect("multisplit stats stored");
    assert!(passthrough_fitness > multisplit_fitness);
}

#[tokio::test]
async fn brain_prefers_remote_reset_after_bidirectional_relay_over_first_data_only() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let brain = Brain::new(
        0.0,
        vec!["passthrough".into(), "multisplit".into()],
        store.clone(),
    );
    let key = StrategyKey::for_target(
        "203.0.113.95:443".parse().unwrap(),
        "remote-reset-relay.example",
        443,
        Some("remote-reset-relay.example"),
        true,
    );

    let first_data_only = KeyObservation {
        first_response_bytes: 0,
        tls_server_hello_seen: false,
        ja3s_md5: None,
        relay_client_to_remote_bytes: 0,
        relay_remote_to_client_bytes: 0,
        relay_lifetime_ms: 0,
        configured_timeout_ms: 0,
        capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
        capture_backend: None,
        capture_filter_applied: false,
        capture_ring_layout: None,
        capture_io_path: None,
        capture_wait_cycles: 0,
        downstream_dup_ack_count: 0,
        downstream_retransmit_count: 0,
        downstream_fin_after_data: false,
        matched_packets: 1,
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_mss: None,
        syn_ack_window_scale: None,
        syn_ack_sack_permitted: None,
        syn_ack_timestamp_option: None,
        syn_ack_server_hint: None,
        first_data_ttl: Some(58),
        first_data_window: Some(65535),
        first_data_payload_len: None,
        first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
        first_data_server_hint: None,
        first_packet_ttl: Some(58),
        first_packet_ip_tos: None,
        first_packet_ip_id: None,
        first_packet_ip_df: None,
        first_packet_window: Some(65535),
        first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
        server_hint: None,
        rst_ttl: Some(58),
        rst_source: Some(RstSource::Remote),
    };
    brain
        .record_outcome(
            &key,
            "multisplit",
            FailSignal::RemoteReset,
            Some(50),
            2048,
            Some(first_data_only),
        )
        .await;
    brain
        .record_outcome(
            &key,
            "multisplit",
            FailSignal::RemoteReset,
            Some(52),
            2048,
            Some(KeyObservation {
                first_response_bytes: 0,
                tls_server_hello_seen: false,
                ja3s_md5: None,
                relay_client_to_remote_bytes: 0,
                relay_remote_to_client_bytes: 0,
                relay_lifetime_ms: 0,
                configured_timeout_ms: 0,
                capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
                capture_backend: None,
                capture_filter_applied: false,
                capture_ring_layout: None,
                capture_io_path: None,
                capture_wait_cycles: 0,
                downstream_dup_ack_count: 0,
                downstream_retransmit_count: 0,
                downstream_fin_after_data: false,
                matched_packets: 1,
                syn_ack_ttl: Some(58),
                syn_ack_window: Some(65535),
                syn_ack_mss: None,
                syn_ack_window_scale: None,
                syn_ack_sack_permitted: None,
                syn_ack_timestamp_option: None,
                syn_ack_server_hint: None,
                first_data_ttl: Some(58),
                first_data_window: Some(65535),
                first_data_payload_len: None,
                first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
                first_data_server_hint: None,
                first_packet_ttl: Some(58),
                first_packet_ip_tos: None,
                first_packet_ip_id: None,
                first_packet_ip_df: None,
                first_packet_window: Some(65535),
                first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
                server_hint: None,
                rst_ttl: Some(58),
                rst_source: Some(RstSource::Remote),
            }),
        )
        .await;

    let after_bidirectional_relay = KeyObservation {
        first_response_bytes: 128,
        tls_server_hello_seen: true,
        ja3s_md5: Some("00112233445566778899aabbccddeeff".into()),
        relay_client_to_remote_bytes: 2048,
        relay_remote_to_client_bytes: 1024,
        relay_lifetime_ms: 0,
        configured_timeout_ms: 0,
        capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
        capture_backend: None,
        capture_filter_applied: false,
        capture_ring_layout: None,
        capture_io_path: None,
        capture_wait_cycles: 0,
        downstream_dup_ack_count: 0,
        downstream_retransmit_count: 0,
        downstream_fin_after_data: false,
        matched_packets: 1,
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_mss: None,
        syn_ack_window_scale: None,
        syn_ack_sack_permitted: None,
        syn_ack_timestamp_option: None,
        syn_ack_server_hint: None,
        first_data_ttl: Some(58),
        first_data_window: Some(65535),
        first_data_payload_len: None,
        first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
        first_data_server_hint: None,
        first_packet_ttl: Some(58),
        first_packet_ip_tos: None,
        first_packet_ip_id: None,
        first_packet_ip_df: None,
        first_packet_window: Some(65535),
        first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
        server_hint: None,
        rst_ttl: Some(58),
        rst_source: Some(RstSource::Remote),
    };
    brain
        .record_outcome(
            &key,
            "passthrough",
            FailSignal::RemoteReset,
            Some(65),
            4096,
            Some(after_bidirectional_relay),
        )
        .await;
    brain
        .record_outcome(
            &key,
            "passthrough",
            FailSignal::RemoteReset,
            Some(67),
            4096,
            Some(KeyObservation {
                first_response_bytes: 128,
                tls_server_hello_seen: true,
                ja3s_md5: Some("00112233445566778899aabbccddeeff".into()),
                relay_client_to_remote_bytes: 1536,
                relay_remote_to_client_bytes: 768,
                relay_lifetime_ms: 0,
                configured_timeout_ms: 0,
                capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
                capture_backend: None,
                capture_filter_applied: false,
                capture_ring_layout: None,
                capture_io_path: None,
                capture_wait_cycles: 0,
                downstream_dup_ack_count: 0,
                downstream_retransmit_count: 0,
                downstream_fin_after_data: false,
                matched_packets: 1,
                syn_ack_ttl: Some(58),
                syn_ack_window: Some(65535),
                syn_ack_mss: None,
                syn_ack_window_scale: None,
                syn_ack_sack_permitted: None,
                syn_ack_timestamp_option: None,
                syn_ack_server_hint: None,
                first_data_ttl: Some(58),
                first_data_window: Some(65535),
                first_data_payload_len: None,
                first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
                first_data_server_hint: None,
                first_packet_ttl: Some(58),
                first_packet_ip_tos: None,
                first_packet_ip_id: None,
                first_packet_ip_df: None,
                first_packet_window: Some(65535),
                first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
                server_hint: None,
                rst_ttl: Some(58),
                rst_source: Some(RstSource::Remote),
            }),
        )
        .await;

    let snap = store.snapshot().await;
    let passthrough_fitness = snap
        .strategy_stats
        .iter()
        .filter(|(entry, _)| entry.ends_with("|passthrough"))
        .map(|(_, stats)| stats.fitness_score)
        .reduce(f64::max)
        .expect("passthrough stats stored");
    let multisplit_fitness = snap
        .strategy_stats
        .iter()
        .filter(|(entry, _)| entry.ends_with("|multisplit"))
        .map(|(_, stats)| stats.fitness_score)
        .reduce(f64::max)
        .expect("multisplit stats stored");
    assert!(passthrough_fitness > multisplit_fitness);
}

#[tokio::test]
async fn brain_prefers_remote_reset_after_bidirectional_relay_over_uplink_only_relay() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let brain = Brain::new(
        0.0,
        vec!["passthrough".into(), "multisplit".into()],
        store.clone(),
    );
    let key = StrategyKey::for_target(
        "203.0.113.96:443".parse().unwrap(),
        "remote-reset-uplink.example",
        443,
        Some("remote-reset-uplink.example"),
        true,
    );

    let after_uplink_only = KeyObservation {
        first_response_bytes: 128,
        tls_server_hello_seen: true,
        ja3s_md5: Some("11223344556677889900aabbccddeeff".into()),
        relay_client_to_remote_bytes: 2048,
        relay_remote_to_client_bytes: 0,
        relay_lifetime_ms: 0,
        configured_timeout_ms: 0,
        capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
        capture_backend: None,
        capture_filter_applied: false,
        capture_ring_layout: None,
        capture_io_path: None,
        capture_wait_cycles: 0,
        downstream_dup_ack_count: 0,
        downstream_retransmit_count: 0,
        downstream_fin_after_data: false,
        matched_packets: 1,
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_mss: None,
        syn_ack_window_scale: None,
        syn_ack_sack_permitted: None,
        syn_ack_timestamp_option: None,
        syn_ack_server_hint: None,
        first_data_ttl: Some(58),
        first_data_window: Some(65535),
        first_data_payload_len: None,
        first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
        first_data_server_hint: None,
        first_packet_ttl: Some(58),
        first_packet_ip_tos: None,
        first_packet_ip_id: None,
        first_packet_ip_df: None,
        first_packet_window: Some(65535),
        first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
        server_hint: None,
        rst_ttl: Some(58),
        rst_source: Some(RstSource::Remote),
    };
    brain
        .record_outcome(
            &key,
            "multisplit",
            FailSignal::RemoteReset,
            Some(55),
            4096,
            Some(after_uplink_only),
        )
        .await;
    brain
        .record_outcome(
            &key,
            "multisplit",
            FailSignal::RemoteReset,
            Some(57),
            4096,
            Some(KeyObservation {
                first_response_bytes: 128,
                tls_server_hello_seen: true,
                ja3s_md5: Some("11223344556677889900aabbccddeeff".into()),
                relay_client_to_remote_bytes: 1536,
                relay_remote_to_client_bytes: 0,
                relay_lifetime_ms: 0,
                configured_timeout_ms: 0,
                capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
                capture_backend: None,
                capture_filter_applied: false,
                capture_ring_layout: None,
                capture_io_path: None,
                capture_wait_cycles: 0,
                downstream_dup_ack_count: 0,
                downstream_retransmit_count: 0,
                downstream_fin_after_data: false,
                matched_packets: 1,
                syn_ack_ttl: Some(58),
                syn_ack_window: Some(65535),
                syn_ack_mss: None,
                syn_ack_window_scale: None,
                syn_ack_sack_permitted: None,
                syn_ack_timestamp_option: None,
                syn_ack_server_hint: None,
                first_data_ttl: Some(58),
                first_data_window: Some(65535),
                first_data_payload_len: None,
                first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
                first_data_server_hint: None,
                first_packet_ttl: Some(58),
                first_packet_ip_tos: None,
                first_packet_ip_id: None,
                first_packet_ip_df: None,
                first_packet_window: Some(65535),
                first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
                server_hint: None,
                rst_ttl: Some(58),
                rst_source: Some(RstSource::Remote),
            }),
        )
        .await;

    let after_bidirectional = KeyObservation {
        first_response_bytes: 128,
        tls_server_hello_seen: true,
        ja3s_md5: Some("11223344556677889900aabbccddeeff".into()),
        relay_client_to_remote_bytes: 2048,
        relay_remote_to_client_bytes: 768,
        relay_lifetime_ms: 0,
        configured_timeout_ms: 0,
        capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
        capture_backend: None,
        capture_filter_applied: false,
        capture_ring_layout: None,
        capture_io_path: None,
        capture_wait_cycles: 0,
        downstream_dup_ack_count: 0,
        downstream_retransmit_count: 0,
        downstream_fin_after_data: false,
        matched_packets: 1,
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_mss: None,
        syn_ack_window_scale: None,
        syn_ack_sack_permitted: None,
        syn_ack_timestamp_option: None,
        syn_ack_server_hint: None,
        first_data_ttl: Some(58),
        first_data_window: Some(65535),
        first_data_payload_len: None,
        first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
        first_data_server_hint: None,
        first_packet_ttl: Some(58),
        first_packet_ip_tos: None,
        first_packet_ip_id: None,
        first_packet_ip_df: None,
        first_packet_window: Some(65535),
        first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
        server_hint: None,
        rst_ttl: Some(58),
        rst_source: Some(RstSource::Remote),
    };
    brain
        .record_outcome(
            &key,
            "passthrough",
            FailSignal::RemoteReset,
            Some(60),
            4096,
            Some(after_bidirectional),
        )
        .await;
    brain
        .record_outcome(
            &key,
            "passthrough",
            FailSignal::RemoteReset,
            Some(62),
            4096,
            Some(KeyObservation {
                first_response_bytes: 128,
                tls_server_hello_seen: true,
                ja3s_md5: Some("11223344556677889900aabbccddeeff".into()),
                relay_client_to_remote_bytes: 1536,
                relay_remote_to_client_bytes: 512,
                relay_lifetime_ms: 0,
                configured_timeout_ms: 0,
                capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
                capture_backend: None,
                capture_filter_applied: false,
                capture_ring_layout: None,
                capture_io_path: None,
                capture_wait_cycles: 0,
                downstream_dup_ack_count: 0,
                downstream_retransmit_count: 0,
                downstream_fin_after_data: false,
                matched_packets: 1,
                syn_ack_ttl: Some(58),
                syn_ack_window: Some(65535),
                syn_ack_mss: None,
                syn_ack_window_scale: None,
                syn_ack_sack_permitted: None,
                syn_ack_timestamp_option: None,
                syn_ack_server_hint: None,
                first_data_ttl: Some(58),
                first_data_window: Some(65535),
                first_data_payload_len: None,
                first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
                first_data_server_hint: None,
                first_packet_ttl: Some(58),
                first_packet_ip_tos: None,
                first_packet_ip_id: None,
                first_packet_ip_df: None,
                first_packet_window: Some(65535),
                first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
                server_hint: None,
                rst_ttl: Some(58),
                rst_source: Some(RstSource::Remote),
            }),
        )
        .await;

    let snap = store.snapshot().await;
    let passthrough_fitness = snap
        .strategy_stats
        .iter()
        .filter(|(entry, _)| entry.ends_with("|passthrough"))
        .map(|(_, stats)| stats.fitness_score)
        .reduce(f64::max)
        .expect("passthrough stats stored");
    let multisplit_fitness = snap
        .strategy_stats
        .iter()
        .filter(|(entry, _)| entry.ends_with("|multisplit"))
        .map(|(_, stats)| stats.fitness_score)
        .reduce(f64::max)
        .expect("multisplit stats stored");
    assert!(passthrough_fitness > multisplit_fitness);
}

#[tokio::test]
async fn brain_prefers_remote_reset_after_downstream_heavy_relay_over_short_bidirectional() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let brain = Brain::new(
        0.0,
        vec!["passthrough".into(), "multisplit".into()],
        store.clone(),
    );
    let key = StrategyKey::for_target(
        "203.0.113.97:443".parse().unwrap(),
        "remote-reset-downstream.example",
        443,
        Some("remote-reset-downstream.example"),
        true,
    );

    let short_bidirectional = KeyObservation {
        first_response_bytes: 128,
        tls_server_hello_seen: true,
        ja3s_md5: Some("22334455667788990011aabbccddeeff".into()),
        relay_client_to_remote_bytes: 4096,
        relay_remote_to_client_bytes: 512,
        relay_lifetime_ms: 0,
        configured_timeout_ms: 0,
        capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
        capture_backend: None,
        capture_filter_applied: false,
        capture_ring_layout: None,
        capture_io_path: None,
        capture_wait_cycles: 0,
        downstream_dup_ack_count: 0,
        downstream_retransmit_count: 0,
        downstream_fin_after_data: false,
        matched_packets: 1,
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_mss: None,
        syn_ack_window_scale: None,
        syn_ack_sack_permitted: None,
        syn_ack_timestamp_option: None,
        syn_ack_server_hint: None,
        first_data_ttl: Some(58),
        first_data_window: Some(65535),
        first_data_payload_len: None,
        first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
        first_data_server_hint: None,
        first_packet_ttl: Some(58),
        first_packet_ip_tos: None,
        first_packet_ip_id: None,
        first_packet_ip_df: None,
        first_packet_window: Some(65535),
        first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
        server_hint: None,
        rst_ttl: Some(58),
        rst_source: Some(RstSource::Remote),
    };
    brain
        .record_outcome(
            &key,
            "multisplit",
            FailSignal::RemoteReset,
            Some(68),
            4096,
            Some(short_bidirectional),
        )
        .await;
    brain
        .record_outcome(
            &key,
            "multisplit",
            FailSignal::RemoteReset,
            Some(70),
            4096,
            Some(KeyObservation {
                first_response_bytes: 128,
                tls_server_hello_seen: true,
                ja3s_md5: Some("22334455667788990011aabbccddeeff".into()),
                relay_client_to_remote_bytes: 3072,
                relay_remote_to_client_bytes: 384,
                relay_lifetime_ms: 0,
                configured_timeout_ms: 0,
                capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
                capture_backend: None,
                capture_filter_applied: false,
                capture_ring_layout: None,
                capture_io_path: None,
                capture_wait_cycles: 0,
                downstream_dup_ack_count: 0,
                downstream_retransmit_count: 0,
                downstream_fin_after_data: false,
                matched_packets: 1,
                syn_ack_ttl: Some(58),
                syn_ack_window: Some(65535),
                syn_ack_mss: None,
                syn_ack_window_scale: None,
                syn_ack_sack_permitted: None,
                syn_ack_timestamp_option: None,
                syn_ack_server_hint: None,
                first_data_ttl: Some(58),
                first_data_window: Some(65535),
                first_data_payload_len: None,
                first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
                first_data_server_hint: None,
                first_packet_ttl: Some(58),
                first_packet_ip_tos: None,
                first_packet_ip_id: None,
                first_packet_ip_df: None,
                first_packet_window: Some(65535),
                first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
                server_hint: None,
                rst_ttl: Some(58),
                rst_source: Some(RstSource::Remote),
            }),
        )
        .await;

    let downstream_heavy = KeyObservation {
        first_response_bytes: 128,
        tls_server_hello_seen: true,
        ja3s_md5: Some("22334455667788990011aabbccddeeff".into()),
        relay_client_to_remote_bytes: 2048,
        relay_remote_to_client_bytes: 2048,
        relay_lifetime_ms: 0,
        configured_timeout_ms: 0,
        capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
        capture_backend: None,
        capture_filter_applied: false,
        capture_ring_layout: None,
        capture_io_path: None,
        capture_wait_cycles: 0,
        downstream_dup_ack_count: 0,
        downstream_retransmit_count: 0,
        downstream_fin_after_data: false,
        matched_packets: 1,
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_mss: None,
        syn_ack_window_scale: None,
        syn_ack_sack_permitted: None,
        syn_ack_timestamp_option: None,
        syn_ack_server_hint: None,
        first_data_ttl: Some(58),
        first_data_window: Some(65535),
        first_data_payload_len: None,
        first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
        first_data_server_hint: None,
        first_packet_ttl: Some(58),
        first_packet_ip_tos: None,
        first_packet_ip_id: None,
        first_packet_ip_df: None,
        first_packet_window: Some(65535),
        first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
        server_hint: None,
        rst_ttl: Some(58),
        rst_source: Some(RstSource::Remote),
    };
    brain
        .record_outcome(
            &key,
            "passthrough",
            FailSignal::RemoteReset,
            Some(72),
            4096,
            Some(downstream_heavy),
        )
        .await;
    brain
        .record_outcome(
            &key,
            "passthrough",
            FailSignal::RemoteReset,
            Some(75),
            4096,
            Some(KeyObservation {
                first_response_bytes: 128,
                tls_server_hello_seen: true,
                ja3s_md5: Some("22334455667788990011aabbccddeeff".into()),
                relay_client_to_remote_bytes: 1536,
                relay_remote_to_client_bytes: 1536,
                relay_lifetime_ms: 0,
                configured_timeout_ms: 0,
                capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
                capture_backend: None,
                capture_filter_applied: false,
                capture_ring_layout: None,
                capture_io_path: None,
                capture_wait_cycles: 0,
                downstream_dup_ack_count: 0,
                downstream_retransmit_count: 0,
                downstream_fin_after_data: false,
                matched_packets: 1,
                syn_ack_ttl: Some(58),
                syn_ack_window: Some(65535),
                syn_ack_mss: None,
                syn_ack_window_scale: None,
                syn_ack_sack_permitted: None,
                syn_ack_timestamp_option: None,
                syn_ack_server_hint: None,
                first_data_ttl: Some(58),
                first_data_window: Some(65535),
                first_data_payload_len: None,
                first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
                first_data_server_hint: None,
                first_packet_ttl: Some(58),
                first_packet_ip_tos: None,
                first_packet_ip_id: None,
                first_packet_ip_df: None,
                first_packet_window: Some(65535),
                first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
                server_hint: None,
                rst_ttl: Some(58),
                rst_source: Some(RstSource::Remote),
            }),
        )
        .await;

    let snap = store.snapshot().await;
    let passthrough_fitness = snap
        .strategy_stats
        .iter()
        .filter(|(entry, _)| entry.ends_with("|passthrough"))
        .map(|(_, stats)| stats.fitness_score)
        .reduce(f64::max)
        .expect("passthrough stats stored");
    let multisplit_fitness = snap
        .strategy_stats
        .iter()
        .filter(|(entry, _)| entry.ends_with("|multisplit"))
        .map(|(_, stats)| stats.fitness_score)
        .reduce(f64::max)
        .expect("multisplit stats stored");
    assert!(passthrough_fitness > multisplit_fitness);
}

#[tokio::test]
async fn brain_prefers_longer_lived_downstream_heavy_relay_over_shorter_one() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let brain = Brain::new(
        0.0,
        vec!["passthrough".into(), "multisplit".into()],
        store.clone(),
    );
    let key = StrategyKey::for_target(
        "203.0.113.98:443".parse().unwrap(),
        "remote-reset-lifetime.example",
        443,
        Some("remote-reset-lifetime.example"),
        true,
    );

    let shorter = KeyObservation {
        first_response_bytes: 128,
        tls_server_hello_seen: true,
        ja3s_md5: Some("33445566778899001122aabbccddeeff".into()),
        relay_client_to_remote_bytes: 2048,
        relay_remote_to_client_bytes: 2048,
        relay_lifetime_ms: 500,
        configured_timeout_ms: 5000,
        capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
        capture_backend: None,
        capture_filter_applied: false,
        capture_ring_layout: None,
        capture_io_path: None,
        capture_wait_cycles: 0,
        downstream_dup_ack_count: 0,
        downstream_retransmit_count: 0,
        downstream_fin_after_data: false,
        matched_packets: 1,
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_mss: None,
        syn_ack_window_scale: None,
        syn_ack_sack_permitted: None,
        syn_ack_timestamp_option: None,
        syn_ack_server_hint: None,
        first_data_ttl: Some(58),
        first_data_window: Some(65535),
        first_data_payload_len: None,
        first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
        first_data_server_hint: None,
        first_packet_ttl: Some(58),
        first_packet_ip_tos: None,
        first_packet_ip_id: None,
        first_packet_ip_df: None,
        first_packet_window: Some(65535),
        first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
        server_hint: None,
        rst_ttl: Some(58),
        rst_source: Some(RstSource::Remote),
    };
    brain
        .record_outcome(
            &key,
            "multisplit",
            FailSignal::RemoteReset,
            Some(70),
            4096,
            Some(shorter),
        )
        .await;
    brain
        .record_outcome(
            &key,
            "multisplit",
            FailSignal::RemoteReset,
            Some(72),
            4096,
            Some(KeyObservation {
                first_response_bytes: 128,
                tls_server_hello_seen: true,
                ja3s_md5: Some("33445566778899001122aabbccddeeff".into()),
                relay_client_to_remote_bytes: 1536,
                relay_remote_to_client_bytes: 1536,
                relay_lifetime_ms: 700,
                configured_timeout_ms: 5000,
                capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
                capture_backend: None,
                capture_filter_applied: false,
                capture_ring_layout: None,
                capture_io_path: None,
                capture_wait_cycles: 0,
                downstream_dup_ack_count: 0,
                downstream_retransmit_count: 0,
                downstream_fin_after_data: false,
                matched_packets: 1,
                syn_ack_ttl: Some(58),
                syn_ack_window: Some(65535),
                syn_ack_mss: None,
                syn_ack_window_scale: None,
                syn_ack_sack_permitted: None,
                syn_ack_timestamp_option: None,
                syn_ack_server_hint: None,
                first_data_ttl: Some(58),
                first_data_window: Some(65535),
                first_data_payload_len: None,
                first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
                first_data_server_hint: None,
                first_packet_ttl: Some(58),
                first_packet_ip_tos: None,
                first_packet_ip_id: None,
                first_packet_ip_df: None,
                first_packet_window: Some(65535),
                first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
                server_hint: None,
                rst_ttl: Some(58),
                rst_source: Some(RstSource::Remote),
            }),
        )
        .await;

    let longer = KeyObservation {
        first_response_bytes: 128,
        tls_server_hello_seen: true,
        ja3s_md5: Some("33445566778899001122aabbccddeeff".into()),
        relay_client_to_remote_bytes: 2048,
        relay_remote_to_client_bytes: 2048,
        relay_lifetime_ms: 3500,
        configured_timeout_ms: 5000,
        capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
        capture_backend: None,
        capture_filter_applied: false,
        capture_ring_layout: None,
        capture_io_path: None,
        capture_wait_cycles: 0,
        downstream_dup_ack_count: 0,
        downstream_retransmit_count: 0,
        downstream_fin_after_data: false,
        matched_packets: 1,
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_mss: None,
        syn_ack_window_scale: None,
        syn_ack_sack_permitted: None,
        syn_ack_timestamp_option: None,
        syn_ack_server_hint: None,
        first_data_ttl: Some(58),
        first_data_window: Some(65535),
        first_data_payload_len: None,
        first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
        first_data_server_hint: None,
        first_packet_ttl: Some(58),
        first_packet_ip_tos: None,
        first_packet_ip_id: None,
        first_packet_ip_df: None,
        first_packet_window: Some(65535),
        first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
        server_hint: None,
        rst_ttl: Some(58),
        rst_source: Some(RstSource::Remote),
    };
    brain
        .record_outcome(
            &key,
            "passthrough",
            FailSignal::RemoteReset,
            Some(95),
            4096,
            Some(longer),
        )
        .await;
    brain
        .record_outcome(
            &key,
            "passthrough",
            FailSignal::RemoteReset,
            Some(98),
            4096,
            Some(KeyObservation {
                first_response_bytes: 128,
                tls_server_hello_seen: true,
                ja3s_md5: Some("33445566778899001122aabbccddeeff".into()),
                relay_client_to_remote_bytes: 1536,
                relay_remote_to_client_bytes: 1536,
                relay_lifetime_ms: 3000,
                configured_timeout_ms: 5000,
                capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
                capture_backend: None,
                capture_filter_applied: false,
                capture_ring_layout: None,
                capture_io_path: None,
                capture_wait_cycles: 0,
                downstream_dup_ack_count: 0,
                downstream_retransmit_count: 0,
                downstream_fin_after_data: false,
                matched_packets: 1,
                syn_ack_ttl: Some(58),
                syn_ack_window: Some(65535),
                syn_ack_mss: None,
                syn_ack_window_scale: None,
                syn_ack_sack_permitted: None,
                syn_ack_timestamp_option: None,
                syn_ack_server_hint: None,
                first_data_ttl: Some(58),
                first_data_window: Some(65535),
                first_data_payload_len: None,
                first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
                first_data_server_hint: None,
                first_packet_ttl: Some(58),
                first_packet_ip_tos: None,
                first_packet_ip_id: None,
                first_packet_ip_df: None,
                first_packet_window: Some(65535),
                first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
                server_hint: None,
                rst_ttl: Some(58),
                rst_source: Some(RstSource::Remote),
            }),
        )
        .await;

    let snap = store.snapshot().await;
    let passthrough_fitness = snap
        .strategy_stats
        .iter()
        .filter(|(entry, _)| entry.ends_with("|passthrough"))
        .map(|(_, stats)| stats.fitness_score)
        .reduce(f64::max)
        .expect("passthrough stats stored");
    let multisplit_fitness = snap
        .strategy_stats
        .iter()
        .filter(|(entry, _)| entry.ends_with("|multisplit"))
        .map(|(_, stats)| stats.fitness_score)
        .reduce(f64::max)
        .expect("multisplit stats stored");
    assert!(passthrough_fitness > multisplit_fitness);
}

#[tokio::test]
async fn brain_prefers_degraded_success_over_equivalent_late_remote_reset() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let brain = Brain::new(
        0.0,
        vec!["passthrough".into(), "multisplit".into()],
        store.clone(),
    );
    let key = StrategyKey::for_target(
        "203.0.113.99:443".parse().unwrap(),
        "degraded-vs-late-reset.example",
        443,
        Some("degraded-vs-late-reset.example"),
        true,
    );

    let shared_observation = KeyObservation {
        first_response_bytes: 128,
        tls_server_hello_seen: true,
        ja3s_md5: Some("44556677889900112233aabbccddeeff".into()),
        relay_client_to_remote_bytes: 1024,
        relay_remote_to_client_bytes: 4096,
        relay_lifetime_ms: 4500,
        configured_timeout_ms: 5000,
        capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
        capture_backend: None,
        capture_filter_applied: false,
        capture_ring_layout: None,
        capture_io_path: None,
        capture_wait_cycles: 0,
        downstream_dup_ack_count: 0,
        downstream_retransmit_count: 0,
        downstream_fin_after_data: false,
        matched_packets: 1,
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_mss: None,
        syn_ack_window_scale: None,
        syn_ack_sack_permitted: None,
        syn_ack_timestamp_option: None,
        syn_ack_server_hint: None,
        first_data_ttl: Some(58),
        first_data_window: Some(65535),
        first_data_payload_len: None,
        first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
        first_data_server_hint: None,
        first_packet_ttl: Some(58),
        first_packet_ip_tos: None,
        first_packet_ip_id: None,
        first_packet_ip_df: None,
        first_packet_window: Some(65535),
        first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
        server_hint: None,
        rst_ttl: Some(58),
        rst_source: Some(RstSource::Remote),
    };

    brain
        .record_outcome(
            &key,
            "multisplit",
            FailSignal::RemoteReset,
            Some(4700),
            4096,
            Some(shared_observation.clone()),
        )
        .await;
    brain
        .record_outcome(
            &key,
            "multisplit",
            FailSignal::RemoteReset,
            Some(4600),
            4096,
            Some(shared_observation.clone()),
        )
        .await;

    brain
        .record_outcome(
            &key,
            "passthrough",
            FailSignal::SuccessDegraded,
            Some(6000),
            4096,
            Some(shared_observation.clone()),
        )
        .await;
    brain
        .record_outcome(
            &key,
            "passthrough",
            FailSignal::SuccessDegraded,
            Some(6200),
            4096,
            Some(shared_observation),
        )
        .await;

    let snap = store.snapshot().await;
    let passthrough_fitness = snap
        .strategy_stats
        .iter()
        .filter(|(entry, _)| entry.ends_with("|passthrough"))
        .map(|(_, stats)| stats.fitness_score)
        .reduce(f64::max)
        .expect("passthrough stats stored");
    let multisplit_fitness = snap
        .strategy_stats
        .iter()
        .filter(|(entry, _)| entry.ends_with("|multisplit"))
        .map(|(_, stats)| stats.fitness_score)
        .reduce(f64::max)
        .expect("multisplit stats stored");
    assert!(passthrough_fitness > multisplit_fitness);
}

#[tokio::test]
async fn brain_prefers_late_throughput_collapse_over_early_first_data_collapse() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let brain = Brain::new(
        0.0,
        vec!["passthrough".into(), "multisplit".into()],
        store.clone(),
    );
    let key = StrategyKey::for_target(
        "203.0.113.101:443".parse().unwrap(),
        "late-collapse-vs-early-collapse.example",
        443,
        Some("late-collapse-vs-early-collapse.example"),
        true,
    );

    let early_observation = KeyObservation {
        first_response_bytes: 128,
        tls_server_hello_seen: true,
        ja3s_md5: Some("55667788990011223344aabbccddeeff".into()),
        relay_client_to_remote_bytes: 0,
        relay_remote_to_client_bytes: 0,
        relay_lifetime_ms: 0,
        configured_timeout_ms: 5000,
        capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
        capture_backend: None,
        capture_filter_applied: false,
        capture_ring_layout: None,
        capture_io_path: None,
        capture_wait_cycles: 0,
        downstream_dup_ack_count: 0,
        downstream_retransmit_count: 0,
        downstream_fin_after_data: false,
        matched_packets: 1,
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_mss: None,
        syn_ack_window_scale: None,
        syn_ack_sack_permitted: None,
        syn_ack_timestamp_option: None,
        syn_ack_server_hint: None,
        first_data_ttl: Some(58),
        first_data_window: Some(65535),
        first_data_payload_len: None,
        first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
        first_data_server_hint: None,
        first_packet_ttl: Some(58),
        first_packet_ip_tos: None,
        first_packet_ip_id: None,
        first_packet_ip_df: None,
        first_packet_window: Some(65535),
        first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
        server_hint: None,
        rst_ttl: None,
        rst_source: None,
    };
    let late_observation = KeyObservation {
        first_response_bytes: 128,
        tls_server_hello_seen: true,
        ja3s_md5: Some("66778899001122334455aabbccddeeff".into()),
        relay_client_to_remote_bytes: 1024,
        relay_remote_to_client_bytes: 4096,
        relay_lifetime_ms: 4500,
        configured_timeout_ms: 5000,
        capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
        capture_backend: None,
        capture_filter_applied: false,
        capture_ring_layout: None,
        capture_io_path: None,
        capture_wait_cycles: 0,
        downstream_dup_ack_count: 0,
        downstream_retransmit_count: 0,
        downstream_fin_after_data: false,
        matched_packets: 1,
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_mss: None,
        syn_ack_window_scale: None,
        syn_ack_sack_permitted: None,
        syn_ack_timestamp_option: None,
        syn_ack_server_hint: None,
        first_data_ttl: Some(58),
        first_data_window: Some(65535),
        first_data_payload_len: None,
        first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
        first_data_server_hint: None,
        first_packet_ttl: Some(58),
        first_packet_ip_tos: None,
        first_packet_ip_id: None,
        first_packet_ip_df: None,
        first_packet_window: Some(65535),
        first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
        server_hint: None,
        rst_ttl: None,
        rst_source: None,
    };

    brain
        .record_outcome(
            &key,
            "multisplit",
            FailSignal::ThroughputCollapse,
            Some(900),
            1024,
            Some(early_observation.clone()),
        )
        .await;
    brain
        .record_outcome(
            &key,
            "multisplit",
            FailSignal::ThroughputCollapse,
            Some(950),
            1024,
            Some(early_observation),
        )
        .await;

    brain
        .record_outcome(
            &key,
            "passthrough",
            FailSignal::ThroughputCollapse,
            Some(4700),
            4096,
            Some(late_observation.clone()),
        )
        .await;
    brain
        .record_outcome(
            &key,
            "passthrough",
            FailSignal::ThroughputCollapse,
            Some(4600),
            4096,
            Some(late_observation),
        )
        .await;

    let snap = store.snapshot().await;
    let passthrough_fitness = snap
        .strategy_stats
        .iter()
        .filter(|(entry, _)| entry.ends_with("|passthrough"))
        .map(|(_, stats)| stats.fitness_score)
        .reduce(f64::max)
        .expect("passthrough stats stored");
    let multisplit_fitness = snap
        .strategy_stats
        .iter()
        .filter(|(entry, _)| entry.ends_with("|multisplit"))
        .map(|(_, stats)| stats.fitness_score)
        .reduce(f64::max)
        .expect("multisplit stats stored");
    assert!(passthrough_fitness > multisplit_fitness);
}

#[tokio::test]
async fn brain_prefers_equivalent_late_remote_reset_over_late_throughput_collapse() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();
    let brain = Brain::new(
        0.0,
        vec!["passthrough".into(), "multisplit".into()],
        store.clone(),
    );
    let key = StrategyKey::for_target(
        "203.0.113.102:443".parse().unwrap(),
        "late-reset-vs-late-collapse.example",
        443,
        Some("late-reset-vs-late-collapse.example"),
        true,
    );

    let shared_observation = KeyObservation {
        first_response_bytes: 128,
        tls_server_hello_seen: true,
        ja3s_md5: Some("77889900112233445566aabbccddeeff".into()),
        relay_client_to_remote_bytes: 1024,
        relay_remote_to_client_bytes: 4096,
        relay_lifetime_ms: 4500,
        configured_timeout_ms: 5000,
        capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
        capture_backend: None,
        capture_filter_applied: false,
        capture_ring_layout: None,
        capture_io_path: None,
        capture_wait_cycles: 0,
        downstream_dup_ack_count: 0,
        downstream_retransmit_count: 0,
        downstream_fin_after_data: false,
        matched_packets: 1,
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_mss: None,
        syn_ack_window_scale: None,
        syn_ack_sack_permitted: None,
        syn_ack_timestamp_option: None,
        syn_ack_server_hint: None,
        first_data_ttl: Some(58),
        first_data_window: Some(65535),
        first_data_payload_len: None,
        first_data_flags: Some(aegis_core::TCP_FLAG_ACK | aegis_core::TCP_FLAG_PSH),
        first_data_server_hint: None,
        first_packet_ttl: Some(58),
        first_packet_ip_tos: None,
        first_packet_ip_id: None,
        first_packet_ip_df: None,
        first_packet_window: Some(65535),
        first_packet_flags: Some(aegis_core::TCP_FLAG_ACK),
        server_hint: None,
        rst_ttl: Some(58),
        rst_source: Some(RstSource::Remote),
    };

    brain
        .record_outcome(
            &key,
            "multisplit",
            FailSignal::ThroughputCollapse,
            Some(4700),
            4096,
            Some(shared_observation.clone()),
        )
        .await;
    brain
        .record_outcome(
            &key,
            "multisplit",
            FailSignal::ThroughputCollapse,
            Some(4600),
            4096,
            Some(shared_observation.clone()),
        )
        .await;

    brain
        .record_outcome(
            &key,
            "passthrough",
            FailSignal::RemoteReset,
            Some(4700),
            4096,
            Some(shared_observation.clone()),
        )
        .await;
    brain
        .record_outcome(
            &key,
            "passthrough",
            FailSignal::RemoteReset,
            Some(4600),
            4096,
            Some(shared_observation),
        )
        .await;

    let snap = store.snapshot().await;
    let passthrough_fitness = snap
        .strategy_stats
        .iter()
        .filter(|(entry, _)| entry.ends_with("|passthrough"))
        .map(|(_, stats)| stats.fitness_score)
        .reduce(f64::max)
        .expect("passthrough stats stored");
    let multisplit_fitness = snap
        .strategy_stats
        .iter()
        .filter(|(entry, _)| entry.ends_with("|multisplit"))
        .map(|(_, stats)| stats.fitness_score)
        .reduce(f64::max)
        .expect("multisplit stats stored");
    assert!(passthrough_fitness > multisplit_fitness);
}

/// Проверяет, что weak observations (runtime_only, explicit_absence) не раздувают
/// probe bias при принятии решений brain advisory.
///
/// Функция observation_confidence_probe_bias_scale возвращает 0.0 для этих типов,
/// что означает что stall-probe предпочтение не усиливается слабыми сигналами.
#[tokio::test]
async fn weak_observations_do_not_inflate_probe_bias() {
    let dir = tempfile::tempdir().unwrap();
    let store = AsyncStateStore::load(dir.path().join("state.json"))
        .await
        .unwrap();

    // Ключ с runtime_only observation (нет capture backing)
    let runtime_only_key = StrategyKey::for_target(
        "203.0.113.200:443".parse().unwrap(),
        "probe-bias-runtime-only.example",
        443,
        Some("probe-bias-runtime-only.example"),
        true,
    );
    // Ключ с explicit_absence observation
    let explicit_absence_key = StrategyKey::for_target(
        "203.0.113.201:443".parse().unwrap(),
        "probe-bias-explicit-absence.example",
        443,
        Some("probe-bias-explicit-absence.example"),
        true,
    );
    // Ключ с capture-backed observation (deep_observed)
    let captured_key = StrategyKey::for_target(
        "203.0.113.202:443".parse().unwrap(),
        "probe-bias-captured.example",
        443,
        Some("probe-bias-captured.example"),
        true,
    );

    let ro_hash = runtime_only_key.hash_key();
    let ea_hash = explicit_absence_key.hash_key();
    let cap_hash = captured_key.hash_key();

    store
        .update(|snap| {
            snap.key_registry
                .insert(ro_hash.clone(), runtime_only_key.clone());
            snap.key_registry
                .insert(ea_hash.clone(), explicit_absence_key.clone());
            snap.key_registry
                .insert(cap_hash.clone(), captured_key.clone());

            // runtime_only: есть syn_ack данные, но нет capture_status Active
            snap.key_observations.insert(
                ro_hash.clone(),
                KeyObservation {
                    syn_ack_ttl: Some(58),
                    syn_ack_window: Some(65535),
                    ..Default::default()
                },
            );
            // explicit_absence: статус явного отсутствия захвата
            snap.key_observations.insert(
                ea_hash.clone(),
                KeyObservation {
                    capture_status: aegis_core::PacketCaptureStatus::UnsupportedPlatform,
                    matched_packets: 2,
                    syn_ack_ttl: Some(58),
                    ..Default::default()
                },
            );
            // captured: реальный capture-backed сигнал
            snap.key_observations.insert(
                cap_hash.clone(),
                KeyObservation {
                    matched_packets: 3,
                    capture_status: aegis_core::PacketCaptureStatus::Active,
                    first_data_ttl: Some(58),
                    first_data_window: Some(65535),
                    ..Default::default()
                },
            );

            // Идентичная stall history для всех — чтобы isolate probe bias
            for hk in [ro_hash.clone(), ea_hash.clone(), cap_hash.clone()] {
                snap.stall_probe_stats.insert(
                    hk,
                    aegis_core::StallProbeStats {
                        trials: 1,
                        collapses: 1,
                        consecutive_stall_failures: 1,
                        last_signal: Some(FailSignal::ThroughputCollapse),
                        ..Default::default()
                    },
                );
            }
        })
        .await;

    let brain = Brain::new(0.0, vec!["passthrough".into(), "ttl_desync".into()], store);

    let ro_advisory = brain.direct_session_advisory(&runtime_only_key).await;
    let ea_advisory = brain.direct_session_advisory(&explicit_absence_key).await;
    let cap_advisory = brain.direct_session_advisory(&captured_key).await;

    // Capture-backed должен иметь более высокий probe bias score чем weak
    assert!(
        cap_advisory.cross_session_signal_metrics.probe_branch_score
            >= ro_advisory.cross_session_signal_metrics.probe_branch_score,
        "captured observation должен давать probe_bias_score >= runtime_only"
    );
    assert!(
        cap_advisory.cross_session_signal_metrics.probe_branch_score
            >= ea_advisory.cross_session_signal_metrics.probe_branch_score,
        "captured observation должен давать probe_bias_score >= explicit_absence"
    );
}

/// Проверяет сохранение и восстановление stall_probe_stats через state_v2 flush/load.
///
/// Это гарантирует что stall history переживает рестарт клиента и brain
/// может использовать накопленные данные между сессиями.
#[tokio::test]
async fn stall_probe_stats_survive_persist_restore_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");

    let key = StrategyKey::for_target(
        "203.0.113.210:443".parse().unwrap(),
        "stall-roundtrip.example",
        443,
        Some("stall-roundtrip.example"),
        true,
    );
    let hk = key.hash_key();

    // --- Сессия 1: создаём и сохраняем stall_probe_stats ---
    {
        let store = AsyncStateStore::load(path.clone()).await.unwrap();
        store
            .update(|snap| {
                snap.key_registry.insert(hk.clone(), key.clone());
                snap.stall_probe_stats.insert(
                    hk.clone(),
                    aegis_core::StallProbeStats {
                        trials: 5,
                        collapses: 3,
                        consecutive_stall_failures: 2,
                        last_signal: Some(FailSignal::ThroughputCollapse),
                        ..Default::default()
                    },
                );
            })
            .await;
        store.flush().await.expect("flush to disk");
    }

    // --- Сессия 2: загружаем и проверяем сохранённые данные ---
    {
        let store2 = AsyncStateStore::load(path.clone()).await.unwrap();
        let snap = store2.snapshot().await;

        let restored = snap
            .stall_probe_stats
            .get(&hk)
            .expect("stall_probe_stats должен быть восстановлен из файла");

        assert_eq!(restored.trials, 5, "trials должен совпадать");
        assert_eq!(restored.collapses, 3, "collapses должен совпадать");
        assert_eq!(
            restored.consecutive_stall_failures, 2,
            "consecutive_stall_failures должен совпадать"
        );
        assert_eq!(
            restored.last_signal,
            Some(FailSignal::ThroughputCollapse),
            "last_signal должен совпадать"
        );
    }
}
