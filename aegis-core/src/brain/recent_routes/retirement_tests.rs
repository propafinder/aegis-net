//! Ordinary in-memory consumer fixtures; synthetic outcomes are not network proof.
use super::*;
fn settings(algorithm: PaperAlgorithm) -> RecentRouteConfig {
    RecentRouteConfig {
        paper_algorithm: Some(algorithm),
        window: Duration::from_secs(60),
        max_observations: 4096,
        diversity_penalty: 0.0,
    }
}
fn algorithm() -> PaperAlgorithm {
    PaperAlgorithm::SlidingWindow {
        rounds: 16,
        xi: 1.0,
    }
}
fn candidate() -> Vec<(EligibleRoute, f64)> {
    vec![(
        EligibleRoute {
            strategy: "one".into(),
            failure_domain: None,
        },
        0.5,
    )]
}
#[test]
fn sixty_fifth_completed_context_does_not_poison_old_and_new_selection() {
    let mut selector = RecentRouteSelector::new(settings(algorithm())).unwrap();
    let now = Instant::now();
    for i in 0..64 {
        selector
            .record_at(
                now + Duration::from_nanos(i),
                &format!("context-{i:03}"),
                "one",
                1.0,
            )
            .unwrap();
    }
    let at = now + Duration::from_nanos(64);
    let completed = selector.record_at(at, "context-064", "one", 1.0);
    let old = selector.rank_at(at, "context-001", &candidate());
    let new = selector.rank_at(at, "context-064", &candidate());
    assert!(
        completed.is_ok() && old.is_ok() && new.is_ok(),
        "65th completion={completed:?}; old={old:?}; new={new:?}"
    );
    assert_eq!(old.unwrap().order, vec!["one"]);
    assert_eq!(new.unwrap().order, vec!["one"]);
}

fn modes() -> [PaperAlgorithm; 2] {
    [
        algorithm(),
        PaperAlgorithm::Discounted {
            gamma: 0.9,
            xi: 1.0,
        },
    ]
}
#[test]
fn sequential_completed_contexts_retire_bounded_histories_and_return_fresh() {
    for mode in modes() {
        let mut selector = RecentRouteSelector::new(settings(mode)).unwrap();
        let now = Instant::now();
        for i in 0..128 {
            selector
                .record_at(
                    now + Duration::from_nanos(i),
                    &format!("c{i:03}"),
                    "one",
                    1.0,
                )
                .unwrap();
            assert!(selector.paper_bandits.len() <= MAX_PAPER_CONTEXTS);
            assert!(selector.observations.len() <= 64);
        }
        assert!(!selector.paper_bandits.contains_key("c000"));
        assert!(selector.observations.iter().all(|o| o.context != "c000"));
        let at = now + Duration::from_nanos(128);
        let fresh = selector.rank_at(at, "c000", &candidate()).unwrap();
        assert_eq!(fresh.ranked[0].window_trials, 0);
        assert_eq!(fresh.ranked[0].window_reward, 0.5); // Independent existing prior, no old paper scores.
        assert!(!selector.paper_bandits.contains_key("c000")); // Ranking allocates nothing.
        selector.record_at(at, "c000", "one", 0.0).unwrap();
        let returned = selector.rank_at(at, "c000", &candidate()).unwrap();
        assert_eq!(returned.ranked[0].window_trials, 1);
        assert_eq!(returned.ranked[0].window_reward, 0.0);
        assert_eq!(selector.paper_bandits.len(), 64);
    }
}
#[test]
fn completion_recency_not_rank_visits_selects_victim_and_late_completion_is_fresh() {
    let mut selector = RecentRouteSelector::new(settings(algorithm())).unwrap();
    let now = Instant::now();
    for i in 0..64 {
        selector
            .record_at(
                now + Duration::from_nanos(i),
                &format!("c{i:03}"),
                "one",
                1.0,
            )
            .unwrap();
    }
    selector
        .record_at(now + Duration::from_nanos(64), "c000", "one", 1.0)
        .unwrap();
    // Reading the old context does not hold or refresh its owned history.
    selector
        .rank_at(now + Duration::from_nanos(65), "c001", &candidate())
        .unwrap();
    selector
        .rank_at(
            now + Duration::from_nanos(65),
            "not-completed",
            &candidate(),
        )
        .unwrap();
    assert_eq!(selector.paper_bandits.len(), 64);
    selector
        .record_at(now + Duration::from_nanos(66), "new", "one", 1.0)
        .unwrap();
    assert!(selector.paper_bandits.contains_key("c000"));
    assert!(!selector.paper_bandits.contains_key("c001"));
    assert_eq!(
        selector.paper_bandits["c000"]
            .estimator
            .estimate("one")
            .trials,
        2
    );
    // This can be the completion of an older in-flight operation. It records
    // only its present completion sample; an evicted estimator is not resurrected.
    selector
        .record_at(now + Duration::from_nanos(67), "c001", "one", 0.0)
        .unwrap();
    assert_eq!(
        selector.paper_bandits["c001"]
            .estimator
            .estimate("one")
            .trials,
        1
    );
    assert_eq!(
        selector.paper_bandits["c001"]
            .estimator
            .estimate("one")
            .mean,
        0.0
    );
    assert_eq!(
        selector.paper_bandits["new"].estimator.estimate("one").mean,
        1.0
    );
    assert_eq!(
        selector
            .observations
            .iter()
            .filter(|o| o.context == "c001")
            .count(),
        1
    );
}
#[test]
fn equal_completion_instants_use_deterministic_context_tie_break() {
    let mut selector = RecentRouteSelector::new(settings(algorithm())).unwrap();
    let at = Instant::now();
    for i in (0..64).rev() {
        selector
            .record_at(at, &format!("c{i:03}"), "one", 1.0)
            .unwrap();
    }
    selector.record_at(at, "new", "one", 0.0).unwrap();
    assert!(!selector.paper_bandits.contains_key("c000"));
    assert!(selector.paper_bandits.contains_key("c001"));
}
#[test]
fn invalid_or_backwards_completion_never_retires_and_clock_survives_expired_observations() {
    let mut selector = RecentRouteSelector::new(settings(algorithm())).unwrap();
    let now = Instant::now();
    for i in 0..64 {
        selector
            .record_at(
                now + Duration::from_nanos(i),
                &format!("c{i:03}"),
                "one",
                1.0,
            )
            .unwrap();
    }
    let original_keys: Vec<_> = selector.paper_bandits.keys().cloned().collect();
    let later = now + Duration::from_secs(61);
    selector.rank_at(later, "unknown", &candidate()).unwrap();
    assert!(selector.observations.is_empty());
    assert!(selector.record_at(now, "new", "one", 1.0).is_err());
    assert!(selector.record_at(later, "new", "one", f64::NAN).is_err());
    assert!(selector.record_at(later, "", "one", 1.0).is_err());
    assert_eq!(
        original_keys,
        selector.paper_bandits.keys().cloned().collect::<Vec<_>>()
    );
    assert_eq!(
        selector.last_paper_completion,
        Some(now + Duration::from_nanos(63))
    );
    assert!(!selector.paper_refused);
    selector.record_at(later, "new", "one", 0.0).unwrap();
    assert_eq!(selector.paper_bandits.len(), 64);
}
#[test]
fn genuine_estimator_arm_refusal_stays_sticky_without_capacity_fallback() {
    let mut selector = RecentRouteSelector::new(settings(algorithm())).unwrap();
    let now = Instant::now();
    for i in 0..64 {
        selector
            .record_at(
                now + Duration::from_nanos(i),
                "context",
                &format!("arm-{i}"),
                1.0,
            )
            .unwrap();
    }
    assert!(selector
        .record_at(now + Duration::from_nanos(64), "context", "arm-64", 1.0)
        .is_err());
    assert!(selector.paper_refused);
    assert_eq!(
        selector.last_paper_completion,
        Some(now + Duration::from_nanos(63))
    );
    assert!(selector
        .rank_at(now + Duration::from_nanos(65), "context", &candidate())
        .is_err());
    // A separate new legitimate completion does not clear a real estimator error.
    selector
        .record_at(now + Duration::from_nanos(66), "other", "one", 1.0)
        .unwrap();
    assert!(selector
        .rank_at(now + Duration::from_nanos(67), "other", &candidate())
        .is_err());
}
#[test]
fn absent_paper_mode_keeps_window_path_without_paper_history_or_completion_marker() {
    let mut config = settings(algorithm());
    config.paper_algorithm = None;
    let mut selector = RecentRouteSelector::new(config).unwrap();
    let now = Instant::now();
    for i in 0..128 {
        selector
            .record_at(
                now + Duration::from_nanos(i),
                &format!("c{i:03}"),
                "one",
                1.0,
            )
            .unwrap();
    }
    assert!(selector.paper_bandits.is_empty());
    assert!(selector.last_paper_completion.is_none());
    assert_eq!(selector.observations.len(), 128);
    assert_eq!(
        selector
            .rank_at(now + Duration::from_nanos(129), "c000", &candidate())
            .unwrap()
            .ranked[0]
            .window_trials,
        1
    );
}
#[tokio::test]
async fn native_brain_api_consumer_handles_one_hundred_synthetic_target_completions() {
    for mode in modes() {
        let settings = RecentRoutesSettings {
            window_ms: 60_000,
            max_observations: 256,
            diversity_penalty: 0.0,
            paper_algorithm: Some(mode),
            failure_domains: BTreeMap::new(),
        };
        let brain = Brain::new(
            0.0,
            vec!["one".into()],
            crate::state_v2::AsyncStateStore::ephemeral(),
        )
        .with_recent_routes(Some(&settings))
        .unwrap();
        let dst = "127.0.0.1:443".parse().unwrap();
        for i in 0..100 {
            let host = format!("synthetic-{i}.test");
            let key = StrategyKey::for_target(dst, &host, 443, Some(&host), true);
            // This explicitly feeds the real API synthetic fixture outcomes;
            // no socket, target response or field success is inferred from it.
            brain
                .record_outcome(
                    &key,
                    "one",
                    crate::signals::FailSignal::Success,
                    None,
                    128,
                    None,
                )
                .await;
            let trace = brain.select_order_trace(&key).await;
            assert_eq!(trace.reward_selected_order, vec!["one"]);
            assert!(trace.recent_selection.unwrap().selection_error.is_none());
        }
        let first =
            StrategyKey::for_target(dst, "synthetic-0.test", 443, Some("synthetic-0.test"), true);
        let trace = brain.select_order_trace(&first).await;
        assert_eq!(trace.reward_selected_order, vec!["one"]);
        assert_eq!(
            trace.recent_selection.unwrap().selection.ranked[0].window_trials,
            0
        );
        let history = brain.recent_routes.as_ref().unwrap().lock().await;
        assert_eq!(history.paper_bandits.len(), 64);
        assert!(!history.paper_refused);
    }
}
