use super::*;

fn config() -> Config {
    Config {
        window_ms: 100,
        failure_cooldown_ms: 20,
        max_observations: 32,
    }
}
fn candidate(name: &str, prior: f64) -> Candidate {
    Candidate {
        strategy: name.into(),
        prior,
        runtime_admitted: true,
        hard_excluded: false,
    }
}
fn decision(at: u64, candidates: Vec<Candidate>) -> Event {
    Event {
        at_unix_ms: at,
        context_sha256: "a".repeat(64),
        kind: EventKind::Decision { candidates },
    }
}
fn outcome(at: u64, strategy: &str, reward: f64, failed: bool) -> Event {
    Event {
        at_unix_ms: at,
        context_sha256: "a".repeat(64),
        kind: EventKind::Outcome {
            strategy: strategy.into(),
            progress_reward: reward,
            cooldown_trigger: failed,
            reported_latency_ms: Some(3),
            reported_outgoing_bytes: u64::from(reward > 0.0),
        },
    }
}
fn two() -> Vec<Candidate> {
    vec![candidate("one", 0.5), candidate("two", 0.25)]
}

#[test]
fn native_ranking_uses_only_past_tape_and_preserves_unknown_policy_metrics() {
    let tape = [
        decision(0, two()),
        outcome(10, "one", 1.0, false),
        decision(11, two()),
        outcome(12, "two", 0.0, true),
    ];
    let r = replay(config(), &tape).unwrap();
    assert_eq!(r.decisions[0].native_recent.order, ["one", "two"]);
    assert_eq!(r.decisions[0].native_recent.ranked[0].window_trials, 0);
    assert_eq!(
        r.decisions[1].native_recent.order[0], "two",
        "cold exploration remains native"
    );
    assert_eq!(r.decisions[1].native_recent.ranked[0].window_trials, 0);
    assert_eq!(r.reported_latency_sum_ms, 6);
    assert_eq!(r.reported_outgoing_bytes_sum, 1);
    assert_eq!(r.policy_recovery_ms, None);
    assert_eq!(r.policy_cost, None);
    assert_eq!(r.policy_regret, None);
    assert!(!r.policy_advantage_established && !r.application_delivery_verified);
    assert!(!r.admission_verified && !r.automatic_policy_application);
}

#[test]
fn cooldown_is_a_declared_overlay_with_exact_boundary_and_teacher_forcing() {
    let tape = [
        decision(0, two()),
        outcome(1, "one", 0.0, true),
        decision(2, two()),
        outcome(3, "one", 1.0, false),
        decision(21, two()),
        outcome(22, "two", 1.0, false),
    ];
    let r = replay(config(), &tape).unwrap();
    assert_eq!(
        r.decisions[1].native_recent_with_fixed_cooldown.order,
        ["two"]
    );
    assert_eq!(r.decisions[1].overlay_cooldown_excluded_candidates, 1);
    assert_eq!(r.decisions[1].logged_strategy.as_deref(), Some("one"));
    assert_eq!(r.decisions[2].overlay_cooldown_excluded_candidates, 0);
    assert!(r.decisions[2]
        .native_recent_with_fixed_cooldown
        .order
        .contains(&"one".into()));
    assert_eq!(r.observed_failure_to_progress_ms, [2]);
    assert_eq!(
        r.policy_recovery_ms, None,
        "logged transition is not overlay recovery"
    );
    assert!(!r.counterfactual_outcomes_available);
}

#[test]
fn hard_blocks_and_admission_precede_cold_exploration_and_empty_stays_empty() {
    let mut blocked = candidate("blocked", 1.0);
    blocked.hard_excluded = true;
    let mut omitted = candidate("omitted", 1.0);
    omitted.runtime_admitted = false;
    let tape = [
        decision(
            0,
            vec![blocked.clone(), omitted.clone(), candidate("one", 0.0)],
        ),
        outcome(1, "one", 1.0, false),
        decision(2, vec![blocked, omitted]),
    ];
    let r = replay(config(), &tape).unwrap();
    assert_eq!(r.decisions[0].native_recent.order, ["one"]);
    assert_eq!(r.decisions[0].hard_excluded_candidates, 1);
    assert_eq!(r.decisions[0].not_admitted_candidates, 1);
    assert!(r.decisions[1].native_recent.order.is_empty());
    assert!(r.decisions[1]
        .native_recent_with_fixed_cooldown
        .order
        .is_empty());
}

#[test]
fn native_window_pruning_and_context_isolation_are_replayed_without_sleep() {
    let mut other_decision = decision(12, two());
    other_decision.context_sha256 = "b".repeat(64);
    let mut other_outcome = outcome(13, "two", 1.0, false);
    other_outcome.context_sha256 = "b".repeat(64);
    let tape = [
        decision(0, two()),
        outcome(10, "one", 1.0, false),
        other_decision,
        other_outcome,
        decision(110, two()),
        outcome(110, "one", 1.0, false),
        decision(211, two()),
        outcome(212, "one", 1.0, false),
    ];
    let r = replay(config(), &tape).unwrap();
    assert_eq!(r.decisions[1].native_recent.ranked[0].window_trials, 0);
    assert_eq!(r.decisions[2].native_recent.order[0], "two");
    assert_eq!(r.decisions[3].native_recent.order[0], "one");
    assert!(r.decisions[3]
        .native_recent
        .ranked
        .iter()
        .all(|v| v.window_trials == 0));
}

#[test]
fn refuses_orphan_missing_overlapping_and_excluded_outcomes() {
    for tape in [
        vec![outcome(0, "one", 1.0, false)],
        vec![decision(0, two())],
        vec![decision(0, two()), decision(1, two())],
        vec![decision(0, two()), outcome(1, "unknown", 1.0, false)],
    ] {
        assert!(replay(config(), &tape).is_err());
    }
    let mut blocked = candidate("one", 0.5);
    blocked.hard_excluded = true;
    assert!(replay(
        config(),
        &[decision(0, vec![blocked]), outcome(1, "one", 1.0, false)]
    )
    .is_err());
}

#[test]
fn rejects_invalid_schema_chronology_rewards_and_declared_work_bounds() {
    let good = [decision(10, two()), outcome(11, "one", 1.0, false)];
    assert!(replay(config(), &[]).is_err());
    assert!(replay(config(), &vec![good[0].clone(); MAX_EVENTS + 1]).is_err());
    for c in [
        Config {
            window_ms: 0,
            ..config()
        },
        Config {
            window_ms: 3_600_001,
            ..config()
        },
        Config {
            failure_cooldown_ms: 3_600_001,
            ..config()
        },
        Config {
            max_observations: 4097,
            ..config()
        },
    ] {
        assert!(replay(c, &good).is_err());
    }
    for reward in [f64::NAN, f64::INFINITY, 0.5, -1.0] {
        assert!(replay(
            config(),
            &[good[0].clone(), outcome(11, "one", reward, false)]
        )
        .is_err());
    }
    assert!(replay(config(), &[good[0].clone(), outcome(9, "one", 1.0, false)]).is_err());
    assert!(replay(
        config(),
        &[
            good[0].clone(),
            outcome(MAX_SPAN_MS + 11, "one", 1.0, false)
        ]
    )
    .is_err());
    for bad in [
        vec![candidate("one", 0.5); 17],
        vec![candidate("one", f64::NAN)],
        vec![candidate("one", 1.1)],
        vec![candidate("secret / target", 0.5)],
        vec![candidate("one", 0.5), candidate("one", 0.5)],
    ] {
        assert!(replay(config(), &[decision(0, bad)]).is_err());
    }
    let mut bad = good.clone();
    bad[0].context_sha256 = "not_digest".into();
    assert!(replay(config(), &bad).is_err());
}

#[test]
fn zero_bytes_cannot_invent_progress_and_reported_byte_overflow_is_refused() {
    let mut no_bytes = outcome(1, "one", 1.0, false);
    if let EventKind::Outcome {
        reported_outgoing_bytes,
        ..
    } = &mut no_bytes.kind
    {
        *reported_outgoing_bytes = 0;
    }
    assert!(replay(config(), &[decision(0, two()), no_bytes]).is_err());
    let mut huge = outcome(1, "one", 1.0, false);
    if let EventKind::Outcome {
        reported_outgoing_bytes,
        ..
    } = &mut huge.kind
    {
        *reported_outgoing_bytes = u64::MAX;
    }
    assert!(replay(
        config(),
        &[
            decision(0, two()),
            huge,
            decision(2, two()),
            outcome(3, "one", 1.0, false)
        ]
    )
    .is_err());
}
