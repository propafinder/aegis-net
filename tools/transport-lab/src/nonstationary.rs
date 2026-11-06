//! Bounded deterministic replay, not the product Brain or a network measurement.
//! Epochs supply eligibility and normalized rewards; policies see only past rewards.
//! Sliding-window UCB is inspired by Garivier/Moulines, without a regret claim.
use serde::Serialize;
use std::collections::VecDeque;
use thiserror::Error;

const MAX_ROUNDS: usize = 4096;
const MAX_ROUTES: usize = 16;
const MAX_EPOCHS: usize = 64;
const MAX_WINDOW: usize = 1024;

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Policy {
    LifetimeUcb,
    SlidingWindowUcb { window_rounds: usize },
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct ReplayConfig {
    pub rounds: usize,
    /// Multiplier inside sqrt(exploration * ln(effective_rounds) / count).
    pub exploration: f64,
    /// First run of this many optimal eligible choices defines recovery.
    pub recovery_run: usize,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct RouteState {
    /// Eligibility to attempt a probe, not a claim of successful delivery.
    pub available: bool,
    pub hard_excluded: bool,
    /// Constant synthetic reward in [0, 1] during this epoch; not success probability.
    pub reward: f64,
}

#[derive(Clone, Debug, Serialize)]
pub struct NetworkEpoch {
    pub start_round: usize,
    pub routes: Vec<RouteState>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReplayError {
    #[error("invalid deterministic route replay: {0}")]
    InvalidInput(&'static str),
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    Completed,
    NoEligibleRoute,
}

#[derive(Debug, Serialize)]
pub struct EpochSummary {
    pub start_round: usize,
    pub end_round_exclusive: usize,
    pub probes: usize,
    pub choice_counts: Vec<usize>,
    pub mean_reward: Option<f64>,
    /// Rounds through completion of the first optimal run; None means not observed.
    pub recovery_after_rounds: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct ReplaySummary {
    pub policy: Policy,
    pub stop_reason: StopReason,
    /// Exclusive end: the stopped round is never probed on NoEligibleRoute.
    pub stopped_at_round: usize,
    /// Route index per round, beginning at round zero. No gaps or hidden probes.
    pub choices: Vec<usize>,
    pub epochs: Vec<EpochSummary>,
}

fn validate(c: &ReplayConfig, epochs: &[NetworkEpoch], p: Policy) -> Result<usize, ReplayError> {
    let bad = ReplayError::InvalidInput;
    if c.rounds == 0
        || c.rounds > MAX_ROUNDS
        || c.recovery_run == 0
        || c.recovery_run > c.rounds.min(256)
        || !c.exploration.is_finite()
        || c.exploration <= 0.0
        || c.exploration > 4.0
    {
        return Err(bad("round, recovery or exploration bounds"));
    }
    if matches!(p, Policy::SlidingWindowUcb { window_rounds } if window_rounds == 0 || window_rounds > MAX_WINDOW)
    {
        return Err(bad("window bounds"));
    }
    let Some(first) = epochs.first() else {
        return Err(bad("missing epochs"));
    };
    let routes = first.routes.len();
    if epochs.len() > MAX_EPOCHS || first.start_round != 0 || routes == 0 || routes > MAX_ROUTES {
        return Err(bad("epoch or route bounds"));
    }
    for (i, epoch) in epochs.iter().enumerate() {
        if epoch.start_round >= c.rounds
            || epoch.routes.len() != routes
            || (i > 0 && epochs[i - 1].start_round >= epoch.start_round)
        {
            return Err(bad("epochs must be ordered with a stable route count"));
        }
        if epoch
            .routes
            .iter()
            .any(|r| !r.reward.is_finite() || !(0.0..=1.0).contains(&r.reward))
        {
            return Err(bad("rewards must be finite in [0, 1]"));
        }
    }
    Ok(routes)
}

/// Replays at most 4096 probes; neither policy resets itself at an epoch boundary.
/// Only eligibility is supplied to selection; the current reward is read afterward.
pub fn replay(
    c: &ReplayConfig,
    input: &[NetworkEpoch],
    policy: Policy,
) -> Result<ReplaySummary, ReplayError> {
    let routes = validate(c, input, policy)?;
    let mut out = ReplaySummary {
        policy,
        stop_reason: StopReason::Completed,
        stopped_at_round: c.rounds,
        choices: Vec::with_capacity(c.rounds),
        epochs: input
            .iter()
            .enumerate()
            .map(|(i, e)| EpochSummary {
                start_round: e.start_round,
                end_round_exclusive: input.get(i + 1).map_or(c.rounds, |n| n.start_round),
                probes: 0,
                choice_counts: vec![0; routes],
                mean_reward: None,
                recovery_after_rounds: None,
            })
            .collect(),
    };
    let mut history: VecDeque<(usize, usize, f64)> = VecDeque::new();
    let mut epoch = 0;
    let mut reward_sums = vec![0.0; input.len()];
    let mut optimal_runs = vec![0; input.len()];
    for round in 0..c.rounds {
        while input.get(epoch + 1).is_some_and(|e| e.start_round <= round) {
            epoch += 1;
        }
        let states = &input[epoch].routes;
        // This filter precedes BOTH zero-count exploration and score evaluation.
        let eligible: Vec<usize> = (0..routes)
            .filter(|&i| states[i].available && !states[i].hard_excluded)
            .collect();
        if eligible.is_empty() {
            out.stop_reason = StopReason::NoEligibleRoute;
            out.stopped_at_round = round;
            break;
        }
        let effective = match policy {
            Policy::LifetimeUcb => round + 1,
            Policy::SlidingWindowUcb { window_rounds } => {
                while history
                    .front()
                    .is_some_and(|(r, _, _)| round - r > window_rounds)
                {
                    history.pop_front();
                }
                (round + 1).min(window_rounds)
            }
        };
        let mut counts = vec![0_usize; routes];
        let mut sums = vec![0.0; routes];
        for &(_, route, reward) in &history {
            counts[route] += 1;
            sums[route] += reward;
        }
        let selected = eligible
            .iter()
            .copied()
            .find(|&i| counts[i] == 0)
            .unwrap_or_else(|| {
                let mut best = eligible[0];
                let score = |i: usize| {
                    sums[i] / counts[i] as f64
                        + (c.exploration * (effective as f64).ln() / counts[i] as f64).sqrt()
                };
                for &i in &eligible[1..] {
                    if score(i) > score(best) {
                        best = i;
                    }
                }
                best // Ascending route index breaks all ties; no infinity sentinel.
            });
        let reward = states[selected].reward;
        history.push_back((round, selected, reward));
        out.choices.push(selected);
        let summary = &mut out.epochs[epoch];
        summary.probes += 1;
        summary.choice_counts[selected] += 1;
        reward_sums[epoch] += reward;
        let best_reward = eligible
            .iter()
            .map(|&i| states[i].reward)
            .fold(0.0_f64, f64::max);
        optimal_runs[epoch] = if reward == best_reward {
            optimal_runs[epoch] + 1
        } else {
            0
        };
        if optimal_runs[epoch] >= c.recovery_run && summary.recovery_after_rounds.is_none() {
            summary.recovery_after_rounds = Some(round - summary.start_round + 1);
        }
    }
    for (i, e) in out.epochs.iter_mut().enumerate() {
        e.mean_reward = (e.probes > 0).then(|| reward_sums[i] / e.probes as f64);
    }
    Ok(out)
}

#[derive(Debug, Serialize)]
pub struct DemoSummary {
    pub scope: &'static str,
    pub network_measured: bool,
    pub current_brain_executed: bool,
    pub config: ReplayConfig,
    pub input_epochs: Vec<NetworkEpoch>,
    pub lifetime: ReplaySummary,
    pub sliding_window: ReplaySummary,
}

fn fixture() -> (ReplayConfig, Vec<NetworkEpoch>) {
    let route = |available, hard_excluded, reward| RouteState {
        available,
        hard_excluded,
        reward,
    };
    (
        ReplayConfig {
            rounds: 512,
            exploration: 2.0,
            recovery_run: 8,
        },
        vec![
            NetworkEpoch {
                start_round: 0,
                routes: vec![
                    route(true, false, 1.0),
                    route(true, false, 0.5),
                    route(false, false, 0.0),
                    route(true, true, 1.0),
                ],
            },
            NetworkEpoch {
                start_round: 384,
                routes: vec![
                    route(true, false, 0.0),
                    route(true, false, 0.5),
                    route(true, false, 0.0),
                    route(true, true, 1.0),
                ],
            },
        ],
    )
}

pub fn demo() -> Result<DemoSummary, ReplayError> {
    let (config, input_epochs) = fixture();
    let lifetime = replay(&config, &input_epochs, Policy::LifetimeUcb)?;
    let sliding_window = replay(
        &config,
        &input_epochs,
        Policy::SlidingWindowUcb { window_rounds: 48 },
    )?;
    Ok(DemoSummary {
        scope: "measured_deterministic_replay_not_network_or_regret_theorem",
        network_measured: false,
        current_brain_executed: false,
        config,
        input_epochs,
        lifetime,
        sliding_window,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn regime_change_adapts_without_epoch_reset() {
        let d = demo().unwrap();
        assert_eq!(d.sliding_window.epochs[1].recovery_after_rounds, Some(44));
        assert_eq!(d.lifetime.epochs[1].recovery_after_rounds, None);
        assert_eq!(d.sliding_window.stopped_at_round, 512);
        assert_eq!(d.sliding_window.stop_reason, StopReason::Completed);
    }
    #[test]
    fn lifetime_and_window_match_the_expected_fixture() {
        let d = demo().unwrap();
        assert_eq!(d.lifetime.epochs[1].choice_counts, [85, 29, 14, 0]);
        assert_eq!(d.sliding_window.epochs[1].choice_counts, [26, 80, 22, 0]);
        assert_eq!(d.lifetime.epochs[1].mean_reward, Some(0.11328125));
        assert_eq!(d.sliding_window.epochs[1].mean_reward, Some(0.3125));
        assert!(serde_json::to_string(&d).is_ok());
    }
    #[test]
    fn hard_excluded_routes_are_never_explored_or_scored() {
        let d = demo().unwrap();
        for result in [&d.lifetime, &d.sliding_window] {
            assert!(!result.choices.contains(&3));
            assert!(!result.choices[..384].contains(&2));
            assert_eq!(result.choices[384], 2); // Newly eligible zero-count route is explored.
        }
    }
    #[test]
    fn invalid_numerics_and_work_bounds_are_rejected() {
        let (c, input) = fixture();
        for reward in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -0.1, 1.1] {
            let mut bad = input.clone();
            bad[0].routes[0].reward = reward;
            assert!(replay(&c, &bad, Policy::LifetimeUcb).is_err());
        }
        for rounds in [0, MAX_ROUNDS + 1] {
            assert!(replay(&ReplayConfig { rounds, ..c }, &input, Policy::LifetimeUcb).is_err());
        }
        for exploration in [f64::NAN, f64::INFINITY, 0.0, -1.0, 4.1] {
            assert!(replay(
                &ReplayConfig { exploration, ..c },
                &input,
                Policy::LifetimeUcb
            )
            .is_err());
        }
        for window_rounds in [0, MAX_WINDOW + 1] {
            assert!(replay(&c, &input, Policy::SlidingWindowUcb { window_rounds }).is_err());
        }
        let mut bad = input.clone();
        bad[0].routes = vec![bad[0].routes[0]; MAX_ROUTES + 1];
        assert!(replay(&c, &bad, Policy::LifetimeUcb).is_err());
        bad = input.clone();
        bad[1].start_round = 0;
        assert!(replay(&c, &bad, Policy::LifetimeUcb).is_err());
    }
    #[test]
    fn no_eligible_route_stops_before_any_probe() {
        let (c, input) = fixture();
        for blocked_epoch in [0, 1] {
            let mut blocked = input.clone();
            for r in &mut blocked[blocked_epoch].routes {
                r.available = false;
            }
            for p in [
                Policy::LifetimeUcb,
                Policy::SlidingWindowUcb { window_rounds: 48 },
            ] {
                let out = replay(&c, &blocked, p).unwrap();
                assert_eq!(out.stop_reason, StopReason::NoEligibleRoute);
                assert_eq!(out.stopped_at_round, input[blocked_epoch].start_round);
                assert_eq!(out.choices.len(), input[blocked_epoch].start_round);
                assert_eq!(out.epochs[blocked_epoch].probes, 0);
                assert_eq!(out.epochs[blocked_epoch].mean_reward, None);
            }
        }
    }
}
