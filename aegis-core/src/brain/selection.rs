use std::cmp::Ordering;

use super::StrategyBelief;

#[derive(Debug, Clone)]
pub(super) struct StrategyEstimate {
    pub(super) reward: f64,
    /// Context- and capture-trust-weighted evidence used for confidence.
    pub(super) trials: f64,
    /// Context-weighted observed trials before capture-trust scaling.
    pub(super) exploration_trials: f64,
    pub(super) total_trials: f64,
    pub(super) belief: StrategyBelief,
}

#[derive(Debug, Clone)]
pub(super) struct RankedStrategy {
    pub(super) index: usize,
    pub(super) name: String,
    pub(super) score: f64,
    pub(super) trials: f64,
    pub(super) estimated_reward: f64,
    pub(super) total_trials: f64,
    pub(super) probe_history_strategy_bias: f64,
    pub(super) belief: StrategyBelief,
    pub(super) selection_score_ucb_exploration_bonus: Option<f64>,
}

pub(super) fn compare_ranked(a: &RankedStrategy, b: &RankedStrategy) -> Ordering {
    match (a.belief.hard_blocked, b.belief.hard_blocked) {
        (true, false) => return Ordering::Greater,
        (false, true) => return Ordering::Less,
        _ => {}
    }
    match b.score.partial_cmp(&a.score).unwrap_or(Ordering::Equal) {
        Ordering::Equal => match a.trials.partial_cmp(&b.trials).unwrap_or(Ordering::Equal) {
            Ordering::Equal => a.index.cmp(&b.index),
            other => other,
        },
        other => other,
    }
}

pub(super) fn ucb1_score(reward: f64, trials: f64, total_trials: f64) -> f64 {
    ucb1_exploration_bonus(trials, total_trials)
        .map(|exploration| reward + exploration)
        .unwrap_or(reward + 1.0)
}

pub(super) fn ucb1_exploration_bonus(trials: f64, total_trials: f64) -> Option<f64> {
    if trials <= f64::EPSILON {
        return None;
    }
    Some(((2.0 * (total_trials + 1.0).ln()) / trials).sqrt())
}
