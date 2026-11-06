//! Garivier–Moulines (2008), Algorithms 2/3, normalized rewards B=1.
//! Decisions count verified outcomes, not elapsed milliseconds. Native admission
//! remains outside this estimator. IEEE arithmetic is not a transferred regret proof.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "algorithm", rename_all = "snake_case", deny_unknown_fields)]
pub enum PaperAlgorithm {
    SlidingWindow { rounds: usize, xi: f64 },
    Discounted { gamma: f64, xi: f64 },
}
impl PaperAlgorithm {
    pub fn validate(&self) -> Result<(), String> {
        let xi = match self {
            Self::SlidingWindow { rounds, xi } if (1..=4096).contains(rounds) => *xi,
            Self::Discounted { gamma, xi }
                if gamma.is_finite() && (0.0..1.0).contains(gamma) && *gamma > 0.0 =>
            {
                *xi
            }
            _ => return Err("invalid nonstationary paper algorithm".into()),
        };
        if !xi.is_finite() || !(0.5..=16.0).contains(&xi) || xi == 0.5 {
            return Err("nonstationary xi must be finite and greater than 1/2".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct Estimate {
    pub trials: usize,
    pub effective_trials: f64,
    pub mean: f64,
    pub bonus: f64,
}
pub struct PaperBandit {
    algorithm: PaperAlgorithm,
    rounds: u64,
    window: VecDeque<(String, f64)>,
    // Aggregate recurrence retains all discounted history, without truncation
    // at the legacy observation cap. Values may underflow after long absence;
    // that is explicitly zero-weight exploration, never fabricated evidence.
    weights: BTreeMap<String, (f64, f64, usize)>,
}
impl PaperBandit {
    pub fn new(algorithm: PaperAlgorithm) -> Result<Self, String> {
        algorithm.validate()?;
        Ok(Self {
            algorithm,
            rounds: 0,
            window: VecDeque::new(),
            weights: BTreeMap::new(),
        })
    }
    pub fn observe(&mut self, arm: &str, reward: f64) -> Result<(), String> {
        if arm.is_empty()
            || arm.len() > 64
            || !reward.is_finite()
            || !(0.0..=1.0).contains(&reward)
            || (!self.weights.contains_key(arm) && self.weights.len() >= 64)
        {
            return Err("invalid or oversized nonstationary observation".into());
        }
        let next = self
            .rounds
            .checked_add(1)
            .ok_or("nonstationary round overflow")?;
        match self.algorithm {
            PaperAlgorithm::SlidingWindow { rounds, .. } => {
                self.weights.entry(arm.into()).or_default();
                self.window.push_back((arm.into(), reward));
                if self.window.len() > rounds {
                    self.window.pop_front();
                }
            }
            PaperAlgorithm::Discounted { gamma, .. } => {
                for (count, sum, _) in self.weights.values_mut() {
                    *count *= gamma;
                    *sum *= gamma;
                }
                let (count, sum, trials) = self.weights.entry(arm.into()).or_default();
                *count += 1.0;
                *sum += reward;
                *trials = trials.saturating_add(1);
            }
        }
        self.rounds = next;
        Ok(())
    }
    pub fn estimate(&self, arm: &str) -> Estimate {
        let (count, sum, trials, horizon, scale, xi) = match self.algorithm {
            PaperAlgorithm::SlidingWindow { rounds, xi } => {
                let mut trials = 0;
                let mut sum = 0.0;
                for (name, reward) in &self.window {
                    if name == arm {
                        trials += 1;
                        sum += reward;
                    }
                }
                (
                    trials as f64,
                    sum,
                    trials,
                    self.rounds.min(rounds as u64) as f64,
                    1.0,
                    xi,
                )
            }
            PaperAlgorithm::Discounted { xi, .. } => {
                let (count, sum, trials) = self.weights.get(arm).copied().unwrap_or_default();
                let horizon = self.weights.values().map(|v| v.0).sum();
                (count, sum, trials, horizon, 2.0, xi)
            }
        };
        if count == 0.0 {
            return Estimate {
                trials,
                effective_trials: 0.0,
                mean: 0.0,
                bonus: 0.0,
            };
        }
        let bonus = scale * (xi * horizon.max(1.0).ln() / count).sqrt();
        // Extremely old discounted arms can have subnormal weights and an
        // unrepresentable score. Re-explore them instead of serializing infinity.
        if !bonus.is_finite() {
            return Estimate {
                trials,
                effective_trials: 0.0,
                mean: 0.0,
                bonus: 0.0,
            };
        }
        Estimate {
            trials,
            effective_trials: count,
            mean: (sum / count).clamp(0.0, 1.0),
            bonus,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discounted_recurrence_matches_full_untruncated_formula() {
        let gamma: f64 = 0.8;
        let mut b = PaperBandit::new(PaperAlgorithm::Discounted { gamma, xi: 1.0 }).unwrap();
        let mut tape = Vec::new();
        for i in 0..180 {
            let arm = if i % 3 == 0 { "a" } else { "b" };
            let reward = if i < 90 { 1.0 } else { 0.0 };
            b.observe(arm, reward).unwrap();
            tape.push((arm, reward));
        }
        let n: f64 = tape
            .iter()
            .enumerate()
            .filter(|(_, v)| v.0 == "a")
            .map(|(i, _)| gamma.powi((179 - i) as i32))
            .sum();
        let sum: f64 = tape
            .iter()
            .enumerate()
            .filter(|(_, v)| v.0 == "a")
            .map(|(i, v)| gamma.powi((179 - i) as i32) * v.1)
            .sum();
        let all: f64 = (0..180).map(|i| gamma.powi(i)).sum();
        let a = b.estimate("a");
        assert!((a.effective_trials - n).abs() < 1e-12);
        assert!((a.mean - sum / n).abs() < 1e-12);
        assert!((a.bonus - 2.0 * (all.ln() / n).sqrt()).abs() < 1e-12);
    }
    #[test]
    fn sliding_window_uses_global_rounds_not_last_per_arm_samples() {
        let mut b = PaperBandit::new(PaperAlgorithm::SlidingWindow { rounds: 4, xi: 1.0 }).unwrap();
        b.observe("a", 1.0).unwrap();
        for _ in 0..4 {
            b.observe("b", 0.0).unwrap();
        }
        assert_eq!(b.estimate("a").effective_trials, 0.0);
        let e = b.estimate("b");
        assert_eq!(e.trials, 4);
        assert!((e.bonus - (4.0_f64.ln() / 4.0).sqrt()).abs() < 1e-12);
    }
    #[test]
    fn validation_rejects_nonfinite_reward_before_state_changes() {
        let mut b = PaperBandit::new(PaperAlgorithm::Discounted {
            gamma: 0.9,
            xi: 1.0,
        })
        .unwrap();
        b.observe("a", 1.0).unwrap();
        let e = b.estimate("a");
        assert!(b.observe("a", f64::NAN).is_err());
        assert_eq!(b.estimate("a").effective_trials, e.effective_trials);
        assert!(PaperBandit::new(PaperAlgorithm::Discounted {
            gamma: 1.0,
            xi: 1.0
        })
        .is_err());
        assert!(PaperBandit::new(PaperAlgorithm::SlidingWindow { rounds: 0, xi: 1.0 }).is_err());
    }
    #[test]
    fn causal_policy_tracks_abrupt_change_without_teacher_forcing() {
        for algorithm in [
            PaperAlgorithm::SlidingWindow {
                rounds: 32,
                xi: 1.0,
            },
            PaperAlgorithm::Discounted {
                gamma: 0.9,
                xi: 1.0,
            },
        ] {
            let mut b = PaperBandit::new(algorithm).unwrap();
            let mut post_change_good = 0;
            for t in 0..600 {
                let a = b.estimate("a");
                let c = b.estimate("b");
                let arm = if a.effective_trials == 0.0 {
                    "a"
                } else if c.effective_trials == 0.0 {
                    "b"
                } else if a.mean + a.bonus >= c.mean + c.bonus {
                    "a"
                } else {
                    "b"
                };
                let good = if t < 300 { "a" } else { "b" };
                if t >= 400 && arm == good {
                    post_change_good += 1;
                }
                b.observe(arm, if arm == good { 1.0 } else { 0.0 }).unwrap();
            }
            assert!(
                post_change_good > 130,
                "only {post_change_good}/200 correct after change"
            );
        }
    }
}
