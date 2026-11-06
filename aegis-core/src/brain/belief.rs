use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StrategyBelief {
    pub alpha: f64,
    pub beta: f64,
    pub detection_risk: f64,
    pub latency_cost: f64,
    pub confidence: f64,
    pub freshness: f64,
    pub hard_blocked: bool,
    pub source: &'static str,
}

impl StrategyBelief {
    pub(super) fn posterior_mean(&self) -> f64 {
        let denom = self.alpha + self.beta;
        if denom <= f64::EPSILON {
            0.5
        } else {
            (self.alpha / denom).clamp(0.0, 1.0)
        }
    }
}
