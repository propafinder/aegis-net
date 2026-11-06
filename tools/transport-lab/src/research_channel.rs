//! Offline finite-channel trainer. Runtime actuation uses the separately admitted
//! label-blind adaptive carrier or the explicit target/purpose Liu carrier.
//! This offline trainer never activates either owner.
use aegis_core::traffic_privacy::rate_distortion::{self, Limits, Problem};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    io,
    time::{Duration, Instant},
};

#[derive(Deserialize)]
#[serde(tag = "model", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    LabelBlind {
        secrets: usize,
        observations: usize,
        outputs: usize,
        joint: Vec<f64>,
        cost: Vec<f64>,
        allowed: Vec<bool>,
        budget: f64,
        iterations: usize,
        gap_bits: f64,
        timeout_ms: u64,
    },
    LabelConditionalWasserstein {
        prior: Vec<f64>,
        features: usize,
        conditionals: Vec<f64>,
        metric: Vec<f64>,
        budget: f64,
        iterations: usize,
        gap_bits: f64,
        timeout_ms: u64,
    },
}
fn refusal(e: rate_distortion::Error) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("finite channel refused: {e:?}"),
    )
}
pub fn analyze(request: Request) -> io::Result<Value> {
    let (problem, iterations, gap_bits, timeout_ms, model) = match request {
        Request::LabelBlind {
            secrets,
            observations,
            outputs,
            joint,
            cost,
            allowed,
            budget,
            iterations,
            gap_bits,
            timeout_ms,
        } => (
            Problem::label_blind(secrets, observations, outputs, joint, cost, allowed, budget),
            iterations,
            gap_bits,
            timeout_ms,
            "label_blind_expected_cost",
        ),
        Request::LabelConditionalWasserstein {
            prior,
            features,
            conditionals,
            metric,
            budget,
            iterations,
            gap_bits,
            timeout_ms,
        } => (
            Problem::label_conditional_wasserstein(prior, features, conditionals, metric, budget),
            iterations,
            gap_bits,
            timeout_ms,
            "label_conditional_wasserstein_theory_only",
        ),
    };
    if !(1..=5000).contains(&timeout_ms) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "trainer timeout must be 1..5000ms",
        ));
    }
    let channel = rate_distortion::optimize(
        problem.map_err(refusal)?,
        Limits {
            iterations,
            smoothing: 1e-8,
            gap_bits,
        },
        Instant::now() + Duration::from_millis(timeout_ms),
        || false,
    )
    .map_err(refusal)?;
    let c = channel.certificate();
    Ok(json!({
        "schema": "aegis_finite_channel_trainer_v1", "model": model,
        "scope": "declared finite model; floating optimizer diagnostics; no network acceptance",
        "observations": channel.observation_count(), "outputs": channel.output_count(),
        "transition_probabilities": channel.probabilities(),
        "iterations": c.iterations, "leakage_bits": c.leakage_bits,
        "expected_cost": c.expected_cost, "cost_budget": c.cost_budget,
        "original_gap_bound_bits": c.original_gap_bound_bits,
        "smoothing_bias_bound_bits": c.smoothing_bias_bound_bits,
        "rigorous_interval_certificate": c.rigorous_interval_certificate,
        "target_network_measured": false, "installed_runtime": false, "beta_exit": false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn typed_training_keeps_theoretical_label_conditional_model_explicit() {
        let req: Request = serde_json::from_value(json!({
            "model":"label_conditional_wasserstein", "prior":[0.5,0.5], "features":2,
            "conditionals":[1.0,0.0,0.0,1.0], "metric":[0.0,1.0,1.0,0.0], "budget":0.5,
            "iterations":1000, "gap_bits":0.001, "timeout_ms":1000
        }))
        .unwrap();
        let report = analyze(req).unwrap();
        assert_eq!(report["model"], "label_conditional_wasserstein_theory_only");
        assert!(report["leakage_bits"].as_f64().unwrap() < 0.001);
        assert_eq!(report["installed_runtime"], false);
        assert_eq!(report["rigorous_interval_certificate"], false);
    }
}
