//! Finite convex privacy/utility channels, not full-flow network guarantees.
//!
//! Calmon/Fawaz: a label-blind `S -> Z -> Y` channel with expected cost.
//! Liu et al.: a SEPARATE label-conditioned transport formulation of finite W1.
//! Smoothing is used only for optimization/certification, never for emission.
#![allow(clippy::needless_range_loop)] // Explicit finite matrix coordinates.
use rand::{CryptoRng, RngCore};
use std::time::Instant;

const MAX_SECRETS: usize = 16;
const MAX_ROWS: usize = 128;
const MAX_OUTPUTS: usize = 32;
const LN_2: f64 = std::f64::consts::LN_2;
// Absolute objective-unit allowance only, NEVER scaled by raw costs/budget.
// This acknowledges tiny IEEE roundoff; it is not an interval proof.
const DUAL_ROUNDOFF_NATS: f64 = 1e-12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Model {
    LabelBlindExpectedCost,
    LabelConditionalWasserstein,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidInput,
    Infeasible,
    Cancelled,
    Deadline,
    NumericalFailure,
    NotConverged,
    UnobservedInput,
    WrongModel,
    EntropyUnavailable,
}

/// Validated finite problem. All costs and the budget have the SAME caller-
/// declared units. A normalized feature metric is not physical delay/bytes.
#[derive(Clone, Debug)]
pub struct Problem {
    secrets: usize,
    rows: usize,
    outputs: usize,
    joint: Vec<f64>,
    cost: Vec<f64>,
    allowed: Vec<bool>,
    budget: f64,
    model: Model,
    original_features: usize,
}

impl Problem {
    /// `joint[s * observations + z] = p(S=s,Z=z)`; rows are K(Y|Z).
    /// `allowed[z * outputs + y]` must encode actual causal actuator limits.
    #[allow(clippy::too_many_arguments)] // Three independent finite alphabet axes.
    pub fn label_blind(
        secrets: usize,
        observations: usize,
        outputs: usize,
        joint: Vec<f64>,
        cost: Vec<f64>,
        allowed: Vec<bool>,
        budget: f64,
    ) -> Result<Self, Error> {
        Self::validated(Self {
            secrets,
            rows: observations,
            outputs,
            joint,
            cost,
            allowed,
            budget,
            model: Model::LabelBlindExpectedCost,
            original_features: observations,
        })
    }

    /// Liu's finite metric model, via transport kernels K(Y|S,Z).
    /// This is NOT executable by a label-blind installed traffic shaper.
    /// `conditionals[s * features + z] = P(Z=z|S=s)`.
    pub fn label_conditional_wasserstein(
        prior: Vec<f64>,
        features: usize,
        conditionals: Vec<f64>,
        metric: Vec<f64>,
        budget: f64,
    ) -> Result<Self, Error> {
        let secrets = prior.len();
        if !(1..=MAX_SECRETS).contains(&secrets)
            || !(1..=MAX_OUTPUTS).contains(&features)
            || secrets * features > MAX_ROWS
            || conditionals.len() != secrets * features
            || metric.len() != features * features
            || prior.iter().any(|p| !p.is_finite() || *p <= 0.0)
            || (prior.iter().sum::<f64>() - 1.0).abs() > 1e-10
        {
            return Err(Error::InvalidInput);
        }
        for z in 0..features {
            for y in 0..features {
                let d = metric[z * features + y];
                if !d.is_finite()
                    || !(0.0..=1.0).contains(&d)
                    || (z == y && d != 0.0)
                    || (z != y && d <= 0.0)
                    || (d - metric[y * features + z]).abs() > 1e-12
                {
                    return Err(Error::InvalidInput);
                }
                for k in 0..features {
                    if d > metric[z * features + k] + metric[k * features + y] + 1e-12 {
                        return Err(Error::InvalidInput);
                    }
                }
            }
        }
        let rows = secrets * features;
        let mut joint = vec![0.0; secrets * rows];
        let mut cost = Vec::with_capacity(rows * features);
        for s in 0..secrets {
            let row = &conditionals[s * features..(s + 1) * features];
            if row.iter().any(|p| !p.is_finite() || *p < 0.0)
                || (row.iter().sum::<f64>() - 1.0).abs() > 1e-10
            {
                return Err(Error::InvalidInput);
            }
            for z in 0..features {
                joint[s * rows + s * features + z] = prior[s] * row[z];
                cost.extend_from_slice(&metric[z * features..(z + 1) * features]);
            }
        }
        Self::validated(Self {
            secrets,
            rows,
            outputs: features,
            joint,
            cost,
            allowed: vec![true; rows * features],
            budget,
            model: Model::LabelConditionalWasserstein,
            original_features: features,
        })
    }

    fn validated(mut self) -> Result<Self, Error> {
        if !(1..=MAX_SECRETS).contains(&self.secrets)
            || !(1..=MAX_ROWS).contains(&self.rows)
            || !(1..=MAX_OUTPUTS).contains(&self.outputs)
            || self.joint.len() != self.secrets * self.rows
            || self.cost.len() != self.rows * self.outputs
            || self.allowed.len() != self.cost.len()
            || !self.budget.is_finite()
            || !(0.0..=1e12).contains(&self.budget)
            || self
                .joint
                .iter()
                .any(|p| !p.is_finite() || *p < 0.0 || (*p > 0.0 && *p < 1e-15))
            || self
                .cost
                .iter()
                .any(|c| !c.is_finite() || !(0.0..=1e12).contains(c))
            || self
                .allowed
                .chunks(self.outputs)
                .any(|row| !row.iter().any(|v| *v))
        {
            return Err(Error::InvalidInput);
        }
        let total: f64 = self.joint.iter().sum();
        if (total - 1.0).abs() > 1e-10 {
            return Err(Error::InvalidInput);
        }
        // The accepted near-unit empirical input is explicitly normalized.
        for p in &mut self.joint {
            *p /= total;
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub iterations: usize,
    pub smoothing: f64,
    /// Required bound on original-objective suboptimality, in bits.
    pub gap_bits: f64,
}

#[derive(Clone, Debug)]
pub struct Certificate {
    pub model: Model,
    pub iterations: usize,
    pub leakage_bits: f64,
    pub expected_cost: f64,
    pub cost_budget: f64,
    /// Mean-MI diagnostics only. For maximum-information channels these fields
    /// do NOT certify the selected objective: use `maximum_information`.
    pub smoothed_objective_bits: f64,
    pub smoothed_lower_bound_bits: f64,
    pub smoothing_bias_bound_bits: f64,
    /// Mean-MI suboptimality bound (the trivial H(S) bound in maximum mode).
    pub original_gap_bound_bits: f64,
    /// These are IEEE-754 numerical diagnostics, not directed-rounding proofs.
    pub rigorous_interval_certificate: bool,
    /// Separate §IV-C entropy-reduction objective; absent for legacy mean MI.
    pub maximum_information: Option<MaximumInformationCertificate>,
}

#[derive(Clone, Debug)]
pub struct Channel {
    problem: Problem,
    probabilities: Vec<f64>,
    row_mass: Vec<f64>,
    certificate: Certificate,
    /// Maximum-information channels certify this exact 53-bit sampler law.
    /// Legacy mean-MI sampling retains its original floating CDF path.
    sampling_thresholds: Option<Vec<u64>>,
}

impl Channel {
    pub fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    /// Complete stochastic matrix for an independently validated actuator.
    pub fn probabilities(&self) -> &[f64] {
        &self.probabilities
    }

    pub fn model(&self) -> Model {
        self.problem.model
    }

    pub fn output_count(&self) -> usize {
        self.problem.outputs
    }

    pub fn observation_count(&self) -> usize {
        self.problem.original_features
    }

    /// Finite 53-bit CSPRNG draw. CDF rounding changes each row's distribution
    /// by at most outputs / 2^53 in exact-arithmetic TV, plus floating CDF
    /// roundoff; this is NOT ideal continuous randomness.
    /// Entropy failure refuses; no deterministic fallback or retry/reset.
    pub fn sample_observable<R: RngCore + CryptoRng>(
        &self,
        observable: usize,
        rng: &mut R,
    ) -> Result<usize, Error> {
        if self.problem.model != Model::LabelBlindExpectedCost {
            return Err(Error::WrongModel);
        }
        self.sample_row(observable, rng)
    }

    /// Explicit theoretical model sampling, which requires the secret label.
    pub fn sample_label_conditional<R: RngCore + CryptoRng>(
        &self,
        secret: usize,
        observable: usize,
        rng: &mut R,
    ) -> Result<usize, Error> {
        if self.problem.model != Model::LabelConditionalWasserstein {
            return Err(Error::WrongModel);
        }
        if secret >= self.problem.secrets || observable >= self.problem.original_features {
            return Err(Error::InvalidInput);
        }
        self.sample_row(secret * self.problem.original_features + observable, rng)
    }

    fn sample_row<R: RngCore + CryptoRng>(&self, row: usize, rng: &mut R) -> Result<usize, Error> {
        if row >= self.problem.rows {
            return Err(Error::InvalidInput);
        }
        if self.row_mass[row] == 0.0 {
            return Err(Error::UnobservedInput);
        }
        let mut bytes = [0_u8; 8];
        rng.try_fill_bytes(&mut bytes)
            .map_err(|_| Error::EntropyUnavailable)?;
        if let Some(thresholds) = &self.sampling_thresholds {
            let u = u64::from_le_bytes(bytes) >> 11;
            return thresholds[row * self.problem.outputs..(row + 1) * self.problem.outputs]
                .iter()
                .position(|t| u < *t)
                .ok_or(Error::NumericalFailure);
        }
        let u = (u64::from_le_bytes(bytes) >> 11) as f64 / ((1_u64 << 53) as f64);
        let total: f64 = self.probabilities
            [row * self.problem.outputs..(row + 1) * self.problem.outputs]
            .iter()
            .sum();
        let mut cumulative = 0.0;
        let mut last = None;
        for y in 0..self.problem.outputs {
            let probability = self.probabilities[row * self.problem.outputs + y];
            if probability > 0.0 {
                last = Some(y);
                cumulative += probability / total;
                if u < cumulative {
                    return Ok(y);
                }
            }
        }
        // Only row-sum roundoff, never an unallowed zero-mass action.
        last.ok_or(Error::NumericalFailure)
    }
}

struct Control<F> {
    deadline: Instant,
    cancelled: F,
}

impl<F: FnMut() -> bool> Control<F> {
    fn check(&mut self) -> Result<(), Error> {
        if (self.cancelled)() {
            return Err(Error::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(Error::Deadline);
        }
        Ok(())
    }
}

/// Bounded Frank-Wolfe with a one-cost row-simplex linear oracle. Failure to
/// reach the requested original-objective gap returns NO channel. Each loop
/// polls cancellation/deadline; no async reactor or native IO is blocked here.
pub fn optimize<F: FnMut() -> bool>(
    problem: Problem,
    limits: Limits,
    deadline: Instant,
    cancelled: F,
) -> Result<Channel, Error> {
    if !(1..=20_000).contains(&limits.iterations)
        || !limits.smoothing.is_finite()
        || !(1e-12..=0.01).contains(&limits.smoothing)
        || !limits.gap_bits.is_finite()
        || !(1e-10..=32.0).contains(&limits.gap_bits)
        || limits.iterations as u64
            * problem.rows as u64
            * problem.outputs as u64
            * problem.secrets as u64
            * 85
            > 200_000_000
    {
        return Err(Error::InvalidInput);
    }
    let mut control = Control {
        deadline,
        cancelled,
    };
    control.check()?;
    let mut row_mass = vec![0.0; problem.rows];
    let mut prior = vec![0.0; problem.secrets];
    for (s, p) in prior.iter_mut().enumerate() {
        for (z, q) in row_mass.iter_mut().enumerate() {
            let mass = problem.joint[s * problem.rows + z];
            *p += mass;
            *q += mass;
        }
    }
    let weights: Vec<_> = problem
        .cost
        .iter()
        .enumerate()
        .map(|(i, d)| row_mass[i / problem.outputs] * d)
        .collect();
    let mut channel = min_cost_channel(&problem, &weights);
    let minimum_cost = dot(&channel, &weights);
    if minimum_cost > problem.budget {
        return Err(Error::Infeasible);
    }
    let tau = limits.smoothing;
    let bias = (-tau * tau.ln() - (1.0 - tau) * (1.0 - tau).ln()
        + tau * (problem.secrets.min(problem.outputs) as f64).ln())
        / LN_2;
    for iteration in 0..limits.iterations {
        control.check()?;
        let (value, gradient) = objective(&problem, &prior, &channel, tau, &mut control)?;
        let oracle = linear_oracle(&problem, &weights, &gradient, minimum_cost, &mut control)?;
        let feasible_linear = dot(&gradient, &channel);
        let raw_lower = value + oracle.lower_value - feasible_linear;
        // A dual lower bound cannot exceed a known feasible linear value or
        // the primal objective. Large common cost offsets can destroy score
        // discrimination/cancel dual arithmetic: refuse, never certify via max(0).
        if !feasible_linear.is_finite()
            || !oracle.lower_value.is_finite()
            || !raw_lower.is_finite()
            || oracle.lower_value > feasible_linear + DUAL_ROUNDOFF_NATS
            || raw_lower > value + DUAL_ROUNDOFF_NATS
        {
            return Err(Error::NumericalFailure);
        }
        // Only the explicitly admitted tiny excess is clamped to the primal;
        // smoothed MI nonnegativity also tightens the numerical lower bound.
        let lower = raw_lower.max(0.0).min(value);
        let gap = (value - lower) / LN_2 + bias;
        if !gap.is_finite() {
            return Err(Error::NumericalFailure);
        }
        if gap <= limits.gap_bits {
            let actual = objective(&problem, &prior, &channel, 0.0, &mut control)?.0 / LN_2;
            let cost = dot(&weights, &channel);
            validate_channel(&problem, &channel, cost)?;
            control.check()?;
            return Ok(Channel {
                certificate: Certificate {
                    model: problem.model,
                    iterations: iteration + 1,
                    leakage_bits: actual,
                    expected_cost: cost,
                    cost_budget: problem.budget,
                    smoothed_objective_bits: value / LN_2,
                    smoothed_lower_bound_bits: lower / LN_2,
                    smoothing_bias_bound_bits: bias,
                    original_gap_bound_bits: gap,
                    rigorous_interval_certificate: false,
                    maximum_information: None,
                },
                problem,
                probabilities: channel,
                row_mass,
                sampling_thresholds: None,
            });
        }
        // Convex line search includes BOTH endpoints: no forced positive step
        // can worsen an already-best feasible iterate.
        let direction: Vec<_> = oracle
            .channel
            .iter()
            .zip(&channel)
            .map(|(v, k)| v - k)
            .collect();
        let mut lo = 0.0;
        let mut hi = 1.0;
        let mut best = channel.clone();
        let mut best_value = value;
        let (end_value, _) = objective(&problem, &prior, &oracle.channel, tau, &mut control)?;
        if end_value < best_value {
            best_value = end_value;
            best.clone_from(&oracle.channel);
        }
        for _ in 0..40 {
            control.check()?;
            let a = (2.0 * lo + hi) / 3.0;
            let b = (lo + 2.0 * hi) / 3.0;
            let ka = interpolate(&channel, &direction, a);
            let kb = interpolate(&channel, &direction, b);
            let va = objective_value(&problem, &prior, &ka, tau, &mut control)?;
            let vb = objective_value(&problem, &prior, &kb, tau, &mut control)?;
            if va < best_value {
                best_value = va;
                best = ka;
            }
            if vb < best_value {
                best_value = vb;
                best = kb;
            }
            if va < vb {
                hi = b;
            } else {
                lo = a;
            }
        }
        channel = best;
    }
    Err(Error::NotConverged)
}

fn validate_channel(p: &Problem, k: &[f64], cost: f64) -> Result<(), Error> {
    if !cost.is_finite() || cost > p.budget + 1e-10 * p.budget.max(1.0) {
        return Err(Error::NumericalFailure);
    }
    for z in 0..p.rows {
        let row = &k[z * p.outputs..(z + 1) * p.outputs];
        if (row.iter().sum::<f64>() - 1.0).abs() > 1e-10 {
            return Err(Error::NumericalFailure);
        }
        for (y, v) in row.iter().enumerate() {
            if !v.is_finite() || *v < 0.0 || (*v > 0.0 && !p.allowed[z * p.outputs + y]) {
                return Err(Error::NumericalFailure);
            }
        }
    }
    Ok(())
}

fn min_cost_channel(p: &Problem, weights: &[f64]) -> Vec<f64> {
    let mut k = vec![0.0; weights.len()];
    for z in 0..p.rows {
        let y = (0..p.outputs)
            .filter(|y| p.allowed[z * p.outputs + y])
            .min_by(|a, b| weights[z * p.outputs + a].total_cmp(&weights[z * p.outputs + b]))
            .expect("validated nonempty allowed row");
        k[z * p.outputs + y] = 1.0;
    }
    k
}

fn dot(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b).map(|(a, b)| a * b).sum()
}
fn interpolate(k: &[f64], d: &[f64], t: f64) -> Vec<f64> {
    k.iter().zip(d).map(|(v, d)| (v + t * d).max(0.0)).collect()
}

fn objective<F: FnMut() -> bool>(
    p: &Problem,
    prior: &[f64],
    k: &[f64],
    tau: f64,
    control: &mut Control<F>,
) -> Result<(f64, Vec<f64>), Error> {
    let mut joint = vec![0.0; p.secrets * p.outputs];
    let mut marginal = vec![0.0; p.outputs];
    for s in 0..p.secrets {
        control.check()?;
        for y in 0..p.outputs {
            let mut mass = tau * prior[s] / p.outputs as f64;
            for z in 0..p.rows {
                mass += (1.0 - tau) * p.joint[s * p.rows + z] * k[z * p.outputs + y];
            }
            joint[s * p.outputs + y] = mass;
            marginal[y] += mass;
        }
    }
    let mut value = 0.0;
    let mut gradient = vec![0.0; k.len()];
    for s in 0..p.secrets {
        control.check()?;
        for y in 0..p.outputs {
            let mass = joint[s * p.outputs + y];
            if mass == 0.0 {
                continue;
            } // includes zero prior and zero output support
            let log_ratio = (mass / (prior[s] * marginal[y])).ln();
            value += mass * log_ratio;
            if tau > 0.0 {
                for z in 0..p.rows {
                    gradient[z * p.outputs + y] +=
                        (1.0 - tau) * p.joint[s * p.rows + z] * log_ratio;
                }
            }
        }
    }
    if !value.is_finite() || gradient.iter().any(|x| !x.is_finite()) {
        return Err(Error::NumericalFailure);
    }
    Ok((value.max(0.0), gradient))
}

// Line search needs the objective, not its gradient. Keep the arithmetic and
// cancellation points identical to objective() while omitting gradient work.
fn objective_value<F: FnMut() -> bool>(
    p: &Problem,
    prior: &[f64],
    k: &[f64],
    tau: f64,
    control: &mut Control<F>,
) -> Result<f64, Error> {
    let mut joint = vec![0.0; p.secrets * p.outputs];
    let mut marginal = vec![0.0; p.outputs];
    for s in 0..p.secrets {
        control.check()?;
        for y in 0..p.outputs {
            let mut mass = tau * prior[s] / p.outputs as f64;
            for z in 0..p.rows {
                mass += (1.0 - tau) * p.joint[s * p.rows + z] * k[z * p.outputs + y];
            }
            joint[s * p.outputs + y] = mass;
            marginal[y] += mass;
        }
    }
    let mut value = 0.0;
    for s in 0..p.secrets {
        control.check()?;
        for y in 0..p.outputs {
            let mass = joint[s * p.outputs + y];
            if mass == 0.0 {
                continue;
            }
            let log_ratio = (mass / (prior[s] * marginal[y])).ln();
            value += mass * log_ratio;
        }
    }
    if !value.is_finite() {
        return Err(Error::NumericalFailure);
    }
    Ok(value.max(0.0))
}

struct Oracle {
    channel: Vec<f64>,
    lower_value: f64,
}

fn penalized(p: &Problem, g: &[f64], w: &[f64], lambda: f64) -> Vec<f64> {
    let score: Vec<_> = g.iter().zip(w).map(|(g, w)| g + lambda * w).collect();
    min_cost_channel(p, &score)
}

fn linear_oracle<F: FnMut() -> bool>(
    p: &Problem,
    w: &[f64],
    g: &[f64],
    minimum: f64,
    control: &mut Control<F>,
) -> Result<Oracle, Error> {
    control.check()?;
    if p.budget == minimum {
        // At the minimum budget, EACH positive-mass row is confined to its
        // minimum-cost face. No infinite Lagrange multiplier is manufactured.
        let mut k = vec![0.0; w.len()];
        for z in 0..p.rows {
            let row_min = (0..p.outputs)
                .filter(|y| p.allowed[z * p.outputs + y])
                .map(|y| w[z * p.outputs + y])
                .min_by(f64::total_cmp)
                .unwrap();
            let y = (0..p.outputs)
                .filter(|y| p.allowed[z * p.outputs + y] && w[z * p.outputs + y] == row_min)
                .min_by(|a, b| g[z * p.outputs + a].total_cmp(&g[z * p.outputs + b]))
                .unwrap();
            k[z * p.outputs + y] = 1.0;
        }
        return Ok(Oracle {
            lower_value: dot(g, &k),
            channel: k,
        });
    }
    let mut high_cost = penalized(p, g, w, 0.0);
    if dot(w, &high_cost) <= p.budget {
        return Ok(Oracle {
            lower_value: dot(g, &high_cost),
            channel: high_cost,
        });
    }
    let mut lo = 0.0;
    let mut hi = 1.0;
    let mut low_cost = penalized(p, g, w, hi);
    for _ in 0..64 {
        control.check()?;
        if dot(w, &low_cost) <= p.budget {
            break;
        }
        lo = hi;
        hi *= 2.0;
        high_cost = low_cost;
        low_cost = penalized(p, g, w, hi);
    }
    if dot(w, &low_cost) > p.budget {
        return Err(Error::NumericalFailure);
    }
    for _ in 0..64 {
        control.check()?;
        let mid = (lo + hi) / 2.0;
        let k = penalized(p, g, w, mid);
        if dot(w, &k) > p.budget {
            lo = mid;
            high_cost = k;
        } else {
            hi = mid;
            low_cost = k;
        }
    }
    let a = dot(w, &high_cost);
    let b = dot(w, &low_cost);
    if !(a > p.budget && b <= p.budget && a > b) {
        return Err(Error::NumericalFailure);
    }
    let mix = ((p.budget - b) / (a - b)).clamp(0.0, 1.0);
    let k: Vec<_> = low_cost
        .iter()
        .zip(&high_cost)
        .map(|(l, h)| (1.0 - mix) * l + mix * h)
        .collect();
    // Any nonnegative lambda yields a VALID dual lower bound even when the
    // finite bisection does not hit the exact breakpoint.
    let best = penalized(p, g, w, hi);
    let lower_value = dot(g, &best) + hi * (dot(w, &best) - p.budget);
    if !lower_value.is_finite() {
        return Err(Error::NumericalFailure);
    }
    Ok(Oracle {
        channel: k,
        lower_value,
    })
}

#[cfg(test)]
#[path = "rate_distortion_tests.rs"]
mod tests;

#[path = "rate_distortion_maximum.rs"]
mod maximum;
pub use maximum::{
    optimize_maximum_information, optimize_minimax_information, MaximumInformationCertificate,
    MaximumInformationLimits, MinimaxInterval, MinimaxLimits,
};
