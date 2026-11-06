//! Calmon/Fawaz §IV-C, equations 27–34: worst supported-output entropy
//! reduction. This is neither Sibson maximal leakage nor differential privacy.
//! The fixed-cap problem is convex; the ratio-form minimax objective itself
//! must not be mislabeled convex. Numerical certificates are IEEE diagnostics.
use super::*;

#[derive(Clone, Copy, Debug)]
pub struct MaximumInformationLimits {
    pub iterations: usize,
    /// Required absolute minimum-cost dual gap in the input cost units.
    pub cost_gap: f64,
}

#[derive(Clone, Debug)]
pub struct MaximumInformationCertificate {
    pub cap_bits: f64,
    pub worst_output_entropy_reduction_bits: f64,
    pub prior_entropy_bits: f64,
    pub cost_lower_bound: f64,
    pub cost_gap_bound: f64,
    pub maximum_perspective_residual_nats: f64,
    pub normalized_dual_roundoff_allowance: f64,
    pub rigorous_interval_certificate: bool,
    /// Present only after a bounded sequence of certified cap programs.
    pub minimax_interval: Option<MinimaxInterval>,
}

#[derive(Clone, Debug)]
pub struct MinimaxInterval {
    pub lower_bits: f64,
    pub feasible_upper_bits: f64,
    pub cap_programs: usize,
    pub reserved_iterations: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct MinimaxLimits {
    pub iterations_per_cap: usize,
    pub maximum_cap_programs: usize,
    pub leakage_gap_bits: f64,
    pub cost_gap: f64,
}

fn entropy(p: &[f64]) -> f64 {
    -p.iter()
        .filter(|v| **v > 0.0)
        .map(|v| v * v.ln())
        .sum::<f64>()
}

fn reserved_work(p: &Problem, iterations: usize) -> u128 {
    // Covers ≤80 perspective evaluations per iteration, including the
    // output×kernel Jacobian allocation/traversal, plus simplex/quantization.
    iterations as u128 * p.rows as u128 * p.outputs as u128 * (p.secrets + p.outputs) as u128 * 128
}

fn quantize(p: &Problem, k: &[f64]) -> Result<(Vec<f64>, Vec<u64>), Error> {
    let n = 1_u64 << 53;
    let mut actual = vec![0.0; k.len()];
    let mut thresholds = vec![0; k.len()];
    for z in 0..p.rows {
        let total: f64 = k[z * p.outputs..(z + 1) * p.outputs].iter().sum();
        if !total.is_finite() || total <= 0.0 {
            return Err(Error::NumericalFailure);
        }
        let last = (0..p.outputs)
            .rfind(|y| k[z * p.outputs + y] > 0.0)
            .ok_or(Error::NumericalFailure)?;
        let mut cumulative = 0.0;
        let mut previous = 0;
        for y in 0..p.outputs {
            cumulative += k[z * p.outputs + y] / total;
            let threshold = if y >= last {
                n
            } else {
                (cumulative * n as f64)
                    .ceil()
                    .clamp(previous as f64, n as f64) as u64
            };
            actual[z * p.outputs + y] = (threshold - previous) as f64 / n as f64;
            if actual[z * p.outputs + y] > 0.0 && !p.allowed[z * p.outputs + y] {
                return Err(Error::NumericalFailure);
            }
            thresholds[z * p.outputs + y] = threshold;
            previous = threshold;
        }
    }
    Ok((actual, thresholds))
}

/// Each constraint is g_u = δ p(u) + Σ_s q(s,u) ln(q(s,u)/p(u)) ≤ 0.
/// Zero-mass outputs have g=0 and no conditional posterior; no output-mass
/// threshold may hide a rare informative output from final admission.
fn perspectives<F: FnMut() -> bool>(
    p: &Problem,
    prior: &[f64],
    k: &[f64],
    delta: f64,
    tau: f64,
    control: &mut Control<F>,
) -> Result<(Vec<f64>, Vec<f64>, f64), Error> {
    let mut joint = vec![0.0; p.secrets * p.outputs];
    let mut mass = vec![0.0; p.outputs];
    for s in 0..p.secrets {
        control.check()?;
        for y in 0..p.outputs {
            let q = tau * prior[s] / p.outputs as f64
                + (1.0 - tau)
                    * (0..p.rows)
                        .map(|z| p.joint[s * p.rows + z] * k[z * p.outputs + y])
                        .sum::<f64>();
            joint[s * p.outputs + y] = q;
            mass[y] += q;
        }
    }
    let mut g = vec![0.0; p.outputs];
    let mut gradients = vec![0.0; p.outputs * k.len()];
    let mut worst = f64::NEG_INFINITY;
    for y in 0..p.outputs {
        control.check()?;
        if mass[y] == 0.0 {
            continue;
        }
        g[y] = delta * mass[y];
        let mut posterior_entropy = 0.0;
        for s in 0..p.secrets {
            let q = joint[s * p.outputs + y];
            if q == 0.0 {
                continue;
            }
            let log = (q / mass[y]).ln();
            g[y] += q * log;
            posterior_entropy -= q / mass[y] * log;
            if tau > 0.0 {
                for z in 0..p.rows {
                    gradients[y * k.len() + z * p.outputs + y] +=
                        (1.0 - tau) * p.joint[s * p.rows + z] * (delta + log);
                }
            }
        }
        worst = worst.max(entropy(prior) - posterior_entropy);
    }
    if g.iter().chain(gradients.iter()).any(|v| !v.is_finite()) || !worst.is_finite() {
        return Err(Error::NumericalFailure);
    }
    Ok((g, gradients, worst.max(0.0) / LN_2))
}

fn penalized_value<F: FnMut() -> bool>(
    p: &Problem,
    prior: &[f64],
    k: &[f64],
    weights: &[f64],
    delta: f64,
    rho: f64,
    control: &mut Control<F>,
) -> Result<(f64, Vec<f64>), Error> {
    let (g, dg, _) = perspectives(p, prior, k, delta, 1e-12, control)?;
    let mut value = dot(weights, k);
    let mut gradient = weights.to_vec();
    for y in 0..p.outputs {
        let v = g[y].max(0.0);
        value += rho * v * v;
        for i in 0..k.len() {
            gradient[i] += 2.0 * rho * v * dg[y * k.len() + i];
        }
    }
    if !value.is_finite() || gradient.iter().any(|v| !v.is_finite()) {
        return Err(Error::NumericalFailure);
    }
    Ok((value, gradient))
}

/// Bounded continuation of convex squared perspective-violation penalties,
/// minimized by row-simplex Frank–Wolfe. Penalty convergence alone is NEVER
/// admission: independently check every unsmoothed supported output and a
/// nonnegative-multiplier Lagrangian lower bound on the ORIGINAL cap program.
/// Failure to produce both feasible primal and declared cost gap yields no
/// channel. Smoothing is used only for finite gradients, never for emission.
pub fn optimize_maximum_information<F: FnMut() -> bool>(
    problem: Problem,
    cap_bits: f64,
    limits: MaximumInformationLimits,
    deadline: Instant,
    cancelled: F,
) -> Result<Channel, Error> {
    if problem.model != Model::LabelBlindExpectedCost {
        return Err(Error::WrongModel);
    }
    if !cap_bits.is_finite()
        || !(0.0..=16.0).contains(&cap_bits)
        || !(1..=20_000).contains(&limits.iterations)
        || !limits.cost_gap.is_finite()
        || !(1e-8..=1e12).contains(&limits.cost_gap)
        || reserved_work(&problem, limits.iterations) > 200_000_000
    {
        return Err(Error::InvalidInput);
    }
    let mut control = Control {
        deadline,
        cancelled,
    };
    control.check()?;
    let p = &problem;
    let mut prior = vec![0.0; p.secrets];
    let mut row_mass = vec![0.0; p.rows];
    for s in 0..p.secrets {
        for z in 0..p.rows {
            prior[s] += p.joint[s * p.rows + z];
            row_mass[z] += p.joint[s * p.rows + z];
        }
    }
    let h = entropy(&prior);
    let delta = h - cap_bits * LN_2;
    let scale = p
        .cost
        .iter()
        .zip(&p.allowed)
        .filter(|(_, a)| **a)
        .map(|(c, _)| *c)
        .fold(1.0, f64::max);
    let weights: Vec<_> = p
        .cost
        .iter()
        .enumerate()
        .map(|(i, c)| row_mass[i / p.outputs] * c / scale)
        .collect();
    let mut k = min_cost_channel(p, &weights);
    let mut best: Option<(Vec<f64>, f64, f64)> = None;
    // A common allowed output is an exact independent feasible candidate, but
    // not asserted optimal: the same dual-gap requirement still applies.
    for y in 0..p.outputs {
        if (0..p.rows).all(|z| p.allowed[z * p.outputs + y]) {
            let mut candidate = vec![0.0; k.len()];
            for z in 0..p.rows {
                candidate[z * p.outputs + y] = 1.0;
            }
            let (_, _, worst) = perspectives(p, &prior, &candidate, delta, 0.0, &mut control)?;
            let cost = dot(&weights, &candidate);
            if worst <= cap_bits && best.as_ref().is_none_or(|(_, c, _)| cost < *c) {
                best = Some((candidate, cost, worst));
            }
        }
    }
    let margin = cap_bits.min(1e-7) * LN_2;
    let target_delta = delta + margin;
    // Write H(S|U) for the homogeneous conditional entropy of the joint array.
    // Per-column entropy mixing adds nonnegative mixture-indicator entropy
    // whose sum is at most h(tau). The absolute base differences sum to at
    // most 2*tau*ln(|S|). The linear mass differences have L1≤2*tau, hence
    // the δ term contributes at most 2*tau*|δ|. Weighting per-column
    // differences by nonnegative λ is bounded by max λ times this global
    // continuity allowance. No divided posterior approximation certifies q.
    let tau: f64 = 1e-12;
    let smoothing_bias = -tau * tau.ln() - (1.0 - tau) * (1.0 - tau).ln()
        + 2.0 * tau * (delta.abs() + (p.secrets as f64).ln());
    let mut lower = 0.0_f64;
    for iteration in 0..limits.iterations {
        control.check()?;
        let rho = 10.0_f64.powi(1 + (iteration * 8 / limits.iterations) as i32);
        let (g_target, _, _) = perspectives(p, &prior, &k, target_delta, tau, &mut control)?;
        let lambda: Vec<_> = g_target.iter().map(|v| 2.0 * rho * v.max(0.0)).collect();
        let (g, dg, _) = perspectives(p, &prior, &k, delta, tau, &mut control)?;
        let mut gradient = weights.clone();
        let mut lagrangian = dot(&weights, &k);
        for y in 0..p.outputs {
            lagrangian += lambda[y] * g[y];
            for i in 0..k.len() {
                gradient[i] += lambda[y] * dg[y * k.len() + i];
            }
        }
        let oracle = min_cost_channel(p, &gradient);
        let raw = lagrangian + dot(&gradient, &oracle)
            - dot(&gradient, &k)
            - lambda.iter().copied().fold(0.0, f64::max) * smoothing_bias;
        if !raw.is_finite() {
            return Err(Error::NumericalFailure);
        }
        // Explicit conservative IEEE allowance, not an interval theorem.
        // Cost is normalized to ≤1 per action, so this is an absolute unit.
        lower = lower.max((raw - 1e-10).max(0.0));
        let (actual, _) = quantize(p, &k)?;
        let (_, _, worst) = perspectives(p, &prior, &actual, delta, 0.0, &mut control)?;
        let cost = dot(&weights, &actual);
        if worst <= cap_bits && best.as_ref().is_none_or(|(_, c, _)| cost < *c) {
            best = Some((actual, cost, worst));
        }
        if let Some((candidate, cost, _worst)) = &best {
            if lower > *cost + 1e-10 {
                return Err(Error::NumericalFailure);
            }
            let gap = (*cost - lower.min(*cost)) * scale;
            if gap <= limits.cost_gap {
                if lower * scale > p.budget {
                    return Err(Error::Infeasible);
                }
                if *cost * scale <= p.budget {
                    let (actual, thresholds) = quantize(p, candidate)?;
                    let (residual, _, final_worst) =
                        perspectives(p, &prior, &actual, delta, 0.0, &mut control)?;
                    if final_worst > cap_bits {
                        return Err(Error::NumericalFailure);
                    }
                    validate_channel(p, candidate, *cost * scale)?;
                    control.check()?;
                    let actual_mean = objective(p, &prior, candidate, 0.0, &mut control)?.0 / LN_2;
                    control.check()?;
                    return Ok(Channel {
                        probabilities: actual,
                        row_mass,
                        sampling_thresholds: Some(thresholds),
                        certificate: Certificate {
                            model: p.model,
                            iterations: iteration + 1,
                            leakage_bits: actual_mean,
                            expected_cost: *cost * scale,
                            cost_budget: p.budget,
                            smoothed_objective_bits: actual_mean,
                            smoothed_lower_bound_bits: 0.0,
                            smoothing_bias_bound_bits: 0.0,
                            original_gap_bound_bits: h / LN_2,
                            rigorous_interval_certificate: false,
                            maximum_information: Some(MaximumInformationCertificate {
                                cap_bits,
                                worst_output_entropy_reduction_bits: final_worst,
                                prior_entropy_bits: h / LN_2,
                                cost_lower_bound: lower * scale,
                                cost_gap_bound: gap,
                                maximum_perspective_residual_nats: residual
                                    .into_iter()
                                    .fold(f64::NEG_INFINITY, f64::max),
                                rigorous_interval_certificate: false,
                                minimax_interval: None,
                                normalized_dual_roundoff_allowance: 1e-10,
                            }),
                        },
                        problem,
                    });
                }
            }
        }
        if lower * scale > p.budget {
            return Err(Error::Infeasible);
        }
        let (value, gradient) =
            penalized_value(p, &prior, &k, &weights, target_delta, rho, &mut control)?;
        let endpoint = min_cost_channel(p, &gradient);
        let direction: Vec<_> = endpoint.iter().zip(&k).map(|(a, b)| a - b).collect();
        let mut next = k.clone();
        let mut best_value = value;
        let endpoint_value = penalized_value(
            p,
            &prior,
            &endpoint,
            &weights,
            target_delta,
            rho,
            &mut control,
        )?
        .0;
        if endpoint_value < best_value {
            best_value = endpoint_value;
            next = endpoint;
        }
        let mut lo = 0.0;
        let mut hi = 1.0;
        for _ in 0..32 {
            control.check()?;
            let a = (2.0 * lo + hi) / 3.0;
            let b = (lo + 2.0 * hi) / 3.0;
            let ka = interpolate(&k, &direction, a);
            let kb = interpolate(&k, &direction, b);
            let va = penalized_value(p, &prior, &ka, &weights, target_delta, rho, &mut control)?.0;
            let vb = penalized_value(p, &prior, &kb, &weights, target_delta, rho, &mut control)?.0;
            if va < best_value {
                best_value = va;
                next = ka;
            }
            if vb < best_value {
                best_value = vb;
                next = kb;
            }
            if va < vb {
                hi = b;
            } else {
                lo = a;
            }
        }
        k = next;
    }
    Err(Error::NotConverged)
}

/// Equation 27 at a fixed cost budget, via Theorem 2 cap-program line search.
/// One inherited deadline and a single pre-reserved iteration/work ledger span
/// ALL cap programs. Only a certified minimum cost above budget advances the
/// infeasible lower bracket; ambiguous numerical/nonconverged programs refuse.
pub fn optimize_minimax_information<F: FnMut() -> bool>(
    problem: Problem,
    limits: MinimaxLimits,
    deadline: Instant,
    mut cancelled: F,
) -> Result<Channel, Error> {
    let total = limits
        .iterations_per_cap
        .checked_mul(limits.maximum_cap_programs)
        .ok_or(Error::InvalidInput)?;
    let work = reserved_work(&problem, total);
    if !(1..=20_000).contains(&total)
        || !(1..=32).contains(&limits.maximum_cap_programs)
        || !limits.leakage_gap_bits.is_finite()
        || !(1e-8..=16.0).contains(&limits.leakage_gap_bits)
        || work > 200_000_000
    {
        return Err(Error::InvalidInput);
    }
    let mut prior = vec![0.0; problem.secrets];
    for (s, v) in prior.iter_mut().enumerate() {
        *v = problem.joint[s * problem.rows..(s + 1) * problem.rows]
            .iter()
            .sum();
    }
    let mut lower = 0.0;
    let mut upper = entropy(&prior) / LN_2;
    let mut remaining = total;
    let mut best = None;
    for program in 0..limits.maximum_cap_programs {
        if cancelled() {
            return Err(Error::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(Error::Deadline);
        }
        let cap = if program == 0 {
            upper
        } else {
            (lower + upper) / 2.0
        };
        // Charge before entering the inner solve; no fresh timeout or budget.
        remaining = remaining
            .checked_sub(limits.iterations_per_cap)
            .ok_or(Error::InvalidInput)?;
        match optimize_maximum_information(
            problem.clone(),
            cap,
            MaximumInformationLimits {
                iterations: limits.iterations_per_cap,
                cost_gap: limits.cost_gap,
            },
            deadline,
            &mut cancelled,
        ) {
            Ok(channel) => {
                upper = channel
                    .certificate
                    .maximum_information
                    .as_ref()
                    .unwrap()
                    .worst_output_entropy_reduction_bits;
                best = Some(channel);
            }
            Err(Error::Infeasible) => lower = cap,
            Err(e) => return Err(e),
        }
        if upper < lower - 1e-10 {
            return Err(Error::NumericalFailure);
        }
        if upper - lower <= limits.leakage_gap_bits {
            if let Some(mut channel) = best.take() {
                if cancelled() {
                    return Err(Error::Cancelled);
                }
                if Instant::now() >= deadline {
                    return Err(Error::Deadline);
                }
                channel
                    .certificate
                    .maximum_information
                    .as_mut()
                    .unwrap()
                    .minimax_interval = Some(MinimaxInterval {
                    lower_bits: lower,
                    feasible_upper_bits: upper,
                    cap_programs: program + 1,
                    reserved_iterations: total - remaining,
                });
                return Ok(channel);
            }
        }
    }
    Err(Error::NotConverged)
}

#[cfg(test)]
#[path = "rate_distortion_maximum_tests.rs"]
mod tests;
