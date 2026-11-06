//! Conditional finite AWGN and Poisson/M/M/1 paper experiments, not IP transports.
//! Numerical seeded randomness is for reproducible simulation, never a session key.
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const SCOPE: &str =
    "finite numerical AWGN/Poisson models; no Internet distribution or covertness guarantee";
const MAX_EVENTS: usize = 8192;
const MAX_WORK: usize = 32_000_000;
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ModelError {
    #[error("invalid covert model: {0}")]
    Invalid(&'static str),
    #[error("finite simulation resource or numerical boundary reached")]
    Resource,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwgnConfig {
    pub seed: u64,
    pub channel_uses: usize,
    pub messages: usize,
    pub trials: usize,
    /// Average Gaussian symbol variance = this coefficient / sqrt(channel_uses).
    pub power_coefficient: f64,
    pub bob_noise_variance: f64,
    pub willie_noise_variance: f64,
}
impl Default for AwgnConfig {
    fn default() -> Self {
        Self {
            seed: 29,
            channel_uses: 256,
            messages: 4,
            trials: 128,
            power_coefficient: 0.5,
            bob_noise_variance: 0.1,
            willie_noise_variance: 1.0,
        }
    }
}
#[derive(Clone, Copy, Debug, Serialize)]
pub struct ErrorEstimate {
    pub events: usize,
    pub trials: usize,
    pub estimate: f64,
    /// Two-sided Hoeffding interval, each marginal has confidence >= 95% in
    /// the ideal independent experiment. Seeded floating simulation is qualified.
    pub lower_95: f64,
    pub upper_95: f64,
}
fn estimate(events: usize, trials: usize) -> ErrorEstimate {
    let p = events as f64 / trials as f64;
    let e = (40.0_f64.ln() / (2.0 * trials as f64)).sqrt();
    ErrorEstimate {
        events,
        trials,
        estimate: p,
        lower_95: (p - e).max(0.0),
        upper_95: (p + e).min(1.0),
    }
}
#[derive(Debug, Serialize)]
pub struct AwgnReport {
    pub scope: &'static str,
    pub config: AwgnConfig,
    pub symbol_power: f64,
    pub expected_energy: f64,
    pub observed_mean_energy: f64,
    pub message_bits: f64,
    pub bits_per_sqrt_n: f64,
    /// Exact analytic D(P0 || P1) for the secret fresh Gaussian-codebook ensemble.
    pub ensemble_kl_nats: f64,
    pub pinsker_sum_error_lower_bound: f64,
    pub gaussian_capacity_bits_reference: f64,
    pub bob_block_error: ErrorEstimate,
    pub willie_false_alarm: ErrorEstimate,
    pub willie_miss: ErrorEstimate,
    pub willie_empirical_sum_errors: f64,
    pub mean_h0_log_likelihood_ratio: f64,
    pub mean_h1_log_likelihood_ratio: f64,
    pub fresh_codebook_per_trial: bool,
    pub numerical_not_exact_distribution_proof: bool,
}
fn positive(x: f64) -> bool {
    x.is_finite() && (1e-9..=1e6).contains(&x)
}
fn dimensions(messages: usize, trials: usize, width: usize) -> Result<(), ModelError> {
    if !(2..=64).contains(&messages)
        || !(1..=1024).contains(&trials)
        || !(1..=MAX_EVENTS).contains(&width)
    {
        return Err(ModelError::Invalid("finite dimensions"));
    }
    if messages
        .checked_mul(trials)
        .and_then(|x| x.checked_mul(width))
        .filter(|x| *x <= MAX_WORK)
        .is_none()
    {
        return Err(ModelError::Resource);
    }
    Ok(())
}
/// Hash-counter pseudorandom *simulation* stream with separate domain/seed.
/// 52-bit midpoint uniforms avoid log(0); floating tails are finite, not exact laws.
struct NumericalRng {
    seed: u64,
    counter: u64,
    domain: &'static [u8],
}
impl NumericalRng {
    fn new(seed: u64, domain: &'static [u8]) -> Self {
        Self {
            seed,
            counter: 0,
            domain,
        }
    }
    fn word(&mut self) -> u64 {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(self.domain);
        h.update(self.seed.to_le_bytes());
        h.update(self.counter.to_le_bytes());
        self.counter += 1;
        let d = h.finalize();
        u64::from_le_bytes(d[..8].try_into().expect("fixed hash prefix"))
    }
    fn uniform(&mut self) -> f64 {
        ((self.word() >> 12) as f64 + 0.5) / (1_u64 << 52) as f64
    }
    fn normal(&mut self) -> f64 {
        (-2.0 * self.uniform().ln()).sqrt() * (std::f64::consts::TAU * self.uniform()).cos()
    }
    fn exp(&mut self, rate: f64) -> f64 {
        -self.uniform().ln() / rate
    }
    fn index(&mut self, n: usize) -> Result<usize, ModelError> {
        let n = n as u64;
        let threshold = n.wrapping_neg() % n;
        for _ in 0..64 {
            let x = self.word();
            if x >= threshold {
                return Ok((x % n) as usize);
            }
        }
        Err(ModelError::Resource)
    }
}
/// Bob's Gaussian maximum likelihood decoder with equal message priors.
pub fn decode_awgn(codebook: &[Vec<f64>], received: &[f64]) -> Result<usize, ModelError> {
    if codebook.is_empty()
        || codebook.len() > 64
        || received.len() > MAX_EVENTS
        || codebook
            .len()
            .checked_mul(received.len())
            .is_none_or(|n| n > MAX_WORK)
    {
        return Err(ModelError::Resource);
    }
    if received.is_empty() || received.iter().any(|x| !x.is_finite()) {
        return Err(ModelError::Invalid("AWGN observation"));
    }
    let mut best = (usize::MAX, f64::INFINITY);
    for (i, c) in codebook.iter().enumerate() {
        if c.len() != received.len() || c.iter().any(|x| !x.is_finite()) {
            return Err(ModelError::Invalid("AWGN codeword"));
        }
        let d: f64 = c.iter().zip(received).map(|(x, y)| (x - y).powi(2)).sum();
        if !d.is_finite() {
            return Err(ModelError::Resource);
        }
        if d < best.1 {
            best = (i, d);
        }
    }
    Ok(best.0)
}
fn awgn_llr(y: &[f64], noise: f64, power: f64) -> f64 {
    -0.5 * y.len() as f64 * (power / noise).ln_1p()
        + 0.5 * (1.0 / noise - 1.0 / (noise + power)) * y.iter().map(|v| v * v).sum::<f64>()
}
pub fn run_awgn(config: AwgnConfig) -> Result<AwgnReport, ModelError> {
    dimensions(config.messages, config.trials, config.channel_uses)?;
    if !positive(config.bob_noise_variance)
        || !positive(config.willie_noise_variance)
        || !config.power_coefficient.is_finite()
        || !(0.0..=1e6).contains(&config.power_coefficient)
    {
        return Err(ModelError::Invalid("nonnegative power/nonzero noise"));
    }
    let p = config.power_coefficient / (config.channel_uses as f64).sqrt();
    let ratio = p / config.willie_noise_variance;
    let kl = 0.5 * config.channel_uses as f64 * (ratio.ln_1p() - ratio / (1.0 + ratio));
    let mut rng = NumericalRng::new(config.seed, b"aegis.covert.awgn.simulation.v1");
    let (mut bob, mut fa, mut miss) = (0, 0, 0);
    let (mut energy, mut l0, mut l1) = (0.0, 0.0, 0.0);
    for _ in 0..config.trials {
        // A new shared-secret codebook every transmission; Willie does not know it.
        let codebook: Vec<Vec<f64>> = (0..config.messages)
            .map(|_| {
                (0..config.channel_uses)
                    .map(|_| p.sqrt() * rng.normal())
                    .collect()
            })
            .collect();
        let m = rng.index(config.messages)?;
        let x = &codebook[m];
        energy += x.iter().map(|v| v * v).sum::<f64>();
        let y: Vec<_> = x
            .iter()
            .map(|v| v + config.bob_noise_variance.sqrt() * rng.normal())
            .collect();
        bob += usize::from(decode_awgn(&codebook, &y)? != m);
        let h0: Vec<_> = (0..config.channel_uses)
            .map(|_| config.willie_noise_variance.sqrt() * rng.normal())
            .collect();
        let h1: Vec<_> = x
            .iter()
            .map(|v| v + config.willie_noise_variance.sqrt() * rng.normal())
            .collect();
        let a = awgn_llr(&h0, config.willie_noise_variance, p);
        let b = awgn_llr(&h1, config.willie_noise_variance, p);
        fa += usize::from(a > 0.0);
        miss += usize::from(b <= 0.0);
        l0 += a;
        l1 += b;
    }
    let n = config.channel_uses as f64;
    let t = config.trials as f64;
    let capacity = 0.5 * n * (p / config.bob_noise_variance).ln_1p() / std::f64::consts::LN_2;
    let bits = (config.messages as f64).log2();
    Ok(AwgnReport {
        scope: SCOPE,
        symbol_power: p,
        expected_energy: n * p,
        observed_mean_energy: energy / t,
        message_bits: bits,
        bits_per_sqrt_n: bits / n.sqrt(),
        ensemble_kl_nats: kl,
        pinsker_sum_error_lower_bound: (1.0 - (kl / 2.0).sqrt()).max(0.0),
        gaussian_capacity_bits_reference: capacity,
        bob_block_error: estimate(bob, config.trials),
        willie_false_alarm: estimate(fa, config.trials),
        willie_miss: estimate(miss, config.trials),
        willie_empirical_sum_errors: (fa + miss) as f64 / t,
        mean_h0_log_likelihood_ratio: l0 / t,
        mean_h1_log_likelihood_ratio: l1 / t,
        fresh_codebook_per_trial: true,
        numerical_not_exact_distribution_proof: true,
        config,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoissonConfig {
    pub seed: u64,
    pub lambda: f64,
    pub mu: f64,
    pub horizon_seconds: f64,
    pub buffering_fraction: f64,
    /// delta = covert_coefficient * sqrt(2 lambda / buffering_time).
    pub covert_coefficient: f64,
    pub messages: usize,
    pub trials: usize,
    /// Finite capacity refusal, never an unreported drop or invented packet.
    pub buffer_capacity: usize,
    pub drain_limit_seconds: f64,
}
impl Default for PoissonConfig {
    fn default() -> Self {
        Self {
            seed: 29,
            lambda: 8.0,
            mu: 24.0,
            horizon_seconds: 20.0,
            buffering_fraction: 0.8,
            covert_coefficient: 0.4,
            messages: 4,
            trials: 128,
            buffer_capacity: 1024,
            drain_limit_seconds: 30.0,
        }
    }
}
#[derive(Debug, Serialize)]
pub struct DistributionCheck {
    pub samples: usize,
    pub empirical_cdf_distance: f64,
    pub dkw_95_reference_radius: f64,
    pub within_reference_radius: bool,
    pub scope: &'static str,
}
#[derive(Debug, Serialize)]
pub struct PoissonReport {
    pub scope: &'static str,
    pub config: PoissonConfig,
    pub insertion_rate: f64,
    pub expected_inserted_packets: f64,
    pub insertion_kl_nats: f64,
    pub insertion_pinsker_sum_error_lower_bound: f64,
    pub insertion_false_alarm: ErrorEstimate,
    pub insertion_miss: ErrorEstimate,
    pub actual_inserted_packets: usize,
    pub inserted_payload_bits_recovered: usize,
    pub inserted_payload_errors: usize,
    pub planned_buffering_rate: f64,
    pub planned_buffering_kl_nats: f64,
    pub buffering_false_alarm: ErrorEstimate,
    pub buffering_miss: ErrorEstimate,
    pub planned_buffering_miss: ErrorEstimate,
    pub buffering_detector_scope: &'static str,
    pub phase_one_completed_trials: usize,
    pub mean_initial_backlog: Option<f64>,
    pub planned_mean_initial_backlog: f64,
    pub mean_unreleased_overt_packets: f64,
    pub starvation: ErrorEstimate,
    pub capacity_refusal: ErrorEstimate,
    pub drain_refusal: ErrorEstimate,
    pub timing_decode_error_given_complete: Option<ErrorEstimate>,
    pub timing_total_failure: ErrorEstimate,
    pub completed_codewords: usize,
    pub forwarded_timing_packets: usize,
    pub maximum_buffer_occupancy: usize,
    pub maximum_queue_wait_seconds: f64,
    pub capacity_nats_per_second_reference: f64,
    pub configured_rate_nats_per_second: f64,
    pub codebook_rate_below_capacity_reference: bool,
    pub planned_count_distribution: DistributionCheck,
    pub planned_one_point_uniform: Option<DistributionCheck>,
    pub actually_released_one_point_uniform: Option<DistributionCheck>,
    pub actually_released_count_distribution: DistributionCheck,
    pub fresh_codebook_per_transmission: bool,
    pub queue_started_empty_not_stationary_burke_claim: bool,
}
fn poisson_process(
    rng: &mut NumericalRng,
    rate: f64,
    horizon: f64,
) -> Result<Vec<f64>, ModelError> {
    let (mut t, mut out) = (0.0, Vec::new());
    for _ in 0..=MAX_EVENTS {
        t += rng.exp(rate);
        if t > horizon {
            return Ok(out);
        }
        if out.len() == MAX_EVENTS {
            return Err(ModelError::Resource);
        }
        out.push(t);
    }
    Err(ModelError::Resource)
}
fn poisson_llr(count: usize, mean0: f64, mean1: f64) -> f64 {
    count as f64 * (mean1 / mean0).ln() - (mean1 - mean0)
}
fn poisson_kl(mean0: f64, mean1: f64) -> f64 {
    let delta = (mean1 - mean0) / mean0;
    (mean0 * (delta - delta.ln_1p())).max(0.0) // roundoff cannot become a negative KL
}
fn poisson_cdf(k: usize, mean: f64) -> f64 {
    // Log probabilities remain usable beyond exp(-mean) underflow.
    let (mut factorial, mut sum) = (0.0, 0.0);
    for i in 0..=k {
        if i > 0 {
            factorial += (i as f64).ln();
        }
        sum += (-mean + i as f64 * mean.ln() - factorial).exp();
    }
    sum.min(1.0)
}
fn count_check(counts: &[usize], mean: f64, scope: &'static str) -> DistributionCheck {
    let mut sorted = counts.to_vec();
    sorted.sort_unstable();
    let n = sorted.len() as f64;
    let mut d: f64 = 0.0;
    let mut i = 0;
    while i < sorted.len() {
        let k = sorted[i];
        let mut j = i + 1;
        while j < sorted.len() && sorted[j] == k {
            j += 1;
        }
        let c = poisson_cdf(k, mean);
        let left = if k == 0 {
            0.0
        } else {
            poisson_cdf(k - 1, mean)
        };
        d = d
            .max((c - j as f64 / n).abs())
            .max((left - i as f64 / n).abs());
        i = j;
    }
    let e = (40.0_f64.ln() / (2.0 * n)).sqrt();
    DistributionCheck {
        samples: counts.len(),
        empirical_cdf_distance: d,
        dkw_95_reference_radius: e,
        within_reference_radius: d <= e,
        scope,
    }
}
fn uniform_check(points: &[f64], scope: &'static str) -> Option<DistributionCheck> {
    if points.is_empty() {
        return None;
    }
    let mut sorted = points.to_vec();
    sorted.sort_by(f64::total_cmp);
    let n = sorted.len() as f64;
    let d = sorted
        .iter()
        .enumerate()
        .map(|(i, &x)| (x - i as f64 / n).abs().max((x - (i + 1) as f64 / n).abs()))
        .fold(0.0, f64::max);
    let e = (40.0_f64.ln() / (2.0 * n)).sqrt();
    Some(DistributionCheck {
        samples: points.len(),
        empirical_cdf_distance: d,
        dkw_95_reference_radius: e,
        within_reference_radius: d <= e,
        scope,
    })
}
/// Physical FIFO exponential-service queue. Every departure >= its arrival and
/// previous departure. The empty initial state is deliberately retained.
fn mm1(rng: &mut NumericalRng, arrivals: &[f64], mu: f64, initial: f64) -> Vec<f64> {
    let mut prev = initial;
    arrivals
        .iter()
        .map(|a| {
            prev = prev.max(*a) + rng.exp(mu);
            prev
        })
        .collect()
}
/// Conditional FIFO service likelihood with observed previous-phase departure.
/// Complete packet-count/boundary observation is required; missing counts have
/// zero likelihood. This is not a decoder for loss/reordering/quantized IP time.
pub fn decode_mm1(
    codebook: &[Vec<f64>],
    departures: &[f64],
    mu: f64,
    previous_departure: f64,
) -> Result<usize, ModelError> {
    if codebook.is_empty()
        || codebook.len() > 64
        || departures.len() > MAX_EVENTS
        || codebook
            .len()
            .checked_mul(departures.len())
            .is_none_or(|n| n > MAX_WORK)
        || codebook.iter().any(|c| c.len() > MAX_EVENTS)
    {
        return Err(ModelError::Resource);
    }
    if !positive(mu)
        || !previous_departure.is_finite()
        || previous_departure < 0.0
        || departures.iter().any(|x| !x.is_finite())
        || departures.windows(2).any(|w| w[1] < w[0])
    {
        return Err(ModelError::Invalid("queue observation"));
    }
    let mut best = None;
    for (i, c) in codebook.iter().enumerate() {
        if c.iter().any(|x| !x.is_finite() || *x < 0.0) || c.windows(2).any(|w| w[1] < w[0]) {
            return Err(ModelError::Invalid("timing codebook"));
        }
        if c.len() != departures.len() {
            continue;
        }
        let mut prev = previous_departure;
        let mut ll = 0.0;
        let mut possible = true;
        for (&a, &d) in c.iter().zip(departures) {
            let service = d - prev.max(a);
            if service < 0.0 {
                possible = false;
                break;
            }
            ll += mu.ln() - mu * service;
            if !service.is_finite() || !ll.is_finite() {
                return Err(ModelError::Resource);
            }
            prev = d;
        }
        if possible && best.is_none_or(|(_, v)| ll > v) {
            best = Some((i, ll));
        }
    }
    best.map(|(i, _)| i)
        .ok_or(ModelError::Invalid("no possible queue codeword"))
}
#[derive(Debug, PartialEq, Eq)]
enum TimingFailure {
    Starvation,
    Capacity,
}
struct CausalRelease {
    /// Defined only once the actual first phase reaches its public end.
    initial_backlog: Option<usize>,
    first_sent: usize,
    emitted: Vec<f64>,
    peak: usize,
    failure: Option<TimingFailure>,
}
/// Event-by-event causal admission. Failed prefixes remain observed emissions;
/// no retrospective deletion, re-timing or fill-in is used to improve statistics.
fn causal_release(
    arrivals: &[f64],
    first: &[f64],
    origin: f64,
    plan: &[f64],
    capacity: usize,
) -> CausalRelease {
    let (mut arrived, mut sent, mut peak) = (0, 0, 0);
    for &t in first {
        while arrived < arrivals.len() && arrivals[arrived] <= t {
            arrived += 1;
            peak = peak.max(arrived - sent);
            if arrived - sent > capacity {
                return CausalRelease {
                    initial_backlog: None,
                    first_sent: sent,
                    emitted: Vec::new(),
                    peak,
                    failure: Some(TimingFailure::Capacity),
                };
            }
        }
        // Scale-up scheduling guarantees at least the corresponding original packet.
        if sent == arrived {
            return CausalRelease {
                initial_backlog: None,
                first_sent: sent,
                emitted: Vec::new(),
                peak,
                failure: Some(TimingFailure::Starvation),
            };
        }
        sent += 1;
    }
    let mut emitted = Vec::new();
    while arrived < arrivals.len() && arrivals[arrived] <= origin {
        arrived += 1;
        peak = peak.max(arrived - sent);
        if arrived - sent > capacity {
            return CausalRelease {
                initial_backlog: None,
                first_sent: first.len(),
                emitted,
                peak,
                failure: Some(TimingFailure::Capacity),
            };
        }
    }
    let initial_backlog = arrived - sent;
    for &t in plan {
        while arrived < arrivals.len() && arrivals[arrived] <= t {
            arrived += 1;
            peak = peak.max(arrived - sent);
            if arrived - sent > capacity {
                return CausalRelease {
                    initial_backlog: Some(initial_backlog),
                    first_sent: first.len(),
                    emitted,
                    peak,
                    failure: Some(TimingFailure::Capacity),
                };
            }
        }
        if sent == arrived {
            return CausalRelease {
                initial_backlog: Some(initial_backlog),
                first_sent: first.len(),
                emitted,
                peak,
                failure: Some(TimingFailure::Starvation),
            };
        }
        sent += 1;
        emitted.push(t);
    }
    // Account for arrivals through the full public phase even after final symbol.
    while arrived < arrivals.len() {
        arrived += 1;
        peak = peak.max(arrived - sent);
        if arrived - sent > capacity {
            return CausalRelease {
                initial_backlog: Some(initial_backlog),
                first_sent: first.len(),
                emitted,
                peak,
                failure: Some(TimingFailure::Capacity),
            };
        }
    }
    CausalRelease {
        initial_backlog: Some(initial_backlog),
        first_sent: first.len(),
        emitted,
        peak,
        failure: None,
    }
}
pub fn run_poisson(config: PoissonConfig) -> Result<PoissonReport, ModelError> {
    if !positive(config.lambda)
        || !positive(config.mu)
        || config.mu <= config.lambda
        || !positive(config.horizon_seconds)
        || !positive(config.drain_limit_seconds)
        || !config.buffering_fraction.is_finite()
        || !(0.0..1.0).contains(&config.buffering_fraction)
        || config.buffering_fraction == 0.0
        || !config.covert_coefficient.is_finite()
        || !(0.0..1.0).contains(&config.covert_coefficient)
        || config.buffer_capacity == 0
        || config.buffer_capacity > MAX_EVENTS
        || config.lambda * config.horizon_seconds > 1024.0
    {
        return Err(ModelError::Invalid("Poisson/MM1 parameters"));
    }
    let t1 = config.horizon_seconds * config.buffering_fraction;
    let t2 = config.horizon_seconds - t1;
    if t1 < 1e-6 || t2 < 1e-6 {
        return Err(ModelError::Invalid("phase numerical resolution"));
    }
    let delta = config.covert_coefficient * (2.0 * config.lambda / t1).sqrt();
    if delta >= config.lambda {
        return Err(ModelError::Invalid("buffering delta must be below lambda"));
    }
    // Preflight worst-case retained event loops, not their expected Poisson size.
    dimensions(config.messages, config.trials, MAX_EVENTS)?;
    let insert = config.covert_coefficient * (2.0 * config.lambda / config.horizon_seconds).sqrt();
    let mut rng = NumericalRng::new(config.seed, b"aegis.covert.poisson.simulation.v1");
    let (mut fa, mut miss, mut bfa, mut bmiss, mut inserted, mut decoded_bits, mut bit_errors) =
        (0, 0, 0, 0, 0, 0, 0);
    let (mut starving, mut capped, mut drained, mut completed, mut errors, mut forwarded, mut peak) =
        (0, 0, 0, 0, 0, 0, 0);
    let (
        mut planned_backlog,
        mut backlog,
        mut phase_one_completed,
        mut planned_bmiss,
        mut pending,
        mut maxwait,
    ) = (0.0, 0.0, 0usize, 0usize, 0.0, 0.0_f64);
    let (mut plans, mut released) = (Vec::new(), Vec::new());
    let (mut planned_points, mut released_points) = (Vec::new(), Vec::new());
    for _ in 0..config.trials {
        let overt = poisson_process(&mut rng, config.lambda, config.horizon_seconds)?;
        let additions = poisson_process(&mut rng, insert, config.horizon_seconds)?;
        // Bob's authentication oracle is an explicit Scenario1 model assumption.
        // Actual merge preserves every overt packet; each inserted packet carries
        // one bit, which Bob separates by its origin label and recovers exactly.
        let mut merged: Vec<_> = overt.iter().map(|&t| (t, None)).collect();
        let encoded_bits: Vec<_> = (0..additions.len())
            .map(|_| rng.index(2))
            .collect::<Result<_, _>>()?;
        for (&t, &bit) in additions.iter().zip(&encoded_bits) {
            merged.push((t, Some(bit)));
        }
        merged.sort_by(|a, b| a.0.total_cmp(&b.0));
        let bits: Vec<_> = merged.iter().filter_map(|(_, b)| *b).collect();
        decoded_bits += bits.len();
        inserted += additions.len();
        bit_errors += bits
            .iter()
            .zip(&encoded_bits)
            .filter(|(a, b)| a != b)
            .count()
            + bits.len().abs_diff(encoded_bits.len());
        fa += usize::from(
            poisson_llr(
                overt.len(),
                config.lambda * config.horizon_seconds,
                (config.lambda + insert) * config.horizon_seconds,
            ) > 0.0,
        );
        miss += usize::from(
            poisson_llr(
                merged.len(),
                config.lambda * config.horizon_seconds,
                (config.lambda + insert) * config.horizon_seconds,
            ) <= 0.0,
        );
        let slower = config.lambda - delta;
        let first: Vec<_> = overt
            .iter()
            .map(|a| a * config.lambda / slower)
            .take_while(|t| *t <= t1)
            .collect();
        let h0_count = overt.partition_point(|t| *t <= t1);
        bfa += usize::from(poisson_llr(h0_count, config.lambda * t1, slower * t1) > 0.0);
        planned_bmiss +=
            usize::from(poisson_llr(first.len(), config.lambda * t1, slower * t1) <= 0.0);
        planned_backlog += (h0_count - first.len()) as f64;
        let book: Vec<Vec<f64>> = (0..config.messages)
            .map(|_| {
                poisson_process(&mut rng, config.lambda, t2)
                    .map(|c| c.into_iter().map(|t| t + t1).collect())
            })
            .collect::<Result<_, _>>()?;
        let m = rng.index(config.messages)?;
        plans.push(book[m].len());
        if !book[m].is_empty() {
            planned_points.push((book[m][rng.index(book[m].len())?] - t1) / t2);
        }
        let flow = causal_release(&overt, &first, t1, &book[m], config.buffer_capacity);
        bmiss += usize::from(poisson_llr(flow.first_sent, config.lambda * t1, slower * t1) <= 0.0);
        if let Some(initial) = flow.initial_backlog {
            backlog += initial as f64;
            phase_one_completed += 1;
        }
        peak = peak.max(flow.peak);
        forwarded += flow.emitted.len();
        released.push(flow.emitted.len());
        pending += (overt.len() - flow.first_sent - flow.emitted.len()) as f64;
        if !flow.emitted.is_empty() {
            released_points.push((flow.emitted[rng.index(flow.emitted.len())?] - t1) / t2);
        }
        let d1 = mm1(&mut rng, &first[..flow.first_sent], config.mu, 0.0);
        let prev = d1.last().copied().unwrap_or(0.0);
        let d2 = mm1(&mut rng, &flow.emitted, config.mu, prev);
        maxwait = maxwait.max(
            d1.iter()
                .zip(&first)
                .chain(d2.iter().zip(&flow.emitted))
                .map(|(d, a)| d - a)
                .fold(0.0, f64::max),
        );
        match flow.failure {
            Some(TimingFailure::Starvation) => {
                starving += 1;
            }
            Some(TimingFailure::Capacity) => {
                capped += 1;
            }
            None => {
                if d2.last().copied().unwrap_or(prev)
                    > config.horizon_seconds + config.drain_limit_seconds
                {
                    drained += 1;
                    continue;
                }
                completed += 1;
                errors += usize::from(decode_mm1(&book, &d2, config.mu, prev)? != m);
            }
        }
    }
    let cap = config.lambda * (config.mu / config.lambda).ln();
    let rate = (config.messages as f64).ln() / t2;
    Ok(PoissonReport {
        scope: SCOPE,
        insertion_rate: insert,
        expected_inserted_packets: insert * config.horizon_seconds,
        insertion_kl_nats: poisson_kl(
            config.lambda * config.horizon_seconds,
            (config.lambda + insert) * config.horizon_seconds,
        ),
        insertion_pinsker_sum_error_lower_bound: (1.0
            - (poisson_kl(
                config.lambda * config.horizon_seconds,
                (config.lambda + insert) * config.horizon_seconds,
            ) / 2.0)
                .sqrt())
        .max(0.0),
        insertion_false_alarm: estimate(fa, config.trials),
        insertion_miss: estimate(miss, config.trials),
        actual_inserted_packets: inserted,
        inserted_payload_bits_recovered: decoded_bits,
        inserted_payload_errors: bit_errors,
        planned_buffering_rate: config.lambda - delta,
        planned_buffering_kl_nats: poisson_kl((config.lambda - delta) * t1, config.lambda * t1),
        buffering_false_alarm: estimate(bfa, config.trials),
        buffering_miss: estimate(bmiss, config.trials),
        planned_buffering_miss: estimate(planned_bmiss,config.trials),
        buffering_detector_scope: "Poisson-reference count LRT applied to actual prefixes; not optimal for refusal-distorted H1",
        phase_one_completed_trials: phase_one_completed,
        mean_initial_backlog: if phase_one_completed==0 {None}else{Some(backlog/phase_one_completed as f64)},
        planned_mean_initial_backlog: planned_backlog/config.trials as f64,
        mean_unreleased_overt_packets: pending / config.trials as f64,
        starvation: estimate(starving, config.trials),
        capacity_refusal: estimate(capped, config.trials),
        drain_refusal: estimate(drained, config.trials),
        timing_decode_error_given_complete: if completed == 0 {
            None
        } else {
            Some(estimate(errors, completed))
        },
        timing_total_failure: estimate(starving + capped + drained + errors, config.trials),
        completed_codewords: completed,
        forwarded_timing_packets: forwarded,
        maximum_buffer_occupancy: peak,
        maximum_queue_wait_seconds: maxwait,
        capacity_nats_per_second_reference: cap,
        configured_rate_nats_per_second: rate,
        codebook_rate_below_capacity_reference: rate < cap,
        planned_one_point_uniform: uniform_check(&planned_points,"one randomly chosen point per nonempty fresh codeword; independent ideal trials"),
        actually_released_one_point_uniform: uniform_check(&released_points,"one point from each actual nonempty prefix including refusal; no success-conditioning guarantee"),
        planned_count_distribution: count_check(
            &plans,
            config.lambda * t2,
            "unconditioned fresh Poisson codeword counts across trials",
        ),
        actually_released_count_distribution: count_check(
            &released,
            config.lambda * t2,
            "includes observed refusal; not a conditional success-only Poisson guarantee",
        ),
        fresh_codebook_per_transmission: true,
        queue_started_empty_not_stationary_burke_claim: true,
        config,
    })
}
#[cfg(test)]
#[path = "research_covert_channels_tests.rs"]
mod tests;
