use super::*;
use std::time::Duration;

fn solve(p: Problem, cap: f64) -> Result<Channel, Error> {
    optimize_maximum_information(
        p,
        cap,
        MaximumInformationLimits {
            iterations: 2000,
            cost_gap: 0.02,
        },
        Instant::now() + Duration::from_secs(10),
        || false,
    )
}

fn binary() -> Problem {
    Problem::label_blind(
        2,
        2,
        2,
        vec![0.5, 0.0, 0.0, 0.5],
        vec![0.0, 1.0, 1.0, 0.0],
        vec![true; 4],
        1.0,
    )
    .unwrap()
}

#[test]
fn fixed_cap_minimum_cost_has_independent_binary_analytic_control() {
    let channel = solve(binary(), 0.5).unwrap();
    let c = channel.certificate.maximum_information.as_ref().unwrap();
    // Binary symmetric optimum: h(D)=1-cap. Independently invert entropy.
    let mut lo: f64 = 0.0;
    let mut hi: f64 = 0.5;
    for _ in 0..60 {
        let x = (lo + hi) / 2.0;
        let h = -x * x.log2() - (1.0 - x) * (1.0 - x).log2();
        if h < 0.5 {
            lo = x;
        } else {
            hi = x;
        }
    }
    let optimum = (lo + hi) / 2.0;
    assert!(channel.certificate.expected_cost >= optimum - 1e-9);
    assert!(channel.certificate.expected_cost <= optimum + 0.02);
    assert!(c.cost_lower_bound <= optimum + 1e-9);
    assert!(c.cost_gap_bound <= 0.02);
    assert!(c.worst_output_entropy_reduction_bits <= 0.5);
    assert!(!c.rigorous_interval_certificate);
}

#[test]
fn rare_revealing_output_is_not_hidden_by_mean_or_mass_threshold() {
    let mut p = Problem::label_blind(
        2,
        2,
        2,
        vec![0.499999, 0.000001, 0.5, 0.0],
        vec![0.0; 4],
        vec![true; 4],
        0.0,
    )
    .unwrap();
    let prior = vec![0.5, 0.5];
    let k = vec![1.0, 0.0, 0.0, 1.0];
    let mut control = Control {
        deadline: Instant::now() + Duration::from_secs(1),
        cancelled: || false,
    };
    let mean = objective(&p, &prior, &k, 0.0, &mut control).unwrap().0 / LN_2;
    let (_, _, worst) = perspectives(&p, &prior, &k, 0.5 * LN_2, 0.0, &mut control).unwrap();
    assert!(mean < 0.00001);
    assert!((worst - 1.0).abs() < 1e-10);
    // Minimum-cost constant output is valid, but the revealing kernel is not.
    let channel = solve(p.clone(), 0.5).unwrap();
    assert!(
        channel
            .certificate
            .maximum_information
            .unwrap()
            .worst_output_entropy_reduction_bits
            <= 0.5
    );
    p.model = Model::LabelConditionalWasserstein;
    assert_eq!(solve(p, 0.5).unwrap_err(), Error::WrongModel);
}

#[test]
fn deadlines_cancellation_and_nonconvergence_never_return_channel() {
    let limits = MaximumInformationLimits {
        iterations: 1,
        cost_gap: 1e-8,
    };
    assert_eq!(
        optimize_maximum_information(binary(), 0.5, limits, Instant::now(), || false).unwrap_err(),
        Error::Deadline
    );
    assert_eq!(
        optimize_maximum_information(
            binary(),
            0.5,
            limits,
            Instant::now() + Duration::from_secs(1),
            || true
        )
        .unwrap_err(),
        Error::Cancelled
    );
    assert_eq!(
        optimize_maximum_information(
            binary(),
            0.5,
            limits,
            Instant::now() + Duration::from_secs(1),
            || false
        )
        .unwrap_err(),
        Error::NotConverged
    );
}

#[test]
fn minimax_uses_cap_search_at_original_cost_and_one_reserved_ledger() {
    let mut p = binary();
    p.budget = 0.25;
    let limits = MinimaxLimits {
        iterations_per_cap: 1000,
        maximum_cap_programs: 16,
        leakage_gap_bits: 0.1,
        cost_gap: 0.01,
    };
    let c =
        optimize_minimax_information(p, limits, Instant::now() + Duration::from_secs(15), || {
            false
        })
        .unwrap();
    let interval = c
        .certificate
        .maximum_information
        .unwrap()
        .minimax_interval
        .unwrap();
    let analytic = 1.0 - (-0.25_f64 * 0.25_f64.log2() - 0.75_f64 * 0.75_f64.log2());
    assert!(interval.lower_bits <= analytic + 1e-9);
    assert!(interval.feasible_upper_bits >= analytic - 1e-9);
    assert!(interval.feasible_upper_bits - interval.lower_bits <= 0.1);
    assert!(c.certificate.expected_cost <= 0.25);
    assert!(interval.reserved_iterations <= 16_000);
    let mut calls = 0;
    assert_eq!(
        optimize_minimax_information(
            binary(),
            limits,
            Instant::now() + Duration::from_secs(1),
            || {
                calls += 1;
                calls > 4
            }
        )
        .unwrap_err(),
        Error::Cancelled
    );
}

#[test]
fn exact_quantized_sampler_law_keeps_zero_actions_and_does_not_hide_rare_output() {
    let p = binary();
    let (actual, thresholds) = quantize(&p, &[1.0 - 1e-16, 1e-16, 1.0, 0.0]).unwrap();
    assert!(actual[1] > 0.0);
    assert_eq!(actual[3], 0.0);
    assert_eq!(thresholds[1], 1_u64 << 53);
    assert_eq!(actual[0] + actual[1], 1.0);
    let mut control = Control {
        deadline: Instant::now() + Duration::from_secs(1),
        cancelled: || false,
    };
    assert_eq!(
        perspectives(&p, &[0.5, 0.5], &actual, 0.5 * LN_2, 0.0, &mut control)
            .unwrap()
            .2,
        1.0
    );
}

#[test]
fn mean_solution_with_tiny_leakage_cannot_be_used_as_maximum_cap_fallback() {
    let p = Problem::label_blind(
        2,
        2,
        2,
        vec![0.499999, 0.000001, 0.5, 0.0],
        vec![0.0, 1.0, 1.0, 0.0],
        vec![true; 4],
        0.0,
    )
    .unwrap();
    let mean = optimize(
        p.clone(),
        Limits {
            iterations: 1000,
            smoothing: 1e-8,
            gap_bits: 1e-5,
        },
        Instant::now() + Duration::from_secs(2),
        || false,
    )
    .unwrap();
    assert!(mean.certificate.leakage_bits < 0.00001);
    assert!(mean.certificate.maximum_information.is_none());
    assert_eq!(solve(p, 0.5).unwrap_err(), Error::Infeasible);
}

#[test]
fn zero_prior_unused_outputs_and_asymmetric_alphabets_are_checked() {
    let p = Problem::label_blind(
        3,
        2,
        3,
        vec![0.2, 0.3, 0.3, 0.2, 0.0, 0.0],
        vec![0.0; 6],
        vec![true; 6],
        0.0,
    )
    .unwrap();
    let channel = solve(p, 0.1).unwrap();
    assert!(
        channel
            .certificate
            .maximum_information
            .unwrap()
            .worst_output_entropy_reduction_bits
            <= 0.1
    );
    assert_eq!(channel.probabilities.len(), 6);
    assert_eq!(solve(binary(), f64::NAN).unwrap_err(), Error::InvalidInput);
    let one = Problem::label_blind(
        2,
        2,
        1,
        vec![0.25, 0.0, 0.0, 0.75],
        vec![0.0, 0.0],
        vec![true; 2],
        0.0,
    )
    .unwrap();
    let zero = solve(one, 0.0).unwrap();
    assert_eq!(
        zero.certificate
            .maximum_information
            .unwrap()
            .worst_output_entropy_reduction_bits,
        0.0
    );
}
