use super::*;
use rand::Rng;
use rand::{rngs::StdRng, SeedableRng};
use std::time::Duration;

fn limits() -> Limits {
    Limits {
        iterations: 2000,
        smoothing: 1e-8,
        gap_bits: 2e-5,
    }
}

fn solve(p: Problem) -> Channel {
    optimize(
        p,
        limits(),
        Instant::now() + Duration::from_secs(10),
        || false,
    )
    .unwrap()
}

fn binary(budget: f64) -> Problem {
    Problem::label_blind(
        2,
        2,
        2,
        vec![0.5, 0.0, 0.0, 0.5],
        vec![0.0, 1.0, 1.0, 0.0],
        vec![true; 4],
        budget,
    )
    .unwrap()
}

fn h(p: f64) -> f64 {
    if p == 0.0 || p == 1.0 {
        0.0
    } else {
        -p * p.log2() - (1.0 - p) * (1.0 - p).log2()
    }
}

#[test]
fn analytic_binary_curve_is_a_new_randomized_channel_not_policy_selection() {
    for d in [0.0, 0.05, 0.25, 0.5] {
        let c = solve(binary(d));
        let expected = 1.0 - h(d);
        assert!(
            (c.certificate.leakage_bits - expected).abs() < 3e-5,
            "D={d}, actual={:?}, expected={expected}",
            c.certificate
        );
        assert!(c.certificate.expected_cost <= d + 1e-10);
        assert!(c.certificate.original_gap_bound_bits <= limits().gap_bits);
        assert!(!c.certificate.rigorous_interval_certificate);
        if d > 0.0 && d < 0.5 {
            assert!(c.probabilities().iter().any(|p| *p > 0.01 && *p < 0.99));
        }
    }
}

#[test]
fn asymmetric_physical_padding_mask_never_shrinks_input() {
    let p = Problem::label_blind(
        2,
        2,
        2,
        vec![0.5, 0.0, 0.0, 0.5],
        vec![0.0, 1.0, 1.0, 0.0],
        vec![true, true, false, true],
        0.25,
    )
    .unwrap();
    let c = solve(p);
    assert_eq!(c.probabilities()[2], 0.0);
    assert_eq!(c.probabilities()[3], 1.0);
    assert!((c.certificate.leakage_bits - (h(0.75) - 0.5)).abs() < 3e-5);
    let mut rng = StdRng::seed_from_u64(91);
    let mut padded = 0;
    for _ in 0..10_000 {
        padded += c.sample_observable(0, &mut rng).unwrap();
        assert_eq!(c.sample_observable(1, &mut rng).unwrap(), 1);
    }
    assert!((padded as f64 / 10_000.0 - 0.5).abs() < 0.03);
}

#[test]
fn liu_transport_and_label_blind_classes_are_distinct() {
    let metric = vec![0.0, 1.0, 1.0, 0.0];
    let liu = solve(
        Problem::label_conditional_wasserstein(
            vec![0.5, 0.5],
            2,
            vec![0.8, 0.2, 0.2, 0.8],
            metric.clone(),
            0.1,
        )
        .unwrap(),
    );
    let blind = solve(
        Problem::label_blind(
            2,
            2,
            2,
            vec![0.4, 0.1, 0.1, 0.4],
            metric,
            vec![true; 4],
            0.1,
        )
        .unwrap(),
    );
    assert_eq!(liu.model(), Model::LabelConditionalWasserstein);
    assert!((liu.certificate.leakage_bits - (1.0 - h(0.3))).abs() < 3e-5);
    assert!(blind.certificate.leakage_bits > liu.certificate.leakage_bits + 0.02);
    let mut rng = StdRng::seed_from_u64(1);
    assert_eq!(liu.sample_observable(0, &mut rng), Err(Error::WrongModel));
    assert_eq!(
        blind.sample_label_conditional(0, 0, &mut rng),
        Err(Error::WrongModel)
    );
    assert!(liu.sample_label_conditional(0, 0, &mut rng).is_ok());
}

#[test]
fn liu_binary_critical_cost_half_w1_yields_independence() {
    let c = solve(
        Problem::label_conditional_wasserstein(
            vec![0.5, 0.5],
            2,
            vec![0.8, 0.2, 0.2, 0.8],
            vec![0.0, 1.0, 1.0, 0.0],
            0.3,
        )
        .unwrap(),
    );
    assert!(c.certificate.leakage_bits < 3e-5);
    assert!(c.certificate.expected_cost <= 0.3 + 1e-10);
}

#[test]
fn zero_support_does_not_become_nan_or_an_untrained_runtime_fallback() {
    let p = Problem::label_blind(
        3,
        3,
        3,
        vec![0.5, 0.0, 0.0, 0.0, 0.5, 0.0, 0.0, 0.0, 0.0],
        vec![0.0, 1.0, 1.0, 1.0, 0.0, 1.0, 1.0, 1.0, 0.0],
        vec![true; 9],
        0.0,
    )
    .unwrap();
    let c = solve(p);
    assert!((c.certificate.leakage_bits - 1.0).abs() < 1e-12);
    let mut rng = StdRng::seed_from_u64(2);
    assert_eq!(
        c.sample_observable(2, &mut rng),
        Err(Error::UnobservedInput)
    );
    assert_eq!(c.sample_observable(3, &mut rng), Err(Error::InvalidInput));
}

#[test]
fn inadmissible_probabilities_costs_shapes_and_metrics_refuse() {
    for bad in [f64::NAN, f64::INFINITY, -0.1, 1e-300] {
        assert!(Problem::label_blind(1, 1, 1, vec![bad], vec![0.0], vec![true], 0.0).is_err());
    }
    assert!(Problem::label_blind(1, 1, 1, vec![1.0], vec![f64::NAN], vec![true], 0.0).is_err());
    assert!(Problem::label_blind(1, 1, 1, vec![1.0], vec![0.0], vec![false], 0.0).is_err());
    assert!(Problem::label_blind(1, 1, 1, vec![1.0], vec![0.0], vec![true], -1.0).is_err());
    for metric in [
        vec![0.0, 0.0, 0.0, 0.0],
        vec![0.0, 0.5, 1.0, 0.0],
        vec![0.0, f64::NAN, 1.0, 0.0],
    ] {
        assert!(Problem::label_conditional_wasserstein(
            vec![0.5, 0.5],
            2,
            vec![1.0, 0.0, 0.0, 1.0],
            metric,
            0.1
        )
        .is_err());
    }
    assert!(Problem::label_conditional_wasserstein(
        vec![1.0],
        3,
        vec![1.0, 0.0, 0.0],
        vec![0.0, 0.1, 1.0, 0.1, 0.0, 0.1, 1.0, 0.1, 0.0],
        0.1
    )
    .is_err());
}

#[test]
fn infeasible_restriction_refuses_without_manufactured_channel() {
    let p = Problem::label_blind(1, 1, 2, vec![1.0], vec![2.0, 3.0], vec![true; 2], 1.0).unwrap();
    assert_eq!(
        optimize(p, limits(), Instant::now() + Duration::from_secs(1), || {
            false
        })
        .unwrap_err(),
        Error::Infeasible
    );
}

#[test]
fn cancellation_deadline_and_nonconvergence_return_no_policy() {
    assert_eq!(
        optimize(binary(0.2), limits(), Instant::now(), || false).unwrap_err(),
        Error::Deadline
    );
    let mut calls = 0;
    assert_eq!(
        optimize(
            binary(0.2),
            limits(),
            Instant::now() + Duration::from_secs(1),
            || {
                calls += 1;
                calls > 12
            }
        )
        .unwrap_err(),
        Error::Cancelled
    );
    assert!(calls > 12);
    let mut bounded = limits();
    bounded.iterations = 1;
    assert_eq!(
        optimize(
            binary(0.2),
            bounded,
            Instant::now() + Duration::from_secs(1),
            || false
        )
        .unwrap_err(),
        Error::NotConverged
    );
}

struct Broken;
impl RngCore for Broken {
    fn next_u32(&mut self) -> u32 {
        panic!("infallible entropy forbidden")
    }
    fn next_u64(&mut self) -> u64 {
        panic!("infallible entropy forbidden")
    }
    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("infallible entropy forbidden")
    }
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand::Error> {
        Err(rand::Error::new(std::io::Error::other(
            "controlled entropy failure",
        )))
    }
}
impl CryptoRng for Broken {}

#[test]
fn entropy_failure_never_emits_default_action() {
    let c = solve(binary(0.2));
    assert_eq!(
        c.sample_observable(0, &mut Broken),
        Err(Error::EntropyUnavailable)
    );
}

#[test]
fn smoothed_gradient_matches_independent_finite_difference() {
    let p = binary(0.4);
    let prior = [0.5, 0.5];
    let k = [0.8, 0.2, 0.3, 0.7];
    let mut ctrl = Control {
        deadline: Instant::now() + Duration::from_secs(1),
        cancelled: || false,
    };
    let (_, g) = objective(&p, &prior, &k, 0.001, &mut ctrl).unwrap();
    let e = 1e-6;
    let plus = [0.8 + e, 0.2 - e, 0.3, 0.7];
    let minus = [0.8 - e, 0.2 + e, 0.3, 0.7];
    let derivative = (objective(&p, &prior, &plus, 0.001, &mut ctrl).unwrap().0
        - objective(&p, &prior, &minus, 0.001, &mut ctrl).unwrap().0)
        / (2.0 * e);
    assert!((derivative - (g[0] - g[1])).abs() < 1e-7);
}

#[test]
fn lp_dual_bound_and_feasible_mixture_match_brute_binary_linear_program() {
    let p = binary(0.17);
    let weights = [0.0, 0.5, 0.5, 0.0];
    let g = [1.0, -2.0, -1.0, 0.7];
    let mut ctrl = Control {
        deadline: Instant::now() + Duration::from_secs(1),
        cancelled: || false,
    };
    let oracle = linear_oracle(&p, &weights, &g, 0.0, &mut ctrl).unwrap();
    assert!(dot(&oracle.channel, &weights) <= 0.17 + 1e-12);
    let mut brute = f64::INFINITY;
    for a in 0..=340 {
        let a = a as f64 / 1000.0;
        let b = 0.34 - a;
        brute = brute.min(dot(&g, &[1.0 - a, a, b, 1.0 - b]));
    }
    assert!(oracle.lower_value <= brute + 1e-12);
    assert!((dot(&g, &oracle.channel) - brute).abs() < 1e-10);
}

#[test]
fn constant_secret_and_output_have_zero_information_without_epsilon_hacks() {
    let c = solve(Problem::label_blind(1, 1, 1, vec![1.0], vec![0.0], vec![true], 0.0).unwrap());
    assert_eq!(c.certificate.leakage_bits, 0.0);
    assert_eq!(c.probabilities(), &[1.0]);
}

#[test]
fn actual_large_common_cost_offset_cannot_certify_a_reversed_dual_bound() {
    // Valid representable finite input: the original implementation reported
    // lower-primal=0.001630121932bits yet gap=0.000000290181bits.
    let delta = 2_f64.powi(-8);
    let base = 1e12 - delta;
    let p = Problem::label_blind(
        2,
        2,
        2,
        vec![0.5, 0.0, 0.0, 0.5],
        vec![base, 1e12, 1e12, base],
        vec![true; 4],
        base + 0.375 * delta,
    )
    .unwrap();
    let result = optimize(
        p,
        Limits {
            iterations: 1000,
            smoothing: 1e-8,
            gap_bits: 0.001,
        },
        Instant::now() + Duration::from_secs(2),
        || false,
    );
    assert_eq!(result.err(), Some(Error::NumericalFailure));
}

#[test]
fn ordinary_binary_certificate_lower_stays_below_its_primal() {
    let channel = solve(binary(0.125));
    let c = channel.certificate();
    assert!(c.smoothed_lower_bound_bits <= c.smoothed_objective_bits);
    assert!(c.original_gap_bound_bits >= c.smoothing_bias_bound_bits);
    assert!(
        (c.leakage_bits - (1.0 + 0.125_f64 * 0.125_f64.log2() + 0.875_f64 * 0.875_f64.log2()))
            .abs()
            < 1e-6
    );
}

// R2 regression: the value-only line-search path must use the same floating
// objective and cancellation contract as the original value+gradient path.
#[test]
fn seeded_feasible_line_search_values_and_cancellation_match_full_objective() {
    fn prior_and_mass(p: &Problem) -> (Vec<f64>, Vec<f64>) {
        let mut prior = vec![0.0; p.secrets];
        let mut row_mass = vec![0.0; p.rows];
        for s in 0..p.secrets {
            for z in 0..p.rows {
                let mass = p.joint[s * p.rows + z];
                prior[s] += mass;
                row_mass[z] += mass;
            }
        }
        (prior, row_mass)
    }
    fn random_feasible(p: &Problem, rng: &mut StdRng) -> Vec<f64> {
        let mut k = vec![0.0; p.rows * p.outputs];
        for z in 0..p.rows {
            // Alternate interior and one-hot rows to exercise zero output
            // support as well as line-search interiors.
            if z % 2 == 0 {
                let allowed: Vec<_> = (0..p.outputs)
                    .filter(|&y| p.allowed[z * p.outputs + y])
                    .collect();
                k[z * p.outputs + allowed[rng.gen_range(0..allowed.len())]] = 1.0;
            } else {
                let mut sum = 0.0;
                for y in 0..p.outputs {
                    if p.allowed[z * p.outputs + y] {
                        let mass = f64::from(rng.gen_range(1_u32..=100));
                        k[z * p.outputs + y] = mass;
                        sum += mass;
                    }
                }
                for y in 0..p.outputs {
                    k[z * p.outputs + y] /= sum;
                }
            }
        }
        k
    }
    let metric: Vec<f64> = (0..4_usize)
        .flat_map(|z| (0..4_usize).map(move |y| z.abs_diff(y) as f64 / 3.0))
        .collect();
    let dense = vec![0.30, 0.15, 0.04, 0.01, 0.01, 0.04, 0.15, 0.30];
    let sparse = vec![0.30, 0.0, 0.20, 0.0, 0.10, 0.0, 0.40, 0.0];
    let causal: Vec<bool> = (0..4).flat_map(|z| (0..4).map(move |y| y >= z)).collect();
    let cases = [
        Problem::label_blind(2, 4, 4, dense, metric.clone(), causal.clone(), 1.0).unwrap(),
        Problem::label_blind(2, 4, 4, sparse, metric.clone(), causal, 1.0).unwrap(),
        Problem::label_conditional_wasserstein(
            vec![0.5, 0.5],
            4,
            vec![0.6, 0.3, 0.08, 0.02, 0.02, 0.08, 0.3, 0.6],
            metric.clone(),
            1.0,
        )
        .unwrap(),
        Problem::label_conditional_wasserstein(
            vec![0.5, 0.5],
            4,
            vec![0.6, 0.0, 0.4, 0.0, 0.0, 0.2, 0.3, 0.5],
            metric,
            1.0,
        )
        .unwrap(),
    ];
    let mut rng = StdRng::seed_from_u64(0x5eeda11ce);
    let deadline = Instant::now() + Duration::from_secs(10);
    for (case, p) in cases.iter().enumerate() {
        let (prior, row_mass) = prior_and_mass(p);
        let weights: Vec<_> = p
            .cost
            .iter()
            .enumerate()
            .map(|(i, cost)| row_mass[i / p.outputs] * cost)
            .collect();
        for sample in 0..24 {
            let left = random_feasible(p, &mut rng);
            let right = random_feasible(p, &mut rng);
            let direction: Vec<_> = right.iter().zip(&left).map(|(r, l)| r - l).collect();
            for (at, t) in [0.0, 0.001, 0.25, 0.5, 0.999, 1.0].into_iter().enumerate() {
                let channel = interpolate(&left, &direction, t);
                assert!(dot(&channel, &weights) <= p.budget + 1e-12);
                for tau in [0.0, 1e-8] {
                    let mut full_checks = 0;
                    let mut full = Control {
                        deadline,
                        cancelled: || {
                            full_checks += 1;
                            false
                        },
                    };
                    let value = objective(p, &prior, &channel, tau, &mut full).unwrap().0;
                    let mut short_checks = 0;
                    let mut short = Control {
                        deadline,
                        cancelled: || {
                            short_checks += 1;
                            false
                        },
                    };
                    let value_only = objective_value(p, &prior, &channel, tau, &mut short).unwrap();
                    assert_eq!(
                        value.to_bits(),
                        value_only.to_bits(),
                        "case={case} sample={sample} at={at} tau={tau}"
                    );
                    assert_eq!(full_checks, short_checks);
                }
            }
        }
        // Every row can emit the last symbol, leaving the other output
        // symbols at exactly zero support when smoothing is disabled.
        let mut one_output = vec![0.0; p.rows * p.outputs];
        for z in 0..p.rows {
            one_output[z * p.outputs + p.outputs - 1] = 1.0;
        }
        assert!(dot(&one_output, &weights) <= p.budget + 1e-12);
        let mut full = Control {
            deadline,
            cancelled: || false,
        };
        let mut short = Control {
            deadline,
            cancelled: || false,
        };
        assert_eq!(
            objective(p, &prior, &one_output, 0.0, &mut full)
                .unwrap()
                .0
                .to_bits(),
            objective_value(p, &prior, &one_output, 0.0, &mut short)
                .unwrap()
                .to_bits(),
            "case={case} exact-zero output support"
        );
        let channel = random_feasible(p, &mut rng);
        for cancel_at in 1..=2 * p.secrets {
            let mut full_checks = 0;
            let mut full = Control {
                deadline,
                cancelled: || {
                    full_checks += 1;
                    full_checks >= cancel_at
                },
            };
            let full_result = objective(p, &prior, &channel, 1e-8, &mut full);
            let mut short_checks = 0;
            let mut short = Control {
                deadline,
                cancelled: || {
                    short_checks += 1;
                    short_checks >= cancel_at
                },
            };
            let short_result = objective_value(p, &prior, &channel, 1e-8, &mut short);
            assert!(matches!(full_result, Err(Error::Cancelled)));
            assert_eq!(short_result, Err(Error::Cancelled));
            assert_eq!(full_checks, short_checks);
        }
    }
}
