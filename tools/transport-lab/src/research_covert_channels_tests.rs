use super::*;
#[test]
fn gaussian_actual_ml_recovers_encoded_word() {
    let book = vec![vec![-1.0, -1.0], vec![1.0, 1.0]];
    assert_eq!(decode_awgn(&book, &[0.8, 1.2]).unwrap(), 1);
    assert_eq!(decode_awgn(&book, &[-0.9, -0.6]).unwrap(), 0);
}
#[test]
fn gaussian_malformed_observations_refuse() {
    assert!(decode_awgn(&[vec![1.0]], &[f64::NAN]).is_err());
    assert!(decode_awgn(&[vec![1.0]], &[1.0, 2.0]).is_err());
}
#[test]
fn gaussian_seeded_reproducible_complete_experiment() {
    let c = AwgnConfig {
        trials: 24,
        ..Default::default()
    };
    assert_eq!(
        serde_json::to_vec(&run_awgn(c.clone()).unwrap()).unwrap(),
        serde_json::to_vec(&run_awgn(c).unwrap()).unwrap()
    );
}
#[test]
fn gaussian_noise_zero_nan_and_unbounded_work_refuse() {
    for v in [0.0, f64::NAN, -1.0, 1e-320] {
        assert!(run_awgn(AwgnConfig {
            willie_noise_variance: v,
            ..Default::default()
        })
        .is_err());
    }
    assert!(run_awgn(AwgnConfig {
        channel_uses: 8192,
        messages: 64,
        trials: 1024,
        ..Default::default()
    })
    .is_err());
}
#[test]
fn gaussian_square_root_energy_and_bounded_kl_computed() {
    let a = run_awgn(AwgnConfig {
        channel_uses: 64,
        trials: 8,
        ..Default::default()
    })
    .unwrap();
    let b = run_awgn(AwgnConfig {
        channel_uses: 256,
        trials: 8,
        ..Default::default()
    })
    .unwrap();
    assert_eq!(b.expected_energy, 2.0 * a.expected_energy);
    assert!(a.ensemble_kl_nats > 0.0 && b.ensemble_kl_nats < 0.063);
    assert!(b.mean_h0_log_likelihood_ratio.is_finite());
    assert!(b.observed_mean_energy > 0.0);
}
#[test]
fn gaussian_zero_power_still_runs_actual_decoder_and_detector() {
    let r = run_awgn(AwgnConfig {
        power_coefficient: 0.0,
        trials: 64,
        ..Default::default()
    })
    .unwrap();
    assert_eq!(r.ensemble_kl_nats, 0.0);
    assert_eq!(r.willie_false_alarm.events, 0);
    assert_eq!(r.willie_miss.events, 64);
    assert!(r.bob_block_error.events > 0);
}
#[test]
fn gaussian_strong_channel_actual_reliability_but_not_covert_constant() {
    let r = run_awgn(AwgnConfig {
        power_coefficient: 20.0,
        bob_noise_variance: 0.001,
        trials: 32,
        ..Default::default()
    })
    .unwrap();
    assert_eq!(r.bob_block_error.events, 0);
    assert!(r.ensemble_kl_nats > 10.0);
    assert!(r.willie_empirical_sum_errors < 0.3);
}
#[test]
fn probability_intervals_are_explicit_not_point_guarantees() {
    let e = estimate(1, 10);
    assert!(e.lower_95 <= 0.1 && e.upper_95 >= 0.1);
    assert_eq!(e.trials, 10);
    assert!(e.upper_95 - e.lower_95 > 0.5);
}
#[test]
fn poisson_analytic_kl_and_lrt_are_actual_rate_dependent() {
    assert!((poisson_kl(10.0, 20.0) - (10.0 - 10.0 * 2.0_f64.ln())).abs() < 1e-12);
    assert!(poisson_llr(0, 10.0, 20.0) < 0.0);
    assert!(poisson_llr(30, 10.0, 20.0) > 0.0);
}
#[test]
fn poisson_clock_generation_order_and_finite_horizon() {
    let mut rng = NumericalRng::new(9, b"clock-test");
    let a = poisson_process(&mut rng, 10.0, 2.0).unwrap();
    assert!(!a.is_empty());
    assert!(a.windows(2).all(|w| w[1] > w[0]));
    assert!(*a.last().unwrap() <= 2.0);
}
#[test]
fn causal_timing_starvation_retains_actual_prefix_and_no_future_packet() {
    let r = causal_release(&[1.0, 8.0], &[], 1.0, &[2.0, 3.0], 10);
    assert_eq!(r.failure, Some(TimingFailure::Starvation));
    assert_eq!(r.emitted, vec![2.0]);
}
#[test]
fn causal_capacity_refusal_is_not_success_or_silent_drop() {
    let r = causal_release(&[0.1, 0.2, 0.3], &[], 1.0, &[2.0], 2);
    assert_eq!(r.failure, Some(TimingFailure::Capacity));
    assert!(r.emitted.is_empty());
    assert_eq!(r.peak, 3);
}
#[test]
fn phase_one_capacity_detected_before_final_backlog() {
    let r = causal_release(&[0.1, 0.2, 0.3], &[0.4, 0.5, 0.6], 1.0, &[], 2);
    assert_eq!(r.failure, Some(TimingFailure::Capacity));
    assert_eq!(r.first_sent, 0);
}
#[test]
fn causal_timing_complete_preserves_schedule_and_fifo_identity() {
    let a = [0.1, 0.2, 2.5];
    let plan = [1.2, 2.6];
    let r = causal_release(&a, &[0.5], 1.0, &plan, 4);
    assert!(r.failure.is_none());
    assert_eq!(r.emitted, plan);
    assert_eq!(r.first_sent, 1);
    assert!(r.emitted.iter().zip(&a[1..]).all(|(d, a)| d >= a));
}
#[test]
fn physical_mm1_never_departs_before_arrival_or_previous_service() {
    let mut rng = NumericalRng::new(12, b"queue-test");
    let arrivals = [1.0, 1.01, 1.02, 2.0];
    let d = mm1(&mut rng, &arrivals, 10.0, 0.0);
    assert!(d.iter().zip(arrivals).all(|(d, a)| *d > a));
    assert!(d.windows(2).all(|w| w[1] > w[0]));
    assert!(d[2] > arrivals[2]);
}
#[test]
fn timing_decoder_uses_exponential_service_support_not_nearest_gap() {
    let book = vec![vec![1.0, 2.0], vec![10.0, 20.0]];
    assert_eq!(decode_mm1(&book, &[1.1, 2.1], 10.0, 0.0).unwrap(), 0);
    assert_eq!(decode_mm1(&book, &[10.1, 20.1], 10.0, 0.0).unwrap(), 1);
    assert!(decode_mm1(&book, &[0.1, 0.2], 10.0, 0.0).is_err());
}
#[test]
fn timing_decoder_rejects_wrong_count_order_or_mu() {
    assert!(decode_mm1(&[vec![1.0]], &[2.0, 3.0], 10.0, 0.0).is_err());
    assert!(decode_mm1(&[vec![1.0, 2.0]], &[3.0, 2.0], 10.0, 0.0).is_err());
    assert!(decode_mm1(&[vec![1.0]], &[2.0], 0.0, 0.0).is_err());
}
#[test]
fn discrete_cdf_ties_are_grouped_and_full_reference_is_checked() {
    let check = count_check(&[0, 0, 0, 0], 0.0001, "test");
    assert!(check.empirical_cdf_distance < 0.001);
    assert!((poisson_cdf(0, 1.0) - (-1.0_f64).exp()).abs() < 1e-12);
}
#[test]
fn poisson_fresh_codebook_end_to_end_reproducible_decode_and_insertions() {
    let c = PoissonConfig {
        trials: 24,
        ..Default::default()
    };
    let r = run_poisson(c.clone()).unwrap();
    assert_eq!(r.actual_inserted_packets, r.inserted_payload_bits_recovered);
    assert_eq!(r.inserted_payload_errors, 0);
    assert!(r.completed_codewords > 0);
    assert!(r.forwarded_timing_packets > 0);
    assert!(r.maximum_queue_wait_seconds > 0.0);
    assert_eq!(
        serde_json::to_vec(&r).unwrap(),
        serde_json::to_vec(&run_poisson(c).unwrap()).unwrap()
    );
    assert_eq!(
        r.timing_total_failure.events,
        r.starvation.events
            + r.capacity_refusal.events
            + r.drain_refusal.events
            + r.timing_decode_error_given_complete.unwrap().events
    );
}
#[test]
fn poisson_unstable_queue_invalid_phase_and_capacity_refuse() {
    assert!(run_poisson(PoissonConfig {
        mu: 8.0,
        ..Default::default()
    })
    .is_err());
    assert!(run_poisson(PoissonConfig {
        buffering_fraction: 0.0,
        ..Default::default()
    })
    .is_err());
    assert!(run_poisson(PoissonConfig {
        buffer_capacity: 0,
        ..Default::default()
    })
    .is_err());
    assert!(run_poisson(PoissonConfig {
        lambda: 1e6,
        ..Default::default()
    })
    .is_err());
}
#[test]
fn poisson_small_real_buffer_refusals_are_reported_not_hidden() {
    let r = run_poisson(PoissonConfig {
        buffer_capacity: 1,
        trials: 24,
        ..Default::default()
    })
    .unwrap();
    assert!(r.capacity_refusal.events > 0);
    assert!(r.timing_total_failure.events > 0);
    assert!(
        !r.actually_released_count_distribution
            .within_reference_radius
    );
}
#[test]
fn poisson_no_insertion_coefficient_gives_actual_empty_payload() {
    let r = run_poisson(PoissonConfig {
        covert_coefficient: 0.0,
        trials: 16,
        ..Default::default()
    })
    .unwrap();
    assert_eq!(r.actual_inserted_packets, 0);
    assert_eq!(r.insertion_kl_nats, 0.0);
    assert_eq!(r.insertion_false_alarm.events, 0);
    assert_eq!(r.insertion_miss.events, 16);
}
#[test]
fn serde_rejects_unknown_model_fields_and_preserves_seed() {
    let mut v = serde_json::to_value(AwgnConfig::default()).unwrap();
    v["unexpected"] = true.into();
    assert!(serde_json::from_value::<AwgnConfig>(v).is_err());
    let c: PoissonConfig =
        serde_json::from_value(serde_json::to_value(PoissonConfig::default()).unwrap()).unwrap();
    assert_eq!(c.seed, 29);
}

#[test]
fn uniform_point_diagnostic_checks_actual_empirical_positions() {
    let a = uniform_check(&[0.125, 0.375, 0.625, 0.875], "test").unwrap();
    assert_eq!(a.empirical_cdf_distance, 0.125);
    assert_eq!(a.samples, 4);
    assert!(uniform_check(&[], "test").is_none());
    assert!(
        !uniform_check(&[0.01; 64], "test")
            .unwrap()
            .within_reference_radius
    );
}
#[test]
fn poisson_work_preflight_uses_worst_case_not_mean() {
    assert_eq!(
        run_poisson(PoissonConfig {
            lambda: 0.1,
            mu: 1.0,
            horizon_seconds: 100.0,
            messages: 64,
            trials: 1024,
            ..Default::default()
        })
        .unwrap_err(),
        ModelError::Resource
    );
}

#[test]
fn public_queue_decoder_extreme_finite_service_cannot_admit_minus_infinity() {
    assert_eq!(
        decode_mm1(&[vec![0.0], vec![1.0]], &[1e308], 1e6, 0.0),
        Err(ModelError::Resource)
    );
    assert!(decode_mm1(&[], &[1.0], 1.0, 0.0).is_err());
    assert!(decode_mm1(&vec![vec![0.0]; 65], &[1.0], 1.0, 0.0).is_err());
    assert!(decode_mm1(&[vec![0.0; 8193]], &vec![1.0; 8193], 1.0, 0.0).is_err());
}
#[test]
fn public_gaussian_decoder_owns_dimensions_not_just_experiment_wrapper() {
    assert!(decode_awgn(&vec![vec![0.0]; 65], &[1.0]).is_err());
    assert!(decode_awgn(&[vec![0.0; 8193]], &vec![1.0; 8193]).is_err());
    assert!(decode_awgn(&[vec![-1e308]], &[1e308]).is_err());
}
#[test]
fn poisson_tiny_rate_difference_kl_stays_nonnegative_and_finite() {
    for delta in [0.0, 1e-16, 1e-12, 1e-8] {
        let d = poisson_kl(1.0, 1.0 + delta);
        assert!(d >= 0.0 && d.is_finite());
    }
}

#[test]
fn phase_one_early_capacity_detector_uses_actual_zero_prefix_not_three_planned() {
    let arrivals = [0.1, 0.2, 0.3];
    let planned = [0.4, 0.5, 0.6];
    let flow = causal_release(&arrivals, &planned, 1.0, &[], 2);
    assert_eq!(flow.failure, Some(TimingFailure::Capacity));
    assert_eq!(flow.first_sent, 0);
    let planned_miss = poisson_llr(planned.len(), 3.0, 2.0) <= 0.0;
    let actual_miss = poisson_llr(flow.first_sent, 3.0, 2.0) <= 0.0;
    assert!(planned_miss);
    assert!(!actual_miss);
    assert_eq!(flow.initial_backlog, None);
    assert_eq!(arrivals.len() - planned.len(), 0);
}
#[test]
fn completed_first_phase_backlog_remains_actual_despite_later_starvation() {
    let flow = causal_release(&[0.1, 0.2, 8.0], &[0.5], 1.0, &[2.0, 3.0], 4);
    assert_eq!(flow.initial_backlog, Some(1));
    assert_eq!(flow.first_sent, 1);
    assert_eq!(flow.failure, Some(TimingFailure::Starvation));
    assert_eq!(flow.emitted, vec![2.0]);
}
#[test]
fn experiment_keeps_planned_and_actual_phase_one_statistics_distinct() {
    let r = run_poisson(PoissonConfig {
        buffer_capacity: 1,
        trials: 24,
        ..Default::default()
    })
    .unwrap();
    assert_eq!(r.phase_one_completed_trials, 0);
    assert_eq!(r.mean_initial_backlog, None);
    assert!(r.planned_mean_initial_backlog > 0.0);
    assert_ne!(r.buffering_miss.events, r.planned_buffering_miss.events);
}
