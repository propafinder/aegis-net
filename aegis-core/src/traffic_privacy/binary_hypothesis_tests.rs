use super::*;

fn samples(counts: [&[usize]; 2]) -> Vec<LeakageSample> {
    counts
        .iter()
        .enumerate()
        .flat_map(|(label, row)| {
            row.iter().enumerate().flat_map(move |(feature, count)| {
                (0..*count).map(move |_| LeakageSample {
                    label,
                    feature,
                    added_bytes: 0,
                    added_delay_ms: 0.0,
                })
            })
        })
        .collect()
}

fn report(counts: [&[usize]; 2]) -> BinaryHypothesisDiagnostic {
    diagnose(
        &samples(counts),
        &Alphabet {
            labels: 2,
            features: counts[0].len(),
        },
    )
    .unwrap()
}

#[test]
fn known_binary_distances_use_natural_logs_and_distinct_directions() {
    let r = report([&[2, 2], &[3, 1]]);
    assert_eq!(r.empirical_total_variation, Some(0.25));
    assert!((r.kl_h0_to_h1.empirical_nats.unwrap() - 0.5 * (4.0_f64 / 3.0).ln()).abs() < 1e-12);
    let reverse = 0.75 * 1.5_f64.ln() + 0.25 * 0.5_f64.ln();
    assert!((r.kl_h1_to_h0.empirical_nats.unwrap() - reverse).abs() < 1e-12);
    let symmetric = report([&[3, 1], &[1, 3]]);
    assert_eq!(symmetric.empirical_total_variation, Some(0.5));
    assert!((symmetric.kl_h0_to_h1.empirical_nats.unwrap() - 0.5 * 3.0_f64.ln()).abs() < 1e-12);
}

#[test]
fn absent_reference_support_is_unknown_without_smoothing_or_infinity() {
    let separated = report([&[2, 0], &[0, 2]]);
    assert_eq!(separated.empirical_total_variation, Some(1.0));
    for kl in [&separated.kl_h0_to_h1, &separated.kl_h1_to_h0] {
        assert_eq!(
            kl.status,
            DistanceStatus::UnknownZeroObservedReferenceSupport
        );
        assert_eq!(kl.empirical_nats, None);
        assert_eq!(kl.zero_observed_reference_bins, 1);
    }
    assert!(!separated.smoothing_applied);
    let one_way = report([&[2, 0, 0], &[1, 1, 0]]);
    assert_eq!(
        one_way.kl_h0_to_h1.status,
        DistanceStatus::KnownEmpiricalValue
    );
    assert_eq!(one_way.kl_h0_to_h1.empirical_nats, Some(2.0_f64.ln()));
    assert_eq!(one_way.kl_h1_to_h0.empirical_nats, None);
    assert_eq!(one_way.observed_union_feature_bins, 2);
    assert!(!one_way.population_distance_established);
}

#[test]
fn insufficient_observations_refuse_all_distances_including_empty_input() {
    for counts in [[&[0, 0][..], &[0, 0][..]], [&[1, 0][..], &[4, 4][..]]] {
        let r = report(counts);
        assert_eq!(r.status, DistanceStatus::UnknownInsufficientObservations);
        assert_eq!(r.empirical_total_variation, None);
        assert_eq!(r.kl_h0_to_h1.empirical_nats, None);
        assert_eq!(r.kl_h1_to_h0.empirical_nats, None);
    }
}

#[test]
fn normalizes_unequal_class_sizes_and_ignores_jointly_unobserved_bins() {
    let r = report([&[5, 5, 0], &[2, 2, 0]]);
    assert_eq!(r.observations_by_hypothesis, [10, 4]);
    assert_eq!(r.empirical_total_variation, Some(0.0));
    assert_eq!(r.kl_h0_to_h1.empirical_nats, Some(0.0));
    assert_eq!(r.kl_h1_to_h0.empirical_nats, Some(0.0));
    assert_eq!(r.observed_union_feature_bins, 2);
    assert!(!r.whole_flow_privacy_guarantee);
    assert!(!r.awgn_or_square_root_guarantee);
    assert!(!r.statistical_independence_proven);
}

#[test]
fn bin_and_row_permutations_preserve_only_these_histogram_diagnostics() {
    let a = report([&[3, 1], &[1, 3]]);
    let b = report([&[1, 3], &[3, 1]]);
    assert_eq!(a.empirical_total_variation, b.empirical_total_variation);
    assert_eq!(a.kl_h0_to_h1.empirical_nats, b.kl_h0_to_h1.empirical_nats);
    let mut rows = samples([&[3, 1], &[1, 3]]);
    rows.reverse();
    let r = diagnose(
        &rows,
        &Alphabet {
            labels: 2,
            features: 2,
        },
    )
    .unwrap();
    assert_eq!(a.empirical_total_variation, r.empirical_total_variation);
}

#[test]
fn rejects_invalid_binary_alphabets_samples_and_resource_budgets() {
    for alphabet in [
        Alphabet {
            labels: 1,
            features: 2,
        },
        Alphabet {
            labels: 3,
            features: 2,
        },
        Alphabet {
            labels: 2,
            features: 0,
        },
        Alphabet {
            labels: 2,
            features: 257,
        },
    ] {
        assert!(diagnose(&[], &alphabet).is_err());
    }
    let alphabet = Alphabet {
        labels: 2,
        features: 2,
    };
    for (label, feature) in [(2, 0), (0, 2)] {
        let invalid = [LeakageSample {
            label,
            feature,
            added_bytes: 0,
            added_delay_ms: 0.0,
        }];
        assert!(diagnose(&invalid, &alphabet).is_err());
    }
    let too_many = vec![
        LeakageSample {
            label: 0,
            feature: 0,
            added_bytes: 0,
            added_delay_ms: 0.0
        };
        MAX_SAMPLES + 1
    ];
    assert!(diagnose(&too_many, &alphabet).is_err());
}

#[test]
fn analytic_error_diagnostics_use_unweighted_errors_and_directional_pinsker() {
    let symmetric = report([&[3, 1], &[1, 3]]);
    assert_eq!(symmetric.empirical_plugin_minimum_sum_error, Some(0.5));
    let expected = 1.0 - (0.25 * 3.0_f64.ln()).sqrt();
    for direction in [&symmetric.kl_h0_to_h1, &symmetric.kl_h1_to_h0] {
        let lower = direction.empirical_pinsker_minimum_sum_error.unwrap();
        assert!((lower - expected).abs() < 1e-12);
        assert!(lower <= symmetric.empirical_plugin_minimum_sum_error.unwrap());
    }
    // Class counts are normalized separately. This is not the 1:3 prior
    // Bayes risk; changing the class multiplicity leaves sum-error unchanged.
    let imbalanced = report([&[3, 1], &[3, 9]]);
    assert_eq!(imbalanced.empirical_plugin_minimum_sum_error, Some(0.5));
    assert_eq!(
        imbalanced.kl_h0_to_h1.empirical_pinsker_minimum_sum_error,
        symmetric.kl_h0_to_h1.empirical_pinsker_minimum_sum_error
    );
    let asymmetric = report([&[2, 2], &[3, 1]]);
    assert_ne!(
        asymmetric.kl_h0_to_h1.empirical_pinsker_minimum_sum_error,
        asymmetric.kl_h1_to_h0.empirical_pinsker_minimum_sum_error
    );
}

#[test]
fn missing_support_and_low_sample_counts_do_not_invent_error_guarantees() {
    let separated = report([&[2, 0], &[0, 2]]);
    assert_eq!(separated.empirical_plugin_minimum_sum_error, Some(0.0));
    assert_eq!(
        separated.kl_h0_to_h1.empirical_pinsker_minimum_sum_error,
        None
    );
    assert_eq!(
        separated.kl_h1_to_h0.empirical_pinsker_minimum_sum_error,
        None
    );
    let absent = report([&[1, 0], &[0, 2]]);
    assert_eq!(absent.empirical_plugin_minimum_sum_error, None);
    assert_eq!(absent.kl_h0_to_h1.empirical_pinsker_minimum_sum_error, None);
    let identical = report([&[2, 2], &[3, 3]]);
    assert_eq!(identical.empirical_plugin_minimum_sum_error, Some(1.0));
    assert_eq!(
        identical.kl_h0_to_h1.empirical_pinsker_minimum_sum_error,
        Some(1.0)
    );
    // A finite, large KL gives the trivial lower bound zero rather than a
    // negative error probability or an assertion that the population matches.
    let large = report([&[100, 0], &[1, 99]]);
    assert_eq!(
        large.kl_h0_to_h1.empirical_pinsker_minimum_sum_error,
        Some(0.0)
    );
    for diagnostic in [separated, absent, identical, large] {
        assert!(!diagnostic.population_distance_established);
        assert!(!diagnostic.statistical_independence_proven);
        assert!(!diagnostic.whole_flow_privacy_guarantee);
        assert!(!diagnostic.awgn_or_square_root_guarantee);
    }
}
