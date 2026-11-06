//! Plug-in distances between two observed finite feature distributions.
//! These are not population distances, a classifier evaluation, an iid product
//! law, or the AWGN square-root theorem. Callers own bin/holdout provenance.
use super::leakage::{Alphabet, LeakageSample};
use serde::Serialize;

pub const MIN_OBSERVATIONS_PER_HYPOTHESIS: usize = 2;
const MAX_SAMPLES: usize = 1_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DistanceStatus {
    KnownEmpiricalValue,
    UnknownInsufficientObservations,
    UnknownZeroObservedReferenceSupport,
}

#[derive(Debug, Serialize)]
pub struct DirectionalKl {
    pub status: DistanceStatus,
    pub empirical_nats: Option<f64>,
    /// max(0, 1-sqrt(KL/2)) for the observed distributions only. This
    /// floating-point diagnostic is not a certified population error bound.
    pub empirical_pinsker_minimum_sum_error: Option<f64>,
    /// Bins observed in the numerator but absent from the reference sample.
    pub zero_observed_reference_bins: usize,
}

#[derive(Debug, Serialize)]
pub struct BinaryHypothesisDiagnostic {
    pub status: DistanceStatus,
    pub observations_by_hypothesis: [usize; 2],
    pub minimum_observations_per_hypothesis: usize,
    pub declared_feature_bins: usize,
    pub observed_union_feature_bins: usize,
    pub empirical_total_variation: Option<f64>,
    /// Minimum unweighted false-positive plus false-negative probability for
    /// a test of the two *observed* histograms: 1-TV. It is neither an actual
    /// classifier result nor a Bayes risk with arbitrary class priors.
    pub empirical_plugin_minimum_sum_error: Option<f64>,
    pub kl_h0_to_h1: DirectionalKl,
    pub kl_h1_to_h0: DirectionalKl,
    pub scope: &'static str,
    pub smoothing_applied: bool,
    pub population_distance_established: bool,
    pub statistical_independence_proven: bool,
    pub whole_flow_privacy_guarantee: bool,
    pub awgn_or_square_root_guarantee: bool,
}

fn kl(numerator: &[u64], reference: &[u64], totals: [usize; 2]) -> DirectionalKl {
    let missing = numerator
        .iter()
        .zip(reference)
        .filter(|(p, q)| **p != 0 && **q == 0)
        .count();
    if totals.iter().any(|n| *n < MIN_OBSERVATIONS_PER_HYPOTHESIS) {
        return DirectionalKl {
            status: DistanceStatus::UnknownInsufficientObservations,
            empirical_nats: None,
            empirical_pinsker_minimum_sum_error: None,
            zero_observed_reference_bins: missing,
        };
    }
    if missing != 0 {
        // The empirical KL would be infinite. An unobserved reference bin
        // does not establish a zero population probability: expose unknown,
        // rather than serialize infinity or silently add pseudocounts.
        return DirectionalKl {
            status: DistanceStatus::UnknownZeroObservedReferenceSupport,
            empirical_nats: None,
            empirical_pinsker_minimum_sum_error: None,
            zero_observed_reference_bins: missing,
        };
    }
    let n = totals[0] as f64;
    let m = totals[1] as f64;
    let value = numerator
        .iter()
        .zip(reference)
        .filter(|(p, _)| **p != 0)
        .map(|(p, q)| {
            let p = *p as f64 / n;
            let q = *q as f64 / m;
            p * (p / q).ln()
        })
        .sum::<f64>();
    let value = value.max(0.0);
    DirectionalKl {
        status: DistanceStatus::KnownEmpiricalValue,
        // Roundoff can make the mathematically nonnegative sum slightly <0.
        empirical_nats: Some(value),
        empirical_pinsker_minimum_sum_error: Some((1.0 - (value / 2.0).sqrt()).max(0.0)),
        zero_observed_reference_bins: 0,
    }
}

/// Labels 0 and 1 are H0/H1; counts are normalized separately, even when the
/// class sizes differ. Costs and sequence order are outside this diagnostic.
/// Two observations is only a declared refusal floor, not statistical power.
pub fn diagnose(
    samples: &[LeakageSample],
    alphabet: &Alphabet,
) -> Result<BinaryHypothesisDiagnostic, &'static str> {
    if alphabet.labels != 2
        || !(1..=256).contains(&alphabet.features)
        || samples.len() > MAX_SAMPLES
    {
        return Err(
            "binary diagnostic requires two labels, 1..=256 bins and at most 1000000 samples",
        );
    }
    let mut counts = [
        vec![0_u64; alphabet.features],
        vec![0_u64; alphabet.features],
    ];
    let mut totals = [0_usize; 2];
    for sample in samples {
        if sample.label >= 2 || sample.feature >= alphabet.features {
            return Err("binary sample outside the declared feature alphabet");
        }
        counts[sample.label][sample.feature] += 1;
        totals[sample.label] += 1;
    }
    let enough = totals.iter().all(|n| *n >= MIN_OBSERVATIONS_PER_HYPOTHESIS);
    let tv = enough.then(|| {
        counts[0]
            .iter()
            .zip(&counts[1])
            .map(|(p, q)| (*p as f64 / totals[0] as f64 - *q as f64 / totals[1] as f64).abs())
            .sum::<f64>()
            .mul_add(0.5, 0.0)
            .clamp(0.0, 1.0)
    });
    Ok(BinaryHypothesisDiagnostic {
        status: if enough {
            DistanceStatus::KnownEmpiricalValue
        } else {
            DistanceStatus::UnknownInsufficientObservations
        },
        observations_by_hypothesis: totals,
        minimum_observations_per_hypothesis: MIN_OBSERVATIONS_PER_HYPOTHESIS,
        declared_feature_bins: alphabet.features,
        observed_union_feature_bins: counts[0]
            .iter()
            .zip(&counts[1])
            .filter(|(p, q)| **p != 0 || **q != 0)
            .count(),
        empirical_total_variation: tv,
        empirical_plugin_minimum_sum_error: tv.map(|distance| 1.0 - distance),
        kl_h0_to_h1: kl(&counts[0], &counts[1], totals),
        kl_h1_to_h0: kl(&counts[1], &counts[0], [totals[1], totals[0]]),
        scope:
            "plug-in observed fixed-bin distributions only; no population/flow/classifier guarantee",
        smoothing_applied: false,
        population_distance_established: false,
        statistical_independence_proven: false,
        whole_flow_privacy_guarantee: false,
        awgn_or_square_root_guarantee: false,
    })
}

#[cfg(test)]
#[path = "binary_hypothesis_tests.rs"]
mod tests;
