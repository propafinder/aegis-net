//! Empirical finite-alphabet I(X;Y), with an optional conservative iid interval.
//! Labels/bins must be fixed before observing the evaluation sample.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LeakageSample {
    pub label: usize,
    pub feature: usize,
    pub added_bytes: u64,
    pub added_delay_ms: f64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Alphabet {
    pub labels: usize,
    pub features: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct LeakageEstimate {
    pub samples: usize,
    pub empirical_mutual_information_bits: f64,
    pub mean_added_bytes: f64,
    pub mean_added_delay_ms: f64,
    pub iid_confidence_interval_bits: Option<[f64; 2]>,
    pub confidence_failure_probability: Option<f64>,
    pub scope: &'static str,
    pub formal_dp_accounting: bool,
    pub theoretical_rate_distortion_bound: bool,
}

pub fn estimate(
    samples: &[LeakageSample],
    alphabet: &Alphabet,
    assume_iid_fixed_alphabet: bool,
    delta: f64,
) -> Result<LeakageEstimate, String> {
    if samples.is_empty()
        || samples.len() > 1_000_000
        || !(1..=256).contains(&alphabet.labels)
        || !(1..=256).contains(&alphabet.features)
        || !delta.is_finite()
        || !(0.0..1.0).contains(&delta)
        || delta == 0.0
    {
        return Err("invalid finite-alphabet measurement budget".into());
    }
    let cells = alphabet.labels * alphabet.features;
    let mut joint = vec![0_u64; cells];
    let mut labels = vec![0_u64; alphabet.labels];
    let mut features = vec![0_u64; alphabet.features];
    let mut bytes = 0_u128;
    let mut delay = 0.0;
    for sample in samples {
        if sample.label >= alphabet.labels
            || sample.feature >= alphabet.features
            || !sample.added_delay_ms.is_finite()
            || sample.added_delay_ms < 0.0
            || sample.added_delay_ms > 3_600_000.0
        {
            return Err("sample outside predeclared alphabet or cost budget".into());
        }
        joint[sample.label * alphabet.features + sample.feature] += 1;
        labels[sample.label] += 1;
        features[sample.feature] += 1;
        bytes += u128::from(sample.added_bytes);
        delay += sample.added_delay_ms;
    }
    let n = samples.len() as f64;
    let entropy = |counts: &[u64]| -> f64 {
        counts
            .iter()
            .filter(|c| **c != 0)
            .map(|c| {
                let p = *c as f64 / n;
                -p * p.log2()
            })
            .sum()
    };
    let mi = (entropy(&labels) + entropy(&features) - entropy(&joint)).max(0.0);
    // Hoeffding + union bound over fixed joint cells => TV <= K*epsilon/2.
    // Marginal TV cannot increase. Finite-alphabet entropy continuity gives
    // the conservative three-entropy error. Valid only for independent samples.
    let interval = assume_iid_fixed_alphabet.then(|| {
        let epsilon = ((2.0 * cells as f64 / delta).ln() / (2.0 * n)).sqrt();
        let tv = (cells as f64 * epsilon / 2.0).min(1.0);
        let error = entropy_continuity(alphabet.labels, tv)
            + entropy_continuity(alphabet.features, tv)
            + entropy_continuity(cells, tv);
        [
            (mi - error).max(0.0),
            (mi + error).min((alphabet.labels.min(alphabet.features) as f64).log2()),
        ]
    });
    Ok(LeakageEstimate {
        samples: samples.len(),
        empirical_mutual_information_bits: mi,
        mean_added_bytes: bytes as f64 / n,
        mean_added_delay_ms: delay / n,
        iid_confidence_interval_bits: interval,
        confidence_failure_probability: assume_iid_fixed_alphabet.then_some(delta),
        scope:
            "empirical fixed-alphabet point; not full-flow privacy or a theoretical Pareto optimum",
        formal_dp_accounting: false,
        theoretical_rate_distortion_bound: false,
    })
}

fn entropy_continuity(alphabet: usize, tv: f64) -> f64 {
    if alphabet <= 1 {
        return 0.0;
    }
    if tv >= 1.0 - 1.0 / alphabet as f64 {
        return (alphabet as f64).log2();
    }
    if tv <= 0.0 {
        return 0.0;
    }
    let binary_entropy = -tv * tv.log2() - (1.0 - tv) * (1.0 - tv).log2();
    tv * ((alphabet - 1) as f64).log2() + binary_entropy
}

/// Indices of nondominated measured policies in (cost bytes, delay, empirical MI).
/// No interpolation, statistical significance or global-optimality assertion.
pub fn empirical_frontier(points: &[LeakageEstimate]) -> Vec<usize> {
    points
        .iter()
        .enumerate()
        .filter_map(|(i, p)| {
            let dominated = points.iter().enumerate().any(|(j, q)| {
                j != i
                    && q.mean_added_bytes <= p.mean_added_bytes
                    && q.mean_added_delay_ms <= p.mean_added_delay_ms
                    && q.empirical_mutual_information_bits <= p.empirical_mutual_information_bits
                    && (q.mean_added_bytes < p.mean_added_bytes
                        || q.mean_added_delay_ms < p.mean_added_delay_ms
                        || q.empirical_mutual_information_bits
                            < p.empirical_mutual_information_bits)
            });
            (!dominated).then_some(i)
        })
        .collect()
}

/// Minimum measured leakage among actually feasible measured frontier points.
/// Ties prefer less byte cost, then delay, then stable input order.
pub fn select_measured_policy(
    points: &[LeakageEstimate],
    max_added_bytes: f64,
    max_added_delay_ms: f64,
) -> Result<Option<usize>, String> {
    if !max_added_bytes.is_finite()
        || max_added_bytes < 0.0
        || !max_added_delay_ms.is_finite()
        || max_added_delay_ms < 0.0
        || points.len() > 64
        || points.iter().any(|p| {
            !p.empirical_mutual_information_bits.is_finite()
                || p.empirical_mutual_information_bits < 0.0
                || !p.mean_added_bytes.is_finite()
                || p.mean_added_bytes < 0.0
                || !p.mean_added_delay_ms.is_finite()
                || p.mean_added_delay_ms < 0.0
        })
    {
        return Err("invalid measured QoS budget or point".into());
    }
    Ok(empirical_frontier(points)
        .into_iter()
        .filter(|i| {
            points[*i].mean_added_bytes <= max_added_bytes
                && points[*i].mean_added_delay_ms <= max_added_delay_ms
        })
        .min_by(|a, b| {
            let a = &points[*a];
            let b = &points[*b];
            a.empirical_mutual_information_bits
                .total_cmp(&b.empirical_mutual_information_bits)
                .then(a.mean_added_bytes.total_cmp(&b.mean_added_bytes))
                .then(a.mean_added_delay_ms.total_cmp(&b.mean_added_delay_ms))
        }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empirical_independence_and_disclosure_are_distinct() {
        let alphabet = Alphabet {
            labels: 2,
            features: 2,
        };
        let independent: Vec<_> = (0..4)
            .map(|i| LeakageSample {
                label: i / 2,
                feature: i % 2,
                added_bytes: u64::MAX,
                added_delay_ms: 0.0,
            })
            .collect();
        let a = estimate(&independent, &alphabet, false, 0.05).unwrap();
        assert_eq!(a.empirical_mutual_information_bits, 0.0);
        assert!(a.iid_confidence_interval_bits.is_none());
        let disclosed = [independent[0].clone(), independent[3].clone()];
        let b = estimate(&disclosed, &alphabet, true, 0.05).unwrap();
        assert_eq!(b.empirical_mutual_information_bits, 1.0);
        assert_eq!(b.iid_confidence_interval_bits, Some([0.0, 1.0]));
        assert!(!b.formal_dp_accounting);
        assert!(!b.theoretical_rate_distortion_bound);
    }
    #[test]
    fn rejects_invalid_samples_and_does_not_claim_frontier_optimality() {
        let sample = LeakageSample {
            label: 0,
            feature: 0,
            added_bytes: 0,
            added_delay_ms: f64::NAN,
        };
        assert!(estimate(
            &[sample],
            &Alphabet {
                labels: 1,
                features: 1
            },
            false,
            0.05
        )
        .is_err());
        let a = estimate(
            &[LeakageSample {
                label: 0,
                feature: 0,
                added_bytes: 0,
                added_delay_ms: 0.0,
            }],
            &Alphabet {
                labels: 1,
                features: 1,
            },
            false,
            0.05,
        )
        .unwrap();
        let mut b = a.clone();
        b.mean_added_bytes = 1.0;
        assert_eq!(empirical_frontier(&[a, b]), vec![0]);
    }
    #[test]
    fn measured_policy_selection_enforces_both_qos_costs() {
        let mut p = estimate(
            &[LeakageSample {
                label: 0,
                feature: 0,
                added_bytes: 0,
                added_delay_ms: 0.0,
            }],
            &Alphabet {
                labels: 1,
                features: 1,
            },
            false,
            0.05,
        )
        .unwrap();
        p.empirical_mutual_information_bits = 1.0;
        let mut q = p.clone();
        q.empirical_mutual_information_bits = 0.0;
        q.mean_added_bytes = 100.0;
        q.mean_added_delay_ms = 10.0;
        let points = [p, q];
        assert_eq!(
            select_measured_policy(&points, 99.0, 10.0).unwrap(),
            Some(0)
        );
        assert_eq!(
            select_measured_policy(&points, 100.0, 9.0).unwrap(),
            Some(0)
        );
        assert_eq!(
            select_measured_policy(&points, 100.0, 10.0).unwrap(),
            Some(1)
        );
        assert!(select_measured_policy(&points, f64::NAN, 10.0).is_err());
    }
}
