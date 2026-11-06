//! Toy synthetic counterexample: equal marginals can conceal different sequence structure.
//! This module measures no real DPI, target network, privacy, or MEC property.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const MAX_FLOWS: usize = 256;
pub const MAX_EVENTS: usize = 128;
pub const MAX_TIME_MS: u64 = 60_000;
pub const MAX_SIZE: u32 = 65_535;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    In,
    Out,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub at_ms: u64,
    pub size: u32,
    pub direction: Direction,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionTrace {
    pub session_id: String,
    pub capture_group: String,
    pub label: u8,
    pub events: Vec<Event>,
}
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FullFlowError {
    #[error("flow/event/time/size bounds or timestamp ordering invalid")]
    Bounds,
    #[error("identity must contain 1..=96 non-control characters")]
    Identity,
    #[error("synthetic label must be 0 or 1")]
    Label,
    #[error("session IDs must be unique across both partitions")]
    SessionOverlap,
    #[error("capture groups overlap between training and held-out partitions")]
    CaptureGroupOverlap,
    #[error("training requires both synthetic classes")]
    MissingClass,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct MarginalHistogram {
    pub sizes: BTreeMap<u32, usize>,
    pub gaps_ms: BTreeMap<u64, usize>,
    pub directions: [usize; 2],
}

pub fn validate_trace(t: &SessionTrace) -> Result<(), FullFlowError> {
    if [&t.session_id, &t.capture_group]
        .iter()
        .any(|s| s.is_empty() || s.chars().count() > 96 || s.chars().any(char::is_control))
    {
        return Err(FullFlowError::Identity);
    }
    if t.label > 1 {
        return Err(FullFlowError::Label);
    }
    if !(2..=MAX_EVENTS).contains(&t.events.len())
        || t.events
            .iter()
            .any(|e| e.size == 0 || e.size > MAX_SIZE || e.at_ms > MAX_TIME_MS)
        || t.events.windows(2).any(|w| w[0].at_ms >= w[1].at_ms)
    {
        return Err(FullFlowError::Bounds);
    }
    Ok(())
}
pub fn marginal_histogram(t: &SessionTrace) -> Result<MarginalHistogram, FullFlowError> {
    validate_trace(t)?;
    let mut h = MarginalHistogram {
        sizes: BTreeMap::new(),
        gaps_ms: BTreeMap::new(),
        directions: [0; 2],
    };
    for e in &t.events {
        *h.sizes.entry(e.size).or_default() += 1;
        h.directions[usize::from(e.direction == Direction::Out)] += 1;
    }
    for w in t.events.windows(2) {
        *h.gaps_ms.entry(w[1].at_ms - w[0].at_ms).or_default() += 1;
    }
    Ok(h)
}
/// Uses only event sequence values; identity and labels never enter the feature vector.
pub fn order_features(t: &SessionTrace) -> Result<[f64; 3], FullFlowError> {
    validate_trace(t)?;
    let (mut changes, mut longest, mut run) = (0, 1, 1);
    for w in t.events.windows(2) {
        if w[0].direction == w[1].direction {
            run += 1;
        } else {
            changes += 1;
            run = 1;
        }
        longest = longest.max(run);
    }
    let gaps: Vec<_> = t
        .events
        .windows(2)
        .map(|w| w[1].at_ms - w[0].at_ms)
        .collect();
    let gap_changes = gaps.windows(2).filter(|w| w[0] != w[1]).count();
    Ok([
        changes as f64 / (t.events.len() - 1) as f64,
        longest as f64 / t.events.len() as f64,
        gap_changes as f64 / (gaps.len() - 1).max(1) as f64,
    ])
}
fn validate_split(train: &[SessionTrace], heldout: &[SessionTrace]) -> Result<(), FullFlowError> {
    if train.is_empty() || heldout.is_empty() || train.len() + heldout.len() > MAX_FLOWS {
        return Err(FullFlowError::Bounds);
    }
    let mut sessions = BTreeSet::new();
    for t in train.iter().chain(heldout) {
        validate_trace(t)?;
        if !sessions.insert(&t.session_id) {
            return Err(FullFlowError::SessionOverlap);
        }
    }
    let groups: BTreeSet<_> = train.iter().map(|t| &t.capture_group).collect();
    if heldout.iter().any(|t| groups.contains(&t.capture_group)) {
        return Err(FullFlowError::CaptureGroupOverlap);
    }
    if (0..2).any(|label| !train.iter().any(|t| t.label == label)) {
        return Err(FullFlowError::MissingClass);
    }
    Ok(())
}
fn evaluate(
    train: &[SessionTrace],
    heldout: &[SessionTrace],
    features: &dyn Fn(&SessionTrace) -> Vec<f64>,
) -> Value {
    let mut means = [
        vec![0.0; features(&train[0]).len()],
        vec![0.0; features(&train[0]).len()],
    ];
    let mut counts = [0; 2];
    for t in train {
        counts[t.label as usize] += 1;
        for (mean, x) in means[t.label as usize].iter_mut().zip(features(t)) {
            *mean += x;
        }
    }
    for c in 0..2 {
        for x in &mut means[c] {
            *x /= counts[c] as f64;
        }
    }
    let mut confusion = [[0usize; 2]; 2];
    for t in heldout {
        let f = features(t);
        let distances: Vec<f64> = means
            .iter()
            .map(|mean| mean.iter().zip(&f).map(|(a, b)| (a - b).powi(2)).sum())
            .collect();
        let prediction = usize::from(distances[1] < distances[0]); // Equal distances select class 0.
        confusion[t.label as usize][prediction] += 1;
    }
    json!({"accuracy": (confusion[0][0] + confusion[1][1]) as f64 / heldout.len() as f64,
        "confusion_actual_rows_predicted_columns": confusion, "class_means": means})
}
pub fn assess(train: &[SessionTrace], heldout: &[SessionTrace]) -> Result<Value, FullFlowError> {
    validate_split(train, heldout)?;
    // Histogram vocabulary is fitted on training events only; unseen values get explicit bins.
    let mut sizes = BTreeSet::new();
    let mut gaps = BTreeSet::new();
    for t in train {
        let h = marginal_histogram(t)?;
        sizes.extend(h.sizes.keys().copied());
        gaps.extend(h.gaps_ms.keys().copied());
    }
    let histogram_features = |t: &SessionTrace| {
        let h = marginal_histogram(t).expect("partition validated");
        let mut f: Vec<f64> = sizes
            .iter()
            .map(|s| *h.sizes.get(s).unwrap_or(&0) as f64 / t.events.len() as f64)
            .collect();
        f.push(
            h.sizes
                .iter()
                .filter(|(s, _)| !sizes.contains(*s))
                .map(|(_, n)| n)
                .sum::<usize>() as f64
                / t.events.len() as f64,
        );
        f.extend(
            gaps.iter()
                .map(|g| *h.gaps_ms.get(g).unwrap_or(&0) as f64 / (t.events.len() - 1) as f64),
        );
        f.push(
            h.gaps_ms
                .iter()
                .filter(|(g, _)| !gaps.contains(*g))
                .map(|(_, n)| n)
                .sum::<usize>() as f64
                / (t.events.len() - 1) as f64,
        );
        f.extend(h.directions.map(|n| n as f64 / t.events.len() as f64));
        f
    };
    Ok(json!({
        "scope": "toy_synthetic_full_flow_counterexample",
        "labels": ["synthetic_alternating", "synthetic_grouped_bursts"],
        "synthetic_only": true, "real_dpi_assessed": false, "target_network_assessed": false,
        "detection_guarantee": false, "formal_dp_guarantee": false, "mec_guarantee": false,
        "classifier": "nearest_class_mean_squared_euclidean_class_0_tie_break",
        "split": "disjoint_session_ids_and_capture_groups", "train_sessions": train.len(), "heldout_sessions": heldout.len(),
        "order_feature_schema": ["direction_change_fraction", "longest_direction_run_fraction", "gap_change_fraction"],
        "histogram_schema": {"size_values_from_train": sizes, "gap_values_from_train": gaps,
            "unknown_bins": ["size", "gap"], "directions": ["in", "out"], "normalized_counts": true},
        "full_flow": evaluate(train, heldout, &|t| order_features(t).expect("partition validated").to_vec()),
        "histogram_baseline": evaluate(train, heldout, &histogram_features),
        "interpretation": "A constructed marginal collision; held-out toy accuracy is not real classifier efficacy or causal feature importance."
    }))
}
fn synthetic_trace(group: &str, variant: usize, label: u8) -> SessionTrace {
    let mut at_ms = variant as u64 * 13;
    let gaps = if label == 0 {
        [1, 4, 1, 4, 1, 4, 1]
    } else {
        [1, 1, 1, 4, 4, 4, 1]
    };
    let events = (0..8)
        .map(|i| {
            if i > 0 {
                at_ms += gaps[i - 1];
            }
            let out = if label == 0 { i % 2 == 0 } else { i < 4 };
            Event {
                at_ms,
                size: (if label == 0 {
                    100 + 100 * (i % 2)
                } else {
                    100 + 100 * (i / 4)
                }) as u32
                    + variant as u32 * 10,
                direction: if out { Direction::Out } else { Direction::In },
            }
        })
        .collect();
    SessionTrace {
        session_id: format!("{group}-{variant}-{label}"),
        capture_group: group.into(),
        label,
        events,
    }
}
fn fixture() -> (Vec<SessionTrace>, Vec<SessionTrace>) {
    let partition = |prefix: &str, groups: usize| {
        (0..groups)
            .flat_map(|g| {
                let name = format!("{prefix}-{g}");
                (0..2).flat_map(move |v| {
                    (0..2).map({
                        let name = name.clone();
                        move |label| synthetic_trace(&name, v, label)
                    })
                })
            })
            .collect()
    };
    (partition("train", 4), partition("heldout", 2))
}
pub fn demo() -> Result<Value, FullFlowError> {
    let (train, heldout) = fixture();
    assess(&train, &heldout)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn marginal_collision_sequence_discrimination() {
        let a = synthetic_trace("a", 0, 0);
        let b = synthetic_trace("b", 0, 1);
        assert_eq!(
            marginal_histogram(&a).unwrap(),
            marginal_histogram(&b).unwrap()
        );
        assert_ne!(order_features(&a).unwrap(), order_features(&b).unwrap());
        let d = demo().unwrap();
        assert_eq!(d["full_flow"]["accuracy"], 1.0);
        assert_eq!(d["histogram_baseline"]["accuracy"], 0.5);
        assert_eq!(
            d["full_flow"]["confusion_actual_rows_predicted_columns"],
            json!([[4, 0], [0, 4]])
        );
        assert_eq!(
            d["histogram_baseline"]["confusion_actual_rows_predicted_columns"],
            json!([[4, 0], [4, 0]])
        );
    }
    #[test]
    fn grouped_holdout_and_identity_leak_guard() {
        let (train, mut test) = fixture();
        let original = assess(&train, &test).unwrap();
        for (i, t) in test.iter_mut().enumerate() {
            t.session_id = format!("opaque-{i}");
            t.capture_group = "fresh".into();
        }
        assert_eq!(assess(&train, &test).unwrap(), original);
        test[0].session_id = train[0].session_id.clone();
        assert_eq!(
            assess(&train, &test).unwrap_err(),
            FullFlowError::SessionOverlap
        );
        test[0].session_id = "unique".into();
        test[0].capture_group = train[0].capture_group.clone();
        assert_eq!(
            assess(&train, &test).unwrap_err(),
            FullFlowError::CaptureGroupOverlap
        );
        test[0].capture_group = "fresh".into();
        test[0].label = 2;
        assert_eq!(assess(&train, &test).unwrap_err(), FullFlowError::Label);
        test[0].label = 0;
        test[0].session_id.clear();
        assert_eq!(assess(&train, &test).unwrap_err(), FullFlowError::Identity);
        test[0].session_id = "unique".into();
        assert_eq!(
            assess(&train[..1], &test).unwrap_err(),
            FullFlowError::MissingClass
        );
    }
    #[test]
    fn invalid_bounds_are_rejected() {
        let a = synthetic_trace("a", 0, 0);
        for edit in 0..6 {
            let mut t = a.clone();
            match edit {
                0 => t.events.clear(),
                1 => t.events = vec![t.events[0].clone(); MAX_EVENTS + 1],
                2 => t.events[0].size = 0,
                3 => t.events[0].size = MAX_SIZE + 1,
                4 => t.events[0].at_ms = MAX_TIME_MS + 1,
                _ => t.events[1].at_ms = t.events[0].at_ms,
            }
            assert_eq!(validate_trace(&t), Err(FullFlowError::Bounds));
        }
        assert_eq!(
            assess(&vec![a.clone(); MAX_FLOWS], &[a]).unwrap_err(),
            FullFlowError::Bounds
        );
    }
    #[test]
    fn no_fabricated_detection_or_privacy_guarantee() {
        let d = demo().unwrap();
        for key in [
            "real_dpi_assessed",
            "target_network_assessed",
            "detection_guarantee",
            "formal_dp_guarantee",
            "mec_guarantee",
        ] {
            assert_eq!(d[key], false);
        }
        assert_eq!(d["scope"], "toy_synthetic_full_flow_counterexample");
        assert_eq!(d["synthetic_only"], true);
    }
    #[test]
    fn deterministic_retest_and_frozen_schema() {
        assert_eq!(demo().unwrap(), demo().unwrap());
        let (train, mut test) = fixture();
        let before = assess(&train, &test).unwrap();
        test[0].events[0].size = 999;
        let after = assess(&train, &test).unwrap();
        assert_eq!(before["histogram_schema"], after["histogram_schema"]);
        assert_eq!(before["full_flow"], after["full_flow"]);
    }
}
