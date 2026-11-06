use crate::external_calibration::ExternalCalibrationSnapshot;
use crate::state_v2::StateSnapshot;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{strategy_entry_key, DecisionContext, StrategyBelief};

const DEFAULT_CALIBRATION_HALF_LIFE_SECS: f64 = 86_400.0;
const DEFAULT_RUNTIME_HALF_LIFE_SECS: f64 = 21_600.0;
const HIGH_CONFIDENCE_FAIL_CLOSED: f64 = 0.85;
const FRESH_FAIL_CLOSED_THRESHOLD: f64 = 0.75;

pub(super) fn strategy_runtime_freshness(
    snapshot: &StateSnapshot,
    base_key_hash: &str,
    effective_key_hash: &str,
    strategy: &str,
) -> f64 {
    let newest = [
        snapshot
            .strategy_stats
            .get(&strategy_entry_key(base_key_hash, strategy)),
        snapshot
            .strategy_stats
            .get(&strategy_entry_key(effective_key_hash, strategy)),
    ]
    .into_iter()
    .flatten()
    .filter_map(|stats| stats.last_updated_unix_ms)
    .max();
    newest.map(freshness_from_unix_ms).unwrap_or(1.0)
}

pub(super) fn strategy_latency_cost(
    snapshot: &StateSnapshot,
    base_key_hash: &str,
    effective_key_hash: &str,
    strategy: &str,
) -> f64 {
    let samples = [
        snapshot
            .strategy_stats
            .get(&strategy_entry_key(base_key_hash, strategy)),
        snapshot
            .strategy_stats
            .get(&strategy_entry_key(effective_key_hash, strategy)),
    ];
    let mut total = 0.0;
    let mut count = 0.0;
    for stats in samples.into_iter().flatten() {
        if stats.mean_latency_ms > 0.0 {
            total += (stats.mean_latency_ms / 2_000.0).clamp(0.0, 1.0);
            count += 1.0;
        }
    }
    if count <= f64::EPSILON {
        0.0
    } else {
        total / count
    }
}

pub(super) fn strategy_belief(
    snapshot: &StateSnapshot,
    strategy: &str,
    context: &DecisionContext,
    runtime_reward: f64,
    runtime_confidence: f64,
    runtime_freshness: f64,
    latency_cost: f64,
) -> StrategyBelief {
    let label = normalize_calibration_label(strategy);
    let mut alpha = 1.0;
    let mut beta = 1.0;
    let mut confidence: f64 = 0.0;
    let mut freshness = runtime_freshness;
    let mut detection_risk: f64 = 0.0;
    let mut source = "l3_runtime_posterior";
    let mut hard_blocked = false;

    let runtime_weight = (runtime_confidence * runtime_freshness).clamp(0.0, 1.0);
    alpha += runtime_reward.clamp(0.0, 1.0) * runtime_weight;
    beta += (1.0 - runtime_reward.clamp(0.0, 1.0)) * runtime_weight;
    confidence = confidence.max(runtime_weight);

    if let Some(calibration) = snapshot
        .external_calibration
        .as_ref()
        .filter(|calibration| calibration.has_measured_external_signal())
    {
        let calibration_freshness = calibration_snapshot_freshness(calibration);
        freshness = freshness.max(calibration_freshness);
        if let Some(prior) = calibration.knowledge.iter().find(|prior| {
            let target = normalize_calibration_label(&prior.target_class);
            target == label || prior.target_class.eq_ignore_ascii_case(strategy)
        }) {
            let prior_freshness = prior
                .generated_at_unix_ms
                .map(freshness_from_unix_ms)
                .unwrap_or(calibration_freshness);
            let prior_confidence = (prior.confidence * prior_freshness).clamp(0.0, 1.0);
            alpha += prior.score.clamp(0.0, 1.0) * prior_confidence;
            beta += (1.0 - prior.score.clamp(0.0, 1.0)) * prior_confidence;
            confidence = confidence.max(prior_confidence);
            detection_risk =
                detection_risk.max((1.0 - prior.score.clamp(0.0, 1.0)) * prior_confidence);
            source = "l1_l2_l3_adaptive_posterior";
            hard_blocked = (prior.hard_excluded || prior.fail_closed)
                && prior.score <= 0.05
                && prior_confidence >= HIGH_CONFIDENCE_FAIL_CLOSED
                && prior_freshness >= FRESH_FAIL_CLOSED_THRESHOLD;
        }

        if let Some((score, calibration_confidence)) =
            external_l2_calibration_score(calibration, label.as_str())
        {
            let effective_confidence =
                (calibration_confidence * calibration_freshness).clamp(0.0, 1.0);
            alpha += score.clamp(0.0, 1.0) * effective_confidence;
            beta += (1.0 - score.clamp(0.0, 1.0)) * effective_confidence;
            confidence = confidence.max(effective_confidence);
            detection_risk =
                detection_risk.max((1.0 - score.clamp(0.0, 1.0)) * effective_confidence);
            source = "l1_l2_l3_adaptive_posterior";
        }
    }

    let recent_failure_risk = (context.recent_failures as f64 / 6.0).clamp(0.0, 1.0) * 0.25;
    detection_risk = (detection_risk + recent_failure_risk).clamp(0.0, 1.0);

    StrategyBelief {
        alpha,
        beta,
        detection_risk,
        latency_cost,
        confidence,
        freshness,
        hard_blocked,
        source,
    }
}

pub(super) fn belief_adjusted_reward(belief: &StrategyBelief) -> f64 {
    if belief.hard_blocked {
        return 0.0;
    }
    let posterior = belief.posterior_mean();
    let risk_penalty = belief.detection_risk * 0.35;
    let latency_penalty = belief.latency_cost * 0.10;
    (posterior - risk_penalty - latency_penalty).clamp(0.0, 1.0)
}

fn calibration_snapshot_freshness(calibration: &ExternalCalibrationSnapshot) -> f64 {
    let half_life = calibration
        .freshness_half_life_secs
        .map(|secs| secs as f64)
        .unwrap_or(DEFAULT_CALIBRATION_HALF_LIFE_SECS);
    calibration
        .generated_at_unix_ms
        .map(|generated| freshness_from_unix_ms_with_half_life(generated, half_life))
        .unwrap_or(1.0)
}

fn freshness_from_unix_ms(generated_at_unix_ms: u64) -> f64 {
    freshness_from_unix_ms_with_half_life(generated_at_unix_ms, DEFAULT_RUNTIME_HALF_LIFE_SECS)
}

fn freshness_from_unix_ms_with_half_life(generated_at_unix_ms: u64, half_life_secs: f64) -> f64 {
    let now = current_unix_ms();
    if generated_at_unix_ms >= now {
        return 1.0;
    }
    // Quantize the age to WHOLE SECONDS (floor). The half-life is seconds-to-hours
    // (default 21_600s = 6h), so sub-second precision is meaningless for the decay
    // — but it is a flake source: two strategies recorded a few ms apart get
    // microscopically different freshness, which flips the order of an otherwise
    // near-exact tie depending on machine timing. Second-granularity makes records
    // made within the same second identically fresh → deterministic tie-break, with
    // no material change to real decay.
    let age_secs = ((now - generated_at_unix_ms) / 1_000) as f64;
    if half_life_secs <= f64::EPSILON {
        return 0.0;
    }
    2.0_f64.powf(-(age_secs / half_life_secs)).clamp(0.0, 1.0)
}

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn external_l2_calibration_score(
    calibration: &ExternalCalibrationSnapshot,
    label: &str,
) -> Option<(f64, f64)> {
    let witness_score = calibration
        .witness
        .iter()
        .find(|entry| normalize_calibration_label(&entry.label) == label && entry.records > 0)
        .map(|entry| {
            (
                entry.combined_avg.clamp(0.0, 1.0),
                record_confidence(entry.records),
            )
        });
    let adversarial_score = calibration
        .adversarial
        .iter()
        .find(|entry| normalize_calibration_label(&entry.transport) == label && entry.measured > 0)
        .and_then(|entry| entry.pass_rate)
        .zip(
            calibration
                .adversarial
                .iter()
                .find(|entry| {
                    normalize_calibration_label(&entry.transport) == label && entry.measured > 0
                })
                .map(|entry| record_confidence(entry.measured)),
        )
        .map(|(score, confidence)| (score.clamp(0.0, 1.0), confidence));

    match (witness_score, adversarial_score) {
        (Some((witness, witness_confidence)), Some((adversarial, adversarial_confidence))) => {
            let total_confidence = witness_confidence + adversarial_confidence;
            if total_confidence <= f64::EPSILON {
                Some(((witness + adversarial) / 2.0, 0.0))
            } else {
                Some((
                    (witness * witness_confidence + adversarial * adversarial_confidence)
                        / total_confidence,
                    (total_confidence / 2.0).clamp(0.0, 1.0),
                ))
            }
        }
        (Some(witness), None) => Some(witness),
        (None, Some(adversarial)) => Some(adversarial),
        (None, None) => None,
    }
}

fn record_confidence(records: u64) -> f64 {
    ((records.min(20) as f64) / 20.0).clamp(0.0, 1.0)
}

fn normalize_calibration_label(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('-', "_")
}
