use crate::signals::classify::FailSignal;
use crate::state_v2::{KeyObservation, ObservationContract, StallProbeStats, StateSnapshot};

use super::observation::{observation_reuse_weight, resolve_effective_key};
use super::{
    CrossSessionSignalMetrics, DirectSessionAdvisory, ProbeHistoryDisposition,
    ProbeHistoryReasonCode, StrategyKey,
};

pub(super) fn direct_session_advisory_from_snapshot(
    snapshot: &StateSnapshot,
    key: &StrategyKey,
) -> DirectSessionAdvisory {
    let base_key_hash = key.hash_key();
    let effective_key = resolve_effective_key(snapshot, key, None);
    let effective_key_hash = effective_key.hash_key();
    let latest_observation = snapshot
        .key_observations
        .get(&effective_key_hash)
        .or_else(|| snapshot.key_observations.get(&base_key_hash))
        .cloned();
    let latest_probe_stats = snapshot.stall_probe_stats.get(&base_key_hash).cloned();
    let observation_contract = latest_observation
        .as_ref()
        .map(KeyObservation::observation_contract)
        .unwrap_or(ObservationContract::RuntimeOnly);
    let cross_session_signal_metrics = cross_session_signal_metrics(
        snapshot,
        &base_key_hash,
        key,
        latest_probe_stats.as_ref(),
        latest_observation.as_ref(),
    );
    let (probe_history_disposition, probe_history_reason_code) = probe_history_disposition(
        latest_probe_stats.as_ref(),
        latest_observation.as_ref(),
        cross_session_signal_metrics,
    );
    DirectSessionAdvisory {
        latest_observation,
        latest_probe_stats,
        observation_contract,
        probe_history_disposition,
        probe_history_reason_code,
        cross_session_signal_metrics,
    }
}

pub(super) fn probe_history_strategy_bias(
    metrics: CrossSessionSignalMetrics,
    observation: Option<&KeyObservation>,
    strategy: &str,
) -> f64 {
    if metrics.probe_branch_score <= f64::EPSILON {
        return 0.0;
    }
    let Some(observation) = observation else {
        return 0.0;
    };
    let path_bonus =
        if observation.reference_path_hops().is_some() || observation.rst_path_hops().is_some() {
            1.0_f64
        } else {
            0.8_f64
        };
    let fingerprint_bonus = if observation.runtime_server_hint().is_some()
        || observation.runtime_window_profile_hint().is_some()
    {
        1.1_f64
    } else {
        1.0_f64
    };
    let branch_score = metrics.probe_branch_score * path_bonus * fingerprint_bonus;

    match strategy {
        "ttl_desync" | "ip_frag" | "fake_disorder" | "overlap" => branch_score,
        "passthrough" => -(branch_score / 2.0),
        _ => 0.0,
    }
}

fn observation_confidence_probe_bias_scale(observation: &KeyObservation) -> f64 {
    match observation.observation_capture_confidence() {
        "explicit_absence" | "runtime_only" => 0.0,
        "trusted_shallow_low" => 0.5,
        "trusted_shallow_medium" => 0.75,
        "trusted_shallow_high" | "deep_observed" => 1.0,
        _ => 0.0,
    }
}

fn probe_history_disposition(
    stats: Option<&StallProbeStats>,
    observation: Option<&KeyObservation>,
    metrics: CrossSessionSignalMetrics,
) -> (ProbeHistoryDisposition, ProbeHistoryReasonCode) {
    let Some(stats) = stats else {
        return (
            ProbeHistoryDisposition::None,
            ProbeHistoryReasonCode::NoRecentProbeHistory,
        );
    };
    if !matches!(
        stats.last_signal,
        Some(
            FailSignal::SessionFreeze { .. } | FailSignal::ThroughputCollapse | FailSignal::Timeout
        )
    ) {
        return (
            ProbeHistoryDisposition::None,
            ProbeHistoryReasonCode::ProbeSignalNotStallLike,
        );
    }
    let Some(observation) = observation else {
        return (
            ProbeHistoryDisposition::None,
            ProbeHistoryReasonCode::ProbeObservationMissing,
        );
    };
    if stats.consecutive_stall_failures >= 2 {
        if metrics.relay_preference_score > 0.55 {
            return (
                ProbeHistoryDisposition::PreferRelay,
                ProbeHistoryReasonCode::RepeatedStallPreferRelay,
            );
        }
        return (
            ProbeHistoryDisposition::None,
            ProbeHistoryReasonCode::ProbeObservationNotProbeCapable,
        );
    }
    if stats.consecutive_stall_failures == 1
        && observation.supports_active_stall_probe()
        && metrics.probe_branch_score > f64::EPSILON
    {
        return (
            ProbeHistoryDisposition::BiasProbeBranch,
            ProbeHistoryReasonCode::SingleStallBiasProbeBranch,
        );
    }
    (
        ProbeHistoryDisposition::None,
        ProbeHistoryReasonCode::ProbeObservationNotProbeCapable,
    )
}

fn cross_session_signal_metrics(
    snapshot: &StateSnapshot,
    key_hash: &str,
    key: &StrategyKey,
    stats: Option<&StallProbeStats>,
    observation: Option<&KeyObservation>,
) -> CrossSessionSignalMetrics {
    let reuse_weight = observation_reuse_weight(snapshot, key_hash, key);
    let Some(stats) = stats else {
        return CrossSessionSignalMetrics {
            reuse_weight,
            ..CrossSessionSignalMetrics::default()
        };
    };
    if !matches!(
        stats.last_signal,
        Some(
            FailSignal::SessionFreeze { .. } | FailSignal::ThroughputCollapse | FailSignal::Timeout
        )
    ) {
        return CrossSessionSignalMetrics {
            reuse_weight,
            ..CrossSessionSignalMetrics::default()
        };
    }
    let Some(observation) = observation else {
        return CrossSessionSignalMetrics {
            reuse_weight,
            ..CrossSessionSignalMetrics::default()
        };
    };
    let confidence_score = observation_confidence_probe_bias_scale(observation);
    if confidence_score <= f64::EPSILON {
        return CrossSessionSignalMetrics {
            reuse_weight,
            ..CrossSessionSignalMetrics::default()
        };
    }
    let trials = stats.trials.max(1) as f64;
    let collapse_ratio = (stats.collapses as f64 / trials).clamp(0.0, 1.0);
    let timeout_ratio = (stats.timeouts as f64 / trials).clamp(0.0, 1.0);
    let freeze_ratio = (stats.freezes as f64 / trials).clamp(0.0, 1.0);
    let repeated_bonus = match stats.consecutive_stall_failures {
        failures if failures >= 2 => 0.32,
        1 => 0.12,
        _ => 0.0,
    };
    let stall_severity =
        (collapse_ratio * 0.45 + timeout_ratio * 0.25 + freeze_ratio * 0.15 + repeated_bonus)
            .clamp(0.0, 1.0);
    let path_bonus =
        if observation.reference_path_hops().is_some() || observation.rst_path_hops().is_some() {
            0.03_f64
        } else {
            0.0_f64
        };
    let fingerprint_bonus = if observation.runtime_server_hint().is_some()
        || observation.runtime_window_profile_hint().is_some()
    {
        0.02_f64
    } else {
        0.0_f64
    };
    let probe_branch_score =
        if stats.consecutive_stall_failures == 1 && observation.supports_active_stall_probe() {
            (0.04 + path_bonus + fingerprint_bonus) * confidence_score * (0.5 + stall_severity)
        } else {
            0.0
        };
    let relay_preference_score = if stats.consecutive_stall_failures >= 2 {
        (0.45 + collapse_ratio * 0.2 + timeout_ratio * 0.1 + path_bonus)
            * confidence_score
            * (0.75 + stall_severity * 0.45)
    } else {
        0.0
    };
    CrossSessionSignalMetrics {
        confidence_score,
        reuse_weight,
        stall_severity,
        probe_branch_score,
        relay_preference_score: relay_preference_score.clamp(0.0, 1.0),
    }
}
