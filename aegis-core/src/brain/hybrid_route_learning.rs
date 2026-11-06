use crate::external_calibration::ExternalCalibrationSnapshot;
use crate::hybrid_route::HybridRouteFamily;
use crate::signals::classify::FailSignal;
use crate::state_v2::{HybridRouteStats, StateSnapshot};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

use super::observation::strategy_entry_key;
use super::{Brain, StrategyKey};

const DIRECT_ATTEMPT_GUARD_MS: u64 = 30_000;
const DIRECT_EVIDENCE_FRESH_MS: u64 = 6 * 60 * 60 * 1_000;
const DIRECT_FAILURE_BASE_COOLDOWN_MS: u64 = 5 * 60 * 1_000;
const DIRECT_FAILURE_MAX_COOLDOWN_MS: u64 = 6 * 60 * 60 * 1_000;
const DEFAULT_CALIBRATION_HALF_LIFE_SECS: u64 = 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HybridRouteSelectionReason {
    Ipv6RelayPolicy,
    DirectCapabilityUnavailable,
    ExternalClassifierHardBlock,
    ExternalClassifierPrefersRelay,
    DirectAttemptInFlight,
    RecentHostileDirectFailure,
    FreshDirectSuccess,
    EvidenceDecayedExploration,
    ColdStartExploration,
}

impl HybridRouteSelectionReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ipv6RelayPolicy => "ipv6_relay_policy",
            Self::DirectCapabilityUnavailable => "direct_capability_unavailable",
            Self::ExternalClassifierHardBlock => "external_classifier_hard_block",
            Self::ExternalClassifierPrefersRelay => "external_classifier_prefers_relay",
            Self::DirectAttemptInFlight => "direct_attempt_in_flight",
            Self::RecentHostileDirectFailure => "recent_hostile_direct_failure",
            Self::FreshDirectSuccess => "fresh_direct_success",
            Self::EvidenceDecayedExploration => "evidence_decayed_exploration",
            Self::ColdStartExploration => "cold_start_exploration",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HybridEvidenceConfidence {
    None,
    Low,
    Medium,
    High,
}

impl HybridEvidenceConfidence {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HybridRouteAdvisory {
    pub route: HybridRouteFamily,
    pub reason: HybridRouteSelectionReason,
    pub evidence_confidence: HybridEvidenceConfidence,
    pub direct_failure_cooldown_remaining_ms: u64,
    pub external_classifier_hint: Option<FailSignal>,
}

#[derive(Debug, Clone)]
struct ExternalGenevaHint {
    signal: FailSignal,
    fingerprint: String,
}

impl Brain {
    /// Select the product route and ingest a fresh external Geneva classifier
    /// result at most once. The same applied calibration snapshot cannot inflate
    /// route or strategy counters on every connection.
    pub async fn select_hybrid_route(
        &self,
        key: &StrategyKey,
        direct_capable: bool,
    ) -> HybridRouteAdvisory {
        let now_unix_ms = current_unix_ms();
        let snapshot = self.state.snapshot().await;
        if let Some(hint) = external_geneva_hint(&snapshot, now_unix_ms) {
            let route_key = key.hash_key();
            let already_applied = snapshot
                .hybrid_route_stats
                .get(&route_key)
                .and_then(|stats| stats.last_external_classifier_fingerprint.as_deref())
                == Some(hint.fingerprint.as_str());
            if !already_applied {
                let strategy_key = strategy_entry_key(&route_key, "geneva");
                let signal = hint.signal.clone();
                let fingerprint = hint.fingerprint.clone();
                self.state
                    .update_touched(|snapshot, touched| {
                        touched.key_registry.insert(route_key.clone());
                        touched.hybrid_route_stats.insert(route_key.clone());
                        touched.strategy_stats.insert(strategy_key.clone());
                        snapshot.key_registry.insert(route_key.clone(), key.clone());
                        let route = snapshot
                            .hybrid_route_stats
                            .entry(route_key.clone())
                            .or_default();
                        route.last_external_classifier_hint = Some(signal.clone());
                        route.last_external_classifier_fingerprint = Some(fingerprint);
                        snapshot
                            .strategy_stats
                            .entry(strategy_key)
                            .or_default()
                            .record(&signal, None, 0);
                    })
                    .await;
                self.persist().await;
            }
        }
        let snapshot = self.state.snapshot().await;
        hybrid_route_advisory_at(&snapshot, key, direct_capable, now_unix_ms)
    }

    /// Read only the hostname-independent hybrid relay admission. No
    /// destination key is fabricated, persisted or credited with an attempt.
    /// Address-family and learned-route decisions remain after resolution.
    pub async fn hybrid_route_before_resolution(
        &self,
        direct_capable: bool,
    ) -> Option<HybridRouteAdvisory> {
        let snapshot = self.state.snapshot().await;
        let hint = external_geneva_hint(&snapshot, current_unix_ms()).map(|hint| hint.signal);
        unresolved_hybrid_relay_advisory(direct_capable, hint)
    }

    pub async fn record_hybrid_route_attempt(&self, key: &StrategyKey, route: HybridRouteFamily) {
        self.record_hybrid_route_attempt_at(key, route, current_unix_ms())
            .await;
    }

    pub async fn record_hybrid_route_outcome(
        &self,
        key: &StrategyKey,
        route: HybridRouteFamily,
        signal: FailSignal,
    ) {
        self.record_hybrid_route_outcome_at(key, route, signal, current_unix_ms())
            .await;
    }

    async fn record_hybrid_route_attempt_at(
        &self,
        key: &StrategyKey,
        route: HybridRouteFamily,
        now_unix_ms: u64,
    ) {
        let route_key = key.hash_key();
        self.state
            .update_touched(|snapshot, touched| {
                touched.key_registry.insert(route_key.clone());
                touched.hybrid_route_stats.insert(route_key.clone());
                snapshot.key_registry.insert(route_key.clone(), key.clone());
                let stats = snapshot.hybrid_route_stats.entry(route_key).or_default();
                match route {
                    HybridRouteFamily::DirectGeneva => {
                        stats.direct_attempts = stats.direct_attempts.saturating_add(1);
                        stats.last_direct_attempt_unix_ms = Some(now_unix_ms);
                    }
                    HybridRouteFamily::RelayGrpc => {
                        stats.relay_attempts = stats.relay_attempts.saturating_add(1);
                    }
                    HybridRouteFamily::RelayMasque | HybridRouteFamily::Block => {}
                }
            })
            .await;
        self.persist().await;
    }

    async fn record_hybrid_route_outcome_at(
        &self,
        key: &StrategyKey,
        route: HybridRouteFamily,
        signal: FailSignal,
        now_unix_ms: u64,
    ) {
        let route_key = key.hash_key();
        self.state
            .update_touched(|snapshot, touched| {
                touched.key_registry.insert(route_key.clone());
                touched.hybrid_route_stats.insert(route_key.clone());
                snapshot.key_registry.insert(route_key.clone(), key.clone());
                let stats = snapshot.hybrid_route_stats.entry(route_key).or_default();
                match route {
                    HybridRouteFamily::DirectGeneva => {
                        stats.last_direct_outcome_unix_ms = Some(now_unix_ms);
                        stats.last_direct_signal = Some(signal.clone());
                        if signal.is_success() {
                            stats.direct_successes = stats.direct_successes.saturating_add(1);
                            stats.consecutive_hostile_direct_failures = 0;
                            stats.last_direct_success_unix_ms = Some(now_unix_ms);
                        } else {
                            stats.direct_failures = stats.direct_failures.saturating_add(1);
                            if hostile_direct_signal(&signal) {
                                stats.consecutive_hostile_direct_failures =
                                    stats.consecutive_hostile_direct_failures.saturating_add(1);
                                stats.last_hostile_direct_failure_unix_ms = Some(now_unix_ms);
                            }
                        }
                    }
                    HybridRouteFamily::RelayGrpc => {
                        stats.last_relay_outcome_unix_ms = Some(now_unix_ms);
                        stats.last_relay_signal = Some(signal.clone());
                        if signal.is_success() {
                            stats.relay_successes = stats.relay_successes.saturating_add(1);
                            stats.last_relay_success_unix_ms = Some(now_unix_ms);
                        } else {
                            stats.relay_failures = stats.relay_failures.saturating_add(1);
                        }
                    }
                    HybridRouteFamily::RelayMasque | HybridRouteFamily::Block => {}
                }
            })
            .await;
        self.persist().await;
    }
}

pub fn hybrid_route_advisory_at(
    snapshot: &StateSnapshot,
    key: &StrategyKey,
    direct_capable: bool,
    now_unix_ms: u64,
) -> HybridRouteAdvisory {
    if key.ip_version != 4 {
        return advisory(
            HybridRouteFamily::RelayGrpc,
            HybridRouteSelectionReason::Ipv6RelayPolicy,
            HybridEvidenceConfidence::High,
            0,
            None,
        );
    }
    let external_hint = external_geneva_hint(snapshot, now_unix_ms).map(|hint| hint.signal);
    if let Some(route) = unresolved_hybrid_relay_advisory(direct_capable, external_hint.clone()) {
        return route;
    }

    let stats = snapshot.hybrid_route_stats.get(&key.hash_key());
    let Some(stats) = stats else {
        return advisory(
            HybridRouteFamily::DirectGeneva,
            HybridRouteSelectionReason::ColdStartExploration,
            HybridEvidenceConfidence::None,
            0,
            external_hint,
        );
    };

    if unresolved_direct_attempt_is_recent(stats, now_unix_ms) {
        return advisory(
            HybridRouteFamily::RelayGrpc,
            HybridRouteSelectionReason::DirectAttemptInFlight,
            HybridEvidenceConfidence::Low,
            DIRECT_ATTEMPT_GUARD_MS
                .saturating_sub(age_ms(stats.last_direct_attempt_unix_ms, now_unix_ms)),
            external_hint,
        );
    }

    let cooldown_ms = hostile_failure_cooldown_ms(stats.consecutive_hostile_direct_failures);
    let hostile_age = age_ms(stats.last_hostile_direct_failure_unix_ms, now_unix_ms);
    if stats.consecutive_hostile_direct_failures > 0 && hostile_age < cooldown_ms {
        return advisory(
            HybridRouteFamily::RelayGrpc,
            HybridRouteSelectionReason::RecentHostileDirectFailure,
            route_stats_confidence(stats),
            cooldown_ms.saturating_sub(hostile_age),
            external_hint,
        );
    }

    let success_age = age_ms(stats.last_direct_success_unix_ms, now_unix_ms);
    let success_is_newest = stats
        .last_direct_success_unix_ms
        .is_some_and(|success| success >= stats.last_hostile_direct_failure_unix_ms.unwrap_or(0));
    if success_is_newest && success_age < DIRECT_EVIDENCE_FRESH_MS {
        return advisory(
            HybridRouteFamily::DirectGeneva,
            HybridRouteSelectionReason::FreshDirectSuccess,
            route_stats_confidence(stats),
            0,
            external_hint,
        );
    }

    advisory(
        HybridRouteFamily::DirectGeneva,
        HybridRouteSelectionReason::EvidenceDecayedExploration,
        route_stats_confidence(stats),
        0,
        external_hint,
    )
}

fn unresolved_hybrid_relay_advisory(
    direct_capable: bool,
    external_hint: Option<FailSignal>,
) -> Option<HybridRouteAdvisory> {
    if !direct_capable {
        return Some(advisory(
            HybridRouteFamily::RelayGrpc,
            HybridRouteSelectionReason::DirectCapabilityUnavailable,
            HybridEvidenceConfidence::High,
            0,
            external_hint,
        ));
    }

    if let Some(FailSignal::ExternalClassifierHint {
        score_milli,
        confidence_milli,
        hard_block,
        ..
    }) = external_hint.as_ref()
    {
        if *hard_block {
            return Some(advisory(
                HybridRouteFamily::RelayGrpc,
                HybridRouteSelectionReason::ExternalClassifierHardBlock,
                classifier_confidence(*confidence_milli),
                0,
                external_hint,
            ));
        }
        if *score_milli <= 300 && *confidence_milli >= 600 {
            return Some(advisory(
                HybridRouteFamily::RelayGrpc,
                HybridRouteSelectionReason::ExternalClassifierPrefersRelay,
                classifier_confidence(*confidence_milli),
                0,
                external_hint,
            ));
        }
    }

    None
}

fn advisory(
    route: HybridRouteFamily,
    reason: HybridRouteSelectionReason,
    evidence_confidence: HybridEvidenceConfidence,
    direct_failure_cooldown_remaining_ms: u64,
    external_classifier_hint: Option<FailSignal>,
) -> HybridRouteAdvisory {
    HybridRouteAdvisory {
        route,
        reason,
        evidence_confidence,
        direct_failure_cooldown_remaining_ms,
        external_classifier_hint,
    }
}

fn unresolved_direct_attempt_is_recent(stats: &HybridRouteStats, now_unix_ms: u64) -> bool {
    let Some(attempt) = stats.last_direct_attempt_unix_ms else {
        return false;
    };
    if stats
        .last_direct_outcome_unix_ms
        .is_some_and(|outcome| outcome >= attempt)
    {
        return false;
    }
    now_unix_ms.saturating_sub(attempt) < DIRECT_ATTEMPT_GUARD_MS
}

fn hostile_failure_cooldown_ms(consecutive_failures: u32) -> u64 {
    if consecutive_failures == 0 {
        return 0;
    }
    let multiplier = 1u64 << consecutive_failures.saturating_sub(1).min(6);
    DIRECT_FAILURE_BASE_COOLDOWN_MS
        .saturating_mul(multiplier)
        .min(DIRECT_FAILURE_MAX_COOLDOWN_MS)
}

fn hostile_direct_signal(signal: &FailSignal) -> bool {
    signal.is_dpi_related()
        || matches!(
            signal,
            FailSignal::Timeout | FailSignal::ThroughputCollapse | FailSignal::SessionFreeze { .. }
        )
}

fn route_stats_confidence(stats: &HybridRouteStats) -> HybridEvidenceConfidence {
    let samples = stats
        .direct_successes
        .saturating_add(stats.direct_failures)
        .saturating_add(stats.relay_successes)
        .saturating_add(stats.relay_failures);
    match samples {
        0 => HybridEvidenceConfidence::None,
        1 => HybridEvidenceConfidence::Low,
        2..=4 => HybridEvidenceConfidence::Medium,
        _ => HybridEvidenceConfidence::High,
    }
}

fn classifier_confidence(confidence_milli: u16) -> HybridEvidenceConfidence {
    match confidence_milli {
        0..=249 => HybridEvidenceConfidence::Low,
        250..=749 => HybridEvidenceConfidence::Medium,
        _ => HybridEvidenceConfidence::High,
    }
}

fn age_ms(timestamp: Option<u64>, now_unix_ms: u64) -> u64 {
    timestamp
        .map(|timestamp| now_unix_ms.saturating_sub(timestamp))
        .unwrap_or(u64::MAX)
}

fn external_geneva_hint(snapshot: &StateSnapshot, now_unix_ms: u64) -> Option<ExternalGenevaHint> {
    let calibration = snapshot.external_calibration.as_ref()?;
    let freshness = calibration_freshness(calibration, now_unix_ms);
    if freshness < 0.1 {
        return None;
    }

    let knowledge = calibration
        .knowledge
        .iter()
        .filter(|prior| {
            matches!(
                normalize_label(&prior.target_class).as_str(),
                "geneva" | "direct_geneva"
            )
        })
        .filter_map(|prior| {
            // A knowledge record can predate the aggregate snapshot. Decay it
            // from its own timestamp as well, so refreshing unrelated
            // classifier data cannot make stale Geneva evidence fresh again.
            let record_freshness = prior
                .generated_at_unix_ms
                .map(|generated_at| {
                    timestamp_freshness(
                        generated_at,
                        calibration.freshness_half_life_secs,
                        now_unix_ms,
                    )
                })
                .unwrap_or(freshness);
            let confidence = (prior.confidence.clamp(0.0, 1.0) * freshness.min(record_freshness))
                .clamp(0.0, 1.0);
            (confidence >= 0.1).then_some((prior, confidence))
        })
        .max_by(|(_, left), (_, right)| left.total_cmp(right));
    let adversarial = calibration.adversarial.iter().find(|entry| {
        matches!(
            normalize_label(&entry.transport).as_str(),
            "geneva" | "direct_geneva"
        ) && entry.measured > 0
    });
    let witness = calibration.witness.iter().find(|entry| {
        matches!(
            normalize_label(&entry.label).as_str(),
            "geneva" | "direct_geneva"
        ) && entry.records > 0
    });

    let (score, confidence, hard_block, source) = if let Some((prior, confidence)) = knowledge {
        (
            prior.score.clamp(0.0, 1.0),
            confidence,
            (prior.hard_excluded || prior.fail_closed) && prior.score <= 0.05,
            "external_knowledge",
        )
    } else if let Some(entry) = adversarial {
        let score = entry.pass_rate?.clamp(0.0, 1.0);
        let confidence = (record_confidence(entry.measured) * freshness).clamp(0.0, 1.0);
        (score, confidence, false, "external_adversarial")
    } else {
        let entry = witness?;
        (
            entry.combined_avg.clamp(0.0, 1.0),
            (record_confidence(entry.records) * freshness).clamp(0.0, 1.0),
            false,
            "external_witness",
        )
    };
    if confidence < 0.1 {
        return None;
    }

    let signal = FailSignal::ExternalClassifierHint {
        source: source.to_string(),
        score_milli: to_milli(score),
        confidence_milli: to_milli(confidence),
        hard_block: hard_block && confidence >= 0.85,
    };
    // Fingerprint the applied snapshot itself, not the time-decayed effective
    // confidence. Otherwise confidence crossing a milli boundary would ingest
    // the same classifier evidence again on later connections.
    let fingerprint_bytes = serde_json::to_vec(calibration).ok()?;
    let fingerprint = hex::encode(Sha256::digest(&fingerprint_bytes));
    Some(ExternalGenevaHint {
        signal,
        fingerprint,
    })
}

fn calibration_freshness(calibration: &ExternalCalibrationSnapshot, now_unix_ms: u64) -> f64 {
    let Some(generated_at) = calibration.generated_at_unix_ms else {
        return 1.0;
    };
    timestamp_freshness(
        generated_at,
        calibration.freshness_half_life_secs,
        now_unix_ms,
    )
}

fn timestamp_freshness(
    generated_at_unix_ms: u64,
    freshness_half_life_secs: Option<u64>,
    now_unix_ms: u64,
) -> f64 {
    if generated_at_unix_ms >= now_unix_ms {
        return 1.0;
    }
    let half_life_secs = freshness_half_life_secs.unwrap_or(DEFAULT_CALIBRATION_HALF_LIFE_SECS);
    if half_life_secs == 0 {
        return 0.0;
    }
    let age_secs = (now_unix_ms - generated_at_unix_ms) as f64 / 1_000.0;
    2.0_f64
        .powf(-(age_secs / half_life_secs as f64))
        .clamp(0.0, 1.0)
}

fn record_confidence(records: u64) -> f64 {
    (records.min(20) as f64 / 20.0).clamp(0.0, 1.0)
}

fn to_milli(value: f64) -> u16 {
    (value.clamp(0.0, 1.0) * 1_000.0).round() as u16
}

fn normalize_label(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('-', "_")
}

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::external_calibration::{
        ExternalAdversarialCalibration, ExternalCalibrationSnapshot, ExternalKnowledgePrior,
    };
    use crate::state_v2::AsyncStateStore;
    use std::net::SocketAddr;
    use tempfile::TempDir;

    fn key(ip: &str) -> StrategyKey {
        StrategyKey::for_target(
            SocketAddr::new(ip.parse().expect("ip"), 443),
            "blocked.example",
            443,
            Some("blocked.example"),
            true,
        )
    }

    #[test]
    fn cold_start_attempt_is_bounded_and_hostile_failure_cools_down() {
        let key = key("203.0.113.9");
        let mut snapshot = StateSnapshot::default();
        let now = 1_000_000;

        let cold = hybrid_route_advisory_at(&snapshot, &key, true, now);
        assert_eq!(cold.route, HybridRouteFamily::DirectGeneva);
        assert_eq!(
            cold.reason,
            HybridRouteSelectionReason::ColdStartExploration
        );

        snapshot.hybrid_route_stats.insert(
            key.hash_key(),
            HybridRouteStats {
                direct_attempts: 1,
                last_direct_attempt_unix_ms: Some(now),
                ..Default::default()
            },
        );
        let guarded = hybrid_route_advisory_at(&snapshot, &key, true, now + 1_000);
        assert_eq!(guarded.route, HybridRouteFamily::RelayGrpc);
        assert_eq!(
            guarded.reason,
            HybridRouteSelectionReason::DirectAttemptInFlight
        );

        let stats = snapshot
            .hybrid_route_stats
            .get_mut(&key.hash_key())
            .expect("route stats");
        stats.direct_failures = 1;
        stats.consecutive_hostile_direct_failures = 1;
        stats.last_direct_outcome_unix_ms = Some(now + 2_000);
        stats.last_hostile_direct_failure_unix_ms = Some(now + 2_000);
        stats.last_direct_signal = Some(FailSignal::DropSuspected);

        let cooled = hybrid_route_advisory_at(&snapshot, &key, true, now + 3_000);
        assert_eq!(cooled.route, HybridRouteFamily::RelayGrpc);
        assert_eq!(
            cooled.reason,
            HybridRouteSelectionReason::RecentHostileDirectFailure
        );
        assert!(cooled.direct_failure_cooldown_remaining_ms > 0);

        let explored = hybrid_route_advisory_at(
            &snapshot,
            &key,
            true,
            now + 2_000 + DIRECT_FAILURE_BASE_COOLDOWN_MS,
        );
        assert_eq!(explored.route, HybridRouteFamily::DirectGeneva);
        assert_eq!(
            explored.reason,
            HybridRouteSelectionReason::EvidenceDecayedExploration
        );
    }

    #[test]
    fn fresh_success_confidence_decays_without_pin() {
        let key = key("203.0.113.10");
        let now = 5_000_000;
        let snapshot = StateSnapshot {
            hybrid_route_stats: std::collections::HashMap::from([(
                key.hash_key(),
                HybridRouteStats {
                    direct_attempts: 1,
                    direct_successes: 1,
                    last_direct_attempt_unix_ms: Some(now),
                    last_direct_outcome_unix_ms: Some(now),
                    last_direct_success_unix_ms: Some(now),
                    last_direct_signal: Some(FailSignal::Success),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };

        let fresh = hybrid_route_advisory_at(&snapshot, &key, true, now + 1_000);
        assert_eq!(fresh.route, HybridRouteFamily::DirectGeneva);
        assert_eq!(fresh.reason, HybridRouteSelectionReason::FreshDirectSuccess);

        let decayed =
            hybrid_route_advisory_at(&snapshot, &key, true, now + DIRECT_EVIDENCE_FRESH_MS + 1);
        assert_eq!(decayed.route, HybridRouteFamily::DirectGeneva);
        assert_eq!(
            decayed.reason,
            HybridRouteSelectionReason::EvidenceDecayedExploration
        );
    }

    #[test]
    fn fresh_hard_classifier_hint_routes_relay_then_expires() {
        let key = key("203.0.113.11");
        let now = 10_000_000;
        let snapshot = StateSnapshot {
            external_calibration: Some(ExternalCalibrationSnapshot {
                source: "controlled-classifier".into(),
                generated_at_unix_ms: Some(now),
                freshness_half_life_secs: Some(60),
                knowledge: vec![ExternalKnowledgePrior {
                    target_class: "direct_geneva".into(),
                    score: 0.0,
                    confidence: 1.0,
                    hard_excluded: true,
                    fail_closed: true,
                    generated_at_unix_ms: Some(now),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };

        let blocked = hybrid_route_advisory_at(&snapshot, &key, true, now + 1_000);
        assert_eq!(blocked.route, HybridRouteFamily::RelayGrpc);
        assert_eq!(
            blocked.reason,
            HybridRouteSelectionReason::ExternalClassifierHardBlock
        );
        assert!(matches!(
            blocked.external_classifier_hint,
            Some(FailSignal::ExternalClassifierHint {
                hard_block: true,
                ..
            })
        ));

        let expired = hybrid_route_advisory_at(&snapshot, &key, true, now + 10 * 60 * 1_000);
        assert_eq!(expired.route, HybridRouteFamily::DirectGeneva);
        assert_eq!(
            expired.reason,
            HybridRouteSelectionReason::ColdStartExploration
        );
    }

    #[test]
    fn stale_knowledge_prior_is_not_refreshed_by_newer_snapshot() {
        let key = key("203.0.113.14");
        let now = 20_000_000;
        let snapshot = StateSnapshot {
            external_calibration: Some(ExternalCalibrationSnapshot {
                source: "mixed-age-classifier".into(),
                generated_at_unix_ms: Some(now),
                freshness_half_life_secs: Some(60),
                knowledge: vec![ExternalKnowledgePrior {
                    target_class: "direct_geneva".into(),
                    score: 0.0,
                    confidence: 1.0,
                    hard_excluded: true,
                    fail_closed: true,
                    generated_at_unix_ms: Some(now - 10 * 60 * 1_000),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };

        let advisory = hybrid_route_advisory_at(&snapshot, &key, true, now);
        assert_eq!(advisory.route, HybridRouteFamily::DirectGeneva);
        assert_eq!(
            advisory.reason,
            HybridRouteSelectionReason::ColdStartExploration
        );
        assert!(advisory.external_classifier_hint.is_none());
    }

    #[test]
    fn stale_knowledge_prior_does_not_mask_fresh_measured_evidence() {
        let key = key("203.0.113.15");
        let now = 30_000_000;
        let snapshot = StateSnapshot {
            external_calibration: Some(ExternalCalibrationSnapshot {
                source: "mixed-source-classifier".into(),
                generated_at_unix_ms: Some(now),
                freshness_half_life_secs: Some(60),
                knowledge: vec![ExternalKnowledgePrior {
                    target_class: "direct_geneva".into(),
                    score: 1.0,
                    confidence: 1.0,
                    generated_at_unix_ms: Some(now - 10 * 60 * 1_000),
                    ..Default::default()
                }],
                adversarial: vec![ExternalAdversarialCalibration {
                    transport: "geneva".into(),
                    records: 20,
                    measured: 20,
                    planned: 20,
                    passed: 0,
                    failed: 20,
                    pass_rate: Some(0.0),
                    threshold: Some(0.8),
                }],
                ..Default::default()
            }),
            ..Default::default()
        };

        let advisory = hybrid_route_advisory_at(&snapshot, &key, true, now);
        assert_eq!(advisory.route, HybridRouteFamily::RelayGrpc);
        assert_eq!(
            advisory.reason,
            HybridRouteSelectionReason::ExternalClassifierPrefersRelay
        );
        assert!(matches!(
            advisory.external_classifier_hint,
            Some(FailSignal::ExternalClassifierHint { ref source, .. })
                if source == "external_adversarial"
        ));
    }

    #[tokio::test]
    async fn classifier_hint_is_recorded_once_and_survives_restart() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("state.json");
        let key = key("203.0.113.12");
        let store = AsyncStateStore::load(path.clone()).await.expect("store");
        store
            .update(|snapshot| {
                snapshot.external_calibration = Some(ExternalCalibrationSnapshot {
                    source: "runtime-classifier".into(),
                    generated_at_unix_ms: Some(current_unix_ms()),
                    freshness_half_life_secs: Some(3_600),
                    knowledge: vec![ExternalKnowledgePrior {
                        target_class: "geneva".into(),
                        score: 0.0,
                        confidence: 1.0,
                        hard_excluded: true,
                        fail_closed: true,
                        generated_at_unix_ms: Some(current_unix_ms()),
                        ..Default::default()
                    }],
                    ..Default::default()
                });
            })
            .await;
        let brain = Brain::new(0.0, vec!["geneva".into()], store.clone());

        let first = brain.select_hybrid_route(&key, true).await;
        let second = brain.select_hybrid_route(&key, true).await;
        assert_eq!(first.route, HybridRouteFamily::RelayGrpc);
        assert_eq!(second.route, HybridRouteFamily::RelayGrpc);
        let snapshot = store.snapshot().await;
        let stats = snapshot
            .strategy_stats
            .get(&strategy_entry_key(&key.hash_key(), "geneva"))
            .expect("classifier strategy record");
        assert_eq!(stats.trials, 1, "same snapshot must be ingested once");
        store.flush().await.expect("flush");

        let restored = AsyncStateStore::load(path).await.expect("restored store");
        let restored_snapshot = restored.snapshot().await;
        assert!(restored_snapshot
            .hybrid_route_stats
            .contains_key(&key.hash_key()));
        assert_eq!(
            restored_snapshot
                .strategy_stats
                .get(&strategy_entry_key(&key.hash_key(), "geneva"))
                .expect("restored classifier record")
                .trials,
            1
        );
    }

    #[tokio::test]
    async fn route_outcomes_share_one_persisted_record() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("state.json");
        let key = key("203.0.113.13");
        let store = AsyncStateStore::load(path).await.expect("store");
        let brain = Brain::new(0.0, vec!["geneva".into()], store);

        brain
            .record_hybrid_route_attempt_at(&key, HybridRouteFamily::DirectGeneva, 1_000)
            .await;
        brain
            .record_hybrid_route_outcome_at(
                &key,
                HybridRouteFamily::DirectGeneva,
                FailSignal::DropSuspected,
                2_000,
            )
            .await;
        brain
            .record_hybrid_route_attempt_at(&key, HybridRouteFamily::RelayGrpc, 3_000)
            .await;
        brain
            .record_hybrid_route_outcome_at(
                &key,
                HybridRouteFamily::RelayGrpc,
                FailSignal::Success,
                4_000,
            )
            .await;

        let snapshot = brain.state.snapshot().await;
        let stats = snapshot
            .hybrid_route_stats
            .get(&key.hash_key())
            .expect("shared route record");
        assert_eq!(stats.direct_attempts, 1);
        assert_eq!(stats.direct_failures, 1);
        assert_eq!(stats.consecutive_hostile_direct_failures, 1);
        assert_eq!(stats.relay_attempts, 1);
        assert_eq!(stats.relay_successes, 1);
        assert_ne!(
            strategy_entry_key(&key.hash_key(), "geneva"),
            strategy_entry_key(&key.hash_key(), "grpc_stream")
        );
    }
}
