pub(crate) use aegis_client::mimicry_runtime_surface::build_mimicry_capability_plan;
use aegis_client::mimicry_runtime_surface::supports_adaptive_ttl_planning;
#[cfg(test)]
use aegis_client::mimicry_runtime_surface::MimicryCapabilityPlan;
use aegis_core::ghost_lurk::GhostLurk;
use aegis_core::probe::canonical_initial_ttl;
use aegis_core::stealth_rotation::{current_unix_secs, surface_epoch, DriftSurface};
use aegis_core::{
    active_probe_budget, active_probe_ttl_candidates, default_raw_engine, preferred_probe_ttl,
    ChecksumTrickStrategy, DirectTerminalReason, FakeDisorderStrategy, FakeRstStrategy,
    IpFragStrategy, KeyObservation, MultisplitStrategy, OobDataStrategy, OverlapStrategy,
    PassthroughStrategy, RawCapabilities, Strategy, TtlDesyncStrategy, TtlPatternStrategy,
};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;

pub struct DirectPlan {
    pub strategies: Vec<Arc<dyn Strategy + 'static>>,
    pub empty_reason: Option<DirectTerminalReason>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActiveProbePlan {
    pub preferred_ttl: u8,
    pub budget: usize,
    pub candidates: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectFingerprintFamily {
    family_id: &'static str,
    raw_decoy_ttl_candidates: &'static [u8],
    overlap_candidates: &'static [usize],
    ip_frag_first_payload_len_candidates: &'static [usize],
    ip_frag_overlap_candidates: &'static [usize],
    fake_disorder_split_at_candidates: &'static [usize],
    checksum_ttl_candidates: &'static [u8],
    ttl_pattern_ttl_candidates: &'static [u32],
    multisplit_profiles: &'static [(usize, usize)],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectFingerprintProfile {
    family_id: &'static str,
    raw_decoy_ttl: u8,
    overlap_bytes: usize,
    ip_frag_first_payload_len: usize,
    ip_frag_overlap: usize,
    fake_disorder_split_at: usize,
    checksum_ttl: u8,
    ttl_pattern_ttl: u32,
    multisplit_min_part: usize,
    multisplit_max_part: usize,
}

const DIRECT_PROFILE_EPOCH_SECS: u64 = 900;
const DIRECT_SUBFEATURE_EPOCH_SECS: u64 = 240;

const DIRECT_PROFILE_CATALOG: [DirectFingerprintFamily; 8] = [
    DirectFingerprintFamily {
        family_id: "browser_split_balanced",
        raw_decoy_ttl_candidates: &[3, 4, 5],
        overlap_candidates: &[8, 10, 12],
        ip_frag_first_payload_len_candidates: &[24, 28, 32],
        ip_frag_overlap_candidates: &[8, 10],
        fake_disorder_split_at_candidates: &[22, 24, 28],
        checksum_ttl_candidates: &[60, 61, 64],
        ttl_pattern_ttl_candidates: &[60, 64],
        multisplit_profiles: &[(8, 128), (10, 112), (12, 96)],
    },
    DirectFingerprintFamily {
        family_id: "browser_split_wide",
        raw_decoy_ttl_candidates: &[4, 5, 6],
        overlap_candidates: &[10, 12, 14],
        ip_frag_first_payload_len_candidates: &[28, 32, 36],
        ip_frag_overlap_candidates: &[10, 12],
        fake_disorder_split_at_candidates: &[26, 28, 32],
        checksum_ttl_candidates: &[60, 61, 62],
        ttl_pattern_ttl_candidates: &[60, 61],
        multisplit_profiles: &[(12, 96), (14, 104), (16, 112)],
    },
    DirectFingerprintFamily {
        family_id: "mobile_compact",
        raw_decoy_ttl_candidates: &[2, 3, 4],
        overlap_candidates: &[6, 8],
        ip_frag_first_payload_len_candidates: &[18, 20, 24],
        ip_frag_overlap_candidates: &[4, 6, 8],
        fake_disorder_split_at_candidates: &[18, 20, 22],
        checksum_ttl_candidates: &[62, 63, 64],
        ttl_pattern_ttl_candidates: &[63, 64],
        multisplit_profiles: &[(12, 72), (16, 80), (20, 88)],
    },
    DirectFingerprintFamily {
        family_id: "cli_conservative",
        raw_decoy_ttl_candidates: &[4, 5, 7],
        overlap_candidates: &[10, 12],
        ip_frag_first_payload_len_candidates: &[32, 36, 40],
        ip_frag_overlap_candidates: &[10, 12, 14],
        fake_disorder_split_at_candidates: &[28, 30, 34],
        checksum_ttl_candidates: &[58, 60, 61],
        ttl_pattern_ttl_candidates: &[58, 60],
        multisplit_profiles: &[(10, 72), (12, 80), (14, 88)],
    },
    DirectFingerprintFamily {
        family_id: "browser_fragment_dense",
        raw_decoy_ttl_candidates: &[3, 5, 6],
        overlap_candidates: &[12, 14, 16],
        ip_frag_first_payload_len_candidates: &[30, 34, 38],
        ip_frag_overlap_candidates: &[12, 14],
        fake_disorder_split_at_candidates: &[24, 30, 36],
        checksum_ttl_candidates: &[59, 60, 62],
        ttl_pattern_ttl_candidates: &[59, 60, 62],
        multisplit_profiles: &[(8, 96), (10, 104), (12, 120)],
    },
    DirectFingerprintFamily {
        family_id: "mobile_burst_fragmented",
        raw_decoy_ttl_candidates: &[2, 4, 5],
        overlap_candidates: &[5, 6, 8],
        ip_frag_first_payload_len_candidates: &[16, 18, 22],
        ip_frag_overlap_candidates: &[4, 6],
        fake_disorder_split_at_candidates: &[16, 18, 20],
        checksum_ttl_candidates: &[61, 63, 64],
        ttl_pattern_ttl_candidates: &[61, 63, 64],
        multisplit_profiles: &[(14, 64), (16, 72), (18, 80)],
    },
    DirectFingerprintFamily {
        family_id: "desktop_latency_smoothed",
        raw_decoy_ttl_candidates: &[5, 6, 7],
        overlap_candidates: &[9, 11, 13],
        ip_frag_first_payload_len_candidates: &[26, 30, 34],
        ip_frag_overlap_candidates: &[8, 10, 12],
        fake_disorder_split_at_candidates: &[24, 27, 30],
        checksum_ttl_candidates: &[60, 62, 63],
        ttl_pattern_ttl_candidates: &[60, 62],
        multisplit_profiles: &[(10, 88), (12, 96), (14, 104)],
    },
    DirectFingerprintFamily {
        family_id: "edge_middlebox_evasive",
        raw_decoy_ttl_candidates: &[1, 2, 3],
        overlap_candidates: &[7, 9, 11],
        ip_frag_first_payload_len_candidates: &[22, 26, 30],
        ip_frag_overlap_candidates: &[6, 8, 10],
        fake_disorder_split_at_candidates: &[20, 24, 28],
        checksum_ttl_candidates: &[57, 59, 60],
        ttl_pattern_ttl_candidates: &[57, 60],
        multisplit_profiles: &[(8, 84), (10, 92), (12, 100)],
    },
];

pub fn build_direct_plan(
    ordered: Vec<String>,
    allowed: &[String],
    dst: SocketAddr,
    ghost: Option<Arc<GhostLurk>>,
    observation: Option<&KeyObservation>,
) -> DirectPlan {
    build_direct_plan_with_caps(
        ordered,
        allowed,
        dst,
        ghost,
        observation,
        default_raw_engine().capabilities(),
    )
}

/// Строит план active stall probe: preferred TTL, список кандидатов и бюджет.
///
/// # Multi-TTL ladder — архитектурное решение
///
/// Цикл по кандидатам **не реализован внутри** `run_active_stall_probe` — это намеренно.
/// Вместо этого используется **внешний retry-путь через `inline_probe_retries`** в `direct.rs`:
///
/// 1. После каждого `ActiveProbeCycleDecision::RetryDirect` функция вызывается повторно
///    с обновлённым `current_observation` из brain advisory.
/// 2. На каждой итерации `preferred_ttl` может измениться, так как brain накапливает
///    историю и observation обновляется.
/// 3. `candidates` — упорядоченный список кандидатов на весь retry-сеанс, но
///    выбор конкретного TTL делается через `preferred_probe_ttl()` на базе текущих
///    данных, а не итерацией по массиву.
///
/// Это позволяет brain корректировать TTL-выбор между retry-попытками без жёсткой
/// привязки к изначальному порядку кандидатов.
#[allow(dead_code)]
pub(crate) fn build_active_probe_plan(observation: Option<&KeyObservation>) -> ActiveProbePlan {
    build_active_probe_plan_for_dst("203.0.113.1:443".parse().unwrap(), observation)
}

pub(crate) fn build_active_probe_plan_for_dst(
    dst: SocketAddr,
    observation: Option<&KeyObservation>,
) -> ActiveProbePlan {
    build_active_probe_plan_for_dst_with_time(dst, observation, current_unix_secs())
}

#[cfg(test)]
fn build_active_probe_plan_for_dst_with_time(
    dst: SocketAddr,
    observation: Option<&KeyObservation>,
    now_secs: u64,
) -> ActiveProbePlan {
    let fallback = direct_fingerprint_profile_with_time(dst, observation, now_secs).raw_decoy_ttl;
    let budget = active_raw_probe_budget(observation);
    let candidates = active_raw_decoy_ttl_candidates(observation, fallback);
    let preferred_ttl = adaptive_raw_decoy_ttl(observation, fallback);
    ActiveProbePlan {
        preferred_ttl,
        budget,
        candidates,
    }
}

#[cfg(not(test))]
fn build_active_probe_plan_for_dst_with_time(
    dst: SocketAddr,
    observation: Option<&KeyObservation>,
    now_secs: u64,
) -> ActiveProbePlan {
    let fallback = direct_fingerprint_profile_with_time(dst, observation, now_secs).raw_decoy_ttl;
    let budget = active_raw_probe_budget(observation);
    let candidates = active_raw_decoy_ttl_candidates(observation, fallback);
    let preferred_ttl = adaptive_raw_decoy_ttl(observation, fallback);
    ActiveProbePlan {
        preferred_ttl,
        budget,
        candidates,
    }
}

fn build_direct_plan_with_caps(
    ordered: Vec<String>,
    allowed: &[String],
    dst: SocketAddr,
    ghost: Option<Arc<GhostLurk>>,
    observation: Option<&KeyObservation>,
    raw_caps: RawCapabilities,
) -> DirectPlan {
    let mut strategies = Vec::new();
    let mut filtered: Vec<&'static str> = Vec::new();
    let mut empty_reason = None;
    for id in ordered {
        if !allowed.iter().any(|item| item == &id) {
            continue;
        }
        for strategy in instantiate_strategies(&id, dst, ghost.clone(), observation) {
            let requirements = strategy.requirements();
            if let Some(reason) = requirements.unsatisfied_reason(dst, raw_caps) {
                tracing::debug!(
                    strategy = strategy.id(),
                    ?dst,
                    ?raw_caps,
                    ?requirements,
                    terminal_reason = reason.as_str(),
                    "planner filtered unsupported direct strategy"
                );
                if !filtered.contains(&strategy.id()) {
                    filtered.push(strategy.id());
                }
                empty_reason = Some(prefer_terminal_reason(empty_reason, reason));
                continue;
            }
            strategies.push(strategy);
        }
    }
    // An empty plan is a session that cannot run, and the reason was only ever
    // at DEBUG. In practice that surfaced as `session: no strategy (Unknown)`
    // with nothing to act on: on a host without raw sockets EVERY
    // packet-shaping strategy — geneva, ttl_desync, overlap, the lot — is
    // filtered here, and only `passthrough` survives. An operator who
    // configured Geneva sees it selected in the config, no error at startup,
    // and a dead session.
    //
    // Say it once, with the capabilities that caused it, so the next person
    // does not have to reach for RUST_LOG=debug to learn that the box cannot
    // send raw IPv4.
    if strategies.is_empty() && !filtered.is_empty() {
        tracing::warn!(
            event_code = "direct_plan_empty_after_capability_filter",
            filtered = %filtered.join(","),
            ipv4_raw_send = raw_caps.ipv4_raw_send,
            ipv4_packet_capture = raw_caps.ipv4_packet_capture,
            ipv4_header_control = raw_caps.ipv4_header_control,
            terminal_reason = empty_reason
                .unwrap_or(DirectTerminalReason::NoExecutableStrategy)
                .as_str(),
            ?dst,
            "every configured direct strategy needs capabilities this host lacks; \
             the direct plan is terminal. An explicit fallback mode may hand the \
             flow to a ready relay; otherwise it fails closed."
        );
    }
    let empty_reason = strategies
        .is_empty()
        .then_some(empty_reason.unwrap_or(DirectTerminalReason::NoExecutableStrategy));
    DirectPlan {
        strategies,
        empty_reason,
    }
}

fn prefer_terminal_reason(
    current: Option<DirectTerminalReason>,
    candidate: DirectTerminalReason,
) -> DirectTerminalReason {
    match (current, candidate) {
        (Some(DirectTerminalReason::UnsupportedAddressFamily), _) => {
            DirectTerminalReason::UnsupportedAddressFamily
        }
        (_, DirectTerminalReason::UnsupportedAddressFamily) => {
            DirectTerminalReason::UnsupportedAddressFamily
        }
        (Some(reason), _) => reason,
        (None, reason) => reason,
    }
}

fn instantiate_strategies(
    id: &str,
    dst: SocketAddr,
    ghost: Option<Arc<GhostLurk>>,
    observation: Option<&KeyObservation>,
) -> Vec<Arc<dyn Strategy + 'static>> {
    let profile = direct_fingerprint_profile(dst, observation);
    match id {
        "multisplit" => vec![Arc::new(MultisplitStrategy {
            ghost,
            min_part: profile.multisplit_min_part,
            max_part: profile.multisplit_max_part,
        })],
        "overlap" => active_raw_decoy_ttl_candidates(observation, OverlapStrategy::default().ttl)
            .into_iter()
            .map(|ttl| {
                Arc::new(OverlapStrategy {
                    ttl,
                    overlap: profile.overlap_bytes,
                    ..Default::default()
                }) as Arc<dyn Strategy + 'static>
            })
            .collect(),
        "ttl_pattern" => vec![Arc::new(TtlPatternStrategy {
            ttl: adaptive_ttl_pattern_ttl(observation, profile.ttl_pattern_ttl),
        })],
        "ttl_desync" => active_raw_decoy_ttl_candidates(observation, profile.raw_decoy_ttl)
            .into_iter()
            .map(|ttl| {
                Arc::new(TtlDesyncStrategy {
                    ttl,
                    ..Default::default()
                }) as Arc<dyn Strategy + 'static>
            })
            .collect(),
        "ip_frag" => active_raw_decoy_ttl_candidates(observation, profile.raw_decoy_ttl)
            .into_iter()
            .map(|ttl| {
                Arc::new(IpFragStrategy {
                    ttl,
                    first_payload_len: profile.ip_frag_first_payload_len,
                    overlap: profile.ip_frag_overlap,
                    ..Default::default()
                }) as Arc<dyn Strategy + 'static>
            })
            .collect(),
        "fake_disorder" => active_raw_decoy_ttl_candidates(observation, profile.raw_decoy_ttl)
            .into_iter()
            .map(|ttl| {
                Arc::new(FakeDisorderStrategy {
                    ttl,
                    split_at: profile.fake_disorder_split_at,
                    ..Default::default()
                }) as Arc<dyn Strategy + 'static>
            })
            .collect(),
        "checksum_trick" => vec![Arc::new(ChecksumTrickStrategy {
            ttl: profile.checksum_ttl,
            ..Default::default()
        })],
        "passthrough" => vec![Arc::new(PassthroughStrategy)],
        "fake_rst" => vec![Arc::new(FakeRstStrategy::default())],
        "oob_data" => vec![Arc::new(OobDataStrategy)],
        // Only present when direct.geneva_strategy is configured; the evolved
        // program supplies the decoy plan instead of a hardcoded one.
        "geneva" => aegis_core::strategies::geneva_configured_strategy(dst.port() as u64)
            .map(|s| Arc::new(s) as Arc<dyn Strategy + 'static>)
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

fn direct_fingerprint_profile(
    dst: SocketAddr,
    observation: Option<&KeyObservation>,
) -> DirectFingerprintProfile {
    direct_fingerprint_profile_with_time(dst, observation, current_unix_secs())
}

fn direct_fingerprint_profile_with_time(
    dst: SocketAddr,
    observation: Option<&KeyObservation>,
    now_secs: u64,
) -> DirectFingerprintProfile {
    let family_epoch = surface_epoch(
        DIRECT_PROFILE_EPOCH_SECS,
        now_secs,
        DriftSurface::DirectFingerprint,
    );
    let feature_epoch = surface_epoch(
        DIRECT_SUBFEATURE_EPOCH_SECS,
        now_secs,
        DriftSurface::DirectFingerprint,
    );
    direct_fingerprint_profile_with_epoch(dst, observation, family_epoch, feature_epoch)
}

#[cfg(test)]
pub(crate) fn direct_profile_family_for_time(
    dst: SocketAddr,
    observation: Option<&KeyObservation>,
    now_secs: u64,
) -> &'static str {
    direct_fingerprint_profile_with_time(dst, observation, now_secs).family_id
}

fn direct_fingerprint_profile_with_epoch(
    dst: SocketAddr,
    observation: Option<&KeyObservation>,
    family_epoch: u64,
    feature_epoch: u64,
) -> DirectFingerprintProfile {
    let family = direct_fingerprint_family_with_epoch(dst, observation, family_epoch);
    let multisplit_profile = direct_family_variant(
        dst,
        observation,
        feature_epoch,
        "multisplit",
        family.multisplit_profiles,
    );
    DirectFingerprintProfile {
        family_id: family.family_id,
        raw_decoy_ttl: direct_family_variant(
            dst,
            observation,
            feature_epoch,
            "raw-decoy-ttl",
            family.raw_decoy_ttl_candidates,
        ),
        overlap_bytes: direct_family_variant(
            dst,
            observation,
            feature_epoch,
            "overlap",
            family.overlap_candidates,
        ),
        ip_frag_first_payload_len: direct_family_variant(
            dst,
            observation,
            feature_epoch,
            "ip-frag-first-payload",
            family.ip_frag_first_payload_len_candidates,
        ),
        ip_frag_overlap: direct_family_variant(
            dst,
            observation,
            feature_epoch,
            "ip-frag-overlap",
            family.ip_frag_overlap_candidates,
        ),
        fake_disorder_split_at: direct_family_variant(
            dst,
            observation,
            feature_epoch,
            "fake-disorder-split",
            family.fake_disorder_split_at_candidates,
        ),
        checksum_ttl: direct_family_variant(
            dst,
            observation,
            feature_epoch,
            "checksum-ttl",
            family.checksum_ttl_candidates,
        ),
        ttl_pattern_ttl: direct_family_variant(
            dst,
            observation,
            feature_epoch,
            "ttl-pattern",
            family.ttl_pattern_ttl_candidates,
        ),
        multisplit_min_part: multisplit_profile.0,
        multisplit_max_part: multisplit_profile.1,
    }
}

fn direct_fingerprint_family_with_epoch(
    dst: SocketAddr,
    observation: Option<&KeyObservation>,
    epoch: u64,
) -> DirectFingerprintFamily {
    let mut hasher = Sha256::new();
    hasher.update(b"direct-fingerprint-profile");
    hasher.update(dst.ip().to_string().as_bytes());
    hasher.update(dst.port().to_le_bytes());
    hasher.update(epoch.to_le_bytes());
    if let Some(observation) = observation {
        hasher.update(observation.observation_capture_confidence().as_bytes());
        hasher.update(
            observation
                .reference_path_hops()
                .unwrap_or_default()
                .to_le_bytes(),
        );
        hasher.update(
            observation
                .rst_path_hops()
                .unwrap_or_default()
                .to_le_bytes(),
        );
    }
    let digest = hasher.finalize();
    DIRECT_PROFILE_CATALOG[(digest[0] as usize) % DIRECT_PROFILE_CATALOG.len()]
}

fn direct_family_variant<T: Copy>(
    dst: SocketAddr,
    observation: Option<&KeyObservation>,
    epoch: u64,
    label: &'static str,
    candidates: &[T],
) -> T {
    let idx = direct_variant_index(dst, observation, epoch, label, candidates.len());
    candidates[idx]
}

fn direct_variant_index(
    dst: SocketAddr,
    observation: Option<&KeyObservation>,
    epoch: u64,
    label: &'static str,
    len: usize,
) -> usize {
    debug_assert!(len > 0);
    let mut hasher = Sha256::new();
    hasher.update(b"direct-fingerprint-variant");
    hasher.update(label.as_bytes());
    hasher.update(dst.ip().to_string().as_bytes());
    hasher.update(dst.port().to_le_bytes());
    hasher.update(epoch.to_le_bytes());
    if let Some(observation) = observation {
        hasher.update(observation.observation_capture_confidence().as_bytes());
        hasher.update(
            observation
                .reference_path_hops()
                .unwrap_or_default()
                .to_le_bytes(),
        );
        hasher.update(
            observation
                .rst_path_hops()
                .unwrap_or_default()
                .to_le_bytes(),
        );
    }
    let digest = hasher.finalize();
    (digest[0] as usize) % len
}

fn adaptive_raw_decoy_ttl(observation: Option<&KeyObservation>, fallback: u8) -> u8 {
    let Some(observation) = observation else {
        return fallback;
    };
    if !supports_adaptive_ttl_planning(observation) {
        return fallback;
    }
    preferred_probe_ttl(
        observation.reference_path_hops(),
        observation.rst_path_hops(),
        observation.rst_source,
        fallback,
    )
}

fn active_raw_decoy_ttl_candidates(observation: Option<&KeyObservation>, fallback: u8) -> Vec<u8> {
    let budget = active_raw_probe_budget(observation);
    let Some(observation) = observation else {
        return vec![fallback];
    };
    active_probe_ttl_candidates(
        observation.reference_path_hops(),
        observation.rst_path_hops(),
        observation.rst_source,
        budget,
        fallback,
    )
}

fn active_raw_probe_budget(observation: Option<&KeyObservation>) -> usize {
    let Some(observation) = observation else {
        return 1;
    };
    if !supports_adaptive_ttl_planning(observation) {
        return 1;
    }
    active_probe_budget(
        observation.matched_packets,
        observation.capture_wait_cycles,
        observation.rst_source,
    )
}

fn adaptive_ttl_pattern_ttl(observation: Option<&KeyObservation>, fallback: u32) -> u32 {
    let Some(observation) = observation else {
        return fallback;
    };
    if !supports_adaptive_ttl_planning(observation) {
        return fallback;
    }
    let Some(reference_ttl) = observation
        .first_data_ttl
        .or(observation.syn_ack_ttl)
        .or(observation.first_packet_ttl)
    else {
        return fallback;
    };
    // For the real socket TTL we prefer a plausible initial TTL value derived
    // from the observed remote path instead of the aggressive decoy expiry TTL.
    u32::from(canonical_initial_ttl(reference_ttl))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::RstSource;

    #[test]
    fn planner_filters_raw_strategies_without_capabilities() {
        let plan = build_direct_plan_with_caps(
            vec!["ttl_desync".into(), "fake_rst".into(), "passthrough".into()],
            &["ttl_desync".into(), "fake_rst".into(), "passthrough".into()],
            "203.0.113.1:443".parse().unwrap(),
            None,
            None,
            RawCapabilities {
                ipv4_raw_send: false,
                ipv4_packet_capture: false,
                tcp_repair_query: false,
                ipv4_header_control: false,
                ipv4_fragmentation: false,
            },
        );
        let ids: Vec<_> = plan.strategies.iter().map(|item| item.id()).collect();
        assert_eq!(ids, vec!["passthrough"]);
        assert_eq!(plan.empty_reason, None);
    }

    #[test]
    fn planner_classifies_geneva_missing_raw_capability() {
        let geneva =
            aegis_core::strategies::GenevaStrategy::from_dsl(r"[TCP:flags:PA]-duplicate(,)-| \/")
                .expect("live Geneva strategy");
        let reason = geneva.requirements().unsatisfied_reason(
            "203.0.113.1:443".parse().unwrap(),
            RawCapabilities {
                ipv4_raw_send: false,
                ipv4_packet_capture: false,
                tcp_repair_query: false,
                ipv4_header_control: false,
                ipv4_fragmentation: false,
            },
        );
        assert_eq!(reason, Some(DirectTerminalReason::MissingRawCapability));
    }

    #[test]
    fn planner_classifies_ipv6_geneva_as_unsupported_address_family() {
        let geneva =
            aegis_core::strategies::GenevaStrategy::from_dsl(r"[TCP:flags:PA]-duplicate(,)-| \/")
                .expect("live Geneva strategy");
        let reason = geneva.requirements().unsatisfied_reason(
            "[2001:db8::1]:443".parse().unwrap(),
            RawCapabilities {
                ipv4_raw_send: true,
                ipv4_packet_capture: true,
                tcp_repair_query: true,
                ipv4_header_control: true,
                ipv4_fragmentation: true,
            },
        );
        assert_eq!(reason, Some(DirectTerminalReason::UnsupportedAddressFamily));
    }

    #[test]
    fn empty_plan_keeps_a_typed_terminal_reason() {
        let plan = build_direct_plan_with_caps(
            vec!["ttl_desync".into()],
            &["ttl_desync".into()],
            "203.0.113.1:443".parse().unwrap(),
            None,
            None,
            RawCapabilities {
                ipv4_raw_send: false,
                ipv4_packet_capture: false,
                tcp_repair_query: false,
                ipv4_header_control: false,
                ipv4_fragmentation: false,
            },
        );
        assert!(plan.strategies.is_empty());
        assert_eq!(
            plan.empty_reason,
            Some(DirectTerminalReason::MissingRawCapability)
        );
    }

    #[test]
    fn uninstantiable_strategy_is_no_executable_strategy() {
        let plan = build_direct_plan_with_caps(
            vec!["not-a-strategy".into()],
            &["not-a-strategy".into()],
            "203.0.113.1:443".parse().unwrap(),
            None,
            None,
            RawCapabilities {
                ipv4_raw_send: false,
                ipv4_packet_capture: false,
                tcp_repair_query: false,
                ipv4_header_control: false,
                ipv4_fragmentation: false,
            },
        );
        assert!(plan.strategies.is_empty());
        assert_eq!(
            plan.empty_reason,
            Some(DirectTerminalReason::NoExecutableStrategy)
        );
    }

    #[test]
    fn planner_keeps_raw_strategies_for_ipv4_when_supported() {
        let plan = build_direct_plan_with_caps(
            vec!["ttl_desync".into(), "fake_rst".into(), "passthrough".into()],
            &["ttl_desync".into(), "fake_rst".into(), "passthrough".into()],
            "203.0.113.1:443".parse().unwrap(),
            None,
            None,
            RawCapabilities {
                ipv4_raw_send: true,
                ipv4_packet_capture: true,
                tcp_repair_query: true,
                ipv4_header_control: true,
                ipv4_fragmentation: true,
            },
        );
        let ids: Vec<_> = plan.strategies.iter().map(|item| item.id()).collect();
        assert_eq!(ids, vec!["ttl_desync", "fake_rst", "passthrough"]);
        assert_eq!(plan.empty_reason, None);
    }

    #[test]
    fn planner_filters_ipv4_only_strategies_for_ipv6() {
        let plan = build_direct_plan_with_caps(
            vec!["ttl_desync".into(), "passthrough".into()],
            &["ttl_desync".into(), "passthrough".into()],
            "[2001:db8::1]:443".parse().unwrap(),
            None,
            None,
            RawCapabilities {
                ipv4_raw_send: true,
                ipv4_packet_capture: true,
                tcp_repair_query: true,
                ipv4_header_control: true,
                ipv4_fragmentation: true,
            },
        );
        let ids: Vec<_> = plan.strategies.iter().map(|item| item.id()).collect();
        assert_eq!(ids, vec!["passthrough"]);
        assert_eq!(plan.empty_reason, None);
    }

    #[test]
    fn active_probe_plan_uses_core_ttl_ladder() {
        let dst: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let observation = KeyObservation {
            first_data_ttl: Some(52),
            rst_ttl: Some(62),
            rst_source: Some(RstSource::Middlebox),
            matched_packets: 3,
            capture_wait_cycles: 1,
            ..Default::default()
        };
        let fallback =
            direct_fingerprint_profile_with_time(dst, Some(&observation), 10_000).raw_decoy_ttl;
        assert_eq!(
            build_active_probe_plan_for_dst_with_time(dst, Some(&observation), 10_000),
            ActiveProbePlan {
                preferred_ttl: 2,
                budget: 4,
                candidates: vec![2, 1, 7, fallback],
            }
        );
    }

    #[test]
    fn adaptive_raw_decoy_ttl_uses_observed_hop_budget() {
        let observation = KeyObservation {
            first_data_ttl: Some(58),
            ..Default::default()
        };
        assert_eq!(
            adaptive_raw_decoy_ttl(Some(&observation), TtlDesyncStrategy::default().ttl),
            1
        );
    }

    #[test]
    fn adaptive_raw_decoy_ttl_falls_back_without_observation() {
        assert_eq!(
            adaptive_raw_decoy_ttl(None, TtlDesyncStrategy::default().ttl),
            TtlDesyncStrategy::default().ttl
        );
    }

    #[test]
    fn adaptive_raw_decoy_ttl_supports_other_raw_strategies() {
        let observation = KeyObservation {
            capture_status: aegis_core::PacketCaptureStatus::Active,
            capture_backend: Some(aegis_core::PacketCaptureBackendKind::LinuxAfPacket),
            capture_filter_applied: true,
            matched_packets: 2,
            syn_ack_ttl: Some(57),
            ..Default::default()
        };
        assert_eq!(
            adaptive_raw_decoy_ttl(Some(&observation), IpFragStrategy::default().ttl),
            2
        );
        assert_eq!(
            adaptive_raw_decoy_ttl(Some(&observation), FakeDisorderStrategy::default().ttl),
            2
        );
    }

    #[test]
    fn adaptive_raw_decoy_ttl_prefers_middlebox_depth_when_known() {
        let observation = KeyObservation {
            first_data_ttl: Some(52),
            rst_ttl: Some(62),
            rst_source: Some(RstSource::Middlebox),
            ..Default::default()
        };
        assert_eq!(
            adaptive_raw_decoy_ttl(Some(&observation), TtlDesyncStrategy::default().ttl),
            2
        );
    }

    #[test]
    fn adaptive_raw_decoy_ttl_keeps_remote_depth_policy_without_middlebox_rst() {
        let observation = KeyObservation {
            first_data_ttl: Some(52),
            rst_ttl: Some(58),
            rst_source: Some(RstSource::Remote),
            ..Default::default()
        };
        assert_eq!(
            adaptive_raw_decoy_ttl(Some(&observation), TtlDesyncStrategy::default().ttl),
            7
        );
    }

    #[test]
    fn active_raw_decoy_ttl_candidates_expand_middlebox_and_remote_depths() {
        let observation = KeyObservation {
            first_data_ttl: Some(52),
            rst_ttl: Some(62),
            rst_source: Some(RstSource::Middlebox),
            matched_packets: 3,
            capture_wait_cycles: 1,
            ..Default::default()
        };
        assert_eq!(
            active_raw_decoy_ttl_candidates(Some(&observation), TtlDesyncStrategy::default().ttl),
            vec![2, 1, 7, TtlDesyncStrategy::default().ttl]
        );
    }

    #[test]
    fn active_raw_decoy_ttl_candidates_fall_back_when_history_missing() {
        assert_eq!(
            active_raw_decoy_ttl_candidates(None, TtlDesyncStrategy::default().ttl),
            vec![TtlDesyncStrategy::default().ttl]
        );
    }

    #[test]
    fn active_raw_probe_budget_stays_at_fallback_for_low_confidence_history() {
        let observation = KeyObservation {
            syn_ack_ttl: Some(52),
            matched_packets: 1,
            capture_status: aegis_core::PacketCaptureStatus::NotAttempted,
            ..Default::default()
        };
        assert_eq!(active_raw_probe_budget(Some(&observation)), 1);
        assert_eq!(
            active_raw_decoy_ttl_candidates(Some(&observation), TtlDesyncStrategy::default().ttl),
            vec![TtlDesyncStrategy::default().ttl]
        );
    }

    #[test]
    fn active_raw_probe_budget_stays_at_fallback_for_unsupported_platform_observation() {
        let observation = KeyObservation {
            syn_ack_ttl: Some(52),
            matched_packets: 2,
            capture_status: aegis_core::PacketCaptureStatus::UnsupportedPlatform,
            capture_backend: Some(aegis_core::PacketCaptureBackendKind::LinuxAfPacket),
            capture_filter_applied: true,
            ..Default::default()
        };
        assert_eq!(active_raw_probe_budget(Some(&observation)), 1);
        assert_eq!(
            adaptive_raw_decoy_ttl(Some(&observation), TtlDesyncStrategy::default().ttl),
            TtlDesyncStrategy::default().ttl
        );
        assert_eq!(
            adaptive_ttl_pattern_ttl(Some(&observation), TtlPatternStrategy::default().ttl),
            TtlPatternStrategy::default().ttl
        );
    }

    #[test]
    fn active_raw_probe_budget_truncates_remote_depth_ladder_for_medium_confidence() {
        let observation = KeyObservation {
            first_data_ttl: Some(52),
            matched_packets: 2,
            capture_wait_cycles: 8,
            ..Default::default()
        };
        assert_eq!(active_raw_probe_budget(Some(&observation)), 3);
        assert_eq!(
            active_raw_decoy_ttl_candidates(Some(&observation), TtlDesyncStrategy::default().ttl),
            vec![7, 6, TtlDesyncStrategy::default().ttl]
        );
    }

    #[test]
    fn adaptive_ttl_pattern_ignores_runtime_only_shallow_history() {
        let observation = KeyObservation {
            syn_ack_ttl: Some(58),
            ..Default::default()
        };
        assert_eq!(
            adaptive_ttl_pattern_ttl(Some(&observation), TtlPatternStrategy::default().ttl),
            TtlPatternStrategy::default().ttl
        );
    }

    #[test]
    fn active_raw_decoy_ttl_uses_trusted_shallow_capture_history() {
        let observation = KeyObservation {
            capture_status: aegis_core::PacketCaptureStatus::Active,
            capture_backend: Some(aegis_core::PacketCaptureBackendKind::LinuxAfPacket),
            capture_filter_applied: true,
            matched_packets: 2,
            syn_ack_ttl: Some(57),
            ..Default::default()
        };
        assert_eq!(
            adaptive_raw_decoy_ttl(Some(&observation), TtlDesyncStrategy::default().ttl),
            2
        );
    }

    #[test]
    fn adaptive_ttl_pattern_uses_canonical_initial_ttl() {
        let observation = KeyObservation {
            first_data_ttl: Some(58),
            ..Default::default()
        };
        assert_eq!(
            adaptive_ttl_pattern_ttl(Some(&observation), TtlPatternStrategy::default().ttl),
            60
        );
    }

    #[test]
    fn adaptive_ttl_pattern_falls_back_without_observation() {
        assert_eq!(
            adaptive_ttl_pattern_ttl(None, TtlPatternStrategy::default().ttl),
            TtlPatternStrategy::default().ttl
        );
    }

    #[test]
    fn mimicry_capability_plan_stays_runtime_only_without_capture_backing() {
        assert_eq!(
            build_mimicry_capability_plan(None),
            MimicryCapabilityPlan {
                stage: "pre_wire_input_surface",
                readiness: "runtime_only_baseline",
                observation_capture_confidence: "runtime_only",
                wire_stage: "architecture_scaffold_only",
                wire_scope: "future_packet_wire_linux_only",
                wire_validation_strategy: "capture_replay_plus_privileged_host_acceptance",
                wire_linux_only: true,
                wire_requires_raw_capabilities: true,
                wire_window_preface_ready: false,
                wire_window_preface: None,
                wire_negotiated_options_ready: false,
                wire_fragment_choreography_ready: false,
                wire_ipv4_header_shaping_ready: false,
                wire_observed_negotiated_options_ready: false,
                wire_observed_fragment_choreography_ready: false,
                wire_observed_ipv4_header_shaping_ready: false,
                wire_observed_negotiated_options: None,
                wire_observed_fragment_choreography: None,
                wire_observed_ipv4_header_shaping: None,
                userspace_ttl_hint_ready: false,
                userspace_ttl_hint: None,
                server_hint_ready: false,
                window_profile_ready: false,
                reference_path_ready: false,
                rst_path_ready: false,
                server_hint: None,
                window_profile: None,
                reference_path_hops: None,
                rst_path_hops: None,
            }
        );
    }

    #[test]
    fn mimicry_capability_plan_reports_fingerprint_ready_surface() {
        let observation = KeyObservation {
            matched_packets: 2,
            capture_status: aegis_core::PacketCaptureStatus::Active,
            first_data_ttl: Some(58),
            first_data_window: Some(65535),
            first_data_server_hint: Some(aegis_core::ServerType::LikelyCdn),
            ..Default::default()
        };
        let plan = build_mimicry_capability_plan(Some(&observation));
        assert_eq!(plan.stage, "early_pre_wire_capability_layer");
        assert_eq!(plan.readiness, "composite_signal_ready");
        assert_eq!(plan.observation_capture_confidence, "deep_observed");
        assert_eq!(plan.wire_stage, "architecture_scaffold_only");
        assert_eq!(plan.wire_scope, "future_packet_wire_linux_only");
        assert_eq!(
            plan.wire_validation_strategy,
            "capture_replay_plus_privileged_host_acceptance"
        );
        assert!(plan.wire_linux_only);
        assert!(plan.wire_requires_raw_capabilities);
        assert!(plan.wire_window_preface_ready);
        assert_eq!(plan.wire_window_preface, Some(65535));
        assert!(plan.wire_negotiated_options_ready);
        assert!(plan.wire_fragment_choreography_ready);
        assert!(!plan.wire_observed_negotiated_options_ready);
        assert!(!plan.wire_observed_fragment_choreography_ready);
        assert!(plan.userspace_ttl_hint_ready);
        assert_eq!(plan.userspace_ttl_hint, Some(60));
        assert!(plan.server_hint_ready);
        assert!(plan.window_profile_ready);
        assert!(plan.reference_path_ready);
        assert!(!plan.rst_path_ready);
        assert_eq!(plan.server_hint, Some("likely_cdn"));
        assert_eq!(plan.window_profile, Some("huge"));
        assert_eq!(plan.reference_path_hops, observation.reference_path_hops());
        assert_eq!(plan.rst_path_hops, None);
    }

    #[test]
    fn mimicry_capability_plan_reports_reset_path_surface() {
        let observation = KeyObservation {
            matched_packets: 2,
            capture_status: aegis_core::PacketCaptureStatus::Active,
            first_data_ttl: Some(58),
            first_data_window: Some(65535),
            first_data_server_hint: Some(aegis_core::ServerType::LikelyCdn),
            rst_ttl: Some(30),
            rst_source: Some(aegis_core::RstSource::Middlebox),
            ..Default::default()
        };
        let plan = build_mimicry_capability_plan(Some(&observation));
        assert_eq!(plan.stage, "early_pre_wire_capability_layer");
        assert_eq!(plan.readiness, "composite_signal_ready");
        assert_eq!(plan.observation_capture_confidence, "deep_observed");
        assert_eq!(plan.wire_stage, "architecture_scaffold_only");
        assert_eq!(plan.wire_scope, "future_packet_wire_linux_only");
        assert!(plan.wire_window_preface_ready);
        assert_eq!(plan.wire_window_preface, Some(65535));
        assert!(plan.wire_negotiated_options_ready);
        assert!(plan.wire_fragment_choreography_ready);
        assert!(!plan.wire_observed_negotiated_options_ready);
        assert!(!plan.wire_observed_fragment_choreography_ready);
        assert!(plan.userspace_ttl_hint_ready);
        assert_eq!(plan.userspace_ttl_hint, Some(60));
        assert!(plan.server_hint_ready);
        assert!(plan.window_profile_ready);
        assert!(plan.reference_path_ready);
        assert!(plan.rst_path_ready);
        assert_eq!(plan.server_hint, Some("likely_cdn"));
        assert_eq!(plan.window_profile, Some("huge"));
        assert_eq!(plan.reference_path_hops, observation.reference_path_hops());
        assert_eq!(plan.rst_path_hops, observation.rst_path_hops());
    }

    #[test]
    fn mimicry_capability_plan_reports_path_only_surface_without_fingerprint_ready() {
        let observation = KeyObservation {
            syn_ack_ttl: Some(58),
            syn_ack_window: Some(65535),
            syn_ack_server_hint: Some(aegis_core::ServerType::LikelyCdn),
            ..Default::default()
        };
        let plan = build_mimicry_capability_plan(Some(&observation));
        assert_eq!(plan.stage, "early_pre_wire_capability_layer");
        assert_eq!(plan.readiness, "path_signal_ready");
        assert_eq!(plan.observation_capture_confidence, "runtime_only");
        assert_eq!(plan.wire_stage, "architecture_scaffold_only");
        assert_eq!(plan.wire_scope, "future_packet_wire_linux_only");
        assert!(!plan.wire_window_preface_ready);
        assert_eq!(plan.wire_window_preface, None);
        assert!(!plan.wire_negotiated_options_ready);
        assert!(!plan.wire_fragment_choreography_ready);
        assert!(!plan.wire_observed_negotiated_options_ready);
        assert!(!plan.wire_observed_fragment_choreography_ready);
        assert!(!plan.userspace_ttl_hint_ready);
        assert_eq!(plan.userspace_ttl_hint, None);
        assert!(!plan.server_hint_ready);
        assert!(!plan.window_profile_ready);
        assert!(plan.reference_path_ready);
        assert!(!plan.rst_path_ready);
        assert_eq!(plan.server_hint, None);
        assert_eq!(plan.window_profile, None);
        assert_eq!(plan.reference_path_hops, observation.reference_path_hops());
        assert_eq!(plan.rst_path_hops, None);
    }

    #[test]
    fn mimicry_capability_plan_keeps_explicit_absence_out_of_ready_surface() {
        let observation = KeyObservation {
            matched_packets: 2,
            capture_status: aegis_core::PacketCaptureStatus::UnsupportedPlatform,
            capture_backend: Some(aegis_core::PacketCaptureBackendKind::LinuxAfPacket),
            capture_filter_applied: true,
            syn_ack_ttl: Some(58),
            syn_ack_window: Some(65535),
            syn_ack_server_hint: Some(aegis_core::ServerType::LikelyCdn),
            rst_ttl: Some(30),
            rst_source: Some(aegis_core::RstSource::Middlebox),
            ..Default::default()
        };
        let plan = build_mimicry_capability_plan(Some(&observation));
        assert_eq!(plan.stage, "early_pre_wire_capability_layer");
        assert_eq!(plan.readiness, "runtime_only_baseline");
        assert_eq!(plan.observation_capture_confidence, "explicit_absence");
        assert_eq!(plan.wire_stage, "architecture_scaffold_only");
        assert_eq!(plan.wire_scope, "future_packet_wire_linux_only");
        assert!(!plan.wire_window_preface_ready);
        assert_eq!(plan.wire_window_preface, None);
        assert!(!plan.wire_negotiated_options_ready);
        assert!(!plan.wire_fragment_choreography_ready);
        assert!(!plan.wire_observed_negotiated_options_ready);
        assert!(!plan.wire_observed_fragment_choreography_ready);
        assert!(!plan.userspace_ttl_hint_ready);
        assert_eq!(plan.userspace_ttl_hint, None);
        assert!(!plan.server_hint_ready);
        assert!(!plan.window_profile_ready);
        assert!(!plan.reference_path_ready);
        assert!(!plan.rst_path_ready);
        assert_eq!(plan.server_hint, None);
        assert_eq!(plan.window_profile, None);
        assert_eq!(plan.reference_path_hops, None);
        assert_eq!(plan.rst_path_hops, None);
    }

    /// Проверяет, что rebuild probe plan с обновлённым observation меняет preferred_ttl.
    ///
    /// Это документирует архитектуру multi-TTL ladder через внешний inline_probe_retries:
    /// каждый retry вызывает build_active_probe_plan с текущим observation, что позволяет
    /// brain адаптировать TTL-выбор между попытками.
    ///
    /// Используем `_with_time(..., 10_000)` вместо `current_unix_secs()` чтобы избавиться
    /// от CI-flake: при некоторых epoch-значениях cold `raw_decoy_ttl` (hash-picked из
    /// catalog) совпадает с updated `preferred_ttl=2` от hop-based TTL ladder, что
    /// ломало `assert_ne!` non-deterministically.
    #[test]
    fn probe_plan_rebuild_with_updated_observation_shifts_preferred_ttl() {
        let dst: SocketAddr = "203.0.113.1:443".parse().unwrap();
        // Первоначальное observation: нет RST-данных → fallback TTL из catalog
        let plan_cold = build_active_probe_plan_for_dst_with_time(dst, None, 10_000);
        let cold_preferred = plan_cold.preferred_ttl;

        // После первой попытки observation обновлён: видны RST с middlebox и path hops
        let updated_observation = KeyObservation {
            first_data_ttl: Some(52), // 64 - 52 = 12 hops, preferred_ttl ≈ hops-2 = 10
            rst_ttl: Some(62),
            rst_source: Some(RstSource::Middlebox),
            matched_packets: 3,
            capture_wait_cycles: 1,
            ..Default::default()
        };
        let plan_updated =
            build_active_probe_plan_for_dst_with_time(dst, Some(&updated_observation), 10_000);

        // preferred_ttl должен измениться — это и есть TTL ladder шаг
        assert_ne!(
            cold_preferred, plan_updated.preferred_ttl,
            "rebuild с observation должен изменить preferred_ttl (TTL ladder step)"
        );
        // candidates должен быть непустым и включать preferred_ttl
        assert!(
            !plan_updated.candidates.is_empty(),
            "candidates не должен быть пустым"
        );
    }

    #[test]
    fn mimicry_capability_plan_exposes_observed_wire_inputs_when_present() {
        let observation = KeyObservation {
            matched_packets: 2,
            capture_status: aegis_core::PacketCaptureStatus::Active,
            capture_backend: Some(aegis_core::PacketCaptureBackendKind::LinuxAfPacket),
            capture_filter_applied: true,
            capture_wait_cycles: 1,
            syn_ack_ttl: Some(52),
            syn_ack_window: Some(64240),
            syn_ack_mss: Some(1460),
            syn_ack_window_scale: Some(8),
            syn_ack_sack_permitted: Some(true),
            syn_ack_timestamp_option: Some(true),
            first_data_ttl: Some(58),
            first_data_window: Some(65535),
            first_data_payload_len: Some(41),
            first_packet_ttl: Some(52),
            first_packet_ip_tos: Some(0x10),
            first_packet_ip_id: Some(0x1234),
            first_packet_ip_df: Some(true),
            ..Default::default()
        };
        let plan = build_mimicry_capability_plan(Some(&observation));
        assert!(plan.wire_ipv4_header_shaping_ready);
        assert!(plan.wire_observed_negotiated_options_ready);
        assert!(plan.wire_observed_fragment_choreography_ready);
        assert!(plan.wire_observed_ipv4_header_shaping_ready);
        let ipv4_header = plan
            .wire_observed_ipv4_header_shaping
            .expect("observed ipv4 header shaping");
        assert_eq!(ipv4_header.tos, 0x10);
        assert_eq!(ipv4_header.identification, 0x1234);
        assert!(ipv4_header.dont_fragment);
        let negotiated = plan
            .wire_observed_negotiated_options
            .expect("observed negotiated options");
        assert_eq!(negotiated.mss, 1460);
        assert_eq!(negotiated.window_scale, 8);
        assert!(negotiated.timestamps);
        let choreography = plan
            .wire_observed_fragment_choreography
            .expect("observed choreography");
        assert_eq!(choreography.first_payload_len, 41);
    }

    #[test]
    fn direct_profile_is_reproducible_inside_same_shifted_window() {
        let dst: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let a = direct_fingerprint_profile_with_time(dst, None, 10_000);
        let b = direct_fingerprint_profile_with_time(dst, None, 10_010);
        assert_eq!(a, b);
    }

    #[test]
    fn direct_profile_keeps_family_but_drifts_subfeatures_inside_long_session() {
        let dst: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let early = direct_fingerprint_profile_with_time(dst, None, 10_000);
        let later = direct_fingerprint_profile_with_time(dst, None, 10_300);
        assert_eq!(early.family_id, later.family_id);
        assert_ne!(early, later);
    }

    #[test]
    fn direct_profile_shows_variance_across_sampled_targets() {
        let families: std::collections::BTreeSet<_> = (1..=32u8)
            .map(|octet| {
                direct_fingerprint_profile_with_time(
                    SocketAddr::from(([203, 0, 113, octet], 443)),
                    None,
                    10_000,
                )
                .family_id
            })
            .collect();
        assert!(families.len() >= 3);
    }

    #[test]
    fn direct_profile_sample_covers_catalog() {
        let families: std::collections::BTreeSet<_> = (1..=128u8)
            .map(|octet| {
                direct_fingerprint_profile_with_time(
                    SocketAddr::from(([198, 51, 100, octet], 443)),
                    None,
                    10_000,
                )
                .family_id
            })
            .collect();
        let expected: std::collections::BTreeSet<_> = DIRECT_PROFILE_CATALOG
            .iter()
            .map(|profile| profile.family_id)
            .collect();
        assert_eq!(families, expected);
    }

    #[test]
    fn direct_profile_distribution_stays_bounded() {
        let mut counts = std::collections::BTreeMap::new();
        for port in 1..=512u16 {
            let family = direct_profile_family_for_time(
                SocketAddr::from(([198, 51, 100, 42], port)),
                None,
                10_000,
            );
            *counts.entry(family).or_insert(0usize) += 1;
        }
        assert_eq!(counts.len(), DIRECT_PROFILE_CATALOG.len());
        let min = counts.values().copied().min().unwrap_or_default();
        let max = counts.values().copied().max().unwrap_or_default();
        assert!(min >= 48, "distribution floor too low: {counts:?}");
        assert!(max <= 80, "distribution ceiling too high: {counts:?}");
    }

    #[test]
    fn direct_probe_and_ttl_pattern_fallbacks_follow_profile_instead_of_fixed_defaults() {
        let dst: SocketAddr = "198.51.100.42:443".parse().unwrap();
        let profile = direct_fingerprint_profile_with_time(dst, None, 10_000);
        let active_probe_plan = build_active_probe_plan_for_dst_with_time(dst, None, 10_000);
        assert_eq!(active_probe_plan.preferred_ttl, profile.raw_decoy_ttl);
        assert_eq!(active_probe_plan.candidates, vec![profile.raw_decoy_ttl]);
        assert_eq!(
            adaptive_ttl_pattern_ttl(None, profile.ttl_pattern_ttl),
            profile.ttl_pattern_ttl
        );
        assert_ne!(
            direct_fingerprint_profile_with_time(dst, None, 10_300).raw_decoy_ttl,
            profile.raw_decoy_ttl
        );
    }
}
