use crate::fingerprint::{ServerType, WindowProfile};
use crate::packet_observer::{PacketCaptureBackendKind, PacketCaptureIoPath};
use crate::probe::RstSource;
use crate::state_v2::{KeyObservation, ObservationContract, StateSnapshot};

use super::{PacketStageHint, PathHopHint, ResetProfileHint, StrategyKey};

pub(super) fn strategy_similarity(a: &StrategyKey, b: &StrategyKey) -> f64 {
    if a.ip_version != b.ip_version || a.mode_hint != b.mode_hint {
        return 0.0;
    }
    if a.target_class != b.target_class
        && a.network_hint != b.network_hint
        && a.port_bucket != b.port_bucket
    {
        return 0.0;
    }

    let mut matches = 2usize;
    let mut total = 2usize;

    total += 1;
    if a.dst_subnet == b.dst_subnet {
        matches += 1;
    }
    total += 1;
    if a.network_hint == b.network_hint {
        matches += 1;
    }
    total += 1;
    if a.target_class == b.target_class {
        matches += 1;
    }
    total += 1;
    if a.target_kind == b.target_kind {
        matches += 1;
    }
    total += 1;
    if a.port_bucket == b.port_bucket {
        matches += 1;
    }
    total += 1;
    if a.target_port == b.target_port {
        matches += 1;
    }
    total += 1;
    if a.is_tls == b.is_tls {
        matches += 1;
    }
    total += 1;
    if a.target_host_hash == b.target_host_hash {
        matches += 1;
    }

    if a.sni_hash.is_some() || b.sni_hash.is_some() {
        total += 1;
        if a.sni_hash == b.sni_hash {
            matches += 1;
        }
    }
    if a.server_signature_hash.is_some() || b.server_signature_hash.is_some() {
        total += 1;
        if a.server_signature_hash == b.server_signature_hash {
            matches += 1;
        }
    }
    if a.server_hint.is_some() || b.server_hint.is_some() {
        total += 1;
        if a.server_hint == b.server_hint {
            matches += 1;
        }
    }
    if a.packet_stage_hint.is_some() || b.packet_stage_hint.is_some() {
        total += 1;
        if a.packet_stage_hint == b.packet_stage_hint {
            matches += 1;
        }
    }
    if a.fingerprint_window_hint.is_some() || b.fingerprint_window_hint.is_some() {
        total += 1;
        if a.fingerprint_window_hint == b.fingerprint_window_hint {
            matches += 1;
        }
    }
    if a.reference_hop_hint.is_some() || b.reference_hop_hint.is_some() {
        total += 1;
        if a.reference_hop_hint == b.reference_hop_hint {
            matches += 1;
        }
    }
    if a.reset_profile_hint.is_some() || b.reset_profile_hint.is_some() {
        total += 1;
        if a.reset_profile_hint == b.reset_profile_hint {
            matches += 1;
        }
    }

    matches as f64 / total as f64
}

pub(super) fn resolve_effective_key(
    snapshot: &StateSnapshot,
    key: &StrategyKey,
    observation: Option<&KeyObservation>,
) -> StrategyKey {
    let base_hash = key.hash_key();
    let observed = observation.or_else(|| snapshot.key_observations.get(&base_hash));
    apply_observation_to_key(key, observed)
}

fn apply_observation_to_key(
    key: &StrategyKey,
    observation: Option<&KeyObservation>,
) -> StrategyKey {
    let mut enriched = key.clone();
    enriched.server_signature_hash = observation
        .and_then(KeyObservation::server_signature_hash)
        .or(enriched.server_signature_hash);
    enriched.server_hint = observation
        .and_then(observed_server_hint)
        .or(enriched.server_hint);
    enriched.packet_stage_hint = observation
        .and_then(observed_packet_stage_hint)
        .or(enriched.packet_stage_hint);
    enriched.fingerprint_window_hint = observation
        .and_then(observed_fingerprint_window_hint)
        .or(enriched.fingerprint_window_hint);
    enriched.reference_hop_hint = observation
        .and_then(observed_reference_hop_hint)
        .or(enriched.reference_hop_hint);
    enriched.reset_profile_hint = observation
        .and_then(observed_reset_profile_hint)
        .or(enriched.reset_profile_hint);
    enriched
}

fn observed_server_hint(observation: &KeyObservation) -> Option<ServerType> {
    observation.runtime_server_hint()
}

fn observed_packet_stage_hint(observation: &KeyObservation) -> Option<PacketStageHint> {
    if observation.first_data_ttl.is_some() {
        Some(PacketStageHint::FirstDataSeen)
    } else if !observation_supports_shallow_key_enrichment(observation) {
        None
    } else if observation.rst_ttl.is_some() {
        Some(PacketStageHint::ResetSeen)
    } else if observation.syn_ack_ttl.is_some() {
        Some(PacketStageHint::SynAckSeen)
    } else {
        None
    }
}

fn observed_fingerprint_window_hint(observation: &KeyObservation) -> Option<WindowProfile> {
    observation.runtime_window_profile_hint()
}

fn observed_reference_hop_hint(observation: &KeyObservation) -> Option<PathHopHint> {
    if observation.first_data_ttl.is_none()
        && !observation_supports_shallow_key_enrichment(observation)
    {
        return None;
    }
    observation.reference_path_hops().map(bucket_path_hops)
}

fn observed_reset_profile_hint(observation: &KeyObservation) -> Option<ResetProfileHint> {
    if observation.first_data_ttl.is_none()
        && !observation_supports_shallow_key_enrichment(observation)
    {
        return None;
    }
    match observation.rst_source {
        Some(RstSource::Remote) => Some(ResetProfileHint::RemotePath),
        Some(RstSource::Middlebox) => Some(ResetProfileHint::MiddleboxPath),
        _ => None,
    }
}

fn bucket_path_hops(hops: u8) -> PathHopHint {
    match hops {
        0..=4 => PathHopHint::Near,
        5..=9 => PathHopHint::Mid,
        _ => PathHopHint::Far,
    }
}

fn observation_supports_shallow_key_enrichment(observation: &KeyObservation) -> bool {
    matches!(
        observation.observation_contract(),
        ObservationContract::TrustedShallow | ObservationContract::DeepObserved
    )
}

pub(super) fn observation_reuse_weight(
    snapshot: &StateSnapshot,
    key_hash: &str,
    key: &StrategyKey,
) -> f64 {
    let Some(observation) = snapshot.key_observations.get(key_hash) else {
        return 1.0;
    };
    let contract = observation.observation_contract();
    let confidence_factor = observation_confidence_reuse_scale(observation);
    if matches!(contract, ObservationContract::DeepObserved)
        || matches!(key.packet_stage_hint, Some(PacketStageHint::FirstDataSeen))
    {
        return 1.0;
    }
    let packet_factor = match observation.matched_packets {
        0 => 0.75_f64,
        1 => 0.9_f64,
        _ => 1.0_f64,
    };
    if !matches!(contract, ObservationContract::TrustedShallow) {
        return (packet_factor * confidence_factor).clamp(0.35_f64, 1.0_f64);
    }
    let backend_factor = {
        match observation.capture_backend {
            Some(PacketCaptureBackendKind::LinuxAfPacket)
                if observation.capture_ring_layout.is_some() =>
            {
                1.0_f64
            }
            Some(PacketCaptureBackendKind::LinuxAfPacket) if observation.capture_filter_applied => {
                0.95_f64
            }
            Some(PacketCaptureBackendKind::LinuxAfPacket) => 0.85_f64,
            Some(PacketCaptureBackendKind::LinuxRawBasic) => 0.65_f64,
            Some(PacketCaptureBackendKind::MacosBpf) => 0.85_f64,
            None => 0.0_f64,
        }
    };
    let io_factor = {
        match observation.capture_io_path {
            Some(PacketCaptureIoPath::AfPacketRing) => 1.0_f64,
            Some(PacketCaptureIoPath::AfPacketRecv) => 0.9_f64,
            Some(PacketCaptureIoPath::RawBasicRecv) => 0.8_f64,
            None => 0.0_f64,
        }
    };
    let wait_factor = match observation.capture_wait_cycles {
        0..=2 => 1.0_f64,
        3..=8 => 0.95_f64,
        9..=16 => 0.85_f64,
        _ => 0.75_f64,
    };
    (packet_factor * backend_factor * io_factor * wait_factor * confidence_factor)
        .clamp(0.35_f64, 1.0_f64)
}

fn observation_confidence_reuse_scale(observation: &KeyObservation) -> f64 {
    match observation.observation_capture_confidence() {
        "explicit_absence" => 0.35,
        "runtime_only" => 0.55,
        "trusted_shallow_low" => 0.75,
        "trusted_shallow_medium" => 0.9,
        "trusted_shallow_high" | "deep_observed" => 1.0,
        _ => 0.5,
    }
}

pub(super) fn observed_stage_reward_factor(stage: Option<PacketStageHint>) -> f64 {
    match stage {
        Some(_) => (1.0 + normalized_packet_stage_depth(stage)) / 2.0,
        None => 1.0,
    }
}

fn normalized_packet_stage_depth(stage: Option<PacketStageHint>) -> f64 {
    packet_stage_depth(stage) as f64
        / packet_stage_depth(Some(PacketStageHint::FirstDataSeen)) as f64
}

fn packet_stage_depth(stage: Option<PacketStageHint>) -> usize {
    match stage {
        Some(PacketStageHint::SynAckSeen) => 1,
        Some(PacketStageHint::ResetSeen) => 2,
        Some(PacketStageHint::FirstDataSeen) => 3,
        None => 0,
    }
}

pub(super) fn strategy_entry_key(key_hash: &str, strategy: &str) -> String {
    format!("{key_hash}|{strategy}")
}
