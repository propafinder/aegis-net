//! State schema v2: расширенная статистика по стратегиям и транспортам.

use crate::brain::StrategyKey;
use crate::external_calibration::ExternalCalibrationSnapshot;
use crate::fingerprint::{ServerType, WindowProfile};
use crate::packet_observer::{
    PacketCaptureBackendKind, PacketCaptureIoPath, PacketCaptureRingLayout, PacketCaptureStatus,
};
use crate::probe::estimated_hops;
use crate::probe::RstSource;
use crate::signals::classify::FailSignal;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashMap;

/// Статистика стратегии v2.
///
/// Отличие от v1 (`StrategyStats`):
/// - Раздельные счётчики по типам результатов (не только success_rate)
/// - fitness_score вычисляется на основе FailSignal, не EMA
/// - Хранит last_signal для windowed UCB
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyStatsV2 {
    pub trials: u64,
    pub successes: u64,
    pub degraded: u64,
    pub freezes: u64,
    pub timeouts: u64,
    pub dpi_blocks: u64,
    pub mean_latency_ms: f64,
    pub mean_session_bytes: f64,
    pub fitness_score: f64,
    pub last_signal: Option<FailSignal>,
    #[serde(default)]
    pub last_updated_unix_ms: Option<u64>,
}

impl Default for StrategyStatsV2 {
    fn default() -> Self {
        Self {
            trials: 0,
            successes: 0,
            degraded: 0,
            freezes: 0,
            timeouts: 0,
            dpi_blocks: 0,
            mean_latency_ms: 0.0,
            mean_session_bytes: 0.0,
            fitness_score: 0.5, // neutral default
            last_signal: None,
            last_updated_unix_ms: None,
        }
    }
}

impl StrategyStatsV2 {
    /// Обновить статистику на основе сигнала.
    pub fn record(&mut self, signal: &FailSignal, latency_ms: Option<u64>, bytes: usize) {
        self.record_with_observation(signal, latency_ms, bytes, None);
    }

    /// Обновить статистику с учётом packet/runtime observation.
    pub fn record_with_observation(
        &mut self,
        signal: &FailSignal,
        latency_ms: Option<u64>,
        bytes: usize,
        observation: Option<&KeyObservation>,
    ) {
        self.trials += 1;
        self.last_signal = Some(signal.clone());
        self.last_updated_unix_ms = Some(current_unix_ms());

        // Обновить счётчики
        match signal {
            FailSignal::Success => self.successes += 1,
            FailSignal::SuccessDegraded => self.degraded += 1,
            FailSignal::SessionFreeze { .. } => self.freezes += 1,
            FailSignal::Timeout => self.timeouts += 1,
            s if s.is_dpi_related() => self.dpi_blocks += 1,
            _ => {}
        }

        // EMA латентности (только для успехов)
        if let Some(ms) = latency_ms {
            if signal.is_success() {
                self.mean_latency_ms = self.mean_latency_ms * 0.9 + (ms as f64) * 0.1;
            }
        }

        // EMA байт
        self.mean_session_bytes = self.mean_session_bytes * 0.9 + (bytes as f64) * 0.1;

        let delta = fitness_delta(signal, observation);
        // EMA fitness
        self.fitness_score = (self.fitness_score * 0.9 + delta * 0.1).clamp(0.0, 1.0);
    }

    /// Success rate (для совместимости / отображения).
    pub fn success_rate(&self) -> f64 {
        if self.trials == 0 {
            return 0.0;
        }
        (self.successes + self.degraded) as f64 / self.trials as f64
    }
}

fn current_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn fitness_delta(signal: &FailSignal, observation: Option<&KeyObservation>) -> f64 {
    let rst_source = observation.and_then(|obs| obs.rst_source);
    let syn_ack_seen = observation.and_then(|obs| obs.syn_ack_ttl).is_some();
    let first_data_seen = observation.and_then(|obs| obs.first_data_ttl).is_some();
    let uplink_relay_seen = observation
        .map(|obs| obs.relay_client_to_remote_bytes > 0 && obs.relay_remote_to_client_bytes == 0)
        .unwrap_or(false);
    let bidirectional_relay_seen = observation
        .map(|obs| obs.relay_client_to_remote_bytes > 0 && obs.relay_remote_to_client_bytes > 0)
        .unwrap_or(false);
    let tls_server_hello_seen = observation
        .map(|obs| obs.tls_server_hello_seen)
        .unwrap_or(false);
    match signal {
        FailSignal::Success => 1.0,
        FailSignal::SuccessDegraded => observation.map(success_degraded_reward).unwrap_or(0.3),
        FailSignal::SessionFreeze { .. } => -0.5,
        FailSignal::ThroughputCollapse if first_data_seen => {
            observation.map(throughput_collapse_reward).unwrap_or(-0.35)
        }
        FailSignal::ThroughputCollapse => -0.7,
        FailSignal::DropSuspected
            if first_data_seen && rst_source == Some(RstSource::Middlebox) =>
        {
            -0.75
        }
        FailSignal::DropSuspected | FailSignal::HandshakeMismatch => -1.0,
        FailSignal::Timeout => -0.2,
        FailSignal::RemoteReset
            if bidirectional_relay_seen && rst_source == Some(RstSource::Remote) =>
        {
            observation.map(late_progress_baseline).unwrap_or(0.45)
        }
        FailSignal::RemoteReset if uplink_relay_seen && rst_source == Some(RstSource::Remote) => {
            0.35
        }
        FailSignal::RemoteReset if first_data_seen && rst_source == Some(RstSource::Remote) => {
            observation
                .map(|obs| blend_shallow_capture_confidence(obs, 0.05, 0.25))
                .unwrap_or(0.25)
        }
        FailSignal::RemoteReset
            if tls_server_hello_seen && rst_source == Some(RstSource::Remote) =>
        {
            -0.15
        }
        FailSignal::RemoteReset if syn_ack_seen && rst_source == Some(RstSource::Remote) => -0.35,
        FailSignal::RemoteReset if first_data_seen => 0.05,
        FailSignal::RemoteRefused | FailSignal::DnsFailure => 0.0, // не связано с DPI
        FailSignal::ExternalClassifierHint {
            hard_block: true, ..
        } => -0.8,
        FailSignal::ExternalClassifierHint { .. } => -0.15,
        _ => -0.1,
    }
}

fn relay_lifetime_ratio(observation: &KeyObservation) -> f64 {
    if observation.configured_timeout_ms == 0 {
        return 0.0;
    }
    ((observation.relay_lifetime_ms as f64) / (observation.configured_timeout_ms as f64))
        .clamp(0.0, 1.0)
}

fn relay_downstream_share(observation: &KeyObservation) -> f64 {
    let total = observation.relay_client_to_remote_bytes + observation.relay_remote_to_client_bytes;
    if total == 0 {
        return 0.0;
    }
    (observation.relay_remote_to_client_bytes as f64 / total as f64).clamp(0.0, 1.0)
}

fn remote_reset_bidirectional_reward(observation: &KeyObservation) -> f64 {
    let downstream_share = relay_downstream_share(observation);
    let lifetime_ratio = relay_lifetime_ratio(observation);
    // Smooth reward curve: deeper downstream dominance and longer relative lifetime
    // move remote resets closer to "almost success" without discrete byte thresholds.
    (0.4 + downstream_share * 0.25 + lifetime_ratio * 0.15).clamp(0.0, 0.8)
}

fn late_progress_baseline(observation: &KeyObservation) -> f64 {
    if observation.relay_client_to_remote_bytes > 0 && observation.relay_remote_to_client_bytes > 0
    {
        remote_reset_bidirectional_reward(observation)
    } else if observation.relay_client_to_remote_bytes > 0 {
        0.35
    } else if observation.first_data_ttl.is_some() {
        0.25
    } else {
        0.2
    }
}

fn success_degraded_reward(observation: &KeyObservation) -> f64 {
    let baseline = late_progress_baseline(observation);
    // A real degraded success should stay ahead of an otherwise similar late reset.
    (baseline + blend_observation_capture_confidence(observation, 0.04, 0.12)).clamp(0.3, 0.9)
}

fn throughput_collapse_reward(observation: &KeyObservation) -> f64 {
    let baseline = late_progress_baseline(observation);
    // Late collapse means real progress existed, but it should still trail
    // the equivalent late reset and degraded success on the same axis.
    let stall_relief = downstream_window_pressure_relief(observation.first_data_window);
    let loss_relief = duplicate_ack_relief(observation.downstream_dup_ack_count);
    let retransmit_relief = retransmit_relief(observation.downstream_retransmit_count);
    let fin_relief = graceful_close_relief(observation.downstream_fin_after_data);
    let confidence_relief = blend_observation_capture_confidence(observation, 0.0, 0.05);
    (baseline - 0.5 + stall_relief + confidence_relief)
        .clamp(-0.7, 0.45)
        .max((baseline - 0.5 + loss_relief + confidence_relief).clamp(-0.7, 0.45))
        .max((baseline - 0.5 + retransmit_relief + confidence_relief).clamp(-0.7, 0.45))
        .max((baseline - 0.5 + fin_relief + confidence_relief).clamp(-0.7, 0.45))
}

fn downstream_window_pressure_relief(window: Option<u16>) -> f64 {
    match window {
        Some(0) => {
            // Zero-window is the strongest remote-side flow-control stall signal we have.
            0.12
        }
        Some(window) => {
            let normalized_window = (window as f64) / (u16::MAX as f64);
            let pressure = (1.0_f64 - normalized_window).clamp(0.0, 1.0);
            // Use a steep continuous curve so only genuinely tiny advertised windows
            // materially soften collapse shaping.
            (pressure.powi(8) * 0.08).clamp(0.0, 0.08)
        }
        None => 0.0,
    }
}

fn duplicate_ack_relief(duplicate_acks: u32) -> f64 {
    match duplicate_acks {
        0 => 0.0,
        1 => 0.025,
        2 => 0.045,
        _ => 0.06,
    }
}

fn retransmit_relief(retransmits: u32) -> f64 {
    match retransmits {
        0 => 0.0,
        1 => 0.055,
        2 => 0.07,
        _ => 0.08,
    }
}

fn graceful_close_relief(fin_after_data: bool) -> f64 {
    if fin_after_data {
        // FIN after real downstream progress is usually a cleaner terminal path
        // than loss-like collapse, but still weaker than explicit stall signals.
        0.065
    } else {
        0.0
    }
}

fn blend_shallow_capture_confidence(
    observation: &KeyObservation,
    low_confidence_reward: f64,
    high_confidence_reward: f64,
) -> f64 {
    let confidence = shallow_capture_confidence(observation);
    low_confidence_reward + (high_confidence_reward - low_confidence_reward) * confidence
}

fn blend_observation_capture_confidence(
    observation: &KeyObservation,
    low_confidence_reward: f64,
    high_confidence_reward: f64,
) -> f64 {
    let confidence = observation_capture_confidence_scale(observation);
    low_confidence_reward + (high_confidence_reward - low_confidence_reward) * confidence
}

fn shallow_capture_confidence(observation: &KeyObservation) -> f64 {
    if observation.first_response_bytes > 0 || observation.tls_server_hello_seen {
        return 1.0;
    }
    let packet_factor = match observation.matched_packets {
        0 => 0.0_f64,
        1 => 0.65_f64,
        2 => 0.85_f64,
        _ => 1.0_f64,
    };
    let backend_factor = if !observation.supports_shallow_capture_trust() {
        0.0_f64
    } else {
        match observation.capture_backend {
            Some(PacketCaptureBackendKind::LinuxAfPacket)
                if observation.capture_ring_layout.is_some() =>
            {
                1.0_f64
            }
            Some(PacketCaptureBackendKind::LinuxAfPacket) if observation.capture_filter_applied => {
                0.9_f64
            }
            Some(PacketCaptureBackendKind::LinuxAfPacket) => 0.75_f64,
            Some(PacketCaptureBackendKind::LinuxRawBasic) => 0.4_f64,
            // Tier 2.3 scaffolding: see brain.rs note for calibration plan.
            Some(PacketCaptureBackendKind::MacosBpf) => 0.75_f64,
            None => 0.0_f64,
        }
    };
    let io_factor = if !observation.supports_shallow_capture_trust() {
        0.0_f64
    } else {
        match observation.capture_io_path {
            Some(PacketCaptureIoPath::AfPacketRing) => 1.0_f64,
            Some(PacketCaptureIoPath::AfPacketRecv) => 0.9_f64,
            Some(PacketCaptureIoPath::RawBasicRecv) => 0.75_f64,
            None => 0.0_f64,
        }
    };
    let wait_factor = match observation.capture_wait_cycles {
        0..=2 => 1.0_f64,
        3..=8 => 0.95_f64,
        9..=16 => 0.8_f64,
        _ => 0.65_f64,
    };
    (packet_factor * backend_factor * io_factor * wait_factor).clamp(0.0_f64, 1.0_f64)
}

fn observation_capture_confidence_scale(observation: &KeyObservation) -> f64 {
    match observation.observation_capture_confidence() {
        "explicit_absence" => 0.0,
        "runtime_only" => 0.2,
        "trusted_shallow_low" => 0.5,
        "trusted_shallow_medium" => 0.75,
        "trusted_shallow_high" | "deep_observed" => 1.0,
        _ => 0.0,
    }
}

/// Статистика транспорта (tunnel family).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TransportStats {
    pub trials: u64,
    pub successes: u64,
    pub freezes: u64,
    pub rejected: u64,
    pub mean_duration_ms: f64,
    pub fitness_score: f64,
}

/// История active stall probe по ключу назначения.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StallProbeStats {
    pub trials: u64,
    pub successes: u64,
    pub degraded: u64,
    pub freezes: u64,
    pub collapses: u64,
    pub timeouts: u64,
    pub dpi_blocks: u64,
    pub consecutive_stall_failures: u64,
    pub last_signal: Option<FailSignal>,
    pub mean_latency_ms: f64,
}

impl Default for StallProbeStats {
    fn default() -> Self {
        Self {
            trials: 0,
            successes: 0,
            degraded: 0,
            freezes: 0,
            collapses: 0,
            timeouts: 0,
            dpi_blocks: 0,
            consecutive_stall_failures: 0,
            last_signal: None,
            mean_latency_ms: 0.0,
        }
    }
}

impl StallProbeStats {
    pub fn record(&mut self, signal: &FailSignal, latency_ms: Option<u64>) {
        self.trials += 1;
        self.last_signal = Some(signal.clone());
        match signal {
            FailSignal::Success => {
                self.successes += 1;
                self.consecutive_stall_failures = 0;
            }
            FailSignal::SuccessDegraded => {
                self.degraded += 1;
                self.consecutive_stall_failures = 0;
            }
            FailSignal::SessionFreeze { .. } => {
                self.freezes += 1;
                self.consecutive_stall_failures += 1;
            }
            FailSignal::ThroughputCollapse => {
                self.collapses += 1;
                self.consecutive_stall_failures += 1;
            }
            FailSignal::Timeout => {
                self.timeouts += 1;
                self.consecutive_stall_failures += 1;
            }
            s if s.is_dpi_related() => self.dpi_blocks += 1,
            _ => self.consecutive_stall_failures = 0,
        }
        if let Some(ms) = latency_ms {
            self.mean_latency_ms = self.mean_latency_ms * 0.9 + (ms as f64) * 0.1;
        }
    }
}

/// Грубый контракт качества observation для Brain/runtime policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservationContract {
    ExplicitAbsence,
    RuntimeOnly,
    TrustedShallow,
    DeepObserved,
}

impl ObservationContract {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExplicitAbsence => "explicit_absence",
            Self::RuntimeOnly => "runtime_only",
            Self::TrustedShallow => "trusted_shallow",
            Self::DeepObserved => "deep_observed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedWireNegotiatedOptions {
    pub mss: u16,
    pub window_scale: u8,
    pub sack_permitted: bool,
    pub timestamps: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedWireChoreographyHint {
    pub first_payload_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedWireIpv4HeaderShaping {
    pub tos: u8,
    pub identification: u16,
    pub dont_fragment: bool,
}

/// Последние наблюдаемые hints по ключу назначения.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct KeyObservation {
    pub first_response_bytes: usize,
    pub tls_server_hello_seen: bool,
    pub ja3s_md5: Option<String>,
    pub relay_client_to_remote_bytes: usize,
    pub relay_remote_to_client_bytes: usize,
    pub relay_lifetime_ms: u64,
    pub configured_timeout_ms: u64,
    pub capture_status: PacketCaptureStatus,
    pub capture_backend: Option<PacketCaptureBackendKind>,
    pub capture_filter_applied: bool,
    pub capture_ring_layout: Option<PacketCaptureRingLayout>,
    pub capture_io_path: Option<PacketCaptureIoPath>,
    pub capture_wait_cycles: u32,
    pub downstream_dup_ack_count: u32,
    pub downstream_retransmit_count: u32,
    pub downstream_fin_after_data: bool,
    pub matched_packets: u32,
    pub syn_ack_ttl: Option<u8>,
    pub syn_ack_window: Option<u16>,
    pub syn_ack_mss: Option<u16>,
    pub syn_ack_window_scale: Option<u8>,
    pub syn_ack_sack_permitted: Option<bool>,
    pub syn_ack_timestamp_option: Option<bool>,
    pub syn_ack_server_hint: Option<ServerType>,
    pub first_data_ttl: Option<u8>,
    pub first_data_window: Option<u16>,
    pub first_data_payload_len: Option<usize>,
    pub first_data_flags: Option<u8>,
    pub first_data_server_hint: Option<ServerType>,
    pub first_packet_ttl: Option<u8>,
    pub first_packet_ip_tos: Option<u8>,
    pub first_packet_ip_id: Option<u16>,
    pub first_packet_ip_df: Option<bool>,
    pub first_packet_window: Option<u16>,
    pub first_packet_flags: Option<u8>,
    pub server_hint: Option<ServerType>,
    pub rst_ttl: Option<u8>,
    pub rst_source: Option<RstSource>,
}

impl KeyObservation {
    pub fn observation_contract(&self) -> ObservationContract {
        if self.capture_status.is_explicit_absence() {
            return ObservationContract::ExplicitAbsence;
        }
        if self.has_deep_observation() {
            return ObservationContract::DeepObserved;
        }
        if self.has_trusted_shallow_observation() {
            return ObservationContract::TrustedShallow;
        }
        ObservationContract::RuntimeOnly
    }

    pub fn supports_active_stall_probe(&self) -> bool {
        if self.capture_status.is_explicit_absence() {
            return false;
        }
        self.capture_status.is_active()
            || self.capture_backend.is_some()
            || self.syn_ack_ttl.is_some()
            || self.first_data_ttl.is_some()
            || self.rst_ttl.is_some()
    }

    pub fn supports_shallow_capture_trust(&self) -> bool {
        if self.capture_status.is_explicit_absence() {
            return false;
        }
        if self.capture_status.is_active() {
            return true;
        }
        // Preserve trust for pre-`capture_status` histories that only recorded
        // backend/io metadata, while explicit absence statuses always win.
        matches!(self.capture_status, PacketCaptureStatus::NotAttempted)
            && self.capture_backend.is_some()
    }

    fn has_deep_observation(&self) -> bool {
        self.first_response_bytes > 0
            || self.tls_server_hello_seen
            || self.ja3s_md5.is_some()
            || self.first_data_ttl.is_some()
            || self.first_data_window.is_some()
            || self.first_data_flags.is_some()
            || self.first_data_server_hint.is_some()
            || self.relay_client_to_remote_bytes > 0
            || self.relay_remote_to_client_bytes > 0
    }

    fn has_trusted_shallow_observation(&self) -> bool {
        if self.matched_packets == 0 || !self.supports_shallow_capture_trust() {
            return false;
        }
        match self.capture_backend {
            Some(PacketCaptureBackendKind::LinuxAfPacket) => {
                (self.capture_filter_applied || self.capture_ring_layout.is_some())
                    && self.capture_wait_cycles <= 8
            }
            Some(PacketCaptureBackendKind::LinuxRawBasic) => false,
            // Tier 2.3 scaffolding: until live BPF impl emits filter_applied
            // / ring_layout signals, treat MacosBpf as untrusted (false).
            Some(PacketCaptureBackendKind::MacosBpf) => false,
            None => false,
        }
    }

    pub fn server_signature_hash(&self) -> Option<u64> {
        self.ja3s_md5.as_ref().map(|digest| {
            let bytes = digest.as_bytes();
            let digest = sha2::Sha256::digest(bytes);
            u64::from_be_bytes([
                digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6],
                digest[7],
            ])
        })
    }

    pub fn reference_path_hops(&self) -> Option<u8> {
        self.first_data_ttl
            .or(self.syn_ack_ttl)
            .or(self.first_packet_ttl)
            .map(estimated_hops)
    }

    pub fn rst_path_hops(&self) -> Option<u8> {
        self.rst_ttl.map(estimated_hops)
    }

    pub fn runtime_server_hint(&self) -> Option<ServerType> {
        if self.first_data_server_hint.is_some() {
            return self.first_data_server_hint;
        }
        if !self.has_trusted_shallow_observation() {
            return None;
        }
        self.server_hint.or(self.syn_ack_server_hint)
    }

    pub fn runtime_window_profile_hint(&self) -> Option<WindowProfile> {
        let handshake_window = self.syn_ack_window.or(self.first_packet_window);
        if let Some(window) = handshake_window {
            if !self.has_trusted_shallow_observation() {
                return None;
            }
            return Some(WindowProfile::from_window(window));
        }
        self.first_data_window.map(WindowProfile::from_window)
    }

    pub fn runtime_window_hint(&self) -> Option<u16> {
        let handshake_window = self.syn_ack_window.or(self.first_packet_window);
        if let Some(window) = handshake_window {
            if !self.has_trusted_shallow_observation() {
                return None;
            }
            return Some(window);
        }
        self.first_data_window
    }

    pub fn observed_wire_negotiated_options_hint(&self) -> Option<ObservedWireNegotiatedOptions> {
        if !self.has_trusted_shallow_observation() {
            return None;
        }
        Some(ObservedWireNegotiatedOptions {
            mss: self.syn_ack_mss?,
            window_scale: self.syn_ack_window_scale?,
            sack_permitted: self.syn_ack_sack_permitted?,
            timestamps: self.syn_ack_timestamp_option?,
        })
    }

    pub fn observed_wire_choreography_hint(&self) -> Option<ObservedWireChoreographyHint> {
        if !self.has_deep_observation() {
            return None;
        }
        Some(ObservedWireChoreographyHint {
            first_payload_len: self.first_data_payload_len?,
        })
    }

    pub fn observed_wire_ipv4_header_shaping_hint(&self) -> Option<ObservedWireIpv4HeaderShaping> {
        if !self.has_trusted_shallow_observation() {
            return None;
        }
        Some(ObservedWireIpv4HeaderShaping {
            tos: self.first_packet_ip_tos?,
            identification: self.first_packet_ip_id?,
            dont_fragment: self.first_packet_ip_df?,
        })
    }

    pub fn observation_capture_confidence(&self) -> &'static str {
        match self.observation_contract() {
            ObservationContract::ExplicitAbsence => "explicit_absence",
            ObservationContract::RuntimeOnly => "runtime_only",
            ObservationContract::DeepObserved => "deep_observed",
            ObservationContract::TrustedShallow => {
                let confidence = shallow_capture_confidence(self);
                if confidence >= 0.9 {
                    "trusted_shallow_high"
                } else if confidence >= 0.7 {
                    "trusted_shallow_medium"
                } else {
                    "trusted_shallow_low"
                }
            }
        }
    }
}

/// Полный снимок состояния для persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub schema_version: u32,
    #[serde(default)]
    pub key_registry: HashMap<String, StrategyKey>,
    #[serde(default)]
    pub key_observations: HashMap<String, KeyObservation>,
    #[serde(default)]
    pub strategy_stats: HashMap<String, StrategyStatsV2>,
    #[serde(default)]
    pub stall_probe_stats: HashMap<String, StallProbeStats>,
    #[serde(default)]
    pub transport_stats: HashMap<String, TransportStats>,
    /// Route-level learning for the explicit Geneva hybrid profile. Kept
    /// separate from `strategy_stats` and `transport_stats`: `geneva` is a
    /// direct strategy, while `grpc_stream` is a relay transport, and neither
    /// identifier is a product route.
    #[serde(default)]
    pub hybrid_route_stats: HashMap<String, HybridRouteStats>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_calibration: Option<ExternalCalibrationSnapshot>,
}

impl Default for StateSnapshot {
    fn default() -> Self {
        Self {
            schema_version: 2,
            key_registry: HashMap::new(),
            key_observations: HashMap::new(),
            strategy_stats: HashMap::new(),
            stall_probe_stats: HashMap::new(),
            transport_stats: HashMap::new(),
            hybrid_route_stats: HashMap::new(),
            external_calibration: None,
        }
    }
}

/// Persistent route-level evidence for one [`StrategyKey`] context.
///
/// Timestamps are wall-clock evidence boundaries, not identifiers. No target
/// hostname, auth material, or application bytes are stored here.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HybridRouteStats {
    pub direct_attempts: u64,
    pub direct_successes: u64,
    pub direct_failures: u64,
    pub consecutive_hostile_direct_failures: u32,
    pub relay_attempts: u64,
    pub relay_successes: u64,
    pub relay_failures: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_direct_attempt_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_direct_outcome_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_direct_success_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_hostile_direct_failure_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_relay_outcome_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_relay_success_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_direct_signal: Option<FailSignal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_relay_signal: Option<FailSignal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_external_classifier_hint: Option<FailSignal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_external_classifier_fingerprint: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strategy_stats_record_success() {
        let mut s = StrategyStatsV2::default();
        s.record(&FailSignal::Success, Some(100), 4096);
        assert_eq!(s.trials, 1);
        assert_eq!(s.successes, 1);
        assert!(s.fitness_score > 0.5);
        assert!(s.mean_latency_ms > 0.0);
    }

    #[test]
    fn strategy_stats_record_freeze() {
        let mut s = StrategyStatsV2::default();
        s.record(
            &FailSignal::SessionFreeze {
                bytes_before_stall: 18000,
            },
            None,
            18000,
        );
        assert_eq!(s.freezes, 1);
        assert!(s.fitness_score < 0.5); // наказание за freeze
    }

    #[test]
    fn strategy_stats_record_server_error_no_penalty() {
        let mut s = StrategyStatsV2::default();
        let initial = s.fitness_score;
        s.record(&FailSignal::RemoteRefused, None, 0);
        // RemoteRefused = 0.0 delta, fitness почти не меняется
        assert!((s.fitness_score - initial).abs() < 0.06);
    }

    #[test]
    fn strategy_stats_shape_reset_fitness_by_observation() {
        let mut remote = StrategyStatsV2::default();
        let remote_obs = KeyObservation {
            first_data_ttl: Some(58),
            rst_source: Some(RstSource::Remote),
            ..Default::default()
        };
        remote.record_with_observation(&FailSignal::RemoteReset, None, 0, Some(&remote_obs));

        let mut middlebox = StrategyStatsV2::default();
        let middlebox_obs = KeyObservation {
            first_data_ttl: Some(58),
            rst_source: Some(RstSource::Middlebox),
            ..Default::default()
        };
        middlebox.record_with_observation(
            &FailSignal::DropSuspected,
            None,
            0,
            Some(&middlebox_obs),
        );

        assert!(remote.fitness_score > middlebox.fitness_score);
        assert!(middlebox.fitness_score < 0.5);
    }

    #[test]
    fn strategy_stats_shape_timeout_after_data_softer_than_middlebox_reset() {
        let mut collapse = StrategyStatsV2::default();
        let collapse_obs = KeyObservation {
            first_data_ttl: Some(58),
            ..Default::default()
        };
        collapse.record_with_observation(
            &FailSignal::ThroughputCollapse,
            None,
            0,
            Some(&collapse_obs),
        );

        let mut middlebox_reset = StrategyStatsV2::default();
        let reset_obs = KeyObservation {
            first_data_ttl: Some(58),
            rst_source: Some(RstSource::Middlebox),
            ..Default::default()
        };
        middlebox_reset.record_with_observation(
            &FailSignal::DropSuspected,
            None,
            0,
            Some(&reset_obs),
        );

        assert!(collapse.fitness_score > middlebox_reset.fitness_score);
    }

    #[test]
    fn strategy_stats_shape_zero_window_collapse_above_plain_collapse() {
        let mut plain_collapse = StrategyStatsV2::default();
        let plain_obs = KeyObservation {
            first_data_ttl: Some(58),
            first_data_window: Some(65535),
            ..Default::default()
        };
        plain_collapse.record_with_observation(
            &FailSignal::ThroughputCollapse,
            None,
            0,
            Some(&plain_obs),
        );

        let mut zero_window_collapse = StrategyStatsV2::default();
        let zero_window_obs = KeyObservation {
            first_data_ttl: Some(58),
            first_data_window: Some(0),
            ..Default::default()
        };
        zero_window_collapse.record_with_observation(
            &FailSignal::ThroughputCollapse,
            None,
            0,
            Some(&zero_window_obs),
        );

        assert!(zero_window_collapse.fitness_score > plain_collapse.fitness_score);
    }

    #[test]
    fn strategy_stats_shape_small_window_collapse_between_zero_window_and_plain() {
        let mut plain_collapse = StrategyStatsV2::default();
        let plain_obs = KeyObservation {
            first_data_ttl: Some(58),
            first_data_window: Some(65535),
            ..Default::default()
        };
        plain_collapse.record_with_observation(
            &FailSignal::ThroughputCollapse,
            None,
            0,
            Some(&plain_obs),
        );

        let mut small_window_collapse = StrategyStatsV2::default();
        let small_window_obs = KeyObservation {
            first_data_ttl: Some(58),
            first_data_window: Some(512),
            ..Default::default()
        };
        small_window_collapse.record_with_observation(
            &FailSignal::ThroughputCollapse,
            None,
            0,
            Some(&small_window_obs),
        );

        let mut zero_window_collapse = StrategyStatsV2::default();
        let zero_window_obs = KeyObservation {
            first_data_ttl: Some(58),
            first_data_window: Some(0),
            ..Default::default()
        };
        zero_window_collapse.record_with_observation(
            &FailSignal::ThroughputCollapse,
            None,
            0,
            Some(&zero_window_obs),
        );

        assert!(small_window_collapse.fitness_score > plain_collapse.fitness_score);
        assert!(zero_window_collapse.fitness_score > small_window_collapse.fitness_score);
    }

    #[test]
    fn strategy_stats_shape_dup_ack_collapse_between_small_window_and_plain() {
        let mut plain_collapse = StrategyStatsV2::default();
        let plain_obs = KeyObservation {
            first_data_ttl: Some(58),
            first_data_window: Some(65535),
            ..Default::default()
        };
        plain_collapse.record_with_observation(
            &FailSignal::ThroughputCollapse,
            None,
            0,
            Some(&plain_obs),
        );

        let mut dup_ack_collapse = StrategyStatsV2::default();
        let dup_ack_obs = KeyObservation {
            first_data_ttl: Some(58),
            first_data_window: Some(65535),
            downstream_dup_ack_count: 2,
            ..Default::default()
        };
        dup_ack_collapse.record_with_observation(
            &FailSignal::ThroughputCollapse,
            None,
            0,
            Some(&dup_ack_obs),
        );

        let mut small_window_collapse = StrategyStatsV2::default();
        let small_window_obs = KeyObservation {
            first_data_ttl: Some(58),
            first_data_window: Some(512),
            ..Default::default()
        };
        small_window_collapse.record_with_observation(
            &FailSignal::ThroughputCollapse,
            None,
            0,
            Some(&small_window_obs),
        );

        assert!(dup_ack_collapse.fitness_score > plain_collapse.fitness_score);
        assert!(small_window_collapse.fitness_score > dup_ack_collapse.fitness_score);
    }

    #[test]
    fn strategy_stats_shape_retransmit_collapse_between_small_window_and_dup_ack() {
        let mut dup_ack_collapse = StrategyStatsV2::default();
        let dup_ack_obs = KeyObservation {
            first_data_ttl: Some(58),
            first_data_window: Some(65535),
            downstream_dup_ack_count: 2,
            ..Default::default()
        };
        dup_ack_collapse.record_with_observation(
            &FailSignal::ThroughputCollapse,
            None,
            0,
            Some(&dup_ack_obs),
        );

        let mut retransmit_collapse = StrategyStatsV2::default();
        let retransmit_obs = KeyObservation {
            first_data_ttl: Some(58),
            first_data_window: Some(65535),
            downstream_retransmit_count: 1,
            ..Default::default()
        };
        retransmit_collapse.record_with_observation(
            &FailSignal::ThroughputCollapse,
            None,
            0,
            Some(&retransmit_obs),
        );

        let mut small_window_collapse = StrategyStatsV2::default();
        let small_window_obs = KeyObservation {
            first_data_ttl: Some(58),
            first_data_window: Some(512),
            ..Default::default()
        };
        small_window_collapse.record_with_observation(
            &FailSignal::ThroughputCollapse,
            None,
            0,
            Some(&small_window_obs),
        );

        assert!(retransmit_collapse.fitness_score > dup_ack_collapse.fitness_score);
        assert!(small_window_collapse.fitness_score > retransmit_collapse.fitness_score);
    }

    #[test]
    fn strategy_stats_shape_fin_collapse_between_small_window_and_retransmit() {
        let mut retransmit_collapse = StrategyStatsV2::default();
        let retransmit_obs = KeyObservation {
            first_data_ttl: Some(58),
            first_data_window: Some(65535),
            downstream_retransmit_count: 1,
            ..Default::default()
        };
        retransmit_collapse.record_with_observation(
            &FailSignal::ThroughputCollapse,
            None,
            0,
            Some(&retransmit_obs),
        );

        let mut fin_collapse = StrategyStatsV2::default();
        let fin_obs = KeyObservation {
            first_data_ttl: Some(58),
            first_data_window: Some(65535),
            downstream_fin_after_data: true,
            ..Default::default()
        };
        fin_collapse.record_with_observation(
            &FailSignal::ThroughputCollapse,
            None,
            0,
            Some(&fin_obs),
        );

        let mut small_window_collapse = StrategyStatsV2::default();
        let small_window_obs = KeyObservation {
            first_data_ttl: Some(58),
            first_data_window: Some(512),
            ..Default::default()
        };
        small_window_collapse.record_with_observation(
            &FailSignal::ThroughputCollapse,
            None,
            0,
            Some(&small_window_obs),
        );

        assert!(fin_collapse.fitness_score > retransmit_collapse.fitness_score);
        assert!(small_window_collapse.fitness_score > fin_collapse.fitness_score);
    }

    #[test]
    fn strategy_stats_shape_remote_reset_after_server_hello_weaker_than_after_data() {
        let mut after_hello = StrategyStatsV2::default();
        let hello_obs = KeyObservation {
            first_response_bytes: 120,
            tls_server_hello_seen: true,
            rst_source: Some(RstSource::Remote),
            ..Default::default()
        };
        after_hello.record_with_observation(&FailSignal::RemoteReset, None, 0, Some(&hello_obs));

        let mut after_data = StrategyStatsV2::default();
        let data_obs = KeyObservation {
            first_data_ttl: Some(58),
            rst_source: Some(RstSource::Remote),
            ..Default::default()
        };
        after_data.record_with_observation(&FailSignal::RemoteReset, None, 0, Some(&data_obs));

        assert!(after_data.fitness_score > after_hello.fitness_score);
    }

    #[test]
    fn strategy_stats_shape_remote_reset_after_syn_ack_weaker_than_after_server_hello() {
        let mut after_syn_ack = StrategyStatsV2::default();
        let syn_ack_obs = KeyObservation {
            syn_ack_ttl: Some(58),
            syn_ack_window: Some(65535),
            rst_source: Some(RstSource::Remote),
            ..Default::default()
        };
        after_syn_ack.record_with_observation(
            &FailSignal::RemoteReset,
            None,
            0,
            Some(&syn_ack_obs),
        );

        let mut after_hello = StrategyStatsV2::default();
        let hello_obs = KeyObservation {
            first_response_bytes: 120,
            tls_server_hello_seen: true,
            syn_ack_ttl: Some(58),
            rst_source: Some(RstSource::Remote),
            ..Default::default()
        };
        after_hello.record_with_observation(&FailSignal::RemoteReset, None, 0, Some(&hello_obs));

        assert!(after_hello.fitness_score > after_syn_ack.fitness_score);
    }

    #[test]
    fn strategy_stats_shape_remote_reset_after_bidirectional_relay_stronger_than_after_first_data()
    {
        let mut after_data = StrategyStatsV2::default();
        let data_obs = KeyObservation {
            first_data_ttl: Some(58),
            rst_source: Some(RstSource::Remote),
            ..Default::default()
        };
        after_data.record_with_observation(&FailSignal::RemoteReset, None, 0, Some(&data_obs));

        let mut after_relay = StrategyStatsV2::default();
        let relay_obs = KeyObservation {
            first_response_bytes: 120,
            tls_server_hello_seen: true,
            first_data_ttl: Some(58),
            relay_client_to_remote_bytes: 2048,
            relay_remote_to_client_bytes: 1024,
            rst_source: Some(RstSource::Remote),
            ..Default::default()
        };
        after_relay.record_with_observation(&FailSignal::RemoteReset, None, 0, Some(&relay_obs));

        assert!(after_relay.fitness_score > after_data.fitness_score);
    }

    #[test]
    fn strategy_stats_shape_remote_reset_after_uplink_only_weaker_than_bidirectional_relay() {
        let mut after_uplink = StrategyStatsV2::default();
        let uplink_obs = KeyObservation {
            first_response_bytes: 120,
            tls_server_hello_seen: true,
            first_data_ttl: Some(58),
            relay_client_to_remote_bytes: 2048,
            relay_remote_to_client_bytes: 0,
            rst_source: Some(RstSource::Remote),
            ..Default::default()
        };
        after_uplink.record_with_observation(&FailSignal::RemoteReset, None, 0, Some(&uplink_obs));

        let mut after_bidirectional = StrategyStatsV2::default();
        let relay_obs = KeyObservation {
            first_response_bytes: 120,
            tls_server_hello_seen: true,
            first_data_ttl: Some(58),
            relay_client_to_remote_bytes: 2048,
            relay_remote_to_client_bytes: 1024,
            rst_source: Some(RstSource::Remote),
            ..Default::default()
        };
        after_bidirectional.record_with_observation(
            &FailSignal::RemoteReset,
            None,
            0,
            Some(&relay_obs),
        );

        assert!(after_bidirectional.fitness_score > after_uplink.fitness_score);
    }

    #[test]
    fn strategy_stats_shape_remote_reset_after_downstream_heavy_relay_stronger_than_short_bidirectional(
    ) {
        let mut short_bidirectional = StrategyStatsV2::default();
        let short_obs = KeyObservation {
            first_response_bytes: 120,
            tls_server_hello_seen: true,
            first_data_ttl: Some(58),
            relay_client_to_remote_bytes: 4096,
            relay_remote_to_client_bytes: 512,
            rst_source: Some(RstSource::Remote),
            ..Default::default()
        };
        short_bidirectional.record_with_observation(
            &FailSignal::RemoteReset,
            None,
            0,
            Some(&short_obs),
        );

        let mut downstream_heavy = StrategyStatsV2::default();
        let heavy_obs = KeyObservation {
            first_response_bytes: 120,
            tls_server_hello_seen: true,
            first_data_ttl: Some(58),
            relay_client_to_remote_bytes: 2048,
            relay_remote_to_client_bytes: 2048,
            rst_source: Some(RstSource::Remote),
            ..Default::default()
        };
        downstream_heavy.record_with_observation(
            &FailSignal::RemoteReset,
            None,
            0,
            Some(&heavy_obs),
        );

        assert!(downstream_heavy.fitness_score > short_bidirectional.fitness_score);
    }

    #[test]
    fn strategy_stats_shape_longer_downstream_heavy_relay_stronger_than_shorter_one() {
        let mut shorter = StrategyStatsV2::default();
        let shorter_obs = KeyObservation {
            first_response_bytes: 120,
            tls_server_hello_seen: true,
            relay_client_to_remote_bytes: 2048,
            relay_remote_to_client_bytes: 2048,
            relay_lifetime_ms: 500,
            configured_timeout_ms: 5000,
            first_data_ttl: Some(58),
            rst_source: Some(RstSource::Remote),
            ..Default::default()
        };
        shorter.record_with_observation(&FailSignal::RemoteReset, None, 0, Some(&shorter_obs));

        let mut longer = StrategyStatsV2::default();
        let longer_obs = KeyObservation {
            first_response_bytes: 120,
            tls_server_hello_seen: true,
            relay_client_to_remote_bytes: 2048,
            relay_remote_to_client_bytes: 2048,
            relay_lifetime_ms: 3500,
            configured_timeout_ms: 5000,
            first_data_ttl: Some(58),
            rst_source: Some(RstSource::Remote),
            ..Default::default()
        };
        longer.record_with_observation(&FailSignal::RemoteReset, None, 0, Some(&longer_obs));

        assert!(longer.fitness_score > shorter.fitness_score);
    }

    #[test]
    fn strategy_stats_shape_very_late_downstream_heavy_reset_above_neutral_baseline() {
        let mut stats = StrategyStatsV2::default();
        let observation = KeyObservation {
            first_response_bytes: 120,
            tls_server_hello_seen: true,
            relay_client_to_remote_bytes: 1024,
            relay_remote_to_client_bytes: 4096,
            relay_lifetime_ms: 4500,
            configured_timeout_ms: 5000,
            first_data_ttl: Some(58),
            rst_source: Some(RstSource::Remote),
            ..Default::default()
        };
        stats.record_with_observation(&FailSignal::RemoteReset, None, 0, Some(&observation));

        assert!(stats.fitness_score > 0.5);
    }

    #[test]
    fn strategy_stats_shape_degraded_success_above_equivalent_late_remote_reset() {
        let observation = KeyObservation {
            first_response_bytes: 120,
            tls_server_hello_seen: true,
            relay_client_to_remote_bytes: 1024,
            relay_remote_to_client_bytes: 4096,
            relay_lifetime_ms: 4500,
            configured_timeout_ms: 5000,
            first_data_ttl: Some(58),
            rst_source: Some(RstSource::Remote),
            ..Default::default()
        };

        let mut late_reset = StrategyStatsV2::default();
        late_reset.record_with_observation(&FailSignal::RemoteReset, None, 0, Some(&observation));

        let mut degraded = StrategyStatsV2::default();
        degraded.record_with_observation(
            &FailSignal::SuccessDegraded,
            Some(6000),
            4096,
            Some(&observation),
        );

        assert!(degraded.fitness_score > late_reset.fitness_score);
    }

    #[test]
    fn strategy_stats_shape_late_throughput_collapse_above_early_first_data_collapse() {
        let mut early_collapse = StrategyStatsV2::default();
        let early_observation = KeyObservation {
            first_response_bytes: 120,
            tls_server_hello_seen: true,
            first_data_ttl: Some(58),
            ..Default::default()
        };
        early_collapse.record_with_observation(
            &FailSignal::ThroughputCollapse,
            None,
            0,
            Some(&early_observation),
        );

        let mut late_collapse = StrategyStatsV2::default();
        let late_observation = KeyObservation {
            first_response_bytes: 120,
            tls_server_hello_seen: true,
            relay_client_to_remote_bytes: 1024,
            relay_remote_to_client_bytes: 4096,
            relay_lifetime_ms: 4500,
            configured_timeout_ms: 5000,
            first_data_ttl: Some(58),
            ..Default::default()
        };
        late_collapse.record_with_observation(
            &FailSignal::ThroughputCollapse,
            None,
            0,
            Some(&late_observation),
        );

        assert!(late_collapse.fitness_score > early_collapse.fitness_score);
    }

    #[test]
    fn strategy_stats_shape_high_confidence_packet_first_data_reset_above_low_confidence_one() {
        let mut low_confidence = StrategyStatsV2::default();
        let low_confidence_observation = KeyObservation {
            capture_backend: Some(PacketCaptureBackendKind::LinuxRawBasic),
            capture_filter_applied: false,
            capture_ring_layout: None,
            capture_io_path: Some(PacketCaptureIoPath::RawBasicRecv),
            capture_wait_cycles: 1,
            matched_packets: 1,
            first_data_ttl: Some(58),
            first_packet_ttl: Some(58),
            rst_ttl: Some(58),
            rst_source: Some(RstSource::Remote),
            ..Default::default()
        };
        low_confidence.record_with_observation(
            &FailSignal::RemoteReset,
            None,
            0,
            Some(&low_confidence_observation),
        );

        let mut high_confidence = StrategyStatsV2::default();
        let high_confidence_observation = KeyObservation {
            capture_backend: Some(PacketCaptureBackendKind::LinuxAfPacket),
            capture_filter_applied: true,
            capture_ring_layout: Some(PacketCaptureRingLayout {
                block_size: 8192,
                block_nr: 3,
                frame_size: 4096,
                frame_nr: 6,
            }),
            capture_io_path: Some(PacketCaptureIoPath::AfPacketRing),
            capture_wait_cycles: 1,
            matched_packets: 2,
            first_data_ttl: Some(58),
            first_packet_ttl: Some(58),
            rst_ttl: Some(58),
            rst_source: Some(RstSource::Remote),
            ..Default::default()
        };
        high_confidence.record_with_observation(
            &FailSignal::RemoteReset,
            None,
            0,
            Some(&high_confidence_observation),
        );

        assert!(high_confidence.fitness_score > low_confidence.fitness_score);
    }

    #[test]
    fn strategy_stats_shape_degraded_success_rewards_higher_capture_confidence() {
        let low_confidence_observation = KeyObservation {
            capture_status: PacketCaptureStatus::Active,
            capture_backend: Some(PacketCaptureBackendKind::LinuxAfPacket),
            capture_filter_applied: false,
            capture_ring_layout: None,
            capture_io_path: Some(PacketCaptureIoPath::AfPacketRecv),
            capture_wait_cycles: 10,
            matched_packets: 1,
            syn_ack_ttl: Some(58),
            syn_ack_window: Some(65535),
            syn_ack_server_hint: Some(ServerType::LikelyCdn),
            ..Default::default()
        };
        let high_confidence_observation = KeyObservation {
            capture_status: PacketCaptureStatus::Active,
            capture_backend: Some(PacketCaptureBackendKind::LinuxAfPacket),
            capture_filter_applied: true,
            capture_ring_layout: Some(PacketCaptureRingLayout {
                block_size: 8192,
                block_nr: 3,
                frame_size: 4096,
                frame_nr: 6,
            }),
            capture_io_path: Some(PacketCaptureIoPath::AfPacketRing),
            capture_wait_cycles: 1,
            matched_packets: 3,
            syn_ack_ttl: Some(58),
            syn_ack_window: Some(65535),
            syn_ack_server_hint: Some(ServerType::LikelyCdn),
            ..Default::default()
        };
        assert!(
            success_degraded_reward(&high_confidence_observation)
                > success_degraded_reward(&low_confidence_observation)
        );
    }

    #[test]
    fn strategy_stats_shape_captureless_shallow_reset_stays_at_low_confidence_floor() {
        let mut captureless = StrategyStatsV2::default();
        let captureless_observation = KeyObservation {
            capture_backend: None,
            capture_filter_applied: false,
            capture_ring_layout: None,
            capture_io_path: None,
            capture_wait_cycles: 0,
            matched_packets: 2,
            first_data_ttl: Some(58),
            first_data_window: Some(65535),
            rst_source: Some(RstSource::Remote),
            ..Default::default()
        };
        captureless.record_with_observation(
            &FailSignal::RemoteReset,
            None,
            0,
            Some(&captureless_observation),
        );

        let mut captured = StrategyStatsV2::default();
        let captured_observation = KeyObservation {
            capture_backend: Some(PacketCaptureBackendKind::LinuxAfPacket),
            capture_filter_applied: true,
            capture_ring_layout: Some(PacketCaptureRingLayout {
                block_size: 8192,
                block_nr: 2,
                frame_size: 4096,
                frame_nr: 4,
            }),
            capture_io_path: Some(PacketCaptureIoPath::AfPacketRing),
            capture_wait_cycles: 1,
            matched_packets: 2,
            first_data_ttl: Some(58),
            first_data_window: Some(65535),
            rst_source: Some(RstSource::Remote),
            ..Default::default()
        };
        captured.record_with_observation(
            &FailSignal::RemoteReset,
            None,
            0,
            Some(&captured_observation),
        );

        assert!(captured.fitness_score > captureless.fitness_score);
    }

    #[test]
    fn strategy_stats_shape_explicit_observer_absence_beats_stale_backend_metadata() {
        let mut absent = StrategyStatsV2::default();
        let absent_observation = KeyObservation {
            capture_status: PacketCaptureStatus::UnsupportedPlatform,
            capture_backend: Some(PacketCaptureBackendKind::LinuxAfPacket),
            capture_filter_applied: true,
            capture_ring_layout: Some(PacketCaptureRingLayout {
                block_size: 8192,
                block_nr: 2,
                frame_size: 4096,
                frame_nr: 4,
            }),
            capture_io_path: Some(PacketCaptureIoPath::AfPacketRing),
            capture_wait_cycles: 1,
            matched_packets: 2,
            first_data_ttl: Some(58),
            first_data_window: Some(65535),
            rst_source: Some(RstSource::Remote),
            ..Default::default()
        };
        absent.record_with_observation(
            &FailSignal::RemoteReset,
            None,
            0,
            Some(&absent_observation),
        );

        let mut captured = StrategyStatsV2::default();
        let captured_observation = KeyObservation {
            capture_status: PacketCaptureStatus::Active,
            capture_backend: Some(PacketCaptureBackendKind::LinuxAfPacket),
            capture_filter_applied: true,
            capture_ring_layout: Some(PacketCaptureRingLayout {
                block_size: 8192,
                block_nr: 2,
                frame_size: 4096,
                frame_nr: 4,
            }),
            capture_io_path: Some(PacketCaptureIoPath::AfPacketRing),
            capture_wait_cycles: 1,
            matched_packets: 2,
            first_data_ttl: Some(58),
            first_data_window: Some(65535),
            rst_source: Some(RstSource::Remote),
            ..Default::default()
        };
        captured.record_with_observation(
            &FailSignal::RemoteReset,
            None,
            0,
            Some(&captured_observation),
        );

        assert!(captured.fitness_score > absent.fitness_score);
    }

    #[test]
    fn strategy_stats_shape_equivalent_late_outcomes_keep_expected_order() {
        let observation = KeyObservation {
            first_response_bytes: 120,
            tls_server_hello_seen: true,
            relay_client_to_remote_bytes: 1024,
            relay_remote_to_client_bytes: 4096,
            relay_lifetime_ms: 4500,
            configured_timeout_ms: 5000,
            first_data_ttl: Some(58),
            rst_source: Some(RstSource::Remote),
            ..Default::default()
        };

        let mut collapse = StrategyStatsV2::default();
        collapse.record_with_observation(
            &FailSignal::ThroughputCollapse,
            None,
            0,
            Some(&observation),
        );

        let mut late_reset = StrategyStatsV2::default();
        late_reset.record_with_observation(&FailSignal::RemoteReset, None, 0, Some(&observation));

        let mut degraded = StrategyStatsV2::default();
        degraded.record_with_observation(
            &FailSignal::SuccessDegraded,
            Some(6000),
            4096,
            Some(&observation),
        );

        assert!(degraded.fitness_score > late_reset.fitness_score);
        assert!(late_reset.fitness_score > collapse.fitness_score);
    }

    #[test]
    fn strategy_stats_success_rate() {
        let mut s = StrategyStatsV2::default();
        s.record(&FailSignal::Success, Some(50), 1000);
        s.record(&FailSignal::Success, Some(60), 2000);
        s.record(&FailSignal::Timeout, None, 0);
        assert!((s.success_rate() - 2.0 / 3.0).abs() < 0.01);
    }

    #[test]
    fn key_observation_exposes_reference_and_rst_hops() {
        let observation = KeyObservation {
            first_data_ttl: Some(58),
            syn_ack_ttl: Some(57),
            first_packet_ttl: Some(56),
            rst_ttl: Some(50),
            ..Default::default()
        };
        assert_eq!(observation.reference_path_hops(), Some(2));
        assert_eq!(observation.rst_path_hops(), Some(10));
    }

    #[test]
    fn runtime_server_hint_prefers_first_data_then_trusted_shallow() {
        let deep = KeyObservation {
            matched_packets: 1,
            first_data_server_hint: Some(ServerType::LikelyCloudflare),
            ..Default::default()
        };
        assert_eq!(
            deep.runtime_server_hint(),
            Some(ServerType::LikelyCloudflare)
        );

        let shallow = KeyObservation {
            matched_packets: 2,
            capture_status: PacketCaptureStatus::Active,
            capture_backend: Some(PacketCaptureBackendKind::LinuxAfPacket),
            capture_filter_applied: true,
            syn_ack_server_hint: Some(ServerType::LikelyCdn),
            ..Default::default()
        };
        assert_eq!(shallow.runtime_server_hint(), Some(ServerType::LikelyCdn));
    }

    #[test]
    fn runtime_window_profile_hint_respects_trust_gating() {
        let low_confidence = KeyObservation {
            syn_ack_window: Some(65000),
            ..Default::default()
        };
        assert_eq!(low_confidence.runtime_window_profile_hint(), None);

        let trusted_shallow = KeyObservation {
            matched_packets: 2,
            capture_status: PacketCaptureStatus::Active,
            capture_backend: Some(PacketCaptureBackendKind::LinuxAfPacket),
            capture_filter_applied: true,
            syn_ack_window: Some(65000),
            ..Default::default()
        };
        assert_eq!(
            trusted_shallow.runtime_window_profile_hint(),
            Some(WindowProfile::Huge)
        );
    }

    #[test]
    fn state_snapshot_default() {
        let snap = StateSnapshot::default();
        assert_eq!(snap.schema_version, 2);
        assert!(snap.key_registry.is_empty());
        assert!(snap.key_observations.is_empty());
        assert!(snap.strategy_stats.is_empty());
        assert!(snap.stall_probe_stats.is_empty());
    }

    #[test]
    fn stall_probe_stats_record_signal() {
        let mut stats = StallProbeStats::default();
        stats.record(&FailSignal::RemoteReset, Some(120));
        stats.record(
            &FailSignal::SessionFreeze {
                bytes_before_stall: 16384,
            },
            Some(250),
        );
        assert_eq!(stats.trials, 2);
        assert_eq!(stats.successes, 0);
        assert_eq!(stats.freezes, 1);
        assert_eq!(stats.collapses, 0);
        assert_eq!(stats.consecutive_stall_failures, 1);
        assert_eq!(
            stats.last_signal,
            Some(FailSignal::SessionFreeze {
                bytes_before_stall: 16384,
            })
        );
        assert!(stats.mean_latency_ms > 0.0);
    }

    #[test]
    fn stall_probe_stats_track_throughput_collapse() {
        let mut stats = StallProbeStats::default();
        stats.record(&FailSignal::ThroughputCollapse, Some(400));
        assert_eq!(stats.trials, 1);
        assert_eq!(stats.collapses, 1);
        assert_eq!(stats.consecutive_stall_failures, 1);
        assert_eq!(stats.last_signal, Some(FailSignal::ThroughputCollapse));
    }

    #[test]
    fn stall_probe_stats_reset_stall_streak_on_success() {
        let mut stats = StallProbeStats::default();
        stats.record(&FailSignal::ThroughputCollapse, Some(400));
        stats.record(
            &FailSignal::SessionFreeze {
                bytes_before_stall: 1024,
            },
            Some(450),
        );
        assert_eq!(stats.consecutive_stall_failures, 2);
        stats.record(&FailSignal::Success, Some(120));
        assert_eq!(stats.successes, 1);
        assert_eq!(stats.consecutive_stall_failures, 0);
    }

    #[test]
    fn stall_probe_stats_deserialize_missing_new_fields() {
        let json = r#"{
            "trials": 2,
            "successes": 0,
            "degraded": 0,
            "freezes": 1,
            "timeouts": 1,
            "dpi_blocks": 0,
            "last_signal": "ThroughputCollapse",
            "mean_latency_ms": 180.0
        }"#;
        let stats: StallProbeStats = serde_json::from_str(json).expect("deserialize old stats");
        assert_eq!(stats.collapses, 0);
        assert_eq!(stats.consecutive_stall_failures, 0);
        assert_eq!(stats.freezes, 1);
        assert_eq!(stats.timeouts, 1);
    }

    #[test]
    fn key_observation_contract_marks_explicit_absence() {
        let observation = KeyObservation {
            capture_status: PacketCaptureStatus::UnsupportedPlatform,
            capture_backend: Some(PacketCaptureBackendKind::LinuxAfPacket),
            matched_packets: 2,
            syn_ack_ttl: Some(58),
            ..Default::default()
        };
        assert_eq!(
            observation.observation_contract(),
            ObservationContract::ExplicitAbsence
        );
    }

    #[test]
    fn explicit_absence_never_supports_active_stall_probe() {
        let observation = KeyObservation {
            capture_status: PacketCaptureStatus::UnsupportedPlatform,
            capture_backend: Some(PacketCaptureBackendKind::LinuxAfPacket),
            matched_packets: 2,
            syn_ack_ttl: Some(58),
            first_data_ttl: Some(58),
            rst_ttl: Some(61),
            ..Default::default()
        };
        assert!(!observation.supports_active_stall_probe());
    }

    #[test]
    fn key_observation_contract_marks_trusted_shallow_capture() {
        let observation = KeyObservation {
            capture_status: PacketCaptureStatus::Active,
            capture_backend: Some(PacketCaptureBackendKind::LinuxAfPacket),
            capture_filter_applied: true,
            capture_io_path: Some(PacketCaptureIoPath::AfPacketRing),
            matched_packets: 2,
            syn_ack_ttl: Some(58),
            ..Default::default()
        };
        assert_eq!(
            observation.observation_contract(),
            ObservationContract::TrustedShallow
        );
        assert_eq!(
            observation.observation_capture_confidence(),
            "trusted_shallow_medium"
        );
    }

    #[test]
    fn key_observation_contract_marks_runtime_only_without_trusted_capture() {
        let observation = KeyObservation {
            capture_status: PacketCaptureStatus::NotAttempted,
            capture_backend: Some(PacketCaptureBackendKind::LinuxRawBasic),
            matched_packets: 1,
            syn_ack_ttl: Some(58),
            ..Default::default()
        };
        assert_eq!(
            observation.observation_contract(),
            ObservationContract::RuntimeOnly
        );
        assert_eq!(observation.observation_capture_confidence(), "runtime_only");
    }

    #[test]
    fn legacy_runtime_metadata_can_still_support_active_stall_probe() {
        let observation = KeyObservation {
            capture_status: PacketCaptureStatus::NotAttempted,
            capture_backend: Some(PacketCaptureBackendKind::LinuxRawBasic),
            matched_packets: 1,
            syn_ack_ttl: Some(58),
            ..Default::default()
        };
        // Preserve probe capability for older observations that recorded runtime
        // path metadata without marking capture as explicitly unavailable.
        assert!(observation.supports_active_stall_probe());
    }

    #[test]
    fn key_observation_contract_marks_deep_observation() {
        let observation = KeyObservation {
            first_response_bytes: 128,
            tls_server_hello_seen: true,
            capture_status: PacketCaptureStatus::NotAttempted,
            ..Default::default()
        };
        assert_eq!(
            observation.observation_contract(),
            ObservationContract::DeepObserved
        );
        assert_eq!(
            observation.observation_capture_confidence(),
            "deep_observed"
        );
    }

    #[test]
    fn explicit_absence_reports_explicit_confidence_bucket() {
        let observation = KeyObservation {
            capture_status: PacketCaptureStatus::UnsupportedPlatform,
            ..Default::default()
        };
        assert_eq!(
            observation.observation_capture_confidence(),
            "explicit_absence"
        );
    }
}
