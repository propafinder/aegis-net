//! Профили TCP-стека до `connect`: то, что доступно из userspace через socket2.
//!
//! Порядок опций на SYN задаёт ядро; здесь — nodelay, reuseaddr, TTL-подсказки там, где API есть.

use crate::config_types::WireMimicryMode;
use crate::probe::canonical_initial_ttl;
use crate::raw_engine::{default_raw_engine, RawCapabilities};
use crate::state_v2::{
    ObservedWireChoreographyHint, ObservedWireIpv4HeaderShaping, ObservedWireNegotiatedOptions,
};
use socket2::SockRef;
use std::io;
use std::net::SocketAddr;
use tokio::net::{TcpSocket, TcpStream};

/// Safe-default TTL used by `WireMimicryMode::LinuxExperimentalTtlPrefaceSafeDefaultCold`
/// when `resolve_wire_mimicry_runtime` is invoked без capture-backed observation.
///
/// Chosen to match the Linux kernel default initial TTL (64). Common on real
/// egress paths, so using it as the preface TTL on cold state doesn't create
/// a signature value that differs from normal traffic. Once `packet_observer`
/// accumulates real SYN-ACK observations the caller will pass a concrete
/// `ttl_hint` и the observed value will override this fallback inside
/// `resolve_wire_mimicry_runtime` независимо от chosen mode.
pub const SAFE_DEFAULT_COLD_START_TTL: u8 = 64;

/// Runtime slice name emitted alongside `activation_reason = "cold_start_safe_default_ttl"`
/// чтобы acceptance / telemetry pipelines могли distinguish cold-start preface
/// от capture-backed variants.
pub const COLD_START_RUNTIME_SLICE: &str = "linux_experimental_ipv4_ttl_preface_cold_start";

/// Именованный профиль из конфига.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackProfileId {
    Default,
    Windows11,
    Android13,
    LinuxDesktop,
    MacOs,
}

impl std::str::FromStr for StackProfileId {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "default" | "" => Ok(Self::Default),
            "windows" | "windows11" | "win11" => Ok(Self::Windows11),
            "android" | "android13" => Ok(Self::Android13),
            "linux" => Ok(Self::LinuxDesktop),
            "mac" | "macos" => Ok(Self::MacOs),
            _ => Err(()),
        }
    }
}

impl StackProfileId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Windows11 => "windows11",
            Self::Android13 => "android13",
            Self::LinuxDesktop => "linux",
            Self::MacOs => "macos",
        }
    }
}

/// Параметры, применимые до установления соединения.
#[derive(Debug, Clone)]
pub struct StackTuning {
    pub nodelay: bool,
    pub reuseaddr: bool,
    /// Coarse userspace buffer shaping. This is still not wire-level
    /// impersonation, but it gives profiles a stronger pre-connect surface.
    pub send_buffer_size: Option<usize>,
    pub recv_buffer_size: Option<usize>,
    /// Подсказка для `IP_TTL` (где поддерживается).
    pub suggested_ttl: Option<u32>,
}

/// Первый технический wire-level scope пока только оформляет границу
/// capability-layer: текущий runtime остаётся userspace-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireMimicryPlan {
    pub stage: &'static str,
    pub scope: &'static str,
    pub validation_strategy: &'static str,
    pub linux_only: bool,
    pub requires_raw_capabilities: bool,
    pub packet_profile_synthesis: &'static str,
    pub wire_policy_boundary: &'static str,
    pub validation_artifact: &'static str,
    pub host_acceptance_contour: &'static str,
    pub first_runtime_slice: &'static str,
    pub expanded_runtime_slice: &'static str,
    pub options_runtime_slice: &'static str,
    pub negotiated_options_runtime_slice: &'static str,
    pub fragment_choreography_runtime_slice: &'static str,
    pub experimental_config_path: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireNegotiatedOptionsPreface {
    pub profile: &'static str,
    pub source: &'static str,
    pub mss: u16,
    pub window_scale: u8,
    pub sack_permitted: bool,
    pub timestamp_mode: &'static str,
    pub size_bytes: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireFragmentChoreographyPlan {
    pub profile: &'static str,
    pub source: &'static str,
    pub steps: &'static str,
    pub fragment_first_payload_len: usize,
    pub fragment_overlap: usize,
    pub disorder_split_at: usize,
    pub overlap_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireIpv4HeaderShapingPreface {
    pub profile: &'static str,
    pub source: &'static str,
    pub tos: u8,
    pub identification: u16,
    pub dont_fragment: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireMimicryRuntimePlan {
    pub requested: bool,
    pub active: bool,
    pub activation_reason: &'static str,
    pub runtime_slice: Option<&'static str>,
    pub ttl_preface: Option<u8>,
    pub window_preface: Option<u16>,
    pub options_preface_profile: Option<&'static str>,
    pub options_preface_size: Option<u8>,
    pub ipv4_header_shaping: Option<WireIpv4HeaderShapingPreface>,
    pub negotiated_options: Option<WireNegotiatedOptionsPreface>,
    pub fragment_choreography: Option<WireFragmentChoreographyPlan>,
    pub raw_ipv4_send_ready: bool,
    pub tcp_repair_ready: bool,
    pub ipv4_header_control_ready: bool,
    pub ipv4_fragmentation_ready: bool,
}

pub fn wire_mimicry_plan() -> WireMimicryPlan {
    WireMimicryPlan {
        stage: "architecture_scaffold_only",
        scope: "future_packet_wire_linux_only",
        validation_strategy: "capture_replay_plus_privileged_host_acceptance",
        linux_only: true,
        requires_raw_capabilities: true,
        packet_profile_synthesis:
            "capture_backed_ttl_path_window_ipv4_header_plus_observed_tcp_option_inputs_with_profile_fallback",
        wire_policy_boundary:
            "best_effort_ipv4_ttl_window_and_negotiated_options_preface_before_strategy_send_first",
        validation_artifact: "wire_mimicry_validation_contract_v1",
        host_acceptance_contour: "privileged_linux_wire_mimicry_acceptance",
        first_runtime_slice: "linux_experimental_ipv4_ttl_preface",
        expanded_runtime_slice: "linux_experimental_ipv4_ttl_window_preface",
        options_runtime_slice: "linux_experimental_ipv4_ttl_window_options_preface",
        negotiated_options_runtime_slice:
            "linux_experimental_ipv4_ttl_window_negotiated_options_preface",
        fragment_choreography_runtime_slice:
            "linux_experimental_ipv4_fragment_ordered_decoy_choreography_preface",
        experimental_config_path: "direct.wire_mimicry_mode=linux_experimental_ttl_preface",
    }
}

pub fn wire_options_preface_profile(stack_profile: Option<StackProfileId>) -> Option<&'static str> {
    match stack_profile {
        Some(StackProfileId::Windows11)
        | Some(StackProfileId::Android13)
        | Some(StackProfileId::LinuxDesktop)
        | Some(StackProfileId::MacOs) => Some("ack_timestamp_pad12"),
        Some(StackProfileId::Default) | None => None,
    }
}

pub fn observed_wire_ipv4_header_shaping_preface(
    observed: Option<ObservedWireIpv4HeaderShaping>,
) -> Option<WireIpv4HeaderShapingPreface> {
    observed.map(|observed| WireIpv4HeaderShapingPreface {
        profile: "observed_capture_backed_ipv4_header_shaping_v1",
        source: "observed_capture_backed",
        tos: observed.tos,
        identification: observed.identification,
        dont_fragment: observed.dont_fragment,
    })
}

pub fn negotiated_wire_options_preface(
    stack_profile: Option<StackProfileId>,
    observation_capture_confidence: &str,
    window_profile: Option<&'static str>,
    observed: Option<ObservedWireNegotiatedOptions>,
) -> Option<WireNegotiatedOptionsPreface> {
    if observation_capture_confidence != "deep_observed" {
        return None;
    }
    if let Some(observed) = observed {
        let timestamp_mode = if observed.timestamps {
            "syn_timestamp_offer_layout20"
        } else {
            "syn_sack_window_scale_layout12"
        };
        let size_bytes = if observed.timestamps { 20 } else { 12 };
        return Some(WireNegotiatedOptionsPreface {
            profile: "observed_capture_backed_negotiated_options_v1",
            source: "observed_capture_backed",
            mss: observed.mss,
            window_scale: observed.window_scale,
            sack_permitted: observed.sack_permitted,
            timestamp_mode,
            size_bytes,
        });
    }
    let profile = match stack_profile {
        Some(StackProfileId::Windows11) => "windows11_negotiated_options_v1",
        Some(StackProfileId::Android13) => "android13_negotiated_options_v1",
        Some(StackProfileId::LinuxDesktop) => "linux_negotiated_options_v1",
        Some(StackProfileId::MacOs) => "macos_negotiated_options_v1",
        Some(StackProfileId::Default) | None => return None,
    };
    let window_profile = window_profile?;
    let window_scale = match window_profile {
        "tiny" => 2,
        "small" => 4,
        "medium" => 6,
        "large" => 7,
        "huge" => 8,
        _ => 6,
    };
    let mss = match stack_profile {
        Some(StackProfileId::Windows11) | Some(StackProfileId::LinuxDesktop) => 1460,
        Some(StackProfileId::Android13) => 1380,
        Some(StackProfileId::MacOs) => 1440,
        Some(StackProfileId::Default) | None => return None,
    };
    Some(WireNegotiatedOptionsPreface {
        profile,
        source: "heuristic_profile_derived",
        mss,
        window_scale,
        sack_permitted: true,
        // We still emit this through the raw preface path, but the byte layout now
        // follows a typical SYN-style option order instead of timestamp-only padding.
        timestamp_mode: "syn_timestamp_offer_layout20",
        size_bytes: 20,
    })
}

pub fn wire_fragment_choreography_plan(
    observation_capture_confidence: &str,
    window_profile: Option<&'static str>,
    observed: Option<ObservedWireChoreographyHint>,
) -> Option<WireFragmentChoreographyPlan> {
    if observation_capture_confidence != "deep_observed" {
        return None;
    }
    if let Some(observed) = observed {
        let first_payload_len = observed_fragment_payload_len(observed.first_payload_len);
        return Some(WireFragmentChoreographyPlan {
            profile: "observed_capture_backed_fragment_ordered_decoy_v1",
            source: "observed_capture_backed",
            steps: "fragment_then_disorder_then_overlap",
            fragment_first_payload_len: first_payload_len,
            fragment_overlap: 8,
            disorder_split_at: first_payload_len,
            overlap_bytes: 8,
        });
    }
    let window_profile = window_profile?;
    let fragment_first_payload_len = match window_profile {
        "tiny" | "small" => 24,
        "medium" => 32,
        "large" | "huge" => 40,
        _ => 32,
    };
    Some(WireFragmentChoreographyPlan {
        profile: "linux_fragment_disorder_overlap_v1",
        source: "heuristic_profile_derived",
        steps: "fragment_then_disorder_then_overlap",
        fragment_first_payload_len,
        fragment_overlap: 8,
        disorder_split_at: fragment_first_payload_len,
        overlap_bytes: 8,
    })
}

fn observed_fragment_payload_len(payload_len: usize) -> usize {
    match payload_len {
        0..=24 => 24,
        25..=36 => 32,
        _ => 40,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn resolve_wire_mimicry_runtime(
    mode: WireMimicryMode,
    dst: SocketAddr,
    raw_caps: RawCapabilities,
    ttl_hint: Option<u32>,
    window_hint: Option<u16>,
    options_preface_profile: Option<&'static str>,
    ipv4_header_shaping: Option<WireIpv4HeaderShapingPreface>,
    negotiated_options: Option<WireNegotiatedOptionsPreface>,
    fragment_choreography: Option<WireFragmentChoreographyPlan>,
) -> WireMimicryRuntimePlan {
    let requested = !matches!(mode, WireMimicryMode::Disabled);
    let ttl_preface = ttl_hint
        .and_then(|ttl| u8::try_from(ttl).ok())
        .filter(|ttl| *ttl > 0);
    if !requested {
        return WireMimicryRuntimePlan {
            requested: false,
            active: false,
            activation_reason: "config_disabled",
            runtime_slice: None,
            ttl_preface: None,
            window_preface: None,
            options_preface_profile: None,
            options_preface_size: None,
            ipv4_header_shaping: None,
            negotiated_options: None,
            fragment_choreography: None,
            raw_ipv4_send_ready: raw_caps.ipv4_raw_send,
            tcp_repair_ready: raw_caps.tcp_repair_query,
            ipv4_header_control_ready: raw_caps.ipv4_header_control,
            ipv4_fragmentation_ready: raw_caps.ipv4_fragmentation,
        };
    }
    if !cfg!(target_os = "linux") {
        return WireMimicryRuntimePlan {
            requested: true,
            active: false,
            activation_reason: "non_linux_runtime",
            runtime_slice: None,
            ttl_preface,
            window_preface: window_hint,
            options_preface_profile,
            options_preface_size: options_preface_profile.map(|_| 12),
            ipv4_header_shaping,
            negotiated_options,
            fragment_choreography,
            raw_ipv4_send_ready: raw_caps.ipv4_raw_send,
            tcp_repair_ready: raw_caps.tcp_repair_query,
            ipv4_header_control_ready: raw_caps.ipv4_header_control,
            ipv4_fragmentation_ready: raw_caps.ipv4_fragmentation,
        };
    }
    if !dst.is_ipv4() {
        return WireMimicryRuntimePlan {
            requested: true,
            active: false,
            activation_reason: "ipv6_not_supported_yet",
            runtime_slice: None,
            ttl_preface,
            window_preface: window_hint,
            options_preface_profile,
            options_preface_size: options_preface_profile.map(|_| 12),
            ipv4_header_shaping,
            negotiated_options,
            fragment_choreography,
            raw_ipv4_send_ready: raw_caps.ipv4_raw_send,
            tcp_repair_ready: raw_caps.tcp_repair_query,
            ipv4_header_control_ready: raw_caps.ipv4_header_control,
            ipv4_fragmentation_ready: raw_caps.ipv4_fragmentation,
        };
    }
    // Safe-default cold-start TTL fallback (v0.1.2 A4 architectural lift).
    //
    // When the caller opted into the permissive mode and the observer has
    // not yet produced a capture-backed TTL hint, substitute a plausible
    // kernel-default TTL (64) so the preface can fire. This is the chicken-
    // and-egg resolver: relay-primarily deployments would otherwise never
    // accumulate observations → never fire preface → stuck on yellow A4
    // verdict. The strict `LinuxExperimentalTtlPreface` mode keeps the old
    // `capture_backed_ttl_missing` refusal intact for callers that prefer
    // the safety gating.
    let mut ttl_preface = ttl_preface;
    let using_safe_default_ttl = match mode {
        WireMimicryMode::LinuxExperimentalTtlPrefaceSafeDefaultCold if ttl_preface.is_none() => {
            ttl_preface = Some(SAFE_DEFAULT_COLD_START_TTL);
            true
        }
        _ => false,
    };

    if ttl_preface.is_none() {
        return WireMimicryRuntimePlan {
            requested: true,
            active: false,
            activation_reason: "capture_backed_ttl_missing",
            runtime_slice: None,
            ttl_preface: None,
            window_preface: window_hint,
            options_preface_profile,
            options_preface_size: options_preface_profile.map(|_| 12),
            ipv4_header_shaping,
            negotiated_options,
            fragment_choreography,
            raw_ipv4_send_ready: raw_caps.ipv4_raw_send,
            tcp_repair_ready: raw_caps.tcp_repair_query,
            ipv4_header_control_ready: raw_caps.ipv4_header_control,
            ipv4_fragmentation_ready: raw_caps.ipv4_fragmentation,
        };
    }
    if !(raw_caps.ipv4_raw_send && raw_caps.tcp_repair_query && raw_caps.ipv4_header_control) {
        return WireMimicryRuntimePlan {
            requested: true,
            active: false,
            activation_reason: "raw_capabilities_missing",
            runtime_slice: None,
            ttl_preface,
            window_preface: window_hint,
            options_preface_profile,
            options_preface_size: options_preface_profile.map(|_| 12),
            ipv4_header_shaping,
            negotiated_options,
            fragment_choreography,
            raw_ipv4_send_ready: raw_caps.ipv4_raw_send,
            tcp_repair_ready: raw_caps.tcp_repair_query,
            ipv4_header_control_ready: raw_caps.ipv4_header_control,
            ipv4_fragmentation_ready: raw_caps.ipv4_fragmentation,
        };
    }
    let active_fragment_choreography =
        fragment_choreography.filter(|_| raw_caps.ipv4_fragmentation);
    // Each higher slice stays behind explicit inputs: TTL first, then capture-backed
    // window shaping, then stack-profile-derived TCP option padding, then
    // deep-observed negotiated option synthesis, then ordered raw choreography.
    //
    // Cold-start safe-default path emits a distinctive `runtime_slice` so
    // telemetry can separate "preface fired with observed TTL" from "preface
    // fired with kernel-default TTL because observer hadn't warmed". Higher
    // slices (window preface, choreography) stay gated behind capture-backed
    // inputs — safe-default only substitutes the TTL itself.
    let runtime_slice = if using_safe_default_ttl {
        COLD_START_RUNTIME_SLICE
    } else if window_hint.is_some() && active_fragment_choreography.is_some() {
        "linux_experimental_ipv4_fragment_ordered_decoy_choreography_preface"
    } else if window_hint.is_some() && negotiated_options.is_some() {
        "linux_experimental_ipv4_ttl_window_negotiated_options_preface"
    } else if window_hint.is_some() && options_preface_profile.is_some() {
        "linux_experimental_ipv4_ttl_window_options_preface"
    } else if window_hint.is_some() {
        "linux_experimental_ipv4_ttl_window_preface"
    } else {
        "linux_experimental_ipv4_ttl_preface"
    };
    let activation_reason = if using_safe_default_ttl {
        "cold_start_safe_default_ttl"
    } else {
        "linux_experimental_ttl_preface_active"
    };
    WireMimicryRuntimePlan {
        requested: true,
        active: true,
        activation_reason,
        runtime_slice: Some(runtime_slice),
        ttl_preface,
        window_preface: window_hint,
        options_preface_profile,
        options_preface_size: options_preface_profile.map(|_| 12),
        ipv4_header_shaping,
        negotiated_options,
        fragment_choreography: active_fragment_choreography,
        raw_ipv4_send_ready: raw_caps.ipv4_raw_send,
        tcp_repair_ready: raw_caps.tcp_repair_query,
        ipv4_header_control_ready: raw_caps.ipv4_header_control,
        ipv4_fragmentation_ready: raw_caps.ipv4_fragmentation,
    }
}

pub fn apply_experimental_wire_preface(
    stream: &TcpStream,
    dst: SocketAddr,
    payload: &[u8],
    runtime: &WireMimicryRuntimePlan,
) -> io::Result<()> {
    if !runtime.active || payload.is_empty() {
        return Ok(());
    }
    let Some(ttl) = runtime.ttl_preface else {
        return Ok(());
    };
    if let Some(window) = runtime.window_preface {
        if let Some(ref negotiated) = runtime.negotiated_options {
            default_raw_engine().try_send_ttl_window_negotiated_options_preface_first_packet(
                stream,
                dst,
                payload,
                ttl,
                window,
                runtime.ipv4_header_shaping.as_ref(),
                negotiated,
                "mimicry_wire_preface",
            )?;
            if let Some(ref choreography) = runtime.fragment_choreography {
                default_raw_engine().try_send_fragment_ordered_decoy_choreography_first_packet(
                    stream,
                    dst,
                    payload,
                    ttl,
                    runtime.ipv4_header_shaping.as_ref(),
                    choreography,
                    "mimicry_wire_preface",
                )?;
            }
        } else if runtime.options_preface_profile.is_some() {
            default_raw_engine().try_send_ttl_window_options_preface_first_packet(
                stream,
                dst,
                payload,
                ttl,
                window,
                runtime.ipv4_header_shaping.as_ref(),
                "mimicry_wire_preface",
            )?;
        } else {
            default_raw_engine().try_send_ttl_window_preface_first_packet(
                stream,
                dst,
                payload,
                ttl,
                window,
                runtime.ipv4_header_shaping.as_ref(),
                "mimicry_wire_preface",
            )?;
        }
    } else {
        default_raw_engine().try_send_ttl_desync_first_packet(
            stream,
            dst,
            payload,
            ttl,
            runtime.ipv4_header_shaping.as_ref(),
            "mimicry_wire_preface",
        )?;
    }
    Ok(())
}

pub fn tuning_for(id: StackProfileId) -> StackTuning {
    match id {
        StackProfileId::Default => StackTuning {
            nodelay: false,
            reuseaddr: false,
            send_buffer_size: None,
            recv_buffer_size: None,
            suggested_ttl: None,
        },
        StackProfileId::Windows11 => StackTuning {
            nodelay: true,
            reuseaddr: true,
            send_buffer_size: Some(256 * 1024),
            recv_buffer_size: Some(256 * 1024),
            suggested_ttl: Some(128),
        },
        StackProfileId::Android13 => StackTuning {
            nodelay: true,
            reuseaddr: true,
            send_buffer_size: Some(128 * 1024),
            recv_buffer_size: Some(128 * 1024),
            suggested_ttl: Some(64),
        },
        StackProfileId::LinuxDesktop => StackTuning {
            nodelay: false,
            reuseaddr: true,
            send_buffer_size: Some(192 * 1024),
            recv_buffer_size: Some(192 * 1024),
            suggested_ttl: Some(64),
        },
        StackProfileId::MacOs => StackTuning {
            nodelay: true,
            reuseaddr: true,
            send_buffer_size: Some(192 * 1024),
            recv_buffer_size: Some(192 * 1024),
            suggested_ttl: Some(64),
        },
    }
}

pub fn suggested_ttl_from_observed_ttl(observed_ttl: Option<u8>) -> Option<u32> {
    observed_ttl.map(canonical_initial_ttl).map(u32::from)
}

pub fn tuning_for_with_observed_ttl(id: StackProfileId, observed_ttl: Option<u8>) -> StackTuning {
    let mut tuning = tuning_for(id);
    if let Some(ttl) = suggested_ttl_from_observed_ttl(observed_ttl) {
        tuning.suggested_ttl = Some(ttl);
    }
    tuning
}

/// Применить настройки к сокету до `TcpSocket::connect`.
pub fn apply_pre_connect(
    socket: &TcpSocket,
    id: StackProfileId,
    dst: SocketAddr,
) -> io::Result<()> {
    apply_pre_connect_with_ttl_hint(socket, id, dst, None)
}

pub fn apply_pre_connect_with_ttl_hint(
    socket: &TcpSocket,
    id: StackProfileId,
    dst: SocketAddr,
    ttl_hint: Option<u32>,
) -> io::Result<()> {
    let mut t = tuning_for(id);
    if ttl_hint.is_some() {
        t.suggested_ttl = ttl_hint;
    }
    apply_socket_tuning(socket, dst, &t)
}

/// Применить только TTL/hops hint без profile-derived tuning.
///
/// Это остаётся userspace-only шагом, но теперь capture-backed path может
/// реально влиять на сокет даже когда оператор не задал `stack_profile`.
pub fn apply_ttl_hint_only(
    socket: &TcpSocket,
    dst: SocketAddr,
    ttl_hint: Option<u32>,
) -> io::Result<()> {
    let tuning = StackTuning {
        nodelay: false,
        reuseaddr: false,
        send_buffer_size: None,
        recv_buffer_size: None,
        suggested_ttl: ttl_hint,
    };
    apply_socket_tuning(socket, dst, &tuning)
}

fn apply_socket_tuning(
    socket: &TcpSocket,
    dst: SocketAddr,
    tuning: &StackTuning,
) -> io::Result<()> {
    let r = SockRef::from(socket);
    r.set_tcp_nodelay(tuning.nodelay)?;
    r.set_reuse_address(tuning.reuseaddr)?;
    if let Some(size) = tuning.send_buffer_size {
        let _ = r.set_send_buffer_size(size);
    }
    if let Some(size) = tuning.recv_buffer_size {
        let _ = r.set_recv_buffer_size(size);
    }
    if let Some(ttl) = tuning.suggested_ttl {
        match dst {
            SocketAddr::V4(_) => {
                let _ = r.set_ttl_v4(ttl);
            }
            SocketAddr::V6(_) => {
                let _ = r.set_unicast_hops_v6(ttl);
            }
        }
    }
    Ok(())
}

/// Per-session soft-wire socket-option plan. All values are sampled
/// independently from a session seed so two sessions in the same drift
/// epoch still diverge on the transport layer. No raw caps are required
/// — this plan is applied with the standard `TcpStream::set_ttl` /
/// `set_nodelay` (TCP) and `UdpSocket::set_ttl` (UDP) APIs that any
/// unprivileged process can call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoftWireRelaySocketPlan {
    /// IP_TTL value to install on the outgoing socket (TCP or UDP).
    /// Sampled from a plausible distribution {62, 64, 96, 128} that
    /// overlaps several real-world OS-family defaults; no single OS
    /// family is statically cloned, and the per-session draw is uniform.
    pub ip_ttl: u8,
    /// TCP_NODELAY flag. When `true`, disables Nagle so small writes go
    /// out immediately — observably varies the packet-coalescing
    /// fingerprint at the middlebox layer. Only meaningful for TCP
    /// transports.
    pub nodelay: bool,
    /// MASQUE/QUIC keep-alive interval override (ms). When `Some`, the
    /// MASQUE transport config uses this value in place of the
    /// settings-provided default; per-session variation in keep-alive
    /// cadence diversifies the UDP heartbeat fingerprint without
    /// drifting outside operationally-plausible idle-keepalive windows.
    /// `None` means the MASQUE transport keeps the settings default.
    pub masque_keep_alive_ms: Option<u64>,
    /// Per-session burst chunk count: number of consecutive write
    /// chunks that are flushed back-to-back before the inter-chunk
    /// delay applies. Sampled from {1, 2, 3, 4} per session seed.
    /// Currently advisory — emitted in the runtime event so the
    /// observer can see the per-session burst envelope; the actual
    /// write loop in `copy_with_policy` honors it best-effort by
    /// pacing every Nth chunk.
    pub burst_chunk_count: u8,
    /// Per-session additive jitter (ms) added to the relay
    /// `connect_timeout_ms` budget so retry pacing across attempts
    /// varies. Sampled from {0, 50, 150, 300} per session seed.
    pub retry_pacing_jitter_ms: u32,
    /// Whether this plan was actually applied to the socket. Set by the
    /// applier; reflects success of every setsockopt call.
    pub applied: bool,
}

impl SoftWireRelaySocketPlan {
    /// Sample a soft-wire socket plan from a session seed. Two distinct
    /// seeds yield two distinct plans with very high probability. The
    /// distribution is intentionally narrow so observed values stay
    /// inside what production traffic on the open internet shows.
    pub fn from_seed(seed: u64) -> Self {
        const TTL_DECK: [u8; 4] = [62, 64, 96, 128];
        // MASQUE keep-alive: sample from {7s, 9s, 11s, 13s} — straddles
        // the conservative default 10s without exceeding the typical
        // 30s idle timeout common at NAT middleboxes.
        const KA_DECK_MS: [u64; 4] = [7_000, 9_000, 11_000, 13_000];
        // Burst envelope: 1..=4 chunks back-to-back. 1 = no burst (each
        // chunk paced independently, identical to pre-axis behavior).
        const BURST_DECK: [u8; 4] = [1, 2, 3, 4];
        // Retry pacing additive jitter (ms): adds to the configured
        // connect_timeout_ms when computing per-attempt budget so the
        // backoff curve varies per session.
        const RETRY_JITTER_DECK_MS: [u32; 4] = [0, 50, 150, 300];
        let ttl_idx = ((seed) % TTL_DECK.len() as u64) as usize;
        let nodelay = (seed >> 8) & 1 == 1;
        let ka_idx = ((seed >> 16) % KA_DECK_MS.len() as u64) as usize;
        let burst_idx = ((seed >> 24) % BURST_DECK.len() as u64) as usize;
        let retry_idx = ((seed >> 32) % RETRY_JITTER_DECK_MS.len() as u64) as usize;
        Self {
            ip_ttl: TTL_DECK[ttl_idx],
            nodelay,
            masque_keep_alive_ms: Some(KA_DECK_MS[ka_idx]),
            burst_chunk_count: BURST_DECK[burst_idx],
            retry_pacing_jitter_ms: RETRY_JITTER_DECK_MS[retry_idx],
            applied: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observed_ttl_can_override_profile_ttl_hint() {
        let tuning = tuning_for_with_observed_ttl(StackProfileId::Windows11, Some(58));
        assert!(tuning.nodelay);
        assert!(tuning.reuseaddr);
        assert_eq!(tuning.send_buffer_size, Some(256 * 1024));
        assert_eq!(tuning.recv_buffer_size, Some(256 * 1024));
        assert_eq!(tuning.suggested_ttl, Some(60));
    }

    #[test]
    fn profile_ttl_hint_stays_default_without_observed_ttl() {
        let tuning = tuning_for_with_observed_ttl(StackProfileId::Windows11, None);
        assert!(tuning.nodelay);
        assert!(tuning.reuseaddr);
        assert_eq!(tuning.send_buffer_size, Some(256 * 1024));
        assert_eq!(tuning.recv_buffer_size, Some(256 * 1024));
        assert_eq!(tuning.suggested_ttl, Some(128));
    }

    #[test]
    fn reuseaddr_stays_profile_only_without_observed_ttl_dependency() {
        assert!(!tuning_for_with_observed_ttl(StackProfileId::Default, Some(58)).reuseaddr);
        assert!(tuning_for_with_observed_ttl(StackProfileId::LinuxDesktop, None).reuseaddr);
    }

    #[test]
    fn buffer_shaping_stays_profile_scoped() {
        let default = tuning_for(StackProfileId::Default);
        assert_eq!(default.send_buffer_size, None);
        assert_eq!(default.recv_buffer_size, None);

        let linux = tuning_for(StackProfileId::LinuxDesktop);
        assert_eq!(linux.send_buffer_size, Some(192 * 1024));
        assert_eq!(linux.recv_buffer_size, Some(192 * 1024));
    }

    #[test]
    fn wire_mimicry_plan_stays_explicitly_separate_from_userspace_surface() {
        let plan = wire_mimicry_plan();
        assert_eq!(plan.stage, "architecture_scaffold_only");
        assert_eq!(plan.scope, "future_packet_wire_linux_only");
        assert_eq!(
            plan.validation_strategy,
            "capture_replay_plus_privileged_host_acceptance"
        );
        assert!(plan.linux_only);
        assert!(plan.requires_raw_capabilities);
        assert_eq!(
            plan.packet_profile_synthesis,
            "capture_backed_ttl_path_window_ipv4_header_plus_observed_tcp_option_inputs_with_profile_fallback"
        );
        assert_eq!(
            plan.wire_policy_boundary,
            "best_effort_ipv4_ttl_window_and_negotiated_options_preface_before_strategy_send_first"
        );
        assert_eq!(
            plan.validation_artifact,
            "wire_mimicry_validation_contract_v1"
        );
        assert_eq!(
            plan.host_acceptance_contour,
            "privileged_linux_wire_mimicry_acceptance"
        );
        assert_eq!(
            plan.first_runtime_slice,
            "linux_experimental_ipv4_ttl_preface"
        );
        assert_eq!(
            plan.expanded_runtime_slice,
            "linux_experimental_ipv4_ttl_window_preface"
        );
        assert_eq!(
            plan.options_runtime_slice,
            "linux_experimental_ipv4_ttl_window_options_preface"
        );
        assert_eq!(
            plan.negotiated_options_runtime_slice,
            "linux_experimental_ipv4_ttl_window_negotiated_options_preface"
        );
        assert_eq!(
            plan.fragment_choreography_runtime_slice,
            "linux_experimental_ipv4_fragment_ordered_decoy_choreography_preface"
        );
        assert_eq!(
            plan.experimental_config_path,
            "direct.wire_mimicry_mode=linux_experimental_ttl_preface"
        );
    }

    #[test]
    fn wire_runtime_plan_stays_disabled_without_explicit_config() {
        let runtime = resolve_wire_mimicry_runtime(
            WireMimicryMode::Disabled,
            "127.0.0.1:443".parse().expect("ipv4 socket"),
            RawCapabilities {
                ipv4_raw_send: true,
                ipv4_packet_capture: true,
                tcp_repair_query: true,
                ipv4_header_control: true,
                ipv4_fragmentation: true,
            },
            Some(64),
            Some(65535),
            wire_options_preface_profile(Some(StackProfileId::LinuxDesktop)),
            None,
            negotiated_wire_options_preface(
                Some(StackProfileId::LinuxDesktop),
                "deep_observed",
                Some("huge"),
                None,
            ),
            wire_fragment_choreography_plan("deep_observed", Some("huge"), None),
        );
        assert!(!runtime.requested);
        assert!(!runtime.active);
        assert_eq!(runtime.activation_reason, "config_disabled");
        assert!(runtime.runtime_slice.is_none());
        assert!(runtime.ttl_preface.is_none());
        assert!(runtime.window_preface.is_none());
        assert!(runtime.options_preface_profile.is_none());
        assert!(runtime.options_preface_size.is_none());
        assert!(runtime.negotiated_options.is_none());
        assert!(runtime.fragment_choreography.is_none());
        assert!(runtime.ipv4_fragmentation_ready);
    }

    #[test]
    fn wire_runtime_plan_requires_ipv4_raw_capabilities_and_ttl_hint() {
        let runtime = resolve_wire_mimicry_runtime(
            WireMimicryMode::LinuxExperimentalTtlPreface,
            "[::1]:443".parse().expect("ipv6 socket"),
            RawCapabilities {
                ipv4_raw_send: true,
                ipv4_packet_capture: true,
                tcp_repair_query: true,
                ipv4_header_control: true,
                ipv4_fragmentation: true,
            },
            Some(64),
            Some(65535),
            wire_options_preface_profile(Some(StackProfileId::LinuxDesktop)),
            None,
            negotiated_wire_options_preface(
                Some(StackProfileId::LinuxDesktop),
                "runtime_only",
                Some("huge"),
                None,
            ),
            wire_fragment_choreography_plan("runtime_only", Some("huge"), None),
        );
        assert!(runtime.requested);
        assert!(!runtime.active);
        if cfg!(target_os = "linux") {
            assert_eq!(runtime.activation_reason, "ipv6_not_supported_yet");
        } else {
            assert_eq!(runtime.activation_reason, "non_linux_runtime");
        }

        let missing_caps = resolve_wire_mimicry_runtime(
            WireMimicryMode::LinuxExperimentalTtlPreface,
            "127.0.0.1:443".parse().expect("ipv4 socket"),
            RawCapabilities {
                ipv4_raw_send: false,
                ipv4_packet_capture: true,
                tcp_repair_query: false,
                ipv4_header_control: false,
                ipv4_fragmentation: true,
            },
            Some(64),
            Some(65535),
            wire_options_preface_profile(Some(StackProfileId::LinuxDesktop)),
            None,
            negotiated_wire_options_preface(
                Some(StackProfileId::LinuxDesktop),
                "deep_observed",
                Some("huge"),
                None,
            ),
            wire_fragment_choreography_plan("deep_observed", Some("huge"), None),
        );
        assert!(missing_caps.requested);
        assert!(!missing_caps.active);
        if cfg!(target_os = "linux") {
            assert_eq!(missing_caps.activation_reason, "raw_capabilities_missing");
        } else {
            assert_eq!(missing_caps.activation_reason, "non_linux_runtime");
        }

        let active = resolve_wire_mimicry_runtime(
            WireMimicryMode::LinuxExperimentalTtlPreface,
            "127.0.0.1:443".parse().expect("ipv4 socket"),
            RawCapabilities {
                ipv4_raw_send: true,
                ipv4_packet_capture: true,
                tcp_repair_query: true,
                ipv4_header_control: true,
                ipv4_fragmentation: true,
            },
            Some(64),
            Some(65535),
            wire_options_preface_profile(Some(StackProfileId::LinuxDesktop)),
            None,
            negotiated_wire_options_preface(
                Some(StackProfileId::LinuxDesktop),
                "deep_observed",
                Some("huge"),
                None,
            ),
            wire_fragment_choreography_plan("deep_observed", Some("huge"), None),
        );
        if cfg!(target_os = "linux") {
            assert!(active.requested);
            assert!(active.active);
            assert_eq!(
                active.activation_reason,
                "linux_experimental_ttl_preface_active"
            );
            assert_eq!(
                active.runtime_slice,
                Some("linux_experimental_ipv4_fragment_ordered_decoy_choreography_preface")
            );
            assert_eq!(active.ttl_preface, Some(64));
            assert_eq!(active.window_preface, Some(65535));
            assert_eq!(active.options_preface_profile, Some("ack_timestamp_pad12"));
            assert_eq!(active.options_preface_size, Some(12));
            let negotiated = active.negotiated_options.expect("negotiated options");
            assert_eq!(negotiated.profile, "linux_negotiated_options_v1");
            assert_eq!(negotiated.source, "heuristic_profile_derived");
            assert_eq!(negotiated.mss, 1460);
            assert_eq!(negotiated.window_scale, 8);
            assert!(negotiated.sack_permitted);
            assert_eq!(negotiated.timestamp_mode, "syn_timestamp_offer_layout20");
            assert_eq!(negotiated.size_bytes, 20);
            let choreography = active.fragment_choreography.expect("fragment choreography");
            assert_eq!(choreography.profile, "linux_fragment_disorder_overlap_v1");
            assert_eq!(choreography.source, "heuristic_profile_derived");
            assert_eq!(choreography.steps, "fragment_then_disorder_then_overlap");
            assert_eq!(choreography.fragment_overlap, 8);
            assert_eq!(choreography.overlap_bytes, 8);
            assert!(active.ipv4_fragmentation_ready);
        } else {
            assert!(active.requested);
            assert!(!active.active);
            assert_eq!(active.activation_reason, "non_linux_runtime");
        }
    }

    #[test]
    fn negotiated_wire_options_require_deep_observed_capture() {
        assert!(negotiated_wire_options_preface(
            Some(StackProfileId::LinuxDesktop),
            "runtime_only",
            Some("huge"),
            None,
        )
        .is_none());
        let negotiated = negotiated_wire_options_preface(
            Some(StackProfileId::LinuxDesktop),
            "deep_observed",
            Some("large"),
            None,
        )
        .expect("deep observed negotiated options");
        assert_eq!(negotiated.profile, "linux_negotiated_options_v1");
        assert_eq!(negotiated.source, "heuristic_profile_derived");
        assert_eq!(negotiated.window_scale, 7);
    }

    #[test]
    fn fragment_choreography_requires_deep_observed_window_surface() {
        assert!(wire_fragment_choreography_plan("runtime_only", Some("huge"), None).is_none());
        let plan = wire_fragment_choreography_plan("deep_observed", Some("large"), None)
            .expect("deep observed choreography");
        assert_eq!(plan.profile, "linux_fragment_disorder_overlap_v1");
        assert_eq!(plan.source, "heuristic_profile_derived");
        assert_eq!(plan.fragment_first_payload_len, 40);
    }

    #[test]
    fn negotiated_wire_options_prefer_observed_capture_backing() {
        let negotiated = negotiated_wire_options_preface(
            None,
            "deep_observed",
            Some("large"),
            Some(ObservedWireNegotiatedOptions {
                mss: 1380,
                window_scale: 5,
                sack_permitted: false,
                timestamps: false,
            }),
        )
        .expect("observed negotiated options");
        assert_eq!(
            negotiated.profile,
            "observed_capture_backed_negotiated_options_v1"
        );
        assert_eq!(negotiated.source, "observed_capture_backed");
        assert_eq!(negotiated.timestamp_mode, "syn_sack_window_scale_layout12");
        assert_eq!(negotiated.size_bytes, 12);
    }

    #[test]
    fn fragment_choreography_prefers_observed_payload_shape() {
        let plan = wire_fragment_choreography_plan(
            "deep_observed",
            Some("small"),
            Some(ObservedWireChoreographyHint {
                first_payload_len: 35,
            }),
        )
        .expect("observed choreography");
        assert_eq!(
            plan.profile,
            "observed_capture_backed_fragment_ordered_decoy_v1"
        );
        assert_eq!(plan.source, "observed_capture_backed");
        assert_eq!(plan.fragment_first_payload_len, 32);
    }

    // v0.1.2 — safe-default TTL fallback tests (A4 architectural lift).
    //
    // Matching the pattern of `wire_runtime_plan_requires_ipv4_raw_capabilities_
    // and_ttl_hint`, each test branches on `cfg!(target_os = "linux")` inside
    // the body: Linux runs the production path, non-Linux short-circuits with
    // `non_linux_runtime` (which is verified too).
    #[test]
    fn cold_start_safe_default_ttl_activates_when_no_capture_hint() {
        let runtime = resolve_wire_mimicry_runtime(
            WireMimicryMode::LinuxExperimentalTtlPrefaceSafeDefaultCold,
            "127.0.0.1:443".parse().expect("ipv4 socket"),
            RawCapabilities {
                ipv4_raw_send: true,
                ipv4_packet_capture: true,
                tcp_repair_query: true,
                ipv4_header_control: true,
                ipv4_fragmentation: true,
            },
            None, // no capture-backed TTL yet (cold state)
            None, // no window hint either — preface keeps minimal slice
            None,
            None,
            None,
            None,
        );
        assert!(runtime.requested);
        if cfg!(target_os = "linux") {
            assert!(
                runtime.active,
                "cold-start safe-default mode must activate even without capture-backed TTL"
            );
            assert_eq!(runtime.activation_reason, "cold_start_safe_default_ttl");
            assert_eq!(runtime.runtime_slice, Some(COLD_START_RUNTIME_SLICE));
            assert_eq!(runtime.ttl_preface, Some(SAFE_DEFAULT_COLD_START_TTL));
            assert_eq!(runtime.ttl_preface, Some(64));
        } else {
            assert!(!runtime.active);
            assert_eq!(runtime.activation_reason, "non_linux_runtime");
        }
    }

    #[test]
    fn cold_start_mode_prefers_capture_backed_ttl_when_hint_available() {
        let observed_ttl: u32 = 55;
        let runtime = resolve_wire_mimicry_runtime(
            WireMimicryMode::LinuxExperimentalTtlPrefaceSafeDefaultCold,
            "127.0.0.1:443".parse().expect("ipv4 socket"),
            RawCapabilities {
                ipv4_raw_send: true,
                ipv4_packet_capture: true,
                tcp_repair_query: true,
                ipv4_header_control: true,
                ipv4_fragmentation: true,
            },
            Some(observed_ttl),
            None,
            None,
            None,
            None,
            None,
        );
        assert!(runtime.requested);
        if cfg!(target_os = "linux") {
            assert!(runtime.active);
            // Observed value wins over the fallback constant.
            assert_eq!(runtime.ttl_preface, Some(observed_ttl as u8));
            assert_ne!(runtime.ttl_preface, Some(SAFE_DEFAULT_COLD_START_TTL));
            // When hint present, the mode behaves identically к strict variant,
            // including the canonical activation reason.
            assert_eq!(
                runtime.activation_reason,
                "linux_experimental_ttl_preface_active"
            );
            // And picks the non-cold-start runtime_slice family.
            assert_ne!(runtime.runtime_slice, Some(COLD_START_RUNTIME_SLICE));
        } else {
            assert!(!runtime.active);
            assert_eq!(runtime.activation_reason, "non_linux_runtime");
            // Non-Linux short-circuit still carries the provided TTL hint.
            assert_eq!(runtime.ttl_preface, Some(observed_ttl as u8));
        }
    }

    #[test]
    fn strict_ttl_preface_mode_still_fails_without_capture_hint() {
        let runtime = resolve_wire_mimicry_runtime(
            WireMimicryMode::LinuxExperimentalTtlPreface, // strict mode
            "127.0.0.1:443".parse().expect("ipv4 socket"),
            RawCapabilities {
                ipv4_raw_send: true,
                ipv4_packet_capture: true,
                tcp_repair_query: true,
                ipv4_header_control: true,
                ipv4_fragmentation: true,
            },
            None, // cold state
            None,
            None,
            None,
            None,
            None,
        );
        assert!(runtime.requested);
        assert!(
            !runtime.active,
            "strict mode must still refuse to fire without capture-backed TTL (v0.1.2 preserves legacy behaviour)"
        );
        if cfg!(target_os = "linux") {
            assert_eq!(runtime.activation_reason, "capture_backed_ttl_missing");
            assert!(runtime.ttl_preface.is_none());
            assert!(runtime.runtime_slice.is_none());
        } else {
            assert_eq!(runtime.activation_reason, "non_linux_runtime");
        }
    }
}
