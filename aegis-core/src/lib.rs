//! AEGIS-Core: Relay-протокол, TLS (SNI), Brain, стратегии, Ghost-LURK, Shield.

pub mod auto_capture_probe;
pub mod bootstrap_launcher;
pub mod brain;
pub mod carrier_program;
pub mod carrier_runtime;
pub mod config_types;
pub mod dns_response;
pub mod error;
pub mod external_calibration;
pub mod installer_secret;
pub mod tunnel_policy;
pub mod web_response_profile;
// M1: Signal Foundation
pub mod auth_token;
pub mod fingerprint;
pub mod fronted_origin;
pub mod ghost_lurk;
pub mod h2_stream;
pub mod https_bridge;
pub mod hybrid_route;
pub mod local_socks_auth;
pub mod lua_engine;
pub mod masque;
pub mod mimicry;
pub mod native_udp;
pub mod packet;
pub mod packet_observer;
pub mod platform;
pub mod probe;
pub mod process_surface;
pub mod protocols;
pub mod raw_engine;
pub mod relay;
pub mod relay_geneva;
pub mod secret_file;
pub mod secure_channel;
pub mod shield;
pub mod signals;
pub mod socket_mark;
pub mod state;
pub mod state_secret;
pub mod state_v2;
pub mod stealth_rotation;
pub mod strategies;
pub mod traffic_privacy;
pub mod tunnel;
pub mod wide_product;
#[cfg(windows)]
pub mod windows_file;
#[cfg(windows)]
pub mod windows_tunnel;
pub mod ws_io;

pub use brain::{
    active_stall_probe_finished_event_data, active_stall_probe_launched_event_data,
    active_stall_probe_retry_budget_exhausted_event_data, direct_relay_failover_event_data,
    direct_session_succeeded_event_data, ActiveStallProbeFailoverContext,
    ActiveStallProbeFinishContext, ActiveStallProbeFinishedEventData,
    ActiveStallProbeFinishedTraceContext, ActiveStallProbeLaunchedEventData,
    ActiveStallProbeLaunchedTraceContext, ActiveStallProbeOutcomeClass,
    ActiveStallProbePlanContext, ActiveStallProbeRetryBudgetExhaustedEventData,
    ActiveStallProbeRetryBudgetExhaustedTraceContext, ActiveStallProbeRetryEventData,
    ActiveStallProbeRetrySkippedEventData, ActiveStallProbeRetrySkippedTraceContext,
    ActiveStallProbeRetrySuppressedReasonCode, ActiveStallProbeRetryTraceContext, Brain,
    CrossSessionSignalMetrics, DirectProbeBranchEventData, DirectProbeBranchTraceContext,
    DirectRelayFailoverEventData, DirectRelayFailoverReasonCode, DirectRelayFailoverTraceContext,
    DirectRelayPreferenceEventData, DirectRelayPreferenceTraceContext, DirectSessionAdvisory,
    DirectSessionSucceededEventData, DirectSessionSucceededTraceContext,
    DirectSessionSuccessMetrics, HybridEvidenceConfidence, HybridRouteAdvisory,
    HybridRouteSelectionReason, ModeHint, NetworkHint, ObservationPathContext,
    ProbeHistoryDisposition, ProbeHistoryReasonCode, RetryBudgetContext, RuntimeEndpoint,
    StrategyKey, TargetClass, TargetKind,
};
pub use config_types::{
    superseded_visible_state_path, DirectSettings, IngressPrimary, IngressSettings,
    LocalStealthProfile, MasqueTrustMode, Mode, RelayEndpointBanditSettings, RelayEndpointSettings,
    RelayPolicySettings, RelaySettings, RelayTlsBackend, Settings, SocksSettings, StealthMode,
    TunnelTransportFamily, WideIngressSettings, WidePlatformBackend, WideRolloutProfile,
    WideUdpCaptureContract, WireMimicryMode,
};
pub use error::{AegisError, Result};
pub use external_calibration::{
    ExternalAdversarialCalibration, ExternalCalibrationSnapshot, ExternalCalibrationVerdict,
    ExternalKnowledgePrior, ExternalWitnessCalibration,
};
pub use fingerprint::{
    from_tcp_snapshot, parse_tcp_header, ConnFingerprint, ServerType, TcpHeaderSnapshot,
    TcpOptionsSnapshot, WindowProfile,
};
pub use ghost_lurk::{ipg_gaps_from_timestamps_ms, mean_ipg_from_gaps_ms, GhostLurk};
pub use hybrid_route::{
    resolve_hybrid_geneva_route, AccessNetworkVisibility, AddressFamily, DirectTerminalReason,
    FlowProtocol, HybridGenevaPolicyError, HybridGenevaPolicyRequirements, HybridRouteDecision,
    HybridRouteFamily, TerminalFailureAction,
};
pub use lua_engine::{
    eval_strategy_hook, try_apply_chunk_hook, try_apply_order_hook, LUA_ENGINE_ABI,
};
pub use masque::{build_connect_udp_path, parse_connect_udp_path, DEFAULT_MASQUE_PATH};
pub use mimicry::{
    apply_experimental_wire_preface, apply_pre_connect, resolve_wire_mimicry_runtime, tuning_for,
    SoftWireRelaySocketPlan, StackProfileId, StackTuning, WireMimicryPlan, WireMimicryRuntimePlan,
    COLD_START_RUNTIME_SLICE, SAFE_DEFAULT_COLD_START_TTL,
};
pub use packet::{
    build_ipv4_tcp_packet, build_ipv4_tcp_packet_with_options_and_shaping,
    build_ipv4_tcp_packet_with_shaping, build_ipv4_tcp_rst_packet, corrupt_ipv4_tcp_checksum,
    fragment_ipv4_packet, ipv4_header_checksum, linux_send_raw_ipv4_best_effort,
    linux_send_raw_ipv4_with_ttl_best_effort, patch_ipv4_header_shaping, patch_ipv4_ttl,
    tcp_checksum_ipv4, Ipv4HeaderShaping, TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_FLAG_RST,
    TCP_FLAG_SYN,
};
pub use packet_observer::{
    maybe_start as start_packet_observer, PacketCaptureBackendKind, PacketCaptureStatus,
    PacketObservation, PacketObserverHandle, RunningPacketObserver,
};
pub use probe::{
    active_probe_budget, active_probe_ttl_candidates, preferred_probe_ttl, RstProbe, RstSource,
};
pub use process_surface::apply_process_alias;
pub use protocols::ja3::{
    ja3_client_fingerprint_string, ja3_client_md5_hex, ja3s_server_fingerprint_string,
    ja3s_server_md5_hex,
};
pub use protocols::tls::{
    client_hello_alpn_protocols, client_hello_ec_point_formats,
    client_hello_encrypted_client_hello_inner, client_hello_encrypted_client_hello_outer,
    client_hello_extension_value, client_hello_key_share, client_hello_pre_shared_key_identities,
    client_hello_psk_key_exchange_modes, client_hello_signature_algorithms,
    client_hello_supported_groups, client_hello_supported_versions, is_likely_tls_server_hello,
    parse_alpn_protocol_names, parse_client_hello_core, parse_ec_point_formats_list,
    parse_encrypted_client_hello, parse_encrypted_client_hello_inner, parse_key_share_client_hello,
    parse_pre_shared_key_identities, parse_psk_key_exchange_modes, parse_server_hello_core,
    parse_signature_algorithms_list, parse_supported_groups_list, parse_supported_versions_list,
    ClientHelloCore, EchClientOuter, KeyShareEntry, ServerHelloCore,
    TLS_EXT_ENCRYPTED_CLIENT_HELLO, TLS_EXT_PRE_SHARED_KEY, TLS_EXT_PSK_KEY_EXCHANGE_MODES,
};
pub use raw_engine::{default_raw_engine, RawCapabilities, RawEngine, TcpSeqState};
pub use relay::{
    decode_relay_request, decode_relay_response, encode_relay_request, encode_relay_response,
    RelayRequest, RelayStatus, RELAY_REQ_MAGIC, RELAY_RESP_MAGIC,
};
#[cfg(target_os = "linux")]
pub use socket_mark::apply_configured_direct_socket_mark;
pub use state::{StateStore, StrategyStats};
pub use state_v2::{
    AsyncStateStore, HybridRouteStats, KeyObservation, ObservationContract,
    ObservedWireChoreographyHint, ObservedWireIpv4HeaderShaping, ObservedWireNegotiatedOptions,
    StallProbeStats, StateSnapshot, StrategyStatsV2, TransportStats,
};
pub use stealth_rotation::{
    current_unix_secs, next_surface_rotation_at, surface_epoch, surface_phase_offset, DriftSurface,
};
pub use strategies::{
    ChecksumTrickStrategy, FakeDisorderStrategy, FakeRstStrategy, IpFragStrategy,
    MultisplitStrategy, OobDataStrategy, OverlapStrategy, PassthroughStrategy, SendFirstContext,
    Strategy, StrategyRequirements, TtlDesyncStrategy, TtlPatternStrategy,
};
pub use tunnel::{
    encode_stream_frame, open_tunnel_request, open_tunnel_request_with_kind, open_tunnel_response,
    read_stream_frame, seal_tunnel_datagram_request, seal_tunnel_request, seal_tunnel_response,
    OpenedTunnelRequest, TunnelRequest, TunnelRequestKind, TunnelResponse, TunnelStatus,
    MAX_TUNNEL_CONTROL_FRAME,
};
pub use wide_product::{
    UbuntuWideVerdict, WideDnsPolicy, WideIpv6Policy, WideLeakRisk, WideProductMode,
    WideProductProfile, WideQuicDisposition, WideScope, WideUdpPolicy,
};

pub mod research_topology;

/// Bounded build-side custody for explicitly private operator delivery.
pub mod operator_artifact;
