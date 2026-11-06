mod common;

use aegis_core::signals::FailSignal;
#[cfg(not(feature = "legacy-challenge-v1"))]
use aegis_core::{ExternalCalibrationSnapshot, ExternalKnowledgePrior};
use aegis_core::{
    KeyObservation, PacketCaptureStatus, ServerType, StallProbeStats, StateSnapshot, StrategyKey,
    StrategyStatsV2,
};

/// Mirror of the relay surface catalog profile id set. Must be kept in sync
/// with `aegis-client/src/relay/policy.rs::RELAY_SURFACE_CATALOG`. Sourced
/// here as a private constant because the catalog itself is module-internal
/// and integration tests only see public API.
const CATALOG_PROFILE_IDS: &[&str] = &[
    "browser_like_balanced",
    "browser_like_chatty",
    "cli_https_compact",
    "mobile_safari_tight",
    "desktop_chrome_streaming",
    "enterprise_java_client",
    "mobile_wifi",
    "mobile_4g",
    "desktop_electron",
    "realtime_websocket",
    "grpc_api",
    "noisy_cafe",
    "congested_hotel",
    "corp_middlebox",
    "iot_telemetry",
    "video_stream_h264",
    "api_batch_poller",
    "tablet_safari",
];

/// gRPC timeout header value per catalog profile id, mirroring
/// `RELAY_SURFACE_CATALOG[*].grpc_timeout_header`. `None` is encoded as
/// `serde_json::Value::Null` and "<value>" as `serde_json::Value::String`.
fn expected_grpc_timeout_for(profile_id: &str) -> serde_json::Value {
    match profile_id {
        "browser_like_balanced" => serde_json::Value::String("15S".into()),
        "browser_like_chatty" => serde_json::Value::String("20S".into()),
        "cli_https_compact" => serde_json::Value::Null,
        "mobile_safari_tight" => serde_json::Value::String("10S".into()),
        "desktop_chrome_streaming" => serde_json::Value::String("30S".into()),
        "enterprise_java_client" => serde_json::Value::String("60S".into()),
        "mobile_wifi" => serde_json::Value::String("20S".into()),
        "mobile_4g" => serde_json::Value::String("12S".into()),
        "desktop_electron" => serde_json::Value::String("25S".into()),
        "realtime_websocket" => serde_json::Value::Null,
        "grpc_api" => serde_json::Value::String("30S".into()),
        "noisy_cafe" => serde_json::Value::String("20S".into()),
        "congested_hotel" => serde_json::Value::String("30S".into()),
        "corp_middlebox" => serde_json::Value::String("25S".into()),
        "iot_telemetry" => serde_json::Value::Null,
        "video_stream_h264" => serde_json::Value::String("60S".into()),
        "api_batch_poller" => serde_json::Value::String("15S".into()),
        "tablet_safari" => serde_json::Value::String("20S".into()),
        other => panic!("unexpected relay surface profile id: {other}"),
    }
}
#[cfg(all(target_os = "linux", feature = "raw-socket"))]
use common::wait_for_event_count;
use common::{
    assert_no_event, assert_socks_listener_healthy, event_codes, read_jsonl_records,
    reserve_tcp_port, socks_handshake, wait_for_event, wait_for_port, ChildGuard, TestDir,
    TEST_RELAY_AUTH_TOKEN,
};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use socket2::SockRef;
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};
#[cfg(not(feature = "legacy-challenge-v1"))]
use std::time::{SystemTime, UNIX_EPOCH};

fn loopback_direct_key(port: u16) -> StrategyKey {
    StrategyKey::for_target(
        format!("127.0.0.1:{port}")
            .parse()
            .expect("loopback target"),
        "127.0.0.1",
        port,
        None,
        false,
    )
}

fn seeded_observation() -> KeyObservation {
    KeyObservation {
        matched_packets: 2,
        capture_status: PacketCaptureStatus::Active,
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
        first_data_server_hint: Some(ServerType::LikelyCdn),
        ..KeyObservation::default()
    }
}

fn runtime_only_seeded_observation() -> KeyObservation {
    KeyObservation {
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_server_hint: Some(ServerType::LikelyCdn),
        ..KeyObservation::default()
    }
}

fn explicit_absence_seeded_observation() -> KeyObservation {
    KeyObservation {
        capture_status: PacketCaptureStatus::UnsupportedPlatform,
        capture_backend: Some(aegis_core::PacketCaptureBackendKind::LinuxAfPacket),
        capture_filter_applied: true,
        capture_io_path: Some(aegis_core::packet_observer::PacketCaptureIoPath::AfPacketRing),
        matched_packets: 2,
        syn_ack_ttl: Some(58),
        syn_ack_window: Some(65535),
        syn_ack_server_hint: Some(ServerType::LikelyCdn),
        ..KeyObservation::default()
    }
}

fn write_seeded_state(path: &Path, target_port: u16, stall_probe_stats: StallProbeStats) {
    write_seeded_state_with_observation(path, target_port, stall_probe_stats, seeded_observation());
}

fn write_seeded_state_with_observation(
    path: &Path,
    target_port: u16,
    stall_probe_stats: StallProbeStats,
    observation: KeyObservation,
) {
    write_seeded_state_with_snapshot_fields(
        path,
        target_port,
        stall_probe_stats,
        observation,
        HashMap::new(),
    );
}

fn write_seeded_state_with_strategy_stats(
    path: &Path,
    target_port: u16,
    stall_probe_stats: StallProbeStats,
    observation: KeyObservation,
    strategy_stats: HashMap<String, StrategyStatsV2>,
) {
    write_seeded_state_with_snapshot_fields(
        path,
        target_port,
        stall_probe_stats,
        observation,
        strategy_stats,
    );
}

fn write_seeded_state_with_snapshot_fields(
    path: &Path,
    target_port: u16,
    stall_probe_stats: StallProbeStats,
    observation: KeyObservation,
    strategy_stats: HashMap<String, StrategyStatsV2>,
) {
    let key = loopback_direct_key(target_port);
    let key_hash = key.hash_key();
    let snapshot = StateSnapshot {
        schema_version: 2,
        key_registry: HashMap::from([(key_hash.clone(), key)]),
        key_observations: HashMap::from([(key_hash.clone(), observation)]),
        strategy_stats,
        stall_probe_stats: HashMap::from([(key_hash, stall_probe_stats)]),
        transport_stats: HashMap::new(),
        hybrid_route_stats: HashMap::new(),
        external_calibration: None,
    };
    common::write_private_file(
        path,
        serde_json::to_vec(&snapshot).expect("serialize state snapshot"),
    )
    .expect("write state");
}

fn stack_profile_config_line(stack_profile: Option<&str>) -> String {
    stack_profile
        .map(|value| format!("stack_profile = \"{value}\"\n"))
        .unwrap_or_default()
}

#[allow(dead_code)]
fn wire_mimicry_mode_config_line(wire_mode: Option<&str>) -> String {
    wire_mode
        .map(|value| format!("wire_mimicry_mode = \"{value}\"\n"))
        .unwrap_or_default()
}

fn assert_userspace_contract(
    record: &serde_json::Value,
    expected_wiring_mode: &str,
    expected_stack_profile: Option<&str>,
    expected_nodelay: Option<bool>,
    expected_reuseaddr: Option<bool>,
) {
    assert_eq!(
        record["fields"]["mimicry_capability_userspace_scope"],
        "pre_connect_socket_only"
    );
    assert_eq!(
        record["fields"]["mimicry_capability_userspace_wiring_mode"],
        expected_wiring_mode
    );
    match expected_stack_profile {
        Some(value) => assert_eq!(
            record["fields"]["mimicry_capability_userspace_stack_profile"],
            value
        ),
        None => assert!(record["fields"]["mimicry_capability_userspace_stack_profile"].is_null()),
    }
    assert_eq!(
        record["fields"]["mimicry_capability_userspace_nodelay_ready"],
        expected_nodelay.is_some()
    );
    match expected_nodelay {
        Some(value) => assert_eq!(
            record["fields"]["mimicry_capability_userspace_nodelay"],
            value
        ),
        None => assert!(record["fields"]["mimicry_capability_userspace_nodelay"].is_null()),
    }
    assert_eq!(
        record["fields"]["mimicry_capability_userspace_reuseaddr_ready"],
        expected_reuseaddr.is_some()
    );
    match expected_reuseaddr {
        Some(value) => assert_eq!(
            record["fields"]["mimicry_capability_userspace_reuseaddr"],
            value
        ),
        None => assert!(record["fields"]["mimicry_capability_userspace_reuseaddr"].is_null()),
    }
    let expected_buffer = match expected_stack_profile {
        Some("windows11") => Some(262_144),
        Some("android13") => Some(131_072),
        Some("linux") | Some("macos") => Some(196_608),
        _ => None,
    };
    assert_eq!(
        record["fields"]["mimicry_capability_userspace_send_buffer_ready"],
        expected_buffer.is_some()
    );
    assert_eq!(
        record["fields"]["mimicry_capability_userspace_recv_buffer_ready"],
        expected_buffer.is_some()
    );
    match expected_buffer {
        Some(value) => {
            assert_eq!(
                record["fields"]["mimicry_capability_userspace_send_buffer"],
                value
            );
            assert_eq!(
                record["fields"]["mimicry_capability_userspace_recv_buffer"],
                value
            );
        }
        None => {
            assert!(record["fields"]["mimicry_capability_userspace_send_buffer"].is_null());
            assert!(record["fields"]["mimicry_capability_userspace_recv_buffer"].is_null());
        }
    }
}

fn assert_compact_runtime_only_mimicry_contract(
    record: &serde_json::Value,
    expected_wiring_mode: &str,
    expected_stack_profile: Option<&str>,
    expected_nodelay: Option<bool>,
    expected_reuseaddr: Option<bool>,
) {
    assert_eq!(
        record["fields"]["mimicry_capability_stage"],
        "early_pre_wire_capability_layer"
    );
    assert_eq!(
        record["fields"]["mimicry_capability_userspace_scope"],
        "pre_connect_socket_only"
    );
    assert_eq!(
        record["fields"]["mimicry_capability_userspace_wiring_mode"],
        expected_wiring_mode
    );
    match expected_stack_profile {
        Some(value) => assert_eq!(
            record["fields"]["mimicry_capability_userspace_stack_profile"],
            value
        ),
        None => assert!(record["fields"]["mimicry_capability_userspace_stack_profile"].is_null()),
    }
    assert_eq!(
        record["fields"]["mimicry_capability_userspace_nodelay_ready"],
        expected_nodelay.is_some()
    );
    match expected_nodelay {
        Some(value) => assert_eq!(
            record["fields"]["mimicry_capability_userspace_nodelay"],
            value
        ),
        None => assert!(record["fields"]["mimicry_capability_userspace_nodelay"].is_null()),
    }
    assert_eq!(
        record["fields"]["mimicry_capability_userspace_reuseaddr_ready"],
        expected_reuseaddr.is_some()
    );
    match expected_reuseaddr {
        Some(value) => assert_eq!(
            record["fields"]["mimicry_capability_userspace_reuseaddr"],
            value
        ),
        None => assert!(record["fields"]["mimicry_capability_userspace_reuseaddr"].is_null()),
    }
}

#[allow(clippy::too_many_arguments, dead_code)]
fn assert_wire_runtime_contract(
    record: &serde_json::Value,
    expected_config_mode: &str,
    expected_requested: bool,
    expected_active: bool,
    expected_activation_reason: &str,
    expected_runtime_slice: Option<&str>,
    expected_ttl_preface: Option<u64>,
    expected_window_preface: Option<u64>,
    expected_options_preface_profile: Option<&str>,
    expected_options_preface_size: Option<u64>,
    expected_ipv4_header_profile: Option<&str>,
    expected_ipv4_header_tos: Option<u64>,
    expected_ipv4_header_ip_id: Option<u64>,
    expected_ipv4_header_dont_fragment: Option<bool>,
    expected_ipv4_header_source: Option<&str>,
    expected_negotiated_options_profile: Option<&str>,
    expected_negotiated_options_size: Option<u64>,
    expected_negotiated_options_mss: Option<u64>,
    expected_negotiated_options_window_scale: Option<u64>,
    expected_negotiated_options_sack_permitted: Option<bool>,
    expected_negotiated_options_timestamp_mode: Option<&str>,
    expected_negotiated_options_source: Option<&str>,
    expected_fragment_choreography_source: Option<&str>,
) {
    assert_eq!(
        record["fields"]["mimicry_capability_wire_config_mode"],
        expected_config_mode
    );
    assert_eq!(
        record["fields"]["mimicry_capability_wire_requested"],
        expected_requested
    );
    assert_eq!(
        record["fields"]["mimicry_capability_wire_active"],
        expected_active
    );
    assert_eq!(
        record["fields"]["mimicry_capability_wire_activation_reason"],
        expected_activation_reason
    );
    match expected_runtime_slice {
        Some(value) => assert_eq!(
            record["fields"]["mimicry_capability_wire_runtime_slice"],
            value
        ),
        None => assert!(record["fields"]["mimicry_capability_wire_runtime_slice"].is_null()),
    }
    match expected_ttl_preface {
        Some(value) => assert_eq!(
            record["fields"]["mimicry_capability_wire_ttl_preface"],
            value
        ),
        None => assert!(record["fields"]["mimicry_capability_wire_ttl_preface"].is_null()),
    }
    match expected_window_preface {
        Some(value) => assert_eq!(
            record["fields"]["mimicry_capability_wire_window_preface"],
            value
        ),
        None => assert!(record["fields"]["mimicry_capability_wire_window_preface"].is_null()),
    }
    match expected_options_preface_profile {
        Some(value) => assert_eq!(
            record["fields"]["mimicry_capability_wire_options_preface_profile"],
            value
        ),
        None => {
            assert!(record["fields"]["mimicry_capability_wire_options_preface_profile"].is_null())
        }
    }
    match expected_options_preface_size {
        Some(value) => assert_eq!(
            record["fields"]["mimicry_capability_wire_options_preface_size"],
            value
        ),
        None => assert!(record["fields"]["mimicry_capability_wire_options_preface_size"].is_null()),
    }
    match expected_ipv4_header_profile {
        Some(value) => assert_eq!(
            record["fields"]["mimicry_capability_wire_ipv4_header_shaping_profile"],
            value
        ),
        None => assert!(
            record["fields"]["mimicry_capability_wire_ipv4_header_shaping_profile"].is_null()
        ),
    }
    match expected_ipv4_header_tos {
        Some(value) => assert_eq!(
            record["fields"]["mimicry_capability_wire_ipv4_header_shaping_tos"],
            value
        ),
        None => {
            assert!(record["fields"]["mimicry_capability_wire_ipv4_header_shaping_tos"].is_null())
        }
    }
    match expected_ipv4_header_ip_id {
        Some(value) => assert_eq!(
            record["fields"]["mimicry_capability_wire_ipv4_header_shaping_ip_id"],
            value
        ),
        None => {
            assert!(record["fields"]["mimicry_capability_wire_ipv4_header_shaping_ip_id"].is_null())
        }
    }
    match expected_ipv4_header_dont_fragment {
        Some(value) => assert_eq!(
            record["fields"]["mimicry_capability_wire_ipv4_header_shaping_dont_fragment"],
            value
        ),
        None => assert!(record["fields"]
            ["mimicry_capability_wire_ipv4_header_shaping_dont_fragment"]
            .is_null()),
    }
    match expected_ipv4_header_source {
        Some(value) => assert_eq!(
            record["fields"]["mimicry_capability_wire_ipv4_header_shaping_source"],
            value
        ),
        None => assert!(
            record["fields"]["mimicry_capability_wire_ipv4_header_shaping_source"].is_null()
        ),
    }
    match expected_negotiated_options_profile {
        Some(value) => assert_eq!(
            record["fields"]["mimicry_capability_wire_negotiated_options_profile"],
            value
        ),
        None => {
            assert!(
                record["fields"]["mimicry_capability_wire_negotiated_options_profile"].is_null()
            )
        }
    }
    match expected_negotiated_options_size {
        Some(value) => assert_eq!(
            record["fields"]["mimicry_capability_wire_negotiated_options_size"],
            value
        ),
        None => {
            assert!(record["fields"]["mimicry_capability_wire_negotiated_options_size"].is_null())
        }
    }
    match expected_negotiated_options_mss {
        Some(value) => assert_eq!(
            record["fields"]["mimicry_capability_wire_negotiated_options_mss"],
            value
        ),
        None => {
            assert!(record["fields"]["mimicry_capability_wire_negotiated_options_mss"].is_null())
        }
    }
    match expected_negotiated_options_window_scale {
        Some(value) => assert_eq!(
            record["fields"]["mimicry_capability_wire_negotiated_options_window_scale"],
            value
        ),
        None => assert!(record["fields"]
            ["mimicry_capability_wire_negotiated_options_window_scale"]
            .is_null()),
    }
    match expected_negotiated_options_sack_permitted {
        Some(value) => assert_eq!(
            record["fields"]["mimicry_capability_wire_negotiated_options_sack_permitted"],
            value
        ),
        None => assert!(record["fields"]
            ["mimicry_capability_wire_negotiated_options_sack_permitted"]
            .is_null()),
    }
    match expected_negotiated_options_timestamp_mode {
        Some(value) => assert_eq!(
            record["fields"]["mimicry_capability_wire_negotiated_options_timestamp_mode"],
            value
        ),
        None => assert!(record["fields"]
            ["mimicry_capability_wire_negotiated_options_timestamp_mode"]
            .is_null()),
    }
    match expected_negotiated_options_source {
        Some(value) => assert_eq!(
            record["fields"]["mimicry_capability_wire_negotiated_options_source"],
            value
        ),
        None => {
            assert!(record["fields"]["mimicry_capability_wire_negotiated_options_source"].is_null())
        }
    }
    match expected_fragment_choreography_source {
        Some(value) => assert_eq!(
            record["fields"]["mimicry_capability_wire_fragment_choreography_source"],
            value
        ),
        None => assert!(
            record["fields"]["mimicry_capability_wire_fragment_choreography_source"].is_null()
        ),
    }
}

fn assert_planner_explainability_contract(
    record: &serde_json::Value,
    expected_reward_source: &str,
    expected_trace_source: &str,
    expected_observation_source: &str,
) {
    assert_eq!(
        record["fields"]["planner_reward_selection_source"],
        expected_reward_source
    );
    assert_eq!(
        record["fields"]["planner_explainability_trace_source"],
        expected_trace_source
    );
    assert_eq!(
        record["fields"]["planner_explainability_observation_source"],
        expected_observation_source
    );
    assert_eq!(
        record["fields"]["planner_explainability_live_runtime_observation_used"],
        false
    );
}

fn assert_direct_path_health_contract(
    record: &serde_json::Value,
    expected_tier: &str,
    expected_reason_code: &str,
) {
    assert_eq!(record["fields"]["direct_path_health_tier"], expected_tier);
    assert_eq!(
        record["fields"]["direct_path_health_reason_code"],
        expected_reason_code
    );
}

fn assert_terminal_health_summary(
    record: &serde_json::Value,
    expected_degraded_before_terminal: bool,
) {
    assert_eq!(record["fields"]["direct_path_health_tier"], "unstable");
    assert_eq!(
        record["fields"]["direct_path_unstable_before_failover"],
        true
    );
    assert_eq!(
        record["fields"]["direct_path_degraded_before_terminal"],
        expected_degraded_before_terminal
    );
}

fn assert_planner_top_candidate_reason_matches_candidate(record: &serde_json::Value) {
    let ranked = record["fields"]["planner_ranked_candidates"]
        .as_array()
        .expect("planner ranked candidates");
    if ranked.is_empty() {
        assert!(record["fields"]["planner_top_candidate_strategy"].is_null());
        assert_eq!(
            record["fields"]["planner_top_candidate_primary_reason"],
            "epsilon_randomized_preferred_order"
        );
        assert!(record["fields"]["planner_top_candidate_dominant_component"].is_null());
        return;
    }
    let top = &ranked[0];
    assert_eq!(
        record["fields"]["planner_top_candidate_strategy"],
        top["strategy"]
    );
    let expected_reason = match top["selection_score_dominant_component"]
        .as_str()
        .expect("dominant component")
    {
        "cold_start_exploration" => "top_candidate_cold_start_exploration",
        "probe_history_bias_component" => "top_candidate_probe_history_bias_component",
        "ucb_exploration_bonus" => "top_candidate_ucb_exploration_bonus",
        _ => "top_candidate_reward_component",
    };
    assert_eq!(
        record["fields"]["planner_top_candidate_primary_reason"],
        expected_reason
    );
    assert_eq!(
        record["fields"]["planner_top_candidate_dominant_component"],
        top["selection_score_dominant_component"]
    );
}

fn assert_planner_delta_baseline(record: &serde_json::Value) {
    assert!(record["fields"]["planner_previous_top_candidate_primary_reason"].is_null());
    assert_eq!(
        record["fields"]["planner_top_candidate_primary_reason_changed"],
        false
    );
    assert!(record["fields"]["planner_previous_top_candidate_dominant_component"].is_null());
    assert_eq!(
        record["fields"]["planner_top_candidate_dominant_component_changed"],
        false
    );
    assert!(record["fields"]["planner_previous_order_resolution"].is_null());
    assert_eq!(record["fields"]["planner_order_resolution_changed"], false);
    assert!(record["fields"]["planner_previous_resolved_order_primary_reason"].is_null());
    assert_eq!(
        record["fields"]["planner_resolved_order_primary_reason_changed"],
        false
    );
    assert!(record["fields"]["planner_previous_post_brain_reorder_applied"].is_null());
    assert_eq!(
        record["fields"]["planner_post_brain_reorder_path_changed"],
        false
    );
    assert!(record["fields"]["planner_previous_lua_order_applied"].is_null());
    assert_eq!(record["fields"]["planner_lua_order_applied_changed"], false);
    assert!(record["fields"]["planner_previous_advisory_reorder_applied"].is_null());
    assert_eq!(
        record["fields"]["planner_advisory_reorder_applied_changed"],
        false
    );
}

struct RelayServerGuard {
    runtime: tokio::runtime::Runtime,
    task: Option<tokio::task::JoinHandle<anyhow::Result<()>>>,
    cert_path: PathBuf,
    server_addr: String,
    quic_server_addr: String,
}

fn wait_for_relay_ready(
    runtime: &tokio::runtime::Runtime,
    task: &mut tokio::task::JoinHandle<anyhow::Result<()>>,
    ready: tokio::sync::oneshot::Receiver<std::net::SocketAddr>,
    timeout: Duration,
) -> Result<std::net::SocketAddr, String> {
    runtime.block_on(async {
        let deadline = tokio::time::Instant::now() + timeout;
        let failed = match tokio::time::timeout_at(deadline, ready).await {
            Ok(Ok(address)) => return Ok(address),
            Ok(Err(closed)) => {
                // The readiness sender may close just before the server finishes
                // unwinding its startup error. Retain that original result instead
                // of racing it with cancellation, within the same total deadline.
                if let Ok(completed) = tokio::time::timeout_at(deadline, &mut *task).await {
                    return Err(format!(
                        "relay readiness channel closed: {closed}; owned server task: {completed:?}"
                    ));
                }
                "readiness channel closed; server did not finish before deadline".to_owned()
            }
            Err(elapsed) => format!("readiness deadline exceeded: {elapsed}"),
        };
        // Failure must close and join this fixture's task before returning.
        // Never leave a delayed startup or bound listener behind for another
        // process test to mistake for its relay.
        task.abort();
        let completed = task.await;
        Err(format!(
            "relay readiness failed: {failed}; owned server task: {completed:?}"
        ))
    })
}

impl RelayServerGuard {
    fn start(dir: &Path) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let cert_dir = dir.join("relay-certs");
        fs::create_dir_all(&cert_dir).expect("create relay cert dir");
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).expect("generate relay cert");
        let cert_path = cert_dir.join("cert.pem");
        let key_path = cert_dir.join("key.pem");
        common::write_private_file(&cert_path, cert.pem()).expect("write relay cert");
        common::write_private_file(&key_path, key_pair.serialize_pem()).expect("write relay key");

        // TCP and UDP have separate Windows port policies. Select QUIC from
        // the UDP namespace, while retaining the server's actual TCP :0 bind.
        // The reservation stays owned through fixture setup. A race after its
        // handoff remains a startup failure; required readiness never retries.
        let quic_reservation = std::net::UdpSocket::bind("127.0.0.1:0")
            .expect("reserve fixture QUIC port in UDP namespace");
        let quic_server_addr = quic_reservation.local_addr().unwrap();
        let server_cfg = aegis_server::config::ServerConfig {
            // Keep the real kernel-selected listener instead of releasing a
            // temporary port reservation before the asynchronous bind.
            listen: "127.0.0.1:0".into(),
            cert: cert_path.clone(),
            key: key_path,
            auth_token: common::TEST_RELAY_AUTH_TOKEN.into(),
            legacy_auth_tokens: Vec::new(),
            process_alias: None,
            logging: Default::default(),
            fallback: "close".into(),
            limits: Default::default(),
            rate_limit: Default::default(),
            target_policy: aegis_server::config::TargetPolicyConfig {
                profile: aegis_server::config::TargetPolicyProfile::FullVpnEgress,
                allowed_ports: Vec::new(),
            },
            transport: aegis_server::config::TransportConfig {
                quic_listen: Some(quic_server_addr.to_string()),
                ..Default::default()
            },
            bundle_endpoint: Default::default(),
        };

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .build()
            .expect("build relay runtime");
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        drop(quic_reservation);
        let mut task = runtime.spawn(async move {
            aegis_server::run_server_with_bound_ready_and_shutdown(
                server_cfg,
                ready_tx,
                std::future::pending(),
            )
            .await
        });
        // The server sends this address only after TCP and required QUIC have
        // both bound. Slow startup is allowed within one explicit deadline.
        let server_addr =
            wait_for_relay_ready(&runtime, &mut task, ready_rx, Duration::from_secs(10))
                .unwrap_or_else(|error| panic!("{error}"));

        Self {
            runtime,
            task: Some(task),
            cert_path,
            server_addr: server_addr.to_string(),
            quic_server_addr: quic_server_addr.to_string(),
        }
    }

    #[cfg(not(feature = "legacy-challenge-v1"))]
    fn diagnostic(&mut self) -> String {
        if self.task.as_ref().is_some_and(|task| task.is_finished()) {
            let task = self.task.take().expect("finished owned relay task");
            format!(
                "owned relay task finished: {:?}",
                self.runtime.block_on(task)
            )
        } else {
            "owned relay task is running".into()
        }
    }
}

impl Drop for RelayServerGuard {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = self.runtime.block_on(task);
        }
    }
}

#[test]
fn fixture_relay_readiness_reports_bound_tcp_and_required_quic() {
    let td = TestDir::new("relay-bound-readiness");
    let relay = RelayServerGuard::start(td.path());
    let address: std::net::SocketAddr = relay.server_addr.parse().unwrap();
    let quic_address: std::net::SocketAddr = relay.quic_server_addr.parse().unwrap();
    assert_ne!(address.port(), 0);
    assert_ne!(quic_address.port(), 0);
    let tcp = std::net::TcpStream::connect(address).expect("ready TCP listener");
    assert_eq!(
        std::net::UdpSocket::bind(quic_address).unwrap_err().kind(),
        std::io::ErrorKind::AddrInUse,
        "readiness must include the required UDP listener",
    );
    drop(tcp);
    drop(relay);
    // A real accepted TCP connection may retain Windows TIME_WAIT after
    // owned cleanup; immediate server-port reuse is not a lifecycle contract.
    let _udp = std::net::UdpSocket::bind(quic_address).expect("owned UDP listener released");
}

#[test]
fn fixture_relay_readiness_surfaces_early_server_error() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let mut task = runtime.spawn(async move {
        drop(ready_tx);
        // A closed readiness channel can precede completion of owned cleanup.
        tokio::time::sleep(Duration::from_millis(10)).await;
        anyhow::bail!("fixture startup failure");
    });
    let error = wait_for_relay_ready(&runtime, &mut task, ready_rx, Duration::from_secs(1))
        .expect_err("a failed server cannot report readiness");
    assert!(error.contains("fixture startup failure"), "{error}");
    assert!(task.is_finished(), "failed owned server was joined");
}

#[test]
fn fixture_relay_readiness_timeout_reaps_only_its_owned_task() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    struct Cancelled(Arc<AtomicBool>);
    impl Drop for Cancelled {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let stopped = Arc::new(AtomicBool::new(false));
    let owned_stop = stopped.clone();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let mut task = runtime.spawn(async move {
        let _owned = (ready_tx, Cancelled(owned_stop));
        started_tx.send(()).unwrap();
        std::future::pending::<anyhow::Result<()>>().await
    });
    let unrelated = runtime.spawn(std::future::pending::<()>());
    runtime.block_on(started_rx).unwrap();
    let error = wait_for_relay_ready(&runtime, &mut task, ready_rx, Duration::from_millis(20))
        .expect_err("unready startup must respect its deadline");
    assert!(error.contains("readiness deadline exceeded"), "{error}");
    assert!(task.is_finished(), "timed-out owned server was joined");
    assert!(stopped.load(Ordering::Acquire), "owned future was dropped");
    assert!(!unrelated.is_finished(), "unrelated task must remain alive");
    unrelated.abort();
    let _ = runtime.block_on(unrelated);
}

#[test]
fn direct_success_runtime_jsonl_e2e() {
    let td = TestDir::new("direct-success");
    let events_path = td.path().join("events.jsonl");
    let cfg_path = td.path().join("direct-success.toml");

    let target_listener = TcpListener::bind("127.0.0.1:0").expect("target bind");
    let target_addr = target_listener.local_addr().expect("target addr");
    let target_thread = thread::spawn(move || {
        let (mut conn, _) = target_listener.accept().expect("accept target");
        let mut request = [0u8; 4096];
        let n = conn.read(&mut request).expect("read request");
        assert!(
            request[..n].starts_with(b"GET / HTTP/1.0"),
            "unexpected request"
        );
        conn.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 8\r\n\r\npayload!")
            .expect("write response");
        let _ = conn.shutdown(Shutdown::Both);
    });

    let socks_port = reserve_tcp_port();
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 500
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false

[relay]
server = ""
server_name = ""
auth_token = ""
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let mut socks = wait_for_port(socks_port, Duration::from_secs(20));
    socks_handshake(&mut socks, target_addr);
    socks
        .write_all(b"GET / HTTP/1.0\r\n\r\n")
        .expect("write request");

    let mut response = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && !response.windows(8).any(|window| window == b"payload!") {
        let mut chunk = [0u8; 4096];
        let n = socks.read(&mut chunk).expect("read response");
        if n == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..n]);
    }
    assert!(
        response
            .windows(15)
            .any(|window| window == b"HTTP/1.0 200 OK"),
        "missing HTTP response"
    );
    assert!(
        response.windows(8).any(|window| window == b"payload!"),
        "missing payload"
    );
    drop(socks);

    let (success, records) = wait_for_event(
        &events_path,
        "direct_session_succeeded",
        Duration::from_secs(10),
    );
    let codes = event_codes(&records);
    assert!(!codes.contains(&"ingress_session_failed"), "{records:?}");
    assert!(
        !codes.contains(&"direct_relay_failover_triggered"),
        "{records:?}"
    );
    assert!(!codes.contains(&"relay_transport_failed"), "{records:?}");

    assert_eq!(success["fields"]["target"], "127.0.0.1");
    assert_eq!(success["fields"]["port"], target_addr.port());
    assert_eq!(success["fields"]["strategy"], "passthrough");
    assert_eq!(success["fields"]["signal"], "Success");
    assert_eq!(success["fields"]["probe_outcome_class"], "success");
    assert_direct_path_health_contract(&success, "healthy", "successful_direct_path");
    assert_eq!(success["fields"]["probe_history_disposition"], "none");
    assert_eq!(
        success["fields"]["probe_history_reason_code"],
        "no_recent_probe_history"
    );
    assert_eq!(success["fields"]["bytes_sent"], 18);
    assert!(
        success["fields"]["first_response_bytes"]
            .as_u64()
            .unwrap_or(0)
            > 0
    );
    assert!(success["fields"]["capture_status"].as_str().is_some());
    assert_eq!(
        success["fields"]["active_stall_probe_retry_attempted"],
        false
    );
    assert_eq!(success["fields"]["retry_attempts_used"], 0);
    assert_eq!(
        success["fields"]["mimicry_capability_stage"],
        "early_pre_wire_capability_layer"
    );
    assert_eq!(
        success["fields"]["mimicry_capability_signal_origin"],
        "live_runtime_observation"
    );
    assert_eq!(
        success["fields"]["mimicry_capability_readiness"],
        "runtime_only_baseline"
    );
    assert_eq!(
        success["fields"]["mimicry_capability_observation_capture_confidence"],
        "explicit_absence"
    );
    assert_compact_runtime_only_mimicry_contract(
        &success,
        "telemetry_only_no_stack_profile",
        None,
        None,
        None,
    );
    assert_eq!(
        success["fields"]["mimicry_capability_wire_config_mode"],
        "disabled"
    );
    assert_eq!(
        success["fields"]["mimicry_capability_wire_requested"],
        false
    );
    assert_eq!(success["fields"]["mimicry_capability_wire_active"], false);
    assert_eq!(
        success["fields"]["mimicry_capability_wire_activation_reason"],
        "config_disabled"
    );
    assert_eq!(
        success["fields"]["mimicry_capability_userspace_ttl_hint_ready"],
        false
    );
    assert!(success["fields"]["mimicry_capability_userspace_ttl_hint"].is_null());
    assert_eq!(
        success["fields"]["cross_session_relay_preference_score"],
        serde_json::json!(0.0)
    );
    assert_eq!(
        success["fields"]["cross_session_probe_branch_score"],
        serde_json::json!(0.0)
    );

    target_thread.join().expect("join target thread");
}

#[test]
fn direct_success_degraded_runtime_jsonl_e2e() {
    let td = TestDir::new("direct-success-degraded");
    let events_path = td.path().join("events.jsonl");
    let cfg_path = td.path().join("direct-success-degraded.toml");

    let target_listener = TcpListener::bind("127.0.0.1:0").expect("target bind");
    let target_addr = target_listener.local_addr().expect("target addr");
    let target_thread = thread::spawn(move || {
        let (mut conn, _) = target_listener.accept().expect("accept target");
        let mut request = [0u8; 4096];
        let n = conn.read(&mut request).expect("read request");
        assert!(
            request[..n].starts_with(b"GET /slow HTTP/1.0"),
            "unexpected request"
        );
        thread::sleep(Duration::from_millis(30));
        conn.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\nslow")
            .expect("write response");
        let _ = conn.shutdown(Shutdown::Both);
    });

    let socks_port = reserve_tcp_port();
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 500
freeze_threshold_bytes = 16384
degraded_latency_ms = 1
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false

[relay]
server = ""
server_name = ""
auth_token = ""
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let mut socks = wait_for_port(socks_port, Duration::from_secs(20));
    socks_handshake(&mut socks, target_addr);
    socks
        .write_all(b"GET /slow HTTP/1.0\r\n\r\n")
        .expect("write request");
    let mut response = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && !response.windows(4).any(|window| window == b"slow") {
        let mut chunk = [0u8; 4096];
        let n = socks.read(&mut chunk).expect("read response");
        if n == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..n]);
    }
    assert!(
        response.windows(4).any(|window| window == b"slow"),
        "missing slow payload"
    );
    drop(socks);

    let (success, records) = wait_for_event(
        &events_path,
        "direct_session_succeeded",
        Duration::from_secs(10),
    );
    let codes = event_codes(&records);
    assert!(
        !codes.contains(&"direct_relay_failover_triggered"),
        "{records:?}"
    );
    assert_eq!(success["fields"]["signal"], "SuccessDegraded");
    assert_eq!(success["fields"]["probe_outcome_class"], "success_degraded");
    assert_direct_path_health_contract(&success, "degraded", "success_latency_degraded");

    target_thread.join().expect("join target thread");
}

#[test]
fn direct_success_with_stack_profile_runtime_jsonl_e2e() {
    let td = TestDir::new("direct-success-stack-profile");
    let events_path = td.path().join("events.jsonl");
    let cfg_path = td.path().join("direct-success-stack-profile.toml");

    let target_listener = TcpListener::bind("127.0.0.1:0").expect("target bind");
    let target_addr = target_listener.local_addr().expect("target addr");
    let target_thread = thread::spawn(move || {
        let (mut conn, _) = target_listener.accept().expect("accept target");
        let mut request = [0u8; 4096];
        let n = conn.read(&mut request).expect("read request");
        assert!(
            request[..n].starts_with(b"GET /profile-only HTTP/1.0"),
            "unexpected request"
        );
        conn.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 8\r\n\r\nprofile!")
            .expect("write response");
        let _ = conn.shutdown(Shutdown::Both);
    });

    let socks_port = reserve_tcp_port();
    let stack_profile_line = stack_profile_config_line(Some("windows11"));
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 500
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
{stack_profile_line}
[relay]
server = ""
server_name = ""
auth_token = ""
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let mut socks = wait_for_port(socks_port, Duration::from_secs(20));
    socks_handshake(&mut socks, target_addr);
    socks
        .write_all(b"GET /profile-only HTTP/1.0\r\n\r\n")
        .expect("write request");

    let mut response = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && !response.windows(8).any(|window| window == b"profile!") {
        let mut chunk = [0u8; 4096];
        let n = socks.read(&mut chunk).expect("read response");
        if n == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..n]);
    }
    assert!(
        response.windows(8).any(|window| window == b"profile!"),
        "missing profile payload"
    );
    drop(socks);

    let (success, _records) = wait_for_event(
        &events_path,
        "direct_session_succeeded",
        Duration::from_secs(10),
    );
    assert_eq!(
        success["fields"]["mimicry_capability_observation_capture_confidence"],
        "explicit_absence"
    );
    assert_direct_path_health_contract(&success, "healthy", "successful_direct_path");
    assert_compact_runtime_only_mimicry_contract(
        &success,
        "profile_only",
        Some("windows11"),
        Some(true),
        Some(true),
    );
    assert_eq!(
        success["fields"]["mimicry_capability_wire_config_mode"],
        "disabled"
    );
    assert_eq!(
        success["fields"]["mimicry_capability_wire_requested"],
        false
    );
    assert_eq!(success["fields"]["mimicry_capability_wire_active"], false);
    assert_eq!(
        success["fields"]["mimicry_capability_wire_activation_reason"],
        "config_disabled"
    );
    assert_eq!(
        success["fields"]["mimicry_capability_userspace_ttl_hint_ready"],
        false
    );
    assert!(success["fields"]["mimicry_capability_userspace_ttl_hint"].is_null());

    target_thread.join().expect("join target thread");
}

#[test]
fn direct_success_with_seeded_observation_runtime_jsonl_e2e() {
    let td = TestDir::new("direct-success-seeded");
    let events_path = td.path().join("events.jsonl");
    let cfg_path = td.path().join("direct-success-seeded.toml");
    let state_path = td.path().join("state.json");

    let target_listener = TcpListener::bind("127.0.0.1:0").expect("target bind");
    let target_addr = target_listener.local_addr().expect("target addr");
    write_seeded_state(
        &state_path,
        target_addr.port(),
        StallProbeStats {
            trials: 1,
            collapses: 1,
            consecutive_stall_failures: 1,
            last_signal: Some(FailSignal::ThroughputCollapse),
            ..StallProbeStats::default()
        },
    );
    let target_thread = thread::spawn(move || {
        let (mut conn, _) = target_listener.accept().expect("accept target");
        let mut request = [0u8; 4096];
        let n = conn.read(&mut request).expect("read request");
        assert!(
            request[..n].starts_with(b"GET /seeded HTTP/1.0"),
            "unexpected request"
        );
        conn.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 7\r\n\r\nseeded!")
            .expect("write response");
        let _ = conn.shutdown(Shutdown::Both);
    });

    let socks_port = reserve_tcp_port();
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
persist_state = true
state_path = "{}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 500
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false

[relay]
server = ""
server_name = ""
auth_token = ""
"#,
            common::toml_path(&state_path),
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let mut socks = wait_for_port(socks_port, Duration::from_secs(20));
    socks_handshake(&mut socks, target_addr);
    socks
        .write_all(b"GET /seeded HTTP/1.0\r\n\r\n")
        .expect("write request");

    let mut response = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && !response.windows(7).any(|window| window == b"seeded!") {
        let mut chunk = [0u8; 4096];
        let n = socks.read(&mut chunk).expect("read response");
        if n == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..n]);
    }
    assert!(
        response.windows(7).any(|window| window == b"seeded!"),
        "missing seeded payload"
    );
    drop(socks);

    let (success, records) = wait_for_event(
        &events_path,
        "direct_session_succeeded",
        Duration::from_secs(10),
    );
    let codes = event_codes(&records);
    assert!(
        !codes.contains(&"direct_relay_preferred_from_probe_history"),
        "{records:?}"
    );
    assert!(
        !codes.contains(&"direct_active_probe_branch_selected"),
        "{records:?}"
    );
    assert_eq!(
        success["fields"]["mimicry_capability_stage"],
        "early_pre_wire_capability_layer"
    );
    assert_eq!(
        success["fields"]["mimicry_capability_signal_origin"],
        "live_runtime_observation"
    );
    assert_eq!(
        success["fields"]["mimicry_capability_readiness"],
        "runtime_only_baseline"
    );
    assert_eq!(
        success["fields"]["mimicry_capability_observation_capture_confidence"],
        "explicit_absence"
    );
    assert_userspace_contract(
        &success,
        "telemetry_only_no_stack_profile",
        None,
        None,
        None,
    );
    assert_eq!(
        success["fields"]["mimicry_capability_server_hint_ready"],
        false
    );
    assert_eq!(
        success["fields"]["mimicry_capability_window_profile_ready"],
        false
    );
    assert_eq!(
        success["fields"]["mimicry_capability_reference_path_ready"],
        false
    );
    assert_eq!(
        success["fields"]["mimicry_capability_rst_path_ready"],
        false
    );
    assert!(success["fields"]["mimicry_capability_server_hint"].is_null());
    assert!(success["fields"]["mimicry_capability_window_profile"].is_null());
    assert!(success["fields"]["mimicry_capability_reference_path_hops"].is_null());
    assert!(success["fields"]["mimicry_capability_rst_path_hops"].is_null());
    assert!(
        success["fields"]["cross_session_confidence_score"]
            .as_f64()
            .expect("confidence score")
            > 0.0
    );
    assert!(
        success["fields"]["cross_session_reuse_weight"]
            .as_f64()
            .expect("reuse weight")
            > 0.0
    );
    assert!(
        success["fields"]["cross_session_stall_severity"]
            .as_f64()
            .expect("stall severity")
            > 0.0
    );
    assert!(
        success["fields"]["cross_session_probe_branch_score"]
            .as_f64()
            .expect("probe branch score")
            > 0.0
    );
    assert_eq!(
        success["fields"]["cross_session_relay_preference_score"],
        serde_json::json!(0.0)
    );

    target_thread.join().expect("join target thread");
}

#[test]
fn direct_planner_order_runtime_jsonl_e2e() {
    let td = TestDir::new("direct-planner-order");
    let events_path = td.path().join("events.jsonl");
    let cfg_path = td.path().join("direct-planner-order.toml");
    let state_path = td.path().join("state.json");

    let target_listener = TcpListener::bind("127.0.0.1:0").expect("target bind");
    let target_addr = target_listener.local_addr().expect("target addr");
    let key_hash = loopback_direct_key(target_addr.port()).hash_key();
    let mut passthrough = StrategyStatsV2::default();
    passthrough.record(&FailSignal::Success, Some(10), 2048);
    passthrough.record(&FailSignal::Success, Some(12), 2048);
    let mut multisplit = StrategyStatsV2::default();
    multisplit.record(&FailSignal::Timeout, None, 0);
    multisplit.record(&FailSignal::Unknown, None, 0);
    write_seeded_state_with_strategy_stats(
        &state_path,
        target_addr.port(),
        StallProbeStats::default(),
        seeded_observation(),
        HashMap::from([
            (format!("{key_hash}|passthrough"), passthrough),
            (format!("{key_hash}|multisplit"), multisplit),
        ]),
    );
    let target_thread = thread::spawn(move || {
        let (mut conn, _) = target_listener.accept().expect("accept target");
        let mut request = [0u8; 4096];
        let n = conn.read(&mut request).expect("read request");
        assert!(
            request[..n].starts_with(b"GET /planner HTTP/1.0"),
            "unexpected request"
        );
        conn.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 8\r\n\r\nplanner!")
            .expect("write response");
        let _ = conn.shutdown(Shutdown::Both);
    });

    let socks_port = reserve_tcp_port();
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
persist_state = true
state_path = "{}"
strategies = ["multisplit", "passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 500
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false

[relay]
server = ""
server_name = ""
auth_token = ""
"#,
            common::toml_path(&state_path),
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let mut socks = wait_for_port(socks_port, Duration::from_secs(20));
    socks_handshake(&mut socks, target_addr);
    socks
        .write_all(b"GET /planner HTTP/1.0\r\n\r\n")
        .expect("write request");
    let mut response = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && !response.windows(8).any(|window| window == b"planner!") {
        let mut chunk = [0u8; 4096];
        let n = socks.read(&mut chunk).expect("read response");
        if n == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..n]);
    }
    assert!(
        response.windows(8).any(|window| window == b"planner!"),
        "missing planner payload"
    );
    drop(socks);

    let (planner, _records) = wait_for_event(
        &events_path,
        "direct_planner_order_selected",
        Duration::from_secs(10),
    );
    let (success, _) = wait_for_event(
        &events_path,
        "direct_session_succeeded",
        Duration::from_secs(10),
    );
    assert_eq!(planner["fields"]["target"], "127.0.0.1");
    assert_eq!(planner["fields"]["port"], target_addr.port());
    assert_eq!(
        planner["fields"]["planner_selector_mode"],
        "ucb1_contextual_reward"
    );
    assert_planner_explainability_contract(
        &planner,
        "brain_reward_loop",
        "state_snapshot_contextual_reward",
        "advisory_state_snapshot_observation",
    );
    assert_eq!(
        planner["fields"]["planner_order_resolution"],
        "reward_loop_only"
    );
    assert_eq!(
        planner["fields"]["planner_resolved_order_primary_reason"],
        "reward_loop_preserved"
    );
    assert_planner_top_candidate_reason_matches_candidate(&planner);
    assert_planner_delta_baseline(&planner);
    assert_eq!(
        planner["fields"]["planner_post_brain_reorder_applied"],
        false
    );
    assert_eq!(
        planner["fields"]["planner_reward_loop_order_preserved"],
        true
    );
    assert_eq!(planner["fields"]["planner_lua_order_configured"], false);
    assert_eq!(planner["fields"]["planner_lua_order_applied"], false);
    assert_eq!(
        planner["fields"]["planner_advisory_reorder_requested"],
        false
    );
    assert_eq!(planner["fields"]["planner_advisory_reorder_applied"], false);
    assert_eq!(
        planner["fields"]["planner_selection_stage"],
        "initial_session_order"
    );
    assert_eq!(planner["fields"]["planner_retry_attempt"], 0);
    assert_eq!(planner["fields"]["planner_has_previous_selection"], false);
    assert_eq!(
        planner["fields"]["planner_previous_reward_selected_order"],
        serde_json::Value::Null
    );
    assert_eq!(
        planner["fields"]["planner_previous_resolved_order"],
        serde_json::Value::Null
    );
    assert_eq!(
        planner["fields"]["planner_reward_selected_order_changed"],
        false
    );
    assert_eq!(planner["fields"]["planner_resolved_order_changed"], false);
    assert_eq!(
        planner["fields"]["planner_reward_selected_order"],
        serde_json::json!(["passthrough", "multisplit"])
    );
    assert_eq!(
        planner["fields"]["planner_resolved_order"],
        serde_json::json!(["passthrough", "multisplit"])
    );
    assert_eq!(planner["fields"]["probe_history_disposition"], "none");
    assert_eq!(
        planner["fields"]["probe_history_reason_code"],
        "probe_signal_not_stall_like"
    );
    assert_eq!(
        planner["fields"]["cross_session_signal_bias"],
        "neutral_advisory_bias"
    );
    assert_eq!(planner["fields"]["observation_contract"], "deep_observed");
    assert_eq!(
        planner["fields"]["observation_capture_confidence"],
        "deep_observed"
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_signal_origin"],
        "advisory_latest_observation"
    );
    assert!(planner["fields"]["mimicry_capability_readiness"]
        .as_str()
        .is_some());
    assert!(
        planner["fields"]["cross_session_confidence_score"]
            .as_f64()
            .expect("confidence score")
            == 0.0
    );
    assert!(
        planner["fields"]["cross_session_reuse_weight"]
            .as_f64()
            .expect("reuse weight")
            > 0.0
    );
    assert!(
        planner["fields"]["cross_session_probe_branch_score"]
            .as_f64()
            .expect("probe branch score")
            == 0.0
    );
    assert!(
        planner["fields"]["cross_session_relay_preference_score"]
            .as_f64()
            .expect("relay preference score")
            == 0.0
    );
    let ranked = planner["fields"]["planner_ranked_candidates"]
        .as_array()
        .expect("ranked candidates");
    assert_eq!(ranked.len(), 2);
    assert_eq!(ranked[0]["strategy"], "passthrough");
    assert_eq!(ranked[1]["strategy"], "multisplit");
    assert_eq!(ranked[0]["rank"], 0);
    assert_eq!(ranked[1]["rank"], 1);
    assert_eq!(ranked[0]["has_previous_candidate_trace"], false);
    assert_eq!(ranked[0]["previous_rank"], serde_json::Value::Null);
    assert_eq!(ranked[0]["rank_delta"], serde_json::Value::Null);
    assert_eq!(
        ranked[0]["previous_estimated_reward"],
        serde_json::Value::Null
    );
    assert_eq!(ranked[0]["estimated_reward_delta"], serde_json::Value::Null);
    assert_eq!(
        ranked[0]["previous_selection_score_reward_component"],
        serde_json::Value::Null
    );
    assert_eq!(
        ranked[0]["selection_score_reward_component_delta"],
        serde_json::Value::Null
    );
    assert_eq!(
        ranked[0]["previous_selection_score_ucb_exploration_bonus"],
        serde_json::Value::Null
    );
    assert_eq!(
        ranked[0]["selection_score_ucb_exploration_bonus_delta"],
        serde_json::Value::Null
    );
    assert_eq!(
        ranked[0]["previous_selection_score_probe_bias_component"],
        serde_json::Value::Null
    );
    assert_eq!(
        ranked[0]["selection_score_probe_bias_component_delta"],
        serde_json::Value::Null
    );
    assert_eq!(
        ranked[0]["previous_selection_score"],
        serde_json::Value::Null
    );
    assert_eq!(ranked[0]["selection_score_delta"], serde_json::Value::Null);
    assert_eq!(
        ranked[0]["selection_score_dominant_component"],
        "ucb_exploration_bonus"
    );
    assert_eq!(ranked[0]["selection_score_probe_bias_effect"], "neutral");
    assert!(
        ranked[0]["estimated_trials"]
            .as_f64()
            .expect("passthrough trials")
            > 0.0
    );
    assert!(
        ranked[0]["total_trials"]
            .as_f64()
            .expect("passthrough total trials")
            >= ranked[0]["estimated_trials"]
                .as_f64()
                .expect("passthrough estimated trials")
    );
    assert_eq!(
        ranked[0]["probe_history_strategy_bias"],
        serde_json::json!(0.0)
    );
    assert_eq!(
        ranked[0]["selection_score_reward_component"],
        ranked[0]["estimated_reward"]
    );
    assert!(ranked[0]["selection_score_ucb_exploration_bonus"]
        .as_f64()
        .is_some());
    assert_eq!(
        ranked[0]["selection_score_probe_bias_component"],
        serde_json::json!(0.0)
    );
    assert!(ranked[0]["selection_score"].as_f64().is_some());
    assert!(
        ranked[0]["estimated_reward"]
            .as_f64()
            .expect("passthrough reward")
            > ranked[1]["estimated_reward"]
                .as_f64()
                .expect("multisplit reward")
    );
    assert_eq!(ranked[0]["cold_start_exploration"], false);
    assert_eq!(ranked[1]["cold_start_exploration"], false);
    assert_eq!(success["fields"]["strategy"], "passthrough");

    target_thread.join().expect("join planner thread");
}

#[test]
fn direct_planner_order_with_stack_profile_runtime_jsonl_e2e() {
    let td = TestDir::new("direct-planner-order-stack-profile");
    let events_path = td.path().join("events.jsonl");
    let cfg_path = td.path().join("direct-planner-order-stack-profile.toml");
    let state_path = td.path().join("state.json");

    let target_listener = TcpListener::bind("127.0.0.1:0").expect("target bind");
    let target_addr = target_listener.local_addr().expect("target addr");
    write_seeded_state(&state_path, target_addr.port(), StallProbeStats::default());
    let target_thread = thread::spawn(move || {
        let (mut conn, _) = target_listener.accept().expect("accept target");
        let mut request = [0u8; 4096];
        let n = conn.read(&mut request).expect("read request");
        assert!(
            request[..n].starts_with(b"GET /planner-profile HTTP/1.0"),
            "unexpected request"
        );
        conn.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 9\r\n\r\nplanner++")
            .expect("write response");
        let _ = conn.shutdown(Shutdown::Both);
    });

    let socks_port = reserve_tcp_port();
    let stack_profile_line = stack_profile_config_line(Some("linux"));
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
persist_state = true
state_path = "{}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 500
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
{stack_profile_line}
[relay]
server = ""
server_name = ""
auth_token = ""
"#,
            common::toml_path(&state_path),
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let mut socks = wait_for_port(socks_port, Duration::from_secs(20));
    socks_handshake(&mut socks, target_addr);
    socks
        .write_all(b"GET /planner-profile HTTP/1.0\r\n\r\n")
        .expect("write request");
    let mut response = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && !response.windows(9).any(|window| window == b"planner++") {
        let mut chunk = [0u8; 4096];
        let n = socks.read(&mut chunk).expect("read response");
        if n == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..n]);
    }
    assert!(
        response.windows(9).any(|window| window == b"planner++"),
        "missing planner profile payload"
    );
    drop(socks);

    let (planner, _records) = wait_for_event(
        &events_path,
        "direct_planner_order_selected",
        Duration::from_secs(10),
    );
    let (success, _) = wait_for_event(
        &events_path,
        "direct_session_succeeded",
        Duration::from_secs(10),
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_signal_origin"],
        "advisory_latest_observation"
    );
    assert_eq!(
        planner["fields"]["planner_resolved_order_primary_reason"],
        "reward_loop_preserved"
    );
    assert_planner_top_candidate_reason_matches_candidate(&planner);
    assert_planner_delta_baseline(&planner);
    assert_planner_explainability_contract(
        &planner,
        "brain_reward_loop",
        "state_snapshot_contextual_reward",
        "advisory_state_snapshot_observation",
    );
    assert_eq!(
        planner["fields"]["planner_post_brain_reorder_applied"],
        false
    );
    assert_eq!(
        planner["fields"]["planner_reward_loop_order_preserved"],
        true
    );
    assert_eq!(planner["fields"]["planner_lua_order_configured"], false);
    assert_eq!(planner["fields"]["planner_lua_order_applied"], false);
    assert_eq!(
        planner["fields"]["planner_advisory_reorder_requested"],
        false
    );
    assert_eq!(planner["fields"]["planner_advisory_reorder_applied"], false);
    assert_eq!(
        planner["fields"]["mimicry_capability_observation_capture_confidence"],
        "deep_observed"
    );
    assert_userspace_contract(
        &planner,
        "profile_plus_capture_backed_ttl",
        Some("linux"),
        Some(false),
        Some(true),
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_userspace_ttl_hint_ready"],
        true
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_userspace_ttl_hint"],
        60
    );
    assert_eq!(
        success["fields"]["mimicry_capability_signal_origin"],
        "live_runtime_observation"
    );
    assert_eq!(
        success["fields"]["mimicry_capability_observation_capture_confidence"],
        "explicit_absence"
    );
    assert_userspace_contract(
        &success,
        "profile_only",
        Some("linux"),
        Some(false),
        Some(true),
    );
    assert_eq!(
        success["fields"]["mimicry_capability_userspace_ttl_hint_ready"],
        false
    );
    assert!(success["fields"]["mimicry_capability_userspace_ttl_hint"].is_null());

    target_thread.join().expect("join planner thread");
}

#[cfg(target_os = "linux")]
#[test]
fn direct_wire_mimicry_requested_but_inactive_runtime_jsonl_e2e() {
    let td = TestDir::new("direct-wire-requested-inactive");
    let events_path = td.path().join("events.jsonl");
    let cfg_path = td.path().join("direct-wire-requested-inactive.toml");
    let state_path = td.path().join("state.json");
    write_seeded_state(&state_path, 0, StallProbeStats::default());

    let target_listener = TcpListener::bind("127.0.0.1:0").expect("target bind");
    let target_addr = target_listener.local_addr().expect("target addr");
    write_seeded_state(&state_path, target_addr.port(), StallProbeStats::default());
    let target_thread = thread::spawn(move || {
        let (mut conn, _) = target_listener.accept().expect("accept target");
        let mut request = [0u8; 4096];
        let n = conn.read(&mut request).expect("read request");
        assert!(
            request[..n].starts_with(b"GET /wire-inactive HTTP/1.0"),
            "unexpected request"
        );
        conn.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 13\r\n\r\nwire-inactive")
            .expect("write response");
        let _ = conn.shutdown(Shutdown::Both);
    });

    let socks_port = reserve_tcp_port();
    let stack_profile_line = stack_profile_config_line(Some("linux"));
    let wire_mode_line = wire_mimicry_mode_config_line(Some("linux_experimental_ttl_preface"));
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
persist_state = true
state_path = "{}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 500
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
{stack_profile_line}{wire_mode_line}
[relay]
server = ""
server_name = ""
auth_token = ""
"#,
            common::toml_path(&state_path),
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn_with_env(
        &cfg_path,
        &events_path,
        &[
            ("AEGIS_TEST_RAW_IPV4_SEND", "0"),
            ("AEGIS_TEST_RAW_PACKET_CAPTURE", "0"),
            ("AEGIS_TEST_RAW_TCP_REPAIR", "0"),
            ("AEGIS_TEST_RAW_IPV4_HEADER_CONTROL", "0"),
            ("AEGIS_TEST_RAW_IPV4_FRAGMENTATION", "0"),
        ],
    );

    let mut socks = wait_for_port(socks_port, Duration::from_secs(20));
    socks_handshake(&mut socks, target_addr);
    socks
        .write_all(b"GET /wire-inactive HTTP/1.0\r\n\r\n")
        .expect("write request");
    let mut response = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline
        && !response
            .windows("wire-inactive".len())
            .any(|window| window == b"wire-inactive")
    {
        let mut chunk = [0u8; 4096];
        let n = socks.read(&mut chunk).expect("read response");
        if n == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..n]);
    }
    assert!(
        response
            .windows("wire-inactive".len())
            .any(|window| window == b"wire-inactive"),
        "missing wire inactive payload"
    );
    drop(socks);

    let (planner, _) = wait_for_event(
        &events_path,
        "direct_planner_order_selected",
        Duration::from_secs(10),
    );
    assert_userspace_contract(
        &planner,
        "profile_plus_capture_backed_ttl",
        Some("linux"),
        Some(false),
        Some(true),
    );
    assert_wire_runtime_contract(
        &planner,
        "linux_experimental_ttl_preface",
        true,
        false,
        "raw_capabilities_missing",
        None,
        Some(60),
        Some(64240),
        Some("ack_timestamp_pad12"),
        Some(12),
        Some("observed_capture_backed_ipv4_header_shaping_v1"),
        Some(16),
        Some(4660),
        Some(true),
        Some("observed_capture_backed"),
        Some("observed_capture_backed_negotiated_options_v1"),
        Some(20),
        Some(1460),
        Some(8),
        Some(true),
        Some("syn_timestamp_offer_layout20"),
        Some("observed_capture_backed"),
        Some("observed_capture_backed"),
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_wire_window_preface_ready"],
        true
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_wire_options_preface_ready"],
        true
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_wire_ipv4_header_shaping_ready"],
        true
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_wire_ipv4_header_shaping_observed_ready"],
        true
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_wire_negotiated_options_ready"],
        true
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_wire_negotiated_options_observed_ready"],
        true
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_wire_fragment_choreography_ready"],
        true
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_wire_fragment_choreography_observed_ready"],
        true
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_userspace_ttl_hint"],
        60
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_wire_raw_ipv4_send_ready"],
        false
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_wire_tcp_repair_ready"],
        false
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_wire_ipv4_header_control_ready"],
        false
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_wire_ipv4_fragmentation_ready"],
        false
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_wire_ipv4_header_shaping_profile"],
        "observed_capture_backed_ipv4_header_shaping_v1"
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_wire_fragment_choreography_profile"],
        "observed_capture_backed_fragment_ordered_decoy_v1"
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_wire_fragment_choreography_steps"],
        "fragment_then_disorder_then_overlap"
    );

    target_thread.join().expect("join target thread");
}

#[cfg(target_os = "linux")]
#[test]
fn direct_wire_mimicry_active_runtime_jsonl_e2e() {
    let td = TestDir::new("direct-wire-active");
    let events_path = td.path().join("events.jsonl");
    let cfg_path = td.path().join("direct-wire-active.toml");
    let state_path = td.path().join("state.json");
    write_seeded_state(&state_path, 0, StallProbeStats::default());

    let target_listener = TcpListener::bind("127.0.0.1:0").expect("target bind");
    let target_addr = target_listener.local_addr().expect("target addr");
    write_seeded_state(&state_path, target_addr.port(), StallProbeStats::default());
    let target_thread = thread::spawn(move || {
        let (mut conn, _) = target_listener.accept().expect("accept target");
        // Active wire mimicry can fragment the first payload and make a single
        // TCP read return only a prefix. Read through the HTTP terminator so
        // the assertion checks the reconstructed stream, not read chunking.
        let mut request = Vec::new();
        while request.len() < 4096 && !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let mut chunk = [0u8; 512];
            let n = conn.read(&mut chunk).expect("read request");
            if n == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..n]);
        }
        assert!(
            request.starts_with(b"GET /wire-active HTTP/1.0"),
            "unexpected request: {request:?}"
        );
        conn.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 11\r\n\r\nwire-active")
            .expect("write response");
        let _ = conn.shutdown(Shutdown::Both);
    });

    let socks_port = reserve_tcp_port();
    let stack_profile_line = stack_profile_config_line(Some("linux"));
    let wire_mode_line = wire_mimicry_mode_config_line(Some("linux_experimental_ttl_preface"));
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
persist_state = true
state_path = "{}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 500
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
{stack_profile_line}{wire_mode_line}
[relay]
server = ""
server_name = ""
auth_token = ""
"#,
            common::toml_path(&state_path),
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn_with_env(
        &cfg_path,
        &events_path,
        &[
            ("AEGIS_TEST_RAW_IPV4_SEND", "1"),
            ("AEGIS_TEST_RAW_PACKET_CAPTURE", "1"),
            ("AEGIS_TEST_RAW_TCP_REPAIR", "1"),
            ("AEGIS_TEST_RAW_IPV4_HEADER_CONTROL", "1"),
            ("AEGIS_TEST_RAW_IPV4_FRAGMENTATION", "1"),
            ("AEGIS_TEST_RAW_TCP_STATE", "1"),
            ("AEGIS_TEST_RAW_SEND_NOOP", "1"),
        ],
    );

    let mut socks = wait_for_port(socks_port, Duration::from_secs(20));
    socks_handshake(&mut socks, target_addr);
    socks
        .write_all(b"GET /wire-active HTTP/1.0\r\n\r\n")
        .expect("write request");
    let mut response = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline
        && !response
            .windows("wire-active".len())
            .any(|window| window == b"wire-active")
    {
        let mut chunk = [0u8; 4096];
        let n = socks.read(&mut chunk).expect("read response");
        if n == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..n]);
    }
    assert!(
        response
            .windows("wire-active".len())
            .any(|window| window == b"wire-active"),
        "missing wire active payload"
    );
    drop(socks);

    let (planner, _) = wait_for_event(
        &events_path,
        "direct_planner_order_selected",
        Duration::from_secs(10),
    );
    assert_userspace_contract(
        &planner,
        "profile_plus_capture_backed_ttl",
        Some("linux"),
        Some(false),
        Some(true),
    );
    assert_wire_runtime_contract(
        &planner,
        "linux_experimental_ttl_preface",
        true,
        true,
        "linux_experimental_ttl_preface_active",
        Some("linux_experimental_ipv4_fragment_ordered_decoy_choreography_preface"),
        Some(60),
        Some(64240),
        Some("ack_timestamp_pad12"),
        Some(12),
        Some("observed_capture_backed_ipv4_header_shaping_v1"),
        Some(16),
        Some(4660),
        Some(true),
        Some("observed_capture_backed"),
        Some("observed_capture_backed_negotiated_options_v1"),
        Some(20),
        Some(1460),
        Some(8),
        Some(true),
        Some("syn_timestamp_offer_layout20"),
        Some("observed_capture_backed"),
        Some("observed_capture_backed"),
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_wire_window_preface_ready"],
        true
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_wire_options_preface_ready"],
        true
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_wire_ipv4_header_shaping_ready"],
        true
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_wire_ipv4_header_shaping_observed_ready"],
        true
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_wire_negotiated_options_ready"],
        true
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_wire_negotiated_options_observed_ready"],
        true
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_wire_fragment_choreography_ready"],
        true
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_wire_fragment_choreography_observed_ready"],
        true
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_userspace_ttl_hint"],
        60
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_wire_raw_ipv4_send_ready"],
        true
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_wire_tcp_repair_ready"],
        true
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_wire_ipv4_header_control_ready"],
        true
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_wire_ipv4_fragmentation_ready"],
        true
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_wire_ipv4_header_shaping_profile"],
        "observed_capture_backed_ipv4_header_shaping_v1"
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_wire_fragment_choreography_profile"],
        "observed_capture_backed_fragment_ordered_decoy_v1"
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_wire_fragment_choreography_steps"],
        "fragment_then_disorder_then_overlap"
    );

    target_thread.join().expect("join target thread");
}

#[test]
fn direct_failover_runtime_jsonl_e2e() {
    let td = TestDir::new("direct-failover");
    let events_path = td.path().join("events.jsonl");
    let cfg_path = td.path().join("direct-failover.toml");

    let server = TcpListener::bind("127.0.0.1:0").expect("stall server bind");
    let target_addr = server.local_addr().expect("stall server addr");
    let target_thread = thread::spawn(move || {
        let (conn, _) = server.accept().expect("accept stalled connection");
        thread::sleep(Duration::from_secs(2));
        drop(conn);
    });

    let socks_port = reserve_tcp_port();
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 300
freeze_threshold_bytes = 65536
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false

[relay]
server = "127.0.0.1:1"
server_name = "localhost"
auth_token = "{TEST_RELAY_AUTH_TOKEN}"
connect_timeout_ms = 3000
transport_priority = ["legacy_tls"]
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let mut socks = wait_for_port(socks_port, Duration::from_secs(20));
    socks_handshake(&mut socks, target_addr);
    socks
        .write_all(b"GET / HTTP/1.0\r\n\r\n")
        .expect("write request");

    let (session_fail, records) = wait_for_event(
        &events_path,
        "ingress_session_failed",
        Duration::from_secs(10),
    );
    let codes = event_codes(&records);
    assert!(
        codes.contains(&"direct_relay_failover_triggered"),
        "{records:?}"
    );
    assert!(codes.contains(&"relay_transport_failed"), "{records:?}");
    assert!(
        !codes.contains(&"direct_active_stall_probe_launched"),
        "{records:?}"
    );
    assert!(
        !codes.contains(&"direct_active_stall_probe_finished"),
        "{records:?}"
    );
    assert!(
        !codes.contains(&"direct_active_stall_probe_retry_selected"),
        "{records:?}"
    );
    assert!(
        !codes.contains(&"direct_active_stall_probe_retry_skipped"),
        "{records:?}"
    );
    assert!(
        !codes.contains(&"direct_active_stall_probe_retry_budget_exhausted"),
        "{records:?}"
    );

    let failover = records
        .iter()
        .find(|record| record["event_code"] == "direct_relay_failover_triggered")
        .expect("failover event");
    assert_eq!(failover["fields"]["target"], "127.0.0.1");
    assert_eq!(failover["fields"]["port"], target_addr.port());
    assert_eq!(failover["fields"]["signal"], "ThroughputCollapse");
    assert_eq!(
        failover["fields"]["probe_outcome_class"],
        "throughput_collapse"
    );
    assert_direct_path_health_contract(failover, "unstable", "direct_relay_failover_triggered");
    assert_terminal_health_summary(failover, false);
    assert_eq!(
        failover["fields"]["observation_contract"],
        "explicit_absence"
    );
    assert_eq!(
        failover["fields"]["observation_capture_confidence"],
        "explicit_absence"
    );
    assert_eq!(
        failover["fields"]["mimicry_capability_signal_origin"],
        "live_runtime_observation"
    );
    assert_compact_runtime_only_mimicry_contract(
        failover,
        "telemetry_only_no_stack_profile",
        None,
        None,
        None,
    );
    assert_eq!(
        failover["fields"]["mimicry_capability_wire_config_mode"],
        "disabled"
    );
    assert_eq!(
        failover["fields"]["mimicry_capability_wire_requested"],
        false
    );
    assert_eq!(failover["fields"]["mimicry_capability_wire_active"], false);
    assert_eq!(
        failover["fields"]["mimicry_capability_wire_activation_reason"],
        "config_disabled"
    );
    assert_eq!(
        failover["fields"]["direct_relay_failover_reason_code"],
        "no_inline_probe_attempt"
    );
    assert_eq!(failover["fields"]["probe_history_disposition"], "none");
    assert_eq!(
        failover["fields"]["probe_history_reason_code"],
        "no_recent_probe_history"
    );
    assert_eq!(
        failover["fields"]["cross_session_signal_bias"],
        "neutral_advisory_bias"
    );
    assert_eq!(failover["fields"]["active_stall_probe_recommended"], false);
    assert_eq!(
        failover["fields"]["active_stall_probe_retry_attempted"],
        false
    );

    let relay_fail = records
        .iter()
        .find(|record| record["event_code"] == "relay_transport_failed")
        .expect("relay transport failure");
    assert_eq!(relay_fail["fields"]["transport"], "LegacyTls");
    assert_eq!(relay_fail["fields"]["target"], "127.0.0.1");
    assert_eq!(relay_fail["fields"]["port"], target_addr.port());
    assert_eq!(relay_fail["fields"]["relay_server"], "127.0.0.1:1");
    assert_eq!(relay_fail["fields"]["relay_server_name"], "localhost");
    assert_eq!(relay_fail["fields"]["attempt_index"], 1);
    assert_eq!(relay_fail["fields"]["attempts_total"], 1);
    assert_eq!(
        relay_fail["fields"]["planned_transports"],
        serde_json::json!(["LegacyTls"])
    );
    assert_eq!(
        relay_fail["fields"]["relay_error_kind"],
        "connection_refused"
    );
    assert!(relay_fail["fields"]["error"].as_str().is_some());
    let relay_error_chain = relay_fail["fields"]["error_chain"]
        .as_array()
        .expect("relay error chain")
        .iter()
        .map(|cause| cause.as_str().expect("relay error cause string"))
        .collect::<Vec<_>>();
    assert!(
        relay_error_chain.len() >= 2,
        "preserve the connection refusal cause"
    );
    assert_eq!(relay_error_chain[0], "connect relay 127.0.0.1:1");
    assert_eq!(
        relay_fail["fields"]["error"],
        relay_error_chain.join(": "),
        "opt-in diagnostic errors must preserve the complete cause chain"
    );

    assert_eq!(session_fail["fields"]["ingress_kind"], "Socks5Fallback");
    assert_eq!(
        session_fail["fields"]["ingress_kind_code"],
        "socks5_fallback"
    );
    assert_eq!(session_fail["fields"]["session_kind"], "Socks5Fallback");
    assert_eq!(
        session_fail["fields"]["session_kind_code"],
        "socks5_fallback"
    );
    assert_eq!(session_fail["fields"]["backend"], "socks5_fallback");
    assert_eq!(session_fail["fields"]["backend_kind"], "Socks5Fallback");
    assert_eq!(
        session_fail["fields"]["backend_kind_code"],
        "socks5_fallback"
    );
    assert_eq!(session_fail["fields"]["requested_primary"], "Socks5");
    assert_eq!(session_fail["fields"]["requested_primary_code"], "socks5");
    assert_eq!(session_fail["fields"]["mode"], "Direct");
    assert_eq!(session_fail["fields"]["mode_code"], "direct");
    assert_eq!(
        session_fail["fields"]["wide_supported"],
        serde_json::Value::Null
    );
    assert_eq!(
        session_fail["fields"]["wide_platform_family_supported"],
        serde_json::Value::Null
    );
    assert_eq!(
        session_fail["fields"]["wide_runtime_readiness"],
        serde_json::Value::Null
    );
    assert_eq!(
        session_fail["fields"]["rollout_profile"],
        serde_json::Value::Null
    );
    assert_eq!(
        session_fail["fields"]["rollout_profile_code"],
        serde_json::Value::Null
    );
    assert_eq!(session_fail["fields"]["relay_terminal"], true);
    assert_eq!(
        session_fail["fields"]["relay_target"],
        relay_fail["fields"]["target"]
    );
    assert_eq!(
        session_fail["fields"]["relay_port"],
        relay_fail["fields"]["port"]
    );
    assert_eq!(
        session_fail["fields"]["relay_server"],
        relay_fail["fields"]["relay_server"]
    );
    assert_eq!(
        session_fail["fields"]["relay_server_name"],
        relay_fail["fields"]["relay_server_name"]
    );
    assert_eq!(
        session_fail["fields"]["relay_attempts_total"],
        relay_fail["fields"]["attempts_total"]
    );
    assert_eq!(
        session_fail["fields"]["relay_planned_transports"],
        relay_fail["fields"]["planned_transports"]
    );
    assert_eq!(
        session_fail["fields"]["relay_last_transport"],
        relay_fail["fields"]["transport"]
    );
    assert_eq!(
        session_fail["fields"]["session_error_kind"],
        relay_fail["fields"]["relay_error_kind"]
    );
    assert_eq!(
        session_fail["fields"]["error_chain"],
        relay_fail["fields"]["error_chain"]
    );
    assert_eq!(session_fail["fields"]["direct_relay_handoff"], true);
    assert_eq!(
        session_fail["fields"]["direct_relay_handoff_path"],
        "runtime_failover"
    );
    assert_eq!(
        session_fail["fields"]["direct_relay_handoff_reason_code"],
        failover["fields"]["direct_relay_failover_reason_code"]
    );
    assert_eq!(
        session_fail["fields"]["direct_relay_handoff_retry_attempted"],
        failover["fields"]["active_stall_probe_retry_attempted"]
    );
    assert!(session_fail["fields"]["error"]
        .as_str()
        .expect("session error")
        .contains(relay_fail["fields"]["error"].as_str().expect("relay error")));

    target_thread.join().expect("join stall thread");
}

#[test]
fn direct_failover_with_stack_profile_runtime_jsonl_e2e() {
    let td = TestDir::new("direct-failover-stack-profile");
    let events_path = td.path().join("events.jsonl");
    let cfg_path = td.path().join("direct-failover-stack-profile.toml");

    let server = TcpListener::bind("127.0.0.1:0").expect("stall server bind");
    let target_addr = server.local_addr().expect("stall server addr");
    let target_thread = thread::spawn(move || {
        let (conn, _) = server.accept().expect("accept stalled connection");
        thread::sleep(Duration::from_secs(2));
        drop(conn);
    });

    let socks_port = reserve_tcp_port();
    let stack_profile_line = stack_profile_config_line(Some("windows11"));
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 300
freeze_threshold_bytes = 65536
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
{stack_profile_line}
[relay]
server = "127.0.0.1:1"
server_name = "localhost"
auth_token = "{TEST_RELAY_AUTH_TOKEN}"
connect_timeout_ms = 3000
transport_priority = ["legacy_tls"]
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let mut socks = wait_for_port(socks_port, Duration::from_secs(20));
    socks_handshake(&mut socks, target_addr);
    socks
        .write_all(b"GET / HTTP/1.0\r\n\r\n")
        .expect("write request");

    let (_session_fail, records) = wait_for_event(
        &events_path,
        "ingress_session_failed",
        Duration::from_secs(10),
    );
    let failover = records
        .iter()
        .find(|record| record["event_code"] == "direct_relay_failover_triggered")
        .expect("failover event");
    assert_eq!(
        failover["fields"]["mimicry_capability_observation_capture_confidence"],
        "explicit_absence"
    );
    assert_direct_path_health_contract(failover, "unstable", "direct_relay_failover_triggered");
    assert_terminal_health_summary(failover, false);
    assert_compact_runtime_only_mimicry_contract(
        failover,
        "profile_only",
        Some("windows11"),
        Some(true),
        Some(true),
    );
    assert_eq!(
        failover["fields"]["mimicry_capability_wire_config_mode"],
        "disabled"
    );
    assert_eq!(
        failover["fields"]["mimicry_capability_wire_requested"],
        false
    );
    assert_eq!(failover["fields"]["mimicry_capability_wire_active"], false);
    assert_eq!(
        failover["fields"]["mimicry_capability_wire_activation_reason"],
        "config_disabled"
    );
    assert_eq!(
        failover["fields"]["mimicry_capability_userspace_ttl_hint_ready"],
        false
    );
    assert!(failover["fields"]["mimicry_capability_userspace_ttl_hint"].is_null());

    target_thread.join().expect("join stall thread");
}

#[test]
fn direct_failover_to_relay_success_runtime_jsonl_e2e() {
    let td = TestDir::new("direct-failover-relay-success");
    let events_path = td.path().join("events.jsonl");
    let cfg_path = td.path().join("direct-failover-relay-success.toml");
    let relay = RelayServerGuard::start(td.path());

    let target_listener = TcpListener::bind("127.0.0.1:0").expect("target bind");
    let target_addr = target_listener.local_addr().expect("target addr");
    let target_thread = thread::spawn(move || {
        let (mut direct_conn, _) = target_listener.accept().expect("accept direct connection");
        let mut request = [0u8; 4096];
        let direct_len = direct_conn.read(&mut request).expect("read direct request");
        assert!(
            request[..direct_len].starts_with(b"GET / HTTP/1.0"),
            "unexpected direct request"
        );
        thread::sleep(Duration::from_millis(800));
        drop(direct_conn);

        let (mut relay_conn, _) = target_listener.accept().expect("accept relay connection");
        let relay_len = relay_conn.read(&mut request).expect("read relay request");
        assert!(
            request[..relay_len].starts_with(b"GET / HTTP/1.0"),
            "unexpected relay request"
        );
        relay_conn
            .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .expect("write relay response");
    });

    let socks_port = reserve_tcp_port();
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 300
freeze_threshold_bytes = 65536
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false

[relay]
server = "{relay_server}"
server_name = "localhost"
auth_token = "{TEST_RELAY_AUTH_TOKEN}"
ca_cert = "{ca_cert}"
transport_priority = ["legacy_tls"]
"#,
            relay_server = relay.server_addr,
            ca_cert = common::toml_path(&relay.cert_path),
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let mut socks = wait_for_port(socks_port, Duration::from_secs(20));
    socks_handshake(&mut socks, target_addr);
    socks
        .write_all(b"GET / HTTP/1.0\r\n\r\n")
        .expect("write request");

    // Read-loop: a single .read() can return short on multi-packet HTTP responses (CI flake).
    socks
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("set read timeout");
    let mut response = Vec::with_capacity(128);
    // Was 10s: under parallel test load the relay-backed response sometimes had
    // not arrived, the loop fell out of the deadline arm with an EMPTY buffer, and
    // the assertion below then failed with a bare `""` — a timeout reported as a
    // protocol error, which is why this test flaked ~1 run in 6 and told nobody
    // why. Give it a realistic budget and report the two cases differently.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut chunk = [0u8; 128];
    let mut timed_out = false;
    loop {
        match socks.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                response.extend_from_slice(&chunk[..n]);
                if response.ends_with(b"ok") {
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    timed_out = true;
                    break;
                }
            }
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if std::time::Instant::now() >= deadline {
                    timed_out = true;
                    break;
                }
            }
            Err(err) => panic!("read relay-backed response: {err}"),
        }
    }
    let response_text = std::str::from_utf8(&response).expect("utf8 response");
    assert!(
        !(timed_out && response.is_empty()),
        "timed out after 30s with no bytes from the relay-backed SOCKS stream \
         (the client never produced a response; this is a timeout, not a bad response)"
    );
    assert!(
        response_text.starts_with("HTTP/1.0 200 OK"),
        "{response_text:?}"
    );
    assert!(response_text.ends_with("ok"), "{response_text:?}");
    drop(socks);

    let (_failover, _) = wait_for_event(
        &events_path,
        "direct_relay_failover_triggered",
        Duration::from_secs(10),
    );
    let (_relay_success, _) = wait_for_event(
        &events_path,
        "relay_session_succeeded",
        Duration::from_secs(10),
    );
    let records = read_jsonl_records(&events_path).expect("runtime records");
    let codes = event_codes(&records);
    assert!(
        codes.contains(&"direct_relay_failover_triggered"),
        "{records:?}"
    );
    assert!(codes.contains(&"relay_session_started"), "{records:?}");
    assert!(codes.contains(&"relay_transport_selected"), "{records:?}");
    assert!(codes.contains(&"relay_session_succeeded"), "{records:?}");
    assert_no_event(&records, "ingress_session_failed");
    assert_no_event(&records, "relay_transport_failed");

    let relay_started = records
        .iter()
        .find(|record| record["event_code"] == "relay_session_started")
        .expect("relay session started event");
    assert_eq!(relay_started["fields"]["relay_session_kind"], "tcp_tunnel");
    assert_eq!(
        relay_started["fields"]["target"],
        target_addr.ip().to_string()
    );
    assert_eq!(relay_started["fields"]["port"], target_addr.port());
    assert_eq!(
        relay_started["fields"]["relay_server"],
        relay.server_addr.as_str()
    );
    let relay_surface_profile_id = relay_started["fields"]["relay_surface_profile_id"]
        .as_str()
        .expect("relay surface profile id");
    assert!(CATALOG_PROFILE_IDS.contains(&relay_surface_profile_id));
    // `relay_surface_grpc_message_type` is null for some catalog profiles
    // (`cli_https_compact`, `enterprise_java_client`, `realtime_websocket`,
    // `grpc_api`, `iot_telemetry`, `api_batch_poller`) and a string for the
    // rest. Only assert string shape when the profile publishes a value.
    if let Some(relay_grpc_message_type) =
        relay_started["fields"]["relay_surface_grpc_message_type"].as_str()
    {
        assert!(["TunnelRequest", "SessionOpenRequest"].contains(&relay_grpc_message_type));
    }
    // `relay_surface_masque_alt_used` is only populated when the selected
    // catalog profile has a `masque_alt_used_strategy` set. Profiles like
    // `cli_https_compact` and `enterprise_java_client` intentionally leave
    // this None, so assert shape only when the field is actually emitted.
    if let Some(masque_alt) = relay_started["fields"]["relay_surface_masque_alt_used"].as_str() {
        assert_eq!(masque_alt, "localhost");
    }

    let relay_selected = records
        .iter()
        .find(|record| record["event_code"] == "relay_transport_selected")
        .expect("relay transport selected event");
    assert_eq!(relay_selected["fields"]["relay_session_kind"], "tcp_tunnel");
    assert_eq!(relay_selected["fields"]["transport"], "LegacyTls");
    assert_eq!(relay_selected["fields"]["attempt_index"], 1);
    // Only `browser_like_*` family profiles publish a WebSocket Origin header.
    // Profiles like `cli_https_compact` and `enterprise_java_client` leave
    // this None by design, so shape-check only when the field is present.
    if let Some(ws_origin) = relay_selected["fields"]["relay_surface_websocket_origin"].as_str() {
        assert_eq!(ws_origin, "https://localhost");
    }

    let relay_succeeded = records
        .iter()
        .find(|record| record["event_code"] == "relay_session_succeeded")
        .expect("relay session succeeded event");
    assert_eq!(
        relay_succeeded["fields"]["relay_session_kind"],
        "tcp_tunnel"
    );
    assert_eq!(relay_succeeded["fields"]["chosen_transport"], "LegacyTls");
    assert_eq!(relay_succeeded["fields"]["attempt_index"], 1);
    // `relay_surface_grpc_timeout` is derived per catalog profile. The
    // expected value table lives in `expected_grpc_timeout_for` near the top
    // of this test file and is kept in lockstep with the catalog itself.
    let succeeded_profile_id = relay_succeeded["fields"]["relay_surface_profile_id"]
        .as_str()
        .expect("relay surface profile id on succeeded event");
    let expected_grpc_timeout = expected_grpc_timeout_for(succeeded_profile_id);
    assert_eq!(
        relay_succeeded["fields"]["relay_surface_grpc_timeout"], expected_grpc_timeout,
        "grpc timeout did not match catalog profile {succeeded_profile_id}"
    );

    target_thread.join().expect("join target thread");
}

#[cfg(not(feature = "legacy-challenge-v1"))]
#[test]
fn hybrid_route_to_grpc_runtime_jsonl_e2e() {
    let td = TestDir::new("hybrid-classifier-route-relay");
    let events_path = td.path().join("events.jsonl");
    let cfg_path = td.path().join("hybrid-classifier-route-relay.toml");
    let state_path = td.path().join("hybrid-state.json");
    let mut relay = RelayServerGuard::start(td.path());

    let target_listener = TcpListener::bind("127.0.0.1:0").expect("target bind");
    let target_addr = target_listener.local_addr().expect("target addr");
    let target_thread = thread::spawn(move || {
        let (mut conn, _) = target_listener.accept().expect("accept relayed connection");
        let mut request = [0u8; 4096];
        let len = conn.read(&mut request).expect("read relayed request");
        assert!(
            request[..len].starts_with(b"GET /hybrid HTTP/1.0"),
            "unexpected relayed request"
        );
        conn.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 6\r\n\r\nhybrid")
            .expect("write response");
    });

    let now_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64;
    let seeded_state = StateSnapshot {
        external_calibration: Some(ExternalCalibrationSnapshot {
            schema_version: 1,
            source: "runtime-e2e-classifier".into(),
            generated_at_unix_ms: Some(now_unix_ms),
            freshness_half_life_secs: Some(3_600),
            knowledge: vec![ExternalKnowledgePrior {
                target_class: "direct_geneva".into(),
                region_id: Some("controlled-e2e".into()),
                score: 0.0,
                confidence: 1.0,
                hard_excluded: true,
                fail_closed: true,
                generated_at_unix_ms: Some(now_unix_ms),
            }],
            ..Default::default()
        }),
        ..Default::default()
    };
    common::write_private_file(
        &state_path,
        serde_json::to_vec(&seeded_state).expect("serialize seeded hybrid state"),
    )
    .expect("write hybrid state");

    let socks_port = reserve_tcp_port();
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "auto"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
persist_state = true
strategies = ["geneva"]
geneva_strategy = '[TCP:flags:PA]-duplicate(,)-| \/'
hybrid_geneva = true
epsilon = 0.0
state_path = "{state_path}"
first_chunk_timeout_ms = 300
freeze_threshold_bytes = 65536
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false

[relay]
server = "{relay_server}"
server_name = "localhost"
auth_token = "{TEST_RELAY_AUTH_TOKEN}"
ca_cert = "{ca_cert}"
transport_priority = ["grpc_stream"]
udp_transport_priority = ["masque_derived"]
masque_server = "{quic_server}"
masque_server_name = "localhost"
masque_ca_cert = "{ca_cert}"
"#,
            state_path = common::toml_path(&state_path),
            relay_server = relay.server_addr,
            quic_server = relay.quic_server_addr,
            ca_cert = common::toml_path(&relay.cert_path),
        ),
    )
    .expect("write hybrid config");

    let client = ChildGuard::spawn(&cfg_path, &events_path);
    let mut socks = wait_for_port(socks_port, Duration::from_secs(20));
    socks_handshake(&mut socks, target_addr);
    socks
        .write_all(b"GET /hybrid HTTP/1.0\r\n\r\n")
        .expect("write request");
    socks
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");
    let mut response = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut chunk = [0u8; 512];
    while Instant::now() < deadline && !response.ends_with(b"hybrid") {
        match socks.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&chunk[..n]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue
            }
            Err(error) => panic!("read response: {error}"),
        }
    }
    assert!(
        response.ends_with(b"hybrid"),
        "hybrid response={response:?}; {}; client stderr:\n{}\nfixture events:\n{:?}",
        relay.diagnostic(),
        client.stderr_tail(),
        read_jsonl_records(&events_path),
    );
    drop(socks);

    let (_handoff_succeeded, records) = wait_for_event(
        &events_path,
        "direct_relay_handoff_succeeded",
        Duration::from_secs(10),
    );
    let selected = records
        .iter()
        .find(|record| record["event_code"] == "hybrid_route_selected")
        .expect("hybrid route selected event");
    assert_eq!(selected["fields"]["route_family"], "relay_grpc");
    let capabilities = &selected["fields"]["capability_summary"];
    let direct_capable =
        capabilities["ipv4_raw_send"] == true && capabilities["tcp_repair_query"] == true;
    let expected_reason = if direct_capable {
        "external_classifier_hard_block"
    } else {
        "direct_capability_unavailable"
    };
    assert_eq!(selected["fields"]["reason_code"], expected_reason);
    assert_eq!(selected["fields"]["address_family"], "ipv4");
    assert_eq!(selected["fields"]["evidence_confidence"], "high");
    assert_eq!(selected["fields"]["external_classifier_hint_present"], true);
    assert!(selected["fields"]["strategy_fingerprint"]
        .as_str()
        .is_some_and(|value| value.len() == 24));
    assert!(records
        .iter()
        .any(|record| record["event_code"] == "direct_relay_handoff_started"));
    let relay_success = records
        .iter()
        .find(|record| {
            record["event_code"] == "relay_session_succeeded"
                && record["fields"]["port"].as_u64() == Some(u64::from(target_addr.port()))
        })
        .expect("successful relay session for the actual owned target");
    assert_eq!(relay_success["fields"]["chosen_transport"], "GrpcStream");
    assert_eq!(relay_success["fields"]["target"], "127.0.0.1");
    assert_eq!(
        relay_success["fields"]["application_response_observed"],
        true
    );
    assert_no_event(&records, "geneva_direct_attempt_started");
    assert_no_event(&records, "geneva_direct_attempt_failed");
    assert_no_event(&records, "hybrid_flow_blocked_fail_closed");

    target_thread.join().expect("join target thread");
}

#[cfg(feature = "legacy-challenge-v1")]
#[test]
fn hybrid_raw_only_build_rejects_before_ingress_or_relay() {
    let td = TestDir::new("hybrid-raw-build-admission");
    let events_path = td.path().join("events.jsonl");
    let cfg_path = td.path().join("hybrid.toml");
    let state_path = td.path().join("state.json");
    let relay = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let masque = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    relay.set_nonblocking(true).unwrap();
    target.set_nonblocking(true).unwrap();
    masque.set_nonblocking(true).unwrap();
    let socks_port = reserve_tcp_port();
    let config = format!(
        r#"mode = "auto"
[ingress]
primary = "socks5"
allow_fallback = false
[socks]
listen = "127.0.0.1:{socks_port}"
[direct]
persist_state = true
state_path = "{state_path}"
strategies = ["geneva"]
geneva_strategy = '[TCP:flags:PA]-duplicate(,)-| \/'
hybrid_geneva = true
[relay]
server = "{relay_addr}"
server_name = "localhost"
auth_token = "{TEST_RELAY_AUTH_TOKEN}"
transport_priority = ["grpc_stream"]
udp_transport_priority = ["masque_derived"]
masque_server = "{masque_addr}"
masque_server_name = "localhost"
"#,
        state_path = common::toml_path(&state_path),
        relay_addr = relay.local_addr().unwrap(),
        masque_addr = masque.local_addr().unwrap()
    );
    let cfg: aegis_core::Settings = toml::from_str(&config).unwrap();
    cfg.validate_hybrid_geneva()
        .expect("otherwise valid hybrid contract");
    common::write_private_file(&cfg_path, config).unwrap();
    let mut client = ChildGuard::spawn(&cfg_path, &events_path);
    let status = client
        .wait_for_exit(Duration::from_secs(10))
        .expect("bounded early config rejection");
    assert!(!status.success(), "incompatible build must fail startup");
    assert!(client.stderr_tail().contains("hybrid Geneva shared-token fallback is incompatible with legacy-challenge-v1 raw-only mode"));
    let _ingress = TcpListener::bind(("127.0.0.1", socks_port)).expect("no client ingress remains");
    for listener in [&relay, &target] {
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
            "no relay or target dialing before admission"
        );
    }
    let mut packet = [0u8; 1];
    assert!(
        matches!(masque.recv_from(&mut packet), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "no QUIC before admission"
    );
    match fs::read(&events_path) {
        Ok(bytes) => assert!(
            bytes.iter().all(u8::is_ascii_whitespace),
            "rejected config must not emit any event bytes, including malformed records"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("cannot verify rejected configuration event file: {error}"),
    }
    assert!(
        !state_path.exists(),
        "rejected config must not write learned state"
    );
}

#[test]
fn direct_advisory_runtime_jsonl_e2e() {
    let td = TestDir::new("direct-advisory");
    let events_path = td.path().join("events.jsonl");
    let cfg_path = td.path().join("direct-advisory.toml");
    let state_path = td.path().join("state.json");

    write_seeded_state(
        &state_path,
        443,
        StallProbeStats {
            trials: 3,
            collapses: 2,
            timeouts: 1,
            consecutive_stall_failures: 2,
            last_signal: Some(FailSignal::Timeout),
            ..StallProbeStats::default()
        },
    );

    let socks_port = reserve_tcp_port();
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
persist_state = true
state_path = "{}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false

[relay]
server = "127.0.0.1:1"
server_name = "localhost"
auth_token = "{TEST_RELAY_AUTH_TOKEN}"
connect_timeout_ms = 3000
transport_priority = ["legacy_tls"]
"#,
            common::toml_path(&state_path),
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let mut socks = wait_for_port(socks_port, Duration::from_secs(20));
    socks_handshake(&mut socks, "127.0.0.1:443".parse().expect("target addr"));
    socks
        .write_all(b"GET / HTTP/1.0\r\n\r\n")
        .expect("write request");
    // Keep the peer readable so the relay handoff still surfaces a terminal
    // failure instead of being short-circuited as an already-aborted local
    // session.
    socks.shutdown(Shutdown::Write).expect("shutdown write");

    let (session_fail, records) = wait_for_event(
        &events_path,
        "ingress_session_failed",
        Duration::from_secs(10),
    );
    let codes = event_codes(&records);
    assert!(
        codes.contains(&"direct_relay_preferred_from_probe_history"),
        "{records:?}"
    );
    assert!(codes.contains(&"relay_transport_failed"), "{records:?}");

    let advisory = records
        .iter()
        .find(|record| record["event_code"] == "direct_relay_preferred_from_probe_history")
        .expect("advisory event");
    assert_eq!(advisory["fields"]["target"], "127.0.0.1");
    assert_eq!(advisory["fields"]["port"], 443);
    assert_eq!(
        advisory["fields"]["probe_history_disposition"],
        "prefer_relay"
    );
    assert_eq!(
        advisory["fields"]["probe_history_reason_code"],
        "repeated_stall_prefer_relay"
    );
    assert_eq!(advisory["fields"]["observation_contract"], "deep_observed");
    assert!(
        advisory["fields"]["cross_session_relay_preference_score"]
            .as_f64()
            .expect("relay preference score")
            > 0.55
    );
    assert_eq!(
        advisory["fields"]["cross_session_probe_branch_score"],
        serde_json::json!(0.0)
    );
    assert_eq!(advisory["fields"]["last_probe_signal"], "Timeout");
    assert_eq!(advisory["fields"]["stall_probe_collapses"], 2);
    assert_eq!(advisory["fields"]["stall_probe_timeouts"], 1);
    assert_eq!(advisory["fields"]["stall_probe_trials"], 3);
    assert_eq!(
        advisory["fields"]["mimicry_capability_stage"],
        "early_pre_wire_capability_layer"
    );
    assert_eq!(
        advisory["fields"]["mimicry_capability_signal_origin"],
        "advisory_latest_observation"
    );
    assert_eq!(
        advisory["fields"]["mimicry_capability_readiness"],
        "composite_signal_ready"
    );
    assert_eq!(
        advisory["fields"]["mimicry_capability_server_hint_ready"],
        true
    );
    assert_eq!(
        advisory["fields"]["mimicry_capability_window_profile_ready"],
        true
    );
    assert_eq!(
        advisory["fields"]["mimicry_capability_reference_path_ready"],
        true
    );
    assert_eq!(
        advisory["fields"]["mimicry_capability_rst_path_ready"],
        false
    );
    assert_eq!(
        advisory["fields"]["mimicry_capability_server_hint"],
        "likely_cdn"
    );
    assert_eq!(
        advisory["fields"]["mimicry_capability_window_profile"],
        "huge"
    );
    assert_eq!(
        advisory["fields"]["mimicry_capability_reference_path_hops"],
        2
    );
    assert!(advisory["fields"]["mimicry_capability_rst_path_hops"].is_null());

    let relay_fail = records
        .iter()
        .find(|record| record["event_code"] == "relay_transport_failed")
        .expect("relay failure");
    assert_eq!(relay_fail["fields"]["transport"], "LegacyTls");
    assert_eq!(relay_fail["fields"]["target"], "127.0.0.1");
    assert_eq!(relay_fail["fields"]["port"], 443);
    assert_eq!(relay_fail["fields"]["relay_server"], "127.0.0.1:1");
    assert_eq!(relay_fail["fields"]["relay_server_name"], "localhost");
    assert_eq!(relay_fail["fields"]["attempt_index"], 1);
    assert_eq!(relay_fail["fields"]["attempts_total"], 1);
    assert_eq!(
        relay_fail["fields"]["planned_transports"],
        serde_json::json!(["LegacyTls"])
    );
    assert_eq!(
        relay_fail["fields"]["relay_error_kind"],
        "connection_refused"
    );
    let relay_surface_profile_id = relay_fail["fields"]["relay_surface_profile_id"]
        .as_str()
        .expect("relay surface profile id");
    assert!(CATALOG_PROFILE_IDS.contains(&relay_surface_profile_id));
    // relay_surface_grpc_message_type is null for the catalog profiles that
    // leave grpc_message_type_header unset by design (cli_https_compact,
    // enterprise_java_client, realtime_websocket, grpc_api, iot_telemetry,
    // api_batch_poller). Shape-check only when present.
    if let Some(relay_grpc_message_type) =
        relay_fail["fields"]["relay_surface_grpc_message_type"].as_str()
    {
        assert!(["TunnelRequest", "SessionOpenRequest"].contains(&relay_grpc_message_type));
    }
    assert!(relay_fail["fields"]["error"].as_str().is_some());

    assert_eq!(session_fail["fields"]["ingress_kind"], "Socks5Fallback");
    assert_eq!(session_fail["fields"]["session_kind"], "Socks5Fallback");
    assert_eq!(session_fail["fields"]["backend"], "socks5_fallback");
    assert_eq!(session_fail["fields"]["backend_kind"], "Socks5Fallback");
    assert_eq!(session_fail["fields"]["requested_primary"], "Socks5");
    assert_eq!(session_fail["fields"]["mode"], "Direct");
    assert_eq!(
        session_fail["fields"]["wide_supported"],
        serde_json::Value::Null
    );
    assert_eq!(
        session_fail["fields"]["wide_platform_family_supported"],
        serde_json::Value::Null
    );
    assert_eq!(
        session_fail["fields"]["wide_runtime_readiness"],
        serde_json::Value::Null
    );
    assert_eq!(
        session_fail["fields"]["rollout_profile"],
        serde_json::Value::Null
    );
    assert_eq!(session_fail["fields"]["relay_terminal"], true);
    assert_eq!(
        session_fail["fields"]["relay_target"],
        relay_fail["fields"]["target"]
    );
    assert_eq!(
        session_fail["fields"]["relay_port"],
        relay_fail["fields"]["port"]
    );
    assert_eq!(
        session_fail["fields"]["relay_server"],
        relay_fail["fields"]["relay_server"]
    );
    assert_eq!(
        session_fail["fields"]["relay_server_name"],
        relay_fail["fields"]["relay_server_name"]
    );
    assert_eq!(
        session_fail["fields"]["relay_attempts_total"],
        relay_fail["fields"]["attempts_total"]
    );
    assert_eq!(
        session_fail["fields"]["relay_planned_transports"],
        relay_fail["fields"]["planned_transports"]
    );
    assert_eq!(
        session_fail["fields"]["relay_last_transport"],
        relay_fail["fields"]["transport"]
    );
    assert_eq!(session_fail["fields"]["direct_relay_handoff"], true);
    assert_eq!(
        session_fail["fields"]["direct_relay_handoff_path"],
        "probe_history_prefer_relay"
    );
    assert_eq!(
        session_fail["fields"]["direct_relay_handoff_reason_code"],
        advisory["fields"]["probe_history_reason_code"]
    );
    assert!(session_fail["fields"]["direct_relay_handoff_retry_attempted"].is_null());
    assert!(session_fail["fields"]["error"]
        .as_str()
        .expect("session error")
        .contains(relay_fail["fields"]["error"].as_str().expect("relay error")));
}

#[test]
fn direct_probe_branch_runtime_jsonl_e2e() {
    let td = TestDir::new("direct-probe-branch");
    let events_path = td.path().join("events.jsonl");
    let cfg_path = td.path().join("direct-branch.toml");
    let state_path = td.path().join("state.json");

    write_seeded_state(
        &state_path,
        443,
        StallProbeStats {
            trials: 1,
            collapses: 1,
            consecutive_stall_failures: 1,
            last_signal: Some(FailSignal::ThroughputCollapse),
            ..StallProbeStats::default()
        },
    );

    let socks_port = reserve_tcp_port();
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
persist_state = true
state_path = "{}"
strategies = ["passthrough", "ttl_desync", "overlap"]
epsilon = 0.0
first_chunk_timeout_ms = 500
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false

[relay]
server = ""
server_name = ""
auth_token = ""
"#,
            common::toml_path(&state_path),
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let mut socks = wait_for_port(socks_port, Duration::from_secs(20));
    socks_handshake(&mut socks, "127.0.0.1:443".parse().expect("target addr"));
    socks
        .write_all(b"GET / HTTP/1.0\r\n\r\n")
        .expect("write request");
    drop(socks);

    let (session_fail, records) = wait_for_event(
        &events_path,
        "ingress_session_failed",
        Duration::from_secs(10),
    );
    let codes = event_codes(&records);
    assert!(
        codes.contains(&"direct_planner_order_selected"),
        "{records:?}"
    );
    assert!(
        !codes.contains(&"direct_active_probe_branch_selected"),
        "{records:?}"
    );

    let planner = records
        .iter()
        .find(|record| record["event_code"] == "direct_planner_order_selected")
        .expect("planner event");
    assert_eq!(
        planner["fields"]["planner_order_resolution"],
        "reward_loop_only"
    );
    assert_eq!(
        planner["fields"]["planner_resolved_order_primary_reason"],
        "reward_loop_preserved"
    );
    assert_planner_top_candidate_reason_matches_candidate(planner);
    assert_eq!(
        planner["fields"]["planner_post_brain_reorder_applied"],
        false
    );
    assert_eq!(
        planner["fields"]["planner_reward_loop_order_preserved"],
        true
    );
    assert_eq!(
        planner["fields"]["planner_advisory_reorder_requested"],
        true
    );
    assert_eq!(planner["fields"]["planner_advisory_reorder_applied"], false);
    assert_eq!(
        planner["fields"]["planner_selection_stage"],
        "initial_session_order"
    );
    assert_eq!(planner["fields"]["planner_retry_attempt"], 0);
    assert_eq!(planner["fields"]["planner_has_previous_selection"], false);
    assert_eq!(
        planner["fields"]["planner_previous_reward_selected_order"],
        serde_json::Value::Null
    );
    assert_eq!(
        planner["fields"]["planner_previous_resolved_order"],
        serde_json::Value::Null
    );
    assert_eq!(
        planner["fields"]["planner_reward_selected_order_changed"],
        false
    );
    assert_eq!(planner["fields"]["planner_resolved_order_changed"], false);
    assert_eq!(
        planner["fields"]["planner_reward_selected_order"],
        serde_json::json!(["ttl_desync", "overlap", "passthrough"])
    );
    assert_eq!(
        planner["fields"]["planner_resolved_order"],
        serde_json::json!(["ttl_desync", "overlap", "passthrough"])
    );
    assert_eq!(
        planner["fields"]["cross_session_signal_bias"],
        "probe_branch_bias"
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_stage"],
        "early_pre_wire_capability_layer"
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_signal_origin"],
        "advisory_latest_observation"
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_readiness"],
        "composite_signal_ready"
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_observation_capture_confidence"],
        "deep_observed"
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_userspace_scope"],
        "pre_connect_socket_only"
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_userspace_wiring_mode"],
        "capture_backed_ttl_only"
    );
    assert!(planner["fields"]["mimicry_capability_userspace_stack_profile"].is_null());
    assert_eq!(
        planner["fields"]["mimicry_capability_userspace_ttl_hint_ready"],
        true
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_userspace_ttl_hint"],
        60
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_server_hint_ready"],
        true
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_window_profile_ready"],
        true
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_reference_path_ready"],
        true
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_rst_path_ready"],
        false
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_server_hint"],
        "likely_cdn"
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_window_profile"],
        "huge"
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_reference_path_hops"],
        2
    );
    assert!(planner["fields"]["mimicry_capability_rst_path_hops"].is_null());

    assert_eq!(planner["fields"]["target"], "127.0.0.1");
    assert_eq!(planner["fields"]["port"], 443);
    assert_eq!(
        planner["fields"]["probe_history_disposition"],
        "bias_probe_branch"
    );
    assert_eq!(
        planner["fields"]["probe_history_reason_code"],
        "single_stall_bias_probe_branch"
    );
    assert_eq!(planner["fields"]["observation_contract"], "deep_observed");
    assert!(
        planner["fields"]["cross_session_probe_branch_score"]
            .as_f64()
            .expect("probe branch score")
            > 0.0
    );
    assert_eq!(
        planner["fields"]["cross_session_relay_preference_score"],
        serde_json::json!(0.0)
    );
    let ranked = planner["fields"]["planner_ranked_candidates"]
        .as_array()
        .expect("ranked candidates");
    assert_eq!(ranked[0]["strategy"], "ttl_desync");
    assert_eq!(ranked[1]["strategy"], "overlap");
    assert_eq!(ranked[2]["strategy"], "passthrough");
    assert!(
        ranked[0]["probe_history_strategy_bias"]
            .as_f64()
            .expect("ttl probe bias")
            > 0.0
    );
    assert!(
        ranked[1]["probe_history_strategy_bias"]
            .as_f64()
            .expect("overlap probe bias")
            > 0.0
    );
    assert!(
        ranked[2]["probe_history_strategy_bias"]
            .as_f64()
            .expect("passthrough probe bias")
            < 0.0
    );
    assert_eq!(
        planner["fields"]["planner_resolved_order"],
        serde_json::json!(["ttl_desync", "overlap", "passthrough"])
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_stage"],
        "early_pre_wire_capability_layer"
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_signal_origin"],
        "advisory_latest_observation"
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_readiness"],
        "composite_signal_ready"
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_server_hint_ready"],
        true
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_window_profile_ready"],
        true
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_reference_path_ready"],
        true
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_rst_path_ready"],
        false
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_server_hint"],
        "likely_cdn"
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_window_profile"],
        "huge"
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_reference_path_hops"],
        2
    );
    assert!(planner["fields"]["mimicry_capability_rst_path_hops"].is_null());

    assert_eq!(session_fail["fields"]["ingress_kind"], "Socks5Fallback");
    assert_eq!(session_fail["fields"]["session_kind"], "Socks5Fallback");
    assert_eq!(session_fail["fields"]["backend"], "socks5_fallback");
    assert_eq!(session_fail["fields"]["backend_kind"], "Socks5Fallback");
    assert_eq!(session_fail["fields"]["requested_primary"], "Socks5");
    assert_eq!(session_fail["fields"]["mode"], "Direct");
    assert_eq!(
        session_fail["fields"]["wide_supported"],
        serde_json::Value::Null
    );
    assert_eq!(
        session_fail["fields"]["wide_platform_family_supported"],
        serde_json::Value::Null
    );
    assert_eq!(
        session_fail["fields"]["wide_runtime_readiness"],
        serde_json::Value::Null
    );
    assert_eq!(session_fail["fields"]["relay_terminal"], false);
    assert!(session_fail["fields"]["relay_planned_transports"].is_null());
    assert_eq!(session_fail["fields"]["direct_relay_handoff"], false);
    assert!(session_fail["fields"]["direct_relay_handoff_path"].is_null());
    assert_eq!(
        session_fail["fields"]["rollout_profile"],
        serde_json::Value::Null
    );
    assert!(session_fail["fields"]["error"].as_str().is_some());
}

#[test]
fn direct_runtime_only_single_stall_does_not_bias_planner_runtime_jsonl_e2e() {
    let td = TestDir::new("direct-runtime-only-planner");
    let events_path = td.path().join("events.jsonl");
    let cfg_path = td.path().join("direct-runtime-only-planner.toml");
    let state_path = td.path().join("state.json");

    let target_listener = TcpListener::bind("127.0.0.1:0").expect("target bind");
    let target_addr = target_listener.local_addr().expect("target addr");
    let key_hash = loopback_direct_key(target_addr.port()).hash_key();
    let mut passthrough = StrategyStatsV2::default();
    passthrough.record(&FailSignal::Success, Some(10), 2048);
    passthrough.record(&FailSignal::Success, Some(12), 2048);
    let mut ttl_desync = StrategyStatsV2::default();
    ttl_desync.record(&FailSignal::Timeout, None, 0);
    ttl_desync.record(&FailSignal::Unknown, None, 0);
    write_seeded_state_with_strategy_stats(
        &state_path,
        target_addr.port(),
        StallProbeStats {
            trials: 1,
            collapses: 1,
            consecutive_stall_failures: 1,
            last_signal: Some(FailSignal::ThroughputCollapse),
            ..StallProbeStats::default()
        },
        runtime_only_seeded_observation(),
        HashMap::from([
            (format!("{key_hash}|passthrough"), passthrough),
            (format!("{key_hash}|ttl_desync"), ttl_desync),
        ]),
    );
    let target_thread = thread::spawn(move || {
        let (mut conn, _) = target_listener.accept().expect("accept target");
        let mut request = [0u8; 4096];
        let n = conn.read(&mut request).expect("read request");
        assert!(
            request[..n].starts_with(b"GET /runtime-only HTTP/1.0"),
            "unexpected request"
        );
        conn.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 12\r\n\r\nruntime-only")
            .expect("write response");
        let _ = conn.shutdown(Shutdown::Both);
    });

    let socks_port = reserve_tcp_port();
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
persist_state = true
state_path = "{}"
strategies = ["passthrough", "ttl_desync"]
epsilon = 0.0
first_chunk_timeout_ms = 500
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false

[relay]
server = ""
server_name = ""
auth_token = ""
"#,
            common::toml_path(&state_path),
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let mut socks = wait_for_port(socks_port, Duration::from_secs(20));
    socks_handshake(&mut socks, target_addr);
    socks
        .write_all(b"GET /runtime-only HTTP/1.0\r\n\r\n")
        .expect("write request");
    let mut response = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && !response.windows(12).any(|window| window == b"runtime-only")
    {
        let mut chunk = [0u8; 4096];
        let n = socks.read(&mut chunk).expect("read response");
        if n == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..n]);
    }
    assert!(
        response.windows(12).any(|window| window == b"runtime-only"),
        "missing runtime-only payload"
    );
    drop(socks);

    let (planner, records) = wait_for_event(
        &events_path,
        "direct_planner_order_selected",
        Duration::from_secs(10),
    );
    let codes = event_codes(&records);
    assert!(
        !codes.contains(&"direct_active_probe_branch_selected"),
        "{records:?}"
    );
    let (success, _) = wait_for_event(
        &events_path,
        "direct_session_succeeded",
        Duration::from_secs(10),
    );
    assert_eq!(
        planner["fields"]["planner_order_resolution"],
        "reward_loop_only"
    );
    assert_eq!(
        planner["fields"]["planner_resolved_order_primary_reason"],
        "reward_loop_preserved"
    );
    assert_planner_top_candidate_reason_matches_candidate(&planner);
    assert_planner_delta_baseline(&planner);
    assert_planner_explainability_contract(
        &planner,
        "brain_reward_loop",
        "state_snapshot_contextual_reward",
        "advisory_state_snapshot_observation",
    );
    assert_eq!(
        planner["fields"]["planner_post_brain_reorder_applied"],
        false
    );
    assert_eq!(
        planner["fields"]["planner_reward_loop_order_preserved"],
        true
    );
    assert_eq!(planner["fields"]["planner_lua_order_configured"], false);
    assert_eq!(planner["fields"]["planner_lua_order_applied"], false);
    assert_eq!(
        planner["fields"]["planner_advisory_reorder_requested"],
        false
    );
    assert_eq!(planner["fields"]["planner_advisory_reorder_applied"], false);
    assert_eq!(
        planner["fields"]["planner_selection_stage"],
        "initial_session_order"
    );
    assert_eq!(planner["fields"]["planner_retry_attempt"], 0);
    assert_eq!(planner["fields"]["planner_has_previous_selection"], false);
    assert_eq!(
        planner["fields"]["planner_previous_reward_selected_order"],
        serde_json::Value::Null
    );
    assert_eq!(
        planner["fields"]["planner_previous_resolved_order"],
        serde_json::Value::Null
    );
    assert_eq!(
        planner["fields"]["planner_reward_selected_order_changed"],
        false
    );
    assert_eq!(planner["fields"]["planner_resolved_order_changed"], false);
    assert_eq!(
        planner["fields"]["planner_reward_selected_order"],
        serde_json::json!(["passthrough", "ttl_desync"])
    );
    assert_eq!(
        planner["fields"]["planner_resolved_order"],
        serde_json::json!(["passthrough", "ttl_desync"])
    );
    assert_eq!(planner["fields"]["observation_contract"], "runtime_only");
    assert_eq!(
        planner["fields"]["observation_capture_confidence"],
        "runtime_only"
    );
    assert!(
        planner["fields"]["cross_session_reuse_weight"]
            .as_f64()
            .expect("reuse weight")
            > 0.0
    );
    assert_eq!(planner["fields"]["probe_history_disposition"], "none");
    assert_eq!(
        planner["fields"]["probe_history_reason_code"],
        "probe_observation_not_probe_capable"
    );
    assert_eq!(
        planner["fields"]["cross_session_signal_bias"],
        "neutral_advisory_bias"
    );
    assert_eq!(
        planner["fields"]["cross_session_probe_branch_score"],
        serde_json::json!(0.0)
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_signal_origin"],
        "advisory_latest_observation"
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_stage"],
        "early_pre_wire_capability_layer"
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_readiness"],
        "path_signal_ready"
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_observation_capture_confidence"],
        "runtime_only"
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_server_hint_ready"],
        false
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_window_profile_ready"],
        false
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_reference_path_ready"],
        true
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_rst_path_ready"],
        false
    );
    assert!(planner["fields"]["mimicry_capability_server_hint"].is_null());
    assert!(planner["fields"]["mimicry_capability_window_profile"].is_null());
    assert_eq!(
        planner["fields"]["mimicry_capability_reference_path_hops"],
        2
    );
    assert!(planner["fields"]["mimicry_capability_rst_path_hops"].is_null());
    let ranked = planner["fields"]["planner_ranked_candidates"]
        .as_array()
        .expect("ranked candidates");
    assert_eq!(ranked.len(), 2);
    assert_eq!(ranked[0]["has_previous_candidate_trace"], false);
    assert_eq!(ranked[0]["previous_rank"], serde_json::Value::Null);
    assert_eq!(ranked[0]["rank_delta"], serde_json::Value::Null);
    assert_eq!(
        ranked[0]["previous_selection_score"],
        serde_json::Value::Null
    );
    assert_eq!(ranked[0]["selection_score_delta"], serde_json::Value::Null);
    assert_eq!(
        ranked[0]["selection_score_reward_component"],
        ranked[0]["estimated_reward"]
    );
    assert!(ranked[0]["selection_score_ucb_exploration_bonus"]
        .as_f64()
        .is_some());
    assert_eq!(
        ranked[0]["selection_score_probe_bias_component"],
        ranked[0]["probe_history_strategy_bias"]
    );
    assert_eq!(
        ranked[0]["selection_score_dominant_component"],
        "ucb_exploration_bonus"
    );
    assert_eq!(ranked[0]["selection_score_probe_bias_effect"], "neutral");
    assert_eq!(ranked[0]["strategy"], "passthrough");
    assert_eq!(ranked[1]["strategy"], "ttl_desync");
    assert_eq!(
        ranked[0]["probe_history_strategy_bias"],
        serde_json::json!(0.0)
    );
    assert_eq!(
        ranked[1]["probe_history_strategy_bias"],
        serde_json::json!(0.0)
    );
    assert_eq!(
        ranked[0]["selection_score_reward_component"],
        ranked[0]["estimated_reward"]
    );
    assert!(ranked[0]["selection_score_ucb_exploration_bonus"]
        .as_f64()
        .is_some());
    assert_eq!(
        ranked[0]["selection_score_probe_bias_component"],
        serde_json::json!(0.0)
    );
    assert_eq!(success["fields"]["strategy"], "passthrough");

    target_thread.join().expect("join runtime-only thread");
}

#[test]
fn direct_explicit_absence_seeded_observation_keeps_planner_explainability_honest() {
    let td = TestDir::new("direct-explicit-absence-planner");
    let events_path = td.path().join("events.jsonl");
    let cfg_path = td.path().join("direct-explicit-absence-planner.toml");
    let state_path = td.path().join("state.json");

    let target_listener = TcpListener::bind("127.0.0.1:0").expect("target bind");
    let target_addr = target_listener.local_addr().expect("target addr");
    let key_hash = loopback_direct_key(target_addr.port()).hash_key();
    let mut passthrough = StrategyStatsV2::default();
    passthrough.record(&FailSignal::Success, Some(10), 2048);
    passthrough.record(&FailSignal::Success, Some(12), 2048);
    let mut ttl_desync = StrategyStatsV2::default();
    ttl_desync.record(&FailSignal::Timeout, None, 0);
    ttl_desync.record(&FailSignal::Unknown, None, 0);
    write_seeded_state_with_strategy_stats(
        &state_path,
        target_addr.port(),
        StallProbeStats {
            trials: 1,
            collapses: 1,
            consecutive_stall_failures: 1,
            last_signal: Some(FailSignal::ThroughputCollapse),
            ..StallProbeStats::default()
        },
        explicit_absence_seeded_observation(),
        HashMap::from([
            (format!("{key_hash}|passthrough"), passthrough),
            (format!("{key_hash}|ttl_desync"), ttl_desync),
        ]),
    );
    let target_thread = thread::spawn(move || {
        let (mut conn, _) = target_listener.accept().expect("accept target");
        let mut request = [0u8; 4096];
        let n = conn.read(&mut request).expect("read request");
        assert!(
            request[..n].starts_with(b"GET /explicit-absence HTTP/1.0"),
            "unexpected request"
        );
        conn.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 15\r\n\r\nexplicit-absent")
            .expect("write response");
        let _ = conn.shutdown(Shutdown::Both);
    });

    let socks_port = reserve_tcp_port();
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
persist_state = true
state_path = "{}"
strategies = ["passthrough", "ttl_desync"]
epsilon = 0.0
first_chunk_timeout_ms = 500
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false

[relay]
server = ""
server_name = ""
auth_token = ""
"#,
            common::toml_path(&state_path),
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let mut socks = wait_for_port(socks_port, Duration::from_secs(20));
    socks_handshake(&mut socks, target_addr);
    socks
        .write_all(b"GET /explicit-absence HTTP/1.0\r\n\r\n")
        .expect("write request");
    let mut response = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline
        && !response
            .windows(15)
            .any(|window| window == b"explicit-absent")
    {
        let mut chunk = [0u8; 4096];
        let n = socks.read(&mut chunk).expect("read response");
        if n == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..n]);
    }
    assert!(
        response
            .windows(15)
            .any(|window| window == b"explicit-absent"),
        "missing explicit-absence payload"
    );
    drop(socks);

    let (planner, _records) = wait_for_event(
        &events_path,
        "direct_planner_order_selected",
        Duration::from_secs(10),
    );
    let (success, _) = wait_for_event(
        &events_path,
        "direct_session_succeeded",
        Duration::from_secs(10),
    );

    assert_planner_explainability_contract(
        &planner,
        "brain_reward_loop",
        "state_snapshot_contextual_reward",
        "advisory_state_snapshot_observation",
    );
    assert_planner_top_candidate_reason_matches_candidate(&planner);
    assert_planner_delta_baseline(&planner);
    assert_eq!(
        planner["fields"]["planner_order_resolution"],
        "reward_loop_only"
    );
    assert_eq!(
        planner["fields"]["planner_post_brain_reorder_applied"],
        false
    );
    assert_eq!(
        planner["fields"]["planner_reward_loop_order_preserved"],
        true
    );
    assert_eq!(planner["fields"]["planner_lua_order_configured"], false);
    assert_eq!(planner["fields"]["planner_lua_order_applied"], false);
    assert_eq!(
        planner["fields"]["planner_advisory_reorder_requested"],
        false
    );
    assert_eq!(planner["fields"]["planner_advisory_reorder_applied"], false);
    assert_eq!(
        planner["fields"]["observation_contract"],
        "explicit_absence"
    );
    assert_eq!(
        planner["fields"]["observation_capture_confidence"],
        "explicit_absence"
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_signal_origin"],
        "advisory_latest_observation"
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_observation_capture_confidence"],
        "explicit_absence"
    );
    assert_eq!(
        planner["fields"]["mimicry_capability_readiness"],
        "runtime_only_baseline"
    );
    assert_eq!(
        success["fields"]["mimicry_capability_signal_origin"],
        "live_runtime_observation"
    );
    assert_eq!(
        success["fields"]["mimicry_capability_observation_capture_confidence"],
        "explicit_absence"
    );
    assert_direct_path_health_contract(&success, "healthy", "successful_direct_path");

    target_thread.join().expect("join explicit-absence thread");
}

#[test]
fn direct_advisory_without_relay_transports_runtime_jsonl_e2e() {
    let td = TestDir::new("direct-advisory-no-relay");
    let events_path = td.path().join("events.jsonl");
    let cfg_path = td.path().join("direct-advisory-no-relay.toml");
    let state_path = td.path().join("state.json");

    write_seeded_state(
        &state_path,
        443,
        StallProbeStats {
            trials: 3,
            collapses: 2,
            timeouts: 1,
            consecutive_stall_failures: 2,
            last_signal: Some(FailSignal::Timeout),
            ..StallProbeStats::default()
        },
    );

    let socks_port = reserve_tcp_port();
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
persist_state = true
state_path = "{}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false

[relay]
server = "127.0.0.1:1"
server_name = "localhost"
auth_token = "{TEST_RELAY_AUTH_TOKEN}"
connect_timeout_ms = 3000
transport_priority = []
"#,
            common::toml_path(&state_path),
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let mut socks = wait_for_port(socks_port, Duration::from_secs(20));
    socks_handshake(&mut socks, "127.0.0.1:443".parse().expect("target addr"));
    socks
        .write_all(b"GET / HTTP/1.0\r\n\r\n")
        .expect("write request");
    drop(socks);

    let (session_fail, records) = wait_for_event(
        &events_path,
        "ingress_session_failed",
        Duration::from_secs(10),
    );
    let codes = event_codes(&records);
    assert!(
        !codes.contains(&"direct_relay_preferred_from_probe_history"),
        "{records:?}"
    );
    assert!(!codes.contains(&"relay_transport_failed"), "{records:?}");

    assert_eq!(session_fail["fields"]["ingress_kind"], "Socks5Fallback");
    assert_eq!(session_fail["fields"]["session_kind"], "Socks5Fallback");
    assert_eq!(session_fail["fields"]["backend"], "socks5_fallback");
    assert_eq!(session_fail["fields"]["mode"], "Direct");
    assert_eq!(session_fail["fields"]["relay_terminal"], false);
    assert!(session_fail["fields"]["relay_planned_transports"].is_null());
    assert_eq!(session_fail["fields"]["direct_relay_handoff"], false);
    assert!(session_fail["fields"]["direct_relay_handoff_path"].is_null());
    assert!(session_fail["fields"]["error"]
        .as_str()
        .expect("session error")
        .starts_with("direct_connect_remote:"));
    assert!(!session_fail["fields"]["error"]
        .as_str()
        .expect("session error")
        .contains("no transport configured"));
}

#[test]
fn direct_first_response_eof_runtime_jsonl_e2e() {
    let td = TestDir::new("direct-first-response-eof");
    let events_path = td.path().join("events.jsonl");
    let cfg_path = td.path().join("direct-first-response-eof.toml");
    // Own state file: these used to point at the operator's real
    // ~/.cache/aegis/state.json, which the client cannot decrypt (its key is
    // bound to the real install), so it refused to start and the test failed
    // with an unexplained "socks listener did not start". A test must never
    // read — or be able to overwrite — a developer's live state.
    let state_path = td.path().join("state.json");
    let state_path = common::toml_path(&state_path);

    let server = TcpListener::bind("127.0.0.1:0").expect("target bind");
    let target_addr = server.local_addr().expect("target addr");
    let accepted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let accepted_flag = accepted.clone();
    let target_thread = thread::spawn(move || {
        let (mut conn, _) = server.accept().expect("accept target");
        accepted_flag.store(true, std::sync::atomic::Ordering::SeqCst);
        let mut buf = [0u8; 4096];
        let _ = conn.read(&mut buf).expect("read request");
        conn.shutdown(Shutdown::Write).expect("shutdown write");
    });

    let socks_port = reserve_tcp_port();
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
state_path = "{state_path}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);
    let _ = wait_for_event(
        &events_path,
        "ingress_backend_started",
        Duration::from_secs(10),
    );

    let mut socks = wait_for_port(socks_port, Duration::from_secs(20));
    socks_handshake(&mut socks, target_addr);
    socks
        .write_all(b"GET / HTTP/1.0\r\n\r\n")
        .expect("write request");
    drop(socks);

    let (session_fail, records) = wait_for_event(
        &events_path,
        "ingress_session_failed",
        Duration::from_secs(10),
    );
    let codes = event_codes(&records);
    assert!(
        accepted.load(std::sync::atomic::Ordering::SeqCst),
        "{records:?}"
    );
    assert!(
        !codes.contains(&"direct_relay_failover_triggered"),
        "{records:?}"
    );
    assert!(!codes.contains(&"relay_transport_failed"), "{records:?}");
    assert_eq!(session_fail["fields"]["backend"], "socks5_fallback");
    assert_eq!(session_fail["fields"]["backend_kind"], "Socks5Fallback");
    assert_eq!(session_fail["fields"]["requested_primary"], "Socks5");
    assert_eq!(session_fail["fields"]["mode"], "Direct");
    assert_eq!(session_fail["fields"]["relay_terminal"], false);
    assert_eq!(session_fail["fields"]["direct_relay_handoff"], false);
    assert!(session_fail["fields"]["error"]
        .as_str()
        .expect("session error")
        .starts_with("direct_first_response_eof:"));

    assert_socks_listener_healthy(socks_port);
    target_thread.join().expect("join target thread");
}

#[test]
fn direct_eof_before_first_chunk_runtime_jsonl_e2e() {
    let td = TestDir::new("direct-eof");
    let events_path = td.path().join("events.jsonl");
    let cfg_path = td.path().join("direct-eof.toml");
    // Own state file: these used to point at the operator's real
    // ~/.cache/aegis/state.json, which the client cannot decrypt (its key is
    // bound to the real install), so it refused to start and the test failed
    // with an unexplained "socks listener did not start". A test must never
    // read — or be able to overwrite — a developer's live state.
    let state_path = td.path().join("state.json");
    let state_path = common::toml_path(&state_path);

    let target = TcpListener::bind("127.0.0.1:0").expect("target bind");
    target
        .set_nonblocking(true)
        .expect("set target nonblocking");
    let target_addr = target.local_addr().expect("target addr");

    let socks_port = reserve_tcp_port();
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
state_path = "{state_path}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);
    let _ = wait_for_event(
        &events_path,
        "ingress_backend_started",
        Duration::from_secs(10),
    );

    let mut socks = wait_for_port(socks_port, Duration::from_secs(20));
    socks_handshake(&mut socks, target_addr);
    drop(socks);

    thread::sleep(Duration::from_millis(500));
    match target.accept() {
        Ok(_) => panic!("target unexpectedly received an outbound direct connection"),
        Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock),
    }

    let records = read_jsonl_records(&events_path).unwrap_or_default();
    assert_no_event(&records, "ingress_session_failed");
    assert_socks_listener_healthy(socks_port);
}

#[test]
fn direct_relay_client_reset_runtime_jsonl_e2e() {
    let td = TestDir::new("direct-relay-client-reset");
    let events_path = td.path().join("events.jsonl");
    let cfg_path = td.path().join("direct-relay-client-reset.toml");
    // Own state file: these used to point at the operator's real
    // ~/.cache/aegis/state.json, which the client cannot decrypt (its key is
    // bound to the real install), so it refused to start and the test failed
    // with an unexplained "socks listener did not start". A test must never
    // read — or be able to overwrite — a developer's live state.
    let state_path = td.path().join("state.json");
    let state_path = common::toml_path(&state_path);

    let server = TcpListener::bind("127.0.0.1:0").expect("target bind");
    let target_addr = server.local_addr().expect("target addr");
    let accepted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let accepted_flag = accepted.clone();
    let target_thread = thread::spawn(move || {
        let (mut conn, _) = server.accept().expect("accept target");
        accepted_flag.store(true, std::sync::atomic::Ordering::SeqCst);
        let mut buf = [0u8; 4096];
        let _ = conn.read(&mut buf).expect("read request");
        conn.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 8\r\n\r\n")
            .expect("write headers");
        thread::sleep(Duration::from_millis(100));
        let _ = conn.write_all(b"payload!");
    });

    let socks_port = reserve_tcp_port();
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
state_path = "{state_path}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let mut socks = wait_for_port(socks_port, Duration::from_secs(20));
    socks_handshake(&mut socks, target_addr);
    socks
        .write_all(b"GET / HTTP/1.0\r\n\r\n")
        .expect("write request");

    let mut first_chunk = [0u8; 64];
    let n = socks.read(&mut first_chunk).expect("read first response");
    assert!(first_chunk[..n]
        .windows(b"HTTP/1.0 200 OK".len())
        .any(|window| window == b"HTTP/1.0 200 OK"));

    SockRef::from(&socks)
        .set_linger(Some(Duration::from_secs(0)))
        .expect("set linger");
    drop(socks);

    let (session_fail, records) = wait_for_event(
        &events_path,
        "ingress_session_failed",
        Duration::from_secs(10),
    );
    let codes = event_codes(&records);
    assert!(
        accepted.load(std::sync::atomic::Ordering::SeqCst),
        "{records:?}"
    );
    assert_no_event(&records, "direct_relay_failover_triggered");
    assert_no_event(&records, "relay_transport_failed");
    assert_eq!(session_fail["fields"]["backend"], "socks5_fallback");
    assert_eq!(session_fail["fields"]["backend_kind"], "Socks5Fallback");
    assert_eq!(session_fail["fields"]["requested_primary"], "Socks5");
    assert_eq!(session_fail["fields"]["mode"], "Direct");
    assert_eq!(session_fail["fields"]["relay_terminal"], false);
    assert_eq!(session_fail["fields"]["direct_relay_handoff"], false);
    assert!(session_fail["fields"]["error"]
        .as_str()
        .expect("session error")
        .starts_with("direct_relay_client_read:"));

    assert_socks_listener_healthy(socks_port);
    assert!(!codes.is_empty());
    target_thread.join().expect("join target thread");
}

#[test]
fn direct_tls_grease_failure_runtime_jsonl_e2e() {
    let td = TestDir::new("direct-grease-failed");
    let events_path = td.path().join("events.jsonl");
    let cfg_path = td.path().join("direct-grease-failed.toml");
    // Own state file: these used to point at the operator's real
    // ~/.cache/aegis/state.json, which the client cannot decrypt (its key is
    // bound to the real install), so it refused to start and the test failed
    // with an unexplained "socks listener did not start". A test must never
    // read — or be able to overwrite — a developer's live state.
    let state_path = td.path().join("state.json");
    let state_path = common::toml_path(&state_path);

    let target = TcpListener::bind("127.0.0.1:0").expect("target bind");
    target
        .set_nonblocking(true)
        .expect("set target nonblocking");
    let target_addr = target.local_addr().expect("target addr");

    let socks_port = reserve_tcp_port();
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
state_path = "{state_path}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = true
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let mut socks = wait_for_port(socks_port, Duration::from_secs(20));
    socks_handshake(&mut socks, target_addr);
    socks
        .write_all(&[22, 3, 3, 0, 6, 1, 0, 0, 2, 3, 3])
        .expect("write malformed tls-like payload");
    drop(socks);

    let (session_fail, _records) = wait_for_event(
        &events_path,
        "ingress_session_failed",
        Duration::from_secs(10),
    );
    assert_eq!(session_fail["fields"]["backend"], "socks5_fallback");
    assert_eq!(session_fail["fields"]["backend_kind"], "Socks5Fallback");
    assert_eq!(session_fail["fields"]["requested_primary"], "Socks5");
    assert_eq!(session_fail["fields"]["mode"], "Direct");
    assert_eq!(
        session_fail["fields"]["wide_supported"],
        serde_json::Value::Null
    );
    assert_eq!(
        session_fail["fields"]["wide_platform_family_supported"],
        serde_json::Value::Null
    );
    assert_eq!(
        session_fail["fields"]["wide_runtime_readiness"],
        serde_json::Value::Null
    );
    assert_eq!(session_fail["fields"]["relay_terminal"], false);
    assert_eq!(session_fail["fields"]["direct_relay_handoff"], false);
    assert!(session_fail["fields"]["error"]
        .as_str()
        .expect("session error")
        .starts_with("direct_tls_grease:"));

    match target.accept() {
        Ok(_) => panic!("target unexpectedly received outbound direct connection"),
        Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock),
    }

    assert_socks_listener_healthy(socks_port);
}

#[cfg(all(target_os = "linux", feature = "raw-socket"))]
#[test]
fn direct_active_stall_probe_retry_budget_runtime_jsonl_e2e() {
    let caps = aegis_core::default_raw_engine().capabilities();
    if !caps.ipv4_packet_capture {
        // This e2e exercises the real packet-observation gate and only makes
        // sense on a Linux runtime with CAP_NET_RAW available to the process.
        eprintln!("skipping active stall probe e2e without ipv4 packet capture capability");
        return;
    }

    let td = TestDir::new("direct-active-stall-probe");
    let events_path = td.path().join("events.jsonl");
    let cfg_path = td.path().join("direct-active-stall-probe.toml");

    let target_listener = TcpListener::bind("127.0.0.1:0").expect("target bind");
    let target_addr = target_listener.local_addr().expect("target addr");
    let target_thread = thread::spawn(move || {
        for attempt in 0..5 {
            let (mut conn, _) = target_listener.accept().expect("accept target");
            let mut request = [0u8; 4096];
            let n = conn.read(&mut request).expect("read request");
            assert!(
                request[..n].starts_with(b"GET / HTTP/1.0"),
                "unexpected request"
            );
            if attempt % 2 == 0 {
                thread::sleep(Duration::from_secs(1));
            } else {
                conn.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 6\r\n\r\nprobe!")
                    .expect("write probe response");
            }
        }
    });

    let socks_port = reserve_tcp_port();
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 300
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false

[relay]
server = "127.0.0.1:1"
server_name = "localhost"
auth_token = "{TEST_RELAY_AUTH_TOKEN}"
connect_timeout_ms = 3000
transport_priority = ["legacy_tls"]
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let mut socks = wait_for_port(socks_port, Duration::from_secs(20));
    socks_handshake(&mut socks, target_addr);
    socks
        .write_all(b"GET / HTTP/1.0\r\n\r\n")
        .expect("write request");
    drop(socks);

    let launched = wait_for_event_count(
        &events_path,
        "direct_active_stall_probe_launched",
        2,
        Duration::from_secs(20),
    );
    assert_eq!(launched.len(), 2);
    for record in &launched {
        assert_eq!(
            record["fields"]["mimicry_capability_signal_origin"],
            "live_runtime_observation"
        );
        assert_direct_path_health_contract(record, "unstable", "active_probe_in_flight");
        assert_userspace_contract(
            record,
            "profile_plus_capture_backed_ttl",
            Some("linux"),
            Some(false),
            Some(true),
        );
        assert_eq!(
            record["fields"]["mimicry_capability_userspace_ttl_hint_ready"],
            true
        );
        assert!(record["fields"]["mimicry_capability_userspace_ttl_hint"]
            .as_u64()
            .is_some());
    }

    let finished = wait_for_event_count(
        &events_path,
        "direct_active_stall_probe_finished",
        2,
        Duration::from_secs(20),
    );
    assert_eq!(finished.len(), 2);
    for record in &finished {
        assert_eq!(record["fields"]["probe_outcome_class"], "success");
        assert_direct_path_health_contract(record, "degraded", "active_probe_recovered_path");
        assert_eq!(
            record["fields"]["mimicry_capability_signal_origin"],
            "live_active_probe_observation"
        );
        assert_userspace_contract(
            record,
            "profile_plus_capture_backed_ttl",
            Some("linux"),
            Some(false),
            Some(true),
        );
        assert_eq!(
            record["fields"]["mimicry_capability_userspace_ttl_hint_ready"],
            true
        );
        assert!(record["fields"]["mimicry_capability_userspace_ttl_hint"]
            .as_u64()
            .is_some());
        assert_eq!(
            record["fields"]["probe_terminal_stage"],
            serde_json::Value::Null
        );
        assert!(
            record["fields"]["first_response_bytes"]
                .as_u64()
                .unwrap_or(0)
                > 0
        );
        assert_eq!(record["fields"]["capture_status"], "Active");
    }

    let retry_selected = wait_for_event_count(
        &events_path,
        "direct_active_stall_probe_retry_selected",
        2,
        Duration::from_secs(20),
    );
    assert_eq!(retry_selected.len(), 2);
    for record in &retry_selected {
        assert_eq!(record["fields"]["signal"], "Success");
        assert_eq!(record["fields"]["probe_outcome_class"], "success");
        assert_direct_path_health_contract(record, "degraded", "active_probe_recovered_path");
        assert_eq!(
            record["fields"]["cross_session_signal_bias"],
            "neutral_advisory_bias"
        );
        assert_eq!(
            record["fields"]["mimicry_capability_signal_origin"],
            "live_active_probe_observation"
        );
        assert_eq!(
            record["fields"]["mimicry_capability_userspace_scope"],
            "pre_connect_socket_only"
        );
        assert_eq!(
            record["fields"]["observation_capture_confidence"],
            "deep_observed"
        );
        assert_userspace_contract(
            record,
            "profile_plus_capture_backed_ttl",
            Some("linux"),
            Some(false),
            Some(true),
        );
        assert_eq!(
            record["fields"]["mimicry_capability_userspace_ttl_hint_ready"],
            true
        );
        assert!(record["fields"]["mimicry_capability_userspace_ttl_hint"]
            .as_u64()
            .is_some());
        assert_eq!(
            record["fields"]["probe_terminal_stage"],
            serde_json::Value::Null
        );
    }

    let planner_records = wait_for_event_count(
        &events_path,
        "direct_planner_order_selected",
        3,
        Duration::from_secs(20),
    );
    assert_eq!(planner_records.len(), 3);
    assert_eq!(
        planner_records[0]["fields"]["planner_selection_stage"],
        "initial_session_order"
    );
    assert_eq!(planner_records[0]["fields"]["planner_retry_attempt"], 0);
    assert_eq!(
        planner_records[0]["fields"]["planner_has_previous_selection"],
        false
    );
    assert_eq!(
        planner_records[0]["fields"]["planner_previous_reward_selected_order"],
        serde_json::Value::Null
    );
    assert_eq!(
        planner_records[0]["fields"]["planner_previous_resolved_order"],
        serde_json::Value::Null
    );
    assert_eq!(
        planner_records[0]["fields"]["planner_reward_selected_order_changed"],
        false
    );
    assert_eq!(
        planner_records[0]["fields"]["planner_resolved_order_changed"],
        false
    );
    assert_planner_delta_baseline(&planner_records[0]);
    assert_eq!(
        planner_records[1]["fields"]["planner_selection_stage"],
        "post_probe_retry_reselect"
    );
    assert_eq!(planner_records[1]["fields"]["planner_retry_attempt"], 1);
    assert_eq!(
        planner_records[1]["fields"]["planner_has_previous_selection"],
        true
    );
    assert_eq!(
        planner_records[1]["fields"]["planner_previous_reward_selected_order"],
        serde_json::json!(["passthrough"])
    );
    assert_eq!(
        planner_records[1]["fields"]["planner_previous_resolved_order"],
        serde_json::json!(["passthrough"])
    );
    assert_eq!(
        planner_records[1]["fields"]["planner_reward_selected_order_changed"],
        false
    );
    assert_eq!(
        planner_records[1]["fields"]["planner_resolved_order_changed"],
        false
    );
    assert_eq!(
        planner_records[1]["fields"]["planner_previous_order_resolution"],
        "reward_loop_only"
    );
    assert_eq!(
        planner_records[1]["fields"]["planner_order_resolution_changed"],
        false
    );
    assert_eq!(
        planner_records[1]["fields"]["planner_previous_resolved_order_primary_reason"],
        "reward_loop_preserved"
    );
    assert_eq!(
        planner_records[1]["fields"]["planner_resolved_order_primary_reason_changed"],
        false
    );
    assert_eq!(
        planner_records[1]["fields"]["planner_previous_post_brain_reorder_applied"],
        false
    );
    assert_eq!(
        planner_records[1]["fields"]["planner_post_brain_reorder_path_changed"],
        false
    );
    assert_eq!(
        planner_records[1]["fields"]["planner_previous_lua_order_applied"],
        false
    );
    assert_eq!(
        planner_records[1]["fields"]["planner_lua_order_applied_changed"],
        false
    );
    assert_eq!(
        planner_records[1]["fields"]["planner_previous_advisory_reorder_applied"],
        false
    );
    assert_eq!(
        planner_records[1]["fields"]["planner_advisory_reorder_applied_changed"],
        false
    );
    assert_eq!(
        planner_records[1]["fields"]["planner_previous_top_candidate_primary_reason"],
        planner_records[1]["fields"]["planner_top_candidate_primary_reason"]
    );
    assert_eq!(
        planner_records[1]["fields"]["planner_top_candidate_primary_reason_changed"],
        false
    );
    assert_eq!(
        planner_records[1]["fields"]["planner_previous_top_candidate_dominant_component"],
        planner_records[1]["fields"]["planner_top_candidate_dominant_component"]
    );
    assert_eq!(
        planner_records[1]["fields"]["planner_top_candidate_dominant_component_changed"],
        false
    );
    let retry_ranked = planner_records[1]["fields"]["planner_ranked_candidates"]
        .as_array()
        .expect("retry ranked candidates");
    assert_eq!(retry_ranked.len(), 1);
    assert_eq!(retry_ranked[0]["strategy"], "passthrough");
    assert_eq!(retry_ranked[0]["rank"], 0);
    assert_eq!(retry_ranked[0]["has_previous_candidate_trace"], true);
    assert_eq!(retry_ranked[0]["previous_rank"], 0);
    assert_eq!(retry_ranked[0]["rank_delta"], 0);
    assert!(retry_ranked[0]["previous_estimated_reward"]
        .as_f64()
        .is_some());
    assert!(retry_ranked[0]["estimated_reward_delta"].as_f64().is_some());
    assert!(retry_ranked[0]["previous_estimated_trials"]
        .as_f64()
        .is_some());
    assert!(retry_ranked[0]["estimated_trials_delta"].as_f64().is_some());
    assert!(retry_ranked[0]["previous_total_trials"].as_f64().is_some());
    assert!(retry_ranked[0]["total_trials_delta"].as_f64().is_some());
    assert!(retry_ranked[0]["previous_probe_history_strategy_bias"]
        .as_f64()
        .is_some());
    assert!(retry_ranked[0]["probe_history_strategy_bias_delta"]
        .as_f64()
        .is_some());
    assert!(retry_ranked[0]["previous_selection_score"]
        .as_f64()
        .is_some());
    assert!(retry_ranked[0]["selection_score_delta"].as_f64().is_some());
    assert!(retry_ranked[0]["previous_selection_score_reward_component"]
        .as_f64()
        .is_some());
    assert!(retry_ranked[0]["selection_score_reward_component_delta"]
        .as_f64()
        .is_some());
    assert!(
        retry_ranked[0]["previous_selection_score_ucb_exploration_bonus"]
            .as_f64()
            .is_some()
    );
    assert!(
        retry_ranked[0]["selection_score_ucb_exploration_bonus_delta"]
            .as_f64()
            .is_some()
    );
    assert!(
        retry_ranked[0]["previous_selection_score_probe_bias_component"]
            .as_f64()
            .is_some()
    );
    assert!(
        retry_ranked[0]["selection_score_probe_bias_component_delta"]
            .as_f64()
            .is_some()
    );
    assert_eq!(
        planner_records[2]["fields"]["planner_selection_stage"],
        "post_probe_retry_reselect"
    );
    assert_eq!(planner_records[2]["fields"]["planner_retry_attempt"], 2);
    assert_eq!(
        planner_records[2]["fields"]["planner_has_previous_selection"],
        true
    );
    assert_eq!(
        planner_records[2]["fields"]["planner_previous_reward_selected_order"],
        serde_json::json!(["passthrough"])
    );
    assert_eq!(
        planner_records[2]["fields"]["planner_previous_resolved_order"],
        serde_json::json!(["passthrough"])
    );
    assert_eq!(
        planner_records[2]["fields"]["planner_reward_selected_order_changed"],
        false
    );
    assert_eq!(
        planner_records[2]["fields"]["planner_resolved_order_changed"],
        false
    );
    assert_eq!(
        planner_records[2]["fields"]["planner_previous_order_resolution"],
        "reward_loop_only"
    );
    assert_eq!(
        planner_records[2]["fields"]["planner_order_resolution_changed"],
        false
    );
    assert_eq!(
        planner_records[2]["fields"]["planner_previous_resolved_order_primary_reason"],
        "reward_loop_preserved"
    );
    assert_eq!(
        planner_records[2]["fields"]["planner_resolved_order_primary_reason_changed"],
        false
    );
    assert_eq!(
        planner_records[2]["fields"]["planner_previous_post_brain_reorder_applied"],
        false
    );
    assert_eq!(
        planner_records[2]["fields"]["planner_post_brain_reorder_path_changed"],
        false
    );
    assert_eq!(
        planner_records[2]["fields"]["planner_previous_lua_order_applied"],
        false
    );
    assert_eq!(
        planner_records[2]["fields"]["planner_lua_order_applied_changed"],
        false
    );
    assert_eq!(
        planner_records[2]["fields"]["planner_previous_advisory_reorder_applied"],
        false
    );
    assert_eq!(
        planner_records[2]["fields"]["planner_advisory_reorder_applied_changed"],
        false
    );
    assert_eq!(
        planner_records[2]["fields"]["planner_previous_top_candidate_primary_reason"],
        planner_records[2]["fields"]["planner_top_candidate_primary_reason"]
    );
    assert_eq!(
        planner_records[2]["fields"]["planner_top_candidate_primary_reason_changed"],
        false
    );
    assert_eq!(
        planner_records[2]["fields"]["planner_previous_top_candidate_dominant_component"],
        planner_records[2]["fields"]["planner_top_candidate_dominant_component"]
    );
    assert_eq!(
        planner_records[2]["fields"]["planner_top_candidate_dominant_component_changed"],
        false
    );
    let retry_ranked = planner_records[2]["fields"]["planner_ranked_candidates"]
        .as_array()
        .expect("retry ranked candidates");
    assert_eq!(retry_ranked.len(), 1);
    assert_eq!(retry_ranked[0]["strategy"], "passthrough");
    assert_eq!(retry_ranked[0]["rank"], 0);
    assert_eq!(retry_ranked[0]["has_previous_candidate_trace"], true);
    assert_eq!(retry_ranked[0]["previous_rank"], 0);
    assert_eq!(retry_ranked[0]["rank_delta"], 0);
    assert!(retry_ranked[0]["previous_estimated_reward"]
        .as_f64()
        .is_some());
    assert!(retry_ranked[0]["estimated_reward_delta"].as_f64().is_some());
    assert!(retry_ranked[0]["previous_estimated_trials"]
        .as_f64()
        .is_some());
    assert!(retry_ranked[0]["estimated_trials_delta"].as_f64().is_some());
    assert!(retry_ranked[0]["previous_total_trials"].as_f64().is_some());
    assert!(retry_ranked[0]["total_trials_delta"].as_f64().is_some());
    assert!(retry_ranked[0]["previous_probe_history_strategy_bias"]
        .as_f64()
        .is_some());
    assert!(retry_ranked[0]["probe_history_strategy_bias_delta"]
        .as_f64()
        .is_some());
    assert!(retry_ranked[0]["previous_selection_score"]
        .as_f64()
        .is_some());
    assert!(retry_ranked[0]["selection_score_delta"].as_f64().is_some());
    assert!(retry_ranked[0]["previous_selection_score_reward_component"]
        .as_f64()
        .is_some());
    assert!(retry_ranked[0]["selection_score_reward_component_delta"]
        .as_f64()
        .is_some());
    assert!(
        retry_ranked[0]["previous_selection_score_ucb_exploration_bonus"]
            .as_f64()
            .is_some()
    );
    assert!(
        retry_ranked[0]["selection_score_ucb_exploration_bonus_delta"]
            .as_f64()
            .is_some()
    );
    assert!(
        retry_ranked[0]["previous_selection_score_probe_bias_component"]
            .as_f64()
            .is_some()
    );
    assert!(
        retry_ranked[0]["selection_score_probe_bias_component_delta"]
            .as_f64()
            .is_some()
    );

    let (budget_exhausted, records) = wait_for_event(
        &events_path,
        "direct_active_stall_probe_retry_budget_exhausted",
        Duration::from_secs(20),
    );
    let codes = event_codes(&records);
    assert!(
        codes.contains(&"direct_relay_failover_triggered"),
        "{records:?}"
    );
    assert!(codes.contains(&"relay_transport_failed"), "{records:?}");
    assert!(codes.contains(&"ingress_session_failed"), "{records:?}");

    assert_eq!(budget_exhausted["fields"]["retry_attempts_used"], 2);
    assert_eq!(budget_exhausted["fields"]["retry_attempts_budget"], 2);
    assert_eq!(
        budget_exhausted["fields"]["probe_terminal_stage"],
        serde_json::Value::Null
    );
    assert_eq!(
        budget_exhausted["fields"]["observation_capture_confidence"],
        "deep_observed"
    );
    assert_eq!(
        budget_exhausted["fields"]["mimicry_capability_signal_origin"],
        "live_runtime_observation"
    );
    assert_direct_path_health_contract(
        &budget_exhausted,
        "unstable",
        "probe_retry_budget_exhausted",
    );
    assert_terminal_health_summary(&budget_exhausted, true);
    assert_userspace_contract(
        &budget_exhausted,
        "profile_plus_capture_backed_ttl",
        Some("linux"),
        Some(false),
        Some(true),
    );
    assert_eq!(
        budget_exhausted["fields"]["mimicry_capability_userspace_ttl_hint_ready"],
        true
    );
    assert!(
        budget_exhausted["fields"]["mimicry_capability_userspace_ttl_hint"]
            .as_u64()
            .is_some()
    );
    assert_eq!(
        budget_exhausted["fields"]["probe_history_disposition"],
        "none"
    );
    assert_eq!(
        budget_exhausted["fields"]["probe_history_reason_code"],
        "no_recent_probe_history"
    );
    assert_eq!(
        budget_exhausted["fields"]["cross_session_signal_bias"],
        "neutral_advisory_bias"
    );
    assert_eq!(budget_exhausted["fields"]["target"], "127.0.0.1");
    assert_eq!(budget_exhausted["fields"]["port"], target_addr.port());

    let failover = records
        .iter()
        .find(|record| record["event_code"] == "direct_relay_failover_triggered")
        .expect("failover event");
    assert_eq!(
        failover["fields"]["direct_relay_failover_reason_code"],
        "probe_retry_budget_exhausted"
    );
    assert_eq!(
        failover["fields"]["observation_capture_confidence"],
        "deep_observed"
    );
    assert_eq!(
        failover["fields"]["mimicry_capability_signal_origin"],
        "live_runtime_observation"
    );
    assert_direct_path_health_contract(failover, "unstable", "direct_relay_failover_triggered");
    assert_terminal_health_summary(failover, true);
    assert_userspace_contract(
        failover,
        "profile_plus_capture_backed_ttl",
        Some("linux"),
        Some(false),
        Some(true),
    );
    assert_eq!(
        failover["fields"]["mimicry_capability_userspace_ttl_hint_ready"],
        true
    );
    assert!(failover["fields"]["mimicry_capability_userspace_ttl_hint"]
        .as_u64()
        .is_some());
    assert_eq!(failover["fields"]["probe_history_disposition"], "none");
    assert_eq!(
        failover["fields"]["probe_history_reason_code"],
        "no_recent_probe_history"
    );
    assert_eq!(
        failover["fields"]["cross_session_signal_bias"],
        "neutral_advisory_bias"
    );
    assert_eq!(failover["fields"]["active_stall_probe_recommended"], true);
    assert_eq!(
        failover["fields"]["active_stall_probe_retry_attempted"],
        true
    );
    assert_eq!(
        failover["fields"]["probe_terminal_stage"],
        serde_json::Value::Null
    );

    let session_fail = records
        .iter()
        .find(|record| record["event_code"] == "ingress_session_failed")
        .expect("session failure");
    assert_eq!(session_fail["fields"]["direct_relay_handoff"], true);
    assert_eq!(
        session_fail["fields"]["direct_relay_handoff_path"],
        "runtime_failover"
    );
    assert_eq!(
        session_fail["fields"]["direct_relay_handoff_reason_code"],
        "probe_retry_budget_exhausted"
    );
    assert_eq!(
        session_fail["fields"]["direct_relay_handoff_retry_attempted"],
        true
    );

    target_thread.join().expect("join target thread");
}

#[cfg(all(target_os = "linux", feature = "raw-socket"))]
#[test]
fn direct_active_stall_probe_retry_skipped_runtime_jsonl_e2e() {
    let caps = aegis_core::default_raw_engine().capabilities();
    if !caps.ipv4_packet_capture {
        eprintln!(
            "skipping active stall probe retry-skipped e2e without ipv4 packet capture capability"
        );
        return;
    }

    let td = TestDir::new("direct-active-stall-probe-skipped");
    let events_path = td.path().join("events.jsonl");
    let cfg_path = td.path().join("direct-active-stall-probe-skipped.toml");

    let target_listener = TcpListener::bind("127.0.0.1:0").expect("target bind");
    let target_addr = target_listener.local_addr().expect("target addr");
    let target_thread = thread::spawn(move || {
        for _ in 0..2 {
            let (mut conn, _) = target_listener.accept().expect("accept target");
            let mut request = [0u8; 4096];
            let n = conn.read(&mut request).expect("read request");
            assert!(
                request[..n].starts_with(b"GET / HTTP/1.0"),
                "unexpected request"
            );
            thread::sleep(Duration::from_secs(1));
            drop(conn);
        }
    });

    let socks_port = reserve_tcp_port();
    let stack_profile_line = stack_profile_config_line(Some("linux"));
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 300
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
{stack_profile_line}

[relay]
server = "127.0.0.1:1"
server_name = "localhost"
auth_token = "{TEST_RELAY_AUTH_TOKEN}"
connect_timeout_ms = 3000
transport_priority = ["legacy_tls"]
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let mut socks = wait_for_port(socks_port, Duration::from_secs(20));
    socks_handshake(&mut socks, target_addr);
    socks
        .write_all(b"GET / HTTP/1.0\r\n\r\n")
        .expect("write request");
    drop(socks);

    let (retry_skipped, records) = wait_for_event(
        &events_path,
        "direct_active_stall_probe_retry_skipped",
        Duration::from_secs(20),
    );
    let codes = event_codes(&records);
    assert!(
        codes.contains(&"direct_active_stall_probe_finished"),
        "{records:?}"
    );
    assert!(
        codes.contains(&"direct_relay_failover_triggered"),
        "{records:?}"
    );
    assert!(codes.contains(&"relay_transport_failed"), "{records:?}");
    assert!(codes.contains(&"ingress_session_failed"), "{records:?}");

    assert_eq!(
        retry_skipped["fields"]["retry_suppressed_reason_code"],
        "probe_signal_not_successful"
    );
    assert_eq!(retry_skipped["fields"]["target"], "127.0.0.1");
    assert_eq!(retry_skipped["fields"]["port"], target_addr.port());
    assert_eq!(
        retry_skipped["fields"]["observation_capture_confidence"],
        "deep_observed"
    );
    assert!(retry_skipped["fields"]["cross_session_confidence_score"]
        .as_f64()
        .is_some());
    assert!(retry_skipped["fields"]["cross_session_reuse_weight"]
        .as_f64()
        .is_some());
    assert!(retry_skipped["fields"]["mimicry_capability_readiness"]
        .as_str()
        .is_some());
    assert_eq!(
        retry_skipped["fields"]["mimicry_capability_stage"],
        "early_pre_wire_capability_layer"
    );
    assert_eq!(
        retry_skipped["fields"]["mimicry_capability_signal_origin"],
        "live_active_probe_observation"
    );
    assert_direct_path_health_contract(&retry_skipped, "unstable", "probe_retry_suppressed");
    assert_terminal_health_summary(&retry_skipped, false);
    assert_userspace_contract(
        &retry_skipped,
        "profile_plus_capture_backed_ttl",
        Some("linux"),
        Some(false),
        Some(true),
    );
    assert_eq!(
        retry_skipped["fields"]["mimicry_capability_userspace_ttl_hint_ready"],
        true
    );
    assert!(
        retry_skipped["fields"]["mimicry_capability_userspace_ttl_hint"]
            .as_u64()
            .is_some()
    );
    assert_eq!(
        retry_skipped["fields"]["cross_session_signal_bias"],
        "neutral_advisory_bias"
    );
    assert!(retry_skipped["fields"]["mimicry_capability_server_hint"]
        .as_str()
        .is_some());
    assert!(retry_skipped["fields"]["mimicry_capability_window_profile"]
        .as_str()
        .is_some());
    assert!(
        retry_skipped["fields"]["mimicry_capability_reference_path_hops"]
            .as_u64()
            .is_some()
    );
    let outcome_class = retry_skipped["fields"]["probe_outcome_class"]
        .as_str()
        .expect("retry skipped outcome class");
    assert!(
        matches!(
            outcome_class,
            "session_freeze" | "throughput_collapse" | "timeout"
        ),
        "{records:?}"
    );

    let failover = records
        .iter()
        .find(|record| record["event_code"] == "direct_relay_failover_triggered")
        .expect("failover event");
    assert_eq!(
        failover["fields"]["direct_relay_failover_reason_code"],
        "probe_signal_not_successful"
    );
    assert_eq!(
        failover["fields"]["mimicry_capability_signal_origin"],
        "live_runtime_observation"
    );
    assert_direct_path_health_contract(failover, "unstable", "direct_relay_failover_triggered");
    assert_terminal_health_summary(failover, false);
    assert_userspace_contract(
        failover,
        "profile_plus_capture_backed_ttl",
        Some("linux"),
        Some(false),
        Some(true),
    );
    assert_eq!(
        failover["fields"]["mimicry_capability_userspace_ttl_hint_ready"],
        true
    );
    assert!(failover["fields"]["mimicry_capability_userspace_ttl_hint"]
        .as_u64()
        .is_some());
    assert_eq!(failover["fields"]["probe_history_disposition"], "none");
    assert_eq!(
        failover["fields"]["probe_history_reason_code"],
        "no_recent_probe_history"
    );
    assert_eq!(
        failover["fields"]["cross_session_signal_bias"],
        "neutral_advisory_bias"
    );
    assert_eq!(
        failover["fields"]["active_stall_probe_retry_attempted"],
        false
    );

    let session_fail = records
        .iter()
        .find(|record| record["event_code"] == "ingress_session_failed")
        .expect("session failure");
    assert_eq!(session_fail["fields"]["direct_relay_handoff"], true);
    assert_eq!(
        session_fail["fields"]["direct_relay_handoff_reason_code"],
        "probe_signal_not_successful"
    );
    assert_eq!(
        session_fail["fields"]["direct_relay_handoff_retry_attempted"],
        false
    );

    target_thread.join().expect("join target thread");
}

// REGRESSION: handle_direct read sni_hostname_range's (start, LEN) as
// (start, END) and sliced buf[start..end]. For any real ClientHello the SNI
// length is far smaller than its offset, so this panicked with
// "slice index starts at N but ends at M" — and with panic = "abort" that
// killed the whole client on the first HTTPS request through the direct path.
// Found on a live host, not by the test suite, because direct mode had no
// coverage that actually parsed a hello.
#[test]
fn sni_hostname_range_is_start_and_length_not_start_and_end() {
    use aegis_core::protocols::tls::sni_hostname_range;

    // Minimal ClientHello carrying SNI "api.ipify.org" (13 bytes) at an offset
    // well past 13 — the exact shape that used to abort the process.
    let host = b"api.ipify.org";
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes()); // list len
    sni_ext.push(0); // name_type = host_name
    sni_ext.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(host);

    let mut exts = Vec::new();
    exts.extend_from_slice(&0u16.to_be_bytes()); // ext type 0 = SNI
    exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    exts.extend_from_slice(&sni_ext);

    let mut ch = Vec::new();
    ch.extend_from_slice(&[0x03, 0x03]); // legacy_version
    ch.extend_from_slice(&[0u8; 32]); // random
    ch.push(0); // session id len
    ch.extend_from_slice(&2u16.to_be_bytes()); // cipher suites len
    ch.extend_from_slice(&[0x13, 0x01]);
    ch.push(1); // compression methods len
    ch.push(0);
    ch.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    ch.extend_from_slice(&exts);

    let mut hs = vec![0x01]; // handshake type: client_hello
    hs.extend_from_slice(&[
        (ch.len() >> 16) as u8,
        (ch.len() >> 8) as u8,
        ch.len() as u8,
    ]);
    hs.extend_from_slice(&ch);

    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);

    let (start, len) = sni_hostname_range(&rec).expect("sni range");
    assert_eq!(len, host.len(), "second element must be the LENGTH");
    assert!(
        start > len,
        "offset must exceed the length here, or the bug would not reproduce"
    );
    assert_eq!(&rec[start..start + len], host);
    // The old, wrong reading would have been rec[start..len] — an inverted range.
    assert!(rec.get(start..len).is_none(), "start..len must be invalid");
}
