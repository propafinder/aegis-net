use super::planner::ActiveProbePlan;
use aegis_core::ghost_lurk::GhostLurk;
use aegis_core::mimicry::{
    apply_experimental_wire_preface, apply_pre_connect_with_ttl_hint, apply_ttl_hint_only,
    negotiated_wire_options_preface, observed_wire_ipv4_header_shaping_preface,
    resolve_wire_mimicry_runtime, wire_fragment_choreography_plan, wire_options_preface_profile,
    StackProfileId,
};
use aegis_core::signals::classify::{classify_outcome, OutcomeContext};
use aegis_core::{
    default_raw_engine, is_likely_tls_server_hello, ja3s_server_md5_hex, start_packet_observer,
    Brain, DirectTerminalReason, KeyObservation, ObservationContract, ObservedWireChoreographyHint,
    ObservedWireIpv4HeaderShaping, ObservedWireNegotiatedOptions, PacketObservation,
    SendFirstContext, Strategy, StrategyKey, WireMimicryMode,
};
use std::io;
use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::{timeout, Duration};

fn apply_direct_socket_mark(socket: &TcpSocket) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        aegis_core::apply_configured_direct_socket_mark(socket.as_raw_fd())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = socket;
        Ok(())
    }
}

fn stage_strategy_error(stage: &'static str, source: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("{stage}: {source}")
}

fn stage_relay_io_error(stage: &'static str, source: io::Error) -> io::Error {
    io::Error::new(source.kind(), format!("{stage}: {source}"))
}

struct StrategyAttemptError {
    error: anyhow::Error,
    packet: PacketObservation,
    observation: Option<KeyObservation>,
    /// False only while replaying the buffered application payload on a relay
    /// is provably safe. Once `Strategy::send_first` starts, a write error or a
    /// missing response cannot prove the destination did not receive bytes.
    application_payload_may_have_been_sent: bool,
}

pub struct DirectExecution<'a> {
    pub dst: SocketAddr,
    pub key: &'a StrategyKey,
    pub buf: &'a [u8],
    pub sni: Option<(usize, usize)>,
    pub sni_host: Option<&'a str>,
    pub timeout: Duration,
    pub freeze_threshold_bytes: usize,
    pub degraded_latency_ms: u64,
    pub stack: Option<StackProfileId>,
    pub wire_mode: WireMimicryMode,
    pub mimicry_ttl_hint: Option<u32>,
    pub wire_window_preface: Option<u16>,
    pub wire_observation_capture_confidence: &'static str,
    pub wire_window_profile: Option<&'static str>,
    pub wire_observed_ipv4_header_shaping: Option<ObservedWireIpv4HeaderShaping>,
    pub wire_observed_negotiated_options: Option<ObservedWireNegotiatedOptions>,
    pub wire_observed_fragment_choreography: Option<ObservedWireChoreographyHint>,
    pub reference_path_hops: Option<u8>,
    pub ghost: Option<Arc<GhostLurk>>,
    pub ghost_jitter_before_attempt: bool,
    pub empty_plan_reason: DirectTerminalReason,
}

#[derive(Debug, Clone)]
pub struct DirectExecutionError {
    pub signal: aegis_core::signals::classify::FailSignal,
    pub terminal_reason: DirectTerminalReason,
    pub error: String,
    pub observation: KeyObservation,
    pub observation_contract: ObservationContract,
    pub observation_capture_confidence: &'static str,
    pub reference_path_hops: Option<u8>,
    pub rst_path_hops: Option<u8>,
    pub relay_replay_safe: bool,
    pub active_stall_probe_recommended: bool,
}

impl DirectExecutionError {
    pub fn recommends_tunnel_failover(&self) -> bool {
        self.terminal_reason == DirectTerminalReason::ClassifiedDirectFailure
    }

    pub fn recommends_active_stall_probe(&self) -> bool {
        self.active_stall_probe_recommended
    }
}

impl std::fmt::Display for DirectExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({:?}, terminal_reason={}, relay_replay_safe={}, observation_contract={:?}, observation_capture_confidence={}, reference_path_hops={:?}, rst_path_hops={:?})",
            self.error,
            self.signal,
            self.terminal_reason.as_str(),
            self.relay_replay_safe,
            self.observation_contract,
            self.observation_capture_confidence,
            self.reference_path_hops,
            self.rst_path_hops
        )
    }
}

impl std::error::Error for DirectExecutionError {}

#[derive(Debug, Clone)]
pub struct DirectExecutionSuccess {
    pub strategy: String,
    pub signal: aegis_core::signals::classify::FailSignal,
    pub observation: KeyObservation,
    pub latency_ms: u64,
}

#[derive(Debug, Clone)]
pub(super) struct ActiveStallProbeResult {
    pub signal: aegis_core::signals::classify::FailSignal,
    pub observation: KeyObservation,
    pub latency_ms: u64,
    pub planned_probe_preferred_ttl: u8,
    pub planned_probe_budget: usize,
    pub planned_probe_ttl_candidates: Vec<u8>,
    pub first_response_bytes: usize,
    pub terminal_stage: Option<&'static str>,
}

#[derive(Debug, Clone)]
pub(super) struct ActiveStallProbeRun {
    pub timeout_limit: Duration,
    pub is_tls: bool,
    pub freeze_threshold_bytes: usize,
    pub degraded_latency_ms: u64,
    pub stack: Option<StackProfileId>,
    pub wire_mode: WireMimicryMode,
    pub mimicry_ttl_hint: Option<u32>,
    pub wire_window_preface: Option<u16>,
    pub wire_observation_capture_confidence: &'static str,
    pub wire_window_profile: Option<&'static str>,
    pub wire_observed_ipv4_header_shaping: Option<ObservedWireIpv4HeaderShaping>,
    pub wire_observed_negotiated_options: Option<ObservedWireNegotiatedOptions>,
    pub wire_observed_fragment_choreography: Option<ObservedWireChoreographyHint>,
    pub active_probe_plan: ActiveProbePlan,
}

pub async fn execute_direct_plan(
    client: &mut TcpStream,
    strategies: &[Arc<dyn Strategy + 'static>],
    brain: Arc<Brain>,
    execution: DirectExecution<'_>,
) -> Result<DirectExecutionSuccess, Box<DirectExecutionError>> {
    let mut last_err = None;
    for strategy in strategies {
        if execution.ghost_jitter_before_attempt {
            if let Some(ref profile) = execution.ghost {
                tokio::time::sleep(Duration::from_millis(profile.next_jitter_ms())).await;
            }
        }
        let t0 = std::time::Instant::now();
        let _sni_host = execution.sni_host;
        match execute_single_strategy(
            client,
            execution.dst,
            strategy.as_ref(),
            execution.buf,
            execution.sni,
            execution.timeout,
            execution.stack,
            execution.wire_mode,
            execution.mimicry_ttl_hint,
            execution.wire_window_preface,
            execution.wire_observation_capture_confidence,
            execution.wire_window_profile,
            execution.wire_observed_ipv4_header_shaping,
            execution.wire_observed_negotiated_options,
            execution.wire_observed_fragment_choreography,
            execution.reference_path_hops,
        )
        .await
        {
            Ok(observation) => {
                let ms = t0.elapsed().as_millis() as u64;
                let signal = classify_success(
                    t0.elapsed(),
                    execution.timeout,
                    execution.buf.len() + observation.relay_client_to_remote_bytes,
                    observation.first_response_bytes + observation.relay_remote_to_client_bytes,
                    execution.key.is_tls,
                    execution.freeze_threshold_bytes,
                    execution.degraded_latency_ms,
                );
                brain
                    .record_outcome(
                        execution.key,
                        strategy.id(),
                        signal.clone(),
                        Some(ms),
                        execution.buf.len(),
                        Some(observation.clone()),
                    )
                    .await;
                return Ok(DirectExecutionSuccess {
                    strategy: strategy.id().to_string(),
                    signal,
                    observation,
                    latency_ms: ms,
                });
            }
            Err(attempt) => {
                let signal = classify_strategy_error(
                    &attempt.error,
                    ErrorClassificationInput {
                        observation: attempt.observation.as_ref(),
                        packet_observation: Some(&attempt.packet),
                        elapsed: t0.elapsed(),
                        timeout_limit: execution.timeout,
                        bytes_sent: execution.buf.len(),
                        is_tls: execution.key.is_tls,
                        freeze_threshold_bytes: execution.freeze_threshold_bytes,
                        degraded_latency_ms: execution.degraded_latency_ms,
                    },
                );
                let reference_path_hops = attempt
                    .observation
                    .as_ref()
                    .and_then(KeyObservation::reference_path_hops)
                    .or_else(|| attempt.packet.reference_path_hops());
                let rst_path_hops = attempt
                    .observation
                    .as_ref()
                    .and_then(KeyObservation::rst_path_hops)
                    .or_else(|| attempt.packet.rst_path_hops());
                let observation_for_record = attempt
                    .observation
                    .clone()
                    .unwrap_or_else(|| packet_only_observation(attempt.packet.clone()));
                let terminal_reason =
                    if recommends_tunnel_failover(&signal, Some(&observation_for_record)) {
                        DirectTerminalReason::ClassifiedDirectFailure
                    } else {
                        DirectTerminalReason::StrategiesExhausted
                    };
                let active_stall_probe_recommended =
                    recommends_active_stall_probe(&signal, Some(&observation_for_record));
                let observation_contract = observation_for_record.observation_contract();
                let observation_capture_confidence =
                    observation_for_record.observation_capture_confidence();
                brain
                    .record_outcome(
                        execution.key,
                        strategy.id(),
                        signal.clone(),
                        Some(t0.elapsed().as_millis() as u64),
                        execution.buf.len(),
                        Some(observation_for_record.clone()),
                    )
                    .await;
                let direct_error = DirectExecutionError {
                    signal,
                    terminal_reason,
                    error: format!("{:#}", attempt.error),
                    observation: observation_for_record,
                    observation_contract,
                    observation_capture_confidence,
                    reference_path_hops,
                    rst_path_hops,
                    relay_replay_safe: !attempt.application_payload_may_have_been_sent,
                    active_stall_probe_recommended,
                };
                // Freeze-like stalls and collapse paths without clear remote-side
                // backpressure/FIN hints are unlikely to recover via another direct
                // strategy in the same session, so surface them for tunnel failover.
                if direct_error.recommends_tunnel_failover() {
                    return Err(Box::new(direct_error));
                }
                last_err = Some(direct_error);
            }
        }
    }
    Err(Box::new(last_err.unwrap_or_else(|| DirectExecutionError {
        signal: aegis_core::signals::classify::FailSignal::Unknown,
        terminal_reason: execution.empty_plan_reason,
        error: execution.empty_plan_reason.as_str().replace('_', " "),
        observation: KeyObservation::default(),
        observation_contract: ObservationContract::RuntimeOnly,
        observation_capture_confidence: "runtime_only",
        reference_path_hops: None,
        rst_path_hops: None,
        relay_replay_safe: true,
        active_stall_probe_recommended: false,
    })))
}

#[derive(Debug, Clone, Default)]
struct SuccessObservation {
    first_response_bytes: usize,
    first_response_prefix: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Default)]
struct RelayPhaseStats {
    client_to_remote_bytes: usize,
    remote_to_client_bytes: usize,
    relay_lifetime_ms: u64,
}

impl SuccessObservation {
    fn into_key_observation(
        self,
        packet: PacketObservation,
        relay: RelayPhaseStats,
        timeout_limit: Duration,
    ) -> KeyObservation {
        let tls_server_hello_seen = is_likely_tls_server_hello(&self.first_response_prefix);
        KeyObservation {
            first_response_bytes: self.first_response_bytes,
            tls_server_hello_seen,
            ja3s_md5: tls_server_hello_seen
                .then(|| ja3s_server_md5_hex(&self.first_response_prefix))
                .flatten(),
            relay_client_to_remote_bytes: relay.client_to_remote_bytes,
            relay_remote_to_client_bytes: relay.remote_to_client_bytes,
            relay_lifetime_ms: relay.relay_lifetime_ms,
            configured_timeout_ms: timeout_limit.as_millis() as u64,
            capture_status: packet.capture_status,
            capture_backend: packet.capture_backend,
            capture_filter_applied: packet.capture_filter_applied,
            capture_ring_layout: packet.capture_ring_layout,
            capture_io_path: packet.capture_io_path,
            capture_wait_cycles: packet.capture_wait_cycles,
            downstream_dup_ack_count: packet.downstream_dup_ack_count,
            downstream_retransmit_count: packet.downstream_retransmit_count,
            downstream_fin_after_data: packet.downstream_fin_after_data,
            matched_packets: packet.matched_packets,
            syn_ack_ttl: packet.syn_ack_ttl,
            syn_ack_window: packet.syn_ack_window,
            syn_ack_mss: packet.syn_ack_mss,
            syn_ack_window_scale: packet.syn_ack_window_scale,
            syn_ack_sack_permitted: packet.syn_ack_sack_permitted,
            syn_ack_timestamp_option: packet.syn_ack_timestamp_option,
            syn_ack_server_hint: packet.syn_ack_server_hint,
            first_data_ttl: packet.first_data_ttl,
            first_data_window: packet.first_data_window,
            first_data_payload_len: packet.first_data_payload_len,
            first_data_flags: packet.first_data_flags,
            first_data_server_hint: packet.first_data_server_hint,
            first_packet_ttl: packet.first_packet_ttl,
            first_packet_ip_tos: packet.first_packet_ip_tos,
            first_packet_ip_id: packet.first_packet_ip_id,
            first_packet_ip_df: packet.first_packet_ip_df,
            first_packet_window: packet.first_packet_window,
            first_packet_flags: packet.first_packet_flags,
            server_hint: packet.server_hint,
            rst_ttl: packet.rst_ttl,
            rst_source: packet.rst_source,
        }
    }
}

fn packet_only_observation(packet: PacketObservation) -> KeyObservation {
    KeyObservation {
        first_response_bytes: 0,
        tls_server_hello_seen: false,
        ja3s_md5: None,
        relay_client_to_remote_bytes: 0,
        relay_remote_to_client_bytes: 0,
        relay_lifetime_ms: 0,
        configured_timeout_ms: 0,
        capture_status: packet.capture_status,
        capture_backend: packet.capture_backend,
        capture_filter_applied: packet.capture_filter_applied,
        capture_ring_layout: packet.capture_ring_layout,
        capture_io_path: packet.capture_io_path,
        capture_wait_cycles: packet.capture_wait_cycles,
        downstream_dup_ack_count: packet.downstream_dup_ack_count,
        downstream_retransmit_count: packet.downstream_retransmit_count,
        downstream_fin_after_data: packet.downstream_fin_after_data,
        matched_packets: packet.matched_packets,
        syn_ack_ttl: packet.syn_ack_ttl,
        syn_ack_window: packet.syn_ack_window,
        syn_ack_mss: packet.syn_ack_mss,
        syn_ack_window_scale: packet.syn_ack_window_scale,
        syn_ack_sack_permitted: packet.syn_ack_sack_permitted,
        syn_ack_timestamp_option: packet.syn_ack_timestamp_option,
        syn_ack_server_hint: packet.syn_ack_server_hint,
        first_data_ttl: packet.first_data_ttl,
        first_data_window: packet.first_data_window,
        first_data_payload_len: packet.first_data_payload_len,
        first_data_flags: packet.first_data_flags,
        first_data_server_hint: packet.first_data_server_hint,
        first_packet_ttl: packet.first_packet_ttl,
        first_packet_ip_tos: packet.first_packet_ip_tos,
        first_packet_ip_id: packet.first_packet_ip_id,
        first_packet_ip_df: packet.first_packet_ip_df,
        first_packet_window: packet.first_packet_window,
        first_packet_flags: packet.first_packet_flags,
        server_hint: packet.server_hint,
        rst_ttl: packet.rst_ttl,
        rst_source: packet.rst_source,
    }
}

fn recommends_tunnel_failover(
    signal: &aegis_core::signals::classify::FailSignal,
    observation: Option<&KeyObservation>,
) -> bool {
    use aegis_core::signals::classify::FailSignal;

    match signal {
        FailSignal::SessionFreeze { .. } => true,
        FailSignal::ThroughputCollapse => !has_remote_stall_relief(observation),
        _ => false,
    }
}

fn recommends_active_stall_probe(
    signal: &aegis_core::signals::classify::FailSignal,
    observation: Option<&KeyObservation>,
) -> bool {
    use aegis_core::signals::classify::FailSignal;

    match signal {
        // Freeze/collapse paths can trigger a bounded active probe cycle so the
        // current session can either retry direct once or confirm relay
        // failover, but only when the observation context is probe-capable.
        FailSignal::SessionFreeze { .. } | FailSignal::ThroughputCollapse => {
            !has_remote_stall_relief(observation)
                && observation
                    .map(KeyObservation::supports_active_stall_probe)
                    .unwrap_or(false)
        }
        _ => false,
    }
}

fn has_remote_stall_relief(observation: Option<&KeyObservation>) -> bool {
    let Some(observation) = observation else {
        return false;
    };
    observation.downstream_fin_after_data
        || observation.downstream_retransmit_count > 0
        || observation.downstream_dup_ack_count >= 2
        || matches!(observation.first_data_window, Some(0))
}

fn active_stall_probe_timeout(timeout_limit: Duration) -> Duration {
    let timeout_ms = timeout_limit.as_millis() as u64;
    Duration::from_millis(timeout_ms.clamp(350, 1500))
}

pub(super) async fn run_active_stall_probe(
    dst: SocketAddr,
    buf: Vec<u8>,
    run: ActiveStallProbeRun,
) -> ActiveStallProbeResult {
    let probe_timeout = active_stall_probe_timeout(run.timeout_limit);
    let started_at = std::time::Instant::now();
    let mut packet = PacketObservation::default();
    let socket = match dst {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    };
    let socket = match socket {
        Ok(socket) => socket,
        Err(error) => {
            // Probe-finished telemetry has no raw error string, so keep the
            // terminal stage explicit in the result for runtime events.
            let mut observation = packet_only_observation(packet.clone());
            observation.configured_timeout_ms = probe_timeout.as_millis() as u64;
            let signal = classify_strategy_error(
                &stage_strategy_error("active_probe_socket_create", error),
                ErrorClassificationInput {
                    observation: None,
                    packet_observation: Some(&packet),
                    elapsed: started_at.elapsed(),
                    timeout_limit: probe_timeout,
                    bytes_sent: buf.len(),
                    is_tls: run.is_tls,
                    freeze_threshold_bytes: run.freeze_threshold_bytes,
                    degraded_latency_ms: run.degraded_latency_ms,
                },
            );
            return ActiveStallProbeResult {
                signal,
                observation,
                latency_ms: started_at.elapsed().as_millis() as u64,
                planned_probe_preferred_ttl: run.active_probe_plan.preferred_ttl,
                planned_probe_budget: run.active_probe_plan.budget,
                planned_probe_ttl_candidates: run.active_probe_plan.candidates.clone(),
                first_response_bytes: 0,
                terminal_stage: Some("active_probe_socket_create"),
            };
        }
    };
    if let Err(error) = apply_direct_socket_mark(&socket) {
        let mut observation = packet_only_observation(packet.clone());
        observation.configured_timeout_ms = probe_timeout.as_millis() as u64;
        let signal = classify_strategy_error(
            &stage_strategy_error("active_probe_socket_mark", error),
            ErrorClassificationInput {
                observation: None,
                packet_observation: Some(&packet),
                elapsed: started_at.elapsed(),
                timeout_limit: probe_timeout,
                bytes_sent: buf.len(),
                is_tls: run.is_tls,
                freeze_threshold_bytes: run.freeze_threshold_bytes,
                degraded_latency_ms: run.degraded_latency_ms,
            },
        );
        return ActiveStallProbeResult {
            signal,
            observation,
            latency_ms: started_at.elapsed().as_millis() as u64,
            planned_probe_preferred_ttl: run.active_probe_plan.preferred_ttl,
            planned_probe_budget: run.active_probe_plan.budget,
            planned_probe_ttl_candidates: run.active_probe_plan.candidates.clone(),
            first_response_bytes: 0,
            terminal_stage: Some("active_probe_socket_mark"),
        };
    }
    if let Err(error) =
        apply_userspace_mimicry_tuning(&socket, run.stack, dst, run.mimicry_ttl_hint)
    {
        let mut observation = packet_only_observation(packet.clone());
        observation.configured_timeout_ms = probe_timeout.as_millis() as u64;
        let signal = classify_strategy_error(
            &stage_strategy_error("active_probe_pre_connect", error),
            ErrorClassificationInput {
                observation: None,
                packet_observation: Some(&packet),
                elapsed: started_at.elapsed(),
                timeout_limit: probe_timeout,
                bytes_sent: buf.len(),
                is_tls: run.is_tls,
                freeze_threshold_bytes: run.freeze_threshold_bytes,
                degraded_latency_ms: run.degraded_latency_ms,
            },
        );
        return ActiveStallProbeResult {
            signal,
            observation,
            latency_ms: started_at.elapsed().as_millis() as u64,
            planned_probe_preferred_ttl: run.active_probe_plan.preferred_ttl,
            planned_probe_budget: run.active_probe_plan.budget,
            planned_probe_ttl_candidates: run.active_probe_plan.candidates.clone(),
            first_response_bytes: 0,
            terminal_stage: Some("active_probe_pre_connect"),
        };
    }

    let mut remote = match timeout(probe_timeout, socket.connect(dst)).await {
        Ok(Ok(remote)) => remote,
        Ok(Err(error)) => {
            let mut observation = packet_only_observation(packet.clone());
            observation.configured_timeout_ms = probe_timeout.as_millis() as u64;
            let signal = classify_strategy_error(
                &stage_strategy_error("active_probe_connect_remote", error),
                ErrorClassificationInput {
                    observation: None,
                    packet_observation: Some(&packet),
                    elapsed: started_at.elapsed(),
                    timeout_limit: probe_timeout,
                    bytes_sent: buf.len(),
                    is_tls: run.is_tls,
                    freeze_threshold_bytes: run.freeze_threshold_bytes,
                    degraded_latency_ms: run.degraded_latency_ms,
                },
            );
            return ActiveStallProbeResult {
                signal,
                observation,
                latency_ms: started_at.elapsed().as_millis() as u64,
                planned_probe_preferred_ttl: run.active_probe_plan.preferred_ttl,
                planned_probe_budget: run.active_probe_plan.budget,
                planned_probe_ttl_candidates: run.active_probe_plan.candidates.clone(),
                first_response_bytes: 0,
                terminal_stage: Some("active_probe_connect_remote"),
            };
        }
        Err(_) => {
            let mut observation = packet_only_observation(packet.clone());
            observation.configured_timeout_ms = probe_timeout.as_millis() as u64;
            let signal = classify_strategy_error(
                &anyhow::anyhow!(
                    "active_probe_connect_timeout: active stall probe timeout during connect"
                ),
                ErrorClassificationInput {
                    observation: None,
                    packet_observation: Some(&packet),
                    elapsed: started_at.elapsed(),
                    timeout_limit: probe_timeout,
                    bytes_sent: buf.len(),
                    is_tls: run.is_tls,
                    freeze_threshold_bytes: run.freeze_threshold_bytes,
                    degraded_latency_ms: run.degraded_latency_ms,
                },
            );
            return ActiveStallProbeResult {
                signal,
                observation,
                latency_ms: started_at.elapsed().as_millis() as u64,
                planned_probe_preferred_ttl: run.active_probe_plan.preferred_ttl,
                planned_probe_budget: run.active_probe_plan.budget,
                planned_probe_ttl_candidates: run.active_probe_plan.candidates.clone(),
                first_response_bytes: 0,
                terminal_stage: Some("active_probe_connect_timeout"),
            };
        }
    };
    let packet_observer = match remote.local_addr() {
        Ok(local_addr) => start_packet_observer(local_addr, dst, probe_timeout),
        Err(_) => aegis_core::PacketObserverHandle::Unavailable(PacketObservation::default()),
    };
    let wire_runtime = resolve_wire_mimicry_runtime(
        run.wire_mode,
        dst,
        default_raw_engine().capabilities(),
        run.mimicry_ttl_hint,
        run.wire_window_preface,
        wire_options_preface_profile(run.stack),
        observed_wire_ipv4_header_shaping_preface(run.wire_observed_ipv4_header_shaping),
        negotiated_wire_options_preface(
            run.stack,
            run.wire_observation_capture_confidence,
            run.wire_window_profile,
            run.wire_observed_negotiated_options,
        ),
        wire_fragment_choreography_plan(
            run.wire_observation_capture_confidence,
            run.wire_window_profile,
            run.wire_observed_fragment_choreography,
        ),
    );
    if let Err(error) = apply_experimental_wire_preface(&remote, dst, &buf, &wire_runtime) {
        packet = packet_observer_finish(packet_observer).await;
        let mut observation = packet_only_observation(packet.clone());
        observation.configured_timeout_ms = probe_timeout.as_millis() as u64;
        let signal = classify_strategy_error(
            &stage_strategy_error("active_probe_wire_preface", error),
            ErrorClassificationInput {
                observation: None,
                packet_observation: Some(&packet),
                elapsed: started_at.elapsed(),
                timeout_limit: probe_timeout,
                bytes_sent: buf.len(),
                is_tls: run.is_tls,
                freeze_threshold_bytes: run.freeze_threshold_bytes,
                degraded_latency_ms: run.degraded_latency_ms,
            },
        );
        return ActiveStallProbeResult {
            signal,
            observation,
            latency_ms: started_at.elapsed().as_millis() as u64,
            planned_probe_preferred_ttl: run.active_probe_plan.preferred_ttl,
            planned_probe_budget: run.active_probe_plan.budget,
            planned_probe_ttl_candidates: run.active_probe_plan.candidates.clone(),
            first_response_bytes: 0,
            terminal_stage: Some("active_probe_wire_preface"),
        };
    }

    if let Err(error) = remote.write_all(&buf).await {
        packet = packet_observer_finish(packet_observer).await;
        let mut observation = packet_only_observation(packet.clone());
        observation.configured_timeout_ms = probe_timeout.as_millis() as u64;
        let signal = classify_strategy_error(
            &stage_strategy_error("active_probe_send_probe", error),
            ErrorClassificationInput {
                observation: None,
                packet_observation: Some(&packet),
                elapsed: started_at.elapsed(),
                timeout_limit: probe_timeout,
                bytes_sent: buf.len(),
                is_tls: run.is_tls,
                freeze_threshold_bytes: run.freeze_threshold_bytes,
                degraded_latency_ms: run.degraded_latency_ms,
            },
        );
        return ActiveStallProbeResult {
            signal,
            observation,
            latency_ms: started_at.elapsed().as_millis() as u64,
            planned_probe_preferred_ttl: run.active_probe_plan.preferred_ttl,
            planned_probe_budget: run.active_probe_plan.budget,
            planned_probe_ttl_candidates: run.active_probe_plan.candidates.clone(),
            first_response_bytes: 0,
            terminal_stage: Some("active_probe_send_probe"),
        };
    }

    let mut prefix = vec![0u8; 4096];
    match timeout(probe_timeout, remote.read(&mut prefix)).await {
        Ok(Ok(0)) => {
            packet = packet_observer_finish(packet_observer).await;
            let mut observation = packet_only_observation(packet.clone());
            observation.configured_timeout_ms = probe_timeout.as_millis() as u64;
            let signal = classify_strategy_error(
                &anyhow::anyhow!("active_probe_first_response_eof: server closed"),
                ErrorClassificationInput {
                    observation: None,
                    packet_observation: Some(&packet),
                    elapsed: started_at.elapsed(),
                    timeout_limit: probe_timeout,
                    bytes_sent: buf.len(),
                    is_tls: run.is_tls,
                    freeze_threshold_bytes: run.freeze_threshold_bytes,
                    degraded_latency_ms: run.degraded_latency_ms,
                },
            );
            ActiveStallProbeResult {
                signal,
                observation,
                latency_ms: started_at.elapsed().as_millis() as u64,
                planned_probe_preferred_ttl: run.active_probe_plan.preferred_ttl,
                planned_probe_budget: run.active_probe_plan.budget,
                planned_probe_ttl_candidates: run.active_probe_plan.candidates.clone(),
                first_response_bytes: 0,
                terminal_stage: Some("active_probe_first_response_eof"),
            }
        }
        Ok(Ok(n)) => {
            prefix.truncate(n);
            packet = packet_observer_finish(packet_observer).await;
            let observation = SuccessObservation {
                first_response_bytes: n,
                first_response_prefix: prefix,
            }
            .into_key_observation(
                packet.clone(),
                RelayPhaseStats::default(),
                probe_timeout,
            );
            let signal = classify_success(
                started_at.elapsed(),
                probe_timeout,
                buf.len(),
                n,
                run.is_tls,
                run.freeze_threshold_bytes,
                run.degraded_latency_ms,
            );
            ActiveStallProbeResult {
                signal,
                observation,
                latency_ms: started_at.elapsed().as_millis() as u64,
                planned_probe_preferred_ttl: run.active_probe_plan.preferred_ttl,
                planned_probe_budget: run.active_probe_plan.budget,
                planned_probe_ttl_candidates: run.active_probe_plan.candidates.clone(),
                first_response_bytes: n,
                terminal_stage: None,
            }
        }
        Ok(Err(error)) => {
            packet = packet_observer_finish(packet_observer).await;
            let mut observation = packet_only_observation(packet.clone());
            observation.configured_timeout_ms = probe_timeout.as_millis() as u64;
            let signal = classify_strategy_error(
                &stage_strategy_error("active_probe_read_first_response", error),
                ErrorClassificationInput {
                    observation: None,
                    packet_observation: Some(&packet),
                    elapsed: started_at.elapsed(),
                    timeout_limit: probe_timeout,
                    bytes_sent: buf.len(),
                    is_tls: run.is_tls,
                    freeze_threshold_bytes: run.freeze_threshold_bytes,
                    degraded_latency_ms: run.degraded_latency_ms,
                },
            );
            ActiveStallProbeResult {
                signal,
                observation,
                latency_ms: started_at.elapsed().as_millis() as u64,
                planned_probe_preferred_ttl: run.active_probe_plan.preferred_ttl,
                planned_probe_budget: run.active_probe_plan.budget,
                planned_probe_ttl_candidates: run.active_probe_plan.candidates.clone(),
                first_response_bytes: 0,
                terminal_stage: Some("active_probe_read_first_response"),
            }
        }
        Err(_) => {
            packet = packet_observer_finish(packet_observer).await;
            let mut observation = packet_only_observation(packet.clone());
            observation.configured_timeout_ms = probe_timeout.as_millis() as u64;
            let signal = classify_strategy_error(
                &anyhow::anyhow!("active_probe_first_response_timeout: active stall probe timeout"),
                ErrorClassificationInput {
                    observation: None,
                    packet_observation: Some(&packet),
                    elapsed: started_at.elapsed(),
                    timeout_limit: probe_timeout,
                    bytes_sent: buf.len(),
                    is_tls: run.is_tls,
                    freeze_threshold_bytes: run.freeze_threshold_bytes,
                    degraded_latency_ms: run.degraded_latency_ms,
                },
            );
            ActiveStallProbeResult {
                signal,
                observation,
                latency_ms: started_at.elapsed().as_millis() as u64,
                planned_probe_preferred_ttl: run.active_probe_plan.preferred_ttl,
                planned_probe_budget: run.active_probe_plan.budget,
                planned_probe_ttl_candidates: run.active_probe_plan.candidates.clone(),
                first_response_bytes: 0,
                terminal_stage: Some("active_probe_first_response_timeout"),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn execute_single_strategy(
    client: &mut TcpStream,
    dst: SocketAddr,
    strategy: &dyn Strategy,
    buf: &[u8],
    sni: Option<(usize, usize)>,
    tout: Duration,
    stack: Option<StackProfileId>,
    wire_mode: WireMimicryMode,
    mimicry_ttl_hint: Option<u32>,
    wire_window_preface: Option<u16>,
    wire_observation_capture_confidence: &'static str,
    wire_window_profile: Option<&'static str>,
    wire_observed_ipv4_header_shaping: Option<ObservedWireIpv4HeaderShaping>,
    wire_observed_negotiated_options: Option<ObservedWireNegotiatedOptions>,
    wire_observed_fragment_choreography: Option<ObservedWireChoreographyHint>,
    reference_path_hops: Option<u8>,
) -> Result<KeyObservation, Box<StrategyAttemptError>> {
    let sctx = SendFirstContext {
        dst,
        reference_path_hops,
    };
    if let Err(error) = strategy.preflight_send_first(buf, sni, &sctx) {
        return Err(Box::new(StrategyAttemptError {
            error: stage_strategy_error("direct_send_first_preflight", error),
            packet: PacketObservation::default(),
            observation: None,
            application_payload_may_have_been_sent: false,
        }));
    }
    let socket = match dst {
        SocketAddr::V4(_) => TcpSocket::new_v4().map_err(|error| {
            Box::new(StrategyAttemptError {
                error: stage_strategy_error("direct_socket_create", error),
                packet: PacketObservation::default(),
                observation: None,
                application_payload_may_have_been_sent: false,
            })
        })?,
        SocketAddr::V6(_) => TcpSocket::new_v6().map_err(|error| {
            Box::new(StrategyAttemptError {
                error: stage_strategy_error("direct_socket_create", error),
                packet: PacketObservation::default(),
                observation: None,
                application_payload_may_have_been_sent: false,
            })
        })?,
    };
    apply_direct_socket_mark(&socket).map_err(|error| {
        Box::new(StrategyAttemptError {
            error: stage_strategy_error("direct_socket_mark", error),
            packet: PacketObservation::default(),
            observation: None,
            application_payload_may_have_been_sent: false,
        })
    })?;
    apply_userspace_mimicry_tuning(&socket, stack, dst, mimicry_ttl_hint).map_err(|error| {
        Box::new(StrategyAttemptError {
            error: stage_strategy_error("direct_pre_connect", error),
            packet: PacketObservation::default(),
            observation: None,
            application_payload_may_have_been_sent: false,
        })
    })?;
    let mut remote = socket.connect(dst).await.map_err(|error| {
        Box::new(StrategyAttemptError {
            error: stage_strategy_error("direct_connect_remote", error),
            packet: PacketObservation::default(),
            observation: None,
            application_payload_may_have_been_sent: false,
        })
    })?;
    let packet_observer = start_packet_observer(
        remote.local_addr().map_err(|error| {
            Box::new(StrategyAttemptError {
                error: stage_strategy_error("direct_local_addr", error),
                packet: PacketObservation::default(),
                observation: None,
                application_payload_may_have_been_sent: false,
            })
        })?,
        dst,
        tout,
    );

    let wire_runtime = resolve_wire_mimicry_runtime(
        wire_mode,
        dst,
        default_raw_engine().capabilities(),
        mimicry_ttl_hint,
        wire_window_preface,
        wire_options_preface_profile(stack),
        observed_wire_ipv4_header_shaping_preface(wire_observed_ipv4_header_shaping),
        negotiated_wire_options_preface(
            stack,
            wire_observation_capture_confidence,
            wire_window_profile,
            wire_observed_negotiated_options,
        ),
        wire_fragment_choreography_plan(
            wire_observation_capture_confidence,
            wire_window_profile,
            wire_observed_fragment_choreography,
        ),
    );
    if let Err(error) = apply_experimental_wire_preface(&remote, dst, buf, &wire_runtime) {
        return Err(Box::new(StrategyAttemptError {
            error: stage_strategy_error("direct_wire_preface", error),
            packet: packet_observer_finish(packet_observer).await,
            observation: None,
            application_payload_may_have_been_sent: false,
        }));
    }
    if let Err(error) = strategy.send_first(&mut remote, buf, sni, &sctx).await {
        return Err(Box::new(StrategyAttemptError {
            error: stage_strategy_error("direct_send_first", error),
            packet: packet_observer_finish(packet_observer).await,
            observation: None,
            application_payload_may_have_been_sent: true,
        }));
    }

    let mut prefix = vec![0u8; 4096];
    match timeout(tout, remote.read(&mut prefix)).await {
        Ok(Ok(0)) => Err(Box::new(StrategyAttemptError {
            error: anyhow::anyhow!("direct_first_response_eof: server closed"),
            packet: packet_observer_finish(packet_observer).await,
            observation: None,
            application_payload_may_have_been_sent: true,
        })),
        Ok(Ok(n)) => {
            prefix.truncate(n);
            client.write_all(&prefix).await.map_err(|error| {
                Box::new(StrategyAttemptError {
                    error: stage_strategy_error("direct_forward_first_response", error),
                    packet: PacketObservation::default(),
                    observation: None,
                    application_payload_may_have_been_sent: true,
                })
            })?;
            let observation = SuccessObservation {
                first_response_bytes: n,
                first_response_prefix: prefix,
            };
            let packet = packet_observer_finish(packet_observer).await;
            match relay_bidirectional(client, &mut remote).await {
                Ok(relay) => Ok(observation.into_key_observation(packet, relay, tout)),
                Err((error, relay)) => {
                    let key_observation =
                        observation.into_key_observation(packet.clone(), relay, tout);
                    Err(Box::new(StrategyAttemptError {
                        error: error.into(),
                        packet,
                        observation: Some(key_observation),
                        application_payload_may_have_been_sent: true,
                    }))
                }
            }
        }
        Ok(Err(e)) => Err(Box::new(StrategyAttemptError {
            error: stage_strategy_error("direct_read_first_response", e),
            packet: packet_observer_finish(packet_observer).await,
            observation: None,
            application_payload_may_have_been_sent: true,
        })),
        Err(_) => Err(Box::new(StrategyAttemptError {
            error: anyhow::anyhow!("direct_first_response_timeout: probe timeout"),
            packet: packet_observer_finish(packet_observer).await,
            observation: None,
            application_payload_may_have_been_sent: true,
        })),
    }
}

async fn packet_observer_finish(observer: aegis_core::PacketObserverHandle) -> PacketObservation {
    observer.finish().await
}

fn apply_userspace_mimicry_tuning(
    socket: &TcpSocket,
    stack: Option<StackProfileId>,
    dst: SocketAddr,
    mimicry_ttl_hint: Option<u32>,
) -> io::Result<()> {
    match (stack, mimicry_ttl_hint) {
        (Some(profile), ttl_hint) => {
            apply_pre_connect_with_ttl_hint(socket, profile, dst, ttl_hint)
        }
        // Capture-backed TTL can still strengthen the userspace surface even
        // when no explicit profile is configured. Future packet/wire shaping
        // remains a separate Linux/raw-capability track above this layer.
        (None, Some(ttl_hint)) => apply_ttl_hint_only(socket, dst, Some(ttl_hint)),
        (None, None) => Ok(()),
    }
}

async fn relay_bidirectional(
    client: &mut TcpStream,
    remote: &mut TcpStream,
) -> Result<RelayPhaseStats, (io::Error, RelayPhaseStats)> {
    let (mut client_read, mut client_write) = client.split();
    let (mut remote_read, mut remote_write) = remote.split();
    let mut stats = RelayPhaseStats::default();
    let mut client_eof = false;
    let mut remote_eof = false;
    let mut client_buf = [0u8; 8192];
    let mut remote_buf = [0u8; 8192];
    let relay_started_at = std::time::Instant::now();

    loop {
        if client_eof && remote_eof {
            stats.relay_lifetime_ms = relay_started_at.elapsed().as_millis() as u64;
            return Ok(stats);
        }

        // Track post-first-response relay bytes so failure feedback can distinguish
        // "reset after first packet" from "reset after real bidirectional traffic".
        tokio::select! {
            read = client_read.read(&mut client_buf), if !client_eof => {
                match read {
                    Ok(0) => {
                        client_eof = true;
                        if let Err(error) = remote_write.shutdown().await {
                            stats.relay_lifetime_ms = relay_started_at.elapsed().as_millis() as u64;
                            return Err((stage_relay_io_error("direct_relay_shutdown_remote", error), stats));
                        }
                    }
                    Ok(n) => {
                        if let Err(error) = remote_write.write_all(&client_buf[..n]).await {
                            stats.relay_lifetime_ms = relay_started_at.elapsed().as_millis() as u64;
                            return Err((stage_relay_io_error("direct_relay_client_to_remote_write", error), stats));
                        }
                        stats.client_to_remote_bytes += n;
                    }
                    Err(error) => {
                        stats.relay_lifetime_ms = relay_started_at.elapsed().as_millis() as u64;
                        return Err((stage_relay_io_error("direct_relay_client_read", error), stats));
                    }
                }
            }
            read = remote_read.read(&mut remote_buf), if !remote_eof => {
                match read {
                    Ok(0) => {
                        remote_eof = true;
                        if let Err(error) = client_write.shutdown().await {
                            stats.relay_lifetime_ms = relay_started_at.elapsed().as_millis() as u64;
                            return Err((stage_relay_io_error("direct_relay_shutdown_client", error), stats));
                        }
                    }
                    Ok(n) => {
                        if let Err(error) = client_write.write_all(&remote_buf[..n]).await {
                            stats.relay_lifetime_ms = relay_started_at.elapsed().as_millis() as u64;
                            return Err((stage_relay_io_error("direct_relay_remote_to_client_write", error), stats));
                        }
                        stats.remote_to_client_bytes += n;
                    }
                    Err(error) => {
                        stats.relay_lifetime_ms = relay_started_at.elapsed().as_millis() as u64;
                        return Err((stage_relay_io_error("direct_relay_remote_read", error), stats));
                    }
                }
            }
        }
    }
}

fn classify_success(
    elapsed: Duration,
    timeout_limit: Duration,
    bytes_sent: usize,
    bytes_received: usize,
    is_tls: bool,
    freeze_threshold_bytes: usize,
    degraded_latency_ms: u64,
) -> aegis_core::signals::classify::FailSignal {
    classify_outcome(
        true,
        &OutcomeContext {
            io_error: None,
            rst_ttl: None,
            rst_source: None,
            expected_ttl: None,
            bytes_sent,
            bytes_received,
            syn_ack_seen: false,
            first_data_seen: false,
            is_tls,
            elapsed,
            configured_timeout: timeout_limit,
            freeze_threshold_bytes,
            degraded_latency_ms,
        },
    )
}

struct ErrorClassificationInput<'a> {
    observation: Option<&'a KeyObservation>,
    packet_observation: Option<&'a PacketObservation>,
    elapsed: Duration,
    timeout_limit: Duration,
    bytes_sent: usize,
    is_tls: bool,
    freeze_threshold_bytes: usize,
    degraded_latency_ms: u64,
}

fn classify_strategy_error(
    err: &anyhow::Error,
    input: ErrorClassificationInput<'_>,
) -> aegis_core::signals::classify::FailSignal {
    let io_error = err
        .chain()
        .find_map(|cause| cause.downcast_ref::<io::Error>().map(|io| io.kind()))
        .or_else(|| {
            err.to_string()
                .contains("probe timeout")
                .then_some(io::ErrorKind::TimedOut)
        });
    classify_outcome(
        false,
        &OutcomeContext {
            io_error,
            rst_ttl: input
                .observation
                .and_then(|obs| obs.rst_ttl)
                .or(input.packet_observation.and_then(|obs| obs.rst_ttl)),
            rst_source: input
                .observation
                .and_then(|obs| obs.rst_source)
                .or(input.packet_observation.and_then(|obs| obs.rst_source)),
            expected_ttl: input
                .observation
                .and_then(|obs| {
                    obs.first_data_ttl
                        .or(obs.syn_ack_ttl)
                        .or(obs.first_packet_ttl)
                })
                .or(input.packet_observation.and_then(|obs| {
                    obs.first_data_ttl
                        .or(obs.syn_ack_ttl)
                        .or(obs.first_packet_ttl)
                })),
            bytes_sent: input.bytes_sent
                + input
                    .observation
                    .map(|obs| obs.relay_client_to_remote_bytes)
                    .unwrap_or(0),
            bytes_received: input
                .observation
                .map(|obs| obs.first_response_bytes + obs.relay_remote_to_client_bytes)
                .unwrap_or(0),
            syn_ack_seen: input.observation.and_then(|obs| obs.syn_ack_ttl).is_some()
                || input
                    .packet_observation
                    .and_then(|obs| obs.syn_ack_ttl)
                    .is_some(),
            first_data_seen: input
                .observation
                .and_then(|obs| obs.first_data_ttl)
                .is_some()
                || input
                    .packet_observation
                    .and_then(|obs| obs.first_data_ttl)
                    .is_some(),
            is_tls: input.is_tls,
            elapsed: input.elapsed,
            configured_timeout: input.timeout_limit,
            freeze_threshold_bytes: input.freeze_threshold_bytes,
            degraded_latency_ms: input.degraded_latency_ms,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::super::planner::ActiveProbePlan;
    use super::execute_single_strategy;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use super::relay_bidirectional;
    use super::run_active_stall_probe;
    use super::DirectExecutionError;
    use aegis_core::strategies::GenevaStrategy;
    use aegis_core::{
        signals::classify::FailSignal, DirectTerminalReason, ObservationContract,
        PacketObservation, PassthroughStrategy, WireMimicryMode,
    };
    use std::net::TcpListener as StdTcpListener;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use std::os::fd::AsRawFd;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::Duration;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn force_reset_on_close(stream: &std::net::TcpStream) {
        let linger = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        let ret = unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                &linger as *const libc::linger as *const libc::c_void,
                std::mem::size_of::<libc::linger>() as libc::socklen_t,
            )
        };
        assert_eq!(ret, 0, "setsockopt(SO_LINGER) failed");
    }

    async fn tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let client = TcpStream::connect(addr).await.expect("connect client");
        let (server, _) = listener.accept().await.expect("accept server");
        (client, server)
    }

    #[test]
    fn recommends_tunnel_failover_for_session_freeze() {
        let err = DirectExecutionError {
            signal: FailSignal::SessionFreeze {
                bytes_before_stall: 32 * 1024,
            },
            terminal_reason: DirectTerminalReason::ClassifiedDirectFailure,
            error: "freeze".into(),
            observation: aegis_core::KeyObservation::default(),
            observation_contract: ObservationContract::DeepObserved,
            observation_capture_confidence: "deep_observed",
            reference_path_hops: Some(7),
            rst_path_hops: None,
            relay_replay_safe: false,
            active_stall_probe_recommended: true,
        };
        assert!(err.recommends_tunnel_failover());
        assert!(err.recommends_active_stall_probe());
    }

    #[test]
    fn does_not_recommend_tunnel_failover_for_handshake_mismatch() {
        let err = DirectExecutionError {
            signal: FailSignal::HandshakeMismatch,
            terminal_reason: DirectTerminalReason::StrategiesExhausted,
            error: "tls mismatch".into(),
            observation: aegis_core::KeyObservation::default(),
            observation_contract: ObservationContract::RuntimeOnly,
            observation_capture_confidence: "runtime_only",
            reference_path_hops: Some(7),
            rst_path_hops: Some(3),
            relay_replay_safe: false,
            active_stall_probe_recommended: false,
        };
        assert!(!err.recommends_tunnel_failover());
        assert!(!err.recommends_active_stall_probe());
    }

    #[test]
    fn planning_terminals_require_immediate_handoff_without_stall_probe() {
        for terminal_reason in [
            DirectTerminalReason::NoExecutableStrategy,
            DirectTerminalReason::UnsupportedAddressFamily,
            DirectTerminalReason::MissingRawCapability,
        ] {
            let err = DirectExecutionError {
                signal: FailSignal::Unknown,
                terminal_reason,
                error: terminal_reason.as_str().into(),
                observation: aegis_core::KeyObservation::default(),
                observation_contract: ObservationContract::RuntimeOnly,
                observation_capture_confidence: "runtime_only",
                reference_path_hops: None,
                rst_path_hops: None,
                relay_replay_safe: true,
                active_stall_probe_recommended: false,
            };
            assert!(err.terminal_reason.requires_immediate_relay_handoff());
            assert!(!err.recommends_tunnel_failover());
            assert!(!err.recommends_active_stall_probe());
        }
    }

    #[test]
    fn recommends_tunnel_failover_for_plain_throughput_collapse() {
        use aegis_core::KeyObservation;

        assert!(super::recommends_tunnel_failover(
            &FailSignal::ThroughputCollapse,
            Some(&KeyObservation::default()),
        ));
    }

    #[test]
    fn recommends_active_stall_probe_for_freeze_with_capture_context() {
        use aegis_core::{KeyObservation, PacketCaptureBackendKind, PacketCaptureStatus};

        let observation = KeyObservation {
            capture_status: PacketCaptureStatus::Active,
            capture_backend: Some(PacketCaptureBackendKind::LinuxAfPacket),
            matched_packets: 2,
            first_data_ttl: Some(58),
            ..KeyObservation::default()
        };
        assert!(super::recommends_active_stall_probe(
            &FailSignal::SessionFreeze {
                bytes_before_stall: 32 * 1024,
            },
            Some(&observation),
        ));
    }

    #[test]
    fn keeps_remote_relief_collapses_on_direct_path() {
        use aegis_core::KeyObservation;

        let observation = KeyObservation {
            downstream_fin_after_data: true,
            ..KeyObservation::default()
        };
        assert!(!super::recommends_tunnel_failover(
            &FailSignal::ThroughputCollapse,
            Some(&observation),
        ));
    }

    #[test]
    fn does_not_recommend_active_stall_probe_without_probe_capability() {
        use aegis_core::{KeyObservation, PacketCaptureStatus};

        let observation = KeyObservation {
            capture_status: PacketCaptureStatus::UnsupportedPlatform,
            matched_packets: 2,
            first_data_ttl: Some(58),
            ..KeyObservation::default()
        };
        assert!(!super::recommends_active_stall_probe(
            &FailSignal::ThroughputCollapse,
            Some(&observation),
        ));
    }

    #[test]
    fn remote_relief_blocks_active_stall_probe_recommendation() {
        use aegis_core::{KeyObservation, PacketCaptureBackendKind, PacketCaptureStatus};

        let observation = KeyObservation {
            capture_status: PacketCaptureStatus::Active,
            capture_backend: Some(PacketCaptureBackendKind::LinuxAfPacket),
            matched_packets: 2,
            first_data_ttl: Some(58),
            downstream_fin_after_data: true,
            ..KeyObservation::default()
        };
        assert!(!super::recommends_active_stall_probe(
            &FailSignal::ThroughputCollapse,
            Some(&observation),
        ));
    }

    #[test]
    fn active_stall_probe_timeout_is_short_and_bounded() {
        assert_eq!(
            super::active_stall_probe_timeout(Duration::from_millis(100)),
            Duration::from_millis(350)
        );
        assert_eq!(
            super::active_stall_probe_timeout(Duration::from_millis(800)),
            Duration::from_millis(800)
        );
        assert_eq!(
            super::active_stall_probe_timeout(Duration::from_secs(5)),
            Duration::from_millis(1500)
        );
    }

    #[test]
    fn packet_only_observation_preserves_capture_status() {
        let packet = PacketObservation::with_capture_status(
            aegis_core::PacketCaptureStatus::UnsupportedPlatform,
        );
        let observation = super::packet_only_observation(packet);
        assert_eq!(
            observation.capture_status,
            aegis_core::PacketCaptureStatus::UnsupportedPlatform
        );
    }

    #[tokio::test]
    async fn connect_refusal_is_stage_prefixed() {
        let (client, mut server) = tcp_pair().await;
        drop(client);

        let closed = StdTcpListener::bind("127.0.0.1:0").expect("bind closed port");
        let dst = closed.local_addr().expect("closed port addr");
        drop(closed);

        let err = execute_single_strategy(
            &mut server,
            dst,
            &PassthroughStrategy,
            b"GET / HTTP/1.0\r\n\r\n",
            None,
            Duration::from_millis(200),
            None,
            WireMimicryMode::Disabled,
            None,
            None,
            "runtime_only",
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect_err("connect should fail");

        assert!(
            err.error.to_string().starts_with("direct_connect_remote:"),
            "unexpected error: {}",
            err.error
        );
        assert!(!err.application_payload_may_have_been_sent);
    }

    #[tokio::test]
    async fn geneva_missing_hop_count_is_a_replay_safe_preflight_terminal() {
        let (client, mut server) = tcp_pair().await;
        drop(client);
        let strategy = GenevaStrategy::from_dsl(
            r"[TCP:flags:PA]-duplicate(tamper{IP:ttl:replace:1}(tamper{TCP:load:corrupt}()),)-| \/",
        )
        .expect("safe live Geneva strategy");

        let err = execute_single_strategy(
            &mut server,
            "203.0.113.10:443".parse().expect("test destination"),
            &strategy,
            b"GET / HTTP/1.0\r\n\r\n",
            None,
            Duration::from_millis(200),
            None,
            WireMimicryMode::Disabled,
            None,
            None,
            "runtime_only",
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect_err("missing hop count must fail before any write or connect");

        assert!(
            err.error
                .to_string()
                .starts_with("direct_send_first_preflight:"),
            "unexpected error: {}",
            err.error
        );
        assert!(!err.application_payload_may_have_been_sent);
    }

    #[tokio::test]
    async fn first_response_eof_is_stage_prefixed() {
        let (client, mut server) = tcp_pair().await;
        drop(client);

        let target = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind target listener");
        let dst = target.local_addr().expect("target addr");
        let accept_task = tokio::spawn(async move {
            let (mut socket, _) = target.accept().await.expect("accept target");
            let mut buf = [0u8; 64];
            let _ = socket.read(&mut buf).await;
            let _ = socket.shutdown().await;
        });

        let err = execute_single_strategy(
            &mut server,
            dst,
            &PassthroughStrategy,
            b"GET / HTTP/1.0\r\n\r\n",
            None,
            Duration::from_millis(500),
            None,
            WireMimicryMode::Disabled,
            None,
            None,
            "runtime_only",
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect_err("first response should fail");

        accept_task.await.expect("join target task");
        assert!(
            err.error
                .to_string()
                .starts_with("direct_first_response_eof:"),
            "unexpected error: {}",
            err.error
        );
        assert!(err.application_payload_may_have_been_sent);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn relay_client_reset_is_stage_prefixed() {
        let (client, mut ingress) = tcp_pair().await;
        let (mut remote_peer, mut remote) = tcp_pair().await;

        let close_client = tokio::spawn(async move {
            let std_client = client.into_std().expect("client into std");
            force_reset_on_close(&std_client);
            drop(std_client);
        });
        let remote_write = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = remote_peer.write_all(b"payload").await;
            let _ = remote_peer.shutdown().await;
        });

        let (err, _) = relay_bidirectional(&mut ingress, &mut remote)
            .await
            .expect_err("relay should fail on client reset");

        close_client.await.expect("join client close task");
        remote_write.await.expect("join remote write task");
        assert!(
            err.to_string().starts_with("direct_relay_client_read:"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn active_stall_probe_connect_refusal_reports_terminal_stage() {
        let closed = StdTcpListener::bind("127.0.0.1:0").expect("bind closed port");
        let dst = closed.local_addr().expect("closed port addr");
        drop(closed);

        let result = run_active_stall_probe(
            dst,
            b"GET / HTTP/1.0\r\n\r\n".to_vec(),
            super::ActiveStallProbeRun {
                // Winsock may delay loopback refusal by a TCP retry. The
                // separate timeout test retains its short deadline.
                timeout_limit: if cfg!(windows) {
                    Duration::from_secs(3)
                } else {
                    Duration::from_millis(300)
                },
                is_tls: false,
                freeze_threshold_bytes: 16 * 1024,
                degraded_latency_ms: 5000,
                stack: None,
                wire_mode: WireMimicryMode::Disabled,
                mimicry_ttl_hint: None,
                wire_window_preface: None,
                wire_observation_capture_confidence: "runtime_only",
                wire_window_profile: None,
                wire_observed_ipv4_header_shaping: None,
                wire_observed_negotiated_options: None,
                wire_observed_fragment_choreography: None,
                active_probe_plan: ActiveProbePlan {
                    preferred_ttl: 2,
                    budget: 3,
                    candidates: vec![2, 1, 3],
                },
            },
        )
        .await;

        #[cfg(not(windows))]
        assert_eq!(result.terminal_stage, Some("active_probe_connect_remote"));
        // The probe's 1500ms cap can expire before Winsock reports refusal.
        #[cfg(windows)]
        assert!(matches!(
            result.terminal_stage,
            Some("active_probe_connect_remote" | "active_probe_connect_timeout")
        ));
    }
}
