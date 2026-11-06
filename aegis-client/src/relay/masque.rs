use super::{
    format_authority_host, local_session_pre_open_aborted, policy, transport_authority_for_host,
};
use crate::ingress::UdpSessionControl;
use crate::runtime_event_stream as runtime_jsonl;
use crate::runtime_events::RuntimeEventCode;
use crate::socks5::{self, ConnectTarget, UdpPacket};
use aegis_core::tunnel::{open_tunnel_response, seal_tunnel_request, TunnelRequest, TunnelStatus};
use aegis_core::{build_connect_udp_path, RelaySettings};
use anyhow::Context;
use bytes::{Buf, Bytes};
use h3::error::{
    Code as H3Code, ConnectionError as H3ConnectionError, StreamError as H3StreamError,
};
use h3::ext::Protocol;
use h3_datagram::datagram_handler::HandleDatagramsExt;
use serde_json::json;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::Instant;

#[cfg(test)]
#[path = "masque_association_tests.rs"]
mod association_tests;

const MAX_ASSOCIATE_TARGETS: usize = 128;
const ASSOCIATE_FLOW_IDLE: Duration = Duration::from_secs(60);
const ASSOCIATE_SWEEP: Duration = Duration::from_secs(1);

struct AssociateFlowEntry {
    generation: u64,
    sender: mpsc::Sender<Vec<u8>>,
    last_activity: Instant,
    abort: tokio::task::AbortHandle,
}

struct TaggedAssociateDownlink {
    generation: u64,
    packet: UdpPacket,
}

enum AssociateQueueResult {
    Queued,
    Full,
    Closed,
}

fn queue_associate_payload(
    entry: &mut AssociateFlowEntry,
    payload: Vec<u8>,
) -> AssociateQueueResult {
    match entry.sender.try_send(payload) {
        Ok(()) => {
            entry.last_activity = Instant::now();
            AssociateQueueResult::Queued
        }
        Err(mpsc::error::TrySendError::Full(_)) => AssociateQueueResult::Full,
        Err(mpsc::error::TrySendError::Closed(_)) => AssociateQueueResult::Closed,
    }
}

fn accept_associate_downlink(
    tunnels: &mut HashMap<ConnectTarget, AssociateFlowEntry>,
    downlink: TaggedAssociateDownlink,
) -> Option<UdpPacket> {
    let entry = tunnels.get_mut(&downlink.packet.target)?;
    if entry.generation != downlink.generation {
        return None;
    }
    entry.last_activity = Instant::now();
    Some(downlink.packet)
}

pub(super) fn masque_transport_authority(
    settings: &RelaySettings,
) -> anyhow::Result<super::RelayTransportAuthority> {
    anyhow::ensure!(
        settings.outer_geneva.is_none(),
        "selected relay Geneva forbids the unsupported QUIC outer carrier"
    );
    let authority_host = settings
        .masque_server_name
        .as_deref()
        .filter(|name| !name.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| settings.server_name.clone());
    transport_authority_for_host(&authority_host, "masque_server_name")
}

fn benign_h3_stream_close(err: &anyhow::Error) -> bool {
    if super::benign_io_close(err) {
        return true;
    }
    err.chain().any(|cause| {
        if let Some(stream_err) = cause.downcast_ref::<H3StreamError>() {
            return stream_err.is_h3_no_error()
                || matches!(
                    stream_err,
                    H3StreamError::RemoteClosing
                        | H3StreamError::RemoteTerminate {
                            code: H3Code::H3_NO_ERROR
                        }
                );
        }
        if let Some(conn_err) = cause.downcast_ref::<H3ConnectionError>() {
            return conn_err.is_h3_no_error();
        }
        false
    })
}

fn emit_udp_datagram_stage(
    stage: &'static str,
    settings: &RelaySettings,
    target: &ConnectTarget,
    payload_len: usize,
) {
    let masque_server = settings
        .masque_server
        .as_deref()
        .unwrap_or(settings.server.as_str());
    let masque_server_name = masque_transport_authority(settings)
        .map(|authority| authority.authority_host)
        .unwrap_or_else(|_| settings.server_name.clone());
    tracing::info!(
        event_code = RuntimeEventCode::RelayUdpDatagramStage.as_str(),
        stage = stage,
        target = %target.host,
        port = target.port,
        relay_server = %masque_server,
        relay_server_name = %masque_server_name,
        masque_server = %masque_server,
        masque_server_name = %masque_server_name,
        payload_len = payload_len,
        "relay udp datagram stage"
    );
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::RelayUdpDatagramStage,
        "relay udp datagram stage",
        json!({
            "stage": stage,
            "target": target.host,
            "port": target.port,
            "relay_server": masque_server,
            "relay_server_name": masque_server_name,
            "masque_server": masque_server,
            "masque_server_name": masque_server_name,
            "payload_len": payload_len
        }),
    );
}

fn apply_chrome_quic_transport(transport: &mut quinn::TransportConfig) {
    let params = &aegis_chrome_profile::chrome_stable().quic.transport;
    if !params.apply {
        return;
    }
    let varint = |value: u64| quinn::VarInt::from_u64(value).ok();
    if let Some(value) = params.initial_max_data.and_then(varint) {
        transport.receive_window(value);
    }
    if let Some(value) = params.initial_max_stream_data.and_then(varint) {
        transport.stream_receive_window(value);
    }
    if let Some(value) = params.initial_max_streams_bidi.and_then(varint) {
        transport.max_concurrent_bidi_streams(value);
    }
    if let Some(value) = params.initial_max_streams_uni.and_then(varint) {
        transport.max_concurrent_uni_streams(value);
    }
}

pub(super) fn masque_transport_config(
    settings: &RelaySettings,
    keep_alive_override_ms: Option<u64>,
) -> anyhow::Result<Arc<quinn::TransportConfig>> {
    // Per-session soft-wire MASQUE keep-alive override takes precedence
    // over settings.masque_keep_alive_interval_ms when present, but is
    // re-clamped under settings.masque_max_idle_timeout_ms so the
    // operator's hard cap still wins.
    let configured_keep_alive_ms = keep_alive_override_ms
        .filter(|&value| value > 0)
        .unwrap_or(settings.masque_keep_alive_interval_ms);
    let keep_alive =
        (configured_keep_alive_ms > 0).then(|| Duration::from_millis(configured_keep_alive_ms));
    let idle_timeout = (settings.masque_max_idle_timeout_ms > 0)
        .then(|| Duration::from_millis(settings.masque_max_idle_timeout_ms));
    if let (Some(keep_alive), Some(idle_timeout)) = (keep_alive, idle_timeout) {
        anyhow::ensure!(
            keep_alive < idle_timeout,
            "relay.masque_keep_alive_interval_ms must be smaller than relay.masque_max_idle_timeout_ms"
        );
    }

    let mut transport = quinn::TransportConfig::default();
    apply_chrome_quic_transport(&mut transport);
    transport.keep_alive_interval(keep_alive);
    transport.max_idle_timeout(
        idle_timeout
            .map(|timeout| timeout.try_into())
            .transpose()
            .context("convert relay.masque_max_idle_timeout_ms to quinn idle timeout")?,
    );
    Ok(Arc::new(transport))
}

/// Close the per-session QUIC endpoint before waiting for its runtime to go
/// idle. Every MASQUE call creates a dedicated endpoint, so closing it cannot
/// affect another flow. Waiting without closing is a deadlock when QUIC
/// keepalives are enabled: the client task stays alive and the relay keeps one
/// connection permit (and one UDP socket) forever.
async fn close_masque_endpoint(endpoint: &quinn::Endpoint) {
    endpoint.close(quinn::VarInt::from_u32(0), b"session complete");
    let _ = tokio::time::timeout(Duration::from_secs(1), endpoint.wait_idle()).await;
}

/// Every attempt owns a dedicated endpoint. Async cleanup is not polled when
/// its caller is cancelled; closing from Drop also covers failed opening.
pub(super) struct CloseEndpointOnDrop(pub(super) quinn::Endpoint);

impl Drop for CloseEndpointOnDrop {
    fn drop(&mut self) {
        self.0.close(quinn::VarInt::from_u32(0), b"session ended");
    }
}

pub async fn run_masque_tunnel(
    local: &mut TcpStream,
    settings: &RelaySettings,
    profile: &super::policy::RelaySessionProfile,
    target_host: String,
    target_port: u16,
    initial_payload: Option<&[u8]>,
    counters: &super::RelaySessionCounters,
) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(settings.connect_timeout_ms);
    #[cfg(unix)]
    let local_fd = local.as_raw_fd();
    let opened = tokio::time::timeout_at(deadline, async {
        let authority = masque_transport_authority(settings)?;
        let mut client_config =
            super::masque_crypto::masque_quic_client_config(settings, &authority)?;
        // Per-session soft-wire plan (when configured): provides per-session
        // keep-alive override and UDP IP_TTL value applied after socket bind.
        let soft_wire_plan = super::policy::relay_soft_wire_plan(
            settings,
            Some((target_host.as_str(), target_port)),
            aegis_core::current_unix_secs(),
        );
        client_config.transport_config(masque_transport_config(
            settings,
            soft_wire_plan.and_then(|p| p.masque_keep_alive_ms),
        )?);

        let bind_addr = "[::]:0".parse().unwrap();
        let mut endpoint = quinn::Endpoint::client(bind_addr)?;
        let endpoint_guard = CloseEndpointOnDrop(endpoint.clone());
        endpoint.set_default_client_config(client_config);
        // Soft-wire UDP TTL: applied after Endpoint::client binds the UDP
        // socket so the QUIC initial datagram carries the chosen TTL. Emit
        // the per-session resolved plan as a relay_soft_wire_applied event
        // so wire diversity is observable in evidence captures alongside
        // the TCP transports.
        super::apply_soft_wire_plan_to_masque_endpoint(
            &endpoint,
            settings,
            Some((target_host.as_str(), target_port)),
            soft_wire_plan,
        );

        let server_addr = settings
            .masque_server
            .as_deref()
            .unwrap_or(&settings.server)
            .parse()
            .with_context(|| "parse masque/quic server addr")?;
        // Bound the QUIC dial by relay.connect_timeout_ms, like every other
        // transport. Without it an unreachable endpoint stalls here until quinn's
        // own idle timeout (relay.masque_max_idle_timeout_ms, 120s by default),
        // which blocks the endpoint loop in relay.rs from ever reaching the next
        // relay in the pool — measured on live hosts: 115s on a blackholed primary
        // and the second endpoint was never tried. The TCP transports short-circuit
        // in ~5s, so MASQUE alone defeated pool failover.
        let conn = endpoint
            .connect(server_addr, &authority.authority_host)?
            .await
            .context("quic connect")?;
        let quic = h3_quinn::Connection::new(conn);
        let mut builder = h3::client::builder();
        builder.enable_extended_connect(true).enable_datagram(true);
        let (_h3_conn, mut send_request) = builder.build::<_, _, Bytes>(quic).await?;

        if local_session_pre_open_aborted(local, initial_payload) {
            return Ok(None);
        }

        let req = TunnelRequest {
            host: target_host,
            port: target_port,
        };
        let target_authority = format_target_authority(&req.host, req.port);
        let mut request = http::Request::builder()
            // Standard CONNECT semantics for TCP path; AEGIS auth/ack stays in encrypted body frame.
            .method("CONNECT")
            .uri(format!("https://{target_authority}"))
            .body(())?;
        super::apply_masque_request_shape_headers(request.headers_mut(), profile)?;
        let mut req_stream = match send_request
            .send_request(request)
            .await
            .context("send h3 CONNECT request")
        {
            Ok(req_stream) => req_stream,
            Err(err) => {
                if local_session_pre_open_aborted(local, initial_payload) {
                    return Ok(None);
                }
                return Err(err);
            }
        };
        if let Err(err) = req_stream
            .send_data(Bytes::from(seal_tunnel_request(
                &req,
                settings.auth_token.as_bytes(),
            )?))
            .await
            .context("send h3 CONNECT tunnel request")
        {
            if local_session_pre_open_aborted(local, initial_payload) {
                return Ok(None);
            }
            return Err(err);
        }

        if local_session_pre_open_aborted(local, initial_payload) {
            return Ok(None);
        }

        let response = match req_stream
            .recv_response()
            .await
            .context("receive h3 CONNECT response")
        {
            Ok(response) => response,
            Err(err) => {
                if local_session_pre_open_aborted(local, initial_payload) {
                    return Ok(None);
                }
                return Err(err);
            }
        };
        if !response.status().is_success() {
            anyhow::bail!("h3 CONNECT status {}", response.status());
        }
        let resp_frame = req_stream
            .recv_data()
            .await
            .context("read h3 CONNECT tunnel response")?
            .ok_or_else(|| anyhow::anyhow!("h3 CONNECT closed before tunnel response"));
        let mut resp_frame = match resp_frame {
            Ok(resp_frame) => resp_frame,
            Err(err) => {
                if local_session_pre_open_aborted(local, initial_payload) {
                    return Ok(None);
                }
                return Err(err);
            }
        };
        let resp_frame = resp_frame.copy_to_bytes(resp_frame.remaining());
        let resp = open_tunnel_response(resp_frame.as_ref(), settings.auth_token.as_bytes())?;
        if resp.status != TunnelStatus::Ok {
            return Err(super::tunnel_response_error(
                "h3 CONNECT tunnel error",
                resp.status,
                resp.message,
            ));
        }
        anyhow::Ok(Some((
            req_stream,
            send_request,
            _h3_conn,
            endpoint,
            endpoint_guard,
        )))
    })
    .await
    .with_context(|| {
        format!(
            "masque tunnel establishment timed out after {}ms",
            settings.connect_timeout_ms
        )
    })??;
    let Some((req_stream, _send_request, _h3_conn, endpoint, _endpoint_guard)) = opened else {
        return Ok(());
    };
    counters.mark_opened();
    let (mut send_stream, mut recv_stream) = req_stream.split();
    if let Some(payload) = initial_payload.filter(|payload| !payload.is_empty()) {
        if let Err(err) = send_stream
            .send_data(Bytes::copy_from_slice(payload))
            .await
            .context("send prefetched h3 CONNECT data")
        {
            if benign_h3_stream_close(&err) {
                return Ok(());
            }
            return Err(err);
        }
        policy::maybe_delay(profile).await;
    }

    let (mut local_read, mut local_write) = tokio::io::split(local);
    let uplink = async {
        let mut buf = vec![0u8; policy::write_chunk_size(profile)];
        loop {
            let n = local_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            counters.add_sent(n);
            if let Err(err) = send_stream
                .send_data(Bytes::copy_from_slice(&buf[..n]))
                .await
                .context("send h3 CONNECT data")
            {
                if benign_h3_stream_close(&err) {
                    break;
                }
                return Err(err);
            }
            policy::maybe_delay(profile).await;
        }
        if let Err(err) = send_stream
            .finish()
            .await
            .context("finish h3 CONNECT request stream")
        {
            if !benign_h3_stream_close(&err) {
                return Err(err);
            }
        }
        anyhow::Ok(())
    };
    let downlink = async {
        loop {
            let next = match recv_stream
                .recv_data()
                .await
                .context("read h3 CONNECT data")
            {
                Ok(next) => next,
                Err(err) => {
                    if benign_h3_stream_close(&err) {
                        break;
                    }
                    return Err(err);
                }
            };
            let Some(mut chunk) = next else {
                break;
            };
            let chunk = chunk.copy_to_bytes(chunk.remaining());
            counters.add_received(chunk.len());
            if let Err(err) = local_write.write_all(chunk.as_ref()).await {
                #[cfg(unix)]
                if super::local_session_aborted_fd(local_fd) {
                    return Ok(());
                }
                return Err(err.into());
            }
        }
        anyhow::Ok(())
    };
    tokio::try_join!(uplink, downlink)?;
    close_masque_endpoint(&endpoint).await;
    Ok(())
}

pub async fn run_udp_association(
    control: UdpSessionControl,
    udp_socket: UdpSocket,
    settings: &RelaySettings,
    profile: &super::policy::RelaySessionProfile,
    family: super::TunnelTransportFamily,
    client_ip: IpAddr,
) -> anyhow::Result<()> {
    run_udp_association_observed(
        control,
        udp_socket,
        settings,
        profile,
        family,
        client_ip,
        #[cfg(test)]
        None,
    )
    .await
}

async fn run_udp_association_observed(
    control: UdpSessionControl,
    udp_socket: UdpSocket,
    settings: &RelaySettings,
    profile: &super::policy::RelaySessionProfile,
    family: super::TunnelTransportFamily,
    client_ip: IpAddr,
    #[cfg(test)] observation: Option<std::sync::Arc<association_tests::AssociationProbe>>,
) -> anyhow::Result<()> {
    let settings = settings.clone();
    let mut control_closed = std::pin::pin!(wait_for_udp_session_close(control));

    let (incoming_tx, mut incoming_rx) = mpsc::channel::<TaggedAssociateDownlink>(256);
    let mut recv_buf = vec![0u8; 65_535];
    let mut client_udp_peer: Option<SocketAddr> = None;
    let mut tunnels = HashMap::<ConnectTarget, AssociateFlowEntry>::new();
    let mut tasks = tokio::task::JoinSet::new();
    let mut generation = 0u64;
    let mut sweep = tokio::time::interval(ASSOCIATE_SWEEP);
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Consume the interval's immediate first tick. Idle lifetime begins at the
    // accepted datagram, not at association construction.
    sweep.tick().await;

    let session = async {
        loop {
            tokio::select! {
                biased;
                completed = tasks.join_next(), if !tasks.is_empty() => {
                    match completed {
                        Some(Ok((target, child_generation, result))) => {
                            let current_generation = tunnels
                                .get(&target)
                                .is_some_and(|entry| entry.generation == child_generation);
                            if current_generation {
                                tunnels.remove(&target);
                                #[cfg(test)]
                                if let Some(probe) = &observation {
                                    probe.retired(&target, child_generation);
                                }
                            }
                            if let Err(error) = result {
                                if current_generation {
                                    super::emit_udp_associate_target_failure(
                                        &settings,
                                        profile,
                                        family,
                                        &target,
                                        &error,
                                    );
                                }
                                tracing::warn!(
                                    event_code = "udp_associate_target_flow_failed",
                                    "connect-udp target flow ended"
                                );
                            }
                        }
                        Some(Err(error)) => {
                            let task_id = error.id();
                            tunnels.retain(|_target, entry| {
                                let retain = entry.abort.id() != task_id;
                                #[cfg(test)]
                                if !retain {
                                    if let Some(probe) = &observation { probe.retired(_target, entry.generation); }
                                }
                                retain
                            });
                            tracing::warn!(
                                event_code = "udp_associate_target_task_failed",
                                "connect-udp target task ended abnormally"
                            );
                        }
                        None => {}
                    }
                }
                _ = sweep.tick() => {
                    let now = Instant::now();
                    let expired: Vec<_> = tunnels
                        .iter()
                        .filter(|(_, entry)| now.duration_since(entry.last_activity) >= ASSOCIATE_FLOW_IDLE)
                        .map(|(target, entry)| (target.clone(), entry.generation))
                        .collect();
                    for (target, expired_generation) in expired {
                        if tunnels.get(&target).is_some_and(|entry| entry.generation == expired_generation) {
                            if let Some(entry) = tunnels.remove(&target) {
                                #[cfg(test)]
                                if let Some(probe) = &observation { probe.retired(&target, entry.generation); }
                                entry.abort.abort();
                            }
                        }
                    }
                }
                incoming = incoming_rx.recv() => {
                    let Some(downlink) = incoming else {
                        break;
                    };
                    let Some(packet) = accept_associate_downlink(&mut tunnels, downlink) else {
                        continue;
                    };
                    if let Some(peer) = client_udp_peer {
                        let out = socks5::encode_udp_packet(&packet.target, &packet.payload)?;
                        udp_socket.send_to(&out, peer).await?;
                    }
                }
                received = udp_socket.recv_from(&mut recv_buf) => {
                    let (n, peer) = received?;
                    if peer.ip() != client_ip {
                        continue;
                    }
                    if let Some(bound_peer) = client_udp_peer {
                        if bound_peer != peer {
                            continue;
                        }
                    }
                    let Ok(packet) = socks5::parse_udp_packet(&recv_buf[..n]) else {
                        continue;
                    };
                    if client_udp_peer.is_none() {
                        client_udp_peer = Some(peer);
                    }
                    let target = packet.target.clone();
                    #[cfg(test)]
                    let was_existing = tunnels.contains_key(&target);
                    let flow_generation = match tunnels.get_mut(&target) {
                        Some(entry) => entry.generation,
                        None => {
                            if tunnels.len() >= MAX_ASSOCIATE_TARGETS {
                                #[cfg(test)]
                                if let Some(probe) = &observation {
                                    probe.refused_at_cap(&target, tunnels.len());
                                }
                                continue;
                            }
                            let (tx, rx) = mpsc::channel(256);
                            let task_settings = settings.clone();
                            let task_target = packet.target.clone();
                            generation = generation.wrapping_add(1);
                            let task_generation = generation;
                            let task_incoming = incoming_tx.clone();
                            let abort = tasks.spawn(async move {
                                let mut rx = rx;
                                let (flow_downlink_tx, mut flow_downlink_rx) = mpsc::channel(1);
                                let flow_result = {
                                    let flow = super::run_relay_udp_associate_flow(
                                        task_settings,
                                        task_target.clone(),
                                        &mut rx,
                                        &flow_downlink_tx,
                                    );
                                    tokio::pin!(flow);
                                    loop {
                                        tokio::select! {
                                            result = &mut flow => break result,
                                            packet = flow_downlink_rx.recv() => {
                                                let Some(packet) = packet else {
                                                    break Err(anyhow::anyhow!("target downlink closed before flow"));
                                                };
                                                if task_incoming
                                                    .send(TaggedAssociateDownlink {
                                                        generation: task_generation,
                                                        packet,
                                                    })
                                                    .await
                                                    .is_err()
                                                {
                                                    break Err(anyhow::anyhow!("association downlink closed"));
                                                }
                                            }
                                        }
                                    }
                                };
                                drop(flow_downlink_tx);
                                let forward_result = async {
                                    while let Some(packet) = flow_downlink_rx.recv().await {
                                        task_incoming
                                            .send(TaggedAssociateDownlink {
                                                generation: task_generation,
                                                packet,
                                            })
                                            .await
                                            .map_err(|_| anyhow::anyhow!("association downlink closed"))?;
                                    }
                                    anyhow::Ok(())
                                }
                                .await;
                                let result = flow_result
                                    .and(forward_result)
                                    .map_err(|error| {
                                    anyhow::Error::new(super::UdpAssociateTunnelFailure {
                                        target: task_target.host.clone(),
                                        port: task_target.port,
                                        message: format!("{error:#}"),
                                    })
                                });
                                (task_target, task_generation, result)
                            });
                            tunnels.insert(target.clone(), AssociateFlowEntry {
                                generation: task_generation,
                                sender: tx,
                                last_activity: Instant::now(),
                                abort,
                            });
                            #[cfg(test)]
                            if let Some(probe) = &observation {
                                probe.admitted(&target, task_generation, tunnels.len());
                            }
                            task_generation
                        }
                    };
                    let queue_result = tunnels
                        .get_mut(&target)
                        .filter(|entry| entry.generation == flow_generation)
                        .map(|entry| queue_associate_payload(entry, packet.payload));
                    #[cfg(test)]
                    if was_existing && matches!(queue_result, Some(AssociateQueueResult::Queued)) {
                        if let Some(probe) = &observation {
                            probe.existing_queued(&target, flow_generation);
                        }
                    }
                    if matches!(queue_result, Some(AssociateQueueResult::Closed)) {
                        if let Some(entry) = tunnels.remove(&target) {
                            #[cfg(test)]
                            if let Some(probe) = &observation { probe.retired(&target, entry.generation); }
                            entry.abort.abort();
                        }
                    }
                }
            }
        }
        anyhow::Ok(())
    };
    // Cancellation must interrupt every stage, including opening a pool entry
    // or awaiting queue/socket capacity inside the session loop.
    let result = tokio::select! {
        biased;
        _ = &mut control_closed => {
            #[cfg(test)]
            if let Some(probe) = &observation { probe.control_closed(); }
            Ok(())
        },
        result = session => result,
    };
    drop(tunnels);
    tasks.shutdown().await;
    #[cfg(test)]
    if let Some(probe) = &observation {
        probe.shutdown_joined();
    }
    result
}

/// Outcome of a MASQUE direct UDP health check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasqueUdpHealth {
    pub ok: bool,
    pub target: String,
    pub detail: String,
}

/// Health-check the MASQUE direct CONNECT-UDP path for the `wide-udp-direct`
/// product mode: connect to the MASQUE endpoint, open CONNECT-UDP to a
/// controlled echo `target`, send a nonce datagram, and verify the echo.
///
/// On success emits `masque_udp_health_succeeded`; on any failure emits
/// `masque_udp_health_failed`. The caller MUST NOT fall back to native UDP on
/// failure — generic UDP stays blocked/fail-closed (the firewall already blocks
/// it; this check only decides whether MASQUE direct may additionally carry it).
pub async fn masque_udp_health_check(
    settings: &RelaySettings,
    target_host: &str,
    target_port: u16,
    nonce: &[u8],
) -> MasqueUdpHealth {
    let target = ConnectTarget {
        host: target_host.to_string(),
        port: target_port,
    };
    let target_label = format!("{target_host}:{target_port}");
    let profile = policy::build_session_profile_with_brain_bias(
        settings,
        Some((target_host, target_port)),
        Default::default(),
    );

    let result = run_masque_udp_datagram_once(settings, &profile, target, nonce).await;
    let health = match result {
        Ok(echo) if echo == nonce => MasqueUdpHealth {
            ok: true,
            target: target_label.clone(),
            detail: "connect-udp echo matched nonce".to_string(),
        },
        Ok(echo) => MasqueUdpHealth {
            ok: false,
            target: target_label.clone(),
            detail: format!(
                "connect-udp echo mismatch ({} bytes back, expected {})",
                echo.len(),
                nonce.len()
            ),
        },
        Err(e) => MasqueUdpHealth {
            ok: false,
            target: target_label.clone(),
            detail: format!("connect-udp failed: {e}"),
        },
    };
    let (level, code) = if health.ok {
        ("info", RuntimeEventCode::MasqueUdpHealthSucceeded)
    } else {
        ("warn", RuntimeEventCode::MasqueUdpHealthFailed)
    };
    runtime_jsonl::emit(
        level,
        code,
        "masque direct udp health check",
        json!({
            "target": health.target,
            "ok": health.ok,
            "detail": health.detail,
            "no_native_fallback": true,
        }),
    );
    health
}

#[cfg_attr(not(test), allow(dead_code))]
pub async fn run_masque_udp_datagram_once(
    settings: &RelaySettings,
    profile: &super::policy::RelaySessionProfile,
    target: ConnectTarget,
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(settings.connect_timeout_ms);
    let settings = settings.clone();
    emit_udp_datagram_stage("connect_start", &settings, &target, payload.len());
    let (endpoint, _endpoint_guard, req_stream, send_request, h3_conn) =
        tokio::time::timeout_at(deadline, async {
            // Same crypto seam as the CONNECT-TCP path: these two UDP paths used to
            // build their own rustls config and so kept a rustls ClientHello even when
            // the Chrome-like backend was selected.
            let authority = masque_transport_authority(&settings)?;
            let mut client_config =
                super::masque_crypto::masque_quic_client_config(&settings, &authority)?;
            client_config.transport_config(masque_transport_config(&settings, None)?);

            let bind_addr = "[::]:0".parse().unwrap();
            let mut endpoint = quinn::Endpoint::client(bind_addr)?;
            let endpoint_guard = CloseEndpointOnDrop(endpoint.clone());
            endpoint.set_default_client_config(client_config);

            let server_addr = settings
                .masque_server
                .as_deref()
                .unwrap_or(&settings.server)
                .parse()
                .with_context(|| "parse connect-udp server addr")?;
            let connecting = endpoint
                .connect(server_addr, &authority.authority_host)
                .context("start h3/masque connect")?;
            let conn = connecting.await.context("connect h3/masque server")?;
            emit_udp_datagram_stage("connect_ready", &settings, &target, payload.len());
            let quic = h3_quinn::Connection::new(conn);
            let mut builder = h3::client::builder();
            builder.enable_extended_connect(true).enable_datagram(true);
            let (h3_conn, mut send_request) = builder.build::<_, _, Bytes>(quic).await?;

            let authority = masque_authority(&settings)?;
            let path = build_connect_udp_path(&profile.masque_path, &target.host, target.port)?;
            let uri = format!("https://{}{}", authority, path);
            let mut request = http::Request::builder()
                .method("CONNECT")
                .uri(uri)
                .header("capsule-protocol", "?1")
                .header(
                    http::header::AUTHORIZATION,
                    connect_udp_credential(&settings, &target.host, target.port)?,
                )
                .body(())?;
            super::apply_masque_request_shape_headers(request.headers_mut(), profile)?;
            request.extensions_mut().insert(Protocol::CONNECT_UDP);

            let mut req_stream = send_request
                .send_request(request)
                .await
                .context("send connect-udp request")?;
            emit_udp_datagram_stage(
                "connect_udp_request_sent",
                &settings,
                &target,
                payload.len(),
            );
            let response = req_stream
                .recv_response()
                .await
                .context("receive connect-udp response")?;
            if !response.status().is_success() {
                anyhow::bail!("connect-udp status {}", response.status());
            }
            emit_udp_datagram_stage(
                "connect_udp_response_ready",
                &settings,
                &target,
                payload.len(),
            );
            anyhow::Ok((endpoint, endpoint_guard, req_stream, send_request, h3_conn))
        })
        .await
        .with_context(|| {
            format!(
                "masque datagram establishment timed out after {}ms",
                settings.connect_timeout_ms
            )
        })??;

    let stream_id = req_stream.id();
    let mut datagram_sender = h3_conn.get_datagram_sender(stream_id);
    let mut datagram_reader = h3_conn.get_datagram_reader();
    let response = async {
        datagram_sender
            .send_datagram(Bytes::from(encode_connect_udp_payload(payload)))
            .map_err(|e| anyhow::anyhow!("send connect-udp datagram: {e}"))?;
        emit_udp_datagram_stage(
            "connect_udp_datagram_sent",
            &settings,
            &target,
            payload.len(),
        );

        let response = tokio::time::timeout(
            std::time::Duration::from_millis(settings.connect_timeout_ms),
            async move {
                loop {
                    let datagram = datagram_reader
                        .read_datagram()
                        .await
                        .map_err(|e| anyhow::anyhow!("read connect-udp datagram: {e}"))?;
                    if datagram.stream_id() != stream_id {
                        continue;
                    }
                    return decode_connect_udp_payload(datagram.into_payload());
                }
            },
        )
        .await
        .context("receive connect-udp datagram timeout")??;
        emit_udp_datagram_stage(
            "connect_udp_response_received",
            &settings,
            &target,
            response.len(),
        );
        anyhow::Ok(response)
    }
    .await
    .map_err(super::udp_payload_committed)?;

    drop(req_stream);
    drop(datagram_sender);
    drop(send_request);
    drop(h3_conn);
    // A one-shot CONNECT-UDP owns its endpoint. Close it explicitly so the
    // relay releases the shared connection permit immediately instead of
    // relying on transport-idle semantics defeated by keepalives.
    close_masque_endpoint(&endpoint).await;
    Ok(response)
}

/// Forward a single datagram over MASQUE **direct** CONNECT-UDP for the wide
/// `udp_policy = masque_direct` send bridge, building the session profile
/// internally (the wide module cannot reach `relay::policy`). Returns the
/// relay-side response datagram on success.
///
/// This is the *send leg* of the wide UDP bridge: the NFQUEUE verdict layer
/// observes a generic UDP flow, DROPs the original packet (never a native
/// fallback), and hands the payload here. The response is proven at the relay
/// but is NOT injected back to the local app — NFQUEUE is verdict-only, so the
/// bridge is honestly send-only. The caller keeps the packet DROPped on every
/// outcome, success or failure.
#[allow(dead_code)]
pub async fn run_masque_udp_send(
    settings: &RelaySettings,
    target_host: &str,
    target_port: u16,
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let target = ConnectTarget {
        host: target_host.to_string(),
        port: target_port,
    };
    let profile = policy::build_session_profile_with_brain_bias(
        settings,
        Some((target_host, target_port)),
        Default::default(),
    );
    run_masque_udp_datagram_once(settings, &profile, target, payload).await
}

async fn wait_for_udp_session_close(control: UdpSessionControl) {
    match control {
        UdpSessionControl::SocksControl(mut control) => {
            let mut buf = [0u8; 256];
            loop {
                match control.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        }
        UdpSessionControl::Detached => std::future::pending::<()>().await,
    }
}

/// Persistent per-flow MASQUE CONNECT-UDP tunnel for the wide IPv6 TUN UDP leg.
/// ONE QUIC/CONNECT-UDP session per target flow, reused for EVERY datagram of the
/// flow (unlike the one-shot [`run_masque_udp_send`]) — required for multi-datagram
/// UDP (QUIC/HTTP3, real-time, VPN-in-UDP). Datagrams to send arrive on
/// `outbound_rx`; responses are pushed to `incoming_tx`. Returns when `outbound_rx`
/// closes (the engine drops the flow on idle) or the QUIC session ends.
// Test-only owning wrapper retained for the lifecycle regression; production
// full-wide callers use the generic policy failover entry point, which borrows
// the same receiver across MASQUE and gRPC attempts.
#[cfg(test)]
pub async fn run_masque_udp_flow(
    settings: &RelaySettings,
    target_host: &str,
    target_port: u16,
    mut outbound_rx: mpsc::Receiver<Vec<u8>>,
    incoming_tx: mpsc::Sender<UdpPacket>,
) -> anyhow::Result<()> {
    run_masque_udp_flow_borrowed(
        settings,
        target_host,
        target_port,
        &mut outbound_rx,
        &incoming_tx,
    )
    .await
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) async fn run_masque_udp_flow_borrowed(
    settings: &RelaySettings,
    target_host: &str,
    target_port: u16,
    outbound_rx: &mut mpsc::Receiver<Vec<u8>>,
    incoming_tx: &mpsc::Sender<UdpPacket>,
) -> anyhow::Result<()> {
    let profile = policy::build_session_profile_with_brain_bias(
        settings,
        Some((target_host, target_port)),
        Default::default(),
    );
    let target = ConnectTarget {
        host: target_host.to_string(),
        port: target_port,
    };
    run_single_connect_udp_tunnel(settings.clone(), profile, target, outbound_rx, incoming_tx).await
}

pub(super) async fn run_single_connect_udp_tunnel(
    settings: RelaySettings,
    profile: super::policy::RelaySessionProfile,
    target: ConnectTarget,
    outbound_rx: &mut mpsc::Receiver<Vec<u8>>,
    incoming_tx: &mpsc::Sender<UdpPacket>,
) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(settings.connect_timeout_ms);
    let (endpoint, _endpoint_guard, req_stream, send_request, h3_conn) =
        tokio::time::timeout_at(deadline, async {
            // Same crypto seam as the CONNECT-TCP path: these two UDP paths used to
            // build their own rustls config and so kept a rustls ClientHello even when
            // the Chrome-like backend was selected.
            let authority = masque_transport_authority(&settings)?;
            let mut client_config =
                super::masque_crypto::masque_quic_client_config(&settings, &authority)?;
            client_config.transport_config(masque_transport_config(&settings, None)?);

            let bind_addr = "[::]:0".parse().unwrap();
            let mut endpoint = quinn::Endpoint::client(bind_addr)?;
            let endpoint_guard = CloseEndpointOnDrop(endpoint.clone());
            endpoint.set_default_client_config(client_config);

            let server_addr = settings
                .masque_server
                .as_deref()
                .unwrap_or(&settings.server)
                .parse()
                .with_context(|| "parse connect-udp server addr")?;
            // Same bound as the other dials: an unreachable origin must fail fast so the
            // caller can move on, not hang until quinn's idle timeout.
            let conn = endpoint
                .connect(server_addr, &authority.authority_host)?
                .await
                .context("connect h3/masque server")?;
            let quic = h3_quinn::Connection::new(conn);
            let mut builder = h3::client::builder();
            builder.enable_extended_connect(true).enable_datagram(true);
            let (h3_conn, mut send_request) = builder.build::<_, _, Bytes>(quic).await?;

            let authority = masque_authority(&settings)?;
            let path = build_connect_udp_path(&profile.masque_path, &target.host, target.port)?;
            let uri = format!("https://{}{}", authority, path);
            let mut request = http::Request::builder()
                .method("CONNECT")
                .uri(uri)
                .header("capsule-protocol", "?1")
                .header(
                    http::header::AUTHORIZATION,
                    connect_udp_credential(&settings, &target.host, target.port)?,
                )
                .body(())?;
            super::apply_masque_request_shape_headers(request.headers_mut(), &profile)?;
            request.extensions_mut().insert(Protocol::CONNECT_UDP);

            let mut req_stream = send_request
                .send_request(request)
                .await
                .context("send connect-udp request")?;
            let response = req_stream
                .recv_response()
                .await
                .context("receive connect-udp response")?;
            if !response.status().is_success() {
                anyhow::bail!("connect-udp status {}", response.status());
            }
            anyhow::Ok((endpoint, endpoint_guard, req_stream, send_request, h3_conn))
        })
        .await
        .with_context(|| {
            format!(
                "masque datagram establishment timed out after {}ms",
                settings.connect_timeout_ms
            )
        })??;

    let stream_id = req_stream.id();
    let mut datagram_sender = h3_conn.get_datagram_sender(stream_id);
    let mut datagram_reader = h3_conn.get_datagram_reader();

    let mut payload_committed = false;
    let result = async {
    loop {
        tokio::select! {
            outbound = outbound_rx.recv() => {
                let Some(payload) = outbound else {
                    break;
                };
                payload_committed = true;
                datagram_sender
                    .send_datagram(Bytes::from(encode_connect_udp_payload(&payload)))
                    .map_err(|e| anyhow::anyhow!("send connect-udp datagram: {e}"))?;
            }
            datagram = datagram_reader.read_datagram() => {
                let datagram = datagram.map_err(|e| anyhow::anyhow!("read connect-udp datagram: {e}"))?;
                if datagram.stream_id() != stream_id {
                    continue;
                }
                let payload = decode_connect_udp_payload(datagram.into_payload())?;
                if incoming_tx.send(UdpPacket {
                    target: target.clone(),
                    payload,
                }).await.is_err() {
                    break;
                }
            }
        }
    }
    anyhow::Ok(())
    }.await;
    if let Err(err) = result {
        return Err(if payload_committed {
            super::udp_payload_committed(err)
        } else {
            err
        });
    }

    drop(req_stream);
    drop(datagram_sender);
    drop(datagram_reader);
    drop(send_request);
    drop(h3_conn);
    // `outbound_rx` closing is the full-wide flow teardown signal. Explicitly
    // close the dedicated QUIC endpoint before waiting; otherwise keepalive
    // traffic prevents `wait_idle()` from ever completing and leaks a relay
    // permit for every expired UDP flow.
    close_masque_endpoint(&endpoint).await;
    Ok(())
}

/// Seal a `TunnelRequest` for this CONNECT-UDP target and format it as an
/// `Authorization: Bearer` value.
///
/// The relay refuses CONNECT-UDP without a valid credential; without this the MASQUE
/// path would accept datagrams from any peer that knows the (compiled-in, public)
/// path, turning the relay into an open UDP proxy and a one-packet AEGIS oracle.
/// The host/port are bound into the sealed frame so a credential minted for one
/// target cannot be replayed onto another.
fn connect_udp_credential(
    settings: &RelaySettings,
    host: &str,
    port: u16,
) -> anyhow::Result<String> {
    let sealed = seal_tunnel_request(
        &TunnelRequest {
            host: host.to_string(),
            port,
        },
        settings.auth_token.as_bytes(),
    )?;
    Ok(format!("Bearer {}", hex::encode(sealed)))
}

fn encode_connect_udp_payload(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + payload.len());
    // Context ID 0 = raw UDP payloads.
    out.push(0);
    out.extend_from_slice(payload);
    out
}

fn decode_connect_udp_payload(payload: Bytes) -> anyhow::Result<Vec<u8>> {
    let bytes = payload.as_ref();
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if bytes[0] != 0 {
        anyhow::bail!("unsupported CONNECT-UDP context id");
    }
    Ok(bytes[1..].to_vec())
}

fn masque_authority(settings: &RelaySettings) -> anyhow::Result<String> {
    let port = masque_server_port(settings)?;
    let authority = masque_transport_authority(settings)?;
    let host = format_authority_host(&authority.authority_host);
    if port == 443 {
        Ok(host)
    } else {
        Ok(format!("{host}:{port}"))
    }
}

fn masque_server_port(settings: &RelaySettings) -> anyhow::Result<u16> {
    let raw = settings
        .masque_server
        .as_deref()
        .unwrap_or(&settings.server);
    if let Ok(addr) = raw.parse::<SocketAddr>() {
        return Ok(addr.port());
    }
    raw.rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .ok_or_else(|| anyhow::anyhow!("cannot determine MASQUE server port from {raw}"))
}

fn format_target_authority(host: &str, port: u16) -> String {
    format!("{}:{port}", format_authority_host(host))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio::time::{timeout, Duration};

    const OPEN_FIXTURE_MS: u64 = 3_000;

    struct LoopbackQuic {
        endpoint: quinn::Endpoint,
        settings: RelaySettings,
        cert_path: std::path::PathBuf,
    }

    impl LoopbackQuic {
        fn new() -> Self {
            use std::io::Write as _;
            static PREPARE_ROOTS: std::sync::Once = std::sync::Once::new();
            PREPARE_ROOTS.call_once(|| {
                drop(super::super::load_roots(None).expect("prepare native roots"));
            });
            let _ = rustls::crypto::ring::default_provider().install_default();
            let rcgen::CertifiedKey { cert, key_pair } =
                rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("fixture cert");
            let cert_path = std::env::temp_dir().join(format!(
                "aegis-masque-open-{}-{:016x}.pem",
                std::process::id(),
                rand::random::<u64>()
            ));
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&cert_path)
                .expect("create fixture CA")
                .write_all(cert.pem().as_bytes())
                .expect("write fixture CA");
            let mut crypto = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.der().clone()],
                    rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into(),
                )
                .expect("server TLS");
            crypto.alpn_protocols = vec![b"h3".to_vec()];
            let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
                .expect("server QUIC crypto");
            let endpoint = quinn::Endpoint::server(
                quinn::ServerConfig::with_crypto(Arc::new(crypto)),
                "127.0.0.1:0".parse().unwrap(),
            )
            .expect("ephemeral QUIC bind");
            let settings = RelaySettings {
                server: endpoint.local_addr().expect("fixture address").to_string(),
                server_name: "localhost".into(),
                ca_cert: Some(cert_path.clone()),
                auth_token: "loopback-masque-test-token".into(),
                connect_timeout_ms: OPEN_FIXTURE_MS,
                tls_backend: aegis_core::RelayTlsBackend::Rustls,
                ..Default::default()
            };
            Self {
                endpoint,
                settings,
                cert_path,
            }
        }

        async fn serve_stalled(
            &self,
            kind: OpeningKind,
            stage: QuicStage,
            ready: tokio::sync::oneshot::Sender<()>,
        ) {
            let conn = self
                .endpoint
                .accept()
                .await
                .expect("QUIC incoming")
                .await
                .expect("QUIC handshake");
            if matches!(stage, QuicStage::H3) {
                let _control = conn.accept_uni().await.expect("client H3 control stream");
                ready.send(()).expect("H3 stage counter");
                assert!(
                    matches!(
                        conn.closed().await,
                        quinn::ConnectionError::ApplicationClosed(_)
                    ),
                    "cancellation sends close on the owned endpoint"
                );
                return;
            }
            let quic = h3_quinn::Connection::new(conn.clone());
            let mut builder = h3::server::builder();
            builder.enable_extended_connect(true).enable_datagram(true);
            let mut h3 = builder.build::<_, Bytes>(quic).await.expect("server H3");
            let (request, mut stream) = h3
                .accept()
                .await
                .expect("accept H3")
                .expect("request resolver")
                .resolve_request()
                .await
                .expect("resolve request");
            assert_eq!(request.method(), http::Method::CONNECT);
            match kind {
                OpeningKind::Tcp => {
                    let mut frame = stream
                        .recv_data()
                        .await
                        .expect("open data")
                        .expect("open frame");
                    let frame = frame.copy_to_bytes(frame.remaining());
                    let open = aegis_core::tunnel::open_tunnel_request(
                        &frame,
                        self.settings.auth_token.as_bytes(),
                    )
                    .expect("authenticated TCP opening control");
                    assert_eq!(open.host, "127.0.0.1");
                }
                OpeningKind::Once | OpeningKind::Flow => {
                    assert_eq!(
                        request.extensions().get::<Protocol>(),
                        Some(&Protocol::CONNECT_UDP)
                    );
                    let credential = request.headers()[http::header::AUTHORIZATION]
                        .to_str()
                        .expect("credential header");
                    let sealed = hex::decode(
                        credential
                            .strip_prefix("Bearer ")
                            .expect("bearer credential"),
                    )
                    .expect("sealed credential");
                    let open = aegis_core::tunnel::open_tunnel_request(
                        &sealed,
                        self.settings.auth_token.as_bytes(),
                    )
                    .expect("authenticated UDP opening control");
                    assert_eq!(open.host, "127.0.0.1");
                }
            }
            if matches!(stage, QuicStage::Ack) {
                stream
                    .send_response(http::Response::new(()))
                    .await
                    .expect("send headers before stalled ack");
            }
            ready.send(()).expect("authenticated open stage counter");
            // Await peer's explicit endpoint close, not server idle expiry.
            assert!(matches!(
                conn.closed().await,
                quinn::ConnectionError::ApplicationClosed(_)
            ));
        }
    }

    impl Drop for LoopbackQuic {
        fn drop(&mut self) {
            self.endpoint
                .close(quinn::VarInt::from_u32(0), b"fixture complete");
            let _ = std::fs::remove_file(&self.cert_path);
        }
    }

    struct CancelTask(tokio::task::AbortHandle);
    impl Drop for CancelTask {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum OpeningKind {
        Tcp,
        Once,
        Flow,
    }
    #[derive(Clone, Copy, Debug)]
    enum QuicStage {
        H3,
        Headers,
        Ack,
    }

    async fn assert_masque_stalled(kind: OpeningKind, stage: QuicStage, cancel: bool) {
        timeout(Duration::from_secs(20), async {
            let relay = LoopbackQuic::new();
            let mut settings = relay.settings.clone();
            if cancel {
                settings.connect_timeout_ms = 60_000;
            }
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                relay.serve_stalled(kind, stage, ready_tx).await;
            });
            let _server_guard = CancelTask(server.abort_handle());
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("local app bind");
            let _peer = TcpStream::connect(listener.local_addr().expect("app address"))
                .await
                .expect("app connect");
            let (mut local, _) = listener.accept().await.expect("app accept");
            let (outbound_tx, mut outbound_rx) = mpsc::channel(1);
            outbound_tx
                .send(b"not sent before open".to_vec())
                .await
                .expect("queue payload");
            let (incoming_tx, _incoming_rx) = mpsc::channel(1);
            let counters = super::super::RelaySessionCounters::default();
            let task_counters = counters.clone();
            let client = tokio::spawn(async move {
                let profile = policy::RelaySessionProfile {
                    masque_path: "/loopback/udp".into(),
                    write_chunk_size: 4096,
                    ..Default::default()
                };
                let target = ConnectTarget {
                    host: "127.0.0.1".into(),
                    port: 43210,
                };
                let result = match kind {
                    OpeningKind::Tcp => {
                        run_masque_tunnel(
                            &mut local,
                            &settings,
                            &profile,
                            target.host,
                            target.port,
                            Some(b"not sent before open"),
                            &task_counters,
                        )
                        .await
                    }
                    OpeningKind::Once => run_masque_udp_datagram_once(
                        &settings,
                        &profile,
                        target,
                        b"not sent before open",
                    )
                    .await
                    .map(|_| ()),
                    OpeningKind::Flow => {
                        run_single_connect_udp_tunnel(
                            settings,
                            profile,
                            target,
                            &mut outbound_rx,
                            &incoming_tx,
                        )
                        .await
                    }
                };
                assert_eq!(
                    outbound_rx
                        .try_recv()
                        .expect("no payload consumed during open"),
                    b"not sent before open"
                );
                result
            });
            let _client_guard = CancelTask(client.abort_handle());
            if ready_rx.await.is_err() {
                let result = client.await;
                let peer = server.await;
                panic!("{kind:?}/{stage:?} intended QUIC/H3 stage not reached; client={result:#?}; peer={peer:#?}");
            }
            if cancel {
                client.abort();
                assert!(client.await.expect_err("cancelled client").is_cancelled());
            } else {
                let err = client
                    .await
                    .expect("client task")
                    .expect_err("opening timed out");
                assert!(
                    err.downcast_ref::<tokio::time::error::Elapsed>().is_some(),
                    "{kind:?}/{stage:?}: {err:#}"
                );
                assert!(
                    !super::super::udp_payload_was_committed(&err),
                    "opening control is not app payload"
                );
            }
            assert!(!counters.was_opened(), "pre-open failure does not mark TCP opened");
            server.await.expect("peer observed endpoint close");
        })
        .await
        .expect("MASQUE staged opening watchdog");
    }

    #[tokio::test]
    async fn masque_establishment_bounds_h3_and_headers_for_tcp_once_and_flow() {
        for kind in [OpeningKind::Tcp, OpeningKind::Once, OpeningKind::Flow] {
            for stage in [QuicStage::H3, QuicStage::Headers] {
                assert_masque_stalled(kind, stage, false).await;
            }
        }
        assert_masque_stalled(OpeningKind::Tcp, QuicStage::Ack, false).await;
    }

    #[tokio::test]
    async fn masque_establishment_cancellation_closes_each_owned_endpoint() {
        for kind in [OpeningKind::Tcp, OpeningKind::Once, OpeningKind::Flow] {
            assert_masque_stalled(kind, QuicStage::Headers, true).await;
        }
    }

    #[tokio::test]
    async fn masque_associate_control_close_and_cancellation_abort_opening_children() {
        for cancel in [false, true] {
            timeout(Duration::from_secs(20), async {
                let relay = LoopbackQuic::new();
                let mut settings = relay.settings.clone();
                settings.connect_timeout_ms = 60_000;
                settings.udp_transport_priority =
                    Some(vec![aegis_core::TunnelTransportFamily::MasqueDerived]);
                let unused_endpoint = UdpSocket::bind("127.0.0.1:0")
                    .await
                    .expect("second endpoint bind");
                settings.endpoints = [
                    settings.server.clone(),
                    unused_endpoint.local_addr().unwrap().to_string(),
                ]
                .into_iter()
                .map(|server| aegis_core::RelayEndpointSettings {
                    server,
                    server_name: "localhost".into(),
                    masque_server: None,
                    masque_server_name: None,
                })
                .collect();
                let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
                let server = tokio::spawn(async move {
                    relay
                        .serve_stalled(OpeningKind::Flow, QuicStage::Headers, ready_tx)
                        .await;
                });
                let _server_guard = CancelTask(server.abort_handle());
                let listener = TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("control bind");
                let control_peer = TcpStream::connect(listener.local_addr().unwrap())
                    .await
                    .expect("control connect");
                let (control, _) = listener.accept().await.expect("control accept");
                let udp = UdpSocket::bind("127.0.0.1:0")
                    .await
                    .expect("associate bind");
                let address = udp.local_addr().unwrap();
                let peer = UdpSocket::bind("127.0.0.1:0").await.expect("UDP app bind");
                let client = tokio::spawn(async move {
                    run_udp_association(
                        UdpSessionControl::SocksControl(control),
                        udp,
                        &settings,
                        &policy::RelaySessionProfile::default(),
                        aegis_core::TunnelTransportFamily::MasqueDerived,
                        "127.0.0.1".parse().unwrap(),
                    )
                    .await
                });
                let _client_guard = CancelTask(client.abort_handle());
                let packet = socks5::encode_udp_packet(
                    &ConnectTarget {
                        host: "127.0.0.1".into(),
                        port: 43210,
                    },
                    b"queued-before-open",
                )
                .unwrap();
                peer.send_to(&packet, address)
                    .await
                    .expect("first datagram");
                ready_rx
                    .await
                    .expect("child reached authenticated opening headers");
                if cancel {
                    client.abort();
                    assert!(client.await.expect_err("cancel associate").is_cancelled());
                    drop(control_peer);
                } else {
                    drop(control_peer);
                    client
                        .await
                        .expect("associate task")
                        .expect("control-close shutdown");
                }
                server
                    .await
                    .expect("child QUIC endpoint closed, not detached");
                let mut buf = [0u8; 2048];
                assert!(
                    timeout(
                        Duration::from_millis(80),
                        unused_endpoint.recv_from(&mut buf)
                    )
                    .await
                    .is_err(),
                    "closed association must not dial the next pool entry"
                );
            })
            .await
            .expect("owned ASSOCIATE children watchdog");
        }
    }

    #[tokio::test]
    async fn masque_udp_payload_error_is_not_retryable_or_flow_lifetime_limited() {
        for one_shot in [false, true] {
            timeout(Duration::from_secs(20), async {
                let relay = LoopbackQuic::new();
                let settings = relay.settings.clone();
                let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
                let server = tokio::spawn(async move {
                    let conn = relay
                        .endpoint
                        .accept()
                        .await
                        .expect("incoming")
                        .await
                        .expect("QUIC");
                    let mut builder = h3::server::builder();
                    builder.enable_extended_connect(true).enable_datagram(true);
                    let mut h3 = builder
                        .build::<_, Bytes>(h3_quinn::Connection::new(conn.clone()))
                        .await
                        .expect("H3");
                    let (request, mut stream) = h3
                        .accept()
                        .await
                        .expect("accept")
                        .expect("resolver")
                        .resolve_request()
                        .await
                        .expect("request");
                    let credential = request.headers()[http::header::AUTHORIZATION]
                        .to_str()
                        .expect("credential");
                    let sealed = hex::decode(credential.strip_prefix("Bearer ").expect("bearer"))
                        .expect("sealed credential");
                    aegis_core::tunnel::open_tunnel_request(
                        &sealed,
                        relay.settings.auth_token.as_bytes(),
                    )
                    .expect("authenticated UDP request");
                    stream
                        .send_response(http::Response::new(()))
                        .await
                        .expect("accept open");
                    let mut reader = h3.get_datagram_reader();
                    let datagram = reader.read_datagram().await.expect("application datagram");
                    assert_eq!(datagram.stream_id(), stream.id());
                    assert_eq!(
                        decode_connect_udp_payload(datagram.into_payload()).expect("context zero"),
                        b"one application datagram"
                    );
                    seen_tx.send(()).expect("payload stage counter");
                    if !one_shot {
                        tokio::time::sleep(Duration::from_millis(OPEN_FIXTURE_MS + 100)).await;
                    }
                    conn.close(quinn::VarInt::from_u32(1), b"fixture post-payload failure");
                });
                let _guard = CancelTask(server.abort_handle());
                let (outbound_tx, mut outbound_rx) = mpsc::channel(1);
                outbound_tx
                    .send(b"one application datagram".to_vec())
                    .await
                    .expect("queue payload");
                let (incoming_tx, _incoming_rx) = mpsc::channel(1);
                let profile = policy::RelaySessionProfile {
                    masque_path: "/loopback/udp".into(),
                    ..Default::default()
                };
                let target = ConnectTarget {
                    host: "127.0.0.1".into(),
                    port: 43210,
                };
                let result = if one_shot {
                    run_masque_udp_datagram_once(
                        &settings,
                        &profile,
                        target,
                        b"one application datagram",
                    )
                    .await
                    .map(|_| ())
                } else {
                    run_single_connect_udp_tunnel(
                        settings,
                        profile,
                        target,
                        &mut outbound_rx,
                        &incoming_tx,
                    )
                    .await
                };
                seen_rx
                    .await
                    .expect("payload reached authenticated relay exactly once");
                let err = result.expect_err("post-payload failure");
                assert!(super::super::udp_payload_was_committed(&err), "{err:#}");
                if !one_shot {
                    assert!(
                        err.downcast_ref::<tokio::time::error::Elapsed>().is_none(),
                        "opening deadline is not flow lifetime"
                    );
                }
                server.await.expect("server completed");
            })
            .await
            .expect("post-payload failure watchdog");
        }
    }

    #[tokio::test]
    async fn masque_tcp_authenticated_stream_transfers_after_opening_deadline() {
        timeout(Duration::from_secs(20), async {
            let relay = LoopbackQuic::new();
            let settings = relay.settings.clone();
            let server = tokio::spawn(async move {
                let conn = relay
                    .endpoint
                    .accept()
                    .await
                    .expect("incoming")
                    .await
                    .expect("QUIC");
                let mut builder = h3::server::builder();
                builder.enable_extended_connect(true).enable_datagram(true);
                let mut h3 = builder
                    .build::<_, Bytes>(h3_quinn::Connection::new(conn.clone()))
                    .await
                    .expect("H3");
                let (_request, mut stream) = h3
                    .accept()
                    .await
                    .expect("accept")
                    .expect("resolver")
                    .resolve_request()
                    .await
                    .expect("request");
                let mut control = stream
                    .recv_data()
                    .await
                    .expect("read open")
                    .expect("open frame");
                let control = control.copy_to_bytes(control.remaining());
                aegis_core::tunnel::open_tunnel_request(
                    &control,
                    relay.settings.auth_token.as_bytes(),
                )
                .expect("authenticated open");
                stream
                    .send_response(http::Response::new(()))
                    .await
                    .expect("headers");
                let ack = aegis_core::tunnel::seal_tunnel_response(
                    &aegis_core::tunnel::TunnelResponse {
                        status: TunnelStatus::Ok,
                        message: String::new(),
                    },
                    relay.settings.auth_token.as_bytes(),
                )
                .expect("authenticated open ack");
                stream.send_data(Bytes::from(ack)).await.expect("send ack");
                for expected in [b"initial".as_slice(), b"late after deadline".as_slice()] {
                    let mut received = Vec::new();
                    while received.len() < expected.len() {
                        let mut chunk = stream
                            .recv_data()
                            .await
                            .expect("read data")
                            .expect("data present");
                        received.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
                    }
                    assert_eq!(received, expected, "each payload arrives once and in order");
                    stream
                        .send_data(Bytes::from(received))
                        .await
                        .expect("echo payload");
                }
                assert!(stream
                    .recv_data()
                    .await
                    .expect("local END_STREAM")
                    .is_none());
                stream.finish().await.expect("finish response");
                let _ = conn.closed().await;
            });
            let _server_guard = CancelTask(server.abort_handle());
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("app bind");
            let mut peer = TcpStream::connect(listener.local_addr().expect("app address"))
                .await
                .expect("connect app");
            let (mut local, _) = listener.accept().await.expect("accept app");
            let counters = super::super::RelaySessionCounters::default();
            let task_counters = counters.clone();
            let client = tokio::spawn(async move {
                run_masque_tunnel(
                    &mut local,
                    &settings,
                    &policy::RelaySessionProfile {
                        write_chunk_size: 4096,
                        ..Default::default()
                    },
                    "127.0.0.1".into(),
                    43210,
                    Some(b"initial"),
                    &task_counters,
                )
                .await
            });
            let _client_guard = CancelTask(client.abort_handle());
            let mut initial = [0u8; 7];
            peer.read_exact(&mut initial).await.expect("initial echo");
            assert_eq!(&initial, b"initial");
            assert!(
                counters.was_opened(),
                "authenticated open prevents TCP replay"
            );
            tokio::time::sleep(Duration::from_millis(OPEN_FIXTURE_MS + 100)).await;
            assert!(
                !client.is_finished(),
                "authenticated stream outlives opening deadline"
            );
            peer.write_all(b"late after deadline")
                .await
                .expect("late send");
            let mut late = [0u8; 19];
            peer.read_exact(&mut late).await.expect("late echo");
            assert_eq!(&late, b"late after deadline");
            peer.shutdown().await.expect("app half close");
            client
                .await
                .expect("client task")
                .expect("successful stream");
            server.await.expect("peer closes after final data");
        })
        .await
        .expect("successful MASQUE stream watchdog");
    }

    #[test]
    fn benign_h3_stream_close_accepts_no_error_variants() {
        assert!(benign_h3_stream_close(&anyhow::Error::new(
            H3StreamError::RemoteClosing
        )));
        assert!(benign_h3_stream_close(&anyhow::Error::new(
            H3StreamError::RemoteTerminate {
                code: H3Code::H3_NO_ERROR
            }
        )));
        assert!(benign_h3_stream_close(&anyhow::Error::from(
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof")
        )));
        assert!(!benign_h3_stream_close(&anyhow::Error::new(
            H3ConnectionError::Timeout
        )));
    }

    #[test]
    fn masque_transport_config_rejects_keepalive_not_below_idle_timeout() {
        let settings = RelaySettings {
            masque_keep_alive_interval_ms: 1_000,
            masque_max_idle_timeout_ms: 1_000,
            ..RelaySettings::default()
        };
        let err =
            masque_transport_config(&settings, None).expect_err("invalid keepalive/idle contract");
        assert!(
            err.to_string()
                .contains("relay.masque_keep_alive_interval_ms must be smaller"),
            "{err:#}"
        );
    }

    #[test]
    fn separate_masque_server_preserves_backward_compatible_relay_authority() {
        let settings = RelaySettings {
            server_name: "front.example.test".into(),
            masque_server: Some("203.0.113.10:8443".into()),
            ..RelaySettings::default()
        };
        let authority = masque_transport_authority(&settings).expect("MASQUE authority");
        assert_eq!(authority.authority_host, "front.example.test");
        assert!(authority.send_sni);
    }

    #[test]
    fn explicit_ip_masque_server_name_suppresses_sni() {
        let settings = RelaySettings {
            server_name: "front.example.test".into(),
            masque_server: Some("203.0.113.10:8443".into()),
            masque_server_name: Some("203.0.113.10".into()),
            ..RelaySettings::default()
        };
        let authority = masque_transport_authority(&settings).expect("MASQUE authority");
        assert_eq!(authority.authority_host, "203.0.113.10");
        assert!(!authority.send_sni);
    }

    #[test]
    fn explicit_masque_server_name_wins_over_derived_ip() {
        let settings = RelaySettings {
            server_name: "front.example.test".into(),
            masque_server: Some("203.0.113.10:8443".into()),
            masque_server_name: Some("masque.example.test".into()),
            ..RelaySettings::default()
        };
        let authority = masque_transport_authority(&settings).expect("MASQUE authority");
        assert_eq!(authority.authority_host, "masque.example.test");
        assert!(authority.send_sni);
    }

    #[tokio::test]
    async fn detached_udp_session_control_stays_open() {
        let result = timeout(
            Duration::from_millis(50),
            wait_for_udp_session_close(UdpSessionControl::Detached),
        )
        .await;
        assert!(result.is_err(), "detached UDP session closed unexpectedly");
    }

    #[tokio::test]
    async fn socks_udp_session_control_closes_on_peer_disconnect() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let client = TcpStream::connect(addr).await.expect("connect client");
        let (server, _) = listener.accept().await.expect("accept server");
        drop(client);

        timeout(
            Duration::from_secs(1),
            wait_for_udp_session_close(UdpSessionControl::SocksControl(server)),
        )
        .await
        .expect("socks UDP session should close after peer disconnect");
    }
}
