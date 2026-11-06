use crate::config::{TargetPolicyConfig, TransportConfig};
use crate::rate_limit::RateLimiter;
use crate::session::bundle_endpoint::BundleEndpointContext;
use crate::session::{benign_io_close, classify_connect_failure_status, TunnelAuthKeyring};
use aegis_core::auto_capture_probe;
use aegis_core::tunnel::{
    seal_tunnel_response, TunnelRequest, TunnelRequestKind, TunnelResponse, TunnelStatus,
};
use anyhow::Context;
use bytes::Bytes;
use http::{Method, Response};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::server::TlsStream;

#[cfg(test)]
#[path = "grpc/coop_h2_tests.rs"]
mod coop_h2_tests;
#[cfg(any(windows, test))]
mod coop_io;

/// Bound on a single inbound gRPC message.
///
/// The 5-byte gRPC prefix carries a 32-bit length, so an unbounded reader will
/// buffer toward 4 GiB on a peer's say-so — and the first message read on a
/// stream is the tunnel request, before the token is checked. Client data
/// frames are capped by `relay.policy.write_chunk_size` (16 KiB by default),
/// so 1 MiB leaves ample headroom.
const MAX_GRPC_MESSAGE_BYTES: usize = 1024 * 1024;

/// Hard ceiling on the tunnel-request message, checked before the AEAD open so
/// an unauthenticated peer cannot buy decryption work in bulk.
const MAX_TUNNEL_REQUEST_BYTES: usize = 8 * 1024;

#[derive(Clone)]
struct GrpcRequestContext {
    witness: Option<crate::phase_witness::ServerPhaseWitness>,
    bridge_activity: Option<super::https_bridge::Activity>,
    transport: TransportConfig,
    target_policy: TargetPolicyConfig,
    auth_keyring: TunnelAuthKeyring,
    rate_limiter: RateLimiter,
    peer: SocketAddr,
    bundle_ctx: Option<BundleEndpointContext>,
    admission: Option<super::AdmissionBudget>,
}

fn benign_h2_close(err: &anyhow::Error) -> bool {
    if benign_io_close(err) {
        return true;
    }
    err.chain().any(|cause| {
        cause
            .downcast_ref::<h2::Error>()
            .map(|h2_err| {
                h2_err
                    .reason()
                    .map(|reason| {
                        matches!(
                            reason,
                            h2::Reason::NO_ERROR | h2::Reason::CANCEL | h2::Reason::STREAM_CLOSED
                        )
                    })
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    })
}

#[allow(dead_code)] // Compatibility wrapper for a standalone connection owner.
pub async fn handle_grpc_session(
    tls: TlsStream<TcpStream>,
    auth_keyring: &TunnelAuthKeyring,
    transport: &TransportConfig,
    target_policy: &TargetPolicyConfig,
    rate_limiter: &RateLimiter,
    peer: SocketAddr,
    bundle_ctx: Option<&BundleEndpointContext>,
) -> anyhow::Result<()> {
    let mut owner = crate::lifecycle::TaskGroupRegistryOwner::new(auth_keyring.operational_log());
    let result = handle_grpc_session_with_owner(
        tls,
        auth_keyring,
        transport,
        target_policy,
        rate_limiter,
        peer,
        bundle_ctx,
        &owner.registry(),
        None,
    )
    .await;
    owner.shutdown().await;
    result
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_grpc_session_with_owner<
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
>(
    tls: S,
    auth_keyring: &TunnelAuthKeyring,
    transport: &TransportConfig,
    target_policy: &TargetPolicyConfig,
    rate_limiter: &RateLimiter,
    peer: SocketAddr,
    bundle_ctx: Option<&BundleEndpointContext>,
    request_registry: &crate::lifecycle::TaskGroupRegistry,
    witness: Option<&crate::phase_witness::ServerPhaseWitness>,
) -> anyhow::Result<()> {
    handle_grpc_session_with_admission(
        tls,
        auth_keyring,
        transport,
        target_policy,
        rate_limiter,
        peer,
        bundle_ctx,
        request_registry,
        witness,
        super::AdmissionBudget::new(std::time::Duration::from_millis(
            crate::config::ServerLimits::default().read_timeout_ms,
        )),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_grpc_session_with_admission<
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
>(
    tls: S,
    auth_keyring: &TunnelAuthKeyring,
    transport: &TransportConfig,
    target_policy: &TargetPolicyConfig,
    rate_limiter: &RateLimiter,
    peer: SocketAddr,
    bundle_ctx: Option<&BundleEndpointContext>,
    request_registry: &crate::lifecycle::TaskGroupRegistry,
    witness: Option<&crate::phase_witness::ServerPhaseWitness>,
    admission: super::AdmissionBudget,
) -> anyhow::Result<()> {
    let admission = if auth_keyring.https_bridge.is_some() {
        admission.bounded(super::https_bridge::ADMISSION_TIMEOUT)
    } else {
        admission
    };
    // Only the existing explicit witness opt-in allocates/updates diagnostics.
    // Disabled connections retain their original bare TLS stream type.
    if let Some(witness) = witness {
        handle_grpc_connection(
            witness.observe_io(tls),
            auth_keyring,
            transport,
            target_policy,
            rate_limiter,
            peer,
            bundle_ctx,
            request_registry,
            Some(witness),
            admission,
        )
        .await
    } else {
        handle_grpc_connection(
            tls,
            auth_keyring,
            transport,
            target_policy,
            rate_limiter,
            peer,
            bundle_ctx,
            request_registry,
            None,
            admission,
        )
        .await
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_grpc_connection<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    tls: S,
    auth_keyring: &TunnelAuthKeyring,
    transport: &TransportConfig,
    target_policy: &TargetPolicyConfig,
    rate_limiter: &RateLimiter,
    peer: SocketAddr,
    bundle_ctx: Option<&BundleEndpointContext>,
    request_registry: &crate::lifecycle::TaskGroupRegistry,
    witness: Option<&crate::phase_witness::ServerPhaseWitness>,
    admission: super::AdmissionBudget,
) -> anyhow::Result<()> {
    #[cfg(any(windows, test))]
    let tls = coop_io::ServerH2Io::new(tls);
    // SETTINGS_ENABLE_CONNECT_PROTOCOL. Without it a peer may not send
    // `:protocol`, so RFC 8441 WebSocket-over-h2 cannot be offered at all.
    //
    // This is what lets the https_ws transport stop being the only thing on
    // the wire that speaks ALPN `http/1.1`. Chrome offers `h2,http/1.1` and
    // sends ALPS; a client that must ask for http/1.1 alone is distinguishable
    // on the ClientHello before it sends a byte of payload.
    let mut builder = h2::server::Builder::new();
    // A CDN-fronted origin never advertises RFC 8441: the fronted carrier is
    // gRPC only, and the audited CDN edge does not offer Extended CONNECT.
    let fronted = auth_keyring.fronted_origin.is_some();
    if auth_keyring.https_bridge.is_none() && !fronted {
        builder.enable_connect_protocol();
    }
    // These limits apply before device/token authentication in every mode.
    builder
        .max_concurrent_streams(transport.h2_max_concurrent_streams)
        .max_header_list_size(8192)
        .initial_window_size(128 * 1024)
        .initial_connection_window_size(4 * 1024 * 1024)
        .max_send_buffer_size(128 * 1024)
        // Retain h2's bounded defaults for local reset history and protocol-error
        // resets (50 retained / 1024 errors with the locked h2 version).
        .max_pending_accept_reset_streams(8);
    let handshake = builder.handshake(tls);
    admission.check_deadline()?;
    let mut connection = tokio::time::timeout_at(admission.deadline, handshake)
        .await
        .context("h2 admission timed out")?
        .context("accept h2 session")?;
    admission.check_deadline()?;
    crate::phase_witness::note(witness, crate::phase_witness::ServerPhase::H2Established);
    // Drop cancels this connection's subset only. The combined server retains
    // join authority even if this handler is aborted during its final await.
    let requests = request_registry.register();
    let activity = super::https_bridge::Activity::default();
    let initial_deadline = admission.deadline;
    // A CDN multiplexes independent clients on one pooled origin connection.
    // There, the idle deadline drains with GOAWAY instead of aborting other
    // clients' in-flight streams, and each stream gets its own admission clock.
    let mut draining = false;
    let result = loop {
        let deadline = activity.deadline_with_timeout(initial_deadline, admission.timeout);
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(deadline.unwrap_or(initial_deadline)), if deadline.is_some() && !draining => {
                // Inner authentication can complete between constructing this
                // select and polling the timer. Only an actual lease suspends it.
                if activity.deadline_with_timeout(initial_deadline, admission.timeout)
                    .is_some_and(|at| tokio::time::Instant::now() >= at) {
                    if !fronted { break Ok(()); }
                    connection.graceful_shutdown();
                    draining = true;
                }
            }
            accepted = accept_h2(&mut connection, witness) => {
                let (request, respond) = match accepted {
                    Some(Ok(request)) => request,
                    Some(Err(error)) => break Err(error).context("accept h2 request"),
                    None => break Ok(()),
                };
                crate::phase_witness::note(witness, crate::phase_witness::ServerPhase::H2RequestReceived);
                let operational_log = auth_keyring.operational_log();
                // BundleEndpointContext is Arc-backed (cheap clone); its task
                // has the same connection lifetime as a gRPC/extended-CONNECT
                // request, rather than surviving as detached background work.
                let context = GrpcRequestContext {
                    witness: witness.cloned(),
                    bridge_activity: Some(activity.clone()),
                    transport: transport.clone(),
                    target_policy: target_policy.clone(),
                    auth_keyring: auth_keyring.clone(),
                    rate_limiter: rate_limiter.clone(),
                    peer,
                    bundle_ctx: bundle_ctx.cloned(),
                    admission: Some(if fronted {
                        admission.with_deadline(tokio::time::Instant::now() + admission.timeout)
                    } else {
                        admission.with_deadline(deadline.unwrap_or(tokio::time::Instant::now() + admission.timeout))
                    }),
                };
                requests.spawn(async move {
                    if let Err(e) = handle_single_grpc_request(request, respond, context).await {
                        if benign_h2_close(&e) {
                            tracing::debug!(event_code = "grpc_request_closed_benignly", "grpc request closed benignly");
                        } else {
                            crate::operational_log::warn_failure(
                                operational_log,
                                crate::operational_log::FailureStage::GrpcRequest,
                                crate::operational_log::FailureReason::RequestFailed,
                                Some(peer),
                                &e,
                            );
                        }
                    }
                });
            }
            joined = requests.join_next(), if !requests.is_empty() => {
                if let Some(Err(error)) = joined {
                    crate::operational_log::warn_failure(
                        auth_keyring.operational_log(),
                        crate::operational_log::FailureStage::H2RequestTask,
                        crate::operational_log::FailureReason::TaskFailed,
                        Some(peer),
                        &error,
                    );
                }
            }
        }
    };
    requests.shutdown().await;
    result
}

type H2Accepted = Option<
    Result<
        (
            http::Request<h2::RecvStream>,
            h2::server::SendResponse<Bytes>,
        ),
        h2::Error,
    >,
>;
async fn accept_h2<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    connection: &mut h2::server::Connection<S, Bytes>,
    witness: Option<&crate::phase_witness::ServerPhaseWitness>,
) -> H2Accepted {
    if let Some(witness) = witness {
        let mut observation = witness.observe_accept();
        std::future::poll_fn(|cx| {
            observation.poll_started();
            let result = connection.poll_accept(cx);
            observation.result(&result);
            result
        })
        .await
    } else {
        connection.accept().await
    }
}

#[cfg(test)]
#[path = "grpc/progress_witness_tests.rs"]
mod progress_witness_tests;

async fn handle_single_grpc_request(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    context: GrpcRequestContext,
) -> anyhow::Result<()> {
    let capture_proof_deadline = tokio::time::Instant::now()
        + std::time::Duration::from_secs(auto_capture_probe::MAX_SECONDS);
    let GrpcRequestContext {
        witness,
        bridge_activity,
        transport,
        target_policy,
        auth_keyring,
        rate_limiter,
        peer,
        bundle_ctx,
        admission,
    } = context;
    let admission = admission.unwrap_or_else(|| {
        super::AdmissionBudget::new(std::time::Duration::from_millis(
            crate::config::ServerLimits::default().read_timeout_ms,
        ))
    });
    admission.check_deadline()?;
    let rate_limit_identity = rate_limiter.http_identity(peer, request.headers());
    if let Some(identity) = rate_limit_identity {
        if rate_limiter.is_banned(identity).await {
            if auth_keyring.operational_log().includes_sensitive_context() {
                tracing::debug!(%peer, %identity, "banned HTTP client identity, dropping h2 request");
            } else {
                tracing::debug!(
                    event_code = "banned_http_identity_dropped",
                    "banned HTTP client identity dropped"
                );
            }
            return Ok(());
        }
    }

    if let Some(fronted) = &auth_keyring.fronted_origin {
        return match fronted.gate.route(&request) {
            Some(aegis_core::fronted_origin::Route::Traffic) => {
                let server = auth_keyring
                    .inner_tls
                    .clone()
                    .context("fronted origin inner TLS missing")?;
                crate::session::secure::handle_with_admission(
                    request,
                    respond,
                    server,
                    &target_policy,
                    &rate_limiter,
                    rate_limit_identity,
                    bridge_activity,
                    transport.authenticated_shaping.as_ref(),
                    auth_keyring.relay_training.as_deref(),
                    Some(admission),
                    auth_keyring.operational_log(),
                    true,
                )
                .await
            }
            Some(aegis_core::fronted_origin::Route::Enrollment) => match &fronted.forward {
                Some(forward) => forward.forward(request, respond).await,
                None => {
                    send_decoy(respond, peer);
                    Ok(())
                }
            },
            None => {
                send_decoy(respond, peer);
                Ok(())
            }
        };
    }

    if let Some(gate) = &auth_keyring.https_bridge {
        if gate.admits(&request, aegis_core::https_bridge::Purpose::Traffic) {
            let server = auth_keyring
                .inner_tls
                .clone()
                .context("bridge inner TLS missing")?;
            return crate::session::secure::handle_with_admission(
                request,
                respond,
                server,
                &target_policy,
                &rate_limiter,
                rate_limit_identity,
                bridge_activity,
                transport.authenticated_shaping.as_ref(),
                auth_keyring.relay_training.as_deref(),
                Some(admission),
                auth_keyring.operational_log(),
                false,
            )
            .await;
        }
        return super::https_bridge::respond_h2(respond, gate.site(&request)).await;
    }

    if request.uri().path() == aegis_core::secure_channel::GRPC_PATH {
        let server = auth_keyring
            .inner_tls
            .clone()
            .context("inner TLS is not enabled on this relay")?;
        return crate::session::secure::handle_with_admission(
            request,
            respond,
            server,
            &target_policy,
            &rate_limiter,
            rate_limit_identity,
            bridge_activity,
            transport.authenticated_shaping.as_ref(),
            auth_keyring.relay_training.as_deref(),
            Some(admission),
            auth_keyring.operational_log(),
            false,
        )
        .await;
    }

    // Cloudflare (and other CDNs) negotiate h2 to the origin, so a
    // `GET /bundle?token=...` arrives here rather than on the HTTP/1.1
    // path. Route it to the bundle endpoint BEFORE the gRPC path check so
    // the bundle is downloadable through a fronted edge without forcing
    // clients onto HTTP/1.1. gRPC paths are unaffected (a tunnel request
    // is POST to a gRPC path, never GET to the bundle prefix).
    if request.method() == Method::GET {
        if let Some(bctx) = bundle_ctx.as_ref() {
            if bctx.config.enabled
                && crate::session::bundle_endpoint::path_matches_prefix_public(
                    request.uri().path(),
                    &bctx.config.path_prefix,
                )
            {
                return crate::session::bundle_endpoint::handle_bundle_request_h2(
                    request,
                    &mut respond,
                    bctx,
                    peer,
                )
                .await;
            }
        }
    }

    // RFC 8441: `:method: CONNECT` with `:protocol: websocket`. The WebSocket
    // begins immediately after `:status: 200` — there is no HTTP/1.1 Upgrade
    // to accept — so the stream is wrapped directly with Role::Server.
    if request.method() == Method::CONNECT {
        let is_websocket = request
            .extensions()
            .get::<h2::ext::Protocol>()
            .is_some_and(|protocol| protocol.as_str().eq_ignore_ascii_case("websocket"));
        if is_websocket {
            if transport.secure_websocket_path.as_deref() == Some(request.uri().path()) {
                let response = Response::builder().status(200).body(())?;
                let send = respond.send_response(response, false)?;
                let stream = aegis_core::h2_stream::H2Stream::new(send, request.into_body());
                let ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
                    stream,
                    tokio_tungstenite::tungstenite::protocol::Role::Server,
                    Some(aegis_core::ws_io::bounded_config()),
                )
                .await;
                let carrier = aegis_core::ws_io::WsIo::new(ws);
                let server = auth_keyring
                    .inner_tls
                    .clone()
                    .context("secure websocket inner TLS missing")?;
                return crate::session::secure::serve_carrier_with_mode(
                    carrier,
                    server,
                    &target_policy,
                    &rate_limiter,
                    rate_limit_identity,
                    bridge_activity,
                    || Ok(()),
                    crate::session::secure::PrivacyMode::Relay(
                        transport.authenticated_shaping.as_ref(),
                        auth_keyring.relay_training.as_deref(),
                    ),
                    Some(admission),
                    auth_keyring.operational_log(),
                )
                .await;
            }
            if !transport.accepts_websocket_path(request.uri().path()) {
                let (resp, body) = crate::session::decoy::http2_response(peer.port());
                if let Ok(mut send) = respond.send_response(resp, false) {
                    let _ = send.send_data(body, true);
                }
                return Ok(());
            }
            let response = Response::builder().status(200).body(())?;
            let half_close = crate::session::websocket::websocket_half_close(request.headers());
            let send = respond.send_response(response, false)?;
            let stream = aegis_core::h2_stream::H2Stream::new(send, request.into_body());
            let ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
                stream,
                tokio_tungstenite::tungstenite::protocol::Role::Server,
                Some(crate::session::websocket::websocket_config()),
            )
            .await;
            return crate::session::websocket::run_websocket_tunnel_with_admission(
                ws,
                &auth_keyring,
                &target_policy,
                &rate_limiter,
                peer,
                rate_limit_identity,
                half_close,
                admission,
                bridge_activity,
            )
            .await;
        }
    }

    if !transport.accepts_grpc_path(request.uri().path()) {
        // Unknown h2 path (not a gRPC tunnel path, not the bundle endpoint):
        // a prober poking random h2 paths must see a generic web decoy, not a
        // bare AEGIS 404. Serve the same decoy shape as every other probe
        // surface.
        let (resp, body) = crate::session::decoy::http2_response(peer.port());
        if let Ok(mut send) = respond.send_response(resp, false) {
            let _ = send.send_data(body, true);
        }
        return Ok(());
    }

    let mut body = request.into_body();
    let mut recv_buf = Vec::new();
    admission.check_deadline()?;
    let frame = tokio::time::timeout_at(
        admission.deadline,
        read_grpc_message_limited(&mut body, &mut recv_buf, MAX_TUNNEL_REQUEST_BYTES),
    )
    .await
    .context("grpc admission timed out")??
    .ok_or_else(|| anyhow::anyhow!("missing grpc tunnel request"))?;
    admission.check_deadline()?;
    crate::phase_witness::note(
        witness.as_ref(),
        crate::phase_witness::ServerPhase::GrpcOpenReceived,
    );
    if frame.len() > MAX_TUNNEL_REQUEST_BYTES {
        if let Some(identity) = rate_limit_identity {
            rate_limiter.record_failure(identity).await;
        }
        anyhow::bail!(
            "grpc tunnel request too large: {} bytes (max {MAX_TUNNEL_REQUEST_BYTES})",
            frame.len()
        );
    }
    let authenticated = match auth_keyring.open_request_any(&frame) {
        Ok(authenticated) => authenticated,
        Err(err) => {
            if let Some(identity) = rate_limit_identity {
                rate_limiter.record_failure(identity).await;
            }
            return Err(err.into());
        }
    };
    let request_kind = authenticated.kind;
    admission.authenticated()?;
    let _activity = bridge_activity
        .as_ref()
        .map(super::https_bridge::Activity::authenticated);
    crate::phase_witness::note(
        witness.as_ref(),
        crate::phase_witness::ServerPhase::GrpcOpenValidated,
    );
    auth_keyring.log_accept(
        &authenticated.key,
        peer,
        match request_kind {
            TunnelRequestKind::Stream => "grpc_stream",
            TunnelRequestKind::Datagram => "grpc_datagram",
        },
    );
    let req = authenticated.request;
    let auth_token = authenticated.key.secret();

    let capture_proof = match request_kind {
        TunnelRequestKind::Stream => auto_capture_probe::tcp_target(&req.host, req.port),
        TunnelRequestKind::Datagram => auto_capture_probe::udp_target(&req.host, req.port),
    };
    if capture_proof {
        // The ordinary signed request authenticated the selected relay key.
        // This exact numeric tuple is a protocol witness: never resolve or
        // dial it, and never answer it before the existing auth gate.
        return run_grpc_capture_proof(
            body,
            recv_buf,
            respond,
            auth_token,
            request_kind,
            capture_proof_deadline,
        )
        .await;
    }

    match request_kind {
        TunnelRequestKind::Stream => {
            run_grpc_stream_tunnel(
                body,
                recv_buf,
                respond,
                req,
                auth_token,
                &target_policy,
                auth_keyring.operational_log(),
                witness.as_ref(),
            )
            .await
        }
        TunnelRequestKind::Datagram => {
            run_grpc_datagram_tunnel(
                body,
                recv_buf,
                respond,
                req,
                auth_token,
                &target_policy,
                transport.quic_max_idle_timeout_ms,
                auth_keyring.operational_log(),
                witness.as_ref(),
            )
            .await
        }
    }
}

/// The same public decoy as an unknown HTTP/2 path. No inner TLS byte,
/// enrollment forwarder or target is reached.
fn send_decoy(mut respond: h2::server::SendResponse<Bytes>, peer: SocketAddr) {
    let (resp, body) = crate::session::decoy::http2_response(peer.port());
    if let Ok(mut send) = respond.send_response(resp, body.is_empty()) {
        if !body.is_empty() {
            let _ = send.send_data(body, true);
        }
    }
}

async fn run_grpc_capture_proof(
    mut body: h2::RecvStream,
    mut recv_buf: Vec<u8>,
    mut respond: h2::server::SendResponse<Bytes>,
    auth_token: &[u8],
    kind: TunnelRequestKind,
    deadline: tokio::time::Instant,
) -> anyhow::Result<()> {
    tokio::time::timeout_at(deadline, async {
        let response = Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .body(())?;
        let mut send = respond.send_response(response, false)?;
        let accepted = seal_tunnel_response(
            &TunnelResponse {
                status: TunnelStatus::Ok,
                message: String::new(),
            },
            auth_token,
        )?;
        send_grpc_message(&mut send, &accepted, false).await?;
        let mut challenge = Vec::with_capacity(auto_capture_probe::CHALLENGE_BYTES);
        match kind {
            TunnelRequestKind::Datagram => {
                challenge = read_grpc_message_limited(
                    &mut body,
                    &mut recv_buf,
                    auto_capture_probe::CHALLENGE_BYTES,
                )
                .await?
                .context("native capture challenge missing")?;
                anyhow::ensure!(
                    challenge.len() == auto_capture_probe::CHALLENGE_BYTES,
                    "native capture datagram challenge length invalid"
                );
            }
            TunnelRequestKind::Stream => {
                // gRPC message boundaries are not TCP write boundaries. A
                // single ordinary write may arrive in several DATA messages.
                // Thirty-two one-byte messages are the maximum useful frames.
                for _ in 0..auto_capture_probe::CHALLENGE_BYTES {
                    let fragment = read_grpc_message_limited(
                        &mut body,
                        &mut recv_buf,
                        auto_capture_probe::CHALLENGE_BYTES,
                    )
                    .await?
                    .context("native capture stream challenge incomplete")?;
                    anyhow::ensure!(!fragment.is_empty(), "empty capture stream fragment");
                    anyhow::ensure!(
                        fragment.len() <= auto_capture_probe::CHALLENGE_BYTES - challenge.len(),
                        "capture stream challenge overflow"
                    );
                    challenge.extend_from_slice(&fragment);
                    if challenge.len() == auto_capture_probe::CHALLENGE_BYTES {
                        break;
                    }
                }
                anyhow::ensure!(
                    challenge.len() == auto_capture_probe::CHALLENGE_BYTES,
                    "capture stream challenge incomplete"
                );
            }
        }
        send_grpc_message(&mut send, &challenge, true).await?;
        anyhow::Ok(())
    })
    .await??;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_grpc_stream_tunnel(
    mut body: h2::RecvStream,
    mut recv_buf: Vec<u8>,
    mut respond: h2::server::SendResponse<Bytes>,
    req: TunnelRequest,
    auth_token: &[u8],
    target_policy: &TargetPolicyConfig,
    operational_log: crate::operational_log::OperationalLogPolicy,
    witness: Option<&crate::phase_witness::ServerPhaseWitness>,
) -> anyhow::Result<()> {
    let response = Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .body(())?;
    let mut send = respond.send_response(response, false)?;
    crate::phase_witness::note(
        witness,
        crate::phase_witness::ServerPhase::GrpcResponseHeadersQueued,
    );
    crate::phase_witness::note(
        witness,
        crate::phase_witness::ServerPhase::TargetDialStarted,
    );
    let mut remote = match crate::target_policy::connect_tcp_target_with_logging(
        &req.host,
        req.port,
        target_policy,
        operational_log,
    )
    .await
    {
        Ok(remote) => remote,
        Err(err) => {
            let frame = seal_tunnel_response(
                &TunnelResponse {
                    status: classify_connect_failure_status(&err),
                    message: "target_connect_failed".to_owned(),
                },
                auth_token,
            )?;
            send.send_data(grpc_frame(&frame), true)?;
            return Ok(());
        }
    };
    let ok = seal_tunnel_response(
        &TunnelResponse {
            status: TunnelStatus::Ok,
            message: String::new(),
        },
        auth_token,
    )?;
    send.send_data(grpc_frame(&ok), false)?;

    let (mut remote_read, mut remote_write) = remote.split();
    let grpc_to_target = async {
        loop {
            let msg = match read_grpc_message(&mut body, &mut recv_buf).await {
                Ok(Some(msg)) => msg,
                // A clean request END_STREAM is only a TCP write half-close;
                // the target may still send a delayed response afterward.
                Ok(None) => break,
                // A reset/connection error instead cancels both directions.
                // Turning a benign reset into Ok made try_join wait forever
                // for a silent target; the request logger still treats it as
                // benign after the sibling copy future is dropped.
                Err(err) => return Err(err),
            };
            if let Err(err) = remote_write.write_all(&msg).await {
                let err = anyhow::Error::from(err);
                if benign_io_close(&err) {
                    break;
                }
                return Err(err);
            }
        }
        let _ = remote_write.shutdown().await;
        anyhow::Ok(())
    };
    let target_to_grpc = async {
        let mut buf = [0u8; 16 * 1024];
        loop {
            let read = tokio::select! {
                read = remote_read.read(&mut buf) => read,
                reset = std::future::poll_fn(|cx| send.poll_reset(cx)) => {
                    // Keep observing cancellation even after the request body
                    // reached END_STREAM and its reader has finished. Waiting
                    // only on the target would strand that half-closed stream.
                    let reason = reset.context("grpc response stream closed")?;
                    return Err(h2::Error::from(reason).into());
                }
            };
            let n = match read {
                Ok(n) => n,
                Err(err) => {
                    let err = anyhow::Error::from(err);
                    if benign_io_close(&err) {
                        break;
                    }
                    return Err(err);
                }
            };
            if n == 0 {
                if let Err(err) = send.send_data(Bytes::new(), true) {
                    let err = anyhow::Error::from(err);
                    if !benign_h2_close(&err) {
                        return Err(err);
                    }
                }
                break;
            }
            if let Err(err) = send_grpc_message(&mut send, &buf[..n], false).await {
                if benign_h2_close(&err) {
                    break;
                }
                return Err(err);
            }
        }
        anyhow::Ok(())
    };
    tokio::try_join!(grpc_to_target, target_to_grpc)?;
    Ok(())
}

/// Message-preserving UDP relay over an ordinary gRPC HTTP/2 request.
/// Each gRPC message after the encrypted request is exactly one UDP datagram;
/// no destination information or AEGIS marker is visible outside TLS.
#[allow(clippy::too_many_arguments)]
async fn run_grpc_datagram_tunnel(
    mut body: h2::RecvStream,
    mut recv_buf: Vec<u8>,
    mut respond: h2::server::SendResponse<Bytes>,
    req: TunnelRequest,
    auth_token: &[u8],
    target_policy: &TargetPolicyConfig,
    idle_timeout_ms: u64,
    operational_log: crate::operational_log::OperationalLogPolicy,
    witness: Option<&crate::phase_witness::ServerPhaseWitness>,
) -> anyhow::Result<()> {
    let response = Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .body(())?;
    let mut send = respond.send_response(response, false)?;
    crate::phase_witness::note(
        witness,
        crate::phase_witness::ServerPhase::GrpcResponseHeadersQueued,
    );
    crate::phase_witness::note(
        witness,
        crate::phase_witness::ServerPhase::TargetDialStarted,
    );
    let remote = match connect_udp_target(&req, target_policy, operational_log).await {
        Ok(remote) => remote,
        Err(err) => {
            let frame = seal_tunnel_response(
                &TunnelResponse {
                    status: classify_connect_failure_status(&err),
                    message: "target_connect_failed".to_owned(),
                },
                auth_token,
            )?;
            send_grpc_message(&mut send, &frame, true).await?;
            return Ok(());
        }
    };
    let ok = seal_tunnel_response(
        &TunnelResponse {
            status: TunnelStatus::Ok,
            message: String::new(),
        },
        auth_token,
    )?;
    send_grpc_message(&mut send, &ok, false).await?;

    let mut udp_buf = vec![0u8; u16::MAX as usize + 1];
    loop {
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_millis(idle_timeout_ms.max(1))) => {
                let _ = send.send_data(Bytes::new(), true);
                break;
            }
            message = read_grpc_message(&mut body, &mut recv_buf) => {
                let payload = match message {
                    Ok(Some(payload)) => payload,
                    Ok(None) => {
                        let _ = send.send_data(Bytes::new(), true);
                        break;
                    }
                    Err(err) if benign_h2_close(&err) => break,
                    Err(err) => return Err(err),
                };
                if payload.len() > u16::MAX as usize {
                    anyhow::bail!("grpc datagram too large: {} bytes", payload.len());
                }
                remote.send(&payload).await.context("send UDP target datagram")?;
            }
            received = remote.recv(&mut udp_buf) => {
                let len = received.context("receive UDP target datagram")?;
                if let Err(err) = send_grpc_message(&mut send, &udp_buf[..len], false).await {
                    if benign_h2_close(&err) {
                        break;
                    }
                    return Err(err);
                }
            }
        }
    }
    Ok(())
}

async fn connect_udp_target(
    req: &TunnelRequest,
    target_policy: &TargetPolicyConfig,
    operational_log: crate::operational_log::OperationalLogPolicy,
) -> std::io::Result<UdpSocket> {
    let addresses = crate::target_policy::resolve_allowed_targets_with_logging(
        &req.host,
        req.port,
        target_policy,
        operational_log,
    )
    .await?;
    let mut last_error = None;
    for address in addresses {
        let bind_address = if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = match UdpSocket::bind(bind_address).await {
            Ok(socket) => socket,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        aegis_core::native_udp::prepare(&socket)?;
        match socket.connect(address).await {
            Ok(()) => return Ok(socket),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "target {}:{} has no connectable allowed addresses",
                req.host, req.port
            ),
        )
    }))
}

fn grpc_frame(payload: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(0);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Bytes::from(out)
}

/// Send a complete gRPC message under explicit HTTP/2 flow control. This
/// bounds per-stream buffering even when an authenticated client stops reading
/// while its stream or datagram target continues to send.
async fn send_grpc_message(
    send: &mut h2::SendStream<Bytes>,
    payload: &[u8],
    end_of_stream: bool,
) -> anyhow::Result<()> {
    let frame = grpc_frame(payload);
    send.reserve_capacity(frame.len());
    let mut offset = 0;
    while offset < frame.len() {
        let capacity = std::future::poll_fn(|cx| match send.poll_capacity(cx) {
            std::task::Poll::Ready(Some(Ok(0))) => std::task::Poll::Pending,
            other => other,
        })
        .await
        .ok_or_else(|| anyhow::anyhow!("grpc send stream closed while awaiting capacity"))??;
        let len = capacity.min(frame.len() - offset);
        let last = offset + len == frame.len();
        send.send_data(frame.slice(offset..offset + len), end_of_stream && last)
            .context("send grpc message data")?;
        offset += len;
    }
    Ok(())
}

async fn read_grpc_message(
    recv: &mut h2::RecvStream,
    pending: &mut Vec<u8>,
) -> anyhow::Result<Option<Vec<u8>>> {
    read_grpc_message_limited(recv, pending, MAX_GRPC_MESSAGE_BYTES).await
}

async fn read_grpc_message_limited(
    recv: &mut h2::RecvStream,
    pending: &mut Vec<u8>,
    maximum: usize,
) -> anyhow::Result<Option<Vec<u8>>> {
    loop {
        if pending.len() >= 5 {
            let len = u32::from_be_bytes([pending[1], pending[2], pending[3], pending[4]]) as usize;
            // The length prefix is attacker-controlled and 32-bit. Without a
            // bound, `pending` grows toward 4 GiB waiting for a message that
            // never arrives — and the first call here happens before the token
            // is verified.
            if pending[0] != 0 {
                anyhow::bail!("compressed grpc messages are unsupported");
            }
            if len > maximum {
                anyhow::bail!("grpc message length {len} exceeds {maximum}-byte limit");
            }
            if pending.len() >= 5 + len {
                let payload = pending[5..5 + len].to_vec();
                pending.drain(..5 + len);
                return Ok(Some(payload));
            }
        }
        let Some(chunk) = recv.data().await else {
            if !pending.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "incomplete gRPC message at END_STREAM",
                )
                .into());
            }
            return Ok(None);
        };
        let chunk = chunk.context("grpc body chunk")?;
        let chunk_len = chunk.len();
        // Parse the five-byte prefix before copying payload from this chunk.
        // An oversized request therefore needs no attacker-supplied body.
        let prefix_bytes = (5usize.saturating_sub(pending.len())).min(chunk_len);
        pending.extend_from_slice(&chunk[..prefix_bytes]);
        if pending.len() >= 5 {
            let length = u32::from_be_bytes(pending[1..5].try_into().unwrap()) as usize;
            if length > maximum {
                anyhow::bail!("grpc message length {length} exceeds {maximum}-byte limit");
            }
            if pending[0] != 0 {
                anyhow::bail!("compressed grpc messages are unsupported");
            }
        }
        pending.extend_from_slice(&chunk[prefix_bytes..]);
        // Return the window to the peer for the bytes we just took ownership of.
        //
        // This is the fix for the ~64 KiB upload stall: h2 hands out a fixed
        // receive window (65535 bytes by default) and only re-opens it when the
        // application releases capacity. Copying the chunk into `pending` and
        // never releasing meant the window closed for good once ~64 KiB had
        // been received, the client could not send another byte, and the
        // upload direction hung until a timeout — after the tunnel had already
        // been established, so it looked like a network fault rather than a bug.
        recv.flow_control()
            .release_capacity(chunk_len)
            .context("release h2 receive window")?;
    }
}

#[cfg(test)]
mod secure_tests;

#[cfg(test)]
mod https_bridge_tests;

#[cfg(test)]
mod preauth_tests;

#[cfg(test)]
mod adversarial_resource_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benign_h2_close_accepts_reset_reason() {
        assert!(benign_h2_close(&anyhow::Error::new(h2::Error::from(
            h2::Reason::CANCEL
        ))));
        assert!(!benign_h2_close(&anyhow::Error::from(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timeout"
        ))));
    }
}

#[cfg(test)]
#[path = "grpc/end_stream_tests.rs"]
mod end_stream_tests;

#[cfg(test)]
mod tcp_capacity_regression {
    use super::*;
    use std::time::Duration;
    use tokio::net::TcpListener;

    struct Owned<T>(tokio::task::JoinHandle<T>);
    impl<T> Drop for Owned<T> {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    impl<T> Owned<T> {
        async fn join(&mut self) -> T {
            tokio::time::timeout(Duration::from_secs(2), &mut self.0)
                .await
                .expect("owned fixture task join bounded")
                .expect("owned fixture task did not panic")
        }
        async fn stop(&mut self) {
            self.0.abort();
            match tokio::time::timeout(Duration::from_secs(2), &mut self.0)
                .await
                .expect("owned fixture abort joined")
            {
                Ok(_) => {}
                Err(e) => assert!(e.is_cancelled(), "owned driver cannot panic"),
            }
        }
    }

    #[tokio::test]
    async fn actual_tcp_response_retains_activity_until_h2_credit_and_exact_two_mib() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let expected: Vec<u8> = (0..2 * 1024 * 1024)
                .map(|i| ((i * 71 + i / 251) % 256) as u8).collect();
            let target_payload = expected.clone();
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await.expect("owned local target");
            let address = listener.local_addr().unwrap();
            let mut target = Owned(tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                socket.read_to_end(&mut request).await.unwrap();
                assert!(request.is_empty(), "clean request half-close reaches real target");
                socket.write_all(&target_payload).await.unwrap();
                socket.shutdown().await.unwrap();
                target_payload.len()
            }));
            let (client_io, server_io) = tokio::io::duplex(4096);
            let mut client_builder = h2::client::Builder::new();
            client_builder.initial_window_size(512);
            let (client_result, server_result) = tokio::join!(
                client_builder.handshake::<_, Bytes>(client_io),
                h2::server::handshake(server_io)
            );
            let (mut client, connection) = client_result.unwrap();
            let mut client_driver = Owned(tokio::spawn(async move { let _ = connection.await; }));
            let mut connection = server_result.unwrap();
            let (response, request_send) = client.send_request(
                http::Request::builder().uri("https://fixture.invalid/tcp")
                    .body(()).unwrap(), true
            ).unwrap();
            let (request, respond) = connection.accept().await.unwrap().unwrap();
            let mut server_driver = Owned(tokio::spawn(async move {
                while connection.accept().await.is_some() {}
            }));
            let activity = super::super::https_bridge::Activity::default();
            let lease = activity.authenticated();
            let initial = tokio::time::Instant::now();
            let key = [7u8; 32];
            let policy = TargetPolicyConfig {
                profile: crate::config::TargetPolicyProfile::FullVpnEgress,
                allowed_ports: vec![address.port()],
            };
            let mut relay = Owned(tokio::spawn(async move {
                // Actual request-local lease has the same lifetime as the actual
                // production TCP method. This seam does not claim auth admission.
                let _lease = lease;
                run_grpc_stream_tunnel(request.into_body(), Vec::new(), respond,
                    TunnelRequest {host: address.ip().to_string(), port: address.port()},
                    &key, &policy, Default::default(), None).await
            }));
            let mut body = response.await.unwrap().into_body();
            let mut pending = Vec::new();
            let ack = read_grpc_message(&mut body, &mut pending).await.unwrap().unwrap();
            assert_eq!(aegis_core::tunnel::open_tunnel_response(&ack, &key).unwrap().status,
                TunnelStatus::Ok);
            assert!(pending.is_empty(), "ACK parsing must not hide uncredited DATA");
            let held = body.data().await.unwrap().unwrap();
            assert!(!held.is_empty() && held.len() <= 512,
                "actual target DATA reached the closed-credit response window");
            // Do not release this chunk's capacity yet. Target DATA cannot drain.
            // Old unreserved TCP enqueue completes and drops the lease: that
            // actual completion is the causal failure, never a timeout as RED.
            let observed = tokio::time::timeout(Duration::from_millis(500), &mut relay.0).await;
            if let Ok(completed) = observed {
                completed.expect("old producer must not panic")
                    .expect("old enqueue completed without transport error");
                panic!("tcp_capacity_causal_failure: actual TCP producer completed while response credit was held");
            }
            assert!(activity.deadline_with_timeout(initial, Duration::from_secs(30)).is_none(),
                "authenticated activity must remain leased across actual credit wait");
            body.flow_control().release_capacity(held.len()).unwrap();
            pending.extend_from_slice(&held);
            let mut received = Vec::new();
            while let Some(message) = read_grpc_message(&mut body, &mut pending).await.unwrap() {
                received.extend_from_slice(&message);
                assert!(received.len() <= expected.len());
            }
            assert!(received == expected, "exact two MiB response and clean END_STREAM");
            relay.join().await.unwrap();
            assert_eq!(target.join().await, 2 * 1024 * 1024);
            assert!(activity.deadline_with_timeout(initial, Duration::from_secs(30)).is_some(),
                "lease releases only after bounded actual target transfer method completes");
            drop(body);drop(request_send);drop(client);
            server_driver.stop().await;client_driver.stop().await;
        }).await.expect("whole actual H2 and owned local target fixture bounded");
    }
}
