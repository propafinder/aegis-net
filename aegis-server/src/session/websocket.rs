use crate::config::{TargetPolicyConfig, TransportConfig};
use crate::rate_limit::RateLimiter;
use crate::session::{benign_io_close, classify_connect_failure_status, TunnelAuthKeyring};
use aegis_core::tunnel::{
    seal_tunnel_response, TunnelResponse, TunnelStatus, WEBSOCKET_HALF_CLOSE_HEADER,
    WEBSOCKET_HALF_CLOSE_MODE,
};
use anyhow::Context;
use futures::{SinkExt, StreamExt};
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::accept_hdr_async_with_config;
use tokio_tungstenite::tungstenite::error::ProtocolError;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::tungstenite::Message;

/// Bound on a single inbound WebSocket message and frame.
///
/// tungstenite defaults to 64 MiB per message / 16 MiB per frame. The first
/// message on this socket is the tunnel request, read *before* the token is
/// verified — so with the default limits any unauthenticated peer that
/// completes a WebSocket handshake can make the server buffer 64 MiB, and
/// `limits.max_connections` of them can do it at once. At the default cap of
/// 1000 connections that is ~64 GiB of attacker-controlled allocation with no
/// credential at all.
///
/// 1 MiB is far above anything the protocol needs. The tunnel request is a few
/// hundred bytes, and client data frames are capped by
/// `relay.policy.write_chunk_size`, which defaults to 16 KiB and acts as a hard
/// cap on the sampled chunk size — so this leaves 64x headroom for an operator
/// who raises it, while cutting the pre-auth exposure by the same factor.
const MAX_WEBSOCKET_MESSAGE_BYTES: usize = 1024 * 1024;

/// Hard ceiling on the tunnel-request frame specifically.
///
/// Checked before the frame is handed to the AEAD open, so a peer cannot make
/// the server do authenticated-decryption work over a megabyte of garbage. A
/// sealed request is host + port + nonce + tag; 8 KiB is generous.
const MAX_TUNNEL_REQUEST_BYTES: usize = 8 * 1024;

pub(crate) fn websocket_half_close(headers: &http::HeaderMap) -> bool {
    headers
        .get(WEBSOCKET_HALF_CLOSE_HEADER)
        .is_some_and(|value| value.as_bytes() == WEBSOCKET_HALF_CLOSE_MODE.as_bytes())
}

pub(crate) fn websocket_config() -> tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
    tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
        max_message_size: Some(MAX_WEBSOCKET_MESSAGE_BYTES),
        max_frame_size: Some(MAX_WEBSOCKET_MESSAGE_BYTES),
        // Unlimited by default. Bounded so a peer that stops reading cannot
        // make the server accumulate an unbounded write buffer either.
        max_write_buffer_size: MAX_WEBSOCKET_MESSAGE_BYTES * 2,
        ..Default::default()
    }
}

fn benign_websocket_close(err: &WsError) -> bool {
    matches!(
        err,
        WsError::ConnectionClosed
            | WsError::AlreadyClosed
            | WsError::Protocol(ProtocolError::SendAfterClosing)
    ) || matches!(
        err,
        WsError::Io(io)
            if matches!(
                io.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::NotConnected
            )
    )
}

#[allow(clippy::too_many_arguments, clippy::result_large_err)]
pub(crate) async fn handle_websocket_session_with_admission<S>(
    stream: &mut S,
    auth_keyring: &TunnelAuthKeyring,
    transport: &TransportConfig,
    target_policy: &TargetPolicyConfig,
    rate_limiter: &RateLimiter,
    peer: SocketAddr,
    rate_limit_identity: Option<IpAddr>,
    admission: super::AdmissionBudget,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    admission.check_deadline()?;
    crate::operational_log::debug_peer_event(
        auth_keyring.operational_log(),
        "websocket_upgrade_starting",
        peer,
        "websocket accept_async starting",
    );
    let mut half_close = false;
    let ws = tokio::time::timeout_at(
        admission.deadline,
        accept_hdr_async_with_config(
            stream,
            |request: &Request, response: Response| {
                half_close = websocket_half_close(request.headers());
                validate_websocket_request_path(request, response, transport, peer.port())
            },
            Some(websocket_config()),
        ),
    )
    .await
    .context("websocket upgrade admission timed out")?
    .context("accept websocket tunnel")?;
    admission.check_deadline()?;
    crate::operational_log::debug_peer_event(
        auth_keyring.operational_log(),
        "websocket_upgrade_accepted",
        peer,
        "websocket accept_async succeeded; waiting for tunnel request",
    );
    run_websocket_tunnel_with_admission(
        ws,
        auth_keyring,
        target_policy,
        rate_limiter,
        peer,
        rate_limit_identity,
        half_close,
        admission,
        None,
    )
    .await
}

/// The tunnel itself, once a WebSocket exists.
///
/// Split out so the RFC 8441 path can reuse it: over HTTP/2 there is no
/// HTTP/1.1 Upgrade to accept — the WebSocket starts immediately after the
/// `:status: 200` — so that path builds the stream with
/// `from_raw_socket(Role::Server)` and joins here.
#[cfg(test)]
pub(crate) async fn run_websocket_tunnel<S>(
    ws: tokio_tungstenite::WebSocketStream<S>,
    auth_keyring: &TunnelAuthKeyring,
    target_policy: &TargetPolicyConfig,
    rate_limiter: &RateLimiter,
    peer: SocketAddr,
    rate_limit_identity: Option<IpAddr>,
    half_close: bool,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    run_websocket_tunnel_with_admission(
        ws,
        auth_keyring,
        target_policy,
        rate_limiter,
        peer,
        rate_limit_identity,
        half_close,
        super::AdmissionBudget::new(std::time::Duration::from_millis(
            crate::config::ServerLimits::default().read_timeout_ms,
        )),
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_websocket_tunnel_with_admission<S>(
    ws: tokio_tungstenite::WebSocketStream<S>,
    auth_keyring: &TunnelAuthKeyring,
    target_policy: &TargetPolicyConfig,
    rate_limiter: &RateLimiter,
    peer: SocketAddr,
    rate_limit_identity: Option<IpAddr>,
    half_close: bool,
    admission: super::AdmissionBudget,
    activity: Option<super::https_bridge::Activity>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    admission.check_deadline()?;
    if let Some(identity) = rate_limit_identity {
        if rate_limiter.is_banned(identity).await {
            crate::operational_log::debug_peer_identity_event(
                auth_keyring.operational_log(),
                "websocket_banned_identity_dropped",
                peer,
                identity,
                "banned HTTP client identity; dropping websocket request",
            );
            return Ok(());
        }
    }
    let (mut ws_tx, mut ws_rx) = ws.split();

    admission.check_deadline()?;
    let first = tokio::time::timeout_at(admission.deadline, ws_rx.next())
        .await
        .context("websocket tunnel admission timed out")?
        .ok_or_else(|| anyhow::anyhow!("websocket closed before tunnel request"))??;
    admission.check_deadline()?;
    let Message::Binary(frame) = first else {
        anyhow::bail!("expected websocket binary tunnel request");
    };
    if frame.len() > MAX_TUNNEL_REQUEST_BYTES {
        // Refuse before the AEAD open: an unauthenticated peer should not be
        // able to buy authenticated-decryption work by the megabyte.
        if let Some(identity) = rate_limit_identity {
            rate_limiter.record_failure(identity).await;
        }
        anyhow::bail!(
            "websocket tunnel request too large: {} bytes (max {MAX_TUNNEL_REQUEST_BYTES})",
            frame.len()
        );
    }
    let authenticated = match auth_keyring.open_request(&frame) {
        Ok(authenticated) => authenticated,
        Err(err) => {
            if let Some(identity) = rate_limit_identity {
                rate_limiter.record_failure(identity).await;
            }
            return Err(err.into());
        }
    };
    admission.authenticated()?;
    auth_keyring.log_accept(&authenticated.key, peer, "websocket");
    let _activity = activity
        .as_ref()
        .map(super::https_bridge::Activity::authenticated);
    let req = authenticated.request;
    let auth_token = authenticated.key.secret();

    let mut remote = match crate::target_policy::connect_tcp_target_with_logging(
        &req.host,
        req.port,
        target_policy,
        auth_keyring.operational_log(),
    )
    .await
    {
        Ok(remote) => remote,
        Err(err) => {
            let status = classify_connect_failure_status(&err);
            let frame = seal_tunnel_response(
                &TunnelResponse {
                    status,
                    message: "target_connect_failed".to_owned(),
                },
                auth_token,
            )?;
            ws_tx.send(Message::Binary(frame)).await?;
            let _ = ws_tx.close().await;
            return Ok(());
        }
    };

    let ok = seal_tunnel_response(
        &TunnelResponse {
            status: TunnelStatus::Ok,
            message: if half_close {
                WEBSOCKET_HALF_CLOSE_MODE.into()
            } else {
                String::new()
            },
        },
        auth_token,
    )?;
    ws_tx.send(Message::Binary(ok)).await?;

    let (mut remote_read, mut remote_write) = remote.split();
    let ws_to_target = async {
        while let Some(msg) = ws_rx.next().await {
            let msg = match msg {
                Ok(msg) => msg,
                Err(err) => {
                    if benign_websocket_close(&err) {
                        break;
                    }
                    return Err(anyhow::Error::from(err));
                }
            };
            match msg {
                Message::Binary(data) => {
                    if half_close && data.is_empty() {
                        break;
                    }
                    if let Err(err) = remote_write.write_all(&data).await {
                        let err = anyhow::Error::from(err);
                        if benign_io_close(&err) {
                            break;
                        }
                        return Err(err);
                    }
                }
                Message::Close(_) => break,
                Message::Ping(_) | Message::Pong(_) => {}
                _ => {}
            }
        }
        let _ = remote_write.shutdown().await;
        anyhow::Ok(())
    };
    let target_to_ws = async {
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = match tokio::io::AsyncReadExt::read(&mut remote_read, &mut buf).await {
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
                if half_close {
                    ws_tx.send(Message::Binary(Vec::new())).await?;
                } else {
                    let _ = ws_tx.close().await;
                }
                break;
            }
            if let Err(err) = ws_tx.send(Message::Binary(buf[..n].to_vec())).await {
                if benign_websocket_close(&err) {
                    break;
                }
                return Err(err.into());
            }
        }
        anyhow::Ok(())
    };
    tokio::try_join!(ws_to_target, target_to_ws)?;
    // tungstenite flushes Close frames without closing its AsyncWrite. Send
    // the carrier FIN/END_STREAM before dropping it; an implicit H2 reset can
    // otherwise overtake the queued Close and turn graceful EOF into CANCEL.
    let mut ws = ws_tx
        .reunite(ws_rx)
        .map_err(|_| anyhow::anyhow!("websocket stream halves do not match"))?;
    if half_close {
        let _ = ws.close(None).await;
        // Preserve the H2 carrier until the peer consumed response EOF. Its
        // receive handle otherwise sends a reset that can overtake final DATA.
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            while let Some(message) = ws.next().await {
                match message {
                    Ok(Message::Close(_)) => break,
                    Ok(Message::Ping(_) | Message::Pong(_)) => {}
                    Err(error) if benign_websocket_close(&error) => break,
                    Err(error) => return Err(error.into()),
                    Ok(_) => anyhow::bail!("websocket data after directional EOF"),
                }
            }
            anyhow::Ok(())
        })
        .await
        .context("websocket close handshake deadline")??;
    }
    // Transfer errors have already propagated; the peer can close its carrier
    // as soon as the WebSocket handshake completes, so final FIN is best effort.
    let _ = ws.get_mut().shutdown().await;
    Ok(())
}

#[allow(clippy::result_large_err)]
fn validate_websocket_request_path(
    request: &Request,
    response: Response,
    transport: &TransportConfig,
    seed: u16,
) -> Result<Response, ErrorResponse> {
    if transport.accepts_websocket_path(request.uri().path()) {
        return Ok(response);
    }

    // Active-probing hardening: a wrong/unknown WebSocket path (a prober
    // sending an Upgrade to a path we don't tunnel on) must look like a stock
    // web server rejecting an unknown resource — NOT leak the AEGIS-specific
    // "websocket path not allowed" tell. Draw the rejection from the SAME
    // seed-indexed decoy deck (seed = peer source port) used by every other
    // probe path, so a prober poking an unknown HTTP path and a bad WS upgrade
    // on one connection sees one consistent origin (matching Server header and
    // authentic error body), not two contradicting servers.
    let (status, server, body) = super::decoy::reject_parts(seed);
    let mut builder = http::Response::builder()
        .status(status)
        .header("server", server);
    if body.is_some() {
        builder = builder.header("content-type", "text/html");
    }
    Err(builder
        .body(body)
        .expect("valid websocket rejection response"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TransportConfig;
    use http::Request as HttpRequest;
    use tokio_tungstenite::tungstenite::http::StatusCode;

    #[test]
    fn benign_websocket_close_accepts_send_after_closing() {
        assert!(benign_websocket_close(&WsError::Protocol(
            ProtocolError::SendAfterClosing
        )));
        assert!(benign_websocket_close(&WsError::ConnectionClosed));
        assert!(benign_websocket_close(&WsError::AlreadyClosed));
    }

    #[test]
    fn validate_websocket_request_path_accepts_pool_entries() {
        let transport = TransportConfig::default();
        let request = HttpRequest::builder()
            .uri("/socket")
            .body(())
            .expect("request");
        let mut response = http::Response::new(());
        *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;

        let accepted = validate_websocket_request_path(&request, response, &transport, 1234);
        assert!(accepted.is_ok());
    }

    #[test]
    fn validate_websocket_request_path_rejects_unknown_entries() {
        let transport = TransportConfig::default();
        let request = HttpRequest::builder()
            .uri("/not-allowed")
            .body(())
            .expect("request");
        let mut response = http::Response::new(());
        *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;

        // Seed 1 → decoy deck variant (403 Forbidden, nginx/1.24.0). The reject
        // must draw from the SAME central decoy deck as every other probe path,
        // not a hardcoded stub, so all endpoints on one connection agree.
        let seed = 1u16;
        let (want_status, want_server, want_body) = crate::session::decoy::reject_parts(seed);
        let rejected = validate_websocket_request_path(&request, response, &transport, seed)
            .expect_err("unexpected websocket path should be rejected");
        assert_eq!(rejected.status().as_u16(), want_status);
        assert_eq!(
            rejected
                .headers()
                .get("server")
                .map(|v| v.to_str().unwrap()),
            Some(want_server)
        );
        assert_eq!(rejected.body().clone(), want_body);
        // Never the old hardcoded non-authentic stub.
        assert_ne!(
            rejected.body().as_deref(),
            Some("<html><body>Not Found</body></html>")
        );
    }
}
