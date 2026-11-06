use super::tls_backend::connect_tls_with_negotiated_alpn;
use super::{
    format_authority_host, local_session_pre_open_aborted, policy, relay_transport_authority,
};
use aegis_core::tunnel::{
    open_tunnel_response, seal_tunnel_request, TunnelRequest, TunnelStatus,
    WEBSOCKET_HALF_CLOSE_HEADER, WEBSOCKET_HALF_CLOSE_MODE,
};
use aegis_core::RelaySettings;
use anyhow::Context;
use futures::{SinkExt, StreamExt};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::client_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::error::ProtocolError;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

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

/// The relay answered the extended CONNECT with a non-200: it does not
/// implement RFC 8441. Distinguished from a transient failure so the caller
/// can refuse to change its ClientHello — see the fallback comment below.
#[derive(Debug)]
struct ExtendedConnectRefused(http::StatusCode);

impl std::fmt::Display for ExtendedConnectRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "relay refused extended CONNECT: status {}", self.0)
    }
}

impl std::error::Error for ExtendedConnectRefused {}

struct H2Driver(Option<tokio::task::AbortHandle>);

impl H2Driver {
    fn disarm(&mut self) {
        self.0.take();
    }
}

impl Drop for H2Driver {
    fn drop(&mut self) {
        if let Some(driver) = self.0.take() {
            driver.abort();
        }
    }
}

/// RFC 8441: WebSocket carried over one HTTP/2 stream via extended CONNECT.
///
/// There is no HTTP/1.1 Upgrade here — the WebSocket begins immediately after
/// `:status: 200`, so the stream is wrapped with `Role::Client` directly.
async fn websocket_over_h2(
    tls: super::tls_backend::RelayTlsStream,
    authority_host: &str,
    websocket_path: &str,
) -> anyhow::Result<(
    tokio_tungstenite::WebSocketStream<super::tls_backend::RelayTlsStream>,
    H2Driver,
)> {
    let (mut client, connection) = super::surface::chrome_like_h2_builder()
        .handshake(tls)
        .await
        .context("h2 handshake for websocket transport")?;
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let driver = H2Driver(Some(driver.abort_handle()));

    let mut request = http::Request::builder()
        .method(http::Method::CONNECT)
        // RFC 8441 section 5 retains the RFC 6455 version negotiation.
        // HTTP/2-to-HTTP/1 proxies need this when constructing Upgrade.
        .header(http::header::SEC_WEBSOCKET_VERSION, "13")
        .header(WEBSOCKET_HALF_CLOSE_HEADER, WEBSOCKET_HALF_CLOSE_MODE)
        .uri(format!(
            "https://{}{}",
            format_authority_host(authority_host),
            websocket_path
        ))
        .body(())
        .context("build extended CONNECT request")?;
    super::order_headers_like_chrome(request.headers_mut());
    request
        .extensions_mut()
        .insert(h2::ext::Protocol::from("websocket"));

    let (response, send) = client
        .send_request(request, false)
        .context("send extended CONNECT")?;
    let response = response.await.context("extended CONNECT response")?;
    if response.status() != http::StatusCode::OK {
        return Err(ExtendedConnectRefused(response.status()).into());
    }
    // Boxed as the same RelayTlsStream the HTTP/1.1 path yields, so both
    // branches produce one type and the tunnel loop below is shared.
    let stream: super::tls_backend::RelayTlsStream = Box::new(
        aegis_core::h2_stream::H2Stream::new(send, response.into_body()),
    );
    Ok((
        tokio_tungstenite::WebSocketStream::from_raw_socket(
            stream,
            tokio_tungstenite::tungstenite::protocol::Role::Client,
            None,
        )
        .await,
        driver,
    ))
}

pub async fn run_websocket_tunnel(
    local: &mut TcpStream,
    settings: &RelaySettings,
    profile: &super::policy::RelaySessionProfile,
    target_host: String,
    target_port: u16,
    initial_payload: Option<&[u8]>,
    counters: &super::RelaySessionCounters,
) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now()
        .checked_add(std::time::Duration::from_millis(
            settings.connect_timeout_ms,
        ))
        .context("websocket opening timeout is out of range")?;
    #[cfg(unix)]
    let local_fd = local.as_raw_fd();
    // A single absolute deadline includes every opening stage and the existing
    // retry. Application payload and the established stream are outside it.
    let opened = tokio::time::timeout_at(deadline, async {
        let tcp = super::geneva_outer::connect(settings)
            .await
            .with_context(|| format!("connect websocket relay {}", settings.server))?;
        super::apply_soft_wire_plan_to_stream(
            &tcp,
            settings,
            Some((target_host.as_str(), target_port)),
        );
        let authority = relay_transport_authority(settings)?;
        // Chrome's ALPN list, not `http/1.1` alone.
        //
        // The WebSocket Upgrade is an HTTP/1.1 mechanism, so this transport used to
        // have to ask for http/1.1 — and that single choice was visible in the
        // ClientHello before any payload: `h1` instead of `h2` in the JA4 head, and
        // no ALPS, which Chrome only sends alongside h2. Measured on the fleet as
        // t13d1515h1_... against Chrome's t13d1516h2_...
        //
        // RFC 8441 removes the constraint: if the relay picks h2 we carry the
        // WebSocket over an extended-CONNECT stream, and if it picks http/1.1 (or
        // is old enough to reject extended CONNECT) we fall back to the Upgrade.
        let alpn = super::surface::chrome_h2_http11_alpn();
        let (tls, negotiated_alpn) = connect_tls_with_negotiated_alpn(
            settings,
            tcp,
            authority.tls_server_name,
            &authority.authority_host,
            &alpn,
            authority.send_sni,
        )
        .await?;

        let uri = format!(
            "wss://{}{}",
            format_authority_host(&authority.authority_host),
            profile.websocket_path
        );
        let (ws, driver) = if negotiated_alpn.as_deref() == Some(b"h2".as_slice()) {
            match websocket_over_h2(tls, &authority.authority_host, &profile.websocket_path).await {
                Ok((ws, driver)) => (ws, Some(driver)),
                Err(err) => {
                    // NEVER retry with a different ALPN offer.
                    //
                    // The first version of this fallback redialled with
                    // `http/1.1` alone, and the witness matrix caught what that
                    // did: under congested_wifi / slow_mobile / middlebox_delay
                    // the captures contained TWO ClientHellos from one client to
                    // one relay — the Chrome-identical
                    // t13d1516h2_8daaf6152771_806a8c22fdea and the old
                    // t13d1515h1_8daaf6152771_e4c2b8c727f2 with no ALPS.
                    //
                    // That made the fallback a fingerprint oracle: an adversary who
                    // induces packet loss forces AEGIS onto its identifiable
                    // ClientHello, exactly when a censor is most likely to be
                    // interfering. A weakness the adversary can trigger is worse
                    // than a static one.
                    //
                    // So the offer is constant. A transient failure gets one retry
                    // with the SAME Chrome ALPN list; a relay that genuinely lacks
                    // RFC 8441 fails this transport and the planner moves to
                    // grpc_stream, which speaks h2 natively. Availability against an
                    // un-redeployed relay is not worth a triggerable tell.
                    if err.downcast_ref::<ExtendedConnectRefused>().is_some() {
                        return Err(err).context(
                            "relay lacks RFC 8441 extended CONNECT; not falling back to an \
                         http/1.1-only ClientHello because that would change our fingerprint",
                        );
                    }
                    tracing::debug!(
                        "websocket over h2 failed transiently ({err:#}); one retry, same ALPN"
                    );
                    let retry_tcp =
                        super::geneva_outer::connect(settings)
                            .await
                            .with_context(|| {
                                format!("reconnect websocket relay {}", settings.server)
                            })?;
                    super::apply_soft_wire_plan_to_stream(
                        &retry_tcp,
                        settings,
                        Some((target_host.as_str(), target_port)),
                    );
                    let retry_authority = relay_transport_authority(settings)?;
                    let retry_alpn_offer = super::surface::chrome_h2_http11_alpn();
                    let (retry_tls, retry_alpn) = connect_tls_with_negotiated_alpn(
                        settings,
                        retry_tcp,
                        retry_authority.tls_server_name,
                        &retry_authority.authority_host,
                        // Identical offer. This is the whole point.
                        &retry_alpn_offer,
                        retry_authority.send_sni,
                    )
                    .await?;
                    if retry_alpn.as_deref() == Some(b"h2".as_slice()) {
                        let (ws, driver) = websocket_over_h2(
                            retry_tls,
                            &retry_authority.authority_host,
                            &profile.websocket_path,
                        )
                        .await?;
                        (ws, Some(driver))
                    } else {
                        let mut request = uri.clone().into_client_request()?;
                        request.headers_mut().insert(
                            WEBSOCKET_HALF_CLOSE_HEADER,
                            http::HeaderValue::from_static(WEBSOCKET_HALF_CLOSE_MODE),
                        );
                        super::apply_websocket_request_shape_headers(
                            request.headers_mut(),
                            profile,
                        )?;
                        let (ws, resp) = client_async(request, retry_tls)
                            .await
                            .context("websocket handshake (relay selected http/1.1)")?;
                        tracing::debug!(status = %resp.status(), "websocket handshake complete");
                        (ws, None)
                    }
                }
            }
        } else {
            let mut request = uri.into_client_request()?;
            request.headers_mut().insert(
                WEBSOCKET_HALF_CLOSE_HEADER,
                http::HeaderValue::from_static(WEBSOCKET_HALF_CLOSE_MODE),
            );
            super::apply_websocket_request_shape_headers(request.headers_mut(), profile)?;
            let (ws, resp) = client_async(request, tls)
                .await
                .context("websocket handshake")?;
            tracing::debug!(status = %resp.status(), "websocket handshake complete");
            (ws, None)
        };
        if local_session_pre_open_aborted(local, initial_payload) {
            return Ok(None);
        }
        let (mut ws_tx, mut ws_rx) = ws.split();

        let req = TunnelRequest {
            host: target_host,
            port: target_port,
        };
        let frame = seal_tunnel_request(&req, settings.auth_token.as_bytes())?;
        tracing::debug!(frame_len = frame.len(), "sending tunnel request frame");
        if let Err(err) = ws_tx.send(Message::Binary(frame)).await {
            let err = anyhow::Error::from(err);
            if local_session_pre_open_aborted(local, initial_payload) {
                return Ok(None);
            }
            return Err(err);
        }

        let first = match ws_rx.next().await {
            Some(Ok(first)) => first,
            Some(Err(err)) => {
                let err = anyhow::Error::from(err);
                if local_session_pre_open_aborted(local, initial_payload) {
                    return Ok(None);
                }
                return Err(err);
            }
            None => {
                let err = anyhow::anyhow!("websocket closed before tunnel response");
                if local_session_pre_open_aborted(local, initial_payload) {
                    return Ok(None);
                }
                return Err(err);
            }
        };
        let Message::Binary(resp_frame) = first else {
            anyhow::bail!("unexpected websocket tunnel response frame");
        };
        let resp = open_tunnel_response(&resp_frame, settings.auth_token.as_bytes())?;
        if resp.status != TunnelStatus::Ok {
            return Err(super::tunnel_response_error(
                "websocket tunnel error",
                resp.status,
                resp.message,
            ));
        }
        counters.mark_opened();
        let half_close = resp.message == WEBSOCKET_HALF_CLOSE_MODE;
        anyhow::Ok(Some((ws_tx, ws_rx, driver, half_close)))
    })
    .await
    .with_context(|| {
        format!(
            "websocket tunnel establishment timed out after {}ms",
            settings.connect_timeout_ms
        )
    })??;
    let Some((mut ws_tx, mut ws_rx, mut driver, half_close)) = opened else {
        return Ok(());
    };
    if let Some(payload) = initial_payload.filter(|payload| !payload.is_empty()) {
        if let Err(err) = ws_tx.send(Message::Binary(payload.to_vec())).await {
            if benign_websocket_close(&err) {
                return Ok(());
            }
            return Err(err.into());
        }
        policy::maybe_delay(profile).await;
    }

    let (mut local_read, mut local_write) = tokio::io::split(local);
    let client_to_ws = async {
        let mut buf = vec![0u8; policy::write_chunk_size(profile)];
        loop {
            let n = local_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            counters.add_sent(n);
            if let Err(err) = ws_tx.send(Message::Binary(buf[..n].to_vec())).await {
                if benign_websocket_close(&err) {
                    break;
                }
                return Err(err.into());
            }
            policy::maybe_delay(profile).await;
        }
        if half_close {
            ws_tx.send(Message::Binary(Vec::new())).await?;
        } else {
            let _ = ws_tx.close().await;
        }
        anyhow::Ok(())
    };
    let ws_to_client = async {
        while let Some(msg) = ws_rx.next().await {
            match msg? {
                Message::Binary(data) => {
                    if half_close && data.is_empty() {
                        break;
                    }
                    counters.add_received(data.len());
                    if let Err(err) = local_write.write_all(&data).await {
                        #[cfg(unix)]
                        if super::local_session_aborted_fd(local_fd) {
                            return Ok(());
                        }
                        return Err(err.into());
                    }
                }
                Message::Close(_) => break,
                Message::Ping(_) | Message::Pong(_) => {}
                _ => {}
            }
        }
        local_write.shutdown().await?;
        anyhow::Ok(())
    };
    tokio::try_join!(client_to_ws, ws_to_client)?;
    // A WebSocket close flushes its own frames, but does not shut down the
    // underlying AsyncWrite. H2 needs END_STREAM before the last handles are
    // dropped, otherwise their implicit reset can overtake the final Close.
    let mut ws = ws_tx
        .reunite(ws_rx)
        .map_err(|_| anyhow::anyhow!("websocket stream halves do not match"))?;
    if half_close {
        let _ = ws.close(None).await;
        // The peer's Close confirms it consumed our EOF and preceding bytes.
        // Dropping an H2 receive half before this can reset queued uplink DATA.
        tokio::time::timeout(
            std::time::Duration::from_millis(settings.connect_timeout_ms),
            async {
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
            },
        )
        .await
        .context("websocket close handshake deadline")??;
    }
    // Both transfer halves completed successfully. A peer may already have
    // closed/reset the carrier after its Close frame; final FIN is best effort.
    // Read/write errors during either transfer still propagate above.
    let _ = ws.get_mut().shutdown().await;
    // H2 writes enqueue frames. Preserve the normal final-frame flush, while
    // every error/cancel path retains abort-on-drop ownership.
    if let Some(driver) = driver.as_mut() {
        driver.disarm();
    }
    Ok(())
}

#[cfg(test)]
#[path = "opening_tests.rs"]
mod opening_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benign_websocket_close_classifies_send_after_closing() {
        assert!(benign_websocket_close(&WsError::Protocol(
            ProtocolError::SendAfterClosing
        )));
        assert!(benign_websocket_close(&WsError::ConnectionClosed));
        assert!(benign_websocket_close(&WsError::AlreadyClosed));
        assert!(benign_websocket_close(&WsError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "eof"
        ))));
    }
}
