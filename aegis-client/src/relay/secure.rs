//! TCP and fixed-target UDP inside an independently authenticated TLS channel.

use aegis_core::carrier_program::CarrierChannel;
use aegis_core::h2_stream::H2Stream;
use aegis_core::https_bridge::Purpose;
use aegis_core::secure_channel::{self, grpc_io::GrpcIo, OpenRequest};
use aegis_core::RelaySettings;
use aegis_web_carrier::{Client as WebClient, Limits as WebLimits};
use anyhow::Context;
use bytes::{Buf, Bytes};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

struct Driver(tokio::task::JoinHandle<()>);
impl Driver {
    // The web-response stream owns and cancels its H2 pump on Drop.
    fn stream_owned() -> Self {
        Self(tokio::spawn(async {}))
    }
}
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

const CONNECTION_RUNNING: u8 = 0;
const CONNECTION_FAILED: u8 = 2;

/// Owner of one outer HTTP/2 carrier connection: its driver task, the
/// optional PING handle used by the failover liveness probe and the
/// connection-level outcome (a failed connection is a carrier failure, not a
/// target or stream close).
pub(crate) struct CarrierDriver {
    task: Driver,
    ping: Option<h2::PingPong>,
    state: std::sync::Arc<std::sync::atomic::AtomicU8>,
}

impl CarrierDriver {
    fn without_h2_ping(task: Driver) -> Self {
        Self {
            task,
            ping: None,
            state: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(CONNECTION_RUNNING)),
        }
    }

    fn take_ping(&mut self) -> Option<h2::PingPong> {
        self.ping.take()
    }

    /// Whether the outer connection itself failed. A session that ended with
    /// an error first gives the driver a short bounded chance to finish.
    async fn connection_failed(&mut self, session_failed: bool) -> bool {
        if session_failed && self.state.load(Ordering::Acquire) == CONNECTION_RUNNING {
            let _ =
                tokio::time::timeout(std::time::Duration::from_millis(100), &mut self.task.0).await;
        }
        self.state.load(Ordering::Acquire) == CONNECTION_FAILED
    }
}

#[derive(Debug, thiserror::Error)]
#[error("secure relay TCP dial failed: {0}")]
struct DialFailure(#[source] std::io::Error);

#[derive(Debug, thiserror::Error)]
#[error("secure carrier unavailable before device authentication: {0}")]
struct CarrierUnavailable(#[source] anyhow::Error);

/// The outer TLS handshake was cut at the transport layer (reset, abort or
/// EOF), as by an injected RST after the ClientHello or an SNI filter. Only
/// the outer ClientHello was sent. Certificate, alert and ECH refusals are not
/// this error and stay terminal.
#[derive(Debug, thiserror::Error)]
#[error("secure carrier outer TLS handshake interrupted before device authentication: {0}")]
struct OuterHandshakeInterrupted(#[source] std::io::Error);

#[derive(Debug, thiserror::Error)]
#[error("secure carrier session frozen: {}", .0.as_str())]
pub(crate) struct CarrierFrozen(pub(crate) aegis_core::brain::carrier_failover::CarrierSignal);

fn outer_handshake_failure(error: std::io::Error) -> anyhow::Error {
    use std::io::ErrorKind;
    if matches!(
        error.kind(),
        ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::UnexpectedEof
            | ErrorKind::BrokenPipe
            | ErrorKind::NotConnected
    ) {
        OuterHandshakeInterrupted(error).into()
    } else {
        error.into()
    }
}

/// Retry only before device authentication: a failed TCP dial, an outer TLS
/// handshake cut at the transport layer, an explicit unavailable carrier after
/// verified outer TLS, or a timeout before inner TLS. No identity or
/// application request has been sent at that point. Authentication/open/data
/// failures must never be replayed.
pub(super) fn retryable_pre_auth_failure(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.is::<DialFailure>()
            || cause.is::<CarrierUnavailable>()
            || cause.is::<OuterHandshakeInterrupted>()
    })
}

/// Typed carrier-health signal for a retryable pre-authentication failure.
pub(super) fn pre_auth_signal(
    error: &anyhow::Error,
) -> Option<aegis_core::brain::carrier_failover::CarrierSignal> {
    use aegis_core::brain::carrier_failover::CarrierSignal;
    for cause in error.chain() {
        if let Some(DialFailure(io)) = cause.downcast_ref::<DialFailure>() {
            return Some(if io.kind() == std::io::ErrorKind::TimedOut {
                CarrierSignal::DialTimeout
            } else {
                CarrierSignal::DialRefused
            });
        }
        if cause.is::<OuterHandshakeInterrupted>() {
            return Some(CarrierSignal::HandshakeReset);
        }
        if let Some(CarrierUnavailable(inner)) = cause.downcast_ref::<CarrierUnavailable>() {
            if inner.chain().any(|c| c.is::<tokio::time::error::Elapsed>()) {
                return Some(CarrierSignal::EstablishmentTimeout);
            }
            // A connection cut while opening HTTP/2 over verified outer TLS.
            if inner.chain().any(|c| {
                c.is::<OuterHandshakeInterrupted>()
                    || c.downcast_ref::<std::io::Error>().is_some_and(|io| {
                        matches!(
                            io.kind(),
                            std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                                | std::io::ErrorKind::UnexpectedEof
                                | std::io::ErrorKind::BrokenPipe
                        )
                    })
            }) {
                return Some(CarrierSignal::HandshakeReset);
            }
            return Some(CarrierSignal::EdgeRefused);
        }
    }
    None
}

/// Period PING liveness on the outer carrier of an open session. A PONG
/// slower than the collapse threshold is recorded as throughput collapse; a
/// PING without PONG within the timeout returns the freeze signal so the
/// caller closes the session (it is never replayed). A closed connection
/// stops probing and leaves the session to finish on its own.
async fn watch_liveness(
    mut ping: h2::PingPong,
    policy: super::carrier_failover::Liveness,
    ticket: super::carrier_failover::Ticket,
) -> aegis_core::brain::carrier_failover::CarrierSignal {
    use aegis_core::brain::carrier_failover::CarrierSignal;
    loop {
        tokio::time::sleep(policy.interval).await;
        let started = tokio::time::Instant::now();
        match tokio::time::timeout(policy.timeout, ping.ping(h2::Ping::opaque())).await {
            Ok(Ok(_)) => {
                if started.elapsed() >= policy.collapse {
                    ticket.degraded(CarrierSignal::ThroughputCollapse);
                }
            }
            Ok(Err(_)) => return std::future::pending().await,
            Err(_) => return CarrierSignal::SessionFreeze,
        }
    }
}

type SecureStream = tokio_rustls::client::TlsStream<GrpcIo<H2Stream>>;
trait CarrierIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> CarrierIo for T {}
type TrafficCarrier = Box<dyn CarrierIo>;

fn explicit_outer_roots(settings: &RelaySettings) -> anyhow::Result<rustls::RootCertStore> {
    let ca_cert = settings
        .ca_cert
        .as_deref()
        .context("explicit outer TLS trust bundle required")?;
    secure_channel::load_trust_roots(ca_cert).context("load explicit outer TLS trust bundle")
}

fn explicit_outer_tls(settings: &RelaySettings) -> anyhow::Result<tokio_rustls::TlsConnector> {
    let roots = explicit_outer_roots(settings)?;
    let alpn = super::surface::chrome_h2_alpn();
    super::tls_backend::rustls_tls_connector_for_settings_with_explicit_roots(
        settings, &alpn, true, true, roots,
    )
}

/// Open only the public H2/gRPC carrier. No device identity, invitation or
/// target OpenRequest is sent here. Callers retain their existing total timeout
/// and TCP-establishment marker so authentication failures are not replayed.
async fn outer_grpc(
    settings: &RelaySettings,
    connector: tokio_rustls::TlsConnector,
    tcp_established: &AtomicBool,
    purpose: Purpose,
) -> anyhow::Result<(GrpcIo<H2Stream>, CarrierDriver)> {
    // Local gate policy and credential errors are terminal, never a retryable
    // carrier outage. No socket exists until this validation has completed.
    let credential = if let Some(bridge) = &settings.https_bridge {
        bridge
            .validate_authority(&settings.server_name)
            .map_err(|_| anyhow::anyhow!("HTTPS bridge policy rejected"))?;
        aegis_client::credential_path_policy::validate_https_bridge_credential_file(bridge)?;
        Some(
            bridge
                .load_credential()
                .map_err(|_| anyhow::anyhow!("HTTPS bridge credential rejected"))?,
        )
    } else {
        None
    };
    let request = aegis_client::prepared_outer_tls::h2_carrier_request_from_held(
        settings,
        credential.as_ref(),
        purpose,
    )?;
    let tcp = super::geneva_outer::connect(settings)
        .await
        .map_err(DialFailure)?;
    tcp_established.store(true, Ordering::Relaxed);
    let authority = super::relay_transport_authority(settings)?;
    let tls = match connector
        .connect(authority.tls_server_name.clone(), tcp)
        .await
    {
        Ok(tls) => tls,
        Err(error) => {
            use aegis_client::ech_policy::{record_rejection, EchRejection};
            // A rotated CDN ECH key: the edge authenticated the pinned public
            // name and returned retry configs. Nothing but the outer
            // ClientHello was sent. Redial exactly once with the admitted
            // configs; a second rejection fails closed and clears them.
            if record_rejection(settings, &error) != EchRejection::RetryAdmitted {
                return Err(outer_handshake_failure(error));
            }
            let connector = explicit_outer_tls(settings)?;
            let tcp = super::geneva_outer::connect(settings)
                .await
                .map_err(DialFailure)?;
            match connector.connect(authority.tls_server_name, tcp).await {
                Ok(tls) => tls,
                Err(error) => {
                    aegis_client::ech_policy::forget_rotation(settings);
                    return Err(outer_handshake_failure(error)
                        .context("required ECH retry with rotated configs failed"));
                }
            }
        }
    };
    super::tls_backend::require_accepted_ech(settings, tls.get_ref().1.ech_status())?;
    async {
        anyhow::ensure!(
            tls.get_ref().1.alpn_protocol() == Some(b"h2"),
            "secure carrier requires HTTP/2"
        );
        let (mut client, mut connection) = h2::client::Builder::new().handshake(tls).await?;
        let ping = connection.ping_pong();
        let state = std::sync::Arc::new(std::sync::atomic::AtomicU8::new(CONNECTION_RUNNING));
        let observed = state.clone();
        let driver = CarrierDriver {
            task: Driver(tokio::spawn(async move {
                let outcome = if connection.await.is_ok() {
                    1
                } else {
                    CONNECTION_FAILED
                };
                observed.store(outcome, Ordering::Release);
            })),
            ping,
            state,
        };
        let (response, send) = client.send_request(request, false)?;
        let response = response.await?;
        anyhow::ensure!(
            response.status() == http::StatusCode::OK,
            "secure carrier rejected with HTTP {}",
            response.status()
        );
        anyhow::ensure!(
            response
                .headers()
                .get("content-type")
                .is_some_and(|h| h == "application/grpc"),
            "invalid secure carrier content type"
        );
        Ok((
            GrpcIo::new(H2Stream::new(send, response.into_body())),
            driver,
        ))
    }
    .await
    .map_err(|error: anyhow::Error| CarrierUnavailable(error).into())
}

/// Dedicated RFC 8441 route. Binary frames carry the original device TLS
/// protocol; no legacy WebSocket token or target request enters this path.
async fn outer_secure_ws(
    settings: &RelaySettings,
    connector: tokio_rustls::TlsConnector,
    tcp_established: &AtomicBool,
) -> anyhow::Result<(TrafficCarrier, Driver)> {
    anyhow::ensure!(
        settings.https_bridge.is_none(),
        "secure websocket cannot use bridge credential"
    );
    let tcp = super::geneva_outer::connect(settings)
        .await
        .map_err(DialFailure)?;
    tcp_established.store(true, Ordering::Relaxed);
    let authority = super::relay_transport_authority(settings)?;
    let tls = connector.connect(authority.tls_server_name, tcp).await?;
    super::tls_backend::require_accepted_ech(settings, tls.get_ref().1.ech_status())?;
    async {
        anyhow::ensure!(
            tls.get_ref().1.alpn_protocol() == Some(b"h2"),
            "secure websocket requires HTTP/2"
        );
        let (mut client, connection) = super::surface::chrome_like_h2_builder()
            .handshake(tls)
            .await?;
        let driver = Driver(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let mut request = http::Request::builder()
            .method(http::Method::CONNECT)
            .header(http::header::SEC_WEBSOCKET_VERSION, "13")
            .uri(format!(
                "https://{}{}",
                super::format_authority_host(&authority.authority_host),
                aegis_core::carrier_program::SECURE_WS_PATH
            ))
            .body(())?;
        super::order_headers_like_chrome(request.headers_mut());
        request
            .extensions_mut()
            .insert(h2::ext::Protocol::from("websocket"));
        let (response, send) = client.send_request(request, false)?;
        let response = response.await?;
        anyhow::ensure!(
            response.status() == http::StatusCode::OK,
            "secure websocket carrier unavailable"
        );
        let stream = H2Stream::new(send, response.into_body());
        let ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
            stream,
            tokio_tungstenite::tungstenite::protocol::Role::Client,
            Some(aegis_core::ws_io::bounded_config()),
        )
        .await;
        Ok((
            Box::new(aegis_core::ws_io::WsIo::new(ws)) as TrafficCarrier,
            driver,
        ))
    }
    .await
    .map_err(|error: anyhow::Error| CarrierUnavailable(error).into())
}

/// The signed bootstrap route returns an ingress descriptor. Its admission
/// key is read from the protected identity sidecar before any network access;
/// the descriptor may redirect only to a signed IP, then inner device TLS
/// still authenticates and opens the target exactly once.
async fn outer_web_response(
    settings: &RelaySettings,
    connector: tokio_rustls::TlsConnector,
    tcp_established: &AtomicBool,
) -> anyhow::Result<(TrafficCarrier, Driver)> {
    let private = settings
        .web_response
        .as_ref()
        .context("web-response sidecar missing")?;
    let identity = settings
        .inner_tls
        .as_ref()
        .context("device identity missing")?;
    let credential =
        aegis_client::device_web_response::credential(private, &identity.key, &identity.cert)?;
    let web = aegis_client::device_web_response::client_settings(private);
    web.validate()
        .map_err(|_| anyhow::anyhow!("web-response policy rejected"))?;
    anyhow::ensure!(
        settings.server_name == private.authority,
        "web-response authority differs"
    );
    let bootstrap: std::net::SocketAddr = settings
        .server
        .parse()
        .context("web-response bootstrap must be numeric")?;
    anyhow::ensure!(
        bootstrap.port() != 0 && !bootstrap.ip().is_unspecified() && !bootstrap.ip().is_multicast(),
        "web-response bootstrap rejected"
    );
    let limits = WebLimits::default();
    tcp_established.store(true, Ordering::Relaxed);
    let descriptor = WebClient::discover(connector.clone(), bootstrap, &web, &credential, &limits)
        .await
        .map_err(|error| CarrierUnavailable(error.into()))?;
    anyhow::ensure!(
        private
            .allowed_ingress_ips
            .contains(&descriptor.ingress.ip()),
        "web-response descriptor ingress not signed"
    );
    let stream = WebClient::connect(connector, &web, descriptor, credential, limits)
        .await
        .map_err(|error| CarrierUnavailable(error.into()))?;
    Ok((Box::new(stream), Driver::stream_owned()))
}

/// Direct H3 CONNECT carries opaque enrolled TLS bytes. No legacy MASQUE
/// credential or target address is sent in the outer request.
async fn outer_enrolled_quic(
    settings: &RelaySettings,
    established: &AtomicBool,
) -> anyhow::Result<(TrafficCarrier, Driver)> {
    let authority = super::transport_authority_for_host(&settings.server_name, "server_name")?;
    let mut config = super::masque_crypto::enrolled_h3_client_config(settings, &authority)?;
    config.transport_config(super::masque::masque_transport_config(settings, None)?);
    let peer: std::net::SocketAddr = settings.server.parse().context("signed QUIC socket")?;
    let mut endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap())?;
    let endpoint_guard = super::masque::CloseEndpointOnDrop(endpoint.clone());
    endpoint.set_default_client_config(config);
    let conn = endpoint
        .connect(peer, &authority.authority_host)?
        .await
        .map_err(|error| DialFailure(std::io::Error::other(error)))?;
    established.store(true, Ordering::Relaxed);
    let quic = h3_quinn::Connection::new(conn.clone());
    let mut builder = h3::client::builder();
    builder.enable_extended_connect(true);
    let (h3_owner, mut requests) = builder
        .build::<_, _, Bytes>(quic)
        .await
        .map_err(|error| CarrierUnavailable(error.into()))?;
    let request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(format!(
            "https://{}",
            aegis_core::carrier_program::SECURE_QUIC_AUTHORITY
        ))
        .body(())?;
    let mut stream = requests
        .send_request(request)
        .await
        .map_err(|error| CarrierUnavailable(error.into()))?;
    let response = stream
        .recv_response()
        .await
        .map_err(|error| CarrierUnavailable(error.into()))?;
    if response.status() != http::StatusCode::OK {
        return Err(CarrierUnavailable(anyhow::anyhow!("enrolled QUIC carrier refused")).into());
    }
    let (app, wire) = tokio::io::duplex(64 * 1024);
    let driver = Driver(tokio::spawn(async move {
        let _endpoint = endpoint;
        let _close_on_drop = endpoint_guard;
        let _connection = conn;
        let _h3_owner = h3_owner;
        let (mut send, mut recv) = stream.split();
        let (mut local_read, mut local_write) = tokio::io::split(wire);
        let uplink = async {
            let mut bytes = [0u8; 16 * 1024];
            loop {
                let n = local_read.read(&mut bytes).await?;
                if n == 0 {
                    send.finish().await?;
                    break;
                }
                send.send_data(Bytes::copy_from_slice(&bytes[..n])).await?;
            }
            anyhow::Ok(())
        };
        let downlink = async {
            while let Some(mut frame) = recv.recv_data().await? {
                let body = frame.copy_to_bytes(frame.remaining());
                local_write.write_all(&body).await?;
            }
            local_write.shutdown().await?;
            anyhow::Ok(())
        };
        let _: anyhow::Result<_> = tokio::try_join!(uplink, downlink);
    }));
    Ok((Box::new(app), driver))
}

async fn outer_traffic(
    settings: &RelaySettings,
    connector: tokio_rustls::TlsConnector,
    tcp_established: &AtomicBool,
    channel: Option<CarrierChannel>,
) -> anyhow::Result<(TrafficCarrier, CarrierDriver)> {
    if channel == Some(CarrierChannel::HttpsWs) {
        outer_secure_ws(settings, connector, tcp_established)
            .await
            .map(|(carrier, driver)| (carrier, CarrierDriver::without_h2_ping(driver)))
    } else if channel == Some(CarrierChannel::MasqueQuic) {
        outer_enrolled_quic(settings, tcp_established)
            .await
            .map(|(carrier, driver)| (carrier, CarrierDriver::without_h2_ping(driver)))
    } else if channel == Some(CarrierChannel::WebResponse) {
        outer_web_response(settings, connector, tcp_established)
            .await
            .map(|(carrier, driver)| (carrier, CarrierDriver::without_h2_ping(driver)))
    } else {
        let (stream, driver) =
            outer_grpc(settings, connector, tcp_established, Purpose::Traffic).await?;
        Ok((Box::new(stream), driver))
    }
}

#[cfg(test)]
async fn open(
    settings: &RelaySettings,
    target_host: String,
    target_port: u16,
    transport: secure_channel::Transport,
) -> anyhow::Result<(aegis_core::carrier_runtime::OwnedCarrier, CarrierDriver)> {
    open_with_endpoint(settings, target_host, target_port, transport, None, None).await
}

async fn open_with_endpoint(
    settings: &RelaySettings,
    target_host: String,
    target_port: u16,
    transport: secure_channel::Transport,
    endpoint: Option<&super::endpoint_bandit::Attempt>,
    channel: Option<CarrierChannel>,
) -> anyhow::Result<(aegis_core::carrier_runtime::OwnedCarrier, CarrierDriver)> {
    let liu_origin = settings
        .authenticated_shaping
        .as_ref()
        .and_then(|s| s.liu_channel.as_ref())
        .map(|_| match endpoint {
            Some(e) => e
                .deadline()
                .checked_sub(std::time::Duration::from_millis(
                    settings.connect_timeout_ms,
                ))
                .context("Liu endpoint original clock unavailable"),
            None => Ok(tokio::time::Instant::now()),
        })
        .transpose()?;
    if let Some(endpoint) = endpoint {
        anyhow::ensure!(
            tokio::time::Instant::now() < endpoint.deadline(),
            "endpoint establishment deadline exhausted before identity access"
        );
    }
    settings
        .validate_inner_tls_transport()
        .map_err(anyhow::Error::msg)?;
    let liu_clock = liu_origin
        .map(|origin| -> anyhow::Result<_> {
            Ok((
                origin,
                if let Some(e) = endpoint {
                    e.deadline()
                } else {
                    origin
                        .checked_add(std::time::Duration::from_millis(
                            settings.connect_timeout_ms,
                        ))
                        .context("Liu establishment clock overflow")?
                },
            ))
        })
        .transpose()?;
    let liu_admission = if let Some((origin, deadline)) = liu_clock {
        let profile = settings
            .authenticated_shaping
            .as_ref()
            .context("Liu profile missing")?;
        let context = profile
            .liu_channel
            .as_ref()
            .context("Liu settings missing")?
            .traffic_context(&target_host, target_port, transport)?;
        Some(
            secure_channel::relay_shaping::prepare_liu_admission(
                profile, context, origin, deadline,
            )
            .await?,
        )
    } else {
        None
    };
    let identity = secure_channel::Client::load(
        settings
            .inner_tls
            .as_ref()
            .context("inner TLS identity missing")?,
    )?;
    let connector = explicit_outer_tls(settings)?;
    let tcp_established = AtomicBool::new(false);
    let inner_started = AtomicBool::new(false);
    let duration = std::time::Duration::from_millis(settings.connect_timeout_ms);
    // Default mode retains timeout's checked-add/far-future behavior. Only
    // explicit shaping needs an absolute agreement deadline; admission caps
    // that establishment interval before any network access.
    let now = tokio::time::Instant::now();
    let deadline = if let Some((_, deadline)) = liu_clock {
        deadline
    } else if let Some(endpoint) = endpoint {
        endpoint.deadline()
    } else if settings.authenticated_shaping.is_some() {
        now.checked_add(duration)
            .context("authenticated relay shaping establishment timeout exceeds clock range")?
    } else {
        now // Ignored by the disabled agreement path, which performs no I/O.
    };
    let duration = if endpoint.is_some() || liu_clock.is_some() {
        deadline
            .checked_duration_since(tokio::time::Instant::now())
            .context("endpoint establishment deadline exhausted before network")?
    } else {
        duration
    };
    let operation = async {
        let (carrier, driver) =
            outer_traffic(settings, connector, &tcp_established, channel).await?;
        inner_started.store(true, Ordering::Relaxed);
        let inner = identity
            .connect(carrier)
            .await
            .context("inner TLS authentication")?;
        let mut inner = secure_channel::relay_shaping::client_admitted(
            inner,
            settings.authenticated_shaping.as_ref(),
            deadline,
            liu_admission,
        )
        .await?;
        secure_channel::write_open(
            &mut inner,
            &OpenRequest {
                transport,
                version: 1,
                host: target_host,
                port: target_port,
            },
        )
        .await?;
        anyhow::ensure!(inner.read_u8().await? == 0, "secure relay rejected target");
        anyhow::Ok((inner, driver))
    };
    let opened = if endpoint.is_some() || liu_clock.is_some() {
        tokio::time::timeout_at(deadline, operation).await
    } else {
        tokio::time::timeout(duration, operation).await
    };
    let opened = match opened {
        Ok(result) => result?,
        Err(_) if !tcp_established.load(Ordering::Relaxed) => {
            return Err(DialFailure(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "secure relay TCP dial timed out",
            ))
            .into());
        }
        Err(error) if !inner_started.load(Ordering::Relaxed) => {
            return Err(CarrierUnavailable(anyhow::Error::new(error)).into());
        }
        Err(error) => {
            return Err(anyhow::Error::new(error).context("secure relay establishment timed out"))
        }
    };
    if liu_clock.is_some() {
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "Liu establishment completed after original deadline"
        );
    }
    if let Some(endpoint) = endpoint {
        endpoint.validate_after_open()?;
    }
    Ok(opened)
}

type EnrollmentStream = secure_channel::enrollment_tls::Session<SecureStream>;

/// Confirm a live, currently authorized device certificate without opening a
/// traffic target. This is distinct from an authority issuance receipt.
pub(crate) async fn policy_ack(
    settings: &RelaySettings,
    expected: &aegis_client::online_expectation::OnlineExpectation,
) -> anyhow::Result<tokio::time::Instant> {
    // The per-attempt copy intentionally drops the route program. Admit the
    // complete signed pool before selecting any endpoint or bridge key.
    settings
        .validate_inner_tls_transport()
        .map_err(anyhow::Error::msg)?;
    let mut last = None;
    let pool = super::effective_relay_endpoints(settings);
    // The same failover order as traffic: a carrier known to be blocked on
    // this network is tried last, and pre-authentication blocks are learned.
    let carriers = super::carrier_failover::Session::prepare(settings, &pool)?;
    let order: Vec<usize> = match &carriers {
        Some(session) => session.order().to_vec(),
        None => (0..pool.len()).collect(),
    };
    for index in order {
        let ticket = carriers.as_ref().map(|session| session.ticket(index));
        let selected = super::relay_settings_for_endpoint(settings, &pool[index]);
        match policy_ack_endpoint(&selected, expected, pool[index].channel).await {
            Ok(deadline) => {
                if let Some(ticket) = &ticket {
                    ticket.opened();
                }
                return Ok(deadline);
            }
            Err(error) if retryable_pre_auth_failure(&error) => {
                if let Some(ticket) = &ticket {
                    ticket.failed_before_open(&error);
                }
                last = Some(error)
            }
            Err(error) => return Err(error),
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("device policy relay pool is empty")))
}

async fn policy_ack_endpoint(
    settings: &RelaySettings,
    expected: &aegis_client::online_expectation::OnlineExpectation,
    channel: Option<CarrierChannel>,
) -> anyhow::Result<tokio::time::Instant> {
    let liu_origin = settings
        .authenticated_shaping
        .as_ref()
        .and_then(|s| s.liu_channel.as_ref())
        .map(|_| tokio::time::Instant::now());
    settings
        .validate_inner_tls_transport()
        .map_err(anyhow::Error::msg)?;
    let liu_deadline = liu_origin.map(|o| o + std::time::Duration::from_secs(5));
    let liu_admission = if let Some(origin) = liu_origin {
        let profile = settings
            .authenticated_shaping
            .as_ref()
            .context("Liu profile missing")?;
        let context = profile
            .liu_channel
            .as_ref()
            .context("Liu settings missing")?
            .policy_context()?;
        Some(
            secure_channel::relay_shaping::prepare_liu_admission(
                profile,
                context,
                origin,
                liu_deadline.context("Liu clock missing")?,
            )
            .await?,
        )
    } else {
        None
    };
    let identity = secure_channel::Client::load(
        settings
            .inner_tls
            .as_ref()
            .context("device inner TLS required")?,
    )?;
    let connector = explicit_outer_tls(settings)?;
    let inner_started = AtomicBool::new(false);
    let deadline = liu_deadline
        .unwrap_or_else(|| tokio::time::Instant::now() + std::time::Duration::from_secs(5));
    let result = tokio::time::timeout_at(deadline, async {
        let tcp_established = AtomicBool::new(false);
        let (carrier, _driver) =
            outer_traffic(settings, connector, &tcp_established, channel).await?;
        inner_started.store(true, Ordering::Relaxed);
        let inner = identity.connect(carrier).await?;
        let mut inner = secure_channel::relay_shaping::client_admitted(
            inner,
            settings.authenticated_shaping.as_ref(),
            deadline,
            liu_admission,
        )
        .await?;
        aegis_client::policy_ack_exchange::exchange_on_authenticated_stream(
            &mut inner,
            expected.binding(),
            liu_origin.is_some(),
        )
        .await
    })
    .await;
    match result {
        Ok(_) if liu_origin.is_some() && tokio::time::Instant::now() >= deadline => Err(
            anyhow::anyhow!("Liu PolicyAck completed after original deadline"),
        ),
        Ok(result) => result,
        Err(error) if !inner_started.load(Ordering::Relaxed) => {
            Err(CarrierUnavailable(anyhow::Error::new(error)).into())
        }
        Err(error) => Err(error.into()),
    }
}

/// The H2 driver remains owned for the entire enrollment session; cancellation
/// drops both the bounded inner TLS stream and its outer connection task.
pub(crate) struct EnrollmentConnection {
    stream: EnrollmentStream,
    _driver: CarrierDriver,
}

impl EnrollmentConnection {
    pub(crate) fn stream_mut(&mut self) -> &mut EnrollmentStream {
        &mut self.stream
    }
    pub(crate) fn deadline(&self) -> tokio::time::Instant {
        self.stream.deadline()
    }
}

pub(crate) async fn open_enrollment(
    profile: &crate::device_bundle::online::OnlineProfile,
) -> anyhow::Result<EnrollmentConnection> {
    let settings = profile.carrier();
    let identity = secure_channel::enrollment_tls::Client::load(profile.tls())?;
    let connector = explicit_outer_tls(settings)?;
    let tcp_established = AtomicBool::new(false);
    tokio::time::timeout(
        std::time::Duration::from_millis(settings.connect_timeout_ms),
        async {
            let (carrier, driver) =
                outer_grpc(settings, connector, &tcp_established, Purpose::Enrollment).await?;
            // Only a verified, enrollment-only inner stream can reach a caller
            // that has access to invitation/CSR material.
            let stream = identity
                .connect(carrier)
                .await
                .context("enrollment TLS authentication")?;
            anyhow::Ok(EnrollmentConnection {
                stream,
                _driver: driver,
            })
        },
    )
    .await
    .context("enrollment connection deadline exceeded")?
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_with_endpoint(
    local: &mut TcpStream,
    settings: &RelaySettings,
    target_host: String,
    target_port: u16,
    initial_payload: Option<&[u8]>,
    counters: &super::RelaySessionCounters,
    endpoint: Option<&super::endpoint_bandit::Attempt>,
    channel: Option<CarrierChannel>,
    carrier: Option<&super::carrier_failover::Ticket>,
) -> anyhow::Result<()> {
    let (inner, mut driver) = open_with_endpoint(
        settings,
        target_host,
        target_port,
        secure_channel::Transport::Tcp,
        endpoint,
        channel,
    )
    .await?;
    counters.mark_opened();
    if let Some(ticket) = carrier {
        ticket.opened();
    }
    let watch = carrier.and_then(|ticket| {
        Some(watch_liveness(
            driver.take_ping()?,
            ticket.liveness()?,
            ticket.clone(),
        ))
    });
    let mut inner = super::byte_progress::ByteProgress::with_endpoint(inner, counters, endpoint);
    let session = async {
        if let Some(payload) = initial_payload.filter(|p| !p.is_empty()) {
            inner.write_all(payload).await?;
            inner.flush().await?;
        }
        tokio::io::copy_bidirectional(local, &mut inner).await?;
        anyhow::Ok(())
    };
    let result = match watch {
        Some(watch) => tokio::select! {
            result = session => result,
            signal = watch => Err(CarrierFrozen(signal).into()),
        },
        None => session.await,
    };
    // Release the stream first so a healthy outer connection can finish.
    drop(inner);
    if let Some(ticket) = carrier {
        if let Err(error) = &result {
            if let Some(CarrierFrozen(signal)) = error.downcast_ref::<CarrierFrozen>() {
                ticket.degraded(*signal);
            }
        }
        let carrier_failed = driver.connection_failed(result.is_err()).await;
        ticket.closed(carrier_failed, counters.received() > 0);
    }
    result
}

pub(super) async fn udp_once_with_endpoint(
    settings: &RelaySettings,
    target: &crate::socks5::ConnectTarget,
    payload: &[u8],
    endpoint: Option<&super::endpoint_bandit::Attempt>,
    carrier: Option<&super::carrier_failover::Ticket>,
) -> anyhow::Result<Vec<u8>> {
    use secure_channel::datagram;
    let (mut inner, mut driver) = open_with_endpoint(
        settings,
        target.host.clone(),
        target.port,
        secure_channel::Transport::Udp,
        endpoint,
        None,
    )
    .await?;
    if let Some(ticket) = carrier {
        ticket.opened();
    }
    // Once write starts, any failure is ambiguous delivery. Never replay this
    // application datagram through another endpoint or a legacy transport.
    let operation = async {
        datagram::write(&mut inner, payload).await?;
        let reply = datagram::read(&mut inner)
            .await?
            .context("secure UDP closed before response")?;
        if !payload.is_empty() && !reply.is_empty() {
            if let Some(endpoint) = endpoint {
                endpoint.progress();
            }
        }
        anyhow::Ok(reply)
    };
    let result = match tokio::time::timeout(
        std::time::Duration::from_millis(settings.connect_timeout_ms),
        operation,
    )
    .await
    {
        Ok(result) => result.map_err(super::udp_payload_committed),
        Err(error) => Err(super::udp_payload_committed(error.into())),
    };
    drop(inner);
    if let Some(ticket) = carrier {
        let response = result.as_ref().is_ok_and(|reply| !reply.is_empty());
        let carrier_failed = driver.connection_failed(result.is_err()).await;
        ticket.closed(carrier_failed, response);
    }
    result
}

pub(super) async fn udp_flow_with_endpoint(
    settings: &RelaySettings,
    target: &crate::socks5::ConnectTarget,
    outbound_rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
    incoming_tx: &tokio::sync::mpsc::Sender<crate::socks5::UdpPacket>,
    endpoint: Option<&super::endpoint_bandit::Attempt>,
    carrier: Option<&super::carrier_failover::Ticket>,
) -> anyhow::Result<()> {
    use secure_channel::datagram;
    let (inner, mut driver) = open_with_endpoint(
        settings,
        target.host.clone(),
        target.port,
        secure_channel::Transport::Udp,
        endpoint,
        None,
    )
    .await?;
    if let Some(ticket) = carrier {
        ticket.opened();
    }
    let watch = carrier.and_then(|ticket| {
        Some(watch_liveness(
            driver.take_ping()?,
            ticket.liveness()?,
            ticket.clone(),
        ))
    });
    let (mut reader, mut writer) = tokio::io::split(inner);
    let committed = AtomicBool::new(false);
    let responded = AtomicBool::new(false);

    let sending = async {
        while let Some(payload) = outbound_rx.recv().await {
            // Mark before the first await so partial writes are never replayed.
            committed.store(true, Ordering::Relaxed);
            datagram::write(&mut writer, &payload).await?;
            if !payload.is_empty() {
                if let Some(endpoint) = endpoint {
                    endpoint.accepted_sent();
                }
            }
        }
        writer.shutdown().await?;
        anyhow::Ok(())
    };
    let receiving = async {
        while let Some(payload) = datagram::read(&mut reader).await? {
            let positive = !payload.is_empty();
            responded.store(true, Ordering::Relaxed);
            incoming_tx
                .send(crate::socks5::UdpPacket {
                    target: target.clone(),
                    payload,
                })
                .await
                .map_err(|_| anyhow::anyhow!("secure UDP response receiver closed"))?;
            if positive {
                if let Some(endpoint) = endpoint {
                    endpoint.observed_response();
                }
            }
        }
        anyhow::Ok(())
    };
    // Each direction owns its frame future until completion. Dropping either
    // cancels the entire flow; no select branch restarts a partial frame read.
    // A frozen carrier ends the flow; its datagrams are never replayed.
    let frozen = async {
        match watch {
            Some(watch) => Err(anyhow::Error::from(CarrierFrozen(watch.await))),
            None => std::future::pending().await,
        }
    };
    let result = tokio::select! {
        result = sending => result,
        result = receiving => result,
        result = frozen => result,
    };
    drop((reader, writer));
    if let Some(ticket) = carrier {
        if let Err(error) = &result {
            if let Some(CarrierFrozen(signal)) = error.downcast_ref::<CarrierFrozen>() {
                ticket.degraded(*signal);
            }
        }
        let carrier_failed = driver.connection_failed(result.is_err()).await;
        ticket.closed(carrier_failed, responded.load(Ordering::Relaxed));
    }
    result.map_err(|error| {
        if committed.load(Ordering::Relaxed) {
            super::udp_payload_committed(error)
        } else {
            error
        }
    })
}

#[cfg(test)]
pub(super) mod tests;

#[cfg(test)]
#[path = "secure/enrollment_tests.rs"]
mod enrollment_tests;

// Real server-side ECH requires the AWS-LC SSL bindings of this feature.
#[cfg(all(test, feature = "chrome-like-tls", unix))]
#[path = "secure/ech_edge_tests.rs"]
mod ech_edge_tests;
