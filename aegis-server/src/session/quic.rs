use crate::config::ServerConfig;
use crate::lifecycle::SharedTaskGroup as QuicSessionTasks;
use crate::rate_limit::RateLimiter;
use crate::session::TunnelAuthKeyring;
use crate::session::{benign_io_close, classify_connect_failure_status};
use aegis_core::tunnel::{seal_tunnel_response, TunnelResponse, TunnelStatus};
use aegis_core::{auto_capture_probe, parse_connect_udp_path};
use anyhow::Context;
use bytes::{Buf, Bytes};
use h3::error::{
    Code as H3Code, ConnectionError as H3ConnectionError, StreamError as H3StreamError,
};
use h3::ext::Protocol;
use h3_datagram::datagram_handler::HandleDatagramsExt;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

mod startup;
pub(crate) use startup::{Failure as QuicStartupFailure, Readiness as QuicReadiness};

const MAX_TUNNEL_REQUEST_BYTES: usize = 8 * 1024;
// Independent of the established TCP/QUIC budget, including its unlimited mode.
const MAX_QUIC_UNAUTHENTICATED_CONNECTIONS: usize = 64;
const MAX_QUIC_PENDING_BYTES_PER_INCOMING: u64 = 4 * 1024;

fn quic_unauthenticated_limit(max_connections: usize) -> usize {
    crate::connection_permit_limit(max_connections).min(MAX_QUIC_UNAUTHENTICATED_CONNECTIONS)
}

/// Own one bounded admission slot until authentication, then one established
/// slot until the H3 owner and its response-draining work finish.
struct QuicAdmission {
    deadline: tokio::time::Instant,
    unauthenticated_permit: Option<OwnedSemaphorePermit>,
    established: Arc<Semaphore>,
    established_permit: Option<OwnedSemaphorePermit>,
    authenticated: Arc<AtomicBool>,
}

impl QuicAdmission {
    fn promote(&mut self) -> anyhow::Result<()> {
        anyhow::ensure!(
            tokio::time::Instant::now() < self.deadline,
            "QUIC authentication exceeded the original admission deadline"
        );
        let permit = self
            .established
            .clone()
            .try_acquire_owned()
            .context("max shared TCP/QUIC established connections reached")?;
        // Never promote a credential whose synchronous verification/admission
        // work used the final part of the original read budget.
        anyhow::ensure!(
            tokio::time::Instant::now() < self.deadline,
            "QUIC authentication exceeded the original admission deadline"
        );
        self.established_permit = Some(permit);
        drop(self.unauthenticated_permit.take());
        self.authenticated.store(true, Ordering::Release);
        Ok(())
    }
}

/// Retain the pinned session after timeout so authenticated forwarding is not
/// cut off by the original preauthentication clock. Promotion checks that clock
/// synchronously; the flag also handles authentication and timer readiness in
/// the same scheduler turn without renewing the admission budget.
async fn await_quic_admitted_session<F, T>(
    session: F,
    deadline: tokio::time::Instant,
    authenticated: Arc<AtomicBool>,
) -> Result<T, tokio::time::error::Elapsed>
where
    F: std::future::Future<Output = T>,
{
    // Tokio polls a timeout's inner future before its clock. Refuse an expired
    // queued worker before polling session can convert Incoming and start TLS.
    if tokio::time::Instant::now() >= deadline {
        drop(session);
        // Produce the existing typed timeout error without polling that session
        // or creating another deadline. This sentinel has no admission effects.
        return tokio::time::timeout_at(deadline, std::future::pending::<T>()).await;
    }
    tokio::pin!(session);
    match tokio::time::timeout_at(deadline, session.as_mut()).await {
        Ok(result) => Ok(result),
        Err(_) if authenticated.load(Ordering::Acquire) => Ok(session.await),
        Err(error) => Err(error),
    }
}

/// Own only this server endpoint's application and Quinn background tasks.
/// Endpoint::close starts protocol draining; dropping Endpoint alone does not
/// join its driver or immediately release its UDP socket in a live runtime.
pub(crate) struct QuicRuntimeTasks {
    runtime: Arc<OwnedQuicRuntime>,
    sessions: QuicSessionTasks,
}

impl QuicRuntimeTasks {
    pub(crate) fn new(operational_log: crate::operational_log::OperationalLogPolicy) -> Self {
        Self {
            runtime: Arc::new(OwnedQuicRuntime {
                tasks: QuicSessionTasks::new(operational_log),
            }),
            sessions: QuicSessionTasks::new(operational_log),
        }
    }

    pub(crate) fn runtime(&self) -> Arc<dyn quinn::Runtime> {
        self.runtime.clone()
    }

    pub(crate) fn sessions(&self) -> QuicSessionTasks {
        self.sessions.clone()
    }

    pub(crate) async fn shutdown(&mut self) {
        // No second grace: abort and join cancellable async futures, not
        // spawn_blocking work. Application handles also retain UDP socket
        // references, so join them before joining the endpoint/connection drivers.
        self.sessions.shutdown().await;
        self.runtime.tasks.shutdown().await;
    }
}

impl Drop for QuicRuntimeTasks {
    fn drop(&mut self) {
        self.sessions.abort_all();
        self.runtime.tasks.abort_all();
    }
}

#[derive(Debug)]
struct OwnedQuicRuntime {
    tasks: QuicSessionTasks,
}

impl quinn::Runtime for OwnedQuicRuntime {
    fn now(&self) -> std::time::Instant {
        quinn::Runtime::now(&quinn::TokioRuntime)
    }

    fn new_timer(&self, at: std::time::Instant) -> std::pin::Pin<Box<dyn quinn::AsyncTimer>> {
        quinn::Runtime::new_timer(&quinn::TokioRuntime, at)
    }

    fn spawn(&self, future: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>) {
        self.tasks.spawn(future);
    }

    fn wrap_udp_socket(
        &self,
        socket: std::net::UdpSocket,
    ) -> std::io::Result<Arc<dyn quinn::AsyncUdpSocket>> {
        quinn::Runtime::wrap_udp_socket(&quinn::TokioRuntime, socket)
    }
}

struct H3RequestContext<'a> {
    cfg: &'a ServerConfig,
    auth_keyring: &'a TunnelAuthKeyring,
    rate_limiter: &'a RateLimiter,
    peer: std::net::SocketAddr,
    decoy_seed: u16,
    admission: &'a mut QuicAdmission,
}

fn benign_h3_close(err: &anyhow::Error) -> bool {
    if benign_io_close(err) {
        return true;
    }
    if err
        .chain()
        .any(|cause| cause.to_string().contains("ApplicationClose: 0x0"))
    {
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

fn masque_transport_config(cfg: &ServerConfig) -> anyhow::Result<Arc<quinn::TransportConfig>> {
    let keep_alive = (cfg.transport.quic_keep_alive_interval_ms > 0)
        .then(|| Duration::from_millis(cfg.transport.quic_keep_alive_interval_ms));
    let idle_timeout = (cfg.transport.quic_max_idle_timeout_ms > 0)
        .then(|| Duration::from_millis(cfg.transport.quic_max_idle_timeout_ms));
    if let (Some(keep_alive), Some(idle_timeout)) = (keep_alive, idle_timeout) {
        anyhow::ensure!(
            keep_alive < idle_timeout,
            "transport.quic_keep_alive_interval_ms must be smaller than transport.quic_max_idle_timeout_ms"
        );
    }

    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(keep_alive);
    transport.max_idle_timeout(
        idle_timeout
            .map(|timeout| timeout.try_into())
            .transpose()
            .context("convert transport.quic_max_idle_timeout_ms to quinn idle timeout")?,
    );
    Ok(Arc::new(transport))
}

#[allow(dead_code)]
pub async fn run_quic_server(cfg: ServerConfig) -> anyhow::Result<()> {
    run_quic_server_with_ready(cfg, None).await
}

/// Tier 2 channel-sync: variant that fires `ready` once the QUIC endpoint
/// is bound and ready to accept. Tests use this to replace the chronic
/// `sleep(1s)` startup race with a deterministic signal.
pub async fn run_quic_server_with_ready(
    cfg: ServerConfig,
    ready: Option<tokio::sync::oneshot::Sender<()>>,
) -> anyhow::Result<()> {
    // Standalone QUIC owns one startup read before opening its endpoint.
    let auth = TunnelAuthKeyring::from_config_for_startup(&cfg).await?;
    let rate_limiter = RateLimiter::new(
        cfg.rate_limit.max_auth_failures_per_ip,
        cfg.rate_limit.ban_duration_secs,
        cfg.rate_limit.enabled,
    )
    .with_operational_log(cfg.logging.policy())
    .with_trusted_proxies(
        &cfg.rate_limit.trusted_proxy_cidrs,
        &cfg.rate_limit.forwarded_ip_header,
    )?;
    let rl_cleanup = rate_limiter.clone();
    let _cleanup_task = crate::lifecycle::OwnedTask(tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            rl_cleanup.cleanup().await;
        }
    }));
    let permits = crate::connection_permit_limit(cfg.limits.max_connections);
    let mut runtime_tasks = QuicRuntimeTasks::new(cfg.logging.policy());
    let result = run_quic_server_with_ready_and_controls(
        VerifiedQuicStartup { cfg, auth },
        ready.map(QuicReadiness::Unit),
        rate_limiter,
        Arc::new(Semaphore::new(permits)),
        None,
        runtime_tasks.runtime(),
        runtime_tasks.sessions(),
    )
    .await;
    runtime_tasks.shutdown().await;
    result
}

/// Internal entry point used by the combined TCP/QUIC server so every direct
/// transport shares one auth-failure budget and one connection budget.
pub(crate) struct VerifiedQuicStartup {
    pub cfg: ServerConfig,
    pub auth: TunnelAuthKeyring,
}

pub(crate) async fn run_quic_server_with_ready_and_controls(
    startup: VerifiedQuicStartup,
    ready: Option<QuicReadiness>,
    rate_limiter: RateLimiter,
    semaphore: Arc<Semaphore>,
    mut shutdown: Option<tokio::sync::oneshot::Receiver<()>>,
    runtime: Arc<dyn quinn::Runtime>,
    sessions: QuicSessionTasks,
) -> anyhow::Result<()> {
    let VerifiedQuicStartup {
        cfg,
        auth: auth_keyring,
    } = startup;
    let mut ready = startup::Reporter::new(ready);
    ready.check(
        if cfg.transport.https_bridge.is_none() && cfg.transport.fronted_origin.is_none() {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "QUIC ingress is disabled by exclusive HTTPS bridge or fronted origin policy"
            ))
        },
        startup::Phase::Policy,
    )?;
    let listen_addr = ready.check(
        cfg.transport
            .quic_listen
            .clone()
            .unwrap_or_else(|| cfg.listen.clone())
            .parse::<std::net::SocketAddr>()
            .with_context(|| "parse quic listen addr"),
        startup::Phase::Address,
    )?;
    let mut server_config = ready.check(
        load_quic_server_config(
            &cfg.cert,
            &cfg.key,
            cfg.transport
                .secure_quic_authority
                .as_ref()
                .and(cfg.transport.inner_tls.as_ref()),
        ),
        startup::Phase::Tls,
    )?;
    server_config
        .transport_config(ready.check(masque_transport_config(&cfg), startup::Phase::Transport)?);
    let unauthenticated_limit = quic_unauthenticated_limit(cfg.limits.max_connections);
    // Bound pending Initial objects before the application can consume them.
    // Quinn's byte limits exclude the first datagram and drop excess buffered
    // data; ordinary QUIC retransmission recovers that data.
    server_config.max_incoming(unauthenticated_limit);
    server_config.incoming_buffer_size(MAX_QUIC_PENDING_BYTES_PER_INCOMING);
    server_config.incoming_buffer_size_total(
        unauthenticated_limit as u64 * MAX_QUIC_PENDING_BYTES_PER_INCOMING,
    );
    let unauthenticated = Arc::new(Semaphore::new(unauthenticated_limit));
    // Same standard UDP socket and Tokio timer/I/O implementation as
    // Endpoint::server, with endpoint-local task ownership added to spawn.
    let socket = ready.check(
        std::net::UdpSocket::bind(listen_addr).map_err(anyhow::Error::from),
        startup::Phase::UdpBind,
    )?;
    let endpoint = ready.check(
        quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            runtime,
        )
        .map_err(anyhow::Error::from),
        startup::Phase::Endpoint,
    )?;
    crate::operational_log::info_quic_listener_bound(cfg.logging.policy(), listen_addr);
    ready.success();

    loop {
        let incoming = tokio::select! {
            incoming = endpoint.accept() => incoming,
            result = sessions.join_next(), if !sessions.is_empty() => {
                if let Some(Err(error)) = result {
                    crate::operational_log::warn_failure(
                        cfg.logging.policy(),
                        crate::operational_log::FailureStage::QuicSession,
                        crate::operational_log::FailureReason::TaskFailed,
                        None,
                        &error,
                    );
                }
                continue;
            }
            _ = wait_for_shutdown(&mut shutdown) => {
                endpoint.set_server_config(None);
                break;
            }
        };
        let Some(incoming) = incoming else {
            break;
        };
        // Stateless Retry proves that the source can receive a response before
        // starting TLS, allocating an application task or holding any permit.
        if !incoming.remote_address_validated() {
            if let Err(error) = incoming.retry() {
                error.into_incoming().ignore();
            }
            continue;
        }
        let permit = match unauthenticated.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                tracing::debug!(
                    unauthenticated_limit,
                    "max unauthenticated QUIC connections reached, refusing ingress"
                );
                incoming.refuse();
                continue;
            }
        };
        // One original clock covers TLS, H3 setup, request headers, credential
        // bytes and any unauthenticated decoy work, including scheduling delay.
        let deadline =
            tokio::time::Instant::now() + Duration::from_millis(cfg.limits.read_timeout_ms);
        let authenticated = Arc::new(AtomicBool::new(false));
        let admission = QuicAdmission {
            deadline,
            unauthenticated_permit: Some(permit),
            established: semaphore.clone(),
            established_permit: None,
            authenticated: authenticated.clone(),
        };
        let cfg = cfg.clone();
        let auth_keyring = auth_keyring.clone();
        let rate_limiter = rate_limiter.clone();
        sessions.spawn(async move {
            let session = async {
                match await_quic_ingress_step(
                    incoming,
                    Duration::from_millis(cfg.limits.read_timeout_ms),
                )
                .await
                {
                    Ok(Ok(conn)) => {
                        if let Err(e) = handle_h3_connection(
                            conn,
                            cfg.clone(),
                            auth_keyring,
                            rate_limiter,
                            admission,
                        )
                        .await
                        {
                            if benign_h3_close(&e) {
                                tracing::debug!(
                                    event_code = "quic_connection_closed_benignly",
                                    "quic connection closed benignly"
                                );
                            } else {
                                crate::operational_log::warn_failure(
                                    cfg.logging.policy(),
                                    crate::operational_log::FailureStage::QuicConnection,
                                    crate::operational_log::FailureReason::ConnectionFailed,
                                    None,
                                    &e,
                                );
                            }
                        }
                    }
                    Ok(Err(e)) => crate::operational_log::warn_failure(
                        cfg.logging.policy(),
                        crate::operational_log::FailureStage::QuicIncoming,
                        crate::operational_log::FailureReason::HandshakeFailed,
                        None,
                        &e,
                    ),
                    Err(_) => tracing::debug!("quic handshake timed out; releasing admission slot"),
                }
            };
            if await_quic_admitted_session(session, deadline, authenticated)
                .await
                .is_err()
            {
                tracing::debug!("quic unauthenticated ingress timed out; releasing admission slot");
            }
        });
    }
    let stop_deadline =
        tokio::time::Instant::now() + Duration::from_millis(cfg.limits.shutdown_grace_ms);
    let drained = sessions
        .drain(Duration::from_millis(cfg.limits.shutdown_grace_ms))
        .await;
    endpoint.close(quinn::VarInt::from_u32(0), b"server shutdown");
    // Let normal QUIC close/draining complete only within the original grace.
    // The outer owner aborts+joins remaining drivers when this time is spent.
    let idle = tokio::time::timeout_at(stop_deadline, endpoint.wait_idle())
        .await
        .is_ok();
    tracing::info!(drained, idle, "QUIC ingress and owned sessions stopped");
    Ok(())
}

async fn await_quic_ingress_step<F, T, E>(
    incoming: F,
    max_wait: Duration,
) -> Result<Result<T, E>, tokio::time::error::Elapsed>
where
    F: std::future::IntoFuture<Output = Result<T, E>>,
{
    tokio::time::timeout(max_wait, std::future::IntoFuture::into_future(incoming)).await
}

async fn wait_for_shutdown(shutdown: &mut Option<tokio::sync::oneshot::Receiver<()>>) {
    match shutdown {
        Some(receiver) => {
            let _ = receiver.await;
        }
        None => std::future::pending::<()>().await,
    }
}

async fn handle_h3_connection(
    conn: quinn::Connection,
    cfg: ServerConfig,
    auth_keyring: TunnelAuthKeyring,
    rate_limiter: RateLimiter,
    mut admission: QuicAdmission,
) -> anyhow::Result<()> {
    // Active-probing seed: the QUIC/MASQUE endpoint is NOT fronted (Cloudflare
    // does not proxy MASQUE), so it sits directly on the origin's UDP/443 and is
    // scannable. A deterministic-per-connection seed keyed on the peer port
    // keeps one prober's decoy responses stable while varying across probers,
    // exactly like the TCP decoy paths.
    let peer = conn.remote_address();
    let decoy_seed = peer.port();
    // HTTP/3/MASQUE is exposed directly on UDP:443; there is no trusted HTTP
    // reverse proxy on this path. Use the QUIC peer IP and the same limiter as
    // TCP so protocol hopping cannot multiply the allowed auth failures.
    if rate_limiter.is_banned(peer.ip()).await {
        if auth_keyring.operational_log().includes_sensitive_context() {
            tracing::debug!(%peer, "banned direct QUIC client, dropping connection");
        } else {
            tracing::debug!(
                event_code = "banned_quic_client_dropped",
                "banned direct QUIC client dropped"
            );
        }
        return Ok(());
    }
    let quic = h3_quinn::Connection::new(conn.clone());
    let mut builder = h3::server::builder();
    builder.enable_extended_connect(true).enable_datagram(true);
    let mut h3_conn = builder.build::<_, Bytes>(quic).await?;

    // Bound the first H3 request as part of the unauthenticated ingress phase.
    // The server enables QUIC keepalive for real MASQUE sessions; without this
    // deadline, a peer that completes TLS but never sends request headers stays
    // alive forever. The outer original admission deadline also covers H3
    // setup and all remaining work before authentication.
    let first_request = async {
        let Some(resolver) = h3_conn.accept().await? else {
            return anyhow::Ok(None);
        };
        let request = resolver.resolve_request().await?;
        anyhow::Ok(Some(request))
    };
    let Some((req, stream)) = await_quic_ingress_step(
        first_request,
        Duration::from_millis(cfg.limits.read_timeout_ms),
    )
    .await
    .context("timed out waiting for first h3 request")??
    else {
        return Ok(());
    };
    let request_context = H3RequestContext {
        cfg: &cfg,
        auth_keyring: &auth_keyring,
        rate_limiter: &rate_limiter,
        peer,
        decoy_seed,
        admission: &mut admission,
    };
    match (req.method(), req.extensions().get::<Protocol>().copied()) {
        (&http::Method::CONNECT, Some(Protocol::CONNECT_UDP)) => {
            handle_connect_udp_request(req, stream, &mut h3_conn, request_context).await
        }
        (&http::Method::CONNECT, None) => {
            if req.uri().authority().is_some_and(|authority| {
                authority.as_str() == aegis_core::carrier_program::SECURE_QUIC_AUTHORITY
            }) && req.uri().path() == "/"
                && cfg.transport.secure_quic_authority.as_deref()
                    == Some(aegis_core::carrier_program::SECURE_QUIC_AUTHORITY)
            {
                // Rustls has already checked the issuing CA. Bind the exact
                // outer leaf to the current inner registry/static pin before
                // the enrolled-only H3 response becomes observable.
                let outer_leaf = conn
                    .peer_identity()
                    .and_then(|identity| identity.downcast::<Vec<CertificateDer<'static>>>().ok())
                    .and_then(|chain| chain.first().cloned());
                handle_enrolled_quic_request(req, stream, request_context, outer_leaf).await?;
            } else {
                handle_connect_tcp_request(req, stream, request_context).await?;
            }
            // h3-quinn's finish only queues the response FIN. Dropping the H3
            // owner here sends CONNECTION_CLOSE and discards unacknowledged
            // response bytes. Each AEGIS TCP tunnel owns a dedicated QUIC
            // connection: its client closes it after reading response EOF.
            // Keep the H3 owner alive until then, with the configured write
            // deadline so an uncooperative peer cannot pin a session forever.
            tokio::time::timeout(
                Duration::from_millis(cfg.limits.write_timeout_ms),
                conn.closed(),
            )
            .await
            .context("timed out draining h3 CONNECT response before peer close")?;
            Ok(())
        }
        _ => {
            // A plain h3 request (e.g. a browser-shaped GET) from an active
            // prober scanning the origin's QUIC endpoint must look like an
            // ordinary h3 web origin, NOT leak a bare AEGIS 400. Serve the same
            // seed-indexed decoy deck used by the h1/h2 probe paths.
            send_h3_decoy(stream, decoy_seed).await;
            // Keep the connection alive briefly so the decoy response reliably
            // flushes over QUIC before close (quinn does not guarantee delivery
            // of pending stream data on an abrupt drop) and so a multi-request
            // scanner is served like a real keep-alive origin. Bounded so a
            // probe cannot pin a connection open.
            let _ = tokio::time::timeout(Duration::from_secs(5), async {
                while let Ok(Some(resolver)) = h3_conn.accept().await {
                    if let Ok((_req, stream)) = resolver.resolve_request().await {
                        send_h3_decoy(stream, decoy_seed).await;
                    }
                }
            })
            .await;
            Ok(())
        }
    }
}

/// Dedicated H3 carrier for enrolled devices. The outer request contains no
/// token or target; the common secure handler authenticates the device before
/// granting a session or interpreting the inner target request.
async fn handle_enrolled_quic_request(
    req: http::Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    context: H3RequestContext<'_>,
    outer_leaf: Option<CertificateDer<'static>>,
) -> anyhow::Result<()> {
    let H3RequestContext {
        cfg,
        auth_keyring,
        rate_limiter,
        peer,
        admission,
        decoy_seed,
    } = context;
    if req.uri().query().is_some() || req.headers().contains_key(http::header::AUTHORIZATION) {
        rate_limiter.record_failure(peer.ip()).await;
        send_h3_decoy(stream, decoy_seed).await;
        anyhow::bail!("enrolled QUIC request carried forbidden outer fields");
    }
    let server = auth_keyring
        .inner_tls
        .clone()
        .context("enrolled QUIC identity absent")?;
    let current = outer_leaf.as_ref().is_some_and(|leaf| {
        server
            .check_current_device_certificate(leaf.as_ref())
            .is_ok()
    });
    if !current {
        rate_limiter.record_failure(peer.ip()).await;
        send_h3_decoy(stream, decoy_seed).await;
        anyhow::bail!("enrolled QUIC outer device authorization refused");
    }
    let response = http::Response::builder().status(200).body(())?;
    stream.send_response(response).await?;
    let (app, wire) = tokio::io::duplex(64 * 1024);
    let (mut send, mut recv) = stream.split();
    let (mut local_read, mut local_write) = tokio::io::split(wire);
    let uplink = async {
        while let Some(mut frame) = recv.recv_data().await? {
            let body = frame.copy_to_bytes(frame.remaining());
            local_write.write_all(&body).await?;
        }
        local_write.shutdown().await?;
        anyhow::Ok(())
    };
    let downlink = async {
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
    let pump = async { tokio::try_join!(uplink, downlink).map(|_| ()) };
    let serve = super::secure::serve_carrier(
        app,
        server,
        &cfg.target_policy,
        rate_limiter,
        Some(peer.ip()),
        None,
        || {
            admission
                .promote()
                .map_err(|_| std::io::Error::other("enrolled QUIC admission refused"))
        },
        cfg.transport.authenticated_shaping.as_ref(),
        cfg.logging.policy(),
    );
    tokio::try_join!(pump, serve)?;
    Ok(())
}

/// Emit a generic web-server decoy over an h3 request stream (best-effort — the
/// prober may already be gone). Reuses the shared decoy deck so the QUIC
/// endpoint tells the same benign-origin story as the TCP surfaces.
async fn send_h3_decoy(
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    seed: u16,
) {
    let (response, body) = crate::session::decoy::http2_response(seed);
    if stream.send_response(response).await.is_ok() {
        if !body.is_empty() {
            let _ = stream.send_data(body).await;
        }
        let _ = stream.finish().await;
    }
}

async fn handle_connect_tcp_request(
    req: http::Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    context: H3RequestContext<'_>,
) -> anyhow::Result<()> {
    let capture_proof_deadline =
        tokio::time::Instant::now() + Duration::from_secs(auto_capture_probe::MAX_SECONDS);
    let H3RequestContext {
        cfg,
        auth_keyring,
        rate_limiter,
        peer,
        decoy_seed,
        admission,
    } = context;
    let (target_host, target_port) = connect_target_from_uri(req.uri())?;
    let first_data = tokio::time::timeout(
        Duration::from_millis(cfg.limits.read_timeout_ms),
        stream.recv_data(),
    )
    .await;
    let mut frame = match first_data {
        Ok(Ok(Some(frame))) => frame,
        Ok(Ok(None)) => {
            rate_limiter.record_failure(peer.ip()).await;
            send_h3_decoy(stream, decoy_seed).await;
            anyhow::bail!("missing h3 CONNECT tunnel request");
        }
        Ok(Err(error)) => return Err(error).context("read h3 CONNECT tunnel request"),
        Err(_) => {
            rate_limiter.record_failure(peer.ip()).await;
            send_h3_decoy(stream, decoy_seed).await;
            anyhow::bail!("timed out reading h3 CONNECT tunnel request");
        }
    };
    let frame = frame.copy_to_bytes(frame.remaining());
    if frame.len() > MAX_TUNNEL_REQUEST_BYTES {
        rate_limiter.record_failure(peer.ip()).await;
        send_h3_decoy(stream, decoy_seed).await;
        anyhow::bail!(
            "h3 CONNECT tunnel request too large: {} bytes (max {MAX_TUNNEL_REQUEST_BYTES})",
            frame.len()
        );
    }
    let authenticated = match auth_keyring.open_request(frame.as_ref()) {
        Ok(authenticated) => authenticated,
        Err(err) => {
            // Unauthenticated CONNECT probe: serve the generic web decoy rather
            // than a bare AEGIS 403, so a prober cannot tell tunnel-auth
            // semantics from a stock h3 origin that simply refuses the path.
            rate_limiter.record_failure(peer.ip()).await;
            send_h3_decoy(stream, decoy_seed).await;
            return Err(err.into());
        }
    };
    auth_keyring.log_accept(&authenticated.key, peer, "masque_connect_tcp");
    let open = authenticated.request;
    let auth_token = authenticated.key.secret();
    if open.host != target_host || open.port != target_port {
        let response = http::Response::builder().status(400).body(())?;
        stream.send_response(response).await?;
        stream.finish().await?;
        anyhow::bail!(
            "CONNECT authority mismatch: uri={target_host}:{target_port} frame={}:{}",
            open.host,
            open.port
        );
    }

    admission.promote()?;
    if auto_capture_probe::tcp_target(&target_host, target_port) {
        // Reuse the authenticated CONNECT response and ordinary DATA stream.
        // Each DATA frame is a chunk of TCP bytes, not a challenge boundary.
        tokio::time::timeout_at(capture_proof_deadline, async {
            let response = http::Response::builder().status(200).body(())?;
            stream.send_response(response).await?;
            stream
                .send_data(Bytes::from(seal_tunnel_response(
                    &TunnelResponse {
                        status: TunnelStatus::Ok,
                        message: String::new(),
                    },
                    auth_token,
                )?))
                .await?;
            let mut challenge = [0u8; auto_capture_probe::CHALLENGE_BYTES];
            let mut received = 0;
            for _ in 0..auto_capture_probe::CHALLENGE_BYTES {
                let mut fragment = stream
                    .recv_data()
                    .await?
                    .context("native capture stream challenge incomplete")?;
                let length = fragment.remaining();
                anyhow::ensure!(length > 0, "empty capture stream fragment");
                anyhow::ensure!(
                    length <= challenge.len() - received,
                    "capture stream challenge overflow"
                );
                fragment.copy_to_slice(&mut challenge[received..received + length]);
                received += length;
                if received == challenge.len() {
                    break;
                }
            }
            anyhow::ensure!(
                received == challenge.len(),
                "capture stream challenge incomplete"
            );
            stream.send_data(Bytes::copy_from_slice(&challenge)).await?;
            stream.finish().await?;
            anyhow::Ok(())
        })
        .await??;
        return Ok(());
    }
    let mut remote = match crate::target_policy::connect_tcp_target_with_logging(
        &target_host,
        target_port,
        &cfg.target_policy,
        cfg.logging.policy(),
    )
    .await
    {
        Ok(remote) => remote,
        Err(err) => {
            let response = http::Response::builder().status(200).body(())?;
            stream.send_response(response).await?;
            stream
                .send_data(Bytes::from(seal_tunnel_response(
                    &TunnelResponse {
                        status: classify_connect_failure_status(&err),
                        message: "target_connect_failed".to_owned(),
                    },
                    auth_token,
                )?))
                .await?;
            let _ = stream.finish().await;
            return Ok(());
        }
    };

    let response = http::Response::builder().status(200).body(())?;
    stream.send_response(response).await?;
    stream
        .send_data(Bytes::from(seal_tunnel_response(
            &TunnelResponse {
                status: TunnelStatus::Ok,
                message: String::new(),
            },
            auth_token,
        )?))
        .await?;
    let (mut send_stream, mut recv_stream) = stream.split();

    let (mut remote_read, mut remote_write) = remote.split();
    let h3_to_target = async {
        loop {
            let next = match recv_stream
                .recv_data()
                .await
                .context("read h3 CONNECT body")
            {
                Ok(next) => next,
                Err(err) => {
                    if benign_h3_close(&err) {
                        break;
                    }
                    return Err(err);
                }
            };
            let Some(mut chunk) = next else {
                break;
            };
            let chunk = chunk.copy_to_bytes(chunk.remaining());
            if let Err(err) = remote_write.write_all(chunk.as_ref()).await {
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
    let target_to_h3 = async {
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = match remote_read.read(&mut buf).await {
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
                if let Err(err) = send_stream.finish().await {
                    let err = anyhow::Error::from(err);
                    if !benign_h3_close(&err) {
                        return Err(err);
                    }
                }
                break;
            }
            if let Err(err) = send_stream
                .send_data(Bytes::copy_from_slice(&buf[..n]))
                .await
            {
                let err = anyhow::Error::from(err);
                if benign_h3_close(&err) {
                    break;
                }
                return Err(err);
            }
        }
        anyhow::Ok(())
    };
    tokio::try_join!(h3_to_target, target_to_h3)?;
    Ok(())
}

async fn handle_connect_udp_request(
    req: http::Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    h3_conn: &mut h3::server::Connection<h3_quinn::Connection, Bytes>,
    context: H3RequestContext<'_>,
) -> anyhow::Result<()> {
    let capture_proof_deadline =
        tokio::time::Instant::now() + Duration::from_secs(auto_capture_probe::MAX_SECONDS);
    let H3RequestContext {
        cfg,
        auth_keyring,
        rate_limiter,
        peer,
        decoy_seed,
        admission,
    } = context;
    let mut parsed = None;
    for path in cfg.transport.accepted_masque_paths() {
        if let Ok(result) = parse_connect_udp_path(req.uri().path(), path) {
            parsed = Some(result);
            break;
        }
    }
    let (host, port) = parsed
        .ok_or_else(|| anyhow::anyhow!("unsupported CONNECT-UDP path {}", req.uri().path()))?;

    // AUTHENTICATE BEFORE DOING ANY WORK.
    //
    // This path previously relayed datagrams for any peer that knew the (compiled-in,
    // public) MASQUE path. That made the relay (a) an open UDP proxy usable for
    // amplification and for laundering scans through the relay IP, (b) an SSRF vector
    // into the origin's own RFC1918/loopback UDP services, and (c) — worst for the
    // threat model — a positive AEGIS oracle: `200` for a valid MASQUE path and
    // silence otherwise identifies the relay in a single packet.
    //
    // The credential is the same sealed `TunnelRequest` the TCP CONNECT path uses,
    // carried in a standard `Authorization: Bearer` header. A header (rather than a
    // stream DATA frame) is deliberate: on an extended-CONNECT stream the body is the
    // capsule stream, so a DATA frame is not reliably readable here, and waiting for
    // one would let an idle peer pin a connection permit. `Authorization` on a MASQUE
    // proxy request is ordinary HTTP and adds no novel fingerprint.
    //
    // Validate *before* resolving a name or binding a socket, so an unauthenticated
    // peer cannot make us do either. Failures get the generic web decoy, not a bare
    // AEGIS error, so probes stay indistinguishable from a stock h3 origin.
    let credential = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .and_then(|value| hex::decode(value.trim()).ok());
    let Some(credential) = credential else {
        rate_limiter.record_failure(peer.ip()).await;
        send_h3_decoy(stream, decoy_seed).await;
        anyhow::bail!("CONNECT-UDP without a tunnel credential");
    };
    if credential.len() > MAX_TUNNEL_REQUEST_BYTES {
        rate_limiter.record_failure(peer.ip()).await;
        send_h3_decoy(stream, decoy_seed).await;
        anyhow::bail!(
            "CONNECT-UDP tunnel credential too large: {} bytes (max {MAX_TUNNEL_REQUEST_BYTES})",
            credential.len()
        );
    }
    let authenticated = match auth_keyring.open_request(&credential) {
        Ok(authenticated) => authenticated,
        Err(err) => {
            rate_limiter.record_failure(peer.ip()).await;
            send_h3_decoy(stream, decoy_seed).await;
            return Err(err.into());
        }
    };
    auth_keyring.log_accept(&authenticated.key, peer, "masque_connect_udp");
    let open = authenticated.request;
    // The sealed frame is the authority: refuse when it disagrees with the URI path,
    // so a valid credential for one target cannot be replayed onto another.
    if open.host != host || open.port != port {
        send_h3_decoy(stream, decoy_seed).await;
        anyhow::bail!(
            "CONNECT-UDP authority mismatch: path={host}:{port} frame={}:{}",
            open.host,
            open.port
        );
    }

    admission.promote()?;
    if auto_capture_probe::udp_target(&host, port) {
        // The exact protocol tuple is admitted only after the ordinary sealed
        // CONNECT-UDP credential, path authority, and shared permit. The
        // datagram stays on the selected user's MASQUE carrier; no target
        // resolution, UDP socket, or public probe response is involved.
        tokio::time::timeout_at(capture_proof_deadline, async {
            let response = http::Response::builder()
                .status(200)
                .header("capsule-protocol", "?1")
                .body(())?;
            stream.send_response(response).await?;
            let stream_id = stream.id();
            let mut sender = h3_conn.get_datagram_sender(stream_id);
            let mut reader = h3_conn.get_datagram_reader();
            loop {
                let datagram = reader.read_datagram().await?;
                if datagram.stream_id() != stream_id {
                    continue;
                }
                let response = masque_capture_reply(datagram.into_payload())?;
                sender
                    .send_datagram(Bytes::copy_from_slice(&response))
                    .map_err(|error| anyhow::anyhow!("send capture datagram: {error}"))?;
                return anyhow::Ok(());
            }
        })
        .await??;
        // h3-quinn queues the datagram. CONNECT-UDP carries no request DATA,
        // so recv_data may report EOF before the datagram reaches the peer.
        // Retain the H3 owner to the original five-second deadline; dropping
        // it immediately discards the unacknowledged response.
        tokio::time::sleep_until(capture_proof_deadline).await;
        return Ok(());
    }
    let resolved = crate::target_policy::resolve_allowed_targets_with_logging(
        &host,
        port,
        &cfg.target_policy,
        cfg.logging.policy(),
    )
    .await?
    .into_iter()
    .next()
    .ok_or_else(|| anyhow::anyhow!("resolve {host}:{port}"))?;
    let bind_addr = if resolved.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let remote = UdpSocket::bind(bind_addr).await?;
    remote.connect(resolved).await?;

    let response = http::Response::builder()
        .status(200)
        .header("capsule-protocol", "?1")
        .body(())?;
    stream.send_response(response).await?;

    let stream_id = stream.id();
    let mut datagram_sender = h3_conn.get_datagram_sender(stream_id);
    let mut datagram_reader = h3_conn.get_datagram_reader();
    let mut recv_buf = vec![0u8; 65_535];
    // QUIC keepalive is intentionally enabled for active MASQUE sessions, so
    // the transport's idle timeout cannot protect the shared connection
    // semaphore from a client that abandons CONNECT-UDP without closing the
    // connection. Treat the configured QUIC idle value as the application
    // inactivity bound as well. `0` retains the documented explicit opt-out.
    let application_idle_enabled = cfg.transport.quic_max_idle_timeout_ms > 0;
    let application_idle = Duration::from_millis(cfg.transport.quic_max_idle_timeout_ms.max(1));

    loop {
        tokio::select! {
            _ = tokio::time::sleep(application_idle), if application_idle_enabled => {
                tracing::debug!(
                    idle_timeout_ms = cfg.transport.quic_max_idle_timeout_ms,
                    "CONNECT-UDP application idle timeout; releasing connection permit"
                );
                return Ok(());
            }
            incoming = datagram_reader.read_datagram() => {
                let datagram = incoming?;
                if datagram.stream_id() != stream_id {
                    continue;
                }
                let payload = decode_connect_udp_payload(datagram.into_payload())?;
                remote.send(&payload).await?;
            }
            outgoing = remote.recv(&mut recv_buf) => {
                let n = outgoing?;
                datagram_sender
                    .send_datagram(Bytes::from(encode_connect_udp_payload(&recv_buf[..n])))
                    .map_err(|e| anyhow::anyhow!("send h3 datagram: {e}"))?;
            }
        }
    }
}

fn masque_capture_reply(
    payload: Bytes,
) -> anyhow::Result<[u8; 1 + auto_capture_probe::CHALLENGE_BYTES]> {
    // CONNECT-UDP context ID 0 followed by one fixed challenge. Check before
    // copying: generic datagrams may be much larger than this proof permits.
    anyhow::ensure!(
        payload.len() == 1 + auto_capture_probe::CHALLENGE_BYTES && payload[0] == 0,
        "invalid native capture datagram"
    );
    let mut response = [0u8; 1 + auto_capture_probe::CHALLENGE_BYTES];
    response.copy_from_slice(&payload);
    Ok(response)
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

fn load_quic_server_config(
    cert: &std::path::Path,
    key: &std::path::Path,
    enrolled: Option<&aegis_core::secure_channel::ServerSettings>,
) -> anyhow::Result<quinn::ServerConfig> {
    let cert_file =
        std::fs::File::open(cert).with_context(|| format!("open {}", cert.display()))?;
    let key_bytes = aegis_core::secret_file::read_config(key, 1024 * 1024)
        .context("read protected QUIC private key")?;
    let mut cert_reader = std::io::BufReader::new(cert_file);
    let mut key_reader = std::io::Cursor::new(key_bytes.as_slice());
    let certs = CertificateDer::pem_reader_iter(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("parse quic cert pem")?;
    let key = PrivateKeyDer::from_pem_reader(&mut key_reader).context("read quic private key")?;

    let builder = rustls::ServerConfig::builder();
    let mut crypto = match enrolled {
        Some(identity) => {
            let roots = aegis_core::secure_channel::load_trust_roots(&identity.client_ca)?;
            let verifier =
                rustls::server::WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
            builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)
        }
        None => builder.with_no_client_auth().with_single_cert(certs, key),
    }
    .context("quic rustls server config")?;
    crypto.alpn_protocols = vec![b"h3".to_vec()];

    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(quic_crypto)))
}

fn connect_target_from_uri(uri: &http::Uri) -> anyhow::Result<(String, u16)> {
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow::anyhow!("missing CONNECT authority"))?;
    // http::uri::Authority::host retains an IPv6 literal's URI brackets.
    // TunnelRequest.host and the egress resolver use the bare address. Remove
    // only that syntax before the existing authenticated host/port comparison.
    let host = authority.host();
    let target_host = match host.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        Some(ipv6) => {
            ipv6.parse::<std::net::Ipv6Addr>()
                .context("invalid CONNECT IPv6 address")?;
            ipv6
        }
        None => host,
    };
    let target_port = authority
        .port_u16()
        .ok_or_else(|| anyhow::anyhow!("missing CONNECT port"))?;
    Ok((target_host.to_string(), target_port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masque_capture_datagram_requires_exact_context_and_challenge_size() {
        let mut frame = [0u8; 1 + auto_capture_probe::CHALLENGE_BYTES];
        frame[1..].fill(0x5b);
        assert_eq!(
            masque_capture_reply(Bytes::copy_from_slice(&frame)).unwrap(),
            frame
        );
        assert!(masque_capture_reply(Bytes::copy_from_slice(&frame[..32])).is_err());
        let mut oversized = frame.to_vec();
        oversized.push(0);
        assert!(masque_capture_reply(Bytes::from(oversized)).is_err());
        frame[0] = 1;
        assert!(masque_capture_reply(Bytes::copy_from_slice(&frame)).is_err());
    }

    #[test]
    fn connect_authority_ipv6_matches_bare_authenticated_host() {
        let uri: http::Uri = "https://[2001:db8::42]:443".parse().unwrap();
        let (host, port) = connect_target_from_uri(&uri).unwrap();
        assert_eq!(host, "2001:db8::42");
        assert_eq!(port, 443);
        assert!(host.parse::<std::net::Ipv6Addr>().is_ok());
    }

    #[test]
    fn connect_authority_preserves_hostname_and_ipv4_targets() {
        for (uri, expected_host, expected_port) in [
            ("https://example.com:443", "example.com", 443),
            ("https://192.0.2.10:8443", "192.0.2.10", 8443),
        ] {
            assert_eq!(
                connect_target_from_uri(&uri.parse().unwrap()).unwrap(),
                (expected_host.to_string(), expected_port)
            );
        }
    }

    #[test]
    fn connect_authority_requires_an_explicit_port() {
        for uri in ["https://example.com", "https://[2001:db8::42]", "/relative"] {
            assert!(connect_target_from_uri(&uri.parse().unwrap()).is_err());
        }
    }

    struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    async fn spawn_pending_with_drop_signal(
        tasks: &QuicSessionTasks,
    ) -> tokio::sync::oneshot::Receiver<()> {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
        tasks.spawn(async move {
            let _drop_signal = DropSignal(Some(dropped_tx));
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        started_rx.await.expect("owned fixture task started");
        dropped_rx
    }

    #[tokio::test]
    async fn quic_session_grace_allows_natural_completion() {
        let tasks = QuicSessionTasks::new(Default::default());
        let (complete_tx, complete_rx) = tokio::sync::oneshot::channel();
        tasks.spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let _ = complete_tx.send(());
        });
        assert!(tasks.drain(Duration::from_secs(1)).await);
        complete_rx
            .await
            .expect("session was not cancelled during grace");
        assert!(tasks.is_empty());
    }

    #[tokio::test]
    async fn quic_cancelled_inner_join_remains_owned_by_outer_guard() {
        let mut owner = QuicRuntimeTasks::new(Default::default());
        let dropped = spawn_pending_with_drop_signal(&owner.sessions).await;
        let sessions = owner.sessions();
        let mut inner_shutdown = Box::pin(sessions.shutdown());
        // Poll once on this single-thread runtime: abort is requested, but the
        // owned task cannot finish until the scheduler next runs it.
        assert!(futures::poll!(inner_shutdown.as_mut()).is_pending());
        drop(inner_shutdown);
        assert!(
            !owner.sessions.is_empty(),
            "cancelled join retained handles"
        );
        tokio::time::timeout(Duration::from_secs(1), owner.shutdown())
            .await
            .expect("outer owner resumes bounded cancellation join");
        dropped
            .await
            .expect("application future was dropped before return");
        assert!(owner.sessions.is_empty());
    }

    #[tokio::test]
    async fn quic_owner_forced_stop_joins_only_its_application_and_driver_tasks() {
        let mut owner = QuicRuntimeTasks::new(Default::default());
        let application_dropped = spawn_pending_with_drop_signal(&owner.sessions).await;
        let driver_dropped = spawn_pending_with_drop_signal(&owner.runtime.tasks).await;
        let unrelated = crate::lifecycle::OwnedTask(tokio::spawn(std::future::pending::<()>()));
        tokio::time::timeout(Duration::from_secs(1), owner.shutdown())
            .await
            .expect("owned task join deadline");
        application_dropped
            .await
            .expect("application future dropped");
        driver_dropped.await.expect("driver future dropped");
        assert!(
            !unrelated.0.is_finished(),
            "unrelated runtime task survives"
        );
        assert!(owner.sessions.is_empty());
        assert!(owner.runtime.tasks.is_empty());

        let (late_tx, late_rx) = tokio::sync::oneshot::channel();
        owner.runtime().spawn(Box::pin(async move {
            let _ = late_tx.send(());
        }));
        assert!(
            late_rx.await.is_err(),
            "late driver spawn is dropped, never run"
        );
    }

    #[tokio::test]
    async fn quic_owner_drop_cancels_application_and_driver_tasks() {
        let owner = QuicRuntimeTasks::new(Default::default());
        let application_dropped = spawn_pending_with_drop_signal(&owner.sessions).await;
        let driver_dropped = spawn_pending_with_drop_signal(&owner.runtime.tasks).await;
        drop(owner);
        tokio::time::timeout(Duration::from_secs(1), async {
            application_dropped
                .await
                .expect("application future cancelled");
            driver_dropped.await.expect("driver future cancelled");
        })
        .await
        .expect("owner drop cancellation deadline");
    }

    #[test]
    fn benign_h3_close_accepts_no_error_variants() {
        assert!(benign_h3_close(&anyhow::Error::new(
            H3StreamError::RemoteClosing
        )));
        assert!(benign_h3_close(&anyhow::Error::new(
            H3StreamError::RemoteTerminate {
                code: H3Code::H3_NO_ERROR
            }
        )));
        assert!(benign_h3_close(&anyhow::anyhow!(
            "Connection error: Remote error: ApplicationClose: 0x0"
        )));
        assert!(!benign_h3_close(&anyhow::Error::from(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timeout"
        ))));
    }

    #[test]
    fn masque_transport_config_rejects_keepalive_not_below_idle_timeout() {
        let mut cfg = ServerConfig {
            listen: "127.0.0.1:8443".into(),
            cert: "cert.pem".into(),
            key: "key.pem".into(),
            auth_token: "token".into(),
            legacy_auth_tokens: Vec::new(),
            process_alias: None,
            logging: Default::default(),
            fallback: "close".into(),
            limits: Default::default(),
            rate_limit: Default::default(),
            target_policy: Default::default(),
            transport: Default::default(),
            bundle_endpoint: Default::default(),
        };
        cfg.transport.quic_keep_alive_interval_ms = 1_000;
        cfg.transport.quic_max_idle_timeout_ms = 1_000;

        let err = masque_transport_config(&cfg).expect_err("invalid keepalive/idle contract");
        assert!(
            err.to_string()
                .contains("transport.quic_keep_alive_interval_ms must be smaller"),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn stalled_quic_ingress_releases_shared_connection_permit() {
        let semaphore = Arc::new(Semaphore::new(1));
        let permit = semaphore.clone().try_acquire_owned().expect("test permit");
        assert_eq!(semaphore.available_permits(), 0);

        let task = tokio::spawn(async move {
            let _permit = permit;
            let result: Result<Result<(), ()>, _> = await_quic_ingress_step(
                std::future::pending::<Result<(), ()>>(),
                Duration::from_millis(20),
            )
            .await;
            assert!(result.is_err(), "pending handshake must time out");
        });
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("handshake timeout task must finish")
            .expect("handshake timeout task must not panic");

        assert_eq!(
            semaphore.available_permits(),
            1,
            "timed-out QUIC handshake must not pin the shared TCP/QUIC budget"
        );
    }
}

#[cfg(test)]
#[path = "quic/admission_tests.rs"]
mod admission_tests;
