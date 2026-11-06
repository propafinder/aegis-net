//! TLS session orchestration for legacy encrypted stream, WebSocket and gRPC.

pub(crate) mod admission;
pub(crate) mod bundle_endpoint;
pub(crate) mod decoy;
#[cfg(feature = "legacy-challenge-v1")]
mod fresh_legacy;
pub(crate) mod fronted;
mod grpc;
pub(crate) mod https_bridge;
mod legacy_tcp;
pub(crate) mod quic;
mod secure;
mod secure_udp;
mod websocket;

#[cfg(all(test, not(feature = "legacy-challenge-v1")))]
#[path = "session/legacy_fallback_decoy_tests.rs"]
mod legacy_fallback_decoy_tests;

/// Admit an opaque web-response or WebRTC stream through the existing device
/// mTLS registry before any TCP/UDP target can be resolved or contacted.
/// The callback must only extend carrier lifetime; it cannot authorize egress.
pub async fn serve_device_carrier<S>(
    carrier: S,
    server: aegis_core::secure_channel::Server,
    policy: &crate::config::TargetPolicyConfig,
    rate_limiter: &crate::rate_limit::RateLimiter,
    peer: Option<std::net::IpAddr>,
    authenticated: impl FnOnce() -> std::io::Result<()>,
    privacy: Option<&aegis_core::carrier_runtime::PrivacySettings>,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    serve_device_carrier_with_logging(
        carrier,
        server,
        policy,
        rate_limiter,
        peer,
        authenticated,
        privacy,
        crate::operational_log::OperationalLogPolicy::default(),
    )
    .await
}

/// Crate runtime path that carries the immutable server logging policy.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve_device_carrier_with_logging<S>(
    carrier: S,
    server: aegis_core::secure_channel::Server,
    policy: &crate::config::TargetPolicyConfig,
    rate_limiter: &crate::rate_limit::RateLimiter,
    peer: Option<std::net::IpAddr>,
    authenticated: impl FnOnce() -> std::io::Result<()>,
    privacy: Option<&aegis_core::carrier_runtime::PrivacySettings>,
    operational_log: crate::operational_log::OperationalLogPolicy,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    secure::serve_carrier(
        carrier,
        server,
        policy,
        rate_limiter,
        peer,
        None,
        authenticated,
        privacy,
        operational_log,
    )
    .await
}

use crate::config::{ServerConfig, ServerLimits, TargetPolicyConfig, TransportConfig};
use crate::rate_limit::RateLimiter;
use aegis_core::tunnel::{
    encode_stream_frame, open_tunnel_request_with_kind, seal_tunnel_response, TunnelRequest,
    TunnelRequestKind, TunnelResponse, TunnelStatus,
};
#[cfg(not(feature = "legacy-challenge-v1"))]
use aegis_core::tunnel::{read_stream_frame, MAX_TUNNEL_CONTROL_FRAME};
use anyhow::Context;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio_rustls::server::TlsStream;

/// One absolute clock from TCP admission through device/token authentication.
#[derive(Clone)]
pub(crate) struct AdmissionBudget {
    pub deadline: tokio::time::Instant,
    pub timeout: Duration,
    socket_permit: Option<Arc<std::sync::Mutex<Option<admission::SocketAdmissionPermit>>>>,
}

impl AdmissionBudget {
    pub(crate) fn new(timeout: Duration) -> Self {
        Self {
            deadline: tokio::time::Instant::now() + timeout,
            timeout,
            socket_permit: None,
        }
    }

    pub(crate) fn bounded(self, timeout: Duration) -> Self {
        Self {
            deadline: self.deadline.min(tokio::time::Instant::now() + timeout),
            timeout: self.timeout.min(timeout),
            socket_permit: self.socket_permit,
        }
    }

    pub(crate) fn with_socket_permit(mut self, permit: admission::SocketAdmissionPermit) -> Self {
        self.socket_permit = Some(Arc::new(std::sync::Mutex::new(Some(permit))));
        self
    }

    pub(crate) fn with_deadline(&self, deadline: tokio::time::Instant) -> Self {
        Self {
            deadline,
            ..self.clone()
        }
    }

    pub(crate) fn check_deadline(&self) -> std::io::Result<()> {
        if tokio::time::Instant::now() >= self.deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "original admission deadline elapsed",
            ));
        }
        Ok(())
    }

    pub(crate) fn authenticated(&self) -> std::io::Result<()> {
        if let Some(permit) = &self.socket_permit {
            let mut permit = permit.lock().unwrap_or_else(|e| e.into_inner());
            self.check_deadline()?;
            permit.take();
        } else {
            self.check_deadline()?;
        }
        Ok(())
    }
}

/// Runtime keyring for a staged tunnel-credential migration.
///
/// Secrets deliberately have no `Debug` implementation. A successful open
/// carries the exact matching key forward because tunnel responses must be
/// sealed with the same secret the client used for its request.
#[derive(Clone)]
pub(crate) struct TunnelAuthKeyring {
    keys: Arc<[TunnelAuthKey]>,
    operational_log: crate::operational_log::OperationalLogPolicy,
    pub(super) inner_tls: Option<aegis_core::secure_channel::Server>,
    pub(super) https_bridge: Option<Arc<aegis_core::https_bridge::Gate>>,
    pub(super) fronted_origin: Option<Arc<fronted::FrontedOrigin>>,
    pub(super) relay_training:
        Option<Arc<aegis_core::secure_channel::relay_shaping::ServerTraining>>,
}

#[derive(Clone)]
pub(crate) struct TunnelAuthKey {
    id: Arc<str>,
    secret: Arc<[u8]>,
    legacy: bool,
    not_after_unix_secs: Option<u64>,
}

pub(crate) struct AuthenticatedTunnelRequest {
    pub request: TunnelRequest,
    pub kind: TunnelRequestKind,
    pub key: TunnelAuthKey,
}

impl TunnelAuthKeyring {
    #[cfg(test)]
    pub fn from_config(cfg: &ServerConfig) -> anyhow::Result<Self> {
        Self::from_config_with_loader(cfg, aegis_core::secure_channel::Server::load)
    }

    pub async fn from_config_for_startup(cfg: &ServerConfig) -> anyhow::Result<Self> {
        Self::from_config_for_startup_with_observer(cfg, None).await
    }

    pub(crate) async fn from_config_for_startup_with_observer(
        cfg: &ServerConfig,
        witness: Option<&crate::phase_witness::ServerPhaseWitness>,
    ) -> anyhow::Result<Self> {
        let profile = cfg.transport.authenticated_shaping.clone();
        let cfg = cfg.clone();
        let mut keyring = tokio::task::spawn_blocking(move || {
            Self::from_config_with_loader(
                &cfg,
                aegis_core::secure_channel::Server::load_for_startup,
            )
        })
        .await??;
        if let Some(profile) = profile {
            let training = crate::phase_witness::ServerPhaseWitness::observe_optimizer_startup(
                witness,
                aegis_core::secure_channel::relay_shaping::ServerTraining::prepare(&profile),
            )
            .await?;
            keyring.relay_training = training.map(Arc::new);
        }
        Ok(keyring)
    }

    fn from_config_with_loader(
        cfg: &ServerConfig,
        load: impl FnOnce(
            &aegis_core::secure_channel::ServerSettings,
        ) -> std::io::Result<aegis_core::secure_channel::Server>,
    ) -> anyhow::Result<Self> {
        cfg.validate_auth_tokens()?;
        let inner_tls = cfg.transport.inner_tls.as_ref().map(load).transpose()?;
        let https_bridge = cfg
            .transport
            .https_bridge
            .as_ref()
            .map(aegis_core::https_bridge::Gate::load)
            .transpose()?
            .map(Arc::new);
        let fronted_origin = cfg
            .transport
            .fronted_origin
            .as_ref()
            .map(fronted::FrontedOrigin::load)
            .transpose()?
            .map(Arc::new);
        // An mTLS origin must not also accept replayable shared-token opens on
        // raw TLS, WebSocket, QUIC or the legacy gRPC dispatcher. All of those
        // paths authenticate through this keyring before opening a target.
        if inner_tls.is_some() {
            return Ok(Self {
                keys: Vec::new().into(),
                operational_log: cfg.logging.policy(),
                inner_tls,
                https_bridge,
                fronted_origin,
                relay_training: None,
            });
        }
        let mut keys = Vec::with_capacity(1 + cfg.legacy_auth_tokens.len());
        keys.push(TunnelAuthKey {
            id: Arc::from("current"),
            secret: Arc::from(cfg.auth_token.as_bytes()),
            legacy: false,
            not_after_unix_secs: None,
        });
        keys.extend(cfg.legacy_auth_tokens.iter().map(|legacy| TunnelAuthKey {
            id: Arc::from(legacy.id.as_str()),
            secret: Arc::from(legacy.auth_token.as_bytes()),
            legacy: true,
            not_after_unix_secs: Some(legacy.not_after_unix_secs),
        }));
        Ok(Self {
            keys: keys.into(),
            operational_log: cfg.logging.policy(),
            inner_tls,
            https_bridge,
            fronted_origin,
            relay_training: None,
        })
    }

    pub fn open_request(&self, frame: &[u8]) -> aegis_core::Result<AuthenticatedTunnelRequest> {
        self.open_request_at(frame, unix_time_now())
    }

    /// Open either the legacy stream request or the message-preserving
    /// datagram request. This is intentionally exposed only to the gRPC
    /// dispatcher; raw TLS, WebSocket and QUIC stream paths stay stream-only.
    pub fn open_request_any(&self, frame: &[u8]) -> aegis_core::Result<AuthenticatedTunnelRequest> {
        self.open_request_any_at(frame, unix_time_now())
    }

    fn open_request_at(
        &self,
        frame: &[u8],
        now_unix_secs: u64,
    ) -> aegis_core::Result<AuthenticatedTunnelRequest> {
        let authenticated = self.open_request_any_at(frame, now_unix_secs)?;
        if authenticated.kind != TunnelRequestKind::Stream {
            return Err(aegis_core::AegisError::RelayCodec(
                "bad tunnel request version/kind".into(),
            ));
        }
        Ok(authenticated)
    }

    fn open_request_any_at(
        &self,
        frame: &[u8],
        now_unix_secs: u64,
    ) -> aegis_core::Result<AuthenticatedTunnelRequest> {
        let mut primary_error = None;
        for key in self.keys.iter() {
            if !key.is_active_at(now_unix_secs) {
                continue;
            }
            match open_tunnel_request_with_kind(frame, key.secret()) {
                Ok(opened) => {
                    return Ok(AuthenticatedTunnelRequest {
                        request: opened.request,
                        kind: opened.kind,
                        key: key.clone(),
                    })
                }
                Err(error) if !key.legacy => primary_error = Some(error),
                Err(_) => {}
            }
        }
        Err(primary_error.unwrap_or(aegis_core::AegisError::Auth))
    }

    pub fn log_accept(&self, matched: &TunnelAuthKey, peer: SocketAddr, transport: &'static str) {
        if matched.legacy {
            if self.operational_log.includes_sensitive_context() {
                tracing::warn!(
                    event_code = "legacy_auth_accepted",
                    %peer,
                    transport,
                    auth_key_id = %matched.id,
                    auth_key_legacy = true,
                    "legacy tunnel credential accepted; migrate this client before expiry"
                );
            } else {
                tracing::warn!(
                    event_code = "legacy_auth_accepted",
                    transport,
                    auth_key_id = %matched.id,
                    auth_key_legacy = true,
                    "legacy tunnel credential accepted; migrate this client before expiry"
                );
            }
        }
    }

    pub(crate) fn operational_log(&self) -> crate::operational_log::OperationalLogPolicy {
        self.operational_log
    }
}

impl TunnelAuthKey {
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    fn is_active_at(&self, now_unix_secs: u64) -> bool {
        self.not_after_unix_secs
            .is_none_or(|not_after| now_unix_secs < not_after)
    }
}

fn unix_time_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub(crate) fn classify_connect_failure_status(err: &std::io::Error) -> TunnelStatus {
    match err.kind() {
        std::io::ErrorKind::ConnectionRefused
        | std::io::ErrorKind::AddrNotAvailable
        | std::io::ErrorKind::NotFound
        | std::io::ErrorKind::InvalidInput
        | std::io::ErrorKind::PermissionDenied => TunnelStatus::BadTarget,
        _ => TunnelStatus::TransportUnavailable,
    }
}

pub(crate) fn benign_io_close(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .map(|io| {
                matches!(
                    io.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::NotConnected
                )
            })
            .unwrap_or(false)
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_tls_session<S: AsyncRead + AsyncWrite + Unpin>(
    mut tls: TlsStream<S>,
    auth_keyring: &TunnelAuthKeyring,
    fallback: &str,
    limits: &ServerLimits,
    transport: &TransportConfig,
    target_policy: &TargetPolicyConfig,
    rate_limiter: &RateLimiter,
    peer: SocketAddr,
    bundle_ctx: Option<&bundle_endpoint::BundleEndpointContext>,
    h2_requests: &crate::lifecycle::TaskGroupRegistry,
    witness: Option<&crate::phase_witness::ServerPhaseWitness>,
    admission: AdmissionBudget,
) -> anyhow::Result<()> {
    admission.check_deadline()?;
    if rate_limiter.is_socket_banned(peer).await {
        tracing::debug!(event_code = "banned_ip_dropped", "banned IP dropped");
        return Ok(());
    }
    admission.check_deadline()?;

    let alpn = tls
        .get_ref()
        .1
        .alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).to_string());
    if auth_keyring.operational_log().includes_sensitive_context() {
        tracing::debug!(%peer, alpn = ?alpn, "tls session accepted");
    } else {
        tracing::debug!(event_code = "tls_session_accepted", "tls session accepted");
    }
    if matches!(tls.get_ref().1.alpn_protocol(), Some(b"h2")) {
        return grpc::handle_grpc_session_with_admission(
            tls,
            auth_keyring,
            transport,
            target_policy,
            rate_limiter,
            peer,
            bundle_ctx,
            h2_requests,
            witness,
            admission,
        )
        .await;
    }

    if let Some(bridge) = &auth_keyring.https_bridge {
        return tokio::time::timeout_at(
            admission.deadline,
            https_bridge::serve_http1(&mut tls, bridge),
        )
        .await
        .context("HTTP site admission timed out")?;
    }
    if auth_keyring.fronted_origin.is_some() {
        // The fronted carrier is HTTP/2 only; never reach the raw TLS path.
        return tokio::time::timeout_at(
            admission.deadline,
            fronted::serve_http1_decoy(&mut tls, peer.port()),
        )
        .await
        .context("fronted HTTP/1.1 decoy timed out")?;
    }
    let mut probe = [0u8; 4];
    match tokio::time::timeout_at(admission.deadline, tls.read_exact(&mut probe)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            crate::operational_log::debug_failure(
                auth_keyring.operational_log(),
                crate::operational_log::FailureStage::TcpSession,
                crate::operational_log::FailureReason::RequestFailed,
                Some(peer),
                &e,
            );
            return tokio::time::timeout_at(
                admission.deadline,
                handle_fallback(&mut tls, fallback),
            )
            .await
            .context("fallback admission timed out")?;
        }
        Err(_) => {
            tracing::debug!(
                event_code = "session_probe_timeout",
                "session probe timeout"
            );
            return Ok(());
        }
    }
    admission.check_deadline()?;

    if probe == *b"GET " {
        // v0.2.0 S3: if bundle endpoint is enabled AND the GET path starts
        // with the configured prefix, route к the bundle handler. Otherwise
        // fall through to the existing WebSocket dispatcher (which lets
        // tungstenite's accept_hdr_async reparse the full HTTP request
        // via PrefixStream replaying probe bytes).
        // Always peek the full request (line + headers) so the dispatcher
        // can route based on bundle prefix AND Upgrade: websocket presence.
        let peeked = match tokio::time::timeout_at(
            admission.deadline,
            peek_http_request_path(&mut tls, &probe),
        )
        .await
        {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(err)) => {
                crate::operational_log::debug_failure(
                    auth_keyring.operational_log(),
                    crate::operational_log::FailureStage::TcpSession,
                    crate::operational_log::FailureReason::RequestFailed,
                    Some(peer),
                    &err,
                );
                return tokio::time::timeout_at(
                    admission.deadline,
                    handle_fallback(&mut tls, fallback),
                )
                .await
                .context("fallback admission timed out")?;
            }
            Err(_) => return Ok(()),
        };
        admission.check_deadline()?;
        let path = request_line_path(&peeked).unwrap_or("");
        let has_ws_upgrade = request_has_websocket_upgrade(&peeked);
        if let Some(bctx) = bundle_ctx {
            if bctx.config.enabled {
                let matches =
                    bundle_endpoint::path_matches_prefix_public(path, &bctx.config.path_prefix);
                if matches {
                    let mut stream = PrefixStream::new(peeked.clone(), tls);
                    return tokio::time::timeout_at(
                        admission.deadline,
                        bundle_endpoint::handle_bundle_request(
                            &mut stream,
                            &[], // prefix already replayed via PrefixStream
                            bctx,
                            peer,
                        ),
                    )
                    .await
                    .context("bundle admission timed out")?;
                }
            }
        }
        // Route by Upgrade header: real WS clients (tungstenite, browsers)
        // always send `Upgrade: websocket`. DPI probes (curl GET, browser
        // root navigation) do not. Non-WS GETs get a synthetic HTTP/1.1
        // 200 response that matches generic HTTPS-server behavior and
        // closes the active-probe-distinguishability gap measured in
        // artifact 2026-05-16/active-probe-corpus/.
        if !has_ws_upgrade {
            tracing::debug!(
                event_code = "http_probe_decoy",
                "non-ws GET probe; sending http decoy"
            );
            let _ = tokio::time::timeout_at(
                admission.deadline,
                write_http_decoy_response(&mut tls, peer),
            )
            .await;
            return Ok(());
        }
        let rate_limit_identity = rate_limiter.http1_identity(peer, &peeked);
        let mut stream = PrefixStream::new(peeked, tls);
        return websocket::handle_websocket_session_with_admission(
            &mut stream,
            auth_keyring,
            transport,
            target_policy,
            rate_limiter,
            peer,
            rate_limit_identity,
            admission,
        )
        .await;
    }

    // HEAD probe (a common active-probe / scanner verb): respond like a stock
    // web server — same decoy headers as the GET path but no body — instead of
    // letting it fall to the legacy-stream handler (which would emit a 400, a
    // less web-realistic shape). Never a valid AEGIS operation.
    if probe == *b"HEAD" {
        tracing::debug!(
            event_code = "http_head_probe_decoy",
            "HEAD probe; sending head-only http decoy"
        );
        let _ = tokio::time::timeout_at(
            admission.deadline,
            decoy::write_http1(&mut tls, peer.port(), true),
        )
        .await;
        return Ok(());
    }

    let mut stream = PrefixStream::new(probe.to_vec(), tls);
    handle_legacy_stream_session_with_admission(
        &mut stream,
        auth_keyring,
        fallback,
        limits,
        target_policy,
        rate_limiter,
        peer,
        admission,
    )
    .await
}

/// Peek the raw TLS stream until at least the HTTP request line has
/// been received (ends with `\r\n`) or a small cap is hit. Returns
/// every byte read including the `probe` prefix. Caller wraps the
/// return value в `PrefixStream` before dispatching so the downstream
/// handler sees a pristine stream.
async fn peek_http_request_path<S>(stream: &mut S, probe: &[u8]) -> std::io::Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // v0.3.10 active-probe defense: peek the FULL request (line + headers)
    // until `\r\n\r\n` or a 1 KiB cap so the dispatcher can detect the
    // presence of `Upgrade: websocket` header and route non-WS GETs to a
    // synthetic HTTP decoy instead of the WebSocket handler. The cap is
    // doubled from the previous 512 to 1024 because real browsers send
    // ~700 bytes of headers; tungstenite-based AEGIS clients send ~300.
    const MAX_PEEK: usize = 1024;
    let mut buf = probe.to_vec();
    while buf.windows(4).all(|w| w != b"\r\n\r\n") && buf.len() < MAX_PEEK {
        let mut chunk = [0u8; 128];
        let capacity = chunk.len().min(MAX_PEEK - buf.len());
        let n = stream.read(&mut chunk[..capacity]).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(buf)
}

/// Detect `Upgrade: websocket` header (case-insensitive) anywhere in the
/// peeked request bytes. WebSocket clients (tungstenite, browsers,
/// proxies) all set this header. Probes (curl GET, browser navigation)
/// do not. False negatives (we miss a real WS upgrade) would route a
/// legitimate client to the HTTP decoy — to avoid that, the check is
/// permissive: any occurrence of the literal "upgrade" header value
/// "websocket" (with surrounding whitespace allowed) counts.
fn request_has_websocket_upgrade(buf: &[u8]) -> bool {
    let lower: Vec<u8> = buf.iter().map(|b| b.to_ascii_lowercase()).collect();
    // Look for "upgrade:" followed (with optional whitespace) by "websocket"
    let needle_upgrade = b"upgrade:";
    let mut idx = 0usize;
    while let Some(found) = lower[idx..]
        .windows(needle_upgrade.len())
        .position(|w| w == needle_upgrade)
    {
        let after = idx + found + needle_upgrade.len();
        // skip whitespace
        let tail = &lower[after..];
        let trimmed_start = tail
            .iter()
            .position(|&b| b != b' ' && b != b'\t')
            .unwrap_or(tail.len());
        let value_start = &tail[trimmed_start..];
        if value_start.starts_with(b"websocket") {
            return true;
        }
        idx = after;
    }
    false
}

/// Synthetic HTTP response that AEGIS server sends to a non-WebSocket
/// GET probe. Each invocation picks one of 4 plausible HTTP responses
/// (404, 403, 410, 301) per-peer so a classifier sampling many probes
/// does not see the same byte pattern every time. All variants stay
/// non-200 to preserve the bundle-endpoint contract (200 = tarball).
/// Variant selection is derived from the peer's source port — stable
/// for the same connection but uncorrelated across connections so a
/// passive observer doesn't see a fingerprintable single response.
/// Emit a generic stock-HTTPS decoy response for an unauthenticated /
/// probe-like HTTP/1.1 request. Delegates to the shared `decoy` module so
/// every probe surface (this, the bundle error paths, gRPC/WebSocket
/// wrong-path) returns the same AEGIS-free shape. Seeded by the peer port
/// for per-connection-stable variety.
async fn write_http_decoy_response<S>(
    stream: &mut S,
    peer: std::net::SocketAddr,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    decoy::write_http1(stream, peer.port(), false).await
}

/// Parse the HTTP request target из `GET /path?query HTTP/1.1\r\n`
/// prefix. Returns the target string (ещё containing query portion).
fn request_line_path(buf: &[u8]) -> Option<&str> {
    let end = buf.iter().position(|&b| b == b'\n')?;
    let line = std::str::from_utf8(&buf[..end]).ok()?;
    let mut parts = line.split_whitespace();
    let _method = parts.next()?;
    parts.next()
}

pub async fn handle_fallback<S>(tls: &mut S, fallback: &str) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if fallback == "close" {
        // Keep the shared process identity and generic malformed-request
        // body. The caller bounds this best-effort write with its original
        // admission deadline.
        let _ = decoy::write_malformed_http1(tls).await;
        return Ok(());
    }

    let addr_str = fallback.strip_prefix("proxy:").unwrap_or(fallback);
    if let Ok(addr) = addr_str.parse::<SocketAddr>() {
        match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(mut decoy)) => {
                let _ = tokio::io::copy_bidirectional(tls, &mut decoy).await;
            }
            Ok(Err(_)) => tracing::debug!(
                event_code = "fallback_connect_failed",
                "fallback connect failed"
            ),
            Err(_) => {
                tracing::debug!("fallback connect timeout");
            }
        }
    }

    Ok(())
}

#[cfg(not(feature = "legacy-challenge-v1"))]
#[allow(clippy::too_many_arguments)]
async fn handle_legacy_stream_session_with_admission<S>(
    stream: &mut S,
    auth_keyring: &TunnelAuthKeyring,
    fallback: &str,
    limits: &ServerLimits,
    target_policy: &TargetPolicyConfig,
    rate_limiter: &RateLimiter,
    peer: SocketAddr,
    admission: AdmissionBudget,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    admission.check_deadline()?;
    // Bound the pre-auth read. read_tunnel_request ends in read_exact with no
    // deadline of its own, so a peer that sends four bytes which are not `GET `
    // or `HEAD` and then stalls held the task — and its connection permit —
    // forever. limits.read_timeout_ms was only ever applied to the 4-byte probe.
    // A stalled connection is also an active-probe tell: a real origin closes on
    // its client-header timeout, this one hung indefinitely.
    let read_request = tokio::time::timeout_at(
        admission.deadline,
        read_tunnel_request(stream, auth_keyring, limits),
    )
    .await
    .unwrap_or_else(|_| Err(anyhow::anyhow!("timed out reading tunnel request")));
    admission.check_deadline()?;
    let authenticated = match read_request {
        Ok(authenticated) => authenticated,
        Err(e) => {
            crate::operational_log::debug_failure(
                auth_keyring.operational_log(),
                crate::operational_log::FailureStage::TcpSession,
                crate::operational_log::FailureReason::RequestFailed,
                Some(peer),
                &e,
            );
            if e.to_string().contains("decrypt tunnel control payload") {
                rate_limiter.record_socket_failure(peer).await;
            }
            return tokio::time::timeout_at(admission.deadline, handle_fallback(stream, fallback))
                .await
                .context("fallback admission timed out")?;
        }
    };
    admission.authenticated()?;
    auth_keyring.log_accept(&authenticated.key, peer, "legacy_tls");
    let req = authenticated.request;
    let auth_token = authenticated.key.secret();

    let target = format!("{}:{}", req.host, req.port);
    let mut remote = match legacy_tcp::establish(
        crate::target_policy::connect_tcp_target_with_logging(
            &req.host,
            req.port,
            target_policy,
            auth_keyring.operational_log(),
        ),
        Duration::from_millis(limits.legacy_tcp_connect_timeout_ms),
    )
    .await
    {
        Ok(remote) => remote,
        Err(err) => {
            legacy_tcp::write_control(
                write_tunnel_error(
                    stream,
                    classify_connect_failure_status(&err),
                    &format!("connect {target}: {err}"),
                    auth_token,
                ),
                Duration::from_millis(limits.write_timeout_ms),
            )
            .await?;
            return Ok(());
        }
    };

    legacy_tcp::write_control(
        write_tunnel_response(
            stream,
            &TunnelResponse {
                status: TunnelStatus::Ok,
                message: String::new(),
            },
            auth_token,
        ),
        Duration::from_millis(limits.write_timeout_ms),
    )
    .await?;

    match legacy_tcp::forward(
        stream,
        &mut remote,
        Duration::from_millis(limits.legacy_tcp_idle_timeout_ms),
        Duration::from_millis(limits.write_timeout_ms),
    )
    .await
    {
        Ok(_) => Ok(()),
        Err(err) => {
            let err = anyhow::Error::from(err);
            if benign_io_close(&err) {
                return Ok(());
            }
            Err(err)
        }
    }
}

#[cfg(feature = "legacy-challenge-v1")]
#[allow(clippy::too_many_arguments)]
async fn handle_legacy_stream_session_with_admission<S>(
    stream: &mut S,
    auth_keyring: &TunnelAuthKeyring,
    _fallback: &str,
    limits: &ServerLimits,
    target_policy: &TargetPolicyConfig,
    rate_limiter: &RateLimiter,
    peer: SocketAddr,
    admission: AdmissionBudget,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Wrong/old protocol closes; no v3 or decoy proxy downgrade.
    fresh_legacy::handle(
        stream,
        auth_keyring,
        limits,
        target_policy,
        rate_limiter,
        peer,
        admission,
    )
    .await
}

#[cfg(not(feature = "legacy-challenge-v1"))]
pub(crate) async fn read_tunnel_request<R: AsyncRead + Unpin>(
    r: &mut R,
    auth_keyring: &TunnelAuthKeyring,
    limits: &ServerLimits,
) -> anyhow::Result<AuthenticatedTunnelRequest> {
    let frame = read_stream_frame(r, MAX_TUNNEL_CONTROL_FRAME).await?;
    let authenticated = auth_keyring.open_request(&frame)?;
    let host_len = authenticated.request.host.len();
    if host_len > limits.max_host_len {
        anyhow::bail!("host_len {} exceeds max {}", host_len, limits.max_host_len);
    }
    Ok(authenticated)
}

pub async fn write_tunnel_response<W: AsyncWrite + Unpin>(
    w: &mut W,
    resp: &TunnelResponse,
    auth_token: &[u8],
) -> anyhow::Result<()> {
    let bytes = seal_tunnel_response(resp, auth_token)?;
    w.write_all(&encode_stream_frame(&bytes)).await?;
    Ok(())
}

pub async fn write_tunnel_error<W: AsyncWrite + Unpin>(
    w: &mut W,
    status: TunnelStatus,
    message: &str,
    auth_token: &[u8],
) -> anyhow::Result<()> {
    write_tunnel_response(
        w,
        &TunnelResponse {
            status,
            message: message.to_string(),
        },
        auth_token,
    )
    .await
}

struct PrefixStream<S> {
    prefix: std::io::Cursor<Vec<u8>>,
    inner: S,
}

impl<S> PrefixStream<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix: std::io::Cursor::new(prefix),
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixStream<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let prefix_pos = self.prefix.position() as usize;
        let prefix = self.prefix.get_ref();
        if prefix_pos < prefix.len() {
            let rem = &prefix[prefix_pos..];
            let to_copy = rem.len().min(buf.remaining());
            buf.put_slice(&rem[..to_copy]);
            self.prefix.set_position((prefix_pos + to_copy) as u64);
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixStream<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        benign_io_close, classify_connect_failure_status, PrefixStream, TunnelAuthKeyring,
    };
    use crate::config::{LegacyAuthTokenConfig, ServerConfig};
    use aegis_core::tunnel::{
        open_tunnel_response, seal_tunnel_request, seal_tunnel_response, TunnelRequest,
        TunnelResponse, TunnelStatus,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn prefix_stream_replays_probe_bytes() {
        let (mut tx, rx) = tokio::io::duplex(32);
        tokio::spawn(async move {
            let _ = tx.write_all(b"more").await;
        });
        let mut prefixed = PrefixStream::new(b"GET ".to_vec(), rx);
        let mut buf = [0u8; 8];
        prefixed.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"GET more");
    }

    fn auth_config() -> ServerConfig {
        ServerConfig {
            listen: "127.0.0.1:8443".into(),
            cert: "cert.pem".into(),
            key: "key.pem".into(),
            auth_token: "7f0bfd1d31eade038cc6d5581467707af913a1a43e16d7cad86894b3e2a9721e".into(),
            legacy_auth_tokens: vec![LegacyAuthTokenConfig {
                id: "legacy-direct".into(),
                auth_token: "3c1fadb246cc88b5fa39a5392cadbc14390abbab8bafa1d7a507777d880a84d3"
                    .into(),
                not_after_unix_secs: 200,
            }],
            process_alias: None,
            logging: Default::default(),
            fallback: "close".into(),
            limits: Default::default(),
            rate_limit: Default::default(),
            target_policy: Default::default(),
            transport: Default::default(),
            bundle_endpoint: Default::default(),
        }
    }

    #[test]
    fn keyring_accepts_current_and_active_legacy_and_keeps_response_key() {
        let keyring = TunnelAuthKeyring::from_config(&auth_config()).expect("keyring");
        let request = TunnelRequest {
            host: "example.org".into(),
            port: 443,
        };

        let current = seal_tunnel_request(
            &request,
            b"7f0bfd1d31eade038cc6d5581467707af913a1a43e16d7cad86894b3e2a9721e",
        )
        .expect("seal current");
        let opened = keyring
            .open_request_at(&current, 100)
            .expect("current opens");
        assert!(!opened.key.legacy);

        let legacy = seal_tunnel_request(
            &request,
            b"3c1fadb246cc88b5fa39a5392cadbc14390abbab8bafa1d7a507777d880a84d3",
        )
        .expect("seal legacy");
        let opened = keyring
            .open_request_at(&legacy, 100)
            .expect("active legacy opens");
        assert!(opened.key.legacy);
        assert_eq!(&*opened.key.id, "legacy-direct");

        let response = seal_tunnel_response(
            &TunnelResponse {
                status: TunnelStatus::Ok,
                message: String::new(),
            },
            opened.key.secret(),
        )
        .expect("seal response with matched key");
        assert!(open_tunnel_response(
            &response,
            b"3c1fadb246cc88b5fa39a5392cadbc14390abbab8bafa1d7a507777d880a84d3"
        )
        .is_ok());
        assert!(open_tunnel_response(
            &response,
            b"7f0bfd1d31eade038cc6d5581467707af913a1a43e16d7cad86894b3e2a9721e"
        )
        .is_err());
    }

    #[test]
    fn keyring_stops_accepting_legacy_at_the_hard_expiry() {
        let keyring = TunnelAuthKeyring::from_config(&auth_config()).expect("keyring");
        let frame = seal_tunnel_request(
            &TunnelRequest {
                host: "example.org".into(),
                port: 443,
            },
            b"3c1fadb246cc88b5fa39a5392cadbc14390abbab8bafa1d7a507777d880a84d3",
        )
        .expect("seal legacy");
        assert!(keyring.open_request_at(&frame, 199).is_ok());
        assert!(keyring.open_request_at(&frame, 200).is_err());
    }

    #[test]
    fn auth_config_rejects_duplicate_or_unbounded_legacy_entries() {
        let mut cfg = auth_config();
        cfg.legacy_auth_tokens[0].auth_token = cfg.auth_token.clone();
        assert!(cfg.validate_auth_tokens().is_err());

        let mut cfg = auth_config();
        let template = cfg.legacy_auth_tokens[0].clone();
        for index in 1..=3 {
            cfg.legacy_auth_tokens.push(LegacyAuthTokenConfig {
                id: format!("legacy-{index}"),
                auth_token: format!("{index:064x}"),
                ..template.clone()
            });
        }
        assert!(cfg.validate_auth_tokens().is_err());
    }

    #[test]
    fn benign_io_close_accepts_common_disconnect_kinds() {
        assert!(benign_io_close(&anyhow::Error::from(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "peer reset"
        ))));
        assert!(benign_io_close(&anyhow::Error::from(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "eof"
        ))));
        assert!(!benign_io_close(&anyhow::Error::from(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timeout"
        ))));
    }

    #[test]
    fn connect_failure_status_distinguishes_bad_target_from_transport() {
        assert_eq!(
            classify_connect_failure_status(&std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "refused"
            )),
            TunnelStatus::BadTarget
        );
        assert_eq!(
            classify_connect_failure_status(&std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timed out"
            )),
            TunnelStatus::TransportUnavailable
        );
    }
}

#[cfg(test)]
mod startup_training_tests {
    use super::TunnelAuthKeyring;
    use crate::{config::ServerConfig, lifecycle::OwnedTask, phase_witness::ServerPhaseWitness};
    use aegis_core::{carrier_runtime::PrivacySettings, secure_channel::ServerSettings};
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    use std::{path::Path, sync::Arc, time::Duration};
    use tokio::{
        sync::oneshot,
        time::{timeout_at, Instant},
    };

    fn profile() -> PrivacySettings {
        serde_json::from_value(serde_json::json!({
            "payload_bytes":2,"cadence_ms":1,"buffer_bytes":1024,"max_wire_bytes":100000,
            "io_timeout_ms":300,"session_timeout_ms":3000,"max_queue_delay_ms":400000,
            "liu_channel":{"class_weights":[1,3],"client_to_server_counts":[[3,1],[1,3]],
            "server_to_client_counts":[[3,1],[1,3]],"target_classes":[],"unmatched_traffic_class":0,
            "policy_ack_class":1,"distortion_microunits":125000,"optimizer_iterations":2000,
            "optimizer_gap_millibits":1,"optimizer_timeout_ms":3000,"buffer_bytes":1024,
            "wire_batch_bytes":1024,"max_wire_bytes":100000,"io_timeout_ms":300,
            "session_timeout_ms":3000,"max_queue_delay_ms":400000}
        }))
        .unwrap()
    }
    fn write_key(path: &Path, key: &KeyPair) {
        aegis_core::secret_file::write_private_new(path, key.serialize_pem().as_bytes()).unwrap();
    }
    fn config(p: PrivacySettings) -> (tempfile::TempDir, ServerConfig) {
        let dir = tempfile::tempdir().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let ca_path = dir.path().join("ca.pem");
        aegis_core::secret_file::write_private_new(&ca_path, ca.pem().as_bytes()).unwrap();
        let mut params = CertificateParams::new(vec!["inner.test".into()]).unwrap();
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let cert = params.signed_by(&key, &ca, &ca_key).unwrap();
        let cert_path = dir.path().join("inner.pem");
        let key_path = dir.path().join("inner.key");
        aegis_core::secret_file::write_private_new(&cert_path, cert.pem().as_bytes()).unwrap();
        write_key(&key_path, &key);
        let outer = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let outer_cert = dir.path().join("outer.pem");
        let outer_key = dir.path().join("outer.key");
        aegis_core::secret_file::write_private_new(&outer_cert, outer.cert.pem().as_bytes())
            .unwrap();
        write_key(&outer_key, &outer.key_pair);
        let mut cfg = ServerConfig {
            listen: "127.0.0.1:0".into(),
            cert: outer_cert,
            key: outer_key,
            auth_token: String::new(),
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
        cfg.limits.shutdown_grace_ms = 1000;
        cfg.transport.quic_listen = Some("127.0.0.1:0".into());
        cfg.transport.inner_tls = Some(ServerSettings {
            cert: cert_path,
            key: key_path,
            client_ca: ca_path,
            allowed_client_sha256: vec!["00".repeat(32)],
            device_registry: None,
            admission: Default::default(),
            handshake_timeout_ms: 1000,
            idle_timeout_ms: 1000,
        });
        cfg.transport.authenticated_shaping = Some(p);
        cfg.validate_auth_tokens().unwrap();
        (dir, cfg)
    }

    #[tokio::test]
    async fn completed_profile_is_shared_by_keyring_clones_before_actual_readiness() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (_dir, cfg) = config(profile());
        let cutoff = Instant::now() + Duration::from_secs(10);
        let keyring = timeout_at(cutoff, TunnelAuthKeyring::from_config_for_startup(&cfg))
            .await
            .unwrap()
            .unwrap();
        let shared = keyring.clone();
        assert!(Arc::ptr_eq(
            keyring.relay_training.as_ref().unwrap(),
            shared.relay_training.as_ref().unwrap()
        ));
        assert!(keyring.inner_tls.is_some());
        // The production run_server path prepares its own completed owner
        // before binding. This is readiness, not a target/network acceptance.
        let (ready_tx, ready_rx) = oneshot::channel();
        let (stop_tx, stop_rx) = oneshot::channel();
        let mut server = OwnedTask(tokio::spawn(
            crate::run_server_with_bound_ready_and_shutdown(cfg, ready_tx, async {
                let _ = stop_rx.await;
            }),
        ));
        let address = timeout_at(cutoff, ready_rx).await.unwrap().unwrap();
        assert_ne!(address.port(), 0);
        stop_tx.send(()).unwrap();
        timeout_at(cutoff, &mut server.0)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn owned_optimizer_startup_witness_records_only_explicit_preparation() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (_dir, mut cfg) = config(profile());
        let witness = ServerPhaseWitness::default();
        let cutoff = Instant::now() + Duration::from_secs(10);

        let ordinary = timeout_at(cutoff, TunnelAuthKeyring::from_config_for_startup(&cfg))
            .await
            .unwrap()
            .unwrap();
        assert!(ordinary.relay_training.is_some());
        assert_eq!(witness.optimizer_startup_snapshot().attempts, 0);

        let observed = timeout_at(
            cutoff,
            TunnelAuthKeyring::from_config_for_startup_with_observer(&cfg, Some(&witness)),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(observed.relay_training.is_some());
        let snapshot = witness.optimizer_startup_snapshot();
        assert_eq!(
            (snapshot.attempts, snapshot.completed, snapshot.failures),
            (1, 1, 0)
        );
        assert!(snapshot.process_cpu_samples <= 1);
        cfg.transport
            .authenticated_shaping
            .as_mut()
            .unwrap()
            .liu_channel
            .as_mut()
            .unwrap()
            .distortion_microunits = 1_000_000;
        assert!(timeout_at(
            Instant::now() + Duration::from_secs(10),
            TunnelAuthKeyring::from_config_for_startup_with_observer(&cfg, Some(&witness)),
        )
        .await
        .unwrap()
        .is_err());
        let refused = witness.optimizer_startup_snapshot();
        assert_eq!(
            (refused.attempts, refused.completed, refused.failures),
            (2, 2, 1)
        );
        // This keyring-only path never binds a listener or accepts a client.
    }

    #[tokio::test]
    async fn actual_numerical_refusal_precedes_bind_and_never_reports_ready() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut p = profile();
        // Locally valid, but the unchanged optimizer's exact unconstrained
        // kernel has physically impossible support and must be rejected.
        p.liu_channel.as_mut().unwrap().distortion_microunits = 1_000_000;
        p.validate().unwrap();
        let (_dir, mut cfg) = config(p);
        let reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        cfg.listen = reservation.local_addr().unwrap().to_string();
        let cutoff = Instant::now() + Duration::from_secs(10);
        let (ready_tx, ready_rx) = oneshot::channel();
        let result = timeout_at(
            cutoff,
            crate::run_server_with_shutdown(cfg, Some(ready_tx), std::future::pending::<()>()),
        )
        .await
        .unwrap();
        let error = result.expect_err("numerical refusal must block startup");
        assert!(
            error
                .to_string()
                .contains("positive physically impossible support"),
            "INVALID: startup failed before actual numerical causal-support check"
        );
        assert!(timeout_at(cutoff, ready_rx).await.unwrap().is_err());
        // Reservation remains owned. A bind-first implementation would have
        // returned AddrInUse instead of the actual numerical rejection above.
        assert_ne!(reservation.local_addr().unwrap().port(), 0);
    }
}
