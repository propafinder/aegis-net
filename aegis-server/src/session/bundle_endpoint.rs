//! `/bundle?token=<X>` HTTP handler for operator-friendly client install
//! flow (v0.2.0 S3b).
//!
//! The existing TLS listener already dispatches on the first bytes of
//! the stream: `b"GET "` → websocket or bundle endpoint, otherwise
//! legacy stream. This module implements the bundle arm: parses an
//! HTTP/1.1 request line + headers, validates the path prefix and
//! token, streams the tarball back as `application/gzip`, and closes.
//!
//! Behaviour:
//! - Only `GET` is accepted. Anything else → 405.
//! - Request path must start с the configured prefix (`/bundle` by
//!   default). Path mismatch → 404.
//! - Query must include `?token=<plaintext>`. Missing → 400.
//! - Token validation surface `BundleTokenError` → mapped к HTTP status
//!   (`NotFound` → 403, `Expired` → 410, `AlreadyConsumed` → 410,
//!   `PersistFailed` → 500 — fail closed, bundle NOT served).
//! - Successful redemption returns 200 с `Content-Type: application/gzip`,
//!   `Content-Length: <bundle size>`, `Cache-Control: no-store`, body =
//!   raw tarball bytes.
//!
//! We intentionally keep the HTTP parser tiny (string splits + regex-
//! free) — we do not accept arbitrary HTTP traffic, only one narrow
//! request shape. Anything malformed short-circuits к 400.

use crate::bundle_tokens::{is_canonical_plaintext_token, BundleTokenError, BundleTokenStore};
use crate::config::BundleEndpointConfig;
use anyhow::Context;
use bytes::Bytes;
use http::{Method, Response};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::time::timeout;

/// Maximum number of bytes we read looking for the end of HTTP headers.
/// Real client bundle requests fit easily в 1 KiB; anything larger is
/// either malformed or an attacker probing. Cap at 8 KiB to bound memory
/// on shared listener.
const MAX_REQUEST_HEADER_BYTES: usize = 8 * 1024;

/// Total time budget from seeing the first GET byte until the full
/// request is parsed. Shared TLS listener must not be blocked forever
/// by a slow-drip attacker.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
enum BundleHandlerError {
    #[error("endpoint disabled by config")]
    Disabled,
    #[error("path {0:?} does not start with configured prefix")]
    PathMismatch(String),
    #[error("missing or malformed ?token= query parameter")]
    MissingToken,
    #[error("method {0:?} not allowed (only GET)")]
    MethodNotAllowed(String),
    #[error("request line or headers too large")]
    RequestTooLarge,
    #[error("malformed HTTP/1.1 request: {0}")]
    Malformed(String),
    #[error("token error: {0}")]
    Token(#[from] BundleTokenError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl BundleHandlerError {
    fn http_status(&self) -> (u16, &'static str) {
        match self {
            Self::Disabled => (404, "Not Found"),
            Self::PathMismatch(_) => (404, "Not Found"),
            Self::MethodNotAllowed(_) => (405, "Method Not Allowed"),
            Self::MissingToken => (400, "Bad Request"),
            Self::RequestTooLarge => (413, "Payload Too Large"),
            Self::Malformed(_) => (400, "Bad Request"),
            Self::Token(BundleTokenError::NotFound) => (403, "Forbidden"),
            Self::Token(BundleTokenError::Expired) => (410, "Gone"),
            Self::Token(BundleTokenError::AlreadyConsumed) => (410, "Gone"),
            // Consumed marker could not be persisted — fail closed (do NOT serve
            // the bundle) so the one-time token is not silently made reusable.
            Self::Token(BundleTokenError::PersistFailed(_)) => (500, "Internal Server Error"),
            Self::Io(_) | Self::Other(_) => (500, "Internal Server Error"),
        }
    }
}

/// Context type shared across the TLS listener и bundle handler. Holds
/// the endpoint config + lock-guarded store handle. Constructed once в
/// `run_server` if `bundle_endpoint.enabled = true`.
#[derive(Clone)]
pub struct BundleEndpointContext {
    pub config: Arc<BundleEndpointConfig>,
    pub store: Arc<Mutex<BundleTokenStore>>,
    operational_log: crate::operational_log::OperationalLogPolicy,
}

impl BundleEndpointContext {
    pub fn new(
        config: BundleEndpointConfig,
        store: BundleTokenStore,
        operational_log: crate::operational_log::OperationalLogPolicy,
    ) -> Self {
        Self {
            config: Arc::new(config),
            store: Arc::new(Mutex::new(store)),
            operational_log,
        }
    }
}

/// Entry point invoked from `handle_tls_session` when the initial
/// 4-byte probe equals `b"GET "` AND subsequent request-line parsing
/// indicates the path matches the configured bundle prefix.
///
/// `initial_bytes` — bytes already consumed from the stream by routing
/// (typically the 4-byte `"GET "` probe). The handler prepends them
/// when reading the rest of the request so the first line parses
/// correctly.
pub async fn handle_bundle_request<S>(
    stream: &mut S,
    initial_bytes: &[u8],
    ctx: &BundleEndpointContext,
    peer: SocketAddr,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match process(stream, initial_bytes, ctx, peer).await {
        Ok(()) => Ok(()),
        Err(err) => {
            let (code, reason) = err.http_status();
            // Internal reason is logged; the WIRE response is a generic web
            // decoy so an active prober hitting `/bundle?token=bad` (or a
            // missing / expired / consumed token) cannot distinguish AEGIS
            // from a stock HTTPS server. Never emit token semantics
            // (400 missing / 403 invalid / 410 gone) on the wire.
            crate::operational_log::debug_bundle_rejected(
                ctx.operational_log,
                "bundle_request_rejected",
                peer,
                code,
                reason,
                &err,
            );
            let _ = super::decoy::write_http1(stream, peer.port(), false).await;
            Ok(())
        }
    }
}

async fn process<S>(
    stream: &mut S,
    initial_bytes: &[u8],
    ctx: &BundleEndpointContext,
    peer: SocketAddr,
) -> Result<(), BundleHandlerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if !ctx.config.enabled {
        return Err(BundleHandlerError::Disabled);
    }

    let headers = read_http_request_headers(stream, initial_bytes).await?;
    let request_line = headers
        .lines()
        .next()
        .ok_or_else(|| BundleHandlerError::Malformed("empty request".into()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| BundleHandlerError::Malformed("missing method".into()))?;
    let target = parts
        .next()
        .ok_or_else(|| BundleHandlerError::Malformed("missing request target".into()))?;
    let http_version = parts
        .next()
        .ok_or_else(|| BundleHandlerError::Malformed("missing HTTP version".into()))?;
    if !http_version.starts_with("HTTP/1.") {
        return Err(BundleHandlerError::Malformed(format!(
            "unsupported HTTP version {http_version}"
        )));
    }
    if method != "GET" {
        return Err(BundleHandlerError::MethodNotAllowed(method.to_string()));
    }

    let (path, query) = split_target(target);
    let bundle_bytes = redeem_bundle_bytes(ctx, path, query, peer).await?;
    write_tarball_response(stream, &bundle_bytes).await?;
    Ok(())
}

/// Shared bundle redemption: validate the endpoint is enabled, the path
/// matches the configured prefix, extract + redeem the one-time token,
/// and read the tarball bytes. Used by both the HTTP/1.1 path
/// (`process`) and the HTTP/2 path (`handle_bundle_request_h2`) so the
/// two transports share identical authorization semantics.
async fn redeem_bundle_bytes(
    ctx: &BundleEndpointContext,
    path: &str,
    query: Option<&str>,
    peer: SocketAddr,
) -> Result<Vec<u8>, BundleHandlerError> {
    redeem_bundle_bytes_with_reader(ctx, path, query, peer, tokio::fs::read).await
}

async fn redeem_bundle_bytes_with_reader<F, R>(
    ctx: &BundleEndpointContext,
    path: &str,
    query: Option<&str>,
    peer: SocketAddr,
    read: F,
) -> Result<Vec<u8>, BundleHandlerError>
where
    F: FnOnce(std::path::PathBuf) -> R,
    R: std::future::Future<Output = std::io::Result<Vec<u8>>>,
{
    if !ctx.config.enabled {
        return Err(BundleHandlerError::Disabled);
    }
    if !path_matches_prefix(path, &ctx.config.path_prefix) {
        return Err(BundleHandlerError::PathMismatch(path.to_string()));
    }

    let token = extract_token(query)
        .filter(|token| is_canonical_plaintext_token(token))
        .ok_or(BundleHandlerError::MissingToken)?;

    let bundle_path = {
        let mut store = ctx.store.clone().lock_owned().await;
        let token = token.to_owned();
        // OS-lock contention and synchronous durable I/O must not block a
        // Tokio runtime worker. The guard stays with the blocking task if the
        // request is cancelled while that task is already running.
        let mut transaction = crate::lifecycle::OwnedTask(tokio::task::spawn_blocking(move || {
            store.authorize_read(&token)
        }));
        (&mut transaction.0)
            .await
            .context("join bundle authorization transaction")??
    };
    let bundle_bytes = timeout(REQUEST_READ_TIMEOUT, read(bundle_path.clone()))
        .await
        .context("bundle file acquisition timed out before redemption")?
        .context("read bundle file before redemption")?;
    {
        let mut store = ctx.store.clone().lock_owned().await;
        let token = token.to_owned();
        let expected_path = bundle_path.clone();
        // Reacquire the shared CLI/server OS lock and reload after acquisition.
        // Concurrent revocation wins; newly issued tokens cannot be overwritten
        // by this request's old snapshot. Unreadable input does not burn a token.
        let mut transaction = crate::lifecycle::OwnedTask(tokio::task::spawn_blocking(move || {
            store.redeem_after_read(&token, Some(&expected_path))
        }));
        (&mut transaction.0)
            .await
            .context("join bundle redemption transaction")??;
    }
    // After commit, an interrupted network transfer still needs a new
    // operator-issued credential; do not make one-time tokens reusable.

    crate::operational_log::info_bundle_redeemed(
        ctx.operational_log,
        peer,
        &bundle_path,
        bundle_bytes.len(),
    );
    Ok(bundle_bytes)
}

/// HTTP/2 variant of the bundle endpoint. When a Cloudflare-fronted edge
/// (or any client) negotiates `h2` ALPN to the origin, the whole TLS
/// connection is owned by the gRPC/h2 handler, so the HTTP/1.1 routing in
/// `handle_tls_session` is never reached and `GET /bundle` previously
/// fell through to the gRPC path check and 404'd. The gRPC dispatch now
/// calls this for `GET <bundle-prefix>` requests. Same token-redemption
/// semantics as the HTTP/1.1 path; the response is framed as an h2
/// response + a single DATA frame (client bundles are a few KiB, well
/// under the default 64 KiB stream flow-control window).
pub(crate) async fn handle_bundle_request_h2(
    request: http::Request<h2::RecvStream>,
    respond: &mut h2::server::SendResponse<Bytes>,
    ctx: &BundleEndpointContext,
    peer: SocketAddr,
) -> anyhow::Result<()> {
    let uri = request.uri().clone();
    let method = request.method().clone();
    let result: Result<Vec<u8>, BundleHandlerError> = if method == Method::GET {
        redeem_bundle_bytes(ctx, uri.path(), uri.query(), peer).await
    } else {
        Err(BundleHandlerError::MethodNotAllowed(method.to_string()))
    };

    match result {
        Ok(bundle_bytes) => {
            let response = Response::builder()
                .status(200)
                .header("content-type", "application/gzip")
                .header("cache-control", "no-store")
                .body(())
                .context("build h2 bundle response")?;
            let mut send = respond.send_response(response, false)?;
            send.send_data(Bytes::from(bundle_bytes), true)?;
            Ok(())
        }
        Err(err) => {
            let (code, reason) = err.http_status();
            // Internal reason logged; the WIRE response is a generic web
            // decoy (same as the h1 path) so a fronted h2 active probe of
            // `/bundle` with a bad/missing token cannot distinguish AEGIS
            // token semantics from a stock HTTPS server's unknown-resource
            // response.
            crate::operational_log::debug_bundle_rejected(
                ctx.operational_log,
                "h2_bundle_request_rejected",
                peer,
                code,
                reason,
                &err,
            );
            let (response, body) = super::decoy::http2_response(peer.port());
            // Best-effort: the peer may already be gone.
            if let Ok(mut send) = respond.send_response(response, false) {
                let _ = send.send_data(body, true);
            }
            Ok(())
        }
    }
}

/// Drain bytes from the stream until either `\r\n\r\n` is seen (end of
/// HTTP headers) or the read cap / timeout is hit. Returns the full
/// header region as a single UTF-8 string.
async fn read_http_request_headers<S>(
    stream: &mut S,
    initial_bytes: &[u8],
) -> Result<String, BundleHandlerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    buf.extend_from_slice(initial_bytes);

    let deadline = tokio::time::Instant::now() + REQUEST_READ_TIMEOUT;
    loop {
        if find_header_terminator(&buf).is_some() {
            break;
        }
        if buf.len() >= MAX_REQUEST_HEADER_BYTES {
            return Err(BundleHandlerError::RequestTooLarge);
        }
        let mut chunk = [0u8; 256];
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(BundleHandlerError::Malformed(
                "timeout waiting for request headers".into(),
            ));
        }
        let n = match timeout(remaining, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => {
                return Err(BundleHandlerError::Malformed(
                    "peer closed before headers complete".into(),
                ))
            }
            Ok(Ok(n)) => n,
            Ok(Err(err)) => return Err(BundleHandlerError::Io(err)),
            Err(_) => {
                return Err(BundleHandlerError::Malformed(
                    "timeout waiting for request headers".into(),
                ))
            }
        };
        buf.extend_from_slice(&chunk[..n]);
    }

    let terminator = find_header_terminator(&buf).expect("terminator present after loop exit");
    String::from_utf8(buf[..terminator].to_vec())
        .map_err(|_| BundleHandlerError::Malformed("non-utf8 request headers".into()))
}

/// Returns byte index of the `\r\n\r\n` terminator (if present).
fn find_header_terminator(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Splits `/path?query` → (`/path`, `Some("query")`). Path without `?`
/// → (path, None).
fn split_target(target: &str) -> (&str, Option<&str>) {
    match target.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (target, None),
    }
}

/// Accepts request path if it equals the prefix exactly OR starts с
/// the prefix followed by `/`, `?`, or end-of-string. Rejects
/// `prefix-extra-path` style collisions.
fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    if path == prefix {
        return true;
    }
    if let Some(rest) = path.strip_prefix(prefix) {
        // Accept either `/sub/path` continuation or `?query` immediately
        // after the prefix. Rejects collisions like `/bundle-extra` or
        // `/bundles` that merely share the prefix string.
        return rest.starts_with('/') || rest.starts_with('?');
    }
    false
}

/// Sibling-module export for `session.rs` routing. `target` is the raw
/// HTTP request target (may include `?query`); strip the query before
/// comparing против the configured prefix, keeping both the handler's
/// path validation и the TLS session routing pre-check в agreement.
pub(crate) fn path_matches_prefix_public(target: &str, prefix: &str) -> bool {
    let (path, _) = split_target(target);
    path_matches_prefix(path, prefix)
}

fn extract_token(query: Option<&str>) -> Option<&str> {
    let query = query?;
    for pair in query.split('&') {
        if let Some(value) = pair.strip_prefix("token=") {
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

async fn write_tarball_response<S>(stream: &mut S, body: &[u8]) -> Result<(), BundleHandlerError>
where
    S: AsyncWrite + Unpin,
{
    let header = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/gzip\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn transaction_fixture() -> (
        tempfile::TempDir,
        BundleEndpointContext,
        String,
        std::path::PathBuf,
    ) {
        let dir = crate::bundle_tokens::test_tempdir();
        let bundle = dir.path().join("bundle.tar.gz");
        std::fs::write(&bundle, b"fixture archive").unwrap();
        let path = dir.path().join("tokens.json");
        let mut store = BundleTokenStore::load(&path).unwrap();
        let token = store.issue(bundle.clone(), 60, None).unwrap();
        let config = BundleEndpointConfig {
            enabled: true,
            token_store_path: path,
            ..Default::default()
        };
        (
            dir,
            BundleEndpointContext::new(config, store, Default::default()),
            token,
            bundle,
        )
    }

    #[tokio::test]
    async fn acquisition_cannot_overwrite_concurrent_cli_issuance() {
        let (_dir, ctx, token, bundle) = transaction_fixture();
        let store_path = ctx.config.token_store_path.clone();
        let query = format!("token={token}");
        let bytes = redeem_bundle_bytes_with_reader(
            &ctx,
            "/bundle",
            Some(&query),
            "127.0.0.1:1".parse().unwrap(),
            |path| async move {
                tokio::task::spawn_blocking(move || {
                    BundleTokenStore::load(store_path)
                        .unwrap()
                        .issue(bundle, 60, None)
                        .unwrap();
                })
                .await
                .unwrap();
                tokio::fs::read(path).await
            },
        )
        .await
        .unwrap();
        assert_eq!(bytes, b"fixture archive");
        let stats = BundleTokenStore::load(&ctx.config.token_store_path)
            .unwrap()
            .stats();
        assert_eq!(stats.active, 1);
        assert_eq!(stats.consumed, 1);
    }

    #[tokio::test]
    async fn acquisition_rechecks_concurrent_cli_revocation_before_commit() {
        let (_dir, ctx, token, _bundle) = transaction_fixture();
        let store_path = ctx.config.token_store_path.clone();
        let hash = crate::bundle_tokens::hash_token(&token);
        let query = format!("token={token}");
        let result = redeem_bundle_bytes_with_reader(
            &ctx,
            "/bundle",
            Some(&query),
            "127.0.0.1:1".parse().unwrap(),
            |path| async move {
                tokio::task::spawn_blocking(move || {
                    BundleTokenStore::load(store_path)
                        .unwrap()
                        .revoke_by_prefix(&hash)
                        .unwrap();
                })
                .await
                .unwrap();
                tokio::fs::read(path).await
            },
        )
        .await;
        assert!(matches!(
            result,
            Err(BundleHandlerError::Token(BundleTokenError::AlreadyConsumed))
        ));
    }

    #[tokio::test]
    async fn token_store_corruption_during_acquisition_fails_closed() {
        let (_dir, ctx, token, _bundle) = transaction_fixture();
        let store_path = ctx.config.token_store_path.clone();
        let query = format!("token={token}");
        let result = redeem_bundle_bytes_with_reader(
            &ctx,
            "/bundle",
            Some(&query),
            "127.0.0.1:1".parse().unwrap(),
            |path| async move {
                tokio::fs::write(store_path, b"invalid store")
                    .await
                    .unwrap();
                tokio::fs::read(path).await
            },
        )
        .await;
        assert!(matches!(
            result,
            Err(BundleHandlerError::Token(BundleTokenError::PersistFailed(
                _
            )))
        ));
        assert_eq!(ctx.store.lock().await.stats().consumed, 0);
    }

    #[tokio::test]
    async fn changed_bundle_path_after_acquisition_never_delivers_old_bytes() {
        let (_dir, ctx, token, _bundle) = transaction_fixture();
        let store_path = ctx.config.token_store_path.clone();
        let hash = crate::bundle_tokens::hash_token(&token);
        let query = format!("token={token}");
        let result = redeem_bundle_bytes_with_reader(
            &ctx,
            "/bundle",
            Some(&query),
            "127.0.0.1:1".parse().unwrap(),
            |path| async move {
                let raw = tokio::fs::read(&store_path).await.unwrap();
                let mut file: crate::bundle_tokens::BundleTokenStoreFile =
                    serde_json::from_slice(&raw).unwrap();
                file.tokens.get_mut(&hash).unwrap().bundle_path =
                    path.with_file_name("replacement.tar.gz");
                tokio::fs::write(store_path, serde_json::to_vec(&file).unwrap())
                    .await
                    .unwrap();
                tokio::fs::read(path).await
            },
        )
        .await;
        assert!(matches!(
            result,
            Err(BundleHandlerError::Token(BundleTokenError::PersistFailed(
                _
            )))
        ));
        assert_eq!(
            BundleTokenStore::load(&ctx.config.token_store_path)
                .unwrap()
                .stats()
                .active,
            1
        );
    }

    #[tokio::test]
    async fn independent_endpoint_contexts_only_deliver_once_after_concurrent_reads() {
        let (_dir, first, token, _bundle) = transaction_fixture();
        let second = BundleEndpointContext::new(
            (*first.config).clone(),
            BundleTokenStore::load(&first.config.token_store_path).unwrap(),
            Default::default(),
        );
        let query = format!("token={token}");
        let barrier = tokio::sync::Barrier::new(2);
        let read = |path| async {
            barrier.wait().await;
            tokio::fs::read(path).await
        };
        let peer = "127.0.0.1:1".parse().unwrap();
        let (one, two) = tokio::join!(
            redeem_bundle_bytes_with_reader(&first, "/bundle", Some(&query), peer, read),
            redeem_bundle_bytes_with_reader(&second, "/bundle", Some(&query), peer, read),
        );
        assert_eq!(usize::from(one.is_ok()) + usize::from(two.is_ok()), 1);
        let rejected = if one.is_err() { one } else { two };
        assert!(matches!(
            rejected,
            Err(BundleHandlerError::Token(BundleTokenError::AlreadyConsumed))
        ));
    }

    #[tokio::test]
    async fn cancelled_acquisition_leaves_token_unconsumed() {
        let (_dir, ctx, token, _bundle) = transaction_fixture();
        let request_ctx = ctx.clone();
        let query = format!("token={token}");
        let (reading_tx, reading_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            redeem_bundle_bytes_with_reader(
                &request_ctx,
                "/bundle",
                Some(&query),
                "127.0.0.1:1".parse().unwrap(),
                |_| async {
                    reading_tx.send(()).unwrap();
                    std::future::pending::<std::io::Result<Vec<u8>>>().await
                },
            )
            .await
        });
        reading_rx.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(
            BundleTokenStore::load(&ctx.config.token_store_path)
                .unwrap()
                .stats()
                .active,
            1
        );
        let query = format!("token={token}");
        assert_eq!(
            redeem_bundle_bytes(
                &ctx,
                "/bundle",
                Some(&query),
                "127.0.0.1:1".parse().unwrap()
            )
            .await
            .unwrap(),
            b"fixture archive"
        );
    }

    #[tokio::test]
    async fn unreadable_bundle_does_not_consume_token_and_success_is_one_time() {
        let dir = crate::bundle_tokens::test_tempdir();
        let path = dir.path().join("bundle.tar.gz");
        std::fs::write(&path, b"private test bundle").unwrap();
        let store_path = dir.path().join("tokens.json");
        let mut store = BundleTokenStore::load(&store_path).unwrap();
        let token = store.issue(path.clone(), 60, None).unwrap();
        let config = BundleEndpointConfig {
            enabled: true,
            token_store_path: store_path,
            ..Default::default()
        };
        let ctx = BundleEndpointContext::new(config, store, Default::default());
        let query = format!("token={token}");
        let peer = "127.0.0.1:1".parse().unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(redeem_bundle_bytes(&ctx, "/bundle", Some(&query), peer)
            .await
            .is_err());
        assert_eq!(ctx.store.lock().await.stats().active, 1);
        std::fs::write(&path, b"private test bundle").unwrap();
        assert_eq!(
            redeem_bundle_bytes(&ctx, "/bundle", Some(&query), peer)
                .await
                .unwrap(),
            b"private test bundle"
        );
        assert!(redeem_bundle_bytes(&ctx, "/bundle", Some(&query), peer)
            .await
            .is_err());
        assert_eq!(ctx.store.lock().await.stats().consumed, 1);
    }

    #[tokio::test]
    async fn token_store_reload_failure_never_uses_stale_authorization() {
        let dir = crate::bundle_tokens::test_tempdir();
        let path = dir.path().join("bundle.tar.gz");
        std::fs::write(&path, b"private test bundle").unwrap();
        let store_path = dir.path().join("tokens.json");
        let mut store = BundleTokenStore::load(&store_path).unwrap();
        let token = store.issue(path, 60, None).unwrap();
        let config = BundleEndpointConfig {
            enabled: true,
            token_store_path: store_path.clone(),
            ..Default::default()
        };
        let ctx = BundleEndpointContext::new(config, store, Default::default());
        std::fs::write(store_path, b"invalid store").unwrap();
        let query = format!("token={token}");
        assert!(redeem_bundle_bytes(
            &ctx,
            "/bundle",
            Some(&query),
            "127.0.0.1:1".parse().unwrap()
        )
        .await
        .is_err());
        assert_eq!(ctx.store.lock().await.stats().consumed, 0);
    }

    #[test]
    fn path_matches_prefix_exact() {
        assert!(path_matches_prefix("/bundle", "/bundle"));
        assert!(path_matches_prefix("/bundle/", "/bundle"));
        assert!(path_matches_prefix("/bundle/sub", "/bundle"));
    }

    #[test]
    fn path_matches_prefix_rejects_partial() {
        assert!(!path_matches_prefix("/bundle-extra", "/bundle"));
        assert!(!path_matches_prefix("/bundles", "/bundle"));
        assert!(!path_matches_prefix("/other", "/bundle"));
        assert!(!path_matches_prefix("/", "/bundle"));
    }

    #[test]
    fn split_target_parses_query() {
        assert_eq!(split_target("/bundle"), ("/bundle", None));
        assert_eq!(
            split_target("/bundle?token=abc"),
            ("/bundle", Some("token=abc"))
        );
        assert_eq!(
            split_target("/bundle?a=1&token=xyz"),
            ("/bundle", Some("a=1&token=xyz"))
        );
    }

    #[test]
    fn extract_token_finds_value() {
        assert_eq!(extract_token(Some("token=abc")), Some("abc"));
        assert_eq!(extract_token(Some("token=abc&extra=1")), Some("abc"));
        assert_eq!(extract_token(Some("extra=1&token=xyz")), Some("xyz"));
        assert_eq!(extract_token(Some("other=1")), None);
        assert_eq!(extract_token(None), None);
        assert_eq!(extract_token(Some("token=")), None); // empty value rejected
    }

    #[test]
    fn find_header_terminator_works() {
        assert_eq!(find_header_terminator(b"GET / HTTP/1.1\r\n\r\n"), Some(14));
        assert_eq!(find_header_terminator(b"GET / HTTP/1.1\r\n"), None);
    }

    #[test]
    fn bundle_handler_error_status_mapping() {
        assert_eq!(BundleHandlerError::Disabled.http_status().0, 404);
        assert_eq!(BundleHandlerError::MissingToken.http_status().0, 400);
        assert_eq!(
            BundleHandlerError::MethodNotAllowed("POST".into())
                .http_status()
                .0,
            405
        );
        assert_eq!(
            BundleHandlerError::PathMismatch("/other".into())
                .http_status()
                .0,
            404
        );
        assert_eq!(
            BundleHandlerError::Token(BundleTokenError::NotFound)
                .http_status()
                .0,
            403
        );
        assert_eq!(
            BundleHandlerError::Token(BundleTokenError::Expired)
                .http_status()
                .0,
            410
        );
        assert_eq!(
            BundleHandlerError::Token(BundleTokenError::AlreadyConsumed)
                .http_status()
                .0,
            410
        );
        // Persist failure must fail closed: 500, bundle not served.
        assert_eq!(
            BundleHandlerError::Token(BundleTokenError::PersistFailed("disk full".into()))
                .http_status()
                .0,
            500
        );
        assert_eq!(BundleHandlerError::RequestTooLarge.http_status().0, 413);
    }
}

#[cfg(test)]
#[path = "bundle_endpoint_format_tests.rs"]
mod token_format_tests;
