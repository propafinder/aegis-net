//! Local CDN-like gRPC edge used by fronted-origin tests.
//!
//! It models the parts of Cloudflare's gRPC proxying that the enrolled
//! carrier depends on, without claiming equivalence with a real edge:
//!
//! - the client-facing TLS terminates at the edge (its own certificate);
//! - only HTTP/2 carries gRPC; SETTINGS_ENABLE_CONNECT_PROTOCOL is never
//!   advertised and any CONNECT (including RFC 8441) is refused;
//! - every client stream is re-originated on ONE pooled, multiplexed HTTP/2
//!   connection to the origin, verified against an origin CA ("Full strict")
//!   with the edge hostname as SNI and `:authority`;
//! - client-supplied origin-key headers are stripped and the configured value
//!   is injected (a request-header transform); `cf-connecting-ip` and friends
//!   are added; bodies and trailers are streamed with flow control.
//!
//! Fault injection covers a missing transform, edge error statuses without
//! contacting the origin, a mid-stream reset and an idle-stream cut.
//! Include with `#[path = ".../tests/support/cdn_grpc_proxy.rs"] mod cdn;`.
#![allow(dead_code)]

use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub const ORIGIN_KEY_HEADER: &str = "x-aegis-origin-key";

#[derive(Clone, Default)]
pub struct Faults {
    /// Answer every request with this status and an HTML body, as an edge
    /// error page would, without contacting the origin (e.g. 502, 521, 530).
    pub status_without_origin: Option<u16>,
    /// Reset the client stream after this many response body bytes.
    pub reset_after_response_bytes: Option<usize>,
    /// Cut a stream when neither direction carried DATA for this long.
    pub idle_timeout: Option<Duration>,
}

#[derive(Clone)]
pub struct EdgeConfig {
    /// Client-facing listener; `None` picks a free loopback port.
    pub listen: Option<SocketAddr>,
    /// Client-facing edge certificate chain and key (PEM).
    pub edge_cert_pem: String,
    pub edge_key_pem: String,
    pub origin: SocketAddr,
    /// Edge hostname: SNI and `:authority` sent to the origin.
    pub origin_server_name: String,
    /// Origin trust ("Full strict").
    pub origin_ca_pem: String,
    /// Value injected as the origin-key request header (`None` = no transform).
    pub origin_key: Option<Vec<u8>>,
    pub faults: Faults,
}

#[derive(Default)]
pub struct EdgeStats {
    pub client_connections: AtomicUsize,
    pub origin_connections: AtomicUsize,
    pub streams: AtomicUsize,
    pub connect_refused: AtomicUsize,
    pub origin_trailers: AtomicUsize,
    pub request_bytes: AtomicUsize,
    pub response_bytes: AtomicUsize,
    pub resets_injected: AtomicUsize,
    pub idle_cuts: AtomicUsize,
}

pub struct Edge {
    pub address: SocketAddr,
    pub stats: Arc<EdgeStats>,
    shared: Arc<Shared>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Edge {
    fn drop(&mut self) {
        self.task.abort();
        // Close pooled origin connections with the edge, like a real edge
        // going away; otherwise the origin would wait for them to drain.
        if let Ok(mut drivers) = self.shared.drivers.lock() {
            for driver in drivers.drain(..) {
                driver.abort();
            }
        }
    }
}

impl Edge {
    /// Serve one already TLS-terminated (plaintext HTTP/2) client connection.
    /// Used when another component terminates client TLS, e.g. with ECH.
    pub fn serve_plaintext<S>(&self, io: S, peer: SocketAddr) -> tokio::task::JoinHandle<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let shared = self.shared.clone();
        tokio::spawn(async move {
            let _ = serve_h2(io, peer, shared).await;
        })
    }
}

struct Shared {
    config: EdgeConfig,
    origin_tls: tokio_rustls::TlsConnector,
    upstream: tokio::sync::Mutex<Option<h2::client::SendRequest<Bytes>>>,
    drivers: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    stats: Arc<EdgeStats>,
    ray: AtomicU64,
}

fn certs(pem: &str) -> Vec<rustls::pki_types::CertificateDer<'static>> {
    use rustls::pki_types::pem::PemObject;
    rustls::pki_types::CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("fixture certificate PEM")
}

pub async fn start(config: EdgeConfig) -> Edge {
    use rustls::pki_types::pem::PemObject;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            certs(&config.edge_cert_pem),
            rustls::pki_types::PrivateKeyDer::from_pem_slice(config.edge_key_pem.as_bytes())
                .expect("fixture edge key"),
        )
        .unwrap();
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs(&config.origin_ca_pem) {
        roots.add(cert).unwrap();
    }
    let mut origin = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    origin.alpn_protocols = vec![b"h2".to_vec()];
    let stats = Arc::new(EdgeStats::default());
    let shared = Arc::new(Shared {
        config,
        origin_tls: tokio_rustls::TlsConnector::from(Arc::new(origin)),
        upstream: tokio::sync::Mutex::new(None),
        drivers: std::sync::Mutex::new(Vec::new()),
        stats: stats.clone(),
        ray: AtomicU64::new(0x7a3c_0000_0000_0001),
    });
    let requested = shared
        .config
        .listen
        .unwrap_or_else(|| "127.0.0.1:0".parse().unwrap());
    // A replaced edge on a pinned port may still be releasing its listener.
    let mut attempts = 0;
    let listener = loop {
        match TcpListener::bind(requested).await {
            Ok(listener) => break listener,
            Err(error) if attempts < 40 => {
                let _ = error;
                attempts += 1;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => panic!("edge listener bind failed: {error}"),
        }
    };
    let address = listener.local_addr().unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let accept_shared = shared.clone();
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((tcp, peer)) = accepted else { break };
                    let acceptor = acceptor.clone();
                    let shared = accept_shared.clone();
                    connections.spawn(async move {
                        shared.stats.client_connections.fetch_add(1, Ordering::Relaxed);
                        let Ok(Ok(mut tls)) = tokio::time::timeout(Duration::from_secs(5), acceptor.accept(tcp)).await else { return };
                        if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
                            // HTTP/1.1 never carries gRPC through this edge.
                            let mut buf = [0u8; 1024];
                            let _ = tokio::time::timeout(Duration::from_millis(200), tls.read(&mut buf)).await;
                            let _ = tls.write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").await;
                            let _ = tls.shutdown().await;
                            return;
                        }
                        let _ = serve_h2(tls, peer, shared).await;
                    });
                }
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
            }
        }
    });
    Edge {
        address,
        stats,
        shared,
        task,
    }
}

async fn serve_h2<S>(io: S, peer: SocketAddr, shared: Arc<Shared>) -> Result<(), h2::Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Default builder: no SETTINGS_ENABLE_CONNECT_PROTOCOL (no RFC 8441).
    let mut connection = h2::server::Builder::new().handshake(io).await?;
    let mut streams = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = connection.accept() => {
                let Some(accepted) = accepted else { break };
                let (request, respond) = accepted?;
                let shared = shared.clone();
                streams.spawn(async move { forward(request, respond, peer, shared).await });
            }
            Some(_) = streams.join_next(), if !streams.is_empty() => {}
        }
    }
    while streams.join_next().await.is_some() {}
    Ok(())
}

fn hop_by_hop(name: &http::header::HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-connection"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | ORIGIN_KEY_HEADER
            | "cf-connecting-ip"
            | "x-forwarded-for"
            | "cf-ray"
    )
}

async fn upstream(shared: &Shared) -> std::io::Result<h2::client::SendRequest<Bytes>> {
    let mut slot = shared.upstream.lock().await;
    if let Some(existing) = slot.as_ref() {
        if let Ok(ready) = existing.clone().ready().await {
            return Ok(ready);
        }
    }
    let tcp = TcpStream::connect(shared.config.origin).await?;
    let name = rustls::pki_types::ServerName::try_from(shared.config.origin_server_name.clone())
        .map_err(|_| std::io::Error::other("origin server name"))?;
    let tls = shared.origin_tls.connect(name, tcp).await?;
    if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
        return Err(std::io::Error::other("origin did not negotiate h2"));
    }
    let (sender, connection) = h2::client::Builder::new()
        .handshake(tls)
        .await
        .map_err(std::io::Error::other)?;
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    if let Ok(mut drivers) = shared.drivers.lock() {
        drivers.retain(|driver| !driver.is_finished());
        drivers.push(driver);
    }
    shared
        .stats
        .origin_connections
        .fetch_add(1, Ordering::Relaxed);
    let ready = sender
        .clone()
        .ready()
        .await
        .map_err(std::io::Error::other)?;
    *slot = Some(sender);
    Ok(ready)
}

fn error_page(respond: &mut h2::server::SendResponse<Bytes>, status: u16) {
    let body = Bytes::from(format!(
        "<!DOCTYPE html><html><head><title>Error {status}</title></head><body>edge error</body></html>"
    ));
    let response = http::Response::builder()
        .status(status)
        .header("content-type", "text/html; charset=UTF-8")
        .header("server", "cloudflare")
        .body(())
        .unwrap();
    if let Ok(mut send) = respond.send_response(response, false) {
        let _ = send.send_data(body, true);
    }
}

async fn forward(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    peer: SocketAddr,
    shared: Arc<Shared>,
) {
    shared.stats.streams.fetch_add(1, Ordering::Relaxed);
    if request.method() == http::Method::CONNECT
        || request.extensions().get::<h2::ext::Protocol>().is_some()
    {
        shared.stats.connect_refused.fetch_add(1, Ordering::Relaxed);
        error_page(&mut respond, 405);
        return;
    }
    if let Some(status) = shared.config.faults.status_without_origin {
        error_page(&mut respond, status);
        return;
    }
    let (parts, body) = request.into_parts();
    let path = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| "/".into());
    let mut upstream_request = http::Request::builder()
        .method(parts.method.clone())
        .uri(format!(
            "https://{}{}",
            shared.config.origin_server_name, path
        ))
        .body(())
        .unwrap();
    for (name, value) in parts.headers.iter() {
        if !hop_by_hop(name) {
            upstream_request
                .headers_mut()
                .append(name.clone(), value.clone());
        }
    }
    let ray = shared.ray.fetch_add(1, Ordering::Relaxed);
    let headers = upstream_request.headers_mut();
    headers.insert("cf-connecting-ip", peer.ip().to_string().parse().unwrap());
    headers.insert("x-forwarded-for", peer.ip().to_string().parse().unwrap());
    headers.insert("x-forwarded-proto", "https".parse().unwrap());
    headers.insert("cf-ray", format!("{ray:016x}-LCL").parse().unwrap());
    headers.insert("cdn-loop", "cloudflare".parse().unwrap());
    if let Some(key) = &shared.config.origin_key {
        let mut value = http::HeaderValue::from_bytes(key).unwrap();
        value.set_sensitive(true);
        headers.insert(ORIGIN_KEY_HEADER, value);
    }
    let end_of_stream = body.is_end_stream();
    let sender = match upstream(&shared).await {
        Ok(sender) => sender,
        Err(_) => return error_page(&mut respond, 502),
    };
    let mut sender = sender;
    let (response, upstream_send) = match sender.send_request(upstream_request, end_of_stream) {
        Ok(pair) => pair,
        Err(_) => return error_page(&mut respond, 502),
    };
    let activity = Arc::new(AtomicU64::new(now_ms()));
    let idle = shared.config.faults.idle_timeout;
    let request_pump = {
        let shared = shared.clone();
        let activity = activity.clone();
        async move {
            if !end_of_stream {
                let _ = pump(
                    body,
                    upstream_send,
                    &shared.stats.request_bytes,
                    None,
                    &shared.stats,
                    activity,
                    idle,
                )
                .await;
            }
        }
    };
    let response_pump = {
        let shared = shared.clone();
        async move {
            let response = match response.await {
                Ok(response) => response,
                Err(_) => return error_page(&mut respond, 502),
            };
            let (parts, upstream_body) = response.into_parts();
            let mut downstream = http::Response::builder()
                .status(parts.status)
                .body(())
                .unwrap();
            for (name, value) in parts.headers.iter() {
                if !hop_by_hop(name) {
                    downstream.headers_mut().append(name.clone(), value.clone());
                }
            }
            downstream
                .headers_mut()
                .insert("server", "cloudflare".parse().unwrap());
            downstream
                .headers_mut()
                .insert("cf-ray", format!("{ray:016x}-LCL").parse().unwrap());
            let end = upstream_body.is_end_stream();
            let Ok(send) = respond.send_response(downstream, end) else {
                return;
            };
            if !end {
                let _ = pump(
                    upstream_body,
                    send,
                    &shared.stats.response_bytes,
                    shared.config.faults.reset_after_response_bytes,
                    &shared.stats,
                    activity,
                    idle,
                )
                .await;
            }
        }
    };
    tokio::join!(request_pump, response_pump);
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

async fn idle_expired(activity: &AtomicU64, idle: Option<Duration>) {
    let Some(idle) = idle else {
        return std::future::pending().await;
    };
    loop {
        let quiet = now_ms().saturating_sub(activity.load(Ordering::Relaxed));
        if quiet >= idle.as_millis() as u64 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(
            (idle.as_millis() as u64 - quiet).max(5),
        ))
        .await;
    }
}

async fn send_all(to: &mut h2::SendStream<Bytes>, mut chunk: Bytes) -> Result<(), h2::Error> {
    while !chunk.is_empty() {
        to.reserve_capacity(chunk.len());
        let capacity = match std::future::poll_fn(|cx| to.poll_capacity(cx)).await {
            Some(capacity) => capacity?,
            None => return Err(h2::Error::from(h2::Reason::STREAM_CLOSED)),
        };
        if capacity == 0 {
            tokio::task::yield_now().await;
            continue;
        }
        let take = capacity.min(chunk.len());
        to.send_data(chunk.split_to(take), false)?;
    }
    Ok(())
}

async fn pump(
    mut from: h2::RecvStream,
    mut to: h2::SendStream<Bytes>,
    counter: &AtomicUsize,
    reset_after: Option<usize>,
    stats: &EdgeStats,
    activity: Arc<AtomicU64>,
    idle: Option<Duration>,
) -> Result<(), h2::Error> {
    let mut total = 0usize;
    loop {
        let next = tokio::select! {
            next = from.data() => next,
            _ = idle_expired(&activity, idle) => {
                stats.idle_cuts.fetch_add(1, Ordering::Relaxed);
                to.send_reset(h2::Reason::CANCEL);
                return Ok(());
            }
            reset = std::future::poll_fn(|cx| to.poll_reset(cx)) => {
                // Peer cancelled the destination; stop reading the source.
                let _ = reset;
                return Ok(());
            }
        };
        match next {
            Some(Ok(chunk)) => {
                let len = chunk.len();
                activity.store(now_ms(), Ordering::Relaxed);
                send_all(&mut to, chunk).await?;
                from.flow_control().release_capacity(len)?;
                counter.fetch_add(len, Ordering::Relaxed);
                total += len;
                if reset_after.is_some_and(|limit| total >= limit) {
                    stats.resets_injected.fetch_add(1, Ordering::Relaxed);
                    to.send_reset(h2::Reason::INTERNAL_ERROR);
                    return Ok(());
                }
            }
            Some(Err(error)) => {
                to.send_reset(h2::Reason::CANCEL);
                return Err(error);
            }
            None => break,
        }
    }
    match from.trailers().await {
        Ok(Some(trailers)) => {
            if trailers.contains_key("grpc-status") {
                stats.origin_trailers.fetch_add(1, Ordering::Relaxed);
            }
            to.send_trailers(trailers)
        }
        Ok(None) => to.send_data(Bytes::new(), true),
        Err(error) => {
            to.send_reset(h2::Reason::CANCEL);
            Err(error)
        }
    }
}
