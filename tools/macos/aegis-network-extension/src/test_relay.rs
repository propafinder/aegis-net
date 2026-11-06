//! cfg(test)-only loopback relay: outer TLS + H2 carrier, inner mutual TLS and
//! one request per connection, for the ACK path (whose every establishment
//! is its own connection). `AckThenClose` mirrors the ACK branch of
//! aegis-server's secure session (session/secure.rs): write_ack, shut the
//! inner stream, end the request; the connection loop in session/grpc.rs then
//! idles until the admission timeout and drops the connection without GOAWAY.
//! Flows are streams of pooled connections (S16h) and are served by the
//! multi-stream relay (`pool`), whose Open branch writes status byte 0 and
//! then serves an in-process target (`serve_target`: TCP echo, UDP echo, a DNS
//! answerer on port 53) in place of the remote socket. Grants are capped at
//! the registry's 3 s MAX_STALENESS. Nothing here is reachable from a
//! production build or names a real relay.
use crate::test_fixture::ReadyTree;
use aegis_core::{
    h2_stream::H2Stream,
    secure_channel::{
        self, datagram, grpc_io::GrpcIo, policy_ack, registry, OpenRequest, Server, ServerSettings,
        Transport,
    },
};
use std::{
    fs::{self, DirBuilder},
    io,
    net::SocketAddr,
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, PermissionsExt},
    },
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc, Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    },
    TlsAcceptor,
};

/// aegis-core `registry::MAX_STALENESS`: the longest ACK a server grants.
pub(crate) const MAX_ACK_VALID_MS: u64 = 3_000;
/// aegis-server `https_bridge::ADMISSION_TIMEOUT`: how long the connection
/// loop keeps an H2 connection after its last request completed. It is longer
/// than any ACK lease, so a live server outlasts the lease it granted.
pub(crate) const ADMISSION_TIMEOUT: Duration = Duration::from_secs(5);
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(crate) type OuterTls = tokio_rustls::server::TlsStream<TcpStream>;

/// The relay's outer TLS acceptor: one server identity, ALPN h2, no client
/// authentication (the device authenticates in the inner TLS).
pub(crate) fn outer_acceptor(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> io::Result<TlsAcceptor> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut outer = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(io::Error::other)?;
    outer.alpn_protocols = vec![b"h2".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(outer)))
}

/// Outer TLS acceptor (ALPN h2) and the inner mutual-TLS server. The inner
/// server's PEM files live in a private directory removed on drop.
pub(crate) struct RelayIdentity {
    outer: TlsAcceptor,
    inner: Server,
    dir: PathBuf,
    allowed_client_sha256: String,
}

impl RelayIdentity {
    pub(crate) fn new(
        outer_cert: CertificateDer<'static>,
        outer_key: Vec<u8>,
        inner_cert_pem: &[u8],
        inner_key_pem: &[u8],
        client_ca_pem: &[u8],
        allowed_client_sha256: String,
    ) -> Self {
        Self::new_allowing(
            outer_cert,
            outer_key,
            inner_cert_pem,
            inner_key_pem,
            client_ca_pem,
            vec![allowed_client_sha256],
        )
    }

    /// `new`, admitting every device fingerprint in `allowed` (S23: a
    /// device before and after its renewal).
    pub(crate) fn new_allowing(
        outer_cert: CertificateDer<'static>,
        outer_key: Vec<u8>,
        inner_cert_pem: &[u8],
        inner_key_pem: &[u8],
        client_ca_pem: &[u8],
        allowed: Vec<String>,
    ) -> Self {
        let allowed_client_sha256 = allowed[0].clone();
        let outer = outer_acceptor(
            outer_cert,
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(outer_key)),
        )
        .unwrap();
        let dir = std::env::temp_dir().join(format!(
            "aegis-ne-test-relay-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let cert = dir.join("server.pem");
        let key = dir.join("server.key");
        let client_ca = dir.join("client-ca.pem");
        for (path, bytes) in [
            (&cert, inner_cert_pem),
            (&key, inner_key_pem),
            (&client_ca, client_ca_pem),
        ] {
            fs::write(path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let inner = Server::load(&ServerSettings {
            device_registry: None,
            cert,
            key,
            client_ca,
            allowed_client_sha256: allowed,
            admission: Default::default(),
            handshake_timeout_ms: 2_000,
            idle_timeout_ms: 2_000,
        })
        .unwrap();
        Self {
            outer,
            inner,
            dir,
            allowed_client_sha256,
        }
    }

    /// An inner server for `tree`'s relay that trusts another device CA: it
    /// completes its side of the inner handshake and then refuses `tree`'s
    /// device certificate with a TLS alert, which a TLS 1.3 client reads only
    /// at its first read after the handshake (as a real relay refusing a
    /// device does).
    pub(crate) fn rejecting_device(tree: &ReadyTree) -> Arc<Server> {
        let other = ReadyTree::with_online_completed("127.0.0.1:9".parse().unwrap());
        let (outer_cert, outer_key) = tree.outer_server_der();
        let (inner_cert, inner_key) = tree.inner_server_pem();
        let identity = Self::new(
            outer_cert,
            outer_key,
            inner_cert.as_bytes(),
            inner_key.as_bytes(),
            other.device_ca_pem().as_bytes(),
            tree.online().certificate_sha256.clone(),
        );
        Arc::new(identity.inner.clone())
    }

    /// The relay the tree's signed bundle trusts, admitting only its device.
    pub(crate) fn for_tree(tree: &ReadyTree) -> Self {
        let (outer_cert, outer_key) = tree.outer_server_der();
        let (inner_cert, inner_key) = tree.inner_server_pem();
        Self::new(
            outer_cert,
            outer_key,
            inner_cert.as_bytes(),
            inner_key.as_bytes(),
            tree.device_ca_pem().as_bytes(),
            tree.online().certificate_sha256.clone(),
        )
    }
}

impl Drop for RelayIdentity {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[derive(Clone)]
pub(crate) struct AckReply {
    pub(crate) certificate_sha256: String,
    pub(crate) certificate_not_after_unix_secs: u64,
    pub(crate) policy_not_after_unix_secs: u64,
    pub(crate) generation: u64,
    pub(crate) snapshot_sha256: String,
    pub(crate) effective_valid_for_ms: u64,
}

impl AckReply {
    /// The ACK this reply grants the request carrying `nonce`.
    pub(crate) fn ack(self, nonce: String) -> policy_ack::RuntimePolicyAck {
        policy_ack::RuntimePolicyAck {
            version: 1,
            nonce,
            generation: self.generation,
            snapshot_sha256: self.snapshot_sha256,
            certificate_sha256: self.certificate_sha256,
            policy_not_after_unix_secs: self.policy_not_after_unix_secs,
            certificate_not_after_unix_secs: self.certificate_not_after_unix_secs,
            effective_valid_for_ms: self.effective_valid_for_ms,
        }
    }

    /// What a registry would grant this tree's device, at the 3 s cap.
    pub(crate) fn for_tree(tree: &ReadyTree) -> Self {
        let online = tree.online();
        Self {
            certificate_sha256: online.certificate_sha256.clone(),
            certificate_not_after_unix_secs: online.not_after_unix_secs,
            policy_not_after_unix_secs: registry::unix_now().unwrap() + 60,
            generation: online.issued_generation.unwrap_or(1),
            snapshot_sha256: online
                .snapshot_sha256
                .clone()
                .unwrap_or_else(|| "c".repeat(64)),
            effective_valid_for_ms: MAX_ACK_VALID_MS,
        }
    }
}

pub(crate) enum Behavior {
    /// Accept TCP and never send a byte: the client stalls in outer TLS.
    Silent,
    /// Complete outer TLS, H2 and inner TLS, read the ACK request, never reply.
    HoldRequest,
    /// Complete outer TLS and H2, read the inner ClientHello and answer it
    /// with a fatal bad_certificate alert: an inner mTLS refusal of the
    /// device, an authentication-class failure.
    AlertInner,
    /// Read the request, then answer with a record that is not valid TLS,
    /// written under the inner TLS: the client's read of the PolicyAck
    /// fails with a TLS error.
    GarbleAck,
    /// aegis-server: write_ack, shut the inner stream, end the request. The H2
    /// connection then stays open and idle for `idle` (the server's admission
    /// timeout) and is dropped with neither GOAWAY nor TLS close_notify, so
    /// the client's driver ends with an error, not a clean shutdown.
    AckThenClose { reply: AckReply, idle: Duration },
    /// Write the ACK and keep the connection until `release` resolves.
    AckThenHold(AckReply, oneshot::Receiver<()>),
    /// `AckThenClose` with the admission-timeout idle, the ACK written only
    /// `delay` after its request was read: a remote relay's PolicyAck round
    /// trip and processing, paid by every request (and counted inside its
    /// validity, which runs from the client's request).
    AckAfter { reply: AckReply, delay: Duration },
    /// Read the ACK request and write nothing until `release` resolves; then
    /// behave as `AckThenClose` with the admission-timeout idle.
    AckWhenReleased(AckReply, oneshot::Receiver<()>),
    /// Read the ACK request, then drop the connection without any reply.
    DropAfterRequest,
    /// Complete outer TLS, H2 and inner TLS, then drop the connection before
    /// reading any request: an idle authenticated channel the relay ended.
    DropBeforeRequest,
    /// Write only the first `keep` bytes of a valid ACK, then drop.
    TruncatedAck { reply: AckReply, keep: usize },
    /// A complete ACK for a different nonce, then the aegis-server close.
    WrongNonceThenClose(AckReply),
    /// Complete outer TLS and the H2 handshake, accept the carrier request
    /// and drop the connection before any response: a relay restart or a
    /// path change after outer TLS.
    DropBeforeCarrier,
}

/// The in-process destination behind an accepted Open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Target {
    /// TCP: echo every byte until EOF, then shut the stream. UDP: answer each
    /// datagram, with `dns_answer` on port 53 and the same bytes elsewhere.
    Echo,
    /// Accept, then never read or write: the client's writes stall once the
    /// H2 flow-control window and socket buffers fill.
    Stall,
    /// TCP, as aegis-server serves a connected remote (S16i-1): connect to
    /// this loopback socket before the status (none when it refuses), then
    /// bridge it with `copy_with_idle_timeout` (secure.rs:282-286), which
    /// passes either side's FIN on as a half-close.
    Socket(SocketAddr),
}

/// aegis-server's idle timeout for a bridged remote (secure_channel
/// `idle_timeout`, 60 s).
const SOCKET_IDLE: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelayStep {
    Accepted,
    AckRequested,
    AckWritten,
    AckClosed,
    /// The client ended the connection before any request.
    Abandoned,
    /// No request within the admission timeout: the relay dropped it.
    IdleDropped,
    /// The inner handshake was refused with a TLS alert.
    Alerted,
    /// The connection was dropped before its carrier response.
    CarrierDropped,
}

/// Connections between the start of their outer TLS (after any setup
/// delay) and the end of their inner handshake (or their end): at least the relay's inner handshakes in
/// progress, which aegis-server caps per peer IP (16 by default, 32 on
/// relay-a; its handshake permit
/// returns right after mTLS), and the highest count seen.
#[derive(Default)]
pub(crate) struct HandshakeGauge {
    current: AtomicUsize,
    high: AtomicUsize,
}

impl HandshakeGauge {
    pub(crate) fn current(&self) -> usize {
        self.current.load(Ordering::SeqCst)
    }

    pub(crate) fn high_water(&self) -> usize {
        self.high.load(Ordering::SeqCst)
    }
}

/// One connection's place in the gauge, left at the end of its inner
/// handshake or when it ends, whichever comes first.
pub(crate) struct Handshake(Option<Arc<HandshakeGauge>>);

impl Handshake {
    pub(crate) fn untracked() -> Self {
        Self(None)
    }

    fn start(gauge: &Arc<HandshakeGauge>) -> Self {
        let now = gauge.current.fetch_add(1, Ordering::SeqCst) + 1;
        gauge.high.fetch_max(now, Ordering::SeqCst);
        Self(Some(gauge.clone()))
    }

    fn end(&mut self) {
        if let Some(gauge) = self.0.take() {
            gauge.current.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

impl Drop for Handshake {
    fn drop(&mut self) {
        self.end();
    }
}

/// The AAAA record every answered query receives.
pub(crate) const DNS_ANSWER_V6: std::net::Ipv6Addr =
    std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x53);

/// One recursive AAAA query for `name`.
pub(crate) fn aaaa_query(id: u16, name: &str) -> Vec<u8> {
    let mut query = id.to_be_bytes().to_vec();
    query.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 28, 0, 1]);
    query
}

/// A DNS response to `query` (one question, nothing after it): same ID,
/// opcode and RD, QR and RA set, NOERROR, and for an AAAA question one
/// `DNS_ANSWER_V6` record; any other type gets NODATA. Malformed queries get
/// nothing.
pub(crate) fn dns_answer(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 || query[4..6] != [0, 1] || query[2] & 0x80 != 0 {
        return None;
    }
    let mut cursor = 12;
    loop {
        let length = usize::from(*query.get(cursor)?);
        cursor += 1;
        if length == 0 {
            break;
        }
        if length & 0xc0 != 0 {
            return None;
        }
        cursor += length;
    }
    let kind = u16::from_be_bytes([*query.get(cursor)?, *query.get(cursor + 1)?]);
    let question_end = cursor + 4;
    if query.len() != question_end {
        return None;
    }
    let mut response = query.to_vec();
    response[2] = 0x80 | (query[2] & 0x79);
    response[3] = 0x80;
    response[6..12].fill(0);
    if kind == 28 {
        response[7] = 1;
        response.extend_from_slice(&[0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
        response.extend_from_slice(&DNS_ANSWER_V6.octets());
    }
    Some(response)
}

/// Serve one accepted Open on `inner`, as secure.rs does with a connected
/// remote socket, but with the in-process `target`.
async fn serve_target<S: AsyncRead + AsyncWrite + Unpin>(
    inner: &mut S,
    open: &OpenRequest,
    target: Target,
) {
    if let (Target::Socket(remote), Transport::Tcp) = (target, open.transport) {
        let Ok(mut remote) = TcpStream::connect(remote).await else {
            return;
        };
        if inner.write_u8(0).await.is_err() || inner.flush().await.is_err() {
            return;
        }
        let _ = aegis_core::secure_channel::copy_with_idle_timeout(inner, &mut remote, SOCKET_IDLE)
            .await;
        return;
    }
    if inner.write_u8(0).await.is_err() || inner.flush().await.is_err() {
        return;
    }
    match (target, open.transport) {
        (Target::Stall, _) | (Target::Socket(_), _) => std::future::pending::<()>().await,
        (Target::Echo, Transport::Tcp) => {
            let mut buffer = vec![0; 16 * 1024];
            loop {
                match inner.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        // TLS over H2 buffers records until flushed.
                        let echoed = async {
                            inner.write_all(&buffer[..read]).await?;
                            inner.flush().await
                        };
                        if echoed.await.is_err() {
                            return;
                        }
                    }
                }
            }
            let _ = inner.shutdown().await;
        }
        (Target::Echo, Transport::Udp) => {
            while let Ok(Some(payload)) = datagram::read(inner).await {
                let reply = if open.port == 53 {
                    match dns_answer(&payload) {
                        Some(reply) => reply,
                        None => continue,
                    }
                } else {
                    payload
                };
                if datagram::write(inner, &reply).await.is_err() {
                    return;
                }
            }
            // secure_udp: an input EOF still ends with the output terminator.
            let _ = inner.shutdown().await;
        }
    }
}

pub(crate) type RelayEvents = mpsc::Sender<(RelayStep, Instant)>;

// B-06 S16h-1: the multi-stream relay beside this first-stream-only one.
#[path = "test_relay_pool.rs"]
pub(crate) mod pool;

// Dropping the task drops the connection: h2 sends nothing on drop, and the
// outer TLS stream closes its TCP socket without close_notify.
pub(crate) async fn drive_connection(
    mut connection: h2::server::Connection<OuterTls, bytes::Bytes>,
) {
    while let Some(Ok(_)) = connection.accept().await {}
}

/// Serve one already accepted TCP connection.
pub(crate) async fn serve_one(
    tcp: TcpStream,
    identity: Arc<RelayIdentity>,
    behavior: Behavior,
    events: RelayEvents,
) {
    serve_counted(tcp, identity, behavior, events, Handshake::untracked()).await
}

/// `serve_one`, counted in a handshake gauge until its first request read.
async fn serve_counted(
    tcp: TcpStream,
    identity: Arc<RelayIdentity>,
    behavior: Behavior,
    events: RelayEvents,
    mut handshake: Handshake,
) {
    let report = |step| {
        let _ = events.send((step, Instant::now()));
    };
    if matches!(behavior, Behavior::Silent) {
        let _held = tcp;
        std::future::pending::<()>().await;
        return;
    }
    // A client may abandon a connection at any step before its request (a
    // discarded pre-warmed channel, a stopped session): the relay then ends
    // that connection quietly, as aegis-server does.
    let Ok(outer_tls) = identity.outer.accept(tcp).await else {
        report(RelayStep::Abandoned);
        return;
    };
    let Ok(mut connection) = h2::server::handshake(outer_tls).await else {
        report(RelayStep::Abandoned);
        return;
    };
    let Some(Ok((request, mut response))) = connection.accept().await else {
        report(RelayStep::Abandoned);
        return;
    };
    assert_eq!(request.uri().path(), secure_channel::GRPC_PATH);
    if matches!(behavior, Behavior::DropBeforeCarrier) {
        // Neither a response nor GOAWAY: the connection simply ends.
        drop((request, response, connection));
        report(RelayStep::CarrierDropped);
        return;
    }
    let sender = response
        .send_response(
            http::Response::builder()
                .status(200)
                .header("content-type", "application/grpc")
                .body(())
                .unwrap(),
            false,
        )
        .unwrap();
    let driver = tokio::spawn(drive_connection(connection));
    let mut carrier = GrpcIo::new(H2Stream::new(sender, request.into_body()));
    if matches!(behavior, Behavior::AlertInner) {
        // TLS record: alert, legacy version 3.3, length 2, fatal,
        // bad_certificate (42), in answer to the ClientHello.
        let mut hello = [0u8; 512];
        let _ = carrier.read(&mut hello).await;
        let _ = carrier
            .write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x2a])
            .await;
        let _ = carrier.flush().await;
        report(RelayStep::Alerted);
        handshake.end();
        // Let the alert reach the client before the connection drops.
        tokio::time::sleep(Duration::from_millis(500)).await;
        drop((carrier, response));
        driver.abort();
        let _ = driver.await;
        return;
    }
    let Ok(mut inner) = identity.inner.accept(carrier).await else {
        driver.abort();
        let _ = driver.await;
        report(RelayStep::Abandoned);
        return;
    };
    // aegis-server returns its handshake permit right after mTLS.
    handshake.end();
    if matches!(behavior, Behavior::DropBeforeRequest) {
        drop((inner, response));
        driver.abort();
        let _ = driver.await;
        report(RelayStep::IdleDropped);
        return;
    }
    // aegis-server session/grpc.rs: an authenticated channel may idle before
    // its one request only for the admission timeout.
    let read = tokio::time::timeout(ADMISSION_TIMEOUT, policy_ack::read_request(&mut inner));
    let read = read.await;
    let Ok(read) = read else {
        drop((inner, response));
        driver.abort();
        let _ = driver.await;
        report(RelayStep::IdleDropped);
        return;
    };
    let Ok(read) = read else {
        drop((inner, response));
        driver.abort();
        let _ = driver.await;
        report(RelayStep::Abandoned);
        return;
    };
    let request = match read {
        policy_ack::ChannelRequest::PolicyAck(request) => request,
        // Flows are served by the multi-stream relay (`pool`).
        policy_ack::ChannelRequest::Open(_) => panic!("targetless ACK required"),
    };
    report(RelayStep::AckRequested);
    let ack = |reply: AckReply, nonce| reply.ack(nonce);
    let (reply, release) = match behavior {
        Behavior::Silent
        | Behavior::HoldRequest
        | Behavior::DropBeforeRequest
        | Behavior::AlertInner
        | Behavior::DropBeforeCarrier => {
            let _held = (inner, driver);
            std::future::pending::<()>().await;
            return;
        }
        Behavior::GarbleAck => {
            garble(&mut inner).await;
            report(RelayStep::AckWritten);
            tokio::time::sleep(Duration::from_millis(500)).await;
            drop((inner, response));
            driver.abort();
            let _ = driver.await;
            report(RelayStep::AckClosed);
            return;
        }
        Behavior::DropAfterRequest => {
            drop((inner, response));
            driver.abort();
            let _ = driver.await;
            report(RelayStep::AckClosed);
            return;
        }
        Behavior::TruncatedAck { reply, keep } => {
            let mut encoded = Vec::new();
            policy_ack::write_ack(&mut encoded, &ack(reply, request.nonce))
                .await
                .unwrap();
            assert!(keep < encoded.len(), "a truncated ACK must be incomplete");
            inner.write_all(&encoded[..keep]).await.unwrap();
            inner.flush().await.unwrap();
            drop((inner, response));
            driver.abort();
            let _ = driver.await;
            report(RelayStep::AckClosed);
            return;
        }
        Behavior::WrongNonceThenClose(reply) => {
            let mut nonce = request.nonce.into_bytes();
            nonce[0] = if nonce[0] == b'0' { b'1' } else { b'0' };
            let nonce = String::from_utf8(nonce).unwrap();
            policy_ack::write_ack(&mut inner, &ack(reply, nonce))
                .await
                .unwrap();
            report(RelayStep::AckWritten);
            let _ = inner.shutdown().await;
            drop((inner, response));
            driver.abort();
            let _ = driver.await;
            report(RelayStep::AckClosed);
            return;
        }
        Behavior::AckThenClose { reply, idle } => (reply, Err(idle)),
        Behavior::AckThenHold(reply, release) => (reply, Ok(release)),
        Behavior::AckAfter { reply, delay } => {
            tokio::time::sleep(delay).await;
            (reply, Err(ADMISSION_TIMEOUT))
        }
        Behavior::AckWhenReleased(reply, release) => {
            let _ = release.await;
            (reply, Err(ADMISSION_TIMEOUT))
        }
    };
    policy_ack::write_ack(&mut inner, &ack(reply, request.nonce))
        .await
        .unwrap();
    report(RelayStep::AckWritten);
    match release {
        Ok(release) => {
            let _ = release.await;
            driver.abort();
            let _ = driver.await;
        }
        Err(idle) => {
            // aegis-server/src/session/secure.rs: shutdown, then the request
            // handler returns and drops every reference to its stream.
            let _ = inner.shutdown().await;
            drop((inner, response));
            // session/grpc.rs: the loop breaks at completed + admission
            // timeout and drops the connection; nothing more is written.
            tokio::time::sleep(idle).await;
            driver.abort();
            let _ = driver.await;
            report(RelayStep::AckClosed);
        }
    }
}

/// Write a record that is not valid TLS under `inner`'s TLS: the client's
/// next read fails with a TLS error.
async fn garble(inner: &mut tokio_rustls::server::TlsStream<GrpcIo<H2Stream>>) {
    let carrier = &mut inner.get_mut().0;
    let mut record = vec![0x17, 0x03, 0x03, 0x00, 0x20];
    record.extend_from_slice(&[0x5a; 0x20]);
    let _ = carrier.write_all(&record).await;
    let _ = carrier.flush().await;
}

/// A relay on its own thread and runtime. Each accepted connection gets the
/// behavior its factory returns for its 0-based index, or is dropped at once
/// when it returns `None`; every accept is counted, so a refused dial is
/// observable.
pub(crate) struct TestRelay {
    address: SocketAddr,
    accepts: Arc<AtomicUsize>,
    events: mpsc::Receiver<(RelayStep, Instant)>,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl TestRelay {
    /// Bind first: the ReadyTree must name this address before keys exist.
    pub(crate) fn bind() -> std::net::TcpListener {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        listener
    }

    /// Only the first connection is served; later ones are dropped unread.
    pub(crate) fn spawn(
        listener: std::net::TcpListener,
        identity: RelayIdentity,
        behavior: Behavior,
    ) -> Self {
        let mut first = Some(behavior);
        Self::spawn_each(listener, identity, move |_| first.take())
    }

    /// Every stream of every connection is served, each with its own inner
    /// mTLS channel, as aegis-server does (`pool`); `spawn` and `spawn_each`
    /// keep their first-stream-only behavior for the ACK-path tests.
    pub(crate) fn spawn_streams(
        listener: std::net::TcpListener,
        identity: RelayIdentity,
        config: pool::PoolConfig,
    ) -> pool::PooledRelay {
        pool::PooledRelay::spawn(listener, identity, config)
    }

    pub(crate) fn spawn_each(
        listener: std::net::TcpListener,
        identity: RelayIdentity,
        behavior: impl FnMut(usize) -> Option<Behavior> + Send + 'static,
    ) -> Self {
        Self::spawn_each_with_setup(listener, identity, Duration::ZERO, behavior)
    }

    /// `spawn_each`, but every served connection first waits `setup` after
    /// its TCP accept before outer TLS begins: a remote relay's handshake
    /// latency, paid by each fresh connection and never by a request on an
    /// already established channel.
    pub(crate) fn spawn_each_with_setup(
        listener: std::net::TcpListener,
        identity: RelayIdentity,
        setup: Duration,
        mut behavior: impl FnMut(usize) -> Option<Behavior> + Send + 'static,
    ) -> Self {
        let address = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let counted = accepts.clone();
        let gauge = Arc::new(HandshakeGauge::default());
        let (report, events) = mpsc::channel();
        let (shutdown, mut stop) = oneshot::channel::<()>();
        let thread = thread::Builder::new()
            .name("aegis-ne-test-relay".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async move {
                    let listener = TcpListener::from_std(listener).unwrap();
                    let identity = Arc::new(identity);
                    let mut served = Vec::new();
                    loop {
                        tokio::select! {
                            _ = &mut stop => break,
                            accepted = listener.accept() => {
                                let Ok((tcp, _)) = accepted else { continue };
                                let index = counted.fetch_add(1, Ordering::SeqCst);
                                let _ = report.send((RelayStep::Accepted, Instant::now()));
                                if let Some(behavior) = behavior(index) {
                                    let identity = identity.clone();
                                    let report = report.clone();
                                    let gauge = gauge.clone();
                                    served.push(tokio::spawn(async move {
                                        // The setup stands for the network
                                        // before the relay sees the
                                        // connection; its handshake starts
                                        // after it.
                                        tokio::time::sleep(setup).await;
                                        let handshake = Handshake::start(&gauge);
                                        serve_counted(tcp, identity, behavior, report, handshake)
                                            .await
                                    }));
                                }
                            }
                        }
                    }
                    for task in &served {
                        task.abort();
                    }
                });
            })
            .unwrap();
        Self {
            address,
            accepts,
            events,
            shutdown: Some(shutdown),
            thread: Some(thread),
        }
    }

    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    pub(crate) fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }

    /// Every event reported and not yet consumed, in order.
    pub(crate) fn drain_events(&self) -> Vec<(RelayStep, Instant)> {
        self.events.try_iter().collect()
    }

    /// Wait for `step`, discarding other events; returns when it happened.
    pub(crate) fn wait_for(&self, step: RelayStep, budget: Duration) -> Option<Instant> {
        let deadline = Instant::now() + budget;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.events.recv_timeout(left) {
                Ok((seen, at)) if seen == step => return Some(at),
                Ok(_) => continue,
                Err(_) => return None,
            }
        }
    }
}

impl Drop for TestRelay {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A loopback listener whose accept queue is full and never drained. The
/// kernel drops every further SYN, so a client's connect() itself stalls; no
/// TCP handshake, TLS or ACK exchange can begin.
pub(crate) struct StalledListener {
    listener: std::net::TcpListener,
    _queued: Vec<std::net::TcpStream>,
}

impl StalledListener {
    pub(crate) fn bind() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        // Shrink the backlog of the bound listener; it never accepts.
        // SAFETY: a valid listening socket owned by `listener`.
        assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 1) }, 0);
        let address = listener.local_addr().unwrap();
        let mut queued = Vec::new();
        for _ in 0..16 {
            match std::net::TcpStream::connect_timeout(&address, Duration::from_millis(300)) {
                Ok(stream) => queued.push(stream),
                Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                    return Self {
                        listener,
                        _queued: queued,
                    };
                }
                Err(error) => panic!("stalled listener probe failed: {error}"),
            }
        }
        panic!("accept queue never filled; connect() would not stall");
    }

    pub(crate) fn address(&self) -> SocketAddr {
        self.listener.local_addr().unwrap()
    }
}
