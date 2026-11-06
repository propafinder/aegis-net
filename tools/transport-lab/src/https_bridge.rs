//! Bounded, opt-in HTTPS/H2 bridge experiment on loopback only.
//!
//! The ordinary page and privately gated carrier share one HTTPS authority.
//! The gate is checked before the distinct gRPC response; the carrier still
//! requires Aegis inner device mTLS and an authorization lease. This is not a
//! Tor WebTunnel implementation or evidence of resistance to active probing.

use aegis_core::h2_stream::H2Stream;
use aegis_core::secure_channel::{grpc_io::GrpcIo, Server};
use bytes::Bytes;
use http::{Method, Request, Response};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{io, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio::time::{timeout, Instant};
use tokio_rustls::TlsAcceptor;

const GATE_HEADER: &str = "x-aegis-lab-gate";
const PAGE: &[u8] = b"<!doctype html><html lang=\"en\"><title>Local HTTPS fixture</title><p>Local research page.</p></html>\n";
const NOT_FOUND: &[u8] = b"Not found\n";

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn protocol_error(_: impl std::fmt::Display) -> io::Error {
    // Do not include paths, headers or TLS credential details in diagnostics.
    io::Error::new(
        io::ErrorKind::InvalidData,
        "local HTTPS fixture protocol error",
    )
}

/// Private route configuration. Debug deliberately reveals no route or token.
#[derive(Clone)]
pub struct BridgeGate {
    authority: String,
    path: String,
    token_sha256: [u8; 32],
}

impl std::fmt::Debug for BridgeGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BridgeGate { redacted }")
    }
}

impl BridgeGate {
    /// The caller supplies a fresh private token; this constructor does not
    /// persist or print it. The token is an additional route gate, not a device
    /// identity or a substitute for the inner secure channel.
    pub fn new(authority: &str, path: &str, token: &[u8]) -> io::Result<Self> {
        let parsed_authority = authority
            .parse::<http::uri::Authority>()
            .map_err(|_| invalid("invalid local bridge authority"))?;
        let parsed_path = path
            .parse::<http::uri::PathAndQuery>()
            .map_err(|_| invalid("invalid local bridge route"))?;
        if parsed_authority.as_str() != authority
            || authority.contains('@')
            || path.len() > 256
            || !path.starts_with('/')
            || path == "/"
            || parsed_path.query().is_some()
            || parsed_path.as_str() != path
            || !(32..=128).contains(&token.len())
            || http::HeaderValue::from_bytes(token).is_err()
        {
            return Err(invalid("invalid local bridge gate"));
        }
        Ok(Self {
            authority: authority.into(),
            path: path.into(),
            token_sha256: Sha256::digest(token).into(),
        })
    }

    fn same_authority<B>(&self, request: &Request<B>) -> bool {
        request.uri().scheme_str() == Some("https")
            && request.uri().authority().map(|a| a.as_str()) == Some(&self.authority)
    }

    fn permits<B>(&self, request: &Request<B>) -> bool {
        if !self.same_authority(request)
            || request.method() != Method::POST
            || request.uri().path_and_query().map(|p| p.as_str()) != Some(&self.path)
            || request.headers().get("content-type").map(|v| v.as_bytes())
                != Some(b"application/grpc")
            || request.headers().get_all(GATE_HEADER).iter().count() != 1
        {
            return false;
        }
        let supplied = request.headers()[GATE_HEADER].as_bytes();
        if !(32..=128).contains(&supplied.len()) {
            return false;
        }
        let digest: [u8; 32] = Sha256::digest(supplied).into();
        // Compare all digest bytes. This is not a timing-privacy guarantee for
        // the HTTP stack or the resulting connection as a whole.
        digest
            .iter()
            .zip(self.token_sha256.iter())
            .fold(0u8, |difference, (a, b)| difference | (a ^ b))
            == 0
    }
}

/// Hard bounds for the experiment. There is no unbounded listener mode.
#[derive(Clone, Copy, Debug)]
pub struct BridgeLimits {
    pub total_time: Duration,
    pub connection_time: Duration,
    pub outer_handshake_time: Duration,
    pub max_connections: usize,
    pub concurrent_connections: usize,
    pub requests_per_connection: usize,
    pub max_echo_bytes: usize,
}

impl Default for BridgeLimits {
    fn default() -> Self {
        Self {
            total_time: Duration::from_secs(3),
            connection_time: Duration::from_secs(2),
            outer_handshake_time: Duration::from_millis(500),
            max_connections: 8,
            concurrent_connections: 4,
            requests_per_connection: 16,
            max_echo_bytes: 4096,
        }
    }
}

impl BridgeLimits {
    fn validate(&self) -> io::Result<()> {
        if !(Duration::from_secs(3)..=Duration::from_secs(10)).contains(&self.total_time)
            || self.connection_time.is_zero()
            || self.connection_time > self.total_time
            || !(Duration::from_millis(25)..=Duration::from_secs(1))
                .contains(&self.outer_handshake_time)
            || self.outer_handshake_time > self.connection_time
            || !(1..=16).contains(&self.max_connections)
            || !(1..=4).contains(&self.concurrent_connections)
            || !(1..=16).contains(&self.requests_per_connection)
            || !(1..=u16::MAX as usize).contains(&self.max_echo_bytes)
        {
            return Err(invalid(
                "local bridge limits are outside the bounded experiment",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct BridgeSummary {
    pub accepted_connections: usize,
    pub completed_connections: usize,
    pub failed_connections: usize,
    pub cancelled_connections: usize,
    pub public_pages: usize,
    pub generic_not_found: usize,
    pub gated_carriers: usize,
    pub authenticated_echoes: usize,
    pub refused_inner_channels: usize,
    /// Failed/cancelled connections or request tasks can discard counters.
    /// A zero counter in that case is not evidence of no activity.
    pub counts_may_be_incomplete: bool,
}

impl BridgeSummary {
    fn merge(&mut self, other: Self) {
        self.public_pages += other.public_pages;
        self.generic_not_found += other.generic_not_found;
        self.gated_carriers += other.gated_carriers;
        self.authenticated_echoes += other.authenticated_echoes;
        self.refused_inner_channels += other.refused_inner_channels;
        self.counts_may_be_incomplete |= other.counts_may_be_incomplete;
    }
}

/// Serve only an already-bound loopback address. Every spawned connection is
/// joined or cancelled before return, including when the total deadline ends.
pub async fn serve_loopback(
    listener: TcpListener,
    outer_tls: Arc<rustls::ServerConfig>,
    gate: BridgeGate,
    inner_tls: Server,
    limits: BridgeLimits,
) -> io::Result<BridgeSummary> {
    limits.validate()?;
    if !listener.local_addr()?.ip().is_loopback() {
        return Err(invalid(
            "HTTPS transport lab accepts a loopback listener only",
        ));
    }
    if outer_tls.alpn_protocols != [b"h2".to_vec()] {
        return Err(invalid("local HTTPS fixture requires explicit h2 ALPN"));
    }
    let deadline = Instant::now() + limits.total_time;
    let mut connections = JoinSet::new();
    let mut summary = BridgeSummary::default();
    let mut listener_failure = None;
    loop {
        if summary.accepted_connections >= limits.max_connections && connections.is_empty() {
            break;
        }
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => break,
            accepted = listener.accept(), if summary.accepted_connections < limits.max_connections
                && connections.len() < limits.concurrent_connections => {
                let (socket, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        listener_failure = Some(error);
                        break;
                    }
                };
                if !peer.ip().is_loopback() {
                    continue;
                }
                summary.accepted_connections += 1;
                let gate = gate.clone();
                let inner = inner_tls.clone();
                let outer = outer_tls.clone();
                connections.spawn(async move {
                    timeout(limits.connection_time,
                        serve_connection(socket, outer, gate, inner, limits))
                        .await
                        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut,
                            "local HTTPS connection deadline reached"))?
                });
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                match completed {
                    Some(Ok(Ok(result))) => {
                        summary.completed_connections += 1;
                        summary.merge(result);
                    }
                    Some(_) => summary.failed_connections += 1,
                    None => {},
                }
            }
        }
    }
    // Independent total deadline owns all subordinate TLS/H2/session work.
    summary.cancelled_connections += connections.len();
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    drop(listener);
    summary.counts_may_be_incomplete |=
        summary.failed_connections > 0 || summary.cancelled_connections > 0;
    match listener_failure {
        Some(error) => Err(error),
        None => Ok(summary),
    }
}

async fn serve_connection(
    socket: TcpStream,
    outer_tls: Arc<rustls::ServerConfig>,
    gate: BridgeGate,
    inner_tls: Server,
    limits: BridgeLimits,
) -> io::Result<BridgeSummary> {
    let tls = timeout(
        limits.outer_handshake_time,
        TlsAcceptor::from(outer_tls).accept(socket),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "outer TLS deadline reached"))??;
    if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
        return Err(protocol_error("missing h2"));
    }
    let mut builder = h2::server::Builder::new();
    builder
        .max_concurrent_streams(4)
        .max_send_buffer_size(64 * 1024);
    let mut connection = builder.handshake(tls).await.map_err(protocol_error)?;
    let mut requests = JoinSet::new();
    let mut summary = BridgeSummary::default();
    let mut request_count = 0;
    let mut connection_failure = None;
    loop {
        tokio::select! {
            accepted = connection.accept() => {
                let (request, mut respond) = match accepted {
                    Some(Ok(accepted)) => accepted,
                    Some(Err(error)) => {
                        connection_failure = Some(protocol_error(error));
                        break;
                    }
                    None => break,
                };
                request_count += 1;
                if request_count > limits.requests_per_connection {
                    fixed_response(&mut respond, 404, NOT_FOUND)?;
                    summary.generic_not_found += 1;
                    connection.graceful_shutdown();
                    continue;
                }
                if gate.same_authority(&request) && request.method() == Method::GET
                    && request.uri().path_and_query().map(|p| p.as_str()) == Some("/") {
                    fixed_response(&mut respond, 200, PAGE)?;
                    summary.public_pages += 1;
                } else if !gate.permits(&request) || requests.len() >= 4 {
                    fixed_response(&mut respond, 404, NOT_FOUND)?;
                    summary.generic_not_found += 1;
                } else {
                    // Only a successful private route gate distinguishes this
                    // carrier. No inner device payload has yet been accepted.
                    let response = Response::builder().status(200)
                        .header("content-type", "application/grpc")
                        .header("cache-control", "no-store")
                        .body(()).map_err(protocol_error)?;
                    let send = respond.send_response(response, false).map_err(protocol_error)?;
                    summary.gated_carriers += 1;
                    let carrier = GrpcIo::new(H2Stream::new(send, request.into_body()));
                    let inner = inner_tls.clone();
                    requests.spawn(async move {
                        let _capacity = inner.try_acquire()?;
                        let (mut secured, lease) = inner.accept_with_lease(carrier).await?;
                        let echo = async {
                            let length = secured.read_u16().await? as usize;
                            if length == 0 || length > limits.max_echo_bytes {
                                return Err(invalid("local echo length is outside fixture limit"));
                            }
                            let mut payload = vec![0; length];
                            secured.read_exact(&mut payload).await?;
                            secured.write_u16(length as u16).await?;
                            secured.write_all(&payload).await?;
                            secured.flush().await?;
                            secured.shutdown().await?;
                            io::Result::Ok(())
                        };
                        tokio::select! {
                            biased;
                            failure = lease.revoked() => Err(failure),
                            result = echo => result,
                        }
                    });
                }
                if request_count >= limits.requests_per_connection {
                    connection.graceful_shutdown();
                }
            }
            result = requests.join_next(), if !requests.is_empty() => {
                match result {
                    Some(Ok(Ok(()))) => summary.authenticated_echoes += 1,
                    Some(Ok(Err(_))) => summary.refused_inner_channels += 1,
                    Some(Err(_)) => summary.counts_may_be_incomplete = true,
                    None => {},
                }
            }
        }
    }
    // A connection cannot leave detached authorized or unauthenticated work.
    requests.abort_all();
    while let Some(result) = requests.join_next().await {
        match result {
            Ok(Ok(())) => summary.authenticated_echoes += 1,
            Ok(Err(_)) => summary.refused_inner_channels += 1,
            Err(_) => summary.counts_may_be_incomplete = true,
        }
    }
    match connection_failure {
        Some(error) => Err(error),
        None => Ok(summary),
    }
}

fn fixed_response(
    respond: &mut h2::server::SendResponse<Bytes>,
    status: u16,
    body: &'static [u8],
) -> io::Result<()> {
    let response = Response::builder()
        .status(status)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .header("content-length", body.len())
        .body(())
        .map_err(protocol_error)?;
    respond
        .send_response(response, false)
        .map_err(protocol_error)?
        .send_data(Bytes::from_static(body), true)
        .map_err(protocol_error)
}

// Disposable key custody is asserted on Unix. This fixture intentionally does
// not claim Windows private-file ACL custody or installed-client support.
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use aegis_core::secure_channel::{Client, ClientSettings, ServerSettings};
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::path::Path;
    use tokio::task::JoinHandle;
    use tokio_rustls::TlsConnector;

    struct Fixture {
        _dir: tempfile::TempDir,
        outer_server: Arc<rustls::ServerConfig>,
        outer_client: Arc<rustls::ClientConfig>,
        inner_server: Server,
        inner_client: Client,
        refused_client: Client,
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let make_leaf = |name: &str, usage| {
            let mut params = CertificateParams::new(vec![name.into()]).unwrap();
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![usage];
            let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
            let cert = params.signed_by(&key, &ca, &ca_key).unwrap();
            (cert, key)
        };
        let (outer_cert, outer_key) = make_leaf("bridge.test", ExtendedKeyUsagePurpose::ServerAuth);
        let (inner_cert, inner_key) = make_leaf("inner.test", ExtendedKeyUsagePurpose::ServerAuth);
        let (device_cert, device_key) =
            make_leaf("device.test", ExtendedKeyUsagePurpose::ClientAuth);
        let (refused_cert, refused_key) =
            make_leaf("refused.test", ExtendedKeyUsagePurpose::ClientAuth);
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut outer_server = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![outer_cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(outer_key.serialize_der())),
            )
            .unwrap();
        outer_server.alpn_protocols = vec![b"h2".to_vec()];
        outer_server.key_log = Arc::new(rustls::NoKeyLog);
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        let mut outer_client = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        outer_client.alpn_protocols = vec![b"h2".to_vec()];
        outer_client.key_log = Arc::new(rustls::NoKeyLog);
        for (name, pem) in [
            ("ca.pem", ca.pem()),
            ("inner.pem", inner_cert.pem()),
            ("device.pem", device_cert.pem()),
            ("refused.pem", refused_cert.pem()),
        ] {
            std::fs::write(dir.path().join(name), pem).unwrap();
        }
        for (name, key) in [
            ("inner.key", inner_key),
            ("device.key", device_key),
            ("refused.key", refused_key),
        ] {
            write_private(&dir.path().join(name), key.serialize_pem().as_bytes());
        }
        let inner_server = Server::load(&ServerSettings {
            cert: dir.path().join("inner.pem"),
            key: dir.path().join("inner.key"),
            client_ca: dir.path().join("ca.pem"),
            allowed_client_sha256: vec![hex::encode(Sha256::digest(device_cert.der().as_ref()))],
            device_registry: None,
            admission: Default::default(),
            handshake_timeout_ms: 500,
            idle_timeout_ms: 500,
        })
        .unwrap();
        let load_client = |prefix: &str| {
            Client::load(&ClientSettings {
                server_name: "inner.test".into(),
                server_ca: dir.path().join("ca.pem"),
                cert: dir.path().join(format!("{prefix}.pem")),
                key: dir.path().join(format!("{prefix}.key")),
            })
            .unwrap()
        };
        let inner_client = load_client("device");
        let refused_client = load_client("refused");
        Fixture {
            _dir: dir,
            outer_server: Arc::new(outer_server),
            outer_client: Arc::new(outer_client),
            inner_server,
            inner_client,
            refused_client,
        }
    }

    struct Driver(JoinHandle<Result<(), h2::Error>>);
    impl Drop for Driver {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    async fn connect(
        f: &Fixture,
        address: std::net::SocketAddr,
    ) -> (h2::client::SendRequest<Bytes>, Driver) {
        let socket = TcpStream::connect(address).await.unwrap();
        let tls = TlsConnector::from(f.outer_client.clone())
            .connect(ServerName::try_from("bridge.test").unwrap(), socket)
            .await
            .unwrap();
        assert_eq!(
            tls.get_ref().1.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
        assert!(tls.get_ref().1.peer_certificates().is_some());
        let (sender, driver) = h2::client::handshake(tls).await.unwrap();
        (sender, Driver(tokio::spawn(driver)))
    }

    fn request(method: Method, path: &str, token: Option<&[u8]>) -> Request<()> {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("https://bridge.test{path}"));
        if let Some(token) = token {
            builder = builder
                .header(GATE_HEADER, token)
                .header("content-type", "application/grpc");
        }
        builder.body(()).unwrap()
    }

    async fn body(mut response: http::Response<h2::RecvStream>) -> Vec<u8> {
        let mut bytes = Vec::new();
        while let Some(chunk) = response.body_mut().data().await {
            let chunk = chunk.unwrap();
            response
                .body_mut()
                .flow_control()
                .release_capacity(chunk.len())
                .unwrap();
            bytes.extend_from_slice(&chunk);
            assert!(bytes.len() <= 4096);
        }
        bytes
    }

    #[test]
    fn https_bridge_gate_is_private_and_canonical() {
        let token = b"disposable-private-test-route-credential";
        let gate = BridgeGate::new("bridge.test", "/private-local-fixture", token).unwrap();
        assert_eq!(format!("{gate:?}"), "BridgeGate { redacted }");
        assert!(gate.permits(&request(
            Method::POST,
            "/private-local-fixture",
            Some(token)
        )));
        for (method, path, supplied) in [
            (Method::GET, "/private-local-fixture", Some(&token[..])),
            (Method::POST, "/private-local-fixture?x=1", Some(&token[..])),
            (Method::POST, "/private-local-fixture/", Some(&token[..])),
            (Method::POST, "/private-local-fixture", None),
            (
                Method::POST,
                "/private-local-fixture",
                Some(&b"different-private-test-route-credential"[..]),
            ),
        ] {
            assert!(!gate.permits(&request(method, path, supplied)));
        }
        let mut duplicate = request(Method::POST, "/private-local-fixture", Some(token));
        duplicate
            .headers_mut()
            .append(GATE_HEADER, http::HeaderValue::from_bytes(token).unwrap());
        assert!(!gate.permits(&duplicate));
        let mut different = request(Method::POST, "/private-local-fixture", Some(token));
        *different.uri_mut() = "https://different.test/private-local-fixture"
            .parse()
            .unwrap();
        assert!(!gate.permits(&different));
        assert!(BridgeGate::new("bridge.test", "/path?query", token).is_err());
        assert!(BridgeGate::new("bridge.test", "/path", b"short").is_err());
    }

    #[tokio::test]
    async fn https_bridge_verified_tls_site_generic_refusal_and_inner_mtls_echo() {
        let f = fixture();
        let token = b"disposable-private-test-route-credential";
        let gate = BridgeGate::new("bridge.test", "/private-local-fixture", token).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let serving = tokio::spawn(serve_loopback(
            listener,
            f.outer_server.clone(),
            gate,
            f.inner_server.clone(),
            BridgeLimits {
                max_connections: 1,
                ..BridgeLimits::default()
            },
        ));
        timeout(Duration::from_secs(3), async {
            let (mut sender, driver) = connect(&f, address).await;
            let (page, _) = sender
                .send_request(request(Method::GET, "/", None), true)
                .unwrap();
            let page = page.await.unwrap();
            assert_eq!(page.status(), 200);
            assert_eq!(body(page).await, PAGE);
            let mut refused = Vec::new();
            for (method, path, supplied) in [
                (Method::POST, "/unknown", Some(&token[..])),
                (Method::GET, "/private-local-fixture", Some(&token[..])),
                (Method::POST, "/private-local-fixture", None),
                (
                    Method::POST,
                    "/private-local-fixture",
                    Some(&b"different-private-test-route-credential"[..]),
                ),
            ] {
                sender = sender.ready().await.unwrap();
                let (response, _) = sender
                    .send_request(request(method, path, supplied), true)
                    .unwrap();
                let response = response.await.unwrap();
                assert_eq!(response.status(), 404);
                assert!(!response.headers().contains_key("grpc-status"));
                refused.push((response.headers().clone(), body(response).await));
            }
            for pair in refused.windows(2) {
                assert_eq!(pair[0], pair[1]);
            }
            assert_eq!(refused[0].1, NOT_FOUND);
            sender = sender.ready().await.unwrap();
            let (response, send) = sender
                .send_request(
                    request(Method::POST, "/private-local-fixture", Some(token)),
                    false,
                )
                .unwrap();
            let response = response.await.unwrap();
            assert_eq!(response.status(), 200);
            let carrier = GrpcIo::new(H2Stream::new(send, response.into_body()));
            let mut secured = f.inner_client.connect(carrier).await.unwrap();
            let secret = b"bounded-authenticated-inner-payload";
            secured.write_u16(secret.len() as u16).await.unwrap();
            secured.write_all(secret).await.unwrap();
            secured.flush().await.unwrap();
            let length = secured.read_u16().await.unwrap() as usize;
            let mut echoed = vec![0; length];
            secured.read_exact(&mut echoed).await.unwrap();
            assert_eq!(echoed, secret);
            let mut eof = [0u8; 1];
            assert_eq!(secured.read(&mut eof).await.unwrap(), 0);
            drop(secured);
            drop(sender);
            drop(driver);
        })
        .await
        .unwrap();
        let summary = serving.await.unwrap().unwrap();
        assert_eq!(summary.public_pages, 1);
        assert_eq!(summary.generic_not_found, 4);
        assert_eq!(summary.gated_carriers, 1);
        assert_eq!(summary.authenticated_echoes, 1);
        assert!(TcpStream::connect(address).await.is_err());
    }

    #[tokio::test]
    async fn https_bridge_route_gate_does_not_authorize_a_refused_device() {
        let f = fixture();
        let token = b"disposable-private-test-route-credential";
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let serving = tokio::spawn(serve_loopback(
            listener,
            f.outer_server.clone(),
            BridgeGate::new("bridge.test", "/private-local-fixture", token).unwrap(),
            f.inner_server.clone(),
            BridgeLimits {
                max_connections: 1,
                ..BridgeLimits::default()
            },
        ));
        timeout(Duration::from_secs(3), async {
            let (mut sender, driver) = connect(&f, address).await;
            let (response, send) = sender
                .send_request(
                    request(Method::POST, "/private-local-fixture", Some(token)),
                    false,
                )
                .unwrap();
            let carrier = GrpcIo::new(H2Stream::new(send, response.await.unwrap().into_body()));
            // TLS may finish at the client before the server's pin check. Only
            // an application response proves acceptance, so test that too.
            if let Ok(mut secured) = f.refused_client.connect(carrier).await {
                let outcome = async {
                    secured.write_u16(1).await?;
                    secured.write_all(b"x").await?;
                    secured.flush().await?;
                    secured.read_u16().await
                }
                .await;
                assert!(outcome.is_err());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
            drop(sender);
            drop(driver);
        })
        .await
        .unwrap();
        let summary = serving.await.unwrap().unwrap();
        assert_eq!(summary.authenticated_echoes, 0);
        assert_eq!(summary.refused_inner_channels, 1);
    }

    #[tokio::test]
    async fn https_bridge_silent_tls_has_bounded_cleanup() {
        let f = fixture();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let serving = tokio::spawn(serve_loopback(
            listener,
            f.outer_server.clone(),
            BridgeGate::new(
                "bridge.test",
                "/private-local-fixture",
                b"disposable-private-test-route-credential",
            )
            .unwrap(),
            f.inner_server.clone(),
            BridgeLimits {
                max_connections: 1,
                outer_handshake_time: Duration::from_millis(50),
                ..BridgeLimits::default()
            },
        ));
        let mut silent = TcpStream::connect(address).await.unwrap();
        let started = Instant::now();
        let summary = timeout(Duration::from_secs(1), serving)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(summary.accepted_connections, 1);
        assert_eq!(summary.failed_connections, 1);
        let mut byte = [0];
        assert_eq!(silent.read(&mut byte).await.unwrap(), 0);
        assert!(TcpStream::connect(address).await.is_err());
    }

    #[tokio::test]
    async fn https_bridge_outer_hostname_substitution_fails() {
        let f = fixture();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let serving = tokio::spawn(serve_loopback(
            listener,
            f.outer_server.clone(),
            BridgeGate::new(
                "bridge.test",
                "/private-local-fixture",
                b"disposable-private-test-route-credential",
            )
            .unwrap(),
            f.inner_server.clone(),
            BridgeLimits {
                max_connections: 1,
                ..BridgeLimits::default()
            },
        ));
        let socket = TcpStream::connect(address).await.unwrap();
        let result = TlsConnector::from(f.outer_client.clone())
            .connect(ServerName::try_from("wrong.test").unwrap(), socket)
            .await;
        assert!(result.is_err());
        let summary = serving.await.unwrap().unwrap();
        assert_eq!(summary.gated_carriers, 0);
        assert_eq!(summary.authenticated_echoes, 0);
    }
}
