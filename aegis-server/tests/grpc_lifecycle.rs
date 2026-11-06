use aegis_core::tunnel::{open_tunnel_response, seal_tunnel_request, TunnelRequest, TunnelStatus};
use aegis_server::config::{ServerConfig, TargetPolicyConfig, TargetPolicyProfile};
use bytes::Bytes;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use std::{future::Future, net::SocketAddr, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;

const WATCHDOG: Duration = Duration::from_secs(15);
const STAGE_TIMEOUT: Duration = Duration::from_secs(3);
const TEST_TOKEN: &[u8] = b"140d05f2c949217d7a78b416c50c24c63355302c2c09cac6f115f39913edd47e";

struct OwnedTask<T>(JoinHandle<T>);

impl<T> Drop for OwnedTask<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn stage<T>(name: &str, future: impl Future<Output = T>) -> T {
    tokio::time::timeout(STAGE_TIMEOUT, future)
        .await
        .unwrap_or_else(|_| panic!("timed out at {name}"))
}

fn live_tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

async fn tasks_return_to(baseline: usize) {
    stage("owned task cleanup", async {
        while live_tasks() != baseline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert_eq!(live_tasks(), baseline);
}

struct ServerFixture {
    server: OwnedTask<anyhow::Result<()>>,
    shutdown: Option<oneshot::Sender<()>>,
    addr: SocketAddr,
    grpc_path: String,
    connector: TlsConnector,
    _cert_dir: tempfile::TempDir,
}

impl ServerFixture {
    async fn start() -> Self {
        Self::start_with_grace(20).await
    }

    async fn start_with_grace(shutdown_grace_ms: u64) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert_dir = tempfile::tempdir().expect("certificate directory");
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).expect("test certificate");
        let cert_path = cert_dir.path().join("cert.pem");
        let key_path = cert_dir.path().join("key.pem");
        std::fs::write(&cert_path, cert.pem()).expect("write certificate");
        std::fs::write(&key_path, key_pair.serialize_pem()).expect("write private key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(cert.der().clone())
            .expect("trust test certificate");
        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h2".to_vec()];

        let reservation = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve server port");
        let addr = reservation.local_addr().expect("server address");
        let mut cfg = ServerConfig {
            listen: addr.to_string(),
            cert: cert_path,
            key: key_path,
            auth_token: String::from_utf8(TEST_TOKEN.to_vec()).expect("ASCII test token"),
            legacy_auth_tokens: Vec::new(),
            process_alias: None,
            logging: Default::default(),
            fallback: "close".into(),
            limits: Default::default(),
            rate_limit: Default::default(),
            target_policy: TargetPolicyConfig {
                profile: TargetPolicyProfile::FullVpnEgress,
                allowed_ports: Vec::new(),
            },
            transport: Default::default(),
            bundle_endpoint: Default::default(),
        };
        cfg.limits.shutdown_grace_ms = shutdown_grace_ms;
        cfg.transport.quic_listen = Some("127.0.0.1:0".into());
        let grpc_path = cfg.transport.grpc_path.clone();
        let (ready_tx, ready_rx) = oneshot::channel();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        drop(reservation);
        let server = OwnedTask(tokio::spawn(aegis_server::run_server_with_shutdown(
            cfg,
            Some(ready_tx),
            async {
                let _ = shutdown_rx.await;
            },
        )));
        let fixture = Self {
            server,
            shutdown: Some(shutdown_tx),
            addr,
            grpc_path,
            connector: TlsConnector::from(Arc::new(tls)),
            _cert_dir: cert_dir,
        };
        stage("server readiness", ready_rx)
            .await
            .expect("server reports ready");
        fixture
    }

    async fn shutdown(&mut self) {
        self.shutdown
            .take()
            .expect("shutdown trigger")
            .send(())
            .expect("server receives shutdown");
        stage("server shutdown grace", &mut self.server.0)
            .await
            .expect("server task joins")
            .expect("server shutdown succeeds");
    }

    async fn abort(&mut self) {
        self.server.0.abort();
        assert!(stage("server abort", &mut self.server.0)
            .await
            .expect_err("server task is cancelled")
            .is_cancelled());
    }
}

struct H2Client {
    sender: h2::client::SendRequest<Bytes>,
    ping: h2::PingPong,
    driver: OwnedTask<Result<(), h2::Error>>,
}

impl H2Client {
    async fn connect(fixture: &ServerFixture) -> Self {
        let tcp = stage("relay TCP connect", TcpStream::connect(fixture.addr))
            .await
            .expect("relay TCP connection");
        let tls = stage(
            "relay TLS connect",
            fixture.connector.connect(
                "localhost".to_string().try_into().expect("TLS server name"),
                tcp,
            ),
        )
        .await
        .expect("authenticated TLS connection");
        let (sender, mut connection) = stage("H2 handshake", h2::client::handshake(tls))
            .await
            .expect("H2 client handshake");
        let ping = connection.ping_pong().expect("H2 ping handle");
        let driver = OwnedTask(tokio::spawn(connection));
        let mut client = Self {
            sender,
            ping,
            driver,
        };
        client.ping().await;
        client
    }

    async fn ping(&mut self) {
        stage("H2 ping barrier", self.ping.ping(h2::Ping::opaque()))
            .await
            .expect("same H2 connection remains live");
        assert!(!self.driver.0.is_finished());
    }

    async fn tunnel(&mut self, fixture: &ServerFixture, target: &TcpListener) -> Tunnel {
        stage(
            "H2 request readiness",
            std::future::poll_fn(|cx| self.sender.poll_ready(cx)),
        )
        .await
        .expect("H2 accepts request");
        let request = http::Request::builder()
            .method("POST")
            .uri(&fixture.grpc_path)
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(())
            .expect("gRPC request");
        let (response, mut send) = self
            .sender
            .send_request(request, false)
            .expect("open stream");
        let open = seal_tunnel_request(
            &TunnelRequest {
                host: "127.0.0.1".into(),
                port: target.local_addr().expect("target address").port(),
            },
            TEST_TOKEN,
        )
        .expect("seal authenticated tunnel open");
        send.send_data(grpc_frame(&open), false)
            .expect("send tunnel open");
        let response = stage("gRPC response headers", response)
            .await
            .expect("response headers");
        assert!(response.status().is_success());
        let mut tunnel = Tunnel {
            send,
            recv: response.into_body(),
            pending: Vec::new(),
        };
        let ack = stage("authenticated tunnel acknowledgment", tunnel.message())
            .await
            .expect("tunnel acknowledgment");
        let ack = open_tunnel_response(&ack, TEST_TOKEN).expect("authenticate acknowledgment");
        assert_eq!(ack.status, TunnelStatus::Ok);
        tunnel
    }

    async fn disconnect(&mut self) {
        self.driver.0.abort();
        assert!(stage("client disconnect", &mut self.driver.0)
            .await
            .expect_err("client driver cancelled")
            .is_cancelled());
    }
}

struct Tunnel {
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
    pending: Vec<u8>,
}

impl Tunnel {
    async fn message(&mut self) -> Option<Vec<u8>> {
        loop {
            if self.pending.len() >= 5 {
                assert_eq!(self.pending[0], 0, "uncompressed gRPC message");
                let len = u32::from_be_bytes(self.pending[1..5].try_into().unwrap()) as usize;
                assert!(len <= 1024 * 1024, "bounded fixture message");
                if self.pending.len() >= 5 + len {
                    let payload = self.pending[5..5 + len].to_vec();
                    self.pending.drain(..5 + len);
                    return Some(payload);
                }
            }
            let Some(chunk) = self.recv.data().await else {
                assert!(self.pending.is_empty(), "no truncated final gRPC message");
                return None;
            };
            let chunk = chunk.expect("gRPC response data");
            self.pending.extend_from_slice(&chunk);
            self.recv
                .flow_control()
                .release_capacity(chunk.len())
                .expect("release H2 capacity");
        }
    }
}

fn grpc_frame(payload: &[u8]) -> Bytes {
    let mut framed = Vec::with_capacity(payload.len() + 5);
    framed.push(0);
    framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    framed.extend_from_slice(payload);
    Bytes::from(framed)
}

async fn target_listener() -> TcpListener {
    TcpListener::bind("127.0.0.1:0")
        .await
        .expect("controlled target listener")
}

async fn accept_target(listener: &TcpListener) -> TcpStream {
    stage("target accepted authenticated tunnel", listener.accept())
        .await
        .expect("target accepts relay socket")
        .0
}

async fn target_eof(target: &mut TcpStream) {
    let result = stage("target peer EOF", target.read(&mut [0u8; 1])).await;
    match result {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
            ) => {}
        other => panic!("target socket was not closed: {other:?}"),
    }
}

#[tokio::test]
async fn grpc_server_shutdown_reaps_silent_target_stream() {
    tokio::time::timeout(WATCHDOG, async {
        let baseline = live_tasks();
        let mut fixture = ServerFixture::start().await;
        let mut client = H2Client::connect(&fixture).await;
        let listener = target_listener().await;
        let _tunnel = client.tunnel(&fixture, &listener).await;
        let mut target = accept_target(&listener).await;
        fixture.shutdown().await;
        target_eof(&mut target).await;
        // EOF alone can be just the leaked worker's write-half shutdown.
        // The silent read-side worker must also disappear, without target data.
        tasks_return_to(baseline).await;
    })
    .await
    .expect("bounded gRPC server shutdown fixture");
}

async fn forced_shutdown_reaps_silent_targets(
    shutdown_grace_ms: u64,
    connection_count: usize,
    streams_per_connection: usize,
) {
    let baseline = live_tasks();
    let mut fixture = ServerFixture::start_with_grace(shutdown_grace_ms).await;
    let listener = target_listener().await;
    let mut clients = Vec::new();
    let mut tunnels = Vec::new();
    let mut targets = Vec::new();
    for _ in 0..connection_count {
        let mut client = H2Client::connect(&fixture).await;
        for _ in 0..streams_per_connection {
            tunnels.push(client.tunnel(&fixture, &listener).await);
            targets.push(accept_target(&listener).await);
        }
        client.ping().await;
        clients.push(client);
    }
    assert_eq!(tunnels.len(), connection_count * streams_per_connection);
    assert!(live_tasks() > baseline, "silent streams remain active");

    // Every request remains open and each target remains silent, so natural
    // stream completion cannot drain the server during the shutdown grace.
    fixture.shutdown().await;
    for target in &mut targets {
        target_eof(target).await;
    }
    // This integration check proves bounded eventual cleanup, not that target
    // destruction happened synchronously before shutdown() returned.
    tasks_return_to(baseline).await;
    assert!(clients.iter().all(|client| client.driver.0.is_finished()));
}

#[tokio::test]
async fn grpc_zero_grace_shutdown_reaps_silent_target_streams() {
    tokio::time::timeout(WATCHDOG, forced_shutdown_reaps_silent_targets(0, 1, 2))
        .await
        .expect("bounded zero-grace gRPC shutdown fixture");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_multithread_forced_shutdown_reaps_silent_connection_subsets() {
    tokio::time::timeout(WATCHDOG, forced_shutdown_reaps_silent_targets(20, 2, 2))
        .await
        .expect("bounded multithread forced gRPC shutdown fixture");
}

#[tokio::test]
async fn grpc_server_abort_reaps_silent_target_stream() {
    tokio::time::timeout(WATCHDOG, async {
        let baseline = live_tasks();
        let mut fixture = ServerFixture::start().await;
        let mut client = H2Client::connect(&fixture).await;
        let listener = target_listener().await;
        let _tunnel = client.tunnel(&fixture, &listener).await;
        let mut target = accept_target(&listener).await;
        fixture.abort().await;
        target_eof(&mut target).await;
        tasks_return_to(baseline).await;
    })
    .await
    .expect("bounded gRPC server abort fixture");
}

#[tokio::test]
async fn grpc_reset_after_request_end_reaps_stream_without_closing_h2_connection() {
    tokio::time::timeout(WATCHDOG, async {
        let mut fixture = ServerFixture::start().await;
        let mut client = H2Client::connect(&fixture).await;
        let baseline = live_tasks();
        let listener = target_listener().await;
        let mut tunnel = client.tunnel(&fixture, &listener).await;
        let mut target = accept_target(&listener).await;
        assert!(
            live_tasks() > baseline,
            "authenticated stream worker is alive"
        );
        tunnel
            .send
            .send_data(Bytes::new(), true)
            .expect("request END_STREAM");
        target_eof(&mut target).await;
        client.ping().await;
        assert!(
            live_tasks() > baseline,
            "clean half-close preserves response worker"
        );

        tunnel.send.send_reset(h2::Reason::CANCEL);
        client.ping().await;
        // Once END_STREAM has sent a target FIN, another target read cannot
        // distinguish full cleanup from a leaked downlink. A target write
        // would wake the old leak and hide it. Count this isolated runtime's
        // worker instead; all other fixture tasks and the H2 connection stay.
        tasks_return_to(baseline).await;
        client.ping().await;
        assert!(!fixture.server.0.is_finished());
        fixture.shutdown().await;
    })
    .await
    .expect("bounded request-END_STREAM then reset fixture");
}

#[tokio::test]
async fn grpc_request_half_close_preserves_delayed_complete_target_response() {
    tokio::time::timeout(WATCHDOG, async {
        let mut fixture = ServerFixture::start().await;
        let mut client = H2Client::connect(&fixture).await;
        let listener = target_listener().await;
        let mut tunnel = client.tunnel(&fixture, &listener).await;
        let mut target = accept_target(&listener).await;
        let request = b"request completed before delayed response";
        tunnel
            .send
            .send_data(grpc_frame(request), true)
            .expect("request and END_STREAM");
        let mut received_request = Vec::new();
        stage(
            "target observes clean request half-close",
            target.read_to_end(&mut received_request),
        )
        .await
        .expect("target reads full request then EOF");
        assert_eq!(received_request, request);
        client.ping().await;

        let expected: Vec<u8> = (0..(256 * 1024 + 137))
            .map(|index| (index % 251) as u8)
            .collect();
        let response = expected.clone();
        let mut writer = OwnedTask(tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            target
                .write_all(&response)
                .await
                .expect("write delayed full response");
            target.shutdown().await.expect("target response EOF");
        }));
        let mut received = Vec::new();
        while let Some(message) = stage("complete delayed gRPC response", tunnel.message()).await {
            received.extend_from_slice(&message);
            assert!(
                received.len() <= expected.len(),
                "no duplicate response bytes"
            );
        }
        stage("delayed response writer", &mut writer.0)
            .await
            .expect("response writer joins");
        assert_eq!(
            received, expected,
            "half-close must not truncate target response"
        );
        client.ping().await;
        fixture.shutdown().await;
    })
    .await
    .expect("bounded half-close delayed response fixture");
}

#[tokio::test]
async fn grpc_client_disconnect_reaps_silent_target_stream() {
    tokio::time::timeout(WATCHDOG, async {
        let mut fixture = ServerFixture::start().await;
        let baseline = live_tasks();
        let mut client = H2Client::connect(&fixture).await;
        let listener = target_listener().await;
        let _tunnel = client.tunnel(&fixture, &listener).await;
        let mut target = accept_target(&listener).await;
        client.disconnect().await;
        target_eof(&mut target).await;
        tasks_return_to(baseline).await;
        assert!(!fixture.server.0.is_finished());
        fixture.shutdown().await;
    })
    .await
    .expect("bounded client disconnect fixture");
}

#[tokio::test]
async fn grpc_connection_disconnect_preserves_other_connections_active_tunnel() {
    tokio::time::timeout(WATCHDOG, async {
        let baseline = live_tasks();
        let mut fixture = ServerFixture::start().await;
        let listener = target_listener().await;
        let mut survivor = H2Client::connect(&fixture).await;
        let mut survivor_tunnel = survivor.tunnel(&fixture, &listener).await;
        let mut survivor_target = accept_target(&listener).await;
        survivor.ping().await;
        let survivor_baseline = live_tasks();

        let mut disconnected = H2Client::connect(&fixture).await;
        let _disconnected_tunnel = disconnected.tunnel(&fixture, &listener).await;
        let mut disconnected_target = accept_target(&listener).await;
        disconnected.ping().await;
        assert!(live_tasks() > survivor_baseline);
        disconnected.disconnect().await;
        target_eof(&mut disconnected_target).await;
        // Do not wake the disconnected tunnel's target read with a write:
        // its entire connection subset must disappear while it stays silent.
        tasks_return_to(survivor_baseline).await;

        survivor.ping().await;
        let request = b"surviving connection request";
        survivor_tunnel
            .send
            .send_data(grpc_frame(request), false)
            .expect("survivor sends request after other connection disconnects");
        let mut received_request = vec![0; request.len()];
        stage(
            "survivor target receives complete request",
            survivor_target.read_exact(&mut received_request),
        )
        .await
        .expect("survivor target reads request");
        assert_eq!(received_request, request);

        let response = b"surviving connection response";
        stage(
            "survivor target writes response",
            survivor_target.write_all(response),
        )
        .await
        .expect("survivor target stays writable");
        let mut received_response = Vec::new();
        while received_response.len() < response.len() {
            let message = stage("survivor tunnel response", survivor_tunnel.message())
                .await
                .expect("survivor response remains open");
            received_response.extend_from_slice(&message);
            assert!(received_response.len() <= response.len());
        }
        assert_eq!(received_response, response);
        survivor.ping().await;
        assert!(!fixture.server.0.is_finished());

        fixture.shutdown().await;
        target_eof(&mut survivor_target).await;
        tasks_return_to(baseline).await;
    })
    .await
    .expect("bounded per-connection cancellation isolation fixture");
}
