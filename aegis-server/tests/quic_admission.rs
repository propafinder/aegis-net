//! Shared causal fixture for the complete predecessor and candidate sources.
//! Every peer and target is local; at most one stalled QUIC peer is introduced.

use aegis_core::tunnel::{open_tunnel_response, seal_tunnel_request, TunnelRequest, TunnelStatus};
use aegis_core::{auto_capture_probe, build_connect_udp_path, DEFAULT_MASQUE_PATH};
use aegis_server::config::{ServerConfig, TargetPolicyConfig, TargetPolicyProfile};
use bytes::{Buf, Bytes};
use h3::ext::Protocol;
use h3_datagram::datagram_handler::HandleDatagramsExt;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::{CertificateDer, ServerName};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;

const STAGE_BOUND: Duration = Duration::from_secs(3);
// Public synthetic fixture credential; never substitute an operational token.
const FIXTURE_TOKEN: &str = "af7e3598d0ce822bd30c46f087e6019cb45256315ad54f885d3244e8c239a1c7";

struct OwnedTask<T>(JoinHandle<T>);

impl<T> Drop for OwnedTask<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct ClientEndpoint(quinn::Endpoint);

impl Drop for ClientEndpoint {
    fn drop(&mut self) {
        self.0
            .close(quinn::VarInt::from_u32(0), b"fixture completed");
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    cert: CertificateDer<'static>,
    tcp_addr: SocketAddr,
    udp_addr: SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    server: OwnedTask<anyhow::Result<()>>,
}

impl Fixture {
    async fn start(read_timeout_ms: u64) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().expect("fixture directory");
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).expect("fixture certificate");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, cert.pem()).expect("fixture certificate write");
        #[cfg(not(windows))]
        std::fs::write(&key_path, key_pair.serialize_pem()).expect("fixture key write");
        #[cfg(windows)]
        aegis_core::windows_file::write_private_new(
            &key_path,
            key_pair.serialize_pem().as_bytes(),
            false,
        )
        .expect("private Windows fixture key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let tcp_reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = tcp_reservation.local_addr().unwrap();
        let udp_reservation = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = udp_reservation.local_addr().unwrap();
        let mut cfg = ServerConfig {
            listen: tcp_addr.to_string(),
            cert: cert_path,
            key: key_path,
            auth_token: FIXTURE_TOKEN.into(),
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
        cfg.limits.max_connections = 1;
        cfg.limits.read_timeout_ms = read_timeout_ms;
        cfg.limits.shutdown_grace_ms = 0;
        cfg.transport.quic_listen = Some(udp_addr.to_string());
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        drop(tcp_reservation);
        drop(udp_reservation);
        let server = OwnedTask(tokio::spawn(aegis_server::run_server_with_shutdown(
            cfg,
            Some(ready_tx),
            async {
                let _ = shutdown_rx.await;
            },
        )));
        tokio::time::timeout(STAGE_BOUND, ready_rx)
            .await
            .expect("combined listener deadline")
            .expect("combined listener readiness");
        Self {
            _dir: dir,
            cert: cert.der().clone(),
            tcp_addr,
            udp_addr,
            shutdown: Some(shutdown_tx),
            server,
        }
    }

    fn tls_config(&self) -> rustls::ClientConfig {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.cert.clone()).unwrap();
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    }

    fn quic_endpoint(&self) -> ClientEndpoint {
        let mut crypto = self.tls_config();
        crypto.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap();
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
        ClientEndpoint(endpoint)
    }

    async fn tcp_tls(&self) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let tcp = TcpStream::connect(self.tcp_addr).await?;
        TlsConnector::from(Arc::new(self.tls_config()))
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
    }

    async fn stop(mut self) {
        self.shutdown.take().unwrap().send(()).unwrap();
        tokio::time::timeout(STAGE_BOUND, &mut self.server.0)
            .await
            .expect("fixture shutdown deadline")
            .expect("fixture shutdown join")
            .expect("fixture server result");
        TcpListener::bind(self.tcp_addr)
            .await
            .expect("TCP listener released");
        UdpSocket::bind(self.udp_addr)
            .await
            .expect("UDP listener released");
    }
}

fn v1_long_packet_type(packet: &[u8]) -> u8 {
    assert!(packet.len() >= 5, "complete long-header prefix");
    // RFC 9287 GREASE_QUIC_BIT can clear 0x40 on a supported relay response.
    // Header form, version and packet type still identify this controlled packet.
    assert_eq!(packet[0] & 0x80, 0x80, "QUIC long header");
    assert_eq!(&packet[1..5], &[0, 0, 0, 1], "controlled QUIC version 1");
    (packet[0] >> 4) & 3
}

fn initial_token_length(packet: &[u8]) -> usize {
    assert_eq!(v1_long_packet_type(packet), 0, "client Initial");
    let mut cursor = 5;
    let dcid_len = usize::from(packet[cursor]);
    cursor += 1 + dcid_len;
    let scid_len = usize::from(packet[cursor]);
    cursor += 1 + scid_len;
    let width = 1usize << (packet[cursor] >> 6);
    let mut value = usize::from(packet[cursor] & 0x3f);
    for byte in &packet[cursor + 1..cursor + width] {
        value = (value << 8) | usize::from(*byte);
    }
    value
}

struct StalledInitial {
    _socket: UdpSocket,
    _endpoint: ClientEndpoint,
    _connecting: quinn::Connecting,
    retried: bool,
}

/// Capture a genuine Quinn Initial from one local client, then forward only
/// enough packets to yield a pending server handshake. The same fixture accepts
/// the predecessor's direct response or the candidate's Retry response.
async fn stalled_initial(fixture: &Fixture) -> StalledInitial {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = fixture.quic_endpoint();
    let connecting = endpoint
        .0
        .connect(socket.local_addr().unwrap(), "localhost")
        .unwrap();
    let mut packet = [0u8; 65_535];
    let (length, client_addr) = tokio::time::timeout(STAGE_BOUND, socket.recv_from(&mut packet))
        .await
        .unwrap()
        .unwrap();
    assert!(length >= 1200, "genuine padded Initial");
    assert_eq!(initial_token_length(&packet[..length]), 0);
    socket
        .send_to(&packet[..length], fixture.udp_addr)
        .await
        .unwrap();
    let (length, source) = tokio::time::timeout(STAGE_BOUND, socket.recv_from(&mut packet))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(source, fixture.udp_addr, "actual relay response");
    let retried = v1_long_packet_type(&packet[..length]) == 3;
    if retried {
        socket
            .send_to(&packet[..length], client_addr)
            .await
            .unwrap();
        let (length, source) = tokio::time::timeout(STAGE_BOUND, socket.recv_from(&mut packet))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(source, client_addr, "client receives actual Retry");
        assert!(
            initial_token_length(&packet[..length]) > 0,
            "token-bearing Initial"
        );
        socket
            .send_to(&packet[..length], fixture.udp_addr)
            .await
            .unwrap();
        // Wait for a real handshake response to prove the token-bearing Initial
        // reached the server. Do not forward it, so TLS remains unfinished.
        let (_, source) = tokio::time::timeout(STAGE_BOUND, socket.recv_from(&mut packet))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(source, fixture.udp_addr, "accepted validated Initial");
    }
    StalledInitial {
        _socket: socket,
        _endpoint: endpoint,
        _connecting: connecting,
        retried,
    }
}

async fn open_h3(
    fixture: &Fixture,
) -> (
    ClientEndpoint,
    quinn::Connection,
    h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    OwnedTask<h3::error::ConnectionError>,
) {
    let endpoint = fixture.quic_endpoint();
    let connection = endpoint
        .0
        .connect(fixture.udp_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let (mut driver, sender) = h3::client::builder()
        .build::<_, _, Bytes>(h3_quinn::Connection::new(connection.clone()))
        .await
        .unwrap();
    let driver = OwnedTask(tokio::spawn(async move { driver.wait_idle().await }));
    (endpoint, connection, sender, driver)
}

#[tokio::test]
async fn quic_unvalidated_initial_requires_retry_before_tls() {
    tokio::time::timeout(STAGE_BOUND, async {
        let fixture = Fixture::start(1000).await;
        let probe = stalled_initial(&fixture).await;
        assert!(
            probe.retried,
            "unvalidated Initial must receive Retry, not a TLS flight"
        );
        drop(probe);
        fixture.stop().await;
    })
    .await
    .expect("single Initial fixture deadline");
}

#[tokio::test]
async fn quic_stalled_initial_keeps_tcp_tls_capacity_available() {
    tokio::time::timeout(STAGE_BOUND, async {
        let fixture = Fixture::start(1000).await;
        let probe = stalled_initial(&fixture).await;
        let tls = tokio::time::timeout(Duration::from_millis(250), fixture.tcp_tls())
            .await
            .expect("TCP TLS progress before the QUIC admission cutoff")
            .expect("stalled QUIC handshake must not take shared established capacity");
        drop(tls);
        drop(probe);
        fixture.stop().await;
    })
    .await
    .expect("stalled Initial capacity fixture deadline");
}

#[tokio::test]
async fn quic_completed_tls_without_h3_keeps_tcp_capacity_available() {
    tokio::time::timeout(STAGE_BOUND, async {
        let fixture = Fixture::start(1000).await;
        let endpoint = fixture.quic_endpoint();
        let connection = endpoint
            .0
            .connect(fixture.udp_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let tls = tokio::time::timeout(Duration::from_millis(250), fixture.tcp_tls())
            .await
            .expect("TCP TLS progress while H3 has no request")
            .expect("completed QUIC TLS without a credential must not take shared capacity");
        drop(tls);
        connection.close(quinn::VarInt::from_u32(0), b"fixture done");
        drop(endpoint);
        fixture.stop().await;
    })
    .await
    .expect("idle H3 capacity fixture deadline");
}

#[tokio::test]
async fn quic_late_headers_close_within_client_start_bound() {
    tokio::time::timeout(STAGE_BOUND, async {
        let fixture = Fixture::start(800).await;
        let endpoint = fixture.quic_endpoint();
        let client_start = tokio::time::Instant::now();
        let connection = endpoint
            .0
            .connect(fixture.udp_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        tokio::time::sleep_until(client_start + Duration::from_millis(400)).await;
        let (mut driver, mut sender) = h3::client::builder()
            .build::<_, _, Bytes>(h3_quinn::Connection::new(connection.clone()))
            .await
            .unwrap();
        let driver = OwnedTask(tokio::spawn(async move { driver.wait_idle().await }));
        let stream = sender
            .send_request(
                http::Request::builder()
                    .method("CONNECT")
                    .uri("https://127.0.0.1:9")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        // This clock starts on the client before QUIC/Retry. Close by client
        // start+1000ms with an 800ms server admission setting is a bounded
        // composition oracle with margin, not an exact server cutoff or an
        // assertion of the server's timeout classification. No credential DATA
        // is sent; renewed per-phase waits would prolong this stalled ingress.
        tokio::time::timeout_at(
            client_start + Duration::from_millis(1000),
            connection.closed(),
        )
        .await
        .expect("late-header ingress closes within the client-origin composition bound");
        drop(stream);
        drop(sender);
        drop(driver);
        drop(endpoint);
        fixture.stop().await;
    })
    .await
    .expect("late-header composition fixture deadline");
}

#[tokio::test]
async fn quic_authenticated_tunnel_outlives_the_admission_deadline() {
    tokio::time::timeout(STAGE_BOUND, async {
        let fixture = Fixture::start(500).await;
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        let echo = OwnedTask(tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await.unwrap();
            let mut buffer = [0u8; 32];
            loop {
                let length = stream.read(&mut buffer).await.unwrap();
                if length == 0 {
                    break;
                }
                stream.write_all(&buffer[..length]).await.unwrap();
            }
        }));
        let (endpoint, connection, mut sender, driver) = open_h3(&fixture).await;
        let request = TunnelRequest {
            host: "127.0.0.1".into(),
            port: echo_port,
        };
        let mut stream = sender
            .send_request(
                http::Request::builder()
                    .method("CONNECT")
                    .uri(format!("https://127.0.0.1:{echo_port}"))
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        stream
            .send_data(Bytes::from(
                seal_tunnel_request(&request, FIXTURE_TOKEN.as_bytes()).unwrap(),
            ))
            .await
            .unwrap();
        assert!(stream.recv_response().await.unwrap().status().is_success());
        let mut ack = stream.recv_data().await.unwrap().unwrap();
        let ack = ack.copy_to_bytes(ack.remaining());
        assert_eq!(
            open_tunnel_response(&ack, FIXTURE_TOKEN.as_bytes())
                .unwrap()
                .status,
            TunnelStatus::Ok
        );
        // An actual established tunnel still owns the configured single slot.
        assert!(
            tokio::time::timeout(Duration::from_millis(250), fixture.tcp_tls())
                .await
                .expect("full established pool refuses promptly")
                .is_err()
        );
        tokio::time::sleep(Duration::from_millis(1000)).await;
        assert!(
            connection.close_reason().is_none(),
            "authorized session survives read cutoff"
        );
        stream
            .send_data(Bytes::from_static(b"after-admission-clock"))
            .await
            .unwrap();
        let mut payload = stream.recv_data().await.unwrap().unwrap();
        assert_eq!(
            &payload.copy_to_bytes(payload.remaining())[..],
            b"after-admission-clock"
        );
        connection.close(quinn::VarInt::from_u32(0), b"fixture done");
        drop(stream);
        drop(sender);
        drop(driver);
        drop(endpoint);
        drop(echo);
        fixture.stop().await;
    })
    .await
    .expect("authorized long-session fixture deadline");
}

#[tokio::test]
async fn authenticated_masque_tcp_capture_echo_uses_normal_connect_data() {
    tokio::time::timeout(Duration::from_secs(8), async {
        let fixture = Fixture::start(1000).await;
        let (endpoint, connection, mut sender, driver) = open_h3(&fixture).await;
        let target = TunnelRequest {
            host: auto_capture_probe::TCP_HOST.into(),
            port: auto_capture_probe::PORT,
        };
        let mut stream = sender
            .send_request(
                http::Request::builder()
                    .method("CONNECT")
                    .uri(format!("https://{}:{}", target.host, target.port))
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        stream
            .send_data(Bytes::from(
                seal_tunnel_request(&target, FIXTURE_TOKEN.as_bytes()).unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(stream.recv_response().await.unwrap().status(), 200);
        let mut accepted = stream.recv_data().await.unwrap().unwrap();
        let accepted = accepted.copy_to_bytes(accepted.remaining());
        assert_eq!(
            open_tunnel_response(&accepted, FIXTURE_TOKEN.as_bytes())
                .unwrap()
                .status,
            TunnelStatus::Ok
        );
        let challenge = [0x27u8; auto_capture_probe::CHALLENGE_BYTES];
        stream
            .send_data(Bytes::copy_from_slice(&challenge[..9]))
            .await
            .unwrap();
        stream
            .send_data(Bytes::copy_from_slice(&challenge[9..]))
            .await
            .unwrap();
        let mut echoed = stream.recv_data().await.unwrap().unwrap();
        assert_eq!(&echoed.copy_to_bytes(echoed.remaining())[..], challenge);
        assert!(stream.recv_data().await.unwrap().is_none());
        connection.close(quinn::VarInt::from_u32(0), b"fixture done");
        drop(stream);
        drop(sender);
        drop(driver);
        drop(endpoint);
        fixture.stop().await;
    })
    .await
    .expect("actual MASQUE TCP capture exchange deadline");
}

#[tokio::test]
async fn authenticated_masque_udp_capture_echo_survives_h3_owner_drain() {
    tokio::time::timeout(Duration::from_secs(8), async {
        let fixture = Fixture::start(1000).await;
        let endpoint = fixture.quic_endpoint();
        let connection = endpoint
            .0
            .connect(fixture.udp_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let mut builder = h3::client::builder();
        builder.enable_extended_connect(true).enable_datagram(true);
        let (h3_conn, mut sender) = builder
            .build::<_, _, Bytes>(h3_quinn::Connection::new(connection.clone()))
            .await
            .unwrap();
        let target = TunnelRequest {
            host: auto_capture_probe::UDP_HOST.into(),
            port: auto_capture_probe::PORT,
        };
        let path = build_connect_udp_path(DEFAULT_MASQUE_PATH, &target.host, target.port).unwrap();
        let credential = seal_tunnel_request(&target, FIXTURE_TOKEN.as_bytes()).unwrap();
        let mut request = http::Request::builder()
            .method("CONNECT")
            .uri(format!("https://localhost{path}"))
            .header("capsule-protocol", "?1")
            .header(
                http::header::AUTHORIZATION,
                format!("Bearer {}", hex::encode(credential)),
            )
            .body(())
            .unwrap();
        request.extensions_mut().insert(Protocol::CONNECT_UDP);
        let mut stream = sender.send_request(request).await.unwrap();
        assert_eq!(stream.recv_response().await.unwrap().status(), 200);
        let stream_id = stream.id();
        let mut datagram_sender = h3_conn.get_datagram_sender(stream_id);
        let challenge = [0x38u8; auto_capture_probe::CHALLENGE_BYTES];
        let mut packet = Vec::with_capacity(1 + challenge.len());
        packet.push(0);
        packet.extend_from_slice(&challenge);
        datagram_sender
            .send_datagram(Bytes::from(packet.clone()))
            .unwrap();
        let mut reader = h3_conn.get_datagram_reader();
        let echoed = loop {
            let datagram = reader.read_datagram().await.unwrap();
            if datagram.stream_id() == stream_id {
                break datagram.into_payload();
            }
        };
        assert_eq!(echoed.as_ref(), packet.as_slice());
        connection.close(quinn::VarInt::from_u32(0), b"fixture done");
        drop(stream);
        drop(datagram_sender);
        drop(reader);
        drop(sender);
        drop(h3_conn);
        drop(endpoint);
        fixture.stop().await;
    })
    .await
    .expect("actual MASQUE UDP capture exchange deadline");
}
