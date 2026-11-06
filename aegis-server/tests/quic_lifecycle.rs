use aegis_server::config::ServerConfig;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;

const STAGE_BOUND: Duration = Duration::from_secs(3);

struct OwnedTask<T>(JoinHandle<T>);

impl<T> Drop for OwnedTask<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Clone, Copy)]
enum StopMode {
    GraceExpiry,
    ZeroGrace,
    PeerAlreadyClosed,
    ServerTaskCancelled,
}

async fn assert_quic_shutdown_releases_listener(mode: StopMode) {
    tokio::time::timeout(Duration::from_secs(10), async {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().expect("fixture directory");
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).expect("fixture certificate");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, cert.pem()).expect("write fixture certificate");
        std::fs::write(&key_path, key_pair.serialize_pem()).expect("write fixture key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let tcp_reservation = TcpListener::bind("127.0.0.1:0").await.expect("reserve TCP");
        let tcp_addr = tcp_reservation.local_addr().expect("fixture TCP address");
        let udp_reservation = UdpSocket::bind("127.0.0.1:0").await.expect("reserve UDP");
        let udp_addr = udp_reservation.local_addr().expect("fixture UDP address");
        let mut cfg = ServerConfig {
            listen: tcp_addr.to_string(),
            cert: cert_path,
            key: key_path,
            auth_token: "c45f2e1896446efda285dd9ae8420da0980fd9d83569f8b0ef15cbda6afaa907".into(),
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
        cfg.limits.shutdown_grace_ms = if matches!(mode, StopMode::ZeroGrace) {
            0
        } else {
            200
        };
        cfg.limits.read_timeout_ms = 30_000;
        cfg.transport.quic_listen = Some(udp_addr.to_string());
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        drop(tcp_reservation);
        drop(udp_reservation);
        let mut server = OwnedTask(tokio::spawn(aegis_server::run_server_with_shutdown(
            cfg,
            Some(ready_tx),
            async {
                let _ = shutdown_rx.await;
            },
        )));
        tokio::time::timeout(STAGE_BOUND, ready_rx)
            .await
            .expect("server ready deadline")
            .expect("server ready signal");

        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(cert.der().clone())
            .expect("trust fixture certificate");
        let mut crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        crypto.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .expect("QUIC fixture TLS config");
        let mut endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("QUIC fixture endpoint");
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
        let client_addr = endpoint.local_addr().expect("client endpoint address");
        let connection = tokio::time::timeout(
            STAGE_BOUND,
            endpoint
                .connect(udp_addr, "localhost")
                .expect("start fixture connection"),
        )
        .await
        .expect("QUIC connection deadline")
        .expect("QUIC connection");
        // Hold an established peer open across shutdown. The runtime remains
        // alive: runtime destruction must not hide an endpoint-driver socket.
        assert!(connection.close_reason().is_none());
        if matches!(mode, StopMode::PeerAlreadyClosed) {
            connection.close(quinn::VarInt::from_u32(0), b"fixture peer completed");
        }
        let start = tokio::time::Instant::now();
        if matches!(mode, StopMode::ServerTaskCancelled) {
            server.0.abort();
            assert!(tokio::time::timeout(STAGE_BOUND, &mut server.0)
                .await
                .expect("server cancellation deadline")
                .expect_err("server task cancelled")
                .is_cancelled());
        } else {
            shutdown_tx.send(()).expect("request shutdown");
            tokio::time::timeout(STAGE_BOUND, &mut server.0)
                .await
                .expect("server shutdown deadline")
                .expect("join server")
                .expect("server shutdown");
        }
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "shutdown grace stays bounded"
        );
        TcpListener::bind(tcp_addr)
            .await
            .expect("TCP listener released after shutdown");
        if matches!(mode, StopMode::ServerTaskCancelled) {
            // An asynchronously cancelled API cannot await in Drop. Give its
            // owned task aborts a scheduler turn, keeping this runtime alive.
            tokio::time::timeout(STAGE_BOUND, async {
                loop {
                    match UdpSocket::bind(udp_addr).await {
                        Ok(socket) => break socket,
                        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                            tokio::task::yield_now().await;
                        }
                        Err(error) => panic!("rebind after cancellation: {error:?}"),
                    }
                }
            })
            .await
            .expect("cancelled QUIC owner releases listener");
        } else {
            // Normal and forced-grace shutdown must join teardown before
            // returning, rather than leave a delayed protocol-draining task.
            UdpSocket::bind(udp_addr)
                .await
                .expect("active QUIC listener released after shutdown");
        }
        assert_eq!(
            UdpSocket::bind(client_addr)
                .await
                .expect_err("unrelated client endpoint stays bound")
                .kind(),
            std::io::ErrorKind::AddrInUse,
            "server teardown must not release an unrelated endpoint socket",
        );
        // Binding alone would not prove the unrelated client driver is live:
        // its endpoint handle can retain a socket after a driver is aborted.
        // Establish a new connection through it to an independent fixture.
        let mut independent_tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into(),
            )
            .expect("independent fixture TLS");
        independent_tls.alpn_protocols = vec![b"h3".to_vec()];
        let independent_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(independent_tls)
            .expect("independent fixture QUIC config");
        let independent = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(independent_crypto)),
            udp_addr,
        )
        .expect("independent endpoint reuses released server socket");
        let reconnecting = endpoint
            .connect(udp_addr, "localhost")
            .expect("reuse unrelated client");
        let (reconnected, accepted) = tokio::time::timeout(STAGE_BOUND, async {
            tokio::join!(reconnecting, async {
                independent
                    .accept()
                    .await
                    .expect("independent incoming")
                    .await
            },)
        })
        .await
        .expect("unrelated endpoint driver remains functional");
        reconnected
            .expect("unrelated client reconnects")
            .close(quinn::VarInt::from_u32(0), b"fixture complete");
        accepted
            .expect("independent endpoint completes handshake")
            .close(quinn::VarInt::from_u32(0), b"fixture complete");
        independent.close(quinn::VarInt::from_u32(0), b"fixture complete");
        connection.close(quinn::VarInt::from_u32(0), b"fixture complete");
        endpoint.close(quinn::VarInt::from_u32(0), b"fixture complete");
    })
    .await
    .expect("QUIC lifecycle test deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn active_quic_shutdown_releases_listener_in_same_runtime() {
    assert_quic_shutdown_releases_listener(StopMode::GraceExpiry).await;
}

#[tokio::test]
async fn active_quic_zero_grace_still_joins_socket_owners() {
    assert_quic_shutdown_releases_listener(StopMode::ZeroGrace).await;
}

#[tokio::test]
async fn completed_quic_peer_shutdown_releases_listener_in_same_runtime() {
    assert_quic_shutdown_releases_listener(StopMode::PeerAlreadyClosed).await;
}

#[tokio::test]
async fn cancelled_server_releases_active_quic_listener_without_runtime_drop() {
    assert_quic_shutdown_releases_listener(StopMode::ServerTaskCancelled).await;
}
