//! Actual loopback UDP dispatcher tests: pool selection and no implicit replay.
use super::*;
use aegis_server::config::{ServerConfig, TargetPolicyConfig, TargetPolicyProfile};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

struct Fixture {
    _dir: tempfile::TempDir,
    settings: RelaySettings,
    server: JoinHandle<anyhow::Result<()>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Fixture {
    async fn start() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        #[cfg(not(windows))]
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
        #[cfg(windows)]
        aegis_core::windows_file::write_private_new(
            &key_path,
            cert.key_pair.serialize_pem().as_bytes(),
            false,
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let port = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp = port.local_addr().unwrap();
        drop(port);
        let port = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp = port.local_addr().unwrap();
        drop(port);
        let mut config = ServerConfig {
            listen: tcp.to_string(),
            cert: cert_path.clone(),
            key: key_path,
            auth_token: "a22a0b4c4bcf6b5850b02bab7c02a24046df90886085389fc8350f2d311ba32b".into(),
            target_policy: TargetPolicyConfig {
                profile: TargetPolicyProfile::FullVpnEgress,
                allowed_ports: Vec::new(),
            },
            legacy_auth_tokens: Vec::new(),
            process_alias: None,
            logging: Default::default(),
            fallback: "close".into(),
            limits: Default::default(),
            rate_limit: Default::default(),
            transport: Default::default(),
            bundle_endpoint: Default::default(),
        };
        config.transport.quic_listen = Some(udp.to_string());
        let (ready_tx, ready_rx) = oneshot::channel();
        let server = tokio::spawn(aegis_server::run_server_with_shutdown(
            config,
            Some(ready_tx),
            std::future::pending(),
        ));
        tokio::time::timeout(Duration::from_secs(10), ready_rx)
            .await
            .unwrap()
            .unwrap();
        let settings = RelaySettings {
            server: tcp.to_string(),
            server_name: "localhost".into(),
            auth_token: "a22a0b4c4bcf6b5850b02bab7c02a24046df90886085389fc8350f2d311ba32b".into(),
            ca_cert: Some(cert_path),
            transport_priority: vec![TunnelTransportFamily::GrpcDatagram],
            udp_transport_priority: Some(vec![TunnelTransportFamily::GrpcDatagram]),
            masque_server: Some(udp.to_string()),
            connect_timeout_ms: 1500,
            ..Default::default()
        };
        // Prime synchronous native trust-store discovery outside timing checks.
        super::tls_connector(settings.ca_cert.as_deref(), Some(b"h2"), true).unwrap();
        Self {
            _dir: dir,
            settings,
            server,
        }
    }

    fn pool(&mut self, first: SocketAddr, second: SocketAddr) {
        self.settings.endpoints = [first, second]
            .into_iter()
            .map(|addr| RelayEndpointSettings {
                server: addr.to_string(),
                server_name: "localhost".into(),
                masque_server: None,
                masque_server_name: None,
            })
            .collect();
        // With a pool, the top-level TCP dial is deliberately unusable.
        self.settings.server = "ignored.invalid:1".into();
    }
}

#[tokio::test]
async fn udp_pool_once_uses_second_endpoint_after_pre_open_failure() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut fixture = Fixture::start().await;
        let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second = fixture.settings.server.parse().unwrap();
        fixture.pool(first.local_addr().unwrap(), second);
        let first_peer = tokio::spawn(async move {
            let (peer, _) = first.accept().await.unwrap();
            drop(peer);
        });
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            let mut buf = [0u8; 128];
            let (n, peer) = target.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"pool-once");
            target.send_to(&buf[..n], peer).await.unwrap();
        });
        let response = run_relay_udp_datagram_once(
            &fixture.settings,
            crate::socks5::ConnectTarget {
                host: "127.0.0.1".into(),
                port: target_port,
            },
            b"pool-once",
        )
        .await
        .unwrap();
        assert_eq!(response, b"pool-once");
        first_peer.await.unwrap();
        echo.await.unwrap();
    })
    .await
    .expect("bounded UDP pool once fixture");
}

#[tokio::test]
async fn udp_pool_once_never_replays_after_target_received_payload() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut fixture = Fixture::start().await;
        let first = fixture.settings.server.parse().unwrap();
        let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
        fixture.pool(first, second.local_addr().unwrap());
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let attempt = run_relay_udp_datagram_once(
            &fixture.settings,
            crate::socks5::ConnectTarget {
                host: "127.0.0.1".into(),
                port: target_port,
            },
            b"exactly-once",
        );
        let observe = async {
            let mut buf = [0u8; 128];
            let (n, _) = target.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"exactly-once");
        };
        let (result, ()) = tokio::join!(attempt, observe);
        assert!(udp_payload_was_committed(&result.unwrap_err()));
        assert!(
            tokio::time::timeout(Duration::from_millis(80), second.accept())
                .await
                .is_err()
        );
        let mut buf = [0u8; 128];
        assert!(
            tokio::time::timeout(Duration::from_millis(80), target.recv_from(&mut buf))
                .await
                .is_err()
        );
    })
    .await
    .expect("bounded no-replay fixture");
}

#[tokio::test]
async fn udp_pool_flow_keeps_queued_payload_until_second_endpoint_opens() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut fixture = Fixture::start().await;
        let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second = fixture.settings.server.parse().unwrap();
        fixture.pool(first.local_addr().unwrap(), second);
        let first_peer = tokio::spawn(async move {
            let (peer, _) = first.accept().await.unwrap();
            drop(peer);
        });
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            let mut buf = [0u8; 128];
            let (n, peer) = target.recv_from(&mut buf).await.unwrap();
            target.send_to(&buf[..n], peer).await.unwrap();
        });
        let (tx, rx) = mpsc::channel(4);
        let (incoming, mut received) = mpsc::channel(4);
        tx.send(b"queued-flow".to_vec()).await.unwrap();
        let flow = run_relay_udp_flow(&fixture.settings, "127.0.0.1", target_port, rx, incoming);
        let observe = async {
            let response = received.recv().await.unwrap();
            assert_eq!(response.payload, b"queued-flow");
            assert_eq!(response.target.port, target_port);
            drop(tx);
        };
        let (result, ()) = tokio::join!(flow, observe);
        result.unwrap();
        first_peer.await.unwrap();
        echo.await.unwrap();
    })
    .await
    .expect("bounded UDP pool flow fixture");
}

#[tokio::test]
async fn udp_pool_associate_target_falls_back_between_masque_endpoints_before_payload() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut fixture = Fixture::start().await;
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second = fixture.settings.masque_server.clone().unwrap();
        fixture.settings.udp_transport_priority = Some(vec![TunnelTransportFamily::MasqueDerived]);
        fixture.settings.masque_server = None;
        fixture.settings.endpoints = [silent.local_addr().unwrap().to_string(), second]
            .into_iter()
            .map(|addr| RelayEndpointSettings {
                server: "127.0.0.1:1".into(),
                server_name: "localhost".into(),
                masque_server: Some(addr),
                masque_server_name: None,
            })
            .collect();
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            let mut buf = [0u8; 128];
            let (n, peer) = target.recv_from(&mut buf).await.unwrap();
            target.send_to(&buf[..n], peer).await.unwrap();
        });
        let (tx, mut rx) = mpsc::channel(4);
        let (incoming, mut received) = mpsc::channel(4);
        tx.send(b"associate-flow".to_vec()).await.unwrap();
        let flow = run_relay_udp_associate_flow(
            fixture.settings.clone(),
            crate::socks5::ConnectTarget {
                host: "127.0.0.1".into(),
                port: target_port,
            },
            &mut rx,
            &incoming,
        );
        let observe = async {
            assert_eq!(received.recv().await.unwrap().payload, b"associate-flow");
            drop(tx);
        };
        let (result, ()) = tokio::join!(flow, observe);
        result.unwrap();
        echo.await.unwrap();
    })
    .await
    .expect("bounded UDP ASSOCIATE pool fixture");
}
