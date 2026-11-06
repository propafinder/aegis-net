//! Installed-product path through a CDN-like edge (carrier program D1):
//! public four-file profile -> device prepare -> online redeem and renewal on
//! the same public authority/port ("variant B") -> rendered client settings
//! -> relay TCP and grpc_datagram UDP, all through the edge to a fronted
//! origin with inner device mTLS. Refusals cover the direct origin and an
//! edge that fails before identity.

use crate::test_cdn_edge as cdn;

use super::*;
use std::sync::atomic::Ordering;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ORIGIN_KEY: [u8; 64] = [b'4'; 64];

impl Fixture {
    /// Fronted origin: exclusive inner TLS, CDN key gate, same-port
    /// enrollment forwarding to the authority listener.
    async fn fronted_relay(&self) -> Server {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let origin_key = self._dir.path().join("origin-pull.key");
        if !origin_key.exists() {
            enrollment::write_private_new(&origin_key, &ORIGIN_KEY).unwrap();
        }
        let cfg: aegis_server::config::ServerConfig = serde_json::from_value(serde_json::json!({
            "listen": self.relay_address.to_string(),
            "cert": self.config.outer_cert, "key": self.config.outer_key, "auth_token": "",
            "rate_limit": {"trusted_proxy_cidrs": ["127.0.0.1/32"]},
            "limits": {"shutdown_grace_ms": 500},
            "target_policy": {"profile": "full_vpn_egress"},
            "transport": {"quic_required": false,
                "inner_tls": {
                    "cert": self.config.outer_cert, "key": self.config.outer_key,
                    "client_ca": self.config.issuer.ca_cert,
                    "device_registry": self.config.issuer.registry,
                    "handshake_timeout_ms": 3000, "idle_timeout_ms": 3000
                },
                "fronted_origin": {
                    "authority": "front.test",
                    "credential_file": origin_key,
                    "enrollment_forward": {
                        "authority_address": self.config.listen.to_string(),
                        "server_name": "enroll.test",
                        "ca": self.config.issuer.ca_cert
                    }
                }
            }
        }))
        .unwrap();
        cfg.validate_auth_tokens().unwrap();
        let (ready_tx, ready_rx) = oneshot::channel();
        let (stop, stopped) = oneshot::channel();
        let mut task = tokio::spawn(aegis_server::run_server_with_shutdown(
            cfg,
            Some(ready_tx),
            async {
                let _ = stopped.await;
            },
        ));
        if tokio::time::timeout(Duration::from_secs(5), ready_rx)
            .await
            .unwrap()
            .is_err()
        {
            panic!("fronted relay startup failed: {:?}", (&mut task).await);
        }
        Server {
            stop: Some(stop),
            task,
        }
    }

    async fn edge(&self, faults: cdn::Faults) -> cdn::Edge {
        cdn::start(cdn::EdgeConfig {
            listen: self.edge_address,
            edge_cert_pem: fs::read_to_string(&self.config.outer_cert).unwrap(),
            edge_key_pem: fs::read_to_string(&self.config.outer_key).unwrap(),
            origin: self.relay_address,
            origin_server_name: "front.test".into(),
            origin_ca_pem: fs::read_to_string(&self.config.issuer.ca_cert).unwrap(),
            origin_key: Some(ORIGIN_KEY.to_vec()),
            faults,
        })
        .await
    }
}

async fn local_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let app = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (client, _) = listener.accept().await.unwrap();
    (app, client)
}

async fn tcp_echo() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buffer = vec![0; 32 * 1024];
                loop {
                    let n = socket.read(&mut buffer).await.unwrap_or(0);
                    if n == 0 {
                        let _ = socket.shutdown().await;
                        return;
                    }
                    if socket.write_all(&buffer[..n]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (address, task)
}

/// One relayed TCP session through the product relay entry point.
async fn tcp_round_trip(
    settings: &aegis_core::RelaySettings,
    target: std::net::SocketAddr,
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let (mut app, client) = local_pair().await;
    let relay_settings = settings.clone();
    let relay = tokio::spawn(async move {
        crate::relay::run_relay_tunnel(
            client,
            &relay_settings,
            target.ip().to_string(),
            target.port(),
            None,
            None,
            None,
        )
        .await
    });
    app.write_all(payload).await?;
    app.shutdown().await?;
    let mut received = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(10), app.read_to_end(&mut received)).await;
    let relay_result = tokio::time::timeout(Duration::from_secs(10), relay).await??;
    relay_result?;
    read??;
    Ok(received)
}

async fn udp_round_trip(settings: &aegis_core::RelaySettings) {
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    let echo = tokio::spawn(async move {
        let mut buffer = vec![0; 65_535];
        for _ in 0..3 {
            let (length, source) = target.recv_from(&mut buffer).await.unwrap();
            target.send_to(&buffer[..length], source).await.unwrap();
        }
    });
    let (outbound, rx) = tokio::sync::mpsc::channel(2);
    let (tx, mut inbound) = tokio::sync::mpsc::channel(2);
    let relay_settings = settings.clone();
    let flow = tokio::spawn(async move {
        crate::relay::run_relay_udp_flow(&relay_settings, "127.0.0.1", port, rx, tx).await
    });
    for expected in [vec![], b"fronted grpc_datagram".to_vec(), vec![0x5a; 4096]] {
        outbound.send(expected.clone()).await.unwrap();
        let received = tokio::time::timeout(Duration::from_secs(10), inbound.recv())
            .await
            .unwrap()
            .expect("UDP reply through the CDN edge");
        assert_eq!(received.payload, expected);
    }
    drop(outbound);
    tokio::time::timeout(Duration::from_secs(10), flow)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    echo.await.unwrap();
}

#[tokio::test]
async fn fronted_profile_redeems_and_relays_tcp_and_udp_only_through_the_cdn_edge() {
    let f = Fixture::new_fronted().await;
    let key = f.key();
    let authority = f.server().await;
    let relay = f.fronted_relay().await;
    let edge = f.edge(cdn::Faults::default()).await;

    // Online redeem: device -> edge -> fronted origin -> forwarder -> authority.
    redeem(&RedeemArgs {
        identity_dir: f.identity.clone(),
        bundle_dir: f.bundle.clone(),
        invitation_file: Some(f.invitation.clone()),
    })
    .await
    .unwrap();
    assert_eq!(f.key(), key, "same device key, issued through the edge");
    let status = store::online_status(&f.identity, registry::unix_now().unwrap()).unwrap();
    assert_eq!(status.state, "ready");
    // The running relay authorizes the newly issued certificate after its
    // one-second dynamic registry refresh; never before.
    tokio::time::sleep(Duration::from_millis(2500)).await;

    // Rendered product settings point at the edge, never the origin.
    let settings = f.settings();
    assert_eq!(settings.relay.server, f.edge_address.unwrap().to_string());
    assert_eq!(settings.relay.server_name, "front.test");
    settings.relay.validate_inner_tls_transport().unwrap();

    let (target, _echo) = tcp_echo().await;
    let payload: Vec<u8> = (0..96 * 1024).map(|i| (i * 13 % 253) as u8).collect();
    let received = tcp_round_trip(&settings.relay, target, &payload)
        .await
        .unwrap();
    assert!(received == payload, "exact TCP echo through the CDN edge");
    udp_round_trip(&settings.relay).await;
    assert!(edge.stats.streams.load(Ordering::SeqCst) >= 3);
    assert!(edge.stats.origin_trailers.load(Ordering::SeqCst) >= 1);

    // The origin itself refuses a device that bypasses the CDN: the decoy
    // arrives before any device identity is sent, so it is a pre-auth outage.
    let mut direct = settings.relay.clone();
    direct.server = f.relay_address.to_string();
    let error = tcp_round_trip(&direct, target, b"bypass")
        .await
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("secure carrier rejected with HTTP 4"),
        "{error:#}"
    );

    relay.stop().await;
    authority.stop().await;
}

#[tokio::test]
async fn fronted_due_renewal_uses_the_same_public_authority_and_port() {
    let f = Fixture::new_fronted().await;
    f.install_due_predecessor().await;
    let before = store::online_status(&f.identity, registry::unix_now().unwrap()).unwrap();
    let key = f.key();
    let old_certificate = fs::read(f.identity.join("device.pem")).unwrap();
    let authority = f.server().await;
    let relay = f.fronted_relay().await;
    let edge = f.edge(cdn::Faults::default()).await;
    renew(&RenewArgs {
        identity_dir: f.identity.clone(),
        bundle_dir: f.bundle.clone(),
        if_due: true,
    })
    .await
    .unwrap();
    let after = store::online_status(&f.identity, registry::unix_now().unwrap()).unwrap();
    assert!(after.not_after_unix_secs > before.not_after_unix_secs);
    assert!(!after.pending && !after.renewal_due);
    assert_ne!(
        fs::read(f.identity.join("device.pem")).unwrap(),
        old_certificate
    );
    assert_eq!(f.key(), key);
    assert!(edge.stats.streams.load(Ordering::SeqCst) >= 1);
    // The renewed certificate carries traffic through the same edge once the
    // running relay's one-second registry refresh has observed it.
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let settings = f.settings();
    let (target, _echo) = tcp_echo().await;
    assert_eq!(
        tcp_round_trip(&settings.relay, target, b"after renewal")
            .await
            .unwrap(),
        b"after renewal"
    );
    relay.stop().await;
    authority.stop().await;
}

#[tokio::test]
async fn edge_failure_before_identity_keeps_the_request_and_never_reaches_the_origin() {
    let f = Fixture::new_fronted().await;
    let authority = f.server().await;
    let relay = f.fronted_relay().await;
    // An edge that cannot reach its origin (as with a 521) answers itself.
    let edge = f
        .edge(cdn::Faults {
            status_without_origin: Some(521),
            ..Default::default()
        })
        .await;
    let registry_before = fs::read(&f.config.issuer.registry).unwrap();
    let result = redeem(&RedeemArgs {
        identity_dir: f.identity.clone(),
        bundle_dir: f.bundle.clone(),
        invitation_file: Some(f.invitation.clone()),
    })
    .await;
    assert!(result.is_err());
    assert_eq!(edge.stats.origin_connections.load(Ordering::SeqCst), 0);
    assert_eq!(
        fs::read(&f.config.issuer.registry).unwrap(),
        registry_before
    );
    assert!(
        f.identity.join("online-request.json").exists(),
        "the local request is retained for an exact resume"
    );
    drop(edge);
    // The same retained request completes once the edge recovers.
    let _edge = f.edge(cdn::Faults::default()).await;
    redeem(&RedeemArgs {
        identity_dir: f.identity.clone(),
        bundle_dir: f.bundle.clone(),
        invitation_file: None,
    })
    .await
    .unwrap();
    relay.stop().await;
    authority.stop().await;
}
