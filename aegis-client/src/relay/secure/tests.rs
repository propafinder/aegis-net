use super::*;
use aegis_core::https_bridge::KEY_HEADER;

#[tokio::test]
async fn signed_enrolled_quic_reaches_device_target_with_reverse_fin() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    use crate::carrier::local_auth_tests::{toml_path, IdentityFixture, Tasks};
    use aegis_core::carrier_program::{CarrierProgramSettings, CarrierRoute};
    use aegis_core::{RelayEndpointSettings, RelayTlsBackend, TunnelTransportFamily};
    let fixture = IdentityFixture::new().unwrap();
    let mut targets = Tasks::default();
    let (target, opens) = fixture.target(&mut targets).await.unwrap();
    let config = format!(
        "listen = '127.0.0.1:0'\ncert = {}\nkey = {}\nfallback = 'close'\n[limits]\nread_timeout_ms = 5000\nwrite_timeout_ms = 2000\nshutdown_grace_ms = 2000\n[target_policy]\nprofile = 'full_vpn_egress'\n[rate_limit]\nenabled = false\n[transport]\nsecure_quic_authority = 'device.aegis.invalid:443'\n[transport.inner_tls]\ncert = {}\nkey = {}\nclient_ca = {}\nallowed_client_sha256 = ['{}']\n",
        toml_path(&fixture.outer_ca), toml_path(&fixture.outer_key),
        toml_path(&fixture.directory.path().join("inner.test.pem")),
        toml_path(&fixture.directory.path().join("inner.test.key")),
        toml_path(&fixture.directory.path().join("inner-ca.pem")),
        fixture.client_digest,
    );
    let cfg: aegis_server::config::ServerConfig = toml::from_str(&config).unwrap();
    cfg.validate_auth_tokens().unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(aegis_server::run_server_with_bound_ready_and_shutdown(
        cfg,
        ready_tx,
        async move {
            let _ = stop_rx.await;
        },
    ));
    let address = tokio::time::timeout(std::time::Duration::from_secs(5), ready_rx)
        .await
        .unwrap()
        .unwrap();
    // An unauthenticated scanner cannot complete QUIC TLS, much less receive
    // the special H3 200, without an issued device certificate.
    let roots = aegis_core::secure_channel::load_trust_roots(&fixture.outer_ca).unwrap();
    let mut no_cert = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    no_cert.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(no_cert).unwrap();
    let mut probe = quinn::Endpoint::client("[::]:0".parse().unwrap()).unwrap();
    probe.set_default_client_config(quinn::ClientConfig::new(std::sync::Arc::new(crypto)));
    // A QUIC client may report its half of TLS established before the server
    // finishes client-certificate verification. Assert the observable H3
    // boundary: no unauthenticated CONNECT can receive the enrolled 200.
    let no_cert_response = tokio::time::timeout(std::time::Duration::from_secs(4), async {
        let conn = probe.connect(address, "site.test")?.await?;
        let quic = h3_quinn::Connection::new(conn);
        let (_owner, mut requests) = h3::client::builder()
            .build::<_, _, bytes::Bytes>(quic)
            .await?;
        let request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(format!(
                "https://{}",
                aegis_core::carrier_program::SECURE_QUIC_AUTHORITY
            ))
            .body(())?;
        let mut stream = requests.send_request(request).await?;
        anyhow::Ok(stream.recv_response().await?.status())
    })
    .await;
    assert!(!matches!(no_cert_response, Ok(Ok(http::StatusCode::OK))));
    assert_eq!(opens.load(std::sync::atomic::Ordering::SeqCst), 0);
    probe.close(quinn::VarInt::from_u32(0), b"fixture done");
    let mut relay = aegis_core::RelaySettings {
        server: "127.0.0.1:9".into(),
        server_name: "site.test".into(),
        ..Default::default()
    };
    relay.auth_token.clear();
    relay.ca_cert = Some(fixture.outer_ca.clone());
    relay.tls_backend = RelayTlsBackend::Rustls;
    relay.transport_priority = vec![TunnelTransportFamily::GrpcStream];
    relay.udp_transport_priority = Some(Vec::new());
    relay.inner_tls = Some(fixture.client.clone());
    relay.endpoints = vec![
        RelayEndpointSettings {
            server: relay.server.clone(),
            server_name: relay.server_name.clone(),
            masque_server: None,
            masque_server_name: None,
        },
        RelayEndpointSettings {
            server: address.to_string(),
            server_name: "site.test".into(),
            masque_server: None,
            masque_server_name: None,
        },
    ];
    relay.carrier_program = Some(CarrierProgramSettings {
        routes: vec![
            CarrierRoute {
                channel: CarrierChannel::DirectH2,
                endpoint_index: 0,
            },
            CarrierRoute {
                channel: CarrierChannel::MasqueQuic,
                endpoint_index: 1,
            },
        ],
        bridge: None,
        web_response: None,
        ech_scope: None,
        fronted_ech_authority: None,
    });
    relay.validate_inner_tls_transport().unwrap();
    let selected = aegis_client::relay_endpoint_policy::effective_relay_endpoints(&relay);
    let quic =
        aegis_client::relay_endpoint_policy::relay_settings_for_endpoint(&relay, &selected[1]);
    // This leaf has the same issuing CA and passes outer mTLS, but is absent
    // from the current inner allowlist. It must see no enrolled H3 200 and
    // cannot open the target.
    let mut unlisted = quic.clone();
    unlisted.inner_tls = Some(fixture.unlisted_client.clone());
    let unlisted_established = std::sync::atomic::AtomicBool::new(false);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_secs(8),
            super::outer_enrolled_quic(&unlisted, &unlisted_established),
        )
        .await
        .unwrap()
        .is_err(),
        "same-issuer unlisted leaf must not receive H3 200"
    );
    assert_eq!(opens.load(std::sync::atomic::Ordering::SeqCst), 0);
    let foreign = IdentityFixture::new().unwrap();
    let mut refused = quic.clone();
    let mut wrong_device = foreign.client.clone();
    wrong_device.server_ca = fixture.client.server_ca.clone();
    refused.inner_tls = Some(wrong_device);
    assert!(tokio::time::timeout(
        std::time::Duration::from_secs(8),
        super::open_with_endpoint(
            &refused,
            target.ip().to_string(),
            target.port(),
            aegis_core::secure_channel::Transport::Tcp,
            None,
            selected[1].channel
        ),
    )
    .await
    .unwrap()
    .is_err());
    assert_eq!(opens.load(std::sync::atomic::Ordering::SeqCst), 0);
    let (mut stream, driver) = tokio::time::timeout(
        std::time::Duration::from_secs(8),
        super::open_with_endpoint(
            &quic,
            target.ip().to_string(),
            target.port(),
            aegis_core::secure_channel::Transport::Tcp,
            None,
            selected[1].channel,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    stream.write_all(b"local-auth-uplink").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut reply = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut reply),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(reply, b"local-auth-downlink");
    assert_eq!(opens.load(std::sync::atomic::Ordering::SeqCst), 1);
    drop(stream);
    drop(driver);
    let _ = stop_tx.send(());
    tokio::time::timeout(std::time::Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn signed_web_response_reaches_device_target_and_keeps_reverse_half_close() {
    use crate::carrier::local_auth_tests::{Harness, IdentityFixture};
    use aegis_core::{
        carrier_program::CarrierChannel, web_response_profile::WebResponseSettings,
        TunnelTransportFamily,
    };
    let fixture = IdentityFixture::new().unwrap();
    let mut harness = Harness::new(&fixture, 5000).await.unwrap();
    let (target, opens) = harness.target(&fixture).await.unwrap();
    let mut relay = aegis_core::RelaySettings {
        server: harness.bootstrap().to_string(),
        server_name: "site.test".into(),
        ..Default::default()
    };
    relay.auth_token.clear();
    relay.ca_cert = Some(fixture.outer_ca.clone());
    relay.tls_backend = aegis_core::RelayTlsBackend::Rustls;
    relay.transport_priority = vec![TunnelTransportFamily::GrpcStream];
    relay.udp_transport_priority = Some(Vec::new());
    relay.inner_tls = Some(fixture.client.clone());
    relay.web_response = Some(WebResponseSettings {
        authority: "site.test".into(),
        descriptor_path: "/private/descriptor".into(),
        allowed_ingress_ips: vec!["127.0.0.1".parse().unwrap()],
        credential_file: fixture.admission_file.clone(),
    });
    let (mut stream, _driver) = tokio::time::timeout(
        std::time::Duration::from_secs(8),
        super::open_with_endpoint(
            &relay,
            target.ip().to_string(),
            target.port(),
            aegis_core::secure_channel::Transport::Tcp,
            None,
            Some(CarrierChannel::WebResponse),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    stream.write_all(b"local-auth-uplink").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut reply = [0; 19];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_exact(&mut reply),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&reply, b"local-auth-downlink");
    assert_eq!(opens.load(std::sync::atomic::Ordering::SeqCst), 1);
    drop(stream);
    harness.finish().await.unwrap();
}
use aegis_core::{IngressPrimary, Mode, Settings, TunnelTransportFamily};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use tokio::net::TcpListener;

#[test]
fn explicit_outer_roots_contain_only_the_configured_bundle() {
    let directory = tempfile::tempdir().unwrap();
    let explicit = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let unrelated_native_like =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let bundle = directory.path().join("outer-ca.pem");
    std::fs::write(&bundle, explicit.cert.pem()).unwrap();
    let unrelated = directory.path().join("native-like-ca.pem");
    std::fs::write(&unrelated, unrelated_native_like.cert.pem()).unwrap();

    let settings = RelaySettings {
        ca_cert: Some(bundle),
        ..RelaySettings::default()
    };
    let roots = explicit_outer_roots(&settings).unwrap();
    let unrelated_roots = aegis_core::secure_channel::load_trust_roots(&unrelated).unwrap();

    assert_eq!(roots.len(), 1, "native roots must not be added implicitly");
    assert_eq!(unrelated_roots.len(), 1);
    assert_ne!(roots.roots, unrelated_roots.roots);
}

fn write_key(path: &Path, key: &KeyPair) {
    #[cfg(windows)]
    aegis_core::windows_file::write_private_new(path, key.serialize_pem().as_bytes(), false)
        .unwrap();
    #[cfg(not(windows))]
    std::fs::write(path, key.serialize_pem()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

pub(crate) fn configs(dir: &Path, address: &str) -> (Settings, aegis_server::config::ServerConfig) {
    let outer = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let outer_cert = dir.join("outer.pem");
    let outer_key = dir.join("outer.key");
    std::fs::write(&outer_cert, outer.cert.pem()).unwrap();
    write_key(&outer_key, &outer.key_pair);
    let mut ca_params = CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let ca_path = dir.join("inner-ca.pem");
    std::fs::write(&ca_path, ca.pem()).unwrap();
    let mut identity = Vec::new();
    for (name, usage) in [
        ("inner.test", ExtendedKeyUsagePurpose::ServerAuth),
        ("device.test", ExtendedKeyUsagePurpose::ClientAuth),
    ] {
        let mut params = CertificateParams::new(vec![name.into()]).unwrap();
        params.extended_key_usages = vec![usage];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let cert = params.signed_by(&key, &ca, &ca_key).unwrap();
        let cert_path = dir.join(format!("{name}.pem"));
        let key_path = dir.join(format!("{name}.key"));
        std::fs::write(&cert_path, cert.pem()).unwrap();
        write_key(&key_path, &key);
        identity.push((
            cert_path,
            key_path,
            hex::encode(Sha256::digest(cert.der().as_ref())),
        ));
    }
    let server: aegis_server::config::ServerConfig = toml::from_str(&format!(
        r#"
listen = '{address}'
cert = '{}'
key = '{}'
auth_token = '9cb2a1e3cb2bd80614253904098241f819eae687c4b0c15c30384a1dfa2e7189'
[target_policy]
profile = 'full_vpn_egress'
[transport]
quic_required = false
[transport.inner_tls]
cert = '{}'
key = '{}'
client_ca = '{}'
allowed_client_sha256 = ['{}']
handshake_timeout_ms = 3000
idle_timeout_ms = 3000
"#,
        outer_cert.display(),
        outer_key.display(),
        identity[0].0.display(),
        identity[0].1.display(),
        ca_path.display(),
        identity[1].2
    ))
    .unwrap();
    let mut settings = Settings {
        mode: Mode::Relay,
        ..Settings::default()
    };
    settings.ingress.primary = IngressPrimary::Socks5;
    settings.relay.server = address.into();
    settings.relay.server_name = "localhost".into();
    settings.relay.ca_cert = Some(outer_cert);
    settings.relay.transport_priority = vec![TunnelTransportFamily::GrpcStream];
    settings.relay.udp_transport_priority = Some(vec![]);
    settings.relay.connect_timeout_ms = 3000;
    settings.relay.tls_backend = aegis_core::RelayTlsBackend::Rustls;
    settings.relay.inner_tls = Some(secure_channel::ClientSettings {
        server_name: "inner.test".into(),
        server_ca: ca_path,
        cert: identity[1].0.clone(),
        key: identity[1].1.clone(),
    });
    (settings, server)
}

async fn local_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let app = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (client, _) = listener.accept().await.unwrap();
    (app, client)
}

#[tokio::test]
async fn https_bridge_sends_exact_gate_after_outer_tls_and_no_inner_bytes_on_rejection() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut settings, server) = configs(dir.path(), &listener.local_addr().unwrap().to_string());
    let credential = dir.path().join("bridge-credential");
    secure_channel::enrollment::write_private_new(&credential, &[b'a'; 64]).unwrap();
    settings.relay.https_bridge = Some(aegis_core::https_bridge::ClientSettings {
        authority: "localhost".into(),
        path: "/private/stream".into(),
        enrollment_path: "/private/enroll".into(),
        credential_file: credential,
    });
    let tls = aegis_server::tls::load_server_config(&server.cert, &server.key).unwrap();
    let edge = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = tokio_rustls::TlsAcceptor::from(tls)
            .accept(tcp)
            .await
            .unwrap();
        assert!(tls.get_ref().1.peer_certificates().is_none());
        let mut connection = h2::server::handshake(tls).await.unwrap();
        let (request, mut response) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.uri().authority().unwrap().as_str(), "localhost");
        assert_eq!(request.uri().path(), "/private/stream");
        assert_eq!(request.headers().get_all(KEY_HEADER).iter().count(), 1);
        assert!(request.headers().get(KEY_HEADER).unwrap().as_bytes() == [b'a'; 64]);
        assert!(!request.headers().contains_key("authorization"));
        response
            .send_response(
                http::Response::builder().status(404).body(()).unwrap(),
                true,
            )
            .unwrap();
        let mut body = request.into_body();
        let (data, _) = tokio::join!(body.data(), async {
            let _ = std::future::poll_fn(|cx| connection.poll_closed(cx)).await;
        });
        assert!(!matches!(data, Some(Ok(bytes)) if !bytes.is_empty()));
    });
    let marker = AtomicBool::new(false);
    let error = outer_grpc(
        &settings.relay,
        explicit_outer_tls(&settings.relay).unwrap(),
        &marker,
        Purpose::Traffic,
    )
    .await
    .err()
    .unwrap();
    assert!(marker.load(Ordering::Relaxed));
    assert!(retryable_pre_auth_failure(&error));
    tokio::time::timeout(std::time::Duration::from_secs(5), edge)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn https_bridge_local_credential_failure_is_terminal_before_dial() {
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut settings, _) = configs(dir.path(), &listener.local_addr().unwrap().to_string());
    settings.relay.https_bridge = Some(aegis_core::https_bridge::ClientSettings {
        authority: "localhost".into(),
        path: "/private/stream".into(),
        enrollment_path: "/private/enroll".into(),
        credential_file: dir.path().join("missing-credential"),
    });
    let marker = AtomicBool::new(false);
    let error = outer_grpc(
        &settings.relay,
        explicit_outer_tls(&settings.relay).unwrap(),
        &marker,
        Purpose::Traffic,
    )
    .await
    .err()
    .unwrap();
    assert!(!retryable_pre_auth_failure(&error));
    assert!(!marker.load(Ordering::Relaxed));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
}

fn shaping_profile() -> aegis_core::carrier_runtime::PrivacySettings {
    aegis_core::carrier_runtime::PrivacySettings {
        payload_bytes: 4096,
        cadence_ms: 1,
        buffer_bytes: 16_384,
        max_wire_bytes: 64 * 1024 * 1024,
        io_timeout_ms: 250,
        session_timeout_ms: 30_000,
        max_queue_delay_ms: 2000,
        poisson_pacing: None,
        net_shaper: None,
        adaptive_channel: None,
        arrival_envelope: None,
        cover_stream: None,
        bit_traps: None,
        liu_channel: None,
    }
}

async fn udp_fixture(dir: &Path) -> (Settings, Driver) {
    udp_fixture_with_shaping(dir, false).await
}

async fn udp_fixture_with_shaping(dir: &Path, shaping: bool) -> (Settings, Driver) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = reservation.local_addr().unwrap().to_string();
    let (mut settings, mut server) = configs(dir, &address);
    if shaping {
        settings.relay.authenticated_shaping = Some(shaping_profile());
        server.transport.authenticated_shaping = Some(shaping_profile());
    }
    settings.relay.udp_transport_priority = Some(vec![TunnelTransportFamily::GrpcDatagram]);
    drop(reservation);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let server = Driver(tokio::spawn(async move {
        aegis_server::run_server_with_shutdown(server, Some(ready_tx), std::future::pending())
            .await
            .unwrap();
    }));
    tokio::time::timeout(std::time::Duration::from_secs(5), ready_rx)
        .await
        .unwrap()
        .unwrap();
    (settings, server)
}

#[tokio::test]
async fn inner_tls_udp_flow_preserves_empty_large_and_multiple_datagrams() {
    assert_udp_flow(false).await;
}

#[tokio::test]
async fn authenticated_shaping_preserves_empty_large_ordered_udp_datagrams() {
    assert_udp_flow(true).await;
}

async fn assert_udp_flow(shaping: bool) {
    let dir = tempfile::tempdir().unwrap();
    let (settings, _server) = udp_fixture_with_shaping(dir.path(), shaping).await;
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    let target_task = Driver(tokio::spawn(async move {
        let mut buffer = vec![0; 65_535];
        for _ in 0..3 {
            let (length, source) = target.recv_from(&mut buffer).await.unwrap();
            target.send_to(&buffer[..length], source).await.unwrap();
        }
    }));
    let (outbound, rx) = tokio::sync::mpsc::channel(2);
    let (tx, mut inbound) = tokio::sync::mpsc::channel(2);
    let flow = tokio::spawn(async move {
        super::super::run_relay_udp_flow(&settings.relay, "127.0.0.1", port, rx, tx).await
    });
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        // macOS's default UDP maxdgram is 9216. Exercise full 60k IP
        // datagrams on Linux; framing itself has a platform-neutral 60k test.
        let large = if cfg!(target_os = "macos") {
            8_192
        } else {
            60_000
        };
        for expected in [vec![], b"private DNS payload".to_vec(), vec![0x5c; large]] {
            outbound.send(expected.clone()).await.unwrap();
            let received = match inbound.recv().await {
                Some(packet) => packet,
                None => panic!(
                    "secure UDP flow closed before {}-byte reply: {:?}",
                    expected.len(),
                    flow.await
                ),
            };
            assert_eq!(received.payload, expected);
            assert_eq!(received.target.port, port);
        }
        drop(outbound);
        flow.await.unwrap().unwrap();
    })
    .await
    .unwrap();
    drop(target_task);
}

#[tokio::test]
async fn inner_tls_udp_response_timeout_never_replays_committed_datagram_to_pool() {
    assert_udp_timeout_no_replay(false).await;
}
#[tokio::test]
async fn endpoint_bandit_udp_timeout_preserves_committed_no_replay() {
    assert_udp_timeout_no_replay(true).await;
}
async fn assert_udp_timeout_no_replay(endpoint_learning: bool) {
    let dir = tempfile::tempdir().unwrap();
    let (mut settings, _server) = udp_fixture(dir.path()).await;
    let backup = TcpListener::bind("127.0.0.1:0").await.unwrap();
    settings.relay.endpoints = vec![
        aegis_core::RelayEndpointSettings {
            server: settings.relay.server.clone(),
            server_name: "localhost".into(),
            masque_server: None,
            masque_server_name: None,
        },
        aegis_core::RelayEndpointSettings {
            server: backup.local_addr().unwrap().to_string(),
            server_name: "localhost".into(),
            masque_server: None,
            masque_server_name: None,
        },
    ];
    if endpoint_learning {
        settings.relay.auth_token.clear();
        settings.relay.endpoint_bandit = Some(aegis_core::RelayEndpointBanditSettings {
            algorithm: aegis_core::brain::recent_routes::paper_bandit::PaperAlgorithm::Discounted {
                gamma: 0.9,
                xi: 1.0,
            },
            max_profiles: 16,
            max_contexts_per_profile: 16,
            pre_auth_block_ms: 1000,
            dependency_policy: None,
        });
    }
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = crate::socks5::ConnectTarget {
        host: "127.0.0.1".into(),
        port: target.local_addr().unwrap().port(),
    };
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        super::super::run_relay_udp_datagram_once(
            &settings.relay,
            address,
            b"one application datagram",
        ),
    )
    .await
    .unwrap();
    assert!(super::super::udp_payload_was_committed(
        &result.unwrap_err()
    ));
    let mut buffer = [0; 128];
    let (length, _) = target.recv_from(&mut buffer).await.unwrap();
    assert_eq!(&buffer[..length], b"one application datagram");
    assert!(tokio::time::timeout(
        std::time::Duration::from_millis(100),
        target.recv_from(&mut buffer)
    )
    .await
    .is_err());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), backup.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn inner_tls_real_client_server_transfers_after_tcp_failover_and_half_closes() {
    assert_transfer_after_failover(None).await;
}

#[tokio::test]
async fn authenticated_carrier_program_uses_declared_direct_then_fronted_fallback() {
    assert_transfer_after_failover_with_shaping(None, false, false, false, false, true, false)
        .await;
}

#[tokio::test]
async fn signed_direct_route_fails_over_to_own_bridge_before_device_authentication() {
    assert_transfer_after_failover_with_shaping(None, false, true, false, false, true, false).await;
}

#[tokio::test]
async fn signed_direct_route_fails_over_to_enrolled_websocket_and_preserves_half_close() {
    assert_transfer_after_failover_with_shaping(None, false, false, false, false, true, true).await;
}

#[tokio::test]
async fn policy_ack_refuses_unbound_bridge_route_before_network() {
    use aegis_core::carrier_program::{
        BridgeDeclaration, CarrierChannel, CarrierProgramSettings, CarrierRoute,
    };
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let (mut settings, _) = configs(dir.path(), &address);
    settings.relay.endpoints = vec![aegis_core::RelayEndpointSettings {
        server: address,
        server_name: "localhost".into(),
        masque_server: None,
        masque_server_name: None,
    }];
    settings.relay.carrier_program = Some(CarrierProgramSettings {
        routes: vec![CarrierRoute {
            channel: CarrierChannel::OwnHttpsBridge,
            endpoint_index: 0,
        }],
        bridge: Some(BridgeDeclaration {
            authority: "localhost".into(),
            path: "/private/stream".into(),
            enrollment_path: "/private/enroll".into(),
        }),
        web_response: None,
        ech_scope: None,
        fronted_ech_authority: None,
    });
    let expected = crate::device_identity::store::OnlineExpectation {
        certificate_sha256: "00".repeat(32),
        not_after_unix_secs: u64::MAX,
        issued_generation: None,
        snapshot_sha256: None,
    };
    let error = policy_ack(&settings.relay, &expected).await.unwrap_err();
    assert!(error.to_string().contains("private bridge differs"));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn inner_tls_transfers_after_verified_cdn_503_without_sending_identity_to_failed_edge() {
    assert_transfer_after_failover(Some(http::StatusCode::SERVICE_UNAVAILABLE)).await;
}

#[tokio::test]
async fn inner_tls_transfers_after_verified_cdn_missing_route_without_replaying_data() {
    assert_transfer_after_failover(Some(http::StatusCode::NOT_FOUND)).await;
}

#[tokio::test]
async fn inner_tls_retries_outer_403_without_treating_it_as_device_authentication() {
    assert_transfer_after_failover(Some(http::StatusCode::FORBIDDEN)).await;
}

#[tokio::test]
async fn inner_tls_retries_pinned_pool_instead_of_following_outer_redirect() {
    assert_transfer_after_failover(Some(http::StatusCode::MOVED_PERMANENTLY)).await;
}

#[tokio::test]
async fn inner_tls_retries_non_grpc_outer_200_without_exposing_identity() {
    assert_transfer_after_failover(Some(http::StatusCode::OK)).await;
}

#[tokio::test]
async fn inner_tls_retries_stalled_carrier_before_sending_device_identity() {
    assert_transfer_after_failover_case(None, true).await;
}

async fn assert_transfer_after_failover(carrier_status: Option<http::StatusCode>) {
    assert_transfer_after_failover_case(carrier_status, false).await;
}

async fn assert_transfer_after_failover_case(
    carrier_status: Option<http::StatusCode>,
    stall: bool,
) {
    assert_transfer_after_failover_with_shaping(
        carrier_status,
        stall,
        false,
        false,
        false,
        false,
        false,
    )
    .await;
}

#[tokio::test]
async fn authenticated_shaping_transfers_tcp_after_pre_auth_failover_and_half_close() {
    assert_transfer_after_failover_with_shaping(None, false, true, false, false, false, false)
        .await;
}

#[tokio::test]
async fn authenticated_shaping_preserves_https_bridge_admission_and_tcp_half_close() {
    assert_transfer_after_failover_with_shaping(None, false, true, true, false, false, false).await;
}

#[tokio::test]
async fn authenticated_shaping_transfers_with_delayed_outer_carrier_and_half_close() {
    assert_transfer_after_failover_with_shaping(None, false, true, false, true, false, false).await;
}

#[derive(Default)]
struct TransferProgress {
    app_stage: AtomicUsize,
    app_written: AtomicUsize,
    target_stage: AtomicUsize,
    target_received: AtomicUsize,
    response_received: AtomicUsize,
    delayed_chunks: AtomicUsize,
    carrier_chunks: AtomicUsize,
    application_joined: AtomicBool,
    target_completed: AtomicBool,
}

impl TransferProgress {
    fn completion(&self) -> TransferCompletion {
        // These release/acquire markers certify the actual task joins and
        // target response shutdown, not an inferred count or later snapshot.
        TransferCompletion {
            application_joined: self.application_joined.load(Ordering::Acquire),
            target_completed: self.target_completed.load(Ordering::Acquire),
            app_written: self.app_written.load(Ordering::Relaxed),
            target_received: self.target_received.load(Ordering::Relaxed),
            response_received: self.response_received.load(Ordering::Relaxed),
        }
    }

    fn diagnostic(&self) -> String {
        let app_stage = match self.app_stage.load(Ordering::Relaxed) {
            0 => "write_payload",
            1 => "app_half_close",
            2 => "read_response",
            3 => "join_client",
            4 => "join_target",
            _ => "complete",
        };
        let target_stage = match self.target_stage.load(Ordering::Relaxed) {
            0 => "accept",
            1 => "read_payload",
            2 => "verify_hash",
            3 => "write_response",
            4 => "target_half_close",
            _ => "complete",
        };
        format!(
            "app={app_stage}, app_written={}, target={target_stage}, target_received={}, response_received={}, delayed_chunks={}, carrier_chunks={}",
            self.app_written.load(Ordering::Relaxed),
            self.target_received.load(Ordering::Relaxed),
            self.response_received.load(Ordering::Relaxed),
            self.delayed_chunks.load(Ordering::Relaxed),
            self.carrier_chunks.load(Ordering::Relaxed),
        )
    }
}

// Delay opaque outer-TLS bytes, without interpreting the authenticated wire.
// Delay four chunks per direction after the target opens, then resume normal
// service. This exercises transient backpressure without making the relay carry
// sustained padding through a link slower than its admitted shaping profile.
// Each direction retains its TCP half-close.
async fn delayed_carrier_copy<R, W>(
    mut reader: R,
    mut writer: W,
    progress: Arc<TransferProgress>,
    direction: &'static str,
) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buffer = [0u8; 4096];
    let mut delayed = 0;
    let mut forwarded_bytes = 0;
    let mut forwarded_chunks = 0;
    let contextualize = |error: std::io::Error,
                         phase: &'static str,
                         forwarded_bytes: usize,
                         forwarded_chunks: usize| {
        std::io::Error::new(
            error.kind(),
            DelayedCarrierFault {
                error,
                direction,
                phase,
                forwarded_bytes,
                forwarded_chunks,
                completion: progress.completion(),
                progress: progress.diagnostic(),
            },
        )
    };
    loop {
        let count = reader
            .read(&mut buffer)
            .await
            .map_err(|error| contextualize(error, "read", forwarded_bytes, forwarded_chunks))?;
        if count == 0 {
            return writer.shutdown().await.map_err(|error| {
                contextualize(error, "shutdown", forwarded_bytes, forwarded_chunks)
            });
        }
        if delayed < 4 && progress.target_stage.load(Ordering::Relaxed) >= 1 {
            tokio::time::sleep(std::time::Duration::from_millis(16)).await;
            delayed += 1;
            progress.delayed_chunks.fetch_add(1, Ordering::Relaxed);
        }
        writer
            .write_all(&buffer[..count])
            .await
            .map_err(|error| contextualize(error, "write", forwarded_bytes, forwarded_chunks))?;
        forwarded_bytes += count;
        forwarded_chunks += 1;
        progress.carrier_chunks.fetch_add(1, Ordering::Relaxed);
    }
}

// Test-only bounded metadata: no TLS bytes, headers, credentials or payload.
// Keep the original I/O error as a source. Only the explicit fault-time
// completion gate below can distinguish a completed fixture's read reset.
#[derive(Debug, thiserror::Error)]
#[error("delayed carrier {direction} {phase} failed after {forwarded_bytes} bytes/{forwarded_chunks} chunks; completion={completion:?}; {progress}")]
struct DelayedCarrierFault {
    #[source]
    error: std::io::Error,
    direction: &'static str,
    phase: &'static str,
    forwarded_bytes: usize,
    forwarded_chunks: usize,
    completion: TransferCompletion,
    progress: String,
}

#[derive(Debug)]
struct TransferCompletion {
    application_joined: bool,
    target_completed: bool,
    app_written: usize,
    target_received: usize,
    response_received: usize,
}

fn admit_delayed_carrier_completion(
    result: std::io::Result<()>,
    payload_length: usize,
) -> std::io::Result<()> {
    match result {
        // secure::run owns and aborts its outer H2 driver when the complete
        // inner transfer returns. A delayed opaque shim can then see TCP RST
        // instead of outer FIN. This exception is solely that owned reader,
        // after fault-time proof of both actual joins plus exact byte counts.
        // Writes, shutdown, early/partial reset and all other errors fail.
        Err(error)
            if error.kind() == std::io::ErrorKind::ConnectionReset
                && error
                    .get_ref()
                    .and_then(|source| source.downcast_ref::<DelayedCarrierFault>())
                    .is_some_and(|fault| {
                        fault.direction == "client_to_relay"
                            && fault.phase == "read"
                            && fault.completion.application_joined
                            && fault.completion.target_completed
                            && fault.completion.app_written == payload_length
                            && fault.completion.target_received == payload_length
                            && fault.completion.response_received
                                == b"delayed-server-response".len()
                    }) =>
        {
            eprintln!("owned delayed carrier post-completion read reset retained: {error:?}");
            Ok(())
        }
        result => result,
    }
}

#[tokio::test]
async fn delayed_carrier_copy_early_tcp_reset_retains_phase_and_failure() {
    let (reader, mut peer) = local_pair().await;
    peer.write_all(b"opaque").await.unwrap();
    socket2::SockRef::from(&peer)
        .set_linger(Some(std::time::Duration::ZERO))
        .unwrap();
    drop(peer);
    let progress = Arc::new(TransferProgress::default());
    let error = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        delayed_carrier_copy(
            reader,
            tokio::io::sink(),
            progress.clone(),
            "client_to_relay",
        ),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    let fault = error
        .get_ref()
        .unwrap()
        .downcast_ref::<DelayedCarrierFault>()
        .unwrap();
    assert_eq!(fault.direction, "client_to_relay");
    assert_eq!(fault.phase, "read");
    assert_eq!(fault.error.kind(), std::io::ErrorKind::ConnectionReset);
    assert!(fault.error.raw_os_error().is_some());
    assert!(fault
        .progress
        .starts_with("app=write_payload, app_written=0"));
    assert!(fault.progress.contains("target=accept, target_received=0"));
    // Completion after the fault cannot retroactively admit its early reset.
    progress.app_written.store(6, Ordering::Relaxed);
    progress.target_received.store(6, Ordering::Relaxed);
    progress
        .response_received
        .store(b"delayed-server-response".len(), Ordering::Relaxed);
    progress.target_completed.store(true, Ordering::Release);
    progress.application_joined.store(true, Ordering::Release);
    assert_eq!(
        admit_delayed_carrier_completion(Err(error), 6)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::ConnectionReset
    );
}

#[tokio::test]
async fn delayed_carrier_copy_actual_tcp_half_close_delivers_opaque_bytes_and_eof() {
    let (reader, mut peer) = local_pair().await;
    peer.write_all(b"opaque").await.unwrap();
    peer.shutdown().await.unwrap();
    let (writer, mut output) = tokio::io::duplex(64);
    let progress = Arc::new(TransferProgress::default());
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        delayed_carrier_copy(reader, writer, progress, "relay_to_client"),
    )
    .await
    .unwrap()
    .unwrap();
    let mut received = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        output.read_to_end(&mut received),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(received, b"opaque");
}

async fn assert_transfer_after_failover_with_shaping(
    carrier_status: Option<http::StatusCode>,
    stall: bool,
    shaping: bool,
    bridge: bool,
    delayed_carrier: bool,
    carrier_program: bool,
    secure_ws: bool,
) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = reservation.local_addr().unwrap().to_string();
    let (mut settings, mut server) = configs(dir.path(), &address);
    if shaping {
        settings.relay.authenticated_shaping = Some(shaping_profile());
        server.transport.authenticated_shaping = Some(shaping_profile());
    }
    if bridge {
        let credential = dir.path().join("bridge-credential");
        secure_channel::enrollment::write_private_new(&credential, &[b'a'; 64]).unwrap();
        let policy = aegis_core::https_bridge::ClientSettings {
            authority: "localhost".into(),
            path: "/private/stream".into(),
            enrollment_path: "/private/enroll".into(),
            credential_file: credential,
        };
        settings.relay.https_bridge = Some(policy.clone());
        server.auth_token.clear();
        server.transport.https_bridge = Some(aegis_core::https_bridge::ServerSettings {
            carrier: policy,
            site_html: "<!doctype html><title>Owned site</title>".into(),
        });
    }
    if secure_ws {
        assert!(carrier_program && !bridge);
        server.auth_token.clear();
        server.transport.secure_websocket_path =
            Some(aegis_core::carrier_program::SECURE_WS_PATH.into());
    }
    let carrier_tls = aegis_server::tls::load_server_config(&server.cert, &server.key).unwrap();
    drop(reservation);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let server_task = Driver(tokio::spawn(async move {
        aegis_server::run_server_with_shutdown(server, Some(ready_tx), async {
            let _ = stop_rx.await;
        })
        .await
        .unwrap();
    }));
    tokio::time::timeout(std::time::Duration::from_secs(5), ready_rx)
        .await
        .unwrap()
        .unwrap();
    assert!(super::super::runtime_fallback_ready(&settings.relay));
    assert!(!super::super::runtime_udp_fallback_ready(&settings.relay));
    settings.validate_inner_tls().unwrap();

    let progress = Arc::new(TransferProgress::default());
    let (carrier_address, mut delayed_driver, delayed_result) = if delayed_carrier {
        assert!(shaping, "the delay regression must exercise framed traffic");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let carrier_address = listener.local_addr().unwrap().to_string();
        let progress = progress.clone();
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        let driver = Driver(tokio::spawn(async move {
            let (client, _) = listener.accept().await.unwrap();
            let relay = TcpStream::connect(address).await.unwrap();
            let (client_read, client_write) = tokio::io::split(client);
            let (relay_read, relay_write) = tokio::io::split(relay);
            let result = tokio::try_join!(
                delayed_carrier_copy(
                    client_read,
                    relay_write,
                    progress.clone(),
                    "client_to_relay",
                ),
                delayed_carrier_copy(relay_read, client_write, progress, "relay_to_client"),
            )
            .map(|_| ());
            // Transfer ownership of the unmodified I/O result to this fixture.
            // The fixture applies its narrow post-completion gate after the
            // independent authenticated request/response assertions below.
            let _ = result_tx.send(result);
        }));
        (carrier_address, Some(driver), Some(result_rx))
    } else {
        (address, None, None)
    };

    let unavailable = TcpListener::bind("127.0.0.1:0").await.unwrap();
    settings.relay.endpoints = vec![
        aegis_core::RelayEndpointSettings {
            server: unavailable.local_addr().unwrap().to_string(),
            server_name: "localhost".into(),
            masque_server: None,
            masque_server_name: None,
        },
        aegis_core::RelayEndpointSettings {
            server: carrier_address,
            server_name: "localhost".into(),
            masque_server: None,
            masque_server_name: None,
        },
    ];
    if carrier_program {
        use aegis_core::carrier_program::{
            BridgeDeclaration, CarrierChannel, CarrierProgramSettings, CarrierRoute,
        };
        settings.relay.endpoints.reverse();
        let channel = CarrierChannel::DirectH2;
        let fallback = if secure_ws {
            CarrierChannel::HttpsWs
        } else if bridge {
            CarrierChannel::OwnHttpsBridge
        } else {
            CarrierChannel::FrontedH2
        };
        let declaration = settings
            .relay
            .https_bridge
            .as_ref()
            .map(|private| BridgeDeclaration {
                authority: private.authority.clone(),
                path: private.path.clone(),
                enrollment_path: private.enrollment_path.clone(),
            });
        settings.relay.carrier_program = Some(CarrierProgramSettings {
            bridge: declaration,
            web_response: None,
            ech_scope: None,
            fronted_ech_authority: None,
            routes: vec![
                CarrierRoute {
                    channel,
                    endpoint_index: 1,
                },
                CarrierRoute {
                    channel: fallback,
                    endpoint_index: 0,
                },
            ],
        });
        settings.validate_inner_tls().unwrap();
    }
    // Keep the refused endpoint reserved until the target owns a distinct port.
    let mut unavailable_reservation = None;
    let failed_carrier = if carrier_status.is_some() || stall {
        Some(Driver(tokio::spawn(async move {
            let (tcp, _) = unavailable.accept().await.unwrap();
            let tls = tokio_rustls::TlsAcceptor::from(carrier_tls)
                .accept(tcp)
                .await
                .unwrap();
            let mut connection = h2::server::handshake(tls).await.unwrap();
            let (request, mut response) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.uri().path(), secure_channel::GRPC_PATH);
            if let Some(status) = carrier_status {
                response
                    .send_response(
                        http::Response::builder().status(status).body(()).unwrap(),
                        true,
                    )
                    .unwrap();
            }
            let mut body = request.into_body();
            let (data, _) = tokio::join!(body.data(), async {
                let _ = std::future::poll_fn(|cx| connection.poll_closed(cx)).await;
            });
            assert!(
                !matches!(data, Some(Ok(bytes)) if !bytes.is_empty()),
                "no inner identity or application bytes may reach an unavailable carrier"
            );
        })))
    } else {
        unavailable_reservation = Some(unavailable);
        None
    };

    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_port = target.local_addr().unwrap().port();
    // The first pool endpoint is closed before the client can dial it.
    drop(unavailable_reservation);
    let pattern = b"signed-in-device-private-payload";
    let payload_length = if shaping {
        128 * 1024
    } else {
        120_000 * pattern.len()
    };
    let mut payload = pattern.repeat(payload_length.div_ceil(pattern.len()));
    payload.truncate(payload_length);
    if shaping {
        // Lifecycle/flow-control coverage, not a scheduler-throughput test:
        // 128 KiB crosses H2's initial 65,535-byte window and spans eight 16 KiB
        // bounded queue capacities, without assuming 938 cells finish
        // inside this fixture's unchanged 15-second watchdog on every OS.
        assert!(payload.len() > 65_535);
        assert_eq!(payload.len(), 8 * shaping_profile().buffer_bytes);
    }
    let expected = Sha256::digest(&payload);
    let target_progress = progress.clone();
    let mut target_task = Driver(tokio::spawn(async move {
        let (mut target, _) = target.accept().await.unwrap();
        target_progress.target_stage.store(1, Ordering::Relaxed);
        let mut received = Vec::new();
        let mut buffer = [0u8; 8192];
        loop {
            let count = target.read(&mut buffer).await.unwrap();
            if count == 0 {
                break;
            }
            received.extend_from_slice(&buffer[..count]);
            target_progress
                .target_received
                .fetch_add(count, Ordering::Relaxed);
            assert!(
                received.len() <= payload_length,
                "target received extra bytes"
            );
        }
        target_progress.target_stage.store(2, Ordering::Relaxed);
        assert_eq!(
            received.len(),
            payload_length,
            "{}",
            target_progress.diagnostic()
        );
        assert_eq!(Sha256::digest(&received), expected);
        target_progress.target_stage.store(3, Ordering::Relaxed);
        target.write_all(b"delayed-server-response").await.unwrap();
        target_progress.target_stage.store(4, Ordering::Relaxed);
        target.shutdown().await.unwrap();
        target_progress.target_stage.store(5, Ordering::Relaxed);
        target_progress
            .target_completed
            .store(true, Ordering::Release);
    }));
    let (mut app, local) = local_pair().await;
    let mut client_task = Driver(tokio::spawn(async move {
        super::super::run_relay_tunnel(
            local,
            &settings.relay,
            "127.0.0.1".into(),
            target_port,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    }));
    let transfer = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        for chunk in payload.chunks(16_384) {
            app.write_all(chunk).await.unwrap();
            progress
                .app_written
                .fetch_add(chunk.len(), Ordering::Relaxed);
        }
        progress.app_stage.store(1, Ordering::Relaxed);
        app.shutdown().await.unwrap();
        progress.app_stage.store(2, Ordering::Relaxed);
        let mut received = Vec::new();
        let mut buffer = [0u8; 64];
        loop {
            let count = app.read(&mut buffer).await.unwrap();
            if count == 0 {
                break;
            }
            received.extend_from_slice(&buffer[..count]);
            progress
                .response_received
                .fetch_add(count, Ordering::Relaxed);
            assert!(received.len() <= b"delayed-server-response".len());
        }
        assert_eq!(received, b"delayed-server-response");
        progress.app_stage.store(3, Ordering::Relaxed);
        (&mut client_task.0).await.unwrap();
        progress.app_stage.store(4, Ordering::Relaxed);
        (&mut target_task.0).await.unwrap();
        progress.app_stage.store(5, Ordering::Relaxed);
        progress.application_joined.store(true, Ordering::Release);
    })
    .await;
    assert!(
        transfer.is_ok(),
        "transfer watchdog expired: {}; client_finished={}, target_finished={}",
        progress.diagnostic(),
        client_task.0.is_finished(),
        target_task.0.is_finished(),
    );
    if let Some(driver) = &mut delayed_driver {
        tokio::time::timeout(std::time::Duration::from_secs(5), &mut driver.0)
            .await
            .unwrap()
            .unwrap();
        let result = delayed_result.unwrap().try_recv().unwrap();
        admit_delayed_carrier_completion(result, payload_length).unwrap();
        assert!(
            progress.carrier_chunks.load(Ordering::Relaxed) >= payload_length.div_ceil(4096),
            "delayed carrier must have forwarded the full bounded payload"
        );
        assert!(
            (1..=8).contains(&progress.delayed_chunks.load(Ordering::Relaxed)),
            "transient delay must have been exercised within its fixed budget"
        );
    }
    if let Some(mut failed_carrier) = failed_carrier {
        tokio::time::timeout(std::time::Duration::from_secs(5), &mut failed_carrier.0)
            .await
            .unwrap()
            .unwrap();
    }
    stop_tx.send(()).unwrap();
    // Keep ownership through graceful shutdown; Driver aborts only on failure.
    let mut server_task = server_task;
    tokio::time::timeout(std::time::Duration::from_secs(5), &mut server_task.0)
        .await
        .unwrap()
        .unwrap();
}

#[test]
fn inner_tls_policy_rejects_legacy_udp_and_direct_modes() {
    let dir = tempfile::tempdir().unwrap();
    let (mut settings, _) = configs(dir.path(), "127.0.0.1:443");
    settings.validate_inner_tls().unwrap();
    settings
        .relay
        .transport_priority
        .push(TunnelTransportFamily::LegacyTls);
    assert!(settings.validate_inner_tls().is_err());
    assert!(!super::super::runtime_fallback_ready(&settings.relay));
    settings.relay.transport_priority = vec![TunnelTransportFamily::GrpcStream];
    settings.relay.udp_transport_priority = Some(vec![TunnelTransportFamily::MasqueDerived]);
    assert!(settings.validate_inner_tls().is_err());
    assert!(!super::super::runtime_udp_fallback_ready(&settings.relay));
    settings.relay.udp_transport_priority = Some(vec![]);
    settings.mode = Mode::Direct;
    assert!(settings.validate_inner_tls().is_err());
    settings.mode = Mode::Relay;
    settings.ingress.primary = IngressPrimary::Wide;
    assert!(settings.validate_inner_tls().is_ok());
    settings.relay.udp_transport_priority = Some(vec![TunnelTransportFamily::GrpcDatagram]);
    assert!(settings.validate_inner_tls().is_ok());
    assert!(super::super::runtime_udp_fallback_ready(&settings.relay));
    assert!(super::super::runtime_udp_associate_ready(&settings.relay));
}

#[tokio::test]
async fn inner_tls_auth_failure_never_reaches_target_or_backup_endpoint() {
    assert_auth_failure_stops_pool(true).await;
}

#[tokio::test]
async fn outer_tls_auth_failure_never_reaches_target_or_backup_endpoint() {
    assert_auth_failure_stops_pool(false).await;
}

async fn assert_auth_failure_stops_pool(wrong_inner: bool) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = reservation.local_addr().unwrap().to_string();
    let (mut settings, server) = configs(dir.path(), &address);
    drop(reservation);
    let backup = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    settings.relay.endpoints = vec![
        aegis_core::RelayEndpointSettings {
            server: address.clone(),
            server_name: "localhost".into(),
            masque_server: None,
            masque_server_name: None,
        },
        aegis_core::RelayEndpointSettings {
            server: backup.local_addr().unwrap().to_string(),
            server_name: "localhost".into(),
            masque_server: None,
            masque_server_name: None,
        },
    ];
    if wrong_inner {
        settings.relay.inner_tls.as_mut().unwrap().server_name = "wrong-inner.test".into();
    } else {
        settings.relay.endpoints[0].server_name = "wrong-outer.test".into();
    }
    settings.relay.auth_token =
        "9cb2a1e3cb2bd80614253904098241f819eae687c4b0c15c30384a1dfa2e7189".into();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let mut server_task = Driver(tokio::spawn(async move {
        aegis_server::run_server_with_shutdown(server, Some(ready_tx), async {
            let _ = stop_rx.await;
        })
        .await
        .unwrap();
    }));
    tokio::time::timeout(std::time::Duration::from_secs(5), ready_rx)
        .await
        .unwrap()
        .unwrap();
    let (_app, local) = local_pair().await;
    let error = super::super::run_relay_tunnel(
        local,
        &settings.relay,
        "127.0.0.1".into(),
        target.local_addr().unwrap().port(),
        Some(b"must-not-be-forwarded"),
        None,
        None,
    )
    .await
    .unwrap_err();
    if wrong_inner {
        assert!(format!("{error:#}").contains("inner TLS authentication"));
    } else {
        assert!(format!("{error:#}").contains("certificate"));
    }
    assert!(!retryable_pre_auth_failure(&error));
    let expectation = crate::device_identity::store::OnlineExpectation {
        certificate_sha256: "00".repeat(32),
        not_after_unix_secs: u64::MAX,
        issued_generation: None,
        snapshot_sha256: None,
    };
    assert!(policy_ack(&settings.relay, &expectation).await.is_err());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), backup.accept())
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), target.accept())
            .await
            .is_err()
    );
    stop_tx.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), &mut server_task.0)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn inner_tls_cannot_enter_legacy_crypto_even_through_direct_helper_calls() {
    let dir = tempfile::tempdir().unwrap();
    let (settings, _) = configs(dir.path(), "127.0.0.1:443");
    let authority = super::super::masque::masque_transport_authority(&settings.relay).unwrap();
    assert!(
        super::super::masque_crypto::masque_quic_client_config(&settings.relay, &authority)
            .is_err()
    );
    let (mut peer, tcp) = local_pair().await;
    let result = super::super::tls_backend::connect_tls(
        &settings.relay,
        tcp,
        "localhost".to_owned().try_into().unwrap(),
        "localhost",
        Some(b"h2"),
        true,
    )
    .await;
    assert!(result.is_err());
    let mut received = Vec::new();
    peer.read_to_end(&mut received).await.unwrap();
    assert!(received.is_empty());
}

#[test]
fn inner_tls_config_resolves_all_trust_and_identity_paths() {
    let dir = tempfile::tempdir().unwrap();
    let (mut settings, _) = configs(dir.path(), "127.0.0.1:443");
    let inner = settings.relay.inner_tls.as_mut().unwrap();
    inner.server_ca = "inner-ca.pem".into();
    inner.cert = "device.test.pem".into();
    inner.key = "device.test.key".into();
    settings.relay.ca_cert = Some("outer.pem".into());
    let path = dir.path().join("client.toml");
    #[cfg(windows)]
    aegis_core::windows_file::write_private_new(&path, b"", false).unwrap();
    std::fs::write(&path, toml::to_string(&settings).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let loaded = crate::config::load_config(&path).unwrap();
    assert_eq!(loaded.relay.ca_cert.unwrap(), dir.path().join("outer.pem"));
    assert_eq!(
        loaded.relay.inner_tls.unwrap().key,
        dir.path().join("device.test.key")
    );
}

#[tokio::test]
async fn authenticated_shaping_mismatch_and_one_sided_profiles_never_dial_target_or_backup() {
    for case in 0..3 {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let (mut settings, mut server) = configs(dir.path(), "127.0.0.1:0");
        if case != 1 {
            settings.relay.authenticated_shaping = Some(shaping_profile());
        }
        if case != 2 {
            let mut policy = shaping_profile();
            if case == 0 {
                policy.max_wire_bytes -= 4098;
            }
            server.transport.authenticated_shaping = Some(policy);
        }
        let backup = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let mut serving = Driver(tokio::spawn(async move {
            aegis_server::run_server_with_bound_ready_and_shutdown(server, ready_tx, async {
                let _ = stop_rx.await;
            })
            .await
            .unwrap();
        }));
        let address = tokio::time::timeout(std::time::Duration::from_secs(5), ready_rx)
            .await
            .unwrap()
            .unwrap()
            .to_string();
        settings.relay.server = address.clone();
        settings.relay.endpoints = vec![
            aegis_core::RelayEndpointSettings {
                server: address,
                server_name: "localhost".into(),
                masque_server: None,
                masque_server_name: None,
            },
            aegis_core::RelayEndpointSettings {
                server: backup.local_addr().unwrap().to_string(),
                server_name: "localhost".into(),
                masque_server: None,
                masque_server_name: None,
            },
        ];
        let (_app, local) = local_pair().await;
        let error = super::super::run_relay_tunnel(
            local,
            &settings.relay,
            "127.0.0.1".into(),
            target.local_addr().unwrap().port(),
            Some(b"must-not-reach-target"),
            None,
            None,
        )
        .await
        .unwrap_err();
        assert!(
            !retryable_pre_auth_failure(&error),
            "case {case}: {error:#}"
        );
        for listener in [&backup, &target] {
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
                    .await
                    .is_err()
            );
        }
        stop_tx.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), &mut serving.0)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn authenticated_shaping_invalid_profile_is_terminal_before_dial() {
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut settings, mut server) =
        configs(dir.path(), &listener.local_addr().unwrap().to_string());
    let mut invalid = shaping_profile();
    invalid.max_wire_bytes = 1;
    settings.relay.authenticated_shaping = Some(invalid.clone());
    server.transport.authenticated_shaping = Some(invalid);
    assert!(server.validate_auth_tokens().is_err());
    let error = open(
        &settings.relay,
        "target.test".into(),
        443,
        secure_channel::Transport::Tcp,
    )
    .await
    .err()
    .unwrap();
    assert!(!retryable_pre_auth_failure(&error));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );

    settings.relay.authenticated_shaping = Some(shaping_profile());
    let mut oversized_timeout = settings.relay.clone();
    oversized_timeout.connect_timeout_ms = u64::MAX;
    let error = open(
        &oversized_timeout,
        "target.test".into(),
        443,
        secure_channel::Transport::Tcp,
    )
    .await
    .err()
    .unwrap();
    assert!(format!("{error:#}").contains("establishment timeout"));
    assert!(!retryable_pre_auth_failure(&error));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
    let mut legacy = settings.relay.clone();
    legacy.inner_tls = None;
    assert!(legacy.validate_inner_tls_transport().is_err());
    legacy.authenticated_shaping = None;
    legacy.connect_timeout_ms = u64::MAX;
    assert!(legacy.validate_inner_tls_transport().is_ok());
    let mut legacy_udp = settings.relay.clone();
    legacy_udp.udp_transport_priority = Some(vec![TunnelTransportFamily::MasqueDerived]);
    assert!(legacy_udp.validate_inner_tls_transport().is_err());
    let mut legacy_tcp = settings.relay;
    legacy_tcp
        .transport_priority
        .push(TunnelTransportFamily::HttpsWs);
    assert!(legacy_tcp.validate_inner_tls_transport().is_err());
    server.transport.authenticated_shaping = Some(shaping_profile());
    server.transport.inner_tls = None;
    assert!(server.validate_auth_tokens().is_err());
}

#[path = "liu_tests.rs"]
mod liu_tests;

/// CP-D3 signal mapping: only typed pre-authentication carrier failures map
/// to a carrier signal; certificate/alert errors stay terminal and unmapped.
#[tokio::test]
async fn pre_auth_failures_map_to_typed_carrier_signals_and_terminal_errors_do_not() {
    use aegis_core::brain::carrier_failover::CarrierSignal;
    use std::io::{Error, ErrorKind};
    let elapsed = tokio::time::timeout(std::time::Duration::ZERO, std::future::pending::<()>())
        .await
        .unwrap_err();
    let cases: Vec<(anyhow::Error, Option<CarrierSignal>)> = vec![
        (
            DialFailure(Error::from(ErrorKind::TimedOut)).into(),
            Some(CarrierSignal::DialTimeout),
        ),
        (
            DialFailure(Error::from(ErrorKind::ConnectionRefused)).into(),
            Some(CarrierSignal::DialRefused),
        ),
        (
            outer_handshake_failure(Error::from(ErrorKind::ConnectionReset)),
            Some(CarrierSignal::HandshakeReset),
        ),
        (
            outer_handshake_failure(Error::from(ErrorKind::UnexpectedEof)),
            Some(CarrierSignal::HandshakeReset),
        ),
        (
            CarrierUnavailable(anyhow::Error::new(elapsed)).into(),
            Some(CarrierSignal::EstablishmentTimeout),
        ),
        (
            CarrierUnavailable(anyhow::Error::new(Error::from(ErrorKind::ConnectionReset))).into(),
            Some(CarrierSignal::HandshakeReset),
        ),
        (
            CarrierUnavailable(anyhow::anyhow!("secure carrier rejected with HTTP 521")).into(),
            Some(CarrierSignal::EdgeRefused),
        ),
        // A certificate or alert failure is InvalidData from the TLS layer:
        // terminal, never a carrier signal, never the next endpoint.
        (
            outer_handshake_failure(Error::new(
                ErrorKind::InvalidData,
                "invalid peer certificate",
            )),
            None,
        ),
        (anyhow::anyhow!("inner TLS authentication"), None),
    ];
    for (error, expected) in cases {
        assert_eq!(pre_auth_signal(&error), expected, "{error:#}");
        assert_eq!(
            retryable_pre_auth_failure(&error),
            expected.is_some(),
            "{error:#}"
        );
    }
    // Context added by the ECH retry path keeps the typed cause.
    let wrapped = outer_handshake_failure(Error::from(ErrorKind::ConnectionReset))
        .context("required ECH retry with rotated configs failed");
    assert_eq!(
        pre_auth_signal(&wrapped),
        Some(CarrierSignal::HandshakeReset)
    );
}
