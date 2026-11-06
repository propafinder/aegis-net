use super::*;
use grpc_io::GrpcIo;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};

struct Fixture {
    _dir: tempfile::TempDir,
    client: ClientSettings,
    server: ServerSettings,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let mut ca_params = CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, ca.pem()).unwrap();
    let mut identities = Vec::new();
    for (name, usage) in [
        ("inner.test", ExtendedKeyUsagePurpose::ServerAuth),
        ("device.test", ExtendedKeyUsagePurpose::ClientAuth),
    ] {
        let mut params = CertificateParams::new(vec![name.into()]).unwrap();
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![usage];
        let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let cert = params.signed_by(&key, &ca, &ca_key).unwrap();
        let cert_path = dir.path().join(format!("{name}.pem"));
        let key_path = dir.path().join(format!("{name}.key"));
        std::fs::write(&cert_path, cert.pem()).unwrap();
        #[cfg(windows)]
        crate::windows_file::write_private_new(&key_path, key.serialize_pem().as_bytes(), false)
            .unwrap();
        #[cfg(not(windows))]
        std::fs::write(&key_path, key.serialize_pem()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        identities.push((
            cert_path,
            key_path,
            hex::encode(Sha256::digest(cert.der().as_ref())),
        ));
    }
    Fixture {
        client: ClientSettings {
            server_name: "inner.test".into(),
            server_ca: ca_path.clone(),
            cert: identities[1].0.clone(),
            key: identities[1].1.clone(),
        },
        server: ServerSettings {
            device_registry: None,
            cert: identities[0].0.clone(),
            key: identities[0].1.clone(),
            client_ca: ca_path,
            allowed_client_sha256: vec![identities[1].2.clone()],
            admission: Default::default(),
            handshake_timeout_ms: 1000,
            idle_timeout_ms: 1000,
        },
        _dir: dir,
    }
}

#[tokio::test]
async fn captured_inner_tls_survives_path_replacement_and_refuses_mismatched_key() {
    let f = fixture();
    let other = fixture();
    let roots = std::fs::read(&f.client.server_ca).unwrap();
    let cert = std::fs::read(&f.client.cert).unwrap();
    let mut key = Zeroizing::new(std::fs::read(&f.client.key).unwrap());
    let prepared = Client::from_captured_pem(&f.client, &roots, &cert, &key).unwrap();
    let oversized = vec![0u8; MAX_CREDENTIAL_BYTES as usize + 1];
    assert!(certificates_from_pem(&oversized).is_err());
    assert!(key_from_pem(&oversized).is_err());
    assert!(trust_roots_from_pem(&oversized).is_err());
    assert!(Client::from_captured_pem(&f.client, &oversized, &cert, &key).is_err());
    assert!(Client::from_captured_pem(&f.client, &roots, &oversized, &key).is_err());
    assert!(Client::from_captured_pem(&f.client, &roots, &cert, &oversized).is_err());
    let wrong_key = Zeroizing::new(std::fs::read(&other.client.key).unwrap());
    assert!(Client::from_captured_pem(&f.client, &roots, &cert, &wrong_key).is_err());
    let server = Server::load(&f.server).unwrap();
    std::fs::write(&f.client.server_ca, b"changed").unwrap();
    std::fs::write(&f.client.cert, b"changed").unwrap();
    key.fill(0);
    std::fs::remove_file(&f.client.key).unwrap();
    let (c, s) = tokio::io::duplex(8192);
    let (client_result, server_result) = tokio::join!(prepared.connect(c), server.accept(s));
    assert!(client_result.is_ok());
    assert!(server_result.is_ok());
}

#[tokio::test(start_paused = true)]
async fn relay_preauth_core_buffered_valid_proof_after_cutoff_is_refused() {
    use std::future::Future;
    let mut f = fixture();
    f.server.handshake_timeout_ms = 100;
    let client = Client::load(&f.client).unwrap();
    let server = Server::load(&f.server).unwrap();
    let (client_io, server_io) = tokio::io::duplex(8192);
    let accepting = server.accept_with_lease(server_io);
    let connecting = client.connect(client_io);
    tokio::pin!(accepting, connecting);
    let _client = std::future::poll_fn(|cx| {
        assert!(accepting.as_mut().poll(cx).is_pending());
        connecting.as_mut().poll(cx)
    })
    .await
    .unwrap();
    tokio::time::advance(Duration::from_millis(101)).await;
    let result = accepting.await;
    let error = result
        .err()
        .expect("buffered valid proof cannot win after cutoff");
    assert!(matches!(
        AuthenticationFailure::from_io(&error),
        Some(AuthenticationFailure::Timeout)
    ));
}

#[tokio::test(start_paused = true)]
async fn authenticated_grpc_agreement_retains_original_shaping_session_clock() {
    let f = fixture();
    let identity = Client::load(&f.client).unwrap();
    let server = Server::load(&f.server).unwrap();
    for poisson in [false, true] {
        let mut profile: crate::carrier_runtime::PrivacySettings =
            serde_json::from_value(serde_json::json!({
                "payload_bytes":32,"cadence_ms":1000,"buffer_bytes":64,
                "max_wire_bytes":1048576,"io_timeout_ms":1000,
                "session_timeout_ms":500,"max_queue_delay_ms":20000
            }))
            .unwrap();
        if poisson {
            profile.poisson_pacing = Some(crate::traffic_privacy::poisson::PoissonPacing {
                mean_interval_us: 1000,
                max_gap_us: 1_000_000,
            });
        } else {
            profile.cadence_ms = 1;
        }
        let (a, b) = tokio::io::duplex(8192);
        let (a, b) = tokio::join!(
            identity.connect(GrpcIo::new(a)),
            server.accept(GrpcIo::new(b))
        );
        let (a, b) = (a.unwrap(), b.unwrap());
        let origin = tokio::time::Instant::now();
        let end = origin + Duration::from_secs(1);
        let (a, b) = tokio::join!(relay_shaping::client(a, Some(&profile), end), async {
            tokio::time::sleep(Duration::from_millis(300)).await;
            relay_shaping::server(b, Some(&profile), end).await
        });
        let (mut a, _b) = (a.unwrap(), b.unwrap());
        let error = a.read_u8().await.unwrap_err();
        assert_eq!(origin.elapsed(), Duration::from_millis(500));
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
}

#[tokio::test]
async fn secure_channel_large_transfer_half_close_and_carrier_confidentiality() {
    let f = fixture();
    let client = Client::load(&f.client).unwrap();
    let server = Server::load(&f.server).unwrap();
    let (client_io, mut middle_client) = tokio::io::duplex(101);
    let (mut middle_server, server_io) = tokio::io::duplex(103);
    let capture = Arc::new(std::sync::Mutex::new(Vec::new()));
    let capture_copy = capture.clone();
    let proxy = tokio::spawn(async move {
        let (mut cr, mut cw) = tokio::io::split(&mut middle_client);
        let (mut sr, mut sw) = tokio::io::split(&mut middle_server);
        let upstream = async {
            let mut bytes = [0; 137];
            loop {
                let n = cr.read(&mut bytes).await?;
                if n == 0 {
                    sw.shutdown().await?;
                    break;
                }
                capture_copy.lock().unwrap().extend_from_slice(&bytes[..n]);
                sw.write_all(&bytes[..n]).await?;
            }
            io::Result::Ok(())
        };
        let downstream = tokio::io::copy(&mut sr, &mut cw);
        tokio::try_join!(upstream, downstream).unwrap();
    });
    let payload = b"PRIVATE-HTTP-DNS-USER-CONTENT".repeat(150_000);
    let expected = Sha256::digest(&payload);
    let serving = tokio::spawn(async move {
        let mut tls = server.accept(GrpcIo::new(server_io)).await.unwrap();
        assert_eq!(
            tls.get_ref().1.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        let open = read_open(&mut tls).await.unwrap();
        assert_eq!(open.host, "private-destination.test");
        let mut received = Vec::new();
        tls.read_to_end(&mut received).await.unwrap();
        assert_eq!(Sha256::digest(&received), expected);
        tls.write_all(b"response-after-half-close").await.unwrap();
        tls.shutdown().await.unwrap();
    });
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut tls = client.connect(GrpcIo::new(client_io)).await.unwrap();
        write_open(
            &mut tls,
            &OpenRequest {
                transport: crate::secure_channel::Transport::Tcp,
                version: 1,
                host: "private-destination.test".into(),
                port: 443,
            },
        )
        .await
        .unwrap();
        tls.write_all(&payload).await.unwrap();
        tls.shutdown().await.unwrap();
        let mut response = Vec::new();
        tls.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"response-after-half-close");
        serving.await.unwrap();
        proxy.await.unwrap();
    })
    .await
    .unwrap();
    let bytes = capture.lock().unwrap();
    for secret in [
        b"PRIVATE-HTTP-DNS-USER-CONTENT".as_slice(),
        b"private-destination.test",
    ] {
        assert!(!bytes.windows(secret.len()).any(|part| part == secret));
    }
}

#[tokio::test]
async fn secure_channel_rejects_untrusted_server_and_unlisted_device() {
    let mut f = fixture();
    let other = fixture();
    f.client.server_ca = other.client.server_ca.clone();
    let client = Client::load(&f.client).unwrap();
    let server = Server::load(&f.server).unwrap();
    let (c, s) = tokio::io::duplex(8192);
    let (client_result, server_result) = tokio::join!(client.connect(c), server.accept(s));
    assert!(client_result.is_err());
    assert!(server_result.is_err());

    f.client.server_ca = f.server.client_ca.clone();
    f.server.allowed_client_sha256 = vec!["00".repeat(32)];
    let client = Client::load(&f.client).unwrap();
    let server = Server::load(&f.server).unwrap();
    let (c, s) = tokio::io::duplex(8192);
    let (_client_result, server_result) = tokio::join!(client.connect(c), server.accept(s));
    let error = server_result.err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(matches!(
        AuthenticationFailure::from_io(&error),
        Some(AuthenticationFailure::DeviceNotAllowed)
    ));
}

#[tokio::test]
async fn secure_channel_silent_handshake_and_half_closed_session_are_bounded() {
    let mut f = fixture();
    f.server.handshake_timeout_ms = 20;
    let server = Server::load(&f.server).unwrap();
    let (_c, s) = tokio::io::duplex(32);
    let error = server.accept(s).await.err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(matches!(
        AuthenticationFailure::from_io(&error),
        Some(AuthenticationFailure::Timeout)
    ));
    let (mut c, mut a) = tokio::io::duplex(32);
    let (_s, mut b) = tokio::io::duplex(32);
    c.shutdown().await.unwrap();
    assert_eq!(
        copy_with_idle_timeout(&mut a, &mut b, Duration::from_millis(20))
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
}

#[tokio::test]
async fn secure_channel_classifies_client_certificate_errors_without_charging_io_errors() {
    let mut f = fixture();
    let unrelated = fixture();
    f.server.client_ca = unrelated.server.client_ca.clone();
    let server = Server::load(&f.server).unwrap();
    let client = Client::load(&f.client).unwrap();
    let (c, s) = tokio::io::duplex(8192);
    let (_, rejected) = tokio::join!(client.connect(c), server.accept(s));
    assert!(matches!(
        AuthenticationFailure::from_io(&rejected.err().unwrap()),
        Some(AuthenticationFailure::CertificateRejected(_))
    ));

    let (c, s) = tokio::io::duplex(8192);
    drop(c);
    assert!(AuthenticationFailure::from_io(&server.accept(s).await.err().unwrap()).is_none());
    for kind in [
        io::ErrorKind::TimedOut,
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::ConnectionReset,
    ] {
        let error = classify_certificate_failure(io::Error::new(
            kind,
            "inner TLS authentication timed out",
        ));
        assert!(AuthenticationFailure::from_io(&error).is_none());
    }
}

#[tokio::test]
async fn secure_grpc_rejects_truncated_compressed_and_oversized_frames() {
    for bytes in [
        vec![0, 0],
        vec![1, 0, 0, 0, 1, 4],
        vec![0, 0, 1, 0, 1],
        vec![0, 0, 0, 0, 2, 1],
    ] {
        let (mut w, r) = tokio::io::duplex(32);
        w.write_all(&bytes).await.unwrap();
        w.shutdown().await.unwrap();
        let mut framed = GrpcIo::new(r);
        assert!(framed.read_to_end(&mut Vec::new()).await.is_err());
    }
}

#[test]
fn secure_channel_config_is_tls13_only_no_tickets_or_key_export() {
    let f = fixture();
    let client = Client::load(&f.client).unwrap();
    let server = Server::load(&f.server).unwrap();
    assert!(!client.config.enable_early_data);
    assert!(!client.config.key_log.will_log("CLIENT_TRAFFIC_SECRET_0"));
    assert!(!server.config.key_log.will_log("CLIENT_TRAFFIC_SECRET_0"));
    assert_eq!(server.config.send_tls13_tickets, 0);
    assert_eq!(server.config.max_early_data_size, 0);
    let held: Vec<_> = (0..128).map(|_| server.try_acquire().unwrap()).collect();
    assert!(server.clone().try_acquire().is_err());
    drop(held);
    assert!(server.try_acquire().is_ok());
}

#[test]
fn secure_admission_pools_enforce_independent_global_and_peer_limits() {
    let mut f = fixture();
    f.server.admission = AdmissionLimits {
        max_handshakes: 3,
        max_sessions: 4,
        max_handshakes_per_peer: 2,
        max_sessions_per_peer: 3,
    };
    let server = Server::load(&f.server).unwrap();
    let first = Some("192.0.2.1".parse().unwrap());
    let second = Some("192.0.2.2".parse().unwrap());
    let mut handshakes = vec![
        server.try_acquire_handshake(first).unwrap(),
        server.try_acquire_handshake(first).unwrap(),
    ];
    let error = server.try_acquire_handshake(first).err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert!(AuthenticationFailure::from_io(&error).is_none());
    handshakes.push(server.try_acquire_handshake(second).unwrap());
    assert!(
        server.try_acquire_handshake(second).is_err(),
        "global handshake limit"
    );
    let mut sessions = (0..3)
        .map(|_| server.try_acquire_session(first).unwrap())
        .collect::<Vec<_>>();
    assert!(
        server.try_acquire_session(first).is_err(),
        "per-peer session limit"
    );
    sessions.push(server.try_acquire_session(second).unwrap());
    assert!(
        server.try_acquire_session(second).is_err(),
        "global session limit"
    );
    drop(handshakes);
    assert!(
        server.try_acquire_handshake(first).is_ok(),
        "sessions cannot occupy handshake capacity"
    );
    drop(sessions);
    assert!(server.try_acquire_session(first).is_ok());
    assert!(
        server.handshakes.peers.lock().unwrap().is_empty(),
        "released peer counts reclaimed"
    );
    assert!(server.sessions.peers.lock().unwrap().is_empty());
}

#[test]
fn secure_admission_limits_reject_zero_or_unbounded_settings() {
    let mut f = fixture();
    for limits in [
        AdmissionLimits {
            max_handshakes: 0,
            ..Default::default()
        },
        AdmissionLimits {
            max_sessions: usize::MAX,
            ..Default::default()
        },
        AdmissionLimits {
            max_handshakes_per_peer: 129,
            ..Default::default()
        },
        AdmissionLimits {
            max_sessions_per_peer: 0,
            ..Default::default()
        },
    ] {
        f.server.admission = limits;
        assert_eq!(
            Server::load(&f.server).err().unwrap().kind(),
            io::ErrorKind::InvalidInput
        );
    }
    let defaults: AdmissionLimits = serde_json::from_str("{}").unwrap();
    assert_eq!(defaults.max_handshakes, 128);
    assert_eq!(defaults.max_sessions, 1024);
}

#[cfg(unix)]
#[test]
fn secure_channel_rejects_readable_or_symlinked_private_keys() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let mut f = fixture();
    std::fs::set_permissions(&f.client.server_ca, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(Client::load(&f.client).is_err());
    std::fs::set_permissions(&f.client.server_ca, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Client::load(&f.client).is_ok());
    std::fs::set_permissions(&f.client.key, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Client::load(&f.client).is_err());
    std::fs::set_permissions(&f.client.key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = f._dir.path().join("key-link");
    symlink(&f.client.key, &link).unwrap();
    f.client.key = link;
    assert!(Client::load(&f.client).is_err());
}

#[tokio::test]
async fn secure_channel_rejects_anonymous_and_tls12_clients() {
    let f = fixture();
    let server = Server::load(&f.server).unwrap();
    let anonymous = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(load_trust_roots(&f.client.server_ca).unwrap())
        .with_no_client_auth();
    let legacy =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_root_certificates(load_trust_roots(&f.client.server_ca).unwrap())
            .with_client_auth_cert(
                certificates(&f.client.cert).unwrap(),
                key(&f.client.key).unwrap(),
            )
            .unwrap();
    for config in [anonymous, legacy] {
        let connector = TlsConnector::from(Arc::new(config));
        let (c, s) = tokio::io::duplex(8192);
        let (_client, result) = tokio::join!(
            connector.connect("inner.test".to_owned().try_into().unwrap(), c),
            server.accept(s)
        );
        assert!(result.is_err());
    }
}

#[tokio::test]
async fn secure_channel_repeated_connections_perform_full_handshakes() {
    let f = fixture();
    let client = Client::load(&f.client).unwrap();
    let server = Server::load(&f.server).unwrap();
    for _ in 0..2 {
        let (c, s) = tokio::io::duplex(8192);
        let (client_tls, server_tls) = tokio::join!(client.connect(c), server.accept(s));
        assert_eq!(
            client_tls.unwrap().get_ref().1.handshake_kind(),
            Some(rustls::HandshakeKind::Full)
        );
        assert_eq!(
            server_tls.unwrap().get_ref().1.handshake_kind(),
            Some(rustls::HandshakeKind::Full)
        );
    }
}

#[tokio::test]
async fn secure_channel_rejects_invalid_open_before_target_processing() {
    for bytes in [vec![0xff, 0xff], b"\x00\x02{}".to_vec()] {
        assert!(read_open(&mut bytes.as_slice()).await.is_err());
    }
    for request in [
        OpenRequest {
            transport: crate::secure_channel::Transport::Tcp,
            version: 0,
            host: "host.test".into(),
            port: 443,
        },
        OpenRequest {
            transport: crate::secure_channel::Transport::Tcp,
            version: 1,
            host: "bad\nhost".into(),
            port: 443,
        },
        OpenRequest {
            transport: crate::secure_channel::Transport::Tcp,
            version: 1,
            host: "host.test".into(),
            port: 0,
        },
    ] {
        let mut bytes = Vec::new();
        assert!(write_open(&mut bytes, &request).await.is_err());
        assert!(bytes.is_empty());
    }
}

#[cfg(unix)]
#[test]
fn startup_server_constructor_uses_verified_registry_retry_without_changing_normal_load() {
    use registry::{publish_snapshot, DeviceRegistry, RegistryTransaction};
    let mut f = fixture();
    let path = f._dir.path().join("registry.json");
    let registry = DeviceRegistry::new(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        900,
    )
    .unwrap();
    publish_snapshot(&path, &registry).unwrap();
    f.server.allowed_client_sha256.clear();
    f.server.device_registry = Some(path.clone());
    let transaction = RegistryTransaction::begin(&path).unwrap();
    assert_eq!(
        Server::load(&f.server).err().unwrap().kind(),
        io::ErrorKind::WouldBlock
    );
    let (send, recv) = std::sync::mpsc::channel();
    let settings = f.server.clone();
    let worker = std::thread::spawn(move || {
        send.send(Server::load_for_startup(&settings)).unwrap();
    });
    assert!(recv.recv_timeout(Duration::from_millis(80)).is_err());
    drop(transaction);
    let server = recv.recv_timeout(Duration::from_secs(2)).unwrap().unwrap();
    worker.join().unwrap();
    assert!(server.registry.is_some());
    assert!(server.allowed_clients.is_empty());
}

#[test]
fn outer_leaf_precheck_requires_exact_current_static_fingerprint() {
    let fixture = fixture();
    let leaf = certificates(&fixture.client.cert).unwrap().remove(0);
    let allowed = Server::load(&fixture.server).unwrap();
    allowed
        .check_current_device_certificate(leaf.as_ref())
        .unwrap();
    let mut unlisted = fixture.server.clone();
    unlisted.allowed_client_sha256 = vec!["00".repeat(32)];
    let server = Server::load(&unlisted).unwrap();
    assert_eq!(
        server
            .check_current_device_certificate(leaf.as_ref())
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied,
    );
}
