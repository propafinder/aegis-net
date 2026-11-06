use super::*;
use aegis_core::secure_channel::enrollment::{self, protocol};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use sha2::{Digest, Sha256};

struct Fixture {
    _dir: tempfile::TempDir,
    config: AuthorityConfig,
    client: enrollment_tls::ClientSettings,
    identity: enrollment::DeviceCsr,
    invitation: PathBuf,
    registry: PathBuf,
    ca_pem: String,
}

#[tokio::test]
async fn ready_accept_backlog_cannot_retain_completed_connection_tasks() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut backlog = Vec::new();
    let mut connections = JoinSet::new();
    let mut completed = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        backlog.push(tokio::net::TcpStream::connect(address).await.unwrap());
        completed.push(connections.spawn(async {}));
    }
    tokio::time::timeout(Duration::from_secs(3), async {
        while completed.iter().any(|task| !task.is_finished()) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // Both branches are ready. A continuously replenished accept backlog must
    // not starve collection and accumulate a new batch of completed tasks.
    for remaining in (0..MAX_CONNECTIONS).rev() {
        assert!(matches!(
            next_connection_event(&listener, &mut connections).await,
            ConnectionEvent::Reaped
        ));
        assert_eq!(connections.len(), remaining);
    }
    assert!(matches!(
        next_connection_event(&listener, &mut connections).await,
        ConnectionEvent::Accepted(Ok(_))
    ));
    assert_eq!(backlog.len(), MAX_CONNECTIONS);
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let registry = dir.path().join("registry.json");
    crate::devices::initialize(&registry).unwrap();
    let invitation = dir.path().join("invitation");
    crate::devices::invite(
        &registry,
        "device-a",
        &invitation,
        300,
        registry::unix_now().unwrap(),
    )
    .unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let ca = params.self_signed(&key).unwrap();
    let ca_path = dir.path().join("ca.pem");
    let ca_key = dir.path().join("ca.key");
    enrollment::write_private_new(&ca_path, ca.pem().as_bytes()).unwrap();
    enrollment::write_private_new(&ca_key, key.serialize_pem().as_bytes()).unwrap();
    let mut leaf = CertificateParams::new(vec!["enroll.test".into()]).unwrap();
    leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let leaf = leaf.signed_by(&leaf_key, &ca, &key).unwrap();
    let cert_path = dir.path().join("authority.pem");
    let key_path = dir.path().join("authority.key");
    enrollment::write_private_new(&cert_path, leaf.pem().as_bytes()).unwrap();
    enrollment::write_private_new(&key_path, leaf_key.serialize_pem().as_bytes()).unwrap();
    let issuer = serde_json::from_value(serde_json::json!({
        "registry":registry,"ca_cert":ca_path,"ca_key":ca_key,"profile_sha256":"02".repeat(32),
        "lifetime_secs":3600,"max_receipts":16,"max_receipt_bytes_total":1048576,"receipt_grace_secs":60
    })).unwrap();
    Fixture {
        config: AuthorityConfig {
            https_bridge: None,
            listen: "127.0.0.1:19000".parse().unwrap(),
            outer_cert: cert_path.clone(),
            outer_key: key_path.clone(),
            inner_tls: enrollment_tls::AuthoritySettings {
                cert: cert_path,
                key: key_path,
            },
            issuer,
        },
        client: enrollment_tls::ClientSettings {
            server_name: "enroll.test".into(),
            server_ca: ca_path,
        },
        identity: enrollment::generate_csr("device-a").unwrap(),
        invitation,
        registry,
        ca_pem: ca.pem(),
        _dir: dir,
    }
}

struct Connection {
    stream: enrollment_tls::Session<tokio_rustls::client::TlsStream<GrpcIo<H2Stream>>>,
    server: crate::lifecycle::OwnedTask<anyhow::Result<()>>,
    _driver: crate::lifecycle::OwnedTask<()>,
    signing: Arc<SigningJobs>,
}

async fn connect(f: &Fixture) -> Connection {
    let prepared = Prepared::new(&f.config).unwrap();
    let signing = Arc::new(SigningJobs::new());
    let cloned = signing.clone();
    let (client, server) = tokio::io::duplex(8192);
    let server = crate::lifecycle::OwnedTask(tokio::spawn(async move {
        serve_h2(
            server,
            prepared.inner,
            prepared.issuer,
            cloned,
            prepared.bridge,
        )
        .await
    }));
    let (mut sender, connection) = h2::client::handshake(client).await.unwrap();
    let driver = crate::lifecycle::OwnedTask(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let mut request = http::Request::builder()
        .method("POST")
        .uri(format!("https://enroll.test{}", enrollment_tls::GRPC_PATH))
        .header("content-type", "application/grpc")
        .body(())
        .unwrap();
    if let Some(bridge) = &f.config.https_bridge {
        *request.uri_mut() = format!(
            "https://{}{}",
            bridge.carrier.authority, bridge.carrier.enrollment_path
        )
        .parse()
        .unwrap();
        request.headers_mut().insert(
            aegis_core::https_bridge::KEY_HEADER,
            bridge.carrier.load_credential().unwrap().header_value(),
        );
    }
    let (response, send) = sender.send_request(request, false).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    let carrier = GrpcIo::new(H2Stream::new(send, response.into_body()));
    let stream = enrollment_tls::Client::load(&f.client)
        .unwrap()
        .connect(carrier)
        .await
        .unwrap();
    Connection {
        stream,
        server,
        _driver: driver,
        signing,
    }
}

async fn exchange(
    f: &Fixture,
    purpose: protocol::ProofPurpose,
    invitation: Option<String>,
) -> wire::ExchangeResponse {
    let mut connection = connect(f).await;
    let challenge = wire::read_challenge(&mut connection.stream).await.unwrap();
    let binding = protocol::RequestBinding {
        operation: protocol::Operation::Redeem,
        request_id: "01".repeat(32),
        profile_sha256: "02".repeat(32),
        csr_sha256: hex::encode(Sha256::digest(f.identity.csr_pem.as_bytes())),
        predecessor_sha256: None,
    };
    let signature = protocol::sign_proof(
        f.identity.private_key_pem.as_bytes(),
        &challenge,
        &binding,
        purpose,
        registry::unix_now().unwrap(),
    )
    .unwrap();
    let request = wire::ExchangeRequest {
        binding,
        purpose,
        csr_pem: f.identity.csr_pem.clone(),
        predecessor_certificate_pem: None,
        invitation,
        signature: hex::encode(signature),
    };
    wire::write_request(&mut connection.stream, &request)
        .await
        .unwrap();
    let response = wire::read_response(&mut connection.stream).await.unwrap();
    connection.stream.shutdown().await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), &mut connection.server.0)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    connection.signing.finish().await;
    response
}

#[tokio::test]
async fn actual_h2_inner_tls_issuance_and_lost_response_receipt_are_idempotent() {
    let f = fixture();
    let before = registry::DeviceRegistry::load(&f.registry).unwrap();
    let invitation = std::fs::read_to_string(&f.invitation).unwrap();
    let issued = exchange(&f, protocol::ProofPurpose::Authorize, Some(invitation)).await;
    let wire::ExchangeResponse::Issued { receipt: first } = issued else {
        panic!("issuance rejected")
    };
    enrollment::validate_device_certificate(
        "device-a",
        first.certificate_pem.as_bytes(),
        f.ca_pem.as_bytes(),
        f.identity.private_key_pem.as_bytes(),
        registry::unix_now().unwrap(),
    )
    .unwrap();
    let state = registry::DeviceRegistry::load(&f.registry).unwrap();
    assert_eq!(
        serde_json::to_value(before.validity).unwrap(),
        serde_json::to_value(state.validity).unwrap()
    );
    assert!(state.invitations[0].consumed);
    assert_eq!(first.state, wire::ReceiptState::IssuedPendingDistribution);
    let recovered = exchange(&f, protocol::ProofPurpose::Receipt, None).await;
    let wire::ExchangeResponse::Issued { receipt: second } = recovered else {
        panic!("receipt recovery rejected")
    };
    assert_eq!(first.certificate_pem, second.certificate_pem);
    assert_eq!(first.issued_generation, second.issued_generation);
    assert_eq!(
        state.generation,
        registry::DeviceRegistry::load(&f.registry)
            .unwrap()
            .generation
    );
}

#[cfg(unix)]
fn enable_bridge(f: &mut Fixture) {
    use std::os::unix::fs::PermissionsExt;
    let credential_file = f._dir.path().join("bridge-key");
    std::fs::write(&credential_file, "ab".repeat(32)).unwrap();
    std::fs::set_permissions(&credential_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    f.config.https_bridge = Some(aegis_core::https_bridge::ServerSettings {
        carrier: aegis_core::https_bridge::ClientSettings {
            authority: "enroll.test".into(),
            path: "/private/stream".into(),
            enrollment_path: "/private/enroll".into(),
            credential_file,
        },
        site_html: "<!doctype html><title>Public site</title>".into(),
    });
}

#[cfg(unix)]
#[tokio::test]
async fn https_bridge_enrollment_preserves_inner_proof_and_receipt_idempotence() {
    let mut f = fixture();
    enable_bridge(&mut f);
    let invitation = std::fs::read_to_string(&f.invitation).unwrap();
    let first = exchange(&f, protocol::ProofPurpose::Authorize, Some(invitation)).await;
    let wire::ExchangeResponse::Issued { receipt: first } = first else {
        panic!("bridge issuance rejected")
    };
    let generation = registry::DeviceRegistry::load(&f.registry)
        .unwrap()
        .generation;
    let second = exchange(&f, protocol::ProofPurpose::Receipt, None).await;
    let wire::ExchangeResponse::Issued { receipt: second } = second else {
        panic!("bridge receipt rejected")
    };
    assert_eq!(first.certificate_pem, second.certificate_pem);
    assert_eq!(
        generation,
        registry::DeviceRegistry::load(&f.registry)
            .unwrap()
            .generation
    );
}

#[cfg(unix)]
#[tokio::test]
async fn https_bridge_authority_hides_old_route_wrong_role_and_wrong_key_without_issuance() {
    let mut f = fixture();
    enable_bridge(&mut f);
    f.config.https_bridge.as_mut().unwrap().site_html = "a".repeat(64 * 1024);
    let before = std::fs::read(&f.registry).unwrap();
    for (method, path, authority, key, expected) in [
        ("POST", enrollment_tls::GRPC_PATH, "enroll.test", true, 404),
        ("POST", "/private/stream", "enroll.test", true, 404),
        ("POST", "/private/enroll", "other.test", true, 404),
        ("POST", "/private/enroll", "enroll.test", false, 404),
        ("GET", "/", "enroll.test", false, 200),
    ] {
        let prepared = Prepared::new(&f.config).unwrap();
        let signing = Arc::new(SigningJobs::new());
        let cloned = signing.clone();
        let (client, server) = tokio::io::duplex(8192);
        let server = crate::lifecycle::OwnedTask(tokio::spawn(async move {
            serve_h2(
                server,
                prepared.inner,
                prepared.issuer,
                cloned,
                prepared.bridge,
            )
            .await
        }));
        let (mut sender, connection) = h2::client::Builder::new()
            .initial_window_size(1024)
            .handshake::<_, bytes::Bytes>(client)
            .await
            .unwrap();
        let driver = crate::lifecycle::OwnedTask(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let mut request = http::Request::builder()
            .method(method)
            .uri(format!("https://{authority}{path}"))
            .header("content-type", "application/grpc")
            .body(())
            .unwrap();
        if key {
            request.headers_mut().insert(
                aegis_core::https_bridge::KEY_HEADER,
                f.config
                    .https_bridge
                    .as_ref()
                    .unwrap()
                    .carrier
                    .load_credential()
                    .unwrap()
                    .header_value(),
            );
        }
        let (response, _) = sender.send_request(request, true).unwrap();
        let response = tokio::time::timeout(Duration::from_secs(2), response)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status().as_u16(), expected);
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.unwrap();
            body.flow_control().release_capacity(chunk.len()).unwrap();
            bytes.extend_from_slice(&chunk);
        }
        assert_eq!(
            &bytes,
            if expected == 200 {
                f.config.https_bridge.as_ref().unwrap().site_html.as_bytes()
            } else {
                b"Not found\n"
            }
        );
        drop(sender);
        drop(driver);
        drop(server);
        signing.finish().await;
        assert_eq!(before, std::fs::read(&f.registry).unwrap());
    }
}

#[tokio::test]
async fn unknown_invitation_is_rejected_without_registry_mutation() {
    let f = fixture();
    let before = std::fs::read(&f.registry).unwrap();
    assert!(matches!(
        exchange(&f, protocol::ProofPurpose::Authorize, Some("ff".repeat(32))).await,
        wire::ExchangeResponse::Failed {
            code: wire::FailureCode::Rejected
        }
    ));
    assert_eq!(before, std::fs::read(&f.registry).unwrap());
}

#[tokio::test]
async fn actual_h2_authority_rejects_data_targets_queries_or_wrong_methods() {
    let f = fixture();
    let before = std::fs::read(&f.registry).unwrap();
    for (method, path, content, expected) in [
        ("GET", enrollment_tls::GRPC_PATH, "application/grpc", false),
        (
            "POST",
            "/enrollment.v1.Authority/Exchange?token=secret",
            "application/grpc",
            false,
        ),
        (
            "POST",
            aegis_core::secure_channel::GRPC_PATH,
            "application/grpc",
            false,
        ),
        ("POST", "/bundle?token=secret", "application/grpc", false),
        ("CONNECT", "enroll.test:443", "application/grpc", false),
        ("POST", enrollment_tls::GRPC_PATH, "application/json", false),
    ] {
        let request = http::Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", content)
            .body(())
            .unwrap();
        assert_eq!(valid_route(&request), expected);
        let prepared = Prepared::new(&f.config).unwrap();
        let (client, server) = tokio::io::duplex(8192);
        let signing = Arc::new(SigningJobs::new());
        let cloned = signing.clone();
        let mut server = crate::lifecycle::OwnedTask(tokio::spawn(async move {
            serve_h2(
                server,
                prepared.inner,
                prepared.issuer,
                cloned,
                prepared.bridge,
            )
            .await
        }));
        let (mut sender, connection) = h2::client::handshake(client).await.unwrap();
        let _driver = crate::lifecycle::OwnedTask(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let (response, _send) = sender.send_request(request, true).unwrap();
        let response = response
            .await
            .unwrap_or_else(|error| panic!("{method} {path}: {error}"));
        assert_eq!(response.status(), http::StatusCode::NOT_FOUND);
        tokio::time::timeout(Duration::from_secs(3), &mut server.0)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        signing.finish().await;
        assert_eq!(before, std::fs::read(&f.registry).unwrap());
    }
}

#[tokio::test]
async fn startup_publication_validation_refuses_before_listener_or_ready() {
    let mut f = fixture();
    // An independently owned occupied loopback port makes bind-before-validation
    // produce AddrInUse; the required result is the registry's InvalidData.
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    f.config.listen = occupied.local_addr().unwrap();
    std::fs::write(&f.registry, b"malformed registry").unwrap();
    let floor = std::fs::read(registry::floor_path(&f.registry)).unwrap();
    let (send, receive) = oneshot::channel();
    let error = tokio::time::timeout(
        Duration::from_secs(2),
        run_with_shutdown(f.config, Some(send), std::future::pending()),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::InvalidData
    );
    assert!(
        receive.await.is_err(),
        "no readiness before verified issuer state"
    );
    assert_eq!(
        std::fs::read(registry::floor_path(&f.registry)).unwrap(),
        floor
    );
    assert!(!registry::issuance_pending_path(&f.registry).exists());
}

#[test]
fn startup_publication_blocking_wait_keeps_executor_responsive_and_abort_cannot_bind() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut f = fixture();
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        f.config.listen = port.local_addr().unwrap();
        let address = f.config.listen;
        drop(port);
        let transaction = registry::RegistryTransaction::begin(&f.registry).unwrap();
        let mut successor = transaction.load().unwrap();
        successor.generation += 1;
        successor.invitations[0].consumed = true;
        let (send, mut receive) = oneshot::channel();
        let server = tokio::spawn(run_with_shutdown(
            f.config,
            Some(send),
            std::future::pending(),
        ));
        let ticker = tokio::spawn(async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            true
        });
        assert!(tokio::time::timeout(Duration::from_secs(1), ticker)
            .await
            .unwrap()
            .unwrap());
        assert!(
            !server.is_finished(),
            "startup stays pending behind the real OS publication lock"
        );
        assert!(matches!(
            receive.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        let before = std::net::TcpListener::bind(address).unwrap();
        drop(before);
        // With one blocking slot, this barrier joins behind any already-started
        // preparation, which may finish after its async owner is cancelled.
        let preparation_retired = tokio::task::spawn_blocking(|| ());
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
        assert!(
            receive.await.is_err(),
            "aborted startup cannot report READY"
        );
        transaction.save(&f.registry, &successor, false).unwrap();
        drop(transaction);
        tokio::time::timeout(Duration::from_secs(2), preparation_retired)
            .await
            .unwrap()
            .unwrap();
        let after = std::net::TcpListener::bind(address).unwrap();
        let current = registry::DeviceRegistry::load(&f.registry).unwrap();
        assert_eq!(current.generation, successor.generation);
        assert!(current.invitations[0].consumed);
        drop(after);
    });
}
