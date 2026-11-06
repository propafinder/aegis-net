use super::*;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Fixture {
    _dir: tempfile::TempDir,
    client: ClientSettings,
    authority: AuthoritySettings,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let mut ca_params = CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let mut params = CertificateParams::new(vec!["enroll.test".into()]).unwrap();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let cert = params.signed_by(&key, &ca, &ca_key).unwrap();
    let ca_path = dir.path().join("ca.pem");
    let cert_path = dir.path().join("authority.pem");
    let key_path = dir.path().join("authority.key");
    std::fs::write(&ca_path, ca.pem()).unwrap();
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    Fixture {
        client: ClientSettings {
            server_name: "enroll.test".into(),
            server_ca: ca_path,
        },
        authority: AuthoritySettings {
            cert: cert_path,
            key: key_path,
        },
        _dir: dir,
    }
}

#[tokio::test]
async fn pinned_enrollment_hides_credentials_from_its_carrier() {
    let f = fixture();
    let client = Client::load(&f.client).unwrap();
    let server = Authority::load(&f.authority).unwrap();
    let (c, mut upstream) = tokio::io::duplex(97);
    let (mut downstream, s) = tokio::io::duplex(101);
    let capture = Arc::new(std::sync::Mutex::new(Vec::new()));
    let saved = capture.clone();
    let proxy = tokio::spawn(async move {
        let (mut cr, mut cw) = tokio::io::split(&mut upstream);
        let (mut sr, mut sw) = tokio::io::split(&mut downstream);
        let copy = async {
            let mut bytes = [0; 137];
            loop {
                let n = cr.read(&mut bytes).await?;
                if n == 0 {
                    sw.shutdown().await?;
                    break;
                }
                saved.lock().unwrap().extend_from_slice(&bytes[..n]);
                sw.write_all(&bytes[..n]).await?;
            }
            io::Result::Ok(())
        };
        tokio::try_join!(copy, tokio::io::copy(&mut sr, &mut cw)).unwrap();
    });
    let secret = b"one-use-invitation-and-private-device-csr";
    let serving = tokio::spawn(async move {
        let mut stream = server.accept(s).await.unwrap();
        assert_eq!(
            stream.stream.get_ref().1.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        assert!(stream.stream.get_ref().1.peer_certificates().is_none());
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, secret);
        stream.write_all(b"public-response").await.unwrap();
        stream.shutdown().await.unwrap();
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut stream = client.connect(c).await.unwrap();
        stream.write_all(secret).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"public-response");
        drop(stream);
        serving.await.unwrap();
        proxy.await.unwrap();
    })
    .await
    .unwrap();
    assert!(!capture
        .lock()
        .unwrap()
        .windows(secret.len())
        .any(|b| b == secret));
}

#[tokio::test]
async fn substituted_ca_and_authority_name_fail_before_application_io() {
    let f = fixture();
    let other = fixture();
    for settings in [
        ClientSettings {
            server_ca: other.client.server_ca.clone(),
            ..f.client.clone()
        },
        ClientSettings {
            server_name: "wrong.test".into(),
            ..f.client.clone()
        },
    ] {
        let client = Client::load(&settings).unwrap();
        let server = Authority::load(&f.authority).unwrap();
        let (c, s) = tokio::io::duplex(8192);
        let (cr, sr) = tokio::join!(client.connect(c), server.accept(s));
        assert!(cr.is_err());
        assert!(sr.is_err());
    }
}

#[tokio::test]
async fn missing_or_different_enrollment_alpn_is_rejected() {
    for alpn in [vec![], vec![b"h2".to_vec()]] {
        let f = fixture();
        let mut client = Client::load(&f.client).unwrap();
        Arc::make_mut(&mut client.config).alpn_protocols = alpn;
        let server = Authority::load(&f.authority).unwrap();
        let (c, s) = tokio::io::duplex(8192);
        let (cr, sr) = tokio::join!(client.connect(c), server.accept(s));
        assert!(cr.is_err());
        assert!(sr.is_err());
    }
}

#[tokio::test]
async fn bootstrap_identity_cannot_get_a_data_plane_lease() {
    let f = fixture();
    let client = Client::load(&f.client).unwrap();
    let server = super::super::Server::load(&super::super::ServerSettings {
        cert: f.authority.cert.clone(),
        key: f.authority.key.clone(),
        client_ca: f.client.server_ca.clone(),
        allowed_client_sha256: vec!["00".repeat(32)],
        device_registry: None,
        admission: Default::default(),
        handshake_timeout_ms: 1000,
        idle_timeout_ms: 1000,
    })
    .unwrap();
    let (c, s) = tokio::io::duplex(8192);
    let (cr, sr) = tokio::join!(client.connect(c), server.accept_with_lease(s));
    assert!(cr.is_err());
    assert!(sr.is_err());
}

#[tokio::test]
async fn tls12_only_peer_cannot_redeem() {
    let f = fixture();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS12])
    .unwrap()
    .with_root_certificates(load_trust_roots(&f.client.server_ca).unwrap())
    .with_no_client_auth();
    config.alpn_protocols = vec![ALPN.to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server = Authority::load(&f.authority).unwrap();
    let (c, s) = tokio::io::duplex(8192);
    let (cr, sr) = tokio::join!(
        connector.connect(ServerName::try_from("enroll.test").unwrap(), c),
        server.accept(s)
    );
    assert!(cr.is_err());
    assert!(sr.is_err());
}

#[tokio::test(start_paused = true)]
async fn silent_handshake_releases_capacity_and_cancel_is_bounded() {
    let f = fixture();
    let mut server = Authority::load(&f.authority).unwrap();
    server.sessions = Arc::new(Semaphore::new(1));
    let (_c, s) = tokio::io::duplex(8192);
    let result = server.accept(s).await;
    assert_eq!(result.err().unwrap().kind(), io::ErrorKind::TimedOut);
    assert_eq!(server.sessions.available_permits(), 1);
    let (_c, s) = tokio::io::duplex(8192);
    let clone = server.clone();
    let task = tokio::spawn(async move { clone.accept(s).await });
    tokio::task::yield_now().await;
    assert_eq!(server.sessions.available_permits(), 0);
    let (_c, s) = tokio::io::duplex(8192);
    assert_eq!(
        server.accept(s).await.err().unwrap().kind(),
        io::ErrorKind::WouldBlock
    );
    task.abort();
    assert!(matches!(task.await, Err(error) if error.is_cancelled()));
    assert_eq!(server.sessions.available_permits(), 1);
}

#[tokio::test(start_paused = true)]
async fn session_deadline_is_absolute_for_pending_reads_and_writes() {
    let (c, mut s) = tokio::io::duplex(8);
    let mut stream = Session::new(c, None);
    let deadline = stream.deadline();
    stream.write_all(b"before").await.unwrap();
    let mut bytes = [0; 6];
    s.read_exact(&mut bytes).await.unwrap();
    tokio::time::advance(Duration::from_secs(29)).await;
    stream.write_all(b"active").await.unwrap();
    s.read_exact(&mut bytes).await.unwrap();
    assert_eq!(stream.deadline(), deadline);
    assert_eq!(
        stream.read_u8().await.unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(
        stream.write_u8(1).await.unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
}

#[tokio::test]
async fn active_session_holds_capacity_until_drop() {
    let f = fixture();
    let client = Client::load(&f.client).unwrap();
    let mut server = Authority::load(&f.authority).unwrap();
    server.sessions = Arc::new(Semaphore::new(1));
    let (c, s) = tokio::io::duplex(8192);
    let (cr, sr) = tokio::join!(client.connect(c), server.accept(s));
    let _client_stream = cr.unwrap();
    let server_stream = sr.unwrap();
    assert_eq!(server.sessions.available_permits(), 0);
    let (_c, s) = tokio::io::duplex(8192);
    assert_eq!(
        server.accept(s).await.err().unwrap().kind(),
        io::ErrorKind::WouldBlock
    );
    drop(server_stream);
    assert_eq!(server.sessions.available_permits(), 1);
}
