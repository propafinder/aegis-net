//! Negative TLS/H2 fixture coverage; no production transport claims.
#![cfg(unix)]

use aegis_core::secure_channel::{Server, ServerSettings};
use aegis_transport_lab::https_bridge::{serve_loopback, BridgeGate, BridgeLimits};
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::{io::Write, os::unix::fs::OpenOptionsExt, sync::Arc, time::Duration};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_rustls::TlsConnector;

struct Fixture {
    _dir: tempfile::TempDir,
    outer_server: Arc<rustls::ServerConfig>,
    outer_client: Arc<rustls::ClientConfig>,
    inner_server: Server,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let mut params = CertificateParams::new(vec!["bridge.test".into()]).unwrap();
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let cert = params.signed_by(&key, &ca, &ca_key).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut outer_server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
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
    std::fs::write(dir.path().join("ca.pem"), ca.pem()).unwrap();
    std::fs::write(dir.path().join("inner.pem"), cert.pem()).unwrap();
    let mut private = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dir.path().join("inner.key"))
        .unwrap();
    private.write_all(key.serialize_pem().as_bytes()).unwrap();
    drop(private);
    // No carrier is created by this test, so no device certificate is needed.
    let inner_server = Server::load(&ServerSettings {
        cert: dir.path().join("inner.pem"),
        key: dir.path().join("inner.key"),
        client_ca: dir.path().join("ca.pem"),
        allowed_client_sha256: vec!["00".repeat(32)],
        device_registry: None,
        admission: Default::default(),
        handshake_timeout_ms: 500,
        idle_timeout_ms: 500,
    })
    .unwrap();
    Fixture {
        _dir: dir,
        outer_server: Arc::new(outer_server),
        outer_client: Arc::new(outer_client),
        inner_server,
    }
}

#[tokio::test]
async fn h2_connection_protocol_error_is_not_a_completed_connection() {
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
            connection_time: Duration::from_secs(1),
            ..BridgeLimits::default()
        },
    ));
    let socket = TcpStream::connect(address).await.unwrap();
    let mut tls = TlsConnector::from(f.outer_client.clone())
        .connect(ServerName::try_from("bridge.test").unwrap(), socket)
        .await
        .unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    tls.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .unwrap();
    tls.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await.unwrap(); // Empty SETTINGS.
                                                                // DATA on stream zero is an H2 connection PROTOCOL_ERROR.
    tls.write_all(&[0, 0, 0, 0, 0, 0, 0, 0, 0]).await.unwrap();
    tls.flush().await.unwrap();
    let summary = timeout(Duration::from_secs(2), serving)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(summary.accepted_connections, 1);
    assert_eq!(
        summary.failed_connections, 1,
        "invalid H2 is a failed connection"
    );
    assert_eq!(summary.completed_connections, 0);
    assert_eq!(summary.gated_carriers, 0);
    assert_eq!(summary.authenticated_echoes, 0);
    assert!(summary.counts_may_be_incomplete);
    assert!(TcpStream::connect(address).await.is_err());
}
