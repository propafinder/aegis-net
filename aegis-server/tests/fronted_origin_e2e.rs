//! CDN-fronted, device-enrolled origin through a local CDN-like gRPC edge.
//!
//! client -> edge (own TLS, HTTP/2 only, no RFC 8441, injected origin key,
//! one pooled origin connection) -> aegis-server fronted origin -> inner
//! device mTLS -> TCP/UDP target, plus same-port enrollment ("variant B")
//! forwarded to a real enrollment authority. Refusals are checked at the
//! edge, at the origin and at inner TLS.

#[path = "../../tests/support/cdn_grpc_proxy.rs"]
mod cdn;

use aegis_core::h2_stream::H2Stream;
use aegis_core::secure_channel::{
    self, datagram, enrollment, enrollment::protocol, enrollment_tls, enrollment_wire as wire,
    grpc_io::GrpcIo, registry,
};
use bytes::Bytes;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const EDGE: &str = "relay.edge.test";
const INNER: &str = "inner.relay.test";
const AUTHORITY_OUTER: &str = "enroll.internal.test";
const AUTHORITY_INNER: &str = "enroll.inner.test";
const ORIGIN_KEY: [u8; 64] = [b'7'; 64];

struct Ca {
    cert: Certificate,
    key: KeyPair,
}

fn ca(name: &str) -> Ca {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    params.distinguished_name.push(DnType::CommonName, name);
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let cert = params.self_signed(&key).unwrap();
    Ca { cert, key }
}

fn leaf(ca: &Ca, names: &[&str], usage: ExtendedKeyUsagePurpose) -> (String, String, String) {
    let mut params =
        CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>()).unwrap();
    params.extended_key_usages = vec![usage];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let cert = params.signed_by(&key, &ca.cert, &ca.key).unwrap();
    (
        cert.pem(),
        key.serialize_pem(),
        hex::encode(Sha256::digest(cert.der().as_ref())),
    )
}

fn private(path: &Path, bytes: &[u8]) -> PathBuf {
    enrollment::write_private_new(path, bytes).unwrap();
    path.to_owned()
}

struct Owned<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for Owned<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Stack {
    dir: tempfile::TempDir,
    edge_ca: String,
    origin_ca: String,
    origin: SocketAddr,
    edge: cdn::Edge,
    device: secure_channel::ClientSettings,
    rogue_device: secure_channel::ClientSettings,
    enroll_client: enrollment_tls::ClientSettings,
    invitation: PathBuf,
    issuer_ca: String,
    _server: Owned<anyhow::Result<()>>,
    _authority: Owned<anyhow::Result<()>>,
}

async fn stack(read_timeout_ms: u64, faults: cdn::Faults, inject_key: bool) -> Stack {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let edge_ca = ca("edge public CA");
    let origin_ca = ca("origin pull CA");
    let inner_ca = ca("inner relay CA");
    let rogue_ca = ca("rogue device CA");
    let authority_ca = ca("authority CA");
    let issuer = ca("device issuer CA");

    let (edge_pem, edge_key, _) = leaf(&edge_ca, &[EDGE], ExtendedKeyUsagePurpose::ServerAuth);
    let (origin_pem, origin_key_pem, _) =
        leaf(&origin_ca, &[EDGE], ExtendedKeyUsagePurpose::ServerAuth);
    let (inner_pem, inner_key, _) = leaf(&inner_ca, &[INNER], ExtendedKeyUsagePurpose::ServerAuth);
    let (device_pem, device_key, device_sha) = leaf(
        &inner_ca,
        &["device-a"],
        ExtendedKeyUsagePurpose::ClientAuth,
    );
    let (rogue_pem, rogue_key, _) = leaf(
        &rogue_ca,
        &["device-a"],
        ExtendedKeyUsagePurpose::ClientAuth,
    );
    let (authority_pem, authority_key, _) = leaf(
        &authority_ca,
        &[AUTHORITY_OUTER, AUTHORITY_INNER],
        ExtendedKeyUsagePurpose::ServerAuth,
    );

    let origin_cert = private(&d.join("origin.pem"), origin_pem.as_bytes());
    let origin_key = private(&d.join("origin.key"), origin_key_pem.as_bytes());
    let inner_cert = private(&d.join("inner.pem"), inner_pem.as_bytes());
    let inner_key_path = private(&d.join("inner.key"), inner_key.as_bytes());
    let inner_ca_path = private(&d.join("inner-ca.pem"), inner_ca.cert.pem().as_bytes());
    let origin_pull = private(&d.join("origin-pull.key"), &ORIGIN_KEY);
    let authority_cert = private(&d.join("authority.pem"), authority_pem.as_bytes());
    let authority_key_path = private(&d.join("authority.key"), authority_key.as_bytes());
    let authority_ca_path = private(
        &d.join("authority-ca.pem"),
        authority_ca.cert.pem().as_bytes(),
    );
    let issuer_ca_path = private(&d.join("issuer-ca.pem"), issuer.cert.pem().as_bytes());
    let issuer_key_path = private(&d.join("issuer.key"), issuer.key.serialize_pem().as_bytes());

    // Real enrollment authority on its own loopback listener.
    let registry_path = d.join("registry.json");
    aegis_server::devices::initialize(&registry_path).unwrap();
    let invitation = d.join("invitation");
    aegis_server::devices::invite(
        &registry_path,
        "device-a",
        &invitation,
        300,
        registry::unix_now().unwrap(),
    )
    .unwrap();
    // The authority requires an explicit nonzero port.
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let authority_listen = reservation.local_addr().unwrap();
    drop(reservation);
    let authority_config = aegis_server::enrollment_service::AuthorityConfig {
        https_bridge: None,
        listen: authority_listen,
        outer_cert: authority_cert.clone(),
        outer_key: authority_key_path.clone(),
        inner_tls: enrollment_tls::AuthoritySettings {
            cert: authority_cert,
            key: authority_key_path,
        },
        issuer: serde_json::from_value(serde_json::json!({
            "registry": registry_path, "ca_cert": issuer_ca_path, "ca_key": issuer_key_path,
            "profile_sha256": "02".repeat(32), "lifetime_secs": 3600, "max_receipts": 16,
            "max_receipt_bytes_total": 1048576, "receipt_grace_secs": 60
        }))
        .unwrap(),
    };
    let (authority_ready, authority_address) = tokio::sync::oneshot::channel();
    let authority = Owned(tokio::spawn(
        aegis_server::enrollment_service::run_with_shutdown(
            authority_config,
            Some(authority_ready),
            std::future::pending(),
        ),
    ));
    let authority_address = match tokio::time::timeout(Duration::from_secs(5), authority_address)
        .await
        .unwrap()
    {
        Ok(address) => address,
        Err(_) => panic!(
            "authority startup failed: {:?}",
            (&mut { authority }.0).await
        ),
    };

    let config = format!(
        r#"
listen = '127.0.0.1:0'
cert = '{origin_cert}'
key = '{origin_key}'
fallback = 'close'
[limits]
read_timeout_ms = {read_timeout_ms}
[rate_limit]
trusted_proxy_cidrs = ['127.0.0.1/32']
[target_policy]
profile = 'full_vpn_egress'
[transport]
quic_required = false
[transport.inner_tls]
cert = '{inner_cert}'
key = '{inner_key}'
client_ca = '{inner_ca}'
allowed_client_sha256 = ['{device_sha}']
handshake_timeout_ms = 3000
idle_timeout_ms = 3000
[transport.fronted_origin]
authority = '{EDGE}'
credential_file = '{origin_pull}'
[transport.fronted_origin.enrollment_forward]
authority_address = '{authority_address}'
server_name = '{AUTHORITY_OUTER}'
ca = '{authority_ca}'
"#,
        origin_cert = origin_cert.display(),
        origin_key = origin_key.display(),
        inner_cert = inner_cert.display(),
        inner_key = inner_key_path.display(),
        inner_ca = inner_ca_path.display(),
        origin_pull = origin_pull.display(),
        authority_ca = authority_ca_path.display(),
    );
    let server_config: aegis_server::config::ServerConfig = toml::from_str(&config).unwrap();
    server_config.validate_auth_tokens().unwrap();
    let (ready, address) = tokio::sync::oneshot::channel();
    let server = Owned(tokio::spawn(
        aegis_server::run_server_with_bound_ready_and_shutdown(
            server_config,
            ready,
            std::future::pending(),
        ),
    ));
    let origin = tokio::time::timeout(Duration::from_secs(5), address)
        .await
        .unwrap()
        .unwrap();
    let edge = cdn::start(cdn::EdgeConfig {
        listen: None,
        edge_cert_pem: edge_pem,
        edge_key_pem: edge_key,
        origin,
        origin_server_name: EDGE.into(),
        origin_ca_pem: origin_ca.cert.pem(),
        origin_key: inject_key.then(|| ORIGIN_KEY.to_vec()),
        faults,
    })
    .await;
    let device = secure_channel::ClientSettings {
        server_name: INNER.into(),
        server_ca: inner_ca_path.clone(),
        cert: private(&d.join("device.pem"), device_pem.as_bytes()),
        key: private(&d.join("device.key"), device_key.as_bytes()),
    };
    let rogue_device = secure_channel::ClientSettings {
        server_name: INNER.into(),
        server_ca: inner_ca_path,
        cert: private(&d.join("rogue.pem"), rogue_pem.as_bytes()),
        key: private(&d.join("rogue.key"), rogue_key.as_bytes()),
    };
    let enroll_client = enrollment_tls::ClientSettings {
        server_name: AUTHORITY_INNER.into(),
        server_ca: authority_ca_path,
    };
    Stack {
        edge_ca: edge_ca.cert.pem(),
        origin_ca: origin_ca.cert.pem(),
        origin,
        edge,
        device,
        rogue_device,
        enroll_client,
        invitation,
        issuer_ca: issuer.cert.pem(),
        _server: server,
        _authority: authority,
        dir,
    }
}

type Sender = h2::client::SendRequest<Bytes>;

/// Client-side HTTP/2 to `address`, verifying `ca_pem` for the edge name.
async fn h2_client(address: SocketAddr, ca_pem: &str) -> (Sender, Owned<()>) {
    use rustls::pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls::pki_types::CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
    let tls = tokio_rustls::TlsConnector::from(Arc::new(tls))
        .connect(rustls::pki_types::ServerName::try_from(EDGE).unwrap(), tcp)
        .await
        .unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let (sender, connection) = h2::client::handshake(tls).await.unwrap();
    let driver = Owned(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let sender = sender.ready().await.unwrap();
    (sender, driver)
}

fn grpc_request(path: &str, key: Option<&[u8]>) -> http::Request<()> {
    let mut request = http::Request::builder()
        .method("POST")
        .uri(format!("https://{EDGE}{path}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .unwrap();
    if let Some(key) = key {
        request.headers_mut().insert(
            cdn::ORIGIN_KEY_HEADER,
            http::HeaderValue::from_bytes(key).unwrap(),
        );
    }
    request
}

/// Open the fixed traffic route and return its gRPC byte carrier.
async fn carrier(
    sender: &mut Sender,
    key: Option<&[u8]>,
) -> Result<GrpcIo<H2Stream>, http::StatusCode> {
    let (response, send) = sender
        .send_request(grpc_request(secure_channel::GRPC_PATH, key), false)
        .unwrap();
    let response = response.await.unwrap();
    if response.status() != http::StatusCode::OK
        || response.headers().get("content-type").map(|v| v.as_bytes())
            != Some(b"application/grpc".as_slice())
    {
        return Err(response.status());
    }
    Ok(GrpcIo::new(H2Stream::new(send, response.into_body())))
}

async fn tcp_echo_target() -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>, Owned<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = accepted.clone();
    let task = Owned(tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = vec![0; 64 * 1024];
                loop {
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        let _ = socket.shutdown().await;
                        break;
                    }
                    socket.write_all(&buf[..n]).await.unwrap();
                }
            });
        }
    }));
    (address, accepted, task)
}

async fn open(
    inner: &mut tokio_rustls::client::TlsStream<GrpcIo<H2Stream>>,
    target: SocketAddr,
    transport: secure_channel::Transport,
) -> u8 {
    secure_channel::write_open(
        inner,
        &secure_channel::OpenRequest {
            version: 1,
            host: target.ip().to_string(),
            port: target.port(),
            transport,
        },
    )
    .await
    .unwrap();
    inner.read_u8().await.unwrap()
}

#[tokio::test]
async fn fronted_tcp_and_udp_reach_targets_through_cdn_edge_with_inner_device_mtls() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let s = stack(5_000, cdn::Faults::default(), true).await;
        let (target, accepted, _target) = tcp_echo_target().await;
        let (mut sender, _driver) = h2_client(s.edge.address, &s.edge_ca).await;
        assert!(
            !sender.is_extended_connect_protocol_enabled(),
            "edge never offers RFC 8441"
        );
        let client = secure_channel::Client::load(&s.device).unwrap();

        // TCP: 256 KiB of patterned bytes echoed through the whole chain.
        let mut inner = client
            .connect(carrier(&mut sender, None).await.unwrap())
            .await
            .unwrap();
        assert_eq!(
            open(&mut inner, target, secure_channel::Transport::Tcp).await,
            0
        );
        let payload: Vec<u8> = (0..256 * 1024).map(|i| (i * 31 % 251) as u8).collect();
        let (mut reader, mut writer) = tokio::io::split(inner);
        let expected = payload.clone();
        let echo = tokio::spawn(async move {
            let mut received = Vec::new();
            reader.read_to_end(&mut received).await.unwrap();
            received
        });
        writer.write_all(&payload).await.unwrap();
        writer.shutdown().await.unwrap();
        assert!(
            echo.await.unwrap() == expected,
            "exact TCP echo through CDN edge"
        );
        assert_eq!(accepted.load(Ordering::SeqCst), 1);

        // UDP (grpc_datagram over the same fronted H2 path): message boundaries kept.
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_target = udp.local_addr().unwrap();
        let _udp_task = Owned(tokio::spawn(async move {
            let mut buf = vec![0; 65_535];
            loop {
                let (n, from) = udp.recv_from(&mut buf).await.unwrap();
                udp.send_to(&buf[..n], from).await.unwrap();
            }
        }));
        let mut inner = client
            .connect(carrier(&mut sender, None).await.unwrap())
            .await
            .unwrap();
        assert_eq!(
            open(&mut inner, udp_target, secure_channel::Transport::Udp).await,
            0
        );
        for message in [b"".to_vec(), b"dns-like query".to_vec(), vec![0x42; 8000]] {
            datagram::write(&mut inner, &message).await.unwrap();
            assert_eq!(datagram::read(&mut inner).await.unwrap().unwrap(), message);
        }
        inner.shutdown().await.unwrap();
        let mut rest = Vec::new();
        let _ = inner.read_to_end(&mut rest).await;

        // Both client streams shared ONE pooled origin connection, and the
        // origin ended its gRPC responses with grpc-status trailers.
        assert_eq!(s.edge.stats.origin_connections.load(Ordering::SeqCst), 1);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(s.edge.stats.origin_trailers.load(Ordering::SeqCst) >= 1);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn direct_origin_hits_and_missing_cdn_transform_get_decoys_before_inner_tls() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let s = stack(5_000, cdn::Faults::default(), true).await;
        // Direct to the origin, bypassing the CDN: no key, wrong key, and even
        // a correct path with a forged-but-wrong key all receive the decoy.
        let (mut direct, _driver) = h2_client(s.origin, &s.origin_ca).await;
        assert!(
            !direct.is_extended_connect_protocol_enabled(),
            "fronted origin never offers RFC 8441"
        );
        for key in [
            None,
            Some([b'8'; 64].as_slice()),
            Some([b'7'; 63].as_slice()),
        ] {
            let status = carrier(&mut direct, key).await.err().expect("decoy");
            assert!(
                matches!(status.as_u16(), 403 | 404 | 410),
                "decoy status, got {status}"
            );
        }
        // Even with the correct key, other paths/methods never reach inner TLS.
        let (response, _) = direct
            .send_request(grpc_request("/", Some(&ORIGIN_KEY)), true)
            .unwrap();
        assert_ne!(response.await.unwrap().status(), http::StatusCode::OK);
        let mut connect = http::Request::builder()
            .method("CONNECT")
            .uri(format!("https://{EDGE}{}", secure_channel::GRPC_PATH))
            .body(())
            .unwrap();
        connect.headers_mut().insert(
            cdn::ORIGIN_KEY_HEADER,
            http::HeaderValue::from_bytes(&ORIGIN_KEY).unwrap(),
        );
        if let Ok((response, _)) = direct.send_request(connect, false) {
            if let Ok(response) = response.await {
                assert_ne!(response.status(), http::StatusCode::OK);
            }
        }
        // HTTP/1.1 directly at the origin: decoy page, never a tunnel.
        let mut tls = {
            use rustls::pki_types::pem::PemObject;
            let mut roots = rustls::RootCertStore::empty();
            for cert in rustls::pki_types::CertificateDer::pem_slice_iter(s.origin_ca.as_bytes()) {
                roots.add(cert.unwrap()).unwrap();
            }
            let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
            cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
            tokio_rustls::TlsConnector::from(Arc::new(cfg))
                .connect(
                    rustls::pki_types::ServerName::try_from(EDGE).unwrap(),
                    tokio::net::TcpStream::connect(s.origin).await.unwrap(),
                )
                .await
                .unwrap()
        };
        tls.write_all(
            format!(
                "POST {} HTTP/1.1\r\nHost: {EDGE}\r\ncontent-type: application/grpc\r\n\r\n",
                secure_channel::GRPC_PATH
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut reply = Vec::new();
        let _ = tls.read_to_end(&mut reply).await;
        let reply = String::from_utf8_lossy(&reply);
        assert!(reply.starts_with("HTTP/1.1 4"), "{reply}");

        // Through an edge whose request transform is missing: decoy, too.
        let bare = stack(5_000, cdn::Faults::default(), false).await;
        let (mut sender, _driver) = h2_client(bare.edge.address, &bare.edge_ca).await;
        let status = carrier(&mut sender, None).await.err().expect("decoy");
        assert!(matches!(status.as_u16(), 403 | 404 | 410), "{status}");
        // A client cannot smuggle the origin key through the edge either.
        let bare_status = carrier(&mut sender, Some(&ORIGIN_KEY)).await.err();
        assert!(
            bare_status.is_some(),
            "edge strips client-supplied origin keys"
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn rfc8441_extended_connect_is_refused_at_the_edge() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let s = stack(5_000, cdn::Faults::default(), true).await;
        let (mut sender, _driver) = h2_client(s.edge.address, &s.edge_ca).await;
        assert!(!sender.is_extended_connect_protocol_enabled());
        let mut request = http::Request::builder()
            .method("CONNECT")
            .uri(format!("https://{EDGE}/ws"))
            .body(())
            .unwrap();
        request
            .extensions_mut()
            .insert(h2::ext::Protocol::from_static("websocket"));
        // h2 refuses locally when the peer never enabled the protocol; if a
        // client sent it anyway, the edge answers without contacting origin.
        match sender.send_request(request, false) {
            Err(_) => {}
            Ok((response, _)) => {
                if let Ok(response) = response.await {
                    assert_ne!(response.status(), http::StatusCode::OK);
                }
            }
        }
        let plain_connect = http::Request::builder()
            .method("CONNECT")
            .uri(format!("{EDGE}:443"))
            .body(())
            .unwrap();
        let (response, _) = sender.send_request(plain_connect, false).unwrap();
        assert_eq!(
            response.await.unwrap().status(),
            http::StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(s.edge.stats.origin_connections.load(Ordering::SeqCst), 0);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn wrong_device_certificate_is_refused_by_inner_tls_after_cdn_admission() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let s = stack(5_000, cdn::Faults::default(), true).await;
        let (target, accepted, _target) = tcp_echo_target().await;
        let (mut sender, _driver) = h2_client(s.edge.address, &s.edge_ca).await;
        let rogue = secure_channel::Client::load(&s.rogue_device).unwrap();
        let result = async {
            let mut inner = rogue
                .connect(carrier(&mut sender, None).await.unwrap())
                .await?;
            secure_channel::write_open(
                &mut inner,
                &secure_channel::OpenRequest {
                    version: 1,
                    host: target.ip().to_string(),
                    port: target.port(),
                    transport: secure_channel::Transport::Tcp,
                },
            )
            .await?;
            inner.read_u8().await
        }
        .await;
        assert!(result.is_err(), "unknown device issuer must be refused");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            0,
            "no target was contacted"
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn variant_b_enrollment_redeems_through_cdn_edge_and_relay_forwarder() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let s = stack(5_000, cdn::Faults::default(), true).await;
        let (mut sender, _driver) = h2_client(s.edge.address, &s.edge_ca).await;
        let (response, send) = sender
            .send_request(grpc_request(enrollment_tls::GRPC_PATH, None), false)
            .unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        let carrier = GrpcIo::new(H2Stream::new(send, response.into_body()));
        // End-to-end enrollment TLS: the relay forwards only opaque bytes.
        let mut session = enrollment_tls::Client::load(&s.enroll_client)
            .unwrap()
            .connect(carrier)
            .await
            .unwrap();
        let identity = enrollment::generate_csr("device-a").unwrap();
        let challenge = wire::read_challenge(&mut session).await.unwrap();
        let binding = protocol::RequestBinding {
            operation: protocol::Operation::Redeem,
            request_id: "01".repeat(32),
            profile_sha256: "02".repeat(32),
            csr_sha256: hex::encode(Sha256::digest(identity.csr_pem.as_bytes())),
            predecessor_sha256: None,
        };
        let signature = protocol::sign_proof(
            identity.private_key_pem.as_bytes(),
            &challenge,
            &binding,
            protocol::ProofPurpose::Authorize,
            registry::unix_now().unwrap(),
        )
        .unwrap();
        wire::write_request(
            &mut session,
            &wire::ExchangeRequest {
                binding,
                purpose: protocol::ProofPurpose::Authorize,
                csr_pem: identity.csr_pem.clone(),
                predecessor_certificate_pem: None,
                invitation: Some(std::fs::read_to_string(&s.invitation).unwrap()),
                signature: hex::encode(signature),
            },
        )
        .await
        .unwrap();
        let wire::ExchangeResponse::Issued { receipt } =
            wire::read_response(&mut session).await.unwrap()
        else {
            panic!("issuance through the fronted forwarder was rejected")
        };
        enrollment::validate_device_certificate(
            "device-a",
            receipt.certificate_pem.as_bytes(),
            s.issuer_ca.as_bytes(),
            identity.private_key_pem.as_bytes(),
            registry::unix_now().unwrap(),
        )
        .unwrap();
        // The relay process never held the issuer key: it is not in its config.
        assert!(s.dir.path().join("issuer.key").exists());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn pooled_cdn_connection_admits_a_late_stream_with_its_own_budget() {
    // One origin connection is shared by independent CDN clients. A stream
    // that starts shortly before that connection's idle admission deadline
    // must keep its own budget, and the connection must drain, not abort it.
    tokio::time::timeout(Duration::from_secs(30), async {
        let s = stack(1_000, cdn::Faults::default(), true).await;
        let (target, _accepted, _target) = tcp_echo_target().await;
        let client = secure_channel::Client::load(&s.device).unwrap();
        let (mut sender, _driver) = h2_client(s.edge.address, &s.edge_ca).await;
        let started = tokio::time::Instant::now();
        let mut first = client
            .connect(carrier(&mut sender, None).await.unwrap())
            .await
            .unwrap();
        assert_eq!(
            open(&mut first, target, secure_channel::Transport::Tcp).await,
            0
        );
        first.write_all(b"one").await.unwrap();
        first.flush().await.unwrap();
        let mut echoed = [0u8; 3];
        first.read_exact(&mut echoed).await.unwrap();
        first.shutdown().await.unwrap();
        let mut rest = Vec::new();
        let _ = first.read_to_end(&mut rest).await;
        drop(first);
        // Start the next stream ~0.85 s in, then hold its inner ClientHello
        // until after the pooled connection's idle deadline (~1.0 s).
        tokio::time::sleep_until(started + Duration::from_millis(850)).await;
        let late = carrier(&mut sender, None).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        let mut second = client
            .connect(late)
            .await
            .expect("late stream keeps its own budget");
        assert_eq!(
            open(&mut second, target, secure_channel::Transport::Tcp).await,
            0
        );
        second.write_all(b"two").await.unwrap();
        second.flush().await.unwrap();
        second.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"two");
        assert_eq!(s.edge.stats.origin_connections.load(Ordering::SeqCst), 1);
    })
    .await
    .unwrap();
}
