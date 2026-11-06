//! Actual loopback QUIC/H3 component for the new held carrier API. All keys
//! stay in memory; the public CA, client leaf and exact authority are supplied
//! through the same production PreparedQuicClient boundary.
use super::*;
use bytes::Buf;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::PrivatePkcs8KeyDer;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const BUDGET: Duration = Duration::from_secs(8);
const UP: &[u8] = b"held-quic-uplink";
const DOWN: &[u8] = b"held-quic-downlink";

struct DropFlag(Arc<AtomicBool>);
impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

struct Signer {
    ca: Certificate,
    key: KeyPair,
}

impl Signer {
    fn new() -> anyhow::Result<Self> {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        Ok(Self {
            ca: params.self_signed(&key)?,
            key,
        })
    }

    fn leaf(
        &self,
        names: Vec<String>,
        purpose: ExtendedKeyUsagePurpose,
    ) -> anyhow::Result<(Certificate, KeyPair)> {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::new(names)?;
        params.extended_key_usages = vec![purpose];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        Ok((params.signed_by(&key, &self.ca, &self.key)?, key))
    }
}

struct Fixture {
    endpoint: quinn::Endpoint,
    server_ca: String,
    client_cert: String,
    client_key: String,
    request_count: Arc<AtomicUsize>,
}

impl Fixture {
    fn new() -> anyhow::Result<Self> {
        let server_ca = Signer::new()?;
        let client_ca = Signer::new()?;
        let (server_cert, server_key) = server_ca.leaf(
            vec!["localhost".into(), "127.0.0.1".into()],
            ExtendedKeyUsagePurpose::ServerAuth,
        )?;
        let (client_cert, client_key) = client_ca.leaf(
            vec!["device.test".into()],
            ExtendedKeyUsagePurpose::ClientAuth,
        )?;
        let mut client_roots = rustls::RootCertStore::empty();
        client_roots.add(client_ca.ca.der().clone())?;
        // The client and this fixture both pin ring. Do not depend on the
        // process-wide provider when the lock enables two rustls backends.
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(client_roots),
            provider.clone(),
        )
        .build()?;
        let mut tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![server_cert.der().clone(), server_ca.ca.der().clone()],
                PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
            )?;
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
        let endpoint = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(crypto)),
            "127.0.0.1:0".parse()?,
        )?;
        Ok(Self {
            endpoint,
            server_ca: server_ca.ca.pem(),
            client_cert: format!("{}{}", client_cert.pem(), client_ca.ca.pem()),
            client_key: client_key.serialize_pem(),
            request_count: Arc::new(AtomicUsize::new(0)),
        })
    }

    fn client(&self) -> anyhow::Result<PreparedQuicClient> {
        PreparedQuicClient::from_held(
            self.server_ca.as_bytes(),
            self.client_cert.as_bytes(),
            self.client_key.as_bytes(),
        )
    }

    fn peer(&self) -> SocketAddr {
        self.endpoint.local_addr().expect("loopback endpoint")
    }

    fn socket() -> UdpSocket {
        UdpSocket::bind("127.0.0.1:0").expect("bound client socket")
    }

    fn serve(&self, echo: bool) -> tokio::task::JoinHandle<anyhow::Result<()>> {
        let endpoint = self.endpoint.clone();
        let count = self.request_count.clone();
        tokio::spawn(async move {
            let incoming = endpoint
                .accept()
                .await
                .ok_or_else(|| anyhow::anyhow!("server closed"))?;
            eprintln!("QUIC_STAGE server_accepted");
            let conn = match incoming.await {
                Ok(conn) => conn,
                Err(_) => return Ok(()),
            };
            eprintln!("QUIC_STAGE server_connected");
            let mut builder = h3::server::builder();
            builder.enable_extended_connect(true);
            let mut h3 = builder
                .build::<_, Bytes>(h3_quinn::Connection::new(conn.clone()))
                .await?;
            let Some(resolver) = h3.accept().await? else {
                return Ok(());
            };
            let (request, mut stream) = resolver.resolve_request().await?;
            eprintln!("QUIC_STAGE server_request");
            count.fetch_add(1, Ordering::SeqCst);
            ensure!(request.method() == http::Method::CONNECT, "wrong H3 method");
            ensure!(
                request
                    .uri()
                    .authority()
                    .is_some_and(|authority| authority.as_str() == SECURE_QUIC_AUTHORITY),
                "wrong H3 authority"
            );
            stream.send_response(http::Response::new(())).await?;
            eprintln!("QUIC_STAGE server_response");
            if echo {
                let mut up = Vec::new();
                while let Some(mut frame) = stream.recv_data().await? {
                    ensure!(up.len() + frame.remaining() <= 128, "uplink bound");
                    up.extend_from_slice(&frame.copy_to_bytes(frame.remaining()));
                }
                ensure!(up == UP, "uplink bytes changed");
                eprintln!("QUIC_STAGE server_uplink_fin");
                stream.send_data(Bytes::from_static(DOWN)).await?;
                stream.finish().await?;
                eprintln!("QUIC_STAGE server_downlink_fin");
                // Retain the server H3/QUIC owner until the held client's
                // driver has drained and closed its endpoint.
                let _ = conn.closed().await;
                eprintln!("QUIC_STAGE server_closed");
            } else {
                ensure!(
                    matches!(
                        conn.closed().await,
                        quinn::ConnectionError::ApplicationClosed(_)
                    ),
                    "held endpoint did not close the accepted connection"
                );
                eprintln!("QUIC_STAGE server_closed");
            }
            Ok(())
        })
    }
}

struct AbortOnDrop<T>(Option<tokio::task::JoinHandle<T>>);
impl<T> AbortOnDrop<T> {
    fn new(task: tokio::task::JoinHandle<T>) -> Self {
        Self(Some(task))
    }
    async fn join(&mut self) -> Result<T, tokio::task::JoinError> {
        let result = self.0.as_mut().expect("owned task").await;
        self.0.take();
        result
    }
}
impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}

#[tokio::test]
async fn held_quic_real_h3_dns_and_ip_transfer_reverse_fin() {
    for tls_name in ["localhost", "127.0.0.1"] {
        tokio::time::timeout(BUDGET, async {
            let fixture = Fixture::new().unwrap();
            let mut server = AbortOnDrop::new(fixture.serve(true));
            let dropped = Arc::new(AtomicBool::new(false));
            let anchor: Arc<dyn Send + Sync> = Arc::new(DropFlag(dropped.clone()));
            let held = fixture
                .client()
                .unwrap()
                .connect(
                    fixture.peer(),
                    tls_name,
                    Fixture::socket(),
                    Duration::from_secs(4),
                    anchor,
                )
                .await
                .unwrap();
            eprintln!("QUIC_STAGE client_connected");
            let (mut app, driver) = held.into_parts();
            let mut driver = AbortOnDrop::new(tokio::spawn(driver));
            app.write_all(UP).await.unwrap();
            eprintln!("QUIC_STAGE client_uplink_written");
            app.shutdown().await.unwrap();
            eprintln!("QUIC_STAGE client_uplink_fin");
            let mut response = Vec::new();
            app.read_to_end(&mut response).await.unwrap();
            eprintln!("QUIC_STAGE client_downlink_fin");
            assert_eq!(response, DOWN);
            driver.join().await.unwrap().unwrap();
            eprintln!("QUIC_STAGE client_driver_joined");
            server.join().await.unwrap().unwrap();
            eprintln!("QUIC_STAGE client_server_joined");
            assert_eq!(fixture.request_count.load(Ordering::SeqCst), 1);
            tokio::time::timeout(Duration::from_secs(2), async {
                while !dropped.load(Ordering::SeqCst) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            fixture
                .endpoint
                .close(quinn::VarInt::from_u32(0), b"fixture done");
        })
        .await
        .expect("real held H3 transfer bounded");
    }
}

#[tokio::test]
async fn held_quic_real_h3_refuses_wrong_ca_name_and_client_certificate() {
    for refusal in ["ca", "name", "client"] {
        tokio::time::timeout(BUDGET, async {
            let fixture = Fixture::new().unwrap();
            let mut server = AbortOnDrop::new(fixture.serve(false));
            let signer = Signer::new().unwrap();
            let mut ca = fixture.server_ca.clone();
            let mut cert = fixture.client_cert.clone();
            let mut key = fixture.client_key.clone();
            let name = if refusal == "name" {
                "wrong.test"
            } else {
                "localhost"
            };
            if refusal == "ca" {
                ca = signer.ca.pem();
            }
            if refusal == "client" {
                let (wrong, wrong_key) = signer
                    .leaf(
                        vec!["wrong-device.test".into()],
                        ExtendedKeyUsagePurpose::ClientAuth,
                    )
                    .unwrap();
                cert = format!("{}{}", wrong.pem(), signer.ca.pem());
                key = wrong_key.serialize_pem();
            }
            let prepared =
                PreparedQuicClient::from_held(ca.as_bytes(), cert.as_bytes(), key.as_bytes())
                    .unwrap();
            let result = prepared
                .connect(
                    fixture.peer(),
                    name,
                    Fixture::socket(),
                    Duration::from_secs(3),
                    Arc::new(()),
                )
                .await;
            assert!(result.is_err(), "{refusal} must fail before H3 200");
            fixture
                .endpoint
                .close(quinn::VarInt::from_u32(0), b"refusal complete");
            // A failed TLS handshake can finish before accept sees close. A
            // timeout keeps the JoinHandle in its abort-on-drop owner.
            let _ = tokio::time::timeout(Duration::from_secs(1), server.join()).await;
            assert_eq!(fixture.request_count.load(Ordering::SeqCst), 0);
        })
        .await
        .expect("real held H3 refusal bounded");
    }
}

#[tokio::test]
async fn held_quic_driver_drop_before_first_poll_closes_endpoint_and_anchor() {
    tokio::time::timeout(BUDGET, async {
        let fixture = Fixture::new().unwrap();
        let mut server = AbortOnDrop::new(fixture.serve(false));
        let dropped = Arc::new(AtomicBool::new(false));
        let anchor: Arc<dyn Send + Sync> = Arc::new(DropFlag(dropped.clone()));
        let held = fixture
            .client()
            .unwrap()
            .connect(
                fixture.peer(),
                "localhost",
                Fixture::socket(),
                Duration::from_secs(4),
                anchor,
            )
            .await
            .unwrap();
        eprintln!("QUIC_STAGE prefirst_connected");
        let (app, driver) = held.into_parts();
        drop(driver);
        drop(app);
        eprintln!("QUIC_STAGE prefirst_driver_dropped");
        tokio::time::timeout(Duration::from_secs(2), async {
            while !dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        eprintln!("QUIC_STAGE prefirst_anchor_dropped");
        server.join().await.unwrap().unwrap();
        eprintln!("QUIC_STAGE prefirst_server_joined");
        assert_eq!(fixture.request_count.load(Ordering::SeqCst), 1);
        fixture
            .endpoint
            .close(quinn::VarInt::from_u32(0), b"driver dropped");
    })
    .await
    .expect("prefirst-poll owner drop bounded");
}
