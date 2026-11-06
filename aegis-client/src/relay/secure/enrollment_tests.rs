use super::*;
use aegis_core::secure_channel::enrollment_tls;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use serde_json::json;
use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context as TaskContext, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

struct Observe<S> {
    stream: S,
    bytes: Arc<Mutex<Vec<u8>>>,
}
impl<S: AsyncRead + Unpin> AsyncRead for Observe<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.stream).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) {
            self.bytes
                .lock()
                .unwrap()
                .extend_from_slice(&buf.filled()[before..]);
        }
        result
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Observe<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[test]
fn carrier_uri_roundtrips_ipv6_without_changing_pinned_tls_identity() {
    for name in ["::1", "2001:db8::1", "127.0.0.1", "front.test"] {
        let authority = super::super::transport_authority_for_host(name, "fixture").unwrap();
        let settings = RelaySettings {
            server_name: name.into(),
            ..RelaySettings::default()
        };
        let uri = aegis_client::prepared_outer_tls::h2_carrier_request_from_held(
            &settings,
            None,
            Purpose::Enrollment,
        )
        .unwrap()
        .uri()
        .clone();
        assert_eq!(uri.path(), enrollment_tls::GRPC_PATH);
        assert_eq!(
            uri.host()
                .unwrap()
                .trim_start_matches('[')
                .trim_end_matches(']'),
            name
        );
        assert_eq!(authority.authority_host, name);
        assert_eq!(
            authority.tls_server_name,
            rustls::pki_types::ServerName::try_from(name.to_owned()).unwrap()
        );
    }
}

#[tokio::test]
async fn enrollment_carrier_authenticates_before_credentials_and_has_no_device_identity() {
    for wrong_name in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let _configs = tests::configs(path, &address);
        let bundle = path.join("bundle");
        std::fs::create_dir(&bundle).unwrap();
        for (src, dst) in [
            ("outer.pem", "outer-ca.pem"),
            ("inner-ca.pem", "inner-ca.pem"),
            ("inner-ca.pem", "device-ca.pem"),
        ] {
            std::fs::copy(path.join(src), bundle.join(dst)).unwrap();
        }
        let profile = json!({"schema":"aegis_device_bundle_v3","product_mode":"socks-only","relay_server":"relay.test:443",
            "outer_server_name":"relay.test","inner_server_name":"origin.test","udp":false,
            "enrollment":{"protocol":"aegis-enrollment-v1","authority_server":address,"outer_server_name":"localhost",
            "inner_server_name":if wrong_name {"wrong.test"} else {"inner.test"},"automatic_renewal":true,"renewal_policy":"same-key-v1"}});
        std::fs::write(
            bundle.join("bundle.json"),
            serde_json::to_vec(&profile).unwrap(),
        )
        .unwrap();
        let identity = path.join("identity");
        std::fs::create_dir(&identity).unwrap();
        crate::device_bundle::inspect(&crate::device_bundle::BundleInspectArgs {
            bundle_dir: bundle.clone(),
            identity_dir: Some(identity.clone()),
            json: false,
        })
        .unwrap();
        assert!(!identity.join("device.pem").exists() && !identity.join("device.key").exists());
        let profile =
            crate::device_bundle::online::OnlineProfile::load(&bundle, &identity).unwrap();
        let mut outer = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            CertificateDer::pem_slice_iter(&std::fs::read(path.join("outer.pem")).unwrap())
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            PrivateKeyDer::from_pem_slice(&std::fs::read(path.join("outer.key")).unwrap()).unwrap(),
        )
        .unwrap();
        outer.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(outer));
        let authority = enrollment_tls::Authority::load(&enrollment_tls::AuthoritySettings {
            cert: path.join("inner.test.pem"),
            key: path.join("inner.test.key"),
        })
        .unwrap();
        let observed = Arc::new(Mutex::new(Vec::new()));
        let captured = observed.clone();
        let secret = b"private-invitation-and-csr-only-after-pinned-enrollment-tls";
        let server = tokio::spawn(async move {
            let tls = acceptor
                .accept(listener.accept().await.unwrap().0)
                .await
                .unwrap();
            let mut h2 = h2::server::handshake(tls).await.unwrap();
            let (request, mut respond) = h2.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(request.uri().path(), enrollment_tls::GRPC_PATH);
            assert!(!request.headers().contains_key("authorization"));
            let send = respond
                .send_response(
                    http::Response::builder()
                        .header("content-type", "application/grpc")
                        .body(())
                        .unwrap(),
                    false,
                )
                .unwrap();
            let carrier = Observe {
                stream: GrpcIo::new(H2Stream::new(send, request.into_body())),
                bytes: captured,
            };
            let mut driver = Driver(tokio::spawn(async move {
                while let Some(stream) = h2.accept().await {
                    assert!(stream.is_err(), "unexpected extra carrier stream");
                }
            }));
            let result = authority.accept(carrier).await;
            if wrong_name {
                assert!(result.is_err());
            } else {
                let mut session = result.unwrap();
                let mut payload = Vec::new();
                session.read_to_end(&mut payload).await.unwrap();
                assert_eq!(payload, secret);
                session
                    .write_all(b"public-certificate-receipt")
                    .await
                    .unwrap();
                session.shutdown().await.unwrap();
            }
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), &mut driver.0).await;
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let connection = crate::relay::open_enrollment(&profile).await;
            if wrong_name {
                assert!(connection.is_err());
            } else {
                let mut connection = connection.unwrap();
                assert!(connection.deadline() > tokio::time::Instant::now());
                connection.stream_mut().write_all(secret).await.unwrap();
                connection.stream_mut().shutdown().await.unwrap();
                let mut response = Vec::new();
                connection
                    .stream_mut()
                    .read_to_end(&mut response)
                    .await
                    .unwrap();
                assert_eq!(response, b"public-certificate-receipt");
            }
            server.await.unwrap();
        })
        .await
        .unwrap();
        assert!(
            observed.lock().unwrap().len() > 64,
            "outer terminator must actually observe inner TLS records"
        );
        assert!(!observed
            .lock()
            .unwrap()
            .windows(secret.len())
            .any(|b| b == secret));
    }
}
