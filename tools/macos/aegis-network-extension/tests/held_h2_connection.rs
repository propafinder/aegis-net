#![cfg(feature = "apple")]

use aegis_client::prepared_outer_tls::connect_h2_from_held;
use aegis_core::{
    https_bridge::Purpose, secure_channel::ClientSettings, RelaySettings, RelayTlsBackend,
    TunnelTransportFamily,
};
use bytes::Bytes;
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    },
    TlsAcceptor,
};

fn settings() -> RelaySettings {
    RelaySettings {
        server_name: "localhost".into(),
        ca_cert: Some("/private/tmp/no-such-outer-ca".into()),
        inner_tls: Some(ClientSettings {
            server_name: "origin.test".into(),
            server_ca: "/private/tmp/no-such-inner-ca".into(),
            cert: "/private/tmp/no-such-device-pem".into(),
            key: "/private/tmp/no-such-device-key".into(),
        }),
        transport_priority: vec![TunnelTransportFamily::GrpcStream],
        udp_transport_priority: Some(vec![TunnelTransportFamily::GrpcDatagram]),
        tls_backend: RelayTlsBackend::Rustls,
        ..RelaySettings::default()
    }
}

fn acceptor(cert: &rcgen::CertifiedKey, alpn: &[u8]) -> TlsAcceptor {
    let mut server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der())),
        )
        .unwrap();
    server.alpn_protocols = vec![alpn.to_vec()];
    TlsAcceptor::from(Arc::new(server))
}

#[tokio::test]
async fn held_ca_dials_real_tls_h2_and_retains_unspawned_driver() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let ca = cert.cert.pem().into_bytes();
    let acceptor = acceptor(&cert, b"h2");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = acceptor.accept(tcp).await.unwrap();
        let mut connection = h2::server::handshake(tls).await.unwrap();
        let (request, mut response) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.uri().path(), aegis_core::secure_channel::GRPC_PATH);
        let mut body = response
            .send_response(
                http::Response::builder()
                    .status(200)
                    .header("content-type", "application/grpc")
                    .body(())
                    .unwrap(),
                false,
            )
            .unwrap();
        body.send_data(Bytes::new(), true).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), connection.accept()).await;
    });
    let tcp = TcpStream::connect(address).await.unwrap();
    let connection = tokio::time::timeout(
        Duration::from_secs(3),
        connect_h2_from_held(&settings(), &ca, None, Purpose::Traffic, tcp),
    )
    .await
    .unwrap()
    .unwrap();
    let (stream, driver) = connection.into_parts();
    drop(stream);
    drop(driver);
    server.await.unwrap();
}

#[tokio::test]
async fn held_h2_driver_carries_payload_and_reaches_terminal_after_peer_close() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let ca = cert.cert.pem().into_bytes();
    let acceptor = acceptor(&cert, b"h2");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (client_done, server_done) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = acceptor.accept(tcp).await.unwrap();
        let mut connection = h2::server::handshake(tls).await.unwrap();
        let (request, mut response) = connection.accept().await.unwrap().unwrap();
        let mut inbound = request.into_body();
        let mut outbound = response
            .send_response(
                http::Response::builder()
                    .status(200)
                    .header("content-type", "application/grpc")
                    .body(())
                    .unwrap(),
                false,
            )
            .unwrap();
        let pump = tokio::spawn(async move {
            let _ = tokio::time::timeout(Duration::from_secs(2), connection.accept()).await;
        });
        let frame = tokio::time::timeout(Duration::from_secs(2), inbound.data())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(frame.as_ref(), b"\0\0\0\0\x04ping");
        outbound
            .send_data(Bytes::from_static(b"\0\0\0\0\x04pong"), true)
            .unwrap();
        let _ = server_done.await;
        pump.abort();
        let _ = pump.await;
    });
    let tcp = TcpStream::connect(address).await.unwrap();
    let connection = tokio::time::timeout(
        Duration::from_secs(3),
        connect_h2_from_held(&settings(), &ca, None, Purpose::Traffic, tcp),
    )
    .await
    .unwrap()
    .unwrap();
    let (mut stream, driver) = connection.into_parts();
    let driver = tokio::spawn(driver);
    tokio::time::timeout(Duration::from_secs(2), async {
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        let mut answer = [0; 4];
        stream.read_exact(&mut answer).await.unwrap();
        assert_eq!(&answer, b"pong");
    })
    .await
    .unwrap();
    client_done.send(()).unwrap();
    drop(stream);
    server.await.unwrap();
    let _terminal = tokio::time::timeout(Duration::from_secs(2), driver)
        .await
        .expect("H2 driver remained detached after peer close")
        .expect("H2 driver task panicked");
}

#[tokio::test]
async fn held_h2_response_stall_exhausts_original_connect_budget() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let ca = cert.cert.pem().into_bytes();
    let acceptor = acceptor(&cert, b"h2");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = acceptor.accept(tcp).await.unwrap();
        let mut connection = h2::server::handshake(tls).await.unwrap();
        let (_request, _response) = connection.accept().await.unwrap().unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
    });
    let mut relay = settings();
    relay.connect_timeout_ms = 30;
    let tcp = TcpStream::connect(address).await.unwrap();
    let error = tokio::time::timeout(
        Duration::from_secs(1),
        connect_h2_from_held(&relay, &ca, None, Purpose::Traffic, tcp),
    )
    .await
    .expect("the held dial ignored its outer test deadline")
    .err()
    .expect("stalled carrier response was admitted");
    assert!(error.to_string().contains("connect deadline exhausted"));
    server.await.unwrap();
}

#[tokio::test]
async fn live_tls_without_h2_alpn_refuses_before_h2_request() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let ca = cert.cert.pem().into_bytes();
    let acceptor = acceptor(&cert, b"http/1.1");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        if let Ok(tls) = acceptor.accept(tcp).await {
            assert_ne!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        }
    });
    let tcp = TcpStream::connect(address).await.unwrap();
    assert!(tokio::time::timeout(
        Duration::from_secs(3),
        connect_h2_from_held(&settings(), &ca, None, Purpose::Traffic, tcp)
    )
    .await
    .unwrap()
    .is_err());
    server.await.unwrap();
}
