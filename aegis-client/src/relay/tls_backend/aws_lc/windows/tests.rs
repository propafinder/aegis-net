use super::*;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::PrivatePkcs8KeyDer;
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn fixture(dir: &Path) -> (RelaySettings, tokio_rustls::TlsAcceptor) {
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let path = dir.join("доверенный-сертификат.pem");
    std::fs::write(&path, cert.pem()).unwrap();
    let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into(),
    )
    .unwrap();
    server.alpn_protocols = vec![b"h2".to_vec()];
    (
        RelaySettings {
            ca_cert: Some(path),
            ..Default::default()
        },
        tokio_rustls::TlsAcceptor::from(Arc::new(server)),
    )
}

#[tokio::test]
async fn stale_thread_error_queue_does_not_poison_another_session() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let dir = tempfile::tempdir().unwrap();
        let (settings, acceptor) = fixture(dir.path());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            tls.write_all(b"done").await.unwrap();
        });
        let mut tls = Stream::new(
            TcpStream::connect(address).await.unwrap(),
            settings.ca_cert.as_deref(),
            "localhost",
            &[b"h2".to_vec()],
            true,
            None,
        )
        .unwrap();
        unsafe {
            let bad = [0u8];
            let mut input = bad.as_ptr();
            assert!(ssl::d2i_X509(std::ptr::null_mut(), &mut input, 1).is_null());
            assert_ne!(ssl::ERR_peek_last_error(), 0);
        }
        std::future::poll_fn(|cx| tls.poll_handshake(cx))
            .await
            .unwrap();
        let mut reply = [0; 4];
        tls.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"done");
        server.await.unwrap();
    })
    .await
    .expect("TLS error-queue isolation deadline");
}

#[tokio::test]
async fn unicode_ca_large_request_and_reply_after_half_close() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let dir = tempfile::tempdir().unwrap();
        let (settings, acceptor) = fixture(dir.path());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let payload: Vec<u8> = (0..2 * 1024 * 1024).map(|n| (n % 251) as u8).collect();
        let expected = payload.clone();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let mut request = Vec::new();
            tls.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, expected);
            tls.write_all(&request).await.unwrap();
            tls.shutdown().await.unwrap();
        });
        let (mut tls, alpn) = connect_aws_lc_tls_with_alpn_protocols(
            &settings,
            TcpStream::connect(address).await.unwrap(),
            "localhost",
            &[b"h2".to_vec()],
            true,
        )
        .await
        .unwrap();
        assert_eq!(alpn.as_deref(), Some(b"h2".as_slice()));
        tls.write_all(&payload).await.unwrap();
        tls.shutdown().await.unwrap();
        let mut reply = Vec::new();
        tls.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, payload);
        server.await.unwrap();
    })
    .await
    .expect("TLS half-close deadline");
}

#[tokio::test]
async fn full_duplex_progress_under_backpressure() {
    tokio::time::timeout(Duration::from_secs(25), async {
        let dir = tempfile::tempdir().unwrap();
        let (settings, acceptor) = fixture(dir.path());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        const SIZE: usize = 8 * 1024 * 1024;
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            // Both peers write more than a socket buffer. Client reading must
            // make progress while its own outbound ciphertext is congested.
            tls.write_all(&vec![19; SIZE]).await.unwrap();
            tls.flush().await.unwrap();
            let mut request = vec![0; SIZE];
            tls.read_exact(&mut request).await.unwrap();
            assert!(request.iter().all(|v| *v == 7));
        });
        let (tls, _) = connect_aws_lc_tls_with_alpn_protocols(
            &settings,
            TcpStream::connect(address).await.unwrap(),
            "localhost",
            &[b"h2".to_vec()],
            true,
        )
        .await
        .unwrap();
        let (mut reader, mut writer) = tokio::io::split(tls);
        let read = async {
            let mut data = vec![0; SIZE];
            reader.read_exact(&mut data).await.unwrap();
            assert!(data.iter().all(|v| *v == 19));
        };
        let write = async {
            writer.write_all(&vec![7; SIZE]).await.unwrap();
            writer.flush().await.unwrap();
        };
        tokio::join!(read, write);
        server.await.unwrap();
    })
    .await
    .expect("TLS duplex deadline");
}

#[tokio::test]
async fn rejects_untrusted_certificate_wrong_dns_name_and_wrong_ip() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let dir = tempfile::tempdir().unwrap();
        let (settings, acceptor) = fixture(dir.path());
        for (trust, name) in [
            (false, "localhost"),
            (true, "wrong.test"),
            (true, "127.0.0.1"),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let acceptor = acceptor.clone();
            let server = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.unwrap();
                let _ = acceptor.accept(tcp).await;
            });
            let mut settings = settings.clone();
            if !trust {
                settings.ca_cert = None;
            }
            let result = connect_aws_lc_tls_with_alpn_protocols(
                &settings,
                TcpStream::connect(address).await.unwrap(),
                name,
                &[b"h2".to_vec()],
                true,
            )
            .await;
            assert!(result.is_err(), "untrusted peer accepted: {name}");
            server.abort();
            let _ = server.await;
        }
    })
    .await
    .expect("TLS rejection deadline");
}

#[tokio::test]
async fn emitted_tcp_clienthello_preserves_chrome_profile() {
    use aegis_quic_boring::fingerprint::clienthello::{ext, parse};
    tokio::time::timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let _ = connect_aws_lc_tls_with_alpn_protocols(
                &RelaySettings::default(),
                TcpStream::connect(address).await.unwrap(),
                "example.com",
                &[b"h2".to_vec(), b"http/1.1".to_vec()],
                true,
            )
            .await;
        });
        let (mut tcp, _) = listener.accept().await.unwrap();
        let mut header = [0; 5];
        tcp.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], 22);
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        assert!(length < 16384);
        let mut record = vec![0; length];
        tcp.read_exact(&mut record).await.unwrap();
        let hello = parse(&record).unwrap();
        assert!(hello.uses_grease());
        assert_eq!(hello.max_version(), 0x0304);
        assert_eq!(hello.server_name.as_deref(), Some("example.com"));
        assert_eq!(hello.alpn, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
        assert!(hello.supported_groups.contains(&0x11ec));
        assert!(!hello.has_extension(ext::QUIC_TRANSPORT_PARAMETERS));
        client.abort();
        let _ = client.await;
    })
    .await
    .expect("ClientHello deadline");
}
