use super::*;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};

const FIXTURE_USER: &str = "fixture-user";
const FIXTURE_PASSWORD: &str = "synthetic-loopback-password";

async fn authenticate(client: &mut TcpStream) {
    client.write_all(&[5, 1, 2]).await.unwrap();
    let mut method = [0; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 2]);
    finish_authenticate(client).await;
}

async fn finish_authenticate(client: &mut TcpStream) {
    let mut credentials = vec![1, FIXTURE_USER.len() as u8];
    credentials.extend_from_slice(FIXTURE_USER.as_bytes());
    credentials.push(FIXTURE_PASSWORD.len() as u8);
    credentials.extend_from_slice(FIXTURE_PASSWORD.as_bytes());
    client.write_all(&credentials).await.unwrap();
    let mut status = [0; 2];
    client.read_exact(&mut status).await.unwrap();
    assert_eq!(status, [1, 0]);
}

async fn auth_backend() -> Socks5FallbackBackend {
    Socks5FallbackBackend::bind_with_auth(
        "127.0.0.1:0".parse().unwrap(),
        Some(socks5::SocksAuthCfg::from_config(
            FIXTURE_PASSWORD,
            Some(FIXTURE_USER),
        )),
        Vec::new(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn socks_admission_stalled_preauth_does_not_block_authenticated_connect() {
    let backend = Arc::new(auth_backend().await);
    let listen = backend.local_addr().unwrap();
    let server = {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move { backend.accept().await })
    };
    let mut slow = TcpStream::connect(listen).await.unwrap();
    slow.write_all(&[5, 1, 2]).await.unwrap();
    let mut selected = [0; 2];
    timeout(Duration::from_secs(1), slow.read_exact(&mut selected))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(selected, [5, 2]);
    // The first socket is now known to be accepted and waiting for credentials.
    let result = timeout(Duration::from_millis(700), async {
        let mut healthy = TcpStream::connect(listen).await.unwrap();
        authenticate(&mut healthy).await;
        healthy
            .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 1, 187])
            .await
            .unwrap();
        let intent = server.await.unwrap().unwrap();
        assert_eq!(intent.kind, IngressKind::Socks5Fallback);
        match intent.transport {
            IngressTransport::TcpConnect(intent) => {
                assert_eq!(intent.target.host, "127.0.0.1");
                assert_eq!(intent.target.port, 443);
                assert_eq!(intent.response, IngressResponse::Socks5);
            }
            _ => panic!("expected authenticated CONNECT"),
        }
    })
    .await;
    backend.shutdown().await;
    result.expect("one stalled unauthenticated socket must not block a valid second client");
}

#[tokio::test]
async fn socks_admission_stalled_request_does_not_block_legacy_udp_associate() {
    let backend = Arc::new(
        Socks5FallbackBackend::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap(),
    );
    let listen = backend.local_addr().unwrap();
    let server = {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move { backend.accept().await })
    };
    let mut slow = TcpStream::connect(listen).await.unwrap();
    slow.write_all(&[5, 1, 0]).await.unwrap();
    let mut selected = [0; 2];
    timeout(Duration::from_secs(1), slow.read_exact(&mut selected))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(selected, [5, 0]);
    let result = timeout(Duration::from_millis(700), async {
        let mut healthy = TcpStream::connect(listen).await.unwrap();
        healthy.write_all(&[5, 1, 0]).await.unwrap();
        let mut selected = [0; 2];
        healthy.read_exact(&mut selected).await.unwrap();
        assert_eq!(selected, [5, 0]);
        healthy
            .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let intent = server.await.unwrap().unwrap();
        match intent.transport {
            IngressTransport::UdpAssociate(intent) => {
                assert!(matches!(intent.control, UdpSessionControl::SocksControl(_)));
                assert_eq!(intent.client_ip, "127.0.0.1".parse::<IpAddr>().unwrap());
                assert_eq!(intent.response, IngressResponse::Socks5);
            }
            _ => panic!("expected legacy UDP ASSOCIATE"),
        }
    })
    .await;
    backend.shutdown().await;
    result.expect("one stalled request must not block a valid UDP ASSOCIATE client");
}

#[tokio::test]
async fn socks_admission_silent_peer_expires_and_listener_recovers() {
    let mut configured = auth_backend().await;
    configured.negotiation_timeout = Duration::from_millis(200);
    let backend = Arc::new(configured);
    let listen = backend.local_addr().unwrap();
    let server = {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move { backend.accept().await })
    };
    let mut silent = TcpStream::connect(listen).await.unwrap();
    let err = timeout(Duration::from_secs(1), server)
        .await
        .unwrap()
        .unwrap()
        .err()
        .expect("negotiation must fail");
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    assert!(err.to_string().starts_with("socks5_negotiation_deadline:"));
    let mut closed = [0; 1];
    assert_eq!(
        timeout(Duration::from_secs(1), silent.read(&mut closed))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(backend.pending.lock().await.is_empty());
    let server = {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move { backend.accept().await })
    };
    timeout(Duration::from_secs(1), async {
        let mut healthy = TcpStream::connect(listen).await.unwrap();
        authenticate(&mut healthy).await;
        healthy
            .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 1, 187])
            .await
            .unwrap();
        assert!(matches!(
            server.await.unwrap().unwrap().transport,
            IngressTransport::TcpConnect(_)
        ));
    })
    .await
    .expect("expired negotiation must release capacity for valid clients");
    backend.shutdown().await;
}

#[tokio::test]
async fn socks_admission_deadline_does_not_restart_after_authentication() {
    let mut configured = auth_backend().await;
    configured.negotiation_timeout = Duration::from_millis(500);
    let backend = Arc::new(configured);
    let listen = backend.local_addr().unwrap();
    let server = {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move { backend.accept().await })
    };
    let mut client = TcpStream::connect(listen).await.unwrap();
    client.write_all(&[5, 1, 2]).await.unwrap();
    let mut selected = [0; 2];
    timeout(Duration::from_secs(1), client.read_exact(&mut selected))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(selected, [5, 2]);
    tokio::time::sleep(Duration::from_millis(300)).await;
    finish_authenticate(&mut client).await;
    // The authenticated client now stalls before its request. A fresh 500 ms
    // request timer would miss this 300 ms cutoff; the accept-origin timer must fire.
    let err = timeout(Duration::from_millis(300), server)
        .await
        .expect("authentication must not restart the total deadline")
        .unwrap()
        .err()
        .expect("negotiation must fail");
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    assert!(err.to_string().starts_with("socks5_negotiation_deadline:"));
    backend.shutdown().await;
}

#[tokio::test]
async fn socks_admission_trickled_greeting_does_not_extend_accept_origin_deadline() {
    let mut configured = auth_backend().await;
    configured.negotiation_timeout = Duration::from_millis(500);
    let backend = Arc::new(configured);
    let listen = backend.local_addr().unwrap();
    let server = {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move { backend.accept().await })
    };
    let mut client = TcpStream::connect(listen).await.unwrap();
    client.write_all(&[5]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    client.write_all(&[1]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    client.write_all(&[2]).await.unwrap();
    let mut selected = [0; 2];
    timeout(Duration::from_millis(300), client.read_exact(&mut selected))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(selected, [5, 2]);
    let err = timeout(Duration::from_millis(300), server)
        .await
        .expect("trickled bytes must not extend the admission lifetime")
        .unwrap()
        .err()
        .expect("negotiation must fail");
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    backend.shutdown().await;
}

#[tokio::test]
async fn socks_admission_saturation_rejects_overflow_and_recovers() {
    let mut configured = auth_backend().await;
    assert_eq!(configured.max_pending_negotiations, 64);
    assert_eq!(configured.negotiation_timeout, Duration::from_secs(10));
    configured.max_pending_negotiations = 2;
    let backend = Arc::new(configured);
    let listen = backend.local_addr().unwrap();
    let server = {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move { backend.accept().await })
    };
    let mut slow = Vec::new();
    for _ in 0..2 {
        let mut client = TcpStream::connect(listen).await.unwrap();
        client.write_all(&[5, 1, 2]).await.unwrap();
        let mut selected = [0; 2];
        timeout(Duration::from_secs(1), client.read_exact(&mut selected))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(selected, [5, 2]);
        slow.push(client);
    }
    let mut excess = TcpStream::connect(listen).await.unwrap();
    let err = timeout(Duration::from_secs(1), server)
        .await
        .unwrap()
        .unwrap()
        .err()
        .expect("negotiation must fail");
    assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    assert!(err.to_string().starts_with("socks5_negotiation_limit:"));
    assert_eq!(backend.pending.lock().await.len(), 2);
    let mut closed = [0; 1];
    assert_eq!(
        timeout(Duration::from_secs(1), excess.read(&mut closed))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    drop(slow);
    for _ in 0..2 {
        let err = timeout(Duration::from_secs(1), backend.accept())
            .await
            .unwrap()
            .err()
            .expect("negotiation must fail");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert!(err.to_string().starts_with("socks5_handshake:"));
    }
    assert!(backend.pending.lock().await.is_empty());
    let server = {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move { backend.accept().await })
    };
    timeout(Duration::from_secs(1), async {
        let mut healthy = TcpStream::connect(listen).await.unwrap();
        authenticate(&mut healthy).await;
        healthy
            .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 1, 187])
            .await
            .unwrap();
        assert!(matches!(
            server.await.unwrap().unwrap().transport,
            IngressTransport::TcpConnect(_)
        ));
    })
    .await
    .expect("released negotiation slots must accept valid clients again");
    backend.shutdown().await;
}

#[tokio::test]
async fn socks_admission_accept_cancellation_preserves_handshake_and_shutdown_closes_pending() {
    let backend = Arc::new(auth_backend().await);
    let listen = backend.local_addr().unwrap();
    let server = {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move { backend.accept().await })
    };
    let mut client = TcpStream::connect(listen).await.unwrap();
    client.write_all(&[5, 1, 2]).await.unwrap();
    let mut selected = [0; 2];
    timeout(Duration::from_secs(1), client.read_exact(&mut selected))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(selected, [5, 2]);
    server.abort();
    assert!(server
        .await
        .err()
        .expect("negotiation must fail")
        .is_cancelled());
    assert_eq!(backend.pending.lock().await.len(), 1);
    let server = {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move { backend.accept().await })
    };
    timeout(Duration::from_secs(1), async {
        finish_authenticate(&mut client).await;
        client
            .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 1, 187])
            .await
            .unwrap();
        assert!(matches!(
            server.await.unwrap().unwrap().transport,
            IngressTransport::TcpConnect(_)
        ));
    })
    .await
    .expect("resuming accept must preserve the original negotiation");
    let server = {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move { backend.accept().await })
    };
    let mut pending = TcpStream::connect(listen).await.unwrap();
    pending.write_all(&[5, 1, 2]).await.unwrap();
    timeout(Duration::from_secs(1), pending.read_exact(&mut selected))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(selected, [5, 2]);
    server.abort();
    assert!(server
        .await
        .err()
        .expect("negotiation must fail")
        .is_cancelled());
    backend.shutdown().await;
    assert!(backend.pending.lock().await.is_empty());
    let mut closed = [0; 1];
    assert_eq!(
        timeout(Duration::from_secs(1), pending.read(&mut closed))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}
