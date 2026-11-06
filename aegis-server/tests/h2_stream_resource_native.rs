//! Loopback TLS verification of relay SETTINGS and reset-driven stream reuse.
//! This does not measure RSS or adversarial clients that ignore SETTINGS.

use aegis_server::config::ServerConfig;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use std::future::Future;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;

const STAGE: Duration = Duration::from_secs(3);
struct OwnedTask<T>(JoinHandle<T>);
impl<T> Drop for OwnedTask<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::test]
async fn relay_tls_h2_stream_settings_bound_preauth_and_resets_release_slots() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(tls));
    let mut cfg = ServerConfig {
        listen: "127.0.0.1:0".into(),
        cert: cert_path,
        key: key_path,
        // Synthetic fixture-only value.
        auth_token: "af7e3598d0ce822bd30c46f087e6019cb45256315ad54f885d3244e8c239a1c7".into(),
        legacy_auth_tokens: Vec::new(),
        process_alias: None,
        logging: Default::default(),
        fallback: "close".into(),
        limits: Default::default(),
        rate_limit: Default::default(),
        target_policy: Default::default(),
        transport: Default::default(),
        bundle_endpoint: Default::default(),
    };
    cfg.limits.read_timeout_ms = 10_000;
    cfg.limits.shutdown_grace_ms = 20;
    let path = cfg.transport.grpc_path.clone();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let mut server = OwnedTask(tokio::spawn(
        aegis_server::run_server_with_bound_ready_and_shutdown(cfg, ready_tx, async move {
            let _ = stop_rx.await;
        }),
    ));
    let addr = match tokio::time::timeout(STAGE, ready_rx)
        .await
        .expect("bounded readiness")
    {
        Ok(addr) => addr,
        Err(error) => panic!(
            "relay readiness failed: {error}; server: {:?}",
            tokio::time::timeout(STAGE, &mut server.0).await
        ),
    };
    let tcp = tokio::time::timeout(STAGE, TcpStream::connect(addr))
        .await
        .unwrap()
        .unwrap();
    let tls = tokio::time::timeout(
        STAGE,
        connector.connect("localhost".to_string().try_into().unwrap(), tcp),
    )
    .await
    .unwrap()
    .unwrap();
    let (mut sender, mut connection) = tokio::time::timeout(STAGE, h2::client::handshake(tls))
        .await
        .unwrap()
        .unwrap();
    let maximum = Arc::new(AtomicUsize::new(usize::MAX));
    let observed = maximum.clone();
    let mut ping = connection.ping_pong().unwrap();
    let mut driver = OwnedTask(tokio::spawn(std::future::poll_fn(move |cx| {
        let result = std::pin::Pin::new(&mut connection).poll(cx);
        observed.store(connection.max_concurrent_send_streams(), Ordering::SeqCst);
        result
    })));
    tokio::time::timeout(STAGE, ping.ping(h2::Ping::opaque()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        maximum.load(Ordering::SeqCst),
        32,
        "real relay SETTINGS advertise the preauth cap"
    );
    let mut open = Vec::new();
    for _ in 0..32 {
        tokio::time::timeout(STAGE, std::future::poll_fn(|cx| sender.poll_ready(cx)))
            .await
            .unwrap()
            .unwrap();
        let request = http::Request::builder()
            .method("POST")
            .uri(&path)
            .header("content-type", "application/grpc")
            .body(())
            .unwrap();
        // No inner credentials or body: these remain unauthenticated.
        open.push(sender.send_request(request, false).unwrap());
    }
    tokio::time::timeout(STAGE, ping.ping(h2::Ping::opaque()))
        .await
        .unwrap()
        .unwrap();
    let request = http::Request::builder().uri("/").body(()).unwrap();
    let (mut response, _) = sender.send_request(request, true).unwrap();
    // h2 queues a new stream locally until SETTINGS permits it. The decoy
    // would respond immediately if admitted; it needs no credentials or body.
    assert!(
        tokio::time::timeout(Duration::from_millis(150), &mut response)
            .await
            .is_err(),
        "32 open streams exhaust server-advertised admission"
    );
    open[0].1.send_reset(h2::Reason::CANCEL);
    tokio::time::timeout(STAGE, ping.ping(h2::Ping::opaque()))
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(STAGE, std::future::poll_fn(|cx| sender.poll_ready(cx)))
        .await
        .expect("resets reclaim stream capacity")
        .unwrap();
    let response = tokio::time::timeout(STAGE, response)
        .await
        .unwrap()
        .unwrap();
    assert!(
        [301, 403, 404, 410].contains(&response.status().as_u16()),
        "same connection serves a fresh decoy request after reset churn"
    );
    drop(response);
    for (_, send) in &mut open {
        send.send_reset(h2::Reason::CANCEL);
    }
    drop(open);
    drop(sender);
    stop_tx.send(()).unwrap();
    tokio::time::timeout(STAGE, &mut server.0)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    driver.0.abort();
    if let Err(error) = tokio::time::timeout(STAGE, &mut driver.0).await.unwrap() {
        assert!(
            error.is_cancelled(),
            "driver joins or is explicitly cancelled"
        );
    }
}
