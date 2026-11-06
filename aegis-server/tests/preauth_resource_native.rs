//! Bounded loopback acceptance of the real TCP/TLS relay entry.
//! This checks socket-cap reclamation and an accept-origin deadline, not RSS
//! under distributed load or installed-host behavior.

use aegis_server::config::{ServerConfig, TargetPolicyConfig, TargetPolicyProfile};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;

const ADMISSION: Duration = Duration::from_millis(400);
const STAGE: Duration = Duration::from_secs(3);
// Synthetic fixture-only credential; no operational secret is used.
const TOKEN: &str = "af7e3598d0ce822bd30c46f087e6019cb45256315ad54f885d3244e8c239a1c7";

struct OwnedServer(JoinHandle<anyhow::Result<()>>);

impl Drop for OwnedServer {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::test]
async fn dripping_tls_socket_expires_and_releases_peer_cap() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().expect("fixture directory");
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".into()]).expect("fixture cert");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.pem()).expect("write cert");
    std::fs::write(&key_path, key_pair.serialize_pem()).expect("write key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).expect("trust fixture cert");
    let connector = TlsConnector::from(Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));
    let mut cfg = ServerConfig {
        listen: "127.0.0.1:0".into(),
        cert: cert_path,
        key: key_path,
        auth_token: TOKEN.into(),
        legacy_auth_tokens: Vec::new(),
        process_alias: None,
        logging: Default::default(),
        fallback: "close".into(),
        limits: Default::default(),
        rate_limit: Default::default(),
        target_policy: TargetPolicyConfig {
            profile: TargetPolicyProfile::FullVpnEgress,
            allowed_ports: Vec::new(),
        },
        transport: Default::default(),
        bundle_endpoint: Default::default(),
    };
    cfg.limits.read_timeout_ms = ADMISSION.as_millis() as u64;
    cfg.limits.max_unauthenticated_connections_per_ip = 1;
    cfg.limits.max_connections = 2;
    cfg.limits.shutdown_grace_ms = 20;

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let mut server = OwnedServer(tokio::spawn(async move {
        aegis_server::run_server_with_bound_ready_and_shutdown(cfg, ready_tx, async move {
            let _ = stop_rx.await;
        })
        .await
    }));
    let ready = tokio::time::timeout(STAGE, ready_rx)
        .await
        .expect("bounded relay readiness");
    let addr = match ready {
        Ok(addr) => addr,
        Err(error) => panic!(
            "relay did not bind: {error}; server result: {:?}",
            tokio::time::timeout(STAGE, &mut server.0).await
        ),
    };

    let start = tokio::time::Instant::now();
    let mut stalled = tokio::time::timeout(STAGE, TcpStream::connect(addr))
        .await
        .expect("stalled connect bound")
        .expect("stalled connect");
    stalled.write_all(&[0x16]).await.expect("first TLS byte");
    tokio::time::sleep_until(start + Duration::from_millis(40)).await;

    // The first socket is still in TLS admission, so this second socket from
    // the same kernel peer must be closed by the pre-auth socket cap.
    let mut capped = tokio::time::timeout(STAGE, TcpStream::connect(addr))
        .await
        .expect("cap probe connect bound")
        .expect("cap probe connect");
    let capped_read = tokio::time::timeout(Duration::from_millis(80), capped.read(&mut [0u8; 1]))
        .await
        .expect("second socket did not close under cap");
    assert!(
        matches!(capped_read, Ok(0) | Err(_)),
        "second socket remained admitted"
    );

    for (offset_ms, byte) in [(190, 0x03), (340, 0x03)] {
        tokio::time::sleep_until(start + Duration::from_millis(offset_ms)).await;
        stalled.write_all(&[byte]).await.expect("drip TLS byte");
    }
    // Each gap stays below 400 ms, while the final byte is late enough that
    // a broken per-byte reset would keep the socket alive past this cutoff.
    // The correct accept-origin deadline is 400 ms; a reset at 340 ms is 740.
    let close = tokio::time::timeout_at(
        start + Duration::from_millis(590),
        stalled.read(&mut [0u8; 1]),
    )
    .await
    .expect("stalled socket outlived accept-origin cutoff");
    assert!(
        matches!(close, Ok(0) | Err(_)),
        "stalled socket remained open"
    );
    let elapsed = start.elapsed();
    assert!(
        elapsed >= ADMISSION.saturating_sub(Duration::from_millis(50)),
        "stalled TLS was closed before the configured deadline: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(590),
        "stalled TLS exceeded bounded release: {elapsed:?}"
    );

    // Successful TLS after expiry proves the peer cap was reclaimed by the
    // actual relay, rather than merely observing a client-side EOF.
    tokio::time::sleep(Duration::from_millis(20)).await;
    let tcp = tokio::time::timeout(STAGE, TcpStream::connect(addr))
        .await
        .expect("recovery connect bound")
        .expect("recovery connect");
    let tls = tokio::time::timeout(
        STAGE,
        connector.connect("localhost".to_string().try_into().unwrap(), tcp),
    )
    .await
    .expect("TLS recovery bound")
    .expect("TLS recovery succeeded after cap release");
    drop(tls);

    stop_tx.send(()).expect("owned shutdown request");
    tokio::time::timeout(STAGE, &mut server.0)
        .await
        .expect("bounded owned shutdown")
        .expect("server task join")
        .expect("server shutdown");
}
