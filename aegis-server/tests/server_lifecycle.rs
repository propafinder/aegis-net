use aegis_server::config::ServerConfig;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

fn fixture() -> (tempfile::TempDir, ServerConfig) {
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
    let cfg = ServerConfig {
        listen: "127.0.0.1:0".into(),
        cert: cert_path,
        key: key_path,
        auth_token: "60a167ff6fb990c55905dff6765eceefaebea4490a809a34955db1f7477a6ec9".into(),
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
    (dir, cfg)
}

#[tokio::test]
async fn required_quic_bind_failure_never_reports_ready() {
    let (_dir, mut cfg) = fixture();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    cfg.transport.quic_listen = Some(udp.local_addr().unwrap().to_string());
    assert!(cfg.transport.quic_required);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        aegis_server::run_server_with_shutdown(cfg, Some(ready_tx), std::future::pending()),
    )
    .await
    .unwrap();
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("required QUIC ingress"));
    assert!(ready_rx.await.is_err());
}

#[tokio::test]
async fn bound_address_readiness_still_requires_quic() {
    let (_dir, mut cfg) = fixture();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    cfg.transport.quic_listen = Some(udp.local_addr().unwrap().to_string());
    assert!(cfg.transport.quic_required);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        aegis_server::run_server_with_bound_ready_and_shutdown(
            cfg,
            ready_tx,
            std::future::pending(),
        ),
    )
    .await
    .unwrap();
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("required QUIC ingress"));
    assert!(
        ready_rx.await.is_err(),
        "a TCP address alone is not overall readiness"
    );
}

#[tokio::test]
async fn default_quic_uses_actual_tcp_ephemeral_address_and_releases_both() {
    use rustls::pki_types::pem::PemObject;

    struct OwnedTask<T>(tokio::task::JoinHandle<T>);
    impl<T> Drop for OwnedTask<T> {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    tokio::time::timeout(Duration::from_secs(10), async {
        let (_dir, mut cfg) = fixture();
        assert_eq!(cfg.listen, "127.0.0.1:0");
        assert!(cfg.transport.quic_listen.is_none());
        assert!(cfg.transport.quic_required);
        cfg.limits.shutdown_grace_ms = 20;
        let cert = rustls::pki_types::CertificateDer::from_pem_slice(
            &std::fs::read(&cfg.cert).expect("read fixture certificate"),
        )
        .expect("parse fixture certificate");
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let mut server = OwnedTask(tokio::spawn(
            aegis_server::run_server_with_bound_ready_and_shutdown(cfg, ready_tx, async {
                let _ = stop_rx.await;
            }),
        ));
        let addr = tokio::time::timeout(Duration::from_secs(3), ready_rx)
            .await
            .expect("actual bound-address readiness deadline")
            .expect("both required listeners ready");
        assert_ne!(addr.port(), 0);
        let _tcp = tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(addr))
            .await
            .expect("TCP connection deadline")
            .expect("TCP connects to actual ready address");

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).expect("trust fixture certificate");
        let mut crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        crypto.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .expect("QUIC fixture TLS config");
        let mut endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("QUIC client endpoint");
        endpoint.set_default_client_config(quinn::ClientConfig::new(std::sync::Arc::new(crypto)));
        let connection = tokio::time::timeout(
            Duration::from_secs(3),
            endpoint
                .connect(addr, "localhost")
                .expect("start QUIC connection"),
        )
        .await
        .expect("QUIC connection to the same ready address deadline")
        .expect("trusted QUIC handshake at actual TCP address");
        let handshake = connection
            .handshake_data()
            .expect("completed TLS handshake metadata")
            .downcast::<quinn::crypto::rustls::HandshakeData>()
            .expect("rustls handshake metadata");
        assert_eq!(handshake.protocol.as_deref(), Some(&b"h3"[..]));
        assert!(connection.close_reason().is_none());

        stop_tx.send(()).expect("request owned shutdown");
        tokio::time::timeout(Duration::from_secs(3), &mut server.0)
            .await
            .expect("server shutdown deadline")
            .expect("join server")
            .expect("server shutdown");
        // Keep this runtime and both clients alive so runtime destruction
        // cannot conceal an unreleased server listener or endpoint driver.
        let _tcp_rebound = tokio::time::timeout(Duration::from_secs(3), TcpListener::bind(addr))
            .await
            .expect("TCP rebind deadline")
            .expect("actual TCP listener released before return");
        let _udp_rebound = tokio::time::timeout(Duration::from_secs(3), UdpSocket::bind(addr))
            .await
            .expect("UDP rebind deadline")
            .expect("same-address QUIC listener released before return");
        endpoint.close(quinn::VarInt::from_u32(0), b"fixture complete");
    })
    .await
    .expect("same-address default QUIC lifecycle deadline");
}

#[tokio::test]
async fn explicitly_optional_quic_allows_tcp_only_until_shutdown() {
    let (_dir, mut cfg) = fixture();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    cfg.transport.quic_listen = Some(udp.local_addr().unwrap().to_string());
    cfg.transport.quic_required = false;
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(aegis_server::run_server_with_shutdown(
        cfg,
        Some(ready_tx),
        async {
            let _ = stop_rx.await;
        },
    ));
    tokio::time::timeout(Duration::from_secs(3), ready_rx)
        .await
        .unwrap()
        .unwrap();
    assert!(!task.is_finished());
    stop_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn shutdown_bounds_idle_connection_and_releases_both_listeners() {
    let (_dir, mut cfg) = fixture();
    let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = reservation.local_addr().unwrap();
    cfg.listen = addr.to_string();
    cfg.limits.shutdown_grace_ms = 20;
    drop(reservation);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(aegis_server::run_server_with_shutdown(
        cfg,
        Some(ready_tx),
        async {
            let _ = stop_rx.await;
        },
    ));
    tokio::time::timeout(Duration::from_secs(3), ready_rx)
        .await
        .unwrap()
        .unwrap();
    let mut client = TcpStream::connect(addr).await.unwrap();
    stop_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(1), client.read(&mut [0u8; 1]))
        .await
        .unwrap();
    assert!(matches!(closed, Ok(0) | Err(_)));
    TcpListener::bind(addr).await.expect("TCP port released");
    UdpSocket::bind(addr).await.expect("QUIC port released");
}

#[cfg(unix)]
#[test]
fn sigterm_enters_bounded_drain_in_real_server_process() {
    assert_signal_drains_server(libc::SIGTERM);
}

#[cfg(unix)]
#[test]
fn sigint_enters_bounded_drain_in_real_server_process() {
    assert_signal_drains_server(libc::SIGINT);
}

#[cfg(unix)]
fn assert_signal_drains_server(signal: libc::c_int) {
    let (dir, cfg) = fixture();
    let config_path = dir.path().join("server.toml");
    std::fs::write(&config_path, format!(
        "listen = '127.0.0.1:0'\ncert = '{}'\nkey = '{}'\nauth_token = '60a167ff6fb990c55905dff6765eceefaebea4490a809a34955db1f7477a6ec9'\n[limits]\nshutdown_grace_ms = 20\n",
        cfg.cert.display(), cfg.key.display(),
    )).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let stderr_path = dir.path().join("stderr.log");
    let log = std::fs::File::create(&stderr_path).unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_aegis-server"))
        .arg("--config")
        .arg(&config_path)
        .env("RUST_LOG", "info")
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .unwrap();
    // Only this test-owned child can receive the signal. Always reap on failure.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !std::fs::read_to_string(&stderr_path)
            .unwrap()
            .contains("server_ingress_ready")
        {
            assert!(
                child.try_wait().unwrap().is_none(),
                "server exited before ready"
            );
            assert!(std::time::Instant::now() < deadline, "ready deadline");
            std::thread::sleep(Duration::from_millis(10));
        }
        // SAFETY: the PID belongs to the live child created immediately above.
        assert_eq!(unsafe { libc::kill(child.id() as libc::pid_t, signal) }, 0);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "SIGTERM must exit through normal server drain"
                );
                break;
            }
            assert!(std::time::Instant::now() < deadline, "shutdown deadline");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(std::fs::read_to_string(&stderr_path)
            .unwrap()
            .contains("server stopped"));
    }));
    let _ = child.kill();
    let _ = child.wait();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}
