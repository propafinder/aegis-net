//! Actual listener refusals must retain their safe phase without announcing ready.
use crate::{config::ServerConfig, lifecycle::OwnedTask};
use std::time::Duration;
use tokio::sync::oneshot;

fn fixture(dir: &std::path::Path) -> ServerConfig {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_path = dir.join("private-cert-path.pem");
    let key_path = dir.join("private-key-path.pem");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    ServerConfig {
        listen: "127.0.0.1:0".into(),
        cert: cert_path,
        key: key_path,
        auth_token: "7f0bfd1d31eade038cc6d5581467707af913a1a43e16d7cad86894b3e2a9721e".into(),
        legacy_auth_tokens: Vec::new(),
        process_alias: None,
        logging: Default::default(),
        fallback: "close".into(),
        limits: Default::default(),
        rate_limit: Default::default(),
        target_policy: Default::default(),
        transport: Default::default(),
        bundle_endpoint: Default::default(),
    }
}

#[tokio::test]
async fn required_quic_actual_startup_refusals_report_phase_and_never_report_ready() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    // Retain the real occupied socket throughout the entire refusal; no
    // released reservation, guessed unused port or repeated bind attempt.
    let occupied = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let occupied_address = occupied.local_addr().unwrap().to_string();
    for (case, expected) in [
        ("occupied", "phase=udp_bind io_kind=Some(AddrInUse)"),
        ("address", "phase=address io_kind=None"),
        ("transport", "phase=transport io_kind=None"),
    ] {
        let mut cfg = fixture(dir.path());
        let private_token = cfg.auth_token.clone();
        assert!(cfg.transport.quic_required);
        cfg.transport.quic_listen = Some(if case == "address" {
            "private-invalid-listener-input".into()
        } else {
            occupied_address.clone()
        });
        if case == "transport" {
            cfg.transport.quic_keep_alive_interval_ms = 2000;
            cfg.transport.quic_max_idle_timeout_ms = 1000;
        }
        let (tx, rx) = oneshot::channel();
        let mut server = OwnedTask(tokio::spawn(super::run_server_with_shutdown(
            cfg,
            Some(tx),
            std::future::pending(),
        )));
        assert!(tokio::time::timeout(Duration::from_secs(3), rx)
            .await
            .unwrap()
            .is_err());
        let error = tokio::time::timeout(Duration::from_secs(3), &mut server.0)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        let report = error.to_string();
        assert_eq!(
            report,
            format!("required QUIC ingress failed before readiness: {expected}")
        );
        for private in [
            private_token.as_str(),
            occupied_address.as_str(),
            "private-invalid-listener-input",
            "private-cert-path.pem",
            "private-key-path.pem",
        ] {
            assert!(!report.contains(private));
        }
    }
    drop(occupied);
}

#[tokio::test]
async fn optional_quic_actual_udp_refusal_keeps_tcp_ready_and_owned_shutdown() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let occupied = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut cfg = fixture(dir.path());
    cfg.transport.quic_required = false;
    cfg.transport.quic_listen = Some(occupied.local_addr().unwrap().to_string());
    let (tx, rx) = oneshot::channel();
    let (stop_tx, stop_rx) = oneshot::channel();
    let mut server = OwnedTask(tokio::spawn(
        super::run_server_with_bound_ready_and_shutdown(cfg, tx, async move {
            let _ = stop_rx.await;
        }),
    ));
    let tcp = tokio::time::timeout(Duration::from_secs(3), rx)
        .await
        .unwrap()
        .unwrap();
    let peer = tokio::net::TcpStream::connect(tcp).await.unwrap();
    drop(peer);
    stop_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(3), &mut server.0)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let rebound = tokio::net::TcpListener::bind(tcp).await.unwrap();
    drop(rebound);
    drop(occupied);
}
