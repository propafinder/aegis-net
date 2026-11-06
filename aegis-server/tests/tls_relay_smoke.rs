//! Full TLS handshake, then the build-admitted authenticated raw tunnel exchange.

#[cfg(not(feature = "legacy-challenge-v1"))]
use aegis_core::tunnel::{encode_stream_frame, open_tunnel_response, seal_tunnel_request};
use aegis_core::tunnel::{TunnelRequest, TunnelStatus};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName};
use std::sync::Arc;
#[cfg(not(feature = "legacy-challenge-v1"))]
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[tokio::test]
async fn tls_then_tunnel_auth_ok() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = tempfile::tempdir().expect("tempdir");
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".into()]).expect("rcgen");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.pem()).expect("write cert");
    std::fs::write(&key_path, key_pair.serialize_pem()).expect("write key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    // «Цель» для туннеля — локальный accept, чтобы connect на сервере прошёл.
    let dummy = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("dummy bind");
    let target_port = dummy.local_addr().expect("addr").port();

    // Cover readiness and both original opening budgets, not an unrepresentable
    // "infinite" wall-clock expiry. No connection or freshness deadline is widened.
    let migration_lease_seconds = aegis_server::config::ServerLimits::default()
        .read_timeout_ms
        .div_ceil(1000)
        .checked_mul(3)
        .and_then(|seconds| seconds.checked_add(1))
        .expect("finite migration fixture lease");
    let migration_not_after = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .expect("fixture wall clock")
        .as_secs()
        .checked_add(migration_lease_seconds)
        .expect("finite migration fixture expiry");
    std::time::SystemTime::UNIX_EPOCH
        .checked_add(std::time::Duration::from_secs(migration_not_after))
        .expect("fixture migration expiry is representable");
    let cfg = aegis_server::config::ServerConfig {
        listen: "127.0.0.1:0".into(),
        cert: cert_path.clone(),
        key: key_path.clone(),
        auth_token: "ac99c6bf1351492d50367daf9be01fc3dfd7bc33f5b9437dbf1b1fde632b87e1".into(),
        legacy_auth_tokens: vec![aegis_server::config::LegacyAuthTokenConfig {
            id: "legacy-test".into(),
            auth_token: "f4668ed7b5f83ba9532822aa375f297cfa8a6911870010e0b30add97c9fca9ca".into(),
            not_after_unix_secs: migration_not_after,
        }],
        process_alias: None,
        logging: Default::default(),
        fallback: "close".into(),
        limits: Default::default(),
        rate_limit: Default::default(),
        target_policy: aegis_server::config::TargetPolicyConfig {
            profile: aegis_server::config::TargetPolicyProfile::FullVpnEgress,
            allowed_ports: Vec::new(),
        },
        transport: Default::default(),
        bundle_endpoint: Default::default(),
    };

    // Reuse the configured opening budget; no longer or retried readiness window.
    let opening_budget = std::time::Duration::from_millis(cfg.limits.read_timeout_ms);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        aegis_server::run_server_with_bound_ready_and_shutdown(cfg, ready_tx, async move {
            let _ = shutdown_rx.await;
        })
        .await
    });
    let relay_addr = tokio::time::timeout(opening_budget, ready_rx)
        .await
        .expect("bounded server readiness")
        .expect("owned server listener ready");

    let mut roots = rustls::RootCertStore::empty();
    let pem = std::fs::read(&cert_path).expect("read cert");
    let mut rd = std::io::BufReader::new(pem.as_slice());
    for c in CertificateDer::pem_reader_iter(&mut rd) {
        roots.add(c.expect("pem cert")).expect("add root");
    }

    let client_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_cfg));

    #[cfg(feature = "legacy-challenge-v1")]
    let opening_deadline = tokio::time::Instant::now() + opening_budget;
    let tcp = TcpStream::connect(relay_addr).await.expect("tcp connect");
    let dns: ServerName = "localhost".to_string().try_into().expect("dns");
    let mut tls = connector.connect(dns, tcp).await.expect("tls handshake");

    let req = TunnelRequest {
        host: "127.0.0.1".into(),
        port: target_port,
    };
    #[cfg(feature = "legacy-challenge-v1")]
    let resp = aegis_core::tunnel::fresh_legacy::exchange_raw(
        &mut tls,
        &req,
        b"ac99c6bf1351492d50367daf9be01fc3dfd7bc33f5b9437dbf1b1fde632b87e1",
        opening_deadline,
    )
    .await
    .expect("fresh tunnel exchange");
    #[cfg(not(feature = "legacy-challenge-v1"))]
    let resp = {
        let frame = seal_tunnel_request(
            &req,
            b"ac99c6bf1351492d50367daf9be01fc3dfd7bc33f5b9437dbf1b1fde632b87e1",
        )
        .expect("seal tunnel");
        tls.write_all(&encode_stream_frame(&frame))
            .await
            .expect("write tunnel");

        let frame =
            aegis_core::tunnel::read_stream_frame(&mut tls, aegis_core::MAX_TUNNEL_CONTROL_FRAME)
                .await
                .expect("read response");
        open_tunnel_response(
            &frame,
            b"ac99c6bf1351492d50367daf9be01fc3dfd7bc33f5b9437dbf1b1fde632b87e1",
        )
        .expect("decode tunnel response")
    };
    assert_eq!(
        resp.status,
        TunnelStatus::Ok,
        "unexpected status: {}",
        resp.message
    );
    drop(tls);

    // A migrated server must respond with the exact legacy key that opened
    // the request. Sealing this response with the current key would make the
    // old client fail after authentication and look like a transport outage.
    #[cfg(feature = "legacy-challenge-v1")]
    let opening_deadline = tokio::time::Instant::now() + opening_budget;
    let tcp = TcpStream::connect(relay_addr)
        .await
        .expect("legacy tcp connect");
    let dns: ServerName = "localhost".to_string().try_into().expect("dns");
    let mut tls = connector
        .connect(dns, tcp)
        .await
        .expect("legacy tls handshake");
    #[cfg(feature = "legacy-challenge-v1")]
    let resp = aegis_core::tunnel::fresh_legacy::exchange_raw(
        &mut tls,
        &req,
        b"f4668ed7b5f83ba9532822aa375f297cfa8a6911870010e0b30add97c9fca9ca",
        opening_deadline,
    )
    .await
    .expect("fresh legacy-key tunnel exchange");
    #[cfg(not(feature = "legacy-challenge-v1"))]
    let resp = {
        let frame = seal_tunnel_request(
            &req,
            b"f4668ed7b5f83ba9532822aa375f297cfa8a6911870010e0b30add97c9fca9ca",
        )
        .expect("seal legacy tunnel");
        tls.write_all(&encode_stream_frame(&frame))
            .await
            .expect("write legacy tunnel");
        let frame =
            aegis_core::tunnel::read_stream_frame(&mut tls, aegis_core::MAX_TUNNEL_CONTROL_FRAME)
                .await
                .expect("read legacy response");
        open_tunnel_response(
            &frame,
            b"f4668ed7b5f83ba9532822aa375f297cfa8a6911870010e0b30add97c9fca9ca",
        )
        .expect("decode legacy tunnel response")
    };
    assert_eq!(resp.status, TunnelStatus::Ok);
    drop(tls);
    shutdown_tx.send(()).expect("request owned server shutdown");
    tokio::time::timeout(opening_budget, server)
        .await
        .expect("bounded server shutdown")
        .expect("join owned server task")
        .expect("owned server completed");
}
