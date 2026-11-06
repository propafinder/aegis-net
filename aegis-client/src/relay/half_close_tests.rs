//! Real client/relay regressions for independently closing TCP directions.
use super::*;
use std::{path::Path, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct AbortOnDrop(tokio::task::AbortHandle);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn write_key(path: &Path, pem: &str) {
    #[cfg(windows)]
    aegis_core::windows_file::write_private_new(path, pem.as_bytes(), false).unwrap();
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, pem).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

async fn transfer(websocket: bool, backend: aegis_core::RelayTlsBackend, response_first: bool) {
    let dir = tempfile::tempdir().unwrap();
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    write_key(&key_path, &key_pair.serialize_pem());
    let cfg = aegis_server::config::ServerConfig {
        listen: "127.0.0.1:0".into(),
        cert: cert_path.clone(),
        key: key_path,
        auth_token: "ac99c6bf1351492d50367daf9be01fc3dfd7bc33f5b9437dbf1b1fde632b87e1".into(),
        target_policy: aegis_server::config::TargetPolicyConfig {
            profile: aegis_server::config::TargetPolicyProfile::FullVpnEgress,
            allowed_ports: vec![],
        },
        legacy_auth_tokens: vec![],
        process_alias: None,
        logging: Default::default(),
        fallback: "close".into(),
        limits: Default::default(),
        rate_limit: Default::default(),
        transport: aegis_server::config::TransportConfig {
            // TCP and UDP ephemeral port spaces are independent. Keep required
            // QUIC enabled, but let its own socket choose an available port.
            quic_listen: Some("127.0.0.1:0".into()),
            ..Default::default()
        },
        bundle_endpoint: Default::default(),
    };
    let auth_token = cfg.auth_token.clone();
    let profile = policy::RelaySessionProfile {
        websocket_path: cfg.transport.websocket_path.clone(),
        write_chunk_size: 4096,
        ..Default::default()
    };
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(aegis_server::run_server_with_bound_ready_and_shutdown(
        cfg,
        ready_tx,
        async {
            let _ = stop_rx.await;
        },
    ));
    let _server_guard = AbortOnDrop(server.abort_handle());
    let address = match ready_rx.await {
        Ok(address) => address,
        Err(error) => panic!(
            "relay stopped before readiness: {error}; server result: {:?}",
            server.await
        ),
    };
    assert!(address.ip().is_loopback() && address.port() != 0);
    let settings = RelaySettings {
        server: address.to_string(),
        server_name: "localhost".into(),
        auth_token,
        ca_cert: Some(cert_path),
        tls_backend: backend,
        ..Default::default()
    };

    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_port = target.local_addr().unwrap().port();
    let payload: Vec<u8> = (0..2 * 1024 * 1024).map(|n| (n % 251) as u8).collect();
    let target_payload = payload.clone();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        if response_first {
            stream.write_all(&target_payload).await.unwrap();
            stream.shutdown().await.unwrap();
        }
        let mut request = Vec::new();
        stream.read_to_end(&mut request).await.unwrap();
        assert_eq!(
            request.len(),
            target_payload.len(),
            "complete request after FIN"
        );
        assert!(request == target_payload, "request content");
        if !response_first {
            stream.write_all(&target_payload).await.unwrap();
            stream.shutdown().await.unwrap();
        }
    });
    let _target_guard = AbortOnDrop(target_task.abort_handle());
    let app_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut app = TcpStream::connect(app_listener.local_addr().unwrap())
        .await
        .unwrap();
    let (mut local, _) = app_listener.accept().await.unwrap();
    let client = tokio::spawn(async move {
        let counters = RelaySessionCounters::default();
        if websocket {
            websocket::run_websocket_tunnel(
                &mut local,
                &settings,
                &profile,
                "127.0.0.1".into(),
                target_port,
                None,
                &counters,
            )
            .await
        } else {
            run_legacy_tls_tunnel(
                &mut local,
                &settings,
                &profile,
                "127.0.0.1".into(),
                target_port,
                None,
                &counters,
            )
            .await
        }
    });
    let _client_guard = AbortOnDrop(client.abort_handle());
    if !response_first {
        app.write_all(&payload).await.unwrap();
        app.shutdown().await.unwrap();
    }
    let mut response = Vec::new();
    app.read_to_end(&mut response).await.unwrap();
    assert_eq!(response.len(), payload.len(), "complete response after FIN");
    assert!(response == payload, "response content");
    if response_first {
        app.write_all(&payload).await.unwrap();
        app.shutdown().await.unwrap();
    }
    target_task.await.unwrap();
    client.await.unwrap().unwrap();
    stop_tx.send(()).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn tcp_half_close_preserves_both_directions() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tls_backend::load_roots(None).unwrap();
    let mut backends = vec![aegis_core::RelayTlsBackend::Rustls];
    if tls_backend::chrome_like_tls_compiled_in() {
        backends.push(aegis_core::RelayTlsBackend::ChromeLikeExperimental);
    }
    for backend in backends {
        for websocket in [false, true] {
            for response_first in [false, true] {
                eprintln!("half-close: {backend:?}, websocket={websocket}, response_first={response_first}");
                tokio::time::timeout(
                    Duration::from_secs(40),
                    transfer(websocket, backend, response_first),
                )
                .await
                .expect("TCP half-close fixture deadline");
            }
        }
    }
}
