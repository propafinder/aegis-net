use crate::config::{ServerConfig, TargetPolicyConfig, TargetPolicyProfile};
use crate::lifecycle::OwnedTask;
use aegis_core::tunnel::{open_tunnel_response, seal_tunnel_request, TunnelRequest, TunnelStatus};
use bytes::Bytes;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use std::{future::Future, sync::Arc, time::Duration};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_rustls::TlsConnector;

const STAGE_TIMEOUT: Duration = Duration::from_secs(3);
const TEST_TOKEN: &[u8] = b"7f0bfd1d31eade038cc6d5581467707af913a1a43e16d7cad86894b3e2a9721e";

#[derive(Debug, thiserror::Error)]
#[error("injected runtime ingress failure")]
struct InjectedIngressFailure;

async fn stage<T>(name: &str, future: impl Future<Output = T>) -> T {
    tokio::time::timeout(STAGE_TIMEOUT, future)
        .await
        .unwrap_or_else(|_| panic!("timed out at {name}"))
}

fn live_tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

fn grpc_frame(payload: &[u8]) -> Bytes {
    let mut frame = Vec::with_capacity(payload.len() + 5);
    frame.push(0);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    Bytes::from(frame)
}

async fn read_ack(body: &mut h2::RecvStream) -> Vec<u8> {
    let mut frame = Vec::new();
    loop {
        if frame.len() >= 5 {
            assert_eq!(frame[0], 0, "uncompressed acknowledgment");
            let len = u32::from_be_bytes(frame[1..5].try_into().unwrap()) as usize;
            assert!(len <= 1024 * 1024, "bounded fixture acknowledgment");
            if frame.len() >= len + 5 {
                assert_eq!(frame.len(), len + 5, "silent target sends no extra data");
                return frame[5..].to_vec();
            }
        }
        let chunk = body
            .data()
            .await
            .expect("acknowledgment before response EOF")
            .expect("acknowledgment data");
        frame.extend_from_slice(&chunk);
        body.flow_control()
            .release_capacity(chunk.len())
            .expect("release acknowledgment capacity");
    }
}

#[tokio::test]
async fn runtime_ingress_error_preserves_error_and_cleans_up_active_h2_tunnel() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let baseline = live_tasks();
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert_dir = tempfile::tempdir().expect("temporary certificate directory");
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).expect("test certificate");
        let cert_path = cert_dir.path().join("cert.pem");
        let key_path = cert_dir.path().join("key.pem");
        std::fs::write(&cert_path, cert.pem()).expect("write temporary certificate");
        std::fs::write(&key_path, key_pair.serialize_pem()).expect("write temporary key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(cert.der().clone())
            .expect("trust fixture certificate");
        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let connector = TlsConnector::from(Arc::new(tls));

        let reservation = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve test server listener");
        let server_addr = reservation.local_addr().expect("server address");
        let mut cfg = ServerConfig {
            listen: server_addr.to_string(),
            cert: cert_path,
            key: key_path,
            auth_token: String::from_utf8(TEST_TOKEN.to_vec()).expect("ASCII test token"),
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
        // A runtime error must abort immediately, not spend this normal grace.
        // The error-return stage timeout is deliberately shorter than the grace.
        cfg.limits.shutdown_grace_ms = 10_000;
        cfg.transport.quic_listen = Some("127.0.0.1:0".into());
        let grpc_path = cfg.transport.grpc_path.clone();
        let (ready_tx, ready_rx) = oneshot::channel();
        let (stop_tx, stop_rx) = oneshot::channel();
        drop(reservation);
        let mut server = OwnedTask(tokio::spawn(super::run_server_with_stop(
            cfg,
            Some(ready_tx),
            async move {
                stop_rx.await.expect("explicit fixture fault trigger");
                Err(InjectedIngressFailure.into())
            },
        )));
        stage("server readiness", ready_rx)
            .await
            .expect("server reports ready");

        let target_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("controlled silent target");
        let tcp = stage("client TCP connect", TcpStream::connect(server_addr))
            .await
            .expect("client TCP connection");
        let tls = stage(
            "client TLS handshake",
            connector.connect("localhost".to_string().try_into().unwrap(), tcp),
        )
        .await
        .expect("trusted TLS connection");
        let (mut sender, connection) = stage("client H2 handshake", h2::client::handshake(tls))
            .await
            .expect("H2 connection");
        let client = OwnedTask(tokio::spawn(connection));
        stage(
            "H2 request readiness",
            std::future::poll_fn(|cx| sender.poll_ready(cx)),
        )
        .await
        .expect("H2 request capacity");
        let request = http::Request::builder()
            .method("POST")
            .uri(grpc_path)
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(())
            .expect("gRPC request");
        let (response, mut request_body) = sender.send_request(request, false).unwrap();
        let open = seal_tunnel_request(
            &TunnelRequest {
                host: "127.0.0.1".into(),
                port: target_listener.local_addr().unwrap().port(),
            },
            TEST_TOKEN,
        )
        .expect("authenticated tunnel open");
        request_body
            .send_data(grpc_frame(&open), false)
            .expect("keep authenticated request open");
        let response = stage("gRPC response headers", response)
            .await
            .expect("response headers");
        assert!(response.status().is_success());
        let mut response_body = response.into_body();
        let ack = stage(
            "authenticated tunnel acknowledgment",
            read_ack(&mut response_body),
        )
        .await;
        let ack = open_tunnel_response(&ack, TEST_TOKEN).expect("authenticate acknowledgment");
        assert_eq!(ack.status, TunnelStatus::Ok);
        let mut target = stage("target socket accepted", target_listener.accept())
            .await
            .expect("target accepts live tunnel")
            .0;
        assert!(
            live_tasks() > baseline,
            "fixture owns active server workers"
        );

        // This private fault seam exercises the common runtime-error cleanup;
        // it does not manufacture an OS accept failure or stop a real ingress.
        stop_tx.send(()).expect("inject runtime ingress failure");
        let error = stage("immediate runtime-error cleanup", &mut server.0)
            .await
            .expect("server task joins")
            .expect_err("injected ingress error must remain an error");
        assert!(
            error.is::<InjectedIngressFailure>(),
            "preserve error identity"
        );
        assert_eq!(error.to_string(), "injected runtime ingress failure");
        let _rebound = TcpListener::bind(server_addr)
            .await
            .expect("server listener released before error return");
        match stage("silent target peer EOF", target.read(&mut [0; 1])).await {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                ) => {}
            other => panic!("target socket was not closed: {other:?}"),
        }
        // EOF can represent just a write-half close. Also require the silent
        // read-side worker to disappear without waking it with target data.
        // This count is eventual cleanup evidence, not a synchronous Drop probe.
        stage("all owned workers disappear", async {
            while live_tasks() != baseline {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert_eq!(live_tasks(), baseline);
        assert!(client.0.is_finished(), "closed H2 driver terminates too");
    })
    .await
    .expect("bounded runtime-error cleanup fixture");
}
