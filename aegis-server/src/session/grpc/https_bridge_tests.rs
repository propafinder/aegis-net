#![cfg(unix)]

use super::*;
use crate::lifecycle::{OwnedTask, TaskGroupRegistryOwner};
use aegis_core::https_bridge::{ClientSettings, Gate, ServerSettings, KEY_HEADER};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::sync::Semaphore;

const STAGE_TIMEOUT: Duration = Duration::from_secs(2);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(8);

struct BridgeFixture {
    inner: super::secure_tests::Fixture,
    settings: ServerSettings,
    gate: Arc<Gate>,
}

impl BridgeFixture {
    fn new(html: String) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let inner = super::secure_tests::fixture(true);
        let credential_file = inner._dir.path().join("bridge-admission-key");
        std::fs::write(&credential_file, "ab".repeat(32)).unwrap();
        std::fs::set_permissions(&credential_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let settings = ServerSettings {
            carrier: ClientSettings {
                authority: "bridge.test".into(),
                path: "/private/stream".into(),
                enrollment_path: "/private/enroll".into(),
                credential_file,
            },
            site_html: html,
        };
        let gate = Arc::new(Gate::load(&settings).unwrap());
        Self {
            inner,
            settings,
            gate,
        }
    }

    fn auth(&self) -> TunnelAuthKeyring {
        TunnelAuthKeyring {
            keys: Vec::new().into(),
            operational_log: Default::default(),
            inner_tls: Some(self.inner.server.clone()),
            https_bridge: Some(self.gate.clone()),
            fronted_origin: None,
            relay_training: None,
        }
    }

    fn assert_inner_capacity_reclaimed(&self) {
        let permits = (0..128)
            .map(|_| {
                self.inner
                    .server
                    .try_acquire()
                    .expect("inner capacity reclaimed")
            })
            .collect::<Vec<_>>();
        assert!(self.inner.server.try_acquire().is_err());
        drop(permits);
    }
}

struct Connection {
    sender: h2::client::SendRequest<Bytes>,
    driver: OwnedTask<Result<(), h2::Error>>,
    server: OwnedTask<anyhow::Result<()>>,
    owner: TaskGroupRegistryOwner,
    permits: Arc<Semaphore>,
    server_joined: bool,
}

async fn connection(fixture: &BridgeFixture, window: u32) -> Connection {
    let (client_io, server_io) = tokio::io::duplex(8192);
    let auth = fixture.auth();
    let owner = TaskGroupRegistryOwner::new(Default::default());
    let registry = owner.registry();
    let permits = Arc::new(Semaphore::new(1));
    let permit = permits.clone().try_acquire_owned().unwrap();
    let server = OwnedTask(tokio::spawn(async move {
        let _permit = permit;
        handle_grpc_session_with_owner(
            server_io,
            &auth,
            &TransportConfig::default(),
            &TargetPolicyConfig::default(),
            &RateLimiter::new(8, 60, false),
            "192.0.2.10:443".parse().unwrap(),
            None,
            &registry,
            None,
        )
        .await
    }));
    let mut builder = h2::client::Builder::new();
    builder.initial_window_size(window);
    let (sender, driver) =
        tokio::time::timeout(STAGE_TIMEOUT, builder.handshake::<_, Bytes>(client_io))
            .await
            .expect("client H2 handshake bounded")
            .unwrap();
    Connection {
        sender,
        driver: OwnedTask(tokio::spawn(driver)),
        server,
        owner,
        permits,
        server_joined: false,
    }
}

impl Connection {
    async fn assert_natural_close(&mut self) {
        tokio::time::timeout(CLOSE_TIMEOUT, &mut self.server.0)
            .await
            .expect("bridge admission has a fixed bound")
            .expect("server task joined")
            .expect("admission expiry is a clean close");
        self.server_joined = true;
        tokio::time::timeout(STAGE_TIMEOUT, self.owner.shutdown())
            .await
            .expect("request children joined");
        assert_eq!(self.permits.available_permits(), 1);
    }

    async fn close(mut self) {
        self.driver.0.abort();
        let _ = (&mut self.driver.0).await;
        drop(self.sender);
        if !self.server_joined {
            let _ = tokio::time::timeout(STAGE_TIMEOUT, &mut self.server.0)
                .await
                .expect("disconnected H2 parent joined");
        }
        tokio::time::timeout(STAGE_TIMEOUT, self.owner.shutdown())
            .await
            .expect("disconnected request children joined");
        assert_eq!(self.permits.available_permits(), 1);
    }
}

fn public_request(path: &str) -> http::Request<()> {
    http::Request::builder()
        .uri(format!("https://bridge.test{path}"))
        .body(())
        .unwrap()
}

async fn read_body(mut body: h2::RecvStream) -> Result<Vec<u8>, h2::Error> {
    let mut received = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        body.flow_control().release_capacity(chunk.len())?;
        received.extend_from_slice(&chunk);
    }
    Ok(received)
}

#[tokio::test]
async fn bridge_gate_without_device_proof_cannot_extend_admission_with_public_replays() {
    let fixture = BridgeFixture::new("<html>Public page</html>".into());
    let mut connection = connection(&fixture, 65_535).await;
    let credential = fixture.settings.carrier.load_credential().unwrap();
    let gated = http::Request::builder()
        .method("POST")
        .uri("https://bridge.test/private/stream")
        .header("content-type", "application/grpc")
        .header(KEY_HEADER, credential.header_value())
        .body(())
        .unwrap();
    let (response, _silent_inner_send) = connection.sender.send_request(gated, false).unwrap();
    let response = tokio::time::timeout(STAGE_TIMEOUT, response)
        .await
        .expect("gated carrier headers bounded")
        .unwrap();
    assert_eq!(response.status(), 200);
    // Retain both halves but send no inner TLS bytes or device certificate.
    let _silent_inner_recv = response.into_body();
    let completed = Arc::new(AtomicUsize::new(0));
    let observed = completed.clone();
    let mut sender = connection.sender.clone();
    let mut replay = OwnedTask(tokio::spawn(async move {
        loop {
            let Ok(ready) = sender.ready().await else {
                break;
            };
            sender = ready;
            let path = if observed.load(Ordering::SeqCst).is_multiple_of(2) {
                "/"
            } else {
                "/unknown"
            };
            let Ok((response, _send)) = sender.send_request(public_request(path), true) else {
                break;
            };
            let Ok(response) = response.await else {
                break;
            };
            if read_body(response.into_body()).await.is_err() {
                break;
            }
            observed.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }));
    connection.assert_natural_close().await;
    assert!(
        completed.load(Ordering::SeqCst) >= 4,
        "public replays reached the dispatcher"
    );
    replay.0.abort();
    let _ = (&mut replay.0).await;
    fixture.assert_inner_capacity_reclaimed();
    connection.close().await;
}

#[tokio::test]
async fn bridge_public_h2_page_finishes_through_a_small_receive_window() {
    let html = format!("<html>{}</html>", "x".repeat(64 * 1024 - 13));
    let fixture = BridgeFixture::new(html.clone());
    let mut connection = connection(&fixture, 1024).await;
    let (response, _send) = connection
        .sender
        .send_request(public_request("/"), true)
        .unwrap();
    let response = tokio::time::timeout(STAGE_TIMEOUT, response)
        .await
        .expect("public headers bounded")
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["content-length"]
            .to_str()
            .unwrap()
            .parse::<usize>()
            .unwrap(),
        html.len()
    );
    // Keep the body blocked beyond the authority's old one-second drain budget.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let mut body = response.into_body();
    let received = tokio::time::timeout(STAGE_TIMEOUT, async {
        let mut received = Vec::new();
        let mut chunks = 0;
        while let Some(chunk) = body.data().await {
            let chunk = chunk.unwrap();
            body.flow_control().release_capacity(chunk.len()).unwrap();
            received.extend_from_slice(&chunk);
            chunks += 1;
        }
        assert!(chunks >= 32, "response exercised receive-window updates");
        received
    })
    .await
    .expect("progressing public body finishes within write budget");
    assert_eq!(received, html.as_bytes());
    connection.close().await;
    fixture.assert_inner_capacity_reclaimed();
}

#[tokio::test]
async fn bridge_public_h2_zero_window_times_out_without_false_completion() {
    let fixture = BridgeFixture::new("<html>Public page</html>".into());
    let (client_io, server_io) = tokio::io::duplex(8192);
    let gate = fixture.gate.clone();
    let permits = Arc::new(Semaphore::new(1));
    let permit = permits.clone().try_acquire_owned().unwrap();
    let mut server = OwnedTask(tokio::spawn(async move {
        let _permit = permit;
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let (request, respond) = connection.accept().await.unwrap().unwrap();
        let sending = super::super::https_bridge::respond_h2(respond, gate.site(&request));
        tokio::pin!(sending);
        tokio::select! {
                result = &mut sending => {
                    connection.graceful_shutdown();
                    let _ = tokio::time::timeout(STAGE_TIMEOUT, async {
                        while connection.accept().await.is_some() {}
                    }).await;
                    result
                }
                accepted = connection.accept() => match accepted {
                    None => panic!("client retained connection while public send was blocked"),
                    Some(Err(error)) => panic!("public H2 driver failed: {error}"),
                    Some(Ok(_)) => panic!("fixture sends one public request"),
                }
        }
    }));
    let mut builder = h2::client::Builder::new();
    builder.initial_window_size(0);
    let (mut sender, driver) =
        tokio::time::timeout(STAGE_TIMEOUT, builder.handshake::<_, Bytes>(client_io))
            .await
            .expect("zero-window H2 handshake bounded")
            .unwrap();
    let mut driver = OwnedTask(tokio::spawn(driver));
    let (response, _send) = sender.send_request(public_request("/"), true).unwrap();
    let response = tokio::time::timeout(STAGE_TIMEOUT, response)
        .await
        .expect("zero-window response headers bounded")
        .unwrap();
    assert_eq!(response.status(), 200);
    let result = tokio::time::timeout(CLOSE_TIMEOUT, &mut server.0)
        .await
        .expect("zero-window public write and drain are bounded")
        .expect("public writer joined");
    assert!(
        result.is_err(),
        "a blocked body must not report a completed write"
    );
    assert_eq!(permits.available_permits(), 1);
    let body = tokio::time::timeout(STAGE_TIMEOUT, read_body(response.into_body()))
        .await
        .expect("response body terminated with its owner");
    assert!(body.is_err() || body.unwrap().is_empty());
    drop(sender);
    driver.0.abort();
    let _ = (&mut driver.0).await;
    fixture.assert_inner_capacity_reclaimed();
}
