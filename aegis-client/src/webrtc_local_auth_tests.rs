//! Actual sidecar session with an owned TLS broker and real intermediary/device.
use super::*;
use crate::carrier::local_auth_tests::{
    authenticate, connect_request, positive_wire, serve_device, toml_path, IdentityFixture, Tasks,
    CLEANUP_BOUND, USER, WORK_BOUND,
};
use anyhow::{ensure, Result};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::{io::AsyncWriteExt, sync::oneshot, time::timeout};

#[cfg(feature = "sfu-media-vp8")]
#[test]
fn sfu_wss_endpoint_is_separate_from_strict_ice_allowlist() {
    let candidate = SfuClientSettings {
        addr: "127.0.0.1:17881".parse().unwrap(),
        tls_name: "localhost".into(),
        ca: "/private/test-ca.pem".into(),
        allowed_sfu_ips: vec!["127.0.0.2".parse().unwrap()],
    };
    assert!(valid_sfu_wss_endpoint(&candidate));
    let path = SfuPath {
        bind: "127.0.0.1:0".parse().unwrap(),
        allowed_sfu_ips: candidate.allowed_sfu_ips.clone(),
    };
    assert!(path.validate().is_ok());
    for bad in ["0.0.0.0:17881", "224.0.0.1:17881", "127.0.0.1:0"] {
        let invalid = SfuClientSettings {
            addr: bad.parse().unwrap(),
            tls_name: candidate.tls_name.clone(),
            ca: candidate.ca.clone(),
            allowed_sfu_ips: candidate.allowed_sfu_ips.clone(),
        };
        assert!(!valid_sfu_wss_endpoint(&invalid));
    }
}

#[cfg(feature = "sfu-media-vp8")]
#[test]
fn sfu_refusal_diagnostic_is_fixed_and_never_uses_input_text() {
    for stage in [
        "broker_begin",
        "broker_take",
        "sfu_signal",
        "media_negotiation",
        "device_tls",
        "target_open",
        "active_data",
        "media_close",
    ] {
        assert_eq!(fixed_sfu_refusal_phase(stage), stage);
    }
    assert_eq!(
        fixed_sfu_refusal_phase("/private/key?token=secret"),
        "unknown"
    );
    assert_eq!(fixed_sfu_refusal_phase("media_close\nsecret"), "unknown");
}

struct Harness {
    tasks: Tasks,
    cancel: Cancellation,
    remote: Arc<AtomicUsize>,
    cfg: Arc<Config>,
    identity: secure_channel::Client,
    key: AdmissionKey,
    tls: tokio_rustls::TlsConnector,
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
impl Harness {
    async fn new(fixture: &IdentityFixture, connect_ms: u64) -> Result<Self> {
        let mut tasks = Tasks::default();
        let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await?);
        let address = listener.local_addr()?;
        let key = AdmissionKey::from_hex(&"a".repeat(64))?;
        let intermediary_key = AdmissionKey::from_hex(&"b".repeat(64))?;
        let broker = Arc::new(aegis_webrtc::OwnedBroker::new(
            key.clone(),
            intermediary_key.clone(),
            aegis_webrtc::BrokerLimits {
                max_sessions: 2,
                session_ttl: Duration::from_secs(10),
            },
        )?);
        let remote = Arc::new(AtomicUsize::new(0));
        let path = fixture.directory.path().join("webrtc.toml");
        let raw = format!("listen = \"127.0.0.1:0\"\nlocal_socks_auth_file = {}\nsignaling_addr = \"{address}\"\nsignaling_name = \"site.test\"\nsignaling_ca = {}\nsignaling_key_file = {}\nidle_timeout_ms = 2000\nmax_sessions = 2\n[inner_tls]\n{}[runtime]\nbind = \"127.0.0.1:0\"\nconnect_timeout_ms = {connect_ms}\nstall_timeout_ms = 2000\nmax_lifetime_ms = 30000\n[runtime.ice]\nmode = \"loopback\"\n", toml_path(&fixture.auth_file), toml_path(&fixture.outer_ca), toml_path(&fixture.admission_file), toml::to_string(&fixture.client)?);
        aegis_core::secret_file::write_private_new(&path, raw.as_bytes())?;
        let (cfg, key, tls) = load(&path)?;
        let identity = secure_channel::Client::load(&cfg.inner_tls)?;
        for _ in 0..4 {
            let listener = listener.clone();
            let broker = broker.clone();
            let acceptor = fixture.outer.clone();
            let observed = remote.clone();
            tasks.0.spawn(async move {
                let (tcp, _) = listener.accept().await?;
                observed.fetch_add(1, Ordering::SeqCst);
                let tls = acceptor.accept(tcp).await?;
                let _ = broker.serve_tls(tls).await;
                Ok(())
            });
        }
        let cancel = Cancellation::default();
        let stop = cancel.clone();
        let device = fixture.server.clone();
        // The actual broker's intermediary role owns ICE/DTLS/SCTP; it is not a
        // signaling model or an authenticated-local-process assumption.
        tasks.0.spawn(async move {
            let stream = aegis_webrtc::accept(
                aegis_webrtc::CarrierConfig::loopback(),
                broker,
                intermediary_key,
                stop,
            )
            .await?;
            let _ = serve_device(stream, device, || Ok(())).await;
            Ok(())
        });
        Ok(Self {
            tasks,
            cancel,
            remote,
            cfg: Arc::new(cfg),
            identity,
            key,
            tls,
        })
    }
    async fn local(&mut self) -> Result<(TcpStream, oneshot::Receiver<bool>)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let client = TcpStream::connect(listener.local_addr()?).await?;
        let (server, _) = listener.accept().await?;
        let cfg = self.cfg.clone();
        let key = self.key.clone();
        let identity = self.identity.clone();
        let tls = self.tls.clone();
        let cancel = self.cancel.clone();
        let (sender, receiver) = oneshot::channel();
        self.tasks.0.spawn(async move {
            let refused = session(server, cfg, key, identity, tls, cancel)
                .await
                .is_err();
            let _ = sender.send(refused);
            Ok(())
        });
        Ok((client, receiver))
    }
    async fn finish(&mut self) -> Result<()> {
        self.cancel.cancel();
        // Cancellation is signaled before aborting/joining every fixture-owned
        // handle. This does not assert joined descendant WebRTC library tasks.
        self.tasks.finish().await
    }
}

async fn exercise(kind: u8) -> Result<()> {
    let fixture = IdentityFixture::new()?;
    let mut harness = Harness::new(&fixture, if kind == 3 { 200 } else { 10000 }).await?;
    let outcome = timeout(WORK_BOUND, async {
        let (target, opens) = fixture.target(&mut harness.tasks).await?;
        let (mut client, done) = harness.local().await?;
        match kind {
            0 => {
                client.write_all(&[5,1,0]).await?;
                let mut reply = [0;2]; client.read_exact(&mut reply).await?;
                // Obey method negotiation. Only the actually admitted old
                // session receives CONNECT; refusal has no unread request.
                if reply == [5,0] { client.write_all(&connect_request(target)?).await?; }
                let _ = timeout(Duration::from_millis(250), async { while harness.remote.load(Ordering::SeqCst) == 0 { tokio::task::yield_now().await; } }).await;
                ensure!(reply == [5,255], "unauthenticated method admitted: selected={} remote_connects={} target_opens={}", reply[1], harness.remote.load(Ordering::SeqCst), opens.load(Ordering::SeqCst));
                let mut tail = Vec::new(); client.read_to_end(&mut tail).await?;
                ensure!(tail.is_empty() && done.await?, "auth refusal did not close directly");
            }
            1 => {
                let (method, auth) = authenticate(&mut client, "wrong-local-password").await?;
                ensure!(method == [5,2] && auth == [1,1], "RFC1929 refusal changed");
                let mut tail = Vec::new(); client.read_to_end(&mut tail).await?;
                ensure!(tail.is_empty() && done.await?, "auth refusal did not close directly");
            }
            2 => { positive_wire(&mut client, target).await?; ensure!(opens.load(Ordering::SeqCst) == 1 && harness.remote.load(Ordering::SeqCst) == 1, "actual broker/device/target path was not exercised"); }
            3 => {
                let start = tokio::time::Instant::now();
                client.write_all(&[5,1,2]).await?; let mut method = [0;2]; client.read_exact(&mut method).await?;
                ensure!(method == [5,2], "partial-auth method changed");
                tokio::time::sleep(Duration::from_millis(120)).await;
                client.write_all(&[1, USER.len() as u8, USER.as_bytes()[0]]).await?;
                let mut tail = Vec::new(); timeout(Duration::from_millis(160), client.read_to_end(&mut tail)).await??;
                ensure!(tail.is_empty() && done.await? && start.elapsed() < Duration::from_millis(350), "auth trickle renewed original deadline");
            }
            _ => unreachable!(),
        }
        if kind != 2 { ensure!(harness.remote.load(Ordering::SeqCst) == 0 && opens.load(Ordering::SeqCst) == 0, "preauth work reached broker/target owner"); }
        Ok(())
    }).await.map_err(|_| anyhow::anyhow!("WebRTC local-auth work deadline"));
    // Outside the operation: a timeout/error still enters separately bounded
    // cleanup. Panic Drop aborts retained handles, but is not joined evidence.
    let cleanup = timeout(CLEANUP_BOUND + Duration::from_secs(1), harness.finish()).await;
    cleanup.map_err(|_| anyhow::anyhow!("WebRTC fixture cleanup outer deadline"))??;
    outcome??;
    Ok(())
}

#[tokio::test]
async fn webrtc_no_auth_cannot_contact_broker_or_target() {
    exercise(0).await.unwrap();
}
#[tokio::test]
async fn webrtc_wrong_auth_closes_before_broker() {
    exercise(1).await.unwrap();
}
#[tokio::test]
async fn webrtc_valid_auth_preserves_real_device_and_target() {
    exercise(2).await.unwrap();
}
#[tokio::test]
async fn webrtc_auth_trickle_keeps_original_single_deadline() {
    exercise(3).await.unwrap();
}

#[test]
fn webrtc_load_requires_private_record_before_run_can_bind() -> Result<()> {
    let fixture = IdentityFixture::new()?;
    let path = fixture.directory.path().join("missing-record-webrtc.toml");
    let raw = format!("listen = \"127.0.0.1:0\"\nlocal_socks_auth_file = {}\nsignaling_addr = \"127.0.0.1:1\"\nsignaling_name = \"site.test\"\nsignaling_ca = {}\nsignaling_key_file = {}\nidle_timeout_ms = 1000\nmax_sessions = 1\n[inner_tls]\n{}[runtime]\nbind = \"127.0.0.1:0\"\nconnect_timeout_ms = 500\nstall_timeout_ms = 1000\nmax_lifetime_ms = 10000\n[runtime.ice]\nmode = \"loopback\"\n", toml_path(&fixture.directory.path().join("missing.json")), toml_path(&fixture.outer_ca), toml_path(&fixture.admission_file), toml::to_string(&fixture.client)?);
    aegis_core::secret_file::write_private_new(&path, raw.as_bytes())?;
    // Separate startup control; this is NOT the behavioral causal RED.
    assert!(load(&path).is_err());
    assert!(!fixture.directory.path().join("missing.json").exists());
    Ok(())
}
