//! The production sidecar session and real descriptor/device owners are used.
//! No standalone SOCKS handshake model or schema-rejection causal RED.
use super::*;
use anyhow::{ensure, Result};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::{
    io::AsyncWriteExt,
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

pub(crate) const USER: &str = "fixture-local-user";
pub(crate) const PASSWORD: &str = "fixture-local-password";
pub(crate) const WORK_BOUND: Duration = Duration::from_secs(15);
pub(crate) const CLEANUP_BOUND: Duration = Duration::from_secs(2);

pub(crate) fn toml_path(path: &Path) -> String {
    toml::Value::String(path.to_string_lossy().into_owned()).to_string()
}

pub(crate) struct Tasks(pub(crate) JoinSet<Result<()>>);
impl Default for Tasks {
    fn default() -> Self {
        Self(JoinSet::new())
    }
}
impl Drop for Tasks {
    fn drop(&mut self) {
        self.0.abort_all();
    }
}
impl Tasks {
    #[cfg(feature = "webrtc-carrier")]
    pub(crate) async fn finish(&mut self) -> Result<()> {
        self.finish_before(tokio::time::Instant::now() + CLEANUP_BOUND)
            .await
    }

    async fn finish_before(&mut self, deadline: tokio::time::Instant) -> Result<()> {
        self.0.abort_all();
        let mut first_error = None;
        let drained = tokio::time::timeout_at(deadline, async {
            while let Some(result) = self.0.join_next().await {
                let error = match result {
                    Ok(result) => result.err(),
                    Err(error) if error.is_cancelled() => None,
                    Err(_) => Some(anyhow::anyhow!("owned local-auth fixture task panicked")),
                };
                if first_error.is_none() {
                    first_error = error;
                }
            }
        })
        .await;
        if drained.is_err() {
            return Err(anyhow::anyhow!("owned local-auth fixture cleanup deadline"));
        }
        first_error.map_or(Ok(()), Err)
    }
}

pub(crate) struct IdentityFixture {
    pub(crate) directory: tempfile::TempDir,
    pub(crate) client: secure_channel::ClientSettings,
    pub(crate) unlisted_client: secure_channel::ClientSettings,
    pub(crate) server: secure_channel::Server,
    pub(crate) outer_ca: PathBuf,
    pub(crate) outer_key: PathBuf,
    pub(crate) client_digest: String,
    pub(crate) outer: TlsAcceptor,
    pub(crate) auth_file: PathBuf,
    pub(crate) admission_file: PathBuf,
}
impl IdentityFixture {
    pub(crate) fn new() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let write = |name: &str, bytes: &[u8]| -> Result<PathBuf> {
            let path = directory.path().join(name);
            aegis_core::secret_file::write_private_new(&path, bytes)?;
            Ok(path)
        };
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
        let ca = params.self_signed(&ca_key)?;
        let ca_path = write("inner-ca.pem", ca.pem().as_bytes())?;
        let mut identities = Vec::new();
        for (name, usage) in [
            ("inner.test", ExtendedKeyUsagePurpose::ServerAuth),
            ("device.test", ExtendedKeyUsagePurpose::ClientAuth),
            ("unlisted.test", ExtendedKeyUsagePurpose::ClientAuth),
        ] {
            let mut params = CertificateParams::new(vec![name.into()])?;
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![usage];
            let key = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
            let cert = params.signed_by(&key, &ca, &ca_key)?;
            identities.push((
                write(&format!("{name}.pem"), cert.pem().as_bytes())?,
                write(&format!("{name}.key"), key.serialize_pem().as_bytes())?,
                hex::encode(Sha256::digest(cert.der())),
            ));
        }
        let client = secure_channel::ClientSettings {
            server_name: "inner.test".into(),
            server_ca: ca_path.clone(),
            cert: identities[1].0.clone(),
            key: identities[1].1.clone(),
        };
        let unlisted_client = secure_channel::ClientSettings {
            server_name: "inner.test".into(),
            server_ca: ca_path.clone(),
            cert: identities[2].0.clone(),
            key: identities[2].1.clone(),
        };
        let server = secure_channel::Server::load(&secure_channel::ServerSettings {
            cert: identities[0].0.clone(),
            key: identities[0].1.clone(),
            client_ca: ca_path,
            allowed_client_sha256: vec![identities[1].2.clone()],
            device_registry: None,
            handshake_timeout_ms: 2000,
            idle_timeout_ms: 2000,
            admission: Default::default(),
        })?;
        let certificate = rcgen::generate_simple_self_signed(vec!["site.test".into()])?;
        let outer_ca = write("outer.pem", certificate.cert.pem().as_bytes())?;
        let outer_key = write("outer.key", certificate.key_pair.serialize_pem().as_bytes())?;
        let mut outer = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der())
                .into(),
        )?;
        outer.alpn_protocols = vec![b"h2".to_vec()];
        let auth_file = write(
            "local-auth.json",
            &serde_json::to_vec(
                &serde_json::json!({"version":1,"username":USER,"password":PASSWORD}),
            )?,
        )?;
        let admission_file = write("carrier-admission.key", &[b'a'; 64])?;
        Ok(Self {
            directory,
            client,
            unlisted_client,
            server,
            outer_ca,
            outer_key,
            client_digest: identities[1].2.clone(),
            outer: TlsAcceptor::from(Arc::new(outer)),
            auth_file,
            admission_file,
        })
    }

    pub(crate) async fn target(&self, tasks: &mut Tasks) -> Result<(SocketAddr, Arc<AtomicUsize>)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let opens = Arc::new(AtomicUsize::new(0));
        let observed = opens.clone();
        tasks.0.spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            observed.fetch_add(1, Ordering::SeqCst);
            let mut marker = [0; 17];
            stream.read_exact(&mut marker).await?;
            ensure!(&marker == b"local-auth-uplink", "uplink marker changed");
            stream.write_all(b"local-auth-downlink").await?;
            stream.shutdown().await?;
            Ok(())
        });
        Ok((address, opens))
    }
}

pub(crate) fn connect_request(target: SocketAddr) -> Result<Vec<u8>> {
    let IpAddr::V4(ip) = target.ip() else {
        anyhow::bail!("fixture requires IPv4")
    };
    let mut bytes = vec![5, 1, 0, 1];
    bytes.extend(ip.octets());
    bytes.extend(target.port().to_be_bytes());
    Ok(bytes)
}

pub(crate) async fn authenticate(
    stream: &mut TcpStream,
    password: &str,
) -> Result<([u8; 2], [u8; 2])> {
    stream.write_all(&[5, 2, 0, 2]).await?;
    let mut method = [0; 2];
    stream.read_exact(&mut method).await?;
    let mut request = vec![1, USER.len() as u8];
    request.extend(USER.as_bytes());
    request.push(password.len() as u8);
    request.extend(password.as_bytes());
    stream.write_all(&request).await?;
    let mut auth = [0; 2];
    stream.read_exact(&mut auth).await?;
    Ok((method, auth))
}

pub(crate) async fn positive_wire(stream: &mut TcpStream, target: SocketAddr) -> Result<()> {
    let (method, auth) = authenticate(stream, PASSWORD).await?;
    ensure!(
        method == [5, 2] && auth == [1, 0],
        "RFC1929 success contract changed"
    );
    stream.write_all(&connect_request(target)?).await?;
    let mut reply = [0; 10];
    stream.read_exact(&mut reply).await?;
    ensure!(
        reply == [5, 0, 0, 1, 0, 0, 0, 0, 0, 0],
        "authenticated target refused"
    );
    stream.write_all(b"local-auth-uplink").await?;
    let mut marker = [0; 19];
    stream.read_exact(&mut marker).await?;
    ensure!(&marker == b"local-auth-downlink", "downlink marker changed");
    stream.shutdown().await?;
    Ok(())
}

pub(crate) async fn serve_device<S>(
    stream: S,
    identity: secure_channel::Server,
    authenticated: impl FnOnce() -> std::io::Result<()> + Send + 'static,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    aegis_server::session::serve_device_carrier(
        stream,
        identity,
        &aegis_server::config::TargetPolicyConfig {
            profile: aegis_server::config::TargetPolicyProfile::FullVpnEgress,
            allowed_ports: Vec::new(),
        },
        &aegis_server::rate_limit::RateLimiter::new(3, 60, false),
        None,
        authenticated,
        None,
    )
    .await
}

pub(crate) struct Harness {
    tasks: Tasks,
    stop: aegis_web_carrier::Cancellation,
    owner: Option<JoinHandle<std::io::Result<()>>>,
    web: Arc<aegis_web_carrier::Server>,
    remote: Arc<AtomicUsize>,
    cfg: Arc<Config>,
    identity: secure_channel::Client,
    credential: Credential,
    tls: tokio_rustls::TlsConnector,
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(owner) = &self.owner {
            owner.abort();
        }
    }
}
impl Harness {
    pub(crate) async fn new(fixture: &IdentityFixture, connect_ms: u64) -> Result<Self> {
        let mut tasks = Tasks::default();
        let real = TcpListener::bind("127.0.0.1:0").await?;
        let real_address = real.local_addr()?;
        let proxy = Arc::new(TcpListener::bind("127.0.0.1:0").await?);
        let address = proxy.local_addr()?;
        let remote = Arc::new(AtomicUsize::new(0));
        let path = fixture.directory.path().join("carrier.toml");
        let raw = format!("listen = \"127.0.0.1:0\"\nlocal_socks_auth_file = {}\nbootstrap = \"{address}\"\nallowed_ingress_ips = [\"127.0.0.1\"]\nouter_ca = {}\nconnect_timeout_ms = {connect_ms}\nidle_timeout_ms = 2000\nmax_sessions = 2\n[inner_tls]\n{}[web]\nauthority = \"site.test\"\ndescriptor_path = \"/private/descriptor\"\ncredential_file = {}\n", toml_path(&fixture.auth_file), toml_path(&fixture.outer_ca), toml::to_string(&fixture.client)?, toml_path(&fixture.admission_file));
        aegis_core::secret_file::write_private_new(&path, raw.as_bytes())?;
        let (cfg, credential) = load(&path)?;
        let tls = connector(&cfg)?;
        let identity = secure_channel::Client::load(&cfg.inner_tls)?;
        let web = aegis_web_carrier::Server::new(
            aegis_web_carrier::ServerSettings {
                client: cfg.web.clone(),
                site_html: "<title>Fixture</title>".into(),
            },
            credential.clone(),
            Limits::default(),
        )?;
        web.rotate_ingress(address)?;
        let (sender, mut receiver) = mpsc::channel::<aegis_web_carrier::AcceptedSession>(2);
        let stop = aegis_web_carrier::Cancellation::default();
        let served = web.clone();
        let stopping = stop.clone();
        let acceptor = fixture.outer.clone();
        let owner = tokio::spawn(async move {
            served
                .serve_at(real, address, acceptor, sender, stopping)
                .await
        });
        // Fixed finite owned forwarding tasks witness all bootstrap/OPEN TCP I/O.
        for _ in 0..6 {
            let listener = proxy.clone();
            let counter = remote.clone();
            tasks.0.spawn(async move {
                let (mut incoming, _) = listener.accept().await?;
                counter.fetch_add(1, Ordering::SeqCst);
                let mut outgoing = TcpStream::connect(real_address).await?;
                let _ = tokio::io::copy_bidirectional(&mut incoming, &mut outgoing).await;
                Ok(())
            });
        }
        let device = fixture.server.clone();
        let device_stop = stop.clone();
        tasks.0.spawn(async move {
            let Some(accepted) = receiver.recv().await else {
                ensure!(device_stop.is_cancelled(), "device owner missing");
                return Ok(());
            };
            let (stream, authorization) = accepted.into_parts();
            let _ = serve_device(stream, device, move || authorization.mark_authenticated()).await;
            Ok(())
        });
        Ok(Self {
            tasks,
            stop,
            owner: Some(owner),
            web,
            remote,
            cfg: Arc::new(cfg),
            identity,
            credential,
            tls,
        })
    }
    async fn local(&mut self) -> Result<(TcpStream, oneshot::Receiver<bool>)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let client = TcpStream::connect(listener.local_addr()?).await?;
        let (server, _) = listener.accept().await?;
        let cfg = self.cfg.clone();
        let credential = self.credential.clone();
        let identity = self.identity.clone();
        let tls = self.tls.clone();
        let (sender, receiver) = oneshot::channel();
        self.tasks.0.spawn(async move {
            let refused = session(server, cfg, credential, identity, tls)
                .await
                .is_err();
            let _ = sender.send(refused);
            Ok(())
        });
        Ok((client, receiver))
    }
    pub(crate) fn bootstrap(&self) -> SocketAddr {
        self.cfg.bootstrap
    }
    pub(crate) async fn target(
        &mut self,
        fixture: &IdentityFixture,
    ) -> Result<(SocketAddr, Arc<AtomicUsize>)> {
        fixture.target(&mut self.tasks).await
    }
    pub(crate) async fn finish(&mut self) -> Result<()> {
        let deadline = tokio::time::Instant::now() + CLEANUP_BOUND;
        let mut first_error = None;
        self.stop.cancel();
        if let Some(mut owner) = self.owner.take() {
            match tokio::time::timeout_at(deadline, &mut owner).await {
                Ok(Ok(Ok(()))) => {}
                Ok(_) => first_error = Some(anyhow::anyhow!("carrier owner join failed")),
                Err(_) => {
                    owner.abort();
                    let _ = tokio::time::timeout_at(deadline, &mut owner).await;
                    first_error = Some(anyhow::anyhow!("carrier owner cleanup deadline"));
                }
            }
        }
        // Owner failure must still enter every remaining abort/drain attempt.
        // This absolute cleanup deadline cannot renew. Expiry is a failure,
        // never joined-cleanup evidence for unconfirmed handles.
        if let Err(error) = self.tasks.finish_before(deadline).await {
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
        let stats = self.web.stats();
        if (stats.active_connections != 0
            || stats.active_requests != 0
            || stats.active_sessions != 0)
            && first_error.is_none()
        {
            first_error = Some(anyhow::anyhow!("carrier owned resources remain"));
        }
        first_error.map_or(Ok(()), Err)
    }
}

async fn exercise(kind: u8) -> Result<()> {
    let fixture = IdentityFixture::new()?;
    let mut harness = Harness::new(&fixture, if kind == 3 { 4000 } else { 5000 }).await?;
    let outcome = timeout(WORK_BOUND, async {
        let (target, opens) = fixture.target(&mut harness.tasks).await?;
        // Include local session spawn/setup in the trickle timing precondition.
        let start = tokio::time::Instant::now();
        let (mut client, done) = harness.local().await?;
        match kind {
            0 => {
                client.write_all(&[5,1,0]).await?;
                let mut reply = [0;2]; client.read_exact(&mut reply).await?;
                // Obey method negotiation. Only the actually admitted old
                // session receives CONNECT; refusal has no unread request.
                if reply == [5,0] { client.write_all(&connect_request(target)?).await?; }
                // Gather the actual owner witness before asserting the method;
                // the old method0 session really contacts this descriptor owner.
                let _ = timeout(Duration::from_millis(250), async { while harness.remote.load(Ordering::SeqCst) == 0 { tokio::task::yield_now().await; } }).await;
                ensure!(reply == [5,255], "unauthenticated method admitted: selected={} remote_connects={} target_opens={}", reply[1], harness.remote.load(Ordering::SeqCst), opens.load(Ordering::SeqCst));
                let mut tail = Vec::new(); client.read_to_end(&mut tail).await?;
                ensure!(tail.is_empty(), "auth refusal appended request reply");
                ensure!(done.await?, "auth refusal did not return an error");
            }
            1 => {
                let (method, auth) = authenticate(&mut client, "wrong-local-password").await?;
                ensure!(method == [5,2] && auth == [1,1], "RFC1929 refusal changed");
                let mut tail = Vec::new(); client.read_to_end(&mut tail).await?;
                ensure!(tail.is_empty() && done.await?, "auth refusal did not close directly");
            }
            2 => { positive_wire(&mut client, target).await?; ensure!(opens.load(Ordering::SeqCst) == 1 && harness.remote.load(Ordering::SeqCst) >= 2, "actual descriptor/device/target path was not exercised"); }
            3 => {
                client.write_all(&[5,1,2]).await?; let mut method = [0;2]; client.read_exact(&mut method).await?;
                ensure!(method == [5,2], "partial-auth method changed");
                tokio::time::sleep(Duration::from_millis(2000)).await;
                client.write_all(&[1, USER.len() as u8, USER.as_bytes()[0]]).await?;
                let trickle_elapsed = start.elapsed();
                ensure!(
                    trickle_elapsed < Duration::from_millis(3000),
                    "auth trickle test setup missed the original 4000 ms deadline: {trickle_elapsed:?}"
                );
                // The 3200 ms read bound after the late byte is shorter than a
                // fresh 4000 ms auth timer. EOF proves that trickling did not
                // renew the session's original establishment deadline.
                let mut tail = Vec::new();
                timeout(Duration::from_millis(3200), client.read_to_end(&mut tail))
                    .await
                    .map_err(|_| anyhow::anyhow!("auth trickle outlived original single deadline"))??;
                ensure!(tail.is_empty(), "auth trickle appended response");
                ensure!(done.await?, "auth trickle session did not return an error");
            }
            _ => unreachable!(),
        }
        if kind != 2 { ensure!(harness.remote.load(Ordering::SeqCst) == 0 && opens.load(Ordering::SeqCst) == 0, "preauth work reached remote/target owner"); }
        Ok(())
    }).await.map_err(|_| anyhow::anyhow!("carrier local-auth work deadline"));
    let cleanup = harness.finish().await;
    cleanup?;
    outcome??;
    Ok(())
}

#[tokio::test]
async fn carrier_no_auth_cannot_contact_descriptor_or_target() {
    exercise(0).await.unwrap();
}
#[tokio::test]
async fn carrier_wrong_auth_closes_before_descriptor() {
    exercise(1).await.unwrap();
}
#[tokio::test]
async fn carrier_valid_auth_preserves_real_device_and_target() {
    exercise(2).await.unwrap();
}
#[tokio::test]
async fn carrier_auth_trickle_keeps_original_single_deadline() {
    exercise(3).await.unwrap();
}

#[test]
fn socks_config_debug_redacts_inline_credentials() {
    let auth = crate::socks5::SocksAuthCfg::from_config(PASSWORD, Some(USER));
    let rendered = format!("{auth:?}");
    assert!(!rendered.contains(PASSWORD) && !rendered.contains(USER));
}

#[test]
fn carrier_load_requires_private_record_before_run_can_bind() -> Result<()> {
    let fixture = IdentityFixture::new()?;
    let path = fixture.directory.path().join("missing-record-carrier.toml");
    let raw = format!("listen = \"127.0.0.1:0\"\nlocal_socks_auth_file = {}\nbootstrap = \"127.0.0.1:1\"\nallowed_ingress_ips = [\"127.0.0.1\"]\nouter_ca = {}\nconnect_timeout_ms = 500\nidle_timeout_ms = 1000\nmax_sessions = 1\n[inner_tls]\n{}[web]\nauthority = \"site.test\"\ndescriptor_path = \"/private/descriptor\"\ncredential_file = {}\n", toml_path(&fixture.directory.path().join("missing.json")), toml_path(&fixture.outer_ca), toml::to_string(&fixture.client)?, toml_path(&fixture.admission_file));
    aegis_core::secret_file::write_private_new(&path, raw.as_bytes())?;
    // Separate startup control; this is NOT the behavioral causal RED.
    assert!(load(&path).is_err());
    assert!(!fixture.directory.path().join("missing.json").exists());
    Ok(())
}
