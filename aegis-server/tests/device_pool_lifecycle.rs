//! Bounded, local-only three-process enrollment/revocation convergence proof.
//! The controller below is test code, not a production registry distributor.
#![cfg(unix)]

use aegis_core::h2_stream::H2Stream;
use aegis_core::secure_channel::{
    self, datagram, enrollment, grpc_io::GrpcIo, registry::DeviceRegistry, Client, ClientSettings,
    OpenRequest, Transport,
};
use anyhow::{ensure, Context, Result};
use futures::future::join_all;
use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::process::{Child, Command};
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsConnector;

const SERVER: &str = env!("CARGO_BIN_EXE_aegis-server");
const RELAYS: usize = 3;
const OPEN_BOUND: Duration = Duration::from_secs(4);
const REVOKE_BOUND: Duration = Duration::from_secs(6);
const TEST_BOUND: Duration = Duration::from_secs(240);

type Inner = tokio_rustls::client::TlsStream<GrpcIo<H2Stream>>;

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

fn binary_digest() -> Result<String> {
    let mut file = File::open(SERVER)?;
    let mut digest = Sha256::new();
    let mut block = vec![0; 1024 * 1024];
    loop {
        let count = file.read(&mut block)?;
        if count == 0 {
            break;
        }
        digest.update(&block[..count]);
    }
    Ok(hex::encode(digest.finalize()))
}

struct Receipt {
    output: Option<PathBuf>,
    started: Instant,
    value: Arc<Mutex<Value>>,
}

impl Receipt {
    fn new() -> Self {
        Self {
            output: std::env::var_os("AEGIS_POOL_PROOF_RECEIPT").map(PathBuf::from),
            started: Instant::now(),
            value: Arc::new(Mutex::new(json!({
                "schema":"aegis_synthetic_device_pool_proof_v2",
                "build_base_commit":env!("AEGIS_BUILD_GIT_SHA"),
                "working_tree_changes_may_be_present":true,
                "started_unix_ms":unix_ms(),
                "status":"incomplete",
                "platform":std::env::consts::OS,
                "arch":std::env::consts::ARCH,
                "relays":RELAYS,
                "scope":"Local synthetic subprocess convergence, not deployed fleet or signed-candidate acceptance",
                "controller":"Actual device apply-snapshot CLI per relay; test-only coordinated invocation",
                "limitations":[
                    "Per-relay publication is not a global atomic transaction",
                    "A disconnected relay denies access when its last explicitly issued policy expires; refresh delivery remains an operator responsibility",
                    "Closure measurements are observed upper bounds in this run, not a production SLA",
                    "Combined rollback of registry and protected floor, or compromise of their owner, is outside this guarantee",
                    "No production keys, device records, services, network hosts or release assets are used"
                ],
                "events":[]
            }))),
        }
    }
    fn event(&self, event: Value) {
        self.value.lock().unwrap()["events"]
            .as_array_mut()
            .unwrap()
            .push(event);
    }
    fn complete(&self) {
        let mut value = self.value.lock().unwrap();
        value["status"] = json!("scoped_three_process_assertions_passed");
        value["elapsed_ms"] = json!(self.started.elapsed().as_millis());
        value["completed_unix_ms"] = json!(unix_ms());
    }
}

impl Drop for Receipt {
    fn drop(&mut self) {
        let value = self.value.lock().unwrap();
        if let Some(path) = &self.output {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            if let Ok(bytes) = serde_json::to_vec_pretty(&*value) {
                let _ = fs::write(path, bytes);
            }
        }
    }
}

fn private_directory(path: &Path) -> Result<()> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    enrollment::write_private_new(path, bytes)?;
    Ok(())
}

async fn operator_output(args: &[String]) -> Result<std::process::Output> {
    let mut command = Command::new(SERVER);
    command
        .args(args)
        .env("AEGIS_NO_BANNER", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(45), command.output())
        .await
        .context("operator CLI wall-clock bound")??;
    Ok(output)
}

async fn operator_status(args: &[String]) -> Result<std::process::ExitStatus> {
    Ok(operator_output(args).await?.status)
}

async fn operator(args: &[String]) -> Result<()> {
    let output = operator_output(args).await?;
    let operation = if args.first().map(String::as_str) == Some("device") {
        args.get(3).map(String::as_str)
    } else {
        args.first().map(String::as_str)
    }
    .unwrap_or("unknown");
    if !output.status.success() {
        // Only fixture-generated arguments and PKI reach this subprocess.
        // Keep stdout (which may contain enrollment records) out of receipts.
        eprintln!(
            "synthetic operator {operation} stderr: {}",
            String::from_utf8_lossy(&output.stderr[..output.stderr.len().min(2048)])
        );
    }
    ensure!(
        output.status.success(),
        "operator {operation} failed with {}",
        output.status
    );
    Ok(())
}

struct Device {
    name: String,
    key: PathBuf,
    cert: PathBuf,
}

struct Issuer {
    directory: PathBuf,
    registry: PathBuf,
    ca: Certificate,
    ca_key: KeyPair,
}

impl Issuer {
    async fn new(base: &Path) -> Result<Self> {
        let directory = base.join("operator");
        private_directory(&directory)?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
        let ca = params.self_signed(&ca_key)?;
        private_file(&directory.join("ca.pem"), ca.pem().as_bytes())?;
        private_file(&directory.join("ca.key"), ca_key.serialize_pem().as_bytes())?;
        let registry = directory.join("registry.json");
        operator(&[
            "device".into(),
            "--registry".into(),
            registry.display().to_string(),
            "init".into(),
        ])
        .await?;
        Ok(Self {
            directory,
            registry,
            ca,
            ca_key,
        })
    }

    async fn issue(&self, devices: &Path, name: &str, rotation: bool) -> Result<Device> {
        let suffix = if rotation { "replacement" } else { "initial" };
        let directory = devices.join(format!("{name}-{suffix}"));
        private_directory(&directory)?;
        let material = enrollment::generate_csr(name)?;
        let key = directory.join("device.key");
        let csr = directory.join("device.csr");
        let cert = directory.join("device.pem");
        private_file(&key, material.private_key_pem.as_bytes())?;
        private_file(&csr, material.csr_pem.as_bytes())?;
        let invitation = self.directory.join(format!("{name}-{suffix}.invitation"));
        operator(&[
            "device".into(),
            "--registry".into(),
            self.registry.display().to_string(),
            if rotation { "rotate-invite" } else { "invite" }.into(),
            "--device-id".into(),
            name.into(),
            "--token-out".into(),
            invitation.display().to_string(),
            "--ttl-secs".into(),
            "600".into(),
        ])
        .await?;
        operator(&[
            "device".into(),
            "--registry".into(),
            self.registry.display().to_string(),
            "issue".into(),
            "--csr".into(),
            csr.display().to_string(),
            "--invitation-file".into(),
            invitation.display().to_string(),
            "--ca-cert".into(),
            self.directory.join("ca.pem").display().to_string(),
            "--ca-key".into(),
            self.directory.join("ca.key").display().to_string(),
            "--certificate-out".into(),
            cert.display().to_string(),
            "--lifetime-secs".into(),
            "3600".into(),
        ])
        .await?;
        Ok(Device {
            name: name.into(),
            key,
            cert,
        })
    }

    async fn revoke(&self, device: &Device) -> Result<()> {
        operator(&[
            "device".into(),
            "--registry".into(),
            self.registry.display().to_string(),
            "revoke".into(),
            "--device-id".into(),
            device.name.clone(),
        ])
        .await
    }

    async fn refresh(&self, ttl_secs: u64) -> Result<Vec<u8>> {
        operator(&[
            "device".into(),
            "--registry".into(),
            self.registry.display().to_string(),
            "refresh-registry".into(),
            "--ttl-secs".into(),
            ttl_secs.to_string(),
        ])
        .await?;
        self.snapshot()
    }

    fn snapshot(&self) -> Result<Vec<u8>> {
        DeviceRegistry::load(&self.registry)?;
        Ok(fs::read(&self.registry)?)
    }
}

struct Relay {
    id: usize,
    directory: PathBuf,
    address: SocketAddr,
    outer: TlsConnector,
    child: Option<Child>,
}

impl Relay {
    fn prepare(base: &Path, id: usize, issuer: &Issuer) -> Result<Self> {
        let directory = base.join(format!("relay-{id}"));
        private_directory(&directory)?;
        let name = format!("relay-{id}.test");
        let mut params = CertificateParams::new(vec![name])?;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let key = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
        let inner = params.signed_by(&key, &issuer.ca, &issuer.ca_key)?;
        private_file(&directory.join("inner.pem"), inner.pem().as_bytes())?;
        private_file(&directory.join("inner.key"), key.serialize_pem().as_bytes())?;
        private_file(&directory.join("ca.pem"), issuer.ca.pem().as_bytes())?;
        let outer = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        private_file(&directory.join("outer.pem"), outer.cert.pem().as_bytes())?;
        private_file(
            &directory.join("outer.key"),
            outer.key_pair.serialize_pem().as_bytes(),
        )?;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(outer.cert.der().clone())?;
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let reservation = std::net::TcpListener::bind("127.0.0.1:0")?;
        let address = reservation.local_addr()?;
        let config = format!(
            r#"listen = "{address}"
cert = "outer.pem"
key = "outer.key"
fallback = "close"
[target_policy]
profile = "full_vpn_egress"
[rate_limit]
enabled = false
[limits]
shutdown_grace_ms = 200
[transport]
quic_listen = "127.0.0.1:0"
[transport.inner_tls]
cert = "inner.pem"
key = "inner.key"
client_ca = "ca.pem"
device_registry = "registry.json"
handshake_timeout_ms = 3000
idle_timeout_ms = 300000
"#
        );
        private_file(&directory.join("server.toml"), config.as_bytes())?;
        drop(reservation);
        Ok(Self {
            id,
            directory,
            address,
            outer: TlsConnector::from(Arc::new(tls)),
            child: None,
        })
    }

    async fn start(&mut self) -> Result<()> {
        ensure!(self.child.is_none(), "relay already started");
        let child = Command::new(SERVER)
            .arg("--config")
            .arg(self.directory.join("server.toml"))
            .current_dir(&self.directory)
            .env("AEGIS_NO_BANNER", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        self.child = Some(child);
        tokio::time::timeout(Duration::from_secs(35), async {
            loop {
                if self.child.as_mut().unwrap().try_wait()?.is_some() {
                    anyhow::bail!("relay exited before ready");
                }
                if TcpStream::connect(self.address).await.is_ok() {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .context("relay startup bound")?
    }

    async fn stop(&mut self) -> Result<()> {
        if let Some(mut child) = self.child.take() {
            child.start_kill()?;
            tokio::time::timeout(Duration::from_secs(5), child.wait())
                .await
                .context("relay reap bound")??;
        }
        Ok(())
    }

    async fn publish(&self, bytes: &[u8], receipt: &Receipt, phase: &str) -> Result<Instant> {
        let started = Instant::now();
        let started_unix_ms = unix_ms();
        let registry: DeviceRegistry = serde_json::from_slice(bytes)?;
        registry.validate()?;
        let mut input = tempfile::NamedTempFile::new_in(&self.directory)?;
        input.write_all(bytes)?;
        input.as_file().sync_all()?;
        operator(&[
            "device".into(),
            "--registry".into(),
            self.directory.join("registry.json").display().to_string(),
            "apply-snapshot".into(),
            "--input".into(),
            input.path().display().to_string(),
        ])
        .await?;
        let published = DeviceRegistry::load(&self.directory.join("registry.json"))?;
        ensure!(
            serde_json::to_value(published)? == serde_json::to_value(&registry)?,
            "apply-snapshot success did not publish the requested verified snapshot"
        );
        ensure!(
            !self.directory.join("registry.json.pending").exists(),
            "successful apply-snapshot left a pending recovery operation"
        );
        receipt.event(
            json!({"phase":phase,"operation":"device_apply_snapshot_committed","relay":self.id,
            "generation":registry.generation,"policy":registry.validity,"delivery_started_unix_ms":started_unix_ms,
            "delivery_ack_unix_ms":unix_ms(),"delivery_cli_ms":started.elapsed().as_millis(),
            "published_pair_verified":true,"pending_present":false}),
        );
        Ok(started)
    }

    async fn reject_old_publish(&self, bytes: &[u8], receipt: &Receipt) -> Result<()> {
        let before = fs::read(self.directory.join("registry.json"))?;
        let floor_before = fs::read(self.directory.join("registry.json.floor"))?;
        let mut input = tempfile::NamedTempFile::new_in(&self.directory)?;
        input.write_all(bytes)?;
        input.as_file().sync_all()?;
        let status = operator_status(&[
            "device".into(),
            "--registry".into(),
            self.directory.join("registry.json").display().to_string(),
            "apply-snapshot".into(),
            "--input".into(),
            input.path().display().to_string(),
        ])
        .await?;
        ensure!(
            !status.success(),
            "operator accepted an older authorization snapshot"
        );
        ensure!(
            fs::read(self.directory.join("registry.json"))? == before,
            "rejected apply changed registry"
        );
        ensure!(
            fs::read(self.directory.join("registry.json.floor"))? == floor_before,
            "rejected apply changed durable floor"
        );
        ensure!(
            !self.directory.join("registry.json.pending").exists(),
            "rejected older input left a pending recovery operation"
        );
        receipt.event(json!({"phase":"rollback_protection","operation":"older_apply_rejected_without_registry_or_floor_change","relay":self.id}));
        Ok(())
    }

    fn inject_registry_only_rollback(&self, bytes: &[u8]) -> Result<Instant> {
        let started = Instant::now();
        // Synthetic fault: replace only the authorization snapshot. Leave its
        // protected floor untouched; this is deliberately NOT a delivery path.
        let mut staging = tempfile::NamedTempFile::new_in(&self.directory)?;
        staging.write_all(bytes)?;
        staging.as_file().sync_all()?;
        staging
            .persist(self.directory.join("registry.json"))
            .map_err(|e| e.error)?;
        File::open(&self.directory)?.sync_all()?;
        Ok(started)
    }

    async fn start_rejected(&mut self) -> Result<()> {
        ensure!(self.child.is_none(), "relay already started");
        let status = tokio::time::timeout(
            Duration::from_secs(15),
            Command::new(SERVER)
                .arg("--config")
                .arg(self.directory.join("server.toml"))
                .current_dir(&self.directory)
                .env("AEGIS_NO_BANNER", "1")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .status(),
        )
        .await
        .context("invalid-snapshot startup bound")??;
        ensure!(
            !status.success(),
            "rolled-back registry unexpectedly started relay"
        );
        ensure!(
            TcpStream::connect(self.address).await.is_err(),
            "rolled-back relay opened listener"
        );
        Ok(())
    }
}

struct Task<T>(JoinHandle<T>);
impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct EchoTargets {
    tcp: u16,
    udp: u16,
    _tcp: Task<()>,
    _udp: Task<()>,
}

impl EchoTargets {
    async fn start() -> Result<Self> {
        let tcp = TcpListener::bind("127.0.0.1:0").await?;
        let udp = UdpSocket::bind("127.0.0.1:0").await?;
        let tcp_port = tcp.local_addr()?.port();
        let udp_port = udp.local_addr()?.port();
        let tcp_task = Task(tokio::spawn(async move {
            let mut children = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = tcp.accept() => {
                        let Ok((mut stream, _)) = accepted else { break; };
                        children.spawn(async move {
                            let mut bytes = [0; 4096];
                            loop {
                                let count = match stream.read(&mut bytes).await { Ok(0)|Err(_) => return, Ok(n)=>n };
                                if stream.write_all(&bytes[..count]).await.is_err() { return; }
                            }
                        });
                    },
                    _ = children.join_next(), if !children.is_empty() => {},
                }
            }
        }));
        let udp_task = Task(tokio::spawn(async move {
            let mut bytes = [0; 65_535];
            while let Ok((count, peer)) = udp.recv_from(&mut bytes).await {
                if udp.send_to(&bytes[..count], peer).await.is_err() {
                    break;
                }
            }
        }));
        Ok(Self {
            tcp: tcp_port,
            udp: udp_port,
            _tcp: tcp_task,
            _udp: udp_task,
        })
    }
}

struct Flow {
    inner: Inner,
    _driver: Task<Result<(), h2::Error>>,
    relay: usize,
    transport: Transport,
    roundtrip: u32,
}

fn transport_name(transport: Transport) -> &'static str {
    match transport {
        Transport::Tcp => "tcp",
        Transport::Udp => "udp",
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
enum OpeningStage {
    #[error("outer TCP establishment")]
    OuterTcp,
    #[error("outer TLS establishment")]
    OuterTls,
    #[error("outer H2 establishment")]
    OuterH2,
    #[error("inner TLS authentication")]
    InnerTls,
    #[error("authenticated open write")]
    InnerOpenWrite,
    #[error("authenticated open acknowledgment")]
    InnerOpenAck,
}

impl Flow {
    async fn open(
        relay: &Relay,
        device: &Device,
        targets: &EchoTargets,
        transport: Transport,
    ) -> Result<Self> {
        tokio::time::timeout(OPEN_BOUND, async {
            let tcp = TcpStream::connect(relay.address)
                .await
                .context(OpeningStage::OuterTcp)?;
            let outer = relay
                .outer
                .connect("localhost".try_into().unwrap(), tcp)
                .await
                .context(OpeningStage::OuterTls)?;
            let (mut requests, connection) = h2::client::handshake(outer)
                .await
                .context(OpeningStage::OuterH2)?;
            let driver = Task(tokio::spawn(connection));
            let request = http::Request::builder()
                .method("POST")
                .uri(secure_channel::GRPC_PATH)
                .header("content-type", "application/grpc")
                .body(())?;
            let (response, send) = requests.send_request(request, false)?;
            let response = response.await?;
            ensure!(response.status().is_success(), "secure carrier HTTP status");
            let client = Client::load(&ClientSettings {
                server_name: format!("relay-{}.test", relay.id),
                server_ca: relay.directory.join("ca.pem"),
                cert: device.cert.clone(),
                key: device.key.clone(),
            })?;
            let mut inner = client
                .connect(GrpcIo::new(H2Stream::new(send, response.into_body())))
                .await
                .context(OpeningStage::InnerTls)?;
            secure_channel::write_open(
                &mut inner,
                &OpenRequest {
                    version: 1,
                    transport,
                    host: "127.0.0.1".into(),
                    port: match transport {
                        Transport::Tcp => targets.tcp,
                        Transport::Udp => targets.udp,
                    },
                },
            )
            .await
            .context(OpeningStage::InnerOpenWrite)?;
            ensure!(
                inner.read_u8().await.context(OpeningStage::InnerOpenAck)? == 0,
                "secure channel denied target/open"
            );
            Ok(Self {
                inner,
                _driver: driver,
                relay: relay.id,
                transport,
                roundtrip: 0,
            })
        })
        .await
        .context("secure opening bound")?
    }

    async fn ping(&mut self) -> Result<()> {
        self.roundtrip += 1;
        let payload = format!(
            "synthetic-pool-{}-{}-{}",
            self.relay,
            transport_name(self.transport),
            self.roundtrip
        )
        .into_bytes();
        tokio::time::timeout(Duration::from_secs(3), async {
            match self.transport {
                Transport::Tcp => {
                    self.inner.write_all(&payload).await?;
                    self.inner.flush().await?;
                    let mut echoed = vec![0; payload.len()];
                    self.inner.read_exact(&mut echoed).await?;
                    ensure!(echoed == payload, "TCP payload differs");
                }
                Transport::Udp => {
                    datagram::write(&mut self.inner, &payload).await?;
                    ensure!(
                        datagram::read(&mut self.inner).await?.as_deref()
                            == Some(payload.as_slice()),
                        "UDP datagram differs"
                    );
                }
            }
            Ok(())
        })
        .await
        .context("payload roundtrip bound")?
    }

    async fn closed(mut self, trigger: Instant, receipt: &Receipt, phase: &str) -> Result<()> {
        let result = tokio::time::timeout(REVOKE_BOUND, self.inner.read_u8())
            .await
            .context("active authorization closure bound")?;
        ensure!(
            result.is_err(),
            "unexpected application data while awaiting closure"
        );
        receipt.event(json!({"phase":phase,"operation":"active_session_closed","relay":self.relay,
            "transport":transport_name(self.transport),"observed_since_trigger_ms":trigger.elapsed().as_millis()}));
        Ok(())
    }
}

async fn open_pair(relay: &Relay, device: &Device, targets: &EchoTargets) -> Result<Vec<Flow>> {
    let mut flows = Vec::new();
    for transport in [Transport::Tcp, Transport::Udp] {
        let mut flow = Flow::open(relay, device, targets, transport).await?;
        flow.ping().await?;
        flows.push(flow);
    }
    Ok(flows)
}

async fn ping_pair(flows: &mut [Flow]) -> Result<()> {
    for flow in flows {
        flow.ping().await?;
    }
    Ok(())
}

async fn close_pair(
    flows: Vec<Flow>,
    commit: Instant,
    receipt: &Receipt,
    phase: &str,
) -> Result<()> {
    for result in join_all(
        flows
            .into_iter()
            .map(|flow| flow.closed(commit, receipt, phase)),
    )
    .await
    {
        result?;
    }
    Ok(())
}

async fn deny_pair(
    relay: &Relay,
    device: &Device,
    targets: &EchoTargets,
    receipt: &Receipt,
    phase: &str,
) -> Result<()> {
    for transport in [Transport::Tcp, Transport::Udp] {
        let error = match Flow::open(relay, device, targets, transport).await {
            Ok(_) => anyhow::bail!("removed identity was admitted"),
            Err(error) => error,
        };
        let stage = error.downcast_ref::<OpeningStage>();
        ensure!(
            matches!(
                stage,
                Some(
                    OpeningStage::InnerTls
                        | OpeningStage::InnerOpenWrite
                        | OpeningStage::InnerOpenAck
                )
            ),
            "rejection was not observed inside the established secure carrier: {error:#}"
        );
        receipt.event(
            json!({"phase":phase,"operation":"reconnect_rejected","relay":relay.id,
            "transport":transport_name(transport),"device":device.name}),
        );
    }
    Ok(())
}

async fn recover_pair(relay: &Relay, device: &Device, targets: &EchoTargets) -> Result<Vec<Flow>> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match open_pair(relay, device, targets).await {
                Ok(flows) => return Ok(flows),
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await
    .context("authorization recovery bound")?
}

async fn pool_proof(receipt: &Receipt) -> Result<()> {
    receipt.value.lock().unwrap()["server_binary_sha256"] = json!(binary_digest()?);
    // Warm only process startup before opening any measured network session.
    operator(&["--version".into()]).await?;
    let directory = tempfile::tempdir()?;
    let devices = directory.path().join("devices");
    private_directory(&devices)?;
    let issuer = Issuer::new(directory.path()).await?;
    let victim = issuer.issue(&devices, "victim", false).await?;
    let rotator = issuer.issue(&devices, "rotator", false).await?;
    let neighbor = issuer.issue(&devices, "neighbor", false).await?;
    let original = issuer.snapshot()?;
    let targets = EchoTargets::start().await?;
    let mut relays = (0..RELAYS)
        .map(|id| Relay::prepare(directory.path(), id, &issuer))
        .collect::<Result<Vec<_>>>()?;
    for relay in &mut relays {
        relay
            .publish(&original, receipt, "initial_delivery")
            .await?;
        relay.start().await?;
    }
    let mut victims = Vec::new();
    let mut neighbors = Vec::new();
    for relay in &relays {
        victims.push(Some(open_pair(relay, &victim, &targets).await?));
        neighbors.push(Some(open_pair(relay, &neighbor, &targets).await?));
        receipt.event(json!({"phase":"baseline","operation":"tcp_udp_payload_verified","relay":relay.id,"devices":["victim","neighbor"]}));
    }

    issuer.revoke(&victim).await?;
    let revoked = issuer.snapshot()?;
    for index in 0..2 {
        let commit = relays[index]
            .publish(&revoked, receipt, "partial_revoke")
            .await?;
        close_pair(
            victims[index].take().unwrap(),
            commit,
            receipt,
            "partial_revoke",
        )
        .await?;
        deny_pair(&relays[index], &victim, &targets, receipt, "partial_revoke").await?;
    }
    ping_pair(victims[2].as_mut().unwrap()).await?;
    drop(open_pair(&relays[2], &victim, &targets).await?);
    receipt.event(json!({"phase":"partial_revoke","pool_status":"PARTIAL","updated_relays":[0,1],"still_authorized_relay":2}));
    let commit = relays[2]
        .publish(&revoked, receipt, "revoke_converged")
        .await?;
    close_pair(
        victims[2].take().unwrap(),
        commit,
        receipt,
        "revoke_converged",
    )
    .await?;
    deny_pair(&relays[2], &victim, &targets, receipt, "revoke_converged").await?;
    for flows in &mut neighbors {
        ping_pair(flows.as_mut().unwrap()).await?;
    }
    receipt.event(json!({"phase":"revoke_converged","pool_status":"all_three_confirmed","neighbor_existing_tcp_udp":"live_on_all_three"}));

    let mut old = Vec::new();
    for relay in &relays {
        old.push(Some(open_pair(relay, &rotator, &targets).await?));
    }
    let replacement = issuer.issue(&devices, "rotator", true).await?;
    let current = issuer.snapshot()?;
    let mut replacements = Vec::new();
    for index in 0..RELAYS {
        let commit = relays[index].publish(&current, receipt, "rotation").await?;
        close_pair(old[index].take().unwrap(), commit, receipt, "rotation").await?;
        deny_pair(&relays[index], &rotator, &targets, receipt, "rotation").await?;
        replacements.push(Some(
            open_pair(&relays[index], &replacement, &targets).await?,
        ));
        ping_pair(neighbors[index].as_mut().unwrap()).await?;
        receipt.event(json!({"phase":"rotation","relay":index,"new_identity_tcp_udp":"verified","neighbor_existing_tcp_udp":"live"}));
    }

    let outage = Instant::now();
    fs::rename(
        relays[2].directory.join("registry.json"),
        relays[2].directory.join("registry.unavailable"),
    )?;
    File::open(&relays[2].directory)?.sync_all()?;
    close_pair(
        neighbors[2].take().unwrap(),
        outage,
        receipt,
        "registry_outage",
    )
    .await?;
    close_pair(
        replacements[2].take().unwrap(),
        outage,
        receipt,
        "registry_outage",
    )
    .await?;
    deny_pair(&relays[2], &neighbor, &targets, receipt, "registry_outage").await?;
    for index in 0..2 {
        ping_pair(neighbors[index].as_mut().unwrap()).await?;
        ping_pair(replacements[index].as_mut().unwrap()).await?;
    }
    receipt.event(
        json!({"phase":"registry_outage","unaffected_relays":[0,1],"existing_tcp_udp":"live"}),
    );
    relays[2]
        .publish(&current, receipt, "registry_recovery")
        .await?;
    neighbors[2] = Some(recover_pair(&relays[2], &neighbor, &targets).await?);
    replacements[2] = Some(open_pair(&relays[2], &replacement, &targets).await?);
    receipt.event(
        json!({"phase":"registry_recovery","relay":2,"neighbor_and_rotated_tcp_udp":"verified"}),
    );

    // Restart with current state preserves the intended authorization outcome.
    relays[1].stop().await?;
    drop(neighbors[1].take());
    drop(replacements[1].take());
    relays[1].start().await?;
    deny_pair(&relays[1], &victim, &targets, receipt, "restart_current").await?;
    deny_pair(&relays[1], &rotator, &targets, receipt, "restart_current").await?;
    neighbors[1] = Some(open_pair(&relays[1], &neighbor, &targets).await?);
    replacements[1] = Some(open_pair(&relays[1], &replacement, &targets).await?);
    receipt.event(json!({"phase":"restart_current","relay":1,"authorized_tcp_udp":"verified","removed_identities":"denied"}));

    // The production distributor rejects older input before mutation.
    relays[1].reject_old_publish(&original, receipt).await?;
    ping_pair(neighbors[1].as_mut().unwrap()).await?;
    // A snapshot-only rollback outside that distributor is detected by the
    // running watcher and again after a new server process starts.
    let rollback = relays[1].inject_registry_only_rollback(&original)?;
    close_pair(
        neighbors[1].take().unwrap(),
        rollback,
        receipt,
        "live_snapshot_rollback",
    )
    .await?;
    close_pair(
        replacements[1].take().unwrap(),
        rollback,
        receipt,
        "live_snapshot_rollback",
    )
    .await?;
    deny_pair(
        &relays[1],
        &victim,
        &targets,
        receipt,
        "live_snapshot_rollback",
    )
    .await?;
    for index in [0, 2] {
        ping_pair(neighbors[index].as_mut().unwrap()).await?;
    }
    relays[1].stop().await?;
    relays[1].start_rejected().await?;
    receipt.event(
        json!({"phase":"restart_older_snapshot","relay":1,"startup":"rejected_before_listener",
        "protected_floor":"preserved","combined_floor_and_registry_rollback":"outside_guarantee"}),
    );
    relays[1]
        .publish(&current, receipt, "restore_current_after_rollback")
        .await?;
    relays[1].start().await?;
    deny_pair(
        &relays[1],
        &victim,
        &targets,
        receipt,
        "restore_current_after_rollback",
    )
    .await?;
    neighbors[1] = Some(open_pair(&relays[1], &neighbor, &targets).await?);
    replacements[1] = Some(open_pair(&relays[1], &replacement, &targets).await?);
    for index in 0..RELAYS {
        ping_pair(neighbors[index].as_mut().unwrap()).await?;
        ping_pair(replacements[index].as_mut().unwrap()).await?;
        receipt.event(json!({"phase":"before_policy_partition","relay":index,"neighbor_and_rotated_tcp_udp":"verified"}));
    }

    // Policy is renewed only by the actual operator command. Give all three a
    // short policy, then simulate loss of control-plane delivery to relay 2.
    // Its registry remains readable and internally consistent throughout.
    let policy_started = Instant::now();
    let short = issuer.refresh(5).await?;
    let short_registry: DeviceRegistry = serde_json::from_slice(&short)?;
    let short_validity = short_registry.validity.context("v2 short policy missing")?;
    ensure!(
        short_validity.expires_at_unix_secs - short_validity.issued_at_unix_secs == 5,
        "operator did not issue the requested short policy"
    );
    for relay in &relays {
        relay
            .publish(&short, receipt, "short_policy_delivery")
            .await?;
    }
    let refreshed = issuer.refresh(60).await?;
    let refreshed_registry: DeviceRegistry = serde_json::from_slice(&refreshed)?;
    ensure!(
        refreshed_registry.generation > short_registry.generation,
        "explicit policy refresh did not advance generation"
    );
    for index in 0..2 {
        relays[index]
            .publish(&refreshed, receipt, "partition_refresh_connected_relays")
            .await?;
        ping_pair(neighbors[index].as_mut().unwrap()).await?;
        ping_pair(replacements[index].as_mut().unwrap()).await?;
    }
    tokio::time::sleep_until(tokio::time::Instant::from_std(
        policy_started + Duration::from_secs(2),
    ))
    .await;
    ping_pair(neighbors[2].as_mut().unwrap()).await?;
    ping_pair(replacements[2].as_mut().unwrap()).await?;
    // Replaying this exact policy late in its lifetime must not start another
    // five-second lease. The absolute wait below still uses its original start.
    relays[2]
        .publish(&short, receipt, "partition_replay_same_policy")
        .await?;
    let mut partitioned = neighbors[2].take().unwrap();
    partitioned.extend(replacements[2].take().unwrap());
    tokio::time::timeout_at(
        tokio::time::Instant::from_std(policy_started + Duration::from_secs(6)),
        close_pair(
            partitioned,
            policy_started,
            receipt,
            "policy_partition_expiry",
        ),
    )
    .await
    .context("policy expiry exceeded the original policy observation bound")??;
    let still_readable = DeviceRegistry::load(&relays[2].directory.join("registry.json"))?;
    ensure!(
        still_readable.generation == short_registry.generation
            && still_readable.validity == Some(short_validity),
        "partitioned relay no longer holds the original readable policy"
    );
    deny_pair(
        &relays[2],
        &neighbor,
        &targets,
        receipt,
        "policy_partition_expiry",
    )
    .await?;
    deny_pair(
        &relays[2],
        &replacement,
        &targets,
        receipt,
        "policy_partition_expiry",
    )
    .await?;
    for index in 0..2 {
        ping_pair(neighbors[index].as_mut().unwrap()).await?;
        ping_pair(replacements[index].as_mut().unwrap()).await?;
    }
    receipt.event(json!({"phase":"policy_partition_expiry","relay":2,
        "readable_registry_and_floor":"verified","policy":short_validity,
        "same_snapshot_replay":"did_not_extend_original_observation_bound",
        "disconnected_relay":"denies_old_policy","connected_relays":[0,1],
        "existing_neighbor_and_rotated_tcp_udp":"live_on_connected_relays",
        "instantaneous_global_revocation":"not_claimed"}));
    relays[2]
        .publish(&refreshed, receipt, "partition_explicit_refresh_recovery")
        .await?;
    neighbors[2] = Some(recover_pair(&relays[2], &neighbor, &targets).await?);
    replacements[2] = Some(open_pair(&relays[2], &replacement, &targets).await?);
    deny_pair(
        &relays[2],
        &victim,
        &targets,
        receipt,
        "partition_explicit_refresh_recovery",
    )
    .await?;
    deny_pair(
        &relays[2],
        &rotator,
        &targets,
        receipt,
        "partition_explicit_refresh_recovery",
    )
    .await?;
    for index in 0..RELAYS {
        ping_pair(neighbors[index].as_mut().unwrap()).await?;
        ping_pair(replacements[index].as_mut().unwrap()).await?;
        receipt.event(json!({"phase":"final_current_state","relay":index,
            "generation":refreshed_registry.generation,"neighbor_and_rotated_tcp_udp":"verified"}));
    }
    drop(neighbors);
    drop(replacements);
    for relay in &mut relays {
        relay.stop().await?;
    }
    drop(targets);
    directory
        .close()
        .context("remove temporary synthetic PKI")?;
    receipt.event(
        json!({"phase":"cleanup","owned_server_processes_reaped":RELAYS,"temporary_pki":"removed"}),
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_process_device_pool_converges_with_revocation_rollback_and_policy_expiry() {
    let receipt = Receipt::new();
    match tokio::time::timeout(TEST_BOUND, pool_proof(&receipt)).await {
        Ok(Ok(())) => receipt.complete(),
        Ok(Err(error)) => {
            receipt.event(json!({"phase":"failure","reason":error.to_string()}));
            panic!("synthetic pool proof failed: {error:#}");
        }
        Err(_) => {
            receipt.event(json!({"phase":"failure","reason":"whole-proof wall-clock bound"}));
            panic!("synthetic pool proof exceeded whole-proof wall-clock bound");
        }
    }
}
