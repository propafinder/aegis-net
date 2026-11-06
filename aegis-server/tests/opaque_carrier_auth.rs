//! Actual device/target acceptance for an opaque byte carrier and native web
//! carrier binaries. All keys, targets and processes are local synthetic fixtures.
//! These tests do not establish DPI resistance, fleet or release acceptance.
#![cfg(unix)]

use aegis_core::carrier_runtime::{shape_authenticated, PrivacySettings};
use aegis_core::secure_channel::{
    self, datagram, ClientSettings, OpenRequest, ServerSettings, Transport,
};
use aegis_server::config::{TargetPolicyConfig, TargetPolicyProfile};
use aegis_server::rate_limit::RateLimiter;
use anyhow::{ensure, Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::process::{Child, Command};
use tokio::time::timeout;

const DEADLINE: Duration = Duration::from_secs(12);
const SERVER_BIN: &str = env!("CARGO_BIN_EXE_aegis-server");

fn record_native_binary_identity(client: &Path) -> Result<()> {
    for (role, binary) in [("client", client), ("server", Path::new(SERVER_BIN))] {
        let mut file = fs::File::open(binary).context("open native fixture executable")?;
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 8192];
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            digest.update(&buffer[..n]);
        }
        eprintln!(
            "native fixture binary: role={role} sha256={}",
            hex::encode(digest.finalize())
        );
    }
    Ok(())
}

fn private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

struct Fixture {
    directory: tempfile::TempDir,
    server: ServerSettings,
    allowed: ClientSettings,
    refused: ClientSettings,
    outer_cert: PathBuf,
    outer_key: PathBuf,
    admission: PathBuf,
    wrong_admission: PathBuf,
    local_auth: PathBuf,
}

impl Fixture {
    fn new() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
        let ca = params.self_signed(&ca_key)?;
        let ca_path = directory.path().join("ca.pem");
        private(&ca_path, ca.pem().as_bytes())?;
        let mut identities = Vec::new();
        for (name, usage) in [
            ("inner.test", ExtendedKeyUsagePurpose::ServerAuth),
            ("allowed.test", ExtendedKeyUsagePurpose::ClientAuth),
            ("refused.test", ExtendedKeyUsagePurpose::ClientAuth),
        ] {
            let mut params = CertificateParams::new(vec![name.into()])?;
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![usage];
            let key = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
            let cert = params.signed_by(&key, &ca, &ca_key)?;
            let cert_path = directory.path().join(format!("{name}.pem"));
            let key_path = directory.path().join(format!("{name}.key"));
            private(&cert_path, cert.pem().as_bytes())?;
            private(&key_path, key.serialize_pem().as_bytes())?;
            identities.push((
                cert_path,
                key_path,
                hex::encode(Sha256::digest(cert.der().as_ref())),
            ));
        }
        let client = |index: usize| ClientSettings {
            server_name: "inner.test".into(),
            server_ca: ca_path.clone(),
            cert: identities[index].0.clone(),
            key: identities[index].1.clone(),
        };
        let outer = rcgen::generate_simple_self_signed(vec!["site.test".into()])?;
        let outer_cert = directory.path().join("outer.pem");
        let outer_key = directory.path().join("outer.key");
        private(&outer_cert, outer.cert.pem().as_bytes())?;
        private(&outer_key, outer.key_pair.serialize_pem().as_bytes())?;
        let admission = directory.path().join("admission.key");
        let wrong_admission = directory.path().join("wrong-admission.key");
        // Deliberately synthetic fixture values, never real admission material.
        private(&admission, &[b'a'; 64])?;
        private(&wrong_admission, &[b'b'; 64])?;
        let local_auth = directory.path().join("local-socks-auth.json");
        private(
            &local_auth,
            br#"{"version":1,"username":"aegis","password":"native-local-fixture-password"}"#,
        )?;
        Ok(Self {
            server: ServerSettings {
                cert: identities[0].0.clone(),
                key: identities[0].1.clone(),
                client_ca: ca_path.clone(),
                allowed_client_sha256: vec![identities[1].2.clone()],
                device_registry: None,
                admission: Default::default(),
                handshake_timeout_ms: 1500,
                idle_timeout_ms: 500,
            },
            allowed: client(1),
            refused: client(2),
            directory,
            outer_cert,
            outer_key,
            admission,
            wrong_admission,
            local_auth,
        })
    }
}

fn full_policy() -> TargetPolicyConfig {
    TargetPolicyConfig {
        profile: TargetPolicyProfile::FullVpnEgress,
        allowed_ports: Vec::new(),
    }
}
fn request(address: SocketAddr, transport: Transport) -> OpenRequest {
    OpenRequest {
        version: 1,
        host: address.ip().to_string(),
        port: address.port(),
        transport,
    }
}
fn privacy() -> PrivacySettings {
    PrivacySettings {
        payload_bytes: 1024,
        cadence_ms: 1,
        buffer_bytes: 8192,
        max_wire_bytes: 1_048_576,
        io_timeout_ms: 250,
        session_timeout_ms: 10_000,
        max_queue_delay_ms: 3000,
        poisson_pacing: None,
        net_shaper: None,
        adaptive_channel: None,
        arrival_envelope: None,
        cover_stream: None,
        bit_traps: None,
        liu_channel: None,
    }
}

#[tokio::test]
async fn opaque_carrier_actual_tcp_preserves_binary_bytes_and_half_close() -> Result<()> {
    timeout(DEADLINE, async {
        let fixture = Fixture::new()?;
        let target = TcpListener::bind("127.0.0.1:0").await?;
        let address = target.local_addr()?;
        let authenticated = Arc::new(AtomicUsize::new(0));
        let (mut io, serving) = generic_session(
            &fixture,
            full_policy(),
            &fixture.allowed,
            None,
            authenticated.clone(),
            false,
        )
        .await?;
        secure_channel::write_open(&mut io, &request(address, Transport::Tcp)).await?;
        ensure!(io.read_u8().await? == 0, "TCP target rejected");
        let (tcp, _) = target.accept().await?;
        let payload: Vec<u8> = (0..55_137).map(|i| (i % 239) as u8).collect();
        let remote = async {
            let (mut read, mut write) = tcp.into_split();
            tokio::io::copy(&mut read, &mut write).await?;
            write.shutdown().await
        };
        let application = async {
            // Concurrent read/write also proves that backpressure cannot force
            // either side to buffer the entire payload before making progress.
            let (mut read, mut write) = tokio::io::split(&mut io);
            let sending = async {
                write.write_all(&payload).await?;
                write.shutdown().await
            };
            let receiving = async {
                let mut echoed = Vec::new();
                read.read_to_end(&mut echoed).await?;
                ensure!(echoed == payload, "opaque TCP changed bytes or half-close");
                anyhow::Ok(())
            };
            let (sent, received) = tokio::join!(sending, receiving);
            sent?;
            received?;
            anyhow::Ok(())
        };
        let (remote, application) = tokio::join!(remote, application);
        remote?;
        application?;
        ensure!(serving.await?.is_ok(), "opaque TCP clean shutdown failed");
        ensure!(
            authenticated.load(Ordering::SeqCst) == 1,
            "authorization callback count changed"
        );
        Ok(())
    })
    .await
    .context("opaque TCP wall-clock bound")?
}

async fn generic_session(
    fixture: &Fixture,
    policy: TargetPolicyConfig,
    settings: &ClientSettings,
    privacy_settings: Option<PrivacySettings>,
    callback: Arc<AtomicUsize>,
    callback_refuses: bool,
) -> Result<(
    aegis_core::carrier_runtime::OwnedCarrier,
    tokio::task::JoinHandle<Result<()>>,
)> {
    let (carrier, peer) = tokio::io::duplex(8192);
    let inner = secure_channel::Server::load(&fixture.server)?;
    let server_privacy = privacy_settings.clone();
    let serving = tokio::spawn(async move {
        let _watcher = inner.start_registry_watcher();
        aegis_server::session::serve_device_carrier(
            peer,
            inner,
            &policy,
            &RateLimiter::new(5, 60, false),
            None,
            move || {
                callback.fetch_add(1, Ordering::SeqCst);
                if callback_refuses {
                    Err(std::io::Error::other("fixture lifetime cancelled"))
                } else {
                    Ok(())
                }
            },
            server_privacy.as_ref(),
        )
        .await
    });
    let tls = secure_channel::Client::load(settings)?
        .connect(carrier)
        .await?;
    let io = shape_authenticated(tls, privacy_settings.as_ref())?;
    Ok((io, serving))
}

#[tokio::test]
async fn opaque_carrier_same_ca_wrong_device_cannot_authenticate_or_touch_target() -> Result<()> {
    timeout(DEADLINE, async {
        let fixture = Fixture::new()?;
        let target = TcpListener::bind("127.0.0.1:0").await?;
        let address = target.local_addr()?;
        let callback = Arc::new(AtomicUsize::new(0));
        let (carrier, peer) = tokio::io::duplex(8192);
        let server = secure_channel::Server::load(&fixture.server)?;
        let observed = callback.clone();
        let serving = tokio::spawn(async move {
            aegis_server::session::serve_device_carrier(
                peer,
                server,
                &full_policy(),
                &RateLimiter::new(5, 60, false),
                None,
                move || {
                    observed.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
                None,
            )
            .await
        });
        let result = async {
            let mut io = secure_channel::Client::load(&fixture.refused)?
                .connect(carrier)
                .await?;
            secure_channel::write_open(&mut io, &request(address, Transport::Tcp)).await?;
            Ok::<u8, anyhow::Error>(io.read_u8().await?)
        }
        .await;
        ensure!(
            result.is_err(),
            "wrong device received a target acknowledgement"
        );
        ensure!(
            serving.await?.is_err(),
            "wrong device session reported as authorized"
        );
        ensure!(
            callback.load(Ordering::SeqCst) == 0,
            "unauthorized device extended lifetime"
        );
        ensure!(
            timeout(Duration::from_millis(50), target.accept())
                .await
                .is_err(),
            "target contacted before device authorization"
        );
        Ok(())
    })
    .await
    .context("wrong-device wall-clock bound")?
}

#[tokio::test]
async fn opaque_carrier_default_policy_denies_private_target_after_device_auth() -> Result<()> {
    timeout(DEADLINE, async {
        let fixture = Fixture::new()?;
        let target = TcpListener::bind("127.0.0.1:0").await?;
        let callback = Arc::new(AtomicUsize::new(0));
        let (mut io, serving) = generic_session(
            &fixture,
            TargetPolicyConfig::default(),
            &fixture.allowed,
            None,
            callback.clone(),
            false,
        )
        .await?;
        secure_channel::write_open(&mut io, &request(target.local_addr()?, Transport::Tcp)).await?;
        ensure!(
            io.read_u8().await? == 1,
            "private destination bypassed default egress policy"
        );
        ensure!(
            serving.await?.is_err(),
            "denied target reported as successful"
        );
        ensure!(
            callback.load(Ordering::SeqCst) == 1,
            "authorized device callback missing"
        );
        ensure!(
            timeout(Duration::from_millis(50), target.accept())
                .await
                .is_err(),
            "denied destination contacted"
        );
        Ok(())
    })
    .await
    .context("SSRF policy wall-clock bound")?
}

#[tokio::test]
async fn opaque_carrier_lifetime_refusal_prevents_target_open() -> Result<()> {
    timeout(DEADLINE, async {
        let fixture = Fixture::new()?;
        let target = TcpListener::bind("127.0.0.1:0").await?;
        let callback = Arc::new(AtomicUsize::new(0));
        let (mut io, serving) = generic_session(
            &fixture,
            full_policy(),
            &fixture.allowed,
            None,
            callback.clone(),
            true,
        )
        .await?;
        let result = async {
            secure_channel::write_open(&mut io, &request(target.local_addr()?, Transport::Tcp))
                .await?;
            io.read_u8().await
        }
        .await;
        ensure!(result.is_err(), "cancelled carrier opened a target");
        ensure!(
            serving.await?.is_err(),
            "cancelled lifetime reported successful"
        );
        ensure!(
            callback.load(Ordering::SeqCst) == 1,
            "callback count incorrect"
        );
        ensure!(
            timeout(Duration::from_millis(50), target.accept())
                .await
                .is_err(),
            "cancelled carrier contacted target"
        );
        Ok(())
    })
    .await
    .context("lifetime-refusal wall-clock bound")?
}

#[tokio::test]
async fn opaque_carrier_authenticated_idle_connection_closes_within_bound() -> Result<()> {
    timeout(DEADLINE, async {
        let fixture = Fixture::new()?;
        let target = TcpListener::bind("127.0.0.1:0").await?;
        let callback = Arc::new(AtomicUsize::new(0));
        let (mut io, serving) = generic_session(
            &fixture,
            full_policy(),
            &fixture.allowed,
            None,
            callback.clone(),
            false,
        )
        .await?;
        secure_channel::write_open(&mut io, &request(target.local_addr()?, Transport::Tcp)).await?;
        ensure!(io.read_u8().await? == 0, "idle fixture target rejected");
        let (mut tcp, _) = target.accept().await?;
        ensure!(
            timeout(Duration::from_secs(2), serving)
                .await
                .context("idle session closure bound")??
                .is_err(),
            "idle session did not fail closed"
        );
        ensure!(
            tcp.read_u8().await.is_err(),
            "idle session left target socket open"
        );
        ensure!(
            callback.load(Ordering::SeqCst) == 1,
            "idle session authorized more than once"
        );
        Ok(())
    })
    .await
    .context("idle session wall-clock bound")?
}

#[tokio::test]
async fn opaque_carrier_registry_revocation_closes_live_target() -> Result<()> {
    timeout(DEADLINE, async {
        use secure_channel::registry::{self, DeviceRecord, DeviceRegistry};
        let mut fixture = Fixture::new()?;
        let now = registry::unix_now()?;
        let path = fixture.directory.path().join("registry.json");
        let mut registry = DeviceRegistry::new(now, 60)?;
        registry.devices.push(DeviceRecord {
            device_id: "synthetic-carrier-device".into(),
            certificate_sha256: fixture.server.allowed_client_sha256[0].clone(),
            not_after_unix_secs: now + 120,
            revoked: false,
        });
        registry::publish_snapshot(&path, &registry)?;
        fixture.server.allowed_client_sha256.clear();
        fixture.server.device_registry = Some(path.clone());
        fixture.server.idle_timeout_ms = 10_000;
        let target = TcpListener::bind("127.0.0.1:0").await?;
        let callback = Arc::new(AtomicUsize::new(0));
        let (mut io, serving) = generic_session(
            &fixture,
            full_policy(),
            &fixture.allowed,
            None,
            callback.clone(),
            false,
        )
        .await?;
        secure_channel::write_open(&mut io, &request(target.local_addr()?, Transport::Tcp)).await?;
        ensure!(io.read_u8().await? == 0, "registry device not admitted");
        let (mut tcp, _) = target.accept().await?;
        io.write_all(b"before revoke").await?;
        io.flush().await?;
        let mut marker = [0; 13];
        tcp.read_exact(&mut marker).await?;
        ensure!(
            &marker == b"before revoke",
            "registry session did not forward before revoke"
        );
        registry.generation += 1;
        registry.devices[0].revoked = true;
        registry::publish_snapshot(&path, &registry)?;
        ensure!(
            timeout(Duration::from_secs(4), serving)
                .await
                .context("live revoke closure bound")??
                .is_err(),
            "revoked carrier remained admitted"
        );
        ensure!(
            tcp.read_u8().await.is_err(),
            "revocation left target forwarding open"
        );
        ensure!(
            callback.load(Ordering::SeqCst) == 1,
            "revocation replayed authentication"
        );
        Ok(())
    })
    .await
    .context("registry revocation wall-clock bound")?
}

#[tokio::test]
async fn opaque_carrier_udp_preserves_empty_and_large_datagrams_then_closes() -> Result<()> {
    timeout(DEADLINE, async {
        let fixture = Fixture::new()?;
        let target = UdpSocket::bind("127.0.0.1:0").await?;
        let address = target.local_addr()?;
        let callback = Arc::new(AtomicUsize::new(0));
        let (mut io, serving) = generic_session(
            &fixture,
            full_policy(),
            &fixture.allowed,
            Some(privacy()),
            callback.clone(),
            false,
        )
        .await?;
        secure_channel::write_open(&mut io, &request(address, Transport::Udp)).await?;
        ensure!(io.read_u8().await? == 0, "UDP target rejected");
        // macOS's default UDP maxdgram rejects 60,000 bytes with EMSGSIZE even
        // on a direct socket; do not mistake that for carrier corruption.
        // Linux still exercises a 60,000-byte datagram over the actual relay.
        let large_datagram_bytes = if cfg!(target_os = "macos") {
            8192
        } else {
            60_000
        };
        let payloads = [
            Vec::new(),
            b"small datagram\0\xff".to_vec(),
            (0..large_datagram_bytes).map(|i| (i % 239) as u8).collect(),
        ];
        for payload in payloads {
            eprintln!(
                "opaque UDP fixture starting datagram length={}",
                payload.len()
            );
            let exchanging = async {
                datagram::write(&mut io, &payload).await?;
                eprintln!(
                    "opaque UDP fixture application write completed length={}",
                    payload.len()
                );
                let mut buffer = vec![0; 65_507];
                let (count, source) = target.recv_from(&mut buffer).await?;
                eprintln!("opaque UDP fixture target received length={count}");
                ensure!(
                    buffer[..count] == payload,
                    "UDP target boundary or bytes changed"
                );
                target.send_to(&buffer[..count], source).await?;
                eprintln!("opaque UDP fixture target reply sent length={count}");
                ensure!(
                    datagram::read(&mut io).await? == Some(payload),
                    "UDP reply boundary or bytes changed"
                );
                anyhow::Ok(())
            };
            timeout(Duration::from_secs(3), exchanging)
                .await
                .context("UDP individual bound")??;
        }
        io.shutdown().await?;
        ensure!(serving.await?.is_ok(), "UDP clean EOF failed");
        ensure!(
            callback.load(Ordering::SeqCst) == 1,
            "UDP auth callback count incorrect"
        );
        Ok(())
    })
    .await
    .context("UDP wall-clock bound")?
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn opaque_carrier_udp_platform_oversize_fails_closed_without_target_delivery() -> Result<()> {
    timeout(DEADLINE, async {
        // Establish the host condition using an independent direct socket.
        // If an operator increased maxdgram, this host no longer needs the
        // conditional EMSGSIZE regression; the positive test remains separate.
        let target = UdpSocket::bind("127.0.0.1:0").await?;
        let direct = UdpSocket::bind("127.0.0.1:0").await?;
        let bytes = vec![0x71; 60_000];
        match direct.send_to(&bytes, target.local_addr()?).await {
            Ok(count) => {
                ensure!(count == bytes.len(), "direct UDP baseline was a short send");
                let mut buffer = vec![0; 65_507];
                target.recv(&mut buffer).await?;
                eprintln!("host supports 60000-byte direct UDP; conditional EMSGSIZE regression inapplicable");
                return Ok(());
            }
            Err(error) => ensure!(error.raw_os_error() == Some(libc::EMSGSIZE), "unexpected direct UDP host error"),
        }
        let fixture = Fixture::new()?;
        let callback = Arc::new(AtomicUsize::new(0));
        let (mut io, serving) = generic_session(
            &fixture,
            full_policy(),
            &fixture.allowed,
            Some(privacy()),
            callback.clone(),
            false,
        )
        .await?;
        secure_channel::write_open(&mut io, &request(target.local_addr()?, Transport::Udp)).await?;
        ensure!(
            io.read_u8().await? == 0,
            "UDP oversize fixture target rejected early"
        );
        datagram::write(&mut io, &bytes).await?;
        let outcome = timeout(Duration::from_secs(3), serving)
            .await
            .context("platform UDP refusal bound")??;
        let error = outcome.expect_err("platform oversized UDP silently succeeded");
        ensure!(
            error
                .downcast_ref::<std::io::Error>()
                .and_then(|e| e.raw_os_error())
                == Some(libc::EMSGSIZE),
            "carrier did not preserve the platform UDP refusal"
        );
        ensure!(
            io.read_u8().await.is_err(),
            "refused datagram left carrier alive"
        );
        let mut buffer = vec![0; 65_507];
        ensure!(
            timeout(Duration::from_millis(50), target.recv(&mut buffer))
                .await
                .is_err(),
            "platform-refused UDP reached target"
        );
        ensure!(
            callback.load(Ordering::SeqCst) == 1,
            "UDP refusal replayed authentication"
        );
        Ok(())
    })
    .await
    .context("platform UDP refusal overall bound")?
}

fn unused_address() -> Result<SocketAddr> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?)
}

struct NativeChild {
    child: Child,
    stderr: PathBuf,
}
#[cfg(feature = "webrtc-carrier")]
fn diagnostic(process: &NativeChild) -> String {
    let mut bytes = Vec::new();
    let result = std::fs::File::open(&process.stderr)
        .and_then(|file| file.take(4096).read_to_end(&mut bytes));
    match result {
        Ok(_) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(error) => format!("synthetic child diagnostic unavailable: {error}"),
    }
}
fn spawn(binary: &Path, config: &Path) -> Result<NativeChild> {
    spawn_command(binary, "carrier", config)
}
fn spawn_command(binary: &Path, command: &str, config: &Path) -> Result<NativeChild> {
    let stderr = config.with_extension("stderr");
    let diagnostic = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&stderr)?;
    let child = Command::new(binary)
        .arg(command)
        .arg("--config")
        .arg(config)
        .env("AEGIS_NO_BANNER", "1")
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(diagnostic))
        .kill_on_drop(true)
        .spawn()?;
    Ok(NativeChild { child, stderr })
}
async fn listening(process: &mut NativeChild, address: SocketAddr) -> Result<()> {
    timeout(Duration::from_secs(5), async {
        loop {
            if let Some(status) = process.child.try_wait()? {
                // Only synthetic fixture material reaches this child. The
                // native config loader redacts parse data; do not dump configs.
                let mut diagnostic = Vec::new();
                std::fs::File::open(&process.stderr)?
                    .take(4096)
                    .read_to_end(&mut diagnostic)?;
                anyhow::bail!(
                    "fixture process exited before listening ({status}); synthetic diagnostic: {}",
                    String::from_utf8_lossy(&diagnostic)
                );
            }
            if TcpStream::connect(address).await.is_ok() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("native listener readiness bound")?
}
async fn stop(process: &mut NativeChild) -> Result<()> {
    stop_signal(process, libc::SIGINT).await
}
async fn stop_signal(process: &mut NativeChild, signal: libc::c_int) -> Result<()> {
    if let Some(id) = process.child.id() {
        // SAFETY: only the owned, unreaped fixture child's PID is signalled.
        ensure!(
            unsafe { libc::kill(id as libc::pid_t, signal) } == 0,
            "fixture shutdown signal failed"
        );
        let status = timeout(Duration::from_secs(5), process.child.wait())
            .await
            .context("native cancellation bound")??;
        ensure!(status.success(), "native fixture did not exit cleanly");
    }
    Ok(())
}

fn server_config(f: &Fixture, address: SocketAddr, profile: &str, shaped: bool) -> Result<PathBuf> {
    let relay = f.directory.path().join("relay.toml");
    private(
        &relay,
        format!(
            r#"listen = "{address}"
cert = "{}"
key = "{}"
fallback = "close"
[rate_limit]
enabled = false
[target_policy]
profile = "{profile}"
[transport]
quic_required = false
[transport.inner_tls]
cert = "{}"
key = "{}"
client_ca = "{}"
allowed_client_sha256 = ["{}"]
handshake_timeout_ms = 2000
idle_timeout_ms = 2000
"#,
            f.outer_cert.display(),
            f.outer_key.display(),
            f.server.cert.display(),
            f.server.key.display(),
            f.server.client_ca.display(),
            f.server.allowed_client_sha256[0]
        )
        .as_bytes(),
    )?;
    let config = f.directory.path().join("server-carrier.toml");
    let mut contents = format!(
        r#"relay_config = "{}"
max_sessions = 8
rotate_descriptor_ms = 240000
[web]
site_html = "<!doctype html><title>Synthetic site</title>"
[web.client]
authority = "site.test"
descriptor_path = "/private/descriptor"
credential_file = "{}"
"#,
        relay.display(),
        f.admission.display()
    );
    if shaped {
        contents.push_str(&format!("\n[privacy]\n{}", toml::to_string(&privacy())?));
    }
    private(&config, contents.as_bytes())?;
    Ok(config)
}

#[allow(clippy::too_many_arguments)]
fn client_config(
    f: &Fixture,
    index: usize,
    local: SocketAddr,
    bootstrap: SocketAddr,
    device: &ClientSettings,
    key: &Path,
    allowed_ip: &str,
    outer_ca: &Path,
    authority: &str,
    connect_timeout_ms: u64,
    shaped: bool,
) -> Result<PathBuf> {
    let path = f.directory.path().join(format!("client-{index}.toml"));
    let mut contents = format!(
        r#"listen = "{local}"
local_socks_auth_file = "{}"
bootstrap = "{bootstrap}"
allowed_ingress_ips = ["{allowed_ip}"]
outer_ca = "{}"
connect_timeout_ms = {connect_timeout_ms}
idle_timeout_ms = 2000
max_sessions = 4
[inner_tls]
{}[web]
authority = "{authority}"
descriptor_path = "/private/descriptor"
credential_file = "{}"
"#,
        f.local_auth.display(),
        outer_ca.display(),
        toml::to_string(device)?,
        key.display()
    );
    if shaped {
        contents.push_str(&format!("\n[privacy]\n{}", toml::to_string(&privacy())?));
    }
    private(&path, contents.as_bytes())?;
    Ok(path)
}

async fn socks(address: SocketAddr, target: SocketAddr) -> Result<(TcpStream, u8)> {
    let mut stream = TcpStream::connect(address).await?;
    stream.write_all(&[5, 1, 2]).await?;
    let mut handshake = [0; 2];
    stream.read_exact(&mut handshake).await?;
    ensure!(handshake == [5, 2], "SOCKS5 handshake changed");
    let user = b"aegis";
    let password = b"native-local-fixture-password";
    let mut auth = vec![1, user.len() as u8];
    auth.extend(user);
    auth.push(password.len() as u8);
    auth.extend(password);
    stream.write_all(&auth).await?;
    let mut auth_reply = [0; 2];
    stream.read_exact(&mut auth_reply).await?;
    ensure!(auth_reply == [1, 0], "local SOCKS authentication refused");
    let std::net::IpAddr::V4(ip) = target.ip() else {
        anyhow::bail!("fixture target must be IPv4");
    };
    let mut open = vec![5, 1, 0, 1];
    open.extend(ip.octets());
    open.extend(target.port().to_be_bytes());
    stream.write_all(&open).await?;
    let mut response = [0; 10];
    stream.read_exact(&mut response).await?;
    ensure!(
        response[0] == 5 && response[2] == 0 && response[3] == 1,
        "SOCKS5 reply framing changed"
    );
    Ok((stream, response[1]))
}

// A controlled blackhole establishes the timeout precondition independently of
// certificate-rejection timing. Keep the accepted socket alive without replying
// to TLS so the production client's actual setup deadline must expire.
async fn setup_timeout(client_bin: &Path, command: &str) -> Result<()> {
    let fixture = Fixture::new()?;
    let ingress = TcpListener::bind("127.0.0.1:0").await?;
    let target = TcpListener::bind("127.0.0.1:0").await?;
    let target_address = target.local_addr()?;
    let local = unused_address()?;
    let config = match command {
        "carrier" => client_config(
            &fixture,
            99,
            local,
            ingress.local_addr()?,
            &fixture.allowed,
            &fixture.admission,
            "127.0.0.1",
            &fixture.outer_cert,
            "site.test",
            700,
            false,
        )?,
        #[cfg(feature = "webrtc-carrier")]
        "webrtc" => webrtc_client_config(
            &fixture,
            99,
            local,
            ingress.local_addr()?,
            &fixture.allowed,
            &fixture.admission,
            "site.test",
            &fixture.outer_cert,
            700,
            false,
        )?,
        _ => anyhow::bail!("unsupported native setup fixture"),
    };
    let mut client = spawn_command(client_bin, command, &config)?;
    listening(&mut client, local).await?;
    let (reply, accepted) = timeout(Duration::from_secs(3), async {
        tokio::join!(socks(local, target_address), ingress.accept())
    })
    .await
    .context("native setup timeout did not send SOCKS response within wall-clock bound")?;
    let (local_stream, code) = reply?;
    ensure!(
        code == 1,
        "native setup timeout omitted general-failure reply"
    );
    let (mut held_peer, _) = accepted?;
    let mut observed = 0usize;
    timeout(Duration::from_secs(2), async {
        let mut buffer = [0; 8192];
        loop {
            let count = held_peer.read(&mut buffer).await?;
            if count == 0 {
                return anyhow::Ok(());
            }
            observed += count;
        }
    })
    .await
    .context("native setup timeout retained the blocked bootstrap connection")??;
    ensure!(
        observed > 0,
        "setup fixture did not observe a real TLS attempt"
    );
    ensure!(
        timeout(Duration::from_millis(50), target.accept())
            .await
            .is_err(),
        "native setup timeout touched target"
    );
    stop_signal(&mut client, libc::SIGTERM).await?;
    drop(local_stream);
    eprintln!(
        "native setup timeout validated: command={command} deadline_ms=700 target_touched=false"
    );
    Ok(())
}

// Rust integration tests know only their own package binary. This explicit test
// needs both packages built; the companion script supplies the exact client path.
// A missing path is an error, never a silent skip or an inferred native PASS.
#[tokio::test]
#[ignore = "run scripts/test-native-web-carrier-contract.sh to build and test both actual binaries"]
async fn native_web_carrier_socks5_device_and_egress_acceptance() -> Result<()> {
    let client_bin = std::env::var_os("AEGIS_NATIVE_CLIENT_BIN")
        .map(PathBuf::from)
        .context("AEGIS_NATIVE_CLIENT_BIN must name the explicitly built client")?;
    ensure!(
        client_bin.is_absolute() && client_bin.is_file(),
        "native client path invalid"
    );
    record_native_binary_identity(&client_bin)?;
    timeout(Duration::from_secs(75), async {
        for (profile, shaped) in [
            ("full_vpn_egress", false),
            ("full_vpn_egress", true),
            ("public_internet", false),
        ] {
            let fixture = Fixture::new()?;
            let ingress = unused_address()?;
            let cfg = server_config(&fixture, ingress, profile, shaped)?;
            let mut relay = spawn(Path::new(SERVER_BIN), &cfg)?;
            listening(&mut relay, ingress).await?;
            for (index, device, key, allowed_ip, outer_ca, authority, success) in [
                (
                    0,
                    &fixture.allowed,
                    &fixture.admission,
                    "127.0.0.1",
                    &fixture.outer_cert,
                    "site.test",
                    profile == "full_vpn_egress",
                ),
                (1, &fixture.refused, &fixture.admission, "127.0.0.1", &fixture.outer_cert, "site.test", false),
                (
                    2,
                    &fixture.allowed,
                    &fixture.wrong_admission,
                    "127.0.0.1",
                    &fixture.outer_cert,
                    "site.test",
                    false,
                ),
                (3, &fixture.allowed, &fixture.admission, "127.0.0.2", &fixture.outer_cert, "site.test", false),
                (4, &fixture.allowed, &fixture.admission, "127.0.0.1", &fixture.outer_cert, "wrong.test", false),
                (5, &fixture.allowed, &fixture.admission, "127.0.0.1", &fixture.server.client_ca, "site.test", false),
            ] {
                let target = TcpListener::bind("127.0.0.1:0").await?;
                let target_address = target.local_addr()?;
                let local = unused_address()?;
                let cfg = client_config(
                    &fixture, index, local, ingress, device, key, allowed_ip, outer_ca, authority, 3000, shaped,
                )?;
                let mut client = spawn(&client_bin, &cfg)?;
                listening(&mut client, local).await?;
                let (mut stream, code) =
                    timeout(Duration::from_secs(5), socks(local, target_address))
                        .await
                        .context("native SOCKS establishment bound")??;
                if success {
                    ensure!(code == 0, "admitted native SOCKS CONNECT rejected");
                    let payload: Vec<u8> = (0..55_137).map(|i| (i % 239) as u8).collect();
                    let exchanging = async {
                        let (tcp, _) = target.accept().await?;
                        let remote = async {
                            let (mut read, mut write) = tcp.into_split();
                            tokio::io::copy(&mut read, &mut write).await?;
                            write.shutdown().await
                        };
                        let application = async {
                            let (mut read, mut write) = tokio::io::split(&mut stream);
                            let sending = async {
                                write.write_all(&payload).await?;
                                write.shutdown().await
                            };
                            let receiving = async {
                                let mut echoed = Vec::new();
                                read.read_to_end(&mut echoed).await?;
                                ensure!(echoed == payload, "native carrier changed binary bytes or half-close");
                                anyhow::Ok(())
                            };
                            let (sent, received) = tokio::join!(sending, receiving);
                            sent?; received?;
                            anyhow::Ok(())
                        };
                        let (remote, application) = tokio::join!(remote, application);
                        remote?;
                        application?;
                        anyhow::Ok(())
                    };
                    timeout(Duration::from_secs(10), exchanging)
                        .await
                        .context("native full-duplex byte preservation bound")??;
                    // Cancel the actual client with an active established target.
                    let (mut active, code) = socks(local, target_address).await?;
                    ensure!(code == 0, "second native session failed");
                    let (mut target_stream, _) = target.accept().await?;
                    active.write_all(b"active before cancellation").await?;
                    let mut bytes = vec![0; 26];
                    target_stream.read_exact(&mut bytes).await?;
                    ensure!(
                        bytes == b"active before cancellation",
                        "second session delivery changed"
                    );
                    stop_signal(&mut client, if shaped {libc::SIGTERM} else {libc::SIGINT}).await?;
                    let closed = timeout(Duration::from_secs(3), target_stream.read_u8())
                        .await
                        .context("native target cancellation bound")?;
                    ensure!(
                        closed.is_err(),
                        "client cancellation left target forwarding alive"
                    );
                    drop(active);
                } else {
                    ensure!(code == 1, "inadmissible native session was accepted");
                    ensure!(
                        timeout(Duration::from_millis(50), target.accept())
                            .await
                            .is_err(),
                        "inadmissible native client touched target"
                    );
                    stop_signal(&mut client, if shaped {libc::SIGTERM} else {libc::SIGINT}).await?;
                }
                eprintln!("native acceptance validated: profile={profile} privacy={shaped} case={index} admitted={success}");
            }
            stop(&mut relay).await?;
        }
        setup_timeout(&client_bin, "carrier").await?;
        Ok(())
    })
    .await
    .context("native acceptance overall bound")?
}

#[cfg(feature = "webrtc-carrier")]
fn webrtc_server_config(f: &Fixture, signaling: SocketAddr, shaped: bool) -> Result<PathBuf> {
    // Reuse the exact same inner device/target policy fixture, including the
    // explicitly disabled legacy QUIC requirement; only the carrier differs.
    server_config(f, unused_address()?, "full_vpn_egress", false)?;
    let path = f.directory.path().join("server-webrtc.toml");
    let mut config = format!(
        r#"relay_config = "{}"
signaling_listen = "{signaling}"
client_key_file = "{}"
intermediary_key_file = "{}"
max_sessions = 2
[runtime]
bind = "127.0.0.1:0"
connect_timeout_ms = 12000
stall_timeout_ms = 3000
max_lifetime_ms = 30000
[runtime.ice]
mode = "loopback"
"#,
        f.directory.path().join("relay.toml").display(),
        f.admission.display(),
        f.wrong_admission.display()
    );
    if shaped {
        config.push_str(&format!("\n[privacy]\n{}", toml::to_string(&privacy())?));
    }
    private(&path, config.as_bytes())?;
    Ok(path)
}

#[cfg(feature = "webrtc-carrier")]
#[allow(clippy::too_many_arguments)]
fn webrtc_client_config(
    f: &Fixture,
    index: usize,
    local: SocketAddr,
    signaling: SocketAddr,
    device: &ClientSettings,
    key: &Path,
    signaling_name: &str,
    signaling_ca: &Path,
    connect_timeout_ms: u64,
    shaped: bool,
) -> Result<PathBuf> {
    let path = f
        .directory
        .path()
        .join(format!("client-webrtc-{index}.toml"));
    let mut config = format!(
        r#"listen = "{local}"
local_socks_auth_file = "{}"
signaling_addr = "{signaling}"
signaling_name = "{signaling_name}"
signaling_ca = "{}"
signaling_key_file = "{}"
idle_timeout_ms = 3000
max_sessions = 2
[inner_tls]
{}[runtime]
bind = "127.0.0.1:0"
connect_timeout_ms = {connect_timeout_ms}
stall_timeout_ms = 3000
max_lifetime_ms = 30000
[runtime.ice]
mode = "loopback"
"#,
        f.local_auth.display(),
        signaling_ca.display(),
        key.display(),
        toml::to_string(device)?
    );
    if shaped {
        config.push_str(&format!("\n[privacy]\n{}", toml::to_string(&privacy())?));
    }
    private(&path, config.as_bytes())?;
    Ok(path)
}

#[cfg(feature = "webrtc-carrier")]
#[tokio::test]
#[ignore = "run scripts/test-native-web-carrier-contract.sh webrtc to build both actual feature-enabled binaries"]
async fn native_webrtc_socks5_verified_broker_device_and_cancellation_acceptance() -> Result<()> {
    let client_bin = std::env::var_os("AEGIS_NATIVE_CLIENT_BIN")
        .map(PathBuf::from)
        .context("AEGIS_NATIVE_CLIENT_BIN must name the explicitly built feature-enabled client")?;
    ensure!(
        client_bin.is_absolute() && client_bin.is_file(),
        "native WebRTC client path invalid"
    );
    record_native_binary_identity(&client_bin)?;
    timeout(Duration::from_secs(115), async {
        for shaped in [false, true] {
            let fixture = Fixture::new()?;
            let signaling = unused_address()?;
            let config = webrtc_server_config(&fixture, signaling, shaped)?;
            let mut relay = spawn_command(Path::new(SERVER_BIN), "webrtc", &config)?;
            listening(&mut relay, signaling).await?;
            for (index, device, key, name, ca, admitted) in [
                (0, &fixture.allowed, &fixture.admission, "site.test", &fixture.outer_cert, true),
                (1, &fixture.refused, &fixture.admission, "site.test", &fixture.outer_cert, false),
                (2, &fixture.allowed, &fixture.wrong_admission, "site.test", &fixture.outer_cert, false),
                (3, &fixture.allowed, &fixture.admission, "wrong.test", &fixture.outer_cert, false),
                (4, &fixture.allowed, &fixture.admission, "site.test", &fixture.server.client_ca, false),
            ] {
                let target = TcpListener::bind("127.0.0.1:0").await?;
                let target_address = target.local_addr()?;
                let local = unused_address()?;
                let config = webrtc_client_config(&fixture, index, local, signaling, device, key, name, ca, 12000, shaped)?;
                let mut client = spawn_command(&client_bin, "webrtc", &config)?;
                listening(&mut client, local).await?;
                let result = timeout(Duration::from_secs(14), socks(local, target_address))
                    .await.with_context(|| format!("native WebRTC SOCKS establishment bound, privacy={shaped} case={index}"))?;
                let (mut stream, code) = result.with_context(|| format!(
                    "native WebRTC SOCKS establishment failed, privacy={shaped} case={index}; client synthetic diagnostic: {}; relay synthetic diagnostic: {}",
                    diagnostic(&client), diagnostic(&relay)))?;
                if admitted {
                    ensure!(code == 0, "authorized native WebRTC session rejected");
                    let (tcp, _) = target.accept().await?;
                    let payload: Vec<u8> = (0..31_137).map(|i| (i % 239) as u8).collect();
                    let remote = async {
                        let (mut read, mut write) = tcp.into_split();
                        tokio::io::copy(&mut read, &mut write).await?;
                        write.shutdown().await
                    };
                    let application = async {
                        let (mut read, mut write) = tokio::io::split(&mut stream);
                        let sending = async {write.write_all(&payload).await?;write.shutdown().await};
                        let receiving = async {
                            let mut echoed = Vec::new();read.read_to_end(&mut echoed).await?;
                            ensure!(echoed == payload, "native WebRTC changed TCP bytes or half-close");
                            anyhow::Ok(())
                        };
                        let (sent, received) = tokio::join!(sending, receiving);sent?;received?;
                        anyhow::Ok(())
                    };
                    timeout(Duration::from_secs(10), async {
                        let (remote, application) = tokio::join!(remote, application);remote?;application?;
                        anyhow::Ok(())
                    }).await.context("native WebRTC binary echo bound")??;
                    let (mut active, code) = timeout(Duration::from_secs(14), socks(local, target_address))
                        .await.context("native WebRTC second session bound")??;
                    ensure!(code == 0, "second authorized WebRTC session rejected");
                    let (mut remote, _) = target.accept().await?;
                    active.write_all(b"before WebRTC cancellation").await?;
                    let mut marker = [0;26];remote.read_exact(&mut marker).await?;
                    ensure!(&marker == b"before WebRTC cancellation", "WebRTC active session did not deliver marker");
                    stop_signal(&mut client, if shaped {libc::SIGTERM} else {libc::SIGINT}).await?;
                    ensure!(timeout(Duration::from_secs(5), remote.read_u8()).await.context("WebRTC live target cancellation bound")?.is_err(), "WebRTC cancellation left target forwarding alive");
                    drop(active);
                } else {
                    ensure!(code == 1, "inadmissible WebRTC native session accepted");
                    ensure!(timeout(Duration::from_millis(50), target.accept()).await.is_err(), "inadmissible WebRTC native client touched target");
                    stop(&mut client).await?;
                }
                eprintln!("native WebRTC acceptance validated: privacy={shaped} case={index} admitted={admitted}");
            }
            stop(&mut relay).await?;
        }
        setup_timeout(&client_bin, "webrtc").await?;
        Ok(())
    }).await.context("native WebRTC overall bound")?
}
