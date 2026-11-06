use super::*;
use aegis_core::h2_stream::H2Stream;
use aegis_core::secure_channel::{
    self, grpc_io::GrpcIo, Client, ClientSettings, Server, ServerSettings,
};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
use std::future::Future;
use std::path::Path;

pub(super) struct Fixture {
    pub(super) _dir: std::sync::Arc<tempfile::TempDir>,
    pub(super) client: Client,
    pub(super) server: Server,
    pub(super) server_settings: ServerSettings,
}

fn write_key(path: &Path, key: &KeyPair) {
    std::fs::write(path, key.serialize_pem()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn fixture_registry_paths(path: &Path) -> [std::path::PathBuf; 3] {
    let mut lock = path.as_os_str().to_os_string();
    lock.push(".lock");
    [
        path.to_owned(),
        secure_channel::registry::floor_path(path),
        lock.into(),
    ]
}

/// Install a fresh reader fixture, not a server publication transaction.
/// Windows retains its production Unsupported result for registry mutations.
fn publish_fresh_reader_fixture(
    path: &Path,
    snapshot: &secure_channel::registry::DeviceRegistry,
) -> std::io::Result<()> {
    use secure_channel::registry;
    let expected = registry::registry_digest(snapshot)?;
    let paths = fixture_registry_paths(path);
    // Refuse every preexisting entry before creating any fixture files.
    for entry in &paths {
        match std::fs::symlink_metadata(entry) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "registry reader fixture requires fresh entries",
                ));
            }
        }
    }
    #[cfg(windows)]
    {
        let snapshot_bytes = serde_json::to_vec(snapshot).map_err(std::io::Error::other)?;
        let floor_bytes = serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "generation": snapshot.generation,
            "snapshot_sha256": hex::encode(expected),
        }))
        .map_err(std::io::Error::other)?;
        // The existing writer installs an owner ACL before bytes, refuses
        // existing entries/reparse points, and flushes each owned file.
        aegis_core::windows_file::write_private_new(&paths[1], &floor_bytes, false)?;
        aegis_core::windows_file::write_private_new(&paths[0], &snapshot_bytes, false)?;
        aegis_core::windows_file::write_private_new(&paths[2], &[], false)?;
    }
    #[cfg(not(windows))]
    registry::publish_snapshot(path, snapshot)?;
    let loaded = registry::DeviceRegistry::load(path)?;
    if registry::registry_digest(&loaded)? != expected {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "registry reader fixture digest mismatch",
        ));
    }
    Ok(())
}

#[test]
fn fresh_registry_fixture_uses_actual_loader_and_private_files() {
    use secure_channel::registry;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("registry.json");
    let snapshot = registry::DeviceRegistry::new(registry::unix_now().unwrap(), 900).unwrap();
    publish_fresh_reader_fixture(&path, &snapshot).unwrap();
    let loaded = registry::DeviceRegistry::load(&path).unwrap();
    assert_eq!(loaded.generation, snapshot.generation);
    assert_eq!(
        registry::registry_digest(&loaded).unwrap(),
        registry::registry_digest(&snapshot).unwrap()
    );
    for entry in fixture_registry_paths(&path) {
        let metadata = std::fs::symlink_metadata(&entry).unwrap();
        assert!(metadata.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(metadata.mode() & 0o777, 0o600);
            assert_eq!(metadata.nlink(), 1);
        }
        #[cfg(windows)]
        aegis_core::windows_file::validate_private(&std::fs::File::open(entry).unwrap(), false)
            .unwrap();
    }
    assert!(std::fs::read(&fixture_registry_paths(&path)[2])
        .unwrap()
        .is_empty());
}

#[test]
fn fresh_registry_fixture_refuses_existing_entries_without_touching_sentinels() {
    use secure_channel::registry;
    let snapshot = registry::DeviceRegistry::new(registry::unix_now().unwrap(), 900).unwrap();
    for existing in 0..3 {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.json");
        let paths = fixture_registry_paths(&path);
        let sentinel = dir.path().join("unrelated-sentinel");
        aegis_core::secret_file::write_private_new(&paths[existing], b"existing entry").unwrap();
        aegis_core::secret_file::write_private_new(&sentinel, b"unrelated sentinel").unwrap();
        let original_modified = [
            std::fs::metadata(&paths[existing])
                .unwrap()
                .modified()
                .unwrap(),
            std::fs::metadata(&sentinel).unwrap().modified().unwrap(),
        ];
        assert_eq!(
            publish_fresh_reader_fixture(&path, &snapshot)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(&paths[existing]).unwrap(), b"existing entry");
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"unrelated sentinel");
        for (entry, modified) in [&paths[existing], &sentinel]
            .into_iter()
            .zip(original_modified)
        {
            let metadata = std::fs::symlink_metadata(entry).unwrap();
            assert_eq!(metadata.modified().unwrap(), modified);
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                assert_eq!(metadata.mode() & 0o777, 0o600);
                assert_eq!(metadata.nlink(), 1);
            }
            #[cfg(windows)]
            aegis_core::windows_file::validate_private(&std::fs::File::open(entry).unwrap(), false)
                .unwrap();
        }
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
        for (index, entry) in paths.iter().enumerate() {
            if index != existing {
                assert!(!entry.exists());
            }
        }
    }
}

#[test]
fn corrupted_fixture_floor_is_refused_by_actual_registry_loader() {
    use secure_channel::registry;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("registry.json");
    let snapshot = registry::DeviceRegistry::new(registry::unix_now().unwrap(), 900).unwrap();
    publish_fresh_reader_fixture(&path, &snapshot).unwrap();
    let original_snapshot = std::fs::read(&path).unwrap();
    let paths = fixture_registry_paths(&path);
    let mut wrong_digest = registry::registry_digest(&snapshot).unwrap();
    wrong_digest[0] ^= 1;
    // Deliberately corrupt only our private fixture floor; retain its ACL/mode.
    std::fs::write(
        &paths[1],
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "generation": snapshot.generation,
            "snapshot_sha256": hex::encode(wrong_digest),
        }))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        registry::DeviceRegistry::load(&path).unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
    assert_eq!(std::fs::read(path).unwrap(), original_snapshot);
    assert!(std::fs::read(&paths[2]).unwrap().is_empty());
}

#[cfg(windows)]
#[test]
fn production_registry_publisher_remains_unsupported_without_creating_entries() {
    use secure_channel::registry;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("registry.json");
    let snapshot = registry::DeviceRegistry::new(registry::unix_now().unwrap(), 900).unwrap();
    assert_eq!(
        registry::publish_snapshot(&path, &snapshot)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::Unsupported
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

pub(super) fn fixture(allowed: bool) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let mut ca_params = CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, ca.pem()).unwrap();
    write_key(&dir.path().join("ca.key"), &ca_key);
    let mut identities = Vec::new();
    for (name, usage) in [
        ("inner.test", ExtendedKeyUsagePurpose::ServerAuth),
        ("device.test", ExtendedKeyUsagePurpose::ClientAuth),
    ] {
        let mut params = CertificateParams::new(vec![name.into()]).unwrap();
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![usage];
        let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let cert = params.signed_by(&key, &ca, &ca_key).unwrap();
        let cert_path = dir.path().join(format!("{name}.pem"));
        let key_path = dir.path().join(format!("{name}.key"));
        std::fs::write(&cert_path, cert.pem()).unwrap();
        write_key(&key_path, &key);
        identities.push((
            cert_path,
            key_path,
            hex::encode(Sha256::digest(cert.der().as_ref())),
        ));
    }
    let client = Client::load(&ClientSettings {
        server_name: "inner.test".into(),
        server_ca: ca_path.clone(),
        cert: identities[1].0.clone(),
        key: identities[1].1.clone(),
    })
    .unwrap();
    let server_settings = ServerSettings {
        device_registry: None,
        cert: identities[0].0.clone(),
        key: identities[0].1.clone(),
        client_ca: ca_path,
        allowed_client_sha256: vec![if allowed {
            identities[1].2.clone()
        } else {
            "00".repeat(32)
        }],
        admission: Default::default(),
        handshake_timeout_ms: 1000,
        idle_timeout_ms: 1000,
    };
    let server = Server::load(&server_settings).unwrap();
    Fixture {
        _dir: std::sync::Arc::new(dir),
        client,
        server,
        server_settings,
    }
}

pub(super) fn context(f: &Fixture, limiter: &RateLimiter, peer: &str) -> GrpcRequestContext {
    GrpcRequestContext {
        witness: None,
        bridge_activity: None,
        transport: TransportConfig::default(),
        target_policy: TargetPolicyConfig::default(),
        auth_keyring: TunnelAuthKeyring {
            keys: Vec::new().into(),
            operational_log: Default::default(),
            inner_tls: Some(f.server.clone()),
            https_bridge: None,
            fronted_origin: None,
            relay_training: None,
        },
        rate_limiter: limiter.clone(),
        peer: peer.parse().unwrap(),
        bundle_ctx: None,
        admission: None,
    }
}

fn shaping_profile() -> aegis_core::carrier_runtime::PrivacySettings {
    aegis_core::carrier_runtime::PrivacySettings {
        payload_bytes: 256,
        cadence_ms: 1,
        buffer_bytes: 1024,
        max_wire_bytes: 1_048_576,
        io_timeout_ms: 100,
        session_timeout_ms: 10_000,
        max_queue_delay_ms: 1000,
        poisson_pacing: None,
        net_shaper: None,
        adaptive_channel: None,
        arrival_envelope: None,
        cover_stream: None,
        bit_traps: None,
        liu_channel: None,
    }
}

fn shaping_context(
    f: &Fixture,
    limiter: &RateLimiter,
    peer: &str,
    shaping: bool,
) -> GrpcRequestContext {
    let mut ctx = context(f, limiter, peer);
    ctx.transport.authenticated_shaping = shaping.then(shaping_profile);
    ctx
}

async fn client_with_shaping(
    client: Client,
    carrier: GrpcIo<H2Stream>,
    shaping: bool,
) -> aegis_core::carrier_runtime::OwnedCarrier {
    let inner = client.connect(carrier).await.unwrap();
    secure_channel::relay_shaping::client(
        inner,
        shaping.then(shaping_profile).as_ref(),
        tokio::time::Instant::now() + std::time::Duration::from_secs(3),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn targetless_ack_confirms_dynamic_live_device_and_refuses_static_pins() {
    assert_targetless_ack(false).await;
}

#[tokio::test]
async fn authenticated_shaping_targetless_ack_uses_live_lease_and_no_target() {
    assert_targetless_ack(true).await;
}

async fn assert_targetless_ack(shaping: bool) {
    use secure_channel::{policy_ack, registry};
    let mut f = fixture(true);
    let limiter = RateLimiter::new(10, 300, true);
    // A valid static-pinned TLS identity has no distributed policy to attest.
    let client = f.client.clone();
    assert!(exchange(
        shaping_context(&f, &limiter, "127.0.0.1:443", shaping),
        None,
        |carrier| async move {
            let mut inner = client_with_shaping(client, carrier, shaping).await;
            policy_ack::write_request(&mut inner, &policy_ack::PolicyAckRequest::new())
                .await
                .unwrap();
            assert!(policy_ack::read_ack(&mut inner).await.is_err());
        }
    )
    .await
    .is_err());
    let now = registry::unix_now().unwrap();
    let fingerprint = f.server_settings.allowed_client_sha256[0].clone();
    let path = f._dir.path().join("registry.json");
    let mut snapshot = registry::DeviceRegistry::new(now, 900).unwrap();
    snapshot.devices.push(registry::DeviceRecord {
        device_id: "test-device".into(),
        certificate_sha256: fingerprint.clone(),
        not_after_unix_secs: now + 600,
        revoked: false,
    });
    publish_fresh_reader_fixture(&path, &snapshot).unwrap();
    f.server_settings.allowed_client_sha256.clear();
    f.server_settings.device_registry = Some(path);
    f.server = Server::load(&f.server_settings).unwrap();
    let _watcher = f.server.start_registry_watcher().unwrap();
    let client = f.client.clone();
    let expected = hex::encode(registry::registry_digest(&snapshot).unwrap());
    exchange(
        shaping_context(&f, &limiter, "127.0.0.1:443", shaping),
        None,
        |carrier| async move {
            let mut inner = client_with_shaping(client, carrier, shaping).await;
            let request = policy_ack::PolicyAckRequest::new();
            policy_ack::write_request(&mut inner, &request)
                .await
                .unwrap();
            let ack = policy_ack::read_ack(&mut inner).await.unwrap();
            ack.verify(
                &request.nonce,
                &fingerprint,
                Some((snapshot.generation, &expected)),
                now,
                std::time::Duration::ZERO,
            )
            .unwrap();
            assert_eq!(inner.read(&mut [0; 1]).await.unwrap(), 0);
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn authenticated_numeric_capture_targets_echo_one_challenge_without_target_dial() {
    use aegis_core::{auto_capture_probe, secure_channel::datagram};
    let f = fixture(true);
    let limiter = RateLimiter::new(10, 300, true);
    for transport in [
        secure_channel::Transport::Tcp,
        secure_channel::Transport::Udp,
    ] {
        let client = f.client.clone();
        let host = match transport {
            secure_channel::Transport::Tcp => auto_capture_probe::TCP_HOST,
            secure_channel::Transport::Udp => auto_capture_probe::UDP_HOST,
        };
        exchange(
            context(&f, &limiter, "127.0.0.1:443"),
            None,
            |carrier| async move {
                let mut inner = client.connect(carrier).await.unwrap();
                secure_channel::write_open(
                    &mut inner,
                    &secure_channel::OpenRequest {
                        version: 1,
                        host: host.into(),
                        port: auto_capture_probe::PORT,
                        transport,
                    },
                )
                .await
                .unwrap();
                assert_eq!(inner.read_u8().await.unwrap(), 0);
                let challenge = [0x7bu8; auto_capture_probe::CHALLENGE_BYTES];
                match transport {
                    secure_channel::Transport::Tcp => {
                        inner.write_all(&challenge).await.unwrap();
                        inner.flush().await.unwrap();
                        let mut response = [0u8; auto_capture_probe::CHALLENGE_BYTES];
                        inner.read_exact(&mut response).await.unwrap();
                        assert_eq!(response, challenge);
                    }
                    secure_channel::Transport::Udp => {
                        datagram::write(&mut inner, &challenge).await.unwrap();
                        assert_eq!(
                            datagram::read(&mut inner).await.unwrap(),
                            Some(challenge.to_vec())
                        );
                    }
                }
                assert_eq!(inner.read(&mut [0u8; 1]).await.unwrap(), 0);
            },
        )
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn capture_probe_rejects_short_datagram_and_nearby_target_is_ordinary_policy() {
    use aegis_core::{auto_capture_probe, secure_channel::datagram};
    let f = fixture(true);
    let limiter = RateLimiter::new(10, 300, true);
    let client = f.client.clone();
    assert!(exchange(
        context(&f, &limiter, "127.0.0.1:443"),
        None,
        |carrier| async move {
            let mut inner = client.connect(carrier).await.unwrap();
            secure_channel::write_open(
                &mut inner,
                &secure_channel::OpenRequest {
                    version: 1,
                    host: auto_capture_probe::UDP_HOST.into(),
                    port: auto_capture_probe::PORT,
                    transport: secure_channel::Transport::Udp,
                },
            )
            .await
            .unwrap();
            assert_eq!(inner.read_u8().await.unwrap(), 0);
            datagram::write(&mut inner, &[0x3bu8; 31]).await.unwrap();
            assert!(!matches!(datagram::read(&mut inner).await, Ok(Some(_))));
        },
    )
    .await
    .is_err());
    let client = f.client.clone();
    assert!(exchange(
        context(&f, &limiter, "127.0.0.1:443"),
        None,
        |carrier| async move {
            let mut inner = client.connect(carrier).await.unwrap();
            secure_channel::write_open(
                &mut inner,
                &secure_channel::OpenRequest {
                    version: 1,
                    host: auto_capture_probe::TCP_HOST.into(),
                    port: auto_capture_probe::PORT + 1,
                    transport: secure_channel::Transport::Tcp,
                },
            )
            .await
            .unwrap();
            assert_eq!(inner.read_u8().await.unwrap(), 1);
        },
    )
    .await
    .is_err());
}

#[tokio::test]
async fn legacy_authenticated_capture_targets_echo_only_after_signed_open() {
    use aegis_core::{
        auto_capture_probe,
        tunnel::{
            open_tunnel_response, seal_tunnel_datagram_request, seal_tunnel_request, TunnelRequest,
            TunnelRequestKind, TunnelStatus,
        },
    };
    const TOKEN: &str = "7f0bfd1d31eade038cc6d5581467707af913a1a43e16d7cad86894b3e2a9721e";
    async fn read_frame<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
        let mut prefix = [0u8; 5];
        stream.read_exact(&mut prefix).await.unwrap();
        assert_eq!(prefix[0], 0);
        let size = u32::from_be_bytes(prefix[1..5].try_into().unwrap()) as usize;
        assert!(size <= 4096);
        let mut payload = vec![0; size];
        stream.read_exact(&mut payload).await.unwrap();
        payload
    }
    let f = fixture(true);
    let limiter = RateLimiter::new(10, 300, true);
    let config: crate::config::ServerConfig = toml::from_str(&format!(
        "listen = '127.0.0.1:0'\ncert = 'unused.pem'\nkey = 'unused.key'\nauth_token = '{TOKEN}'"
    ))
    .unwrap();
    for kind in [TunnelRequestKind::Stream, TunnelRequestKind::Datagram] {
        let mut server = context(&f, &limiter, "127.0.0.1:443");
        server.auth_keyring = TunnelAuthKeyring::from_config(&config).unwrap();
        let request = TunnelRequest {
            host: match kind {
                TunnelRequestKind::Stream => auto_capture_probe::TCP_HOST,
                TunnelRequestKind::Datagram => auto_capture_probe::UDP_HOST,
            }
            .into(),
            port: auto_capture_probe::PORT,
        };
        let open = match kind {
            TunnelRequestKind::Stream => seal_tunnel_request(&request, TOKEN.as_bytes()),
            TunnelRequestKind::Datagram => seal_tunnel_datagram_request(&request, TOKEN.as_bytes()),
        }
        .unwrap();
        exchange_legacy(server, open, |mut carrier| async move {
            let accepted = read_frame(&mut carrier).await;
            assert_eq!(
                open_tunnel_response(&accepted, TOKEN.as_bytes())
                    .unwrap()
                    .status,
                TunnelStatus::Ok
            );
            let challenge = [0x59u8; auto_capture_probe::CHALLENGE_BYTES];
            match kind {
                TunnelRequestKind::Stream => {
                    // One TCP write need not map to one gRPC DATA message.
                    carrier
                        .write_all(&grpc_frame(&challenge[..7]))
                        .await
                        .unwrap();
                    carrier
                        .write_all(&grpc_frame(&challenge[7..]))
                        .await
                        .unwrap();
                }
                TunnelRequestKind::Datagram => {
                    carrier.write_all(&grpc_frame(&challenge)).await.unwrap();
                }
            }
            carrier.flush().await.unwrap();
            // The one-shot request has no more uplink bytes. A live H2 client
            // half-closes its send side before dropping the stream; otherwise
            // dropping it after the echo sends RST_CANCEL and races the
            // server handler's successful completion in this fixture.
            carrier.shutdown().await.unwrap();
            assert_eq!(read_frame(&mut carrier).await, challenge);
            assert_eq!(carrier.read(&mut [0u8; 1]).await.unwrap(), 0);
        })
        .await
        .unwrap();
    }
    let mut server = context(&f, &limiter, "127.0.0.1:443");
    server.auth_keyring = TunnelAuthKeyring::from_config(&config).unwrap();
    let open = seal_tunnel_datagram_request(
        &TunnelRequest {
            host: auto_capture_probe::UDP_HOST.into(),
            port: auto_capture_probe::PORT,
        },
        TOKEN.as_bytes(),
    )
    .unwrap();
    assert!(exchange_legacy(server, open, |mut carrier| async move {
        let accepted = read_frame(&mut carrier).await;
        assert_eq!(
            open_tunnel_response(&accepted, TOKEN.as_bytes())
                .unwrap()
                .status,
            TunnelStatus::Ok
        );
        carrier.write_all(&grpc_frame(&[0x59u8; 31])).await.unwrap();
        carrier.flush().await.unwrap();
        let mut first = [0u8; 1];
        assert!(matches!(carrier.read(&mut first).await, Ok(0) | Err(_)));
    })
    .await
    .is_err());
    let mut server = context(&f, &limiter, "127.0.0.1:443");
    server.auth_keyring = TunnelAuthKeyring::from_config(&config).unwrap();
    let unauthorized = seal_tunnel_request(
        &TunnelRequest {
            host: auto_capture_probe::TCP_HOST.into(),
            port: auto_capture_probe::PORT,
        },
        b"foreign-shared-token",
    )
    .unwrap();
    assert!(
        exchange_legacy(server, unauthorized, |mut carrier| async move {
            let mut first = [0u8; 1];
            assert!(matches!(carrier.read(&mut first).await, Ok(0) | Err(_)));
        })
        .await
        .is_err()
    );
}

#[test]
fn inner_tls_origin_rejects_all_shared_token_request_kinds() {
    use aegis_core::tunnel::{seal_tunnel_datagram_request, seal_tunnel_request, TunnelRequest};
    let f = fixture(true);
    let token = "7f0bfd1d31eade038cc6d5581467707af913a1a43e16d7cad86894b3e2a9721e";
    let mut cfg: crate::config::ServerConfig = toml::from_str(&format!(
        "listen = '127.0.0.1:0'\ncert = 'unused.pem'\nkey = 'unused.key'\nauth_token = '{token}'"
    ))
    .unwrap();
    let request = TunnelRequest {
        host: "example.org".into(),
        port: 443,
    };
    let frames = [
        seal_tunnel_request(&request, token.as_bytes()).unwrap(),
        seal_tunnel_datagram_request(&request, token.as_bytes()).unwrap(),
    ];
    // The same valid frames are accepted by an explicitly legacy origin.
    let legacy = TunnelAuthKeyring::from_config(&cfg).unwrap();
    for frame in &frames {
        assert!(legacy.open_request_any(frame).is_ok());
    }
    cfg.transport.inner_tls = Some(f.server_settings.clone());
    let secure = TunnelAuthKeyring::from_config(&cfg).unwrap();
    for frame in &frames {
        assert!(secure.open_request(frame).is_err());
        assert!(secure.open_request_any(frame).is_err());
    }
    cfg.auth_token.clear();
    assert!(TunnelAuthKeyring::from_config(&cfg).is_ok());
}

struct Driver<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for Driver<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Exercise the real HTTP request dispatcher and inner handler over an in-memory
/// H2 carrier. Certificates and all addresses are synthetic; no remote sockets.
async fn exchange<F, Fut>(
    context: GrpcRequestContext,
    forwarded: Option<&str>,
    action: F,
) -> anyhow::Result<()>
where
    F: FnOnce(GrpcIo<H2Stream>) -> Fut,
    Fut: Future<Output = ()>,
{
    exchange_with_watchdog(
        context,
        forwarded,
        std::time::Duration::from_secs(5),
        action,
    )
    .await
}

async fn exchange_with_watchdog<F, Fut>(
    context: GrpcRequestContext,
    forwarded: Option<&str>,
    watchdog: std::time::Duration,
    action: F,
) -> anyhow::Result<()>
where
    F: FnOnce(GrpcIo<H2Stream>) -> Fut,
    Fut: Future<Output = ()>,
{
    exchange_with_watchdog_on_path(
        context,
        forwarded,
        watchdog,
        secure_channel::GRPC_PATH,
        None,
        GrpcIo::new,
        action,
    )
    .await
}

async fn exchange_legacy<F, Fut>(
    context: GrpcRequestContext,
    open: Vec<u8>,
    action: F,
) -> anyhow::Result<()>
where
    F: FnOnce(H2Stream) -> Fut,
    Fut: Future<Output = ()>,
{
    let path = context.transport.grpc_path.clone();
    exchange_with_watchdog_on_path(
        context,
        None,
        std::time::Duration::from_secs(5),
        &path,
        Some(open),
        std::convert::identity,
        action,
    )
    .await
}

async fn exchange_with_watchdog_on_path<F, Fut, S, Wrap>(
    context: GrpcRequestContext,
    forwarded: Option<&str>,
    watchdog: std::time::Duration,
    path: &str,
    prelude: Option<Vec<u8>>,
    wrap: Wrap,
    action: F,
) -> anyhow::Result<()>
where
    Wrap: FnOnce(H2Stream) -> S,
    F: FnOnce(S) -> Fut,
    Fut: Future<Output = ()>,
{
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
    let _serving = Driver(tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let (request, respond) = connection.accept().await.unwrap().unwrap();
        let handling = handle_single_grpc_request(request, respond, context);
        tokio::pin!(handling);
        let mut result_tx = Some(result_tx);
        loop {
            tokio::select! {
                biased;
                result = &mut handling, if result_tx.is_some() => {
                    // Forward the same handler result as the connection-EOF arm:
                    // which event wins must not change the observed refusal.
                    let _ = result_tx.take().unwrap().send(result);
                    // Keep the H2 driver alive to flush queued TLS alerts/ACKs,
                    // as the production connection owner does after a request.
                },
                next = connection.accept() => match next {
                    None => {
                        if let Some(tx) = result_tx.take() { let _ = tx.send(handling.await); }
                        return;
                    },
                    Some(Err(error)) => {
                        if let Some(tx) = result_tx.take() {
                            let _ = tx.send(Err(anyhow::Error::from(error).context("h2 connection accept")));
                        }
                        return;
                    },
                    Some(Ok(_)) => panic!("fixture sends a single request"),
                }
            }
        }
    }));
    let (mut requests, connection) = h2::client::handshake(client_io).await.unwrap();
    let _driver = Driver(tokio::spawn(connection));
    let mut request = http::Request::builder()
        .method(http::Method::POST)
        .uri(path)
        .header("content-type", "application/grpc");
    if let Some(forwarded) = forwarded {
        request = request.header("cf-connecting-ip", forwarded);
    }
    let (response, mut send) = requests
        .send_request(request.body(()).unwrap(), false)
        .unwrap();
    if let Some(prelude) = prelude {
        send_grpc_message(&mut send, &prelude, false).await?;
    }
    let response = response.await?;
    assert_eq!(response.status(), 200);
    let stream = wrap(H2Stream::new(send, response.into_body()));
    let ((), result) =
        tokio::time::timeout(watchdog, async { tokio::join!(action(stream), result_rx) })
            .await
            .unwrap();
    result.unwrap()
}

async fn await_rejection(client: Client, carrier: GrpcIo<H2Stream>) {
    // TLS 1.3 client completion may precede the server's device allowlist check.
    // Waiting for the protected ACK observes the application's rejection.
    if let Ok(mut inner) = client.connect(carrier).await {
        assert!(inner.read_u8().await.is_err());
    }
}

#[tokio::test]
async fn secure_auth_failures_charge_only_the_trusted_forwarded_client() {
    let f = fixture(false);
    let limiter = RateLimiter::new(2, 300, true)
        .with_trusted_proxies(&["203.0.113.0/24".into()], "cf-connecting-ip")
        .unwrap();
    let client_ip = "198.51.100.10".parse().unwrap();
    for attempt in 1..=2 {
        let client = f.client.clone();
        let result = exchange(
            context(&f, &limiter, "203.0.113.10:443"),
            Some("198.51.100.10"),
            |carrier| await_rejection(client, carrier),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(limiter.is_banned(client_ip).await, attempt == 2);
    }
    assert!(!limiter.is_banned("203.0.113.10".parse().unwrap()).await);
    assert!(!limiter.is_banned("198.51.100.11".parse().unwrap()).await);
}

#[tokio::test]
async fn secure_auth_failures_do_not_trust_spoofed_or_missing_forwarded_identity() {
    let f = fixture(false);
    let limiter = RateLimiter::new(1, 300, true)
        .with_trusted_proxies(&["203.0.113.0/24".into()], "cf-connecting-ip")
        .unwrap();
    let client = f.client.clone();
    assert!(exchange(
        context(&f, &limiter, "192.0.2.10:443"),
        Some("198.51.100.10"),
        |carrier| await_rejection(client, carrier)
    )
    .await
    .is_err());
    assert!(limiter.is_banned("192.0.2.10".parse().unwrap()).await);
    assert!(!limiter.is_banned("198.51.100.10".parse().unwrap()).await);
    let client = f.client.clone();
    assert!(
        exchange(context(&f, &limiter, "203.0.113.10:443"), None, |carrier| {
            await_rejection(client, carrier)
        })
        .await
        .is_err()
    );
    assert!(!limiter.is_banned("203.0.113.10".parse().unwrap()).await);
}

#[tokio::test]
async fn secure_auth_timeout_and_post_auth_timeout_do_not_count_as_failures() {
    let f = fixture(true);
    let limiter = RateLimiter::new(1, 300, true);
    assert!(exchange(
        context(&f, &limiter, "192.0.2.10:443"),
        None,
        |mut carrier| async move {
            assert!(carrier.read_u8().await.is_err());
        }
    )
    .await
    .is_err());
    assert!(!limiter.is_banned("192.0.2.10".parse().unwrap()).await);
    let client = f.client.clone();
    assert!(exchange(
        context(&f, &limiter, "192.0.2.11:443"),
        None,
        |carrier| async move {
            let mut inner = client.connect(carrier).await.unwrap();
            // The device authenticated, but does not send an OpenRequest.
            assert!(inner.read_u8().await.is_err());
        }
    )
    .await
    .is_err());
    assert!(!limiter.is_banned("192.0.2.11".parse().unwrap()).await);
}

#[tokio::test]
async fn secure_auth_rejected_certificate_counts_each_failed_handshake() {
    let mut f = fixture(true);
    let foreign = fixture(true);
    // The client still trusts this server, whose client verifier trusts another CA.
    f.server_settings.client_ca = foreign.server_settings.client_ca.clone();
    f.server = Server::load(&f.server_settings).unwrap();
    let limiter = RateLimiter::new(2, 300, true);
    let peer = "192.0.2.12".parse().unwrap();
    for attempt in 1..=2 {
        let client = f.client.clone();
        let error = exchange(context(&f, &limiter, "192.0.2.12:443"), None, |carrier| {
            await_rejection(client, carrier)
        })
        .await
        .unwrap_err();
        assert!(
            matches!(
                error
                    .downcast_ref::<std::io::Error>()
                    .and_then(secure_channel::AuthenticationFailure::from_io),
                Some(secure_channel::AuthenticationFailure::CertificateRejected(
                    _
                ))
            ),
            "{error:#}"
        );
        assert_eq!(limiter.is_banned(peer).await, attempt == 2);
    }
}

#[tokio::test]
async fn secure_target_rejection_and_carrier_eof_do_not_count_as_auth_failures() {
    let f = fixture(true);
    let limiter = RateLimiter::new(1, 300, true);
    let client = f.client.clone();
    assert!(exchange(
        context(&f, &limiter, "192.0.2.10:443"),
        None,
        |carrier| async move {
            let mut inner = client.connect(carrier).await.unwrap();
            secure_channel::write_open(
                &mut inner,
                &secure_channel::OpenRequest {
                    transport: aegis_core::secure_channel::Transport::Tcp,
                    version: 1,
                    host: "127.0.0.1".into(),
                    port: 443,
                },
            )
            .await
            .unwrap();
            // PublicInternet policy rejects this numeric target before socket dial.
            assert_eq!(inner.read_u8().await.unwrap(), 1);
        }
    )
    .await
    .is_err());
    assert!(!limiter.is_banned("192.0.2.10".parse().unwrap()).await);
    assert!(exchange(
        context(&f, &limiter, "192.0.2.11:443"),
        None,
        |mut carrier| async move {
            carrier.shutdown().await.unwrap();
            assert!(carrier.read_u8().await.is_err());
        }
    )
    .await
    .is_err());
    assert!(!limiter.is_banned("192.0.2.11".parse().unwrap()).await);
}

#[tokio::test]
#[cfg(unix)]
async fn secure_device_revoke_closes_existing_tcp_and_udp_and_rejects_reconnect() {
    device_authorization_change_closes_existing_transports(false).await;
}

#[tokio::test]
#[cfg(unix)]
async fn secure_device_rotation_closes_old_tcp_and_udp_and_rejects_old_reconnect() {
    device_authorization_change_closes_existing_transports(true).await;
}

#[cfg(unix)]
async fn device_authorization_change_closes_existing_transports(rotate: bool) {
    assert_device_authorization_change(rotate, false).await;
}

#[tokio::test]
#[cfg(unix)]
async fn authenticated_shaping_revocation_closes_existing_tcp_and_udp() {
    assert_device_authorization_change(false, true).await;
}

#[tokio::test]
#[cfg(unix)]
async fn authenticated_shaping_revocation_keeps_live_io_while_publication_waits_off_runtime() {
    assert_device_authorization_change_with_publication_gate(false, true, true).await;
}

struct FixturePublication {
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
    ready: tokio::sync::oneshot::Receiver<()>,
    release: std::sync::mpsc::Sender<()>,
}

impl FixturePublication {
    fn start(
        owner: std::sync::Arc<tempfile::TempDir>,
        gated: bool,
        publish: impl FnOnce() -> anyhow::Result<()> + Send + 'static,
    ) -> Self {
        let (ready_tx, ready) = tokio::sync::oneshot::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        let task = tokio::task::spawn_blocking(move || {
            // Dropping the async JoinHandle cannot cancel an entered blocking
            // CLI operation. Keep its exact synthetic files alive to completion.
            let _owner = owner;
            if gated {
                ready_tx
                    .send(())
                    .map_err(|_| anyhow::anyhow!("publication owner lost"))?;
                release_rx.recv_timeout(std::time::Duration::from_secs(1))?;
            }
            publish()
        });
        Self {
            task,
            ready,
            release,
        }
    }
}

#[tokio::test]
#[cfg(unix)]
async fn cancelled_fixture_publication_gate_joins_without_mutating_registry() {
    use secure_channel::registry::{DeviceRecord, DeviceRegistry};
    let f = fixture(true);
    let path = f._dir.path().join("cancelled-publication.json");
    let now = secure_channel::registry::unix_now().unwrap();
    let mut snapshot = DeviceRegistry::new(now, 900).unwrap();
    snapshot.devices.push(DeviceRecord {
        device_id: "device-a".into(),
        certificate_sha256: f.server_settings.allowed_client_sha256[0].clone(),
        not_after_unix_secs: now + 600,
        revoked: false,
    });
    secure_channel::registry::publish_snapshot(&path, &snapshot).unwrap();
    let before = std::fs::read(&path).unwrap();
    let target = path.clone();
    let publisher = FixturePublication::start(f._dir.clone(), true, move || {
        crate::devices::revoke(&target, "device-a")
    });
    tokio::time::timeout(std::time::Duration::from_secs(1), publisher.ready)
        .await
        .unwrap()
        .unwrap();
    assert!(!publisher.task.is_finished());
    drop(publisher.release);
    let error = tokio::time::timeout(std::time::Duration::from_secs(1), publisher.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(matches!(
        error.downcast_ref::<std::sync::mpsc::RecvTimeoutError>(),
        Some(std::sync::mpsc::RecvTimeoutError::Disconnected)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(!DeviceRegistry::load(&path).unwrap().devices[0].revoked);
}

#[tokio::test]
#[cfg(unix)]
async fn fixture_publication_preserves_actual_registry_failure() {
    let f = fixture(true);
    let path = f._dir.path().join("failed-publication.json");
    let now = secure_channel::registry::unix_now().unwrap();
    let snapshot = secure_channel::registry::DeviceRegistry::new(now, 900).unwrap();
    secure_channel::registry::publish_snapshot(&path, &snapshot).unwrap();
    let before = std::fs::read(&path).unwrap();
    let target = path.clone();
    let publisher = FixturePublication::start(f._dir.clone(), false, move || {
        crate::devices::revoke(&target, "absent-device")
    });
    let error = tokio::time::timeout(std::time::Duration::from_secs(1), publisher.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(error.to_string().contains("device not found"));
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[tokio::test]
#[cfg(unix)]
async fn fixture_publication_retains_identity_until_entered_detached_work_finishes() {
    use secure_channel::registry::{DeviceRecord, DeviceRegistry};
    let f = fixture(true);
    let directory = f._dir.path().to_owned();
    let weak_owner = std::sync::Arc::downgrade(&f._dir);
    let path = directory.join("detached-publication.json");
    let now = secure_channel::registry::unix_now().unwrap();
    let mut snapshot = DeviceRegistry::new(now, 900).unwrap();
    snapshot.devices.push(DeviceRecord {
        device_id: "device-a".into(),
        certificate_sha256: f.server_settings.allowed_client_sha256[0].clone(),
        not_after_unix_secs: now + 600,
        revoked: false,
    });
    secure_channel::registry::publish_snapshot(&path, &snapshot).unwrap();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
    let publisher = FixturePublication::start(f._dir.clone(), false, move || {
        entered_tx.send(()).unwrap();
        // This bounds only the controlled fixture wait, not CLI lock/fsync.
        release_rx.recv_timeout(std::time::Duration::from_secs(1))?;
        let result = crate::devices::revoke(&path, "device-a");
        let revoked = DeviceRegistry::load(&path)?.devices[0].revoked;
        finished_tx.send((result.is_ok(), revoked)).unwrap();
        result
    });
    let waiter = tokio::spawn(async move { publisher.task.await.unwrap() });
    tokio::time::timeout(std::time::Duration::from_secs(1), entered_rx)
        .await
        .unwrap()
        .unwrap();
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    drop(f);
    // Only the already-entered blocking owner now retains these identities.
    assert!(directory.is_dir());
    assert!(weak_owner.upgrade().is_some());
    release_tx.send(()).unwrap();
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(1), finished_rx)
            .await
            .unwrap()
            .unwrap(),
        (true, true)
    );
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while weak_owner.upgrade().is_some() || directory.exists() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!directory.exists());
}

#[tokio::test]
#[cfg(unix)]
async fn authenticated_shaping_revocation_interrupts_unfinished_agreement() {
    use secure_channel::registry::{DeviceRecord, DeviceRegistry};
    let mut f = fixture(true);
    let now = secure_channel::registry::unix_now().unwrap();
    let registry_path = f._dir.path().join("agreement-device.json");
    let mut snapshot = DeviceRegistry::new(now, 900).unwrap();
    snapshot.devices.push(DeviceRecord {
        device_id: "agreement-device".into(),
        certificate_sha256: f.server_settings.allowed_client_sha256[0].clone(),
        not_after_unix_secs: now + 600,
        revoked: false,
    });
    secure_channel::registry::publish_snapshot(&registry_path, &snapshot).unwrap();
    f.server_settings.allowed_client_sha256.clear();
    f.server_settings.device_registry = Some(registry_path.clone());
    f.server_settings.handshake_timeout_ms = 10_000;
    f.server = Server::load(&f.server_settings).unwrap();
    let _watcher = f.server.start_registry_watcher().unwrap();
    let limiter = RateLimiter::new(1, 300, true);
    let client = f.client.clone();
    let error = exchange(
        shaping_context(&f, &limiter, "192.0.2.10:443", true),
        None,
        |carrier| async move {
            let mut inner = client.connect(carrier).await.unwrap();
            // Deliberately do not send the agreement or any target request.
            crate::devices::revoke(&registry_path, "agreement-device").unwrap();
            assert!(
                tokio::time::timeout(std::time::Duration::from_secs(3), inner.read_u8())
                    .await
                    .unwrap()
                    .is_err()
            );
        },
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            error
                .downcast_ref::<std::io::Error>()
                .and_then(secure_channel::AuthenticationFailure::from_io),
            Some(secure_channel::AuthenticationFailure::DeviceNotAllowed)
        ),
        "{error:#}"
    );
    assert!(!limiter.is_banned("192.0.2.10".parse().unwrap()).await);
    assert!(f.server.try_acquire().is_ok());
}

async fn assert_device_authorization_change(rotate: bool, shaping: bool) {
    assert_device_authorization_change_with_publication_gate(rotate, shaping, false).await;
}

async fn assert_live_ping_pong(
    inner: &mut aegis_core::carrier_runtime::OwnedCarrier,
    transport: secure_channel::Transport,
) {
    match transport {
        secure_channel::Transport::Tcp => {
            inner.write_all(b"ping").await.unwrap();
            inner.flush().await.unwrap();
            let mut pong = [0; 4];
            inner.read_exact(&mut pong).await.unwrap();
            assert_eq!(&pong, b"pong");
        }
        secure_channel::Transport::Udp => {
            secure_channel::datagram::write(inner, b"ping")
                .await
                .unwrap();
            assert_eq!(
                secure_channel::datagram::read(inner)
                    .await
                    .unwrap()
                    .unwrap(),
                b"pong"
            );
        }
    }
}

async fn assert_device_authorization_change_with_publication_gate(
    rotate: bool,
    shaping: bool,
    gated: bool,
) {
    use aegis_core::secure_channel::registry::{
        DeviceRecord, DeviceRegistry, DEFAULT_POLICY_TTL_SECS,
    };
    use aegis_core::secure_channel::{enrollment, Transport};
    for transport in [Transport::Tcp, Transport::Udp] {
        let mut f = fixture(true);
        let registry_path = f._dir.path().join("devices.json");
        let now = secure_channel::registry::unix_now().unwrap();
        let registry = DeviceRegistry {
            devices: vec![DeviceRecord {
                device_id: "device-a".into(),
                certificate_sha256: f.server_settings.allowed_client_sha256[0].clone(),
                not_after_unix_secs: now + 3600,
                revoked: false,
            }],
            ..DeviceRegistry::new(now, DEFAULT_POLICY_TTL_SECS).unwrap()
        };
        secure_channel::registry::publish_snapshot(&registry_path, &registry).unwrap();
        f.server_settings.allowed_client_sha256.clear();
        f.server_settings.device_registry = Some(registry_path.clone());
        f.server_settings.handshake_timeout_ms = 3000;
        f.server_settings.idle_timeout_ms = 10_000;
        f.server = Server::load(&f.server_settings).unwrap();
        let _watcher = f.server.start_registry_watcher().unwrap();
        let enrollment_dir = f._dir.path().to_owned();
        if rotate {
            let csr = enrollment::generate_csr("device-a").unwrap();
            enrollment::write_private_new(
                &enrollment_dir.join("renew.csr"),
                csr.csr_pem.as_bytes(),
            )
            .unwrap();
            crate::devices::rotate_invite(
                &registry_path,
                "device-a",
                &enrollment_dir.join("renew.invitation"),
                300,
                secure_channel::registry::unix_now().unwrap(),
            )
            .unwrap();
            // Creating an invitation has not retired the old certificate;
            // its real TCP/UDP connection is established below.
        }
        let transfers = if gated { 2 } else { 1 };
        let (port, _target) = match transport {
            Transport::Tcp => {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let port = listener.local_addr().unwrap().port();
                let task = Driver(tokio::spawn(async move {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    for _ in 0..transfers {
                        let mut ping = [0; 4];
                        stream.read_exact(&mut ping).await.unwrap();
                        assert_eq!(&ping, b"ping");
                        stream.write_all(b"pong").await.unwrap();
                    }
                    let mut remaining = Vec::new();
                    stream.read_to_end(&mut remaining).await.unwrap();
                    assert!(remaining.is_empty());
                }));
                (port, task)
            }
            Transport::Udp => {
                let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let port = socket.local_addr().unwrap().port();
                let task = Driver(tokio::spawn(async move {
                    for _ in 0..transfers {
                        let mut ping = [0; 64];
                        let (n, peer) = socket.recv_from(&mut ping).await.unwrap();
                        assert_eq!(&ping[..n], b"ping");
                        socket.send_to(b"pong", peer).await.unwrap();
                    }
                    // Keep the target alive so only revocation ends the relay.
                    std::future::pending::<()>().await;
                }));
                (port, task)
            }
        };
        let limiter = RateLimiter::new(1, 300, true);
        let mut ctx = shaping_context(&f, &limiter, "192.0.2.10:443", shaping);
        ctx.target_policy.profile = crate::config::TargetPolicyProfile::FullVpnEgress;
        let client = f.client.clone();
        let publication_owner = f._dir.clone();
        let error = exchange(ctx, None, |carrier| async move {
            let mut inner = client_with_shaping(client, carrier, shaping).await;
            secure_channel::write_open(
                &mut inner,
                &secure_channel::OpenRequest {
                    version: 1,
                    transport,
                    host: "127.0.0.1".into(),
                    port,
                },
            )
            .await
            .unwrap();
            assert_eq!(inner.read_u8().await.unwrap(), 0);
            assert_live_ping_pong(&mut inner, transport).await;
            // Publication owns blocking transaction/lock/fsync/signing work.
            // It must not starve the current-thread carrier/watcher runtime.
            let publisher = FixturePublication::start(
                publication_owner,
                gated,
                move || -> anyhow::Result<()> {
                    if rotate {
                        crate::devices::issue(
                            &registry_path,
                            &enrollment_dir.join("renew.csr"),
                            &enrollment_dir.join("renew.invitation"),
                            &enrollment_dir.join("ca.pem"),
                            &enrollment_dir.join("ca.key"),
                            &enrollment_dir.join("renew.pem"),
                            3600,
                        )?;
                    } else {
                        crate::devices::revoke(&registry_path, "device-a")?;
                    }
                    Ok(())
                },
            );
            if gated {
                publisher.ready.await.unwrap();
                assert!(!publisher.task.is_finished());
                // Real shaped TCP/UDP response while the same publication
                // owner is blocked; failure drops the release channel.
                assert_live_ping_pong(&mut inner, transport).await;
                assert!(!publisher.task.is_finished());
                publisher.release.send(()).unwrap();
            }
            publisher.task.await.unwrap().unwrap();
            assert!(inner.read_u8().await.is_err());
        })
        .await
        .unwrap_err();
        assert!(
            matches!(
                error
                    .downcast_ref::<std::io::Error>()
                    .and_then(secure_channel::AuthenticationFailure::from_io),
                Some(secure_channel::AuthenticationFailure::DeviceNotAllowed)
            ),
            "{error:#}"
        );
        assert!(
            f.server.try_acquire().is_ok(),
            "revoked request released its permit"
        );
        assert!(
            !limiter.is_banned("192.0.2.10".parse().unwrap()).await,
            "active session revocation is not a failed login"
        );
        let client = f.client.clone();
        assert!(
            exchange(context(&f, &limiter, "192.0.2.10:443"), None, |carrier| {
                await_rejection(client, carrier)
            })
            .await
            .is_err()
        );
        assert!(
            limiter.is_banned("192.0.2.10".parse().unwrap()).await,
            "new authentication with a revoked certificate must fail"
        );
    }
}

fn poisson_shaping_profile() -> aegis_core::carrier_runtime::PrivacySettings {
    let mut profile = shaping_profile();
    profile.cadence_ms = 1000;
    profile.max_queue_delay_ms = 20_000;
    profile.poisson_pacing = Some(aegis_core::traffic_privacy::poisson::PoissonPacing {
        mean_interval_us: 1000,
        max_gap_us: 1_000_000,
    });
    profile
}

#[tokio::test]
async fn poisson_authenticated_h2_handler_preserves_target_policy_refusal() {
    let f = fixture(true);
    let limiter = RateLimiter::new(1, 300, true);
    let client = f.client.clone();
    let mut ctx = context(&f, &limiter, "192.0.2.31:443");
    ctx.transport.authenticated_shaping = Some(poisson_shaping_profile());
    let result = exchange(ctx, None, |carrier| async move {
        let inner = client.connect(carrier).await.unwrap();
        let mut shaped = secure_channel::relay_shaping::client(
            inner,
            Some(&poisson_shaping_profile()),
            tokio::time::Instant::now() + std::time::Duration::from_secs(3),
        )
        .await
        .unwrap();
        secure_channel::write_open(
            &mut shaped,
            &secure_channel::OpenRequest {
                transport: secure_channel::Transport::Tcp,
                version: 1,
                host: "127.0.0.1".into(),
                port: 443,
            },
        )
        .await
        .unwrap();
        // Actual authenticated TLS/H2 dispatcher invokes the pacer, but still
        // refuses a private numeric target before dialing it.
        assert_eq!(shaped.read_u8().await.unwrap(), 1);
    })
    .await;
    assert!(result.is_err());
    assert!(!limiter.is_banned("192.0.2.31".parse().unwrap()).await);
}

#[tokio::test]
async fn poisson_authenticated_h2_handler_rejects_peer_rate_mismatch() {
    let f = fixture(true);
    let limiter = RateLimiter::new(1, 300, true);
    let client = f.client.clone();
    let mut ctx = context(&f, &limiter, "192.0.2.32:443");
    ctx.transport.authenticated_shaping = Some(poisson_shaping_profile());
    let result = exchange(ctx, None, |carrier| async move {
        let inner = client.connect(carrier).await.unwrap();
        let mut peer = poisson_shaping_profile();
        peer.poisson_pacing.as_mut().unwrap().mean_interval_us = 2000;
        assert!(secure_channel::relay_shaping::client(
            inner,
            Some(&peer),
            tokio::time::Instant::now() + std::time::Duration::from_secs(3),
        )
        .await
        .is_err());
        // No Open request or target data is sent on a refused profile.
    })
    .await;
    assert!(result.is_err());
    assert!(!limiter.is_banned("192.0.2.32".parse().unwrap()).await);
}

fn research_profiles() -> Vec<aegis_core::carrier_runtime::PrivacySettings> {
    use aegis_core::traffic_privacy::{adaptive_channel, bittraps, cover_stream, netshaper};
    let mut net = shaping_profile();
    // Real TCP/TLS execution retains real clocks. Its happy-path public
    // envelope must not rely on a hosted Windows/ARM runner waking in 10 ms.
    // Runtime missed-slot and late-poll rejection are unchanged.
    net.cadence_ms = 100;
    net.io_timeout_ms = 500;
    net.max_queue_delay_ms = 7000;
    net.net_shaper = Some(netshaper::NetShaperConfig {
        slots: 64,
        cadence_ms: 100,
        window_ms: 7000,
        io_timeout_ms: 100,
        queue_cap: 256,
        release_cap: 128,
        sigma_bytes: 1024,
        rho_limit_n: "64".into(),
        rho_limit_d: "1".into(),
    });
    let mut bit = shaping_profile();
    bit.cadence_ms = 100;
    bit.io_timeout_ms = 500;
    bit.max_queue_delay_ms = 7000;
    bit.bit_traps = Some(bittraps::BitTrapsSettings {
        slots: 64,
        cadence_ms: 100,
        io_timeout_ms: 100,
        queue_cap: 256,
        service: vec![(128, 1), (256, 1)],
    });
    let mut adaptive = shaping_profile();
    adaptive.max_queue_delay_ms = 200_000;
    adaptive.adaptive_channel = Some(adaptive_channel::AdaptiveSettings {
        objective: None,
        joint_counts: vec![vec![10, 0], vec![0, 10]],
        length_bin_upper: vec![128, 256],
        actions: vec![
            adaptive_channel::Action {
                padded_bytes: 128,
                delay_ms: 0,
            },
            adaptive_channel::Action {
                padded_bytes: 256,
                delay_ms: 0,
            },
        ],
        delay_cost_per_ms: 0,
        cost_budget: 256,
        optimizer_iterations: 1000,
        optimizer_gap_millibits: 1,
        optimizer_timeout_ms: 500,
        buffer_bytes: 1024,
        max_wire_bytes: 1_048_576,
        io_timeout_ms: 100,
        session_timeout_ms: 10_000,
        max_queue_delay_ms: 200_000,
    });
    let mut cover = shaping_profile();
    cover.io_timeout_ms = 1000;
    cover.max_queue_delay_ms = 10_000;
    cover.cover_stream = Some(cover_stream::CoverStreamSettings {
        tokens: vec![vec![65], vec![66], vec![67]],
        weights: vec![4, 2, 1],
        conditional_model: None,
        capacity: 33,
        horizon: 1024,
        max_records: 32,
        buffer_bytes: 1024,
        max_wire_bytes: 32768,
        io_timeout_ms: 1000,
        session_timeout_ms: 10_000,
    });
    let mut conditional = cover.clone();
    let stream = conditional.cover_stream.as_mut().unwrap();
    stream.weights = vec![2, 1, 1];
    stream.conditional_model = Some(
        aegis_core::traffic_privacy::general_coupling::ConditionalCoverSettings {
            initial_state: 0,
            state_weights: vec![stream.weights.clone(), vec![1, 2, 1]],
            next_states: vec![vec![0, 1, 0], vec![0, 1, 0]],
        },
    );
    let mut maximum = adaptive.clone();
    maximum.adaptive_channel.as_mut().unwrap().objective =
        Some(adaptive_channel::AdaptiveObjective::MaximumInformation {
            leakage_cap_millibits: 500,
            cost_gap: 1,
        });
    let mut minimax = adaptive.clone();
    minimax.adaptive_channel.as_mut().unwrap().objective =
        Some(adaptive_channel::AdaptiveObjective::MinimaxInformation {
            leakage_gap_millibits: 100,
            cost_gap: 1,
            cap_programs: 8,
        });
    vec![net, bit, adaptive, cover, conditional, maximum, minimax]
}

fn research_fixture(profile: &aegis_core::carrier_runtime::PrivacySettings) -> Fixture {
    let mut f = fixture(true);
    // This positive workload declares a 10s envelope. Its fixed public epochs
    // last 6.4s even on EOF; a 1s establishment/idle budget cannot promise their
    // drain or even an ACK after fresh Gaussian zero releases. These are test
    // settings, not renewed runtime clocks or a transport availability proof.
    f.server_settings.handshake_timeout_ms = profile.session_timeout_ms;
    f.server_settings.idle_timeout_ms = profile.session_timeout_ms;
    f.server = Server::load(&f.server_settings).unwrap();
    f
}

#[tokio::test(start_paused = true)]
async fn research_netshaper_first_slot_after_original_deadline_refuses_open() {
    let mut profile = research_profiles().remove(0);
    let net = profile.net_shaper.as_mut().unwrap();
    net.slots = 4;
    net.cadence_ms = 1500;
    profile.validate().unwrap();
    // Keep the existing 1s server deadline. No first public frame can carry
    // Open until 1.5s, irrespective of the fresh Gaussian release or key draws.
    let f = fixture(true);
    assert_eq!(f.server_settings.handshake_timeout_ms, 1000);
    let limiter = RateLimiter::new(1, 300, true);
    let client = f.client.clone();
    let mut ctx = context(&f, &limiter, "192.0.2.60:443");
    ctx.transport.authenticated_shaping = Some(profile.clone());
    let result = exchange(ctx, None, |carrier| async move {
        let inner = client.connect(carrier).await.unwrap();
        let mut shaped = secure_channel::relay_shaping::client(
            inner,
            Some(&profile),
            tokio::time::Instant::now() + std::time::Duration::from_secs(3),
        )
        .await
        .unwrap();
        secure_channel::write_open(
            &mut shaped,
            &secure_channel::OpenRequest {
                transport: secure_channel::Transport::Tcp,
                version: 1,
                host: "127.0.0.1".into(),
                port: 443,
            },
        )
        .await
        .unwrap();
        assert!(shaped.read_u8().await.is_err());
    })
    .await;
    assert_eq!(
        result.unwrap_err().to_string(),
        "authenticated secure channel establishment timed out"
    );
    assert!(!limiter.is_banned("192.0.2.60".parse().unwrap()).await);
}

#[tokio::test]
async fn research_profiles_cross_actual_device_tls_and_h2_target_policy() {
    for (index, profile) in research_profiles().into_iter().enumerate() {
        profile.validate().unwrap();
        let f = research_fixture(&profile);
        let limiter = RateLimiter::new(1, 300, true);
        let client = f.client.clone();
        let peer = format!("192.0.2.{}:443", 41 + index);
        let mut ctx = context(&f, &limiter, &peer);
        ctx.transport.authenticated_shaping = Some(profile.clone());
        let result = exchange_with_watchdog(
            ctx,
            None,
            std::time::Duration::from_secs(12),
            |carrier| async move {
                let inner = client.connect(carrier).await.unwrap();
                let mut shaped = secure_channel::relay_shaping::client(
                    inner,
                    Some(&profile),
                    tokio::time::Instant::now() + std::time::Duration::from_secs(3),
                )
                .await
                .unwrap();
                secure_channel::write_open(
                    &mut shaped,
                    &secure_channel::OpenRequest {
                        transport: secure_channel::Transport::Tcp,
                        version: 1,
                        host: "127.0.0.1".into(),
                        port: 443,
                    },
                )
                .await
                .unwrap();
                assert_eq!(shaped.read_u8().await.unwrap(), 1, "profile {index}");
            },
        )
        .await;
        // These are actual TLS and H2 codecs over local duplex I/O. An admitted
        // modifier must preserve target policy and never cause an auth ban.
        assert!(
            result.is_err(),
            "target policy should refuse profile {index}"
        );
        assert!(
            !limiter
                .is_banned(format!("192.0.2.{}", 41 + index).parse().unwrap())
                .await
        );
    }
}

#[tokio::test]
async fn research_profiles_relay_actual_tcp_payload_and_owned_completion() {
    for (index, profile) in research_profiles().into_iter().enumerate() {
        let f = research_fixture(&profile);
        let limiter = RateLimiter::new(1, 300, true);
        let client = f.client.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let target = tokio::spawn(async move {
            let (mut remote, _) = listener.accept().await.unwrap();
            let mut ping = [0; 4];
            remote.read_exact(&mut ping).await.unwrap();
            assert_eq!(&ping, b"ping");
            remote.write_all(b"pong").await.unwrap();
            remote.shutdown().await.unwrap();
        });
        let mut ctx = context(&f, &limiter, "192.0.2.50:443");
        ctx.transport.authenticated_shaping = Some(profile.clone());
        ctx.target_policy.profile = crate::config::TargetPolicyProfile::FullVpnEgress;
        let result = exchange_with_watchdog(
            ctx,
            None,
            std::time::Duration::from_secs(12),
            |carrier| async move {
                let inner = client.connect(carrier).await.unwrap();
                let mut shaped = secure_channel::relay_shaping::client(
                    inner,
                    Some(&profile),
                    tokio::time::Instant::now() + std::time::Duration::from_secs(3),
                )
                .await
                .unwrap();
                secure_channel::write_open(
                    &mut shaped,
                    &secure_channel::OpenRequest {
                        transport: secure_channel::Transport::Tcp,
                        version: 1,
                        host: "127.0.0.1".into(),
                        port,
                    },
                )
                .await
                .unwrap();
                assert_eq!(shaped.read_u8().await.unwrap(), 0);
                shaped.write_all(b"ping").await.unwrap();
                if index >= 2 {
                    // Continuous causal/MEC adapters support an ordinary half-close.
                    shaped.shutdown().await.unwrap();
                }
                let mut pong = [0; 4];
                shaped.read_exact(&mut pong).await.unwrap();
                assert_eq!(&pong, b"pong", "profile {index}");
                if index >= 2 {
                    assert_eq!(
                        shaped.read_u8().await.unwrap_err().kind(),
                        std::io::ErrorKind::UnexpectedEof
                    );
                }
                // Fixed epochs are deliberately cancelled here after the exchange;
                // an open source must not be promoted into successful clean EOF.
            },
        )
        .await;
        if index >= 2 {
            assert!(result.is_ok(), "profile {index}: {result:?}");
        }
        tokio::time::timeout(std::time::Duration::from_secs(2), target)
            .await
            .unwrap()
            .unwrap();
        assert!(!limiter.is_banned("192.0.2.50".parse().unwrap()).await);
    }
}

#[path = "secure_liu_tests.rs"]
mod liu_tests;

#[cfg(unix)]
#[path = "secure_cleanup_tests.rs"]
mod cleanup_tests;
