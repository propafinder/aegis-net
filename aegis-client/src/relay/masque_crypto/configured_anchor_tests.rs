//! Owned loopback QUIC/TLS1.3/H3 trust-policy tests. Generated private keys stay
//! in memory; only public CA certificates enter the production file reader.
//! Synthetic platform anchors are a controlled loader seam, not OS trust edits.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use bytes::{Buf, Bytes};
use h3::ext::Protocol;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::PrivatePkcs8KeyDer;
use tokio::task::JoinSet;

use super::*;

const WORK: Duration = Duration::from_secs(10);
const CLEANUP: Duration = Duration::from_secs(2);
const UP: &[u8] = b"configured-anchor-up";
const DOWN: &[u8] = b"configured-anchor-down";
const FIXTURE_AUTH: &[u8] = b"owned-local-trust-policy-fixture";

struct Signer {
    ca: Certificate,
    key: KeyPair,
}

impl Signer {
    fn new() -> anyhow::Result<Self> {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca = params.self_signed(&key)?;
        Ok(Self { ca, key })
    }

    fn server(&self) -> anyhow::Result<quinn::ServerConfig> {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::new(vec!["localhost".to_owned()])?;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let cert = params.signed_by(&key, &self.ca, &self.key)?;
        let mut crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone(), self.ca.der().clone()],
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )?;
        crypto.alpn_protocols = vec![b"h3".to_vec()];
        Ok(quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?,
        )))
    }
}

fn settings(ca: Option<&Path>, mode: MasqueTrustMode) -> RelaySettings {
    RelaySettings {
        server_name: "localhost".into(),
        tls_backend: RelayTlsBackend::Rustls,
        masque_ca_cert: ca.map(Path::to_path_buf),
        masque_trust_mode: mode,
        ..Default::default()
    }
}

fn production_config(settings: &RelaySettings) -> anyhow::Result<quinn::ClientConfig> {
    let authority = super::super::relay_transport_authority(settings)?;
    masque_quic_client_config(settings, &authority)
}

#[derive(Debug)]
struct Exchange {
    handshake_accepted: bool,
    refusal_crypto_code: Option<u64>,
    authorized_requests: usize,
    marker_received: bool,
    direct_cleanup_confirmed: bool,
}

// These categories bind the two production Runtime::spawn sites in the locked
// Quinn 0.11.9 source: Endpoint::new_with_abstract_socket spawns synchronously
// during construction, and Connecting::new spawns once during this exchange.
// They are construction phases, not guessed background-task ordinals. A source
// epoch or additional spawn must fail the fixture's ownership checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpawnPhase {
    Constructing,
    Serving,
    Closing,
}

#[derive(Debug)]
struct RuntimeTasks {
    phase: SpawnPhase,
    endpoint: Option<tokio::task::JoinHandle<()>>,
    connection: Option<tokio::task::JoinHandle<()>>,
    invalid: bool,
}

impl Drop for RuntimeTasks {
    fn drop(&mut self) {
        for handle in [&self.connection, &self.endpoint].into_iter().flatten() {
            handle.abort();
        }
        // Emergency abort alone is never a joined-cleanup observation.
    }
}

#[derive(Debug)]
struct FixtureRuntime(std::sync::Mutex<RuntimeTasks>);

impl FixtureRuntime {
    fn shared() -> Arc<Self> {
        Arc::new(Self(std::sync::Mutex::new(RuntimeTasks {
            phase: SpawnPhase::Constructing,
            endpoint: None,
            connection: None,
            invalid: false,
        })))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RuntimeTasks> {
        self.0.lock().unwrap_or_else(|poisoned| {
            let mut tasks = poisoned.into_inner();
            tasks.invalid = true;
            tasks
        })
    }

    fn finish_construction(&self) -> anyhow::Result<()> {
        let mut tasks = self.lock();
        let valid = tasks.phase == SpawnPhase::Constructing
            && tasks.endpoint.is_some()
            && tasks.connection.is_none()
            && !tasks.invalid;
        tasks.phase = SpawnPhase::Serving;
        anyhow::ensure!(valid, "fixture endpoint spawn binding refused");
        Ok(())
    }

    fn take(&self) -> RuntimeTasks {
        let mut tasks = self.lock();
        tasks.phase = SpawnPhase::Closing;
        RuntimeTasks {
            phase: SpawnPhase::Closing,
            endpoint: tasks.endpoint.take(),
            connection: tasks.connection.take(),
            invalid: tasks.invalid,
        }
    }

    fn invalid(&self) -> bool {
        self.lock().invalid
    }

    fn abort_retained(&self) {
        let tasks = self.lock();
        for handle in [&tasks.connection, &tasks.endpoint].into_iter().flatten() {
            handle.abort();
        }
    }
}

impl quinn::Runtime for FixtureRuntime {
    fn new_timer(&self, at: std::time::Instant) -> std::pin::Pin<Box<dyn quinn::AsyncTimer>> {
        quinn::Runtime::new_timer(&quinn::TokioRuntime, at)
    }

    fn spawn(&self, future: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>) {
        let mut tasks = self.lock();
        match tasks.phase {
            SpawnPhase::Constructing if tasks.endpoint.is_none() => {
                tasks.endpoint = Some(tokio::spawn(future));
            }
            SpawnPhase::Serving if tasks.connection.is_none() => {
                tasks.connection = Some(tokio::spawn(future));
            }
            _ => {
                tasks.invalid = true;
                // Refuse an unexpected, still-unspawned future. Do not create
                // an unretained task or invent a role for an extra spawn.
                drop(tasks);
                drop(future);
            }
        }
    }

    fn wrap_udp_socket(
        &self,
        socket: std::net::UdpSocket,
    ) -> std::io::Result<Arc<dyn quinn::AsyncUdpSocket>> {
        quinn::Runtime::wrap_udp_socket(&quinn::TokioRuntime, socket)
    }

    fn now(&self) -> std::time::Instant {
        quinn::Runtime::now(&quinn::TokioRuntime)
    }
}

struct FixtureDrivers {
    client: RuntimeTasks,
    server: RuntimeTasks,
    connection_handles: usize,
    endpoint_handles: usize,
    connections_joined: usize,
    endpoints_joined: usize,
}

impl FixtureDrivers {
    fn new(client: &FixtureRuntime, server: &FixtureRuntime) -> Self {
        let client = client.take();
        let server = server.take();
        Self {
            connection_handles: usize::from(client.connection.is_some())
                + usize::from(server.connection.is_some()),
            endpoint_handles: usize::from(client.endpoint.is_some())
                + usize::from(server.endpoint.is_some()),
            client,
            server,
            connections_joined: 0,
            endpoints_joined: 0,
        }
    }

    fn abort_connections(&self) {
        for handle in [&self.client.connection, &self.server.connection]
            .into_iter()
            .flatten()
        {
            handle.abort();
        }
    }

    fn abort_endpoints(&self) {
        for handle in [&self.client.endpoint, &self.server.endpoint]
            .into_iter()
            .flatten()
        {
            handle.abort();
        }
    }

    async fn join_connections(&mut self) -> Option<anyhow::Error> {
        let mut first = None;
        for slot in [&mut self.client.connection, &mut self.server.connection] {
            Self::join(slot, &mut self.connections_joined, &mut first).await;
        }
        first
    }

    async fn join_endpoints(&mut self) -> Option<anyhow::Error> {
        let mut first = None;
        for slot in [&mut self.client.endpoint, &mut self.server.endpoint] {
            Self::join(slot, &mut self.endpoints_joined, &mut first).await;
        }
        first
    }

    async fn join(
        slot: &mut Option<tokio::task::JoinHandle<()>>,
        observed: &mut usize,
        first: &mut Option<anyhow::Error>,
    ) {
        if let Some(handle) = slot.as_mut() {
            // The handle stays in its exterior owner across this await. A
            // timeout drops only this borrow, then owner Drop aborts the same
            // retained task without claiming it was joined.
            let result = handle.await;
            *slot = None;
            *observed += 1;
            if matches!(result, Err(error) if !error.is_cancelled()) && first.is_none() {
                *first = Some(anyhow!("fixture Quinn worker failed"));
            }
        }
    }
}

struct FixtureEndpoints {
    client: Option<quinn::Endpoint>,
    server: Option<quinn::Endpoint>,
    client_runtime: Arc<FixtureRuntime>,
    server_runtime: Arc<FixtureRuntime>,
}

impl Drop for FixtureEndpoints {
    fn drop(&mut self) {
        // Explicitly break task/runtime Arc custody on external cancellation
        // or panic. This emergency path does not assert joined cleanup.
        self.client_runtime.abort_retained();
        self.server_runtime.abort_retained();
    }
}

impl FixtureEndpoints {
    async fn new(config: quinn::ClientConfig, signer: &Signer) -> anyhow::Result<Self> {
        // Finish fallible certificate/socket preparation before any driver is
        // spawned. Endpoint::new delegates wrapping to the original runtime.
        let server_config = signer.server()?;
        let server_socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let client_socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
        server_socket.set_nonblocking(true)?;
        client_socket.set_nonblocking(true)?;
        let mut endpoints = Self {
            client: None,
            server: None,
            client_runtime: FixtureRuntime::shared(),
            server_runtime: FixtureRuntime::shared(),
        };
        let setup = (|| -> anyhow::Result<()> {
            endpoints.server = Some(quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(server_config),
                server_socket,
                endpoints.server_runtime.clone(),
            )?);
            endpoints.server_runtime.finish_construction()?;
            let mut client = quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                None,
                client_socket,
                endpoints.client_runtime.clone(),
            )?;
            // Assign before a fallible binding check so error cleanup owns it.
            client.set_default_client_config(config);
            endpoints.client = Some(client);
            endpoints.client_runtime.finish_construction()?;
            Ok(())
        })();
        if let Err(error) = setup {
            let deadline = tokio::time::Instant::now() + CLEANUP;
            endpoints.close();
            let mut drivers =
                FixtureDrivers::new(&endpoints.client_runtime, &endpoints.server_runtime);
            let cleanup = tokio::time::timeout_at(deadline, async {
                drivers.abort_connections();
                let mut first = drivers.join_connections().await;
                for endpoint in [&endpoints.client, &endpoints.server].into_iter().flatten() {
                    endpoint.wait_idle().await;
                }
                drivers.abort_endpoints();
                let failure = drivers.join_endpoints().await;
                if first.is_none() {
                    first = failure;
                }
                if let Some(error) = first {
                    return Err(error);
                }
                Ok(())
            })
            .await;
            cleanup.context("fixture setup cleanup deadline")??;
            return Err(error);
        }
        Ok(endpoints)
    }

    fn close(&self) {
        for endpoint in [&self.client, &self.server].into_iter().flatten() {
            endpoint.close(quinn::VarInt::from_u32(0), b"fixture complete");
        }
    }
}

// The exterior direct-task and Runtime owners outlive the timed operation.
// Cleanup joins actual connection drivers before endpoint drivers, while the
// latter remain active to consume real State::drop Drained events. All close,
// direct/background joins and both original wait_idle calls share CLEANUP.
async fn exchange(config: quinn::ClientConfig, signer: &Signer) -> anyhow::Result<Exchange> {
    let endpoints = FixtureEndpoints::new(config, signer).await?;
    let server = endpoints.server.as_ref().context("fixture server absent")?;
    let client = endpoints.client.as_ref().context("fixture client absent")?;
    let requests = Arc::new(AtomicUsize::new(0));
    // Test-only finite phase facts. Relaxed observations are not coherent
    // health or transport-completion claims and carry no packet contents.
    let server_phase = Arc::new(AtomicUsize::new(0));
    let mut client_phase = 0usize;
    let mut tasks = JoinSet::<anyhow::Result<()>>::new();
    let server_worker = server.clone();
    let worker_requests = requests.clone();
    let worker_phase = server_phase.clone();
    tasks.spawn(async move {
        worker_phase.store(1, Ordering::Relaxed);
        let incoming = server_worker
            .accept()
            .await
            .context("fixture incoming absent")?;
        worker_phase.store(2, Ordering::Relaxed);
        let connection = match incoming.await {
            Ok(connection) => connection,
            // Peer verification refusal must produce no H3 request.
            Err(_) => return Ok(()),
        };
        let mut builder = h3::server::builder();
        builder.enable_extended_connect(true).enable_datagram(true);
        worker_phase.store(3, Ordering::Relaxed);
        let mut h3 = builder
            .build::<_, Bytes>(h3_quinn::Connection::new(connection))
            .await?;
        worker_phase.store(4, Ordering::Relaxed);
        let resolver = h3.accept().await?.context("fixture H3 request absent")?;
        worker_phase.store(5, Ordering::Relaxed);
        let (request, mut stream) = resolver.resolve_request().await?;
        anyhow::ensure!(request.method() == http::Method::CONNECT, "fixture method");
        anyhow::ensure!(
            request.extensions().get::<Protocol>() == Some(&Protocol::CONNECT_UDP),
            "fixture protocol"
        );
        let header = request.headers()[http::header::AUTHORIZATION].to_str()?;
        let sealed = hex::decode(
            header
                .strip_prefix("Bearer ")
                .context("fixture auth header")?,
        )?;
        let open = aegis_core::tunnel::open_tunnel_request(&sealed, FIXTURE_AUTH)?;
        anyhow::ensure!(
            open.host == "localhost" && open.port == 443,
            "fixture bound target"
        );
        worker_requests.fetch_add(1, Ordering::Relaxed);
        worker_phase.store(6, Ordering::Relaxed);
        let mut up = Vec::new();
        worker_phase.store(7, Ordering::Relaxed);
        while let Some(mut data) = stream.recv_data().await? {
            anyhow::ensure!(up.len() + data.remaining() <= 128, "fixture uplink bound");
            up.extend_from_slice(&data.copy_to_bytes(data.remaining()));
        }
        anyhow::ensure!(up == UP, "fixture uplink marker");
        worker_phase.store(8, Ordering::Relaxed);
        stream.send_response(http::Response::new(())).await?;
        worker_phase.store(9, Ordering::Relaxed);
        stream.send_data(Bytes::from_static(DOWN)).await?;
        worker_phase.store(10, Ordering::Relaxed);
        stream.finish().await?;
        worker_phase.store(11, Ordering::Relaxed);
        // Keep the H3 connection owner alive until exterior cleanup. No
        // assertion depends on circular graceful connection joins.
        std::future::pending::<()>().await;
        Ok(())
    });
    let operation = tokio::time::timeout(WORK, async {
        client_phase = 1;
        let connection = match client.connect(server.local_addr()?, "localhost")?.await {
            Ok(connection) => connection,
            Err(quinn::ConnectionError::TransportError(error))
                if (0x100..0x200).contains(&u64::from(error.code)) =>
            {
                return Ok::<_, anyhow::Error>((false, false, Some(u64::from(error.code))));
            }
            Err(_) => anyhow::bail!("fixture failed outside TLS verification"),
        };
        let mut builder = h3::client::builder();
        builder.enable_extended_connect(true).enable_datagram(true);
        client_phase = 2;
        let (mut h3, mut send) = builder
            .build::<_, _, Bytes>(h3_quinn::Connection::new(connection))
            .await?;
        tasks.spawn(async move {
            let _ = h3.wait_idle().await;
            Ok(())
        });
        let sealed = aegis_core::tunnel::seal_tunnel_request(
            &aegis_core::tunnel::TunnelRequest {
                host: "localhost".into(),
                port: 443,
            },
            FIXTURE_AUTH,
        )?;
        let mut request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri("https://localhost/.well-known/masque/udp/localhost/443/")
            .header(
                http::header::AUTHORIZATION,
                format!("Bearer {}", hex::encode(sealed)),
            )
            .body(())?;
        request.extensions_mut().insert(Protocol::CONNECT_UDP);
        client_phase = 3;
        let mut stream = send.send_request(request).await?;
        client_phase = 4;
        stream.send_data(Bytes::from_static(UP)).await?;
        client_phase = 5;
        stream.finish().await?;
        client_phase = 6;
        anyhow::ensure!(
            stream.recv_response().await?.status().is_success(),
            "fixture response status"
        );
        let mut down = Vec::new();
        client_phase = 7;
        while let Some(mut data) = stream.recv_data().await? {
            anyhow::ensure!(
                down.len() + data.remaining() <= 128,
                "fixture downlink bound"
            );
            down.extend_from_slice(&data.copy_to_bytes(data.remaining()));
        }
        client_phase = 8;
        Ok((true, down == DOWN, None))
    })
    .await;
    let operation_state = match &operation {
        Err(_) => "work_timeout",
        Ok(Err(_)) => "work_returned_error",
        Ok(Ok(_)) => "work_returned_ok",
    };
    let operation_handshake = operation
        .as_ref()
        .ok()
        .and_then(|r| r.as_ref().ok())
        .map(|r| r.0);
    let operation_marker = operation
        .as_ref()
        .ok()
        .and_then(|r| r.as_ref().ok())
        .map(|r| r.1);
    let server_phase_at_work_end = server_phase.load(Ordering::Relaxed);
    let client_connections_at_work_end = client.open_connections();
    let server_connections_at_work_end = server.open_connections();
    let mut tasks_drained = false;
    let mut direct_results_observed = 0usize;
    let mut client_idle_entered = false;
    let mut client_idle_completed = false;
    let mut server_idle_entered = false;
    let mut server_idle_completed = false;
    let cleanup_deadline = tokio::time::Instant::now() + CLEANUP;
    endpoints.close();
    tasks.abort_all();
    // This exterior Option retains handles even if timeout drops its borrowed
    // cleanup future. Capture only after direct tasks are drained, so no
    // application owner can race a new Connecting spawn with role capture.
    let mut drivers = None;
    let cleanup = tokio::time::timeout_at(cleanup_deadline, async {
        let mut first = None;
        while let Some(result) = tasks.join_next().await {
            direct_results_observed += 1;
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    if first.is_none() {
                        first = Some(error);
                    }
                }
                Err(error) if error.is_cancelled() => {}
                Err(_) => {
                    if first.is_none() {
                        first = Some(anyhow!("fixture task failed"));
                    }
                }
            }
        }
        tasks_drained = true;
        let drivers = drivers.insert(FixtureDrivers::new(
            &endpoints.client_runtime,
            &endpoints.server_runtime,
        ));
        // Once all app ConnectionRefs are gone, abort/await the same captured
        // connection drivers. Their actual State Drop emits Drained; keep the
        // endpoint drivers active until those events empty the real maps.
        drivers.abort_connections();
        let failure = drivers.join_connections().await;
        if first.is_none() {
            first = failure;
        }
        client_idle_entered = true;
        client.wait_idle().await;
        client_idle_completed = true;
        server_idle_entered = true;
        server.wait_idle().await;
        server_idle_completed = true;
        let maps_empty = client.open_connections() == 0 && server.open_connections() == 0;
        drivers.abort_endpoints();
        let failure = drivers.join_endpoints().await;
        if first.is_none() {
            first = failure;
        }
        let ownership_valid = !drivers.client.invalid
            && !drivers.server.invalid
            && !endpoints.client_runtime.invalid()
            && !endpoints.server_runtime.invalid()
            && drivers.connection_handles == 2
            && drivers.connections_joined == 2
            && drivers.endpoint_handles == 2
            && drivers.endpoints_joined == 2;
        if first.is_none() && (!maps_empty || !ownership_valid) {
            first = Some(anyhow!("fixture Quinn ownership refused"));
        }
        if let Some(error) = first {
            return Err(error);
        }
        Ok::<_, anyhow::Error>(())
    })
    .await;
    // Emit only after the original cleanup attempt, before its existing
    // assertion can mask the independent work result. No error is formatted.
    eprintln!(
        "configured_anchor_exchange_observation={}",
        serde_json::json!({
            "work_state": operation_state,
            "client_phase_at_work_end": client_phase,
            "server_phase_at_work_end": server_phase_at_work_end,
            "work_handshake_accepted": operation_handshake,
            "work_marker_received": operation_marker,
            "authorized_requests": requests.load(Ordering::Relaxed),
            "client_connections_at_work_end": client_connections_at_work_end,
            "server_connections_at_work_end": server_connections_at_work_end,
            "direct_results_observed": direct_results_observed,
            "tasks_drained": tasks_drained,
            "client_idle_entered": client_idle_entered,
            "client_idle_completed": client_idle_completed,
            "server_idle_entered": server_idle_entered,
            "server_idle_completed": server_idle_completed,
            "client_connections_after_cleanup": client.open_connections(),
            "server_connections_after_cleanup": server.open_connections(),
            "cleanup_deadline_elapsed": cleanup.is_err(),
            "cleanup_returned_error": matches!(&cleanup, Ok(Err(_))),
            "cleanup_confirmed": matches!(&cleanup, Ok(Ok(()))),
            "runtime_connection_handles": drivers.as_ref().map_or(0, |d| d.connection_handles),
            "runtime_connections_joined": drivers.as_ref().map_or(0, |d| d.connections_joined),
            "runtime_endpoint_handles": drivers.as_ref().map_or(0, |d| d.endpoint_handles),
            "runtime_endpoints_joined": drivers.as_ref().map_or(0, |d| d.endpoints_joined),
            "runtime_spawn_binding_refused": endpoints.client_runtime.invalid()
                || endpoints.server_runtime.invalid(),
        })
    );
    cleanup.context("fixture cleanup deadline")??;
    let (handshake_accepted, marker_received, refusal_crypto_code) =
        operation.context("fixture work deadline")??;
    Ok(Exchange {
        handshake_accepted,
        refusal_crypto_code,
        authorized_requests: requests.load(Ordering::Relaxed),
        marker_received,
        direct_cleanup_confirmed: true,
    })
}

fn assert_exchange(result: Exchange, accepted: bool) {
    assert!(
        result.direct_cleanup_confirmed,
        "owned direct cleanup must be confirmed"
    );
    assert_eq!(
        result.handshake_accepted, accepted,
        "real verifier handshake outcome"
    );
    assert_eq!(
        result.refusal_crypto_code.is_some(),
        !accepted,
        "TLS alert required for refusal"
    );
    assert_eq!(
        result.authorized_requests,
        usize::from(accepted),
        "authenticated H3 request count"
    );
    assert_eq!(
        result.marker_received, accepted,
        "bidirectional marker outcome"
    );
}

#[test]
fn omitted_trust_policy_preserves_legacy_and_roundtrips_explicit_mode() {
    let source = "server = '127.0.0.1:8443'\nauth_token = ''\n";
    let old: RelaySettings = toml::from_str(source).unwrap();
    assert_eq!(
        old.masque_trust_mode,
        MasqueTrustMode::SystemAndConfiguredCa
    );
    assert_eq!(
        RelaySettings::default().masque_trust_mode,
        old.masque_trust_mode
    );
    assert!(!toml::to_string(&old).unwrap().contains("masque_trust_mode"));
    let explicit: RelaySettings = toml::from_str(&format!(
        "{source}masque_trust_mode = 'configured_ca_only'\nmasque_ca_cert = 'owned-public-ca.pem'\n"
    ))
    .unwrap();
    assert!(explicit.validate_inner_tls_transport().is_ok());
    let encoded = toml::to_string(&explicit).unwrap();
    let decoded: RelaySettings = toml::from_str(&encoded).unwrap();
    assert_eq!(decoded.masque_trust_mode, MasqueTrustMode::ConfiguredCaOnly);
}

#[test]
fn configured_only_missing_empty_or_unusable_anchor_refuses_before_config() {
    for ca in [None, Some(Path::new(""))] {
        let settings = settings(ca, MasqueTrustMode::ConfiguredCaOnly);
        assert!(settings.validate_inner_tls_transport().is_err());
        assert!(production_config(&settings).is_err());
    }
    let dir = tempfile::tempdir().unwrap();
    for (name, contents) in [
        ("empty.pem", b"".as_slice()),
        ("invalid.pem", b"not a certificate".as_slice()),
        (
            "truncated.pem",
            b"-----BEGIN CERTIFICATE-----\nAQID\n".as_slice(),
        ),
        (
            "noncert.pem",
            b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n".as_slice(),
        ),
    ] {
        let path = dir.path().join(name);
        std::fs::write(&path, contents).unwrap();
        let settings = settings(Some(&path), MasqueTrustMode::ConfiguredCaOnly);
        assert!(
            production_config(&settings).is_err(),
            "unusable anchor refused"
        );
    }
    let path = dir.path().join("large.pem");
    let file = std::fs::File::create(&path).unwrap();
    file.set_len(CONFIGURED_CA_BYTE_CAP + 1).unwrap();
    assert!(production_config(&settings(Some(&path), MasqueTrustMode::ConfiguredCaOnly)).is_err());
    assert!(production_config(&settings(
        Some(dir.path()),
        MasqueTrustMode::ConfiguredCaOnly
    ))
    .is_err());
}

#[tokio::test]
async fn configured_anchor_factory_accepts_own_signer_and_refuses_disjoint_signer() {
    let signer = Signer::new().unwrap();
    let unrelated = Signer::new().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("public-ca.pem");
    std::fs::write(&path, signer.ca.pem()).unwrap();
    let settings = settings(Some(&path), MasqueTrustMode::ConfiguredCaOnly);
    assert_exchange(
        exchange(production_config(&settings).unwrap(), &signer)
            .await
            .unwrap(),
        true,
    );
    assert_exchange(
        exchange(production_config(&settings).unwrap(), &unrelated)
            .await
            .unwrap(),
        false,
    );
}

#[tokio::test]
async fn configured_anchor_excludes_owned_platform_signer_using_real_verifier() {
    let configured = Signer::new().unwrap();
    let platform = Signer::new().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("public-ca.pem");
    std::fs::write(&path, configured.ca.pem()).unwrap();
    for (mode, expected_calls, expected_handshake) in [
        (MasqueTrustMode::SystemAndConfiguredCa, 1, true),
        (MasqueTrustMode::ConfiguredCaOnly, 0, false),
    ] {
        let settings = settings(Some(&path), mode);
        let native_calls = AtomicUsize::new(0);
        // The owned callback models platform root input only. The production
        // policy function and real Rustls/QUIC/H3 verifier remain unchanged.
        let roots = masque_roots_with(&settings, |ca| {
            native_calls.fetch_add(1, Ordering::Relaxed);
            anyhow::ensure!(ca == Some(path.as_path()), "legacy effective CA");
            let mut roots = rustls::RootCertStore::empty();
            roots.add(configured.ca.der().clone())?;
            roots.add(platform.ca.der().clone())?;
            Ok(roots)
        })
        .unwrap();
        let authority = super::super::relay_transport_authority(&settings).unwrap();
        let config = rustls_quic_client_config_from_roots(&settings, &authority, roots).unwrap();
        let result = exchange(config, &platform).await.unwrap();
        assert_exchange(result, expected_handshake);
        assert_eq!(native_calls.load(Ordering::Relaxed), expected_calls);
    }
}

#[tokio::test]
async fn legacy_configured_ca_still_verifies_and_rejects_disjoint_signer() {
    let signer = Signer::new().unwrap();
    let unrelated = Signer::new().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy-public-ca.pem");
    std::fs::write(&path, signer.ca.pem()).unwrap();
    let settings = settings(Some(&path), MasqueTrustMode::SystemAndConfiguredCa);
    assert_exchange(
        exchange(production_config(&settings).unwrap(), &signer)
            .await
            .unwrap(),
        true,
    );
    assert_exchange(
        exchange(production_config(&settings).unwrap(), &unrelated)
            .await
            .unwrap(),
        false,
    );
}

#[tokio::test]
async fn fresh_config_reads_replaced_public_ca_without_shared_trust_epoch() {
    let first = Signer::new().unwrap();
    let second = Signer::new().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fresh-public-ca.pem");
    std::fs::write(&path, first.ca.pem()).unwrap();
    let settings = settings(Some(&path), MasqueTrustMode::ConfiguredCaOnly);
    assert_exchange(
        exchange(production_config(&settings).unwrap(), &first)
            .await
            .unwrap(),
        true,
    );
    std::fs::write(&path, second.ca.pem()).unwrap();
    assert_exchange(
        exchange(production_config(&settings).unwrap(), &second)
            .await
            .unwrap(),
        true,
    );
    assert_exchange(
        exchange(production_config(&settings).unwrap(), &first)
            .await
            .unwrap(),
        false,
    );
}

#[tokio::test]
async fn masque_ca_precedes_general_ca_and_general_fallback_remains_usable() {
    let general = Signer::new().unwrap();
    let masque = Signer::new().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let general_path = dir.path().join("general.pem");
    let masque_path = dir.path().join("masque.pem");
    std::fs::write(&general_path, general.ca.pem()).unwrap();
    std::fs::write(&masque_path, masque.ca.pem()).unwrap();
    let mut settings = settings(Some(&masque_path), MasqueTrustMode::ConfiguredCaOnly);
    settings.ca_cert = Some(general_path);
    assert_exchange(
        exchange(production_config(&settings).unwrap(), &masque)
            .await
            .unwrap(),
        true,
    );
    assert_exchange(
        exchange(production_config(&settings).unwrap(), &general)
            .await
            .unwrap(),
        false,
    );
    settings.masque_ca_cert = None;
    assert_exchange(
        exchange(production_config(&settings).unwrap(), &general)
            .await
            .unwrap(),
        true,
    );
}

#[cfg(not(feature = "chrome-like-quic"))]
#[tokio::test]
async fn featureless_chrome_fallback_keeps_configured_only_verification() {
    let signer = Signer::new().unwrap();
    let unrelated = Signer::new().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("public-ca.pem");
    std::fs::write(&path, signer.ca.pem()).unwrap();
    let mut settings = settings(Some(&path), MasqueTrustMode::ConfiguredCaOnly);
    settings.tls_backend = RelayTlsBackend::ChromeLikeExperimental;
    assert_exchange(
        exchange(production_config(&settings).unwrap(), &signer)
            .await
            .unwrap(),
        true,
    );
    assert_exchange(
        exchange(production_config(&settings).unwrap(), &unrelated)
            .await
            .unwrap(),
        false,
    );
}

#[cfg(feature = "chrome-like-quic")]
#[tokio::test]
async fn direct_chrome_ca_file_verifies_without_a_rustls_fallback_surrogate() {
    let signer = Signer::new().unwrap();
    let unrelated = Signer::new().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("public-ca.pem");
    std::fs::write(&path, signer.ca.pem()).unwrap();
    // Direct backend construction ensures a fallback cannot fake Chrome PASS.
    // No ECH is pinned, so the config offers ECH GREASE as before.
    let settings = RelaySettings::default();
    let config = chrome_quic_client_config(
        &settings,
        Some(&path),
        MasqueTrustMode::ConfiguredCaOnly,
        true,
    )
    .unwrap();
    assert_exchange(exchange(config, &signer).await.unwrap(), true);
    let config = chrome_quic_client_config(
        &settings,
        Some(&path),
        MasqueTrustMode::ConfiguredCaOnly,
        true,
    )
    .unwrap();
    assert_exchange(exchange(config, &unrelated).await.unwrap(), false);
}
