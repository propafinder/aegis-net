//! Authenticated TLS 1.3 byte channel, independent of the outer CDN TLS.
//!
//! This module uses only explicit trust roots and never exports traffic keys.
//! Certificate provisioning and fleet-wide live revocation are separate concerns.

#[cfg(feature = "device-enrollment")]
pub mod enrollment;
#[cfg(feature = "device-enrollment")]
pub mod enrollment_tls;
#[cfg(feature = "device-enrollment")]
pub mod enrollment_wire;
pub mod grpc_io;
pub mod registry;
pub use registry::{AuthorizationLease, RegistryWatcher};
pub mod datagram;
pub mod poisson_control;
pub mod poisson_insertion;
pub mod policy_ack;
pub mod private_control;
pub mod relay_shaping;

use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::{self, Read};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use zeroize::Zeroizing;

pub const GRPC_PATH: &str = "/tunnel.v1.Channel/Connect";
const MAX_CREDENTIAL_BYTES: u64 = 1024 * 1024;
const MAX_OPEN_BYTES: usize = 1024;

/// Authentication outcomes that may be charged to an already established
/// end-client identity. I/O error kinds or error text alone are not auth proof.
#[derive(Debug, thiserror::Error)]
pub enum AuthenticationFailure {
    #[error("inner TLS authentication timed out")]
    Timeout,
    #[error("inner TLS device certificate missing")]
    MissingCertificate,
    #[error("inner TLS device is not allowed")]
    DeviceNotAllowed,
    #[error("inner TLS device certificate rejected")]
    CertificateRejected(#[source] io::Error),
}

impl AuthenticationFailure {
    pub fn from_io(error: &io::Error) -> Option<&Self> {
        error.get_ref()?.downcast_ref()
    }
}

fn classify_certificate_failure(error: io::Error) -> io::Error {
    let rejected = matches!(
        error
            .get_ref()
            .and_then(|source| source.downcast_ref::<rustls::Error>()),
        Some(rustls::Error::NoCertificatesPresented | rustls::Error::InvalidCertificate(_))
    );
    if rejected {
        io::Error::new(
            error.kind(),
            AuthenticationFailure::CertificateRejected(error),
        )
    } else {
        error
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientSettings {
    pub server_name: String,
    pub server_ca: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSettings {
    pub cert: PathBuf,
    pub key: PathBuf,
    pub client_ca: PathBuf,
    /// SHA-256 of each permitted device's DER leaf certificate. No shared secret.
    #[serde(default)]
    pub allowed_client_sha256: Vec<String>,
    /// Operator-managed device lifecycle; mutually exclusive with static pins.
    #[serde(default)]
    pub device_registry: Option<PathBuf>,
    #[serde(default = "default_handshake_timeout_ms")]
    pub handshake_timeout_ms: u64,
    #[serde(default = "default_idle_timeout_ms")]
    pub idle_timeout_ms: u64,
    #[serde(default)]
    pub admission: AdmissionLimits,
}

/// Separate bounded budgets for device authentication and authorized channels.
/// A peer identity is the direct client or a verified forwarded client, never
/// an untrusted header. Missing identities share a bounded unknown bucket.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdmissionLimits {
    pub max_handshakes: usize,
    pub max_sessions: usize,
    pub max_handshakes_per_peer: usize,
    pub max_sessions_per_peer: usize,
}

impl Default for AdmissionLimits {
    fn default() -> Self {
        Self {
            max_handshakes: 128,
            max_sessions: 1024,
            max_handshakes_per_peer: 16,
            max_sessions_per_peer: 128,
        }
    }
}

#[derive(Clone)]
struct AdmissionPool {
    permits: Arc<tokio::sync::Semaphore>,
    peers: Arc<std::sync::Mutex<HashMap<Option<IpAddr>, usize>>>,
    per_peer: usize,
}

pub struct AdmissionPermit {
    _permit: tokio::sync::OwnedSemaphorePermit,
    peers: Arc<std::sync::Mutex<HashMap<Option<IpAddr>, usize>>>,
    peer: Option<IpAddr>,
}

impl AdmissionPool {
    fn new(total: usize, per_peer: usize) -> Self {
        Self {
            permits: Arc::new(tokio::sync::Semaphore::new(total)),
            peers: Arc::new(std::sync::Mutex::new(HashMap::new())),
            per_peer,
        }
    }

    fn acquire(&self, peer: Option<IpAddr>) -> io::Result<AdmissionPermit> {
        let permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| capacity())?;
        let mut peers = self.peers.lock().unwrap_or_else(|e| e.into_inner());
        let count = peers.entry(peer).or_default();
        if *count >= self.per_peer {
            return Err(capacity());
        }
        *count += 1;
        Ok(AdmissionPermit {
            _permit: permit,
            peers: self.peers.clone(),
            peer,
        })
    }
}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        let mut peers = self.peers.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = peers.get_mut(&self.peer) {
            *count -= 1;
            if *count == 0 {
                peers.remove(&self.peer);
            }
        }
    }
}

fn capacity() -> io::Error {
    io::Error::new(
        io::ErrorKind::WouldBlock,
        "secure channel capacity exhausted",
    )
}

fn default_handshake_timeout_ms() -> u64 {
    5_000
}

fn default_idle_timeout_ms() -> u64 {
    60_000
}

impl ClientSettings {
    pub fn resolve_paths(&mut self, base: &Path) {
        for path in [&mut self.server_ca, &mut self.cert, &mut self.key] {
            if path.is_relative() {
                *path = base.join(&*path);
            }
        }
    }
}

impl ServerSettings {
    pub fn resolve_paths(&mut self, base: &Path) {
        for path in [&mut self.client_ca, &mut self.cert, &mut self.key] {
            if path.is_relative() {
                *path = base.join(&*path);
            }
        }
        if let Some(path) = &mut self.device_registry {
            if path.is_relative() {
                *path = base.join(&*path);
            }
        }
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn credential(path: &Path, private: bool) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        };
        crate::windows_file::reject_reparse_ancestry(path)?;
        options
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    #[cfg(windows)]
    if private {
        crate::windows_file::validate_private(&file, true)?;
    }
    if !metadata.is_file() || metadata.len() > MAX_CREDENTIAL_BYTES {
        return Err(invalid(
            "inner TLS credential must be a bounded regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid reads the calling process's effective uid.
        let effective_uid = unsafe { libc::geteuid() };
        if metadata.uid() != 0 && metadata.uid() != effective_uid {
            return Err(invalid(
                "inner TLS credential must be owned by root or the service user",
            ));
        }
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(invalid(
                "inner TLS credentials must not be writable by group or others",
            ));
        }
        if private && metadata.permissions().mode() & 0o077 != 0 {
            return Err(invalid(
                "inner TLS private key must deny group and other access",
            ));
        }
    }
    let _ = private;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_CREDENTIAL_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CREDENTIAL_BYTES {
        return Err(invalid("inner TLS credential exceeds size limit"));
    }
    Ok(bytes)
}

fn certificates(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    let bytes = credential(path, false)?;
    certificates_from_pem(&bytes)
}

fn certificates_from_pem(bytes: &[u8]) -> io::Result<Vec<CertificateDer<'static>>> {
    if bytes.len() as u64 > MAX_CREDENTIAL_BYTES {
        return Err(invalid("inner TLS certificate chain exceeds size limit"));
    }
    let certs = CertificateDer::pem_slice_iter(bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid("invalid inner TLS certificate PEM"))?;
    if certs.is_empty() {
        return Err(invalid("empty inner TLS certificate chain"));
    }
    Ok(certs)
}

fn key(path: &Path) -> io::Result<PrivateKeyDer<'static>> {
    key_from_pem(&credential(path, true)?)
}

/// Reuse the enrolled inner-TLS credential's protected file checks when the
/// direct QUIC origin requires a client certificate before exposing H3.
/// The inner channel still performs its own registry and lease authorization.
pub fn enrolled_quic_client_identity(
    settings: &ClientSettings,
) -> io::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    Ok((certificates(&settings.cert)?, key(&settings.key)?))
}

fn key_from_pem(bytes: &[u8]) -> io::Result<PrivateKeyDer<'static>> {
    if bytes.len() as u64 > MAX_CREDENTIAL_BYTES {
        return Err(invalid("inner TLS private key exceeds size limit"));
    }
    PrivateKeyDer::from_pem_slice(bytes).map_err(|_| invalid("invalid inner TLS private key PEM"))
}

pub fn load_trust_roots(path: &Path) -> io::Result<RootCertStore> {
    trust_roots_from_pem(&credential(path, false)?)
}

/// Parse trust roots from bytes retained by an independently admitted owner.
/// This never reopens a mutable pathname.
pub fn trust_roots_from_pem(bytes: &[u8]) -> io::Result<RootCertStore> {
    if bytes.len() as u64 > MAX_CREDENTIAL_BYTES {
        return Err(invalid("inner TLS trust roots exceed size limit"));
    }
    let mut roots = RootCertStore::empty();
    for cert in certificates_from_pem(bytes)? {
        roots
            .add(cert)
            .map_err(|_| invalid("invalid inner TLS trust root"))?;
    }
    Ok(roots)
}

/// Public certificate-chain identity using the same bounded trusted reader as
/// TLS configuration. Does not load or export private keys.
pub fn public_certificate_chain_sha256(path: &Path) -> io::Result<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(b"aegis.public-certificate-chain.v1\0");
    for cert in certificates(path)? {
        hash.update((cert.len() as u64).to_be_bytes());
        hash.update(cert.as_ref());
    }
    Ok(hash.finalize().into())
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites = vec![
        rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
    ];
    provider.kx_groups = vec![rustls::crypto::ring::kx_group::X25519];
    Arc::new(provider)
}

#[derive(Clone)]
pub struct Client {
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
}

impl Client {
    pub fn load(settings: &ClientSettings) -> io::Result<Self> {
        let server_name = ServerName::try_from(settings.server_name.clone())
            .map_err(|_| invalid("invalid inner TLS server name"))?;
        let mut config = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| invalid("inner TLS 1.3 unavailable"))?
            .with_root_certificates(load_trust_roots(&settings.server_ca)?)
            .with_client_auth_cert(certificates(&settings.cert)?, key(&settings.key)?)
            .map_err(|_| invalid("invalid inner TLS client identity"))?;
        config.resumption = rustls::client::Resumption::disabled();
        config.enable_early_data = false;
        config.key_log = Arc::new(rustls::NoKeyLog);
        Ok(Self {
            config: Arc::new(config),
            server_name,
        })
    }

    /// Build the existing inner TLS client from one caller-held file snapshot.
    /// File custody and issuance binding remain the caller's responsibility.
    pub fn from_captured_pem(
        settings: &ClientSettings,
        roots_pem: &[u8],
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> io::Result<Self> {
        if [roots_pem, cert_pem, key_pem]
            .iter()
            .any(|bytes| bytes.len() as u64 > MAX_CREDENTIAL_BYTES)
        {
            return Err(invalid("inner TLS captured credential exceeds size limit"));
        }
        let server_name = ServerName::try_from(settings.server_name.clone())
            .map_err(|_| invalid("invalid inner TLS server name"))?;
        let mut config = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| invalid("inner TLS 1.3 unavailable"))?
            .with_root_certificates(trust_roots_from_pem(roots_pem)?)
            .with_client_auth_cert(certificates_from_pem(cert_pem)?, key_from_pem(key_pem)?)
            .map_err(|_| invalid("invalid inner TLS client identity"))?;
        config.resumption = rustls::client::Resumption::disabled();
        config.enable_early_data = false;
        config.key_log = Arc::new(rustls::NoKeyLog);
        Ok(Self {
            config: Arc::new(config),
            server_name,
        })
    }

    /// Caller owns a bounded establishment deadline including carrier setup.
    pub async fn connect<S>(&self, carrier: S) -> io::Result<tokio_rustls::client::TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        TlsConnector::from(self.config.clone())
            .connect(self.server_name.clone(), carrier)
            .await
    }
}

#[derive(Clone)]
pub struct Server {
    config: Arc<ServerConfig>,
    allowed_clients: Arc<HashSet<[u8; 32]>>,
    timeout: Duration,
    idle_timeout: Duration,
    handshakes: AdmissionPool,
    sessions: AdmissionPool,
    registry: Option<registry::RuntimeRegistry>,
}

impl Server {
    pub fn load(settings: &ServerSettings) -> io::Result<Self> {
        Self::load_with_registry_reader(settings, registry::RuntimeRegistry::load)
    }

    /// Relay startup may overlap an operator's durable registry publication.
    /// This bounded blocking API retries only that verified registry read;
    /// callers on async executors must invoke it through spawn_blocking.
    pub fn load_for_startup(settings: &ServerSettings) -> io::Result<Self> {
        Self::load_with_registry_reader(settings, registry::RuntimeRegistry::load_for_startup)
    }

    fn load_with_registry_reader(
        settings: &ServerSettings,
        read_registry: impl FnOnce(&Path) -> io::Result<registry::RuntimeRegistry>,
    ) -> io::Result<Self> {
        if !(1..=60_000).contains(&settings.handshake_timeout_ms) {
            return Err(invalid("inner TLS handshake timeout must be 1..60000ms"));
        }
        if !(1..=3_600_000).contains(&settings.idle_timeout_ms) {
            return Err(invalid("inner TLS idle timeout must be 1..3600000ms"));
        }
        let limits = &settings.admission;
        if !(1..=4096).contains(&limits.max_handshakes)
            || !(1..=65_536).contains(&limits.max_sessions)
            || !(1..=limits.max_handshakes).contains(&limits.max_handshakes_per_peer)
            || !(1..=limits.max_sessions).contains(&limits.max_sessions_per_peer)
        {
            return Err(invalid("invalid inner TLS admission limits"));
        }
        if (settings.allowed_client_sha256.is_empty() && settings.device_registry.is_none())
            || settings.allowed_client_sha256.len() > 4096
        {
            return Err(invalid(
                "inner TLS requires 1..4096 allowed device certificates",
            ));
        }
        if settings.device_registry.is_some() && !settings.allowed_client_sha256.is_empty() {
            return Err(invalid(
                "inner TLS device registry and static device pins are mutually exclusive",
            ));
        }
        let registry = settings
            .device_registry
            .as_deref()
            .map(read_registry)
            .transpose()?;
        let mut allowed_clients = HashSet::new();
        for fingerprint in &settings.allowed_client_sha256 {
            let mut bytes = [0u8; 32];
            hex::decode_to_slice(fingerprint, &mut bytes)
                .map_err(|_| invalid("invalid allowed device certificate SHA-256"))?;
            if !allowed_clients.insert(bytes) {
                return Err(invalid("duplicate allowed device certificate"));
            }
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(load_trust_roots(&settings.client_ca)?),
            provider(),
        )
        .build()
        .map_err(|_| invalid("invalid inner TLS client verifier"))?;
        let mut config = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| invalid("inner TLS 1.3 unavailable"))?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates(&settings.cert)?, key(&settings.key)?)
            .map_err(|_| invalid("invalid inner TLS server identity"))?;
        config.send_tls13_tickets = 0;
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        config.max_early_data_size = 0;
        config.key_log = Arc::new(rustls::NoKeyLog);
        Ok(Self {
            config: Arc::new(config),
            allowed_clients: Arc::new(allowed_clients),
            timeout: Duration::from_millis(settings.handshake_timeout_ms),
            idle_timeout: Duration::from_millis(settings.idle_timeout_ms),
            handshakes: AdmissionPool::new(limits.max_handshakes, limits.max_handshakes_per_peer),
            sessions: AdmissionPool::new(limits.max_sessions, limits.max_sessions_per_peer),
            registry,
        })
    }

    pub fn handshake_timeout(&self) -> Duration {
        self.timeout
    }
    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    pub fn try_acquire(&self) -> io::Result<tokio::sync::OwnedSemaphorePermit> {
        self.handshakes
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| capacity())
    }

    pub fn try_acquire_handshake(&self, peer: Option<IpAddr>) -> io::Result<AdmissionPermit> {
        self.handshakes.acquire(peer)
    }

    /// Call only after device TLS and registry/allowlist authorization succeed.
    pub fn try_acquire_session(&self, peer: Option<IpAddr>) -> io::Result<AdmissionPermit> {
        self.sessions.acquire(peer)
    }

    pub async fn accept<S>(&self, carrier: S) -> io::Result<tokio_rustls::server::TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if self.registry.is_some() {
            return Err(invalid(
                "dynamic device authorization requires accept_with_lease",
            ));
        }
        self.accept_with_lease(carrier)
            .await
            .map(|(stream, _)| stream)
    }

    pub fn start_registry_watcher(&self) -> Option<RegistryWatcher> {
        self.registry
            .as_ref()
            .and_then(registry::RuntimeRegistry::start_watcher)
    }

    /// A live authorization-state acknowledgement, never a new disk read.
    pub fn registry_status(&self) -> io::Result<registry::RuntimePolicyStatus> {
        self.registry
            .as_ref()
            .ok_or_else(|| invalid("dynamic registry is required"))?
            .status()
    }

    pub fn has_dynamic_registry(&self) -> bool {
        self.registry.is_some()
    }

    /// Check the current issued leaf before exposing a distinct outer
    /// carrier response. This does not grant a target or allocate a session
    /// lease; the inner TLS handshake repeats the live authorization check.
    pub fn check_current_device_certificate(&self, leaf_der: &[u8]) -> io::Result<()> {
        let fingerprint: [u8; 32] = Sha256::digest(leaf_der).into();
        if let Some(registry) = &self.registry {
            return registry.check_current(fingerprint);
        }
        if self.allowed_clients.contains(&fingerprint) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                AuthenticationFailure::DeviceNotAllowed,
            ))
        }
    }

    pub async fn accept_with_lease<S>(
        &self,
        carrier: S,
    ) -> io::Result<(tokio_rustls::server::TlsStream<S>, AuthorizationLease)>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let deadline = tokio::time::Instant::now() + self.timeout;
        let check_deadline = || {
            if tokio::time::Instant::now() >= deadline {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    AuthenticationFailure::Timeout,
                ))
            } else {
                Ok(())
            }
        };
        check_deadline()?;
        let accepted = tokio::time::timeout_at(
            deadline,
            TlsAcceptor::from(self.config.clone()).accept(carrier),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, AuthenticationFailure::Timeout))?;
        // Tokio polls ready I/O before its timer. A buffered proof completing
        // on a late poll must not become an authorized device channel.
        check_deadline()?;
        let stream = accepted.map_err(classify_certificate_failure)?;
        let leaf = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|chain| chain.first())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    AuthenticationFailure::MissingCertificate,
                )
            })?;
        let fingerprint: [u8; 32] = Sha256::digest(leaf.as_ref()).into();
        if let Some(registry) = &self.registry {
            let lease = registry.lease(fingerprint);
            check_deadline()?;
            let lease = lease?;
            return Ok((stream, lease));
        }
        if !self.allowed_clients.contains(&fingerprint) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                AuthenticationFailure::DeviceNotAllowed,
            ));
        }
        check_deadline()?;
        Ok((stream, AuthorizationLease::static_allowlist()))
    }
}

/// This control message exists only inside the authenticated TLS channel.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    #[default]
    Tcp,
    Udp,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenRequest {
    pub version: u8,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub transport: Transport,
}

impl OpenRequest {
    fn validate(&self) -> io::Result<()> {
        if self.version != 1
            || self.port == 0
            || self.host.is_empty()
            || self.host.len() > 253
            || self
                .host
                .chars()
                .any(|ch| ch.is_whitespace() || ch.is_control())
        {
            return Err(invalid("invalid secure channel open request"));
        }
        Ok(())
    }
}

pub async fn write_open<S: AsyncWrite + Unpin>(
    stream: &mut S,
    request: &OpenRequest,
) -> io::Result<()> {
    request.validate()?;
    let bytes = serde_json::to_vec(request).map_err(io::Error::other)?;
    if bytes.len() > MAX_OPEN_BYTES {
        return Err(invalid("secure channel open request too large"));
    }
    stream.write_u16(bytes.len() as u16).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await
}

pub async fn read_open<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<OpenRequest> {
    let length = stream.read_u16().await? as usize;
    if length == 0 || length > MAX_OPEN_BYTES {
        return Err(invalid("secure channel open request too large"));
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    let request: OpenRequest = serde_json::from_slice(&bytes)
        .map_err(|_| invalid("invalid secure channel open request"))?;
    request.validate()?;
    Ok(request)
}

struct ActivityIo<S> {
    io: S,
    activity: Arc<std::sync::Mutex<tokio::time::Instant>>,
}

impl<S: AsyncRead + Unpin> AsyncRead for ActivityIo<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let before = buffer.filled().len();
        let result = std::pin::Pin::new(&mut self.io).poll_read(cx, buffer);
        if buffer.filled().len() > before {
            *self.activity.lock().unwrap() = tokio::time::Instant::now();
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ActivityIo<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let result = std::pin::Pin::new(&mut self.io).poll_write(cx, bytes);
        if matches!(result, std::task::Poll::Ready(Ok(n)) if n > 0) {
            *self.activity.lock().unwrap() = tokio::time::Instant::now();
        }
        result
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// Bound silent and half-closed sessions without terminating an active transfer.
pub async fn copy_with_idle_timeout<A, B>(
    left: &mut A,
    right: &mut B,
    idle: Duration,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let activity = Arc::new(std::sync::Mutex::new(tokio::time::Instant::now()));
    let mut left = ActivityIo {
        io: left,
        activity: activity.clone(),
    };
    let mut right = ActivityIo {
        io: right,
        activity: activity.clone(),
    };
    let copy = tokio::io::copy_bidirectional(&mut left, &mut right);
    tokio::pin!(copy);
    let mut deadline = tokio::time::Instant::now() + idle;
    loop {
        tokio::select! {
            result = &mut copy => return result,
            _ = tokio::time::sleep_until(deadline) => {
                deadline = *activity.lock().unwrap() + idle;
                if deadline <= tokio::time::Instant::now() {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "secure channel idle timeout"));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
