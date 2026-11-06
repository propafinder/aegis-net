//! B-06 S16b: cfg(test)-only fixture relay for one bounded installed window.
//!
//! It serves the installed fixture identity (the relay material written by
//! `write_installed_fixture`) with aegis-server's secure-session semantics,
//! reusing the test relay's outer TLS, H2 carrier and ACK encoding: outer TLS
//! and H2, then on every stream of the connection (S16h: a session's flows
//! share pooled connections, its ACKs dial their own) its own carrier, inner
//! mutual TLS and one request. A PolicyAck is
//! answered once with the registry's 3 s cap and the inner stream is shut; an
//! Open is terminated here and never dialled. TCP and UDP echo serve the two
//! documentation echo targets (and `probe.test:7` over TCP, the fake-IP
//! path); a DNS answerer for `probe.test` serves the signed upstream over UDP
//! and TCP. Every other target is refused at once with status 1, as secure.rs
//! does for a failed connect. Each event is one JSON line; no key material is
//! ever logged. Nothing here is reachable from a release build.
//!
//! The material holds the device CA but not the device certificate, so the
//! inner TLS mirrors aegis-core's `Server` (TLS 1.3, the same suites and
//! group, the device CA as the only client root) and, instead of a static
//! pin, admits the presented leaf through the enrollment profile check for
//! the fixture device id and pins the first admitted fingerprint.
use crate::{
    test_fixture,
    test_relay::{self, AckReply, ADMISSION_TIMEOUT, MAX_ACK_VALID_MS},
};
use aegis_core::{
    h2_stream::H2Stream,
    secure_channel::{
        self, datagram, enrollment, grpc_io::GrpcIo, policy_ack, registry, OpenRequest, Transport,
    },
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    future::Future,
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicI32, AtomicU64, Ordering},
        Arc, Mutex, PoisonError,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::timeout_at,
};
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
        server::WebPkiClientVerifier,
        RootCertStore,
    },
    TlsAcceptor,
};
use zeroize::Zeroizing;

/// The longest window one run may serve.
pub(crate) const MAX_LIFETIME: Duration = Duration::from_secs(300);
pub(crate) const ECHO_V4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 7);
pub(crate) const ECHO_V6: SocketAddr = SocketAddr::new(
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10)),
    7,
);
/// The one name the DNS answerer knows, and the hostname echo target.
pub(crate) const PROBE_NAME: &str = "probe.test";
pub(crate) const PROBE_TXT: &[u8] = b"aegis-b06-probe";
/// `probe.test` AAAA: the IPv6 echo target.
pub(crate) const PROBE_AAAA: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10);

const ENV_MATERIAL: &str = "AEGIS_B06_RELAY_MATERIAL_DIR";
const ENV_BIND: &str = "AEGIS_B06_RELAY_BIND";
const ENV_LOG: &str = "AEGIS_B06_RELAY_LOG";
const ENV_SECONDS: &str = "AEGIS_B06_RELAY_SECONDS";
/// Exactly what `ReadyTree::write_relay_material` writes, sorted.
const MATERIAL_LEAVES: [&str; 5] = [
    "device-ca.pem",
    "inner-server.key",
    "inner-server.pem",
    "outer-server.key",
    "outer-server.pem",
];
const MAX_MATERIAL_BYTES: u64 = 64 * 1024;
/// Outer TLS, H2, inner TLS and the request must complete within this.
const ESTABLISH: Duration = Duration::from_secs(5);
const MAX_CONNECTIONS: usize = 256;
/// How long aborted connections may take to drop once the window ends.
const CLOSE_BUDGET: Duration = Duration::from_secs(2);
const DNS_TTL: u32 = 60;
const MAX_DNS_MESSAGE: usize = 4096;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The fixture's signed DNS upstream, the only DNS target answered.
pub(crate) fn dns_upstream() -> SocketAddr {
    test_fixture::DNS_UPSTREAM
        .parse()
        .expect("fixture DNS upstream is an address")
}

/// One run's window, from the environment of the ignored entry point.
#[derive(Debug)]
pub(crate) struct RelayConfig {
    pub(crate) material: PathBuf,
    pub(crate) bind: SocketAddr,
    pub(crate) log: PathBuf,
    pub(crate) lifetime: Duration,
}

impl RelayConfig {
    pub(crate) fn from_env() -> Result<Self, String> {
        Self::parse(
            std::env::var_os(ENV_MATERIAL),
            std::env::var_os(ENV_BIND),
            std::env::var_os(ENV_LOG),
            std::env::var_os(ENV_SECONDS),
        )
    }

    /// Absolute material and log paths, one unicast address with a port, and
    /// 1..=300 whole seconds written as plain digits.
    pub(crate) fn parse(
        material: Option<OsString>,
        bind: Option<OsString>,
        log: Option<OsString>,
        seconds: Option<OsString>,
    ) -> Result<Self, String> {
        fn absolute(value: Option<OsString>, name: &str) -> Result<PathBuf, String> {
            let path = PathBuf::from(value.ok_or_else(|| format!("{name} is required"))?);
            if !path.is_absolute() {
                return Err(format!("{name} must be absolute"));
            }
            Ok(path)
        }
        fn text(value: Option<OsString>, name: &str) -> Result<String, String> {
            value
                .ok_or_else(|| format!("{name} is required"))?
                .into_string()
                .map_err(|_| format!("{name} must be UTF-8"))
        }
        let material = absolute(material, ENV_MATERIAL)?;
        let bind: SocketAddr = text(bind, ENV_BIND)?
            .parse()
            .map_err(|_| format!("{ENV_BIND} must be ip:port"))?;
        // An IPv4-mapped IPv6 address is refused outright: std never sets
        // IPV6_V6ONLY and macOS defaults it off, so XNU binds a mapped
        // address as AF_INET, where [::ffff:0.0.0.0] means every interface.
        // The plain IPv4 form names the same single address unambiguously.
        let mapped = matches!(bind.ip(), IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some());
        let broadcast = matches!(bind.ip(), IpAddr::V4(v4) if v4.is_broadcast());
        if mapped
            || broadcast
            || bind.ip().is_unspecified()
            || bind.ip().is_multicast()
            || bind.port() == 0
        {
            return Err(format!(
                "{ENV_BIND} must name one unicast address and a port"
            ));
        }
        let log = absolute(log, ENV_LOG)?;
        let seconds = text(seconds, ENV_SECONDS)?;
        let lifetime = (!seconds.is_empty()
            && seconds.len() <= 3
            && seconds.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| seconds.parse::<u64>().ok())
        .flatten()
        .map(Duration::from_secs)
        .filter(|lifetime| !lifetime.is_zero() && *lifetime <= MAX_LIFETIME)
        .ok_or_else(|| format!("{ENV_SECONDS} must be 1..=300"))?;
        Ok(Self {
            material,
            bind,
            log,
            lifetime,
        })
    }
}

/// The relay's side of the fixture: outer and inner server identities and
/// the device CA. The PEM text it was read from is zeroized on drop.
pub(crate) struct FixtureMaterial {
    outer_cert: CertificateDer<'static>,
    outer_key: PrivateKeyDer<'static>,
    inner_chain: Vec<CertificateDer<'static>>,
    inner_key: PrivateKeyDer<'static>,
    device_ca_pem: String,
}

fn private(meta: &fs::Metadata, directory: bool) -> io::Result<()> {
    let kind = if directory {
        meta.file_type().is_dir()
    } else {
        meta.file_type().is_file()
    };
    // SAFETY: geteuid has no preconditions.
    if !kind || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "relay material must be the caller's private directory and files",
        ));
    }
    Ok(())
}

impl FixtureMaterial {
    /// Read the material directory: absolute, not a symlink, the caller's
    /// and private, holding exactly the five fixture leaves, each a private
    /// regular file of at most 64 KiB opened without following links.
    pub(crate) fn read(dir: &Path) -> io::Result<Self> {
        if !dir.is_absolute() {
            return Err(invalid("relay material directory must be absolute"));
        }
        private(&fs::symlink_metadata(dir)?, true)?;
        let mut leaves = fs::read_dir(dir)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<io::Result<Vec<_>>>()?;
        leaves.sort();
        if leaves
            .iter()
            .map(OsString::as_os_str)
            .ne(MATERIAL_LEAVES.map(OsStr::new))
        {
            return Err(invalid(
                "relay material must hold exactly the five fixture leaves",
            ));
        }
        let read = |leaf: &str| -> io::Result<Zeroizing<Vec<u8>>> {
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(dir.join(leaf))?;
            let meta = file.metadata()?;
            private(&meta, false)?;
            if meta.len() > MAX_MATERIAL_BYTES {
                return Err(invalid("relay material leaf exceeds 64 KiB"));
            }
            let mut bytes = Zeroizing::new(Vec::new());
            file.take(MAX_MATERIAL_BYTES + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 > MAX_MATERIAL_BYTES {
                return Err(invalid("relay material leaf exceeds 64 KiB"));
            }
            Ok(bytes)
        };
        Self::from_pem(
            &read("outer-server.pem")?,
            &read("outer-server.key")?,
            &read("inner-server.pem")?,
            &read("inner-server.key")?,
            &read("device-ca.pem")?,
        )
    }

    pub(crate) fn from_pem(
        outer_cert: &[u8],
        outer_key: &[u8],
        inner_cert: &[u8],
        inner_key: &[u8],
        device_ca: &[u8],
    ) -> io::Result<Self> {
        let certificates = |pem: &[u8]| {
            CertificateDer::pem_slice_iter(pem)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| invalid("relay material certificate PEM invalid"))
        };
        let key = |pem: &[u8]| {
            PrivateKeyDer::from_pem_slice(pem).map_err(|_| invalid("relay material key invalid"))
        };
        let mut outer = certificates(outer_cert)?;
        if outer.len() != 1 {
            return Err(invalid("outer server material must be one certificate"));
        }
        let inner_chain = certificates(inner_cert)?;
        if !(1..=4).contains(&inner_chain.len()) {
            return Err(invalid("inner server chain must be 1..=4 certificates"));
        }
        enrollment::validate_device_ca(device_ca)
            .map_err(|_| invalid("device CA must be one certificate-signing CA"))?;
        let device_ca_pem = std::str::from_utf8(device_ca)
            .map_err(|_| invalid("device CA must be UTF-8 PEM"))?
            .to_owned();
        Ok(Self {
            outer_cert: outer.remove(0),
            outer_key: key(outer_key)?,
            inner_chain,
            inner_key: key(inner_key)?,
            device_ca_pem,
        })
    }
}

/// The inner TLS server as aegis-core builds it, with the device CA as the
/// only client root. Device admission happens after the handshake.
fn inner_acceptor(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    device_ca_pem: &str,
) -> io::Result<TlsAcceptor> {
    let mut roots = RootCertStore::empty();
    for ca in CertificateDer::pem_slice_iter(device_ca_pem.as_bytes()) {
        roots
            .add(ca.map_err(|_| invalid("device CA PEM invalid"))?)
            .map_err(|_| invalid("device CA trust anchor invalid"))?;
    }
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites = vec![
        rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
    ];
    provider.kx_groups = vec![rustls::crypto::ring::kx_group::X25519];
    let provider = Arc::new(provider);
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|_| invalid("device CA verifier invalid"))?;
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| invalid("inner TLS 1.3 unavailable"))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .map_err(|_| invalid("inner server identity invalid"))?;
    config.send_tls13_tickets = 0;
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.max_early_data_size = 0;
    config.key_log = Arc::new(rustls::NoKeyLog);
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// A public DER certificate as one PEM block.
pub(crate) fn certificate_pem(der: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = Vec::with_capacity(der.len().div_ceil(3) * 4);
    for chunk in der.chunks(3) {
        let bytes = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let word = u32::from(bytes[0]) << 16 | u32::from(bytes[1]) << 8 | u32::from(bytes[2]);
        for index in 0..4 {
            encoded.push(if index <= chunk.len() {
                ALPHABET[(word >> (18 - 6 * index)) as usize & 63]
            } else {
                b'='
            });
        }
    }
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in encoded.chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

/// The device an inner handshake presented, as its ACK must name it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AdmittedDevice {
    pub(crate) certificate_sha256: String,
    pub(crate) not_after_unix_secs: u64,
}

impl AdmittedDevice {
    /// What the registry grants this device now: the fixture's issuance and
    /// the 3 s cap.
    fn reply(&self, now: u64) -> AckReply {
        AckReply {
            certificate_sha256: self.certificate_sha256.clone(),
            certificate_not_after_unix_secs: self.not_after_unix_secs,
            policy_not_after_unix_secs: now + 60,
            generation: test_fixture::ISSUED_GENERATION,
            snapshot_sha256: test_fixture::SNAPSHOT_SHA256.into(),
            effective_valid_for_ms: MAX_ACK_VALID_MS,
        }
    }
}

/// Admits only a currently valid fixture-profile device certificate under
/// the device CA, and after the first admission only that same certificate.
pub(crate) struct DeviceGate {
    device_ca_pem: String,
    pinned: Mutex<Option<AdmittedDevice>>,
}

impl DeviceGate {
    pub(crate) fn new(device_ca_pem: String) -> Self {
        Self {
            device_ca_pem,
            pinned: Mutex::new(None),
        }
    }

    /// The admitted device, and whether this admission pinned it.
    pub(crate) fn admit(
        &self,
        leaf: &[u8],
        now: u64,
    ) -> Result<(AdmittedDevice, bool), &'static str> {
        let facts = enrollment::validate_device_certificate_public(
            test_fixture::DEVICE_ID,
            certificate_pem(leaf).as_bytes(),
            self.device_ca_pem.as_bytes(),
            now,
        )
        .map_err(|_| "device_profile_refused")?;
        let certificate_sha256 = sha256_hex(leaf);
        if facts.fingerprint != certificate_sha256 {
            return Err("device_fingerprint_mismatch");
        }
        let device = AdmittedDevice {
            certificate_sha256,
            not_after_unix_secs: facts.not_after_unix_secs,
        };
        let mut pinned = self.pinned.lock().unwrap_or_else(PoisonError::into_inner);
        match pinned.as_ref() {
            Some(first) if *first != device => Err("device_pin_mismatch"),
            Some(_) => Ok((device, false)),
            None => {
                *pinned = Some(device.clone());
                Ok((device, true))
            }
        }
    }
}

/// Outer acceptor, inner mutual-TLS acceptor and device gate.
pub(crate) struct FixtureIdentity {
    outer: TlsAcceptor,
    inner: TlsAcceptor,
    device: DeviceGate,
}

impl FixtureIdentity {
    pub(crate) fn new(material: FixtureMaterial) -> io::Result<Self> {
        let FixtureMaterial {
            outer_cert,
            outer_key,
            inner_chain,
            inner_key,
            device_ca_pem,
        } = material;
        Ok(Self {
            outer: test_relay::outer_acceptor(outer_cert, outer_key)?,
            inner: inner_acceptor(inner_chain, inner_key, &device_ca_pem)?,
            device: DeviceGate::new(device_ca_pem),
        })
    }

    /// The inner handshake, then admission of the device it presented.
    pub(crate) async fn accept_device<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        carrier: S,
    ) -> Result<(tokio_rustls::server::TlsStream<S>, AdmittedDevice, bool), &'static str> {
        let stream = self
            .inner
            .accept(carrier)
            .await
            .map_err(|_| "inner_tls_refused")?;
        let leaf = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|chain| chain.first())
            .ok_or("device_certificate_missing")?
            .as_ref()
            .to_vec();
        let now = registry::unix_now().map_err(|_| "clock_unavailable")?;
        let (device, pinned) = self.device.admit(&leaf, now)?;
        Ok((stream, device, pinned))
    }
}

/// What the relay does with one Open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Route {
    TcpEcho,
    UdpEcho,
    DnsUdp,
    DnsTcp,
    Refused,
}

impl Route {
    fn outcome(self) -> &'static str {
        match self {
            Self::TcpEcho => "tcp_echo",
            Self::UdpEcho => "udp_echo",
            Self::DnsUdp => "dns_udp",
            Self::DnsTcp => "dns_tcp",
            Self::Refused => "refused",
        }
    }
}

/// Echo: TCP and UDP to the two echo targets, and TCP to `probe.test:7`.
/// DNS: TCP and UDP to the signed upstream. Anything else is refused.
pub(crate) fn route(open: &OpenRequest) -> Route {
    let host = open.host.strip_suffix('.').unwrap_or(&open.host);
    let ip = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
        .parse::<IpAddr>()
        .ok();
    let target = |address: SocketAddr| ip == Some(address.ip()) && open.port == address.port();
    let echo_ip = target(ECHO_V4) || target(ECHO_V6);
    let probe =
        ip.is_none() && host.eq_ignore_ascii_case(PROBE_NAME) && open.port == ECHO_V4.port();
    let dns = target(dns_upstream());
    match open.transport {
        Transport::Tcp if echo_ip || probe => Route::TcpEcho,
        Transport::Udp if echo_ip => Route::UdpEcho,
        Transport::Tcp if dns => Route::DnsTcp,
        Transport::Udp if dns => Route::DnsUdp,
        _ => Route::Refused,
    }
}

/// One answered DNS query.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DnsReply {
    pub(crate) response: Vec<u8>,
    pub(crate) qtype: u16,
    pub(crate) outcome: &'static str,
}

/// Answer one standard query with one uncompressed question; records after
/// the question (EDNS) are ignored and none are returned. `probe.test` IN
/// gets its AAAA or TXT record and NODATA for any other type; every other
/// name or class is REFUSED. A malformed query, or a response, gets nothing.
pub(crate) fn probe_dns_answer(query: &[u8]) -> Option<DnsReply> {
    if !(12..=MAX_DNS_MESSAGE).contains(&query.len())
        || query[2] & 0xf8 != 0
        || query[4..6] != [0, 1]
    {
        return None;
    }
    let mut name = Vec::new();
    let mut cursor = 12;
    loop {
        let length = usize::from(*query.get(cursor)?);
        cursor += 1;
        if length == 0 {
            break;
        }
        if length > 63 || cursor + length - 12 > 255 {
            return None;
        }
        if !name.is_empty() {
            name.push(b'.');
        }
        name.extend(query.get(cursor..cursor + length)?.to_ascii_lowercase());
        cursor += length;
    }
    let field = |at: usize| Some(u16::from_be_bytes([*query.get(at)?, *query.get(at + 1)?]));
    let (qtype, qclass) = (field(cursor)?, field(cursor + 2)?);
    let question_end = cursor + 4;
    let probe = name == PROBE_NAME.as_bytes() && qclass == 1;
    let (rcode, record, outcome) = match (probe, qtype) {
        (false, _) => (5, None, "refused_name"),
        (true, 28) => (0, Some(PROBE_AAAA.octets().to_vec()), "answered"),
        (true, 16) => {
            let mut text = vec![PROBE_TXT.len() as u8];
            text.extend_from_slice(PROBE_TXT);
            (0, Some(text), "answered")
        }
        (true, _) => (0, None, "nodata"),
    };
    let mut response = query[..question_end].to_vec();
    // QR, the request's opcode and RD; RA and the rcode; one question only.
    response[2] = 0x80 | (query[2] & 0x79);
    response[3] = 0x80 | rcode;
    response[6..12].fill(0);
    if let Some(data) = record {
        response[7] = 1;
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&qtype.to_be_bytes());
        response.extend_from_slice(&[0, 1]);
        response.extend_from_slice(&DNS_TTL.to_be_bytes());
        response.extend_from_slice(&(data.len() as u16).to_be_bytes());
        response.extend_from_slice(&data);
    }
    Some(DnsReply {
        response,
        qtype,
        outcome,
    })
}

/// One JSON object per line, created fresh and private. Callers pass only
/// addresses, names, counts, outcomes and public fingerprints.
pub(crate) struct JsonLog {
    file: Mutex<File>,
    started: Instant,
}

impl JsonLog {
    pub(crate) fn create(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(invalid("relay log path must be absolute"));
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        Ok(Self {
            file: Mutex::new(file),
            started: Instant::now(),
        })
    }

    pub(crate) fn event(&self, event: &'static str, fields: Value) {
        let mut line = match fields {
            Value::Object(fields) => fields,
            _ => serde_json::Map::new(),
        };
        line.insert("event".into(), event.into());
        line.insert(
            "t_ms".into(),
            u64::try_from(self.started.elapsed().as_millis())
                .unwrap_or(u64::MAX)
                .into(),
        );
        let unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_millis());
        line.insert(
            "unix_ms".into(),
            u64::try_from(unix_ms).unwrap_or(u64::MAX).into(),
        );
        let mut text = serde_json::to_vec(&Value::Object(line)).unwrap_or_default();
        text.push(b'\n');
        let mut file = self.file.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = file.write_all(&text);
    }

    fn sync(&self) {
        let _ = self
            .file
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .sync_all();
    }
}

#[derive(Default)]
struct Counters {
    connections: AtomicU64,
    acks: AtomicU64,
    opens: AtomicU64,
    refused: AtomicU64,
}

/// How one window ended and what it served.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServeSummary {
    pub(crate) reason: &'static str,
    pub(crate) connections: u64,
    pub(crate) acks: u64,
    pub(crate) opens: u64,
    pub(crate) refused: u64,
    /// Connections still live, and aborted, when the window ended.
    pub(crate) aborted: usize,
}

/// Serve `listener` until `lifetime` passes or `stop` yields its reason, on
/// a runtime of this thread; then abort and drop every connection within
/// the close budget and log `all_flows_closed`.
pub(crate) fn serve(
    listener: std::net::TcpListener,
    material: FixtureMaterial,
    log_path: &Path,
    lifetime: Duration,
    stop: impl Future<Output = &'static str>,
) -> io::Result<ServeSummary> {
    if lifetime.is_zero() || lifetime > MAX_LIFETIME {
        return Err(invalid("relay lifetime must be 1..=300 s"));
    }
    let identity = Arc::new(FixtureIdentity::new(material)?);
    let bind = listener.local_addr()?;
    listener.set_nonblocking(true)?;
    let log = Arc::new(JsonLog::create(log_path)?);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let counters = Arc::new(Counters::default());
    let summary = runtime.block_on(async {
        let listener = TcpListener::from_std(listener)?;
        log.event(
            "relay_started",
            json!({"bind": bind.to_string(), "lifetime_s": lifetime.as_secs()}),
        );
        let window = tokio::time::sleep(lifetime);
        tokio::pin!(window, stop);
        let mut connections = JoinSet::new();
        let mut next = 0u64;
        let reason = loop {
            tokio::select! {
                biased;
                () = &mut window => break "lifetime_reached",
                reason = &mut stop => break reason,
                accepted = listener.accept() => {
                    while connections.try_join_next().is_some() {}
                    let Ok((tcp, peer)) = accepted else { continue };
                    next += 1;
                    if connections.len() >= MAX_CONNECTIONS {
                        log.event(
                            "connection_refused",
                            json!({"conn": next, "peer": peer.to_string(), "reason": "capacity"}),
                        );
                        continue;
                    }
                    counters.connections.fetch_add(1, Ordering::Relaxed);
                    connections.spawn(connection(
                        tcp,
                        peer,
                        next,
                        identity.clone(),
                        log.clone(),
                        counters.clone(),
                    ));
                }
            }
        };
        drop(listener);
        log.event("stop", json!({"reason": reason}));
        while connections.try_join_next().is_some() {}
        let aborted = connections.len();
        connections.abort_all();
        let drained = tokio::time::timeout(CLOSE_BUDGET, async {
            while connections.join_next().await.is_some() {}
        })
        .await;
        if drained.is_err() {
            log.event("flows_not_closed", json!({"left": connections.len()}));
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "connections outlived the close budget",
            ));
        }
        log.event("all_flows_closed", json!({"aborted": aborted}));
        Ok(ServeSummary {
            reason,
            connections: counters.connections.load(Ordering::Relaxed),
            acks: counters.acks.load(Ordering::Relaxed),
            opens: counters.opens.load(Ordering::Relaxed),
            refused: counters.refused.load(Ordering::Relaxed),
            aborted,
        })
    });
    drop(runtime);
    log.sync();
    summary
}

async fn connection(
    tcp: TcpStream,
    peer: SocketAddr,
    conn: u64,
    identity: Arc<FixtureIdentity>,
    log: Arc<JsonLog>,
    counters: Arc<Counters>,
) {
    log.event("accepted", json!({"conn": conn, "peer": peer.to_string()}));
    let reason = carry(tcp, conn, identity, log.clone(), counters).await;
    log.event("close", json!({"conn": conn, "reason": reason}));
}

/// One connection: every stream task, and the H2 driver, live in this
/// future, so aborting its task closes all of them. Every stream is its own
/// secure session (session/grpc.rs:240-276). As the https_bridge Activity
/// rule, the connection idles out `ADMISSION_TIMEOUT` after its last stream
/// ended (before its first, at the establishment deadline) and is then
/// dropped without GOAWAY; the close reason is its last stream's outcome.
async fn carry(
    tcp: TcpStream,
    conn: u64,
    identity: Arc<FixtureIdentity>,
    log: Arc<JsonLog>,
    counters: Arc<Counters>,
) -> &'static str {
    let deadline = tokio::time::Instant::now() + ESTABLISH;
    let Ok(Ok(outer)) = timeout_at(deadline, identity.outer.accept(tcp)).await else {
        return "outer_tls_failed";
    };
    // aegis-server's H2 limits (session/grpc.rs:203-216).
    let handshake = test_relay::pool::builder().handshake::<_, bytes::Bytes>(outer);
    let Ok(Ok(mut h2)) = timeout_at(deadline, handshake).await else {
        return "h2_failed";
    };
    let mut streams: JoinSet<&'static str> = JoinSet::new();
    let mut idle_at = deadline;
    let mut outcome = "no_request";
    loop {
        tokio::select! {
            accepted = h2.accept() => match accepted {
                Some(Ok((request, respond))) => {
                    // grpc.rs:260 and secure.rs:131-137: each stream's own
                    // establishment deadline from its accept.
                    let deadline = tokio::time::Instant::now() + ESTABLISH;
                    streams.spawn(stream(
                        request,
                        respond,
                        deadline,
                        conn,
                        (identity.clone(), log.clone(), counters.clone()),
                    ));
                }
                Some(Err(_)) => break if streams.is_empty() { outcome } else { "carrier_ended" },
                None => break outcome,
            },
            Some(done) = streams.join_next(), if !streams.is_empty() => {
                outcome = done.unwrap_or("stream_aborted");
                if streams.is_empty() {
                    idle_at = tokio::time::Instant::now() + ADMISSION_TIMEOUT;
                }
            }
            () = tokio::time::sleep_until(idle_at), if streams.is_empty() => break outcome,
        }
    }
}

/// One stream: its carrier request answered 200, then its secure session.
async fn stream(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<bytes::Bytes>,
    deadline: tokio::time::Instant,
    conn: u64,
    (identity, log, counters): (Arc<FixtureIdentity>, Arc<JsonLog>, Arc<Counters>),
) -> &'static str {
    if request.uri().path() != secure_channel::GRPC_PATH {
        return "wrong_path";
    }
    let response = http::Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .body(())
        .expect("static response");
    let Ok(sender) = respond.send_response(response, false) else {
        return "response_failed";
    };
    let carrier = GrpcIo::new(H2Stream::new(sender, request.into_body()));
    session(carrier, respond, deadline, conn, &identity, &log, &counters).await
}

async fn session(
    carrier: GrpcIo<H2Stream>,
    respond: h2::server::SendResponse<bytes::Bytes>,
    deadline: tokio::time::Instant,
    conn: u64,
    identity: &FixtureIdentity,
    log: &JsonLog,
    counters: &Counters,
) -> &'static str {
    // Held until the request is served, as secure.rs holds its stream.
    let _respond = respond;
    let accepted = timeout_at(deadline, identity.accept_device(carrier))
        .await
        .unwrap_or(Err("inner_tls_timeout"));
    let (mut inner, device, pinned) = match accepted {
        Ok(accepted) => accepted,
        Err(reason) => {
            log.event("device_refused", json!({"conn": conn, "reason": reason}));
            return reason;
        }
    };
    if pinned {
        log.event(
            "device_pinned",
            json!({
                "conn": conn,
                "certificate_sha256": device.certificate_sha256,
                "not_after_unix_secs": device.not_after_unix_secs,
            }),
        );
    }
    let Ok(Ok(request)) = timeout_at(deadline, policy_ack::read_request(&mut inner)).await else {
        return "request_unreadable";
    };
    match request {
        policy_ack::ChannelRequest::PolicyAck(request) => {
            let Ok(now) = registry::unix_now() else {
                return "clock_unavailable";
            };
            let ack = device.reply(now).ack(request.nonce);
            if policy_ack::write_ack(&mut inner, &ack).await.is_err() {
                return "ack_write_failed";
            }
            // secure.rs: shut the inner stream after the one ACK.
            let _ = inner.shutdown().await;
            counters.acks.fetch_add(1, Ordering::Relaxed);
            log.event(
                "ack",
                json!({"conn": conn, "valid_ms": MAX_ACK_VALID_MS, "generation": test_fixture::ISSUED_GENERATION}),
            );
            "ack_served"
        }
        policy_ack::ChannelRequest::Open(open) => {
            counters.opens.fetch_add(1, Ordering::Relaxed);
            let route = route(&open);
            let kind = match open.transport {
                Transport::Tcp => "tcp",
                Transport::Udp => "udp",
            };
            log.event(
                "open",
                json!({"conn": conn, "kind": kind, "host": open.host, "port": open.port, "outcome": route.outcome()}),
            );
            if route == Route::Refused {
                counters.refused.fetch_add(1, Ordering::Relaxed);
                // secure.rs on a failed connect: status 1, flushed and shut
                // so the H2 end keeps it.
                let _ = inner.write_u8(1).await;
                let _ = inner.flush().await;
                let _ = inner.shutdown().await;
                return "open_refused";
            }
            if inner.write_u8(0).await.is_err() || inner.flush().await.is_err() {
                return "open_status_failed";
            }
            serve_route(&mut inner, route, conn, log).await
        }
    }
}

/// Serve an accepted Open until its input ends, then shut the stream.
async fn serve_route<S: AsyncRead + AsyncWrite + Unpin>(
    inner: &mut S,
    route: Route,
    conn: u64,
    log: &JsonLog,
) -> &'static str {
    let mut units = 0u64;
    let end = match route {
        Route::TcpEcho => {
            let mut buffer = vec![0; 16 * 1024];
            loop {
                match inner.read(&mut buffer).await {
                    Ok(0) => break "eof",
                    Err(_) => break "read_failed",
                    Ok(read) => {
                        // TLS over H2 buffers records until flushed.
                        let echoed = async {
                            inner.write_all(&buffer[..read]).await?;
                            inner.flush().await
                        };
                        if echoed.await.is_err() {
                            break "write_failed";
                        }
                        units += read as u64;
                    }
                }
            }
        }
        Route::UdpEcho => loop {
            match datagram::read(inner).await {
                Ok(None) => break "eof",
                Err(_) => break "read_failed",
                Ok(Some(payload)) => {
                    if datagram::write(inner, &payload).await.is_err() {
                        break "write_failed";
                    }
                    units += 1;
                }
            }
        },
        Route::DnsUdp => loop {
            let query = match datagram::read(inner).await {
                Ok(None) => break "eof",
                Err(_) => break "read_failed",
                Ok(Some(query)) => query,
            };
            let Some(reply) = dns_reply(&query, "udp", conn, log) else {
                break "malformed_query";
            };
            if datagram::write(inner, &reply).await.is_err() {
                break "write_failed";
            }
            units += 1;
        },
        Route::DnsTcp => loop {
            let length = match inner.read_u16().await {
                Ok(length) => usize::from(length),
                Err(_) => break "eof",
            };
            let mut query = vec![0; length];
            if inner.read_exact(&mut query).await.is_err() {
                break "read_failed";
            }
            let Some(reply) = dns_reply(&query, "tcp", conn, log) else {
                break "malformed_query";
            };
            let written = async {
                inner.write_u16(reply.len() as u16).await?;
                inner.write_all(&reply).await?;
                inner.flush().await
            };
            if written.await.is_err() {
                break "write_failed";
            }
            units += 1;
        },
        Route::Refused => return "open_refused",
    };
    // secure_udp: an input EOF still ends with the output terminator.
    let _ = inner.shutdown().await;
    log.event(
        "flow_end",
        json!({"conn": conn, "route": route.outcome(), "units": units, "end": end}),
    );
    "flow_served"
}

fn dns_reply(query: &[u8], transport: &str, conn: u64, log: &JsonLog) -> Option<Vec<u8>> {
    let Some(reply) = probe_dns_answer(query) else {
        log.event(
            "dns",
            json!({"conn": conn, "transport": transport, "outcome": "malformed"}),
        );
        return None;
    };
    log.event(
        "dns",
        json!({"conn": conn, "transport": transport, "qtype": reply.qtype, "outcome": reply.outcome}),
    );
    Some(reply.response)
}

static STOP_SIGNAL: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_stop_signal(signal: libc::c_int) {
    // Only an atomic store: async-signal-safe.
    STOP_SIGNAL.store(signal, Ordering::SeqCst);
}

/// Route SIGTERM and SIGINT to `stop_signal` for the rest of this process.
fn install_stop_signals() -> io::Result<()> {
    for signal in [libc::SIGTERM, libc::SIGINT] {
        // SAFETY: a zeroed sigaction with an empty mask and a handler that
        // only stores to an atomic.
        let installed = unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction =
                on_stop_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
            libc::sigemptyset(&mut action.sa_mask);
            libc::sigaction(signal, &action, std::ptr::null_mut())
        };
        if installed != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

async fn stop_signal() -> &'static str {
    loop {
        match STOP_SIGNAL.load(Ordering::SeqCst) {
            libc::SIGTERM => return "sigterm",
            libc::SIGINT => return "sigint",
            _ => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
}

/// Read the material, bind, then serve one window that SIGTERM ends early.
pub(crate) fn run(config: &RelayConfig) -> io::Result<ServeSummary> {
    let material = FixtureMaterial::read(&config.material)?;
    let listener = std::net::TcpListener::bind(config.bind)?;
    install_stop_signals()?;
    serve(
        listener,
        material,
        &config.log,
        config.lifetime,
        stop_signal(),
    )
}

/// B-06 S16b: serve the installed fixture relay for one bounded window. Not
/// run by default; the orchestrator runs it with the owner.
#[test]
#[ignore = "serves the installed fixture relay; set AEGIS_B06_RELAY_MATERIAL_DIR, _BIND, _LOG and _SECONDS"]
fn fixture_relay_serve() {
    let config = RelayConfig::from_env().unwrap_or_else(|error| panic!("{error}"));
    let summary = run(&config).expect("fixture relay failed");
    println!(
        "fixture_relay_result={} connections={} acks={} opens={} refused={} aborted={}",
        summary.reason,
        summary.connections,
        summary.acks,
        summary.opens,
        summary.refused,
        summary.aborted
    );
}

#[cfg(test)]
#[path = "fixture_relay_tests.rs"]
mod tests;
