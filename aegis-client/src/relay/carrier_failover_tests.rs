//! Deterministic multi-carrier failover harness (carrier program D3).
//!
//! ```text
//! product relay runtime (run_relay_tunnel / run_relay_udp_flow)
//!   carrier 0: fault proxy A -> direct H2 relay (outer relay.test)  -> inner device mTLS
//!   carrier 1: fault proxy B -> CDN-like edge (front.test) -> fronted origin -> inner device mTLS
//! ```
//!
//! Both origins accept exactly one device certificate fingerprint, so every
//! successful session on either carrier is the same inner identity. Faults
//! model what a censor does to one carrier at a time: SYN dropped by a full
//! accept queue (real kernel behaviour, no packet leaves loopback), RST after
//! the ClientHello, SNI-matched reset, slow-loris throttling during
//! establishment, queueing collapse and a freeze of an open session.
//! Leak oracles: the client relay layer dials only the declared carriers and
//! never a destination; destination accepts/datagrams match relayed sessions.

use super::carrier_failover::{inspect, set_test_network};
use crate::test_cdn_edge as cdn;
use aegis_core::brain::carrier_failover::{
    CarrierFailoverSettings, CarrierSignal, CarrierState, NetworkKey,
};
use aegis_core::secure_channel::{self, enrollment};
use aegis_core::{RelayEndpointSettings, RelaySettings, TunnelTransportFamily};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

const RELAY_NAME: &str = "relay.test";
const EDGE_NAME: &str = "front.test";
const INNER_NAME: &str = "inner.test";
const ORIGIN_KEY: [u8; 64] = [b'5'; 64];
const CONNECT_TIMEOUT_MS: u64 = 1_500;

struct Owned(tokio::task::JoinHandle<()>);
impl Drop for Owned {
    fn drop(&mut self) {
        self.0.abort();
    }
}

// ---------------------------------------------------------------- faults ---

#[derive(Clone, Debug, PartialEq, Eq)]
enum Fault {
    Pass,
    /// Saturate the backlog-1 accept queue so the kernel drops new SYNs.
    DropSyn,
    /// Read the first TLS record, then close with SO_LINGER 0 (RST).
    ResetAfterClientHello,
    /// RST only when the ClientHello SNI equals this name; pass otherwise.
    ResetSni(String),
    /// Forward at most `bytes` per `tick` per direction on every connection.
    Throttle {
        bytes: usize,
        tick: Duration,
    },
    /// Hold every chunk for `delay` before forwarding (queueing collapse).
    Congest {
        delay: Duration,
    },
    /// Stop forwarding in both directions; sockets stay open.
    Freeze,
}

#[derive(Default)]
struct ProxyStats {
    accepted: AtomicUsize,
    forwarded: AtomicUsize,
    resets: AtomicUsize,
    syn_drop_armed: AtomicBool,
}

struct FaultProxy {
    address: SocketAddr,
    faults: watch::Sender<Fault>,
    stats: Arc<ProxyStats>,
    _task: Owned,
}

impl FaultProxy {
    async fn start(upstream: SocketAddr) -> Self {
        let socket =
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
        socket
            .bind(&SocketAddr::from(([127, 0, 0, 1], 0)).into())
            .unwrap();
        socket.listen(1).unwrap();
        socket.set_nonblocking(true).unwrap();
        let listener = TcpListener::from_std(socket.into()).unwrap();
        let address = listener.local_addr().unwrap();
        let (faults, receiver) = watch::channel(Fault::Pass);
        let stats = Arc::new(ProxyStats::default());
        let task = Owned(tokio::spawn(accept_loop(
            listener,
            upstream,
            receiver,
            stats.clone(),
        )));
        Self {
            address,
            faults,
            stats,
            _task: task,
        }
    }

    async fn set(&self, fault: Fault) {
        let drop_syn = fault == Fault::DropSyn;
        self.stats.syn_drop_armed.store(false, Ordering::SeqCst);
        self.faults.send_replace(fault);
        if drop_syn {
            let armed = async {
                while !self.stats.syn_drop_armed.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            };
            tokio::time::timeout(Duration::from_secs(10), armed)
                .await
                .expect("accept queue saturated");
        }
    }

    fn accepted(&self) -> usize {
        self.stats.accepted.load(Ordering::SeqCst)
    }

    fn forwarded(&self) -> usize {
        self.stats.forwarded.load(Ordering::SeqCst)
    }

    fn endpoint(&self, server_name: &str) -> RelayEndpointSettings {
        RelayEndpointSettings {
            server: self.address.to_string(),
            server_name: server_name.into(),
            masque_server: None,
            masque_server_name: None,
        }
    }
}

async fn accept_loop(
    listener: TcpListener,
    upstream: SocketAddr,
    mut faults: watch::Receiver<Fault>,
    stats: Arc<ProxyStats>,
) {
    let address = listener.local_addr().unwrap();
    let mut dummies: Vec<TcpStream> = Vec::new();
    let mut dummy_ports = HashSet::new();
    loop {
        let fault = faults.borrow_and_update().clone();
        if fault == Fault::DropSyn {
            if dummies.is_empty() {
                // Completed handshakes that are never accepted fill the queue;
                // the first connect that times out proves SYNs are dropped.
                while dummies.len() < 64 {
                    match tokio::time::timeout(
                        Duration::from_millis(200),
                        TcpStream::connect(address),
                    )
                    .await
                    {
                        Ok(Ok(stream)) => {
                            dummy_ports.insert(stream.local_addr().unwrap().port());
                            dummies.push(stream);
                        }
                        _ => break,
                    }
                }
            }
            stats.syn_drop_armed.store(true, Ordering::SeqCst);
            if faults.changed().await.is_err() {
                return;
            }
            continue;
        }
        dummies.clear();
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((socket, peer)) = accepted else { continue };
                if dummy_ports.remove(&peer.port()) {
                    continue;
                }
                stats.accepted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(handle(socket, upstream, faults.clone(), stats.clone()));
            }
            changed = faults.changed() => if changed.is_err() { return },
        }
    }
}

async fn read_record(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut record = vec![0; 5];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut record))
        .await
        .ok()?
        .ok()?;
    let length = usize::from(u16::from_be_bytes([record[3], record[4]]));
    record.resize(5 + length, 0);
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut record[5..]))
        .await
        .ok()?
        .ok()?;
    Some(record)
}

fn client_hello_sni(record: &[u8]) -> Option<String> {
    let (start, length) = aegis_core::protocols::tls::sni_hostname_range(record)?;
    Some(String::from_utf8_lossy(record.get(start..start + length)?).into_owned())
}

fn reset(stream: TcpStream) {
    let _ = socket2::SockRef::from(&stream).set_linger(Some(Duration::ZERO));
    drop(stream);
}

async fn handle(
    mut client: TcpStream,
    upstream: SocketAddr,
    faults: watch::Receiver<Fault>,
    stats: Arc<ProxyStats>,
) {
    let fault = faults.borrow().clone();
    let mut prefix = Vec::new();
    if matches!(fault, Fault::ResetAfterClientHello | Fault::ResetSni(_)) {
        let Some(hello) = read_record(&mut client).await else {
            return;
        };
        let matched = match &fault {
            Fault::ResetSni(name) => client_hello_sni(&hello).as_deref() == Some(name.as_str()),
            _ => true,
        };
        if matched {
            stats.resets.fetch_add(1, Ordering::SeqCst);
            reset(client);
            return;
        }
        prefix = hello;
    }
    let Ok(mut server) = TcpStream::connect(upstream).await else {
        return;
    };
    stats.forwarded.fetch_add(1, Ordering::SeqCst);
    if !prefix.is_empty() && server.write_all(&prefix).await.is_err() {
        return;
    }
    let (client_read, client_write) = client.into_split();
    let (server_read, server_write) = server.into_split();
    tokio::join!(
        pump(client_read, server_write, faults.clone()),
        pump(server_read, client_write, faults)
    );
}

async fn pump(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    mut faults: watch::Receiver<Fault>,
) {
    let mut buffer = vec![0; 16 * 1024];
    loop {
        let n = match from.read(&mut buffer).await {
            Ok(0) | Err(_) => {
                let _ = to.shutdown().await;
                return;
            }
            Ok(n) => n,
        };
        let mut chunk = &buffer[..n];
        while !chunk.is_empty() {
            let fault = faults.borrow_and_update().clone();
            match fault {
                Fault::Freeze => {
                    if faults.changed().await.is_err() {
                        return;
                    }
                }
                Fault::Throttle { bytes, tick } => {
                    let take = bytes.min(chunk.len());
                    if to.write_all(&chunk[..take]).await.is_err() {
                        return;
                    }
                    chunk = &chunk[take..];
                    tokio::time::sleep(tick).await;
                }
                Fault::Congest { delay } => {
                    tokio::time::sleep(delay).await;
                    if to.write_all(chunk).await.is_err() {
                        return;
                    }
                    chunk = &[];
                }
                _ => {
                    if to.write_all(chunk).await.is_err() {
                        return;
                    }
                    chunk = &[];
                }
            }
        }
    }
}

// ----------------------------------------------------------------- stack ---

struct Ca {
    cert: Certificate,
    key: KeyPair,
}

fn ca(name: &str) -> Ca {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    params.distinguished_name.push(DnType::CommonName, name);
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let cert = params.self_signed(&key).unwrap();
    Ca { cert, key }
}

fn leaf(ca: &Ca, name: &str, usage: ExtendedKeyUsagePurpose) -> (String, String, String) {
    let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
    params.extended_key_usages = vec![usage];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let cert = params.signed_by(&key, &ca.cert, &ca.key).unwrap();
    (
        cert.pem(),
        key.serialize_pem(),
        hex::encode(Sha256::digest(cert.der().as_ref())),
    )
}

fn private(path: &Path, bytes: &[u8]) -> PathBuf {
    enrollment::write_private_new(path, bytes).unwrap();
    path.to_owned()
}

async fn serve(config: String) -> (SocketAddr, Owned) {
    let config: aegis_server::config::ServerConfig = toml::from_str(&config).unwrap();
    config.validate_auth_tokens().unwrap();
    let (ready, address) = tokio::sync::oneshot::channel();
    let task = Owned(tokio::spawn(async move {
        let _ = aegis_server::run_server_with_bound_ready_and_shutdown(
            config,
            ready,
            std::future::pending(),
        )
        .await;
    }));
    let address = tokio::time::timeout(Duration::from_secs(5), address)
        .await
        .expect("relay ready")
        .expect("relay bound");
    (address, task)
}

struct Stack {
    dir: tempfile::TempDir,
    a: FaultProxy,
    b: FaultProxy,
    edge: cdn::Edge,
    outer_ca: PathBuf,
    device: secure_channel::ClientSettings,
    rogue: secure_channel::ClientSettings,
    _direct: Owned,
    _origin: Owned,
}

impl Stack {
    async fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let relay_ca = ca("direct relay CA");
        let edge_ca = ca("edge public CA");
        let origin_ca = ca("origin pull CA");
        let inner_ca = ca("inner CA");
        let (relay_pem, relay_key, _) =
            leaf(&relay_ca, RELAY_NAME, ExtendedKeyUsagePurpose::ServerAuth);
        let (edge_pem, edge_key, _) =
            leaf(&edge_ca, EDGE_NAME, ExtendedKeyUsagePurpose::ServerAuth);
        let (origin_pem, origin_key, _) =
            leaf(&origin_ca, EDGE_NAME, ExtendedKeyUsagePurpose::ServerAuth);
        let (inner_pem, inner_key, _) =
            leaf(&inner_ca, INNER_NAME, ExtendedKeyUsagePurpose::ServerAuth);
        let (device_pem, device_key, device_sha) =
            leaf(&inner_ca, "device-a", ExtendedKeyUsagePurpose::ClientAuth);
        // Same inner CA, but not the one admitted fingerprint.
        let (rogue_pem, rogue_key, _) =
            leaf(&inner_ca, "device-a", ExtendedKeyUsagePurpose::ClientAuth);

        let inner_cert = private(&d.join("inner.pem"), inner_pem.as_bytes());
        let inner_key_path = private(&d.join("inner.key"), inner_key.as_bytes());
        let inner_ca_path = private(&d.join("inner-ca.pem"), inner_ca.cert.pem().as_bytes());
        let inner_tls = format!(
            "[transport.inner_tls]\ncert = '{}'\nkey = '{}'\nclient_ca = '{}'\n\
             allowed_client_sha256 = ['{device_sha}']\nhandshake_timeout_ms = 3000\n\
             idle_timeout_ms = 5000\n",
            inner_cert.display(),
            inner_key_path.display(),
            inner_ca_path.display(),
        );
        let relay_cert = private(&d.join("relay.pem"), relay_pem.as_bytes());
        let relay_key_path = private(&d.join("relay.key"), relay_key.as_bytes());
        let (direct_address, direct) = serve(format!(
            "listen = '127.0.0.1:0'\ncert = '{}'\nkey = '{}'\nauth_token = ''\n\
             [target_policy]\nprofile = 'full_vpn_egress'\n[transport]\nquic_required = false\n{inner_tls}",
            relay_cert.display(),
            relay_key_path.display(),
        ))
        .await;
        let origin_cert = private(&d.join("origin.pem"), origin_pem.as_bytes());
        let origin_key_path = private(&d.join("origin.key"), origin_key.as_bytes());
        let origin_pull = private(&d.join("origin-pull.key"), &ORIGIN_KEY);
        let (origin_address, origin) = serve(format!(
            "listen = '127.0.0.1:0'\ncert = '{}'\nkey = '{}'\nauth_token = ''\nfallback = 'close'\n\
             [rate_limit]\ntrusted_proxy_cidrs = ['127.0.0.1/32']\n\
             [target_policy]\nprofile = 'full_vpn_egress'\n[transport]\nquic_required = false\n{inner_tls}\
             [transport.fronted_origin]\nauthority = '{EDGE_NAME}'\ncredential_file = '{}'\n",
            origin_cert.display(),
            origin_key_path.display(),
            origin_pull.display(),
        ))
        .await;
        let edge = cdn::start(cdn::EdgeConfig {
            listen: None,
            edge_cert_pem: edge_pem,
            edge_key_pem: edge_key,
            origin: origin_address,
            origin_server_name: EDGE_NAME.into(),
            origin_ca_pem: origin_ca.cert.pem(),
            origin_key: Some(ORIGIN_KEY.to_vec()),
            faults: cdn::Faults::default(),
        })
        .await;
        let a = FaultProxy::start(direct_address).await;
        let b = FaultProxy::start(edge.address).await;
        // One explicit outer trust file pins both the direct relay CA and the
        // edge CA set (the D1 profile's `outer-ca.pem`).
        let outer_ca = private(
            &d.join("outer-ca.pem"),
            format!("{}{}", relay_ca.cert.pem(), edge_ca.cert.pem()).as_bytes(),
        );
        let device = secure_channel::ClientSettings {
            server_name: INNER_NAME.into(),
            server_ca: inner_ca_path.clone(),
            cert: private(&d.join("device.pem"), device_pem.as_bytes()),
            key: private(&d.join("device.key"), device_key.as_bytes()),
        };
        let rogue = secure_channel::ClientSettings {
            server_name: INNER_NAME.into(),
            server_ca: inner_ca_path,
            cert: private(&d.join("rogue.pem"), rogue_pem.as_bytes()),
            key: private(&d.join("rogue.key"), rogue_key.as_bytes()),
        };
        Self {
            dir,
            a,
            b,
            edge,
            outer_ca,
            device,
            rogue,
            _direct: direct,
            _origin: origin,
        }
    }

    /// Enrolled relay settings: [direct H2 relay, CDN edge], grpc_stream for
    /// TCP and grpc_datagram for UDP, exactly as a v4 device profile renders.
    fn relay(&self, failover: Option<CarrierFailoverSettings>) -> RelaySettings {
        let mut relay = RelaySettings {
            server: self.a.address.to_string(),
            server_name: RELAY_NAME.into(),
            endpoints: vec![self.a.endpoint(RELAY_NAME), self.b.endpoint(EDGE_NAME)],
            auth_token: String::new(),
            ca_cert: Some(self.outer_ca.clone()),
            transport_priority: vec![TunnelTransportFamily::GrpcStream],
            udp_transport_priority: Some(vec![TunnelTransportFamily::GrpcDatagram]),
            tls_backend: aegis_core::RelayTlsBackend::Rustls,
            connect_timeout_ms: CONNECT_TIMEOUT_MS,
            inner_tls: Some(self.device.clone()),
            carrier_failover: failover,
            ..RelaySettings::default()
        };
        relay.grpc_path = secure_channel::GRPC_PATH.into();
        relay.grpc_path_pool.clear();
        relay.validate_inner_tls_transport().unwrap();
        // Keep these fault tests independent of the Linux runner's real
        // default route. The separate parser test exercises route-derived keys.
        if relay.carrier_failover.is_some() {
            set_test_network(&relay, NetworkKey::UNKNOWN);
        }
        relay
    }
}

fn policy() -> CarrierFailoverSettings {
    CarrierFailoverSettings {
        base_cooldown_ms: 30_000,
        max_cooldown_ms: 60_000,
        degraded_threshold: 1,
        liveness_interval_ms: 250,
        liveness_timeout_ms: 3_000,
        collapse_rtt_ms: 500,
        max_networks: 4,
    }
}

// --------------------------------------------------------------- targets ---

struct TcpTarget {
    address: SocketAddr,
    accepted: Arc<AtomicUsize>,
    _task: Owned,
}

async fn tcp_echo() -> TcpTarget {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = accepted.clone();
    let task = Owned(tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buffer = vec![0; 32 * 1024];
                loop {
                    let n = socket.read(&mut buffer).await.unwrap_or(0);
                    if n == 0 {
                        let _ = socket.shutdown().await;
                        return;
                    }
                    if socket.write_all(&buffer[..n]).await.is_err() {
                        return;
                    }
                }
            });
        }
    }));
    TcpTarget {
        address,
        accepted,
        _task: task,
    }
}

async fn local_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let app = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (client, _) = listener.accept().await.unwrap();
    (app, client)
}

/// One relayed TCP echo session through the product relay entry point.
async fn round_trip(
    relay: &RelaySettings,
    target: &TcpTarget,
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let (mut app, client) = local_pair().await;
    let settings = relay.clone();
    let port = target.address.port();
    let session = tokio::spawn(async move {
        super::run_relay_tunnel(
            client,
            &settings,
            "127.0.0.1".into(),
            port,
            None,
            None,
            None,
        )
        .await
    });
    app.write_all(payload).await?;
    app.shutdown().await?;
    let mut received = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(15), app.read_to_end(&mut received)).await;
    tokio::time::timeout(Duration::from_secs(15), session).await???;
    read??;
    Ok(received)
}

fn dials_to(address: SocketAddr) -> usize {
    let address = address.to_string();
    super::TEST_DIAL_LOG
        .lock()
        .unwrap()
        .iter()
        .filter(|dial| **dial == address)
        .count()
}

/// The relay layer never dialed the destination itself.
fn assert_no_native_dial(target: SocketAddr) {
    assert_eq!(dials_to(target), 0, "destination dialed outside the tunnel");
}

fn payload(size: usize, seed: u8) -> Vec<u8> {
    (0..size)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

// ----------------------------------------------------------------- tests ---

/// Failing first: before the outer handshake classification, an RST after
/// the ClientHello was a terminal error and the session never reached the
/// next carrier, although only the outer ClientHello had been sent.
#[tokio::test]
async fn rst_after_client_hello_continues_on_the_next_carrier_without_policy() {
    let stack = Stack::new().await;
    let target = tcp_echo().await;
    stack.a.set(Fault::ResetAfterClientHello).await;
    let relay = stack.relay(None);
    let data = payload(48 * 1024, 1);
    let started = Instant::now();
    let echoed = round_trip(&relay, &target, &data).await.unwrap();
    assert!(echoed == data, "exact echo through the CDN carrier");
    assert!(started.elapsed() < Duration::from_secs(4));
    assert_eq!(stack.a.stats.resets.load(Ordering::SeqCst), 1);
    assert_eq!(stack.a.forwarded(), 0);
    assert_eq!(stack.b.forwarded(), 1);
    assert!(stack.edge.stats.streams.load(Ordering::SeqCst) >= 1);
    assert_eq!(target.accepted.load(Ordering::SeqCst), 1);
    assert_no_native_dial(target.address);
}

/// Failing first: without carrier failover every new session waited the full
/// establishment timeout on the SYN-dropped preferred carrier.
#[tokio::test]
async fn syn_drop_fails_over_within_one_timeout_then_later_sessions_skip_the_carrier() {
    let stack = Stack::new().await;
    let target = tcp_echo().await;
    let relay = stack.relay(Some(policy()));
    // Healthy: the preferred direct carrier is used.
    assert_eq!(round_trip(&relay, &target, b"warm").await.unwrap(), b"warm");
    assert_eq!((stack.a.forwarded(), stack.b.forwarded()), (1, 0));

    stack.a.set(Fault::DropSyn).await;
    let started = Instant::now();
    let data = payload(64 * 1024, 2);
    assert!(round_trip(&relay, &target, &data).await.unwrap() == data);
    let first = started.elapsed();
    assert!(
        first >= Duration::from_millis(CONNECT_TIMEOUT_MS - 100)
            && first < Duration::from_millis(CONNECT_TIMEOUT_MS + 2_500),
        "first switch bounded by one establishment timeout: {first:?}"
    );
    assert_eq!(stack.b.forwarded(), 1);
    assert_eq!(
        inspect(&relay, |c| c.last_signal(NetworkKey::UNKNOWN, 0)),
        Some(CarrierSignal::DialTimeout)
    );

    let dials_before = dials_to(stack.a.address);
    for round in 0..3 {
        let started = Instant::now();
        let data = payload(16 * 1024, 10 + round);
        assert!(round_trip(&relay, &target, &data).await.unwrap() == data);
        assert!(
            started.elapsed() < Duration::from_millis(CONNECT_TIMEOUT_MS),
            "cooling carrier must not cost another timeout: {:?}",
            started.elapsed()
        );
    }
    assert_eq!(
        dials_to(stack.a.address),
        dials_before,
        "blocked carrier skipped"
    );
    assert_eq!(stack.b.forwarded(), 4);
    assert_eq!(
        stack.a.accepted(),
        1,
        "only the warm session reached carrier A"
    );
    assert_eq!(target.accepted.load(Ordering::SeqCst), 5);
    assert_no_native_dial(target.address);
}

#[tokio::test]
async fn sni_filter_resets_only_the_direct_name_and_traffic_moves_to_the_edge() {
    let stack = Stack::new().await;
    let target = tcp_echo().await;
    // One censor policy in front of both carriers: reset the relay SNI only.
    for proxy in [&stack.a, &stack.b] {
        proxy.set(Fault::ResetSni(RELAY_NAME.into())).await;
    }
    let relay = stack.relay(Some(policy()));
    let started = Instant::now();
    let data = payload(32 * 1024, 3);
    assert!(round_trip(&relay, &target, &data).await.unwrap() == data);
    assert!(started.elapsed() < Duration::from_secs(4));
    assert_eq!(stack.a.stats.resets.load(Ordering::SeqCst), 1);
    assert_eq!(stack.b.stats.resets.load(Ordering::SeqCst), 0);
    assert_eq!(stack.b.forwarded(), 1);
    assert_eq!(
        inspect(&relay, |c| c.last_signal(NetworkKey::UNKNOWN, 0)),
        Some(CarrierSignal::HandshakeReset)
    );
    // The next session goes straight to the edge.
    assert!(round_trip(&relay, &target, b"again").await.unwrap() == b"again");
    assert_eq!(stack.a.accepted(), 1);
    assert_eq!(stack.b.forwarded(), 2);
    assert_no_native_dial(target.address);
}

#[tokio::test]
async fn slow_loris_establishment_is_an_establishment_timeout_and_fails_over() {
    let stack = Stack::new().await;
    let target = tcp_echo().await;
    stack
        .a
        .set(Fault::Throttle {
            bytes: 24,
            tick: Duration::from_millis(100),
        })
        .await;
    let relay = stack.relay(Some(policy()));
    let started = Instant::now();
    let data = payload(24 * 1024, 4);
    assert!(round_trip(&relay, &target, &data).await.unwrap() == data);
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(CONNECT_TIMEOUT_MS + 2_500),
        "{elapsed:?}"
    );
    assert_eq!(
        inspect(&relay, |c| c.last_signal(NetworkKey::UNKNOWN, 0)),
        Some(CarrierSignal::EstablishmentTimeout)
    );
    assert_eq!(stack.b.forwarded(), 1);
    assert_eq!(target.accepted.load(Ordering::SeqCst), 1);
    assert_no_native_dial(target.address);
}

#[tokio::test]
async fn frozen_open_session_is_closed_by_liveness_never_replayed_and_next_uses_edge() {
    let stack = Stack::new().await;
    let target = tcp_echo().await;
    let relay = stack.relay(Some(policy()));
    let (mut app, client) = local_pair().await;
    let settings = relay.clone();
    let port = target.address.port();
    let session = tokio::spawn(async move {
        super::run_relay_tunnel(
            client,
            &settings,
            "127.0.0.1".into(),
            port,
            None,
            None,
            None,
        )
        .await
    });
    app.write_all(b"before freeze").await.unwrap();
    let mut echoed = [0; 13];
    tokio::time::timeout(Duration::from_secs(5), app.read_exact(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&echoed, b"before freeze");
    assert_eq!(stack.a.forwarded(), 1);

    stack.a.set(Fault::Freeze).await;
    let frozen_at = Instant::now();
    app.write_all(b"held by the frozen path").await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(8), session)
        .await
        .expect("liveness must end a frozen session")
        .unwrap();
    let error = result.unwrap_err();
    assert!(format!("{error:#}").contains("session_freeze"), "{error:#}");
    let detection = frozen_at.elapsed();
    assert!(
        detection < Duration::from_millis(250 + 3_000 + 1_500),
        "{detection:?}"
    );
    // The frozen session's bytes were not replayed through another carrier.
    assert_eq!(stack.b.forwarded(), 0);
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), app.read_to_end(&mut rest)).await;
    assert!(rest.is_empty());
    assert_eq!(
        inspect(&relay, |c| c.last_signal(NetworkKey::UNKNOWN, 0)),
        Some(CarrierSignal::SessionFreeze)
    );

    let started = Instant::now();
    assert!(round_trip(&relay, &target, b"after").await.unwrap() == b"after");
    assert!(started.elapsed() < Duration::from_millis(CONNECT_TIMEOUT_MS));
    assert_eq!(stack.b.forwarded(), 1);
    assert_eq!(stack.a.accepted(), 1);
    assert_eq!(target.accepted.load(Ordering::SeqCst), 2);
    assert_no_native_dial(target.address);
}

#[tokio::test]
async fn queueing_collapse_on_open_session_demotes_carrier_for_later_sessions() {
    let stack = Stack::new().await;
    let target = tcp_echo().await;
    let relay = stack.relay(Some(policy()));
    let (mut app, client) = local_pair().await;
    let settings = relay.clone();
    let port = target.address.port();
    let session = tokio::spawn(async move {
        super::run_relay_tunnel(
            client,
            &settings,
            "127.0.0.1".into(),
            port,
            None,
            None,
            None,
        )
        .await
    });
    app.write_all(b"ok").await.unwrap();
    let mut echoed = [0; 2];
    tokio::time::timeout(Duration::from_secs(5), app.read_exact(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    // PING round trips now take about 2 x 400 ms: above the 500 ms collapse
    // threshold, below the 3 s freeze timeout. The session is not closed.
    stack
        .a
        .set(Fault::Congest {
            delay: Duration::from_millis(400),
        })
        .await;
    let collapse = async {
        loop {
            if inspect(&relay, |c| c.last_signal(NetworkKey::UNKNOWN, 0))
                == Some(CarrierSignal::ThroughputCollapse)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(5), collapse)
        .await
        .expect("throughput collapse recorded");
    assert!(matches!(
        inspect(&relay, |c| c.state(NetworkKey::UNKNOWN, 0, Instant::now())),
        CarrierState::Cooling { .. }
    ));
    // The degraded but open session still completes (slowly) on carrier A.
    app.write_all(b"slow").await.unwrap();
    app.shutdown().await.unwrap();
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), app.read_to_end(&mut rest))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rest, b"slow");
    tokio::time::timeout(Duration::from_secs(10), session)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    // Later sessions use the edge.
    assert!(round_trip(&relay, &target, b"next").await.unwrap() == b"next");
    assert_eq!((stack.a.accepted(), stack.b.forwarded()), (1, 1));
    assert_no_native_dial(target.address);
}

#[tokio::test]
async fn udp_stays_on_grpc_datagram_and_fails_over_without_losing_the_first_datagram() {
    let stack = Stack::new().await;
    let relay = stack.relay(Some(policy()));
    let plan = super::udp_endpoint_attempts(&relay, false);
    assert_eq!(plan.len(), 2);
    assert!(plan
        .iter()
        .all(|attempt| attempt.family == TunnelTransportFamily::GrpcDatagram));
    assert_eq!(
        super::planned_udp_associate_transports(&relay),
        vec![TunnelTransportFamily::GrpcDatagram]
    );

    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    let received = Arc::new(AtomicUsize::new(0));
    let counter = received.clone();
    let _echo = Owned(tokio::spawn(async move {
        let mut buffer = vec![0; 65_535];
        loop {
            let Ok((length, source)) = target.recv_from(&mut buffer).await else {
                return;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            let _ = target.send_to(&buffer[..length], source).await;
        }
    }));
    stack.a.set(Fault::DropSyn).await;
    let (outbound, rx) = tokio::sync::mpsc::channel(4);
    let (tx, mut inbound) = tokio::sync::mpsc::channel(4);
    // The first datagram is queued before the flow opens; it must be carried
    // exactly once by the next carrier, not dropped or duplicated.
    outbound.send(b"first".to_vec()).await.unwrap();
    let settings = relay.clone();
    let started = Instant::now();
    let flow = tokio::spawn(async move {
        super::run_relay_udp_flow(&settings, "127.0.0.1", port, rx, tx).await
    });
    let mut expected = vec![b"first".to_vec()];
    let first = tokio::time::timeout(Duration::from_secs(6), inbound.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.payload, b"first");
    assert!(started.elapsed() < Duration::from_millis(CONNECT_TIMEOUT_MS + 2_500));
    for datagram in [vec![], vec![0x5a; 4096]] {
        outbound.send(datagram.clone()).await.unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(5), inbound.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply.payload, datagram);
        expected.push(datagram);
    }
    drop(outbound);
    tokio::time::timeout(Duration::from_secs(5), flow)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(received.load(Ordering::SeqCst), expected.len());
    assert_eq!(
        stack.b.forwarded(),
        1,
        "one grpc_datagram stream on the edge"
    );
    assert_eq!(stack.a.accepted(), 0);
    assert_eq!(
        inspect(&relay, |c| c.last_signal(NetworkKey::UNKNOWN, 0)),
        Some(CarrierSignal::DialTimeout)
    );
}

#[tokio::test]
async fn preferred_carrier_returns_after_recovery_through_one_trial() {
    let stack = Stack::new().await;
    let target = tcp_echo().await;
    let relay = stack.relay(Some(CarrierFailoverSettings {
        base_cooldown_ms: 800,
        ..policy()
    }));
    stack.a.set(Fault::ResetAfterClientHello).await;
    assert!(round_trip(&relay, &target, b"one").await.unwrap() == b"one");
    assert_eq!((stack.a.accepted(), stack.b.forwarded()), (1, 1));
    assert_eq!(inspect(&relay, |c| c.active(NetworkKey::UNKNOWN)), Some(1));

    // Still blocked when the cooldown expires: one trial, doubled cooldown.
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert!(round_trip(&relay, &target, b"two").await.unwrap() == b"two");
    assert_eq!((stack.a.accepted(), stack.b.forwarded()), (2, 2));
    assert!(matches!(
        inspect(&relay, |c| c.state(NetworkKey::UNKNOWN, 0, Instant::now())),
        CarrierState::Cooling { remaining } if remaining > Duration::from_millis(900)
    ));

    // Carrier A recovers; after the doubled cooldown the trial succeeds and
    // traffic returns to the preferred direct carrier.
    stack.a.set(Fault::Pass).await;
    tokio::time::sleep(Duration::from_millis(1_700)).await;
    assert!(round_trip(&relay, &target, b"three").await.unwrap() == b"three");
    assert_eq!((stack.a.forwarded(), stack.b.forwarded()), (1, 2));
    assert_eq!(inspect(&relay, |c| c.active(NetworkKey::UNKNOWN)), Some(0));
    assert_eq!(
        inspect(&relay, |c| c.state(NetworkKey::UNKNOWN, 0, Instant::now())),
        CarrierState::Closed
    );
    assert!(round_trip(&relay, &target, b"four").await.unwrap() == b"four");
    assert_eq!((stack.a.forwarded(), stack.b.forwarded()), (2, 2));
    assert_eq!(target.accepted.load(Ordering::SeqCst), 4);
    assert_no_native_dial(target.address);
}

#[tokio::test]
async fn carrier_memory_is_per_network() {
    let stack = Stack::new().await;
    let target = tcp_echo().await;
    let relay = stack.relay(Some(policy()));
    let salt = [9; 32];
    let censored = NetworkKey::derive(&salt, &[b"wlan0", b"home"]);
    let open = NetworkKey::derive(&salt, &[b"eth0", b"office"]);
    stack.a.set(Fault::ResetAfterClientHello).await;
    set_test_network(&relay, censored);
    assert!(round_trip(&relay, &target, b"home-1").await.unwrap() == b"home-1");
    assert_eq!(stack.a.accepted(), 1);
    // Another network has no memory of the block: the preferred carrier is
    // tried first there (and here it is blocked as well, so it is learned).
    set_test_network(&relay, open);
    assert!(round_trip(&relay, &target, b"office").await.unwrap() == b"office");
    assert_eq!(stack.a.accepted(), 2);
    // Back on the first network the block is remembered: no new attempt.
    set_test_network(&relay, censored);
    assert!(round_trip(&relay, &target, b"home-2").await.unwrap() == b"home-2");
    assert_eq!(stack.a.accepted(), 2);
    assert_eq!(stack.b.forwarded(), 3);
    assert_eq!(inspect(&relay, |c| c.remembered_networks()), 2);
    assert_no_native_dial(target.address);
}

#[tokio::test]
async fn inner_identity_refusal_is_terminal_and_never_tried_on_the_next_carrier() {
    let stack = Stack::new().await;
    let target = tcp_echo().await;
    // Same CA, different (not admitted) device certificate.
    let mut relay = stack.relay(Some(policy()));
    relay.inner_tls = Some(stack.rogue.clone());
    // Changing the certificate changes the profile identity used by the
    // test-only network override; bind the rogue profile as well.
    set_test_network(&relay, NetworkKey::UNKNOWN);
    let error = round_trip(&relay, &target, b"must not arrive")
        .await
        .unwrap_err();
    assert!(
        !super::secure::retryable_pre_auth_failure(&error),
        "{error:#}"
    );
    assert_eq!(stack.a.forwarded(), 1);
    assert_eq!(
        stack.b.accepted(),
        0,
        "identity refusal is not a carrier block"
    );
    assert_eq!(dials_to(stack.b.address), 0);
    assert_eq!(target.accepted.load(Ordering::SeqCst), 0);
    // Not learned as a carrier block either.
    assert_eq!(
        inspect(&relay, |c| c.state(NetworkKey::UNKNOWN, 0, Instant::now())),
        CarrierState::Closed
    );
    // The admitted identity works on both carriers: identity is unchanged by
    // a switch because there is only one admitted device on both origins.
    let admitted = stack.relay(Some(policy()));
    assert!(round_trip(&admitted, &target, b"a").await.unwrap() == b"a");
    stack.a.set(Fault::ResetAfterClientHello).await;
    assert!(round_trip(&admitted, &target, b"b").await.unwrap() == b"b");
    assert_eq!((stack.a.forwarded(), stack.b.forwarded()), (2, 1));
    assert_no_native_dial(target.address);
}

#[tokio::test]
async fn all_carriers_blocked_fails_closed_without_native_egress() {
    let stack = Stack::new().await;
    let target = tcp_echo().await;
    stack.a.set(Fault::ResetAfterClientHello).await;
    stack.b.set(Fault::DropSyn).await;
    let relay = stack.relay(Some(policy()));
    let started = Instant::now();
    let error = round_trip(&relay, &target, b"nothing leaves")
        .await
        .unwrap_err();
    assert!(
        error.chain().any(|c| c.is::<super::RelayTerminalFailure>()),
        "{error:#}"
    );
    assert!(started.elapsed() < Duration::from_millis(2 * CONNECT_TIMEOUT_MS + 2_000));
    assert_eq!(target.accepted.load(Ordering::SeqCst), 0);
    assert_no_native_dial(target.address);
    // Both carriers are cooling, but both stay in the plan as last resort:
    // nothing outside the explicit carrier list is ever attempted.
    let dials_a = dials_to(stack.a.address);
    let dials_b = dials_to(stack.b.address);
    assert!(round_trip(&relay, &target, b"again").await.is_err());
    assert_eq!(dials_to(stack.a.address), dials_a + 1);
    assert_eq!(dials_to(stack.b.address), dials_b + 1);
    assert_eq!(target.accepted.load(Ordering::SeqCst), 0);
    assert_no_native_dial(target.address);
    let _ = stack.dir.path();
}
