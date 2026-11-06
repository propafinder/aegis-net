//! Carrier program D2: required ECH over the CDN-fronted enrolled carrier.
//!
//! A real AWS-LC TLS 1.3 server with ECH keys terminates client TLS (as a CDN
//! edge does), then hands plaintext HTTP/2 to the CDN-like gRPC edge, which
//! forwards to the fronted aegis-server origin. The client is the production
//! enrolled carrier (`outer_grpc` + inner device mTLS). No GREASE surrogate,
//! permissive verifier or fake status is used: acceptance is the server's
//! own `SSL_ech_accepted` plus a working tunnel.

use crate::test_cdn_edge as cdn;

use super::tests::configs;
use aegis_core::secure_channel;
use aws_lc_sys as ssl;
use base64::Engine;
use std::ffi::{c_int, c_void, CStr};
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const EDGE: &str = "relay.edge.test";
const COVER: &str = "cover.edge.test";
const OTHER_COVER: &str = "other-cover.edge.test";
const ORIGIN_KEY: [u8; 64] = [b'5'; 64];

macro_rules! owned_native {
    ($name:ident, $native:ty, $free:path) => {
        struct $name(NonNull<$native>);
        impl $name {
            fn new(pointer: *mut $native) -> Self {
                Self(NonNull::new(pointer).expect(stringify!($name)))
            }
            fn as_ptr(&self) -> *mut $native {
                self.0.as_ptr()
            }
        }
        impl Drop for $name {
            fn drop(&mut self) {
                unsafe { $free(self.as_ptr()) }
            }
        }
        // Each owner is used by one task at a time; AWS-LC objects are not
        // shared between threads concurrently in this fixture.
        unsafe impl Send for $name {}
        unsafe impl Sync for $name {}
    };
}

owned_native!(Context, ssl::SSL_CTX, ssl::SSL_CTX_free);
owned_native!(Session, ssl::SSL, ssl::SSL_free);
owned_native!(HpkeKey, ssl::EVP_HPKE_KEY, ssl::EVP_HPKE_KEY_free);
owned_native!(EchKeys, ssl::SSL_ECH_KEYS, ssl::SSL_ECH_KEYS_free);
owned_native!(PrivateKey, ssl::EVP_PKEY, ssl::EVP_PKEY_free);

/// One real server ECH key and its public ECHConfig.
struct EchKey {
    key: HpkeKey,
    config: Vec<u8>,
}

impl EchKey {
    fn generate(config_id: u8, public_name: &CStr) -> Self {
        unsafe {
            let key = HpkeKey::new(ssl::EVP_HPKE_KEY_new());
            assert_eq!(
                ssl::EVP_HPKE_KEY_generate(key.as_ptr(), ssl::EVP_hpke_x25519_hkdf_sha256()),
                1
            );
            let mut raw = ptr::null_mut();
            let mut length = 0;
            assert_eq!(
                ssl::SSL_marshal_ech_config(
                    &mut raw,
                    &mut length,
                    config_id,
                    key.as_ptr(),
                    public_name.as_ptr(),
                    64,
                ),
                1
            );
            let config = std::slice::from_raw_parts(raw, length).to_vec();
            ssl::OPENSSL_free(raw.cast());
            Self { key, config }
        }
    }

    /// The public ECHConfigList a profile would pin for this key.
    fn list(&self) -> Vec<u8> {
        let mut list = (self.config.len() as u16).to_be_bytes().to_vec();
        list.extend_from_slice(&self.config);
        list
    }

    fn base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.list())
    }
}

unsafe extern "C" fn select_h2(
    _session: *mut ssl::SSL,
    output: *mut *const u8,
    output_length: *mut u8,
    input: *const u8,
    input_length: u32,
    _argument: *mut c_void,
) -> c_int {
    const H2: &[u8] = b"h2";
    if input.is_null() || output.is_null() || output_length.is_null() {
        return ssl::SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    let mut offered = std::slice::from_raw_parts(input, input_length as usize);
    while let Some((&length, rest)) = offered.split_first() {
        let length = length as usize;
        if rest.len() < length {
            break;
        }
        if &rest[..length] == H2 {
            *output = H2.as_ptr();
            *output_length = H2.len() as u8;
            return ssl::SSL_TLSEXT_ERR_OK;
        }
        offered = &rest[length..];
    }
    ssl::SSL_TLSEXT_ERR_ALERT_FATAL
}

/// A TLS 1.3 server context: certificate, optional ECH keys.
struct EchServer {
    context: Context,
    _keys: Option<EchKeys>,
}

impl EchServer {
    /// `keys`: (key, is_retry_config). Retry configs are what a rejecting
    /// server returns to the client in EncryptedExtensions.
    fn new(cert_der: &[u8], private_der: &[u8], keys: &[(&EchKey, bool)]) -> Self {
        unsafe {
            let context = Context::new(ssl::SSL_CTX_new(ssl::TLS_method()));
            assert_eq!(
                ssl::SSL_CTX_set_min_proto_version(context.as_ptr(), 0x0304),
                1
            );
            assert_eq!(
                ssl::SSL_CTX_set_max_proto_version(context.as_ptr(), 0x0304),
                1
            );
            assert_eq!(ssl::SSL_CTX_set_num_tickets(context.as_ptr(), 0), 1);
            assert_eq!(
                ssl::SSL_CTX_use_certificate_ASN1(
                    context.as_ptr(),
                    cert_der.len(),
                    cert_der.as_ptr()
                ),
                1
            );
            let mut cbs = std::mem::MaybeUninit::<ssl::CBS>::uninit();
            ssl::CBS_init(cbs.as_mut_ptr(), private_der.as_ptr(), private_der.len());
            let mut cbs = cbs.assume_init();
            let private = PrivateKey::new(ssl::EVP_parse_private_key(&mut cbs));
            assert_eq!(
                ssl::SSL_CTX_use_PrivateKey(context.as_ptr(), private.as_ptr()),
                1
            );
            assert_eq!(ssl::SSL_CTX_check_private_key(context.as_ptr()), 1);
            let ech = if keys.is_empty() {
                None
            } else {
                let ech = EchKeys::new(ssl::SSL_ECH_KEYS_new());
                for (key, retry) in keys {
                    assert_eq!(
                        ssl::SSL_ECH_KEYS_add(
                            ech.as_ptr(),
                            c_int::from(*retry),
                            key.config.as_ptr(),
                            key.config.len(),
                            key.key.as_ptr(),
                        ),
                        1
                    );
                }
                assert_eq!(
                    ssl::SSL_CTX_set1_ech_keys(context.as_ptr(), ech.as_ptr()),
                    1
                );
                Some(ech)
            };
            ssl::SSL_CTX_set_alpn_select_cb(context.as_ptr(), Some(select_h2), ptr::null_mut());
            Self {
                context,
                _keys: ech,
            }
        }
    }
}

#[derive(Clone, Debug, Default)]
struct Handshake {
    completed: bool,
    ech_accepted: bool,
    server_name: Option<String>,
}

struct Tls {
    session: Session,
    read_bio: *mut ssl::BIO,
    write_bio: *mut ssl::BIO,
}
// Accessed by exactly one task; see owned_native.
unsafe impl Send for Tls {}

impl Tls {
    fn new(server: &EchServer) -> Self {
        unsafe {
            let session = Session::new(ssl::SSL_new(server.context.as_ptr()));
            let read_bio = ssl::BIO_new(ssl::BIO_s_mem());
            let write_bio = ssl::BIO_new(ssl::BIO_s_mem());
            assert!(!read_bio.is_null() && !write_bio.is_null());
            // The SSL object owns both BIOs from here on.
            ssl::SSL_set_bio(session.as_ptr(), read_bio, write_bio);
            ssl::SSL_set_accept_state(session.as_ptr());
            Self {
                session,
                read_bio,
                write_bio,
            }
        }
    }

    fn feed(&mut self, bytes: &[u8]) {
        unsafe {
            let written =
                ssl::BIO_write(self.read_bio, bytes.as_ptr().cast(), bytes.len() as c_int);
            assert_eq!(written as usize, bytes.len());
        }
    }

    fn drain(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let read = unsafe {
                ssl::BIO_read(
                    self.write_bio,
                    buffer.as_mut_ptr().cast(),
                    buffer.len() as c_int,
                )
            };
            if read <= 0 {
                return out;
            }
            out.extend_from_slice(&buffer[..read as usize]);
        }
    }

    /// Ok(true) when finished, Ok(false) when more input is needed.
    fn handshake(&mut self) -> std::io::Result<bool> {
        unsafe {
            ssl::ERR_clear_error();
            let result = ssl::SSL_do_handshake(self.session.as_ptr());
            if result == 1 {
                return Ok(true);
            }
            match ssl::SSL_get_error(self.session.as_ptr(), result) {
                ssl::SSL_ERROR_WANT_READ => Ok(false),
                _ => Err(std::io::Error::other("server TLS handshake failed")),
            }
        }
    }

    fn info(&self) -> Handshake {
        unsafe {
            let name = ssl::SSL_get_servername(self.session.as_ptr(), 0);
            Handshake {
                completed: true,
                ech_accepted: ssl::SSL_ech_accepted(self.session.as_ptr()) == 1,
                server_name: (!name.is_null())
                    .then(|| CStr::from_ptr(name).to_string_lossy().into_owned()),
            }
        }
    }

    /// Decrypted application bytes; Ok(None) on close_notify.
    fn read_plain(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        let mut out = Vec::new();
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let read = unsafe {
                ssl::SSL_read(
                    self.session.as_ptr(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len() as c_int,
                )
            };
            if read > 0 {
                out.extend_from_slice(&buffer[..read as usize]);
                continue;
            }
            let error = unsafe { ssl::SSL_get_error(self.session.as_ptr(), read) };
            return match error {
                ssl::SSL_ERROR_WANT_READ => Ok(Some(out)),
                ssl::SSL_ERROR_ZERO_RETURN if out.is_empty() => Ok(None),
                ssl::SSL_ERROR_ZERO_RETURN => Ok(Some(out)),
                _ => Err(std::io::Error::other("server TLS read failed")),
            };
        }
    }

    fn write_plain(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let written = unsafe {
            ssl::SSL_write(
                self.session.as_ptr(),
                bytes.as_ptr().cast(),
                bytes.len() as c_int,
            )
        };
        if written as usize != bytes.len() {
            return Err(std::io::Error::other("server TLS write failed"));
        }
        Ok(())
    }
}

/// Terminate one client TLS connection with AWS-LC (ECH-capable edge),
/// record the handshake, and pump plaintext to `plain`.
async fn terminate(
    mut tcp: TcpStream,
    server: Arc<EchServer>,
    plain: tokio::io::DuplexStream,
    record: Arc<Mutex<Vec<Handshake>>>,
) -> std::io::Result<()> {
    let mut tls = Tls::new(&server);
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        let finished = tls.handshake();
        let flight = tls.drain();
        if !flight.is_empty() {
            tcp.write_all(&flight).await?;
        }
        match finished {
            Ok(true) => break,
            Ok(false) => {}
            Err(error) => {
                record.lock().unwrap().push(Handshake::default());
                return Err(error);
            }
        }
        let read = tcp.read(&mut buffer).await?;
        if read == 0 {
            // The client aborted (e.g. after an authenticated ECH rejection).
            record.lock().unwrap().push(Handshake::default());
            return Ok(());
        }
        tls.feed(&buffer[..read]);
    }
    record.lock().unwrap().push(tls.info());
    let (mut plain_read, mut plain_write) = tokio::io::split(plain);
    let mut plain_buffer = vec![0u8; 16 * 1024];
    loop {
        tokio::select! {
            read = tcp.read(&mut buffer) => {
                let read = read?;
                if read == 0 { return Ok(()); }
                tls.feed(&buffer[..read]);
                match tls.read_plain()? {
                    Some(bytes) => if !bytes.is_empty() { plain_write.write_all(&bytes).await?; },
                    None => { let _ = plain_write.shutdown().await; return Ok(()); }
                }
                let flight = tls.drain();
                if !flight.is_empty() { tcp.write_all(&flight).await?; }
            }
            read = plain_read.read(&mut plain_buffer) => {
                let read = read?;
                if read == 0 { return Ok(()); }
                tls.write_plain(&plain_buffer[..read])?;
                let flight = tls.drain();
                tcp.write_all(&flight).await?;
            }
        }
    }
}

/// An ECH-terminating edge in front of the CDN-like gRPC edge. The context
/// used for connection `n` is `servers[min(n, len-1)]`.
struct EchEdge {
    address: std::net::SocketAddr,
    handshakes: Arc<Mutex<Vec<Handshake>>>,
    accepted: Arc<AtomicUsize>,
    _task: super::Driver,
}

async fn ech_edge(servers: Vec<Arc<EchServer>>, edge: Arc<cdn::Edge>) -> EchEdge {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let handshakes = Arc::new(Mutex::new(Vec::new()));
    let accepted = Arc::new(AtomicUsize::new(0));
    let record = handshakes.clone();
    let count = accepted.clone();
    let task = super::Driver(tokio::spawn(async move {
        loop {
            let Ok((tcp, peer)) = listener.accept().await else {
                return;
            };
            let index = count.fetch_add(1, Ordering::SeqCst).min(servers.len() - 1);
            let server = servers[index].clone();
            let (plain, edge_side) = tokio::io::duplex(64 * 1024);
            drop(edge.serve_plaintext(edge_side, peer));
            let record = record.clone();
            tokio::spawn(async move {
                let _ = terminate(tcp, server, plain, record).await;
            });
        }
    }));
    EchEdge {
        address,
        handshakes,
        accepted,
        _task: task,
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    settings: aegis_core::Settings,
    cert_der: Vec<u8>,
    private_der: Vec<u8>,
    edge: Arc<cdn::Edge>,
    _server: super::Driver,
}

/// Fronted origin + CDN-like edge; the client trusts the AWS-LC edge cert
/// (valid for the inner edge name and both cover names).
async fn fixture() -> Fixture {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = reservation.local_addr().unwrap();
    let (settings, mut server) = configs(dir.path(), &address.to_string());
    // Origin certificate for the edge hostname ("Full strict").
    let origin = rcgen::generate_simple_self_signed(vec![EDGE.into()]).unwrap();
    let origin_cert = dir.path().join("origin.pem");
    let origin_key = dir.path().join("origin.key");
    secure_channel::enrollment::write_private_new(&origin_cert, origin.cert.pem().as_bytes())
        .unwrap();
    secure_channel::enrollment::write_private_new(
        &origin_key,
        origin.key_pair.serialize_pem().as_bytes(),
    )
    .unwrap();
    let pull = dir.path().join("origin-pull.key");
    secure_channel::enrollment::write_private_new(&pull, &ORIGIN_KEY).unwrap();
    server.cert = origin_cert;
    server.key = origin_key;
    server.auth_token.clear();
    server.limits.shutdown_grace_ms = 200;
    server.rate_limit.trusted_proxy_cidrs = vec!["127.0.0.1/32".into()];
    server.transport.fronted_origin = Some(aegis_core::fronted_origin::Settings {
        authority: EDGE.into(),
        credential_file: pull,
        next_credential_file: None,
        enrollment_forward: None,
    });
    server.validate_auth_tokens().unwrap();
    drop(reservation);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let server_task = super::Driver(tokio::spawn(async move {
        aegis_server::run_server_with_shutdown(server, Some(ready_tx), std::future::pending())
            .await
            .unwrap();
    }));
    tokio::time::timeout(Duration::from_secs(5), ready_rx)
        .await
        .unwrap()
        .unwrap();
    let edge_tls =
        rcgen::generate_simple_self_signed(vec![EDGE.into(), COVER.into(), OTHER_COVER.into()])
            .unwrap();
    let edge = Arc::new(
        cdn::start(cdn::EdgeConfig {
            listen: None,
            edge_cert_pem: edge_tls.cert.pem(),
            edge_key_pem: edge_tls.key_pair.serialize_pem(),
            origin: address,
            origin_server_name: EDGE.into(),
            origin_ca_pem: origin.cert.pem(),
            origin_key: Some(ORIGIN_KEY.to_vec()),
            faults: Default::default(),
        })
        .await,
    );
    let outer_ca = dir.path().join("edge-ca.pem");
    std::fs::write(&outer_ca, edge_tls.cert.pem()).unwrap();
    let mut settings = settings;
    settings.relay.server_name = EDGE.into();
    settings.relay.ca_cert = Some(outer_ca);
    Fixture {
        settings,
        cert_der: edge_tls.cert.der().to_vec(),
        private_der: edge_tls.key_pair.serialize_der(),
        edge,
        _server: server_task,
        _dir: dir,
    }
}

async fn echo_target() -> (std::net::SocketAddr, Arc<AtomicUsize>, super::Driver) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    let task = super::Driver(tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                loop {
                    let n = socket.read(&mut buffer).await.unwrap_or(0);
                    if n == 0 || socket.write_all(&buffer[..n]).await.is_err() {
                        return;
                    }
                }
            });
        }
    }));
    (address, accepted, task)
}

async fn round_trip(
    settings: &aegis_core::RelaySettings,
    target: std::net::SocketAddr,
) -> anyhow::Result<()> {
    let (mut inner, _driver) = super::open(
        settings,
        target.ip().to_string(),
        target.port(),
        secure_channel::Transport::Tcp,
    )
    .await?;
    inner.write_all(b"through ECH and the CDN").await?;
    inner.flush().await?;
    let mut echoed = [0u8; 23];
    inner.read_exact(&mut echoed).await?;
    anyhow::ensure!(&echoed == b"through ECH and the CDN");
    Ok(())
}

#[tokio::test]
async fn pinned_current_ech_reaches_inner_device_mtls_through_the_cdn_edge() {
    let f = fixture().await;
    let current = EchKey::generate(1, c"cover.edge.test");
    let server = Arc::new(EchServer::new(
        &f.cert_der,
        &f.private_der,
        &[(&current, true)],
    ));
    let edge = ech_edge(vec![server], f.edge.clone()).await;
    let mut relay = f.settings.relay.clone();
    relay.server = edge.address.to_string();
    relay.ech_config_list_base64 = Some(current.base64());
    let (target, accepted, _target) = echo_target().await;
    round_trip(&relay, target).await.unwrap();
    let handshakes = edge.handshakes.lock().unwrap().clone();
    assert_eq!(handshakes.len(), 1);
    assert!(
        handshakes[0].ech_accepted,
        "AWS-LC decrypted and accepted real ECH"
    );
    assert_eq!(
        handshakes[0].server_name.as_deref(),
        Some(EDGE),
        "inner SNI"
    );
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn stale_pinned_config_rotates_once_through_authenticated_retry_configs() {
    let f = fixture().await;
    let stale = EchKey::generate(7, c"cover.edge.test");
    let rotated = EchKey::generate(8, c"cover.edge.test");
    // The edge no longer holds the pinned key; it advertises the new one.
    let server = Arc::new(EchServer::new(
        &f.cert_der,
        &f.private_der,
        &[(&rotated, true)],
    ));
    let edge = ech_edge(vec![server], f.edge.clone()).await;
    let mut relay = f.settings.relay.clone();
    relay.server = edge.address.to_string();
    relay.server_name = EDGE.into();
    relay.ech_config_list_base64 = Some(stale.base64());
    assert!(!aegis_client::ech_policy::has_rotation(&relay));
    let (target, accepted, _target) = echo_target().await;
    round_trip(&relay, target).await.unwrap();
    {
        let handshakes = edge.handshakes.lock().unwrap();
        assert_eq!(
            handshakes.len(),
            2,
            "one authenticated rejection, one retry"
        );
        assert!(!handshakes[0].completed && !handshakes[0].ech_accepted);
        assert!(handshakes[1].completed && handshakes[1].ech_accepted);
        assert_eq!(handshakes[1].server_name.as_deref(), Some(EDGE));
    }
    assert!(aegis_client::ech_policy::has_rotation(&relay));
    // The next connection uses the learned rotation directly.
    round_trip(&relay, target).await.unwrap();
    let handshakes = edge.handshakes.lock().unwrap().clone();
    assert_eq!(handshakes.len(), 3);
    assert!(handshakes[2].ech_accepted);
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
    aegis_client::ech_policy::forget_rotation(&relay);
}

#[tokio::test]
async fn ech_less_edge_fails_closed_before_any_http2_or_device_identity() {
    let f = fixture().await;
    let pinned = EchKey::generate(3, c"cover.edge.test");
    let server = Arc::new(EchServer::new(&f.cert_der, &f.private_der, &[]));
    let edge = ech_edge(vec![server], f.edge.clone()).await;
    let mut relay = f.settings.relay.clone();
    relay.server = edge.address.to_string();
    relay.server_name = EDGE.into();
    relay.ech_config_list_base64 = Some(pinned.base64());
    let (target, accepted, _target) = echo_target().await;
    assert!(round_trip(&relay, target).await.is_err());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        edge.accepted.load(Ordering::SeqCst),
        1,
        "no retry without retry configs"
    );
    assert_eq!(
        f.edge.stats.streams.load(Ordering::SeqCst),
        0,
        "no HTTP/2 request"
    );
    assert_eq!(f.edge.stats.origin_connections.load(Ordering::SeqCst), 0);
    assert_eq!(accepted.load(Ordering::SeqCst), 0);
    assert!(!aegis_client::ech_policy::has_rotation(&relay));
}

#[tokio::test]
async fn retry_configs_that_change_the_pinned_public_name_are_refused() {
    let f = fixture().await;
    let pinned = EchKey::generate(4, c"cover.edge.test");
    let foreign = EchKey::generate(5, c"other-cover.edge.test");
    let server = Arc::new(EchServer::new(
        &f.cert_der,
        &f.private_der,
        &[(&foreign, true)],
    ));
    let edge = ech_edge(vec![server], f.edge.clone()).await;
    let mut relay = f.settings.relay.clone();
    relay.server = edge.address.to_string();
    relay.server_name = EDGE.into();
    relay.ech_config_list_base64 = Some(pinned.base64());
    let (target, accepted, _target) = echo_target().await;
    assert!(round_trip(&relay, target).await.is_err());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(edge.accepted.load(Ordering::SeqCst), 1);
    assert_eq!(f.edge.stats.streams.load(Ordering::SeqCst), 0);
    assert_eq!(accepted.load(Ordering::SeqCst), 0);
    assert!(!aegis_client::ech_policy::has_rotation(&relay));
}

#[tokio::test]
async fn a_rejected_retry_fails_closed_without_a_loop_and_clears_the_rotation() {
    let f = fixture().await;
    let stale = EchKey::generate(9, c"cover.edge.test");
    let rotated = EchKey::generate(10, c"cover.edge.test");
    // First connection: rejection with authenticated retry configs.
    // Every later connection: an edge that has lost ECH entirely.
    let first = Arc::new(EchServer::new(
        &f.cert_der,
        &f.private_der,
        &[(&rotated, true)],
    ));
    let later = Arc::new(EchServer::new(&f.cert_der, &f.private_der, &[]));
    let edge = ech_edge(vec![first, later], f.edge.clone()).await;
    let mut relay = f.settings.relay.clone();
    relay.server = edge.address.to_string();
    relay.server_name = EDGE.into();
    relay.ech_config_list_base64 = Some(stale.base64());
    let (target, accepted, _target) = echo_target().await;
    assert!(round_trip(&relay, target).await.is_err());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(edge.accepted.load(Ordering::SeqCst), 2, "exactly one retry");
    assert_eq!(f.edge.stats.streams.load(Ordering::SeqCst), 0);
    assert_eq!(accepted.load(Ordering::SeqCst), 0);
    assert!(!aegis_client::ech_policy::has_rotation(&relay));
}
