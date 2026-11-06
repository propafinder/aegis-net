//! Real QUIC TLS handshakes against an in-memory AWS-LC ECH server.
//!
//! The client uses the production MASQUE TLS builder. No socket, thread,
//! external server, GREASE acceptance surrogate or permissive verifier is used.
//! Only public fixture certificates are written for the production CA-file API;
//! private certificate/HPKE keys and exporter bytes remain in memory.

#![cfg(feature = "chrome-like-tls")]

use std::collections::VecDeque;
use std::ffi::{c_char, c_int, c_void, CStr};
use std::mem::MaybeUninit;
use std::ptr::{self, NonNull};
use std::sync::Arc;

use aws_lc_sys as ssl;
use base64::Engine;
use rcgen::{
    generate_simple_self_signed, Certificate, CertificateParams, CertifiedKey, DnType, KeyPair,
};
use rustls::quic::{ClientConnection, Connection, KeyChange, Version};
use rustls::{CertificateError, Error, PeerIncompatible};
use zeroize::Zeroizing;

use super::rustls_masque_tls_config;
use aegis_core::{RelaySettings, RelayTlsBackend};

const RELAY: &str = "relay.example";
const COVER: &str = "cover.example";
const INITIAL: ssl::ssl_encryption_level_t = ssl::ssl_encryption_level_t_ssl_encryption_initial;
const HANDSHAKE: ssl::ssl_encryption_level_t = ssl::ssl_encryption_level_t_ssl_encryption_handshake;
const APPLICATION: ssl::ssl_encryption_level_t =
    ssl::ssl_encryption_level_t_ssl_encryption_application;
const FLIGHT_CAP: usize = 64 * 1024;
const BYTE_CAP: usize = 256 * 1024;
const H3: &[u8] = b"h3";
const SERVER_PARAMS: &[u8] = &[0x04, 0x01, 0x00];
const CLIENT_PARAMS: &[u8] = &[0x05, 0x01, 0x00];

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
    };
}

owned_native!(Context, ssl::SSL_CTX, ssl::SSL_CTX_free);
owned_native!(Session, ssl::SSL, ssl::SSL_free);
owned_native!(HpkeKey, ssl::EVP_HPKE_KEY, ssl::EVP_HPKE_KEY_free);
owned_native!(EchKeys, ssl::SSL_ECH_KEYS, ssl::SSL_ECH_KEYS_free);
owned_native!(PrivateKey, ssl::EVP_PKEY, ssl::EVP_PKEY_free);

struct NativeBytes(*mut u8);
impl Drop for NativeBytes {
    fn drop(&mut self) {
        unsafe { ssl::OPENSSL_free(self.0.cast()) }
    }
}

struct EchFixture {
    keys: EchKeys,
    list: Vec<u8>,
}

impl EchFixture {
    fn new() -> Self {
        unsafe {
            let key = HpkeKey::new(ssl::EVP_HPKE_KEY_new());
            assert_eq!(
                ssl::EVP_HPKE_KEY_generate(key.as_ptr(), ssl::EVP_hpke_x25519_hkdf_sha256(),),
                1,
                "generate real server ECH key"
            );
            let mut raw = ptr::null_mut();
            let mut length = 0;
            let result = ssl::SSL_marshal_ech_config(
                &mut raw,
                &mut length,
                42,
                key.as_ptr(),
                c"cover.example".as_ptr(),
                64,
            );
            let bytes = NativeBytes(raw);
            assert_eq!(result, 1, "marshal supported ECHConfig");
            assert!(!bytes.0.is_null() && (1..=16 * 1024).contains(&length));
            let config = std::slice::from_raw_parts(bytes.0, length);
            let keys = EchKeys::new(ssl::SSL_ECH_KEYS_new());
            assert_eq!(
                ssl::SSL_ECH_KEYS_add(
                    keys.as_ptr(),
                    1,
                    config.as_ptr(),
                    config.len(),
                    key.as_ptr()
                ),
                1,
                "bind ECHConfig to real private key"
            );
            let mut list = (config.len() as u16).to_be_bytes().to_vec();
            list.extend_from_slice(config);
            // ECH_KEYS owns its copy of the private key; the public list has no
            // private key bytes. Both the original key and allocated config
            // buffer are released on this return, including assertion unwinds.
            Self { keys, list }
        }
    }
}

#[derive(Default)]
struct Wire {
    pending: VecDeque<(ssl::ssl_encryption_level_t, Vec<u8>)>,
    sent_bytes: usize,
    read_levels: u8,
    write_levels: u8,
    alert: Option<u8>,
}

// ex_data[0] is the documented SSL application-data slot. Each Session owns a
// live, immovable Box<Wire>; callbacks execute synchronously on the test thread.
unsafe extern "C" fn add_handshake_data(
    session: *mut ssl::SSL,
    level: ssl::ssl_encryption_level_t,
    data: *const u8,
    length: usize,
) -> c_int {
    let Some(wire) = (ssl::SSL_get_ex_data(session, 0) as *mut Wire).as_mut() else {
        return 0;
    };
    if data.is_null()
        || !matches!(level, INITIAL | HANDSHAKE | APPLICATION)
        || length > FLIGHT_CAP
        || wire.sent_bytes.saturating_add(length) > BYTE_CAP
        || wire.pending.len() >= 32
    {
        return 0;
    }
    wire.sent_bytes += length;
    wire.pending
        .push_back((level, std::slice::from_raw_parts(data, length).to_vec()));
    1
}

unsafe fn mark_secret(
    session: *mut ssl::SSL,
    level: ssl::ssl_encryption_level_t,
    cipher: *const ssl::SSL_CIPHER,
    secret: *const u8,
    length: usize,
    read: bool,
) -> c_int {
    let Some(wire) = (ssl::SSL_get_ex_data(session, 0) as *mut Wire).as_mut() else {
        return 0;
    };
    if !matches!(level, HANDSHAKE | APPLICATION)
        || cipher.is_null()
        || secret.is_null()
        || !(1..=64).contains(&length)
    {
        return 0;
    }
    // Crypto-stream TLS testing does not packetize or copy traffic secrets.
    // Record only the genuine level transition; never log a key/secret.
    if read {
        wire.read_levels |= 1 << level;
    } else {
        wire.write_levels |= 1 << level;
    }
    1
}

unsafe extern "C" fn read_secret(
    session: *mut ssl::SSL,
    level: ssl::ssl_encryption_level_t,
    cipher: *const ssl::SSL_CIPHER,
    secret: *const u8,
    length: usize,
) -> c_int {
    mark_secret(session, level, cipher, secret, length, true)
}

unsafe extern "C" fn write_secret(
    session: *mut ssl::SSL,
    level: ssl::ssl_encryption_level_t,
    cipher: *const ssl::SSL_CIPHER,
    secret: *const u8,
    length: usize,
) -> c_int {
    mark_secret(session, level, cipher, secret, length, false)
}

unsafe extern "C" fn flush_flight(_session: *mut ssl::SSL) -> c_int {
    1
}

unsafe extern "C" fn send_alert(
    session: *mut ssl::SSL,
    _level: ssl::ssl_encryption_level_t,
    alert: u8,
) -> c_int {
    let Some(wire) = (ssl::SSL_get_ex_data(session, 0) as *mut Wire).as_mut() else {
        return 0;
    };
    wire.alert = Some(alert);
    1
}

static QUIC_METHOD: ssl::SSL_QUIC_METHOD = ssl::SSL_QUIC_METHOD {
    set_read_secret: Some(read_secret),
    set_write_secret: Some(write_secret),
    add_handshake_data: Some(add_handshake_data),
    flush_flight: Some(flush_flight),
    send_alert: Some(send_alert),
};

unsafe extern "C" fn select_h3(
    _session: *mut ssl::SSL,
    output: *mut *const u8,
    output_length: *mut u8,
    input: *const u8,
    input_length: u32,
    _argument: *mut c_void,
) -> c_int {
    if input.is_null()
        || output.is_null()
        || output_length.is_null()
        || input_length != 3
        || std::slice::from_raw_parts(input, 3) != b"\x02h3"
    {
        return ssl::SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    *output = H3.as_ptr();
    *output_length = H3.len() as u8;
    ssl::SSL_TLSEXT_ERR_OK
}

struct Server {
    // Field order frees SSL before the context and its referenced Wire.
    session: Session,
    _context: Context,
    wire: Box<Wire>,
}

impl Server {
    fn new(cert: &Certificate, private_der: &[u8], ech: Option<&EchFixture>) -> Self {
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
                ssl::SSL_CTX_set_quic_method(context.as_ptr(), &QUIC_METHOD),
                1
            );
            assert_eq!(
                ssl::SSL_CTX_use_certificate_ASN1(
                    context.as_ptr(),
                    cert.der().len(),
                    cert.der().as_ptr(),
                ),
                1
            );
            let mut cbs = MaybeUninit::<ssl::CBS>::uninit();
            ssl::CBS_init(cbs.as_mut_ptr(), private_der.as_ptr(), private_der.len());
            let mut cbs = cbs.assume_init();
            let private = PrivateKey::new(ssl::EVP_parse_private_key(&mut cbs));
            assert_eq!(
                ssl::CBS_len(&cbs),
                0,
                "consume the exact fixture private key"
            );
            assert_eq!(
                ssl::SSL_CTX_use_PrivateKey(context.as_ptr(), private.as_ptr()),
                1
            );
            assert_eq!(ssl::SSL_CTX_check_private_key(context.as_ptr()), 1);
            if let Some(ech) = ech {
                assert_eq!(
                    ssl::SSL_CTX_set1_ech_keys(context.as_ptr(), ech.keys.as_ptr()),
                    1
                );
            }
            ssl::SSL_CTX_set_alpn_select_cb(context.as_ptr(), Some(select_h3), ptr::null_mut());
            let session = Session::new(ssl::SSL_new(context.as_ptr()));
            let mut wire = Box::<Wire>::default();
            assert_eq!(
                ssl::SSL_set_ex_data(session.as_ptr(), 0, (&mut *wire as *mut Wire).cast()),
                1
            );
            ssl::SSL_set_quic_use_legacy_codepoint(session.as_ptr(), 0);
            assert_eq!(
                ssl::SSL_set_quic_transport_params(
                    session.as_ptr(),
                    SERVER_PARAMS.as_ptr(),
                    SERVER_PARAMS.len(),
                ),
                1
            );
            ssl::SSL_set_accept_state(session.as_ptr());
            Self {
                session,
                _context: context,
                wire,
            }
        }
    }

    fn step(&mut self) {
        unsafe {
            ssl::ERR_clear_error();
            let result = ssl::SSL_do_handshake(self.session.as_ptr());
            if result != 1 {
                let error = ssl::SSL_get_error(self.session.as_ptr(), result);
                assert_eq!(
                    error,
                    ssl::SSL_ERROR_WANT_READ,
                    "unexpected server TLS failure"
                );
            }
        }
        assert!(self.wire.alert.is_none(), "server issued a fatal alert");
    }

    fn finished(&self) -> bool {
        unsafe { ssl::SSL_is_init_finished(self.session.as_ptr()) == 1 }
    }

    fn accepted_ech(&self) -> bool {
        unsafe { ssl::SSL_ech_accepted(self.session.as_ptr()) == 1 }
    }

    fn negotiated_h3(&self) -> bool {
        unsafe {
            let mut protocol = ptr::null();
            let mut length = 0;
            ssl::SSL_get0_alpn_selected(self.session.as_ptr(), &mut protocol, &mut length);
            !protocol.is_null()
                && length == H3.len() as u32
                && std::slice::from_raw_parts(protocol, length as usize) == H3
        }
    }

    fn server_name(&self) -> &str {
        unsafe {
            let name = ssl::SSL_get_servername(self.session.as_ptr(), 0);
            assert!(!name.is_null(), "server received no SNI");
            CStr::from_ptr(name).to_str().expect("fixture DNS SNI")
        }
    }

    fn exporter(&self) -> Zeroizing<[u8; 32]> {
        const LABEL: &[u8] = b"aegis-masque-ech-test";
        let mut exported = Zeroizing::new([0; 32]);
        unsafe {
            assert_eq!(
                ssl::SSL_export_keying_material(
                    self.session.as_ptr(),
                    exported.as_mut_ptr(),
                    exported.len(),
                    LABEL.as_ptr().cast::<c_char>(),
                    LABEL.len(),
                    ptr::null(),
                    0,
                    0,
                ),
                1,
                "server exporter after Finished"
            );
        }
        exported
    }
}

struct Fixture {
    cert: Certificate,
    private_der: Zeroizing<Vec<u8>>,
    ech: EchFixture,
    directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec![RELAY.into(), COVER.into()])
                .expect("fixture certificate");
        Self {
            cert,
            private_der: Zeroizing::new(key_pair.serialize_der()),
            ech: EchFixture::new(),
            directory: tempfile::tempdir().expect("public CA fixture directory"),
        }
    }

    fn client(&self, name: &str, trust_server: bool) -> Connection {
        let ca = self.directory.path().join(if trust_server {
            "trusted.pem"
        } else {
            "wrong.pem"
        });
        let pem = if trust_server {
            self.cert.pem()
        } else {
            let key_pair = KeyPair::generate().expect("unrelated trust anchor key");
            let mut params = CertificateParams::new(vec![RELAY.into(), COVER.into()])
                .expect("unrelated trust anchor parameters");
            // rcgen's default subject is shared by all self-signed fixtures.
            // A distinct issuer makes this an unknown-CA case rather than a
            // matching-issuer, wrong-key signature failure.
            params
                .distinguished_name
                .push(DnType::CommonName, "unrelated MASQUE test CA");
            params
                .self_signed(&key_pair)
                .expect("unrelated trust anchor")
                .pem()
        };
        std::fs::write(&ca, pem).expect("write public certificate only");
        let settings = RelaySettings {
            server_name: name.into(),
            tls_backend: RelayTlsBackend::Rustls,
            masque_ca_cert: Some(ca),
            ech_config_list_base64: Some(
                base64::engine::general_purpose::STANDARD.encode(&self.ech.list),
            ),
            ..RelaySettings::default()
        };
        let authority =
            super::super::relay_transport_authority(&settings).expect("fixture DNS authority");
        let config =
            rustls_masque_tls_config(&settings, &authority).expect("production ECH config");
        assert_eq!(config.alpn_protocols, vec![H3.to_vec()]);
        let client = ClientConnection::new(
            Arc::new(config),
            Version::V1,
            authority.tls_server_name,
            CLIENT_PARAMS.to_vec(),
        )
        .expect("real required-ECH QUIC client");
        assert!(client.zero_rtt_keys().is_none(), "no 0-RTT offer");
        Connection::Client(client)
    }
}

struct ClientFlight {
    level: ssl::ssl_encryption_level_t,
    sent_bytes: usize,
    one_rtt: bool,
}

fn flush_client(client: &mut Connection, server: &mut Server, state: &mut ClientFlight) -> bool {
    let mut progressed = false;
    for _ in 0..4 {
        let mut flight = Vec::new();
        let change = client.write_hs(&mut flight);
        assert!(flight.len() <= FLIGHT_CAP, "client flight bound");
        state.sent_bytes += flight.len();
        assert!(state.sent_bytes <= BYTE_CAP, "client handshake byte bound");
        if !flight.is_empty() {
            unsafe {
                assert_eq!(
                    ssl::SSL_quic_read_level(server.session.as_ptr()),
                    state.level
                );
                assert_eq!(
                    ssl::SSL_provide_quic_data(
                        server.session.as_ptr(),
                        state.level,
                        flight.as_ptr(),
                        flight.len(),
                    ),
                    1,
                    "provide genuine client CRYPTO flight"
                );
            }
            progressed = true;
        }
        match change {
            Some(KeyChange::Handshake { .. }) => {
                state.level = HANDSHAKE;
                progressed = true;
            }
            Some(KeyChange::OneRtt { .. }) => {
                state.level = APPLICATION;
                state.one_rtt = true;
                progressed = true;
            }
            None => return progressed,
        }
    }
    panic!("client key-change iteration budget exhausted");
}

/// Transport only CRYPTO-stream plaintext at the genuine key-change boundaries.
/// Both TLS implementations still do their own transcript, HPKE, certificate,
/// signature, ECH-confirmation and Finished verification.
fn handshake(client: &mut Connection, server: &mut Server) -> Result<(), Error> {
    let mut state = ClientFlight {
        level: INITIAL,
        sent_bytes: 0,
        one_rtt: false,
    };
    for _ in 0..32 {
        let mut progressed = flush_client(client, server, &mut state);
        server.step();
        while let Some((level, flight)) = server.wire.pending.pop_front() {
            assert!(matches!(level, INITIAL | HANDSHAKE | APPLICATION));
            // Keep encryption levels separate, as required by rustls::quic.
            client.read_hs(&flight)?;
            progressed = true;
            // Consume the Handshake key change immediately after ServerHello,
            // before a later server flight can queue client Finished. This
            // preserves rustls's actual level-boundary ordering.
            flush_client(client, server, &mut state);
        }
        if !client.is_handshaking() && server.finished() {
            assert!(state.one_rtt, "client produced real 1-RTT keys");
            assert_ne!(server.wire.read_levels & (1 << APPLICATION), 0);
            assert_ne!(server.wire.write_levels & (1 << APPLICATION), 0);
            return Ok(());
        }
        assert!(progressed, "in-memory QUIC TLS made no progress");
    }
    panic!("in-memory QUIC TLS iteration budget exhausted");
}

#[test]
fn required_ech_quic_accepts_real_inner_hello_finished_and_h3() {
    let fixture = Fixture::new();
    let mut client = fixture.client(RELAY, true);
    let mut server = Server::new(&fixture.cert, &fixture.private_der, Some(&fixture.ech));
    handshake(&mut client, &mut server).expect("real ECH QUIC handshake");
    // rustls QUIC has no public ech_status() accessor. Actual server acceptance
    // plus successful client Finished is the checked result, never a fake status.
    assert!(
        server.accepted_ech(),
        "AWS-LC must decrypt and accept real ECH"
    );
    assert_eq!(
        server.server_name(),
        RELAY,
        "server processed encrypted inner SNI"
    );
    assert!(server.finished() && !client.is_handshaking());
    assert!(server.negotiated_h3());
    assert_eq!(client.alpn_protocol(), Some(H3));
    assert_eq!(
        client.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    assert_eq!(client.quic_transport_parameters(), Some(SERVER_PARAMS));
    let exported = Zeroizing::new(
        client
            .export_keying_material([0u8; 32], b"aegis-masque-ech-test", None)
            .expect("client exporter after Finished"),
    );
    // assert_eq would dump secret exporter bytes on a failing test.
    assert!(
        exported.as_slice() == server.exporter().as_slice(),
        "TLS exporter disagreement"
    );
    let Connection::Client(client) = client else {
        unreachable!()
    };
    assert!(!client.is_early_data_accepted());
    assert_eq!(client.tls13_tickets_received(), 0);
}

#[test]
fn required_ech_quic_rejects_an_authenticated_server_without_ech_at_finished() {
    let fixture = Fixture::new();
    let mut client = fixture.client(RELAY, true);
    // Same trusted certificate covers both relay and cover names. The failure
    // must be ECH rejection, not a certificate/name or ALPN setup failure.
    let mut server = Server::new(&fixture.cert, &fixture.private_der, None);
    let error = handshake(&mut client, &mut server).expect_err("ECH-less peer must fail");
    assert!(matches!(
        error,
        Error::PeerIncompatible(PeerIncompatible::ServerRejectedEncryptedClientHello(_))
    ));
    assert_eq!(
        client.alert(),
        Some(rustls::AlertDescription::EncryptedClientHelloRequired)
    );
    assert!(!server.accepted_ech());
    assert_eq!(server.server_name(), COVER, "only outer SNI was available");
    assert!(
        !server.finished(),
        "client never confirmed a successful session"
    );
}

#[test]
fn required_ech_quic_still_rejects_wrong_ca() {
    let fixture = Fixture::new();
    let mut client = fixture.client(RELAY, false);
    let mut server = Server::new(&fixture.cert, &fixture.private_der, Some(&fixture.ech));
    let error = handshake(&mut client, &mut server).expect_err("wrong CA must fail");
    assert!(
        matches!(
            error,
            Error::InvalidCertificate(CertificateError::UnknownIssuer)
        ),
        "unexpected certificate-verification error: {error:?}"
    );
    assert!(server.accepted_ech(), "negative reaches the real ECH path");
    assert!(!server.finished());
}

#[test]
fn required_ech_quic_still_rejects_wrong_inner_dns_name() {
    let fixture = Fixture::new();
    let mut client = fixture.client("wrong.example", true);
    let mut server = Server::new(&fixture.cert, &fixture.private_der, Some(&fixture.ech));
    let error = handshake(&mut client, &mut server).expect_err("wrong inner DNS name must fail");
    assert!(matches!(
        error,
        Error::InvalidCertificate(
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. }
        )
    ));
    assert!(server.accepted_ech(), "negative reaches the real ECH path");
    assert_eq!(server.server_name(), "wrong.example");
    assert!(!server.finished());
}
