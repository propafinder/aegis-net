//! Self-tests of the multi-stream relay (B-06 S16h-1): the stream cap, the
//! Activity idle rule, the strike rule, connection-end aborts, the fault
//! switches and the frame tap, driven by a plain H2 client over loopback.
use super::*;
use crate::test_relay::{RelayIdentity, TestRelay};
use aegis_core::secure_channel::{ClientSettings, OpenRequest, Transport};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose, PKCS_ED25519};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinHandle as TaskHandle,
};
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{CertificateDer, ServerName},
    },
    TlsConnector,
};

type Inner = tokio_rustls::client::TlsStream<GrpcIo<H2Stream>>;
type Client = h2::client::SendRequest<Bytes>;
type Driver = TaskHandle<Result<(), h2::Error>>;

/// The device side: the relay's outer certificate and an inner client.
struct Kit {
    outer: CertificateDer<'static>,
    inner: secure_channel::Client,
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// A pooled relay trusting one freshly issued device, and that device.
fn relay(config: PoolConfig) -> (PooledRelay, Kit) {
    let listener = TestRelay::bind();
    let outer = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let (ca, ca_key) = crate::test_fixture::signing_ca();
    let signed = |name: &str, usage| {
        let mut params = CertificateParams::new(vec![name.into()]).unwrap();
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![usage];
        let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let cert = params.signed_by(&key, &ca, &ca_key).unwrap();
        (cert, key)
    };
    let (server, server_key) = signed("inner.test", ExtendedKeyUsagePurpose::ServerAuth);
    let (device, device_key) = signed("device.test", ExtendedKeyUsagePurpose::ClientAuth);
    let digest = Sha256::digest(device.der().as_ref())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let identity = RelayIdentity::new(
        outer.cert.der().clone(),
        outer.key_pair.serialize_der(),
        server.pem().as_bytes(),
        server_key.serialize_pem().as_bytes(),
        ca.pem().as_bytes(),
        digest,
    );
    let inner = secure_channel::Client::from_captured_pem(
        &ClientSettings {
            server_name: "inner.test".into(),
            server_ca: PathBuf::new(),
            cert: PathBuf::new(),
            key: PathBuf::new(),
        },
        ca.pem().as_bytes(),
        device.pem().as_bytes(),
        device_key.serialize_pem().as_bytes(),
    )
    .unwrap();
    let kit = Kit {
        outer: outer.cert.der().clone(),
        inner,
    };
    (TestRelay::spawn_streams(listener, identity, config), kit)
}

/// TCP, outer TLS (ALPN h2) and the H2 handshake; the connection is not
/// polled yet.
async fn dial(
    relay: SocketAddr,
    kit: &Kit,
) -> (
    Client,
    h2::client::Connection<tokio_rustls::client::TlsStream<TcpStream>, Bytes>,
) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(kit.outer.clone()).unwrap();
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let tcp = TcpStream::connect(relay).await.unwrap();
    let tls = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    h2::client::handshake(tls).await.unwrap()
}

async fn connect(relay: SocketAddr, kit: &Kit) -> (Client, Driver) {
    let (client, connection) = dial(relay, kit).await;
    (client, tokio::spawn(connection))
}

fn carrier_request() -> http::Request<()> {
    http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("https://localhost{}", secure_channel::GRPC_PATH))
        .header("content-type", "application/grpc")
        .body(())
        .unwrap()
}

/// One carrier stream, answered 200.
async fn carrier(client: &mut Client) -> GrpcIo<H2Stream> {
    std::future::poll_fn(|cx| client.poll_ready(cx))
        .await
        .unwrap();
    let (response, send) = client.send_request(carrier_request(), false).unwrap();
    let response = tokio::time::timeout(Duration::from_secs(5), response)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    GrpcIo::new(H2Stream::new(send, response.into_body()))
}

async fn authenticate(client: &mut Client, kit: &Kit) -> Inner {
    let carrier = carrier(client).await;
    kit.inner.connect(carrier).await.unwrap()
}

async fn write_open(inner: &mut Inner) {
    let open = OpenRequest {
        version: 1,
        host: "echo.test".into(),
        port: 7,
        transport: Transport::Tcp,
    };
    secure_channel::write_open(inner, &open).await.unwrap();
    inner.flush().await.unwrap();
}

/// An authenticated stream whose Open was accepted with status 0.
async fn open_echo(client: &mut Client, kit: &Kit) -> Inner {
    let mut inner = authenticate(client, kit).await;
    write_open(&mut inner).await;
    assert_eq!(inner.read_u8().await.unwrap(), 0);
    inner
}

async fn echo(inner: &mut Inner, bytes: &[u8]) {
    inner.write_all(bytes).await.unwrap();
    inner.flush().await.unwrap();
    let mut echoed = vec![0; bytes.len()];
    tokio::time::timeout(Duration::from_secs(5), inner.read_exact(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(echoed, bytes);
}

/// End an echo stream as a client does: FIN, then read the relay's EOF.
async fn finish(mut inner: Inner) {
    inner.shutdown().await.unwrap();
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), inner.read_to_end(&mut rest)).await;
}

/// The device's ClientHello for the inner server, as raw TLS bytes.
fn client_hello() -> Vec<u8> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let mut connection = rustls::ClientConnection::new(
        Arc::new(config),
        ServerName::try_from("inner.test").unwrap(),
    )
    .unwrap();
    let mut hello = Vec::new();
    connection.write_tls(&mut hello).unwrap();
    hello
}

fn between(value: Duration, low_ms: u64, high_ms: u64) -> bool {
    (Duration::from_millis(low_ms)..=Duration::from_millis(high_ms)).contains(&value)
}

#[test]
fn pooled_relay_self_test_refuses_the_33rd_concurrent_stream() {
    // At aegis-core's default 16 handshakes per peer (the default config
    // runs relay-a's 32), so its handshake cap is met as well.
    let (relay, kit) = relay(PoolConfig {
        inner_admission: AdmissionLimits::default(),
        ..PoolConfig::default()
    });
    runtime().block_on(async {
        let (mut client, connection) = dial(relay.address(), &kit).await;
        // Until the relay's SETTINGS arrive the client assumes no stream
        // limit, so all 33 requests leave together.
        let mut opened: Vec<_> = (0..33)
            .map(|_| client.send_request(carrier_request(), false).unwrap())
            .collect();
        let driver = tokio::spawn(connection);
        let (refused, _send) = opened.pop().unwrap();
        let error = tokio::time::timeout(Duration::from_secs(5), refused)
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.reason(), Some(Reason::REFUSED_STREAM));
        let mut held = Vec::new();
        for (response, send) in opened {
            let response = tokio::time::timeout(Duration::from_secs(5), response)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response.status(), http::StatusCode::OK);
            held.push((response, send));
        }
        assert!(
            wait_until(Duration::from_secs(2), || (relay.handshake_caps() == 16)
                .then_some(()))
            .await
            .is_some()
        );
        assert!(!driver.is_finished());
    });
    assert_eq!(relay.conns(), 1);
    assert_eq!(relay.streams(), 32);
    let stats = relay.connection(0);
    assert_eq!(stats.max_concurrent_streams(), 32);
    // aegis-core's per-peer handshake cap: 16 in handshake, 16 ended after
    // their 200.
    assert_eq!(relay.handshakes().high_water(), 16);
    assert_eq!(stats.handshakes().high_water(), 16);
    assert_eq!(
        relay
            .events()
            .iter()
            .filter(|event| event.step == StreamStep::HandshakeCapped)
            .count(),
        16
    );
    // The relay accepted streams 1, 3, ..., 63 on connection 0, in order.
    let accepted: Vec<u32> = relay
        .events()
        .iter()
        .filter(|event| event.step == StreamStep::Accepted)
        .inspect(|event| assert_eq!(event.conn, 0))
        .map(|event| event.id)
        .collect();
    assert_eq!(accepted, (0..32).map(|n| 2 * n + 1).collect::<Vec<u32>>());
    // The tap: the library's refusal of stream 65 (the 33rd odd ID), the
    // relay's SETTINGS and connection window, and the client's SETTINGS.
    assert!(stats
        .resets(false)
        .contains(&(65, u32::from(Reason::REFUSED_STREAM))));
    let settings = stats.settings(false);
    assert_eq!(settings.len(), 1);
    for entry in [(0x3, 32), (0x4, 128 * 1024), (0x6, 8192)] {
        assert!(settings[0].contains(&entry), "{settings:?}");
    }
    assert!(!settings[0].iter().any(|(id, _)| *id == 0x8));
    assert!(stats
        .window_updates(false)
        .contains(&(0, 128 * 1024 - 65_535)));
    assert_eq!(stats.settings(true).len(), 1);
    assert!(stats
        .frames()
        .iter()
        .any(|frame| frame.from_client && frame.is_ack()));
}

#[test]
fn pooled_relay_self_test_idles_out_only_after_the_last_authenticated_stream() {
    let (relay, kit) = relay(PoolConfig::default());
    let stats = runtime().block_on(async {
        let (mut client, driver) = connect(relay.address(), &kit).await;
        let mut live = open_echo(&mut client, &kit).await;
        let stats = relay.connection(0);
        // Past the initial admission deadline (outer TLS + 5 s) the live
        // authenticated stream still holds the connection open.
        for round in 0..3u8 {
            tokio::time::sleep(Duration::from_secs(2)).await;
            echo(&mut live, &[round; 64]).await;
            assert!(stats.closed().is_none());
        }
        assert!(stats.last_completed().is_none());
        finish(live).await;
        let (closed_at, close) = relay.wait_closed(0, Duration::from_secs(7)).await.unwrap();
        assert_eq!(close, Close::Idle);
        let completed = stats.last_completed().unwrap();
        let idle = closed_at.duration_since(completed);
        assert!(between(idle, 4_900, 5_100), "{idle:?}");
        // The client sees the connection end.
        let ended = tokio::time::timeout(Duration::from_secs(2), driver).await;
        assert!(ended.is_ok());
        drop(client);
        stats
    });
    assert_eq!(stats.live_streams(), 0);
    assert_eq!(relay.steps(0).last(), Some(&StreamStep::Ended));
    assert_eq!(relay.stream_closed_resets(), 0);
    assert_eq!(relay.strikes(), 0);
}

#[test]
fn pooled_relay_self_test_strikes_only_at_its_own_accept_deadline() {
    let (relay, kit) = relay(PoolConfig::default());
    runtime().block_on(async {
        let (mut client, _driver) = connect(relay.address(), &kit).await;
        // A live authenticated stream: later streams inherit now + 5 s.
        let mut live = open_echo(&mut client, &kit).await;
        let stats = relay.connection(0);
        // Stream 1: the client resets its stream in the middle of the inner
        // handshake, once the relay's first flight has arrived.
        let mut reset = carrier(&mut client).await;
        reset.write_all(&client_hello()).await.unwrap();
        reset.flush().await.unwrap();
        let mut flight = [0u8; 512];
        let read = tokio::time::timeout(Duration::from_secs(5), reset.read(&mut flight))
            .await
            .unwrap()
            .unwrap();
        assert!(read > 0);
        assert_eq!(stats.handshakes().current(), 1);
        drop(reset);
        assert!(relay
            .wait_step(1, StreamStep::HandshakeFailed, Duration::from_secs(2))
            .await
            .is_some());
        assert!(stats.resets(true).contains(&(3, u32::from(Reason::CANCEL))));
        assert_eq!(relay.strikes(), 0);
        assert_eq!(stats.handshakes().current(), 0);
        // Stream 2: the device never sends its ClientHello; the stream's
        // own accept deadline fires 5 s after its accept.
        let asked = std::time::Instant::now();
        let _stalled = carrier(&mut client).await;
        let struck = relay
            .wait_step(2, StreamStep::Struck, Duration::from_secs(6))
            .await
            .unwrap();
        let after = struck.duration_since(asked);
        assert!(between(after, 4_900, 5_300), "{after:?}");
        assert_eq!(relay.strikes(), 1);
        assert_eq!(stats.handshakes().current(), 0);
        // The live stream is untouched.
        echo(&mut live, b"after the strike").await;
        assert!(stats.closed().is_none());
    });
}

#[test]
fn pooled_relay_self_test_streams_inherit_the_connection_idle_deadline() {
    let (relay, kit) = relay(PoolConfig::default());
    runtime().block_on(async {
        let (mut client, _driver) = connect(relay.address(), &kit).await;
        finish(open_echo(&mut client, &kit).await).await;
        let stats = relay.connection(0);
        let completed = wait_until(Duration::from_secs(2), || stats.last_completed())
            .await
            .unwrap();
        // Two seconds into the idle period a stream arrives and never sends
        // its ClientHello. It inherits the connection's idle deadline
        // (completed + 5 s), not its own accept + 5 s: it strikes at the
        // instant the connection idles out.
        tokio::time::sleep(Duration::from_secs(2)).await;
        let _stalled = carrier(&mut client).await;
        let struck = relay
            .wait_step(1, StreamStep::Struck, Duration::from_secs(4))
            .await
            .unwrap();
        let after = struck.duration_since(completed);
        assert!(between(after, 4_900, 5_150), "{after:?}");
        let (closed_at, close) = relay.wait_closed(0, Duration::from_secs(2)).await.unwrap();
        assert_eq!(close, Close::Idle);
        assert!(between(closed_at.duration_since(completed), 4_900, 5_150));
    });
    assert_eq!(relay.strikes(), 1);
}

#[test]
fn pooled_relay_self_test_expired_streams_end_without_a_strike() {
    let config = PoolConfig {
        admission_timeout: Duration::from_secs(1),
        ..PoolConfig::default()
    };
    let (relay, kit) = relay(config);
    runtime().block_on(async {
        let (mut client, _driver) = connect(relay.address(), &kit).await;
        // A live authenticated stream: later streams inherit now + 1 s and
        // the connection never idles out.
        let mut live = open_echo(&mut client, &kit).await;
        let stats = relay.connection(0);
        // Stream 1 (ID 3) is accepted past its inherited deadline: as at
        // grpc.rs:347 it ends with no 200.
        relay.accept_past_deadline(1);
        let (response, _send) = client.send_request(carrier_request(), false).unwrap();
        let answered = tokio::time::timeout(Duration::from_secs(2), response)
            .await
            .unwrap();
        assert!(answered.is_err());
        assert!(relay
            .wait_step(1, StreamStep::Expired, Duration::from_secs(2))
            .await
            .is_some());
        // Stream 2 (ID 5): the 200, then its deadline passes before the
        // handshake permit: as at secure.rs:148 it ends with no strike.
        relay.deadline_passes_after_200(1);
        let asked = std::time::Instant::now();
        let late = carrier(&mut client).await;
        let connected = tokio::time::timeout(Duration::from_secs(3), kit.inner.connect(late));
        assert!(connected.await.unwrap().is_err());
        let expired = relay
            .wait_step(2, StreamStep::Expired, Duration::from_secs(2))
            .await
            .unwrap();
        let after = expired.duration_since(asked);
        assert!(between(after, 900, 1_500), "{after:?}");
        // Neither expired stream entered the inner handshake.
        assert_eq!(stats.handshakes().high_water(), 1);
        echo(&mut live, b"after both expiries").await;
        assert!(stats.closed().is_none());
    });
    assert_eq!(relay.steps(1), [StreamStep::Accepted, StreamStep::Expired]);
    assert_eq!(
        relay.steps(2),
        [
            StreamStep::Accepted,
            StreamStep::Responded,
            StreamStep::Expired
        ]
    );
    assert_eq!(relay.strikes(), 0);
}

#[test]
fn pooled_relay_self_test_a_frozen_connection_never_idles_out() {
    let timeout = Duration::from_secs(1);
    let config = PoolConfig {
        admission_timeout: timeout,
        ..PoolConfig::default()
    };
    let (relay, kit) = relay(config);
    runtime().block_on(async {
        let (mut client, driver) = connect(relay.address(), &kit).await;
        // The only authenticated stream ends: unfrozen, the connection
        // would idle out at completed + 1 s.
        finish(open_echo(&mut client, &kit).await).await;
        let stats = relay.connection(0);
        let completed = wait_until(Duration::from_secs(2), || stats.last_completed())
            .await
            .unwrap();
        relay.freeze(0);
        assert!(
            wait_until(Duration::from_secs(2), || stats.is_frozen().then_some(()))
                .await
                .is_some()
        );
        assert!(completed.elapsed() < timeout);
        // Well past that idle deadline the relay has not closed it.
        let past = completed + 3 * timeout;
        tokio::time::sleep_until(Instant::from_std(past)).await;
        assert!(stats.closed().is_none());
        assert!(!driver.is_finished());
        // Nor does it answer a new request.
        let (response, _send) = client.send_request(carrier_request(), false).unwrap();
        let answered = tokio::time::timeout(Duration::from_millis(500), response);
        assert!(answered.await.is_err());
        assert!(stats.closed().is_none());
        assert!(!driver.is_finished());
    });
    assert_eq!(relay.streams(), 1);
    assert_eq!(relay.strikes(), 0);
}

#[test]
fn pooled_relay_self_test_tcp_drop_aborts_every_stream_without_a_strike() {
    let (relay, kit) = relay(PoolConfig::default());
    runtime().block_on(async {
        let (mut client, driver) = connect(relay.address(), &kit).await;
        let mut echoes = Vec::new();
        for _ in 0..3 {
            echoes.push(open_echo(&mut client, &kit).await);
        }
        let started = std::time::Instant::now();
        let mut handshaking = Vec::new();
        for _ in 0..2 {
            handshaking.push(carrier(&mut client).await);
        }
        let stats = relay.connection(0);
        assert!(
            wait_until(Duration::from_secs(2), || (stats.handshakes().current()
                == 2)
                .then_some(()))
            .await
            .is_some()
        );
        assert_eq!(stats.live_streams(), 5);
        relay.drop_tcp(0);
        let closed = relay.wait_closed(0, Duration::from_secs(2)).await;
        assert_eq!(closed.map(|(_, close)| close), Some(Close::DropTcp));
        // Recorded after the aborts: no stream task is left.
        assert_eq!(stats.live_streams(), 0);
        assert_eq!(stats.handshakes().current(), 0);
        assert_eq!(relay.handshakes().current(), 0);
        for mut stream in echoes {
            let mut byte = [0u8; 1];
            let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte))
                .await
                .unwrap();
            assert!(matches!(read, Ok(0) | Err(_)));
        }
        let ended = tokio::time::timeout(Duration::from_secs(2), driver).await;
        assert!(ended.is_ok());
        // Past the in-handshake streams' 5 s deadline nothing strikes.
        let wait = Duration::from_millis(5_500).saturating_sub(started.elapsed());
        tokio::time::sleep(wait).await;
        drop(handshaking);
    });
    assert_eq!(relay.strikes(), 0);
    for index in 0..5 {
        let steps = relay.steps(index);
        for after_drop in [
            StreamStep::Ended,
            StreamStep::Struck,
            StreamStep::HandshakeFailed,
            StreamStep::EstablishFailed,
        ] {
            assert!(!steps.contains(&after_drop), "{index}: {steps:?}");
        }
    }
    let at = relay.events().iter().map(|event| event.at).max().unwrap();
    assert!(at <= relay.connection(0).closed().unwrap().0);
}

#[test]
fn pooled_relay_fault_switches_act_on_streams_and_connections() {
    let config = PoolConfig {
        handshake_timeout: Duration::from_secs(1),
        ..PoolConfig::default()
    };
    let (relay, kit) = relay(config);
    runtime().block_on(async {
        let (mut client, driver) = connect(relay.address(), &kit).await;
        // Stream 0 (ID 1) keeps connection 0 authenticated.
        let mut live = open_echo(&mut client, &kit).await;
        // Stream 1: RST_STREAM in place of the 200.
        relay.reset_before_200(1, Reason::INTERNAL_ERROR);
        let (response, _send) = client.send_request(carrier_request(), false).unwrap();
        let error = response.await.unwrap_err();
        assert_eq!(error.reason(), Some(Reason::INTERNAL_ERROR));
        assert!(relay
            .wait_step(1, StreamStep::ResetBefore200, Duration::from_secs(2))
            .await
            .is_some());
        // Stream 2: the 200, then the stream ends before any handshake.
        relay.refuse_after_200(1);
        let refused = carrier(&mut client).await;
        assert!(kit.inner.connect(refused).await.is_err());
        assert!(relay
            .wait_step(2, StreamStep::RefusedAfter200, Duration::from_secs(2))
            .await
            .is_some());
        // Stream 3: mTLS completes, then the channel closes before a status.
        relay.end_stream_after_mtls(1);
        let mut ended = authenticate(&mut client, &kit).await;
        write_open(&mut ended).await;
        let status = ended.read_u8().await.unwrap_err();
        assert_eq!(status.kind(), io::ErrorKind::UnexpectedEof);
        assert!(relay
            .wait_step(3, StreamStep::EndedAfterMtls, Duration::from_secs(2))
            .await
            .is_some());
        // Stream 4: the Open is read and never answered; the stream is reset
        // at its deadline, origin + the 1 s handshake timeout.
        relay.hang_target(1);
        let asked = std::time::Instant::now();
        let mut hung = authenticate(&mut client, &kit).await;
        write_open(&mut hung).await;
        assert!(hung.read_u8().await.is_err());
        let waited = asked.elapsed();
        assert!(between(waited, 800, 1_600), "{waited:?}");
        assert!(relay
            .wait_step(4, StreamStep::TargetHung, Duration::from_secs(2))
            .await
            .is_some());
        // Stream 5 (ID 11): status 0, then the relay never reads; the upload
        // stalls once the 128 KiB window and the buffers are full.
        relay.stall_upload(5);
        let mut stalled = open_echo(&mut client, &kit).await;
        let upload = vec![0x5a; 1 << 20];
        let write = tokio::time::timeout(Duration::from_secs(1), stalled.write_all(&upload));
        assert!(write.await.is_err());
        let stats = relay.connection(0);
        assert!(!stats.window_updates(false).iter().any(|(id, _)| *id == 11));
        assert_eq!(relay.steps(5).last(), Some(&StreamStep::Opened));

        // GOAWAY(NO_ERROR, 1): stream 1 drains, stream 11 is aborted, no
        // new stream is served, and the connection closes once it drained.
        relay.goaway(0, Reason::NO_ERROR, 1);
        assert!(wait_until(Duration::from_secs(2), || stats
            .frames()
            .into_iter()
            .find(|f| !f.from_client && f.kind == frame_type::GOAWAY))
        .await
        .is_some_and(|f| f.reason() == Some(0) && f.payload[..4] == 1u32.to_be_bytes()));
        assert!(relay
            .wait_step(5, StreamStep::GoneAway, Duration::from_secs(2))
            .await
            .is_some());
        echo(&mut live, b"draining").await;
        let refused = match client.send_request(carrier_request(), false) {
            Err(_) => true,
            Ok((response, _)) => response.await.is_err(),
        };
        assert!(refused);
        assert!(stats.closed().is_none());
        finish(live).await;
        let closed = relay.wait_closed(0, Duration::from_secs(2)).await;
        assert_eq!(closed.map(|(_, close)| close), Some(Close::GoAway));
        assert!(tokio::time::timeout(Duration::from_secs(2), driver)
            .await
            .is_ok());
        drop((client, ended, hung, stalled));

        // Connection 1: an error GOAWAY closes at once.
        let (mut client, driver) = connect(relay.address(), &kit).await;
        let _live = open_echo(&mut client, &kit).await;
        relay.goaway(1, Reason::ENHANCE_YOUR_CALM, 13);
        let closed = relay.wait_closed(1, Duration::from_secs(2)).await;
        assert_eq!(closed.map(|(_, close)| close), Some(Close::GoAway));
        let ended = tokio::time::timeout(Duration::from_secs(2), driver)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ended.unwrap_err().reason(), Some(Reason::ENHANCE_YOUR_CALM));

        // Connection 2: frozen with a live stream, it answers nothing (the
        // idle half is pooled_relay_self_test_a_frozen_connection_never_idles_out).
        let (mut client, driver) = connect(relay.address(), &kit).await;
        let mut frozen = open_echo(&mut client, &kit).await;
        relay.freeze(2);
        let stats = relay.connection(2);
        assert!(
            wait_until(Duration::from_secs(2), || stats.is_frozen().then_some(()))
                .await
                .is_some()
        );
        frozen.write_all(b"x").await.unwrap();
        frozen.flush().await.unwrap();
        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_millis(600), frozen.read(&mut byte));
        assert!(read.await.is_err());
        assert!(!driver.is_finished());
        assert!(stats.closed().is_none());
    });
    assert_eq!(relay.conns(), 3);
    assert_eq!(relay.strikes(), 0);
}
