//! Pooled outer sessions (B-06 S16h-3), the flow pool (S16h-4) and a flow's
//! stream on it through the held relay services (S16h-5) against the
//! multi-stream test relay (behind a 170 ms latency link for the pool) and
//! small loopback carrier servers, with the held crypto of a ready test tree
//! and no first ACK.
use super::*;
use crate::{
    app_group::CapturedAppGroupInputs,
    establish_limit::{
        handshake_auth_class, is_auth_refused, live_cap_for, AuthBackoff, EstablishLimiter,
        LiveFlow, ACK_RESERVE, AUTH_BACKOFF, CARRIER_REFUSALS, ESTABLISH_PERMITS, FLOW_OPENS,
    },
    local_identity::PreparedLocalSession,
    prepared_crypto::Judged,
    test_fixture::ReadyTree,
    test_link::{TestLink, DEFAULT_RTT},
    test_relay::{
        outer_acceptor,
        pool::{frame_type, Close, PoolConfig, PooledRelay, StreamFault, StreamStep},
        RelayIdentity, TestRelay,
    },
};
use aegis_client::protected_online_expectation::ProtectedOnlineExpectation;
use aegis_core::secure_channel::{self, OpenRequest, Transport};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
    thread,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    runtime::Runtime,
};
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    },
    TlsAcceptor,
};

type Inner = crate::carrier_io::InnerCarrier;

/// h2's initial connection window before any WINDOW_UPDATE (RFC 9113 6.9.2).
const DEFAULT_WINDOW: u32 = 65_535;
/// SETTINGS_INITIAL_WINDOW_SIZE (RFC 9113 6.5.2).
const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;

// Declaration order is drop order: the held crypto and Store claim go while
// their runtime still exists.
struct Kit {
    crypto: Arc<PreparedCryptoInputs>,
    _prepared: PreparedLocalSession,
    _store: Arc<ProtectedOnlineExpectation<'static>>,
    runtime: Runtime,
    tree: ReadyTree,
}

impl Kit {
    fn peer(&self) -> SocketAddr {
        self.tree.relay()
    }

    async fn dial(
        &self,
        interface: &RelayInterface,
        limiter: &Arc<EstablishLimiter>,
        gate: &WorkGate,
    ) -> io::Result<PooledConn> {
        PooledConn::dial(self.peer(), interface, &self.crypto, limiter, gate, 0).await
    }
}

/// A ready tree whose signed relay is `listener`'s address, and its held
/// crypto. The caller serves `listener`.
fn kit() -> (std::net::TcpListener, Kit) {
    let listener = TestRelay::bind();
    let tree = ReadyTree::with_online_completed(listener.local_addr().unwrap());
    (listener, kit_on(tree))
}

/// The held crypto of `tree`.
fn kit_on(tree: ReadyTree) -> Kit {
    let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
    let (prepared, store) = PreparedLocalSession::from_claim_with_store_guard(claim).unwrap();
    Kit {
        crypto: prepared.crypto_for_test(),
        _prepared: prepared,
        _store: store,
        runtime: tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap(),
        tree,
    }
}

/// `kit` served by the multi-stream relay.
fn pooled() -> (PooledRelay, Kit) {
    let (listener, kit) = kit();
    let relay = TestRelay::spawn_streams(
        listener,
        RelayIdentity::for_tree(&kit.tree),
        PoolConfig::default(),
    );
    (relay, kit)
}

fn limiter() -> Arc<EstablishLimiter> {
    EstablishLimiter::new(AuthBackoff::default())
}

fn loopback() -> RelayInterface {
    RelayInterface::loopback_for_test()
}

/// Inner mTLS on `carrier` and an accepted TCP Open to the relay's echo.
async fn open_echo(crypto: &PreparedCryptoInputs, carrier: PooledCarrier) -> Inner {
    let mut inner = crypto.inner_client().connect(carrier.io).await.unwrap();
    let open = OpenRequest {
        transport: Transport::Tcp,
        version: 1,
        host: "echo.test".into(),
        port: 7,
    };
    secure_channel::write_open(&mut inner, &open).await.unwrap();
    inner.flush().await.unwrap();
    assert_eq!(inner.read_u8().await.unwrap(), 0);
    inner
}

async fn echo(inner: &mut Inner, bytes: &[u8]) {
    inner.write_all(bytes).await.unwrap();
    inner.flush().await.unwrap();
    let mut echoed = vec![0; bytes.len()];
    inner.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, bytes);
}

fn wait_until(budget: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + budget;
    while !done() {
        if std::time::Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(2));
    }
    true
}

/// The `CARRIER_REFUSALS` entry some error in `error`'s chain starts with.
fn refusal_of(error: &anyhow::Error) -> Option<&'static str> {
    error.chain().find_map(|current| {
        let text = current.to_string();
        CARRIER_REFUSALS
            .iter()
            .copied()
            .find(|refusal| text.starts_with(refusal))
    })
}

/// Both refusals name the same `CARRIER_REFUSALS` entry, `expected`, read
/// the same, and are authentication class.
fn assert_same_refusal(ours: &anyhow::Error, reference: &anyhow::Error, expected: &str) {
    assert_eq!(refusal_of(ours), Some(expected), "{ours:#}");
    assert_eq!(refusal_of(reference), Some(expected), "{reference:#}");
    assert_eq!(ours.to_string(), reference.to_string());
    assert!(handshake_auth_class(ours.judged()));
    assert!(handshake_auth_class(reference.judged()));
    assert!(is_auth_refused(&handshake_refusal(ours)));
}

#[test]
fn two_carriers_one_connection() {
    let (relay, f) = pooled();
    let gate = WorkGate::new();
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(20), async {
            let conn = f.dial(&loopback(), &limiter(), &gate).await.unwrap();
            assert_eq!(conn.ended(), None);
            let first = conn.open_carrier(&f.crypto).await.unwrap();
            let second = conn.open_carrier(&f.crypto).await.unwrap();
            assert_ne!(first.stream_id, second.stream_id);
            assert!(first.stream_id < second.stream_id);
            let mut first = open_echo(&f.crypto, first).await;
            let mut second = open_echo(&f.crypto, second).await;
            // Interleaved, each stream echoes its own bytes.
            first.write_all(b"first flow").await.unwrap();
            second.write_all(b"second flow, other bytes").await.unwrap();
            first.flush().await.unwrap();
            second.flush().await.unwrap();
            let mut a = [0; 10];
            let mut b = [0; 24];
            second.read_exact(&mut b).await.unwrap();
            first.read_exact(&mut a).await.unwrap();
            assert_eq!(&a, b"first flow");
            assert_eq!(&b, b"second flow, other bytes");
            echo(&mut first, b"again").await;
            assert_eq!(conn.ended(), None);
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.conns(), 1);
    assert_eq!(relay.streams(), 2);
    assert_eq!(relay.strikes(), 0);
    // The connection dropped: its driver task is gone with it.
    assert!(wait_until(Duration::from_secs(2), || gate.tasks_left() == 0));
}

/// How the loopback carrier server answers the next connection.
#[derive(Clone, Copy)]
enum Answer {
    /// Outer TLS with ALPN h2, then every carrier request answered with
    /// this status and content type.
    Carrier(u16, &'static str),
    /// Outer TLS that negotiates no ALPN (an HTTP/1.1-only server).
    NoAlpn,
    /// The first carrier request starts a graceful GOAWAY (last stream ID
    /// 2^31-1, then the last processed one); its 200 follows 300 ms later.
    GracefulThenOk,
}

fn acceptor(tree: &ReadyTree, alpn: bool) -> TlsAcceptor {
    let (cert, key) = tree.outer_server_der();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key));
    if alpn {
        return outer_acceptor(cert, key).unwrap();
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    TlsAcceptor::from(Arc::new(config))
}

async fn answer(
    listener: std::net::TcpListener,
    h2: TlsAcceptor,
    plain: TlsAcceptor,
    mode: Arc<Mutex<Answer>>,
) {
    let listener = TcpListener::from_std(listener).unwrap();
    loop {
        let Ok((tcp, _)) = listener.accept().await else {
            continue;
        };
        let answer = *mode.lock().unwrap();
        let (h2, plain) = (h2.clone(), plain.clone());
        tokio::spawn(async move {
            match answer {
                Answer::GracefulThenOk => {
                    let Ok(tls) = h2.accept(tcp).await else {
                        return;
                    };
                    let Ok(mut connection) = h2::server::handshake(tls).await else {
                        return;
                    };
                    let Some(Ok((_, respond))) = connection.accept().await else {
                        return;
                    };
                    connection.graceful_shutdown();
                    let mut respond = Some(respond);
                    let mut held = None;
                    let later = tokio::time::sleep(Duration::from_millis(300));
                    tokio::pin!(later);
                    loop {
                        tokio::select! {
                            next = connection.accept() => if next.is_none() { break },
                            () = &mut later, if respond.is_some() => {
                                let response = http::Response::builder()
                                    .status(200)
                                    .header("content-type", "application/grpc")
                                    .body(())
                                    .unwrap();
                                held = respond.take().unwrap().send_response(response, false).ok();
                            }
                        }
                    }
                    drop(held);
                }
                Answer::NoAlpn => {
                    let Ok(mut tls) = plain.accept(tcp).await else {
                        return;
                    };
                    let mut rest = Vec::new();
                    let _ = tls.read_to_end(&mut rest).await;
                }
                Answer::Carrier(status, content_type) => {
                    let Ok(tls) = h2.accept(tcp).await else {
                        return;
                    };
                    let Ok(mut connection) = h2::server::handshake(tls).await else {
                        return;
                    };
                    let mut held = Vec::new();
                    while let Some(Ok((_, mut respond))) = connection.accept().await {
                        let response = http::Response::builder()
                            .status(status)
                            .header("content-type", content_type)
                            .body(())
                            .unwrap();
                        if let Ok(stream) = respond.send_response(response, false) {
                            held.push(stream);
                        }
                    }
                }
            }
        });
    }
}

#[test]
fn carrier_texts_match_aegis_client() {
    let (listener, f) = kit();
    let mode = Arc::new(Mutex::new(Answer::NoAlpn));
    let server = f.runtime.spawn(answer(
        listener,
        acceptor(&f.tree, true),
        acceptor(&f.tree, false),
        mode.clone(),
    ));
    let gate = WorkGate::new();
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(20), async {
            let reference = || async {
                let tcp = TcpStream::connect(f.peer()).await.unwrap();
                match f.crypto.reference_carrier(tcp).await {
                    Ok(_) => panic!("the reference carrier was accepted"),
                    Err(error) => error,
                }
            };
            // An explicit carrier refusal and a wrong content type, after
            // a ready pooled connection.
            for (answer, expected) in [
                (
                    Answer::Carrier(403, "application/grpc"),
                    CARRIER_REFUSALS[0],
                ),
                (Answer::Carrier(200, "text/html"), CARRIER_REFUSALS[1]),
            ] {
                *mode.lock().unwrap() = answer;
                let conn = f.dial(&loopback(), &limiter(), &gate).await.unwrap();
                let ours = match conn.open_carrier(&f.crypto).await {
                    Ok(_) => panic!("the pooled carrier was accepted"),
                    Err(error) => error,
                };
                assert_same_refusal(&ours, &reference().await, expected);
            }
            // A relay that negotiates no ALPN: refused at the dial, judged
            // authentication class.
            *mode.lock().unwrap() = Answer::NoAlpn;
            let tcp = TcpStream::connect(f.peer()).await.unwrap();
            let ours = match outer_tls(&f.crypto, tcp).await {
                Ok(_) => panic!("outer TLS without h2 was accepted"),
                Err(error) => error,
            };
            assert_same_refusal(&ours, &reference().await, CARRIER_REFUSALS[2]);
            let judged = limiter();
            let refusal = match f.dial(&loopback(), &judged, &gate).await {
                Ok(_) => panic!("a pooled dial without h2 succeeded"),
                Err(error) => error,
            };
            assert!(is_auth_refused(&refusal));
            assert_eq!(refusal.to_string(), refused().to_string());
            assert_eq!(judged.auth_failures(), 1);
            assert!(judged.backing_off());
        })
        .await
        .unwrap();
    });
    // A refused ECH: no loopback relay can produce it (rustls fails the
    // outer handshake itself when the relay declines ECH), so the check is
    // compared with the very function connect_h2_from_held calls.
    let mut pinned = f.crypto.signed_relay().clone();
    pinned.ech_config_list_base64 = Some("AA==".into());
    for status in [EchStatus::NotOffered, EchStatus::Rejected] {
        let ours = verify_outer(&pinned, status, Some(b"h2")).unwrap_err();
        let reference =
            aegis_client::ech_policy::require_accepted_ech(&pinned, status).unwrap_err();
        assert_same_refusal(&ours, &reference, CARRIER_REFUSALS[3]);
    }
    // Without a pinned ECH config, an h2 relay passes.
    verify_outer(f.crypto.signed_relay(), EchStatus::NotOffered, Some(b"h2")).unwrap();
    server.abort();
}

#[test]
fn graceful_goaway_keeps_a_processed_carrier() {
    let (listener, f) = kit();
    let mode = Arc::new(Mutex::new(Answer::GracefulThenOk));
    let server = f.runtime.spawn(answer(
        listener,
        acceptor(&f.tree, true),
        acceptor(&f.tree, false),
        mode,
    ));
    let gate = WorkGate::new();
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(20), async {
            let conn = f.dial(&loopback(), &limiter(), &gate).await.unwrap();
            let carrier = conn.open_carrier(&f.crypto).await.unwrap();
            // Both GOAWAYs arrived before the 200; the stream was processed.
            assert_eq!(
                conn.ended(),
                Some(ConnEnd::GoAway(h2::Reason::NO_ERROR, carrier.stream_id))
            );
            // An ended connection opens no further stream, never sent.
            let lost = match conn.open_carrier(&f.crypto).await {
                Ok(_) => panic!("a stream opened after GOAWAY"),
                Err(error) => error,
            };
            assert!(lost.downcast_ref::<CarrierLost>().unwrap().unprocessed);
        })
        .await
        .unwrap();
    });
    server.abort();
}

#[test]
fn pooled_dial_bound_to_interface() {
    let (relay, f) = pooled();
    let gate = WorkGate::new();
    let limiter = limiter();
    f.runtime.block_on(async {
        // An interface no index names: the bound dial fails before any SYN,
        // and that is no authentication failure.
        let gone = RelayInterface::for_test("en99", 0x7fff_0000);
        let refusal = match f.dial(&gone, &limiter, &gate).await {
            Ok(_) => panic!("a pooled dial on a missing interface succeeded"),
            Err(error) => error,
        };
        assert!(!is_auth_refused(&refusal));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(relay.conns(), 0);
        assert_eq!(gate.tasks_left(), 0);
        // The lo0-bound dial reaches the relay; its driver is a gate task.
        let conn = f.dial(&loopback(), &limiter, &gate).await.unwrap();
        assert_eq!(relay.conns(), 1);
        assert_eq!(gate.tasks_left(), 1);
        drop(conn);
    });
    assert_eq!(limiter.auth_failures(), 0);
    assert!(wait_until(Duration::from_secs(2), || gate.tasks_left() == 0));
}

/// HEADERS frames a silent relay read: outer TLS with ALPN h2, then it
/// reads the client's H2 bytes and never writes, so no SETTINGS arrive.
async fn count_headers(
    listener: std::net::TcpListener,
    h2: TlsAcceptor,
    headers: Arc<AtomicUsize>,
) {
    let listener = TcpListener::from_std(listener).unwrap();
    let (tcp, _) = listener.accept().await.unwrap();
    let mut tls = h2.accept(tcp).await.unwrap();
    let mut wire = Vec::new();
    let mut chunk = [0; 16 * 1024];
    // After the 24-byte client preface.
    let mut at = 24;
    loop {
        match tls.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => wire.extend_from_slice(&chunk[..read]),
        }
        while wire.len() >= at + 9 {
            let length = u32::from_be_bytes([0, wire[at], wire[at + 1], wire[at + 2]]) as usize;
            if wire.len() < at + 9 + length {
                break;
            }
            if wire[at + 3] == 0x1 {
                headers.fetch_add(1, Ordering::SeqCst);
            }
            at += 9 + length;
        }
    }
}

#[test]
fn settings_tap() {
    // The windows, on the multi-stream relay's control-frame tap.
    let (relay, f) = pooled();
    let gate = WorkGate::new();
    f.runtime.block_on(async {
        let conn = f.dial(&loopback(), &limiter(), &gate).await.unwrap();
        let carrier = conn.open_carrier(&f.crypto).await.unwrap();
        drop(carrier);
        drop(conn);
    });
    let stats = relay.connection(0);
    let settings = stats.settings(true);
    assert_eq!(settings.len(), 1, "{settings:?}");
    assert!(settings[0].contains(&(SETTINGS_INITIAL_WINDOW_SIZE, STREAM_WINDOW)));
    // v34, written out: SETTINGS stays v33's 131072; the connection window
    // is 15 MiB, so its WINDOW_UPDATE is Chrome's 15663105 (v33: 8323073).
    assert!(settings[0].contains(&(SETTINGS_INITIAL_WINDOW_SIZE, 131_072)));
    let connection: Vec<u32> = stats
        .window_updates(true)
        .into_iter()
        .filter(|(stream, _)| *stream == 0)
        .map(|(_, increment)| increment)
        .collect();
    assert_eq!(connection.first(), Some(&(CONN_WINDOW - DEFAULT_WINDOW)));
    assert_eq!(connection.first(), Some(&15_663_105));
    assert!(stats
        .frames()
        .iter()
        .any(|frame| !frame.from_client && frame.kind == frame_type::SETTINGS));

    // Before the relay's SETTINGS, at most STREAMS_BEFORE_SETTINGS streams open.
    let (listener, f) = kit();
    let headers = Arc::new(AtomicUsize::new(0));
    let server = f.runtime.spawn(count_headers(
        listener,
        acceptor(&f.tree, true),
        headers.clone(),
    ));
    let opens = f.runtime.block_on(async {
        let conn = Arc::new(f.dial(&loopback(), &limiter(), &gate).await.unwrap());
        let mut opens = tokio::task::JoinSet::new();
        for _ in 0..STREAMS_BEFORE_SETTINGS + 10 {
            let (conn, crypto) = (conn.clone(), f.crypto.clone());
            opens.spawn(async move { conn.open_carrier(&crypto).await.map(|_| ()) });
        }
        opens
    });
    assert!(wait_until(Duration::from_secs(5), || {
        headers.load(Ordering::SeqCst) >= STREAMS_BEFORE_SETTINGS
    }));
    thread::sleep(Duration::from_millis(300));
    assert_eq!(headers.load(Ordering::SeqCst), STREAMS_BEFORE_SETTINGS);
    f.runtime.block_on(async move {
        let mut opens = opens;
        opens.abort_all();
        while opens.join_next().await.is_some() {}
    });
    server.abort();
    assert!(wait_until(Duration::from_secs(2), || gate.tasks_left() == 0));
}

#[test]
fn dial_respects_backoff() {
    let (relay, f) = pooled();
    let gate = WorkGate::new();
    let crypto = f.crypto.clone();
    let peer = f.peer();
    let dial = move |limiter: Arc<EstablishLimiter>, gate: Arc<WorkGate>| {
        let crypto = crypto.clone();
        async move {
            PooledConn::dial(peer, &loopback(), &crypto, &limiter, &gate, 0)
                .await
                .map(|_| std::time::Instant::now())
        }
    };
    f.runtime.block_on(async {
        // An authentication failure: no TCP accept until the backoff ends.
        let limiter = EstablishLimiter::for_test(6, 3, Duration::from_millis(800));
        let started = std::time::Instant::now();
        limiter.auth_failure(Purpose::Flow);
        let dialed = tokio::spawn(dial(limiter.clone(), gate.clone()));
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(relay.conns(), 0);
        let ready = dialed.await.unwrap().unwrap();
        assert!(ready.duration_since(started) >= Duration::from_millis(790));
        assert_eq!(relay.conns(), 1);

        // The pause before sleep: no TCP accept until resume().
        let epoch = AuthBackoff::default();
        let limiter = EstablishLimiter::new(epoch.clone());
        epoch.quiesce(std::time::Instant::now());
        let dialed = tokio::spawn(dial(limiter.clone(), gate.clone()));
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(relay.conns(), 1);
        let resumed = std::time::Instant::now();
        epoch.resume();
        let ready = tokio::time::timeout(Duration::from_secs(2), dialed)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(ready.duration_since(resumed) < Duration::from_secs(1));
        assert_eq!(relay.conns(), 2);
        assert_eq!(limiter.auth_failures(), 0);
    });
}

#[test]
fn conn_end_reports_goaway_transport_and_local_close() {
    let (relay, f) = pooled();
    let gate = WorkGate::new();
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(20), async {
            // A GOAWAY: its code and last stream ID, before the close; no
            // new stream opens on the connection.
            let conn = f.dial(&loopback(), &limiter(), &gate).await.unwrap();
            let carrier = conn.open_carrier(&f.crypto).await.unwrap();
            relay.goaway(0, h2::Reason::ENHANCE_YOUR_CALM, carrier.stream_id);
            let mut end = conn.end_watch();
            end.wait_for(Option::is_some).await.unwrap();
            assert_eq!(
                conn.ended(),
                Some(ConnEnd::GoAway(
                    h2::Reason::ENHANCE_YOUR_CALM,
                    carrier.stream_id
                ))
            );
            let lost = match conn.open_carrier(&f.crypto).await {
                Ok(_) => panic!("a stream opened after GOAWAY"),
                Err(error) => error,
            };
            let lost = lost.downcast_ref::<CarrierLost>().unwrap();
            assert!(lost.unprocessed);
            drop((carrier, conn));

            // A dropped TCP connection without GOAWAY: a transport end.
            let conn = f.dial(&loopback(), &limiter(), &gate).await.unwrap();
            let _carrier = conn.open_carrier(&f.crypto).await.unwrap();
            relay.drop_tcp(1);
            let mut end = conn.end_watch();
            end.wait_for(Option::is_some).await.unwrap();
            assert_eq!(conn.ended(), Some(ConnEnd::Io));

            // This side's drop: a local close.
            let conn = f.dial(&loopback(), &limiter(), &gate).await.unwrap();
            let mut end = conn.end_watch();
            drop(conn);
            let _ = end.changed().await;
            assert_eq!(*end.borrow(), Some(ConnEnd::LocalClose));
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.strikes(), 0);
    assert!(wait_until(Duration::from_secs(2), || gate.tasks_left() == 0));
}

fn frame(kind: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len()).unwrap().to_be_bytes();
    let mut bytes = vec![length[1], length[2], length[3], kind, 0];
    bytes.extend_from_slice(&stream.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

#[test]
fn goaway_tap_reports_code_and_last_id_across_any_split() {
    // SETTINGS, a DATA frame whose payload looks like a GOAWAY header, an
    // empty frame, then GOAWAY(last 5 with the reserved bit set,
    // ENHANCE_YOUR_CALM, debug data).
    let mut goaway = 0x8000_0005_u32.to_be_bytes().to_vec();
    goaway.extend_from_slice(&0xb_u32.to_be_bytes());
    goaway.extend_from_slice(b"calm");
    let mut wire = frame(0x4, 0, &[0, 3, 0, 0, 0, 30]);
    wire.extend(frame(0x0, 1, &frame(GOAWAY, 0, &[0; 8])[..12]));
    wire.extend(frame(0x4, 0, &[]));
    let goaway_at = wire.len();
    wire.extend(frame(GOAWAY, 0, &goaway));
    let complete = goaway_at + FRAME_HEADER + 8;
    let expected = ConnEnd::GoAway(h2::Reason::ENHANCE_YOUR_CALM, 5);
    for split in 1..=wire.len() {
        let (sender, receiver) = watch::channel(None);
        let mut tap = GoAwayTap::new(
            (),
            Arc::new(sender),
            Arc::new(Liveness::new(Duration::ZERO)),
        );
        for (at, chunk) in wire.chunks(split).enumerate() {
            tap.observe(chunk);
            let seen = (at * split + chunk.len()).min(wire.len());
            let want = (seen >= complete).then_some(expected);
            assert_eq!(*receiver.borrow(), want, "split {split} at {seen}");
        }
        assert_eq!(*receiver.borrow(), Some(expected));
    }
    // A later GOAWAY replaces an earlier one; a transport end never does.
    let (sender, receiver) = watch::channel(None);
    record(&sender, ConnEnd::GoAway(h2::Reason::NO_ERROR, 0x7fff_ffff));
    record(&sender, expected);
    record(&sender, ConnEnd::Io);
    record(&sender, ConnEnd::LocalClose);
    assert_eq!(*receiver.borrow(), Some(expected));
    let (sender, receiver) = watch::channel(None);
    record(&sender, ConnEnd::Io);
    record(&sender, expected);
    assert_eq!(*receiver.borrow(), Some(ConnEnd::Io));
}

/// The stream ID of the first HEADERS frame the client writes on `io`.
async fn first_headers(io: &mut (impl tokio::io::AsyncRead + Unpin)) -> Option<u32> {
    let mut wire = Vec::new();
    let mut chunk = [0; 16 * 1024];
    // After the 24-byte client preface.
    let mut at = 24;
    loop {
        match io.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(read) => wire.extend_from_slice(&chunk[..read]),
        }
        while wire.len() >= at + FRAME_HEADER {
            let length = u32::from_be_bytes([0, wire[at], wire[at + 1], wire[at + 2]]) as usize;
            if wire.len() < at + FRAME_HEADER + length {
                break;
            }
            if wire[at + 3] == 0x1 {
                let id =
                    u32::from_be_bytes([wire[at + 5], wire[at + 6], wire[at + 7], wire[at + 8]]);
                return Some(id & 0x7fff_ffff);
            }
            at += FRAME_HEADER + length;
        }
    }
}

fn goaway_frame(reason: h2::Reason, last: u32) -> Vec<u8> {
    let mut payload = last.to_be_bytes().to_vec();
    payload.extend_from_slice(&u32::from(reason).to_be_bytes());
    frame(GOAWAY, 0, &payload)
}

/// What the raw relay does once a connection's first carrier HEADERS arrive.
#[derive(Clone, Copy, Debug)]
enum OnHeaders {
    /// GOAWAY(reason, last stream ID 0): the stream in flight is above it.
    GoAwayBelow(h2::Reason),
    /// The stream's 200 and GOAWAY(reason, that stream) in one write.
    OkThenGoAway(h2::Reason),
    /// Close the TCP socket: no GOAWAY, no TLS close_notify.
    DropTcp,
    /// Nothing more: the stream waits for its 200.
    Silent,
}

/// Outer TLS with ALPN h2, an empty SETTINGS, then `on` once the first
/// HEADERS frame of each connection has arrived; `headers` counts them.
async fn raw_relay(
    listener: std::net::TcpListener,
    h2: TlsAcceptor,
    on: Arc<Mutex<OnHeaders>>,
    headers: Arc<AtomicUsize>,
) {
    // HPACK: :status 200 (static index 8), then content-type (static index
    // 31) application/grpc as a literal without indexing.
    let mut block = vec![0x88, 0x0f, 0x10, 0x10];
    block.extend_from_slice(b"application/grpc");
    let listener = TcpListener::from_std(listener).unwrap();
    loop {
        let Ok((tcp, _)) = listener.accept().await else {
            continue;
        };
        let (h2, on, headers, block) = (
            h2.clone(),
            *on.lock().unwrap(),
            headers.clone(),
            block.clone(),
        );
        tokio::spawn(async move {
            let Ok(mut tls) = h2.accept(tcp).await else {
                return;
            };
            if tls.write_all(&frame(0x4, 0, &[])).await.is_err() || tls.flush().await.is_err() {
                return;
            }
            let Some(stream) = first_headers(&mut tls).await else {
                return;
            };
            headers.fetch_add(1, Ordering::SeqCst);
            let write = match on {
                OnHeaders::GoAwayBelow(reason) => goaway_frame(reason, 0),
                OnHeaders::OkThenGoAway(reason) => {
                    let mut write = frame(0x1, stream, &block);
                    // END_HEADERS.
                    write[4] = 0x4;
                    write.extend(goaway_frame(reason, stream));
                    write
                }
                OnHeaders::DropTcp => return,
                OnHeaders::Silent => Vec::new(),
            };
            if tls.write_all(&write).await.is_err() || tls.flush().await.is_err() {
                return;
            }
            let mut rest = [0; 4096];
            while matches!(tls.read(&mut rest).await, Ok(read) if read > 0) {}
        });
    }
}

/// `kit` served by the raw relay.
fn raw() -> (
    Kit,
    Arc<Mutex<OnHeaders>>,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let (listener, f) = kit();
    let on = Arc::new(Mutex::new(OnHeaders::Silent));
    let headers = Arc::new(AtomicUsize::new(0));
    let server = f.runtime.spawn(raw_relay(
        listener,
        acceptor(&f.tree, true),
        on.clone(),
        headers.clone(),
    ));
    (f, on, headers, server)
}

fn carrier_lost(opened: anyhow::Result<PooledCarrier>) -> (ConnEnd, bool) {
    match opened {
        Ok(_) => panic!("the carrier opened"),
        Err(error) => match error.downcast_ref::<CarrierLost>() {
            Some(lost) => (lost.end, lost.unprocessed),
            None => panic!("not CarrierLost: {error:#}"),
        },
    }
}

#[test]
fn in_flight_carrier_lost_to_goaway_or_transport_end() {
    // A carrier stream waiting for its 200 when the connection ends is
    // CarrierLost every time, whether h2 fails the stream or the watch shows
    // the end first; rounds catch either order.
    const ROUNDS: usize = 16;
    let (f, on, headers, server) = raw();
    let gate = WorkGate::new();
    let cases = [
        (
            OnHeaders::GoAwayBelow(h2::Reason::NO_ERROR),
            ConnEnd::GoAway(h2::Reason::NO_ERROR, 0),
            true,
        ),
        (
            OnHeaders::GoAwayBelow(h2::Reason::ENHANCE_YOUR_CALM),
            ConnEnd::GoAway(h2::Reason::ENHANCE_YOUR_CALM, 0),
            true,
        ),
        // The relay processed the stream (its 200 came), but the error
        // GOAWAY read with it ends the connection: the end wins.
        (
            OnHeaders::OkThenGoAway(h2::Reason::ENHANCE_YOUR_CALM),
            ConnEnd::GoAway(h2::Reason::ENHANCE_YOUR_CALM, 1),
            false,
        ),
        (OnHeaders::DropTcp, ConnEnd::Io, false),
    ];
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(60), async {
            for (mode, end, unprocessed) in cases {
                *on.lock().unwrap() = mode;
                for round in 0..ROUNDS {
                    let conn = f.dial(&loopback(), &limiter(), &gate).await.unwrap();
                    let lost = carrier_lost(conn.open_carrier(&f.crypto).await);
                    assert_eq!(lost, (end, unprocessed), "{mode:?} round {round}");
                    assert_eq!(conn.ended(), Some(end), "{mode:?} round {round}");
                }
            }
        })
        .await
        .unwrap();
    });
    assert_eq!(headers.load(Ordering::SeqCst), cases.len() * ROUNDS);
    server.abort();
    assert!(wait_until(Duration::from_secs(2), || gate.tasks_left() == 0));
}

#[test]
fn gate_stop_records_a_transport_end() {
    let (f, _, headers, server) = raw();
    let gate = WorkGate::new();
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(20), async {
            let conn = Arc::new(f.dial(&loopback(), &limiter(), &gate).await.unwrap());
            let mut end = conn.end_watch();
            // A carrier stream in flight on the silent relay.
            let (open, crypto) = (conn.clone(), f.crypto.clone());
            let in_flight =
                tokio::spawn(async move { carrier_lost(open.open_carrier(&crypto).await) });
            while headers.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            // The test thread is no runtime worker: stop blocks only it.
            gate.stop(crate::held_relay_services::MAX_DRAIN).unwrap();
            assert_eq!(gate.tasks_left(), 0);
            tokio::time::timeout(CONN_END_GRACE, end.wait_for(Option::is_some))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(conn.ended(), Some(ConnEnd::Io));
            // The stream in flight was sent: possibly processed.
            assert_eq!(in_flight.await.unwrap(), (ConnEnd::Io, false));
            // A later open is never sent.
            assert_eq!(
                carrier_lost(conn.open_carrier(&f.crypto).await),
                (ConnEnd::Io, true)
            );
        })
        .await
        .unwrap();
    });
    server.abort();
}

/// A `PooledConn` over an in-memory pipe whose driver records no end: it
/// drops the h2 connection when `cut` fires, and the test records the end.
async fn unrecorded_conn(
    gate: &WorkGate,
) -> (
    PooledConn,
    EndSender,
    tokio::sync::oneshot::Sender<()>,
    tokio::io::DuplexStream,
) {
    let (client, relay) = tokio::io::duplex(1 << 16);
    let (end_sender, end) = watch::channel(None);
    let end_sender = Arc::new(end_sender);
    let (send, connection) = h2::client::Builder::new()
        .handshake::<_, Bytes>(client)
        .await
        .unwrap();
    let (cut, cutting) = tokio::sync::oneshot::channel::<()>();
    let driver = gate
        .spawn(async move {
            tokio::pin!(connection);
            tokio::select! {
                _ = &mut connection => {}
                _ = cutting => {}
            }
        })
        .unwrap();
    let conn = PooledConn {
        send,
        end,
        end_sender: end_sender.clone(),
        connect_started: Instant::now(),
        live: Arc::new(Liveness::new(Duration::ZERO)),
        stream_cap: AtomicUsize::new(STREAMS_BEFORE_SETTINGS),
        answered: AtomicBool::new(false),
        pin_gen: 0,
        wake_gen: 0,
        fd: -1,
        _driver: driver,
    };
    (conn, end_sender, cut, relay)
}

fn record_later(sender: EndSender, after: Duration) {
    tokio::spawn(async move {
        tokio::time::sleep(after).await;
        record(&sender, ConnEnd::Io);
    });
}

#[test]
fn stream_error_waits_for_the_recorded_end() {
    // h2 fails the streams before the driver records the transport end; an
    // end recorded within CONN_END_GRACE still makes the stream CarrierLost.
    let (_listener, f) = kit();
    let gate = WorkGate::new();
    let lag = Duration::from_millis(50);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(20), async {
            // Ended before the open: the refused send was never sent.
            let (conn, sender, cut, _relay) = unrecorded_conn(&gate).await;
            cut.send(()).unwrap();
            while gate.tasks_left() != 0 {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            assert_eq!(conn.ended(), None);
            record_later(sender, lag);
            assert_eq!(
                carrier_lost(conn.open_carrier(&f.crypto).await),
                (ConnEnd::Io, true)
            );
            drop(conn);

            // Ended with the stream sent and waiting for its 200.
            let (conn, sender, cut, mut relay) = unrecorded_conn(&gate).await;
            let conn = Arc::new(conn);
            let (open, crypto) = (conn.clone(), f.crypto.clone());
            let in_flight = tokio::spawn(async move { open.open_carrier(&crypto).await });
            assert_eq!(first_headers(&mut relay).await, Some(1));
            cut.send(()).unwrap();
            record_later(sender, lag);
            assert_eq!(carrier_lost(in_flight.await.unwrap()), (ConnEnd::Io, false));
            drop(conn);

            // No end recorded within the grace: h2's own error.
            let (conn, _sender, cut, _relay) = unrecorded_conn(&gate).await;
            cut.send(()).unwrap();
            while gate.tasks_left() != 0 {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            let started = Instant::now();
            let error = match conn.open_carrier(&f.crypto).await {
                Ok(_) => panic!("the carrier opened"),
                Err(error) => error,
            };
            assert!(started.elapsed() >= CONN_END_GRACE);
            assert!(error.downcast_ref::<CarrierLost>().is_none(), "{error:#}");
            assert!(error.downcast_ref::<h2::Error>().unwrap().is_io());
        })
        .await
        .unwrap();
    });
    assert!(wait_until(Duration::from_secs(2), || gate.tasks_left() == 0));
}

#[test]
fn stream_reset_stays_an_h2_error() {
    // A RST_STREAM before the 200 is the stream's own answer on a live
    // connection: h2's error at once, with no wait for a connection end.
    let (relay, f) = pooled();
    let gate = WorkGate::new();
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(20), async {
            let conn = f.dial(&loopback(), &limiter(), &gate).await.unwrap();
            relay.reset_before_200(1, h2::Reason::REFUSED_STREAM);
            let started = Instant::now();
            let error = match conn.open_carrier(&f.crypto).await {
                Ok(_) => panic!("a reset carrier opened"),
                Err(error) => error,
            };
            assert!(started.elapsed() < CONN_END_GRACE / 2);
            assert!(error.downcast_ref::<CarrierLost>().is_none(), "{error:#}");
            let error = error.downcast_ref::<h2::Error>().unwrap();
            assert!(error.is_reset());
            assert_eq!(error.reason(), Some(h2::Reason::REFUSED_STREAM));
            assert_eq!(conn.ended(), None);
            // The connection still carries the next stream.
            let carrier = conn.open_carrier(&f.crypto).await.unwrap();
            echo(&mut open_echo(&f.crypto, carrier).await, b"after a reset").await;
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.conns(), 1);
    assert!(wait_until(Duration::from_secs(2), || gate.tasks_left() == 0));
}

// ---- S16h-4: the flow pool, at 170 ms RTT ----

/// How long one test flow may wait for its stream and its permit.
const FLOW_BUDGET: Duration = Duration::from_secs(30);

/// `kit` whose signed relay is a latency link at the design RTT in front
/// of the multi-stream relay.
fn linked() -> (PooledRelay, TestLink, Kit) {
    linked_with(PoolConfig::default())
}

fn linked_with(config: PoolConfig) -> (PooledRelay, TestLink, Kit) {
    linked_with_rtt(config, DEFAULT_RTT)
}

fn linked_with_rtt(config: PoolConfig, rtt: Duration) -> (PooledRelay, TestLink, Kit) {
    let listener = TestRelay::bind();
    let link = TestLink::with_rtt(listener.local_addr().unwrap(), rtt);
    let f = kit_on(ReadyTree::with_online_completed(link.address()));
    let relay = TestRelay::spawn_streams(listener, RelayIdentity::for_tree(&f.tree), config);
    (relay, link, f)
}

/// An epoch's pins with nothing re-pinned, and the generation a session
/// binds under.
fn unpinned() -> (EpochPins, u64) {
    let pins = EpochPins::default();
    let generation = pins.generation();
    (pins, generation)
}

/// v36: the pins of an epoch whose start asked for the v35 window
/// (`--window-policy adaptive`, a QA arm). A fresh epoch's default is now
/// the fixed window, so a test of the adaptive window's growth asks for it.
fn adaptive() -> (EpochPins, u64) {
    let (pins, generation) = unpinned();
    pins.set_window_mode(crate::configuration::WindowMode::Adaptive);
    (pins, generation)
}

fn pool_of(
    f: &Kit,
    limiter: &Arc<EstablishLimiter>,
    gate: &Arc<WorkGate>,
    pins: (EpochPins, u64),
    limits: Limits,
) -> Arc<FlowPool> {
    FlowPool::with_limits(
        f.peer(),
        loopback(),
        f.crypto.clone(),
        (limiter.clone(), gate.clone()),
        pins,
        limits,
    )
    .unwrap()
}

/// One accepted TCP flow to the relay's echo on a pooled stream.
struct Flow {
    inner: Inner,
    slot: StreamSlot,
    // Its carrier stream's H2 ID.
    stream_id: u32,
    _live: LiveFlow,
}

/// A flow as the flow path runs one: its live place, a pooled stream (no
/// permit held while it waits), then a flow permit for the carrier (sent as
/// `StreamSlot::sent` records), the inner mTLS and the Open, returned once
/// the Open is written. v34: its carrier opens as a flow's does
/// (`StreamSlot::open_carrier`), its receive window under the pool's
/// budget.
async fn flow(
    pool: &Arc<FlowPool>,
    crypto: &PreparedCryptoInputs,
    limiter: &Arc<EstablishLimiter>,
    live: LiveFlow,
) -> anyhow::Result<Flow> {
    let deadline = Instant::now() + FLOW_BUDGET;
    let mut slot = pool.reserve(deadline).await?;
    let mut permit = limiter
        .acquire(
            Purpose::Flow,
            deadline.saturating_duration_since(Instant::now()),
        )
        .await?;
    let _ = slot.sent(slot.conn().srtt());
    let carrier = slot.open_carrier(crypto).await?;
    let stream_id = carrier.stream_id;
    let inner = crypto.inner_client().connect(carrier.io).await;
    slot.handshake_done(inner.is_ok());
    let mut inner = inner?;
    let open = OpenRequest {
        transport: Transport::Tcp,
        version: 1,
        host: "echo.test".into(),
        port: 7,
    };
    secure_channel::write_open(&mut inner, &open).await?;
    inner.flush().await?;
    permit.request_written();
    let status = inner.read_u8().await;
    slot.answered();
    anyhow::ensure!(status? == 0, "open refused");
    permit.succeeded();
    Ok(Flow {
        inner,
        slot,
        stream_id,
        _live: live,
    })
}

async fn open_flow(
    pool: &Arc<FlowPool>,
    crypto: &PreparedCryptoInputs,
    limiter: &Arc<EstablishLimiter>,
) -> Flow {
    let live = limiter.live_flow().expect("a live place");
    flow(pool, crypto, limiter, live).await.unwrap()
}

/// End `flow` as a client does: its FIN, then the relay's EOF.
async fn end(mut flow: Flow) {
    flow.inner.shutdown().await.unwrap();
    let mut rest = Vec::new();
    flow.inner.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty());
}

#[test]
fn lazy_single_connection() {
    let (relay, link, f) = linked();
    let gate = WorkGate::new();
    let limiter = limiter();
    let pool = pool_of(&f, &limiter, &gate, unpinned(), Limits::default());
    // A pool with no flow dials nothing.
    thread::sleep(Duration::from_millis(200));
    assert_eq!(link.connections(), 0);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(60), async {
            for round in 0..5u8 {
                let mut flow = open_flow(&pool, &f.crypto, &limiter).await;
                assert_eq!(flow.slot.conn_id(), 0, "round {round}");
                echo(&mut flow.inner, &[round; 16]).await;
                end(flow).await;
            }
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.conns(), 1);
    assert_eq!(link.connections(), 1);
    assert_eq!(relay.streams(), 5);
    assert_eq!(pool.stats().dials, 1);
    assert_eq!(relay.strikes(), 0);
    assert_eq!(limiter.auth_failures(), 0);
}

#[derive(Debug)]
enum Outcome {
    LiveCap,
    Done(u64),
    Failed(String),
}

/// aegis-core's default inner sessions per peer (`AdmissionLimits`), which
/// the test relay keeps unless a test takes a deployed relay's value.
const DEFAULT_RELAY_SESSIONS: usize = 128;
/// The live cap against a relay at aegis-server's defaults (128 sessions per
/// peer, 32 streams per connection): 119 (S16k: 128 less the ACK path's 4
/// sessions and the margin's 5), written out so that a changed
/// derivation fails here. It is not this build's `LIVE_FLOWS`, which is
/// derived from relay-a's 1024 sessions per peer (248, the pool's bound
/// at 62 streams per connection): the tests of a default relay tune their
/// limiter to this cap, as a session bound to such a relay would need.
const DEFAULT_RELAY_LIVE: usize = live_cap_for(usize::MAX, DEFAULT_RELAY_SESSIONS);
const _: () = assert!(DEFAULT_RELAY_LIVE == 119);

#[test]
fn caps() {
    const FLOWS: usize = 130;
    // The bounds the relay's limits fix, written out so that a changed pool
    // constant fails here rather than moving the bound with it: at most four
    // connections (an unauthenticated-socket and DPI budget), 30 streams each
    // (under aegis-server's 32), four handshakes each (S16j-4: 16 under the
    // deployed relay's 32 per peer; since R2 a timeout is no strike) and two
    // dials at once.
    const CONNS: usize = 4;
    const STREAMS: usize = 30;
    const HANDSHAKES: usize = 4;
    const DIALS: usize = 2;
    // A relay at aegis-server's defaults (the test relay's): 128 sessions
    // per peer and 32 streams per connection. Its live cap is 119 (S16k:
    // its 128 sessions less the ACK path's 4 and the margin's 5, one under 4
    // connections of 30 streams), not this build's 248 (`LIVE_FLOWS`,
    // relay-a's 1024 sessions), so the limiter is tuned to it: the 120th
    // flow and later must still find the live cap before any stream.
    const LIVE: usize = DEFAULT_RELAY_LIVE;
    assert_eq!(
        secure_channel::AdmissionLimits::default().max_sessions_per_peer,
        DEFAULT_RELAY_SESSIONS
    );
    // S16k: one place under the pool's 4 connections of 30 streams.
    assert_eq!(LIVE + 1, CONNS * STREAMS);
    let (relay, link, f) = linked();
    let gate = WorkGate::new();
    // Permits enough that only the pool's own caps bind (S16h-7 sizes the
    // session limiter to the pool).
    let mut limiter = EstablishLimiter::for_test(ESTABLISH_PERMITS, ACK_RESERVE, AUTH_BACKOFF);
    assert_eq!((ESTABLISH_PERMITS, ACK_RESERVE), (20, 4));
    EstablishLimiter::tune(&mut limiter).set_flow_limits(FLOW_BACKOFF, 40, LIVE);
    EstablishLimiter::tune(&mut limiter).set_relay_sessions(DEFAULT_RELAY_SESSIONS);
    let pool = pool_of(&f, &limiter, &gate, unpinned(), Limits::default());
    let opened = Arc::new(AtomicUsize::new(0));
    let (release, released) = watch::channel(false);
    let outcomes = f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(90), async {
            let mut flows = tokio::task::JoinSet::new();
            for _ in 0..FLOWS {
                // Taken in order: the 120th and later find the live cap.
                let live = limiter.live_flow();
                let (pool, crypto, limiter) = (pool.clone(), f.crypto.clone(), limiter.clone());
                let (opened, mut released) = (opened.clone(), released.clone());
                flows.spawn(async move {
                    let Some(live) = live else {
                        return Outcome::LiveCap;
                    };
                    match flow(&pool, &crypto, &limiter, live).await {
                        Ok(mut flow) => {
                            echo(&mut flow.inner, b"held").await;
                            opened.fetch_add(1, Ordering::SeqCst);
                            released.wait_for(|go| *go).await.unwrap();
                            let conn = flow.slot.conn_id();
                            end(flow).await;
                            Outcome::Done(conn)
                        }
                        Err(error) => Outcome::Failed(format!("{error:#}")),
                    }
                });
            }
            while opened.load(Ordering::SeqCst) < LIVE {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            // Every admitted flow is live at once.
            let views = pool.views();
            assert!(views.len() <= CONNS, "{views:?}");
            assert!(views.iter().all(|view| view.streams <= STREAMS));
            assert_eq!(views.iter().map(|view| view.streams).sum::<usize>(), LIVE);
            release.send(true).unwrap();
            let mut outcomes = Vec::new();
            while let Some(outcome) = flows.join_next().await {
                outcomes.push(outcome.unwrap());
            }
            outcomes
        })
        .await
        .unwrap()
    });
    let failed: Vec<_> = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, Outcome::Failed(_)))
        .collect();
    assert!(failed.is_empty(), "{failed:?}");
    let capped = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, Outcome::LiveCap))
        .count();
    assert_eq!(capped, FLOWS - LIVE);
    let done = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, Outcome::Done(_)))
        .count();
    assert_eq!(done, LIVE);
    // The 120th flow and later never reached the relay.
    assert_eq!(relay.streams(), LIVE);
    let stats = pool.stats();
    assert!(stats.max_conns <= CONNS, "{stats:?}");
    assert!(stats.max_dials <= DIALS, "{stats:?}");
    assert!(stats.max_establishing <= HANDSHAKES, "{stats:?}");
    assert!(stats.max_streams <= STREAMS, "{stats:?}");
    assert!(relay.conns() <= CONNS);
    assert_eq!(link.connections(), relay.conns());
    let refused = u32::from(h2::Reason::REFUSED_STREAM);
    let events = relay.events();
    for conn in 0..relay.conns() {
        let stats = relay.connection(conn);
        assert!(stats.max_concurrent_streams() <= STREAMS);
        assert!(
            handshake_high_water(&events, conn, link.rtt() / 4) <= HANDSHAKES,
            "conn {conn}"
        );
        assert!(stats
            .resets(false)
            .iter()
            .all(|(_, reason)| *reason != refused));
    }
    assert_eq!(relay.strikes(), 0);
    assert_eq!(relay.handshake_caps(), 0);
    assert_eq!(limiter.auth_failures(), 0);
    assert_eq!(limiter.flow_refusals(), 0);
}

/// The most streams of relay connection `conn` exposed in their inner
/// handshake at once, from the relay's events: each from its 200 until its
/// authentication, less `slack`. The client frees a handshake slot when the
/// relay's Finished arrives and may start the next stream at once; that
/// stream's HEADERS reach the relay right behind the client's Finished, so
/// the relay's own gauge can overlap the two for a moment of task order,
/// while a stream over the cap overlaps for about a whole RTT.
fn handshake_high_water(
    events: &[crate::test_relay::pool::StreamEvent],
    conn: usize,
    slack: Duration,
) -> usize {
    let mut edges = Vec::new();
    for responded in events
        .iter()
        .filter(|event| event.conn == conn && event.step == StreamStep::Responded)
    {
        let ended = events
            .iter()
            .filter(|event| event.index == responded.index && event.at >= responded.at)
            .find(|event| {
                matches!(
                    event.step,
                    StreamStep::Authenticated
                        | StreamStep::Struck
                        | StreamStep::HandshakeFailed
                        | StreamStep::HandshakeCapped
                        | StreamStep::Expired
                )
            })
            .map(|event| event.at);
        // A handshake that never ended stays exposed to the end.
        let ended = ended.map_or(std::time::Instant::now(), |at| at - slack);
        if ended > responded.at {
            edges.push((responded.at, 1i64));
            edges.push((ended, -1));
        }
    }
    edges.sort();
    let (mut now, mut high) = (0i64, 0i64);
    for (_, step) in edges {
        now += step;
        high = high.max(now);
    }
    usize::try_from(high).unwrap()
}

#[test]
fn probe_then_fill() {
    // Each connection's probe, then `H_CONN` more on one of them (5 at
    // `H_CONN` 2, 9 at 4): the second connection's probe and the rest.
    const FLOWS: usize = 1 + 2 * H_CONN;
    let (relay, link, f) = linked();
    let gate = WorkGate::new();
    let limiter = EstablishLimiter::for_test(20, 3, AUTH_BACKOFF);
    let pool = pool_of(&f, &limiter, &gate, unpinned(), Limits::default());
    let conns = f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(60), async {
            let mut flows = tokio::task::JoinSet::new();
            for _ in 0..FLOWS {
                let (pool, crypto, limiter) = (pool.clone(), f.crypto.clone(), limiter.clone());
                flows.spawn(async move { open_flow(&pool, &crypto, &limiter).await });
            }
            let mut held = Vec::new();
            while let Some(flow) = flows.join_next().await {
                held.push(flow.unwrap());
            }
            let conns: Vec<u64> = held.iter().map(|flow| flow.slot.conn_id()).collect();
            for flow in held {
                end(flow).await;
            }
            conns
        })
        .await
        .unwrap()
    });
    let events = relay.events();
    // S16j-1: the first connection to authenticate a stream (the pool was
    // unproven while its probe ran) carried that one stream until then; a
    // connection of the proven pool may take more after its first 200
    // (`proven_session_opens_new_connections_after_their_first_200`).
    let first_auth = |conn: usize| {
        events
            .iter()
            .filter(|event| event.conn == conn && event.step == StreamStep::Authenticated)
            .map(|event| event.at)
            .min()
            .unwrap()
    };
    let first = (0..relay.conns())
        .min_by_key(|conn| first_auth(*conn))
        .unwrap();
    // A fresh connection carries one stream until its mTLS completes.
    // The client's inner connect returns when the relay's Finished
    // arrives; the relay authenticates the probe half an RTT later, as
    // the client's Finished arrives, and the next stream's HEADERS ride
    // right behind it. Without the probe rule the second stream arrives
    // about two RTT before the probe authenticates.
    let probe_done = first_auth(first) - link.rtt() / 2;
    let before = events
        .iter()
        .filter(|event| event.conn == first && event.step == StreamStep::Accepted)
        .filter(|event| event.at < probe_done)
        .count();
    assert_eq!(before, 1, "conn {first}: {events:?}");
    // Two dials at once at most, and no more than the flows needed.
    assert_eq!(pool.stats().dials, 2, "{conns:?}");
    assert_eq!(relay.conns(), 2);
    // Then it fills: the waiting flows took every handshake slot of a
    // connection at once.
    assert_eq!(pool.stats().max_establishing, H_CONN);
    assert!(
        (0..relay.conns()).any(|conn| relay.connection(conn).handshakes().high_water() == H_CONN)
    );
    assert_eq!(relay.strikes(), 0);
}

#[test]
fn idle_reuse() {
    let (relay, _link, f) = linked();
    let gate = WorkGate::new();
    let limiter = limiter();
    let pool = pool_of(&f, &limiter, &gate, unpinned(), Limits::default());
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(60), async {
            let round = |idle: Duration, conns: usize| {
                let (pool, crypto, limiter, relay) = (&pool, &f.crypto, &limiter, &relay);
                async move {
                    tokio::time::sleep(idle).await;
                    let mut flow = open_flow(pool, crypto, limiter).await;
                    assert_eq!(relay.conns(), conns, "after {idle:?} idle");
                    echo(&mut flow.inner, b"idle").await;
                    end(flow).await;
                    assert_eq!(relay.strikes(), 0, "after {idle:?} idle");
                }
            };
            round(Duration::ZERO, 1).await;
            // Within IDLE_REUSE: the same connection.
            round(Duration::from_millis(500), 1).await;
            // Past it: a fresh connection, and the idle one is closed by
            // this side at once, not left to the relay's idle close.
            round(Duration::from_millis(1_200), 2).await;
            let closed = relay.connection(0).closed();
            assert_eq!(closed.map(|(_, close)| close), Some(Close::ClientEnded));
            // Close to the relay's idle close: a stream reusing the
            // connection would race its accept deadline and strike.
            round(Duration::from_millis(4_700), 3).await;
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.streams(), 4);
    assert_eq!(relay.strikes(), 0);
    assert_eq!(limiter.flow_refusals(), 0);
}

#[test]
fn repin_fails_fast() {
    let (relay, _link, f) = linked();
    let gate = WorkGate::new();
    let pins = EpochPins::default();
    let limiter = EstablishLimiter::new(pins.auth_backoff());
    let pool = pool_of(
        &f,
        &limiter,
        &gate,
        (pins.clone(), pins.generation()),
        Limits::default(),
    );
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            let mut held = open_flow(&pool, &f.crypto, &limiter).await;
            echo(&mut held.inner, b"before").await;
            pins.repin(&RelayInterface::for_test("en9", 9));
            let streams = relay.streams();
            let started = Instant::now();
            let refusal = match pool.reserve(started + FLOW_BUDGET).await {
                Ok(_) => panic!("a stale session reserved a stream"),
                Err(error) => error,
            };
            assert!(started.elapsed() < Duration::from_millis(25));
            assert_eq!(refusal.kind(), io::ErrorKind::PermissionDenied);
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert_eq!(relay.streams(), streams);
            assert_eq!(relay.conns(), 1);
            assert_eq!(pool.views()[0].phase, Phase::Draining);
            drop(held);
        })
        .await
        .unwrap();
    });
    assert_eq!(
        relay
            .events()
            .iter()
            .filter(|event| event.step == StreamStep::Accepted)
            .count(),
        1
    );
}

#[test]
fn wake_drains() {
    let (relay, _link, f) = linked();
    let gate = WorkGate::new();
    let pins = EpochPins::default();
    let epoch = pins.auth_backoff();
    let limiter = EstablishLimiter::new(epoch.clone());
    let pool = pool_of(
        &f,
        &limiter,
        &gate,
        (pins.clone(), pins.generation()),
        Limits::default(),
    );
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            let mut old = open_flow(&pool, &f.crypto, &limiter).await;
            assert_eq!(old.slot.conn_id(), 0);
            // A sleep and its wake.
            epoch.quiesce(std::time::Instant::now());
            epoch.resume();
            let mut new = open_flow(&pool, &f.crypto, &limiter).await;
            assert_eq!(new.slot.conn_id(), 1);
            assert_eq!(relay.conns(), 2);
            let phases: Vec<Phase> = pool.views().iter().map(|view| view.phase).collect();
            assert_eq!(phases, [Phase::Draining, Phase::Open]);
            // The drained connection's flow runs to its end; then it closes.
            echo(&mut old.inner, b"old").await;
            echo(&mut new.inner, b"new").await;
            end(old).await;
            let closed = relay.wait_closed(0, Duration::from_secs(2)).await;
            assert_eq!(closed.map(|(_, close)| close), Some(Close::ClientEnded));
            assert_eq!(pool.views().len(), 1);
            end(new).await;
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.strikes(), 0);
}

#[test]
fn rotation() {
    const ROTATE_AT: usize = 8;
    let (relay, _link, f) = linked();
    let gate = WorkGate::new();
    let limiter = limiter();
    let limits = Limits {
        max_conn_streams: ROTATE_AT,
        pool_conns: 1,
        pool_dials: 1,
        ..Limits::default()
    };
    let pool = pool_of(&f, &limiter, &gate, unpinned(), limits);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(60), async {
            let mut opening = tokio::task::JoinSet::new();
            for _ in 0..ROTATE_AT {
                let (pool, crypto, limiter) = (pool.clone(), f.crypto.clone(), limiter.clone());
                opening.spawn(async move { open_flow(&pool, &crypto, &limiter).await });
            }
            let mut old = Vec::new();
            while let Some(flow) = opening.join_next().await {
                old.push(flow.unwrap());
            }
            assert!(old.iter().all(|flow| flow.slot.conn_id() == 0));
            // The ninth stream opens on a new connection.
            let mut ninth = open_flow(&pool, &f.crypto, &limiter).await;
            assert_eq!(ninth.slot.conn_id(), 1);
            assert_eq!(relay.conns(), 2);
            assert_eq!(pool.views()[0].phase, Phase::Draining);
            assert_eq!(pool.views()[0].opened, ROTATE_AT);
            // The old connection's flows echo until their EOF.
            for (at, flow) in old.iter_mut().enumerate() {
                echo(&mut flow.inner, format!("old {at}").as_bytes()).await;
            }
            for flow in old {
                end(flow).await;
            }
            let closed = relay.wait_closed(0, Duration::from_secs(2)).await;
            assert_eq!(closed.map(|(_, close)| close), Some(Close::ClientEnded));
            echo(&mut ninth.inner, b"ninth").await;
            end(ninth).await;
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.connection(0).max_concurrent_streams(), ROTATE_AT);
    assert_eq!(relay.strikes(), 0);
}

#[test]
fn gate_drain() {
    const FLOWS: usize = 30;
    let (relay, _link, f) = linked();
    let gate = WorkGate::new();
    let limiter = EstablishLimiter::for_test(20, 3, AUTH_BACKOFF);
    let limits = Limits {
        pool_conns: 3,
        ..Limits::default()
    };
    let pool = pool_of(&f, &limiter, &gate, unpinned(), limits);
    let opened = Arc::new(AtomicUsize::new(0));
    let tasks = f.runtime.block_on(async {
        let mut tasks = Vec::new();
        for _ in 0..FLOWS {
            let (pool, crypto, limiter) = (pool.clone(), f.crypto.clone(), limiter.clone());
            let (opened, permit) = (opened.clone(), gate.admit().unwrap());
            // Each flow holds a gate permit and runs as a gate task, as the
            // packet engine's relay work does.
            tasks.push(
                gate.spawn(async move {
                    let _permit = permit;
                    let mut flow = open_flow(&pool, &crypto, &limiter).await;
                    echo(&mut flow.inner, b"live").await;
                    opened.fetch_add(1, Ordering::SeqCst);
                    std::future::pending::<()>().await;
                })
                .unwrap(),
            );
        }
        tokio::time::timeout(Duration::from_secs(60), async {
            while opened.load(Ordering::SeqCst) < FLOWS {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        tasks
    });
    let views = pool.views();
    assert_eq!(views.len(), 3, "{views:?}");
    assert_eq!(views.iter().map(|view| view.streams).sum::<usize>(), FLOWS);
    assert_eq!(gate.flows(), FLOWS);
    // Three drivers and thirty flows, all gate tasks.
    assert_eq!(gate.tasks_left(), FLOWS + 3);
    // The test thread is no runtime worker: stop blocks only it.
    gate.stop(crate::held_relay_services::MAX_DRAIN).unwrap();
    assert_eq!(gate.tasks_left(), 0);
    assert_eq!(gate.flows(), 0);
    // A stopped gate refuses every reservation at once, before any dial.
    f.runtime.block_on(async {
        let started = Instant::now();
        let refusal = match pool.reserve(started + FLOW_BUDGET).await {
            Ok(_) => panic!("a stopped gate reserved a stream"),
            Err(error) => error,
        };
        assert_eq!(refusal.kind(), io::ErrorKind::PermissionDenied);
        assert!(started.elapsed() < Duration::from_millis(25));
    });
    // Every pooled connection ended with its driver, the pool alive.
    f.runtime.block_on(async {
        for conn in 0..3 {
            assert!(
                relay
                    .wait_closed(conn, Duration::from_secs(1))
                    .await
                    .is_some(),
                "conn {conn} still open"
            );
        }
    });
    assert_eq!(relay.conns(), 3);
    assert_eq!(relay.strikes(), 0);
    drop((tasks, pool));
}

#[test]
fn goaway_marks_dead_and_calm_pauses_dials() {
    let (relay, _link, f) = linked();
    let gate = WorkGate::new();
    let limiter = limiter();
    let pool = pool_of(&f, &limiter, &gate, unpinned(), Limits::default());
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            let held = open_flow(&pool, &f.crypto, &limiter).await;
            let mut end_watch = held.slot.conn().end_watch();
            relay.goaway(0, h2::Reason::ENHANCE_YOUR_CALM, 1);
            end_watch.wait_for(Option::is_some).await.unwrap();
            // The next flow finds the connection dead, and no new one is
            // dialed during the pause.
            let started = Instant::now();
            let mut calm = open_flow(&pool, &f.crypto, &limiter).await;
            let waited = started.elapsed();
            assert!(
                waited >= FLOW_BACKOFF - Duration::from_millis(50),
                "{waited:?}"
            );
            assert!(waited < FLOW_BACKOFF + Duration::from_secs(2), "{waited:?}");
            assert_eq!(calm.slot.conn_id(), 1);
            let phases: Vec<Phase> = pool.views().iter().map(|view| view.phase).collect();
            assert_eq!(phases, [Phase::Dead, Phase::Open]);
            drop(held);
            assert_eq!(pool.views().len(), 1);
            // A graceful GOAWAY keeps the processed flow, marks the
            // connection dead, and pauses nothing.
            relay.goaway(1, h2::Reason::NO_ERROR, 1);
            let mut end_watch = calm.slot.conn().end_watch();
            end_watch.wait_for(Option::is_some).await.unwrap();
            let started = Instant::now();
            let next = open_flow(&pool, &f.crypto, &limiter).await;
            assert!(started.elapsed() < Duration::from_secs(1));
            assert_eq!(next.slot.conn_id(), 2);
            echo(&mut calm.inner, b"after a graceful goaway").await;
            end(calm).await;
            end(next).await;
        })
        .await
        .unwrap();
    });
    assert_eq!(pool.stats().goaways, 2);
    assert_eq!(relay.conns(), 3);
    assert_eq!(relay.strikes(), 0);
    assert_eq!(limiter.auth_failures(), 0);
}

#[test]
fn selection_prefers_fewest_establishing_then_fewest_live() {
    let (_listener, f) = kit();
    let gate = WorkGate::new();
    let limiter = limiter();
    let pool = pool_of(&f, &limiter, &gate, unpinned(), Limits::default());
    f.runtime.block_on(async {
        let mut held = Vec::new();
        let mut ids = Vec::new();
        // (phase, establishing, authenticated live streams)
        for (phase, counts) in [
            (Phase::Open, (1, 5)),
            (Phase::Open, (0, 9)),
            (Phase::Open, (0, 3)),
            // A probe in flight, and a drained connection: never chosen.
            (Phase::Probing, (1, 0)),
            (Phase::Draining, (0, 1)),
        ] {
            let (conn, sender, cut, relay) = unrecorded_conn(&gate).await;
            ids.push(pool.insert_for_test(conn, phase, counts));
            held.push((sender, cut, relay));
        }
        let mut chosen = Vec::new();
        let mut slots = Vec::new();
        for _ in 0..5 {
            let slot = pool.reserve(Instant::now() + FLOW_BUDGET).await.unwrap();
            chosen.push(slot.conn_id());
            slots.push(slot);
        }
        // (0,3) -> (0,9) -> (1,4) -> (1,6) -> (1,10); then all are full.
        assert_eq!(chosen, [ids[2], ids[1], ids[2], ids[0], ids[1]]);
        let views = pool.views();
        assert_eq!(
            views
                .iter()
                .map(|view| view.establishing)
                .collect::<Vec<_>>(),
            [2, 2, 2, 1, 0]
        );
        drop(slots);
        drop(held);
    });
    assert_eq!(pool.stats().dials, 0);
}

#[test]
fn age_drains() {
    let (relay, _link, f) = linked();
    let gate = WorkGate::new();
    let limiter = limiter();
    let limits = Limits {
        max_conn_age: Duration::from_secs(3),
        ..Limits::default()
    };
    let pool = pool_of(&f, &limiter, &gate, unpinned(), limits);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            let mut old = open_flow(&pool, &f.crypto, &limiter).await;
            // Young and live: reused.
            let young = open_flow(&pool, &f.crypto, &limiter).await;
            assert_eq!(young.slot.conn_id(), 0);
            end(young).await;
            tokio::time::sleep(Duration::from_millis(3_100)).await;
            // Past its age: no new stream, though a flow keeps it live.
            let mut fresh = open_flow(&pool, &f.crypto, &limiter).await;
            assert_eq!(fresh.slot.conn_id(), 1);
            let phases: Vec<Phase> = pool.views().iter().map(|view| view.phase).collect();
            assert_eq!(phases, [Phase::Draining, Phase::Open]);
            echo(&mut old.inner, b"old").await;
            echo(&mut fresh.inner, b"fresh").await;
            end(old).await;
            end(fresh).await;
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.conns(), 2);
    assert_eq!(relay.strikes(), 0);
}

#[test]
fn cancelled_waiters_and_dials_leave_no_count() {
    let (relay, _link, f) = linked();
    let gate = WorkGate::new();
    let limiter = limiter();
    let limits = Limits {
        pool_conns: 1,
        pool_dials: 1,
        ..Limits::default()
    };
    let pool = pool_of(&f, &limiter, &gate, unpinned(), limits);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            // A dialer and a waiter behind it, both dropped mid-dial (the
            // outer TLS takes one RTT).
            let dialer = tokio::spawn({
                let pool = pool.clone();
                async move { pool.reserve(Instant::now() + FLOW_BUDGET).await.map(|_| ()) }
            });
            tokio::time::sleep(Duration::from_millis(20)).await;
            let waiter = tokio::spawn({
                let pool = pool.clone();
                async move { pool.reserve(Instant::now() + FLOW_BUDGET).await.map(|_| ()) }
            });
            tokio::time::sleep(Duration::from_millis(20)).await;
            assert_eq!(pool.queue(), (2, 1));
            dialer.abort();
            waiter.abort();
            let _ = (dialer.await, waiter.await);
            assert_eq!(pool.queue(), (0, 0));
            // A waiter that runs out of time leaves no count either.
            let timed_out = pool.reserve(Instant::now()).await.map(|_| ()).unwrap_err();
            assert_eq!(timed_out.kind(), io::ErrorKind::TimedOut);
            assert_eq!(pool.queue(), (0, 0));
            // The next flow dials as if nothing had been cancelled.
            let flow = open_flow(&pool, &f.crypto, &limiter).await;
            end(flow).await;
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.strikes(), 0);
}

#[test]
fn a_reservation_past_its_deadline_never_dials() {
    let (relay, link, f) = linked();
    let gate = WorkGate::new();
    let limiter = limiter();
    let pool = pool_of(&f, &limiter, &gate, unpinned(), Limits::default());
    f.runtime.block_on(async {
        // An empty pool with dial capacity: the deadline has passed by the
        // time the flow looks, so it times out with no dial and no SYN.
        let timed_out = pool.reserve(Instant::now()).await.map(|_| ()).unwrap_err();
        assert_eq!(timed_out.kind(), io::ErrorKind::TimedOut);
        tokio::time::sleep(Duration::from_millis(300)).await;
    });
    assert_eq!(pool.stats().dials, 0);
    assert_eq!(pool.stats().max_dials, 0);
    assert_eq!(pool.queue(), (0, 0));
    assert_eq!(link.connections(), 0);
    assert_eq!(relay.conns(), 0);
}

#[test]
fn a_dial_held_over_a_sleep_is_current_after_the_wake() {
    let (relay, _link, f) = linked();
    let gate = WorkGate::new();
    let pins = EpochPins::default();
    let epoch = pins.auth_backoff();
    let limiter = EstablishLimiter::new(epoch.clone());
    let pool = pool_of(
        &f,
        &limiter,
        &gate,
        (pins.clone(), pins.generation()),
        Limits::default(),
    );
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            // The pause before sleep holds a flow's dial in its permit wait.
            epoch.quiesce(std::time::Instant::now());
            let first = tokio::spawn({
                let (pool, crypto, limiter) = (pool.clone(), f.crypto.clone(), limiter.clone());
                async move { open_flow(&pool, &crypto, &limiter).await }
            });
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert_eq!(pool.queue(), (1, 1));
            assert_eq!(relay.conns(), 0);
            // The wake: the held dial connects after it, so its connection
            // is current and takes the next flow.
            epoch.resume();
            let first = first.await.unwrap();
            assert_eq!(first.slot.conn_id(), 0);
            let second = open_flow(&pool, &f.crypto, &limiter).await;
            assert_eq!(second.slot.conn_id(), 0);
            let phases: Vec<Phase> = pool.views().iter().map(|view| view.phase).collect();
            assert_eq!(phases, [Phase::Open]);
            end(first).await;
            end(second).await;
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.conns(), 1);
    assert_eq!(pool.stats().dials, 1);
    assert_eq!(relay.strikes(), 0);
}

#[test]
fn repin_refuses_a_dial_that_completes_after_it() {
    let (relay, f) = pooled();
    let gate = WorkGate::new();
    let pins = EpochPins::default();
    let epoch = pins.auth_backoff();
    let limiter = EstablishLimiter::new(epoch.clone());
    let pool = pool_of(
        &f,
        &limiter,
        &gate,
        (pins.clone(), pins.generation()),
        Limits::default(),
    );
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            // A dial waits in its permit wait; the epoch re-pins, then the
            // dial completes on the old pin.
            epoch.quiesce(std::time::Instant::now());
            let dialer = tokio::spawn({
                let pool = pool.clone();
                async move { pool.reserve(Instant::now() + FLOW_BUDGET).await.map(|_| ()) }
            });
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert_eq!(pool.queue(), (1, 1));
            pins.repin(&RelayInterface::for_test("en9", 9));
            epoch.resume();
            let refusal = dialer.await.unwrap().unwrap_err();
            assert_eq!(refusal.kind(), io::ErrorKind::PermissionDenied);
            // The dial reached the relay; its connection took no stream and
            // was closed by this side at once (it was dropped right after its
            // H2 handshake), long before the relay's idle close.
            assert_eq!(relay.conns(), 1);
            assert!(pool.views().is_empty());
            assert_eq!(pool.queue(), (0, 0));
            let closed = relay.wait_closed(0, Duration::from_secs(2)).await;
            assert!(
                closed.is_some_and(|(_, close)| close != Close::Idle),
                "{closed:?}"
            );
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.streams(), 0);
    assert_eq!(relay.strikes(), 0);
    assert_eq!(limiter.auth_failures(), 0);
    assert!(wait_until(Duration::from_secs(2), || gate.tasks_left() == 0));
}

#[test]
fn calm_goaway_on_a_draining_connection_pauses_dials() {
    let (relay, _link, f) = linked();
    let gate = WorkGate::new();
    let limiter = limiter();
    // One stream per connection's life: each connection drains at the next
    // look after its first stream.
    let limits = Limits {
        max_conn_streams: 1,
        ..Limits::default()
    };
    let pool = pool_of(&f, &limiter, &gate, unpinned(), limits);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            let old = open_flow(&pool, &f.crypto, &limiter).await;
            let held = open_flow(&pool, &f.crypto, &limiter).await;
            assert_eq!(held.slot.conn_id(), 1);
            let phases: Vec<Phase> = pool.views().iter().map(|view| view.phase).collect();
            assert_eq!(phases, [Phase::Draining, Phase::Open]);
            let mut end_watch = old.slot.conn().end_watch();
            relay.goaway(0, h2::Reason::ENHANCE_YOUR_CALM, 1);
            end_watch.wait_for(Option::is_some).await.unwrap();
            // The draining connection's last flow ends before any flow looks
            // at the pool: its end is noted as it leaves.
            drop(old);
            assert_eq!(pool.views().len(), 1);
            assert_eq!(pool.stats().goaways, 1);
            // The next flow needs a dial, and waits out the pause.
            let started = Instant::now();
            let next = open_flow(&pool, &f.crypto, &limiter).await;
            let waited = started.elapsed();
            assert!(
                waited >= FLOW_BACKOFF - Duration::from_millis(50),
                "{waited:?}"
            );
            assert!(waited < FLOW_BACKOFF + Duration::from_secs(2), "{waited:?}");
            assert_eq!(next.slot.conn_id(), 2);
            end(held).await;
            end(next).await;
        })
        .await
        .unwrap();
    });
    assert_eq!(pool.stats().goaways, 1);
    assert_eq!(relay.conns(), 3);
    assert_eq!(relay.strikes(), 0);
    assert_eq!(limiter.auth_failures(), 0);
}

#[test]
fn limits_cannot_exceed_the_constants() {
    let (_listener, f) = kit();
    let gate = WorkGate::new();
    let limiter = limiter();
    let build = |limits: Limits| {
        FlowPool::with_limits(
            f.peer(),
            loopback(),
            f.crypto.clone(),
            (limiter.clone(), gate.clone()),
            unpinned(),
            limits,
        )
        .map(|_| ())
    };
    build(Limits::default()).unwrap();
    for limits in [
        Limits {
            pool_conns: POOL_CONNS + 1,
            ..Limits::default()
        },
        Limits {
            streams_per_conn: STREAMS_CAP + 1,
            ..Limits::default()
        },
        Limits {
            h_conn: H_CONN + 1,
            ..Limits::default()
        },
        Limits {
            pool_dials: 0,
            ..Limits::default()
        },
        Limits {
            max_conn_streams: 0,
            ..Limits::default()
        },
    ] {
        assert_eq!(
            build(limits).unwrap_err().kind(),
            io::ErrorKind::InvalidInput,
            "{limits:?}"
        );
    }
    // Only the session's verified peer.
    let other: SocketAddr = "127.0.0.1:9".parse().unwrap();
    assert!(FlowPool::new(
        other,
        loopback(),
        f.crypto.clone(),
        (limiter.clone(), gate.clone()),
        unpinned(),
    )
    .is_err());
}

// ---- S16h-5: a flow's stream on the pool, through the held relay services,
// ---- at 170 ms RTT ----

struct NoEvents;
impl aegis_client::packet_engine::services::EventSink for NoEvents {
    fn emit(
        &self,
        _: &'static str,
        _: aegis_client::packet_engine::services::EngineEvent,
        _: &'static str,
        _: serde_json::Value,
    ) {
    }
}

type Services = Arc<crate::held_relay_services::HeldRelayServices>;
type FlowTask = tokio::task::JoinHandle<anyhow::Result<()>>;

/// The relay services of a session whose flow pool is `pool`, its bridge
/// granted a long lease by hand.
fn services_of(pool: &Arc<FlowPool>) -> (Services, aegis_core::RelaySettings) {
    services_leased(pool, Duration::from_secs(60))
}

/// `services_of` with a lease of `lease`.
fn services_leased(pool: &Arc<FlowPool>, lease: Duration) -> (Services, aegis_core::RelaySettings) {
    use crate::bridge::{LeasedPacketBridge, PacketBridge};
    let bridge = LeasedPacketBridge::new(
        PacketBridge::default(),
        aegis_client::capture_lease_gate::CaptureLeaseDeadline::default(),
    );
    let lease = u64::try_from(lease.as_nanos()).unwrap();
    bridge
        .grant_until(bridge.clock_ns().unwrap() + lease)
        .unwrap();
    let services = Arc::new(
        crate::held_relay_services::HeldRelayServices::new(
            Arc::new(NoEvents),
            bridge,
            pool.clone(),
        )
        .unwrap(),
    );
    let settings = services.signed_relay();
    (services, settings)
}

/// One TCP flow through `services` to the relay's echo: its application
/// side and its flow task.
async fn tcp_flow(
    services: &Services,
    settings: &aegis_core::RelaySettings,
) -> (TcpStream, FlowTask) {
    use aegis_client::packet_engine::services::RelayServices;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let app = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (local, _) = listener.accept().await.unwrap();
    let (services, settings) = (services.clone(), settings.clone());
    let task =
        tokio::spawn(async move { services.tcp(local, &settings, "echo.test".into(), 7).await });
    (app, task)
}

/// `bytes` through the flow's echo and back.
async fn app_echo(app: &mut TcpStream, bytes: &[u8]) -> io::Result<()> {
    app.write_all(bytes).await?;
    let mut echoed = vec![0; bytes.len()];
    app.read_exact(&mut echoed).await?;
    if echoed != bytes {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}

/// End a flow as an application does: its FIN, the relay's EOF, the flow's
/// own result.
async fn close(mut app: TcpStream, task: FlowTask) -> anyhow::Result<()> {
    app.shutdown().await?;
    let mut rest = Vec::new();
    app.read_to_end(&mut rest).await?;
    anyhow::ensure!(rest.is_empty(), "bytes after the echo");
    task.await?
}

/// `close` for every one of `flows` at once (S16n): each ends exactly as
/// `close` ends it, and each result is checked, but their FIN round trips
/// overlap instead of queueing one RTT apiece behind each other.
async fn close_all(flows: impl IntoIterator<Item = (TcpStream, FlowTask)>) -> anyhow::Result<()> {
    let mut closing = tokio::task::JoinSet::new();
    for (app, task) in flows {
        closing.spawn(close(app, task));
    }
    while let Some(closed) = closing.join_next().await {
        closed??;
    }
    Ok(())
}

/// `n` live echo flows opened together on a pool of one connection: the
/// probe, then two at a time. With at least four, the last ones are sent
/// after the probe authenticated at the relay, so the connection is fresh
/// (`StreamSlot::sent`): every later stream on it inherits a whole relay
/// deadline.
async fn live_flows(
    services: &Services,
    settings: &aegis_core::RelaySettings,
    n: usize,
) -> Vec<(TcpStream, FlowTask)> {
    let mut flows = Vec::new();
    for _ in 0..n {
        flows.push(tcp_flow(services, settings).await);
    }
    for (tag, (app, _)) in flows.iter_mut().enumerate() {
        app_echo(app, &[u8::try_from(tag).unwrap(); 32])
            .await
            .unwrap();
    }
    flows
}

/// The pool limits of these tests: one connection (and one more once it is
/// dead), so every live flow shares it.
fn one_conn() -> Limits {
    Limits {
        pool_conns: 1,
        pool_dials: 1,
        ..Limits::default()
    }
}

/// Live siblings that make a connection fresh: the probe, then `H_CONN`
/// streams sent as it authenticated, then one more a whole cycle later, at
/// least one RTT after a live sibling's handshake (`FRESH_MARGIN`), so the
/// relay's idle anchor is known to have moved (6 at `H_CONN` 4; 4 at 2).
const SIBLINGS: usize = H_CONN + 2;

async fn wait_for(budget: Duration, mut done: impl FnMut() -> bool) -> bool {
    crate::test_relay::pool::wait_until(budget, || done().then_some(()))
        .await
        .is_some()
}

/// When the client sent stream `index`'s carrier request: half the link
/// before the relay accepted it.
fn client_request(relay: &PooledRelay, link: &TestLink, index: usize) -> std::time::Instant {
    relay
        .events()
        .iter()
        .find(|event| event.index == index && event.step == StreamStep::Accepted)
        .map(|event| event.at - link.rtt() / 2)
        .expect("never accepted")
}

#[test]
fn stream_bounds_run_from_the_request_within_the_relay_horizons() {
    let requested = Instant::now();
    let bounds = StreamBounds::new(requested, Duration::ZERO);
    assert_eq!(bounds.handshake, requested + HS_WATCHDOG);
    assert_eq!(bounds.status, requested + STATUS_BUDGET);
    assert_eq!(hs_budget(IDLE_REUSE), HS_WATCHDOG);
    // Past reuse (a live connection whose relay deadline is stale), both
    // end before the relay's deadline, which runs from the anchor.
    for idle_ms in [0u64, 500, 1_000, 1_500, 2_000, 2_500, 3_000, 4_000, 9_000] {
        let idle = Duration::from_millis(idle_ms);
        let bounds = StreamBounds::new(requested, idle);
        let anchor = requested.checked_sub(idle).unwrap();
        // Never before the request, however long the idle.
        assert!(
            bounds.handshake <= (anchor + HS_HORIZON).max(requested),
            "{idle:?}"
        );
        assert!(
            bounds.status <= (anchor + STATUS_HORIZON).max(requested),
            "{idle:?}"
        );
        assert!(bounds.handshake <= bounds.status, "{idle:?}");
        assert!(bounds.handshake >= requested, "{idle:?}");
    }
    assert_eq!(
        hs_budget(Duration::from_millis(2_000)),
        Duration::from_millis(1_500)
    );
    assert_eq!(hs_budget(Duration::from_secs(9)), Duration::ZERO);
}

#[test]
fn status_budget_leaves_the_relay_deadline_its_margin() {
    assert_eq!(status_budget(Duration::ZERO), STATUS_BUDGET);
    assert_eq!(status_budget(Duration::from_millis(500)), STATUS_BUDGET);
    // A connection idle at the open has spent that much of the relay's
    // deadline the stream inherits: the client gives up that much sooner.
    assert_eq!(
        status_budget(Duration::from_millis(800)),
        Duration::from_millis(3_700)
    );
    assert_eq!(status_budget(IDLE_REUSE), Duration::from_millis(3_500));
    assert_eq!(status_budget(Duration::from_secs(9)), Duration::ZERO);
}

#[test]
fn connection_loss_mid_burst() {
    const LIVE: usize = 10;
    let (relay, _link, f) = linked();
    let gate = WorkGate::new();
    let limiter = EstablishLimiter::for_test(20, 3, AUTH_BACKOFF);
    let pool = pool_of(&f, &limiter, &gate, unpinned(), one_conn());
    let (services, settings) = services_of(&pool);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(60), async {
            // Ten live flows on the one connection.
            let live = live_flows(&services, &settings, LIVE).await;
            assert_eq!(relay.conns(), 1);
            // Then one flow awaiting its status, and two in their inner
            // handshake, on the same connection.
            let next = relay.streams();
            relay.at(next, StreamFault::HangTarget);
            relay.at(next + 1, StreamFault::StallHandshake);
            relay.at(next + 2, StreamFault::StallHandshake);
            let (_awaiting_app, awaiting) = tcp_flow(&services, &settings).await;
            assert!(wait_for(Duration::from_secs(5), || limiter.unverified() == 1).await);
            let establishing = vec![
                tcp_flow(&services, &settings).await,
                tcp_flow(&services, &settings).await,
            ];
            relay
                .wait_count(StreamStep::HandshakeStalled, 2, Duration::from_secs(5))
                .await
                .unwrap();
            let views = pool.views();
            assert_eq!((views.len(), views[0].establishing), (1, 2), "{views:?}");
            assert_eq!(views[0].streams, LIVE + 3);
            // The connection dies: no GOAWAY, no close_notify.
            relay.drop_tcp(0);
            for (_app, task) in live {
                assert!(task.await.unwrap().is_err());
            }
            assert!(awaiting.await.unwrap().is_err());
            // Both establishing flows were retried on a new connection.
            for (mut app, task) in establishing {
                app_echo(&mut app, b"retried").await.unwrap();
                close(app, task).await.unwrap();
            }
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.conns(), 2);
    assert_eq!(relay.streams(), LIVE + 3 + 2);
    // A transport loss: neither class backs anything off, and the relay
    // charged nothing. Its RST was the relay's own end: no ledger entry
    // for the streams it ended mid-handshake (S16h-8b).
    assert_eq!(limiter.auth_failures(), 0);
    assert_eq!(limiter.flow_refusals(), 0);
    assert!(!limiter.flows_backing_off());
    assert_eq!(relay.strikes(), 0);
    assert_eq!(limiter.strikes(), 0);
}

#[test]
fn stream_only_end_is_unanswered() {
    let (relay, _link, f) = linked();
    let gate = WorkGate::new();
    let limiter = EstablishLimiter::for_test(20, 3, AUTH_BACKOFF);
    let pool = pool_of(&f, &limiter, &gate, unpinned(), one_conn());
    let (services, settings) = services_of(&pool);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            let mut siblings = live_flows(&services, &settings, SIBLINGS).await;
            relay.next_streams(1, StreamFault::EndStreamAfterMtls);
            let (_app, ended) = tcp_flow(&services, &settings).await;
            assert!(ended.await.unwrap().is_err());
            assert_eq!(relay.count(StreamStep::EndedAfterMtls), 1);
            assert_eq!(limiter.flow_refusals(), 1);
            assert!(limiter.flows_backing_off());
            // Its siblings on the same live connection keep echoing.
            for (app, _) in &mut siblings {
                app_echo(app, b"still here").await.unwrap();
            }
            close_all(siblings).await.unwrap();
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.conns(), 1);
    assert_eq!(relay.connection(0).closed(), None);
    assert_eq!(limiter.flow_refusals(), 1);
    assert_eq!(limiter.auth_failures(), 0);
}

#[test]
fn hang_target_not_unanswered() {
    let (relay, link, f) = linked();
    let gate = WorkGate::new();
    let limiter = EstablishLimiter::for_test(20, 3, AUTH_BACKOFF);
    let pool = pool_of(&f, &limiter, &gate, unpinned(), one_conn());
    let (services, settings) = services_of(&pool);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            // A live sibling: the connection never idles, so the whole
            // STATUS_BUDGET applies.
            let siblings = live_flows(&services, &settings, SIBLINGS).await;
            let index = relay.streams();
            relay.at(index, StreamFault::HangTarget);
            let asked = std::time::Instant::now();
            let (_app, hung) = tcp_flow(&services, &settings).await;
            // The connection is fresh: its stream goes out at once.
            let accepted = relay
                .wait_step(index, StreamStep::Accepted, Duration::from_secs(2))
                .await
                .expect("the stream waited");
            assert!(accepted - asked < link.rtt() * 2, "{:?}", accepted - asked);
            assert_eq!(relay.events().last().map(|event| event.conn), Some(0));
            assert!(hung.await.unwrap().is_err());
            let gave_up = std::time::Instant::now();
            let waited = gave_up - client_request(&relay, &link, index);
            assert!(
                waited >= STATUS_BUDGET - Duration::from_millis(100)
                    && waited <= STATUS_BUDGET + Duration::from_millis(100),
                "{waited:?}"
            );
            // Before the relay's own status-less reset at its deadline.
            assert_eq!(relay.count(StreamStep::TargetHung), 0);
            // A timeout: no flow backoff, no probing, and the next flow
            // starts at once.
            assert_eq!(limiter.flow_refusals(), 0);
            assert!(!limiter.flows_backing_off() && !limiter.flows_probing());
            let started = std::time::Instant::now();
            let (mut app, task) = tcp_flow(&services, &settings).await;
            app_echo(&mut app, b"next").await.unwrap();
            assert!(started.elapsed() < Duration::from_millis(1_500));
            close(app, task).await.unwrap();
            close_all(siblings).await.unwrap();
        })
        .await
        .unwrap();
    });
    assert_eq!(limiter.flow_refusals(), 0);
    assert_eq!(limiter.auth_failures(), 0);
    assert_eq!(relay.strikes(), 0);
}

#[test]
fn handshake_watchdog_prevents_strike() {
    let (relay, link, f) = linked();
    let gate = WorkGate::new();
    let limiter = EstablishLimiter::for_test(20, 3, AUTH_BACKOFF);
    let pool = pool_of(&f, &limiter, &gate, unpinned(), one_conn());
    let (services, settings) = services_of(&pool);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            let siblings = live_flows(&services, &settings, SIBLINGS).await;
            // The relay withholds its ServerHello past its own deadline.
            let index = relay.streams();
            relay.at(index, StreamFault::StallHandshake);
            let (_app, stalled) = tcp_flow(&services, &settings).await;
            assert!(stalled.await.unwrap().is_err());
            let reset = std::time::Instant::now();
            let waited = reset - client_request(&relay, &link, index);
            assert!(
                waited >= HS_WATCHDOG - Duration::from_millis(100)
                    && waited <= HS_WATCHDOG + Duration::from_millis(150),
                "{waited:?}"
            );
            // The relay saw the client's reset, not its own deadline: a
            // timeout on a live connection, no ledger entry (S16h-8b).
            assert!(relay
                .wait_step(index, StreamStep::HandshakeFailed, Duration::from_secs(4))
                .await
                .is_some());
            assert_eq!(limiter.strikes(), 0);
            close_all(siblings).await.unwrap();
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.strikes(), 0);
    assert_eq!(limiter.auth_failures(), 0);
    assert_eq!(limiter.flow_refusals(), 0);
}

#[test]
fn goaway_retry_unprocessed() {
    let (relay, _link, f) = linked();
    let gate = WorkGate::new();
    let limiter = EstablishLimiter::for_test(20, 3, AUTH_BACKOFF);
    let pool = pool_of(&f, &limiter, &gate, unpinned(), one_conn());
    let (services, settings) = services_of(&pool);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            // Streams 1 to 2 * SIBLINGS - 1 live (11 at `H_CONN` 4); then the
            // next two in their inner handshake.
            let mut processed = live_flows(&services, &settings, SIBLINGS).await;
            let next = relay.streams();
            relay.at(next, StreamFault::StallHandshake);
            relay.at(next + 1, StreamFault::StallHandshake);
            let unprocessed = vec![
                tcp_flow(&services, &settings).await,
                tcp_flow(&services, &settings).await,
            ];
            relay
                .wait_count(StreamStep::HandshakeStalled, 2, Duration::from_secs(5))
                .await
                .unwrap();
            let last = relay
                .events()
                .iter()
                .filter(|event| event.index < next)
                .map(|event| event.id)
                .max()
                .unwrap();
            assert_eq!(last, u32::try_from(2 * SIBLINGS - 1).unwrap());
            relay.goaway(0, h2::Reason::NO_ERROR, last);
            // Streams above the last ID are retried once, elsewhere.
            for (mut app, task) in unprocessed {
                app_echo(&mut app, b"retried").await.unwrap();
                close(app, task).await.unwrap();
            }
            // Those at or below it run to their end.
            for (app, _) in &mut processed {
                app_echo(app, b"processed").await.unwrap();
            }
            close_all(processed).await.unwrap();
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.conns(), 2);
    assert_eq!(relay.streams(), SIBLINGS + 2 + 2);
    assert_eq!(relay.count(StreamStep::GoneAway), 2);
    let retried = relay
        .events()
        .iter()
        .filter(|event| event.conn == 1 && event.step == StreamStep::Accepted)
        .count();
    assert_eq!(retried, 2);
    assert_eq!(pool.stats().goaways, 1);
    assert_eq!(limiter.auth_failures(), 0);
    assert!(!limiter.backing_off());
    assert_eq!(limiter.flow_refusals(), 0);
    assert_eq!(relay.strikes(), 0);
}

#[test]
fn carrier_refusal_on_pooled_stream_is_auth_class() {
    let (relay, _link, f) = linked();
    let gate = WorkGate::new();
    let limiter = limiter();
    let pool = pool_of(&f, &limiter, &gate, unpinned(), one_conn());
    let (services, settings) = services_of(&pool);
    relay.always(Some(StreamFault::RejectCarrier(403)));
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            let (_app, refused) = tcp_flow(&services, &settings).await;
            assert!(refused.await.unwrap().is_err());
            let refused_at = std::time::Instant::now();
            assert_eq!(limiter.auth_failures(), 1);
            assert!(limiter.backing_off() && limiter.probing());
            // An engine retrying at once: nothing reaches the relay during
            // the backoff, then a single probe.
            let retries = vec![
                tcp_flow(&services, &settings).await,
                tcp_flow(&services, &settings).await,
            ];
            tokio::time::sleep_until(
                (refused_at + AUTH_BACKOFF - Duration::from_millis(200)).into(),
            )
            .await;
            assert_eq!((relay.conns(), relay.streams()), (1, 1));
            assert!(wait_for(Duration::from_secs(3), || relay.streams() == 2).await);
            assert!(wait_for(Duration::from_secs(2), || limiter.auth_failures() == 2).await);
            tokio::time::sleep(Duration::from_millis(500)).await;
            assert_eq!(relay.streams(), 2);
            for (_app, task) in retries {
                task.abort();
            }
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.count(StreamStep::CarrierRejected), 2);
    assert_eq!(limiter.flow_refusals(), 0);
}

#[test]
fn no_client_data_after_server_end() {
    let (relay, _link, f) = linked();
    let gate = WorkGate::new();
    let limiter = EstablishLimiter::for_test(20, 3, AUTH_BACKOFF);
    let pool = pool_of(&f, &limiter, &gate, unpinned(), one_conn());
    let (services, settings) = services_of(&pool);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            let siblings = live_flows(&services, &settings, SIBLINGS).await;
            // A refused target: status 1, then the relay ends the stream.
            relay.next_streams(1, StreamFault::RefuseTarget);
            let (mut app, refused) = tcp_flow(&services, &settings).await;
            let _ = app.write_all(b"queued before the status").await;
            assert!(refused.await.unwrap().is_err());
            // A target that fails after one echo while the app still sends.
            relay.next_streams(1, StreamFault::TargetError);
            let (mut app, failed) = tcp_flow(&services, &settings).await;
            app_echo(&mut app, b"first").await.unwrap();
            let sending = tokio::spawn(async move {
                for _ in 0..30 {
                    if app.write_all(&[7; 1024]).await.is_err() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                app
            });
            let _ = failed.await.unwrap();
            let _app = sending.await.unwrap();
            assert_eq!(relay.count(StreamStep::TargetRefused), 1);
            assert_eq!(relay.count(StreamStep::TargetFailed), 1);
            // Let any late frame reach the relay; the connection lives on.
            tokio::time::sleep(Duration::from_millis(500)).await;
            close_all(siblings).await.unwrap();
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.stream_closed_resets(), 0);
    assert_eq!(relay.connection(0).closed(), None);
    assert_eq!(limiter.auth_failures(), 0);
    assert_eq!(limiter.flow_refusals(), 0);
}

#[test]
fn three_resets_before_200_are_one_unanswered_open() {
    let (relay, _link, f) = linked();
    let gate = WorkGate::new();
    let mut limiter = EstablishLimiter::for_test(20, 3, AUTH_BACKOFF);
    EstablishLimiter::tune(&mut limiter).set_flow_limits(
        Duration::from_millis(300),
        40,
        LIVE_FLOWS,
    );
    let pool = pool_of(&f, &limiter, &gate, unpinned(), one_conn());
    let (services, settings) = services_of(&pool);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            relay.always(Some(StreamFault::ResetBefore200(
                h2::Reason::INTERNAL_ERROR,
            )));
            let refused = || async {
                let (_app, task) = tcp_flow(&services, &settings).await;
                assert!(task.await.unwrap().is_err());
            };
            // Two resets are not authentication class and back nothing off.
            refused().await;
            refused().await;
            assert_eq!(limiter.flow_refusals(), 0);
            assert!(!limiter.flows_backing_off());
            // A 200 forgives them.
            relay.always(None);
            let (mut app, task) = tcp_flow(&services, &settings).await;
            app_echo(&mut app, b"answered").await.unwrap();
            close(app, task).await.unwrap();
            relay.always(Some(StreamFault::ResetBefore200(
                h2::Reason::INTERNAL_ERROR,
            )));
            refused().await;
            refused().await;
            assert_eq!(limiter.flow_refusals(), 0);
            // The third without a 200 between them is one unanswered Open.
            refused().await;
            assert_eq!(limiter.flow_refusals(), 1);
            assert!(limiter.flows_backing_off());
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.count(StreamStep::ResetBefore200), 5);
    assert_eq!(limiter.auth_failures(), 0);
}

#[test]
fn a_stale_relay_deadline_bounds_the_stream_that_freshens_its_connection() {
    let (relay, link, f) = linked();
    let gate = WorkGate::new();
    let limiter = EstablishLimiter::for_test(20, 3, AUTH_BACKOFF);
    let pool = pool_of(&f, &limiter, &gate, unpinned(), Limits::default());
    let (services, settings) = services_of(&pool);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            // The probe and a sibling sent as the probe returned, before the
            // relay authenticated it: its loop has not run since, so a
            // stream it accepts inherits the connection's stale idle
            // deadline (its TLS accept plus 5 s) although both are live.
            let pair = live_flows(&services, &settings, 2).await;
            assert_eq!(relay.conns(), 1);
            // Past idle reuse, within what the stale deadline still leaves
            // a handshake.
            tokio::time::sleep(Duration::from_millis(300)).await;
            let index = relay.streams();
            relay.at(index, StreamFault::HangTarget);
            let (_app, hung) = tcp_flow(&services, &settings).await;
            assert!(hung.await.unwrap().is_err());
            let gave_up = std::time::Instant::now();
            // It reused the live connection, bounded by the stale deadline
            // it inherited: a timeout well before the status budget and
            // before the relay's status-less reset at that deadline.
            let conn = relay
                .events()
                .iter()
                .find(|event| event.index == index)
                .map(|event| event.conn);
            assert_eq!(conn, Some(0));
            let waited = gave_up - client_request(&relay, &link, index);
            assert!(
                waited < STATUS_BUDGET - Duration::from_millis(500),
                "{waited:?}"
            );
            let hung_at = relay
                .wait_step(index, StreamStep::TargetHung, Duration::from_secs(3))
                .await
                .expect("the relay's deadline never fired");
            assert!(hung_at > gave_up);
            assert_eq!(limiter.flow_refusals(), 0);
            assert!(!limiter.flows_backing_off() && !limiter.flows_probing());
            // That stream went out more than one RTT after its siblings
            // authenticated: the relay's loop ran again at its accept, so
            // the connection is fresh and the next stream inherits a whole
            // deadline and the whole status budget.
            let index = relay.streams();
            relay.at(index, StreamFault::HangTarget);
            let (_app, hung) = tcp_flow(&services, &settings).await;
            assert!(hung.await.unwrap().is_err());
            let waited = std::time::Instant::now() - client_request(&relay, &link, index);
            assert!(
                waited >= STATUS_BUDGET - Duration::from_millis(100)
                    && waited <= STATUS_BUDGET + Duration::from_millis(100),
                "{waited:?}"
            );
            assert_eq!(relay.events()[relay.events().len() - 1].conn, 0);
            assert_eq!(relay.count(StreamStep::TargetHung), 1);
            close_all(pair).await.unwrap();
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.conns(), 1);
    assert_eq!(limiter.flow_refusals(), 0);
    assert_eq!(relay.strikes(), 0);
}

/// A carrier whose 200 the relay holds `delay` (a lost HEADERS segment
/// retransmitted after an RTO) on a fresh connection: the relay's deadline
/// was fixed at its accept, so this side's bounds run from the request.
fn slow_200(
    fault: StreamFault,
    delay: Duration,
) -> (PooledRelay, TestLink, Arc<EstablishLimiter>, Duration) {
    let (relay, link, f) = linked();
    let gate = WorkGate::new();
    let limiter = EstablishLimiter::for_test(20, 3, AUTH_BACKOFF);
    let pool = pool_of(&f, &limiter, &gate, unpinned(), one_conn());
    let (services, settings) = services_of(&pool);
    let waited = f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            let siblings = live_flows(&services, &settings, SIBLINGS).await;
            let index = relay.streams();
            relay.at(index, fault);
            relay.delay_200(index, delay);
            let (_app, slow) = tcp_flow(&services, &settings).await;
            assert!(slow.await.unwrap().is_err());
            let completed = std::time::Instant::now();
            assert_eq!(relay.events().last().map(|event| event.conn), Some(0));
            // Let the relay's own deadline pass, then the siblings end.
            tokio::time::sleep(Duration::from_millis(1_500)).await;
            close_all(siblings).await.unwrap();
            let accepted = relay
                .events()
                .into_iter()
                .find(|event| event.index == index && event.step == StreamStep::Accepted)
                .expect("the slow carrier was never accepted");
            // Both observations are on the relay side of the same link.
            // Measure the actual cancellation, not the later PONG verdict
            // that classifies a live path after its watchdog already fired.
            let reset = relay
                .connection(accepted.conn)
                .frames()
                .into_iter()
                .find(|frame| {
                    frame.from_client
                        && frame.kind == frame_type::RST_STREAM
                        && frame.stream == accepted.id
                })
                .expect("the expired carrier was never reset");
            let waited = reset.at.duration_since(accepted.at);
            if std::env::var_os("AEGIS_B06_TIMING_TRACE").is_some() {
                eprintln!(
                    "B06_TIMING slow200_reset={waited:?} terminal={:?}",
                    completed.duration_since(accepted.at)
                );
            }
            waited
        })
        .await
        .unwrap()
    });
    (relay, link, limiter, waited)
}

#[test]
fn a_late_200_never_moves_the_status_bound() {
    // The 200 arrives 1.5 s late: from it, the status budget would end
    // after the relay's status-less reset at its deadline.
    let (relay, _link, limiter, waited) =
        slow_200(StreamFault::HangTarget, Duration::from_millis(1_500));
    assert!(
        waited >= STATUS_BUDGET - Duration::from_millis(100)
            && waited <= STATUS_BUDGET + Duration::from_millis(100),
        "{waited:?}"
    );
    // The client gave up first: a timeout, no flow backoff or probing.
    assert_eq!(relay.count(StreamStep::TargetHung), 1);
    assert_eq!(limiter.flow_refusals(), 0);
    assert!(!limiter.flows_backing_off() && !limiter.flows_probing());
    assert_eq!(limiter.auth_failures(), 0);
    assert_eq!(relay.strikes(), 0);
}

#[test]
fn a_late_200_never_moves_the_handshake_watchdog() {
    // The 200 arrives 2.6 s late, its ServerHello never: from the 200, the
    // watchdog's reset would reach the relay after its deadline, a strike.
    let (relay, _link, limiter, waited) =
        slow_200(StreamFault::StallHandshake, Duration::from_millis(2_600));
    assert!(
        waited >= HS_WATCHDOG - Duration::from_millis(100)
            && waited <= HS_WATCHDOG + Duration::from_millis(150),
        "{waited:?}"
    );
    assert_eq!(relay.count(StreamStep::Struck), 0);
    assert_eq!(relay.strikes(), 0);
    assert_eq!(limiter.auth_failures(), 0);
    assert_eq!(limiter.flow_refusals(), 0);
}

#[test]
fn a_half_closed_flow_the_relay_ended_never_keeps_its_connection_live() {
    use crate::test_relay::pool::IDLE_END;
    let (relay, link, f) = linked();
    let gate = WorkGate::new();
    let limiter = EstablishLimiter::for_test(20, 3, AUTH_BACKOFF);
    let pool = pool_of(&f, &limiter, &gate, unpinned(), Limits::default());
    let (services, settings) = services_of(&pool);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            let (mut first, first_task) = tcp_flow(&services, &settings).await;
            app_echo(&mut first, b"probe").await.unwrap();
            // Its target sends FIN; the application keeps its half open and
            // silent, so the flow only polls the application from then on.
            let index = relay.streams();
            relay.at(index, StreamFault::FinThenIdleEnd);
            let (mut half, half_task) = tcp_flow(&services, &settings).await;
            let mut rest = Vec::new();
            half.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty());
            // A sibling sent well after both authenticated: the connection
            // is fresh while they are live.
            let (mut sibling, sibling_task) = tcp_flow(&services, &settings).await;
            app_echo(&mut sibling, b"sibling").await.unwrap();
            // The relay's idle timeout ends the half-closed channel, a reset
            // this side never reads; then the other two end.
            relay
                .wait_step(index, StreamStep::IdleEnded, IDLE_END * 4)
                .await
                .expect("the relay kept the half-closed channel");
            close(first, first_task).await.unwrap();
            close(sibling, sibling_task).await.unwrap();
            assert_eq!(relay.conns(), 1);
            // The relay has no live channel left on the connection: a stream
            // it accepts now inherits its idle deadline.
            tokio::time::sleep(IDLE_REUSE + Duration::from_millis(500)).await;
            let index = relay.streams();
            relay.at(index, StreamFault::HangTarget);
            let (_app, hung) = tcp_flow(&services, &settings).await;
            assert!(hung.await.unwrap().is_err());
            let gave_up = std::time::Instant::now();
            // Not on that connection, as if it were live: on a new one,
            // with its whole deadline, given up as a timeout first.
            let conn = relay
                .events()
                .iter()
                .find(|event| event.index == index)
                .map(|event| event.conn);
            assert_eq!(conn, Some(1));
            let waited = gave_up - client_request(&relay, &link, index);
            assert!(
                waited >= STATUS_BUDGET - Duration::from_millis(100)
                    && waited <= STATUS_BUDGET + Duration::from_millis(100),
                "{waited:?}"
            );
            assert_eq!(relay.count(StreamStep::TargetHung), 0);
            drop(half);
            half_task.abort();
        })
        .await
        .unwrap();
    });
    assert_eq!(limiter.flow_refusals(), 0);
    assert!(!limiter.flows_backing_off());
    assert_eq!(limiter.auth_failures(), 0);
    assert_eq!(relay.strikes(), 0);
}

/// What a burst at the design RTT left behind (`burst_at_design_rtt`).
#[derive(Debug)]
struct Burst {
    /// From the first flow's start to the last echo (or failed echo).
    last: Duration,
    /// Flows whose echo failed, and the first such failure.
    failed: (usize, Option<String>),
    /// The flows' connect budget.
    budget: Duration,
    /// Concurrent inner handshakes at the relay, at most.
    relay_handshakes: usize,
    /// Streams exposed in their inner handshake on one connection, at most.
    conn_handshakes: usize,
    /// TCP connections the relay accepted, and those through the link.
    conns: usize,
    link_conns: usize,
    /// Permits of the session limiter held at once, at most.
    permits: usize,
    opened: usize,
    strikes: usize,
    handshake_caps: usize,
    flow_refusals: u64,
    auth_failures: u64,
    stats: PoolStats,
}

/// `flows` live TCP echo flows through the held relay services, all started
/// at once, at the design RTT, with the session's own limiter and pool. The
/// TCP handshake each fresh connection pays on the real path before its
/// ClientHello (the link answers it at loopback speed) is the relay holding
/// its ServerHello until two RTTs after the connect.
fn burst_at_design_rtt(flows: usize) -> Burst {
    burst_with(flows, limiter(), Limits::default(), true)
}

/// `burst_at_design_rtt` under `limiter` and `limits`. A flow whose echo
/// fails fails a `strict` burst; otherwise it is counted (`Burst::failed`).
fn burst_with(flows: usize, limiter: Arc<EstablishLimiter>, limits: Limits, strict: bool) -> Burst {
    let (relay, link, f) = linked_with(PoolConfig {
        setup: DEFAULT_RTT * 3 / 2,
        ..PoolConfig::default()
    });
    assert_eq!(link.rtt(), DEFAULT_RTT);
    let gate = WorkGate::new();
    let pool = pool_of(&f, &limiter, &gate, unpinned(), limits);
    let (services, settings) = services_of(&pool);
    let budget = Duration::from_millis(settings.connect_timeout_ms);
    let (last, failed) = f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(60), async {
            // Every flow of the burst starts at once and stays live.
            let started = std::time::Instant::now();
            let mut opened = Vec::new();
            for _ in 0..flows {
                opened.push(tcp_flow(&services, &settings).await);
            }
            let mut echoes = tokio::task::JoinSet::new();
            for (tag, (mut app, task)) in opened.into_iter().enumerate() {
                let tag = u8::try_from(tag).unwrap();
                echoes.spawn(async move {
                    let echo = app_echo(&mut app, &[tag; 64]).await;
                    (started.elapsed(), echo, app, task)
                });
            }
            let mut echoed = Vec::new();
            let mut last = Duration::ZERO;
            let mut failed = (0, None);
            for (at, echo, app, task) in echoes.join_all().await {
                last = last.max(at);
                match echo {
                    Ok(()) => echoed.push((app, task)),
                    Err(error) if strict => {
                        panic!("a flow failed: {error:?} {:?}", pool.views())
                    }
                    Err(error) => {
                        failed.0 += 1;
                        failed
                            .1
                            .get_or_insert_with(|| format!("{error:?} {:?}", pool.views()));
                    }
                }
            }
            eprintln!(
                "burst of {flows} last echoed at {last:?} failed {} stats {:?}",
                failed.0,
                pool.stats()
            );
            close_all(echoed).await.unwrap();
            (last, failed)
        })
        .await
        .unwrap()
    });
    let events = relay.events();
    let conn_handshakes = (0..relay.conns())
        .map(|conn| handshake_high_water(&events, conn, link.rtt() / 4))
        .max()
        .unwrap_or(0);
    Burst {
        last,
        failed,
        budget,
        relay_handshakes: relay.handshakes().high_water(),
        conn_handshakes,
        conns: relay.conns(),
        link_conns: link.connections(),
        permits: limiter.high_water(),
        opened: relay.count(StreamStep::Opened),
        strikes: relay.strikes(),
        handshake_caps: relay.handshake_caps(),
        flow_refusals: limiter.flow_refusals(),
        auth_failures: limiter.auth_failures(),
        stats: pool.stats(),
    }
}

/// The bounds every burst at the design RTT keeps, written out so that a
/// changed constant fails here: at most 22 concurrent inner handshakes at
/// the relay (16 flow permits, S16k's 4 for the ACK path the pool never
/// sees, and a skew of 2, under its 32 per peer IP less that skew), 4 per
/// connection, the pool's 4 connections, and at most the 16 permits flows
/// may take of the limiter's 20; no strike, no capacity refusal, no
/// backoff.
fn assert_burst_bounds(burst: &Burst, flows: usize) {
    assert_eq!(burst.opened, flows, "{burst:?}");
    assert!(burst.relay_handshakes <= 22, "{burst:?}");
    assert!(burst.relay_handshakes <= 32 - 2, "{burst:?}");
    assert!(burst.conn_handshakes <= 4, "{burst:?}");
    assert!(burst.stats.max_establishing <= 4, "{burst:?}");
    assert!(burst.conns <= 4, "{burst:?}");
    assert_eq!(burst.link_conns, burst.conns, "{burst:?}");
    assert!(burst.stats.max_conns <= 4, "{burst:?}");
    assert!(burst.permits <= 16, "{burst:?}");
    assert!(burst.permits <= 20, "{burst:?}");
    assert_eq!(burst.strikes, 0, "{burst:?}");
    assert_eq!(burst.handshake_caps, 0, "{burst:?}");
    assert_eq!(burst.flow_refusals, 0, "{burst:?}");
    assert_eq!(burst.auth_failures, 0, "{burst:?}");
}

/// The design's burst timing at 170 ms, as this loopback relay measures it:
/// about 0.45 s of dial (TCP setup, outer TLS, H2) before the first stream,
/// then one cycle of about 2.15 RTT (365 ms) per batch of streams (the 200,
/// the inner mTLS, the next stream's carrier right behind the Finished),
/// the batches at `H_CONN` 2 were 2 (each fresh connection probes alone),
/// 6, then 8 (every flow permit), and about 1.5 RTT after the last Open for
/// its status and the echo. The S16h plan's model (2 RTT per cycle, 23.5
/// flows/s from the first stream) gave 1.7 s and 4.8 s; measured at
/// `H_CONN` 2, the 24-flow burst took 4 cycles (2.14 s) and the 90-flow
/// burst 13 (5.1-5.5 s). At `H_CONN` 4 (S16j-4: batches of up to 16, every
/// flow permit) they take 1.75 s and 3.17-3.18 s alone. The timing tests
/// bound each burst by the installed v20 window's acceptance (2.5 s, 6 s),
/// which also fails at 3 flow permits. Each cycle's excess over 2 RTT is the
/// debug build's inner mTLS on this one-threaded relay and the client's two
/// workers, so the bounds hold only on an otherwise idle Mac: they are
/// ignored by default and run alone under the timing lock (README).
const BURST_24_BOUND: Duration = Duration::from_millis(2_500);
const BURST_90_BOUND: Duration = Duration::from_millis(6_000);

/// S16h-7: the 24-flow burst opens every flow within its connect budget,
/// using every flow permit on the pool's 4 connections (at S16g's 3 flow
/// permits it took 3.94 s; its wall-clock bound is `burst_24_timing`).
#[test]
fn burst_24() {
    const FLOWS: usize = 24;
    let burst = burst_at_design_rtt(FLOWS);
    assert_burst_bounds(&burst, FLOWS);
    assert_eq!(burst.permits, 16, "{burst:?}");
    assert!(burst.last < burst.budget, "{burst:?}");
}

/// S16h-7, timing: the 24-flow burst completes within 2.5 s of its first
/// flow (`BURST_24_BOUND`; measured 2.13-2.14 s at 8 flow permits, 1.75 s
/// at 16).
#[test]
#[ignore = "timing: run alone under the timing-self lock with --ignored --test-threads=1"]
fn burst_24_timing() {
    const FLOWS: usize = 24;
    let burst = burst_at_design_rtt(FLOWS);
    assert_burst_bounds(&burst, FLOWS);
    assert!(burst.last < BURST_24_BOUND, "{burst:?}");
}

/// S16h-7, timing: the 90-flow burst v19 starved (4 of 24 flows, a queue of
/// 89) completes within 6 s of its first flow (`BURST_90_BOUND`; measured
/// 5.3-5.5 s at 8 flow permits, 3.18 s at 16): no flow runs out of its connect budget,
/// although the whole burst outlasts it. Its last carrier 200 arrives only
/// tens of milliseconds inside that budget, so a loaded Mac refuses the
/// last flows with no regression: it never runs in the parallel suite.
#[test]
#[ignore = "timing: run alone under the timing-self lock with --ignored --test-threads=1"]
fn flow_pool_burst_90_at_170ms() {
    const FLOWS: usize = 90;
    let burst = burst_at_design_rtt(FLOWS);
    assert_burst_bounds(&burst, FLOWS);
    assert_eq!(burst.permits, 16, "{burst:?}");
    assert!(burst.last < BURST_90_BOUND, "{burst:?}");
}

/// S16j-4: the geometry before it, for comparison: `H_CONN` 2 under 12
/// permits (8 for flows, the pool's 4 connections of 2 handshakes, and
/// S16k's ACK reserve of 4) and 24 Opens, against the same relay.
fn two_handshakes_per_connection() -> (Arc<EstablishLimiter>, Limits) {
    let mut limiter = EstablishLimiter::for_test(4 * 2 + ACK_RESERVE, ACK_RESERVE, AUTH_BACKOFF);
    EstablishLimiter::tune(&mut limiter).set_flow_limits(FLOW_BACKOFF, 8 + 16, LIVE_FLOWS);
    let limits = Limits {
        h_conn: 2,
        ..Limits::default()
    };
    (limiter, limits)
}

/// S16j-4: the 90-flow burst at 170 ms RTT against the deployed relay's
/// 32 handshakes per peer completes faster at `H_CONN` 4 (16 flow permits)
/// than at 2 (8), run back to back in this one test, as a relative bound:
/// at most 85 % of the time (measured alone: 3.17 s against 5.09 s, 62 %).
/// The faster burst
/// keeps every bound: at most 30 handshakes at the relay (its 32 less the
/// skew), at most 4 per connection, every flow opened, no strike. The
/// slower one may lose its last flows to their connect budget on a loaded
/// Mac (the reason `flow_pool_burst_90_at_170ms` is ignored); its time then
/// runs to those flows' refusals, so the comparison still holds.
#[test]
fn burst_90_at_170ms_is_faster_at_four_handshakes_per_connection() {
    const FLOWS: usize = 90;
    let (limiter, limits) = two_handshakes_per_connection();
    let before = burst_with(FLOWS, limiter, limits, false);
    assert!(before.conn_handshakes <= 2, "{before:?}");
    assert!(before.stats.max_establishing <= 2, "{before:?}");
    assert!(before.permits <= 8, "{before:?}");
    let after = burst_at_design_rtt(FLOWS);
    assert_burst_bounds(&after, FLOWS);
    assert_eq!(after.permits, 16, "{after:?}");
    // Four handshakes per connection were used, never more.
    assert_eq!(after.stats.max_establishing, H_CONN, "{after:?}");
    assert!(after.conn_handshakes <= H_CONN, "{after:?}");
    assert!(after.relay_handshakes <= 32 - 2, "{after:?}");
    assert_eq!(after.strikes, 0, "{after:?}");
    assert!(
        after.last.as_millis() * 100 <= before.last.as_millis() * 85,
        "H_CONN 4 {:?} vs 2 {:?}\n{after:?}\n{before:?}",
        after.last,
        before.last
    );
}

/// S16h-7: 150 flows at the design RTT against a relay that refuses the
/// 33rd concurrent inner handshake of a peer (aegis-core's per-peer cap at
/// relay-a's 32, `HandshakeCapped`) and the 33rd stream of a connection (its H2
/// MAX_CONCURRENT_STREAMS, a REFUSED_STREAM): the session's own limiter and
/// pool never meet either. The 120th flow and later find the live cap,
/// before any stream; every other flow is live at once.
#[test]
fn server_limits_never_exceeded() {
    const FLOWS: usize = 150;
    // The relay is at aegis-server's defaults (128 sessions per peer, 32
    // streams per connection), whose live cap is 119: the production
    // limiter (its permits, Open cap and flow backoff) is tuned to that cap
    // instead of this build's 248 (`LIVE_FLOWS`, derived from relay-a's
    // 1024 sessions), as a session bound to such a relay would need.
    const LIVE: usize = DEFAULT_RELAY_LIVE;
    let (relay, link, f) = linked();
    let gate = WorkGate::new();
    let mut limiter = limiter();
    EstablishLimiter::tune(&mut limiter).set_flow_limits(FLOW_BACKOFF, FLOW_OPENS, LIVE);
    EstablishLimiter::tune(&mut limiter).set_relay_sessions(DEFAULT_RELAY_SESSIONS);
    let pool = pool_of(&f, &limiter, &gate, unpinned(), Limits::default());
    let opened = Arc::new(AtomicUsize::new(0));
    let (release, released) = watch::channel(false);
    let outcomes = f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(90), async {
            let mut flows = tokio::task::JoinSet::new();
            for _ in 0..FLOWS {
                let live = limiter.live_flow();
                let (pool, crypto, limiter) = (pool.clone(), f.crypto.clone(), limiter.clone());
                let (opened, mut released) = (opened.clone(), released.clone());
                flows.spawn(async move {
                    let Some(live) = live else {
                        return Outcome::LiveCap;
                    };
                    match flow(&pool, &crypto, &limiter, live).await {
                        Ok(mut flow) => {
                            echo(&mut flow.inner, b"held").await;
                            opened.fetch_add(1, Ordering::SeqCst);
                            released.wait_for(|go| *go).await.unwrap();
                            let conn = flow.slot.conn_id();
                            end(flow).await;
                            Outcome::Done(conn)
                        }
                        Err(error) => Outcome::Failed(format!("{error:#}")),
                    }
                });
            }
            while opened.load(Ordering::SeqCst) < LIVE {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            release.send(true).unwrap();
            let mut outcomes = Vec::new();
            while let Some(outcome) = flows.join_next().await {
                outcomes.push(outcome.unwrap());
            }
            outcomes
        })
        .await
        .unwrap()
    });
    let failed: Vec<_> = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, Outcome::Failed(_)))
        .collect();
    assert!(failed.is_empty(), "{failed:?}");
    let capped = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, Outcome::LiveCap))
        .count();
    assert_eq!(capped, FLOWS - LIVE);
    assert_eq!(relay.streams(), LIVE);
    assert_eq!(relay.count(StreamStep::Opened), LIVE);
    // No capacity refusal: neither the per-peer handshake cap nor the
    // per-peer session cap (both `HandshakeCapped`) was ever met...
    assert_eq!(relay.handshake_caps(), 0);
    assert_eq!(relay.count(StreamStep::HandshakeCapped), 0);
    // ...at most the 16 flow permits, the 4 the ACK path keeps and a skew
    // of 2, well under the relay's 32 less that skew...
    assert_eq!(
        PoolConfig::default()
            .inner_admission
            .max_handshakes_per_peer,
        32
    );
    assert!(
        relay.handshakes().high_water() <= 22,
        "{}",
        relay.handshakes().high_water()
    );
    // ...nor any connection's stream cap: no REFUSED_STREAM.
    let refused = u32::from(h2::Reason::REFUSED_STREAM);
    for conn in 0..relay.conns() {
        let stats = relay.connection(conn);
        assert!(stats.max_concurrent_streams() <= 30, "conn {conn}");
        assert!(
            stats
                .resets(false)
                .iter()
                .all(|(_, reason)| *reason != refused),
            "conn {conn}"
        );
    }
    assert!(relay.conns() <= 4);
    assert_eq!(link.connections(), relay.conns());
    assert!(limiter.high_water() <= 16);
    assert_eq!(relay.strikes(), 0);
    assert_eq!(limiter.auth_failures(), 0);
    assert_eq!(limiter.flow_refusals(), 0);
}

/// S16i-2 against the deployed relay-a geometry (since 2026-10-22 07:21
/// UTC, handoff `capacity`): H2 MAX_CONCURRENT_STREAMS 128, reset guards
/// 50 and 1024 and a 4 MiB connection window, and an inner server holding
/// 1024 sessions per peer (4096 in all) beside 32 handshakes per peer (128
/// in all; S16j-4, with R2). At aegis-server's reset guards (8) the relay's own stream ends
/// can break a connection whose 62 flows end at once (h2 GOAWAY
/// ENHANCE_YOUR_CALM, seen under a loaded parallel suite): the deployed
/// relay raised them, so this test takes them too. The production limiter's live cap is then the pool's bound,
/// 248 (`LIVE_FLOWS`). 260 flows queue for a live place first come first
/// served: the first 248 are live at once on at most 4 connections of at
/// most 62 streams; the 12 later ones wait at the live cap and are refused
/// there only at their deadline, before any stream. The relay never meets
/// a capacity limit and never strikes.
#[test]
fn deployed_relay_geometry_holds_every_live_flow() {
    const EXTRA: usize = 12;
    const FLOWS: usize = LIVE_FLOWS + EXTRA;
    // Written out so that a changed pool or limiter constant fails here.
    const CONNS: usize = 4;
    const STREAMS: usize = 62;
    const HANDSHAKES_PER_PEER: usize = 32;
    const SESSIONS_PER_PEER: usize = 1024;
    // The client's share of a peer's handshakes: the relay's 32 less a skew
    // of 2 between a permit's return and the relay's.
    const HANDSHAKE_ROOM: usize = HANDSHAKES_PER_PEER - 2;
    // The later flows' wait for a live place.
    const WAIT: Duration = Duration::from_secs(5);
    // Flows ending at once. Each end sends the relay small DATA frames (the
    // TLS close_notify and the END_STREAM), and h2 0.4.16 (the vendored h2
    // of client and relay) ends a connection with GOAWAY ENHANCE_YOUR_CALM
    // once about 100 small DATA frames wait unread on it
    // (`DEFAULT_DATA_FRAME_BUDGET`): 62 flows released at once on one
    // connection broke it whenever this one-threaded debug relay lagged (a
    // loaded parallel suite; the deployed reset guards did not help, and no
    // other ENHANCE_YOUR_CALM path applies). That burst is not what this
    // test bounds.
    const ENDING: usize = 16;
    #[derive(Debug)]
    enum Deployed {
        Refused(usize, std::time::Instant),
        Done(usize, u64),
        Failed(usize, String),
    }
    assert_eq!(LIVE_FLOWS, 248);
    assert_eq!(LIVE_FLOWS, CONNS * STREAMS);
    let (relay, link, f) = linked_with(PoolConfig {
        max_concurrent_streams: Some(128),
        inner_admission: secure_channel::AdmissionLimits {
            max_handshakes: 128,
            max_sessions: 4096,
            max_handshakes_per_peer: HANDSHAKES_PER_PEER,
            max_sessions_per_peer: SESSIONS_PER_PEER,
        },
        h2_reset_streams: 50,
        h2_local_error_resets: Some(1024),
        h2_connection_window: 4 * 1024 * 1024,
        ..PoolConfig::default()
    });
    let gate = WorkGate::new();
    let limiter = limiter();
    assert_eq!(limiter.live_cap(), LIVE_FLOWS);
    let pool = pool_of(&f, &limiter, &gate, unpinned(), Limits::default());
    let opened = Arc::new(AtomicUsize::new(0));
    // Flows that failed before they were live, to fail fast.
    let failures = Arc::new(AtomicUsize::new(0));
    let (release, released) = watch::channel(false);
    let ending = Arc::new(tokio::sync::Semaphore::new(ENDING));
    // The limiter's own clock (std, unlike this suite's tokio `Instant`).
    let deadline = std::time::Instant::now() + WAIT;
    let outcomes = f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(120), async {
            let mut flows = tokio::task::JoinSet::new();
            for index in 0..FLOWS {
                // Queued in order: the 249th and later wait at the cap.
                let mut ticket = limiter.live_ticket();
                let (pool, crypto, limiter) = (pool.clone(), f.crypto.clone(), limiter.clone());
                let (opened, mut released) = (opened.clone(), released.clone());
                let (ending, failures) = (ending.clone(), failures.clone());
                flows.spawn(async move {
                    let live = loop {
                        if limiter.live_ready(&ticket, deadline).await.is_err() {
                            return Deployed::Refused(index, std::time::Instant::now());
                        }
                        if let Some(live) = limiter.take_live(&mut ticket) {
                            break live;
                        }
                    };
                    match flow(&pool, &crypto, &limiter, live).await {
                        Ok(mut flow) => {
                            echo(&mut flow.inner, b"held").await;
                            opened.fetch_add(1, Ordering::SeqCst);
                            released.wait_for(|go| *go).await.unwrap();
                            let conn = flow.slot.conn_id();
                            // Ended a few at a time (`ENDING`).
                            let _ending = ending.acquire().await.unwrap();
                            end(flow).await;
                            Deployed::Done(index, conn)
                        }
                        Err(error) => {
                            failures.fetch_add(1, Ordering::SeqCst);
                            Deployed::Failed(index, format!("{error:#}"))
                        }
                    }
                });
            }
            // Every place is taken at once; the later flows wait, unrefused.
            while limiter.live() < LIVE_FLOWS || limiter.live_waiting() > EXTRA {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(limiter.live_waiting(), EXTRA);
            assert_eq!(limiter.live_refusals(), 0);
            assert!(
                std::time::Instant::now() < deadline,
                "the queue formed too late"
            );
            // Held until every flow is live and every later one refused.
            while opened.load(Ordering::SeqCst) < LIVE_FLOWS
                || limiter.live_refusals() < EXTRA as u64
            {
                assert_eq!(failures.load(Ordering::SeqCst), 0, "a flow failed");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            // Every admitted flow is live at once, within the pool's bounds.
            let views = pool.views();
            assert!(views.len() <= CONNS, "{views:?}");
            assert!(
                views.iter().all(|view| view.streams <= STREAMS),
                "{views:?}"
            );
            assert_eq!(
                views.iter().map(|view| view.streams).sum::<usize>(),
                LIVE_FLOWS
            );
            assert_eq!(limiter.live(), LIVE_FLOWS);
            assert_eq!(limiter.live_waiting(), 0);
            assert_eq!(relay.sessions().current(), LIVE_FLOWS);
            release.send(true).unwrap();
            let mut outcomes = Vec::new();
            while let Some(outcome) = flows.join_next().await {
                outcomes.push(outcome.unwrap());
            }
            outcomes
        })
        .await
        .unwrap()
    });
    let failed: Vec<_> = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, Deployed::Failed(..)))
        .collect();
    assert!(failed.is_empty(), "{failed:?}");
    let mut refused: Vec<_> = outcomes
        .iter()
        .filter_map(|outcome| match outcome {
            Deployed::Refused(index, at) => Some((*index, *at)),
            _ => None,
        })
        .collect();
    refused.sort_unstable_by_key(|(index, _)| *index);
    // The later flows, in their queue order, each only at its deadline.
    assert_eq!(
        refused.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
        (LIVE_FLOWS..FLOWS).collect::<Vec<_>>()
    );
    assert!(refused.iter().all(|(_, at)| *at >= deadline), "{refused:?}");
    let done = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, Deployed::Done(index, _) if *index < LIVE_FLOWS))
        .count();
    assert_eq!(done, LIVE_FLOWS);
    assert_eq!(limiter.live_refusals(), EXTRA as u64);
    assert_eq!(limiter.live_high_water(), LIVE_FLOWS);
    // The refused flows never reached the relay.
    assert_eq!(relay.streams(), LIVE_FLOWS);
    assert_eq!(relay.count(StreamStep::Opened), LIVE_FLOWS);
    // The relay held every live flow's session at once, and no more...
    assert_eq!(relay.sessions().high_water(), LIVE_FLOWS);
    // ...and met none of its capacity limits: no `HandshakeCapped` (the
    // per-peer handshake or session cap), no REFUSED_STREAM.
    assert_eq!(relay.handshake_caps(), 0);
    assert_eq!(relay.session_caps(), 0);
    assert_eq!(relay.count(StreamStep::HandshakeCapped), 0);
    assert!(
        relay.handshakes().high_water() <= HANDSHAKE_ROOM,
        "{}",
        relay.handshakes().high_water()
    );
    let refused_stream = u32::from(h2::Reason::REFUSED_STREAM);
    for conn in 0..relay.conns() {
        let stats = relay.connection(conn);
        assert!(stats.max_concurrent_streams() <= STREAMS, "conn {conn}");
        assert!(
            stats
                .resets(false)
                .iter()
                .all(|(_, reason)| *reason != refused_stream),
            "conn {conn}"
        );
    }
    let stats = pool.stats();
    assert!(stats.max_conns <= CONNS, "{stats:?}");
    assert!(stats.max_streams <= STREAMS, "{stats:?}");
    assert!(relay.conns() <= CONNS);
    assert_eq!(link.connections(), relay.conns());
    assert!(limiter.high_water() <= 16);
    // Per connection at most `H_CONN` (4) handshakes at once.
    assert!(stats.max_establishing <= 4, "{stats:?}");
    assert_eq!(relay.strikes(), 0);
    assert_eq!(limiter.auth_failures(), 0);
    assert_eq!(limiter.flow_refusals(), 0);
}

#[test]
fn a_tls_alert_stays_auth_class_when_its_connection_then_ends() {
    let (relay, _link, f) = linked();
    let gate = WorkGate::new();
    let limiter = limiter();
    let pool = pool_of(&f, &limiter, &gate, unpinned(), one_conn());
    let (services, settings) = services_of(&pool);
    relay.always(Some(StreamFault::AlertInner));
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            let (_app, refused) = tcp_flow(&services, &settings).await;
            // The relay refuses the device with an alert and then the
            // connection dies, within CONN_END_GRACE of the alert.
            relay
                .wait_count(StreamStep::Alerted, 1, Duration::from_secs(5))
                .await
                .unwrap();
            relay.drop_tcp(0);
            assert!(refused.await.unwrap().is_err());
        })
        .await
        .unwrap();
    });
    // A delivered refusal of the device, never a connection loss.
    assert_eq!(limiter.auth_failures(), 1);
    assert!(limiter.backing_off());
    assert_eq!(relay.streams(), 1);
}

#[test]
fn status_budget_shrinks_with_idle_age() {
    const IDLE: Duration = Duration::from_millis(900);
    let (relay, link, f) = linked();
    let gate = WorkGate::new();
    let limiter = EstablishLimiter::for_test(20, 3, AUTH_BACKOFF);
    let pool = pool_of(&f, &limiter, &gate, unpinned(), one_conn());
    let (services, settings) = services_of(&pool);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            let (mut app, task) = tcp_flow(&services, &settings).await;
            app_echo(&mut app, b"first").await.unwrap();
            close(app, task).await.unwrap();
            // Within reuse, but the relay's idle deadline the next stream
            // inherits already runs from the first one's end.
            tokio::time::sleep(IDLE).await;
            let index = relay.streams();
            relay.at(index, StreamFault::HangTarget);
            let (_app, hung) = tcp_flow(&services, &settings).await;
            assert!(hung.await.unwrap().is_err());
            let waited = std::time::Instant::now() - client_request(&relay, &link, index);
            let budget = status_budget(IDLE);
            assert!(budget < STATUS_BUDGET);
            assert!(
                waited >= budget - Duration::from_millis(100)
                    && waited <= budget + Duration::from_millis(150),
                "{waited:?}"
            );
        })
        .await
        .unwrap();
    });
    // Reused, and given up before the relay's status-less reset.
    assert_eq!(relay.conns(), 1);
    assert_eq!(limiter.flow_refusals(), 0);
    assert_eq!(relay.strikes(), 0);
}

// ---- S16h-8a: the stall watchdog and the capacity refusal after the 200,
// ---- at 170 ms RTT ----

/// When the relay sent stream `index`'s 200.
fn responded(relay: &PooledRelay, index: usize) -> std::time::Instant {
    relay
        .events()
        .iter()
        .find(|event| event.index == index && event.step == StreamStep::Responded)
        .map(|event| event.at)
        .expect("never answered 200")
}

/// Client PING frames (not ACKs) the relay read on any connection.
fn client_pings(relay: &PooledRelay) -> usize {
    (0..relay.conns())
        .map(|conn| {
            relay
                .connection(conn)
                .frames()
                .iter()
                .filter(|f| f.from_client && f.kind == frame_type::PING && !f.is_ack())
                .count()
        })
        .sum()
}

#[test]
fn pong_wait_is_its_floor_or_three_round_trips() {
    assert_eq!(pong_wait(Duration::ZERO), PONG_FLOOR);
    assert_eq!(pong_wait(DEFAULT_RTT), PONG_FLOOR);
    assert_eq!(
        pong_wait(Duration::from_millis(500)),
        Duration::from_millis(1_500)
    );
    // Found stalled before a status-awaiting stream gives up on its own.
    assert!(STALL_QUIET + PONG_FLOOR < STATUS_BUDGET);
}

#[test]
fn stall_watchdog_closes_a_frozen_connection() {
    let (relay, link, f) = linked();
    let gate = WorkGate::new();
    let limiter = EstablishLimiter::for_test(20, 3, AUTH_BACKOFF);
    let pool = pool_of(&f, &limiter, &gate, unpinned(), one_conn());
    let (services, settings) = services_of(&pool);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            let siblings = live_flows(&services, &settings, SIBLINGS).await;
            let conn = pool.conn_for_test(0).unwrap();
            // Two flows in their inner handshake on the one connection.
            let next = relay.streams();
            relay.at(next, StreamFault::StallHandshake);
            relay.at(next + 1, StreamFault::StallHandshake);
            let establishing = vec![
                tcp_flow(&services, &settings).await,
                tcp_flow(&services, &settings).await,
            ];
            let stalled = relay
                .wait_count(StreamStep::HandshakeStalled, 2, Duration::from_secs(5))
                .await
                .unwrap();
            let views = pool.views();
            assert_eq!((views.len(), views[0].establishing), (1, 2), "{views:?}");
            // Then the path freezes the connection: no byte either way, no
            // TCP ACK, no FIN, no GOAWAY.
            relay.freeze(0);
            conn.freeze_acks_for_test();
            assert_eq!(conn.pings(), 0);
            assert!(wait_for(Duration::from_secs(5), || conn.ended().is_some()).await);
            let closed = std::time::Instant::now();
            assert_eq!(conn.ended(), Some(ConnEnd::LocalClose));
            assert_eq!(conn.pings(), 1);
            // Its last inbound byte came between the later 200 and half an
            // RTT after the relay read the second ClientHello: one PING
            // after STALL_QUIET, then PONG_FLOOR (3 RTTs are less).
            let earliest =
                responded(&relay, next).max(responded(&relay, next + 1)) + link.rtt() / 2;
            let latest = stalled + link.rtt() / 2;
            assert!(
                closed - earliest >= STALL_QUIET + PONG_FLOOR - Duration::from_millis(50),
                "{:?}",
                closed - earliest
            );
            assert!(
                closed - latest <= STALL_QUIET + PONG_FLOOR + Duration::from_millis(300),
                "{:?}",
                closed - latest
            );
            // Its live flows end with it. The establishing ones outlived
            // their handshake watchdog (the close comes after it) and were
            // judged at the stall verdict: a connection loss, retried once
            // on a fresh connection, never a timeout.
            assert!(closed - client_request(&relay, &link, next) > HS_WATCHDOG);
            for (_app, task) in siblings {
                assert!(task.await.unwrap().is_err());
            }
            for (mut app, task) in establishing {
                app_echo(&mut app, b"retried").await.unwrap();
                close(app, task).await.unwrap();
            }
            // The next flow goes on a fresh connection.
            let (mut app, task) = tcp_flow(&services, &settings).await;
            app_echo(&mut app, b"fresh").await.unwrap();
            assert!(!pool.views().iter().any(|view| view.id == 0));
            close(app, task).await.unwrap();
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.conns(), 2);
    // A transport loss: neither class backs anything off. Both establishing
    // streams were past their 200: two ledger entries (S16h-8b).
    assert_eq!(limiter.strikes(), 2);
    assert_eq!(limiter.auth_failures(), 0);
    assert_eq!(limiter.flow_refusals(), 0);
    assert!(!limiter.flows_backing_off());
    assert!(!limiter.backing_off());
}

#[test]
fn stall_watchdog_makes_awaited_opens_a_connection_loss() {
    let (relay, link, f) = linked();
    let gate = WorkGate::new();
    let limiter = EstablishLimiter::for_test(20, 3, AUTH_BACKOFF);
    let pool = pool_of(&f, &limiter, &gate, unpinned(), one_conn());
    let (services, settings) = services_of(&pool);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            let siblings = live_flows(&services, &settings, SIBLINGS).await;
            // Two Opens written and awaiting their status.
            let next = relay.streams();
            relay.at(next, StreamFault::HangTarget);
            relay.at(next + 1, StreamFault::HangTarget);
            let awaiting = vec![
                tcp_flow(&services, &settings).await,
                tcp_flow(&services, &settings).await,
            ];
            assert!(wait_for(Duration::from_secs(5), || limiter.unverified() == 2).await);
            // Frozen once the relay read both Finished messages: past the
            // window in which its deadline could strike (S16h-8b).
            for index in [next, next + 1] {
                assert!(relay
                    .wait_step(index, StreamStep::Authenticated, Duration::from_secs(2))
                    .await
                    .is_some());
            }
            relay.freeze(0);
            pool.conn_for_test(0).unwrap().freeze_acks_for_test();
            for (_app, task) in awaiting {
                assert!(task.await.unwrap().is_err());
            }
            // Both end with their connection, after one PING and PONG_FLOOR
            // and before their own STATUS_BUDGET: a connection loss, not a
            // timeout and not an unanswered Open.
            let asked = client_request(&relay, &link, next);
            let waited = std::time::Instant::now() - asked;
            assert!(waited >= STALL_QUIET + PONG_FLOOR, "{waited:?}");
            assert!(
                waited <= STALL_QUIET + PONG_FLOOR + link.rtt() * 2 + Duration::from_millis(300),
                "{waited:?}"
            );
            assert!(waited < STATUS_BUDGET, "{waited:?}");
            // Past their exposed window (the relay's TCP acknowledged their
            // Opens): no ledger entry (S16h-8b).
            assert_eq!(limiter.strikes(), 0);
            assert_eq!(limiter.unverified(), 0);
            assert_eq!(limiter.flow_refusals(), 0);
            assert!(!limiter.flows_backing_off() && !limiter.flows_probing());
            for (_app, task) in siblings {
                assert!(task.await.unwrap().is_err());
            }
            // The next flow starts at once, on a fresh connection.
            let started = std::time::Instant::now();
            let (mut app, task) = tcp_flow(&services, &settings).await;
            app_echo(&mut app, b"fresh").await.unwrap();
            assert!(started.elapsed() < Duration::from_millis(1_500));
            close(app, task).await.unwrap();
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.conns(), 2);
    // Neither did the relay count one.
    assert_eq!(relay.strikes(), 0);
    assert_eq!(limiter.auth_failures(), 0);
    assert_eq!(limiter.flow_refusals(), 0);
}

#[test]
fn refuse_after_200_gives_h_conn_1() {
    let (relay, link, f) = linked();
    let gate = WorkGate::new();
    let limiter = EstablishLimiter::for_test(20, 3, AUTH_BACKOFF);
    let pool = pool_of(&f, &limiter, &gate, unpinned(), Limits::default());
    let (services, settings) = services_of(&pool);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            let siblings = live_flows(&services, &settings, 1).await;
            assert_eq!(pool.views()[0].h_conn, H_CONN);
            // The relay's handshake cap is full: the 200, then the stream
            // ends before the handshake (aegis-server secure.rs:44-48, :131).
            relay.next_streams(1, StreamFault::RefuseAfter200);
            let (_app, refused) = tcp_flow(&services, &settings).await;
            assert!(refused.await.unwrap().is_err());
            let refused_at = std::time::Instant::now();
            assert_eq!(relay.count(StreamStep::RefusedAfter200), 1);
            let views = pool.views();
            assert_eq!((views.len(), views[0].h_conn), (1, 1), "{views:?}");
            // The relay ended the stream itself: no ledger entry.
            assert_eq!(limiter.strikes(), 0);
            // Neither class: nothing backs off.
            assert_eq!(limiter.auth_failures(), 0);
            assert_eq!(limiter.flow_refusals(), 0);
            assert!(!limiter.flows_backing_off() && !limiter.backing_off());
            // Two flows that stall in their handshake. While the connection
            // is narrowed one runs and the other waits: no dial replaces the
            // withheld slot, since the relay's cap is per client IP.
            let dials = pool.stats().dials;
            let next = relay.streams();
            relay.at(next, StreamFault::StallHandshake);
            relay.at(next + 1, StreamFault::StallHandshake);
            let stalled = vec![
                tcp_flow(&services, &settings).await,
                tcp_flow(&services, &settings).await,
            ];
            relay
                .wait_count(StreamStep::HandshakeStalled, 1, Duration::from_secs(5))
                .await
                .unwrap();
            let narrowed_until = refused_at + FLOW_BACKOFF;
            while std::time::Instant::now() + Duration::from_millis(100) < narrowed_until {
                let views = pool.views();
                assert_eq!(views.len(), 1, "{views:?}");
                assert_eq!((views[0].establishing, views[0].h_conn), (1, 1));
                assert_eq!(pool.queue(), (1, 0));
                assert_eq!(relay.count(StreamStep::HandshakeStalled), 1);
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            assert_eq!(pool.stats().dials, dials);
            assert_eq!(relay.conns(), 1);
            // After FLOW_BACKOFF the connection takes `H_CONN` again:
            // the waiting flow's runs there too.
            let second = relay
                .wait_count(StreamStep::HandshakeStalled, 2, Duration::from_secs(5))
                .await
                .unwrap();
            assert!(second >= narrowed_until, "{:?}", narrowed_until - second);
            let views = pool.views();
            assert_eq!(views.len(), 1, "{views:?}");
            assert_eq!(views[0].h_conn, H_CONN);
            let conns: Vec<usize> = relay
                .events()
                .iter()
                .filter(|event| event.step == StreamStep::HandshakeStalled)
                .map(|event| event.conn)
                .collect();
            assert_eq!(conns, [0, 0]);
            // The stalled flows give up at their handshake bound (at most
            // HS_WATCHDOG; less on a connection idle past IDLE_REUSE),
            // judged a timeout within about a round trip: the connection is
            // alive, its PONG answers the verdict's PING.
            for (at, (_app, task)) in stalled.into_iter().enumerate() {
                assert!(task.await.unwrap().is_err());
                let judged = std::time::Instant::now() - client_request(&relay, &link, next + at);
                assert!(
                    judged <= HS_WATCHDOG + link.rtt() * 2 + Duration::from_millis(250),
                    "{judged:?}"
                );
            }
            assert!(pool.conn_for_test(0).unwrap().ended().is_none());
            close_all(siblings).await.unwrap();
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.strikes(), 0);
    assert_eq!(limiter.auth_failures(), 0);
    assert_eq!(limiter.flow_refusals(), 0);
}

/// The rounds of one whole cycle of `no_ping_over`'s pattern and the burst
/// that follows it: a burst of three every fifth round and a 2 s idle every
/// fourth repeat every 20 rounds, and round 20 is a burst right after an
/// idle (S16n).
const NO_PING_CYCLE: u8 = 21;

#[test]
fn no_ping_on_a_healthy_connection() {
    // DPI guard: a PING only on suspicion. One whole cycle of flows opening,
    // echoing, idling live past STALL_QUIET and ending sends none: every
    // burst and idle the pattern has, each one of them after the other
    // (5 bursts of three and 16 single flows, about 37 s);
    // `no_ping_on_a_healthy_connection_for_a_minute` runs the same pattern
    // for 60 s.
    let opened = no_ping_over(Duration::ZERO);
    assert_eq!(opened, 5 * 3 + 16);
}

/// `no_ping_on_a_healthy_connection` run for a minute, as before S16n: a
/// soak, ignored by default and run alone under the timing lock.
#[test]
fn no_ping_on_a_healthy_connection_for_a_minute() {
    let opened = no_ping_over(Duration::from_secs(60));
    assert!(opened >= 40, "{opened}");
}

/// Flows opening, echoing, idling live past STALL_QUIET and ending, for
/// `NO_PING_CYCLE` rounds and at least `run`, send no PING; how many opened.
fn no_ping_over(run: Duration) -> usize {
    const LIVE: usize = 4;
    let (relay, _link, f) = linked();
    let gate = WorkGate::new();
    let limiter = EstablishLimiter::for_test(20, 3, AUTH_BACKOFF);
    let pool = pool_of(&f, &limiter, &gate, unpinned(), Limits::default());
    // A lease that outlasts the run.
    let span = run.max(Duration::from_secs(30));
    let (services, settings) = services_leased(&pool, span * 3);
    let opened = f.runtime.block_on(async {
        tokio::time::timeout(span * 2, async {
            let started = std::time::Instant::now();
            let mut live = VecDeque::new();
            let mut opened = 0usize;
            let mut round = 0u8;
            while round < NO_PING_CYCLE || started.elapsed() < run {
                // Now and then a burst of three, so streams await at once.
                let burst = if round.is_multiple_of(5) { 3 } else { 1 };
                let mut flows = Vec::new();
                for _ in 0..burst {
                    flows.push(tcp_flow(&services, &settings).await);
                }
                for (mut app, task) in flows {
                    if let Err(error) = app_echo(&mut app, &[round; 64]).await {
                        panic!("round {round}: {error:?} {:?}", task.await);
                    }
                    live.push_back((app, task));
                    opened += 1;
                }
                while live.len() > LIVE {
                    let (app, task) = live.pop_front().unwrap();
                    close(app, task).await.unwrap();
                }
                // Live flows idle past STALL_QUIET every fourth round.
                let idle = if round % 4 == 3 { 2_000 } else { 300 };
                tokio::time::sleep(Duration::from_millis(idle)).await;
                round = round.wrapping_add(1);
            }
            close_all(live).await.unwrap();
            opened
        })
        .await
        .unwrap()
    });
    assert_eq!(client_pings(&relay), 0);
    assert_eq!((limiter.strikes(), limiter.fallbacks()), (0, 0));
    assert!(relay.conns() >= 1);
    assert_eq!(relay.strikes(), 0);
    assert_eq!(limiter.auth_failures(), 0);
    assert_eq!(limiter.flow_refusals(), 0);
    opened
}

#[test]
fn stall_clock_arms_on_quiet_or_a_verdict_and_disarms_on_life() {
    let t = Instant::now();
    let at = |ms: u64| t + Duration::from_millis(ms);
    let wait = PONG_FLOOR;
    let mut clock = StallClock::default();
    // Nothing awaits and no verdict is asked for: idle, however quiet.
    assert_eq!(clock.next(at(10_000), None, t, None, wait), Stall::Idle);
    // A stream awaits from 100 ms, the last sign of life at 400 ms: armed
    // STALL_QUIET after the later.
    let since = Some(at(100));
    assert_eq!(
        clock.next(at(500), since, at(400), None, wait),
        Stall::Until(at(1_900))
    );
    assert_eq!(
        clock.next(at(1_900), since, at(400), None, wait),
        Stall::Arm
    );
    // Armed: it closes at the end of the wait with no sign of life since.
    assert_eq!(
        clock.next(at(2_000), since, at(400), None, wait),
        Stall::Until(at(2_900))
    );
    assert_eq!(
        clock.next(at(2_900), since, at(400), None, wait),
        Stall::Close
    );

    // A sign of life after arming disarms; quiet again re-arms.
    let mut clock = StallClock::default();
    assert_eq!(
        clock.next(at(1_600), since, at(100), None, wait),
        Stall::Arm
    );
    assert_eq!(
        clock.next(at(2_000), since, at(1_700), None, wait),
        Stall::Until(at(3_200))
    );
    assert_eq!(
        clock.next(at(3_200), since, at(1_700), None, wait),
        Stall::Arm
    );
    // A sign of life at the arming instant is not one after it.
    assert_eq!(
        clock.next(at(4_200), since, at(3_200), None, wait),
        Stall::Close
    );

    // A verdict asked for with no sign of life since arms at once, with
    // nothing awaiting the relay.
    let mut clock = StallClock::default();
    let asked = Some(at(500));
    assert_eq!(clock.next(at(510), None, at(400), asked, wait), Stall::Arm);
    assert_eq!(
        clock.next(at(900), None, at(400), asked, wait),
        Stall::Until(at(1_510))
    );
    assert_eq!(
        clock.next(at(1_510), None, at(400), asked, wait),
        Stall::Close
    );
    // One with a sign of life since needs no PING, and is handled once.
    let mut clock = StallClock::default();
    assert_eq!(clock.next(at(510), None, at(505), asked, wait), Stall::Idle);
    assert_eq!(clock.next(at(600), None, at(400), asked, wait), Stall::Idle);
    // One asked while armed waits for that arming's end.
    let mut clock = StallClock::default();
    assert_eq!(
        clock.next(at(1_600), since, at(100), None, wait),
        Stall::Arm
    );
    assert_eq!(
        clock.next(at(2_000), since, at(100), Some(at(2_000)), wait),
        Stall::Until(at(2_600))
    );
    // The wait is the one given when it armed.
    let mut clock = StallClock::default();
    let long = Duration::from_millis(1_500);
    assert_eq!(
        clock.next(at(1_600), since, at(100), None, long),
        Stall::Arm
    );
    assert_eq!(
        clock.next(at(2_000), since, at(100), None, wait),
        Stall::Until(at(3_100))
    );
}

#[test]
fn tcp_acks_grow_as_the_peer_acknowledges_and_stop_when_it_cannot() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();
        let live = Arc::new(Liveness::new(Duration::ZERO));
        let written = || live.written.load(Ordering::SeqCst);
        let mut acks = TcpAcks::new(client.as_raw_fd(), live.clone());
        let mut tcp = CountedTcp {
            tcp: client,
            live: live.clone(),
        };
        assert!(!acks.progressed());
        // The peer's kernel acknowledges what fits its receive buffer.
        tcp.write_all(&[1; 1_000]).await.unwrap();
        assert_eq!(written(), 1_000);
        assert!(wait_for(Duration::from_secs(1), || acks.progressed()).await);
        assert_eq!(acks.read(), Some(1_000));
        // The peer never reads: once its window closes, written bytes stay
        // in this side's send buffer, unacknowledged.
        let chunk = vec![2; 64 * 1024];
        while let Ok(Ok(_)) =
            tokio::time::timeout(Duration::from_millis(200), tcp.write(&chunk)).await
        {}
        tokio::time::sleep(Duration::from_millis(200)).await;
        let _ = acks.progressed();
        let stuck = acks.read().unwrap();
        assert!(written() > stuck);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!acks.progressed());
        assert_eq!(acks.read(), Some(stuck));
        // The peer reads all it received: its window opens and new bytes
        // are acknowledged.
        let mut sink = vec![0; 256 * 1024];
        let mut drained = 0;
        while drained < stuck {
            drained += u64::try_from(peer.read(&mut sink).await.unwrap()).unwrap();
        }
        assert!(wait_for(Duration::from_secs(1), || acks.progressed()).await);
        assert!(acks.read().unwrap() > stuck);
    });
}

#[test]
fn pooled_writes_wait_while_more_than_notsent_lowat_is_unsent() {
    // S16j-1: XNU applies TCP_NOTSENT_LOWAT to write events only, and a
    // write is taken while the send buffer has room. The pooled stream takes
    // none while its socket holds more than NOTSENT_LOWAT unsent, and its
    // writer is woken once the peer reads.
    const CHUNK: usize = 16 * 1024;
    const TOTAL: usize = 4 * 1024 * 1024;
    let mark = usize::try_from(NOTSENT_LOWAT).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let listening = tokio::net::TcpSocket::new_v4().unwrap();
        listening.set_recv_buffer_size(64 * 1024).unwrap();
        listening.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = listening.listen(1).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        set_notsent_lowat(&client).unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();
        let fd = client.as_raw_fd();
        let live = Arc::new(Liveness::new(Duration::ZERO));
        let acks = TcpAcks::new(fd, live.clone());
        let mut tcp = CountedTcp {
            tcp: client,
            live: live.clone(),
        };
        // The peer reads nothing: once its window closes, the writes stop
        // with at most the mark and one write unsent.
        let chunk = vec![3; CHUNK];
        let mut sent = 0;
        while sent < TOTAL {
            match tokio::time::timeout(Duration::from_millis(500), tcp.write(&chunk)).await {
                Ok(Ok(written)) => sent += written,
                _ => break,
            }
        }
        assert!(sent < TOTAL, "{sent}");
        assert!(acks.read().is_some());
        let queued = usize::try_from(live.queued.load(Ordering::Relaxed)).unwrap();
        assert!(queued > mark, "{queued}");
        assert!(queued <= mark + CHUNK, "{queued}");
        assert!(unsent(fd).unwrap() > u64::try_from(mark).unwrap());
        // The peer reads everything: the writer, a task of its own woken
        // only by its socket, finishes.
        let writer = tokio::spawn(async move {
            while sent < TOTAL {
                sent += tcp.write(&chunk).await.unwrap();
            }
            tcp.flush().await.unwrap();
            tcp
        });
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut sink = vec![0; 256 * 1024];
            let mut read = 0;
            while read < TOTAL {
                read += peer.read(&mut sink).await.unwrap();
            }
            writer.await.unwrap()
        })
        .await
        .expect("the writer was never woken");
        assert_eq!(live.written.load(Ordering::SeqCst), TOTAL as u64);
    });
}

#[test]
fn stall_verdict_retries_a_flow_awaiting_its_200() {
    let (relay, link, f) = linked();
    let gate = WorkGate::new();
    let limiter = EstablishLimiter::for_test(20, 3, AUTH_BACKOFF);
    let pool = pool_of(&f, &limiter, &gate, unpinned(), one_conn());
    let (services, settings) = services_of(&pool);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            let mut siblings = live_flows(&services, &settings, SIBLINGS).await;
            let conn = pool.conn_for_test(0).unwrap();
            let accepted = relay.streams();
            // The path freezes the connection before the flow's request
            // reaches the relay. A sibling's upload after the request is
            // acknowledged (by the loopback kernel) as a sign of life, so
            // the watchdog arms only after the flow's carrier bound passed;
            // then the path's ACKs stop too.
            relay.freeze(0);
            let requested = std::time::Instant::now();
            let (mut app, task) = tcp_flow(&services, &settings).await;
            tokio::time::sleep(Duration::from_millis(300)).await;
            siblings[0].0.write_all(b"late").await.unwrap();
            tokio::time::sleep(ACK_SAMPLE * 2).await;
            conn.freeze_acks_for_test();
            // The flow's carrier bound passes first; its verdict is the
            // close, so it is a connection loss, retried on a fresh
            // connection.
            app_echo(&mut app, b"retried").await.unwrap();
            assert_eq!(conn.ended(), Some(ConnEnd::LocalClose));
            assert_eq!(conn.pings(), 1);
            assert!(requested.elapsed() > HS_WATCHDOG + RETRY_MARGIN);
            // Lost before its 200: the relay never ran its handshake, no
            // ledger entry (S16h-8b).
            assert_eq!(limiter.strikes(), 0);
            close(app, task).await.unwrap();
            assert_eq!(relay.streams(), accepted + 1);
            for (_app, task) in siblings {
                assert!(task.await.unwrap().is_err());
            }
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.conns(), 2);
    assert_eq!(link.connections(), 2);
    assert_eq!(limiter.auth_failures(), 0);
    assert_eq!(limiter.flow_refusals(), 0);
    assert!(!limiter.flows_backing_off() && !limiter.backing_off());
}

#[test]
fn stall_watchdog_spares_a_connection_whose_uplink_is_backlogged() {
    // A slow uplink (16 KB/s) under one flow's bulk upload to a target that
    // only reads: the relay's answers are its window updates, one per
    // half window consumed (seconds apart), and the upload queues in the
    // client's socket buffers. A flow opened behind it awaits its 200 past
    // STALL_QUIET and PONG_FLOOR with no inbound byte. The TCP ACKs of the
    // draining backlog are a sign of life: no PING, no close.
    const UPLINK: u32 = 16 * 1024;
    let listener = TestRelay::bind();
    let link = TestLink::with_uplink(listener.local_addr().unwrap(), DEFAULT_RTT, UPLINK);
    let f = kit_on(ReadyTree::with_online_completed(link.address()));
    let relay = TestRelay::spawn_streams(
        listener,
        RelayIdentity::for_tree(&f.tree),
        PoolConfig::default(),
    );
    let gate = WorkGate::new();
    let limiter = EstablishLimiter::for_test(20, 3, AUTH_BACKOFF);
    let pool = pool_of(&f, &limiter, &gate, unpinned(), one_conn());
    let (services, settings) = services_of(&pool);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(40), async {
            relay.at(0, StreamFault::SinkUpload);
            let (mut upload, uploading) = tcp_flow(&services, &settings).await;
            relay
                .wait_count(StreamStep::Opened, 1, Duration::from_secs(10))
                .await
                .unwrap();
            let conn = pool.conn_for_test(0).unwrap();
            let pump = tokio::spawn(async move {
                let chunk = vec![0x5a; 16 * 1024];
                while upload.write_all(&chunk).await.is_ok() {}
            });
            // The backlog builds up to the relay's window.
            tokio::time::sleep(Duration::from_secs(3)).await;
            let behind_at = std::time::Instant::now();
            let (_app, behind) = tcp_flow(&services, &settings).await;
            // Its request sits behind the backlog past its carrier bound,
            // then its verdict finds the connection alive: a timeout.
            assert!(behind.await.unwrap().is_err());
            assert!(behind_at.elapsed() >= HS_WATCHDOG);
            let watched = behind_at + HS_WATCHDOG + PONG_FLOOR * 2;
            tokio::time::sleep_until(Instant::from_std(watched)).await;
            assert_eq!(conn.ended(), None);
            assert_eq!(conn.pings(), 0);
            assert!(!uploading.is_finished() && !pump.is_finished());
            assert_eq!(pool.views().len(), 1);
            pump.abort();
            uploading.abort();
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.conns(), 1);
    assert_eq!(relay.strikes(), 0);
    assert_eq!(limiter.auth_failures(), 0);
}

// ---- S16h-8b, 8d: the epoch's strike ledger and the one-stream fallback,
// ---- at 170 ms RTT ----

#[test]
fn only_an_end_the_relay_may_not_have_seen_is_a_strike_cause() {
    // This side's close (the stall watchdog's among them), which a frozen
    // path never carried, or a lost interface.
    assert!(strike_cause(Some(ConnEnd::LocalClose), false, false));
    assert!(strike_cause(Some(ConnEnd::Io), true, false));
    assert!(strike_cause(None, true, false));
    // v41: a loss in a session an epoch re-pin superseded is the re-pin's
    // own teardown, whatever ended its connection: never a strike.
    for end in [
        None,
        Some(ConnEnd::Io),
        Some(ConnEnd::LocalClose),
        Some(ConnEnd::GoAway(h2::Reason::NO_ERROR, 1)),
    ] {
        for interface_lost in [false, true] {
            assert!(!strike_cause(end, interface_lost, true), "{end:?}");
        }
    }
    // The relay's own end (RST, EOF) or GOAWAY is its to see.
    assert!(!strike_cause(Some(ConnEnd::Io), false, false));
    for reason in [h2::Reason::NO_ERROR, h2::Reason::ENHANCE_YOUR_CALM] {
        assert!(!strike_cause(
            Some(ConnEnd::GoAway(reason, 0)),
            false,
            false
        ));
    }
    assert!(!strike_cause(None, false, false));
}

/// How many flow permits `limiter` grants at once now, returned at once.
async fn flow_permits_now(limiter: &Arc<EstablishLimiter>) -> usize {
    let mut held = Vec::new();
    while let Ok(permit) = limiter
        .acquire(Purpose::Flow, Duration::from_millis(30))
        .await
    {
        held.push(permit);
    }
    held.len()
}

#[test]
fn freeze_watchdog_and_ledger() {
    // A production limiter of one provider epoch: S17 rebuilds a session
    // with a new limiter registered with the same AuthBackoff.
    let (relay, link, f) = linked();
    let epoch = AuthBackoff::default();
    let gate = WorkGate::new();
    let limiter = EstablishLimiter::new(epoch.clone());
    let pool = pool_of(&f, &limiter, &gate, unpinned(), one_conn());
    let (services, settings) = services_of(&pool);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(40), async {
            let siblings = live_flows(&services, &settings, SIBLINGS).await;
            let conn = pool.conn_for_test(0).unwrap();
            assert_eq!(limiter.strikes(), 0);
            // Two flows in their inner handshake on the one connection,
            // past their 200: the relay's deadline runs for both.
            let next = relay.streams();
            relay.at(next, StreamFault::StallHandshake);
            relay.at(next + 1, StreamFault::StallHandshake);
            let establishing = vec![
                tcp_flow(&services, &settings).await,
                tcp_flow(&services, &settings).await,
            ];
            let stalled = relay
                .wait_count(StreamStep::HandshakeStalled, 2, Duration::from_secs(5))
                .await
                .unwrap();
            assert_eq!(pool.views()[0].establishing, 2);
            relay.freeze(0);
            conn.freeze_acks_for_test();
            // The stall watchdog closes it within STALL_QUIET + PONG_FLOOR
            // of its last inbound byte.
            assert!(wait_for(Duration::from_secs(5), || conn.ended().is_some()).await);
            let closed = std::time::Instant::now();
            assert_eq!(conn.ended(), Some(ConnEnd::LocalClose));
            let latest = stalled + link.rtt() / 2;
            assert!(
                closed - latest <= STALL_QUIET + PONG_FLOOR + Duration::from_millis(300),
                "{:?}",
                closed - latest
            );
            // Both were lost in their exposed window to a close the relay
            // never saw: the ledger reaches 2 (level 2).
            assert!(wait_for(Duration::from_secs(2), || limiter.strikes() == 2).await);
            for (_app, task) in siblings {
                assert!(task.await.unwrap().is_err());
            }
            // Retried once each on a fresh connection, one handshake at a
            // time, and through.
            for (mut app, task) in establishing {
                app_echo(&mut app, b"retried").await.unwrap();
                close(app, task).await.unwrap();
            }
            assert_eq!(limiter.strikes(), 2);
            assert_eq!(
                limiter.pool_mode(),
                crate::establish_limit::PoolMode {
                    strikes: 2,
                    fallback: false
                }
            );
            // Flow permits drop to 1; the ACK path keeps every permit it
            // had at once, with no backoff.
            assert_eq!(flow_permits_now(&limiter).await, 1);
            let flow = limiter
                .acquire(Purpose::Flow, Duration::ZERO)
                .await
                .unwrap();
            let mut acks = Vec::new();
            for _ in 0..ACK_RESERVE {
                acks.push(limiter.acquire(Purpose::Ack, Duration::ZERO).await.unwrap());
            }
            assert!(!limiter.backing_off() && !limiter.probing());
            drop((acks, flow));
            // The relay's deadlines fire on the frozen connection: it
            // charged exactly what the ledger counts.
            assert!(wait_for(Duration::from_secs(8), || relay.strikes() == 2).await);
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.strikes(), 2);
    assert_eq!(limiter.auth_failures(), 0);
    assert_eq!(limiter.flow_refusals(), 0);
    // S17: the session is rebuilt in the same epoch. The new limiter and its
    // pool start at level 2: one flow permit, one handshake per connection.
    drop(services);
    drop(pool);
    drop(limiter);
    let gate = WorkGate::new();
    let rebuilt = EstablishLimiter::new(epoch.clone());
    assert_eq!(rebuilt.strikes(), 2);
    let pool = pool_of(&f, &rebuilt, &gate, unpinned(), Limits::default());
    let (services, settings) = services_of(&pool);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(20), async {
            assert_eq!(flow_permits_now(&rebuilt).await, 1);
            let (mut app, task) = tcp_flow(&services, &settings).await;
            app_echo(&mut app, b"rebuilt").await.unwrap();
            assert_eq!(pool.views()[0].h_conn, 1);
            // Its handshake ran on a connection whose outer TLS handshake had
            // just proved the path: no PING.
            assert_eq!(pool.conn_for_test(0).unwrap().pings(), 0);
            close(app, task).await.unwrap();
        })
        .await
        .unwrap();
    });
    assert_eq!(rebuilt.strikes(), 2);
    assert_eq!(relay.strikes(), 2);
}

#[test]
fn strike_levels_narrow_the_pool() {
    let (relay, _link, f) = linked();
    let gate = WorkGate::new();
    let limiter = EstablishLimiter::new(AuthBackoff::default());
    let pool = pool_of(&f, &limiter, &gate, unpinned(), Limits::default());
    let (services, settings) = services_of(&pool);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            // One fresh connection with live flows, opened one by one.
            let mut siblings = Vec::new();
            for tag in 0..SIBLINGS {
                let (mut app, task) = tcp_flow(&services, &settings).await;
                app_echo(&mut app, &[u8::try_from(tag).unwrap(); 32])
                    .await
                    .unwrap();
                siblings.push((app, task));
            }
            let views = pool.views();
            assert_eq!((views.len(), views[0].h_conn), (1, H_CONN), "{views:?}");
            let deadline = Instant::now() + Duration::from_secs(5);
            // Level 1: one inner handshake per connection, so a second
            // reservation dials a second connection.
            assert_eq!(limiter.strike(), 1);
            assert_eq!(pool.views()[0].h_conn, 1);
            assert_eq!(flow_permits_now(&limiter).await, POOL_CONNS);
            let first = pool.reserve(deadline).await.unwrap();
            let mut second = pool.reserve(deadline).await.unwrap();
            assert_eq!((first.conn_id(), second.conn_id()), (0, 1));
            assert_eq!(pool.stats().dials, 2);
            // The second connection's probe returns: it is Open, and its
            // one slot takes the next reservation.
            second.handshake_done(true);
            let third = pool.reserve(deadline).await.unwrap();
            assert_eq!(third.conn_id(), 1);
            let views = pool.views();
            assert!(
                views
                    .iter()
                    .all(|view| view.establishing == 1 && view.h_conn == 1),
                "{views:?}"
            );
            // Level 2: one handshake at a time, so with every connection's
            // slot taken no connection is dialed for another.
            assert_eq!(limiter.strike(), 2);
            assert_eq!(flow_permits_now(&limiter).await, 1);
            let refused = pool
                .reserve(Instant::now() + Duration::from_millis(400))
                .await;
            assert_eq!(
                refused.err().map(|error| error.kind()),
                Some(io::ErrorKind::TimedOut)
            );
            assert_eq!(pool.stats().dials, 2);
            drop((first, second, third));
            // The second connection idles out; the first keeps its live
            // flows. Neither path proved itself (a PONG, or its TLS
            // handshake) within PROOF_FRESH: a flow's handshake waits for
            // one PING's PONG; the next, within PROOF_FRESH, needs none.
            tokio::time::sleep(crate::establish_limit::PROOF_FRESH + IDLE_REUSE / 4).await;
            assert_eq!(client_pings(&relay), 0);
            let (mut app, task) = tcp_flow(&services, &settings).await;
            app_echo(&mut app, b"proven").await.unwrap();
            assert_eq!(client_pings(&relay), 1);
            let (mut next, next_task) = tcp_flow(&services, &settings).await;
            app_echo(&mut next, b"still proven").await.unwrap();
            assert_eq!(client_pings(&relay), 1);
            assert_eq!(pool.stats().dials, 2);
            close(app, task).await.unwrap();
            close(next, next_task).await.unwrap();
            close_all(siblings).await.unwrap();
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.strikes(), 0);
    assert_eq!(limiter.auth_failures(), 0);
    assert_eq!(limiter.flow_refusals(), 0);
}

#[test]
fn stall_fallback() {
    const FLOWS: usize = 5;
    let (relay, _link, f) = linked();
    let epoch = AuthBackoff::default();
    let gate = WorkGate::new();
    let limiter = EstablishLimiter::new(epoch.clone());
    let pool = pool_of(&f, &limiter, &gate, unpinned(), Limits::default());
    let (services, settings) = services_of(&pool);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(40), async {
            // Two connections, each frozen under an Open awaiting its
            // status (outside its exposed window: no strike), each closed by
            // its stall watchdog, well within STALL_DEATH_WINDOW.
            for conn_index in 0..2usize {
                relay.at(relay.streams(), StreamFault::HangTarget);
                let (_app, awaiting) = tcp_flow(&services, &settings).await;
                assert!(wait_for(Duration::from_secs(5), || limiter.unverified() == 1).await);
                let id = u64::try_from(conn_index).unwrap();
                let conn = pool.conn_for_test(id).unwrap();
                assert_eq!(limiter.fallbacks(), 0);
                relay.freeze(conn_index);
                conn.freeze_acks_for_test();
                assert!(awaiting.await.unwrap().is_err());
                assert_eq!(conn.ended(), Some(ConnEnd::LocalClose));
            }
            assert_eq!(limiter.strikes(), 0);
            // The second stall death switched the fallback on (its
            // pool_fallback line).
            assert_eq!(limiter.fallbacks(), 1);
            assert!(limiter.pool_mode().fallback);
            assert_eq!(flow_permits_now(&limiter).await, 3);
            // Live flows opened together: each on its own connection.
            let flows = live_flows(&services, &settings, FLOWS).await;
            assert_eq!(relay.conns(), 2 + FLOWS);
            assert_eq!(pool.stats().max_streams, 1);
            let views = pool.views();
            assert!(views.iter().all(|view| view.streams <= 1), "{views:?}");
            close_all(flows).await.unwrap();
            // A probing connection offers no second stream: a flow opened
            // while another's probe is in its handshake dials at once,
            // rather than waiting for that probe to return. The idle
            // connections drain first, so both flows dial.
            tokio::time::sleep(IDLE_REUSE + Duration::from_millis(200)).await;
            let conns = relay.conns();
            relay.at(relay.streams(), StreamFault::StallHandshake);
            let (_stalled_app, stalled) = tcp_flow(&services, &settings).await;
            relay
                .wait_count(StreamStep::HandshakeStalled, 1, Duration::from_secs(5))
                .await
                .unwrap();
            let started = std::time::Instant::now();
            let (mut app, task) = tcp_flow(&services, &settings).await;
            app_echo(&mut app, b"beside a probe").await.unwrap();
            assert!(
                started.elapsed() < Duration::from_millis(2_000),
                "{:?}",
                started.elapsed()
            );
            assert_eq!(relay.conns(), conns + 2);
            close(app, task).await.unwrap();
            // The stalled probe gives up at its watchdog on a live
            // connection: a timeout, no ledger entry.
            assert!(stalled.await.unwrap().is_err());
            assert_eq!(limiter.strikes(), 0);
        })
        .await
        .unwrap();
    });
    assert!(limiter.high_water() <= 3, "{}", limiter.high_water());
    // The fallback is the epoch's: a rebuilt session keeps it.
    assert!(EstablishLimiter::new(epoch).pool_mode().fallback);
    assert_eq!(limiter.auth_failures(), 0);
    assert_eq!(limiter.flow_refusals(), 0);
}

// ---- S16h-8b, 8d review fixes ----

/// `n` live echo flows opened one by one: all on one connection.
async fn one_by_one(
    services: &Services,
    settings: &aegis_core::RelaySettings,
    n: usize,
) -> Vec<(TcpStream, FlowTask)> {
    let mut flows = Vec::new();
    for tag in 0..n {
        let (mut app, task) = tcp_flow(services, settings).await;
        app_echo(&mut app, &[u8::try_from(tag).unwrap(); 32])
            .await
            .unwrap();
        flows.push((app, task));
    }
    flows
}

#[test]
fn an_unproven_connection_closes_and_its_flow_dials_past_it() {
    let (relay, _link, f) = linked();
    let gate = WorkGate::new();
    let limiter = EstablishLimiter::new(AuthBackoff::default());
    let pool = pool_of(&f, &limiter, &gate, unpinned(), Limits::default());
    let (services, settings) = services_of(&pool);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            // One connection whose live flows are quiet: reusable, with a
            // free handshake slot, so level 2 dials no second one beside it.
            let siblings = one_by_one(&services, &settings, SIBLINGS).await;
            assert_eq!(pool.views().len(), 1);
            let conn = pool.conn_for_test(0).unwrap();
            assert_eq!(limiter.strike(), 1);
            assert_eq!(limiter.strike(), 2);
            // Its last proof (its outer TLS handshake) grows stale, and then
            // its path freezes.
            tokio::time::sleep(crate::establish_limit::PROOF_FRESH).await;
            relay.freeze(0);
            conn.freeze_acks_for_test();
            // The next flow's proof gets no PONG: its question closes the
            // connection, and its retry dials past it and goes through.
            let (mut app, task) = tcp_flow(&services, &settings).await;
            app_echo(&mut app, b"past the frozen one").await.unwrap();
            assert_eq!(conn.ended(), Some(ConnEnd::LocalClose));
            assert_eq!(conn.pings(), 1);
            assert_eq!(pool.stats().dials, 2);
            assert!(!pool.views().iter().any(|view| view.id == 0));
            close(app, task).await.unwrap();
            // So does the one after it, with no wait for a proof.
            let started = std::time::Instant::now();
            let (mut app, task) = tcp_flow(&services, &settings).await;
            app_echo(&mut app, b"next").await.unwrap();
            assert!(started.elapsed() < PONG_FLOOR, "{:?}", started.elapsed());
            close(app, task).await.unwrap();
            for (_app, task) in siblings {
                assert!(task.await.unwrap().is_err());
            }
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.conns(), 2);
    // The unproven flow sent no byte: no ledger entry, and the relay
    // charged nothing.
    assert_eq!(limiter.strikes(), 2);
    assert_eq!(relay.strikes(), 0);
    assert_eq!(limiter.auth_failures(), 0);
    assert_eq!(limiter.flow_refusals(), 0);
}

#[test]
fn a_loss_before_the_relay_read_the_finished_is_a_strike() {
    let (relay, _link, f) = linked();
    let gate = WorkGate::new();
    let limiter = EstablishLimiter::for_test(20, 3, AUTH_BACKOFF);
    let pool = pool_of(&f, &limiter, &gate, unpinned(), one_conn());
    let (services, settings) = services_of(&pool);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            let siblings = live_flows(&services, &settings, SIBLINGS).await;
            let conn = pool.conn_for_test(0).unwrap();
            // The next flow's inner handshake returns, and the path freezes
            // before its Finished reaches the relay, half an RTT away: no
            // TCP ACK of it, and the relay never reads it.
            conn.freeze_acks_at_handshake_for_test();
            let next = relay.streams();
            let (_app, task) = tcp_flow(&services, &settings).await;
            assert!(wait_for(Duration::from_secs(5), || conn.acks_frozen()).await);
            relay.freeze(0);
            // Its Open is lost with the connection at the stall watchdog's
            // close, seconds after its handshake returned.
            assert!(task.await.unwrap().is_err());
            assert_eq!(conn.ended(), Some(ConnEnd::LocalClose));
            assert_eq!(limiter.strikes(), 1);
            // The relay's deadline fired on it as a strike: the ledger
            // counts what the relay charged.
            assert!(
                relay
                    .wait_step(next, StreamStep::Struck, Duration::from_secs(8))
                    .await
                    .is_some(),
                "{:?}",
                relay.steps(next)
            );
            assert!(!relay.steps(next).contains(&StreamStep::Authenticated));
            for (_app, task) in siblings {
                assert!(task.await.unwrap().is_err());
            }
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.strikes(), 1);
    assert_eq!(limiter.strikes(), 1);
    assert_eq!(limiter.auth_failures(), 0);
}

/// v41: a re-pin's own teardown is no strike (window-v39-ifswitch-r1 on
/// build 40: nine slots dropped by the plug re-pin's teardown were nine
/// ledger entries, and the session rebuilt on the new pin ran at strike
/// level 2). Its handshakes are still stranded against the relay's 32.
#[test]
fn a_repins_own_teardown_is_no_strike_and_strands_its_handshakes() {
    let (relay, link, f) = linked();
    let gate = WorkGate::new();
    let pins = EpochPins::default();
    let limiter = EstablishLimiter::new(pins.auth_backoff());
    let pool = pool_of(
        &f,
        &limiter,
        &gate,
        (pins.clone(), pins.generation()),
        one_conn(),
    );
    let (services, settings) = services_of(&pool);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            let siblings = live_flows(&services, &settings, SIBLINGS).await;
            let conn = pool.conn_for_test(0).unwrap();
            // A flow whose Finished no TCP ACK followed, accepted all the
            // same: past its handshake, whatever the path showed.
            conn.freeze_acks_at_handshake_for_test();
            let (mut accepted, accepted_task) = tcp_flow(&services, &settings).await;
            app_echo(&mut accepted, b"accepted").await.unwrap();
            assert!(conn.acks_frozen());
            // A flow dropped mid-handshake on a path that still carries its
            // reset costs nothing.
            let next = relay.streams();
            relay.at(next, StreamFault::StallHandshake);
            let (_app, cancelled) = tcp_flow(&services, &settings).await;
            assert!(relay
                .wait_step(next, StreamStep::HandshakeStalled, Duration::from_secs(5))
                .await
                .is_some());
            // Its 200 reached it: past its 200, in its inner handshake.
            tokio::time::sleep(link.rtt()).await;
            cancelled.abort();
            assert!(cancelled.await.unwrap_err().is_cancelled());
            assert!(relay
                .wait_step(next, StreamStep::HandshakeFailed, Duration::from_secs(5))
                .await
                .is_some());
            assert_eq!(limiter.strikes(), 0);
            // Two flows in their inner handshake when the path changes: the
            // session's teardown drops them unjudged. The re-pin is this
            // side's own act, which the relay charges no strike for (R2),
            // so the ledger counts none; the relay may still hold their
            // handshakes until its deadline, so they are stranded.
            let next = relay.streams();
            relay.at(next, StreamFault::StallHandshake);
            relay.at(next + 1, StreamFault::StallHandshake);
            let stalled = vec![
                tcp_flow(&services, &settings).await,
                tcp_flow(&services, &settings).await,
            ];
            assert!(relay
                .wait_count(StreamStep::HandshakeStalled, 3, Duration::from_secs(5))
                .await
                .is_some());
            tokio::time::sleep(link.rtt()).await;
            pins.repin(&RelayInterface::for_test("en9", 9));
            assert!(pins.auth_backoff().stranded_hs_recorded() >= 2);
            for (_app, task) in stalled {
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
            }
            assert_eq!(limiter.strikes(), 0);
            // Both were exposed: the ledger would have counted them, and
            // the re-pin spared exactly these two.
            assert_eq!(limiter.spared(), 2);
            // Accepted and live flows that end after the re-pin cost none.
            close(accepted, accepted_task).await.unwrap();
            close_all(siblings).await.unwrap();
            assert_eq!(limiter.strikes(), 0);
            assert_eq!(limiter.spared(), 2);
        })
        .await
        .unwrap();
    });
    // The epoch's: the session rebuilt on the new pin starts at full width.
    let rebuilt = EstablishLimiter::new(pins.auth_backoff());
    assert_eq!(rebuilt.pool_mode(), PoolMode::default());
    assert_eq!(limiter.auth_failures(), 0);
}

/// v41, the installed defect (window-v39-ifswitch-r1, build 40, the plug
/// direction Wi-Fi to cable with Wi-Fi still up): the re-pin's teardown
/// dropped nine flows in their inner handshake, each an entry of the
/// epoch's strike ledger, and the session rebuilt on the new pin ran at
/// strike level 2 for the ledger's 300 s: one inner handshake at a time,
/// each behind a proof PING, one pooled connection (`conns:1-0-0`), 26 to
/// 78 flows waiting and refused as pool waits, so whoami, the UDP echo and
/// the TCP echo failed 6 to 20 s after the rebuild. The deployed relay (R2)
/// charged none of those losses: it admitted the rebuilt session's
/// handshakes after their deadlines had passed. Here a session with many
/// live pooled flows and three in their inner handshake is re-pinned (the
/// old path still up: this loopback relay sees its resets), torn down, and
/// the session rebuilt on the new pin must serve a burst at full width:
/// its first flow within 3 s, every flow within its connect budget, and its
/// pool beyond one connection.
#[test]
fn a_session_rebuilt_after_a_plug_repin_serves_a_burst_at_full_width() {
    // Sized to stay light beside the parallel suite's timing tests (24
    // live and a 32-flow burst coincided with lease-timing failures there).
    const LIVE: usize = 12;
    const EXPOSED: usize = 3;
    const BURST: usize = 24;
    const FIRST_FLOW: Duration = Duration::from_secs(3);
    let (relay, link, f) = linked_with(PoolConfig {
        setup: DEFAULT_RTT * 3 / 2,
        ..PoolConfig::default()
    });
    let pins = EpochPins::default();
    // The session the re-pin ends.
    let lost_gate = WorkGate::new();
    let lost = EstablishLimiter::new(pins.auth_backoff());
    let lost_pool = pool_of(
        &f,
        &lost,
        &lost_gate,
        (pins.clone(), pins.generation()),
        Limits::default(),
    );
    let (services, settings) = services_of(&lost_pool);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(60), async {
            let live = live_flows(&services, &settings, LIVE).await;
            let next = relay.streams();
            for index in next..next + EXPOSED {
                relay.at(index, StreamFault::StallHandshake);
            }
            let mut stalled = Vec::new();
            for _ in 0..EXPOSED {
                stalled.push(tcp_flow(&services, &settings).await);
            }
            assert!(relay
                .wait_count(
                    StreamStep::HandshakeStalled,
                    EXPOSED,
                    Duration::from_secs(5)
                )
                .await
                .is_some());
            // Their 200s reached this side: in their inner handshake.
            tokio::time::sleep(link.rtt()).await;
            // The plug: a new primary, the old interface still up.
            pins.repin(&RelayInterface::for_test("en9", 9));
            // The session's teardown ends every one of its flows unjudged.
            for (_app, task) in stalled.into_iter().chain(live) {
                task.abort();
                let _ = task.await;
            }
        })
        .await
        .unwrap();
    });
    lost_gate
        .stop(crate::held_relay_services::MAX_DRAIN)
        .unwrap();
    drop((services, lost_pool));
    // The scenario of the defect: each flow in its inner handshake was an
    // exposed loss of the teardown, which the ledger counted before v41.
    assert_eq!(lost.spared(), u64::try_from(EXPOSED).unwrap());
    assert_eq!(lost.strikes(), 0);
    // The session rebuilt on the new pin, and the burst of flows every app
    // sends once the path changed.
    let gate = WorkGate::new();
    let rebuilt = EstablishLimiter::new(pins.auth_backoff());
    let pool = pool_of(
        &f,
        &rebuilt,
        &gate,
        (pins.clone(), pins.generation()),
        Limits::default(),
    );
    let (services, settings) = services_of(&pool);
    let budget = Duration::from_millis(settings.connect_timeout_ms);
    let (first, last, failed) = f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(90), async {
            let started = std::time::Instant::now();
            let mut opened = Vec::new();
            for _ in 0..BURST {
                opened.push(tcp_flow(&services, &settings).await);
            }
            let mut echoes = tokio::task::JoinSet::new();
            for (tag, (mut app, task)) in opened.into_iter().enumerate() {
                let tag = u8::try_from(tag).unwrap();
                echoes.spawn(async move {
                    let echo = app_echo(&mut app, &[tag; 64]).await;
                    (started.elapsed(), echo, app, task)
                });
            }
            let mut first: Option<Duration> = None;
            let mut last = Duration::ZERO;
            let mut failed = 0;
            let mut echoed = Vec::new();
            for (at, echo, app, task) in echoes.join_all().await {
                last = last.max(at);
                match echo {
                    Ok(()) => {
                        first = Some(first.map_or(at, |first| first.min(at)));
                        echoed.push((app, task));
                    }
                    Err(_) => failed += 1,
                }
            }
            close_all(echoed).await.unwrap();
            (first, last, failed)
        })
        .await
        .unwrap()
    });
    let stats = pool.stats();
    eprintln!(
        "rebuilt burst of {BURST}: first {first:?} last {last:?} failed {failed} budget \
         {budget:?} mode {:?} stats {stats:?}",
        rebuilt.pool_mode()
    );
    assert!(first.is_some_and(|first| first <= FIRST_FLOW), "{first:?}");
    assert_eq!(failed, 0, "{stats:?}");
    assert!(last < budget, "{last:?} {budget:?}");
    assert!(stats.max_conns >= 2, "{stats:?}");
    assert_eq!(rebuilt.pool_mode(), PoolMode::default());
    assert_eq!(rebuilt.strikes(), 0);
    assert_eq!(relay.strikes(), 0);
    assert_eq!(rebuilt.auth_failures(), 0);
}

#[test]
fn a_slot_reserved_before_a_strike_never_shares_its_handshake() {
    let (relay, link, f) = linked();
    let gate = WorkGate::new();
    let limiter = EstablishLimiter::new(AuthBackoff::default());
    let pool = pool_of(&f, &limiter, &gate, unpinned(), Limits::default());
    let (services, settings) = services_of(&pool);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            let siblings = one_by_one(&services, &settings, SIBLINGS).await;
            assert_eq!(pool.stats().dials, 1);
            // Every flow permit held: `H_CONN` flows reserve every handshake
            // slot of the one connection, then wait for their permits.
            let mut held = Vec::new();
            while let Ok(permit) = limiter
                .acquire(Purpose::Flow, Duration::from_millis(30))
                .await
            {
                held.push(permit);
            }
            let mut flows = Vec::new();
            for _ in 0..H_CONN {
                flows.push(tcp_flow(&services, &settings).await);
            }
            assert!(
                wait_for(Duration::from_secs(5), || pool.views()[0].establishing
                    == H_CONN)
                .await
            );
            // The first strike narrows every connection to one inner
            // handshake meanwhile; then their permits come.
            assert_eq!(limiter.strike(), 1);
            drop(held);
            for (mut app, task) in flows {
                app_echo(&mut app, b"one at a time").await.unwrap();
                close(app, task).await.unwrap();
            }
            // The `H_CONN - 1` that shared it gave their slots back and
            // dialed connections of their own (at most `POOL_DIALS` at once
            // and the pool's 4 in all), each running one handshake.
            let dials = pool.stats().dials;
            assert!((2..=H_CONN.min(POOL_CONNS)).contains(&dials), "{dials}");
            assert_eq!(relay.conns(), dials);
            close_all(siblings).await.unwrap();
        })
        .await
        .unwrap();
    });
    // No connection ever ran two inner handshakes at once: the siblings
    // opened one by one, and after the strike every slot ran alone.
    let events = relay.events();
    for conn in 0..relay.conns() {
        assert_eq!(
            handshake_high_water(&events, conn, link.rtt() / 4),
            1,
            "conn {conn}"
        );
    }
    assert_eq!(relay.strikes(), 0);
    assert_eq!(limiter.strikes(), 1);
    assert_eq!(limiter.auth_failures(), 0);
    assert_eq!(limiter.flow_refusals(), 0);
}

#[test]
fn an_awaited_predial_no_flow_took_closes_after_its_probes_last_chance() {
    // S16i-1: a pre-dial that joined with flows waiting for it keeps its
    // probe offered past IDLE_REUSE while hs_budget leaves HS_FLOOR; one no
    // flow took is closed by this side once that passed, never left to
    // the relay's idle close.
    let (_listener, f) = kit();
    let gate = WorkGate::new();
    let limiter = limiter();
    let pool = pool_of(&f, &limiter, &gate, unpinned(), Limits::default());
    f.runtime.block_on(async {
        let (conn, _sender, _cut, _relay) = unrecorded_conn(&gate).await;
        let anchor = conn.connect_started();
        let id = pool.insert_for_test(conn, Phase::Probing, (0, 0));
        {
            let mut state = pool.lock();
            let entry = state.entry(id).unwrap();
            (entry.waited_for, entry.prewarmed) = (true, true);
        }
        pool.close_unused(id).await;
        let closed = Instant::now();
        assert!(pool.views().is_empty(), "{:?}", pool.views());
        assert!(
            closed >= anchor + HS_HORIZON.saturating_sub(HS_FLOOR),
            "{:?}",
            closed - anchor
        );
        assert!(closed < anchor + HS_HORIZON, "{:?}", closed - anchor);
    });
    assert!(limiter
        .flow_log_lines()
        .contains(&"pool_prewarm unused".to_owned()));
}

#[test]
fn a_slow_dials_probe_and_an_awaited_predial_are_offered_while_hs_floor_is_left() {
    // S16i-1: past IDLE_REUSE a connection with no stream drains and one
    // without an authenticated stream takes none, but its own probe (its
    // one stream ever) is still sent, and an awaited pre-dial still offers
    // its probe, while hs_budget leaves HS_FLOOR.
    let (_listener, f) = kit();
    let gate = WorkGate::new();
    let limiter = limiter();
    let pool = pool_of(&f, &limiter, &gate, unpinned(), Limits::default());
    let limits = Limits::default();
    f.runtime.block_on(async {
        let (conn, _sender, _cut, _relay) = unrecorded_conn(&gate).await;
        let anchor = conn.connect_started();
        // Its probe taken: one establishing stream, its only one.
        let id = pool.insert_for_test(conn, Phase::Probing, (1, 0));
        let past = anchor + IDLE_REUSE + Duration::from_millis(1);
        let last = anchor + HS_HORIZON.saturating_sub(HS_FLOOR);
        let after = last + Duration::from_millis(1);
        let mut state = pool.lock();
        let entry = state.entry(id).unwrap();
        assert!(!entry.reusable(&limits, past));
        assert!(entry.probe_sendable(past));
        assert!(entry.probe_sendable(last));
        assert!(!entry.probe_sendable(after));
        // A second stream on it is no probe.
        entry.opened = 2;
        assert!(!entry.probe_sendable(past));
        // A pre-dial no flow took yet.
        (entry.establishing, entry.streams, entry.opened) = (0, 0, 0);
        assert!(!entry.reusable(&limits, past));
        assert!(!entry.awaited(past));
        entry.waited_for = true;
        assert!(entry.awaited(past));
        assert!(entry.reusable(&limits, past));
        assert!(entry.reusable(&limits, last));
        assert!(!entry.reusable(&limits, after));
        // Once its probe was taken and ended, the idle rule applies again.
        entry.opened = 1;
        assert!(!entry.awaited(past));
        assert!(!entry.reusable(&limits, past));
    });
}

/// `kit` served by the multi-stream relay with `config`.
fn pooled_with(config: PoolConfig) -> (PooledRelay, Kit) {
    let (listener, kit) = kit();
    let relay = TestRelay::spawn_streams(listener, RelayIdentity::for_tree(&kit.tree), config);
    (relay, kit)
}

/// A pool of `conns` connections and one dial at once on `f`.
fn narrow_pool(
    f: &Kit,
    limiter: &Arc<EstablishLimiter>,
    gate: &Arc<WorkGate>,
    conns: usize,
) -> Arc<FlowPool> {
    pool_of(
        f,
        limiter,
        gate,
        unpinned(),
        Limits {
            pool_conns: conns,
            pool_dials: 1,
            ..Limits::default()
        },
    )
}

/// S16i-2: the streams a connection takes at once follow the relay's
/// SETTINGS_MAX_CONCURRENT_STREAMS as of its first 200 (`stream_cap`), and
/// `STREAMS_BEFORE_SETTINGS` before it.
#[test]
fn stream_cap_follows_advertised_settings() {
    for (advertised, expected) in [(Some(128), 62), (Some(32), 30), (Some(16), 14), (None, 62)] {
        let (relay, f) = pooled_with(PoolConfig {
            max_concurrent_streams: advertised,
            ..PoolConfig::default()
        });
        let gate = WorkGate::new();
        let limiter = limiter();
        f.runtime.block_on(async {
            let conn = f.dial(&loopback(), &limiter, &gate).await.unwrap();
            assert_eq!(conn.stream_cap(), STREAMS_BEFORE_SETTINGS, "{advertised:?}");
            let carrier = conn.open_carrier(&f.crypto).await.unwrap();
            assert_eq!(conn.stream_cap(), expected, "{advertised:?}");
            drop(carrier);
        });
        // On a pool of one connection, every live flow up to the cap shares
        // it: past the 30 taken before the relay's SETTINGS were known.
        let pool = narrow_pool(&f, &limiter, &gate, 1);
        let flows = expected.min(40);
        let held = f.runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(60), async {
                let mut held = Vec::new();
                for _ in 0..flows {
                    held.push(open_flow(&pool, &f.crypto, &limiter).await);
                }
                held
            })
            .await
            .unwrap()
        });
        let views = pool.views();
        assert_eq!(views.len(), 1, "{views:?}");
        assert_eq!(views[0].stream_cap, expected, "{advertised:?}");
        assert_eq!(views[0].streams, flows, "{advertised:?}");
        // Never past what the relay's own H2 admits: no REFUSED_STREAM.
        let refused = u32::from(h2::Reason::REFUSED_STREAM);
        assert!(relay
            .connection(1)
            .resets(false)
            .iter()
            .all(|(_, reason)| *reason != refused));
        assert_eq!(relay.connection(1).max_concurrent_streams(), flows);
        f.runtime.block_on(async {
            for flow in held {
                end(flow).await;
            }
        });
        assert_eq!(relay.strikes(), 0);
    }
}

/// S16i-2: a SETTINGS that lowers the relay's limit mid-connection is read
/// at the next 200: that connection takes no stream past it less the
/// margin, the next flows go on a new one, and no stream is refused.
#[test]
fn settings_lowered_mid_connection_stops_new_slots() {
    let (relay, f) = pooled_with(PoolConfig {
        settings_injection: true,
        ..PoolConfig::default()
    });
    let gate = WorkGate::new();
    let limiter = limiter();
    let pool = narrow_pool(&f, &limiter, &gate, 2);
    let mut held = f.runtime.block_on(async {
        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(open_flow(&pool, &f.crypto, &limiter).await);
        }
        held
    });
    assert_eq!(pool.views()[0].stream_cap, 30);
    relay.advertise_streams(0, 8);
    // The client ACKed it (the relay's H2 never saw that ACK).
    let acked = || {
        relay
            .connection(0)
            .frames()
            .iter()
            .filter(|frame| frame.from_client && frame.kind == frame_type::SETTINGS)
            .filter(|frame| frame.is_ack())
            .count()
    };
    assert!(wait_until(Duration::from_secs(2), || acked() >= 2));
    // Bounded: a stream past the client's lowered limit would queue in h2
    // for ever rather than fail.
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(20), async {
            for _ in 0..8 {
                held.push(open_flow(&pool, &f.crypto, &limiter).await);
            }
        })
        .await
        .expect("a flow queued past the lowered stream limit")
    });
    let views = pool.views();
    assert_eq!(views.len(), 2, "{views:?}");
    assert_eq!(views[0].stream_cap, 6, "{views:?}");
    assert_eq!(views[0].streams, 6, "{views:?}");
    assert_eq!(views[1].stream_cap, 30, "{views:?}");
    assert_eq!(views[1].streams, 6, "{views:?}");
    assert_eq!(relay.connection(0).max_concurrent_streams(), 6);
    // No stream was refused, either side.
    let refused = u32::from(h2::Reason::REFUSED_STREAM);
    for conn in 0..2 {
        let stats = relay.connection(conn);
        for from_client in [false, true] {
            assert!(
                stats
                    .resets(from_client)
                    .iter()
                    .all(|(_, reason)| *reason != refused),
                "{conn} {from_client}"
            );
        }
    }
    f.runtime.block_on(async {
        for flow in held {
            end(flow).await;
        }
    });
    assert_eq!(relay.strikes(), 0);
}

/// S16i-2: a relay that advertises 2 streams leaves a connection a cap of
/// 0 after its probe's 200: it takes no further stream and drains, and the
/// next flow dials a new connection.
#[test]
fn stream_cap_zero_drains_connection() {
    let (relay, f) = pooled_with(PoolConfig {
        max_concurrent_streams: Some(2),
        ..PoolConfig::default()
    });
    let gate = WorkGate::new();
    let limiter = limiter();
    let pool = narrow_pool(&f, &limiter, &gate, 1);
    let first = f.runtime.block_on(open_flow(&pool, &f.crypto, &limiter));
    assert_eq!(first.slot.conn_id(), 0);
    assert_eq!(pool.views()[0].stream_cap, 0);
    // Its probe runs on; the connection takes no stream beside it, and no
    // longer counts against the pool's one connection.
    let second = f.runtime.block_on(open_flow(&pool, &f.crypto, &limiter));
    assert_eq!(second.slot.conn_id(), 1);
    let views = pool.views();
    assert_eq!(views[0].phase, Phase::Draining, "{views:?}");
    assert_eq!(views[0].streams, 1, "{views:?}");
    assert_eq!(relay.conns(), 2);
    assert_eq!(relay.connection(0).max_concurrent_streams(), 1);
    assert_eq!(relay.connection(1).max_concurrent_streams(), 1);
    f.runtime.block_on(async {
        end(first).await;
        end(second).await;
    });
    // The drained connection closes once its last stream ended.
    assert!(wait_until(Duration::from_secs(2), || pool
        .views()
        .iter()
        .all(|view| view.id != 0)));
    assert_eq!(relay.strikes(), 0);
}

/// S16i-2: a connection's stream cap bounds its probe slot, its handshake
/// slots, the slots it offers once its probe returns, and whether a slot
/// reserved before the cap fell still fits.
#[test]
fn stream_cap_bounds_slots_capacity_and_fits() {
    let (_listener, f) = kit();
    let gate = WorkGate::new();
    let limiter = limiter();
    let pool = pool_of(&f, &limiter, &gate, unpinned(), Limits::default());
    let limits = Limits::default();
    f.runtime.block_on(async {
        let (conn, _sender, _cut, _relay) = unrecorded_conn(&gate).await;
        let fresh = pool.insert_for_test(conn, Phase::Probing, (0, 0));
        let (conn, _sender, _cut, _relay) = unrecorded_conn(&gate).await;
        let probing = pool.insert_for_test(conn, Phase::Probing, (1, 0));
        let (conn, _sender, _cut, _relay) = unrecorded_conn(&gate).await;
        let open = pool.insert_for_test(conn, Phase::Open, (0, 5));
        let now = Instant::now();
        let set = |id: u64, cap: usize| {
            pool.conn_for_test(id)
                .unwrap()
                .stream_cap
                .store(cap, Ordering::SeqCst);
        };
        {
            let mut state = pool.lock();
            assert_eq!(state.entry(fresh).unwrap().free(&limits, now), 1);
            // S16j-1: its free probe, then H_CONN once that returns.
            assert_eq!(
                state.entry(fresh).unwrap().capacity(&limits, now),
                1 + H_CONN
            );
            assert_eq!(state.entry(probing).unwrap().capacity(&limits, now), H_CONN);
            assert_eq!(state.entry(open).unwrap().free(&limits, now), H_CONN);
        }
        // A cap of 0 leaves no probe and no slot once the probe returns; a
        // cap at the live streams leaves no handshake slot.
        set(fresh, 0);
        set(probing, 0);
        set(open, 5);
        {
            let mut state = pool.lock();
            assert_eq!(state.entry(fresh).unwrap().free(&limits, now), 0);
            assert_eq!(state.entry(fresh).unwrap().capacity(&limits, now), 0);
            assert_eq!(state.entry(probing).unwrap().capacity(&limits, now), 0);
            assert_eq!(state.entry(open).unwrap().free(&limits, now), 0);
        }
        set(open, 6);
        assert_eq!(pool.lock().entry(open).unwrap().free(&limits, now), 1);
        // A cap of 0 drains the connection at the next look.
        let generation = pool.pins.generation();
        pool.refresh(&mut pool.lock(), now, generation, limiter.wake_generation());
        let views = pool.views();
        let phase = |id: u64| views.iter().find(|view| view.id == id).unwrap().phase;
        assert_eq!(phase(fresh), Phase::Draining, "{views:?}");
        assert_eq!(phase(probing), Phase::Draining, "{views:?}");
        assert_eq!(phase(open), Phase::Open, "{views:?}");
    });
    // A slot reserved before the relay lowered its limit no longer fits
    // once its connection holds more streams than its cap.
    let (relay, f) = pooled();
    let gate = WorkGate::new();
    let limiter = self::limiter();
    let pool = narrow_pool(&f, &limiter, &gate, 1);
    let flows = f.runtime.block_on(async {
        vec![
            open_flow(&pool, &f.crypto, &limiter).await,
            open_flow(&pool, &f.crypto, &limiter).await,
        ]
    });
    let conn = pool.conn_for_test(flows[0].slot.conn_id()).unwrap();
    let mode = PoolMode::default();
    assert!(flows.iter().all(|flow| flow.slot.fits(mode)));
    conn.stream_cap.store(1, Ordering::SeqCst);
    assert!(flows.iter().all(|flow| !flow.slot.fits(mode)));
    conn.stream_cap.store(2, Ordering::SeqCst);
    assert!(flows.iter().all(|flow| flow.slot.fits(mode)));
    conn.stream_cap.store(stream_cap(32), Ordering::SeqCst);
    f.runtime.block_on(async {
        for flow in flows {
            end(flow).await;
        }
    });
    assert_eq!(relay.strikes(), 0);
}

// ---- S16j-1: flow establishment under the post-connect burst ----

/// A current-thread runtime: the woken waiters run only when the test task
/// yields, so a release and a new arrival meet in a known order.
fn one_thread() -> Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// One connection with one handshake slot.
fn one_slot() -> Limits {
    Limits {
        pool_conns: 1,
        pool_dials: 1,
        h_conn: 1,
        ..Limits::default()
    }
}

type Grants = tokio::sync::mpsc::UnboundedSender<(usize, StreamSlot)>;

/// A flow `tag` that reserves a stream within `budget` and hands its slot
/// over; queued once `queued` flows wait.
async fn queue_flow(
    pool: &Arc<FlowPool>,
    tag: usize,
    granted: &Grants,
    queued: usize,
) -> tokio::task::JoinHandle<io::Result<()>> {
    let (pool_, granted) = (pool.clone(), granted.clone());
    let waiter = tokio::spawn(async move {
        let slot = pool_.reserve(Instant::now() + FLOW_BUDGET).await?;
        let _ = granted.send((tag, slot));
        Ok(())
    });
    while pool.queue().0 != queued {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    waiter
}

#[test]
fn waiters_take_slots_in_arrival_order() {
    let (_listener, f) = kit();
    let gate = WorkGate::new();
    let limiter = limiter();
    let pool = pool_of(&f, &limiter, &gate, unpinned(), one_slot());
    one_thread().block_on(async {
        let (conn, _sender, _cut, _relay) = unrecorded_conn(&gate).await;
        let id = pool.insert_for_test(conn, Phase::Open, (0, 1));
        // The one handshake slot, held.
        let mut held = pool.reserve(Instant::now() + FLOW_BUDGET).await.unwrap();
        assert_eq!(held.conn_id(), id);
        let (granted, mut grants) = tokio::sync::mpsc::unbounded_channel();
        let mut waiters = Vec::new();
        for tag in 0..4 {
            waiters.push(queue_flow(&pool, tag, &granted, tag + 1).await);
        }
        // The third leaves (its application gave up): the fourth moves up.
        waiters[2].abort();
        assert!(
            wait_for(Duration::from_secs(2), || pool.queue().0 == 3).await,
            "a cancelled waiter kept its ticket"
        );
        let mut order = Vec::new();
        for _ in 0..3 {
            // Its handshake returns: the one slot is free again.
            held.handshake_done(true);
            let (tag, slot) = tokio::time::timeout(Duration::from_secs(2), grants.recv())
                .await
                .expect("a free slot went to no waiter")
                .unwrap();
            order.push(tag);
            held = slot;
        }
        assert_eq!(order, [0, 1, 3]);
        assert_eq!(pool.queue(), (0, 0));
    });
    assert_eq!(pool.stats().dials, 0);
}

#[test]
fn a_new_arrival_does_not_barge_past_queued_waiters() {
    let (_listener, f) = kit();
    let gate = WorkGate::new();
    let limiter = limiter();
    let pool = pool_of(&f, &limiter, &gate, unpinned(), one_slot());
    one_thread().block_on(async {
        let (conn, _sender, _cut, _relay) = unrecorded_conn(&gate).await;
        pool.insert_for_test(conn, Phase::Open, (0, 1));
        let mut held = pool.reserve(Instant::now() + FLOW_BUDGET).await.unwrap();
        let (granted, mut grants) = tokio::sync::mpsc::unbounded_channel();
        let _waiter = queue_flow(&pool, 0, &granted, 1).await;
        // The slot frees, and a new flow looks before the woken waiter runs.
        held.handshake_done(true);
        let barged =
            tokio::time::timeout(Duration::ZERO, pool.reserve(Instant::now() + FLOW_BUDGET)).await;
        assert!(barged.is_err(), "a new arrival took an older waiter's slot");
        let (tag, _slot) = grants.recv().await.unwrap();
        assert_eq!(tag, 0);
        assert_eq!(pool.queue(), (0, 0));
    });
}

#[test]
fn a_waiter_without_establish_time_leaves_as_pool_wait_without_a_slot() {
    let (_listener, f) = kit();
    let gate = WorkGate::new();
    let limiter = limiter();
    let pool = pool_of(&f, &limiter, &gate, unpinned(), one_slot());
    // The in-memory connection's round trip is zero: the floor is its least.
    let floor = establish_floor(Duration::ZERO);
    assert_eq!(floor, Duration::from_millis(250));
    // Three round trips: the 200, the inner handshake, the Open status.
    assert_eq!(establish_floor(DEFAULT_RTT), Duration::from_millis(510));
    f.runtime.block_on(async {
        let (conn, _sender, _cut, _relay) = unrecorded_conn(&gate).await;
        pool.insert_for_test(conn, Phase::Open, (0, 1));
        // A free slot, but too little time to establish on it: refused at
        // once, the slot untaken.
        let started = Instant::now();
        let refused = pool
            .reserve(started + floor - Duration::from_millis(50))
            .await
            .map(|_| ())
            .unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::TimedOut);
        assert!(!is_dial_failed(&refused) && !is_permit_wait(&refused));
        assert!(started.elapsed() < Duration::from_millis(50));
        let views = pool.views();
        assert_eq!((views[0].establishing, views[0].streams), (0, 1));
        // A waiter whose time runs below the floor leaves then, not at its
        // deadline.
        let held = pool.reserve(Instant::now() + FLOW_BUDGET).await.unwrap();
        let started = Instant::now();
        let left = Duration::from_millis(300);
        let refused = pool
            .reserve(started + floor + left)
            .await
            .map(|_| ())
            .unwrap_err();
        let waited = started.elapsed();
        assert_eq!(refused.kind(), io::ErrorKind::TimedOut);
        assert!(
            waited >= left - Duration::from_millis(5) && waited < left + floor / 2,
            "{waited:?}"
        );
        assert_eq!(pool.queue(), (0, 0));
        drop(held);
    });
    assert_eq!(pool.stats().dials, 0);
}

#[test]
fn a_lazy_dials_probe_goes_to_the_queue_head() {
    let limits = Limits {
        pool_conns: 2,
        pool_dials: 1,
        ..Limits::default()
    };
    // A connection whose probe is in flight offers H_CONN once it returns:
    // H_CONN waiters wait for it, and the next one dials.
    let (relay, _link, f) = linked();
    let gate = WorkGate::new();
    let limiter = limiter();
    let pool = pool_of(&f, &limiter, &gate, unpinned(), limits);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            let (conn, _sender, _cut, _relay) = unrecorded_conn(&gate).await;
            pool.insert_for_test(conn, Phase::Probing, (1, 0));
            let (granted, mut grants) = tokio::sync::mpsc::unbounded_channel();
            let mut waiters = Vec::new();
            for tag in 0..=H_CONN {
                waiters.push(queue_flow(&pool, tag, &granted, tag + 1).await);
            }
            assert_eq!(pool.queue(), (H_CONN + 1, 1));
            // The last flow's dial joins: its probe goes to the first.
            let (tag, slot) = grants.recv().await.unwrap();
            assert_eq!((tag, slot.conn_id()), (0, 1));
            assert!(
                wait_for(Duration::from_secs(1), || pool.queue() == (H_CONN, 0)).await,
                "{:?}",
                pool.queue()
            );
            assert!(grants.try_recv().is_err());
            drop(slot);
            for waiter in waiters {
                waiter.abort();
            }
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.conns(), 1);
    assert_eq!(pool.stats().dials, 1);
    // The dialer's own dial failure is still its own refusal.
    let (_relay, _link, f) = linked_with(PoolConfig {
        silent_from: Some(0),
        ..PoolConfig::default()
    });
    let gate = WorkGate::new();
    let limiter = self::limiter();
    let pool = pool_of(&f, &limiter, &gate, unpinned(), limits);
    f.runtime.block_on(async {
        let (conn, _sender, _cut, _relay) = unrecorded_conn(&gate).await;
        pool.insert_for_test(conn, Phase::Probing, (1, 0));
        let (granted, _grants) = tokio::sync::mpsc::unbounded_channel();
        let mut waiters = Vec::new();
        for tag in 0..H_CONN {
            waiters.push(queue_flow(&pool, tag, &granted, tag + 1).await);
        }
        let deadline =
            Instant::now() + establish_floor(Duration::ZERO) + Duration::from_millis(400);
        let failed = pool.reserve(deadline).await.map(|_| ()).unwrap_err();
        assert!(is_dial_failed(&failed), "{failed:?}");
        assert_eq!(pool.queue(), (H_CONN, 0));
        for waiter in waiters {
            waiter.abort();
        }
    });
}

#[test]
fn a_dialing_waiter_holds_back_no_one() {
    // The oldest waiter dials (slowly); a slot that frees meanwhile on
    // another connection goes to the next waiter, not held for the dialer.
    let (relay, _link, f) = linked_with(PoolConfig {
        setup: Duration::from_millis(500),
        ..PoolConfig::default()
    });
    let gate = WorkGate::new();
    let limiter = limiter();
    let limits = Limits {
        pool_conns: 2,
        pool_dials: 1,
        h_conn: 1,
        ..Limits::default()
    };
    let pool = pool_of(&f, &limiter, &gate, unpinned(), limits);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            let (conn, _sender, _cut, _relay) = unrecorded_conn(&gate).await;
            let open = pool.insert_for_test(conn, Phase::Open, (0, 1));
            let mut held = pool.reserve(Instant::now() + FLOW_BUDGET).await.unwrap();
            let (granted, mut grants) = tokio::sync::mpsc::unbounded_channel();
            let dialer = queue_flow(&pool, 0, &granted, 1).await;
            assert!(wait_for(Duration::from_secs(1), || pool.queue() == (1, 1)).await);
            let waiter = queue_flow(&pool, 1, &granted, 2).await;
            held.handshake_done(true);
            let (tag, slot) = tokio::time::timeout(Duration::from_millis(200), grants.recv())
                .await
                .expect("the free slot waited for the dialer")
                .unwrap();
            assert_eq!((tag, slot.conn_id()), (1, open));
            // The dial joins: its probe is the dialer's, now the oldest.
            let (tag, probe) = grants.recv().await.unwrap();
            assert_eq!(tag, 0);
            assert_ne!(probe.conn_id(), open);
            drop((held, slot, probe));
            let _ = (dialer.await, waiter.await);
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.conns(), 1);
}

#[test]
fn the_youngest_waiter_dials() {
    // Two flows wait through a pause of the pool's dials; once it ends, the
    // younger dials, so the older still takes the next free slot.
    let (relay, _link, f) = linked_with(PoolConfig {
        setup: Duration::from_millis(500),
        ..PoolConfig::default()
    });
    let gate = WorkGate::new();
    let limiter = limiter();
    let limits = Limits {
        pool_conns: 2,
        pool_dials: 1,
        h_conn: 1,
        ..Limits::default()
    };
    let pool = pool_of(&f, &limiter, &gate, unpinned(), limits);
    one_thread().block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            let (conn, _sender, _cut, _relay) = unrecorded_conn(&gate).await;
            let open = pool.insert_for_test(conn, Phase::Open, (0, 1));
            let mut held = pool.reserve(Instant::now() + FLOW_BUDGET).await.unwrap();
            pool.lock().dial_pause = Some(Instant::now() + Duration::from_millis(200));
            let (granted, mut grants) = tokio::sync::mpsc::unbounded_channel();
            let older = queue_flow(&pool, 0, &granted, 1).await;
            let younger = queue_flow(&pool, 1, &granted, 2).await;
            assert_eq!(pool.queue(), (2, 0));
            assert!(wait_for(Duration::from_secs(1), || pool.queue() == (2, 1)).await);
            held.handshake_done(true);
            let (tag, slot) = tokio::time::timeout(Duration::from_millis(200), grants.recv())
                .await
                .expect("the free slot went to no waiter")
                .unwrap();
            assert_eq!((tag, slot.conn_id()), (0, open));
            let (tag, probe) = grants.recv().await.unwrap();
            assert_eq!(tag, 1);
            assert_ne!(probe.conn_id(), open);
            drop((held, slot, probe));
            let _ = (older.await, younger.await);
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.conns(), 1);
}

#[test]
fn predial_probe_goes_to_the_oldest_waiter() {
    // The v21 cold echo: the first flow after Running arrives while the
    // pre-dials are in flight, then more flows; the first is served first.
    let (relay, _link, f) = linked_with(PoolConfig {
        setup: Duration::from_millis(300),
        ..PoolConfig::default()
    });
    let gate = WorkGate::new();
    let limiter = limiter();
    let pool = pool_of(&f, &limiter, &gate, unpinned(), Limits::default());
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            let prewarm = tokio::spawn({
                let pool = pool.clone();
                async move { pool.prewarm().await }
            });
            assert!(wait_for(Duration::from_secs(1), || pool.queue().1 == PREWARM_CONNS).await);
            let (granted, mut grants) = tokio::sync::mpsc::unbounded_channel();
            let mut waiters = Vec::new();
            for tag in 0..5 {
                waiters.push(queue_flow(&pool, tag, &granted, tag + 1).await);
            }
            let (first, slot) = grants.recv().await.unwrap();
            let (second, other) = grants.recv().await.unwrap();
            assert_eq!((first, second), (0, 1));
            assert_ne!(slot.conn_id(), other.conn_id());
            // No dial of their own: both rode the pre-dials.
            assert_eq!(pool.stats().dials, PREWARM_CONNS);
            drop((slot, other));
            for waiter in waiters {
                waiter.abort();
            }
            let prewarmed = prewarm.await.unwrap();
            assert!(
                prewarmed
                    .iter()
                    .all(|prewarm| matches!(prewarm, Prewarm::Dialed(_))),
                "{prewarmed:?}"
            );
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.conns(), PREWARM_CONNS);
}

#[test]
fn fifo_bounds_the_order_of_a_burst() {
    // Flows that arrive one after another on the default pool at the
    // design RTT are served in arrival order, but for the slots free at
    // once and the waiters that dial meanwhile: the oldest first.
    const FLOWS: usize = 40;
    let (relay, link, f) = linked();
    let gate = WorkGate::new();
    let limiter = limiter();
    let pool = pool_of(&f, &limiter, &gate, unpinned(), Limits::default());
    let order = Arc::new(Mutex::new(Vec::new()));
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(60), async {
            let mut flows = tokio::task::JoinSet::new();
            for tag in 0..FLOWS {
                let (flow_pool, flow_order) = (pool.clone(), order.clone());
                let hold = link.rtt() * 2;
                flows.spawn(async move {
                    let (pool, order) = (flow_pool, flow_order);
                    let mut slot = pool.reserve(Instant::now() + FLOW_BUDGET).await.unwrap();
                    order.lock().unwrap().push(tag);
                    // Its 200 and inner handshake, then it lives on.
                    let _ = slot.sent(slot.conn().srtt());
                    tokio::time::sleep(hold).await;
                    slot.handshake_done(true);
                    slot
                });
                while pool.queue().0 + order.lock().unwrap().len() < tag + 1 {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
            let held = flows.join_all().await;
            assert_eq!(held.len(), FLOWS);
        })
        .await
        .unwrap();
    });
    let order = order.lock().unwrap().clone();
    assert_eq!(order[0], 0, "{order:?}");
    // A flow is overtaken only by the flows that took the slots free with
    // it, or while it dialed (each dial takes one RTT of TCP and TLS and
    // one of H2): at most the pool's handshake slots, twice.
    let slack = 2 * POOL_CONNS * H_CONN;
    for (granted, tag) in order.iter().enumerate() {
        assert!(granted.abs_diff(*tag) <= slack, "{order:?}");
    }
    assert!(relay.conns() <= POOL_CONNS);
}

#[test]
fn proven_session_opens_new_connections_after_their_first_200() {
    let (relay, _link, f) = linked();
    let gate = WorkGate::new();
    let limiter = EstablishLimiter::for_test(20, 3, AUTH_BACKOFF);
    let limits = Limits {
        pool_conns: 2,
        pool_dials: 1,
        ..Limits::default()
    };
    let pool = pool_of(&f, &limiter, &gate, unpinned(), limits);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            // Connection 0 authenticates a stream: the pool is proven.
            assert!(!pool.proven());
            let first = open_flow(&pool, &f.crypto, &limiter).await;
            assert!(pool.proven());
            // Every handshake slot of it held: the next flow dials
            // connection 1 and takes its probe.
            let deadline = Instant::now() + FLOW_BUDGET;
            let mut held = Vec::new();
            for _ in 0..H_CONN {
                held.push(pool.reserve(deadline).await.unwrap());
            }
            assert!(held.iter().all(|slot| slot.conn_id() == 0));
            let mut probe = pool.reserve(deadline).await.unwrap();
            assert_eq!(probe.conn_id(), 1);
            // Before its 200 it takes no second stream.
            let early = tokio::time::timeout(Duration::from_millis(100), pool.reserve(deadline));
            assert!(early.await.is_err());
            // Its 200; its inner handshake not yet run.
            let _ = probe.sent(probe.conn().srtt());
            let carrier = probe.conn().open_carrier(&f.crypto).await.unwrap();
            pool.carrier_answered();
            // It takes its whole `H_CONN` at once, and no more.
            let mut second = Vec::new();
            for _ in 1..H_CONN {
                let slot = tokio::time::timeout(Duration::from_millis(500), pool.reserve(deadline))
                    .await
                    .expect("a proven pool's connection took no second stream after its 200")
                    .unwrap();
                assert_eq!(slot.conn_id(), 1);
                second.push(slot);
            }
            let views = pool.views();
            assert_eq!(
                (views[1].phase, views[1].establishing),
                (Phase::Probing, H_CONN),
                "{views:?}"
            );
            let full = tokio::time::timeout(Duration::from_millis(100), pool.reserve(deadline));
            assert!(full.await.is_err());
            // The probe completes: the connection opens, and nothing struck.
            let mut inner = open_echo(&f.crypto, carrier).await;
            probe.handshake_done(true);
            echo(&mut inner, b"probe").await;
            assert_eq!(pool.views()[1].phase, Phase::Open);
            drop((held, second, inner, probe));
            end(first).await;
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.strikes(), 0);
    assert_eq!(limiter.auth_failures(), 0);
}

#[test]
fn unproven_session_keeps_one_probe() {
    let (relay, _link, f) = linked();
    let gate = WorkGate::new();
    let limiter = EstablishLimiter::for_test(20, 3, AUTH_BACKOFF);
    let pool = pool_of(&f, &limiter, &gate, unpinned(), one_conn());
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            let deadline = Instant::now() + FLOW_BUDGET;
            let mut probe = pool.reserve(deadline).await.unwrap();
            let _ = probe.sent(probe.conn().srtt());
            let carrier = probe.conn().open_carrier(&f.crypto).await.unwrap();
            pool.carrier_answered();
            assert!(probe.conn().answered());
            // No stream of the session authenticated: its 200 alone takes
            // no second stream onto the connection.
            assert!(!pool.proven());
            let second = tokio::time::timeout(Duration::from_millis(300), pool.reserve(deadline));
            assert!(second.await.is_err());
            assert_eq!(pool.views()[0].streams, 1);
            // Its probe authenticates: then the connection fills.
            let inner = open_echo(&f.crypto, carrier).await;
            probe.handshake_done(true);
            let second = tokio::time::timeout(Duration::from_millis(300), pool.reserve(deadline))
                .await
                .expect("an open connection took no second stream")
                .unwrap();
            assert_eq!(second.conn_id(), 0);
            drop((second, inner, probe));
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.strikes(), 0);
}

#[test]
fn a_pool_proven_by_its_sessions_ack_ramps_its_first_connection() {
    // S16m, v23 13.73 s: two probing connections carried one stream each
    // while 45 flows waited, although the session's own PolicyAck had
    // authenticated it at the relay before any flow. A pool proven by that
    // ACK (on the present wake generation) takes a second stream onto its
    // first connection at its first 200; one proven on an older wake
    // generation, or marked once a connection is in it, still probes alone.
    let (relay, _link, f) = linked();
    let gate = WorkGate::new();
    let limiter = EstablishLimiter::for_test(20, 3, AUTH_BACKOFF);
    let wake = limiter.wake_generation();
    for (case, proof, ramps) in [
        ("present wake", Some(wake), true),
        ("older wake", Some(wake + 1), false),
        ("after a connection", None, false),
    ] {
        let pool = pool_of(&f, &limiter, &gate, unpinned(), one_conn());
        if let Some(proof) = proof {
            pool.prove_by_session_ack(proof);
        }
        f.runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(30), async {
                let deadline = Instant::now() + FLOW_BUDGET;
                let mut probe = pool.reserve(deadline).await.unwrap();
                if proof.is_none() {
                    pool.prove_by_session_ack(wake);
                }
                let _ = probe.sent(probe.conn().srtt());
                let carrier = probe.conn().open_carrier(&f.crypto).await.unwrap();
                pool.carrier_answered();
                let second =
                    tokio::time::timeout(Duration::from_millis(300), pool.reserve(deadline)).await;
                assert_eq!(second.is_ok(), ramps, "{case}");
                if ramps {
                    let views = pool.views();
                    assert_eq!(
                        (views.len(), views[0].phase, views[0].establishing),
                        (1, Phase::Probing, 2),
                        "{case}: {views:?}"
                    );
                } else {
                    assert_eq!(pool.views()[0].streams, 1, "{case}");
                }
                let inner = open_echo(&f.crypto, carrier).await;
                probe.handshake_done(true);
                drop((second, inner, probe));
            })
            .await
            .unwrap();
        });
    }
    assert_eq!(relay.strikes(), 0);
}

#[test]
fn a_ramped_slot_granted_past_idle_reuse_is_kept_once_its_permit_comes() {
    // S16j-1: on a proven pool a Probing connection whose first 200 arrived
    // past IDLE_REUSE of its TCP connect, its probe not yet authenticated,
    // offers a second handshake slot. The flow that took it judges it, once
    // its permit came, under the limits the pool granted it by: kept, not
    // given back and taken again (each take another stream of its budget,
    // the flow's ticket lost) until its probe authenticates.
    let (_listener, f) = kit();
    let gate = WorkGate::new();
    let limiter = limiter();
    let pool = pool_of(&f, &limiter, &gate, unpinned(), Limits::default());
    f.runtime.block_on(async {
        let (conn, _sender, _cut, _relay) = unrecorded_conn(&gate).await;
        conn.answered.store(true, Ordering::SeqCst);
        // Its probe taken and sent, its 200 in; none authenticated on it.
        let id = pool.insert_for_test(conn, Phase::Probing, (1, 0));
        {
            let mut state = pool.lock();
            state.proven = Some(0);
            let entry = state.entry(id).unwrap();
            entry.anchor = Instant::now()
                .checked_sub(IDLE_REUSE + Duration::from_millis(100))
                .unwrap();
            assert!(entry.idle_age(Instant::now()) > IDLE_REUSE);
        }
        let mode = limiter.pool_mode();
        let slot = pool.reserve(Instant::now() + FLOW_BUDGET).await.unwrap();
        assert_eq!(slot.conn_id(), id);
        assert!(slot.reusable(mode));
        assert!(slot.fits(mode));
        assert_eq!(pool.views()[0].opened, 2);
        // Unproven, the same slot is past reuse and given back.
        pool.lock().proven = None;
        assert!(!slot.reusable(mode));
        // So it is after a strike, which unproves the pool on this look.
        pool.lock().proven = Some(0);
        assert!(slot.reusable(mode));
        assert_eq!(limiter.strike(), 1);
        assert!(!slot.reusable(limiter.pool_mode()));
        assert!(!pool.proven());
        drop(slot);
    });
}

#[test]
fn a_strike_or_a_capacity_refusal_unproves_the_pool() {
    let (_listener, f) = kit();
    let gate = WorkGate::new();
    let limiter = limiter();
    let pool = pool_of(&f, &limiter, &gate, unpinned(), Limits::default());
    f.runtime.block_on(async {
        let (conn, _sender, _cut, _relay) = unrecorded_conn(&gate).await;
        pool.insert_for_test(conn, Phase::Probing, (0, 0));
        let deadline = Instant::now() + FLOW_BUDGET;
        let mut probe = pool.reserve(deadline).await.unwrap();
        probe.handshake_done(true);
        assert!(pool.proven());
        // The relay refused a stream after its 200: unproven.
        let refused = pool.reserve(deadline).await.unwrap();
        refused.capacity_refused();
        assert!(!pool.proven());
        drop(refused);
        // Proven again by the next authenticated stream; then a strike: the
        // next look finds the pool unproven.
        let mut next = pool.reserve(deadline).await.unwrap();
        next.handshake_done(true);
        assert!(pool.proven());
        assert_eq!(limiter.strike(), 1);
        let look = pool.reserve(deadline).await.unwrap();
        assert!(!pool.proven());
        // Under the strike a Probing connection's 200 takes it no further
        // stream: one inner handshake per connection.
        assert_eq!(pool.views()[0].h_conn, 1);
        drop((look, next, probe));
    });
}

#[test]
fn a_new_handshake_avoids_a_connection_whose_handshake_is_slow() {
    let (_listener, f) = kit();
    let gate = WorkGate::new();
    let limiter = limiter();
    let pool = pool_of(&f, &limiter, &gate, unpinned(), Limits::default());
    f.runtime.block_on(async {
        let (conn, _sender, _cut, _relay) = unrecorded_conn(&gate).await;
        let quiet = pool.insert_for_test(conn, Phase::Open, (0, 3));
        let (conn, _sender2, _cut2, _relay2) = unrecorded_conn(&gate).await;
        let busy = pool.insert_for_test(conn, Phase::Open, (1, 3));
        let slow = Instant::now()
            .checked_sub(slow_after(Duration::ZERO) + Duration::from_millis(50))
            .unwrap();
        pool.lock().entry(quiet).unwrap().inflight.push(slow);
        // The fewest establishing, but its oldest handshake is slow: the
        // other connection takes the stream.
        let slot = pool.reserve(Instant::now() + FLOW_BUDGET).await.unwrap();
        assert_eq!(slot.conn_id(), busy);
        drop(slot);
        // A young handshake in flight is no reason to avoid it.
        pool.lock().entry(quiet).unwrap().inflight = vec![Instant::now()];
        let slot = pool.reserve(Instant::now() + FLOW_BUDGET).await.unwrap();
        assert_eq!(slot.conn_id(), quiet);
        // A sent slot is in flight on its connection until its handshake.
        let mut slot = slot;
        let _ = slot.sent(Duration::ZERO);
        assert_eq!(pool.lock().entry(quiet).unwrap().inflight.len(), 2);
        slot.handshake_done(false);
        assert_eq!(pool.lock().entry(quiet).unwrap().inflight.len(), 1);
    });
    assert_eq!(slow_after(Duration::ZERO), HS_FLOOR);
    assert_eq!(slow_after(DEFAULT_RTT), DEFAULT_RTT * 4);
}

#[test]
fn pooled_socket_sets_notsent_lowat_and_a_large_connection_window() {
    // Written out so that a changed constant fails here. v34: the
    // connection window is 15 MiB (v33: 8 MiB), the stream window as
    // announced stays 128 KiB, and a stream grows to at most 1 MiB from a
    // 7 MiB session budget.
    assert_eq!(NOTSENT_LOWAT, 16 * 1024);
    assert_eq!(CONN_WINDOW, 15 * 1024 * 1024);
    assert_eq!(STREAM_WINDOW, 128 * 1024);
    assert_eq!(crate::stream_window::STREAM_WINDOW_MAX, 1024 * 1024);
    assert_eq!(crate::stream_window::GROW_BUDGET, 7 * 1024 * 1024);
    assert_eq!(SEND_BUFFER, 128 * 1024);
    // `settings_tap` reads the connection window off the wire.
    let (_relay, f) = pooled();
    let gate = WorkGate::new();
    let limiter = limiter();
    f.runtime.block_on(async {
        let conn = f.dial(&loopback(), &limiter, &gate).await.unwrap();
        assert_eq!(conn.notsent_lowat_for_test().unwrap(), NOTSENT_LOWAT);
        drop(conn);
    });
}

#[test]
fn a_connection_full_of_unread_streams_still_carries_a_new_handshake() {
    // S16j-1: on a relay whose SETTINGS allow the pool's stream cap (62),
    // more streams stop reading than a 4 MiB connection window holds (32),
    // each with its whole stream window unread. A new stream on the same
    // connection still gets its ServerHello and its Open status: the
    // connection window covers every stream it may hold.
    // v34 (T5): the first `GROWN` of them read until their windows grew,
    // then stopped, each leaving its grown window unread, as many grown as
    // the session's budget covers (on this Mac 8 at 1 MiB, 6.1 MiB of the
    // budget): the connection window, every stream's window and the whole
    // budget beside them, still covers them all.
    const UNREAD: usize = 40;
    const GROWN: usize = 10;
    const _: () = assert!(UNREAD * STREAM_WINDOW as usize > 4 * 1024 * 1024);
    const _: () = assert!(UNREAD < STREAMS_CAP);
    // A real 20 ms link gives the time-based growth rule its measurement
    // history before the unchanged 4 MiB read cap. A fast loopback can
    // exhaust that cap before even the first 40 ms measurement finishes.
    let (relay, _link, f) = linked_with_rtt(
        PoolConfig {
            max_concurrent_streams: Some(128),
            h2_connection_window: 16 * 1024 * 1024,
            ..PoolConfig::default()
        },
        crate::stream_window::RTT_FLOOR,
    );
    let gate = WorkGate::new();
    let limiter = EstablishLimiter::for_test(20, 3, AUTH_BACKOFF);
    let pool = pool_of(&f, &limiter, &gate, adaptive(), one_conn());
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(40), async {
            let mut unread = Vec::new();
            let (stalled, mut stalls) = tokio::sync::mpsc::unbounded_channel();
            for at in 0..UNREAD {
                let mut flow = open_flow(&pool, &f.crypto, &limiter).await;
                if at < GROWN {
                    let (stats, stalled) = (relay.connection(0), stalled.clone());
                    unread.push(tokio::spawn(async move {
                        grow_then_stall(flow, &stats, stalled).await;
                    }));
                    continue;
                }
                unread.push(tokio::spawn(async move {
                    let bulk = vec![0x5a; STREAM_WINDOW as usize * 3 / 2];
                    let _ = flow.inner.write_all(&bulk).await;
                    let _ = flow.inner.flush().await;
                    std::future::pending::<()>().await;
                    drop(flow);
                }));
            }
            for _ in 0..GROWN {
                stalls.recv().await.unwrap();
            }
            assert_eq!(pool.views()[0].stream_cap, STREAMS_CAP);
            // The echoes fill each stream's window.
            tokio::time::sleep(Duration::from_secs(2)).await;
            // As many grew as the budget covers, and they stopped reading
            // with their windows grown.
            let window = pool.window().stats();
            println!("grown then stalled: {window:?}");
            let next = tokio::time::timeout(HS_WATCHDOG, open_flow(&pool, &f.crypto, &limiter))
                .await
                .expect("a new stream waited behind unread streams");
            assert_eq!(next.slot.conn_id(), 0);
            end(next).await;
            // The guard above holds on b9adfe19 too; that the grown case was
            // exercised is v34's: each grew by its first step (at the 20 ms
            // floor on loopback, up to 1 MiB) and stopped before that step
            // was judged.
            assert!(window.grown >= 2, "{window:?}");
            assert!(window.used <= crate::stream_window::GROW_BUDGET);
            assert!(window.high > STREAM_WINDOW, "{window:?}");
            for task in unread {
                task.abort();
            }
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.conns(), 1);
    assert_eq!(relay.strikes(), 0);
}

#[test]
fn unread_streams_never_hold_back_a_new_streams_handshake() {
    // Live flows whose readers are slow: the relay echoes more than a
    // stream window to each, and none is read. A new stream on the same
    // connection still gets its 200, its ServerHello and its Open status.
    // Five unread windows are past v21's 512 KiB connection window, where
    // the new stream waited for ever (at four, the window's last few KiB,
    // handshake bytes already read, still carried a ServerHello).
    const UNREAD: usize = 5;
    const _: () = assert!(UNREAD * STREAM_WINDOW as usize > 524_288);
    const _: () = assert!(UNREAD * (STREAM_WINDOW as usize) < CONN_WINDOW as usize);
    let (relay, _link, f) = linked_with(PoolConfig {
        h2_connection_window: 4 * 1024 * 1024,
        ..PoolConfig::default()
    });
    let gate = WorkGate::new();
    let limiter = EstablishLimiter::for_test(20, 3, AUTH_BACKOFF);
    let pool = pool_of(&f, &limiter, &gate, unpinned(), one_conn());
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(40), async {
            let mut unread = Vec::new();
            for _ in 0..UNREAD {
                let mut flow = open_flow(&pool, &f.crypto, &limiter).await;
                unread.push(tokio::spawn(async move {
                    let bulk = vec![0x5a; STREAM_WINDOW as usize * 3 / 2];
                    let _ = flow.inner.write_all(&bulk).await;
                    let _ = flow.inner.flush().await;
                    std::future::pending::<()>().await;
                    flow
                }));
            }
            // The echoes fill each stream's window.
            tokio::time::sleep(Duration::from_secs(2)).await;
            let next = tokio::time::timeout(HS_WATCHDOG, open_flow(&pool, &f.crypto, &limiter))
                .await
                .expect("a new stream waited behind unread streams");
            assert_eq!(next.slot.conn_id(), 0);
            end(next).await;
            for task in unread {
                task.abort();
            }
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.conns(), 1);
    assert_eq!(relay.strikes(), 0);
}

#[test]
fn tcp_acks_record_the_send_buffer() {
    // S16j-1: a socket whose peer reads nothing fills its send buffer; the
    // stall watchdog's read of its ACKs records those bytes (`pool_detail
    // sndq_kib`).
    use std::io::Write;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (_peer, _) = listener.accept().unwrap();
    client.set_nonblocking(true).unwrap();
    let chunk = vec![0x5a; 64 * 1024];
    let mut written = 0u64;
    while written < 64 * 1024 * 1024 {
        match client.write(&chunk) {
            Ok(wrote) => written += u64::try_from(wrote).unwrap(),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("{error}"),
        }
    }
    let live = Arc::new(Liveness::new(Duration::ZERO));
    live.written.store(written, Ordering::SeqCst);
    let acks = TcpAcks::new(client.as_raw_fd(), live.clone());
    let queued = live.queued.load(Ordering::Relaxed);
    assert!(queued > 0 && queued <= written, "{queued} of {written}");
    assert_eq!(acks.acked, written - queued);
}

#[test]
fn pool_detail_reports_the_oldest_wait_and_handshake_times() {
    // The percentiles of the kept handshake times, nearest rank.
    let mut state = PoolState::default();
    assert_eq!((state.handshake_ms(50), state.handshake_ms(90)), (0, 0));
    for ms in (1..=10u64).rev().map(|tenth| tenth * 100) {
        state.sample_handshake(Duration::from_millis(ms));
    }
    assert_eq!(
        (state.handshake_ms(50), state.handshake_ms(90)),
        (600, 1_000)
    );
    for _ in 0..HS_SAMPLES {
        state.sample_handshake(Duration::from_millis(7));
    }
    assert_eq!(state.hs_samples.len(), HS_SAMPLES);
    assert_eq!(state.handshake_ms(90), 7);
    // A flow's real handshake: its 200 and its inner mTLS, two round trips.
    let (relay, link, f) = linked();
    let gate = WorkGate::new();
    let limiter = limiter();
    let pool = pool_of(&f, &limiter, &gate, unpinned(), one_slot());
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            let flow = open_flow(&pool, &f.crypto, &limiter).await;
            let snapshot = pool.snapshot_for_test();
            let rtt = u64::try_from(link.rtt().as_millis()).unwrap();
            assert!(
                snapshot.hs_p50_ms >= 2 * rtt - 20 && snapshot.hs_p50_ms < 6 * rtt,
                "{snapshot:?}"
            );
            assert_eq!(snapshot.hs_p50_ms, snapshot.hs_p90_ms);
            // The one slot held: a waiter's age.
            let held = pool.reserve(Instant::now() + FLOW_BUDGET).await.unwrap();
            let (granted, _grants) = tokio::sync::mpsc::unbounded_channel();
            let waiter = queue_flow(&pool, 0, &granted, 1).await;
            tokio::time::sleep(Duration::from_millis(300)).await;
            let snapshot = pool.snapshot_for_test();
            assert_eq!(snapshot.waiting, 1);
            assert!(snapshot.oldest_ms >= 290, "{snapshot:?}");
            waiter.abort();
            drop(held);
            end(flow).await;
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.strikes(), 0);
}

#[test]
fn an_open_never_completes_after_its_flows_connect_deadline() {
    let (relay, link, f) = linked();
    let gate = WorkGate::new();
    let limiter = EstablishLimiter::for_test(20, 3, AUTH_BACKOFF);
    // One inner handshake at a time on the one connection.
    let limits = Limits {
        h_conn: 1,
        ..one_conn()
    };
    let pool = pool_of(&f, &limiter, &gate, unpinned(), limits);
    let (services, settings) = services_of(&pool);
    let budget = Duration::from_millis(settings.connect_timeout_ms);
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            let siblings = live_flows(&services, &settings, SIBLINGS).await;
            // A flow stalled in its inner handshake holds the one slot for
            // its watchdog; the next waits for it, then its target hangs.
            let stalled_at = relay.streams();
            relay.at(stalled_at, StreamFault::StallHandshake);
            relay.at(stalled_at + 1, StreamFault::HangTarget);
            let (_stalled_app, stalled) = tcp_flow(&services, &settings).await;
            relay
                .wait_step(
                    stalled_at,
                    StreamStep::HandshakeStalled,
                    Duration::from_secs(5),
                )
                .await
                .unwrap();
            let started = std::time::Instant::now();
            let (_app, late) = tcp_flow(&services, &settings).await;
            assert!(late.await.unwrap().is_err());
            let took = started.elapsed();
            // Its status bound, from its request, ends well past its
            // flow's connect budget: it gave up at that budget instead.
            let requested = client_request(&relay, &link, stalled_at + 1) - started;
            assert!(
                requested + STATUS_BUDGET > budget + Duration::from_millis(500),
                "{requested:?}"
            );
            assert!(
                took >= budget - Duration::from_millis(100)
                    && took <= budget + Duration::from_millis(150),
                "{took:?}"
            );
            assert_eq!(limiter.refusals(Refusal::StatusBudget), 1);
            assert!(stalled.await.unwrap().is_err());
            close_all(siblings).await.unwrap();
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.strikes(), 0);
    assert_eq!(limiter.flow_refusals(), 0);
}

/// v22 review: a capacity refusal narrows its connection to one inner
/// handshake for the slots already reserved on it too. With `H_CONN` 4 a
/// connection holds up to three more reserved slots when one of its
/// streams is refused after its 200; one whose flow waited for its permit
/// past the refusal fits only once it is the connection's one handshake,
/// and the connection runs `H_CONN` again once the pause ends.
#[test]
fn a_capacity_refusal_narrows_slots_reserved_before_it() {
    let (_listener, f) = kit();
    let gate = WorkGate::new();
    let limiter = limiter();
    let pause = Duration::from_millis(400);
    let limits = Limits {
        capacity_pause: pause,
        ..Limits::default()
    };
    let pool = pool_of(&f, &limiter, &gate, unpinned(), limits);
    f.runtime.block_on(async {
        let (conn, _sender, _cut, _relay) = unrecorded_conn(&gate).await;
        let id = pool.insert_for_test(conn, Phase::Open, (0, 1));
        let view = |pool: &FlowPool| {
            let views = pool.views();
            let view = views.iter().find(|view| view.id == id).unwrap();
            (view.establishing, view.h_conn)
        };
        let mode = limiter.pool_mode();
        let deadline = Instant::now() + FLOW_BUDGET;
        let mut slots = Vec::new();
        for _ in 0..H_CONN {
            let slot = pool.reserve(deadline).await.unwrap();
            assert_eq!(slot.conn_id(), id);
            slots.push(slot);
        }
        assert!(slots.iter().all(|slot| slot.fits(mode)));
        assert_eq!(view(&pool), (H_CONN, H_CONN));
        // The relay at its handshake cap refuses one after its 200, in the
        // order `PreparedCrypto` reports it.
        let mut refused = slots.remove(0);
        refused.handshake_done(false);
        refused.capacity_refused();
        assert_eq!(view(&pool), (H_CONN - 1, 1));
        // The others, reserved before, run no handshake beside each other.
        assert_eq!(slots.len(), H_CONN - 1);
        assert!(slots.iter().all(|slot| !slot.fits(mode)));
        // Given back but one: that one is the connection's one handshake.
        drop(slots.split_off(1));
        assert_eq!(view(&pool), (1, 1));
        assert!(slots[0].fits(mode));
        {
            let mut state = pool.lock();
            let limits = pool.limits_now(&mut state, mode);
            assert_eq!(state.entry(id).unwrap().free(&limits, Instant::now()), 0);
        }
        // Past the pause the connection takes `H_CONN` again, and every
        // slot on it fits.
        tokio::time::sleep(pause + Duration::from_millis(50)).await;
        for _ in 1..H_CONN {
            let slot = pool.reserve(Instant::now() + FLOW_BUDGET).await.unwrap();
            assert_eq!(slot.conn_id(), id);
            slots.push(slot);
        }
        assert_eq!(view(&pool), (H_CONN, H_CONN));
        assert!(slots.iter().all(|slot| slot.fits(mode)));
        drop((slots, refused));
    });
    assert_eq!(limiter.strikes(), 0);
}

// ---- v34: the adaptive stream window and bulk-aware placement ----

/// The most a growing test flow reads before it stops anyway.
const GROW_READ_MAX: usize = 4 * 1024 * 1024;

/// A flow that echoes bulk data and reads it until the relay's credit on
/// its stream is above the initial window (its window grew) or it read
/// `GROW_READ_MAX`, then stops reading, still writing: the echo fills its
/// window unread. Signals `stalled` when it stopped, then holds the flow.
async fn grow_then_stall(
    flow: Flow,
    stats: &crate::test_relay::pool::ConnStats,
    stalled: tokio::sync::mpsc::UnboundedSender<()>,
) {
    let Flow {
        inner,
        slot,
        stream_id,
        _live,
    } = flow;
    let (mut read, mut write) = tokio::io::split(inner);
    let writer = tokio::spawn(async move {
        let chunk = vec![0x5a; 64 * 1024];
        loop {
            if write.write_all(&chunk).await.is_err() || write.flush().await.is_err() {
                break;
            }
        }
        std::future::pending::<()>().await;
        drop(write);
    });
    let mut buffer = vec![0; 64 * 1024];
    let mut got = 0;
    while stats.credit_high(stream_id) <= i64::from(STREAM_WINDOW) && got < GROW_READ_MAX {
        match read.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(read) => got += read,
        }
    }
    let _ = stalled.send(());
    std::future::pending::<()>().await;
    drop((read, writer, slot, _live));
}

/// A loopback target that writes `bytes` to every connection, then its FIN,
/// as a download's server does (`Target::Socket`).
fn bulk_target(bytes: usize) -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                return;
            };
            thread::spawn(move || {
                let chunk = vec![0x5a; 64 * 1024];
                let mut left = bytes;
                while left > 0 {
                    let take = left.min(chunk.len());
                    if std::io::Write::write_all(&mut stream, &chunk[..take]).is_err() {
                        return;
                    }
                    left -= take;
                }
                let _ = stream.shutdown(std::net::Shutdown::Write);
                let mut sink = [0u8; 1024];
                while matches!(std::io::Read::read(&mut stream, &mut sink), Ok(read) if read > 0) {}
            });
        }
    });
    address
}

/// Reads `flow` to its end, returning the bytes and whether its connection
/// (`conn`) counted as carrying a bulk flow while it ran.
async fn read_bulk(flow: &mut Flow, conn: &PooledConn) -> (usize, bool) {
    let mut buffer = vec![0; 64 * 1024];
    let (mut got, mut bulk) = (0, false);
    loop {
        match flow.inner.read(&mut buffer).await {
            Ok(0) => return (got, bulk),
            Ok(read) => got += read,
            Err(error) => panic!("{error} after {got}"),
        }
        bulk |= conn.window().bulk(Instant::now());
    }
}

#[test]
fn a_keeping_up_stream_grows_its_window_past_the_initial() {
    // T1: one download at the design RTT (170 ms), read as fast as it
    // comes. The relay's credit on its stream goes above the 128 KiB the
    // stream starts with (SETTINGS) and never above 1 MiB; its connection
    // counts as carrying a bulk flow; its end logs its window. On b9adfe19
    // the credit never exceeds 131072.
    use crate::stream_window::{GROW_BUDGET, STREAM_WINDOW_MAX};
    const BYTES: usize = 12 * 1024 * 1024;
    let target = bulk_target(BYTES);
    let (relay, _link, f) = linked_with(PoolConfig {
        target: crate::test_relay::Target::Socket(target),
        ..PoolConfig::default()
    });
    let gate = WorkGate::new();
    let limiter = limiter();
    let pool = pool_of(&f, &limiter, &gate, adaptive(), one_conn());
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(60), async {
            let mut flow = open_flow(&pool, &f.crypto, &limiter).await;
            let conn = pool.conn_for_test(flow.slot.conn_id()).unwrap();
            let (got, bulk) = read_bulk(&mut flow, &conn).await;
            assert_eq!(got, BYTES);
            let stats = relay.connection(0);
            let credit = stats.credit_high(flow.stream_id);
            assert!(credit > i64::from(STREAM_WINDOW), "{credit}");
            assert!(credit <= i64::from(STREAM_WINDOW_MAX), "{credit}");
            assert!(bulk);
            let window = pool.window().stats();
            assert!(window.high > STREAM_WINDOW, "{window:?}");
            assert!(window.high <= STREAM_WINDOW_MAX, "{window:?}");
            assert!(window.high_used <= GROW_BUDGET, "{window:?}");
            let id = flow.slot.conn_id();
            drop(flow);
            // Its budget is back once it is gone.
            assert_eq!(pool.window().stats().used, 0);
            let lines = limiter.flow_log_lines();
            let bulk: Vec<&String> = lines
                .iter()
                .filter(|line| line.starts_with("flow_bulk "))
                .collect();
            assert_eq!(bulk.len(), 1, "{lines:?}");
            // Its stream's bytes: the download and the inner TLS around it.
            let field = |name: &str| -> usize {
                let token = bulk[0].split(' ').find(|token| token.starts_with(name));
                token.unwrap()[name.len()..].parse().unwrap()
            };
            assert!(
                bulk[0].starts_with(&format!("flow_bulk conn:{id} ")),
                "{bulk:?}"
            );
            let kib = field("kib:");
            assert!(
                (BYTES / 1024..=BYTES / 1024 * 102 / 100).contains(&kib),
                "{bulk:?}"
            );
            assert!(field("ms:") > 0, "{bulk:?}");
            let win_kib = field("win_kib:");
            assert!(win_kib > 128 && win_kib <= 1024, "{bulk:?}");
            for event in ["pool_window grown:", "pool_rtt conn:"] {
                assert!(
                    lines.iter().any(|line| line.starts_with(event)),
                    "{event} {lines:?}"
                );
            }
            for line in lines
                .iter()
                .filter(|line| line.starts_with("pool_") || line.starts_with("flow_bulk"))
            {
                let mut fields = line.split(' ');
                let event = fields.next().unwrap();
                let fields: Vec<&str> = fields.collect();
                assert!(crate::apple::stable_fields(event, &fields), "{line}");
            }
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.strikes(), 0);
}

#[test]
fn the_default_window_holds_a_keeping_up_stream_at_the_initial_window() {
    // T29 (v36, outcome `fixed`): T1's download on a fresh epoch, which runs
    // the product default (no window-policy option): the relay's credit
    // never exceeds the 128 KiB of SETTINGS, no step is taken and no budget
    // is charged, while the measurements, the bulk mark and the flow's
    // `flow_bulk` line (at 128 KiB) stay as in the v35 window.
    const BYTES: usize = 12 * 1024 * 1024;
    let target = bulk_target(BYTES);
    let (relay, _link, f) = linked_with(PoolConfig {
        target: crate::test_relay::Target::Socket(target),
        ..PoolConfig::default()
    });
    let gate = WorkGate::new();
    let limiter = limiter();
    let pool = pool_of(&f, &limiter, &gate, unpinned(), one_conn());
    assert_eq!(
        pool.window().mode(),
        crate::configuration::WindowMode::Fixed
    );
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(60), async {
            let mut flow = open_flow(&pool, &f.crypto, &limiter).await;
            let conn = pool.conn_for_test(flow.slot.conn_id()).unwrap();
            let (got, bulk) = read_bulk(&mut flow, &conn).await;
            assert_eq!(got, BYTES);
            let credit = relay.connection(0).credit_high(flow.stream_id);
            assert!(credit <= i64::from(STREAM_WINDOW), "{credit}");
            assert!(bulk);
            let window = pool.window().stats();
            assert_eq!(window.grown, 0, "{window:?}");
            assert_eq!(window.high_used, 0, "{window:?}");
            assert!(window.high <= STREAM_WINDOW, "{window:?}");
            drop(flow);
            let lines = limiter.flow_log_lines();
            assert!(
                lines.iter().any(|line| line == "pool_policy mode:fixed"),
                "{lines:?}"
            );
            let bulk: Vec<&String> = lines
                .iter()
                .filter(|line| line.starts_with("flow_bulk "))
                .collect();
            assert_eq!(bulk.len(), 1, "{lines:?}");
            assert!(
                bulk[0].split(' ').any(|token| token == "win_kib:128"),
                "{bulk:?}"
            );
        })
        .await
        .unwrap();
    });
    assert_eq!(relay.strikes(), 0);
}

#[test]
fn a_stalled_or_slow_reader_never_grows_and_holds_at_most_its_initial_window() {
    // T3, a guard that holds on b9adfe19 too: a download whose reader never
    // reads, and one whose reader takes 4 KiB every 50 ms (80 KiB/s), on
    // loopback (the rule's round-trip floor). Neither grows: the relay's
    // credit stays within 131072, so neither holds more unread.
    use crate::stream_window::STREAM_WINDOW_MAX;
    let target = bulk_target(STREAM_WINDOW_MAX as usize * 4);
    let (relay, f) = pooled_with(PoolConfig {
        target: crate::test_relay::Target::Socket(target),
        ..PoolConfig::default()
    });
    let gate = WorkGate::new();
    let limiter = limiter();
    let pool = pool_of(&f, &limiter, &gate, adaptive(), one_conn());
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            let stalled = open_flow(&pool, &f.crypto, &limiter).await;
            let mut slow = open_flow(&pool, &f.crypto, &limiter).await;
            let mut buffer = vec![0; 4 * 1024];
            let mut got = 0;
            for _ in 0..40 {
                got += slow.inner.read(&mut buffer).await.unwrap();
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            assert!(got > 0);
            let stats = relay.connection(0);
            for flow in [&stalled, &slow] {
                let credit = stats.credit_high(flow.stream_id);
                assert!(credit <= i64::from(STREAM_WINDOW), "{credit}");
            }
            let window = pool.window().stats();
            assert_eq!(
                (window.grown, window.used, window.high),
                (0, 0, STREAM_WINDOW)
            );
            drop((stalled, slow));
        })
        .await
        .unwrap();
    });
}

#[test]
fn a_new_flow_goes_to_a_connection_without_a_bulk_flow() {
    // T9: two connections equal in slowness and handshakes in flight; the
    // one carrying a download has fewer live streams (idle background
    // flows sit on the other). A new flow goes to the one without the
    // download; b9adfe19 put it beside the download. Handshakes in flight
    // still come first, and a download that ended counts no more.
    use crate::stream_window::BULK_HOLD;
    let (_listener, f) = kit();
    let gate = WorkGate::new();
    let limiter = limiter();
    let pool = pool_of(&f, &limiter, &gate, unpinned(), Limits::default());
    f.runtime.block_on(async {
        let mut held = Vec::new();
        let (conn, sender, cut, relay) = unrecorded_conn(&gate).await;
        let download = pool.insert_for_test(conn, Phase::Open, (0, 3));
        held.push((sender, cut, relay));
        let (conn, sender, cut, relay) = unrecorded_conn(&gate).await;
        let background = pool.insert_for_test(conn, Phase::Open, (0, 9));
        held.push((sender, cut, relay));
        pool.conn_for_test(download)
            .unwrap()
            .window()
            .mark_bulk(Instant::now());
        let first = pool.reserve(Instant::now() + FLOW_BUDGET).await.unwrap();
        assert_eq!(first.conn_id(), background);
        // A handshake in flight there: the download's connection, with
        // none, takes the next.
        let second = pool.reserve(Instant::now() + FLOW_BUDGET).await.unwrap();
        assert_eq!(second.conn_id(), download);
        drop((first, second));
        // A connection whose download ended more than BULK_HOLD ago, with
        // the fewest streams, takes the next again.
        let (conn, sender, cut, relay) = unrecorded_conn(&gate).await;
        let ended = pool.insert_for_test(conn, Phase::Open, (0, 1));
        held.push((sender, cut, relay));
        let long_ago = Instant::now()
            .checked_sub(BULK_HOLD + Duration::from_millis(100))
            .unwrap();
        let conn = pool.conn_for_test(ended).unwrap();
        conn.window().mark_bulk(long_ago);
        assert!(!conn.window().bulk(Instant::now()));
        let third = pool.reserve(Instant::now() + FLOW_BUDGET).await.unwrap();
        assert_eq!(third.conn_id(), ended);
        drop(third);
        drop(held);
    });
    assert_eq!(pool.stats().dials, 0);
}

// ---- v35: queue-aware placement and its lines (RED over a9dadf6e's pool;
// ---- only a9dadf6e's API) ----

/// v35: makes `conn` queued as of now: a stream on it releases 16 KiB
/// every 50 ms for a second while the relay holds 128 KiB of its credit, so
/// at the connection's 180 ms round trip each measurement's credit-loop
/// delay is about 270 ms, its rate (320 KiB/s) bulk, and the stream uses
/// its window (59 KiB per round trip, at least a quarter of 128 KiB).
fn queue_on(pool: &FlowPool, conn: &PooledConn) {
    let rtt = Duration::from_millis(180);
    conn.window().sample(rtt, rtt);
    releases_on(pool, conn);
}

/// v35: a stream on `conn` releases 16 KiB every 50 ms for a second while
/// the relay holds 128 KiB of its credit; true when its connection carries
/// a bulk flow afterwards.
fn releases_on(pool: &FlowPool, conn: &PooledConn) {
    use crate::stream_window::WindowPolicy;
    use aegis_core::h2_stream::{RecvWindow, RecvWindowPolicy};
    let now = Instant::now();
    let start = now.checked_sub(Duration::from_secs(1)).unwrap();
    let mut policy = WindowPolicy::new(pool.window().clone(), conn.window().clone(), start);
    let window = RecvWindow {
        target: STREAM_WINDOW,
        peer: STREAM_WINDOW,
        unreleased: 0,
    };
    for k in 0..=20u32 {
        assert_eq!(
            policy.on_release(16_384, window, start + Duration::from_millis(50) * k),
            None
        );
    }
    assert!(conn.window().bulk(now));
}

#[test]
fn a_new_flow_goes_to_a_bulk_connection_without_a_standing_queue() {
    // T21 (RED): two Open connections both carrying a download; on the one
    // with fewer streams the download's credit-loop delay stands at about
    // 430 ms. New flows go to the other while it has a free slot (a9dadf6e
    // put the first beside the queue: fewer streams); once it has none the
    // queued one still takes a flow; and once the queue is older than
    // BULK_HOLD, v34's order applies again.
    use crate::stream_window::BULK_HOLD;
    let (_listener, f) = kit();
    let gate = WorkGate::new();
    let limiter = limiter();
    let pool = pool_of(&f, &limiter, &gate, unpinned(), Limits::default());
    f.runtime.block_on(async {
        let mut held = Vec::new();
        let (conn, sender, cut, relay) = unrecorded_conn(&gate).await;
        let queued = pool.insert_for_test(conn, Phase::Open, (0, 2));
        held.push((sender, cut, relay));
        let (conn, sender, cut, relay) = unrecorded_conn(&gate).await;
        let clear = pool.insert_for_test(conn, Phase::Open, (0, 6));
        held.push((sender, cut, relay));
        pool.conn_for_test(clear)
            .unwrap()
            .window()
            .mark_bulk(Instant::now());
        queue_on(&pool, &pool.conn_for_test(queued).unwrap());
        let mut slots = Vec::new();
        for _ in 0..H_CONN {
            let slot = pool.reserve(Instant::now() + FLOW_BUDGET).await.unwrap();
            assert_eq!(slot.conn_id(), clear, "a flow beside a standing queue");
            slots.push(slot);
        }
        // The other has no free slot: the queued one takes the next.
        let slot = pool.reserve(Instant::now() + FLOW_BUDGET).await.unwrap();
        assert_eq!(slot.conn_id(), queued);
        slots.push(slot);
        drop(slots);
        // Past BULK_HOLD neither is bulk nor queued: the fewest streams.
        tokio::time::sleep(BULK_HOLD + Duration::from_millis(200)).await;
        let slot = pool.reserve(Instant::now() + FLOW_BUDGET).await.unwrap();
        assert_eq!(slot.conn_id(), queued);
        drop(slot);
        drop(held);
    });
    assert_eq!(pool.stats().dials, 0);
}

#[test]
fn a_source_limited_bulk_flow_does_not_mark_its_connection_queued() {
    // T21b (v35 review): the same releases at the 20 ms round-trip floor,
    // where 16 KiB per 50 ms is under a quarter of a 128 KiB window per
    // round trip: the stream under-used its window (the relay had nothing
    // more to send), so its idle credit, which Little's law reads as about
    // 430 ms of delay, is no queue. The connection is bulk but not queued,
    // and v34's order (the fewest streams) places the next flow there.
    let (_listener, f) = kit();
    let gate = WorkGate::new();
    let limiter = limiter();
    let pool = pool_of(&f, &limiter, &gate, unpinned(), Limits::default());
    f.runtime.block_on(async {
        let mut held = Vec::new();
        let (conn, sender, cut, relay) = unrecorded_conn(&gate).await;
        let limited = pool.insert_for_test(conn, Phase::Open, (0, 2));
        held.push((sender, cut, relay));
        let (conn, sender, cut, relay) = unrecorded_conn(&gate).await;
        let other = pool.insert_for_test(conn, Phase::Open, (0, 6));
        held.push((sender, cut, relay));
        pool.conn_for_test(other)
            .unwrap()
            .window()
            .mark_bulk(Instant::now());
        let conn = pool.conn_for_test(limited).unwrap();
        releases_on(&pool, &conn);
        assert!(!conn.window().queued(Instant::now()));
        let slot = pool.reserve(Instant::now() + FLOW_BUDGET).await.unwrap();
        assert_eq!(slot.conn_id(), limited);
        drop(slot);
        drop(held);
    });
    assert_eq!(pool.stats().dials, 0);
}

#[test]
fn the_pool_logs_its_policy_and_the_flows_it_takes_on_a_queued_connection() {
    // T22 (RED): a pool logs `pool_policy mode:<mode>` once, as it is
    // built (the window harness's window_policy row reads it; v36: a fresh
    // epoch's mode is the default, fixed); and while
    // flows wait, `pool_take` counts the flows taken since its line before
    // and those taken on a queued connection, with the queued connections
    // among those taking streams. a9dadf6e logs neither.
    let (_listener, f) = kit();
    let gate = WorkGate::new();
    let limiter = limiter();
    let pool = pool_of(
        &f,
        &limiter,
        &gate,
        unpinned(),
        Limits {
            pool_conns: 2,
            pool_dials: 1,
            ..Limits::default()
        },
    );
    let lines = limiter.flow_log_lines();
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.starts_with("pool_policy "))
            .collect::<Vec<_>>(),
        ["pool_policy mode:fixed"],
        "{lines:?}"
    );
    f.runtime.block_on(async {
        let mut held = Vec::new();
        let (conn, sender, cut, relay) = unrecorded_conn(&gate).await;
        let queued = pool.insert_for_test(conn, Phase::Open, (H_CONN - 1, 2));
        held.push((sender, cut, relay));
        let (conn, sender, cut, relay) = unrecorded_conn(&gate).await;
        pool.insert_for_test(conn, Phase::Open, (H_CONN, 6));
        held.push((sender, cut, relay));
        queue_on(&pool, &pool.conn_for_test(queued).unwrap());
        // The only free slot is beside the queue.
        let slot = pool.reserve(Instant::now() + FLOW_BUDGET).await.unwrap();
        assert_eq!(slot.conn_id(), queued);
        // Every slot taken: the next flow waits, and the pool's state is
        // logged.
        let waited = tokio::time::timeout(
            Duration::from_millis(300),
            pool.reserve(Instant::now() + FLOW_BUDGET),
        )
        .await;
        assert!(waited.is_err());
        drop(slot);
        drop(held);
    });
    let lines = limiter.flow_log_lines();
    let takes: Vec<&String> = lines
        .iter()
        .filter(|line| line.starts_with("pool_take "))
        .collect();
    assert_eq!(
        takes,
        ["pool_take n:1 queued:1 conns_queued:1-2"],
        "{lines:?}"
    );
    for line in lines
        .iter()
        .filter(|line| line.starts_with("pool_take") || line.starts_with("pool_policy"))
    {
        let mut fields = line.split(' ');
        let event = fields.next().unwrap();
        let fields: Vec<&str> = fields.collect();
        assert!(crate::apple::stable_fields(event, &fields), "{line}");
    }
    assert_eq!(pool.stats().dials, 0);
}

#[test]
fn a_flow_pool_runs_the_window_mode_its_epoch_was_started_with() {
    // T25 (v35; v36, outcome `fixed`): an epoch whose start asked for the
    // v35 window (`adaptive`, a QA arm) builds every flow pool, its first
    // session's and a rebuilt session's (each session builds its own pool
    // from the epoch's pins), in Adaptive mode, each logging `pool_policy
    // mode:adaptive`; a fresh epoch's pools run the default, fixed.
    use crate::configuration::WindowMode;
    let (_listener, f) = kit();
    let gate = WorkGate::new();
    let limiter = limiter();
    let (pins, generation) = unpinned();
    assert_eq!(pins.window_mode(), WindowMode::Fixed);
    pins.set_window_mode(WindowMode::Adaptive);
    let first = pool_of(&f, &limiter, &gate, (pins.clone(), generation), one_conn());
    let rebuilt = pool_of(&f, &limiter, &gate, (pins.clone(), generation), one_conn());
    for pool in [&first, &rebuilt] {
        assert_eq!(pool.window().mode(), WindowMode::Adaptive);
    }
    assert_eq!(
        limiter
            .flow_log_lines()
            .iter()
            .filter(|line| line.starts_with("pool_policy "))
            .collect::<Vec<_>>(),
        ["pool_policy mode:adaptive", "pool_policy mode:adaptive"]
    );
    let fresh = pool_of(&f, &limiter, &gate, unpinned(), one_conn());
    assert_eq!(fresh.window().mode(), WindowMode::Fixed);
    assert_eq!(
        limiter.flow_log_lines().last().map(String::as_str),
        Some("pool_policy mode:fixed")
    );
}

/// v40 (CP-D3 M1): a PONG of the stall watchdog's PING at least the
/// policy's collapse threshold slow is the open session's throughput
/// collapse, recorded once per session; a faster one is nothing.
#[test]
fn a_slow_pong_is_the_open_sessions_throughput_collapse_once() {
    use crate::carrier_failover::{inspect, profile_identity, SessionCarriers};
    use aegis_core::brain::carrier_failover::{CarrierFailoverSettings, CarrierSignal, NetworkKey};
    let identity = profile_identity("flow-pool-collapse");
    let policy = CarrierFailoverSettings {
        collapse_rtt_ms: 200,
        ..CarrierFailoverSettings::default()
    };
    let carriers = SessionCarriers::plan(identity, Some(&policy), 2, NetworkKey::UNKNOWN).unwrap();
    let ticket = carriers.ticket(0).unwrap();
    let collapse = Collapse {
        ticket: ticket.clone(),
        rtt: ticket.collapse_rtt().unwrap(),
    };
    let last = || {
        inspect(identity, |controller| {
            controller.last_signal(NetworkKey::UNKNOWN, 0)
        })
        .unwrap()
    };
    // Before the session opened nothing is learned.
    collapse.observe(Duration::from_secs(1));
    assert_eq!(last(), None);
    ticket.opened();
    collapse.observe(Duration::from_millis(199));
    assert_eq!(last(), None);
    collapse.observe(Duration::from_millis(200));
    assert_eq!(last(), Some(CarrierSignal::ThroughputCollapse));
    // Once per session: a later freeze of the same session adds nothing.
    ticket.degraded(CarrierSignal::SessionFreeze);
    assert_eq!(last(), Some(CarrierSignal::ThroughputCollapse));
}
