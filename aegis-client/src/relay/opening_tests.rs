//! Loopback-only staged opening/lifetime regressions for WS and legacy TLS.

use super::super::{policy::RelaySessionProfile, RelaySessionCounters};
use super::*;
use aegis_core::tunnel::{
    encode_stream_frame, open_tunnel_request, read_stream_frame, seal_tunnel_response,
    TunnelResponse, MAX_TUNNEL_CONTROL_FRAME,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

const OPEN_MS: u64 = 3_000;
const WATCHDOG: Duration = Duration::from_secs(18);
const INITIAL: &[u8] = b"initial fixture payload";
const LATE: &[u8] = b"late fixture payload";

// Public static stages only; no target, credentials or arbitrary error text.
#[derive(Clone, Copy)]
#[repr(u32)]
enum RetryPhase {
    Started,
    FirstTcp,
    FirstTls,
    FirstConnect,
    ResetQueued,
    RetryTcp,
    RetryTls,
    RetryConnect,
    RetryOpen,
    FirstClosed,
    ServerClosed,
}
struct RetryWitness {
    phase: std::sync::atomic::AtomicU32,
    observed: std::sync::atomic::AtomicU32,
}
impl RetryWitness {
    fn new() -> Self {
        Self {
            phase: std::sync::atomic::AtomicU32::new(RetryPhase::Started as u32),
            observed: std::sync::atomic::AtomicU32::new(1),
        }
    }
    fn record(&self, phase: RetryPhase) {
        use std::sync::atomic::Ordering;
        self.observed.fetch_or(1 << phase as u32, Ordering::SeqCst);
        self.phase.store(phase as u32, Ordering::SeqCst);
    }
    fn saw(&self, phase: RetryPhase) -> bool {
        self.observed.load(std::sync::atomic::Ordering::SeqCst) & (1 << phase as u32) != 0
    }
    fn snapshot(&self) -> (u32, u32) {
        use std::sync::atomic::Ordering;
        (
            self.phase.load(Ordering::SeqCst),
            self.observed.load(Ordering::SeqCst),
        )
    }
}

// Keep one owned task runnable: an idle paused Tokio clock would auto-advance
// during actual TLS/H2 network readiness. Success aborts and joins the keeper;
// failure cancels this keeper and restores only this test runtime's clock.
struct FrozenClock {
    keeper: Option<tokio::task::JoinHandle<()>>,
}
impl FrozenClock {
    fn new() -> Self {
        tokio::time::pause();
        Self {
            keeper: Some(tokio::spawn(async {
                loop {
                    tokio::task::yield_now().await;
                }
            })),
        }
    }
    async fn finish(mut self) {
        let keeper = self.keeper.take().unwrap();
        keeper.abort();
        assert!(keeper.await.unwrap_err().is_cancelled());
    }
}
impl Drop for FrozenClock {
    fn drop(&mut self) {
        if let Some(keeper) = self.keeper.take() {
            keeper.abort();
        }
        tokio::time::resume();
    }
}

// Preserve the existing 18 s watchdog in native time while the production Tokio
// deadline is frozen. Every path wakes and joins this owned thread promptly.
struct NativeWatchdog {
    cancelled: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl NativeWatchdog {
    fn new() -> (Self, oneshot::Receiver<()>) {
        let deadline = std::time::Instant::now() + WATCHDOG;
        let cancelled = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let state = cancelled.clone();
        let (expired, receiver) = oneshot::channel();
        let thread = std::thread::spawn(move || {
            let (lock, changed) = &*state;
            let cancelled = lock.lock().unwrap_or_else(|p| p.into_inner());
            let (cancelled, timeout) = changed
                .wait_timeout_while(
                    cancelled,
                    deadline.saturating_duration_since(std::time::Instant::now()),
                    |cancelled| !*cancelled,
                )
                .unwrap_or_else(|p| p.into_inner());
            if timeout.timed_out() && !*cancelled {
                let _ = expired.send(());
            }
        });
        (
            Self {
                cancelled,
                thread: Some(thread),
            },
            receiver,
        )
    }
    fn cancel(&self) {
        let (lock, changed) = &*self.cancelled;
        *lock.lock().unwrap_or_else(|p| p.into_inner()) = true;
        changed.notify_one();
    }
    fn finish(mut self) {
        self.cancel();
        self.thread
            .take()
            .unwrap()
            .join()
            .expect("owned native watchdog joined");
    }
}
impl Drop for NativeWatchdog {
    fn drop(&mut self) {
        self.cancel();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RetryBarrierFailure {
    ReadyClosed,
    ClientTerminal { opening_elapsed: bool },
    ServerTerminal,
}
async fn retry_barrier(
    ready: &mut oneshot::Receiver<()>,
    client: &mut tokio::task::JoinHandle<anyhow::Result<()>>,
    server: &mut tokio::task::JoinHandle<()>,
) -> Result<(), RetryBarrierFailure> {
    tokio::select! {
        biased;
        result = client => Err(RetryBarrierFailure::ClientTerminal {
            opening_elapsed: matches!(result, Ok(Err(error)) if error.downcast_ref::<tokio::time::error::Elapsed>().is_some()),
        }),
        _ = server => Err(RetryBarrierFailure::ServerTerminal),
        ready = ready => ready.map_err(|_| RetryBarrierFailure::ReadyClosed),
    }
}

fn warm_native_roots() {
    // OS trust enumeration is synchronous and can be slow on a busy Darwin
    // host. Complete it outside network watchdogs; all handshakes still use
    // the production certificate verifier and the same opening timeout.
    static ROOTS: std::sync::Once = std::sync::Once::new();
    ROOTS.call_once(|| {
        super::super::tls_backend::load_roots(None).unwrap();
    });
}

#[derive(Clone, Copy, Debug)]
enum Carrier {
    Legacy,
    Http1,
    H2,
}

#[derive(Clone, Copy, Debug)]
enum Stage {
    Tls,
    Protocol,
    Headers,
    Ack,
}

struct Fixture {
    _dir: tempfile::TempDir,
    listener: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    settings: RelaySettings,
    carrier: Carrier,
}

impl Fixture {
    async fn new(carrier: Carrier) -> Self {
        // Warm cold synchronous OS trust enumeration before measuring network
        // opening, as in the existing gRPC fixture. Certificate checks remain real.
        warm_native_roots();
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, cert.pem()).unwrap();
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into(),
            )
            .unwrap();
        config.alpn_protocols = match carrier {
            Carrier::Legacy => vec![],
            Carrier::Http1 => vec![b"http/1.1".to_vec()],
            Carrier::H2 => vec![b"h2".to_vec()],
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let settings = RelaySettings {
            server: listener.local_addr().unwrap().to_string(),
            server_name: "localhost".into(),
            auth_token: "opening-fixture-only".into(),
            ca_cert: Some(ca),
            connect_timeout_ms: OPEN_MS,
            tls_backend: aegis_core::RelayTlsBackend::Rustls,
            ..Default::default()
        };
        Self {
            _dir: dir,
            listener,
            acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(config)),
            settings,
            carrier,
        }
    }

    async fn stall(&self, stage: Stage, ready: oneshot::Sender<()>) {
        let (mut tcp, _) = self.listener.accept().await.unwrap();
        if matches!(stage, Stage::Tls) {
            tcp.read_exact(&mut [0]).await.expect("actual TLS bytes");
            ready.send(()).unwrap();
            let _ = tokio::io::copy(&mut tcp, &mut tokio::io::sink()).await;
            return;
        }
        let mut tls = self.acceptor.accept(tcp).await.expect("real verified TLS");
        if matches!(stage, Stage::Protocol) {
            tls.read_exact(&mut [0]).await.expect("actual H2 preface");
            ready.send(()).unwrap();
            let _ = tokio::io::copy(&mut tls, &mut tokio::io::sink()).await;
            return;
        }
        if matches!((self.carrier, stage), (Carrier::Http1, Stage::Headers)) {
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(tls.read_u8().await.unwrap());
                assert!(request.len() < 8192);
            }
            assert!(request.starts_with(b"GET "));
            ready.send(()).unwrap();
            let mut extra = Vec::new();
            let _ = tls.read_to_end(&mut extra).await;
            assert!(extra.is_empty(), "no application bytes before Upgrade");
            return;
        }
        if matches!((self.carrier, stage), (Carrier::H2, Stage::Headers)) {
            let (request, respond, mut driver) = accept_h2(tls).await;
            let _driver = H2Driver(Some(driver.abort_handle()));
            ready.send(()).unwrap();
            let mut body = request.into_body();
            assert!(
                !matches!(body.data().await, Some(Ok(bytes)) if !bytes.is_empty()),
                "no application before CONNECT response"
            );
            drop(respond);
            (&mut driver).await.expect("H2 peer observed actual close");
            return;
        }
        if matches!(self.carrier, Carrier::Legacy) {
            #[cfg(not(feature = "legacy-challenge-v1"))]
            {
                let frame = read_stream_frame(&mut tls, MAX_TUNNEL_CONTROL_FRAME)
                    .await
                    .unwrap();
                validate_open(&frame, &self.settings);
                ready.send(()).unwrap();
                assert!(
                    !matches!(tls.read(&mut [0; 1024]).await, Ok(n) if n > 0),
                    "no payload before authenticated ack"
                );
                return;
            }
            #[cfg(feature = "legacy-challenge-v1")]
            {
                use aegis_core::tunnel::fresh_legacy::{KeyCandidate, ServerPending};
                let authority = ();
                let key = KeyCandidate {
                    authority: &authority,
                    secret: self.settings.auth_token.as_bytes(),
                    expires: None,
                };
                let open = read_stream_frame(&mut tls, MAX_TUNNEL_CONTROL_FRAME)
                    .await
                    .unwrap();
                let (challenge, pending) =
                    ServerPending::start(&open, &key, tokio::time::Instant::now() + WATCHDOG)
                        .unwrap();
                tls.write_all(&encode_stream_frame(&challenge))
                    .await
                    .unwrap();
                let proof = read_stream_frame(&mut tls, MAX_TUNNEL_CONTROL_FRAME)
                    .await
                    .unwrap();
                let authenticated = pending.authenticate(&proof, |_| true).unwrap();
                // Hold the consumed proof owner without releasing any Final.
                // The actual client must still bound this same opening or cancel it.
                ready.send(()).unwrap();
                assert!(
                    !matches!(tls.read(&mut [0; 1024]).await, Ok(n) if n > 0),
                    "no payload before authenticated ack"
                );
                drop(authenticated);
                return;
            }
        }
        let mut server = accept_ws(tls, self.carrier).await;
        let Message::Binary(frame) = server.ws.next().await.unwrap().unwrap() else {
            panic!("binary open");
        };
        validate_open(&frame, &self.settings);
        ready.send(()).unwrap();
        assert!(
            !matches!(server.ws.next().await, Some(Ok(Message::Binary(_)))),
            "no payload before authenticated ack"
        );
        server.finish().await;
    }

    async fn echo(&self, ready: oneshot::Sender<()>) {
        let (tcp, _) = self.listener.accept().await.unwrap();
        let mut tls = self.acceptor.accept(tcp).await.unwrap();
        let ack = seal_tunnel_response(
            &TunnelResponse {
                status: TunnelStatus::Ok,
                message: String::new(),
            },
            self.settings.auth_token.as_bytes(),
        )
        .unwrap();
        if matches!(self.carrier, Carrier::Legacy) {
            #[cfg(not(feature = "legacy-challenge-v1"))]
            {
                validate_open(
                    &read_stream_frame(&mut tls, MAX_TUNNEL_CONTROL_FRAME)
                        .await
                        .unwrap(),
                    &self.settings,
                );
                tls.write_all(&encode_stream_frame(&ack)).await.unwrap();
            }
            #[cfg(feature = "legacy-challenge-v1")]
            {
                use aegis_core::tunnel::fresh_legacy::{admit_raw, KeyCandidate};
                let authority = ();
                let keys = [KeyCandidate {
                    authority: &authority,
                    secret: self.settings.auth_token.as_bytes(),
                    expires: None,
                }];
                let admitted = admit_raw(
                    &mut tls,
                    &keys,
                    tokio::time::Instant::now() + WATCHDOG,
                    WATCHDOG,
                    |_| true,
                    |request, _| async move {
                        assert_eq!(request.host, "127.0.0.1");
                        assert_eq!(request.port, 43210);
                        Ok((
                            Some(()),
                            TunnelResponse {
                                status: TunnelStatus::Ok,
                                message: String::new(),
                            },
                        ))
                    },
                )
                .await
                .unwrap();
                assert_eq!(admitted, Some(()), "fresh proof and bound Ok Final");
            }
            let mut first = vec![0; INITIAL.len()];
            tls.read_exact(&mut first).await.unwrap();
            assert_eq!(first, INITIAL);
            tls.write_all(&first).await.unwrap();
            ready.send(()).unwrap();
            let mut late = vec![0; LATE.len()];
            tls.read_exact(&mut late).await.unwrap();
            assert_eq!(late, LATE);
            tls.write_all(&late).await.unwrap();
            tls.shutdown().await.unwrap();
            return;
        }
        let mut server = accept_ws(tls, self.carrier).await;
        let Message::Binary(frame) = server.ws.next().await.unwrap().unwrap() else {
            panic!("binary open");
        };
        validate_open(&frame, &self.settings);
        server.ws.send(Message::Binary(ack)).await.unwrap();
        let Message::Binary(first) = server.ws.next().await.unwrap().unwrap() else {
            panic!("first payload");
        };
        assert_eq!(first, INITIAL);
        server.ws.send(Message::Binary(first)).await.unwrap();
        ready.send(()).unwrap();
        let Message::Binary(late) = server.ws.next().await.unwrap().unwrap() else {
            panic!("late payload");
        };
        assert_eq!(late, LATE);
        server.ws.send(Message::Binary(late)).await.unwrap();
        assert!(matches!(
            server.ws.next().await,
            Some(Ok(Message::Close(_)))
        ));
        let _ = server.ws.flush().await;
        // WebSocket flush only queues H2 DATA. End the carrier explicitly so
        // dropping its handles cannot replace the final Close with RST_STREAM.
        server.ws.get_mut().shutdown().await.unwrap();
        server.finish().await;
    }
}

type ServerTls = tokio_rustls::server::TlsStream<TcpStream>;
type Ws = tokio_tungstenite::WebSocketStream<super::super::tls_backend::RelayTlsStream>;

async fn accept_h2(
    tls: ServerTls,
) -> (
    http::Request<h2::RecvStream>,
    h2::server::SendResponse<bytes::Bytes>,
    tokio::task::JoinHandle<()>,
) {
    let mut connection = h2::server::Builder::new()
        .enable_connect_protocol()
        .handshake(tls)
        .await
        .unwrap();
    let (request, respond) = connection.accept().await.unwrap().unwrap();
    assert_eq!(request.method(), http::Method::CONNECT);
    assert_eq!(request.headers()[http::header::SEC_WEBSOCKET_VERSION], "13");
    assert_eq!(
        request
            .extensions()
            .get::<h2::ext::Protocol>()
            .unwrap()
            .as_str(),
        "websocket"
    );
    let driver = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| connection.poll_closed(cx)).await;
    });
    (request, respond, driver)
}

struct ServerWs {
    ws: Ws,
    driver: Option<tokio::task::JoinHandle<()>>,
    _guard: Option<H2Driver>,
}

impl ServerWs {
    async fn finish(self) {
        drop(self.ws);
        if let Some(driver) = self.driver {
            driver.await.unwrap();
        }
    }
}

async fn accept_ws(tls: ServerTls, carrier: Carrier) -> ServerWs {
    if matches!(carrier, Carrier::H2) {
        let (request, mut respond, driver) = accept_h2(tls).await;
        let guard = H2Driver(Some(driver.abort_handle()));
        let send = respond
            .send_response(http::Response::new(()), false)
            .unwrap();
        let io: super::super::tls_backend::RelayTlsStream = Box::new(
            aegis_core::h2_stream::H2Stream::new(send, request.into_body()),
        );
        let ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
            io,
            tokio_tungstenite::tungstenite::protocol::Role::Server,
            None,
        )
        .await;
        ServerWs {
            ws,
            driver: Some(driver),
            _guard: Some(guard),
        }
    } else {
        let io: super::super::tls_backend::RelayTlsStream = Box::new(tls);
        ServerWs {
            ws: tokio_tungstenite::accept_async(io).await.unwrap(),
            driver: None,
            _guard: None,
        }
    }
}

fn validate_open(frame: &[u8], settings: &RelaySettings) {
    let request = open_tunnel_request(frame, settings.auth_token.as_bytes()).unwrap();
    assert_eq!(request.host, "127.0.0.1");
    assert_eq!(request.port, 43210);
}

fn profile() -> RelaySessionProfile {
    RelaySessionProfile {
        websocket_path: "/fixture".into(),
        write_chunk_size: 4096,
        ..Default::default()
    }
}

async fn local_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (local, _) = listener.accept().await.unwrap();
    (local, peer)
}

async fn run_client(
    carrier: Carrier,
    mut local: TcpStream,
    settings: RelaySettings,
) -> anyhow::Result<()> {
    let counters = RelaySessionCounters::default();
    let result = if matches!(carrier, Carrier::Legacy) {
        super::super::run_legacy_tls_tunnel(
            &mut local,
            &settings,
            &profile(),
            "127.0.0.1".into(),
            43210,
            Some(INITIAL),
            &counters,
        )
        .await
    } else {
        run_websocket_tunnel(
            &mut local,
            &settings,
            &profile(),
            "127.0.0.1".into(),
            43210,
            Some(INITIAL),
            &counters,
        )
        .await
    };
    if result.is_ok() {
        assert!(
            counters.was_opened(),
            "authenticated ACK marks retry commitment for {carrier:?}"
        );
    }
    result
}

async fn assert_stall(carrier: Carrier, stage: Stage, cancel: bool) {
    warm_native_roots();
    tokio::time::timeout(WATCHDOG, async {
        let relay = Fixture::new(carrier).await;
        let mut settings = relay.settings.clone();
        if cancel {
            settings.connect_timeout_ms = 60_000;
        }
        let (ready_tx, ready_rx) = oneshot::channel();
        let mut server = tokio::spawn(async move {
            relay.stall(stage, ready_tx).await;
        });
        let _server = H2Driver(Some(server.abort_handle()));
        let (local, _peer) = local_pair().await;
        let mut client = tokio::spawn(run_client(carrier, local, settings));
        let _client = H2Driver(Some(client.abort_handle()));
        if ready_rx.await.is_err() {
            panic!(
                "required {carrier:?}/{stage:?} stage not reached; client={:#?}, server={:#?}",
                (&mut client).await,
                (&mut server).await
            );
        }
        if cancel {
            client.abort();
            assert!(client.await.unwrap_err().is_cancelled());
        } else {
            let error = (&mut client).await.unwrap().expect_err("opening deadline");
            assert!(
                error
                    .downcast_ref::<tokio::time::error::Elapsed>()
                    .is_some(),
                "{error:#}"
            );
        }
        (&mut server)
            .await
            .expect("peer observed close; no detached driver");
    })
    .await
    .expect("staged opening/cleanup watchdog");
}

#[tokio::test]
async fn legacy_opening_bounds_tls_and_ack_and_closes_on_cancel() {
    for stage in [Stage::Tls, Stage::Ack] {
        assert_stall(Carrier::Legacy, stage, false).await;
        assert_stall(Carrier::Legacy, stage, true).await;
    }
}

#[tokio::test]
async fn websocket_http1_opening_bounds_upgrade_and_ack() {
    for stage in [Stage::Headers, Stage::Ack] {
        assert_stall(Carrier::Http1, stage, false).await;
        assert_stall(Carrier::Http1, stage, true).await;
    }
}

#[tokio::test]
async fn websocket_h2_opening_bounds_tls_protocol_headers_ack_and_owns_driver() {
    for stage in [Stage::Tls, Stage::Protocol, Stage::Headers, Stage::Ack] {
        assert_stall(Carrier::H2, stage, false).await;
        assert_stall(Carrier::H2, stage, true).await;
    }
}

#[tokio::test]
async fn websocket_internal_retry_does_not_reset_opening_deadline() {
    warm_native_roots();
    let (watchdog, expired) = NativeWatchdog::new();
    let witness = Arc::new(RetryWitness::new());
    let stages = witness.clone();
    let test = async {
        let relay = Fixture::new(Carrier::H2).await;
        let settings = relay.settings.clone();
        let (first_tx, mut first_rx) = oneshot::channel();
        let (reset_tx, reset_rx) = oneshot::channel();
        let (ready_tx, mut ready_rx) = oneshot::channel();
        let frozen = FrozenClock::new();
        let mut server = tokio::spawn(async move {
            let (tcp, _) = relay.listener.accept().await.unwrap();
            stages.record(RetryPhase::FirstTcp);
            let tls = relay.acceptor.accept(tcp).await.unwrap();
            stages.record(RetryPhase::FirstTls);
            let (request, mut respond, mut driver) = accept_h2(tls).await;
            let _driver = H2Driver(Some(driver.abort_handle()));
            stages.record(RetryPhase::FirstConnect);
            first_tx.send(()).unwrap();
            reset_rx.await.unwrap();
            respond.send_reset(h2::Reason::INTERNAL_ERROR);
            stages.record(RetryPhase::ResetQueued);
            drop(request);
            drop(respond);

            // Reset/close is driven concurrently with retry admission; joining
            // the first connection before the next accept is not a retry proof.
            let (tcp, _) = relay.listener.accept().await.unwrap();
            stages.record(RetryPhase::RetryTcp);
            let tls = relay.acceptor.accept(tcp).await.unwrap();
            stages.record(RetryPhase::RetryTls);
            let mut retry = accept_ws(tls, Carrier::H2).await;
            stages.record(RetryPhase::RetryConnect);
            let Message::Binary(frame) = retry.ws.next().await.unwrap().unwrap() else {
                panic!("retry binary authenticated open");
            };
            validate_open(&frame, &relay.settings);
            stages.record(RetryPhase::RetryOpen);
            ready_tx.send(()).unwrap();
            assert!(
                !matches!(retry.ws.next().await, Some(Ok(Message::Binary(_)))),
                "no application payload before retry authenticated ACK"
            );
            retry.finish().await;
            (&mut driver)
                .await
                .expect("failed first attempt closes driver");
            stages.record(RetryPhase::FirstClosed);
            stages.record(RetryPhase::ServerClosed);
        });
        let _server = H2Driver(Some(server.abort_handle()));
        let (local, _peer) = local_pair().await;
        let started = tokio::time::Instant::now();
        let mut client = tokio::spawn(run_client(Carrier::H2, local, settings));
        let _client = H2Driver(Some(client.abort_handle()));
        retry_barrier(&mut first_rx, &mut client, &mut server)
            .await
            .unwrap_or_else(|reason| {
                panic!(
                    "first CONNECT barrier {reason:?}; stages={:?}",
                    witness.snapshot()
                )
            });
        assert_eq!(
            started.elapsed(),
            Duration::ZERO,
            "network readiness cannot advance test clock"
        );
        tokio::time::advance(Duration::from_millis(2_000)).await;
        reset_tx.send(()).unwrap();
        retry_barrier(&mut ready_rx, &mut client, &mut server)
            .await
            .unwrap_or_else(|reason| {
                panic!(
                    "retry ACK barrier {reason:?}; stages={:?}",
                    witness.snapshot()
                )
            });
        assert_eq!(started.elapsed(), Duration::from_millis(2_000));
        assert!(witness.saw(RetryPhase::ResetQueued) && witness.saw(RetryPhase::RetryOpen));
        assert!(
            !client.is_finished(),
            "retry actually awaits authenticated ACK"
        );
        // Timer-wheel millisecond slack is still before a reset budget at 5 s.
        // The runnable keeper prevents unrelated timers from advancing time.
        tokio::time::advance(Duration::from_millis(1_001)).await;
        let error = (&mut client).await.unwrap().unwrap_err();
        assert!(error
            .downcast_ref::<tokio::time::error::Elapsed>()
            .is_some());
        assert_eq!(started.elapsed(), Duration::from_millis(OPEN_MS + 1));
        (&mut server).await.unwrap();
        assert!(witness.saw(RetryPhase::FirstClosed) && witness.saw(RetryPhase::ServerClosed));
        frozen.finish().await;
    };
    tokio::select! {
        _ = expired => panic!("native retry deadline watchdog; stages={:?}", witness.snapshot()),
        _ = test => {},
    }
    watchdog.finish();
    assert_eq!(
        witness.snapshot(),
        (RetryPhase::ServerClosed as u32, (1 << 11) - 1)
    );
    eprintln!("opening_retry_fixture: all11_phases=true initial_budget_ms=3000 frozen_elapsed_ms=3001 first_driver_joined=true server_joined=true keeper_joined=true watchdog_joined=true");
}

#[tokio::test]
async fn websocket_retry_barrier_observes_client_failure_before_readiness() {
    let (_ready, mut ready) = oneshot::channel();
    let mut client =
        tokio::spawn(async { Err(anyhow::anyhow!("synthetic fixture terminal error")) });
    let _client = H2Driver(Some(client.abort_handle()));
    let mut server = tokio::spawn(std::future::pending());
    let _server = H2Driver(Some(server.abort_handle()));
    assert_eq!(
        retry_barrier(&mut ready, &mut client, &mut server).await,
        Err(RetryBarrierFailure::ClientTerminal {
            opening_elapsed: false
        })
    );
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn websocket_retry_barrier_reports_actual_opening_elapsed_before_readiness() {
    let (_ready, mut ready) = oneshot::channel();
    let mut client = tokio::spawn(async {
        tokio::time::timeout(Duration::ZERO, std::future::pending::<()>())
            .await
            .map_err(anyhow::Error::from)
    });
    let _client = H2Driver(Some(client.abort_handle()));
    let mut server = tokio::spawn(std::future::pending());
    let _server = H2Driver(Some(server.abort_handle()));
    assert_eq!(
        retry_barrier(&mut ready, &mut client, &mut server).await,
        Err(RetryBarrierFailure::ClientTerminal {
            opening_elapsed: true
        })
    );
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn websocket_retry_barrier_observes_fixture_failure_before_readiness() {
    let (_ready, mut ready) = oneshot::channel();
    let mut client = tokio::spawn(std::future::pending());
    let _client = H2Driver(Some(client.abort_handle()));
    let mut server = tokio::spawn(async {});
    let _server = H2Driver(Some(server.abort_handle()));
    assert_eq!(
        retry_barrier(&mut ready, &mut client, &mut server).await,
        Err(RetryBarrierFailure::ServerTerminal)
    );
    client.abort();
    assert!(client.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn opening_deadline_does_not_limit_established_payload_or_half_close() {
    warm_native_roots();
    for carrier in [Carrier::Legacy, Carrier::Http1, Carrier::H2] {
        tokio::time::timeout(WATCHDOG, async {
            let relay = Fixture::new(carrier).await;
            let settings = relay.settings.clone();
            let (ready_tx, ready_rx) = oneshot::channel();
            let mut server = tokio::spawn(async move {
                relay.echo(ready_tx).await;
            });
            let _server = H2Driver(Some(server.abort_handle()));
            let (local, mut peer) = local_pair().await;
            let mut client = tokio::spawn(run_client(carrier, local, settings));
            let _client = H2Driver(Some(client.abort_handle()));
            ready_rx
                .await
                .expect("authenticated ack and exactly one initial payload");
            let mut initial = vec![0; INITIAL.len()];
            peer.read_exact(&mut initial).await.unwrap();
            assert_eq!(initial, INITIAL);
            tokio::time::sleep(Duration::from_millis(OPEN_MS + 100)).await;
            assert!(!client.is_finished());
            peer.write_all(LATE).await.unwrap();
            let mut late = vec![0; LATE.len()];
            peer.read_exact(&mut late).await.unwrap();
            assert_eq!(late, LATE);
            peer.shutdown().await.unwrap();
            (&mut client)
                .await
                .unwrap()
                .unwrap_or_else(|error| panic!("{carrier:?} graceful half-close: {error:#}"));
            (&mut server).await.unwrap();
        })
        .await
        .unwrap_or_else(|_| panic!("{carrier:?} positive stream/half-close watchdog"));
    }
}

#[cfg(not(feature = "legacy-challenge-v1"))]
#[tokio::test]
async fn authenticated_websocket_error_never_replays_payload_to_second_endpoint() {
    warm_native_roots();
    tokio::time::timeout(WATCHDOG, async {
        let relay = Fixture::new(Carrier::H2).await;
        let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut settings = relay.settings.clone();
        settings.transport_priority = vec![aegis_core::TunnelTransportFamily::HttpsWs];
        settings.endpoints = [
            relay.listener.local_addr().unwrap(),
            second.local_addr().unwrap(),
        ]
        .into_iter()
        .map(|address| aegis_core::RelayEndpointSettings {
            server: address.to_string(),
            server_name: "localhost".into(),
            masque_server: None,
            masque_server_name: None,
        })
        .collect();
        let (seen_tx, seen_rx) = oneshot::channel();
        let mut server = tokio::spawn(async move {
            let (tcp, _) = relay.listener.accept().await.unwrap();
            let tls = relay.acceptor.accept(tcp).await.unwrap();
            let (request, mut respond, mut driver) = accept_h2(tls).await;
            let _driver = H2Driver(Some(driver.abort_handle()));
            let send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            let io: super::super::tls_backend::RelayTlsStream = Box::new(
                aegis_core::h2_stream::H2Stream::new(send, request.into_body()),
            );
            let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
                io,
                tokio_tungstenite::tungstenite::protocol::Role::Server,
                None,
            )
            .await;
            let Message::Binary(frame) = ws.next().await.unwrap().unwrap() else {
                panic!("binary open");
            };
            validate_open(&frame, &relay.settings);
            let ack = seal_tunnel_response(
                &TunnelResponse {
                    status: TunnelStatus::Ok,
                    message: String::new(),
                },
                relay.settings.auth_token.as_bytes(),
            )
            .unwrap();
            ws.send(Message::Binary(ack)).await.unwrap();
            let Message::Binary(first) = ws.next().await.unwrap().unwrap() else {
                panic!("initial application payload");
            };
            assert_eq!(first, INITIAL, "one exact application payload before error");
            seen_tx.send(()).unwrap();
            respond.send_reset(h2::Reason::INTERNAL_ERROR);
            drop(ws);
            (&mut driver)
                .await
                .expect("error path closes owned client driver");
        });
        let _server = H2Driver(Some(server.abort_handle()));
        let (local, _peer) = local_pair().await;
        let result = super::super::run_relay_tunnel(
            local,
            &settings,
            "127.0.0.1".into(),
            43210,
            Some(INITIAL),
            None,
            None,
        )
        .await;
        seen_rx
            .await
            .expect("authenticated open plus real payload observed");
        assert!(
            result.is_err(),
            "fixture must exercise non-benign transport error"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(150), second.accept())
                .await
                .is_err(),
            "no retry/initial-payload replay after authenticated open"
        );
        (&mut server).await.unwrap();
    })
    .await
    .expect("no-replay watchdog");
}

#[cfg(feature = "legacy-challenge-v1")]
#[tokio::test]
async fn fresh_raw_feature_refuses_shared_token_websocket_before_either_endpoint_dial() {
    tokio::time::timeout(WATCHDOG, async {
        let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addresses = [first.local_addr().unwrap(), second.local_addr().unwrap()];
        let settings = RelaySettings {
            server: addresses[0].to_string(),
            server_name: "localhost".into(),
            auth_token: "opening-fixture-only".into(),
            transport_priority: vec![aegis_core::TunnelTransportFamily::HttpsWs],
            tls_backend: aegis_core::RelayTlsBackend::Rustls,
            endpoints: addresses.into_iter().map(|address| aegis_core::RelayEndpointSettings {
                server: address.to_string(),
                server_name: "localhost".into(),
                masque_server: None,
                masque_server_name: None,
            }).collect(),
            ..Default::default()
        };
        let (local, _peer) = local_pair().await;
        let error = super::super::run_relay_tunnel(
            local, &settings, "127.0.0.1".into(), 43210, Some(INITIAL), None, None,
        ).await.expect_err("fresh raw mode must refuse the shared-token WS order");
        assert_eq!(error.to_string(),
            "legacy-challenge-v1 requires a raw legacy_tls-only TCP transport order; downgrade is refused");
        assert!(tokio::time::timeout(Duration::from_millis(150), first.accept()).await.is_err(),
            "no first-endpoint dial before raw-only admission");
        assert!(tokio::time::timeout(Duration::from_millis(150), second.accept()).await.is_err(),
            "no fallback-endpoint dial after raw-only refusal");
    }).await.expect("raw-only refusal/no-dial watchdog");
}
