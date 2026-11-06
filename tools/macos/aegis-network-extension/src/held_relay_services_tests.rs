//! WorkGate and HeldRelayServices (B-06 S06) against the loopback test relay.
//! The fixture observes one real ACK and then grants its bridge a long test
//! lease by hand, with no monitor or re-ACK: after that first connection and
//! its one stream, every relay connection is one of the session's pooled
//! flow connections (S16h) and every relay stream is a flow's own. The relay
//! serves every stream of every connection (`test_relay::pool`); a test's
//! fault for its flows is set after the fixture's ACK.
use super::*;
use crate::{
    app_group::CapturedAppGroupInputs,
    bridge::PacketBridge,
    establish_limit::{AuthBackoff, FLOW_BACKOFF, FLOW_OPENS},
    flow_pool::{FlowPool, POOL_CONNS},
    local_identity::{ObservedLocalSession, PreparedLocalSession},
    provider_session_body::{tests::saved, EpochPins},
    relay_socket::RelayInterface,
    test_fixture::ReadyTree,
    test_relay::{
        aaaa_query,
        pool::{PoolConfig, PooledRelay, StreamFault, StreamStep},
        AckReply, RelayIdentity, Target, TestRelay, DNS_ANSWER_V6,
    },
};
use aegis_client::{
    capture_lease_gate::CaptureLeaseDeadline,
    protected_online_expectation::ProtectedOnlineExpectation,
};
use std::{
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    thread,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    runtime::Runtime,
};

const SECOND_NS: u64 = 1_000_000_000;

struct NoEvents;
impl EventSink for NoEvents {
    fn emit(&self, _: &'static str, _: EngineEvent, _: &'static str, _: serde_json::Value) {}
}

/// Sets its flag when the wrapped flow future is dropped. Its own Drop runs
/// before its fields', so the flag is set before the flow's permit returns.
struct Watched<F> {
    work: F,
    dropped: Arc<AtomicBool>,
}
impl<F: Future + Unpin> Future for Watched<F> {
    type Output = F::Output;
    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<F::Output> {
        Pin::new(&mut self.work).poll(context)
    }
}
impl<F> Drop for Watched<F> {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

struct DropFlag(Arc<AtomicBool>);
impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

// Declaration order is drop order: services and the observed channel go
// while their runtime and the relay still exist.
struct Fixture {
    services: Arc<HeldRelayServices>,
    gate: Arc<WorkGate>,
    bridge: LeasedPacketBridge,
    jump: Arc<AtomicU64>,
    settings: RelaySettings,
    observed: ObservedLocalSession,
    _store: Arc<ProtectedOnlineExpectation<'static>>,
    runtime: Runtime,
    relay: PooledRelay,
    _tree: ReadyTree,
}

impl Fixture {
    /// Wait until `n` relay streams recorded `step`; when the last did.
    fn wait_count(&self, step: StreamStep, n: usize, budget: Duration) -> Option<Instant> {
        self.runtime
            .block_on(self.relay.wait_count(step, n, budget))
    }

    /// Streams the session's flow pool holds now, on every connection.
    fn pooled_streams(&self) -> usize {
        self.services
            .pool()
            .views()
            .iter()
            .map(|view| view.streams)
            .sum()
    }
}

fn runtime() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

/// The production bridge clock plus a test-controlled forward jump.
fn jumping_bridge() -> (LeasedPacketBridge, Arc<AtomicU64>) {
    let real = LeasedPacketBridge::new(PacketBridge::default(), CaptureLeaseDeadline::default());
    let jump = Arc::new(AtomicU64::new(0));
    let offset = jump.clone();
    let bridge = LeasedPacketBridge::with_clock(
        PacketBridge::default(),
        CaptureLeaseDeadline::default(),
        move || Ok(real.clock_ns()? + offset.load(Ordering::SeqCst)),
    );
    (bridge, jump)
}

/// Every stream is served as aegis-server's whole secure session, an Open
/// by `target`.
fn fixture(target: Target) -> Fixture {
    fixture_on(
        EstablishLimiter::new(AuthBackoff::default()),
        |_, config| {
            config.target = target;
        },
    )
}

/// `fixture` on `limiter`, the relay configured by `configure` from the
/// fixture's tree (its PolicyAck reply is the tree's).
fn fixture_on(
    limiter: Arc<EstablishLimiter>,
    configure: impl FnOnce(&ReadyTree, &mut PoolConfig),
) -> Fixture {
    let listener = TestRelay::bind();
    let tree = ReadyTree::with_online_completed(listener.local_addr().unwrap());
    let mut config = PoolConfig {
        reply: Some(AckReply::for_tree(&tree)),
        ..PoolConfig::default()
    };
    configure(&tree, &mut config);
    let relay = TestRelay::spawn_streams(listener, RelayIdentity::for_tree(&tree), config);
    let runtime = runtime();
    let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
    let (prepared, store) = PreparedLocalSession::from_claim_with_store_guard(claim).unwrap();
    let mut observed = runtime
        .block_on(async {
            let tcp = TcpStream::connect(tree.relay()).await.unwrap();
            prepared
                .observe_ack(saved(&tree), tcp, RelayInterface::loopback_for_test())
                .await
        })
        .unwrap();
    let (bridge, jump) = jumping_bridge();
    let now = bridge.clock_ns().unwrap();
    bridge.grant_until(now + 60 * SECOND_NS).unwrap();
    let gate = WorkGate::new();
    let services = services_on(&mut observed, &bridge, gate.clone(), limiter);
    let settings = services.signed_relay();
    // The session's ACK alone: one connection, one stream.
    assert_eq!((relay.conns(), relay.streams(), relay.acks()), (1, 1, 1));
    Fixture {
        services,
        gate,
        bridge,
        jump,
        settings,
        observed,
        _store: store,
        runtime,
        relay,
        _tree: tree,
    }
}

/// The session's relay services over a fresh flow pool on `gate` and
/// `limiter`, with nothing re-pinned.
fn services_on(
    observed: &mut ObservedLocalSession,
    bridge: &LeasedPacketBridge,
    gate: Arc<WorkGate>,
    limiter: Arc<EstablishLimiter>,
) -> Arc<HeldRelayServices> {
    let pool = observed
        .flow_pool((limiter, gate), (EpochPins::default(), 0))
        .unwrap();
    observed
        .held_relay_services(Arc::new(NoEvents), bridge.clone(), pool)
        .unwrap()
}

/// A connected loopback pair: (application side, side handed to `tcp`).
async fn loopback() -> (TcpStream, TcpStream) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let app = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (local, _) = listener.accept().await.unwrap();
    (app, local)
}

/// `loopback` with 8 KiB socket buffers, so loopback autotuning cannot
/// absorb a 1 MiB write that the relay never reads.
async fn small_buffered_loopback() -> (TcpStream, TcpStream) {
    let listening = tokio::net::TcpSocket::new_v4().unwrap();
    listening.set_recv_buffer_size(8 * 1024).unwrap();
    listening.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let listener = listening.listen(1).unwrap();
    let connecting = tokio::net::TcpSocket::new_v4().unwrap();
    connecting.set_send_buffer_size(8 * 1024).unwrap();
    let app = connecting
        .connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (local, _) = listener.accept().await.unwrap();
    (app, local)
}

fn wait_until(budget: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + budget;
    while !done() {
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(1));
    }
    true
}

fn udp_target(host: &str, port: u16) -> ConnectTarget {
    ConnectTarget {
        host: host.into(),
        port,
    }
}

#[test]
fn held_relay_services_gate_stop_aborts_and_waits_for_its_tasks() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let gate = WorkGate::new();
    let dropped = Arc::new(AtomicBool::new(false));
    let flag = DropFlag(dropped.clone());
    let guard = runtime
        .block_on(async {
            gate.spawn(async move {
                let _flag = flag;
                std::future::pending::<()>().await;
            })
        })
        .unwrap();
    assert_eq!(gate.tasks_left(), 1);
    // Occupy the only worker, so the abort cannot be processed at once.
    let (busy, busied) = std::sync::mpsc::channel();
    runtime.spawn(async move {
        busy.send(()).unwrap();
        thread::sleep(Duration::from_millis(150));
    });
    busied.recv_timeout(Duration::from_secs(2)).unwrap();
    let stopping = Instant::now();
    gate.stop(MAX_DRAIN).unwrap();
    // stop returned only once the aborted task had been dropped by the
    // runtime, although this flow's own abort guard is still held.
    assert!(dropped.load(Ordering::SeqCst));
    assert!(stopping.elapsed() >= Duration::from_millis(50));
    assert_eq!(gate.tasks_left(), 0);
    assert!(gate.drained());
    // A stopped gate takes no task and admits no flow.
    let refused = runtime.block_on(async { gate.spawn(async {}) });
    assert_eq!(
        refused.err().unwrap().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert!(gate.admit().is_err());
    assert_eq!(gate.tasks_left(), 0);
    drop(guard);
    // Outside a runtime nothing is spawned either.
    assert!(WorkGate::new().spawn(async {}).is_err());
}

#[test]
fn held_relay_services_gate_drains_tasks_of_the_runtime_it_waits_on() {
    // S16j-3, the v21 stop: the session's relay pre-dial and the driver of
    // the connection it dials are gate tasks on the session's current-thread
    // runtime, which only the session thread polls. An aborted task is
    // dropped only when its runtime polls it.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let gate = WorkGate::new();
    let (outer, inner) = (
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(false)),
    );
    let (outer_flag, inner_flag) = (DropFlag(outer.clone()), DropFlag(inner.clone()));
    let spawner = gate.clone();
    let guard = runtime
        .block_on(async {
            gate.spawn(async move {
                let _flag = outer_flag;
                // As a dial spawns its connection's driver.
                let _driver = spawner.spawn(async move {
                    let _flag = inner_flag;
                    std::future::pending::<()>().await;
                });
                std::future::pending::<()>().await;
            })
        })
        .unwrap();
    // Let the outer task spawn its driver.
    runtime.block_on(async { tokio::time::sleep(Duration::from_millis(20)).await });
    assert_eq!(gate.tasks_left(), 2);
    // Waiting with this thread asleep: nothing polls the runtime, so the
    // aborted tasks are never dropped and the gate never drains.
    assert_eq!(
        gate.stop(Duration::from_millis(200)).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert!(!outer.load(Ordering::SeqCst) && !inner.load(Ordering::SeqCst));
    assert_eq!(gate.tasks_left(), 2);
    // Waiting on that runtime drops them at once.
    let stopping = Instant::now();
    runtime.block_on(gate.stop_async(MAX_DRAIN)).unwrap();
    assert!(
        stopping.elapsed() < Duration::from_millis(250),
        "{:?}",
        stopping.elapsed()
    );
    assert!(outer.load(Ordering::SeqCst) && inner.load(Ordering::SeqCst));
    assert_eq!(gate.tasks_left(), 0);
    assert!(gate.drained());
    // Closed as `stop` closes: no task, no flow, and the budget bound holds.
    assert!(runtime.block_on(async { gate.spawn(async {}) }).is_err());
    assert!(gate.admit().is_err());
    assert_eq!(
        runtime
            .block_on(gate.stop_async(MAX_DRAIN + Duration::from_millis(1)))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    drop(guard);
}

#[test]
fn held_relay_services_gate_stop_async_keeps_waiting_for_a_held_permit() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let gate = WorkGate::new();
    let permit = gate.admit().unwrap();
    let stopping = Instant::now();
    assert_eq!(
        runtime
            .block_on(gate.stop_async(Duration::from_millis(100)))
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert!(stopping.elapsed() >= Duration::from_millis(100));
    assert!(gate.is_closed());
    assert_eq!(gate.flows(), 1);
    drop(permit);
    runtime.block_on(gate.stop_async(MAX_DRAIN)).unwrap();
    assert!(gate.drained());
}

#[test]
fn held_relay_services_gate_stop_times_out_while_a_flow_holds_its_permit() {
    let gate = WorkGate::new();
    let permit = gate.admit().unwrap();
    assert_eq!(gate.flows(), 1);
    assert_eq!(
        gate.stop(MAX_DRAIN + Duration::from_millis(1))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    let stopping = Instant::now();
    assert_eq!(
        gate.stop(Duration::from_millis(50)).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert!(stopping.elapsed() >= Duration::from_millis(50));
    // Still closed after the timeout: no new flow while the old one runs.
    assert!(gate.is_closed());
    assert!(gate.admit().is_err());
    assert!(!gate.drained());
    drop(permit);
    // The closed semaphore still takes the permit back.
    assert_eq!(gate.flows(), 0);
    gate.stop(Duration::ZERO).unwrap();
    assert!(gate.drained());
}

#[test]
fn held_relay_services_tcp_udp_once_and_udp_flow_echo() {
    let f = fixture(Target::Echo);
    let services = f.services.clone();
    let settings = f.settings.clone();
    f.runtime.block_on(async move {
        tokio::time::timeout(Duration::from_secs(10), async {
            // TCP: echo both ways, then a half-close ends the flow cleanly.
            let (mut app, local) = loopback().await;
            let flow = {
                let services = services.clone();
                let settings = settings.clone();
                tokio::spawn(
                    async move { services.tcp(local, &settings, "echo.test".into(), 7).await },
                )
            };
            for round in 0..3u8 {
                let sent = vec![round; 4096];
                app.write_all(&sent).await.unwrap();
                let mut echoed = vec![0; sent.len()];
                app.read_exact(&mut echoed).await.unwrap();
                assert_eq!(echoed, sent);
            }
            app.shutdown().await.unwrap();
            let mut rest = Vec::new();
            app.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty());
            flow.await.unwrap().unwrap();

            // udp_once: one echoed datagram, then a DNS answer on port 53.
            let echoed = services
                .udp_once(&settings, udp_target("192.0.2.7", 7), b"held datagram")
                .await
                .unwrap();
            assert_eq!(echoed, b"held datagram");
            let query = aaaa_query(0x5a17, "flow.example.test");
            let answer = services
                .udp_once(&settings, udp_target("198.19.255.2", 53), &query)
                .await
                .unwrap();
            assert!(aegis_core::dns_response::is_valid_relay_response(
                &query, &answer
            ));
            assert!(answer.ends_with(&DNS_ANSWER_V6.octets()));

            // udp_flow: several datagrams over one persistent channel.
            let (outbound, out_rx) = mpsc::channel(8);
            let (in_tx, mut incoming) = mpsc::channel(8);
            let flow = {
                let services = services.clone();
                let settings = settings.clone();
                tokio::spawn(async move {
                    let host = String::from("2001:db8::7");
                    services.udp_flow(&settings, &host, 7, out_rx, in_tx).await
                })
            };
            for round in 0..3u8 {
                let sent = vec![round; 100 + usize::from(round)];
                outbound.send(sent.clone()).await.unwrap();
                let packet = incoming.recv().await.unwrap();
                assert_eq!(packet.payload, sent);
                assert_eq!(packet.target.host, "2001:db8::7");
                assert_eq!(packet.target.port, 7);
            }
            drop(outbound);
            flow.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    });
    // The session's ACK, then one pooled connection that carried every
    // flow as its own stream.
    assert_eq!(f.relay.conns(), 2);
    assert_eq!(f.relay.streams(), 5);
    assert_eq!(f.gate.flows(), 0);
    // Each flow's stream is returned once its flow dropped; the pooled
    // connection's driver is the one gate task left.
    assert!(wait_until(Duration::from_secs(2), || f.pooled_streams() == 0));
    assert_eq!(f.services.pool().views().len(), 1);
    assert_eq!(f.gate.tasks_left(), 1);
    assert!(!f.gate.is_closed());
}

#[test]
fn held_relay_services_refuse_an_empty_target_before_any_dial() {
    let f = fixture(Target::Echo);
    f.runtime.block_on(async {
        let (_app, local) = loopback().await;
        assert!(f
            .services
            .tcp(local, &f.settings, String::new(), 7)
            .await
            .is_err());
        assert!(f
            .services
            .udp_once(&f.settings, udp_target("192.0.2.7", 0), b"no port")
            .await
            .is_err());
    });
    thread::sleep(Duration::from_millis(100));
    assert_eq!((f.relay.conns(), f.relay.streams()), (1, 1));
    assert!(f.services.pool().views().is_empty());
    assert_eq!(f.services.limiter.active(), (0, 0));
}

#[test]
fn held_relay_services_dial_every_flow_on_the_session_relay_interface() {
    let mut f = fixture(Target::Echo);
    assert_eq!(
        *f.services.pool().interface(),
        RelayInterface::loopback_for_test()
    );
    // The same services over a pool on an interface no interface index
    // names: every flow kind fails at its bound dial and nothing reaches
    // the relay.
    let pool = FlowPool::new(
        f.services.peer,
        RelayInterface::for_test("en99", 0x7fff_0000),
        f.services.crypto.clone(),
        (f.services.limiter.clone(), f.gate.clone()),
        (EpochPins::default(), 0),
    )
    .unwrap();
    // The session's own services are never built over a pool of another
    // interface.
    let bridge = f.bridge.clone();
    assert!(f
        .observed
        .held_relay_services(Arc::new(NoEvents), bridge, pool.clone())
        .is_err());
    let gone =
        Arc::new(HeldRelayServices::new(Arc::new(NoEvents), f.bridge.clone(), pool).unwrap());
    let settings = f.settings.clone();
    f.runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(10), async {
            let (_app, local) = loopback().await;
            assert!(gone
                .tcp(local, &settings, "echo.test".into(), 7)
                .await
                .is_err());
            assert!(gone
                .udp_once(&settings, udp_target("192.0.2.7", 7), b"bound")
                .await
                .is_err());
            let (_outbound, out_rx) = mpsc::channel(1);
            let (in_tx, _incoming) = mpsc::channel(1);
            assert!(gone
                .udp_flow(&settings, "192.0.2.7", 7, out_rx, in_tx)
                .await
                .is_err());
        })
        .await
        .unwrap();
    });
    thread::sleep(Duration::from_millis(100));
    // Only the session's own ACK connection and its stream.
    assert_eq!((f.relay.conns(), f.relay.streams()), (1, 1));
    assert_eq!(f.gate.flows(), 0);
    // The lo0-bound services still reach the relay.
    let echoed = f.runtime.block_on(f.services.udp_once(
        &settings,
        udp_target("192.0.2.7", 7),
        b"bound",
    ));
    assert_eq!(echoed.unwrap(), b"bound");
    assert_eq!((f.relay.conns(), f.relay.streams()), (2, 2));
}

#[test]
fn held_relay_services_udp_once_without_a_reply_fails_within_the_signed_budget() {
    // The relay's port-53 answerer drops a malformed query and keeps the
    // channel open, as a lost upstream reply leaves the server waiting for
    // its idle timeout. The lease stays live for 60 s, so only the reply
    // budget can end this flow.
    let f = fixture(Target::Echo);
    let budget = Duration::from_millis(f.settings.connect_timeout_ms);
    let services = f.services.clone();
    let settings = f.settings.clone();
    let (elapsed, error) = f.runtime.block_on(async move {
        tokio::time::timeout(budget * 4, async {
            let started = Instant::now();
            let error = services
                .udp_once(&settings, udp_target("198.19.255.2", 53), b"\x5a")
                .await
                .expect_err("an unanswered datagram returned a reply");
            (started.elapsed(), error)
        })
        .await
        .expect("udp_once outlived its reply budget")
    });
    assert_eq!(
        error.downcast_ref::<io::Error>().map(io::Error::kind),
        Some(io::ErrorKind::TimedOut),
        "{error:#}"
    );
    assert!(elapsed >= budget, "ended after {elapsed:?}");
    // The open and the loaded runtime may add to the budget, never double it.
    assert!(elapsed <= budget * 2, "ended after {elapsed:?}");
    assert!(f
        .bridge
        .refreshable_deadline()
        .active_at(f.bridge.clock_ns().unwrap()));
    // The flow returned its permit and its stream; its pooled connection
    // stays for the next flow.
    assert_eq!(f.gate.flows(), 0);
    assert!(wait_until(Duration::from_secs(2), || f.pooled_streams() == 0));
    assert_eq!(f.gate.tasks_left(), 1);
    // The next query on a fresh channel (its own stream) is still answered.
    let services = f.services.clone();
    let settings = f.settings.clone();
    let query = aaaa_query(0x5a18, "after.example.test");
    let answer = f
        .runtime
        .block_on(async move {
            tokio::time::timeout(
                budget,
                services.udp_once(&settings, udp_target("198.19.255.2", 53), &query),
            )
            .await
        })
        .expect("the follow-up query outlived its budget")
        .unwrap();
    assert!(answer.ends_with(&DNS_ANSWER_V6.octets()));
    assert_eq!((f.relay.conns(), f.relay.streams()), (2, 3));
    assert!(!f.gate.is_closed());
}

#[test]
fn held_relay_services_stop_during_inflight_1mib_write_returns_after_flow_drop() {
    let f = fixture(Target::Stall);
    let dropped = Arc::new(AtomicBool::new(false));
    let (app, local) = f.runtime.block_on(small_buffered_loopback());
    let app = app.into_std().unwrap();
    app.set_nonblocking(false).unwrap();
    let flow = {
        let services = f.services.clone();
        let settings = f.settings.clone();
        let dropped = dropped.clone();
        f.runtime.spawn(async move {
            Watched {
                work: services.tcp(local, &settings, "stall.test".into(), 9),
                dropped,
            }
            .await
        })
    };
    let written = Arc::new(AtomicBool::new(false));
    let writer = {
        let written = written.clone();
        let mut app = app.try_clone().unwrap();
        thread::spawn(move || {
            let result = std::io::Write::write_all(&mut app, &vec![7; 1 << 20]);
            written.store(true, Ordering::SeqCst);
            result
        })
    };
    f.wait_count(StreamStep::Opened, 1, Duration::from_secs(3))
        .expect("the flow never opened its target");
    // The relay reads nothing: flow control and both socket buffers fill,
    // so the 1 MiB write is still in flight.
    thread::sleep(Duration::from_millis(300));
    assert!(!written.load(Ordering::SeqCst), "1 MiB write completed");
    assert!(!dropped.load(Ordering::SeqCst));
    assert_eq!(f.gate.flows(), 1);
    // The flow's pooled connection's driver.
    assert_eq!(f.gate.tasks_left(), 1);
    // The lease is live: only the gate ends this flow.
    f.gate.stop(MAX_DRAIN).unwrap();
    assert!(dropped.load(Ordering::SeqCst), "stop returned before drop");
    assert_eq!(f.gate.flows(), 0);
    assert_eq!(f.gate.tasks_left(), 0);
    assert!(f
        .bridge
        .refreshable_deadline()
        .active_at(f.bridge.clock_ns().unwrap()));
    let result = f.runtime.block_on(flow).unwrap();
    assert!(result.is_err());
    // The dropped flow closed its socket, so the stalled write fails.
    assert!(writer.join().unwrap().is_err());
}

#[test]
fn held_relay_services_stop_during_a_stalled_open_ends_the_flow_within_recheck() {
    // Each pooled dial is accepted and never answered: the flow waits in
    // outer TLS, before any driver task exists, for the 5 s connect budget.
    let f = fixture_on(
        EstablishLimiter::new(AuthBackoff::default()),
        |_, config| {
            config.silent_from = Some(1);
        },
    );
    let dropped = Arc::new(AtomicBool::new(false));
    let flow = {
        let services = f.services.clone();
        let settings = f.settings.clone();
        let dropped = dropped.clone();
        f.runtime.spawn(async move {
            let payload = b"stalled".to_vec();
            Watched {
                work: services.udp_once(&settings, udp_target("192.0.2.7", 7), &payload),
                dropped,
            }
            .await
        })
    };
    // The fixture's own ACK connection, then the flow's pooled dial.
    assert!(
        wait_until(Duration::from_secs(3), || f.relay.conns() == 2),
        "the flow never dialed"
    );
    thread::sleep(Duration::from_millis(100));
    assert_eq!(f.gate.flows(), 1);
    assert_eq!(f.gate.tasks_left(), 0);
    assert!(!dropped.load(Ordering::SeqCst));
    let stopping = Instant::now();
    f.gate.stop(MAX_DRAIN).unwrap();
    assert!(
        stopping.elapsed() <= RECHECK + Duration::from_millis(100),
        "stop took {:?}",
        stopping.elapsed()
    );
    assert!(dropped.load(Ordering::SeqCst));
    assert!(f.runtime.block_on(flow).unwrap().is_err());
    // S16i-1: an open the gate ended unfinished.
    assert!(
        f.services
            .limiter()
            .flow_log_lines()
            .iter()
            .any(|line| line.starts_with("flow_open dropped ms:")),
        "{:?}",
        f.services.limiter().flow_log_lines()
    );
}

#[test]
fn held_relay_services_refuse_every_flow_after_stop_without_dialing() {
    let f = fixture(Target::Echo);
    f.gate.stop(MAX_DRAIN).unwrap();
    let before = (f.relay.conns(), f.relay.streams());
    f.runtime.block_on(async {
        let (mut app, local) = loopback().await;
        assert!(f
            .services
            .tcp(local, &f.settings, "echo.test".into(), 7)
            .await
            .is_err());
        // The refused flow dropped its socket unused.
        let mut rest = Vec::new();
        let _ = app.read_to_end(&mut rest).await;
        assert!(rest.is_empty());
        assert!(f
            .services
            .udp_once(&f.settings, udp_target("192.0.2.7", 7), b"late")
            .await
            .is_err());
        let (_outbound, out_rx) = mpsc::channel(1);
        let (in_tx, _incoming) = mpsc::channel(1);
        assert!(f
            .services
            .udp_flow(&f.settings, "192.0.2.7", 7, out_rx, in_tx)
            .await
            .is_err());
    });
    // Any dial would have been accepted by now.
    thread::sleep(Duration::from_millis(300));
    assert_eq!((f.relay.conns(), f.relay.streams()), before);
    assert_eq!(f.gate.flows(), 0);
    // S16i-1: each refusal recorded once, as its session's.
    assert_eq!(closed_opens(f.services.limiter()), 3);
    // Only the gate refused: the lease itself is still live.
    assert!(f
        .bridge
        .refreshable_deadline()
        .active_at(f.bridge.clock_ns().unwrap()));
}

#[test]
fn held_relay_services_refuse_without_a_live_lease_or_signed_settings_before_dialing() {
    let mut f = fixture(Target::Echo);
    let refuses = |services: &HeldRelayServices, settings: &RelaySettings| {
        f.runtime.block_on(async {
            services
                .udp_once(settings, udp_target("192.0.2.7", 7), b"refused")
                .await
                .is_err()
        })
    };
    let services_on = |observed: &mut ObservedLocalSession, bridge: &LeasedPacketBridge| {
        services_on(
            observed,
            bridge,
            WorkGate::new(),
            EstablishLimiter::new(AuthBackoff::default()),
        )
    };
    let before = (f.relay.conns(), f.relay.streams());
    // A bridge that never saw a grant.
    let ungranted =
        LeasedPacketBridge::new(PacketBridge::default(), CaptureLeaseDeadline::default());
    let never = services_on(&mut f.observed, &ungranted);
    assert!(refuses(&never, &f.settings));
    assert_eq!(closed_opens(never.limiter()), 1);
    // A granted, then revoked, bridge; a later grant cannot revive it.
    let revoked = LeasedPacketBridge::new(PacketBridge::default(), CaptureLeaseDeadline::default());
    revoked
        .grant_until(revoked.clock_ns().unwrap() + 60 * SECOND_NS)
        .unwrap();
    let stopped = services_on(&mut f.observed, &revoked);
    revoked.stop();
    assert!(revoked
        .grant_until(revoked.clock_ns().unwrap() + 60 * SECOND_NS)
        .is_err());
    assert!(refuses(&stopped, &f.settings));
    assert_eq!(closed_opens(stopped.limiter()), 1);
    // An unreadable clock.
    let broken = LeasedPacketBridge::with_clock(
        PacketBridge::default(),
        CaptureLeaseDeadline::default(),
        || Err(io::Error::other("clock unavailable")),
    );
    let blind = services_on(&mut f.observed, &broken);
    assert!(refuses(&blind, &f.settings));
    assert_eq!(closed_opens(blind.limiter()), 1);
    // A live lease, but relay settings other than the signed ones: refused
    // in class other, not as the session's.
    let mut substituted = f.settings.clone();
    substituted.server_name = "other.test".into();
    assert!(refuses(&f.services, &substituted));
    let limiter = f.services.limiter().clone();
    assert_eq!(limiter.refusals(crate::flow_log::Refusal::Other), 1);
    assert_eq!(closed_opens(&limiter), 0);
    // The fixture's lease, after the bridge clock passed its end.
    f.jump.store(61 * SECOND_NS, Ordering::SeqCst);
    assert!(refuses(&f.services, &f.settings));
    assert_eq!(closed_opens(&limiter), 1);
    thread::sleep(Duration::from_millis(300));
    assert_eq!((f.relay.conns(), f.relay.streams()), before);
    // Control: back inside the lease, the same call is served, on the one
    // pooled connection it dials.
    f.jump.store(0, Ordering::SeqCst);
    assert!(!refuses(&f.services, &f.settings));
    assert_eq!(
        (f.relay.conns(), f.relay.streams()),
        (before.0 + 1, before.1 + 1)
    );
}

/// The `flow_open closed` lines the epoch of `limiter` logged (S16i-1).
fn closed_opens(limiter: &EstablishLimiter) -> usize {
    limiter
        .flow_log_lines()
        .iter()
        .filter(|line| line.starts_with("flow_open closed ms:"))
        .count()
}

#[test]
fn held_relay_services_a_lease_ending_before_the_first_poll_is_recorded() {
    // Admitted while the lease is live; the lease ends before the flow's
    // future is first polled, so its open never starts.
    let f = fixture(Target::Echo);
    let (_app, local) = f.runtime.block_on(loopback());
    let before = (f.relay.conns(), f.relay.streams());
    let work = f.services.tcp(local, &f.settings, "echo.test".into(), 7);
    assert_eq!(f.gate.flows(), 1);
    f.jump.store(61 * SECOND_NS, Ordering::SeqCst);
    assert!(f.runtime.block_on(work).is_err());
    assert_eq!(closed_opens(f.services.limiter()), 1);
    assert_eq!(f.gate.flows(), 0);
    assert_eq!((f.relay.conns(), f.relay.streams()), before);
}

/// A running TCP echo flow ends within one RECHECK, with margin, of `end`.
fn live_flow_ends_on(f: &Fixture, end: impl FnOnce()) {
    let (mut app, local) = f.runtime.block_on(loopback());
    let flow = {
        let services = f.services.clone();
        let settings = f.settings.clone();
        f.runtime.spawn(async move {
            let result = services.tcp(local, &settings, "echo.test".into(), 7).await;
            (result, Instant::now())
        })
    };
    f.runtime.block_on(async {
        app.write_all(b"live").await.unwrap();
        let mut echoed = [0; 4];
        app.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"live");
    });
    assert_eq!(f.gate.flows(), 1);
    let ended_at = Instant::now();
    end();
    let (result, ended) = f
        .runtime
        .block_on(async { tokio::time::timeout(Duration::from_secs(2), flow).await })
        .expect("flow outlived its lease")
        .unwrap();
    assert!(result.is_err());
    assert!(
        ended - ended_at <= RECHECK + Duration::from_millis(100),
        "flow ended {:?} after its lease",
        ended - ended_at
    );
    assert!(wait_until(Duration::from_secs(2), || f.gate.flows() == 0));
}

#[test]
fn held_relay_services_live_flow_ends_within_recheck_of_expiry() {
    let f = fixture(Target::Echo);
    live_flow_ends_on(&f, || f.jump.store(61 * SECOND_NS, Ordering::SeqCst));
    assert!(!f.gate.is_closed());
}

#[test]
fn held_relay_services_live_flow_ends_within_recheck_of_revocation() {
    let f = fixture(Target::Echo);
    live_flow_ends_on(&f, || f.bridge.stop());
    assert!(f.bridge.refreshable_deadline().is_revoked());
}

/// One TCP flow through `services` to the relay's echo target: `tag` both
/// ways, then a half-close. A refused flow drops its local side, so the
/// application sees the end and the flow's own result is returned.
async fn echo_flow(
    services: Arc<HeldRelayServices>,
    settings: RelaySettings,
    tag: u8,
) -> anyhow::Result<()> {
    let (mut app, local) = loopback().await;
    let flow =
        tokio::spawn(async move { services.tcp(local, &settings, "echo.test".into(), 7).await });
    let exchanged = async {
        let sent = vec![tag; 1024];
        app.write_all(&sent).await?;
        let mut echoed = vec![0; sent.len()];
        app.read_exact(&mut echoed).await?;
        anyhow::ensure!(echoed == sent, "echo mismatch");
        app.shutdown().await?;
        let mut rest = Vec::new();
        app.read_to_end(&mut rest).await?;
        anyhow::Ok(())
    };
    let exchanged = exchanged.await;
    flow.await??;
    exchanged
}

#[test]
fn held_relay_services_flow_burst_queues_within_the_flow_cap_and_completes() {
    use crate::establish_limit::{ACK_RESERVE, ESTABLISH_PERMITS};
    let limiter = EstablishLimiter::new(AuthBackoff::default());
    // Every establishment pays 100 ms at the relay (each connection before
    // its outer TLS, each stream before its 200), so the burst overlaps.
    let f = fixture_on(limiter.clone(), |_, config| {
        config.setup = Duration::from_millis(100);
        config.stream_setup = Duration::from_millis(100);
    });
    let flows = 24;
    let started = Instant::now();
    let results = f.runtime.block_on(async {
        let mut set = tokio::task::JoinSet::new();
        for tag in 0..flows {
            set.spawn(echo_flow(f.services.clone(), f.settings.clone(), tag));
        }
        tokio::time::timeout(Duration::from_secs(10), set.join_all())
            .await
            .expect("the burst never completed")
    });
    // Every queued flow completed within its signed budget.
    assert!(results.iter().all(Result::is_ok), "{results:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
    // One stream per flow, on at most the pool's connections.
    assert_eq!(f.relay.streams(), 1 + usize::from(flows));
    assert!(f.relay.conns() <= 1 + POOL_CONNS, "{}", f.relay.conns());
    // Flows never held more than their share, nor did the relay see more
    // concurrent handshakes, and the burst had to queue. S16h-7: the flow
    // share is the pool's handshake slots, so a burst queues for a stream
    // in the pool (no permit held) rather than at the limiter, whose queue
    // log the limiter's own tests cover.
    let cap = ESTABLISH_PERMITS - ACK_RESERVE;
    assert_eq!(limiter.high_water(), cap);
    assert!(f.relay.handshakes().high_water() <= cap);
    let stats = f.services.pool().stats();
    assert!(stats.max_waiting > cap, "{stats:?}");
    assert_eq!(limiter.flow_timeouts(), 0);
    assert_eq!(limiter.active(), (0, 0));
    assert_eq!(limiter.unverified(), 0);
    assert_eq!(limiter.live(), 0);
    assert_eq!(f.relay.handshakes().current(), 0);
}

#[test]
fn held_relay_services_a_flow_without_a_permit_is_refused_within_its_wait() {
    // Longer than the establish floor (S16j-1), so a flow's own deadline can
    // still end a dial's permit wait first.
    let wait = Duration::from_millis(800);
    const _: () = assert!(crate::flow_pool::ESTABLISH_MIN.as_millis() + 100 < 800);
    // `H_CONN` flow permits; all held by flows stalled in their inner
    // handshake on the one pooled connection, which then has no handshake
    // slot left.
    use crate::flow_pool::H_CONN;
    let limiter =
        EstablishLimiter::for_test_with_flow_wait(H_CONN + 1, 1, Duration::from_secs(2), wait);
    let f = fixture_on(limiter.clone(), |_, _| {});
    let opened = f
        .runtime
        .block_on(echo_flow(f.services.clone(), f.settings.clone(), 0));
    assert!(opened.is_ok(), "{opened:?}");
    for index in 2..2 + H_CONN {
        f.relay.at(index, StreamFault::StallHandshake);
    }
    let stalled = (1..=u8::try_from(H_CONN).unwrap())
        .map(|tag| {
            f.runtime
                .spawn(echo_flow(f.services.clone(), f.settings.clone(), tag))
        })
        .collect::<Vec<_>>();
    assert!(wait_until(Duration::from_secs(2), || limiter.active().1 == H_CONN));
    assert!(f
        .wait_count(StreamStep::HandshakeStalled, H_CONN, Duration::from_secs(2))
        .is_some());
    assert_eq!((f.relay.conns(), f.relay.streams()), (2, 2 + H_CONN));
    let started = Instant::now();
    let refused = f
        .runtime
        .block_on(echo_flow(f.services.clone(), f.settings.clone(), 9));
    let took = started.elapsed();
    // Its pooled dial found no permit: refused cleanly after its wait,
    // never dialed, its gate permit back.
    assert!(refused.is_err());
    assert!(took >= wait, "{took:?}");
    assert!(took < wait + Duration::from_secs(1), "{took:?}");
    assert_eq!(limiter.flow_timeouts(), 1);
    // S16i-1: logged as a permit wait, never as a failed dial: it sent no
    // SYN.
    assert_eq!(limiter.refusals(crate::flow_log::Refusal::PermitWait), 1);
    assert_eq!(limiter.refusals(crate::flow_log::Refusal::DialFailed), 0);
    assert!(logged_refusal(
        &limiter,
        crate::flow_log::Refusal::PermitWait
    ));
    // The flow's own deadline ending that permit wait first is a permit
    // wait too. S16j-1: it leaves its establish floor (the loopback round
    // trip is under a millisecond), so it still dials.
    let short = tokio::time::Instant::now()
        + crate::flow_pool::establish_floor(Duration::from_millis(1))
        + Duration::from_millis(100);
    let refused = f.runtime.block_on(f.services.pool().reserve(short));
    let error = refused.err().expect("reserved without a permit");
    assert!(crate::flow_pool::is_permit_wait(&error), "{error:?}");
    assert!(!crate::flow_pool::is_dial_failed(&error), "{error:?}");
    assert_eq!((f.relay.conns(), f.relay.streams()), (2, 2 + H_CONN));
    assert_eq!(f.gate.flows(), H_CONN);
    // The stalled flows end with the gate and return their permits; their
    // handshakes ended with the connection, never as strikes.
    f.gate.stop(MAX_DRAIN).unwrap();
    for flow in stalled {
        assert!(f.runtime.block_on(flow).unwrap().is_err());
    }
    assert_eq!(limiter.active(), (0, 0));
    assert_eq!(limiter.auth_failures(), 0);
    assert!(f
        .runtime
        .block_on(f.relay.wait_closed(1, Duration::from_secs(2)))
        .is_some());
    assert_eq!(f.relay.strikes(), 0);
}

#[test]
fn held_relay_services_a_dial_that_outlives_its_flow_after_its_permit_failed() {
    use crate::flow_pool::{is_dial_failed, is_permit_wait};
    // Every connection after the session's ACK is accepted and never
    // answered: the flow's dial gets its permit, sends its SYN and its
    // ClientHello, and runs out of the flow's budget in its outer TLS.
    let limiter = EstablishLimiter::new(AuthBackoff::default());
    let f = fixture_on(limiter.clone(), |_, config| {
        config.silent_from = Some(1);
    });
    // S16j-1: beyond its establish floor (an empty pool's is HS_FLOOR), so
    // it dials.
    let deadline = tokio::time::Instant::now()
        + crate::flow_pool::establish_floor(Duration::ZERO)
        + Duration::from_millis(300);
    let refused = f.runtime.block_on(f.services.pool().reserve(deadline));
    let error = refused.err().expect("reserved on a silent relay");
    assert!(is_dial_failed(&error), "{error:?}");
    assert!(!is_permit_wait(&error), "{error:?}");
    assert_eq!(f.relay.conns(), 2);
    assert_eq!(limiter.flow_timeouts(), 0);
    assert_eq!(limiter.active(), (0, 0));
}

#[test]
fn held_relay_services_an_auth_refused_flow_backs_off_and_never_loops() {
    use crate::establish_limit::AUTH_BACKOFF;
    let limiter = EstablishLimiter::new(AuthBackoff::default());
    // After the fixture's ACK, the relay refuses every device handshake
    // with a TLS alert.
    let f = fixture_on(limiter.clone(), |_, _| {});
    f.relay.always(Some(StreamFault::AlertInner));
    // An engine that retries each refused flow at once, for three seconds.
    let window = Duration::from_secs(3);
    let attempts = f.runtime.block_on(async {
        let mut attempts = 0usize;
        let _ = tokio::time::timeout(window, async {
            loop {
                attempts += 1;
                let refused = echo_flow(f.services.clone(), f.settings.clone(), 1).await;
                assert!(refused.is_err());
            }
        })
        .await;
        attempts
    });
    let first = f
        .wait_count(StreamStep::Alerted, 1, Duration::from_secs(1))
        .expect("the relay never refused a handshake");
    let second = f
        .wait_count(StreamStep::Alerted, 2, Duration::from_secs(1))
        .expect("the refused flow was never retried after the backoff");
    // One stream at once, one after the backoff, and nothing in between:
    // the retries in the meantime waited for the backoff instead of opening
    // a stream. The connection the first one idled on past reuse while it
    // waited, so the second dialed its own.
    assert_eq!(f.relay.streams(), 1 + 2, "{attempts} attempts");
    assert_eq!(f.relay.conns(), 1 + 2, "{attempts} attempts");
    assert!(second - first >= AUTH_BACKOFF - Duration::from_millis(50));
    assert_eq!(limiter.auth_failures(), 2);
    assert!(limiter.backing_off());
    assert!(attempts <= 3, "{attempts}");
    assert_eq!(limiter.active(), (0, 0));
}

#[test]
fn held_relay_services_a_device_refused_after_its_handshake_backs_off_its_flows() {
    // TLS 1.3: the client's inner handshake completes and the relay refuses
    // its certificate after it; the client sees the channel end before the
    // Open status, as with aegis-server, whose session-cap refusal looks the
    // same. An unanswered Open: flows back off, the ACK path does not.
    let limiter = EstablishLimiter::new(AuthBackoff::default());
    let f = fixture_on(limiter.clone(), |tree, config| {
        config.rejecting = Some(RelayIdentity::rejecting_device(tree));
    });
    f.relay.always(Some(StreamFault::RejectDevice));
    let refused = f
        .runtime
        .block_on(echo_flow(f.services.clone(), f.settings.clone(), 1));
    assert!(refused.is_err());
    f.wait_count(StreamStep::Alerted, 1, Duration::from_secs(1))
        .expect("the relay never refused the device");
    assert_eq!(limiter.flow_refusals(), 1);
    assert_eq!(limiter.auth_failures(), 0);
    assert!(limiter.flows_backing_off());
    assert!(limiter.flows_probing());
    assert!(!limiter.backing_off());
    // The next flow waits out the backoff before it dials: never a loop.
    let started = Instant::now();
    let refused = f
        .runtime
        .block_on(echo_flow(f.services.clone(), f.settings.clone(), 2));
    assert!(refused.is_err());
    assert!(
        started.elapsed() >= FLOW_BACKOFF - Duration::from_millis(100),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(f.relay.streams(), 1 + 2);
    assert_eq!(limiter.flow_refusals(), 2);
}

#[test]
fn held_relay_services_a_tls_error_at_the_open_status_is_an_auth_failure() {
    // The relay answers the Open with a record that is not valid TLS: a TLS
    // error after the handshake stays authentication class.
    let limiter = EstablishLimiter::new(AuthBackoff::default());
    let f = fixture_on(limiter.clone(), |_, _| {});
    f.relay.always(Some(StreamFault::GarbleOpen));
    let refused = f
        .runtime
        .block_on(echo_flow(f.services.clone(), f.settings.clone(), 1));
    assert!(refused.is_err());
    f.wait_count(StreamStep::OpenGarbled, 1, Duration::from_secs(1))
        .expect("the relay never answered the Open");
    assert_eq!(limiter.auth_failures(), 1);
    assert_eq!(limiter.flow_refusals(), 0);
    assert!(limiter.backing_off());
    assert!(limiter.probing());
}

#[test]
fn held_relay_services_black_holed_targets_never_hold_a_flow_permit() {
    use crate::establish_limit::{ACK_RESERVE, ESTABLISH_PERMITS};
    let limiter = EstablishLimiter::new(AuthBackoff::default());
    let cap = ESTABLISH_PERMITS - ACK_RESERVE;
    // More flows than flow permits to targets whose connect never ends.
    let held = cap + 1;
    let f = fixture_on(limiter.clone(), |_, _| {});
    f.relay.next_streams(held, StreamFault::HangTarget);
    let stalled = (0..held)
        .map(|tag| {
            let tag = u8::try_from(tag).unwrap();
            f.runtime
                .spawn(echo_flow(f.services.clone(), f.settings.clone(), tag))
        })
        .collect::<Vec<_>>();
    // Every one wrote its Open and awaits its status holding no permit.
    assert!(
        wait_until(Duration::from_secs(2), || limiter.unverified() == held),
        "{} awaiting, {:?} active",
        limiter.unverified(),
        limiter.active()
    );
    assert_eq!(limiter.active(), (0, 0));
    assert_eq!(f.relay.streams(), 1 + held);
    // A flow to a live target is not held up behind them.
    let started = Instant::now();
    let served = f
        .runtime
        .block_on(echo_flow(f.services.clone(), f.settings.clone(), 9));
    assert!(served.is_ok(), "{served:?}");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(limiter.flow_timeouts(), 0);
    assert_eq!(f.relay.streams(), 1 + held + 1);
    // The stalled flows end with the gate; nothing is left counted, and a
    // hanging target is neither an authentication failure nor unanswered.
    f.gate.stop(MAX_DRAIN).unwrap();
    for flow in stalled {
        assert!(f.runtime.block_on(flow).unwrap().is_err());
    }
    assert_eq!((limiter.active(), limiter.unverified()), ((0, 0), 0));
    assert_eq!(limiter.auth_failures(), 0);
    assert_eq!(limiter.flow_refusals(), 0);
}

/// A TCP echo flow through `services` that exchanges `tag` and then holds
/// its application side open until `release` is dropped or sent; returns
/// whether it opened, and when its open ended (opened or refused).
async fn held_echo_flow(
    services: Arc<HeldRelayServices>,
    settings: RelaySettings,
    tag: u8,
    mut release: tokio::sync::watch::Receiver<bool>,
) -> (anyhow::Result<()>, Duration) {
    let started = Instant::now();
    let (mut app, local) = loopback().await;
    let flow =
        tokio::spawn(async move { services.tcp(local, &settings, "echo.test".into(), 7).await });
    let mut echoed = [0u8; 1];
    let opened = async {
        app.write_all(&[tag]).await?;
        app.read_exact(&mut echoed).await?;
        anyhow::ensure!(echoed == [tag], "echo mismatch");
        anyhow::Ok(())
    }
    .await;
    let took = started.elapsed();
    if opened.is_err() {
        let refused = flow.await.unwrap();
        return (refused.and(opened), took);
    }
    let _ = release.wait_for(|go| *go).await;
    app.shutdown().await.unwrap();
    let mut rest = Vec::new();
    let _ = app.read_to_end(&mut rest).await;
    (flow.await.unwrap(), took)
}

#[test]
fn held_relay_services_a_flow_at_the_live_cap_waits_and_takes_a_returned_place() {
    // S16i-2: a flow beyond the live cap is no longer refused at once: it
    // waits, holding no stream and no live place, and takes the first one
    // returned.
    let mut limiter = EstablishLimiter::new(AuthBackoff::default());
    EstablishLimiter::tune(&mut limiter).set_flow_limits(FLOW_BACKOFF, FLOW_OPENS, 2);
    let f = fixture_on(limiter.clone(), |_, _| {});
    let (release, released) = tokio::sync::watch::channel(false);
    let live = (0..2)
        .map(|tag| {
            f.runtime.spawn(held_echo_flow(
                f.services.clone(),
                f.settings.clone(),
                tag,
                released.clone(),
            ))
        })
        .collect::<Vec<_>>();
    assert!(wait_until(Duration::from_secs(2), || {
        f.relay.count(StreamStep::Opened) == 2
    }));
    assert_eq!(limiter.live(), 2);
    let streams = f.relay.streams();
    let third = f
        .runtime
        .spawn(echo_flow(f.services.clone(), f.settings.clone(), 3));
    assert!(wait_until(Duration::from_secs(1), || limiter
        .live_waiting()
        == 1));
    thread::sleep(Duration::from_millis(100));
    // Queued: no stream reserved, no dial, no relay session, no refusal.
    assert_eq!(f.relay.streams(), streams);
    assert_eq!(f.pooled_streams(), 2);
    assert_eq!(limiter.live(), 2);
    assert!(!third.is_finished());
    // One live flow ends: the waiter takes its place and is served.
    live[0].abort();
    let served = f.runtime.block_on(third).unwrap();
    assert!(served.is_ok(), "{served:?}");
    assert_eq!(limiter.live_refusals(), 0);
    assert_eq!(limiter.refusals(crate::flow_log::Refusal::LiveCap), 0);
    assert_eq!(limiter.live_high_water(), 2);
    release.send(true).unwrap();
    for flow in live.into_iter().skip(1) {
        let (result, _) = f.runtime.block_on(flow).unwrap();
        assert!(result.is_ok(), "{result:?}");
    }
    assert!(wait_until(Duration::from_secs(2), || limiter.live() == 0));
    assert_eq!(limiter.live_waiting(), 0);
}

#[test]
fn held_relay_services_queued_flows_do_not_take_live_before_cap() {
    use crate::{flow_log::Refusal, flow_pool::Limits};
    const CAP: usize = 10;
    const FLOWS: usize = 30;
    let mut limiter = EstablishLimiter::new(AuthBackoff::default());
    EstablishLimiter::tune(&mut limiter).set_flow_limits(FLOW_BACKOFF, FLOW_OPENS, CAP);
    let f = fixture_on(limiter.clone(), |_, _| {});
    // One connection, one inner handshake at a time: the burst queues in
    // the pool and at the live cap, never in the relay.
    let narrow = FlowPool::with_limits(
        f.services.peer,
        RelayInterface::loopback_for_test(),
        f.services.crypto.clone(),
        (limiter.clone(), f.gate.clone()),
        (EpochPins::default(), 0),
        Limits {
            pool_conns: 1,
            h_conn: 1,
            pool_dials: 1,
            ..Limits::default()
        },
    )
    .unwrap();
    let narrow =
        Arc::new(HeldRelayServices::new(Arc::new(NoEvents), f.bridge.clone(), narrow).unwrap());
    let budget = Duration::from_millis(f.settings.connect_timeout_ms);
    let (release, released) = tokio::sync::watch::channel(false);
    // A probe of the limiter's live count, beside the relay's below.
    let probing = Arc::new(AtomicBool::new(true));
    let probe = {
        let (probing, limiter) = (probing.clone(), limiter.clone());
        thread::spawn(move || {
            let mut most = 0;
            while probing.load(Ordering::SeqCst) {
                most = most.max(limiter.live());
                thread::sleep(Duration::from_millis(1));
            }
            most
        })
    };
    let flows = (0..FLOWS)
        .map(|tag| {
            f.runtime.spawn(held_echo_flow(
                narrow.clone(),
                f.settings.clone(),
                u8::try_from(tag).unwrap(),
                released.clone(),
            ))
        })
        .collect::<Vec<_>>();
    // The relay's sessions: never more than the cap at once.
    let mut relay_most = 0;
    let deadline = Instant::now() + budget + Duration::from_secs(2);
    while Instant::now() < deadline && limiter.refusals(Refusal::LiveCap) < (FLOWS - CAP) as u64 {
        let live: usize = (1..f.relay.conns())
            .map(|conn| f.relay.connection(conn).live_streams())
            .sum();
        relay_most = relay_most.max(live);
        thread::sleep(Duration::from_millis(1));
    }
    release.send(true).unwrap();
    let outcomes: Vec<_> = flows
        .into_iter()
        .map(|flow| f.runtime.block_on(flow).unwrap())
        .collect();
    probing.store(false, Ordering::SeqCst);
    let limiter_most = probe.join().unwrap();
    let served = outcomes.iter().filter(|(result, _)| result.is_ok()).count();
    assert_eq!(served, CAP, "{outcomes:?}");
    // Every refused flow waited out its budget: none was refused while
    // under the cap, and each one past it as a live-cap refusal.
    for (result, took) in &outcomes {
        if result.is_err() {
            assert!(*took >= budget - Duration::from_millis(50), "{took:?}");
        }
    }
    assert_eq!(limiter.refusals(Refusal::LiveCap), (FLOWS - CAP) as u64);
    assert_eq!(limiter.live_refusals(), (FLOWS - CAP) as u64);
    assert!(logged_refusal(&limiter, Refusal::LiveCap));
    assert_eq!(limiter.refusals(Refusal::PoolWait), 0);
    // Never above the cap, at the limiter or at the relay; the refused
    // flows never reached the relay.
    assert!(limiter_most <= CAP, "{limiter_most}");
    assert_eq!(limiter.live_high_water(), CAP);
    assert!(relay_most <= CAP, "{relay_most}");
    assert_eq!(f.relay.streams(), 1 + CAP);
    assert!(wait_until(Duration::from_secs(2), || limiter.live() == 0));
    assert_eq!(limiter.live_waiting(), 0);
}

#[test]
fn held_relay_services_an_unanswered_open_backs_off_flows_but_not_the_ack_path() {
    let limiter = EstablishLimiter::new(AuthBackoff::default());
    // The relay ends every flow's channel before its Open status, as
    // aegis-server does at its session cap.
    let f = fixture_on(limiter.clone(), |_, _| {});
    f.relay.always(Some(StreamFault::RefuseOpen));
    let refused = f
        .runtime
        .block_on(echo_flow(f.services.clone(), f.settings.clone(), 1));
    assert!(refused.is_err());
    f.wait_count(StreamStep::OpenRefused, 1, Duration::from_secs(1))
        .expect("the relay never refused the Open");
    assert_eq!(limiter.flow_refusals(), 1);
    // Not an authentication failure: the epoch neither backs off nor
    // probes, and the ACK path starts at once.
    assert_eq!(limiter.auth_failures(), 0);
    assert!(!limiter.backing_off());
    assert!(!limiter.probing());
    assert!(limiter.flows_backing_off());
    let ack = f.runtime.block_on(async {
        (
            limiter.acquire(Purpose::Ack, Duration::ZERO).await,
            limiter.acquire(Purpose::Ack, Duration::ZERO).await,
        )
    });
    assert!(ack.0.is_ok() && ack.1.is_ok());
    drop(ack);
    // The next flow waits out the flows' backoff before it dials.
    let started = Instant::now();
    let refused = f
        .runtime
        .block_on(echo_flow(f.services.clone(), f.settings.clone(), 2));
    assert!(refused.is_err());
    assert!(
        started.elapsed() >= FLOW_BACKOFF - Duration::from_millis(100),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(f.relay.streams(), 1 + 2);
    assert_eq!(limiter.flow_refusals(), 2);
    assert_eq!(limiter.auth_failures(), 0);
    assert_eq!((limiter.active(), limiter.unverified()), ((0, 0), 0));
}

#[test]
fn held_relay_services_a_carrier_dropped_before_its_response_is_not_an_auth_failure() {
    let limiter = EstablishLimiter::new(AuthBackoff::default());
    let f = fixture_on(limiter.clone(), |_, _| {});
    f.relay.always(Some(StreamFault::DropConnection));
    for tag in 0..3 {
        let started = Instant::now();
        let refused = f
            .runtime
            .block_on(echo_flow(f.services.clone(), f.settings.clone(), tag));
        assert!(refused.is_err());
        // Retried at once: no backoff of either kind.
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
    }
    f.wait_count(StreamStep::CarrierDropped, 1, Duration::from_secs(1))
        .expect("the relay never dropped a carrier");
    // A connection lost before any Open was written: each flow was retried
    // exactly once, on a connection of its own.
    assert_eq!(f.relay.conns(), 1 + 2 * 3);
    assert_eq!(f.relay.streams(), 1 + 2 * 3);
    assert_eq!(f.relay.count(StreamStep::CarrierDropped), 2 * 3);
    assert_eq!(limiter.auth_failures(), 0);
    assert_eq!(limiter.flow_refusals(), 0);
    assert!(!limiter.backing_off());
    assert!(!limiter.probing());
    assert!(!limiter.flows_backing_off());
}

#[test]
fn held_relay_services_an_explicit_carrier_refusal_is_an_auth_failure() {
    let limiter = EstablishLimiter::new(AuthBackoff::default());
    let f = fixture_on(limiter.clone(), |_, _| {});
    f.relay.always(Some(StreamFault::RejectCarrier(403)));
    let refused = f
        .runtime
        .block_on(echo_flow(f.services.clone(), f.settings.clone(), 1));
    assert!(refused.is_err());
    f.wait_count(StreamStep::CarrierRejected, 1, Duration::from_secs(1))
        .expect("the relay never refused the carrier");
    assert_eq!(limiter.auth_failures(), 1);
    assert!(limiter.backing_off());
    assert!(limiter.probing());
    assert_eq!(limiter.flow_refusals(), 0);
}

/// One TCP flow that writes `sent` and half-closes at once, then reads to
/// EOF, as `printf ping | nc` does: what came back, when its FIN was
/// queued, and the flow's own result.
async fn half_closed_flow(
    services: Arc<HeldRelayServices>,
    settings: RelaySettings,
    sent: Vec<u8>,
) -> (Vec<u8>, Instant, anyhow::Result<()>) {
    let (mut app, local) = loopback().await;
    let flow =
        tokio::spawn(async move { services.tcp(local, &settings, "echo.test".into(), 7).await });
    app.write_all(&sent).await.unwrap();
    app.shutdown().await.unwrap();
    let fin = Instant::now();
    let mut echoed = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), app.read_to_end(&mut echoed))
        .await
        .expect("no echo and EOF within 2 s of the half-close")
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), flow)
        .await
        .expect("the flow outlived both ends")
        .unwrap();
    (echoed, fin, result)
}

/// A loopback TCP target served as the fleet relay's echo service serves
/// one: every chunk received is echoed at once, the socket closed at EOF.
fn echo_target() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                return;
            };
            thread::spawn(move || {
                let mut buffer = [0u8; 16 * 1024];
                loop {
                    match std::io::Read::read(&mut stream, &mut buffer) {
                        Ok(0) | Err(_) => return,
                        Ok(read) => {
                            if std::io::Write::write_all(&mut stream, &buffer[..read]).is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    address
}

/// The half-close cases of S16i-1 on `f`: `ping` then a FIN on an open
/// flow, 64 KiB then a FIN, and `ping` then a FIN queued on the local
/// socket before the flow's Open completed (its stream's 200 held 300 ms).
fn half_close_cases(f: &Fixture) {
    let flow = |sent: Vec<u8>| {
        f.runtime.block_on(half_closed_flow(
            f.services.clone(),
            f.settings.clone(),
            sent,
        ))
    };
    let (echoed, _, result) = flow(b"ping".to_vec());
    assert_eq!(echoed, b"ping");
    result.unwrap();
    let large: Vec<u8> = (0..64 * 1024).map(|at| (at % 251) as u8).collect();
    let (echoed, _, result) = flow(large.clone());
    assert!(echoed == large, "{} of {} bytes", echoed.len(), large.len());
    result.unwrap();
    let index = f.relay.streams();
    f.relay.delay_200(index, Duration::from_millis(300));
    let (echoed, fin, result) = flow(b"ping".to_vec());
    assert_eq!(echoed, b"ping");
    result.unwrap();
    let opened = f
        .runtime
        .block_on(
            f.relay
                .wait_step(index, StreamStep::Opened, Duration::from_secs(1)),
        )
        .expect("the delayed flow never opened");
    assert!(fin < opened, "the FIN followed the Open");
    // Every flow a stream of the one pooled connection.
    assert_eq!(f.relay.conns(), 2);
    assert_eq!(f.relay.streams(), 1 + 3);
}

#[test]
fn held_relay_services_tcp_write_half_close_then_read_echo() {
    half_close_cases(&fixture(Target::Echo));
}

#[test]
fn held_relay_services_tcp_half_close_through_a_server_faithful_target() {
    // The relay bridges a real loopback target with aegis-core's
    // copy_with_idle_timeout, as aegis-server secure.rs does.
    let target = echo_target();
    let f = fixture(Target::Socket(target));
    half_close_cases(&f);
    assert_eq!(f.relay.count(StreamStep::Ended), 3);
}

#[test]
fn held_relay_services_first_flow_after_a_predial_opens_no_tcp_connection() {
    use crate::flow_pool::{Phase, Prewarm};
    let f = fixture(Target::Echo);
    let pool = f.services.pool().clone();
    let limiter = f.services.limiter().clone();
    let prewarm = {
        let pool = pool.clone();
        f.runtime.spawn(async move { pool.prewarm().await })
    };
    // S16j-1: two pre-dials at once.
    assert!(wait_until(Duration::from_secs(2), || pool.views().len() == 2));
    assert_eq!(f.relay.conns(), 3);
    for view in pool.views() {
        assert_eq!(
            (view.phase, view.streams, view.opened),
            (Phase::Probing, 0, 0)
        );
    }
    // Ready, they hold no live flow, no permit and no gate flow.
    assert_eq!(limiter.live(), 0);
    assert_eq!(limiter.active(), (0, 0));
    assert_eq!(f.gate.flows(), 0);
    // A later pre-dial finds the pool taken.
    assert_eq!(
        f.runtime.block_on(pool.prewarm()),
        [Prewarm::Busy, Prewarm::Busy]
    );
    let served = f
        .runtime
        .block_on(echo_flow(f.services.clone(), f.settings.clone(), 1));
    assert!(served.is_ok(), "{served:?}");
    // The flow took a pre-dial's probe: no TCP connection of its own.
    assert_eq!(f.relay.conns(), 3);
    assert_eq!(f.relay.streams(), 1 + 1);
    let stats = pool.stats();
    assert_eq!((stats.dials, stats.prewarms), (2, 2), "{stats:?}");
    let prewarmed = f.runtime.block_on(prewarm).unwrap();
    assert!(
        prewarmed
            .iter()
            .all(|prewarm| matches!(prewarm, Prewarm::Dialed(_))),
        "{prewarmed:?}"
    );
    let lines = limiter.flow_log_lines();
    for wanted in ["pool_prewarm dialed", "pool_prewarm busy"] {
        assert!(lines.contains(&wanted.to_owned()), "{lines:?}");
    }
    // The other pre-dial no flow took closed at the pool's idle rule.
    let unused = lines
        .iter()
        .filter(|line| *line == "pool_prewarm unused")
        .count();
    assert_eq!(unused, 1, "{lines:?}");
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("flow_open ok ms:")),
        "{lines:?}"
    );
}

#[test]
fn held_relay_services_an_unused_predial_closes_at_the_pool_idle_rule() {
    use crate::{
        flow_pool::{Prewarm, IDLE_REUSE},
        test_relay::pool::Close,
    };
    let f = fixture(Target::Echo);
    let pool = f.services.pool().clone();
    let limiter = f.services.limiter().clone();
    let started = Instant::now();
    let prewarmed = f.runtime.block_on(pool.prewarm());
    assert!(
        prewarmed
            .iter()
            .all(|prewarm| matches!(prewarm, Prewarm::Dialed(_))),
        "{prewarmed:?}"
    );
    assert!(started.elapsed() >= IDLE_REUSE);
    assert!(pool.views().is_empty());
    // Both closed by this side, long before the relay's admission idle
    // close.
    for conn in [1, 2] {
        let closed = f
            .runtime
            .block_on(f.relay.wait_closed(conn, Duration::from_secs(2)))
            .expect("an unused pre-dial stayed open");
        assert_ne!(closed.1, Close::Idle);
        assert!(closed.0 - started < Duration::from_secs(3));
    }
    let unused = limiter
        .flow_log_lines()
        .iter()
        .filter(|line| *line == "pool_prewarm unused")
        .count();
    assert_eq!(unused, 2);
    assert_eq!((limiter.live(), limiter.active()), (0, (0, 0)));
    assert_eq!(f.relay.strikes(), 0);
    // The next flow dials its own connection.
    let served = f
        .runtime
        .block_on(echo_flow(f.services.clone(), f.settings.clone(), 1));
    assert!(served.is_ok(), "{served:?}");
    assert_eq!(f.relay.conns(), 4);
    assert_eq!(pool.stats().dials, 3);
}

#[test]
fn held_relay_services_no_predial_on_an_old_pin_or_before_the_wake() {
    use crate::flow_pool::Prewarm;
    let epoch = AuthBackoff::default();
    let limiter = EstablishLimiter::new(epoch.clone());
    // Each connection waits 300 ms before its outer TLS.
    let f = fixture_on(limiter.clone(), |_, config| {
        config.setup = Duration::from_millis(300);
    });
    let pool_on = |pins: &EpochPins| {
        f.observed
            .flow_pool((limiter.clone(), f.gate.clone()), (pins.clone(), 0))
            .unwrap()
    };
    // Re-pinned before: nothing dialed, and a flow on it is closed.
    let old = EpochPins::default();
    let stale = pool_on(&old);
    old.repin(&RelayInterface::loopback_for_test());
    assert_eq!(
        f.runtime.block_on(stale.prewarm()),
        [Prewarm::Stale, Prewarm::Stale]
    );
    let services = Arc::new(
        HeldRelayServices::new(Arc::new(NoEvents), f.bridge.clone(), stale.clone()).unwrap(),
    );
    assert!(f
        .runtime
        .block_on(echo_flow(services, f.settings.clone(), 1))
        .is_err());
    assert_eq!(f.relay.conns(), 1);
    // Re-pinned during its dial: closed, never pooled.
    let moving = EpochPins::default();
    let during = pool_on(&moving);
    let dial = {
        let during = during.clone();
        f.runtime.spawn(async move { during.prewarm().await })
    };
    // S16j-1: both pre-dials reached the relay.
    assert!(wait_until(Duration::from_secs(2), || f.relay.conns() == 3));
    moving.repin(&RelayInterface::loopback_for_test());
    assert_eq!(
        f.runtime.block_on(dial).unwrap(),
        [Prewarm::Stale, Prewarm::Stale]
    );
    assert!(during.views().is_empty());
    // Before the wake: nothing dialed; after it, the control dials.
    let current = EpochPins::default();
    let pool = pool_on(&current);
    epoch.quiesce(std::time::Instant::now());
    assert_eq!(
        f.runtime.block_on(pool.prewarm()),
        [Prewarm::Held, Prewarm::Held]
    );
    thread::sleep(Duration::from_millis(100));
    assert_eq!(f.relay.conns(), 3);
    epoch.resume();
    let _dial = {
        let pool = pool.clone();
        f.runtime.spawn(async move { pool.prewarm().await })
    };
    assert!(wait_until(Duration::from_secs(2), || pool.views().len() == 2));
    assert_eq!(f.relay.conns(), 5);
    let lines = limiter.flow_log_lines();
    for wanted in [
        "pool_prewarm stale",
        "pool_prewarm held",
        "pool_prewarm dialed",
    ] {
        assert!(lines.contains(&wanted.to_owned()), "{lines:?}");
    }
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("flow_open closed ms:")),
        "{lines:?}"
    );
}

#[test]
fn held_relay_services_no_predial_during_a_backoff() {
    use crate::flow_pool::Prewarm;
    let limiter = EstablishLimiter::new(AuthBackoff::default());
    let f = fixture_on(limiter.clone(), |_, _| {});
    let pool = f.services.pool().clone();
    // The flows' own backoff after an unanswered Open.
    limiter.flow_unanswered();
    assert_eq!(
        f.runtime.block_on(pool.prewarm()),
        [Prewarm::Held, Prewarm::Held]
    );
    // The epoch's after an authentication failure.
    limiter.auth_failure(Purpose::Flow);
    assert_eq!(
        f.runtime.block_on(pool.prewarm()),
        [Prewarm::Held, Prewarm::Held]
    );
    thread::sleep(Duration::from_millis(200));
    assert_eq!(f.relay.conns(), 1);
    let stats = pool.stats();
    assert_eq!((stats.dials, stats.prewarms), (0, 0));
    assert_eq!(limiter.active(), (0, 0));
    let held = limiter
        .flow_log_lines()
        .iter()
        .filter(|line| *line == "pool_prewarm held")
        .count();
    assert_eq!(held, 4);
}

/// Connection setup (before the relay's outer TLS) slower than the pool's
/// `IDLE_REUSE`, so a new connection arrives past it.
const SLOW_SETUP: Duration = Duration::from_millis(1_100);

#[test]
fn held_relay_services_a_dial_slower_than_idle_reuse_serves_its_flow() {
    use crate::flow_pool::IDLE_REUSE;
    const _: () = assert!(SLOW_SETUP.as_millis() > IDLE_REUSE.as_millis());
    let limiter = EstablishLimiter::new(AuthBackoff::default());
    let f = fixture_on(limiter.clone(), |_, config| {
        config.setup = SLOW_SETUP;
    });
    let started = Instant::now();
    let served = f
        .runtime
        .block_on(echo_flow(f.services.clone(), f.settings.clone(), 1));
    assert!(served.is_ok(), "{served:?}");
    // Its own dial's probe carried it: one dial, never a second.
    assert!(
        started.elapsed() < SLOW_SETUP * 2,
        "{:?}",
        started.elapsed()
    );
    assert_eq!(f.services.pool().stats().dials, 1);
    assert_eq!((f.relay.conns(), f.relay.streams()), (2, 1 + 1));
    assert!(
        limiter
            .flow_log_lines()
            .iter()
            .any(|line| line.starts_with("flow_open ok ms:")),
        "{:?}",
        limiter.flow_log_lines()
    );
    assert_eq!(f.relay.strikes(), 0);
}

#[test]
fn held_relay_services_a_slow_predial_serves_the_flow_that_waited_for_it() {
    use crate::flow_pool::Prewarm;
    let limiter = EstablishLimiter::new(AuthBackoff::default());
    let f = fixture_on(limiter.clone(), |_, config| {
        config.setup = SLOW_SETUP;
    });
    let pool = f.services.pool().clone();
    let started = Instant::now();
    let prewarm = {
        let pool = pool.clone();
        f.runtime.spawn(async move { pool.prewarm().await })
    };
    // The pre-dials are in flight; a flow arrives and waits for them.
    assert!(wait_until(Duration::from_secs(1), || pool.queue().1 == 2));
    let flow = f
        .runtime
        .spawn(echo_flow(f.services.clone(), f.settings.clone(), 1));
    assert!(wait_until(Duration::from_secs(1), || pool.queue().0 == 1));
    assert!(started.elapsed() < SLOW_SETUP, "{:?}", started.elapsed());
    let served = f.runtime.block_on(flow).unwrap();
    assert!(served.is_ok(), "{served:?}");
    // It rode a pre-dial, which arrived past IDLE_REUSE: no dial of its
    // own, no third connection.
    assert!(
        started.elapsed() < SLOW_SETUP * 2,
        "{:?}",
        started.elapsed()
    );
    let stats = pool.stats();
    assert_eq!((stats.dials, stats.prewarms), (2, 2), "{stats:?}");
    assert_eq!((f.relay.conns(), f.relay.streams()), (3, 1 + 1));
    let prewarmed = f.runtime.block_on(prewarm).unwrap();
    assert!(
        prewarmed
            .iter()
            .all(|prewarm| matches!(prewarm, Prewarm::Dialed(_))),
        "{prewarmed:?}"
    );
    let lines = limiter.flow_log_lines();
    assert!(
        lines.contains(&"pool_prewarm dialed".to_owned()),
        "{lines:?}"
    );
    // The other pre-dial no flow took, after its probe's last chance.
    let unused = lines
        .iter()
        .filter(|line| *line == "pool_prewarm unused")
        .count();
    assert_eq!(unused, 1, "{lines:?}");
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("flow_open ok ms:")),
        "{lines:?}"
    );
    assert_eq!(f.relay.strikes(), 0);
}

#[test]
fn held_relay_services_a_ramped_slot_past_idle_reuse_serves_the_flow_that_took_it() {
    // S16j-1: on a proven pool a Probing connection whose first 200 arrived,
    // its probe still in its inner handshake past IDLE_REUSE of its TCP
    // connect, offers a second handshake slot. The flow that takes it gets
    // its permit at once and opens on it: it does not give the slot back and
    // take it again, each take another stream of the connection's budget,
    // until the connection drains and the flow dials a third one.
    use crate::flow_pool::{Phase, H_CONN, IDLE_REUSE};
    let limiter = EstablishLimiter::new(AuthBackoff::default());
    let f = fixture_on(limiter.clone(), |_, _| {});
    let pool = f.services.pool().clone();
    let (release, released) = tokio::sync::watch::channel(false);
    // Connection A authenticates a flow that lives on: the pool is proven.
    let first = f.runtime.spawn(held_echo_flow(
        f.services.clone(),
        f.settings.clone(),
        1,
        released,
    ));
    assert!(wait_until(Duration::from_secs(5), || {
        f.relay.count(StreamStep::Opened) == 1
    }));
    assert!(pool.proven());
    // The next `H_CONN + 1` streams stall in their inner handshake:
    // `H_CONN` hold A's handshake slots, the last is the probe of connection
    // C, which the last of those flows dials.
    f.relay
        .next_streams(H_CONN + 1, StreamFault::StallHandshake);
    let last = 2 + u8::try_from(H_CONN).unwrap();
    let stalled = (2..=last)
        .map(|tag| {
            f.runtime
                .spawn(echo_flow(f.services.clone(), f.settings.clone(), tag))
        })
        .collect::<Vec<_>>();
    assert!(wait_until(Duration::from_secs(2), || {
        f.relay.count(StreamStep::HandshakeStalled) == H_CONN + 1
    }));
    let views = pool.views();
    let c = views
        .iter()
        .find(|view| view.phase == Phase::Probing)
        .expect("no probing connection")
        .id;
    let conn = pool.conn_for_test(c).unwrap();
    // Its probe's 200, sent before the relay stalled, reaches the client.
    assert!(wait_until(Duration::from_secs(1), || conn.answered()));
    // Past IDLE_REUSE of C's connect, its probe unauthenticated.
    let past = IDLE_REUSE + Duration::from_millis(100);
    thread::sleep(past.saturating_sub(conn.connect_started().elapsed()));
    let streams = f.relay.streams();
    let served = f
        .runtime
        .block_on(echo_flow(f.services.clone(), f.settings.clone(), last + 1));
    assert!(served.is_ok(), "{served:?}");
    // It opened on C's second slot (C opens with it): C took two streams,
    // no third connection was dialed, and the relay saw this flow's one
    // stream.
    let view = pool
        .views()
        .into_iter()
        .find(|view| view.id == c)
        .expect("C left the pool");
    assert_eq!((view.phase, view.opened), (Phase::Open, 2), "{view:?}");
    assert_eq!(pool.stats().dials, 2);
    assert_eq!(f.relay.conns(), 1 + 2);
    assert_eq!(f.relay.streams(), streams + 1);
    release.send(true).unwrap();
    let (first, _) = f.runtime.block_on(first).unwrap();
    assert!(first.is_ok(), "{first:?}");
    for flow in stalled {
        flow.abort();
    }
}

/// Whether the epoch of `limiter` logged `class`'s first refusal.
fn logged_refusal(limiter: &EstablishLimiter, class: crate::flow_log::Refusal) -> bool {
    let wanted = format!("flow_refused class:{} n:1", class.code());
    limiter.flow_log_lines().contains(&wanted)
}

#[test]
fn held_relay_services_flow_refusals_are_logged_by_class() {
    use crate::flow_log::Refusal;
    let limiter = EstablishLimiter::new(AuthBackoff::default());
    let f = fixture_on(limiter.clone(), |_, _| {});
    let flow = |tag| {
        f.runtime
            .block_on(echo_flow(f.services.clone(), f.settings.clone(), tag))
    };
    assert!(flow(0).is_ok());
    assert!(
        limiter
            .flow_log_lines()
            .iter()
            .any(|line| line.starts_with("flow_open ok ms:")),
        "{:?}",
        limiter.flow_log_lines()
    );
    // A pool dial that fails before any SYN: its flow's own dial failed.
    let gone = FlowPool::new(
        f.services.peer,
        RelayInterface::for_test("en99", 0x7fff_0000),
        f.services.crypto.clone(),
        (limiter.clone(), f.gate.clone()),
        (EpochPins::default(), 0),
    )
    .unwrap();
    let gone =
        Arc::new(HeldRelayServices::new(Arc::new(NoEvents), f.bridge.clone(), gone).unwrap());
    assert!(f
        .runtime
        .block_on(echo_flow(gone, f.settings.clone(), 1))
        .is_err());
    assert_eq!(limiter.refusals(Refusal::DialFailed), 1);
    assert!(logged_refusal(&limiter, Refusal::DialFailed));
    // The relay's answers, one class each; the unanswered Open last, as
    // it backs flows off.
    for (fault, class) in [
        (StreamFault::RefuseTarget, Refusal::StatusRefused),
        (
            StreamFault::ResetBefore200(h2::Reason::REFUSED_STREAM),
            Refusal::CarrierReset,
        ),
        (StreamFault::RefuseAfter200, Refusal::HsRefused),
        (StreamFault::DropConnection, Refusal::ConnLost),
        (StreamFault::AlertInner, Refusal::Auth),
    ] {
        f.relay.always(Some(fault));
        assert!(flow(2).is_err(), "{fault:?}");
        f.relay.always(None);
        assert_eq!(
            limiter.refusals(class),
            1,
            "{fault:?} {:?}",
            limiter.flow_log_lines()
        );
        assert!(logged_refusal(&limiter, class), "{fault:?}");
        if class == Refusal::Auth {
            // Out of the epoch's backoff before the next.
            thread::sleep(crate::establish_limit::AUTH_BACKOFF);
        }
    }
    f.relay.always(Some(StreamFault::RefuseOpen));
    assert!(flow(3).is_err());
    assert_eq!(limiter.refusals(Refusal::Unanswered), 1);
    assert!(logged_refusal(&limiter, Refusal::Unanswered));
    for class in [Refusal::PoolWait, Refusal::PermitWait, Refusal::Other] {
        assert_eq!(limiter.refusals(class), 0, "{class:?}");
    }
}

#[test]
fn held_relay_services_a_stream_without_a_permit_is_logged_as_permit_wait() {
    use crate::flow_log::Refusal;
    let wait = Duration::from_millis(300);
    // One flow permit: a flow stalled in its inner handshake holds it while
    // its Open connection still offers a second handshake slot.
    let limiter = EstablishLimiter::for_test_with_flow_wait(2, 1, Duration::from_secs(2), wait);
    let f = fixture_on(limiter.clone(), |_, _| {});
    let opened = f
        .runtime
        .block_on(echo_flow(f.services.clone(), f.settings.clone(), 0));
    assert!(opened.is_ok(), "{opened:?}");
    f.relay.at(2, StreamFault::StallHandshake);
    let stalled = f
        .runtime
        .spawn(echo_flow(f.services.clone(), f.settings.clone(), 1));
    assert!(f
        .wait_count(StreamStep::HandshakeStalled, 1, Duration::from_secs(2))
        .is_some());
    assert_eq!(limiter.active().1, 1);
    let refused = f
        .runtime
        .block_on(echo_flow(f.services.clone(), f.settings.clone(), 2));
    assert!(refused.is_err());
    // It reserved a stream and never sent it.
    assert_eq!((f.relay.conns(), f.relay.streams()), (2, 3));
    assert_eq!(limiter.refusals(Refusal::PermitWait), 1);
    assert!(logged_refusal(&limiter, Refusal::PermitWait));
    f.gate.stop(MAX_DRAIN).unwrap();
    assert!(f.runtime.block_on(stalled).unwrap().is_err());
    // The gate ended the stalled flow: its connection's end found its
    // retry's session closed, or its open was dropped unfinished.
    assert!(
        limiter.flow_log_lines().iter().any(|line| {
            line.starts_with("flow_open closed ms:") || line.starts_with("flow_open dropped ms:")
        }),
        "{:?}",
        limiter.flow_log_lines()
    );
}

#[test]
fn held_relay_services_a_stalled_handshake_is_logged_as_hs_inner() {
    use crate::flow_log::Refusal;
    let limiter = EstablishLimiter::new(AuthBackoff::default());
    let f = fixture_on(limiter.clone(), |_, _| {});
    f.relay.next_streams(1, StreamFault::StallHandshake);
    let refused = f
        .runtime
        .block_on(echo_flow(f.services.clone(), f.settings.clone(), 1));
    assert!(refused.is_err());
    // S16j-1: past its 200, apart from a carrier's own bound.
    assert_eq!(
        limiter.refusals(Refusal::HsInner),
        1,
        "{:?}",
        limiter.flow_log_lines()
    );
    assert_eq!(limiter.refusals(Refusal::HsBound), 0);
    assert!(logged_refusal(&limiter, Refusal::HsInner));
    assert_eq!(f.relay.strikes(), 0);
}

#[test]
fn held_relay_services_a_target_without_a_status_is_logged_as_status_budget() {
    use crate::flow_log::Refusal;
    let limiter = EstablishLimiter::new(AuthBackoff::default());
    let f = fixture_on(limiter.clone(), |_, _| {});
    f.relay.next_streams(1, StreamFault::HangTarget);
    let refused = f
        .runtime
        .block_on(echo_flow(f.services.clone(), f.settings.clone(), 1));
    assert!(refused.is_err());
    assert_eq!(
        limiter.refusals(Refusal::StatusBudget),
        1,
        "{:?}",
        limiter.flow_log_lines()
    );
    assert!(logged_refusal(&limiter, Refusal::StatusBudget));
}

#[test]
fn held_relay_services_a_flow_with_no_pool_stream_is_logged_as_pool_wait() {
    use crate::{flow_log::Refusal, flow_pool::Limits};
    let limiter = EstablishLimiter::new(AuthBackoff::default());
    let f = fixture_on(limiter.clone(), |_, config| {
        config.target = Target::Stall;
    });
    // A pool of one connection of one stream, which a live flow holds.
    let narrow = FlowPool::with_limits(
        f.services.peer,
        RelayInterface::loopback_for_test(),
        f.services.crypto.clone(),
        (limiter.clone(), f.gate.clone()),
        (EpochPins::default(), 0),
        Limits {
            pool_conns: 1,
            streams_per_conn: 1,
            pool_dials: 1,
            ..Limits::default()
        },
    )
    .unwrap();
    let narrow =
        Arc::new(HeldRelayServices::new(Arc::new(NoEvents), f.bridge.clone(), narrow).unwrap());
    let (_held_app, held_local) = f.runtime.block_on(loopback());
    let held = {
        let narrow = narrow.clone();
        let settings = f.settings.clone();
        f.runtime.spawn(async move {
            narrow
                .tcp(held_local, &settings, "stall.test".into(), 9)
                .await
        })
    };
    f.wait_count(StreamStep::Opened, 1, Duration::from_secs(2))
        .expect("the holding flow never opened");
    let budget = Duration::from_millis(f.settings.connect_timeout_ms);
    let started = Instant::now();
    let refused = f.runtime.block_on(async {
        let (_app, local) = loopback().await;
        narrow.tcp(local, &f.settings, "stall.test".into(), 9).await
    });
    assert!(refused.is_err());
    // S16j-1: refused once less than its establish floor was left (the
    // loopback round trip is far under a millisecond), before its deadline.
    let waited = started.elapsed();
    let floor = crate::flow_pool::establish_floor(Duration::ZERO);
    assert!(
        waited >= budget - floor - Duration::from_millis(50) && waited < budget,
        "{waited:?}"
    );
    assert_eq!((f.relay.conns(), f.relay.streams()), (2, 2));
    assert_eq!(limiter.refusals(Refusal::PoolWait), 1);
    assert!(logged_refusal(&limiter, Refusal::PoolWait));
    let lines = limiter.flow_log_lines();
    assert!(
        lines.contains(&"pool_state conns:1-0-0 streams:1 waiting:1".to_owned()),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("pool_detail oldest_ms:")),
        "{lines:?}"
    );
    f.gate.stop(MAX_DRAIN).unwrap();
    assert!(f.runtime.block_on(held).unwrap().is_err());
}

#[test]
fn held_relay_services_a_200_later_than_its_bound_is_logged_as_hs_bound() {
    use crate::{flow_log::Refusal, flow_pool::HS_WATCHDOG};
    let limiter = EstablishLimiter::new(AuthBackoff::default());
    let f = fixture_on(limiter.clone(), |_, _| {});
    // The relay answers PINGs but holds this stream's 200 past its
    // handshake bound: no connection loss, the stream's own bound.
    f.relay
        .delay_200(f.relay.streams(), HS_WATCHDOG + Duration::from_secs(1));
    let started = Instant::now();
    let refused = f
        .runtime
        .block_on(echo_flow(f.services.clone(), f.settings.clone(), 1));
    assert!(refused.is_err());
    assert!(started.elapsed() >= HS_WATCHDOG, "{:?}", started.elapsed());
    assert_eq!(
        limiter.refusals(Refusal::HsBound),
        1,
        "{:?}",
        limiter.flow_log_lines()
    );
    assert!(logged_refusal(&limiter, Refusal::HsBound));
}

#[test]
fn held_relay_services_idle_flow_reaped_after_relay_idle() {
    // S16i-2, on the clock's own arithmetic (this crate's tokio has no
    // paused test clock): a flow with no byte either way is due 62 s after
    // its last one, the relay's 60 s and a margin; one byte at 59 s keeps
    // it to 121 s, and an earlier touch never moves it back.
    assert_eq!(RELAY_IDLE_REAP, RELAY_IDLE + Duration::from_secs(2));
    let start = tokio::time::Instant::now();
    let clock = IdleClock::new(start);
    assert_eq!(clock.due(RELAY_IDLE_REAP), start + Duration::from_secs(62));
    clock.touch(start + Duration::from_secs(59));
    assert_eq!(clock.due(RELAY_IDLE_REAP), start + Duration::from_secs(121));
    clock.touch(start + Duration::from_secs(30));
    assert_eq!(clock.due(RELAY_IDLE_REAP), start + Duration::from_secs(121));
    assert!(clock.due(RELAY_IDLE_REAP) > start + Duration::from_millis(120_999));

    // End to end on a short idle: a silent flow ends on this side once
    // idle, returning its live place and its stream; a flow with a byte
    // every third of that idle is never ended so.
    let idle = Duration::from_millis(400);
    let f = fixture(Target::Echo);
    let limiter = f.services.limiter().clone();
    let reaping = Arc::new(
        HeldRelayServices::new(
            Arc::new(NoEvents),
            f.bridge.clone(),
            f.services.pool().clone(),
        )
        .unwrap()
        .with_idle_reap(idle),
    );
    let (mut silent_app, silent_local) = f.runtime.block_on(loopback());
    let (mut busy_app, busy_local) = f.runtime.block_on(loopback());
    let silent = {
        let (reaping, settings) = (reaping.clone(), f.settings.clone());
        f.runtime.spawn(async move {
            let result = reaping
                .tcp(silent_local, &settings, "echo.test".into(), 7)
                .await;
            (result, Instant::now())
        })
    };
    let busy = {
        let (reaping, settings) = (reaping.clone(), f.settings.clone());
        f.runtime.spawn(async move {
            reaping
                .tcp(busy_local, &settings, "echo.test".into(), 7)
                .await
        })
    };
    // The reference instant is taken before the byte is sent, so it lies
    // before the extension's last touch (its write of the echo to this
    // socket), never after the app's own, load-dependent wake-up on it.
    let last_byte = f.runtime.block_on(async {
        let sent = Instant::now();
        silent_app.write_all(b"s").await.unwrap();
        let mut echoed = [0u8; 1];
        silent_app.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, *b"s");
        sent
    });
    assert!(wait_until(Duration::from_secs(1), || limiter.live() == 2));
    let kept = f.runtime.block_on(async {
        let mut echoed = [0u8; 1];
        // Three idle times of traffic, a byte every third of one.
        for round in 0..9u8 {
            busy_app.write_all(&[round]).await.unwrap();
            busy_app.read_exact(&mut echoed).await.unwrap();
            assert_eq!(echoed, [round]);
            tokio::time::sleep(idle / 3).await;
        }
        true
    });
    assert!(kept);
    let (result, ended) = f
        .runtime
        .block_on(async { tokio::time::timeout(Duration::from_secs(5), silent).await })
        .expect("the silent flow was never reaped")
        .unwrap();
    let error = result.expect_err("the silent flow ended without a reap");
    assert!(
        error
            .downcast_ref::<io::Error>()
            .is_some_and(crate::held_relay_services::is_idle_reaped),
        "{error:#}"
    );
    let after = ended - last_byte;
    assert!(after >= idle, "{after:?}");
    assert!(after < idle + Duration::from_millis(300), "{after:?}");
    assert_eq!(limiter.idle_reaps(), 1);
    // Its place and its stream are back; the busy flow still runs.
    assert!(wait_until(Duration::from_secs(1), || limiter.live() == 1));
    assert!(wait_until(Duration::from_secs(1), || f.pooled_streams() == 1));
    assert!(!busy.is_finished());
    f.runtime.block_on(async {
        busy_app.shutdown().await.unwrap();
        let mut rest = Vec::new();
        busy_app.read_to_end(&mut rest).await.unwrap();
        let _ = silent_app.read_to_end(&mut rest).await;
    });
    assert!(f.runtime.block_on(busy).unwrap().is_ok());
    assert_eq!(limiter.idle_reaps(), 1);
    assert!(wait_until(Duration::from_secs(1), || limiter.live() == 0));
}

#[test]
fn held_relay_services_a_flow_waiting_for_a_pool_stream_holds_no_live_place() {
    // S16i-2: a flow takes its live place only with its reserved stream,
    // so one queued in the pool counts against no relay session.
    use crate::flow_pool::Limits;
    let limiter = EstablishLimiter::new(AuthBackoff::default());
    let f = fixture_on(limiter.clone(), |_, _| {});
    // A pool of one connection of one stream, which a live flow holds.
    let narrow = FlowPool::with_limits(
        f.services.peer,
        RelayInterface::loopback_for_test(),
        f.services.crypto.clone(),
        (limiter.clone(), f.gate.clone()),
        (EpochPins::default(), 0),
        Limits {
            pool_conns: 1,
            streams_per_conn: 1,
            pool_dials: 1,
            ..Limits::default()
        },
    )
    .unwrap();
    let narrow =
        Arc::new(HeldRelayServices::new(Arc::new(NoEvents), f.bridge.clone(), narrow).unwrap());
    let (release, released) = tokio::sync::watch::channel(false);
    let first = f.runtime.spawn(held_echo_flow(
        narrow.clone(),
        f.settings.clone(),
        1,
        released.clone(),
    ));
    assert!(wait_until(Duration::from_secs(2), || {
        f.relay.count(StreamStep::Opened) == 1
    }));
    let second = f.runtime.spawn(held_echo_flow(
        narrow.clone(),
        f.settings.clone(),
        2,
        released.clone(),
    ));
    assert!(wait_until(Duration::from_secs(1), || {
        narrow.pool().queue().0 == 1
    }));
    thread::sleep(Duration::from_millis(50));
    // Waiting for its stream: no live place, no live wait.
    assert_eq!(limiter.live(), 1);
    assert_eq!(limiter.live_waiting(), 1);
    assert_eq!(f.relay.count(StreamStep::Opened), 1);
    first.abort();
    assert!(wait_until(Duration::from_secs(2), || {
        f.relay.count(StreamStep::Opened) == 2
    }));
    assert_eq!(limiter.live(), 1);
    assert_eq!(limiter.live_waiting(), 0);
    release.send(true).unwrap();
    let (result, _) = f.runtime.block_on(second).unwrap();
    assert!(result.is_ok(), "{result:?}");
    assert!(wait_until(Duration::from_secs(2), || limiter.live() == 0));
}
