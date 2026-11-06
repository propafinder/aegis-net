//! The session's persistent ACK connection (B-06 S16l) against the
//! multi-stream relay, which serves every stream of every connection as its
//! own secure session, as aegis-server does, behind a 170 ms latency link
//! (`TestLink`): every PolicyAck is a stream of one TCP connection, apart
//! from the flow pool's, and the ACK path falls back to its own dials while
//! that connection is down.
use crate::{
    app_group::CapturedAppGroupInputs,
    establish_limit::{EstablishLimiter, ACK_RESERVE, ESTABLISH_PERMITS},
    flow_pool::POOL_CONNS,
    provider_session::{
        relay::{echo, production_bridge, recorder, runtime, times, ArmedHandles, Steps},
        SessionHandle, SessionPhase,
    },
    provider_session_body::{
        spawn_link,
        tests::{frame, saved, store_locked},
        EpochPins, LinkOptions, LinkSlot, Renewals,
    },
    relay_socket::RelayInterface,
    test_fixture::ReadyTree,
    test_link::{TestLink, DEFAULT_RTT},
    test_relay::{
        pool::{Close, PoolConfig, PooledRelay, StreamFault, StreamStep},
        AckReply, RelayIdentity, TestRelay,
    },
};
use std::{
    collections::BTreeSet,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

const RTT: Duration = DEFAULT_RTT;
/// The relay's concurrent inner handshakes of this session at most: every
/// permit and the skew of 2 (`establish_limit::HANDSHAKE_SKEW`).
const RELAY_HANDSHAKES: usize = ESTABLISH_PERMITS + 2;

/// The multi-stream relay behind a `DEFAULT_RTT` link, answering every
/// PolicyAck with the tree's reply, configured further by `configure`. The
/// tree names the link.
fn linked_relay(
    configure: impl FnOnce(&mut PoolConfig),
) -> (PooledRelay, TestLink, Arc<ReadyTree>) {
    let listener = TestRelay::bind();
    let link = TestLink::spawn(listener.local_addr().unwrap());
    let tree = Arc::new(ReadyTree::with_online_completed(link.address()));
    let relay = serve(listener, &tree, configure);
    (relay, link, tree)
}

fn serve(
    listener: std::net::TcpListener,
    tree: &ReadyTree,
    configure: impl FnOnce(&mut PoolConfig),
) -> PooledRelay {
    let mut config = PoolConfig {
        reply: Some(AckReply::for_tree(tree)),
        ..PoolConfig::default()
    };
    configure(&mut config);
    TestRelay::spawn_streams(listener, RelayIdentity::for_tree(tree), config)
}

struct Started {
    session: SessionHandle,
    phases: mpsc::Receiver<SessionPhase>,
    steps: Steps,
    renewals: Renewals,
    armed: ArmedHandles,
}

impl Started {
    fn limiter(&self) -> Arc<EstablishLimiter> {
        self.armed.0.limiter().clone()
    }

    /// Renewals traced after `from`.
    fn renewed_after(&self, from: Instant) -> usize {
        times(&self.steps, "reack_renewed")
            .into_iter()
            .filter(|at| *at > from)
            .count()
    }
}

/// A session on `tree` with `options` (the persistent ACK connection unless
/// `per_dial`), Ready within `ready`.
fn start(tree: &ReadyTree, mut options: LinkOptions, ready: Duration) -> Started {
    let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
    let (trace, steps) = recorder();
    let renewals = Renewals::default();
    options.renewals = Some(renewals.clone());
    let (tx, phases) = mpsc::channel();
    let (armed_tx, armed_rx) = mpsc::channel();
    let armed_tx = Mutex::new(armed_tx);
    options.armed = Some(Arc::new(move |services, gate| {
        let _ = armed_tx.lock().unwrap().send((services, gate));
    }));
    let session = spawn_link(
        saved(tree),
        claim,
        move |phase| {
            let _ = tx.send(phase);
        },
        (Some(trace), production_bridge()),
        options,
    )
    .unwrap();
    let phase = phases.recv_timeout(ready);
    assert_eq!(
        phase.ok(),
        Some(SessionPhase::Ready),
        "{:?}",
        session.refusal()
    );
    let armed = armed_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    Started {
        session,
        phases,
        steps,
        renewals,
        armed,
    }
}

/// Serve packets every 20 ms for `span`, asserting Ready throughout and
/// that the ACK path never holds more than its reserve of permits; `each`
/// runs at every sample with the time since the start.
fn ready_for(started: &Started, span: Duration, mut each: impl FnMut(Duration)) {
    let session = &started.session;
    let limiter = started.limiter();
    let probe = session.probe();
    let from = Instant::now();
    while from.elapsed() < span {
        assert_eq!(
            session.phase(),
            SessionPhase::Ready,
            "{:?} after {:?}",
            session.refusal(),
            from.elapsed()
        );
        assert!(probe.ready(), "sealed at {:?}", session.refusal());
        let (acks, _) = limiter.active();
        assert!(acks <= ACK_RESERVE, "{acks} ACK-path permits");
        probe.bridge().from_os(&frame()).unwrap();
        each(from.elapsed());
        thread::sleep(Duration::from_millis(20));
    }
}

/// How long after the `nth` (0-based) step `after` the next step `wanted`
/// came.
fn next_after(steps: &Steps, (after, nth): (&str, usize), wanted: &str) -> Option<Duration> {
    let at = *times(steps, after).get(nth)?;
    let next = times(steps, wanted).into_iter().find(|then| *then >= at)?;
    Some(next - at)
}

fn count(steps: &Steps, wanted: &str) -> usize {
    times(steps, wanted).len()
}

/// The relay connections that answered a PolicyAck, and those that
/// accepted an Open.
fn ack_and_flow_conns(relay: &PooledRelay) -> (BTreeSet<usize>, BTreeSet<usize>) {
    let events = relay.events();
    let of = |step| -> BTreeSet<usize> {
        events
            .iter()
            .filter(|event| event.step == step)
            .map(|event| event.conn)
            .collect()
    };
    (of(StreamStep::Acked), of(StreamStep::Opened))
}

/// PolicyAcks answered on relay connection `conn`.
fn acks_on(relay: &PooledRelay, conn: usize) -> usize {
    relay
        .events()
        .iter()
        .filter(|event| event.conn == conn && event.step == StreamStep::Acked)
        .count()
}

/// The renewal latencies (bound request to renewed lease) of renewals that
/// reached the relay `via`, sorted.
fn latencies(renewals: &Renewals, via: &str) -> Vec<Duration> {
    let mut latencies: Vec<Duration> = renewals
        .lock()
        .unwrap()
        .iter()
        .filter(|(how, _)| *how == via)
        .map(|(_, latency)| *latency)
        .collect();
    latencies.sort_unstable();
    latencies
}

fn median(sorted: &[Duration]) -> Duration {
    assert!(!sorted.is_empty(), "no renewal");
    sorted[sorted.len() / 2]
}

/// The ACK connection's handshakes never outnumbered the ACK reserve, the
/// relay's never this session's permits and skew, and none was refused or
/// struck.
fn assert_handshake_budget(relay: &PooledRelay, ack_conns: &BTreeSet<usize>) {
    for conn in ack_conns {
        let high = relay.connection(*conn).handshakes().high_water();
        assert!(high <= ACK_RESERVE, "ACK conn {conn}: {high} handshakes");
    }
    let high = relay.handshakes().high_water();
    assert!(high <= RELAY_HANDSHAKES, "{high} relay handshakes");
    assert_eq!(relay.handshake_caps(), 0);
    assert_eq!(relay.session_caps(), 0);
    assert_eq!(relay.strikes(), 0);
}

fn stop(mut started: Started, tree: &ReadyTree) {
    let (services, gate) = started.armed;
    drop(services);
    let begun = Instant::now();
    assert!(started.session.try_join(crate::apple::STOP_BUDGET));
    assert!(begun.elapsed() <= crate::apple::STOP_BUDGET);
    assert_eq!(started.session.refusal(), Some("provider_stop"));
    assert!(gate.drained());
    assert!(!store_locked(&tree.identity_dir()));
    assert!(started.phases.try_recv().is_err());
}

/// S16l: re-ACKs at 170 ms ride one TCP connection: the first ACK, both
/// first pre-warms and every renewal are streams of the one ACK connection,
/// the only connection the relay ever accepted, and the session is Ready
/// throughout. 15 s spans every timer of the ACK path and its pre-warms at
/// least twice (grants of 3 s, `PREWARM_MAX_AGE` 4 s, `LINK_LOG_EVERY` 5 s,
/// the relay's 5 s `ADMISSION_TIMEOUT`) and `ACK_IDLE_REUSE` many times;
/// neither it nor 60 s nears a connection's `MAX_CONN_STREAMS` or
/// `MAX_CONN_AGE` (S16n). `link_sixty_seconds_of_reacks_ride_one_tcp_connection`
/// runs it for 60 s.
#[test]
fn link_reacks_ride_one_tcp_connection() {
    reacks_ride_one_tcp_connection(Duration::from_secs(15));
}

/// `link_reacks_ride_one_tcp_connection` for 60 s, as before S16n: a soak,
/// ignored by default and run alone under the timing lock.
#[test]
fn link_sixty_seconds_of_reacks_ride_one_tcp_connection() {
    reacks_ride_one_tcp_connection(Duration::from_secs(60));
}

fn reacks_ride_one_tcp_connection(span: Duration) {
    let (relay, link, tree) = linked_relay(|_| {});
    let started = start(&tree, LinkOptions::default(), Duration::from_secs(4));
    assert_eq!(relay.conns(), 1);
    assert_eq!(link.connections(), 1);
    let from = Instant::now();
    ready_for(&started, span, |_| {});
    let renewed = started.renewed_after(from);
    // Grants of 3 s, renewed 2 s before they end: one about every second
    // (at least 40 in 60 s, two in three seconds).
    let least = usize::try_from(span.as_secs() * 2 / 3).unwrap();
    assert!(renewed >= least, "only {renewed} renewals in {span:?}");
    assert_eq!(relay.conns(), 1, "the ACK path dialed again");
    assert_eq!(link.connections(), 1);
    let (acks, flows) = ack_and_flow_conns(&relay);
    assert_eq!(acks, BTreeSet::from([0]));
    assert!(flows.is_empty());
    assert!(acks_on(&relay, 0) > renewed);
    // Every renewal on a stream of it, nearly all pre-warmed (a request
    // whose pre-warm a loaded Mac had not yet set up goes as a fresh stream
    // of it); never a dial of its own.
    let all = started.renewals.lock().unwrap().len();
    assert!(all >= renewed);
    let prewarmed = latencies(&started.renewals, "prewarm").len();
    assert_eq!(prewarmed + latencies(&started.renewals, "link").len(), all);
    assert!(prewarmed * 10 >= all * 9, "{prewarmed} of {all} pre-warmed");
    assert!(latencies(&started.renewals, "fresh").is_empty());
    assert_eq!(count(&started.steps, "ack_link_dialed"), 1);
    assert_eq!(count(&started.steps, "ack_link_fallback"), 0);
    assert_eq!(count(&started.steps, "ack_link_lost"), 0);
    assert_eq!(count(&started.steps, "reack_failed"), 0);
    assert_eq!(relay.connection(0).closed(), None);
    assert_handshake_budget(&relay, &acks);
    stop(started, &tree);
    let closed = runtime().block_on(relay.wait_closed(0, Duration::from_secs(2)));
    assert!(closed.is_some(), "the ACK connection outlived its session");
}

/// S16l: under a 90-flow burst on the flow pool the lease holds at 170 ms:
/// every PolicyAck rides the ACK connection, which no flow ever shares, on a
/// pre-warmed stream in about one round trip (two at most at the median),
/// where installed v22 spent a whole dial (TCP, outer TLS, H2 and inner
/// mTLS) on each. The ACK path keeps within its reserve, the session within
/// the relay's per-peer handshakes, and nothing is struck.
#[test]
fn link_keeps_the_lease_under_a_concurrent_flow_burst() {
    const FLOWS: u8 = 90;
    let (relay, _link, tree) = linked_relay(|_| {});
    let started = start(&tree, LinkOptions::default(), Duration::from_secs(6));
    let (services, _) = &started.armed;
    let limiter = started.limiter();
    let settings = services.signed_relay();
    let runtime = runtime();
    let span = Duration::from_secs(8);
    let from = Instant::now();
    let burst = {
        let services = services.clone();
        runtime.spawn(async move {
            let mut set = tokio::task::JoinSet::new();
            for tag in 0..FLOWS {
                set.spawn(echo(services.clone(), settings.clone(), tag));
            }
            let mut completed = 0usize;
            while let Some(result) = set.join_next().await {
                completed += usize::from(matches!(result, Ok(Ok(()))));
            }
            completed
        })
    };
    let mut max_flow_permits = 0;
    ready_for(&started, span, |_| {
        max_flow_permits = max_flow_permits.max(limiter.active().1);
    });
    let completed = runtime.block_on(burst).unwrap();
    assert!(completed > 0, "no flow completed");
    let renewed = started.renewed_after(from);
    assert!(renewed >= 5, "only {renewed} renewals in {span:?}");
    assert_eq!(started.session.refusal(), None);
    // One ACK connection, apart from every flow's.
    let (acks, flows) = ack_and_flow_conns(&relay);
    assert_eq!(acks.len(), 1, "{acks:?}");
    assert!(acks.is_disjoint(&flows), "{acks:?} {flows:?}");
    assert!(!flows.is_empty());
    let stats = services.pool().stats();
    assert!(stats.max_conns <= POOL_CONNS, "{stats:?}");
    // Each renewal one request on a stream set up beforehand.
    let prewarmed = latencies(&started.renewals, "prewarm");
    assert!(prewarmed.len() >= renewed, "{prewarmed:?}");
    assert!(latencies(&started.renewals, "fresh").is_empty());
    let typical = median(&prewarmed);
    assert!(
        typical <= RTT * 2,
        "median renewal {typical:?}: {prewarmed:?}"
    );
    assert_eq!(count(&started.steps, "ack_link_fallback"), 0);
    // Flows never took the ACK reserve; the limiter never ran past its
    // permits; nothing backed off.
    assert!(max_flow_permits <= ESTABLISH_PERMITS - ACK_RESERVE);
    assert!(limiter.high_water() <= ESTABLISH_PERMITS);
    assert_eq!(limiter.auth_failures(), 0);
    assert_handshake_budget(&relay, &acks);
    stop(started, &tree);
}

/// S16o: r13's lapse at 170 ms. A 90-flow burst right after Ready, on a
/// cold flow pool whose first connections are still coming up, and the ACK
/// connection dropped 300 ms into that ramp (no GOAWAY), so the ACK path
/// falls back to dials of its own while the pool ramps: every lease is
/// renewed before it ends (the session never seals and the lease always
/// has time left), and no re-ACK is ever reported stalled.
#[test]
fn link_lease_is_renewed_through_a_cold_pool_ramp_burst_and_ack_connection_loss() {
    const FLOWS: u8 = 90;
    let (relay, _link, tree) = linked_relay(|_| {});
    let started = start(&tree, LinkOptions::default(), Duration::from_secs(6));
    let (services, _) = &started.armed;
    let settings = services.signed_relay();
    let bridge = started.session.probe().bridge().clone();
    let lease = bridge.refreshable_deadline();
    let runtime = runtime();
    let from = Instant::now();
    let burst = {
        let services = services.clone();
        runtime.spawn(async move {
            let mut set = tokio::task::JoinSet::new();
            for tag in 0..FLOWS {
                set.spawn(echo(services.clone(), settings.clone(), tag));
            }
            let mut completed = 0usize;
            while let Some(result) = set.join_next().await {
                completed += usize::from(matches!(result, Ok(Ok(()))));
            }
            completed
        })
    };
    let mut dropped = false;
    let mut least_left = u64::MAX;
    ready_for(&started, Duration::from_secs(8), |elapsed| {
        if !dropped && elapsed >= Duration::from_millis(300) {
            relay.drop_tcp(0);
            dropped = true;
        }
        if let (Some(end), Ok(now)) = (lease.current(), bridge.clock_ns()) {
            least_left = least_left.min(end.saturating_sub(now));
        }
    });
    let completed = runtime.block_on(burst).unwrap();
    assert!(completed > 0, "no flow completed");
    assert!(dropped);
    assert!(least_left > 0 && least_left < u64::MAX, "{least_left}");
    assert!(started.renewed_after(from) >= 5);
    assert_eq!(started.session.refusal(), None);
    assert!(count(&started.steps, "ack_link_lost") >= 1);
    let stalled = started
        .steps
        .lock()
        .unwrap()
        .iter()
        .filter(|(step, _)| step.starts_with("reack_stalled_"))
        .count();
    assert_eq!(stalled, 0);
    assert_eq!(started.limiter().auth_failures(), 0);
    stop(started, &tree);
}

/// S16l: what a fresh ACK costs, every pre-warmed channel aged out (a bound
/// of 1 ms) so every request goes fresh: about three round trips on the ACK
/// connection (the carrier's 200, the inner mTLS, the PolicyAck), where a
/// dial of its own (outer TLS, H2, the carrier's 200, the inner mTLS, the
/// PolicyAck) costs at least four.
#[test]
fn link_fresh_acks_cost_three_round_trips_where_a_dial_costs_four_or_more() {
    let run = |per_dial: bool| {
        let (relay, _link, tree) = linked_relay(|_| {});
        let options = LinkOptions {
            per_dial,
            prewarm_max_age: Some(Duration::from_millis(1)),
            ..LinkOptions::default()
        };
        let started = start(&tree, options, Duration::from_secs(4));
        ready_for(&started, Duration::from_secs(6), |_| {});
        let via = if per_dial { "fresh" } else { "link" };
        let fresh = latencies(&started.renewals, via);
        assert!(fresh.len() >= 4, "{per_dial}: {fresh:?}");
        assert_eq!(relay.strikes(), 0);
        stop(started, &tree);
        (median(&fresh), fresh, relay.conns())
    };
    let (link, linked, link_conns) = run(false);
    let (dial, dialed, dial_conns) = run(true);
    assert!(
        link <= RTT * 3 + RTT / 2,
        "on the link {link:?}: {linked:?}"
    );
    assert!(dial >= RTT * 4, "dialed {dial:?}: {dialed:?}");
    assert!(
        link + RTT / 2 <= dial,
        "link {link:?} against dial {dial:?}"
    );
    // Fresh streams of one connection, against a connection each.
    assert_eq!(link_conns, 1);
    assert!(dial_conns >= dialed.len());
}

/// S16l: the relay drops the ACK connection (no GOAWAY) mid-run, and the
/// first stream of its redial (a pre-warm's second try on the link) drops
/// that one too. The lease holds: the pre-warms fall back to their own
/// dials, the link dial budget spent, and the next bound request redials
/// the ACK connection, which carries the renewals from then on.
#[test]
fn link_killed_mid_run_keeps_the_lease_by_fallback_and_redials() {
    let (relay, _link, tree) = linked_relay(|_| {});
    let started = start(&tree, LinkOptions::default(), Duration::from_secs(4));
    let runtime = runtime();
    ready_for(&started, Duration::from_secs(3), |_| {});
    assert_eq!(relay.conns(), 1);
    relay.drop_tcp(0);
    let closed = runtime.block_on(relay.wait_closed(0, Duration::from_secs(2)));
    assert_eq!(closed.map(|(_, close)| close), Some(Close::DropTcp));
    relay.next_streams(1, StreamFault::DropConnection);
    let from = Instant::now();
    ready_for(&started, Duration::from_secs(8), |_| {});
    assert!(started.renewed_after(from) >= 5);
    assert_eq!(started.session.refusal(), None);
    assert!(count(&started.steps, "ack_link_lost") >= 2);
    assert!(count(&started.steps, "ack_link_fallback") >= 1);
    assert!(count(&started.steps, "ack_link_dialed") >= 2);
    // The loss is redialed at once: its streams end with it, freeing their
    // pre-warm slots, and the first to fill again dials (outer TLS, one
    // round trip).
    let redial = next_after(&started.steps, ("ack_link_lost", 0), "ack_link_dialed");
    assert!(redial.is_some_and(|redial| redial <= RTT * 3), "{redial:?}");
    // The last renewals ride the last ACK connection again.
    let (acks, _) = ack_and_flow_conns(&relay);
    let last = *acks.last().unwrap();
    assert!(last >= 2, "{acks:?}");
    assert!(acks_on(&relay, last) >= 3, "{acks:?}");
    assert!(relay.connection(last).closed().is_none());
    assert!(relay.conns() <= 8, "{} connections", relay.conns());
    assert_eq!(started.limiter().auth_failures(), 0);
    assert_handshake_budget(&relay, &BTreeSet::from([last]));
    stop(started, &tree);
}

/// S16l: a path that froze the ACK connection alone (the relay reads and
/// writes nothing on it, and no byte it is sent is acknowledged) never holds
/// both requests in flight: the one dispatched while the first has seen no
/// sign of the connection's life goes on a dial of its own and renews the
/// lease; the connection's stall watchdog then closes it, and it is
/// redialed. Frozen once its streams finished their handshakes, so none of
/// them can run into the relay's deadline mid-handshake.
#[test]
fn link_frozen_mid_run_never_holds_both_requests_and_is_replaced() {
    let (relay, _link, tree) = linked_relay(|_| {});
    let slot = LinkSlot::default();
    let options = LinkOptions {
        link_slot: Some(slot.clone()),
        ..LinkOptions::default()
    };
    let started = start(&tree, options, Duration::from_secs(4));
    let link = slot.lock().unwrap().clone().expect("no ACK connection");
    ready_for(&started, Duration::from_secs(2), |_| {});
    // Right after a pre-warmed stream authenticated: none mid-handshake.
    let authenticated = relay.count(StreamStep::Authenticated);
    let deadline = Instant::now() + Duration::from_secs(3);
    while relay.count(StreamStep::Authenticated) == authenticated && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(1));
    }
    assert!(relay.connection(0).handshakes().current() == 0);
    relay.freeze(0);
    assert!(link.freeze_acks_for_test());
    let from = Instant::now();
    ready_for(&started, Duration::from_secs(8), |_| {});
    assert!(started.renewed_after(from) >= 5);
    assert_eq!(started.session.refusal(), None);
    assert!(count(&started.steps, "reack_off_link") >= 1);
    // Renewed on dials of their own meanwhile.
    assert!(!latencies(&started.renewals, "fresh").is_empty());
    assert!(count(&started.steps, "ack_link_lost") >= 1);
    assert!(count(&started.steps, "ack_link_dialed") >= 2);
    let (acks, _) = ack_and_flow_conns(&relay);
    let last = *acks.last().unwrap();
    assert!(acks_on(&relay, last) >= 3, "{acks:?}");
    assert_eq!(started.limiter().auth_failures(), 0);
    assert_handshake_budget(&relay, &acks);
    stop(started, &tree);
}

/// S16l: a slow relay (700 ms per PolicyAck) keeps two requests in flight
/// (S16k), and both ride the one ACK connection: TCP ACKs of each request,
/// which its stall watchdog samples while the request awaits, show the
/// connection alive, so it never counts as quiet.
#[test]
fn link_slow_acks_keep_both_requests_on_the_connection() {
    let (relay, _link, tree) = linked_relay(|config| {
        config.ack_delay = Duration::from_millis(700);
    });
    let started = start(&tree, LinkOptions::default(), Duration::from_secs(5));
    let from = Instant::now();
    ready_for(&started, Duration::from_secs(8), |_| {});
    assert!(started.renewed_after(from) >= 5);
    assert!(count(&started.steps, "reack_pipelined") >= 2);
    assert_eq!(count(&started.steps, "reack_off_link"), 0);
    assert!(latencies(&started.renewals, "fresh").is_empty());
    assert_eq!(relay.conns(), 1);
    assert_eq!(started.session.refusal(), None);
    stop(started, &tree);
}

/// S16l: a GOAWAY on the ACK connection, graceful and then one with an
/// error on its successor: each is let go and redialed at once, the
/// renewals move on, the lease holds and nothing is struck.
#[test]
fn link_goaway_is_let_go_and_redialed() {
    let (relay, _link, tree) = linked_relay(|_| {});
    let started = start(&tree, LinkOptions::default(), Duration::from_secs(4));
    ready_for(&started, Duration::from_secs(2), |_| {});
    let last = u32::try_from(relay.streams() * 2 + 1).unwrap();
    relay.goaway(0, h2::Reason::NO_ERROR, last);
    ready_for(&started, Duration::from_secs(4), |_| {});
    assert_eq!(count(&started.steps, "ack_link_goaway"), 1);
    let (acks, _) = ack_and_flow_conns(&relay);
    assert_eq!(acks.len(), 2, "{acks:?}");
    let second = *acks.last().unwrap();
    assert!(acks_on(&relay, second) >= 2);
    relay.goaway(second, h2::Reason::ENHANCE_YOUR_CALM, 1);
    let from = Instant::now();
    ready_for(&started, Duration::from_secs(4), |_| {});
    assert!(started.renewed_after(from) >= 2);
    assert_eq!(count(&started.steps, "ack_link_goaway"), 2);
    // The GOAWAY that ended its streams is redialed at once.
    let redial = next_after(&started.steps, ("ack_link_goaway", 1), "ack_link_dialed");
    assert!(redial.is_some_and(|redial| redial <= RTT * 3), "{redial:?}");
    let (acks, _) = ack_and_flow_conns(&relay);
    assert_eq!(acks.len(), 3, "{acks:?}");
    assert!(acks_on(&relay, *acks.last().unwrap()) >= 2);
    assert_eq!(started.session.refusal(), None);
    assert_eq!(started.limiter().auth_failures(), 0);
    assert_handshake_budget(&relay, &acks);
    stop(started, &tree);
}

/// S16l: a wake drains the ACK connection as it drains a flow connection
/// (it was dialed under the earlier wake generation): its pre-warmed
/// streams are never used, the forced re-ACK and every later one ride a new
/// connection.
#[test]
fn link_wake_drains_the_connection_and_renews_on_a_new_one() {
    let (relay, _link, tree) = linked_relay(|_| {});
    let pins = EpochPins::pinned_for_test(RelayInterface::loopback_for_test());
    let options = LinkOptions {
        pinned: Some(pins.clone()),
        ..LinkOptions::default()
    };
    let started = start(&tree, options, Duration::from_secs(4));
    ready_for(&started, Duration::from_secs(2), |_| {});
    let before = acks_on(&relay, 0);
    pins.auth_backoff().resume();
    started.session.probe().request_reack();
    let from = Instant::now();
    ready_for(&started, Duration::from_secs(4), |_| {});
    assert!(started.renewed_after(from) >= 3);
    assert!(count(&started.steps, "ack_link_drained") >= 1);
    assert!(count(&started.steps, "reack_forced") >= 1);
    // The streams pre-warmed before the wake were dropped unused.
    let stale = times(&started.steps, "reack_prewarm_stale")
        .into_iter()
        .filter(|at| *at > from)
        .count();
    assert!(stale >= 1, "no pre-warmed stream dropped after the wake");
    let (acks, _) = ack_and_flow_conns(&relay);
    assert_eq!(acks.len(), 2, "{acks:?}");
    // The drained connection answered nothing after the wake but what was
    // in flight then.
    assert!(acks_on(&relay, 0) <= before + 2);
    assert!(acks_on(&relay, 1) >= 3);
    assert_eq!(started.session.refusal(), None);
    stop(started, &tree);
}

/// S16l: a re-pin (S18) seals the Ready session at its next tick, and its
/// ACK connection dials nothing more.
#[test]
fn link_repin_seals_and_dials_nothing_more() {
    let (relay, _link, tree) = linked_relay(|_| {});
    let pins = EpochPins::pinned_for_test(RelayInterface::loopback_for_test());
    let options = LinkOptions {
        pinned: Some(pins.clone()),
        ..LinkOptions::default()
    };
    let mut started = start(&tree, options, Duration::from_secs(4));
    ready_for(&started, Duration::from_secs(1), |_| {});
    pins.repin(&RelayInterface::loopback_for_test());
    let deadline = Instant::now() + Duration::from_secs(2);
    while started.session.phase() == SessionPhase::Ready && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert_ne!(started.session.phase(), SessionPhase::Ready);
    assert_eq!(started.session.refusal(), Some("relay_path_changed"));
    let conns = relay.conns();
    thread::sleep(Duration::from_secs(2));
    assert_eq!(relay.conns(), conns);
    assert!(started.session.try_join(crate::apple::STOP_BUDGET));
    assert!(started.armed.1.drained());
    assert!(!store_locked(&tree.identity_dir()));
}

/// S16l, S16j-3: a stop while the ACK connection holds pre-warmed streams
/// and the flow pool live flows drains both within the stop budget; the
/// ACK connection's driver is a gate task, so the relay sees it end.
#[test]
fn link_stop_drains_the_ack_connection_within_budget() {
    let (relay, _link, tree) = linked_relay(|_| {});
    let started = start(&tree, LinkOptions::default(), Duration::from_secs(4));
    ready_for(&started, Duration::from_secs(2), |_| {});
    let runtime = runtime();
    let (services, _) = &started.armed;
    let settings = services.signed_relay();
    let flows: Vec<_> = (0..8)
        .map(|tag| runtime.spawn(echo(services.clone(), settings.clone(), tag)))
        .collect();
    thread::sleep(Duration::from_millis(500));
    assert!(relay.connection(0).live_streams() >= 1);
    stop(started, &tree);
    let closed = runtime.block_on(relay.wait_closed(0, Duration::from_secs(2)));
    assert!(closed.is_some(), "the ACK connection outlived its session");
    for flow in flows {
        let _ = runtime.block_on(flow);
    }
}

/// A TCP proxy in front of `upstream` that drops its first `drop` accepted
/// connections unread and passes every later one through.
struct DropFirst {
    address: SocketAddr,
    accepted: Arc<AtomicUsize>,
    _thread: thread::JoinHandle<()>,
}

impl DropFirst {
    fn spawn(upstream: SocketAddr, drop: usize) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counted = accepted.clone();
        let thread = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                while let Ok((mut client, _)) = listener.accept().await {
                    if counted.fetch_add(1, Ordering::SeqCst) < drop {
                        continue;
                    }
                    tokio::spawn(async move {
                        let Ok(mut relay) = tokio::net::TcpStream::connect(upstream).await else {
                            return;
                        };
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut relay).await;
                    });
                }
            });
        });
        Self {
            address,
            accepted,
            _thread: thread,
        }
    }
}

/// S16l: when the ACK connection cannot come up for the first ACK (its
/// connection is dropped before outer TLS), the first ACK and the first
/// pre-warms fall back to dials of their own; the first bound request then
/// brings the ACK connection up, and it carries the renewals from there.
#[test]
fn link_first_ack_falls_back_to_its_own_dial_when_the_link_cannot_come_up() {
    let listener = TestRelay::bind();
    let link = TestLink::spawn(listener.local_addr().unwrap());
    let proxy = DropFirst::spawn(link.address(), 1);
    let tree = Arc::new(ReadyTree::with_online_completed(proxy.address));
    let relay = serve(listener, &tree, |_| {});
    let started = start(&tree, LinkOptions::default(), Duration::from_secs(6));
    assert!(count(&started.steps, "ack_link_fallback") >= 1);
    // The first ACK on a connection of its own, alone on it.
    assert_eq!(acks_on(&relay, 0), 1);
    let from = Instant::now();
    ready_for(&started, Duration::from_secs(6), |_| {});
    assert!(started.renewed_after(from) >= 4);
    assert_eq!(count(&started.steps, "ack_link_dialed"), 1);
    let (acks, _) = ack_and_flow_conns(&relay);
    let last = *acks.last().unwrap();
    assert!(acks_on(&relay, last) >= 4, "{acks:?}");
    assert!(proxy.accepted.load(Ordering::SeqCst) >= 2);
    assert_eq!(started.limiter().auth_failures(), 0);
    assert_handshake_budget(&relay, &BTreeSet::from([last]));
    stop(started, &tree);
}

/// Bytes each bulk flow carries each way at least (S16m carried exactly
/// 4 MiB, which outlasted every test's window by 10 s or more).
const BULK_FLOOR: usize = 1024 * 1024;
/// The most bytes a bulk flow has up and not yet back (S16n): four of the
/// relay's 128 KiB stream windows, so the flow's stream always has a full
/// window to send, while the bytes the application's own socket would
/// otherwise queue (megabytes) do not take seconds to drain at the end.
const BULK_WINDOW: usize = 4 * 128 * 1024;

/// One TCP flow through `services` to the relay's echo target carrying
/// bytes up while it reads them back, until `stop` and at least
/// `BULK_FLOOR` of them, at most `BULK_WINDOW` on their way: a bulk
/// transfer on the flow pool beside the ACK connection, as long as the
/// test's window rather than a fixed size (S16n). Every byte comes back. A
/// refused flow is an error.
async fn bulk_echo(
    services: Arc<crate::held_relay_services::HeldRelayServices>,
    settings: aegis_core::RelaySettings,
    tag: u8,
    stop: Arc<AtomicBool>,
) -> anyhow::Result<usize> {
    use aegis_client::packet_engine::services::RelayServices;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (app, local) = crate::provider_session::relay::loopback().await;
    let flow =
        tokio::spawn(async move { services.tcp(local, &settings, "echo.test".into(), 7).await });
    let (mut read, mut write) = app.into_split();
    // Bytes back so far, and whether the download has ended.
    let received = Arc::new((AtomicUsize::new(0), AtomicBool::new(false)));
    let back = received.clone();
    let upload = async move {
        let chunk = vec![tag; 16 * 1024];
        let mut sent = 0usize;
        while sent < BULK_FLOOR || !stop.load(Ordering::SeqCst) {
            while sent - back.0.load(Ordering::SeqCst) + chunk.len() > BULK_WINDOW {
                anyhow::ensure!(!back.1.load(Ordering::SeqCst), "echo ended at {sent}");
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            write.write_all(&chunk).await?;
            sent += chunk.len();
        }
        write.shutdown().await?;
        anyhow::Ok(sent)
    };
    let download = async move {
        let mut buffer = vec![0; 64 * 1024];
        let mut total = 0usize;
        let ended = loop {
            let n = match read.read(&mut buffer).await {
                Ok(0) => break Ok(total),
                Ok(n) => n,
                Err(error) => break Err(error.into()),
            };
            if !buffer[..n].iter().all(|byte| *byte == tag) {
                break Err(anyhow::anyhow!("echo mismatch"));
            }
            total += n;
            received.0.store(total, Ordering::SeqCst);
        };
        received.1.store(true, Ordering::SeqCst);
        ended
    };
    let (uploaded, downloaded) = tokio::join!(upload, download);
    let sent = uploaded?;
    let total = downloaded?;
    anyhow::ensure!(total == sent, "{total} of {sent} bytes echoed");
    flow.await??;
    Ok(total)
}

/// `flows` bulk echo flows on `started`'s flow pool, from now on, on the
/// returned runtime, until the flag is set.
type Bulk = (
    tokio::runtime::Runtime,
    tokio::task::JoinHandle<Vec<anyhow::Result<usize>>>,
    Arc<AtomicBool>,
);

fn bulk_load(started: &Started, flows: u8) -> Bulk {
    let (services, _) = &started.armed;
    let services = services.clone();
    let settings = services.signed_relay();
    let runtime = runtime();
    let stop = Arc::new(AtomicBool::new(false));
    let stopping = stop.clone();
    let load = runtime.spawn(async move {
        let mut set = tokio::task::JoinSet::new();
        for tag in 0..flows {
            let stop = stopping.clone();
            set.spawn(bulk_echo(services.clone(), settings.clone(), tag + 1, stop));
        }
        let mut done = Vec::new();
        while let Some(result) = set.join_next().await {
            done.push(result.unwrap_or_else(|error| Err(error.into())));
        }
        done
    });
    (runtime, load, stop)
}

/// Ends `bulk`: every one of its flows carried at least `BULK_FLOOR` bytes,
/// each of them back.
fn bulk_moved((runtime, load, stop): Bulk, flows: usize) {
    stop.store(true, Ordering::SeqCst);
    let moved = runtime.block_on(load).unwrap();
    assert_eq!(moved.len(), flows);
    assert!(
        moved
            .iter()
            .all(|moved| matches!(moved, Ok(n) if *n >= BULK_FLOOR)),
        "{moved:?}"
    );
}

/// S16m, v23 13.30 s: on a slow path (700 ms per PolicyAck) whose TCP ACKs
/// stop showing for a while (a backlog), the request dispatched beside one
/// in flight goes off the quiet ACK connection; the moment the connection's
/// ACKs show again (its quiet request's bytes acknowledged), that request
/// comes back to it and renews there, never on the dial of its own it had
/// started (v23: 2.2 s under the burst, while the connection answered the
/// quiet request 117 ms after the other left it).
#[test]
fn link_request_sent_off_a_quiet_link_comes_back_once_it_shows_life() {
    let (relay, _link, tree) = linked_relay(|config| {
        config.ack_delay = Duration::from_millis(700);
    });
    let slot = LinkSlot::default();
    let options = LinkOptions {
        link_slot: Some(slot.clone()),
        ..LinkOptions::default()
    };
    let started = start(&tree, options, Duration::from_secs(5));
    let link = slot.lock().unwrap().clone().expect("no ACK connection");
    ready_for(&started, Duration::from_secs(2), |_| {});
    assert_eq!(count(&started.steps, "reack_off_link"), 0);
    // Bulk transfers on the flow pool throughout.
    let bulk = bulk_load(&started, 4);
    ready_for(&started, Duration::from_secs(1), |_| {});
    assert_eq!(count(&started.steps, "reack_off_link"), 0);
    assert!(link.freeze_acks_for_test());
    let mut thawed = false;
    ready_for(&started, Duration::from_secs(6), |_| {
        if !thawed && count(&started.steps, "reack_off_link") > 0 {
            assert!(link.thaw_acks_for_test());
            thawed = true;
        }
    });
    assert!(thawed, "no request went off the quiet ACK connection");
    let back = next_after(&started.steps, ("reack_off_link", 0), "reack_back_on_link");
    assert!(back.is_some_and(|back| back <= RTT * 3), "{back:?}");
    // The request carried on: no attempt ended without its renewal.
    assert_eq!(count(&started.steps, "reack_failed"), 0);
    // Nothing renewed on a dial of its own; every PolicyAck the relay
    // answered rode the one ACK connection.
    assert!(
        latencies(&started.renewals, "fresh").is_empty(),
        "{:?}",
        latencies(&started.renewals, "fresh")
    );
    let (acks, _) = ack_and_flow_conns(&relay);
    assert_eq!(acks, BTreeSet::from([0]));
    assert_eq!(count(&started.steps, "ack_link_lost"), 0);
    assert_eq!(started.session.refusal(), None);
    assert_eq!(started.limiter().auth_failures(), 0);
    bulk_moved(bulk, 4);
    stop(started, &tree);
}

/// S16m review: a request sent off a quiet ACK connection whose own dial
/// completed its inner mTLS is committed to that dial: its PolicyAck is
/// written there and its answer is at most one exchange away, which going
/// back to the connection cannot beat. The connection's ACKs show again
/// only once such a dial is established; no request that reached that
/// point went back, and every one of them was answered.
#[test]
fn link_request_off_a_quiet_link_keeps_its_dial_once_its_policy_ack_is_written() {
    let (relay, _link, tree) = linked_relay(|config| {
        config.ack_delay = Duration::from_millis(700);
    });
    let slot = LinkSlot::default();
    let options = LinkOptions {
        link_slot: Some(slot.clone()),
        ..LinkOptions::default()
    };
    let started = start(&tree, options, Duration::from_secs(5));
    let link = slot.lock().unwrap().clone().expect("no ACK connection");
    ready_for(&started, Duration::from_secs(2), |_| {});
    assert_eq!(count(&started.steps, "reack_off_link"), 0);
    assert!(link.freeze_acks_for_test());
    let mut thawed = false;
    ready_for(&started, Duration::from_secs(6), |_| {
        if !thawed && count(&started.steps, "reack_off_link_established") > 0 {
            assert!(link.thaw_acks_for_test());
            thawed = true;
        }
    });
    assert!(
        thawed,
        "no dial sent off the quiet connection was established"
    );
    let off = count(&started.steps, "reack_off_link");
    let established = count(&started.steps, "reack_off_link_established");
    let back = count(&started.steps, "reack_back_on_link");
    // Each request sent off either went back before its dial was
    // established, or kept its dial: never both.
    assert!(
        back + established <= off,
        "off {off}, established {established}, back {back}"
    );
    assert_eq!(count(&started.steps, "reack_failed"), 0);
    // The kept dial's PolicyAck was answered on a connection of its own.
    let (acks, _) = ack_and_flow_conns(&relay);
    assert!(acks.iter().any(|conn| *conn != 0), "{acks:?}");
    assert_eq!(started.session.refusal(), None);
    assert_eq!(started.limiter().auth_failures(), 0);
    stop(started, &tree);
}

/// S16m review: the revival race covers the off-link dial's TCP connect
/// too. Every fresh dial's connect is held 1.2 s (a SYN retransmit under
/// the burst); the quiet connection's ACKs show again as soon as a request
/// goes off it, so that request comes back to it within 3 RTT, never after
/// its connect, and nothing renews on a dial of its own.
#[test]
fn link_request_off_a_quiet_link_comes_back_during_its_dials_tcp_connect() {
    let (relay, _link, tree) = linked_relay(|config| {
        config.ack_delay = Duration::from_millis(700);
    });
    let slot = LinkSlot::default();
    let options = LinkOptions {
        link_slot: Some(slot.clone()),
        fresh_connect_delay: Some(Duration::from_millis(1200)),
        ..LinkOptions::default()
    };
    let started = start(&tree, options, Duration::from_secs(5));
    let link = slot.lock().unwrap().clone().expect("no ACK connection");
    ready_for(&started, Duration::from_secs(2), |_| {});
    assert_eq!(count(&started.steps, "reack_off_link"), 0);
    assert!(link.freeze_acks_for_test());
    let mut thawed = false;
    ready_for(&started, Duration::from_secs(6), |_| {
        if !thawed && count(&started.steps, "reack_off_link") > 0 {
            assert!(link.thaw_acks_for_test());
            thawed = true;
        }
    });
    assert!(thawed, "no request went off the quiet ACK connection");
    let back = next_after(&started.steps, ("reack_off_link", 0), "reack_back_on_link");
    assert!(back.is_some_and(|back| back <= RTT * 3), "{back:?}");
    assert_eq!(count(&started.steps, "reack_off_link_established"), 0);
    assert_eq!(count(&started.steps, "reack_failed"), 0);
    assert!(
        latencies(&started.renewals, "fresh").is_empty(),
        "{:?}",
        latencies(&started.renewals, "fresh")
    );
    let (acks, _) = ack_and_flow_conns(&relay);
    assert_eq!(acks, BTreeSet::from([0]));
    assert_eq!(started.session.refusal(), None);
    stop(started, &tree);
}

/// S16m: under bulk transfers on the flow pool, a slow relay (700 ms per
/// PolicyAck) keeps both requests in flight on the ACK connection: each
/// request's own bytes are acknowledged, so it is never quiet, and nothing
/// goes off it.
#[test]
fn link_slow_acks_beside_bulk_flows_keep_both_requests_on_the_connection() {
    let (relay, _link, tree) = linked_relay(|config| {
        config.ack_delay = Duration::from_millis(700);
    });
    let started = start(&tree, LinkOptions::default(), Duration::from_secs(5));
    let bulk = bulk_load(&started, 4);
    let from = Instant::now();
    ready_for(&started, Duration::from_secs(8), |_| {});
    assert!(started.renewed_after(from) >= 5);
    assert!(count(&started.steps, "reack_pipelined") >= 2);
    assert_eq!(count(&started.steps, "reack_off_link"), 0);
    assert!(latencies(&started.renewals, "fresh").is_empty());
    let (acks, flows) = ack_and_flow_conns(&relay);
    assert_eq!(acks, BTreeSet::from([0]));
    assert!(acks.is_disjoint(&flows) && !flows.is_empty());
    bulk_moved(bulk, 4);
    assert_eq!(started.session.refusal(), None);
    stop(started, &tree);
}

/// S16m: v23's three `ack_conn lost` were each its session's own end (the
/// relay join after a lease lapse, twice, and the window's stop): the gate
/// drained the ACK connection's driver while pre-warmed streams of it were
/// still establishing, and their failure let it go as lost. A stop with
/// streams establishing on it (every new stream stalled in its inner
/// handshake) lets it go as closed, never lost, and nothing is struck.
#[test]
fn link_stop_with_streams_establishing_is_no_ack_connection_loss() {
    let (relay, _link, tree) = linked_relay(|_| {});
    let started = start(&tree, LinkOptions::default(), Duration::from_secs(4));
    ready_for(&started, Duration::from_secs(2), |_| {});
    // Bulk flows hold their streams; every stream after them stalls.
    let bulk = bulk_load(&started, 2);
    ready_for(&started, Duration::from_millis(500), |_| {});
    relay.always(Some(StreamFault::StallHandshake));
    // A pre-warm started after the fault, past its 200: stalled in its
    // inner handshake on the ACK connection.
    let before = count(&started.steps, "reack_prewarm_start");
    let deadline = Instant::now() + Duration::from_secs(3);
    while count(&started.steps, "reack_prewarm_start") == before {
        assert!(Instant::now() < deadline, "no pre-warm after the fault");
        ready_for(&started, Duration::from_millis(20), |_| {});
    }
    ready_for(&started, RTT * 4, |_| {});
    assert!(relay.connection(0).handshakes().current() >= 1);
    assert_eq!(count(&started.steps, "ack_link_lost"), 0);
    let steps = started.steps.clone();
    stop(started, &tree);
    let (bulk_runtime, load, stop_bulk) = bulk;
    stop_bulk.store(true, Ordering::SeqCst);
    drop(bulk_runtime.block_on(load));
    assert_eq!(
        count(&steps, "ack_link_lost"),
        0,
        "teardown counted as a loss"
    );
    assert!(
        count(&steps, "ack_link_closed") >= 1,
        "{:?}",
        steps
            .lock()
            .unwrap()
            .iter()
            .rev()
            .take(40)
            .map(|(s, _)| *s)
            .collect::<Vec<_>>()
    );
    let runtime = runtime();
    assert!(runtime
        .block_on(relay.wait_closed(0, Duration::from_secs(2)))
        .is_some());
    thread::sleep(Duration::from_millis(200));
    assert_eq!(relay.strikes(), 0);
}
