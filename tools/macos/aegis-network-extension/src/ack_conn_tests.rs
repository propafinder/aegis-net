//! S16l: the ACK connection's own rules, against the multi-stream relay on
//! loopback: one dial under its caller's permit, its streams, when it is
//! let go, its dial budget, and its logs.
use super::*;
use crate::{
    app_group::CapturedAppGroupInputs,
    establish_limit::{AuthBackoff, Purpose, ACK_RESERVE},
    local_identity::PreparedLocalSession,
    test_fixture::ReadyTree,
    test_relay::{
        pool::{PoolConfig, PooledRelay, StreamStep},
        AckReply, RelayIdentity, TestRelay,
    },
};
use aegis_client::protected_online_expectation::ProtectedOnlineExpectation;
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    thread,
};
use tokio::runtime::Runtime;
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    },
    TlsAcceptor,
};

const BUDGET: Duration = Duration::from_secs(5);

// Declaration order is drop order: the link and the held crypto go while
// their runtime still exists.
struct Kit {
    link: Arc<AckLink>,
    limiter: Arc<EstablishLimiter>,
    epoch: AuthBackoff,
    gate: Arc<WorkGate>,
    pins: EpochPins,
    crypto: Arc<PreparedCryptoInputs>,
    _prepared: PreparedLocalSession,
    _store: Arc<ProtectedOnlineExpectation<'static>>,
    runtime: Runtime,
}

impl Kit {
    /// A link to the relay `tree` names, on fresh pins, limiter and gate.
    fn new(tree: &ReadyTree) -> Self {
        let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
        let (prepared, store) = PreparedLocalSession::from_claim_with_store_guard(claim).unwrap();
        let epoch = AuthBackoff::default();
        let limiter = EstablishLimiter::new(epoch.clone());
        let gate = WorkGate::new();
        let interface = RelayInterface::loopback_for_test();
        let pins = EpochPins::pinned_for_test(interface.clone());
        let link = prepared
            .ack_link(
                &interface,
                (limiter.clone(), gate.clone()),
                (pins.clone(), pins.generation()),
                None,
            )
            .unwrap();
        Self {
            link,
            limiter,
            epoch,
            gate,
            pins,
            crypto: prepared.crypto_for_test(),
            _prepared: prepared,
            _store: store,
            runtime: tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap(),
        }
    }

    /// `link.conn` under an ACK-path permit held meanwhile.
    fn conn(&self) -> io::Result<Option<LinkConn>> {
        self.runtime.block_on(async {
            let _permit = self.limiter.acquire(Purpose::Ack, BUDGET).await.unwrap();
            self.link.conn(BUDGET).await
        })
    }

    /// One authenticated stream channel on `conn`.
    fn channel(&self, (conn, live): &LinkConn) -> crate::prepared_crypto::AckReadyChannel {
        self.runtime
            .block_on(
                self.crypto
                    .establish_ack_stream(conn.clone(), live, "test_link"),
            )
            .unwrap()
    }
}

/// A kit on the multi-stream relay answering every PolicyAck.
fn served() -> (PooledRelay, ReadyTree, Kit) {
    served_with(|_| {})
}

/// `served`, its relay configured further by `configure`.
fn served_with(configure: impl FnOnce(&mut PoolConfig)) -> (PooledRelay, ReadyTree, Kit) {
    let listener = TestRelay::bind();
    let tree = ReadyTree::with_online_completed(listener.local_addr().unwrap());
    let mut config = PoolConfig {
        reply: Some(AckReply::for_tree(&tree)),
        ..PoolConfig::default()
    };
    configure(&mut config);
    let relay = TestRelay::spawn_streams(listener, RelayIdentity::for_tree(&tree), config);
    let kit = Kit::new(&tree);
    (relay, tree, kit)
}

/// A relay that accepts `listener`'s connections and runs `serve` on each
/// (inside its runtime), on its own thread; the count of connections
/// accepted.
fn accepting(
    listener: std::net::TcpListener,
    serve: impl Fn(tokio::net::TcpStream) + Send + 'static,
) -> Arc<AtomicUsize> {
    let accepted = Arc::new(AtomicUsize::new(0));
    let counted = accepted.clone();
    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            while let Ok((tcp, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                serve(tcp);
            }
        });
    });
    accepted
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

#[test]
fn conn_live_counts_channels_and_ages_from_the_last_one() {
    let ready = Instant::now();
    let live = ConnLive::new(ready);
    assert_eq!(live.live(), 0);
    // No channel yet: a stream inherits the deadline from its outer TLS.
    let later = ready + Duration::from_millis(700);
    assert_eq!(live.aged_from(later), ready);
    assert_eq!(live.idle_for(later), Some(Duration::from_millis(700)));
    let first = ConnLive::enter(&live);
    let second = ConnLive::enter(&live);
    assert_eq!(live.live(), 2);
    // A live channel: a stream's deadline runs from its own accept.
    assert_eq!(live.aged_from(later), later);
    assert_eq!(live.idle_for(later), None);
    drop(first);
    assert_eq!(live.live(), 1);
    assert_eq!(live.aged_from(later), later);
    let before = Instant::now();
    drop(second);
    let after = Instant::now();
    assert_eq!(live.live(), 0);
    // Idle again from the last channel's end.
    let idle_from = live.aged_from(after + Duration::from_secs(3));
    assert!(idle_from >= before && idle_from <= after, "{idle_from:?}");
    assert!(live.idle_for(after).unwrap() <= after - before);
}

#[test]
fn one_dial_under_its_callers_permit_carries_every_stream() {
    let (relay, _tree, kit) = served();
    let up = kit.runtime.block_on(async {
        let permit = kit.limiter.acquire(Purpose::Ack, BUDGET).await.unwrap();
        let dialed = kit.link.conn(BUDGET).await.unwrap().unwrap();
        // The dial took no permit of its own.
        assert_eq!(kit.limiter.active(), (1, 0));
        drop(permit);
        dialed
    });
    let (conn, live) = (up.0.clone(), up.1.clone());
    assert_eq!(relay.conns(), 1);
    assert_eq!(kit.limiter.auth_failures(), 0);
    // The current connection is the one dialed, stream after stream.
    for _ in 0..3 {
        let (again, shared) = kit.link.current().unwrap();
        assert!(Arc::ptr_eq(&again, &conn));
        assert!(Arc::ptr_eq(&shared, &live));
    }
    // The ACK reserve's worth of authenticated channels, all streams of it.
    let channels: Vec<_> = (0..ACK_RESERVE).map(|_| kit.channel(&up)).collect();
    for channel in &channels {
        let (on, _) = channel.conn().unwrap();
        assert!(Arc::ptr_eq(on, &conn));
    }
    assert_eq!(live.live(), ACK_RESERVE);
    assert_eq!(relay.conns(), 1);
    assert!(wait_until(BUDGET, || relay
        .count(StreamStep::Authenticated)
        == ACK_RESERVE));
    assert!(relay.connection(0).handshakes().high_water() <= ACK_RESERVE);
    let ids: std::collections::BTreeSet<u32> = channels
        .iter()
        .map(|channel| channel.conn().unwrap().1)
        .collect();
    assert_eq!(ids.len(), ACK_RESERVE);
    // While one is live, a new stream ages from its own request.
    let now = Instant::now();
    assert_eq!(live.aged_from(now), now);
    kit.runtime.block_on(async move { drop(channels) });
    assert_eq!(live.live(), 0);
    let stats = kit.link.stats();
    assert_eq!((stats.dials, stats.dialed, stats.lost), (1, 1, 0));
    assert_eq!(stats.streams, 4);
    assert_eq!(relay.strikes(), 0);
}

#[test]
fn dials_are_budgeted_between_bound_requests() {
    // Every connection is dropped before outer TLS: no dial comes up.
    let listener = TestRelay::bind();
    let tree = ReadyTree::with_online_completed(listener.local_addr().unwrap());
    let accepted = accepting(listener, drop);
    let kit = Kit::new(&tree);
    assert!(matches!(kit.conn(), Ok(None)));
    assert_eq!(kit.link.stats().dials, 1);
    // The budget is spent: nothing is dialed until the next bound request.
    assert!(matches!(kit.conn(), Ok(None)));
    assert!(kit.link.claim().is_none());
    assert_eq!(kit.link.stats().dials, 1);
    assert!(wait_until(BUDGET, || accepted.load(Ordering::SeqCst) == 1));
    kit.link.note_request();
    assert!(matches!(kit.conn(), Ok(None)));
    assert_eq!(kit.link.stats().dials, 2);
    assert!(wait_until(BUDGET, || accepted.load(Ordering::SeqCst) == 2));
    // A transport drop is no authentication failure.
    assert_eq!(kit.limiter.auth_failures(), 0);
    // A claim dropped before its dial frees the link for the next one.
    kit.link.note_request();
    let claim = kit.link.claim().unwrap();
    assert!(kit.link.claim().is_none());
    drop(claim);
    kit.link.note_request();
    assert!(kit.link.claim().is_some());
}

#[test]
fn a_refused_outer_handshake_is_judged_and_returned() {
    // Outer TLS without ALPN h2: an explicit carrier refusal.
    let listener = TestRelay::bind();
    let tree = ReadyTree::with_online_completed(listener.local_addr().unwrap());
    let (cert, key) = tree.outer_server_der();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
        )
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let _accepted = accepting(listener, move |tcp| {
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let _tls = acceptor.accept(tcp).await;
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
    });
    let kit = Kit::new(&tree);
    let refused = kit.conn().map(|_| ()).unwrap_err();
    assert!(is_auth_refused(&refused));
    assert_eq!(kit.limiter.auth_failures(), 1);
    assert!(kit.link.current().is_none());
    assert_eq!(kit.link.stats().dialed, 0);
}

#[test]
fn an_ended_connection_is_let_go_and_redialed_within_the_budget() {
    let (relay, _tree, kit) = served();
    let (conn, _) = kit.conn().unwrap().unwrap();
    relay.drop_tcp(0);
    assert!(wait_until(BUDGET, || conn.ended().is_some()));
    assert!(kit.link.current().is_none());
    assert_eq!(kit.link.stats().lost, 1);
    assert!(!kit.link.usable(&conn, 1));
    // Within the dial budget, the next caller redials it.
    assert!(kit.link.claim().is_none());
    kit.link.note_request();
    let (again, _) = kit.conn().unwrap().unwrap();
    assert!(!Arc::ptr_eq(&again, &conn));
    assert_eq!(relay.conns(), 2);
    let stats = kit.link.stats();
    assert_eq!((stats.dials, stats.dialed), (2, 2));
}

#[test]
fn a_goaway_lets_the_connection_go_but_not_the_streams_it_covers() {
    let (relay, _tree, kit) = served();
    let up = kit.conn().unwrap().unwrap();
    let channel = kit.channel(&up);
    let (_, stream_id) = channel.conn().unwrap();
    relay.goaway(0, h2::Reason::NO_ERROR, stream_id);
    assert!(wait_until(BUDGET, || up.0.ended().is_some()));
    assert!(kit.link.current().is_none());
    assert_eq!(kit.link.stats().goaways, 1);
    // The stream the graceful GOAWAY covers may still carry its request; a
    // later one may not.
    assert!(kit.link.usable(&up.0, stream_id));
    assert!(!kit.link.usable(&up.0, stream_id + 2));
    kit.runtime.block_on(async move { drop(channel) });
}

#[test]
fn a_wake_drains_it_and_a_repin_closes_it() {
    let (relay, _tree, kit) = served();
    let (conn, _) = kit.conn().unwrap().unwrap();
    assert!(kit.link.usable(&conn, 1));
    // S16h: dialed before the sleep, it takes no new stream after it.
    kit.epoch.resume();
    assert!(!kit.link.usable(&conn, 1));
    assert!(kit.link.current().is_none());
    assert_eq!(kit.link.stats().drained, 1);
    kit.link.note_request();
    let (woken, _) = kit.conn().unwrap().unwrap();
    assert!(kit.link.usable(&woken, 1));
    assert_eq!(relay.conns(), 2);
    // S18: after a re-pin the session is stale: nothing current, nothing
    // dialed.
    kit.pins.repin(&RelayInterface::loopback_for_test());
    assert!(kit.link.closed());
    assert!(kit.link.current().is_none());
    // Let go at once, so it closes once its last channel is done.
    assert_eq!(kit.link.stats().drained, 2);
    assert!(!kit.link.usable(&woken, 1));
    kit.link.note_request();
    assert!(matches!(kit.conn(), Ok(None)));
    assert!(kit.link.claim().is_none());
    assert_eq!(kit.link.stats().dials, 2);
    assert_eq!(relay.conns(), 2);
}

#[test]
fn an_idle_connection_is_drained_past_idle_reuse() {
    let (relay, _tree, kit) = served();
    let up = kit.conn().unwrap().unwrap();
    // A live channel keeps it current however long.
    let channel = kit.channel(&up);
    thread::sleep(ACK_IDLE_REUSE + Duration::from_millis(200));
    let (current, _) = kit.link.current().unwrap();
    assert!(Arc::ptr_eq(&current, &up.0));
    // With none, within idle reuse it still is; past it, it is drained.
    kit.runtime.block_on(async move { drop(channel) });
    thread::sleep(ACK_IDLE_REUSE / 2);
    assert!(kit.link.current().is_some());
    thread::sleep(ACK_IDLE_REUSE);
    assert!(kit.link.current().is_none());
    assert_eq!(kit.link.stats().drained, 1);
    assert_eq!(relay.conns(), 1);
}

#[test]
fn a_connection_is_drained_past_its_streams_its_age_or_the_relays_stream_room() {
    use crate::flow_pool::MAX_CONN_STREAMS;
    // Its streams over its life: the dial's, then every one given out.
    let (_relay, _tree, kit) = served();
    let (conn, _) = kit.conn().unwrap().unwrap();
    for _ in 1..MAX_CONN_STREAMS {
        let (again, _) = kit.link.current().unwrap();
        assert!(Arc::ptr_eq(&again, &conn));
    }
    assert!(kit.link.current().is_none());
    assert_eq!(kit.link.stats().drained, 1);
    assert_eq!(kit.link.stats().streams, MAX_CONN_STREAMS);
    // Its age.
    let (relay, _tree, kit) = served();
    let up = kit.conn().unwrap().unwrap();
    let channel = kit.channel(&up);
    kit.link.set_max_age_for_test(Duration::from_millis(300));
    assert!(kit.link.current().is_some());
    thread::sleep(Duration::from_millis(350));
    assert!(kit.link.current().is_none());
    assert_eq!(kit.link.stats().drained, 1);
    kit.runtime.block_on(async move { drop(channel) });
    drop(relay);
    // The relay's SETTINGS leaving it no stream room (S16i-2), read at the
    // next 200.
    let listener = TestRelay::bind();
    let tree = ReadyTree::with_online_completed(listener.local_addr().unwrap());
    let config = PoolConfig {
        reply: Some(AckReply::for_tree(&tree)),
        settings_injection: true,
        ..PoolConfig::default()
    };
    let relay = TestRelay::spawn_streams(listener, RelayIdentity::for_tree(&tree), config);
    let kit = Kit::new(&tree);
    let up = kit.conn().unwrap().unwrap();
    let first = kit.channel(&up);
    assert!(kit.link.current().is_some());
    relay.advertise_streams(0, 2);
    thread::sleep(Duration::from_millis(100));
    let second = kit.channel(&up);
    assert_eq!(up.0.stream_cap(), 0);
    assert!(kit.link.current().is_none());
    assert_eq!(kit.link.stats().drained, 1);
    kit.runtime.block_on(async move { drop((first, second)) });
}

#[test]
fn a_closed_gate_dials_nothing() {
    let (relay, _tree, kit) = served();
    kit.gate.stop(Duration::from_secs(1)).unwrap();
    assert!(kit.link.closed());
    assert!(matches!(kit.conn(), Ok(None)));
    assert!(kit.link.claim().is_none());
    assert_eq!(kit.link.stats().dials, 0);
    assert_eq!(relay.conns(), 0);
}

#[test]
fn a_failed_stream_lets_its_connection_go_unless_authentication_refused() {
    let (_relay, _tree, kit) = served();
    let (conn, _) = kit.conn().unwrap().unwrap();
    // An authentication-class refusal is the device's, not the connection's.
    kit.link
        .failed(&conn, &crate::establish_limit::auth_refused());
    assert!(kit.link.current().is_some());
    // Any other failure lets it go, once.
    let lost = io::Error::from(io::ErrorKind::ConnectionReset);
    kit.link.failed(&conn, &lost);
    assert!(kit.link.current().is_none());
    kit.link.failed(&conn, &lost);
    assert_eq!(kit.link.stats().lost, 1);
    // A connection other than the current one is never let go for it.
    kit.link.note_request();
    let (next, _) = kit.conn().unwrap().unwrap();
    kit.link.failed(&conn, &lost);
    let (current, _) = kit.link.current().unwrap();
    assert!(Arc::ptr_eq(&current, &next));
    assert_eq!(kit.link.stats().lost, 1);
}

#[test]
fn a_request_without_a_sign_of_life_makes_its_connection_quiet() {
    let (_relay, _tree, kit) = served();
    let up = kit.conn().unwrap().unwrap();
    let conn = up.0.clone();
    assert_eq!(
        quiet_after(Duration::from_millis(100)),
        Duration::from_millis(400)
    );
    assert_eq!(
        quiet_after(Duration::from_millis(170)),
        Duration::from_millis(450)
    );
    let after = quiet_after(conn.srtt());
    // No request: never quiet.
    assert!(!kit.link.quiet(&conn) && !kit.link.quiet_any());
    // A request whose connection then shows life is never quiet.
    let request = kit.link.begin(&conn);
    let channel = kit.channel(&up);
    thread::sleep(after + Duration::from_millis(20));
    assert!(!kit.link.quiet(&conn));
    drop(request);
    // One that left after the last sign of life is quiet once `quiet_after`
    // passed, not before; it ends with the request.
    let request = kit.link.begin(&conn);
    assert!(!kit.link.quiet(&conn));
    thread::sleep(after + Duration::from_millis(20));
    assert!(kit.link.quiet(&conn) && kit.link.quiet_any());
    // Another connection is not quiet for it.
    kit.link
        .failed(&conn, &io::Error::from(io::ErrorKind::ConnectionReset));
    kit.link.note_request();
    let (other, _) = kit.conn().unwrap().unwrap();
    assert!(!kit.link.quiet(&other));
    drop(request);
    assert!(!kit.link.quiet(&conn) && !kit.link.quiet_any());
    kit.runtime.block_on(async move { drop(channel) });
}

#[test]
fn a_slow_connection_is_quiet_inside_the_stagger_between_two_requests() {
    // Review v23: on a path whose srtt passed about 200 ms an uncapped
    // threshold (srtt + 300 ms) outlasted the 500 ms stagger, so the second
    // request rode a connection that froze under the first and both lost
    // the lease at its stall-watchdog close.
    use crate::provider_session_body::REACK_SPACING;
    for srtt_ms in [150, 200, 250, 400, 700, 1_000, 5_000] {
        let after = quiet_after(Duration::from_millis(srtt_ms));
        assert_eq!(after, REACK_SPACING - QUIET_SLACK, "srtt {srtt_ms} ms");
    }
    assert_eq!(quiet_after(Duration::MAX), REACK_SPACING - QUIET_SLACK);
    let (_relay, _tree, kit) = served();
    let up = kit.conn().unwrap().unwrap();
    let conn = up.0.clone();
    // A settled connection with a channel of its own (its carrier sample
    // taken), then the slow path's round trip.
    let channel = kit.channel(&up);
    thread::sleep(Duration::from_millis(200));
    conn.set_srtt_for_test(Duration::from_millis(400));
    assert_eq!(conn.srtt(), Duration::from_millis(400));
    // A request with no sign of life since it left: not quiet at first, and
    // quiet by the time the second request in flight is due.
    let request = kit.link.begin(&conn);
    assert!(!kit.link.quiet(&conn) && !kit.link.quiet_any());
    thread::sleep(REACK_SPACING);
    assert!(
        kit.link.quiet(&conn) && kit.link.quiet_any(),
        "srtt {:?}, alive since: {}",
        conn.srtt(),
        conn.alive_since(Instant::now() - REACK_SPACING)
    );
    drop(request);
    assert!(!kit.link.quiet(&conn));
    kit.runtime.block_on(async move { drop(channel) });
}

#[test]
fn a_frozen_connection_is_closed_by_its_watchdog_and_never_narrows_the_flow_pool() {
    // Two ACK connections in turn, each frozen under a request in flight
    // (the relay reads and writes nothing, and no byte is acknowledged):
    // each one's stall watchdog closes it, a local close; two such stall
    // deaths of flow connections would switch the flow pool to one stream
    // per connection (S16h-8d), but the ACK path's never count.
    let (relay, _tree, kit) = served();
    for conn in 0..2 {
        if conn > 0 {
            kit.link.note_request();
        }
        let (up, _) = kit.conn().unwrap().unwrap();
        relay.freeze(conn);
        up.freeze_acks_for_test();
        let _request = kit.link.begin(&up);
        let _awaiting = up.awaiting();
        assert!(wait_until(Duration::from_secs(6), || up.ended().is_some()));
        assert_eq!(up.ended(), Some(ConnEnd::LocalClose));
        assert!(kit.link.current().is_none());
    }
    assert_eq!(kit.link.stats().lost, 2);
    assert!(!kit.limiter.pool_mode().fallback);
    assert_eq!(relay.strikes(), 0);
}

#[test]
fn link_logs_are_stable_and_rate_limited_per_code() {
    let (_relay, _tree, kit) = served();
    let start = Instant::now();
    for code in LINK_CODES {
        let fields = kit.link.log_line(code, start).unwrap();
        assert_eq!(fields, [code]);
        assert!(crate::apple::stable_fields("ack_conn", &[code]));
    }
    // Held back within the period, per code.
    let soon = start + LINK_LOG_EVERY / 2;
    assert_eq!(kit.link.log_line("lost", soon), None);
    assert_eq!(kit.link.log_line("lost", soon), None);
    assert_eq!(kit.link.log_line("fallback", soon), None);
    let later = start + LINK_LOG_EVERY;
    let lost = kit.link.log_line("lost", later).unwrap();
    assert_eq!(lost, ["lost", "held:2"]);
    let fields: Vec<&str> = lost.iter().map(String::as_str).collect();
    assert!(crate::apple::stable_fields("ack_conn", &fields));
    assert_eq!(
        kit.link.log_line("fallback", later).unwrap(),
        ["fallback", "held:1"]
    );
    assert_eq!(kit.link.log_line("dialed", later).unwrap(), ["dialed"]);
    // An unknown code is never logged.
    assert_eq!(kit.link.log_line("unknown", later), None);
}

#[test]
fn inbound_bytes_already_on_their_way_are_no_sign_of_a_later_requests_life() {
    // S16m, v23 54.29 s: the ACK of the request before it landed 40 ms
    // after the second request left and counted as that one's life for
    // good, so the third rode the same connection and both lapsed the lease.
    // An answer the relay sends to an earlier request proves nothing about
    // a request that left after it: only a TCP ACK of a byte written after
    // the request left does.
    let (_relay, _tree, kit) = served_with(|config| {
        config.ack_delay = Duration::from_millis(300);
    });
    let up = kit.conn().unwrap().unwrap();
    let conn = up.0.clone();
    let mut channel = kit.channel(&up);
    thread::sleep(Duration::from_millis(100));
    // An earlier request, answered 300 ms from now.
    kit.runtime
        .block_on(channel.request_ack_for_test())
        .unwrap();
    thread::sleep(Duration::from_millis(50));
    // The path freezes for what is written from now on; the next request
    // leaves.
    conn.freeze_acks_for_test();
    let left = Instant::now();
    let request = kit.link.begin(&conn);
    // The earlier answer arrives after it left...
    assert!(wait_until(Duration::from_secs(2), || conn.alive_since(left)));
    // ...and is no sign of its life: it is quiet once `quiet_after` passed.
    let after = quiet_after(conn.srtt());
    thread::sleep(
        (left + after + Duration::from_millis(20)).saturating_duration_since(Instant::now()),
    );
    assert!(
        kit.link.quiet(&conn),
        "an earlier answer kept the request alive"
    );
    assert!(kit.link.quiet_mark(&conn).is_some() && kit.link.quiet_any());
    drop(request);
    assert!(!kit.link.quiet(&conn));
    kit.runtime.block_on(async move { drop(channel) });
}

#[test]
fn a_requests_own_acknowledged_bytes_show_its_life_before_any_answer() {
    // S16m: a request whose bytes the relay's TCP acknowledged is alive,
    // read when asked: no answer for 2 s, no inbound byte, and no stall
    // watchdog sample (nothing awaits on the connection), where v23's rule
    // saw no sign of life and sent the next request off the connection.
    let (_relay, _tree, kit) = served_with(|config| {
        config.ack_delay = Duration::from_secs(2);
    });
    let up = kit.conn().unwrap().unwrap();
    let conn = up.0.clone();
    let mut channel = kit.channel(&up);
    thread::sleep(Duration::from_millis(300));
    let left = Instant::now();
    let mark = conn.write_mark();
    let request = kit.link.begin(&conn);
    assert!(!conn.acked_beyond(mark));
    kit.runtime
        .block_on(channel.request_ack_for_test())
        .unwrap();
    assert!(wait_until(Duration::from_secs(1), || conn.acked_beyond(mark)));
    thread::sleep(quiet_after(conn.srtt()) + Duration::from_millis(20));
    // The old evidence saw nothing...
    assert!(!conn.alive_since(left));
    // ...the request's own acknowledged bytes keep it from quiet.
    assert!(!kit.link.quiet(&conn) && !kit.link.quiet_any());
    assert_eq!(kit.link.quiet_mark(&conn), None);
    // Frozen before its bytes left, the same request is quiet.
    drop(request);
    conn.freeze_acks_for_test();
    let mark = conn.write_mark();
    let request = kit.link.begin(&conn);
    kit.runtime
        .block_on(channel.request_ack_for_test())
        .unwrap();
    thread::sleep(quiet_after(conn.srtt()) + Duration::from_millis(20));
    assert!(!conn.acked_beyond(mark));
    assert_eq!(kit.link.quiet_mark(&conn), Some(mark));
    drop(request);
    kit.runtime.block_on(async move { drop(channel) });
}

#[test]
fn a_quiet_connection_revives_once_a_byte_after_its_request_is_acknowledged() {
    // S16m, v23 13.30 s: a request sent off a connection judged quiet goes
    // back to it once the evidence its quiet request lacked arrives, and
    // only then: never while its bytes are unacknowledged, never on a
    // connection the link let go, never once the link is closed.
    let (_relay, _tree, kit) = served();
    let up = kit.conn().unwrap().unwrap();
    let conn = up.0.clone();
    let mut channel = kit.channel(&up);
    thread::sleep(Duration::from_millis(200));
    conn.freeze_acks_for_test();
    let request = kit.link.begin(&conn);
    kit.runtime
        .block_on(channel.request_ack_for_test())
        .unwrap();
    thread::sleep(quiet_after(conn.srtt()) + Duration::from_millis(20));
    let mark = kit.link.quiet_mark(&conn).expect("not quiet");
    assert!(!kit.link.revived(&conn, mark));
    // The backlog drains: its bytes show acknowledged.
    conn.thaw_acks_for_test();
    assert!(kit.link.revived(&conn, mark));
    assert!(!kit.link.quiet(&conn));
    kit.link.note_revived();
    assert_eq!(kit.link.stats().revived, 1);
    // Let go, it never revives.
    kit.link
        .failed(&conn, &io::Error::from(io::ErrorKind::ConnectionReset));
    assert!(!kit.link.revived(&conn, mark));
    drop(request);
    kit.runtime.block_on(async move { drop(channel) });
}

#[test]
fn a_closed_link_lets_its_connection_go_as_closed_never_lost() {
    // S16m: v23's three `ack_conn lost` were each its session's own
    // teardown (the relay join after a lease lapse, twice, and the
    // window's stop): the gate drained the connection's driver and its
    // streams failed. Once the link is closed, an end or a failed stream is
    // `closed`, whichever path sees it first, and nothing revives.
    let (_relay, _tree, kit) = served();
    let (conn, _) = kit.conn().unwrap().unwrap();
    kit.gate.stop(Duration::from_secs(1)).unwrap();
    assert!(wait_until(Duration::from_secs(2), || conn
        .ended()
        .is_some()));
    kit.link
        .failed(&conn, &io::Error::from(io::ErrorKind::ConnectionReset));
    let stats = kit.link.stats();
    assert_eq!((stats.closed, stats.lost), (1, 0), "{stats:?}");
    assert!(kit.link.current().is_none());
    // Its socket let go before it closed: no read on demand outlives it.
    assert!(!conn.socket_held_for_test());
    assert!(!conn.acked_beyond(0));
    drop(kit);
    // An end its next look finds once closed is `closed` too.
    let (_relay, _tree, kit) = served();
    let (conn, _) = kit.conn().unwrap().unwrap();
    kit.gate.stop(Duration::from_secs(1)).unwrap();
    assert!(wait_until(Duration::from_secs(2), || conn
        .ended()
        .is_some()));
    assert!(kit.link.current().is_none());
    let stats = kit.link.stats();
    assert_eq!((stats.closed, stats.lost), (1, 0), "{stats:?}");
    drop(kit);
    // Open, the same failure is a loss.
    let (_relay, _tree, kit) = served();
    let (conn, _) = kit.conn().unwrap().unwrap();
    kit.link
        .failed(&conn, &io::Error::from(io::ErrorKind::ConnectionReset));
    let stats = kit.link.stats();
    assert_eq!((stats.closed, stats.lost), (0, 1), "{stats:?}");
    drop(kit);
    // A re-pin closes the link: its current connection, acknowledged and
    // not ended, revives no request.
    let (_relay, _tree, kit) = served();
    let (conn, _) = kit.conn().unwrap().unwrap();
    assert!(wait_until(Duration::from_secs(1), || kit
        .link
        .revived(&conn, 0)));
    kit.pins.repin(&RelayInterface::loopback_for_test());
    assert!(kit.link.closed() && conn.ended().is_none());
    assert!(!kit.link.revived(&conn, 0));
}
