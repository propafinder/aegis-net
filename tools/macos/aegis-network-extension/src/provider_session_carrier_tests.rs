//! B-06 v40 (CP-D3 M1): carrier failover inside the composite session body,
//! against loopback relays standing for the pins of one signed pool (a
//! direct relay and CDN edge pins on their own ports, every pin with the
//! fixture's outer identity). A pin that refuses TCP, drops its SYNs, cuts
//! the outer handshake or answers the carrier with a non-200 moves the
//! session build to the next pin before any device identity is sent; a
//! build whose every pin fails is refused and dials nothing else; the
//! profile's controller remembers the failed pin for the next build.
use crate::{
    app_group::CapturedAppGroupInputs,
    carrier_failover::{inspect, profile_identity},
    provider_session::{
        relay::{production_bridge, recorder},
        SessionHandle, SessionPhase,
    },
    provider_session_body::{spawn_link, tests::saved, EpochPins, LinkOptions},
    test_fixture::ReadyTree,
    test_relay::{
        pool::{PoolConfig, PooledRelay, StreamFault, StreamStep},
        AckReply, RelayIdentity, StalledListener, TestRelay,
    },
};
use aegis_core::brain::carrier_failover::{CarrierSignal, CarrierState, NetworkKey};
use std::{
    net::SocketAddr,
    sync::mpsc,
    time::{Duration, Instant},
};

/// A loopback port nothing listens on: a dial is refused at once.
fn refused_pin() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

/// The multi-stream relay on `listener`, answering every PolicyAck.
fn live(
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

/// A session of a fresh epoch on `tree` (production's ACK connection) and
/// its first phase within `within`.
fn start(tree: &ReadyTree, pins: &EpochPins, within: Duration) -> (SessionHandle, SessionPhase) {
    let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
    let (trace, _steps) = recorder();
    let (tx, phases) = mpsc::channel();
    let session = spawn_link(
        saved(tree),
        claim,
        move |phase| {
            let _ = tx.send(phase);
        },
        (Some(trace), production_bridge()),
        LinkOptions {
            pinned: Some(pins.clone()),
            ..LinkOptions::default()
        },
    )
    .unwrap();
    let phase = phases.recv_timeout(within).unwrap_or(SessionPhase::Joined);
    (session, phase)
}

fn identity(tree: &ReadyTree) -> [u8; 32] {
    profile_identity(tree.profile_sha256())
}

fn state(tree: &ReadyTree, carrier: usize) -> CarrierState {
    inspect(identity(tree), |controller| {
        controller.state(NetworkKey::UNKNOWN, carrier, Instant::now())
    })
    .expect("the profile's controller")
}

fn last_signal(tree: &ReadyTree, carrier: usize) -> Option<CarrierSignal> {
    inspect(identity(tree), |controller| {
        controller.last_signal(NetworkKey::UNKNOWN, carrier)
    })
    .expect("the profile's controller")
}

fn active(tree: &ReadyTree) -> Option<usize> {
    inspect(identity(tree), |controller| {
        controller.active(NetworkKey::UNKNOWN)
    })
    .expect("the profile's controller")
}

fn stop(mut session: SessionHandle) {
    assert!(session.try_join(Duration::from_secs(5)));
}

#[test]
fn a_refused_pin_moves_the_build_to_the_next_pin_and_the_guard_holds_the_whole_pool() {
    let blocked = refused_pin();
    let listener = TestRelay::bind();
    let tree = ReadyTree::pooled(blocked, &[listener.local_addr().unwrap()]);
    let relay = live(listener, &tree, |_| {});
    let pins = EpochPins::default();
    let (session, phase) = start(&tree, &pins, Duration::from_secs(8));
    assert_eq!(phase, SessionPhase::Ready, "{:?}", session.refusal());
    assert!(relay.acks() >= 1, "the second pin carried the ACK");
    assert!(matches!(state(&tree, 0), CarrierState::Cooling { .. }));
    assert_eq!(last_signal(&tree, 0), Some(CarrierSignal::DialRefused));
    assert_eq!(active(&tree), Some(1));
    // The epoch's guard record names every pin of the signed pool, exactly.
    let guard = pins.guard().expect("the session recorded its guard");
    let armed: Vec<SocketAddr> = guard
        .relays
        .as_slice()
        .iter()
        .map(|peer| SocketAddr::new(peer.ip, peer.port))
        .collect();
    assert_eq!(armed, tree.pins());
    stop(session);
    // The next build of this profile starts on the pin that worked.
    let pins = EpochPins::default();
    let (session, phase) = start(&tree, &pins, Duration::from_secs(5));
    assert_eq!(phase, SessionPhase::Ready, "{:?}", session.refusal());
    stop(session);
}

#[test]
fn an_edge_refusal_of_the_carrier_moves_the_build_on_before_any_identity() {
    let edge = TestRelay::bind();
    let next = TestRelay::bind();
    let tree = ReadyTree::pooled(edge.local_addr().unwrap(), &[next.local_addr().unwrap()]);
    let refusing = live(edge, &tree, |_| {});
    refusing.always(Some(StreamFault::RejectCarrier(403)));
    let relay = live(next, &tree, |_| {});
    let (session, phase) = start(&tree, &EpochPins::default(), Duration::from_secs(10));
    assert_eq!(phase, SessionPhase::Ready, "{:?}", session.refusal());
    // The edge saw the carrier request and nothing after it: no inner
    // handshake, no PolicyAck (no identity was sent to it).
    assert!(refusing.count(StreamStep::CarrierRejected) >= 1);
    assert_eq!(refusing.count(StreamStep::Authenticated), 0);
    assert_eq!(refusing.count(StreamStep::Struck), 0);
    assert_eq!(refusing.acks(), 0);
    assert!(relay.acks() >= 1);
    assert_eq!(last_signal(&tree, 0), Some(CarrierSignal::EdgeRefused));
    assert_eq!(active(&tree), Some(1));
    stop(session);
}

#[test]
fn a_handshake_cut_after_the_client_hello_moves_the_build_on() {
    let cut = TestRelay::bind();
    let next = TestRelay::bind();
    let tree = ReadyTree::pooled(cut.local_addr().unwrap(), &[next.local_addr().unwrap()]);
    // Every connection is accepted and dropped at once: the outer TLS
    // handshake ends with a reset or EOF, as an SNI filter cuts it.
    let resetting = TestRelay::spawn_each(cut, RelayIdentity::for_tree(&tree), |_| None);
    let relay = live(next, &tree, |_| {});
    let (session, phase) = start(&tree, &EpochPins::default(), Duration::from_secs(10));
    assert_eq!(phase, SessionPhase::Ready, "{:?}", session.refusal());
    assert!(resetting.accepts() >= 1);
    assert!(relay.acks() >= 1);
    assert_eq!(last_signal(&tree, 0), Some(CarrierSignal::HandshakeReset));
    stop(session);
}

#[test]
fn a_pin_that_drops_its_syns_times_out_and_the_build_moves_on() {
    let stalled = StalledListener::bind();
    let next = TestRelay::bind();
    let tree = ReadyTree::pooled(stalled.address(), &[next.local_addr().unwrap()]);
    let relay = live(next, &tree, |_| {});
    let started = Instant::now();
    let (session, phase) = start(&tree, &EpochPins::default(), Duration::from_secs(15));
    assert_eq!(phase, SessionPhase::Ready, "{:?}", session.refusal());
    // One establishment budget (5 s) on the silent pin, not more.
    assert!(
        started.elapsed() < Duration::from_secs(12),
        "{:?}",
        started.elapsed()
    );
    assert!(relay.acks() >= 1);
    assert_eq!(last_signal(&tree, 0), Some(CarrierSignal::DialTimeout));
    stop(session);
}

#[test]
fn a_build_whose_every_pin_fails_is_refused_and_dials_nothing_else() {
    let first = refused_pin();
    let second = TestRelay::bind();
    let tree = ReadyTree::pooled(first, &[second.local_addr().unwrap()]);
    let refusing = live(second, &tree, |_| {});
    refusing.always(Some(StreamFault::RejectCarrier(503)));
    let (session, phase) = start(&tree, &EpochPins::default(), Duration::from_secs(10));
    assert_ne!(phase, SessionPhase::Ready);
    assert!(refusing.count(StreamStep::CarrierRejected) >= 1);
    assert_eq!(refusing.count(StreamStep::Authenticated), 0);
    assert_eq!(refusing.acks(), 0);
    // Both pins are cooling; nothing outside the pool was ever dialed (the
    // session's sockets go only to `direct_peer`'s selected pin).
    assert!(matches!(state(&tree, 0), CarrierState::Cooling { .. }));
    assert!(matches!(state(&tree, 1), CarrierState::Cooling { .. }));
    assert_eq!(active(&tree), None);
    assert!(session.refusal().is_some());
    stop(session);
}

#[test]
fn a_single_pin_profile_keeps_no_controller() {
    let listener = TestRelay::bind();
    let tree = ReadyTree::with_online_completed(listener.local_addr().unwrap());
    let relay = live(listener, &tree, |_| {});
    let (session, phase) = start(&tree, &EpochPins::default(), Duration::from_secs(5));
    assert_eq!(phase, SessionPhase::Ready, "{:?}", session.refusal());
    assert!(relay.acks() >= 1);
    assert!(inspect(identity(&tree), |_| ()).is_none());
    stop(session);
}

#[tokio::test]
async fn later_dials_of_an_open_session_record_one_fault_and_lose_the_pin_at_the_second() {
    use crate::{
        establish_limit::EstablishLimiter, flow_pool::PooledConn, held_relay_services::WorkGate,
        local_identity::PreparedLocalSession, relay_socket::RelayInterface,
    };
    let blocked = refused_pin();
    let listener = TestRelay::bind();
    let tree = ReadyTree::pooled(listener.local_addr().unwrap(), &[blocked]);
    drop(listener);
    let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
    let mut prepared = PreparedLocalSession::from_claim(claim).unwrap();
    let carriers = prepared.carrier_plan(NetworkKey::UNKNOWN).unwrap();
    let ticket = carriers.ticket(1).unwrap();
    prepared.select_carrier(1, Some(ticket.clone())).unwrap();
    // The session opened on pin 1 (its ACK verified), then pin 1 began to
    // refuse new connections.
    ticket.opened();
    let crypto = prepared.crypto_for_test();
    // The held crypto is shared now: no session can switch its pin.
    assert!(prepared.select_carrier(0, None).is_err());
    let limiter = EstablishLimiter::new(Default::default());
    let gate = WorkGate::new();
    let interface = RelayInterface::loopback_for_test();
    let dial = || PooledConn::dial(blocked, &interface, &crypto, &limiter, &gate, 0);
    assert!(dial().await.is_err());
    assert!(!ticket.lost(), "one transient failure keeps the session");
    assert!(matches!(state(&tree, 1), CarrierState::Cooling { .. }));
    assert_eq!(last_signal(&tree, 1), Some(CarrierSignal::DialRefused));
    assert!(dial().await.is_err());
    assert!(ticket.lost(), "the second ends the session for a rebuild");
    // A dial to any tuple but the session's pin is refused before a SYN.
    assert!(
        PooledConn::dial(tree.relay(), &interface, &crypto, &limiter, &gate, 0)
            .await
            .is_err()
    );
    drop((ticket, carriers));
}

#[test]
fn a_pin_lost_under_a_running_session_ends_it_and_the_rebuild_runs_on_the_next_pin() {
    let first = TestRelay::bind();
    let second = TestRelay::bind();
    let tree = ReadyTree::pooled(first.local_addr().unwrap(), &[second.local_addr().unwrap()]);
    let relay = live(first, &tree, |_| {});
    let fallback = live(second, &tree, |_| {});
    let (session, phase) = start(&tree, &EpochPins::default(), Duration::from_secs(5));
    assert_eq!(phase, SessionPhase::Ready, "{:?}", session.refusal());
    assert_eq!(active(&tree), Some(0));
    assert_eq!(fallback.acks(), 0);
    // The primary goes away under the running session: its connections end
    // and every later dial to it is refused.
    drop(relay);
    let deadline = Instant::now() + Duration::from_secs(10);
    while session.refusal().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    let code = session.refusal().expect("the session ended");
    assert!(
        [
            "carrier_unavailable",
            "capture_lease_expired",
            "session_monitor_ended"
        ]
        .contains(&code),
        "{code}"
    );
    assert_eq!(
        crate::session_rebuild::classify(code),
        crate::session_rebuild::Recovery::Recoverable
    );
    stop(session);
    // The S17 rebuild's next build plans the pool again: the lost primary
    // is cooling, so it starts on the fallback pin.
    assert!(matches!(state(&tree, 0), CarrierState::Cooling { .. }));
    let (session, phase) = start(&tree, &EpochPins::default(), Duration::from_secs(5));
    assert_eq!(phase, SessionPhase::Ready, "{:?}", session.refusal());
    assert!(fallback.acks() >= 1);
    assert_eq!(active(&tree), Some(1));
    stop(session);
}

#[tokio::test]
async fn an_unanswered_liveness_ping_on_an_open_session_is_its_pins_freeze() {
    use crate::{
        establish_limit::EstablishLimiter,
        flow_pool::{ConnEnd, PooledConn},
        held_relay_services::WorkGate,
        local_identity::PreparedLocalSession,
        relay_socket::RelayInterface,
    };
    let first = TestRelay::bind();
    let second = TestRelay::bind();
    let tree = ReadyTree::pooled(first.local_addr().unwrap(), &[second.local_addr().unwrap()]);
    let relay = live(first, &tree, |_| {});
    drop(second);
    let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
    let mut prepared = PreparedLocalSession::from_claim(claim).unwrap();
    let carriers = prepared.carrier_plan(NetworkKey::UNKNOWN).unwrap();
    let ticket = carriers.ticket(0).unwrap();
    prepared.select_carrier(0, Some(ticket.clone())).unwrap();
    ticket.opened();
    let crypto = prepared.crypto_for_test();
    let limiter = EstablishLimiter::new(Default::default());
    let gate = WorkGate::new();
    let interface = RelayInterface::loopback_for_test();
    let conn = PooledConn::dial(tree.relay(), &interface, &crypto, &limiter, &gate, 0)
        .await
        .unwrap();
    // A request awaits the relay when the path freezes: no byte either way.
    let awaiting = conn.awaiting();
    relay.freeze(0);
    conn.freeze_acks_for_test();
    let deadline = Instant::now() + Duration::from_secs(6);
    while conn.ended().is_none() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(conn.ended(), Some(ConnEnd::LocalClose));
    assert_eq!(conn.pings(), 1, "one liveness PING, no PONG");
    assert_eq!(last_signal(&tree, 0), Some(CarrierSignal::SessionFreeze));
    // One session's freeze is a degradation: the pin stays usable until a
    // second session degrades on it (the policy's threshold of 2).
    assert_eq!(state(&tree, 0), CarrierState::Closed);
    assert!(!ticket.lost());
    drop((awaiting, conn, ticket, carriers));
}
