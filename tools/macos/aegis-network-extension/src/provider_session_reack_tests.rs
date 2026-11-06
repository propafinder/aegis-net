//! Continuous re-ACK on the bridge clock (B-06 S05, S16e). The test relay
//! grants 3000 ms per ACK, the aegis-core registry cap, and serves one ACK
//! per connection, so every renewal is its own TCP, outer H2 and inner TLS
//! connection, pre-warmed or fresh: the per-dial ACK path, which S16l keeps
//! as its fallback while the persistent ACK connection is down (its own
//! tests run on the multi-stream relay, `provider_session_link_tests`).
use crate::{
    app_group::CapturedAppGroupInputs,
    bridge::{LeasedPacketBridge, PacketBridge},
    configuration::SavedProviderIntent,
    policy::FullWide,
    provider_session::{SessionHandle, SessionPhase},
    provider_session_body::{
        next_reack_ns, prewarm_due_ns, prewarm_exchange_limit, prewarm_usable, reack_lead,
        reack_ok_logged, renew_lease, spawn_on_bridge, spawn_with_prewarm_age,
        tests::{expect_phase, frame, saved, store_locked, wait_until},
        Lease, Trace, PREWARM_DIALS_PER_REACK, PREWARM_EXCHANGE_FLOOR, PREWARM_LEAD,
        PREWARM_MAX_AGE, PREWARM_SLOTS, REACK_LEAD, REACK_LEAD_MARGIN, REACK_SPACING,
    },
    relay_socket::RelayInterface,
    test_fixture::ReadyTree,
    test_relay::{AckReply, Behavior, RelayIdentity, RelayStep, TestRelay, ADMISSION_TIMEOUT},
};
use aegis_client::capture_lease_gate::CaptureLeaseDeadline;
use std::{
    os::fd::AsRawFd,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use tokio::sync::oneshot;

type Steps = Arc<Mutex<Vec<(&'static str, Instant)>>>;

const MS: u64 = 1_000_000;

// The bound on a request over a pre-warmed channel in direct tests.
const LIMIT: Duration = Duration::from_secs(5);

fn ns(duration: Duration) -> u64 {
    duration.as_nanos() as u64
}

fn server_ack(tree: &ReadyTree) -> Behavior {
    Behavior::AckThenClose {
        reply: AckReply::for_tree(tree),
        idle: ADMISSION_TIMEOUT,
    }
}

/// A relay whose connection `index` gets `behavior(tree, index)`.
fn relay_each(
    behavior: impl Fn(&ReadyTree, usize) -> Option<Behavior> + Send + 'static,
) -> (TestRelay, Arc<ReadyTree>) {
    let listener = TestRelay::bind();
    let tree = Arc::new(ReadyTree::with_online_completed(
        listener.local_addr().unwrap(),
    ));
    let served = tree.clone();
    let relay = TestRelay::spawn_each(listener, RelayIdentity::for_tree(&tree), move |index| {
        behavior(&served, index)
    });
    assert_eq!(relay.address(), tree.relay());
    (relay, tree)
}

fn recorder() -> (Trace, Steps) {
    let steps: Steps = Arc::default();
    let held = steps.clone();
    let trace: Trace = Arc::new(move |step| held.lock().unwrap().push((step, Instant::now())));
    (trace, steps)
}

fn count(steps: &Steps, wanted: &str) -> usize {
    steps
        .lock()
        .unwrap()
        .iter()
        .filter(|(step, _)| *step == wanted)
        .count()
}

fn times(steps: &Steps, wanted: &str) -> Vec<Instant> {
    steps
        .lock()
        .unwrap()
        .iter()
        .filter(|(step, _)| *step == wanted)
        .map(|(_, at)| *at)
        .collect()
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

fn start(
    tree: &ReadyTree,
    bridge: LeasedPacketBridge,
    trace: Trace,
) -> (SessionHandle, mpsc::Receiver<SessionPhase>) {
    let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
    let (tx, rx) = mpsc::channel();
    let session = spawn_on_bridge(
        saved(tree),
        claim,
        move |phase| {
            let _ = tx.send(phase);
        },
        Some(trace),
        bridge,
    )
    .unwrap();
    (session, rx)
}

fn production_bridge() -> LeasedPacketBridge {
    LeasedPacketBridge::new(PacketBridge::default(), CaptureLeaseDeadline::default())
}

/// Consecutive attempts begin at least REACK_SPACING apart. Each trace mark
/// precedes the bridge-clock read that spaces the next attempt; the 1 ms
/// slack covers the two clocks' rounding only.
fn assert_spaced(attempts: &[Instant]) {
    for pair in attempts.windows(2) {
        let gap = pair[1] - pair[0];
        assert!(
            gap + Duration::from_millis(1) >= REACK_SPACING,
            "attempts {gap:?} apart"
        );
    }
}

#[test]
fn reack_schedule_leads_the_deadline_and_never_hot_loops() {
    let lead = ns(REACK_LEAD);
    let spacing = ns(REACK_SPACING);
    // A fresh 2.75 s lease: first attempt 2 s before it ends.
    let lease = Lease {
        deadline_ns: 10_000 * MS + 2_750 * MS,
        last_attempt_ns: 10_000 * MS,
        lead: REACK_LEAD,
    };
    assert_eq!(next_reack_ns(lease), lease.deadline_ns - lead);
    // After a failure near the deadline: the spacing floor wins.
    for last in [
        lease.deadline_ns - lead,
        lease.deadline_ns - 1,
        lease.deadline_ns,
    ] {
        let lease = Lease {
            last_attempt_ns: last,
            ..lease
        };
        assert_eq!(next_reack_ns(lease), last + spacing);
    }
    // A lease shorter than the lead never schedules at or before `last`.
    let short = Lease {
        deadline_ns: 100 * MS,
        last_attempt_ns: 50 * MS,
        lead: REACK_LEAD,
    };
    assert_eq!(next_reack_ns(short), 50 * MS + spacing);
    for last in [0, 1, 7 * MS, u64::MAX - spacing, u64::MAX] {
        for deadline in [0, 1, 3_000 * MS, u64::MAX] {
            let next = next_reack_ns(Lease {
                deadline_ns: deadline,
                last_attempt_ns: last,
                lead: REACK_LEAD,
            });
            assert!(next >= last.saturating_add(spacing));
        }
    }
}

#[test]
fn reack_renewal_refuses_an_expired_lease_and_never_revives_it() {
    let now = Arc::new(AtomicU64::new(10));
    let clock = now.clone();
    let bridge = LeasedPacketBridge::with_clock(
        PacketBridge::default(),
        CaptureLeaseDeadline::default(),
        move || Ok(clock.load(Ordering::SeqCst)),
    );
    let shared = bridge.refreshable_deadline();
    bridge.grant_until(100).unwrap();
    // At and past the current deadline, a valid later lease is refused.
    for expired in [100, 101, 10_000] {
        now.store(expired, Ordering::SeqCst);
        assert_eq!(
            renew_lease(&bridge, 100, 5_000),
            Err("capture_lease_expired")
        );
        assert_eq!(shared.current(), Some(100));
    }
    // A failing clock is never treated as live.
    let broken = LeasedPacketBridge::with_clock(
        PacketBridge::default(),
        CaptureLeaseDeadline::default(),
        || Err(std::io::Error::other("clock unavailable")),
    );
    assert_eq!(
        renew_lease(&broken, u64::MAX, 5_000),
        Err("capture_lease_expired")
    );
    assert_eq!(broken.refreshable_deadline().current(), None);

    // Live lease: the renewal replaces it.
    let now = Arc::new(AtomicU64::new(10));
    let clock = now.clone();
    let bridge = LeasedPacketBridge::with_clock(
        PacketBridge::default(),
        CaptureLeaseDeadline::default(),
        move || Ok(clock.load(Ordering::SeqCst)),
    );
    bridge.grant_until(100).unwrap();
    now.store(99, Ordering::SeqCst);
    assert_eq!(renew_lease(&bridge, 100, 5_000), Ok(()));
    assert_eq!(bridge.refreshable_deadline().current(), Some(5_000));
    now.store(4_000, Ordering::SeqCst);
    bridge.from_os(&frame()).unwrap();
    // A sealed bridge is never reopened by a renewal.
    bridge.stop();
    assert_eq!(
        renew_lease(&bridge, 5_000, 9_000),
        Err("session_lease_refused")
    );
    assert_eq!(bridge.refreshable_deadline().current(), None);
    assert!(bridge.from_os(&frame()).is_err());
}

/// S16n: continuous packets for 6 s, more than two of the first ACK's
/// 2.75 s leases, renew without refusal;
/// `reack_continuous_packets_for_12s_renew_without_refusal` is the 12 s
/// soak it was before.
#[test]
fn reack_continuous_packets_for_6s_renew_without_refusal() {
    continuous_packets_renew_without_refusal(Duration::from_secs(6));
}

#[test]
fn reack_continuous_packets_for_12s_renew_without_refusal() {
    continuous_packets_renew_without_refusal(Duration::from_secs(12));
}

/// Packets every 20 ms for `span` renew the lease without refusal, each
/// renewal on a connection of its own: at least a renewal every 2 s and 25
/// packets a second (6 and 300 in 12 s, S16n).
fn continuous_packets_renew_without_refusal(span: Duration) {
    let (relay, tree) = relay_each(|tree, _| Some(server_ack(tree)));
    let (trace, steps) = recorder();
    let (mut session, phases) = start(&tree, production_bridge(), trace);
    expect_phase(&phases, &session, SessionPhase::Ready);
    let probe = session.probe();
    let lease = probe.bridge().refreshable_deadline();
    let first = lease.current().unwrap();
    let started = Instant::now();
    let mut sent = 0usize;
    while started.elapsed() < span {
        assert_eq!(
            session.phase(),
            SessionPhase::Ready,
            "{:?}",
            session.refusal()
        );
        assert!(probe.ready(), "sealed at {:?}", session.refusal());
        probe.bridge().from_os(&frame()).unwrap();
        sent += 1;
        thread::sleep(Duration::from_millis(20));
    }
    let secs = usize::try_from(span.as_secs()).unwrap();
    assert!(sent >= 25 * secs, "only {sent} packets");
    assert_eq!(session.refusal(), None);
    let renewed = count(&steps, "reack_renewed");
    assert!(renewed >= secs / 2, "only {renewed} re-ACKs in {span:?}");
    assert_eq!(count(&steps, "reack_failed"), 0);
    assert_spaced(&times(&steps, "reack_attempt"));
    // Every renewal is its own connection after the first ACK's.
    assert!(relay.accepts() > renewed);
    // The lease moved forward with the renewals, far past the first ACK's.
    assert!(lease.current().unwrap() >= first + ns(span - Duration::from_secs(3)));
    assert!(session.try_join(Duration::from_secs(2)));
    assert_eq!(session.refusal(), Some("provider_stop"));
    assert_prewarms_joined(&steps);
    assert!(lease.current().is_none());
    assert!(!store_locked(&tree.identity_dir()));
    assert!(phases.try_recv().is_err());
}

/// Every re-ACK is refused: the session serves until the current lease ends,
/// is sealed by the monitor alone (nothing here probes the lease) within
/// 300 ms of it, and the lease never moves. Returns the attempt times.
fn refused_reack_seals_at_deadline(refusal: fn(&ReadyTree) -> Option<Behavior>) -> Vec<Instant> {
    let (_relay, tree) = relay_each(move |tree, index| {
        if index == 0 {
            Some(server_ack(tree))
        } else {
            refusal(tree)
        }
    });
    let (trace, steps) = recorder();
    let bridge = production_bridge();
    let clock = bridge.clone();
    let (mut session, phases) = start(&tree, bridge, trace);
    expect_phase(&phases, &session, SessionPhase::Ready);
    let lease = clock.refreshable_deadline();
    let deadline = lease.current().unwrap();
    let mut last_ready = clock.clock_ns().unwrap();
    let sealed_at = loop {
        let before = clock.clock_ns().unwrap();
        if session.phase() != SessionPhase::Ready {
            // Read after the seal was seen, so never before the seal itself.
            break clock.clock_ns().unwrap();
        }
        last_ready = before;
        let now = before;
        // Revoked (None) once the seal lands between the two reads.
        let current = lease.current();
        assert!(
            current.is_none_or(|current| current == deadline),
            "lease moved to {current:?} after a refused re-ACK"
        );
        assert!(now < deadline + ns(Duration::from_secs(3)), "never sealed");
        thread::sleep(Duration::from_millis(1));
    };
    assert_eq!(session.refusal(), Some("capture_lease_expired"));
    // Served up to the deadline, sealed no later than 300 ms past it.
    assert!(
        last_ready + 100 * MS >= deadline,
        "last Ready {} ms before the deadline",
        deadline.saturating_sub(last_ready) / MS
    );
    assert!(
        sealed_at >= deadline,
        "sealed {} ms early",
        (deadline - sealed_at) / MS
    );
    assert!(
        sealed_at <= deadline + 300 * MS,
        "sealed {} ms after the deadline",
        (sealed_at - deadline) / MS
    );
    assert_eq!(count(&steps, "reack_renewed"), 0);
    assert!(count(&steps, "reack_failed") >= 1);
    assert!(session.try_join(Duration::from_secs(2)));
    assert!(!store_locked(&tree.identity_dir()));
    assert!(phases.try_recv().is_err());
    times(&steps, "reack_attempt")
}

#[test]
fn reack_wrong_nonce_is_refused_and_seals_by_deadline_plus_300ms() {
    let attempts = refused_reack_seals_at_deadline(|tree| {
        Some(Behavior::WrongNonceThenClose(AckReply::for_tree(tree)))
    });
    assert!(!attempts.is_empty());
    assert_spaced(&attempts);
}

#[test]
fn reack_dropped_or_truncated_ack_is_refused_and_seals_by_deadline_plus_300ms() {
    assert_spaced(&refused_reack_seals_at_deadline(|_| {
        Some(Behavior::DropAfterRequest)
    }));
    assert_spaced(&refused_reack_seals_at_deadline(|tree| {
        Some(Behavior::TruncatedAck {
            reply: AckReply::for_tree(tree),
            keep: 4,
        })
    }));
}

#[test]
fn reack_attempts_never_closer_than_500ms_even_when_refused_at_once() {
    // Each re-ACK connection is dropped unread, so it fails within a few
    // milliseconds: only the schedule's spacing floor stops a hot loop.
    let attempts = refused_reack_seals_at_deadline(|_| None);
    assert!(attempts.len() >= 2, "{} attempts", attempts.len());
    assert_spaced(&attempts);
    // A 2.75 s lease, first attempt 2 s before its end: at most one attempt
    // per 500 ms over the remaining 2 s.
    assert!(attempts.len() <= 5, "{} attempts", attempts.len());
}

#[test]
fn reack_stop_during_a_pending_reack_joins_within_2s() {
    let (relay, tree) = relay_each(|tree, index| match index {
        0 => Some(server_ack(tree)),
        _ => Some(Behavior::HoldRequest),
    });
    let (trace, steps) = recorder();
    let (mut session, phases) = start(&tree, production_bridge(), trace);
    expect_phase(&phases, &session, SessionPhase::Ready);
    for _ in 0..2 {
        relay
            .wait_for(RelayStep::AckRequested, Duration::from_secs(3))
            .expect("re-ACK request never reached the relay");
    }
    assert_eq!(session.phase(), SessionPhase::Ready);
    assert_eq!(count(&steps, "reack_attempt"), 1);
    let stopping = Instant::now();
    assert!(session.try_join(Duration::from_secs(2)));
    assert!(
        stopping.elapsed() <= Duration::from_secs(2),
        "stop took {:?}",
        stopping.elapsed()
    );
    assert_eq!(session.phase(), SessionPhase::Joined);
    assert_eq!(session.refusal(), Some("provider_stop"));
    assert_eq!(count(&steps, "reack_renewed"), 0);
    assert!(!store_locked(&tree.identity_dir()));
    assert!(phases.try_recv().is_err());
}

#[test]
fn reack_clock_jump_past_the_deadline_seals_at_once_and_drops_the_pending_reack() {
    let (release, released) = oneshot::channel();
    let released = Mutex::new(Some(released));
    let (relay, tree) = relay_each(move |tree, index| match index {
        0 => Some(server_ack(tree)),
        1 => Some(Behavior::AckWhenReleased(
            AckReply::for_tree(tree),
            released.lock().unwrap().take().unwrap(),
        )),
        // The other first pre-warm never answers, so no re-ACK renews
        // whichever channel carries it first.
        2 => Some(Behavior::HoldRequest),
        _ => Some(server_ack(tree)),
    });
    let (trace, steps) = recorder();
    let (bridge, jump) = jumping_bridge();
    let (mut session, phases) = start(&tree, bridge, trace);
    expect_phase(&phases, &session, SessionPhase::Ready);
    for _ in 0..2 {
        relay
            .wait_for(RelayStep::AckRequested, Duration::from_secs(3))
            .expect("re-ACK request never reached the relay");
    }
    let probe = session.probe();
    assert!(probe.ready());
    // The bridge clock leaps 10 s, far past the lease; the runtime clock
    // that times the pending re-ACK does not move.
    jump.store(ns(Duration::from_secs(10)), Ordering::SeqCst);
    assert!(probe.bridge().from_os(&frame()).is_err());
    assert!(!probe.ready());
    assert_eq!(session.phase(), SessionPhase::Sealed);
    assert_eq!(session.refusal(), Some("capture_lease_expired"));
    // The ACK now arriving cannot renew the sealed lease.
    let _ = release.send(());
    relay.wait_for(RelayStep::AckWritten, Duration::from_secs(2));
    assert!(session.try_join(Duration::from_secs(2)));
    assert_eq!(count(&steps, "reack_renewed"), 0);
    assert!(probe.bridge().refreshable_deadline().current().is_none());
    assert!(!store_locked(&tree.identity_dir()));
}

#[test]
fn reack_clock_jump_seals_without_any_packet_or_probe() {
    let (_relay, tree) = relay_each(|tree, _| Some(server_ack(tree)));
    let (trace, _steps) = recorder();
    let (bridge, jump) = jumping_bridge();
    let (mut session, phases) = start(&tree, bridge, trace);
    expect_phase(&phases, &session, SessionPhase::Ready);
    jump.store(ns(Duration::from_secs(10)), Ordering::SeqCst);
    let jumped = Instant::now();
    let sealed = wait_until(Duration::from_secs(2), || {
        session.phase() != SessionPhase::Ready
    })
    .expect("clock jump never sealed the session");
    // One 250 ms monitor tick, with 2x headroom on a loaded machine.
    assert!(
        sealed - jumped <= Duration::from_millis(600),
        "sealed after {:?}",
        sealed - jumped
    );
    assert_eq!(session.refusal(), Some("capture_lease_expired"));
    assert!(session.try_join(Duration::from_secs(2)));
    assert!(!store_locked(&tree.identity_dir()));
}

#[test]
fn reack_issuance_change_during_a_reack_never_renews_the_lease() {
    let (release, released) = oneshot::channel();
    let released = Mutex::new(Some(released));
    let (relay, tree) = relay_each(move |tree, index| match index {
        0 => Some(server_ack(tree)),
        1 => Some(Behavior::AckWhenReleased(
            AckReply::for_tree(tree),
            released.lock().unwrap().take().unwrap(),
        )),
        // The other first pre-warm never answers: only the released ACK,
        // after the issuance change, can complete a re-ACK.
        2 => Some(Behavior::HoldRequest),
        _ => Some(server_ack(tree)),
    });
    let (trace, steps) = recorder();
    let (mut session, phases) = start(&tree, production_bridge(), trace);
    expect_phase(&phases, &session, SessionPhase::Ready);
    let lease = session.probe().bridge().refreshable_deadline();
    let first = lease.current().unwrap();
    for _ in 0..2 {
        relay
            .wait_for(RelayStep::AckRequested, Duration::from_secs(3))
            .expect("re-ACK request never reached the relay");
    }
    // A renewal on disk while the re-ACK is in flight, then its valid ACK.
    tree.rewrite_issued_generation(8);
    let _ = release.send(());
    wait_until(Duration::from_secs(2), || {
        session.phase() != SessionPhase::Ready
    })
    .expect("issuance change never sealed the session");
    assert_eq!(session.refusal(), Some("store_revalidation_failed"));
    assert_eq!(count(&steps, "reack_renewed"), 0);
    assert!(lease.current().is_none_or(|deadline| deadline == first));
    assert!(session.try_join(Duration::from_secs(2)));
    assert!(!store_locked(&tree.identity_dir()));
}

/// The packet side seals the bridge 2.7 s before its lease ends, through
/// `stop` (the engine worker's exit path) or an invalid outbound packet. Either
/// revokes the lease view, yet the session reports an engine terminal, not a
/// lease expiry, and the lease end itself never moves.
fn packet_side_seal_mid_lease(seal: fn(&LeasedPacketBridge)) {
    let (_relay, tree) = relay_each(|tree, _| Some(server_ack(tree)));
    let (trace, _steps) = recorder();
    let (mut session, phases) = start(&tree, production_bridge(), trace);
    expect_phase(&phases, &session, SessionPhase::Ready);
    let probe = session.probe();
    let lease = probe.bridge().refreshable_deadline();
    let deadline = lease.current().unwrap();
    // Past the monitor's immediate first tick, so the session body, not the
    // tick's lease probe, normally classifies the seal.
    thread::sleep(Duration::from_millis(100));
    seal(probe.bridge());
    let sealed_at = probe.bridge().clock_ns().unwrap();
    assert!(lease.is_revoked());
    // At least 1 s of lease left, so this cannot be an expiry race.
    assert!(
        sealed_at + ns(Duration::from_secs(1)) <= deadline,
        "sealed only {} ms before the lease end",
        deadline.saturating_sub(sealed_at) / MS
    );
    wait_until(Duration::from_secs(1), || {
        session.phase() != SessionPhase::Ready
    })
    .expect("a packet-side seal never sealed the session");
    assert_eq!(session.refusal(), Some("session_packet_terminal"));
    assert!(probe.bridge().clock_ns().unwrap() < deadline);
    assert!(!probe.ready());
    assert!(probe.bridge().from_os(&frame()).is_err());
    assert_eq!(lease.current(), None);
    assert!(session.try_join(Duration::from_secs(2)));
    assert_eq!(session.refusal(), Some("session_packet_terminal"));
    assert!(!store_locked(&tree.identity_dir()));
    assert!(phases.try_recv().is_err());
}

#[test]
fn reack_engine_stop_mid_lease_reports_packet_terminal_not_expiry() {
    packet_side_seal_mid_lease(|bridge| bridge.stop());
}

#[test]
fn reack_invalid_outbound_packet_mid_lease_reports_packet_terminal_not_expiry() {
    packet_side_seal_mid_lease(|bridge| {
        let _ = bridge.engine_send(&[0x45]);
    });
}

/// Audit regression: a burst that overflows the packet queues in both
/// directions drops (and counts) the excess, and the session stays Ready
/// with its lease and bridge intact. Only a seal ends it.
#[test]
fn reack_queue_overflow_burst_drops_packets_and_stays_ready() {
    let (_relay, tree) = relay_each(|tree, _| Some(server_ack(tree)));
    let (trace, _steps) = recorder();
    let (mut session, phases) = start(&tree, production_bridge(), trace);
    expect_phase(&phases, &session, SessionPhase::Ready);
    let probe = session.probe();
    let bridge = probe.bridge();
    let lease = bridge.refreshable_deadline();
    // Several packetFlow batches back to back, faster than any drain.
    let mut admitted = 0usize;
    for _ in 0..8 * 128 {
        if bridge
            .from_native(&frame())
            .expect("inbound overflow is not fatal")
        {
            admitted += 1;
        }
    }
    // A burst of engine output with no packetFlow writer draining it.
    let mut blocked = 0usize;
    for _ in 0..8 * 128 {
        match bridge.engine_send(&frame()) {
            Ok(()) => {}
            Err(error) => {
                assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
                blocked += 1;
            }
        }
    }
    assert!(admitted < 8 * 128, "the inbound burst never overflowed");
    assert!(bridge.dropped_inbound() > 0);
    assert_eq!(bridge.dropped_outbound(), blocked as u64);
    assert!(blocked > 0, "the outbound burst never overflowed");
    // Ready throughout, past the session body's packet and lease checks.
    let watched = Instant::now();
    while watched.elapsed() < Duration::from_millis(400) {
        assert_eq!(
            session.phase(),
            SessionPhase::Ready,
            "{:?}",
            session.refusal()
        );
        assert!(probe.ready());
        thread::sleep(Duration::from_millis(20));
    }
    assert!(!bridge.is_sealed());
    assert!(!lease.is_revoked());
    assert_eq!(session.refusal(), None);
    // The queued output still drains to packetFlow and new input flows.
    assert!(bridge.deliver_to_os(|_| Ok(())).unwrap());
    assert!(bridge.from_native(&frame()).is_ok());
    assert!(phases.try_recv().is_err());
    // A genuine stop still seals.
    bridge.stop();
    wait_until(Duration::from_secs(1), || {
        session.phase() != SessionPhase::Ready
    })
    .expect("a stop never sealed the session");
    assert!(session.try_join(Duration::from_secs(2)));
    assert!(!store_locked(&tree.identity_dir()));
}

// --- S16e: re-ACK on pre-warmed channels ---------------------------------

/// The installed v13/v14 relay as its first ACK logged it: `ack_valid_ms`
/// about 3881 (validity runs from the request, so it includes the setup
/// after TCP) about 2.4 s after the dial. Reproduced as 1.45 s of setup per
/// connection and 0.85 s per PolicyAck request under a 2.4 s grant (the 3 s
/// registry cap less 0.6 s of registry age): `ack_valid_ms` about 3.9 s,
/// 2.3 s from dial, and about 1.3 s of the first lease left at Ready, less
/// than one fresh setup and exchange.
const REMOTE_SETUP: Duration = Duration::from_millis(1_450);
const REMOTE_REPLY: Duration = Duration::from_millis(850);
const REMOTE_GRANT_MS: u64 = 2_400;

fn remote_ack(tree: &ReadyTree) -> Behavior {
    let mut reply = AckReply::for_tree(tree);
    reply.effective_valid_for_ms = REMOTE_GRANT_MS;
    Behavior::AckAfter {
        reply,
        delay: REMOTE_REPLY,
    }
}

/// `relay_each`, every fresh connection paying `setup` before outer TLS.
fn slow_relay_each(
    setup: Duration,
    behavior: impl Fn(&ReadyTree, usize) -> Option<Behavior> + Send + 'static,
) -> (TestRelay, Arc<ReadyTree>) {
    let listener = TestRelay::bind();
    let tree = Arc::new(ReadyTree::with_online_completed(
        listener.local_addr().unwrap(),
    ));
    let served = tree.clone();
    let relay = TestRelay::spawn_each_with_setup(
        listener,
        RelayIdentity::for_tree(&tree),
        setup,
        move |index| behavior(&served, index),
    );
    assert_eq!(relay.address(), tree.relay());
    (relay, tree)
}

/// Serve packets every 20 ms for `span`, asserting Ready throughout.
fn serve_ready_for(session: &SessionHandle, span: Duration) -> usize {
    let probe = session.probe();
    let started = Instant::now();
    let mut sent = 0usize;
    while started.elapsed() < span {
        assert_eq!(
            session.phase(),
            SessionPhase::Ready,
            "{:?} after {:?}",
            session.refusal(),
            started.elapsed()
        );
        assert!(probe.ready(), "sealed at {:?}", session.refusal());
        probe.bridge().from_os(&frame()).unwrap();
        sent += 1;
        thread::sleep(Duration::from_millis(20));
    }
    sent
}

/// S16n: served for 6 s after Ready; the 10 s it was before is the soak
/// `prewarm_keeps_an_installed_like_relay_ready_on_overlapped_channels_for_10s`.
#[test]
fn prewarm_keeps_an_installed_like_relay_ready_on_overlapped_channels() {
    installed_like_relay_ready_on_overlapped_channels(Duration::from_secs(6));
}

#[test]
fn prewarm_keeps_an_installed_like_relay_ready_on_overlapped_channels_for_10s() {
    installed_like_relay_ready_on_overlapped_channels(Duration::from_secs(10));
}

/// An installed-like relay keeps the session Ready for `span` after Ready
/// on pre-warmed channels whose setup overlapped the first ACK's: 20
/// packets and 0.6 renewals a second at least (200 and 6 in 10 s, S16n).
fn installed_like_relay_ready_on_overlapped_channels(span: Duration) {
    let (relay, tree) = slow_relay_each(REMOTE_SETUP, |tree, _| Some(remote_ack(tree)));
    let (trace, steps) = recorder();
    let bridge = production_bridge();
    let clock = bridge.clone();
    let dialed = clock.clock_ns().unwrap();
    let (mut session, phases) = start(&tree, bridge, trace);
    let phase = phases.recv_timeout(REMOTE_SETUP + REMOTE_REPLY + Duration::from_secs(3));
    assert_eq!(
        phase.ok(),
        Some(SessionPhase::Ready),
        "{:?}",
        session.refusal()
    );
    let ready = Instant::now();
    let ready_ns = clock.clock_ns().unwrap();
    let lease = clock.refreshable_deadline();
    let first = lease.current().unwrap();
    // The installed geometry: Ready one setup and one exchange after the
    // dial, with less of the first lease left than either a fresh
    // connection or a pre-warm dialed only now would need.
    assert!(ready_ns - dialed >= ns(REMOTE_SETUP + REMOTE_REPLY));
    let left = Duration::from_nanos(first - ready_ns);
    assert!(
        left < REMOTE_SETUP + REMOTE_REPLY,
        "{left:?} of the first lease left at Ready"
    );
    assert!(left >= Duration::from_millis(900), "{left:?} left at Ready");
    let sent = serve_ready_for(&session, span);
    let secs = usize::try_from(span.as_secs()).unwrap();
    assert!(sent >= 20 * secs, "only {sent} packets");
    assert_eq!(session.refusal(), None);
    // The first renewal landed inside the first lease, on a channel whose
    // setup overlapped the first ACK's own.
    let renewals = times(&steps, "reack_renewed");
    let renewed_at = *renewals.first().expect("never renewed");
    assert!(renewed_at <= ready + left, "first renewal after its lease");
    let renewed = renewals.len();
    assert!(
        renewed >= secs * 6 / 10,
        "only {renewed} re-ACKs in {span:?}"
    );
    assert_eq!(count(&steps, "reack_failed"), 0);
    assert!(count(&steps, "reack_prewarm_used") >= renewed);
    assert_eq!(count(&steps, "reack_fresh"), 0);
    assert_spaced(&times(&steps, "reack_attempt"));
    assert!(lease.current().unwrap() >= first + ns(span - Duration::from_secs(3)));
    assert!(relay.accepts() > renewed);
    assert!(session.try_join(Duration::from_secs(2)));
    assert_eq!(session.refusal(), Some("provider_stop"));
    assert_prewarms_joined(&steps);
    assert!(!store_locked(&tree.identity_dir()));
    assert!(phases.try_recv().is_err());
}

/// Every pre-warm task started was joined, each before the monitor (or, for
/// one the monitor never took, the transport) was let go.
fn assert_prewarms_joined(steps: &Steps) {
    let started = count(steps, "reack_prewarm_start");
    assert!(started >= 1, "no pre-warm ever started");
    assert_eq!(count(steps, "reack_prewarm_joined"), started);
    let released = times(steps, "transport_close");
    let released = released.first().expect("transport never closed");
    for joined in times(steps, "reack_prewarm_joined") {
        assert!(joined <= *released, "a pre-warm outlived its session");
    }
    if let Some(monitor) = times(steps, "monitor_stop").first() {
        for joined in times(steps, "reack_prewarm_joined") {
            assert!(joined <= *monitor, "a pre-warm outlived its monitor");
        }
    }
}

/// The first step named `wanted` after the first one named `after`.
fn first_after(steps: &Steps, after: &str, wanted: &str) -> Option<usize> {
    let steps = steps.lock().unwrap();
    let from = steps.iter().position(|(step, _)| *step == after)?;
    steps[from..]
        .iter()
        .position(|(step, _)| *step == wanted)
        .map(|at| at + from)
}

fn steps_before(steps: &Steps, index: usize, wanted: &str) -> usize {
    steps.lock().unwrap()[..index]
        .iter()
        .filter(|(step, _)| *step == wanted)
        .count()
}

#[test]
fn prewarm_lead_covers_two_exchange_round_trips_and_keeps_the_spacing_floor() {
    // Fast exchanges keep the 2 s floor.
    for exchange in [0, 1, 100, 875] {
        assert_eq!(reack_lead(Duration::from_millis(exchange)), REACK_LEAD);
    }
    // Slow ones lead by two round trips plus the margin.
    assert_eq!(
        reack_lead(Duration::from_millis(1_350)),
        Duration::from_millis(2_700) + REACK_LEAD_MARGIN
    );
    assert_eq!(reack_lead(Duration::MAX), Duration::MAX);
    // A 2.95 s lead before a 2.75 s lease: due at once, but never within the
    // spacing floor of the previous attempt, and never a hot loop.
    let lease = Lease {
        deadline_ns: 10_000 * MS + 2_750 * MS,
        last_attempt_ns: 10_000 * MS,
        lead: reack_lead(Duration::from_millis(1_350)),
    };
    assert_eq!(next_reack_ns(lease), 10_000 * MS + ns(REACK_SPACING));
    let lease = Lease {
        lead: reack_lead(Duration::from_millis(400)),
        ..lease
    };
    assert_eq!(next_reack_ns(lease), lease.deadline_ns - ns(REACK_LEAD));
    let lease = Lease {
        deadline_ns: 20_000 * MS,
        last_attempt_ns: 10_000 * MS,
        lead: reack_lead(Duration::from_millis(1_500)),
    };
    assert_eq!(next_reack_ns(lease), 20_000 * MS - 3_250 * MS);
    for lead in [
        Duration::ZERO,
        REACK_LEAD,
        Duration::from_secs(9),
        Duration::MAX,
    ] {
        for last in [0, 7 * MS, u64::MAX] {
            let next = next_reack_ns(Lease {
                deadline_ns: 3_000 * MS,
                last_attempt_ns: last,
                lead,
            });
            assert!(next >= last.saturating_add(ns(REACK_SPACING)));
        }
    }
}

#[test]
fn prewarm_age_bound_and_reack_ok_rate_limit() {
    assert!(prewarm_usable(Duration::ZERO, PREWARM_MAX_AGE));
    assert!(prewarm_usable(PREWARM_MAX_AGE, PREWARM_MAX_AGE));
    assert!(!prewarm_usable(
        PREWARM_MAX_AGE + Duration::from_nanos(1),
        PREWARM_MAX_AGE
    ));
    // Inside the server's admission timeout, with room for one request.
    assert!(PREWARM_MAX_AGE + Duration::from_millis(500) < ADMISSION_TIMEOUT);
    let logged: Vec<u64> = (1..=100).filter(|n| reack_ok_logged(*n)).collect();
    assert_eq!(logged, [1, 2, 3, 4, 5, 20, 40, 60, 80, 100]);
}

#[test]
fn prewarm_schedule_overlaps_setup_with_short_acks_and_never_idles_on_long_ones() {
    let lead = ns(PREWARM_LEAD);
    // A 2.75 s lease from its request, due 2 s before its end.
    let lease = Lease {
        deadline_ns: 10_000 * MS + 2_750 * MS,
        last_attempt_ns: 10_000 * MS,
        lead: REACK_LEAD,
    };
    let span = 2_750 * MS;
    let due = next_reack_ns(lease);
    // Both slots are due well before the request each serves...
    assert_eq!(prewarm_due_ns(lease, span, false, 0), due - lead);
    assert_eq!(prewarm_due_ns(lease, span, false, 1), due + 750 * MS - lead);
    // ...and, with a request out, the next one follows it by one interval.
    assert_eq!(
        prewarm_due_ns(lease, span, true, 0),
        10_000 * MS + 750 * MS - lead
    );
    // Both are already past here, so every free slot is dialed at once.
    for queued in 0..PREWARM_SLOTS {
        assert!(prewarm_due_ns(lease, span, true, queued) <= lease.last_attempt_ns);
    }
    // A 30 s grant: no channel is dialed earlier than PREWARM_LEAD before
    // its use, so none idles past its age bound.
    let long = Lease {
        deadline_ns: 100_000 * MS + 29_750 * MS,
        last_attempt_ns: 100_000 * MS,
        lead: REACK_LEAD,
    };
    let span = 29_750 * MS;
    assert_eq!(
        prewarm_due_ns(long, span, false, 0),
        next_reack_ns(long) - lead
    );
    // The request out now went at the old lease's due time: the next one,
    // and so its channel, follows a whole interval later, not at the old
    // lease's next slot.
    let asked = Lease {
        last_attempt_ns: next_reack_ns(long),
        ..long
    };
    assert_eq!(
        prewarm_due_ns(asked, span, true, 0),
        next_reack_ns(long) + 27_750 * MS - lead
    );
    assert!(prewarm_due_ns(asked, span, true, 0) > prewarm_due_ns(asked, span, false, 0));
    assert_eq!(
        prewarm_due_ns(long, span, false, 1),
        next_reack_ns(long) + 27_750 * MS - lead
    );
    assert!(PREWARM_LEAD < PREWARM_MAX_AGE);
    // A span under the lead still spaces predicted uses by the floor.
    let tight = Lease {
        lead: reack_lead(Duration::from_millis(1_500)),
        ..lease
    };
    assert_eq!(
        prewarm_due_ns(tight, 2_000 * MS, true, 1),
        (10_000 * MS + 2 * ns(REACK_SPACING)).saturating_sub(lead)
    );
    for queued in [0, 1, usize::MAX] {
        for outstanding in [false, true] {
            let _ = prewarm_due_ns(
                Lease {
                    deadline_ns: u64::MAX,
                    last_attempt_ns: u64::MAX,
                    lead: Duration::ZERO,
                },
                u64::MAX,
                outstanding,
                queued,
            );
        }
    }
    // One retry beyond the slots per bound request, never an unbounded loop.
    assert_eq!(PREWARM_DIALS_PER_REACK, PREWARM_SLOTS + 1);
    // The bound on a pre-warmed request: two round trips plus the margin,
    // at least the floor, never past the attempt's budget.
    let budget = Duration::from_secs(2);
    assert_eq!(
        prewarm_exchange_limit(Duration::from_millis(5), budget),
        PREWARM_EXCHANGE_FLOOR
    );
    assert_eq!(
        prewarm_exchange_limit(Duration::from_millis(800), Duration::from_secs(3)),
        Duration::from_millis(1_600) + REACK_LEAD_MARGIN
    );
    assert_eq!(
        prewarm_exchange_limit(Duration::from_millis(900), budget),
        budget
    );
    assert_eq!(
        prewarm_exchange_limit(Duration::MAX, Duration::from_millis(300)),
        Duration::from_millis(300)
    );
    assert!(PREWARM_EXCHANGE_FLOOR < REACK_LEAD);
}

fn start_with_prewarm_age(
    tree: &ReadyTree,
    trace: Trace,
    age: Duration,
) -> (SessionHandle, mpsc::Receiver<SessionPhase>) {
    let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
    let (tx, rx) = mpsc::channel();
    let session = spawn_with_prewarm_age(
        saved(tree),
        claim,
        move |phase| {
            let _ = tx.send(phase);
        },
        Some(trace),
        production_bridge(),
        age,
    )
    .unwrap();
    (session, rx)
}

#[test]
fn prewarm_older_than_the_bound_is_discarded_and_the_reack_reestablished() {
    // Each pre-warmed channel opens in milliseconds and the re-ACK comes due
    // about 750 ms later: with a 100 ms bound every one of them is stale.
    let (relay, tree) = relay_each(|tree, _| Some(server_ack(tree)));
    let (trace, steps) = recorder();
    let (mut session, phases) = start_with_prewarm_age(&tree, trace, Duration::from_millis(100));
    expect_phase(&phases, &session, SessionPhase::Ready);
    serve_ready_for(&session, Duration::from_secs(4));
    let renewed = count(&steps, "reack_renewed");
    assert!(renewed >= 3, "only {renewed} re-ACKs in 4 s");
    assert_eq!(count(&steps, "reack_failed"), 0);
    // No request ever went out on a stale channel; each renewal dialed anew.
    assert_eq!(count(&steps, "reack_prewarm_used"), 0);
    assert!(count(&steps, "reack_prewarm_stale") >= renewed);
    assert!(count(&steps, "reack_fresh") >= renewed);
    // The client ended each discarded channel before any request on it.
    relay
        .wait_for(RelayStep::Abandoned, Duration::from_secs(1))
        .expect("a discarded pre-warmed channel was never closed");
    assert!(session.try_join(Duration::from_secs(2)));
    assert_eq!(session.refusal(), Some("provider_stop"));
    assert_prewarms_joined(&steps);
    assert!(!store_locked(&tree.identity_dir()));
}

#[test]
fn prewarm_within_the_bound_carries_the_reack_without_a_fresh_dial() {
    // Control for the test above: the production bound keeps the same
    // channels, and every renewal is one request on one of them.
    let (_relay, tree) = relay_each(|tree, _| Some(server_ack(tree)));
    let (trace, steps) = recorder();
    let (mut session, phases) = start_with_prewarm_age(&tree, trace, PREWARM_MAX_AGE);
    expect_phase(&phases, &session, SessionPhase::Ready);
    serve_ready_for(&session, Duration::from_secs(3));
    let renewed = count(&steps, "reack_renewed");
    assert!(renewed >= 2, "only {renewed} re-ACKs in 3 s");
    assert_eq!(count(&steps, "reack_prewarm_stale"), 0);
    assert_eq!(count(&steps, "reack_fresh"), 0);
    assert!(count(&steps, "reack_prewarm_used") >= renewed);
    assert!(session.try_join(Duration::from_secs(2)));
    assert_prewarms_joined(&steps);
}

#[test]
fn prewarm_that_cannot_open_is_dialed_once_more_then_falls_back_to_a_fresh_dial() {
    // Both first pre-warms and the one dial again are dropped at accept;
    // every later connection, the fallback's first, is served.
    let (relay, tree) = relay_each(|tree, index| match index {
        1..=PREWARM_DIALS_PER_REACK => None,
        _ => Some(server_ack(tree)),
    });
    let (trace, steps) = recorder();
    let (mut session, phases) = start(&tree, production_bridge(), trace);
    expect_phase(&phases, &session, SessionPhase::Ready);
    serve_ready_for(&session, Duration::from_secs(3));
    assert_eq!(count(&steps, "reack_failed"), 0);
    assert!(count(&steps, "reack_renewed") >= 2);
    // Before the first request: the slots and one dial more, never a loop.
    let attempt = first_after(&steps, "dial", "reack_attempt").unwrap();
    assert_eq!(
        steps_before(&steps, attempt, "reack_prewarm_start"),
        PREWARM_DIALS_PER_REACK
    );
    assert_eq!(
        steps_before(&steps, attempt, "reack_prewarm_failed"),
        PREWARM_DIALS_PER_REACK
    );
    // The first renewal went over a fresh dial, inside the first attempt.
    let first = first_after(&steps, "dial", "reack_renewed").unwrap();
    assert_eq!(steps_before(&steps, first, "reack_attempt"), 1);
    assert_eq!(steps_before(&steps, first, "reack_fresh"), 1);
    assert_eq!(steps_before(&steps, first, "reack_prewarm_used"), 0);
    // Later renewals are back on pre-warmed channels.
    assert!(count(&steps, "reack_prewarm_used") >= 1);
    assert!(relay.accepts() >= 2 + PREWARM_DIALS_PER_REACK);
    assert!(session.try_join(Duration::from_secs(2)));
    assert_prewarms_joined(&steps);
    assert!(!store_locked(&tree.identity_dir()));
}

/// The name of the first of `wanted` after step `index`.
fn next_of(steps: &Steps, index: usize, wanted: &[&str]) -> Option<&'static str> {
    steps.lock().unwrap()[index + 1..]
        .iter()
        .map(|(step, _)| *step)
        .find(|step| wanted.contains(step))
}

#[test]
fn prewarmed_channel_whose_request_fails_is_carried_on_another_channel_at_once() {
    // The first pre-warmed channel opens, but its request is dropped
    // unanswered; the other slot's channel is served.
    let (_relay, tree) = relay_each(|tree, index| match index {
        1 => Some(Behavior::DropAfterRequest),
        _ => Some(server_ack(tree)),
    });
    let (trace, steps) = recorder();
    let (mut session, phases) = start(&tree, production_bridge(), trace);
    expect_phase(&phases, &session, SessionPhase::Ready);
    serve_ready_for(&session, Duration::from_secs(3));
    assert_eq!(count(&steps, "reack_failed"), 0);
    assert!(count(&steps, "reack_renewed") >= 2);
    assert_eq!(count(&steps, "reack_fresh"), 0);
    // The failed request went out again at once on another pre-warmed
    // channel, inside the same attempt.
    let failed = first_after(&steps, "dial", "reack_prewarm_failed").unwrap();
    assert_eq!(
        next_of(&steps, failed, &["reack_prewarm_used", "reack_attempt"]),
        Some("reack_prewarm_used")
    );
    assert!(session.try_join(Duration::from_secs(2)));
    assert_prewarms_joined(&steps);
    assert!(!store_locked(&tree.identity_dir()));
}

#[test]
fn prewarmed_channel_whose_request_goes_unanswered_yields_to_another_within_the_lease() {
    // The first pre-warmed channel reads its request and never answers, as
    // a connection gone silent while idle would.
    let (_relay, tree) = relay_each(|tree, index| match index {
        1 => Some(Behavior::HoldRequest),
        _ => Some(server_ack(tree)),
    });
    let (trace, steps) = recorder();
    let (mut session, phases) = start(&tree, production_bridge(), trace);
    expect_phase(&phases, &session, SessionPhase::Ready);
    serve_ready_for(&session, Duration::from_secs(4));
    // Bounded by the exchange limit, not the 5 s connect timeout: the
    // request moved on with the lease still live.
    assert_eq!(count(&steps, "reack_failed"), 0);
    assert!(count(&steps, "reack_renewed") >= 3);
    assert_eq!(count(&steps, "reack_prewarm_failed"), 1);
    assert_eq!(count(&steps, "reack_fresh"), 0);
    let failed = first_after(&steps, "dial", "reack_prewarm_failed").unwrap();
    assert_eq!(
        next_of(&steps, failed, &["reack_prewarm_used", "reack_attempt"]),
        Some("reack_prewarm_used")
    );
    assert!(session.try_join(Duration::from_secs(2)));
    assert_prewarms_joined(&steps);
    assert!(!store_locked(&tree.identity_dir()));
}

#[test]
fn prewarm_stop_while_the_next_channels_are_still_opening_joins_them_within_2s() {
    // Every pre-warmed connection stalls before outer TLS.
    let (relay, tree) = relay_each(|tree, index| match index {
        0 => Some(server_ack(tree)),
        _ => Some(Behavior::Silent),
    });
    let (trace, steps) = recorder();
    let (mut session, phases) = start(&tree, production_bridge(), trace);
    expect_phase(&phases, &session, SessionPhase::Ready);
    // Both slots dialed beside the first ACK and are still opening.
    wait_until(Duration::from_secs(1), || {
        relay.accepts() == 1 + PREWARM_SLOTS
    })
    .expect("the first pre-warms never dialed");
    assert_eq!(count(&steps, "reack_prewarm_start"), PREWARM_SLOTS);
    assert_eq!(count(&steps, "reack_prewarm_joined"), 0);
    let stopping = Instant::now();
    assert!(session.try_join(Duration::from_secs(2)));
    assert!(
        stopping.elapsed() <= Duration::from_secs(2),
        "stop took {:?}",
        stopping.elapsed()
    );
    assert_eq!(session.phase(), SessionPhase::Joined);
    assert_eq!(session.refusal(), Some("provider_stop"));
    assert_prewarms_joined(&steps);
    assert_eq!(count(&steps, "reack_renewed"), 0);
    assert!(!store_locked(&tree.identity_dir()));
    assert!(phases.try_recv().is_err());
}

#[test]
fn prewarm_channel_opened_by_another_session_is_refused_before_any_request() {
    use crate::local_identity::{ObservedLocalSession, PreparedLocalSession};
    use aegis_client::protected_online_expectation::ProtectedOnlineExpectation;
    type Opened = (
        ObservedLocalSession,
        Arc<ProtectedOnlineExpectation<'static>>,
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let open = |tree: &ReadyTree| -> Opened {
        let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
        let (prepared, store) = PreparedLocalSession::from_claim_with_store_guard(claim).unwrap();
        let observed = runtime
            .block_on(async {
                let tcp = tokio::net::TcpStream::connect(tree.relay()).await.unwrap();
                prepared
                    .observe_ack(saved(tree), tcp, RelayInterface::loopback_for_test())
                    .await
            })
            .unwrap();
        (observed, store)
    };
    let (relay_a, tree_a) = relay_each(|tree, _| Some(server_ack(tree)));
    let (relay_b, tree_b) = relay_each(|tree, _| Some(server_ack(tree)));
    let (mut a, _store_a) = open(&tree_a);
    let (mut b, _store_b) = open(&tree_b);
    for relay in [&relay_a, &relay_b] {
        relay
            .wait_for(RelayStep::AckRequested, Duration::from_secs(2))
            .expect("first ACK never requested");
    }
    runtime.block_on(async {
        let opener = b.begin_prewarm().unwrap();
        let tcp = tokio::net::TcpStream::connect(opener.peer()).await.unwrap();
        let foreign = opener.establish(tcp, "reack_prewarm").await.unwrap();
        let request = a.begin_reack().unwrap();
        let request = request
            .observe_on(foreign, LIMIT, "reack_prewarm")
            .await
            .err()
            .expect("another session's channel carried this session's request");
        // Control: the same request on this session's own channel renews.
        let opener = a.begin_prewarm().unwrap();
        let tcp = tokio::net::TcpStream::connect(opener.peer()).await.unwrap();
        let own = opener.establish(tcp, "reack_prewarm").await.unwrap();
        let observation = request
            .observe_on(own, LIMIT, "reack_prewarm")
            .await
            .ok()
            .expect("own pre-warmed channel refused");
        a.install_reack(observation).unwrap();
    });
    // The foreign channel was dropped without a request ever written on it.
    assert!(relay_b
        .wait_for(RelayStep::AckRequested, Duration::from_millis(500))
        .is_none());
    assert!(relay_a
        .wait_for(RelayStep::AckRequested, Duration::from_secs(1))
        .is_some());
    drop((a, b));
    drop(runtime);
}

#[test]
fn prewarmed_channels_the_relay_ends_while_idle_are_dialed_once_more_before_the_reack() {
    // Both first pre-warmed channels are ended by the relay while idle.
    let (relay, tree) = relay_each(|tree, index| match index {
        1 | 2 => Some(Behavior::DropBeforeRequest),
        _ => Some(server_ack(tree)),
    });
    let (trace, steps) = recorder();
    let (mut session, phases) = start(&tree, production_bridge(), trace);
    expect_phase(&phases, &session, SessionPhase::Ready);
    for _ in 0..PREWARM_SLOTS {
        relay
            .wait_for(RelayStep::IdleDropped, Duration::from_secs(2))
            .expect("the relay never ended an idle channel");
    }
    serve_ready_for(&session, Duration::from_secs(3));
    assert_eq!(count(&steps, "reack_failed"), 0);
    assert!(count(&steps, "reack_renewed") >= 2);
    // The ended channels were noticed while idle and never carried a
    // request; one dial again, before the re-ACK came due, carried it.
    let attempt = first_after(&steps, "dial", "reack_attempt").unwrap();
    assert_eq!(steps_before(&steps, attempt, "reack_prewarm_failed"), 2);
    assert_eq!(
        steps_before(&steps, attempt, "reack_prewarm_start"),
        PREWARM_DIALS_PER_REACK
    );
    let first = first_after(&steps, "dial", "reack_renewed").unwrap();
    assert_eq!(steps_before(&steps, first, "reack_prewarm_used"), 1);
    assert_eq!(steps_before(&steps, first, "reack_fresh"), 0);
    assert!(session.try_join(Duration::from_secs(2)));
    assert_prewarms_joined(&steps);
    assert!(!store_locked(&tree.identity_dir()));
}

#[test]
fn prewarm_opener_refuses_other_peers_and_ended_channels_before_any_request() {
    use crate::local_identity::PreparedLocalSession;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (relay, tree) = relay_each(|tree, index| match index {
        1 => Some(Behavior::DropBeforeRequest),
        _ => Some(server_ack(tree)),
    });
    let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
    let (prepared, _store) = PreparedLocalSession::from_claim_with_store_guard(claim).unwrap();
    let mut observed = runtime
        .block_on(async {
            let tcp = tokio::net::TcpStream::connect(tree.relay()).await.unwrap();
            prepared
                .observe_ack(saved(&tree), tcp, RelayInterface::loopback_for_test())
                .await
        })
        .unwrap();
    relay
        .wait_for(RelayStep::AckRequested, Duration::from_secs(2))
        .unwrap();
    runtime.block_on(async {
        // A socket to any other endpoint is refused before a byte is sent;
        // without the peer check it would wait out the 5 s setup deadline.
        let other = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let opener = observed.begin_prewarm().unwrap();
        let tcp = tokio::net::TcpStream::connect(other.local_addr().unwrap())
            .await
            .unwrap();
        let (mut accepted, _) = other.accept().await.unwrap();
        let refused = tokio::time::timeout(
            Duration::from_millis(500),
            opener.establish(tcp, "reack_prewarm"),
        )
        .await
        .expect("a foreign peer was not refused at once");
        assert!(refused.is_err());
        let mut byte = [0u8; 1];
        let read = tokio::io::AsyncReadExt::read(&mut accepted, &mut byte).await;
        assert!(matches!(read, Ok(0)), "bytes reached a foreign peer");
        // A channel the relay ended while idle is refused before a request.
        let opener = observed.begin_prewarm().unwrap();
        let tcp = tokio::net::TcpStream::connect(opener.peer()).await.unwrap();
        let mut ended = opener.establish(tcp, "reack_prewarm").await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), ended.drive_idle())
            .await
            .expect("the relay's close never reached the idle channel");
        let request = observed.begin_reack().unwrap();
        let request = request
            .observe_on(ended, LIMIT, "reack_prewarm")
            .await
            .err()
            .expect("an ended channel carried a request");
        drop(request);
    });
    assert!(relay
        .wait_for(RelayStep::AckRequested, Duration::from_millis(300))
        .is_none());
    drop(observed);
    drop(runtime);
}

#[test]
fn prewarmed_channel_recorded_as_ended_never_writes_a_request() {
    use crate::local_identity::PreparedLocalSession;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    // The relay would report any request it reads on the second connection.
    let (relay, tree) = relay_each(|tree, index| match index {
        1 => Some(Behavior::HoldRequest),
        _ => Some(server_ack(tree)),
    });
    let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
    let (prepared, _store) = PreparedLocalSession::from_claim_with_store_guard(claim).unwrap();
    let mut observed = runtime
        .block_on(async {
            let tcp = tokio::net::TcpStream::connect(tree.relay()).await.unwrap();
            prepared
                .observe_ack(saved(&tree), tcp, RelayInterface::loopback_for_test())
                .await
        })
        .unwrap();
    relay
        .wait_for(RelayStep::AckRequested, Duration::from_secs(2))
        .unwrap();
    runtime.block_on(async {
        let opener = observed.begin_prewarm().unwrap();
        let tcp = tokio::net::TcpStream::connect(opener.peer()).await.unwrap();
        let mut channel = opener.establish(tcp, "reack_prewarm").await.unwrap();
        channel.mark_ended_for_test();
        let request = observed.begin_reack().unwrap();
        let refused = tokio::time::timeout(
            Duration::from_millis(500),
            request.observe_on(channel, LIMIT, "reack_prewarm"),
        )
        .await
        .expect("an ended channel was used for a request");
        drop(refused.err().expect("an ended channel carried a request"));
    });
    assert!(relay
        .wait_for(RelayStep::AckRequested, Duration::from_millis(300))
        .is_none());
    drop(observed);
    drop(runtime);
}

#[test]
fn prewarm_renewal_is_measured_from_the_request_on_the_prewarmed_channel() {
    // The relay answers the request on the first pre-warmed channel only
    // 300 ms after reading it, inside the exchange bound and (S16k) before
    // a second request may follow it (`REACK_SPACING`).
    let (release, released) = oneshot::channel();
    let released = Mutex::new(Some(released));
    let (relay, tree) = relay_each(move |tree, index| match index {
        1 => Some(Behavior::AckWhenReleased(
            AckReply::for_tree(tree),
            released.lock().unwrap().take().unwrap(),
        )),
        _ => Some(server_ack(tree)),
    });
    let (trace, steps) = recorder();
    let bridge = production_bridge();
    let clock = bridge.clone();
    let (mut session, phases) = start(&tree, bridge, trace);
    expect_phase(&phases, &session, SessionPhase::Ready);
    let lease = clock.refreshable_deadline();
    let first = lease.current().unwrap();
    for _ in 0..2 {
        relay
            .wait_for(RelayStep::AckRequested, Duration::from_secs(3))
            .expect("re-ACK request never reached the relay");
    }
    // No earlier than the request itself left.
    let asked_ns = clock.clock_ns().unwrap();
    assert_eq!(count(&steps, "reack_prewarm_used"), 1);
    thread::sleep(Duration::from_millis(300));
    let _ = release.send(());
    wait_until(Duration::from_secs(1), || {
        lease.current().is_some_and(|deadline| deadline != first)
    })
    .expect("the delayed ACK never renewed the lease");
    let renewed = lease.current().unwrap();
    // A 3 s grant less the 250 ms margin, from the request, never from the
    // ACK's arrival 300 ms later.
    let grant = ns(Duration::from_millis(2_750));
    assert!(
        renewed <= asked_ns + grant,
        "lease ends {} ms past request + grant",
        (renewed - asked_ns - grant) / MS
    );
    assert!(renewed + 300 * MS >= asked_ns + grant);
    // The renewal is that request's own: no other was in flight yet.
    assert_eq!(count(&steps, "reack_pipelined"), 0);
    assert_eq!(count(&steps, "reack_fresh"), 0);
    assert!(session.try_join(Duration::from_secs(2)));
    assert_prewarms_joined(&steps);
    assert!(!store_locked(&tree.identity_dir()));
}

#[test]
fn prewarm_started_before_a_construction_refusal_is_joined() {
    // A 200 ms grant is shorter than the lease margin: construction refuses
    // it after the first pre-warms have already been started.
    let (_relay, tree) = relay_each(|tree, _| {
        let mut reply = AckReply::for_tree(tree);
        reply.effective_valid_for_ms = 200;
        Some(Behavior::AckThenClose {
            reply,
            idle: ADMISSION_TIMEOUT,
        })
    });
    let (trace, steps) = recorder();
    let (mut session, phases) = start(&tree, production_bridge(), trace);
    expect_phase(&phases, &session, SessionPhase::Sealed);
    assert!(session.try_join(Duration::from_secs(2)));
    assert_eq!(session.refusal(), Some("session_ack_too_short"));
    assert_eq!(count(&steps, "reack_prewarm_start"), PREWARM_SLOTS);
    assert_prewarms_joined(&steps);
    assert!(!store_locked(&tree.identity_dir()));
}

#[test]
fn first_prewarm_opener_needs_the_saved_relay_and_a_current_binding() {
    use crate::local_identity::PreparedLocalSession;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (relay, tree) = relay_each(|tree, _| Some(server_ack(tree)));
    let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
    let (mut prepared, _store) = PreparedLocalSession::from_claim_with_store_guard(claim).unwrap();
    let intent = |policy| SavedProviderIntent {
        generation: tree.generation().into(),
        policy,
    };
    let dns = tree.policy().dns().to_vec();
    let mtu = tree.policy().mtu();
    // Another relay, or DNS or MTU the signed bundle does not name.
    let other = FullWide::new("192.0.2.5".parse().unwrap(), dns.clone(), mtu).unwrap();
    let mut fewer = dns.clone();
    fewer.truncate(1);
    let relay_ip = tree.relay().ip();
    for refused in [
        intent(other),
        intent(FullWide::for_test_loopback(relay_ip, fewer, mtu).unwrap()),
        intent(FullWide::for_test_loopback(relay_ip, dns.clone(), 1400).unwrap()),
    ] {
        assert!(prepared
            .begin_first_prewarm(&refused, &RelayInterface::loopback_for_test())
            .is_err());
    }
    let opener = prepared
        .begin_first_prewarm(&saved(&tree), &RelayInterface::loopback_for_test())
        .unwrap();
    assert_eq!(opener.peer(), tree.relay());
    assert_eq!(relay.accepts(), 0);
    runtime.block_on(async {
        // Opened beside the first ACK, the channel carries a re-ACK of the
        // session that ACK observed: the same held crypto.
        let tcp = tokio::net::TcpStream::connect(tree.relay()).await.unwrap();
        let first = prepared.observe_ack(saved(&tree), tcp, RelayInterface::loopback_for_test());
        // The opener's own dial: bound to the session's relay interface.
        let tcp = opener.connect().await.unwrap();
        assert_eq!(tcp.peer_addr().unwrap(), tree.relay());
        assert_eq!(
            crate::relay_socket::bound_index(tcp.as_raw_fd(), false).unwrap(),
            RelayInterface::loopback_for_test().index()
        );
        let channel = opener.establish(tcp, "reack_prewarm");
        let (observed, channel) = tokio::join!(first, channel);
        let mut observed = observed.unwrap();
        let request = observed.begin_reack().unwrap();
        let observation = request
            .observe_on(channel.unwrap(), LIMIT, "reack_prewarm")
            .await
            .ok()
            .expect("the first pre-warmed channel was refused");
        observed.install_reack(observation).unwrap();
        drop(observed);
    });
    drop(runtime);
}

#[test]
fn prewarm_dials_stay_bounded_per_reack_when_the_relay_drops_every_channel() {
    // Only the first ACK is served; every later connection is dropped at
    // accept, so each pre-warm fails within milliseconds.
    let (relay, tree) = relay_each(|tree, index| match index {
        0 => Some(server_ack(tree)),
        _ => None,
    });
    let (trace, steps) = recorder();
    let (mut session, phases) = start(&tree, production_bridge(), trace);
    expect_phase(&phases, &session, SessionPhase::Ready);
    wait_until(Duration::from_secs(4), || {
        session.phase() != SessionPhase::Ready
    })
    .expect("the lease never ended");
    assert_eq!(session.refusal(), Some("capture_lease_expired"));
    assert!(session.try_join(Duration::from_secs(2)));
    // Between two bound requests, never more than the slots plus one dial.
    let log = steps.lock().unwrap().clone();
    let mut dials = 0usize;
    let mut rounds = 1usize;
    for (step, _) in &log {
        match *step {
            "reack_attempt" => {
                dials = 0;
                rounds += 1;
            }
            "reack_prewarm_start" => {
                dials += 1;
                assert!(dials <= PREWARM_DIALS_PER_REACK, "{dials} dials in a round");
            }
            _ => {}
        }
    }
    // A 2.75 s lease with attempts at least 500 ms apart: a few rounds, each
    // with at most its dials and one fresh connection.
    assert!(rounds <= 6, "{rounds} rounds");
    assert!(relay.accepts() <= 1 + rounds * (PREWARM_DIALS_PER_REACK + 1));
    assert_prewarms_joined(&steps);
    assert!(!store_locked(&tree.identity_dir()));
}

/// Observe the first ACK over a test dial; later relay dials of the session
/// are bound to `interface`.
fn observed_on(
    runtime: &tokio::runtime::Runtime,
    tree: &ReadyTree,
    interface: RelayInterface,
) -> (
    crate::local_identity::ObservedLocalSession,
    Arc<aegis_client::protected_online_expectation::ProtectedOnlineExpectation<'static>>,
) {
    use crate::local_identity::PreparedLocalSession;
    let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
    let (prepared, store) = PreparedLocalSession::from_claim_with_store_guard(claim).unwrap();
    let observed = runtime
        .block_on(async {
            let tcp = tokio::net::TcpStream::connect(tree.relay()).await.unwrap();
            prepared.observe_ack(saved(tree), tcp, interface).await
        })
        .unwrap();
    (observed, store)
}

#[test]
fn prewarm_and_fresh_reack_dials_are_bound_to_the_session_relay_interface() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (relay, tree) = relay_each(|tree, _| Some(server_ack(tree)));
    let lo = RelayInterface::loopback_for_test();
    let (mut observed, _store) = observed_on(&runtime, &tree, lo.clone());
    assert_eq!(relay.accepts(), 1);
    runtime.block_on(async {
        let opener = observed.begin_prewarm().unwrap();
        let prewarm = opener.connect().await.unwrap();
        let request = observed.begin_reack().unwrap();
        let fresh = request.connect().await.unwrap();
        for tcp in [&prewarm, &fresh] {
            assert_eq!(tcp.peer_addr().unwrap(), tree.relay());
            assert_eq!(
                crate::relay_socket::bound_index(tcp.as_raw_fd(), false).unwrap(),
                lo.index()
            );
        }
        // The bound fresh dial still carries a full re-ACK.
        let observation = request.observe(fresh).await.unwrap();
        observed.install_reack(observation).unwrap();
    });
    assert!(wait_until(Duration::from_secs(2), || relay.accepts() == 3).is_some());
    drop(observed);
    drop(runtime);
}

#[test]
fn reack_dials_on_a_vanished_relay_interface_never_reach_the_relay() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (relay, tree) = relay_each(|tree, _| Some(server_ack(tree)));
    // No interface has this index: every later dial of the session fails.
    let gone = RelayInterface::for_test("en99", 0x7fff_0000);
    let (mut observed, _store) = observed_on(&runtime, &tree, gone);
    assert_eq!(relay.accepts(), 1);
    runtime.block_on(async {
        let opener = observed.begin_prewarm().unwrap();
        let request = observed.begin_reack().unwrap();
        let budget = Duration::from_secs(1);
        let prewarm = tokio::time::timeout(budget, opener.connect()).await;
        assert!(!matches!(prewarm, Ok(Ok(_))));
        let fresh = tokio::time::timeout(budget, request.connect()).await;
        assert!(!matches!(fresh, Ok(Ok(_))));
    });
    // Any dial that reached the relay would have been accepted by now.
    thread::sleep(Duration::from_millis(200));
    assert_eq!(relay.accepts(), 1);
    drop(observed);
    drop(runtime);
}

// ---- S16k: pipelined re-ACKs keep a short lease under a loaded uplink ----

use crate::{
    establish_limit::ACK_RESERVE,
    provider_session::relay::start_armed,
    provider_session_body::{
        exchange_p90, reack_due_ns, reack_stagger, record_exchange, request_limit, ACK_IN_FLIGHT,
        EXCHANGE_WINDOW, REACK_STAGGER_MAX,
    },
};
use std::{collections::VecDeque, sync::atomic::AtomicBool};

/// The first ACK's round trip in the S16k tests: an idle uplink's, as
/// installed (v21, about 0.45 s), before the post-connect flow burst.
const IDLE_REPLY: Duration = Duration::from_millis(450);

/// A PolicyAck answered `delay` after its request, granting `grant_ms`.
fn ack_after(tree: &ReadyTree, delay: Duration, grant_ms: u64) -> Behavior {
    let mut reply = AckReply::for_tree(tree);
    reply.effective_valid_for_ms = grant_ms;
    Behavior::AckAfter { reply, delay }
}

/// From the relay's events: the most PolicyAck requests read and not yet
/// answered at once, and the most connections at once between their accept
/// and their ACK (or their end before any): the ACK path's channels.
fn relay_concurrency(events: &[(RelayStep, Instant)]) -> (usize, usize) {
    let (mut requests, mut most_requests) = (0usize, 0usize);
    let (mut channels, mut most_channels) = (0usize, 0usize);
    for (step, _) in events {
        match step {
            RelayStep::Accepted => channels += 1,
            RelayStep::AckRequested => requests += 1,
            RelayStep::AckWritten => {
                requests = requests.saturating_sub(1);
                channels = channels.saturating_sub(1);
            }
            RelayStep::Abandoned | RelayStep::IdleDropped | RelayStep::CarrierDropped => {
                channels = channels.saturating_sub(1);
            }
            _ => {}
        }
        most_requests = most_requests.max(requests);
        most_channels = most_channels.max(channels);
    }
    (most_requests, most_channels)
}

/// The longest gap between two consecutive renewals.
fn longest_gap(at: &[Instant]) -> Duration {
    at.windows(2)
        .map(|pair| pair[1] - pair[0])
        .max()
        .unwrap_or_default()
}

/// A session whose first ACK is idle-fast and whose every re-ACK (on
/// connection `index`) takes `reply(index, elapsed since the relay
/// started)` and grants `grant_ms` stays Ready for `span` with no lease
/// lapse, no failed re-ACK and a lease that never moves back, on at most
/// `ACK_IN_FLIGHT` requests and `ACK_RESERVE` ACK channels at once, a grant
/// landing at least every `max_gap`. Its counts are those S16k asserted
/// over 30 s, in proportion to `span` (S16n).
fn pipelined_session_stays_ready(
    span: Duration,
    grant_ms: u64,
    reply: fn(usize, Duration) -> Duration,
    max_gap: Duration,
) -> Steps {
    // Opt-in CI diagnosis only. Measure the host's native 20 ms sleep jitter
    // before creating the relay so this probe cannot consume a grant.
    let timing_trace = std::env::var_os("AEGIS_B06_TIMING_TRACE").is_some();
    if timing_trace {
        let mut sleeps = Vec::with_capacity(60);
        for _ in 0..60 {
            let began = Instant::now();
            thread::sleep(Duration::from_millis(20));
            sleeps.push(began.elapsed());
        }
        sleeps.sort();
        eprintln!(
            "B06_TIMING native_sleep20_ms samples=60 median={} p90={} max={}",
            sleeps[30].as_millis(),
            sleeps[54].as_millis(),
            sleeps[59].as_millis()
        );
    }
    let started = Instant::now();
    let (relay, tree) = relay_each(move |tree, index| {
        let delay = if index == 0 {
            IDLE_REPLY
        } else {
            reply(index, started.elapsed())
        };
        Some(ack_after(tree, delay, grant_ms))
    });
    let (trace, steps) = recorder();
    let (mut session, phases, (services, gate)) = start_armed(&tree, production_bridge(), trace);
    let limiter = services.limiter().clone();
    let lease = session.probe().bridge().refreshable_deadline();
    let first = lease.current().unwrap();
    let ready = Instant::now();
    // Ready throughout, the lease end never earlier than before.
    let probe = session.probe();
    let (mut sent, mut granted) = (0usize, first);
    let mut phase_time = [Duration::ZERO; 4];
    while ready.elapsed() < span {
        let began = timing_trace.then(Instant::now);
        assert!(probe.ready(), "sealed at {:?}", session.refusal());
        if let Some(began) = began {
            phase_time[0] += began.elapsed();
        }
        let began = timing_trace.then(Instant::now);
        let now = lease.current().expect("the lease lapsed");
        assert!(now >= granted, "the lease moved back");
        granted = now;
        if let Some(began) = began {
            phase_time[1] += began.elapsed();
        }
        let began = timing_trace.then(Instant::now);
        probe.bridge().from_os(&frame()).unwrap();
        if let Some(began) = began {
            phase_time[2] += began.elapsed();
        }
        sent += 1;
        let began = timing_trace.then(Instant::now);
        thread::sleep(Duration::from_millis(20));
        if let Some(began) = began {
            phase_time[3] += began.elapsed();
        }
    }
    if timing_trace {
        eprintln!(
            "B06_TIMING packet_loop sent={sent} span_ms={} wall_ms={} ready_ms={} lease_ms={} from_os_ms={} sleep_ms={}",
            span.as_millis(),
            ready.elapsed().as_millis(),
            phase_time[0].as_millis(),
            phase_time[1].as_millis(),
            phase_time[2].as_millis(),
            phase_time[3].as_millis()
        );
    }
    // At least 20 packets, 2/3 of a renewal and 1/3 of a pipelined request
    // a second: 600, 20 and 10 in 30 s.
    let secs = usize::try_from(span.as_secs()).unwrap();
    assert!(sent >= 20 * secs, "only {sent} packets");
    assert_eq!(session.refusal(), None);
    // No re-ACK failed or ran out of lease, and none went fresh: every
    // request rode a pre-warmed channel.
    assert_eq!(count(&steps, "reack_failed"), 0);
    assert_eq!(count(&steps, "reack_fresh"), 0);
    let renewals: Vec<Instant> = times(&steps, "reack_renewed")
        .into_iter()
        .filter(|at| *at > ready)
        .collect();
    assert!(
        renewals.len() >= secs * 2 / 3,
        "only {} renewals",
        renewals.len()
    );
    // A fresh grant landed at least every `max_gap`, well inside the lease.
    let gap = longest_gap(&renewals);
    assert!(gap <= max_gap, "{gap:?} without a grant");
    // The requests were pipelined, never more than two at once at the relay
    // and never more ACK channels than the reserve.
    assert!(count(&steps, "reack_pipelined") >= secs / 3);
    let (requests, channels) = relay_concurrency(&relay.drain_events());
    assert_eq!(requests, ACK_IN_FLIGHT, "requests at once");
    assert!(channels <= ACK_RESERVE, "{channels} ACK channels at once");
    assert!(limiter.high_water() <= ACK_RESERVE);
    assert!(lease.current().unwrap() >= first + ns(span - Duration::from_secs(2)));
    drop((services, gate));
    assert!(session.try_join(Duration::from_secs(2)));
    assert_eq!(session.refusal(), Some("provider_stop"));
    assert_prewarms_joined(&steps);
    assert!(!store_locked(&tree.identity_dir()));
    assert!(phases.try_recv().is_err());
    steps
}

/// The pipelined sessions' span in the suite (S16n): 8 s past the rise at
/// 8 s, about ten exchanges at 1.5 s, more than the eight
/// `EXCHANGE_WINDOW` holds; out of order, about twelve renewals. The
/// `_for_30s` soaks run S16k's 30 s.
const PIPELINED_SPAN: Duration = Duration::from_secs(16);
/// The steady 1 s session's span: about twenty renewals of a 1.85 s lease
/// that one request at a time would lapse within seconds.
const STEADY_SPAN: Duration = Duration::from_secs(12);
/// S16k's span, for the soaks.
const PIPELINED_SOAK: Duration = Duration::from_secs(30);

/// Installed v21: 2.1 s grants (a 1.85 s lease from each request) and
/// a re-ACK round trip of about 1 s under the flow burst. One request at
/// a time lands each grant a whole round trip after the last one and
/// lapses within seconds; two in flight land them half a round trip
/// apart.
fn one_second_round_trips(span: Duration) {
    pipelined_session_stays_ready(
        span,
        2_100,
        |_, _| Duration::from_secs(1),
        Duration::from_secs(1),
    );
}

/// 2.9 s grants (a 2.65 s lease), the round trip rising from 1 s to 1.5 s
/// under load at 8 s: one request at a time lapses past 1.325 s. Grants
/// land about 0.75 s apart, once (at the rise) about 1 s.
fn rising_round_trips(span: Duration) {
    pipelined_session_stays_ready(
        span,
        2_900,
        |_, elapsed| {
            if elapsed < Duration::from_secs(8) {
                Duration::from_secs(1)
            } else {
                Duration::from_millis(1_500)
            }
        },
        Duration::from_millis(1_150),
    );
}

/// Connections alternate between 1.3 s and 0.3 s round trips, so a later
/// request's grant often lands before an earlier one's: the earlier
/// grant, ending sooner, is dropped rather than installed.
fn out_of_order_grants(span: Duration) {
    let steps = pipelined_session_stays_ready(
        span,
        2_900,
        |index, _| {
            if index % 2 == 0 {
                Duration::from_millis(1_300)
            } else {
                Duration::from_millis(300)
            }
        },
        // Superseded grants renew nothing: renewals land less evenly, still
        // well inside the 2.65 s lease.
        Duration::from_millis(1_600),
    );
    assert!(count(&steps, "reack_superseded") >= 3);
}

#[test]
fn pipelined_reacks_keep_1s_round_trips_on_2_1s_grants_ready_for_12s() {
    one_second_round_trips(STEADY_SPAN);
}

#[test]
fn pipelined_reacks_keep_round_trips_rising_to_1_5s_on_2_9s_grants_ready_for_16s() {
    rising_round_trips(PIPELINED_SPAN);
}

#[test]
fn pipelined_grants_landing_out_of_order_never_move_the_lease_back() {
    out_of_order_grants(PIPELINED_SPAN);
}

#[test]
fn pipelined_reacks_keep_1s_round_trips_on_2_1s_grants_ready_for_30s() {
    one_second_round_trips(PIPELINED_SOAK);
}

#[test]
fn pipelined_reacks_keep_round_trips_rising_to_1_5s_on_2_9s_grants_ready_for_30s() {
    rising_round_trips(PIPELINED_SOAK);
}

#[test]
fn pipelined_grants_landing_out_of_order_never_move_the_lease_back_for_30s() {
    out_of_order_grants(PIPELINED_SOAK);
}

#[test]
fn pipelined_reacks_on_a_relay_gone_silent_still_lapse_and_seal_at_the_lease_end() {
    let alive = Arc::new(AtomicBool::new(true));
    let serving = alive.clone();
    let (relay, tree) = relay_each(move |tree, index| {
        if index == 0 {
            Some(ack_after(tree, IDLE_REPLY, 2_100))
        } else if serving.load(Ordering::SeqCst) {
            Some(ack_after(tree, Duration::from_secs(1), 2_100))
        } else {
            // Accepted, then never a byte: a black-holed path.
            Some(Behavior::Silent)
        }
    });
    let (trace, steps) = recorder();
    let bridge = production_bridge();
    let clock = bridge.clone();
    let (mut session, phases) = start(&tree, bridge, trace);
    expect_phase(&phases, &session, SessionPhase::Ready);
    serve_ready_for(&session, Duration::from_secs(5));
    assert!(count(&steps, "reack_pipelined") >= 1);
    alive.store(false, Ordering::SeqCst);
    let lease = clock.refreshable_deadline();
    // Requests already on their way may still renew; then nothing can.
    let sealed = wait_until(Duration::from_secs(8), || session.refusal().is_some());
    let sealed = sealed.expect("never sealed on a silent relay");
    assert_eq!(session.refusal(), Some("capture_lease_expired"));
    // Sealed by the lease end itself: no later than 300 ms after it.
    let end = times(&steps, "reack_renewed").last().copied().unwrap();
    assert!(sealed <= end + Duration::from_millis(2_100 + 300));
    assert!(lease.current().is_none());
    let (requests, _) = relay_concurrency(&relay.drain_events());
    assert!(requests <= ACK_IN_FLIGHT, "{requests} requests at once");
    assert!(session.try_join(Duration::from_secs(2)));
    assert_eq!(session.refusal(), Some("capture_lease_expired"));
    assert_prewarms_joined(&steps);
    assert!(!store_locked(&tree.identity_dir()));
}

#[test]
fn reack_pipeline_staggers_by_half_a_round_trip_over_the_last_eight() {
    // The p90 of the last eight round trips is their longest; older ones
    // leave the window.
    let mut window = VecDeque::new();
    assert_eq!(exchange_p90(&window), Duration::ZERO);
    record_exchange(&mut window, Duration::from_millis(3_000));
    for ms in [450, 500, 1_000, 900, 600, 700, 800, 650] {
        record_exchange(&mut window, Duration::from_millis(ms));
    }
    assert_eq!(window.len(), EXCHANGE_WINDOW);
    assert_eq!(exchange_p90(&window), Duration::from_millis(1_000));
    let mut ten: VecDeque<Duration> = (1..=10).map(Duration::from_millis).collect();
    assert_eq!(exchange_p90(&ten), Duration::from_millis(9));
    ten.truncate(1);
    assert_eq!(exchange_p90(&ten), Duration::from_millis(1));
    // Half a round trip between the two requests in flight, within the
    // spacing floor and the cap.
    assert_eq!(ACK_IN_FLIGHT, 2);
    assert_eq!(reack_stagger(Duration::from_millis(300)), REACK_SPACING);
    assert_eq!(
        reack_stagger(Duration::from_millis(1_200)),
        Duration::from_millis(600)
    );
    assert_eq!(reack_stagger(Duration::from_secs(9)), REACK_STAGGER_MAX);
    // A second request is due on the lease schedule, but never within the
    // stagger of the first; the lead from the window's p90.
    let lease = Lease {
        deadline_ns: 10_000 * MS + 1_850 * MS,
        last_attempt_ns: 10_000 * MS,
        lead: reack_lead(Duration::from_millis(1_200)),
    };
    assert_eq!(lease.lead, Duration::from_millis(2_650));
    let stagger = reack_stagger(Duration::from_millis(1_200));
    assert_eq!(reack_due_ns(lease, false, stagger), 10_000 * MS + 600 * MS);
    assert_eq!(
        reack_due_ns(lease, false, REACK_SPACING),
        next_reack_ns(lease)
    );
    // A spacing under the floor is the floor; a forced request keeps it.
    assert_eq!(
        reack_due_ns(lease, false, Duration::ZERO),
        10_000 * MS + ns(REACK_SPACING)
    );
    assert_eq!(
        reack_due_ns(lease, true, stagger),
        10_000 * MS + ns(REACK_SPACING)
    );
    // A pre-warmed request is answered up to its own grant's end however
    // fast the last round trips were, and up to the pre-warm limit beyond.
    assert_eq!(
        request_limit(Duration::from_millis(5), 2_750 * MS),
        Duration::from_millis(2_750)
    );
    assert_eq!(
        request_limit(Duration::from_millis(5), 0),
        PREWARM_EXCHANGE_FLOOR
    );
    assert_eq!(
        request_limit(Duration::from_millis(1_500), 1_850 * MS),
        Duration::from_millis(3_000) + REACK_LEAD_MARGIN
    );
    // A long lease keeps its lead before the end.
    let long = Lease {
        deadline_ns: 10_000 * MS + 29_750 * MS,
        ..lease
    };
    assert_eq!(
        reack_due_ns(long, false, stagger),
        long.deadline_ns - ns(lease.lead)
    );
}

/// S16o: every re-ACK after the first ACK is held unanswered, so the lease
/// runs out under requests in flight. Each is reported once with where it
/// was (`reack_stalled`): a request on a pre-warmed channel at least, as
/// the relay holds every request it reads.
#[test]
fn reack_stalled_requests_name_their_stage_when_the_lease_runs_out() {
    let (relay, tree) = relay_each(|tree, index| match index {
        0 => Some(server_ack(tree)),
        _ => Some(Behavior::HoldRequest),
    });
    let (trace, steps) = recorder();
    let (mut session, phases) = start(&tree, production_bridge(), trace);
    expect_phase(&phases, &session, SessionPhase::Ready);
    relay
        .wait_for(RelayStep::AckRequested, Duration::from_secs(3))
        .expect("re-ACK request never reached the relay");
    let sealed = wait_until(Duration::from_secs(5), || {
        session.phase() != SessionPhase::Ready
    });
    assert!(sealed.is_some(), "the held lease never ran out");
    assert_eq!(session.refusal(), Some("capture_lease_expired"));
    assert!(session.try_join(Duration::from_secs(2)));
    let stalled: Vec<&'static str> = steps
        .lock()
        .unwrap()
        .iter()
        .map(|(step, _)| *step)
        .filter(|step| step.starts_with("reack_stalled_"))
        .collect();
    assert!(
        stalled.contains(&"reack_stalled_prewarm_request"),
        "{stalled:?}"
    );
    // Once each: the attempts in flight and the requests waiting, at most.
    assert!(
        stalled.len() <= crate::provider_session_body::ACK_IN_FLIGHT,
        "{stalled:?}"
    );
    assert_eq!(count(&steps, "reack_renewed"), 0);
    assert!(!store_locked(&tree.identity_dir()));
}
