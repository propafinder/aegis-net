//! S17 rebuild lifecycle: refusal classification, bounded backoff, native
//! packet disposition and real rebuilt sessions against the test relay. The
//! `Host` below performs exactly the provider's main-runloop decisions
//! (`session_lost`, `rebuild_finished`, `native_packets`, `Lifecycle`) and
//! counts the native effects: settings applications and tunnel cancels.
use super::*;
use crate::{
    app_group::CapturedAppGroupInputs,
    provider_session::SessionProbe,
    provider_session_body::{
        spawn_pinned,
        tests::{frame, saved, store_locked, wait_until},
        EpochPins,
    },
    relay_socket::{self, RelayInterface},
    test_fixture::ReadyTree,
    test_relay::{AckReply, Behavior, RelayIdentity, TestRelay, ADMISSION_TIMEOUT},
};
use std::{
    collections::HashSet,
    sync::{atomic::AtomicBool, mpsc},
};

const FAST: Schedule = Schedule {
    first: Duration::from_millis(40),
    cap: Duration::from_millis(160),
    construct: Duration::from_secs(5),
    stable: Duration::from_secs(30),
};
const STOP_BUDGET: Duration = Duration::from_secs(2);

type Events = Arc<Mutex<Vec<(RebuildEvent, Instant)>>>;

fn recorder() -> (RebuildTrace, Events) {
    let events: Events = Arc::default();
    let held = events.clone();
    let trace: RebuildTrace = Arc::new(move |event| {
        held.lock().unwrap().push((event, Instant::now()));
    });
    (trace, events)
}

fn ended(events: &Events) -> Vec<&'static str> {
    events
        .lock()
        .unwrap()
        .iter()
        .filter_map(|(event, _)| match event {
            RebuildEvent::Ended { code, .. } => Some(*code),
            _ => None,
        })
        .collect()
}

fn spawned_at(events: &Events) -> Vec<Instant> {
    events
        .lock()
        .unwrap()
        .iter()
        .filter(|(event, _)| matches!(event, RebuildEvent::Spawned { .. }))
        .map(|(_, at)| *at)
        .collect()
}

fn server_ack(tree: &ReadyTree) -> Behavior {
    Behavior::AckThenClose {
        reply: AckReply::for_tree(tree),
        idle: ADMISSION_TIMEOUT,
    }
}

/// Connection 0 (the first session's ACK) is always served; every later
/// connection gets `later(tree)` (None: dropped at once).
fn relay(
    later: impl Fn(&ReadyTree) -> Option<Behavior> + Send + 'static,
) -> (TestRelay, Arc<ReadyTree>) {
    let listener = TestRelay::bind();
    let tree = Arc::new(ReadyTree::with_online_completed(
        listener.local_addr().unwrap(),
    ));
    let served = tree.clone();
    let relay = TestRelay::spawn_each(listener, RelayIdentity::for_tree(&tree), move |index| {
        if index == 0 {
            Some(server_ack(&served))
        } else {
            later(&served)
        }
    });
    assert_eq!(relay.address(), tree.relay());
    (relay, tree)
}

/// A relay that serves later connections only while `accepting` is set.
fn gated_relay(accepting: Arc<AtomicBool>) -> (TestRelay, Arc<ReadyTree>) {
    relay(move |tree| accepting.load(Ordering::SeqCst).then(|| server_ack(tree)))
}

/// The production rebuild factory over the unsigned test claim. Rebuilt
/// sessions get no loopback override: they reach the loopback relay only
/// through the interface the first session pinned.
fn factory(tree: Arc<ReadyTree>, pinned: EpochPins) -> RebuildFactory {
    Box::new(move |notifier, _stop| {
        let claim = CapturedAppGroupInputs::capture_test_root(tree.root())
            .map_err(|error| Refusal::custody(&error))?;
        spawn_pinned(saved(&tree), claim, notifier, None, pinned.clone(), None)
            .map_err(|_| Refusal::transient("session_spawn_failed"))
    })
}

/// The provider's main-runloop decisions over real sessions.
struct Host {
    tree: Arc<ReadyTree>,
    pinned: EpochPins,
    lifecycle: Lifecycle,
    g: u64,
    session: Arc<Mutex<SessionHandle>>,
    probe: SessionProbe,
    rebuilds: Rebuilds,
    trace: Option<RebuildTrace>,
    schedule: Schedule,
    applied: usize,
    cancels: usize,
    reasserting: bool,
    reassertions: usize,
    swaps: usize,
    dropped: usize,
    failed: Option<&'static str>,
}

impl Host {
    fn start(tree: Arc<ReadyTree>, trace: Option<RebuildTrace>, schedule: Schedule) -> Self {
        let mut lifecycle = Lifecycle::default();
        let g = lifecycle.admit().unwrap();
        let pinned = EpochPins::default();
        let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
        let (tx, rx) = mpsc::channel();
        // The first session resolves (here: the lo0 override) and pins.
        let session = spawn_pinned(
            saved(&tree),
            claim,
            move |phase| {
                let _ = tx.send(phase);
            },
            None,
            pinned.clone(),
            Some(RelayInterface::loopback_for_test()),
        )
        .unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(3)).ok(),
            Some(SessionPhase::Ready),
            "{:?}",
            session.refusal()
        );
        assert_eq!(pinned.get(), Some(RelayInterface::loopback_for_test()));
        let probe = session.probe();
        let mut applied = 0;
        if lifecycle.session_ready(g) == Effect::ApplySettings {
            applied += 1;
        }
        assert_eq!(lifecycle.ready(g), Ok(Effect::CompleteStart));
        Self {
            tree,
            pinned,
            lifecycle,
            g,
            session: Arc::new(Mutex::new(session)),
            probe,
            rebuilds: Rebuilds::default(),
            trace,
            schedule,
            applied,
            cancels: 0,
            reasserting: false,
            reassertions: 0,
            swaps: 0,
            dropped: 0,
            failed: None,
        }
    }

    // fail_epoch_on_main: only the first failure of a live generation
    // acts, and that one cancels the tunnel.
    fn fail(&mut self, code: &'static str) {
        if self.lifecycle.fail(self.g).is_ok() {
            self.cancels += 1;
            self.failed = Some(code);
        }
    }

    /// One drain-timer / rebuildChanged observation.
    fn tick(&mut self) {
        if self.lifecycle.phase == Phase::Running && !self.probe.ready() {
            let (_, refusal) = self.probe.phase_reader().snapshot();
            let code = refusal.unwrap_or("packet_path_not_ready");
            match session_lost(&mut self.lifecycle, self.g, code) {
                Lost::Reassert => {
                    let (lost, schedule) = (self.session.clone(), self.schedule);
                    let factory = factory(self.tree.clone(), self.pinned.clone());
                    let trace = self.trace.clone();
                    self.rebuilds
                        .start_with(schedule, Instant::now(), move |spent| {
                            Rebuild::spawn(lost, factory, schedule, trace, Box::new(|| {}), spent)
                        })
                        .unwrap();
                    self.reasserting = true;
                    self.reassertions += 1;
                }
                Lost::Fail(code) => self.fail(code),
                Lost::Ignore => {}
            }
        }
        let Some(rebuild) = self.rebuilds.current.clone() else {
            return;
        };
        let finished = rebuild_finished(&mut self.lifecycle, self.g, &mut rebuild.lock().unwrap());
        match finished {
            Finished::Swap(session, attempts) => {
                self.rebuilds.swapped(attempts, Instant::now());
                self.probe = session.probe();
                self.session = Arc::new(Mutex::new(session));
                self.reasserting = false;
                self.swaps += 1;
            }
            Finished::Fail(code) => self.fail(code),
            Finished::Ignore => {}
        }
    }

    fn tick_until(&mut self, budget: Duration, mut done: impl FnMut(&Self) -> bool) -> bool {
        let deadline = Instant::now() + budget;
        loop {
            self.tick();
            if done(self) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(2));
        }
    }

    /// One native read batch of `count` IPv4 packets: forwarded or dropped.
    fn packets(&mut self, count: usize) -> usize {
        let mut forwarded = 0;
        for _ in 0..count {
            match native_packets(self.lifecycle.phase, self.probe.ready()) {
                Disposition::Forward => {
                    self.probe.bridge().from_os(&frame()).unwrap();
                    forwarded += 1;
                }
                Disposition::Drop => self.dropped += 1,
                Disposition::Stale => {}
            }
        }
        forwarded
    }

    /// Apple's stop, then the provider's stop poll within its budget: true
    /// once the current session and any rebuild have joined.
    fn stop(&mut self) -> Option<Duration> {
        let started = Instant::now();
        let (g, _) = self.lifecycle.stop().unwrap();
        loop {
            let rebuilt =
                self.rebuilds.current.as_ref().is_none_or(|rebuild| {
                    rebuild.lock().unwrap().seal_and_try_join(Duration::ZERO)
                });
            let joined = self.session.lock().unwrap().try_join(Duration::ZERO);
            if rebuilt && joined {
                // Joined means the rebuild thread has returned, having
                // joined every session it built.
                assert!(self
                    .rebuilds
                    .current
                    .as_ref()
                    .is_none_or(|rebuild| rebuild.lock().unwrap().finished()));
                assert_eq!(self.lifecycle.joined(g), Effect::CompleteStop);
                return Some(started.elapsed());
            }
            if started.elapsed() > STOP_BUDGET {
                return None;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

#[test]
fn rebuild_refused_reack_reasserts_drops_packets_and_rebuilds_without_reapplying_settings() {
    let accepting = Arc::new(AtomicBool::new(false));
    let (relay, tree) = gated_relay(accepting.clone());
    let (trace, events) = recorder();
    let mut host = Host::start(tree.clone(), Some(trace), FAST);
    assert_eq!(host.packets(3), 3);
    let first = host.probe.clone();
    // Every re-ACK is refused: the lease ends and the session seals.
    assert!(host.tick_until(Duration::from_secs(8), |h| h.reasserting));
    assert_eq!(host.lifecycle.phase, Phase::Reasserting);
    assert_eq!(
        first.phase_reader().snapshot().1,
        Some("capture_lease_expired")
    );
    assert_eq!((host.applied, host.cancels), (1, 0));
    // Packets are dropped: the provider never hands them to the sealed bridge,
    // which itself passes nothing in either direction.
    assert_eq!(host.packets(5), 0);
    assert_eq!(host.dropped, 5);
    assert!(first.bridge().from_os(&frame()).is_err());
    assert!(first
        .bridge()
        .deliver_to_os(|_| panic!("a sealed bridge delivered a packet"))
        .is_err());
    // Rebuild attempts are refused by the relay and retried with backoff.
    assert!(host.tick_until(Duration::from_secs(5), |_| ended(&events).len() >= 2));
    assert!(ended(&events)
        .iter()
        .all(|code| classify(code) == Recoverable));
    assert_eq!(host.lifecycle.phase, Phase::Reasserting);
    assert!(host.reasserting);
    assert_eq!(host.packets(2), 0);
    // The lost session joined (releasing the Store) before any rebuild.
    assert_eq!(
        events.lock().unwrap().first().map(|(event, _)| *event),
        Some(RebuildEvent::OldJoined)
    );
    assert_eq!(first.phase(), SessionPhase::Joined);
    // The relay accepts again: the rebuild reaches Ready and takes over the
    // packet path without a second settings application or any cancel.
    accepting.store(true, Ordering::SeqCst);
    assert!(host.tick_until(Duration::from_secs(5), |h| h.swaps == 1));
    assert_eq!(host.lifecycle.phase, Phase::Running);
    assert!(!host.reasserting);
    assert_eq!((host.applied, host.reassertions, host.cancels), (1, 1, 0));
    assert!(host.probe.ready());
    assert_eq!(host.packets(3), 3);
    assert!(relay.accepts() >= 2);
    let stopped = host.stop().expect("stop never joined");
    assert!(stopped <= STOP_BUDGET);
    assert!(!store_locked(&tree.identity_dir()));
}

/// S16k: a session renewing on pipelined re-ACKs (1 s round trips, 2.1 s
/// grants) whose relay then refuses every connection still lapses, seals
/// `capture_lease_expired` and is rebuilt once the relay serves again.
#[test]
fn rebuild_pipelined_lease_lapse_on_a_dead_relay_reasserts_and_rebuilds() {
    use std::sync::atomic::AtomicU8;
    const SLOW: u8 = 0;
    const DEAD: u8 = 1;
    const SERVING: u8 = 2;
    let mode = Arc::new(AtomicU8::new(SLOW));
    let serving = mode.clone();
    let (relay, tree) = relay(move |tree| match serving.load(Ordering::SeqCst) {
        SLOW => {
            let mut reply = AckReply::for_tree(tree);
            reply.effective_valid_for_ms = 2_100;
            Some(Behavior::AckAfter {
                reply,
                delay: Duration::from_secs(1),
            })
        }
        DEAD => None,
        _ => Some(server_ack(tree)),
    });
    let (trace, events) = recorder();
    let mut host = Host::start(tree.clone(), Some(trace), FAST);
    let first = host.probe.clone();
    // Pipelined renewals keep the first session Ready across many leases.
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(6) {
        host.tick();
        assert!(first.ready(), "{:?}", first.phase_reader().snapshot());
        assert_eq!(host.packets(1), 1);
        thread::sleep(Duration::from_millis(20));
    }
    assert!(!host.reasserting);
    mode.store(DEAD, Ordering::SeqCst);
    assert!(host.tick_until(Duration::from_secs(5), |h| h.reasserting));
    assert_eq!(
        first.phase_reader().snapshot().1,
        Some("capture_lease_expired")
    );
    assert_eq!((host.applied, host.cancels), (1, 0));
    assert_eq!(host.packets(2), 0);
    mode.store(SERVING, Ordering::SeqCst);
    assert!(host.tick_until(Duration::from_secs(8), |h| h.swaps == 1));
    assert_eq!(host.lifecycle.phase, Phase::Running);
    assert!(ended(&events)
        .iter()
        .all(|code| classify(code) == Recoverable));
    assert_eq!((host.applied, host.reassertions, host.cancels), (1, 1, 0));
    assert!(host.probe.ready());
    assert_eq!(host.packets(3), 3);
    assert!(relay.accepts() >= 2);
    let stopped = host.stop().expect("stop never joined");
    assert!(stopped <= STOP_BUDGET);
    assert!(!store_locked(&tree.identity_dir()));
}

#[test]
fn rebuild_tampered_identity_during_rebuild_cancels_exactly_once() {
    let accepting = Arc::new(AtomicBool::new(true));
    let (_relay, tree) = gated_relay(accepting);
    let (trace, events) = recorder();
    let mut host = Host::start(tree.clone(), Some(trace), FAST);
    // The held completion receipt is tampered with on disk: the running
    // session's revalidation misses (recoverable); the rebuild's own
    // admission of the held identity then refuses (terminal).
    tree.write_identity_file("online-completed.json", b"{}");
    let done = host.tick_until(Duration::from_secs(5), |h| h.cancels > 0);
    assert!(done, "{:?}", ended(&events));
    assert_eq!(host.reassertions, 1);
    let lost = host.probe.phase_reader().snapshot().1;
    assert_eq!(lost, Some("store_revalidation_failed"));
    // The claim capture's own custody refusal (unlisted: every capture
    // refusal is terminal) or the session admission's listed terminal code.
    let failed = host.failed.expect("no failure code");
    let listed = REFUSALS.iter().any(|(code, _)| *code == failed);
    assert!(!listed || classify(failed) == Terminal, "{failed}");
    assert_eq!(ended(&events), [failed]);
    // Exactly one cancel: later observations change nothing.
    for _ in 0..50 {
        host.tick();
        thread::sleep(Duration::from_millis(2));
    }
    assert_eq!((host.cancels, host.applied, host.swaps), (1, 1, 0));
    assert_eq!(host.lifecycle.phase, Phase::Blocking);
    assert!(host.stop().is_some());
    assert!(!store_locked(&tree.identity_dir()));
}

#[test]
fn rebuild_identity_gone_is_a_terminal_custody_refusal() {
    let accepting = Arc::new(AtomicBool::new(false));
    let (_relay, tree) = gated_relay(accepting);
    let (trace, events) = recorder();
    let mut host = Host::start(tree.clone(), Some(trace), FAST);
    assert!(host.tick_until(Duration::from_secs(8), |h| h.reasserting));
    // The held identity is forgotten while the tunnel reasserts.
    std::fs::remove_dir_all(tree.identity_dir()).unwrap();
    assert!(host.tick_until(Duration::from_secs(5), |h| h.cancels > 0));
    let failed = host.failed.unwrap();
    assert_eq!(ended(&events).last(), Some(&failed));
    for _ in 0..50 {
        host.tick();
        thread::sleep(Duration::from_millis(2));
    }
    assert_eq!((host.cancels, host.applied, host.swaps), (1, 1, 0));
    assert!(host.stop().is_some());
}

#[test]
fn rebuild_stop_while_reasserting_joins_both_sessions_within_budget() {
    // Every later connection holds its ACK request: the first session's
    // re-ACKs and the rebuilt session's first ACK never complete.
    let (relay, tree) = relay(|_| Some(Behavior::HoldRequest));
    let (trace, events) = recorder();
    let mut host = Host::start(tree.clone(), Some(trace), FAST);
    let first = host.probe.clone();
    assert!(host.tick_until(Duration::from_secs(8), |h| h.reasserting));
    assert!(host.tick_until(Duration::from_secs(3), |_| !spawned_at(&events).is_empty()));
    // The rebuilt session is Constructing inside its held ACK.
    let accepted = relay.accepts();
    assert!(wait_until(Duration::from_secs(2), || relay.accepts() > accepted).is_some());
    thread::sleep(Duration::from_millis(200));
    assert!(ended(&events).is_empty());
    assert!(store_locked(&tree.identity_dir()));
    let stopped = host.stop().expect("stop exceeded the 2 s budget");
    assert!(stopped <= STOP_BUDGET, "{stopped:?}");
    assert_eq!(first.phase(), SessionPhase::Joined);
    assert!(!store_locked(&tree.identity_dir()));
    assert_eq!((host.applied, host.cancels, host.swaps), (1, 0, 0));
}

#[test]
fn rebuild_stop_during_backoff_joins_at_once() {
    let (_relay, tree) = relay(|_| None);
    let slow = Schedule {
        first: Duration::from_secs(20),
        ..FAST
    };
    let (trace, events) = recorder();
    let mut host = Host::start(tree.clone(), Some(trace), slow);
    assert!(host.tick_until(Duration::from_secs(8), |h| h.reasserting));
    assert!(host.tick_until(Duration::from_secs(2), |_| events
        .lock()
        .unwrap()
        .iter()
        .any(|(event, _)| matches!(event, RebuildEvent::Backoff { .. }))));
    let stopped = host.stop().unwrap();
    assert!(stopped < Duration::from_millis(500), "{stopped:?}");
    assert!(spawned_at(&events).is_empty());
    assert!(!store_locked(&tree.identity_dir()));
}

#[test]
fn rebuild_backoff_never_hot_loops_against_a_refusing_relay() {
    let (relay, tree) = relay(|_| None);
    let (trace, events) = recorder();
    let mut host = Host::start(tree.clone(), Some(trace), FAST);
    assert!(host.tick_until(Duration::from_secs(8), |h| h.reasserting));
    let reasserted = Instant::now();
    assert!(host.tick_until(Duration::from_secs(5), |_| spawned_at(&events).len() >= 6));
    let window = reasserted.elapsed();
    let spawned = spawned_at(&events);
    // Every attempt waited at least half its nominal delay first.
    for pair in spawned.windows(2) {
        assert!(
            pair[1] - pair[0] >= FAST.first / 2,
            "{:?}",
            pair[1] - pair[0]
        );
    }
    let delays: Vec<_> = events
        .lock()
        .unwrap()
        .iter()
        .filter_map(|(event, _)| match event {
            RebuildEvent::Backoff { attempt, delay } => Some((*attempt, *delay)),
            _ => None,
        })
        .collect();
    for (attempt, delay) in &delays {
        assert!(*delay >= FAST.nominal(*attempt) / 2 && *delay <= FAST.nominal(*attempt));
        assert!(*delay <= FAST.cap);
    }
    // No more attempts than the floor allows in the elapsed window.
    let floor = FAST.first / 2;
    assert!(
        spawned.len() as u128 <= window.as_millis() / floor.as_millis() + 1,
        "{} attempts in {window:?}",
        spawned.len()
    );
    assert!(ended(&events)
        .iter()
        .all(|code| classify(code) == Recoverable));
    assert_eq!((host.cancels, host.applied), (0, 1));
    assert!(relay.accepts() >= 6);
    assert!(host.stop().is_some());
    assert!(!store_locked(&tree.identity_dir()));
}

#[test]
fn rebuild_pinned_interface_is_reused_without_resolution() {
    let (_relay, tree) = relay(|_| None);
    // Production resolution refuses a loopback relay before any dial...
    let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
    let (tx, rx) = mpsc::channel();
    let mut unpinned = spawn_pinned(
        saved(&tree),
        claim,
        move |phase| {
            let _ = tx.send(phase);
        },
        None,
        EpochPins::default(),
        None,
    )
    .unwrap();
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(3)).ok(),
        Some(SessionPhase::Sealed)
    );
    assert!(unpinned.try_join(Duration::from_secs(2)));
    assert_eq!(unpinned.refusal(), Some(relay_socket::UNRESOLVED));
    // ...while an epoch whose interface is pinned dials through it.
    let (relay, tree) = relay(|_| None);
    let pinned = EpochPins::pinned_for_test(RelayInterface::loopback_for_test());
    let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
    let (tx, rx) = mpsc::channel();
    let mut session = spawn_pinned(
        saved(&tree),
        claim,
        move |phase| {
            let _ = tx.send(phase);
        },
        None,
        pinned.clone(),
        None,
    )
    .unwrap();
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(3)).ok(),
        Some(SessionPhase::Ready),
        "{:?}",
        session.refusal()
    );
    assert!(relay.accepts() >= 1);
    assert!(session.try_join(Duration::from_secs(2)));
    // A pinned interface is never replaced.
    assert_eq!(pinned.get(), Some(RelayInterface::loopback_for_test()));
}

/// The string literals that a provider session, its body or the provider's
/// packet path records as a refusal: arguments of the sealing and refusing
/// calls, and the codes returned bare from the classifying expressions.
fn emitted(source: &str, contexts: &[&str], bare: bool) -> HashSet<String> {
    let end = ["\nmod tests {", "\npub(crate) mod tests {"]
        .iter()
        .filter_map(|cut| source.find(cut))
        .min()
        .unwrap_or(source.len());
    let mut codes = HashSet::new();
    for line in source[..end].lines() {
        let mut rest = line;
        let mut offset = 0;
        while let Some(open) = rest.find('"') {
            let start = offset + open;
            let Some(close) = line[start + 1..].find('"') else {
                break;
            };
            let literal = &line[start + 1..start + 1 + close];
            let before = &line[..start];
            let token = !literal.is_empty()
                && literal
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
            let alone = line.trim() == format!("\"{literal}\"");
            if token && (contexts.iter().any(|c| before.ends_with(c)) || (bare && alone)) {
                codes.insert(literal.to_string());
            }
            offset = start + close + 2;
            rest = &line[offset..];
        }
    }
    codes
}

#[test]
fn rebuild_refusal_table_classifies_every_code_the_session_can_emit() {
    let calls = [
        "refused(",
        "Refused(",
        "seal(",
        "Sealed(",
        "Err(",
        "unwrap_or(",
        "|_| ",
        "bridge, ",
        "=> ",
    ];
    let mut codes = emitted(include_str!("provider_session_body.rs"), &calls, true);
    codes.extend(emitted(include_str!("provider_session.rs"), &calls, true));
    codes.extend(emitted(
        include_str!("session_rebuild.rs"),
        &["seal("],
        false,
    ));
    codes.extend(emitted(include_str!("apple.rs"), &["seal("], false));
    // S23: the renewal step's refusals before a capture.
    codes.extend(emitted(
        include_str!("identity_renewal.rs"),
        &["transient("],
        false,
    ));
    for code in [
        crate::identity_renewal::IDENTITY_RENEWAL_DUE,
        crate::identity_renewal::IDENTITY_RENEWAL_PENDING,
        crate::identity_renewal::IDENTITY_RENEWAL_STOPPED,
        crate::identity_renewal::SESSION_IDENTITY_EXPIRED,
        crate::renewal_journal::BUSY,
    ] {
        codes.insert(code.to_string());
    }
    // Passed through by name: the relay interface resolution's refusal.
    codes.insert(relay_socket::UNRESOLVED.to_string());
    // The scan itself is live: it finds codes of every kind.
    for known in [
        "capture_lease_expired",
        "session_monitor_ended",
        "session_ack_refused",
        "session_binding_refused",
        "session_panicked",
        "session_handle_dropped",
        "store_revalidation_failed",
        "session_rebuild_timeout",
        "native_packet_malformed",
        "packet_io_failed",
    ] {
        assert!(codes.contains(known), "scan missed {known}");
    }
    let listed: HashSet<_> = REFUSALS.iter().map(|(code, _)| code.to_string()).collect();
    assert_eq!(listed.len(), REFUSALS.len(), "a code is listed twice");
    let mut missing: Vec<_> = codes.difference(&listed).collect();
    missing.sort();
    assert!(
        missing.is_empty(),
        "unclassified refusal codes: {missing:?}"
    );
}

#[test]
fn rebuild_refusal_table_is_terminal_only_for_custody_panic_and_owner_end() {
    let terminal: HashSet<&str> = [
        "session_identity_refused",
        "session_peer_refused",
        "session_peer_mismatch",
        "session_binding_refused",
        "session_panicked",
        "provider_stop",
        "session_handle_dropped",
    ]
    .into_iter()
    .collect();
    for (code, recovery) in REFUSALS {
        let expected = if terminal.contains(code) {
            Terminal
        } else {
            Recoverable
        };
        assert_eq!(*recovery, expected, "{code}");
        assert_eq!(classify(code), expected, "{code}");
    }
    // The installed findings: refused or late re-ACK, expiry, an
    // unreachable relay and a revalidation miss never cancel by themselves.
    for code in [
        "capture_lease_expired",
        "session_ack_refused",
        "session_connect_failed",
        "session_packet_terminal",
        "store_revalidation_failed",
    ] {
        assert_eq!(classify(code), Recoverable, "{code}");
    }
    // An unlisted code is rebuilt: the rebuild's admission re-checks custody.
    assert_eq!(classify("unlisted_fixture_code"), Recoverable);
    // Every capture-time custody refusal is terminal, whatever its code,
    // unless it failed only for want of descriptors, memory or a retry.
    let gone = io::Error::new(io::ErrorKind::NotFound, "fixture");
    assert_eq!(Refusal::custody(&gone).recovery, Terminal);
    for errno in [
        libc::ENOENT,
        libc::EACCES,
        libc::EPERM,
        libc::ELOOP,
        libc::ENOTDIR,
    ] {
        let refused = io::Error::from_raw_os_error(errno);
        assert_eq!(Refusal::custody(&refused).recovery, Terminal, "{errno}");
    }
    for errno in [
        libc::EMFILE,
        libc::ENFILE,
        libc::ENOMEM,
        libc::EAGAIN,
        libc::EINTR,
    ] {
        let exhausted = io::Error::from_raw_os_error(errno);
        assert_eq!(
            Refusal::custody(&exhausted).recovery,
            Recoverable,
            "{errno}"
        );
    }
    assert_eq!(
        Refusal::transient("session_spawn_failed").recovery,
        Recoverable
    );
}

#[test]
fn rebuild_backoff_doubles_from_half_a_second_to_eight_and_is_jittered() {
    let nominal: Vec<_> = (1..=7).map(|n| PRODUCTION.nominal(n).as_millis()).collect();
    assert_eq!(nominal, [500, 1_000, 2_000, 4_000, 8_000, 8_000, 8_000]);
    for attempt in [0, 1, 2, 5, 16, 17, 1_000, u32::MAX] {
        let n = PRODUCTION.nominal(attempt);
        assert!(n >= PRODUCTION.first && n <= PRODUCTION.cap, "{attempt}");
        for jitter in [0, 1, 7, 249_999, 250_000, 250_001, u64::MAX / 3, u64::MAX] {
            let delay = PRODUCTION.delay(attempt, jitter);
            assert!(delay >= n / 2 && delay <= n, "{attempt} {jitter} {delay:?}");
            // Never a hot loop: at least a quarter second, at most eight.
            assert!(delay >= Duration::from_millis(250));
            assert!(delay <= Duration::from_secs(8));
        }
    }
    // The jitter spans the upper half of the nominal delay.
    assert_eq!(PRODUCTION.delay(1, 0), Duration::from_millis(250));
    assert_eq!(PRODUCTION.delay(1, 250_000), Duration::from_millis(500));
    // Real jitter values differ between attempts and runs.
    let seen: HashSet<_> = (0..64).map(|_| jitter(1)).collect();
    assert!(seen.len() > 1);
    assert_eq!(PRODUCTION.construct, Duration::from_secs(10));
}

#[test]
fn rebuild_native_packets_are_dropped_while_reasserting_or_lost() {
    assert_eq!(native_packets(Phase::Running, true), Disposition::Forward);
    assert_eq!(native_packets(Phase::Running, false), Disposition::Drop);
    assert_eq!(native_packets(Phase::Reasserting, true), Disposition::Drop);
    assert_eq!(native_packets(Phase::Reasserting, false), Disposition::Drop);
    for phase in [
        Phase::Idle,
        Phase::Admitted,
        Phase::Applying,
        Phase::Blocking,
        Phase::Stopped,
    ] {
        for live in [true, false] {
            assert_eq!(native_packets(phase, live), Disposition::Stale, "{phase:?}");
        }
    }
}

#[test]
fn rebuild_lifecycle_session_lost_reasserts_only_a_running_recoverable_epoch() {
    let mut l = Lifecycle::default();
    let g = l.admit().unwrap();
    // Before Running a loss is the start path's failure, never a reassert.
    assert_eq!(
        session_lost(&mut l, g, "capture_lease_expired"),
        Lost::Ignore
    );
    assert_eq!(l.session_ready(g), Effect::ApplySettings);
    assert_eq!(
        session_lost(&mut l, g, "capture_lease_expired"),
        Lost::Ignore
    );
    assert_eq!(l.ready(g), Ok(Effect::CompleteStart));
    // A stale generation changes nothing.
    assert_eq!(
        session_lost(&mut l, g + 1, "capture_lease_expired"),
        Lost::Ignore
    );
    assert_eq!(l.phase, Phase::Running);
    // Terminal custody: fail (one cancel), the phase is left to `fail`.
    assert_eq!(
        session_lost(&mut l, g, "session_identity_refused"),
        Lost::Fail("session_identity_refused")
    );
    assert_eq!(l.phase, Phase::Running);
    // Recoverable: reassert exactly once.
    assert_eq!(
        session_lost(&mut l, g, "session_ack_refused"),
        Lost::Reassert
    );
    assert_eq!(l.phase, Phase::Reasserting);
    assert_eq!(session_lost(&mut l, g, "session_ack_refused"), Lost::Ignore);
    assert_eq!(
        session_lost(&mut l, g, "session_identity_refused"),
        Lost::Ignore
    );
    // A stop wins over every later loss.
    assert_eq!(l.rebuilt(g), Ok(Effect::Reasserted));
    assert_eq!(l.stop(), Some((g, Effect::None)));
    assert_eq!(
        session_lost(&mut l, g, "capture_lease_expired"),
        Lost::Ignore
    );
}

/// A lost session whose body needs `teardown` to return after its seal.
fn slow_lost_session(teardown: Duration) -> SessionHandle {
    use crate::bridge::{LeasedPacketBridge, PacketBridge};
    use aegis_client::capture_lease_gate::CaptureLeaseDeadline;
    let bridge = LeasedPacketBridge::new(PacketBridge::default(), CaptureLeaseDeadline::default());
    SessionHandle::spawn(
        bridge,
        |_| {},
        move |control| {
            control.mark_ready();
            while !control.stop_requested() {
                thread::park_timeout(Duration::from_millis(5));
            }
            // Simulates releasing the Store and joining the engine.
            thread::sleep(teardown);
            Ok(())
        },
    )
    .unwrap()
}

#[test]
fn rebuild_joins_the_lost_session_before_building_any() {
    let lost = slow_lost_session(Duration::from_millis(300));
    let reader = lost.probe().phase_reader();
    lost.seal("capture_lease_expired");
    let lost = Arc::new(Mutex::new(lost));
    let (seen_tx, seen_rx) = mpsc::channel();
    let started = Instant::now();
    let mut rebuild = Rebuild::spawn(
        lost,
        Box::new(move |_, _| {
            let _ = seen_tx.send((reader.snapshot(), started.elapsed()));
            Err(Refusal {
                code: "fixture_custody_refused",
                recovery: Terminal,
            })
        }),
        FAST,
        None,
        Box::new(|| {}),
        0,
    )
    .unwrap();
    let ((phase, code), after) = seen_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    // The new claim is captured only once the lost session has joined.
    assert_eq!(phase, SessionPhase::Joined);
    assert_eq!(code, Some("capture_lease_expired"));
    assert!(after >= Duration::from_millis(300), "{after:?}");
    assert!(wait_until(Duration::from_secs(2), || rebuild.finished()).is_some());
    assert!(matches!(
        rebuild.take_outcome(),
        Some(RebuildOutcome::Terminal("fixture_custody_refused", None))
    ));
    assert!(rebuild.seal_and_try_join(Duration::ZERO));
}

#[test]
fn rebuild_lifecycle_outcome_after_stop_is_left_to_the_stop_path() {
    let mut l = Lifecycle::default();
    let g = l.admit().unwrap();
    assert_eq!(l.session_ready(g), Effect::ApplySettings);
    assert_eq!(l.ready(g), Ok(Effect::CompleteStart));
    assert_eq!(l.reassert(g), Ok(Effect::Reassert));
    let lost = slow_lost_session(Duration::ZERO);
    lost.seal("capture_lease_expired");
    let mut rebuild = Rebuild::spawn(
        Arc::new(Mutex::new(lost)),
        Box::new(|_, _| {
            Err(Refusal {
                code: "fixture_custody_refused",
                recovery: Terminal,
            })
        }),
        FAST,
        None,
        Box::new(|| {}),
        0,
    )
    .unwrap();
    assert!(wait_until(Duration::from_secs(3), || rebuild.finished()).is_some());
    // Apple's stop arrived first: a terminal rebuild no longer fails (and so
    // never cancels) the stopping generation, and nothing is taken.
    assert_eq!(l.stop(), Some((g, Effect::None)));
    assert!(matches!(
        rebuild_finished(&mut l, g, &mut rebuild),
        Finished::Ignore
    ));
    assert_eq!(l.phase, Phase::Blocking);
    assert!(matches!(
        rebuild.take_outcome(),
        Some(RebuildOutcome::Terminal(_, None))
    ));
    // A stale generation never takes an outcome either.
    let mut l = Lifecycle::default();
    let g = l.admit().unwrap();
    assert_eq!(l.session_ready(g), Effect::ApplySettings);
    assert_eq!(l.ready(g), Ok(Effect::CompleteStart));
    assert_eq!(l.reassert(g), Ok(Effect::Reassert));
    assert!(matches!(
        rebuild_finished(&mut l, g + 1, &mut rebuild),
        Finished::Ignore
    ));
}

#[test]
fn rebuild_constructing_past_its_budget_is_sealed_and_retried() {
    // Every rebuilt session's ACK is held: it would stay Constructing.
    let (_relay, tree) = relay(|_| Some(Behavior::HoldRequest));
    let short = Schedule {
        construct: Duration::from_millis(300),
        ..FAST
    };
    let (trace, events) = recorder();
    let mut host = Host::start(tree.clone(), Some(trace), short);
    assert!(host.tick_until(Duration::from_secs(8), |h| h.reasserting));
    assert!(host.tick_until(Duration::from_secs(5), |_| ended(&events).len() >= 2));
    assert!(ended(&events)
        .iter()
        .all(|code| *code == "session_rebuild_timeout"));
    assert_eq!(classify("session_rebuild_timeout"), Recoverable);
    assert_eq!((host.cancels, host.applied, host.swaps), (0, 1, 0));
    assert!(host.stop().is_some());
    assert!(!store_locked(&tree.identity_dir()));
}

/// A session without Store or relay: Ready at once, then `body` until stop.
/// `lifetime` (if any) seals it with `capture_lease_expired` after Ready.
fn fake_session(notifier: SessionNotifier, lifetime: Option<Duration>) -> SessionHandle {
    use crate::bridge::{LeasedPacketBridge, PacketBridge};
    use aegis_client::capture_lease_gate::CaptureLeaseDeadline;
    let bridge = LeasedPacketBridge::new(PacketBridge::default(), CaptureLeaseDeadline::default());
    SessionHandle::spawn(bridge, notifier, move |control| {
        control.mark_ready();
        let ready = Instant::now();
        while !control.stop_requested() {
            if lifetime.is_some_and(|lifetime| ready.elapsed() >= lifetime) {
                control.seal("capture_lease_expired");
            }
            thread::park_timeout(Duration::from_millis(2));
        }
        Ok(())
    })
    .unwrap()
}

/// A session whose body panics: while Constructing, or once stopped.
fn panicking_session(notifier: SessionNotifier, constructing: bool) -> SessionHandle {
    use crate::bridge::{LeasedPacketBridge, PacketBridge};
    use aegis_client::capture_lease_gate::CaptureLeaseDeadline;
    let bridge = LeasedPacketBridge::new(PacketBridge::default(), CaptureLeaseDeadline::default());
    SessionHandle::spawn(bridge, notifier, move |control| {
        if constructing {
            panic!("fixture session panicked while constructing");
        }
        control.mark_ready();
        while !control.stop_requested() {
            thread::park_timeout(Duration::from_millis(2));
        }
        panic!("fixture session panicked during teardown");
    })
    .unwrap()
}

fn running_lifecycle() -> (Lifecycle, u64) {
    let mut l = Lifecycle::default();
    let g = l.admit().unwrap();
    assert_eq!(l.session_ready(g), Effect::ApplySettings);
    assert_eq!(l.ready(g), Ok(Effect::CompleteStart));
    (l, g)
}

#[test]
fn rebuild_outcome_is_taken_on_its_one_notification_before_the_thread_exits() {
    let (mut l, g) = running_lifecycle();
    let lost = slow_lost_session(Duration::ZERO);
    lost.seal("capture_lease_expired");
    assert_eq!(
        session_lost(&mut l, g, "capture_lease_expired"),
        Lost::Reassert
    );
    let (posted_tx, posted_rx) = mpsc::channel();
    // The worker is held inside `done` after posting, as a preempted thread
    // would be: it has not exited when the one notification is handled.
    let done: Box<dyn FnOnce() + Send> = Box::new(move || {
        let _ = posted_tx.send(());
        thread::sleep(Duration::from_millis(400));
    });
    let mut rebuild = Rebuild::spawn(
        Arc::new(Mutex::new(lost)),
        Box::new(|notifier, _stop| Ok(fake_session(notifier, None))),
        FAST,
        None,
        done,
        0,
    )
    .unwrap();
    posted_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    assert!(!rebuild.finished());
    // Exactly one observation, as rebuildChanged: makes: it swaps.
    let Finished::Swap(mut session, attempts) = rebuild_finished(&mut l, g, &mut rebuild) else {
        panic!("the one notification did not swap");
    };
    assert_eq!(attempts, 1);
    assert_eq!(l.phase, Phase::Running);
    assert_eq!(session.phase(), SessionPhase::Ready);
    assert!(rebuild.seal_and_try_join(Duration::from_secs(2)));
    assert!(session.try_join(Duration::from_secs(2)));
    // A terminal outcome is likewise taken on its one notification.
    let (mut l, g) = running_lifecycle();
    let lost = slow_lost_session(Duration::ZERO);
    lost.seal("capture_lease_expired");
    assert_eq!(
        session_lost(&mut l, g, "capture_lease_expired"),
        Lost::Reassert
    );
    let (posted_tx, posted_rx) = mpsc::channel();
    let mut rebuild = Rebuild::spawn(
        Arc::new(Mutex::new(lost)),
        Box::new(|_, _| {
            Err(Refusal {
                code: "fixture_custody_refused",
                recovery: Terminal,
            })
        }),
        FAST,
        None,
        Box::new(move || {
            let _ = posted_tx.send(());
            thread::sleep(Duration::from_millis(400));
        }),
        0,
    )
    .unwrap();
    posted_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    assert!(matches!(
        rebuild_finished(&mut l, g, &mut rebuild),
        Finished::Fail("fixture_custody_refused")
    ));
    assert!(rebuild.seal_and_try_join(Duration::from_secs(2)));
}

/// One epoch over fake sessions that each stay Ready for `lifetime`: the
/// provider's loss, rebuild and swap decisions. Returns the first attempt
/// number of each rebuild.
fn flapping_epoch(lifetime: Duration, schedule: Schedule, rebuilds: usize) -> Vec<u32> {
    let (mut l, g) = running_lifecycle();
    let (trace, events) = recorder();
    let mut slot = Rebuilds::default();
    let mut session = Arc::new(Mutex::new(fake_session(Box::new(|_| {}), Some(lifetime))));
    let mut firsts = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    while firsts.len() < rebuilds {
        assert!(Instant::now() < deadline, "{firsts:?}");
        let probe = session.lock().unwrap().probe();
        // The fake bridge holds no lease: a loss is the session's own seal.
        if l.phase == Phase::Running
            && matches!(probe.phase(), SessionPhase::Sealed | SessionPhase::Joined)
        {
            let code = probe.phase_reader().snapshot().1.unwrap();
            assert_eq!(session_lost(&mut l, g, code), Lost::Reassert);
            let (lost, trace) = (session.clone(), trace.clone());
            let before = events.lock().unwrap().len();
            slot.start_with(schedule, Instant::now(), move |spent| {
                Rebuild::spawn(
                    lost,
                    Box::new(move |notifier, _stop| Ok(fake_session(notifier, Some(lifetime)))),
                    schedule,
                    Some(trace),
                    Box::new(|| {}),
                    spent,
                )
            })
            .unwrap();
            let first = wait_until(Duration::from_secs(2), || {
                events.lock().unwrap()[before..]
                    .iter()
                    .find_map(|(event, _)| match event {
                        RebuildEvent::Backoff { attempt, .. } => Some(*attempt),
                        _ => None,
                    })
                    .is_some()
            });
            assert!(first.is_some());
            let attempt = events.lock().unwrap()[before..]
                .iter()
                .find_map(|(event, _)| match event {
                    RebuildEvent::Backoff { attempt, .. } => Some(*attempt),
                    _ => None,
                })
                .unwrap();
            firsts.push(attempt);
        }
        if let Some(rebuild) = slot.current.clone() {
            let finished = rebuild_finished(&mut l, g, &mut rebuild.lock().unwrap());
            match finished {
                Finished::Swap(rebuilt, attempts) => {
                    slot.swapped(attempts, Instant::now());
                    let old = std::mem::replace(&mut session, Arc::new(Mutex::new(rebuilt)));
                    assert!(old.lock().unwrap().try_join(Duration::from_secs(2)));
                }
                Finished::Fail(code) => panic!("cancelled with {code}"),
                Finished::Ignore => {}
            }
        }
        thread::sleep(Duration::from_millis(2));
    }
    if let Some(rebuild) = slot.current.take() {
        assert!(rebuild
            .lock()
            .unwrap()
            .seal_and_try_join(Duration::from_secs(2)));
    }
    assert!(session.lock().unwrap().try_join(Duration::from_secs(2)));
    firsts
}

#[test]
fn rebuild_backoff_carries_across_rebuilds_of_a_session_that_drops_after_ready() {
    let quick = Schedule {
        first: Duration::from_millis(10),
        cap: Duration::from_millis(80),
        construct: Duration::from_secs(2),
        stable: Duration::from_secs(30),
    };
    // Each rebuilt session is lost 20 ms after Ready, well inside `stable`:
    // every rebuild starts one attempt later than the last, so the backoff
    // climbs to its cap instead of restarting at the first step.
    let firsts = flapping_epoch(Duration::from_millis(20), quick, 6);
    assert_eq!(firsts, [1, 2, 3, 4, 5, 6]);
    assert!(quick.nominal(firsts[5]) == quick.cap);
    // A session that stayed live for `stable` restarts the backoff.
    let settled = Schedule {
        stable: Duration::from_millis(5),
        ..quick
    };
    let firsts = flapping_epoch(Duration::from_millis(40), settled, 4);
    assert_eq!(firsts, [1, 1, 1, 1]);
}

#[test]
fn rebuild_carry_and_respawn_state_is_bounded_and_per_epoch() {
    let now = Instant::now();
    let stable = Duration::from_secs(30);
    let mut carry = Carry::default();
    assert_eq!(carry.spent(now, stable), 0);
    carry.swapped(4, now);
    assert_eq!(carry.spent(now + Duration::from_secs(29), stable), 4);
    assert_eq!(carry.spent(now + stable, stable), 0);
    assert_eq!(carry.spent(now + Duration::from_secs(3_600), stable), 0);
    // A failed rebuild-thread spawn is never a cancel: it is retried with
    // the same bounded backoff from the drain timer, and only once due.
    let mut slot = Rebuilds::default();
    assert!(!slot.respawn_due(now));
    let refused = slot.start_with(FAST, now, |_| {
        Err(io::Error::from_raw_os_error(libc::EAGAIN))
    });
    assert_eq!(refused, Err("session_rebuild_spawn_failed"));
    assert_eq!(classify("session_rebuild_spawn_failed"), Recoverable);
    assert!(slot.current.is_none());
    assert!(!slot.respawn_due(now));
    assert!(!slot.respawn_due(now + FAST.first / 2 - Duration::from_millis(1)));
    assert!(slot.respawn_due(now + FAST.first));
    // A second failure waits longer (attempt 2 of the same schedule).
    let later = now + FAST.first;
    assert!(slot
        .start_with(FAST, later, |_| Err(io::Error::from_raw_os_error(
            libc::EAGAIN
        )))
        .is_err());
    assert!(!slot.respawn_due(later + FAST.nominal(2) / 2 - Duration::from_millis(1)));
    assert!(slot.respawn_due(later + FAST.nominal(2)));
    // A successful spawn clears the retry, receiving the carried attempts.
    slot.swapped(3, later);
    let lost = slow_lost_session(Duration::ZERO);
    lost.seal("capture_lease_expired");
    let mut seen = None;
    slot.start_with(FAST, later, |spent| {
        seen = Some(spent);
        Rebuild::spawn(
            Arc::new(Mutex::new(lost)),
            Box::new(|_, _| Err(Refusal::transient("fixture_transient"))),
            FAST,
            None,
            Box::new(|| {}),
            spent,
        )
    })
    .unwrap();
    assert_eq!(seen, Some(3));
    assert!(!slot.respawn_due(later + Duration::from_secs(60)));
    assert!(slot
        .current
        .take()
        .unwrap()
        .lock()
        .unwrap()
        .seal_and_try_join(Duration::from_secs(2)));
}

#[test]
fn rebuild_panicked_rebuilt_session_is_terminal_once_and_retained_for_the_stop_path() {
    let (mut l, g) = running_lifecycle();
    let lost = slow_lost_session(Duration::ZERO);
    lost.seal("capture_lease_expired");
    assert_eq!(
        session_lost(&mut l, g, "capture_lease_expired"),
        Lost::Reassert
    );
    let (trace, events) = recorder();
    let mut rebuild = Rebuild::spawn(
        Arc::new(Mutex::new(lost)),
        Box::new(|notifier, _stop| Ok(panicking_session(notifier, true))),
        FAST,
        Some(trace),
        Box::new(|| {}),
        0,
    )
    .unwrap();
    // The outcome arrives: the join of an unwound session gives up.
    let outcome = wait_until(Duration::from_secs(3), || {
        !matches!(rebuild_finished(&mut l, g, &mut rebuild), Finished::Ignore)
            || l.phase != Phase::Reasserting
    });
    assert!(outcome.is_some(), "{:?}", ended(&events));
    assert_eq!(ended(&events), ["session_panicked"]);
    assert_eq!(classify("session_panicked"), Terminal);
    // Exactly one failure: the lifecycle `fail` then refuses any second one.
    assert_eq!(l.fail(g), Ok(Effect::None));
    assert!(matches!(
        rebuild_finished(&mut l, g, &mut rebuild),
        Finished::Ignore
    ));
    // The unwound session stays with the rebuild: the stop path never joins
    // it, so the provider ends by its stop-budget exit.
    assert!(!rebuild.seal_and_try_join(Duration::from_millis(200)));
    assert!(rebuild.finished());
    assert!(!rebuild.seal_and_try_join(Duration::ZERO));
}

#[test]
fn rebuild_lost_session_that_unwinds_is_terminal_without_any_rebuild() {
    let (mut l, g) = running_lifecycle();
    let lost = panicking_session(Box::new(|_| {}), false);
    // First sealed with a recoverable code; the body then panics in teardown.
    lost.seal("capture_lease_expired");
    assert_eq!(lost.refusal(), Some("capture_lease_expired"));
    assert_eq!(
        session_lost(&mut l, g, "capture_lease_expired"),
        Lost::Reassert
    );
    let (trace, events) = recorder();
    let built = Arc::new(AtomicBool::new(false));
    let factory_built = built.clone();
    let lost = Arc::new(Mutex::new(lost));
    let mut rebuild = Rebuild::spawn(
        lost.clone(),
        Box::new(move |_, _| {
            factory_built.store(true, Ordering::SeqCst);
            Err(Refusal::transient("fixture_transient"))
        }),
        FAST,
        Some(trace),
        Box::new(|| {}),
        0,
    )
    .unwrap();
    assert!(wait_until(Duration::from_secs(3), || rebuild.finished()).is_some());
    assert!(matches!(
        rebuild_finished(&mut l, g, &mut rebuild),
        Finished::Fail("session_panicked")
    ));
    assert!(!built.load(Ordering::SeqCst));
    assert!(events.lock().unwrap().is_empty());
    // The provider still holds the unwound session: it never joins.
    assert!(lost.lock().unwrap().unwound());
    assert!(!lost.lock().unwrap().try_join(Duration::ZERO));
    assert!(rebuild.seal_and_try_join(Duration::ZERO));
}

#[test]
fn rebuild_admission_refusal_outside_the_admitted_window_is_a_validity_miss() {
    let window = Some(Admitted {
        at: 1_000,
        not_before: 900,
        not_after: 2_000,
    });
    let code = "session_identity_refused";
    // Inside the window the held identity is refused: terminal custody.
    assert_eq!(admission_refusal(code, window, Some(1_000)), code);
    assert_eq!(admission_refusal(code, window, Some(1_999)), code);
    assert_eq!(classify(code), Terminal);
    // S23: expired at or past not_after; the clock moved back before the
    // admission. Both recoverable.
    for now in [2_000, 2_001, u64::MAX] {
        let judged = admission_refusal(code, window, Some(now));
        assert_eq!(judged, "session_identity_expired", "{now}");
        assert_eq!(classify(judged), Recoverable);
    }
    for now in [999, 0] {
        let judged = admission_refusal(code, window, Some(now));
        assert_eq!(judged, "session_identity_not_current", "{now}");
        assert_eq!(classify(judged), Recoverable);
    }
    assert_eq!(
        admission_refusal("session_binding_refused", window, Some(2_000)),
        "session_identity_expired"
    );
    assert_eq!(
        admission_refusal("session_binding_refused", window, Some(1_500)),
        "session_binding_refused"
    );
    // An unreadable clock is recoverable; no admission yet leaves the code.
    assert_eq!(
        admission_refusal(code, window, None),
        "session_clock_failed"
    );
    assert_eq!(classify("session_clock_failed"), Recoverable);
    assert_eq!(admission_refusal(code, None, Some(5_000)), code);
    assert_eq!(admission_refusal(code, None, None), code);
}

#[test]
fn rebuild_certificate_expiry_mid_session_never_cancels() {
    let accepting = Arc::new(AtomicBool::new(true));
    let (_relay, tree) = gated_relay(accepting);
    let (trace, events) = recorder();
    let mut host = Host::start(tree.clone(), Some(trace), FAST);
    // The first session's admission recorded its validity window.
    let admitted = host.pinned.admitted().expect("no admitted window");
    let now = aegis_core::secure_channel::registry::unix_now().unwrap();
    assert!(admitted.at <= now && now < admitted.not_after);
    // The certificate's validity has passed: the held identity no longer
    // admits. Here the Store's profile pin no longer matches (a refusal the
    // claim capture passes and the Store admission refuses, as it refuses an
    // expired certificate) while the clock lies past the admitted window.
    host.pinned.admit_for_test(now - 120, now - 1);
    tree.write_identity_file("bundle-profile.sha256", "0".repeat(64).as_bytes());
    assert!(host.tick_until(Duration::from_secs(5), |h| h.reasserting));
    let enough = host.tick_until(Duration::from_secs(5), |_| ended(&events).len() >= 3);
    let codes = ended(&events);
    assert!(enough, "{codes:?} {:?}", host.failed);
    assert!(
        codes.iter().all(|code| *code == "session_identity_expired"),
        "{codes:?}"
    );
    // Blocked, never cancelled: settings stay applied and packets drop.
    assert_eq!((host.cancels, host.applied, host.swaps), (0, 1, 0));
    assert_eq!(host.lifecycle.phase, Phase::Reasserting);
    assert_eq!(host.packets(3), 0);
    assert!(host.stop().is_some());
    assert!(!store_locked(&tree.identity_dir()));
}

#[test]
fn rebuild_store_refusal_inside_the_admitted_window_still_cancels_once() {
    let accepting = Arc::new(AtomicBool::new(true));
    let (_relay, tree) = gated_relay(accepting);
    let (trace, events) = recorder();
    let mut host = Host::start(tree.clone(), Some(trace), FAST);
    // The same Store refusal while the certificate is still valid: the held
    // identity itself is refused, a terminal custody failure.
    tree.write_identity_file("bundle-profile.sha256", "0".repeat(64).as_bytes());
    assert!(host.tick_until(Duration::from_secs(5), |h| h.cancels > 0));
    assert_eq!(host.failed, Some("session_identity_refused"));
    assert_eq!(ended(&events), ["session_identity_refused"]);
    for _ in 0..50 {
        host.tick();
        thread::sleep(Duration::from_millis(2));
    }
    assert_eq!((host.cancels, host.applied, host.swaps), (1, 1, 0));
    assert!(host.stop().is_some());
    assert!(!store_locked(&tree.identity_dir()));
}
