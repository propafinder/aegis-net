//! Provider-visible handle for one composite session.
//!
//! The session thread owns the protected Store claim, the authenticated relay
//! channel and the packet engine. Native packetFlow callbacks see only the
//! leased bridge and an atomic phase, so the per-packet path performs no Store
//! or filesystem I/O. Store revalidation, re-ACK and lease renewal belong to the
//! session body, which seals the bridge when any of them fails.
use crate::bridge::LeasedPacketBridge;
use std::{
    io,
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const MAX_JOIN_BUDGET: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum SessionPhase {
    Constructing = 0,
    Ready = 1,
    Sealed = 2,
    // The session body has returned: every child it owned, and the Store claim,
    // are released. Only this phase permits dropping the handle as terminal.
    Joined = 3,
}

impl SessionPhase {
    fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Constructing,
            1 => Self::Ready,
            2 => Self::Sealed,
            _ => Self::Joined,
        }
    }
}

type Notifier = Box<dyn FnOnce(SessionPhase) + Send>;

/// Phase and first refusal code of one session. Shared with the diagnostics
/// reader, which outlives the session: it holds only this atomic and one
/// `&'static str`, never the bridge, notifier, Store claim or session thread.
struct SessionRecord {
    phase: AtomicU8,
    // Sealing records the code and leaves Ready under this lock, so a reader
    // holding it never sees a refusal beside Ready or Sealed without one.
    refusal: Mutex<Option<&'static str>>,
    // The session body unwound: it can never reach Joined (S17).
    unwound: AtomicBool,
}

impl SessionRecord {
    fn phase(&self) -> SessionPhase {
        SessionPhase::from_u8(self.phase.load(Ordering::Acquire))
    }

    fn refusal(&self) -> std::sync::MutexGuard<'_, Option<&'static str>> {
        self.refusal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

struct SessionShared {
    record: Arc<SessionRecord>,
    stop: AtomicBool,
    // S18: one pending forced re-ACK (after a wake), consumed by the next
    // attempt the monitor starts, and the monitor's wake-up for it.
    reack: AtomicBool,
    reack_signal: tokio::sync::Notify,
    // Fired exactly once, on the first transition out of Constructing. The
    // provider uses it to post Ready or Sealed to the main runloop.
    notifier: Mutex<Option<Notifier>>,
}

impl SessionShared {
    fn phase(&self) -> SessionPhase {
        self.record.phase()
    }

    fn notify(&self, phase: SessionPhase) {
        let notifier = self
            .notifier
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(notifier) = notifier {
            notifier(phase);
        }
    }

    fn seal(&self, bridge: &LeasedPacketBridge, code: &'static str) {
        self.stop.store(true, Ordering::Release);
        bridge.stop();
        let sealed = {
            let mut refusal = self.record.refusal();
            refusal.get_or_insert(code);
            self.record
                .phase
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    match SessionPhase::from_u8(current) {
                        SessionPhase::Constructing | SessionPhase::Ready => {
                            Some(SessionPhase::Sealed as u8)
                        }
                        SessionPhase::Sealed | SessionPhase::Joined => None,
                    }
                })
                .is_ok()
        };
        if sealed {
            self.notify(SessionPhase::Sealed);
        }
    }
}

/// Cheap clone used by native callbacks. It cannot join or drop the session.
#[derive(Clone)]
pub(crate) struct SessionProbe {
    shared: Arc<SessionShared>,
    bridge: LeasedPacketBridge,
}

impl SessionProbe {
    /// Ready phase and a live bridge lease. Atomics and one clock read only;
    /// an expired lease seals the session.
    pub(crate) fn ready(&self) -> bool {
        if self.shared.phase() != SessionPhase::Ready {
            return false;
        }
        if self.bridge.probe_lease().is_err() {
            // A bridge the packet side sealed mid-lease has not expired.
            let code = if self.bridge.lease_elapsed() {
                "capture_lease_expired"
            } else {
                "session_packet_terminal"
            };
            self.shared.seal(&self.bridge, code);
            return false;
        }
        true
    }

    pub(crate) fn seal(&self, code: &'static str) {
        self.shared.seal(&self.bridge, code);
    }

    /// S18: ask the session's monitor for one re-ACK as soon as the attempt
    /// spacing allows, ahead of its lease schedule. Requests made before the
    /// monitor starts that attempt coalesce into it.
    pub(crate) fn request_reack(&self) {
        self.shared.reack.store(true, Ordering::Release);
        self.shared.reack_signal.notify_one();
    }

    /// A forced re-ACK is pending.
    pub(crate) fn reack_requested(&self) -> bool {
        self.shared.reack.load(Ordering::Acquire)
    }

    /// Consume the pending forced re-ACK: true at most once per request.
    pub(crate) fn take_reack(&self) -> bool {
        self.shared.reack.swap(false, Ordering::AcqRel)
    }

    /// Completes once a re-ACK has been requested (a stored permit).
    pub(crate) async fn reack_signalled(&self) {
        self.shared.reack_signal.notified().await;
    }

    pub(crate) fn bridge(&self) -> &LeasedPacketBridge {
        &self.bridge
    }

    /// The session's phase alone; an atomic load, no lease probe.
    pub(crate) fn phase(&self) -> SessionPhase {
        self.shared.phase()
    }

    /// A diagnostics observer that holds only the session's phase record:
    /// neither the bridge nor the session. It keeps reporting the last phase
    /// and first refusal after every owner is gone.
    pub(crate) fn phase_reader(&self) -> SessionPhaseReader {
        SessionPhaseReader(self.shared.record.clone())
    }
}

/// Read-only view of one session's phase and first refusal code. It never
/// seals, probes the lease, joins or keeps the session, its bridge or its
/// Store claim alive. Every owner seals on drop, so a session whose owners
/// are gone reads as Sealed (a detached body) or Joined, with its code.
#[derive(Clone)]
pub(crate) struct SessionPhaseReader(Arc<SessionRecord>);

impl SessionPhaseReader {
    /// Phase and first refusal, taken together under the refusal lock.
    pub(crate) fn snapshot(&self) -> (SessionPhase, Option<&'static str>) {
        let refusal = self.0.refusal();
        (self.0.phase(), *refusal)
    }
}

/// Passed to the session body. The body marks the session Ready once its
/// authenticated relay lease and packet engine are live, polls `stop_requested`
/// and seals on any failure. A clone may move to the body's own Store worker.
#[derive(Clone)]
pub(crate) struct SessionControl {
    probe: SessionProbe,
}

impl SessionControl {
    pub(crate) fn mark_ready(&self) -> bool {
        let ready = self
            .probe
            .shared
            .record
            .phase
            .compare_exchange(
                SessionPhase::Constructing as u8,
                SessionPhase::Ready as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok();
        if ready {
            self.probe.shared.notify(SessionPhase::Ready);
        }
        ready
    }

    pub(crate) fn stop_requested(&self) -> bool {
        self.probe.shared.stop.load(Ordering::Acquire)
    }

    pub(crate) fn seal(&self, code: &'static str) {
        self.probe.seal(code);
    }

    pub(crate) fn bridge(&self) -> &LeasedPacketBridge {
        self.probe.bridge()
    }

    pub(crate) fn probe(&self) -> SessionProbe {
        self.probe.clone()
    }
}

// Owned by the session thread outside the body. A body that returns has, by
// contract, joined every child it owned before releasing its Store claim, so
// the session is Joined. An unwinding body has only *dropped* its owners, and
// owner Drop detaches unfinished threads rather than joining them, so a panic
// leaves the session Sealed: the handle is retained and never reports terminal.
struct SealThenJoinOnExit {
    shared: Arc<SessionShared>,
    bridge: LeasedPacketBridge,
    outcome: Option<&'static str>,
}

impl Drop for SealThenJoinOnExit {
    fn drop(&mut self) {
        if thread::panicking() {
            self.shared.record.unwound.store(true, Ordering::Release);
            self.shared.seal(&self.bridge, "session_panicked");
            return;
        }
        self.shared
            .seal(&self.bridge, self.outcome.unwrap_or("session_ended"));
        self.shared
            .record
            .phase
            .store(SessionPhase::Joined as u8, Ordering::Release);
    }
}

#[must_use = "retain the session until try_join reports Joined"]
pub(crate) struct SessionHandle {
    probe: SessionProbe,
    worker: Option<JoinHandle<()>>,
}

impl SessionHandle {
    pub(crate) fn spawn<F>(
        bridge: LeasedPacketBridge,
        notifier: impl FnOnce(SessionPhase) + Send + 'static,
        body: F,
    ) -> io::Result<Self>
    where
        F: FnOnce(&SessionControl) -> Result<(), &'static str> + Send + 'static,
    {
        let shared = Arc::new(SessionShared {
            record: Arc::new(SessionRecord {
                phase: AtomicU8::new(SessionPhase::Constructing as u8),
                refusal: Mutex::new(None),
                unwound: AtomicBool::new(false),
            }),
            stop: AtomicBool::new(false),
            reack: AtomicBool::new(false),
            reack_signal: tokio::sync::Notify::new(),
            notifier: Mutex::new(Some(Box::new(notifier))),
        });
        let probe = SessionProbe {
            shared: shared.clone(),
            bridge: bridge.clone(),
        };
        let control = SessionControl {
            probe: probe.clone(),
        };
        let spawned = thread::Builder::new()
            .name("aegis-ne-session".into())
            .spawn(move || {
                let mut exit = SealThenJoinOnExit {
                    shared,
                    bridge,
                    outcome: None,
                };
                exit.outcome = Some(match body(&control) {
                    Ok(()) => "session_ended",
                    Err(code) => code,
                });
            });
        match spawned {
            Ok(worker) => Ok(Self {
                probe,
                worker: Some(worker),
            }),
            Err(error) => {
                // No thread exists, so nothing is owned beyond the bridge.
                probe.seal("session_spawn_failed");
                probe
                    .shared
                    .record
                    .phase
                    .store(SessionPhase::Joined as u8, Ordering::Release);
                Err(error)
            }
        }
    }

    pub(crate) fn probe(&self) -> SessionProbe {
        self.probe.clone()
    }

    pub(crate) fn phase(&self) -> SessionPhase {
        self.probe.shared.phase()
    }

    pub(crate) fn refusal(&self) -> Option<&'static str> {
        *self.probe.shared.record.refusal()
    }

    /// The session body unwound: it stays Sealed and never joins, so a
    /// caller waiting for its join stops waiting and retains the handle.
    pub(crate) fn unwound(&self) -> bool {
        self.probe.shared.record.unwound.load(Ordering::Acquire)
    }

    /// The session thread has returned or unwound. Test-only observation;
    /// it never joins, and only Joined permits treating the session as gone.
    #[cfg(test)]
    pub(crate) fn body_finished(&self) -> bool {
        self.worker.as_ref().is_none_or(JoinHandle::is_finished)
    }

    pub(crate) fn seal(&self, code: &'static str) {
        self.probe.seal(code);
        if let Some(worker) = &self.worker {
            worker.thread().unpark();
        }
    }

    /// Seal, then wait up to `budget` for the session body to finish. True only
    /// once the body has returned and its thread is joined. A live worker is
    /// never dropped or detached by this call.
    pub(crate) fn try_join(&mut self, budget: Duration) -> bool {
        self.seal("provider_stop");
        let budget = budget.min(MAX_JOIN_BUDGET);
        let deadline = Instant::now() + budget;
        loop {
            let finished = self.worker.as_ref().is_none_or(JoinHandle::is_finished);
            if finished && self.phase() == SessionPhase::Joined {
                if let Some(worker) = self.worker.take() {
                    // Joined is published only on a normal return, so the
                    // thread exits without a panic payload.
                    if worker.join().is_err() {
                        return false;
                    }
                }
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(1).min(deadline - now));
        }
    }
}

impl Drop for SessionHandle {
    fn drop(&mut self) {
        // Never joins: a dropped handle only requests stop and revokes the
        // lease, so a detached body cannot keep renewing it.
        self.seal("session_handle_dropped");
    }
}

/// Converts an authenticated ACK validity into a bridge-clock deadline. The
/// bridge clock is CLOCK_MONOTONIC_RAW, read when the request was sent, so the
/// lease can never outlive the server's grant measured from that point.
pub(crate) fn lease_deadline_ns(
    mono_at_request_ns: u64,
    valid_for: Duration,
    margin: Duration,
) -> Option<u64> {
    let usable = valid_for.checked_sub(margin)?;
    if usable.is_zero() {
        return None;
    }
    mono_at_request_ns.checked_add(u64::try_from(usable.as_nanos()).ok()?)
}

// Continuous re-ACK of the composite session body against the test relay.
#[cfg(test)]
#[path = "provider_session_reack_tests.rs"]
mod reack;

// Armed relay services inside the composite session body (S06).
#[cfg(test)]
#[path = "provider_session_relay_tests.rs"]
pub(crate) mod relay;

// S16l: the persistent ACK connection inside the composite session body.
#[cfg(test)]
#[path = "provider_session_link_tests.rs"]
mod link;

// v40 (CP-D3 M1): carrier failover over the signed pool's pins.
#[cfg(test)]
#[path = "provider_session_carrier_tests.rs"]
mod carrier;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::PacketBridge;
    use aegis_client::capture_lease_gate::CaptureLeaseDeadline;
    use std::sync::{atomic::AtomicU64, mpsc};

    fn frame() -> Vec<u8> {
        let mut p = vec![0; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&20u16.to_be_bytes());
        p
    }

    fn leased(now: Arc<AtomicU64>) -> (LeasedPacketBridge, CaptureLeaseDeadline) {
        let deadline = CaptureLeaseDeadline::default();
        let bridge =
            LeasedPacketBridge::with_clock(PacketBridge::default(), deadline.clone(), move || {
                Ok(now.load(Ordering::SeqCst))
            });
        (bridge, deadline)
    }

    fn wait_for(budget: Duration, mut done: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + budget;
        while Instant::now() < deadline {
            if done() {
                return true;
            }
            thread::sleep(Duration::from_millis(1));
        }
        done()
    }

    // Marks Ready, then waits for stop like a real session body.
    fn ready_then_wait(control: &SessionControl) -> Result<(), &'static str> {
        control.mark_ready();
        while !control.stop_requested() {
            thread::park_timeout(Duration::from_millis(5));
        }
        Ok(())
    }

    #[test]
    fn ready_false_after_seal() {
        let now = Arc::new(AtomicU64::new(10));
        let (bridge, deadline) = leased(now);
        deadline.replace(Some(1_000)).unwrap();
        let (tx, rx) = mpsc::channel();
        let mut session = SessionHandle::spawn(
            bridge,
            move |phase| tx.send(phase).unwrap(),
            ready_then_wait,
        )
        .unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            SessionPhase::Ready
        );
        let probe = session.probe();
        assert!(probe.ready());
        probe.bridge().from_os(&frame()).unwrap();
        session.seal("fixture_seal");
        assert!(!probe.ready());
        assert!(probe.bridge().from_os(&frame()).is_err());
        assert_eq!(session.refusal(), Some("fixture_seal"));
        assert!(session.try_join(Duration::from_secs(1)));
        assert_eq!(session.phase(), SessionPhase::Joined);
        // The notifier fires once: Ready, never a later Sealed.
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn expired_lease_seals_on_probe() {
        let now = Arc::new(AtomicU64::new(10));
        let (bridge, deadline) = leased(now.clone());
        deadline.replace(Some(100)).unwrap();
        let mut session = SessionHandle::spawn(bridge, |_| {}, ready_then_wait).unwrap();
        let probe = session.probe();
        assert!(wait_for(Duration::from_secs(2), || probe.ready()));
        now.store(100, Ordering::SeqCst);
        assert!(!probe.ready());
        assert_eq!(session.refusal(), Some("capture_lease_expired"));
        assert!(session.try_join(Duration::from_secs(1)));
    }

    #[test]
    fn packet_side_seal_mid_lease_is_not_reported_as_expiry() {
        let now = Arc::new(AtomicU64::new(10));
        let (bridge, _deadline) = leased(now.clone());
        bridge.grant_until(1_000).unwrap();
        let mut session = SessionHandle::spawn(bridge, |_| {}, ready_then_wait).unwrap();
        let probe = session.probe();
        assert!(wait_for(Duration::from_secs(2), || probe.ready()));
        // The packet engine stops its bridge clone, as its worker does on exit.
        probe.bridge().stop();
        assert!(!probe.ready());
        assert_eq!(session.refusal(), Some("session_packet_terminal"));
        assert!(probe.bridge().from_os(&frame()).is_err());
        assert!(session.try_join(Duration::from_secs(1)));

        // A sealed bridge whose granted lease has also elapsed is an expiry.
        let now = Arc::new(AtomicU64::new(10));
        let (bridge, _deadline) = leased(now.clone());
        bridge.grant_until(100).unwrap();
        let mut session = SessionHandle::spawn(bridge, |_| {}, ready_then_wait).unwrap();
        let probe = session.probe();
        assert!(wait_for(Duration::from_secs(2), || probe.ready()));
        probe.bridge().stop();
        now.store(100, Ordering::SeqCst);
        assert!(!probe.ready());
        assert_eq!(session.refusal(), Some("capture_lease_expired"));
        assert!(session.try_join(Duration::from_secs(1)));

        // A granted lease reaching its end, unsealed, is still an expiry.
        let now = Arc::new(AtomicU64::new(10));
        let (bridge, _deadline) = leased(now.clone());
        bridge.grant_until(100).unwrap();
        let mut session = SessionHandle::spawn(bridge, |_| {}, ready_then_wait).unwrap();
        let probe = session.probe();
        assert!(wait_for(Duration::from_secs(2), || probe.ready()));
        now.store(100, Ordering::SeqCst);
        assert!(!probe.ready());
        assert_eq!(session.refusal(), Some("capture_lease_expired"));
        assert!(probe.bridge().refreshable_deadline().current().is_none());
        assert!(session.try_join(Duration::from_secs(1)));
    }

    #[test]
    fn packet_path_never_waits_for_the_join_lock() {
        let now = Arc::new(AtomicU64::new(10));
        let (bridge, deadline) = leased(now);
        deadline.replace(Some(1_000)).unwrap();
        let session = Arc::new(Mutex::new(
            SessionHandle::spawn(bridge, |_| {}, ready_then_wait).unwrap(),
        ));
        let probe = session.lock().unwrap().probe();
        assert!(wait_for(Duration::from_secs(2), || probe.ready()));
        // Hold the join-side lock on another thread for the whole packet run.
        let (held_tx, held_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let holder = {
            let session = session.clone();
            thread::spawn(move || {
                let _guard = session.lock().unwrap();
                held_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            })
        };
        held_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        for _ in 0..1000 {
            assert!(probe.ready());
            probe.bridge().from_os(&frame()).unwrap();
            assert_eq!(probe.bridge().engine_receive().unwrap(), Some(frame()));
        }
        release_tx.send(()).unwrap();
        holder.join().unwrap();
        assert!(session.lock().unwrap().try_join(Duration::from_secs(1)));
    }

    #[test]
    fn lease_deadline_bounds() {
        let margin = Duration::from_millis(250);
        assert_eq!(
            lease_deadline_ns(1_000, Duration::from_millis(3_000), margin),
            Some(1_000 + 2_750_000_000)
        );
        for valid_ms in [0, 100, 250] {
            assert_eq!(
                lease_deadline_ns(1_000, Duration::from_millis(valid_ms), margin),
                None
            );
        }
        for request in [0, 7, 1_000_000_000_000] {
            for valid_ms in [251, 1_000, 3_000] {
                let valid = Duration::from_millis(valid_ms);
                let deadline = lease_deadline_ns(request, valid, margin).unwrap();
                assert!(deadline > request);
                assert!(deadline <= request + valid.as_nanos() as u64);
            }
        }
        assert_eq!(
            lease_deadline_ns(u64::MAX - 1, Duration::from_secs(3), margin),
            None
        );
    }

    #[test]
    fn seal_and_join_waits_for_worker_return() {
        let now = Arc::new(AtomicU64::new(10));
        let (bridge, deadline) = leased(now);
        deadline.replace(Some(1_000)).unwrap();
        let mut session = SessionHandle::spawn(
            bridge,
            |_| {},
            |control| {
                control.mark_ready();
                while !control.stop_requested() {
                    thread::park_timeout(Duration::from_millis(5));
                }
                // Simulates releasing the Store and joining the engine.
                thread::sleep(Duration::from_millis(300));
                Ok(())
            },
        )
        .unwrap();
        let probe = session.probe();
        assert!(wait_for(Duration::from_secs(2), || probe.ready()));
        assert!(!session.try_join(Duration::ZERO));
        assert_eq!(session.phase(), SessionPhase::Sealed);
        assert!(!probe.ready());
        assert!(session.try_join(Duration::from_secs(2)));
        assert_eq!(session.phase(), SessionPhase::Joined);
    }

    #[test]
    fn worker_panic_seals_within_300ms_and_is_never_terminal() {
        let now = Arc::new(AtomicU64::new(10));
        let (bridge, deadline) = leased(now);
        deadline.replace(Some(1_000)).unwrap();
        let (tx, rx) = mpsc::channel();
        let mut session = SessionHandle::spawn(
            bridge,
            move |phase| tx.send(phase).unwrap(),
            |control| {
                control.mark_ready();
                thread::sleep(Duration::from_millis(20));
                panic!("fixture session panic");
            },
        )
        .unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            SessionPhase::Ready
        );
        let probe = session.probe();
        let started = Instant::now();
        assert!(wait_for(Duration::from_millis(300), || {
            session.refusal() == Some("session_panicked")
        }));
        assert!(started.elapsed() <= Duration::from_millis(300));
        assert!(!probe.ready());
        assert!(probe.bridge().from_os(&frame()).is_err());
        // Unwinding dropped, but did not join, whatever the body owned.
        assert!(!session.try_join(Duration::from_millis(200)));
        assert_eq!(session.phase(), SessionPhase::Sealed);
    }

    #[test]
    fn dropped_handle_requests_stop_and_revokes_lease() {
        let now = Arc::new(AtomicU64::new(10));
        let (bridge, deadline) = leased(now);
        deadline.replace(Some(1_000)).unwrap();
        let (exited_tx, exited_rx) = mpsc::channel();
        let session = SessionHandle::spawn(
            bridge,
            |_| {},
            move |control| {
                let result = ready_then_wait(control);
                exited_tx.send(()).unwrap();
                result
            },
        )
        .unwrap();
        let probe = session.probe();
        assert!(wait_for(Duration::from_secs(2), || probe.ready()));
        drop(session);
        assert!(!probe.ready());
        assert!(probe.bridge().from_os(&frame()).is_err());
        exited_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    }

    #[test]
    fn construction_refusal_notifies_sealed_once() {
        let now = Arc::new(AtomicU64::new(10));
        let (bridge, _deadline) = leased(now);
        let (tx, rx) = mpsc::channel();
        let mut session = SessionHandle::spawn(
            bridge,
            move |phase| tx.send(phase).unwrap(),
            |_| Err("fixture_ack_refused"),
        )
        .unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            SessionPhase::Sealed
        );
        assert!(session.try_join(Duration::from_secs(1)));
        assert_eq!(session.refusal(), Some("fixture_ack_refused"));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn provider_xpc_phase_reader_observes_without_owning_the_session() {
        let now = Arc::new(AtomicU64::new(10));
        let (bridge, deadline) = leased(now);
        deadline.replace(Some(1_000)).unwrap();
        let (tx, rx) = mpsc::channel();
        let mut session = SessionHandle::spawn(
            bridge,
            move |phase| tx.send(phase).unwrap(),
            ready_then_wait,
        )
        .unwrap();
        let probe = session.probe();
        let reader = probe.phase_reader();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            SessionPhase::Ready
        );
        assert_eq!(reader.snapshot(), (SessionPhase::Ready, None));
        assert!(session.try_join(Duration::from_secs(1)));
        assert_eq!(
            reader.snapshot(),
            (SessionPhase::Joined, Some("provider_stop"))
        );
        // The reader holds the record only: once every owner is gone the
        // session is not kept alive, yet its outcome is still reported.
        let shared = Arc::downgrade(&probe.shared);
        drop(probe);
        drop(session);
        assert!(shared.upgrade().is_none());
        assert_eq!(
            reader.snapshot(),
            (SessionPhase::Joined, Some("provider_stop"))
        );
    }

    #[test]
    fn provider_xpc_reader_reports_a_dropped_unjoined_session_as_sealed() {
        let now = Arc::new(AtomicU64::new(10));
        let (bridge, deadline) = leased(now);
        deadline.replace(Some(1_000)).unwrap();
        let (exited_tx, exited_rx) = mpsc::channel();
        let session = SessionHandle::spawn(
            bridge,
            |_| {},
            move |control| {
                let result = ready_then_wait(control);
                exited_tx.send(()).unwrap();
                result
            },
        )
        .unwrap();
        let reader = session.probe().phase_reader();
        assert!(wait_for(Duration::from_secs(2), || reader.snapshot().0
            == SessionPhase::Ready));
        // A dropped handle never joins: the detached body is Sealed, not gone.
        drop(session);
        let (phase, refusal) = reader.snapshot();
        assert_ne!(phase, SessionPhase::Ready);
        assert_eq!(refusal, Some("session_handle_dropped"));
        exited_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(wait_for(Duration::from_secs(2), || reader.snapshot()
            == (SessionPhase::Joined, Some("session_handle_dropped"))));
    }

    #[test]
    fn provider_xpc_reader_snapshot_never_pairs_a_refusal_with_a_live_phase() {
        // Seal races the reader: a code is never seen beside Constructing or
        // Ready, and Sealed or Joined is never seen without one.
        for _ in 0..200 {
            let now = Arc::new(AtomicU64::new(10));
            let (bridge, deadline) = leased(now);
            deadline.replace(Some(1_000)).unwrap();
            let mut session = SessionHandle::spawn(bridge, |_| {}, ready_then_wait).unwrap();
            let reader = session.probe().phase_reader();
            let watcher = thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(2);
                loop {
                    let (phase, refusal) = reader.snapshot();
                    let live = matches!(phase, SessionPhase::Constructing | SessionPhase::Ready);
                    assert_eq!(live, refusal.is_none(), "{phase:?} {refusal:?}");
                    if phase == SessionPhase::Joined || Instant::now() >= deadline {
                        return;
                    }
                }
            });
            session.seal("fixture_seal");
            assert!(session.try_join(Duration::from_secs(1)));
            watcher.join().unwrap();
        }
    }
}
