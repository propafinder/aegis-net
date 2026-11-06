//! B-06 S17 failure policy: a lost session never ends the tunnel by itself.
//!
//! Installed v13-v16 showed that cancelling the tunnel when a running session
//! sealed let macOS restore the normal default route, so traffic flowed
//! outside the tunnel while the profile read Disconnected (fail-open). Under
//! S17 a recoverable loss keeps the applied network settings, sets the
//! provider's `reasserting` flag and drops every native packet (the sealed
//! bridge passes nothing; only the provider's own bound relay sockets leave),
//! while a fresh session (new claim, bridge, packet engine and ACK) is built
//! with bounded, jittered exponential backoff. A Ready rebuild swaps the
//! packet path without re-applying settings. Only an explicit stop or a
//! terminal custody failure (identity gone or tampered, container custody
//! refused, binding mismatch) or a panicked session cancels the tunnel. A
//! validity miss (certificate expired, clock moved back) or a failure to
//! spawn the rebuild thread is recoverable. There is no automatic give-up:
//! the tunnel stays blocked until the user disconnects. The backoff carries
//! across rebuilds while a swapped-in session has not stayed live for
//! `Schedule::stable`, so a relay that accepts and then drops is not redialled
//! at the first backoff step forever.
//!
//! The principle behind the table: a mid-session miss (lease, relay, channel,
//! engine, Store/ACK revalidation) is recoverable, because the rebuild runs
//! the complete admission again; that admission's own refusals (claim
//! custody, held identity, pinned peer, derived binding) are terminal.
use crate::{
    app_group::{custody_errno, custody_refusal_code},
    policy::{Effect, Lifecycle, Phase},
    provider_session::{SessionHandle, SessionPhase},
};
use std::{
    collections::hash_map::RandomState,
    hash::{BuildHasher, Hasher},
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex, PoisonError,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

/// What a lost session's first refusal code means for the tunnel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Recovery {
    /// Keep the settings, drop packets, rebuild with backoff.
    Recoverable,
    /// Cancel the tunnel exactly once.
    Terminal,
}

use Recovery::{Recoverable, Terminal};

/// Every refusal code a provider session, its body or the provider's packet
/// path can record, and its recovery. Claim-capture (custody) refusals are
/// classified where the claim is captured: always terminal.
pub(crate) const REFUSALS: &[(&str, Recovery)] = &[
    // Lease and re-ACK: the relay refused, timed out or was unreachable.
    ("capture_lease_expired", Recoverable),
    ("session_ack_refused", Recoverable),
    ("session_ack_too_short", Recoverable),
    ("session_lease_refused", Recoverable),
    ("session_connect_failed", Recoverable),
    // v40 (CP-D3 M1): the open session's carrier pin failed its later dials
    // before authentication: the rebuild plans the pool again.
    ("carrier_unavailable", Recoverable),
    ("session_clock_failed", Recoverable),
    ("relay_interface_unresolved", Recoverable),
    // S18: the physical path changed and the epoch was re-pinned.
    ("relay_path_changed", Recoverable),
    // Mid-session Store/ACK revalidation miss: the rebuild's own admission
    // re-checks custody, identity and binding and is terminal on tampering.
    ("store_revalidation_failed", Recoverable),
    ("session_packet_config_refused", Recoverable),
    ("session_services_refused", Recoverable),
    // Relay channel, engine and monitor ends.
    ("session_packet_terminal", Recoverable),
    ("session_monitor_ended", Recoverable),
    ("session_monitor_failed", Recoverable),
    ("session_engine_spawn_failed", Recoverable),
    ("session_engine_failed", Recoverable),
    ("session_engine_timeout", Recoverable),
    ("session_engine_not_ready", Recoverable),
    ("session_runtime_failed", Recoverable),
    ("session_spawn_failed", Recoverable),
    ("session_worker_refused", Recoverable),
    ("session_ended", Recoverable),
    ("session_rebuild_timeout", Recoverable),
    // The rebuild thread could not be spawned: retried from the drain timer.
    ("session_rebuild_spawn_failed", Recoverable),
    // Admission refused outside the epoch's admitted validity window: a
    // clock moved back before that admission, never tampering. Blocked
    // until the clock is right again or the user disconnects.
    ("session_identity_not_current", Recoverable),
    // S23: the admitted (or held) certificate has expired. Blocked until a
    // new identity is imported, the clock is corrected or the user
    // disconnects; never a cancel.
    ("session_identity_expired", Recoverable),
    // S23 renewal: the running session was sealed for a due renewal, a
    // renewal request is journaled and unanswered (no capture may run
    // beside it), the Store was busy, or the provider stopped the step.
    ("identity_renewal_due", Recoverable),
    ("identity_renewal_pending", Recoverable),
    ("identity_renewal_busy", Recoverable),
    ("identity_renewal_stopped", Recoverable),
    // Provider packet path.
    ("packet_path_not_ready", Recoverable),
    ("packet_io_failed", Recoverable),
    ("native_packet_malformed", Recoverable),
    // Terminal custody: held identity gone or tampered, pinned peer or
    // derived binding mismatch.
    ("session_identity_refused", Terminal),
    ("session_peer_refused", Terminal),
    ("session_peer_mismatch", Terminal),
    ("session_binding_refused", Terminal),
    // A panicked session never joins and keeps the Store for the process:
    // nothing can be rebuilt beside it.
    ("session_panicked", Terminal),
    // The owner itself ended the session: an explicit stop.
    ("provider_stop", Terminal),
    ("session_handle_dropped", Terminal),
];

/// The recovery of one session refusal code. A code outside the table is
/// recoverable: the rebuild re-runs the complete admission, whose terminal
/// refusals are listed. The table-completeness test keeps every emitted code
/// listed.
pub(crate) fn classify(code: &str) -> Recovery {
    REFUSALS
        .iter()
        .find(|(listed, _)| *listed == code)
        .map_or(Recoverable, |(_, recovery)| *recovery)
}

/// The validity window of an epoch's last identity admission: the wall-clock
/// second it was admitted and its certificate's `not_before` and
/// `not_after` (S23 renewal schedules from both ends).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Admitted {
    pub(crate) at: u64,
    pub(crate) not_before: u64,
    pub(crate) not_after: u64,
}

/// The code of a refused identity admission (`code`) in an epoch whose last
/// admission was `admitted`, at wall-clock `now`. At or past its `not_after`
/// the certificate has expired: `session_identity_expired` (S23); before the
/// admission the clock moved back: `session_identity_not_current`. Both are
/// recoverable. An unreadable clock is the recoverable
/// `session_clock_failed`. Inside the window, or before any admission (the
/// first session's start), `code` stands.
pub(crate) fn admission_refusal(
    code: &'static str,
    admitted: Option<Admitted>,
    now: Option<u64>,
) -> &'static str {
    let Some(window) = admitted else {
        return code;
    };
    match now {
        None => "session_clock_failed",
        Some(now) if now >= window.not_after => "session_identity_expired",
        Some(now) if now < window.at => "session_identity_not_current",
        Some(_) => code,
    }
}

/// Resource errnos of a claim capture: transient, never custody evidence.
const RESOURCE_ERRNOS: [i32; 5] = [
    libc::EMFILE,
    libc::ENFILE,
    libc::ENOMEM,
    libc::EAGAIN,
    libc::EINTR,
];

/// A factory refusal: its code and recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Refusal {
    pub(crate) code: &'static str,
    pub(crate) recovery: Recovery,
}

impl Refusal {
    /// A claim that could not be captured: container custody refused or the
    /// held identity gone, terminal. A capture that failed only for want of
    /// descriptors, memory or an interrupted call is recoverable.
    pub(crate) fn custody(error: &io::Error) -> Self {
        let exhausted = custody_errno(error).is_some_and(|errno| RESOURCE_ERRNOS.contains(&errno));
        Self {
            code: custody_refusal_code(error),
            recovery: if exhausted { Recoverable } else { Terminal },
        }
    }

    /// A transient construction failure (no thread could be spawned).
    pub(crate) fn transient(code: &'static str) -> Self {
        Self {
            code,
            recovery: Recoverable,
        }
    }
}

/// Bounded exponential backoff between rebuild attempts, the longest a
/// rebuilt session may stay Constructing before it is sealed and retried, and
/// how long a swapped-in session must stay live before the backoff restarts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Schedule {
    pub(crate) first: Duration,
    pub(crate) cap: Duration,
    pub(crate) construct: Duration,
    pub(crate) stable: Duration,
}

/// 0.5 s doubling to 8 s, each delay jittered within its upper half; the
/// backoff restarts only after a rebuilt session stayed live for 30 s.
pub(crate) const PRODUCTION: Schedule = Schedule {
    first: Duration::from_millis(500),
    cap: Duration::from_secs(8),
    construct: Duration::from_secs(10),
    stable: Duration::from_secs(30),
};

impl Schedule {
    /// The nominal delay before attempt `attempt` (1-based): `first`
    /// doubling, never above `cap`.
    pub(crate) fn nominal(&self, attempt: u32) -> Duration {
        let doublings = attempt.saturating_sub(1).min(16);
        self.first.saturating_mul(1 << doublings).min(self.cap)
    }

    /// The jittered delay before attempt `attempt`: within the nominal
    /// delay's upper half, so it is never shorter than half of `first`.
    pub(crate) fn delay(&self, attempt: u32, jitter: u64) -> Duration {
        let nominal = self.nominal(attempt);
        let half = nominal / 2;
        let span = u64::try_from((nominal - half).as_micros()).unwrap_or(u64::MAX);
        half + Duration::from_micros(jitter % span.saturating_add(1))
    }
}

/// A randomly keyed hash of the attempt number: no new dependency, and two
/// providers never share a jitter sequence.
fn jitter(attempt: u32) -> u64 {
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u32(attempt);
    hasher.finish()
}

/// How one rebuild ended.
pub(crate) enum RebuildOutcome {
    /// A fresh session reached Ready after `attempts` attempts.
    Rebuilt {
        session: SessionHandle,
        attempts: u32,
    },
    /// A terminal refusal: the tunnel is cancelled once. A rebuilt session
    /// that unwound never joins: it is retained here for the stop path.
    Terminal(&'static str, Option<SessionHandle>),
    /// Stopped by the provider; every session it owned has joined.
    Stopped,
}

/// Test-visible rebuild steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RebuildEvent {
    OldJoined,
    Backoff { attempt: u32, delay: Duration },
    Spawned { attempt: u32 },
    Ended { attempt: u32, code: &'static str },
}

pub(crate) type RebuildTrace = Arc<dyn Fn(RebuildEvent) + Send + Sync>;
pub(crate) type SessionNotifier = Box<dyn FnOnce(SessionPhase) + Send>;
/// Builds one fresh session: a new claim, bridge, packet engine and ACK. The
/// probe reports a provider stop, so a step before the capture (the S23
/// renewal) never delays the stop beyond its own poll.
pub(crate) type RebuildFactory =
    Box<dyn FnMut(SessionNotifier, &dyn Fn() -> bool) -> Result<SessionHandle, Refusal> + Send>;

struct Shared {
    stop: AtomicBool,
    signal: Mutex<u64>,
    wake: Condvar,
}

impl Shared {
    fn stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    fn notify(&self) {
        *self.signal.lock().unwrap_or_else(PoisonError::into_inner) += 1;
        self.wake.notify_all();
    }

    /// Wait up to `budget`; with `early`, also return on any signal. A late
    /// session notification never shortens a backoff. True once stopped.
    fn wait(&self, budget: Duration, early: bool) -> bool {
        let deadline = Instant::now() + budget;
        let mut signal = self.signal.lock().unwrap_or_else(PoisonError::into_inner);
        let seen = *signal;
        loop {
            if self.stopped() {
                return true;
            }
            let now = Instant::now();
            if now >= deadline || (early && *signal != seen) {
                return false;
            }
            signal = self
                .wake
                .wait_timeout(signal, deadline - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }
}

const JOIN_POLL: Duration = Duration::from_millis(10);
const CONSTRUCT_POLL: Duration = Duration::from_millis(5);

/// Seal and wait for `session` without a budget: the rebuild thread, like the
/// session supervisor, never lets go of an unjoined session. False once the
/// session body has unwound: it never joins, and the caller retains it.
fn join_owned(session: &mut SessionHandle) -> bool {
    loop {
        if session.try_join(JOIN_POLL) {
            return true;
        }
        if session.unwound() {
            return false;
        }
    }
}

/// Seal and wait for the shared lost session without holding its lock while
/// sleeping, so the provider's own non-blocking join observation never waits.
/// False once it has unwound; the provider retains it.
fn join_shared(session: &Mutex<SessionHandle>) -> bool {
    loop {
        {
            let mut session = session.lock().unwrap_or_else(PoisonError::into_inner);
            if session.try_join(Duration::ZERO) {
                return true;
            }
            if session.unwound() {
                return false;
            }
        }
        thread::sleep(JOIN_POLL);
    }
}

/// One rebuild after one recoverable loss, on its own thread. It first joins
/// the lost session (whose Store claim must be released before a new one is
/// captured), then builds fresh sessions until one is Ready, a terminal
/// refusal arrives or the provider stops it. Every session it built and did
/// not hand over has joined before its outcome is published.
pub(crate) struct Rebuild {
    shared: Arc<Shared>,
    outcome: Arc<Mutex<Option<RebuildOutcome>>>,
    worker: Option<JoinHandle<()>>,
    // A panicked rebuild may have dropped a session unjoined: never terminal.
    panicked: bool,
}

impl Rebuild {
    /// `spent` attempts carried from the epoch's earlier rebuilds: the first
    /// attempt of this one is `spent + 1`, with that attempt's backoff.
    pub(crate) fn spawn(
        lost: Arc<Mutex<SessionHandle>>,
        factory: RebuildFactory,
        schedule: Schedule,
        trace: Option<RebuildTrace>,
        done: Box<dyn FnOnce() + Send>,
        spent: u32,
    ) -> io::Result<Self> {
        let shared = Arc::new(Shared {
            stop: AtomicBool::new(false),
            signal: Mutex::new(0),
            wake: Condvar::new(),
        });
        let outcome = Arc::new(Mutex::new(None));
        let worker = {
            let shared = shared.clone();
            let outcome = outcome.clone();
            thread::Builder::new()
                .name("aegis-ne-rebuild".into())
                .spawn(move || {
                    let ended = run(&shared, &lost, factory, schedule, trace.as_ref(), spent);
                    *outcome.lock().unwrap_or_else(PoisonError::into_inner) = Some(ended);
                    done();
                })?
        };
        Ok(Self {
            shared,
            outcome,
            worker: Some(worker),
            panicked: false,
        })
    }

    /// Request stop: the backoff wait and a Constructing session end at once.
    pub(crate) fn stop(&self) {
        self.shared.stop.store(true, Ordering::Release);
        self.shared.notify();
    }

    /// The rebuild thread has returned (its outcome is published).
    pub(crate) fn finished(&self) -> bool {
        self.worker.as_ref().is_none_or(JoinHandle::is_finished)
    }

    fn reap(&mut self) -> bool {
        if !self.finished() {
            return false;
        }
        if let Some(worker) = self.worker.take() {
            self.panicked |= worker.join().is_err();
        }
        !self.panicked
    }

    /// The published outcome. It is published only once `run` has returned,
    /// so every session the rebuild did not hand over has joined (or is
    /// retained in it); the thread then only posts its one notification and
    /// exits. That notification may be handled before the thread has exited,
    /// so the outcome is never gated on the thread's exit: the stop path or
    /// the drop of this rebuild reaps the thread.
    pub(crate) fn take_outcome(&mut self) -> Option<RebuildOutcome> {
        if self.panicked {
            return None;
        }
        let taken = self
            .outcome
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if taken.is_none() {
            // A rebuild that panicked publishes nothing: never terminal.
            self.reap();
        }
        taken
    }

    fn restore(&mut self, outcome: RebuildOutcome) {
        *self.outcome.lock().unwrap_or_else(PoisonError::into_inner) = Some(outcome);
    }

    /// Stop, then wait up to `budget` for the thread and for any rebuilt
    /// session not yet handed over to join. True only when both have.
    pub(crate) fn seal_and_try_join(&mut self, budget: Duration) -> bool {
        self.stop();
        let deadline = Instant::now() + budget;
        while !self.finished() {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            thread::sleep(JOIN_POLL.min(deadline - now));
        }
        if !self.reap() {
            return false;
        }
        let mut outcome = self.outcome.lock().unwrap_or_else(PoisonError::into_inner);
        match outcome.as_mut() {
            Some(
                RebuildOutcome::Rebuilt { session, .. }
                | RebuildOutcome::Terminal(_, Some(session)),
            ) => session.try_join(deadline.saturating_duration_since(Instant::now())),
            _ => true,
        }
    }
}

impl Drop for Rebuild {
    fn drop(&mut self) {
        // Never joins: a detached rebuild still joins what it owns.
        self.stop();
    }
}

fn run(
    shared: &Arc<Shared>,
    lost: &Mutex<SessionHandle>,
    mut factory: RebuildFactory,
    schedule: Schedule,
    trace: Option<&RebuildTrace>,
    spent: u32,
) -> RebuildOutcome {
    let mark = |event| {
        if let Some(trace) = trace {
            trace(event);
        }
    };
    // The lost session's Store claim is released only by its join. One that
    // unwound keeps the Store for the process: nothing can be built beside
    // it, and the provider (which retains it) cancels once.
    if !join_shared(lost) {
        crate::apple::log_code("session_rebuild_refused", "session_panicked");
        return RebuildOutcome::Terminal("session_panicked", None);
    }
    mark(RebuildEvent::OldJoined);
    let mut attempt: u32 = spent;
    loop {
        attempt = attempt.saturating_add(1);
        let delay = schedule.delay(attempt, jitter(attempt));
        crate::apple::log_fields(
            "session_rebuild",
            &[
                &format!("attempt:{attempt}"),
                &format!("backoff_ms:{}", delay.as_millis()),
            ],
        );
        mark(RebuildEvent::Backoff { attempt, delay });
        if shared.wait(delay, false) {
            return RebuildOutcome::Stopped;
        }
        let notified = shared.clone();
        let notifier: SessionNotifier = Box::new(move |_| notified.notify());
        let stopping = || shared.stopped();
        let mut session = match factory(notifier, &stopping) {
            Ok(session) => session,
            Err(refusal) => {
                mark(RebuildEvent::Ended {
                    attempt,
                    code: refusal.code,
                });
                if refusal.recovery == Terminal {
                    return RebuildOutcome::Terminal(refusal.code, None);
                }
                continue;
            }
        };
        mark(RebuildEvent::Spawned { attempt });
        let deadline = Instant::now() + schedule.construct;
        loop {
            if shared.stopped() {
                if join_owned(&mut session) {
                    return RebuildOutcome::Stopped;
                }
                return RebuildOutcome::Terminal("session_panicked", Some(session));
            }
            match session.phase() {
                SessionPhase::Ready => {
                    return RebuildOutcome::Rebuilt {
                        session,
                        attempts: attempt,
                    }
                }
                SessionPhase::Constructing if Instant::now() >= deadline => {
                    session.seal("session_rebuild_timeout");
                    break;
                }
                SessionPhase::Constructing => {
                    shared.wait(CONSTRUCT_POLL, true);
                }
                SessionPhase::Sealed | SessionPhase::Joined => break,
            }
        }
        let joined = join_owned(&mut session);
        // An unwound session never joins: terminal whatever it sealed with.
        let code = match session.refusal() {
            _ if !joined => "session_panicked",
            Some(code) => code,
            None => "session_ended",
        };
        mark(RebuildEvent::Ended { attempt, code });
        crate::apple::log_code("session_rebuild_refused", code);
        if !joined {
            return RebuildOutcome::Terminal(code, Some(session));
        }
        if classify(code) == Terminal {
            return RebuildOutcome::Terminal(code, None);
        }
    }
}

/// The provider's answer to a running session that is no longer live.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Lost {
    /// Keep the settings, set `reasserting`, start one rebuild.
    Reassert,
    /// Fail the epoch (cancel once) with this code.
    Fail(&'static str),
    /// Stale, already reasserting, stopping or not yet running.
    Ignore,
}

/// Judge one lost running session by its first refusal code.
pub(crate) fn session_lost(lifecycle: &mut Lifecycle, generation: u64, code: &'static str) -> Lost {
    if lifecycle.generation != generation || lifecycle.phase != Phase::Running {
        return Lost::Ignore;
    }
    match classify(code) {
        Terminal => Lost::Fail(code),
        Recoverable => match lifecycle.reassert(generation) {
            Ok(Effect::Reassert) => Lost::Reassert,
            _ => Lost::Ignore,
        },
    }
}

/// The provider's answer to a finished rebuild.
pub(crate) enum Finished {
    /// Swap the packet path to this session and clear `reasserting`.
    Swap(SessionHandle, u32),
    /// Fail the epoch (cancel once) with this code.
    Fail(&'static str),
    /// Not finished, stale, stopped or stopping: the stop path joins it.
    Ignore,
}

/// Judge a finished rebuild. Only a Reasserting generation takes its
/// outcome; otherwise the rebuild keeps it for the stop path's join.
pub(crate) fn rebuild_finished(
    lifecycle: &mut Lifecycle,
    generation: u64,
    rebuild: &mut Rebuild,
) -> Finished {
    if lifecycle.generation != generation || lifecycle.phase != Phase::Reasserting {
        return Finished::Ignore;
    }
    match rebuild.take_outcome() {
        Some(RebuildOutcome::Rebuilt { session, attempts }) => {
            match lifecycle.rebuilt(generation) {
                Ok(Effect::Reasserted) => Finished::Swap(session, attempts),
                _ => {
                    rebuild.restore(RebuildOutcome::Rebuilt { session, attempts });
                    Finished::Ignore
                }
            }
        }
        Some(RebuildOutcome::Terminal(code, unjoined)) => {
            // An unwound session stays with the rebuild: the stop path's
            // join of it never succeeds, so the provider exits after its
            // stop budget instead of releasing a Store still held.
            if unjoined.is_some() {
                rebuild.restore(RebuildOutcome::Terminal(code, unjoined));
            }
            Finished::Fail(code)
        }
        Some(RebuildOutcome::Stopped) | None => Finished::Ignore,
    }
}

/// The backoff carried between the rebuilds of one epoch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Carry {
    attempts: u32,
    swapped: Option<Instant>,
}

impl Carry {
    /// The attempts the next rebuild starts after: those of the last swap
    /// while that session has been live for less than `stable`, else none.
    pub(crate) fn spent(&self, now: Instant, stable: Duration) -> u32 {
        match self.swapped {
            Some(at) if now.saturating_duration_since(at) < stable => self.attempts,
            _ => 0,
        }
    }

    pub(crate) fn swapped(&mut self, attempts: u32, now: Instant) {
        self.attempts = attempts;
        self.swapped = Some(now);
    }
}

/// One epoch's rebuild state, kept by the provider beside its session: the
/// running rebuild, the carried backoff and a pending retry of a rebuild
/// thread that could not be spawned.
#[derive(Default)]
pub(crate) struct Rebuilds {
    pub(crate) current: Option<Arc<Mutex<Rebuild>>>,
    carry: Carry,
    // A failed spawn: retried no earlier than `due`, after `failures` fails.
    respawn: Option<(Instant, u32)>,
}

impl Rebuilds {
    /// Start one rebuild with `spawn`, given the carried attempts. A spawn
    /// failure keeps the epoch reasserting (fail closed) and schedules a
    /// retry with the same bounded backoff; nothing is cancelled.
    pub(crate) fn start_with(
        &mut self,
        schedule: Schedule,
        now: Instant,
        spawn: impl FnOnce(u32) -> io::Result<Rebuild>,
    ) -> Result<(), &'static str> {
        match spawn(self.carry.spent(now, schedule.stable)) {
            Ok(rebuild) => {
                self.current = Some(Arc::new(Mutex::new(rebuild)));
                self.respawn = None;
                Ok(())
            }
            Err(_) => {
                let failures = self.respawn.map_or(1, |(_, n)| n.saturating_add(1));
                let due = now + schedule.delay(failures, jitter(failures));
                self.respawn = Some((due, failures));
                Err("session_rebuild_spawn_failed")
            }
        }
    }

    /// No rebuild runs and a failed spawn's retry is due.
    pub(crate) fn respawn_due(&self, now: Instant) -> bool {
        self.current.is_none() && self.respawn.is_some_and(|(due, _)| now >= due)
    }

    /// A rebuilt session took over after `attempts` attempts.
    pub(crate) fn swapped(&mut self, attempts: u32, now: Instant) {
        self.current = None;
        self.respawn = None;
        self.carry.swapped(attempts, now);
    }
}

/// What the native read path does with one batch of packets from the OS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Disposition {
    /// Running on a live session: into its bridge.
    Forward,
    /// Running on a session that is no longer live, or reasserting: drop the
    /// batch and keep reading. Nothing reaches the relay or the OS.
    Drop,
    /// Another generation or phase: stop reading.
    Stale,
}

pub(crate) fn native_packets(phase: Phase, live: bool) -> Disposition {
    match phase {
        Phase::Running if live => Disposition::Forward,
        Phase::Running | Phase::Reasserting => Disposition::Drop,
        _ => Disposition::Stale,
    }
}

#[cfg(test)]
#[path = "session_rebuild_tests.rs"]
mod tests;
