//! B-06 S23: provider-epoch renewal of the device certificate.
//!
//! The Linux client renews only while ingress is stopped
//! (aegis-client `device_renewal`). The provider maps that onto S17: every
//! session holds the protected Store's lock for its whole life, and any write
//! under `Aegis/identity` changes the generation it holds, so a renewal never
//! runs beside a live session. Instead:
//!
//! 1. The epoch's monitor (`decide`, every `CHECK_INTERVAL` on the main
//!    runloop, no I/O) seals a Running session with `identity_renewal_due`
//!    once two thirds of the admitted lifetime have passed (the library's
//!    rule, `renewal_due_at`) plus a bounded clock-skew margin
//!    (`renewal_attempt_at`), its next attempt is due and no epoch
//!    authentication backoff is in force. The S17 loss policy then keeps the
//!    settings, sets `reasserting` (native packets drop) and rebuilds.
//! 2. Every rebuild, and the provider's start, runs `before_capture` after
//!    the lost session has joined (its Store lock released) and before the
//!    fresh claim: under the provider tree lease and the Store lock it
//!    finishes a saved response, reads the installed window and journal and,
//!    when renewal is due or a request is journaled, runs one bounded
//!    exchange (`renewal_exchange`) on sockets bound to the epoch's pinned
//!    physical interface. The Store update is `renewal_journal`'s.
//! 3. The fresh capture then admits the successor; the next session's ACK
//!    picks it up without a provider restart.
//!
//! Failure keeps the old certificate when no journal is left (traffic
//! resumes; the next attempt waits `backoff_secs`), and refuses the capture
//! with `identity_renewal_pending` while a request is journaled: a capture
//! beside a journal would be the terminal `identity_journal_pending`. An
//! expired certificate refuses with `session_identity_expired` (recoverable,
//! blocked) and is never renewed: only a request journaled before expiry gets
//! bounded receipt recovery. Recovery from expiry is a new import, which the
//! expired gate admits without holding any capture lease; a clock corrected
//! back before the judged `not_after` lifts the gate as well.
//!
//! v31 (S23b), until the renewal transport is decided (option B: the
//! authority behind the relay's own tuple):
//!
//! - **Never beside the armed guard.** While the process leak guard is
//!   armed, no renewal dials a tuple other than the armed relay's
//!   (`leak_guard::Gate::dial_refused`). A renewal that falls due then is
//!   deferred (`deferred:guarded` in `cert-status`, logged once, by the
//!   step or the monitor, whichever sees it first) to the next
//!   provider start, which runs before that start's arm; the monitor never
//!   seals for it. The S20b authority allowance is gone from the filter.
//! - **Never a teardown for a renewal that cannot help.** The monitor
//!   (`judge`) seals only when the renewal could run, the session has been
//!   live for the S17 stable period, and the last failure was not a
//!   transport-class one with no journal (connect timeout, unavailable,
//!   interface unresolved); later attempts ride the next natural rebuild or
//!   provider start. v31 review: that hold ends in the last stretch before
//!   expiry (`transport_hold_ends_at`), where the backoff alone paces the
//!   seals, so a session with no natural rebuild still renews before it
//!   expires. An attempt due within one `CHECK_INTERVAL` runs in a
//!   concurrent rebuild instead of a seal moments later.
//! - **Backoff across epochs.** The provider start's handle carries its
//!   record in process memory, keyed by certificate window and import
//!   generation (`Carry`), so a Connect in the Due window waits out the
//!   backoff instead of adding the exchange before settings every time
//!   (v31 review: not beside a journaled request, whose receipt recovery a
//!   Connect always tries at once); and `cert-status` answers from it while
//!   no epoch runs (v31 review: a saved response finished at a start
//!   replaces the predecessor's record there).
//! - **One connect after a starved step.** When every connect of the last
//!   step timed out, the next step makes one connect attempt, back to
//!   three after any connect succeeded. `connect_timeout` is its own class.
//!   v31 review: a provider stop during a step is no connect timeout and
//!   records no attempt.
//!
//! v32 (S23c), after the 27 October incident (an issued successor shorter
//! than its predecessor, refused at every Connect while the authority had
//! already replaced the device's registry record with it):
//!
//! - **Every local refusal names its check** (`renewal_journal::CHECKS` and
//!   this module's codes): logged on its own line after the unchanged v31
//!   failure line (`state:refused` or `state:superseded attempt:N
//!   check:<code>`) and sent in `cert-status` (`check`, beside
//!   `last_failure` `local_refused` only).
//! - **An issued receipt this client refuses is never parked.** The
//!   authority replays a receipt only while its registry lists that
//!   successor, so the predecessor is no longer the device's record and the
//!   relay refuses it: the request stays the blocking journal, the start is
//!   refused (`identity_renewal_pending`, no relay dial), and the record
//!   keeps `issued` (state `superseded` for a definitive check, else
//!   `pending` with the check). Its receipt recovery is Receipt purpose
//!   only and paced by the carried backoff, not retried at every Connect.
//! - **A request the authority only rejected is parked** (Rejected or
//!   RecoveryRequired, no issued answer seen, outside the skew window; v32
//!   review: and settled, below):
//!   renamed to `online-request.parked.json`, which blocks no capture, so
//!   the installed certificate keeps carrying traffic (state `parked`) and
//!   the relay judges it. A later attempt resumes the parked request id and
//!   renames it back before its first byte (`renewal_journal::unpark`).
//! - **Pacing beside a journal.** A journaled request whose outcome is
//!   unknown keeps v31's retry at the next Connect; a parked one, one with
//!   `issued` and an expired window are paced by the carried backoff
//!   (`EXPIRED_RECOVERY_SECS` once expired), and the expired gate is
//!   carried across epochs under the same import generation and
//!   `not_after` (v32 review: one a definite outcome closed). The carried
//!   record (`issued`, check, gate, settled) is process memory: a provider
//!   restart forgets it.
//! - **A forced renewal the guard defers** runs at the next Connect even
//!   inside the backoff (`next_attempt_at` is cleared).
//!
//! v32 review:
//!
//! - **Only a settled request is parked.** Rejected does not prove the
//!   authority committed nothing (it answers Rejected for every issuer
//!   error, another device's retained issuance among them), so a request
//!   is parked only when every request of it was answered in this process
//!   (`settled`: written fresh in this step, resumed from the parked leaf,
//!   or journaled under this process's watch, and no request lost, timed out
//!   or answered `Unavailable` after its first byte, `Dials::unanswered`). A
//!   request found journaled at a start this process has no record of (a
//!   v31 leftover, a provider restart) is never parked: it stays the
//!   blocking journal, the start is refused, and no relay dial presents a
//!   predecessor the authority may have superseded.
//! - **A rejection paces the journal.** Beside a journaled request whose
//!   last attempt the authority answered Rejected or RecoveryRequired, a
//!   new epoch takes up the carried backoff (not v31's retry at once).
//! - **Only a definite outcome closes the carried expired gate**: nothing
//!   recoverable, a definitive receipt check, or a rejection of a settled
//!   request with no issued answer. A rejection that may be transient
//!   closes the gate for its epoch only (v31); the next Connect is paced by
//!   `EXPIRED_RECOVERY_SECS` and still recovers a committed successor.
//! - **A refused park keeps the authority's class** (`state:failed:rejected`,
//!   then `state:refused attempt:N check:<code>`).
//! - **A superseded request keeps its check**: `cert-status` names the
//!   receipt check while the request keeps its issued answer, and a later
//!   attempt's failure line is followed by `state:superseded`.
//!
//! Logs carry stable tokens only: never a certificate, key, path or address.
use crate::{
    app_group::CapturedRenewalInputs,
    provider_xpc::CertStatusReport as CertStatus,
    relay_socket::RelayInterface,
    renewal_exchange::{Dials, EnrollmentAuthority, Outcome, Resume, ATTEMPTS},
    renewal_journal::{RenewalJournal, BUSY},
    session_rebuild::Refusal,
};
use aegis_core::secure_channel::registry;
use std::{
    io,
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock, PoisonError},
    time::{Duration, Instant},
};

/// The library monitor's interval (`online_renewal_monitor::CHECK_INTERVAL`).
pub(crate) const CHECK_INTERVAL: Duration = Duration::from_secs(5);
/// v31: an attempt due within one check interval runs in the step now (a
/// concurrent rebuild), not after a seal a few seconds later.
pub(crate) const FOLD_SECS: u64 = CHECK_INTERVAL.as_secs();
/// v31: the monitor never seals a session live for less than the S17
/// stable period.
pub(crate) const STABLE: Duration = crate::session_rebuild::PRODUCTION.stable;
/// The longest one renewal step may run, stop polled throughout.
pub(crate) const RENEWAL_BUDGET: Duration = Duration::from_secs(20);
const STOP_POLL: Duration = Duration::from_millis(10);
/// The exchange's own budget ends this long before the step's, so its last
/// attempt reports its own failure class.
const PERFORM_SLACK: Duration = Duration::from_millis(500);
/// Backoff between failed attempts: 60 s doubling to 15 min.
pub(crate) const BACKOFF_FIRST_SECS: u64 = 60;
pub(crate) const BACKOFF_CAP_SECS: u64 = 15 * 60;
/// Receipt recovery of a request journaled before expiry: at most this often.
pub(crate) const EXPIRED_RECOVERY_SECS: u64 = 5 * 60;
/// Clock skew tolerated against the authority: a scheduled attempt starts
/// this long after the due instant (the authority refuses a Renew request
/// before its own clock reaches it), at most a quarter of the remaining
/// lifetime.
pub(crate) const SKEW_MARGIN_SECS: u64 = 60;
/// A fresh authorization refused within the skew margin after the first
/// scheduled attempt is retried this soon, not after the backoff.
pub(crate) const SKEW_RETRY_SECS: u64 = 15;
/// v31 review: the last stretch before `not_after` in which a
/// transport-class failure no longer holds the monitor back. The expiry
/// tears the session down anyway, so a seal for one more attempt can only
/// help (a session with no natural rebuild otherwise expires while the
/// authority is reachable). At most this long, and at most half the time
/// from due to `not_after`.
pub(crate) const LAST_STRETCH_SECS: u64 = 60 * 60;

/// Seal code of a Running session whose renewal is due.
pub(crate) const IDENTITY_RENEWAL_DUE: &str = "identity_renewal_due";
pub(crate) const IDENTITY_RENEWAL_PENDING: &str = "identity_renewal_pending";
pub(crate) const IDENTITY_RENEWAL_STOPPED: &str = "identity_renewal_stopped";
pub(crate) const SESSION_IDENTITY_EXPIRED: &str = "session_identity_expired";
/// v32: the step's runtime could not be built (check, `local_refused`).
pub(crate) const RUNTIME_FAILED: &str = "renewal_runtime_failed";
/// v32: the library's own validator refused the installed successor.
pub(crate) const EXPECTATION_REFUSED: &str = "renewal_expectation_refused";

/// The library's due instant: two thirds of the lifetime after `not_before`
/// (aegis-client `device_identity_online`, exactly `nb + (na - nb) * 2 / 3`).
pub(crate) fn renewal_due_at(not_before: u64, not_after: u64) -> u64 {
    let lifetime = u128::from(not_after.saturating_sub(not_before));
    not_before.saturating_add(u64::try_from(lifetime * 2 / 3).unwrap_or(u64::MAX))
}

/// When a scheduled (not forced) attempt may start: the due instant plus the
/// skew margin, at most a quarter of the time left from due to `not_after`.
pub(crate) fn renewal_attempt_at(not_before: u64, not_after: u64) -> u64 {
    let due = renewal_due_at(not_before, not_after);
    due.saturating_add(SKEW_MARGIN_SECS.min(not_after.saturating_sub(due) / 4))
}

/// v31 review: when the monitor's transport hold ends (`judge`): the start
/// of the last stretch, `LAST_STRETCH_SECS` before `not_after`, at most
/// half the time from due to `not_after`.
pub(crate) fn transport_hold_ends_at(not_before: u64, not_after: u64) -> u64 {
    let due = renewal_due_at(not_before, not_after);
    not_after.saturating_sub(LAST_STRETCH_SECS.min(not_after.saturating_sub(due) / 2))
}

/// Where `now` lies in a certificate's lifetime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Window {
    NotYetValid,
    Valid,
    Due,
    Expired,
}

pub(crate) fn identity_window(now: u64, not_before: u64, not_after: u64) -> Window {
    if now >= not_after {
        Window::Expired
    } else if now < not_before {
        Window::NotYetValid
    } else if now >= renewal_due_at(not_before, not_after) {
        Window::Due
    } else {
        Window::Valid
    }
}

/// A failed attempt's stable class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailureClass {
    /// Busy, Unavailable or a transport failure.
    Unavailable,
    /// v31: a timeout after the TCP connect (outer TLS and H2 carrier,
    /// inner TLS handshake, challenge to response, or an attempt's or the
    /// step's budget once connected): an authority-side fault. Up to v30
    /// it also covered the connect.
    Timeout,
    Rejected,
    RecoveryRequired,
    /// A local Store or journal check refused.
    LocalRefused,
    /// No physical interface reaches the authority.
    InterfaceUnresolved,
    /// v31: the TCP connect never completed within `CONNECT_BUDGET` (or a
    /// budget ended during it): network reachability of the authority.
    ConnectTimeout,
}

impl FailureClass {
    pub(crate) fn token(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Timeout => "timeout",
            Self::Rejected => "rejected",
            Self::RecoveryRequired => "recovery_required",
            Self::LocalRefused => "local_refused",
            Self::InterfaceUnresolved => "interface_unresolved",
            Self::ConnectTimeout => "connect_timeout",
        }
    }

    /// v31: a transport-class failure (the authority was not reached, or
    /// answered only Busy/Unavailable): with no journal, never a reason to
    /// tear down a working session for the next attempt.
    pub(crate) fn is_transport(self) -> bool {
        matches!(
            self,
            Self::ConnectTimeout | Self::Unavailable | Self::InterfaceUnresolved
        )
    }
}

/// The delay before attempt `failures + 1`, after `failures` failed ones.
pub(crate) fn backoff_secs(failures: u32) -> u64 {
    let doublings = failures.saturating_sub(1).min(16);
    BACKOFF_FIRST_SECS
        .saturating_mul(1 << doublings)
        .min(BACKOFF_CAP_SECS)
}

/// v32: where a step left the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Journal {
    /// No request (none written, or the renewal finished).
    None,
    /// A journal leaf (request or response) that blocks the capture.
    Blocking,
    /// A parked request of the installed certificate (no block).
    Parked,
}

/// The last thing the renewal step did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Last {
    None,
    InProgress,
    Failed(FailureClass),
    /// Installed; the next session's ACK has not yet admitted it.
    Renewed,
}

/// One epoch's renewal state, shared by its sessions, its monitor, the
/// rebuild factory and the XPC `cert-status`/`renew` verbs.
#[derive(Clone, Debug)]
pub(crate) struct RenewalState {
    window: Option<(u64, u64)>,
    last: Last,
    pending: bool,
    attempts: u32,
    last_attempt_at: Option<u64>,
    next_attempt_at: u64,
    last_failure: Option<FailureClass>,
    forced: bool,
    // The expired gate: the import generation an expiry was judged under and
    // the `not_after` it was judged against. It stands only while both hold,
    // so a clock corrected back before `not_after` lifts it.
    expired_under: Option<(u64, u64)>,
    // The monitor's last check (main runloop).
    checked: Option<Instant>,
    // v31: a due attempt the armed leak guard forbids (`deferred:guarded`).
    deferred: bool,
    // v31: the first failure of the current failing run.
    failing_since: Option<u64>,
    // v31: every connect of the last step timed out: the next step makes
    // one connect attempt.
    starved: bool,
    // v31: the connect attempts of the last step.
    last_dials: u32,
    // v31: the monitor's last verdict, so a hold is logged once per change.
    hold: Action,
    // v31: the import generation this record was carried in under, and the
    // process carry it is kept in (`RenewalHandle::process`).
    generation: Option<u64>,
    carry: Option<Arc<Carry>>,
    // v32: the local check of the last failure (reported beside
    // `local_refused` only).
    check: Option<&'static str>,
    // v32: a parked request of the installed certificate exists.
    parked: bool,
    // v32: an issued receipt for the journaled request was refused locally,
    // with this check: the request is never parked, and is resumed for its
    // receipt only, paced by the backoff.
    issued: Option<&'static str>,
    // v32 review: every request of the journaled request was answered in
    // this process (none lost, timed out or `Unavailable` after its first
    // byte), so a Rejected answer to it is definite. False for a request
    // found journaled at a start this process has no record of (a v31
    // leftover, a provider restart): such a request is never parked and its
    // rejection never closes a carried expired gate.
    settled: bool,
    // v32 review: the expired gate was closed by a definite outcome (nothing
    // recoverable, a definitive receipt check, or a definite rejection), so
    // it is carried to the next Connect; otherwise it stands for this epoch
    // only and the next Connect is paced by `EXPIRED_RECOVERY_SECS`.
    gate_carried: bool,
}

impl Default for RenewalState {
    fn default() -> Self {
        Self {
            window: None,
            last: Last::None,
            pending: false,
            attempts: 0,
            last_attempt_at: None,
            next_attempt_at: 0,
            last_failure: None,
            forced: false,
            expired_under: None,
            checked: None,
            deferred: false,
            failing_since: None,
            starved: false,
            last_dials: 0,
            hold: Action::None,
            generation: None,
            carry: None,
            check: None,
            parked: false,
            issued: None,
            settled: false,
            gate_carried: false,
        }
    }
}

impl RenewalState {
    /// A session admitted the identity valid over `(not_before, not_after)`.
    /// A different window than the last one is a renewed identity: its
    /// attempt record restarts.
    pub(crate) fn admitted(&mut self, not_before: u64, not_after: u64) {
        if self.window != Some((not_before, not_after)) {
            self.attempts = 0;
            self.next_attempt_at = 0;
            self.last_failure = None;
            self.forced = false;
            self.restart_run();
        }
        if self.last == Last::Renewed || self.window != Some((not_before, not_after)) {
            self.last = Last::None;
        }
        self.window = Some((not_before, not_after));
        self.pending = false;
        self.expired_under = None;
    }

    /// `observed_with` with no parked request (tests).
    #[cfg(test)]
    fn observed(&mut self, not_before: u64, not_after: u64, pending: bool) {
        self.observed_with(not_before, not_after, pending, false);
    }

    /// The step read the installed window and journal: `pending` (a journal
    /// leaf), v32: `parked` (a parked request of this certificate).
    fn observed_with(&mut self, not_before: u64, not_after: u64, pending: bool, parked: bool) {
        if self.window != Some((not_before, not_after)) && self.last != Last::Renewed {
            self.attempts = 0;
            self.next_attempt_at = 0;
            self.last_failure = None;
            self.restart_run();
        }
        self.window = Some((not_before, not_after));
        self.pending = pending;
        self.parked = parked;
        // v32: an issued answer belongs to the journaled request only (v32
        // review: and so does its settled history).
        if !pending {
            self.issued = None;
            self.settled = false;
        }
    }

    /// v31: a new identity window starts with no failing run, no deferral
    /// and the full connect count (v32: and no check, parked request or
    /// issued answer; v32 review: nor a settled request).
    fn restart_run(&mut self) {
        self.failing_since = None;
        self.starved = false;
        self.deferred = false;
        self.check = None;
        self.parked = false;
        self.issued = None;
        self.settled = false;
    }

    /// `failed_at` with a blocking journal or none, and no check (tests).
    #[cfg(test)]
    fn failed(&mut self, now: u64, class: FailureClass, pending: bool) {
        let journal = if pending {
            Journal::Blocking
        } else {
            Journal::None
        };
        self.failed_at(now, class, journal, None);
    }

    /// A failed attempt at `now`: its class, where it left the request and
    /// (v32) the local check that refused, if any.
    fn failed_at(
        &mut self,
        now: u64,
        class: FailureClass,
        journal: Journal,
        check: Option<&'static str>,
    ) {
        self.attempts = self.attempts.saturating_add(1);
        self.last = Last::Failed(class);
        self.last_failure = Some(class);
        self.pending = journal == Journal::Blocking;
        self.parked = journal == Journal::Parked;
        self.check = check;
        self.failing_since.get_or_insert(now);
        let mut next = now.saturating_add(backoff_secs(self.attempts));
        // Never scheduled at or after expiry: one last attempt before it.
        if let Some((_, not_after)) = self.window {
            if next >= not_after {
                next = not_after.saturating_sub(1).max(now.saturating_add(1));
            }
        }
        self.next_attempt_at = next;
    }

    fn renewed(&mut self, not_before: u64, not_after: u64) {
        self.window = Some((not_before, not_after));
        self.last = Last::Renewed;
        self.pending = false;
        self.attempts = 0;
        self.next_attempt_at = 0;
        self.last_failure = None;
        self.expired_under = None;
        self.restart_run();
    }

    /// The stable state token at `now`.
    pub(crate) fn token(&self, now: u64) -> String {
        if self.last == Last::InProgress {
            return "in_progress".into();
        }
        let Some((not_before, not_after)) = self.window else {
            return "unknown".into();
        };
        match identity_window(now, not_before, not_after) {
            Window::Expired => "expired".into(),
            // v32: the authority issued a successor a definitive check
            // refused.
            _ if self.pending && self.issued.is_some_and(crate::renewal_journal::definitive) => {
                "superseded".into()
            }
            _ if self.pending => "pending".into(),
            _ if self.last == Last::Renewed => "renewed_pending_ack".into(),
            // v31: due, and the armed leak guard forbids the dial.
            Window::Due if self.deferred => "deferred:guarded".into(),
            // v32: the installed certificate is captured beside it.
            _ if self.parked => "parked".into(),
            Window::Due => match self.last {
                Last::Failed(class) => format!("failed:{}", class.token()),
                _ => "due".into(),
            },
            Window::NotYetValid => "not_yet_valid".into(),
            Window::Valid => "valid".into(),
        }
    }

    pub(crate) fn report(&self, now: u64) -> CertStatus {
        CertStatus {
            state: self.token(now),
            not_before: self.window.map(|(nb, _)| nb),
            not_after: self.window.map(|(_, na)| na),
            renew_at: self.window.map(|(nb, na)| renewal_due_at(nb, na)),
            attempts: self.attempts,
            last_attempt_at: self.last_attempt_at,
            next_attempt_at: (self.next_attempt_at > 0).then_some(self.next_attempt_at),
            last_failure: self.last_failure.map(|class| class.token().into()),
            failing_since: self.last_failure.and(self.failing_since),
            check: self.reported_check().map(Into::into),
        }
    }

    /// v32 review: the check `cert-status` names. While the journaled
    /// request keeps an issued answer, the receipt check that refused it
    /// (a later attempt's rejection or transport failure does not hide why
    /// the request is superseded); else the last failure's own check: beside
    /// `local_refused`, or beside the authority's answer when the park of a
    /// definite rejection was refused.
    fn reported_check(&self) -> Option<&'static str> {
        self.last_failure?;
        if self.pending && self.issued.is_some() {
            return self.issued;
        }
        self.check
    }

    /// Whether the step may skip all I/O: the window is known and valid,
    /// no scheduled attempt is due (v31: or due within `FOLD_SECS`),
    /// nothing is journaled and no renewal was forced.
    fn quiet(&self, now: u64) -> bool {
        !self.pending
            && !self.forced
            && self.window.is_some_and(|(nb, na)| {
                nb <= now && now.saturating_add(FOLD_SECS) < renewal_attempt_at(nb, na)
            })
    }

    /// v31: take up the process carry's record of this identity window and
    /// import `generation`, once per generation, when this epoch has none
    /// of its own yet (a fresh provider start). v31 review: beside a
    /// journaled request (`pending`, as just observed) its next attempt is
    /// not taken up: a start that waited would be refused
    /// (`identity_renewal_pending`, or `session_identity_expired` before a
    /// receipt-only recovery) with no `--renew` to force it (the refused
    /// start has no epoch), so a Connect always tries its receipt recovery
    /// at once, as up to v30. The attempt count still is, so the backoff
    /// after another failure keeps doubling. v32: that exception holds only
    /// for a journaled request whose outcome is unknown: beside one the
    /// authority already issued for (`issued`), and in the expired window
    /// (`now`), the next attempt is taken up too; and the check, the issued
    /// answer and the expired gate are carried. v32 review: so it is beside
    /// one whose last attempt the authority answered Rejected or
    /// RecoveryRequired (kept journaled because an earlier request of it
    /// went unanswered, or because its park was refused): another attempt at
    /// once would only be refused again. The request's settled history is
    /// carried with it, and only a gate closed by a definite outcome.
    fn carry_in(&mut self, generation: u64, now: u64) {
        let (Some(carry), Some((nb, na))) = (self.carry.clone(), self.window) else {
            return;
        };
        if self.generation == Some(generation) {
            return;
        }
        self.generation = Some(generation);
        let fresh =
            self.attempts == 0 && self.last_attempt_at.is_none() && self.last_failure.is_none();
        let Some(saved) = carry
            .get()
            .filter(|saved| saved.key == (nb, na, generation))
        else {
            return;
        };
        if !fresh {
            return;
        }
        self.attempts = saved.attempts;
        let issued = if self.pending { saved.issued } else { None };
        let answered = matches!(
            saved.last_failure,
            Some(FailureClass::Rejected | FailureClass::RecoveryRequired)
        );
        if !self.pending
            || issued.is_some()
            || answered
            || identity_window(now, nb, na) == Window::Expired
        {
            self.next_attempt_at = saved.next_attempt_at;
        }
        self.issued = issued;
        self.settled = self.pending && saved.settled;
        self.check = saved.check;
        if self.expired_under.is_none() && saved.expired_under.is_some() {
            self.expired_under = saved.expired_under;
            self.gate_carried = true;
        }
        self.last_attempt_at = saved.last_attempt_at;
        self.last_failure = saved.last_failure;
        self.failing_since = saved.failing_since;
        self.starved = saved.starved;
        self.last_dials = saved.last_dials;
        self.deferred = saved.deferred;
        if let (Last::None, Some(class)) = (self.last, saved.last_failure) {
            self.last = Last::Failed(class);
        }
    }

    /// v31: this record as the process carry keeps it, keyed by its window
    /// and generation (`None` without a carry, or before `carry_in` named
    /// the generation).
    fn carried(&self) -> Option<Carried> {
        let (Some(_), Some((nb, na)), Some(generation)) =
            (&self.carry, self.window, self.generation)
        else {
            return None;
        };
        Some(Carried {
            key: (nb, na, generation),
            attempts: self.attempts,
            next_attempt_at: self.next_attempt_at,
            last_attempt_at: self.last_attempt_at,
            last_failure: self.last_failure,
            failing_since: self.failing_since,
            starved: self.starved,
            last_dials: self.last_dials,
            deferred: self.deferred,
            pending: self.pending,
            renewed: self.last == Last::Renewed,
            check: self.check,
            parked: self.parked,
            issued: self.issued,
            settled: self.settled,
            // v32 review: an epoch's own gate is not carried.
            expired_under: self.expired_under.filter(|_| self.gate_carried),
        })
    }

    /// v32: a fresh epoch (no window of its own yet) takes up the process
    /// carry's expired gate of import `generation` before any capture, so
    /// a Connect after an expiry was judged dials and reads nothing (v32
    /// review: only a gate a definite outcome closed is carried).
    fn carry_gate(&mut self, generation: u64) {
        if self.window.is_some() || self.expired_under.is_some() {
            return;
        }
        if let Some(saved) = self
            .carry
            .as_ref()
            .and_then(|carry| carry.get())
            .filter(|saved| saved.key.2 == generation)
        {
            self.expired_under = saved.expired_under;
            self.gate_carried = saved.expired_under.is_some();
        }
    }

    /// Close the expired gate for `generation`: it stands while the clock
    /// stays at or past the observed window's `not_after`. v32 review:
    /// `carried`: a definite outcome closed it, so the next Connect takes
    /// it up; else it stands for this epoch only.
    fn gate_expired(&mut self, generation: u64, carried: bool) {
        if let Some((_, not_after)) = self.window {
            self.expired_under = Some((generation, not_after));
            self.gate_carried = carried;
        }
    }

    /// Whether the expired gate refuses at `now` under `generation`. A gate
    /// of another generation, or whose `not_after` the clock is back before,
    /// is lifted.
    fn gated(&mut self, now: u64, generation: u64) -> bool {
        match self.expired_under {
            Some((judged, not_after)) if judged == generation && now >= not_after => true,
            Some(_) => {
                self.expired_under = None;
                false
            }
            None => false,
        }
    }
}

/// v31: one identity window's renewal record as the process keeps it
/// between epochs (`Carry`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Carried {
    /// `(not_before, not_after, import generation)`.
    pub(crate) key: (u64, u64, u64),
    pub(crate) attempts: u32,
    pub(crate) next_attempt_at: u64,
    pub(crate) last_attempt_at: Option<u64>,
    pub(crate) last_failure: Option<FailureClass>,
    pub(crate) failing_since: Option<u64>,
    pub(crate) starved: bool,
    pub(crate) last_dials: u32,
    pub(crate) deferred: bool,
    pub(crate) pending: bool,
    pub(crate) renewed: bool,
    /// v32: the last failure's check, the parked flag, the issued answer
    /// refused locally and the expired gate (v32 review: only one a definite
    /// outcome closed), and (v32 review) whether every request of the
    /// journaled request was answered in this process.
    pub(crate) check: Option<&'static str>,
    pub(crate) parked: bool,
    pub(crate) issued: Option<&'static str>,
    pub(crate) settled: bool,
    pub(crate) expired_under: Option<(u64, u64)>,
}

impl Carried {
    /// The record as a state, for `cert-status` while no epoch runs.
    fn state(&self) -> RenewalState {
        let (not_before, not_after, generation) = self.key;
        RenewalState {
            window: Some((not_before, not_after)),
            last: match (self.renewed, self.last_failure) {
                (true, _) => Last::Renewed,
                (false, Some(class)) => Last::Failed(class),
                (false, None) => Last::None,
            },
            pending: self.pending,
            attempts: self.attempts,
            last_attempt_at: self.last_attempt_at,
            next_attempt_at: self.next_attempt_at,
            last_failure: self.last_failure,
            deferred: self.deferred,
            failing_since: self.failing_since,
            starved: self.starved,
            last_dials: self.last_dials,
            generation: Some(generation),
            check: self.check,
            parked: self.parked,
            issued: self.issued,
            settled: self.settled,
            expired_under: self.expired_under,
            gate_carried: self.expired_under.is_some(),
            ..RenewalState::default()
        }
    }
}

/// v31: the renewal record kept in process memory across provider epochs:
/// the newest epoch's record of one identity window and import generation.
/// It never outlives the provider process and holds no material.
#[derive(Debug, Default)]
pub(crate) struct Carry(Mutex<Option<Carried>>);

impl Carry {
    pub(crate) fn get(&self) -> Option<Carried> {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn set(&self, carried: Carried) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(carried);
    }

    /// `cert-status` from the kept record of import `generation`, `None`
    /// when nothing was kept for it (an import or forget since hides an
    /// older identity's record).
    pub(crate) fn report(&self, now: u64, generation: u64) -> Option<CertStatus> {
        self.get()
            .filter(|carried| carried.key.2 == generation)
            .map(|carried| carried.state().report(now))
    }
}

static PROCESS_CARRY: OnceLock<Arc<Carry>> = OnceLock::new();

/// The shared handle (`EpochPins` keeps one per epoch).
#[derive(Clone, Default)]
pub(crate) struct RenewalHandle(Arc<Mutex<RenewalState>>);

impl RenewalHandle {
    /// v31: a handle whose record is kept in `carry` across epochs.
    pub(crate) fn carried(carry: Arc<Carry>) -> Self {
        Self(Arc::new(Mutex::new(RenewalState {
            carry: Some(carry),
            ..RenewalState::default()
        })))
    }

    /// v31: a provider start's handle, carried in the process carry.
    pub(crate) fn process() -> Self {
        Self::carried(PROCESS_CARRY.get_or_init(Arc::default).clone())
    }

    /// Run `step` on the state; v31: then keep a changed record in its
    /// carry, if any (the monitor's 2 ms ticks write nothing).
    pub(crate) fn with<T>(&self, step: impl FnOnce(&mut RenewalState) -> T) -> T {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let before = state.carried();
        let result = step(&mut state);
        let after = state.carried();
        if let (Some(carry), Some(record)) = (&state.carry, after) {
            if after != before {
                carry.set(record);
            }
        }
        result
    }

    /// A copy of the state (v31: the monitor reads it through
    /// `monitor_step`; tests only).
    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> RenewalState {
        self.with(|state| state.clone())
    }
}

/// The monitor's verdict for one check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    None,
    /// Seal the running session with `identity_renewal_due`.
    Seal,
    /// Due, but an epoch authentication backoff is in force.
    SkipAuthBackoff,
    /// v31: due, but the armed leak guard forbids the dial: deferred to the
    /// next provider start (no seal).
    DeferGuarded,
    /// v31: due, but the last failure was transport-class with no journal:
    /// no teardown for it; the attempt rides the next natural rebuild or
    /// provider start (v31 review: until the last stretch before expiry).
    HoldTransport,
    /// v31: due, but the live session is younger than `STABLE`.
    HoldYoung,
    /// v32: due, but the request is parked (the authority rejected it) and
    /// the last stretch before expiry has not begun: no teardown for it
    /// unless forced; it rides the next natural rebuild or Connect.
    HoldParked,
}

/// v31: what the monitor knows besides the renewal state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Monitor {
    /// The epoch's authentication backoff is in force.
    pub(crate) auth_backoff: bool,
    /// A Running epoch with a live session.
    pub(crate) live: bool,
    /// The renewal would dial a tuple the armed leak guard forbids
    /// (`leak_guard::Gate::dial_refused` of the epoch's authority).
    pub(crate) guarded: bool,
    /// How long the live session has been live (`None`: unknown, read as
    /// young).
    pub(crate) live_for: Option<Duration>,
}

/// Pure monitor rule. `live`: a Running epoch with a live session (a
/// Reasserting epoch's rebuild runs the step anyway). `auth_backoff`: the
/// epoch's authentication backoff is in force.
pub(crate) fn decide(now: u64, state: &RenewalState, auth_backoff: bool, live: bool) -> Action {
    if !live || state.last == Last::InProgress {
        return Action::None;
    }
    let Some((not_before, not_after)) = state.window else {
        return Action::None;
    };
    match identity_window(now, not_before, not_after) {
        Window::Expired | Window::NotYetValid => return Action::None,
        Window::Valid if !state.pending && !(state.parked && state.forced) => return Action::None,
        // Due, but inside the skew margin: the authority may not agree yet.
        Window::Due
            if !state.pending
                && !state.forced
                && now < renewal_attempt_at(not_before, not_after) =>
        {
            return Action::None
        }
        Window::Valid | Window::Due => {}
    }
    if !state.forced && now < state.next_attempt_at {
        return Action::None;
    }
    if auth_backoff {
        return Action::SkipAuthBackoff;
    }
    Action::Seal
}

/// v31 (S23b): the monitor's rule. `decide` says whether a renewal is due
/// now; a seal (or an authentication-backoff skip) then needs a renewal
/// that can run and is worth a teardown, first match deciding:
/// - the armed guard forbids its dial: `DeferGuarded` (to the next
///   provider start, before its arm);
/// - not forced, nothing journaled, the last failure transport-class, and
///   (v31 review) the last stretch before expiry not yet begun
///   (`transport_hold_ends_at`): `HoldTransport` (it rides the next natural
///   rebuild or start; in the last stretch the backoff alone paces seals);
/// - the live session is younger than `STABLE`: `HoldYoung` (a forced
///   renewal waits for it too).
pub(crate) fn judge(now: u64, state: &RenewalState, monitor: &Monitor) -> Action {
    let action = decide(now, state, monitor.auth_backoff, monitor.live);
    if action == Action::None {
        return action;
    }
    if monitor.guarded {
        return Action::DeferGuarded;
    }
    // v32: nor for a renewal an unreadable parked request refuses before
    // any dial (it cannot help until an import), and a parked request is
    // no reason for a teardown before the last stretch either.
    if !state.forced
        && !state.pending
        && state.check == Some(crate::renewal_journal::PARKED_REFUSED)
    {
        return Action::HoldParked;
    }
    if !state.forced
        && state.parked
        && state
            .window
            .is_some_and(|(nb, na)| now < transport_hold_ends_at(nb, na))
    {
        return Action::HoldParked;
    }
    if !state.forced
        && !state.pending
        && state.last_failure.is_some_and(FailureClass::is_transport)
        && state
            .window
            .is_some_and(|(nb, na)| now < transport_hold_ends_at(nb, na))
    {
        return Action::HoldTransport;
    }
    if monitor.live_for.is_none_or(|age| age < STABLE) {
        return Action::HoldYoung;
    }
    action
}

/// v31: one monitor check on the epoch's handle: `judge`, then the
/// bookkeeping (a deferral is recorded and ends a forced request) and the
/// log (a seal and an authentication skip as before, a hold once per
/// change). v31 review: a deferral is logged only when it begins (the
/// record was not deferred), the same rule as the step's `defer`, so one
/// deferral is one line whichever of the two sees it first and whatever
/// checks come between. Main runloop only; no I/O.
pub(crate) fn monitor_step(handle: &RenewalHandle, now: u64, monitor: &Monitor) -> Action {
    let (action, logged) = handle.with(|state| {
        let action = judge(now, state, monitor);
        let changed = state.hold != action;
        let began = action == Action::DeferGuarded && !state.deferred;
        match action {
            Action::DeferGuarded => {
                state.deferred = true;
                // v32: a forced renewal the guard defers runs at the next
                // Connect, even inside the backoff.
                if state.forced {
                    state.next_attempt_at = 0;
                }
                state.forced = false;
            }
            Action::Seal
            | Action::SkipAuthBackoff
            | Action::HoldTransport
            | Action::HoldYoung
            | Action::HoldParked => state.deferred = false,
            Action::None => {}
        }
        state.hold = action;
        let log = match action {
            Action::Seal | Action::SkipAuthBackoff => true,
            Action::DeferGuarded => began,
            Action::HoldTransport | Action::HoldYoung | Action::HoldParked => changed,
            Action::None => false,
        };
        (action, log.then(|| state.clone()))
    });
    if let Some(state) = logged {
        log_decision_at(action, &state, now);
    }
    action
}

/// A forced renewal is judged this often (the drain timer ticks every 2 ms).
pub(crate) const FORCED_CHECK_INTERVAL: Duration = Duration::from_millis(250);

/// Whether the monitor should judge now: every `CHECK_INTERVAL`, or every
/// `FORCED_CHECK_INTERVAL` while a renewal is forced. Records the check.
pub(crate) fn check_due(handle: &RenewalHandle, now: Instant) -> bool {
    handle.with(|state| {
        let interval = if state.forced {
            FORCED_CHECK_INTERVAL
        } else {
            CHECK_INTERVAL
        };
        let due = state
            .checked
            .is_none_or(|at| now.saturating_duration_since(at) >= interval);
        if due {
            state.checked = Some(now);
        }
        due
    })
}

fn log(state: &str, attempt: u32, next_in: Option<u64>) {
    log_with(state, attempt, next_in, None);
}

/// `log` with one more stable field (v31: `dials:N`, `connects:N`,
/// `remaining_s:N`).
fn log_with(state: &str, attempt: u32, next_in: Option<u64>, extra: Option<String>) {
    let attempt = format!("attempt:{attempt}");
    let next = next_in.map(|next| format!("next_s:{next}"));
    let mut fields = vec![state, attempt.as_str()];
    fields.extend(next.as_deref());
    fields.extend(extra.as_deref());
    #[cfg(test)]
    tests::record_log(&fields);
    crate::apple::log_fields("identity_renewal", &fields);
}

/// v31: the seconds left before `not_after`, for a deferral's log line.
fn remaining(state: &RenewalState, now: u64) -> Option<String> {
    state
        .window
        .map(|(_, not_after)| format!("remaining_s:{}", not_after.saturating_sub(now)))
}

/// Log the monitor's decision (`monitor_step`).
fn log_decision_at(action: Action, state: &RenewalState, now: u64) {
    match action {
        Action::Seal => log("state:due", state.attempts.saturating_add(1), None),
        Action::SkipAuthBackoff => log("state:skipped:auth_backoff", state.attempts, None),
        Action::DeferGuarded => log_with(
            "state:deferred:guarded",
            state.attempts,
            None,
            remaining(state, now),
        ),
        Action::HoldTransport => log("state:held:transport", state.attempts, None),
        Action::HoldYoung => log("state:held:young", state.attempts, None),
        Action::HoldParked => log("state:held:parked", state.attempts, None),
        Action::None => {}
    }
}

// ---------------------------------------------------------------------------
// Publication for the XPC verbs.

static PUBLISHED: Mutex<Option<RenewalHandle>> = Mutex::new(None);

/// Record the newest epoch's renewal state for `cert-status` and `renew`.
pub(crate) fn publish(handle: &RenewalHandle) {
    *PUBLISHED.lock().unwrap_or_else(PoisonError::into_inner) = Some(handle.clone());
}

/// The epoch owning `handle` ended (its start refused, or its session
/// joined): `cert-status` and `renew` answer `no_epoch` until the next
/// start publishes again. A newer epoch's publication is kept.
pub(crate) fn unpublish(handle: &RenewalHandle) {
    let mut published = PUBLISHED.lock().unwrap_or_else(PoisonError::into_inner);
    if published
        .as_ref()
        .is_some_and(|current| Arc::ptr_eq(&current.0, &handle.0))
    {
        *published = None;
    }
}

fn published() -> Option<RenewalHandle> {
    PUBLISHED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// `cert-status` over a handle alone (tests; production adds the carry).
#[cfg(test)]
pub(crate) fn cert_status_of(
    handle: Option<&RenewalHandle>,
    now: u64,
) -> Result<CertStatus, &'static str> {
    cert_status_with(handle, None, 0, now)
}

/// v31: `cert-status` of the published epoch, else of the process carry's
/// kept record of the current import `generation` (the last outcome
/// survives the epoch), else `no_epoch`.
pub(crate) fn cert_status_with(
    handle: Option<&RenewalHandle>,
    carry: Option<&Carry>,
    generation: u64,
    now: u64,
) -> Result<CertStatus, &'static str> {
    if let Some(handle) = handle {
        return Ok(handle.with(|state| state.report(now)));
    }
    carry
        .and_then(|carry| carry.report(now, generation))
        .ok_or("no_epoch")
}

pub(crate) fn cert_status() -> Result<CertStatus, &'static str> {
    let now = registry::unix_now().map_err(|_| "session_clock_failed")?;
    cert_status_with(
        published().as_ref(),
        PROCESS_CARRY.get().map(Arc::as_ref),
        identity_generation(),
        now,
    )
}

/// `renew` over a handle: force the next monitor check to seal for renewal
/// (the library refuses a Renew request before it is due, unless one is
/// journaled). Answered without I/O.
pub(crate) fn request_renewal_of(
    handle: Option<&RenewalHandle>,
    now: u64,
) -> Result<&'static str, &'static str> {
    let handle = handle.ok_or("no_epoch")?;
    handle.with(|state| {
        let Some((not_before, not_after)) = state.window else {
            return Err("identity_unknown");
        };
        match identity_window(now, not_before, not_after) {
            Window::Expired => Err("identity_expired"),
            Window::Due => {
                state.forced = true;
                Ok("renew_scheduled")
            }
            Window::Valid | Window::NotYetValid if state.pending || state.parked => {
                state.forced = true;
                Ok("renew_scheduled")
            }
            Window::Valid | Window::NotYetValid => Err("renewal_not_due"),
        }
    })
}

pub(crate) fn request_renewal() -> Result<&'static str, &'static str> {
    let now = registry::unix_now().map_err(|_| "session_clock_failed")?;
    request_renewal_of(published().as_ref(), now)
}

// ---------------------------------------------------------------------------
// The step before a session's capture.

/// What one `before_capture` runs with.
pub(crate) struct Step<'a> {
    pub(crate) renewal: &'a RenewalHandle,
    /// The interface renewal sockets bind to, given the authority: the
    /// epoch's pin on a rebuild; resolved before any settings at start.
    pub(crate) interface: &'a dyn Fn(SocketAddr) -> Result<RelayInterface, &'static str>,
    /// The provider is stopping.
    pub(crate) stop: &'a dyn Fn() -> bool,
    /// Test-only: the authority's bound-index recorder.
    #[cfg(test)]
    pub(crate) bound: Option<Arc<Mutex<Vec<u32>>>>,
}

fn transient(code: &'static str) -> Refusal {
    Refusal::transient(code)
}

/// The import generation (S14 identity verbs): an expiry judged under one
/// generation stands until an import or forget commits.
fn identity_generation() -> u64 {
    #[cfg(test)]
    if let Some(generation) = tests::GENERATION.with(std::cell::Cell::get) {
        return generation;
    }
    crate::identity_import::IDENTITY_GENERATION.load(std::sync::atomic::Ordering::Acquire)
}

/// v31 (S23b): whether a renewal dial to `authority` must not be made now:
/// the process leak guard is armed (by any epoch or provider instance) and
/// `authority` is not an armed relay pin's own tuple (`Gate::dial_refused`;
/// v40: any pin of the carrier pool, so a fronted authority on the edge's
/// 443, variant B, is relay traffic).
fn dial_refused(authority: SocketAddr) -> bool {
    #[cfg(test)]
    if let Some(armed) = tests::ARMED_RELAY.with(std::cell::Cell::get) {
        return crate::leak_guard::Snapshot {
            mode: crate::leak_guard::Mode::Guarding,
            token: 1,
            relays: crate::leak_guard::PeerSet::one(armed.map(crate::leak_guard::Peer::from)),
            udp_relay: false,
            udp_media: crate::leak_guard::PeerSet::EMPTY,
        }
        .dial_refused(authority);
    }
    crate::leak_guard::LEAK_GUARD.dial_refused(authority)
}

/// Run before every capture of a session's claim (start and rebuild). Ok:
/// capture now (the installed identity, renewed or not). Err: a refusal of
/// this attempt, no capture; nothing it held (tree lease, Store lock)
/// outlives it.
pub(crate) fn before_capture(
    step: &Step<'_>,
    capture: impl FnOnce() -> io::Result<CapturedRenewalInputs>,
) -> Result<(), Refusal> {
    let now = registry::unix_now().map_err(|_| transient("session_clock_failed"))?;
    let generation = identity_generation();
    let quiet = step.renewal.with(|state| {
        // v32: a fresh epoch takes up the process's expired gate first.
        state.carry_gate(generation);
        if state.gated(now, generation) {
            return Err(transient(SESSION_IDENTITY_EXPIRED));
        }
        Ok(state.quiet(now))
    })?;
    if quiet {
        return Ok(());
    }
    let mut inputs = capture().map_err(|error| Refusal::custody(&error))?;
    let public = inputs
        .public_payload()
        .map_err(|error| Refusal::custody(&error))?;
    let profile_sha256 = aegis_client::public_profile_file::profile_digest_bytes(&public);
    // v31: the tuple any exchange of this step would dial (none: the
    // exchange refuses before any dial).
    let authority = crate::renewal_exchange::authority_address(&public[0]).ok();
    let opened = inputs
        .with_identity_path(|identity| RenewalJournal::open(identity, &profile_sha256))
        .map_err(|error| Refusal::custody(&error))?;
    let journal = match opened {
        Ok(journal) => journal,
        Err(code) if code == BUSY => return Err(transient(BUSY)),
        // Not this step's to judge: the session's own admission refuses a
        // broken identity with its classified code.
        Err(_) => return Ok(()),
    };
    // 1. A verified saved response finishes locally, before any network.
    match journal.resume_response(now) {
        Ok(Some(done)) => {
            step.renewal.with(|state| {
                state.renewed(done.not_before_unix_secs, done.not_after_unix_secs);
                // v31 review: this return skips step 2's `carry_in`, so name
                // the generation here: the carry then keeps the successor's
                // record, never the predecessor's pending one (which
                // `cert-status` would report while disconnected).
                state.carry_in(generation, now);
            });
            log("state:issued", 0, None);
            return Ok(());
        }
        Ok(None) => {}
        Err(_) => return Err(transient(IDENTITY_RENEWAL_PENDING)),
    }
    // 2. The installed window and journal.
    let status = match journal.status(now) {
        Ok(status) => status,
        Err(_) if journal.journal_present().unwrap_or(true) => {
            return Err(transient(IDENTITY_RENEWAL_PENDING))
        }
        Err(_) => return Ok(()),
    };
    let (nb, na) = (status.not_before_unix_secs, status.not_after_unix_secs);
    let window = identity_window(now, nb, na);
    let (forced, next_attempt_at, issued, settled) = step.renewal.with(|state| {
        state.observed_with(nb, na, status.pending, status.parked);
        // v31: a fresh epoch takes up the process's record of this window.
        state.carry_in(generation, now);
        (
            state.forced,
            state.next_attempt_at,
            state.issued,
            state.settled,
        )
    });
    // v32: a parked request that cannot be read refuses every renewal (no
    // dial, no fresh request beside it) but never the capture.
    if status.parked_refused && window != Window::Expired {
        refuse_parked(step, now);
        return Ok(());
    }
    // v31: due within one check interval is due now (folded into this
    // step instead of a seal moments after it).
    let soon = now.saturating_add(FOLD_SECS);
    let expired = match window {
        Window::Expired if status.recoverable => {
            if now < next_attempt_at {
                return Err(transient(SESSION_IDENTITY_EXPIRED));
            }
            true
        }
        Window::Expired => {
            // Nothing recoverable: a definite outcome, carried.
            step.renewal
                .with(|state| state.gate_expired(generation, true));
            log("state:expired", 0, None);
            return Err(transient(SESSION_IDENTITY_EXPIRED));
        }
        Window::NotYetValid | Window::Valid if !status.pending && !(status.parked && forced) => {
            return Ok(())
        }
        // Due within the skew margin: the first scheduled attempt waits.
        Window::Due
            if !status.pending
                && !status.parked
                && !forced
                && soon < renewal_attempt_at(nb, na) =>
        {
            return Ok(())
        }
        _ if !forced && soon < next_attempt_at => {
            // v31: nothing is attempted, so nothing is deferred either.
            step.renewal.with(|state| state.deferred = false);
            // v32: a parked request waits out its backoff beside the
            // captured certificate.
            if status.parked {
                log("state:waiting:parked", 0, Some(next_attempt_at - now));
                return Ok(());
            }
            let waiting = if status.pending {
                "state:pending"
            } else {
                "state:not_due"
            };
            log(waiting, 0, Some(next_attempt_at - now));
            return if status.pending {
                Err(transient(IDENTITY_RENEWAL_PENDING))
            } else {
                Ok(())
            };
        }
        _ => false,
    };
    // v32: Receipt purpose only once expired, or once the authority issued
    // for this request (a fresh authorization would only be rejected).
    let receipt_only = expired || issued.is_some();
    let resume = if status.pending {
        Resume::Request
    } else if status.parked {
        Resume::Parked
    } else {
        Resume::None
    };
    // 3. v31: never a dial beside the armed leak guard, other than to the
    // relay's own tuple: deferred, with the old certificate (or the
    // journal's and the expiry's refusal) kept.
    if authority.is_some_and(dial_refused) {
        return defer(step, now, status.pending, expired);
    }
    // 4. One bounded exchange on the pinned physical interface; one connect
    // attempt after a step whose every connect timed out.
    let (attempt, connects, previous_attempt_at) = step.renewal.with(|state| {
        state.forced = false;
        state.deferred = false;
        state.last = Last::InProgress;
        let previous = state.last_attempt_at.replace(now);
        let connects = if state.starved { 1 } else { ATTEMPTS };
        (state.attempts.saturating_add(1), connects, previous)
    });
    log_with(
        "state:start",
        attempt,
        None,
        Some(format!("connects:{connects}")),
    );
    let dials = Dials::default();
    let outcome = exchange(
        step,
        &mut inputs,
        &journal,
        resume,
        receipt_only,
        connects,
        &dials,
    );
    // v31 review: a provider stop is no attempt. It drops the exchange,
    // possibly inside a connect that never timed out, so it settles no
    // connect timeout and leaves the record's connect count, starved flag
    // and last attempt as they were: the next Connect (the only moment a
    // deferred renewal can run) keeps its full connect count.
    let stopped = matches!(outcome, Err(Interrupted::Stopped));
    let cut_in_connect = !stopped && dials.settle();
    // v32 review: whether every request of the active request has been
    // answered: a fresh one written in this step, or a parked one (every
    // answer it ever had was a rejection), or a journaled one this process
    // saw settled, and no request of this step unanswered (a stop, too, may
    // drop one after its first byte).
    let settled = !dials.unanswered() && (resume != Resume::Request || settled);
    step.renewal.with(|state| {
        state.settled = settled;
        if stopped {
            state.last_attempt_at = previous_attempt_at;
            return;
        }
        state.last_dials = dials.started();
        if let Some(starved) = dials.starved() {
            state.starved = starved;
        }
    });
    let now = registry::unix_now().unwrap_or(now);
    // v32: where the step left the request. A parked request whose unpark
    // never ran (no challenge was read) still keeps the capture open.
    let leaf = if journal.journal_present().unwrap_or(true) {
        Journal::Blocking
    } else if journal.is_parked() {
        Journal::Parked
    } else {
        Journal::None
    };
    let ended = Ended {
        now,
        attempt,
        expired,
        fresh: resume == Resume::None,
        dials: dials.started(),
        leaf,
        // v32 review: a rejection is definite for a settled request that
        // never had an issued answer, or once a definitive check refused the
        // successor the authority issued for it (it can never be installed).
        definite: (settled && issued.is_none())
            || issued.is_some_and(crate::renewal_journal::definitive),
    };
    match outcome {
        Ok(Outcome::Issued(done)) => {
            // The library's own validator, under the same held lock, must
            // admit the installed successor before any capture.
            if journal.expectation(now).is_err() {
                step.renewal.with(|state| {
                    state.failed_at(
                        now,
                        FailureClass::LocalRefused,
                        leaf,
                        Some(EXPECTATION_REFUSED),
                    )
                });
                log("state:failed:local_refused", attempt, None);
                log_check("state:refused", attempt, EXPECTATION_REFUSED);
                return Err(transient(IDENTITY_RENEWAL_PENDING));
            }
            step.renewal
                .with(|state| state.renewed(done.not_before_unix_secs, done.not_after_unix_secs));
            log_with(
                "state:issued",
                attempt,
                None,
                Some(format!("dials:{}", dials.started())),
            );
            Ok(())
        }
        // v32: the authority issued and this client refused: never parked.
        Ok(Outcome::Unaccepted(code)) => unaccepted(step, &ended, code),
        // v32: rejected (or recovery required), no issued answer seen for
        // this request, outside the skew window: parked. v32 review: only a
        // settled request (every request of it answered in this process): a
        // request whose earlier answer was lost may have been issued, and
        // Rejected does not prove otherwise (the authority answers Rejected
        // for any issuer error, another device's retained issuance among
        // them), so it stays journaled and the superseded predecessor never
        // reaches the relay.
        Ok(Outcome::Failed(class @ (FailureClass::Rejected | FailureClass::RecoveryRequired)))
            if issued.is_none()
                && settled
                && leaf == Journal::Blocking
                && !(ended.fresh
                    && class == FailureClass::Rejected
                    && in_skew_window(nb, na, now)) =>
        {
            park(step, &journal, &ended, class)
        }
        Ok(Outcome::Failed(class)) => fail(step, &ended, class, None),
        Ok(Outcome::Local(code)) => fail(step, &ended, FailureClass::LocalRefused, Some(code)),
        Err(Interrupted::Stopped) => {
            step.renewal.with(|state| {
                state.last = Last::None;
                state.pending = leaf == Journal::Blocking;
                state.parked = leaf == Journal::Parked;
            });
            log("state:stopped", attempt, None);
            Err(transient(IDENTITY_RENEWAL_STOPPED))
        }
        // v31: the step's budget ended during a connect, or once connected.
        Err(Interrupted::Timeout) if cut_in_connect => {
            fail(step, &ended, FailureClass::ConnectTimeout, None)
        }
        Err(Interrupted::Timeout) => fail(step, &ended, FailureClass::Timeout, None),
        Err(Interrupted::Unresolved) => fail(step, &ended, FailureClass::InterfaceUnresolved, None),
        Err(Interrupted::Authority) => fail(
            step,
            &ended,
            FailureClass::LocalRefused,
            Some(crate::renewal_exchange::AUTHORITY_REFUSED),
        ),
        Err(Interrupted::Runtime) => fail(
            step,
            &ended,
            FailureClass::LocalRefused,
            Some(RUNTIME_FAILED),
        ),
        Err(Interrupted::Guarded) => {
            step.renewal.with(|state| state.last = Last::None);
            defer(step, now, status.pending, expired)
        }
    }
}

/// v32: what one finished exchange left for its outcome's bookkeeping.
struct Ended {
    now: u64,
    attempt: u32,
    /// The installed certificate had expired (receipt recovery only).
    expired: bool,
    /// No request was journaled or parked at the step's start.
    fresh: bool,
    dials: u32,
    leaf: Journal,
    /// v32 review: a Rejected answer of this step is definite for the
    /// request (an expired gate it closes is carried).
    definite: bool,
}

/// v32 review: what a failed step does to the expired gate once expired.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Gate {
    /// Left open: the next attempt is paced by `EXPIRED_RECOVERY_SECS`.
    Open,
    /// Closed for this epoch only (v31): a rejection that may be transient.
    Epoch,
    /// Closed and carried to the next Connect: a definite outcome.
    Carried,
}

impl Gate {
    /// The gate a Rejected answer closes (`definite`), none for any other.
    fn after(class: FailureClass, definite: bool) -> Self {
        match (class, definite) {
            (FailureClass::Rejected, true) => Self::Carried,
            (FailureClass::Rejected, false) => Self::Epoch,
            _ => Self::Open,
        }
    }
}

/// v32: `log_with` a `check:<code>` field.
fn log_check(state: &str, attempt: u32, code: &str) {
    log_with(state, attempt, None, Some(format!("check:{code}")));
}

/// v32: a parked request that cannot be read: the renewal is refused with
/// `renewal_parked_refused`, recorded and logged once, and nothing is
/// dialed or written; the capture proceeds.
fn refuse_parked(step: &Step<'_>, now: u64) {
    let first = step.renewal.with(|state| {
        let first = state.check != Some(crate::renewal_journal::PARKED_REFUSED);
        state.check = Some(crate::renewal_journal::PARKED_REFUSED);
        state.last_failure = Some(FailureClass::LocalRefused);
        state.last = Last::Failed(FailureClass::LocalRefused);
        state.failing_since.get_or_insert(now);
        state.deferred = false;
        state.forced = false;
        first.then_some(state.attempts)
    });
    if let Some(attempts) = first {
        log_check(
            "state:refused",
            attempts,
            crate::renewal_journal::PARKED_REFUSED,
        );
    }
}

/// v31: a due attempt the armed leak guard forbids. Nothing is dialed,
/// counted or rescheduled; the deferral is recorded (`deferred:guarded`)
/// and logged once per run, and a forced request ends with it (v32: and
/// runs at the next Connect, inside the backoff or not). A fresh renewal
/// and a parked request keep the old certificate; a journaled request and
/// an expired identity keep their recoverable refusals.
fn defer(step: &Step<'_>, now: u64, pending: bool, expired: bool) -> Result<(), Refusal> {
    let logged = step.renewal.with(|state| {
        let first = !state.deferred;
        state.deferred = true;
        if state.forced {
            state.next_attempt_at = 0;
        }
        state.forced = false;
        first.then(|| (state.attempts, remaining(state, now)))
    });
    if let Some((attempts, remaining)) = logged {
        log_with("state:deferred:guarded", attempts, None, remaining);
    }
    if expired {
        Err(transient(SESSION_IDENTITY_EXPIRED))
    } else if pending {
        Err(transient(IDENTITY_RENEWAL_PENDING))
    } else {
        Ok(())
    }
}

/// v32: whether a fresh authorization rejected at `now` is inside the skew
/// margin after the first scheduled attempt (its clock may lag ours).
fn in_skew_window(not_before: u64, not_after: u64, now: u64) -> bool {
    now < renewal_attempt_at(not_before, not_after).saturating_add(SKEW_MARGIN_SECS)
}

/// The retry of a fresh authorization the authority refused within the skew
/// margin after the first scheduled attempt (its clock may lag ours).
fn skew_retry(state: &RenewalState, now: u64, class: FailureClass, fresh: bool) -> Option<u64> {
    let (not_before, not_after) = state.window?;
    (fresh && class == FailureClass::Rejected && in_skew_window(not_before, not_after, now)).then(
        || {
            now.saturating_add(SKEW_RETRY_SECS)
                .min(state.next_attempt_at)
        },
    )
}

/// Record a failed attempt (v32: where it left the request and its check),
/// with the v31 line `state:failed:<class> attempt:N next_s:S dials:D`
/// unchanged, then (v32) `state:refused attempt:N check:<code>` for a
/// local check, or (v32 review) `state:superseded attempt:N check:<code>`
/// for a later attempt of a superseded request (its receipt check).
/// Returns the start's verdict.
fn fail(
    step: &Step<'_>,
    ended: &Ended,
    class: FailureClass,
    check: Option<&'static str>,
) -> Result<(), Refusal> {
    record_failure(step, ended, class, ended.leaf, check);
    if let Some(code) = check {
        log_check("state:refused", ended.attempt, code);
    } else if let Some(code) = step.renewal.with(|state| {
        state
            .issued
            .filter(|code| state.pending && crate::renewal_journal::definitive(code))
    }) {
        log_check("state:superseded", ended.attempt, code);
    }
    verdict(step, ended, ended.leaf, Gate::after(class, ended.definite))
}

/// The bookkeeping and the v31 failure line of every failed attempt.
fn record_failure(
    step: &Step<'_>,
    ended: &Ended,
    class: FailureClass,
    journal: Journal,
    check: Option<&'static str>,
) {
    let now = ended.now;
    let next = step.renewal.with(|state| {
        state.failed_at(now, class, journal, check);
        if let Some(retry) = skew_retry(state, now, class, ended.fresh) {
            state.next_attempt_at = retry;
        }
        if ended.expired {
            // Expired: receipt recovery at most every EXPIRED_RECOVERY_SECS,
            // and (v32 review) a definite rejection leaves nothing to
            // recover (`verdict`'s gate).
            state.next_attempt_at = now.saturating_add(EXPIRED_RECOVERY_SECS);
        }
        state.next_attempt_at
    });
    log_with(
        &format!("state:failed:{}", class.token()),
        ended.attempt,
        Some(next.saturating_sub(now)),
        Some(format!("dials:{}", ended.dials)),
    );
}

/// A failed step's verdict: once expired `session_identity_expired` (and
/// the expired `gate`, v32 review: for this epoch or carried), else
/// `identity_renewal_pending` beside a blocking journal, else the capture.
fn verdict(step: &Step<'_>, ended: &Ended, journal: Journal, gate: Gate) -> Result<(), Refusal> {
    if ended.expired {
        if gate != Gate::Open {
            step.renewal
                .with(|state| state.gate_expired(identity_generation(), gate == Gate::Carried));
        }
        return Err(transient(SESSION_IDENTITY_EXPIRED));
    }
    if journal == Journal::Blocking {
        Err(transient(IDENTITY_RENEWAL_PENDING))
    } else {
        Ok(())
    }
}

/// v32: the authority issued a receipt this client refused (`code`). The
/// request stays the blocking journal and is never parked: the authority
/// replays a receipt only while its registry names that successor, so the
/// relay no longer admits the predecessor. The record keeps `issued`, so
/// later attempts ask only for the receipt, paced by the backoff; a
/// definitive check is `superseded` (and, once expired, gated).
fn unaccepted(step: &Step<'_>, ended: &Ended, code: &'static str) -> Result<(), Refusal> {
    step.renewal.with(|state| state.issued = Some(code));
    record_failure(
        step,
        ended,
        FailureClass::LocalRefused,
        ended.leaf,
        Some(code),
    );
    let definitive = crate::renewal_journal::definitive(code);
    log_check(
        if definitive {
            "state:superseded"
        } else {
            "state:refused"
        },
        ended.attempt,
        code,
    );
    let gate = if definitive {
        Gate::Carried
    } else {
        Gate::Open
    };
    verdict(step, ended, ended.leaf, gate)
}

/// v32: park a request the authority rejected (Rejected or
/// RecoveryRequired; no issued answer seen; v32 review: every request of it
/// answered): the installed certificate is captured beside it and the
/// relay judges it. A park the journal refuses keeps the blocking request,
/// with its check. v32 review: that failure is still the authority's
/// answer: its class is recorded and logged (`state:failed:rejected`, then
/// `state:refused attempt:N check:<code>`), so the request is paced like
/// any rejection, the next attempt parks it again, and once expired a
/// definite rejection closes the carried gate.
fn park(
    step: &Step<'_>,
    journal: &RenewalJournal,
    ended: &Ended,
    class: FailureClass,
) -> Result<(), Refusal> {
    let gate = Gate::after(class, ended.definite);
    match journal.park() {
        Ok(()) => {
            record_failure(step, ended, class, Journal::Parked, None);
            log_with(
                "state:parked",
                ended.attempt,
                None,
                Some(format!("check:{}", class.token())),
            );
            verdict(step, ended, Journal::Parked, gate)
        }
        Err(code) => {
            record_failure(step, ended, class, ended.leaf, Some(code));
            log_check("state:refused", ended.attempt, code);
            verdict(step, ended, ended.leaf, gate)
        }
    }
}

enum Interrupted {
    Stopped,
    Timeout,
    Unresolved,
    Authority,
    /// v31: the step's runtime could not be built (local; up to v30 it was
    /// reported as a timeout).
    Runtime,
    /// v31: the leak guard armed between the step's check and its exchange.
    Guarded,
}

/// The network part: the authority from the held profile, the interface,
/// then the exchange under `RENEWAL_BUDGET`, stop polled throughout, with
/// at most `connects` connect attempts, each counted in `dials`.
fn exchange(
    step: &Step<'_>,
    inputs: &mut CapturedRenewalInputs,
    journal: &RenewalJournal,
    resume: Resume,
    receipt_only: bool,
    connects: u32,
    dials: &Dials,
) -> Result<Outcome, Interrupted> {
    let public = inputs
        .public_payload()
        .map_err(|_| Interrupted::Authority)?;
    let bridge = inputs
        .bridge_snapshot()
        .map_err(|_| Interrupted::Authority)?;
    #[allow(unused_mut)]
    let mut authority = EnrollmentAuthority::from_held(
        public,
        bridge,
        inputs.bundle_path(),
        inputs.identity_path(),
    )
    .map_err(|_| Interrupted::Authority)?;
    #[cfg(test)]
    {
        authority.bound = step.bound.clone();
    }
    // v31: the armed guard is read again right before the network part (a
    // fail-closed re-check: it can only defer).
    if dial_refused(authority.address()) {
        return Err(Interrupted::Guarded);
    }
    let interface = (step.interface)(authority.address()).map_err(|_| Interrupted::Unresolved)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| Interrupted::Runtime)?;
    let stop = step.stop;
    runtime.block_on(async {
        let stopped = async {
            while !stop() {
                tokio::time::sleep(STOP_POLL).await;
            }
        };
        tokio::select! {
            biased;
            _ = stopped => Err(Interrupted::Stopped),
            _ = tokio::time::sleep(RENEWAL_BUDGET) => Err(Interrupted::Timeout),
            outcome = authority.perform(
                journal,
                &interface,
                resume,
                receipt_only,
                RENEWAL_BUDGET.saturating_sub(PERFORM_SLACK),
                connects,
                dials,
            ) => Ok(outcome),
        }
    })
}

#[cfg(test)]
#[path = "identity_renewal_tests.rs"]
mod tests;
