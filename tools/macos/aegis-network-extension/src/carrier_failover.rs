//! B-06 v40 (CP-D3 M1): aegis-core's carrier failover controller in the
//! macOS provider.
//!
//! The controller is the shared, pure `aegis_core::brain::carrier_failover`
//! (the Linux client runs the same one): per access network, a circuit
//! breaker per pin of the signed pool, closed pins first in profile order,
//! a single-flight trial of a cooled-down preferred pin, pins in cooldown
//! kept as a last resort. This module holds one controller per admitted
//! profile for the life of the provider process (RAM only, as the Linux
//! client's), keyed by the public profile digest, and maps the provider's
//! own observations onto its signals:
//!
//! - one session build ([`SessionCarriers`]) tries the plan's pins in order;
//!   a typed pre-authentication failure of its first ACK's outer carrier
//!   (TCP dial timeout or refusal, an outer TLS handshake cut at the
//!   transport layer, no inner TLS before the deadline, a non-200 or
//!   non-gRPC carrier answer) is recorded and the same build moves to the
//!   next pin before any device identity, PolicyAck or target is sent;
//! - an authenticated session ([`CarrierTicket::opened`]) records `Opened`;
//!   a pre-authentication failure of a later pooled dial of that open
//!   session is recorded once and marks the session's carrier lost
//!   ([`CarrierTicket::lost`]): the session then ends recoverably and the
//!   rebuild plans again;
//! - post-authentication degradations of an open session are recorded once
//!   per session: a pooled connection its stall watchdog closed because a
//!   PING went unanswered (`session_freeze`), a PONG slower than the
//!   policy's collapse threshold (`throughput_collapse`), a lease that ran
//!   out with neither a wake nor a re-pin in between (`session_freeze`);
//! - a session that ends otherwise with no degradation is `Healthy`.
//!
//! Certificate, TLS alert and ECH refusals, inner identity refusals and
//! local errors are never carrier signals: they keep their existing
//! terminal or backoff handling. Nothing here adds a pin, resolves a name,
//! dials, or relaxes an admission, filter or identity check; the order only
//! changes which signed pin a session dials. A single-pin profile has no
//! controller and dials its one pin exactly as before.
use crate::establish_limit::{any_in_chain, carrier_refusal, peer_ended, timed_out, tls_failure};
use aegis_core::brain::carrier_failover::{
    CarrierFailover, CarrierFailoverSettings, CarrierOutcome, CarrierSignal, CarrierTransition,
    NetworkKey,
};
use std::{
    error::Error as StdError,
    io,
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc, Mutex, MutexGuard, PoisonError,
    },
    time::{Duration, Instant},
};

/// Profiles with live controllers in this process (the Linux client's
/// bound); the least recently used is evicted beyond it. An installed
/// provider holds one profile.
const MAX_PROFILES: usize = 32;

type Shared = Arc<Mutex<CarrierFailover>>;
type Registry = Vec<([u8; 32], Shared, Instant)>;
static REGISTRY: Mutex<Registry> = Mutex::new(Vec::new());

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn refused() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "carrier failover refused")
}

/// The process's controller for profile `identity`, created with `policy`
/// for `carriers` pins on first use.
fn controller(
    identity: [u8; 32],
    policy: &CarrierFailoverSettings,
    carriers: usize,
) -> io::Result<Shared> {
    let mut registry = lock(&REGISTRY);
    let now = Instant::now();
    if let Some((_, shared, used)) = registry.iter_mut().find(|(key, _, _)| *key == identity) {
        *used = now;
        return Ok(shared.clone());
    }
    if registry.len() >= MAX_PROFILES {
        if let Some(oldest) = registry
            .iter()
            .enumerate()
            .min_by_key(|(_, (_, _, used))| *used)
            .map(|(index, _)| index)
        {
            registry.swap_remove(oldest);
        }
    }
    let shared = Arc::new(Mutex::new(
        CarrierFailover::new(policy.clone(), carriers).map_err(|_| refused())?,
    ));
    registry.push((identity, shared.clone(), now));
    Ok(shared)
}

/// The identity a profile's controller is kept under: its public profile
/// digest (the signed pool and policy are part of the profile).
pub(crate) fn profile_identity(public_digest: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"aegis.ne.carrier-failover.profile.v1\0");
    hash.update(public_digest.as_bytes());
    hash.finalize().into()
}

/// Test-only: a view of the controller kept for `identity`.
#[cfg(test)]
pub(crate) fn inspect<T>(
    identity: [u8; 32],
    view: impl FnOnce(&CarrierFailover) -> T,
) -> Option<T> {
    let shared = lock(&REGISTRY)
        .iter()
        .find(|(key, _, _)| *key == identity)
        .map(|(_, shared, _)| shared.clone())?;
    let guard = lock(&shared);
    Some(view(&guard))
}

struct SessionShared {
    controller: Shared,
    network: NetworkKey,
    policy: CarrierFailoverSettings,
}

impl SessionShared {
    fn record(&self, carrier: usize, outcome: CarrierOutcome) {
        let transitions =
            lock(&self.controller).record(self.network, carrier, outcome, Instant::now());
        for transition in transitions {
            log_transition(&self.network, &transition);
        }
    }
}

/// `carrier_failover <transition> carrier:<i> ...`: address free (pins by
/// index only, the network by its salted four-byte label).
fn log_transition(network: &NetworkKey, transition: &CarrierTransition) {
    {
        let net = format!("net:{}", network.label());
        match transition {
            CarrierTransition::CooldownStarted {
                carrier,
                signal,
                cooldown,
            } => crate::apple::log_fields(
                "carrier_failover",
                &[
                    &format!("cooldown:{}", signal.as_str()),
                    &format!("carrier:{carrier}"),
                    &format!("ms:{}", cooldown.as_millis()),
                    &net,
                ],
            ),
            CarrierTransition::ActiveSwitched { to, .. } => crate::apple::log_fields(
                "carrier_failover",
                &["active", &format!("carrier:{to}"), &net],
            ),
            CarrierTransition::Recovered { carrier } => crate::apple::log_fields(
                "carrier_failover",
                &["recovered", &format!("carrier:{carrier}"), &net],
            ),
        }
    }
}

/// One session build's attempt order over the pool. Dropping it releases
/// a reserved recovery trial that was never attempted.
pub(crate) struct SessionCarriers {
    shared: Option<Arc<SessionShared>>,
    order: Vec<usize>,
    trial: Option<(usize, Arc<AtomicBool>)>,
}

impl SessionCarriers {
    /// The plan of one session build for a pool of `carriers` pins on
    /// `network`. Without a failover `policy` (a single-pin profile) the
    /// order is the profile order and nothing is learned.
    pub(crate) fn plan(
        identity: [u8; 32],
        policy: Option<&CarrierFailoverSettings>,
        carriers: usize,
        network: NetworkKey,
    ) -> io::Result<Self> {
        if carriers == 0 || carriers > aegis_core::brain::carrier_failover::MAX_CARRIERS {
            return Err(refused());
        }
        let Some(policy) = policy else {
            return Ok(Self {
                shared: None,
                order: (0..carriers).collect(),
                trial: None,
            });
        };
        let controller = controller(identity, policy, carriers)?;
        if lock(&controller).carriers() != carriers {
            return Err(refused());
        }
        let plan = lock(&controller).plan(network, Instant::now());
        Ok(Self {
            shared: Some(Arc::new(SessionShared {
                controller,
                network,
                policy: policy.clone(),
            })),
            order: plan.order,
            trial: plan
                .trial
                .map(|carrier| (carrier, Arc::new(AtomicBool::new(false)))),
        })
    }

    /// Every pin exactly once, in attempt order.
    pub(crate) fn order(&self) -> &[usize] {
        &self.order
    }

    /// The ticket of one attempt on `carrier`; None without a controller.
    pub(crate) fn ticket(&self, carrier: usize) -> Option<Arc<CarrierTicket>> {
        let shared = self.shared.as_ref()?;
        let trial = self
            .trial
            .as_ref()
            .filter(|(index, _)| *index == carrier)
            .map(|(_, settled)| settled.clone());
        Some(Arc::new(CarrierTicket {
            shared: shared.clone(),
            carrier,
            trial,
            state: AtomicU8::new(PENDING),
            degraded: AtomicBool::new(false),
            faults: AtomicU8::new(0),
            lost: AtomicBool::new(false),
        }))
    }
}

impl Drop for SessionCarriers {
    fn drop(&mut self) {
        if let (Some(shared), Some((carrier, settled))) = (&self.shared, &self.trial) {
            if !settled.swap(true, Ordering::AcqRel) {
                shared.record(*carrier, CarrierOutcome::Neutral);
            }
        }
    }
}

const PENDING: u8 = 0;
const OPENED: u8 = 1;
const FAILED: u8 = 2;
const SETTLED: u8 = 3;

/// Pre-authentication faults of later dials after which an open session's
/// carrier is lost: the first is recorded (it opens the breaker), one alone
/// never ends a working session (a transient dial failure), a second does.
pub(crate) const LOST_AFTER_FAULTS: u8 = 2;

/// One session's carrier: exactly one terminal outcome is recorded (an
/// unsettled ticket records `Neutral` on drop), at most one degradation and
/// at most one pre-authentication fault after it opened.
pub(crate) struct CarrierTicket {
    shared: Arc<SessionShared>,
    carrier: usize,
    trial: Option<Arc<AtomicBool>>,
    state: AtomicU8,
    degraded: AtomicBool,
    // Pre-authentication faults of dials after the session opened.
    faults: AtomicU8,
    lost: AtomicBool,
}

impl std::fmt::Debug for CarrierTicket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CarrierTicket")
            .field("carrier", &self.carrier)
            .field("state", &self.state.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl CarrierTicket {
    fn settle_trial(&self) {
        if let Some(settled) = &self.trial {
            settled.store(true, Ordering::Release);
        }
    }

    /// The outer carrier and the inner device authentication (a verified
    /// PolicyAck) opened the session on this pin.
    pub(crate) fn opened(&self) {
        if self
            .state
            .compare_exchange(PENDING, OPENED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.settle_trial();
            self.shared.record(self.carrier, CarrierOutcome::Opened);
        }
    }

    /// A typed pre-authentication `signal` of a dial of this session's pin.
    /// Before the session opened it settles the attempt as failed (the
    /// build moves on). After, the first one is recorded (the breaker opens
    /// for later sessions) and the [`LOST_AFTER_FAULTS`]th marks the
    /// carrier lost for this session.
    pub(crate) fn fault(&self, signal: CarrierSignal) {
        if !signal.pre_auth() {
            return;
        }
        if self
            .state
            .compare_exchange(PENDING, FAILED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.settle_trial();
            self.shared
                .record(self.carrier, CarrierOutcome::Failed(signal));
            return;
        }
        if self.state.load(Ordering::Acquire) != OPENED {
            return;
        }
        let faults = self
            .faults
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                Some(n.saturating_add(1))
            })
            .unwrap_or(u8::MAX)
            .saturating_add(1);
        if faults == 1 {
            self.shared
                .record(self.carrier, CarrierOutcome::Failed(signal));
        }
        if faults >= LOST_AFTER_FAULTS {
            self.lost.store(true, Ordering::Release);
        }
    }

    /// Whether the session opened on this pin (and has not ended).
    pub(crate) fn is_open(&self) -> bool {
        self.state.load(Ordering::Acquire) == OPENED
    }

    /// Whether the attempt failed with a pre-authentication signal before
    /// the session opened: the build tries the next pin.
    pub(crate) fn failed(&self) -> bool {
        self.state.load(Ordering::Acquire) == FAILED
    }

    /// Whether a later dial of the open session failed before
    /// authentication: the session should end so a rebuild plans again.
    pub(crate) fn lost(&self) -> bool {
        self.lost.load(Ordering::Acquire)
    }

    /// An open session observed a post-authentication degradation; one per
    /// session is recorded, none before it opened.
    pub(crate) fn degraded(&self, signal: CarrierSignal) {
        if signal.pre_auth() || self.state.load(Ordering::Acquire) != OPENED {
            return;
        }
        if !self.degraded.swap(true, Ordering::AcqRel) {
            self.shared
                .record(self.carrier, CarrierOutcome::Failed(signal));
        }
    }

    /// The session ended. `frozen`: its lease ran out with no wake and no
    /// re-pin since it opened, a freeze of this carrier. A session that
    /// opened and ended with no degradation (and no fault) is healthy.
    pub(crate) fn closed(&self, frozen: bool) {
        if frozen {
            self.degraded(CarrierSignal::SessionFreeze);
        }
        let opened = self.state.load(Ordering::Acquire) == OPENED;
        let outcome = if opened && !self.degraded.load(Ordering::Acquire) && !self.lost() {
            CarrierOutcome::Healthy
        } else {
            CarrierOutcome::Neutral
        };
        self.finish(outcome);
    }

    fn finish(&self, outcome: CarrierOutcome) {
        let previous = self.state.swap(SETTLED, Ordering::AcqRel);
        if previous == PENDING || previous == OPENED {
            self.settle_trial();
            self.shared.record(self.carrier, outcome);
        }
    }

    /// A PONG at least this slow is a throughput collapse; None when the
    /// policy disables liveness.
    pub(crate) fn collapse_rtt(&self) -> Option<Duration> {
        let policy = &self.shared.policy;
        policy
            .liveness_enabled()
            .then(|| Duration::from_millis(policy.collapse_rtt_ms))
    }
}

impl Drop for CarrierTicket {
    fn drop(&mut self) {
        let previous = self.state.swap(SETTLED, Ordering::AcqRel);
        if previous == PENDING || previous == OPENED {
            if let Some(settled) = &self.trial {
                settled.store(true, Ordering::Release);
            }
            self.shared.record(self.carrier, CarrierOutcome::Neutral);
        }
    }
}

/// The signal of a failed TCP dial to a pin: no SYN-ACK within the budget
/// is a dial timeout, any refusal or unreachable error a dial refusal.
pub(crate) fn dial_signal(timed_out: bool) -> CarrierSignal {
    if timed_out {
        CarrierSignal::DialTimeout
    } else {
        CarrierSignal::DialRefused
    }
}

/// aegis-client `ech_policy::require_accepted_ech`: required ECH refused.
const ECH_NOT_ACCEPTED: &str = "required ECH was not accepted by the relay";
/// aegis-client `connect_h2_from_held`: the H2 driver ended before the
/// carrier's answer.
const DRIVER_ENDED: &str = "H2 driver ended before carrier response";

fn text_starts(error: &(dyn StdError + 'static), prefix: &str) -> bool {
    any_in_chain(error, &mut |current| {
        current.to_string().starts_with(prefix)
    })
}

/// The pre-authentication signal of a failed outer carrier step after the
/// TCP connect (outer TLS, HTTP/2, the carrier request), or None when the
/// failure is not a carrier signal and keeps its existing handling: a TLS
/// error (certificate, alert, ECH rejection), a refused required ECH, a
/// local error. The same classes as the Linux client's `pre_auth_signal`.
pub(crate) fn outer_signal(error: &(dyn StdError + 'static)) -> Option<CarrierSignal> {
    if tls_failure(error) || text_starts(error, ECH_NOT_ACCEPTED) {
        return None;
    }
    if timed_out(error) {
        return Some(CarrierSignal::EstablishmentTimeout);
    }
    if peer_ended(error)
        || text_starts(error, DRIVER_ENDED)
        || any_in_chain(error, &mut |current| {
            current.is::<crate::flow_pool::CarrierLost>()
        })
    {
        return Some(CarrierSignal::HandshakeReset);
    }
    if carrier_refusal(error) || any_in_chain(error, &mut |current| current.is::<h2::Error>()) {
        return Some(CarrierSignal::EdgeRefused);
    }
    None
}

/// The signal of a failed carrier stream on a connection that is already
/// up, once its session opened: only an explicit carrier refusal (a non-200
/// or non-gRPC answer, no HTTP/2), never a GOAWAY, a connection end or a
/// stream reset, which the pool retries as before.
pub(crate) fn stream_refusal_signal(error: &(dyn StdError + 'static)) -> Option<CarrierSignal> {
    (!tls_failure(error) && !text_starts(error, ECH_NOT_ACCEPTED) && carrier_refusal(error))
        .then_some(CarrierSignal::EdgeRefused)
}

#[cfg(test)]
#[path = "carrier_failover_tests.rs"]
mod tests;
