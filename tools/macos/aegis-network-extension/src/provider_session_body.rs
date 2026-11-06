//! Composite provider session body. The constructor returns a Constructing
//! handle at once; the session thread supervises one Store-last worker that
//! opens the protected Store, dials only the saved relay, observes one
//! authenticated PolicyAck, leases the bridge from it and runs the real packet
//! engine over held relay services. Every relay flow holds a WorkGate permit
//! and follows the bridge's refreshable lease; teardown stops the gate and
//! waits for it to drain before the engine join, so no flow outlives the
//! session. The monitor re-ACKs on the bridge clock with one connection per
//! ACK, as aegis-server writes one ACK per connection, with up to two
//! requests in flight (S16k) so one slow round trip never lapses the lease:
//! the lease ends at the latest verified grant. The next connections
//! are pre-warmed (TCP, outer TLS, H2, inner mTLS) in up to two slots, the
//! first two while the first ACK is still being exchanged and each next one
//! as soon as a request takes a channel, so a re-ACK is one request round
//! trip whose setup overlapped the exchanges before it. A failed request on a
//! pre-warmed channel moves to another, then to a fresh connection. A lease
//! that is not renewed in time seals the session. Before its first dial the
//! session resolves the relay's physical egress interface, and every relay
//! socket it or its relay services open is bound to it (S16f), so the
//! provider's own full-wide tunnel never captures them. A rebuilt session
//! (S17) reuses the interface its epoch's first session resolved: once the
//! tunnel settings are applied, a fresh route lookup would name the tunnel.
//! A physical path change re-pins it from the path monitor (S18), and a
//! wake forces one re-ACK ahead of the lease schedule.
//!
//! S16l: aegis-server serves every H2 stream as its own secure session, so
//! the ACK path keeps one persistent outer TLS + H2 connection of its own
//! (`ack_conn::AckLink`), apart from the flow pool, and every PolicyAck's
//! inner channel is a stream of it: the first ACK's, each pre-warmed channel
//! (its carrier request, 200 and inner mTLS done, waiting for its request,
//! aged below the relay's admission timeout from its carrier request or the
//! connection's last live channel) and each fresh re-ACK's. Its dial runs
//! under the ACK-path permit of the establishment it serves, so the ACK path
//! holds no more than its reserve; its driver is a gate task, so the relay
//! join drains it on every exit, and the epoch's re-pin or a wake drains it
//! as it drains a flow connection. While it is down (lost, a GOAWAY, never
//! up) the ACK path runs on its own dials as before, so the lease never
//! depends on one TCP connection, and a request dispatched while one in
//! flight on it has seen no sign of its life goes on another connection.
//!
//! Every channel establishment of the session, the ACK path's and every
//! flow's, takes a permit of one session-wide `EstablishLimiter` (S16g): at
//! most `ESTABLISH_PERMITS` at once, `ACK_RESERVE` of them reserved for the
//! ACK path (both pre-warm slots and both requests in flight), which also
//! goes first; the pool keeps
//! both pre-warm slots whatever the flow load. After an authentication-class
//! failure no establishment of the epoch starts for two seconds, and then
//! only one per purpose at a time until the relay answers one; an unanswered
//! Open backs off flows alone.
use crate::{
    ack_conn::{AckLink, LinkConn},
    app_group::CapturedAppGroupInputs,
    bridge::{LeasedPacketBridge, PacketBridge},
    carrier_failover::CarrierTicket,
    configuration::SavedProviderIntent,
    establish_limit::{
        is_auth_refused, AuthBackoff, EstablishLimiter, EstablishPermit, Purpose, AUTH_BACKOFF,
    },
    flow_pool::PooledConn,
    held_relay_services::{AbortOnDrop, HeldRelayServices, WorkGate, MAX_DRAIN},
    identity_renewal::RenewalHandle,
    local_identity::{
        CapturedLocalIdentity, ChannelOpener, ObservedLocalSession, PreparedLocalSession,
        PrewarmedChannel, ReackObservation, ReackRequest,
    },
    packet_engine::{flows::FlowLedger, PacketEngineOwner},
    provider_session::{
        lease_deadline_ns, SessionControl, SessionHandle, SessionPhase, SessionProbe,
    },
    relay_socket::{self, RelayInterface},
    session_rebuild::{admission_refusal, Admitted},
    store_last_thread::StoreLastThreadOwner,
    store_scoped_packet::packet_terminal,
};
use aegis_client::{
    capture_lease_gate::CaptureLeaseDeadline,
    packet_engine::services::{EngineEvent, EventSink},
    protected_online_expectation::ProtectedOnlineExpectation,
};
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering},
        Arc, Mutex, Weak,
    },
    task::{Context, Poll},
    thread,
    time::{Duration, Instant},
};
use tokio::{
    runtime::{Builder, Handle, Runtime},
    sync::oneshot,
    task::JoinHandle,
    time::MissedTickBehavior,
};

const CONNECT_BUDGET: Duration = Duration::from_secs(2);
const ENGINE_BUDGET: Duration = Duration::from_secs(2);
// The engine wait drives the session runtime, so a pre-warm progresses.
const ENGINE_POLL: Duration = Duration::from_millis(2);
const MONITOR_INTERVAL: Duration = Duration::from_millis(250);
// The lease ends this long before the ACK's own deadline.
const LEASE_MARGIN: Duration = Duration::from_millis(250);
const STOP_POLL: Duration = Duration::from_millis(2);
const MAX_JOIN: Duration = Duration::from_secs(2);
// A re-ACK starts at least this long before the current lease ends...
pub(crate) const REACK_LEAD: Duration = Duration::from_secs(2);
// ...or twice the last PolicyAck round trip plus this, when that is longer...
pub(crate) const REACK_LEAD_MARGIN: Duration = Duration::from_millis(250);
// ...but never sooner than this after the previous attempt began.
pub(crate) const REACK_SPACING: Duration = Duration::from_millis(500);
// A pre-warmed channel older than this (from its dial) is discarded: the
// server keeps an authenticated channel without a request only for its
// admission timeout (aegis-server session/grpc.rs, about 5 s).
pub(crate) const PREWARM_MAX_AGE: Duration = Duration::from_secs(4);
// Channels held or opening for the next re-ACKs: two, so one is open when the
// previous ACK arrives although a setup takes longer than an exchange.
pub(crate) const PREWARM_SLOTS: usize = 2;
// S16k: PolicyAck requests in flight at once, each on its own channel (the
// server answers one PolicyAck per inner channel): a second one overlaps a
// slow round trip, so the grants land about half a round trip apart.
pub(crate) const ACK_IN_FLIGHT: usize = 2;
const _: () = assert!(ACK_IN_FLIGHT >= 1 && ACK_IN_FLIGHT <= 2);
// The ACK reserve covers every slot and every request in flight (S16g, S16k).
const _: () = assert!(crate::establish_limit::ACK_RESERVE == PREWARM_SLOTS + ACK_IN_FLIGHT);
// The PolicyAck round trips the lead, the stagger and a pre-warmed request's
// bound are judged on: the last eight, so their p90 is their longest.
pub(crate) const EXCHANGE_WINDOW: usize = 8;
// The longest stagger between two requests in flight.
pub(crate) const REACK_STAGGER_MAX: Duration = Duration::from_secs(1);
// `reack_inflight` and `reack_lead` log a changed value at most this often.
const REACK_LOG_EVERY: Duration = Duration::from_secs(5);
// A channel is dialed this long before its predicted use, inside its bound.
pub(crate) const PREWARM_LEAD: Duration = Duration::from_millis(3_500);
// Dials allowed between two bound requests: every slot, plus one at once
// after a channel failed to open or ended idle.
pub(crate) const PREWARM_DIALS_PER_REACK: usize = PREWARM_SLOTS + 1;
// The shortest bound on a request over a pre-warmed channel.
pub(crate) const PREWARM_EXCHANGE_FLOOR: Duration = Duration::from_secs(1);
// Log event of every pre-warm failure, with the refusing step.
const PREWARM_EVENT: &str = "reack_prewarm";
// S16l: tries of one channel or fresh request on the ACK connection: a
// stream its connection's end failed goes once more on the connection that
// replaces it (redialed under the same permit, or brought up meanwhile),
// then per-dial.
pub(crate) const LINK_TRIES: usize = 2;

/// Terminal order of a session that reached its packet engine, as traced.
#[cfg(test)]
pub(crate) const TEARDOWN: [&str; 8] = [
    "bridge_stop",
    "relay_join",
    "packet_join",
    "monitor_stop",
    "transport_close",
    "runtime_drop",
    "identity_drop",
    "store_guard_drop",
];

pub(crate) type Trace = Arc<dyn Fn(&'static str) + Send + Sync>;

/// What one provider epoch pins across its sessions (S17).
///
/// The relay interface: the first session resolves it before any network
/// settings exist and pins it here; every session rebuilt in that epoch binds
/// its relay sockets to the pinned interface and never resolves again, as a
/// route lookup under the applied full-wide settings would name the tunnel.
///
/// The last admission's validity window: when a rebuild's identity admission
/// is refused while the wall clock lies outside it (the certificate expired,
/// or the clock moved back before that admission), the refusal is a
/// validity miss, never tampering: recoverable, so the tunnel stays blocked.
#[derive(Clone, Default)]
pub(crate) struct EpochPins(Arc<Mutex<Pins>>);
#[derive(Default)]
struct Pins {
    interface: Option<RelayInterface>,
    // The process-global filter arm that currently owns this epoch. A stale
    // session cannot amend a newer arm with an authenticated D5 descriptor.
    leak_arm: Option<crate::leak_guard::ArmToken>,
    web_ingress: HashMap<std::net::SocketAddr, usize>,
    udp_media: HashMap<std::net::SocketAddr, usize>,
    guard_revision: u64,
    // S18: counts re-pins; a session bound under an earlier one is stale.
    generation: u64,
    admitted: Option<Admitted>,
    auth_backoff: AuthBackoff,
    // S23: the epoch's certificate renewal state.
    renewal: RenewalHandle,
    // S20b: the relay and enrollment-authority endpoints the epoch's
    // sessions dial, recorded before their first dial for the leak guard
    // (v31: it arms the relay only; the authority is for the renewal
    // monitor's guard check).
    guard: Option<GuardEndpoints>,
    // S16o: the TCP flows a lost session's engine answered, which the next
    // session's engine resets towards the app.
    flows: FlowLedger,
    // v35: the stream-window mode this epoch's start asked for (its start
    // option, judged before any capture); every session's flow pool reads
    // it, a rebuilt one included. The next start sets its own.
    window: crate::configuration::WindowMode,
}

/// S20b: what the leak guard allows on a physical interface while the epoch
/// may have its settings applied: the relay. v31: `authority` is never
/// armed; the renewal monitor defers a renewal whose authority is not the
/// relay's own tuple. v40 (CP-D3 M1): `relays` is the profile's whole
/// carrier pool, every exact pin in profile order (one for a single-pin
/// profile), because any session of the epoch may run on any of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GuardEndpoints {
    pub(crate) relays: crate::leak_guard::PeerSet,
    pub(crate) base_len: u8,
    pub(crate) authority: Option<std::net::SocketAddr>,
}

/// One D5 stream's exact filter allowance. The final owner withdraws its
/// tuple; a second stream sharing the descriptor keeps its own reference.
#[must_use = "retain this lease for the complete web carrier lifetime"]
pub(crate) struct WebIngressLease<'a> {
    pins: EpochPins,
    gate: &'a crate::leak_guard::Gate,
    ingress: std::net::SocketAddr,
    generation: u64,
    revision: u64,
    dynamic: bool,
}

impl Drop for WebIngressLease<'_> {
    fn drop(&mut self) {
        if !self.dynamic {
            return;
        }
        self.pins
            .release_web_ingress_on(self.gate, self.generation, self.revision, self.ingress);
    }
}

/// One ICE candidate's exact UDP permission. The broker/media owner keeps
/// this through the whole peer lifetime; re-pin or new guard removes it
/// earlier and a stale drop cannot affect a replacement session.
#[must_use = "retain until the media peer and all its sockets have ended"]
#[allow(dead_code)] // D6 admission waits for the complete media session owner.
pub(crate) struct UdpMediaLease<'a> {
    pins: EpochPins,
    gate: &'a crate::leak_guard::Gate,
    candidate: std::net::SocketAddr,
    generation: u64,
    revision: u64,
}

// Remote trickle may repeat an authenticated tuple indefinitely. A bounded
// reference count retains concurrent owners without unbounded lease memory.
const MAX_UDP_MEDIA_LEASES_PER_PIN: usize = 256;

impl Drop for UdpMediaLease<'_> {
    fn drop(&mut self) {
        self.pins
            .release_udp_media_on(self.gate, self.generation, self.revision, self.candidate);
    }
}

impl GuardEndpoints {
    /// The guard of a single-pin profile.
    #[cfg(test)]
    pub(crate) fn one(
        relay: std::net::SocketAddr,
        authority: Option<std::net::SocketAddr>,
    ) -> Self {
        Self {
            relays: crate::leak_guard::PeerSet::one(Some(relay.into())),
            base_len: 1,
            authority,
        }
    }

    /// The guard of a carrier pool: every pin, exactly; None when the pool
    /// exceeds the gate's bound (never a truncated allowance).
    pub(crate) fn pool(
        pins: &[std::net::SocketAddr],
        authority: Option<std::net::SocketAddr>,
    ) -> Option<Self> {
        let peers: Vec<crate::leak_guard::Peer> = pins.iter().map(|pin| (*pin).into()).collect();
        let relays = crate::leak_guard::PeerSet::new(&peers)?;
        Some(Self {
            base_len: relays.len() as u8,
            relays,
            authority,
        })
    }
}
impl EpochPins {
    pub(crate) fn set_leak_arm(&self, token: crate::leak_guard::ArmToken) {
        self.pins().leak_arm = Some(token);
    }

    pub(crate) fn authorize_web_ingress(
        &self,
        generation: u64,
        ingress: std::net::SocketAddr,
    ) -> Option<WebIngressLease<'static>> {
        self.authorize_web_ingress_on(&crate::leak_guard::LEAK_GUARD, generation, ingress)
    }

    fn authorize_web_ingress_on<'a>(
        &self,
        gate: &'a crate::leak_guard::Gate,
        generation: u64,
        ingress: std::net::SocketAddr,
    ) -> Option<WebIngressLease<'a>> {
        if ingress.port() == 0 || ingress.ip().is_unspecified() || ingress.ip().is_multicast() {
            return None;
        }
        let mut pins = self.pins();
        if pins.generation != generation || pins.interface.is_none() {
            return None;
        }
        let mut guard = pins.guard?;
        let dynamic =
            !guard.relays.as_slice()[..usize::from(guard.base_len)].contains(&ingress.into());
        let mut members = guard.relays.as_slice().to_vec();
        members.push(ingress.into());
        let extended = crate::leak_guard::PeerSet::new(&members)?;
        let already_held = pins.web_ingress.contains_key(&ingress);
        if gate.guarding_now() {
            let token = pins.leak_arm?;
            if !gate.amend_tcp_pin(token, ingress) {
                return None;
            }
        }
        if gate.dial_refused(ingress) {
            if dynamic && !already_held {
                if let Some(token) = pins.leak_arm {
                    let _ = gate.withdraw_tcp_pin(token, ingress);
                }
            }
            return None;
        }
        guard.relays = extended;
        pins.guard = Some(guard);
        if dynamic {
            *pins.web_ingress.entry(ingress).or_default() += 1;
        }
        Some(WebIngressLease {
            pins: self.clone(),
            gate,
            ingress,
            generation,
            revision: pins.guard_revision,
            dynamic,
        })
    }

    fn release_web_ingress_on(
        &self,
        gate: &crate::leak_guard::Gate,
        generation: u64,
        revision: u64,
        ingress: std::net::SocketAddr,
    ) {
        let mut pins = self.pins();
        // A prior physical generation never releases a new generation's
        // identically numbered tuple or its refcount.
        if pins.generation != generation || pins.guard_revision != revision {
            return;
        }
        let Some(count) = pins.web_ingress.get_mut(&ingress) else {
            return;
        };
        *count -= 1;
        if *count != 0 {
            return;
        }
        pins.web_ingress.remove(&ingress);
        if let Some(mut guard) = pins.guard {
            let kept: Vec<_> = guard
                .relays
                .as_slice()
                .iter()
                .copied()
                .filter(|pin| *pin != ingress.into())
                .collect();
            if let Some(reduced) = crate::leak_guard::PeerSet::new(&kept) {
                guard.relays = reduced;
                pins.guard = Some(guard);
            }
        }
        if let Some(token) = pins.leak_arm {
            let _ = gate.withdraw_tcp_pin(token, ingress);
        }
    }

    /// Admit a whole authenticated SDP/trickle batch before the WebRTC
    /// backend sees any candidate. Partial additions are rolled back by
    /// their leases on refusal; the caller must retain all successful leases.
    #[allow(dead_code)] // D6 admission waits for the composite media owner.
    pub(crate) fn authorize_udp_media(
        &self,
        generation: u64,
        interface: &RelayInterface,
        candidates: &[std::net::SocketAddr],
    ) -> Option<Vec<UdpMediaLease<'static>>> {
        self.authorize_udp_media_on(
            &crate::leak_guard::LEAK_GUARD,
            generation,
            interface,
            candidates,
        )
    }

    fn authorize_udp_media_on<'a>(
        &self,
        gate: &'a crate::leak_guard::Gate,
        generation: u64,
        interface: &RelayInterface,
        candidates: &[std::net::SocketAddr],
    ) -> Option<Vec<UdpMediaLease<'a>>> {
        if candidates.len() > crate::leak_guard::MAX_RELAY_PINS || !gate.guarding_now() {
            return None;
        }
        let mut leases = Vec::with_capacity(candidates.len());
        for &candidate in candidates {
            if candidate.port() == 0
                || candidate.ip().is_unspecified()
                || candidate.ip().is_multicast()
            {
                return None;
            }
            let mut pins = self.pins();
            if pins.generation != generation || pins.interface.as_ref() != Some(interface) {
                return None;
            }
            if pins
                .udp_media
                .get(&candidate)
                .is_some_and(|count| *count >= MAX_UDP_MEDIA_LEASES_PER_PIN)
            {
                return None;
            }
            let token = pins.leak_arm?;
            if !gate.amend_udp_media(token, candidate) {
                return None;
            }
            *pins.udp_media.entry(candidate).or_default() += 1;
            leases.push(UdpMediaLease {
                pins: self.clone(),
                gate,
                candidate,
                generation,
                revision: pins.guard_revision,
            });
        }
        Some(leases)
    }

    #[allow(dead_code)] // Called by the D6 lease drop once the media owner is linked.
    fn release_udp_media_on(
        &self,
        gate: &crate::leak_guard::Gate,
        generation: u64,
        revision: u64,
        candidate: std::net::SocketAddr,
    ) {
        let mut pins = self.pins();
        if pins.generation != generation || pins.guard_revision != revision {
            return;
        }
        let Some(count) = pins.udp_media.get_mut(&candidate) else {
            return;
        };
        *count -= 1;
        if *count == 0 {
            pins.udp_media.remove(&candidate);
            if let Some(token) = pins.leak_arm {
                let _ = gate.withdraw_udp_media(token, candidate);
            }
        }
    }
    /// v31: a fresh epoch whose renewal state is `renewal` (the provider
    /// start's process-carried handle, `RenewalHandle::process`).
    pub(crate) fn with_renewal(renewal: RenewalHandle) -> Self {
        Self(Arc::new(Mutex::new(Pins {
            renewal,
            ..Pins::default()
        })))
    }

    fn pins(&self) -> std::sync::MutexGuard<'_, Pins> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn get(&self) -> Option<RelayInterface> {
        self.pins().interface.clone()
    }

    /// The re-pins so far: a session binds under one, and is stale once it
    /// changed.
    pub(crate) fn generation(&self) -> u64 {
        self.pins().generation
    }

    /// The pinned interface and the re-pin it belongs to, read together.
    fn current(&self) -> (Option<RelayInterface>, u64) {
        let pins = self.pins();
        (pins.interface.clone(), pins.generation)
    }

    /// Pin `interface` unless one is pinned already; the first one stays.
    fn pin(&self, interface: &RelayInterface) {
        self.pins()
            .interface
            .get_or_insert_with(|| interface.clone());
    }

    /// S18: replace the pinned interface after a physical path change. Only
    /// sessions built afterwards bind to it; the running one is rebuilt, and
    /// one still constructing on the old pin never becomes Ready. The old
    /// session's relay sessions cannot be closed over the lost interface or
    /// address, so they are counted as stranded (`AuthBackoff::strand_current`).
    pub(crate) fn repin(&self, interface: &RelayInterface) {
        let auth_backoff = {
            let mut pins = self.pins();
            if let Some(token) = pins.leak_arm {
                for ingress in pins.web_ingress.keys().copied() {
                    let _ = crate::leak_guard::LEAK_GUARD.withdraw_tcp_pin(token, ingress);
                }
                for candidate in pins.udp_media.keys().copied() {
                    let _ = crate::leak_guard::LEAK_GUARD.withdraw_udp_media(token, candidate);
                }
            }
            pins.web_ingress.clear();
            pins.udp_media.clear();
            pins.guard = None;
            pins.leak_arm = None;
            pins.guard_revision = pins.guard_revision.wrapping_add(1);
            pins.interface = Some(interface.clone());
            pins.generation = pins.generation.wrapping_add(1);
            pins.auth_backoff.clone()
        };
        auth_backoff.strand_current(Instant::now());
    }

    /// v35: this epoch's stream-window mode, set by its start before the
    /// factory runs (`apple::start_window_mode`).
    pub(crate) fn set_window_mode(&self, mode: crate::configuration::WindowMode) {
        self.pins().window = mode;
    }

    /// v35: the stream-window mode every flow pool of this epoch is built
    /// with (`FlowPool::with_limits`). v36: Fixed (the default) unless the
    /// start asked for the v35 window (`adaptive`).
    pub(crate) fn window_mode(&self) -> crate::configuration::WindowMode {
        self.pins().window
    }

    /// S16o: the epoch's flow ledger, shared by every session's engine.
    pub(crate) fn flow_ledger(&self) -> FlowLedger {
        self.pins().flows.clone()
    }

    /// The authentication backoff every session of this epoch observes.
    pub(crate) fn auth_backoff(&self) -> AuthBackoff {
        self.pins().auth_backoff.clone()
    }

    /// The window of this epoch's last admitted identity.
    pub(crate) fn admitted(&self) -> Option<Admitted> {
        self.pins().admitted
    }

    /// Record an admission at `at` of a certificate valid over
    /// `(not_before, not_after)`. The latest admission replaces the earlier
    /// one (a renewed identity), and the renewal monitor schedules from it.
    fn admit(&self, at: u64, (not_before, not_after): (u64, u64)) {
        let renewal = {
            let mut pins = self.pins();
            pins.admitted = Some(Admitted {
                at,
                not_before,
                not_after,
            });
            pins.renewal.clone()
        };
        renewal.with(|state| state.admitted(not_before, not_after));
    }

    /// S23: the epoch's certificate renewal state.
    pub(crate) fn renewal(&self) -> RenewalHandle {
        self.pins().renewal.clone()
    }

    /// S20b: record the endpoints a session of this epoch dials. The
    /// newest session's record replaces an earlier one.
    pub(crate) fn set_guard(&self, guard: GuardEndpoints) {
        let mut pins = self.pins();
        if let Some(token) = pins.leak_arm {
            for ingress in pins.web_ingress.keys().copied() {
                let _ = crate::leak_guard::LEAK_GUARD.withdraw_tcp_pin(token, ingress);
            }
            for candidate in pins.udp_media.keys().copied() {
                let _ = crate::leak_guard::LEAK_GUARD.withdraw_udp_media(token, candidate);
            }
        }
        pins.web_ingress.clear();
        pins.udp_media.clear();
        pins.leak_arm = None;
        pins.guard_revision = pins.guard_revision.wrapping_add(1);
        pins.guard = Some(guard);
    }

    /// S20b: the endpoints the leak guard allows for this epoch, once a
    /// session recorded them.
    pub(crate) fn guard(&self) -> Option<GuardEndpoints> {
        self.pins().guard
    }

    /// Test-only: an epoch whose interface is already pinned.
    #[cfg(test)]
    pub(crate) fn pinned_for_test(interface: RelayInterface) -> Self {
        let pins = Self::default();
        pins.pin(&interface);
        pins
    }

    /// Test-only: replace the admitted window, as the passage of time would.
    #[cfg(test)]
    pub(crate) fn admit_for_test(&self, at: u64, not_after: u64) {
        self.admit(at, (at, not_after));
    }
}

/// Test hook: the session's armed relay services and their gate.
#[cfg(test)]
pub(crate) type Armed = Arc<dyn Fn(Arc<HeldRelayServices>, Arc<WorkGate>) + Send + Sync>;

#[derive(Clone)]
struct Steps {
    trace: Option<Trace>,
    pinned: EpochPins,
    #[cfg(test)]
    armed: Option<Armed>,
    #[cfg(test)]
    prewarm_max_age: Option<Duration>,
    // Test-only relay interface override: loopback test relays sit on lo0,
    // which production resolution refuses. None resolves as production does.
    #[cfg(test)]
    relay_interface: Option<RelayInterface>,
    // S16l, test-only: whether the ACK path keeps its persistent ACK
    // connection, as production always does. The first-stream-only test
    // relay (`TestRelay::spawn_each`) serves one ACK per connection, so the
    // tests built on it run the per-dial path the ACK path falls back to;
    // the tests of the persistent connection run on the multi-stream relay.
    #[cfg(test)]
    ack_link: bool,
    // Test-only: every renewal, how it reached the relay and how long after
    // its request was bound it renewed the lease.
    #[cfg(test)]
    renewals: Option<Renewals>,
    // Test-only: where the session's ACK connection is handed once made.
    #[cfg(test)]
    link_slot: Option<LinkSlot>,
    // Test-only (S16m): how long each fresh re-ACK dial's TCP connect is
    // held before it starts, as a SYN retransmit would hold it.
    #[cfg(test)]
    fresh_connect_delay: Option<Duration>,
}

/// Test-only: a session's ACK connection, once made.
#[cfg(test)]
pub(crate) type LinkSlot = Arc<Mutex<Option<Arc<AckLink>>>>;

/// Test-only: renewals as `Steps::renewed` records them.
#[cfg(test)]
pub(crate) type Renewals = Arc<Mutex<Vec<(&'static str, Duration)>>>;
impl Steps {
    fn traced(trace: Option<Trace>) -> Self {
        Self {
            trace,
            pinned: EpochPins::default(),
            #[cfg(test)]
            armed: None,
            #[cfg(test)]
            prewarm_max_age: None,
            #[cfg(test)]
            relay_interface: Some(RelayInterface::loopback_for_test()),
            #[cfg(test)]
            ack_link: false,
            #[cfg(test)]
            renewals: None,
            #[cfg(test)]
            link_slot: None,
            #[cfg(test)]
            fresh_connect_delay: None,
        }
    }

    /// Test-only (S16m): hold a fresh re-ACK dial's TCP connect for
    /// `fresh_connect_delay`; nothing in production.
    async fn hold_fresh_connect(&self) {
        #[cfg(test)]
        if let Some(delay) = self.fresh_connect_delay {
            tokio::time::sleep(delay).await;
        }
    }

    /// Test-only: hand the session's ACK connection to `link_slot`.
    #[cfg_attr(not(test), allow(unused_variables))]
    fn link_made(&self, link: &Arc<AckLink>) {
        #[cfg(test)]
        if let Some(slot) = &self.link_slot {
            *slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(link.clone());
        }
    }

    /// Test-only record of one renewal (`Renewals`).
    #[cfg_attr(not(test), allow(unused_variables))]
    fn renewed(&self, via: Via, latency: Duration) {
        #[cfg(test)]
        if let Some(renewals) = &self.renewals {
            renewals
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((via.code(), latency));
        }
    }

    /// S16l: whether the ACK path keeps a persistent ACK connection (always,
    /// outside the per-dial tests).
    fn ack_link(&self) -> bool {
        #[cfg(test)]
        return self.ack_link;
        #[cfg(not(test))]
        true
    }

    /// The interface every relay socket of this session is bound to: the
    /// epoch's pinned interface, or else the physical egress interface for
    /// `peer`, resolved before the first dial and pinned for the epoch; and
    /// the re-pin generation it was read under (`pin_current`).
    fn session_interface(
        &self,
        peer: std::net::SocketAddr,
    ) -> Result<(RelayInterface, u64), &'static str> {
        let (pinned, generation) = self.pinned.current();
        if let Some(pinned) = pinned {
            self.mark("relay_interface_pinned");
            return Ok((pinned, generation));
        }
        let resolved = self.relay_interface(peer)?;
        self.pinned.pin(&resolved);
        Ok((resolved, generation))
    }

    /// S18: no re-pin happened since this session bound its relay sockets
    /// under `generation`. Once one did, they are bound to a lost interface
    /// or address: the session never becomes Ready, and a Ready one seals.
    fn pin_current(&self, generation: u64) -> bool {
        self.pinned.generation() == generation
    }

    /// An admission refusal of `code`, judged against the epoch's last
    /// admitted validity window (S17): outside it, a validity miss.
    fn admission_refused(&self, code: &'static str) -> Exit {
        let now = aegis_core::secure_channel::registry::unix_now().ok();
        Exit::Refused(admission_refusal(code, self.pinned.admitted(), now))
    }

    /// Record this session's admitted identity as the epoch's window.
    fn admitted(&self, prepared: &PreparedLocalSession) {
        if let Ok(now) = aegis_core::secure_channel::registry::unix_now() {
            self.pinned.admit(now, prepared.admitted_window());
        }
    }

    fn relay_interface(&self, peer: std::net::SocketAddr) -> Result<RelayInterface, &'static str> {
        #[cfg(test)]
        if let Some(interface) = &self.relay_interface {
            return Ok(interface.clone());
        }
        relay_socket::resolve_relay_interface(peer)
    }

    fn prewarm_max_age(&self) -> Duration {
        #[cfg(test)]
        if let Some(age) = self.prewarm_max_age {
            return age;
        }
        PREWARM_MAX_AGE
    }

    fn mark(&self, step: &'static str) {
        if let Some(trace) = &self.trace {
            trace(step);
        }
    }

    #[cfg_attr(not(test), allow(unused_variables))]
    fn arm(&self, services: &Arc<HeldRelayServices>, gate: &Arc<WorkGate>) {
        #[cfg(test)]
        if let Some(armed) = &self.armed {
            armed(services.clone(), gate.clone());
        }
    }
}

/// The engine's event sink: flow events carry destinations and stay local.
struct NoEvents;
impl EventSink for NoEvents {
    fn emit(&self, _: &'static str, _: EngineEvent, _: &'static str, _: serde_json::Value) {}
}

/// S16j-3: the relay drain's first bounded attempt. A gate still holding
/// work then is logged once (`relay_drain_pending`), well before the
/// provider's stop budget ends the process, so a stop that overruns names
/// the stuck class.
pub(crate) const RELAY_DRAIN_FIRST: Duration = Duration::from_millis(500);
const _: () = assert!(RELAY_DRAIN_FIRST.as_millis() <= MAX_DRAIN.as_millis());
// The first drain attempt and the packet join's first slice leave the
// provider's stop budget at least this much for the remaining stages
// (monitor and ACK pre-warm joins, runtime and Store drop), which run in
// milliseconds once the relay drained; its exit 70 stays the backstop.
const STOP_MARGIN: Duration = Duration::from_millis(500);
const _: () = assert!(
    RELAY_DRAIN_FIRST.as_millis()
        + crate::store_scoped_packet::PACKET_JOIN_SLICE.as_millis()
        + STOP_MARGIN.as_millis()
        <= crate::apple::STOP_BUDGET.as_millis()
);

/// Stop the gate and wait until every flow and gate task has ended. A gate
/// that never drains keeps this thread, and so the Store, like a stuck engine
/// join does; the session then never reports Joined.
///
/// S16j-3: the wait drives the session's `runtime`. Its relay pre-dial and
/// the driver of the connection that pre-dial opened are gate tasks on it,
/// and an aborted task is dropped only when its runtime polls it: waiting
/// with this thread asleep never drained them (the v21 stop's exit 70).
fn join_relay(runtime: &Runtime, gate: &WorkGate, steps: &Steps) {
    drain_relay(runtime, gate, |tasks, flows| {
        // v41: two fields, each stable; one field with a space between the
        // counts was logged as `unstable_code`.
        crate::apple::log_fields(
            "relay_drain_pending",
            &[&format!("tasks:{tasks}"), &format!("flows:{flows}")],
        );
        steps.mark("relay_drain_pending");
    });
    steps.mark("relay_join");
}

/// `join_relay`'s wait: `pending` sees the gate's tasks and flows left after
/// the first bounded attempt, once, and the wait goes on until drained.
fn drain_relay(runtime: &Runtime, gate: &WorkGate, pending: impl FnOnce(usize, usize)) {
    if runtime.block_on(gate.stop_async(RELAY_DRAIN_FIRST)).is_ok() {
        return;
    }
    pending(gate.tasks_left(), gate.flows());
    while runtime.block_on(gate.stop_async(MAX_DRAIN)).is_err() {}
}

/// Why construction or the live session ended. A requested stop is not a
/// refusal; every other exit seals with its code.
enum Exit {
    Stopped,
    Refused(&'static str),
}
type Step<T> = Result<T, Exit>;

fn refused<T>(code: &'static str) -> Step<T> {
    Err(Exit::Refused(code))
}

struct Halt<'a> {
    control: &'a SessionControl,
    store_stop: &'a AtomicBool,
}
impl Halt<'_> {
    fn requested(&self) -> bool {
        self.control.stop_requested() || self.store_stop.load(Ordering::Acquire)
    }
    async fn wait(&self) {
        while !self.requested() {
            tokio::time::sleep(STOP_POLL).await;
        }
    }
}

/// The provider factory's constructor: returns at once with a Constructing
/// handle. `notifier` sees Ready or Sealed exactly once.
/// Every session of one provider epoch shares `pinned`.
pub(crate) fn start_session(
    saved: SavedProviderIntent,
    claim: CapturedAppGroupInputs,
    notifier: impl FnOnce(SessionPhase) + Send + 'static,
    pinned: EpochPins,
) -> io::Result<SessionHandle> {
    let bridge = LeasedPacketBridge::new(PacketBridge::default(), CaptureLeaseDeadline::default());
    let steps = Steps {
        pinned,
        ..Steps::traced(None)
    };
    spawn_steps(saved, claim, notifier, steps, bridge)
}

/// `start_session` with a trace and the test relay interface override;
/// `relay_interface: None` resolves (when nothing is pinned) as production.
#[cfg(test)]
pub(crate) fn spawn_pinned(
    saved: SavedProviderIntent,
    claim: CapturedAppGroupInputs,
    notifier: impl FnOnce(SessionPhase) + Send + 'static,
    trace: Option<Trace>,
    pinned: EpochPins,
    relay_interface: Option<RelayInterface>,
) -> io::Result<SessionHandle> {
    let bridge = LeasedPacketBridge::new(PacketBridge::default(), CaptureLeaseDeadline::default());
    let steps = Steps {
        pinned,
        relay_interface,
        ..Steps::traced(trace)
    };
    spawn_steps(saved, claim, notifier, steps, bridge)
}

#[cfg(test)]
fn spawn_traced(
    saved: SavedProviderIntent,
    claim: CapturedAppGroupInputs,
    notifier: impl FnOnce(SessionPhase) + Send + 'static,
    trace: Option<Trace>,
) -> io::Result<SessionHandle> {
    // No deadline: every packet operation is refused until the ACK lease.
    let bridge = LeasedPacketBridge::new(PacketBridge::default(), CaptureLeaseDeadline::default());
    spawn_on_bridge(saved, claim, notifier, trace, bridge)
}

#[cfg(test)]
pub(crate) fn spawn_on_bridge(
    saved: SavedProviderIntent,
    claim: CapturedAppGroupInputs,
    notifier: impl FnOnce(SessionPhase) + Send + 'static,
    trace: Option<Trace>,
    bridge: LeasedPacketBridge,
) -> io::Result<SessionHandle> {
    spawn_steps(saved, claim, notifier, Steps::traced(trace), bridge)
}

/// `spawn_on_bridge`, also handing the armed services and gate to `armed`.
#[cfg(test)]
pub(crate) fn spawn_armed(
    saved: SavedProviderIntent,
    claim: CapturedAppGroupInputs,
    notifier: impl FnOnce(SessionPhase) + Send + 'static,
    trace: Option<Trace>,
    bridge: LeasedPacketBridge,
    armed: Armed,
) -> io::Result<SessionHandle> {
    let steps = Steps {
        armed: Some(armed),
        ..Steps::traced(trace)
    };
    spawn_steps(saved, claim, notifier, steps, bridge)
}

/// S16l, test-only: how `spawn_link` runs a session.
#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct LinkOptions {
    /// Whether the ACK path keeps its persistent ACK connection
    /// (production's ACK path, on the multi-stream relay) or runs per-dial.
    pub(crate) per_dial: bool,
    pub(crate) armed: Option<Armed>,
    /// The epoch's pins; fresh ones when None.
    pub(crate) pinned: Option<EpochPins>,
    pub(crate) renewals: Option<Renewals>,
    pub(crate) prewarm_max_age: Option<Duration>,
    pub(crate) link_slot: Option<LinkSlot>,
    pub(crate) fresh_connect_delay: Option<Duration>,
}

/// S16l: `spawn_armed` with the persistent ACK connection unless
/// `options.per_dial`, on `options`.
#[cfg(test)]
pub(crate) fn spawn_link(
    saved: SavedProviderIntent,
    claim: CapturedAppGroupInputs,
    notifier: impl FnOnce(SessionPhase) + Send + 'static,
    (trace, bridge): (Option<Trace>, LeasedPacketBridge),
    options: LinkOptions,
) -> io::Result<SessionHandle> {
    let LinkOptions {
        per_dial,
        armed,
        pinned,
        renewals,
        prewarm_max_age,
        link_slot,
        fresh_connect_delay,
    } = options;
    let steps = Steps {
        armed,
        ack_link: !per_dial,
        pinned: pinned.unwrap_or_default(),
        renewals,
        prewarm_max_age,
        link_slot,
        fresh_connect_delay,
        ..Steps::traced(trace)
    };
    spawn_steps(saved, claim, notifier, steps, bridge)
}

/// `spawn_on_bridge` with a test bound on a pre-warmed channel's age.
#[cfg(test)]
pub(crate) fn spawn_with_prewarm_age(
    saved: SavedProviderIntent,
    claim: CapturedAppGroupInputs,
    notifier: impl FnOnce(SessionPhase) + Send + 'static,
    trace: Option<Trace>,
    bridge: LeasedPacketBridge,
    prewarm_max_age: Duration,
) -> io::Result<SessionHandle> {
    let steps = Steps {
        prewarm_max_age: Some(prewarm_max_age),
        ..Steps::traced(trace)
    };
    spawn_steps(saved, claim, notifier, steps, bridge)
}

/// `spawn_on_bridge` with `relay_interface` as the test override; None
/// resolves the session's relay interface exactly as production does.
#[cfg(test)]
pub(crate) fn spawn_on_interface(
    saved: SavedProviderIntent,
    claim: CapturedAppGroupInputs,
    notifier: impl FnOnce(SessionPhase) + Send + 'static,
    trace: Option<Trace>,
    bridge: LeasedPacketBridge,
    relay_interface: Option<RelayInterface>,
) -> io::Result<SessionHandle> {
    let steps = Steps {
        relay_interface,
        ..Steps::traced(trace)
    };
    spawn_steps(saved, claim, notifier, steps, bridge)
}

fn spawn_steps(
    saved: SavedProviderIntent,
    claim: CapturedAppGroupInputs,
    notifier: impl FnOnce(SessionPhase) + Send + 'static,
    steps: Steps,
    bridge: LeasedPacketBridge,
) -> io::Result<SessionHandle> {
    SessionHandle::spawn(bridge, notifier, move |control| {
        supervise(control, claim, saved, steps)
    })
}

/// Session-thread body: own the one Store-last worker until it has returned.
fn supervise(
    control: &SessionControl,
    claim: CapturedAppGroupInputs,
    saved: SavedProviderIntent,
    steps: Steps,
) -> Result<(), &'static str> {
    let worker = control.clone();
    let mut owner = StoreLastThreadOwner::spawn(Some(claim), move |claim, store_stop| {
        let claim = claim.take().ok_or(io::ErrorKind::InvalidInput)?;
        let halt = Halt {
            control: &worker,
            store_stop: &store_stop,
        };
        match run_worker(claim, saved, &halt, &steps) {
            Ok(()) | Err(Exit::Stopped) => Ok(()),
            Err(Exit::Refused(code)) => {
                worker.seal(code);
                Err(io::Error::new(io::ErrorKind::PermissionDenied, code))
            }
        }
    })
    .map_err(|_| "session_spawn_failed")?;
    while !control.stop_requested() && !owner.finished() {
        // SessionHandle::seal unparks this thread.
        thread::park_timeout(Duration::from_millis(5));
    }
    loop {
        let joined = owner.stop_and_join(MAX_JOIN);
        if owner.worker_panicked() {
            // Unwinding dropped, but did not join, the worker's children: keep
            // the session Sealed and never terminal.
            std::panic::resume_unwind(Box::new("session worker panicked"));
        }
        match joined {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::TimedOut => continue,
            // The worker sealed with its own code before returning.
            Err(_) => return Err("session_worker_refused"),
        }
    }
}

/// The protected Store lock, released only by a normal return. Unwinding
/// drops, but does not join, the packet engine and its watchdog, so a worker
/// that panics keeps the Store locked for the life of the process: no other
/// owner may open it while those detached children can still run.
struct StoreHeldOnUnwind(Option<Arc<ProtectedOnlineExpectation<'static>>>);
impl Drop for StoreHeldOnUnwind {
    fn drop(&mut self) {
        if thread::panicking() {
            if let Some(store) = self.0.take() {
                std::mem::forget(store);
            }
        }
    }
}

/// Store-last worker. `store_guard` is the protected Store lock: it is
/// released last, after the runtime and every transport it drove.
fn run_worker(
    claim: CapturedAppGroupInputs,
    saved: SavedProviderIntent,
    halt: &Halt<'_>,
    steps: &Steps,
) -> Step<()> {
    // 0. S23: a held receipt already past its `not_after` is an expired
    // identity, judged before the Store opens: recoverable and blocked,
    // never the terminal refusal of a tampered identity.
    let now = aegis_core::secure_channel::registry::unix_now().ok();
    if now.is_some_and(|now| now >= claim.held_window().1) {
        return refused("session_identity_expired");
    }
    // 1. Store, signed bundle and held crypto under the one claim.
    // A refusal outside the epoch's admitted window is a validity miss
    // (recoverable under S17); inside it, the held identity is refused.
    let (prepared, store_guard) = PreparedLocalSession::from_claim_with_store_guard(claim)
        .map_err(|_| steps.admission_refused("session_identity_refused"))?;
    steps.admitted(&prepared);
    let store_guard = StoreHeldOnUnwind(Some(store_guard));
    let result = run_prepared(prepared, saved, halt, steps);
    drop(store_guard);
    steps.mark("store_guard_drop");
    result
}

fn run_prepared(
    prepared: PreparedLocalSession,
    saved: SavedProviderIntent,
    halt: &Halt<'_>,
    steps: &Steps,
) -> Step<()> {
    // 2. Only the saved relay may be dialed. v40 (CP-D3 M1): the saved
    // intent names the signed pool's primary pin; a session dials one pin of
    // that pool (`run_on_runtime`), the primary until it selects another.
    let peer = prepared
        .pinned_peer()
        .map_err(|_| Exit::Refused("session_peer_refused"))?;
    if peer != prepared.primary_peer() || peer.ip() != saved.policy.relay() {
        return refused("session_peer_mismatch");
    }
    // S20b: the leak guard allows exactly this relay endpoint once the
    // settings may be applied. v31: the held profile's enrollment authority
    // is recorded beside it only for the renewal monitor, which compares it
    // with the armed relay tuples; the guard no longer allows it. v40: every
    // exact pin of the signed pool, and nothing else, since any session of
    // the epoch may run on any of them.
    let guard = GuardEndpoints::pool(&prepared.carrier_pins(), prepared.authority_address())
        .ok_or(Exit::Refused("session_peer_refused"))?;
    steps.pinned.set_guard(guard);
    // 2b. The saved intent must derive the held signed binding before any
    // dial: a local binding mismatch is its own (terminal, S17) refusal,
    // never mistaken for a relay's ACK refusal. The ACK derives it again.
    let mut prepared = prepared;
    if prepared.derive_runtime(&saved).is_err() {
        return Err(steps.admission_refused("session_binding_refused"));
    }
    if halt.requested() {
        return Err(Exit::Stopped);
    }
    // 2a. The relay's physical egress interface, before the first dial and
    // before any network settings exist; every relay socket is bound to it.
    // A rebuilt session uses the epoch's pinned interface instead. v40: the
    // primary pin's egress carries every pin of the pool.
    let (interface, pin) = steps.session_interface(peer).map_err(|code| {
        crate::apple::log_code("session_relay_interface", code);
        Exit::Refused(code)
    })?;
    relay_socket::log_interface(&interface);
    steps.mark("relay_interface");
    // 3.
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| Exit::Refused("session_runtime_failed"))?;
    let (identity, result) = run_on_runtime(
        &runtime,
        prepared,
        saved,
        (peer, interface, pin),
        halt,
        steps,
    );
    // Blocking shutdown: a pending task keeps this thread, and so the Store.
    drop(runtime);
    steps.mark("runtime_drop");
    drop(identity);
    steps.mark("identity_drop");
    result
}

// Installed diagnosis only: the errno (or io kind) of a refused relay dial,
// never an address or any identity material.
fn log_dial_failure(event: &str, error: &std::io::Error) {
    let code = match error.raw_os_error() {
        Some(errno) => format!("errno:{errno}"),
        None => format!("kind:{:?}", error.kind()).to_ascii_lowercase(),
    };
    crate::apple::log_code(event, &code);
}

fn log_connect_failure(error: &std::io::Error) {
    log_dial_failure("session_connect", error);
}

// Installed diagnosis only: the ACK validity the relay granted, in ms.
fn log_valid_for(event: &str, valid_for: Duration) {
    crate::apple::log_code(event, &format!("ms:{}", valid_for.as_millis()));
}

fn run_on_runtime(
    runtime: &Runtime,
    prepared: PreparedLocalSession,
    saved: SavedProviderIntent,
    (primary, interface, pin): (std::net::SocketAddr, RelayInterface, u64),
    halt: &Halt<'_>,
    steps: &Steps,
) -> (Option<CapturedLocalIdentity>, Step<()>) {
    // 4. Dial and observe the ACK; stop wins over every pending step. The
    // first ACK's establishment holds an ACK permit from before its dial
    // until its PolicyAck; an epoch backoff in force delays it.
    let limiter = EstablishLimiter::new(steps.pinned.auth_backoff());
    // The session's gate: every relay connection's driver is one of its
    // tasks (S16h: the flow pool's; S16l: the ACK connection's from its
    // first ACK on), and every exit drains it.
    let gate = WorkGate::new();
    // v40 (CP-D3 M1): this build's attempt order over the signed pool, from
    // the profile's failover controller on the current access network (the
    // profile order and no learning for a single pin). The build dials one
    // pin at a time: a typed pre-authentication failure of its first ACK's
    // outer carrier (no identity, PolicyAck or target sent yet) moves it to
    // the next pin; any other failure ends it as before.
    let carriers = match prepared.carrier_plan(crate::carrier_network::current()) {
        Ok(carriers) => carriers,
        Err(_) => {
            close_gate(runtime, &gate);
            return (None, refused("session_peer_refused"));
        }
    };
    let _ = primary;
    let bridge = halt.control.bridge().clone();
    let mut prepared = prepared;
    let mut opened = None;
    for (attempt, &carrier) in carriers.order().iter().enumerate() {
        let more = attempt + 1 < carriers.order().len();
        let ticket = carriers.ticket(carrier);
        // The held crypto is not shared yet (every earlier attempt's link,
        // pre-warms and connections were dropped and joined), so one
        // session never dials two pins at once.
        if prepared.select_carrier(carrier, ticket.clone()).is_err() {
            close_gate(runtime, &gate);
            return (None, refused("session_peer_refused"));
        }
        let peer = match prepared.pinned_peer() {
            Ok(peer) => peer,
            Err(_) => {
                close_gate(runtime, &gate);
                return (None, refused("session_peer_refused"));
            }
        };
        if attempt > 0 {
            crate::apple::log_fields(
                "carrier_failover",
                &["attempt", &format!("carrier:{carrier}")],
            );
        }
        let link = steps
            .ack_link()
            .then(|| {
                prepared.ack_link(
                    &interface,
                    (limiter.clone(), gate.clone()),
                    (steps.pinned.clone(), pin),
                    steps.trace.clone(),
                )
            })
            .and_then(Result::ok);
        if let Some(link) = &link {
            steps.link_made(link);
        }
        steps.mark("dial");
        // S16m: the wake generation the first ACK is dialed under; verified,
        // it proves the flow pool on it (`FlowPool::prove_by_session_ack`).
        let ack_wake = limiter.wake_generation();
        let first = runtime.block_on(async {
            tokio::select! {
                biased;
                _ = halt.wait() => Err(Exit::Stopped),
                connected = first_dial(&limiter, &prepared, peer, &interface, link.as_ref(), &steps.pinned, pin, &gate) => connected,
            }
        });
        let (first, first_permit) = match first {
            Ok(first) => first,
            // The pin failed before authentication: the next pin, if any.
            Err(Exit::Refused(_)) if prepared.carrier_failed() && more => {
                drop(link);
                continue;
            }
            Err(exit) => {
                drop(link);
                close_gate(runtime, &gate);
                return (None, Err(exit));
            }
        };
        // 4a. The first re-ACKs' channels open now, so their setup overlaps
        // the first ACK's own (S16l: as streams of the ACK connection the
        // first ACK brought up); a refusal here (the ACK below refuses too)
        // leaves them to the monitor. Whatever happens next, every task is
        // joined.
        let mut pool = Pool::new(limiter.clone(), link.clone());
        if let Ok(opener) = prepared.begin_first_prewarm(&saved, &interface) {
            for _ in 0..PREWARM_SLOTS {
                if pool.may_dial() {
                    pool.start(runtime.handle(), opener.clone(), steps);
                }
            }
        }
        // Bridge clock first: the lease is measured from no later than the
        // request on the runtime clock that bounds the ACK.
        let Ok(ns) = bridge.clock_ns() else {
            runtime.block_on(pool.join(steps));
            drop((first, first_permit, link));
            close_gate(runtime, &gate);
            return (None, refused("session_clock_failed"));
        };
        let requested = RequestClock {
            ns,
            at: tokio::time::Instant::now(),
        };
        // v40: the first ACK's outer carrier (outer TLS and ECH, HTTP/2, the
        // carrier's 200) before the prepared identity is used.
        let carried = runtime.block_on(async {
            tokio::select! {
                biased;
                _ = halt.wait() => Err(Exit::Stopped),
                carried = first_carrier(&limiter, &prepared, first, link.as_ref(), &interface, &steps.pinned, pin) => carried,
            }
        });
        match carried {
            Ok(first) => {
                opened = Some((
                    (first, first_permit),
                    (link, pool),
                    (requested, ack_wake),
                    ticket,
                    peer,
                ));
                break;
            }
            Err(exit) => {
                drop(first_permit);
                // Its pre-warms dial the same pin: joined before any other.
                runtime.block_on(pool.join(steps));
                drop(link);
                if matches!(exit, Exit::Refused(_)) && prepared.carrier_failed() && more {
                    continue;
                }
                close_gate(runtime, &gate);
                return (None, Err(exit));
            }
        }
    }
    drop(carriers);
    let Some(((first, first_permit), (link, mut pool), (requested, ack_wake), ticket, peer)) =
        opened
    else {
        close_gate(runtime, &gate);
        return (None, refused("session_connect_failed"));
    };
    let observed = runtime.block_on(async {
        let observe = async {
            match first {
                Carried::Held(held, deadline) => {
                    prepared
                        .observe_ack_on_held(saved, held, peer, interface, deadline)
                        .await
                }
                Carried::Link(conn, carrier, deadline) => {
                    let Some(link) = link.as_ref() else {
                        return Err(io::ErrorKind::PermissionDenied.into());
                    };
                    let on = conn.0.clone();
                    let limit = deadline.saturating_duration_since(tokio::time::Instant::now());
                    let observed = prepared
                        .observe_ack_on_link_carrier(
                            saved,
                            link,
                            conn,
                            Some(carrier),
                            interface,
                            limit,
                        )
                        .await;
                    if let Err(error) = &observed {
                        link.failed(&on, error);
                    }
                    observed
                }
            }
        };
        tokio::select! {
            biased;
            _ = halt.wait() => Err(Exit::Stopped),
            observed = observe => {
                observed.map_err(|error| {
                    limiter.judge(Purpose::Ack, &error);
                    Exit::Refused("session_ack_refused")
                })
            }
        }
    });
    // An ACK failure has consumed the prepared identity inside its future;
    // `store_guard` still holds the Store until after runtime shutdown.
    let observed = match observed {
        Ok(observed) => {
            first_permit.succeeded();
            // v40: the outer carrier and the device's inner authentication
            // opened the session on this pin.
            if let Some(ticket) = &ticket {
                ticket.opened();
            }
            observed
        }
        Err(exit) => {
            drop(first_permit);
            runtime.block_on(pool.join(steps));
            drop(link);
            close_gate(runtime, &gate);
            return (None, Err(exit));
        }
    };
    drop(link);
    // Whatever `run_observed` returns, a task it did not hand to the monitor
    // is joined here; it drains the gate on every path.
    let (observed, result) = run_observed(
        runtime,
        observed,
        &bridge,
        (requested, ack_wake),
        (&mut pool, gate),
        (pin, ticket.as_ref()),
        halt,
        steps,
    );
    runtime.block_on(pool.join(steps));
    let identity = observed.map(|observed| {
        let identity = observed.close_transport_keep_store();
        steps.mark("transport_close");
        identity
    });
    (identity, result)
}

/// Drain the session's gate on an exit before its relay services exist: at
/// most the ACK connection's driver (S16l) is a task of it.
fn close_gate(runtime: &Runtime, gate: &WorkGate) {
    drain_relay(runtime, gate, |_, _| {});
}

/// How the first ACK reaches the relay: a socket of its own, or (S16l) a
/// stream of the session's ACK connection it brought up.
enum First {
    Tcp(tokio::net::TcpStream),
    Link(LinkConn),
    #[cfg(feature = "enrolled-quic")]
    Quic(crate::prepared_crypto::HeldOuter, tokio::time::Instant),
}

/// v40: the first ACK's outer carrier, opened to the build's pin (its 200
/// included) before any device identity: on a socket of its own, or as a
/// carrier stream of the ACK connection. The deadline is the first ACK's
/// one `connect_timeout_ms`, counted from that carrier's start.
enum Carried {
    Held(crate::prepared_crypto::HeldOuter, tokio::time::Instant),
    Link(
        LinkConn,
        crate::flow_pool::PooledCarrier,
        tokio::time::Instant,
    ),
}

/// The first ACK's dial under its ACK permit. Its wait covers an epoch
/// backoff in force plus the connect budget. S16l: with an ACK connection,
/// the dial brings that connection up under the same permit; when it does
/// not come up short of an authentication-class refusal, the first ACK
/// falls back to a socket of its own. v40 (CP-D3 M1): a refused or timed
/// out TCP dial is the pin's carrier fault, and a pin whose ACK connection
/// failed so gets no per-dial fallback: the build moves on to the next pin
/// (`run_on_runtime`).
#[allow(clippy::too_many_arguments)] // Each argument is a distinct session owner, as above.
async fn first_dial(
    limiter: &Arc<EstablishLimiter>,
    prepared: &PreparedLocalSession,
    peer: std::net::SocketAddr,
    interface: &RelayInterface,
    link: Option<&Arc<AckLink>>,
    pins: &EpochPins,
    generation: u64,
    gate: &WorkGate,
) -> Step<(First, EstablishPermit)> {
    let Ok(permit) = limiter
        .acquire(Purpose::Ack, AUTH_BACKOFF + CONNECT_BUDGET)
        .await
    else {
        crate::apple::log_code("session_connect", "establish_queue_timeout");
        return refused("session_connect_failed");
    };
    #[cfg(feature = "enrolled-quic")]
    let selected_quic = match prepared.selected_quic() {
        Ok(selected) => selected,
        Err(_) => return refused("session_connect_failed"),
    };
    #[cfg(feature = "enrolled-quic")]
    if selected_quic {
        let deadline = tokio::time::Instant::now() + prepared.connect_timeout();
        let held = tokio::time::timeout_at(
            deadline,
            prepared.quic_carrier(interface, pins, generation, gate),
        )
        .await;
        return match held {
            Ok(Ok(held)) => Ok((First::Quic(held, deadline), permit)),
            Ok(Err(error)) => {
                limiter.judge(Purpose::Ack, &error);
                refused("session_connect_failed")
            }
            Err(_) => {
                prepared.carrier_fault(crate::carrier_failover::dial_signal(true));
                refused("session_connect_failed")
            }
        };
    }
    #[cfg(not(feature = "enrolled-quic"))]
    let _ = (pins, generation, gate);
    if let Some(link) = link {
        match link.conn(CONNECT_BUDGET).await {
            Ok(Some(conn)) => return Ok((First::Link(conn), permit)),
            // Judged; the epoch backs off, and the ACK path refuses.
            Err(_) => return refused("session_ack_refused"),
            // v40: the pin itself failed before authentication.
            Ok(None) if prepared.carrier_failed() => {
                crate::apple::log_code("session_connect", "carrier_failed");
                return refused("session_connect_failed");
            }
            Ok(None) => link.fallback(),
        }
    }
    match tokio::time::timeout(CONNECT_BUDGET, relay_socket::connect_bound(peer, interface)).await {
        Ok(Ok(tcp)) => Ok((First::Tcp(tcp), permit)),
        Ok(Err(error)) => {
            log_connect_failure(&error);
            if !relay_socket::interface_lost(&error) {
                prepared.carrier_fault(crate::carrier_failover::dial_signal(false));
            }
            refused("session_connect_failed")
        }
        Err(_) => {
            crate::apple::log_code("session_connect", "timeout");
            prepared.carrier_fault(crate::carrier_failover::dial_signal(true));
            refused("session_connect_failed")
        }
    }
}

/// v40 (CP-D3 M1): the first ACK's outer carrier on what `first_dial`
/// brought up (outer TLS and ECH, HTTP/2 and the carrier's 200 on a socket
/// of its own; the carrier stream's 200 on the ACK connection), before the
/// prepared identity is used. A failure is judged as the ACK's was (the
/// ACK connection told, the epoch backing off on an authentication-class
/// one) and refuses the ACK; a typed pre-authentication failure is also the
/// pin's carrier fault, so the build can move on to the next pin.
async fn first_carrier(
    limiter: &Arc<EstablishLimiter>,
    prepared: &PreparedLocalSession,
    first: First,
    link: Option<&Arc<AckLink>>,
    interface: &RelayInterface,
    pins: &EpochPins,
    generation: u64,
) -> Step<Carried> {
    let deadline = tokio::time::Instant::now() + prepared.connect_timeout();
    match first {
        #[cfg(feature = "enrolled-quic")]
        First::Quic(held, deadline) => Ok(Carried::Held(held, deadline)),
        First::Link(conn) => {
            let Some(link) = link else {
                return refused("session_ack_refused");
            };
            match prepared.open_link_carrier(&conn.0).await {
                Ok(carrier) => Ok(Carried::Link(conn, carrier, deadline)),
                Err(error) => {
                    link.failed(&conn.0, &error);
                    limiter.judge(Purpose::Ack, &error);
                    refused("session_ack_refused")
                }
            }
        }
        First::Tcp(tcp) => match prepared
            .held_carrier(tcp, interface, pins, generation)
            .await
        {
            Ok(held) => Ok(Carried::Held(held, deadline)),
            Err(error) => {
                limiter.judge(Purpose::Ack, &error);
                refused("session_ack_refused")
            }
        },
    }
}

/// The bridge and runtime clocks, read together just before an ACK request.
#[derive(Clone, Copy)]
struct RequestClock {
    ns: u64,
    at: tokio::time::Instant,
}

#[allow(clippy::too_many_arguments)]
fn run_observed(
    runtime: &Runtime,
    mut observed: ObservedLocalSession,
    bridge: &LeasedPacketBridge,
    (requested, ack_wake): (RequestClock, u64),
    (pool, gate): (&mut Pool, Arc<WorkGate>),
    (pin, ticket): (u64, Option<&Arc<CarrierTicket>>),
    halt: &Halt<'_>,
    steps: &Steps,
) -> (Option<ObservedLocalSession>, Step<()>) {
    // 5. The pre-warms keep progressing while the engine comes up, as the
    // engine wait drives this runtime.
    let Ok(config) = observed.verified_held_packet_config() else {
        close_gate(runtime, &gate);
        return (Some(observed), refused("session_packet_config_refused"));
    };
    // S16i-2: the session's live cap follows the signed `max_flows` from
    // here, before its engine (and any flow) starts.
    pool.limiter.bind_signed_max_flows(config.max_flows);
    // 6-7. The ACK lease, on the bridge's own clock.
    let valid_for = observed.ack_valid_until().duration_since(requested.at);
    log_valid_for("ack_valid_ms", valid_for);
    log_valid_for("ack_exchange_ms", observed.ack_exchange_elapsed());
    let Some(lease_end_ns) = lease_deadline_ns(requested.ns, valid_for, LEASE_MARGIN) else {
        close_gate(runtime, &gate);
        return (Some(observed), refused("session_ack_too_short"));
    };
    if bridge.grant_until(lease_end_ns).is_err() {
        let exit = if halt.requested() {
            Exit::Stopped
        } else {
            Exit::Refused("session_lease_refused")
        };
        close_gate(runtime, &gate);
        return (Some(observed), Err(exit));
    }
    // 8. The real engine over gated relay services that follow this lease.
    // S16h: the session's flow pool, beside its gate and on its limiter,
    // carries every flow as a stream. It dials nothing until a flow reserves
    // a stream. Its connections' drivers are gate tasks, so the relay join
    // below closes them, as it closes the ACK connection (S16l), which the
    // flow pool never sees: flow data never queues ahead of an ACK.
    let standalone_route = match observed.selected_channel() {
        Ok(aegis_core::carrier_program::CarrierChannel::WebResponse) => true,
        #[cfg(feature = "enrolled-quic")]
        Ok(aegis_core::carrier_program::CarrierChannel::MasqueQuic) => true,
        Ok(_) => false,
        Err(_) => {
            bridge.stop();
            join_relay(runtime, &gate, steps);
            return (Some(observed), refused("session_services_refused"));
        }
    };
    #[cfg(feature = "sfu-media-vp8")]
    let sfu_route = observed.has_sfu_media();
    #[cfg(not(feature = "sfu-media-vp8"))]
    let sfu_route = false;
    let flow_pool = if standalone_route || sfu_route {
        None
    } else {
        match observed.flow_pool(
            (pool.limiter.clone(), gate.clone()),
            (steps.pinned.clone(), pin),
        ) {
            Ok(flow_pool) => Some(flow_pool),
            Err(_) => {
                bridge.stop();
                join_relay(runtime, &gate, steps);
                return (Some(observed), refused("session_services_refused"));
            }
        }
    };
    // S16m: the verified ACK's inner mTLS authenticated this session at the
    // relay before any flow, so the pool starts proven: its first
    // connections take `H_CONN` streams at their first 200 rather than
    // probe alone (v23: two probing connections carried one stream each
    // while 45 flows waited a second after connect).
    if let Some(flow_pool) = &flow_pool {
        flow_pool.prove_by_session_ack(ack_wake);
    }
    #[cfg(feature = "sfu-media-vp8")]
    let services = if sfu_route {
        observed.held_sfu_relay_services(
            Arc::new(NoEvents),
            bridge.clone(),
            (pool.limiter.clone(), gate.clone()),
            (steps.pinned.clone(), pin),
        )
    } else {
        match flow_pool.as_ref() {
            Some(flow_pool) => {
                observed.held_relay_services(Arc::new(NoEvents), bridge.clone(), flow_pool.clone())
            }
            None => observed.held_web_relay_services(
                Arc::new(NoEvents),
                bridge.clone(),
                (pool.limiter.clone(), gate.clone()),
                (steps.pinned.clone(), pin),
            ),
        }
    };
    #[cfg(not(feature = "sfu-media-vp8"))]
    let services = match flow_pool.as_ref() {
        Some(flow_pool) => {
            observed.held_relay_services(Arc::new(NoEvents), bridge.clone(), flow_pool.clone())
        }
        None => observed.held_web_relay_services(
            Arc::new(NoEvents),
            bridge.clone(),
            (pool.limiter.clone(), gate.clone()),
            (steps.pinned.clone(), pin),
        ),
    };
    let services = match services {
        Ok(services) => services,
        Err(_) => {
            bridge.stop();
            join_relay(runtime, &gate, steps);
            return (Some(observed), refused("session_services_refused"));
        }
    };
    steps.arm(&services, &gate);
    let ledger = steps.pinned.flow_ledger();
    let mut packet = match PacketEngineOwner::spawn_on_ledger(
        bridge.clone(),
        config,
        services.clone(),
        ledger,
    ) {
        Ok(packet) => packet,
        Err(_) => {
            bridge.stop();
            join_relay(runtime, &gate, steps);
            return (Some(observed), refused("session_engine_spawn_failed"));
        }
    };
    // The engine holds its own reference; flows are judged through the gate.
    drop(services);
    let constructed = wait_engine(runtime, &mut packet, halt).and_then(|()| {
        // Store, saved intent and ACK again after the engine came up.
        observed
            .revalidate_bound_ack()
            .map_err(|_| Exit::Refused("store_revalidation_failed"))?;
        packet
            .ready_under_lease()
            .map_err(|_| Exit::Refused("session_engine_not_ready"))?;
        // S18: a re-pin while this session was constructing (a reasserting
        // epoch's next attempt binds to the new pin) leaves its relay
        // sockets on the lost interface: never swapped in.
        if !steps.pin_current(pin) {
            crate::apple::log_code("session_pin_stale", "constructing");
            return refused("relay_path_changed");
        }
        Ok(())
    });
    match constructed {
        Err(exit) => {
            bridge.stop();
            steps.mark("bridge_stop");
            join_relay(runtime, &gate, steps);
            let _ = packet_terminal(packet);
            steps.mark("packet_join");
            (Some(observed), Err(exit))
        }
        Ok(()) => {
            // 9. Ready goes through the notifier; the monitor then drives it.
            halt.control.mark_ready();
            let (stop_monitor, monitor_stopped) = oneshot::channel();
            let lease = Lease {
                deadline_ns: lease_end_ns,
                last_attempt_ns: requested.ns,
                lead: reack_lead(observed.ack_exchange_elapsed()),
            };
            let monitor = runtime.spawn(monitor(
                observed,
                halt.control.clone(),
                monitor_stopped,
                steps.clone(),
                lease,
                pool.take(),
                lease_end_ns.saturating_sub(requested.ns),
                pin,
                gate.clone(),
            ));
            // S16i-1: once the epoch is Running (a rebuilt session's at
            // once), one pre-dial of the flow pool, as a gate task the relay
            // join below aborts; and the flows' refusal counts a second held
            // back are logged meanwhile.
            let mut prewarm: Option<io::Result<AbortOnDrop>> = None;
            // v40: a pin lost under the open session (repeated
            // pre-authentication failures of its later dials) ends it, so a
            // rebuild plans again; never with a single pin (no ticket).
            let carrier_lost = || ticket.is_some_and(|ticket| ticket.lost());
            runtime.block_on(async {
                while !halt.requested()
                    && !packet.terminal_signal_observed()
                    && !monitor.is_finished()
                    && !carrier_lost()
                {
                    if prewarm.is_none() && pool.limiter.epoch_running() {
                        if let Some(flow_pool) = flow_pool.clone() {
                            prewarm = Some(gate.spawn(async move {
                                flow_pool.prewarm().await;
                            }));
                        }
                    }
                    pool.limiter.flush_flow_log(false);
                    tokio::time::sleep(STOP_POLL).await;
                }
            });
            // v40: a lease that ran out with neither a wake nor a re-pin
            // since the session's ACK is a freeze of its pin.
            let mut frozen = false;
            if !halt.requested() {
                let code = if carrier_lost() {
                    crate::apple::log_code("carrier_failover", "carrier_lost");
                    "carrier_unavailable"
                } else {
                    terminal_code(bridge, packet.terminal_signal_observed())
                };
                frozen = code == "capture_lease_expired"
                    && pool.limiter.wake_generation() == ack_wake
                    && steps.pin_current(pin);
                halt.control.seal(code);
            }
            if let Some(ticket) = ticket {
                ticket.closed(frozen);
            }
            // Terminal order. The revoked lease ends every flow at its next
            // recheck and the gate drains before the engine join. The monitor
            // outlives both, so the transport it polls stays live until the
            // last packet worker ends; it joins its pre-warms before it ends.
            bridge.stop();
            steps.mark("bridge_stop");
            join_relay(runtime, &gate, steps);
            drop(prewarm);
            pool.limiter.flush_flow_log(true);
            let _ = packet_terminal(packet);
            steps.mark("packet_join");
            let _ = stop_monitor.send(());
            let joined = runtime.block_on(monitor);
            steps.mark("monitor_stop");
            match joined {
                Ok((observed, result)) => (Some(observed), result),
                // A panicked monitor dropped the session inside the runtime.
                Err(_) => (None, refused("session_monitor_failed")),
            }
        }
    }
}

/// Why a Ready session ended without a stop request. Expiry is judged on the
/// bridge clock against the last granted lease, never on the revocable view:
/// every engine-side seal revokes that view, and is not a lease expiry.
fn terminal_code(bridge: &LeasedPacketBridge, packet_terminal: bool) -> &'static str {
    if bridge.lease_elapsed() {
        "capture_lease_expired"
    } else if packet_terminal {
        "session_packet_terminal"
    } else {
        "session_monitor_ended"
    }
}

/// Wait for the engine on the session runtime, so a pending pre-warm keeps
/// progressing meanwhile; never blocks the runtime for longer than one poll.
fn wait_engine(runtime: &Runtime, packet: &mut PacketEngineOwner, halt: &Halt<'_>) -> Step<()> {
    let deadline = Instant::now() + ENGINE_BUDGET;
    runtime.block_on(async {
        loop {
            if halt.requested() {
                return Err(Exit::Stopped);
            }
            match packet.wait_engine_constructed(Duration::ZERO) {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::TimedOut => {}
                Err(_) => return refused("session_engine_failed"),
            }
            if Instant::now() >= deadline {
                return refused("session_engine_timeout");
            }
            tokio::time::sleep(ENGINE_POLL).await;
        }
    })
}

/// The live bridge lease as the monitor last granted it, on the bridge clock,
/// and how long before its end the next re-ACK starts.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Lease {
    pub(crate) deadline_ns: u64,
    pub(crate) last_attempt_ns: u64,
    pub(crate) lead: Duration,
}

fn duration_ns(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

/// The re-ACK lead after a PolicyAck round trip of `exchange`: at least
/// `REACK_LEAD`, and room for two such round trips plus a margin.
pub(crate) fn reack_lead(exchange: Duration) -> Duration {
    REACK_LEAD.max(exchange.saturating_mul(2).saturating_add(REACK_LEAD_MARGIN))
}

/// Bridge-clock time of the next re-ACK: the lease's lead before it ends,
/// but never within `REACK_SPACING` of the previous attempt.
pub(crate) fn next_reack_ns(lease: Lease) -> u64 {
    lease
        .deadline_ns
        .saturating_sub(duration_ns(lease.lead))
        .max(
            lease
                .last_attempt_ns
                .saturating_add(duration_ns(REACK_SPACING)),
        )
}

/// Bridge-clock time the next re-ACK is due. A forced one (S18: after a
/// wake) is due `REACK_SPACING` after the previous attempt began, ahead of
/// the lease schedule but never sooner, so wakes never draw a hot loop.
/// Otherwise it follows the lease schedule, and never comes within
/// `spacing` (at least `REACK_SPACING`) of the previous attempt: while a
/// request is in flight, the stagger of the next one (`reack_stagger`).
pub(crate) fn reack_due_ns(lease: Lease, forced: bool, spacing: Duration) -> u64 {
    if forced {
        lease
            .last_attempt_ns
            .saturating_add(duration_ns(REACK_SPACING))
    } else {
        next_reack_ns(lease).max(
            lease
                .last_attempt_ns
                .saturating_add(duration_ns(spacing.max(REACK_SPACING))),
        )
    }
}

/// The p90 of `window`'s PolicyAck round trips (of `EXCHANGE_WINDOW` of
/// them, the longest); zero for none.
pub(crate) fn exchange_p90(window: &VecDeque<Duration>) -> Duration {
    let mut sorted: Vec<Duration> = window.iter().copied().collect();
    sorted.sort_unstable();
    let rank = (sorted.len() * 9).div_ceil(10);
    sorted
        .get(rank.saturating_sub(1))
        .copied()
        .unwrap_or_default()
}

/// Keep `exchange` among the last `EXCHANGE_WINDOW` round trips.
pub(crate) fn record_exchange(window: &mut VecDeque<Duration>, exchange: Duration) {
    while window.len() >= EXCHANGE_WINDOW {
        window.pop_front();
    }
    window.push_back(exchange);
}

/// The least gap between the starts of two requests in flight after `p90`
/// round trips: one round trip shared among `ACK_IN_FLIGHT` requests, so
/// their grants land evenly, never under `REACK_SPACING` nor over
/// `REACK_STAGGER_MAX`.
pub(crate) fn reack_stagger(p90: Duration) -> Duration {
    let share = u32::try_from(ACK_IN_FLIGHT).unwrap_or(1);
    (p90 / share).clamp(REACK_SPACING, REACK_STAGGER_MAX)
}

/// A rate-limited log line of one S16k value: a changed value at most once
/// per `REACK_LOG_EVERY`.
#[derive(Default)]
struct RateLog {
    value: Option<u128>,
    at: Option<Instant>,
}

impl RateLog {
    fn note(&mut self, event: &'static str, unit: &str, value: u128) {
        if self.value == Some(value) || self.at.is_some_and(|at| at.elapsed() < REACK_LOG_EVERY) {
            return;
        }
        self.value = Some(value);
        self.at = Some(Instant::now());
        crate::apple::log_code(event, &format!("{unit}:{value}"));
    }
}

/// Whether the `renewal`th renewal (1-based) logs `reack_ok`: the first five,
/// then every twentieth.
pub(crate) fn reack_ok_logged(renewal: u64) -> bool {
    renewal <= 5 || renewal.is_multiple_of(20)
}

/// Whether a pre-warmed channel dialed `age` ago may still carry a request.
pub(crate) fn prewarm_usable(age: Duration, max_age: Duration) -> bool {
    age <= max_age
}

/// Replace the bridge lease with one derived from a newly installed ACK. The
/// current lease must still be live on the bridge clock: an expired lease is
/// never revived, however valid the later ACK.
pub(crate) fn renew_lease(
    bridge: &LeasedPacketBridge,
    current_ns: u64,
    renewed_ns: u64,
) -> Result<(), &'static str> {
    match bridge.clock_ns() {
        Ok(now) if now < current_ns => {}
        _ => return Err("capture_lease_expired"),
    }
    bridge
        .grant_until(renewed_ns)
        .map_err(|_| "session_lease_refused")
}

/// Bridge-clock time to dial the channel for pool position `queued` (0: the
/// next request's). Requests follow each other about one interval apart:
/// the granted lease `span_ns` less the lead, never under the spacing floor.
/// While a request is outstanding, the next one follows its attempt by one
/// interval. Each channel is dialed `PREWARM_LEAD` before its use, so with
/// the server's 3 s ACKs every free slot is dialed at once (its setup then
/// overlaps the exchanges before its use), and with long ACKs no channel
/// idles past its age bound.
pub(crate) fn prewarm_due_ns(lease: Lease, span_ns: u64, outstanding: bool, queued: usize) -> u64 {
    let interval = span_ns
        .saturating_sub(duration_ns(lease.lead))
        .max(duration_ns(REACK_SPACING));
    let first = if outstanding {
        lease.last_attempt_ns.saturating_add(interval)
    } else {
        next_reack_ns(lease)
    };
    let queued = u64::try_from(queued).unwrap_or(u64::MAX);
    first
        .saturating_add(interval.saturating_mul(queued))
        .saturating_sub(duration_ns(PREWARM_LEAD))
}

/// How long a request on a pre-warmed channel may take before it is carried
/// on another channel: twice the last PolicyAck round trip plus the lead
/// margin, at least `PREWARM_EXCHANGE_FLOOR`, never past the attempt budget.
/// A channel that went silent while idle so leaves time for another.
pub(crate) fn prewarm_exchange_limit(last_exchange: Duration, budget: Duration) -> Duration {
    last_exchange
        .saturating_mul(2)
        .saturating_add(REACK_LEAD_MARGIN)
        .max(PREWARM_EXCHANGE_FLOOR)
        .min(budget)
}

/// One pre-warm slot: a channel being opened by a task on the session
/// runtime, or open and idle. Every task is joined (aborted, then awaited)
/// before the monitor or the session body lets go of it; an idle channel
/// keeps its H2 driver polled by the monitor and is dropped on its runtime.
#[derive(Default)]
enum Prewarm {
    #[default]
    Idle,
    Pending {
        task: JoinHandle<Option<Warm>>,
    },
    Ready {
        warm: Warm,
    },
}

/// An open pre-warmed channel, the establishment permit it keeps while it
/// idles (its establishment ends only with its PolicyAck), and when its TCP
/// dial began: after its permit was granted, so its age tracks the relay's
/// admission timer and never includes a wait for a permit.
/// Boxed, as is every pre-warmed channel: it carries a whole TLS stream.
struct Warm {
    channel: Box<PrewarmedChannel>,
    permit: EstablishPermit,
    dialed: tokio::time::Instant,
}

enum PrewarmEvent {
    /// An opening task returned (a failure was logged inside it).
    Opened { channel: Option<Warm> },
    /// An idle channel's connection ended before it was used.
    IdleEnded,
}

impl Prewarm {
    fn start(
        runtime: &Handle,
        opener: ChannelOpener,
        (limiter, link): (Arc<EstablishLimiter>, Option<Arc<AckLink>>),
        steps: &Steps,
    ) -> Self {
        steps.mark("reack_prewarm_start");
        let task = runtime.spawn(open_channel(opener, limiter, link));
        Prewarm::Pending { task }
    }

    fn is_idle(&self) -> bool {
        matches!(self, Prewarm::Idle)
    }

    /// The pending open finishing, or the idle channel ending; the slot is
    /// then Idle, so a returned task or an ended channel is never polled
    /// again.
    fn poll_event(&mut self, cx: &mut Context<'_>) -> Poll<PrewarmEvent> {
        let event = match self {
            Prewarm::Idle => return Poll::Pending,
            Prewarm::Pending { task } => match Pin::new(task).poll(cx) {
                Poll::Ready(opened) => PrewarmEvent::Opened {
                    channel: opened.ok().flatten(),
                },
                Poll::Pending => return Poll::Pending,
            },
            Prewarm::Ready { warm } => match warm.channel.poll_idle(cx) {
                Poll::Ready(()) => PrewarmEvent::IdleEnded,
                Poll::Pending => return Poll::Pending,
            },
        };
        *self = Prewarm::Idle;
        Poll::Ready(event)
    }

    async fn join(self, steps: &Steps) {
        if let Prewarm::Pending { task } = self {
            task.abort();
            let _ = task.await;
            steps.mark("reack_prewarm_joined");
        }
    }
}

/// The channels for the next re-ACKs, at most `PREWARM_SLOTS` of them, so a
/// channel is open when the previous ACK arrives even when one setup takes
/// longer than one exchange, whatever the flow load: one slot loses the
/// lease of the installed relay (S16e). `dials` counts the dials since the
/// last request was bound: at most `PREWARM_DIALS_PER_REACK`, so a relay that ends
/// every channel never draws a dial loop. Every channel of the pool, and
/// every re-ACK, establishes under `limiter`'s ACK permits. S16l: with the
/// session's ACK connection `link`, its channels are streams of that
/// connection, and per-dial only while it is down.
struct Pool {
    slots: [Prewarm; PREWARM_SLOTS],
    dials: usize,
    limiter: Arc<EstablishLimiter>,
    link: Option<Arc<AckLink>>,
}

impl Pool {
    fn new(limiter: Arc<EstablishLimiter>, link: Option<Arc<AckLink>>) -> Self {
        Self {
            slots: Default::default(),
            dials: 0,
            limiter,
            link,
        }
    }

    /// Hand this pool on, leaving an empty one on the same limiter and link.
    fn take(&mut self) -> Self {
        let empty = Self::new(self.limiter.clone(), self.link.clone());
        std::mem::replace(self, empty)
    }

    fn busy(&self) -> usize {
        self.slots.iter().filter(|slot| !slot.is_idle()).count()
    }

    fn opening(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| matches!(slot, Prewarm::Pending { .. }))
            .count()
    }

    fn may_dial(&self) -> bool {
        self.busy() < PREWARM_SLOTS && self.dials < PREWARM_DIALS_PER_REACK
    }

    /// Dial `opener`'s peer into a free slot; nothing when none is free.
    fn start(&mut self, runtime: &Handle, opener: ChannelOpener, steps: &Steps) {
        if let Some(slot) = self.slots.iter_mut().find(|slot| slot.is_idle()) {
            let link = self.link.clone();
            *slot = Prewarm::start(runtime, opener, (self.limiter.clone(), link), steps);
            self.dials = self.dials.saturating_add(1);
        }
    }

    fn put_ready(&mut self, warm: Warm) {
        if let Some(slot) = self.slots.iter_mut().find(|slot| slot.is_idle()) {
            *slot = Prewarm::Ready { warm };
        }
    }

    /// The oldest open channel still young enough to carry a request. Every
    /// older one is logged and dropped, so its request goes elsewhere, as is
    /// (S16l) a stream channel whose ACK connection is no longer usable (it
    /// ended, or a wake or a re-pin left it behind).
    fn take_ready(
        &mut self,
        steps: &Steps,
        avoid: &dyn Fn(&Arc<PooledConn>) -> bool,
    ) -> Option<Warm> {
        let max_age = steps.prewarm_max_age();
        let mut oldest: Option<(usize, tokio::time::Instant)> = None;
        for (index, slot) in self.slots.iter_mut().enumerate() {
            let Prewarm::Ready { warm } = slot else {
                continue;
            };
            let dialed = warm.dialed;
            let behind = match (&self.link, warm.channel.conn()) {
                (Some(link), Some((conn, stream_id))) => !link.usable(conn, stream_id),
                _ => false,
            };
            if behind {
                crate::apple::log_code(PREWARM_EVENT, "link_stale");
                steps.mark("reack_prewarm_stale");
                *slot = Prewarm::Idle;
                continue;
            }
            // S16l: a channel on a quiet ACK connection stays for later.
            if warm.channel.conn().is_some_and(|(conn, _)| avoid(conn)) {
                continue;
            }
            if !prewarm_usable(dialed.elapsed(), max_age) {
                crate::apple::log_code(PREWARM_EVENT, "stale");
                steps.mark("reack_prewarm_stale");
                *slot = Prewarm::Idle;
                continue;
            }
            if oldest.is_none_or(|(_, at)| dialed < at) {
                oldest = Some((index, dialed));
            }
        }
        let (index, _) = oldest?;
        let Prewarm::Ready { warm } = std::mem::take(&mut self.slots[index]) else {
            return None;
        };
        Some(warm)
    }

    /// The next event of any slot; cancelling it loses nothing.
    fn next(&mut self) -> impl Future<Output = PrewarmEvent> + '_ {
        std::future::poll_fn(move |cx| {
            for slot in &mut self.slots {
                if let Poll::Ready(event) = slot.poll_event(cx) {
                    return Poll::Ready(event);
                }
            }
            Poll::Pending
        })
    }

    async fn join(self, steps: &Steps) {
        for slot in self.slots {
            slot.join(steps).await;
        }
    }
}

/// Dial the session's own peer and establish one channel for a later
/// PolicyAck, under an ACK permit waited for within an epoch backoff plus
/// the connect budget, so a pre-warm queued at a failure still dials once
/// the backoff lifts. Its age runs from the dial, after the permit. Every
/// failure is logged with its step and is `None`; an authentication-class
/// one backs the session off before its permit returns.
///
/// S16l: with the session's ACK connection `link`, the channel is a stream
/// of it instead (dialed now under this permit when none is up), aging from
/// its carrier request or from when that connection last had a live channel
/// (`ConnLive::aged_from`); per-dial only when no connection comes up or
/// its stream fails short of an authentication-class refusal, and never
/// once the gate is closed.
async fn open_channel(
    opener: ChannelOpener,
    limiter: Arc<EstablishLimiter>,
    link: Option<Arc<AckLink>>,
) -> Option<Warm> {
    let Ok(permit) = limiter
        .acquire(Purpose::Ack, AUTH_BACKOFF + CONNECT_BUDGET)
        .await
    else {
        crate::apple::log_code(PREWARM_EVENT, "establish_queue_timeout");
        return None;
    };
    if let Some(link) = &link {
        // A stream its connection's end failed goes once more on the
        // connection that replaces it (`LINK_TRIES`).
        for _ in 0..LINK_TRIES {
            let conn = match link.conn(CONNECT_BUDGET).await {
                Ok(Some(conn)) => conn,
                // Judged: the epoch backs off.
                Err(_) => return None,
                Ok(None) => break,
            };
            let dialed = conn.1.aged_from(tokio::time::Instant::now());
            let on = conn.0.clone();
            match opener
                .clone()
                .establish_on_link(link, conn, PREWARM_EVENT)
                .await
            {
                Ok(channel) => {
                    return Some(Warm {
                        channel: Box::new(channel),
                        permit,
                        dialed,
                    })
                }
                Err(error) => {
                    link.failed(&on, &error);
                    if is_auth_refused(&error) {
                        limiter.judge(Purpose::Ack, &error);
                        return None;
                    }
                }
            }
        }
        if link.closed() {
            return None;
        }
        link.fallback();
    }
    let dialed = tokio::time::Instant::now();
    let connected = tokio::time::timeout(CONNECT_BUDGET, opener.connect());
    let tcp = match connected.await {
        Ok(Ok(tcp)) => tcp,
        Ok(Err(error)) => {
            log_dial_failure("reack_prewarm_connect", &error);
            return None;
        }
        Err(_) => {
            crate::apple::log_code("reack_prewarm_connect", "timeout");
            opener.connect_timed_out();
            return None;
        }
    };
    match opener.establish(tcp, PREWARM_EVENT).await {
        Ok(channel) => Some(Warm {
            channel: Box::new(channel),
            permit,
            dialed,
        }),
        Err(error) => {
            limiter.judge(Purpose::Ack, &error);
            drop(permit);
            None
        }
    }
}

/// How a re-ACK reached the relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Via {
    /// A pre-warmed channel (a stream of the ACK connection, or per-dial).
    Prewarm,
    /// S16l: a fresh stream of the ACK connection.
    Link,
    /// A fresh dial of its own.
    Fresh,
}

impl Via {
    /// Its `reack_ok` log prefix (never a refusal code).
    fn code(self) -> &'static str {
        ["prewarm", "link", "fresh"][self as usize]
    }
}

/// A re-ACK that completed its exchange, with the bridge and runtime clocks
/// read just before the request left, and when it was bound (its first
/// attempt began).
struct Reacked {
    observation: ReackObservation,
    requested: RequestClock,
    via: Via,
    bound: tokio::time::Instant,
}

/// A bound re-ACK request and when it was bound, carried on to another
/// channel when one fails it.
type BoundRequest = (ReackRequest, tokio::time::Instant);

/// How one attempt ended: an exchange (or its failure), or a request on a
/// pre-warmed channel that failed and is carried on by the monitor.
enum Outcome {
    // Boxed: the observation carries a whole TLS stream.
    Done(Option<Box<Reacked>>),
    Retry(BoundRequest),
}

type Attempt = Pin<Box<dyn Future<Output = Outcome> + Send>>;

/// S16o: where a re-ACK attempt is, for the `reack_stalled` line logged
/// when the lease ran out under it (r13: the grant after the last renewal
/// never landed while the pool held four probing connections).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum ReackStage {
    /// Waiting for an ACK-path establishment permit.
    Permit,
    /// Waiting for the ACK connection (its dial, or one in progress).
    LinkConn,
    /// Its PolicyAck on a fresh stream of the ACK connection: the stream's
    /// carrier 200 and inner mTLS, the request and its grant.
    LinkRequest,
    /// Its own dial's TCP connect.
    Dial,
    /// On its own dial: the outer TLS, H2, the carrier's 200, the inner
    /// mTLS, the request and its grant.
    DialExchange,
    /// Its request on a pre-warmed channel, and its grant.
    PrewarmRequest,
}

impl ReackStage {
    const ALL: [Self; 6] = [
        Self::Permit,
        Self::LinkConn,
        Self::LinkRequest,
        Self::Dial,
        Self::DialExchange,
        Self::PrewarmRequest,
    ];

    fn code(self) -> &'static str {
        [
            "permit",
            "link_conn",
            "link_request",
            "dial",
            "dial_exchange",
            "prewarm_request",
        ][self as usize]
    }

    fn mark(self) -> &'static str {
        [
            "reack_stalled_permit",
            "reack_stalled_link_conn",
            "reack_stalled_link_request",
            "reack_stalled_dial",
            "reack_stalled_dial_exchange",
            "reack_stalled_prewarm_request",
        ][self as usize]
    }
}

/// S16o: one attempt's current stage and when it entered it, reported once.
struct StageCell {
    stage: AtomicU8,
    entered: Mutex<tokio::time::Instant>,
    bound: tokio::time::Instant,
    reported: AtomicBool,
}

impl StageCell {
    fn enter(&self, stage: ReackStage) {
        self.stage.store(stage as u8, Ordering::Release);
        *self
            .entered
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = tokio::time::Instant::now();
    }

    fn stage(&self) -> ReackStage {
        let value = self.stage.load(Ordering::Acquire);
        ReackStage::ALL
            .into_iter()
            .find(|stage| *stage as u8 == value)
            .unwrap_or(ReackStage::Permit)
    }

    /// Log this attempt's stage, how long it has been in it and since its
    /// request was bound; once.
    fn report(&self, steps: &Steps) {
        if self.reported.swap(true, Ordering::AcqRel) {
            return;
        }
        let stage = self.stage();
        let entered = *self
            .entered
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        crate::apple::log_fields(
            "reack_stalled",
            &[
                &stage_field(stage.code(), entered.elapsed()),
                &stage_field("bound", self.bound.elapsed()),
            ],
        );
        steps.mark(stage.mark());
    }
}

/// `<name>_ms:<elapsed>`.
fn stage_field(name: &str, elapsed: Duration) -> String {
    format!("{name}_ms:{}", elapsed.as_millis())
}

/// The lease end the monitor last granted, on the bridge clock, shared with
/// every attempt in flight: a grant of one request moves the budget of the
/// other (S16k). S16o: also where each attempt in flight is.
#[derive(Clone)]
struct LeaseEnd(Arc<AtomicU64>, Arc<Mutex<Vec<Weak<StageCell>>>>);

impl LeaseEnd {
    fn new(deadline_ns: u64) -> Self {
        Self(Arc::new(AtomicU64::new(deadline_ns)), Arc::default())
    }

    fn set(&self, deadline_ns: u64) {
        self.0.fetch_max(deadline_ns, Ordering::SeqCst);
    }

    /// S16o: a new attempt of the request bound at `bound`, tracked while it
    /// lives.
    fn track(&self, bound: tokio::time::Instant) -> Arc<StageCell> {
        let now = tokio::time::Instant::now();
        let cell = Arc::new(StageCell {
            stage: AtomicU8::new(ReackStage::Permit as u8),
            entered: Mutex::new(now),
            bound,
            reported: AtomicBool::new(false),
        });
        let mut cells = self
            .1
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cells.retain(|cell| cell.strong_count() > 0);
        cells.push(Arc::downgrade(&cell));
        cell
    }

    /// S16o: report every attempt in flight, and every request `waiting`
    /// for a channel still opening, as the lease ran out under them.
    fn report_stalled(
        &self,
        waiting: impl IntoIterator<Item = tokio::time::Instant>,
        steps: &Steps,
    ) {
        let cells: Vec<Arc<StageCell>> = self
            .1
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter_map(Weak::upgrade)
            .collect();
        for cell in cells {
            cell.report(steps);
        }
        for bound in waiting {
            crate::apple::log_code("reack_stalled", &stage_field("waiting", bound.elapsed()));
            steps.mark("reack_stalled_waiting");
        }
    }

    /// Resolves once the bridge clock reaches the latest lease end (or
    /// fails); a renewal meanwhile moves the wait on.
    async fn elapsed(&self, bridge: &LeasedPacketBridge) {
        loop {
            let deadline = self.0.load(Ordering::SeqCst);
            let Ok(now) = bridge.clock_ns() else {
                return;
            };
            if now >= deadline {
                return;
            }
            tokio::time::sleep(Duration::from_nanos(deadline - now)).await;
        }
    }
}

/// Observe one ACK while the lease (`lease_end`, which a grant to another
/// request in flight moves on) is live: one request on `prewarmed` when
/// given, bounded by `limit`, else (S16l) over a fresh stream of the
/// session's ACK connection `link` (dialed now under this request's permit
/// when it is down and its dial budget allows), bounded by `limit` and that
/// stream's two round trips of setup, else over a fresh dial of the
/// session's own peer. A failed request on `prewarmed` comes back for
/// another channel; a failed one on the ACK connection goes on a fresh dial
/// within the same attempt; every other failure is `Done(None)`.
#[allow(clippy::too_many_arguments)]
fn reack_attempt(
    (request, bound): BoundRequest,
    prewarmed: Option<Warm>,
    bridge: LeasedPacketBridge,
    lease_end: LeaseEnd,
    limit: Duration,
    (limiter, link): (Arc<EstablishLimiter>, Option<Arc<AckLink>>),
    steps: Steps,
) -> Attempt {
    Box::pin(async move {
        let stage = lease_end.track(bound);
        let stage = &*stage;
        let exchange = async {
            if let Some(Warm {
                channel, permit, ..
            }) = prewarmed
            {
                stage.enter(ReackStage::PrewarmRequest);
                // S16l: in flight on the ACK connection until it ends.
                let _in_flight = match (&link, channel.conn()) {
                    (Some(link), Some((conn, _))) => Some(link.begin(conn)),
                    _ => None,
                };
                let Ok(ns) = bridge.clock_ns() else {
                    return Outcome::Done(None);
                };
                let requested = RequestClock {
                    ns,
                    at: tokio::time::Instant::now(),
                };
                let observed = request
                    .observe_on_judged(*channel, limit, PREWARM_EVENT)
                    .await;
                return match observed {
                    Ok(observation) => {
                        permit.succeeded();
                        Outcome::Done(Some(Box::new(Reacked {
                            observation,
                            requested,
                            via: Via::Prewarm,
                            bound,
                        })))
                    }
                    Err((returned, auth)) => {
                        if auth {
                            limiter.auth_failure(Purpose::Ack);
                        }
                        drop(permit);
                        crate::apple::log_code(PREWARM_EVENT, "request_failed");
                        steps.mark("reack_prewarm_failed");
                        Outcome::Retry((returned, bound))
                    }
                };
            }
            steps.mark("reack_fresh");
            // A fresh re-ACK's establishment holds an ACK permit until its
            // PolicyAck; the lease bounds the wait. It goes before every
            // waiting pre-warm: while probing, a pre-warm taking the one
            // ACK-path slot would idle on it while this request waits.
            stage.enter(ReackStage::Permit);
            let Ok(permit) = limiter.acquire_bound(Duration::MAX).await else {
                crate::apple::log_code("reack", "establish_queue_timeout");
                return Outcome::Done(None);
            };
            #[cfg(feature = "enrolled-quic")]
            match request.selected_quic() {
                Ok(true) => {
                    stage.enter(ReackStage::Dial);
                    let Ok(ns) = bridge.clock_ns() else {
                        return Outcome::Done(None);
                    };
                    let requested = RequestClock {
                        ns,
                        at: tokio::time::Instant::now(),
                    };
                    stage.enter(ReackStage::DialExchange);
                    let observation = match request.observe_quic(limit).await {
                        Ok(observation) => observation,
                        Err(error) => {
                            limiter.judge(Purpose::Ack, &error);
                            return Outcome::Done(None);
                        }
                    };
                    permit.succeeded();
                    return Outcome::Done(Some(Box::new(Reacked {
                        observation,
                        requested,
                        via: Via::Fresh,
                        bound,
                    })));
                }
                Ok(false) => {}
                Err(_) => return Outcome::Done(None),
            }
            let mut request = request;
            // S16m: the quiet connection this request left, and the write
            // mark of its quiet request: once a byte past it is
            // acknowledged, this request comes back to that connection.
            let mut off: Option<(Arc<PooledConn>, u64)> = None;
            if let Some(link) = &link {
                for _ in 0..LINK_TRIES {
                    // The current connection, else one this request dials
                    // (or a dial in progress brings up) under its permit.
                    stage.enter(ReackStage::LinkConn);
                    let conn = match link.conn(CONNECT_BUDGET).await {
                        Ok(Some(conn)) => conn,
                        // An authentication-class dial failure, judged.
                        Err(_) => return Outcome::Done(None),
                        Ok(None) => break,
                    };
                    // A quiet connection holds no second request.
                    if let Some(mark) = link.quiet_mark(&conn.0) {
                        steps.mark("reack_off_link");
                        off = Some((conn.0.clone(), mark));
                        break;
                    }
                    steps.mark("reack_link");
                    stage.enter(ReackStage::LinkRequest);
                    let on = conn.0.clone();
                    let _in_flight = link.begin(&on);
                    let link_limit = limit.saturating_add(on.srtt().saturating_mul(2));
                    let Ok(ns) = bridge.clock_ns() else {
                        return Outcome::Done(None);
                    };
                    let requested = RequestClock {
                        ns,
                        at: tokio::time::Instant::now(),
                    };
                    match request
                        .observe_on_link(link, conn, link_limit, "ack_stage")
                        .await
                    {
                        Ok(observation) => {
                            permit.succeeded();
                            return Outcome::Done(Some(Box::new(Reacked {
                                observation,
                                requested,
                                via: Via::Link,
                                bound,
                            })));
                        }
                        Err((returned, error)) => {
                            link.failed(&on, &error);
                            if is_auth_refused(&error) {
                                limiter.judge(Purpose::Ack, &error);
                                return Outcome::Done(None);
                            }
                            request = returned;
                        }
                    }
                }
                if link.closed() {
                    return Outcome::Done(None);
                }
                link.fallback();
            }
            // S16m: sent off a quiet ACK connection, its own dial's TCP
            // connect, outer TLS, H2 and inner mTLS race that connection's
            // revival: once it shows the life its quiet request lacked,
            // this request goes back to it (a pre-warmed stream, one round
            // trip) rather than finish the dial (v23: 2.2 s under the
            // burst, while the connection answered 117 ms after the request
            // left it). Once the dial's inner mTLS completed its PolicyAck
            // is written and answered on it: nothing on the connection can
            // answer sooner.
            let off_link = off.is_some();
            stage.enter(ReackStage::Dial);
            let revived = revival(link.clone(), off);
            tokio::pin!(revived);
            let connected = {
                let connect = tokio::time::timeout(CONNECT_BUDGET, async {
                    steps.hold_fresh_connect().await;
                    request.connect().await
                });
                tokio::select! {
                    biased;
                    connected = connect => Some(connected),
                    () = &mut revived => None,
                }
            };
            let tcp = match connected {
                Some(Ok(Ok(tcp))) => tcp,
                Some(Ok(Err(error))) => {
                    log_dial_failure("reack_connect", &error);
                    return Outcome::Done(None);
                }
                Some(Err(_)) => {
                    crate::apple::log_code("reack_connect", "timeout");
                    request.connect_timed_out();
                    return Outcome::Done(None);
                }
                None => return back_on_link(link.as_deref(), (request, bound), &steps),
            };
            let Ok(ns) = bridge.clock_ns() else {
                return Outcome::Done(None);
            };
            let requested = RequestClock {
                ns,
                at: tokio::time::Instant::now(),
            };
            // Traced for a dial sent off a quiet connection only: from here
            // on it is committed to its own PolicyAck.
            let established = || {
                if off_link {
                    steps.mark("reack_off_link_established");
                }
            };
            stage.enter(ReackStage::DialExchange);
            let observation = match request.observe_or(tcp, (revived, established)).await {
                Ok(Ok(observation)) => observation,
                Ok(Err(error)) => {
                    limiter.judge(Purpose::Ack, &error);
                    return Outcome::Done(None);
                }
                Err(request) => {
                    return back_on_link(link.as_deref(), (request, bound), &steps);
                }
            };
            permit.succeeded();
            Outcome::Done(Some(Box::new(Reacked {
                observation,
                requested,
                via: Via::Fresh,
                bound,
            })))
        };
        tokio::select! {
            outcome = exchange => outcome,
            () = lease_end.elapsed(&bridge) => {
                crate::apple::log_code("reack", "lease_budget_elapsed");
                stage.report(&steps);
                Outcome::Done(None)
            }
        }
    })
}

/// S16m: resolves once `off`'s quiet ACK connection revived
/// (`AckLink::revived`), looked at every `REVIVE_POLL`; never without one.
async fn revival(link: Option<Arc<AckLink>>, off: Option<(Arc<PooledConn>, u64)>) {
    let (Some(link), Some((conn, mark))) = (link, off) else {
        return std::future::pending().await;
    };
    loop {
        if link.revived(&conn, mark) {
            return;
        }
        tokio::time::sleep(crate::ack_conn::REVIVE_POLL).await;
    }
}

/// S16m: a request sent off a quiet ACK connection that revived goes back
/// to the monitor, which dispatches it again (onto that connection now);
/// its dial of its own is dropped in its TCP connect, outer TLS, H2 or
/// inner mTLS, before its PolicyAck is written.
fn back_on_link(link: Option<&AckLink>, request: BoundRequest, steps: &Steps) -> Outcome {
    if let Some(link) = link {
        link.note_revived();
    }
    steps.mark("reack_back_on_link");
    Outcome::Retry(request)
}

/// The bound on a request over a pre-warmed channel after `p90` round
/// trips, with grants lasting `span_ns` from their request: the pre-warm
/// limit (`prewarm_exchange_limit`), but (S16k) never before the request's
/// own grant would have ended, so a round trip rising past twice the last
/// ones is still answered; the request in flight beside it covers a channel
/// gone silent meanwhile. The lease bounds every request besides.
pub(crate) fn request_limit(p90: Duration, span_ns: u64) -> Duration {
    prewarm_exchange_limit(p90, Duration::MAX).max(Duration::from_nanos(span_ns))
}

/// Send `request` on the oldest usable pre-warmed channel, bounded by
/// `limit` (`request_limit`); while a channel is still opening for it (one
/// per request already held), hold it until one opens; with none, dial
/// fresh. The lease (`lease_end`) bounds every request.
fn dispatch(
    request: BoundRequest,
    reacks: (&mut Pool, &mut Vec<Attempt>, &mut VecDeque<BoundRequest>),
    limit: Duration,
    bridge: &LeasedPacketBridge,
    lease_end: &LeaseEnd,
    steps: &Steps,
) {
    let (pool, attempts, waiting) = reacks;
    // S16l: while a request on the ACK connection has seen no sign of its
    // life, this one goes on another TCP connection: a pre-warmed one of its
    // own, else a fresh dial, never one still opening (on that connection).
    let link = pool.link.clone();
    let quiet = link.as_ref().is_some_and(|link| link.quiet_any());
    if quiet {
        steps.mark("reack_off_link");
    }
    let avoid = |conn: &Arc<PooledConn>| link.as_ref().is_some_and(|link| link.quiet(conn));
    if let Some(warm) = pool.take_ready(steps, &avoid) {
        // Marked as the channel is taken, before any later attempt starts.
        steps.mark("reack_prewarm_used");
        attempts.push(reack_attempt(
            request,
            Some(warm),
            bridge.clone(),
            lease_end.clone(),
            limit,
            (pool.limiter.clone(), pool.link.clone()),
            steps.clone(),
        ));
    } else if !quiet && pool.opening() > waiting.len() {
        waiting.push_back(request);
    } else {
        attempts.push(reack_attempt(
            request,
            None,
            bridge.clone(),
            lease_end.clone(),
            limit,
            (pool.limiter.clone(), pool.link.clone()),
            steps.clone(),
        ));
    }
}

/// The outcome of the first attempt in `attempts` to end; that attempt is
/// removed. Cancelling the wait loses nothing.
fn next_outcome(attempts: &mut Vec<Attempt>) -> impl Future<Output = Outcome> + '_ {
    std::future::poll_fn(move |cx| {
        for index in 0..attempts.len() {
            if let Poll::Ready(outcome) = attempts[index].as_mut().poll(cx) {
                drop(attempts.swap_remove(index));
                return Poll::Ready(outcome);
            }
        }
        Poll::Pending
    })
}

/// The monitor's re-ACK work: the pre-warm pool, the attempts in flight and
/// the requests held for a channel still opening (together at most
/// `ACK_IN_FLIGHT`), the last grant's lease span (from its request), the
/// last `EXCHANGE_WINDOW` PolicyAck round trips, the lease end every attempt
/// is bounded by, and the S16k logs.
struct Reacks {
    pool: Pool,
    attempts: Vec<Attempt>,
    waiting: VecDeque<BoundRequest>,
    renewals: u64,
    span_ns: u64,
    exchanges: VecDeque<Duration>,
    lease_end: LeaseEnd,
    inflight_log: RateLog,
    lead_log: RateLog,
}

impl Reacks {
    fn in_flight(&self) -> usize {
        self.attempts.len() + self.waiting.len()
    }
}

/// Seal on an elapsed lease, noting a re-ACK that was still in flight and
/// (S16o) where each one was.
fn seal_expired(probe: &SessionProbe, reacks: &Reacks, steps: &Steps) {
    if reacks.in_flight() > 0 {
        crate::apple::log_code("reack", "lease_budget_elapsed");
        report_reacks(reacks, steps);
    }
    probe.seal("capture_lease_expired");
}

/// S16o: where each re-ACK in flight was.
fn report_reacks(reacks: &Reacks, steps: &Steps) {
    reacks
        .lease_end
        .report_stalled(reacks.waiting.iter().map(|(_, bound)| *bound), steps);
}

/// The session ended on a lease that ran out with re-ACKs still in flight:
/// say so, and (S16o) where each one was.
fn lapsed_under_reacks(reacks: &Reacks, bridge: &LeasedPacketBridge, steps: &Steps) {
    if reacks.in_flight() > 0 && bridge.lease_elapsed() {
        crate::apple::log_code("reack", "lease_budget_elapsed");
        report_reacks(reacks, steps);
    }
}

/// What one completed re-ACK exchange did to the session.
enum Renewal {
    Renewed {
        via: Via,
        bound: tokio::time::Instant,
        exchange: Duration,
        span_ns: u64,
    },
    /// A verified grant ending no later than the lease already granted (an
    /// earlier request's, landing after a later one's): not installed.
    Superseded {
        exchange: Duration,
    },
    Refused,
    Sealed(&'static str, Step<()>),
}

/// Install a completed re-ACK and renew the lease from its request time on
/// the bridge clock. The lease ends at the latest verified grant: one ending
/// no later is dropped. A refused ACK keeps the current lease; an expired
/// lease is never revived.
fn renew(
    observed: &mut ObservedLocalSession,
    bridge: &LeasedPacketBridge,
    lease: &mut Lease,
    reacked: Reacked,
) -> Renewal {
    let valid_for = reacked
        .observation
        .ack_valid_until()
        .duration_since(reacked.requested.at);
    log_valid_for("reack_valid_ms", valid_for);
    let Some(renewed_ns) = lease_deadline_ns(reacked.requested.ns, valid_for, LEASE_MARGIN) else {
        crate::apple::log_code("reack", "validity_below_margin");
        return Renewal::Refused;
    };
    let exchange = reacked.observation.exchange_elapsed();
    if renewed_ns <= lease.deadline_ns {
        return Renewal::Superseded { exchange };
    }
    if observed.install_reack(reacked.observation).is_err() {
        if observed.revalidate_bound_ack().is_err() {
            return Renewal::Sealed(
                "store_revalidation_failed",
                refused("store_revalidation_failed"),
            );
        }
        return Renewal::Refused;
    }
    if let Err(code) = renew_lease(bridge, lease.deadline_ns, renewed_ns) {
        return Renewal::Sealed(code, Ok(()));
    }
    lease.deadline_ns = renewed_ns;
    Renewal::Renewed {
        via: reacked.via,
        bound: reacked.bound,
        exchange,
        span_ns: renewed_ns.saturating_sub(reacked.requested.ns),
    }
}

/// 250 ms Store/ACK revalidation and lease probe, plus continuous re-ACK on
/// the bridge clock. One ACK connection ending is not a failure: the server
/// shuts the inner stream after write_ack. A failed re-ACK keeps the current
/// lease, and the session serves until it ends; expiry is judged only on the
/// bridge clock and seals the session. Nothing the monitor started outlives
/// it: every attempt drops here, on the runtime, and every pre-warm is
/// joined.
#[allow(clippy::too_many_arguments)]
async fn monitor(
    observed: ObservedLocalSession,
    control: SessionControl,
    mut stop: oneshot::Receiver<()>,
    steps: Steps,
    lease: Lease,
    pool: Pool,
    span_ns: u64,
    pin: u64,
    gate: Arc<WorkGate>,
) -> (ObservedLocalSession, Step<()>) {
    let mut exchanges = VecDeque::with_capacity(EXCHANGE_WINDOW);
    record_exchange(&mut exchanges, observed.ack_exchange_elapsed());
    let mut reacks = Reacks {
        pool,
        attempts: Vec::with_capacity(ACK_IN_FLIGHT),
        waiting: VecDeque::with_capacity(ACK_IN_FLIGHT),
        renewals: 0,
        span_ns,
        exchanges,
        lease_end: LeaseEnd::new(lease.deadline_ns),
        inflight_log: RateLog::default(),
        lead_log: RateLog::default(),
    };
    let ended = monitor_loop(
        observed,
        &control,
        &mut stop,
        &steps,
        lease,
        &mut reacks,
        pin,
        &gate,
    )
    .await;
    let Reacks {
        pool,
        attempts,
        waiting,
        ..
    } = reacks;
    drop(attempts);
    drop(waiting);
    pool.join(&steps).await;
    ended
}

#[allow(clippy::too_many_arguments)] // Each argument is a distinct session owner, as above.
async fn monitor_loop(
    mut observed: ObservedLocalSession,
    control: &SessionControl,
    stop: &mut oneshot::Receiver<()>,
    steps: &Steps,
    mut lease: Lease,
    reacks: &mut Reacks,
    pin: u64,
    gate: &Arc<WorkGate>,
) -> (ObservedLocalSession, Step<()>) {
    enum Event {
        Stop,
        Reack(Outcome),
        Prewarm(PrewarmEvent),
        TransportEnded,
        Tick,
        Wake,
    }
    let probe = control.probe();
    let bridge = control.bridge().clone();
    let mut tick = tokio::time::interval(MONITOR_INTERVAL);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut transport_open = true;
    // S16j-3: the relay drain drives this runtime, so the monitor runs on
    // after a seal or stop until its next tick. A session no longer serving
    // starts no relay work: no new re-ACK and no pre-warm dial.
    loop {
        if probe.phase() != SessionPhase::Ready || control.stop_requested() {
            // S16o: the packet path sealed on the lapsed lease first.
            lapsed_under_reacks(reacks, &bridge, steps);
            return (observed, Ok(()));
        }
        let pending = reacks.in_flight() > 0;
        let now = match bridge.clock_ns() {
            Ok(now) if now < lease.deadline_ns => now,
            _ => {
                seal_expired(&probe, reacks, steps);
                return (observed, Ok(()));
            }
        };
        // S18: a wake forces one re-ACK as soon as the spacing allows. S16k:
        // a second request follows the one in flight by its stagger.
        let forced = probe.reack_requested();
        let p90 = exchange_p90(&reacks.exchanges);
        let spacing = if pending {
            reack_stagger(p90)
        } else {
            REACK_SPACING
        };
        if reacks.in_flight() < ACK_IN_FLIGHT && now >= reack_due_ns(lease, forced, spacing) {
            steps.mark("reack_attempt");
            // The attempt starting now serves every request made before it.
            if probe.take_reack() {
                steps.mark("reack_forced");
                crate::apple::log_code("reack", "forced");
            }
            // Read after the mark: attempts are spaced from this instant.
            let Ok(started) = bridge.clock_ns() else {
                seal_expired(&probe, reacks, steps);
                return (observed, Ok(()));
            };
            lease.last_attempt_ns = started;
            if started >= lease.deadline_ns {
                seal_expired(&probe, reacks, steps);
                return (observed, Ok(()));
            }
            let Ok(request) = observed
                .begin_reack_with_transport(Some((steps.pinned.clone(), pin)), Some(gate.clone()))
            else {
                probe.seal("store_revalidation_failed");
                return (observed, refused("store_revalidation_failed"));
            };
            // Bound requests open a new round of pre-warm dials (S16l: and
            // of ACK connection dials).
            reacks.pool.dials = 0;
            if let Some(link) = &reacks.pool.link {
                link.note_request();
            }
            dispatch(
                (request, tokio::time::Instant::now()),
                (&mut reacks.pool, &mut reacks.attempts, &mut reacks.waiting),
                request_limit(p90, reacks.span_ns),
                &bridge,
                &reacks.lease_end,
                steps,
            );
            let in_flight = reacks.in_flight();
            if in_flight > 1 {
                steps.mark("reack_pipelined");
            }
            let counted = u128::try_from(in_flight).unwrap_or(u128::MAX);
            reacks.inflight_log.note("reack_inflight", "n", counted);
        }
        // Fill each free slot once its channel is due: at once with 3 s ACKs,
        // also while a request is out, so setup overlaps the exchange. S16l:
        // the first slot to fill after the ACK connection was lost (its
        // streams end with it, freeing their slots) redials it, at once.
        let outstanding = reacks.in_flight() > 0;
        let pool = &mut reacks.pool;
        while pool.may_dial()
            && now >= prewarm_due_ns(lease, reacks.span_ns, outstanding, pool.busy())
        {
            let Ok(opener) = observed.begin_prewarm() else {
                probe.seal("store_revalidation_failed");
                return (observed, refused("store_revalidation_failed"));
            };
            pool.start(&Handle::current(), opener, steps);
        }
        // Wake for the lease end and, when due, the next attempt or dial.
        let mut wake_ns = lease.deadline_ns;
        if reacks.in_flight() < ACK_IN_FLIGHT {
            let spacing = if outstanding {
                reack_stagger(p90)
            } else {
                REACK_SPACING
            };
            wake_ns = wake_ns.min(reack_due_ns(lease, forced, spacing));
        }
        if reacks.pool.may_dial() {
            wake_ns = wake_ns.min(prewarm_due_ns(
                lease,
                reacks.span_ns,
                outstanding,
                reacks.pool.busy(),
            ));
        }
        let wake = Duration::from_nanos(wake_ns.saturating_sub(now));
        let attempting = !reacks.attempts.is_empty();
        let prewarming = reacks.pool.busy() > 0;
        let event = tokio::select! {
            biased;
            _ = &mut *stop => Event::Stop,
            done = next_outcome(&mut reacks.attempts), if attempting => Event::Reack(done),
            event = reacks.pool.next(), if prewarming => Event::Prewarm(event),
            _ = observed.drive_ack_transport(), if transport_open => Event::TransportEnded,
            _ = tick.tick() => Event::Tick,
            _ = tokio::time::sleep(wake) => Event::Wake,
            // A forced re-ACK request re-evaluates the schedule at once.
            () = probe.reack_signalled() => Event::Wake,
        };
        let p90 = exchange_p90(&reacks.exchanges);
        match event {
            Event::Stop => {
                lapsed_under_reacks(reacks, &bridge, steps);
                return (observed, Ok(()));
            }
            Event::Prewarm(PrewarmEvent::Opened { channel }) => {
                // The task has returned; its handle is spent.
                steps.mark("reack_prewarm_joined");
                match channel {
                    Some(warm) => reacks.pool.put_ready(warm),
                    None => steps.mark("reack_prewarm_failed"),
                }
                if let Some(request) = reacks.waiting.pop_front() {
                    dispatch(
                        request,
                        (&mut reacks.pool, &mut reacks.attempts, &mut reacks.waiting),
                        request_limit(p90, reacks.span_ns),
                        &bridge,
                        &reacks.lease_end,
                        steps,
                    );
                }
            }
            Event::Prewarm(PrewarmEvent::IdleEnded) => {
                // Its slot is free; the schedule above dials it again.
                crate::apple::log_code(PREWARM_EVENT, "idle_closed");
                steps.mark("reack_prewarm_failed");
            }
            Event::Reack(Outcome::Retry(request)) => {
                // The same bound request, on another channel or fresh.
                dispatch(
                    request,
                    (&mut reacks.pool, &mut reacks.attempts, &mut reacks.waiting),
                    request_limit(p90, reacks.span_ns),
                    &bridge,
                    &reacks.lease_end,
                    steps,
                );
            }
            Event::Reack(Outcome::Done(done)) => {
                match done.map(|reacked| renew(&mut observed, &bridge, &mut lease, *reacked)) {
                    Some(Renewal::Renewed {
                        via,
                        bound,
                        exchange: round_trip,
                        span_ns: span,
                    }) => {
                        steps.renewed(via, bound.elapsed());
                        // The new channel's driver is live; the old one was
                        // dropped.
                        transport_open = true;
                        reacks.lease_end.set(lease.deadline_ns);
                        reacks.span_ns = span;
                        lease.lead = note_exchange(reacks, round_trip);
                        steps.mark("reack_renewed");
                        reacks.renewals = reacks.renewals.saturating_add(1);
                        if reack_ok_logged(reacks.renewals) {
                            let code = format!("{}_ms:{}", via.code(), round_trip.as_millis());
                            crate::apple::log_code("reack_ok", &code);
                        }
                    }
                    Some(Renewal::Superseded {
                        exchange: round_trip,
                    }) => {
                        lease.lead = note_exchange(reacks, round_trip);
                        steps.mark("reack_superseded");
                    }
                    Some(Renewal::Sealed(code, ended)) => {
                        probe.seal(code);
                        return (observed, ended);
                    }
                    Some(Renewal::Refused) | None => steps.mark("reack_failed"),
                }
            }
            Event::TransportEnded => {
                transport_open = false;
                steps.mark("ack_transport_ended");
            }
            Event::Tick => {
                // An expired lease seals inside `ready`.
                if !probe.ready() {
                    lapsed_under_reacks(reacks, &bridge, steps);
                    return (observed, Ok(()));
                }
                if observed.revalidate_bound_ack().is_err() {
                    probe.seal("store_revalidation_failed");
                    return (observed, refused("store_revalidation_failed"));
                }
                // S18: re-pinned after this session became Ready, before or
                // while it was swapped in: its relay sockets are on the lost
                // interface, so it seals and the epoch rebuilds on the pin.
                if !steps.pin_current(pin) {
                    crate::apple::log_code("session_pin_stale", "running");
                    probe.seal("relay_path_changed");
                    return (observed, refused("relay_path_changed"));
                }
            }
            Event::Wake => {}
        }
    }
}

/// Record a verified PolicyAck round trip; the lead it gives (`reack_lead`
/// of the window's p90), logged when it changed.
fn note_exchange(reacks: &mut Reacks, round_trip: Duration) -> Duration {
    record_exchange(&mut reacks.exchanges, round_trip);
    let lead = reack_lead(exchange_p90(&reacks.exchanges));
    reacks.lead_log.note("reack_lead", "ms", lead.as_millis());
    lead
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        policy::FullWide,
        test_fixture::ReadyTree,
        test_relay::{
            AckReply, Behavior, RelayIdentity, RelayStep, StalledListener, TestRelay,
            ADMISSION_TIMEOUT,
        },
    };
    use aegis_client::protected_identity_store::ProtectedIdentityStore;
    use std::{
        path::{Path, PathBuf},
        sync::{mpsc, Mutex},
    };

    // (step, Store still locked, when)
    type Log = Arc<Mutex<Vec<(&'static str, bool, Instant)>>>;

    #[test]
    fn web_ingress_guard_amendment_is_generation_and_arm_bound() {
        let gate = crate::leak_guard::Gate::new();
        let pins = EpochPins::default();
        let interface = RelayInterface::for_test("en0", 7);
        pins.pin(&interface);
        let bootstrap: std::net::SocketAddr = "198.51.100.5:443".parse().unwrap();
        let ingress: std::net::SocketAddr = "198.51.100.6:9443".parse().unwrap();
        pins.set_guard(GuardEndpoints::pool(&[bootstrap], None).unwrap());
        let first = pins.authorize_web_ingress_on(&gate, 0, ingress).unwrap();
        assert!(pins.guard().unwrap().relays.contains(ingress.into()));

        let guard = pins.guard().unwrap();
        let arm = gate
            .arm_pins_with_base(&guard.relays, usize::from(guard.base_len), false)
            .unwrap();
        pins.set_leak_arm(arm);
        let next: std::net::SocketAddr = "198.51.100.7:9443".parse().unwrap();
        let second = pins.authorize_web_ingress_on(&gate, 0, next).unwrap();
        let second_shared = pins.authorize_web_ingress_on(&gate, 0, next).unwrap();
        assert!(!gate.dial_refused(next));
        assert!(pins
            .authorize_web_ingress_on(&gate, 1, "198.51.100.8:9443".parse().unwrap())
            .is_none());
        assert!(pins
            .authorize_web_ingress_on(&gate, 0, "0.0.0.0:9443".parse().unwrap())
            .is_none());
        drop(second);
        assert!(!gate.dial_refused(next));
        drop(second_shared);
        assert!(gate.dial_refused(next));
        drop(first);
        assert!(gate.dial_refused(ingress));
        assert!(!pins.guard().unwrap().relays.contains(ingress.into()));
        let newer = gate.arm_pins(
            &crate::leak_guard::PeerSet::one(Some(bootstrap.into())),
            false,
        );
        assert!(pins
            .authorize_web_ingress_on(&gate, 0, "198.51.100.8:9443".parse().unwrap())
            .is_none());
        assert!(gate.dial_refused(next));
        assert!(gate.disarm(newer));
        pins.repin(&interface);
        assert!(pins.authorize_web_ingress_on(&gate, 0, ingress).is_none());
    }

    #[test]
    fn old_web_ingress_lease_cannot_withdraw_new_generation_tuple() {
        let gate = crate::leak_guard::Gate::new();
        let pins = EpochPins::default();
        let interface = RelayInterface::for_test("en0", 7);
        let bootstrap: std::net::SocketAddr = "198.51.100.5:443".parse().unwrap();
        let ingress: std::net::SocketAddr = "198.51.100.6:9443".parse().unwrap();
        pins.pin(&interface);
        pins.set_guard(GuardEndpoints::pool(&[bootstrap], None).unwrap());
        let old = pins.authorize_web_ingress_on(&gate, 0, ingress).unwrap();
        pins.repin(&interface);
        pins.set_guard(GuardEndpoints::pool(&[bootstrap], None).unwrap());
        let new = pins.authorize_web_ingress_on(&gate, 1, ingress).unwrap();
        let guard = pins.guard().unwrap();
        let arm = gate
            .arm_pins_with_base(&guard.relays, usize::from(guard.base_len), false)
            .unwrap();
        pins.set_leak_arm(arm);
        drop(old);
        assert!(!gate.dial_refused(ingress));
        drop(new);
        assert!(gate.dial_refused(ingress));
    }

    #[test]
    fn replaced_guard_cannot_lose_new_session_ingress_owner() {
        let gate = crate::leak_guard::Gate::new();
        let pins = EpochPins::default();
        let interface = RelayInterface::for_test("en0", 7);
        let bootstrap: std::net::SocketAddr = "198.51.100.5:443".parse().unwrap();
        let ingress: std::net::SocketAddr = "198.51.100.6:9443".parse().unwrap();
        pins.pin(&interface);
        pins.set_guard(GuardEndpoints::pool(&[bootstrap], None).unwrap());
        let old = pins.authorize_web_ingress_on(&gate, 0, ingress).unwrap();
        pins.set_guard(GuardEndpoints::pool(&[bootstrap], None).unwrap());
        let new = pins.authorize_web_ingress_on(&gate, 0, ingress).unwrap();
        let guard = pins.guard().unwrap();
        let arm = gate
            .arm_pins_with_base(&guard.relays, usize::from(guard.base_len), false)
            .unwrap();
        pins.set_leak_arm(arm);
        drop(old);
        assert!(!gate.dial_refused(ingress));
        drop(new);
        assert!(gate.dial_refused(ingress));
    }

    #[test]
    fn sfu_candidate_batch_is_atomic_and_scoped_to_ice_peer_lifetime() {
        let gate = crate::leak_guard::Gate::new();
        let pins = EpochPins::default();
        let interface = RelayInterface::for_test("en0", 7);
        let bootstrap: std::net::SocketAddr = "198.51.100.5:443".parse().unwrap();
        let one: std::net::SocketAddr = "198.51.100.20:7882".parse().unwrap();
        let two: std::net::SocketAddr = "198.51.100.21:7883".parse().unwrap();
        pins.pin(&interface);
        pins.set_guard(GuardEndpoints::pool(&[bootstrap], None).unwrap());
        let arm = gate.arm_pins(&pins.guard().unwrap().relays, false);
        pins.set_leak_arm(arm);
        assert!(pins
            .authorize_udp_media_on(&gate, 0, &interface, &[one, "0.0.0.0:4".parse().unwrap()])
            .is_none());
        assert!(gate.snapshot().0.udp_media.is_empty());
        assert!(pins
            .authorize_udp_media_on(&gate, 1, &interface, &[one])
            .is_none());
        let first = pins
            .authorize_udp_media_on(&gate, 0, &interface, &[one, two])
            .unwrap();
        let second = pins
            .authorize_udp_media_on(&gate, 0, &interface, &[one])
            .unwrap();
        assert_eq!(gate.snapshot().0.udp_media.len(), 2);
        drop(first);
        assert_eq!(
            gate.snapshot().0.udp_media,
            crate::leak_guard::PeerSet::one(Some(one.into()))
        );
        drop(second);
        assert!(gate.snapshot().0.udp_media.is_empty());
    }

    #[test]
    fn repeated_sfu_trickle_is_bounded_without_withdrawing_live_pin() {
        let gate = crate::leak_guard::Gate::new();
        let pins = EpochPins::default();
        let interface = RelayInterface::for_test("en0", 7);
        let bootstrap: std::net::SocketAddr = "198.51.100.5:443".parse().unwrap();
        let candidate: std::net::SocketAddr = "198.51.100.20:7882".parse().unwrap();
        pins.pin(&interface);
        pins.set_guard(GuardEndpoints::pool(&[bootstrap], None).unwrap());
        let arm = gate.arm_pins(&pins.guard().unwrap().relays, false);
        pins.set_leak_arm(arm);
        let mut held = Vec::new();
        for _ in 0..MAX_UDP_MEDIA_LEASES_PER_PIN {
            held.push(
                pins.authorize_udp_media_on(&gate, 0, &interface, &[candidate])
                    .unwrap(),
            );
        }
        assert!(pins
            .authorize_udp_media_on(&gate, 0, &interface, &[candidate])
            .is_none());
        assert_eq!(gate.snapshot().0.udp_media.len(), 1);
        held.pop();
        held.push(
            pins.authorize_udp_media_on(&gate, 0, &interface, &[candidate])
                .unwrap(),
        );
        drop(held);
        assert!(gate.snapshot().0.udp_media.is_empty());
    }

    pub(crate) fn frame() -> Vec<u8> {
        let mut p = vec![0; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&20u16.to_be_bytes());
        p
    }

    fn relay_and_tree(behavior: impl FnOnce(&ReadyTree) -> Behavior) -> (TestRelay, ReadyTree) {
        let listener = TestRelay::bind();
        let tree = ReadyTree::with_online_completed(listener.local_addr().unwrap());
        let behavior = behavior(&tree);
        let relay = TestRelay::spawn(listener, RelayIdentity::for_tree(&tree), behavior);
        assert_eq!(relay.address(), tree.relay());
        (relay, tree)
    }

    // aegis-server: the connection outlives every ACK lease it grants.
    fn acks_then_closes(tree: &ReadyTree) -> Behavior {
        Behavior::AckThenClose {
            reply: AckReply::for_tree(tree),
            idle: ADMISSION_TIMEOUT,
        }
    }

    // A connection dropped (no GOAWAY, no close_notify) while the lease runs.
    fn acks_then_drops_early(tree: &ReadyTree) -> Behavior {
        Behavior::AckThenClose {
            reply: AckReply::for_tree(tree),
            idle: Duration::from_secs(1),
        }
    }

    pub(crate) fn logged(log: &Log, wanted: &'static str) -> bool {
        log.lock()
            .unwrap()
            .iter()
            .any(|(step, _, _)| *step == wanted)
    }

    pub(crate) fn saved(tree: &ReadyTree) -> SavedProviderIntent {
        SavedProviderIntent {
            generation: tree.generation().into(),
            policy: tree.policy().clone(),
        }
    }

    pub(crate) fn store_locked(identity: &Path) -> bool {
        ProtectedIdentityStore::open_existing(identity).is_err()
    }

    // Each step records whether the protected Store is still held.
    fn recorder(identity: PathBuf) -> (Trace, Log) {
        let log: Log = Arc::default();
        let held = log.clone();
        let trace: Trace = Arc::new(move |step| {
            let locked = store_locked(&identity);
            held.lock().unwrap().push((step, locked, Instant::now()));
        });
        (trace, log)
    }

    fn start(
        tree: &ReadyTree,
        saved: SavedProviderIntent,
        trace: Option<Trace>,
    ) -> (SessionHandle, mpsc::Receiver<SessionPhase>) {
        let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
        let (tx, rx) = mpsc::channel();
        let session = spawn_traced(
            saved,
            claim,
            move |phase| {
                let _ = tx.send(phase);
            },
            trace,
        )
        .unwrap();
        (session, rx)
    }

    pub(crate) fn expect_phase(
        phases: &mpsc::Receiver<SessionPhase>,
        session: &SessionHandle,
        expected: SessionPhase,
    ) {
        let phase = phases.recv_timeout(Duration::from_secs(2));
        assert_eq!(phase.ok(), Some(expected), "{:?}", session.refusal());
    }

    // First instant at which `done` holds, polling every millisecond.
    pub(crate) fn wait_until(budget: Duration, mut done: impl FnMut() -> bool) -> Option<Instant> {
        let deadline = Instant::now() + budget;
        loop {
            if done() {
                return Some(Instant::now());
            }
            if Instant::now() >= deadline {
                return None;
            }
            thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn relay_drain_reports_a_pending_gate_once_and_returns_only_once_drained() {
        // S16j-3: a gate still holding a flow after the first bounded
        // attempt is reported once, with its counts, and the drain goes on
        // (so the Store stays held) until the flow's permit is back.
        let gate = WorkGate::new();
        let permit = gate.admit().unwrap();
        let pending: Arc<Mutex<Vec<(usize, usize, Instant)>>> = Arc::default();
        let (seen, draining) = (pending.clone(), gate.clone());
        let started = Instant::now();
        let drain = thread::spawn(move || {
            let runtime = Builder::new_current_thread().enable_all().build().unwrap();
            // A gate task on the runtime the drain waits on.
            let task = runtime
                .block_on(async { draining.spawn(std::future::pending()) })
                .unwrap();
            drain_relay(&runtime, &draining, |tasks, flows| {
                seen.lock().unwrap().push((tasks, flows, Instant::now()));
            });
            drop(task);
            Instant::now()
        });
        // Past the first attempt and into a second full one.
        thread::sleep(RELAY_DRAIN_FIRST + MAX_DRAIN + Duration::from_millis(300));
        assert!(!drain.is_finished());
        assert!(!gate.drained());
        let released = Instant::now();
        drop(permit);
        let drained = drain.join().unwrap();
        assert!(drained >= released);
        assert!(gate.drained());
        let pending = pending.lock().unwrap();
        assert_eq!(pending.len(), 1, "{pending:?}");
        let (tasks, flows, at) = pending[0];
        // The aborted task was dropped within the first attempt.
        assert_eq!((tasks, flows), (0, 1));
        assert!(at.duration_since(started) >= RELAY_DRAIN_FIRST);
        assert!(at.duration_since(started) < RELAY_DRAIN_FIRST + Duration::from_millis(400));
    }

    #[test]
    fn relay_drain_of_a_drained_gate_reports_nothing() {
        let gate = WorkGate::new();
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        let task = runtime
            .block_on(async { gate.spawn(std::future::pending()) })
            .unwrap();
        let started = Instant::now();
        drain_relay(&runtime, &gate, |_, _| panic!("reported a drained gate"));
        assert!(started.elapsed() < Duration::from_millis(250));
        assert!(gate.drained());
        drop(task);
    }

    #[test]
    fn prewarm_pool_keeps_both_slots_and_the_ack_reserve_under_a_flow_burst() {
        use crate::establish_limit::{ACK_RESERVE, ESTABLISH_PERMITS};
        // Both pre-warm slots and (S16k) two requests in flight: S16e lost
        // the installed relay's lease with one slot.
        assert_eq!((PREWARM_SLOTS, ACK_IN_FLIGHT, ACK_RESERVE), (2, 2, 4));
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        let limiter = EstablishLimiter::new(AuthBackoff::default());
        let mut pool = Pool::new(limiter.clone(), None);
        let steps = Steps::traced(None);
        runtime.block_on(async {
            // One slot busy with an open that never finishes.
            pool.slots[0] = Prewarm::Pending {
                task: tokio::spawn(std::future::pending()),
            };
            // Every flow permit held and one more flow waiting.
            let mut held = Vec::new();
            for _ in 0..ESTABLISH_PERMITS - ACK_RESERVE {
                held.push(
                    limiter
                        .acquire(Purpose::Flow, Duration::ZERO)
                        .await
                        .unwrap(),
                );
            }
            let mut waiting = Box::pin(limiter.acquire(Purpose::Flow, Duration::from_secs(5)));
            assert!(futures_poll_once(&mut waiting).await.is_none());
            assert!(limiter.flows_establishing());
            // The second slot is still dialed...
            assert!(pool.may_dial());
            // ...and both pre-warms plus both re-ACK requests find their
            // permits at once, ahead of the waiting flow.
            let mut acks = Vec::new();
            for _ in 0..ACK_RESERVE {
                acks.push(limiter.acquire(Purpose::Ack, Duration::ZERO).await.unwrap());
            }
            assert_eq!(
                limiter.active(),
                (ACK_RESERVE, ESTABLISH_PERMITS - ACK_RESERVE)
            );
            drop(acks);
            drop(held);
            let flow = tokio::time::timeout(Duration::from_secs(1), waiting)
                .await
                .expect("the waiting flow never started")
                .unwrap();
            assert!(pool.may_dial());
            drop(flow);
            pool.join(&steps).await;
        });
    }

    /// Poll `future` once; Some when it finished.
    async fn futures_poll_once<F: Future + Unpin>(future: &mut F) -> Option<F::Output> {
        std::future::poll_fn(|cx| match Pin::new(&mut *future).poll(cx) {
            Poll::Ready(output) => Poll::Ready(Some(output)),
            Poll::Pending => Poll::Ready(None),
        })
        .await
    }

    #[test]
    fn a_prewarm_age_runs_from_its_dial_after_its_permit_wait() {
        let (_relay, tree) = relay_and_tree(acks_then_closes);
        let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
        let (mut prepared, _store) =
            PreparedLocalSession::from_claim_with_store_guard(claim).unwrap();
        let opener = prepared
            .begin_first_prewarm(&saved(&tree), &RelayInterface::loopback_for_test())
            .unwrap();
        let runtime = Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let wait = Duration::from_millis(400);
        let limiter = EstablishLimiter::for_test(1, 0, AUTH_BACKOFF);
        runtime.block_on(async {
            // The only permit is held: the pre-warm waits for it.
            let held = limiter.acquire(Purpose::Ack, Duration::ZERO).await.unwrap();
            let spawned = tokio::time::Instant::now();
            let task = tokio::spawn(open_channel(opener, limiter.clone(), None));
            tokio::time::sleep(wait).await;
            let released = tokio::time::Instant::now();
            drop(held);
            let warm = task.await.unwrap().expect("the pre-warm never opened");
            // Its age starts at its dial, after the wait, not at its spawn.
            assert!(warm.dialed >= released, "{:?}", warm.dialed - spawned);
            assert_eq!(limiter.active(), (1, 0));
            drop(warm);
            assert_eq!(limiter.active(), (0, 0));
        });
        drop(runtime);
    }

    #[test]
    fn a_prewarm_on_the_ack_connection_ages_from_its_last_live_channel() {
        // S16l: on an ACK connection with no live channel, a pre-warmed
        // stream inherits the relay's idle deadline: it ages from when the
        // connection last had one (here: since it came up), not from its own
        // request; beside a live one it ages from its request.
        let listener = TestRelay::bind();
        let tree = ReadyTree::with_online_completed(listener.local_addr().unwrap());
        let config = crate::test_relay::pool::PoolConfig {
            reply: Some(AckReply::for_tree(&tree)),
            ..Default::default()
        };
        let _relay = TestRelay::spawn_streams(listener, RelayIdentity::for_tree(&tree), config);
        let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
        let (mut prepared, _store) =
            PreparedLocalSession::from_claim_with_store_guard(claim).unwrap();
        let interface = RelayInterface::loopback_for_test();
        let opener = prepared
            .begin_first_prewarm(&saved(&tree), &interface)
            .unwrap();
        let runtime = Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let limiter = EstablishLimiter::new(AuthBackoff::default());
        let gate = WorkGate::new();
        let pins = EpochPins::pinned_for_test(interface.clone());
        let link = prepared
            .ack_link(
                &interface,
                (limiter.clone(), gate.clone()),
                (pins.clone(), pins.generation()),
                None,
            )
            .unwrap();
        let idle = Duration::from_millis(600);
        assert!(idle < crate::ack_conn::ACK_IDLE_REUSE);
        runtime.block_on(async {
            let permit = limiter.acquire(Purpose::Ack, CONNECT_BUDGET).await.unwrap();
            let up = link.conn(CONNECT_BUDGET).await.unwrap().unwrap();
            let came_up = tokio::time::Instant::now();
            drop((permit, up));
            tokio::time::sleep(idle).await;
            let warm = open_channel(opener.clone(), limiter.clone(), Some(link.clone()))
                .await
                .expect("no pre-warm");
            assert!(warm.channel.conn().is_some(), "not a stream of the link");
            assert!(warm.dialed <= came_up, "{:?}", warm.dialed - came_up);
            assert!(warm.dialed.elapsed() >= idle);
            let requested = tokio::time::Instant::now();
            let next = open_channel(opener, limiter.clone(), Some(link.clone()))
                .await
                .expect("no second pre-warm");
            assert!(next.dialed >= requested);
            drop((warm, next));
        });
        runtime
            .block_on(gate.stop_async(Duration::from_secs(1)))
            .unwrap();
        drop(link);
        drop(runtime);
    }

    #[test]
    fn a_closed_ack_connection_starts_no_dial_of_its_own() {
        // S16l: once the epoch re-pinned (S18) or the gate closed, neither a
        // pre-warm nor a fresh re-ACK falls back to a dial of its own: the
        // session is stale, or stopping.
        let listener = TestRelay::bind();
        let tree = ReadyTree::with_online_completed(listener.local_addr().unwrap());
        let config = crate::test_relay::pool::PoolConfig {
            reply: Some(AckReply::for_tree(&tree)),
            ..Default::default()
        };
        let relay = TestRelay::spawn_streams(listener, RelayIdentity::for_tree(&tree), config);
        let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
        let (mut prepared, _store) =
            PreparedLocalSession::from_claim_with_store_guard(claim).unwrap();
        let interface = RelayInterface::loopback_for_test();
        let saved = saved(&tree);
        let opener = prepared.begin_first_prewarm(&saved, &interface).unwrap();
        let runtime = Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let limiter = EstablishLimiter::new(AuthBackoff::default());
        let gate = WorkGate::new();
        let pins = EpochPins::pinned_for_test(interface.clone());
        let link = prepared
            .ack_link(
                &interface,
                (limiter.clone(), gate.clone()),
                (pins.clone(), pins.generation()),
                None,
            )
            .unwrap();
        let bridge =
            LeasedPacketBridge::new(PacketBridge::default(), CaptureLeaseDeadline::default());
        let mut observed = runtime.block_on(async {
            let permit = limiter.acquire(Purpose::Ack, CONNECT_BUDGET).await.unwrap();
            let up = link.conn(CONNECT_BUDGET).await.unwrap().unwrap();
            let observed = prepared
                .observe_ack_on_link(saved, &link, up, interface.clone())
                .await
                .unwrap();
            permit.succeeded();
            observed
        });
        assert_eq!(relay.conns(), 1);
        pins.repin(&interface);
        assert!(link.closed());
        let request = observed.begin_reack().unwrap();
        let lease_end = LeaseEnd::new(bridge.clock_ns().unwrap() + 10_000_000_000);
        runtime.block_on(async {
            let warm = open_channel(opener, limiter.clone(), Some(link.clone())).await;
            assert!(warm.is_none(), "a pre-warm dialed after the re-pin");
            let attempt = reack_attempt(
                (request, tokio::time::Instant::now()),
                None,
                bridge.clone(),
                lease_end,
                Duration::from_secs(1),
                (limiter.clone(), Some(link.clone())),
                Steps::traced(None),
            );
            assert!(matches!(attempt.await, Outcome::Done(None)));
        });
        // No connection beyond the ACK connection itself.
        thread::sleep(Duration::from_millis(200));
        assert_eq!(relay.conns(), 1);
        assert_eq!(limiter.active(), (0, 0));
        drop(observed);
        runtime
            .block_on(gate.stop_async(Duration::from_secs(1)))
            .unwrap();
        drop(link);
        drop(runtime);
    }

    #[test]
    fn a_request_on_a_frozen_ack_connection_ends_at_its_stall_watchdog() {
        // S16l: a PolicyAck awaiting its reply on the ACK connection arms
        // that connection's stall watchdog, so on a path that froze it (no
        // byte read, none acknowledged) the request fails once the watchdog
        // closes it, long before its own bound, and comes back for another
        // channel.
        let listener = TestRelay::bind();
        let tree = ReadyTree::with_online_completed(listener.local_addr().unwrap());
        let config = crate::test_relay::pool::PoolConfig {
            reply: Some(AckReply::for_tree(&tree)),
            ..Default::default()
        };
        let relay = TestRelay::spawn_streams(listener, RelayIdentity::for_tree(&tree), config);
        let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
        let (mut prepared, _store) =
            PreparedLocalSession::from_claim_with_store_guard(claim).unwrap();
        let interface = RelayInterface::loopback_for_test();
        let saved = saved(&tree);
        let opener = prepared.begin_first_prewarm(&saved, &interface).unwrap();
        let runtime = Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let limiter = EstablishLimiter::new(AuthBackoff::default());
        let gate = WorkGate::new();
        let pins = EpochPins::pinned_for_test(interface.clone());
        let link = prepared
            .ack_link(
                &interface,
                (limiter.clone(), gate.clone()),
                (pins.clone(), pins.generation()),
                None,
            )
            .unwrap();
        let bridge =
            LeasedPacketBridge::new(PacketBridge::default(), CaptureLeaseDeadline::default());
        let (mut observed, warm) = runtime.block_on(async {
            let permit = limiter.acquire(Purpose::Ack, CONNECT_BUDGET).await.unwrap();
            let up = link.conn(CONNECT_BUDGET).await.unwrap().unwrap();
            let observed = prepared
                .observe_ack_on_link(saved, &link, up, interface.clone())
                .await
                .unwrap();
            permit.succeeded();
            let warm = open_channel(opener, limiter.clone(), Some(link.clone()))
                .await
                .expect("no pre-warm");
            (observed, warm)
        });
        // Nothing else on the connection: only this request arms its watchdog.
        relay.freeze(0);
        assert!(link.freeze_acks_for_test());
        let request = observed.begin_reack().unwrap();
        let lease_end = LeaseEnd::new(bridge.clock_ns().unwrap() + 30_000_000_000);
        let bound = Duration::from_secs(8);
        let started = Instant::now();
        let outcome = runtime.block_on(reack_attempt(
            (request, tokio::time::Instant::now()),
            Some(warm),
            bridge.clone(),
            lease_end,
            bound,
            (limiter.clone(), Some(link.clone())),
            Steps::traced(None),
        ));
        let took = started.elapsed();
        assert!(matches!(outcome, Outcome::Retry(_)));
        let watchdog =
            crate::flow_pool::STALL_QUIET + crate::flow_pool::PONG_FLOOR + Duration::from_secs(1);
        assert!(took < watchdog, "{took:?}");
        assert!(link.current().is_none());
        drop(observed);
        runtime
            .block_on(gate.stop_async(Duration::from_secs(1)))
            .unwrap();
        drop(link);
        drop(runtime);
    }

    #[test]
    fn a_prewarm_on_a_frozen_ack_connection_falls_back_at_its_stall_watchdog() {
        // S16l: a stream establishing on the ACK connection arms its stall
        // watchdog too, so a pre-warm on a connection a path froze fails
        // once the watchdog closes it (long before the connect budget), and,
        // the link's dial budget spent, falls back to a dial of its own.
        let listener = TestRelay::bind();
        let tree = ReadyTree::with_online_completed(listener.local_addr().unwrap());
        let config = crate::test_relay::pool::PoolConfig {
            reply: Some(AckReply::for_tree(&tree)),
            ..Default::default()
        };
        let relay = TestRelay::spawn_streams(listener, RelayIdentity::for_tree(&tree), config);
        let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
        let (mut prepared, _store) =
            PreparedLocalSession::from_claim_with_store_guard(claim).unwrap();
        let interface = RelayInterface::loopback_for_test();
        let opener = prepared
            .begin_first_prewarm(&saved(&tree), &interface)
            .unwrap();
        let runtime = Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let limiter = EstablishLimiter::new(AuthBackoff::default());
        let gate = WorkGate::new();
        let pins = EpochPins::pinned_for_test(interface.clone());
        let link = prepared
            .ack_link(
                &interface,
                (limiter.clone(), gate.clone()),
                (pins.clone(), pins.generation()),
                None,
            )
            .unwrap();
        runtime.block_on(async {
            let permit = limiter.acquire(Purpose::Ack, CONNECT_BUDGET).await.unwrap();
            link.conn(CONNECT_BUDGET).await.unwrap().unwrap();
            drop(permit);
        });
        relay.freeze(0);
        assert!(link.freeze_acks_for_test());
        let started = Instant::now();
        let warm = runtime
            .block_on(open_channel(opener, limiter.clone(), Some(link.clone())))
            .expect("no pre-warm");
        let took = started.elapsed();
        assert!(warm.channel.conn().is_none(), "still on the frozen link");
        let watchdog =
            crate::flow_pool::STALL_QUIET + crate::flow_pool::PONG_FLOOR + Duration::from_secs(1);
        assert!(took < watchdog, "{took:?}");
        assert_eq!(relay.conns(), 2);
        runtime.block_on(async move { drop(warm) });
        runtime
            .block_on(gate.stop_async(Duration::from_secs(1)))
            .unwrap();
        drop(link);
        drop(runtime);
    }

    #[test]
    fn an_ack_connection_of_other_held_crypto_is_refused_before_a_byte() {
        // S16l: the ACK connection carries only its own session's channels:
        // an opener, a first ACK and a re-ACK of other held crypto are each
        // refused before any stream is opened on it.
        let pooled = |tree: &ReadyTree| crate::test_relay::pool::PoolConfig {
            reply: Some(AckReply::for_tree(tree)),
            ..Default::default()
        };
        let ours = TestRelay::bind();
        let tree = ReadyTree::with_online_completed(ours.local_addr().unwrap());
        let our_relay =
            TestRelay::spawn_streams(ours, RelayIdentity::for_tree(&tree), pooled(&tree));
        let theirs = TestRelay::bind();
        let other = ReadyTree::with_online_completed(theirs.local_addr().unwrap());
        let their_relay =
            TestRelay::spawn_streams(theirs, RelayIdentity::for_tree(&other), pooled(&other));
        let prepare = |tree: &ReadyTree| {
            let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
            PreparedLocalSession::from_claim_with_store_guard(claim).unwrap()
        };
        let (mut prepared, _store) = prepare(&tree);
        let (their_prepared, _their_store) = prepare(&other);
        let interface = RelayInterface::loopback_for_test();
        let runtime = Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let limiter = EstablishLimiter::new(AuthBackoff::default());
        let gate = WorkGate::new();
        let pins = EpochPins::pinned_for_test(interface.clone());
        let link_of = |prepared: &PreparedLocalSession| {
            prepared
                .ack_link(
                    &interface,
                    (limiter.clone(), gate.clone()),
                    (pins.clone(), pins.generation()),
                    None,
                )
                .unwrap()
        };
        let link = link_of(&prepared);
        let their_link = link_of(&their_prepared);
        let ours_saved = saved(&tree);
        let opener = prepared
            .begin_first_prewarm(&ours_saved, &interface)
            .unwrap();
        runtime.block_on(async {
            let permit = limiter.acquire(Purpose::Ack, CONNECT_BUDGET).await.unwrap();
            let theirs = their_link.conn(CONNECT_BUDGET).await.unwrap().unwrap();
            let up = link.conn(CONNECT_BUDGET).await.unwrap().unwrap();
            assert!(opener
                .clone()
                .establish_on_link(&their_link, theirs.clone(), "test_link")
                .await
                .is_err());
            let mut observed = prepared
                .observe_ack_on_link(ours_saved, &link, up, interface.clone())
                .await
                .unwrap();
            permit.succeeded();
            let request = observed.begin_reack().unwrap();
            let refused = request
                .observe_on_link(&their_link, theirs.clone(), CONNECT_BUDGET, "test_link")
                .await;
            assert!(refused.is_err());
            drop(observed);
            // Not one stream reached their relay.
            assert_eq!(their_relay.streams(), 0);
        });
        // A first ACK of their crypto on our connection, likewise.
        let ours_up = runtime.block_on(async {
            let _permit = limiter.acquire(Purpose::Ack, CONNECT_BUDGET).await.unwrap();
            link.note_request();
            link.conn(CONNECT_BUDGET).await.unwrap().unwrap()
        });
        let streams = our_relay.streams();
        let foreign = runtime.block_on(their_prepared.observe_ack_on_link(
            saved(&tree),
            &link,
            ours_up,
            interface.clone(),
        ));
        assert!(foreign.is_err());
        assert_eq!(our_relay.streams(), streams);
        runtime
            .block_on(gate.stop_async(Duration::from_secs(1)))
            .unwrap();
        drop((link, their_link));
        drop(runtime);
    }

    #[test]
    fn a_prewarm_queued_before_an_auth_failure_still_dials_after_the_backoff() {
        let (_relay, tree) = relay_and_tree(acks_then_closes);
        let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
        let (mut prepared, _store) =
            PreparedLocalSession::from_claim_with_store_guard(claim).unwrap();
        let opener = prepared
            .begin_first_prewarm(&saved(&tree), &RelayInterface::loopback_for_test())
            .unwrap();
        let runtime = Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let limiter = EstablishLimiter::for_test(1, 0, AUTH_BACKOFF);
        runtime.block_on(async {
            // Queued behind a held permit, then an authentication failure:
            // its wait must outlast the backoff that starts after it queued.
            let held = limiter.acquire(Purpose::Ack, Duration::ZERO).await.unwrap();
            let queued = tokio::time::Instant::now();
            let task = tokio::spawn(open_channel(opener, limiter.clone(), None));
            tokio::time::sleep(Duration::from_millis(300)).await;
            limiter.auth_failure(Purpose::Ack);
            drop(held);
            let warm = task.await.unwrap().expect("the queued pre-warm gave up");
            assert!(warm.dialed - queued >= AUTH_BACKOFF + Duration::from_millis(250));
            // It started after the failure: its PolicyAck would verify again.
            assert!(limiter.probing());
            drop(warm);
        });
        drop(runtime);
    }

    #[test]
    fn provider_session_first_dial_waits_out_the_epoch_auth_backoff_and_probes_alone() {
        let (relay, tree) = relay_and_tree(acks_then_closes);
        let pinned = EpochPins::pinned_for_test(RelayInterface::loopback_for_test());
        // A lost session of this epoch saw an authentication-class failure.
        EstablishLimiter::new(pinned.auth_backoff()).auth_failure(Purpose::Ack);
        let failed = Instant::now();
        let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
        let (tx, phases) = mpsc::channel();
        let mut session = spawn_pinned(
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
        // The rebuilt session's first dial waits out the epoch's backoff...
        let accepted = relay
            .wait_for(RelayStep::Accepted, AUTH_BACKOFF + Duration::from_secs(2))
            .expect("the first ACK never dialed");
        assert!(
            accepted.duration_since(failed) >= AUTH_BACKOFF - Duration::from_millis(50),
            "dialed {:?} after the failure",
            accepted.duration_since(failed)
        );
        expect_phase(&phases, &session, SessionPhase::Ready);
        // ...and runs alone: its pre-warms dial only once it was answered,
        // which verified the identity again.
        let written = relay
            .wait_for(RelayStep::AckWritten, Duration::from_secs(1))
            .expect("the first ACK was never written");
        let prewarm = relay
            .wait_for(RelayStep::Accepted, Duration::from_secs(1))
            .expect("no pre-warm dialed after the first ACK");
        assert!(prewarm >= written);
        assert!(!EstablishLimiter::new(pinned.auth_backoff()).probing());
        assert!(session.try_join(Duration::from_secs(2)));
        assert_eq!(session.refusal(), Some("provider_stop"));
        assert!(!store_locked(&tree.identity_dir()));
    }

    #[test]
    fn provider_session_tls_error_on_the_first_ack_backs_the_epoch_off() {
        let (relay, tree) = relay_and_tree(|_| Behavior::GarbleAck);
        let pinned = EpochPins::pinned_for_test(RelayInterface::loopback_for_test());
        let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
        let (tx, phases) = mpsc::channel();
        let mut session = spawn_pinned(
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
        expect_phase(&phases, &session, SessionPhase::Sealed);
        assert_eq!(session.refusal(), Some("session_ack_refused"));
        relay
            .wait_for(RelayStep::AckWritten, Duration::from_secs(1))
            .expect("the relay never answered the request");
        // A TLS error on the PolicyAck is authentication class: a session
        // rebuilt in this epoch waits it out.
        let rebuilt = EstablishLimiter::new(pinned.auth_backoff());
        assert!(rebuilt.backing_off());
        assert!(rebuilt.probing());
        assert!(session.try_join(Duration::from_secs(2)));
        assert!(!store_locked(&tree.identity_dir()));
    }

    #[test]
    fn provider_session_dropped_ack_is_not_an_authentication_failure() {
        // The relay ends the channel after the request: it refused the ACK,
        // which aegis-server does not count as an authentication failure.
        let (_relay, tree) = relay_and_tree(|_| Behavior::DropAfterRequest);
        let pinned = EpochPins::pinned_for_test(RelayInterface::loopback_for_test());
        let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
        let (tx, phases) = mpsc::channel();
        let mut session = spawn_pinned(
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
        expect_phase(&phases, &session, SessionPhase::Sealed);
        assert_eq!(session.refusal(), Some("session_ack_refused"));
        let rebuilt = EstablishLimiter::new(pinned.auth_backoff());
        assert!(!rebuilt.backing_off());
        assert!(!rebuilt.probing());
        assert!(session.try_join(Duration::from_secs(2)));
    }

    #[test]
    fn terminal_code_judges_expiry_on_time_not_on_revocation() {
        let now = Arc::new(std::sync::atomic::AtomicU64::new(10));
        let clock = now.clone();
        let bridge = LeasedPacketBridge::with_clock(
            PacketBridge::default(),
            CaptureLeaseDeadline::default(),
            move || Ok(clock.load(Ordering::SeqCst)),
        );
        // Nothing granted yet: never a live lease.
        assert_eq!(terminal_code(&bridge, true), "capture_lease_expired");
        bridge.grant_until(100).unwrap();
        assert_eq!(terminal_code(&bridge, false), "session_monitor_ended");
        // The engine's exit stops (and so revokes) the bridge mid-lease.
        bridge.stop();
        assert!(bridge.refreshable_deadline().is_revoked());
        assert_eq!(terminal_code(&bridge, true), "session_packet_terminal");
        assert_eq!(terminal_code(&bridge, false), "session_monitor_ended");
        // At and past the granted end it is an expiry, whatever else ended.
        for at in [100, 101, u64::MAX] {
            now.store(at, Ordering::SeqCst);
            assert_eq!(terminal_code(&bridge, true), "capture_lease_expired");
            assert_eq!(terminal_code(&bridge, false), "capture_lease_expired");
        }
        let broken = LeasedPacketBridge::with_clock(
            PacketBridge::default(),
            CaptureLeaseDeadline::default(),
            || Err(io::Error::other("clock unavailable")),
        );
        assert_eq!(terminal_code(&broken, true), "capture_lease_expired");
    }

    #[test]
    fn provider_session_ready_accepts_ipv4_and_tears_down_in_order() {
        let (relay, tree) = relay_and_tree(acks_then_closes);
        let (trace, log) = recorder(tree.identity_dir());
        let (mut session, phases) = start(&tree, saved(&tree), Some(trace));
        // The constructor returns before any Store, dial or ACK work is done.
        assert_eq!(session.phase(), SessionPhase::Constructing);
        expect_phase(&phases, &session, SessionPhase::Ready);
        let probe = session.probe();
        assert!(probe.ready());
        probe.bridge().from_os(&frame()).unwrap();
        assert!(store_locked(&tree.identity_dir()));
        // The first ACK's connection and the pre-warmed ones dialed beside it
        // (refused here: this relay serves only its first connection), plus
        // at most one dial again before any re-ACK is due.
        let dialed = 1 + PREWARM_SLOTS..=1 + PREWARM_DIALS_PER_REACK;
        wait_until(Duration::from_secs(1), || relay.accepts() > PREWARM_SLOTS)
            .expect("the first pre-warms never dialed");
        assert!(session.try_join(Duration::from_secs(2)));
        assert_eq!(session.phase(), SessionPhase::Joined);
        assert_eq!(session.refusal(), Some("provider_stop"));
        assert!(dialed.contains(&relay.accepts()), "{}", relay.accepts());
        assert!(probe.bridge().from_os(&frame()).is_err());
        // The server keeps the ACK connection past the stop, so the monitor's
        // driver stayed pending throughout and never saw the transport end.
        let log = log.lock().unwrap().clone();
        // The relay interface is resolved before the first dial.
        assert_eq!(
            log.iter()
                .take(2)
                .map(|(step, _, _)| *step)
                .collect::<Vec<_>>(),
            ["relay_interface", "dial"]
        );
        let teardown: Vec<_> = log
            .iter()
            .skip(2)
            .filter(|(step, _, _)| !step.starts_with("reack_"))
            .collect();
        assert_eq!(
            teardown
                .iter()
                .map(|(step, _, _)| *step)
                .collect::<Vec<_>>(),
            TEARDOWN
        );
        // The Store opens only once its guard, the very last step, is gone.
        for (step, locked, _) in &teardown {
            assert_eq!(*locked, *step != "store_guard_drop", "{step}");
        }
        assert!(!store_locked(&tree.identity_dir()));
        // The notifier fired once: Ready, never a later Sealed.
        assert!(phases.try_recv().is_err());
    }

    #[test]
    fn provider_session_issuance_change_on_disk_seals_within_500ms() {
        let (_relay, tree) = relay_and_tree(acks_then_closes);
        let (mut session, phases) = start(&tree, saved(&tree), None);
        expect_phase(&phases, &session, SessionPhase::Ready);
        let probe = session.probe();
        assert!(probe.ready());
        // The live ACK connection is still open: the 250 ms tick must run
        // beside a pending H2 driver.
        tree.rewrite_issued_generation(8);
        let changed = Instant::now();
        let sealed = wait_until(Duration::from_secs(2), || {
            session.phase() != SessionPhase::Ready
        })
        .expect("issuance change never sealed the session");
        assert!(
            sealed - changed <= Duration::from_millis(500),
            "sealed after {:?}",
            sealed - changed
        );
        assert_eq!(session.refusal(), Some("store_revalidation_failed"));
        assert!(!probe.ready());
        assert!(probe.bridge().from_os(&frame()).is_err());
        assert!(session.try_join(Duration::from_secs(2)));
        assert!(!store_locked(&tree.identity_dir()));
        assert!(phases.try_recv().is_err());
    }

    #[test]
    fn provider_session_refuses_peer_other_than_saved_relay_before_dial() {
        let (relay, tree) = relay_and_tree(acks_then_closes);
        let other = FullWide::new(
            "192.0.2.5".parse().unwrap(),
            tree.policy().dns().to_vec(),
            tree.policy().mtu(),
        )
        .unwrap();
        let saved = SavedProviderIntent {
            generation: tree.generation().into(),
            policy: other,
        };
        let (mut session, phases) = start(&tree, saved, None);
        expect_phase(&phases, &session, SessionPhase::Sealed);
        assert!(session.try_join(Duration::from_secs(2)));
        assert_eq!(session.refusal(), Some("session_peer_mismatch"));
        assert!(!store_locked(&tree.identity_dir()));
        // Any dial would have reached the relay's accept loop by now.
        assert!(relay
            .wait_for(RelayStep::Accepted, Duration::from_millis(300))
            .is_none());
        assert_eq!(relay.accepts(), 0);
    }

    fn start_on_interface(
        tree: &ReadyTree,
        trace: Option<Trace>,
        relay_interface: Option<RelayInterface>,
    ) -> (SessionHandle, mpsc::Receiver<SessionPhase>) {
        let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
        let (tx, rx) = mpsc::channel();
        let bridge =
            LeasedPacketBridge::new(PacketBridge::default(), CaptureLeaseDeadline::default());
        let session = spawn_on_interface(
            saved(tree),
            claim,
            move |phase| {
                let _ = tx.send(phase);
            },
            trace,
            bridge,
            relay_interface,
        )
        .unwrap();
        (session, rx)
    }

    #[test]
    fn provider_session_resolving_as_production_refuses_a_loopback_relay_before_dial() {
        let (relay, tree) = relay_and_tree(acks_then_closes);
        let (trace, log) = recorder(tree.identity_dir());
        let (mut session, phases) = start_on_interface(&tree, Some(trace), None);
        expect_phase(&phases, &session, SessionPhase::Sealed);
        assert!(session.try_join(Duration::from_secs(2)));
        assert_eq!(session.refusal(), Some(relay_socket::UNRESOLVED));
        assert!(!store_locked(&tree.identity_dir()));
        assert!(relay
            .wait_for(RelayStep::Accepted, Duration::from_millis(300))
            .is_none());
        assert_eq!(relay.accepts(), 0);
        // Refused before any runtime existed: no dial, no relay socket.
        let steps: Vec<_> = log.lock().unwrap().iter().map(|(s, _, _)| *s).collect();
        assert_eq!(steps, ["store_guard_drop"]);
    }

    #[test]
    fn provider_session_first_dial_uses_the_resolved_relay_interface() {
        let (relay, tree) = relay_and_tree(acks_then_closes);
        // An interface index no interface has: the bound first dial fails.
        let gone = RelayInterface::for_test("en99", 0x7fff_0000);
        let (mut session, phases) = start_on_interface(&tree, None, Some(gone));
        expect_phase(&phases, &session, SessionPhase::Sealed);
        assert!(session.try_join(Duration::from_secs(2)));
        assert_eq!(session.refusal(), Some("session_connect_failed"));
        assert!(!store_locked(&tree.identity_dir()));
        assert!(relay
            .wait_for(RelayStep::Accepted, Duration::from_millis(300))
            .is_none());
        assert_eq!(relay.accepts(), 0);
        // The same relay is reached over lo0, the explicit loopback override.
        let (relay, tree) = relay_and_tree(acks_then_closes);
        let lo = Some(RelayInterface::loopback_for_test());
        let (mut session, phases) = start_on_interface(&tree, None, lo);
        expect_phase(&phases, &session, SessionPhase::Ready);
        assert!(relay.accepts() >= 1);
        assert!(session.try_join(Duration::from_secs(2)));
        assert_eq!(session.refusal(), Some("provider_stop"));
    }

    #[test]
    fn provider_session_refuses_saved_dns_or_mtu_the_signed_bundle_does_not_name() {
        // (name, number of signed DNS servers kept, saved MTU)
        for (name, kept, mtu) in [("mtu", 2, 1400), ("dns", 1, 1280)] {
            let (relay, tree) = relay_and_tree(acks_then_closes);
            let mut dns = tree.policy().dns().to_vec();
            dns.truncate(kept);
            let saved = SavedProviderIntent {
                generation: tree.generation().into(),
                policy: FullWide::for_test_loopback(tree.relay().ip(), dns, mtu).unwrap(),
            };
            let (mut session, phases) = start(&tree, saved, None);
            expect_phase(&phases, &session, SessionPhase::Sealed);
            assert!(session.try_join(Duration::from_secs(2)), "{name}");
            // A local binding mismatch has its own code (terminal under S17),
            // never the relay's ACK refusal.
            assert_eq!(session.refusal(), Some("session_binding_refused"), "{name}");
            assert!(!store_locked(&tree.identity_dir()), "{name}");
            // The derived binding refused before any dial.
            assert!(
                relay
                    .wait_for(RelayStep::Accepted, Duration::from_millis(300))
                    .is_none(),
                "{name}"
            );
            assert_eq!(relay.accepts(), 0, "{name}");
        }
    }

    fn stop_while_constructing(behavior: fn(&ReadyTree) -> Behavior, reached: RelayStep) {
        let (relay, tree) = relay_and_tree(behavior);
        let (mut session, phases) = start(&tree, saved(&tree), None);
        relay
            .wait_for(reached, Duration::from_secs(2))
            .expect("session never reached the stalled relay step");
        assert_eq!(session.phase(), SessionPhase::Constructing);
        assert!(store_locked(&tree.identity_dir()));
        let stopping = Instant::now();
        assert!(session.try_join(Duration::from_secs(2)));
        assert!(stopping.elapsed() <= Duration::from_secs(2));
        assert_eq!(session.phase(), SessionPhase::Joined);
        assert_eq!(session.refusal(), Some("provider_stop"));
        assert_eq!(
            phases.recv_timeout(Duration::from_secs(1)).unwrap(),
            SessionPhase::Sealed
        );
        assert!(!store_locked(&tree.identity_dir()));
        // The first ACK's dial and, beside it, at most the first pre-warms
        // (this relay drops them unserved); nothing dialed again.
        assert!((1..=1 + PREWARM_SLOTS).contains(&relay.accepts()));
    }

    #[test]
    fn provider_session_stop_during_stalled_outer_tls_joins_within_2s() {
        stop_while_constructing(|_| Behavior::Silent, RelayStep::Accepted);
    }

    #[test]
    fn provider_session_stop_during_stalled_tcp_connect_joins_before_connect_budget() {
        let stalled = StalledListener::bind();
        let tree = ReadyTree::with_online_completed(stalled.address());
        let (trace, log) = recorder(tree.identity_dir());
        let (mut session, phases) = start(&tree, saved(&tree), Some(trace));
        wait_until(Duration::from_secs(2), || logged(&log, "dial")).expect("session never dialed");
        // The kernel drops this SYN: the dial is pending inside connect().
        thread::sleep(Duration::from_millis(100));
        assert_eq!(session.phase(), SessionPhase::Constructing);
        assert!(store_locked(&tree.identity_dir()));
        let stopping = Instant::now();
        assert!(session.try_join(Duration::from_secs(2)));
        // Without the stop arm the dial would hold teardown until the 2 s
        // CONNECT_BUDGET timeout, about 1.9 s from here.
        assert!(
            stopping.elapsed() < CONNECT_BUDGET / 2,
            "stop took {:?}",
            stopping.elapsed()
        );
        assert_eq!(session.phase(), SessionPhase::Joined);
        assert_eq!(session.refusal(), Some("provider_stop"));
        assert_eq!(
            phases.recv_timeout(Duration::from_secs(1)).unwrap(),
            SessionPhase::Sealed
        );
        assert!(!store_locked(&tree.identity_dir()));
        // Nothing past the dial ran: no engine, monitor or transport step.
        let steps: Vec<_> = log.lock().unwrap().iter().map(|(s, _, _)| *s).collect();
        assert_eq!(
            steps,
            [
                "relay_interface",
                "dial",
                "runtime_drop",
                "identity_drop",
                "store_guard_drop"
            ]
        );
    }

    #[test]
    fn provider_session_panicking_notifier_keeps_store_locked_after_unwind() {
        let (_relay, tree) = relay_and_tree(acks_then_closes);
        let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
        let (tx, notified) = mpsc::channel();
        let mut session = spawn_traced(
            saved(&tree),
            claim,
            move |phase| {
                let _ = tx.send(phase);
                panic!("provider notifier failed on {phase:?}");
            },
            None,
        )
        .unwrap();
        // Ready is notified on the Store worker after the engine spawned.
        expect_phase(&notified, &session, SessionPhase::Ready);
        // The session thread ends only after joining the unwound Store
        // worker; it re-raises the panic and never reports Joined.
        wait_until(Duration::from_secs(5), || session.body_finished())
            .expect("session thread never ended after the worker panic");
        assert_eq!(session.phase(), SessionPhase::Sealed);
        assert!(!session.try_join(Duration::from_millis(100)));
        // The engine and its watchdog were dropped, not joined: the Store
        // stays locked although every owner on the worker has unwound.
        assert!(store_locked(&tree.identity_dir()));
        thread::sleep(Duration::from_millis(100));
        assert!(store_locked(&tree.identity_dir()));
    }

    #[test]
    fn provider_session_stop_during_ack_joins_within_2s() {
        stop_while_constructing(|_| Behavior::HoldRequest, RelayStep::AckRequested);
    }

    // observe_ack finishes on frames already received when the relay ends the
    // connection, so every ended-early or invalid reply must still be refused.
    fn refused_without_ready(behavior: fn(&ReadyTree) -> Behavior) {
        let (relay, tree) = relay_and_tree(behavior);
        let (mut session, phases) = start(&tree, saved(&tree), None);
        expect_phase(&phases, &session, SessionPhase::Sealed);
        assert_eq!(session.refusal(), Some("session_ack_refused"));
        assert!(!session.probe().ready());
        relay
            .wait_for(RelayStep::AckClosed, Duration::from_secs(2))
            .expect("relay never ended the connection");
        assert!(session.try_join(Duration::from_secs(2)));
        assert!(!store_locked(&tree.identity_dir()));
        assert!(phases.try_recv().is_err());
    }

    #[test]
    fn provider_session_connection_dropped_before_ack_is_refused() {
        refused_without_ready(|_| Behavior::DropAfterRequest);
    }

    #[test]
    fn provider_session_truncated_ack_is_refused() {
        refused_without_ready(|tree| Behavior::TruncatedAck {
            reply: AckReply::for_tree(tree),
            keep: 1,
        });
        refused_without_ready(|tree| Behavior::TruncatedAck {
            reply: AckReply::for_tree(tree),
            keep: 4,
        });
        refused_without_ready(|tree| Behavior::TruncatedAck {
            reply: AckReply::for_tree(tree),
            keep: 16,
        });
    }

    // Control for the refusals above: the same immediate close after a valid
    // ACK is admitted, so they are refused for their reply, not the close.
    #[test]
    fn provider_session_valid_ack_then_immediate_close_is_admitted() {
        let (relay, tree) = relay_and_tree(|tree| Behavior::AckThenClose {
            reply: AckReply::for_tree(tree),
            idle: Duration::ZERO,
        });
        let (mut session, phases) = start(&tree, saved(&tree), None);
        expect_phase(&phases, &session, SessionPhase::Ready);
        relay
            .wait_for(RelayStep::AckClosed, Duration::from_secs(2))
            .expect("relay never ended the connection");
        assert!(session.try_join(Duration::from_secs(2)));
        assert!(!store_locked(&tree.identity_dir()));
    }

    #[test]
    fn provider_session_wrong_nonce_ack_before_close_is_refused() {
        refused_without_ready(|tree| Behavior::WrongNonceThenClose(AckReply::for_tree(tree)));
    }

    #[test]
    fn provider_session_dropped_ack_connection_does_not_seal_before_ack_validity_ends() {
        let (relay, tree) = relay_and_tree(acks_then_drops_early);
        let (trace, log) = recorder(tree.identity_dir());
        let started = Instant::now();
        let (mut session, phases) = start(&tree, saved(&tree), Some(trace));
        expect_phase(&phases, &session, SessionPhase::Ready);
        let ready = Instant::now();
        let written = relay
            .wait_for(RelayStep::AckWritten, Duration::from_secs(2))
            .unwrap();
        // Still open at Ready: the monitor drives a pending driver until the
        // relay drops the connection a second after the ACK.
        assert!(!logged(&log, "ack_transport_ended"));
        let closed = relay
            .wait_for(RelayStep::AckClosed, Duration::from_secs(2))
            .expect("relay never dropped the ACK connection");
        assert!(ready < closed, "Ready came only after the connection drop");
        let ended = wait_until(Duration::from_secs(2), || {
            logged(&log, "ack_transport_ended")
        })
        .expect("session never observed the ACK connection end");
        assert!(ended >= closed);
        // Two monitor ticks after the end: still Ready on the ACK lease.
        thread::sleep(Duration::from_millis(500).saturating_sub(ended.elapsed()));
        let probe = session.probe();
        assert!(probe.ready(), "sealed at {:?}", session.refusal());
        probe.bridge().from_os(&frame()).unwrap();
        let sealed = wait_until(Duration::from_secs(6), || {
            session.phase() != SessionPhase::Ready
        })
        .expect("ACK lease never ended");
        // The request left after `started` with a 3 s grant and a 250 ms
        // margin, so the lease cannot end earlier than started + 2.75 s.
        assert!(
            sealed - started >= Duration::from_millis(2_600),
            "sealed {:?} after start",
            sealed - started
        );
        assert!(
            sealed - written <= Duration::from_secs(5),
            "lease outlived its ACK"
        );
        assert_eq!(session.refusal(), Some("capture_lease_expired"));
        assert!(!probe.ready());
        assert!(session.try_join(Duration::from_secs(2)));
        assert!(!store_locked(&tree.identity_dir()));
        assert!(phases.try_recv().is_err());
    }

    /// S16o: each stage's `reack_stalled` line is a stable log line, and an
    /// attempt reports its stage once, however many paths see the lease run
    /// out under it.
    #[test]
    fn reack_stage_reports_once_on_a_stable_line() {
        for stage in ReackStage::ALL {
            let field = stage_field(stage.code(), Duration::from_millis(1234));
            let bound = stage_field("bound", Duration::from_secs(9));
            assert!(crate::apple::stable_fields(
                "reack_stalled",
                &[&field, &bound]
            ));
            assert_eq!(stage.mark(), format!("reack_stalled_{}", stage.code()));
        }
        assert!(crate::apple::stable_fields(
            "reack_stalled",
            &["waiting_ms:10"]
        ));
        let marks: Arc<Mutex<Vec<&'static str>>> = Arc::default();
        let held = marks.clone();
        let steps = Steps::traced(Some(Arc::new(move |step| held.lock().unwrap().push(step))));
        let rt = Builder::new_current_thread().enable_time().build().unwrap();
        rt.block_on(async {
            let lease_end = LeaseEnd::new(0);
            let first = lease_end.track(tokio::time::Instant::now());
            first.enter(ReackStage::DialExchange);
            let second = lease_end.track(tokio::time::Instant::now());
            second.enter(ReackStage::LinkRequest);
            // An attempt that ended is never reported.
            drop(lease_end.track(tokio::time::Instant::now()));
            // Its own lease-elapsed arm first, then both monitor paths.
            first.report(&steps);
            lease_end.report_stalled([tokio::time::Instant::now()], &steps);
            lease_end.report_stalled([], &steps);
            second.report(&steps);
        });
        assert_eq!(
            *marks.lock().unwrap(),
            [
                "reack_stalled_dial_exchange",
                "reack_stalled_link_request",
                "reack_stalled_waiting",
            ]
        );
    }
}
