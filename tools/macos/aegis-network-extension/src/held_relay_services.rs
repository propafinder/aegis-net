//! Fixed-peer relay services for the composite provider session (B-06 S06).
//!
//! Every flow is admitted by a [`WorkGate`] and holds one of its permits for
//! the flow future's whole lifetime, until whoever polls it drops it. Every
//! H2 driver of the session's pooled outer connections (S16h) lives in the
//! gate's JoinSet. `stop` closes the gate, aborts those tasks and waits,
//! within a budget, until every permit is back and the set is empty; the
//! session reports Joined, and releases the Store, only after that.
//!
//! Each flow is also bound to the bridge's refreshable lease and judged on the
//! bridge clock every `RECHECK`: it follows ACK renewals, and ends within one
//! `RECHECK` of an unrenewed deadline, a revocation or a gate stop. Nothing
//! here sleeps until a fixed instant, so a renewal is never missed.
//!
//! Every flow is one H2 stream on one of the session's pooled outer
//! connections (S16h, `flow_pool`), with its own carrier request, inner mTLS
//! channel and Open. Its open is two-phase under one signed connect budget:
//! it first reserves a stream on the pool holding no limiter permit (the
//! pool dials a connection under a flow permit of its own when none can take
//! the stream), then takes a flow permit of the session's `EstablishLimiter`
//! (S16g) for its carrier request, inner mTLS and Open request, and then
//! counts as an unanswered Open until its status. A flow that finds no
//! stream or no permit waits at most that budget, inside its liveness
//! recheck, and is then refused. S16i-2: so does a flow at the limiter's
//! live cap, first come first served, before it reserves a stream or dials;
//! it takes its live place only with its reserved stream and holds it
//! across a retry until it ends, so a queued flow counts against no relay
//! session. A TCP flow with no byte either way for `RELAY_IDLE_REAP` (the
//! relay's own idle end and a margin) ends here too, which returns its
//! place; a flow with traffic is never ended so. An authentication-class
//! failure backs the whole session off, an unanswered Open its flows alone,
//! and a
//! connection that ended under a flow neither: a flow whose Open was not yet
//! written is retried once on another connection, with budget left. A live
//! flow ends when its connection does (its `StreamGuard`).
//!
//! Every flow's open ends in one outcome (S16i-1, `flow_log`): accepted, or
//! refused in one class, or closed with its session, or dropped unfinished,
//! logged with its elapsed time from the start of its open.
#[cfg(feature = "sfu-media-vp8")]
use crate::app_group::CapturedSfuSnapshot;
use crate::{
    bridge::{LeasedPacketBridge, RefreshableDeadline},
    carrier_io::{own, OwnedCarrier},
    establish_limit::{
        conn_lost, is_auth_refused, is_conn_lost, is_open_unanswered, open_unanswered,
        EstablishLimiter, LiveFlow, Purpose, PROOF_FRESH,
    },
    flow_log::{Outcome, Refusal},
    flow_pool::{
        is_dial_failed, is_permit_wait, CarrierLost, FlowPool, StreamGuard, StreamSlot,
        RETRY_MARGIN,
    },
    prepared_crypto::{handshake_refusal, PreparedCryptoInputs},
    provider_session_body::EpochPins,
    relay_socket::{connect_bound, RelayInterface},
};
use aegis_client::{
    packet_engine::services::{EngineEvent, EventSink, RelayServices, RelayWork},
    relay_runtime_types::{ConnectTarget, UdpPacket},
};
#[cfg(feature = "sfu-media-vp8")]
use aegis_core::carrier_program::SfuDeclaration;
use aegis_core::{
    secure_channel::{self, Transport},
    RelaySettings,
};
use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, MutexGuard, PoisonError,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
    sync::{mpsc, OwnedSemaphorePermit, Semaphore},
    task::{AbortHandle, JoinSet},
    time::MissedTickBehavior,
};

/// How often a live flow re-judges the gate and the lease.
pub(crate) const RECHECK: Duration = Duration::from_millis(25);
/// One permit per concurrent flow: the packet engine's own relay-work budget.
pub(crate) const FLOW_PERMITS: usize = 4096;
// An open gate refuses no permit to a flow under the live cap (S16i-1), nor
// to one queued for a place (S16i-2): the signed bundle admits at most 512
// flows.
const _: () = assert!(crate::establish_limit::LIVE_FLOWS_MAX < FLOW_PERMITS);
const _: () = assert!(512 < FLOW_PERMITS);
/// aegis-server ends an inner session after this long with no byte either
/// way (aegis-core secure_channel idle timeout).
pub(crate) const RELAY_IDLE: Duration = Duration::from_secs(60);
/// S16i-2: a TCP flow with no byte either way for this long ends here: the
/// relay has ended its session by then, and its live place returns.
pub(crate) const RELAY_IDLE_REAP: Duration = Duration::from_secs(62);
const _: () = assert!(RELAY_IDLE_REAP.as_secs() == RELAY_IDLE.as_secs() + 2);
const DRAIN_POLL: Duration = Duration::from_millis(1);
pub(crate) const MAX_DRAIN: Duration = Duration::from_secs(2);

type Inner = crate::carrier_io::InnerCarrier;

enum CarrierGuard {
    Pool(StreamGuard),
    Web(Pin<Box<dyn Future<Output = ()> + Send>>),
    #[cfg(feature = "sfu-media-vp8")]
    Sfu(Pin<Box<crate::sfu_media_owner::MediaTerminal>>),
}

impl CarrierGuard {
    fn relay_end(&mut self, inner: Inner) -> OwnedCarrier {
        match self {
            Self::Pool(stream) => own(stream.relay_end(inner)),
            Self::Web(_) => own(inner),
            #[cfg(feature = "sfu-media-vp8")]
            Self::Sfu(_) => own(inner),
        }
    }

    async fn ended(&mut self) {
        match self {
            Self::Pool(stream) => stream.ended().await,
            Self::Web(terminal) => terminal.as_mut().await,
            #[cfg(feature = "sfu-media-vp8")]
            Self::Sfu(terminal) => terminal.as_mut().await,
        }
    }
}

struct WebBackend {
    interface: RelayInterface,
    pins: EpochPins,
    generation: u64,
}

#[cfg(feature = "sfu-media-vp8")]
struct SfuBackend {
    interface: RelayInterface,
    pins: EpochPins,
    generation: u64,
    signed: SfuDeclaration,
    private: Arc<CapturedSfuSnapshot>,
}

/// A flow's failed open: its error and its outcome (S16i-1).
type Failed = (io::Error, Outcome);

/// One flow's open, timed from its start: its outcome is recorded once,
/// as `Dropped` when the open is dropped unfinished.
struct OpenTrace<'a> {
    limiter: &'a EstablishLimiter,
    started: Instant,
    done: bool,
}

impl<'a> OpenTrace<'a> {
    fn start(limiter: &'a EstablishLimiter) -> Self {
        Self {
            limiter,
            started: Instant::now(),
            done: false,
        }
    }

    fn done(mut self, outcome: Outcome) {
        self.done = true;
        self.limiter.flow_opened(outcome, self.started.elapsed());
    }
}

impl Drop for OpenTrace<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.limiter
                .flow_opened(Outcome::Dropped, self.started.elapsed());
        }
    }
}

/// The refusal class of a flow's failed establishment: the class its stream
/// noted at the step that failed, else its error's.
fn refusal(error: &io::Error, noted: Option<Refusal>) -> Refusal {
    if let Some(noted) = noted {
        return noted;
    }
    if is_conn_lost(error) {
        Refusal::ConnLost
    } else if is_auth_refused(error) {
        Refusal::Auth
    } else if is_open_unanswered(error) {
        Refusal::Unanswered
    } else {
        Refusal::Other
    }
}

/// The outcome of a flow whose stream reservation failed: its own dial
/// got no limiter permit (before any SYN) or failed after it, or it found
/// no stream before less than its establish floor was left (S16j-1: within
/// its budget), or the session is stale (its gate closed, or the
/// epoch re-pinned).
fn reserve_outcome(error: &io::Error) -> Outcome {
    if is_permit_wait(error) {
        Outcome::Refused(Refusal::PermitWait)
    } else if is_dial_failed(error) {
        Outcome::Refused(Refusal::DialFailed)
    } else if error.kind() == io::ErrorKind::TimedOut {
        Outcome::Refused(Refusal::PoolWait)
    } else {
        Outcome::Closed
    }
}

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "held relay session inactive",
    )
}

fn timed_out() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "held relay datagram reply timed out",
    )
}

/// The session's synchronized stop-and-join point for relay work.
pub(crate) struct WorkGate {
    permits: Arc<Semaphore>,
    // Spawning checks `permits.is_closed()` under this lock, and `stop`
    // closes and aborts under it, so no task can land after the abort.
    tasks: Mutex<JoinSet<()>>,
}

impl WorkGate {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            permits: Arc::new(Semaphore::new(FLOW_PERMITS)),
            tasks: Mutex::new(JoinSet::new()),
        })
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.permits.is_closed()
    }

    fn tasks(&self) -> MutexGuard<'_, JoinSet<()>> {
        self.tasks.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// One flow's permit; refused once stopped.
    pub(crate) fn admit(&self) -> io::Result<OwnedSemaphorePermit> {
        self.permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| denied())
    }

    /// Spawn `task` on the caller's runtime into the gate's set. Refused once
    /// stopped. The returned guard aborts the task when its owner (a flow,
    /// or a pooled outer connection, S16h) drops.
    pub(crate) fn spawn(
        &self,
        task: impl Future<Output = ()> + Send + 'static,
    ) -> io::Result<AbortOnDrop> {
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| denied())?;
        let mut tasks = self.tasks();
        if self.is_closed() {
            return Err(denied());
        }
        while tasks.try_join_next().is_some() {}
        Ok(AbortOnDrop(tasks.spawn_on(task, &runtime)))
    }

    /// Flows currently holding a permit.
    pub(crate) fn flows(&self) -> usize {
        FLOW_PERMITS.saturating_sub(self.permits.available_permits())
    }

    /// Spawned tasks that have not yet completed or been dropped.
    pub(crate) fn tasks_left(&self) -> usize {
        let mut tasks = self.tasks();
        while tasks.try_join_next().is_some() {}
        tasks.len()
    }

    /// Every permit is back and every spawned task has ended.
    pub(crate) fn drained(&self) -> bool {
        self.tasks_left() == 0 && self.flows() == 0
    }

    /// Refuse new flows and tasks and abort the spawned tasks, under the set's
    /// lock, so no task lands after the abort. Idempotent.
    fn close_and_abort(&self, budget: Duration) -> io::Result<Instant> {
        if budget > MAX_DRAIN {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut tasks = self.tasks();
        self.permits.close();
        tasks.abort_all();
        Ok(Instant::now() + budget)
    }

    /// `stop_async`, waiting by sleeping this thread. Test-only (S16j-3): an
    /// aborted task is dropped only when its runtime next polls it, so this
    /// never drains a gate holding a task of a runtime only this thread
    /// drives (the session's current-thread runtime, whose relay pre-dial
    /// and its connection's driver are gate tasks).
    #[cfg(test)]
    pub(crate) fn stop(&self, budget: Duration) -> io::Result<()> {
        let deadline = self.close_and_abort(budget)?;
        loop {
            if self.drained() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            std::thread::sleep(DRAIN_POLL);
        }
    }

    /// Refuse new flows and tasks, abort the spawned tasks, then wait within
    /// `budget` until the gate has drained. A timeout keeps the gate closed;
    /// the caller must wait again before it releases the Store. It waits on
    /// the runtime that polls it, so that runtime's aborted gate tasks are
    /// dropped meanwhile (S16j-3): the session drains on its own runtime;
    /// tasks on another runtime need that runtime's own threads.
    pub(crate) async fn stop_async(&self, budget: Duration) -> io::Result<()> {
        let deadline = self.close_and_abort(budget)?;
        loop {
            if self.drained() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            tokio::time::sleep(DRAIN_POLL).await;
        }
    }
}

/// Aborts its gate task on drop.
pub(crate) struct AbortOnDrop(AbortHandle);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The flow future with its permit. Fields drop in order, so the permit is
/// returned only after the flow and everything it owns (its live place
/// under the relay's per-IP session cap among them, S16i-2) have been
/// dropped.
struct Gated<'a, T> {
    work: RelayWork<'a, T>,
    _permit: OwnedSemaphorePermit,
}

impl<T> Future for Gated<'_, T> {
    type Output = anyhow::Result<T>;
    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().work.as_mut().poll(context)
    }
}

/// Fixed-peer adapter over prepared CA, device identity and bridge credential.
/// Its flows go only to the session's verified relay peer, as streams of the
/// session's flow pool (whose sockets are bound to the session's relay
/// interface), and only while the gate is open and the bridge lease is live
/// on the bridge clock.
pub(crate) struct HeldRelayServices {
    crypto: Arc<PreparedCryptoInputs>,
    events: Arc<dyn EventSink>,
    peer: SocketAddr,
    // The lease clock and its lock-free, sticky-revocable deadline view.
    bridge: LeasedPacketBridge,
    lease: RefreshableDeadline,
    gate: Arc<WorkGate>,
    limiter: Arc<EstablishLimiter>,
    pool: Option<Arc<FlowPool>>,
    web: Option<WebBackend>,
    #[cfg(feature = "sfu-media-vp8")]
    sfu: Option<SfuBackend>,
    // `RELAY_IDLE_REAP`; tests shorten it.
    idle_reap: Duration,
}

impl HeldRelayServices {
    /// The services of the session whose flow `pool` this is: its peer,
    /// held crypto, gate and limiter are the pool's.
    pub(crate) fn new(
        events: Arc<dyn EventSink>,
        bridge: LeasedPacketBridge,
        pool: Arc<FlowPool>,
    ) -> io::Result<Self> {
        let crypto = pool.crypto().clone();
        let peer = pool.peer();
        crypto.direct_peer(peer)?;
        Ok(Self {
            crypto,
            events,
            peer,
            lease: bridge.refreshable_deadline(),
            bridge,
            gate: pool.gate().clone(),
            limiter: pool.limiter().clone(),
            pool: Some(pool),
            web: None,
            #[cfg(feature = "sfu-media-vp8")]
            sfu: None,
            idle_reap: RELAY_IDLE_REAP,
        })
    }

    /// A D5 service owns one verified web carrier per target, never an H2
    /// pool. The same WorkGate and limiter that proved the first ACK own all
    /// later flows and their terminal watches.
    pub(crate) fn new_web(
        events: Arc<dyn EventSink>,
        bridge: LeasedPacketBridge,
        crypto: Arc<PreparedCryptoInputs>,
        peer: SocketAddr,
        interface: RelayInterface,
        (pins, generation): (EpochPins, u64),
        (limiter, gate): (Arc<EstablishLimiter>, Arc<WorkGate>),
    ) -> io::Result<Self> {
        crypto.direct_peer(peer)?;
        let channel = crypto.selected_channel()?;
        if channel != aegis_core::carrier_program::CarrierChannel::WebResponse
            && !(cfg!(feature = "enrolled-quic")
                && channel == aegis_core::carrier_program::CarrierChannel::MasqueQuic)
            || pins.generation() != generation
            || pins.get().as_ref() != Some(&interface)
        {
            return Err(denied());
        }
        Ok(Self {
            crypto,
            events,
            peer,
            lease: bridge.refreshable_deadline(),
            bridge,
            gate,
            limiter,
            pool: None,
            web: Some(WebBackend {
                interface,
                pins,
                generation,
            }),
            #[cfg(feature = "sfu-media-vp8")]
            sfu: None,
            idle_reap: RELAY_IDLE_REAP,
        })
    }

    /// One H2-authenticated epoch carries its flow traffic over a separate
    /// exact signed SFU media route. The H2 ACK monitor owns this gate and
    /// bridge lease; losing that ACK revokes every media flow.
    #[cfg(feature = "sfu-media-vp8")]
    pub(crate) fn new_sfu(
        events: Arc<dyn EventSink>,
        bridge: LeasedPacketBridge,
        crypto: Arc<PreparedCryptoInputs>,
        peer: SocketAddr,
        interface: RelayInterface,
        (pins, generation): (EpochPins, u64),
        (limiter, gate): (Arc<EstablishLimiter>, Arc<WorkGate>),
    ) -> io::Result<Self> {
        crypto.direct_peer(peer)?;
        let (signed, private) = crypto.sfu_media_inputs().ok_or_else(denied)?;
        let signed = signed.clone();
        if crypto.selected_channel()? != aegis_core::carrier_program::CarrierChannel::DirectH2
            || pins.generation() != generation
            || pins.get().as_ref() != Some(&interface)
        {
            return Err(denied());
        }
        Ok(Self {
            crypto,
            events,
            peer,
            lease: bridge.refreshable_deadline(),
            bridge,
            gate,
            limiter,
            pool: None,
            web: None,
            sfu: Some(SfuBackend {
                interface,
                pins,
                generation,
                signed,
                private,
            }),
            idle_reap: RELAY_IDLE_REAP,
        })
    }

    /// Test-only: these services with TCP flows ended after `idle` with no
    /// byte either way.
    #[cfg(test)]
    pub(crate) fn with_idle_reap(mut self, idle: Duration) -> Self {
        self.idle_reap = idle;
        self
    }

    /// The session's flow pool.
    #[cfg(test)]
    pub(crate) fn pool(&self) -> &Arc<FlowPool> {
        self.pool.as_ref().expect("pooled test service")
    }

    /// The session limiter every flow establishment takes a permit of.
    #[cfg(test)]
    pub(crate) fn limiter(&self) -> &Arc<EstablishLimiter> {
        &self.limiter
    }

    /// The signed relay settings the packet engine must supply.
    #[cfg(test)]
    pub(crate) fn signed_relay(&self) -> RelaySettings {
        self.crypto.signed_relay().clone()
    }

    /// Open gate and an unrevoked lease strictly before its end, on the clock
    /// the bridge enforces. An unreadable clock is never live.
    fn live(&self) -> io::Result<()> {
        if self.gate.is_closed() {
            return Err(denied());
        }
        match self.bridge.clock_ns() {
            Ok(now) if self.lease.active_at(now) => Ok(()),
            _ => Err(denied()),
        }
    }

    /// Checked once per flow before it takes a permit: liveness, the signed
    /// relay settings (they cannot change under the borrow) and the peer. A
    /// refusal carries its flow's outcome (S16i-1): `Closed` when the gate
    /// closed or the lease is not live, else refused in class `other`.
    fn admit(&self, settings: &RelaySettings) -> Result<(), Failed> {
        self.live().map_err(|error| (error, Outcome::Closed))?;
        let other = |error| (error, Outcome::Refused(Refusal::Other));
        if !self.crypto.relay_matches(settings) {
            return Err(other(denied()));
        }
        self.crypto.direct_peer(self.peer).map_err(other)
    }

    /// Admit, take a permit and run `make`'s flow under `guarded`. A refused
    /// flow never builds its future, so nothing it was handed is used.
    fn gated<'a, T: 'a, F>(
        &'a self,
        settings: &RelaySettings,
        make: impl FnOnce() -> F,
    ) -> RelayWork<'a, T>
    where
        F: Future<Output = anyhow::Result<T>> + Send + 'a,
    {
        // The gate refuses a permit only once closed: its permits outnumber
        // every flow the signed bundle admits, live or queued for a place.
        let admitted = self
            .admit(settings)
            .and_then(|()| self.gate.admit().map_err(|error| (error, Outcome::Closed)));
        let permit = match admitted {
            Ok(permit) => permit,
            Err((error, outcome)) => {
                // S16i-1: refused before its open started, and recorded as
                // that open's outcome.
                self.limiter.flow_opened(outcome, Duration::ZERO);
                return Box::pin(async move { Err(error.into()) });
            }
        };
        Box::pin(Gated {
            work: Box::pin(self.guarded(make())),
            _permit: permit,
        })
    }

    /// Poll `operation` while re-judging liveness every `RECHECK`. A result
    /// that lands after the lease ended is refused, never delivered.
    async fn guarded<T>(
        &self,
        operation: impl Future<Output = anyhow::Result<T>>,
    ) -> anyhow::Result<T> {
        if let Err(error) = self.live() {
            // S16i-1: every guarded operation starts with its flow's open,
            // and one refused here, before its first poll, never started
            // it: recorded as that open's outcome.
            self.limiter.flow_opened(Outcome::Closed, Duration::ZERO);
            return Err(error.into());
        }
        tokio::pin!(operation);
        let mut recheck = tokio::time::interval_at(tokio::time::Instant::now() + RECHECK, RECHECK);
        recheck.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                _ = recheck.tick() => self.live()?,
                result = &mut operation => {
                    self.live()?;
                    return result;
                }
            }
        }
    }

    /// One target channel to the verified peer on a pooled stream, under
    /// one signed connect budget. Phase 1 reserves a stream on the pool
    /// (which may dial a connection under a permit of its own) and holds no
    /// permit; phase 2 takes a flow permit for the carrier request, the inner
    /// mTLS and the Open request, and the flow then counts as an unanswered
    /// Open until the relay accepted or refused it. A connection that ended
    /// before the Open was written is retried once on another connection.
    /// S16i-2: before its first reservation the flow waits, first come first
    /// served and within the same budget, until the live cap leaves it a
    /// place, which it takes with its reserved stream and holds until it
    /// ends (returned here beside its stream).
    async fn open(
        &self,
        transport: Transport,
        host: String,
        port: u16,
    ) -> anyhow::Result<(Inner, CarrierGuard, LiveFlow)> {
        let trace = OpenTrace::start(&self.limiter);
        match self.open_traced(transport, host, port).await {
            Ok(opened) => {
                trace.done(Outcome::Ok);
                Ok(opened)
            }
            Err((error, outcome)) => {
                trace.done(outcome);
                Err(error.into())
            }
        }
    }

    /// `open`, with the outcome of a failure.
    async fn open_traced(
        &self,
        transport: Transport,
        host: String,
        port: u16,
    ) -> Result<(Inner, CarrierGuard, LiveFlow), Failed> {
        if let Some(web) = &self.web {
            return self.open_web_traced(web, transport, host, port).await;
        }
        #[cfg(feature = "sfu-media-vp8")]
        if let Some(sfu) = &self.sfu {
            return self.open_sfu_traced(sfu, transport, host, port).await;
        }
        let pool = self
            .pool
            .as_ref()
            .ok_or_else(|| (denied(), Outcome::Closed))?;
        if host.is_empty() || port == 0 {
            return Err((denied(), Outcome::Refused(Refusal::Other)));
        }
        let budget = Duration::from_millis(self.crypto.signed_relay().connect_timeout_ms);
        let deadline = tokio::time::Instant::now() + budget;
        let mut retried = false;
        // S16i-2: its place in the queue for a live place, then the place
        // itself, taken with its first reserved stream.
        let mut ticket = self.limiter.live_ticket();
        let mut live: Option<LiveFlow> = None;
        loop {
            if live.is_none() {
                self.limiter
                    .live_ready(&ticket, deadline.into_std())
                    .await
                    .map_err(|_| (denied(), Outcome::Refused(Refusal::LiveCap)))?;
            }
            let mut slot = pool
                .reserve(deadline)
                .await
                .map_err(|error| (denied(), reserve_outcome(&error)))?;
            let held = match live.take() {
                Some(held) => held,
                None => match self.limiter.take_live(&mut ticket) {
                    Some(held) => held,
                    None => {
                        // The cap narrowed meanwhile: the stream goes back.
                        drop(slot);
                        continue;
                    }
                },
            };
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            let mut permit = self
                .limiter
                .acquire(Purpose::Flow, self.limiter.flow_wait(left))
                .await
                .map_err(|_| (denied(), Outcome::Refused(Refusal::PermitWait)))?;
            // A stream that waited for its permit until its connection no
            // longer takes one would race the relay's deadline, and one
            // reserved before a strike or the fallback narrowed the pool, or
            // a capacity refusal its connection, would share its
            // connection's handshakes beyond the narrower pool (S16h-8b,
            // 8c, 8d): give it back and take a fresh one.
            let mode = self.limiter.pool_mode();
            if !slot.reusable(mode) || !slot.fits(mode) {
                drop(permit);
                drop(slot);
                live = Some(held);
                continue;
            }
            let srtt = slot.conn().srtt();
            // S16h-8b, strike level 2: a handshake only on a connection
            // whose path proved its life within PROOF_FRESH; one that does
            // not is a connection loss before this stream sent a byte.
            let unproven = self.limiter.pool_mode().needs_proof()
                && !slot.conn().proven_within(PROOF_FRESH).await;
            let opened = if unproven {
                crate::apple::log_code("pool_proof", "none");
                Err(conn_lost())
            } else {
                self.establish(&mut slot, transport, (&host, port), &mut permit, deadline)
                    .await
            };
            // Judged before the permit (or its unanswered-Open count) returns,
            // so no probe-blocked waiter starts ahead of a backoff; an
            // accepted Open verifies the identity.
            match opened {
                Ok((inner, stream_id)) => {
                    permit.succeeded();
                    return Ok((inner, CarrierGuard::Pool(slot.into_guard(stream_id)), held));
                }
                Err(error) => {
                    // A stream lost while the relay may have been in its
                    // inner handshake, to a cause it may never have seen:
                    // one entry of the epoch's strike ledger (S16h-8b).
                    if slot.take_strike(is_conn_lost(&error)) {
                        self.limiter.strike();
                    }
                    let left = deadline.saturating_duration_since(tokio::time::Instant::now());
                    if is_conn_lost(&error)
                        && !permit.is_written()
                        && !retried
                        && left >= srtt * 2 + RETRY_MARGIN
                    {
                        retried = true;
                        crate::apple::log_code("pool_conn_lost", "retry");
                        drop(permit);
                        drop(slot);
                        live = Some(held);
                        continue;
                    }
                    if is_conn_lost(&error) {
                        let why = if permit.is_written() {
                            "after_open"
                        } else {
                            "no_retry"
                        };
                        crate::apple::log_code("pool_conn_lost", why);
                    }
                    self.limiter.judge(Purpose::Flow, &error);
                    drop(permit);
                    let outcome = Outcome::Refused(refusal(&error, slot.noted()));
                    return Err((error, outcome));
                }
            }
        }
    }

    async fn open_web_traced(
        &self,
        web: &WebBackend,
        transport: Transport,
        host: String,
        port: u16,
    ) -> Result<(Inner, CarrierGuard, LiveFlow), Failed> {
        if host.is_empty() || port == 0 || web.pins.generation() != web.generation {
            return Err((denied(), Outcome::Closed));
        }
        #[cfg(feature = "enrolled-quic")]
        let quic = match self.crypto.selected_channel() {
            Ok(aegis_core::carrier_program::CarrierChannel::MasqueQuic) => true,
            Ok(aegis_core::carrier_program::CarrierChannel::WebResponse) => false,
            _ => return Err((denied(), Outcome::Closed)),
        };
        #[cfg(feature = "enrolled-quic")]
        if quic && transport != Transport::Tcp {
            return Err((denied(), Outcome::Refused(Refusal::Other)));
        }
        let deadline = tokio::time::Instant::now()
            + Duration::from_millis(self.crypto.signed_relay().connect_timeout_ms);
        let mut ticket = self.limiter.live_ticket();
        self.limiter
            .live_ready(&ticket, deadline.into_std())
            .await
            .map_err(|_| (denied(), Outcome::Refused(Refusal::LiveCap)))?;
        let live = self
            .limiter
            .take_live(&mut ticket)
            .ok_or_else(|| (denied(), Outcome::Refused(Refusal::LiveCap)))?;
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let mut permit = self
            .limiter
            .acquire(Purpose::Flow, self.limiter.flow_wait(left))
            .await
            .map_err(|_| (denied(), Outcome::Refused(Refusal::PermitWait)))?;
        let opened = async {
            #[cfg(feature = "enrolled-quic")]
            if quic {
                return self
                    .crypto
                    .open_target_on_quic(
                        &web.interface,
                        &web.pins,
                        web.generation,
                        &self.gate,
                        transport,
                        (host, port),
                        &mut permit,
                        deadline,
                    )
                    .await;
            }
            let tcp = tokio::time::timeout_at(deadline, connect_bound(self.peer, &web.interface))
                .await
                .map_err(|_| denied())??;
            self.crypto
                .open_target_on_web(
                    tcp,
                    &web.interface,
                    &web.pins,
                    web.generation,
                    transport,
                    (host, port),
                    &mut permit,
                    deadline,
                )
                .await
        }
        .await;
        match opened {
            Ok(flow) => {
                permit.succeeded();
                Ok((flow.inner, CarrierGuard::Web(flow.terminal), live))
            }
            Err(error) => {
                self.limiter.judge(Purpose::Flow, &error);
                Err((error, Outcome::Refused(Refusal::Other)))
            }
        }
    }

    #[cfg(feature = "sfu-media-vp8")]
    async fn open_sfu_traced(
        &self,
        sfu: &SfuBackend,
        transport: Transport,
        host: String,
        port: u16,
    ) -> Result<(Inner, CarrierGuard, LiveFlow), Failed> {
        if host.is_empty() || port == 0 || sfu.pins.generation() != sfu.generation {
            return Err((denied(), Outcome::Closed));
        }
        let deadline = tokio::time::Instant::now()
            + Duration::from_millis(self.crypto.signed_relay().connect_timeout_ms);
        let mut ticket = self.limiter.live_ticket();
        self.limiter
            .live_ready(&ticket, deadline.into_std())
            .await
            .map_err(|_| (denied(), Outcome::Refused(Refusal::LiveCap)))?;
        let live = self
            .limiter
            .take_live(&mut ticket)
            .ok_or_else(|| (denied(), Outcome::Refused(Refusal::LiveCap)))?;
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let mut permit = self
            .limiter
            .acquire(Purpose::Flow, self.limiter.flow_wait(left))
            .await
            .map_err(|_| (denied(), Outcome::Refused(Refusal::PermitWait)))?;
        let media_lifetime = crate::sfu_media_owner::task_lifetime(&self.gate)
            .map_err(|_| (denied(), Outcome::Closed))?;
        let opened = crate::sfu_media_owner::open_target(
            &sfu.signed,
            &sfu.private,
            &sfu.interface,
            &sfu.pins,
            sfu.generation,
            self.crypto.inner_client(),
            transport,
            (host, port),
            &mut permit,
            deadline,
            media_lifetime,
        )
        .await;
        match opened {
            Ok(flow) => {
                permit.succeeded();
                Ok((flow.inner, CarrierGuard::Sfu(Box::pin(flow.terminal)), live))
            }
            Err(error) => {
                self.limiter.judge(Purpose::Flow, &error);
                Err((error, Outcome::Refused(Refusal::Other)))
            }
        }
    }

    /// The carrier request on `slot`'s connection within `deadline`, then the
    /// target channel on it (`open_target_on_stream`).
    async fn establish(
        &self,
        slot: &mut StreamSlot,
        transport: Transport,
        (host, port): (&str, u16),
        permit: &mut crate::establish_limit::EstablishPermit,
        deadline: tokio::time::Instant,
    ) -> io::Result<(Inner, u32)> {
        // This stream's bounds, from the age of the relay deadline it
        // inherits at its accept. A 200 later than its handshake bound
        // leaves no time for the inner mTLS. S16j-1: the inner mTLS, the
        // Open and its status run within the flow's own deadline too, so
        // no open completes after its application gave up.
        let bounds = slot.sent(slot.conn().srtt());
        let within = bounds.within(deadline);
        // v34: the flow's stream window may grow (`StreamSlot::open_carrier`).
        let carrier = tokio::time::timeout_at(
            deadline.min(bounds.handshake),
            slot.open_carrier(&self.crypto),
        )
        .await;
        let carrier = match carrier {
            Ok(Ok(carrier)) => carrier,
            Ok(Err(error)) => {
                slot.handshake_done(false);
                if error
                    .downcast_ref::<h2::Error>()
                    .is_some_and(h2::Error::is_reset)
                {
                    slot.note(Refusal::CarrierReset);
                }
                return Err(self.carrier_refusal(&error));
            }
            Err(_) => {
                slot.handshake_done(false);
                // No 200 within its handshake bound, the request dropped
                // (reset): a connection loss when its connection ended, now
                // or at its stall watchdog's verdict. A flow out of budget
                // is not kept waiting for one.
                if bounds.handshake <= deadline && slot.conn().lost_after_watchdog(None).await {
                    return Err(conn_lost());
                }
                slot.note(Refusal::HsBound);
                return Err(self.carrier_refusal(&denied().into()));
            }
        };
        self.pool.as_ref().expect("H2 pool only").carrier_answered();
        slot.relay_handshaking();
        let stream_id = carrier.stream_id;
        let inner = self
            .crypto
            .open_target_on_stream(
                carrier,
                slot,
                transport,
                (host.to_owned(), port),
                permit,
                within,
            )
            .await?;
        Ok((inner, stream_id))
    }

    /// The refusal of a failed carrier request: a connection loss when its
    /// connection ended under it (`CarrierLost`); a reset before the 200 is
    /// never authentication class, but `RESETS_UNANSWERED` of them
    /// pool-wide count as an unanswered Open; else the handshake class (a
    /// TLS error or an explicit carrier refusal).
    fn carrier_refusal(&self, error: &anyhow::Error) -> io::Error {
        if error.downcast_ref::<CarrierLost>().is_some() {
            return conn_lost();
        }
        if error
            .downcast_ref::<h2::Error>()
            .is_some_and(h2::Error::is_reset)
        {
            return if self.pool.as_ref().expect("H2 pool only").carrier_reset() {
                open_unanswered()
            } else {
                denied()
            };
        }
        handshake_refusal(error)
    }
}

/// The refusal of a TCP flow ended after its idle time with no byte either
/// way (S16i-2). Same kind as a reply timeout.
#[derive(Debug)]
pub(crate) struct IdleReaped;

impl std::fmt::Display for IdleReaped {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("held relay flow idle")
    }
}

impl std::error::Error for IdleReaped {}

fn idle_reaped() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, IdleReaped)
}

/// Whether `error` is the end of a flow that idled (`copy_or_reap`).
pub(crate) fn is_idle_reaped(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.is::<IdleReaped>())
}

/// When a flow last moved a byte either way, on the runtime clock.
pub(crate) struct IdleClock {
    base: tokio::time::Instant,
    // Microseconds after `base`.
    last_us: AtomicU64,
}

impl IdleClock {
    pub(crate) fn new(now: tokio::time::Instant) -> Self {
        Self {
            base: now,
            last_us: AtomicU64::new(0),
        }
    }

    /// A byte moved at `now`.
    pub(crate) fn touch(&self, now: tokio::time::Instant) {
        let us =
            u64::try_from(now.saturating_duration_since(self.base).as_micros()).unwrap_or(u64::MAX);
        self.last_us.fetch_max(us, Ordering::Relaxed);
    }

    /// When the flow has idled `idle`, unless a byte moves first.
    pub(crate) fn due(&self, idle: Duration) -> tokio::time::Instant {
        self.base + Duration::from_micros(self.last_us.load(Ordering::Relaxed)) + idle
    }

    /// Resolves once the flow idled `idle` with no byte either way.
    async fn idled(&self, idle: Duration) {
        loop {
            let due = self.due(idle);
            if tokio::time::Instant::now() >= due {
                return;
            }
            tokio::time::sleep_until(due).await;
        }
    }
}

/// One side of a flow that touches its [`IdleClock`] whenever a read
/// returns bytes or a write takes some.
struct Active<'a, T> {
    io: T,
    clock: &'a IdleClock,
}

impl<T: AsyncRead + Unpin> AsyncRead for Active<'_, T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let read = Pin::new(&mut self.io).poll_read(context, buf);
        if matches!(read, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.clock.touch(tokio::time::Instant::now());
        }
        read
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Active<'_, T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let written = Pin::new(&mut self.io).poll_write(context, buf);
        if matches!(written, Poll::Ready(Ok(1..))) {
            self.clock.touch(tokio::time::Instant::now());
        }
        written
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let written = Pin::new(&mut self.io).poll_write_vectored(context, bufs);
        if matches!(written, Poll::Ready(Ok(1..))) {
            self.clock.touch(tokio::time::Instant::now());
        }
        written
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(context)
    }
}

/// S16i-2: copy `local` and `relay` both ways until both ended, as
/// `copy_bidirectional` does, or until no byte moved either way, on either
/// side, for `idle`: then [`IdleReaped`]. Any byte read or written on
/// either side restarts the idle time, so a flow with traffic never ends
/// so.
pub(crate) async fn copy_or_reap<L, R>(local: &mut L, relay: R, idle: Duration) -> io::Result<()>
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    let clock = IdleClock::new(tokio::time::Instant::now());
    let mut local = Active {
        io: local,
        clock: &clock,
    };
    let mut relay = Active {
        io: relay,
        clock: &clock,
    };
    tokio::select! {
        copied = tokio::io::copy_bidirectional(&mut local, &mut relay) => copied.map(|_| ()),
        () = clock.idled(idle) => Err(idle_reaped()),
    }
}

impl EventSink for HeldRelayServices {
    fn emit(
        &self,
        level: &'static str,
        event: EngineEvent,
        message: &'static str,
        fields: serde_json::Value,
    ) {
        self.events.emit(level, event, message, fields);
    }
}

impl RelayServices for HeldRelayServices {
    fn tcp<'a>(
        &'a self,
        mut local: TcpStream,
        settings: &'a RelaySettings,
        host: String,
        port: u16,
    ) -> RelayWork<'a, ()> {
        self.gated(settings, move || async move {
            let (inner, mut stream, _live) = self.open(Transport::Tcp, host, port).await?;
            // Once the relay ended its side (a target's FIN it forwarded),
            // its channel lives only until its idle timeout while this flow
            // may stay half-closed: the stream no longer keeps its
            // connection live.
            let inner = stream.relay_end(inner);
            tokio::select! {
                result = copy_or_reap(&mut local, inner, self.idle_reap) => {
                    if result.as_ref().is_err_and(is_idle_reaped) {
                        // S16i-2: the relay ended its session by now; its
                        // live place returns as this flow ends.
                        self.limiter.idle_reaped();
                    }
                    result?;
                    Ok(())
                }
                () = stream.ended() => Err(denied().into()),
            }
        })
    }

    fn udp_once<'a>(
        &'a self,
        settings: &'a RelaySettings,
        target: ConnectTarget,
        payload: &'a [u8],
    ) -> RelayWork<'a, Vec<u8>> {
        self.gated(settings, move || async move {
            let (mut inner, mut stream, _live) =
                self.open(Transport::Udp, target.host, target.port).await?;
            // As aegis-client's udp_once_with_endpoint: the exchange after the
            // open has its own signed connect budget, so a lost reply ends
            // this flow (the engine answers SERVFAIL) and returns its permit
            // and channel instead of waiting out the server's idle timeout.
            let budget = Duration::from_millis(self.crypto.signed_relay().connect_timeout_ms);
            let exchange = async {
                secure_channel::datagram::write(&mut inner, payload).await?;
                secure_channel::datagram::read(&mut inner)
                    .await?
                    .ok_or_else(denied)
                    .map_err(anyhow::Error::from)
            };
            tokio::select! {
                result = tokio::time::timeout(budget, exchange) => {
                    result.unwrap_or_else(|_| Err(timed_out().into()))
                }
                () = stream.ended() => Err(denied().into()),
            }
        })
    }

    fn udp_flow<'a>(
        &'a self,
        settings: &'a RelaySettings,
        host: &'a str,
        port: u16,
        mut outbound: mpsc::Receiver<Vec<u8>>,
        incoming: mpsc::Sender<UdpPacket>,
    ) -> RelayWork<'a, ()> {
        self.gated(settings, move || async move {
            let target = ConnectTarget {
                host: host.to_owned(),
                port,
            };
            let (inner, mut stream, _live) =
                self.open(Transport::Udp, target.host.clone(), port).await?;
            let (mut reader, mut writer) = tokio::io::split(inner);
            let send = async {
                while let Some(payload) = outbound.recv().await {
                    secure_channel::datagram::write(&mut writer, &payload).await?;
                }
                writer.shutdown().await?;
                anyhow::Ok(())
            };
            let receive = async {
                while let Some(payload) = secure_channel::datagram::read(&mut reader).await? {
                    incoming
                        .send(UdpPacket {
                            target: target.clone(),
                            payload,
                        })
                        .await
                        .map_err(|_| denied())?;
                }
                anyhow::Ok(())
            };
            tokio::select! {
                result = send => result,
                result = receive => result,
                () = stream.ended() => Err(denied().into()),
            }
        })
    }
}

#[cfg(test)]
#[path = "held_relay_services_tests.rs"]
mod tests;
