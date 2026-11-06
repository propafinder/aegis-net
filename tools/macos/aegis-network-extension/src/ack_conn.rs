//! The session's persistent ACK connection (B-06 S16l).
//!
//! Installed v22 lost its 3 s PolicyAck lease eight times in 90 s under the
//! post-connect flow burst: every PolicyAck needed its own inner channel,
//! and each one was its own pre-warmed dial (TCP, outer TLS with ECH, H2 and
//! inner mTLS), whose setup averaged 473 ms (at most 1061 ms) under load.
//! aegis-server answers one request (an Open or a PolicyAck) per inner
//! channel, but serves every H2 stream as its own secure session
//! (session/grpc.rs), so the ACK path now keeps one outer TLS + H2
//! connection of its own, an [`AckLink`], apart from the flow pool so that
//! flow data never blocks an ACK at its head: each PolicyAck still gets its
//! own inner channel, now a carrier stream of that connection (its request,
//! the 200, the inner mTLS, the PolicyAck and its reply), two round trips
//! less than a dial.
//!
//! The connection is a [`PooledConn`] (bound to the session's relay
//! interface, its ECH, ALPN and carrier checks, its driver a task of the
//! session's [`WorkGate`]), dialed with `PooledConn::dial_ack` only under an
//! ACK-path permit of the session's limiter that its dialer already holds
//! for the stream that follows (the first ACK's, a pre-warm slot's, a fresh
//! re-ACK request's), so the
//! epoch's backoff and probing gate it and the ACK path never holds more
//! permits than its reserve; a failure is judged as an ACK-path
//! establishment's. At most [`LINK_DIALS_PER_REACK`] dials run between two
//! bound re-ACK requests, so a relay that ends every connection draws no
//! dial loop.
//!
//! It takes new streams only while it is current: not ended (a GOAWAY or a
//! transport end), dialed under the epoch's present pin (S18) and wake
//! generations, younger than `flow_pool::MAX_CONN_AGE`, under
//! `flow_pool::MAX_CONN_STREAMS` streams over its life, with stream room in
//! the relay's SETTINGS, and with a live channel of its own within
//! [`ACK_IDLE_REUSE`] (the relay closes a connection with no authenticated
//! stream after its admission timeout). Otherwise it is let go (logged
//! `ack_conn lost`, `goaway` or `drained`) and its existing channels finish
//! on it; the next pre-warm dials another, at once: with the relay's grants
//! of at most 3 s every free pre-warm slot is due at once, and a lost
//! connection's streams end with it, freeing their slots. While none is up, and whenever a stream of it fails, the
//! ACK path falls back to its own per-dial channels (`ack_conn fallback`),
//! so the lease never depends on one TCP connection.
//!
//! Both requests S16k keeps in flight may ride the connection, so one
//! connection a path froze must not hold both: a request in flight on it
//! whose own bytes have not been acknowledged for [`quiet_after`] of its
//! round trip makes it quiet ([`AckLink::quiet`]), and while it is, the next
//! request goes on another TCP connection (a per-dial pre-warm, else a fresh
//! dial). The threshold is capped inside the shortest stagger between the
//! two, so on any path the second request never rides a connection on which
//! the first has shown no sign of life. Its stall watchdog then closes the
//! frozen connection (a PING unanswered), which lets it go and fails the
//! streams still on it.
//!
//! S16m: a request's sign of life is causal: the relay's TCP acknowledged a
//! byte the connection wrote after the request left
//! ([`PooledConn::acked_beyond`], read when asked, not at the watchdog's
//! next sample). Installed v23 counted any inbound byte after the request
//! left: the ACK of the request before it, landing 40 ms after the second
//! one left, kept that second one "alive" for good, so the third rode the
//! same connection. (That v23 lapse itself was a stall of the path or the
//! relay for every connection, flow connections included, which no choice
//! of connection averts with about 1 s of lease left; it stays residual.)
//! A request sent off a quiet connection comes back to it once the
//! evidence its first request lacked arrives ([`AckLink::revived`]), while
//! its own dial is still in its TCP connect, outer TLS, H2 or inner mTLS:
//! v23 sent one to a fresh dial that took 2.2 s, while the connection
//! answered the quiet one 117 ms later. A dial already established keeps
//! its request: its PolicyAck is then at most one exchange away.
//!
//! S16m: once the session's gate is closed (its stop, or the relay join
//! after a seal) or its epoch re-pinned, a connection that ends or a stream
//! of it that fails is `closed`, never `lost`: v23's three `ack_conn lost`
//! were all its own teardown, at the instant each session ended.
//!
//! A pre-warmed stream channel ages from its carrier request, or, when its
//! connection had no live channel then, from when it last had one
//! ([`ConnLive::aged_from`]): the relay's stream inherits the connection's
//! idle deadline at its accept, and its deadline covers the inner mTLS and
//! the request read.
use crate::{
    establish_limit::{is_auth_refused, EstablishLimiter},
    flow_pool::{fails, ConnEnd, PooledConn, ACK_SAMPLE, MAX_CONN_AGE, MAX_CONN_STREAMS},
    held_relay_services::WorkGate,
    prepared_crypto::PreparedCryptoInputs,
    provider_session_body::{EpochPins, Trace},
    relay_socket::RelayInterface,
};
use std::{
    io,
    net::SocketAddr,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Duration,
};
use tokio::{sync::Notify, time::Instant};

/// The longest an ACK connection with no live channel of its own takes a
/// new stream: the relay closes it `ADMISSION_TIMEOUT` (5 s) after its last
/// authenticated stream ended, and a new stream inherits that deadline, so a
/// channel opened on it keeps at least 4 s less this before the relay's.
pub(crate) const ACK_IDLE_REUSE: Duration = Duration::from_secs(1);
/// ACK connection dials between two bound re-ACK requests (the first ACK's
/// counts before the first): a connection lost is redialed at once, one
/// lost again falls back to per-dial channels until the next request.
pub(crate) const LINK_DIALS_PER_REACK: usize = 1;
/// Each `ack_conn` code is logged at most this often (with the count held
/// back since).
pub(crate) const LINK_LOG_EVERY: Duration = Duration::from_secs(5);
/// Slack on [`quiet_after`] for the stall watchdog's TCP ACK sample to land.
pub(crate) const QUIET_SLACK: Duration = Duration::from_millis(50);

/// How long a request in flight on an ACK connection whose smoothed round
/// trip is `srtt` may see no sign of the connection's life before the
/// connection counts as quiet: one round trip for the TCP ACK of the
/// request, one stall-watchdog sample (`flow_pool::ACK_SAMPLE`) for it to be
/// read, and `QUIET_SLACK`, at most [`QUIET_CAP`] (450 ms), `QUIET_SLACK`
/// inside the 500 ms the second request in flight follows the first by at
/// least (`provider_session_body::REACK_SPACING`). The cap binds from a
/// 150 ms srtt (at 170 ms: 450 ms, not 470 ms), so on every path a second
/// request whose first has seen no sign of life by then goes on another TCP
/// connection rather than riding one that may be frozen, whose stall
/// watchdog closes it only about 2.5 s after its last life, past the 2 s
/// re-ACK lead. On a healthy slow path whose TCP ACK the watchdog has not
/// sampled yet, that costs the second request a dial of its own while the
/// first still renews on the connection, never the lease.
pub(crate) const fn quiet_after(srtt: Duration) -> Duration {
    let after = srtt.saturating_add(ACK_SAMPLE).saturating_add(QUIET_SLACK);
    if after.as_nanos() > QUIET_CAP.as_nanos() {
        QUIET_CAP
    } else {
        after
    }
}
/// The longest [`quiet_after`].
pub(crate) const QUIET_CAP: Duration =
    crate::provider_session_body::REACK_SPACING.saturating_sub(QUIET_SLACK);
const _: () = assert!(
    quiet_after(Duration::MAX).as_nanos() + QUIET_SLACK.as_nanos()
        <= crate::provider_session_body::REACK_SPACING.as_nanos()
);

/// The `ack_conn` log codes.
pub(crate) const LINK_CODES: [&str; 7] = [
    "dialed", "lost", "goaway", "drained", "fallback", "closed", "revived",
];
/// How often a request sent off a quiet connection looks for that
/// connection's revival ([`AckLink::revived`]).
pub(crate) const REVIVE_POLL: Duration = Duration::from_millis(20);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The authenticated channels of this session live on one ACK connection
/// (from their inner mTLS until their exchange ends, as the relay counts an
/// authenticated stream), and since when none has been.
pub(crate) struct ConnLive {
    state: Mutex<(usize, Instant)>,
}

impl ConnLive {
    /// A connection ready at `at`, with no channel yet: the relay's idle
    /// deadline runs from its outer TLS.
    pub(crate) fn new(at: Instant) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new((0, at)),
        })
    }

    /// One more live channel, until the guard drops.
    pub(crate) fn enter(live: &Arc<Self>) -> LiveChannel {
        lock(&live.state).0 += 1;
        LiveChannel(live.clone())
    }

    /// Live channels now.
    #[cfg(test)]
    pub(crate) fn live(&self) -> usize {
        lock(&self.state).0
    }

    /// The instant a stream channel whose carrier request leaves at `at`
    /// ages from: `at` while a channel is live (the relay's stream deadline
    /// then runs from its accept), else when the last one ended (or the
    /// connection became ready), whose idle deadline the stream inherits.
    pub(crate) fn aged_from(&self, at: Instant) -> Instant {
        let (live, idle_from) = *lock(&self.state);
        if live > 0 {
            at
        } else {
            idle_from.min(at)
        }
    }

    /// How long no channel has been live at `now`; None while one is.
    pub(crate) fn idle_for(&self, now: Instant) -> Option<Duration> {
        let (live, idle_from) = *lock(&self.state);
        (live == 0).then(|| now.saturating_duration_since(idle_from))
    }
}

/// One live channel of an ACK connection ([`ConnLive::enter`]).
pub(crate) struct LiveChannel(Arc<ConnLive>);

impl Drop for LiveChannel {
    fn drop(&mut self) {
        let mut state = lock(&self.0.state);
        state.0 = state.0.saturating_sub(1);
        if state.0 == 0 {
            state.1 = Instant::now();
        }
    }
}

/// The current connection and its live channels.
struct Up {
    conn: Arc<PooledConn>,
    live: Arc<ConnLive>,
    // Streams it was given over its life.
    opened: usize,
}

impl LinkStats {
    /// One connection let go with `code`.
    fn count(&mut self, code: &str) {
        match code {
            "goaway" => self.goaways += 1,
            "lost" => self.lost += 1,
            "closed" => self.closed += 1,
            _ => self.drained += 1,
        }
    }
}

/// What an [`AckLink`] did, for its tests and logs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct LinkStats {
    /// Dials started.
    pub(crate) dials: usize,
    /// Dials that brought a connection up.
    pub(crate) dialed: usize,
    /// Connections let go because they ended without a GOAWAY, or after a
    /// stream of theirs failed.
    pub(crate) lost: usize,
    /// Connections let go after the relay's GOAWAY.
    pub(crate) goaways: usize,
    /// Connections let go because they were no longer current.
    pub(crate) drained: usize,
    /// S16m: connections let go because the link closed (the session's
    /// gate, or a re-pin) as they ended or a stream of theirs failed.
    pub(crate) closed: usize,
    /// S16m: requests sent off a quiet connection that came back to it.
    pub(crate) revived: usize,
    /// ACK-path channels or requests that went per-dial.
    pub(crate) fallbacks: usize,
    /// Streams given out.
    pub(crate) streams: usize,
}

struct State {
    up: Option<Up>,
    // `flow_pool::MAX_CONN_AGE`, shorter in tests.
    max_age: Duration,
    dialing: bool,
    // Dials since the last bound request.
    dials: usize,
    // PolicyAck requests in flight on a connection of the link, when each
    // left and (S16m) its connection's write mark then ([`AckLink::begin`]).
    requests: Vec<InFlight>,
    next_request: u64,
    stats: LinkStats,
}

impl Default for State {
    fn default() -> Self {
        Self {
            up: None,
            max_age: MAX_CONN_AGE,
            dialing: false,
            dials: 0,
            requests: Vec::new(),
            next_request: 0,
            stats: LinkStats::default(),
        }
    }
}

/// One PolicyAck request in flight on a connection of the link.
struct InFlight {
    id: u64,
    conn: Arc<PooledConn>,
    at: Instant,
    // `PooledConn::write_mark` as it left: its bytes follow it.
    mark: u64,
}

/// Rate-limited `ack_conn` logs, one clock per code.
#[derive(Default)]
struct Logs {
    at: [Option<Instant>; LINK_CODES.len()],
    held: [usize; LINK_CODES.len()],
}

/// The session's persistent ACK connection: see the module.
pub(crate) struct AckLink {
    peer: SocketAddr,
    interface: RelayInterface,
    crypto: Arc<PreparedCryptoInputs>,
    limiter: Arc<EstablishLimiter>,
    gate: Arc<WorkGate>,
    pins: EpochPins,
    // The re-pin generation the session was bound under.
    pin: u64,
    trace: Option<Trace>,
    state: Mutex<State>,
    logs: Mutex<Logs>,
    changed: Notify,
}

/// A connection for one more stream, and its live channels.
pub(crate) type LinkConn = (Arc<PooledConn>, Arc<ConnLive>);

impl AckLink {
    /// The ACK connection of one session: its verified `peer`, the relay
    /// interface it is bound to, its held crypto, its limiter and gate, and
    /// the epoch's pins with the generation it was bound under. It dials
    /// nothing until a dialer holding an ACK-path permit asks.
    pub(crate) fn new(
        peer: SocketAddr,
        interface: RelayInterface,
        crypto: Arc<PreparedCryptoInputs>,
        (limiter, gate): (Arc<EstablishLimiter>, Arc<WorkGate>),
        (pins, pin): (EpochPins, u64),
        trace: Option<Trace>,
    ) -> io::Result<Arc<Self>> {
        crypto.direct_peer(peer)?;
        Ok(Arc::new(Self {
            peer,
            interface,
            crypto,
            limiter,
            gate,
            pins,
            pin,
            trace,
            state: Mutex::default(),
            logs: Mutex::default(),
            changed: Notify::new(),
        }))
    }

    /// The session's verified relay peer.
    pub(crate) fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// The held crypto its streams authenticate with.
    pub(crate) fn crypto(&self) -> &Arc<PreparedCryptoInputs> {
        &self.crypto
    }

    fn mark(&self, step: &'static str) {
        if let Some(trace) = &self.trace {
            trace(step);
        }
    }

    /// `ack_conn <code>`, at most once per `LINK_LOG_EVERY` per code, with
    /// the count held back since (`ack_conn <code> held:<n>`).
    fn log(&self, code: &'static str) {
        if let Some(fields) = self.log_line(code, Instant::now()) {
            let fields: Vec<&str> = fields.iter().map(String::as_str).collect();
            crate::apple::log_fields("ack_conn", &fields);
        }
    }

    /// The fields `log` writes for `code` at `now`, None when held back.
    fn log_line(&self, code: &'static str, now: Instant) -> Option<Vec<String>> {
        let at = LINK_CODES.iter().position(|known| *known == code)?;
        let mut logs = lock(&self.logs);
        if logs.at[at].is_some_and(|last| now.saturating_duration_since(last) < LINK_LOG_EVERY) {
            logs.held[at] += 1;
            return None;
        }
        logs.at[at] = Some(now);
        match std::mem::take(&mut logs.held[at]) {
            0 => Some(vec![code.to_string()]),
            held => Some(vec![code.to_string(), format!("held:{held}")]),
        }
    }

    /// Whether the link may do no more relay work: the gate is closed (a
    /// stop or a seal drains it) or the epoch was re-pinned (S18: the
    /// session is rebuilt on the new pin).
    pub(crate) fn closed(&self) -> bool {
        self.gate.is_closed() || self.pins.generation() != self.pin
    }

    /// Let go of the current connection if it ended or is no longer
    /// current; the code it was let go with. S16m: once the link is
    /// `closed` (read before the link lock), any end is its own teardown.
    fn refresh(
        &self,
        state: &mut State,
        now: Instant,
        (generation, wake): (u64, u64),
        closed: bool,
    ) -> Option<&'static str> {
        let up = state.up.as_ref()?;
        let code = match up.conn.ended() {
            Some(_) if closed => "closed",
            Some(ConnEnd::GoAway(..)) => "goaway",
            Some(_) => "lost",
            None => {
                let stale = up.conn.pin_gen() != generation
                    || up.conn.wake_gen() != wake
                    || now.saturating_duration_since(up.conn.connect_started()) >= state.max_age
                    || up.opened >= MAX_CONN_STREAMS
                    || up.conn.stream_cap() == 0
                    || up
                        .live
                        .idle_for(now)
                        .is_some_and(|idle| idle > ACK_IDLE_REUSE);
                if !stale {
                    return None;
                }
                "drained"
            }
        };
        state.up = None;
        state.stats.count(code);
        Some(code)
    }

    fn let_go(&self, code: &'static str) {
        self.log(code);
        self.mark(match code {
            "goaway" => "ack_link_goaway",
            "lost" => "ack_link_lost",
            "closed" => "ack_link_closed",
            _ => "ack_link_drained",
        });
        self.changed.notify_waiters();
    }

    /// The current connection, for one more stream, if one is up and
    /// current; one that is not is let go here.
    pub(crate) fn current(&self) -> Option<LinkConn> {
        // Read before the link lock, which is never held while taking the
        // epoch's own locks.
        let generation = self.pins.generation();
        let wake = self.limiter.wake_generation();
        let closed = generation != self.pin || self.gate.is_closed();
        let (current, gone) = {
            let mut state = lock(&self.state);
            let gone = self.refresh(&mut state, Instant::now(), (generation, wake), closed);
            let current = if !closed {
                state.up.as_mut().map(|up| {
                    up.opened += 1;
                    (up.conn.clone(), up.live.clone())
                })
            } else {
                None
            };
            if current.is_some() {
                state.stats.streams += 1;
            }
            (current, gone)
        };
        if let Some(code) = gone {
            self.let_go(code);
        }
        current
    }

    /// Whether a channel on stream `stream_id` of `conn` may still carry
    /// its request: no end of `conn` fails that stream (a graceful GOAWAY
    /// covering it still lets it finish, as it lets a flow's), and `conn`
    /// was dialed under the epoch's present pin and wake generations (a
    /// channel opened before a sleep is never used after it). A channel
    /// whose stream an end fails also ends on its own.
    pub(crate) fn usable(&self, conn: &PooledConn, stream_id: u32) -> bool {
        conn.ended().is_none_or(|end| !fails(end, stream_id))
            && conn.pin_gen() == self.pins.generation()
            && conn.wake_gen() == self.limiter.wake_generation()
    }

    /// Claim the next dial, if one may start now: no connection is up or
    /// dialing, the dial budget allows one and the link is not closed.
    pub(crate) fn claim(self: &Arc<Self>) -> Option<DialClaim> {
        let generation = self.pins.generation();
        let wake = self.limiter.wake_generation();
        let closed = generation != self.pin || self.gate.is_closed();
        let (claim, gone) = {
            let mut state = lock(&self.state);
            let gone = self.refresh(&mut state, Instant::now(), (generation, wake), closed);
            let may = state.up.is_none()
                && !state.dialing
                && state.dials < LINK_DIALS_PER_REACK
                && !closed;
            if may {
                state.dialing = true;
                state.dials += 1;
                state.stats.dials += 1;
            }
            (may.then(|| DialClaim(self.clone())), gone)
        };
        if let Some(code) = gone {
            self.let_go(code);
        }
        claim
    }

    /// A connection for one more stream, for a dialer that holds an
    /// ACK-path permit: the current one; else one this dial brings up under
    /// that permit; else, while another dialer's dial runs, that one, waited
    /// for at most `wait`. None when none comes up (the caller falls back to
    /// a per-dial channel); an error only for an authentication-class dial
    /// failure, already judged (the caller backs off).
    pub(crate) async fn conn(self: &Arc<Self>, wait: Duration) -> io::Result<Option<LinkConn>> {
        let deadline = Instant::now() + wait;
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            // Registered before the state is read, so no change is missed.
            changed.as_mut().enable();
            if self.closed() {
                return Ok(None);
            }
            if let Some(conn) = self.current() {
                return Ok(Some(conn));
            }
            if let Some(claim) = self.claim() {
                return claim.dial().await;
            }
            if !lock(&self.state).dialing || Instant::now() >= deadline {
                return Ok(None);
            }
            tokio::select! {
                () = &mut changed => {}
                () = tokio::time::sleep_until(deadline) => return Ok(None),
            }
        }
    }

    /// A bound re-ACK request started: dials are budgeted anew.
    pub(crate) fn note_request(&self) {
        lock(&self.state).dials = 0;
    }

    /// One PolicyAck request leaving now on `conn`, in flight until the
    /// guard drops: its bytes follow `conn`'s write mark taken here.
    pub(crate) fn begin(self: &Arc<Self>, conn: &Arc<PooledConn>) -> LinkRequest {
        let mark = conn.write_mark();
        let mut state = lock(&self.state);
        let id = state.next_request;
        state.next_request += 1;
        state.requests.push(InFlight {
            id,
            conn: conn.clone(),
            at: Instant::now(),
            mark,
        });
        LinkRequest {
            link: self.clone(),
            id,
        }
    }

    /// The write mark of the earliest request in flight on `conn` that is
    /// quiet: `quiet_after` its round trip has passed since it left, and no
    /// byte `conn` wrote since has been acknowledged (S16m: inbound bytes,
    /// which may have left the relay before it, are no sign of its life).
    /// None: `conn` is not quiet.
    pub(crate) fn quiet_mark(&self, conn: &Arc<PooledConn>) -> Option<u64> {
        let left: Vec<(Instant, u64)> = lock(&self.state)
            .requests
            .iter()
            .filter(|request| Arc::ptr_eq(&request.conn, conn))
            .map(|request| (request.at, request.mark))
            .collect();
        let after = quiet_after(conn.srtt());
        left.into_iter()
            .filter(|(at, mark)| at.elapsed() >= after && !conn.acked_beyond(*mark))
            .map(|(_, mark)| mark)
            .min()
    }

    /// Whether `conn` is quiet (`quiet_mark`). Then no new request goes on
    /// it.
    pub(crate) fn quiet(&self, conn: &Arc<PooledConn>) -> bool {
        self.quiet_mark(conn).is_some()
    }

    /// Whether any connection of the link is quiet (`quiet`) now.
    pub(crate) fn quiet_any(&self) -> bool {
        let on: Vec<Arc<PooledConn>> = lock(&self.state)
            .requests
            .iter()
            .map(|request| request.conn.clone())
            .collect();
        on.iter().any(|conn| self.quiet(conn))
    }

    /// S16m: whether `conn`, quiet when a request left it at `mark`
    /// (`quiet_mark`), has since shown the life it lacked: it is still the
    /// link's current connection, not ended, the link is not closed, and a
    /// byte it wrote after `mark` has been acknowledged. A request sent off
    /// it then comes back to it rather than finish a dial of its own.
    pub(crate) fn revived(&self, conn: &Arc<PooledConn>, mark: u64) -> bool {
        if self.closed() {
            return false;
        }
        let current = lock(&self.state)
            .up
            .as_ref()
            .is_some_and(|up| Arc::ptr_eq(&up.conn, conn));
        current && conn.acked_beyond(mark)
    }

    /// S16m: a request sent off a quiet connection came back to it
    /// (`revived`).
    pub(crate) fn note_revived(&self) {
        lock(&self.state).stats.revived += 1;
        self.log("revived");
        self.mark("ack_link_revived");
    }

    /// A channel or request of the ACK path went per-dial.
    pub(crate) fn fallback(&self) {
        lock(&self.state).stats.fallbacks += 1;
        self.log("fallback");
        self.mark("ack_link_fallback");
    }

    /// A stream of `conn` failed short of an authentication-class refusal
    /// (a lost or refused carrier, an inner handshake or exchange that did
    /// not complete): if `conn` is the current connection it is let go, so
    /// no later stream waits on a connection that fails them.
    pub(crate) fn failed(&self, conn: &Arc<PooledConn>, error: &io::Error) {
        if is_auth_refused(error) {
            return;
        }
        // A GOAWAY is recorded as it is read, before h2 fails the streams
        // it names. S16m: once the link is closed, its own teardown.
        let code = match conn.ended() {
            _ if self.closed() => "closed",
            Some(ConnEnd::GoAway(..)) => "goaway",
            _ => "lost",
        };
        let gone = {
            let mut state = lock(&self.state);
            match &state.up {
                Some(up) if Arc::ptr_eq(&up.conn, conn) => {
                    state.up = None;
                    state.stats.count(code);
                    true
                }
                _ => false,
            }
        };
        if gone {
            self.let_go(code);
        }
    }

    /// Test-only: no byte the current connection writes from now on is
    /// acknowledged (`PooledConn::freeze_acks_for_test`), as on a path that
    /// froze now; whether one was up.
    #[cfg(test)]
    pub(crate) fn freeze_acks_for_test(&self) -> bool {
        let state = lock(&self.state);
        if let Some(up) = &state.up {
            up.conn.freeze_acks_for_test();
        }
        state.up.is_some()
    }

    /// Test-only (S16m): the current connection's TCP ACKs flow again
    /// (`PooledConn::thaw_acks_for_test`); whether one was up.
    #[cfg(test)]
    pub(crate) fn thaw_acks_for_test(&self) -> bool {
        let state = lock(&self.state);
        if let Some(up) = &state.up {
            up.conn.thaw_acks_for_test();
        }
        state.up.is_some()
    }

    /// Test-only: a connection this old is no longer current.
    #[cfg(test)]
    pub(crate) fn set_max_age_for_test(&self, max_age: Duration) {
        lock(&self.state).max_age = max_age;
    }

    /// What the link did so far.
    #[cfg(test)]
    pub(crate) fn stats(&self) -> LinkStats {
        lock(&self.state).stats
    }
}

/// One PolicyAck request in flight on the link ([`AckLink::begin`]).
pub(crate) struct LinkRequest {
    link: Arc<AckLink>,
    id: u64,
}

impl Drop for LinkRequest {
    fn drop(&mut self) {
        lock(&self.link.state)
            .requests
            .retain(|request| request.id != self.id);
    }
}

/// The one dial of the link in progress ([`AckLink::claim`]); dropped
/// before it completes, the link is down and may dial again.
pub(crate) struct DialClaim(Arc<AckLink>);

impl DialClaim {
    /// Dial under the caller's ACK-path permit. Up: logged `ack_conn
    /// dialed`. A failure was judged by `PooledConn::dial_ack`; an
    /// authentication-class one is returned, any other is None.
    pub(crate) async fn dial(self) -> io::Result<Option<LinkConn>> {
        let link = &self.0;
        let dialed = PooledConn::dial_ack(
            link.peer,
            &link.interface,
            &link.crypto,
            &link.limiter,
            &link.gate,
            link.pin,
        )
        .await;
        let conn = match dialed {
            Ok(conn) => Arc::new(conn),
            Err(error) if is_auth_refused(&error) => return Err(error),
            Err(_) => return Ok(None),
        };
        let live = ConnLive::new(Instant::now());
        {
            let mut state = lock(&link.state);
            state.up = Some(Up {
                conn: conn.clone(),
                live: live.clone(),
                opened: 1,
            });
            state.stats.dialed += 1;
            state.stats.streams += 1;
        }
        link.log("dialed");
        link.mark("ack_link_dialed");
        Ok(Some((conn, live)))
    }
}

impl Drop for DialClaim {
    fn drop(&mut self) {
        lock(&self.0.state).dialing = false;
        self.0.changed.notify_waiters();
    }
}

#[cfg(test)]
#[path = "ack_conn_tests.rs"]
mod tests;
