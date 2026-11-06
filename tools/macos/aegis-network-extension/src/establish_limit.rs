//! Session-wide relay channel establishment limiter (B-06 S16g).
//!
//! Installed v17 showed that the burst of flows macOS sends right after the
//! tunnel comes up opened one outer TLS + H2 + inner mTLS channel per flow at
//! once, beside the pre-warmed ACK channels, and the first session lost its
//! lease after its pre-warms failed. aegis-server admits at most
//! `max_handshakes_per_peer` concurrent inner handshakes per peer IP (16 by
//! default, 32 on relay-a; its handshake permit runs from the carrier
//! request through mTLS), at most `max_sessions_per_peer` established inner
//! sessions per peer IP (128 by default, 1024 on relay-a; every live
//! flow and every ACK channel holds one), runs one 5 s deadline over mTLS
//! and the first Open or PolicyAck, and bans an IP for 300 s after 3
//! authentication failures. Since R2 (aegis-server c7c4cd4b, deployed on
//! relay-a as 83b48386) only a refused device counts as one
//! (MissingCertificate, CertificateRejected, DeviceNotAllowed): an inner
//! handshake that misses its deadline or loses its transport no longer does.
//!
//! Every establishment of a session holds one permit of this limiter (S16l:
//! the ACK path's persistent ACK connection is dialed under the permit of
//! the first ACK, pre-warm or fresh re-ACK whose stream it carries, so it
//! never needs one of its own). An
//! ACK-path establishment (the first ACK, a pre-warmed ACK channel and a
//! fresh re-ACK) takes it before its own TCP dial and keeps it until its
//! PolicyAck, or until it failed; a pre-warmed channel keeps it while it
//! idles, since the relay's establishment deadline still runs for it until
//! its PolicyAck. A flow (its TCP, udp_once or udp_flow channel) rides one
//! H2 stream of the session's flow pool (S16h): it takes its permit once its
//! stream is reserved, and the permit covers that stream's carrier request
//! and 200, its inner mTLS and its Open, until the Open request is written,
//! the point by which the relay has ended its handshake; the flow then only
//! counts as an unanswered Open until its status, so a slow or black-holed
//! target never holds a permit. A pool dial (TCP, outer TLS and H2) holds a
//! flow permit too, until its connection is ready. At most
//! `ESTABLISH_PERMITS` run at once, under the relay's 32 concurrent inner
//! handshakes per peer IP (`RELAY_HANDSHAKES_PER_IP`) with room for the
//! skew between a permit's return and the relay's. Flows may hold at most `ESTABLISH_PERMITS - ACK_RESERVE`
//! of them, exactly the pool's handshake slots (`POOL_CONNS * H_CONN`), the
//! reserve covering every pre-warm slot and both re-ACK requests in flight,
//! and a waiting ACK-path establishment goes before every waiting flow, so
//! a flow burst never starves the lease. Flows establishing or awaiting
//! their Open status are capped at `FLOW_OPENS`, and live flows at the
//! session's live cap ([`live_cap`], S16i-2): the signed bundle's
//! `max_flows` once bound ([`EstablishLimiter::bind_signed_max_flows`]),
//! the relay's `RELAY_SESSIONS_PER_IP` less the ACK path's sessions and
//! `LIVE_MARGIN`, and what the pool can carry (`LIVE_FLOWS_MAX`), whichever
//! is least. A flow takes its live place only once it reserved its pooled
//! stream, so a flow still queued counts against no relay session. A flow
//! that finds no permit, or no live place, waits within its budget and is
//! then refused; places are handed out first come, first served
//! ([`LiveTicket`]), and every release wakes the queue; nothing here waits
//! without a bound.
//!
//! After an authentication-class failure no establishment of the session (and
//! none of a session rebuilt in the same provider epoch) starts for at least
//! `AUTH_BACKOFF`, so a refused identity is never retried in a tight loop;
//! then each purpose runs one establishment at a time until the relay
//! answers one, so the next attempt is a single probe per purpose, never a
//! burst of refusals, and a flow probe never holds the ACK path back.
//! Authentication class is opt-in: a TLS error anywhere in the chain (a peer
//! alert, a refused certificate) at any step, or an explicit refusal of the
//! outer carrier (a non-200 carrier status or a wrong content type, a
//! refused ALPN or ECH). A timeout, a transport drop, an H2 reset or GOAWAY,
//! a local network error and anything else unrecognised are not.
//!
//! A bound re-ACK (a fresh dial carrying the request that renews the lease)
//! goes before every waiting pre-warm, as ACK-path establishments go before
//! flows: while probing, the one ACK-path slot is never taken by a pre-warm
//! that would idle on it until the relay's admission deadline while the
//! request that could renew the lease waits behind it.
//!
//! The relay keeps counting the inner sessions of a session whose relay
//! sockets were bound to an interface (or address) that is gone: no FIN or
//! RST reaches it, and it reaps them only after its idle timeout. So an
//! epoch re-pin (S18) records the outgoing session's live flows and ACK-path
//! establishments as stranded for `STRANDED_HOLD`, and meanwhile every
//! session of the epoch takes that count off the relay's room alone
//! (`relay_live_room`: `RELAY_SESSIONS_PER_IP` less the ACK path's sessions
//! and `LIVE_MARGIN`) and runs at most the lesser of that and its live cap,
//! so stranded and new sessions together stay under the relay's sessions
//! per IP. Stranded sessions hold no stream of the rebuilt pool and no
//! place of the signed `max_flows`, which only this side enforces, so they
//! narrow neither: against relay-a's 1024 a rebuilt session keeps all
//! 248 live places with 251 stranded. Its
//! establishments in progress, and its flows whose Open was written within
//! the relay's deadline and is still unanswered (over the lost path the
//! relay may never have read their Finished), may still hold relay
//! handshakes until the relay's 5 s deadline ends them. So they are recorded
//! as stranded handshakes, each for `STRANDED_HS_HOLD` from the strand (a
//! written flow's from its write, which follows the relay's accept), and
//! meanwhile every session of the epoch runs at most
//! `RELAY_HANDSHAKES_PER_IP - HANDSHAKE_SKEW` less every stranded one at
//! once, however many re-pins stranded them: flows only beyond the ACK
//! reserve, and the ACK path itself waits, within its budget, while fewer
//! than its reserve remain. So stranded and new handshakes together stay
//! under the relay's 32.
//!
//! Before the Mac sleeps no new establishment starts (`quiesce`), at most
//! `QUIESCE_MAX` of awake time or until the wake: one begun then would most
//! likely stall mid-handshake on a sleeping interface, where it would only
//! hold a relay handshake until the deadline (and, at a relay without R2,
//! count as an authentication failure of the public IP).
//!
//! A flow's channel the relay ends after the inner handshake and before its
//! Open status is ambiguous: aegis-server ends one without a delivered alert
//! both when it refuses the device and when its 128-session cap is full,
//! which it does not count. That is an unanswered Open: it backs off flows
//! alone for `FLOW_BACKOFF`, and then flows run one at a time until a flow's
//! status arrives. The ACK path, whose identity the current lease proves,
//! keeps running. A PolicyAck channel the relay ends is neither: the relay
//! also ends one when it refuses the ACK itself, and the re-ACK schedule
//! already paces that path.
//!
//! The epoch also keeps a strike ledger (S16h-8b): pooled flow streams lost
//! while the relay may have been in their inner handshake, to a cause it
//! may never have seen, each of which may have cost an authentication
//! strike at the relay's deadline (v41: a re-pin's own teardown is none;
//! its handshakes are stranded instead, as above). Its entries expire `STRIKE_WINDOW` after
//! the first, as aegis-server's do. From one entry flows hold at most
//! `L1_FLOW_PERMITS`, from two `L2_FLOW_PERMITS`; and two stall deaths of
//! pooled connections within `STALL_DEATH_WINDOW` leave flows
//! `FALLBACK_FLOW_PERMITS` for `FALLBACK_HOLD` (S16h-8d). Both live in the
//! epoch, so a rebuilt session inherits them; neither touches the ACK path.
//!
//! The epoch also keeps its flows' outcome record (S16i-1, `flow_log`) and
//! whether it reached Running, after which each of its sessions pre-dials
//! one pooled connection ([`EstablishLimiter::try_prewarm`]): only while no
//! backoff, probing or pause before sleep is in force and no flow waits for
//! a permit, never by waiting for one.
use crate::flow_log::{FlowLog, Outcome, PoolSnapshot};
use std::{
    collections::VecDeque,
    error::Error as StdError,
    fmt, io,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, MutexGuard, PoisonError, Weak,
    },
    time::{Duration, Instant},
};
use tokio::sync::Notify;
use tokio_rustls::rustls;

/// Flow establishments of one session at once: exactly the flow pool's
/// handshake slots, whatever the ACK reserve.
pub(crate) const FLOW_PERMITS: usize = crate::flow_pool::POOL_CONNS * crate::flow_pool::H_CONN;
/// Concurrent establishments across every purpose of one session: every
/// flow permit (`POOL_CONNS * H_CONN`, 4 x 4) and the ACK reserve (20).
pub(crate) const ESTABLISH_PERMITS: usize = FLOW_PERMITS + ACK_RESERVE;
/// Permits flows can never take: every pre-warm slot and every re-ACK
/// request in flight (S16k: two; or the first ACK beside the first
/// pre-warms).
pub(crate) const ACK_RESERVE: usize =
    crate::provider_session_body::PREWARM_SLOTS + crate::provider_session_body::ACK_IN_FLIGHT;
/// The shortest pause after an authentication-class failure.
pub(crate) const AUTH_BACKOFF: Duration = Duration::from_secs(2);
/// The shortest pause of flows alone after an unanswered Open.
pub(crate) const FLOW_BACKOFF: Duration = Duration::from_secs(2);
/// Flows establishing or awaiting their Open status, at most: every flow
/// permit, and 16 Opens awaiting a slow target's status beside them.
pub(crate) const FLOW_OPENS: usize = 32;
/// aegis-server's established inner sessions per peer IP (aegis-core
/// secure_channel/mod.rs admission default, taken after the inner mTLS,
/// session/secure.rs). It is raised only once the server owner confirms the
/// deployed relay's value: admitting more live flows than the relay holds
/// turns into its session refusals, which this side reads as unanswered
/// Opens and answers with `FLOW_BACKOFF` for every flow. relay-a, the
/// only macOS relay, runs 1024 since 2026-10-22 07:21 UTC (server source
/// 83b48386, handoff `capacity.max_sessions_per_peer`); a relay still at
/// the 128 default would over-admit until a signed per-relay value exists.
pub(crate) const RELAY_SESSIONS_PER_IP: usize = 1024;
/// The ACK path's relay sessions: every pre-warm and every request in
/// flight.
pub(crate) const ACK_SESSIONS: usize = ACK_RESERVE;
/// Relay sessions left spare beyond the ACK path's: a released flow's
/// session ends at the relay only once its RST_STREAM is processed there.
pub(crate) const LIVE_MARGIN: usize = 5;
/// Live flows the flow pool can carry at once, at most: every connection
/// at the stream cap (`flow_pool::STREAMS_CAP`).
pub(crate) const LIVE_FLOWS_MAX: usize =
    crate::flow_pool::POOL_CONNS * crate::flow_pool::STREAMS_CAP;

/// S16i-2: the live cap of a session whose signed `max_flows` is
/// `signed_max_flows`, against a relay that holds `relay_sessions` inner
/// sessions per peer IP: the least of the signed cap, the relay's sessions
/// less the ACK path's and `LIVE_MARGIN`, and `LIVE_FLOWS_MAX`.
pub(crate) const fn live_cap_for(signed_max_flows: usize, relay_sessions: usize) -> usize {
    let relay = relay_sessions.saturating_sub(ACK_SESSIONS + LIVE_MARGIN);
    let cap = if signed_max_flows < relay {
        signed_max_flows
    } else {
        relay
    };
    if cap < LIVE_FLOWS_MAX {
        cap
    } else {
        LIVE_FLOWS_MAX
    }
}

/// The live flows a relay holding `relay_sessions` inner sessions per peer
/// IP leaves a session while `stranded` of the epoch's sessions are still
/// counted there (a re-pin, `STRANDED_HOLD`): its sessions less the ACK
/// path's, `LIVE_MARGIN` and the stranded ones. A session runs at most the
/// lesser of this and its live cap (`EstablishLimiter::live_room`).
pub(crate) const fn relay_live_room(relay_sessions: usize, stranded: usize) -> usize {
    relay_sessions
        .saturating_sub(ACK_SESSIONS + LIVE_MARGIN)
        .saturating_sub(stranded)
}

/// `live_cap_for` against this build's `RELAY_SESSIONS_PER_IP`.
pub(crate) const fn live_cap(signed_max_flows: usize) -> usize {
    live_cap_for(signed_max_flows, RELAY_SESSIONS_PER_IP)
}

/// Live flows of one session before the signed `max_flows` is bound: the
/// relay's and the pool's bound alone.
pub(crate) const LIVE_FLOWS: usize = live_cap(usize::MAX);
// The signed bundle admits at most 512 flows; with every one of them live
// the ACK path still finds its sessions at the relay.
const _: () = assert!(live_cap(512) + ACK_RESERVE < RELAY_SESSIONS_PER_IP);
const _: () = assert!(LIVE_FLOWS == live_cap(512));
// The derivation itself, independent of the relay value this build carries:
// 119 against today's 128 sessions, 248 (the pool's bound) against 1024.
const _: () = assert!(live_cap_for(256, 128) == 119);
const _: () = assert!(live_cap_for(256, 1024) == 248);
const _: () = assert!(live_cap_for(64, 128) == 64);
const _: () = assert!(live_cap_for(64, 1024) == 64);
const _: () = assert!(live_cap_for(512, 1024) == LIVE_FLOWS_MAX);
const _: () = assert!(live_cap_for(0, 128) == 0);
const _: () = assert!(live_cap_for(usize::MAX, 0) == 0);
const _: () = assert!(LIVE_FLOWS_MAX == 248);
// Stranded sessions come off the relay's room only: 252 stranded (248 live
// and the ACK path's 4) leave relay-a room for every pooled flow.
const _: () = assert!(relay_live_room(1024, 252) == 763);
const _: () = assert!(relay_live_room(128, 30) == 89);
const _: () = assert!(relay_live_room(128, 252) == 0);
/// aegis-server's concurrent inner handshakes per peer IP
/// (`max_handshakes_per_peer`, aegis-core secure_channel/mod.rs:123). Like
/// `RELAY_SESSIONS_PER_IP` it is raised only once the server owner
/// confirmed the deployed relay's value: relay-a, the only macOS relay,
/// runs 32 (handoff `capacity.max_handshakes_per_peer`) with R2 (server
/// source c7c4cd4b, deployed as 83b48386: an inner handshake's timeout or
/// lost transport is no authentication strike; only MissingCertificate,
/// CertificateRejected and DeviceNotAllowed count). A relay still at
/// aegis-core's default 16 would see up to `ESTABLISH_PERMITS +
/// HANDSHAKE_SKEW` (22) concurrent handshakes of this session and refuse
/// those beyond its 16 after their 200 (`HandshakeCapped`, which narrows
/// that connection to one handshake for its capacity pause); a relay
/// without R2 would also count each of up to `H_CONN` (4) handshakes of a
/// connection frozen mid-handshake as a strike at its deadline, past its
/// ban at 3. The epoch's strike ledger (S16h-8b) and stall fallback (8d)
/// still narrow the pool after such a loss, as they did at `H_CONN` 2,
/// until a signed per-relay value exists.
const RELAY_HANDSHAKES_PER_IP: usize = 32;
/// Relay handshakes beyond this session's permits it may still count: a
/// flow's permit returns when its Open is written, and the relay's
/// handshake permit only once it read the client's Finished written just
/// before, while the next flow's carrier already reaches it.
const HANDSHAKE_SKEW: usize = 2;
// Flows take exactly the pool's handshake slots: never a permit a pool
// connection cannot use, never a pool slot without a permit.
const _: () = assert!(
    ESTABLISH_PERMITS - ACK_RESERVE == crate::flow_pool::POOL_CONNS * crate::flow_pool::H_CONN
);
// Every permit, the skew and as much again in spare under the relay's 32.
const _: () = assert!(ESTABLISH_PERMITS + 2 * HANDSHAKE_SKEW <= RELAY_HANDSHAKES_PER_IP);
// S16k: the reserve is exactly the pre-warm slots and the requests in
// flight, and flows keep their share beside it.
const _: () = assert!(
    ACK_RESERVE
        == crate::provider_session_body::PREWARM_SLOTS
            + crate::provider_session_body::ACK_IN_FLIGHT
);
const _: () = assert!(ESTABLISH_PERMITS - ACK_RESERVE == FLOW_PERMITS);
// The merged geometry written out: 16 flow permits (4 connections of 4
// handshakes), 4 reserved for the ACK path, 20 in all, and 20 with twice
// the skew within relay-a's 32.
const _: () = assert!(FLOW_PERMITS == 16);
const _: () = assert!(ACK_RESERVE == 4);
const _: () = assert!(ESTABLISH_PERMITS == 20);
const _: () = assert!(ESTABLISH_PERMITS + 2 * HANDSHAKE_SKEW == 24);
const _: () = assert!(FLOW_OPENS >= FLOW_PERMITS + 16);
// Every flow permit, and 16 Opens awaiting their status beside them.
const _: () = assert!(FLOW_OPENS >= (ESTABLISH_PERMITS - ACK_RESERVE) + 16);
/// How long the relay may keep counting a stranded session: aegis-server's
/// 60 s idle timeout from the last progress, and a margin.
pub(crate) const STRANDED_HOLD: Duration = Duration::from_secs(65);
/// How long the relay may keep counting a stranded handshake: aegis-server's
/// 5 s deadline from the stream's accept, and a margin.
pub(crate) const STRANDED_HS_HOLD: Duration = Duration::from_secs(6);
/// The longest pause of new establishments before sleep without a wake, in
/// awake time (the monotonic clock does not advance while the Mac sleeps).
pub(crate) const QUIESCE_MAX: Duration = Duration::from_secs(10);
/// The longest wait any caller may ask for.
const MAX_WAIT: Duration = Duration::from_secs(60);
/// `establish_queue` and `flow_live_cap` are each logged at most this often.
pub(crate) const QUEUE_LOG_EVERY: Duration = Duration::from_secs(1);

/// How long aegis-server counts a peer IP's authentication failures: from
/// the first, after which the whole count is pruned (rate_limit.rs entries
/// keyed by their first failure, config.rs 300 s). The epoch's strike
/// ledger mirrors it ([`StrikeLedger`]).
pub(crate) const STRIKE_WINDOW: Duration = Duration::from_secs(300);
/// Flow permits at strike level 1 (one pooled stream lost while the relay
/// may have been mid-handshake): one handshake per pool connection.
pub(crate) const L1_FLOW_PERMITS: usize = crate::flow_pool::POOL_CONNS;
/// Flow permits at strike level 2 and above: one handshake at a time.
pub(crate) const L2_FLOW_PERMITS: usize = 1;
/// Stall deaths of pooled connections within `STALL_DEATH_WINDOW` that
/// switch the pool to one stream per connection ([`StallBook`]).
pub(crate) const STALL_DEATHS: usize = 2;
pub(crate) const STALL_DEATH_WINDOW: Duration = Duration::from_secs(60);
/// How long the one-stream-per-connection fallback lasts.
pub(crate) const FALLBACK_HOLD: Duration = Duration::from_secs(300);
/// Flow permits during the fallback: before S16h, every flow dialed its own
/// connection under `6 - 3` permits.
pub(crate) const FALLBACK_FLOW_PERMITS: usize = 3;
// Each level is narrower than the one below it, and every one is under the
// flows' own permits.
const _: () = assert!(L2_FLOW_PERMITS < L1_FLOW_PERMITS);
const _: () = assert!(L1_FLOW_PERMITS < ESTABLISH_PERMITS - ACK_RESERVE);
const _: () = assert!(FALLBACK_FLOW_PERMITS < ESTABLISH_PERMITS - ACK_RESERVE);
const _: () = assert!(STALL_DEATHS == 2);

/// The epoch's strike ledger (S16h-8b): pooled streams lost while the relay
/// may have been in their inner handshake, from their 200 until half an RTT
/// after their mTLS returned, to a stall, a local close or a lost interface,
/// whose relay deadline may then have fired as an authentication failure
/// of the public IP. Like aegis-server's own count, every entry expires
/// `STRIKE_WINDOW` after the first. It lives in the epoch's `AuthBackoff`,
/// so a session rebuilt after the loss (S17) inherits it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct StrikeLedger {
    first: Option<Instant>,
    count: usize,
}

impl StrikeLedger {
    /// The entries still counted at `now`.
    pub(crate) fn at(&self, now: Instant) -> usize {
        match self.first {
            Some(first) if now < first + STRIKE_WINDOW => self.count,
            _ => 0,
        }
    }

    /// One more entry at `now`; returns the count. An expired ledger starts
    /// again from this one.
    pub(crate) fn record(&mut self, now: Instant) -> usize {
        if self.at(now) == 0 {
            *self = Self {
                first: Some(now),
                count: 0,
            };
        }
        self.count = self.count.saturating_add(1);
        self.count
    }

    /// When the entries counted at `now` expire (none: None).
    fn expires(&self, now: Instant) -> Option<Instant> {
        self.first
            .filter(|_| self.at(now) > 0)
            .map(|first| first + STRIKE_WINDOW)
    }
}

/// The epoch's stall deaths (S16h-8d): `STALL_DEATHS` pooled connections
/// closed by their stall watchdog within `STALL_DEATH_WINDOW` switch the
/// pool to one stream per connection for `FALLBACK_HOLD`, as every flow ran
/// before S16h: one frozen 5-tuple then ends one flow.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct StallBook {
    last: Option<Instant>,
    until: Option<Instant>,
    switched: u64,
}

impl StallBook {
    /// A stall death at `now`: whether it switched the fallback on (or
    /// renewed it).
    pub(crate) fn death(&mut self, now: Instant) -> bool {
        let second = self
            .last
            .is_some_and(|last| now.saturating_duration_since(last) < STALL_DEATH_WINDOW);
        self.last = Some(now);
        if second {
            let until = now + FALLBACK_HOLD;
            self.until = Some(self.until.map_or(until, |at| at.max(until)));
            self.switched = self.switched.wrapping_add(1);
        }
        second
    }

    /// Whether the fallback is in force at `now`.
    pub(crate) fn active(&self, now: Instant) -> bool {
        self.until.is_some_and(|until| now < until)
    }

    fn ends(&self, now: Instant) -> Option<Instant> {
        self.until.filter(|until| now < *until)
    }
}

/// How the epoch's strikes and stall deaths narrow its flows at one
/// instant: strike level 1 leaves one inner handshake per connection
/// (`L1_FLOW_PERMITS` at once), level 2 one handshake at a time and only on
/// a connection proven alive within `PROOF_FRESH`; the fallback one stream
/// per connection under `FALLBACK_FLOW_PERMITS`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PoolMode {
    pub(crate) strikes: usize,
    pub(crate) fallback: bool,
}

impl PoolMode {
    /// Flow permits at once, at most, beyond the limiter's own (None: no
    /// narrower cap).
    pub(crate) fn flow_permits(self) -> Option<usize> {
        let strikes = match self.strikes {
            0 => None,
            1 => Some(L1_FLOW_PERMITS),
            _ => Some(L2_FLOW_PERMITS),
        };
        let fallback = self.fallback.then_some(FALLBACK_FLOW_PERMITS);
        match (strikes, fallback) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Whether a flow's handshake needs its connection proven alive
    /// (a PONG, or its outer TLS handshake) within `PROOF_FRESH`.
    pub(crate) fn needs_proof(self) -> bool {
        self.strikes >= 2
    }
}

/// How recent a connection's proof of life must be at strike level 2.
pub(crate) const PROOF_FRESH: Duration = Duration::from_secs(1);

/// What an establishment is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Purpose {
    /// The first ACK, a pre-warmed ACK channel or a fresh re-ACK.
    Ack,
    /// A packet-engine flow's own channel.
    Flow,
}

impl Purpose {
    fn code(self) -> &'static str {
        match self {
            Purpose::Ack => "ack",
            Purpose::Flow => "flow",
        }
    }
}

/// The opaque refusal of an authentication-class failure. Its text is the
/// same as every other held-crypto refusal; only its type tells it apart.
#[derive(Debug)]
pub(crate) struct AuthRefused;

impl fmt::Display for AuthRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("prepared crypto refused")
    }
}

impl StdError for AuthRefused {}

pub(crate) fn auth_refused() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, AuthRefused)
}

/// Whether `error` is the refusal of an authentication-class failure.
pub(crate) fn is_auth_refused(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.is::<AuthRefused>())
}

/// The opaque refusal of an unanswered Open: the relay ended a flow's
/// channel after the inner handshake and before its status. Same text as
/// every other held-crypto refusal.
#[derive(Debug)]
pub(crate) struct OpenUnanswered;

impl fmt::Display for OpenUnanswered {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("prepared crypto refused")
    }
}

impl StdError for OpenUnanswered {}

pub(crate) fn open_unanswered() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, OpenUnanswered)
}

/// Whether `error` is the refusal of an unanswered Open.
pub(crate) fn is_open_unanswered(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.is::<OpenUnanswered>())
}

/// The opaque refusal of a flow whose pooled outer connection ended under
/// it (S16h): a transport loss of every stream on that connection, judged
/// neither authentication class nor an unanswered Open, so one connection's
/// end never backs the session's flows off. Same text as every other
/// held-crypto refusal.
#[derive(Debug)]
pub(crate) struct ConnLost;

impl fmt::Display for ConnLost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("prepared crypto refused")
    }
}

impl StdError for ConnLost {}

pub(crate) fn conn_lost() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, ConnLost)
}

/// Whether `error` is the refusal of a flow whose connection ended.
pub(crate) fn is_conn_lost(error: &io::Error) -> bool {
    error.get_ref().is_some_and(|inner| inner.is::<ConnLost>())
}

/// Every error in `error`'s chain, including what an `io::Error` wraps
/// (its `source` skips the wrapped error itself).
pub(crate) fn any_in_chain(
    error: &(dyn StdError + 'static),
    found: &mut dyn FnMut(&(dyn StdError + 'static)) -> bool,
) -> bool {
    let mut next = Some(error);
    while let Some(current) = next {
        if found(current) {
            return true;
        }
        if let Some(wrapped) = current
            .downcast_ref::<io::Error>()
            .and_then(io::Error::get_ref)
        {
            if any_in_chain(wrapped, found) {
                return true;
            }
        }
        next = current.source();
    }
    false
}

/// A TLS error anywhere in the chain: a peer alert, a refused certificate.
pub(crate) fn tls_failure(error: &(dyn StdError + 'static)) -> bool {
    any_in_chain(error, &mut |current| current.is::<rustls::Error>())
}

/// The explicit carrier refusals aegis-client's `connect_h2_from_held` and
/// `ech_policy::require_accepted_ech` raise as plain messages after the
/// outer TLS handshake: the relay answered, and refused. Each is matched as
/// a message prefix; an unmatched message is never authentication class.
pub(crate) const CARRIER_REFUSALS: [&str; 4] = [
    "secure carrier rejected with HTTP",
    "invalid secure carrier content type",
    "secure carrier requires HTTP/2",
    "required ECH was not accepted by the relay",
];

/// An explicit refusal of the outer carrier anywhere in the chain.
pub(crate) fn carrier_refusal(error: &(dyn StdError + 'static)) -> bool {
    any_in_chain(error, &mut |current| {
        let text = current.to_string();
        CARRIER_REFUSALS
            .iter()
            .any(|refusal| text.starts_with(refusal))
    })
}

/// A timeout anywhere in the chain.
pub(crate) fn timed_out(error: &(dyn StdError + 'static)) -> bool {
    any_in_chain(error, &mut |current| {
        current.is::<tokio::time::error::Elapsed>()
            || current
                .downcast_ref::<io::Error>()
                .is_some_and(|io| io.kind() == io::ErrorKind::TimedOut)
    })
}

/// The peer ended the connection or stream: an end of file, a reset, a
/// broken pipe.
pub(crate) fn peer_ended(error: &(dyn StdError + 'static)) -> bool {
    any_in_chain(error, &mut |current| {
        current.downcast_ref::<io::Error>().is_some_and(|io| {
            matches!(
                io.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::NotConnected
            )
        })
    })
}

/// A failed outer TLS/H2 or inner mTLS handshake that is authentication
/// class, identified positively: a TLS error, or an explicit carrier
/// refusal. A timeout, a transport drop (at TLS or inside H2), an H2 reset
/// or GOAWAY, a local network error and an unrecognised error are not.
pub(crate) fn handshake_auth_class(error: &(dyn StdError + 'static)) -> bool {
    tls_failure(error) || carrier_refusal(error)
}

/// A flow's failed Open exchange after the inner handshake that is
/// authentication class: a TLS error (a delivered alert refusing the
/// device certificate).
pub(crate) fn exchange_auth_class(error: &(dyn StdError + 'static)) -> bool {
    tls_failure(error)
}

/// A flow's failed Open exchange that is an unanswered Open: the relay ended
/// the channel before its status, with no TLS error and no timeout.
pub(crate) fn exchange_unanswered(error: &(dyn StdError + 'static)) -> bool {
    !tls_failure(error) && peer_ended(error) && !timed_out(error)
}

/// The epoch's authentication backoff, shared by every session rebuilt in
/// one provider epoch, so a rebuild never restarts a refused identity's dial
/// at once: the backoff end, and whether establishments run one at a time
/// per purpose until one is verified by the relay's first reply. It also
/// carries the epoch's relay sessions stranded by a re-pin, the pause before
/// sleep, and the epoch's current session limiter.
#[derive(Clone, Default)]
pub(crate) struct AuthBackoff {
    auth: Arc<Mutex<EpochAuth>>,
    slots: Arc<Mutex<EpochSlots>>,
    // The epoch's flow outcome record (S16i-1); its own lock, never taken
    // under another.
    flows: Arc<Mutex<FlowLog>>,
}

#[derive(Clone, Copy, Default)]
struct EpochAuth {
    until: Option<Instant>,
    probing: bool,
    // Failures recorded so far: only an establishment started after the
    // latest one verifies the identity again.
    failures: u64,
    // No establishment starts before this (the pause before sleep).
    quiet_until: Option<Instant>,
    // Wakes so far (S16h): a pooled connection dialed before the latest one
    // may have stalled while the Mac slept, where `Instant` does not advance.
    wakes: u64,
    // Pooled streams lost while the relay may have been mid-handshake, and
    // pooled connections closed stalled (S16h-8b, 8d): epoch scope, so a
    // rebuilt session inherits both.
    strikes: StrikeLedger,
    stalls: StallBook,
    // v41: exposed pooled streams a re-pin's own teardown lost, which the
    // ledger no longer counts (`flow_pool::strike_cause`).
    spared: u64,
    // The provider reached Running (S16i-1): a session at Ready pre-dials.
    running: bool,
}

impl EpochAuth {
    fn mode(&self, now: Instant) -> PoolMode {
        PoolMode {
            strikes: self.strikes.at(now),
            fallback: self.stalls.active(now),
        }
    }

    /// The first instant after `now` at which the mode narrows less.
    fn relaxes(&self, now: Instant) -> Option<Instant> {
        match (self.strikes.expires(now), self.stalls.ends(now)) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

#[derive(Default)]
struct EpochSlots {
    // The latest session limiter of the epoch.
    current: Weak<EstablishLimiter>,
    // Relay sessions a re-pin stranded, each counted until its instant.
    stranded: Vec<(usize, Instant)>,
    // Relay handshakes a re-pin stranded, each counted until its instant.
    stranded_hs: Vec<(usize, Instant)>,
}

impl AuthBackoff {
    fn lock(&self) -> MutexGuard<'_, EpochAuth> {
        self.auth.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn slots(&self) -> MutexGuard<'_, EpochSlots> {
        self.slots.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn register(&self, limiter: &Arc<EstablishLimiter>) {
        self.slots().current = Arc::downgrade(limiter);
    }

    fn current(&self) -> Option<Arc<EstablishLimiter>> {
        self.slots().current.upgrade()
    }

    /// S18: the epoch was re-pinned at `now`. The current session's live
    /// flows and ACK-path establishments are bound to the interface (or
    /// address) that is gone, so the relay keeps counting them until its idle
    /// timeout: they count against every session's live flows for
    /// `STRANDED_HOLD`. Its establishments in progress may still hold relay
    /// handshakes until the relay's deadline: they count against every
    /// session's permits for `STRANDED_HS_HOLD` (S16h). So do its flows
    /// whose Open was written within `STRANDED_HS_HOLD` before `now` and is
    /// still unanswered, each until `STRANDED_HS_HOLD` after its write: the
    /// relay ends a handshake only once it read the client's Finished, which
    /// a lost path may never have carried. A session is counted at most
    /// once. Returns the count of relay sessions.
    pub(crate) fn strand_current(&self, now: Instant) -> usize {
        let Some(limiter) = self.current() else {
            return 0;
        };
        let (held, establishing, written) = {
            let mut state = limiter.state();
            if state.stranded {
                return 0;
            }
            state.stranded = true;
            // Which written flows are unanswered is unknown: the latest
            // writes, the longest counted, as many as are unanswered.
            let written: Vec<Instant> = state
                .writes
                .iter()
                .rev()
                .map(|at| *at + STRANDED_HS_HOLD)
                .filter(|until| *until > now)
                .take(state.unverified)
                .collect();
            (state.live + state.ack, state.active(), written)
        };
        if held > 0 {
            self.slots().stranded.push((held, now + STRANDED_HOLD));
            crate::apple::log_code("relay_sessions_stranded", &format!("count:{held}"));
        }
        let handshakes = establishing + written.len();
        if handshakes > 0 {
            let mut slots = self.slots();
            if establishing > 0 {
                slots
                    .stranded_hs
                    .push((establishing, now + STRANDED_HS_HOLD));
            }
            slots
                .stranded_hs
                .extend(written.into_iter().map(|until| (1, until)));
            drop(slots);
            crate::apple::log_code("relay_handshakes_stranded", &format!("count:{handshakes}"));
        }
        held
    }

    /// The relay handshakes still counted as stranded at `now`, and the
    /// first instant that count drops.
    fn stranded_hs_at(&self, now: Instant) -> (usize, Option<Instant>) {
        let mut slots = self.slots();
        slots.stranded_hs.retain(|(_, until)| *until > now);
        let count = slots.stranded_hs.iter().map(|(count, _)| count).sum();
        let next = slots.stranded_hs.iter().map(|(_, until)| *until).min();
        (count, next)
    }

    /// Test-only: the relay handshakes recorded as stranded, expired ones
    /// included until a read prunes them.
    #[cfg(test)]
    pub(crate) fn stranded_hs_recorded(&self) -> usize {
        self.slots()
            .stranded_hs
            .iter()
            .map(|(count, _)| count)
            .sum()
    }

    /// The relay sessions still counted as stranded at `now`.
    #[cfg(test)]
    fn stranded_at(&self, now: Instant) -> usize {
        self.stranded_until(now).0
    }

    /// The relay sessions still counted as stranded at `now`, and the first
    /// instant that count drops.
    fn stranded_until(&self, now: Instant) -> (usize, Option<Instant>) {
        let mut slots = self.slots();
        slots.stranded.retain(|(_, until)| *until > now);
        let count = slots.stranded.iter().map(|(count, _)| count).sum();
        let next = slots.stranded.iter().map(|(_, until)| *until).min();
        (count, next)
    }

    /// Test-only: the relay sessions counted as stranded now.
    #[cfg(test)]
    pub(crate) fn stranded_now(&self) -> usize {
        self.stranded_at(Instant::now())
    }

    /// S23: the end of the epoch's authentication backoff or sleep pause in
    /// force at `now`, if any (the ACK path's `backoff_at` without flows).
    /// The renewal monitor seals no session for renewal before it.
    pub(crate) fn auth_until(&self, now: Instant) -> Option<Instant> {
        let auth = *self.lock();
        let epoch = auth.until.filter(|until| *until > now);
        let quiet = auth.quiet_until.filter(|until| *until > now);
        epoch.max(quiet)
    }

    /// The Mac is about to sleep: no establishment of the epoch starts until
    /// `resume`, and at most `QUIESCE_MAX` from `now`.
    pub(crate) fn quiesce(&self, now: Instant) {
        self.lock().quiet_until = Some(now + QUIESCE_MAX);
    }

    /// The Mac woke: establishments start again at once, and the wake
    /// generation advances, so no pooled connection dialed before the sleep
    /// takes another stream (S16h).
    pub(crate) fn resume(&self) {
        let was = {
            let mut auth = self.lock();
            auth.wakes = auth.wakes.wrapping_add(1);
            auth.quiet_until.take()
        };
        if was.is_some() {
            if let Some(limiter) = self.current() {
                limiter.changed.notify_waiters();
            }
        }
    }

    fn get(&self) -> EpochAuth {
        *self.lock()
    }

    fn flows(&self) -> MutexGuard<'_, FlowLog> {
        self.flows.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// S16i-1: the provider reached Running. Every session of the epoch
    /// pre-dials one pooled connection from its Ready on (its first at
    /// once, a rebuilt one at its own Ready), and every flow's outcome is
    /// logged for `OPEN_LOG_ALL` from now.
    pub(crate) fn mark_running(&self) {
        self.lock().running = true;
        self.flows().running(Instant::now());
    }

    /// The wakes of this epoch so far.
    pub(crate) fn wake_generation(&self) -> u64 {
        self.lock().wakes
    }

    /// S16h-8b: one more strike-ledger entry at `now`; returns the count.
    fn strike(&self, now: Instant) -> usize {
        self.lock().strikes.record(now)
    }

    /// v41: one more exposed stream a re-pin's teardown lost; returns the
    /// epoch's count.
    fn spare(&self) -> u64 {
        let mut auth = self.lock();
        auth.spared = auth.spared.wrapping_add(1);
        auth.spared
    }

    /// S16h-8d: one stall death at `now`; whether it switched the fallback
    /// on (or renewed it).
    fn stall_death(&self, now: Instant) -> bool {
        self.lock().stalls.death(now)
    }

    /// The epoch's pool mode at `now`.
    fn mode(&self, now: Instant) -> PoolMode {
        self.lock().mode(now)
    }

    /// Test-only: one strike-ledger entry at `at`.
    #[cfg(test)]
    pub(crate) fn strike_at(&self, at: Instant) -> usize {
        self.strike(at)
    }

    /// Test-only: the epoch's pool mode at `now`.
    #[cfg(test)]
    pub(crate) fn mode_at(&self, now: Instant) -> PoolMode {
        self.mode(now)
    }

    fn fail(&self, until: Instant) {
        let mut auth = self.lock();
        auth.until = Some(auth.until.map_or(until, |at| at.max(until)));
        auth.probing = true;
        auth.failures = auth.failures.wrapping_add(1);
    }

    /// An establishment started when `failures` failures were recorded was
    /// answered. One that started before a later failure proves nothing
    /// about that failure, so it leaves probing on.
    fn verified(&self, failures: u64) {
        let mut auth = self.lock();
        if auth.failures == failures {
            auth.probing = false;
        }
    }
}

#[derive(Default)]
struct State {
    ack: usize,
    flow: usize,
    // Flows past their Open request, before its status: no permit.
    unverified: usize,
    // When the latest Open requests were written, oldest first: at most
    // `flow_opens` of them.
    writes: VecDeque<Instant>,
    ack_waiting: usize,
    // Waiting bound re-ACKs, also counted in `ack_waiting`.
    bound_waiting: usize,
    flow_waiting: usize,
    live: usize,
    // S16i-2: flows waiting for a live place, by ticket, first come first
    // (ascending), and the next ticket.
    live_queue: VecDeque<u64>,
    live_next: u64,
    // A re-pin counted this session's relay sessions as stranded.
    stranded: bool,
    // The flows' own backoff after an unanswered Open, as `EpochAuth`.
    flow_until: Option<Instant>,
    flow_probing: bool,
    flow_refusals: u64,
    last_queue_log: Option<Instant>,
    last_live_log: Option<Instant>,
    last_reap_log: Option<Instant>,
    high_water: usize,
    auth_failures: u64,
    queue_logs: u64,
    flow_timeouts: u64,
    live_refusals: u64,
    // The most live flows at once, and flows ended idle (S16i-2).
    live_high_water: usize,
    idle_reaps: u64,
}

impl State {
    fn active(&self) -> usize {
        self.ack + self.flow
    }

    fn count(&mut self, purpose: Purpose) -> &mut usize {
        match purpose {
            Purpose::Ack => &mut self.ack,
            Purpose::Flow => &mut self.flow,
        }
    }

    fn waiting(&mut self, purpose: Purpose) -> &mut usize {
        match purpose {
            Purpose::Ack => &mut self.ack_waiting,
            Purpose::Flow => &mut self.flow_waiting,
        }
    }

    /// Flows establishing or awaiting their Open status.
    fn opening(&self) -> usize {
        self.flow + self.unverified
    }
}

/// One session's establishment limiter. See the module documentation.
pub(crate) struct EstablishLimiter {
    state: Mutex<State>,
    changed: Notify,
    permits: usize,
    reserve: usize,
    backoff: Duration,
    epoch: AuthBackoff,
    // S16i-2: a live place returned or a ticket left (or the cap was
    // bound): live waiters look again, oldest ticket first.
    live_changed: Notify,
    // Tests shorten or narrow these; the live cap is also bound to the
    // signed `max_flows` once the packet config is verified.
    flow_wait: Duration,
    flow_backoff: Duration,
    flow_opens: usize,
    live_flows: AtomicUsize,
    // The relay's inner sessions per peer IP (`RELAY_SESSIONS_PER_IP`):
    // the room a re-pin's stranded sessions narrow (`relay_live_room`).
    relay_sessions: usize,
}

impl EstablishLimiter {
    /// The epoch's next session limiter; a re-pin strands its sessions.
    pub(crate) fn new(epoch: AuthBackoff) -> Arc<Self> {
        let limiter = Self::with_limits(ESTABLISH_PERMITS, ACK_RESERVE, AUTH_BACKOFF, epoch);
        limiter.epoch.register(&limiter);
        limiter
    }

    fn with_limits(
        permits: usize,
        reserve: usize,
        backoff: Duration,
        epoch: AuthBackoff,
    ) -> Arc<Self> {
        assert!(reserve < permits, "flows need at least one permit");
        Arc::new(Self {
            state: Mutex::new(State::default()),
            changed: Notify::new(),
            permits,
            reserve,
            backoff,
            epoch,
            live_changed: Notify::new(),
            flow_wait: MAX_WAIT,
            flow_backoff: FLOW_BACKOFF,
            flow_opens: FLOW_OPENS,
            live_flows: AtomicUsize::new(LIVE_FLOWS),
            relay_sessions: RELAY_SESSIONS_PER_IP,
        })
    }

    /// S16i-2: bind the session's live cap to the signed bundle's
    /// `max_flows` (`live_cap`), once its packet config is verified and
    /// before its engine starts (the limiter is built before that config).
    /// Logged `flow_live_bound cap:<n>`.
    pub(crate) fn bind_signed_max_flows(&self, signed_max_flows: usize) {
        let cap = live_cap(signed_max_flows);
        self.live_flows.store(cap, Ordering::SeqCst);
        crate::apple::log_code("flow_live_bound", &format!("cap:{cap}"));
        self.live_changed.notify_waiters();
    }

    /// The live cap in force before stranded sessions (`live_cap`).
    pub(crate) fn live_cap(&self) -> usize {
        self.live_flows.load(Ordering::SeqCst)
    }

    /// `for_test` whose flows wait at most `flow_wait` for a permit.
    #[cfg(test)]
    pub(crate) fn for_test_with_flow_wait(
        permits: usize,
        reserve: usize,
        backoff: Duration,
        flow_wait: Duration,
    ) -> Arc<Self> {
        let mut limiter = Self::with_limits(permits, reserve, backoff, AuthBackoff::default());
        Self::tune(&mut limiter).flow_wait = flow_wait;
        limiter
    }

    /// A fresh test limiter's limits, to narrow before it is shared. An
    /// epoch's registration holds a weak reference: a tuned limiter is no
    /// longer the epoch's current one (a test registers it again if needed).
    #[cfg(test)]
    pub(crate) fn tune(limiter: &mut Arc<Self>) -> &mut Self {
        {
            let mut slots = limiter.epoch.slots();
            if std::ptr::eq(slots.current.as_ptr(), Arc::as_ptr(limiter)) {
                slots.current = Weak::new();
            }
        }
        Arc::get_mut(limiter).expect("fresh limiter")
    }

    /// Test-only: set the flows' own backoff, live cap and Open cap.
    #[cfg(test)]
    pub(crate) fn set_flow_limits(&mut self, flow_backoff: Duration, opens: usize, live: usize) {
        self.flow_backoff = flow_backoff;
        self.flow_opens = opens;
        *self.live_flows.get_mut() = live;
    }

    /// Test-only: the relay's inner sessions per peer IP, which a re-pin's
    /// stranded sessions narrow (`relay_live_room`).
    #[cfg(test)]
    pub(crate) fn set_relay_sessions(&mut self, relay_sessions: usize) {
        self.relay_sessions = relay_sessions;
    }

    /// The epoch's wake generation (`AuthBackoff::resume`): a pooled
    /// connection dialed under an earlier one is drained (S16h).
    pub(crate) fn wake_generation(&self) -> u64 {
        self.epoch.wake_generation()
    }

    /// The epoch's pool mode now (S16h-8b, 8d): its strike level and
    /// whether the one-stream-per-connection fallback is in force.
    pub(crate) fn pool_mode(&self) -> PoolMode {
        self.epoch.mode(Instant::now())
    }

    /// S16h-8b: a pooled stream was lost while the relay may have been in
    /// its inner handshake (`StreamSlot::take_strike`, or a slot dropped
    /// unjudged so; v41: never by a re-pin's own teardown,
    /// `flow_pool::strike_cause`): one entry of the epoch's strike ledger
    /// (logged `pool_strike count:<n>`). The flows of
    /// every session of the epoch narrow at once (`PoolMode`); the ACK path
    /// keeps its own permits.
    pub(crate) fn strike(&self) -> usize {
        let count = self.epoch.strike(Instant::now());
        crate::apple::log_code("pool_strike", &format!("count:{count}"));
        count
    }

    /// v41: a pooled stream lost while the relay may have been in its inner
    /// handshake, in a session an epoch re-pin superseded: the re-pin's own
    /// teardown, which is no strike (`flow_pool::strike_cause`). Counted in
    /// the epoch and logged `pool_repin_spared count:<n>`, so an installed
    /// window shows what the ledger would have counted before v41.
    pub(crate) fn repin_spared(&self) -> u64 {
        let count = self.epoch.spare();
        crate::apple::log_code("pool_repin_spared", &format!("count:{count}"));
        count
    }

    /// Test-only: the epoch's exposed streams a re-pin spared so far.
    #[cfg(test)]
    pub(crate) fn spared(&self) -> u64 {
        self.epoch.get().spared
    }

    /// S16h-8d: where a pooled connection's driver records its stall death,
    /// in the epoch, which outlives this session.
    pub(crate) fn stall_deaths(&self) -> StallDeaths {
        StallDeaths(self.epoch.clone())
    }

    /// S16i-1: whether the epoch reached Running.
    pub(crate) fn epoch_running(&self) -> bool {
        self.epoch.get().running
    }

    /// Test-only: the epoch reached Running (`AuthBackoff::mark_running`).
    #[cfg(test)]
    pub(crate) fn mark_epoch_running(&self) {
        self.epoch.mark_running();
    }

    /// S16i-1: one flow's open ended with `outcome` after `elapsed`
    /// (`flow_open`, and `flow_refused` for its class).
    pub(crate) fn flow_opened(&self, outcome: Outcome, elapsed: Duration) {
        self.epoch.flows().opened(outcome, elapsed, Instant::now());
    }

    /// S16i-1: the flow pool's state while flows wait for a stream
    /// (`pool_state`, at most once a second).
    pub(crate) fn pool_state(&self, pool: PoolSnapshot) {
        self.epoch.flows().pool_state(pool, Instant::now());
    }

    /// S16i-1: one stable line of the epoch's flow record.
    pub(crate) fn flow_note(&self, event: &str, code: &str) {
        self.epoch.flows().note(event, code);
    }

    /// v34: one stable line of up to four fields in the epoch's flow record
    /// (the stream window's `pool_window`, `pool_rtt` and `flow_bulk`).
    pub(crate) fn flow_fields(&self, event: &str, fields: &[&str]) {
        self.epoch.flows().fields(event, fields);
    }

    /// S16i-1: log the `flow_refused` counts a second held back (`force`:
    /// all of them now, as a session ends).
    pub(crate) fn flush_flow_log(&self, force: bool) {
        self.epoch.flows().flush(Instant::now(), force);
    }

    /// Test-only: every line of the epoch's flow record so far.
    #[cfg(test)]
    pub(crate) fn flow_log_lines(&self) -> Vec<String> {
        self.epoch.flows().lines()
    }

    /// Test-only: the epoch's flows refused in `refusal`'s class so far.
    #[cfg(test)]
    pub(crate) fn refusals(&self, refusal: crate::flow_log::Refusal) -> u64 {
        self.epoch.flows().total(refusal)
    }

    /// Test-only: the epoch's strike-ledger entries counted now.
    #[cfg(test)]
    pub(crate) fn strikes(&self) -> usize {
        self.pool_mode().strikes
    }

    /// Test-only: how often the epoch's fallback was switched on (each a
    /// `pool_fallback` log line).
    #[cfg(test)]
    pub(crate) fn fallbacks(&self) -> u64 {
        self.epoch.get().stalls.switched
    }

    /// How long a flow whose signed connect budget is `budget` may wait.
    pub(crate) fn flow_wait(&self, budget: Duration) -> Duration {
        budget.min(self.flow_wait)
    }

    /// A test limiter with its own limits and backoff.
    #[cfg(test)]
    pub(crate) fn for_test(permits: usize, reserve: usize, backoff: Duration) -> Arc<Self> {
        Self::with_limits(permits, reserve, backoff, AuthBackoff::default())
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The permits in force at `now`, and the first instant they may grow:
    /// all of them, unless re-pins stranded relay handshakes of the epoch
    /// (`STRANDED_HS_HOLD`); then the relay's 32 less the skew and every
    /// stranded one, never more than all, and as few as none: flows take
    /// only those beyond the ACK reserve, and the ACK path waits for one.
    fn permits_at(&self, now: Instant) -> (usize, Option<Instant>) {
        let (stranded, until) = self.epoch.stranded_hs_at(now);
        if stranded == 0 {
            return (self.permits, None);
        }
        let room = (RELAY_HANDSHAKES_PER_IP - HANDSHAKE_SKEW).saturating_sub(stranded);
        (room.min(self.permits), until)
    }

    /// Test-only: the permits in force at `now`.
    #[cfg(test)]
    pub(crate) fn effective_permits(&self, now: Instant) -> usize {
        self.permits_at(now).0
    }

    /// Whether `purpose` may start now under `permits` (`permits_at`),
    /// backoffs aside. A flow never takes the ACK reserve and never goes
    /// before a waiting ACK-path establishment, and flows hold at most
    /// `flow_cap` (the epoch's `PoolMode::flow_permits`); an unbound ACK-path
    /// establishment (a pre-warm, the first ACK) never goes before a waiting
    /// bound re-ACK. While probing, each purpose runs one at a time (a flow
    /// awaiting its Open status included), so a flow probe never holds the
    /// ACK path back.
    fn admits(
        &self,
        state: &State,
        (permits, flow_cap): (usize, usize),
        purpose: Purpose,
        probing: bool,
        bound: bool,
    ) -> bool {
        if state.active() >= permits {
            return false;
        }
        match purpose {
            Purpose::Ack => !(probing && state.ack > 0) && (bound || state.bound_waiting == 0),
            Purpose::Flow => {
                state.flow + self.reserve < permits
                    && state.flow < flow_cap
                    && state.opening() < self.flow_opens
                    && state.ack_waiting == 0
                    && !((probing || state.flow_probing) && state.opening() > 0)
            }
        }
    }

    /// The end of the backoff in force for `purpose` at `now`, if any: the
    /// epoch's for every purpose, the flows' own for flows.
    fn backoff_at(
        &self,
        state: &State,
        auth: EpochAuth,
        purpose: Purpose,
        now: Instant,
    ) -> Option<Instant> {
        let epoch = auth.until.filter(|until| *until > now);
        let quiet = auth.quiet_until.filter(|until| *until > now);
        let flows = match purpose {
            Purpose::Flow => state.flow_until.filter(|until| *until > now),
            Purpose::Ack => None,
        };
        epoch.max(quiet).max(flows)
    }

    /// Take one permit for `purpose`, waiting at most `budget`. A refusal is
    /// a timeout; dropping the wait leaves nothing behind.
    pub(crate) async fn acquire(
        self: &Arc<Self>,
        purpose: Purpose,
        budget: Duration,
    ) -> io::Result<EstablishPermit> {
        self.acquire_as(purpose, budget, false).await
    }

    /// `acquire` of an ACK permit for a bound re-ACK: a fresh dial carrying
    /// the request that renews the lease, ahead of every waiting pre-warm.
    pub(crate) async fn acquire_bound(
        self: &Arc<Self>,
        budget: Duration,
    ) -> io::Result<EstablishPermit> {
        self.acquire_as(Purpose::Ack, budget, true).await
    }

    /// S16i-1: a flow permit for a pool pre-dial, now or never: none while
    /// any backoff (the epoch's, the flows' own after an unanswered Open, or
    /// the pause before sleep) is in force, while establishments or flows
    /// probe one at a time, while any establishment waits for a permit, or
    /// when `acquire` would not admit a flow now. It never queues and never
    /// counts as a flow's timeout.
    pub(crate) fn try_prewarm(self: &Arc<Self>) -> Option<EstablishPermit> {
        let now = Instant::now();
        // Read before the state lock, as `acquire_as` does.
        let (permits, _) = self.permits_at(now);
        let mut state = self.state();
        let auth = self.epoch.get();
        let flow_cap = auth.mode(now).flow_permits().unwrap_or(usize::MAX);
        let held = self.backoff_at(&state, auth, Purpose::Flow, now).is_some()
            || auth.probing
            || state.flow_probing
            || state.flow_waiting + state.ack_waiting > 0;
        if held
            || !self.admits(
                &state,
                (permits, flow_cap),
                Purpose::Flow,
                auth.probing,
                false,
            )
        {
            return None;
        }
        state.flow += 1;
        state.high_water = state.high_water.max(state.active());
        Some(EstablishPermit {
            limiter: self.clone(),
            purpose: Purpose::Flow,
            failures: auth.failures,
            flow_refusals: state.flow_refusals,
            written: false,
        })
    }

    async fn acquire_as(
        self: &Arc<Self>,
        purpose: Purpose,
        budget: Duration,
        bound: bool,
    ) -> io::Result<EstablishPermit> {
        let deadline = Instant::now() + budget.min(MAX_WAIT);
        let mut queued: Option<Queued> = None;
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            // Registered before the state is read, so no release is missed.
            notified.as_mut().enable();
            let wake = {
                let now = Instant::now();
                // Read before the state lock, as `live_flow` reads the
                // stranded sessions.
                let (permits, grows) = self.permits_at(now);
                let mut state = self.state();
                let auth = self.epoch.get();
                let backoff = self.backoff_at(&state, auth, purpose, now);
                let flow_cap = auth.mode(now).flow_permits().unwrap_or(usize::MAX);
                if backoff.is_none()
                    && self.admits(&state, (permits, flow_cap), purpose, auth.probing, bound)
                {
                    let mut yielded = false;
                    if let Some(queued) = queued.as_mut() {
                        *state.waiting(purpose) -= 1;
                        if queued.bound {
                            state.bound_waiting -= 1;
                            yielded = true;
                        }
                        queued.armed = false;
                    }
                    *state.count(purpose) += 1;
                    state.high_water = state.high_water.max(state.active());
                    let permit = EstablishPermit {
                        limiter: self.clone(),
                        purpose,
                        failures: auth.failures,
                        flow_refusals: state.flow_refusals,
                        written: false,
                    };
                    drop(state);
                    // A pre-warm that yielded to this re-ACK may start now.
                    if yielded {
                        self.changed.notify_waiters();
                    }
                    return Ok(permit);
                }
                if now >= deadline {
                    if purpose == Purpose::Flow {
                        state.flow_timeouts += 1;
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "relay establishment queue budget elapsed",
                    ));
                }
                if queued.is_none() {
                    *state.waiting(purpose) += 1;
                    if bound {
                        state.bound_waiting += 1;
                    }
                    queued = Some(Queued {
                        limiter: self.clone(),
                        purpose,
                        bound,
                        armed: true,
                    });
                    self.log_queue(&mut state, now);
                }
                // Stranded handshakes that expire free permits with no
                // release, as an expiring strike ledger or fallback frees
                // flow permits.
                let relaxes = match purpose {
                    Purpose::Flow => auth.relaxes(now),
                    Purpose::Ack => None,
                };
                let grows = match (grows, relaxes) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                };
                let wake = grows.map_or(deadline, |at| at.min(deadline));
                backoff.map_or(wake, |until| until.min(wake))
            };
            tokio::select! {
                () = &mut notified => {}
                () = tokio::time::sleep_until(tokio::time::Instant::from_std(wake)) => {}
            }
        }
    }

    /// Rate-limited `establish_queue depth:<n>`.
    fn log_queue(&self, state: &mut State, now: Instant) {
        if state
            .last_queue_log
            .is_some_and(|at| now.saturating_duration_since(at) < QUEUE_LOG_EVERY)
        {
            return;
        }
        state.last_queue_log = Some(now);
        state.queue_logs += 1;
        let depth = state.ack_waiting + state.flow_waiting;
        crate::apple::log_code("establish_queue", &format!("depth:{depth}"));
    }

    /// The live places at `now`: the live cap, or the relay's room less the
    /// epoch's stranded relay sessions if that is less (`relay_live_room`;
    /// stranded sessions hold no place of the pool or of the signed cap),
    /// and the first instant it may grow with no release (a stranded count
    /// expiring). Read before the state lock: `strand_current` takes them
    /// the other way round.
    fn live_room(&self, now: Instant) -> (usize, Option<Instant>) {
        let (stranded, grows) = self.epoch.stranded_until(now);
        let relay = relay_live_room(self.relay_sessions, stranded);
        (self.live_cap().min(relay), grows)
    }

    /// One refusal at the live cap: counted, logged `flow_live_cap
    /// live:<n> waiting:<n>` at most once a second.
    fn live_refused(state: &mut State) {
        state.live_refusals += 1;
        let now = Instant::now();
        if state
            .last_live_log
            .is_none_or(|at| now.saturating_duration_since(at) >= QUEUE_LOG_EVERY)
        {
            state.last_live_log = Some(now);
            crate::apple::log_fields(
                "flow_live_cap",
                &[
                    &format!("live:{}", state.live),
                    &format!("waiting:{}", state.live_queue.len()),
                ],
            );
        }
    }

    fn take_place(self: &Arc<Self>, state: &mut State) -> LiveFlow {
        state.live += 1;
        state.live_high_water = state.live_high_water.max(state.live);
        LiveFlow(self.clone())
    }

    /// One live flow's place now or never, held for the flow's whole
    /// lifetime; `None` (a refusal at the live cap) when the live cap, less
    /// the epoch's stranded relay sessions, is taken by live flows and by
    /// the flows queued for a place ahead of it, so the relay's per-IP
    /// session cap keeps room for the ACK path. Test-only: a flow waits for
    /// its place (`live_ticket`).
    #[cfg(test)]
    pub(crate) fn live_flow(self: &Arc<Self>) -> Option<LiveFlow> {
        let (room, _) = self.live_room(Instant::now());
        let mut state = self.state();
        if state.live + state.live_queue.len() >= room {
            Self::live_refused(&mut state);
            return None;
        }
        Some(self.take_place(&mut state))
    }

    /// S16i-2: a flow's place in the queue for a live place, first come
    /// first served, left on drop.
    pub(crate) fn live_ticket(self: &Arc<Self>) -> LiveTicket {
        let mut state = self.state();
        let id = state.live_next;
        state.live_next = state.live_next.wrapping_add(1);
        state.live_queue.push_back(id);
        LiveTicket {
            limiter: self.clone(),
            id,
            armed: true,
        }
    }

    /// Whether `ticket` would take a place now: fewer tickets queue ahead
    /// of it than the places left under the cap at `room`.
    fn ticket_admits(state: &State, ticket: &LiveTicket, room: usize) -> bool {
        let ahead = state
            .live_queue
            .binary_search(&ticket.id)
            .unwrap_or(state.live_queue.len());
        ahead < room.saturating_sub(state.live)
    }

    /// S16i-2: wait until `ticket` may take a live place (`take_live`),
    /// until `deadline` at most: a refusal at the live cap then (logged
    /// `flow_live_cap`). Every live place returned, ticket left or cap bound
    /// wakes the queue, so the oldest ticket goes first; a stranded count
    /// expiring is looked at when it expires. A ready ticket holds no
    /// place, but no later ticket overtakes it.
    pub(crate) async fn live_ready(
        &self,
        ticket: &LiveTicket,
        deadline: Instant,
    ) -> io::Result<()> {
        let deadline = deadline.min(Instant::now() + MAX_WAIT);
        loop {
            let notified = self.live_changed.notified();
            tokio::pin!(notified);
            // Registered before the state is read, so no release is missed.
            notified.as_mut().enable();
            let now = Instant::now();
            let (room, grows) = self.live_room(now);
            {
                let mut state = self.state();
                if Self::ticket_admits(&state, ticket, room) {
                    return Ok(());
                }
                if now >= deadline {
                    Self::live_refused(&mut state);
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "relay live flow budget elapsed",
                    ));
                }
            }
            let wake = grows.map_or(deadline, |at| at.min(deadline));
            tokio::select! {
                () = &mut notified => {}
                () = tokio::time::sleep_until(tokio::time::Instant::from_std(wake)) => {}
            }
        }
    }

    /// S16i-2: `ticket`'s live place, if it may take one now
    /// (`live_ready`); the ticket leaves the queue with it. `None` only when
    /// the cap narrowed since (a bind, a stranded count): wait again.
    pub(crate) fn take_live(self: &Arc<Self>, ticket: &mut LiveTicket) -> Option<LiveFlow> {
        let (room, _) = self.live_room(Instant::now());
        let mut state = self.state();
        if !ticket.armed || !Self::ticket_admits(&state, ticket, room) {
            return None;
        }
        if let Ok(at) = state.live_queue.binary_search(&ticket.id) {
            state.live_queue.remove(at);
        }
        ticket.armed = false;
        Some(self.take_place(&mut state))
    }

    /// S16i-2: one live place, waiting first come first served until
    /// `deadline` at most (`live_ticket`, `live_ready`, `take_live`).
    /// Test-only: a flow takes its place with its stream instead.
    #[cfg(test)]
    pub(crate) async fn acquire_live(self: &Arc<Self>, deadline: Instant) -> io::Result<LiveFlow> {
        let mut ticket = self.live_ticket();
        loop {
            self.live_ready(&ticket, deadline).await?;
            if let Some(live) = self.take_live(&mut ticket) {
                return Ok(live);
            }
        }
    }

    fn leave_live_queue(&self, id: u64) {
        {
            let mut state = self.state();
            if let Ok(at) = state.live_queue.binary_search(&id) {
                state.live_queue.remove(at);
            }
        }
        self.live_changed.notify_waiters();
    }

    fn release_live(&self) {
        {
            let mut state = self.state();
            state.live = state.live.saturating_sub(1);
        }
        self.live_changed.notify_waiters();
    }

    /// S16i-2: a flow ended after `idle` with no byte either way (logged
    /// `flow_idle_reap total:<n>` at most once a second).
    pub(crate) fn idle_reaped(&self) {
        let mut state = self.state();
        state.idle_reaps += 1;
        let now = Instant::now();
        if state
            .last_reap_log
            .is_none_or(|at| now.saturating_duration_since(at) >= QUEUE_LOG_EVERY)
        {
            state.last_reap_log = Some(now);
            crate::apple::log_code("flow_idle_reap", &format!("total:{}", state.idle_reaps));
        }
    }

    /// Record an authentication-class failure of a `purpose` establishment:
    /// no establishment of this epoch starts for `backoff` from now, and
    /// then only one per purpose at a time until the relay answers one.
    pub(crate) fn auth_failure(&self, purpose: Purpose) {
        let until = Instant::now() + self.backoff;
        self.epoch.fail(until);
        self.state().auth_failures += 1;
        crate::apple::log_code("relay_auth_failure", purpose.code());
        crate::apple::log_code(
            "establish_backoff",
            &format!("ms:{}", self.backoff.as_millis()),
        );
    }

    /// Record an unanswered Open: no flow of this session starts for
    /// `FLOW_BACKOFF` from now, and then only one at a time until a flow's
    /// status arrives. The ACK path is not held back.
    pub(crate) fn flow_unanswered(&self) {
        {
            let mut state = self.state();
            let until = Instant::now() + self.flow_backoff;
            state.flow_until = Some(state.flow_until.map_or(until, |at| at.max(until)));
            state.flow_probing = true;
            state.flow_refusals = state.flow_refusals.wrapping_add(1);
        }
        crate::apple::log_code("relay_open_unanswered", "flow");
        crate::apple::log_code(
            "flow_backoff",
            &format!("ms:{}", self.flow_backoff.as_millis()),
        );
    }

    /// Record `error`'s failure of a `purpose` establishment by its class.
    pub(crate) fn judge(&self, purpose: Purpose, error: &io::Error) {
        if is_auth_refused(error) {
            self.auth_failure(purpose);
        } else if purpose == Purpose::Flow && is_open_unanswered(error) {
            self.flow_unanswered();
        }
    }

    /// A flow started when `refusals` unanswered Opens were recorded got
    /// its status: flows no longer run one at a time.
    fn flow_verified(&self, refusals: u64) {
        {
            let mut state = self.state();
            if state.flow_refusals == refusals {
                state.flow_probing = false;
            }
        }
        self.changed.notify_waiters();
    }

    fn release(&self, purpose: Purpose, written: bool) {
        {
            let mut state = self.state();
            let count = if written {
                &mut state.unverified
            } else {
                state.count(purpose)
            };
            *count = count.saturating_sub(1);
        }
        self.changed.notify_waiters();
    }

    /// A flow's Open request was written: its permit returns and it counts
    /// as an unanswered Open until its status.
    fn written(&self) {
        {
            let now = Instant::now();
            let mut state = self.state();
            state.flow = state.flow.saturating_sub(1);
            state.unverified += 1;
            // No more flows are unanswered at once (`admits`).
            while state.writes.len() >= self.flow_opens.max(1) {
                state.writes.pop_front();
            }
            state.writes.push_back(now);
        }
        self.changed.notify_waiters();
    }

    fn leave_queue(&self, purpose: Purpose, bound: bool) {
        {
            let mut state = self.state();
            let waiting = state.waiting(purpose);
            *waiting = waiting.saturating_sub(1);
            if bound {
                state.bound_waiting = state.bound_waiting.saturating_sub(1);
            }
        }
        // A leaving ACK waiter may let a flow through.
        self.changed.notify_waiters();
    }

    /// The most permits ever held at once.
    #[cfg(test)]
    pub(crate) fn high_water(&self) -> usize {
        self.state().high_water
    }

    #[cfg(test)]
    pub(crate) fn active(&self) -> (usize, usize) {
        let state = self.state();
        (state.ack, state.flow)
    }

    /// Flows past their Open request awaiting its status.
    #[cfg(test)]
    pub(crate) fn unverified(&self) -> usize {
        self.state().unverified
    }

    /// The Open writes kept for a strand (`strand_current`).
    #[cfg(test)]
    pub(crate) fn writes_kept(&self) -> usize {
        self.state().writes.len()
    }

    /// Flows establishing or waiting for a permit.
    #[cfg(test)]
    pub(crate) fn flows_establishing(&self) -> bool {
        let state = self.state();
        state.flow + state.flow_waiting > 0
    }

    #[cfg(test)]
    pub(crate) fn live(&self) -> usize {
        self.state().live
    }

    #[cfg(test)]
    pub(crate) fn live_refusals(&self) -> u64 {
        self.state().live_refusals
    }

    /// Flows queued for a live place.
    #[cfg(test)]
    pub(crate) fn live_waiting(&self) -> usize {
        self.state().live_queue.len()
    }

    /// The most live flows at once.
    #[cfg(test)]
    pub(crate) fn live_high_water(&self) -> usize {
        self.state().live_high_water
    }

    /// Flows ended idle.
    #[cfg(test)]
    pub(crate) fn idle_reaps(&self) -> u64 {
        self.state().idle_reaps
    }

    #[cfg(test)]
    pub(crate) fn auth_failures(&self) -> u64 {
        self.state().auth_failures
    }

    #[cfg(test)]
    pub(crate) fn flow_refusals(&self) -> u64 {
        self.state().flow_refusals
    }

    #[cfg(test)]
    pub(crate) fn queue_logs(&self) -> u64 {
        self.state().queue_logs
    }

    #[cfg(test)]
    pub(crate) fn flow_timeouts(&self) -> u64 {
        self.state().flow_timeouts
    }

    /// Whether the epoch's backoff is in force now.
    #[cfg(test)]
    pub(crate) fn backing_off(&self) -> bool {
        self.epoch
            .get()
            .until
            .is_some_and(|until| until > Instant::now())
    }

    /// Whether the flows' own backoff is in force now.
    #[cfg(test)]
    pub(crate) fn flows_backing_off(&self) -> bool {
        self.state()
            .flow_until
            .is_some_and(|until| until > Instant::now())
    }

    /// Whether establishments run one per purpose after a failure.
    #[cfg(test)]
    pub(crate) fn probing(&self) -> bool {
        self.epoch.get().probing
    }

    /// Whether flows run one at a time after an unanswered Open.
    #[cfg(test)]
    pub(crate) fn flows_probing(&self) -> bool {
        self.state().flow_probing
    }
}

/// The epoch's record of pooled connections closed stalled (S16h-8d).
pub(crate) struct StallDeaths(AuthBackoff);

impl StallDeaths {
    /// A pooled connection's stall watchdog closed it now. The second
    /// within `STALL_DEATH_WINDOW` switches the epoch's pool to one stream
    /// per connection for `FALLBACK_HOLD` (logged `pool_fallback`).
    pub(crate) fn died(&self) {
        if self.0.stall_death(Instant::now()) {
            crate::apple::log_code("pool_fallback", "streams:1");
        }
    }
}

/// One establishment's permit, returned on drop (a flow's at its Open
/// request, `request_written`, its unanswered-Open count then on drop).
#[must_use = "an establishment permit is held for the whole establishment"]
pub(crate) struct EstablishPermit {
    limiter: Arc<EstablishLimiter>,
    purpose: Purpose,
    failures: u64,
    flow_refusals: u64,
    written: bool,
}

impl fmt::Debug for EstablishPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EstablishPermit")
            .field("purpose", &self.purpose)
            .field("written", &self.written)
            .finish()
    }
}

impl EstablishPermit {
    /// A flow's Open request was written: by then the relay has ended its
    /// handshake, so the permit returns, and the flow counts as an
    /// unanswered Open until its status. Nothing for the ACK path, whose
    /// PolicyAck is the relay's establishment reply.
    pub(crate) fn request_written(&mut self) {
        if self.purpose == Purpose::Flow && !self.written {
            self.written = true;
            self.limiter.written();
        }
    }

    /// Whether this flow's Open request was written (S16h: a flow whose
    /// connection ended before it may be retried once on another).
    pub(crate) fn is_written(&self) -> bool {
        self.written
    }

    /// The relay answered this establishment (its Open status or its
    /// PolicyAck): when it started after the latest authentication failure,
    /// the identity is verified again and establishments no longer run one
    /// at a time; a flow's status lifts the flows' own probing likewise.
    pub(crate) fn succeeded(self) {
        self.limiter.epoch.verified(self.failures);
        if self.purpose == Purpose::Flow {
            self.limiter.flow_verified(self.flow_refusals);
        }
    }
}

impl Drop for EstablishPermit {
    fn drop(&mut self) {
        self.limiter.release(self.purpose, self.written);
    }
}

/// One live flow's place under the session's live cap, returned on drop,
/// which wakes the flows queued for one (S16i-2).
pub(crate) struct LiveFlow(Arc<EstablishLimiter>);

impl Drop for LiveFlow {
    fn drop(&mut self) {
        self.0.release_live();
    }
}

/// A flow's place in the queue for a live place (S16i-2), left on drop
/// unless it took one.
pub(crate) struct LiveTicket {
    limiter: Arc<EstablishLimiter>,
    id: u64,
    armed: bool,
}

impl Drop for LiveTicket {
    fn drop(&mut self) {
        if self.armed {
            self.limiter.leave_live_queue(self.id);
        }
    }
}

/// A waiter's place in the queue, left on drop unless it took a permit.
struct Queued {
    limiter: Arc<EstablishLimiter>,
    purpose: Purpose,
    bound: bool,
    armed: bool,
}

impl Drop for Queued {
    fn drop(&mut self) {
        if self.armed {
            self.limiter.leave_queue(self.purpose, self.bound);
        }
    }
}

#[cfg(test)]
#[path = "establish_limit_tests.rs"]
mod tests;
