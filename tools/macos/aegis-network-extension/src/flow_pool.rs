//! Pooled outer sessions for relay flows (B-06 S16h), part 1: one outer
//! TCP + TLS + H2 connection that carries many flows, each flow one H2
//! stream with its own carrier request, inner mTLS channel and Open, as
//! aegis-server serves them (session/grpc.rs: every accepted stream is its
//! own secure session).
//!
//! A [`PooledConn`] is dialed only through the session's
//! [`EstablishLimiter`]: its TCP, outer TLS and H2 handshake hold one flow
//! permit, so the authentication backoff, probing and the pause before
//! sleep gate pool dials as they gate every other establishment. The permit
//! returns once the connection is ready; an authentication-class failure
//! (a TLS error, or a refused ALPN or ECH) backs the session off. Its socket
//! is bound to the session's relay interface (S16f) like every other relay
//! socket, and only this pooled socket sets TCP_NODELAY (and, S16j-1,
//! TCP_NOTSENT_LOWAT).
//!
//! The connection's H2 driver runs as a [`WorkGate`] task, so a gate stop
//! aborts it; the task's guard is owned by the `PooledConn`, never by a
//! flow. A watch reports how the connection ended: a GOAWAY the relay sent
//! (its error code and last stream ID, read off the wire as it arrives,
//! since h2 reports neither), a transport end (the driver returned or was
//! aborted), or a local close. A carrier stream that the connection's end
//! fails is reported as [`CarrierLost`], whichever of the two h2 and the
//! watch shows first.
//!
//! The outer checks of aegis-client's `connect_h2_from_held` (ALPN, ECH,
//! the carrier's 200 and content type) are rebuilt here with byte-identical
//! texts, so `establish_limit::CARRIER_REFUSALS` judges both alike; a test
//! pins them against aegis-client's own output.
//!
//! Part 2 (S16h-4) is the [`FlowPool`] of one session: which connection a
//! flow's stream goes on, when a connection is dialed, and when it drains
//! or is dead. A flow reserves a [`StreamSlot`] without holding a limiter
//! permit; the slot counts against its connection's handshake cap until the
//! flow's inner connect returns. A dial holds a flow permit only for its own
//! TCP, outer TLS and H2 handshake.
//!
//! Part 3 (S16h-5) bounds a flow's stream against the relay's deadline,
//! which every stream inherits at its accept and which also covers its
//! target dial (aegis-server session/grpc.rs:260, secure.rs:131-278): the
//! 200, the inner mTLS and the Open write run under [`hs_budget`], and the
//! status read under [`status_budget`], both from when the carrier request
//! was sent ([`StreamBounds`]), before which the relay cannot accept the
//! stream, so a 200 however late never moves them; this side gives up (a
//! reset, never a strike, and a timeout, never an unanswered Open) before
//! the relay's deadline fires. A stream error on a connection whose end is
//! recorded within [`CONN_END_GRACE`] is a connection loss, not the
//! stream's own answer ([`ended_within`]); resets before the 200 are counted
//! pool-wide ([`FlowPool::carrier_reset`]). A flow then holds its stream as
//! a [`StreamGuard`] (S16h-6). A stream's bounds are also clamped to its
//! flow's own connect deadline (S16j-1, [`StreamBounds::within`]), so no
//! open succeeds after its application gave up.
//!
//! Part 4 (S16h-8a) defends a connection against a path that froze it. A
//! stall watchdog in its driver task arms when a stream has awaited the
//! relay (its 200, inner handshake or Open status) for [`STALL_QUIET`] with
//! no sign of life, or when a stream's own watchdog fired and it asks for a
//! verdict ([`PooledConn::lost_after_watchdog`]): it sends one PING and,
//! with no sign of life within [`pong_wait`], closes the connection as a
//! local close (its FIN), so its streams are a connection loss (retried
//! once before the Open was written) and no new stream goes on it. Signs of
//! life are inbound bytes, the PONG among them, and TCP ACKs of new bytes
//! ([`TcpAcks`]), so an upload backlog ahead of the PING never closes a
//! healthy connection, and a healthy connection is never pinged on its
//! quiet (logged `pool_stall ping`, `pool_stall close`). A relay that ends
//! a stream after its 200 and before the inner handshake answered (its
//! handshake cap, aegis-server secure.rs:44-48 vs :131) leaves that
//! connection one inner handshake at a time for [`Limits::capacity_pause`]
//! ([`StreamSlot::capacity_refused`]), with no dial in place of the slot it
//! withholds.
//!
//! Part 5 (S16h-8b, 8d) carries what the relay may have counted across
//! sessions. A stream lost with its connection after its 200 and before the
//! relay can have read the Finished of its inner handshake (half an RTT
//! after this side's returned, and until the relay's TCP acknowledged a
//! byte written after it), to a local close (the stall watchdog's among
//! them) or a lost interface, may have run into the relay's deadline as an
//! authentication strike of the public IP (at a relay without R2; since R2
//! aegis-server counts no such timeout, and the ledger stays as the
//! conservative reading of an unknown relay): it is one entry of the
//! epoch's strike ledger ([`StreamSlot::take_strike`], and a slot dropped
//! unjudged so), which expires as aegis-server's count does
//! (`EstablishLimiter::strike`). v41: a loss in a session an epoch re-pin
//! superseded is the re-pin's own teardown and no entry ([`strike_cause`]);
//! its handshakes stay stranded against the relay's 32. From one entry
//! every connection runs one inner handshake at a time and flows hold at
//! most `L1_FLOW_PERMITS`; from two, flows run one handshake at a time and
//! only on a connection whose path proved its life within `PROOF_FRESH`
//! ([`PooledConn::proven_within`]), and one that cannot is closed. Two
//! stall deaths within `STALL_DEATH_WINDOW` switch the pool to one stream
//! per connection for `FALLBACK_HOLD` ([`Limits::under`]), so a frozen
//! 5-tuple ends one flow. A slot reserved before the pool (or, after a
//! capacity refusal, its connection) narrowed runs only once it fits the
//! narrower pool ([`StreamSlot::fits`]).
//!
//! Part 6 (S16i-2) sizes each connection by what the relay advertises: the
//! streams it takes at once are [`stream_cap`] of the relay's
//! SETTINGS_MAX_CONCURRENT_STREAMS, read again at every 200 (a later
//! SETTINGS may lower it), `STREAMS_BEFORE_SETTINGS` before its first; a
//! cap of 0 drains it. aegis-server's 32 keeps today's 30.
//!
//! Part 7 (S16j-1) is the post-connect burst. Waiting flows are served in
//! arrival order ([`FlowPool::reserve`]): each holds a ticket, a free slot
//! goes to the oldest, a new arrival never takes one while older flows
//! wait, and a dial's probe goes to the oldest waiter, not to the flow that
//! dialed (which keeps its place). A flow with no time left to establish
//! ([`establish_floor`], three round trips) leaves as a pool wait before it
//! takes a slot. Once
//! any connection of the pool authenticated a stream
//! (the pool is proven), a Probing connection whose first 200 arrived takes
//! `h_conn` streams at once, as an Open one does; the first connection of
//! an unproven pool, or any after a strike, still probes alone. Connections
//! whose oldest handshake in flight is slow ([`slow_after`]) get a new one
//! only when no other has a free slot. The session pre-dials
//! [`PREWARM_CONNS`] connections at Running. Each pooled connection writes
//! to its socket only while at most [`NOTSENT_LOWAT`] is unsent
//! ([`CountedTcp`]), and its connection window ([`CONN_WINDOW`]) covers
//! every stream it may hold, so an upload backlog delays a new stream's
//! request by at most that much, and unread downloads never hold back its
//! ServerHello.
//!
//! Part 8 (v34) lets a flow's stream grow its own receive window while it
//! is window-limited, from one budget per session
//! ([`crate::stream_window`], [`StreamSlot::open_carrier`]): every
//! round-trip sample the connection takes also feeds its least round trip
//! ([`PooledConn::window`]), which that rule judges by, while its smoothed
//! round trip stays what the timers above use. The connection window
//! covers that budget too. A new flow prefers, among connections as free,
//! one that carries no bulk flow ([`FlowPool::take`]).
use crate::{
    establish_limit::{
        EstablishLimiter, EstablishPermit, PoolMode, Purpose, FALLBACK_FLOW_PERMITS, FLOW_BACKOFF,
        LIVE_FLOWS,
    },
    flow_log::{PoolSnapshot, Refusal},
    held_relay_services::{AbortOnDrop, WorkGate},
    prepared_crypto::{handshake_refusal, Judged, PreparedCryptoInputs},
    provider_session_body::EpochPins,
    relay_socket::{connect_bound, interface_lost, RelayInterface},
    stream_window::{ConnWindow, PoolWindow, WindowPolicy},
};
use aegis_core::{h2_stream::H2Stream, https_bridge, secure_channel::grpc_io::GrpcIo};
use bytes::Bytes;
use std::{
    collections::VecDeque,
    fmt, io,
    net::SocketAddr,
    os::fd::AsRawFd,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex, MutexGuard, PoisonError,
    },
    task::{ready, Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, Interest, ReadBuf},
    sync::{watch, Notify},
    time::Instant,
};
use tokio_rustls::rustls::client::EchStatus;

/// Streams one pooled connection may open before the relay's SETTINGS are
/// known here (its first 200): under aegis-server's 32
/// (session/grpc.rs:209). h2's own default is unlimited until SETTINGS.
pub(crate) const STREAMS_BEFORE_SETTINGS: usize = 30;
/// Streams below the relay's advertised SETTINGS_MAX_CONCURRENT_STREAMS a
/// connection keeps unused ([`stream_cap`]): a stream this side dropped is
/// still counted there until its RST_STREAM is processed.
pub(crate) const STREAM_MARGIN: usize = 2;
/// Streams of one pooled connection at once, at most, whatever the relay
/// advertises: one lost connection ends at most this many flows.
pub(crate) const STREAMS_CAP: usize = 62;

/// S16i-2: the streams a pooled connection takes at once when the relay
/// advertised `advertised` concurrent streams (h2's
/// `current_max_send_streams`, `usize::MAX` when the relay sent no
/// limit): `STREAM_MARGIN` fewer, at most `STREAMS_CAP`. 0 takes no new
/// stream, and the connection drains.
pub(crate) const fn stream_cap(advertised: usize) -> usize {
    let cap = advertised.saturating_sub(STREAM_MARGIN);
    if cap < STREAMS_CAP {
        cap
    } else {
        STREAMS_CAP
    }
}
// aegis-server's 32 keeps the streams taken before its SETTINGS were known;
// 128 and an absent limit take the cap; 2 or fewer drain.
const _: () = assert!(stream_cap(32) == STREAMS_BEFORE_SETTINGS);
const _: () = assert!(stream_cap(16) == 14);
const _: () = assert!(stream_cap(128) == STREAMS_CAP);
const _: () = assert!(stream_cap(usize::MAX) == STREAMS_CAP);
const _: () = assert!(stream_cap(2) == 0 && stream_cap(1) == 0 && stream_cap(0) == 0);
const _: () = assert!(STREAMS_BEFORE_SETTINGS <= STREAMS_CAP);
/// The client's receive window per stream as SETTINGS_INITIAL_WINDOW_SIZE
/// announces it: one relay send buffer (session/grpc.rs:213). Every stream
/// starts with it and every new, idle or slow stream keeps it; v34 grows a
/// window-limited stream's own window beyond it, up to
/// [`crate::stream_window::STREAM_WINDOW_MAX`], from the session's budget
/// ([`crate::stream_window`]).
pub(crate) const STREAM_WINDOW: u32 = 131_072;
/// The client's receive window per connection, shared by its streams
/// (S16j-1): a stream window for each stream it may hold
/// ([`STREAMS_CAP`]) and two more, so the connection window is never what
/// a stream waits for: however many of its streams' readers stopped, each
/// holding its whole stream window unread, every other stream still gets
/// its bytes, a new stream's ServerHello among them. At four stream
/// windows (v21's 512 KiB) four slow readers starved the connection so; at
/// 32 (4 MiB) 32 of the 62 streams a deployed relay's SETTINGS allow would
/// have. v34: and the session's whole growth budget
/// ([`crate::stream_window::GROW_BUDGET`], 7 MiB) beside them, so that
/// still holds when every grown stream of the session is on one
/// connection and stopped reading: 15 MiB, Chrome's connection window
/// (its WINDOW_UPDATE 15663105). It bounds no memory: the stream windows
/// do, at most `STREAM_WINDOW` unread per live flow, about 31 MiB at the
/// live cap (`establish_limit::LIVE_FLOWS_MAX`), draining connections
/// included, and the budget at most 7 MiB more.
pub(crate) const CONN_WINDOW: u32 = 15_728_640;
const _: () = assert!(
    STREAMS_CAP as u64 * (STREAM_WINDOW as u64) + (crate::stream_window::GROW_BUDGET as u64)
        < (CONN_WINDOW as u64)
);
const _: () = assert!(CONN_WINDOW == 15 * 1024 * 1024);
const _: () = assert!(
    CONN_WINDOW == (STREAMS_CAP as u32 + 2) * STREAM_WINDOW + crate::stream_window::GROW_BUDGET
);
// The connection WINDOW_UPDATE after h2's initial 65535 (RFC 9113 6.9.2).
const _: () = assert!(CONN_WINDOW - 65_535 == 15_663_105);
// h2's largest window.
const _: () = assert!(CONN_WINDOW < (1 << 31));
/// What h2 buffers of one stream's sends beyond its flow-control window
/// (S16j-1): one relay stream window, under h2's 400 KiB default, so an
/// upload waits in its own stream's queue.
pub(crate) const SEND_BUFFER: usize = 131_072;
/// The most of a pooled connection's bytes its socket holds unsent before
/// it takes more (S16j-1, [`CountedTcp`]), so an upload backlog waits in
/// h2's per-stream queues, which take turns frame by frame, and a new
/// stream's request, ClientHello and Finished queue behind at most this
/// much of it (and one write) rather than a send buffer grown to megabytes.
/// Each pooled socket also sets it as TCP_NOTSENT_LOWAT, which XNU applies
/// only to its write events, never to a write: a writer that waits for one
/// is woken once no more than this is unsent.
pub(crate) const NOTSENT_LOWAT: libc::c_int = 16_384;
/// macOS netinet/tcp.h `TCP_NOTSENT_LOWAT` (libc 0.2.190 lacks it).
const TCP_NOTSENT_LOWAT: libc::c_int = 0x201;

/// How long a stream error waits for its connection's end to be recorded:
/// h2 fails the streams before the driver task records a transport end.
pub(crate) const CONN_END_GRACE: Duration = Duration::from_millis(250);

/// A pooled flow's 200, inner mTLS and Open write, at most, from its carrier
/// request ([`hs_budget`]). The relay accepts the stream after the request
/// was sent, with at least 5 s less the connection's idle age left of the
/// deadline it inherits; this side's reset reaches the relay well before
/// it, so a stalled inner handshake ends as the client's reset and never as
/// a strike.
pub(crate) const HS_WATCHDOG: Duration = Duration::from_millis(2_500);
/// The handshake deadline after the relay's anchor (the idle age at the
/// request already spent), at most: 1.5 s before the relay's own.
pub(crate) const HS_HORIZON: Duration = Duration::from_millis(3_500);
/// A pooled flow's Open status, at most, from its carrier request
/// ([`status_budget`]).
pub(crate) const STATUS_BUDGET: Duration = Duration::from_secs(4);
/// The status deadline after the relay's anchor (the idle age at the
/// request already spent), at most: before the relay's own fires.
pub(crate) const STATUS_HORIZON: Duration = Duration::from_millis(4_500);
/// What a stream on a live connection whose relay deadline is stale must
/// still have of [`hs_budget`] beyond two round trips (its 200 and its inner
/// handshake) to be sent at all.
pub(crate) const HS_FLOOR: Duration = Duration::from_millis(500);
/// Resets before a 200, pool-wide and with no 200 between them, within
/// `RESET_WINDOW` that count as one unanswered Open.
pub(crate) const RESETS_UNANSWERED: usize = 3;
pub(crate) const RESET_WINDOW: Duration = Duration::from_secs(10);
/// A flow whose connection ended before its Open was written is retried
/// once on another connection when at least two RTTs and this are left.
pub(crate) const RETRY_MARGIN: Duration = Duration::from_millis(500);
/// aegis-server's inner deadline per stream (secure.rs:131-137) and the
/// admission timeout a stream inherits (https_bridge.rs:25-36).
const RELAY_DEADLINE_MS: u128 = 5_000;
const _: () = assert!(HS_WATCHDOG.as_millis() < STATUS_BUDGET.as_millis());
const _: () = assert!(STATUS_BUDGET.as_millis() <= STATUS_HORIZON.as_millis());
const _: () = assert!(STATUS_HORIZON.as_millis() < RELAY_DEADLINE_MS);
// Within `IDLE_REUSE` the whole watchdog applies; the horizon only shortens
// it on a connection idle longer.
const _: () = assert!(HS_HORIZON.as_millis() == HS_WATCHDOG.as_millis() + IDLE_REUSE.as_millis());
const _: () = assert!(HS_HORIZON.as_millis() < STATUS_HORIZON.as_millis());
const _: () = assert!(
    HS_WATCHDOG.as_millis() + IDLE_REUSE.as_millis() + RETRY_MARGIN.as_millis() < RELAY_DEADLINE_MS
);

/// How long a connection may stay without a sign of life (an inbound byte
/// or TCP ACKs of new bytes) while one of its streams awaits the relay (its
/// 200, its inner handshake or its Open status), from that stream's carrier
/// request or the last sign of life, before it is sent one PING: a relay
/// that answers each step within a round trip never sees one.
pub(crate) const STALL_QUIET: Duration = Duration::from_millis(1_500);
/// The least a pinged connection waits for its PONG ([`pong_wait`]).
pub(crate) const PONG_FLOOR: Duration = Duration::from_secs(1);
/// Round trips a pinged connection waits for its PONG, when longer.
pub(crate) const PONG_RTTS: u32 = 3;
/// How often a watched connection's TCP ACKs are read ([`TcpAcks`]): its
/// ACKs are a sign of life seen at most this late.
pub(crate) const ACK_SAMPLE: Duration = Duration::from_millis(250);
const _: () = assert!(ACK_SAMPLE.as_millis() * 4 <= PONG_FLOOR.as_millis());
// A stream awaiting its status on a frozen connection is a connection loss
// before its own status budget gives up on it as a timeout.
const _: () = assert!(STALL_QUIET.as_millis() + PONG_FLOOR.as_millis() < STATUS_BUDGET.as_millis());

/// How long an armed stall watchdog whose connection's smoothed round trip
/// is `srtt` waits for a sign of life (its PONG, another inbound byte or
/// TCP ACKs of new bytes) before it closes: `PONG_FLOOR` or `PONG_RTTS`
/// round trips, whichever is longer.
pub(crate) fn pong_wait(srtt: Duration) -> Duration {
    PONG_FLOOR.max(srtt.saturating_mul(PONG_RTTS))
}

/// How long a pooled flow awaits its Open status from its carrier request,
/// when its connection had idled `idle_age` then: `STATUS_BUDGET`, or less
/// on a connection that idled past `STATUS_HORIZON - STATUS_BUDGET`, so the
/// client gives up before the relay's status-less reset at its deadline.
pub(crate) fn status_budget(idle_age: Duration) -> Duration {
    STATUS_BUDGET.min(STATUS_HORIZON.saturating_sub(idle_age))
}

/// How long a pooled flow's 200, inner mTLS and Open write may take from
/// its carrier request, when its connection had idled `idle_age` then:
/// `HS_WATCHDOG`, or less on a connection that idled past `IDLE_REUSE`.
pub(crate) fn hs_budget(idle_age: Duration) -> Duration {
    HS_WATCHDOG.min(HS_HORIZON.saturating_sub(idle_age))
}

/// The client's own deadlines of one pooled stream, from the instant its
/// carrier request was sent and its connection's idle age then. The relay
/// accepts the stream only after that instant and its deadline runs from
/// the connection's anchor (that instant less the idle age), so a 200 that
/// arrives late never moves either past the relay's own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StreamBounds {
    /// The 200, the inner mTLS and the Open write ([`hs_budget`]).
    pub(crate) handshake: Instant,
    /// The Open status ([`status_budget`]).
    pub(crate) status: Instant,
}

impl StreamBounds {
    pub(crate) fn new(requested: Instant, idle_age: Duration) -> Self {
        Self {
            handshake: requested + hs_budget(idle_age),
            status: requested + status_budget(idle_age),
        }
    }

    /// S16j-1: these bounds, neither past `deadline`, the flow's own connect
    /// deadline: no open completes after its application gave up. Only ever
    /// earlier than the relay's, so a stream given up so is this side's
    /// reset, never a strike.
    pub(crate) fn within(self, deadline: Instant) -> Self {
        Self {
            handshake: self.handshake.min(deadline),
            status: self.status.min(deadline),
        }
    }
}

/// S16j-1: the least a flow must have left of its connect budget to take a
/// stream slot, on a pool whose round trip is `srtt`: its 200, its inner
/// handshake and its Open status, three round trips, and at least
/// `ESTABLISH_MIN` (a pool with no round trip yet). A flow with less cannot
/// open within its budget (its bounds are clamped to it): it leaves as a
/// pool wait rather than take a handshake slot it can only spend as a
/// bound. The diagnosis's `2 x srtt + HS_FLOOR` (840 ms at 170 ms) turned
/// away 8 of the 90-flow burst's flows that open within their budget.
pub(crate) fn establish_floor(srtt: Duration) -> Duration {
    srtt.saturating_mul(ESTABLISH_RTTS).max(ESTABLISH_MIN)
}
/// Round trips an open takes from its carrier request ([`establish_floor`]).
pub(crate) const ESTABLISH_RTTS: u32 = 3;
/// The establish floor of a pool with no round trip yet.
pub(crate) const ESTABLISH_MIN: Duration = Duration::from_millis(250);

/// S16j-1: how old a connection's oldest inner handshake in flight (from its
/// carrier request) may be before the connection counts as slow, at round
/// trip `srtt`: four round trips (a handshake takes two), at least
/// `HS_FLOOR`. A slow connection gets a new handshake only when no other has
/// a free slot.
pub(crate) fn slow_after(srtt: Duration) -> Duration {
    srtt.saturating_mul(4).max(HS_FLOOR)
}

/// Whether the end of a stream's connection fails stream `stream_id`: every
/// end but a graceful GOAWAY whose last stream ID covers it.
pub(crate) fn fails(end: ConnEnd, stream_id: u32) -> bool {
    !matches!(end, ConnEnd::GoAway(h2::Reason::NO_ERROR, last) if stream_id <= last)
}

/// After an error on stream `stream_id`: whether its connection's end that
/// fails it is recorded now or within `grace` (h2 fails the streams before
/// the driver task records a transport end).
pub(crate) async fn ended_within(
    end: &mut watch::Receiver<Option<ConnEnd>>,
    stream_id: u32,
    grace: Duration,
) -> bool {
    let failed = tokio::time::timeout(
        grace,
        end.wait_for(|ended| ended.is_some_and(|ended| fails(ended, stream_id))),
    )
    .await;
    match failed {
        Ok(Ok(_)) => true,
        // The sender lives as long as the `PooledConn`: it was closed.
        Ok(Err(_)) => true,
        Err(_) => false,
    }
}

/// H2 frame type GOAWAY and the frame header length (RFC 9113 4.1, 6.8).
const GOAWAY: u8 = 0x7;
const FRAME_HEADER: usize = 9;

fn refused() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "prepared crypto refused")
}

/// How a pooled connection ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConnEnd {
    /// The relay sent GOAWAY with this error code and last stream ID: no
    /// stream above it was processed. NO_ERROR keeps the streams at or
    /// below it running.
    GoAway(h2::Reason, u32),
    /// The transport ended without a GOAWAY: a reset, an EOF, an H2
    /// protocol error, or the driver task aborted by a gate stop.
    Io,
    /// This side dropped the connection.
    LocalClose,
}

/// A carrier request lost to its connection's end before its response.
/// `unprocessed`: the relay never processed this stream (it was never sent,
/// or the relay's GOAWAY named a lower last stream ID).
#[derive(Debug)]
pub(crate) struct CarrierLost {
    pub(crate) end: ConnEnd,
    pub(crate) unprocessed: bool,
}

impl fmt::Display for CarrierLost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("pooled connection ended before carrier response")
    }
}

impl std::error::Error for CarrierLost {}

type EndSender = Arc<watch::Sender<Option<ConnEnd>>>;

/// Record `end` unless an end is already recorded; a later GOAWAY replaces
/// an earlier one (a graceful GOAWAY is followed by the final one).
fn record(sender: &watch::Sender<Option<ConnEnd>>, end: ConnEnd) {
    sender.send_if_modified(|current| match (*current, end) {
        (None, _) | (Some(ConnEnd::GoAway(..)), ConnEnd::GoAway(..)) => {
            *current = Some(end);
            true
        }
        _ => false,
    });
}

/// Records a transport end when the driver task ends, however it ends: its
/// connection returned, or a gate stop or the `PooledConn` aborted it. An
/// end recorded earlier (a GOAWAY or a local close) is kept.
struct EndOnDrop(EndSender);

impl Drop for EndOnDrop {
    fn drop(&mut self) {
        record(&self.0, ConnEnd::Io);
    }
}

/// What a pooled connection's stall watchdog reads: its last sign of life
/// (an inbound byte, or TCP ACKs of new bytes: [`TcpAcks`]), its streams
/// awaiting the relay and since when, the latest verdict a stream asked for
/// after its own watchdog, and its smoothed round trip.
pub(crate) struct Liveness {
    base: Instant,
    // The last sign of life, in microseconds after `base`.
    alive_us: AtomicU64,
    // Streams awaiting the relay, and since when the count is above zero.
    awaiting: Mutex<(usize, Instant)>,
    // Smoothed round trip in microseconds: the outer TLS handshake (one
    // round trip in TLS 1.3), then each carrier request to its response and
    // each PING to its PONG.
    srtt_us: AtomicU64,
    // The latest verdict asked for ([`PooledConn::lost_after_watchdog`]), in
    // microseconds after `base` (0: none).
    probe_us: AtomicU64,
    // A sign of life wakes `changed` while the watchdog is armed or a
    // stream awaits its verdict.
    armed: AtomicBool,
    verdicts: AtomicUsize,
    // PINGs sent.
    pings: AtomicUsize,
    // The last proof of the path's life both ways (S16h-8b): a PONG, or the
    // outer TLS handshake, in microseconds after `base` (0: none).
    proof_us: AtomicU64,
    // The latest PING a stream asked for to prove the path (0: none).
    ping_want_us: AtomicU64,
    // The driver ended on an error of a lost interface (`interface_lost`).
    interface_lost: AtomicBool,
    // Bytes the outer TCP socket accepted ([`CountedTcp`]).
    written: AtomicU64,
    // S16j-1: its send buffer's bytes (SO_NWRITE) as the stall watchdog
    // last read them.
    queued: AtomicU64,
    // The most of them the relay's TCP acknowledged, as its stall watchdog
    // last read them ([`TcpAcks`]).
    acked: AtomicU64,
    // Test-only: no byte written after this is acknowledged, as on a path
    // that froze then (u64::MAX: none). A loopback kernel acknowledges
    // whatever a userspace freeze holds.
    #[cfg(test)]
    acks_cap: AtomicU64,
    // Test-only: the next inner handshake that returns authenticated sets
    // `acks_cap` to the bytes written then, as a path that froze as it
    // returned.
    #[cfg(test)]
    freeze_at_handshake: AtomicBool,
    // S16m: the outer socket while its driver task holds the connection
    // (`SocketHeld`), for a TCP ACK read on demand ([`Liveness::acked_now`]);
    // None before the task first ran and once it lets the socket go. Read
    // only under this lock, which the task takes before the socket closes.
    socket: Mutex<Option<std::os::fd::RawFd>>,
    changed: Notify,
    // v34: every round-trip sample also goes here, for the stream window's
    // minimum round trip and its telemetry; `srtt_us` is computed exactly
    // as before.
    window: Arc<ConnWindow>,
}

impl Liveness {
    pub(crate) fn new(srtt: Duration) -> Self {
        let base = Instant::now();
        Self {
            base,
            alive_us: AtomicU64::new(0),
            awaiting: Mutex::new((0, base)),
            srtt_us: AtomicU64::new(micros(srtt)),
            probe_us: AtomicU64::new(0),
            armed: AtomicBool::new(false),
            verdicts: AtomicUsize::new(0),
            pings: AtomicUsize::new(0),
            proof_us: AtomicU64::new(0),
            ping_want_us: AtomicU64::new(0),
            interface_lost: AtomicBool::new(false),
            written: AtomicU64::new(0),
            queued: AtomicU64::new(0),
            acked: AtomicU64::new(0),
            #[cfg(test)]
            acks_cap: AtomicU64::new(u64::MAX),
            #[cfg(test)]
            freeze_at_handshake: AtomicBool::new(false),
            socket: Mutex::new(None),
            changed: Notify::new(),
            window: Arc::new(ConnWindow::new()),
        }
    }

    /// S16m: the bytes of the outer socket the relay's TCP acknowledged,
    /// read now (`acked_bytes`) rather than at the stall watchdog's next
    /// sample; None while no driver holds the socket or it is unreadable.
    fn acked_now(&self) -> Option<u64> {
        let socket = self.socket.lock().unwrap_or_else(PoisonError::into_inner);
        let fd = (*socket)?;
        let acked = acked_bytes(fd, self)?;
        self.acked.fetch_max(acked, Ordering::SeqCst);
        Some(acked)
    }

    fn awaiting(&self) -> MutexGuard<'_, (usize, Instant)> {
        self.awaiting.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn since_base(&self, at: Instant) -> u64 {
        micros(at.saturating_duration_since(self.base))
    }

    /// A sign of life now: inbound bytes, or TCP ACKs of new bytes.
    fn alive(&self) {
        self.alive_us
            .fetch_max(self.since_base(Instant::now()), Ordering::SeqCst);
        if self.armed.load(Ordering::SeqCst) || self.verdicts.load(Ordering::SeqCst) > 0 {
            self.changed.notify_waiters();
        }
    }

    fn last_alive(&self) -> Instant {
        self.base + Duration::from_micros(self.alive_us.load(Ordering::SeqCst))
    }

    /// Since when a stream has awaited the relay (none awaits: None).
    fn awaiting_since(&self) -> Option<Instant> {
        let (count, since) = *self.awaiting();
        (count > 0).then_some(since)
    }

    /// The latest verdict a stream asked for (none: None).
    fn probe_at(&self) -> Option<Instant> {
        match self.probe_us.load(Ordering::SeqCst) {
            0 => None,
            us => Some(self.base + Duration::from_micros(us)),
        }
    }

    fn srtt(&self) -> Duration {
        Duration::from_micros(self.srtt_us.load(Ordering::Relaxed))
    }

    /// The path proved its life both ways now: a PONG arrived, or the outer
    /// TLS handshake returned.
    fn proven(&self) {
        self.proof_us
            .fetch_max(self.since_base(Instant::now()).max(1), Ordering::SeqCst);
        self.changed.notify_waiters();
    }

    /// The last proof of life (none: None).
    fn last_proof(&self) -> Option<Instant> {
        match self.proof_us.load(Ordering::SeqCst) {
            0 => None,
            us => Some(self.base + Duration::from_micros(us)),
        }
    }

    /// A stream asks for one PING at `at` to prove the path.
    fn want_ping(&self, at: Instant) {
        self.ping_want_us
            .fetch_max(self.since_base(at).max(1), Ordering::SeqCst);
        self.changed.notify_waiters();
    }

    /// The first round trip: the outer TLS handshake.
    fn seed_rtt(&self, srtt: Duration) {
        self.srtt_us.store(micros(srtt), Ordering::Relaxed);
        self.window.sample(srtt, srtt);
    }

    fn sample_rtt(&self, sample: Duration) {
        let us = micros(sample);
        let _ = self
            .srtt_us
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |srtt| {
                Some((srtt.saturating_mul(7).saturating_add(us)) / 8)
            });
        // v34: the same sample, unsmoothed, for the stream window.
        self.window.sample(sample, self.srtt());
    }
}

/// One stream's wait for the relay, from its carrier request until its Open
/// status ([`StreamSlot::sent`], [`StreamSlot::answered`]), or (S16l) one
/// PolicyAck request on the session's ACK connection until its ACK
/// ([`PooledConn::awaiting`]): while any is held, the connection's quiet is
/// watched.
pub(crate) struct Awaiting(Arc<Liveness>);

impl Awaiting {
    fn start(live: &Arc<Liveness>) -> Self {
        {
            let mut awaiting = live.awaiting();
            if awaiting.0 == 0 {
                awaiting.1 = Instant::now();
            }
            awaiting.0 += 1;
        }
        live.changed.notify_waiters();
        Self(live.clone())
    }
}

impl Drop for Awaiting {
    fn drop(&mut self) {
        {
            let mut awaiting = self.0.awaiting();
            awaiting.0 = awaiting.0.saturating_sub(1);
        }
        self.0.changed.notify_waiters();
    }
}

/// A stream awaiting its connection's verdict: a sign of life wakes it.
struct Verdict<'a>(&'a Liveness);

impl<'a> Verdict<'a> {
    fn ask(live: &'a Liveness, at: Instant) -> Self {
        live.verdicts.fetch_add(1, Ordering::SeqCst);
        live.probe_us
            .fetch_max(live.since_base(at).max(1), Ordering::SeqCst);
        live.changed.notify_waiters();
        Self(live)
    }
}

impl Drop for Verdict<'_> {
    fn drop(&mut self) {
        self.0.verdicts.fetch_sub(1, Ordering::SeqCst);
    }
}

/// What the stall watchdog does next ([`StallClock::next`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stall {
    /// Nothing awaits the relay and no verdict is asked for.
    Idle,
    /// Look again at this instant, or on a change.
    Until(Instant),
    /// Suspect the connection now: one PING unless one is unanswered, and
    /// close unless a sign of life follows within the PONG wait.
    Arm,
    /// No sign of life since it was armed, for the PONG wait: close.
    Close,
}

/// The stall watchdog's decisions (S16h-8a), apart from its I/O.
#[derive(Debug, Default)]
struct StallClock {
    // Armed then, closing at the second instant.
    armed: Option<(Instant, Instant)>,
    // The latest verdict asked for that was handled.
    probe_seen: Option<Instant>,
}

impl StallClock {
    /// The decision at `now`: `since` the earliest stream awaiting the
    /// relay, `alive` the last sign of life, `probe` the latest verdict a
    /// stream asked for after its own watchdog, `wait` the PONG wait. Armed,
    /// any sign of life disarms it; else it closes at its end. A verdict
    /// asked for with no sign of life since arms it at once; else a stream
    /// awaiting the relay arms it after `STALL_QUIET` with no sign of life.
    fn next(
        &mut self,
        now: Instant,
        since: Option<Instant>,
        alive: Instant,
        probe: Option<Instant>,
        wait: Duration,
    ) -> Stall {
        if let Some((from, close_at)) = self.armed {
            if alive <= from {
                return if now >= close_at {
                    Stall::Close
                } else {
                    Stall::Until(close_at)
                };
            }
            self.armed = None;
        }
        if let Some(probe) = probe.filter(|probe| self.probe_seen.is_none_or(|seen| *probe > seen))
        {
            self.probe_seen = Some(probe);
            if alive < probe {
                self.armed = Some((now, now + wait));
                return Stall::Arm;
            }
        }
        let Some(since) = since else {
            return Stall::Idle;
        };
        let due = since.max(alive) + STALL_QUIET;
        if now < due {
            return Stall::Until(due);
        }
        self.armed = Some((now, now + wait));
        Stall::Arm
    }

    fn is_armed(&self) -> bool {
        self.armed.is_some()
    }
}

/// The outer TCP stream, counting the bytes its socket accepted in its
/// connection's [`Liveness`] ([`TcpAcks`]). S16j-1: it takes no write while
/// its socket holds more than [`NOTSENT_LOWAT`] unsent bytes
/// ([`CountedTcp::poll_backlog`]).
struct CountedTcp {
    tcp: tokio::net::TcpStream,
    live: Arc<Liveness>,
}

/// S16j-1: the bytes of the socket `fd`'s send buffer that its windows do
/// not let fly yet: all of them (`tcpi_snd_sbbytes`, in flight included)
/// less the lesser of its congestion and send windows (TCP_CONNECTION_INFO).
/// Never more than those unsent, as no more than those windows are ever in
/// flight. None: unreadable.
fn unsent(fd: std::os::fd::RawFd) -> Option<u64> {
    // SAFETY: tcp_connection_info is plain integers, valid all zero.
    let mut info: libc::tcp_connection_info = unsafe { std::mem::zeroed() };
    let mut length =
        libc::socklen_t::try_from(std::mem::size_of::<libc::tcp_connection_info>()).ok()?;
    // SAFETY: `fd` is an open socket (its caller owns it), and the value and
    // length describe one tcp_connection_info.
    let read = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_CONNECTION_INFO,
            std::ptr::addr_of_mut!(info).cast(),
            &mut length,
        )
    };
    if read != 0 {
        return None;
    }
    let flying = info.tcpi_snd_cwnd.min(info.tcpi_snd_wnd);
    Some(u64::from(info.tcpi_snd_sbbytes.saturating_sub(flying)))
}

impl CountedTcp {
    /// S16j-1: ready for a write once its socket holds at most
    /// [`NOTSENT_LOWAT`] unsent bytes ([`unsent`]). XNU applies
    /// TCP_NOTSENT_LOWAT to its write events only and takes a write while
    /// the send buffer has room, and tokio writes for as long as the last
    /// write event stands, so h2 alone would fill the buffer. Past the mark
    /// the write readiness is cleared (unless a newer event arrived), and
    /// the kernel's next write event, due once no more than the mark is
    /// unsent, wakes the writer.
    fn poll_backlog(&self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let fd = self.tcp.as_raw_fd();
        let mark = u64::try_from(NOTSENT_LOWAT).unwrap_or(0);
        loop {
            ready!(self.tcp.poll_write_ready(context))?;
            let backlog = self.tcp.try_io(Interest::WRITABLE, || match unsent(fd) {
                Some(unsent) if unsent > mark => Err(io::ErrorKind::WouldBlock.into()),
                _ => Ok(()),
            });
            match backlog {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                done => return Poll::Ready(done),
            }
        }
    }

    fn count(&self, written: &Poll<io::Result<usize>>) {
        if let Poll::Ready(Ok(written)) = written {
            self.live.written.fetch_add(
                u64::try_from(*written).unwrap_or(u64::MAX),
                Ordering::SeqCst,
            );
        }
    }
}

impl AsyncRead for CountedTcp {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tcp).poll_read(context, buf)
    }
}

impl AsyncWrite for CountedTcp {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.poll_backlog(context))?;
        let written = Pin::new(&mut self.tcp).poll_write(context, buf);
        self.count(&written);
        written
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        ready!(self.poll_backlog(context))?;
        let written = Pin::new(&mut self.tcp).poll_write_vectored(context, bufs);
        self.count(&written);
        written
    }

    fn is_write_vectored(&self) -> bool {
        self.tcp.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tcp).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tcp).poll_shutdown(context)
    }
}

/// The outer TCP connection's acknowledged bytes: those its socket accepted
/// ([`CountedTcp`]) less those still in its send buffer (SO_NWRITE). They
/// grow only as the relay's TCP ACKs of new bytes arrive, so the path
/// carries bytes both ways however long an upload backlog queues ahead of
/// a PING; a frozen path's never grow.
struct TcpAcks {
    // Valid while the driver task holds the connection, which owns the
    // socket: a `TcpAcks` lives in that task and is read only there.
    fd: std::os::fd::RawFd,
    live: Arc<Liveness>,
    acked: u64,
}

impl TcpAcks {
    fn new(fd: std::os::fd::RawFd, live: Arc<Liveness>) -> Self {
        let mut acks = Self { fd, live, acked: 0 };
        acks.acked = acks.read().unwrap_or(0);
        acks.live.acked.fetch_max(acks.acked, Ordering::SeqCst);
        acks
    }

    fn read(&self) -> Option<u64> {
        acked_bytes(self.fd, &self.live)
    }

    /// Whether new bytes were acknowledged since the last look.
    fn progressed(&mut self) -> bool {
        match self.read() {
            Some(acked) if acked > self.acked => {
                self.acked = acked;
                self.live.acked.fetch_max(acked, Ordering::SeqCst);
                true
            }
            _ => false,
        }
    }
}

/// The bytes of socket `fd` (its connection's `live`) the relay's TCP
/// acknowledged: those it accepted ([`CountedTcp`]) less those still in its
/// send buffer (SO_NWRITE), which also sets `live.queued`. `fd` must be the
/// connection's open socket: read in its driver task ([`TcpAcks`]) or under
/// `Liveness::socket` while that task holds it.
fn acked_bytes(fd: std::os::fd::RawFd, live: &Liveness) -> Option<u64> {
    // Written first: a write in between only understates the ACKs.
    let written = live.written.load(Ordering::SeqCst);
    let mut unacked: libc::c_int = 0;
    let mut length = libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>()).ok()?;
    // SAFETY: `fd` is the connection's open socket (see above), and the
    // value and length describe one c_int.
    let read = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_NWRITE,
            std::ptr::addr_of_mut!(unacked).cast(),
            &mut length,
        )
    };
    if read == 0 {
        live.queued
            .store(u64::try_from(unacked).unwrap_or(0), Ordering::Relaxed);
    }
    let acked = written.saturating_sub(u64::try_from(unacked).unwrap_or(0));
    #[cfg(test)]
    let acked = acked.min(live.acks_cap.load(Ordering::SeqCst));
    (read == 0).then_some(acked)
}

/// S16m: the outer socket as its driver task holds it, published in
/// `Liveness::socket` for TCP ACK reads on demand; dropped (under that
/// lock) before the task lets the connection and its socket go.
struct SocketHeld(Arc<Liveness>);

impl SocketHeld {
    fn new(live: Arc<Liveness>, fd: std::os::fd::RawFd) -> Self {
        *live.socket.lock().unwrap_or_else(PoisonError::into_inner) = Some(fd);
        Self(live)
    }
}

impl Drop for SocketHeld {
    fn drop(&mut self) {
        *self.0.socket.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }
}

/// A pooled connection's stall watchdog (S16h-8a). A stream awaiting the
/// relay with no sign of life for `STALL_QUIET`, or a stream whose own
/// watchdog fired asking for a verdict, arms it: it sends one PING (none
/// while one is unanswered) and returns, so its driver closes the
/// connection, unless a sign of life follows within [`pong_wait`]. Signs of
/// life are inbound bytes (the PONG among them) and TCP ACKs of new bytes,
/// read at each look and at least every [`ACK_SAMPLE`] while it watches
/// ([`TcpAcks`]): a healthy connection whose uplink is busy with a backlog
/// is never pinged on its quiet and never closed. A
/// PONG is a round-trip sample and a proof of life ([`Liveness::proven`]).
/// A stream at strike level 2 that asks for a proof
/// ([`PooledConn::proven_within`]) gets one PING too, unless one is
/// unanswered (logged `pool_proof ping`); its question also asks for a
/// verdict, so with no sign of life within the PONG wait the connection
/// closes. A PING the ending connection refuses leaves it pending: the
/// driver records that end itself.
async fn stall_watch(
    live: Arc<Liveness>,
    mut pings: h2::PingPong,
    mut acks: TcpAcks,
    collapse: Option<Collapse>,
) {
    let mut clock = StallClock::default();
    // When the unanswered PING was sent.
    let mut unanswered: Option<Instant> = None;
    // The latest proof PING asked for that was handled.
    let mut want_seen = 0u64;
    // Whether the last look watched, so its TCP ACKs were read at least
    // every ACK_SAMPLE since. ACKs found after an unwatched quiet are of
    // unknown age, perhaps from before the path froze: a baseline, never a
    // sign of life, so a verdict or proof asked after the quiet still arms.
    let mut watched = false;
    loop {
        let changed = live.changed.notified();
        tokio::pin!(changed);
        // Registered before the state is read, so no change is missed.
        changed.as_mut().enable();
        if acks.progressed() && watched {
            live.alive();
        }
        let now = Instant::now();
        let next = clock.next(
            now,
            live.awaiting_since(),
            live.last_alive(),
            live.probe_at(),
            pong_wait(live.srtt()),
        );
        live.armed.store(clock.is_armed(), Ordering::SeqCst);
        watched = matches!(next, Stall::Arm | Stall::Until(_));
        if next == Stall::Close {
            crate::apple::log_code("pool_stall", "close");
            return;
        }
        let want = live.ping_want_us.load(Ordering::SeqCst);
        if want > want_seen {
            want_seen = want;
            // An unanswered PING's PONG proves the path as well.
            if unanswered.is_none() {
                if pings.send_ping(h2::Ping::opaque()).is_err() {
                    std::future::pending::<()>().await;
                }
                unanswered = Some(now);
                live.pings.fetch_add(1, Ordering::Relaxed);
                crate::apple::log_code("pool_proof", "ping");
            }
        }
        let until = match next {
            Stall::Arm => {
                if unanswered.is_none() {
                    if pings.send_ping(h2::Ping::opaque()).is_err() {
                        std::future::pending::<()>().await;
                    }
                    unanswered = Some(now);
                    live.pings.fetch_add(1, Ordering::Relaxed);
                    crate::apple::log_code("pool_stall", "ping");
                }
                continue;
            }
            // Watched: its TCP ACKs are read at least every ACK_SAMPLE.
            Stall::Until(at) => Some(at.min(now + ACK_SAMPLE)),
            Stall::Idle | Stall::Close => None,
        };
        let pong = async {
            match unanswered {
                Some(_) => std::future::poll_fn(|context| pings.poll_pong(context)).await,
                None => std::future::pending().await,
            }
        };
        let wake = async {
            match until {
                Some(at) => tokio::time::sleep_until(at).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            () = &mut changed => {}
            () = wake => {}
            pong = pong => match pong {
                Ok(_) => {
                    if let Some(sent) = unanswered.take() {
                        let rtt = sent.elapsed();
                        live.sample_rtt(rtt);
                        // v40: a PONG this slow is the session pin's
                        // throughput collapse (once per session).
                        if let Some(collapse) = &collapse {
                            collapse.observe(rtt);
                        }
                    }
                    live.proven();
                }
                Err(_) => std::future::pending::<()>().await,
            },
        }
    }
}

/// v40 (CP-D3 M1): the session pin's PING liveness thresholds, when its
/// profile's failover policy enables liveness: a PONG at least `rtt` slow
/// is a throughput collapse of that pin.
pub(crate) struct Collapse {
    ticket: Arc<crate::carrier_failover::CarrierTicket>,
    rtt: Duration,
}

impl Collapse {
    fn of(crypto: &PreparedCryptoInputs) -> Option<Self> {
        let ticket = crypto.carrier_ticket()?.clone();
        let rtt = ticket.collapse_rtt()?;
        Some(Self { ticket, rtt })
    }

    fn observe(&self, rtt: Duration) {
        if rtt >= self.rtt {
            self.ticket
                .degraded(aegis_core::brain::carrier_failover::CarrierSignal::ThroughputCollapse);
        }
    }
}

/// Whether the relay never processed `stream_id` (None: never sent) when
/// its connection ended with `end`.
fn lost(end: ConnEnd, stream_id: Option<u32>) -> CarrierLost {
    CarrierLost {
        end,
        unprocessed: match (end, stream_id) {
            (_, None) => true,
            (ConnEnd::GoAway(_, last), Some(id)) => id > last,
            _ => false,
        },
    }
}

/// An h2 error on a carrier stream: [`CarrierLost`] when the connection has
/// ended or its end is recorded within [`CONN_END_GRACE`], otherwise the h2
/// error. A RST_STREAM is the stream's own answer and stays as h2 gave it.
async fn lost_or(
    end: &mut watch::Receiver<Option<ConnEnd>>,
    error: h2::Error,
    stream_id: Option<u32>,
) -> anyhow::Error {
    if error.is_reset() {
        return error.into();
    }
    let ended = match tokio::time::timeout(CONN_END_GRACE, end.wait_for(Option::is_some)).await {
        Ok(Ok(ended)) => *ended,
        // The sender lives as long as the `PooledConn`.
        Ok(Err(_)) => Some(ConnEnd::LocalClose),
        Err(_) => None,
    };
    match ended {
        Some(ended) => lost(ended, stream_id).into(),
        None => error.into(),
    }
}

/// One authenticated carrier stream on a pooled connection, answered 200.
/// Its bounds run from its request ([`StreamBounds`]), never from its 200.
#[must_use = "a carrier stream resets when dropped"]
pub(crate) struct PooledCarrier {
    pub(crate) io: crate::carrier_io::OwnedCarrier,
    pub(crate) stream_id: u32,
}

/// One pooled outer TCP + TLS + H2 connection. Dropping it closes the
/// connection: its driver task is aborted and every stream on it ends.
pub(crate) struct PooledConn {
    send: h2::client::SendRequest<Bytes>,
    end: watch::Receiver<Option<ConnEnd>>,
    end_sender: EndSender,
    // When its TCP connect started: its idle age before any stream.
    connect_started: Instant,
    // Its inbound bytes, awaiting streams and round trip (S16h-8a).
    live: Arc<Liveness>,
    // S16i-2: the streams it takes at once ([`stream_cap`] of the relay's
    // SETTINGS as of its latest 200; `STREAMS_BEFORE_SETTINGS` until then).
    stream_cap: AtomicUsize,
    // S16j-1: a carrier on it was answered 200 (`Entry::slots`).
    answered: AtomicBool,
    pin_gen: u64,
    wake_gen: u64,
    // Test-only: its socket, open while its driver holds the connection.
    #[cfg(test)]
    fd: std::os::fd::RawFd,
    // Last: aborts the driver after `Drop` recorded the local close.
    _driver: AbortOnDrop,
}

impl Drop for PooledConn {
    fn drop(&mut self) {
        record(&self.end_sender, ConnEnd::LocalClose);
    }
}

impl PooledConn {
    /// Dial one pooled connection to the session's verified `peer` over a
    /// socket bound to `interface`. It waits for a flow permit of `limiter`
    /// at most the signed connect budget, then runs TCP, outer TLS and the
    /// H2 handshake under that same budget; the permit returns once the
    /// connection is ready or failed, after its failure was judged. The
    /// driver runs as a `gate` task. `pin_gen` is the epoch's pin
    /// generation it was dialed under. Its wake generation is read once the
    /// permit is granted, right before its TCP connect: a dial that waited
    /// out the pause before sleep connects after the wake and is current.
    pub(crate) async fn dial(
        peer: SocketAddr,
        interface: &RelayInterface,
        crypto: &PreparedCryptoInputs,
        limiter: &Arc<EstablishLimiter>,
        gate: &WorkGate,
        pin_gen: u64,
    ) -> io::Result<Self> {
        let permit = Self::dial_permit(peer, crypto, limiter).await?;
        Self::dial_with(peer, interface, crypto, limiter, gate, pin_gen, permit).await
    }

    /// The flow permit a pooled dial waits for, at most the signed connect
    /// budget. Refused as a permit wait ([`is_permit_wait`], S16i-1): no
    /// SYN was sent.
    pub(crate) async fn dial_permit(
        peer: SocketAddr,
        crypto: &PreparedCryptoInputs,
        limiter: &Arc<EstablishLimiter>,
    ) -> io::Result<EstablishPermit> {
        let budget = dial_budget(peer, crypto)?;
        limiter
            .acquire(Purpose::Flow, limiter.flow_wait(budget))
            .await
            .map_err(|_| permit_wait())
    }

    /// `dial` under a flow `permit` already granted (S16i-1: a pre-dial's,
    /// `EstablishLimiter::try_prewarm`), which it returns once the
    /// connection is ready or failed, after its failure was judged.
    pub(crate) async fn dial_with(
        peer: SocketAddr,
        interface: &RelayInterface,
        crypto: &PreparedCryptoInputs,
        limiter: &Arc<EstablishLimiter>,
        gate: &WorkGate,
        pin_gen: u64,
        permit: EstablishPermit,
    ) -> io::Result<Self> {
        let dialed = Self::dial_as(
            Purpose::Flow,
            peer,
            interface,
            crypto,
            limiter,
            gate,
            pin_gen,
        )
        .await;
        // Judged before the permit returns, so no probe-blocked waiter
        // starts ahead of a backoff.
        drop(permit);
        dialed
    }

    /// S16l: the session's persistent ACK connection, dialed as `dial_with`
    /// does under an ACK-path permit the caller holds and keeps (its first
    /// stream's inner handshake and PolicyAck follow under it). A failure is
    /// judged as an ACK-path establishment's. Its stall watchdog closes it
    /// on a frozen path as any pooled connection's, but its stall deaths
    /// never switch the flow pool's fallback: the ACK path redials instead.
    pub(crate) async fn dial_ack(
        peer: SocketAddr,
        interface: &RelayInterface,
        crypto: &PreparedCryptoInputs,
        limiter: &Arc<EstablishLimiter>,
        gate: &WorkGate,
        pin_gen: u64,
    ) -> io::Result<Self> {
        Self::dial_as(
            Purpose::Ack,
            peer,
            interface,
            crypto,
            limiter,
            gate,
            pin_gen,
        )
        .await
    }

    /// TCP, outer TLS and the H2 handshake under the signed connect budget,
    /// a failure judged for `purpose` before this returns. v40 (CP-D3 M1):
    /// a typed pre-authentication failure (the TCP dial refused or timed
    /// out, the outer handshake cut, no outer carrier within the budget) is
    /// also noted as the session pin's carrier fault; D2: an ECH rejection
    /// with authenticated retry configs redials exactly once with them.
    async fn dial_as(
        purpose: Purpose,
        peer: SocketAddr,
        interface: &RelayInterface,
        crypto: &PreparedCryptoInputs,
        limiter: &Arc<EstablishLimiter>,
        gate: &WorkGate,
        pin_gen: u64,
    ) -> io::Result<Self> {
        let budget = dial_budget(peer, crypto)?;
        let wake_gen = limiter.wake_generation();
        // Whether a TCP connect completed: a budget that ends before one is
        // a dial timeout, after one an establishment timeout.
        let connected = AtomicBool::new(false);
        let dialed = tokio::time::timeout(budget, async {
            let connect_started = Instant::now();
            // D2: at most one redial, only after an admitted ECH rotation.
            let mut redialed = false;
            let (tls, live, fd) = loop {
                let tcp = match connect_bound(peer, interface).await {
                    Ok(tcp) => tcp,
                    Err(error) => {
                        if !interface_lost(&error) {
                            crypto.carrier_fault(crate::carrier_failover::dial_signal(
                                error.kind() == io::ErrorKind::TimedOut,
                            ));
                        }
                        return Err(refused());
                    }
                };
                connected.store(true, Ordering::SeqCst);
                if tcp.peer_addr().map_err(|_| refused())? != peer {
                    return Err(refused());
                }
                tcp.set_nodelay(true).map_err(|_| refused())?;
                set_notsent_lowat(&tcp).map_err(|_| refused())?;
                let tls_started = Instant::now();
                let live = Arc::new(Liveness::new(Duration::ZERO));
                let fd = tcp.as_raw_fd();
                let tcp = CountedTcp {
                    tcp,
                    live: live.clone(),
                };
                match outer_tls(crypto, tcp).await {
                    Ok(tls) => {
                        live.seed_rtt(tls_started.elapsed());
                        break (tls, live, fd);
                    }
                    Err(error) => {
                        if !redialed {
                            if crypto.ech_rejected(error.judged())
                                == crate::carrier_pool::EchRedial::Redial
                            {
                                redialed = true;
                                crate::apple::log_code("ech_rotation", "redial");
                                continue;
                            }
                        } else {
                            // The one redial with the admitted retry
                            // configs failed: fail closed and forget them.
                            crypto.forget_ech_rotation();
                            crate::apple::log_code("ech_rotation", "refused");
                        }
                        crypto.note_outer_failure(error.judged(), true);
                        return Err(handshake_refusal(&error));
                    }
                }
            };
            // The relay's Finished just arrived: the path carries bytes both
            // ways now, as a PONG would show.
            live.proven();
            let (end_sender, end) = watch::channel(None);
            let end_sender = Arc::new(end_sender);
            let (send, mut connection) = h2::client::Builder::new()
                .initial_window_size(STREAM_WINDOW)
                .initial_connection_window_size(CONN_WINDOW)
                .initial_max_send_streams(STREAMS_BEFORE_SETTINGS)
                .max_send_buffer_size(SEND_BUFFER)
                .handshake::<_, Bytes>(GoAwayTap::new(tls, end_sender.clone(), live.clone()))
                .await
                .map_err(|error| {
                    let error = anyhow::Error::from(error);
                    crypto.note_outer_failure(error.judged(), true);
                    handshake_refusal(&error)
                })?;
            let pings = connection.ping_pong();
            let acks = TcpAcks::new(fd, live.clone());
            let ended = EndOnDrop(end_sender.clone());
            let (watched, closing, ending) = (live.clone(), end_sender.clone(), live.clone());
            let held = live.clone();
            let stalls = (purpose == Purpose::Flow).then(|| limiter.stall_deaths());
            // v40: the session pin's ticket: a stall close is its freeze,
            // a slow PONG its collapse (post-authentication degradations).
            let frozen = crypto.carrier_ticket().cloned();
            let collapse = Collapse::of(crypto);
            let driver = gate.spawn(async move {
                // The guard records the transport end on return and on an
                // abort alike. An Ok end without a GOAWAY is the relay's EOF;
                // a local close was recorded before its abort.
                let _ended = ended;
                tokio::pin!(connection);
                // S16m: declared after the connection, so it drops first:
                // no on-demand read outlives the socket.
                let _socket = SocketHeld::new(held, fd);
                let stalled = async move {
                    match pings {
                        Some(pings) => stall_watch(watched, pings, acks, collapse).await,
                        None => std::future::pending().await,
                    }
                };
                tokio::select! {
                    driven = &mut connection => {
                        // Noted before the guard records the transport end,
                        // so a stream judging its loss sees it (S16h-8b).
                        let lost = driven
                            .as_ref()
                            .err()
                            .and_then(h2::Error::get_io)
                            .is_some_and(interface_lost);
                        if lost {
                            ending.interface_lost.store(true, Ordering::SeqCst);
                        }
                    }
                    () = stalled => {
                        // A stalled connection closes as a local close,
                        // recorded before the connection drops (its FIN), so
                        // its streams fail as a connection loss. The epoch
                        // counts its stall deaths (S16h-8d).
                        record(&closing, ConnEnd::LocalClose);
                        if let Some(stalls) = stalls {
                            stalls.died();
                        }
                        if let Some(ticket) = &frozen {
                            ticket.degraded(
                                aegis_core::brain::carrier_failover::CarrierSignal::SessionFreeze,
                            );
                        }
                    }
                }
            })?;
            Ok(Self {
                send,
                end,
                end_sender,
                connect_started,
                live,
                stream_cap: AtomicUsize::new(STREAMS_BEFORE_SETTINGS),
                answered: AtomicBool::new(false),
                pin_gen,
                wake_gen,
                #[cfg(test)]
                fd,
                _driver: driver,
            })
        })
        .await
        .unwrap_or_else(|_| {
            crypto.carrier_fault(if connected.load(Ordering::SeqCst) {
                aegis_core::brain::carrier_failover::CarrierSignal::EstablishmentTimeout
            } else {
                aegis_core::brain::carrier_failover::CarrierSignal::DialTimeout
            });
            Err(refused())
        });
        if let Err(error) = &dialed {
            limiter.judge(purpose, error);
        }
        dialed
    }

    /// Open one carrier stream: wait for stream capacity, send the held
    /// carrier request and await its response, raced against the
    /// connection's end. A non-200 status or a wrong content type is an
    /// explicit carrier refusal with aegis-client's own texts. A stream the
    /// connection's end fails is [`CarrierLost`], never a bare h2 error.
    /// Its receive window stays SETTINGS_INITIAL_WINDOW_SIZE (v33's), as the
    /// ACK connection's streams keep it; a flow's stream opens through
    /// [`StreamSlot::open_carrier`], whose window may grow (v34).
    pub(crate) async fn open_carrier(
        &self,
        crypto: &PreparedCryptoInputs,
    ) -> anyhow::Result<PooledCarrier> {
        self.open_carrier_with(crypto, None).await
    }

    /// `open_carrier`, whose stream's receive window follows the v34 rule
    /// under `window`'s budget when given ([`crate::stream_window`]).
    pub(crate) async fn open_carrier_with(
        &self,
        crypto: &PreparedCryptoInputs,
        window: Option<&Arc<PoolWindow>>,
    ) -> anyhow::Result<PooledCarrier> {
        let request = crypto.carrier_request(https_bridge::Purpose::Traffic)?;
        let mut end = self.end.clone();
        // An ended connection (a GOAWAY included) never opens a stream.
        if let Some(ended) = *end.borrow_and_update() {
            return Err(lost(ended, None).into());
        }
        // A fresh clone has no pending open: ready at once. Streams over the
        // relay's concurrency limit queue inside h2 (and await below). A
        // refused send never reached the relay.
        let asked = Instant::now();
        let sent = match self.send.clone().ready().await {
            Ok(mut send) => send.send_request(request, false),
            Err(error) => Err(error),
        };
        let (response, stream) = match sent {
            Ok(sent) => sent,
            Err(error) => return Err(lost_or(&mut end, error, None).await),
        };
        let stream_id = u32::from(response.stream_id());
        tokio::pin!(response);
        let response = loop {
            // The end first: a GOAWAY is recorded as it is read, before h2
            // answers or fails the stream it names.
            tokio::select! {
                biased;
                changed = end.changed() => {
                    let ended = match (changed, *end.borrow_and_update()) {
                        (Ok(()), Some(ended)) => ended,
                        (Ok(()), None) => continue,
                        (Err(_), _) => ConnEnd::LocalClose,
                    };
                    let lost = lost(ended, Some(stream_id));
                    // A stream the relay processed under a graceful GOAWAY
                    // still gets its response.
                    if matches!(ended, ConnEnd::GoAway(h2::Reason::NO_ERROR, _))
                        && !lost.unprocessed
                    {
                        continue;
                    }
                    return Err(lost.into());
                }
                response = &mut response => match response {
                    Ok(response) => break response,
                    Err(error) => return Err(lost_or(&mut end, error, Some(stream_id)).await),
                },
            }
        };
        self.sample_rtt(asked.elapsed());
        let channel = crypto.selected_channel().map_err(anyhow::Error::from)?;
        match channel {
            aegis_core::carrier_program::CarrierChannel::HttpsWs => {
                anyhow::ensure!(
                    response.status() == http::StatusCode::OK,
                    "secure websocket carrier unavailable"
                );
            }
            aegis_core::carrier_program::CarrierChannel::DirectH2
            | aegis_core::carrier_program::CarrierChannel::FrontedH2
            | aegis_core::carrier_program::CarrierChannel::OwnHttpsBridge => {
                verify_carrier(response.status(), response.headers())?;
            }
            _ => anyhow::bail!("selected carrier channel has no H2 stream owner"),
        }
        // S16i-2: the relay's SETTINGS precede any response, so h2 holds
        // their MAX_CONCURRENT_STREAMS by now; a later SETTINGS may lower
        // it, so every 200 reads it again.
        self.note_settings();
        self.answered.store(true, Ordering::SeqCst);
        let body = response.into_body();
        let stream = match window {
            Some(pool) => {
                let policy =
                    WindowPolicy::new(pool.clone(), self.live.window.clone(), Instant::now());
                H2Stream::with_recv_window(stream, body, Box::new(policy))
            }
            None => H2Stream::new(stream, body),
        };
        let io = if channel == aegis_core::carrier_program::CarrierChannel::HttpsWs {
            let ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
                stream,
                tokio_tungstenite::tungstenite::protocol::Role::Client,
                Some(aegis_core::ws_io::bounded_config()),
            )
            .await;
            crate::carrier_io::own(aegis_core::ws_io::WsIo::new(ws))
        } else {
            crate::carrier_io::own(GrpcIo::new(stream))
        };
        Ok(PooledCarrier { stream_id, io })
    }

    /// v34: its round trips and load as the stream window reads them.
    pub(crate) fn window(&self) -> &Arc<ConnWindow> {
        &self.live.window
    }

    /// How the connection ended, if it has.
    pub(crate) fn ended(&self) -> Option<ConnEnd> {
        *self.end.borrow()
    }

    /// A receiver of the connection's end.
    pub(crate) fn end_watch(&self) -> watch::Receiver<Option<ConnEnd>> {
        self.end.clone()
    }

    pub(crate) fn connect_started(&self) -> Instant {
        self.connect_started
    }

    /// The connection's smoothed round trip.
    pub(crate) fn srtt(&self) -> Duration {
        self.live.srtt()
    }

    /// S16i-2: the streams it takes at once now ([`stream_cap`]).
    pub(crate) fn stream_cap(&self) -> usize {
        self.stream_cap.load(Ordering::SeqCst)
    }

    /// S16j-1: whether a carrier on it was answered 200.
    pub(crate) fn answered(&self) -> bool {
        self.answered.load(Ordering::SeqCst)
    }

    /// S16l: one request awaiting the relay on this connection (a PolicyAck
    /// on the ACK connection, until its ACK): while held, its stall watchdog
    /// watches the connection's quiet and closes it on a frozen path.
    pub(crate) fn awaiting(&self) -> Awaiting {
        Awaiting::start(&self.live)
    }

    /// Test-only: whether the connection showed a sign of life (inbound
    /// bytes, or TCP ACKs of new bytes while its watchdog watched) at or
    /// after `at`. S16m: no longer what makes an ACK request alive
    /// (`acked_beyond`).
    #[cfg(test)]
    pub(crate) fn alive_since(&self, at: Instant) -> bool {
        self.live.last_alive() >= at
    }

    /// S16m: the bytes its socket accepted so far: a request whose bytes
    /// follow this mark is alive once a byte past it is acknowledged
    /// ([`PooledConn::acked_beyond`]).
    pub(crate) fn write_mark(&self) -> u64 {
        self.live.written.load(Ordering::SeqCst)
    }

    /// S16m: whether the relay's TCP acknowledged a byte this connection
    /// wrote after `mark` ([`PooledConn::write_mark`]), read now: the path
    /// carried a byte both ways after the mark was taken. Inbound bytes are
    /// no such proof (they may have left the relay before it), nor are TCP
    /// ACKs of earlier bytes. False while no driver holds its socket (before
    /// its task first ran, and once it let the socket go) or it is
    /// unreadable.
    pub(crate) fn acked_beyond(&self, mark: u64) -> bool {
        self.live.acked_now().is_some_and(|acked| acked > mark)
    }

    /// Test-only (S16m): whether its driver task holds its socket now.
    #[cfg(test)]
    pub(crate) fn socket_held_for_test(&self) -> bool {
        self.live
            .socket
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    /// S16j-1: the bytes in its send buffer (SO_NWRITE) as its stall
    /// watchdog last read them, while a stream awaited the relay.
    pub(crate) fn send_queued(&self) -> u64 {
        self.live.queued.load(Ordering::Relaxed)
    }

    /// Test-only: its smoothed round trip is `srtt` from now on (until a
    /// carrier sample moves it), as on a slower path.
    #[cfg(test)]
    pub(crate) fn set_srtt_for_test(&self, srtt: Duration) {
        self.live.srtt_us.store(micros(srtt), Ordering::Relaxed);
        self.live.window.set_srtt(srtt);
    }

    /// Test-only: its socket's TCP_NOTSENT_LOWAT, read now.
    #[cfg(test)]
    pub(crate) fn notsent_lowat_for_test(&self) -> io::Result<libc::c_int> {
        let mut value: libc::c_int = 0;
        let mut length = socklen_of_int();
        // SAFETY: `fd` is the connection's open socket while its driver
        // holds it (a live connection), and the value and length describe
        // one c_int.
        let read = unsafe {
            libc::getsockopt(
                self.fd,
                libc::IPPROTO_TCP,
                TCP_NOTSENT_LOWAT,
                std::ptr::addr_of_mut!(value).cast(),
                &mut length,
            )
        };
        if read == 0 {
            Ok(value)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// S16i-2: a 200 arrived: the relay's SETTINGS_MAX_CONCURRENT_STREAMS as
    /// h2 now holds it sets the streams it takes at once (logged
    /// `pool_streams cap:<n>` when that changes).
    fn note_settings(&self) {
        let cap = stream_cap(self.send.current_max_send_streams());
        if self.stream_cap.swap(cap, Ordering::SeqCst) != cap {
            crate::apple::log_code("pool_streams", &format!("cap:{cap}"));
        }
    }

    fn sample_rtt(&self, sample: Duration) {
        self.live.sample_rtt(sample);
    }

    /// After a stream's own watchdog fired (its 200 or its inner handshake
    /// outlived its bound): whether its connection ended, now or at its
    /// stall watchdog's verdict, rather than showed a sign of life. The
    /// watchdog is armed unless a sign of life follows the question, so a
    /// stream on a frozen connection is a connection loss, never a timeout;
    /// the wait is a PONG wait and `CONN_END_GRACE` at most. `stream_id`:
    /// the stream, None before it was sent.
    pub(crate) async fn lost_after_watchdog(&self, stream_id: Option<u32>) -> bool {
        let stream_id = stream_id.unwrap_or(u32::MAX);
        let mut end = self.end_watch();
        if ended_within(&mut end, stream_id, Duration::ZERO).await {
            return true;
        }
        let asked = Instant::now();
        let live = &*self.live;
        let _verdict = Verdict::ask(live, asked);
        let verdict = async {
            loop {
                let changed = live.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if live.last_alive() >= asked {
                    return false;
                }
                tokio::select! {
                    () = &mut changed => {}
                    _ = end.wait_for(|ended| ended.is_some_and(|ended| fails(ended, stream_id))) => {
                        return true;
                    }
                }
            }
        };
        tokio::time::timeout(pong_wait(self.srtt()) + CONN_END_GRACE, verdict)
            .await
            .unwrap_or(false)
    }

    /// S16h-8b, strike level 2: whether the path proved its life both ways
    /// within `fresh` (a PONG, or the outer TLS handshake), or, asked now,
    /// within one PONG wait (its stall watchdog sends one PING unless one is
    /// unanswered). An ended connection proves nothing. A stream's
    /// handshake starts only on a proven connection, so one frozen since its
    /// last answer costs no strike. The question is also a verdict
    /// ([`PooledConn::lost_after_watchdog`]): with no sign of life within
    /// the PONG wait the stall watchdog closes the connection (a local
    /// close, one stall death), and the answer waits up to `CONN_END_GRACE`
    /// more for that end, so the flow's retry never takes this connection
    /// again but dials past it.
    pub(crate) async fn proven_within(&self, fresh: Duration) -> bool {
        let live = &*self.live;
        let asked = Instant::now();
        if live
            .last_proof()
            .is_some_and(|at| asked.saturating_duration_since(at) <= fresh)
        {
            return self.ended().is_none();
        }
        let mut end = self.end_watch();
        let _verdict = Verdict::ask(live, asked);
        let proof = async {
            live.want_ping(asked);
            loop {
                let changed = live.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if live.last_proof().is_some_and(|at| at >= asked) {
                    return true;
                }
                tokio::select! {
                    () = &mut changed => {}
                    _ = end.wait_for(Option::is_some) => return false,
                }
            }
        };
        let proven = tokio::time::timeout(pong_wait(self.srtt()) + CONN_END_GRACE, proof)
            .await
            .unwrap_or(false);
        proven && self.ended().is_none()
    }

    /// PINGs its stall watchdog sent.
    #[cfg(test)]
    pub(crate) fn pings(&self) -> usize {
        self.live.pings.load(Ordering::Relaxed)
    }

    /// Test-only: no byte it writes from now on is acknowledged, as on a
    /// path that froze now (a loopback kernel acknowledges whatever a
    /// userspace freeze holds); those written before still are.
    #[cfg(test)]
    pub(crate) fn freeze_acks_for_test(&self) {
        let written = self.live.written.load(Ordering::SeqCst);
        self.live.acks_cap.store(written, Ordering::SeqCst);
    }

    /// Test-only (S16m): its TCP ACKs flow again, as when a path's backlog
    /// drains: every byte the kernel acknowledged shows from now on.
    #[cfg(test)]
    pub(crate) fn thaw_acks_for_test(&self) {
        self.live.acks_cap.store(u64::MAX, Ordering::SeqCst);
    }

    /// Test-only: the next stream whose inner handshake returns
    /// authenticated freezes its connection's TCP ACKs as it returns
    /// (`freeze_acks_for_test` then), before its Finished can be
    /// acknowledged.
    #[cfg(test)]
    pub(crate) fn freeze_acks_at_handshake_for_test(&self) {
        self.live.freeze_at_handshake.store(true, Ordering::SeqCst);
    }

    /// Test-only: whether its TCP ACKs are frozen.
    #[cfg(test)]
    pub(crate) fn acks_frozen(&self) -> bool {
        self.live.acks_cap.load(Ordering::SeqCst) != u64::MAX
    }

    pub(crate) fn pin_gen(&self) -> u64 {
        self.pin_gen
    }

    pub(crate) fn wake_gen(&self) -> u64 {
        self.wake_gen
    }
}

fn socklen_of_int() -> libc::socklen_t {
    // A c_int's 4 bytes always fit.
    libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>()).unwrap_or(4)
}

/// S16j-1: TCP_NOTSENT_LOWAT of `NOTSENT_LOWAT` on a pooled socket.
fn set_notsent_lowat(tcp: &tokio::net::TcpStream) -> io::Result<()> {
    let value: libc::c_int = NOTSENT_LOWAT;
    // SAFETY: the socket is open (owned by `tcp`), and the value and length
    // describe one c_int.
    let set = unsafe {
        libc::setsockopt(
            tcp.as_raw_fd(),
            libc::IPPROTO_TCP,
            TCP_NOTSENT_LOWAT,
            std::ptr::addr_of!(value).cast(),
            socklen_of_int(),
        )
    };
    if set == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// A pooled dial's budget: the signed connect budget, to the session's
/// verified peer only.
fn dial_budget(peer: SocketAddr, crypto: &PreparedCryptoInputs) -> io::Result<Duration> {
    crypto.direct_peer(peer)?;
    let budget_ms = crypto.signed_relay().connect_timeout_ms;
    if !(1..=60_000).contains(&budget_ms) {
        return Err(refused());
    }
    Ok(Duration::from_millis(budget_ms))
}

/// Outer TLS to the relay with the held connector and authority, then the
/// outer checks of `connect_h2_from_held`. v40: the selected pin's held
/// connector and TLS name.
async fn outer_tls<T: AsyncRead + AsyncWrite + Unpin>(
    crypto: &PreparedCryptoInputs,
    tcp: T,
) -> anyhow::Result<tokio_rustls::client::TlsStream<T>> {
    let relay = crypto.carrier().relay();
    let authority = aegis_client::relay_endpoint_policy::relay_transport_authority(relay)?;
    let tls = crypto
        .outer_connector()
        .connect(authority.tls_server_name, tcp)
        .await?;
    let (_, connection) = tls.get_ref();
    verify_outer(relay, connection.ech_status(), connection.alpn_protocol())?;
    Ok(tls)
}

/// prepared_outer_tls.rs:161-165: the pinned ECH accepted, ALPN h2.
fn verify_outer(
    relay: &aegis_core::RelaySettings,
    ech: EchStatus,
    alpn: Option<&[u8]>,
) -> anyhow::Result<()> {
    aegis_client::ech_policy::require_accepted_ech(relay, ech)?;
    anyhow::ensure!(alpn == Some(b"h2"), "secure carrier requires HTTP/2");
    Ok(())
}

/// prepared_outer_tls.rs:173-184: 200 with content type application/grpc.
fn verify_carrier(status: http::StatusCode, headers: &http::HeaderMap) -> anyhow::Result<()> {
    anyhow::ensure!(
        status == http::StatusCode::OK,
        "secure carrier rejected with HTTP {}",
        status
    );
    anyhow::ensure!(
        headers
            .get("content-type")
            .is_some_and(|h| h == "application/grpc"),
        "invalid secure carrier content type"
    );
    Ok(())
}

/// Passes the relay's H2 bytes to h2 unchanged and reports each GOAWAY
/// frame's error code and last stream ID the moment it is read; a read that
/// returns bytes is a sign of the connection's life ([`Liveness`]).
struct GoAwayTap<T> {
    io: T,
    end: EndSender,
    live: Arc<Liveness>,
    header: [u8; FRAME_HEADER],
    header_len: usize,
    // Payload bytes left of the current frame, and whether it is a GOAWAY.
    payload_left: usize,
    goaway: bool,
    body: [u8; 8],
    body_len: usize,
}

impl<T> GoAwayTap<T> {
    fn new(io: T, end: EndSender, live: Arc<Liveness>) -> Self {
        Self {
            io,
            end,
            live,
            header: [0; FRAME_HEADER],
            header_len: 0,
            payload_left: 0,
            goaway: false,
            body: [0; 8],
            body_len: 0,
        }
    }

    fn observe(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            if self.payload_left == 0 {
                let take = (FRAME_HEADER - self.header_len).min(bytes.len());
                self.header[self.header_len..self.header_len + take]
                    .copy_from_slice(&bytes[..take]);
                self.header_len += take;
                bytes = &bytes[take..];
                if self.header_len == FRAME_HEADER {
                    self.header_len = 0;
                    let [a, b, c, kind, ..] = self.header;
                    self.payload_left = u32::from_be_bytes([0, a, b, c]) as usize;
                    self.goaway = kind == GOAWAY;
                    self.body_len = 0;
                }
                continue;
            }
            let take = self.payload_left.min(bytes.len());
            if self.goaway && self.body_len < self.body.len() {
                let part = (self.body.len() - self.body_len).min(take);
                self.body[self.body_len..self.body_len + part].copy_from_slice(&bytes[..part]);
                self.body_len += part;
                if self.body_len == self.body.len() {
                    let [a, b, c, d, e, f, g, h] = self.body;
                    let last = u32::from_be_bytes([a, b, c, d]) & 0x7fff_ffff;
                    let code = u32::from_be_bytes([e, f, g, h]);
                    record(&self.end, ConnEnd::GoAway(h2::Reason::from(code), last));
                }
            }
            self.payload_left -= take;
            bytes = &bytes[take..];
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for GoAwayTap<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        ready!(Pin::new(&mut self.io).poll_read(context, buf))?;
        let this = &mut *self;
        if buf.filled().len() > before {
            this.live.alive();
        }
        this.observe(&buf.filled()[before..]);
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for GoAwayTap<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(context, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write_vectored(context, bufs)
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

/// Pooled connections of one session that may take new streams (Probing,
/// Open or dialing), at most.
pub(crate) const POOL_CONNS: usize = 4;
/// Streams of one connection in their inner handshake at once, at most.
/// Four (S16j-4, was 2): against relay-a's 32 handshakes per peer the
/// 4 connections run 16 at once beside the ACK reserve, so a burst opens
/// twice the flows per cycle. Before R2 aegis-server charged every stream
/// whose accept deadline fired as an authentication strike, so a
/// connection frozen mid-handshake cost up to `H_CONN` strikes and `H_CONN`
/// stayed below its ban at three. R2 (aegis-server c7c4cd4b, deployed as
/// 83b48386) counts only a refused device (MissingCertificate,
/// CertificateRejected, DeviceNotAllowed), never a timeout or a lost
/// transport, so a frozen connection costs no strike whatever `H_CONN` is;
/// a relay without R2 would count up to four (`RELAY_HANDSHAKES_PER_IP`'s
/// note). The epoch's strike ledger and stall fallback (S16h-8b, 8d) stay:
/// from one ledger entry every connection runs one handshake at a time.
pub(crate) const H_CONN: usize = 4;
/// Pool dials in flight at once, at most.
pub(crate) const POOL_DIALS: usize = 2;
/// S16j-1: connections the session pre-dials at Running, at once: as many
/// as dials may be in flight, each under a flow permit of its own.
pub(crate) const PREWARM_CONNS: usize = POOL_DIALS;
// `FlowPool::prewarm` runs exactly two.
const _: () = assert!(PREWARM_CONNS == 2);
/// S16j-1: handshake times (carrier request to inner connect) the pool
/// keeps for its `pool_detail` percentiles.
const HS_SAMPLES: usize = 64;
/// The longest a connection may have been idle and still take a stream:
/// aegis-server closes it `ADMISSION_TIMEOUT` (5 s) after its last
/// authenticated stream ended, and a stream it accepts inherits that same
/// deadline for its handshake, its request and its target
/// (https_bridge.rs:25-36, session/grpc.rs:260), so a stream on a
/// connection that idled long would race the relay's close.
///
/// aegis-server computes that deadline at the top of its connection loop
/// (grpc.rs:231) and hands it to the next stream it accepts (grpc.rs:260):
/// a stream accepted before the loop ran again since a sibling
/// authenticated inherits the stale idle deadline (the connection's TLS
/// accept, or its last authenticated stream's end, plus 5 s), although the
/// sibling is live. The loop runs again at each accept, request end, or that
/// deadline. So a connection's idle age ([`Entry::idle_age`]) runs from that
/// anchor while it has a live authenticated stream too, until this side
/// knows the loop ran since one authenticated: a carrier was sent at least
/// one RTT (and [`FRESH_MARGIN`]) after a live sibling's handshake, or
/// [`STALE_ANCHOR`] passed since the anchor with one live throughout. Past
/// `IDLE_REUSE`, such a live connection still takes a stream bounded by the
/// stale deadline while it leaves a handshake time (`Entry::reusable`).
/// A stream counts as live only until the relay ended its side of it
/// ([`RelayEnd`]).
pub(crate) const IDLE_REUSE: Duration = Duration::from_secs(1);
/// After a live sibling's handshake, beyond one RTT, by when the relay has
/// authenticated it (its Finished arrived half an RTT after the handshake
/// returned here).
pub(crate) const FRESH_MARGIN: Duration = Duration::from_millis(50);
/// The relay's idle deadline after its anchor, and a margin: its loop has
/// run again by then.
pub(crate) const STALE_ANCHOR: Duration = Duration::from_millis(5_500);
/// Streams one connection opens over its life before it drains: h2 on the
/// relay counts locally reset streams over the connection's whole life
/// (`max_local_error_reset_streams(Some(8))`, session/grpc.rs:216).
pub(crate) const MAX_CONN_STREAMS: usize = 256;
/// The age, from its TCP connect, at which a connection drains.
pub(crate) const MAX_CONN_AGE: Duration = Duration::from_secs(600);
/// How often a waiting flow looks at the pool again without a release (a
/// connection's end, an idle age, the pause after ENHANCE_YOUR_CALM).
const POOL_RECHECK: Duration = Duration::from_millis(25);
// R2: timeouts are no strikes, so `H_CONN` is bounded by the relay's
// handshakes per peer (`establish_limit`'s assertions over
// `ESTABLISH_PERMITS`), not by its ban; a connection's handshakes fit the
// streams it may take before the relay's SETTINGS.
const _: () = assert!(H_CONN == 4 && H_CONN <= STREAMS_BEFORE_SETTINGS);
const _: () = assert!(H_CONN >= 1 && POOL_DIALS >= 1 && POOL_DIALS <= POOL_CONNS);
// Every live flow the limiter admits fits on the pool at the stream cap.
const _: () = assert!(crate::establish_limit::LIVE_FLOWS_MAX <= POOL_CONNS * STREAMS_CAP);
const _: () = assert!(LIVE_FLOWS <= crate::establish_limit::LIVE_FLOWS_MAX);

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "relay flow pool budget elapsed")
}

/// The refusal of a flow whose own pool dial failed (S16i-1: its
/// `dial_failed` class), of the dial error's kind; the dial's failure was
/// judged by the limiter already.
#[derive(Debug)]
pub(crate) struct DialFailed;

impl fmt::Display for DialFailed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("relay flow pool dial failed")
    }
}

impl std::error::Error for DialFailed {}

fn dial_failed(error: &io::Error) -> io::Error {
    io::Error::new(error.kind(), DialFailed)
}

/// Whether `error` is the refusal of a flow whose own pool dial failed.
pub(crate) fn is_dial_failed(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.is::<DialFailed>())
}

/// The refusal of a pooled dial that got no flow permit within its wait
/// (S16i-1: its flow's `permit_wait` class): it never sent a SYN.
#[derive(Debug)]
pub(crate) struct PermitWait;

impl fmt::Display for PermitWait {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("relay flow pool dial got no permit")
    }
}

impl std::error::Error for PermitWait {}

fn permit_wait() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, PermitWait)
}

/// Whether `error` is the refusal of a pooled dial that got no permit.
pub(crate) fn is_permit_wait(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.is::<PermitWait>())
}

fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

/// A pooled connection's place in its pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    /// Fresh: one stream at a time until a stream's inner connect returned
    /// authenticated, so a refused or broken connection costs one handshake.
    /// S16j-1: on a proven pool, `h_conn` once its first 200 arrived
    /// (`Entry::ramped`): the relay already authenticated this session.
    Probing,
    /// Takes up to `H_CONN` establishing and its stream cap of live streams
    /// (`PooledConn::stream_cap`, at most `STREAMS_CAP`).
    Open,
    /// Takes no new stream; its streams run to their end, then it closes.
    Draining,
    /// Its connection ended (a GOAWAY or a transport end).
    Dead,
}

/// The pool's limits; tests narrow them.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pub(crate) pool_conns: usize,
    pub(crate) streams_per_conn: usize,
    pub(crate) h_conn: usize,
    pub(crate) pool_dials: usize,
    pub(crate) idle_reuse: Duration,
    pub(crate) max_conn_streams: usize,
    pub(crate) max_conn_age: Duration,
    /// No new dial for this long after a GOAWAY with ENHANCE_YOUR_CALM.
    pub(crate) calm_pause: Duration,
    /// One inner handshake at a time on a connection for this long after
    /// the relay refused one of its streams after the 200.
    pub(crate) capacity_pause: Duration,
    /// S16j-1: never configured, set for each look from the pool's state:
    /// a stream of this session authenticated (the pool is proven), so a
    /// Probing connection whose first 200 arrived takes `h_conn` streams.
    pub(crate) proven: bool,
}

impl Limits {
    /// These limits under the epoch's pool `mode` (S16h-8b, 8d): from
    /// strike level 1 one inner handshake per connection; in the fallback
    /// one stream per connection, as many connections as live flows, and
    /// as many dials at once as its flow permits.
    pub(crate) fn under(self, mode: PoolMode) -> Self {
        let mut limits = self;
        if mode.strikes >= 1 || mode.fallback {
            limits.h_conn = 1;
            // S16j-1: a strike or the fallback unproves the pool.
            limits.proven = false;
        }
        if mode.fallback {
            limits.streams_per_conn = 1;
            limits.pool_conns = limits.pool_conns.max(LIVE_FLOWS);
            limits.pool_dials = limits.pool_dials.max(FALLBACK_FLOW_PERMITS);
        }
        limits
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            pool_conns: POOL_CONNS,
            streams_per_conn: STREAMS_CAP,
            h_conn: H_CONN,
            pool_dials: POOL_DIALS,
            idle_reuse: IDLE_REUSE,
            max_conn_streams: MAX_CONN_STREAMS,
            max_conn_age: MAX_CONN_AGE,
            calm_pause: FLOW_BACKOFF,
            capacity_pause: FLOW_BACKOFF,
            proven: false,
        }
    }
}

/// One pooled connection and its counts.
struct Entry {
    id: u64,
    conn: Arc<PooledConn>,
    phase: Phase,
    // Streams from their reservation until their inner connect returned.
    establishing: usize,
    // Streams reserved and not yet ended, establishing ones included.
    streams: usize,
    // Live streams whose inner connect returned authenticated.
    authenticated: usize,
    // Streams ever reserved on it.
    opened: usize,
    // Where the relay's idle deadline runs from: its TCP connect, then its
    // last authenticated stream's end.
    anchor: Instant,
    // When its live authenticated streams began (none: None).
    auth_since: Option<Instant>,
    // The relay's loop ran since a live stream authenticated: every stream
    // it accepts now inherits a whole deadline (`IDLE_REUSE`).
    fresh: bool,
    // One inner handshake at a time until then: the relay refused a stream
    // after its 200 (`StreamSlot::capacity_refused`).
    narrowed: Option<Instant>,
    // A pre-dial that joined with flows waiting for it (S16i-1): its probe
    // is offered past `idle_reuse` (`Entry::awaited`).
    waited_for: bool,
    // S16j-1: when each stream in its inner handshake sent its carrier
    // request (`StreamSlot::sent` until `handshake_done`).
    inflight: Vec<Instant>,
    // S16j-1: a pre-dial's: it leaves the pool logged `pool_prewarm
    // unused` if no flow ever took it (`FlowPool::release`).
    prewarmed: bool,
}

impl Entry {
    /// The age of the deadline a stream the relay accepts now inherits
    /// (`IDLE_REUSE`): zero once the relay's loop ran since a live stream
    /// authenticated; else the time since the anchor (its last
    /// authenticated stream's end, or its TCP connect if none has ended).
    fn idle_age(&self, now: Instant) -> Duration {
        let age = now.saturating_duration_since(self.anchor);
        if self.fresh || (self.authenticated > 0 && age >= STALE_ANCHOR) {
            return Duration::ZERO;
        }
        age
    }

    fn takes_streams(&self) -> bool {
        matches!(self.phase, Phase::Probing | Phase::Open)
    }

    /// S16j-1: a Probing connection of a proven pool whose first 200
    /// arrived: it takes `h_conn` streams at once, as an Open one does.
    fn ramped(&self, limits: &Limits) -> bool {
        limits.proven && self.phase == Phase::Probing && self.conn.answered()
    }

    /// S16j-1: a stream whose carrier was sent at `sent` left its inner
    /// handshake.
    fn unsent(&mut self, sent: Instant) {
        if let Some(at) = self.inflight.iter().position(|at| *at == sent) {
            self.inflight.swap_remove(at);
        }
    }

    /// v34: whether a stream on it carries a bulk flow at `now`
    /// (`ConnWindow::bulk`): a new flow goes elsewhere while a connection
    /// as free has none.
    fn bulk(&self, now: Instant) -> bool {
        self.conn.window().bulk(now)
    }

    /// v35: whether its latest bulk measurement's credit-loop delay stood at
    /// `Q_SHRINK` or more within `BULK_HOLD` (`ConnWindow::queued`): a new
    /// flow's 200 and handshake would wait behind that queue, so it goes to
    /// another connection with a free slot (P1).
    fn queued(&self, now: Instant) -> bool {
        self.conn.window().queued(now)
    }

    /// S16j-1: whether its oldest inner handshake in flight is older than
    /// [`slow_after`] its round trip at `now`: its relay or its path is
    /// slow, and a new handshake goes elsewhere while another has room.
    fn slow(&self, now: Instant) -> bool {
        let limit = slow_after(self.conn.srtt());
        self.inflight
            .iter()
            .min()
            .is_some_and(|sent| now.saturating_duration_since(*sent) > limit)
    }

    /// S16i-1: a pre-dial that joined with flows waiting for it, whose
    /// probe no flow took yet, offers that probe past `idle_reuse` while
    /// [`hs_budget`] leaves `HS_FLOOR`: as a lazy dialer's own probe is sent
    /// whatever its dial took, bounded by the relay's deadline from the
    /// connection's TCP connect ([`StreamBounds`]). A pre-dial slower than
    /// `idle_reuse` would otherwise arrive unusable, and the flows that
    /// waited for it would only then dial their own.
    fn awaited(&self, now: Instant) -> bool {
        self.waited_for && self.opened == 0 && hs_budget(self.idle_age(now)) >= HS_FLOOR
    }

    /// S16i-1: whether its probe, the one stream it ever took (asked
    /// before that stream's carrier request, so none authenticated), is
    /// still sent past `idle_reuse`: while [`hs_budget`] leaves `HS_FLOOR`,
    /// bounded by the relay's deadline from the TCP connect
    /// ([`StreamBounds`]). Its flow (the one that dialed it, or waited for
    /// its pre-dial) would otherwise dial again and pay as long again, at
    /// the same age: a dial slower than `idle_reuse` is never discarded by
    /// its own flow.
    fn probe_sendable(&self, now: Instant) -> bool {
        self.opened == 1 && hs_budget(self.idle_age(now)) >= HS_FLOOR
    }

    /// Inner handshakes it may run at once now: `h_conn`, or one while it
    /// is narrowed after a capacity refusal.
    fn h_conn(&self, limits: &Limits, now: Instant) -> usize {
        if self.narrowed.is_some_and(|until| now < until) {
            1
        } else {
            limits.h_conn
        }
    }

    /// Whether a stream the relay accepts now inherits enough of its
    /// deadline: within `idle_reuse` its whole budgets apply. A connection
    /// with a live authenticated stream whose relay deadline is stale (not
    /// yet `fresh`) also takes one while [`hs_budget`] leaves two round
    /// trips and `HS_FLOOR`: that stream is bounded by the stale deadline
    /// ([`StreamBounds`]), and sent at least one RTT after a sibling
    /// authenticated it makes the connection fresh, so a connection whose
    /// first streams returned just past `idle_reuse` is never left unusable
    /// until `STALE_ANCHOR`. S16j-1: so does a ramped Probing connection
    /// (`Entry::ramped`), its streams bounded by the same stale deadline.
    fn reusable(&self, limits: &Limits, now: Instant) -> bool {
        let age = self.idle_age(now);
        age <= limits.idle_reuse
            || ((self.authenticated > 0 || self.ramped(limits))
                && hs_budget(age) >= self.conn.srtt().saturating_mul(2) + HS_FLOOR)
            || self.awaited(now)
    }

    /// Handshake slots it offers now: one probe on a Probing connection
    /// with no stream; up to `h_conn` on an Open one (one while narrowed),
    /// or on a ramped Probing one (S16j-1), within its stream cap.
    fn free(&self, limits: &Limits, now: Instant) -> usize {
        self.slots(limits, now, self.h_conn(limits, now))
    }

    /// S16i-2: the streams it may hold at once now: the relay's advertised
    /// limit less `STREAM_MARGIN` as of its latest 200
    /// (`PooledConn::stream_cap`), under the pool's own stream cap.
    fn stream_cap(&self, limits: &Limits) -> usize {
        self.conn.stream_cap().min(limits.streams_per_conn)
    }

    /// `free` with `h_conn` handshakes at once on an Open connection.
    fn slots(&self, limits: &Limits, now: Instant, h_conn: usize) -> usize {
        if !self.reusable(limits, now) {
            return 0;
        }
        let room = self.stream_cap(limits).saturating_sub(self.streams);
        match self.phase {
            _ if self.ramped(limits) => h_conn.saturating_sub(self.establishing).min(room),
            Phase::Probing if self.streams == 0 => room.min(1),
            Phase::Open => h_conn.saturating_sub(self.establishing).min(room),
            _ => 0,
        }
    }

    /// Handshake slots it offers waiting flows soon, as [`FlowPool::grows`]
    /// counts them: a Probing connection whose probe is in flight offers
    /// `h_conn` once the probe returns (within its stream cap: none in the
    /// one-stream fallback), and a narrowed connection counts its whole
    /// `h_conn`. The relay's handshake cap is per client IP and
    /// relay-wide (aegis-core secure_channel/mod.rs:112-123), so a dial in
    /// place of the slot it withholds would only move that load.
    ///
    /// S16j-1: a Probing connection whose probe no flow took yet (a dial
    /// joins so, its probe for the oldest waiter) offers that probe and
    /// `h_conn` once it returns, as a dial's connection did whose dialer
    /// took its probe as it joined (that flow then waited no more).
    fn capacity(&self, limits: &Limits, now: Instant) -> usize {
        let room = self.stream_cap(limits).saturating_sub(self.streams);
        match self.phase {
            Phase::Probing if self.streams > 0 => limits.h_conn.min(room),
            Phase::Probing if self.slots(limits, now, limits.h_conn) > 0 => {
                (1 + limits.h_conn).min(room)
            }
            _ => self.slots(limits, now, limits.h_conn),
        }
    }
}

/// S16j-1: one waiting flow's place in the pool's arrival order.
#[derive(Clone, Copy, Debug)]
struct Ticket {
    id: u64,
    since: Instant,
    // Its flow dials a connection now: it takes no slot meanwhile, and
    // holds back no ticket behind it.
    dialing: bool,
}

#[derive(Default)]
struct PoolState {
    conns: Vec<Entry>,
    next_id: u64,
    // Dials in flight, pre-dials included.
    dials: usize,
    // S16j-1: pre-dials in flight.
    prewarming: usize,
    // S16j-1: flows waiting for a stream, dialing ones included, oldest
    // first.
    queue: VecDeque<Ticket>,
    next_ticket: u64,
    // S16j-1: a stream of this session authenticated, on a connection of
    // this wake generation: the pool is proven (`Limits::proven`). A strike,
    // the fallback, a capacity refusal or a wake unproves it.
    proven: Option<u64>,
    // S16j-1: the latest handshake times, carrier request to an
    // authenticated inner connect.
    hs_samples: VecDeque<Duration>,
    // No new dial before this (after ENHANCE_YOUR_CALM).
    dial_pause: Option<Instant>,
    // Carrier resets before a 200 since the last 200.
    resets: VecDeque<Instant>,
    stats: PoolStats,
    // v35: the flows taken a stream for, and those on a queued connection.
    takes: (u64, u64),
}

/// Test-visible counters of one pool.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PoolStats {
    /// Dials started.
    pub(crate) dials: usize,
    /// The most connections taking streams or dialing at once.
    pub(crate) max_conns: usize,
    /// The most dials in flight at once.
    pub(crate) max_dials: usize,
    /// The most establishing streams on one connection at once.
    pub(crate) max_establishing: usize,
    /// The most streams on one connection at once.
    pub(crate) max_streams: usize,
    /// Connections that ended with a GOAWAY.
    pub(crate) goaways: usize,
    /// The most flows waiting for a stream at once, dialing ones included.
    pub(crate) max_waiting: usize,
    /// Pre-dials started (S16i-1), also counted in `dials`.
    pub(crate) prewarms: usize,
}

impl PoolState {
    fn entry(&mut self, id: u64) -> Option<&mut Entry> {
        self.conns.iter_mut().find(|entry| entry.id == id)
    }

    /// Flows waiting for a stream, dialing ones included.
    fn waiting(&self) -> usize {
        self.queue.len()
    }

    /// S16j-1: a new flow's ticket, at the back of the queue.
    fn enqueue(&mut self, now: Instant) -> u64 {
        let id = self.next_ticket;
        self.next_ticket += 1;
        self.queue.push_back(Ticket {
            id,
            since: now,
            dialing: false,
        });
        self.stats.max_waiting = self.stats.max_waiting.max(self.waiting());
        id
    }

    /// S16j-1: ticket `id` leaves the queue.
    fn leave(&mut self, id: u64) {
        self.queue.retain(|ticket| ticket.id != id);
    }

    fn set_dialing(&mut self, id: u64, dialing: bool) {
        if let Some(ticket) = self.queue.iter_mut().find(|ticket| ticket.id == id) {
            ticket.dialing = dialing;
        }
    }

    /// S16j-1: the tickets ahead of `id` that may take a slot now (those
    /// not dialing).
    fn ahead(&self, id: u64) -> usize {
        self.queue
            .iter()
            .take_while(|ticket| ticket.id != id)
            .filter(|ticket| !ticket.dialing)
            .count()
    }

    /// S16j-1: the youngest ticket not dialing, the one that dials when the
    /// pool grows, so the oldest stay ready for the next free slot.
    fn youngest_idle(&self) -> Option<u64> {
        self.queue
            .iter()
            .rev()
            .find(|ticket| !ticket.dialing)
            .map(|ticket| ticket.id)
    }

    /// Handshake slots the connections offer now, in all.
    fn free(&self, limits: &Limits, now: Instant) -> usize {
        self.conns.iter().map(|entry| entry.free(limits, now)).sum()
    }

    /// S16j-1: the pool's round trip for [`establish_floor`]: the shortest
    /// of the connections taking streams (a flow may land on it), zero with
    /// none.
    fn srtt(&self) -> Duration {
        self.conns
            .iter()
            .filter(|entry| entry.takes_streams())
            .map(|entry| entry.conn.srtt())
            .min()
            .unwrap_or(Duration::ZERO)
    }

    /// S16j-1: one handshake time, carrier request to an authenticated
    /// inner connect.
    fn sample_handshake(&mut self, took: Duration) {
        if self.hs_samples.len() == HS_SAMPLES {
            self.hs_samples.pop_front();
        }
        self.hs_samples.push_back(took);
    }

    /// S16j-1: the `pct` percentile of the kept handshake times, in ms
    /// (none: 0).
    fn handshake_ms(&self, pct: usize) -> u64 {
        let mut samples: Vec<Duration> = self.hs_samples.iter().copied().collect();
        if samples.is_empty() {
            return 0;
        }
        samples.sort_unstable();
        let at = (samples.len() * pct / 100).min(samples.len() - 1);
        u64::try_from(samples[at].as_millis()).unwrap_or(u64::MAX)
    }

    /// Connections taking streams, and dials that will.
    fn active(&self) -> usize {
        self.conns
            .iter()
            .filter(|entry| entry.takes_streams())
            .count()
            + self.dials
    }

    fn note_active(&mut self) {
        self.stats.max_conns = self.stats.max_conns.max(self.active());
        self.stats.max_dials = self.stats.max_dials.max(self.dials);
    }

    /// The counts of one `pool_state` line (S16i-1).
    fn snapshot(&self, now: Instant) -> PoolSnapshot {
        let mut pool = PoolSnapshot {
            waiting: self.waiting(),
            oldest_ms: self.queue.front().map_or(0, |ticket| {
                u64::try_from(now.saturating_duration_since(ticket.since).as_millis())
                    .unwrap_or(u64::MAX)
            }),
            hs_p50_ms: self.handshake_ms(50),
            hs_p90_ms: self.handshake_ms(90),
            ..PoolSnapshot::default()
        };
        for entry in &self.conns {
            match entry.phase {
                Phase::Open => pool.open += 1,
                Phase::Probing => pool.probing += 1,
                Phase::Draining | Phase::Dead => pool.draining += 1,
            }
            pool.streams += entry.streams;
            pool.send_queued = pool.send_queued.max(entry.conn.send_queued());
            if entry.takes_streams() {
                pool.conns_taking += 1;
                pool.conns_queued += usize::from(entry.queued(now));
            }
        }
        (pool.takes, pool.takes_queued) = self.takes;
        pool
    }

    /// A connection's end, as the pool notes it once: a GOAWAY is counted
    /// and logged `pool_goaway reason:<code>`, and ENHANCE_YOUR_CALM pauses
    /// new dials for `calm_pause` from `now`.
    fn note_end(&mut self, end: ConnEnd, now: Instant, limits: &Limits) {
        let ConnEnd::GoAway(reason, _) = end else {
            return;
        };
        self.stats.goaways += 1;
        crate::apple::log_code("pool_goaway", &format!("reason:{}", u32::from(reason)));
        if reason == h2::Reason::ENHANCE_YOUR_CALM {
            let until = now + limits.calm_pause;
            self.dial_pause = Some(self.dial_pause.map_or(until, |at| at.max(until)));
        }
    }

    /// Ended or drained connections with no stream left leave the pool; the
    /// last reference closes each (a local close: TLS close_notify, FIN). A
    /// draining connection that ended since the last look has its end noted
    /// here, as a look would have.
    fn sweep(&mut self, now: Instant, limits: &Limits) -> Vec<Entry> {
        let mut gone = Vec::new();
        let mut at = 0;
        while at < self.conns.len() {
            let entry = &self.conns[at];
            if !entry.takes_streams() && entry.streams == 0 {
                let entry = self.conns.swap_remove(at);
                if entry.phase != Phase::Dead {
                    if let Some(end) = entry.conn.ended() {
                        self.note_end(end, now, limits);
                    }
                }
                gone.push(entry);
            } else {
                at += 1;
            }
        }
        gone
    }
}

/// How a pre-dial ended ([`FlowPool::prewarm`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Prewarm {
    /// The connection with this pool ID joined the pool.
    Dialed(u64),
    /// The session is stale: its gate closed or the epoch was re-pinned.
    Stale,
    /// The limiter grants no permit now (a backoff, probing, the pause
    /// before sleep, or establishments waiting).
    Held,
    /// The pool has a connection, a dial in flight or a waiting flow, or
    /// pauses its dials.
    Busy,
    /// Its dial failed (judged by the limiter).
    Failed,
}

impl Prewarm {
    fn code(self) -> &'static str {
        match self {
            Prewarm::Dialed(_) => "dialed",
            Prewarm::Stale => "stale",
            Prewarm::Held => "held",
            Prewarm::Busy => "busy",
            Prewarm::Failed => "failed",
        }
    }
}

/// What a waiting flow does next.
enum Next {
    Take(StreamSlot),
    Dial,
    Wait,
    /// Out of time: its deadline passed, or less than its establish floor
    /// is left (S16j-1).
    Late(io::Error),
}

/// The pool of outer connections that carries one session's flows (S16h):
/// at most `POOL_CONNS` taking streams, each at most its stream cap of
/// streams (S16i-2: [`stream_cap`] of the relay's SETTINGS as of its latest
/// 200, `STREAMS_BEFORE_SETTINGS` before its first; one whose cap is 0
/// drains) and `H_CONN` inner handshakes at once. Waiting flows are served
/// first come, first served (S16j-1). Connections are dialed lazily, by the
/// youngest waiting flow, while more flows wait than the connections and
/// dials will offer, at most `POOL_DIALS` at once, each dial under a flow permit of the session's
/// limiter ([`PooledConn::dial`]). A flow waiting for a stream holds no
/// limiter permit.
///
/// A connection takes a new stream only while it is current: dialed under
/// the epoch's present pin and wake generations, younger than
/// `MAX_CONN_AGE`, under `MAX_CONN_STREAMS` streams over its life, and idle
/// at most `IDLE_REUSE` (or, with a live stream, while the stale relay
/// deadline still leaves a handshake time). Otherwise it drains once it has
/// no stream. A connection that ended (a
/// GOAWAY or a transport end) is dead; after ENHANCE_YOUR_CALM no new
/// connection is dialed for `FLOW_BACKOFF`. After an epoch re-pin the whole
/// session is stale (S18 rebuilds it): every reservation is refused at once.
pub(crate) struct FlowPool {
    peer: SocketAddr,
    interface: RelayInterface,
    crypto: Arc<PreparedCryptoInputs>,
    limiter: Arc<EstablishLimiter>,
    gate: Arc<WorkGate>,
    pins: EpochPins,
    // The re-pin generation this session was bound under.
    pin: u64,
    limits: Limits,
    state: Mutex<PoolState>,
    changed: Notify,
    // v34: the session's stream-window budget, which every flow's stream
    // grows from ([`StreamSlot::open_carrier`]).
    window: Arc<PoolWindow>,
}

impl FlowPool {
    /// The pool of one session: its verified `peer`, the relay interface it
    /// is bound to, its held crypto, its limiter and gate, and the epoch's
    /// pins with the generation the session was bound under.
    pub(crate) fn new(
        peer: SocketAddr,
        interface: RelayInterface,
        crypto: Arc<PreparedCryptoInputs>,
        (limiter, gate): (Arc<EstablishLimiter>, Arc<WorkGate>),
        (pins, pin): (EpochPins, u64),
    ) -> io::Result<Arc<Self>> {
        Self::with_limits(
            peer,
            interface,
            crypto,
            (limiter, gate),
            (pins, pin),
            Limits::default(),
        )
    }

    pub(crate) fn with_limits(
        peer: SocketAddr,
        interface: RelayInterface,
        crypto: Arc<PreparedCryptoInputs>,
        (limiter, gate): (Arc<EstablishLimiter>, Arc<WorkGate>),
        (pins, pin): (EpochPins, u64),
        limits: Limits,
    ) -> io::Result<Arc<Self>> {
        crypto.direct_peer(peer)?;
        if crypto.selected_channel()? == aegis_core::carrier_program::CarrierChannel::WebResponse {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let sane = (1..=POOL_CONNS).contains(&limits.pool_conns)
            && (1..=STREAMS_CAP).contains(&limits.streams_per_conn)
            && (1..=H_CONN).contains(&limits.h_conn)
            && (1..=limits.pool_conns).contains(&limits.pool_dials)
            && limits.max_conn_streams >= 1;
        if !sane {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // v35: the start's stream-window mode, from the epoch's pins (a
        // rebuilt session's pool reads the same).
        let window = PoolWindow::new_with_mode(pins.window_mode(), limiter.clone());
        // v35: once per pool (so per session, a rebuild included): the
        // stream-window mode this tunnel start runs, which the window
        // harness's window_policy row checks.
        limiter.flow_fields("pool_policy", &[&format!("mode:{}", window.mode().code())]);
        Ok(Arc::new(Self {
            peer,
            interface,
            crypto,
            limiter,
            gate,
            pins,
            pin,
            limits,
            state: Mutex::default(),
            changed: Notify::new(),
            window,
        }))
    }

    /// v34: the session's stream-window budget and its streams' windows.
    pub(crate) fn window(&self) -> &Arc<PoolWindow> {
        &self.window
    }

    fn lock(&self) -> MutexGuard<'_, PoolState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The session's verified relay peer.
    pub(crate) fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// The relay interface every pooled socket is bound to.
    pub(crate) fn interface(&self) -> &RelayInterface {
        &self.interface
    }

    pub(crate) fn crypto(&self) -> &Arc<PreparedCryptoInputs> {
        &self.crypto
    }

    pub(crate) fn limiter(&self) -> &Arc<EstablishLimiter> {
        &self.limiter
    }

    pub(crate) fn gate(&self) -> &Arc<WorkGate> {
        &self.gate
    }

    /// A carrier stream was reset before its 200. Not authentication class:
    /// the relay resets one before any admission. `RESETS_UNANSWERED` of
    /// them within `RESET_WINDOW` and no 200 between them count as one
    /// unanswered Open (true), and the count starts again.
    pub(crate) fn carrier_reset(&self) -> bool {
        let now = Instant::now();
        let mut state = self.lock();
        state
            .resets
            .retain(|at| now.saturating_duration_since(*at) < RESET_WINDOW);
        state.resets.push_back(now);
        if state.resets.len() >= RESETS_UNANSWERED {
            state.resets.clear();
            return true;
        }
        false
    }

    /// A carrier stream was answered 200: earlier resets are forgiven.
    /// S16j-1: on a proven pool its connection may now take more streams
    /// (`Entry::ramped`): waiting flows look again.
    pub(crate) fn carrier_answered(&self) {
        self.lock().resets.clear();
        self.changed.notify_waiters();
    }

    /// Reserve one stream for a flow, waiting until `deadline`: on a
    /// current connection with a free handshake slot (one not slow, then the
    /// fewest establishing, then the fewest live streams), or on one a
    /// waiting flow dials. The slot counts as establishing until
    /// [`StreamSlot::handshake_done`]. Refused at once when the gate is
    /// closed or the epoch was re-pinned, and refused when its own dial
    /// completes after a re-pin; a timeout when the deadline passes, and no
    /// dial starts after it.
    ///
    /// S16j-1: first come, first served. The flow takes a ticket at once; it
    /// takes a slot only while fewer tickets ahead of it (those not dialing)
    /// wait than the connections offer free slots, so a new arrival never
    /// takes one while older flows wait, whichever waiter a release wakes
    /// first. Only the youngest waiter dials when the pool grows; the
    /// connection it dials joins with its probe free, which the oldest
    /// waiter takes, and the dialer keeps its place. With less than
    /// [`establish_floor`] left (the pool's round trip) it leaves before it
    /// takes a slot, as a timeout (its flow's `pool_wait`): every pool wait
    /// ends so, before its deadline.
    pub(crate) async fn reserve(self: &Arc<Self>, deadline: Instant) -> io::Result<StreamSlot> {
        let mut waiting: Option<Waiting> = None;
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            // Registered before the state is read, so no release is missed.
            notified.as_mut().enable();
            // Read before the pool lock, which is never held while taking
            // the epoch's own locks.
            let generation = self.pins.generation();
            let wake = self.limiter.wake_generation();
            let mode = self.limiter.pool_mode();
            let (next, gone, snapshot) = {
                let mut state = self.lock();
                if self.gate.is_closed() {
                    drop(state);
                    return Err(refused());
                }
                let now = Instant::now();
                self.refresh(&mut state, now, generation, wake);
                let gone = state.sweep(now, &self.limits);
                // S18: the session is stale; it is rebuilt on the new pin.
                if generation != self.pin {
                    drop(state);
                    self.release(gone);
                    return Err(refused());
                }
                let ticket = match &waiting {
                    Some(waiting) => waiting.ticket,
                    None => {
                        let ticket = state.enqueue(now);
                        waiting = Some(Waiting {
                            pool: self.clone(),
                            ticket,
                            armed: true,
                        });
                        ticket
                    }
                };
                let limits = self.limits_now(&mut state, mode);
                let next = if now >= deadline {
                    Next::Late(timed_out())
                } else if deadline.saturating_duration_since(now) < establish_floor(state.srtt()) {
                    // S16j-1: no time left to establish: a pool wait now,
                    // before it takes a slot it could only spend as a bound.
                    Next::Late(timed_out())
                } else if state.ahead(ticket) < state.free(&limits, now) {
                    match self.take(&mut state, &limits, now) {
                        Some(slot) => {
                            state.leave(ticket);
                            if let Some(waiting) = waiting.as_mut() {
                                waiting.armed = false;
                            }
                            Next::Take(slot)
                        }
                        None => Next::Wait,
                    }
                } else if state.youngest_idle() == Some(ticket)
                    && self.grows(&state, &limits, now, mode)
                {
                    state.set_dialing(ticket, true);
                    state.dials += 1;
                    state.stats.dials += 1;
                    state.note_active();
                    Next::Dial
                } else {
                    Next::Wait
                };
                let snapshot = matches!(next, Next::Wait).then(|| state.snapshot(now));
                (next, gone, snapshot)
            };
            self.release(gone);
            // S16i-1: logged outside the pool lock, which is never held
            // while taking the epoch's own locks.
            if let Some(snapshot) = snapshot {
                self.limiter.pool_state(snapshot);
            }
            match next {
                Next::Take(slot) => return Ok(slot),
                // Its ticket leaves with `waiting`.
                Next::Late(error) => return Err(error),
                Next::Dial => {
                    let ticket = waiting.as_ref().map_or(0, |waiting| waiting.ticket);
                    self.dial(deadline, ticket).await?;
                }
                Next::Wait => {
                    let now = Instant::now();
                    tokio::select! {
                        () = &mut notified => {}
                        () = tokio::time::sleep_until(deadline.min(now + POOL_RECHECK)) => {}
                    }
                }
            }
        }
    }

    /// The pool's limits under the epoch's pool `mode` for this look
    /// (S16j-1: proven, unless a strike or the fallback unproved it).
    fn limits_now(&self, state: &mut PoolState, mode: PoolMode) -> Limits {
        let mut limits = self.limits;
        limits.proven = state.proven.is_some();
        let limits = limits.under(mode);
        if !limits.proven {
            state.proven = None;
        }
        limits
    }

    /// Mark what changed since the last look: an ended connection is dead
    /// (logged `pool_goaway reason:<code>` for a GOAWAY; ENHANCE_YOUR_CALM
    /// also pauses new dials); one that is no longer current drains.
    fn refresh(&self, state: &mut PoolState, now: Instant, generation: u64, wake: u64) {
        let limits = self.limits;
        // S16j-1: a wake unproves the pool; its connections drain.
        if state.proven.is_some_and(|proven| proven != wake) {
            state.proven = None;
        }
        for at in 0..state.conns.len() {
            let entry = &mut state.conns[at];
            if entry.phase == Phase::Dead {
                continue;
            }
            if let Some(end) = entry.conn.ended() {
                entry.phase = Phase::Dead;
                state.note_end(end, now, &limits);
                continue;
            }
            if !entry.takes_streams() {
                continue;
            }
            let stale = entry.conn.pin_gen() != generation
                || entry.conn.wake_gen() != wake
                || entry.opened >= limits.max_conn_streams
                || now.saturating_duration_since(entry.conn.connect_started())
                    >= limits.max_conn_age
                // Idle past reuse with no stream: it never becomes
                // reusable again (an awaited pre-dial, past its probe's
                // last chance).
                || (entry.streams == 0
                    && entry.idle_age(now) > limits.idle_reuse
                    && !entry.awaited(now))
                // S16i-2: the relay's SETTINGS leave it no stream.
                || entry.conn.stream_cap() == 0;
            if stale {
                entry.phase = Phase::Draining;
            }
        }
    }

    /// One stream on the eligible connection under `limits` (the epoch's
    /// pool mode applied): one not slow first (S16j-1, `Entry::slow`), then
    /// (v35) one not queued (`Entry::queued`), then the fewest
    /// establishing, then (v34) one that carries no bulk flow
    /// (`Entry::bulk`), then the fewest live streams. Idle background flows
    /// count as live streams, so before v34 a connection that carried a
    /// download but fewer of them took the next flow, which then shared
    /// that download's congestion window. A queued connection still takes a
    /// flow once no other has a free slot (`Entry::free` bounds how many).
    fn take(
        self: &Arc<Self>,
        state: &mut PoolState,
        limits: &Limits,
        now: Instant,
    ) -> Option<StreamSlot> {
        let entry = state
            .conns
            .iter_mut()
            .filter(|entry| entry.free(limits, now) > 0)
            .min_by_key(|entry| {
                (
                    entry.slow(now),
                    entry.queued(now),
                    entry.establishing,
                    entry.bulk(now),
                    entry.streams,
                )
            })?;
        let queued = entry.queued(now);
        entry.establishing += 1;
        entry.streams += 1;
        entry.opened += 1;
        let (id, conn) = (entry.id, entry.conn.clone());
        let (establishing, streams) = (entry.establishing, entry.streams);
        state.takes.0 += 1;
        state.takes.1 += u64::from(queued);
        state.stats.max_establishing = state.stats.max_establishing.max(establishing);
        state.stats.max_streams = state.stats.max_streams.max(streams);
        Some(StreamSlot {
            pool: self.clone(),
            id,
            conn,
            establishing: true,
            authenticated: None,
            awaiting: None,
            exposed: Exposure::Unexposed,
            noted: None,
            sent_at: None,
        })
    }

    /// Whether a waiting flow dials: more flows wait (dialers included) than
    /// the handshake slots the current connections offer now or once their
    /// probe returns (a narrowed connection's whole `h_conn`), and the dials
    /// in flight once open (`h_conn` each, the oldest waiter's probe first),
    /// under the connection and dial caps, and not during the pause after
    /// ENHANCE_YOUR_CALM. Under the epoch's pool `mode` (`limits`), the
    /// handshakes in
    /// flight and those slots stay under its flow permits: a connection
    /// dialed beyond them would wait for a permit.
    fn grows(&self, state: &PoolState, limits: &Limits, now: Instant, mode: PoolMode) -> bool {
        let capacity: usize = state
            .conns
            .iter()
            .map(|entry| entry.capacity(limits, now))
            .sum::<usize>()
            + state.dials * limits.h_conn;
        let establishing: usize = state.conns.iter().map(|entry| entry.establishing).sum();
        state.waiting() > capacity
            && mode
                .flow_permits()
                .is_none_or(|permits| establishing + capacity < permits)
            && state.active() < limits.pool_conns
            && state.dials < limits.pool_dials
            && state.dial_pause.is_none_or(|until| until <= now)
    }

    /// Dial one connection for the waiting flow of `ticket` (S16j-1: it
    /// joins with its probe free, which the oldest waiter takes, exactly as
    /// a pre-dial that flows waited for; the dialer keeps its ticket). A
    /// failed dial (judged by the limiter) fails this flow alone; one that
    /// completes after an epoch re-pin is refused and closed.
    async fn dial(self: &Arc<Self>, deadline: Instant, ticket: u64) -> io::Result<()> {
        let mut dialing = Dialing {
            pool: self.clone(),
            armed: true,
            prewarm: false,
        };
        // S16i-1: a dial that got no permit before the flow's deadline sent
        // no SYN (a permit wait); one that failed or ran out of the flow's
        // budget after its permit is the flow's own dial failure.
        let mut permitted = false;
        let dialed = tokio::time::timeout_at(deadline, async {
            let permit = PooledConn::dial_permit(self.peer, &self.crypto, &self.limiter)
                .await
                .map_err(|error| {
                    if is_permit_wait(&error) {
                        error
                    } else {
                        dial_failed(&error)
                    }
                })?;
            permitted = true;
            PooledConn::dial_with(
                self.peer,
                &self.interface,
                &self.crypto,
                &self.limiter,
                &self.gate,
                self.pin,
                permit,
            )
            .await
            .map_err(|error| dial_failed(&error))
        })
        .await
        .unwrap_or_else(|_| {
            Err(if permitted {
                dial_failed(&timed_out())
            } else {
                permit_wait()
            })
        });
        // Read before the pool lock, as in `reserve`.
        let generation = self.pins.generation();
        let mut stale = None;
        let joined = {
            let mut state = self.lock();
            state.dials -= 1;
            dialing.armed = false;
            state.set_dialing(ticket, false);
            // S18: a re-pin during the dial makes the session stale; the
            // new connection takes no stream and closes.
            let dialed = match dialed {
                Ok(conn) if generation != self.pin => {
                    stale = Some(conn);
                    Err(refused())
                }
                dialed => dialed,
            };
            dialed.map(|conn| {
                let conn = Arc::new(conn);
                let id = state.next_id;
                state.next_id += 1;
                conn.window().set_id(id);
                state.conns.push(Entry {
                    id,
                    anchor: conn.connect_started(),
                    conn,
                    phase: Phase::Probing,
                    establishing: 0,
                    streams: 0,
                    authenticated: 0,
                    opened: 0,
                    auth_since: None,
                    fresh: false,
                    narrowed: None,
                    // Flows wait for it: its probe stays offered past
                    // `idle_reuse` (`Entry::awaited`).
                    waited_for: true,
                    inflight: Vec::new(),
                    prewarmed: false,
                });
                state.note_active();
            })
        };
        drop(stale);
        self.changed.notify_waiters();
        joined
    }

    /// S16i-1: pre-dial pooled connections when the session reaches
    /// Running (a rebuilt one at its Ready), so the first flows skip their
    /// TCP, outer TLS and H2 setup; S16j-1: [`PREWARM_CONNS`] at once, one
    /// outcome each, so the post-connect burst finds that many probes.
    /// Each only on a current session (its gate open, the epoch's pin
    /// generation its own), only under a flow permit the limiter grants now
    /// (`EstablishLimiter::try_prewarm`: never during a backoff, while
    /// probing or in the pause before sleep, never by waiting for one), and
    /// only into a pool with no connection, no dial in flight but these
    /// pre-dials, no flow waiting and no pause after ENHANCE_YOUR_CALM. Its
    /// wake generation is read as any dial's is, right before its TCP
    /// connect. It joins the pool as a Probing connection with no stream,
    /// whose probe the oldest waiting flow takes, and counts against no live
    /// flow; flows that reserve meanwhile wait for it as for any dial in
    /// flight. Unused, it drains and closes by the pool's idle rule (idle
    /// past `idle_reuse` with no stream), which this waits out. Logged
    /// `pool_prewarm <outcome>` (and `pool_prewarm unused`) for each.
    pub(crate) async fn prewarm(self: &Arc<Self>) -> Vec<Prewarm> {
        let (first, second) = tokio::join!(self.prewarm_one(), self.prewarm_one());
        vec![first, second]
    }

    async fn prewarm_one(self: &Arc<Self>) -> Prewarm {
        let prewarm = self.prewarm_dial().await;
        self.limiter.flow_note("pool_prewarm", prewarm.code());
        if let Prewarm::Dialed(id) = prewarm {
            self.close_unused(id).await;
        }
        prewarm
    }

    async fn prewarm_dial(self: &Arc<Self>) -> Prewarm {
        // Read before the pool lock, as in `reserve`.
        let generation = self.pins.generation();
        let wake = self.limiter.wake_generation();
        if self.gate.is_closed() || generation != self.pin {
            return Prewarm::Stale;
        }
        let Some(permit) = self.limiter.try_prewarm() else {
            return Prewarm::Held;
        };
        let gone = {
            let mut state = self.lock();
            let now = Instant::now();
            self.refresh(&mut state, now, generation, wake);
            let gone = state.sweep(now, &self.limits);
            // S16j-1: beside the other pre-dials only.
            let busy = state.conns.iter().any(Entry::takes_streams)
                || state.dials > state.prewarming
                || state.prewarming >= PREWARM_CONNS
                || state.waiting() > 0
                || state.dial_pause.is_some_and(|until| until > now);
            if busy {
                drop(state);
                self.release(gone);
                drop(permit);
                return Prewarm::Busy;
            }
            state.dials += 1;
            state.prewarming += 1;
            state.stats.dials += 1;
            state.stats.prewarms += 1;
            state.note_active();
            gone
        };
        self.release(gone);
        let mut dialing = Dialing {
            pool: self.clone(),
            armed: true,
            prewarm: true,
        };
        let dialed = PooledConn::dial_with(
            self.peer,
            &self.interface,
            &self.crypto,
            &self.limiter,
            &self.gate,
            self.pin,
            permit,
        )
        .await;
        let generation = self.pins.generation();
        let mut stale = None;
        let prewarm = {
            let mut state = self.lock();
            state.dials -= 1;
            state.prewarming -= 1;
            dialing.armed = false;
            match dialed {
                // S18: a re-pin during the dial; it takes no stream.
                Ok(conn) if generation != self.pin || self.gate.is_closed() => {
                    stale = Some(conn);
                    Prewarm::Stale
                }
                Ok(conn) => {
                    let conn = Arc::new(conn);
                    let id = state.next_id;
                    state.next_id += 1;
                    conn.window().set_id(id);
                    // Flows that reserved meanwhile waited for it.
                    let waited_for = state.waiting() > 0;
                    state.conns.push(Entry {
                        id,
                        anchor: conn.connect_started(),
                        conn,
                        phase: Phase::Probing,
                        establishing: 0,
                        streams: 0,
                        authenticated: 0,
                        opened: 0,
                        auth_since: None,
                        fresh: false,
                        narrowed: None,
                        waited_for,
                        inflight: Vec::new(),
                        prewarmed: true,
                    });
                    state.note_active();
                    Prewarm::Dialed(id)
                }
                Err(_) => Prewarm::Failed,
            }
        };
        drop(stale);
        self.changed.notify_waiters();
        prewarm
    }

    /// Wait out the pool's idle rule for pre-dialed connection `id`, then
    /// drain and close it if it has no stream (logged `pool_prewarm unused`
    /// when no flow ever took it).
    async fn close_unused(&self, id: u64) {
        let Some((anchor, awaited)) = self
            .lock()
            .entry(id)
            .map(|entry| (entry.anchor, entry.waited_for))
        else {
            return;
        };
        // An awaited one's probe stays offered while `hs_budget` leaves
        // `HS_FLOOR` (`Entry::awaited`).
        let reuse = if awaited {
            self.limits
                .idle_reuse
                .max(HS_HORIZON.saturating_sub(HS_FLOOR))
        } else {
            self.limits.idle_reuse
        };
        tokio::time::sleep_until(anchor + reuse + POOL_RECHECK).await;
        let generation = self.pins.generation();
        let wake = self.limiter.wake_generation();
        let gone = {
            let mut state = self.lock();
            let now = Instant::now();
            self.refresh(&mut state, now, generation, wake);
            state.sweep(now, &self.limits)
        };
        let closed = gone.iter().any(|entry| entry.id == id);
        self.release(gone);
        if closed {
            self.changed.notify_waiters();
        }
    }

    /// Close the connections that left the pool, outside the pool lock
    /// (which is never held while taking the epoch's own locks), logging
    /// `pool_prewarm unused` for each pre-dial no flow ever took, whichever
    /// look swept it (S16j-1: two pre-dials age out together).
    fn release(&self, gone: Vec<Entry>) {
        let unused = gone
            .iter()
            .filter(|entry| entry.prewarmed && entry.opened == 0)
            .count();
        drop(gone);
        for _ in 0..unused {
            self.limiter.flow_note("pool_prewarm", "unused");
        }
    }

    /// Test-only: every connection in the pool, oldest first.
    #[cfg(test)]
    pub(crate) fn views(&self) -> Vec<ConnView> {
        let limits = self.limits.under(self.limiter.pool_mode());
        let now = Instant::now();
        let state = self.lock();
        let mut views: Vec<ConnView> = state
            .conns
            .iter()
            .map(|entry| ConnView {
                id: entry.id,
                phase: entry.phase,
                establishing: entry.establishing,
                streams: entry.streams,
                opened: entry.opened,
                h_conn: entry.h_conn(&limits, now),
                stream_cap: entry.stream_cap(&limits),
            })
            .collect();
        views.sort_by_key(|view| view.id);
        views
    }

    /// Test-only: the connection with pool ID `id`, while it is pooled.
    #[cfg(test)]
    pub(crate) fn conn_for_test(&self, id: u64) -> Option<Arc<PooledConn>> {
        let mut state = self.lock();
        state.entry(id).map(|entry| entry.conn.clone())
    }

    #[cfg(test)]
    pub(crate) fn stats(&self) -> PoolStats {
        self.lock().stats
    }

    /// Test-only: flows waiting now, and dials in flight.
    #[cfg(test)]
    pub(crate) fn queue(&self) -> (usize, usize) {
        let state = self.lock();
        (state.waiting(), state.dials)
    }

    /// S16m: the session's own first PolicyAck was verified on a channel it
    /// authenticated (its inner mTLS) under wake generation `wake`, before
    /// any flow: a stream of this session authenticated, so the pool starts
    /// proven (S16j-1's rule) and a Probing connection whose first 200
    /// arrived takes `h_conn` streams from the first. A wake since
    /// (`refresh`), a strike, the fallback or a capacity refusal unproves it
    /// as before. Only an empty pool not proven already is marked.
    pub(crate) fn prove_by_session_ack(&self, wake: u64) {
        let mut state = self.lock();
        if state.proven.is_none() && state.conns.is_empty() {
            state.proven = Some(wake);
        }
    }

    /// Test-only: whether the pool is proven now (S16j-1).
    #[cfg(test)]
    pub(crate) fn proven(&self) -> bool {
        self.lock().proven.is_some()
    }

    /// Test-only: the counts of the next `pool_state` line (S16j-1).
    #[cfg(test)]
    pub(crate) fn snapshot_for_test(&self) -> PoolSnapshot {
        self.lock().snapshot(Instant::now())
    }

    /// Test-only: add `conn` as a connection with these counts.
    #[cfg(test)]
    pub(crate) fn insert_for_test(
        &self,
        conn: PooledConn,
        phase: Phase,
        (establishing, authenticated): (usize, usize),
    ) -> u64 {
        let mut state = self.lock();
        let id = state.next_id;
        state.next_id += 1;
        let conn = Arc::new(conn);
        conn.window().set_id(id);
        state.conns.push(Entry {
            id,
            anchor: conn.connect_started(),
            conn,
            phase,
            establishing,
            streams: establishing + authenticated,
            authenticated,
            opened: establishing + authenticated,
            auth_since: (authenticated > 0).then(Instant::now),
            fresh: false,
            narrowed: None,
            waited_for: false,
            inflight: Vec::new(),
            prewarmed: false,
        });
        id
    }
}

/// Test-only view of one pooled connection.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ConnView {
    pub(crate) id: u64,
    pub(crate) phase: Phase,
    pub(crate) establishing: usize,
    pub(crate) streams: usize,
    pub(crate) opened: usize,
    /// Inner handshakes it may run at once now.
    pub(crate) h_conn: usize,
    /// Streams it may hold at once now (S16i-2).
    pub(crate) stream_cap: usize,
}

/// A waiting flow's ticket in the pool's queue, left on drop unless it took
/// a stream; the tickets behind it move up (S16j-1).
struct Waiting {
    pool: Arc<FlowPool>,
    ticket: u64,
    armed: bool,
}

impl Drop for Waiting {
    fn drop(&mut self) {
        if self.armed {
            self.pool.lock().leave(self.ticket);
            self.pool.changed.notify_waiters();
        }
    }
}

/// A dial in flight, left on drop (a cancelled flow) unless it finished.
struct Dialing {
    pool: Arc<FlowPool>,
    armed: bool,
    // A pre-dial's (S16j-1: `PoolState::prewarming`).
    prewarm: bool,
}

impl Drop for Dialing {
    fn drop(&mut self) {
        if self.armed {
            {
                let mut state = self.pool.lock();
                state.dials = state.dials.saturating_sub(1);
                if self.prewarm {
                    state.prewarming = state.prewarming.saturating_sub(1);
                }
            }
            self.pool.changed.notify_waiters();
        }
    }
}

/// One flow's stream reserved on a pooled connection. It counts as
/// establishing until `handshake_done`, then (when authenticated) as a live
/// authenticated stream that keeps its connection from idling, until the
/// relay ended its side or the slot drops ([`AuthHold`]); dropping it
/// returns its place.
pub(crate) struct StreamSlot {
    pool: Arc<FlowPool>,
    id: u64,
    conn: Arc<PooledConn>,
    establishing: bool,
    authenticated: Option<AuthHold>,
    // From its carrier request until its Open status (S16h-8a).
    awaiting: Option<Awaiting>,
    // Whether the relay may be in its inner handshake (S16h-8b).
    exposed: Exposure,
    // The refusal class its establishment noted (S16i-1).
    noted: Option<Refusal>,
    // S16j-1: when its carrier request was sent, until its inner connect
    // returned (`Entry::inflight`).
    sent_at: Option<Instant>,
}

/// How long a pooled stream's loss may cost a strike at the relay's inner
/// deadline (S16h-8b): from its 200 until the relay can have read the
/// Finished of its inner handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Exposure {
    /// Before its 200, or judged ([`StreamSlot::take_strike`]), or answered.
    Unexposed,
    /// Its 200 arrived and this side's inner handshake has not returned.
    Handshaking,
    /// This side's inner handshake returned authenticated: the relay reads
    /// its Finished half an RTT later (`until`), and its TCP acknowledges a
    /// byte the outer socket accepted after `written` (the Finished, or the
    /// Open behind it) once it has.
    Returned { until: Instant, written: u64 },
}

/// A live stream's place in its connection's authenticated count: while it
/// is held, this side takes the relay's channel as live, which keeps the
/// connection from idling. Released when the relay ended its side of the
/// stream (`RelayEnd`) or the stream ends; the last release moves the
/// connection's anchor, from where the relay's next idle deadline runs.
pub(crate) struct AuthHold {
    pool: Arc<FlowPool>,
    id: u64,
}

impl Drop for AuthHold {
    fn drop(&mut self) {
        {
            let mut state = self.pool.lock();
            if let Some(entry) = state.entry(self.id) {
                entry.authenticated = entry.authenticated.saturating_sub(1);
                if entry.authenticated == 0 {
                    // The relay's next idle deadline runs from here.
                    entry.anchor = Instant::now();
                    entry.auth_since = None;
                    entry.fresh = false;
                }
            }
        }
        self.pool.changed.notify_waiters();
    }
}

impl StreamSlot {
    /// The connection to open this flow's carrier on.
    pub(crate) fn conn(&self) -> &PooledConn {
        &self.conn
    }

    /// This flow's carrier stream on its connection
    /// ([`PooledConn::open_carrier`]), whose receive window grows under the
    /// session's budget while it is window-limited (v34,
    /// [`crate::stream_window`]).
    pub(crate) async fn open_carrier(
        &self,
        crypto: &PreparedCryptoInputs,
    ) -> anyhow::Result<PooledCarrier> {
        self.conn
            .open_carrier_with(crypto, Some(&self.pool.window))
            .await
    }

    /// The flow's inner connect returned: its handshake slot is free again,
    /// and an authenticated stream opens a Probing connection.
    pub(crate) fn handshake_done(&mut self, authenticated: bool) {
        if !self.establishing {
            return;
        }
        self.establishing = false;
        if authenticated && self.exposed == Exposure::Handshaking {
            // The relay ends its handshake once it read the Finished this
            // side has just written, which its socket accepts from here.
            let live = &self.conn.live;
            let written = live.written.load(Ordering::SeqCst);
            #[cfg(test)]
            if live.freeze_at_handshake.swap(false, Ordering::SeqCst) {
                live.acks_cap.store(written, Ordering::SeqCst);
            }
            self.exposed = Exposure::Returned {
                until: Instant::now() + self.conn.srtt() / 2,
                written,
            };
        }
        let sent = self.sent_at.take();
        {
            let mut state = self.pool.lock();
            let mut proven = None;
            if let Some(entry) = state.entry(self.id) {
                entry.establishing = entry.establishing.saturating_sub(1);
                if let Some(sent) = sent {
                    entry.unsent(sent);
                }
                if authenticated {
                    if entry.authenticated == 0 {
                        entry.auth_since = Some(Instant::now());
                    }
                    entry.authenticated += 1;
                    if entry.phase == Phase::Probing {
                        entry.phase = Phase::Open;
                    }
                    self.authenticated = Some(AuthHold {
                        pool: self.pool.clone(),
                        id: self.id,
                    });
                    // S16j-1: the pool is proven, on this wake generation.
                    proven = Some(entry.conn.wake_gen());
                }
            }
            if let Some(wake) = proven {
                state.proven = Some(wake);
                if let Some(sent) = sent {
                    state.sample_handshake(sent.elapsed());
                }
            }
        }
        self.pool.changed.notify_waiters();
    }

    /// Whether its connection would still take this stream now
    /// (`Entry::reusable`), or this is its connection's probe and still
    /// worth sending (`Entry::probe_sendable`): a slot whose flow waited for
    /// its permit past that would race the relay's deadline. Judged under
    /// the limits `FlowPool::reserve` grants slots by under the epoch's
    /// pool `mode` (S16j-1: proven, so a ramped Probing connection's slot
    /// granted past `idle_reuse` is not given back for want of a proof the
    /// pool holds; that churn cost its flow its place in the queue).
    pub(crate) fn reusable(&self, mode: PoolMode) -> bool {
        let now = Instant::now();
        let mut state = self.pool.lock();
        let limits = self.pool.limits_now(&mut state, mode);
        state
            .entry(self.id)
            .is_some_and(|entry| entry.reusable(&limits, now) || entry.probe_sendable(now))
    }

    /// S16h-8b, 8d: whether its connection's counts, this slot's own among
    /// them, fit the epoch's pool `mode` now: no more inner handshakes at
    /// once than its `h_conn` (`Entry::h_conn`: one while a capacity
    /// refusal narrowed it), no more streams than its stream cap. A slot
    /// reserved before a strike, the fallback or a capacity refusal
    /// narrowed its connection, whose flow then waited for its permit, is
    /// given back and reserved again rather than run a second handshake,
    /// or a second stream, on its connection.
    pub(crate) fn fits(&self, mode: PoolMode) -> bool {
        let now = Instant::now();
        let mut state = self.pool.lock();
        let limits = self.pool.limits_now(&mut state, mode);
        state.entry(self.id).is_some_and(|entry| {
            entry.establishing <= entry.h_conn(&limits, now)
                && entry.streams <= entry.stream_cap(&limits)
        })
    }

    /// This flow's carrier request is sent now: its bounds from now and its
    /// connection's idle age now (`Entry::idle_age`). When a live
    /// authenticated stream of its connection returned its handshake at
    /// least `srtt` and `FRESH_MARGIN` ago, the relay authenticated it
    /// before it accepts this stream, and its loop runs again right after
    /// that accept: every later stream inherits a whole deadline. From now
    /// until [`StreamSlot::answered`] the stream awaits the relay, and its
    /// connection's quiet is watched (S16h-8a).
    pub(crate) fn sent(&mut self, srtt: Duration) -> StreamBounds {
        self.awaiting = Some(Awaiting::start(&self.conn.live));
        let now = Instant::now();
        let mut state = self.pool.lock();
        let Some(entry) = state.entry(self.id) else {
            return StreamBounds::new(now, Duration::MAX);
        };
        // S16j-1: in its inner handshake from now (`Entry::slow`).
        if self.establishing && self.sent_at.is_none() {
            self.sent_at = Some(now);
            entry.inflight.push(now);
        }
        let age = entry.idle_age(now);
        if entry
            .auth_since
            .is_some_and(|since| now >= since + srtt + FRESH_MARGIN)
        {
            entry.fresh = true;
        }
        StreamBounds::new(now, age)
    }

    /// The carrier's 200 arrived: from now the relay runs this stream's
    /// inner handshake, until it read the Finished of this side's
    /// (`handshake_done`), and its deadline firing meanwhile would be a
    /// strike of the public IP (S16h-8b).
    pub(crate) fn relay_handshaking(&mut self) {
        self.exposed = Exposure::Handshaking;
    }

    /// Whether the relay may still be in this stream's inner handshake as
    /// far as the path showed: its handshake runs, or returned less than
    /// half an RTT ago, or no byte written after it returned was
    /// acknowledged. The tail is judged by what the path carried, not by
    /// when its loss was found: a stall is found seconds after the path
    /// froze.
    fn exposed_now(&self) -> bool {
        match self.exposed {
            Exposure::Unexposed => false,
            Exposure::Handshaking => true,
            Exposure::Returned { until, written } => {
                Instant::now() <= until || self.conn.live.acked.load(Ordering::SeqCst) <= written
            }
        }
    }

    /// S16h-8b: whether this stream, lost now, may have cost a strike: lost
    /// while the relay may have been in its inner handshake (`exposed_now`)
    /// to a cause it may never have seen ([`strike_cause`]): a local close
    /// (its stall watchdog's among them) or a lost interface, unless an
    /// epoch re-pin since the session bound superseded it (v41).
    /// v41: an exposed loss a re-pin spared is counted and logged
    /// (`EstablishLimiter::repin_spared`), so a window shows what the
    /// teardown would have struck.
    fn lost_exposed(&self) -> bool {
        if !self.exposed_now() {
            return false;
        }
        let repinned = self.pool.pins.generation() != self.pool.pin;
        if repinned {
            self.pool.limiter.repin_spared();
        }
        strike_cause(
            self.conn.ended(),
            self.conn.live.interface_lost.load(Ordering::SeqCst),
            repinned,
        )
    }

    /// S16h-8b: the stream's establishment failed, a connection loss
    /// (`conn_lost`) or not: whether that loss may have cost a strike
    /// (`lost_exposed`), judged once. Any other failure is an answer the
    /// relay gave or saw (a refusal, this side's reset).
    pub(crate) fn take_strike(&mut self, conn_lost: bool) -> bool {
        let struck = conn_lost && self.lost_exposed();
        self.exposed = Exposure::Unexposed;
        struck
    }

    /// The flow's Open status arrived, or its wait for it ended: it no
    /// longer awaits the relay.
    pub(crate) fn answered(&mut self) {
        self.awaiting = None;
    }

    /// The relay refused this stream after its 200 and before the inner
    /// handshake answered: its handshake cap (aegis-server secure.rs:44-48
    /// vs :131), or a ban. Its connection runs one inner handshake at a time
    /// for `capacity_pause` (S16h-8c), and no dial replaces the slot it
    /// withholds ([`Entry::capacity`]). A slot reserved on it before, whose
    /// flow still waits for its permit, runs only once it is the
    /// connection's one handshake ([`StreamSlot::fits`]).
    pub(crate) fn capacity_refused(&self) {
        let until = Instant::now() + self.pool.limits.capacity_pause;
        {
            let mut state = self.pool.lock();
            if let Some(entry) = state.entry(self.id) {
                entry.narrowed = Some(entry.narrowed.map_or(until, |at| at.max(until)));
            }
            // S16j-1: the relay's cap was met: no connection ramps past its
            // probe until a stream authenticates again.
            state.proven = None;
        }
        crate::apple::log_code("pool_capacity", "h_conn:1");
    }

    /// The flow's stream `stream_id` on this slot's connection, held for
    /// the flow's life.
    pub(crate) fn into_guard(mut self, stream_id: u32) -> StreamGuard {
        self.answered();
        // The relay accepted its Open: its handshake is over.
        self.exposed = Exposure::Unexposed;
        StreamGuard {
            end: self.conn.end_watch(),
            stream_id,
            _slot: self,
        }
    }

    /// S16i-1: this stream's establishment failed in `refusal`'s class, as
    /// only the step that failed can tell (a bound, a reset, a status).
    pub(crate) fn note(&mut self, refusal: Refusal) {
        self.noted = Some(refusal);
    }

    /// The refusal class its establishment noted (none: None).
    pub(crate) fn noted(&self) -> Option<Refusal> {
        self.noted
    }

    /// Test-only: the pool's ID of this stream's connection.
    #[cfg(test)]
    pub(crate) fn conn_id(&self) -> u64 {
        self.id
    }
}

/// Whether a pooled connection's end, as `end` records it, may have left
/// the relay unaware, so a stream in its inner handshake then ran into the
/// relay's deadline: a local close (the stall watchdog's, which a frozen
/// path never carried) or the driver's error of a lost interface. A GOAWAY
/// or the relay's own end (RST, EOF) is the relay's to see.
///
/// v41: a loss in a session that an epoch re-pin superseded (`repinned`)
/// is the re-pin's own teardown, whatever ended its connection, and never
/// a strike. A re-pin is this side's deliberate move to a new path: it
/// says nothing of that path, and the relay that serves macOS (R2) charges
/// no timeout or lost transport. Installed build 40 counted the nine slots
/// a plug re-pin's teardown dropped as nine strikes, and the session rebuilt
/// on the new pin ran one handshake at a time on one connection for the
/// ledger's 300 s (window-v39-ifswitch-r1). What the relay may still hold
/// of the old session stays counted where its real limits are: the
/// stranded sessions and handshakes (`AuthBackoff::strand_current`). A
/// relay without R2, which the built-in capacity values do not cover,
/// would charge each such loss at its deadline (a lost interface found
/// after the re-pin included), as it charges a frozen connection's
/// `H_CONN` handshakes already; each spared loss is logged
/// (`pool_repin_spared`).
pub(crate) fn strike_cause(end: Option<ConnEnd>, interface_lost: bool, repinned: bool) -> bool {
    !repinned && (matches!(end, Some(ConnEnd::LocalClose)) || interface_lost)
}

/// A live flow's place on its pooled connection: its slot (returned on
/// drop) and its connection's end.
pub(crate) struct StreamGuard {
    end: watch::Receiver<Option<ConnEnd>>,
    stream_id: u32,
    _slot: StreamSlot,
}

impl StreamGuard {
    /// `io`, the flow's inner channel, as a [`RelayEnd`]: the stream's
    /// authenticated place is released once a read of it ends (the relay
    /// ended its side: EOF or an error), while the flow may live on
    /// half-closed with the relay's channel already gone.
    pub(crate) fn relay_end<T>(&mut self, io: T) -> RelayEnd<T> {
        RelayEnd {
            io,
            hold: self._slot.authenticated.take(),
        }
    }

    /// Resolves once the flow's connection ended in a way that fails its
    /// stream: every end but a graceful GOAWAY that covers it.
    pub(crate) async fn ended(&mut self) {
        let stream_id = self.stream_id;
        let _ = self
            .end
            .wait_for(|ended| ended.is_some_and(|ended| fails(ended, stream_id)))
            .await;
    }

    /// Test-only: the pool's ID of this stream's connection.
    #[cfg(test)]
    pub(crate) fn conn_id(&self) -> u64 {
        self._slot.id
    }
}

/// A flow's inner channel that releases its stream's [`AuthHold`] once a
/// read ends (EOF or an error): the relay ended its side. A relay that
/// forwarded its target's FIN keeps its channel only until its own idle
/// timeout, and a flow that only polls its application then never sees the
/// relay's later reset; its connection must not count as live past that.
pub(crate) struct RelayEnd<T> {
    io: T,
    hold: Option<AuthHold>,
}

impl<T: AsyncRead + Unpin> AsyncRead for RelayEnd<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let room = buf.remaining() > 0;
        let read = ready!(Pin::new(&mut self.io).poll_read(context, buf));
        if read.is_err() || (room && buf.filled().len() == before) {
            self.hold = None;
        }
        Poll::Ready(read)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for RelayEnd<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(context, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write_vectored(context, bufs)
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

impl Drop for StreamSlot {
    fn drop(&mut self) {
        // A flow dropped unjudged while the relay may have been in its inner
        // handshake, on a connection this side closed or whose interface was
        // lost (S16h-8b); a re-pin's own teardown is none (v41,
        // `strike_cause`). Before the pool lock, which is never held while
        // taking the epoch's own locks.
        if self.lost_exposed() {
            self.pool.limiter.strike();
        }
        // Its own lock and notification, before this one's.
        drop(self.authenticated.take());
        let gone = {
            let mut state = self.pool.lock();
            if let Some(entry) = state.entry(self.id) {
                if self.establishing {
                    entry.establishing = entry.establishing.saturating_sub(1);
                }
                if let Some(sent) = self.sent_at.take() {
                    entry.unsent(sent);
                }
                entry.streams = entry.streams.saturating_sub(1);
            }
            state.sweep(Instant::now(), &self.pool.limits)
        };
        self.pool.release(gone);
        self.pool.changed.notify_waiters();
    }
}

#[cfg(test)]
#[path = "flow_pool_tests.rs"]
mod tests;
