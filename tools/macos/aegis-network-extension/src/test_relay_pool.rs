//! cfg(test)-only multi-stream relay (B-06 S16h-1): many H2 streams on one
//! outer TLS connection, each stream its own inner mTLS channel and its own
//! request, as aegis-server serves them in https_bridge mode. It mirrors:
//!
//! - the H2 limits of session/grpc.rs:207-216 (32 streams, 8 KiB header lists,
//!   128 KiB stream and connection windows, a 128 KiB send buffer, reset
//!   guards 8/8/Some(8)), without extended CONNECT;
//! - the connection's admission deadline, bounded to `admission_timeout`
//!   after outer TLS (grpc.rs:143-145), and the Activity idle rule of
//!   https_bridge.rs:11-44: while an authenticated stream is live the
//!   connection never idles out; after the last one ends it closes
//!   `admission_timeout` later; before any it closes at the initial deadline;
//! - each stream's deadline, inherited at accept from the connection's idle
//!   deadline (or now + the timeout while one is live, grpc.rs:260) and
//!   min'd with origin + the handshake timeout when the handshake permit is
//!   taken (secure.rs:131-137); it covers mTLS, the request read and the
//!   target, as in secure.rs:189-278;
//! - the 200 sent before the handshake permit (secure.rs:44-49 vs :131), the
//!   per-peer handshake and session caps of aegis-core's Server
//!   (`try_acquire_handshake`, `try_acquire_session`): relay-a's 32
//!   handshakes per peer (`DEPLOYED_HANDSHAKES_PER_PEER`) beside aegis-core's
//!   default 128 sessions per peer, or a relay's own
//!   `PoolConfig::inner_admission`;
//! - the two early exits that never strike: a stream whose inherited
//!   deadline has passed ends unanswered, before any 200
//!   (`admission.check_deadline()?`, grpc.rs:347), and one whose deadline
//!   passes before its handshake permit ends after the 200 with no strike
//!   (`authentication_deadline()?`, secure.rs:148);
//! - a strike only for an authentication-class failure of the inner accept
//!   (secure.rs:149-168: `AuthenticationFailure::from_io`). With the device
//!   this relay trusts that is the accept deadline firing, as before R2
//!   (aegis-server c7c4cd4b, which no longer counts it): the conservative
//!   reading, so a test that sees no strike here sees none at either relay.
//!   A client reset, an EOF or the connection ending records nothing;
//! - the end of a connection aborting every stream task (grpc.rs:291).
//!
//! When a stalled stream's deadline and its connection's idle deadline are
//! the same instant (a stream on a connection with no authenticated stream),
//! the real server's outcome depends on task order; this relay lets the
//! stream's strike land first, the conservative reading for a client.
//!
//! Fault switches act on live connections (by accept index) or on the next
//! streams (relay-wide accept order), or on every later stream. A tap records
//! every control frame (RST_STREAM, SETTINGS, PING, GOAWAY, WINDOW_UPDATE) in
//! both directions, and (v34) each stream's send credit as the relay sees it
//! (`ConnStats::credit_high`). It also answers PolicyAcks, so a session's ACK
//! path (one stream per connection) and its pooled flows (S16h-6) share one
//! relay; the ACK-path tests keep the first-stream-only relay.
//! Nothing here is reachable from a production build or names a real relay.
use super::{
    garble, serve_target, AckReply, Handshake, HandshakeGauge, OuterTls, RelayIdentity, Target,
};
use aegis_core::{
    h2_stream::H2Stream,
    secure_channel::{
        self, grpc_io::GrpcIo, policy_ack, AdmissionLimits, AuthenticationFailure, Server,
        ServerSettings,
    },
};
use bytes::Bytes;
use h2::Reason;
use std::{
    collections::{HashMap, VecDeque},
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll, Waker},
    thread::{self, JoinHandle},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot, Notify},
    task::{AbortHandle, JoinSet},
    time::Instant,
};

/// aegis-server session/grpc.rs:209: streams per connection.
pub(crate) const MAX_CONCURRENT_STREAMS: u32 = 32;
/// grpc.rs:211-213: stream window, connection window and send buffer.
pub(crate) const WINDOW: u32 = 128 * 1024;
/// grpc.rs:214-216: the reset guards.
const RESET_GUARD: usize = 8;
/// aegis-core ServerSettings default `handshake_timeout_ms`.
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// aegis-server `limits.read_timeout_ms` default: TCP accept to outer TLS.
const READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Control-frame payload bytes the tap keeps.
const TAP_PAYLOAD: usize = 256;

/// H2 frame types the tap records.
pub(crate) mod frame_type {
    /// Not recorded; v34's credit ledger counts its length.
    pub(crate) const DATA: u8 = 0x0;
    pub(crate) const RST_STREAM: u8 = 0x3;
    pub(crate) const SETTINGS: u8 = 0x4;
    pub(crate) const PING: u8 = 0x6;
    pub(crate) const GOAWAY: u8 = 0x7;
    pub(crate) const WINDOW_UPDATE: u8 = 0x8;
}

#[derive(Clone)]
pub(crate) struct PoolConfig {
    /// https_bridge::ADMISSION_TIMEOUT.
    pub(crate) admission_timeout: Duration,
    /// The inner server's handshake timeout (origin + this).
    pub(crate) handshake_timeout: Duration,
    /// The PolicyAck answer; None ends an ACK request's stream unanswered.
    pub(crate) reply: Option<AckReply>,
    /// What serves an accepted Open after its status byte 0.
    pub(crate) target: Target,
    /// Waited after each TCP accept before outer TLS: a remote relay's
    /// connection setup, paid by every fresh connection.
    pub(crate) setup: Duration,
    /// Waited before each stream's 200: a remote relay's per-stream setup.
    pub(crate) stream_setup: Duration,
    /// Waited after a PolicyAck request is read, before its ACK.
    pub(crate) ack_delay: Duration,
    /// Only this many PolicyAcks are answered; later ones end unanswered.
    pub(crate) ack_limit: Option<usize>,
    /// Connections from this accept index on are held without a byte: the
    /// client stalls in outer TLS.
    pub(crate) silent_from: Option<usize>,
    /// The inner server `StreamFault::RejectDevice` handshakes with.
    pub(crate) rejecting: Option<Arc<Server>>,
    /// SETTINGS_MAX_CONCURRENT_STREAMS the relay advertises (and enforces)
    /// at its handshake; None advertises no limit (S16i-2).
    pub(crate) max_concurrent_streams: Option<u32>,
    /// Swallow the client's SETTINGS ACKs that answer a SETTINGS injected
    /// by `PooledRelay::advertise_streams`, which the relay's own H2 never
    /// sent and would refuse as unexpected (S16i-2).
    pub(crate) settings_injection: bool,
    /// The inner server's admission limits: by default aegis-core's 128
    /// sessions per peer beside relay-a's 32 handshakes per peer (the
    /// session's geometry since S16j-4 assumes them), or a deployed relay's
    /// in full, such as relay-a's 1024 sessions per peer since
    /// 2026-10-22 (S16i-2), or aegis-core's 16 handshakes per peer.
    pub(crate) inner_admission: AdmissionLimits,
    /// h2's `max_concurrent_reset_streams` (grpc.rs:214's 8, or a deployed
    /// relay's: relay-a runs 50).
    pub(crate) h2_reset_streams: usize,
    /// h2's `max_local_error_reset_streams` (grpc.rs:216's Some(8), or a
    /// deployed relay's: relay-a runs 1024). Past it the connection
    /// ends with GOAWAY ENHANCE_YOUR_CALM.
    pub(crate) h2_local_error_resets: Option<usize>,
    /// The connection window (grpc.rs:212's 128 KiB, or a deployed relay's:
    /// relay-a runs 4 MiB).
    pub(crate) h2_connection_window: u32,
}

/// relay-a's concurrent inner handshakes per peer IP (handoff
/// `capacity.max_handshakes_per_peer`, with R2), twice aegis-core's 16.
pub(crate) const DEPLOYED_HANDSHAKES_PER_PEER: usize = 32;

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            admission_timeout: super::ADMISSION_TIMEOUT,
            handshake_timeout: HANDSHAKE_TIMEOUT,
            reply: None,
            target: Target::Echo,
            setup: Duration::ZERO,
            stream_setup: Duration::ZERO,
            ack_delay: Duration::ZERO,
            ack_limit: None,
            silent_from: None,
            rejecting: None,
            max_concurrent_streams: Some(MAX_CONCURRENT_STREAMS),
            settings_injection: false,
            inner_admission: AdmissionLimits {
                max_handshakes_per_peer: DEPLOYED_HANDSHAKES_PER_PEER,
                ..AdmissionLimits::default()
            },
            h2_reset_streams: RESET_GUARD,
            h2_local_error_resets: Some(RESET_GUARD),
            h2_connection_window: WINDOW,
        }
    }
}

/// A per-stream fault, taken by the next stream or by one stream index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StreamFault {
    /// RST_STREAM with this reason instead of the 200.
    ResetBefore200(Reason),
    /// The 200, then the stream ends unanswered (as a full handshake cap).
    RefuseAfter200,
    /// Read the Open, never answer it, reset the stream at its deadline.
    HangTarget,
    /// Complete mTLS, then close the inner channel before any request.
    EndStreamAfterMtls,
    /// Accept the Open with status 0, then never read: uploads stall once
    /// the stream window and buffers fill.
    StallUpload,
    /// The stream inherits a deadline that has already passed, as when H2
    /// hands a stream over after its connection's idle deadline but before
    /// the idle timer fired.
    AcceptedPastDeadline,
    /// After the 200, wait until the stream's deadline before taking the
    /// handshake permit.
    DeadlinePassesAfter200,
    /// Answer the carrier request with this HTTP status and end the stream:
    /// an explicit carrier refusal.
    RejectCarrier(u16),
    /// Drop the whole connection when this stream's request arrives, with
    /// neither a response nor GOAWAY: a relay restart after outer TLS.
    DropConnection,
    /// After the 200, answer the inner ClientHello with a fatal
    /// bad_certificate alert: a refusal of the device, one strike.
    AlertInner,
    /// Run the inner handshake on `PoolConfig::rejecting`, which refuses the
    /// device certificate after the client's handshake completed: the
    /// client sees its channel end before the Open status. One strike.
    RejectDevice,
    /// After the 200, read the ClientHello and never answer it, as a path
    /// that froze for this stream: a strike at the stream's own deadline,
    /// none when the client ends the stream first.
    StallHandshake,
    /// Read the Open and end the stream without its status, as aegis-server
    /// does at its session cap.
    RefuseOpen,
    /// Read the Open and answer with a record that is not valid TLS.
    GarbleOpen,
    /// Read the Open and refuse it with status 1, as secure.rs does for a
    /// failed target connect (flushed, then the inner stream shut).
    RefuseTarget,
    /// Accept the Open with status 0, echo one chunk, then end the stream
    /// while the client may still be sending: a target that failed.
    TargetError,
    /// Accept the Open with status 0 and shut the inner stream at once (the
    /// target's FIN, forwarded), then keep reading the client's half; with
    /// no byte for `IDLE_END` end the stream, as aegis-server's
    /// copy_with_idle_timeout ends a silent half-closed channel.
    FinThenIdleEnd,
    /// Accept the Open with status 0, then read and discard every byte and
    /// never write: an upload whose only answers are window updates.
    SinkUpload,
}

/// `StreamFault::FinThenIdleEnd`'s idle timeout: aegis-server's 60 s,
/// shortened for tests.
pub(crate) const IDLE_END: Duration = Duration::from_millis(300);

/// Why a connection ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Close {
    /// Before H2 was established (outer TLS or the H2 handshake failed).
    Abandoned,
    /// The Activity idle rule: no live authenticated stream for the timeout.
    Idle,
    /// The client ended the connection.
    ClientEnded,
    /// A connection-level H2 or I/O error.
    Error,
    /// `drop_tcp`: closed without GOAWAY or TLS close_notify.
    DropTcp,
    /// After a `goaway` (an error GOAWAY at once, NO_ERROR when drained).
    GoAway,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StreamStep {
    Accepted,
    /// The stream's deadline had passed at its accept (ended unanswered) or
    /// at its handshake permit (ended after the 200): no strike.
    Expired,
    /// Not a gRPC POST to the carrier path: ended unanswered.
    Invalid,
    ResetBefore200,
    Responded,
    RefusedAfter200,
    /// The per-peer handshake cap was full: ended after the 200.
    HandshakeCapped,
    /// The inner accept failed with no strike (reset, EOF, TLS error).
    HandshakeFailed,
    /// The inner accept failed authentication class: one strike.
    Struck,
    Authenticated,
    EndedAfterMtls,
    /// The request was not read within the deadline or was malformed.
    EstablishFailed,
    TargetHung,
    Opened,
    /// The Open's target finished (echo EOF or error).
    Ended,
    Acked,
    AckRefused,
    /// A stream above a GOAWAY's last stream ID, refused or aborted.
    GoneAway,
    /// The carrier request was refused with an HTTP status.
    CarrierRejected,
    /// The connection was dropped at this stream's request.
    CarrierDropped,
    /// The inner handshake was refused with a TLS alert (a strike).
    Alerted,
    /// The ClientHello was read and left unanswered.
    HandshakeStalled,
    /// An Open was read and its stream ended without a status.
    OpenRefused,
    /// An Open was answered with a record that is not valid TLS.
    OpenGarbled,
    /// An Open was refused with status 1.
    TargetRefused,
    /// An accepted Open's stream was ended by the relay after one echo.
    TargetFailed,
    /// A half-closed channel ended by the relay's idle timeout.
    IdleEnded,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct StreamEvent {
    pub(crate) conn: usize,
    /// Relay-wide accept index.
    pub(crate) index: usize,
    pub(crate) id: u32,
    pub(crate) step: StreamStep,
    pub(crate) at: std::time::Instant,
}

/// One tapped control frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Frame {
    /// When this complete frame header crossed the relay's wire tap.
    pub(crate) at: std::time::Instant,
    pub(crate) from_client: bool,
    pub(crate) kind: u8,
    pub(crate) flags: u8,
    pub(crate) stream: u32,
    pub(crate) payload: Vec<u8>,
}

impl Frame {
    fn word(&self, at: usize) -> Option<u32> {
        let bytes = self.payload.get(at..at + 4)?;
        Some(u32::from_be_bytes(bytes.try_into().ok()?))
    }

    /// RST_STREAM or GOAWAY error code.
    pub(crate) fn reason(&self) -> Option<u32> {
        match self.kind {
            frame_type::RST_STREAM => self.word(0),
            frame_type::GOAWAY => self.word(4),
            _ => None,
        }
    }

    /// WINDOW_UPDATE increment.
    pub(crate) fn increment(&self) -> Option<u32> {
        (self.kind == frame_type::WINDOW_UPDATE)
            .then(|| self.word(0).map(|word| word & 0x7fff_ffff))
            .flatten()
    }

    /// SETTINGS entries (empty for an ACK).
    pub(crate) fn settings(&self) -> Vec<(u16, u32)> {
        if self.kind != frame_type::SETTINGS {
            return Vec::new();
        }
        self.payload
            .chunks_exact(6)
            .map(|entry| {
                (
                    u16::from_be_bytes([entry[0], entry[1]]),
                    u32::from_be_bytes([entry[2], entry[3], entry[4], entry[5]]),
                )
            })
            .collect()
    }

    pub(crate) fn is_ack(&self) -> bool {
        matches!(self.kind, frame_type::SETTINGS | frame_type::PING) && self.flags & 1 != 0
    }
}

/// One connection's counters, deadlines and tap.
#[derive(Default)]
pub(crate) struct ConnStats {
    live: AtomicUsize,
    high: AtomicUsize,
    frozen: AtomicBool,
    handshakes: Arc<HandshakeGauge>,
    last_completed: Mutex<Option<std::time::Instant>>,
    closed: Mutex<Option<(std::time::Instant, Close)>>,
    frames: Mutex<Vec<Frame>>,
    // v34: per stream, the relay's send credit beyond the client's
    // SETTINGS_INITIAL_WINDOW_SIZE as the relay sees it (the client's stream
    // WINDOW_UPDATEs read, less the DATA written), now and at its highest.
    credits: Mutex<HashMap<u32, (i64, i64)>>,
}

impl ConnStats {
    /// v34: the relay's send credit on `stream` at its highest: the
    /// client's initial stream window (`flow_pool::STREAM_WINDOW`, from its
    /// SETTINGS) plus its stream WINDOW_UPDATEs less the relay's DATA, as
    /// the tap saw them pass.
    pub(crate) fn credit_high(&self, stream: u32) -> i64 {
        let high = self
            .credits
            .lock()
            .unwrap()
            .get(&stream)
            .map_or(0, |(_, high)| *high);
        i64::from(crate::flow_pool::STREAM_WINDOW) + high
    }

    fn credit(&self, stream: u32, change: i64) {
        let mut credits = self.credits.lock().unwrap();
        let (now, high) = credits.entry(stream).or_insert((0, 0));
        *now += change;
        *high = (*high).max(*now);
    }
    /// Stream tasks running now.
    pub(crate) fn live_streams(&self) -> usize {
        self.live.load(Ordering::SeqCst)
    }

    /// The most stream tasks that ran at once.
    pub(crate) fn max_concurrent_streams(&self) -> usize {
        self.high.load(Ordering::SeqCst)
    }

    /// Streams between their 200 and the end of their inner handshake.
    pub(crate) fn handshakes(&self) -> &HandshakeGauge {
        &self.handshakes
    }

    pub(crate) fn is_frozen(&self) -> bool {
        self.frozen.load(Ordering::SeqCst)
    }

    /// When the last authenticated stream ended (the Activity `completed`).
    pub(crate) fn last_completed(&self) -> Option<std::time::Instant> {
        *self.last_completed.lock().unwrap()
    }

    /// When and why the connection ended; recorded after its stream tasks
    /// were aborted.
    pub(crate) fn closed(&self) -> Option<(std::time::Instant, Close)> {
        *self.closed.lock().unwrap()
    }

    pub(crate) fn frames(&self) -> Vec<Frame> {
        self.frames.lock().unwrap().clone()
    }

    /// Non-ACK SETTINGS frames from one side.
    pub(crate) fn settings(&self, from_client: bool) -> Vec<Vec<(u16, u32)>> {
        self.frames()
            .into_iter()
            .filter(|f| f.from_client == from_client && f.kind == frame_type::SETTINGS)
            .filter(|f| !f.is_ack())
            .map(|f| f.settings())
            .collect()
    }

    /// WINDOW_UPDATE frames from one side, as (stream, increment).
    pub(crate) fn window_updates(&self, from_client: bool) -> Vec<(u32, u32)> {
        self.frames()
            .into_iter()
            .filter(|f| f.from_client == from_client)
            .filter_map(|f| Some((f.stream, f.increment()?)))
            .collect()
    }

    /// RST_STREAM frames from one side, as (stream, error code).
    pub(crate) fn resets(&self, from_client: bool) -> Vec<(u32, u32)> {
        self.frames()
            .into_iter()
            .filter(|f| f.from_client == from_client && f.kind == frame_type::RST_STREAM)
            .filter_map(|f| Some((f.stream, f.reason()?)))
            .collect()
    }

    fn close(&self, close: Close) {
        self.closed
            .lock()
            .unwrap()
            .get_or_insert((std::time::Instant::now(), close));
    }
}

/// https_bridge.rs Activity: authenticated streams in flight and when the
/// last one ended.
#[derive(Clone)]
struct Activity {
    state: Arc<Mutex<(usize, Option<Instant>)>>,
    stats: Arc<ConnStats>,
}

struct ActivityGuard(Activity);

impl Activity {
    fn new(stats: Arc<ConnStats>) -> Self {
        Self {
            state: Arc::default(),
            stats,
        }
    }

    /// Called only after the device's inner mTLS was accepted.
    fn authenticated(&self) -> ActivityGuard {
        self.state.lock().unwrap().0 += 1;
        ActivityGuard(self.clone())
    }

    fn deadline_with_timeout(&self, initial: Instant, timeout: Duration) -> Option<Instant> {
        let (active, completed) = *self.state.lock().unwrap();
        if active > 0 {
            None
        } else {
            Some(completed.map_or(initial, |at| at + timeout))
        }
    }
}

impl Drop for ActivityGuard {
    fn drop(&mut self) {
        let now = Instant::now();
        let mut state = self.0.state.lock().unwrap();
        state.0 -= 1;
        state.1 = Some(now);
        *self.0.stats.last_completed.lock().unwrap() = Some(now.into_std());
    }
}

/// A stream task's place in its connection's live count.
struct LiveStream(Arc<ConnStats>);

impl LiveStream {
    fn start(stats: &Arc<ConnStats>) -> Self {
        let now = stats.live.fetch_add(1, Ordering::SeqCst) + 1;
        stats.high.fetch_max(now, Ordering::SeqCst);
        Self(stats.clone())
    }
}

impl Drop for LiveStream {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::SeqCst);
    }
}

enum Command {
    Freeze,
    GoAway(Reason, u32),
    DropTcp,
    Settings(u32),
}

#[derive(Default)]
struct Faults {
    next: VecDeque<StreamFault>,
    indexed: HashMap<usize, StreamFault>,
    // Taken by every stream with no other fault.
    always: Option<StreamFault>,
    // Extra waits before the 200 of one stream, by accept index.
    delays: HashMap<usize, Duration>,
}

struct Shared {
    config: PoolConfig,
    identity: Arc<RelayIdentity>,
    inner: Server,
    conns: AtomicUsize,
    streams: AtomicUsize,
    strikes: AtomicUsize,
    handshake_caps: AtomicUsize,
    session_caps: AtomicUsize,
    // PolicyAck requests read, and those answered.
    ack_requests: AtomicUsize,
    acks: AtomicUsize,
    handshakes: Arc<HandshakeGauge>,
    sessions: Arc<HandshakeGauge>,
    connections: Mutex<Vec<(Arc<ConnStats>, mpsc::UnboundedSender<Command>)>>,
    faults: Mutex<Faults>,
    events: Mutex<Vec<StreamEvent>>,
}

impl Shared {
    fn fault(&self, index: usize) -> Option<StreamFault> {
        let mut faults = self.faults.lock().unwrap();
        faults
            .indexed
            .remove(&index)
            .or_else(|| faults.next.pop_front())
            .or(faults.always)
    }

    fn delay(&self, index: usize) -> Duration {
        let mut faults = self.faults.lock().unwrap();
        faults.delays.remove(&index).unwrap_or_default()
    }

    fn event(&self, conn: usize, index: usize, id: u32, step: StreamStep) {
        self.events.lock().unwrap().push(StreamEvent {
            conn,
            index,
            id,
            step,
            at: std::time::Instant::now(),
        });
    }
}

/// The multi-stream relay on its own thread and current-thread runtime.
pub(crate) struct PooledRelay {
    address: SocketAddr,
    shared: Arc<Shared>,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl PooledRelay {
    pub(crate) fn spawn(
        listener: std::net::TcpListener,
        identity: RelayIdentity,
        config: PoolConfig,
    ) -> Self {
        let address = listener.local_addr().unwrap();
        let inner = identity.inner_server(config.handshake_timeout, &config.inner_admission);
        let shared = Arc::new(Shared {
            config,
            identity: Arc::new(identity),
            inner,
            conns: AtomicUsize::new(0),
            streams: AtomicUsize::new(0),
            strikes: AtomicUsize::new(0),
            handshake_caps: AtomicUsize::new(0),
            session_caps: AtomicUsize::new(0),
            ack_requests: AtomicUsize::new(0),
            acks: AtomicUsize::new(0),
            handshakes: Arc::default(),
            sessions: Arc::default(),
            connections: Mutex::default(),
            faults: Mutex::default(),
            events: Mutex::default(),
        });
        let relay = shared.clone();
        let (shutdown, mut stop) = oneshot::channel::<()>();
        let thread = thread::Builder::new()
            .name("aegis-ne-test-relay-pool".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async move {
                    let listener = TcpListener::from_std(listener).unwrap();
                    let mut served = Vec::new();
                    loop {
                        tokio::select! {
                            _ = &mut stop => break,
                            accepted = listener.accept() => {
                                let Ok((tcp, peer)) = accepted else { continue };
                                let index = relay.conns.fetch_add(1, Ordering::SeqCst);
                                let stats = Arc::new(ConnStats::default());
                                let (control, commands) = mpsc::unbounded_channel();
                                relay.connections.lock().unwrap().push((stats.clone(), control));
                                served.push(tokio::spawn(serve_connection(
                                    tcp,
                                    peer.ip(),
                                    index,
                                    relay.clone(),
                                    stats,
                                    commands,
                                )));
                            }
                        }
                    }
                    for task in &served {
                        task.abort();
                    }
                });
            })
            .unwrap();
        Self {
            address,
            shared,
            shutdown: Some(shutdown),
            thread: Some(thread),
        }
    }

    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    /// TCP connections accepted.
    pub(crate) fn conns(&self) -> usize {
        self.shared.conns.load(Ordering::SeqCst)
    }

    /// H2 requests accepted, on every connection.
    pub(crate) fn streams(&self) -> usize {
        self.shared.streams.load(Ordering::SeqCst)
    }

    /// Authentication-class inner accept failures (the server's
    /// `record_failure`).
    pub(crate) fn strikes(&self) -> usize {
        self.shared.strikes.load(Ordering::SeqCst)
    }

    /// Streams ended after their 200 because the per-peer handshake cap was
    /// full.
    pub(crate) fn handshake_caps(&self) -> usize {
        self.shared.handshake_caps.load(Ordering::SeqCst)
    }

    /// Streams between their 200 and the end of their inner handshake, on
    /// every connection.
    pub(crate) fn handshakes(&self) -> &HandshakeGauge {
        &self.shared.handshakes
    }

    /// Streams ended after their inner mTLS because the per-peer session
    /// cap was full (also recorded `StreamStep::HandshakeCapped`).
    pub(crate) fn session_caps(&self) -> usize {
        self.shared.session_caps.load(Ordering::SeqCst)
    }

    /// Inner sessions held (from `try_acquire_session` until the stream
    /// ends), on every connection.
    pub(crate) fn sessions(&self) -> &HandshakeGauge {
        &self.shared.sessions
    }

    pub(crate) fn connection(&self, conn: usize) -> Arc<ConnStats> {
        self.shared.connections.lock().unwrap()[conn].0.clone()
    }

    pub(crate) fn events(&self) -> Vec<StreamEvent> {
        self.shared.events.lock().unwrap().clone()
    }

    /// PolicyAcks answered.
    pub(crate) fn acks(&self) -> usize {
        self.shared.acks.load(Ordering::SeqCst)
    }

    /// Streams that recorded `step`, on every connection.
    pub(crate) fn count(&self, step: StreamStep) -> usize {
        self.events()
            .iter()
            .filter(|event| event.step == step)
            .count()
    }

    /// Wait until `n` streams recorded `step`; returns when the last did.
    pub(crate) async fn wait_count(
        &self,
        step: StreamStep,
        n: usize,
        budget: Duration,
    ) -> Option<std::time::Instant> {
        wait_until(budget, || {
            let at: Vec<_> = self
                .events()
                .into_iter()
                .filter(|event| event.step == step)
                .map(|event| event.at)
                .collect();
            (at.len() >= n).then(|| at[n - 1])
        })
        .await
    }

    /// Steps recorded for the stream with relay-wide accept index `index`.
    pub(crate) fn steps(&self, index: usize) -> Vec<StreamStep> {
        self.events()
            .into_iter()
            .filter(|event| event.index == index)
            .map(|event| event.step)
            .collect()
    }

    /// RST_STREAM(STREAM_CLOSED) frames the relay's H2 library sent, on
    /// every connection: frames that reached a stream it already closed.
    pub(crate) fn stream_closed_resets(&self) -> usize {
        let closed = u32::from(Reason::STREAM_CLOSED);
        let connections = self.shared.connections.lock().unwrap();
        connections
            .iter()
            .map(|(stats, _)| {
                stats
                    .resets(false)
                    .iter()
                    .filter(|(_, reason)| *reason == closed)
                    .count()
            })
            .sum()
    }

    fn command(&self, conn: usize, command: Command) {
        let connections = self.shared.connections.lock().unwrap();
        let _ = connections[conn].1.send(command);
    }

    /// Stop reading and writing on `conn` and never close it: no FIN, no
    /// GOAWAY, no idle close. Its stream tasks keep running (their deadlines
    /// and strikes still apply), but nothing they write leaves.
    pub(crate) fn freeze(&self, conn: usize) {
        self.command(conn, Command::Freeze);
    }

    /// Send GOAWAY(`last_id`, `reason`) on `conn` at the next frame boundary.
    /// Streams above `last_id` are aborted and new ones refused. NO_ERROR
    /// keeps the others and closes once they end; any other reason closes
    /// the connection as soon as the frame is flushed. Either close ends as
    /// h2's own GOAWAY path does: TLS close_notify, then the FIN.
    pub(crate) fn goaway(&self, conn: usize, reason: Reason, last_id: u32) {
        self.command(conn, Command::GoAway(reason, last_id));
    }

    /// Close `conn`'s TCP socket at once: no GOAWAY, no TLS close_notify.
    pub(crate) fn drop_tcp(&self, conn: usize) {
        self.command(conn, Command::DropTcp);
    }

    /// Send a second SETTINGS frame on `conn` advertising `max` concurrent
    /// streams to the client (S16i-2), at the next frame boundary; the
    /// relay's own H2 keeps enforcing its handshake value. Needs
    /// `PoolConfig::settings_injection`, which swallows the client's ACK.
    pub(crate) fn advertise_streams(&self, conn: usize, max: u32) {
        assert!(self.shared.config.settings_injection);
        self.command(conn, Command::Settings(max));
    }

    fn next(&self, n: usize, fault: StreamFault) {
        let mut faults = self.shared.faults.lock().unwrap();
        faults.next.extend(std::iter::repeat_n(fault, n));
    }

    pub(crate) fn reset_before_200(&self, n: usize, reason: Reason) {
        self.next(n, StreamFault::ResetBefore200(reason));
    }

    pub(crate) fn refuse_after_200(&self, n: usize) {
        self.next(n, StreamFault::RefuseAfter200);
    }

    pub(crate) fn hang_target(&self, n: usize) {
        self.next(n, StreamFault::HangTarget);
    }

    pub(crate) fn end_stream_after_mtls(&self, n: usize) {
        self.next(n, StreamFault::EndStreamAfterMtls);
    }

    pub(crate) fn accept_past_deadline(&self, n: usize) {
        self.next(n, StreamFault::AcceptedPastDeadline);
    }

    pub(crate) fn deadline_passes_after_200(&self, n: usize) {
        self.next(n, StreamFault::DeadlinePassesAfter200);
    }

    /// Stall the uploads of the stream with relay-wide accept index `index`.
    pub(crate) fn stall_upload(&self, index: usize) {
        self.at(index, StreamFault::StallUpload);
    }

    /// `fault` for the stream with relay-wide accept index `index`.
    pub(crate) fn at(&self, index: usize, fault: StreamFault) {
        let mut faults = self.shared.faults.lock().unwrap();
        faults.indexed.insert(index, fault);
    }

    /// Hold the 200 of the stream with relay-wide accept index `index` for
    /// `delay` more than `PoolConfig::stream_setup`, as a lost HEADERS
    /// segment retransmitted after an RTO; its inherited deadline does not
    /// move.
    pub(crate) fn delay_200(&self, index: usize, delay: Duration) {
        self.shared
            .faults
            .lock()
            .unwrap()
            .delays
            .insert(index, delay);
    }

    /// `fault` for the next `n` streams.
    pub(crate) fn next_streams(&self, n: usize, fault: StreamFault) {
        self.next(n, fault);
    }

    /// `fault` for every later stream that has no other fault (None: none).
    pub(crate) fn always(&self, fault: Option<StreamFault>) {
        self.shared.faults.lock().unwrap().always = fault;
    }

    /// Wait until `conn` has ended; returns when and why. Async, so the
    /// client's own tasks keep running on the waiting runtime.
    pub(crate) async fn wait_closed(
        &self,
        conn: usize,
        budget: Duration,
    ) -> Option<(std::time::Instant, Close)> {
        let stats = self.connection(conn);
        wait_until(budget, || stats.closed()).await
    }

    /// Wait until stream `index` has recorded `step`; returns when.
    pub(crate) async fn wait_step(
        &self,
        index: usize,
        step: StreamStep,
        budget: Duration,
    ) -> Option<std::time::Instant> {
        wait_until(budget, || {
            self.events()
                .into_iter()
                .find(|event| event.index == index && event.step == step)
                .map(|event| event.at)
        })
        .await
    }
}

impl Drop for PooledRelay {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Poll `probe` every few milliseconds until it answers or `budget` ends,
/// without blocking the caller's runtime.
pub(crate) async fn wait_until<T>(
    budget: Duration,
    mut probe: impl FnMut() -> Option<T>,
) -> Option<T> {
    let deadline = std::time::Instant::now() + budget;
    loop {
        if let Some(found) = probe() {
            return Some(found);
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

impl RelayIdentity {
    /// The inner server of this identity with `timeout` as its handshake
    /// timeout (aegis-core's default is 5 s) and `admission` as its limits.
    fn inner_server(&self, timeout: Duration, admission: &AdmissionLimits) -> Server {
        Server::load(&ServerSettings {
            device_registry: None,
            cert: self.dir.join("server.pem"),
            key: self.dir.join("server.key"),
            client_ca: self.dir.join("client-ca.pem"),
            allowed_client_sha256: vec![self.allowed_client_sha256.clone()],
            admission: admission.clone(),
            handshake_timeout_ms: u64::try_from(timeout.as_millis()).unwrap(),
            idle_timeout_ms: 2_000,
        })
        .unwrap()
    }
}

/// session/grpc.rs:203-216 in https_bridge mode: no extended CONNECT.
/// The fixture relay serves its connections with the same limits.
pub(crate) fn builder() -> h2::server::Builder {
    builder_for(&PoolConfig::default())
}

/// `builder` with `config`'s H2 limits: its advertised (and enforced)
/// MAX_CONCURRENT_STREAMS (None: no limit), reset guards and connection
/// window.
pub(crate) fn builder_for(config: &PoolConfig) -> h2::server::Builder {
    let mut builder = h2::server::Builder::new();
    if let Some(max) = config.max_concurrent_streams {
        builder.max_concurrent_streams(max);
    }
    builder
        .max_header_list_size(8192)
        .initial_window_size(WINDOW)
        .initial_connection_window_size(config.h2_connection_window)
        .max_send_buffer_size(WINDOW as usize)
        .max_concurrent_reset_streams(config.h2_reset_streams)
        .max_pending_accept_reset_streams(RESET_GUARD)
        .max_local_error_reset_streams(config.h2_local_error_resets);
    builder
}

/// SETTINGS_MAX_CONCURRENT_STREAMS (RFC 9113 6.5.2).
pub(crate) const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;

fn settings_frame(max_streams: u32) -> Vec<u8> {
    let mut frame = vec![0, 0, 6, frame_type::SETTINGS, 0, 0, 0, 0, 0];
    frame.extend_from_slice(&SETTINGS_MAX_CONCURRENT_STREAMS.to_be_bytes());
    frame.extend_from_slice(&max_streams.to_be_bytes());
    frame
}

fn goaway_frame(reason: Reason, last_id: u32) -> Vec<u8> {
    let mut frame = vec![0, 0, 8, frame_type::GOAWAY, 0, 0, 0, 0, 0];
    frame.extend_from_slice(&(last_id & 0x7fff_ffff).to_be_bytes());
    frame.extend_from_slice(&u32::from(reason).to_be_bytes());
    frame
}

async fn serve_connection(
    tcp: TcpStream,
    peer: IpAddr,
    conn: usize,
    shared: Arc<Shared>,
    stats: Arc<ConnStats>,
    mut commands: mpsc::UnboundedReceiver<Command>,
) {
    if shared.config.silent_from.is_some_and(|from| conn >= from) {
        let _held = tcp;
        std::future::pending::<()>().await;
        return;
    }
    tokio::time::sleep(shared.config.setup).await;
    let Ok(Ok(outer)) = tokio::time::timeout(READ_TIMEOUT, shared.identity.outer.accept(tcp)).await
    else {
        stats.close(Close::Abandoned);
        return;
    };
    // grpc.rs:143-145: https_bridge bounds the admission to the timeout.
    let timeout = shared.config.admission_timeout;
    let initial = Instant::now() + timeout;
    let tap = Arc::new(WireTap {
        stats: stats.clone(),
        inject: Mutex::default(),
        waker: Mutex::default(),
        flushed: Notify::new(),
        close: AtomicBool::new(false),
        closed: Notify::new(),
        swallow_acks: AtomicUsize::new(0),
    });
    let mut wire = Wire::new(outer, tap.clone());
    if shared.config.settings_injection {
        wire.acks = Some(AckFilter::new());
    }
    let handshake = builder_for(&shared.config).handshake::<_, Bytes>(wire);
    let Ok(Ok(mut connection)) = tokio::time::timeout_at(initial, handshake).await else {
        stats.close(Close::Abandoned);
        return;
    };
    let activity = Activity::new(stats.clone());
    let mut requests = JoinSet::new();
    let mut ids: Vec<(u32, usize, AbortHandle)> = Vec::new();
    // (last stream ID, graceful) once a GOAWAY is queued; flushed once sent.
    let mut goaway: Option<(u32, bool)> = None;
    let mut flushed = false;
    let mut commands_open = true;
    let close = loop {
        if let Some((_, graceful)) = goaway {
            if flushed && (!graceful || stats.live_streams() == 0) {
                // As h2's own GOAWAY path: TLS close_notify, then the FIN.
                tap.close();
                let closing = async {
                    loop {
                        tokio::select! {
                            _ = tap.closed.notified() => break,
                            accepted = connection.accept() => {
                                if !matches!(accepted, Some(Ok(_))) {
                                    break;
                                }
                            }
                        }
                    }
                };
                let _ = tokio::time::timeout(Duration::from_secs(1), closing).await;
                break Close::GoAway;
            }
        }
        let deadline = activity.deadline_with_timeout(initial, timeout);
        tokio::select! {
            biased;
            command = commands.recv(), if commands_open => match command {
                Some(Command::Freeze) => {
                    stats.frozen.store(true, Ordering::SeqCst);
                    // Hold the socket, the H2 state and every stream task.
                    let _held = (&mut connection, &mut requests);
                    std::future::pending::<()>().await;
                }
                Some(Command::DropTcp) => break Close::DropTcp,
                Some(Command::Settings(max)) => {
                    // Swallowed before it can arrive: the relay's H2 never
                    // sent this SETTINGS and would refuse its ACK.
                    tap.swallow_acks.fetch_add(1, Ordering::SeqCst);
                    tap.inject(settings_frame(max));
                }
                Some(Command::GoAway(reason, last_id)) => {
                    tap.inject(goaway_frame(reason, last_id));
                    for (id, index, task) in &ids {
                        if *id > last_id && !task.is_finished() {
                            task.abort();
                            shared.event(conn, *index, *id, StreamStep::GoneAway);
                        }
                    }
                    goaway = Some((last_id, reason == Reason::NO_ERROR));
                }
                None => commands_open = false,
            },
            _ = tap.flushed.notified(), if goaway.is_some() && !flushed => flushed = true,
            _ = tokio::time::sleep_until(deadline.unwrap_or(initial)), if deadline.is_some() => {
                // Authentication may complete between computing the deadline
                // and the timer; only a live authenticated stream suspends it.
                if activity
                    .deadline_with_timeout(initial, timeout)
                    .is_some_and(|at| Instant::now() >= at)
                {
                    break Close::Idle;
                }
            }
            accepted = connection.accept() => {
                let (request, mut respond) = match accepted {
                    Some(Ok(request)) => request,
                    Some(Err(_)) => break Close::Error,
                    None => break Close::ClientEnded,
                };
                let index = shared.streams.fetch_add(1, Ordering::SeqCst);
                let id = u32::from(respond.stream_id());
                shared.event(conn, index, id, StreamStep::Accepted);
                if goaway.is_some_and(|(last_id, _)| id > last_id) {
                    respond.send_reset(Reason::REFUSED_STREAM);
                    shared.event(conn, index, id, StreamStep::GoneAway);
                    continue;
                }
                // grpc.rs:260: the stream inherits the connection's deadline.
                let fault = shared.fault(index);
                if fault == Some(StreamFault::DropConnection) {
                    shared.event(conn, index, id, StreamStep::CarrierDropped);
                    break Close::DropTcp;
                }
                let inherited = if fault == Some(StreamFault::AcceptedPastDeadline) {
                    Instant::now()
                } else {
                    deadline.unwrap_or_else(|| Instant::now() + timeout)
                };
                let stream = StreamContext {
                    conn,
                    index,
                    id,
                    peer,
                    inherited,
                    fault,
                    shared: shared.clone(),
                    activity: activity.clone(),
                    stats: stats.clone(),
                    _live: LiveStream::start(&stats),
                };
                let task = requests.spawn(serve_stream(request, respond, stream));
                ids.push((id, index, task));
            }
            _ = requests.join_next(), if !requests.is_empty() => {}
        }
    };
    // A stream whose deadline is this same instant records its strike first.
    tokio::task::yield_now().await;
    // grpc.rs:291: the connection's end aborts every stream task.
    requests.shutdown().await;
    stats.close(close);
    // Neither GOAWAY nor close_notify: the TCP socket simply closes.
    drop(connection);
}

struct StreamContext {
    conn: usize,
    index: usize,
    id: u32,
    peer: IpAddr,
    inherited: Instant,
    fault: Option<StreamFault>,
    shared: Arc<Shared>,
    activity: Activity,
    stats: Arc<ConnStats>,
    _live: LiveStream,
}

impl StreamContext {
    fn event(&self, step: StreamStep) {
        self.shared.event(self.conn, self.index, self.id, step);
    }
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, AuthenticationFailure::Timeout)
}

async fn serve_stream(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    stream: StreamContext,
) {
    // grpc.rs:347: `admission.check_deadline()?` before any response.
    if Instant::now() >= stream.inherited {
        stream.event(StreamStep::Expired);
        return;
    }
    // secure.rs:36-43: a gRPC POST on the carrier path.
    let valid = request.method() == http::Method::POST
        && request.uri().path() == secure_channel::GRPC_PATH
        && request
            .headers()
            .get("content-type")
            .is_some_and(|value| value == "application/grpc");
    if !valid {
        stream.event(StreamStep::Invalid);
        return;
    }
    if let Some(StreamFault::ResetBefore200(reason)) = stream.fault {
        respond.send_reset(reason);
        stream.event(StreamStep::ResetBefore200);
        return;
    }
    let delay = stream.shared.delay(stream.index);
    tokio::time::sleep(stream.shared.config.stream_setup + delay).await;
    if let Some(StreamFault::RejectCarrier(status)) = stream.fault {
        let refusal = http::Response::builder().status(status).body(()).unwrap();
        let _ = respond.send_response(refusal, true);
        stream.event(StreamStep::CarrierRejected);
        // Let the refusal reach the client before the stream task ends.
        tokio::time::sleep(Duration::from_millis(100)).await;
        return;
    }
    // secure.rs:44-49: the 200 goes out before any admission.
    let response = http::Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .body(())
        .unwrap();
    let Ok(send) = respond.send_response(response, false) else {
        return;
    };
    stream.event(StreamStep::Responded);
    let carrier = GrpcIo::new(H2Stream::new(send, request.into_body()));
    if stream.fault == Some(StreamFault::RefuseAfter200) {
        stream.event(StreamStep::RefusedAfter200);
        return;
    }
    if stream.fault == Some(StreamFault::DeadlinePassesAfter200) {
        tokio::time::sleep_until(stream.inherited).await;
    }
    let inner = &stream.shared.inner;
    // secure.rs:131-137: the handshake permit, then the stream's deadline.
    let Ok(permit) = inner.try_acquire_handshake(Some(stream.peer)) else {
        stream.shared.handshake_caps.fetch_add(1, Ordering::SeqCst);
        stream.event(StreamStep::HandshakeCapped);
        return;
    };
    let origin = Instant::now();
    let deadline = stream.inherited.min(origin + inner.handshake_timeout());
    // secure.rs:148: `authentication_deadline()?` returns before the accept
    // and its `record_failure`.
    if Instant::now() >= deadline {
        stream.event(StreamStep::Expired);
        return;
    }
    let mut relay_handshake = Handshake::start(&stream.shared.handshakes);
    let mut conn_handshake = Handshake::start(&stream.stats.handshakes);
    let mut carrier = carrier;
    match stream.fault {
        Some(StreamFault::AlertInner) => {
            // TLS record: alert, legacy version 3.3, length 2, fatal,
            // bad_certificate (42), in answer to the ClientHello.
            let mut hello = [0u8; 512];
            let _ = carrier.read(&mut hello).await;
            let _ = carrier
                .write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x2a])
                .await;
            let _ = carrier.flush().await;
            relay_handshake.end();
            conn_handshake.end();
            stream.shared.strikes.fetch_add(1, Ordering::SeqCst);
            stream.event(StreamStep::Alerted);
            // Let the alert reach the client before the stream ends.
            tokio::time::sleep(Duration::from_millis(500)).await;
            return;
        }
        Some(StreamFault::RejectDevice) => {
            let rejecting = stream.shared.config.rejecting.clone().unwrap();
            let refused = tokio::time::timeout_at(deadline, rejecting.accept(carrier)).await;
            relay_handshake.end();
            conn_handshake.end();
            assert!(
                !matches!(refused, Ok(Ok(_))),
                "the foreign device CA admitted the device"
            );
            stream.shared.strikes.fetch_add(1, Ordering::SeqCst);
            stream.event(StreamStep::Alerted);
            tokio::time::sleep(Duration::from_millis(500)).await;
            return;
        }
        Some(StreamFault::StallHandshake) => {
            stream.event(StreamStep::HandshakeStalled);
            // Read until the client ends the stream; never answer.
            let mut sink = [0u8; 2048];
            let ended = tokio::time::timeout_at(deadline, async {
                while matches!(carrier.read(&mut sink).await, Ok(read) if read > 0) {}
            })
            .await;
            relay_handshake.end();
            conn_handshake.end();
            if ended.is_ok() {
                stream.event(StreamStep::HandshakeFailed);
            } else {
                stream.shared.strikes.fetch_add(1, Ordering::SeqCst);
                stream.event(StreamStep::Struck);
            }
            return;
        }
        _ => {}
    }
    let accepted = tokio::time::timeout_at(deadline, inner.accept_with_lease(carrier))
        .await
        .unwrap_or_else(|_| Err(timed_out()))
        .and_then(|accepted| {
            if Instant::now() >= deadline {
                Err(timed_out())
            } else {
                Ok(accepted)
            }
        });
    relay_handshake.end();
    conn_handshake.end();
    let mut inner_tls = match accepted {
        Ok((inner_tls, _lease)) => inner_tls,
        Err(error) => {
            // secure.rs:160-167: only an authentication-class failure is
            // charged to the peer.
            if AuthenticationFailure::from_io(&error).is_some() {
                stream.shared.strikes.fetch_add(1, Ordering::SeqCst);
                stream.event(StreamStep::Struck);
            } else {
                stream.event(StreamStep::HandshakeFailed);
            }
            return;
        }
    };
    let Ok(_session) = inner.try_acquire_session(Some(stream.peer)) else {
        stream.shared.session_caps.fetch_add(1, Ordering::SeqCst);
        stream.event(StreamStep::HandshakeCapped);
        return;
    };
    let _held = Handshake::start(&stream.shared.sessions);
    if Instant::now() >= deadline {
        stream.event(StreamStep::EstablishFailed);
        return;
    }
    drop(permit);
    let _activity = stream.activity.authenticated();
    stream.event(StreamStep::Authenticated);
    if stream.fault == Some(StreamFault::EndStreamAfterMtls) {
        let _ = inner_tls.shutdown().await;
        stream.event(StreamStep::EndedAfterMtls);
        return;
    }
    let read = tokio::time::timeout_at(deadline, policy_ack::read_request(&mut inner_tls)).await;
    let Ok(Ok(request)) = read else {
        stream.event(StreamStep::EstablishFailed);
        return;
    };
    match request {
        policy_ack::ChannelRequest::Open(open) => {
            match stream.fault {
                Some(StreamFault::HangTarget) => {
                    // secure.rs:189-278: the target connect shares the
                    // deadline; at it the stream ends with no status.
                    tokio::time::sleep_until(deadline).await;
                    stream.event(StreamStep::TargetHung);
                    return;
                }
                Some(StreamFault::RefuseOpen) => {
                    stream.event(StreamStep::OpenRefused);
                    return;
                }
                Some(StreamFault::GarbleOpen) => {
                    garble(&mut inner_tls).await;
                    stream.event(StreamStep::OpenGarbled);
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    return;
                }
                Some(StreamFault::RefuseTarget) => {
                    // secure.rs:257-266: status 1, flushed, then shut.
                    let _ = inner_tls.write_u8(1).await;
                    let _ = inner_tls.flush().await;
                    let _ = inner_tls.shutdown().await;
                    stream.event(StreamStep::TargetRefused);
                    return;
                }
                Some(StreamFault::TargetError) => {
                    stream.event(StreamStep::Opened);
                    if inner_tls.write_u8(0).await.is_ok() && inner_tls.flush().await.is_ok() {
                        let mut chunk = [0u8; 4096];
                        if let Ok(read @ 1..) = inner_tls.read(&mut chunk).await {
                            let _ = inner_tls.write_all(&chunk[..read]).await;
                            let _ = inner_tls.flush().await;
                        }
                        let _ = inner_tls.shutdown().await;
                    }
                    stream.event(StreamStep::TargetFailed);
                    return;
                }
                Some(StreamFault::SinkUpload) => {
                    stream.event(StreamStep::Opened);
                    if inner_tls.write_u8(0).await.is_ok() && inner_tls.flush().await.is_ok() {
                        let mut sink = vec![0u8; 16 * 1024];
                        while let Ok(1..) = inner_tls.read(&mut sink).await {}
                    }
                    stream.event(StreamStep::Ended);
                    return;
                }
                Some(StreamFault::FinThenIdleEnd) => {
                    stream.event(StreamStep::Opened);
                    if inner_tls.write_u8(0).await.is_ok() && inner_tls.flush().await.is_ok() {
                        let _ = inner_tls.shutdown().await;
                        let mut sink = [0u8; 4096];
                        let idle = async {
                            loop {
                                match tokio::time::timeout(IDLE_END, inner_tls.read(&mut sink))
                                    .await
                                {
                                    Ok(Ok(1..)) => {}
                                    Ok(_) => return false,
                                    Err(_) => return true,
                                }
                            }
                        };
                        if idle.await {
                            stream.event(StreamStep::IdleEnded);
                            return;
                        }
                    }
                    stream.event(StreamStep::Ended);
                    return;
                }
                _ => {}
            }
            let target = if stream.fault == Some(StreamFault::StallUpload) {
                Target::Stall
            } else {
                stream.shared.config.target
            };
            stream.event(StreamStep::Opened);
            serve_target(&mut inner_tls, &open, target).await;
            stream.event(StreamStep::Ended);
        }
        policy_ack::ChannelRequest::PolicyAck(request) => match &stream.shared.config.reply {
            Some(reply)
                if stream.shared.config.ack_limit.is_none_or(|limit| {
                    stream.shared.ack_requests.fetch_add(1, Ordering::SeqCst) < limit
                }) =>
            {
                tokio::time::sleep(stream.shared.config.ack_delay).await;
                let ack = reply.clone().ack(request.nonce);
                if policy_ack::write_ack(&mut inner_tls, &ack).await.is_ok() {
                    let _ = inner_tls.shutdown().await;
                    stream.shared.acks.fetch_add(1, Ordering::SeqCst);
                    stream.event(StreamStep::Acked);
                }
            }
            _ => stream.event(StreamStep::AckRefused),
        },
    }
}

/// The outer TLS stream under the relay's H2 connection, with the tap and a
/// frame injector. Injected bytes are written only where everything H2 has
/// written so far ends on a frame boundary.
struct Wire {
    io: OuterTls,
    tap: Arc<WireTap>,
    read: FrameParser,
    write: FrameParser,
    out: Vec<u8>,
    notify: bool,
    shut: bool,
    // `PoolConfig::settings_injection`: the client's bytes pass through
    // this filter before the relay's H2 reads them.
    acks: Option<AckFilter>,
}

struct WireTap {
    stats: Arc<ConnStats>,
    inject: Mutex<Vec<u8>>,
    waker: Mutex<Option<Waker>>,
    /// Notified once injected bytes were written and flushed.
    flushed: Notify,
    close: AtomicBool,
    /// Notified once the TLS stream was shut after a requested close.
    closed: Notify,
    /// Client SETTINGS ACKs still to swallow (`advertise_streams`).
    swallow_acks: AtomicUsize,
}

impl WireTap {
    fn wake(&self) {
        if let Some(waker) = self.waker.lock().unwrap().take() {
            waker.wake();
        }
    }

    fn inject(&self, frame: Vec<u8>) {
        self.inject.lock().unwrap().extend(frame);
        self.wake();
    }

    /// Shut the TLS stream (close_notify, FIN) at the next frame boundary.
    fn close(&self) {
        self.close.store(true, Ordering::SeqCst);
        self.wake();
    }
}

impl Wire {
    fn new(io: OuterTls, tap: Arc<WireTap>) -> Self {
        Self {
            io,
            tap,
            // The client's connection preface precedes its first frame.
            read: FrameParser::new(true, 24),
            write: FrameParser::new(false, 0),
            out: Vec::new(),
            notify: false,
            shut: false,
            acks: None,
        }
    }

    /// Move queued injections out and flush them; Ready when nothing waits.
    fn pump(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write.at_boundary() {
            let injected = std::mem::take(&mut *self.tap.inject.lock().unwrap());
            if !injected.is_empty() {
                self.write.feed(&injected, &self.tap.stats);
                self.out.extend(injected);
                self.notify = true;
            }
        }
        while !self.out.is_empty() {
            let written = std::task::ready!(Pin::new(&mut self.io).poll_write(cx, &self.out))?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.out.drain(..written);
        }
        if self.notify {
            std::task::ready!(Pin::new(&mut self.io).poll_flush(cx))?;
            self.notify = false;
            self.tap.flushed.notify_one();
        }
        if !self.shut && self.write.at_boundary() && self.tap.close.load(Ordering::SeqCst) {
            std::task::ready!(Pin::new(&mut self.io).poll_shutdown(cx))?;
            self.shut = true;
            self.tap.closed.notify_one();
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for Wire {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        *this.tap.waker.lock().unwrap() = Some(cx.waker().clone());
        if let Poll::Ready(Err(error)) = this.pump(cx) {
            return Poll::Ready(Err(error));
        }
        let Some(acks) = this.acks.as_mut() else {
            let before = buf.filled().len();
            std::task::ready!(Pin::new(&mut this.io).poll_read(cx, buf))?;
            this.read.feed(&buf.filled()[before..], &this.tap.stats);
            return Poll::Ready(Ok(()));
        };
        loop {
            if !acks.pending.is_empty() {
                let take = acks.pending.len().min(buf.remaining());
                buf.put_slice(&acks.pending[..take]);
                acks.pending.drain(..take);
                return Poll::Ready(Ok(()));
            }
            let mut chunk = [0u8; 16 * 1024];
            let mut read = ReadBuf::new(&mut chunk);
            std::task::ready!(Pin::new(&mut this.io).poll_read(cx, &mut read))?;
            let bytes = read.filled();
            if bytes.is_empty() {
                return Poll::Ready(Ok(()));
            }
            this.read.feed(bytes, &this.tap.stats);
            acks.filter(bytes, &this.tap.swallow_acks);
        }
    }
}

impl AsyncWrite for Wire {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        std::task::ready!(this.pump(cx))?;
        let written = std::task::ready!(Pin::new(&mut this.io).poll_write(cx, buf))?;
        this.write.feed(&buf[..written], &this.tap.stats);
        Poll::Ready(Ok(written))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.pump(cx))?;
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.pump(cx))?;
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

/// The client's byte stream with every SETTINGS ACK the relay's H2 never
/// asked for removed (`WireTap::swallow_acks`), frame by frame; whatever
/// else arrives passes on unchanged, in order.
struct AckFilter {
    // The client's connection preface precedes its first frame.
    preface: usize,
    header: [u8; 9],
    have: usize,
    // Payload bytes of the current frame still to pass on.
    remaining: usize,
    // Bytes ready for the relay's H2.
    pending: Vec<u8>,
}

impl AckFilter {
    fn new() -> Self {
        Self {
            preface: 24,
            header: [0; 9],
            have: 0,
            remaining: 0,
            pending: Vec::new(),
        }
    }

    fn filter(&mut self, mut bytes: &[u8], swallow: &AtomicUsize) {
        while !bytes.is_empty() {
            if self.preface > 0 || self.remaining > 0 {
                let left = if self.preface > 0 {
                    &mut self.preface
                } else {
                    &mut self.remaining
                };
                let take = (*left).min(bytes.len());
                *left -= take;
                self.pending.extend_from_slice(&bytes[..take]);
                bytes = &bytes[take..];
                continue;
            }
            let take = (9 - self.have).min(bytes.len());
            self.header[self.have..self.have + take].copy_from_slice(&bytes[..take]);
            self.have += take;
            bytes = &bytes[take..];
            if self.have < 9 {
                continue;
            }
            self.have = 0;
            let header = self.header;
            let length =
                usize::from(header[0]) << 16 | usize::from(header[1]) << 8 | usize::from(header[2]);
            let ack = header[3] == frame_type::SETTINGS && header[4] & 1 != 0 && length == 0;
            let swallowed = ack
                && swallow
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                    .is_ok();
            if !swallowed {
                self.pending.extend_from_slice(&header);
            }
            self.remaining = length;
        }
    }
}

/// An incremental H2 frame splitter for one direction of the byte stream.
struct FrameParser {
    from_client: bool,
    preface: usize,
    header: [u8; 9],
    have: usize,
    remaining: usize,
    current: Option<(Frame, bool)>,
}

impl FrameParser {
    fn new(from_client: bool, preface: usize) -> Self {
        Self {
            from_client,
            preface,
            header: [0; 9],
            have: 0,
            remaining: 0,
            current: None,
        }
    }

    /// Everything fed so far ends a whole frame.
    fn at_boundary(&self) -> bool {
        self.preface == 0 && self.have == 0 && self.current.is_none()
    }

    fn feed(&mut self, mut bytes: &[u8], stats: &ConnStats) {
        while !bytes.is_empty() {
            if self.preface > 0 {
                let skip = self.preface.min(bytes.len());
                self.preface -= skip;
                bytes = &bytes[skip..];
                continue;
            }
            if self.current.is_none() {
                let take = (9 - self.have).min(bytes.len());
                self.header[self.have..self.have + take].copy_from_slice(&bytes[..take]);
                self.have += take;
                bytes = &bytes[take..];
                if self.have < 9 {
                    continue;
                }
                self.have = 0;
                let header = self.header;
                let kind = header[3];
                let keep = matches!(
                    kind,
                    frame_type::RST_STREAM
                        | frame_type::SETTINGS
                        | frame_type::PING
                        | frame_type::GOAWAY
                        | frame_type::WINDOW_UPDATE
                );
                self.remaining = usize::from(header[0]) << 16
                    | usize::from(header[1]) << 8
                    | usize::from(header[2]);
                let frame = Frame {
                    at: std::time::Instant::now(),
                    from_client: self.from_client,
                    kind,
                    flags: header[4],
                    stream: u32::from_be_bytes([header[5], header[6], header[7], header[8]])
                        & 0x7fff_ffff,
                    payload: Vec::new(),
                };
                // v34: the relay's DATA spends its credit on that stream.
                if !self.from_client && kind == frame_type::DATA && frame.stream != 0 {
                    stats.credit(
                        frame.stream,
                        -i64::try_from(self.remaining).unwrap_or(i64::MAX),
                    );
                }
                self.current = Some((frame, keep));
            } else {
                let take = self.remaining.min(bytes.len());
                if let Some((frame, true)) = &mut self.current {
                    let room = TAP_PAYLOAD.saturating_sub(frame.payload.len());
                    frame.payload.extend_from_slice(&bytes[..take.min(room)]);
                }
                self.remaining -= take;
                bytes = &bytes[take..];
            }
            if self.remaining == 0 {
                if let Some((frame, keep)) = self.current.take() {
                    // v34: a client's stream WINDOW_UPDATE adds to it.
                    if frame.from_client && frame.stream != 0 {
                        if let Some(increment) = frame.increment() {
                            stats.credit(frame.stream, i64::from(increment));
                        }
                    }
                    if keep {
                        stats.frames.lock().unwrap().push(frame);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "test_relay_pool_tests.rs"]
mod tests;
