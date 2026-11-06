//! B-06 v34/v35: the adaptive receive window of a pooled flow's stream.
//!
//! v33 held every stream to SETTINGS_INITIAL_WINDOW_SIZE ([`STREAM_WINDOW`],
//! 128 KiB): one stream moved at most one window per round trip, about
//! 4 Mbit/s at the relay's 185 ms. v34 let a window-limited stream grow its
//! own window through the vendored h2's `FlowControl::grow_window`
//! ([`WindowPolicy`], an aegis-core `RecvWindowPolicy`). SETTINGS stays
//! 131072 on the wire, so every new, idle or slow stream keeps v33's
//! window. v35 judges growth by the delay the stream's credit spends in its
//! loop, not by a share of the window.
//!
//! The signal (v35), measured over at least [`EVAL_RTTS`] of the
//! connection's least round trip ([`ConnWindow::rtt`]): at each release the
//! credit the stream held just before it (the relay's credit, the bytes h2
//! holds unread and the bytes released) is integrated over the time since
//! the release before ([`CreditLoop`]). By Little's law the credit held
//! over the bytes released is the time a byte of credit spends in the loop
//! (announced, sent, queued, received, read), and less the round trip it is
//! the credit-loop delay `q`: the relay's send buffer behind its congestion
//! window, any network queue, head-of-line holds and a slow reader. h2
//! announces a stream's credit only once half the credit the peer holds is
//! free again, so a stream that its window alone holds keeps `q` near a
//! sixth of a round trip.
//!
//! The rule ([`WindowPolicy::decide`]):
//!
//! - It grows only while `q` was at most [`q_grow`] (`min(60 ms, RTT/3)`,
//!   that is, it delivered at least 3/4 of the credit it held per round
//!   trip, and at most 60 ms of queue) on each of its last
//!   [`GROW_HISTORY`] measurements, to twice what it delivered per round
//!   trip (at least [`STREAM_WINDOW`], at most [`STREAM_WINDOW_MAX`]), only
//!   when that is more than its window, while no other stream of its
//!   connection has a step in flight ([`ConnWindow`]'s step token), and only
//!   as far as the session's budget covers the step ([`PoolWindow`],
//!   [`GROW_BUDGET`]); a step the budget cannot cover is refused whole. A
//!   grown stream yields the token while a stream of its connection still
//!   at [`STREAM_WINDOW`] waits for it (v35 review), so every stream there
//!   takes its first step before any takes another; after that the token
//!   goes to whichever stream's measurement ends first.
//! - A step is judged one round trip after it, over the next measurement:
//!   unless the rate rose by at least a tenth (or half the step's share of
//!   the window, for a small last step), the step is given back and the
//!   stream holds, growing no more for [`HOLD_RTTS`] round trips
//!   ([`raised`]).
//! - `q` at least [`Q_SHRINK`] on [`STANDING_HISTORY`] measurements in a row
//!   returns a grown window to [`STREAM_WINDOW`] (a standing queue); the
//!   history starts over, so it grows again only after [`GROW_HISTORY`]
//!   fresh measurements. Within [`AFTER_STEP`] measurements of a step kept
//!   at its judgment that step made the queue: the stream also holds.
//! - `q` above [`q_grow`] on [`FROZEN_HISTORY`] measurements in a row gives
//!   back what the latest measurement says the window overshot: the window
//!   scaled by the round trip plus [`q_grow`] over the measured loop time
//!   ([`frozen_target`]: back to the zone's lower edge), at least
//!   [`FROZEN_LEAST`], and the stream holds. No grown window sits in the 60
//!   to 120 ms zone for long, and one
//!   whose last step overshot a bottleneck keeps the part that still fills
//!   it (h2 lets the relay's credit fall to 2/3 of the window between
//!   announcements, so a window that keeps a bottleneck busy holds about
//!   5/4 of its bandwidth-delay product, q about a quarter round trip).
//! - A measurement the stream under-used (under a quarter of its window per
//!   round trip: an idle gap, a reader that slowed) judges no step and never
//!   enters the history; [`RECLAIM_RTTS`] of them in a row give the extra
//!   back (an idle time counts as every round trip it spans).
//! - A window lowered by h2's `shrink_window` takes effect as the relay uses
//!   its credit: HTTP/2 cannot revoke credit already announced. The budget
//!   is credited only once the relay's credit and the bytes h2 holds unread
//!   are back within the lowered window. A dropped stream returns
//!   everything.
//! - In [`WindowMode::Fixed`] (v35: the A/B's control arm; v36: the product
//!   default, the adaptive rule above only on `--window-policy adaptive`)
//!   every measurement, mark and line is the same and no step is ever
//!   taken: v33's window.
//!
//! The round trip is the least the connection ever measured: its outer TLS
//! handshake, each carrier request to its 200 and each PING to its PONG,
//! over its life (at most `MAX_CONN_AGE`), and at least [`RTT_FLOOR`]. Data
//! queued at the relay delays the 200s and PONGs behind it but never lowers
//! that minimum (B-06 v34 critic A).
//!
//! A stream is judged by what it releases, and H2Stream releases a chunk as
//! the bridge takes it. Memory stays inside the budget: what a stream may
//! hold, its credit still to come and the bytes h2 holds unread, is never
//! more than [`STREAM_WINDOW`] plus what it is charged (at most
//! [`STREAM_WINDOW_MAX`] in all), and a session's charges never exceed
//! [`GROW_BUDGET`].
//!
//! Telemetry, stable lines of at most four fields, no address:
//! `pool_window grown:<n> max_kib:<k> budget_kib:<used>-<total> denied:<n>`
//! and, per connection, `pool_rtt conn:<id> min_ms:<n> srtt_ms:<n>
//! last_ms:<n>` with `pool_queue conn:<id> q_ms:<n> held_kib:<n>
//! extra_kib:<n>` (v35: its latest bulk measurement's `q`, and the sums of
//! its live streams' latest mean credit held and extras), each at most once
//! per `POOL_STATE_EVERY` while a connection carries a bulk flow or the
//! budget is in use; and at the end of each flow that moved at least
//! [`BULK_BYTES`], `flow_bulk conn:<id> kib:<n> ms:<n> win_kib:<n>` and
//! (v35) `flow_queue conn:<id> q_bins:<lo>-<mid>-<hi> grows:<n>
//! resets:<after_step>-<standing>`: its measurements by zone, its growth
//! steps, and its returns to [`STREAM_WINDOW`] (those a kept step caused,
//! and the others).
use crate::configuration::WindowMode;
use crate::flow_log::POOL_STATE_EVERY;
use crate::flow_pool::{CONN_WINDOW, STREAMS_CAP, STREAM_WINDOW};
use aegis_core::h2_stream::{RecvWindow, RecvWindowPolicy, WindowStep};
#[cfg(test)]
use std::sync::atomic::AtomicBool;
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, MutexGuard, PoisonError,
    },
    time::Duration,
};
use tokio::time::Instant;

/// The most one stream's receive window grows to. At 185 ms about
/// 34 Mbit/s for one stream, where the packet engine's own limits start.
pub(crate) const STREAM_WINDOW_MAX: u32 = 1_048_576;
/// What a session's streams may grow by at once, in all: the connection
/// window less a stream window for every stream a connection may hold and
/// two more, so even with the whole budget on one connection the
/// connection window is never what a stream waits for (S16j-1).
pub(crate) const GROW_BUDGET: u32 = CONN_WINDOW - (STREAMS_CAP as u32 + 2) * STREAM_WINDOW;
/// The least round trip the rule uses: on a LAN or loopback a window is
/// judged over at least this long.
pub(crate) const RTT_FLOOR: Duration = Duration::from_millis(20);
/// Round trips each measurement spans, at least.
pub(crate) const EVAL_RTTS: u32 = 2;
/// Under-used round trips in a row after which a stream gives its extra back.
pub(crate) const RECLAIM_RTTS: u32 = 8;
/// Round trips a stream holds after a step that did not raise its rate, or
/// whose queue made it give the step back (v35).
pub(crate) const HOLD_RTTS: u32 = 64;
/// A flow that released at least this much logs `flow_bulk` and
/// `flow_queue` lines.
pub(crate) const BULK_BYTES: u64 = 1_048_576;
/// A stream released at least this many bytes per second over a
/// measurement: its connection carries a bulk flow ([`ConnWindow::bulk`]).
pub(crate) const BULK_RATE: u64 = 131_072;
/// How long a connection counts as carrying a bulk flow after the last
/// measurement that showed one, and (v35) as queued after the last bulk
/// measurement whose `q` stood ([`ConnWindow::queued`]).
pub(crate) const BULK_HOLD: Duration = Duration::from_secs(2);
/// v35: the most credit-loop delay under which a window may grow, on a
/// long round trip ([`q_grow`]).
pub(crate) const Q_GROW_MAX: Duration = Duration::from_millis(60);
/// v35: a credit-loop delay at least this long on [`STANDING_HISTORY`]
/// measurements in a row is a standing queue: a grown window returns to
/// [`STREAM_WINDOW`]. A connection whose latest bulk measurement stood so
/// is queued for placement ([`ConnWindow::queued`]).
pub(crate) const Q_SHRINK: Duration = Duration::from_millis(120);
/// v35: measurements in a row at most [`q_grow`] before a step.
pub(crate) const GROW_HISTORY: u32 = 3;
/// v35: measurements in a row at least [`Q_SHRINK`] that return a grown
/// window to [`STREAM_WINDOW`].
pub(crate) const STANDING_HISTORY: u32 = 2;
/// v35 (critic REQUIRED 7): measurements in a row above [`q_grow`] after
/// which a grown window gives back what its queue says it overshot
/// ([`frozen_target`]).
pub(crate) const FROZEN_HISTORY: u32 = 4;
/// v35: the least a give-back from the 60 to 120 ms zone returns (one DATA
/// frame), so the zone's give-backs always end.
pub(crate) const FROZEN_LEAST: u32 = 16 * 1024;
/// v35 (critic REQUIRED 6): a return to [`STREAM_WINDOW`] within this many
/// measurements of a step kept at its judgment was that step's own queue.
pub(crate) const AFTER_STEP: u64 = 2;
/// v35: the longest a connection's step token stays claimed: the step's
/// settling round trip, its measurement, and one more.
pub(crate) const STEP_RTTS: u32 = EVAL_RTTS + 2;

// Under-used: less than 1/4 of the window per round trip.
const UNDER: (u64, u64) = (1, 4);
// A step raised the rate: by at least a tenth.
const GAIN: (u64, u64) = (11, 10);

// The memory bound: every live flow's v33 window and the whole budget (a
// stream's credit and unread bytes stay within its window and its charge,
// `WindowPolicy::settle`).
const _: () = assert!(
    crate::establish_limit::LIVE_FLOWS_MAX as u64 * STREAM_WINDOW as u64 + GROW_BUDGET as u64
        <= 40 * 1024 * 1024
);
// One stream at the maximum fits the budget.
const _: () = assert!(STREAM_WINDOW_MAX <= GROW_BUDGET);
const _: () = assert!(STREAM_WINDOW < STREAM_WINDOW_MAX);
// h2's largest window, with every byte of a maximal window unreleased.
const _: () = assert!((STREAM_WINDOW_MAX as u64) * 2 < (1 << 31));
const _: () = assert!(GROW_BUDGET == 7 * 1024 * 1024);
// v35: a standing queue is at least twice the most a window grows under,
// so the zone between them is where a window neither grows nor resets.
const _: () = assert!(Q_SHRINK.as_micros() >= 2 * Q_GROW_MAX.as_micros());
const _: () = assert!(FROZEN_HISTORY > STANDING_HISTORY);
const _: () = assert!(STEP_RTTS > EVAL_RTTS + 1);

/// v35: the most credit-loop delay a window grows under at round trip
/// `rtt`: a third of it (the stream delivered at least 3/4 of the credit it
/// held per round trip), at most [`Q_GROW_MAX`].
pub(crate) fn q_grow(rtt: Duration) -> Duration {
    Q_GROW_MAX.min(rtt / 3)
}

/// v35: the window a grown `window` returns to from the 60 to 120 ms zone,
/// after a measurement `credit` at round trip `rtt`: scaled by the round
/// trip plus [`q_grow`] over the measured loop time (held / bytes): the
/// window whose credit would leave the zone's lower edge,
/// exactly in integers, never below [`STREAM_WINDOW`] or above `window`.
pub(crate) fn frozen_target(window: u32, credit: CreditLoop, rtt: Duration) -> u32 {
    if credit.held == 0 || credit.bytes == 0 {
        return window;
    }
    let goal = u128::from(micros(rtt)) + u128::from(micros(q_grow(rtt)));
    let scaled = u128::from(window) * u128::from(credit.bytes) * goal / credit.held;
    u32::try_from(scaled.min(u128::from(window)))
        .unwrap_or(window)
        .max(STREAM_WINDOW)
}

/// Whether a stream that delivered `delivered` bytes per round trip uses
/// under a quarter of window `window`.
fn under_used(delivered: u64, window: u32) -> bool {
    delivered * UNDER.1 < u64::from(window) * UNDER.0
}

/// Whether a step that added `added` to window `window` raised the
/// delivered rate from `before` to `after`: by a tenth, or by half the
/// step's share of the window when that is less (a step clamped at the
/// maximum can raise a window-bound stream's rate only by its own share).
fn raised(before: u64, after: u64, (added, window): (u32, u32)) -> bool {
    let (after, before) = (u128::from(after), u128::from(before));
    let (added, window) = (u128::from(added), u128::from(window).max(1));
    let gain = u128::from(GAIN.0 - GAIN.1);
    let whole = u128::from(GAIN.1);
    if added * whole >= window * 2 * gain {
        after * whole >= before * (whole + gain)
    } else {
        after * window * 2 >= before * (window * 2 + added)
    }
}

fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

fn millis(us: u64) -> u64 {
    us / 1_000
}

/// `bytes` released over `elapsed`, per round trip `rtt`.
fn per_rtt(bytes: u64, rtt: Duration, elapsed: Duration) -> u64 {
    let elapsed = elapsed.as_nanos().max(1);
    u64::try_from(u128::from(bytes) * rtt.as_nanos() / elapsed).unwrap_or(u64::MAX)
}

/// `bytes` released over `elapsed`, per second.
fn per_second(bytes: u64, elapsed: Duration) -> u64 {
    per_rtt(bytes, Duration::from_secs(1), elapsed)
}

/// v35: where one measurement's credit-loop delay lies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Zone {
    /// At most [`q_grow`]: the window binds, it may grow.
    Low,
    /// Between: no growth, no reset.
    Mid,
    /// At least [`Q_SHRINK`]: a queue.
    High,
}

/// v35: one measurement's credit loop, by Little's law: the credit the
/// stream held, integrated over time, and the bytes it released.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CreditLoop {
    /// Credit held, in byte-microseconds: at each release, the credit held
    /// just before it (the relay's credit, the bytes h2 holds unread and the
    /// bytes released) times the time since the release before.
    pub(crate) held: u128,
    /// Bytes released over it.
    pub(crate) bytes: u64,
    /// Its span, in microseconds.
    pub(crate) elapsed_us: u64,
}

impl CreditLoop {
    /// The time a byte of credit spent in the loop, in microseconds (none
    /// released: unbounded).
    fn loop_us(&self) -> u128 {
        match self.bytes {
            0 => u128::MAX,
            bytes => self.held / u128::from(bytes),
        }
    }

    /// Its credit-loop delay `q` at round trip `rtt`, in microseconds: the
    /// loop's time less the round trip, at least 0.
    pub(crate) fn delay_us(&self, rtt: Duration) -> u64 {
        u64::try_from(self.loop_us().saturating_sub(u128::from(micros(rtt)))).unwrap_or(u64::MAX)
    }

    /// The credit it held on average, in bytes.
    pub(crate) fn mean_held(&self) -> u64 {
        u64::try_from(self.held / u128::from(self.elapsed_us.max(1))).unwrap_or(u64::MAX)
    }

    /// Its zone at round trip `rtt`, compared exactly in integers: low when
    /// `3 x held <= 4 x bytes x rtt` (q at most a third of the round trip)
    /// and `held <= bytes x (rtt + Q_GROW_MAX)`; high when `held >= bytes x
    /// (rtt + Q_SHRINK)`.
    pub(crate) fn zone(&self, rtt: Duration) -> Zone {
        let (held, bytes) = (self.held, u128::from(self.bytes));
        let rtt = u128::from(micros(rtt));
        if bytes == 0 || held >= bytes * (rtt + u128::from(micros(Q_SHRINK))) {
            Zone::High
        } else if 3 * held <= 4 * bytes * rtt
            && held <= bytes * (rtt + u128::from(micros(Q_GROW_MAX)))
        {
            Zone::Low
        } else {
            Zone::Mid
        }
    }
}

/// Where the window's lines go: the epoch's flow log in production
/// (`EstablishLimiter`), a list in tests.
pub(crate) trait WindowLog: Send + Sync {
    fn line(&self, event: &str, fields: &[&str]);
}

impl WindowLog for crate::establish_limit::EstablishLimiter {
    fn line(&self, event: &str, fields: &[&str]) {
        self.flow_fields(event, fields);
    }
}

/// One pooled connection's round trips and load, as the window rule and its
/// telemetry read them. Held by the connection's `Liveness`, which feeds it
/// every round-trip sample it takes.
pub(crate) struct ConnWindow {
    base: Instant,
    // Its pool ID plus one once it joined a pool (0: none).
    id: AtomicU64,
    // The least round-trip sample, in microseconds (u64::MAX: none).
    min_us: AtomicU64,
    // Its smoothed round trip as `Liveness` last computed it.
    srtt_us: AtomicU64,
    // The latest round-trip sample since its last `pool_rtt` line (0: none):
    // a carrier's 200 or a PONG.
    latest_us: AtomicU64,
    // It carries a bulk flow until then, in microseconds after `base` (0:
    // never).
    bulk_us: AtomicU64,
    // Its last `pool_rtt` line, in microseconds after `base` plus one (0:
    // none).
    logged_us: AtomicU64,
    // v35: the latest credit-loop delay of a bulk measurement on it, in
    // microseconds, and when, in microseconds after `base` plus one (0:
    // none).
    queue_us: AtomicU64,
    queue_at: AtomicU64,
    // v35: its live streams' latest mean credit held and extras, in bytes.
    held_sum: AtomicU64,
    extra_sum: AtomicU64,
    // v35: its step token, claimed until then, in microseconds after `base`
    // plus one (0: free).
    step_until: AtomicU64,
    // v35 review: a stream at `STREAM_WINDOW` found the token held and
    // waits for it until then, in microseconds after `base` plus one (0:
    // none).
    base_wanted: AtomicU64,
    // Test-only: the rule's round trip follows the smoothed one, as the
    // rejected v34 design had it (critic A).
    #[cfg(test)]
    follow_srtt: AtomicBool,
}

impl Default for ConnWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnWindow {
    pub(crate) fn new() -> Self {
        Self {
            base: Instant::now(),
            id: AtomicU64::new(0),
            min_us: AtomicU64::new(u64::MAX),
            srtt_us: AtomicU64::new(0),
            latest_us: AtomicU64::new(0),
            bulk_us: AtomicU64::new(0),
            logged_us: AtomicU64::new(0),
            queue_us: AtomicU64::new(0),
            queue_at: AtomicU64::new(0),
            held_sum: AtomicU64::new(0),
            extra_sum: AtomicU64::new(0),
            step_until: AtomicU64::new(0),
            base_wanted: AtomicU64::new(0),
            #[cfg(test)]
            follow_srtt: AtomicBool::new(false),
        }
    }

    fn since_base(&self, at: Instant) -> u64 {
        micros(at.saturating_duration_since(self.base))
    }

    /// One round-trip `sample`, after which its smoothed round trip is
    /// `srtt` (`Liveness::seed_rtt`, `Liveness::sample_rtt`).
    pub(crate) fn sample(&self, sample: Duration, srtt: Duration) {
        let us = micros(sample).max(1);
        self.min_us.fetch_min(us, Ordering::SeqCst);
        self.latest_us.store(us, Ordering::SeqCst);
        self.srtt_us.store(micros(srtt), Ordering::SeqCst);
    }

    /// Test-only: its smoothed round trip changed without a sample.
    #[cfg(test)]
    pub(crate) fn set_srtt(&self, srtt: Duration) {
        self.srtt_us.store(micros(srtt), Ordering::SeqCst);
    }

    /// The least round trip it measured (none: None).
    pub(crate) fn min_rtt(&self) -> Option<Duration> {
        match self.min_us.load(Ordering::SeqCst) {
            u64::MAX => None,
            us => Some(Duration::from_micros(us)),
        }
    }

    /// The round trip the window rule judges by: its least, at least
    /// `RTT_FLOOR` (the floor when it has none).
    pub(crate) fn rtt(&self) -> Duration {
        #[cfg(test)]
        if self.follow_srtt.load(Ordering::SeqCst) {
            let srtt = Duration::from_micros(self.srtt_us.load(Ordering::SeqCst));
            return srtt.max(RTT_FLOOR);
        }
        self.min_rtt().map_or(RTT_FLOOR, |min| min.max(RTT_FLOOR))
    }

    /// Test-only: the rule's round trip follows the smoothed one, which
    /// grows with the data queued ahead of the 200s and PONGs (critic A).
    #[cfg(test)]
    pub(crate) fn follow_srtt_for_test(&self) {
        self.follow_srtt.store(true, Ordering::SeqCst);
    }

    /// It joined a pool as connection `id`.
    pub(crate) fn set_id(&self, id: u64) {
        self.id.store(id.saturating_add(1), Ordering::SeqCst);
    }

    /// Its pool ID (none: None).
    pub(crate) fn id(&self) -> Option<u64> {
        match self.id.load(Ordering::SeqCst) {
            0 => None,
            id => Some(id - 1),
        }
    }

    fn id_field(&self) -> String {
        self.id()
            .map_or_else(|| "conn:none".to_owned(), |id| format!("conn:{id}"))
    }

    /// A stream on it carried a bulk flow as of `now`. A mark whose
    /// `BULK_HOLD` ended before this connection existed marks nothing.
    pub(crate) fn mark_bulk(&self, now: Instant) {
        let until = self.since_base(now + BULK_HOLD);
        if until > 0 {
            self.bulk_us.fetch_max(until, Ordering::SeqCst);
        }
    }

    /// Whether it carries a bulk flow at `now`: a stream on it released at
    /// least `BULK_RATE` over a measurement within `BULK_HOLD`.
    pub(crate) fn bulk(&self, now: Instant) -> bool {
        match self.bulk_us.load(Ordering::SeqCst) {
            0 => false,
            until => self.since_base(now) < until,
        }
    }

    /// v35: a bulk measurement of a stream on it, one the stream did not
    /// under-use, ended at `now` with credit-loop delay `q_us`.
    pub(crate) fn note_queue(&self, q_us: u64, now: Instant) {
        self.queue_us.store(q_us, Ordering::SeqCst);
        self.queue_at
            .store(self.since_base(now).saturating_add(1), Ordering::SeqCst);
    }

    /// v35: whether it is queued at `now`: its latest bulk measurement's
    /// credit-loop delay was at least [`Q_SHRINK`], within `BULK_HOLD`. A new
    /// flow goes elsewhere while another connection has a free slot.
    pub(crate) fn queued(&self, now: Instant) -> bool {
        let at = self.queue_at.load(Ordering::SeqCst);
        at != 0
            && self.since_base(now).saturating_add(1).saturating_sub(at) < micros(BULK_HOLD)
            && self.queue_us.load(Ordering::SeqCst) >= micros(Q_SHRINK)
    }

    /// v35: one stream's share of the sums moved from `from` to `to`
    /// (mean credit held, extra).
    fn moved_sums(&self, from: (u64, u64), to: (u64, u64)) {
        for (sum, from, to) in [
            (&self.held_sum, from.0, to.0),
            (&self.extra_sum, from.1, to.1),
        ] {
            if to >= from {
                sum.fetch_add(to - from, Ordering::SeqCst);
            } else {
                sum.fetch_sub(from - to, Ordering::SeqCst);
            }
        }
    }

    /// v35: claims its step token at `now` for `span`, unless another
    /// stream holds it; the token to release, or None.
    fn claim_step(&self, now: Instant, span: Duration) -> Option<u64> {
        let at = self.since_base(now).saturating_add(1);
        let until = at.saturating_add(micros(span).max(1));
        let current = self.step_until.load(Ordering::SeqCst);
        if current != 0 && current > at {
            return None;
        }
        self.step_until
            .compare_exchange(current, until, Ordering::SeqCst, Ordering::SeqCst)
            .ok()
            .map(|_| until)
    }

    /// v35: releases `token`, unless it ran out and another stream claimed
    /// the token since.
    fn release_step(&self, token: u64) {
        let _ = self
            .step_until
            .compare_exchange(token, 0, Ordering::SeqCst, Ordering::SeqCst);
    }

    /// v35 review: a stream still at `STREAM_WINDOW` found the token held
    /// at `now`; for `span` a grown stream yields the token to it. Its
    /// mark, to drop once it claims the token.
    fn want_step(&self, now: Instant, span: Duration) -> u64 {
        let until = self
            .since_base(now)
            .saturating_add(1)
            .saturating_add(micros(span).max(1));
        self.base_wanted.fetch_max(until, Ordering::SeqCst);
        until
    }

    /// v35 review: whether a stream still at `STREAM_WINDOW` waits for the
    /// token at `now`.
    fn step_wanted(&self, now: Instant) -> bool {
        let until = self.base_wanted.load(Ordering::SeqCst);
        until != 0 && until > self.since_base(now).saturating_add(1)
    }

    /// v35 review: drops the mark `mark`, unless a later one replaced it.
    fn drop_want(&self, mark: u64) {
        let _ = self
            .base_wanted
            .compare_exchange(mark, 0, Ordering::SeqCst, Ordering::SeqCst);
    }

    /// Its `pool_rtt` and (v35) `pool_queue` lines at `now`, at most once
    /// per `POOL_STATE_EVERY`; `last_ms` (the latest sample since the line
    /// before: a carrier's 200 or a PONG, never only PINGs) only when it
    /// took one.
    fn rtt_lines(&self, now: Instant) -> Option<[Vec<String>; 2]> {
        let at = self.since_base(now).saturating_add(1);
        let last = self.logged_us.load(Ordering::SeqCst);
        if last != 0 && at.saturating_sub(last) < micros(POOL_STATE_EVERY) {
            return None;
        }
        self.logged_us
            .compare_exchange(last, at, Ordering::SeqCst, Ordering::SeqCst)
            .ok()?;
        let min = self.min_us.load(Ordering::SeqCst);
        let mut rtt = vec![
            self.id_field(),
            format!("min_ms:{}", if min == u64::MAX { 0 } else { millis(min) }),
            format!("srtt_ms:{}", millis(self.srtt_us.load(Ordering::SeqCst))),
        ];
        match self.latest_us.swap(0, Ordering::SeqCst) {
            0 => {}
            latest => rtt.push(format!("last_ms:{}", millis(latest))),
        }
        let q = match self.queue_at.load(Ordering::SeqCst) {
            0 => "q_ms:none".to_owned(),
            _ => format!("q_ms:{}", millis(self.queue_us.load(Ordering::SeqCst))),
        };
        let queue = vec![
            self.id_field(),
            q,
            format!(
                "held_kib:{}",
                self.held_sum.load(Ordering::SeqCst).div_ceil(1024)
            ),
            format!(
                "extra_kib:{}",
                self.extra_sum.load(Ordering::SeqCst).div_ceil(1024)
            ),
        ];
        Some([rtt, queue])
    }
}

/// Test-only: the counts of a pool's windows, as `pool_window` lines report
/// them.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct WindowStats {
    /// Live streams whose window is above `STREAM_WINDOW` now.
    pub(crate) grown: usize,
    /// The largest window of a live stream now (`STREAM_WINDOW` when none
    /// grew).
    pub(crate) largest: u32,
    /// Budget bytes held now: extras, and extras given back whose bytes
    /// the stream may still hold (the relay's credit, h2's unread bytes).
    pub(crate) used: u32,
    /// The session's budget.
    pub(crate) budget: u32,
    /// Growth steps the budget refused.
    pub(crate) denied: u64,
    /// The largest window ever granted.
    pub(crate) high: u32,
    /// The most budget ever held at once.
    pub(crate) high_used: u32,
}

#[derive(Default)]
struct PoolWindowState {
    used: u32,
    // The windows above `STREAM_WINDOW` of live streams, and how many
    // streams hold each.
    grown: BTreeMap<u32, usize>,
    // The largest window granted since the last `pool_window` line.
    peak: u32,
    high: u32,
    high_used: u32,
    denied: u64,
    logged: Option<Instant>,
}

impl PoolWindowState {
    fn largest(&self) -> u32 {
        self.grown
            .keys()
            .next_back()
            .copied()
            .unwrap_or(STREAM_WINDOW)
    }
}

/// The window budget of one session's flow pool ([`GROW_BUDGET`]), the
/// counts of its streams' windows, and (v35) the start's window mode.
pub(crate) struct PoolWindow {
    budget: u32,
    mode: WindowMode,
    state: Mutex<PoolWindowState>,
    log: Arc<dyn WindowLog>,
    // Test-only: every step is kept: no judgment gives a step back, and
    // (v35) no queue does either, as the rejected v34 design had it (critic
    // A).
    #[cfg(test)]
    no_hold: AtomicBool,
}

impl PoolWindow {
    /// v35: a pool window whose streams receive by `mode`.
    pub(crate) fn new_with_mode(mode: WindowMode, log: Arc<dyn WindowLog>) -> Arc<Self> {
        Self::with_budget_and_mode(GROW_BUDGET, mode, log)
    }

    /// Test-only: a pool window whose budget is `budget`.
    #[cfg(test)]
    pub(crate) fn with_budget(budget: u32, log: Arc<dyn WindowLog>) -> Arc<Self> {
        Self::with_budget_and_mode(budget, WindowMode::Adaptive, log)
    }

    fn with_budget_and_mode(budget: u32, mode: WindowMode, log: Arc<dyn WindowLog>) -> Arc<Self> {
        Arc::new(Self {
            budget,
            mode,
            state: Mutex::default(),
            log,
            #[cfg(test)]
            no_hold: AtomicBool::new(false),
        })
    }

    /// v35: how its streams receive.
    pub(crate) fn mode(&self) -> WindowMode {
        self.mode
    }

    fn lock(&self) -> MutexGuard<'_, PoolWindowState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Test-only: every step is kept.
    #[cfg(test)]
    pub(crate) fn no_hold_for_test(&self) {
        self.no_hold.store(true, Ordering::SeqCst);
    }

    fn holds(&self) -> bool {
        #[cfg(test)]
        if self.no_hold.load(Ordering::SeqCst) {
            return false;
        }
        true
    }

    /// Takes `amount` of the budget, or refuses it whole (counted).
    fn charge(&self, amount: u32) -> bool {
        let mut state = self.lock();
        match state.used.checked_add(amount) {
            Some(used) if used <= self.budget => {
                state.used = used;
                state.high_used = state.high_used.max(used);
                true
            }
            _ => {
                state.denied += 1;
                false
            }
        }
    }

    /// Returns `amount` to the budget.
    fn refund(&self, amount: u32) {
        if amount > 0 {
            let mut state = self.lock();
            state.used = state.used.saturating_sub(amount);
        }
    }

    /// One stream's window went from `from` to `to`.
    fn moved(&self, from: u32, to: u32) {
        if from == to {
            return;
        }
        let mut state = self.lock();
        if from > STREAM_WINDOW {
            if let Some(count) = state.grown.get_mut(&from) {
                *count -= 1;
                if *count == 0 {
                    state.grown.remove(&from);
                }
            }
        }
        if to > STREAM_WINDOW {
            *state.grown.entry(to).or_insert(0) += 1;
            state.peak = state.peak.max(to);
            state.high = state.high.max(to);
        }
    }

    /// Test-only: the counts now.
    #[cfg(test)]
    pub(crate) fn stats(&self) -> WindowStats {
        let state = self.lock();
        WindowStats {
            grown: state.grown.values().sum(),
            largest: state.largest(),
            used: state.used,
            budget: self.budget,
            denied: state.denied,
            high: state.high.max(STREAM_WINDOW),
            high_used: state.high_used,
        }
    }

    /// A measurement of a stream on `conn` at `now`: the pool's
    /// `pool_window` line and `conn`'s `pool_rtt` and `pool_queue` lines,
    /// each when due, while `conn` carries a bulk flow or the budget is in
    /// use.
    fn tick(&self, now: Instant, conn: &ConnWindow) {
        let bulk = conn.bulk(now);
        let rtt = bulk.then(|| conn.rtt_lines(now)).flatten();
        let window = {
            let mut state = self.lock();
            let due = state
                .logged
                .is_none_or(|at| now.saturating_duration_since(at) >= POOL_STATE_EVERY);
            let active = bulk || state.used > 0 || !state.grown.is_empty();
            if due && active {
                state.logged = Some(now);
                let largest = state.largest();
                let max = state.peak.max(largest);
                state.peak = largest;
                Some([
                    format!("grown:{}", state.grown.values().sum::<usize>()),
                    format!("max_kib:{}", max.div_ceil(1024)),
                    format!(
                        "budget_kib:{}-{}",
                        state.used.div_ceil(1024),
                        self.budget / 1024
                    ),
                    format!("denied:{}", state.denied),
                ])
            } else {
                None
            }
        };
        if let Some(fields) = window {
            let fields: Vec<&str> = fields.iter().map(String::as_str).collect();
            self.log.line("pool_window", &fields);
        }
        if let Some([rtt, queue]) = rtt {
            for (event, fields) in [("pool_rtt", rtt), ("pool_queue", queue)] {
                let fields: Vec<&str> = fields.iter().map(String::as_str).collect();
                self.log.line(event, &fields);
            }
        }
    }
}

/// A growth step awaiting its judgment.
#[derive(Clone, Copy, Debug)]
struct Step {
    added: u32,
    // The window before it.
    window: u32,
    // Delivered per round trip before it.
    before: u64,
}

/// One measurement as [`WindowPolicy::decide`] reads it.
#[derive(Clone, Copy, Debug)]
struct Measure {
    // Delivered per round trip.
    delivered: u64,
    // Whole round trips it spans.
    rtts: u32,
    rtt: Duration,
    now: Instant,
    credit: CreditLoop,
}

/// One pooled stream's receive window (see the module documentation): the
/// `RecvWindowPolicy` its `H2Stream` asks after every release. Dropped with
/// its stream, it returns its budget and logs `flow_bulk` and `flow_queue`
/// for a bulk flow.
pub(crate) struct WindowPolicy {
    pool: Arc<PoolWindow>,
    conn: Arc<ConnWindow>,
    opened: Instant,
    // Bytes above `STREAM_WINDOW` its window re-opens to now.
    extra: u32,
    // Budget bytes it holds: `extra`, or more while the stream may still
    // hold bytes of an extra it gave back (unused credit or unread data).
    charged: u32,
    // What its latest growth charged (returned if h2 refused it).
    last_charge: u32,
    // The most credit the relay held on it, as its releases saw it.
    credit_high: u32,
    // Bytes it released over its life.
    total: u64,
    // The current measurement: since when (none: from the next release),
    // the bytes released since, the credit held since (byte-microseconds)
    // and its latest release.
    from: Option<Instant>,
    bytes: u64,
    held: u128,
    last: Option<Instant>,
    // No measurement before then: a step settling.
    settle_until: Option<Instant>,
    step: Option<Step>,
    // No growth before then: a step did not raise its rate, or its queue
    // made it give a step back.
    hold_until: Option<Instant>,
    // Under-used round trips in a row.
    quiet: u32,
    // v35: the history, as runs of measurements: at most `q_grow`, at least
    // `Q_SHRINK`, and above `q_grow`.
    low_run: u32,
    high_run: u32,
    above_run: u32,
    // v35: measurements in its history so far, and the one at which its
    // latest step was kept.
    measured: u64,
    kept_at: Option<u64>,
    // v35: its connection's step token, while it holds it.
    token: Option<u64>,
    // v35 review: its mark while it waits, at STREAM_WINDOW, for the token.
    want: Option<u64>,
    // v35: its share of its connection's sums (mean credit held, extra).
    reported: (u64, u64),
    mean_held: u64,
    // v35: its measurements by zone, its steps, and its returns to
    // `STREAM_WINDOW` (after a kept step, and the others).
    bins: [u64; 3],
    grows: u64,
    resets: (u64, u64),
    // Test-only (v35): every zone in its history, and its latest
    // measurement (the credit loop, its round trip, delivered per round
    // trip).
    #[cfg(test)]
    zones: Vec<Zone>,
    #[cfg(test)]
    latest: Option<(CreditLoop, Duration, u64)>,
}

impl WindowPolicy {
    /// The window of a stream on `conn` answered 200 at `now`, under
    /// `pool`'s budget.
    pub(crate) fn new(pool: Arc<PoolWindow>, conn: Arc<ConnWindow>, now: Instant) -> Self {
        Self {
            pool,
            conn,
            opened: now,
            extra: 0,
            charged: 0,
            last_charge: 0,
            credit_high: 0,
            total: 0,
            from: None,
            bytes: 0,
            held: 0,
            last: None,
            settle_until: None,
            step: None,
            hold_until: None,
            quiet: 0,
            low_run: 0,
            high_run: 0,
            above_run: 0,
            measured: 0,
            kept_at: None,
            token: None,
            want: None,
            reported: (0, 0),
            mean_held: 0,
            bins: [0; 3],
            grows: 0,
            resets: (0, 0),
            #[cfg(test)]
            zones: Vec::new(),
            #[cfg(test)]
            latest: None,
        }
    }

    fn window(&self) -> u32 {
        STREAM_WINDOW + self.extra
    }

    /// The extra it gave back is returned to the budget once what the
    /// stream may still hold is back within its lowered window: the credit
    /// the relay has not used (`peer`) and the bytes h2 holds unread
    /// (`unreleased`). Until then those bytes stay charged, so a stream's
    /// credit and unread bytes never exceed `STREAM_WINDOW` plus its charge.
    fn settle(&mut self, window: RecvWindow) {
        let held = u64::from(window.peer) + u64::from(window.unreleased);
        if self.charged > self.extra && held <= u64::from(self.window()) {
            self.pool.refund(self.charged - self.extra);
            self.charged = self.extra;
        }
    }

    fn shrink(&mut self, amount: u32) -> Option<WindowStep> {
        let from = self.window();
        self.extra -= amount;
        self.pool.moved(from, self.window());
        self.step = None;
        Some(WindowStep::Shrink(amount))
    }

    /// v35: its connection's step token goes back.
    fn release_token(&mut self) {
        if let Some(token) = self.token.take() {
            self.conn.release_step(token);
        }
    }

    /// v35: the history starts over.
    fn clear_history(&mut self) {
        (self.low_run, self.high_run, self.above_run) = (0, 0, 0);
    }

    /// v35: one measurement in `zone` enters the history.
    fn record(&mut self, zone: Zone) {
        self.measured += 1;
        let (low, high) = match zone {
            Zone::Low => (true, false),
            Zone::Mid => (false, false),
            Zone::High => (false, true),
        };
        self.bins[zone as usize] += 1;
        #[cfg(test)]
        self.zones.push(zone);
        self.low_run = if low {
            self.low_run.saturating_add(1)
        } else {
            0
        };
        self.high_run = if high {
            self.high_run.saturating_add(1)
        } else {
            0
        };
        self.above_run = if low {
            0
        } else {
            self.above_run.saturating_add(1)
        };
    }

    /// v35: its share of its connection's sums is now what it is.
    fn report(&mut self) {
        let now = (self.mean_held, u64::from(self.extra));
        self.conn.moved_sums(self.reported, now);
        self.reported = now;
    }

    fn hold(&mut self, now: Instant, rtt: Duration) {
        self.hold_until = Some(now + rtt.saturating_mul(HOLD_RTTS));
    }

    /// The decision of one measurement (see the module documentation), in
    /// order: the standing queue, the pending step's judgment, the reclaim
    /// of an under-used stream, the 60 to 120 ms zone's exit, the hold, and
    /// growth.
    fn decide(&mut self, m: Measure) -> Option<WindowStep> {
        let window = self.window();
        let under = under_used(m.delivered, window);
        #[cfg(test)]
        {
            self.latest = Some((m.credit, m.rtt, m.delivered));
        }
        if !under {
            self.record(m.credit.zone(m.rtt));
        }
        if self.pool.mode() == WindowMode::Fixed {
            return None;
        }
        let keeps = !self.pool.holds();
        // A standing queue: back to v33's window, whatever is pending. A
        // pending step is dropped unjudged; one kept within AFTER_STEP
        // measurements made the queue, and the stream holds.
        if !under && !keeps && self.high_run >= STANDING_HISTORY && self.extra > 0 {
            if self.step.take().is_some() {
                self.release_token();
            }
            let after_step = self
                .kept_at
                .is_some_and(|at| self.measured.saturating_sub(at) <= AFTER_STEP);
            if after_step {
                self.hold(m.now, m.rtt);
                self.resets.0 += 1;
            } else {
                self.resets.1 += 1;
            }
            self.clear_history();
            self.kept_at = None;
            return self.shrink(self.extra);
        }
        if let Some(step) = self.step.take() {
            self.release_token();
            // A measurement it under-used (an idle gap, a reader that slowed)
            // says nothing of the step: dropped unjudged, without a hold, its
            // round trips counted as quiet below.
            if !under {
                if !keeps && !raised(step.before, m.delivered, (step.added, step.window)) {
                    self.hold(m.now, m.rtt);
                    return self.shrink(step.added);
                }
                self.kept_at = Some(self.measured);
            }
        }
        if under {
            self.quiet = self.quiet.saturating_add(m.rtts);
        } else {
            self.quiet = 0;
        }
        if self.quiet >= RECLAIM_RTTS {
            // A quiet stream starts over: its next burst may grow again,
            // after a fresh history.
            self.hold_until = None;
            self.kept_at = None;
            self.clear_history();
            return (self.extra > 0).then(|| self.shrink(self.extra)).flatten();
        }
        // The zone between: what the queue says the window overshot goes
        // back, and the stream holds.
        if !under && !keeps && self.above_run >= FROZEN_HISTORY && self.extra > 0 {
            let back = window
                .saturating_sub(frozen_target(window, m.credit, m.rtt))
                .max(FROZEN_LEAST)
                .min(self.extra);
            self.above_run = 0;
            self.hold(m.now, m.rtt);
            return self.shrink(back);
        }
        if self.hold_until.is_some_and(|until| m.now < until) {
            return None;
        }
        self.hold_until = None;
        if under || self.low_run < GROW_HISTORY {
            return None;
        }
        let target = u32::try_from(m.delivered.saturating_mul(2))
            .unwrap_or(u32::MAX)
            .clamp(STREAM_WINDOW, STREAM_WINDOW_MAX);
        if target <= window {
            return None;
        }
        // A grown stream yields the token while a stream still at v33's
        // window waits for it (v35 review): every stream on a connection
        // takes its first step before any takes another.
        if self.extra > 0 && self.conn.step_wanted(m.now) {
            return None;
        }
        let span = m.rtt.saturating_mul(STEP_RTTS);
        let Some(token) = self.conn.claim_step(m.now, span) else {
            if self.extra == 0 {
                self.want = Some(self.conn.want_step(m.now, span));
            }
            return None;
        };
        if let Some(mark) = self.want.take() {
            self.conn.drop_want(mark);
        }
        let added = target - window;
        let extra = self.extra + added;
        let charge = extra.saturating_sub(self.charged);
        if !self.pool.charge(charge) {
            self.conn.release_step(token);
            return None;
        }
        self.token = Some(token);
        self.charged += charge;
        self.last_charge = charge;
        self.extra = extra;
        self.grows += 1;
        self.pool.moved(window, target);
        self.step = Some(Step {
            added,
            window,
            before: m.delivered,
        });
        // Judged from one round trip on: its credit reaches the relay and
        // the data it lets fly comes back.
        self.settle_until = Some(m.now + m.rtt);
        self.from = None;
        self.bytes = 0;
        self.held = 0;
        self.last = None;
        Some(WindowStep::Grow(added))
    }

    /// Test-only: its window now.
    #[cfg(test)]
    pub(crate) fn window_for_test(&self) -> u32 {
        self.window()
    }

    /// Test-only: the budget it holds now.
    #[cfg(test)]
    pub(crate) fn charged_for_test(&self) -> u32 {
        self.charged
    }

    /// Test-only (v35): when it may grow again, if it holds.
    #[cfg(test)]
    pub(crate) fn hold_for_test(&self) -> Option<Instant> {
        self.hold_until
    }

    /// Test-only (v35): its measurements by zone, its steps and its resets.
    #[cfg(test)]
    pub(crate) fn queue_for_test(&self) -> ([u64; 3], u64, (u64, u64)) {
        (self.bins, self.grows, self.resets)
    }

    /// Test-only (v35): every zone of its history so far.
    #[cfg(test)]
    pub(crate) fn zones_for_test(&self) -> &[Zone] {
        &self.zones
    }

    /// Test-only (v35): its latest measurement: the credit loop, the round
    /// trip and what it delivered per round trip.
    #[cfg(test)]
    pub(crate) fn latest_for_test(&self) -> Option<(CreditLoop, Duration, u64)> {
        self.latest
    }
}

impl RecvWindowPolicy for WindowPolicy {
    fn on_release(
        &mut self,
        released: u32,
        window: RecvWindow,
        now: Instant,
    ) -> Option<WindowStep> {
        self.total = self.total.saturating_add(u64::from(released));
        self.credit_high = self.credit_high.max(window.peer);
        self.settle(window);
        if self.settle_until.is_some_and(|until| now < until) {
            return None;
        }
        self.settle_until = None;
        // A measurement starts at a release; the bytes before it are not
        // its own.
        let Some(from) = self.from else {
            self.from = Some(now);
            self.last = Some(now);
            return None;
        };
        // v35: the credit held just before this release, since the one
        // before (a DATA frame read between h2's two reads counts twice, so
        // any error is upward).
        let held = u128::from(window.peer) + u128::from(window.unreleased) + u128::from(released);
        let since = self
            .last
            .map_or(Duration::ZERO, |last| now.saturating_duration_since(last));
        self.held = self
            .held
            .saturating_add(held.saturating_mul(u128::from(micros(since))));
        self.last = Some(now);
        self.bytes = self.bytes.saturating_add(u64::from(released));
        let rtt = self.conn.rtt();
        let elapsed = now.saturating_duration_since(from);
        if elapsed < rtt.saturating_mul(EVAL_RTTS) {
            return None;
        }
        let bytes = std::mem::take(&mut self.bytes);
        let credit = CreditLoop {
            held: std::mem::take(&mut self.held),
            bytes,
            elapsed_us: micros(elapsed),
        };
        self.from = Some(now);
        self.mean_held = credit.mean_held();
        let delivered = per_rtt(bytes, rtt, elapsed);
        if per_second(bytes, elapsed) >= BULK_RATE {
            self.conn.mark_bulk(now);
            // v35 review: only a measurement the stream did not under-use
            // says where its credit waits. An under-used one's credit sat
            // idle at a relay that had nothing to send, which Little's law
            // reads as delay: it never marks the connection queued.
            if !under_used(delivered, self.window()) {
                self.conn.note_queue(credit.delay_us(rtt), now);
            }
        }
        let rtts = u32::try_from(elapsed.as_nanos() / rtt.as_nanos().max(1)).unwrap_or(u32::MAX);
        let step = self.decide(Measure {
            delivered,
            rtts,
            rtt,
            now,
            credit,
        });
        self.report();
        self.pool.tick(now, &self.conn);
        step
    }

    fn refused(&mut self, step: WindowStep) {
        let from = self.window();
        match step {
            WindowStep::Grow(added) => {
                self.extra = self.extra.saturating_sub(added);
                self.pool.refund(self.last_charge);
                self.charged = self.charged.saturating_sub(self.last_charge);
                self.last_charge = 0;
                self.step = None;
                self.grows = self.grows.saturating_sub(1);
                self.release_token();
            }
            WindowStep::Shrink(amount) => {
                self.extra = self.extra.saturating_add(amount);
            }
        }
        self.pool.moved(from, self.window());
        self.report();
    }
}

impl Drop for WindowPolicy {
    fn drop(&mut self) {
        self.release_token();
        if let Some(mark) = self.want.take() {
            self.conn.drop_want(mark);
        }
        self.conn.moved_sums(self.reported, (0, 0));
        self.pool.moved(self.window(), STREAM_WINDOW);
        self.pool.refund(self.charged);
        if self.total >= BULK_BYTES {
            let ms = Instant::now()
                .saturating_duration_since(self.opened)
                .as_millis();
            let [low, mid, high] = self.bins;
            let lines = [
                (
                    "flow_bulk",
                    [
                        self.conn.id_field(),
                        format!("kib:{}", self.total / 1024),
                        format!("ms:{ms}"),
                        format!("win_kib:{}", self.credit_high.div_ceil(1024)),
                    ],
                ),
                (
                    "flow_queue",
                    [
                        self.conn.id_field(),
                        format!("q_bins:{low}-{mid}-{high}"),
                        format!("grows:{}", self.grows),
                        format!("resets:{}-{}", self.resets.0, self.resets.1),
                    ],
                ),
            ];
            for (event, fields) in lines {
                let fields: Vec<&str> = fields.iter().map(String::as_str).collect();
                self.pool.log.line(event, &fields);
            }
        }
    }
}

#[cfg(test)]
#[path = "stream_window_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "stream_window_v35_tests.rs"]
mod v35_tests;
