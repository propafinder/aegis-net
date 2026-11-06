//! B-06 v34/v35: the stream window's rule on a simulated window, and over
//! real h2 between a client that reads as the pool's flows do and a server
//! that sends as fast as its credit allows, across a delayed link in paused
//! time (90 ms each way), with or without a bottleneck that queues.
//!
//! v35: every test here uses only what a9dadf6e's stream window offers, so
//! the v35 RED tests (T10 to T13, T16 to T18, T20, T28) run unchanged over
//! a9dadf6e's policy for the red evidence; tests of v35's new API are in
//! `stream_window_v35_tests.rs`.
use super::*;
use aegis_core::h2_stream::H2Stream;
use bytes::Bytes;
use std::sync::Mutex as StdMutex;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf},
    sync::{mpsc, oneshot},
};

/// Every line a test pool window logged.
#[derive(Default)]
pub(super) struct Lines(StdMutex<Vec<String>>);

impl WindowLog for Lines {
    fn line(&self, event: &str, fields: &[&str]) {
        assert!(
            crate::apple::stable_fields(event, fields),
            "{event} {fields:?}"
        );
        self.0
            .lock()
            .unwrap()
            .push(format!("{event} {}", fields.join(" ")));
    }
}

impl Lines {
    pub(super) fn all(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }

    pub(super) fn of(&self, event: &str) -> Vec<String> {
        self.all()
            .into_iter()
            .filter(|line| line.split(' ').next() == Some(event))
            .collect()
    }
}

pub(super) fn pool_with(budget: u32) -> (Arc<PoolWindow>, Arc<Lines>) {
    let lines = Arc::new(Lines::default());
    (PoolWindow::with_budget(budget, lines.clone()), lines)
}

pub(super) fn new_pool() -> (Arc<PoolWindow>, Arc<Lines>) {
    pool_with(GROW_BUDGET)
}

pub(super) const RTT: Duration = Duration::from_millis(180);
const ONE_WAY: Duration = Duration::from_millis(90);

/// A connection whose least round trip is `rtt`.
pub(super) fn conn_at(rtt: Duration) -> Arc<ConnWindow> {
    let conn = Arc::new(ConnWindow::new());
    conn.sample(rtt, rtt);
    conn
}

/// One stream's window as h2 holds it, reduced to what the rule reads: what
/// it re-opens to (`target`), the relay's credit (`peer`) and the bytes h2
/// holds unread (`unreleased`, 0 unless a test sets it). v35: faithful to
/// h2, in this order: an arrival lowers the relay's credit; the policy is
/// asked; then a WINDOW_UPDATE raises the credit to the target less the
/// unread bytes only once that frees at least half the credit the relay
/// holds (h2 flow_control.rs `unclaimed_capacity`, UNCLAIMED 1/2). v34's
/// helper re-announced every release at once, which h2 never does.
pub(super) struct Sim {
    pub(super) policy: WindowPolicy,
    pub(super) target: u32,
    pub(super) peer: u32,
    pub(super) unreleased: u32,
}

impl Sim {
    pub(super) fn new(pool: &Arc<PoolWindow>, conn: &Arc<ConnWindow>, now: Instant) -> Self {
        Self {
            policy: WindowPolicy::new(pool.clone(), conn.clone(), now),
            target: STREAM_WINDOW,
            peer: STREAM_WINDOW,
            unreleased: 0,
        }
    }

    /// h2's WINDOW_UPDATE rule: announce the free credit once it is at least
    /// half what the relay holds.
    fn announce(&mut self) {
        let available = self.target.saturating_sub(self.unreleased);
        if available > self.peer && available - self.peer >= self.peer / 2 {
            self.peer = available;
        }
    }

    /// `bytes` arrive and are released at `now`.
    pub(super) fn release(&mut self, bytes: u32, now: Instant) -> Option<WindowStep> {
        self.peer = self.peer.saturating_sub(bytes);
        let window = RecvWindow {
            target: self.target,
            peer: self.peer,
            unreleased: self.unreleased,
        };
        let step = self.policy.on_release(bytes, window, now);
        match step {
            Some(WindowStep::Grow(bytes)) => self.target += bytes,
            Some(WindowStep::Shrink(bytes)) => self.target -= bytes,
            None => {}
        }
        self.announce();
        assert_eq!(self.target, self.policy.window_for_test());
        step
    }

    /// A sender that delivers `share` of the window per `rtt`, capped at
    /// `cap` bytes per `rtt`, for `run` from `from`, in eighths of a round
    /// trip. Returns where it stopped. Checks the budget at every step.
    pub(super) fn drive(
        &mut self,
        pool: &PoolWindow,
        (from, run): (Instant, Duration),
        rtt: Duration,
        share: (u32, u32),
        cap: u32,
    ) -> Instant {
        let tick = rtt / 8;
        let mut now = from;
        while now < from + run {
            let per_rtt = (self.target / share.1 * share.0).min(cap);
            self.release(per_rtt / 8, now);
            let stats = pool.stats();
            assert!(stats.used <= stats.budget, "{stats:?}");
            assert!(self.target <= STREAM_WINDOW_MAX);
            now += tick;
        }
        now
    }
}

/// What a window-bound sender delivers per round trip: h2 re-announces at
/// a third used, so about three quarters of the window.
pub(super) const BOUND: (u32, u32) = (3, 4);

#[test]
fn the_round_trip_is_the_least_sample_and_never_follows_a_queue() {
    let conn = ConnWindow::new();
    assert_eq!(conn.min_rtt(), None);
    assert_eq!(conn.rtt(), RTT_FLOOR);
    conn.sample(Duration::from_millis(181), Duration::from_millis(181));
    // Samples through a queue raise the smoothed RTT, never the least.
    for queued in [300, 450, 700, 900] {
        conn.sample(Duration::from_millis(queued), Duration::from_millis(queued));
    }
    assert_eq!(conn.min_rtt(), Some(Duration::from_millis(181)));
    assert_eq!(conn.rtt(), Duration::from_millis(181));
    conn.sample(Duration::from_millis(175), Duration::from_millis(600));
    assert_eq!(conn.rtt(), Duration::from_millis(175));
    // A LAN's round trip is judged over the floor.
    let lan = ConnWindow::new();
    lan.sample(Duration::from_micros(300), Duration::from_micros(300));
    assert_eq!(lan.rtt(), RTT_FLOOR);
    // The rejected design's round trip follows the queue (critic A).
    conn.follow_srtt_for_test();
    assert_eq!(conn.rtt(), Duration::from_millis(600));
}

#[test]
fn the_unchanged_rule_thresholds_are_as_documented() {
    // v35: the 5/8 window-limited share is gone (T15 in the v35 tests holds
    // its replacement); the under-use, gain and rate thresholds stay.
    assert!(under_used(32_767, STREAM_WINDOW) && !under_used(32_768, STREAM_WINDOW));
    // A step of half the window: a tenth more; the last, clamped step of
    // 52 KiB on 972 KiB: half its share, 2.7%.
    let half = (STREAM_WINDOW / 2, STREAM_WINDOW);
    assert!(raised(100, 110, half) && !raised(100, 109, half));
    let last = (52 * 1024, 972 * 1024);
    assert!(raised(1000, 1027, last) && !raised(1000, 1026, last));
    assert_eq!(per_rtt(1_000, RTT, RTT * 2), 500);
    assert_eq!(per_second(1_000, Duration::from_millis(500)), 2_000);
}

#[test]
fn a_window_bound_stream_grows_toward_twice_its_delivery_up_to_the_maximum() {
    let (pool, _lines) = new_pool();
    let conn = conn_at(RTT);
    let start = Instant::now();
    let mut sim = Sim::new(&pool, &conn, start);
    // Each step is judged over two round trips, one round trip after it.
    let mut steps = Vec::new();
    let mut now = start;
    for _ in 0..400 {
        let per_rtt = sim.target / BOUND.1 * BOUND.0;
        if let Some(step) = sim.release(per_rtt / 8, now) {
            steps.push((now - start, step));
        }
        now += RTT / 8;
    }
    let grown: Vec<u32> = steps
        .iter()
        .map(|(_, step)| match step {
            WindowStep::Grow(bytes) => *bytes,
            WindowStep::Shrink(bytes) => panic!("shrank {bytes}: {steps:?}"),
        })
        .collect();
    // 128 -> 192 -> 288 -> 432 -> 648 -> 972 -> 1024 KiB.
    let mut window = STREAM_WINDOW;
    for added in &grown {
        assert!(window + added <= STREAM_WINDOW_MAX);
        assert!(window + added <= window / 2 * 3 + 1024, "{steps:?}");
        window += added;
    }
    assert_eq!(window, STREAM_WINDOW_MAX, "{steps:?}");
    assert_eq!(grown.len(), 6, "{steps:?}");
    for pair in steps.windows(2) {
        // At most once per two round trips and the one it settles.
        assert!(pair[1].0 - pair[0].0 >= RTT * 3 - RTT / 8, "{steps:?}");
    }
    let stats = pool.stats();
    assert_eq!(stats.used, STREAM_WINDOW_MAX - STREAM_WINDOW);
    assert_eq!(
        (stats.grown, stats.largest, stats.denied),
        (1, STREAM_WINDOW_MAX, 0)
    );
    drop(sim);
    let stats = pool.stats();
    assert_eq!((stats.grown, stats.used), (0, 0));
}

#[test]
fn a_stream_that_is_not_window_limited_never_grows() {
    let (pool, lines) = new_pool();
    let conn = conn_at(RTT);
    let start = Instant::now();
    // Half its window per round trip: two v33 streams on one connection.
    let mut sim = Sim::new(&pool, &conn, start);
    sim.drive(
        &pool,
        (start, Duration::from_secs(30)),
        RTT,
        (1, 2),
        u32::MAX,
    );
    assert_eq!(sim.target, STREAM_WINDOW);
    // A stream that stopped reading is never asked: no release, no growth.
    let stalled = Sim::new(&pool, &conn, start);
    assert_eq!(stalled.target, STREAM_WINDOW);
    assert_eq!(
        pool.stats(),
        WindowStats {
            budget: GROW_BUDGET,
            largest: STREAM_WINDOW,
            high: STREAM_WINDOW,
            ..WindowStats::default()
        }
    );
    // Over 1 Mbit/s its connection counts as carrying a bulk flow, and its
    // pool_window line reports nothing grown.
    assert!(conn.bulk(start + Duration::from_secs(30)));
    let windows = lines.of("pool_window");
    assert!(!windows.is_empty());
    assert!(windows
        .iter()
        .all(|line| line == "pool_window grown:0 max_kib:128 budget_kib:0-7168 denied:0"));
}

#[test]
fn a_step_that_does_not_raise_the_rate_is_given_back_and_the_stream_holds() {
    // A sender the relay's congestion window holds at 96 KiB per round
    // trip: window-bound at 128 KiB (3/4 of it), the same at 192 KiB.
    let (pool, _lines) = new_pool();
    let conn = conn_at(RTT);
    let start = Instant::now();
    let mut sim = Sim::new(&pool, &conn, start);
    let cap = STREAM_WINDOW / BOUND.1 * BOUND.0;
    let mut now = start;
    let mut steps = Vec::new();
    while now < start + RTT * (HOLD_RTTS + 20) {
        if let Some(step) = sim.release(cap / 8, now) {
            steps.push((now - start, step));
        }
        now += RTT / 8;
    }
    // Grown once to twice its delivery, given back at its judgment, then
    // held for HOLD_RTTS before it probes again.
    assert!(steps.len() >= 2, "{steps:?}");
    assert_eq!(steps[0].1, WindowStep::Grow(STREAM_WINDOW / 2), "{steps:?}");
    assert_eq!(
        steps[1].1,
        WindowStep::Shrink(STREAM_WINDOW / 2),
        "{steps:?}"
    );
    let held = steps.get(2).map_or(now - start, |(at, _)| *at) - steps[1].0;
    assert!(held >= RTT * HOLD_RTTS, "{steps:?}");
    // Never further than one step, whatever the run.
    assert_eq!(pool.stats().high, STREAM_WINDOW + STREAM_WINDOW / 2);
    // The relay's credit fell back within the window: nothing is held.
    assert_eq!(sim.target, STREAM_WINDOW);
    assert_eq!(pool.stats().used, 0);
}

#[test]
fn growth_stops_at_the_budget_and_returns_on_close() {
    // T4: eight streams at the maximum take the whole budget; a ninth,
    // window-bound too, stays at 128 KiB; closing a grown stream lets it
    // grow. The budget is never exceeded.
    const _: () = assert!(GROW_BUDGET == 8 * (STREAM_WINDOW_MAX - STREAM_WINDOW));
    let (pool, _lines) = new_pool();
    let conn = conn_at(RTT);
    let mut now = Instant::now();
    let mut grown = Vec::new();
    for _ in 0..8 {
        let mut sim = Sim::new(&pool, &conn, now);
        now = sim.drive(&pool, (now, RTT * 40), RTT, BOUND, u32::MAX);
        assert_eq!(sim.target, STREAM_WINDOW_MAX);
        grown.push(sim);
    }
    let stats = pool.stats();
    assert_eq!((stats.used, stats.grown, stats.denied), (GROW_BUDGET, 8, 0));
    let mut ninth = Sim::new(&pool, &conn, now);
    now = ninth.drive(&pool, (now, RTT * 40), RTT, BOUND, u32::MAX);
    assert_eq!(ninth.target, STREAM_WINDOW);
    assert!(pool.stats().denied > 0);
    assert_eq!(pool.stats().used, GROW_BUDGET);
    // Closing one returns its extra at once.
    drop(grown.pop());
    assert_eq!(
        pool.stats().used,
        GROW_BUDGET - (STREAM_WINDOW_MAX - STREAM_WINDOW)
    );
    ninth.drive(&pool, (now, RTT * 40), RTT, BOUND, u32::MAX);
    assert_eq!(ninth.target, STREAM_WINDOW_MAX);
    let stats = pool.stats();
    assert_eq!((stats.used, stats.grown), (GROW_BUDGET, 8));
    assert!(stats.high_used <= GROW_BUDGET);
    drop(grown);
    drop(ninth);
    assert_eq!(pool.stats().used, 0);
}

#[test]
fn an_idle_grown_stream_gives_its_extra_back_once_the_relays_credit_is_down() {
    // The rule on a simulated window: idle for 5 s, then a trickle. The
    // window falls back at once; the budget only once the relay's credit is
    // back within the window.
    let (pool, _lines) = new_pool();
    let conn = conn_at(RTT);
    let start = Instant::now();
    let mut sim = Sim::new(&pool, &conn, start);
    let now = sim.drive(&pool, (start, RTT * 40), RTT, BOUND, u32::MAX);
    assert_eq!(sim.target, STREAM_WINDOW_MAX);
    let mut now = now + Duration::from_secs(5);
    // The first byte after the idle time: it spanned more than
    // RECLAIM_RTTS round trips.
    let step = sim.release(1024, now);
    assert_eq!(
        step,
        Some(WindowStep::Shrink(STREAM_WINDOW_MAX - STREAM_WINDOW))
    );
    assert_eq!(sim.target, STREAM_WINDOW);
    // The relay still holds nearly a megabyte of credit: still charged.
    assert!(sim.peer > STREAM_WINDOW);
    assert_eq!(pool.stats().used, STREAM_WINDOW_MAX - STREAM_WINDOW);
    assert_eq!(pool.stats().grown, 0);
    while sim.peer > STREAM_WINDOW {
        now += Duration::from_millis(100);
        assert_eq!(sim.release(8 * 1024, now), None);
    }
    // At or below 128 KiB: returned, the stream still open.
    assert_eq!(sim.policy.charged_for_test(), 0);
    assert_eq!(pool.stats().used, 0);
    // A new burst may grow it again.
    sim.drive(&pool, (now, RTT * 40), RTT, BOUND, u32::MAX);
    assert_eq!(sim.target, STREAM_WINDOW_MAX);
}

#[test]
fn a_given_back_extra_stays_charged_until_the_bytes_h2_holds_unread_drain() {
    // B-06 v34 review: the relay filled the grown window while the reader
    // stopped; the reader then takes 16 KiB at a time. The window falls back
    // at the first read, the budget only once the relay's credit and the
    // bytes h2 holds unread are back within 128 KiB.
    let (pool, _lines) = new_pool();
    let conn = conn_at(RTT);
    let start = Instant::now();
    let mut sim = Sim::new(&pool, &conn, start);
    let mut now = sim.drive(&pool, (start, RTT * 40), RTT, BOUND, u32::MAX);
    assert_eq!(sim.target, STREAM_WINDOW_MAX);
    let extra = STREAM_WINDOW_MAX - STREAM_WINDOW;
    // Everything granted arrived and sits in h2's buffer.
    (sim.peer, sim.unreleased) = (0, STREAM_WINDOW_MAX);
    now += Duration::from_secs(3);
    let mut reads = 0;
    while pool.stats().used > 0 {
        assert!(reads < 100, "never returned");
        sim.unreleased -= 16_384;
        let step = sim.release(16_384, now);
        let expected = (reads == 0).then_some(WindowStep::Shrink(extra));
        assert_eq!(step, expected, "read {reads}");
        reads += 1;
        assert_eq!(sim.target, STREAM_WINDOW);
        // What it may hold never exceeds its window and its charge, and
        // all of the extra stays charged while it holds more than 128 KiB.
        let held = sim.peer + sim.unreleased;
        let used = pool.stats().used;
        assert!(held <= STREAM_WINDOW + used, "held {held} used {used}");
        assert_eq!(used, if held > STREAM_WINDOW { extra } else { 0 });
        now += Duration::from_millis(200);
    }
    // 56 reads: about 7/8 of the buffer drained first.
    assert!(reads > 50, "{reads}");
    assert_eq!(sim.policy.charged_for_test(), 0);
    // Its reader caught up; a new burst may grow it again.
    sim.unreleased = 0;
    sim.drive(&pool, (now, RTT * 40), RTT, BOUND, u32::MAX);
    assert_eq!(sim.target, STREAM_WINDOW_MAX);
}

#[test]
fn an_idle_gap_inside_a_steps_judgment_judges_nothing_and_reclaims_the_whole_extra() {
    // B-06 v34 review: a window-bound burst ends while its second step
    // awaits its judgment, then 5 s idle. The first byte after the idle
    // gives the whole extra back (the idle time spans more than
    // RECLAIM_RTTS), sets no hold, and the next window-bound burst grows.
    let (pool, _lines) = new_pool();
    let conn = conn_at(RTT);
    let start = Instant::now();
    let mut sim = Sim::new(&pool, &conn, start);
    let mut now = start;
    let mut grown = 0;
    while grown < 2 {
        let per_rtt = sim.target / BOUND.1 * BOUND.0;
        if let Some(WindowStep::Grow(_)) = sim.release(per_rtt / 8, now) {
            grown += 1;
        }
        now += RTT / 8;
    }
    // On for its settling round trip and half its measurement.
    for _ in 0..12 {
        let per_rtt = sim.target / BOUND.1 * BOUND.0;
        assert_eq!(sim.release(per_rtt / 8, now), None);
        now += RTT / 8;
    }
    let window = sim.target;
    assert!(window > STREAM_WINDOW + STREAM_WINDOW / 2, "{window}");
    now += Duration::from_secs(5);
    assert_eq!(
        sim.release(1024, now),
        Some(WindowStep::Shrink(window - STREAM_WINDOW))
    );
    assert_eq!(sim.target, STREAM_WINDOW);
    // The next burst is not held: it grows to the maximum within 5 s.
    now += RTT / 8;
    sim.drive(&pool, (now, Duration::from_secs(5)), RTT, BOUND, u32::MAX);
    assert_eq!(sim.target, STREAM_WINDOW_MAX);
    // A dip shorter than RECLAIM_RTTS inside a judgment keeps the step and
    // holds nothing either: the stream goes on growing after it.
    let (pool, _lines) = new_pool();
    let mut sim = Sim::new(&pool, &conn, start);
    let mut now = start;
    while sim.target == STREAM_WINDOW {
        let per_rtt = sim.target / BOUND.1 * BOUND.0;
        sim.release(per_rtt / 8, now);
        now += RTT / 8;
    }
    let first = sim.target;
    for _ in 0..12 {
        sim.release(sim.target / BOUND.1 * BOUND.0 / 8, now);
        now += RTT / 8;
    }
    // Three round trips with a trickle: under a quarter of the window.
    for _ in 0..24 {
        assert_eq!(sim.release(1024, now), None);
        now += RTT / 8;
    }
    assert_eq!(sim.target, first);
    sim.drive(&pool, (now, RTT * 10), RTT, BOUND, u32::MAX);
    assert!(sim.target > first, "{} {first}", sim.target);
}

#[test]
fn the_window_lines_are_stable_bounded_and_carry_no_address() {
    let (pool, lines) = new_pool();
    let conn = conn_at(RTT);
    conn.set_id(3);
    let start = Instant::now();
    let mut sim = Sim::new(&pool, &conn, start);
    let end = sim.drive(
        &pool,
        (start, Duration::from_secs(10)),
        RTT,
        BOUND,
        u32::MAX,
    );
    // A 200 sample on it under load.
    conn.sample(Duration::from_millis(260), Duration::from_millis(190));
    sim.drive(&pool, (end, Duration::from_secs(2)), RTT, BOUND, u32::MAX);
    drop(sim);
    let windows = lines.of("pool_window");
    // At most one a second over 12 s of data.
    assert!((10..=13).contains(&windows.len()), "{windows:?}");
    assert!(windows
        .contains(&"pool_window grown:1 max_kib:1024 budget_kib:896-7168 denied:0".to_owned()));
    let rtts = lines.of("pool_rtt");
    assert!((10..=13).contains(&rtts.len()), "{rtts:?}");
    assert_eq!(
        rtts[0],
        "pool_rtt conn:3 min_ms:180 srtt_ms:180 last_ms:180"
    );
    // last_ms only for a sample since the line before.
    assert!(rtts.contains(&"pool_rtt conn:3 min_ms:180 srtt_ms:180".to_owned()));
    assert!(rtts.contains(&"pool_rtt conn:3 min_ms:180 srtt_ms:190 last_ms:260".to_owned()));
    let bulk = lines.of("flow_bulk");
    assert_eq!(bulk.len(), 1);
    assert!(
        // v35: the faithful helper asks the policy after the arrival, before
        // h2's WINDOW_UPDATE, as h2 does: its releases see at most the
        // maximum less one tick's 96 KiB (v34's helper re-announced first:
        // 1024).
        bulk[0].starts_with("flow_bulk conn:3 kib:") && bulk[0].ends_with(" win_kib:928"),
        "{bulk:?}"
    );
    // No dotted quad and no colon-hex group anywhere.
    for line in lines.all() {
        assert!(
            !line
                .split(|c: char| !(c.is_ascii_hexdigit() || c == '.' || c == ':'))
                .any(|token| token.matches('.').count() >= 3 || token.matches(':').count() >= 2),
            "{line}"
        );
    }
    // A flow under 1 MiB logs no flow_bulk line.
    let (pool, lines) = new_pool();
    let mut small = Sim::new(&pool, &conn, start);
    small.release(500_000, start);
    small.release(500_000, start + RTT * 3);
    drop(small);
    assert!(lines.of("flow_bulk").is_empty());
}

// ---- over real h2, a delayed link, paused time ----

const DATA: u8 = 0x0;
const WINDOW_UPDATE: u8 = 0x8;

/// The stream's credit as the server sees it, relative to
/// SETTINGS_INITIAL_WINDOW_SIZE: the client's stream WINDOW_UPDATEs less
/// the server's DATA.
#[derive(Clone, Copy, Debug, Default)]
struct Ledger {
    credit: i64,
    high: i64,
    // Every stream WINDOW_UPDATE the client sent, summed.
    granted: i64,
}

type Shared = Arc<StdMutex<Ledger>>;

/// One direction of the link (v35: its shape).
#[derive(Clone, Copy, Debug)]
struct Shape {
    from_client: bool,
    delay: Duration,
    /// Frames also leave at most this many bytes per second, queueing
    /// behind each other.
    rate: Option<u64>,
    /// v35: from this long after the link starts, the rate is this.
    drop_to: Option<(Duration, u64)>,
    /// v35 review: and from this long, this (after `drop_to`).
    back_to: Option<(Duration, u64)>,
    /// v35: once per `every`, a frame due to leave within the first `hold`
    /// of it leaves at the hold's end, with every frame behind it: a hole
    /// the receiver's TCP fills one round trip later, all at once.
    holes: Option<(Duration, Duration)>,
}

/// One direction of the link: each frame reaches the other side `delay`
/// after it was read, and with `rate` frames also leave at most `rate`
/// bytes per second, queueing behind each other (a bottleneck and its
/// queue: the relay's send buffer, which delays PONGs as it delays data).
async fn link(
    mut from: ReadHalf<DuplexStream>,
    to: WriteHalf<DuplexStream>,
    shape: Shape,
    ledger: Shared,
) {
    let Shape {
        from_client,
        delay,
        rate,
        drop_to,
        back_to,
        holes,
    } = shape;
    let started = Instant::now();
    let (sender, mut queue) = mpsc::unbounded_channel::<(Instant, Vec<u8>)>();
    let deliver = tokio::spawn(async move {
        let mut to = to;
        while let Some((at, bytes)) = queue.recv().await {
            tokio::time::sleep_until(at).await;
            if to.write_all(&bytes).await.is_err() {
                return;
            }
        }
    });
    if from_client {
        let mut preface = [0; 24];
        if from.read_exact(&mut preface).await.is_err() {
            return;
        }
        let _ = sender.send((Instant::now() + delay, preface.to_vec()));
    }
    let mut free = Instant::now();
    loop {
        let mut head = [0; 9];
        if from.read_exact(&mut head).await.is_err() {
            break;
        }
        let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
        let mut frame = head.to_vec();
        frame.resize(9 + len, 0);
        if from.read_exact(&mut frame[9..]).await.is_err() {
            break;
        }
        let stream = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
        if stream != 0 {
            let mut ledger = ledger.lock().unwrap();
            match (from_client, head[3]) {
                (true, WINDOW_UPDATE) => {
                    let increment = u32::from_be_bytes([frame[9], frame[10], frame[11], frame[12]])
                        & 0x7fff_ffff;
                    ledger.credit += i64::from(increment);
                    ledger.high = ledger.high.max(ledger.credit);
                    ledger.granted += i64::from(increment);
                }
                (false, DATA) => ledger.credit -= len as i64,
                _ => {}
            }
        }
        let now = Instant::now();
        let rate = match (rate, drop_to) {
            (Some(_), Some((after, lower))) if now >= started + after => Some(lower),
            (rate, _) => rate,
        };
        let rate = match (rate, back_to) {
            (Some(_), Some((after, back))) if now >= started + after => Some(back),
            (rate, _) => rate,
        };
        let mut leaves = match rate {
            Some(rate) => {
                let busy = Duration::from_nanos(frame.len() as u64 * 1_000_000_000 / rate);
                free = free.max(now) + busy;
                free
            }
            None => now,
        };
        if let Some((every, hold)) = holes {
            let into = leaves.saturating_duration_since(started).as_nanos() % every.as_nanos();
            if into < hold.as_nanos() {
                leaves += hold - Duration::from_nanos(into as u64);
            }
        }
        if sender.send((leaves + delay, frame)).is_err() {
            break;
        }
    }
    drop(sender);
    let _ = deliver.await;
}

/// What the server sends, in order.
#[derive(Clone, Copy, Debug)]
pub(super) enum Send {
    /// As fast as its credit allows, for this long, bytes 0x5a.
    Bulk(Duration),
    /// Nothing for this long.
    Idle(Duration),
    /// `count` chunks of `chunk` bytes 0x01, one per `every`.
    Trickle {
        chunk: usize,
        every: Duration,
        count: usize,
    },
}

/// The server's sends of `plan`, then (once `last` fires) a last chunk of
/// 0x02 and END_STREAM.
async fn send_plan(send: &mut h2::SendStream<Bytes>, plan: Vec<Send>) {
    for step in plan {
        match step {
            Send::Bulk(run) => {
                let until = Instant::now() + run;
                while Instant::now() < until {
                    send.reserve_capacity(256 * 1024);
                    let capacity = send.capacity();
                    if capacity > 0 {
                        send.send_data(Bytes::from(vec![0x5a; capacity]), false)
                            .unwrap();
                        continue;
                    }
                    tokio::select! {
                        granted = std::future::poll_fn(|cx| send.poll_capacity(cx)) => {
                            if !matches!(granted, Some(Ok(_))) {
                                return;
                            }
                        }
                        () = tokio::time::sleep_until(until) => {}
                    }
                }
                send.reserve_capacity(0);
            }
            Send::Idle(run) => tokio::time::sleep(run).await,
            Send::Trickle {
                chunk,
                every,
                count,
            } => {
                for _ in 0..count {
                    tokio::time::sleep(every).await;
                    send.reserve_capacity(chunk);
                    while send.capacity() < chunk {
                        if !matches!(
                            std::future::poll_fn(|cx| send.poll_capacity(cx)).await,
                            Some(Ok(_))
                        ) {
                            return;
                        }
                    }
                    send.send_data(Bytes::from(vec![0x01; chunk]), false)
                        .unwrap();
                }
            }
        }
    }
}

async fn serve(io: DuplexStream, plan: Vec<Send>, last: oneshot::Receiver<()>) {
    let mut connection = h2::server::Builder::new()
        // The relay's (aegis-server session/grpc.rs:211-213).
        .initial_window_size(STREAM_WINDOW)
        .max_send_buffer_size(STREAM_WINDOW as usize)
        .handshake::<_, Bytes>(io)
        .await
        .unwrap();
    let (_request, mut respond) = connection.accept().await.unwrap().unwrap();
    let mut send = respond
        .send_response(http::Response::new(()), false)
        .unwrap();
    let sender = async {
        send_plan(&mut send, plan).await;
        let _ = last.await;
        send.send_data(Bytes::from_static(&[0x02; 64]), true)
            .unwrap();
        std::future::pending::<()>().await;
    };
    // The connection is driven until the client leaves.
    tokio::select! {
        () = sender => {}
        _ = async { while let Some(Ok(_)) = connection.accept().await {} } => {}
    }
}

/// How the client receives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Window {
    /// v33 (b9adfe19): `H2Stream::new`.
    Fixed,
    /// v34: `H2Stream::with_recv_window` and `WindowPolicy`.
    Policy,
}

/// The link's shape: 90 ms each way, and a downlink bottleneck when given.
#[derive(Clone, Copy, Debug)]
pub(super) struct Line {
    pub(super) downlink: Option<u64>,
    /// PINGs one per this, each sampled as the stall watchdog's PONG is.
    pub(super) pings: Option<Duration>,
    /// v35: the downlink's rate from then on.
    pub(super) drop_to: Option<(Duration, u64)>,
    /// v35 review: and from then on, this.
    pub(super) back_to: Option<(Duration, u64)>,
    /// v35: the downlink's holes (`Shape::holes`).
    pub(super) holes: Option<(Duration, Duration)>,
}

const UPLINK: Shape = Shape {
    from_client: true,
    delay: ONE_WAY,
    rate: None,
    drop_to: None,
    back_to: None,
    holes: None,
};

impl Line {
    fn downlink(&self) -> Shape {
        Shape {
            from_client: false,
            delay: ONE_WAY,
            rate: self.downlink,
            drop_to: self.drop_to,
            back_to: self.back_to,
            holes: self.holes,
        }
    }
}

#[allow(dead_code)]
pub(super) struct Report {
    /// Bulk bytes read within the plan's bulk and idle time from the 200.
    pub(super) bulk_within: u64,
    /// Bulk bytes read.
    pub(super) bulk: u64,
    /// The stream's credit at its highest, as the server saw it.
    pub(super) credit_high: i64,
    /// The credit once every planned byte was read, before the last chunk.
    pub(super) credit_after: i64,
    /// The window stats then.
    pub(super) stats: WindowStats,
    /// The largest PING round trip during the run.
    pub(super) ping_max: Duration,
    /// The least.
    pub(super) ping_min: Duration,
    /// v35: each PONG's round trip, by when it came back (from the 200).
    pub(super) pongs: Vec<(Duration, Duration)>,
    /// v35: the bulk bytes read by then (from the 200), at every read.
    pub(super) reads: Vec<(Duration, u64)>,
    /// v35: the largest live window then (`WindowStats::largest`), at every
    /// read.
    pub(super) windows: Vec<(Duration, u32)>,
}

impl std::fmt::Debug for Report {
    // v35: the series are summarised (every change of the largest window,
    // with its time), so a failing test's message stays readable.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut changes = Vec::new();
        let mut last = 0;
        for (at, window) in &self.windows {
            if *window != last {
                changes.push(format!("{:.1}s:{}K", at.as_secs_f64(), window / 1024));
                last = *window;
            }
        }
        f.debug_struct("Report")
            .field("bulk_within", &self.bulk_within)
            .field("bulk", &self.bulk)
            .field("credit_high", &self.credit_high)
            .field("credit_after", &self.credit_after)
            .field("stats", &self.stats)
            .field("ping_max", &self.ping_max)
            .field("ping_min", &self.ping_min)
            .field("pongs", &self.pongs.len())
            .field("windows", &changes.join(" "))
            .finish()
    }
}

impl Report {
    /// v35: the `p`th percentile of the PONGs' queue (each round trip less
    /// the least) that came back between `from` and `to`.
    pub(super) fn pong_queue(&self, (from, to): (Duration, Duration), p: usize) -> Duration {
        let mut queue: Vec<Duration> = self
            .pongs
            .iter()
            .filter(|(at, _)| (from..to).contains(at))
            .map(|(_, sample)| sample.saturating_sub(self.ping_min))
            .collect();
        assert!(!queue.is_empty(), "no PONG between {from:?} and {to:?}");
        queue.sort();
        queue[(queue.len() * p).div_ceil(100).max(1) - 1]
    }

    /// v35: the bulk bytes read between `from` and `to`.
    pub(super) fn bulk_between(&self, (from, to): (Duration, Duration)) -> u64 {
        let at = |when: Duration| {
            self.reads
                .iter()
                .take_while(|(at, _)| *at <= when)
                .last()
                .map_or(0, |(_, bytes)| *bytes)
        };
        at(to) - at(from)
    }

    /// v35: the largest window seen between `from` and `to`.
    pub(super) fn largest_between(&self, (from, to): (Duration, Duration)) -> u32 {
        self.windows
            .iter()
            .filter(|(at, _)| (from..to).contains(at))
            .map(|(_, window)| *window)
            .max()
            .unwrap_or(STREAM_WINDOW)
    }
}

/// One GET answered 200 whose body follows `plan`, read as a pool flow
/// reads, through `window` on `line`.
pub(super) async fn exchange(
    line: Line,
    window: Window,
    plan: Vec<Send>,
    pool: Arc<PoolWindow>,
    conn: Arc<ConnWindow>,
) -> Report {
    let (client_io, tap_client) = tokio::io::duplex(1 << 20);
    let (tap_server, server_io) = tokio::io::duplex(1 << 20);
    let ledger = Shared::default();
    let (up_from, down_to) = tokio::io::split(tap_client);
    let (down_from, up_to) = tokio::io::split(tap_server);
    tokio::spawn(link(up_from, up_to, UPLINK, ledger.clone()));
    tokio::spawn(link(down_from, down_to, line.downlink(), ledger.clone()));
    let (last_tx, last_rx) = oneshot::channel();
    let trickled: usize = plan
        .iter()
        .map(|step| match step {
            Send::Trickle { chunk, count, .. } => chunk * count,
            _ => 0,
        })
        .sum();
    let bulk_for: Duration = plan
        .iter()
        .map(|step| match step {
            Send::Bulk(run) | Send::Idle(run) => *run,
            Send::Trickle { .. } => Duration::ZERO,
        })
        .sum();
    tokio::spawn(serve(server_io, plan, last_rx));
    let (client, mut connection) = h2::client::Builder::new()
        // The pool's (flow_pool.rs PooledConn::dial_as).
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONN_WINDOW)
        .max_send_buffer_size(crate::flow_pool::SEND_BUFFER)
        .handshake::<_, Bytes>(client_io)
        .await
        .unwrap();
    let mut pings = connection.ping_pong().unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    // The first round trip on an empty link, as the outer TLS handshake
    // seeds it.
    let sent = Instant::now();
    pings.ping(h2::Ping::opaque()).await.unwrap();
    let first = sent.elapsed();
    conn.sample(first, first);
    let ping_min = Arc::new(AtomicU64::new(micros(first)));
    let ping_max = Arc::new(AtomicU64::new(micros(first)));
    let pongs = Arc::new(StdMutex::new(Vec::<(Instant, Duration)>::new()));
    let pinger = line.pings.map(|every| {
        let (conn, low, high) = (conn.clone(), ping_min.clone(), ping_max.clone());
        let pongs = pongs.clone();
        tokio::spawn(async move {
            let mut srtt = first;
            loop {
                tokio::time::sleep(every).await;
                let sent = Instant::now();
                if pings.ping(h2::Ping::opaque()).await.is_err() {
                    return;
                }
                let sample = sent.elapsed();
                srtt = (srtt * 7 + sample) / 8;
                conn.sample(sample, srtt);
                low.fetch_min(micros(sample), Ordering::SeqCst);
                high.fetch_max(micros(sample), Ordering::SeqCst);
                pongs.lock().unwrap().push((Instant::now(), sample));
            }
        })
    });
    let mut client = client.ready().await.unwrap();
    let request = http::Request::get("https://example.test/")
        .body(())
        .unwrap();
    let (response, request_body) = client.send_request(request, false).unwrap();
    let body = response.await.unwrap().into_body();
    let opened = Instant::now();
    let mut stream = match window {
        Window::Fixed => H2Stream::new(request_body, body),
        Window::Policy => H2Stream::with_recv_window(
            request_body,
            body,
            Box::new(WindowPolicy::new(pool.clone(), conn.clone(), opened)),
        ),
    };
    let mut buffer = vec![0; 64 * 1024];
    let (mut bulk, mut bulk_within, mut seen) = (0u64, 0u64, 0usize);
    let (mut reads, mut windows) = (Vec::new(), Vec::new());
    let mut last = Some(last_tx);
    let mut after = None;
    loop {
        // Every planned byte read (the trickle's, or the bulk's time over):
        // the window as it stands, the stream open, then its last chunk.
        let planned = trickled > 0 && seen == trickled;
        let timed = trickled == 0 && Instant::now() >= opened + bulk_for + RTT * 2;
        if last.is_some() && (planned || timed) {
            after = Some((ledger.lock().unwrap().credit, pool.stats()));
            let _ = last.take().unwrap().send(());
        }
        let read = match tokio::time::timeout(RTT, stream.read(&mut buffer)).await {
            Ok(read) => read.unwrap(),
            Err(_) => continue,
        };
        if read == 0 {
            break;
        }
        let within = Instant::now() < opened + bulk_for;
        for byte in &buffer[..read] {
            match byte {
                0x5a => {
                    bulk += 1;
                    bulk_within += u64::from(within);
                }
                0x01 => seen += 1,
                _ => {}
            }
        }
        let at = opened.elapsed();
        reads.push((at, bulk));
        windows.push((at, pool.stats().largest));
    }
    if let Some(pinger) = pinger {
        pinger.abort();
    }
    let (credit_after, stats) = after.expect("every planned byte read");
    drop(stream);
    let ledger = *ledger.lock().unwrap();
    let pongs: Vec<(Duration, Duration)> = pongs
        .lock()
        .unwrap()
        .iter()
        .map(|(at, sample)| (at.saturating_duration_since(opened), *sample))
        .collect();
    Report {
        bulk_within,
        bulk,
        credit_high: i64::from(STREAM_WINDOW) + ledger.high,
        credit_after: i64::from(STREAM_WINDOW) + credit_after,
        stats,
        ping_max: Duration::from_micros(ping_max.load(Ordering::SeqCst)),
        ping_min: Duration::from_micros(ping_min.load(Ordering::SeqCst)),
        pongs,
        reads,
        windows,
    }
}

pub(super) const OPEN_LINE: Line = Line {
    downlink: None,
    pings: None,
    drop_to: None,
    back_to: None,
    holes: None,
};

#[tokio::test(start_paused = true)]
async fn one_stream_over_a_delayed_link_moves_more_than_twice_the_v33_bound() {
    // T2: 10 s of bulk at 180 ms. v33's window moves at most 128 KiB per
    // round trip; the grown window more than twice that, in the same time.
    const RUN: Duration = Duration::from_secs(10);
    let bound = u64::from(STREAM_WINDOW) * RUN.as_millis() as u64 / RTT.as_millis() as u64;
    let (pool, lines) = new_pool();
    let v34 = exchange(
        OPEN_LINE,
        Window::Policy,
        vec![Send::Bulk(RUN)],
        pool.clone(),
        conn_at(RTT),
    )
    .await;
    println!("v34 {v34:?} bound {bound}");
    assert!(v34.bulk_within > 2 * bound, "{v34:?} bound {bound}");
    assert!(v34.credit_high > i64::from(STREAM_WINDOW), "{v34:?}");
    assert!(v34.credit_high <= i64::from(STREAM_WINDOW_MAX), "{v34:?}");
    assert_eq!(v34.stats.high, STREAM_WINDOW_MAX, "{v34:?}");
    assert_eq!(pool.stats().used, 0);
    // Its flow_bulk line's win_kib is the credit the relay held, as its
    // releases saw it: above 128 KiB, within the largest window granted.
    let bulk = lines.of("flow_bulk");
    let win: u32 = bulk[0].rsplit("win_kib:").next().unwrap().parse().unwrap();
    assert!(win > 128 && win <= STREAM_WINDOW_MAX / 1024, "{bulk:?}");
    // The control, b9adfe19's fixed window on the same link: within the
    // bound (and the window it may hold at the start), its credit never
    // above 128 KiB.
    let (pool, _lines) = new_pool();
    let v33 = exchange(
        OPEN_LINE,
        Window::Fixed,
        vec![Send::Bulk(RUN)],
        pool,
        conn_at(RTT),
    )
    .await;
    println!("v33 {v33:?}");
    assert!(
        v33.bulk_within <= bound + u64::from(STREAM_WINDOW),
        "{v33:?} bound {bound}"
    );
    assert!(v33.credit_high <= i64::from(STREAM_WINDOW), "{v33:?}");
}

#[tokio::test(start_paused = true)]
async fn a_congestion_bound_stream_does_not_ratchet_its_window_to_the_maximum() {
    // T8: a bottleneck of 1 MiB/s behind the relay, its queue in front of
    // the PONGs too: the delivery rate is fixed, and the RTT grows with
    // every byte of credit above the path's own. The stream grows while
    // its window binds, then holds: never past twice what the path carries
    // per least round trip, far from the maximum.
    const RATE: u64 = 1_048_576;
    const RUN: Duration = Duration::from_secs(20);
    let bdp = RATE * RTT.as_millis() as u64 / 1000;
    let line = Line {
        downlink: Some(RATE),
        pings: Some(Duration::from_millis(500)),
        ..OPEN_LINE
    };
    let (pool, _lines) = new_pool();
    let held = exchange(
        line,
        Window::Policy,
        vec![Send::Bulk(RUN)],
        pool,
        conn_at(RTT),
    )
    .await;
    println!("held {held:?} bdp {bdp}");
    assert!(held.stats.high > STREAM_WINDOW, "{held:?}");
    assert!(
        u64::from(held.stats.high) <= 2 * bdp + 32 * 1024,
        "{held:?} bdp {bdp}"
    );
    assert!(held.credit_high <= i64::from(held.stats.high), "{held:?}");
    // The rate is the path's either way.
    assert!(held.bulk >= RATE * 18, "{held:?}");

    // The least RTT alone keeps it there, with a step that did not help
    // kept rather than given back.
    let (pool, _lines) = new_pool();
    pool.no_hold_for_test();
    let min_only = exchange(
        line,
        Window::Policy,
        vec![Send::Bulk(RUN)],
        pool,
        conn_at(RTT),
    )
    .await;
    println!("min_only {min_only:?}");
    assert!(
        u64::from(min_only.stats.high) <= 2 * bdp + 32 * 1024,
        "{min_only:?}"
    );

    // The control: critic A's failure. A rule that judges by the smoothed
    // RTT (PONGs queued behind the data) and keeps every step ratchets to
    // the maximum, leaving a standing queue.
    let (pool, _lines) = new_pool();
    pool.no_hold_for_test();
    let conn = conn_at(RTT);
    conn.follow_srtt_for_test();
    let ratchet = exchange(line, Window::Policy, vec![Send::Bulk(RUN * 2)], pool, conn).await;
    println!("ratchet {ratchet:?}");
    assert_eq!(ratchet.stats.high, STREAM_WINDOW_MAX, "{ratchet:?}");
    // v35: the queue was there, behind the ratchet: PONGs came back well
    // behind the path's RTT (v34 checked this on the held run, whose v35
    // window leaves no such queue).
    assert!(
        ratchet.ping_max > ratchet.ping_min + Duration::from_millis(30),
        "{ratchet:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_grown_stream_that_goes_idle_returns_its_extra_without_closing() {
    // T7: 6 s of bulk (it grows), 5 s idle, then a trickle of 8 KiB every
    // 100 ms. Its window falls back at the first trickle byte; the budget
    // comes back once the server's credit is within 128 KiB; the stream
    // stays open and carries its last chunk afterwards.
    let (pool, lines) = new_pool();
    let conn = conn_at(RTT);
    conn.set_id(7);
    let plan = vec![
        Send::Bulk(Duration::from_secs(6)),
        Send::Idle(Duration::from_secs(5)),
        Send::Trickle {
            chunk: 8 * 1024,
            every: Duration::from_millis(100),
            count: 200,
        },
    ];
    let report = exchange(OPEN_LINE, Window::Policy, plan, pool.clone(), conn).await;
    println!(
        "idle {report:?} {:?}",
        lines
            .all()
            .iter()
            .filter(|line| !line.starts_with("pool_rtt"))
            .collect::<Vec<_>>()
    );
    assert!(
        report.credit_high > i64::from(STREAM_WINDOW) * 4,
        "{report:?}"
    );
    assert!(report.stats.high > STREAM_WINDOW * 4, "{report:?}");
    // Before the last chunk, the stream open: nothing grown, nothing held,
    // the server's credit within the initial window.
    assert_eq!(
        (report.stats.grown, report.stats.used),
        (0, 0),
        "{report:?}"
    );
    assert!(
        report.credit_after <= i64::from(STREAM_WINDOW),
        "{report:?}"
    );
    // The stream ended only after that (its last chunk, then END_STREAM).
    let bulk = lines.of("flow_bulk");
    assert_eq!(bulk.len(), 1, "{bulk:?}");
    assert!(bulk[0].starts_with("flow_bulk conn:7 "), "{bulk:?}");
    assert_eq!(pool.stats().used, 0);
}

#[tokio::test(start_paused = true)]
async fn a_grown_stream_whose_reader_slows_keeps_its_budget_until_h2_has_drained() {
    // B-06 v34 review: over real h2, the budget narrowed to one stream's
    // extra. A keeping-up reader for 8 s (it grows to 1 MiB), a 3 s stall
    // (the relay fills the grown window into h2's buffer), then 16 KiB per
    // 200 ms (its window falls back at once), then 16 KiB per 100 ms
    // (still under a quarter of its window). At every read what the client
    // granted and the reader has not taken, on the wire, in h2's buffer or
    // still the relay's credit, stays within 128 KiB plus the budget held;
    // while it is above that a second window-bound stream cannot grow, and
    // once h2 has drained the budget returns and the second one grows.
    const FRAME: i64 = 16_384;
    let budget = STREAM_WINDOW_MAX - STREAM_WINDOW;
    let (pool, _lines) = pool_with(budget);
    let conn = conn_at(RTT);
    let (client_io, tap_client) = tokio::io::duplex(1 << 20);
    let (tap_server, server_io) = tokio::io::duplex(1 << 20);
    let ledger = Shared::default();
    let (up_from, down_to) = tokio::io::split(tap_client);
    let (down_from, up_to) = tokio::io::split(tap_server);
    tokio::spawn(link(up_from, up_to, UPLINK, ledger.clone()));
    tokio::spawn(link(
        down_from,
        down_to,
        OPEN_LINE.downlink(),
        ledger.clone(),
    ));
    let (_last_tx, last_rx) = oneshot::channel();
    let server = tokio::spawn(serve(
        server_io,
        vec![Send::Bulk(Duration::from_secs(120))],
        last_rx,
    ));
    let (client, connection) = h2::client::Builder::new()
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONN_WINDOW)
        .max_send_buffer_size(crate::flow_pool::SEND_BUFFER)
        .handshake::<_, Bytes>(client_io)
        .await
        .unwrap();
    let driver = tokio::spawn(connection);
    let mut client = client.ready().await.unwrap();
    let request = http::Request::get("https://example.test/")
        .body(())
        .unwrap();
    let (response, request_body) = client.send_request(request, false).unwrap();
    let body = response.await.unwrap().into_body();
    let opened = Instant::now();
    let mut stream = H2Stream::with_recv_window(
        request_body,
        body,
        Box::new(WindowPolicy::new(pool.clone(), conn.clone(), opened)),
    );
    let mut buffer = vec![0; FRAME as usize];
    let mut taken = 0i64;
    // What the client granted on the stream that its reader has not taken.
    let held = |taken: i64| i64::from(STREAM_WINDOW) + ledger.lock().unwrap().granted - taken;
    while Instant::now() < opened + Duration::from_secs(8) {
        if let Ok(read) = tokio::time::timeout(RTT, stream.read(&mut buffer)).await {
            taken += read.unwrap() as i64;
        }
    }
    let grown = pool.stats();
    assert_eq!(
        (grown.largest, grown.used),
        (STREAM_WINDOW_MAX, budget),
        "{grown:?}"
    );
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        held(taken) > i64::from(STREAM_WINDOW) * 6,
        "{}",
        held(taken)
    );
    let mut second = None;
    let mut reads = 0;
    while pool.stats().used > 0 {
        assert!(
            reads < 400,
            "the budget never came back: {:?}",
            pool.stats()
        );
        let pause = if reads < 20 { 200 } else { 100 };
        tokio::time::sleep(Duration::from_millis(pause)).await;
        taken += stream.read(&mut buffer).await.unwrap() as i64;
        reads += 1;
        let (stats, held) = (pool.stats(), held(taken));
        // Given back at the first read after the stall.
        assert_eq!(stats.largest, STREAM_WINDOW, "{stats:?}");
        assert!(
            held <= i64::from(STREAM_WINDOW) + i64::from(stats.used) + FRAME,
            "read {reads}: held {held} {stats:?}"
        );
        if reads == 10 {
            // Still holding most of a megabyte: a second stream's growth is
            // refused whole.
            assert!(held > i64::from(STREAM_WINDOW) * 4, "{held}");
            let now = Instant::now();
            let mut sim = Sim::new(&pool, &conn, now);
            sim.drive(&pool, (now, RTT * 40), RTT, BOUND, u32::MAX);
            assert_eq!(sim.target, STREAM_WINDOW);
            assert!(pool.stats().denied > 0);
            second = Some(sim);
        }
    }
    // The budget came back only once h2 had drained to about one window.
    assert!(reads > 40, "{reads}");
    assert!(
        held(taken) <= i64::from(STREAM_WINDOW) + FRAME,
        "{}",
        held(taken)
    );
    let mut second = second.expect("tried while the budget was held");
    let now = Instant::now();
    second.drive(&pool, (now, RTT * 40), RTT, BOUND, u32::MAX);
    assert_eq!(second.target, STREAM_WINDOW_MAX);
    drop(second);
    drop(stream);
    assert_eq!(pool.stats().used, 0);
    driver.abort();
    server.abort();
}

#[tokio::test(start_paused = true)]
async fn a_step_the_bottleneck_does_not_reward_is_given_back_over_real_h2() {
    // T8b (B-06 v34 review): T8's 1 MiB/s path lets the window-limited check
    // alone stop the growth, so its hold never acts. At 1.2 MB/s (216 KB per
    // 180 ms) the stream grows past what the path carries while its window
    // still binds; the next step to twice that is not rewarded, so it is
    // given back and the stream holds. The budget returns to the remaining
    // extra once the relay's credit has drained, and the relay holds less
    // credit than when the step is kept.
    const RATE: u64 = 1_200_000;
    const RUN: Duration = Duration::from_secs(12);
    let bdp = RATE * RTT.as_millis() as u64 / 1000;
    let line = Line {
        downlink: Some(RATE),
        pings: Some(Duration::from_millis(500)),
        ..OPEN_LINE
    };
    let (pool, _lines) = new_pool();
    let held = exchange(
        line,
        Window::Policy,
        vec![Send::Bulk(RUN)],
        pool,
        conn_at(RTT),
    )
    .await;
    println!("held {held:?} bdp {bdp}");
    let (pool, _lines) = new_pool();
    pool.no_hold_for_test();
    let kept = exchange(
        line,
        Window::Policy,
        vec![Send::Bulk(RUN)],
        pool,
        conn_at(RTT),
    )
    .await;
    println!("kept {kept:?}");
    // Given back: its window is below the largest it was granted, still
    // above the initial one, and only that extra is charged now.
    assert!(held.stats.largest < held.stats.high, "{held:?}");
    assert!(held.stats.largest > STREAM_WINDOW, "{held:?}");
    assert_eq!(
        held.stats.used,
        held.stats.largest - STREAM_WINDOW,
        "{held:?}"
    );
    assert!(held.stats.high_used > held.stats.used, "{held:?}");
    assert!(
        u64::from(held.stats.high) <= 2 * bdp + 32 * 1024,
        "{held:?} bdp {bdp}"
    );
    // Without the hold the same step is kept, with more credit at the relay.
    assert_eq!(kept.stats.largest, kept.stats.high, "{kept:?}");
    assert!(held.stats.largest < kept.stats.largest, "{held:?} {kept:?}");
    assert!(held.credit_after < kept.credit_after, "{held:?} {kept:?}");
    // Either way the stream carries the path's rate.
    for report in [&held, &kept] {
        assert!(report.bulk >= RATE * RUN.as_secs() * 9 / 10, "{report:?}");
    }
}

// ---- v35 RED tests: only a9dadf6e's API, so the red run builds them over
// ---- a9dadf6e's policy unchanged ----

/// Drives `sim` with a sender that delivers `share` of its window per round
/// trip `rtt` for `run` from `from`, in eighths of a round trip, and
/// returns where it stopped with every step it took and when.
fn steps_of(
    sim: &mut Sim,
    pool: &PoolWindow,
    (from, run): (Instant, Duration),
    rtt: Duration,
    share: (u32, u32),
) -> (Instant, Vec<(Instant, WindowStep)>) {
    let mut now = from;
    let mut steps = Vec::new();
    while now < from + run {
        let per_rtt = sim.target / share.1 * share.0;
        if let Some(step) = sim.release(per_rtt / 8, now) {
            steps.push((now, step));
        }
        let stats = pool.stats();
        assert!(stats.used <= stats.budget, "{stats:?}");
        now += rtt / 8;
    }
    (now, steps)
}

fn grows(steps: &[(Instant, WindowStep)]) -> usize {
    steps
        .iter()
        .filter(|(_, step)| matches!(step, WindowStep::Grow(_)))
        .count()
}

#[test]
fn a_grown_stream_under_a_standing_queue_returns_to_the_v33_window() {
    // T10 (RED): a stream grown to 1 MiB whose delivery then falls to 3/8 of
    // its window per round trip: q about 220 ms. v35 returns it to 128 KiB
    // within 5 round trips and never grows it there; the budget stays
    // charged until the relay's credit is back within 128 KiB. a9dadf6e
    // keeps the megabyte (neither 5/8 nor under a quarter).
    let (pool, _lines) = new_pool();
    let conn = conn_at(RTT);
    let start = Instant::now();
    let mut sim = Sim::new(&pool, &conn, start);
    let (now, _) = steps_of(&mut sim, &pool, (start, RTT * 40), RTT, BOUND);
    assert_eq!(sim.target, STREAM_WINDOW_MAX);
    let extra = STREAM_WINDOW_MAX - STREAM_WINDOW;
    let mut at = now;
    let mut reset = None;
    let mut charged_while_held = true;
    while at < now + RTT * 30 {
        let per_rtt = sim.target / 8 * 3;
        let step = sim.release(per_rtt / 8, at);
        match step {
            Some(WindowStep::Shrink(amount)) if reset.is_none() => {
                assert_eq!(amount, extra, "a whole reset");
                reset = Some(at);
            }
            Some(other) => panic!("{other:?} after the reset"),
            None => {}
        }
        if reset.is_some() {
            let held = sim.peer + sim.unreleased;
            let used = pool.stats().used;
            if held > STREAM_WINDOW {
                charged_while_held &= used == extra;
            } else {
                assert!(used == 0 || used == extra, "{used}");
            }
        }
        at += RTT / 8;
    }
    let reset = reset.expect("the standing queue reset the window");
    assert!(reset - now <= RTT * 5, "{:?}", reset - now);
    assert_eq!(sim.target, STREAM_WINDOW);
    assert!(charged_while_held);
    assert_eq!(pool.stats().used, 0, "returned once the credit drained");
}

#[test]
fn a_burst_after_a_hold_does_not_grow_a_queued_stream() {
    // T11 (RED): 19/32 of the window per round trip for 4 round trips (q
    // about 80 ms), then a round trip with nothing, then every byte of
    // credit the relay holds at once (a hole filled), for 60 s. a9dadf6e
    // grows on the burst's measurement; v35 never grows, and its flow_queue
    // line shows low measurements: the history, not the burst's own
    // measurement, kept it from growing.
    let (pool, lines) = new_pool();
    let conn = conn_at(RTT);
    conn.set_id(5);
    let start = Instant::now();
    let mut sim = Sim::new(&pool, &conn, start);
    let mut now = start;
    let mut steps = Vec::new();
    while now < start + Duration::from_secs(60) {
        for _ in 0..32 {
            let per_rtt = sim.target / 32 * 19;
            if let Some(step) = sim.release(per_rtt / 8, now) {
                steps.push((now - start, step));
            }
            now += RTT / 8;
        }
        now += RTT;
        let all = sim.peer;
        if all > 0 {
            if let Some(step) = sim.release(all, now) {
                steps.push((now - start, step));
            }
        }
        now += RTT / 8;
    }
    assert!(
        !steps
            .iter()
            .any(|(_, step)| matches!(step, WindowStep::Grow(_))),
        "{steps:?}"
    );
    assert_eq!(sim.target, STREAM_WINDOW);
    drop(sim);
    let queue = lines.of("flow_queue");
    assert_eq!(queue.len(), 1, "{queue:?}");
    let bins: Vec<u64> = queue[0]
        .split(' ')
        .find_map(|field| field.strip_prefix("q_bins:"))
        .unwrap()
        .split('-')
        .map(|n| n.parse().unwrap())
        .collect();
    assert!(bins[0] > 0 && bins[1] > bins[0], "{queue:?}");
}

#[test]
fn the_long_round_trip_caps_the_grow_queue_at_60_ms() {
    // T12 (RED): 21/32 of the window per round trip. At 300 ms q is about
    // 82 ms: v35 never grows (a9dadf6e does: 0.656 >= 0.625). At 180 ms q is
    // about 49 ms: both grow.
    let long = Duration::from_millis(300);
    let (pool, _lines) = new_pool();
    let conn = conn_at(long);
    let start = Instant::now();
    let mut sim = Sim::new(&pool, &conn, start);
    let (_, steps) = steps_of(
        &mut sim,
        &pool,
        (start, Duration::from_secs(60)),
        long,
        (21, 32),
    );
    assert_eq!(grows(&steps), 0, "{steps:?}");
    assert_eq!(pool.stats().high, STREAM_WINDOW);
    let (pool, _lines) = new_pool();
    let conn = conn_at(RTT);
    let mut sim = Sim::new(&pool, &conn, start);
    let (_, steps) = steps_of(
        &mut sim,
        &pool,
        (start, Duration::from_secs(10)),
        RTT,
        (21, 32),
    );
    assert!(grows(&steps) > 0, "{steps:?}");
}

#[test]
fn two_streams_on_one_connection_never_step_together() {
    // T13 (RED): two window-bound streams on one connection, started
    // together. Their growth steps are at least a step's settling and
    // measurement apart (three round trips, less a tick), and both still
    // reach 1 MiB within twice the time one stream alone takes. a9dadf6e
    // steps both at the same release.
    let start = Instant::now();
    let (pool, _lines) = new_pool();
    let alone = conn_at(RTT);
    let mut one = Sim::new(&pool, &alone, start);
    let mut now = start;
    while one.target < STREAM_WINDOW_MAX {
        assert!(now < start + RTT * 100, "never reached the maximum");
        let per_rtt = one.target / BOUND.1 * BOUND.0;
        one.release(per_rtt / 8, now);
        now += RTT / 8;
    }
    let single = now - start;
    drop(one);
    let (pool, _lines) = new_pool();
    let conn = conn_at(RTT);
    let mut sims = [Sim::new(&pool, &conn, start), Sim::new(&pool, &conn, start)];
    let mut steps = Vec::new();
    let mut reached = [None, None];
    let mut now = start;
    while now < start + single * 2 + RTT {
        for (index, sim) in sims.iter_mut().enumerate() {
            let per_rtt = sim.target / BOUND.1 * BOUND.0;
            if let Some(WindowStep::Grow(added)) = sim.release(per_rtt / 8, now) {
                steps.push((now - start, index, added));
            }
            if sim.target == STREAM_WINDOW_MAX && reached[index].is_none() {
                reached[index] = Some(now - start);
            }
        }
        now += RTT / 8;
    }
    for pair in steps.windows(2) {
        assert!(pair[1].0 - pair[0].0 >= RTT * 3 - RTT / 8, "{steps:?}");
    }
    for at in reached {
        let at = at.expect("both reach the maximum");
        assert!(at <= single * 2, "{at:?} single {single:?} {steps:?}");
    }
}

#[test]
fn every_stream_on_a_connection_steps_once_before_any_steps_again() {
    // T13b (v35 review): four window-bound streams on one connection,
    // started together. A grown stream yields the step token while a
    // stream still at 128 KiB waits for it, so the connection's first four
    // steps are the four streams' first; steps stay a settling and a
    // measurement apart; and every stream reaches 1 MiB within four times
    // the time one stream alone takes. 36e9a961 let the stream just judged
    // claim the token again in the same measurement: the fourth stream's
    // first step came after the first three reached 1 MiB.
    let start = Instant::now();
    let (pool, _lines) = new_pool();
    let alone = conn_at(RTT);
    let mut one = Sim::new(&pool, &alone, start);
    let mut now = start;
    while one.target < STREAM_WINDOW_MAX {
        assert!(now < start + RTT * 100, "never reached the maximum");
        let per_rtt = one.target / BOUND.1 * BOUND.0;
        one.release(per_rtt / 8, now);
        now += RTT / 8;
    }
    let single = now - start;
    drop(one);
    let (pool, _lines) = new_pool();
    let conn = conn_at(RTT);
    let mut sims: Vec<Sim> = (0..4).map(|_| Sim::new(&pool, &conn, start)).collect();
    let mut steps = Vec::new();
    let mut reached = [None; 4];
    let mut now = start;
    while now < start + single * 4 + RTT && reached.iter().any(Option::is_none) {
        for (index, sim) in sims.iter_mut().enumerate() {
            let per_rtt = sim.target / BOUND.1 * BOUND.0;
            if let Some(WindowStep::Grow(added)) = sim.release(per_rtt / 8, now) {
                steps.push((now - start, index, added));
            }
            if sim.target == STREAM_WINDOW_MAX && reached[index].is_none() {
                reached[index] = Some(now - start);
            }
        }
        now += RTT / 8;
    }
    let mut first: Vec<usize> = steps.iter().take(4).map(|(_, index, _)| *index).collect();
    first.sort_unstable();
    assert_eq!(first, [0, 1, 2, 3], "{steps:?}");
    for pair in steps.windows(2) {
        assert!(pair[1].0 - pair[0].0 >= RTT * 3 - RTT / 8, "{steps:?}");
    }
    for at in reached {
        let at = at.expect("every stream reaches the maximum");
        assert!(at <= single * 4, "{at:?} single {single:?} {steps:?}");
    }
}

#[test]
fn a_grown_stream_in_the_60_to_120_ms_zone_gives_its_steps_back() {
    // T28 (RED, critic REQUIRED 7): a stream grown to 1 MiB whose delivery
    // then holds q at about 95 ms (9/16 of its window per round trip,
    // whatever the window: the helper's sender never lets the queue fall).
    // v35 gives back what each measurement says it overshot, until it is at
    // v33's window; a9dadf6e keeps the megabyte with that queue standing.
    let (pool, _lines) = new_pool();
    let conn = conn_at(RTT);
    let start = Instant::now();
    let mut sim = Sim::new(&pool, &conn, start);
    let (now, _) = steps_of(&mut sim, &pool, (start, RTT * 40), RTT, BOUND);
    assert_eq!(sim.target, STREAM_WINDOW_MAX);
    let (_, steps) = steps_of(
        &mut sim,
        &pool,
        (now, Duration::from_secs(60)),
        RTT,
        (9, 16),
    );
    assert_eq!(grows(&steps), 0, "{steps:?}");
    assert_eq!(sim.target, STREAM_WINDOW, "{steps:?}");
    // Each give-back is a part of the extra, never the whole megabyte at once.
    assert!(steps.len() > 2, "{steps:?}");
    assert!(
        steps.iter().all(|(_, step)| matches!(step,
        WindowStep::Shrink(back) if *back < STREAM_WINDOW_MAX - STREAM_WINDOW)),
        "{steps:?}"
    );
}

#[test]
fn the_v35_queue_lines_are_stable_bounded_and_carry_no_address() {
    // T20 (RED): every pool_rtt line comes with a pool_queue line for its
    // connection (its latest bulk q, the credit its streams held, their
    // extras), and a bulk flow's end logs flow_queue beside flow_bulk.
    // Stable, at most one a second, no address. a9dadf6e logs neither.
    let (pool, lines) = new_pool();
    let conn = conn_at(RTT);
    conn.set_id(3);
    let start = Instant::now();
    let mut sim = Sim::new(&pool, &conn, start);
    sim.drive(
        &pool,
        (start, Duration::from_secs(12)),
        RTT,
        BOUND,
        u32::MAX,
    );
    drop(sim);
    let queue = lines.of("pool_queue");
    let rtts = lines.of("pool_rtt");
    assert!((10..=13).contains(&queue.len()), "{queue:?}");
    assert_eq!(queue.len(), rtts.len());
    for line in &queue {
        let fields: Vec<&str> = line.split(' ').collect();
        assert_eq!(fields.len(), 5, "{line}");
        assert_eq!(fields[1], "conn:3", "{line}");
        for (field, name) in fields[2..].iter().zip(["q_ms:", "held_kib:", "extra_kib:"]) {
            let value = field.strip_prefix(name).unwrap_or_else(|| panic!("{line}"));
            assert!(value == "none" || value.parse::<u64>().is_ok(), "{line}");
        }
    }
    // At the maximum the extra is 896 KiB and the credit held most of it.
    assert!(
        queue.iter().any(|line| line.ends_with(" extra_kib:896")),
        "{queue:?}"
    );
    let flows = lines.of("flow_queue");
    assert_eq!(flows.len(), 1, "{flows:?}");
    assert!(
        flows[0].starts_with("flow_queue conn:3 q_bins:")
            && flows[0].contains(" grows:6 ")
            && flows[0].ends_with(" resets:0-0"),
        "{flows:?}"
    );
    for line in lines.all() {
        assert!(
            !line
                .split(|c: char| !(c.is_ascii_hexdigit() || c == '.' || c == ':'))
                .any(|token| token.matches('.').count() >= 3 || token.matches(':').count() >= 2),
            "{line}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_rate_drop_after_growth_returns_the_queue_to_the_v33_bound() {
    // T16 (RED, real h2): 2.5 MB/s for 15 s, then 1.5 MB/s until 40 s, PINGs
    // every 100 ms. Over 25 to 40 s v35's window leaves no standing queue
    // (PONG queue p50 at most 120 ms) and stays within twice the path's
    // bandwidth-delay product after the drop; the stream still carries most
    // of the line's rate. a9dadf6e keeps a grown window that queues.
    const BEFORE: u64 = 2_500_000;
    const AFTER: u64 = 1_500_000;
    let line = Line {
        downlink: Some(BEFORE),
        pings: Some(Duration::from_millis(100)),
        drop_to: Some((Duration::from_secs(15), AFTER)),
        back_to: None,
        holes: None,
    };
    let (pool, _lines) = new_pool();
    let report = exchange(
        line,
        Window::Policy,
        vec![Send::Bulk(Duration::from_secs(40))],
        pool,
        conn_at(RTT),
    )
    .await;
    let late = (Duration::from_secs(25), Duration::from_secs(40));
    let p50 = report.pong_queue(late, 50);
    let bdp = AFTER * RTT.as_millis() as u64 / 1000;
    let largest = report.largest_between(late);
    let bulk = report.bulk_between(late);
    println!(
        "rate drop: pong p50 {p50:?} p90 {:?} largest {largest} bdp {bdp} bulk {bulk} high {}",
        report.pong_queue(late, 90),
        report.stats.high
    );
    assert!(p50 <= Duration::from_millis(120), "{p50:?}");
    assert!(u64::from(largest) <= 2 * bdp + 32 * 1024, "{largest}");
    assert!(bulk >= AFTER * 15 * 9 / 10, "{bulk}");
}

#[tokio::test(start_paused = true)]
async fn a_bottleneck_leaves_no_standing_queue_behind_the_window() {
    // T17 (GUARD): T8's 1 MiB/s path with PINGs every 100 ms. Over 5 to 20 s
    // the PONG queue's p90 is at most Q_SHRINK and one 16 KiB frame (136 ms),
    // and the stream carries the path's rate.
    const RATE: u64 = 1_048_576;
    let line = Line {
        downlink: Some(RATE),
        pings: Some(Duration::from_millis(100)),
        ..OPEN_LINE
    };
    let (pool, _lines) = new_pool();
    let report = exchange(
        line,
        Window::Policy,
        vec![Send::Bulk(Duration::from_secs(20))],
        pool,
        conn_at(RTT),
    )
    .await;
    let steady = (Duration::from_secs(5), Duration::from_secs(20));
    let p90 = report.pong_queue(steady, 90);
    let bulk = report.bulk_between(steady);
    println!(
        "bottleneck: pong p90 {p90:?} bulk {bulk} high {}",
        report.stats.high
    );
    assert!(p90 <= Duration::from_millis(136), "{p90:?}");
    assert!(bulk >= RATE * 15 * 95 / 100, "{bulk}");
}

#[tokio::test(start_paused = true)]
async fn a_hole_bursting_path_does_not_grow_a_stream_v33_already_queues() {
    // T18 (RED where it reproduces, else GUARD): 400 KB/s, so v33's 128 KiB
    // already queues at the relay, and once a second the path holds the
    // data for a round trip and delivers it at once (a hole filled). A burst
    // measurement must not grow the window: the relay never holds more than
    // the initial credit.
    let line = Line {
        downlink: Some(400_000),
        pings: Some(Duration::from_millis(500)),
        drop_to: None,
        back_to: None,
        holes: Some((Duration::from_secs(1), RTT)),
    };
    let (pool, _lines) = new_pool();
    let report = exchange(
        line,
        Window::Policy,
        vec![Send::Bulk(Duration::from_secs(30))],
        pool,
        conn_at(RTT),
    )
    .await;
    println!(
        "holes {:?} credit_high {}",
        report.stats, report.credit_high
    );
    assert_eq!(report.stats.high, STREAM_WINDOW, "{:?}", report.stats);
    assert!(
        report.credit_high <= i64::from(STREAM_WINDOW),
        "{}",
        report.credit_high
    );
}
