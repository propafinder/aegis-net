//! B-06 v35: tests of the v35 stream window's new API (T14, T15, T19, T27,
//! the invariants I-2 to I-8 over random load, the faithful helper against
//! real h2, and the hold after a step whose own queue gave it back). Only
//! v35's stream_window.rs declares this module, so the red run over
//! a9dadf6e's policy never builds it: each test here is red by
//! construction.
use super::tests::{
    conn_at, exchange, new_pool, pool_with, Lines, Send, Sim, Window, BOUND, OPEN_LINE, RTT,
};
use super::*;

fn fixed_pool() -> (Arc<PoolWindow>, Arc<Lines>) {
    let lines = Arc::new(Lines::default());
    (
        PoolWindow::new_with_mode(WindowMode::Fixed, lines.clone()),
        lines,
    )
}

/// The value of `name` in one telemetry line.
fn field<'a>(line: &'a str, name: &str) -> &'a str {
    line.split(' ')
        .find_map(|token| token.strip_prefix(name))
        .unwrap_or_else(|| panic!("{name} in {line}"))
}

/// The median of `values`.
fn median(mut values: Vec<u64>) -> u64 {
    assert!(!values.is_empty());
    values.sort_unstable();
    values[values.len() / 2]
}

/// Drives `sim` with `share` of its window per round trip for `run`.
fn drive_steps(
    sim: &mut Sim,
    (from, run): (Instant, Duration),
    share: (u32, u32),
) -> (Instant, Vec<(Instant, WindowStep)>) {
    let mut now = from;
    let mut steps = Vec::new();
    while now < from + run {
        let per_rtt = sim.target / share.1 * share.0;
        if let Some(step) = sim.release(per_rtt / 8, now) {
            steps.push((now, step));
        }
        now += RTT / 8;
    }
    (now, steps)
}

#[test]
fn the_rule_thresholds_are_as_documented() {
    // T15: the exact edges of the zones, compared in integers, with no
    // tolerance (they replace v34's 5/8 asserts).
    assert_eq!(
        q_grow(Duration::from_millis(150)),
        Duration::from_millis(50)
    );
    assert_eq!(
        q_grow(Duration::from_millis(180)),
        Duration::from_millis(60)
    );
    assert_eq!(
        q_grow(Duration::from_millis(300)),
        Duration::from_millis(60)
    );
    assert_eq!(q_grow(RTT_FLOOR), RTT_FLOOR / 3);
    assert!(Q_SHRINK >= Q_GROW_MAX * 2);
    let at = |held: u128, rtt_ms: u64| {
        CreditLoop {
            held,
            bytes: 1_000,
            elapsed_us: 1_000_000,
        }
        .zone(Duration::from_millis(rtt_ms))
    };
    // 180 ms: RTT/3 and 60 ms coincide; low up to 1.333 round trips.
    assert_eq!(at(240_000_000, 180), Zone::Low);
    assert_eq!(at(240_000_001, 180), Zone::Mid);
    // 300 ms: the 60 ms cap binds before RTT/3 (100 ms).
    assert_eq!(at(360_000_000, 300), Zone::Low);
    assert_eq!(at(360_000_001, 300), Zone::Mid);
    // 150 ms: RTT/3 (50 ms) binds before the cap.
    assert_eq!(at(200_000_000, 150), Zone::Low);
    assert_eq!(at(200_000_001, 150), Zone::Mid);
    // A standing queue from exactly Q_SHRINK.
    assert_eq!(at(299_999_999, 180), Zone::Mid);
    assert_eq!(at(300_000_000, 180), Zone::High);
    // Nothing released: no evidence of a bound.
    let none = CreditLoop {
        held: 1,
        bytes: 0,
        elapsed_us: 1,
    };
    assert_eq!(none.zone(RTT), Zone::High);
    let queued = CreditLoop {
        held: 300_000_000,
        bytes: 1_000,
        elapsed_us: 1_000_000,
    };
    assert_eq!(queued.delay_us(RTT), 120_000);
    assert_eq!(queued.mean_held(), 300);
    assert_eq!(queued.delay_us(Duration::from_millis(400)), 0);
    // The zone's give-back: at 180 ms the goal is 180 + 60 ms of loop; a
    // loop of 300 ms keeps 240/300 of the window.
    assert_eq!(frozen_target(400_000, queued, RTT), 320_000);
    // Never below v33's window, never above the window, nothing measured:
    // nothing to give back.
    assert_eq!(frozen_target(150_000, queued, RTT), STREAM_WINDOW);
    let fast = CreditLoop {
        held: 100_000_000,
        ..queued
    };
    assert_eq!(frozen_target(400_000, fast, RTT), 400_000);
    assert_eq!(frozen_target(400_000, none, RTT), 400_000);
}

#[test]
fn a_reset_clears_the_history() {
    // T14: after a standing queue's reset (T10's), with a window-bound
    // sender back, the first step comes no earlier than GROW_HISTORY fresh
    // measurements later, and the reset (long after its last kept step) set
    // no hold.
    let (pool, _lines) = new_pool();
    let conn = conn_at(RTT);
    let start = Instant::now();
    let mut sim = Sim::new(&pool, &conn, start);
    let (now, _) = drive_steps(&mut sim, (start, RTT * 40), BOUND);
    assert_eq!(sim.target, STREAM_WINDOW_MAX);
    let (now, steps) = drive_steps(&mut sim, (now, RTT * 12), (3, 8));
    let (reset, _) = steps
        .iter()
        .find(|(_, step)| *step == WindowStep::Shrink(STREAM_WINDOW_MAX - STREAM_WINDOW))
        .copied()
        .expect("a reset");
    assert_eq!(sim.policy.hold_for_test(), None);
    assert_eq!(sim.policy.queue_for_test().2, (0, 1));
    let measured = sim.policy.zones_for_test().len();
    let (_, steps) = drive_steps(&mut sim, (now, RTT * 30), BOUND);
    let (grown, _) = steps
        .iter()
        .find(|(_, step)| matches!(step, WindowStep::Grow(_)))
        .copied()
        .expect("grows again");
    // Three fresh measurements, each at least EVAL_RTTS long.
    assert!(
        grown - reset >= RTT * EVAL_RTTS * GROW_HISTORY - RTT / 8,
        "{:?}",
        grown - reset
    );
    assert!(sim.policy.zones_for_test().len() >= measured + GROW_HISTORY as usize);
}

#[test]
fn a_reset_right_after_a_kept_step_holds() {
    // T27 (critic REQUIRED 6): a step kept at its judgment, then its own
    // queue (q about 220 ms twice) returns the window to 128 KiB. That was
    // the step's doing: the stream holds for HOLD_RTTS, so it does not grow
    // and reset again every few seconds. The budget covers that one step
    // only, so no second step (and no judgment's own hold) comes between.
    let (pool, _lines) = pool_with(STREAM_WINDOW / 2);
    let conn = conn_at(RTT);
    let start = Instant::now();
    let mut sim = Sim::new(&pool, &conn, start);
    let mut now = start;
    // Window-bound until the first step and its judgment (kept).
    while sim.policy.queue_for_test().1 == 0 || sim.policy.latest_for_test().is_none() {
        let per_rtt = sim.target / BOUND.1 * BOUND.0;
        sim.release(per_rtt / 8, now);
        now += RTT / 8;
    }
    let judged = sim.policy.zones_for_test().len() + 1;
    while sim.policy.zones_for_test().len() < judged {
        let per_rtt = sim.target / BOUND.1 * BOUND.0;
        sim.release(per_rtt / 8, now);
        now += RTT / 8;
    }
    assert_eq!(sim.target, STREAM_WINDOW + STREAM_WINDOW / 2);
    assert_eq!(sim.policy.hold_for_test(), None);
    assert!(pool.stats().denied > 0, "a second step was refused");
    // Its queue stands.
    let (now, steps) = drive_steps(&mut sim, (now, RTT * 8), (3, 8));
    let reset = steps
        .iter()
        .find(|(_, step)| matches!(step, WindowStep::Shrink(_)))
        .map(|(at, _)| *at)
        .expect("reset");
    assert_eq!(sim.target, STREAM_WINDOW);
    assert_eq!(sim.policy.queue_for_test().2, (1, 0));
    assert!(sim.policy.hold_for_test().is_some());
    // Window-bound again: no step within the hold.
    let (_, steps) = drive_steps(&mut sim, (now, RTT * (HOLD_RTTS + 12)), BOUND);
    let first = steps
        .iter()
        .find(|(_, step)| matches!(step, WindowStep::Grow(_)))
        .map(|(at, _)| *at)
        .expect("grows after the hold");
    assert!(first - reset >= RTT * HOLD_RTTS, "{:?}", first - reset);
}

#[test]
fn a_waiting_mark_lapses_and_goes_with_the_stream_that_claimed() {
    // v35 review: the mark a stream at STREAM_WINDOW leaves while it waits
    // for the step token lasts its span, goes once that stream claims the
    // token (so grown streams stop yielding to it at once), and a later
    // stream's mark is never dropped by an earlier one's.
    let conn = conn_at(RTT);
    let now = Instant::now();
    let span = RTT * STEP_RTTS;
    assert!(!conn.step_wanted(now));
    let first = conn.want_step(now, span);
    assert!(conn.step_wanted(now + span - RTT / 8));
    assert!(!conn.step_wanted(now + span));
    conn.drop_want(first);
    assert!(!conn.step_wanted(now));
    let early = conn.want_step(now, span);
    let late = conn.want_step(now + RTT, span);
    conn.drop_want(early);
    assert!(conn.step_wanted(now + span), "the later mark stays");
    conn.drop_want(late);
    assert!(!conn.step_wanted(now));
}

/// A tiny deterministic generator for the random-load test.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self, below: u64) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) % below
    }
}

#[test]
fn every_step_and_reset_keeps_the_invariants_under_random_load() {
    // I-1 to I-5 and I-8, two streams on one connection under 600 s of
    // random load (shares from under-used to window-bound, idle gaps,
    // bursts), five seeds:
    // - I-1: a stream's credit and unread bytes stay within 128 KiB and its
    //   charge; the session's charges within the budget;
    // - I-2: every Grow follows GROW_HISTORY low measurements in a row, with
    //   no hold;
    // - I-3: a measurement that makes the last STANDING_HISTORY zones high
    //   leaves the window at v33's;
    // - I-4: two Grow steps on the connection are at least a settling round
    //   trip and a measurement apart;
    // - I-5: a step's target is at most max(128 KiB, min(2 x delivered,
    //   1 MiB));
    // - I-8: at a Grow, the credit held is at most 4/3 of what it
    //   delivered per round trip (3 x held <= 4 x bytes x rtt).
    const SHARES: [(u32, u32); 9] = [
        (1, 8),
        (3, 8),
        (1, 2),
        (9, 16),
        (19, 32),
        (21, 32),
        (3, 4),
        (7, 8),
        (1, 1),
    ];
    for seed in 1..=5u64 {
        let mut random = Lcg(seed);
        let (pool, _lines) = new_pool();
        let conn = conn_at(RTT);
        let start = Instant::now();
        let mut sims = [Sim::new(&pool, &conn, start), Sim::new(&pool, &conn, start)];
        let mut shares = [BOUND, BOUND];
        let mut until = [start, start];
        let mut last_grow: Option<Instant> = None;
        let mut grows = 0;
        let mut resets = 0;
        let mut now = start;
        while now < start + Duration::from_secs(600) {
            for (index, sim) in sims.iter_mut().enumerate() {
                if now >= until[index] {
                    shares[index] = SHARES[random.next(SHARES.len() as u64) as usize];
                    until[index] = now + RTT * (2 + random.next(20) as u32);
                    if random.next(10) == 0 {
                        // An idle gap.
                        until[index] += RTT * (1 + random.next(30) as u32);
                        continue;
                    }
                }
                let share = shares[index];
                let per_rtt = sim.target / share.1 * share.0;
                let before = sim.policy.zones_for_test().len();
                let window = sim.target;
                let step = sim.release(per_rtt / 8, now);
                let zones = sim.policy.zones_for_test();
                if let Some(WindowStep::Grow(added)) = step {
                    grows += 1;
                    assert!(zones.len() >= GROW_HISTORY as usize, "seed {seed}");
                    assert!(
                        zones[zones.len() - GROW_HISTORY as usize..]
                            .iter()
                            .all(|zone| *zone == Zone::Low),
                        "I-2 seed {seed}: {:?}",
                        &zones[zones.len().saturating_sub(4)..]
                    );
                    let (credit, rtt, delivered) = sim.policy.latest_for_test().unwrap();
                    assert!(
                        3 * credit.held <= 4 * u128::from(credit.bytes) * u128::from(micros(rtt)),
                        "I-8 seed {seed}"
                    );
                    let bound = (2 * delivered).min(u64::from(STREAM_WINDOW_MAX));
                    assert!(
                        u64::from(window + added) <= bound.max(u64::from(STREAM_WINDOW)),
                        "I-5 seed {seed}"
                    );
                    if let Some(last) = last_grow {
                        assert!(
                            now - last >= RTT * (EVAL_RTTS + 1) - RTT / 8,
                            "I-4 seed {seed}: {:?}",
                            now - last
                        );
                    }
                    last_grow = Some(now);
                }
                if zones.len() > before
                    && zones.len() >= STANDING_HISTORY as usize
                    && zones[zones.len() - STANDING_HISTORY as usize..]
                        .iter()
                        .all(|zone| *zone == Zone::High)
                {
                    assert_eq!(sim.target, STREAM_WINDOW, "I-3 seed {seed}");
                }
                if matches!(step, Some(WindowStep::Shrink(_))) && sim.target == STREAM_WINDOW {
                    resets += 1;
                }
                let held = sim.peer + sim.unreleased;
                assert!(
                    held <= STREAM_WINDOW + sim.policy.charged_for_test(),
                    "I-1 seed {seed}"
                );
                let stats = pool.stats();
                assert!(stats.used <= stats.budget, "I-1 seed {seed}");
                assert!(sim.target <= STREAM_WINDOW_MAX);
            }
            now += RTT / 8;
        }
        // The load exercised both directions.
        assert!(
            grows > 5 && resets > 0,
            "seed {seed}: grows {grows} resets {resets}"
        );
        drop(sims);
        assert_eq!(pool.stats().used, 0);
    }
}

#[test]
fn the_fixed_mode_never_steps_and_keeps_every_measurement() {
    // I-6 on the simulated window: a window-bound stream in Fixed mode
    // never steps and never charges the budget (nothing denied), while it
    // measures, marks its connection bulk and logs every line.
    let (pool, lines) = fixed_pool();
    let conn = conn_at(RTT);
    conn.set_id(2);
    let start = Instant::now();
    let mut sim = Sim::new(&pool, &conn, start);
    let (_, steps) = drive_steps(&mut sim, (start, Duration::from_secs(12)), BOUND);
    assert!(steps.is_empty(), "{steps:?}");
    assert_eq!(sim.target, STREAM_WINDOW);
    assert!(sim.peer <= STREAM_WINDOW);
    assert!(conn.bulk(start + Duration::from_secs(12)));
    let (bins, grows, resets) = sim.policy.queue_for_test();
    assert!(bins[0] > 10, "{bins:?}");
    assert_eq!((grows, resets), (0, (0, 0)));
    drop(sim);
    let stats = pool.stats();
    assert_eq!(
        (stats.used, stats.denied, stats.high),
        (0, 0, STREAM_WINDOW)
    );
    for event in ["pool_rtt", "pool_queue", "flow_bulk", "flow_queue"] {
        assert!(!lines.of(event).is_empty(), "{event}");
    }
    assert!(lines
        .of("pool_queue")
        .iter()
        .all(|line| line.ends_with(" extra_kib:0")));
}

#[tokio::test(start_paused = true)]
async fn the_fixed_mode_is_v33_on_the_wire_and_keeps_the_telemetry() {
    // T19 (I-6 over real h2): on T2's open link and T8's 1 MiB/s link, the
    // Fixed mode's stream credit never exceeds SETTINGS (131072) and it
    // moves no more than v33's bound; pool_rtt, pool_queue, flow_bulk and
    // flow_queue are logged, its connection counts as bulk, and the budget
    // is never asked.
    const RUN: Duration = Duration::from_secs(10);
    let bound = u64::from(STREAM_WINDOW) * RUN.as_millis() as u64 / RTT.as_millis() as u64;
    for line in [
        OPEN_LINE,
        super::tests::Line {
            downlink: Some(1_048_576),
            pings: Some(Duration::from_millis(500)),
            ..OPEN_LINE
        },
    ] {
        let (pool, lines) = fixed_pool();
        let conn = conn_at(RTT);
        conn.set_id(4);
        let report = exchange(
            line,
            Window::Policy,
            vec![Send::Bulk(RUN)],
            pool.clone(),
            conn.clone(),
        )
        .await;
        println!("fixed {line:?}: {report:?}");
        assert!(report.credit_high <= i64::from(STREAM_WINDOW), "{report:?}");
        assert!(
            report.bulk_within <= bound + u64::from(STREAM_WINDOW),
            "{report:?} bound {bound}"
        );
        assert_eq!(
            (
                report.stats.high,
                report.stats.denied,
                report.stats.high_used
            ),
            (STREAM_WINDOW, 0, 0)
        );
        for event in ["pool_rtt", "pool_queue", "flow_bulk", "flow_queue"] {
            assert!(!lines.of(event).is_empty(), "{event} {:?}", lines.all());
        }
        assert!(lines
            .of("flow_queue")
            .iter()
            .all(|line| line.contains(" grows:0 ")));
    }
}

#[tokio::test(start_paused = true)]
async fn the_faithful_helper_matches_real_h2() {
    // Critic REQUIRED 10: the simulated window the unit tests drive is
    // checked against real h2. A window-bound stream in Fixed mode on the
    // open 180 ms link and on T8's 1 MiB/s link: its delivered share of the
    // window, the credit it held and its q, from its pool_queue lines; then
    // the helper at the nearest 1/32 of that share. Declared tolerance: the
    // mean credit held within an eighth of the window (16 KiB: the helper
    // spreads the releases of a round trip evenly, while an open link
    // delivers each window in one burst) and q within 25 ms.
    const RUN: Duration = Duration::from_secs(12);
    for line in [
        OPEN_LINE,
        super::tests::Line {
            downlink: Some(1_048_576),
            ..OPEN_LINE
        },
    ] {
        let (pool, lines) = fixed_pool();
        let conn = conn_at(RTT);
        conn.set_id(1);
        let report = exchange(line, Window::Policy, vec![Send::Bulk(RUN)], pool, conn).await;
        let share = report.bulk_between((Duration::from_secs(2), RUN)) as f64
            / (RUN - Duration::from_secs(2)).as_secs_f64()
            * RTT.as_secs_f64()
            / f64::from(STREAM_WINDOW);
        let of = |lines: &Lines, name: &str| -> u64 {
            median(
                lines
                    .of("pool_queue")
                    .iter()
                    .skip(2)
                    .map(|line| field(line, name).parse().unwrap())
                    .collect(),
            )
        };
        let (real_q, real_held) = (of(&lines, "q_ms:"), of(&lines, "held_kib:"));
        let thirty_seconds = ((share * 32.0).round() as u32).clamp(1, 32);
        let (pool, lines) = fixed_pool();
        let conn = conn_at(RTT);
        conn.set_id(1);
        let start = Instant::now();
        let mut sim = Sim::new(&pool, &conn, start);
        drive_steps(&mut sim, (start, RUN), (thirty_seconds, 32));
        drop(sim);
        let (sim_q, sim_held) = (of(&lines, "q_ms:"), of(&lines, "held_kib:"));
        println!(
            "{line:?}: real h2 share {share:.3} q {real_q} ms held {real_held} KiB; helper at {thirty_seconds}/32: q {sim_q} ms held {sim_held} KiB"
        );
        assert!(real_held.abs_diff(sim_held) <= 16, "{real_held} {sim_held}");
        assert!(real_q.abs_diff(sim_q) <= 25, "{real_q} {sim_q}");
    }
}

/// The times (from the 200) at which the largest live window returned to
/// `STREAM_WINDOW` from above it, and at which it rose.
fn resets_and_rises(windows: &[(Duration, u32)]) -> (Vec<Duration>, Vec<Duration>) {
    let (mut resets, mut rises) = (Vec::new(), Vec::new());
    for pair in windows.windows(2) {
        if pair[0].1 > STREAM_WINDOW && pair[1].1 == STREAM_WINDOW {
            resets.push(pair[1].0);
        }
        if pair[1].1 > pair[0].1 {
            rises.push(pair[1].0);
        }
    }
    (resets, rises)
}

#[tokio::test(start_paused = true)]
async fn a_step_whose_queue_gave_it_back_holds_on_a_noisy_path() {
    // Critic REQUIRED 6 over real h2 (v35 review: before, its path never
    // reached a reset, so it passed with no reset at all). The path rewards
    // the first step by 30% (its rate is 1.3 times a window-bound 128 KiB
    // stream's), then drops to 0.6 times that rate, where the grown
    // window's own credit stands in a queue, and 2 s later returns, where
    // v33's window binds again with q low (without a hold it would grow
    // after three measurements). The budget covers that one step only. The
    // drop is scanned over two round trips around the step's judgment, as
    // h2's timing decides which measurement first sees it: in at least one
    // run the window returns to 128 KiB within two measurements of the
    // kept step (flow_queue `resets:<after_step>-` at least 1), and in
    // every run with such a reset the stream grows again, but no sooner
    // than HOLD_RTTS after it. PONGs see no standing queue.
    const RUN: Duration = Duration::from_secs(30);
    // A window-bound 128 KiB stream moves about 0.83 x 128 KiB per 180 ms.
    let base = u64::from(STREAM_WINDOW) * 83 / 100 * 1000 / RTT.as_millis() as u64;
    let high = base * 13 / 10;
    let line = |drop_to, back_to| super::tests::Line {
        downlink: Some(high),
        pings: Some(Duration::from_millis(100)),
        drop_to,
        back_to,
        holes: None,
    };
    let budget = STREAM_WINDOW * 7 / 8;
    // Without the drop: the first step's time (from the 200).
    let (pool, _lines) = pool_with(budget);
    let report = exchange(
        line(None, None),
        Window::Policy,
        vec![Send::Bulk(Duration::from_secs(8))],
        pool,
        conn_at(RTT),
    )
    .await;
    let (_, rises) = resets_and_rises(&report.windows);
    let first = *rises.first().expect("the first step");
    let mut after_step = 0;
    for eighth in (8..=40u32).step_by(2) {
        let at = first + RTT * eighth / 8;
        let (pool, lines) = pool_with(budget);
        let conn = conn_at(RTT);
        conn.set_id(6);
        let report = exchange(
            line(
                Some((at, base * 6 / 10)),
                Some((at + Duration::from_secs(2), high)),
            ),
            Window::Policy,
            vec![Send::Bulk(RUN)],
            pool,
            conn,
        )
        .await;
        let queue = lines.of("flow_queue");
        let resets = field(&queue[0], "resets:").to_owned();
        let (resets_at, rises) = resets_and_rises(&report.windows);
        let p90 = report.pong_queue((Duration::from_secs(10), RUN), 90);
        println!("drop at {at:?}: {queue:?} resets {resets_at:?} rises {rises:?} pong p90 {p90:?}");
        assert!(p90 <= Duration::from_millis(250), "{p90:?}");
        if resets.split('-').next().unwrap() == "0" {
            continue;
        }
        after_step += 1;
        let reset = resets_at[0];
        let rise = rises
            .iter()
            .find(|rise| **rise > reset)
            .unwrap_or_else(|| panic!("drop at {at:?}: no growth after the hold"));
        assert!(
            *rise - reset >= RTT * HOLD_RTTS - RTT / 8,
            "drop at {at:?}: {:?}",
            *rise - reset
        );
    }
    assert!(
        after_step > 0,
        "no run reset its window right after a kept step"
    );
}
