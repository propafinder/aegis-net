//! The epoch's flow outcome record (B-06 S16i-1), on a hand-driven clock.
use super::*;

fn at(base: Instant, ms: u64) -> Instant {
    base + Duration::from_millis(ms)
}

#[test]
fn flow_open_buckets_are_stable_codes() {
    for (ms, code) in [
        (0, "ms:le100"),
        (100, "ms:le100"),
        (101, "ms:le250"),
        (499, "ms:le500"),
        (1_000, "ms:le1000"),
        (1_900, "ms:le2000"),
        (2_999, "ms:le3000"),
        (3_400, "ms:le5000"),
        (5_000, "ms:le5000"),
        (5_001, "ms:gt5000"),
    ] {
        assert_eq!(bucket(Duration::from_millis(ms)), code, "{ms}");
    }
    // Every code passes the stable log path: no unstable_code line.
    for refusal in Refusal::ALL {
        let class = format!("class:{}", refusal.code());
        assert!(crate::apple::stable_fields(
            "flow_refused",
            &[&class, "n:12"]
        ));
        assert!(crate::apple::stable_fields(
            "flow_open",
            &[Outcome::Refused(refusal).code(), "ms:gt5000"]
        ));
    }
    for outcome in [Outcome::Ok, Outcome::Closed, Outcome::Dropped] {
        assert!(crate::apple::stable_fields(
            "flow_open",
            &[outcome.code(), "ms:le100"]
        ));
    }
    assert!(crate::apple::stable_fields(
        "pool_state",
        &["conns:4-0-12", "streams:96", "waiting:120"]
    ));
    assert!(crate::apple::stable_fields(
        "pool_detail",
        &["oldest_ms:4999", "sndq_kib:4096", "hs_ms:341-612"]
    ));
    // Codes are distinct.
    let mut codes: Vec<_> = Refusal::ALL.iter().map(|r| r.code()).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), Refusal::ALL.len());
}

#[test]
fn flow_refused_is_logged_at_once_then_at_most_once_a_second_per_class() {
    let base = Instant::now();
    let mut log = FlowLog::default();
    log.running(base);
    // The first refusal of a class is logged at once.
    log.opened(
        Outcome::Refused(Refusal::PoolWait),
        Duration::from_millis(5_000),
        at(base, 10),
    );
    // Two more within its second are held back; another class is not.
    log.opened(
        Outcome::Refused(Refusal::PoolWait),
        Duration::from_millis(5_000),
        at(base, 300),
    );
    log.opened(
        Outcome::Refused(Refusal::LiveCap),
        Duration::ZERO,
        at(base, 400),
    );
    log.opened(
        Outcome::Refused(Refusal::PoolWait),
        Duration::from_millis(5_000),
        at(base, 900),
    );
    let refused = |log: &FlowLog| -> Vec<String> {
        log.lines()
            .into_iter()
            .filter(|line| line.starts_with("flow_refused"))
            .collect()
    };
    assert_eq!(
        refused(&log),
        [
            "flow_refused class:pool_wait n:1",
            "flow_refused class:live_cap n:1"
        ]
    );
    // A flush before the second ends logs nothing more; after it, the
    // count held back.
    log.flush(at(base, 1_009), false);
    assert_eq!(refused(&log).len(), 2);
    log.flush(at(base, 1_010), false);
    assert_eq!(
        refused(&log).last().map(String::as_str),
        Some("flow_refused class:pool_wait n:2")
    );
    // A forced flush logs whatever is left, at once.
    log.opened(
        Outcome::Refused(Refusal::PoolWait),
        Duration::from_millis(5_000),
        at(base, 1_100),
    );
    assert_eq!(refused(&log).len(), 3);
    log.flush(at(base, 1_101), true);
    assert_eq!(
        refused(&log).last().map(String::as_str),
        Some("flow_refused class:pool_wait n:1")
    );
    log.flush(at(base, 9_000), true);
    assert_eq!(refused(&log).len(), 4);
    assert_eq!(log.total(Refusal::PoolWait), 4);
    assert_eq!(log.total(Refusal::LiveCap), 1);
    assert_eq!(log.total(Refusal::ConnLost), 0);
}

#[test]
fn flow_open_logs_every_flow_for_five_seconds_then_samples() {
    let base = Instant::now();
    let mut log = FlowLog::default();
    log.running(base);
    let opens = |log: &FlowLog| {
        log.lines()
            .into_iter()
            .filter(|line| line.starts_with("flow_open"))
            .count()
    };
    // Every flow within OPEN_LOG_ALL of Running.
    for ms in [0, 1_000, 4_999] {
        log.opened(Outcome::Ok, Duration::from_millis(40), at(base, ms));
    }
    assert_eq!(opens(&log), 3);
    assert_eq!(log.lines()[0], "flow_open ok ms:le100", "{:?}", log.lines());
    // Then one in OPEN_SAMPLE: the 16th flow overall.
    for n in 4..OPEN_SAMPLE {
        log.opened(Outcome::Ok, Duration::from_millis(40), at(base, 5_000 + n));
    }
    assert_eq!(opens(&log), 3);
    log.opened(Outcome::Ok, Duration::from_millis(40), at(base, 6_000));
    assert_eq!(opens(&log), 4);
    // A slow flow is logged out of turn, at most once a second.
    log.opened(Outcome::Ok, SLOW_OPEN, at(base, 7_000));
    log.opened(
        Outcome::Refused(Refusal::HsBound),
        Duration::from_millis(2_600),
        at(base, 7_500),
    );
    assert_eq!(opens(&log), 5);
    assert_eq!(
        log.lines()
            .iter()
            .rfind(|line| line.starts_with("flow_open"))
            .map(String::as_str),
        Some("flow_open ok ms:le2000")
    );
    log.opened(
        Outcome::Refused(Refusal::HsBound),
        Duration::from_millis(2_600),
        at(base, 8_000),
    );
    assert_eq!(opens(&log), 6);
    assert!(log
        .lines()
        .contains(&"flow_open hs_bound ms:le3000".to_owned()));
}

#[test]
fn flow_open_window_starts_at_the_first_flow_without_running() {
    let base = Instant::now();
    let mut log = FlowLog::default();
    log.opened(Outcome::Closed, Duration::ZERO, at(base, 20_000));
    log.opened(
        Outcome::Dropped,
        Duration::from_millis(300),
        at(base, 24_000),
    );
    log.opened(Outcome::Ok, Duration::from_millis(300), at(base, 25_000));
    assert_eq!(
        log.lines(),
        ["flow_open closed ms:le100", "flow_open dropped ms:le500"]
    );
    // A later Running never moves the window.
    log.running(at(base, 30_000));
    log.opened(Outcome::Ok, Duration::from_millis(300), at(base, 30_001));
    assert_eq!(log.lines().len(), 2);
    // Running opens the window, not a first flow that comes later.
    let mut log = FlowLog::default();
    log.running(base);
    log.opened(Outcome::Ok, Duration::from_millis(40), at(base, 6_000));
    assert!(log.lines().is_empty(), "{:?}", log.lines());
}

#[test]
fn pool_state_is_logged_only_while_flows_wait_at_most_once_a_second() {
    let base = Instant::now();
    let mut log = FlowLog::default();
    let waiting = PoolSnapshot {
        open: 2,
        probing: 1,
        draining: 3,
        streams: 17,
        waiting: 5,
        oldest_ms: 2_345,
        send_queued: 1_025,
        hs_p50_ms: 341,
        hs_p90_ms: 612,
        ..PoolSnapshot::default()
    };
    log.pool_state(
        PoolSnapshot {
            waiting: 0,
            ..waiting
        },
        base,
    );
    assert!(log.lines().is_empty());
    log.pool_state(waiting, at(base, 1));
    log.pool_state(waiting, at(base, 999));
    // S16j-1: each followed by its detail line, KiB rounded up.
    assert_eq!(
        log.lines(),
        [
            "pool_state conns:2-1-3 streams:17 waiting:5",
            "pool_detail oldest_ms:2345 sndq_kib:2 hs_ms:341-612"
        ]
    );
    log.pool_state(waiting, at(base, 1_001));
    assert_eq!(log.lines().len(), 4);
    log.note("pool_prewarm", "dialed");
    assert_eq!(
        log.lines().last().map(String::as_str),
        Some("pool_prewarm dialed")
    );
}
