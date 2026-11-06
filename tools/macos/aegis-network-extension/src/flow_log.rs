//! Per-flow outcome instrumentation (B-06 S16i-1).
//!
//! The v20 window showed flows refused near their 5 s connect budget, and a
//! first TCP flow after Connected that left no trace: every refusal path a
//! flow could take there (a wait for a pool stream or a limiter permit, a
//! failed pool dial, a stream bound, a carrier reset, an Open status that
//! came too late or refused) was silent. This is the epoch's record of them.
//!
//! Every refusal of a flow counts once in its class, and each class is
//! logged at most once per `REFUSED_LOG_EVERY` as `flow_refused class:<c>
//! n:<k>`, `k` the refusals of that class since its last line; what a second
//! held back is logged by the next event after it, or by the session's own
//! flush. Every flow's outcome is `flow_open <outcome> ms:<bucket>`, its
//! elapsed time from the start of its open bucketed (`bucket`): every flow
//! within `OPEN_LOG_ALL` of the epoch's Running (or its first flow), then
//! one in `OPEN_SAMPLE` and any slow one (`SLOW_OPEN`) at most once per
//! `REFUSED_LOG_EVERY`. While flows wait for a pool stream the pool's state
//! is logged at most once per `POOL_STATE_EVERY` as `pool_state
//! conns:<open>-<probing>-<draining> streams:<n> waiting:<n>`: the stable log
//! path carries no `/`, so the three connection counts are joined by `-`.
//! S16j-1: each `pool_state` line is followed by `pool_detail
//! oldest_ms:<n> sndq_kib:<n> hs_ms:<p50>-<p90>` (a stable line takes at
//! most four fields): the oldest waiting flow's wait, the largest send
//! buffer of a connection as its stall watchdog last read it, and the
//! median and 90th percentile of the latest handshakes (carrier request to
//! an authenticated inner connect). v35: then, when flows were taken since
//! the line before or a connection taking streams is queued, `pool_take
//! n:<n> queued:<n> conns_queued:<k>-<m>`: the new flows taken since the
//! last such line, those taken on a queued connection (its credit-loop
//! delay stood, `ConnWindow::queued`), and the queued connections among
//! the m taking streams. A rebuilt pool counts from zero again.
//! Every line is a stable code through `apple::log_fields`: no address, no
//! host, no key material.
use std::time::{Duration, Instant};

/// Each `flow_refused` class is logged at most this often.
pub(crate) const REFUSED_LOG_EVERY: Duration = Duration::from_secs(1);
/// Every flow's `flow_open` is logged for this long from the epoch's
/// Running (or its first flow).
pub(crate) const OPEN_LOG_ALL: Duration = Duration::from_secs(5);
/// After `OPEN_LOG_ALL`, one flow in this many is logged.
pub(crate) const OPEN_SAMPLE: u64 = 16;
/// After `OPEN_LOG_ALL`, a flow whose open took at least this long is
/// logged too, at most once per `REFUSED_LOG_EVERY`.
pub(crate) const SLOW_OPEN: Duration = Duration::from_secs(2);
/// `pool_state` is logged at most this often, and only while flows wait.
pub(crate) const POOL_STATE_EVERY: Duration = Duration::from_secs(1);

/// Why a flow was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// No pool stream within its budget (S16j-1: before less than its
    /// establish floor was left, `flow_pool::establish_floor`).
    PoolWait,
    /// No limiter permit within its budget: for its stream's carrier
    /// request, or for the pool connection it was to dial (no SYN sent).
    PermitWait,
    /// The pool connection it dialed under its permit failed (its bind,
    /// TCP connect, outer TLS or H2 handshake) or ran out of its budget.
    DialFailed,
    /// No 200 within its stream's handshake bound (S16j-1: the inner mTLS
    /// and the Open write are `HsInner`).
    HsBound,
    /// S16j-1: the 200 arrived, and no inner mTLS or Open write within its
    /// stream's handshake bound.
    HsInner,
    /// The relay ended its stream after the 200 and before the inner
    /// handshake answered (its handshake cap).
    HsRefused,
    /// The relay reset its carrier request before the 200.
    CarrierReset,
    /// No Open status within its stream's status budget.
    StatusBudget,
    /// The relay refused its Open (a nonzero status: its target).
    StatusRefused,
    /// Beyond the limiter's live cap.
    LiveCap,
    /// Its pooled connection ended under it.
    ConnLost,
    /// Authentication class (the session backs off).
    Auth,
    /// The relay ended its channel before the Open status.
    Unanswered,
    /// Anything else.
    Other,
}

impl Refusal {
    pub(crate) const ALL: [Refusal; 14] = [
        Refusal::PoolWait,
        Refusal::PermitWait,
        Refusal::DialFailed,
        Refusal::HsBound,
        Refusal::HsInner,
        Refusal::HsRefused,
        Refusal::CarrierReset,
        Refusal::StatusBudget,
        Refusal::StatusRefused,
        Refusal::LiveCap,
        Refusal::ConnLost,
        Refusal::Auth,
        Refusal::Unanswered,
        Refusal::Other,
    ];

    pub(crate) fn code(self) -> &'static str {
        match self {
            Refusal::PoolWait => "pool_wait",
            Refusal::PermitWait => "permit_wait",
            Refusal::DialFailed => "dial_failed",
            Refusal::HsBound => "hs_bound",
            Refusal::HsInner => "hs_inner",
            Refusal::HsRefused => "hs_refused",
            Refusal::CarrierReset => "carrier_reset",
            Refusal::StatusBudget => "status_budget",
            Refusal::StatusRefused => "status_refused",
            Refusal::LiveCap => "live_cap",
            Refusal::ConnLost => "conn_lost",
            Refusal::Auth => "auth",
            Refusal::Unanswered => "unanswered",
            Refusal::Other => "other",
        }
    }

    fn index(self) -> usize {
        self as usize
    }
}

const CLASSES: usize = Refusal::ALL.len();

/// How a flow's open ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Its Open was accepted.
    Ok,
    Refused(Refusal),
    /// The session refused it: its gate closed, its bridge lease was not
    /// live (ended, revoked, never granted, or its clock unreadable) before
    /// or as its open started, or its epoch was re-pinned. A lease that
    /// ends during an open drops it (`Dropped`).
    Closed,
    /// Its open was dropped unfinished (the engine or the session ended it).
    Dropped,
}

impl Outcome {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::Refused(refusal) => refusal.code(),
            Outcome::Closed => "closed",
            Outcome::Dropped => "dropped",
        }
    }
}

/// The upper bounds, in ms, of the `flow_open` elapsed-time buckets.
const BUCKETS: [(u128, &str); 7] = [
    (100, "ms:le100"),
    (250, "ms:le250"),
    (500, "ms:le500"),
    (1_000, "ms:le1000"),
    (2_000, "ms:le2000"),
    (3_000, "ms:le3000"),
    (5_000, "ms:le5000"),
];

/// `elapsed` as its `flow_open` bucket.
pub(crate) fn bucket(elapsed: Duration) -> &'static str {
    let ms = elapsed.as_millis();
    BUCKETS
        .iter()
        .find(|(bound, _)| ms <= *bound)
        .map_or("ms:gt5000", |(_, code)| code)
}

/// The pool's counts for one `pool_state` line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PoolSnapshot {
    pub(crate) open: usize,
    pub(crate) probing: usize,
    /// Draining or ended, with streams left.
    pub(crate) draining: usize,
    pub(crate) streams: usize,
    pub(crate) waiting: usize,
    /// S16j-1: how long the oldest waiting flow has waited.
    pub(crate) oldest_ms: u64,
    /// S16j-1: the most bytes in one connection's send buffer.
    pub(crate) send_queued: u64,
    /// S16j-1: the latest handshakes' median and 90th percentile.
    pub(crate) hs_p50_ms: u64,
    pub(crate) hs_p90_ms: u64,
    /// v35: the flows the pool has taken a stream for, and those on a
    /// queued connection, over its life.
    pub(crate) takes: u64,
    pub(crate) takes_queued: u64,
    /// v35: the connections taking streams, and those of them queued.
    pub(crate) conns_taking: usize,
    pub(crate) conns_queued: usize,
}

/// One epoch's flow outcome record. See the module documentation.
#[derive(Debug, Default)]
pub(crate) struct FlowLog {
    // Every flow_open is logged within OPEN_LOG_ALL from here.
    window: Option<Instant>,
    opens: u64,
    last_slow: Option<Instant>,
    // Per class: refusals not yet logged, when its last line was, and all.
    pending: [u64; CLASSES],
    last: [Option<Instant>; CLASSES],
    totals: [u64; CLASSES],
    last_pool_state: Option<Instant>,
    // v35: the pool's takes as of the last pool_take line.
    takes_logged: (u64, u64),
    #[cfg(test)]
    lines: Vec<String>,
}

impl FlowLog {
    /// The epoch reached Running at `now`: every flow is logged from here
    /// for `OPEN_LOG_ALL`, unless a flow came first.
    pub(crate) fn running(&mut self, now: Instant) {
        self.window.get_or_insert(now);
    }

    /// One flow's open ended with `outcome` after `elapsed`, at `now`.
    pub(crate) fn opened(&mut self, outcome: Outcome, elapsed: Duration, now: Instant) {
        let start = *self.window.get_or_insert(now);
        if let Outcome::Refused(refusal) = outcome {
            let at = refusal.index();
            self.pending[at] = self.pending[at].saturating_add(1);
            self.totals[at] = self.totals[at].saturating_add(1);
        }
        self.opens = self.opens.wrapping_add(1);
        let all = now.saturating_duration_since(start) < OPEN_LOG_ALL;
        let sampled = self.opens.is_multiple_of(OPEN_SAMPLE);
        let slow = elapsed >= SLOW_OPEN
            && self
                .last_slow
                .is_none_or(|at| now.saturating_duration_since(at) >= REFUSED_LOG_EVERY);
        if all || sampled || slow {
            if slow {
                self.last_slow = Some(now);
            }
            self.emit("flow_open", &[outcome.code(), bucket(elapsed)]);
        }
        self.flush(now, false);
    }

    /// Log every class with refusals not yet logged whose last line is at
    /// least `REFUSED_LOG_EVERY` old (`force`: every one).
    pub(crate) fn flush(&mut self, now: Instant, force: bool) {
        for refusal in Refusal::ALL {
            let at = refusal.index();
            let due = self.last[at]
                .is_none_or(|last| now.saturating_duration_since(last) >= REFUSED_LOG_EVERY);
            if self.pending[at] > 0 && (force || due) {
                let count = format!("n:{}", self.pending[at]);
                let class = format!("class:{}", refusal.code());
                self.emit("flow_refused", &[&class, &count]);
                self.pending[at] = 0;
                self.last[at] = Some(now);
            }
        }
    }

    /// The pool's state at `now`, logged while flows wait, at most once per
    /// `POOL_STATE_EVERY`.
    pub(crate) fn pool_state(&mut self, pool: PoolSnapshot, now: Instant) {
        if pool.waiting == 0
            || self
                .last_pool_state
                .is_some_and(|at| now.saturating_duration_since(at) < POOL_STATE_EVERY)
        {
            return;
        }
        self.last_pool_state = Some(now);
        let conns = format!("conns:{}-{}-{}", pool.open, pool.probing, pool.draining);
        let streams = format!("streams:{}", pool.streams);
        let waiting = format!("waiting:{}", pool.waiting);
        self.emit("pool_state", &[&conns, &streams, &waiting]);
        let oldest = format!("oldest_ms:{}", pool.oldest_ms);
        let queued = format!("sndq_kib:{}", pool.send_queued.div_ceil(1024));
        let handshakes = format!("hs_ms:{}-{}", pool.hs_p50_ms, pool.hs_p90_ms);
        self.emit("pool_detail", &[&oldest, &queued, &handshakes]);
        // v35: a rebuilt pool counts from zero.
        if pool.takes < self.takes_logged.0 || pool.takes_queued < self.takes_logged.1 {
            self.takes_logged = (0, 0);
        }
        let n = pool.takes - self.takes_logged.0;
        let on_queued = pool.takes_queued - self.takes_logged.1;
        if n > 0 || pool.conns_queued > 0 {
            self.takes_logged = (pool.takes, pool.takes_queued);
            let n = format!("n:{n}");
            let on_queued = format!("queued:{on_queued}");
            let conns = format!("conns_queued:{}-{}", pool.conns_queued, pool.conns_taking);
            self.emit("pool_take", &[&n, &on_queued, &conns]);
        }
    }

    /// One more stable line of this epoch's flows (`pool_prewarm`).
    pub(crate) fn note(&mut self, event: &str, code: &str) {
        self.emit(event, &[code]);
    }

    /// v34: one stable line of up to four fields (`stream_window`'s
    /// `pool_window`, `pool_rtt` and `flow_bulk`; v35 `pool_queue`,
    /// `flow_queue` and the flow pool's `pool_policy`).
    pub(crate) fn fields(&mut self, event: &str, fields: &[&str]) {
        self.emit(event, fields);
    }

    fn emit(&mut self, event: &str, fields: &[&str]) {
        crate::apple::log_fields(event, fields);
        #[cfg(test)]
        self.lines.push(format!("{event} {}", fields.join(" ")));
    }

    /// Test-only: every line logged so far, as `event field...`.
    #[cfg(test)]
    pub(crate) fn lines(&self) -> Vec<String> {
        self.lines.clone()
    }

    /// Test-only: every refusal of `refusal`'s class so far.
    #[cfg(test)]
    pub(crate) fn total(&self, refusal: Refusal) -> u64 {
        self.totals[refusal.index()]
    }
}

#[cfg(test)]
#[path = "flow_log_tests.rs"]
mod tests;
