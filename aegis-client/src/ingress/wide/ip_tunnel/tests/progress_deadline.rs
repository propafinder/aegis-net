//! Bound stalled transfers independently from a slower but progressing runner.
use std::time::{Duration, Instant};

pub(super) struct ProgressDeadline {
    idle_limit: Duration,
    hard_end: Instant,
    last_progress: Instant,
    counters: (usize, usize, usize),
}

impl ProgressDeadline {
    pub(super) fn new(now: Instant, idle_limit: Duration, total_limit: Duration) -> Self {
        Self {
            idle_limit,
            hard_end: now + total_limit,
            last_progress: now,
            counters: (0, 0, 0),
        }
    }

    pub(super) fn expired(&mut self, now: Instant, counters: (usize, usize, usize)) -> bool {
        // A late observation must not erase an already exceeded idle deadline.
        if now >= self.hard_end || now.duration_since(self.last_progress) >= self.idle_limit {
            return true;
        }
        if counters != self.counters {
            self.counters = counters;
            self.last_progress = now;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_retains_response_budget_after_slow_upload() {
        let now = Instant::now();
        let mut deadline =
            ProgressDeadline::new(now, Duration::from_secs(45), Duration::from_secs(180));
        assert!(!deadline.expired(now + Duration::from_secs(40), (2_000_000, 0, 20)));
        assert!(!deadline.expired(now + Duration::from_secs(70), (2_000_000, 1_000_000, 20)));
        assert!(!deadline.expired(now + Duration::from_secs(100), (2_000_000, 2_000_000, 20)));
    }

    #[test]
    fn idle_stall_cannot_be_reset_by_late_progress() {
        let now = Instant::now();
        let mut deadline =
            ProgressDeadline::new(now, Duration::from_secs(45), Duration::from_secs(180));
        assert!(deadline.expired(now + Duration::from_secs(45), (1, 0, 0)));
    }

    #[test]
    fn continuous_progress_never_removes_total_bound() {
        let now = Instant::now();
        let mut deadline =
            ProgressDeadline::new(now, Duration::from_secs(45), Duration::from_secs(180));
        for second in [40, 80, 120, 160] {
            assert!(!deadline.expired(now + Duration::from_secs(second), (second as usize, 0, 0)));
        }
        assert!(deadline.expired(now + Duration::from_secs(180), (181, 0, 0)));
    }
}
