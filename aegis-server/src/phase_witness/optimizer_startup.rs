//! Explicitly owned startup-only aggregate. No per-connection event or sink.
use std::{
    future::Future,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

#[derive(Default)]
pub(super) struct OptimizerStartupWitness {
    attempts: AtomicU64,
    completed: AtomicU64,
    failures: AtomicU64,
    total_wall_us: AtomicU64,
    total_process_cpu_us: AtomicU64,
    process_cpu_samples: AtomicU64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OptimizerStartupSnapshot {
    pub attempts: u64,
    pub completed: u64,
    pub failures: u64,
    pub total_wall_us: u64,
    /// Process-wide CPU during the startup window, including other threads.
    /// This is not isolated optimizer-worker CPU.
    pub total_process_cpu_us: u64,
    pub process_cpu_samples: u64,
}

fn add(counter: &AtomicU64, value: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_add(value))
    });
}
fn micros(duration: Duration) -> u64 {
    duration.as_micros().min(u128::from(u64::MAX)) as u64
}

#[cfg(unix)]
fn process_cpu() -> Option<Duration> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: successful getrusage writes one rusage into valid exclusive storage.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: getrusage returned success and initialized usage.
    let usage = unsafe { usage.assume_init() };
    let valid = |t: libc::timeval| t.tv_sec >= 0 && (0..1_000_000).contains(&t.tv_usec);
    if !valid(usage.ru_utime) || !valid(usage.ru_stime) {
        return None;
    }
    let user = Duration::new(
        usage.ru_utime.tv_sec as u64,
        usage.ru_utime.tv_usec as u32 * 1000,
    );
    let system = Duration::new(
        usage.ru_stime.tv_sec as u64,
        usage.ru_stime.tv_usec as u32 * 1000,
    );
    user.checked_add(system)
}
#[cfg(not(unix))]
fn process_cpu() -> Option<Duration> {
    None
}

impl OptimizerStartupWitness {
    pub(super) fn snapshot(&self) -> OptimizerStartupSnapshot {
        OptimizerStartupSnapshot {
            attempts: self.attempts.load(Ordering::Relaxed),
            completed: self.completed.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
            total_wall_us: self.total_wall_us.load(Ordering::Relaxed),
            total_process_cpu_us: self.total_process_cpu_us.load(Ordering::Relaxed),
            process_cpu_samples: self.process_cpu_samples.load(Ordering::Relaxed),
        }
    }
}

pub(super) async fn observe<T, E>(
    witness: Option<&OptimizerStartupWitness>,
    work: impl Future<Output = Result<T, E>>,
) -> Result<T, E> {
    let Some(witness) = witness else {
        return work.await;
    };
    add(&witness.attempts, 1);
    let wall = Instant::now();
    let cpu = process_cpu();
    let result = work.await;
    add(&witness.completed, 1);
    if result.is_err() {
        add(&witness.failures, 1);
    }
    add(&witness.total_wall_us, micros(wall.elapsed()));
    if let Some(delta) = cpu.and_then(|start| process_cpu()?.checked_sub(start)) {
        add(&witness.total_process_cpu_us, micros(delta));
        add(&witness.process_cpu_samples, 1);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{atomic::AtomicBool, Arc};

    #[tokio::test]
    async fn disabled_path_does_not_sample_or_change_result() {
        assert_eq!(observe::<_, ()>(None, async { Ok(7) }).await, Ok(7));
        assert_eq!(observe::<(), _>(None, async { Err(9) }).await, Err(9));
    }

    #[tokio::test]
    async fn owned_aggregate_records_completion_after_future_and_saturates() {
        let witness = OptimizerStartupWitness::default();
        let completed = Arc::new(AtomicBool::new(false));
        let flag = completed.clone();
        let value: Result<usize, ()> = observe(Some(&witness), async move {
            flag.store(true, Ordering::Release);
            Ok(7)
        })
        .await;
        assert_eq!(value, Ok(7));
        assert!(completed.load(Ordering::Acquire));
        let first = witness.snapshot();
        assert_eq!((first.attempts, first.completed, first.failures), (1, 1, 0));
        assert!(first.process_cpu_samples <= 1);
        let err: Result<(), usize> = observe(Some(&witness), async { Err(9) }).await;
        assert_eq!(err, Err(9));
        let second = witness.snapshot();
        assert_eq!(
            (second.attempts, second.completed, second.failures),
            (2, 2, 1)
        );
        witness.attempts.store(u64::MAX, Ordering::Relaxed);
        add(&witness.attempts, 1);
        assert_eq!(witness.snapshot().attempts, u64::MAX);
        assert_eq!(micros(Duration::MAX), u64::MAX);
    }

    #[test]
    fn dropped_pending_startup_has_no_completed_measurement() {
        use std::task::{Context, Poll, Waker};
        let witness = OptimizerStartupWitness::default();
        let mut future = Box::pin(observe::<(), ()>(Some(&witness), std::future::pending()));
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
        drop(future);
        assert_eq!(witness.snapshot().attempts, 1);
        assert_eq!(witness.snapshot().completed, 0);
        assert_eq!(witness.snapshot().total_wall_us, 0);
    }
}
