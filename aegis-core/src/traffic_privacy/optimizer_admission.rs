//! Process-local ownership bounds for expensive numerical preparation.
//! These bounds govern availability, not DP, CPU time, or global process heap.
use std::{
    io,
    sync::{Arc, OnceLock},
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError},
    time::{timeout_at, Instant},
};

const MAX_WORKER_OWNERS: usize = 4;
const MAX_ADMISSION_WAITERS: usize = 32;
static PROCESS_ADMISSION: OnceLock<Admission> = OnceLock::new();

struct Admission {
    workers: Arc<Semaphore>,
    waiters: Arc<Semaphore>,
}

impl Admission {
    fn new() -> Self {
        Self {
            workers: Arc::new(Semaphore::new(MAX_WORKER_OWNERS)),
            waiters: Arc::new(Semaphore::new(MAX_ADMISSION_WAITERS)),
        }
    }

    async fn acquire(&self, original_cutoff: Instant) -> io::Result<OwnedSemaphorePermit> {
        if Instant::now() >= original_cutoff {
            return Err(expired());
        }
        match self.workers.clone().try_acquire_owned() {
            Ok(permit) => return admitted_before_cutoff(permit, original_cutoff),
            Err(TryAcquireError::Closed) => return Err(closed()),
            Err(TryAcquireError::NoPermits) => {}
        }
        if Instant::now() >= original_cutoff {
            return Err(expired());
        }
        // No unbounded semaphore waiter can exist without this bounded owner.
        let waiter = match self.waiters.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(TryAcquireError::Closed) => return Err(closed()),
            Err(TryAcquireError::NoPermits) => return Err(capacity()),
        };
        let permit = timeout_at(original_cutoff, self.workers.clone().acquire_owned())
            .await
            .map_err(|_| expired())?
            .map_err(|_| closed())?;
        drop(waiter);
        admitted_before_cutoff(permit, original_cutoff)
    }
}

fn admitted_before_cutoff(
    permit: OwnedSemaphorePermit,
    original_cutoff: Instant,
) -> io::Result<OwnedSemaphorePermit> {
    if Instant::now() >= original_cutoff {
        return Err(expired()); // The owned permit drops here.
    }
    Ok(permit)
}

fn expired() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "privacy optimizer admission timed out",
    )
}

fn capacity() -> io::Error {
    io::Error::new(
        io::ErrorKind::WouldBlock,
        "privacy optimizer admission capacity exhausted",
    )
}

fn closed() -> io::Error {
    io::Error::other("privacy optimizer admission unavailable")
}

pub(super) async fn acquire(original_cutoff: Instant) -> io::Result<OwnedSemaphorePermit> {
    PROCESS_ADMISSION
        .get_or_init(Admission::new)
        .acquire(original_cutoff)
        .await
}
