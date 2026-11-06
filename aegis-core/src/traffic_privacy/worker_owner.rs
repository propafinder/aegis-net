//! The original shaper JoinHandle has one result consumer and an explicit
//! outer cancellation owner. No proxy task, runtime global or reaper is used.
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::{
    task::{JoinError, JoinHandle},
    time::{timeout_at, Instant},
};

#[derive(Clone, Copy, Debug)]
enum Terminal {
    Success,
    WorkerError(io::ErrorKind),
    Cancelled,
    Panic,
}
struct State<T> {
    handle: Option<JoinHandle<io::Result<T>>>,
    terminal: Option<Terminal>,
}
struct Shared<T>(Mutex<State<T>>);

fn terminal<T>(result: &Result<io::Result<T>, JoinError>) -> Terminal {
    match result {
        Ok(Ok(_)) => Terminal::Success,
        Ok(Err(error)) => Terminal::WorkerError(error.kind()),
        Err(error) if error.is_cancelled() => Terminal::Cancelled,
        Err(_) => Terminal::Panic,
    }
}
trait Control: Send + Sync {
    fn abort(&self);
    fn poll_terminal(&self, cx: &mut Context<'_>) -> Poll<Terminal>;
    fn observed(&self) -> Option<Terminal>;
}
impl<T: Send + 'static> Control for Shared<T> {
    fn abort(&self) {
        let state = self.0.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(handle) = &state.handle {
            handle.abort();
        }
    }
    fn poll_terminal(&self, cx: &mut Context<'_>) -> Poll<Terminal> {
        let mut state = self.0.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(value) = state.terminal {
            return Poll::Ready(value);
        }
        let result = match state.handle.as_mut() {
            Some(handle) => match Pin::new(handle).poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => result,
            },
            None => return Poll::Ready(Terminal::Panic),
        };
        let value = terminal(&result);
        state.handle = None;
        state.terminal = Some(value);
        // The cancelled forwarding future no longer consumes these typed stats.
        // Dropping the real JoinHandle output happens only after Ready.
        drop(state);
        drop(result);
        Poll::Ready(value)
    }
    fn observed(&self) -> Option<Terminal> {
        self.0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .terminal
    }
}

pub(crate) struct SharedWorker<T: Send + 'static>(Arc<Shared<T>>);
impl<T: Send + 'static> SharedWorker<T> {
    pub(crate) fn abort(&self) {
        self.0.abort();
    }
}
impl<T: Send + 'static> Future for SharedWorker<T> {
    type Output = Result<io::Result<T>, JoinError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self.0 .0.lock().unwrap_or_else(|error| error.into_inner());
        let result = match state.handle.as_mut() {
            Some(handle) => match Pin::new(handle).poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => result,
            },
            None => {
                return Poll::Ready(Ok(Err(io::Error::other("shaper result already consumed"))))
            }
        };
        state.terminal = Some(terminal(&result));
        state.handle = None;
        Poll::Ready(result)
    }
}
impl<T: Send + 'static> Drop for SharedWorker<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct OwnerState {
    closed: bool,
    workers: Vec<Arc<dyn Control>>,
}
/// Explicit outer join authority for the one admitted shaping owner.
/// Drop requests abort only; callers must await cancel_and_join_until for proof.
pub struct ShapingCleanupOwner(Mutex<OwnerState>);
impl Default for ShapingCleanupOwner {
    fn default() -> Self {
        Self::new()
    }
}
impl ShapingCleanupOwner {
    pub fn new() -> Self {
        Self(Mutex::new(OwnerState {
            closed: false,
            workers: Vec::with_capacity(1),
        }))
    }
    fn register<T: Send + 'static>(
        &self,
        future: impl Future<Output = io::Result<T>> + Send + 'static,
    ) -> io::Result<SharedWorker<T>> {
        let mut owner = self.0.lock().unwrap_or_else(|error| error.into_inner());
        if owner.closed || !owner.workers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "shaping cleanup owner closed or full",
            ));
        }
        let shared = Arc::new(Shared(Mutex::new(State {
            handle: Some(tokio::spawn(future)),
            terminal: None,
        })));
        owner.workers.push(shared.clone());
        Ok(SharedWorker(shared))
    }
    pub fn observation(&self) -> CleanupObservation {
        let owner = self.0.lock().unwrap_or_else(|error| error.into_inner());
        let mut result = CleanupObservation {
            registered: owner.workers.len(),
            joined: 0,
            worker_error: None,
            panicked: false,
        };
        for worker in &owner.workers {
            if let Some(value) = worker.observed() {
                result.joined += 1;
                match value {
                    Terminal::WorkerError(kind) => result.worker_error = Some(kind),
                    Terminal::Panic => result.panicked = true,
                    _ => {}
                }
            }
        }
        result
    }
    /// Call after dropping/cancelling the forwarding future. This aborts before
    /// awaiting; it never flushes payload or gives the session a new lifetime.
    pub async fn cancel_and_join_until(&self, cutoff: Instant) -> io::Result<CleanupObservation> {
        let workers = {
            let mut state = self.0.lock().unwrap_or_else(|error| error.into_inner());
            state.closed = true;
            state.workers.clone()
        };
        for worker in &workers {
            worker.abort();
        }
        timeout_at(
            cutoff,
            std::future::poll_fn(|cx| {
                let mut pending = false;
                for worker in &workers {
                    if worker.poll_terminal(cx).is_pending() {
                        pending = true;
                    }
                }
                if pending {
                    Poll::Pending
                } else {
                    Poll::Ready(())
                }
            }),
        )
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "shaping cleanup terminal unconfirmed",
            )
        })?;
        let observed = self.observation();
        if Instant::now() >= cutoff {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "shaping cleanup completed beyond cutoff",
            ));
        }
        if observed.panicked {
            return Err(io::Error::other("shaping cleanup observed worker panic"));
        }
        Ok(observed)
    }
}
impl Drop for ShapingCleanupOwner {
    fn drop(&mut self) {
        let owner = self.0.get_mut().unwrap_or_else(|error| error.into_inner());
        for worker in &owner.workers {
            worker.abort();
        }
    }
}
/// Independent numeric observations, never application payload or delivery proof.
#[derive(Clone, Copy, Debug)]
pub struct CleanupObservation {
    pub registered: usize,
    pub joined: usize,
    pub worker_error: Option<io::ErrorKind>,
    pub panicked: bool,
}

pub(crate) fn spawn<T: Send + 'static>(
    owner: Option<&ShapingCleanupOwner>,
    future: impl Future<Output = io::Result<T>> + Send + 'static,
) -> io::Result<SharedWorker<T>> {
    match owner {
        Some(owner) => owner.register(future),
        None => Ok(SharedWorker(Arc::new(Shared(Mutex::new(State {
            handle: Some(tokio::spawn(future)),
            terminal: None,
        }))))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    struct Held(Arc<AtomicBool>);
    impl Drop for Held {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    fn cutoff() -> Instant {
        Instant::now() + Duration::from_secs(1)
    }

    #[tokio::test]
    async fn typed_result_and_prior_terminal_are_consumed_once() {
        let owner = ShapingCleanupOwner::new();
        let worker = spawn(Some(&owner), async { Ok::<_, io::Error>(37u64) }).unwrap();
        assert_eq!(worker.await.unwrap().unwrap(), 37);
        assert_eq!(owner.observation().joined, 1);
        let observed = owner.cancel_and_join_until(cutoff()).await.unwrap();
        assert_eq!((observed.registered, observed.joined), (1, 1));
        assert!(observed.worker_error.is_none());
    }

    #[tokio::test]
    async fn cancelled_worker_drops_actual_captured_owner_before_join_returns() {
        let owner = ShapingCleanupOwner::new();
        let dropped = Arc::new(AtomicBool::new(false));
        let held = Held(dropped.clone());
        let worker = spawn(Some(&owner), async move {
            let _held = held;
            std::future::pending::<io::Result<()>>().await
        })
        .unwrap();
        drop(worker);
        let observed = owner.cancel_and_join_until(cutoff()).await.unwrap();
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!((observed.registered, observed.joined), (1, 1));
    }

    #[tokio::test]
    async fn full_owner_refuses_second_worker_before_it_can_be_polled() {
        let owner = ShapingCleanupOwner::new();
        let first = spawn(Some(&owner), std::future::pending::<io::Result<()>>()).unwrap();
        let polls = Arc::new(AtomicUsize::new(0));
        let second_polls = polls.clone();
        let second = spawn(Some(&owner), async move {
            second_polls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        assert!(matches!(second, Err(error) if error.kind() == io::ErrorKind::InvalidInput));
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        drop(first);
        owner.cancel_and_join_until(cutoff()).await.unwrap();
        assert!(spawn(Some(&owner), async { Ok(()) }).is_err());
        assert_eq!(owner.observation().registered, 1);
    }

    #[tokio::test]
    async fn expired_cleanup_refuses_instead_of_claiming_terminal_custody() {
        let owner = ShapingCleanupOwner::new();
        let worker = spawn(Some(&owner), std::future::pending::<io::Result<()>>()).unwrap();
        drop(worker);
        let error = owner
            .cancel_and_join_until(Instant::now())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            owner.cancel_and_join_until(cutoff()).await.unwrap().joined,
            1
        );
    }

    #[tokio::test]
    async fn observed_worker_error_retains_its_kind_for_outer_success_refusal() {
        let owner = ShapingCleanupOwner::new();
        let worker = spawn(Some(&owner), async {
            Err::<(), _>(io::Error::new(
                io::ErrorKind::InvalidData,
                "controlled worker refusal",
            ))
        })
        .unwrap();
        assert_eq!(
            worker.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let observed = owner.cancel_and_join_until(cutoff()).await.unwrap();
        assert_eq!(observed.worker_error, Some(io::ErrorKind::InvalidData));
        assert_eq!(observed.joined, 1);
    }
}
