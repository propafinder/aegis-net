//! Test-only observations owned by one TCP establishment attempt. These report
//! local API/poll boundaries, never prove delivery to the peer. No global state,
//! headers, targets, credentials, raw error bodies or unbounded event list.
use std::future::Future;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicU64, AtomicU8, Ordering},
    Arc,
};
use std::task::{Context, Poll, Wake, Waker};

#[derive(Clone, Default)]
pub(super) struct Witness(Arc<State>);
#[derive(Default)]
struct State {
    status: AtomicU8,
    polls: AtomicU64,
    pending: AtomicU64,
    wakes: AtomicU64,
    phase: AtomicU8,
    error: AtomicU8,
    io: aegis_server::phase_witness::IoWitness,
    wire: aegis_server::phase_witness::IoWitness,
}

fn bump(value: &AtomicU64) {
    let _ = value.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_add(1))
    });
}

impl Witness {
    pub(super) fn request_queued(&self) {
        self.0.phase.fetch_or(1, Ordering::Relaxed);
    }
    pub(super) fn open_queued(&self) {
        self.0.phase.fetch_or(2, Ordering::Relaxed);
    }
    pub(super) fn headers_received(&self) {
        self.0.phase.fetch_or(4, Ordering::Relaxed);
    }
    pub(super) fn headers_error(&self) {
        self.0.phase.fetch_or(8, Ordering::Relaxed);
    }
    pub(super) fn snapshot(&self) -> String {
        let status = match self.0.status.load(Ordering::Relaxed) {
            0 => "not_spawned",
            1 => "spawned",
            2 => "polled",
            3 => "terminal_ok",
            4 => "terminal_error",
            5 => "cancelled",
            _ => unreachable!(),
        };
        let error = match self.0.error.load(Ordering::Relaxed) {
            0 => "none",
            1 => "io",
            2 => "goaway",
            3 => "reset",
            4 => "other",
            _ => unreachable!(),
        };
        let phase = self.0.phase.load(Ordering::Relaxed);
        format!("h2_driver={status}, driver_polls={}, driver_pending={}, driver_wakes={}, driver_error={error}, request_queued={}, open_queued={}, headers_received={}, headers_error={}, tls_application_io={:?}, tls_underlying_io={:?}",
            self.0.polls.load(Ordering::Relaxed), self.0.pending.load(Ordering::Relaxed), self.0.wakes.load(Ordering::Relaxed),
            phase & 1 != 0, phase & 2 != 0, phase & 4 != 0, phase & 8 != 0, self.0.io.snapshot(), self.0.wire.snapshot())
    }
    pub(super) fn wire_io(&self) -> &aegis_server::phase_witness::IoWitness {
        &self.0.wire
    }
    pub(super) fn observe_io<S>(
        &self,
        io: S,
    ) -> aegis_server::phase_witness::io_progress::ObservedIo<S> {
        self.0.io.observe(io)
    }
    pub(super) fn observe<F>(&self, future: F) -> Driver<F> {
        self.0.status.store(1, Ordering::Relaxed);
        Driver {
            future: Box::pin(future),
            witness: self.clone(),
            completed: false,
        }
    }
}

struct ForwardWake {
    witness: Witness,
    original: Waker,
}
impl Wake for ForwardWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        bump(&self.witness.0.wakes);
        self.original.wake_by_ref();
    }
}

pub(super) struct Driver<F> {
    future: Pin<Box<F>>,
    witness: Witness,
    completed: bool,
}
impl<F: Future<Output = Result<(), h2::Error>>> Future for Driver<F> {
    type Output = Result<(), h2::Error>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        bump(&self.witness.0.polls);
        self.witness.0.status.store(2, Ordering::Relaxed);
        let waker = Waker::from(Arc::new(ForwardWake {
            witness: self.witness.clone(),
            original: cx.waker().clone(),
        }));
        let result = self.future.as_mut().poll(&mut Context::from_waker(&waker));
        match &result {
            Poll::Pending => bump(&self.witness.0.pending),
            Poll::Ready(result) => {
                self.completed = true;
                let code = result
                    .as_ref()
                    .err()
                    .map(|e| {
                        if e.is_io() {
                            1
                        } else if e.is_go_away() {
                            2
                        } else if e.is_reset() {
                            3
                        } else {
                            4
                        }
                    })
                    .unwrap_or(0);
                self.witness.0.error.store(code, Ordering::Relaxed);
                self.witness
                    .0
                    .status
                    .store(if result.is_ok() { 3 } else { 4 }, Ordering::Relaxed);
            }
        }
        result
    }
}
impl<F> Drop for Driver<F> {
    fn drop(&mut self) {
        if !self.completed {
            self.witness.0.status.store(5, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
#[path = "diagnostics_tests.rs"]
mod tests;
