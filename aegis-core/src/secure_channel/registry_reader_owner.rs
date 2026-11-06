//! Retains the original blocking registry-read handle across async cancellation.
//! Aborting an entered blocking task is a request, not evidence of completion.

use std::future::{poll_fn, Future};
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::task::{JoinError, JoinHandle};
use tokio::time::Instant;

use super::DeviceRegistry;

type ReadResult = io::Result<DeviceRegistry>;

#[derive(Clone, Copy)]
enum Terminal {
    Completed,
    Cancelled,
    Failed,
}

struct State {
    closed: bool,
    handle: Option<JoinHandle<ReadResult>>,
    terminal: Option<Terminal>,
}

#[derive(Clone)]
pub(super) struct ReaderOwner(Arc<Mutex<State>>);

impl ReaderOwner {
    pub(super) fn new() -> Self {
        Self(Arc::new(Mutex::new(State {
            closed: false,
            handle: None,
            terminal: None,
        })))
    }

    pub(super) fn start(
        &self,
        read: impl FnOnce() -> ReadResult + Send + 'static,
    ) -> io::Result<ReaderFuture> {
        let mut state = self.0.lock().unwrap_or_else(|error| error.into_inner());
        if state.closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "registry reader owner stopped",
            ));
        }
        if state.handle.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "registry reader already outstanding",
            ));
        }
        // Admission and installing this original handle share one short lock.
        // The read callback runs in the blocking task, never under this lock.
        state.terminal = None;
        state.handle = Some(tokio::task::spawn_blocking(read));
        Ok(ReaderFuture(self.clone()))
    }

    pub(super) fn close(&self) {
        let mut state = self.0.lock().unwrap_or_else(|error| error.into_inner());
        state.closed = true;
        if let Some(handle) = &state.handle {
            handle.abort();
        }
    }

    fn poll_result(&self, cx: &mut Context<'_>) -> Poll<Result<ReadResult, JoinError>> {
        let mut state = self.0.lock().unwrap_or_else(|error| error.into_inner());
        let Some(handle) = state.handle.as_mut() else {
            return Poll::Pending;
        };
        let result = match Pin::new(handle).poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result,
        };
        state.handle = None;
        state.terminal = Some(match &result {
            Ok(_) => Terminal::Completed,
            Err(error) if error.is_cancelled() => Terminal::Cancelled,
            Err(_) => Terminal::Failed,
        });
        // Return the snapshot/error outside the lock. No user callback or
        // result destructor is invoked while retaining the ownership mutex.
        drop(state);
        Poll::Ready(result)
    }

    fn poll_terminal(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_result(cx) {
            Poll::Ready(result) => {
                let joined = match &result {
                    Ok(_) => Ok(()),
                    Err(error) if error.is_cancelled() => Ok(()),
                    Err(_) => Err(io::Error::other("registry reader task failed")),
                };
                // Cleanup discards an unread snapshot only after unlocking.
                drop(result);
                Poll::Ready(joined)
            }
            Poll::Pending => {
                let state = self.0.lock().unwrap_or_else(|error| error.into_inner());
                if state.handle.is_some() {
                    Poll::Pending
                } else if matches!(state.terminal, Some(Terminal::Failed)) {
                    Poll::Ready(Err(io::Error::other("registry reader task failed")))
                } else {
                    Poll::Ready(Ok(()))
                }
            }
        }
    }

    pub(super) async fn join_until(&self, cutoff: Instant) -> io::Result<()> {
        tokio::time::timeout_at(cutoff, poll_fn(|cx| self.poll_terminal(cx)))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "registry reader terminal unconfirmed",
                )
            })??;
        if Instant::now() >= cutoff {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "registry reader completed beyond cutoff",
            ));
        }
        Ok(())
    }

    #[cfg(all(test, unix))]
    pub(super) fn handle_id(&self) -> Option<tokio::task::Id> {
        self.0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .handle
            .as_ref()
            .map(JoinHandle::id)
    }
}

pub(super) struct ReaderFuture(ReaderOwner);

impl Future for ReaderFuture {
    type Output = ReadResult;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.poll_result(cx).map(|result| {
            result.unwrap_or_else(|_| Err(super::invalid("device registry reader failed")))
        })
    }
}
