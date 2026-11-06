//! Fixed aggregate API observations, never packet contents or delivery proof.
use std::fmt;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicU64, AtomicU8, Ordering},
    Arc,
};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

fn add(value: &AtomicU64, n: u64) {
    let _ = value.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
        Some(old.saturating_add(n))
    });
}
#[derive(Default)]
struct Operation {
    polls: AtomicU64,
    pending: AtomicU64,
    pending_budget_empty_at_entry: AtomicU64,
    pending_budget_empty_at_return: AtomicU64,
    ready: AtomicU64,
    errors: AtomicU64,
    error_kind: AtomicU8,
}
#[derive(Debug)]
pub struct OperationSnapshot {
    pub polls: u64,
    pub pending: u64,
    pub pending_budget_empty_at_entry: u64,
    pub pending_budget_empty_at_return: u64,
    pub ready: u64,
    pub errors: u64,
    pub last_error_kind: Option<&'static str>,
}
fn error_code(kind: io::ErrorKind) -> u8 {
    match kind {
        io::ErrorKind::WouldBlock => 1,
        io::ErrorKind::TimedOut => 2,
        io::ErrorKind::Interrupted => 3,
        io::ErrorKind::UnexpectedEof => 4,
        io::ErrorKind::BrokenPipe => 5,
        io::ErrorKind::ConnectionReset => 6,
        io::ErrorKind::ConnectionAborted => 7,
        io::ErrorKind::NotConnected => 8,
        io::ErrorKind::InvalidData => 9,
        _ => 10,
    }
}
impl Operation {
    fn result<T>(&self, result: &Poll<io::Result<T>>, budget_at_entry: bool) {
        match result {
            Poll::Pending => {
                add(&self.pending, 1);
                if !budget_at_entry {
                    add(&self.pending_budget_empty_at_entry, 1);
                }
                // A read-only task-local observation. This neither consumes nor
                // replenishes budget, polls I/O again, or changes the waker.
                // Remaining budget does not prove native WouldBlock; these are
                // boundary observations, not a classification of the OS cause.
                if !tokio::task::coop::has_budget_remaining() {
                    add(&self.pending_budget_empty_at_return, 1);
                }
            }
            Poll::Ready(Ok(_)) => add(&self.ready, 1),
            Poll::Ready(Err(error)) => {
                add(&self.errors, 1);
                self.error_kind
                    .store(error_code(error.kind()), Ordering::Relaxed);
            }
        }
    }
    fn snapshot(&self) -> OperationSnapshot {
        OperationSnapshot {
            polls: self.polls.load(Ordering::Relaxed),
            pending: self.pending.load(Ordering::Relaxed),
            pending_budget_empty_at_entry: self
                .pending_budget_empty_at_entry
                .load(Ordering::Relaxed),
            pending_budget_empty_at_return: self
                .pending_budget_empty_at_return
                .load(Ordering::Relaxed),
            ready: self.ready.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            last_error_kind: match self.error_kind.load(Ordering::Relaxed) {
                0 => None,
                1 => Some("would_block"),
                2 => Some("timed_out"),
                3 => Some("interrupted"),
                4 => Some("unexpected_eof"),
                5 => Some("broken_pipe"),
                6 => Some("connection_reset"),
                7 => Some("connection_aborted"),
                8 => Some("not_connected"),
                9 => Some("invalid_data"),
                _ => Some("other"),
            },
        }
    }
}
#[derive(Default)]
struct State {
    read: Operation,
    write: Operation,
    write_vectored: Operation,
    flush: Operation,
    shutdown: Operation,
    read_bytes: AtomicU64,
    write_bytes: AtomicU64,
    read_eof: AtomicU64,
    dropped: AtomicU64,
}
#[derive(Clone, Default)]
pub struct IoWitness(Arc<State>);
#[derive(Debug)]
pub struct IoSnapshot {
    pub read: OperationSnapshot,
    pub write: OperationSnapshot,
    pub write_vectored: OperationSnapshot,
    pub flush: OperationSnapshot,
    pub shutdown: OperationSnapshot,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub read_eof: u64,
    pub dropped: u64,
}
impl IoWitness {
    pub fn snapshot(&self) -> IoSnapshot {
        IoSnapshot {
            read: self.0.read.snapshot(),
            write: self.0.write.snapshot(),
            write_vectored: self.0.write_vectored.snapshot(),
            flush: self.0.flush.snapshot(),
            shutdown: self.0.shutdown.snapshot(),
            read_bytes: self.0.read_bytes.load(Ordering::Relaxed),
            write_bytes: self.0.write_bytes.load(Ordering::Relaxed),
            read_eof: self.0.read_eof.load(Ordering::Relaxed),
            dropped: self.0.dropped.load(Ordering::Relaxed),
        }
    }
    /// Owns the original stream. Drop/cancellation closes that stream normally.
    pub fn observe<S>(&self, stream: S) -> ObservedIo<S> {
        ObservedIo {
            stream,
            witness: self.clone(),
        }
    }
}
pub struct ObservedIo<S> {
    stream: S,
    witness: IoWitness,
}
impl<S> fmt::Debug for ObservedIo<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObservedIo")
            .field("metadata", &self.witness.snapshot())
            .finish()
    }
}
impl<S> Drop for ObservedIo<S> {
    fn drop(&mut self) {
        add(&self.witness.0.dropped, 1);
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for ObservedIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let had_space = buf.remaining() > 0;
        add(&this.witness.0.read.polls, 1);
        let budget_at_entry = tokio::task::coop::has_budget_remaining();
        let result = Pin::new(&mut this.stream).poll_read(cx, buf);
        this.witness.0.read.result(&result, budget_at_entry);
        if matches!(result, Poll::Ready(Ok(()))) {
            let n = buf.filled().len() - before;
            add(&this.witness.0.read_bytes, n as u64);
            if n == 0 && had_space {
                add(&this.witness.0.read_eof, 1);
            }
        }
        result
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for ObservedIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        add(&this.witness.0.write.polls, 1);
        let budget_at_entry = tokio::task::coop::has_budget_remaining();
        let result = Pin::new(&mut this.stream).poll_write(cx, buf);
        this.witness.0.write.result(&result, budget_at_entry);
        if let Poll::Ready(Ok(n)) = result {
            add(&this.witness.0.write_bytes, n as u64);
        }
        result
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        add(&this.witness.0.write.polls, 1);
        add(&this.witness.0.write_vectored.polls, 1);
        let budget_at_entry = tokio::task::coop::has_budget_remaining();
        let result = Pin::new(&mut this.stream).poll_write_vectored(cx, bufs);
        this.witness.0.write.result(&result, budget_at_entry);
        this.witness
            .0
            .write_vectored
            .result(&result, budget_at_entry);
        if let Poll::Ready(Ok(n)) = result {
            add(&this.witness.0.write_bytes, n as u64);
        }
        result
    }
    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        add(&this.witness.0.flush.polls, 1);
        let budget_at_entry = tokio::task::coop::has_budget_remaining();
        let result = Pin::new(&mut this.stream).poll_flush(cx);
        this.witness.0.flush.result(&result, budget_at_entry);
        result
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        add(&this.witness.0.shutdown.polls, 1);
        let budget_at_entry = tokio::task::coop::has_budget_remaining();
        let result = Pin::new(&mut this.stream).poll_shutdown(cx);
        this.witness.0.shutdown.result(&result, budget_at_entry);
        result
    }
}

#[cfg(test)]
#[path = "io_progress_tests.rs"]
mod tests;
