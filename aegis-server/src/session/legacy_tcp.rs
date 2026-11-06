//! Deadlines for the authenticated legacy TCP path only.
//!
//! An active tunnel has no total lifetime limit. One shared byte-progress clock
//! bounds silence in both directions, while each destination write, flush, or
//! half-close must make progress within its own write deadline.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Duration, Instant, Sleep};

#[cfg(test)]
#[path = "legacy_tcp/tests.rs"]
mod tests;

/// A single deadline includes resolution, validation and all exact-address
/// attempts. The existing resolve-once target-policy future is cancelled as a
/// whole on expiry; this helper does not retry or reconnect by hostname.
pub(super) async fn establish<F, T>(future: F, budget: Duration) -> io::Result<T>
where
    F: Future<Output = io::Result<T>>,
{
    bounded_at(
        future,
        Instant::now() + budget,
        "legacy target establishment timed out",
    )
    .await
}

/// Bound the complete encrypted control-frame write, including partial writes.
#[cfg(any(test, not(feature = "legacy-challenge-v1")))]
pub(super) async fn write_control<F>(future: F, budget: Duration) -> anyhow::Result<()>
where
    F: Future<Output = anyhow::Result<()>>,
{
    bounded_at(
        future,
        Instant::now() + budget,
        "legacy control response write timed out",
    )
    .await
}

/// Ready I/O cannot bypass an expired timer. Guard both sides of each poll:
/// an operation may become ready while its owner is not scheduled, or spend
/// time inside the poll itself. Neither renews this absolute cutoff.
async fn bounded_at<F, T, E>(future: F, deadline: Instant, message: &'static str) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
    E: From<io::Error>,
{
    let mut future = Box::pin(future);
    let mut cutoff = Box::pin(tokio::time::sleep_until(deadline));
    std::future::poll_fn(move |cx| {
        if Instant::now() >= deadline {
            return Poll::Ready(Err(E::from(deadline_error(message))));
        }
        let result = future.as_mut().poll(cx);
        if Instant::now() >= deadline {
            return Poll::Ready(Err(E::from(deadline_error(message))));
        }
        match result {
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => match cutoff.as_mut().poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(()) => Poll::Ready(Err(E::from(deadline_error(message)))),
            },
        }
    })
    .await
}

/// Borrowed adapters and the copy future share one owner. Returning, cancelling
/// or timing out drops every forwarding future; no direction is spawned away.
pub(super) async fn forward<A, B>(
    client: &mut A,
    target: &mut B,
    idle_budget: Duration,
    write_budget: Duration,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let last_activity = Arc::new(Mutex::new(Instant::now()));
    let mut client = ProgressStream::new(client, last_activity.clone(), idle_budget, write_budget);
    let mut target = ProgressStream::new(target, last_activity.clone(), idle_budget, write_budget);
    let idle = async {
        loop {
            let deadline = *last_activity.lock().unwrap_or_else(|e| e.into_inner()) + idle_budget;
            tokio::time::sleep_until(deadline).await;
            let deadline = *last_activity.lock().unwrap_or_else(|e| e.into_inner()) + idle_budget;
            if Instant::now() >= deadline {
                return deadline_error("authenticated legacy TCP tunnel idle deadline elapsed");
            }
        }
    };

    tokio::select! {
        // Adapters refuse the prior idle/write cutoff before polling or renewal.
        biased;
        result = tokio::io::copy_bidirectional(&mut client, &mut target) => result,
        error = idle => Err(error),
    }
}

fn deadline_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, message)
}

struct ProgressStream<'a, S> {
    inner: &'a mut S,
    last_activity: Arc<Mutex<Instant>>,
    idle_budget: Duration,
    write_budget: Duration,
    stalled_write: Option<Pin<Box<Sleep>>>,
}

impl<'a, S> ProgressStream<'a, S> {
    fn new(
        inner: &'a mut S,
        last_activity: Arc<Mutex<Instant>>,
        idle_budget: Duration,
        write_budget: Duration,
    ) -> Self {
        Self {
            inner,
            last_activity,
            idle_budget,
            write_budget,
            stalled_write: None,
        }
    }

    fn check_idle(&self) -> io::Result<()> {
        let activity = *self.last_activity.lock().unwrap_or_else(|e| e.into_inner());
        if Instant::now() >= activity + self.idle_budget {
            return Err(deadline_error(
                "authenticated legacy TCP tunnel idle deadline elapsed",
            ));
        }
        Ok(())
    }

    fn note_bytes(&self) -> io::Result<()> {
        let mut activity = self.last_activity.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if now >= *activity + self.idle_budget {
            return Err(deadline_error(
                "authenticated legacy TCP tunnel idle deadline elapsed",
            ));
        }
        *activity = now;
        Ok(())
    }

    fn check_write(&self) -> io::Result<()> {
        self.check_idle()?;
        if self
            .stalled_write
            .as_ref()
            .is_some_and(|timer| Instant::now() >= timer.deadline())
        {
            return Err(deadline_error("legacy TCP write progress timed out"));
        }
        Ok(())
    }

    fn begin_write(&mut self) -> io::Result<()> {
        self.check_write()?;
        let budget = self.write_budget;
        self.stalled_write
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(budget)));
        self.check_write()
    }

    fn poll_stalled_write<T>(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<T>> {
        let deadline = self
            .stalled_write
            .as_mut()
            .expect("write deadline started before inner poll");
        match deadline.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(()) => {
                Poll::Ready(Err(deadline_error("legacy TCP write progress timed out")))
            }
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ProgressStream<'_, S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Err(error) = self.check_idle() {
            return Poll::Ready(Err(error));
        }
        let before = buf.filled().len();
        let result = Pin::new(&mut *self.inner).poll_read(cx, buf);
        if let Err(error) = self.check_idle() {
            return Poll::Ready(Err(error));
        }
        if matches!(&result, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            if let Err(error) = self.note_bytes() {
                return Poll::Ready(Err(error));
            }
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ProgressStream<'_, S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Err(error) = self.begin_write() {
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut *self.inner).poll_write(cx, buf);
        if let Err(error) = self.check_write() {
            return Poll::Ready(Err(error));
        }
        match result {
            Poll::Ready(result) => {
                if matches!(&result, Ok(n) if *n > 0) {
                    if let Err(error) = self.note_bytes() {
                        return Poll::Ready(Err(error));
                    }
                }
                self.stalled_write = None;
                Poll::Ready(result)
            }
            Poll::Pending => self.poll_stalled_write(cx),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.begin_write() {
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut *self.inner).poll_flush(cx);
        if let Err(error) = self.check_write() {
            return Poll::Ready(Err(error));
        }
        match result {
            Poll::Ready(result) => {
                self.stalled_write = None;
                Poll::Ready(result)
            }
            Poll::Pending => self.poll_stalled_write(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.begin_write() {
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut *self.inner).poll_shutdown(cx);
        if let Err(error) = self.check_write() {
            return Poll::Ready(Err(error));
        }
        match result {
            Poll::Ready(result) => {
                self.stalled_write = None;
                Poll::Ready(result)
            }
            Poll::Pending => self.poll_stalled_write(cx),
        }
    }
}
