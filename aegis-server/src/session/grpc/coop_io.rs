use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Gives a queued H2 write one fresh cooperative-budget turn after a pending
/// receive poll consumes the last available permit.
pub(super) struct ServerH2Io<S> {
    inner: S,
    write_turn_due: bool,
    read_handoff_pending: bool,
    wake_scheduled: bool,
}

impl<S> ServerH2Io<S> {
    pub(super) fn new(inner: S) -> Self {
        Self {
            inner,
            write_turn_due: false,
            read_handoff_pending: false,
            wake_scheduled: false,
        }
    }

    #[cfg(test)]
    pub(super) fn get_ref(&self) -> &S {
        &self.inner
    }

    fn write_turn(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if !self.write_turn_due {
            return Poll::Ready(());
        }
        if !tokio::task::coop::has_budget_remaining() {
            if !self.wake_scheduled {
                self.wake_scheduled = true;
                cx.waker().wake_by_ref();
            }
            return Poll::Pending;
        }
        self.write_turn_due = false;
        self.wake_scheduled = false;
        Poll::Ready(())
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ServerH2Io<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
        if this.read_handoff_pending {
            // Skip exactly one receive attempt. The wake is owned here because
            // a pure-read user may never poll the write side. Subsequent reads
            // delegate even if no write operation consumes write_turn_due.
            this.read_handoff_pending = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let budget_at_entry = tokio::task::coop::has_budget_remaining();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if result.is_pending()
            && budget_at_entry
            && !tokio::task::coop::has_budget_remaining()
            && !this.write_turn_due
        {
            this.write_turn_due = true;
            this.read_handoff_pending = true;
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ServerH2Io<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        std::task::ready!(this.write_turn(cx));
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        std::task::ready!(this.write_turn(cx));
        Pin::new(&mut this.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.write_turn(cx));
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.write_turn(cx));
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
#[path = "coop_io_tests.rs"]
mod tests;
