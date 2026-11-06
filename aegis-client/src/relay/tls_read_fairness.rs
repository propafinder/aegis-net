//! Bounded Rustls socket reads for Windows readiness fairness.

use aegis_core::relay_geneva::RelayProtectedTcp;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(super) trait ReadinessSource: AsyncWrite + Unpin {
    fn check_worker(&self) -> io::Result<()>;
    fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
    fn try_read(&self, buf: &mut [u8]) -> io::Result<usize>;
}

impl ReadinessSource for RelayProtectedTcp {
    fn check_worker(&self) -> io::Result<()> {
        RelayProtectedTcp::check_worker(self)
    }

    fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        (**self).poll_read_ready(cx)
    }

    fn try_read(&self, buf: &mut [u8]) -> io::Result<usize> {
        (**self).try_read(buf)
    }
}

pub(super) struct WindowsRustlsTcp<S = RelayProtectedTcp> {
    source: S,
}

impl<S> WindowsRustlsTcp<S> {
    pub(super) fn new(source: S) -> Self {
        Self { source }
    }
}

impl<S: ReadinessSource> AsyncRead for WindowsRustlsTcp<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.source.check_worker()?;
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        std::task::ready!(this.source.poll_read_ready(cx))?;
        match this.source.try_read(buf.initialize_unfilled()) {
            Ok(read) => {
                buf.advance(read);
                Poll::Ready(Ok(()))
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                // `TcpStream::try_read` clears the observed readiness. The
                // preceding Ready path need not have registered this waker, so
                // schedule exactly one fresh poll and let the next readiness
                // observation participate in Tokio's cooperative budget.
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

impl<S: ReadinessSource> AsyncWrite for WindowsRustlsTcp<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().source).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().source).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.source.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().source).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().source).poll_shutdown(cx)
    }
}

#[cfg(test)]
#[path = "tls_read_fairness_tests.rs"]
mod tests;
