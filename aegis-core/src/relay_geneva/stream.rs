//! Socket lifetime bound to an owned packet worker. The guard must quiesce its
//! exact socket on close; the stream checks worker failure before every I/O.
use std::{
    io,
    ops::Deref,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};

pub trait RelaySocketGuard: Send + Sync + 'static {
    fn failed(&self) -> bool;
    /// Idempotent: shutdown only this registered socket and retire its flow.
    fn close(&mut self);
}

pub struct RelayProtectedTcp {
    tcp: TcpStream,
    guard: Option<GuardDrop>,
}
impl RelayProtectedTcp {
    pub fn protected(tcp: TcpStream, guard: Box<dyn RelaySocketGuard>) -> io::Result<Self> {
        let guard = GuardDrop(guard);
        if guard.0.failed() {
            // Last original socket reference must be closed before guard's
            // duplicate/inode quiescence check; otherwise cleanup falsely fails.
            drop(tcp);
            drop(guard);
            return Err(closed());
        }
        Ok(Self {
            tcp,
            guard: Some(guard),
        })
    }
    pub fn is_protected(&self) -> bool {
        self.guard.is_some()
    }
    pub fn check_worker(&self) -> io::Result<()> {
        if self.guard.as_ref().is_some_and(|g| g.0.failed()) {
            Err(closed())
        } else {
            Ok(())
        }
    }
    /// Only ordinary carriers can expose the raw socket to another TLS backend.
    pub fn into_unprotected(self) -> io::Result<TcpStream> {
        if self.guard.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "protected relay socket cannot lose its Geneva lifetime guard",
            ));
        }
        // No Drop implementation on Self; guard ownership is independently RAII.
        Ok(self.tcp)
    }
}
impl From<TcpStream> for RelayProtectedTcp {
    fn from(tcp: TcpStream) -> Self {
        Self { tcp, guard: None }
    }
}
impl Deref for RelayProtectedTcp {
    type Target = TcpStream;
    fn deref(&self) -> &TcpStream {
        &self.tcp
    }
}
fn closed() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "relay Geneva worker failed closed",
    )
}
impl AsyncRead for RelayProtectedTcp {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Err(e) = self.check_worker() {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.tcp).poll_read(cx, buf)
    }
}
impl AsyncWrite for RelayProtectedTcp {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Err(e) = self.check_worker() {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.tcp).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(e) = self.check_worker() {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.tcp).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tcp).poll_shutdown(cx)
    }
}
// The guard itself is held through TLS and HTTP/2 ownership. Normal field drop
// first closes the TcpStream, then this wrapper's guard calls exact-flow close.
struct GuardDrop(Box<dyn RelaySocketGuard>);
impl Drop for GuardDrop {
    fn drop(&mut self) {
        self.0.close()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    };
    struct BoundGuard {
        failed: Arc<AtomicBool>,
        closed: Arc<AtomicUsize>,
    }
    impl RelaySocketGuard for BoundGuard {
        fn failed(&self) -> bool {
            self.failed.load(Ordering::SeqCst)
        }
        fn close(&mut self) {
            self.closed.fetch_add(1, Ordering::SeqCst);
        }
    }
    #[test]
    fn guard_raii_closes_once_and_reads_live_failure_state_without_sockets() {
        let failed = Arc::new(AtomicBool::new(false));
        let closed = Arc::new(AtomicUsize::new(0));
        {
            let guard = GuardDrop(Box::new(BoundGuard {
                failed: failed.clone(),
                closed: closed.clone(),
            }));
            assert!(!guard.0.failed());
            failed.store(true, Ordering::SeqCst);
            assert!(guard.0.failed());
            assert_eq!(closed.load(Ordering::SeqCst), 0);
        }
        assert_eq!(closed.load(Ordering::SeqCst), 1);
    }
}
