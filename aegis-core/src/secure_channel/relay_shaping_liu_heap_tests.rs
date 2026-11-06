//! No-poll regression for the heap boundary of the newly added dispatcher.
//! Include this cfg(test) module beneath relay_shaping::liu.
use super::*;
use std::{
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
};
struct LargeOwnedCarrier {
    _slab: [u8; 64 * 1024],
    polls: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}
impl Drop for LargeOwnedCarrier {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}
impl tokio::io::AsyncRead for LargeOwnedCarrier {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Poll::Pending
    }
}
impl tokio::io::AsyncWrite for LargeOwnedCarrier {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Poll::Pending
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Poll::Pending
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Poll::Pending
    }
}
#[test]
fn new_liu_dispatcher_heap_boundary_is_small_lazy_and_exactly_owned() {
    assert!(std::mem::size_of::<LargeOwnedCarrier>() >= 64 * 1024);
    let polls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let carrier = LargeOwnedCarrier {
        _slab: [0x5a; 64 * 1024],
        polls: polls.clone(),
        drops: drops.clone(),
    };
    let future = client_admitted(carrier, None, Instant::now(), None);
    // Checks run even on the old expected-red large future; no future polled.
    let bytes = std::mem::size_of_val(&future);
    fn assert_send<T: Send>(_: &T) {}
    assert_send(&future);
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(future);
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    println!("new Liu dispatcher returned_future_bytes={bytes}");
    assert!(
        bytes <= 1024,
        "new dispatcher propagates {bytes} inline bytes into startup callers"
    );
}
