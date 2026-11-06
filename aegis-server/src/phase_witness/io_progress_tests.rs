use super::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const WATCHDOG: Duration = Duration::from_secs(3);
struct AbortTask(tokio::task::AbortHandle);
impl Drop for AbortTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::test]
async fn actual_short_vectored_write_and_short_read_keep_exact_io_results() {
    tokio::time::timeout(WATCHDOG, async {
        let (local, mut peer) = tokio::io::duplex(3);
        let witness = IoWitness::default();
        let mut local = witness.observe(local);
        let n = local
            .write_vectored(&[IoSlice::new(b"abc"), IoSlice::new(b"private")])
            .await
            .unwrap();
        assert_eq!(n, 3);
        let mut first = [0; 2];
        peer.read_exact(&mut first).await.unwrap();
        assert_eq!(first, *b"ab");
        let mut last = [0; 1];
        peer.read_exact(&mut last).await.unwrap();
        assert_eq!(last, *b"c");
        peer.write_all(b"xyz").await.unwrap();
        assert_eq!(local.read(&mut first).await.unwrap(), 2);
        assert_eq!(first, *b"xy");
        assert_eq!(local.read(&mut last).await.unwrap(), 1);
        local.flush().await.unwrap();
        local.shutdown().await.unwrap();
        let snapshot = witness.snapshot();
        assert_eq!(snapshot.write_bytes, 3);
        assert_eq!(snapshot.read_bytes, 3);
        assert_eq!(snapshot.write.ready, 1);
        assert!(snapshot.flush.ready > 0 && snapshot.shutdown.ready > 0);
        assert_eq!(snapshot.read_eof, 0);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn actual_pending_read_eof_and_empty_read_are_distinct() {
    tokio::time::timeout(WATCHDOG, async {
        let (local, peer) = tokio::io::duplex(4);
        let witness = IoWitness::default();
        let mut local = witness.observe(local);
        let mut bytes = [0; 2];
        let pending = std::future::poll_fn(|cx| {
            Poll::Ready(
                Pin::new(&mut local)
                    .poll_read(cx, &mut ReadBuf::new(&mut bytes))
                    .is_pending(),
            )
        })
        .await;
        assert!(pending);
        assert_eq!(witness.snapshot().read.pending, 1);
        assert_eq!(witness.snapshot().read.pending_budget_empty_at_entry, 0);
        assert_eq!(witness.snapshot().read.pending_budget_empty_at_return, 0);
        drop(peer);
        assert_eq!(local.read(&mut bytes).await.unwrap(), 0);
        assert_eq!(witness.snapshot().read_eof, 1);
        assert_eq!(local.read(&mut []).await.unwrap(), 0);
        assert_eq!(
            witness.snapshot().read_eof,
            1,
            "empty caller buffer is not peer EOF"
        );
        assert_eq!(witness.snapshot().read_bytes, 0);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn actual_cooperative_refusal_preserves_ready_bytes_and_does_not_restore_budget() {
    tokio::time::timeout(WATCHDOG, async {
        let (local, mut peer) = tokio::io::duplex(4);
        peer.write_all(b"abc").await.unwrap();
        let witness = IoWitness::default();
        let observed = witness.clone();
        let task = tokio::spawn(async move {
            let mut local = observed.observe(local);
            // Exhaust the real Tokio budget without polling beyond its empty
            // boundary or assuming a particular initial budget size.
            let mut consumed = 0;
            while tokio::task::coop::has_budget_remaining() {
                assert!(consumed < 4096, "Tokio budget did not exhaust");
                tokio::task::consume_budget().await;
                consumed += 1;
            }
            assert!(consumed > 0);
            let mut bytes = [0u8; 3];
            let (pending, filled) = std::future::poll_fn(|cx| {
                let mut read = ReadBuf::new(&mut bytes);
                let pending = Pin::new(&mut local).poll_read(cx, &mut read).is_pending();
                Poll::Ready((pending, read.filled().len()))
            })
            .await;
            assert!(pending);
            assert_eq!(filled, 0, "cooperative refusal must not consume bytes");
            assert!(!tokio::task::coop::has_budget_remaining());
            let snapshot = observed.snapshot();
            assert_eq!(snapshot.read.pending, 1);
            assert_eq!(snapshot.read.pending_budget_empty_at_entry, 1);
            assert_eq!(snapshot.read.pending_budget_empty_at_return, 1);
            assert_eq!(snapshot.read_bytes, 0);
            tokio::task::yield_now().await;
            local.read_exact(&mut bytes).await.unwrap();
            assert_eq!(bytes, *b"abc");
            assert_eq!(observed.snapshot().read_bytes, 3);
        });
        let _owner = AbortTask(task.abort_handle());
        task.await.unwrap();
        assert_eq!(witness.snapshot().dropped, 1);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn actual_pending_task_abort_drops_only_owned_stream_and_preserves_foreign_io() {
    tokio::time::timeout(WATCHDOG, async {
        let (local, mut peer) = tokio::io::duplex(4);
        let (mut foreign, mut foreign_peer) = tokio::io::duplex(4);
        let witness = IoWitness::default();
        let mut local = witness.observe(local);
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let mut ready = Some(ready_tx);
        let task = tokio::spawn(async move {
            let mut bytes = [0; 1];
            std::future::poll_fn(|cx| {
                let result = Pin::new(&mut local).poll_read(cx, &mut ReadBuf::new(&mut bytes));
                if result.is_pending() {
                    if let Some(tx) = ready.take() {
                        tx.send(()).unwrap();
                    }
                }
                result
            })
            .await
        });
        let _owner = AbortTask(task.abort_handle());
        ready_rx.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(witness.snapshot().dropped, 1);
        let mut bytes = [0; 1];
        assert_eq!(peer.read(&mut bytes).await.unwrap(), 0);
        foreign.write_all(b"f").await.unwrap();
        foreign_peer.read_exact(&mut bytes).await.unwrap();
        assert_eq!(bytes, *b"f");
        foreign_peer.write_all(b"g").await.unwrap();
        foreign.read_exact(&mut bytes).await.unwrap();
        assert_eq!(bytes, *b"g");
    })
    .await
    .unwrap();
}

struct PrivateError;
impl fmt::Debug for PrivateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PRIVATE-INNER-MARKER")
    }
}
impl AsyncWrite for PrivateError {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "PRIVATE-ERROR-MARKER",
        )))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
#[tokio::test]
async fn debug_redacts_actual_inner_and_error_while_original_error_is_preserved() {
    let witness = IoWitness::default();
    let mut io = witness.observe(PrivateError);
    let error = io.write(b"PRIVATE-PAYLOAD-MARKER").await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    assert_eq!(error.to_string(), "PRIVATE-ERROR-MARKER");
    let snapshot = witness.snapshot();
    assert_eq!(snapshot.write.errors, 1);
    assert_eq!(snapshot.write.last_error_kind, Some("connection_reset"));
    assert_eq!(snapshot.write_bytes, 0);
    let displayed = format!("{io:?} {snapshot:?}");
    assert!(!displayed.contains("PRIVATE-"));
}

#[tokio::test]
async fn actual_peer_close_preserves_write_error_and_fixed_counters_saturate() {
    let (local, peer) = tokio::io::duplex(3);
    let witness = IoWitness::default();
    let mut io = witness.observe(local);
    witness.0.write.polls.store(u64::MAX, Ordering::Relaxed);
    witness.0.write.errors.store(u64::MAX, Ordering::Relaxed);
    drop(peer);
    assert_eq!(
        io.write(b"x").await.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    let snapshot = witness.snapshot();
    assert_eq!(snapshot.write.polls, u64::MAX);
    assert_eq!(snapshot.write.errors, u64::MAX);
    assert_eq!(snapshot.write.last_error_kind, Some("broken_pipe"));
}
