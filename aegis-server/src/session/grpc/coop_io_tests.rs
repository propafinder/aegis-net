use super::ServerH2Io;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Default, Debug)]
struct Calls {
    reads: usize,
    writes: usize,
    vectored: usize,
    flushes: usize,
    shutdowns: usize,
}

struct ControlIo {
    calls: Arc<Mutex<Calls>>,
    read: Option<io::Result<Vec<u8>>>,
    write: Option<io::Result<usize>>,
    flush: Option<io::Result<()>>,
    shutdown: Option<io::Result<()>>,
}

impl ControlIo {
    fn ready() -> (Self, Arc<Mutex<Calls>>) {
        let calls = Arc::new(Mutex::new(Calls::default()));
        (
            Self {
                calls: calls.clone(),
                read: Some(Ok(b"read".to_vec())),
                write: Some(Ok(3)),
                flush: Some(Ok(())),
                shutdown: Some(Ok(())),
            },
            calls,
        )
    }
}

impl AsyncRead for ControlIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.calls.lock().unwrap().reads += 1;
        match self.read.take() {
            Some(Ok(bytes)) => {
                buf.put_slice(&bytes[..bytes.len().min(buf.remaining())]);
                Poll::Ready(Ok(()))
            }
            Some(Err(error)) => Poll::Ready(Err(error)),
            None => Poll::Ready(Ok(())),
        }
    }
}

impl AsyncWrite for ControlIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.calls.lock().unwrap().writes += 1;
        Poll::Ready(self.write.take().unwrap_or(Ok(0)))
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.calls.lock().unwrap().vectored += 1;
        Poll::Ready(self.write.take().unwrap_or(Ok(0)))
    }
    fn is_write_vectored(&self) -> bool {
        true
    }
    fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.calls.lock().unwrap().flushes += 1;
        Poll::Ready(self.flush.take().unwrap_or(Ok(())))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.calls.lock().unwrap().shutdowns += 1;
        Poll::Ready(self.shutdown.take().unwrap_or(Ok(())))
    }
}

#[tokio::test]
async fn ready_eof_error_and_zero_capacity_reads_delegate_unchanged() {
    use tokio::io::AsyncReadExt;
    let (inner, calls) = ControlIo::ready();
    let mut io = ServerH2Io::new(inner);
    let mut bytes = [0; 4];
    assert_eq!(io.read(&mut bytes).await.unwrap(), 4);
    assert_eq!(&bytes, b"read");
    assert_eq!(io.read(&mut bytes).await.unwrap(), 0, "EOF preserved");
    assert_eq!(calls.lock().unwrap().reads, 2);

    let (mut inner, _) = ControlIo::ready();
    inner.read = Some(Err(io::Error::from_raw_os_error(10054)));
    let error = ServerH2Io::new(inner).read(&mut bytes).await.unwrap_err();
    assert_eq!(error.raw_os_error(), Some(10054));

    let (inner, calls) = ControlIo::ready();
    let mut io = ServerH2Io::new(inner);
    let mut empty = [];
    assert_eq!(io.read(&mut empty).await.unwrap(), 0);
    assert_eq!(calls.lock().unwrap().reads, 1, "zero read delegated");
}

#[tokio::test]
async fn write_vectored_zero_error_flush_and_shutdown_delegate_unchanged() {
    use tokio::io::AsyncWriteExt;
    let (inner, calls) = ControlIo::ready();
    let mut io = ServerH2Io::new(inner);
    assert!(io.is_write_vectored());
    assert_eq!(io.write(b"abc").await.unwrap(), 3);
    io.flush().await.unwrap();
    io.shutdown().await.unwrap();
    {
        let state = calls.lock().unwrap();
        assert_eq!((state.writes, state.flushes, state.shutdowns), (1, 1, 1));
    }

    let (mut inner, _) = ControlIo::ready();
    inner.write = Some(Ok(0));
    assert_eq!(ServerH2Io::new(inner).write(b"x").await.unwrap(), 0);

    let (mut inner, _) = ControlIo::ready();
    inner.write = Some(Err(io::Error::from_raw_os_error(10053)));
    assert_eq!(
        ServerH2Io::new(inner)
            .write(b"x")
            .await
            .unwrap_err()
            .raw_os_error(),
        Some(10053)
    );

    let (mut inner, calls) = ControlIo::ready();
    inner.write = Some(Ok(4));
    let mut io = ServerH2Io::new(inner);
    let bufs = [io::IoSlice::new(b"ab"), io::IoSlice::new(b"cd")];
    let n = std::future::poll_fn(|cx| Pin::new(&mut io).poll_write_vectored(cx, &bufs))
        .await
        .unwrap();
    assert_eq!(n, 4);
    assert_eq!(calls.lock().unwrap().vectored, 1);

    let (mut inner, _) = ControlIo::ready();
    inner.flush = Some(Err(io::Error::from_raw_os_error(10055)));
    assert_eq!(
        ServerH2Io::new(inner)
            .flush()
            .await
            .unwrap_err()
            .raw_os_error(),
        Some(10055)
    );
}

struct ExhaustOnRead {
    calls: Arc<Mutex<Calls>>,
}

impl AsyncRead for ExhaustOnRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.calls.lock().unwrap().reads += 1;
        while let Poll::Ready(permit) = tokio::task::coop::poll_proceed(cx) {
            permit.made_progress();
        }
        Poll::Pending
    }
}

impl AsyncWrite for ExhaustOnRead {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.calls.lock().unwrap().writes += 1;
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.calls.lock().unwrap().flushes += 1;
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.calls.lock().unwrap().shutdowns += 1;
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn exhausted_pending_read_defers_inner_write_once_then_uses_fresh_budget() {
    let calls = Arc::new(Mutex::new(Calls::default()));
    let mut io = ServerH2Io::new(ExhaustOnRead {
        calls: calls.clone(),
    });
    let mut byte = [0; 1];
    std::future::poll_fn(|cx| {
        assert!(Pin::new(&mut io)
            .poll_read(cx, &mut ReadBuf::new(&mut byte))
            .is_pending());
        assert!(!tokio::task::coop::has_budget_remaining());
        assert!(Pin::new(&mut io).poll_write(cx, b"queued").is_pending());
        assert_eq!(calls.lock().unwrap().writes, 0);
        Poll::Ready(())
    })
    .await;
    tokio::task::yield_now().await;
    std::future::poll_fn(|cx| {
        assert!(Pin::new(&mut io)
            .poll_read(cx, &mut ReadBuf::new(&mut byte))
            .is_pending());
        assert_eq!(calls.lock().unwrap().reads, 1, "one read skipped");
        match Pin::new(&mut io).poll_write(cx, b"queued") {
            Poll::Ready(Ok(6)) => Poll::Ready(()),
            other => panic!("fresh write did not delegate: {other:?}"),
        }
    })
    .await;
    assert_eq!(calls.lock().unwrap().writes, 1);
}

struct ExhaustOnceThenRead {
    calls: usize,
    result: Option<io::Result<Vec<u8>>>,
}

impl AsyncRead for ExhaustOnceThenRead {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.calls += 1;
        if self.calls == 1 {
            while let Poll::Ready(permit) = tokio::task::coop::poll_proceed(cx) {
                permit.made_progress();
            }
            return Poll::Pending;
        }
        match self.result.take().unwrap_or(Ok(Vec::new())) {
            Ok(bytes) => {
                buf.put_slice(&bytes);
                Poll::Ready(Ok(()))
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

impl AsyncWrite for ExhaustOnceThenRead {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        panic!("pure-read control must not poll write")
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("pure-read control must not poll flush")
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("pure-read control must not poll shutdown")
    }
}

#[tokio::test]
async fn pure_read_without_queued_write_skips_once_then_delivers_data_eof_and_error() {
    use tokio::io::AsyncReadExt;
    for result in [
        Ok(b"peer-window-update".to_vec()),
        Ok(Vec::new()),
        Err(io::Error::from_raw_os_error(10054)),
    ] {
        let expected = result
            .as_ref()
            .map(|bytes| bytes.clone())
            .map_err(|error| error.raw_os_error());
        let mut io = ServerH2Io::new(ExhaustOnceThenRead {
            calls: 0,
            result: Some(result),
        });
        let mut bytes = vec![0; 32];
        let observed = io.read(&mut bytes).await;
        match expected {
            Ok(expected) => {
                let n = observed.unwrap();
                assert_eq!(&bytes[..n], expected.as_slice());
            }
            Err(raw) => assert_eq!(observed.unwrap_err().raw_os_error(), raw),
        }
        assert_eq!(
            io.get_ref().calls,
            2,
            "one inner read after one skipped poll"
        );
    }
}
