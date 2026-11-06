//! Recording-only application progress on an already authenticated remote stream.
//! Successful reads are observed response bytes; successful writes are local
//! stream acceptance, not remote acknowledgement or complete application delivery.
use super::RelaySessionCounters;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(super) struct ByteProgress<T> {
    inner: T,
    counters: RelaySessionCounters,
    endpoint: Option<super::endpoint_bandit::Attempt>,
}

impl<T> ByteProgress<T> {
    pub(super) fn new(inner: T, counters: &RelaySessionCounters) -> Self {
        Self {
            inner,
            counters: counters.clone(),
            endpoint: None,
        }
    }
    pub(super) fn with_endpoint(
        inner: T,
        counters: &RelaySessionCounters,
        endpoint: Option<&super::endpoint_bandit::Attempt>,
    ) -> Self {
        Self {
            inner,
            counters: counters.clone(),
            endpoint: endpoint.cloned(),
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for ByteProgress<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            this.counters.add_received(buf.filled().len() - before);
            if buf.filled().len() > before {
                if let Some(endpoint) = &this.endpoint {
                    endpoint.observed_response();
                }
            }
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ByteProgress<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, bytes);
        if let Poll::Ready(Ok(written)) = &result {
            this.counters.add_sent(*written);
            if *written > 0 {
                if let Some(endpoint) = &this.endpoint {
                    endpoint.accepted_sent();
                }
            }
        }
        result
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write_vectored(cx, bytes);
        if let Poll::Ready(Ok(written)) = &result {
            this.counters.add_sent(*written);
            if *written > 0 {
                if let Some(endpoint) = &this.endpoint {
                    endpoint.accepted_sent();
                }
            }
        }
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{classify_relay_attempt, policy};
    use super::*;
    use aegis_core::signals::FailSignal;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::task::Waker;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    enum ReadStep {
        Data(Vec<u8>),
        Pending,
        Reset,
    }

    // Only owned memory is used. Reset can wait for an exact number of writes,
    // so both directions progress before the failure without ordering sleeps.
    struct ScriptedIo {
        reads: VecDeque<ReadStep>,
        written: Arc<Mutex<Vec<u8>>>,
        max_write: usize,
        write_limit: Option<usize>,
        reset_after_written: usize,
        read_waker: Option<Waker>,
        write_pending: bool,
        shutdown_error: bool,
    }

    impl ScriptedIo {
        fn new(bytes: &[u8], reset: bool) -> Self {
            let mut reads = VecDeque::new();
            if !bytes.is_empty() {
                reads.push_back(ReadStep::Data(bytes.to_vec()));
            }
            if reset {
                reads.push_back(ReadStep::Reset);
            }
            Self {
                reads,
                written: Arc::new(Mutex::new(Vec::new())),
                max_write: 2,
                write_limit: None,
                reset_after_written: 0,
                read_waker: None,
                write_pending: false,
                shutdown_error: false,
            }
        }
    }

    impl AsyncRead for ScriptedIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            match self.reads.pop_front() {
                Some(ReadStep::Data(bytes)) => {
                    let count = bytes.len().min(buf.remaining());
                    buf.put_slice(&bytes[..count]);
                    if count < bytes.len() {
                        self.reads
                            .push_front(ReadStep::Data(bytes[count..].to_vec()));
                    }
                    Poll::Ready(Ok(()))
                }
                Some(ReadStep::Pending) => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Some(ReadStep::Reset) => {
                    let written = self.written.lock().unwrap().len();
                    if written < self.reset_after_written {
                        self.reads.push_front(ReadStep::Reset);
                        self.read_waker = Some(cx.waker().clone());
                        Poll::Pending
                    } else {
                        Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()))
                    }
                }
                None => Poll::Ready(Ok(())),
            }
        }
    }

    impl AsyncWrite for ScriptedIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.write_pending {
                self.write_pending = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let count = {
                let mut written = self.written.lock().unwrap();
                let remaining = self.write_limit.map(|limit| limit - written.len());
                if remaining == Some(0) {
                    return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
                }
                let count = bytes
                    .len()
                    .min(self.max_write)
                    .min(remaining.unwrap_or(usize::MAX));
                written.extend_from_slice(&bytes[..count]);
                count
            };
            if let Some(waker) = self.read_waker.take() {
                waker.wake();
            }
            Poll::Ready(Ok(count))
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[io::IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            let first = bytes
                .iter()
                .find(|bytes| !bytes.is_empty())
                .map_or(&[][..], |bytes| &bytes[..]);
            self.poll_write(cx, first)
        }

        fn is_write_vectored(&self) -> bool {
            true
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.shutdown_error {
                Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
            } else {
                Poll::Ready(Ok(()))
            }
        }
    }

    fn profile() -> policy::RelaySessionProfile {
        policy::RelaySessionProfile {
            write_chunk_size: 3,
            surface_chunk_size_range: (3, 3),
            padding_probability_milli: 1000,
            padding_split_ratio_milli_range: (500, 500),
            ..Default::default()
        }
    }

    fn assert_post_data_reset(error: io::Error, counters: &RelaySessionCounters) {
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        let result = Err(anyhow::Error::new(error));
        assert_eq!(
            classify_relay_attempt(
                &result,
                counters.sent(),
                counters.received(),
                Duration::from_millis(1),
                Duration::from_secs(20),
            ),
            FailSignal::RemoteReset,
        );
    }

    #[tokio::test]
    async fn bidirectional_reset_retains_both_directions_and_classifier_progress() {
        let counters = RelaySessionCounters::default();
        counters.mark_opened();
        let mut local = ScriptedIo::new(b"upload", false);
        let local_written = local.written.clone();
        let mut remote = ScriptedIo::new(b"reply", true);
        remote.reset_after_written = b"upload".len();
        let remote_written = remote.written.clone();
        let mut remote = ByteProgress::new(remote, &counters);
        let error = tokio::io::copy_bidirectional(&mut local, &mut remote)
            .await
            .unwrap_err();
        assert_eq!(counters.sent(), b"upload".len() as u64);
        assert_eq!(counters.received(), b"reply".len() as u64);
        assert_eq!(&*remote_written.lock().unwrap(), b"upload");
        assert_eq!(&*local_written.lock().unwrap(), b"reply");
        assert!(counters.was_opened());
        assert_post_data_reset(error, &counters);
    }

    #[tokio::test]
    async fn bidirectional_success_and_prefetch_are_not_double_counted() {
        let counters = RelaySessionCounters::default();
        let mut local = ScriptedIo::new(b"tail", false);
        let remote = ScriptedIo::new(b"reply", false);
        let written = remote.written.clone();
        let mut remote = ByteProgress::new(remote, &counters);
        remote.write_all(b"prefix").await.unwrap();
        remote.flush().await.unwrap();
        let totals = tokio::io::copy_bidirectional(&mut local, &mut remote)
            .await
            .unwrap();
        assert_eq!(totals, (4, 5));
        assert_eq!(counters.sent(), 10);
        assert_eq!(counters.received(), 5);
        assert_eq!(&*written.lock().unwrap(), b"prefixtail");
        drop(remote);
        assert_eq!(counters.clone().sent(), 10);
        // The observer itself must never change the authenticated-open marker.
        assert!(!counters.was_opened());
    }

    #[tokio::test]
    async fn policy_both_directions_and_prefetch_survive_late_reset() {
        let counters = RelaySessionCounters::default();
        let local = ScriptedIo::new(b"tail", false);
        let local_written = local.written.clone();
        let mut remote = ScriptedIo::new(b"reply", true);
        remote.reset_after_written = b"prefixtail".len();
        let remote_written = remote.written.clone();
        let mut remote = ByteProgress::new(remote, &counters);
        let profile = profile();
        policy::write_prefetched_payload(&mut remote, &profile, Some(b"prefix"))
            .await
            .unwrap();
        let (mut local_read, mut local_write) = tokio::io::split(local);
        let (mut remote_read, mut remote_write) = tokio::io::split(remote);
        let up = async {
            let count =
                policy::copy_with_policy(&mut local_read, &mut remote_write, &profile).await?;
            remote_write.shutdown().await?;
            io::Result::Ok(count)
        };
        let down = async {
            let count =
                policy::copy_with_policy(&mut remote_read, &mut local_write, &profile).await?;
            local_write.shutdown().await?;
            io::Result::Ok(count)
        };
        let error = tokio::try_join!(up, down).unwrap_err();
        assert_eq!(counters.sent(), 10);
        assert_eq!(counters.received(), 5);
        assert_eq!(&*remote_written.lock().unwrap(), b"prefixtail");
        assert_eq!(&*local_written.lock().unwrap(), b"reply");
        assert_post_data_reset(error, &counters);
    }

    #[tokio::test]
    async fn policy_partial_write_failure_preserves_only_accepted_prefix() {
        let counters = RelaySessionCounters::default();
        let mut remote = ScriptedIo::new(b"", false);
        remote.write_limit = Some(8);
        let written = remote.written.clone();
        let mut remote = ByteProgress::new(remote, &counters);
        let profile = profile();
        policy::write_prefetched_payload(&mut remote, &profile, Some(b"prefix"))
            .await
            .unwrap();
        let mut local = ScriptedIo::new(b"tail", false);
        let error = policy::copy_with_policy(&mut local, &mut remote, &profile)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(counters.sent(), 8);
        assert_eq!(counters.received(), 0);
        assert_eq!(&*written.lock().unwrap(), b"prefixta");
    }

    #[tokio::test]
    async fn bidirectional_shutdown_failure_keeps_successful_writes() {
        let counters = RelaySessionCounters::default();
        let mut local = ScriptedIo::new(b"upload", false);
        let mut remote = ScriptedIo::new(b"", false);
        remote.shutdown_error = true;
        let written = remote.written.clone();
        let mut remote = ByteProgress::new(remote, &counters);
        let error = tokio::io::copy_bidirectional(&mut local, &mut remote)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(counters.sent(), 6);
        assert_eq!(&*written.lock().unwrap(), b"upload");
    }

    #[test]
    fn read_buffer_delta_pending_and_error_never_create_extra_progress() {
        let counters = RelaySessionCounters::default();
        let mut io = ScriptedIo::new(b"abc", true);
        io.reads.push_front(ReadStep::Pending);
        io.write_pending = true;
        io.write_limit = Some(2);
        let mut io = ByteProgress::new(io, &counters);
        let mut cx = Context::from_waker(Waker::noop());
        let mut storage = [0u8; 16];
        let mut buf = ReadBuf::new(&mut storage);
        buf.put_slice(b"old");
        assert!(Pin::new(&mut io).poll_read(&mut cx, &mut buf).is_pending());
        assert_eq!(counters.received(), 0);
        assert!(matches!(
            Pin::new(&mut io).poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(buf.filled(), b"oldabc");
        assert_eq!(counters.received(), 3);
        assert!(matches!(
            Pin::new(&mut io).poll_read(&mut cx, &mut buf),
            Poll::Ready(Err(_))
        ));
        assert_eq!(counters.received(), 3);
        assert!(Pin::new(&mut io).poll_write(&mut cx, b"data").is_pending());
        assert_eq!(counters.sent(), 0);
        assert!(io.is_write_vectored());
        assert!(matches!(
            Pin::new(&mut io).poll_write_vectored(&mut cx, &[io::IoSlice::new(b"data")]),
            Poll::Ready(Ok(2))
        ));
        assert_eq!(counters.sent(), 2);
        assert!(matches!(
            Pin::new(&mut io).poll_write(&mut cx, b"more"),
            Poll::Ready(Err(_))
        ));
        assert_eq!(counters.sent(), 2);
    }
}
