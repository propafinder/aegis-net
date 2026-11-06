use crate::{
    endpoint::{PeerOwner, CHUNK},
    Cancellation, PathEvidence,
};
use bytes::BytesMut;
use std::{
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use webrtc::{
    data_channel::{DataChannel, DataChannelEvent},
    peer_connection::PeerConnection,
};

/// A bounded adapter over actual UDP ICE, DTLS and reliable ordered SCTP.
/// The in-process duplex buffer implements the AsyncRead/Write boundary only;
/// every peer byte is transported by the negotiated network DataChannel.
pub struct WebRtcStream {
    io: DuplexStream,
    path: PathEvidence,
    peer_ip: std::net::IpAddr,
    stop: Cancellation,
    failed: Arc<Mutex<Option<&'static str>>>,
    worker: Option<tokio::task::JoinHandle<()>>,
    sent: Arc<Mutex<(bool, Option<Waker>)>>,
    received_fin: Arc<AtomicBool>,
}
impl WebRtcStream {
    pub fn path_evidence(&self) -> &PathEvidence {
        &self.path
    }
    /// Actual nominated remote address, checked against the configured policy.
    /// Callers must not log this address as public diagnostics.
    pub fn peer_ip(&self) -> std::net::IpAddr {
        self.peer_ip
    }
    pub async fn close(mut self) {
        self.stop.cancel();
        if let Some(worker) = self.worker.take() {
            let _ = tokio::time::timeout(Duration::from_secs(3), worker).await;
        }
    }
    pub(crate) fn start(
        pc: Arc<dyn PeerConnection>,
        dc: Arc<dyn DataChannel>,
        path: PathEvidence,
        peer_ip: std::net::IpAddr,
        stall: Duration,
        lifetime: Duration,
        cancel: Cancellation,
    ) -> Self {
        let (io, pump) = tokio::io::duplex(65536);
        let (mut outgoing, mut incoming) = tokio::io::split(pump);
        let stop = Cancellation::new();
        let stopping = stop.clone();
        let failed = Arc::new(Mutex::new(None));
        let failure = failed.clone();
        let sent = Arc::new(Mutex::new((false, None::<Waker>)));
        let sending_done = sent.clone();
        let failed_done = sent.clone();
        let received_fin = Arc::new(AtomicBool::new(false));
        let worker_fin = received_fin.clone();
        let worker = tokio::spawn(async move {
            let expires = tokio::time::Instant::now() + lifetime;
            let owner = PeerOwner(Some(pc));
            let sending = dc.clone();
            let receiving = dc.clone();
            let send = async move {
                let mut buf = [0u8; CHUNK];
                loop {
                    let n = outgoing
                        .read(&mut buf)
                        .await
                        .map_err(|_| "local stream failed")?;
                    let mut frame = BytesMut::with_capacity(n + 1);
                    frame.extend_from_slice(&[u8::from(n == 0)]);
                    frame.extend_from_slice(&buf[..n]);
                    tokio::time::timeout(stall, sending.send(frame))
                        .await
                        .map_err(|_| "send stalled")?
                        .map_err(|_| "channel send failed")?;
                    if n == 0 {
                        // Don't close SCTP before the ordered FIN/data are acknowledged.
                        tokio::time::timeout(stall, async {
                            while sending
                                .outstanding_bytes()
                                .await
                                .map_err(|_| "channel closed")?
                                > 0
                            {
                                tokio::time::sleep(Duration::from_millis(5)).await;
                            }
                            Ok::<(), &'static str>(())
                        })
                        .await
                        .map_err(|_| "send stalled")??;
                        if let Ok(mut done) = sending_done.lock() {
                            done.0 = true;
                            if let Some(waker) = done.1.take() {
                                waker.wake();
                            }
                        }
                        return Ok::<(), &'static str>(());
                    }
                }
            };
            let receive = async move {
                loop {
                    match receiving.poll().await {
                        Some(DataChannelEvent::OnMessage(message)) => {
                            if message.is_string
                                || message.data.is_empty()
                                || message.data.len() > CHUNK + 1
                            {
                                return Err("invalid channel frame");
                            }
                            match message.data[0] {
                                0 if message.data.len() > 1 => tokio::time::timeout(
                                    stall,
                                    incoming.write_all(&message.data[1..]),
                                )
                                .await
                                .map_err(|_| "receive stalled")?
                                .map_err(|_| "local stream failed")?,
                                1 if message.data.len() == 1 => {
                                    // Publish before shutdown/drop can wake a reader. Only an
                                    // exact ordered one-byte FIN authorizes a clean local EOF.
                                    worker_fin.store(true, Ordering::Release);
                                    incoming
                                        .shutdown()
                                        .await
                                        .map_err(|_| "local stream failed")?;
                                    return Ok::<(), &'static str>(());
                                }
                                2 if message.data.len() == 1 => {
                                    return Err("peer cancelled carrier")
                                }
                                _ => return Err("invalid channel frame"),
                            }
                        }
                        Some(
                            DataChannelEvent::OnBufferedAmountHigh
                            | DataChannelEvent::OnBufferedAmountLow,
                        ) => {}
                        _ => return Err("channel closed before FIN"),
                    }
                }
            };
            let reason = tokio::select! {
                biased;
                _=stopping.cancelled()=>Some("carrier closed"),
                _=cancel.cancelled()=>Some("carrier cancelled"),
                _=tokio::time::sleep(lifetime)=>Some("carrier lifetime exceeded"),
                r=async {tokio::try_join!(send,receive)}=>r.err(),
            };
            if let Some(reason) = reason {
                if let Ok(mut state) = failure.lock() {
                    *state = Some(reason);
                }
                if let Ok(mut done) = failed_done.lock() {
                    if let Some(waker) = done.1.take() {
                        waker.wake();
                    }
                }
                // PeerConnection::close alone need not notify a remote idle
                // DataChannel promptly. Send an authenticated terminal error,
                // never FIN, before bounded transport cleanup. This is best
                // effort; its failure cannot turn a failed session into success.
                let _ = tokio::time::timeout(stall.min(Duration::from_secs(1)), async {
                    dc.send(BytesMut::from(&[2u8][..])).await.map_err(|_| ())?;
                    while dc.outstanding_bytes().await.map_err(|_| ())? > 0 {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                    Ok::<(), ()>(())
                })
                .await;
            } else {
                // rtc-sctp0.21 delays a final SACK for200ms. Both application
                // halves can finish before that timer runs. Retain the owned
                // driver for two ACK intervals plus a scheduling allowance;
                // immediate caller Drop must not discard the peer's final ACK.
                // This is bounded cleanup, not a promise for arbitrary RTT/loss.
                let remaining = expires.saturating_duration_since(tokio::time::Instant::now());
                tokio::time::sleep(remaining.min(Duration::from_millis(500))).await;
            }
            let _ = tokio::time::timeout(Duration::from_secs(1), dc.close()).await;
            if let Some(peer) = owner.0.as_ref() {
                let _ = tokio::time::timeout(Duration::from_secs(1), peer.close()).await;
            }
            // owner Drop supplies a second bounded cleanup only if close was cancelled.
        });
        Self {
            io,
            path,
            peer_ip,
            stop,
            failed,
            worker: Some(worker),
            sent,
            received_fin,
        }
    }
    fn failure(&self) -> Option<io::Error> {
        self.failed
            .lock()
            .ok()
            .and_then(|v| v.map(|s| io::Error::new(io::ErrorKind::ConnectionAborted, s)))
    }
}
impl Drop for WebRtcStream {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}
impl AsyncRead for WebRtcStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(e) = self.failure() {
            return Poll::Ready(Err(e));
        }
        let before = buf.filled().len();
        let capacity = buf.remaining();
        match Pin::new(&mut self.io).poll_read(cx, buf) {
            Poll::Ready(Ok(()))
                if capacity > 0
                    && buf.filled().len() == before
                    && !self.received_fin.load(Ordering::Acquire) =>
            {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "channel closed before FIN",
                )))
            }
            result => result,
        }
    }
}
impl AsyncWrite for WebRtcStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(e) = self.failure() {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(e) = self.failure() {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(e) = self.failure() {
            return Poll::Ready(Err(e));
        }
        match Pin::new(&mut self.io).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        let mut sent = match self.sent.lock() {
            Ok(sent) => sent,
            Err(_) => return Poll::Ready(Err(io::Error::other("carrier completion unavailable"))),
        };
        if sent.0 {
            Poll::Ready(Ok(()))
        } else {
            sent.1 = Some(cx.waker().clone());
            // Register before rechecking failure: a worker may have failed
            // between the first check and acquiring the completion lock.
            if let Some(e) = self.failure() {
                Poll::Ready(Err(e))
            } else {
                Poll::Pending
            }
        }
    }
}
