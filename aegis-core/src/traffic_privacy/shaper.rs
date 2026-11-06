//! Causal fixed-frame stream with finite memory, wire budget and lifetime.
//! Install inside authenticated encryption at both peers with identical settings.
use super::poisson::PoissonPacing;
use rand::{rngs::OsRng, RngCore};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    time::{timeout, timeout_at, Instant},
};

const END: u16 = u16::MAX;

#[derive(Clone, Debug)]
pub struct ShaperConfig {
    pub payload_bytes: usize,
    pub cadence: Duration,
    pub buffer_bytes: usize,
    /// Per-direction wire bytes, including headers, padding and the end frame.
    pub max_wire_bytes: u64,
    pub io_timeout: Duration,
    pub session_timeout: Duration,
    /// Conservative local queue residence allowance, not an Internet delay bound.
    pub max_queue_delay: Duration,
}

impl ShaperConfig {
    pub fn validate(&self) -> io::Result<()> {
        if !(1..=4096).contains(&self.payload_bytes)
            || !(self.payload_bytes..=1_048_576).contains(&self.buffer_bytes)
            || self.cadence < Duration::from_millis(1)
            || self.cadence > Duration::from_secs(1)
            || self.io_timeout.is_zero()
            || self.io_timeout > Duration::from_secs(30)
            || self.session_timeout.is_zero()
            || self.session_timeout > Duration::from_secs(3600)
            || self.max_wire_bytes < (self.payload_bytes + 2) as u64
        {
            return Err(invalid("invalid framing, memory, wire or lifetime budget"));
        }
        let frames = self.buffer_bytes.div_ceil(self.payload_bytes) + 1;
        let bound = self
            .cadence
            .checked_add(self.io_timeout)
            .and_then(|d| d.checked_mul(frames as u32))
            .ok_or_else(|| invalid("queue budget overflow"))?;
        if self.max_queue_delay < bound {
            return Err(invalid("queue allowance below conservative service bound"));
        }
        Ok(())
    }

    /// Payload service rate assuming a ready transport and full data frames.
    pub fn payload_bytes_per_second(&self) -> f64 {
        self.payload_bytes as f64 / self.cadence.as_secs_f64()
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "shaping deadline exceeded")
}

#[derive(Default, Clone, Debug, serde::Serialize)]
pub struct DirectionStats {
    pub data_bytes: u64,
    pub wire_bytes: u64,
    pub padding_bytes: u64,
    pub frames: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arrival_guard: Option<super::network_calculus_guard::Snapshot>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ShapingStats {
    pub sent: DirectionStats,
    pub received: DirectionStats,
}

/// The worker is owned by this stream. Dropping it aborts both directions.
/// `flush` means local bounded-buffer acceptance, not remote delivery.
pub struct ShapedStream {
    app: DuplexStream,
    worker: Option<super::worker_owner::SharedWorker<ShapingStats>>,
    completed: Option<ShapingStats>,
    received_end: Arc<AtomicBool>,
    sent_end: Arc<SendCompletion>,
    failure: Option<(io::ErrorKind, String)>,
}

#[derive(Default)]
struct SendCompletion {
    done: AtomicBool,
    waker: Mutex<Option<std::task::Waker>>,
}
impl SendCompletion {
    fn finish(&self) {
        self.done.store(true, Ordering::Release);
        if let Some(waker) = self.waker.lock().unwrap_or_else(|e| e.into_inner()).take() {
            waker.wake();
        }
    }
}

impl ShapedStream {
    fn check_worker(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if let Some(worker) = self.worker.as_mut() {
            if let Poll::Ready(result) = Pin::new(worker).poll(cx) {
                self.worker = None;
                let result =
                    result.unwrap_or_else(|_| Err(io::Error::other("shaping worker failed")));
                match result {
                    Ok(stats) => self.completed = Some(stats),
                    Err(error) => self.failure = Some((error.kind(), error.to_string())),
                }
            }
        }
        if let Some((kind, message)) = &self.failure {
            return Err(io::Error::new(*kind, message.clone()));
        }
        Ok(())
    }

    /// Half-close local input, then wait for both protocol directions to finish.
    /// Call after reading the peer to EOF; peer half-close is required.
    pub async fn finish(mut self) -> io::Result<ShapingStats> {
        self.app.shutdown().await?;
        if let Some((kind, message)) = self.failure.take() {
            return Err(io::Error::new(kind, message));
        }
        if let Some(stats) = self.completed.take() {
            return Ok(stats);
        }
        // Keep the handle owned across await: cancellation still aborts it.
        let result = self
            .worker
            .as_mut()
            .ok_or_else(|| io::Error::other("worker result already consumed"))?
            .await
            .map_err(|_| io::Error::other("shaping worker failed"));
        self.worker = None;
        result?
    }
}

impl Drop for ShapedStream {
    fn drop(&mut self) {
        if let Some(worker) = &self.worker {
            worker.abort();
        }
    }
}
impl AsyncRead for ShapedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Err(error) = self.check_worker(cx) {
            return Poll::Ready(Err(error));
        }
        // No application bytes were requested. Keep terminal worker errors
        // above observable, but do not wait on an empty idle duplex buffer.
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let before = buf.filled().len();
        match Pin::new(&mut self.app).poll_read(cx, buf) {
            Poll::Ready(Ok(()))
                if buf.remaining() != 0
                    && buf.filled().len() == before
                    && !self.received_end.load(Ordering::Acquire) =>
            {
                // A worker failure may close the local pipe before its join
                // result is visible. Never turn that failure into clean EOF.
                match self.check_worker(cx) {
                    Err(error) => Poll::Ready(Err(error)),
                    Ok(()) => Poll::Pending,
                }
            }
            result => result,
        }
    }
}
impl AsyncWrite for ShapedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Err(error) = self.check_worker(cx) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.app).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.check_worker(cx) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.app).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.check_worker(cx) {
            return Poll::Ready(Err(error));
        }
        match Pin::new(&mut self.app).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => {
                *self
                    .sent_end
                    .waker
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = Some(cx.waker().clone());
                if self.sent_end.done.load(Ordering::Acquire) {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            }
            result => result,
        }
    }
}

pub fn attach_framed<S>(transport: S, config: ShaperConfig) -> io::Result<ShapedStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    attach_with_pacing(transport, config, None, None, None, None)
}

/// Online alpha enforcement is independent of whether any network provides the
/// declared lower-service curve. Failure is terminal; no arrival debt is borrowed.
pub fn attach_regulated<S>(
    transport: S,
    config: ShaperConfig,
    envelope: Option<super::network_calculus_guard::Settings>,
) -> io::Result<ShapedStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    attach_regulated_with_deadline(transport, config, envelope, None, None)
}

/// Typed relay agreement owns this cutoff before its first control exchange.
pub(crate) fn attach_regulated_until<S>(
    transport: S,
    config: ShaperConfig,
    envelope: Option<super::network_calculus_guard::Settings>,
    deadline: Instant,
) -> io::Result<ShapedStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    attach_regulated_with_deadline(transport, config, envelope, Some(deadline), None)
}

pub(crate) fn attach_regulated_owned<S>(
    transport: S,
    config: ShaperConfig,
    envelope: Option<super::network_calculus_guard::Settings>,
    owner: Option<&super::worker_owner::ShapingCleanupOwner>,
) -> io::Result<ShapedStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match owner {
        Some(owner) => {
            attach_regulated_with_deadline(transport, config, envelope, None, Some(owner))
        }
        None => attach_regulated(transport, config, envelope),
    }
}

pub(crate) fn attach_regulated_until_owned<S>(
    transport: S,
    config: ShaperConfig,
    envelope: Option<super::network_calculus_guard::Settings>,
    deadline: Instant,
    owner: Option<&super::worker_owner::ShapingCleanupOwner>,
) -> io::Result<ShapedStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match owner {
        Some(owner) => {
            attach_regulated_with_deadline(transport, config, envelope, Some(deadline), Some(owner))
        }
        None => attach_regulated_until(transport, config, envelope, deadline),
    }
}

pub(crate) fn attach_poisson_owned<S>(
    transport: S,
    config: ShaperConfig,
    pacing: PoissonPacing,
    owner: Option<&super::worker_owner::ShapingCleanupOwner>,
) -> io::Result<ShapedStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match owner {
        Some(owner) => attach_poisson_with_deadline(transport, config, pacing, None, Some(owner)),
        None => attach_poisson(transport, config, pacing),
    }
}

pub(crate) fn attach_poisson_until_owned<S>(
    transport: S,
    config: ShaperConfig,
    pacing: PoissonPacing,
    deadline: Instant,
    owner: Option<&super::worker_owner::ShapingCleanupOwner>,
) -> io::Result<ShapedStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match owner {
        Some(owner) => {
            attach_poisson_with_deadline(transport, config, pacing, Some(deadline), Some(owner))
        }
        None => attach_poisson_until(transport, config, pacing, deadline),
    }
}

fn attach_regulated_with_deadline<S>(
    transport: S,
    config: ShaperConfig,
    envelope: Option<super::network_calculus_guard::Settings>,
    deadline: Option<Instant>,
    owner: Option<&super::worker_owner::ShapingCleanupOwner>,
) -> io::Result<ShapedStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if let Some(e) = &envelope {
        let period = config
            .cadence
            .checked_add(config.io_timeout)
            .ok_or_else(|| invalid("service period overflow"))?;
        e.validate_local_ceiling(
            config.payload_bytes as u64,
            period
                .as_nanos()
                .try_into()
                .map_err(|_| invalid("service period overflow"))?,
        )
        .map_err(io::Error::other)?;
    }
    attach_with_pacing(transport, config, None, envelope, deadline, owner)
}

/// Same authenticated fixed framing, FIFO, ownership and finite budgets as
/// attach_framed, with independent exponential pacing proposals. Tail admission
/// is terminal; this does not hide EOF, stalls or protocol/endpoint identity.
pub fn attach_poisson<S>(
    transport: S,
    config: ShaperConfig,
    pacing: PoissonPacing,
) -> io::Result<ShapedStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    attach_poisson_with_deadline(transport, config, pacing, None, None)
}

/// The agreement and worker scheduling consume the same original session cap.
pub(crate) fn attach_poisson_until<S>(
    transport: S,
    config: ShaperConfig,
    pacing: PoissonPacing,
    deadline: Instant,
) -> io::Result<ShapedStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    attach_poisson_with_deadline(transport, config, pacing, Some(deadline), None)
}

fn attach_poisson_with_deadline<S>(
    transport: S,
    config: ShaperConfig,
    pacing: PoissonPacing,
    deadline: Option<Instant>,
    owner: Option<&super::worker_owner::ShapingCleanupOwner>,
) -> io::Result<ShapedStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    pacing.validate()?;
    // The existing public cadence is the maximum receive/queue gap envelope.
    if config.cadence < pacing.max_gap() {
        return Err(invalid("receive envelope below maximum pacing gap"));
    }
    attach_with_pacing(transport, config, Some(pacing), None, deadline, owner)
}

fn attach_with_pacing<S>(
    transport: S,
    config: ShaperConfig,
    pacing: Option<PoissonPacing>,
    envelope: Option<super::network_calculus_guard::Settings>,
    deadline: Option<Instant>,
    owner: Option<&super::worker_owner::ShapingCleanupOwner>,
) -> io::Result<ShapedStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    config.validate()?;
    // Never enlarge either the caller's original cap or this local profile.
    let deadline = deadline.map(|end| end.min(Instant::now() + config.session_timeout));
    check_deadline(deadline)?;
    let (app, tunnel) = tokio::io::duplex(config.buffer_bytes);
    let received_end = Arc::new(AtomicBool::new(false));
    let worker_end = received_end.clone();
    let sent_end = Arc::new(SendCompletion::default());
    let worker_sent = sent_end.clone();
    let worker = super::worker_owner::spawn(owner, async move {
        // A queued worker can first run after the caller's cap has expired.
        // Refuse before polling either owned transport direction in that case.
        check_deadline(deadline)?;
        let (input, output) = tokio::io::split(tunnel);
        let (reader, writer) = tokio::io::split(transport);
        let lifetime = config.session_timeout;
        let operation = async {
            let sending = async {
                let result =
                    encode(input, writer, &config, pacing.as_ref(), envelope, deadline).await;
                if result.is_ok() {
                    worker_sent.finish();
                }
                result
            };
            let (sent, received) = tokio::try_join!(
                sending,
                decode(reader, output, &config, worker_end, deadline)
            )?;
            Ok(ShapingStats { sent, received })
        };
        match deadline {
            Some(end) => {
                let result = timeout_at(end, operation).await.map_err(|_| timed_out())?;
                // A synchronously ready final poll must not become late success.
                check_deadline(Some(end))?;
                result
            }
            // Standalone/opaque callers retain their previous worker lifetime.
            None => timeout(lifetime, operation)
                .await
                .map_err(|_| timed_out())?,
        }
    })?;
    Ok(ShapedStream {
        app,
        worker: Some(worker),
        completed: None,
        received_end,
        sent_end,
        failure: None,
    })
}

fn check_deadline(deadline: Option<Instant>) -> io::Result<()> {
    if deadline.is_some_and(|end| Instant::now() >= end) {
        return Err(timed_out());
    }
    Ok(())
}

fn account(stats: &mut DirectionStats, config: &ShaperConfig, count: usize) -> io::Result<()> {
    let next = stats
        .wire_bytes
        .checked_add((config.payload_bytes + 2) as u64)
        .ok_or_else(|| invalid("wire budget overflow"))?;
    if next > config.max_wire_bytes {
        return Err(io::Error::other("shaping wire budget exhausted"));
    }
    stats.wire_bytes = next;
    stats.data_bytes += count as u64;
    stats.padding_bytes += (config.payload_bytes - count) as u64;
    stats.frames += 1;
    Ok(())
}

fn next_gap(config: &ShaperConfig, pacing: Option<&PoissonPacing>) -> io::Result<Duration> {
    match pacing {
        Some(p) => p.next_gap(&mut OsRng),
        None => Ok(config.cadence),
    }
}

async fn wait_for_frame_tick(next: Instant) {
    // A fresh elapsed Tokio timer can still yield or round forward. Keep the
    // original target and the deadline checks at the caller.
    if Instant::now() < next {
        tokio::time::sleep_until(next).await;
    }
}

async fn encode<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut input: R,
    mut wire: W,
    config: &ShaperConfig,
    pacing: Option<&PoissonPacing>,
    envelope: Option<super::network_calculus_guard::Settings>,
    deadline: Option<Instant>,
) -> io::Result<DirectionStats> {
    let mut stats = DirectionStats::default();
    let mut payload = vec![0; config.payload_bytes];
    let mut frame = vec![0; config.payload_bytes + 2];
    let mut eof = false;
    let mut count = 0;
    let started = Instant::now();
    let mut guard = envelope
        .map(|e| super::network_calculus_guard::ArrivalGuard::new(e, 0))
        .transpose()
        .map_err(io::Error::other)?;
    // Start only after one full cadence. Missed slots never produce catch-up bursts.
    let mut next = Instant::now() + next_gap(config, pacing)?;
    loop {
        while count < payload.len() && !eof {
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(next) => break,
                read = input.read(&mut payload[count..]) => {
                    let n = read?;
                    if n > 0 {
                        if let Some(guard) = &mut guard {
                            let now_ns = started.elapsed().as_nanos().try_into()
                                .map_err(|_| invalid("arrival clock overflow"))?;
                            guard.admit(now_ns, n as u64).map_err(io::Error::other)?;
                        }
                    }
                    eof = n == 0;
                    count += n;
                }
            }
        }
        wait_for_frame_tick(next).await;
        check_deadline(deadline)?;
        OsRng
            .try_fill_bytes(&mut frame)
            .map_err(|_| io::Error::other("padding entropy unavailable"))?;
        check_deadline(deadline)?;
        let length = if eof && count == 0 { END } else { count as u16 };
        frame[..2].copy_from_slice(&length.to_be_bytes());
        frame[2..2 + count].copy_from_slice(&payload[..count]);
        account(&mut stats, config, count)?;
        let emitted = timeout(config.io_timeout, async {
            wire.write_all(&frame).await?;
            wire.flush().await
        })
        .await
        .map_err(|_| timed_out())
        .and_then(|r| r);
        if let Err(error) = emitted {
            if let Some(guard) = &mut guard {
                guard.service_failed();
            }
            return Err(error);
        }
        check_deadline(deadline)?;
        if length == END {
            timeout(config.io_timeout, wire.shutdown())
                .await
                .map_err(|_| timed_out())??;
            stats.arrival_guard = guard
                .map(|g| g.snapshot())
                .transpose()
                .map_err(io::Error::other)?;
            return Ok(stats);
        }
        count = 0;
        next = Instant::now() + next_gap(config, pacing)?;
    }
}

async fn decode<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut wire: R,
    mut output: W,
    config: &ShaperConfig,
    received_end: Arc<AtomicBool>,
    deadline: Option<Instant>,
) -> io::Result<DirectionStats> {
    let mut stats = DirectionStats::default();
    let mut frame = vec![0; config.payload_bytes + 2];
    loop {
        check_deadline(deadline)?;
        if stats.wire_bytes > config.max_wire_bytes - (config.payload_bytes + 2) as u64 {
            return Err(io::Error::other("shaping wire budget exhausted"));
        }
        timeout(
            // The peer may still be flushing the previous complete frame for
            // one I/O budget, then wait a cadence and write this frame within
            // a second budget. Keep both bounded phases in the receive limit.
            config.io_timeout * 2 + config.cadence,
            wire.read_exact(&mut frame),
        )
        .await
        .map_err(|_| timed_out())??;
        check_deadline(deadline)?;
        let length = u16::from_be_bytes([frame[0], frame[1]]);
        let count = if length == END {
            0
        } else {
            usize::from(length)
        };
        if count > config.payload_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "oversized shaping frame",
            ));
        }
        account(&mut stats, config, count)?;
        if length == END {
            received_end.store(true, Ordering::Release);
            output.shutdown().await?;
            return Ok(stats);
        }
        timeout(config.io_timeout, output.write_all(&frame[2..2 + count]))
            .await
            .map_err(|_| timed_out())??;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn regulated_pair_keeps_fifo_halfclose_and_conditional_receipt() {
        // In-memory FIFO/half-close semantics use deterministic timer ticks;
        // native wall-clock service remains explicitly unverified.
        let (a, b) = tokio::io::duplex(4096);
        let mut cfg = config();
        cfg.cadence = Duration::from_millis(1);
        cfg.io_timeout = Duration::from_millis(5);
        let envelope = super::super::network_calculus_guard::Settings {
            burst_bytes: 16,
            arrival_rate_bytes_per_second: 0,
            service_rate_bytes_per_second: 1000,
            service_latency_ns: 10_000_000,
        };
        let mut a = attach_regulated(a, cfg.clone(), Some(envelope.clone())).unwrap();
        let mut b = attach_regulated(b, cfg, Some(envelope)).unwrap();
        let (sa, sb) = tokio::join!(
            async {
                a.write_all(b"request").await.unwrap();
                a.shutdown().await.unwrap();
                let mut reply = Vec::new();
                a.read_to_end(&mut reply).await.unwrap();
                assert_eq!(reply, b"response");
                a.finish().await.unwrap()
            },
            async {
                let mut request = Vec::new();
                b.read_to_end(&mut request).await.unwrap();
                assert_eq!(request, b"request");
                b.write_all(b"response").await.unwrap();
                b.shutdown().await.unwrap();
                b.finish().await.unwrap()
            }
        );
        for (stats, expected) in [(sa, 7), (sb, 8)] {
            let guard = stats.sent.arrival_guard.unwrap();
            assert_eq!(guard.cumulative_admitted_bytes, expected);
            assert!(!guard.service_premise_invalidated);
            assert!(
                !guard
                    .conditional_bounds
                    .unwrap()
                    .guaranteed_service_verified
            );
        }
    }
    #[tokio::test]
    async fn regulated_worker_refuses_overburst_before_first_wire_frame() {
        let (wire, mut observer) = tokio::io::duplex(1024);
        let mut cfg = poisson_config();
        cfg.cadence = Duration::from_millis(1);
        cfg.io_timeout = Duration::from_millis(5);
        let envelope = super::super::network_calculus_guard::Settings {
            burst_bytes: 4,
            arrival_rate_bytes_per_second: 0,
            service_rate_bytes_per_second: 1000,
            service_latency_ns: 10_000_000,
        };
        let mut stream = attach_regulated(wire, cfg, Some(envelope)).unwrap();
        stream.write_all(b"too-many-bytes").await.unwrap();
        assert!(stream.finish().await.is_err());
        let mut received = Vec::new();
        observer.read_to_end(&mut received).await.unwrap();
        assert!(received.is_empty());
    }
    fn config() -> ShaperConfig {
        ShaperConfig {
            payload_bytes: 32,
            cadence: Duration::from_millis(2),
            buffer_bytes: 64,
            max_wire_bytes: 100_000,
            io_timeout: Duration::from_secs(1),
            session_timeout: Duration::from_secs(5),
            max_queue_delay: Duration::from_secs(4),
        }
    }
    fn poisson_config() -> ShaperConfig {
        ShaperConfig {
            cadence: Duration::from_secs(1),
            max_queue_delay: Duration::from_secs(20),
            ..config()
        }
    }
    fn pacing() -> PoissonPacing {
        PoissonPacing {
            mean_interval_us: 1_000,
            max_gap_us: 1_000_000,
        }
    }
    #[tokio::test]
    async fn poisson_real_tcp_preserves_fifo_and_bidirectional_half_close() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (b, _) = listener.accept().await.unwrap();
        drop(listener);
        // Mechanism fixture: public profile is pre-agreed, TLS assumed here;
        // authenticated relay agreement is independently exercised below.
        let mut a = attach_poisson(a, poisson_config(), pacing()).unwrap();
        let mut b = attach_poisson(b, poisson_config(), pacing()).unwrap();
        let expected: Vec<u8> = (0..97).cycle().take(513).collect();
        let outgoing = expected.clone();
        let send = tokio::spawn(async move {
            for c in outgoing.chunks(7) {
                a.write_all(c).await.unwrap();
            }
            a.shutdown().await.unwrap();
            let mut response = Vec::new();
            a.read_to_end(&mut response).await.unwrap();
            (response, a.finish().await.unwrap())
        });
        let mut input = Vec::new();
        b.read_to_end(&mut input).await.unwrap();
        assert_eq!(input, expected);
        b.write_all(&input).await.unwrap();
        b.shutdown().await.unwrap();
        let stats = b.finish().await.unwrap();
        let (response, sender) = send.await.unwrap();
        assert_eq!(response, expected);
        assert_eq!(stats.received.data_bytes, 513);
        assert_eq!(sender.sent.wire_bytes, sender.sent.frames * 34);
    }
    #[tokio::test]
    async fn poisson_wire_exhaustion_is_error_and_not_clean_eof() {
        let (a, b) = tokio::io::duplex(256);
        let mut cfg = poisson_config();
        cfg.max_wire_bytes = 34;
        let mut a = attach_poisson(a, cfg, pacing()).unwrap();
        let mut b = attach_poisson(b, poisson_config(), pacing()).unwrap();
        a.write_all(&[7; 64]).await.unwrap();
        let mut result = Vec::new();
        assert!(b.read_to_end(&mut result).await.is_err());
        // Each direction has its own finite budget. Independent peer cover
        // may exhaust the receive leg first; terminal worker errors may also
        // become visible before the application drains buffered data. Accepted
        // writes do not promise delivered bytes on this failure path.
        assert!(result.len() <= 32);
        assert!(result.iter().all(|b| *b == 7));
        assert!(a.finish().await.is_err());
    }
    #[tokio::test(start_paused = true)]
    async fn poisson_raw_wire_exhaustion_writes_one_queued_frame_then_owned_eof() {
        let (a, mut peer) = tokio::io::duplex(256);
        let mut cfg = poisson_config();
        cfg.max_wire_bytes = 34;
        let mut a = attach_poisson(a, cfg, pacing()).unwrap();
        a.write_all(&[7; 64]).await.unwrap();
        // Paused Tokio time admits already-queued input before a strictly
        // positive first proposal. This controls test scheduling only, not
        // production timing or a native-clock/capture claim.
        let mut frame = [0; 34];
        timeout(Duration::from_secs(1), peer.read_exact(&mut frame))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&frame[..2], &32u16.to_be_bytes());
        assert_eq!(&frame[2..], &[7; 32]);
        let mut beyond_budget = Vec::new();
        timeout(Duration::from_secs(1), peer.read_to_end(&mut beyond_budget))
            .await
            .unwrap()
            .unwrap();
        assert!(beyond_budget.is_empty());
        assert!(a.finish().await.is_err());
    }
    #[tokio::test]
    async fn poisson_drop_aborts_owned_worker_but_not_spectator() {
        let (wire, mut peer) = tokio::io::duplex(256);
        let mut owned = attach_poisson(wire, poisson_config(), pacing()).unwrap();
        owned.write_all(b"queued").await.unwrap();
        drop(owned);
        let mut bytes = Vec::new();
        timeout(Duration::from_secs(1), peer.read_to_end(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        let (mut other, mut spectator) = tokio::io::duplex(32);
        other.write_all(b"still-alive").await.unwrap();
        let mut seen = [0; 11];
        spectator.read_exact(&mut seen).await.unwrap();
        assert_eq!(&seen, b"still-alive");
    }
    #[test]
    fn poisson_preflight_rejects_insufficient_gap_or_queue_envelope() {
        let cfg = config();
        let (a, _b) = tokio::io::duplex(128);
        assert!(attach_poisson(a, cfg, pacing()).is_err());
        let mut cfg = poisson_config();
        cfg.max_queue_delay = Duration::from_secs(1);
        let (a, _b) = tokio::io::duplex(128);
        assert!(attach_poisson(a, cfg, pacing()).is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn empty_read_on_idle_stream_needs_no_peer_traffic() {
        let (local, _idle_peer) = tokio::io::duplex(128);
        let mut shaped = attach_framed(local, config()).unwrap();
        let started = Instant::now();
        assert_eq!(
            timeout(Duration::from_millis(1), shaped.read(&mut []))
                .await
                .expect("an empty read must not wait for traffic or authenticated END")
                .unwrap(),
            0
        );
        assert_eq!(started.elapsed(), Duration::ZERO);
        assert!(!shaped.received_end.load(Ordering::Acquire));
    }
    #[tokio::test]
    async fn actual_duplex_preserves_fragmented_bytes_and_half_closes() {
        let (a, b) = tokio::io::duplex(128);
        let mut a = attach_framed(a, config()).unwrap();
        let mut b = attach_framed(b, config()).unwrap();
        let payload: Vec<u8> = (0..251).cycle().take(1027).collect();
        let expected = payload.clone();
        let sender = tokio::spawn(async move {
            for chunk in payload.chunks(7) {
                a.write_all(chunk).await.unwrap();
            }
            a.shutdown().await.unwrap();
            let mut echo = Vec::new();
            a.read_to_end(&mut echo).await.unwrap();
            (echo, a.finish().await.unwrap())
        });
        let mut got = Vec::new();
        b.read_to_end(&mut got).await.unwrap();
        b.write_all(&got).await.unwrap();
        b.shutdown().await.unwrap();
        let stats = b.finish().await.unwrap();
        let (echo, sent) = sender.await.unwrap();
        assert_eq!(got, expected);
        assert_eq!(echo, expected);
        assert_eq!(stats.received.data_bytes, expected.len() as u64);
        assert_eq!(sent.sent.data_bytes, expected.len() as u64);
        assert_eq!(sent.sent.wire_bytes, sent.sent.frames * 34);
    }
    #[tokio::test]
    async fn invalid_header_is_error_not_eof() {
        let (local, mut peer) = tokio::io::duplex(128);
        let mut shaped = attach_framed(local, config()).unwrap();
        let mut frame = vec![0; 34];
        frame[..2].copy_from_slice(&33_u16.to_be_bytes());
        peer.write_all(&frame).await.unwrap();
        assert!(shaped.read_u8().await.is_err());
        assert!(shaped.read(&mut []).await.is_err());
    }
    #[tokio::test]
    async fn finite_budget_stops_idle_padding_with_error() {
        let (local, mut peer) = tokio::io::duplex(128);
        let mut cfg = config();
        cfg.max_wire_bytes = 34;
        let mut shaped = attach_framed(local, cfg).unwrap();
        let mut frame = vec![0; 34];
        peer.read_exact(&mut frame).await.unwrap();
        assert_eq!(&frame[..2], &[0, 0]);
        assert!(timeout(Duration::from_secs(1), shaped.read_u8())
            .await
            .unwrap()
            .is_err());
    }
    #[test]
    fn queue_budget_is_checked() {
        let mut cfg = config();
        cfg.max_queue_delay = Duration::ZERO;
        assert!(cfg.validate().is_err());
    }
    #[tokio::test(start_paused = true)]
    async fn actual_frame_waits_for_cadence_and_idle_frames_are_fixed_size() {
        let (local, mut peer) = tokio::io::duplex(128);
        let mut shaped = attach_framed(local, config()).unwrap();
        shaped.write_all(b"payload").await.unwrap();
        tokio::task::yield_now().await;
        let mut frame = vec![0; 34];
        assert!(
            timeout(Duration::from_millis(1), peer.read_exact(&mut frame))
                .await
                .is_err()
        );
        peer.read_exact(&mut frame).await.unwrap();
        assert_eq!(&frame[..2], &7_u16.to_be_bytes());
        assert_eq!(&frame[2..9], b"payload");
        peer.read_exact(&mut frame).await.unwrap();
        assert_eq!(&frame[..2], &[0, 0]);
    }
    #[tokio::test(start_paused = true)]
    async fn honest_prior_flush_and_next_write_each_may_use_their_io_budget() {
        // A received frame may already be complete while the sender is still
        // flushing it. The next frame may itself take nearly one I/O budget.
        // Those are two separately valid sender operations, not one stall.
        struct DelayedWriter {
            inner: DuplexStream,
            completed_flushes: usize,
            delay: Option<Pin<Box<tokio::time::Sleep>>>,
            delayed_next_write: bool,
        }
        impl AsyncWrite for DelayedWriter {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                if self.completed_flushes == 1 && !self.delayed_next_write {
                    let delay = self.delay.get_or_insert_with(|| {
                        Box::pin(tokio::time::sleep(Duration::from_millis(750)))
                    });
                    if delay.as_mut().poll(cx).is_pending() {
                        return Poll::Pending;
                    }
                    self.delay = None;
                    self.delayed_next_write = true;
                }
                Pin::new(&mut self.inner).poll_write(cx, buf)
            }
            fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                if self.completed_flushes == 0 {
                    let delay = self.delay.get_or_insert_with(|| {
                        Box::pin(tokio::time::sleep(Duration::from_millis(750)))
                    });
                    if delay.as_mut().poll(cx).is_pending() {
                        return Poll::Pending;
                    }
                    self.delay = None;
                }
                match Pin::new(&mut self.inner).poll_flush(cx) {
                    Poll::Ready(Ok(())) => {
                        self.completed_flushes += 1;
                        Poll::Ready(Ok(()))
                    }
                    result => result,
                }
            }
            fn poll_shutdown(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut self.inner).poll_shutdown(cx)
            }
        }
        let (writer, reader) = tokio::io::duplex(128);
        let writer = DelayedWriter {
            inner: writer,
            completed_flushes: 0,
            delay: None,
            delayed_next_write: false,
        };
        let cfg = config();
        let received_end = Arc::new(AtomicBool::new(false));
        let (sent, received) = tokio::join!(
            encode(&b"x"[..], writer, &cfg, None, None, None),
            decode(reader, tokio::io::sink(), &cfg, received_end.clone(), None),
        );
        let received = received.unwrap();
        let sent = sent.unwrap();
        assert_eq!(sent.frames, 2);
        assert_eq!(received.frames, 2);
        assert_eq!(received.data_bytes, 1);
        assert!(received_end.load(Ordering::Acquire));
    }
    #[tokio::test(start_paused = true)]
    async fn missing_peer_frame_still_expires_at_the_bounded_receive_deadline() {
        let (_peer, reader) = tokio::io::duplex(128);
        let cfg = config();
        let start = Instant::now();
        let error = decode(
            reader,
            tokio::io::sink(),
            &cfg,
            Arc::new(AtomicBool::new(false)),
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(start.elapsed(), cfg.cadence + cfg.io_timeout * 2);
    }

    #[tokio::test(start_paused = true)]
    async fn delayed_worker_cannot_poll_transport_after_original_session_cutoff() {
        use std::sync::atomic::AtomicUsize;
        struct Watched {
            inner: DuplexStream,
            polls: Arc<AtomicUsize>,
            dropped: Arc<AtomicBool>,
        }
        impl Drop for Watched {
            fn drop(&mut self) {
                self.dropped.store(true, Ordering::Release);
            }
        }
        impl AsyncRead for Watched {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                self.polls.fetch_add(1, Ordering::Relaxed);
                Pin::new(&mut self.inner).poll_read(cx, buf)
            }
        }
        impl AsyncWrite for Watched {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                self.polls.fetch_add(1, Ordering::Relaxed);
                Pin::new(&mut self.inner).poll_write(cx, buf)
            }
            fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                self.polls.fetch_add(1, Ordering::Relaxed);
                Pin::new(&mut self.inner).poll_flush(cx)
            }
            fn poll_shutdown(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<io::Result<()>> {
                self.polls.fetch_add(1, Ordering::Relaxed);
                Pin::new(&mut self.inner).poll_shutdown(cx)
            }
        }
        for poisson in [false, true] {
            for already_expired in [false, true] {
                let polls = Arc::new(AtomicUsize::new(0));
                let dropped = Arc::new(AtomicBool::new(false));
                let (inner, _peer) = tokio::io::duplex(128);
                let wire = Watched {
                    inner,
                    polls: polls.clone(),
                    dropped: dropped.clone(),
                };
                let origin = Instant::now();
                let end = origin + Duration::from_millis(if already_expired { 0 } else { 5 });
                let stream = if poisson {
                    attach_poisson_until(wire, poisson_config(), pacing(), end)
                } else {
                    attach_regulated_until(wire, config(), None, end)
                };
                let error = if already_expired {
                    stream
                        .err()
                        .expect("expired admission must not create a worker")
                } else {
                    let mut stream = stream.unwrap();
                    // advance updates the clock before yielding to the queued worker.
                    tokio::time::advance(Duration::from_millis(6)).await;
                    stream.read_u8().await.unwrap_err()
                };
                assert_eq!(error.kind(), io::ErrorKind::TimedOut);
                assert_eq!(polls.load(Ordering::Relaxed), 0);
                assert!(dropped.load(Ordering::Acquire));
            }
        }
    }
    #[tokio::test]
    async fn cancelling_finish_aborts_owned_transport() {
        struct Watched {
            inner: DuplexStream,
            dropped: Arc<AtomicBool>,
        }
        impl Drop for Watched {
            fn drop(&mut self) {
                self.dropped.store(true, Ordering::Release);
            }
        }
        impl AsyncRead for Watched {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut self.inner).poll_read(cx, buf)
            }
        }
        impl AsyncWrite for Watched {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Pin::new(&mut self.inner).poll_write(cx, buf)
            }
            fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.inner).poll_flush(cx)
            }
            fn poll_shutdown(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut self.inner).poll_shutdown(cx)
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let (local, _peer) = tokio::io::duplex(128);
        let shaped = attach_framed(
            Watched {
                inner: local,
                dropped: dropped.clone(),
            },
            config(),
        )
        .unwrap();
        let finishing = tokio::spawn(shaped.finish());
        tokio::task::yield_now().await;
        finishing.abort();
        let _ = finishing.await;
        timeout(Duration::from_secs(1), async {
            while !dropped.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn stalled_transport_backpressures_and_expires_with_error() {
        let (local, _peer) = tokio::io::duplex(1);
        let mut cfg = config();
        cfg.io_timeout = Duration::from_millis(30);
        let mut shaped = attach_framed(local, cfg).unwrap();
        assert!(
            timeout(Duration::from_millis(10), shaped.write_all(&vec![7; 4096]))
                .await
                .is_err()
        );
        let error = timeout(Duration::from_secs(1), shaped.read_u8())
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
    #[tokio::test]
    async fn shutdown_preserves_failure_ack_before_immediate_drop() {
        let (local, mut peer) = tokio::io::duplex(128);
        let mut shaped = attach_framed(local, config()).unwrap();
        shaped.write_all(&[1]).await.unwrap();
        shaped.flush().await.unwrap();
        shaped.shutdown().await.unwrap();
        drop(shaped);
        let mut frame = vec![0; 34];
        peer.read_exact(&mut frame).await.unwrap();
        assert_eq!(&frame[..3], &[0, 1, 1]);
        peer.read_exact(&mut frame).await.unwrap();
        assert_eq!(&frame[..2], &END.to_be_bytes());
    }

    #[tokio::test(start_paused = true)]
    async fn elapsed_submillisecond_frame_tick_never_reenters_timer() {
        let next = Instant::now() + Duration::from_micros(800);
        tokio::time::advance(Duration::from_micros(900)).await;
        let before = Instant::now();
        assert!(before > next);
        wait_for_frame_tick(next).await;
        assert_eq!(
            Instant::now(),
            before,
            "an elapsed frame tick must not register or await another timer"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn future_frame_tick_still_waits_without_early_release() {
        let before = Instant::now();
        let next = before + Duration::from_micros(800);
        wait_for_frame_tick(next).await;
        assert!(Instant::now() >= next);
        assert!(Instant::now() > before);
    }

    struct PendingForFrameDeadline {
        entered: Arc<tokio::sync::Notify>,
    }
    impl AsyncRead for PendingForFrameDeadline {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.entered.notify_one();
            Poll::Pending
        }
    }

    #[tokio::test(start_paused = true)]
    async fn elapsed_frame_wait_never_revives_original_encode_deadline() {
        let cfg = config();
        let entered = Arc::new(tokio::sync::Notify::new());
        let input = PendingForFrameDeadline {
            entered: entered.clone(),
        };
        let (wire, mut peer) = tokio::io::duplex(128);
        let end = Instant::now() + Duration::from_micros(1500);
        let (result, ()) = tokio::join!(encode(input, wire, &cfg, None, None, Some(end)), async {
            entered.notified().await;
            tokio::time::advance(Duration::from_millis(3)).await;
        });
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        let mut bytes = Vec::new();
        peer.read_to_end(&mut bytes).await.unwrap();
        assert!(
            bytes.is_empty(),
            "the original encode deadline permits no wire frame"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn delayed_frame_completion_rebases_next_cadence_without_catchup() {
        struct DelayedFirstFlush {
            inner: DuplexStream,
            writes: Arc<Mutex<Vec<Instant>>>,
            first_completed: Arc<Mutex<Option<Instant>>>,
            delay: Option<Pin<Box<tokio::time::Sleep>>>,
        }
        impl AsyncWrite for DelayedFirstFlush {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                bytes: &[u8],
            ) -> Poll<io::Result<usize>> {
                let result = Pin::new(&mut self.inner).poll_write(cx, bytes);
                if matches!(result, Poll::Ready(Ok(n)) if n > 0) {
                    self.writes.lock().unwrap().push(Instant::now());
                }
                result
            }
            fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                if self.first_completed.lock().unwrap().is_none() {
                    let delay = self.delay.get_or_insert_with(|| {
                        Box::pin(tokio::time::sleep(Duration::from_millis(10)))
                    });
                    if delay.as_mut().poll(cx).is_pending() {
                        return Poll::Pending;
                    }
                    self.delay = None;
                    match Pin::new(&mut self.inner).poll_flush(cx) {
                        Poll::Ready(Ok(())) => {
                            *self.first_completed.lock().unwrap() = Some(Instant::now());
                            Poll::Ready(Ok(()))
                        }
                        result => result,
                    }
                } else {
                    Pin::new(&mut self.inner).poll_flush(cx)
                }
            }
            fn poll_shutdown(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut self.inner).poll_shutdown(cx)
            }
        }
        let cfg = config();
        let writes = Arc::new(Mutex::new(Vec::new()));
        let first_completed = Arc::new(Mutex::new(None));
        let (inner, mut peer) = tokio::io::duplex(128);
        let wire = DelayedFirstFlush {
            inner,
            writes: writes.clone(),
            first_completed: first_completed.clone(),
            delay: None,
        };
        let end = Instant::now() + Duration::from_secs(1);
        let result = encode(&b"x"[..], wire, &cfg, None, None, Some(end))
            .await
            .unwrap();
        assert_eq!(result.frames, 2);
        {
            let recorded = writes.lock().unwrap();
            assert_eq!(recorded.len(), 2);
            let completed = first_completed.lock().unwrap().unwrap();
            assert!(
                recorded[1] >= completed + cfg.cadence,
                "next frame is based on actual completion, never the missed nominal slot"
            );
        }
        let mut actual = Vec::new();
        peer.read_to_end(&mut actual).await.unwrap();
        assert_eq!(actual.len(), 68);
        assert_eq!(&actual[..3], &[0, 1, b'x']);
        assert_eq!(&actual[34..36], &END.to_be_bytes());
    }
}
