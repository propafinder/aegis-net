//! Bounded causal iMEC records inside a separately authenticated TLS session.
use super::cover_control::{ControlRecord, CoverModel, OneTimeMaterial};
use super::shaper::{DirectionStats, ShapingStats};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    time::{timeout_at, Instant},
};
use zeroize::Zeroizing;

/// All fields are public negotiated parameters. Capacity includes the encrypted
/// DATA/END discriminator; every outer record has exactly horizon*token_width bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverStreamSettings {
    pub tokens: Vec<Vec<u8>>,
    pub weights: Vec<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_conditional"
    )]
    pub conditional_model: Option<super::general_coupling::ConditionalCoverSettings>,
    pub capacity: usize,
    pub horizon: usize,
    pub max_records: u64,
    pub buffer_bytes: usize,
    pub max_wire_bytes: u64,
    pub io_timeout_ms: u32,
    pub session_timeout_ms: u32,
}
fn present_conditional<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<super::general_coupling::ConditionalCoverSettings>, D::Error> {
    super::general_coupling::ConditionalCoverSettings::deserialize(d).map(Some)
}
impl CoverStreamSettings {
    pub fn payload_bytes(&self) -> usize {
        self.capacity.saturating_sub(1)
    }
    fn model(&self) -> io::Result<CoverModel> {
        if let Some(model) = &self.conditional_model {
            model.validate(self.tokens.len())?;
            if self.weights != model.state_weights[model.initial_state] {
                return Err(invalid("conditional initial cover weights differ"));
            }
            return CoverModel::new_general_conditional(
                self.tokens.clone(),
                model.clone(),
                self.capacity,
                self.horizon,
                Duration::from_millis(u64::from(self.io_timeout_ms)),
            );
        }
        CoverModel::new_general(
            self.tokens.clone(),
            self.weights.clone(),
            self.capacity,
            self.horizon,
            Duration::from_millis(u64::from(self.io_timeout_ms)),
        )
    }
    pub fn wire_bytes(&self) -> io::Result<usize> {
        Ok(self.model()?.wire_bytes())
    }
    pub fn validate(&self) -> io::Result<()> {
        if !(2..=256).contains(&self.capacity)
            || !(1..=4096).contains(&self.horizon)
            || !(2..=65536).contains(&self.max_records)
            || !(self.payload_bytes()..=1048576).contains(&self.buffer_bytes)
            || !(1..=30000).contains(&self.io_timeout_ms)
            || !(1..=3600000).contains(&self.session_timeout_ms)
            || self.max_wire_bytes > 1073741824
        {
            return Err(invalid("invalid cover stream budgets"));
        }
        // Explicit finite per-record construction work domain; no unbounded alphabet/horizon.
        if self
            .capacity
            .checked_mul(self.horizon)
            .and_then(|v| v.checked_mul(self.tokens.len()))
            .is_none_or(|v| v > 1048576)
        {
            return Err(invalid("cover stream construction budget exceeded"));
        }
        let wire = self.model()?.wire_bytes() as u64;
        if self
            .max_records
            .checked_mul(wire)
            .is_none_or(|v| v > self.max_wire_bytes)
        {
            return Err(invalid(
                "cover stream wire budget below full public record allowance",
            ));
        }
        Ok(())
    }
    pub fn descriptor(&self) -> io::Result<[u8; 32]> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"aegis.cover-stream.imec.hkdf.v1");
        hash.update(self.model()?.descriptor_sha256());
        for value in [
            self.capacity as u64,
            self.horizon as u64,
            self.max_records,
            self.buffer_bytes as u64,
            self.max_wire_bytes,
            u64::from(self.io_timeout_ms),
            u64::from(self.session_timeout_ms),
        ] {
            hash.update(value.to_be_bytes());
        }
        Ok(hash.finalize().into())
    }
}

/// Fresh authenticated-session contribution. Never Clone/Debug or persisted.
/// Caller must derive fresh matching per-direction seeds AFTER typed agreement;
/// no resumption/restart reuse. This is computational PRF material, not ideal OTP.
pub struct CoverStreamMaterial {
    seed: Zeroizing<[u8; 32]>,
    direction: u8,
}
impl CoverStreamMaterial {
    pub fn new(seed: Zeroizing<[u8; 32]>, direction: u8) -> io::Result<Self> {
        if direction > 1 {
            return Err(invalid("invalid cover stream direction"));
        }
        Ok(Self { seed, direction })
    }
    fn record(
        &self,
        model: &CoverModel,
        profile: &[u8; 32],
        ordinal: u64,
    ) -> io::Result<ControlRecord> {
        let kdf = Hkdf::<Sha256>::new(Some(profile), self.seed.as_ref());
        let mut context = b"aegis.cover-stream.frame.v1".to_vec();
        context.push(self.direction);
        context.extend_from_slice(&ordinal.to_be_bytes());
        let mut material = Zeroizing::new(vec![0u8; 44 + model.pad_bytes()]);
        kdf.expand(&context, material.as_mut())
            .map_err(|_| invalid("cover stream derivation refused"))?;
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&material[..32]);
        let mut nonce = Zeroizing::new([0u8; 12]);
        nonce.copy_from_slice(&material[32..44]);
        let pad = Zeroizing::new(material[44..].to_vec());
        // The transient nonce is public AEAD material; all secret derivation buffers drop zeroized.
        ControlRecord::new(
            model.clone(),
            OneTimeMaterial::from_preprovisioned(key, *nonce, pad)?,
        )
    }
}
#[derive(Default)]
struct Completion {
    done: AtomicBool,
    waker: Mutex<Option<std::task::Waker>>,
}
impl Completion {
    fn finish(&self) {
        self.done.store(true, Ordering::Release);
        if let Some(w) = self.waker.lock().unwrap_or_else(|e| e.into_inner()).take() {
            w.wake();
        }
    }
}

/// Dropping this owner aborts BOTH directions. No detached stream worker.
pub struct CoverStream {
    app: DuplexStream,
    worker: Option<super::worker_owner::SharedWorker<ShapingStats>>,
    completed: Option<ShapingStats>,
    received_end: Arc<Completion>,
    sent_end: Arc<Completion>,
    failure: Option<(io::ErrorKind, String)>,
}
impl Drop for CoverStream {
    fn drop(&mut self) {
        if let Some(w) = &self.worker {
            w.abort();
        }
    }
}
impl CoverStream {
    fn check(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if let Some(w) = self.worker.as_mut() {
            if let Poll::Ready(result) = Pin::new(w).poll(cx) {
                self.worker = None;
                match result.unwrap_or_else(|_| Err(io::Error::other("cover stream worker failed")))
                {
                    Ok(stats) => self.completed = Some(stats),
                    Err(e) => self.failure = Some((e.kind(), e.to_string())),
                }
            }
        }
        if let Some((kind, message)) = &self.failure {
            return Err(io::Error::new(*kind, message.clone()));
        }
        Ok(())
    }
    pub async fn finish(mut self) -> io::Result<ShapingStats> {
        self.app.shutdown().await?;
        if let Some((kind, message)) = &self.failure {
            return Err(io::Error::new(*kind, message.clone()));
        }
        if let Some(stats) = self.completed.take() {
            return Ok(stats);
        }
        let result = self
            .worker
            .as_mut()
            .ok_or_else(|| io::Error::other("cover stream result already consumed"))?
            .await
            .map_err(|_| io::Error::other("cover stream worker failed"));
        self.worker = None;
        result?
    }
}
impl AsyncRead for CoverStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Err(e) = self.check(cx) {
            return Poll::Ready(Err(e));
        }
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        *self
            .received_end
            .waker
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(cx.waker().clone());
        let before = buf.filled().len();
        match Pin::new(&mut self.app).poll_read(cx, buf) {
            Poll::Ready(Ok(()))
                if buf.filled().len() == before
                    && !self.received_end.done.load(Ordering::Acquire) =>
            {
                match self.check(cx) {
                    Err(e) => Poll::Ready(Err(e)),
                    Ok(()) => Poll::Pending,
                }
            }
            other => other,
        }
    }
}
impl AsyncWrite for CoverStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Err(e) = self.check(cx) {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.app).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(e) = self.check(cx) {
            return Poll::Ready(Err(e));
        }
        Pin::new(&mut self.app).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(e) = self.check(cx) {
            return Poll::Ready(Err(e));
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
            other => other,
        }
    }
}

/// Caller owns authorized TLS, exact typed agreement and ONE framing owner.
/// The generic adapter does not itself authenticate a bare transport.
pub fn attach_authenticated<S>(
    transport: S,
    settings: CoverStreamSettings,
    send: CoverStreamMaterial,
    receive: CoverStreamMaterial,
    original_deadline: Instant,
) -> io::Result<CoverStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    attach_authenticated_owned(transport, settings, send, receive, original_deadline, None)
}

pub(crate) fn attach_authenticated_owned<S>(
    transport: S,
    settings: CoverStreamSettings,
    send: CoverStreamMaterial,
    receive: CoverStreamMaterial,
    original_deadline: Instant,
    owner: Option<&super::worker_owner::ShapingCleanupOwner>,
) -> io::Result<CoverStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    settings.validate()?;
    if send.direction == receive.direction {
        return Err(invalid("cover stream directions must differ"));
    }
    let profile = settings.descriptor()?;
    let model = settings.model()?;
    let deadline = original_deadline
        .min(Instant::now() + Duration::from_millis(u64::from(settings.session_timeout_ms)));
    if Instant::now() >= deadline {
        return Err(timed_out());
    }
    let (app, worker_app) = tokio::io::duplex(settings.buffer_bytes);
    let (app_read, app_write) = tokio::io::split(worker_app);
    let (wire_read, wire_write) = tokio::io::split(transport);
    let received_end = Arc::new(Completion::default());
    let sent_end = Arc::new(Completion::default());
    let received = received_end.clone();
    let sent = sent_end.clone();
    let worker = super::worker_owner::spawn(owner, async move {
        let result = timeout_at(deadline, async {
            let (a, b) = tokio::try_join!(
                send_records(
                    app_read, wire_write, &settings, &model, &profile, send, deadline, sent
                ),
                receive_records(
                    wire_read, app_write, &settings, &model, &profile, receive, deadline, received
                )
            )?;
            Ok(ShapingStats {
                sent: a,
                received: b,
            })
        })
        .await
        .map_err(|_| timed_out())?;
        if Instant::now() >= deadline {
            return Err(timed_out());
        }
        result
    })?;
    Ok(CoverStream {
        app,
        worker: Some(worker),
        completed: None,
        received_end,
        sent_end,
        failure: None,
    })
}
fn invalid(s: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, s)
}
fn bad(s: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s)
}
fn timed_out() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "cover stream original deadline exceeded",
    )
}
fn due(s: &CoverStreamSettings, end: Instant) -> Instant {
    end.min(Instant::now() + Duration::from_millis(u64::from(s.io_timeout_ms)))
}
async fn checked<T, F: Future<Output = io::Result<T>>>(end: Instant, work: F) -> io::Result<T> {
    let result = timeout_at(end, work).await.map_err(|_| timed_out())??;
    if Instant::now() >= end {
        return Err(timed_out());
    }
    Ok(result)
}
fn debit(
    stats: &mut DirectionStats,
    s: &CoverStreamSettings,
    model: &CoverModel,
) -> io::Result<u64> {
    let ordinal = stats.frames;
    if ordinal >= s.max_records {
        return Err(bad("cover stream record allowance exhausted before END"));
    }
    let wire = stats
        .wire_bytes
        .checked_add(model.wire_bytes() as u64)
        .ok_or_else(|| bad("cover stream wire overflow"))?;
    if wire > s.max_wire_bytes {
        return Err(bad("cover stream wire allowance exhausted"));
    }
    stats.frames += 1;
    stats.wire_bytes = wire;
    Ok(ordinal)
}
#[allow(clippy::too_many_arguments)]
async fn send_records<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut app: R,
    mut wire: W,
    s: &CoverStreamSettings,
    model: &CoverModel,
    profile: &[u8; 32],
    material: CoverStreamMaterial,
    end: Instant,
    completed: Arc<Completion>,
) -> io::Result<DirectionStats> {
    let mut stats = DirectionStats::default();
    let mut payload = Zeroizing::new(vec![0u8; s.capacity]);
    loop {
        let ordinal = debit(&mut stats, s, model)?; // refuse exhaustion BEFORE any new app read
        let length = checked(end, app.read(&mut payload[1..])).await?;
        payload[0] = u8::from(length > 0);
        let record = material.record(model, profile, ordinal)?;
        checked(
            due(s, end),
            record.send(&payload[..length + 1], &mut OsRng, &mut wire),
        )
        .await?;
        if length == 0 {
            checked(due(s, end), wire.shutdown()).await?;
            completed.finish();
            return Ok(stats);
        }
        stats.data_bytes += length as u64;
        stats.padding_bytes += (model.wire_bytes().saturating_sub(length)) as u64;
    }
}
#[allow(clippy::too_many_arguments)]
async fn receive_records<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut wire: R,
    mut app: W,
    s: &CoverStreamSettings,
    model: &CoverModel,
    profile: &[u8; 32],
    material: CoverStreamMaterial,
    end: Instant,
    completed: Arc<Completion>,
) -> io::Result<DirectionStats> {
    let mut stats = DirectionStats::default();
    loop {
        let ordinal = debit(&mut stats, s, model)?;
        let record = material.record(model, profile, ordinal)?;
        let mut first = [0_u8; 1];
        checked(end, wire.read_exact(&mut first)).await?;
        let record_due = due(s, end);
        let mut prefixed = first.as_slice().chain(&mut wire);
        let payload = checked(record_due, record.receive(&mut prefixed)).await?;
        match payload.as_slice() {
            [0] => {
                checked(due(s, end), app.shutdown()).await?;
                completed.finish();
                return Ok(stats);
            }
            [1, data @ ..] if !data.is_empty() => {
                checked(due(s, end), app.write_all(data)).await?;
                stats.data_bytes += data.len() as u64;
                stats.padding_bytes += (model.wire_bytes().saturating_sub(data.len())) as u64;
            }
            _ => return Err(bad("cover stream malformed encrypted record type")),
        }
    }
}
#[cfg(test)]
#[path = "cover_idle_receive_tests.rs"]
mod idle_receive_tests;
#[cfg(test)]
#[path = "cover_stream_tests.rs"]
mod tests;
