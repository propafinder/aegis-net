//! Explicit operator-labelled finite Liu W1 kernels inside authenticated TLS.
//! The unchanged optimizer is admitted only when ALL positive output support
//! is causal. Read-chunk lengths are not physical packet sizes or whole flows.
use super::rate_distortion::{self, Channel, Limits, Problem};
use super::shaper::{DirectionStats, ShapingStats};
use rand::{rngs::OsRng, RngCore};
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
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    task::JoinHandle,
    time::{timeout_at, Instant},
};
use zeroize::{Zeroize, Zeroizing};
const HEADER: usize = 48;
const DIGEST: usize = 32;
const OVERHEAD: usize = HEADER + DIGEST;
const MAGIC: &[u8; 4] = b"LWC1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum TrafficTransport {
    Tcp,
    Udp,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassMapping {
    pub host: String,
    pub port: u16,
    pub transport: TrafficTransport,
    pub class: u8,
}

/// Explicit operator classes/calibration, never an inferred true application
/// label. Each directional row contains strictly positive counts for EXACT
/// current read lengths 1..P. Metric |z-y|/(P-1), normalized bytes; no IAT model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiuSettings {
    pub class_weights: Vec<u64>,
    pub client_to_server_counts: Vec<Vec<u64>>,
    pub server_to_client_counts: Vec<Vec<u64>>,
    pub target_classes: Vec<ClassMapping>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub unmatched_traffic_class: Option<u8>,
    pub policy_ack_class: u8,
    pub distortion_microunits: u32,
    pub optimizer_iterations: u16,
    pub optimizer_gap_millibits: u16,
    pub optimizer_timeout_ms: u32,
    pub buffer_bytes: usize,
    pub wire_batch_bytes: u16,
    pub max_wire_bytes: u64,
    pub io_timeout_ms: u32,
    pub session_timeout_ms: u32,
    pub max_queue_delay_ms: u32,
}
fn present<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

pub fn canonical_host(host: &str) -> io::Result<String> {
    // Bound work and allocation before parsing or creating a lowercase copy.
    if host.is_empty() || host.len() > 253 {
        return Err(invalid("invalid Liu target host"));
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(ip.to_string());
    }
    let h = host.to_ascii_lowercase();
    if h.len() > 253
        || h.is_empty()
        || h.ends_with('.')
        || !h.is_ascii()
        || h.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(invalid("invalid Liu target host"));
    }
    Ok(h)
}
/// Frozen admission purpose; not a target authorization capability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "purpose", rename_all = "snake_case", deny_unknown_fields)]
pub enum BoundContext {
    Traffic {
        host: String,
        port: u16,
        transport: TrafficTransport,
        class: u8,
    },
    PolicyAck {
        class: u8,
    },
}
impl BoundContext {
    pub fn class(&self) -> usize {
        match self {
            Self::Traffic { class, .. } | Self::PolicyAck { class } => usize::from(*class),
        }
    }
    pub fn check_open(&self, open: &crate::secure_channel::OpenRequest) -> io::Result<()> {
        let Self::Traffic {
            host,
            port,
            transport,
            ..
        } = self
        else {
            return Err(bad("Liu purpose differs from Open"));
        };
        let actual = match open.transport {
            crate::secure_channel::Transport::Tcp => TrafficTransport::Tcp,
            crate::secure_channel::Transport::Udp => TrafficTransport::Udp,
        };
        if *host != canonical_host(&open.host)? || *port != open.port || *transport != actual {
            return Err(bad("Liu admitted target differs from Open"));
        }
        Ok(())
    }
    pub fn check_policy_ack(&self) -> io::Result<()> {
        if matches!(self, Self::PolicyAck { .. }) {
            Ok(())
        } else {
            Err(bad("Liu traffic purpose differs from PolicyAck"))
        }
    }
}
impl LiuSettings {
    pub fn payload_bytes(&self) -> usize {
        self.client_to_server_counts.first().map_or(0, Vec::len)
    }
    pub fn validate(&self) -> io::Result<()> {
        let classes = self.class_weights.len();
        let p = self.payload_bytes();
        if !(1..=4).contains(&classes)
            || !(2..=8).contains(&p)
            || self.class_weights.contains(&0)
            || self.target_classes.len() > 16
            || usize::from(self.policy_ack_class) >= classes
            || self
                .unmatched_traffic_class
                .is_some_and(|c| usize::from(c) >= classes)
            || self.distortion_microunits > 1_000_000
            || !(1..=2000).contains(&self.optimizer_iterations)
            || !(1..=1000).contains(&self.optimizer_gap_millibits)
            || !(1..=5000).contains(&self.optimizer_timeout_ms)
            || !(1..=30_000).contains(&self.io_timeout_ms)
            || !(1..=3_600_000).contains(&self.session_timeout_ms)
            || !(p..=65_536).contains(&self.buffer_bytes)
            || !(OVERHEAD + p..=4096).contains(&usize::from(self.wire_batch_bytes))
            || usize::from(self.wire_batch_bytes) > self.buffer_bytes
            || !((OVERHEAD * 2 + p) as u64..=1_073_741_824).contains(&self.max_wire_bytes)
            || u64::from(self.max_queue_delay_ms)
                < (self.buffer_bytes as u64 + 1) * u64::from(self.io_timeout_ms)
            || u64::from(self.optimizer_iterations) * classes as u64 * p as u64 * p as u64 * 85 * 2
                > 200_000_000
        {
            return Err(invalid("invalid Liu finite model or resource bounds"));
        }
        let total = self
            .class_weights
            .iter()
            .try_fold(0u64, |a, b| a.checked_add(*b))
            .filter(|n| *n <= 1 << 53)
            .ok_or_else(|| invalid("Liu prior count overflow"))?;
        for table in [&self.client_to_server_counts, &self.server_to_client_counts] {
            if table.len() != classes {
                return Err(invalid("Liu directional class count mismatch"));
            }
            for (s, row) in table.iter().enumerate() {
                if row.len() != p || row.contains(&0) {
                    return Err(invalid("Liu requires all actual read lengths supported"));
                }
                let sum = row
                    .iter()
                    .try_fold(0u64, |a, b| a.checked_add(*b))
                    .filter(|n| *n <= 1 << 53)
                    .ok_or_else(|| invalid("Liu conditional count overflow"))?;
                if row.iter().any(|n| {
                    self.class_weights[s] as f64 / total as f64 * (*n as f64 / sum as f64) < 1e-15
                }) {
                    return Err(invalid("Liu numerical support too small"));
                }
            }
        }
        for (i, m) in self.target_classes.iter().enumerate() {
            if m.port == 0
                || usize::from(m.class) >= classes
                || canonical_host(&m.host)? != m.host
                || self.target_classes[..i]
                    .iter()
                    .any(|n| n.host == m.host && n.port == m.port && n.transport == m.transport)
            {
                return Err(invalid("invalid or ambiguous Liu target class mapping"));
            }
        }
        Ok(())
    }
    pub fn traffic_context(
        &self,
        host: &str,
        port: u16,
        transport: crate::secure_channel::Transport,
    ) -> io::Result<BoundContext> {
        self.validate()?;
        if port == 0 {
            return Err(invalid("Liu target port zero"));
        }
        let host = canonical_host(host)?;
        let transport = match transport {
            crate::secure_channel::Transport::Tcp => TrafficTransport::Tcp,
            crate::secure_channel::Transport::Udp => TrafficTransport::Udp,
        };
        let class = self
            .target_classes
            .iter()
            .find(|m| m.host == host && m.port == port && m.transport == transport)
            .map(|m| m.class)
            .or(self.unmatched_traffic_class)
            .ok_or_else(|| invalid("Liu target has no declared class"))?;
        Ok(BoundContext::Traffic {
            host,
            port,
            transport,
            class,
        })
    }
    pub fn policy_context(&self) -> io::Result<BoundContext> {
        self.validate()?;
        Ok(BoundContext::PolicyAck {
            class: self.policy_ack_class,
        })
    }
    pub fn validate_context(&self, c: &BoundContext) -> io::Result<()> {
        let expected = match c {
            BoundContext::Traffic {
                host,
                port,
                transport,
                ..
            } => self.traffic_context(
                host,
                *port,
                match transport {
                    TrafficTransport::Tcp => crate::secure_channel::Transport::Tcp,
                    TrafficTransport::Udp => crate::secure_channel::Transport::Udp,
                },
            )?,
            BoundContext::PolicyAck { .. } => self.policy_context()?,
        };
        if expected != *c {
            return Err(bad("Liu class or context differs from declared mapping"));
        }
        Ok(())
    }
    pub fn descriptor(&self) -> io::Result<[u8; 32]> {
        self.validate()?;
        let mut h = Sha256::new();
        h.update(b"AEGIS-Liu-exact-finite-readlength-v1\0");
        h.update(serde_json::to_vec(self).map_err(io::Error::other)?);
        Ok(h.finalize().into())
    }
    fn problem(&self, table: &[Vec<u64>]) -> io::Result<Problem> {
        self.validate()?;
        let total: u64 = self.class_weights.iter().sum();
        let prior = self
            .class_weights
            .iter()
            .map(|n| *n as f64 / total as f64)
            .collect();
        let conditional = table
            .iter()
            .flat_map(|row| {
                let sum: u64 = row.iter().sum();
                row.iter().map(move |n| *n as f64 / sum as f64)
            })
            .collect();
        let p = self.payload_bytes();
        let metric = (0..p)
            .flat_map(|z| (0..p).map(move |y| z.abs_diff(y) as f64 / (p - 1) as f64))
            .collect();
        Problem::label_conditional_wasserstein(
            prior,
            p,
            conditional,
            metric,
            f64::from(self.distortion_microunits) / 1_000_000.0,
        )
        .map_err(|_| invalid("Liu exact model refused"))
    }
}
/// Session input owning immutable public kernels. No masked re-solve or shared session state.
pub struct PreparedChannel {
    settings: LiuSettings,
    channels: [Arc<Channel>; 2],
}
impl PreparedChannel {
    // Only the completed public numerical model is reusable. This operation
    // carries no bound target/context, seed, stream, cancellation or clock.
    pub(crate) fn reuse_public_training(&self) -> Self {
        Self {
            settings: self.settings.clone(),
            channels: self.channels.clone(),
        }
    }
    /// Exact numerical representation binding, not a proof of true calibration.
    pub fn kernel_descriptor(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"AEGIS-Liu-two-exact-IEEE-kernels-v1\0");
        for channel in &self.channels {
            for p in channel.probabilities() {
                h.update(p.to_bits().to_be_bytes());
            }
            let c = channel.certificate();
            h.update((c.iterations as u64).to_be_bytes());
            for x in [
                c.leakage_bits,
                c.expected_cost,
                c.cost_budget,
                c.smoothed_objective_bits,
                c.smoothed_lower_bound_bits,
                c.smoothing_bias_bound_bits,
                c.original_gap_bound_bits,
            ] {
                h.update(x.to_bits().to_be_bytes());
            }
            h.update([u8::from(c.rigorous_interval_certificate)]);
        }
        h.finalize().into()
    }
    pub fn settings(&self) -> &LiuSettings {
        &self.settings
    }
    pub fn certificates(&self) -> [&rate_distortion::Certificate; 2] {
        [
            self.channels[0].certificate(),
            self.channels[1].certificate(),
        ]
    }
    pub fn probabilities(&self, direction: usize) -> Option<&[f64]> {
        self.channels
            .get(direction)
            .map(|channel| channel.probabilities())
    }
}
fn causal_support(channel: &Channel, p: usize) -> io::Result<()> {
    for (row, probs) in channel.probabilities().chunks_exact(p).enumerate() {
        for (y, mass) in probs.iter().enumerate() {
            if !mass.is_finite() || *mass < 0.0 || (*mass > 0.0 && y < row % p) {
                return Err(invalid(
                    "Liu exact kernel has positive physically impossible support",
                ));
            }
        }
    }
    Ok(())
}
struct TrainingOwner {
    cancellation: Arc<AtomicBool>,
    task: JoinHandle<io::Result<PreparedChannel>>,
}
impl Drop for TrainingOwner {
    fn drop(&mut self) {
        self.cancellation.store(true, Ordering::Release);
        self.task.abort();
    }
}
pub async fn prepare(
    settings: LiuSettings,
    original_deadline: Instant,
) -> io::Result<PreparedChannel> {
    prepare_with_owner(settings, original_deadline, || ()).await
}
async fn prepare_with_owner<F, W>(
    settings: LiuSettings,
    original_deadline: Instant,
    on_start: F,
) -> io::Result<PreparedChannel>
where
    F: FnOnce() -> W + Send + 'static,
    W: Send + 'static,
{
    prepare_with_probes(settings, original_deadline, on_start, |flag| {
        flag.load(Ordering::Acquire)
    })
    .await
}
async fn prepare_with_probes<F, W, C>(
    settings: LiuSettings,
    original_deadline: Instant,
    on_start: F,
    mut cancellation_probe: C,
) -> io::Result<PreparedChannel>
where
    F: FnOnce() -> W + Send + 'static,
    W: Send + 'static,
    C: FnMut(&AtomicBool) -> bool + Send + 'static,
{
    let problems = [
        settings.problem(&settings.client_to_server_counts)?,
        settings.problem(&settings.server_to_client_counts)?,
    ];
    let deadline = original_deadline
        .min(Instant::now() + Duration::from_millis(u64::from(settings.optimizer_timeout_ms)));
    if Instant::now() >= deadline {
        return Err(timed_out());
    }
    let training_permit = super::optimizer_admission::acquire(deadline).await?;
    let cancellation = Arc::new(AtomicBool::new(false));
    let flag = cancellation.clone();
    #[cfg(test)]
    let preparation_probe = super::optimizer_admission_test_support::capture();
    #[cfg(test)]
    let creation_probe = preparation_probe.clone();
    let task = tokio::task::spawn_blocking(move || {
        #[cfg(test)]
        let _observed_worker_lifetime = preparation_probe
            .as_ref()
            .map(|probe| probe.clone().enter_worker(deadline.into_std()));
        // One admission owner covers both unchanged directional optimizations.
        let _training_permit = training_permit;
        let _owned_lifetime = on_start();
        if flag.load(Ordering::Acquire) {
            return Err(invalid("Liu preparation cancelled before optimization"));
        }
        let mut results = Vec::with_capacity(2);
        for problem in problems {
            #[cfg(test)]
            if let Some(probe) = &preparation_probe {
                probe.optimizer_entered();
            }
            let result = rate_distortion::optimize(
                problem,
                Limits {
                    iterations: usize::from(settings.optimizer_iterations),
                    smoothing: 1e-8,
                    gap_bits: f64::from(settings.optimizer_gap_millibits) / 1000.0,
                },
                deadline.into_std(),
                || cancellation_probe(&flag),
            );
            #[cfg(test)]
            if let Some(probe) = &preparation_probe {
                probe.optimizer_returned(&result, deadline.into_std());
            }
            let channel =
                result.map_err(|_| invalid("Liu optimizer refused or did not converge"))?;
            causal_support(&channel, settings.payload_bytes())?;
            results.push(channel);
        }
        let channels = results
            .into_iter()
            .map(Arc::new)
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| invalid("Liu directional preparation failed"))?;
        Ok(PreparedChannel { settings, channels })
    });
    #[cfg(test)]
    if let Some(probe) = &creation_probe {
        probe.task_created(deadline.into_std());
    }
    let mut owner = TrainingOwner { cancellation, task };
    let result = timeout_at(deadline, &mut owner.task)
        .await
        .map_err(|_| timed_out())?
        .map_err(|_| io::Error::other("Liu preparation worker failed"))??;
    if Instant::now() >= deadline {
        return Err(timed_out());
    }
    Ok(result)
}
struct PreparedDirection {
    settings: LiuSettings,
    descriptor: [u8; 32],
    channel: Arc<Channel>,
    class: usize,
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

#[derive(Debug)]
struct OwnedFailure(&'static str);
impl std::fmt::Display for OwnedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for OwnedFailure {}
fn join_error(e: tokio::task::JoinError) -> io::Error {
    io::Error::other(OwnedFailure(if e.is_cancelled() {
        "Liu worker cancelled"
    } else if e.is_panic() {
        "Liu worker panicked"
    } else {
        "Liu worker join failed"
    }))
}
fn phase_error(error: io::Error, phase: &'static str) -> io::Error {
    io::Error::new(error.kind(), OwnedFailure(phase))
}
/// Dropping this owner aborts BOTH directions. No detached stream worker.
pub struct LiuStream {
    app: DuplexStream,
    worker: Option<super::worker_owner::SharedWorker<ShapingStats>>,
    completed: Option<ShapingStats>,
    received_end: Arc<Completion>,
    sent_end: Arc<Completion>,
    failure: Option<(io::ErrorKind, &'static str)>,
}
impl std::fmt::Debug for LiuStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiuStream").finish_non_exhaustive()
    }
}
impl Drop for LiuStream {
    fn drop(&mut self) {
        if let Some(w) = &self.worker {
            w.abort();
        }
    }
}
impl LiuStream {
    fn check(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if let Some(w) = self.worker.as_mut() {
            if let Poll::Ready(result) = Pin::new(w).poll(cx) {
                self.worker = None;
                match result.unwrap_or_else(|e| Err(join_error(e))) {
                    Ok(stats) => self.completed = Some(stats),
                    Err(e) => {
                        self.failure = Some((
                            e.kind(),
                            e.get_ref()
                                .and_then(|s| s.downcast_ref::<OwnedFailure>())
                                .map_or("Liu owned worker failed", |s| s.0),
                        ))
                    }
                }
            }
        }
        if let Some((kind, message)) = &self.failure {
            return Err(io::Error::new(*kind, *message));
        }
        Ok(())
    }
    pub async fn finish(mut self) -> io::Result<ShapingStats> {
        self.app.shutdown().await?;
        if let Some((kind, message)) = &self.failure {
            return Err(io::Error::new(*kind, *message));
        }
        if let Some(stats) = self.completed.take() {
            return Ok(stats);
        }
        let result = self
            .worker
            .as_mut()
            .ok_or_else(|| io::Error::other("Liu result already consumed"))?
            .await
            .map_err(join_error);
        self.worker = None;
        result?
    }
}
impl AsyncRead for LiuStream {
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
impl AsyncWrite for LiuStream {
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

/// Caller must establish authorized authenticated TLS and matching typed profile
/// FIRST, and enforce exactly ONE shaping owner. This generic type cannot prove
/// TLS itself; calling it on bare TCP does not create authenticated encryption.
pub fn attach_authenticated<S>(
    transport: S,
    prepared: PreparedChannel,
    context: BoundContext,
    material: Zeroizing<[u8; 32]>,
    is_client: bool,
    original_deadline: Instant,
) -> io::Result<LiuStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    attach_authenticated_owned(
        transport,
        prepared,
        context,
        material,
        is_client,
        original_deadline,
        None,
    )
}

pub(crate) fn attach_authenticated_owned<S>(
    transport: S,
    prepared: PreparedChannel,
    context: BoundContext,
    material: Zeroizing<[u8; 32]>,
    is_client: bool,
    original_deadline: Instant,
    owner: Option<&super::worker_owner::ShapingCleanupOwner>,
) -> io::Result<LiuStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    prepared.settings.validate_context(&context)?;
    let original_deadline = original_deadline.min(
        Instant::now() + Duration::from_millis(u64::from(prepared.settings.session_timeout_ms)),
    );
    if Instant::now() >= original_deadline {
        return Err(timed_out());
    }
    let profile = prepared.settings.descriptor()?;
    let kernel_descriptor = prepared.kernel_descriptor();
    let hk = hkdf::Hkdf::<Sha256>::new(Some(&profile), &*material);
    let mut info = b"AEGIS-Liu-fresh-context-direction-v1/".to_vec();
    info.extend(serde_json::to_vec(&context).map_err(io::Error::other)?);
    info.extend(kernel_descriptor);
    let direction = |channel, ordinal: u8| -> io::Result<PreparedDirection> {
        let mut descriptor = [0; 32];
        let mut d = info.clone();
        d.push(ordinal);
        hk.expand(&d, &mut descriptor)
            .map_err(|_| bad("Liu session derivation refused"))?;
        Ok(PreparedDirection {
            settings: prepared.settings.clone(),
            descriptor,
            channel,
            class: context.class(),
        })
    };
    let [c2s, s2c] = prepared.channels;
    let c2s = direction(c2s, 0)?;
    let s2c = direction(s2c, 1)?;
    let (send, receive) = if is_client { (c2s, s2c) } else { (s2c, c2s) };
    let (app, worker_app) = tokio::io::duplex(prepared.settings.buffer_bytes);
    let (app_read, app_write) = tokio::io::split(worker_app);
    let (wire_read, wire_write) = tokio::io::split(transport);
    let received_end = Arc::new(Completion::default());
    let sent_end = Arc::new(Completion::default());
    let received = received_end.clone();
    let sent = sent_end.clone();
    let worker = super::worker_owner::spawn(owner, async move {
        let work = async {
            let (send, recv) = tokio::try_join!(
                async {
                    send_frames(app_read, wire_write, &send, original_deadline, sent)
                        .await
                        .map_err(|e| phase_error(e, "Liu sender failed"))
                },
                async {
                    receive_frames(wire_read, app_write, &receive, original_deadline, received)
                        .await
                        .map_err(|e| phase_error(e, "Liu receiver failed"))
                }
            )?;
            Ok(ShapingStats {
                sent: send,
                received: recv,
            })
        };
        let result = timeout_at(original_deadline, work)
            .await
            .map_err(|_| timed_out())?;
        if Instant::now() >= original_deadline {
            return Err(timed_out());
        }
        result
    })?;
    Ok(LiuStream {
        app,
        worker: Some(worker),
        completed: None,
        received_end,
        sent_end,
        failure: None,
    })
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn bad(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "Liu original deadline exceeded")
}
fn bin(p: &PreparedDirection, length: usize) -> io::Result<usize> {
    if length == 0 || length > p.settings.payload_bytes() {
        return Err(bad("Liu read outside exact declared alphabet"));
    }
    Ok(length - 1)
}
fn header(
    p: &PreparedDirection,
    sequence: u64,
    length: usize,
    action: u8,
    end: bool,
) -> [u8; HEADER] {
    let mut h = [0; HEADER];
    h[..4].copy_from_slice(MAGIC);
    h[4] = u8::from(end);
    h[5] = action;
    h[6..14].copy_from_slice(&sequence.to_be_bytes());
    h[14..16].copy_from_slice(&(length as u16).to_be_bytes());
    h[16..].copy_from_slice(&p.descriptor);
    h
}
fn digest(h: &[u8], body: &[u8]) -> [u8; DIGEST] {
    let mut hash = Sha256::new();
    hash.update(h);
    hash.update(body);
    hash.finalize().into()
}
fn debit(stats: &mut DirectionStats, body: usize, config: &LiuSettings) -> io::Result<()> {
    let bytes = (OVERHEAD + body) as u64;
    let new = stats
        .wire_bytes
        .checked_add(bytes)
        .ok_or_else(|| bad("Liu wire overflow"))?;
    if new > config.max_wire_bytes {
        return Err(bad("Liu wire budget exhausted"));
    }
    stats.wire_bytes = new;
    stats.frames += 1;
    Ok(())
}
fn io_deadline(config: &LiuSettings, original: Instant) -> Instant {
    original.min(Instant::now() + Duration::from_millis(u64::from(config.io_timeout_ms)))
}
async fn checked<T, F: Future<Output = io::Result<T>>>(
    deadline: Instant,
    work: F,
) -> io::Result<T> {
    if Instant::now() >= deadline {
        return Err(timed_out());
    }
    let result = timeout_at(deadline, work)
        .await
        .map_err(|_| timed_out())??;
    if Instant::now() >= deadline {
        return Err(timed_out());
    }
    Ok(result)
}

async fn send_frames<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut app: R,
    mut wire: W,
    p: &PreparedDirection,
    original: Instant,
    end: Arc<Completion>,
) -> io::Result<DirectionStats> {
    let mut stats = DirectionStats::default();
    let mut sequence = 0u64;
    let mut payload = Zeroizing::new(vec![0; p.settings.payload_bytes()]);
    let cap = usize::from(p.settings.wire_batch_bytes);
    let mut batch = Zeroizing::new(Vec::with_capacity(cap));
    loop {
        let mut length = checked(original, app.read(&mut payload)).await?;
        // Earliest queued record owns the complete batch's I/O cutoff. Later
        // input never extends it; no input waits or secret-derived timers.
        let due = io_deadline(&p.settings, original);
        let mut terminal = false;
        loop {
            if Instant::now() >= due {
                return Err(timed_out());
            }
            if length == 0 {
                debit(&mut stats, 0, &p.settings)?;
                let h = header(p, sequence, 0, u8::MAX, true);
                batch.extend_from_slice(&h);
                batch.extend_from_slice(&digest(&h, &[]));
                terminal = true;
                break;
            }
            let observation = bin(p, length)?;
            let selected = p
                .channel
                .sample_label_conditional(p.class, observation, &mut OsRng)
                .map_err(|_| io::Error::other("Liu entropy or channel refusal"))?;
            if selected < observation {
                return Err(bad("Liu noncausal support escaped admission"));
            }
            let mut body = Zeroizing::new(vec![0; selected + 1]);
            OsRng
                .try_fill_bytes(&mut body)
                .map_err(|_| io::Error::other("Liu padding entropy unavailable"))?;
            body[..length].copy_from_slice(&payload[..length]);
            payload[..length].zeroize();
            let h = header(p, sequence, length, selected as u8, false);
            let d = digest(&h, &body);
            debit(&mut stats, body.len(), &p.settings)?;
            batch.extend_from_slice(&h);
            batch.extend_from_slice(&body);
            batch.extend_from_slice(&d);
            stats.data_bytes += length as u64;
            stats.padding_bytes += (body.len() - length) as u64;
            sequence = sequence
                .checked_add(1)
                .ok_or_else(|| bad("Liu sequence exhausted"))?;
            if batch.len() + OVERHEAD + p.settings.payload_bytes() > cap {
                break;
            }
            // Only immediately ready CURRENT input may enter this batch. A
            // Pending observation flushes the short request without waiting
            // for future bytes. This does not change any inner kernel row.
            let next = std::future::poll_fn(|cx| {
                if Instant::now() >= due {
                    return Poll::Ready(Some(Err(timed_out())));
                }
                let mut b = ReadBuf::new(&mut payload);
                Poll::Ready(match Pin::new(&mut app).poll_read(cx, &mut b) {
                    Poll::Pending => None,
                    Poll::Ready(r) => Some(r.map(|()| b.filled().len())),
                })
            })
            .await;
            match next {
                None => break,
                Some(n) => {
                    length = n?;
                }
            }
        }
        checked(due, async {
            wire.write_all(&batch).await?;
            wire.flush().await?;
            if terminal {
                wire.shutdown().await?;
            }
            Ok(())
        })
        .await?;
        batch.as_mut_slice().zeroize();
        batch.clear();
        if terminal {
            end.finish();
            return Ok(stats);
        }
    }
}

async fn receive_frames<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut wire: R,
    mut app: W,
    p: &PreparedDirection,
    original: Instant,
    end: Arc<Completion>,
) -> io::Result<DirectionStats> {
    let mut stats = DirectionStats::default();
    let mut sequence = 0_u64;
    loop {
        let mut h = [0; HEADER];
        checked(original, wire.read_exact(&mut h[..1])).await?;
        let due = io_deadline(&p.settings, original);
        checked(due, wire.read_exact(&mut h[1..])).await?;
        if &h[..4] != MAGIC || h[16..] != p.descriptor || h[6..14] != sequence.to_be_bytes() {
            return Err(bad("Liu profile, format or sequence mismatch"));
        }
        let length = usize::from(u16::from_be_bytes([h[14], h[15]]));
        let body_len = match h[4] {
            0 => {
                if length == 0 {
                    return Err(bad("Liu empty data frame"));
                }
                let observation = bin(p, length)?;
                let selected = usize::from(h[5]);
                if selected >= p.settings.payload_bytes()
                    || selected < observation
                    || p.channel.probabilities()[(p.class * p.settings.payload_bytes()
                        + observation)
                        * p.settings.payload_bytes()
                        + selected]
                        <= 0.0
                {
                    return Err(bad("Liu noncausal or unsupported received action"));
                }
                selected + 1
            }
            1 if length == 0 && h[5] == u8::MAX => 0,
            _ => return Err(bad("Liu invalid terminal frame")),
        };
        debit(&mut stats, body_len, &p.settings)?;
        let mut body = Zeroizing::new(vec![0; body_len]);
        let mut received = [0; DIGEST];
        checked(due, async {
            wire.read_exact(&mut body).await?;
            wire.read_exact(&mut received).await?;
            Ok(())
        })
        .await?;
        if digest(&h, &body).ct_eq(&received).unwrap_u8() != 1 {
            return Err(bad("Liu frame consistency mismatch"));
        }
        if h[4] == 1 {
            checked(due, app.shutdown()).await?;
            end.finish();
            return Ok(stats);
        }
        // Only now expose ANY bytes of this frame to the application.
        checked(
            io_deadline(&p.settings, original),
            app.write_all(&body[..length]),
        )
        .await?;
        stats.data_bytes += length as u64;
        stats.padding_bytes += (body_len - length) as u64;
        sequence = sequence
            .checked_add(1)
            .ok_or_else(|| bad("Liu sequence exhausted"))?;
    }
}

#[cfg(test)]
#[path = "liu_idle_receive_tests.rs"]
mod idle_receive_tests;
#[cfg(test)]
#[path = "liu_channel_tests.rs"]
mod tests;

// This façade delegates to the original per-invocation task-local observer.
// It supplies no alternate budget, solver, gate cutoff, or production state.
#[cfg(test)]
pub(crate) mod training_test_probe {
    use super::super::optimizer_admission_test_support as original;
    use std::{future::Future, sync::Arc};
    use tokio::time::Instant;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum SolverOutcome {
        Succeeded,
        Cancelled,
        Deadline,
        Refused,
    }
    #[derive(Clone, Copy, Debug, Default)]
    pub(crate) struct Snapshot {
        pub(crate) task_created: usize,
        pub(crate) worker_entered: usize,
        pub(crate) optimizer_entered: usize,
        pub(crate) worker_exited: usize,
        pub(crate) gate_expired: bool,
        pub(crate) directional_outcomes: [Option<SolverOutcome>; 2],
    }
    fn snapshot(actual: original::Snapshot) -> Snapshot {
        let outcome = |value| match value {
            original::SolverOutcome::Succeeded => SolverOutcome::Succeeded,
            original::SolverOutcome::Cancelled => SolverOutcome::Cancelled,
            original::SolverOutcome::Deadline => SolverOutcome::Deadline,
            original::SolverOutcome::Refused => SolverOutcome::Refused,
        };
        Snapshot {
            task_created: actual.task_created,
            worker_entered: actual.worker_entered,
            optimizer_entered: actual.optimizer_entered,
            worker_exited: actual.worker_exited,
            gate_expired: actual.gate_expired,
            directional_outcomes: actual.directional_outcomes.map(|value| value.map(outcome)),
        }
    }
    pub(crate) struct PreparationProbe {
        actual: Arc<original::PreparationProbe>,
    }
    impl PreparationProbe {
        pub(crate) fn held() -> Arc<Self> {
            Arc::new(Self {
                actual: original::PreparationProbe::held(),
            })
        }
        pub(crate) fn released() -> Arc<Self> {
            Arc::new(Self {
                actual: original::PreparationProbe::released(),
            })
        }
        pub(crate) fn snapshot(&self) -> Snapshot {
            snapshot(self.actual.snapshot())
        }
        pub(crate) fn release(&self) {
            self.actual.release();
        }
        pub(crate) async fn wait_for(
            &self,
            original_fixture_cutoff: Instant,
            predicate: impl Fn(Snapshot) -> bool,
        ) -> Snapshot {
            snapshot(
                self.actual
                    .wait_for(original_fixture_cutoff, |value| predicate(snapshot(value)))
                    .await,
            )
        }
    }
    pub(crate) async fn scope<T>(probe: Arc<PreparationProbe>, work: impl Future<Output = T>) -> T {
        original::scope(probe.actual.clone(), work).await
    }
}
