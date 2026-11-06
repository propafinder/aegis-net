//! Causal, opt-in finite-channel padding/delay INSIDE authenticated TLS.
//! Framing/digests supply consistency only, not standalone authentication.
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

const HEADER: usize = 48;
const DIGEST: usize = 32;
const OVERHEAD: usize = HEADER + DIGEST;
const MAGIC: &[u8; 4] = b"ARC1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub padded_bytes: u16,
    pub delay_ms: u16,
}

/// Absent means the unchanged mean-MI solver. Maximum information solves the
/// separate §IV-C fixed-cap minimum-cost program in the declared public model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdaptiveObjective {
    MaximumInformation {
        leakage_cap_millibits: u16,
        cost_gap: u32,
    },
    MinimaxInformation {
        leakage_gap_millibits: u16,
        cost_gap: u32,
        cap_programs: u8,
    },
}

fn present_objective<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<AdaptiveObjective>, D::Error> {
    AdaptiveObjective::deserialize(d).map(Some)
}

/// Public, predeclared length-bin model. Integer counts are offline training
/// inputs only. No secret label is provided at actuation. One cost unit is one
/// padding byte plus `delay_cost_per_ms` per millisecond, measured against the
/// bin LOWER bound (conservative for any actual length in that bin); record
/// overhead is separate. This is not a physical QoS theorem.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdaptiveSettings {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_objective"
    )]
    pub objective: Option<AdaptiveObjective>,
    pub joint_counts: Vec<Vec<u64>>,
    pub length_bin_upper: Vec<u16>,
    pub actions: Vec<Action>,
    pub delay_cost_per_ms: u32,
    pub cost_budget: u32,
    pub optimizer_iterations: u16,
    pub optimizer_gap_millibits: u16,
    pub optimizer_timeout_ms: u32,
    pub buffer_bytes: usize,
    pub max_wire_bytes: u64,
    pub io_timeout_ms: u32,
    pub session_timeout_ms: u32,
    pub max_queue_delay_ms: u32,
}

impl AdaptiveSettings {
    pub fn payload_bytes(&self) -> usize {
        self.length_bin_upper.last().copied().unwrap_or(0) as usize
    }

    pub fn max_delay_ms(&self) -> u32 {
        self.actions
            .iter()
            .map(|a| u32::from(a.delay_ms))
            .max()
            .unwrap_or(0)
    }

    pub fn validate(&self) -> io::Result<()> {
        if let Some(objective) = self.objective {
            let (cost_gap, programs) = match objective {
                AdaptiveObjective::MaximumInformation {
                    leakage_cap_millibits,
                    cost_gap,
                } => {
                    if leakage_cap_millibits > 16_000 {
                        return Err(invalid("adaptive leakage cap bounds"));
                    }
                    (cost_gap, 1)
                }
                AdaptiveObjective::MinimaxInformation {
                    leakage_gap_millibits,
                    cost_gap,
                    cap_programs,
                } => {
                    if !(1..=16_000).contains(&leakage_gap_millibits)
                        || !(1..=32).contains(&cap_programs)
                    {
                        return Err(invalid("adaptive minimax search bounds"));
                    }
                    (cost_gap, u128::from(cap_programs))
                }
            };
            let iterations = (self.optimizer_iterations as u128) * programs;
            let work = iterations
                .saturating_mul(self.length_bin_upper.len() as u128)
                .saturating_mul(self.actions.len() as u128)
                .saturating_mul(
                    (self.joint_counts.len() as u128).saturating_add(self.actions.len() as u128),
                )
                .saturating_mul(128);
            if iterations > 20_000 || !(1..=1_000_000).contains(&cost_gap) || work > 200_000_000 {
                return Err(invalid("adaptive maximum-information objective bounds"));
            }
        }
        if !(1..=8).contains(&self.joint_counts.len())
            || !(1..=8).contains(&self.length_bin_upper.len())
            || !(1..=16).contains(&self.actions.len())
            || self
                .length_bin_upper
                .iter()
                .any(|u| !(1..=4096).contains(u))
            || self.length_bin_upper.windows(2).any(|w| w[0] >= w[1])
            || self
                .actions
                .iter()
                .any(|a| !(1..=4096).contains(&a.padded_bytes) || a.delay_ms > 1000)
            || self
                .joint_counts
                .iter()
                .any(|row| row.len() != self.length_bin_upper.len())
            || self.delay_cost_per_ms > 1_000_000
            || self.cost_budget > 1_000_000_000
            || !(1..=2000).contains(&self.optimizer_iterations)
            || !(1..=1000).contains(&self.optimizer_gap_millibits)
            || !(1..=5000).contains(&self.optimizer_timeout_ms)
            || !(1..=30_000).contains(&self.io_timeout_ms)
            || !(1..=3_600_000).contains(&self.session_timeout_ms)
            || self.io_timeout_ms <= self.max_delay_ms()
            || !(self.payload_bytes()..=1_048_576).contains(&self.buffer_bytes)
        {
            return Err(invalid("invalid adaptive finite profile or budgets"));
        }
        let total = self
            .joint_counts
            .iter()
            .flatten()
            .try_fold(0_u64, |a, b| a.checked_add(*b))
            .ok_or_else(|| invalid("training count overflow"))?;
        if total == 0
            || total > (1_u64 << 53)
            || (0..self.length_bin_upper.len()).any(|z| self.joint_counts.iter().all(|r| r[z] == 0))
            || self
                .length_bin_upper
                .iter()
                .any(|u| !self.actions.iter().any(|a| a.padded_bytes >= *u))
            || u64::from(self.optimizer_iterations)
                * self.joint_counts.len() as u64
                * self.length_bin_upper.len() as u64
                * self.actions.len() as u64
                * 85
                > 200_000_000
        {
            return Err(invalid("invalid adaptive support, actuator or work budget"));
        }
        if self
            .joint_counts
            .iter()
            .flatten()
            .any(|n| *n > 0 && *n as f64 / (total as f64) < 1e-15)
        {
            return Err(invalid("training count outside numerical support domain"));
        }
        let mut minimum_cost = 0_u128;
        for (z, upper) in self.length_bin_upper.iter().enumerate() {
            let lower = if z == 0 {
                1
            } else {
                self.length_bin_upper[z - 1] + 1
            };
            let minimum = self
                .actions
                .iter()
                .filter(|a| a.padded_bytes >= *upper)
                .map(|a| {
                    u64::from(a.padded_bytes - lower)
                        + u64::from(a.delay_ms) * u64::from(self.delay_cost_per_ms)
                })
                .min()
                .expect("validated physical action for each bin");
            let row_count: u64 = self.joint_counts.iter().map(|row| row[z]).sum();
            minimum_cost += u128::from(row_count) * u128::from(minimum);
        }
        if minimum_cost > u128::from(total) * u128::from(self.cost_budget) {
            return Err(invalid("adaptive physical expected-cost budget infeasible"));
        }
        let maximum_body = self
            .actions
            .iter()
            .map(|a| usize::from(a.padded_bytes))
            .max()
            .unwrap();
        if self.max_wire_bytes < (OVERHEAD * 2 + maximum_body) as u64
            || self.max_wire_bytes > 1_073_741_824
        {
            return Err(invalid("wire allowance cannot hold data and END"));
        }
        // Worst case one-byte reads, finite local backlog, each with delay+IO.
        // This is conservative local admission, not a network latency bound.
        let queue = (self.buffer_bytes as u64 + 1)
            .checked_mul(u64::from(self.max_delay_ms()) + u64::from(self.io_timeout_ms))
            .ok_or_else(|| invalid("queue allowance overflow"))?;
        if queue > u64::from(self.max_queue_delay_ms) {
            return Err(invalid(
                "queue allowance below conservative one-byte service bound",
            ));
        }
        Ok(())
    }

    /// Binds ALL public settings and wire version, before any application data.
    pub fn descriptor(&self) -> io::Result<[u8; 32]> {
        self.validate()?;
        let bytes =
            serde_json::to_vec(self).map_err(|_| invalid("profile serialization failed"))?;
        let mut hash = Sha256::new();
        hash.update(b"AEGIS-adaptive-causal-profile-v1\0");
        hash.update(bytes);
        Ok(hash.finalize().into())
    }

    fn problem(&self) -> io::Result<Problem> {
        self.validate()?;
        let total: u64 = self.joint_counts.iter().flatten().sum();
        let joint = self
            .joint_counts
            .iter()
            .flatten()
            .map(|n| *n as f64 / total as f64)
            .collect();
        let mut cost = Vec::new();
        let mut allowed = Vec::new();
        for (z, upper) in self.length_bin_upper.iter().enumerate() {
            let lower = if z == 0 {
                1
            } else {
                self.length_bin_upper[z - 1] + 1
            };
            for action in &self.actions {
                allowed.push(action.padded_bytes >= *upper);
                cost.push(
                    f64::from(action.padded_bytes.saturating_sub(lower))
                        + f64::from(action.delay_ms) * f64::from(self.delay_cost_per_ms),
                );
            }
        }
        Problem::label_blind(
            self.joint_counts.len(),
            self.length_bin_upper.len(),
            self.actions.len(),
            joint,
            cost,
            allowed,
            f64::from(self.cost_budget),
        )
        .map_err(|_| invalid("training model outside numerical domain"))
    }
}

#[derive(Clone)]
pub struct PreparedChannel {
    settings: AdaptiveSettings,
    descriptor: [u8; 32],
    channel: Arc<Channel>,
}
impl PreparedChannel {
    pub fn settings(&self) -> &AdaptiveSettings {
        &self.settings
    }
    pub fn descriptor(&self) -> [u8; 32] {
        self.descriptor
    }
    pub fn certificate(&self) -> &rate_distortion::Certificate {
        self.channel.certificate()
    }
}

struct TrainingOwner {
    cancellation: Arc<AtomicBool>,
    task: JoinHandle<io::Result<PreparedChannel>>,
}
impl Drop for TrainingOwner {
    fn drop(&mut self) {
        self.cancellation.store(true, Ordering::Release);
        self.task.abort(); // a running blocking task stops cooperatively, not by force
    }
}

/// Train OFF the async reactor BEFORE the profile agreement/target request.
/// Cancellation owns the flag; the worker also observes the original deadline.
pub async fn prepare(
    settings: AdaptiveSettings,
    original_deadline: Instant,
) -> io::Result<PreparedChannel> {
    let problem = settings.problem()?;
    let descriptor = settings.descriptor()?;
    let deadline = original_deadline
        .min(Instant::now() + Duration::from_millis(u64::from(settings.optimizer_timeout_ms)));
    if Instant::now() >= deadline {
        return Err(timed_out());
    }
    let training_permit = super::optimizer_admission::acquire(deadline).await?;
    let std_deadline = deadline.into_std();
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
            .map(|probe| probe.clone().enter_worker(std_deadline));
        // Keep admission across queued/running work, even after caller cancellation.
        let _training_permit = training_permit;
        let limits = Limits {
            iterations: usize::from(settings.optimizer_iterations),
            smoothing: 1e-8,
            gap_bits: f64::from(settings.optimizer_gap_millibits) / 1000.0,
        };
        let channel = match settings.objective {
            None => {
                #[cfg(test)]
                if let Some(probe) = &preparation_probe {
                    probe.optimizer_entered();
                }
                let result = rate_distortion::optimize(problem, limits, std_deadline, || {
                    flag.load(Ordering::Acquire)
                });
                #[cfg(test)]
                if let Some(probe) = &preparation_probe {
                    probe.optimizer_returned(&result, std_deadline);
                }
                result
            }
            Some(AdaptiveObjective::MaximumInformation {
                leakage_cap_millibits,
                cost_gap,
            }) => rate_distortion::optimize_maximum_information(
                problem,
                f64::from(leakage_cap_millibits) / 1000.0,
                rate_distortion::MaximumInformationLimits {
                    iterations: limits.iterations,
                    cost_gap: f64::from(cost_gap),
                },
                std_deadline,
                || flag.load(Ordering::Acquire),
            ),
            Some(AdaptiveObjective::MinimaxInformation {
                leakage_gap_millibits,
                cost_gap,
                cap_programs,
            }) => rate_distortion::optimize_minimax_information(
                problem,
                rate_distortion::MinimaxLimits {
                    iterations_per_cap: limits.iterations,
                    maximum_cap_programs: usize::from(cap_programs),
                    leakage_gap_bits: f64::from(leakage_gap_millibits) / 1000.0,
                    cost_gap: f64::from(cost_gap),
                },
                std_deadline,
                || flag.load(Ordering::Acquire),
            ),
        }
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("adaptive optimizer refused: {e:?}"),
            )
        })?;
        Ok(PreparedChannel {
            settings,
            descriptor,
            channel: Arc::new(channel),
        })
    });
    #[cfg(test)]
    if let Some(probe) = &creation_probe {
        probe.task_created(std_deadline);
    }
    let mut owner = TrainingOwner { cancellation, task };
    let result = timeout_at(deadline, &mut owner.task)
        .await
        .map_err(|_| timed_out())?
        .map_err(|_| io::Error::other("adaptive training worker failed"))??;
    if Instant::now() >= deadline {
        return Err(timed_out());
    }
    Ok(result)
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
pub struct AdaptiveStream {
    app: DuplexStream,
    worker: Option<super::worker_owner::SharedWorker<ShapingStats>>,
    completed: Option<ShapingStats>,
    received_end: Arc<Completion>,
    sent_end: Arc<Completion>,
    failure: Option<(io::ErrorKind, String)>,
}
impl Drop for AdaptiveStream {
    fn drop(&mut self) {
        if let Some(w) = &self.worker {
            w.abort();
        }
    }
}
impl AdaptiveStream {
    fn check(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if let Some(w) = self.worker.as_mut() {
            if let Poll::Ready(result) = Pin::new(w).poll(cx) {
                self.worker = None;
                match result.unwrap_or_else(|_| Err(io::Error::other("adaptive worker failed"))) {
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
            .ok_or_else(|| io::Error::other("adaptive result already consumed"))?
            .await
            .map_err(|_| io::Error::other("adaptive worker failed"));
        self.worker = None;
        result?
    }
}
impl AsyncRead for AdaptiveStream {
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
impl AsyncWrite for AdaptiveStream {
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
    original_deadline: Instant,
) -> io::Result<AdaptiveStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    attach_authenticated_owned(transport, prepared, original_deadline, None)
}

pub(crate) fn attach_authenticated_owned<S>(
    transport: S,
    prepared: PreparedChannel,
    original_deadline: Instant,
    owner: Option<&super::worker_owner::ShapingCleanupOwner>,
) -> io::Result<AdaptiveStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    prepared.settings.validate()?;
    let deadline = original_deadline.min(
        Instant::now() + Duration::from_millis(u64::from(prepared.settings.session_timeout_ms)),
    );
    if Instant::now() >= deadline {
        return Err(timed_out());
    }
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
                send_frames(app_read, wire_write, &prepared, deadline, sent),
                receive_frames(wire_read, app_write, &prepared, deadline, received)
            )?;
            Ok(ShapingStats {
                sent: send,
                received: recv,
            })
        };
        let result = timeout_at(deadline, work).await.map_err(|_| timed_out())?;
        if Instant::now() >= deadline {
            return Err(timed_out());
        }
        result
    })?;
    Ok(AdaptiveStream {
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
    io::Error::new(
        io::ErrorKind::TimedOut,
        "adaptive original deadline exceeded",
    )
}
fn bin(p: &PreparedChannel, length: usize) -> io::Result<usize> {
    p.settings
        .length_bin_upper
        .iter()
        .position(|upper| length <= usize::from(*upper))
        .ok_or_else(|| bad("payload outside declared causal bins"))
}
fn header(
    p: &PreparedChannel,
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
fn debit(stats: &mut DirectionStats, body: usize, config: &AdaptiveSettings) -> io::Result<()> {
    let bytes = (OVERHEAD + body) as u64;
    let new = stats
        .wire_bytes
        .checked_add(bytes)
        .ok_or_else(|| bad("adaptive wire overflow"))?;
    if new > config.max_wire_bytes {
        return Err(bad("adaptive wire budget exhausted"));
    }
    stats.wire_bytes = new;
    stats.frames += 1;
    Ok(())
}
fn io_deadline(config: &AdaptiveSettings, original: Instant) -> Instant {
    original.min(Instant::now() + Duration::from_millis(u64::from(config.io_timeout_ms)))
}
async fn checked<T, F: Future<Output = io::Result<T>>>(
    deadline: Instant,
    work: F,
) -> io::Result<T> {
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
    p: &PreparedChannel,
    original: Instant,
    end: Arc<Completion>,
) -> io::Result<DirectionStats> {
    let mut stats = DirectionStats::default();
    let mut sequence = 0_u64;
    let mut payload = vec![0; p.settings.payload_bytes()];
    loop {
        let length = checked(original, app.read(&mut payload)).await?;
        if length == 0 {
            debit(&mut stats, 0, &p.settings)?;
            let h = header(p, sequence, 0, u8::MAX, true);
            let d = digest(&h, &[]);
            let due = io_deadline(&p.settings, original);
            checked(due, async {
                wire.write_all(&h).await?;
                wire.write_all(&d).await?;
                wire.flush().await?;
                wire.shutdown().await
            })
            .await?;
            end.finish();
            return Ok(stats);
        }
        let observation = bin(p, length)?;
        let selected = p
            .channel
            .sample_observable(observation, &mut OsRng)
            .map_err(|_| io::Error::other("adaptive entropy or channel refusal"))?;
        let action = &p.settings.actions[selected];
        let mut body = vec![0; usize::from(action.padded_bytes)];
        OsRng
            .try_fill_bytes(&mut body)
            .map_err(|_| io::Error::other("adaptive padding entropy unavailable"))?;
        body[..length].copy_from_slice(&payload[..length]);
        let h = header(p, sequence, length, selected as u8, false);
        let d = digest(&h, &body);
        debit(&mut stats, body.len(), &p.settings)?;
        checked(original, async {
            tokio::time::sleep(Duration::from_millis(u64::from(action.delay_ms))).await;
            Ok(())
        })
        .await?;
        let due = io_deadline(&p.settings, original);
        checked(due, async {
            wire.write_all(&h).await?;
            wire.write_all(&body).await?;
            wire.write_all(&d).await?;
            wire.flush().await
        })
        .await?;
        stats.data_bytes += length as u64;
        stats.padding_bytes += (body.len() - length) as u64;
        sequence = sequence
            .checked_add(1)
            .ok_or_else(|| bad("adaptive sequence exhausted"))?;
    }
}

async fn receive_frames<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut wire: R,
    mut app: W,
    p: &PreparedChannel,
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
            return Err(bad("adaptive profile, format or sequence mismatch"));
        }
        let length = usize::from(u16::from_be_bytes([h[14], h[15]]));
        let body_len = match h[4] {
            0 => {
                if length == 0 {
                    return Err(bad("adaptive empty data frame"));
                }
                let action = p
                    .settings
                    .actions
                    .get(usize::from(h[5]))
                    .ok_or_else(|| bad("adaptive action outside profile"))?;
                let observation = bin(p, length)?;
                if action.padded_bytes < p.settings.length_bin_upper[observation] {
                    return Err(bad("adaptive noncausal shrinking action"));
                }
                usize::from(action.padded_bytes)
            }
            1 if length == 0 && h[5] == u8::MAX => 0,
            _ => return Err(bad("adaptive invalid terminal frame")),
        };
        debit(&mut stats, body_len, &p.settings)?;
        let mut body = vec![0; body_len];
        let mut received = [0; DIGEST];
        checked(due, async {
            wire.read_exact(&mut body).await?;
            wire.read_exact(&mut received).await?;
            Ok(())
        })
        .await?;
        if digest(&h, &body).ct_eq(&received).unwrap_u8() != 1 {
            return Err(bad("adaptive frame consistency mismatch"));
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
            .ok_or_else(|| bad("adaptive sequence exhausted"))?;
    }
}

#[cfg(test)]
#[path = "adaptive_idle_receive_tests.rs"]
mod idle_receive_tests;
#[cfg(test)]
#[path = "adaptive_channel_tests.rs"]
mod tests;
