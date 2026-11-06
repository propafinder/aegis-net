//! Finite BIT-TRAPS independent-service authenticated byte-stream consumer.
//! Ideal inner size transcript is independent of arrivals; refusal, timing,
//! transport framing, keys and finite tail require separate whole-wire analysis.
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305,
};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    io,
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::{sleep_until, timeout_at, Instant},
};
use zeroize::{Zeroize, Zeroizing};
const DOMAIN: &[u8] = b"aegis.bittraps.independent-service.v1";
const OVERHEAD: usize = 24;
/// Canonical public finite service distribution, validated on every deserialize.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "BitTrapsSettings", into = "BitTrapsSettings")]
pub struct BitTrapsConfig {
    slots: u32,
    cadence: Duration,
    io_timeout: Duration,
    queue_cap: usize,
    release_cap: usize,
    service: Vec<(usize, u32)>,
    weight: u32,
    descriptor: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BitTrapsSettings {
    pub slots: u32,
    pub cadence_ms: u64,
    pub io_timeout_ms: u64,
    pub queue_cap: usize,
    /// Ascending unique service-byte sizes with positive integer weights.
    pub service: Vec<(usize, u32)>,
}
impl TryFrom<BitTrapsSettings> for BitTrapsConfig {
    type Error = io::Error;
    fn try_from(s: BitTrapsSettings) -> io::Result<Self> {
        Self::new(
            s.slots,
            Duration::from_millis(s.cadence_ms),
            Duration::from_millis(s.io_timeout_ms),
            s.queue_cap,
            s.service,
        )
    }
}
impl From<BitTrapsConfig> for BitTrapsSettings {
    fn from(p: BitTrapsConfig) -> Self {
        Self {
            slots: p.slots,
            cadence_ms: p.cadence.as_millis() as u64,
            io_timeout_ms: p.io_timeout.as_millis() as u64,
            queue_cap: p.queue_cap,
            service: p.service,
        }
    }
}
impl BitTrapsConfig {
    pub fn new(
        slots: u32,
        cadence: Duration,
        io_timeout: Duration,
        queue_cap: usize,
        service: Vec<(usize, u32)>,
    ) -> io::Result<Self> {
        if !(1..=256).contains(&slots)
            || cadence < Duration::from_millis(1)
            || !cadence.as_nanos().is_multiple_of(1_000_000)
            || io_timeout.is_zero()
            || io_timeout > cadence
            || !io_timeout.as_nanos().is_multiple_of(1_000_000)
            || cadence
                .checked_mul(slots)
                .is_none_or(|h| h > Duration::from_secs(60))
            || !(1..=1_048_576).contains(&queue_cap)
            || service.is_empty()
            || service.len() > 64
            || service
                .iter()
                .any(|(s, w)| *s > 65536 - OVERHEAD || *w == 0)
            || service.windows(2).any(|s| s[0].0 >= s[1].0)
        {
            return Err(invalid());
        }
        let weight = service
            .iter()
            .try_fold(0u32, |a, (_, w)| a.checked_add(*w))
            .ok_or_else(invalid)?;
        let release_cap = service.last().ok_or_else(invalid)?.0;
        let mut h = Sha256::new();
        h.update(DOMAIN);
        h.update(slots.to_be_bytes());
        h.update((cadence.as_millis() as u64).to_be_bytes());
        h.update((io_timeout.as_millis() as u64).to_be_bytes());
        h.update((queue_cap as u64).to_be_bytes());
        for (s, w) in &service {
            h.update((*s as u32).to_be_bytes());
            h.update(w.to_be_bytes());
        }
        Ok(Self {
            slots,
            cadence,
            io_timeout,
            queue_cap,
            release_cap,
            service,
            weight,
            descriptor: h.finalize().into(),
        })
    }
    pub fn descriptor_sha256(&self) -> [u8; 32] {
        self.descriptor
    }
    pub fn horizon(&self) -> Duration {
        self.cadence * self.slots
    }
    pub fn slots(&self) -> u32 {
        self.slots
    }
    pub fn queue_capacity(&self) -> usize {
        self.queue_cap
    }
    pub fn release_capacity(&self) -> usize {
        self.release_cap
    }
    pub fn worst_wire_bytes(&self) -> u64 {
        self.slots as u64 * (self.release_cap + OVERHEAD) as u64
    }
    fn sample<G: RngCore + CryptoRng>(&self, rng: &mut G, deadline: Instant) -> io::Result<usize> {
        let total = self.weight as u64;
        let threshold = total.wrapping_neg() % total;
        for _ in 0..128 {
            if Instant::now() >= deadline {
                return Err(timed());
            }
            let mut bytes = Zeroizing::new([0; 8]);
            rng.try_fill_bytes(bytes.as_mut())
                .map_err(|_| io::Error::other("BIT-TRAPS entropy unavailable"))?;
            if Instant::now() >= deadline {
                return Err(timed());
            }
            let word = u64::from_le_bytes(*bytes);
            if word < threshold {
                continue;
            }
            let mut n = word % total;
            for (s, w) in &self.service {
                if n < *w as u64 {
                    return Ok(*s);
                }
                n -= *w as u64;
            }
            return Err(invalid());
        }
        Err(io::Error::other("BIT-TRAPS public sampling fuel exhausted"))
    }
}
/// ONE externally fresh direction/epoch seed. No Clone/Debug/serialization.
/// Caller must prevent reuse across restarts/backups; consumed on failure too.
pub struct BitTrapsMaterial {
    seed: Zeroizing<[u8; 32]>,
}
impl BitTrapsMaterial {
    pub fn from_preprovisioned(seed: Zeroizing<[u8; 32]>) -> Self {
        Self { seed }
    }
}
struct DerivedMaterial {
    key: Zeroizing<[u8; 32]>,
    prefix: Zeroizing<[u8; 8]>,
}
impl DerivedMaterial {
    fn derive(material: BitTrapsMaterial, profile: &BitTrapsConfig) -> io::Result<Self> {
        let hk = hkdf::Hkdf::<Sha256>::new(Some(&profile.descriptor), material.seed.as_ref());
        let mut b = Zeroizing::new([0; 40]);
        hk.expand(DOMAIN, b.as_mut()).map_err(|_| invalid())?;
        let mut key = Zeroizing::new([0; 32]);
        key.copy_from_slice(&b[..32]);
        let mut prefix = Zeroizing::new([0; 8]);
        prefix.copy_from_slice(&b[32..]);
        Ok(Self { key, prefix })
    }
    fn nonce(&self, index: u32) -> Zeroizing<[u8; 12]> {
        let mut n = Zeroizing::new([0; 12]);
        n[..8].copy_from_slice(self.prefix.as_ref());
        n[8..].copy_from_slice(&index.to_be_bytes());
        n
    }
}
pub struct BitTrapsSession {
    profile: BitTrapsConfig,
    material: DerivedMaterial,
}
#[derive(Debug)]
pub struct BitTrapsReceipt {
    pub wire_bytes: u64,
    pub padding_bytes: u64,
    pub delivered_input_bytes: u64,
    pub pending_bytes: usize,
    pub input_eof_observed: bool,
}
impl BitTrapsSession {
    pub fn new(profile: BitTrapsConfig, material: BitTrapsMaterial) -> io::Result<Self> {
        let material = DerivedMaterial::derive(material, &profile)?;
        Ok(Self { profile, material })
    }
    /// Owned finite sender: collect live FIFO bytes between public ticks, emit
    /// exactly slots records including padding after input EOF. An unserved tail
    /// remains a local receipt, never an extra data-dependent drain/END record.
    /// Carrier must already be authenticated; fresh material is per direction.
    pub async fn send<R, W>(
        self,
        input: R,
        transport: W,
        deadline: Instant,
    ) -> io::Result<BitTrapsReceipt>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        self.send_with_rng(input, transport, deadline, &mut rand::rngs::OsRng)
            .await
    }
    pub async fn send_with_rng<R, W, G>(
        self,
        mut input: R,
        mut transport: W,
        deadline: Instant,
        rng: &mut G,
    ) -> io::Result<BitTrapsReceipt>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
        G: RngCore + CryptoRng,
    {
        #[cfg(windows)]
        let _timer_resolution = super::windows_timer_resolution::WindowsTimerResolution::acquire()?;
        let start = Instant::now();
        let end = start
            .checked_add(self.profile.horizon())
            .ok_or_else(invalid)?;
        if end
            .checked_add(self.profile.io_timeout)
            .ok_or_else(invalid)?
            > deadline
        {
            return Err(phase_error(
                io::ErrorKind::TimedOut,
                "BIT-TRAPS sender epoch admission expired",
            ));
        }
        let mut q = SecretQueue::new(self.profile.queue_cap);
        let mut eof = false;
        let mut wire = 0;
        let (mut padding, mut delivered) = (0, 0);
        let cipher =
            ChaCha20Poly1305::new_from_slice(self.material.key.as_ref()).map_err(|_| invalid())?;
        for index in 0..self.profile.slots {
            let tick = start + self.profile.cadence * (index + 1);
            let selected = self
                .profile
                .sample(rng, tick.min(deadline))
                .map_err(|e| phase_error(e.kind(), "BIT-TRAPS sampling failed"))?; // independent of input and queue, before application reads
            let mut buf = Zeroizing::new(vec![0u8; self.profile.queue_cap.min(4096)]);
            #[cfg(test)]
            let mut last_input_wait = None;
            while !eof && q.bytes.len() < q.cap && Instant::now() < tick {
                let free = (q.cap - q.bytes.len()).min(buf.len());
                // Timeout polls its inner future before its timer. Do not
                // consume input when an expired wakeup ends this public slot.
                let read = std::future::poll_fn(|cx| {
                    use std::{pin::Pin, task::Poll};
                    if Instant::now() >= tick {
                        return Poll::Ready(Ok(None));
                    }
                    let mut read_buf = tokio::io::ReadBuf::new(&mut buf[..free]);
                    let result = Pin::new(&mut input).poll_read(cx, &mut read_buf);
                    // A poll begun on time that itself crosses the tick still
                    // fails; this does not legitimize a blocking application.
                    if Instant::now() >= tick {
                        return Poll::Ready(Err(phase_error(
                            io::ErrorKind::TimedOut,
                            "BIT-TRAPS input poll exceeded public tick",
                        )));
                    }
                    match result {
                        Poll::Pending => Poll::Pending,
                        Poll::Ready(Err(error)) => Poll::Ready(Err(phase_error(
                            error.kind(),
                            "BIT-TRAPS input read failed",
                        ))),
                        Poll::Ready(Ok(())) => Poll::Ready(Ok(Some(read_buf.filled().len()))),
                    }
                });
                #[cfg(test)]
                let input_entered = Instant::now();
                let read_result = timeout_at(tick, read).await;
                #[cfg(test)]
                {
                    last_input_wait = Some((input_entered, Instant::now(), read_result.is_err()));
                }
                match read_result {
                    Err(_) => break,
                    Ok(Ok(None)) => break,
                    Ok(Err(error)) => return Err(error),
                    Ok(Ok(Some(n))) => {
                        if Instant::now() >= tick {
                            return Err(phase_error(
                                io::ErrorKind::TimedOut,
                                "BIT-TRAPS input poll exceeded public tick",
                            ));
                        }
                        if n == 0 {
                            eof = true;
                        } else {
                            q.enqueue(&buf[..n])?;
                            buf[..n].zeroize();
                        }
                    }
                }
            }
            #[cfg(test)]
            let sleep_entered = Instant::now();
            wait_for_public_tick(tick).await;
            #[cfg(test)]
            let sleep_returned = Instant::now();
            if Instant::now() > tick + self.profile.io_timeout || Instant::now() >= deadline {
                #[cfg(test)]
                {
                    // Test-only bounded, public-slot attribution. The bracket
                    // includes scheduling/observer work, not kernel-only time.
                    // Original tick, allowance and refusal checks stay intact.
                    let ns = |later: Instant, earlier: Instant| {
                        later
                            .saturating_duration_since(earlier)
                            .as_nanos()
                            .min(u128::from(u64::MAX)) as u64
                    };
                    eprintln!(
                        "bittraps_public_tick_diagnostics={}",
                        serde_json::json!({
                            "slot": index,
                            "slots": self.profile.slots,
                            "cadence_ns": self.profile.cadence.as_nanos() as u64,
                            "write_allowance_ns": self.profile.io_timeout.as_nanos() as u64,
                            "sleep_entered_after_tick": sleep_entered >= tick,
                            "sleep_bracket_ns": ns(sleep_returned, sleep_entered),
                            "tick_lateness_at_sleep_return_ns": ns(sleep_returned, tick),
                            "original_deadline_reached_at_sleep_return": sleep_returned >= deadline,
                            "last_input_await": last_input_wait.map(|(entered, returned, timed_out)| serde_json::json!({
                                "bracket_ns": ns(returned, entered),
                                "tick_lateness_at_return_ns": ns(returned, tick),
                                "timeout_result": timed_out,
                            })),
                            "native_only_latency_cause_proven": false,
                        })
                    );
                }
                return Err(phase_error(
                    io::ErrorKind::TimedOut,
                    "BIT-TRAPS public tick exceeded write allowance",
                ));
            }
            let real = q.bytes.len().min(selected);
            padding += (selected - real) as u64;
            delivered += real as u64;
            let plain = q.frame(selected);
            let aad = aad(&self.profile, index, selected);
            let ciphertext = cipher
                .encrypt(
                    self.material.nonce(index).as_ref().into(),
                    Payload {
                        msg: plain.as_ref(),
                        aad: &aad,
                    },
                )
                .map_err(|_| invalid())?;
            let limit = (tick + self.profile.io_timeout).min(deadline);
            timeout_at(limit, async {
                transport
                    .write_all(&(selected as u32).to_be_bytes())
                    .await?;
                transport.write_all(&ciphertext).await?;
                transport.flush().await
            })
            .await
            .map_err(|_| phase_error(io::ErrorKind::TimedOut, "BIT-TRAPS wire write timed out"))?
            .map_err(|e| phase_error(e.kind(), "BIT-TRAPS wire write failed"))?;
            // Synchronous Ready after the deadline is not timely completion.
            if Instant::now() >= limit {
                return Err(phase_error(
                    io::ErrorKind::TimedOut,
                    "BIT-TRAPS wire write poll exceeded allowance",
                ));
            }
            wire += (selected + OVERHEAD) as u64;
        }
        Ok(BitTrapsReceipt {
            padding_bytes: padding,
            delivered_input_bytes: delivered,
            wire_bytes: wire,
            pending_bytes: q.bytes.len(),
            input_eof_observed: eof,
        })
    }
    /// Complete-frame authentication before delivery; EOF before public slots is
    /// a failure. Original caller deadline is never renewed per frame.
    pub async fn receive<R>(self, transport: R, deadline: Instant) -> io::Result<Zeroizing<Vec<u8>>>
    where
        R: AsyncRead + Unpin,
    {
        let mut out = SecretOutput(Zeroizing::new(Vec::new()));
        self.receive_into(transport, &mut out, deadline).await?;
        Ok(out.0)
    }
    pub async fn receive_into<R, W>(
        self,
        mut transport: R,
        mut output: W,
        deadline: Instant,
    ) -> io::Result<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        if Instant::now() >= deadline {
            return Err(phase_error(
                io::ErrorKind::TimedOut,
                "BIT-TRAPS receiver deadline expired",
            ));
        }
        let cipher =
            ChaCha20Poly1305::new_from_slice(self.material.key.as_ref()).map_err(|_| invalid())?;
        let mut delivered = 0usize;
        for index in 0..self.profile.slots {
            let mut header = [0; 4];
            timeout_at(deadline, transport.read_exact(&mut header))
                .await
                .map_err(|_| {
                    phase_error(
                        io::ErrorKind::TimedOut,
                        "BIT-TRAPS receiver header timed out",
                    )
                })?
                .map_err(|e| phase_error(e.kind(), "BIT-TRAPS receiver header failed"))?;
            if Instant::now() >= deadline {
                return Err(phase_error(
                    io::ErrorKind::TimedOut,
                    "BIT-TRAPS receiver header poll exceeded deadline",
                ));
            }
            let selected = u32::from_be_bytes(header) as usize;
            if !self.profile.service.iter().any(|(s, _)| *s == selected) {
                return Err(invalid_data());
            }
            let mut body = vec![0; selected + 20];
            timeout_at(deadline, transport.read_exact(&mut body))
                .await
                .map_err(|_| {
                    phase_error(io::ErrorKind::TimedOut, "BIT-TRAPS receiver body timed out")
                })?
                .map_err(|e| phase_error(e.kind(), "BIT-TRAPS receiver body failed"))?;
            if Instant::now() >= deadline {
                return Err(phase_error(
                    io::ErrorKind::TimedOut,
                    "BIT-TRAPS receiver body poll exceeded deadline",
                ));
            }
            let aad = aad(&self.profile, index, selected);
            let plain = Zeroizing::new(
                cipher
                    .decrypt(
                        self.material.nonce(index).as_ref().into(),
                        Payload {
                            msg: &body,
                            aad: &aad,
                        },
                    )
                    .map_err(|_| invalid_data())?,
            );
            let length =
                u32::from_be_bytes(plain[..4].try_into().map_err(|_| invalid_data())?) as usize;
            if plain.len() != selected + 4 || length > selected {
                return Err(invalid_data());
            }
            // Bound output even if the peer uses every public slot at capacity.
            if delivered
                .checked_add(length)
                .is_none_or(|n| n > self.profile.slots as usize * self.profile.release_cap)
            {
                return Err(invalid_data());
            }
            timeout_at(deadline, async {
                output.write_all(&plain[4..4 + length]).await?;
                output.flush().await
            })
            .await
            .map_err(|_| {
                phase_error(
                    io::ErrorKind::TimedOut,
                    "BIT-TRAPS receiver output timed out",
                )
            })?
            .map_err(|e| phase_error(e.kind(), "BIT-TRAPS receiver output failed"))?;
            if Instant::now() >= deadline {
                return Err(phase_error(
                    io::ErrorKind::TimedOut,
                    "BIT-TRAPS receiver output poll exceeded deadline",
                ));
            }
            delivered += length;
        }
        Ok(())
    }
}
struct SecretOutput(Zeroizing<Vec<u8>>);
impl AsyncWrite for SecretOutput {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        b: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        self.0.extend_from_slice(b);
        std::task::Poll::Ready(Ok(b.len()))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}
/// Finite installed-carrier consumer. The transport is owned and already
/// authenticated; caller supplies two distinct fresh direction materials after
/// matching the complete public profile at both peers. There is no fallback.
pub fn attach_authenticated<S>(
    transport: S,
    profile: BitTrapsConfig,
    send_material: BitTrapsMaterial,
    receive_material: BitTrapsMaterial,
    deadline: Instant,
) -> io::Result<BitTrapsStream>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    attach_authenticated_owned(
        transport,
        profile,
        send_material,
        receive_material,
        deadline,
        None,
    )
}

pub(crate) fn attach_authenticated_owned<S>(
    transport: S,
    profile: BitTrapsConfig,
    send_material: BitTrapsMaterial,
    receive_material: BitTrapsMaterial,
    deadline: Instant,
    owner: Option<&super::worker_owner::ShapingCleanupOwner>,
) -> io::Result<BitTrapsStream>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    if bool::from(
        send_material
            .seed
            .as_ref()
            .ct_eq(receive_material.seed.as_ref()),
    ) {
        return Err(invalid());
    }
    let required = profile
        .horizon()
        .checked_add(profile.io_timeout)
        .ok_or_else(invalid)?;
    if Instant::now().checked_add(required).ok_or_else(invalid)? > deadline {
        return Err(timed());
    }
    let (app, worker_app) = tokio::io::duplex(profile.queue_cap.min(65_536));
    let (input, output) = tokio::io::split(worker_app);
    let (carrier_read, carrier_write) = tokio::io::split(transport);
    let worker = super::worker_owner::spawn(owner, async move {
        let send = BitTrapsSession::new(profile.clone(), send_material)?.send(
            input,
            carrier_write,
            deadline,
        );
        let receive = BitTrapsSession::new(profile, receive_material)?.receive_into(
            carrier_read,
            output,
            deadline,
        );
        let sending = async {
            send.await
                .map_err(|e| retain_phase_or_redact(e, "BIT-TRAPS sender failed"))
        };
        let receiving = async {
            receive
                .await
                .map_err(|e| retain_phase_or_redact(e, "BIT-TRAPS receiver failed"))
        };
        let (sent, ()) = tokio::try_join!(sending, receiving)?;
        // Real unserved bytes cannot masquerade as a clean application EOF.
        if sent.pending_bytes != 0 || !sent.input_eof_observed {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "BIT-TRAPS public epoch ended with an unserved tail",
            ));
        }
        Ok(sent)
    })?;
    Ok(BitTrapsStream {
        app,
        worker: Some(worker),
        completed: None,
        failure: None,
    })
}
/// Dropping/aborting the stream retires its one owned worker and carrier halves.
/// Cancellation is not proof of remote delivery or privacy budget recovery.
pub struct BitTrapsStream {
    app: tokio::io::DuplexStream,
    worker: Option<super::worker_owner::SharedWorker<BitTrapsReceipt>>,
    completed: Option<BitTrapsReceipt>,
    failure: Option<(io::ErrorKind, &'static str)>,
}
impl std::fmt::Debug for BitTrapsStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // DuplexStream Debug includes buffered application bytes; never delegate.
        f.debug_struct("BitTrapsStream").finish_non_exhaustive()
    }
}
impl BitTrapsStream {
    fn poll_worker(&mut self, cx: &mut std::task::Context<'_>) -> io::Result<()> {
        use std::{future::Future, pin::Pin, task::Poll};
        if let Some(worker) = self.worker.as_mut() {
            if let Poll::Ready(result) = Pin::new(worker).poll(cx) {
                self.worker = None;
                match result {
                    Ok(Ok(receipt)) => self.completed = Some(receipt),
                    Ok(Err(error)) => {
                        let message = error
                            .get_ref()
                            .and_then(|inner| inner.downcast_ref::<FailurePhase>())
                            .map_or("BIT-TRAPS owned worker failed", |phase| phase.0);
                        self.failure = Some((error.kind(), message));
                    }
                    Err(_) => {
                        self.failure =
                            Some((io::ErrorKind::Other, "BIT-TRAPS owned worker cancelled"))
                    }
                }
            }
        }
        if let Some((kind, message)) = self.failure {
            return Err(io::Error::new(kind, message));
        }
        Ok(())
    }
    /// Call after consuming peer EOF, or read concurrently with half-close.
    /// Completion includes the fixed public dummy horizon and both directions.
    pub async fn finish(mut self) -> io::Result<BitTrapsReceipt> {
        self.app.shutdown().await?;
        std::future::poll_fn(|cx| {
            if let Err(e) = self.poll_worker(cx) {
                return std::task::Poll::Ready(Err(e));
            }
            match self.completed.take() {
                Some(receipt) => std::task::Poll::Ready(Ok(receipt)),
                None => std::task::Poll::Pending,
            }
        })
        .await
    }
}
// The private typed payload admits only internal static phase labels. Never
// preserve or format arbitrary underlying transport/application error text.
#[derive(Debug)]
struct FailurePhase(&'static str);
impl std::fmt::Display for FailurePhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for FailurePhase {}
fn phase_error(kind: io::ErrorKind, phase: &'static str) -> io::Error {
    io::Error::new(kind, FailurePhase(phase))
}
fn retain_phase_or_redact(error: io::Error, fallback: &'static str) -> io::Error {
    if error
        .get_ref()
        .is_some_and(|inner| inner.is::<FailurePhase>())
    {
        error
    } else {
        phase_error(error.kind(), fallback)
    }
}
impl AsyncRead for BitTrapsStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        use std::{pin::Pin, task::Poll};
        if let Err(e) = self.poll_worker(cx) {
            return Poll::Ready(Err(e));
        }
        let before = buf.filled().len();
        match Pin::new(&mut self.app).poll_read(cx, buf) {
            Poll::Ready(Ok(()))
                if buf.filled().len() == before && self.worker.is_some() && buf.remaining() > 0 =>
            {
                Poll::Pending
            }
            result => result,
        }
    }
}
impl AsyncWrite for BitTrapsStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        if let Err(e) = self.poll_worker(cx) {
            return std::task::Poll::Ready(Err(e));
        }
        if self.completed.is_some() {
            return std::task::Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "BIT-TRAPS public epoch completed",
            )));
        }
        std::pin::Pin::new(&mut self.app).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        if let Err(e) = self.poll_worker(cx) {
            return std::task::Poll::Ready(Err(e));
        }
        std::pin::Pin::new(&mut self.app).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        use std::task::Poll;
        if let Err(e) = self.poll_worker(cx) {
            return Poll::Ready(Err(e));
        }
        if let Poll::Ready(result) = std::pin::Pin::new(&mut self.app).poll_shutdown(cx) {
            if let Err(e) = result {
                return Poll::Ready(Err(e));
            }
            if self.worker.is_none() {
                return Poll::Ready(Ok(()));
            }
        }
        Poll::Pending
    }
}
impl Drop for BitTrapsStream {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            worker.abort();
        }
    }
}

fn aad(profile: &BitTrapsConfig, index: u32, selected: usize) -> Vec<u8> {
    let mut out = DOMAIN.to_vec();
    out.extend_from_slice(&profile.descriptor);
    out.extend_from_slice(&index.to_be_bytes());
    out.extend_from_slice(&(selected as u32).to_be_bytes());
    out
}
struct SecretQueue {
    bytes: VecDeque<u8>,
    cap: usize,
}
impl SecretQueue {
    fn new(cap: usize) -> Self {
        Self {
            bytes: VecDeque::with_capacity(cap),
            cap,
        }
    }
    fn enqueue(&mut self, b: &[u8]) -> io::Result<()> {
        if self
            .bytes
            .len()
            .checked_add(b.len())
            .is_none_or(|n| n > self.cap)
        {
            return Err(invalid());
        }
        self.bytes.extend(b);
        Ok(())
    }
    fn frame(&mut self, selected: usize) -> Zeroizing<Vec<u8>> {
        let n = self.bytes.len().min(selected);
        let mut out = Zeroizing::new(vec![0; selected + 4]);
        out[..4].copy_from_slice(&(n as u32).to_be_bytes());
        for b in &mut out[4..4 + n] {
            let front = self.bytes.front_mut().expect("admitted queue length");
            *b = *front;
            front.zeroize(); // clear the backing cell before it leaves the deque
            self.bytes.pop_front();
        }
        out
    }
}
impl Drop for SecretQueue {
    fn drop(&mut self) {
        // No relocation into an untracked gap while clearing remaining bytes.
        let (first, second) = self.bytes.as_mut_slices();
        first.zeroize();
        second.zeroize();
    }
}

/// Finite first-order Markov source and independent service law. Enumerates whole
/// joint sequences; no single-letter MI or stationary information-rate shortcut.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FiniteStreamModel {
    pub horizon: usize,
    pub arrival_sizes: Vec<usize>,
    pub initial: Vec<f64>,
    pub transition: Vec<Vec<f64>>,
    pub service: Vec<(usize, f64)>,
    pub queue_cap: usize,
    pub padding: bool,
}
#[derive(Debug, Clone, serde::Serialize)]
pub struct FiniteStreamReport {
    pub scope: &'static str,
    pub horizon: usize,
    pub enumerated_paths: usize,
    pub probability_mass: f64,
    pub joint_sequence_mutual_information_bits: f64,
    pub bits_per_slot_not_stationary_rate: f64,
    pub expected_padding_bytes: f64,
    pub expected_queue_area_byte_slots: f64,
    pub expected_tail_bytes: f64,
    pub overflow_probability: f64,
    pub overflow_reachable: bool,
}
fn pmf(p: &[f64]) -> bool {
    !p.is_empty()
        && p.iter().all(|x| x.is_finite() && *x >= 0.0)
        && (p.iter().sum::<f64>() - 1.0).abs() < 1e-10
}
/// Exhaustive finite path enumeration with qualified floating arithmetic. Output
/// retains an absorbing overflow sentinel and refuses unsupported underflow.
pub fn finite_stream_law(m: &FiniteStreamModel) -> io::Result<FiniteStreamReport> {
    let a = m.arrival_sizes.len();
    let b = m.service.len();
    if !(1..=6).contains(&m.horizon)
        || !(1..=4).contains(&a)
        || !(1..=4).contains(&b)
        || m.initial.len() != a
        || !pmf(&m.initial)
        || m.transition.len() != a
        || m.transition.iter().any(|r| r.len() != a || !pmf(r))
        || m.arrival_sizes.iter().any(|n| *n > 256)
        || m.service.iter().any(|(n, _)| *n > 256)
        || !pmf(&m.service.iter().map(|(_, p)| *p).collect::<Vec<_>>())
        || m.queue_cap > 4096
        || m.arrival_sizes.windows(2).any(|w| w[0] >= w[1])
        || m.service.windows(2).any(|w| w[0].0 >= w[1].0)
    {
        return Err(invalid());
    }
    let paths = (a * b)
        .checked_pow(m.horizon as u32)
        .filter(|n| *n <= 262144)
        .ok_or_else(invalid)?;
    let mut joint: BTreeMap<(Vec<usize>, Vec<usize>), f64> = BTreeMap::new();
    let (mut padding, mut area, mut tail, mut overflow) = (0.0, 0.0, 0.0, 0.0);
    let mut overflow_reachable = false;
    for encoded in 0..paths {
        let (mut code, mut p, mut q, mut previous, mut failed) =
            (encoded, 1.0, 0usize, 0usize, false);
        let (mut av, mut dv) = (Vec::new(), Vec::new());
        let mut supported = true;
        let (mut z, mut x) = (0usize, 0usize);
        for slot in 0..m.horizon {
            let ai = code % a;
            code /= a;
            let si = code % b;
            code /= b;
            let arrival_probability = if slot == 0 {
                m.initial[ai]
            } else {
                m.transition[previous][ai]
            };
            supported &= arrival_probability > 0.0 && m.service[si].1 > 0.0;
            p *= arrival_probability;
            p *= m.service[si].1;
            previous = ai;
            av.push(m.arrival_sizes[ai]);
            if failed {
                dv.push(usize::MAX);
                continue;
            }
            q += m.arrival_sizes[ai];
            if q > m.queue_cap {
                failed = true;
                dv.push(usize::MAX);
                continue;
            }
            x += q;
            let service = m.service[si].0;
            let real = q.min(service);
            q -= real;
            z += if m.padding { service - real } else { 0 };
            dv.push(if m.padding { service } else { real });
        }
        if !supported {
            continue;
        }
        overflow_reachable |= failed; // positivity is independent of float mass
        if p == 0.0 || !p.is_finite() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "BIT-TRAPS supported path probability is not representable",
            ));
        }
        *joint.entry((av, dv)).or_default() += p;
        padding += p * z as f64;
        area += p * x as f64;
        tail += p * q as f64;
        overflow += p * f64::from(failed);
    }
    let (mut am, mut dm) = (BTreeMap::new(), BTreeMap::new());
    for ((a, d), p) in &joint {
        *am.entry(a.clone()).or_insert(0.0) += p;
        *dm.entry(d.clone()).or_insert(0.0) += p;
    }
    let mass: f64 = joint.values().sum();
    if (mass - 1.0).abs() > 1e-8 {
        return Err(invalid());
    }
    let mut mi = 0.0;
    for ((a, d), p) in &joint {
        let log_ratio = p.log2() - am[a].log2() - dm[d].log2();
        let term = p * log_ratio;
        if !log_ratio.is_finite() || !term.is_finite() || (log_ratio != 0.0 && term == 0.0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "BIT-TRAPS mutual-information arithmetic is not representable",
            ));
        }
        mi += term;
    }
    if !mi.is_finite() {
        return Err(invalid());
    }
    let mi = mi.max(0.0);
    Ok(FiniteStreamReport {
        scope: "finite Markov sequence joint law; overflow observable; no stationary rate theorem",
        horizon: m.horizon,
        enumerated_paths: paths,
        probability_mass: mass,
        joint_sequence_mutual_information_bits: mi,
        bits_per_slot_not_stationary_rate: mi / m.horizon as f64,
        expected_padding_bytes: padding,
        expected_queue_area_byte_slots: area,
        expected_tail_bytes: tail,
        overflow_probability: overflow,
        overflow_reachable,
    })
}
/// Exhaustive choice among a DECLARED finite grid, not an optimizer over all laws.
/// Tail/overflow limits stay explicit alongside average padding and queue costs.
pub fn optimize_service_grid(
    base: &FiniteStreamModel,
    candidates: &[Vec<(usize, f64)>],
    max_padding: f64,
    max_queue_area: f64,
    max_tail: f64,
) -> io::Result<(usize, FiniteStreamReport)> {
    if candidates.is_empty()
        || candidates.len() > 32
        || [max_padding, max_queue_area, max_tail]
            .iter()
            .any(|x| !x.is_finite() || *x < 0.0)
    {
        return Err(invalid());
    }
    let mut best: Option<(usize, FiniteStreamReport)> = None;
    for (i, c) in candidates.iter().enumerate() {
        let mut m = base.clone();
        m.service = c.clone();
        let r = finite_stream_law(&m)?;
        if r.expected_padding_bytes > max_padding
            || r.expected_queue_area_byte_slots > max_queue_area
            || r.expected_tail_bytes > max_tail
            || r.overflow_reachable
        {
            continue;
        }
        if best.as_ref().is_none_or(|(_, b)| {
            r.joint_sequence_mutual_information_bits
                < b.joint_sequence_mutual_information_bits - 1e-12
                || (r.joint_sequence_mutual_information_bits
                    - b.joint_sequence_mutual_information_bits)
                    .abs()
                    <= 1e-12
                    && r.expected_queue_area_byte_slots < b.expected_queue_area_byte_slots
        }) {
            best = Some((i, r));
        }
    }
    best.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "no declared BIT-TRAPS service candidate satisfies finite budgets",
        )
    })
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid BIT-TRAPS public profile",
    )
}
fn invalid_data() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "BIT-TRAPS frame admission refused",
    )
}
fn timed() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "BIT-TRAPS original deadline expired",
    )
}
async fn wait_for_public_tick(tick: Instant) {
    // A newly polled Tokio Sleep may yield/register a rounded timer even when
    // its Instant has already elapsed. The public tick already reached needs
    // no second wait; original post-wait write/session cutoffs remain below.
    if Instant::now() < tick {
        sleep_until(tick).await;
    }
}

#[cfg(test)]
#[path = "bittraps_tests.rs"]
mod tests;
