//! NetShaper-style finite Gaussian queue shaping for authenticated byte carriers.
//! The exact rational accountant describes the discrete-Gaussian reference model.
//! Integer CKS reference sampling uses exact rational arithmetic; bounded
//! refusal, entropy and network/error timing are NOT automatically certified DP.
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305,
};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use std::{collections::VecDeque, io, time::Duration};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::{sleep_until, timeout_at, Instant},
};
use zeroize::{Zeroize, Zeroizing};

const DOMAIN: &[u8] = b"aegis.netshaper.integer.v1";
const OVERHEAD: usize = 24; // public size4, private payload length4, AEAD tag16
pub const NETSHAPER_SCOPE: &str = "integer discrete-Gaussian reference accounting; bounded-refusal/network transcript requires separate proof";

/// Public immutable settings agreed before entering the authenticated epoch.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "NetShaperConfig", into = "NetShaperConfig")]
pub struct NetShaperProfile {
    slots: u32,
    cadence: Duration,
    window: Duration,
    io_timeout: Duration,
    queue_cap: usize,
    release_cap: usize,
    sigma: u32,
    rho_limit_n: u128,
    rho_limit_d: u128,
    descriptor: [u8; 32],
}
/// Validated serde representation. Every input reconstructs and revalidates the
/// profile/descriptor; unknown fields and noncanonical rational strings refuse.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetShaperConfig {
    pub slots: u32,
    pub cadence_ms: u64,
    pub window_ms: u64,
    pub io_timeout_ms: u64,
    pub queue_cap: usize,
    pub release_cap: usize,
    pub sigma_bytes: u32,
    pub rho_limit_n: String,
    pub rho_limit_d: String,
}
fn canonical_integer(s: &str) -> io::Result<u128> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return Err(invalid());
    }
    s.parse().map_err(|_| invalid())
}
impl TryFrom<NetShaperConfig> for NetShaperProfile {
    type Error = io::Error;
    fn try_from(c: NetShaperConfig) -> io::Result<Self> {
        Self::new(
            c.slots,
            Duration::from_millis(c.cadence_ms),
            Duration::from_millis(c.window_ms),
            Duration::from_millis(c.io_timeout_ms),
            c.queue_cap,
            c.release_cap,
            c.sigma_bytes,
            canonical_integer(&c.rho_limit_n)?,
            canonical_integer(&c.rho_limit_d)?,
        )
    }
}
impl From<NetShaperProfile> for NetShaperConfig {
    fn from(p: NetShaperProfile) -> Self {
        Self {
            slots: p.slots,
            cadence_ms: p.cadence.as_millis() as u64,
            window_ms: p.window.as_millis() as u64,
            io_timeout_ms: p.io_timeout.as_millis() as u64,
            queue_cap: p.queue_cap,
            release_cap: p.release_cap,
            sigma_bytes: p.sigma,
            rho_limit_n: p.rho_limit_n.to_string(),
            rho_limit_d: p.rho_limit_d.to_string(),
        }
    }
}
impl NetShaperProfile {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        slots: u32,
        cadence: Duration,
        window: Duration,
        io_timeout: Duration,
        queue_cap: usize,
        release_cap: usize,
        sigma_bytes: u32,
        rho_limit_n: u128,
        rho_limit_d: u128,
    ) -> io::Result<Self> {
        let horizon = cadence.checked_mul(slots).ok_or_else(invalid)?;
        if !(1..=256).contains(&slots)
            || cadence < Duration::from_millis(1)
            || horizon > window
            || window > Duration::from_secs(60)
            || [cadence, window, io_timeout]
                .iter()
                .any(|d| d.subsec_nanos() % 1_000_000 != 0)
            || io_timeout.is_zero()
            || io_timeout > cadence
            || !(1..=1_048_576).contains(&queue_cap)
            || !(1..=65_536 - OVERHEAD).contains(&release_cap)
            || !(1..=1_048_576).contains(&sigma_bytes)
            || rho_limit_d == 0
        {
            return Err(invalid());
        }
        let n = u128::from(slots) * (queue_cap as u128).pow(2);
        let d = 2 * u128::from(sigma_bytes).pow(2);
        // Preflight ALL public slots. No data-dependent privacy-budget stop.
        if n.checked_mul(rho_limit_d).ok_or_else(invalid)?
            > rho_limit_n.checked_mul(d).ok_or_else(invalid)?
        {
            return Err(invalid());
        }
        let mut h = Sha256::new();
        h.update(DOMAIN);
        for bytes in [
            slots.to_be_bytes().to_vec(),
            cadence.as_nanos().to_be_bytes().to_vec(),
            window.as_nanos().to_be_bytes().to_vec(),
            io_timeout.as_nanos().to_be_bytes().to_vec(),
            (queue_cap as u64).to_be_bytes().to_vec(),
            (release_cap as u64).to_be_bytes().to_vec(),
            sigma_bytes.to_be_bytes().to_vec(),
            rho_limit_n.to_be_bytes().to_vec(),
            rho_limit_d.to_be_bytes().to_vec(),
        ] {
            h.update(bytes);
        }
        Ok(Self {
            slots,
            cadence,
            window,
            io_timeout,
            queue_cap,
            release_cap,
            sigma: sigma_bytes,
            rho_limit_n,
            rho_limit_d,
            descriptor: h.finalize().into(),
        })
    }
    pub fn descriptor_sha256(&self) -> [u8; 32] {
        self.descriptor
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
    pub fn horizon(&self) -> Duration {
        self.cadence * self.slots
    }
    pub fn neighboring_window(&self) -> Duration {
        self.window
    }
    pub fn worst_wire_bytes(&self) -> u64 {
        u64::from(self.slots) * (self.release_cap + OVERHEAD) as u64
    }
    pub fn accountant(&self) -> GaussianAccountant {
        GaussianAccountant {
            per_n: (self.queue_cap as u128).pow(2),
            denominator: 2 * u128::from(self.sigma).pow(2),
            numerator: 0,
            releases: 0,
            max_releases: self.slots,
            limit_n: self.rho_limit_n,
            limit_d: self.rho_limit_d,
        }
    }
}

/// No floating-point comparison or sampling admits a privacy budget. rho=numerator/denominator.
/// For the scalar integer discrete-Gaussian reference, RDP(alpha)<=alpha*rho,
/// alpha>1. Clipped query
/// lies in [0, queue_cap], so ANY conditional neighboring queue difference<=cap.
/// This universal bound does not assume timely Internet service or a TTL flush.
#[derive(Debug)]
pub struct GaussianAccountant {
    per_n: u128,
    denominator: u128,
    numerator: u128,
    releases: u32,
    max_releases: u32,
    limit_n: u128,
    limit_d: u128,
}
#[derive(Debug, Clone, serde::Serialize)]
pub struct GaussianReceipt {
    pub releases: u32,
    pub rho_numerator: String,
    pub rho_denominator: String,
    pub scope: &'static str,
}
impl GaussianAccountant {
    /// Spend before noise or emission, including entropy/I/O failure. No refund.
    pub fn charge(&mut self) -> io::Result<()> {
        if self.releases == self.max_releases {
            return Err(invalid());
        }
        let next = self.numerator.checked_add(self.per_n).ok_or_else(invalid)?;
        if next.checked_mul(self.limit_d).ok_or_else(invalid)?
            > self
                .limit_n
                .checked_mul(self.denominator)
                .ok_or_else(invalid)?
        {
            return Err(invalid());
        }
        self.numerator = next;
        self.releases += 1;
        Ok(())
    }
    pub fn receipt(&self) -> GaussianReceipt {
        GaussianReceipt {
            releases: self.releases,
            rho_numerator: self.numerator.to_string(),
            rho_denominator: self.denominator.to_string(),
            scope: NETSHAPER_SCOPE,
        }
    }
    /// Informational conversion for the IDEAL model; NOT bounded runtime transcript admission.
    pub fn ideal_epsilon_estimate(&self, delta: f64) -> io::Result<f64> {
        if !delta.is_finite() || !(0.0..1.0).contains(&delta) || delta == 0.0 {
            return Err(invalid());
        }
        let rho = self.numerator as f64 / self.denominator as f64;
        Ok(rho + 2.0 * (rho * (-delta.ln())).sqrt())
    }
}

/// Dedicated fresh key/prefix for ONE direction/epoch, consumed also on cancel.
/// Callers must prevent restart/backup reconstruction and account multiple epochs.
pub struct NetShaperMaterial {
    key: Zeroizing<[u8; 32]>,
    prefix: Zeroizing<[u8; 8]>,
}
impl NetShaperMaterial {
    pub fn from_preprovisioned(key: Zeroizing<[u8; 32]>, prefix: [u8; 8]) -> Self {
        Self {
            key,
            prefix: Zeroizing::new(prefix),
        }
    }
    fn nonce(&self, index: u32) -> Zeroizing<[u8; 12]> {
        let mut n = Zeroizing::new([0; 12]);
        n[..8].copy_from_slice(self.prefix.as_ref());
        n[8..].copy_from_slice(&index.to_be_bytes());
        n
    }
}
pub struct NetShaperSession {
    profile: NetShaperProfile,
    material: NetShaperMaterial,
}
#[derive(Debug)]
pub struct NetShaperReceipt {
    pub accounting: GaussianReceipt,
    pub wire_bytes: u64,
    /// LOCAL diagnostic only. Never include this secret-dependent value on wire.
    pub pending_bytes: usize,
    /// True only after an actual source read returned EOF, not merely empty FIFO.
    pub input_eof_observed: bool,
}
impl NetShaperSession {
    pub fn new(profile: NetShaperProfile, material: NetShaperMaterial) -> Self {
        Self { profile, material }
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
    ) -> io::Result<NetShaperReceipt>
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
    ) -> io::Result<NetShaperReceipt>
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
            return Err(timed());
        }
        let mut q = SecretQueue::new(self.profile.queue_cap);
        let mut eof = false;
        let mut wire = 0;
        let mut accounting = self.profile.accountant();
        let cipher =
            ChaCha20Poly1305::new_from_slice(self.material.key.as_ref()).map_err(|_| invalid())?;
        for index in 0..self.profile.slots {
            let tick = start + self.profile.cadence * (index + 1);
            accounting.charge()?; // before entropy, application reads or emission
            let noise = discrete_gaussian(self.profile.sigma, rng, Some(tick.min(deadline)))
                .map_err(|e| phase_error(e.kind(), "NetShaper sampling failed"))?;
            let mut buf = Zeroizing::new(vec![0u8; self.profile.queue_cap.min(4096)]);
            while !eof && q.bytes.len() < q.cap && Instant::now() < tick {
                let free = (q.cap - q.bytes.len()).min(buf.len());
                // Timeout polls its inner future before its timer. On a wakeup
                // at/after this public tick, never poll or consume input first:
                // end this slot's collection and retain the original schedule.
                let read = std::future::poll_fn(|cx| {
                    use std::{pin::Pin, task::Poll};
                    if Instant::now() >= tick {
                        return Poll::Ready(Ok(None));
                    }
                    let mut read_buf = tokio::io::ReadBuf::new(&mut buf[..free]);
                    let polled = Pin::new(&mut input).poll_read(cx, &mut read_buf);
                    // A poll begun on time that itself crosses the boundary is
                    // still a failure. This must not legitimize blocking reads.
                    if Instant::now() >= tick {
                        return Poll::Ready(Err(phase_error(
                            io::ErrorKind::TimedOut,
                            "NetShaper input poll exceeded public tick",
                        )));
                    }
                    match polled {
                        Poll::Pending => Poll::Pending,
                        Poll::Ready(Err(error)) => Poll::Ready(Err(phase_error(
                            error.kind(),
                            "NetShaper input read failed",
                        ))),
                        Poll::Ready(Ok(())) => Poll::Ready(Ok(Some(read_buf.filled().len()))),
                    }
                });
                match timeout_at(tick, read).await {
                    Err(_) => break,
                    Ok(Ok(None)) => break,
                    Ok(Err(error)) => return Err(error),
                    Ok(Ok(Some(n))) => {
                        if Instant::now() >= tick {
                            return Err(phase_error(
                                io::ErrorKind::TimedOut,
                                "NetShaper input poll exceeded public tick",
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
            wait_for_public_tick(tick).await;
            if Instant::now() > tick + self.profile.io_timeout || Instant::now() >= deadline {
                return Err(phase_error(
                    io::ErrorKind::TimedOut,
                    "NetShaper public tick exceeded write allowance",
                ));
            }
            let selected = release_bytes(q.bytes.len(), noise, self.profile.release_cap);
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
            .map_err(|_| phase_error(io::ErrorKind::TimedOut, "NetShaper wire write timed out"))?
            .map_err(|e| phase_error(e.kind(), "NetShaper wire write failed"))?;
            // Synchronous Ready after the deadline is not timely completion.
            if Instant::now() >= limit {
                return Err(phase_error(
                    io::ErrorKind::TimedOut,
                    "NetShaper wire write poll exceeded allowance",
                ));
            }
            wire += (selected + OVERHEAD) as u64;
        }
        Ok(NetShaperReceipt {
            accounting: accounting.receipt(),
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
            return Err(timed());
        }
        let cipher =
            ChaCha20Poly1305::new_from_slice(self.material.key.as_ref()).map_err(|_| invalid())?;
        let mut delivered = 0usize;
        for index in 0..self.profile.slots {
            let mut header = [0; 4];
            timeout_at(deadline, transport.read_exact(&mut header))
                .await
                .map_err(|_| timed())??;
            if Instant::now() >= deadline {
                return Err(timed());
            }
            let selected = u32::from_be_bytes(header) as usize;
            if selected > self.profile.release_cap {
                return Err(invalid_data());
            }
            let mut body = vec![0; selected + 20];
            timeout_at(deadline, transport.read_exact(&mut body))
                .await
                .map_err(|_| timed())??;
            if Instant::now() >= deadline {
                return Err(timed());
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
            .map_err(|_| timed())??;
            if Instant::now() >= deadline {
                return Err(timed());
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
    profile: NetShaperProfile,
    send_material: NetShaperMaterial,
    receive_material: NetShaperMaterial,
    deadline: Instant,
) -> io::Result<NetShaperStream>
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
    profile: NetShaperProfile,
    send_material: NetShaperMaterial,
    receive_material: NetShaperMaterial,
    deadline: Instant,
    owner: Option<&super::worker_owner::ShapingCleanupOwner>,
) -> io::Result<NetShaperStream>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    if bool::from(
        send_material
            .key
            .as_ref()
            .ct_eq(receive_material.key.as_ref()),
    ) && bool::from(
        send_material
            .prefix
            .as_ref()
            .ct_eq(receive_material.prefix.as_ref()),
    ) {
        return Err(invalid()); // reflection/nonce collision from same direction material
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
        let send = NetShaperSession::new(profile.clone(), send_material).send(
            input,
            carrier_write,
            deadline,
        );
        let receive = NetShaperSession::new(profile, receive_material).receive_into(
            carrier_read,
            output,
            deadline,
        );
        let sending = async {
            send.await
                .map_err(|e| retain_phase_or_redact(e, "NetShaper sender failed"))
        };
        let receiving = async {
            receive
                .await
                .map_err(|e| retain_phase_or_redact(e, "NetShaper receiver failed"))
        };
        let (sent, ()) = tokio::try_join!(sending, receiving)?;
        // Real unserved bytes cannot masquerade as a clean application EOF.
        if sent.pending_bytes != 0 || !sent.input_eof_observed {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "NetShaper public epoch ended with an unserved tail",
            ));
        }
        Ok(sent)
    })?;
    Ok(NetShaperStream {
        app,
        worker: Some(worker),
        completed: None,
        failure: None,
    })
}
/// Dropping/aborting the stream retires its one owned worker and carrier halves.
/// Cancellation is not proof of remote delivery or privacy budget recovery.
pub struct NetShaperStream {
    app: tokio::io::DuplexStream,
    worker: Option<super::worker_owner::SharedWorker<NetShaperReceipt>>,
    completed: Option<NetShaperReceipt>,
    failure: Option<(io::ErrorKind, &'static str)>,
}
impl std::fmt::Debug for NetShaperStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // DuplexStream Debug includes buffered application bytes; never delegate.
        f.debug_struct("NetShaperStream").finish_non_exhaustive()
    }
}
impl NetShaperStream {
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
                            .map_or("NetShaper owned worker failed", |phase| phase.0);
                        self.failure = Some((error.kind(), message));
                    }
                    Err(_) => {
                        self.failure =
                            Some((io::ErrorKind::Other, "NetShaper owned worker cancelled"))
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
    pub async fn finish(mut self) -> io::Result<NetShaperReceipt> {
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

/// Only module-owned static phase names may cross the worker boundary. Never
/// copy a caller/transport error string: it can contain application bytes.
#[derive(Debug)]
struct FailurePhase(&'static str);
impl std::fmt::Display for FailurePhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for FailurePhase {}
fn phase_error(kind: io::ErrorKind, message: &'static str) -> io::Error {
    io::Error::new(kind, FailurePhase(message))
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
impl AsyncRead for NetShaperStream {
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
impl AsyncWrite for NetShaperStream {
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
                "NetShaper public epoch completed",
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
impl Drop for NetShaperStream {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            worker.abort();
        }
    }
}

fn aad(profile: &NetShaperProfile, index: u32, selected: usize) -> Vec<u8> {
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
/// Exact integer CKS Algorithms 1/2 under unbounded independent random draws.
/// This implementation refuses at a PUBLIC fuel/clock/checked-integer bound;
/// it never substitutes approximate noise. Returned samples are not claimed to
/// retain the reference distribution after conditioning on bounded success.
struct SamplingBudget {
    left: u32,
    deadline: Option<Instant>,
}
impl SamplingBudget {
    fn step(&mut self) -> io::Result<()> {
        if self.left == 0 {
            return Err(io::Error::other("NetShaper sampling fuel exhausted"));
        }
        if self.deadline.is_some_and(|t| Instant::now() >= t) {
            return Err(timed());
        }
        self.left -= 1;
        Ok(())
    }
    fn uniform<G: RngCore + CryptoRng>(&mut self, rng: &mut G, upper: u128) -> io::Result<u128> {
        if upper == 0 {
            return Err(invalid());
        }
        // Unbiased rejection over the complete 128-bit alphabet; all attempts
        // share one fuel, never modulo-bias a draw or silently reset the cap.
        let threshold = upper.wrapping_neg() % upper;
        loop {
            self.step()?;
            let mut b = [0; 16];
            rng.try_fill_bytes(&mut b)
                .map_err(|_| io::Error::other("NetShaper cryptographic entropy unavailable"))?;
            if self.deadline.is_some_and(|t| Instant::now() >= t) {
                return Err(timed());
            }
            let x = u128::from_le_bytes(b);
            if x >= threshold {
                return Ok(x % upper);
            }
        }
    }
    fn bernoulli<G: RngCore + CryptoRng>(
        &mut self,
        rng: &mut G,
        n: u128,
        d: u128,
    ) -> io::Result<bool> {
        if d == 0 || n > d {
            return Err(invalid());
        }
        Ok(self.uniform(rng, d)? < n)
    }
    fn exp_unit<G: RngCore + CryptoRng>(
        &mut self,
        rng: &mut G,
        n: u128,
        d: u128,
    ) -> io::Result<bool> {
        if n > d || d == 0 {
            return Err(invalid());
        }
        let mut k = 1u128;
        // P(k parity odd)=1-x+x²/2!-x³/3!+...=exp(-x).
        loop {
            let denom = d.checked_mul(k).ok_or_else(invalid)?;
            if !self.bernoulli(rng, n, denom)? {
                return Ok(k % 2 == 1);
            }
            k = k.checked_add(1).ok_or_else(invalid)?;
        }
    }
    fn exp<G: RngCore + CryptoRng>(&mut self, rng: &mut G, n: u128, d: u128) -> io::Result<bool> {
        if d == 0 {
            return Err(invalid());
        }
        for _ in 0..n / d {
            self.step()?;
            if !self.exp_unit(rng, 1, 1)? {
                return Ok(false);
            }
        }
        self.exp_unit(rng, n % d, d)
    }
}
fn discrete_gaussian<G: RngCore + CryptoRng>(
    sigma: u32,
    rng: &mut G,
    deadline: Option<Instant>,
) -> io::Result<i64> {
    discrete_gaussian_budget(
        sigma,
        rng,
        SamplingBudget {
            left: 65_536,
            deadline,
        },
    )
}
fn discrete_gaussian_budget<G: RngCore + CryptoRng>(
    sigma: u32,
    rng: &mut G,
    mut fuel: SamplingBudget,
) -> io::Result<i64> {
    if sigma == 0 || sigma > 1_048_576 {
        return Err(invalid());
    }
    let t = u128::from(sigma) + 1;
    let variance = u128::from(sigma).pow(2);
    loop {
        fuel.step()?;
        let u = fuel.uniform(rng, t)?;
        if !fuel.exp_unit(rng, u, t)? {
            continue;
        }
        let mut v = 0u128;
        while fuel.exp_unit(rng, 1, 1)? {
            v = v.checked_add(1).ok_or_else(invalid)?;
        }
        let y = u
            .checked_add(t.checked_mul(v).ok_or_else(invalid)?)
            .ok_or_else(invalid)?;
        let negative = fuel.bernoulli(rng, 1, 2)?;
        if negative && y == 0 {
            continue;
        }
        let diff = y.checked_mul(t).ok_or_else(invalid)?.abs_diff(variance);
        let n = diff.checked_mul(diff).ok_or_else(invalid)?;
        let d = 2u128
            .checked_mul(variance)
            .and_then(|x| x.checked_mul(t))
            .and_then(|x| x.checked_mul(t))
            .ok_or_else(invalid)?;
        if fuel.exp(rng, n, d)? {
            let magnitude = i64::try_from(y).map_err(|_| invalid())?;
            return Ok(if negative { -magnitude } else { magnitude });
        }
    }
}
fn release_bytes(query: usize, noise: i64, cap: usize) -> usize {
    (query as i128 + i128::from(noise)).clamp(0, cap as i128) as usize
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid NetShaper public profile or budget",
    )
}
fn invalid_data() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "NetShaper frame admission refused",
    )
}
fn timed() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "NetShaper original deadline expired",
    )
}

async fn wait_for_public_tick(tick: Instant) {
    // A fresh Tokio Sleep can yield/register a rounded timer after its Instant
    // has elapsed. No second wait is needed for a public tick already reached;
    // original write/session cutoffs remain at the caller.
    if Instant::now() < tick {
        sleep_until(tick).await;
    }
}

#[cfg(test)]
#[path = "netshaper_tests.rs"]
mod tests;
