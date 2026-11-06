//! Explicit application-owned insertion. Ideal Poisson count references are
//! conditional; these fixed encrypted records are not IP packets or a wire law.
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{io, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::{sleep_until, timeout_at, Instant},
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InsertionProfile {
    pub capacity: usize,
    pub horizon_ms: u64,
    pub insertion_rate_milli: u32,
    /// Operator's conditional H0 rate, not an inference from the source.
    pub overt_rate_milli: u32,
    pub max_records: usize,
    pub max_wire_bytes: usize,
    pub io_timeout_ms: u64,
    pub max_lateness_ms: u64,
}
impl InsertionProfile {
    pub fn validate(&self) -> io::Result<()> {
        if !(64..=1024).contains(&self.capacity)
            || !(20..=10000).contains(&self.horizon_ms)
            || self.insertion_rate_milli > 1_000_000
            || !(1..=1_000_000).contains(&self.overt_rate_milli)
            || !(2..=512).contains(&self.max_records)
            || !(1..=1000).contains(&self.io_timeout_ms)
            || !(1..=1000).contains(&self.max_lateness_ms)
            || self.max_wire_bytes > 1024 * 1024
            || self
                .max_records
                .checked_mul(self.frame_bytes())
                .is_none_or(|n| n > self.max_wire_bytes)
        {
            return Err(fail(
                io::ErrorKind::InvalidInput,
                "insertion profile refused",
            ));
        }
        Ok(())
    }
    pub fn frame_bytes(&self) -> usize {
        self.capacity + 3 + 16
    }
    pub fn descriptor(&self) -> io::Result<[u8; 32]> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|_| fail(io::ErrorKind::InvalidInput, "insertion descriptor"))?;
        let mut h = Sha256::new();
        h.update(b"aegis.poisson.insertion.v1");
        h.update(bytes);
        Ok(h.finalize().into())
    }
    pub fn ideal_count_reference(&self) -> io::Result<CountReference> {
        self.validate()?;
        let lambda = f64::from(self.overt_rate_milli) / 1000.0;
        let delta = f64::from(self.insertion_rate_milli) / 1000.0;
        let t = self.horizon_ms as f64 / 1000.0;
        let d = lambda * t * ((delta / lambda) - (delta / lambda).ln_1p());
        if !d.is_finite() || d < -1e-12 {
            return Err(fail(
                io::ErrorKind::InvalidInput,
                "insertion numerical reference",
            ));
        }
        Ok(CountReference {
            expected_overt: lambda * t,
            expected_inserted: delta * t,
            kl_p0_p1_nats: d.max(0.0),
            pinsker_sum_error_lower: (1.0 - (d.max(0.0) / 2.0).sqrt()).max(0.0),
        })
    }
}
#[derive(Debug, Serialize)]
pub struct CountReference {
    pub expected_overt: f64,
    pub expected_inserted: f64,
    pub kl_p0_p1_nats: f64,
    pub pinsker_sum_error_lower: f64,
}
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct InsertionReceipt {
    pub original_records: usize,
    pub original_bytes: usize,
    pub inserted_records: usize,
    /// Includes the single authenticated terminal record outside the horizon.
    pub wire_records: usize,
    pub wire_bytes: usize,
    pub source_eof: bool,
    pub first_arrival_us: Option<u64>,
    pub last_arrival_us: Option<u64>,
}
/// No Clone/Debug. Constructed only by the fresh authenticated TLS owner.
pub(crate) struct Material {
    key: Zeroizing<[u8; 32]>,
    prefix: Zeroizing<[u8; 4]>,
}
impl Material {
    pub(crate) fn new(key: Zeroizing<[u8; 32]>, prefix: Zeroizing<[u8; 4]>) -> Self {
        Self { key, prefix }
    }
}
pub type PrivateBytes = Zeroizing<Vec<u8>>;
/// Explicit owned file/application input; no borrow or plaintext Debug.
pub struct OwnedApplicationInput {
    bytes: PrivateBytes,
    offset: usize,
}
impl OwnedApplicationInput {
    pub fn new(bytes: PrivateBytes, max_bytes: usize) -> io::Result<Self> {
        if max_bytes > 1024 * 1024 || bytes.len() > max_bytes {
            return Err(fail(
                io::ErrorKind::InvalidInput,
                "insertion application input cap",
            ));
        }
        Ok(Self { bytes, offset: 0 })
    }
}
impl AsyncRead for OwnedApplicationInput {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let n = buf.remaining().min(self.bytes.len() - self.offset);
        buf.put_slice(&self.bytes[self.offset..self.offset + n]);
        let start = self.offset;
        self.bytes[start..start + n].zeroize();
        self.offset += n;
        std::task::Poll::Ready(Ok(()))
    }
}
pub struct ReceivedInsertion {
    pub receipt: InsertionReceipt,
    control: Zeroizing<Vec<u8>>,
}
impl ReceivedInsertion {
    pub fn control(&self) -> &[u8] {
        &self.control
    }
    pub fn save_control_private_new(self, path: &std::path::Path) -> io::Result<()> {
        crate::secret_file::write_private_new(path, &self.control)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FailureRecordState {
    original_records: usize,
    original_bytes: usize,
    inserted_records: usize,
    wire_records: usize,
    wire_bytes: usize,
    source_eof_observed: bool,
    terminal_write_attempted: bool,
    terminal_write_completed: bool,
}
struct InsertionPhase {
    phase: &'static str,
    records: Option<FailureRecordState>,
}
impl std::fmt::Debug for InsertionPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InsertionPhase")
            .field("phase", &self.phase)
            .field("records", &self.records)
            .finish()
    }
}
impl std::fmt::Display for InsertionPhase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.phase)
    }
}
impl std::error::Error for InsertionPhase {}

pub(crate) fn fail(kind: io::ErrorKind, phase: &'static str) -> io::Error {
    io::Error::new(
        kind,
        InsertionPhase {
            phase,
            records: None,
        },
    )
}
// Preserve only our static stage and aggregate custody. Never retain source
// error text, payload, key material, identities, or absolute clock values.
fn with_record_state(
    error: io::Error,
    receipt: &InsertionReceipt,
    terminal_write_attempted: bool,
    terminal_write_completed: bool,
) -> io::Error {
    let Some(phase) = error
        .get_ref()
        .and_then(|e| e.downcast_ref::<InsertionPhase>())
    else {
        return error;
    };
    io::Error::new(
        error.kind(),
        InsertionPhase {
            phase: phase.phase,
            records: Some(FailureRecordState {
                original_records: receipt.original_records,
                original_bytes: receipt.original_bytes,
                inserted_records: receipt.inserted_records,
                wire_records: receipt.wire_records,
                wire_bytes: receipt.wire_bytes,
                source_eof_observed: receipt.source_eof,
                terminal_write_attempted,
                terminal_write_completed,
            }),
        },
    )
}
#[cfg(test)]
pub(crate) fn failure_phase(error: &io::Error) -> Option<&'static str> {
    error
        .get_ref()?
        .downcast_ref::<InsertionPhase>()
        .map(|p| p.phase)
}
#[cfg(test)]
fn failure_records(error: &io::Error) -> Option<FailureRecordState> {
    error.get_ref()?.downcast_ref::<InsertionPhase>()?.records
}
fn guard(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(fail(io::ErrorKind::TimedOut, "insertion original deadline"))
    } else {
        Ok(())
    }
}
fn io_deadline(p: &InsertionProfile, end: Instant) -> Instant {
    end.min(Instant::now() + Duration::from_millis(p.io_timeout_ms))
}
async fn source_poll<R: AsyncRead + Unpin>(
    source: &mut R,
    buffer: &mut [u8],
    boundary: Instant,
) -> io::Result<Option<usize>> {
    std::future::poll_fn(|cx| {
        if Instant::now() >= boundary {
            return std::task::Poll::Ready(Ok(None));
        }
        let mut read = tokio::io::ReadBuf::new(buffer);
        let result = std::pin::Pin::new(&mut *source).poll_read(cx, &mut read);
        if Instant::now() >= boundary {
            return std::task::Poll::Ready(Err(fail(
                io::ErrorKind::TimedOut,
                "insertion source poll crossed slot",
            )));
        }
        match result {
            std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(Some(read.filled().len()))),
            std::task::Poll::Ready(Err(e)) => {
                std::task::Poll::Ready(Err(fail(e.kind(), "insertion source")))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    })
    .await
}
async fn bounded<F, T>(end: Instant, future: F, phase: &'static str) -> io::Result<T>
where
    F: std::future::Future<Output = io::Result<T>>,
{
    guard(end)?;
    let result = timeout_at(end, future)
        .await
        .map_err(|_| fail(io::ErrorKind::TimedOut, phase))?
        .map_err(|e| fail(e.kind(), phase))?;
    guard(end)?;
    Ok(result)
}
fn interval<R: RngCore + CryptoRng>(rate: u32, rng: &mut R) -> io::Result<Option<Duration>> {
    if rate == 0 {
        return Ok(None);
    }
    let mut b = [0; 8];
    rng.try_fill_bytes(&mut b)
        .map_err(|_| fail(io::ErrorKind::Other, "insertion entropy"))?;
    // Finite midpoint uniform; numerical/CSPRNG approximation, not ideal law.
    let u = ((u64::from_le_bytes(b) >> 12) as f64 + 0.5) / (1_u64 << 52) as f64;
    let seconds = -u.ln() / (f64::from(rate) / 1000.0);
    if !seconds.is_finite() || seconds < 1e-9 {
        return Err(fail(
            io::ErrorKind::InvalidInput,
            "insertion clock resolution",
        ));
    }
    Ok(Some(Duration::from_secs_f64(seconds)))
}
fn nonce(material: &Material, ordinal: usize) -> [u8; 12] {
    let mut n = [0; 12];
    n[..4].copy_from_slice(material.prefix.as_ref());
    n[4..].copy_from_slice(&(ordinal as u64).to_be_bytes());
    n
}
fn seal<R: RngCore + CryptoRng>(
    p: &InsertionProfile,
    m: &Material,
    ordinal: usize,
    kind: u8,
    payload: &[u8],
    rng: &mut R,
) -> io::Result<Zeroizing<Vec<u8>>> {
    if payload.len() > p.capacity {
        return Err(fail(io::ErrorKind::InvalidInput, "insertion payload bound"));
    }
    let mut plain = Zeroizing::new(vec![0; p.capacity + 3]);
    rng.try_fill_bytes(&mut plain)
        .map_err(|_| fail(io::ErrorKind::Other, "insertion entropy"))?;
    plain[0] = kind;
    plain[1..3].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    plain[3..3 + payload.len()].copy_from_slice(payload);
    let c = ChaCha20Poly1305::new(m.key.as_ref().into());
    c.encrypt_in_place(
        Nonce::from_slice(&nonce(m, ordinal)),
        &p.descriptor()?,
        &mut *plain,
    )
    .map_err(|_| fail(io::ErrorKind::InvalidData, "insertion seal"))?;
    Ok(plain)
}
fn open(
    p: &InsertionProfile,
    m: &Material,
    ordinal: usize,
    mut frame: Zeroizing<Vec<u8>>,
) -> io::Result<(u8, Zeroizing<Vec<u8>>)> {
    let c = ChaCha20Poly1305::new(m.key.as_ref().into());
    c.decrypt_in_place(
        Nonce::from_slice(&nonce(m, ordinal)),
        &p.descriptor()?,
        &mut *frame,
    )
    .map_err(|_| fail(io::ErrorKind::InvalidData, "insertion authentication"))?;
    let n = usize::from(u16::from_be_bytes([frame[1], frame[2]]));
    if n > p.capacity {
        return Err(fail(io::ErrorKind::InvalidData, "insertion length"));
    }
    Ok((frame[0], Zeroizing::new(frame[3..3 + n].to_vec())))
}
fn account(p: &InsertionProfile, r: &mut InsertionReceipt, kind: u8, n: usize) -> io::Result<()> {
    if r.wire_records >= p.max_records {
        return Err(fail(io::ErrorKind::OutOfMemory, "insertion record cap"));
    }
    r.wire_records += 1;
    r.wire_bytes += p.frame_bytes();
    if r.wire_bytes > p.max_wire_bytes {
        return Err(fail(io::ErrorKind::OutOfMemory, "insertion wire cap"));
    }
    match kind {
        0 => {
            r.original_records += 1;
            r.original_bytes += n
        }
        1 => r.inserted_records += 1,
        2 => {}
        _ => return Err(fail(io::ErrorKind::InvalidData, "insertion kind")),
    };
    Ok(())
}
fn terminal(r: &InsertionReceipt, hash: [u8; 32]) -> [u8; 57] {
    let mut b = [0; 57];
    b[..8].copy_from_slice(&(r.original_records as u64).to_be_bytes());
    b[8..16].copy_from_slice(&(r.original_bytes as u64).to_be_bytes());
    b[16..24].copy_from_slice(&(r.inserted_records as u64).to_be_bytes());
    b[24] = u8::from(r.source_eof);
    b[25..].copy_from_slice(&hash);
    b
}
/// Consumes the stream/source/material on every error or cancellation. Source
/// chunks are the application's actual reads, not inferred UDP/IP packets.
pub(crate) async fn send_records<R, W, G>(
    p: &InsertionProfile,
    m: Material,
    mut source: R,
    mut wire: W,
    message: Zeroizing<Vec<u8>>,
    rng: &mut G,
    absolute_end: Instant,
) -> io::Result<(W, InsertionReceipt)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    G: RngCore + CryptoRng,
{
    p.validate()?;
    if message.is_empty() || message.len() > p.capacity {
        return Err(fail(
            io::ErrorKind::InvalidInput,
            "insertion control capacity",
        ));
    }
    guard(absolute_end)?;
    let origin = Instant::now();
    let horizon = origin + Duration::from_millis(p.horizon_ms);
    if horizon + Duration::from_millis(p.io_timeout_ms) >= absolute_end {
        return Err(fail(
            io::ErrorKind::InvalidInput,
            "insertion original budget",
        ));
    }
    let mut next = interval(p.insertion_rate_milli, rng)?.map(|d| origin + d);
    let mut receipt = InsertionReceipt::default();
    let mut original_hash = Sha256::new();
    let mut input = Zeroizing::new(vec![0; p.capacity]);
    loop {
        guard(absolute_end)?;
        if Instant::now() >= horizon {
            break;
        }
        let wake = next.unwrap_or(horizon).min(horizon);
        let event = tokio::select! {biased;
            _=sleep_until(wake)=>None,
            n=source_poll(&mut source,&mut input,wake.min(absolute_end)),if !receipt.source_eof=>n?,
        };
        if Instant::now() >= horizon {
            if event.is_some_and(|n| n > 0) {
                return Err(fail(io::ErrorKind::TimedOut, "insertion late source poll"));
            }
            break;
        }
        let deadline =
            io_deadline(p, absolute_end).min(wake + Duration::from_millis(p.max_lateness_ms));
        let (kind, payload) = match event {
            Some(0) => {
                receipt.source_eof = true;
                continue;
            }
            Some(n) => {
                original_hash.update(&input[..n]);
                (0, &input[..n])
            }
            None => {
                if Instant::now().duration_since(wake) > Duration::from_millis(p.max_lateness_ms) {
                    return Err(fail(io::ErrorKind::TimedOut, "insertion late arrival"));
                }
                next = interval(p.insertion_rate_milli, rng)?.map(|d| wake + d);
                (1, message.as_slice())
            }
        };
        // Reserve a terminal slot. A cap refuses rather than truncates the law.
        if receipt.wire_records + 1 >= p.max_records {
            return Err(fail(io::ErrorKind::OutOfMemory, "insertion record cap"));
        }
        let frame = seal(p, &m, receipt.wire_records, kind, payload, rng)?;
        bounded(
            deadline,
            async {
                wire.write_all(&frame).await?;
                wire.flush().await
            },
            "insertion write",
        )
        .await?;
        account(p, &mut receipt, kind, payload.len())?;
        input.as_mut_slice().zeroize();
    }
    if !receipt.source_eof {
        return Err(with_record_state(
            fail(io::ErrorKind::UnexpectedEof, "insertion source incomplete"),
            &receipt,
            false,
            false,
        ));
    }
    let terminal_deadline = io_deadline(p, absolute_end);
    let end = terminal(&receipt, original_hash.finalize().into());
    let frame = seal(p, &m, receipt.wire_records, 2, &end, rng)?;
    write_terminal(&mut wire, &frame, terminal_deadline, &receipt).await?;
    account(p, &mut receipt, 2, end.len())?;
    if receipt.inserted_records == 0 {
        return Err(with_record_state(
            fail(io::ErrorKind::UnexpectedEof, "insertion no control arrived"),
            &receipt,
            true,
            true,
        ));
    }
    Ok((wire, receipt))
}
// Keep I/O custody separate from bounded admission and its post-write guard.
async fn write_terminal<W: AsyncWrite + Unpin>(
    wire: &mut W,
    frame: &[u8],
    terminal_deadline: Instant,
    receipt: &InsertionReceipt,
) -> io::Result<()> {
    let mut terminal_write_attempted = false;
    let mut terminal_write_completed = false;
    bounded(
        terminal_deadline,
        async {
            terminal_write_attempted = true;
            wire.write_all(frame).await?;
            wire.flush().await?;
            terminal_write_completed = true;
            Ok(())
        },
        "insertion terminal write",
    )
    .await
    .map_err(|e| {
        with_record_state(
            e,
            receipt,
            terminal_write_attempted,
            terminal_write_completed,
        )
    })
}
pub(crate) async fn receive_records<W, S>(
    p: &InsertionProfile,
    m: Material,
    mut wire: W,
    mut sink: S,
    absolute_end: Instant,
    terminal_not_before: Instant,
) -> io::Result<(W, S, ReceivedInsertion)>
where
    W: AsyncRead + Unpin,
    S: AsyncWrite + Unpin,
{
    p.validate()?;
    guard(absolute_end)?;
    if terminal_not_before >= absolute_end {
        return Err(fail(
            io::ErrorKind::InvalidInput,
            "insertion receiver horizon budget",
        ));
    }
    let origin = Instant::now();
    let mut receipt = InsertionReceipt::default();
    let mut hash = Sha256::new();
    let mut control = Zeroizing::new(Vec::new());
    loop {
        if receipt.wire_records >= p.max_records {
            return Err(fail(io::ErrorKind::OutOfMemory, "insertion record cap"));
        }
        let mut frame = Zeroizing::new(vec![0; p.frame_bytes()]);
        // Arrival gaps may legitimately span the public horizon. One partial
        // frame still cannot extend the caller's absolute exchange deadline.
        bounded(
            absolute_end,
            wire.read_exact(&mut frame[..1]),
            "insertion arrival",
        )
        .await
        .map_err(|e| with_record_state(e, &receipt, false, false))?;
        bounded(
            io_deadline(p, absolute_end),
            wire.read_exact(&mut frame[1..]),
            "insertion partial record",
        )
        .await
        .map_err(|e| with_record_state(e, &receipt, false, false))?;
        let elapsed = origin.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        let (kind, payload) = open(p, &m, receipt.wire_records, frame)?;
        if kind == 2 {
            if Instant::now() < terminal_not_before {
                return Err(fail(io::ErrorKind::InvalidData, "insertion early terminal"));
            }
            receipt.source_eof = true;
            if payload.as_slice() != terminal(&receipt, hash.finalize().into())
                || receipt.inserted_records == 0
            {
                return Err(fail(io::ErrorKind::InvalidData, "insertion terminal count"));
            }
            account(p, &mut receipt, kind, payload.len())?;
            bounded(
                io_deadline(p, absolute_end),
                sink.flush(),
                "insertion sink flush",
            )
            .await?;
            return Ok((wire, sink, ReceivedInsertion { receipt, control }));
        }
        if kind == 0 {
            if payload.is_empty() {
                return Err(fail(io::ErrorKind::InvalidData, "insertion empty original"));
            }
            hash.update(payload.as_slice());
            bounded(
                io_deadline(p, absolute_end),
                sink.write_all(&payload),
                "insertion sink",
            )
            .await?;
        } else if kind == 1 {
            if payload.is_empty()
                || (!control.is_empty() && control.as_slice() != payload.as_slice())
            {
                return Err(fail(
                    io::ErrorKind::InvalidData,
                    "insertion control consistency",
                ));
            }
            if control.is_empty() {
                control.extend_from_slice(&payload);
            }
        }
        account(p, &mut receipt, kind, payload.len())?;
        receipt.first_arrival_us.get_or_insert(elapsed);
        receipt.last_arrival_us = Some(elapsed);
    }
}

#[cfg(test)]
#[path = "poisson_insertion_tests.rs"]
mod tests;
