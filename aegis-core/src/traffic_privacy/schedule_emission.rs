//! One-shot, finite, opt-in consumer for the binary randomized-response
//! accountant. Only the released-bit transcript has its stated pure-DP bound.
//! Ciphertext, stalls, errors, cancellation, endpoints and actual timing are
//! outside that information-theoretic claim. This is not NetShaper's Gaussian
//! queue mechanism and is not a default transport or a whole-flow DP tunnel.
use super::schedule_dp::{ScheduleAccountant, ScheduleReceipt};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305,
};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use std::{io, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::{sleep_until, timeout_at, Instant},
};
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"aegis.binary-schedule-emission.v1";
const LONG_PADDING: usize = 16;

/// Every field is public and pre-agreed. The batch is a fixed, bounded input
/// queue, not an unbounded live arrival process. Two frame sizes differ only by
/// sixteen public padding bytes selected by the released randomized bit.
#[derive(Clone, Debug)]
pub struct ScheduleProfile {
    slots: usize,
    capacity: usize,
    cadence: Duration,
    io_timeout: Duration,
    truthful: u32,
    flipped: u32,
    limit_numerator: u128,
    limit_denominator: u128,
    descriptor: [u8; 32],
}
impl ScheduleProfile {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        slots: usize,
        capacity: usize,
        cadence: Duration,
        io_timeout: Duration,
        truthful: u32,
        flipped: u32,
        limit_numerator: u128,
        limit_denominator: u128,
    ) -> io::Result<Self> {
        if !(1..=64).contains(&slots)
            || !(1..=256).contains(&capacity)
            || cadence < Duration::from_millis(1)
            || io_timeout.is_zero()
            || io_timeout > Duration::from_secs(30)
            || cadence
                .checked_mul(slots as u32)
                .is_none_or(|d| d > Duration::from_secs(30))
        {
            return Err(invalid());
        }
        // Constructor validation is separate from the one live accountant.
        ScheduleAccountant::new(truthful, flipped, limit_numerator, limit_denominator, slots)?;
        validate_horizon(slots, truthful, flipped, limit_numerator, limit_denominator)?;
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        hash.update((slots as u16).to_be_bytes());
        hash.update((capacity as u16).to_be_bytes());
        hash.update(cadence.as_nanos().to_be_bytes());
        hash.update(io_timeout.as_nanos().to_be_bytes());
        hash.update(truthful.to_be_bytes());
        hash.update(flipped.to_be_bytes());
        hash.update(limit_numerator.to_be_bytes());
        hash.update(limit_denominator.to_be_bytes());
        Ok(Self {
            slots,
            capacity,
            cadence,
            io_timeout,
            truthful,
            flipped,
            limit_numerator,
            limit_denominator,
            descriptor: hash.finalize().into(),
        })
    }
    pub fn descriptor_sha256(&self) -> [u8; 32] {
        self.descriptor
    }
    /// Public payload capacity for admission before any I/O.
    pub fn capacity(&self) -> usize {
        self.capacity
    }
    pub fn slots(&self) -> usize {
        self.slots
    }
    pub fn frame_bytes(&self, released_bit: u8) -> io::Result<usize> {
        if released_bit > 1 {
            return Err(invalid());
        }
        Ok(1 + self.capacity + 2 + 16 + usize::from(released_bit) * LONG_PADDING)
    }
    fn accountant(&self) -> io::Result<ScheduleAccountant> {
        ScheduleAccountant::new(
            self.truthful,
            self.flipped,
            self.limit_numerator,
            self.limit_denominator,
            self.slots,
        )
    }
    fn horizon(&self) -> Duration {
        self.cadence * self.slots as u32
    }
}

// Pure public arithmetic mirrors the accountant's exact checked composition.
// It never releases a bit, consumes entropy, spends or resets a live budget.
fn validate_horizon(
    slots: usize,
    truthful: u32,
    flipped: u32,
    limit_n: u128,
    limit_d: u128,
) -> io::Result<()> {
    let (mut n, mut d) = (1u128, 1u128);
    let (a, b) = (u128::from(truthful), u128::from(flipped));
    for _ in 0..slots {
        let (cancel_a, cancel_b) = (gcd(a, d), gcd(b, n));
        n = (n / cancel_b)
            .checked_mul(a / cancel_a)
            .ok_or_else(invalid)?;
        d = (d / cancel_a)
            .checked_mul(b / cancel_b)
            .ok_or_else(invalid)?;
        if n.checked_mul(limit_d).ok_or_else(invalid)?
            > limit_n.checked_mul(d).ok_or_else(invalid)?
        {
            return Err(invalid());
        }
    }
    Ok(())
}
fn gcd(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a
}

/// Dedicated fresh key and nonce prefix for ONE direction/batch. Not Clone or
/// Debug; sending/receiving consumes it, including error/cancellation. External
/// provisioning must prevent reconstruction/reuse across backups and restarts.
pub struct BatchMaterial {
    key: Zeroizing<[u8; 32]>,
    prefix: Zeroizing<[u8; 8]>,
}
impl BatchMaterial {
    pub fn from_preprovisioned(key: Zeroizing<[u8; 32]>, prefix: [u8; 8]) -> Self {
        Self {
            key,
            prefix: Zeroizing::new(prefix),
        }
    }
    fn nonce(&self, index: usize) -> Zeroizing<[u8; 12]> {
        let mut nonce = Zeroizing::new([0; 12]);
        nonce[..8].copy_from_slice(self.prefix.as_ref());
        nonce[8..].copy_from_slice(&(index as u32).to_be_bytes());
        nonce
    }
}

pub struct ScheduleBatch {
    profile: ScheduleProfile,
    material: BatchMaterial,
    accountant: ScheduleAccountant,
}
#[derive(Debug)]
pub struct SendReceipt {
    pub accounting: ScheduleReceipt,
    pub fully_written_slots: usize,
    pub fully_written_frame_bytes: usize,
}
/// Actual spending is retained, including entropy/partial-I/O failures. This
/// consumed sender cannot retry or reset. This is not a DP claim about errors.
#[derive(Debug)]
pub struct SendFailure {
    pub kind: io::ErrorKind,
    pub receipt: SendReceipt,
    pub partial_frame_may_have_been_written: bool,
}
pub struct ReceivedBatch {
    pub payloads: Vec<Zeroizing<Vec<u8>>>,
    pub released_bits: Vec<u8>,
    pub wire_bytes: usize,
}
impl ScheduleBatch {
    pub fn new(profile: ScheduleProfile, material: BatchMaterial) -> io::Result<Self> {
        let accountant = profile.accountant()?;
        Ok(Self {
            profile,
            material,
            accountant,
        })
    }
    /// The preloaded bounded queue contains exactly the public number of cells;
    /// empty cell means dummy. A real payload is carried regardless of the
    /// released bit, so no secret queue-availability fallback affects framing.
    /// All lengths are checked before the first release or write.
    pub async fn send<S: AsyncWrite + Unpin, R: RngCore + CryptoRng>(
        mut self,
        payloads: Vec<Zeroizing<Vec<u8>>>,
        rng: &mut R,
        wire: &mut S,
    ) -> Result<SendReceipt, SendFailure> {
        let (mut complete_slots, mut complete_bytes, mut partial) = (0, 0, false);
        let result = async {
            if payloads.len() != self.profile.slots
                || payloads.iter().any(|p| p.len() > self.profile.capacity)
            {
                return Err(invalid());
            }
            let cipher = ChaCha20Poly1305::new_from_slice(self.material.key.as_ref())
                .map_err(|_| invalid())?;
            let start = Instant::now();
            let public_end = start + self.profile.horizon();
            timeout_at(public_end + self.profile.io_timeout, async {
                for (index, payload) in payloads.iter().enumerate() {
                    sleep_until(start + self.profile.cadence * index as u32).await;
                    let bit = self
                        .accountant
                        .release(u8::from(!payload.is_empty()), rng)?;
                    let mut plain = Zeroizing::new(vec![0; self.profile.capacity + 2]);
                    plain[..2].copy_from_slice(&(payload.len() as u16).to_be_bytes());
                    plain[2..2 + payload.len()].copy_from_slice(payload);
                    let aad = associated_data(&self.profile, index, bit);
                    let nonce = self.material.nonce(index);
                    let encrypted = cipher
                        .encrypt(
                            nonce.as_ref().into(),
                            Payload {
                                msg: &plain,
                                aad: &aad,
                            },
                        )
                        .map_err(|_| malformed())?;
                    let mut frame = vec![0; self.profile.frame_bytes(bit)?];
                    frame[0] = bit;
                    frame[1..1 + encrypted.len()].copy_from_slice(&encrypted);
                    partial = true;
                    timeout_at(
                        Instant::now() + self.profile.io_timeout,
                        wire.write_all(&frame),
                    )
                    .await
                    .map_err(|_| timed_out())??;
                    partial = false;
                    complete_slots += 1;
                    complete_bytes += frame.len();
                }
                // Completion never follows secret empty queue/EOF. This is a
                // nominal cadence; scheduler/transport stalls are not DP timing.
                sleep_until(public_end).await;
                wire.flush().await
            })
            .await
            .map_err(|_| timed_out())?
        }
        .await;
        let receipt = SendReceipt {
            accounting: self.accountant.receipt(),
            fully_written_slots: complete_slots,
            fully_written_frame_bytes: complete_bytes,
        };
        result.map(|_| receipt).map_err(|e| SendFailure {
            kind: e.kind(),
            receipt: SendReceipt {
                accounting: self.accountant.receipt(),
                fully_written_slots: complete_slots,
                fully_written_frame_bytes: complete_bytes,
            },
            partial_frame_may_have_been_written: partial,
        })
    }
    /// Reads exactly the public horizon's records. No payload is exposed until
    /// every cell authenticates. No EOF scan, implicit retries or negotiation.
    /// Returned empty cells are authenticated dummies; later bytes remain owned
    /// by the caller. This does not prove remote delivery of a sender receipt.
    pub async fn receive<S: AsyncRead + Unpin>(self, wire: &mut S) -> io::Result<ReceivedBatch> {
        let deadline = Instant::now() + self.profile.horizon() + self.profile.io_timeout;
        timeout_at(deadline, async {
            let cipher = ChaCha20Poly1305::new_from_slice(self.material.key.as_ref())
                .map_err(|_| invalid())?;
            let mut payloads = Vec::with_capacity(self.profile.slots);
            let mut bits = Vec::with_capacity(self.profile.slots);
            let mut wire_bytes = 0;
            for index in 0..self.profile.slots {
                let bit = timeout_at(
                    Instant::now() + self.profile.cadence + self.profile.io_timeout,
                    wire.read_u8(),
                )
                .await
                .map_err(|_| timed_out())??;
                let size = self.profile.frame_bytes(bit).map_err(|_| malformed())?;
                let mut frame = vec![0; size - 1];
                timeout_at(
                    Instant::now() + self.profile.io_timeout,
                    wire.read_exact(&mut frame),
                )
                .await
                .map_err(|_| timed_out())??;
                let cipher_len = self.profile.capacity + 2 + 16;
                if frame[cipher_len..].iter().any(|b| *b != 0) {
                    return Err(malformed());
                }
                let nonce = self.material.nonce(index);
                let aad = associated_data(&self.profile, index, bit);
                let plain = Zeroizing::new(
                    cipher
                        .decrypt(
                            nonce.as_ref().into(),
                            Payload {
                                msg: &frame[..cipher_len],
                                aad: &aad,
                            },
                        )
                        .map_err(|_| malformed())?,
                );
                let count = usize::from(u16::from_be_bytes([plain[0], plain[1]]));
                if count > self.profile.capacity || plain[2 + count..].iter().any(|b| *b != 0) {
                    return Err(malformed());
                }
                payloads.push(Zeroizing::new(plain[2..2 + count].to_vec()));
                bits.push(bit);
                wire_bytes += size;
            }
            Ok(ReceivedBatch {
                payloads,
                released_bits: bits,
                wire_bytes,
            })
        })
        .await
        .map_err(|_| timed_out())?
    }
}
fn associated_data(profile: &ScheduleProfile, index: usize, bit: u8) -> Vec<u8> {
    let mut aad = Vec::with_capacity(37);
    aad.extend_from_slice(&profile.descriptor);
    aad.extend_from_slice(&(index as u32).to_be_bytes());
    aad.push(bit);
    aad
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid or insufficient finite schedule contract",
    )
}
fn malformed() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "unauthenticated finite schedule batch",
    )
}
fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "finite schedule I/O timeout")
}

#[cfg(test)]
#[path = "schedule_emission_tests.rs"]
mod tests;
