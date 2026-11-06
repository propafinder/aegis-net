//! Bounded deferred-response MODEL only: no HTTPS server, browser, or compatibility claim.
//! Opaque payloads must already be inner-TLS ciphertext. The cover hash, session,
//! and sequence fields synchronize this model; they do not authenticate payloads.
//! Callers supply fresh session IDs and drive expiry (or drop the owner). There is
//! no shared cache. Replacement preserves body length, not TLS records or timing.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use thiserror::Error;

pub type SessionId = [u8; 16];
const HEADER: usize = 64;
const MAGIC: &[u8; 4] = b"DCM1";
const MAX_BODY: usize = 1 << 20;

#[derive(Clone, Copy, Debug)]
pub struct CoverConfig {
    pub max_body_bytes: usize,
    /// Counts full prepared bodies, including framing and cover bytes.
    pub max_queued_bytes: usize,
    pub max_queued_chunks: usize,
    pub max_polls: u64,
    pub ttl_ticks: u64,
}
impl Default for CoverConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: 4096,
            max_queued_bytes: 16384,
            max_queued_chunks: 4,
            max_polls: 64,
            ttl_ticks: 128,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CoverError {
    #[error("invalid cover or finite budget configuration")]
    Config,
    #[error("cover length, version, framing, or unchanged suffix mismatch")]
    Cover,
    #[error("session binding mismatch")]
    Session,
    #[error("sequence gap, reorder, replay, or exhaustion")]
    Sequence,
    #[error("body, queue, or poll budget exceeded")]
    Budget,
    #[error("model time moved backwards")]
    Clock,
    #[error("model TTL expired")]
    Expired,
    #[error("model cancelled or closed")]
    Closed,
}

#[derive(Clone)]
pub struct KnownCover {
    body: Vec<u8>,
    hash: [u8; 32],
}
impl KnownCover {
    pub fn new(body: Vec<u8>) -> Result<Self, CoverError> {
        if body.len() <= HEADER || body.len() > MAX_BODY || body.starts_with(MAGIC) {
            return Err(CoverError::Config);
        }
        let hash = Sha256::digest(&body).into();
        Ok(Self { body, hash })
    }
    pub fn capacity(&self) -> usize {
        self.body.len() - HEADER
    }
    pub fn body_len(&self) -> usize {
        self.body.len()
    }
}

struct Lifetime {
    last: u64,
    deadline: u64,
    polls: u64,
    closed: bool,
}
impl Lifetime {
    fn new(
        id: SessionId,
        c: CoverConfig,
        cover: &KnownCover,
        tick: u64,
    ) -> Result<Self, CoverError> {
        if id == [0; 16]
            || c.max_body_bytes > MAX_BODY
            || cover.body_len() > c.max_body_bytes
            || c.max_queued_chunks == 0
            || c.max_queued_chunks > 256
            || c.max_queued_bytes < cover.body_len()
            || c.max_queued_bytes > 16 * MAX_BODY
            || c.max_polls == 0
            || c.max_polls > 100_000
            || c.ttl_ticks == 0
        {
            return Err(CoverError::Config);
        }
        let deadline = tick.checked_add(c.ttl_ticks).ok_or(CoverError::Config)?;
        Ok(Self {
            last: tick,
            deadline,
            polls: 0,
            closed: false,
        })
    }
    fn check(&mut self, tick: u64, max_polls: u64) -> Result<(), CoverError> {
        if self.closed {
            return Err(CoverError::Closed);
        }
        if tick < self.last {
            return Err(CoverError::Clock);
        }
        if tick >= self.deadline {
            return Err(CoverError::Expired);
        }
        if self.polls >= max_polls {
            return Err(CoverError::Budget);
        }
        self.last = tick;
        self.polls += 1;
        Ok(())
    }
}

pub struct DeferredCover {
    id: SessionId,
    cover: KnownCover,
    config: CoverConfig,
    life: Lifetime,
    next_seq: u64,
    prepared: VecDeque<Vec<u8>>,
}
impl DeferredCover {
    pub fn new(
        id: SessionId,
        cover: KnownCover,
        config: CoverConfig,
        tick: u64,
    ) -> Result<Self, CoverError> {
        let life = Lifetime::new(id, config, &cover, tick)?;
        Ok(Self {
            id,
            cover,
            config,
            life,
            next_seq: 0,
            prepared: VecDeque::new(),
        })
    }
    pub fn retained_bytes(&self) -> usize {
        self.prepared.len() * self.cover.body_len()
    }
    pub fn cancel(&mut self) {
        self.prepared.clear();
        self.life.closed = true;
    }
    /// A synchronous model needs its owner/sweeper to drive the deadline.
    pub fn expire(&mut self, tick: u64) -> bool {
        if tick >= self.life.deadline {
            self.cancel();
            true
        } else {
            false
        }
    }
    /// Emits only a previously prepared body. All incoming chunks become eligible
    /// on a later poll, even the first poll. Any invalid request closes and clears.
    pub fn poll(
        &mut self,
        id: SessionId,
        tick: u64,
        incoming: &[(u64, &[u8])],
    ) -> Result<Vec<u8>, CoverError> {
        let result = self.poll_inner(id, tick, incoming);
        if result.is_err() {
            self.cancel();
        }
        result
    }
    fn poll_inner(
        &mut self,
        id: SessionId,
        tick: u64,
        incoming: &[(u64, &[u8])],
    ) -> Result<Vec<u8>, CoverError> {
        self.life.check(tick, self.config.max_polls)?;
        if id != self.id {
            return Err(CoverError::Session);
        }
        let remaining = self.prepared.len().saturating_sub(1);
        let count = remaining
            .checked_add(incoming.len())
            .ok_or(CoverError::Budget)?;
        if count > self.config.max_queued_chunks
            || count > self.config.max_queued_bytes / self.cover.body_len()
        {
            return Err(CoverError::Budget);
        }
        let mut next = self.next_seq;
        for &(seq, bytes) in incoming {
            if seq != next {
                return Err(CoverError::Sequence);
            }
            if bytes.is_empty() || bytes.len() > self.cover.capacity() {
                return Err(CoverError::Budget);
            }
            next = next.checked_add(1).ok_or(CoverError::Sequence)?;
        }
        let output = self
            .prepared
            .pop_front()
            .unwrap_or_else(|| self.cover.body.clone());
        for &(seq, bytes) in incoming {
            let mut body = self.cover.body.clone();
            body[..4].copy_from_slice(MAGIC);
            body[4..20].copy_from_slice(&self.id);
            body[20..28].copy_from_slice(&seq.to_be_bytes());
            body[28..32].copy_from_slice(&(bytes.len() as u32).to_be_bytes());
            body[32..HEADER].copy_from_slice(&self.cover.hash);
            body[HEADER..HEADER + bytes.len()].copy_from_slice(bytes);
            self.prepared.push_back(body);
        }
        self.next_seq = next;
        Ok(output)
    }
}

pub struct CoverDecoder {
    id: SessionId,
    cover: KnownCover,
    config: CoverConfig,
    life: Lifetime,
    next_seq: u64,
}
impl CoverDecoder {
    pub fn new(
        id: SessionId,
        cover: KnownCover,
        config: CoverConfig,
        tick: u64,
    ) -> Result<Self, CoverError> {
        let life = Lifetime::new(id, config, &cover, tick)?;
        Ok(Self {
            id,
            cover,
            config,
            life,
            next_seq: 0,
        })
    }
    pub fn cancel(&mut self) {
        self.life.closed = true;
    }
    /// Returned bytes are unauthenticated carrier bytes; only inner TLS can
    /// establish their integrity. Failure closes the decoder without advancing.
    pub fn recover(&mut self, tick: u64, body: &[u8]) -> Result<Option<Vec<u8>>, CoverError> {
        let result = self.recover_inner(tick, body);
        if result.is_err() {
            self.cancel();
        }
        result
    }
    fn recover_inner(&mut self, tick: u64, body: &[u8]) -> Result<Option<Vec<u8>>, CoverError> {
        self.life.check(tick, self.config.max_polls)?;
        if body.len() != self.cover.body_len() {
            return Err(CoverError::Cover);
        }
        if body == self.cover.body {
            return Ok(None);
        }
        if &body[..4] != MAGIC || body[32..HEADER] != self.cover.hash {
            return Err(CoverError::Cover);
        }
        if body[4..20] != self.id {
            return Err(CoverError::Session);
        }
        let seq = u64::from_be_bytes(body[20..28].try_into().map_err(|_| CoverError::Cover)?);
        if seq != self.next_seq {
            return Err(CoverError::Sequence);
        }
        let len =
            u32::from_be_bytes(body[28..32].try_into().map_err(|_| CoverError::Cover)?) as usize;
        if len == 0
            || len > self.cover.capacity()
            || body[HEADER + len..] != self.cover.body[HEADER + len..]
        {
            return Err(CoverError::Cover);
        }
        let next = seq.checked_add(1).ok_or(CoverError::Sequence)?;
        let opaque = body[HEADER..HEADER + len].to_vec();
        self.next_seq = next;
        Ok(Some(opaque))
    }
}

#[derive(Debug, Serialize)]
pub struct DemoSummary {
    pub scope: &'static str,
    pub cover_bytes: usize,
    pub recovered_bytes: usize,
    pub first_poll_plain: bool,
    pub deferred_to_next_poll: bool,
    pub retained_after_cancel: usize,
}
pub fn demo() -> Result<DemoSummary, CoverError> {
    let cover = KnownCover::new(vec![b'.'; 128])?;
    let mut sender = DeferredCover::new([1; 16], cover.clone(), CoverConfig::default(), 0)?;
    let mut decoder = CoverDecoder::new([1; 16], cover.clone(), CoverConfig::default(), 0)?;
    let opaque = [0x17, 0x03, 0x03, 0, 3, 0xa1, 0xb2, 0xc3]; // Fixture bytes, not a TLS transcript.
    let first = sender.poll([1; 16], 0, &[(0, &opaque)])?;
    let first_poll_plain = decoder.recover(0, &first)?.is_none();
    let second = sender.poll([1; 16], 1, &[])?;
    let recovered = decoder.recover(1, &second)?.ok_or(CoverError::Cover)?;
    sender.cancel();
    Ok(DemoSummary {
        scope: "local_deferred_cover_model_only",
        cover_bytes: second.len(),
        recovered_bytes: recovered.len(),
        first_poll_plain,
        deferred_to_next_poll: first == cover.body && recovered == opaque,
        retained_after_cancel: sender.retained_bytes(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pair(c: CoverConfig) -> (DeferredCover, CoverDecoder) {
        let cover = KnownCover::new(vec![b'.'; 128]).unwrap();
        (
            DeferredCover::new([1; 16], cover.clone(), c, 0).unwrap(),
            CoverDecoder::new([1; 16], cover, c, 0).unwrap(),
        )
    }
    #[test]
    fn first_and_current_poll_cannot_emit_new_bytes() {
        let (mut s, mut d) = pair(CoverConfig::default());
        assert_eq!(
            d.recover(0, &s.poll([1; 16], 0, &[(0, b"old")]).unwrap())
                .unwrap(),
            None
        );
        assert_eq!(
            d.recover(1, &s.poll([1; 16], 1, &[(1, b"future")]).unwrap())
                .unwrap(),
            Some(b"old".to_vec())
        );
        assert_eq!(
            d.recover(2, &s.poll([1; 16], 2, &[]).unwrap()).unwrap(),
            Some(b"future".to_vec())
        );
    }
    #[test]
    fn exact_length_and_full_capacity_roundtrip() {
        let (mut s, mut d) = pair(CoverConfig::default());
        let bytes = [0xfa; 64];
        assert_eq!(s.poll([1; 16], 0, &[(0, &bytes)]).unwrap().len(), 128);
        let body = s.poll([1; 16], 1, &[]).unwrap();
        assert_eq!(body.len(), 128);
        assert_eq!(d.recover(1, &body).unwrap(), Some(bytes.to_vec()));
    }
    #[test]
    fn cross_session_cover_and_suffix_mismatch_fail_closed() {
        let (mut s, _) = pair(CoverConfig::default());
        s.poll([1; 16], 0, &[(0, b"x")]).unwrap();
        let body = s.poll([1; 16], 1, &[]).unwrap();
        let cover = KnownCover::new(vec![b'.'; 128]).unwrap();
        let mut alien = CoverDecoder::new([2; 16], cover, CoverConfig::default(), 0).unwrap();
        assert_eq!(alien.recover(1, &body), Err(CoverError::Session));
        assert_eq!(alien.recover(2, &body), Err(CoverError::Closed));
        let wrong = KnownCover::new(vec![b'#'; 128]).unwrap();
        let mut wrong = CoverDecoder::new([1; 16], wrong, CoverConfig::default(), 0).unwrap();
        assert_eq!(wrong.recover(1, &body), Err(CoverError::Cover));
        for index in [32, 127] {
            let (_, mut d) = pair(CoverConfig::default());
            let mut changed = body.clone();
            changed[index] ^= 1;
            assert_eq!(d.recover(1, &changed), Err(CoverError::Cover));
        }
    }
    #[test]
    fn opaque_payload_integrity_is_an_inner_tls_boundary() {
        let (mut s, mut d) = pair(CoverConfig::default());
        s.poll([1; 16], 0, &[(0, b"opaque")]).unwrap();
        let mut body = s.poll([1; 16], 1, &[]).unwrap();
        body[HEADER] ^= 1;
        assert_eq!(d.recover(1, &body).unwrap().unwrap()[0], b'o' ^ 1);
    }
    #[test]
    fn sequence_gap_and_replay_rejected() {
        let (mut s, mut d) = pair(CoverConfig::default());
        s.poll([1; 16], 0, &[(0, b"a"), (1, b"b")]).unwrap();
        let first = s.poll([1; 16], 1, &[]).unwrap();
        let second = s.poll([1; 16], 2, &[]).unwrap();
        assert!(d.recover(1, &first).unwrap().is_some());
        assert_eq!(d.recover(2, &first), Err(CoverError::Sequence));
        let (_, mut gap) = pair(CoverConfig::default());
        assert_eq!(gap.recover(2, &second), Err(CoverError::Sequence));
        let (mut bad, _) = pair(CoverConfig::default());
        assert_eq!(
            bad.poll([1; 16], 0, &[(1, b"gap")]),
            Err(CoverError::Sequence)
        );
    }
    #[test]
    fn finite_bounds_and_cancel_clear_prepared_bodies() {
        let config = CoverConfig {
            max_queued_chunks: 1,
            max_queued_bytes: 128,
            ..CoverConfig::default()
        };
        let (mut s, _) = pair(config);
        assert_eq!(
            s.poll([1; 16], 0, &[(0, b"a"), (1, b"b")]),
            Err(CoverError::Budget)
        );
        assert_eq!(s.retained_bytes(), 0);
        let (mut s, _) = pair(config);
        assert_eq!(
            s.poll([1; 16], 0, &[(0, &[0; 65])]),
            Err(CoverError::Budget)
        );
        let (mut s, _) = pair(config);
        s.poll([1; 16], 0, &[(0, b"a")]).unwrap();
        assert_eq!(s.retained_bytes(), 128);
        s.cancel();
        assert_eq!(s.retained_bytes(), 0);
        assert_eq!(s.poll([1; 16], 1, &[]), Err(CoverError::Closed));
    }
    #[test]
    fn ttl_poll_and_clock_budgets_close_and_clear() {
        let (mut s, _) = pair(CoverConfig {
            ttl_ticks: 2,
            ..CoverConfig::default()
        });
        s.poll([1; 16], 0, &[(0, b"a")]).unwrap();
        assert_eq!(s.poll([1; 16], 2, &[]), Err(CoverError::Expired));
        assert_eq!(s.retained_bytes(), 0);
        let (mut s, _) = pair(CoverConfig {
            max_polls: 1,
            ..CoverConfig::default()
        });
        s.poll([1; 16], 0, &[(0, b"a")]).unwrap();
        assert_eq!(s.poll([1; 16], 1, &[]), Err(CoverError::Budget));
        assert_eq!(s.retained_bytes(), 0);
        let (mut s, _) = pair(CoverConfig::default());
        s.poll([1; 16], 1, &[(0, b"a")]).unwrap();
        assert_eq!(s.poll([1; 16], 0, &[]), Err(CoverError::Clock));
        assert_eq!(s.retained_bytes(), 0);
    }
}
