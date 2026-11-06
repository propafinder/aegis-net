//! Opt-in one-message finite-cover control consumer. This is not a VPN carrier.
//! The exact cover marginal requires an independent uniformly random one-use
//! pad over ALL ciphertext bytes, including the authentication tag. A CSPRNG
//! only supplies a computational approximation to that ideal assumption.
use super::{
    coupling::MinimumEntropyCoupling,
    general_coupling::{FiniteDistribution, GeneralCoverByteCodec},
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305,
};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use std::{io, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::{timeout_at, Instant},
};
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"aegis.finite-cover-control.v2";
const MAX_WIRE: usize = 65_536;

/// Public, pre-agreed finite cover model, optionally prefix-conditioned. Token length, record
/// count, endpoints and timing are public and are NOT protected by this model.
#[derive(Clone, Debug)]
pub struct CoverModel {
    codec: CoverCodec,
    tokens: Vec<Vec<u8>>,
    capacity: usize,
    token_width: usize,
    symbol_count: usize,
    descriptor: [u8; 32],
    io_timeout: Duration,
}

#[derive(Clone, Debug)]
enum CoverCodec {
    Partition(MinimumEntropyCoupling),
    Iterative(GeneralCoverByteCodec),
}

impl CoverModel {
    /// Equal-width distinct tokens; exact equal-mass MEC partition only.
    /// Bits must divide eight, so every encrypted byte has an exact mapping.
    pub fn new(
        tokens: Vec<Vec<u8>>,
        weights: Vec<u64>,
        bits: u8,
        capacity: usize,
        io_timeout: Duration,
    ) -> io::Result<Self> {
        if ![1, 2, 4].contains(&bits)
            || !(1..=256).contains(&capacity)
            || tokens.len() != weights.len()
            || tokens.is_empty()
            || tokens.len() > 32
            || io_timeout.is_zero()
            || io_timeout > Duration::from_secs(30)
        {
            return Err(invalid());
        }
        let token_width = tokens[0].len();
        if !(1..=32).contains(&token_width)
            || tokens
                .iter()
                .enumerate()
                .any(|(i, t)| t.len() != token_width || tokens[..i].contains(t))
        {
            return Err(invalid());
        }
        let coupling = MinimumEntropyCoupling::new(weights, bits)?;
        let symbol_count = (capacity + 2 + 16) * (8 / usize::from(bits));
        if symbol_count * token_width > MAX_WIRE {
            return Err(invalid());
        }
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        hash.update(io_timeout.as_nanos().to_be_bytes());
        hash.update((capacity as u16).to_be_bytes());
        hash.update([bits, tokens.len() as u8, token_width as u8]);
        for (token, weight) in tokens.iter().zip(coupling.cover_weights()) {
            hash.update(weight.to_be_bytes());
            hash.update(token);
        }
        // Include the actual partition, not just a claim that peers share it.
        for row in coupling.joint_weights() {
            for weight in row {
                hash.update(weight.to_be_bytes());
            }
        }
        let descriptor = hash.finalize().into();
        Ok(Self {
            codec: CoverCodec::Partition(coupling),
            tokens,
            capacity,
            token_width,
            symbol_count,
            descriptor,
            io_timeout,
        })
    }
    /// Multi-block iterative minimum-entropy coupling for a general finite
    /// memoryless cover. A public fixed horizon is emitted even when posterior
    /// resolution fails; no successful-only retry or stop-time signaling.
    pub fn new_general(
        tokens: Vec<Vec<u8>>,
        weights: Vec<u64>,
        capacity: usize,
        horizon: usize,
        io_timeout: Duration,
    ) -> io::Result<Self> {
        if !(1..=256).contains(&capacity)
            || tokens.is_empty()
            || tokens.len() > 256
            || tokens.len() != weights.len()
            || io_timeout.is_zero()
            || io_timeout > Duration::from_secs(30)
        {
            return Err(invalid());
        }
        let token_width = tokens[0].len();
        if !(1..=32).contains(&token_width)
            || tokens
                .iter()
                .enumerate()
                .any(|(i, t)| t.len() != token_width || tokens[..i].contains(t))
        {
            return Err(invalid());
        }
        let codec =
            GeneralCoverByteCodec::new(FiniteDistribution::new(weights)?, capacity + 18, horizon)?;
        if horizon.checked_mul(token_width).ok_or_else(invalid)? > MAX_WIRE {
            return Err(invalid());
        }
        let mut h = Sha256::new();
        h.update(b"aegis.general-cover-control.imec-greedy-q32.v2");
        h.update(io_timeout.as_nanos().to_be_bytes());
        h.update((capacity as u16).to_be_bytes());
        h.update((horizon as u32).to_be_bytes());
        h.update((tokens.len() as u16).to_be_bytes());
        h.update([token_width as u8]);
        for (token, weight) in tokens.iter().zip(codec.cover().weights()) {
            h.update(weight.to_be_bytes());
            h.update(token);
        }
        Ok(Self {
            codec: CoverCodec::Iterative(codec),
            tokens,
            capacity,
            token_width,
            symbol_count: horizon,
            descriptor: h.finalize().into(),
            io_timeout,
        })
    }
    #[cfg(test)]
    fn partition(&self) -> &MinimumEntropyCoupling {
        match &self.codec {
            CoverCodec::Partition(p) => p,
            _ => panic!("legacy test fixture required"),
        }
    }
    /// Finite prefix-conditioned iMEC model; resets to initial_state per record.
    /// Complete tables and the original I/O allowance enter the AEAD descriptor.
    pub fn new_general_conditional(
        tokens: Vec<Vec<u8>>,
        model: super::general_coupling::ConditionalCoverSettings,
        capacity: usize,
        horizon: usize,
        io_timeout: Duration,
    ) -> io::Result<Self> {
        if !(1..=256).contains(&capacity)
            || tokens.is_empty()
            || tokens.len() > 256
            || io_timeout.is_zero()
            || io_timeout > Duration::from_secs(30)
        {
            return Err(invalid());
        }
        model.validate(tokens.len())?;
        let token_width = tokens[0].len();
        if !(1..=32).contains(&token_width)
            || tokens
                .iter()
                .enumerate()
                .any(|(i, t)| t.len() != token_width || tokens[..i].contains(t))
            || horizon
                .checked_mul(token_width)
                .is_none_or(|n| n > MAX_WIRE)
        {
            return Err(invalid());
        }
        let codec = GeneralCoverByteCodec::new_conditional(model.clone(), capacity + 18, horizon)?;
        let mut h = Sha256::new();
        h.update(b"aegis.conditional-cover-control.imec-greedy-q32.v1");
        h.update(io_timeout.as_nanos().to_be_bytes());
        h.update((capacity as u16).to_be_bytes());
        h.update((horizon as u32).to_be_bytes());
        h.update((tokens.len() as u16).to_be_bytes());
        h.update([token_width as u8]);
        for token in &tokens {
            h.update(token);
        }
        h.update(serde_json::to_vec(&model).map_err(|_| invalid())?);
        Ok(Self {
            codec: CoverCodec::Iterative(codec),
            tokens,
            capacity,
            token_width,
            symbol_count: horizon,
            descriptor: h.finalize().into(),
            io_timeout,
        })
    }
    pub fn descriptor_sha256(&self) -> [u8; 32] {
        self.descriptor
    }
    pub fn wire_bytes(&self) -> usize {
        self.symbol_count * self.token_width
    }
    /// Public payload capacity for admission before any I/O.
    pub fn capacity(&self) -> usize {
        self.capacity
    }
    pub fn pad_bytes(&self) -> usize {
        self.capacity + 2 + 16
    }
}

/// Non-Clone and not Debug: consumed on any send/receive attempt, including
/// cancellation, malformed data, entropy failure and partial I/O. Provision a
/// fresh dedicated key and independent pad for EACH direction/message. The
/// caller must prevent reuse across reconstruction, backups and restarts.
/// Neither this material nor its nonce is transmitted on the cover stream.
pub struct OneTimeMaterial {
    key: Zeroizing<[u8; 32]>,
    nonce: Zeroizing<[u8; 12]>,
    pad: Zeroizing<Vec<u8>>,
}
impl OneTimeMaterial {
    /// Material must already be shared with the intended peer over a trusted
    /// authenticated channel. This constructor does not establish freshness,
    /// uniformity, independence or trusted key delivery.
    pub fn from_preprovisioned(
        key: Zeroizing<[u8; 32]>,
        nonce: [u8; 12],
        pad: Zeroizing<Vec<u8>>,
    ) -> io::Result<Self> {
        if !(19..=274).contains(&pad.len()) {
            return Err(invalid());
        }
        Ok(Self {
            key,
            nonce: Zeroizing::new(nonce),
            pad,
        })
    }
}

/// One record only: no implicit handshake, cover model discovery, retries,
/// message chaining or default adoption by installed client transports.
pub struct ControlRecord {
    model: CoverModel,
    material: OneTimeMaterial,
}
impl ControlRecord {
    pub fn new(model: CoverModel, material: OneTimeMaterial) -> io::Result<Self> {
        if material.pad.len() != model.pad_bytes() {
            return Err(invalid());
        }
        Ok(Self { model, material })
    }

    /// Entire fixed record is encoded before the first write. Failure or
    /// cancellation consumes this object and never retries a partial record.
    /// One original operation cutoff includes encoding, writes and flush.
    /// A synchronous stall cannot be preempted; late completion is refused.
    pub async fn send<S: AsyncWrite + Unpin, R: RngCore + CryptoRng>(
        self,
        payload: &[u8],
        rng: &mut R,
        wire: &mut S,
    ) -> io::Result<usize> {
        let deadline = Instant::now() + self.model.io_timeout;
        if payload.len() > self.model.capacity {
            return Err(invalid());
        }
        let mut plain = Zeroizing::new(vec![0; self.model.capacity + 2]);
        plain[..2].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        plain[2..2 + payload.len()].copy_from_slice(payload);
        let cipher =
            ChaCha20Poly1305::new_from_slice(self.material.key.as_ref()).map_err(|_| invalid())?;
        let mut masked = Zeroizing::new(
            cipher
                .encrypt(
                    self.material.nonce.as_ref().into(),
                    Payload {
                        msg: &plain,
                        aad: &self.model.descriptor,
                    },
                )
                .map_err(|_| malformed())?,
        );
        for (byte, pad) in masked.iter_mut().zip(self.material.pad.iter()) {
            *byte ^= *pad;
        }
        let symbols = match &self.model.codec {
            CoverCodec::Iterative(codec) => codec.encode(&masked, rng)?,
            CoverCodec::Partition(coupling) => {
                let bits = coupling.bits_per_symbol();
                let mask = (1u8 << bits) - 1;
                let mut symbols = Vec::with_capacity(self.model.symbol_count);
                for byte in masked.iter() {
                    for shift in (0..8).step_by(usize::from(bits)).rev() {
                        symbols.push(coupling.encode(usize::from((byte >> shift) & mask), rng)?);
                    }
                }
                symbols
            }
        };
        if symbols.len() != self.model.symbol_count {
            return Err(malformed());
        }
        let mut encoded = vec![0; self.model.wire_bytes()];
        for (token, symbol) in encoded
            .chunks_exact_mut(self.model.token_width)
            .zip(symbols)
        {
            token.copy_from_slice(self.model.tokens.get(symbol).ok_or_else(malformed)?);
        }
        require_before(deadline)?;
        timeout_at(deadline, async {
            wire.write_all(&encoded).await?;
            require_before(deadline)?;
            wire.flush().await
        })
        .await
        .map_err(|_| timed_out())??;
        require_before(deadline)?;
        Ok(encoded.len()) // local completed write/flush; NOT remote acceptance
    }

    /// Reads exactly one pre-agreed fixed record, never scans for a header or
    /// waits for EOF. The caller owns the stream and any later records/closure.
    /// Equivalent tokens in the same MEC bin are intentionally interchangeable;
    /// authentication protects recovered content/model, not cover token choice.
    pub async fn receive<S: AsyncRead + Unpin>(
        self,
        wire: &mut S,
    ) -> io::Result<Zeroizing<Vec<u8>>> {
        let deadline = Instant::now() + self.model.io_timeout;
        let mut encoded = vec![0; self.model.wire_bytes()];
        require_before(deadline)?;
        timeout_at(deadline, wire.read_exact(&mut encoded))
            .await
            .map_err(|_| timed_out())??;
        require_before(deadline)?;
        let symbols = encoded
            .chunks_exact(self.model.token_width)
            .map(|token| {
                self.model
                    .tokens
                    .iter()
                    .position(|t| t == token)
                    .ok_or_else(malformed)
            })
            .collect::<io::Result<Vec<_>>>()?;
        let mut recovered = match &self.model.codec {
            CoverCodec::Iterative(codec) => Zeroizing::new(codec.decode(&symbols)?),
            CoverCodec::Partition(coupling) => {
                let bits = coupling.bits_per_symbol();
                let per_byte = 8 / usize::from(bits);
                let mut bytes = Zeroizing::new(vec![0u8; self.model.pad_bytes()]);
                for (i, symbol) in symbols.into_iter().enumerate() {
                    let shift = 8 - usize::from(bits) * (i % per_byte + 1);
                    bytes[i / per_byte] |= (coupling.decode(symbol)? as u8) << shift;
                }
                bytes
            }
        };
        for (byte, pad) in recovered.iter_mut().zip(self.material.pad.iter()) {
            *byte ^= *pad;
        }
        let cipher =
            ChaCha20Poly1305::new_from_slice(self.material.key.as_ref()).map_err(|_| invalid())?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    self.material.nonce.as_ref().into(),
                    Payload {
                        msg: &recovered,
                        aad: &self.model.descriptor,
                    },
                )
                .map_err(|_| malformed())?,
        );
        let count = usize::from(u16::from_be_bytes([plain[0], plain[1]]));
        if count > self.model.capacity || plain[2 + count..].iter().any(|b| *b != 0) {
            return Err(malformed());
        }
        let payload = Zeroizing::new(plain[2..2 + count].to_vec());
        require_before(deadline)?;
        Ok(payload)
    }
}
fn require_before(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(timed_out())
    } else {
        Ok(())
    }
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid finite cover control contract",
    )
}
fn malformed() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "unauthenticated finite cover control record",
    )
}
fn timed_out() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "finite cover control original operation cutoff",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };
    fn model() -> CoverModel {
        CoverModel::new(
            [b"a", b"b", b"c", b"d"].map(|t| t.to_vec()).to_vec(),
            vec![3, 1, 2, 2],
            1,
            32,
            Duration::from_secs(1),
        )
        .unwrap()
    }
    // Test material only: deterministic seeded entropy is not live provisioning.
    fn material(model: &CoverModel, seed: u64) -> OneTimeMaterial {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut key = Zeroizing::new([0; 32]);
        let mut pad = Zeroizing::new(vec![0; model.pad_bytes()]);
        let mut nonce = [0; 12];
        rng.fill_bytes(key.as_mut());
        rng.fill_bytes(&mut pad);
        rng.fill_bytes(&mut nonce);
        OneTimeMaterial::from_preprovisioned(key, nonce, pad).unwrap()
    }
    fn record(model: CoverModel, seed: u64) -> ControlRecord {
        let secret = material(&model, seed);
        ControlRecord::new(model, secret).unwrap()
    }
    async fn encoded(model: CoverModel, seed: u64, data: &[u8]) -> Vec<u8> {
        let mut wire = Vec::new();
        record(model, seed)
            .send(data, &mut StdRng::seed_from_u64(91), &mut wire)
            .await
            .unwrap();
        wire
    }
    #[tokio::test]
    async fn actual_tcp_consumers_deliver_authenticated_control_content() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        drop(listener);
        let mut client = client;
        let mut server = server;
        let send = async {
            record(model(), 43)
                .send(
                    b"rotate route 2",
                    &mut StdRng::seed_from_u64(51),
                    &mut client,
                )
                .await
                .unwrap()
        };
        let receive = record(model(), 43).receive(&mut server);
        let (written, received) = tokio::join!(send, receive);
        assert_eq!(written, model().wire_bytes());
        assert_eq!(received.unwrap().as_slice(), b"rotate route 2");
    }
    #[tokio::test]
    async fn fixed_wire_size_and_all_supported_bit_widths_roundtrip() {
        for bits in [1, 2, 4] {
            let count = 1usize << bits;
            let m = CoverModel::new(
                (0..count).map(|i| vec![i as u8]).collect(),
                vec![1; count],
                bits,
                32,
                Duration::from_secs(1),
            )
            .unwrap();
            for data in [vec![], vec![0, 255, 3], vec![87; 32]] {
                let wire = encoded(m.clone(), 9, &data).await;
                assert_eq!(wire.len(), m.wire_bytes());
                assert_eq!(
                    record(m.clone(), 9)
                        .receive(&mut wire.as_slice())
                        .await
                        .unwrap()
                        .as_slice(),
                    data
                );
            }
        }
    }
    #[test]
    fn agreed_cover_descriptor_binds_original_operation_budget() {
        let tokens = vec![vec![0], vec![1]];
        for general in [false, true] {
            let build = |budget| {
                if general {
                    CoverModel::new_general(tokens.clone(), vec![1, 1], 2, 256, budget)
                } else {
                    CoverModel::new(tokens.clone(), vec![1, 1], 1, 2, budget)
                }
            };
            let first = build(Duration::from_secs(1)).unwrap();
            let second = build(Duration::from_secs(2)).unwrap();
            assert_eq!(first.wire_bytes(), second.wire_bytes());
            assert_ne!(first.descriptor_sha256(), second.descriptor_sha256());
        }
    }
    #[test]
    fn exact_cover_marginals_under_explicit_uniform_message_premise() {
        let m = model();
        let joint = m.partition().joint_weights();
        let total: u64 = m.partition().cover_weights().iter().sum();
        for row in &joint {
            assert_eq!(row.iter().sum::<u64>() * 2, total);
        }
        for symbol in 0..m.tokens.len() {
            assert_eq!(
                joint.iter().map(|r| r[symbol]).sum::<u64>(),
                m.partition().cover_weights()[symbol]
            );
        }
        // For every fixed ciphertext byte, XOR with all256 equiprobable pad
        // bytes yields every masked byte exactly once, regardless of its tag.
        for ciphertext in 0..=255u8 {
            let mut counts = [0u16; 256];
            for pad in 0..=255u8 {
                counts[usize::from(ciphertext ^ pad)] += 1;
            }
            assert!(counts.into_iter().all(|c| c == 1));
        }
        // This is a finite conditional identity, not measured real wire DP.
    }
    #[tokio::test]
    async fn altered_message_bin_and_unknown_token_are_refused() {
        let m = model();
        let wire = encoded(m.clone(), 7, b"control").await;
        let symbol = m.tokens.iter().position(|t| t == &wire[..1]).unwrap();
        let group = m.partition().decode(symbol).unwrap();
        let other = (0..m.tokens.len())
            .find(|i| m.partition().decode(*i).unwrap() != group)
            .unwrap();
        let mut tampered = wire.clone();
        tampered[0] = m.tokens[other][0];
        assert_eq!(
            record(m.clone(), 7)
                .receive(&mut tampered.as_slice())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        let mut unknown = wire;
        unknown[0] = b'x';
        assert!(record(m, 7).receive(&mut unknown.as_slice()).await.is_err());
    }
    #[tokio::test]
    async fn equivalent_tokens_preserve_authenticated_content() {
        let m = model();
        let mut wire = encoded(m.clone(), 7, b"control").await;
        let symbol = m.tokens.iter().position(|t| t == &wire[..1]).unwrap();
        let group = m.partition().decode(symbol).unwrap();
        let other = (0..m.tokens.len())
            .find(|i| *i != symbol && m.partition().decode(*i).unwrap() == group)
            .unwrap();
        wire[0] = m.tokens[other][0];
        assert_eq!(
            record(m, 7)
                .receive(&mut wire.as_slice())
                .await
                .unwrap()
                .as_slice(),
            b"control"
        );
    }
    #[tokio::test]
    async fn wrong_material_and_agreed_descriptor_are_refused() {
        let m = model();
        let wire = encoded(m.clone(), 7, b"control").await;
        assert!(record(m.clone(), 8)
            .receive(&mut wire.as_slice())
            .await
            .is_err());
        let other = CoverModel::new(
            m.tokens.clone(),
            vec![4, 2, 3, 3],
            1,
            32,
            Duration::from_secs(1),
        )
        .unwrap();
        assert_ne!(m.descriptor_sha256(), other.descriptor_sha256());
        // Same partition and token decoding, different authenticated weights.
        assert_eq!(
            m.partition()
                .joint_weights()
                .iter()
                .map(|r| r.iter().map(|w| *w != 0).collect::<Vec<_>>())
                .collect::<Vec<_>>(),
            other
                .partition()
                .joint_weights()
                .iter()
                .map(|r| r.iter().map(|w| *w != 0).collect::<Vec<_>>())
                .collect::<Vec<_>>()
        );
        assert!(record(other, 7)
            .receive(&mut wire.as_slice())
            .await
            .is_err());
    }
    #[tokio::test]
    async fn truncation_and_extra_stream_bytes_are_not_conflated() {
        let m = model();
        let mut wire = encoded(m.clone(), 7, b"control").await;
        assert_eq!(
            record(m.clone(), 7)
                .receive(&mut &wire[..wire.len() - 1])
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
        wire.extend_from_slice(b"next");
        let mut input = wire.as_slice();
        assert_eq!(
            record(m, 7).receive(&mut input).await.unwrap().as_slice(),
            b"control"
        );
        assert_eq!(input, b"next");
    }
    #[tokio::test(start_paused = true)]
    async fn idle_input_and_blocked_output_have_bounded_cooperative_deadlines() {
        let (mut reader, _held) = tokio::io::duplex(1);
        assert_eq!(
            record(model(), 7)
                .receive(&mut reader)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        let (mut writer, _held) = tokio::io::duplex(1);
        assert_eq!(
            record(model(), 7)
                .send(b"a", &mut StdRng::seed_from_u64(1), &mut writer)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
    }
    struct BrokenEntropy;
    impl RngCore for BrokenEntropy {
        fn next_u32(&mut self) -> u32 {
            panic!("infallible entropy forbidden")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("infallible entropy forbidden")
        }
        fn fill_bytes(&mut self, _: &mut [u8]) {
            panic!("infallible entropy forbidden")
        }
        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand::Error> {
            Err(rand::Error::new(io::Error::other(
                "controlled entropy failure",
            )))
        }
    }
    impl CryptoRng for BrokenEntropy {}
    #[tokio::test]
    async fn entropy_and_oversize_refusals_emit_no_prefix() {
        let mut wire = Vec::new();
        assert!(record(model(), 7)
            .send(b"a", &mut BrokenEntropy, &mut wire)
            .await
            .is_err());
        assert!(wire.is_empty());
        assert!(record(model(), 7)
            .send(&[1; 33], &mut StdRng::seed_from_u64(1), &mut wire)
            .await
            .is_err());
        assert!(wire.is_empty());
    }
    // Controlled synchronous stalls exercise late-ready polling. They do not
    // model a real network or claim a kernel-preemptible deadline.
    fn short_budget_model() -> CoverModel {
        let mut m = model();
        m.io_timeout = Duration::from_millis(5);
        m
    }
    struct SlowEntropy(StdRng, bool);
    impl RngCore for SlowEntropy {
        fn next_u32(&mut self) -> u32 {
            self.0.next_u32()
        }
        fn next_u64(&mut self) -> u64 {
            self.0.next_u64()
        }
        fn fill_bytes(&mut self, bytes: &mut [u8]) {
            self.try_fill_bytes(bytes).unwrap();
        }
        fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand::Error> {
            if !self.1 {
                self.1 = true;
                std::thread::sleep(Duration::from_millis(25));
            }
            self.0.try_fill_bytes(bytes)
        }
    }
    impl CryptoRng for SlowEntropy {}
    #[tokio::test]
    async fn original_cover_budget_includes_entropy_before_emission() {
        let mut wire = Vec::new();
        let result = record(short_budget_model(), 7)
            .send(
                b"control",
                &mut SlowEntropy(StdRng::seed_from_u64(51), false),
                &mut wire,
            )
            .await;
        assert!(wire.is_empty(), "late encoding must emit no prefix");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }
    #[derive(Default)]
    struct LateFlush(Vec<u8>);
    impl AsyncWrite for LateFlush {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.0.extend_from_slice(data);
            Poll::Ready(Ok(data.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            std::thread::sleep(Duration::from_millis(25));
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    #[tokio::test]
    async fn original_cover_budget_refuses_late_ready_flush_and_retains_actual_prefix() {
        let m = short_budget_model();
        let expected = m.wire_bytes();
        let mut wire = LateFlush::default();
        let result = record(m, 7)
            .send(b"control", &mut StdRng::seed_from_u64(51), &mut wire)
            .await;
        assert_eq!(wire.0.len(), expected);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }
    struct LateRead(Vec<u8>);
    impl AsyncRead for LateRead {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            std::thread::sleep(Duration::from_millis(25));
            buf.put_slice(&self.0);
            Poll::Ready(Ok(()))
        }
    }
    #[tokio::test]
    async fn original_cover_budget_refuses_late_ready_read_without_plaintext() {
        let wire = encoded(model(), 7, b"control").await;
        assert_eq!(
            record(short_budget_model(), 7)
                .receive(&mut LateRead(wire))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
    }
    #[derive(Default)]
    struct PartialFailure {
        bytes: Vec<u8>,
        calls: usize,
    }
    impl AsyncWrite for PartialFailure {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.calls += 1;
            if self.calls == 1 {
                self.bytes.extend_from_slice(&data[..7]);
                Poll::Ready(Ok(7))
            } else {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "controlled sink failure",
                )))
            }
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    #[tokio::test]
    async fn partial_sink_failure_is_terminal_without_retry() {
        let mut wire = PartialFailure::default();
        assert_eq!(
            record(model(), 7)
                .send(b"a", &mut StdRng::seed_from_u64(1), &mut wire)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(wire.bytes.len(), 7);
        assert_eq!(wire.calls, 2);
    }
    #[test]
    fn model_and_secret_contract_bound_allocations() {
        let tokens = vec![vec![0; 32], vec![1; 32]];
        assert!(CoverModel::new(tokens, vec![1, 1], 1, 256, Duration::from_secs(1)).is_err());
        for bits in [0, 3, 5] {
            assert!(CoverModel::new(
                vec![vec![0], vec![1]],
                vec![1, 1],
                bits,
                2,
                Duration::from_secs(1)
            )
            .is_err());
        }
        assert!(CoverModel::new(
            vec![vec![0], vec![0]],
            vec![1, 1],
            1,
            2,
            Duration::from_secs(1)
        )
        .is_err());
        assert!(CoverModel::new(
            (0..33).map(|i| vec![i]).collect(),
            vec![1; 33],
            1,
            2,
            Duration::from_secs(1)
        )
        .is_err());
        assert!(CoverModel::new(
            vec![vec![0], vec![1, 2]],
            vec![1, 1],
            1,
            2,
            Duration::from_secs(1)
        )
        .is_err());
        assert!(ControlRecord::new(
            model(),
            material(
                &CoverModel::new(
                    vec![vec![0], vec![1]],
                    vec![1, 1],
                    1,
                    2,
                    Duration::from_secs(1)
                )
                .unwrap(),
                1
            )
        )
        .is_err());
    }
}
