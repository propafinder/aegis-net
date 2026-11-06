//! Explicit raw-legacy v4 challenge/proof exchange; the shared v3 codec is unchanged.
//!
//! The `legacy-challenge-v1` client/server Cargo feature selects this protocol on
//! their raw legacy path. A caller must already validate outer TLS authority, hold
//! its setup permit through proof, and supply its original admission deadline.
//! The single connector callback is reached only after fresh, matched-key proof.
//! It must retain the existing target policy and established-stream bounds.

use super::{
    encode_stream_frame, read_stream_frame, TunnelRequest, TunnelResponse, TunnelStatus,
    MAX_TUNNEL_CONTROL_FRAME, TUNNEL_NONCE_LEN, TUNNEL_SALT_LEN,
};
use crate::error::{AegisError, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use std::future::{poll_fn, Future};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::time::{Duration, Instant};
use zeroize::Zeroizing;

const VERSION: u8 = 4;
const BINDING_LEN: usize = 32;
const CHALLENGE_LEN: usize = 32;
const ENVELOPE_OVERHEAD: usize = TUNNEL_SALT_LEN + TUNNEL_NONCE_LEN + 16;

#[derive(Clone, Copy)]
enum Role {
    Open = 1,
    Challenge = 2,
    Proof = 3,
    Final = 4,
}

impl Role {
    fn label(self) -> &'static [u8] {
        match self {
            Self::Open => b"aegis-legacy-challenge-v1/c2s-open",
            Self::Challenge => b"aegis-legacy-challenge-v1/s2c-challenge",
            Self::Proof => b"aegis-legacy-challenge-v1/c2s-proof",
            Self::Final => b"aegis-legacy-challenge-v1/s2c-final",
        }
    }
}

fn codec(message: &'static str) -> AegisError {
    AegisError::RelayCodec(message.into())
}

fn deadline_error() -> AegisError {
    codec("fresh legacy admission deadline expired")
}

fn check_deadline(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        return Err(deadline_error());
    }
    Ok(())
}

fn guarded_poll<F, T>(
    mut future: Pin<&mut F>,
    cx: &mut Context<'_>,
    deadline: Instant,
    now: impl Fn() -> Instant,
) -> Poll<Result<T>>
where
    F: Future<Output = Result<T>>,
{
    if now() >= deadline {
        return Poll::Ready(Err(deadline_error()));
    }
    match future.as_mut().poll(cx) {
        Poll::Ready(result) => {
            if now() >= deadline {
                Poll::Ready(Err(deadline_error()))
            } else {
                Poll::Ready(result)
            }
        }
        Poll::Pending => Poll::Pending,
    }
}

async fn until_deadline<F, T>(deadline: Instant, future: F) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    let mut future = std::pin::pin!(future);
    tokio::time::timeout_at(
        deadline,
        poll_fn(|cx| guarded_poll(future.as_mut(), cx, deadline, Instant::now)),
    )
    .await
    .map_err(|_| deadline_error())?
}

fn random<R: RngCore + CryptoRng>(rng: &mut R, bytes: &mut [u8]) -> Result<()> {
    rng.try_fill_bytes(bytes)
        .map_err(|_| codec("fresh legacy randomness unavailable"))
}

fn key(role: Role, secret: &[u8], salt: &[u8]) -> Result<Key> {
    if secret.is_empty() {
        return Err(AegisError::Auth);
    }
    let hk = Hkdf::<Sha256>::new(Some(salt), secret);
    let mut bytes = Zeroizing::new([0u8; 32]);
    hk.expand(role.label(), &mut *bytes)
        .map_err(|_| codec("fresh legacy HKDF failed"))?;
    Ok(*Key::from_slice(bytes.as_ref()))
}

fn seal<R: RngCore + CryptoRng>(
    role: Role,
    plain: &[u8],
    secret: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>> {
    if plain.len() < 2 || plain.len() > MAX_TUNNEL_CONTROL_FRAME - ENVELOPE_OVERHEAD {
        return Err(codec("fresh legacy plaintext length invalid"));
    }
    let mut salt = [0u8; TUNNEL_SALT_LEN];
    let mut nonce = [0u8; TUNNEL_NONCE_LEN];
    random(rng, &mut salt)?;
    random(rng, &mut nonce)?;
    let cipher = ChaCha20Poly1305::new(&key(role, secret, &salt)?);
    let encrypted = cipher
        .encrypt(Nonce::from_slice(&nonce), plain)
        .map_err(|_| codec("fresh legacy encryption failed"))?;
    let mut frame = Vec::with_capacity(ENVELOPE_OVERHEAD + plain.len());
    frame.extend_from_slice(&salt);
    frame.extend_from_slice(&nonce);
    frame.extend_from_slice(&encrypted);
    Ok(frame)
}

fn open(role: Role, frame: &[u8], secret: &[u8]) -> Result<Vec<u8>> {
    if !(ENVELOPE_OVERHEAD + 2..=MAX_TUNNEL_CONTROL_FRAME).contains(&frame.len()) {
        return Err(codec("fresh legacy envelope length invalid"));
    }
    let salt = &frame[..TUNNEL_SALT_LEN];
    let nonce = &frame[TUNNEL_SALT_LEN..TUNNEL_SALT_LEN + TUNNEL_NONCE_LEN];
    let encrypted = &frame[TUNNEL_SALT_LEN + TUNNEL_NONCE_LEN..];
    let cipher = ChaCha20Poly1305::new(&key(role, secret, salt)?);
    let plain = cipher
        .decrypt(Nonce::from_slice(nonce), encrypted)
        .map_err(|_| AegisError::Auth)?;
    if plain.len() < 2 || plain[0] != VERSION || plain[1] != role as u8 {
        return Err(codec("fresh legacy version/role invalid"));
    }
    Ok(plain)
}

fn binding(frame: &[u8]) -> Result<[u8; BINDING_LEN]> {
    if frame.len() > MAX_TUNNEL_CONTROL_FRAME {
        return Err(codec("fresh legacy Open too large"));
    }
    let len = u32::try_from(frame.len()).map_err(|_| codec("fresh legacy Open too large"))?;
    let mut hash = Sha256::new();
    hash.update(b"aegis-legacy-challenge-v1/open\0");
    hash.update(len.to_be_bytes());
    hash.update(frame);
    Ok(hash.finalize().into())
}

fn open_request(plain: &[u8]) -> Result<TunnelRequest> {
    if plain.len() < 6 {
        return Err(codec("fresh legacy Open truncated"));
    }
    let len = u16::from_be_bytes([plain[2], plain[3]]) as usize;
    if plain.len() != 6 + len {
        return Err(codec("fresh legacy Open length invalid"));
    }
    let host = std::str::from_utf8(&plain[4..4 + len])
        .map_err(|_| codec("fresh legacy host is not UTF-8"))?
        .to_owned();
    let port = u16::from_be_bytes([plain[4 + len], plain[5 + len]]);
    Ok(TunnelRequest { host, port })
}

fn pair(role: Role, binding: &[u8; BINDING_LEN], nonce: &[u8; CHALLENGE_LEN]) -> Vec<u8> {
    let mut plain = Vec::with_capacity(2 + BINDING_LEN + CHALLENGE_LEN);
    plain.extend_from_slice(&[VERSION, role as u8]);
    plain.extend_from_slice(binding);
    plain.extend_from_slice(nonce);
    plain
}

fn check_pair(
    plain: &[u8],
    binding: &[u8; BINDING_LEN],
    nonce: &[u8; CHALLENGE_LEN],
) -> Result<()> {
    if plain.len() < 2 + BINDING_LEN + CHALLENGE_LEN
        || &plain[2..2 + BINDING_LEN] != binding
        || &plain[2 + BINDING_LEN..2 + BINDING_LEN + CHALLENGE_LEN] != nonce
    {
        return Err(AegisError::Auth);
    }
    Ok(())
}

/// Non-Clone client context bound to the exact Open envelope sent on this stream.
pub struct ClientOpen<'a> {
    secret: &'a [u8],
    binding: [u8; BINDING_LEN],
}
/// Non-Clone context awaiting only the Final for this Open and server challenge.
pub struct ClientProof<'a> {
    secret: &'a [u8],
    binding: [u8; BINDING_LEN],
    nonce: [u8; CHALLENGE_LEN],
}

impl<'a> ClientOpen<'a> {
    pub fn start(request: &TunnelRequest, secret: &'a [u8]) -> Result<(Vec<u8>, Self)> {
        Self::start_with_rng(request, secret, &mut rand::rngs::OsRng)
    }

    fn start_with_rng<R: RngCore + CryptoRng>(
        request: &TunnelRequest,
        secret: &'a [u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, Self)> {
        let len =
            u16::try_from(request.host.len()).map_err(|_| codec("fresh legacy host too large"))?;
        if request.host.len() > MAX_TUNNEL_CONTROL_FRAME - ENVELOPE_OVERHEAD - 6 {
            return Err(codec("fresh legacy host too large"));
        }
        let mut plain = vec![VERSION, Role::Open as u8];
        plain.extend_from_slice(&len.to_be_bytes());
        plain.extend_from_slice(request.host.as_bytes());
        plain.extend_from_slice(&request.port.to_be_bytes());
        let frame = seal(Role::Open, &plain, secret, rng)?;
        let context = Self {
            secret,
            binding: binding(&frame)?,
        };
        Ok((frame, context))
    }

    pub fn prove(self, challenge: &[u8]) -> Result<(Vec<u8>, ClientProof<'a>)> {
        self.prove_with_rng(challenge, &mut rand::rngs::OsRng)
    }

    fn prove_with_rng<R: RngCore + CryptoRng>(
        self,
        challenge: &[u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, ClientProof<'a>)> {
        let plain = open(Role::Challenge, challenge, self.secret)?;
        if plain.len() != 2 + BINDING_LEN + CHALLENGE_LEN
            || plain[2..2 + BINDING_LEN] != self.binding
        {
            return Err(AegisError::Auth);
        }
        let mut nonce = [0; CHALLENGE_LEN];
        nonce.copy_from_slice(&plain[2 + BINDING_LEN..]);
        let proof = seal(
            Role::Proof,
            &pair(Role::Proof, &self.binding, &nonce),
            self.secret,
            rng,
        )?;
        Ok((
            proof,
            ClientProof {
                secret: self.secret,
                binding: self.binding,
                nonce,
            },
        ))
    }
}

impl ClientProof<'_> {
    pub fn finish(self, final_frame: &[u8]) -> Result<TunnelResponse> {
        let plain = open(Role::Final, final_frame, self.secret)?;
        let fixed = 2 + BINDING_LEN + CHALLENGE_LEN;
        if plain.len() < fixed + 3 {
            return Err(codec("fresh legacy Final truncated"));
        }
        check_pair(&plain, &self.binding, &self.nonce)?;
        let status = match plain[fixed] {
            0 => TunnelStatus::Ok,
            1 => TunnelStatus::AuthFailed,
            2 => TunnelStatus::BadTarget,
            3 => TunnelStatus::TransportUnavailable,
            _ => return Err(codec("fresh legacy Final status invalid")),
        };
        let len = u16::from_be_bytes([plain[fixed + 1], plain[fixed + 2]]) as usize;
        if plain.len() != fixed + 3 + len {
            return Err(codec("fresh legacy Final length invalid"));
        }
        let message = std::str::from_utf8(&plain[fixed + 3..])
            .map_err(|_| codec("fresh legacy Final message is not UTF-8"))?
            .to_owned();
        Ok(TunnelResponse { status, message })
    }
}

/// The caller supplies existing authority/key ownership; this is not a new keyring.
pub struct KeyCandidate<'a, K> {
    pub authority: &'a K,
    pub secret: &'a [u8],
    /// Optional existing credential expiry; it can only narrow admission.
    pub expires: Option<Instant>,
}

/// The authenticated request is private until proof consumes this single owner.
/// No Clone, detached proof queue, cache, target accessor or renewed deadline.
pub struct ServerPending<'a, K> {
    authority: &'a K,
    secret: &'a [u8],
    request: TunnelRequest,
    binding: [u8; BINDING_LEN],
    nonce: [u8; CHALLENGE_LEN],
    deadline: Instant,
}
pub struct ServerAuthenticated<'a, K> {
    pending: ServerPending<'a, K>,
}

impl<'a, K> ServerPending<'a, K> {
    pub fn start(
        open_frame: &[u8],
        key: &KeyCandidate<'a, K>,
        deadline: Instant,
    ) -> Result<(Vec<u8>, Self)> {
        Self::start_with_rng(open_frame, key, deadline, &mut rand::rngs::OsRng)
    }

    fn start_with_rng<R: RngCore + CryptoRng>(
        open_frame: &[u8],
        key: &KeyCandidate<'a, K>,
        deadline: Instant,
        rng: &mut R,
    ) -> Result<(Vec<u8>, Self)> {
        let deadline = key.expires.map_or(deadline, |expiry| deadline.min(expiry));
        check_deadline(deadline)?;
        let request = open_request(&open(Role::Open, open_frame, key.secret)?)?;
        let binding = binding(open_frame)?;
        let mut nonce = [0; CHALLENGE_LEN];
        random(rng, &mut nonce)?;
        let challenge = seal(
            Role::Challenge,
            &pair(Role::Challenge, &binding, &nonce),
            key.secret,
            rng,
        )?;
        check_deadline(deadline)?;
        Ok((
            challenge,
            Self {
                authority: key.authority,
                secret: key.secret,
                request,
                binding,
                nonce,
                deadline,
            },
        ))
    }

    pub fn authenticate(
        self,
        proof: &[u8],
        is_active: impl FnOnce(&K) -> bool,
    ) -> Result<ServerAuthenticated<'a, K>> {
        check_deadline(self.deadline)?;
        let plain = open(Role::Proof, proof, self.secret)?;
        if plain.len() != 2 + BINDING_LEN + CHALLENGE_LEN {
            return Err(codec("fresh legacy Proof length invalid"));
        }
        check_pair(&plain, &self.binding, &self.nonce)?;
        if !is_active(self.authority) {
            return Err(AegisError::Auth);
        }
        check_deadline(self.deadline)?;
        Ok(ServerAuthenticated { pending: self })
    }
}

impl<'a, K> ServerAuthenticated<'a, K> {
    async fn connect<R, F, T>(
        self,
        is_active: impl FnOnce(&K) -> bool,
        connector: F,
    ) -> Result<(Option<T>, Vec<u8>, Instant)>
    where
        F: FnOnce(TunnelRequest, &'a K) -> R,
        R: Future<Output = Result<(Option<T>, TunnelResponse)>>,
    {
        let ServerPending {
            authority,
            secret,
            request,
            binding,
            nonce,
            deadline,
        } = self.pending;
        check_deadline(deadline)?;
        if !is_active(authority) {
            return Err(AegisError::Auth);
        }
        // The only request/authority release and connector invocation are here,
        // after proof and immediately before the original-deadline guard.
        let (target, response) =
            until_deadline(deadline, async move { connector(request, authority).await }).await?;
        if (response.status == TunnelStatus::Ok) != target.is_some() {
            return Err(codec("fresh legacy connector status/target mismatch"));
        }
        let message_len = u16::try_from(response.message.len())
            .map_err(|_| codec("fresh legacy Final message too large"))?;
        let mut plain = pair(Role::Final, &binding, &nonce);
        if response.message.len() > MAX_TUNNEL_CONTROL_FRAME - ENVELOPE_OVERHEAD - plain.len() - 3 {
            return Err(codec("fresh legacy Final message too large"));
        }
        plain.push(response.status as u8);
        plain.extend_from_slice(&message_len.to_be_bytes());
        plain.extend_from_slice(response.message.as_bytes());
        let frame = seal(Role::Final, &plain, secret, &mut rand::rngs::OsRng)?;
        check_deadline(deadline)?;
        Ok((target, frame, deadline))
    }
}

async fn write<S: AsyncWrite + Unpin>(
    stream: &mut S,
    frame: &[u8],
    deadline: Instant,
) -> Result<()> {
    until_deadline(deadline, async {
        stream.write_all(&encode_stream_frame(frame)).await?;
        Ok(())
    })
    .await
}

// Per-write policy can only shorten the original (possibly key-narrowed) setup cutoff.
async fn write_control<S: AsyncWrite + Unpin>(
    stream: &mut S,
    frame: &[u8],
    deadline: Instant,
    budget: Duration,
) -> Result<()> {
    let cutoff = Instant::now()
        .checked_add(budget)
        .map_or(deadline, |end| deadline.min(end));
    write(stream, frame, cutoff).await
}

async fn read<S: AsyncRead + Unpin>(stream: &mut S, deadline: Instant) -> Result<Vec<u8>> {
    until_deadline(
        deadline,
        read_stream_frame(stream, MAX_TUNNEL_CONTROL_FRAME),
    )
    .await
}

/// No application bytes are written here; the caller may open only a bound Ok Final.
pub async fn exchange_raw<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    request: &TunnelRequest,
    secret: &[u8],
    deadline: Instant,
) -> Result<TunnelResponse> {
    check_deadline(deadline)?;
    let (open_frame, context) = ClientOpen::start(request, secret)?;
    write(stream, &open_frame, deadline).await?;
    let challenge = read(stream, deadline).await?;
    let (proof, context) = context.prove(&challenge)?;
    write(stream, &proof, deadline).await?;
    let final_frame = read(stream, deadline).await?;
    let response = context.finish(&final_frame)?;
    check_deadline(deadline)?;
    Ok(response)
}

/// Actual raw-stream admission seam: zero connector calls until valid fresh proof.
/// `is_active` must recheck the exact existing matched key's current expiry.
/// The caller keeps its setup permit and existing target/forwarding policy.
pub async fn admit_raw<'a, S, K, F, R, T>(
    stream: &mut S,
    keys: &[KeyCandidate<'a, K>],
    deadline: Instant,
    control_write_budget: Duration,
    is_active: impl Fn(&K) -> bool,
    connector: F,
) -> Result<Option<T>>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(TunnelRequest, &'a K) -> R,
    R: Future<Output = Result<(Option<T>, TunnelResponse)>>,
{
    admit_with_rng(
        stream,
        keys,
        deadline,
        control_write_budget,
        is_active,
        connector,
        &mut rand::rngs::OsRng,
    )
    .await
}

async fn admit_with_rng<'a, S, K, F, R, T, G>(
    stream: &mut S,
    keys: &[KeyCandidate<'a, K>],
    deadline: Instant,
    control_write_budget: Duration,
    is_active: impl Fn(&K) -> bool,
    connector: F,
    rng: &mut G,
) -> Result<Option<T>>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(TunnelRequest, &'a K) -> R,
    R: Future<Output = Result<(Option<T>, TunnelResponse)>>,
    G: RngCore + CryptoRng,
{
    let open_frame = read(stream, deadline).await?;
    let mut chosen = None;
    for key in keys {
        if !is_active(key.authority) {
            continue;
        }
        match ServerPending::start_with_rng(&open_frame, key, deadline, rng) {
            Ok(value) => {
                chosen = Some(value);
                break;
            }
            Err(AegisError::Auth) => continue,
            Err(error) => return Err(error),
        }
    }
    let (challenge, pending) = chosen.ok_or(AegisError::Auth)?;
    let deadline = pending.deadline; // Exact matched lease can only narrow setup.
    write_control(stream, &challenge, deadline, control_write_budget).await?;
    let proof = read(stream, deadline).await?;
    let authenticated = pending.authenticate(&proof, &is_active)?;
    let (target, final_frame, original_deadline) =
        authenticated.connect(&is_active, connector).await?;
    write_control(
        stream,
        &final_frame,
        original_deadline,
        control_write_budget,
    )
    .await?;
    Ok(target)
}

#[cfg(test)]
mod tests;
