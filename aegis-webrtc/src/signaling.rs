use crate::{
    sfu_media::{
        MediaError, MediaIssuer, ProtectedMediaGrant, ProvisionedSession, Role as MediaRole,
    },
    Error, Result,
};
use async_trait::async_trait;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fmt, sync::Mutex, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::Notify,
    time::Instant,
};
use zeroize::Zeroize;

const MAX_SDP: usize = 32 * 1024;
const MAX_FRAME: usize = 96 * 1024;

/// Private broker admission; independent of the inner device identity.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AdmissionKey([u8; 32]);
impl AdmissionKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        if bytes == [0; 32] {
            return Err(Error::Configuration);
        }
        Ok(Self(bytes))
    }
    pub fn from_hex(text: &str) -> Result<Self> {
        if text.len() != 64 {
            return Err(Error::Configuration);
        }
        let mut bytes = [0; 32];
        for (i, pair) in text.as_bytes().chunks_exact(2).enumerate() {
            let a = (pair[0] as char).to_digit(16).ok_or(Error::Configuration)?;
            let b = (pair[1] as char).to_digit(16).ok_or(Error::Configuration)?;
            bytes[i] = (a * 16 + b) as u8;
        }
        Self::from_bytes(bytes)
    }
    fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.0).into()
    }
}
impl Drop for AdmissionKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl fmt::Debug for AdmissionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AdmissionKey([redacted])")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum Role {
    Client,
    Intermediary,
}
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId([u8; 16]);
impl SessionId {
    fn random() -> Result<Self> {
        let mut b = [0; 16];
        rand::rngs::OsRng
            .try_fill_bytes(&mut b)
            .map_err(|_| Error::Signaling)?;
        Ok(Self(b))
    }
}
impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionId([redacted])")
    }
}

/// SDP contains ICE credentials; Debug deliberately never exposes them.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signal {
    pub(crate) sdp: String,
    pub(crate) offer: bool,
}
impl Signal {
    pub fn offer(sdp: String) -> Result<Self> {
        Self::new(sdp, true)
    }
    pub fn answer(sdp: String) -> Result<Self> {
        Self::new(sdp, false)
    }
    fn new(sdp: String, offer: bool) -> Result<Self> {
        let value = Self { sdp, offer };
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if self.sdp.is_empty()
            || self.sdp.len() > MAX_SDP
            || !self.sdp.is_ascii()
            || self
                .sdp
                .bytes()
                .any(|c| c.is_ascii_control() && !matches!(c, b'\r' | b'\n' | b'\t'))
        {
            return Err(Error::Signaling);
        }
        Ok(())
    }
}
impl Drop for Signal {
    fn drop(&mut self) {
        self.sdp.zeroize();
    }
}
impl fmt::Debug for Signal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Signal([redacted])")
    }
}

#[derive(Serialize, Deserialize)]
pub enum Operation {
    Probe,
    Submit(Signal),
    Take,
    Answer {
        session: SessionId,
        claim: SessionId,
        signal: Signal,
    },
    Poll(SessionId),
    Cancel(SessionId),
    /// Distinct media-only broker transaction; no direct-WebRTC SDP is reused.
    MediaBegin,
    MediaClaim,
    MediaTake {
        session: SessionId,
        claim: Option<SessionId>,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalingRequest {
    role: Role,
    key: AdmissionKey,
    operation: Operation,
}
impl SignalingRequest {
    pub fn new(role: Role, key: AdmissionKey, operation: Operation) -> Self {
        Self {
            role,
            key,
            operation,
        }
    }
}
impl fmt::Debug for SignalingRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignalingRequest([redacted])")
    }
}
#[derive(Serialize, Deserialize)]
pub enum SignalingReply {
    Ok,
    Submitted(SessionId),
    Offer {
        session: SessionId,
        claim: SessionId,
        signal: Signal,
    },
    Answer(Signal),
    MediaSubmitted(SessionId),
    MediaOffered {
        session: SessionId,
        claim: SessionId,
    },
    MediaGrant(ProtectedMediaGrant),
}
impl fmt::Debug for SignalingReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignalingReply([redacted])")
    }
}

#[async_trait]
pub trait Signaling: Send + Sync {
    async fn exchange(
        &self,
        request: SignalingRequest,
        deadline: Instant,
    ) -> Result<SignalingReply>;
}

#[derive(Clone, Copy, Debug)]
pub struct BrokerLimits {
    pub max_sessions: usize,
    pub session_ttl: Duration,
}
impl Default for BrokerLimits {
    fn default() -> Self {
        Self {
            max_sessions: 32,
            session_ttl: Duration::from_secs(20),
        }
    }
}
struct Pending {
    offer: Signal,
    claim: Option<SessionId>,
    answer: Option<Signal>,
    expires: Instant,
}
struct PendingMedia {
    claim: SessionId,
    expires: Instant,
    claimed: bool,
}

/// The server owns the LiveKit signing secret. Broker TLS authenticates the
/// client key before invoking this callback on an already consumed descriptor.
pub trait MediaGrantIssuer: Send + Sync {
    fn issue_client(&self, descriptor: ProvisionedSession) -> Result<ProtectedMediaGrant>;
}
/// Expiring, bounded owned broker. Two distinct role credentials are mandatory.
pub struct OwnedBroker {
    client: [u8; 32],
    intermediary: [u8; 32],
    limits: BrokerLimits,
    pending: Mutex<HashMap<SessionId, Pending>>,
    media_pending: Mutex<HashMap<SessionId, PendingMedia>>,
    media: MediaIssuer,
    changed: Notify,
}
impl fmt::Debug for OwnedBroker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnedBroker([redacted])")
    }
}
fn same(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |v, (a, b)| v | (a ^ b)) == 0
}
fn media_error(error: MediaError) -> Error {
    match error {
        MediaError::Capacity => Error::Capacity,
        MediaError::AlreadyIssued | MediaError::Expired | MediaError::Descriptor => Error::Session,
        _ => Error::Signaling,
    }
}
fn media_room(session: SessionId) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut room = String::from("aegis_");
    for byte in session.0 {
        room.push(HEX[(byte >> 4) as usize] as char);
        room.push(HEX[(byte & 15) as usize] as char);
    }
    room
}
impl OwnedBroker {
    pub fn new(
        client: AdmissionKey,
        intermediary: AdmissionKey,
        limits: BrokerLimits,
    ) -> Result<Self> {
        if limits.max_sessions == 0
            || limits.max_sessions > 64
            || limits.session_ttl.is_zero()
            || limits.session_ttl > Duration::from_secs(30)
            || same(&client.hash(), &intermediary.hash())
        {
            return Err(Error::Configuration);
        }
        let media = MediaIssuer::new(limits.max_sessions).map_err(|_| Error::Configuration)?;
        Ok(Self {
            client: client.hash(),
            intermediary: intermediary.hash(),
            limits,
            pending: Mutex::new(HashMap::new()),
            media_pending: Mutex::new(HashMap::new()),
            media,
            changed: Notify::new(),
        })
    }

    /// Start a media rendezvous without creating or accepting a P2P SDP.
    /// The claim is withheld from the client and only an admitted intermediary
    /// may obtain it. Issuance capacity and expiry are bounded by the broker.
    pub fn begin_media_v1(&self, key: &AdmissionKey) -> Result<SessionId> {
        self.authenticate(Role::Client, key)?;
        let now = Instant::now();
        let expires = now + self.limits.session_ttl;
        let mut pending = self.media_pending.lock().map_err(|_| Error::Signaling)?;
        pending.retain(|_, entry| entry.expires > now);
        if pending.len() >= self.limits.max_sessions {
            return Err(Error::Capacity);
        }
        let session = (0..4)
            .map(|_| SessionId::random())
            .find_map(|id| match id {
                Ok(id) if !pending.contains_key(&id) => Some(Ok(id)),
                Err(error) => Some(Err(error)),
                _ => None,
            })
            .ok_or(Error::Signaling)??;
        let claim = SessionId::random()?;
        self.media
            .reserve(
                session.0,
                claim.0,
                media_room(session),
                "client".into(),
                "intermediary".into(),
                expires.into_std(),
            )
            .map_err(media_error)?;
        pending.insert(
            session,
            PendingMedia {
                claim,
                expires,
                claimed: false,
            },
        );
        drop(pending);
        self.changed.notify_waiters();
        Ok(session)
    }

    pub async fn claim_media_v1(
        &self,
        key: &AdmissionKey,
        deadline: Instant,
    ) -> Result<(SessionId, SessionId)> {
        self.authenticate(Role::Intermediary, key)?;
        loop {
            if Instant::now() >= deadline {
                return Err(Error::Deadline);
            }
            let notified = self.changed.notified();
            let now = Instant::now();
            let claimed = {
                let mut pending = self.media_pending.lock().map_err(|_| Error::Signaling)?;
                pending.retain(|_, entry| entry.expires > now);
                pending
                    .iter_mut()
                    .find(|(_, entry)| !entry.claimed)
                    .map(|(session, entry)| {
                        entry.claimed = true;
                        (*session, entry.claim)
                    })
            };
            if let Some(pair) = claimed {
                return Ok(pair);
            }
            let wake = deadline.min(now + Duration::from_millis(50));
            let _ = tokio::time::timeout_at(wake, notified).await;
        }
    }

    pub fn take_claimed_media_v1(
        &self,
        role: Role,
        key: &AdmissionKey,
        session: SessionId,
        claim: Option<SessionId>,
    ) -> Result<ProvisionedSession> {
        self.authenticate(role, key)?;
        let pending = self.media_pending.lock().map_err(|_| Error::Signaling)?;
        let entry = pending.get(&session).ok_or(Error::Session)?;
        if entry.expires <= Instant::now()
            || !entry.claimed
            || (role == Role::Client && claim.is_some())
            || (role == Role::Intermediary && claim != Some(entry.claim))
        {
            return Err(Error::Session);
        }
        self.media
            .take(
                match role {
                    Role::Client => MediaRole::Client,
                    Role::Intermediary => MediaRole::Intermediary,
                },
                session.0,
                claim.map(|id| id.0),
            )
            .map_err(media_error)
    }

    /// Server-internal V1 start boundary. No signaling wire variant calls this.
    /// The intermediary admission key and exact pending claim are required.
    pub fn start_media_v1(
        &self,
        key: &AdmissionKey,
        session: SessionId,
        claim: SessionId,
        answer: Signal,
    ) -> Result<()> {
        self.answer_media_for_claim(key, session, claim, answer)
    }

    /// Server-internal V1 take boundary. A successful call consumes exactly
    /// one role's descriptor; the caller must protect any later token delivery.
    pub fn take_media_v1(
        &self,
        role: Role,
        key: &AdmissionKey,
        session: SessionId,
        claim: Option<SessionId>,
    ) -> Result<ProvisionedSession> {
        self.take_media(role, key, session, claim)
    }

    /// One descriptor per admitted role. The intermediary must also hold the
    /// claim. A failed credential/claim check never consumes issuance state.
    #[allow(dead_code)]
    pub(crate) fn take_media(
        &self,
        role: Role,
        key: &AdmissionKey,
        session: SessionId,
        claim: Option<SessionId>,
    ) -> Result<ProvisionedSession> {
        self.authenticate(role, key)?;
        let media_role = match role {
            Role::Client => MediaRole::Client,
            Role::Intermediary => MediaRole::Intermediary,
        };
        self.media
            .take(media_role, session.0, claim.map(|id| id.0))
            .map_err(media_error)
    }
    /// Future media-only admission transaction. It reserves the descriptor
    /// before publishing Answer under the same pending lock, so Poll cannot
    /// consume the answer first. Existing `Operation::Answer` stays unchanged.
    #[allow(dead_code)]
    pub(crate) fn answer_media_for_claim(
        &self,
        key: &AdmissionKey,
        session: SessionId,
        claim: SessionId,
        signal: Signal,
    ) -> Result<()> {
        self.authenticate(Role::Intermediary, key)?;
        signal.validate()?;
        if signal.offer {
            return Err(Error::Signaling);
        }
        let mut pending = self.pending.lock().map_err(|_| Error::Signaling)?;
        let entry = pending.get_mut(&session).ok_or(Error::Session)?;
        if entry.claim != Some(claim) || entry.answer.is_some() || entry.expires <= Instant::now() {
            return Err(Error::Session);
        }
        self.media
            .reserve(
                session.0,
                claim.0,
                media_room(session),
                "client".into(),
                "intermediary".into(),
                entry.expires.into_std(),
            )
            .map_err(media_error)?;
        entry.answer = Some(signal);
        drop(pending);
        self.changed.notify_waiters();
        Ok(())
    }
    fn authenticate(&self, role: Role, key: &AdmissionKey) -> Result<()> {
        let expected = match role {
            Role::Client => &self.client,
            Role::Intermediary => &self.intermediary,
        };
        if same(expected, &key.hash()) {
            Ok(())
        } else {
            Err(Error::Admission)
        }
    }
    /// Serve only an already established TLS connection. The owner must bound
    /// TLS handshakes/concurrent connections and verify broker certificate/name.
    /// No plaintext listener, credential logging or implicit enrollment exists.
    pub async fn serve_tls<S>(&self, mut tls: tokio_rustls::server::TlsStream<S>) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let end = Instant::now() + Duration::from_secs(30);
        for _ in 0..32 {
            let deadline = end.min(Instant::now() + Duration::from_secs(5));
            let request = match tokio::time::timeout_at(deadline, read_frame(&mut tls)).await {
                Ok(Ok(r)) => r,
                Ok(Err(_)) => return Ok(()),
                Err(_) => return Err(Error::Deadline),
            };
            let reply = self.exchange(request, deadline).await;
            let wire = WireReply::from(reply);
            tokio::time::timeout_at(deadline, write_frame(&mut tls, &wire))
                .await
                .map_err(|_| Error::Deadline)??;
        }
        tokio::time::timeout(Duration::from_secs(1), tls.shutdown())
            .await
            .map_err(|_| Error::Deadline)?
            .map_err(|_| Error::Signaling)
    }

    /// Opt-in media broker wire. The ordinary SDP broker listener never
    /// accepts these operations; its role and credential checks are retained.
    pub async fn serve_tls_media<S, I>(
        &self,
        mut tls: tokio_rustls::server::TlsStream<S>,
        issuer: &I,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
        I: MediaGrantIssuer,
    {
        let end = Instant::now() + Duration::from_secs(30);
        for _ in 0..32 {
            let deadline = end.min(Instant::now() + Duration::from_secs(5));
            let request = match tokio::time::timeout_at(deadline, read_frame(&mut tls)).await {
                Ok(Ok(request)) => request,
                Ok(Err(_)) => return Ok(()),
                Err(_) => return Err(Error::Deadline),
            };
            let reply = self.exchange_media(request, issuer, deadline).await;
            tokio::time::timeout_at(deadline, write_frame(&mut tls, &WireReply::from(reply)))
                .await
                .map_err(|_| Error::Deadline)??;
        }
        tokio::time::timeout(Duration::from_secs(1), tls.shutdown())
            .await
            .map_err(|_| Error::Deadline)?
            .map_err(|_| Error::Signaling)
    }

    async fn exchange_media<I: MediaGrantIssuer>(
        &self,
        request: SignalingRequest,
        issuer: &I,
        deadline: Instant,
    ) -> Result<SignalingReply> {
        if deadline <= Instant::now() {
            return Err(Error::Deadline);
        }
        match (request.role, request.operation) {
            (Role::Client, Operation::MediaBegin) => Ok(SignalingReply::MediaSubmitted(
                self.begin_media_v1(&request.key)?,
            )),
            (Role::Intermediary, Operation::MediaClaim) => {
                let (session, claim) = self.claim_media_v1(&request.key, deadline).await?;
                Ok(SignalingReply::MediaOffered { session, claim })
            }
            (
                Role::Client,
                Operation::MediaTake {
                    session,
                    claim: None,
                },
            ) => {
                let descriptor =
                    self.take_claimed_media_v1(Role::Client, &request.key, session, None)?;
                Ok(SignalingReply::MediaGrant(issuer.issue_client(descriptor)?))
            }
            (role, Operation::Probe) => {
                self.exchange(
                    SignalingRequest::new(role, request.key, Operation::Probe),
                    deadline,
                )
                .await
            }
            _ => Err(Error::Admission),
        }
    }
}
#[async_trait]
impl Signaling for OwnedBroker {
    async fn exchange(
        &self,
        request: SignalingRequest,
        deadline: Instant,
    ) -> Result<SignalingReply> {
        self.authenticate(request.role, &request.key)?;
        if deadline <= Instant::now() {
            return Err(Error::Deadline);
        }
        match (&request.operation, request.role) {
            (Operation::Probe, _)
            | (Operation::Submit(_) | Operation::Poll(_) | Operation::Cancel(_), Role::Client)
            | (Operation::Take | Operation::Answer { .. }, Role::Intermediary) => {}
            _ => return Err(Error::Admission),
        }
        loop {
            // Register before examining the predicate; notify_waiters cannot be lost.
            let notified = self.changed.notified();
            let outcome = {
                let mut p = self.pending.lock().map_err(|_| Error::Signaling)?;
                let now = Instant::now();
                p.retain(|_, v| v.expires > now);
                match &request.operation {
                    Operation::Probe => Some(Ok(SignalingReply::Ok)),
                    Operation::Submit(signal) => {
                        signal.validate()?;
                        if !signal.offer {
                            return Err(Error::Signaling);
                        }
                        if p.len() >= self.limits.max_sessions {
                            return Err(Error::Capacity);
                        }
                        let id = (0..4)
                            .map(|_| SessionId::random())
                            .find_map(|r| match r {
                                Ok(id) if !p.contains_key(&id) => Some(Ok(id)),
                                Err(e) => Some(Err(e)),
                                _ => None,
                            })
                            .ok_or(Error::Signaling)??;
                        p.insert(
                            id,
                            Pending {
                                offer: signal.clone(),
                                claim: None,
                                answer: None,
                                expires: now + self.limits.session_ttl,
                            },
                        );
                        Some(Ok(SignalingReply::Submitted(id)))
                    }
                    Operation::Take => {
                        p.iter_mut()
                            .find(|(_, v)| v.claim.is_none())
                            .map(|(id, v)| {
                                let claim = SessionId::random()?;
                                v.claim = Some(claim);
                                Ok(SignalingReply::Offer {
                                    session: *id,
                                    claim,
                                    signal: v.offer.clone(),
                                })
                            })
                    }
                    Operation::Answer {
                        session,
                        claim,
                        signal,
                    } => {
                        signal.validate()?;
                        if signal.offer {
                            return Err(Error::Signaling);
                        }
                        let v = p.get_mut(session).ok_or(Error::Session)?;
                        if v.claim != Some(*claim) || v.answer.is_some() {
                            return Err(Error::Session);
                        }
                        v.answer = Some(signal.clone());
                        Some(Ok(SignalingReply::Ok))
                    }
                    Operation::Poll(id) => {
                        let v = p.get_mut(id).ok_or(Error::Session)?;
                        if let Some(answer) = v.answer.take() {
                            p.remove(id);
                            Some(Ok(SignalingReply::Answer(answer)))
                        } else {
                            None
                        }
                    }
                    Operation::Cancel(id) => {
                        p.remove(id);
                        self.media.cancel(id.0).map_err(media_error)?;
                        Some(Ok(SignalingReply::Ok))
                    }
                    Operation::MediaBegin | Operation::MediaClaim | Operation::MediaTake { .. } => {
                        return Err(Error::Admission);
                    }
                }
            };
            if let Some(outcome) = outcome {
                self.changed.notify_waiters();
                return outcome;
            }
            // Periodic expiry is necessary even if nobody publishes another offer.
            let wake = deadline.min(Instant::now() + Duration::from_millis(50));
            let _ = tokio::time::timeout_at(wake, notified).await;
            if Instant::now() >= deadline {
                return Err(Error::Deadline);
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
enum WireReply {
    Accepted(SignalingReply),
    Refused(u8),
}
impl From<Result<SignalingReply>> for WireReply {
    fn from(r: Result<SignalingReply>) -> Self {
        match r {
            Ok(v) => Self::Accepted(v),
            Err(e) => Self::Refused(match e {
                Error::Admission => 1,
                Error::Capacity => 2,
                Error::Session => 3,
                Error::Deadline => 4,
                _ => 5,
            }),
        }
    }
}
impl WireReply {
    fn result(self) -> Result<SignalingReply> {
        match self {
            Self::Accepted(v) => Ok(v),
            Self::Refused(n) => Err(match n {
                1 => Error::Admission,
                2 => Error::Capacity,
                3 => Error::Session,
                4 => Error::Deadline,
                _ => Error::Signaling,
            }),
        }
    }
}

async fn read_frame<S: AsyncRead + Unpin, T: serde::de::DeserializeOwned>(
    stream: &mut S,
) -> Result<T> {
    let n = stream.read_u32().await.map_err(|_| Error::Signaling)? as usize;
    if n == 0 || n > MAX_FRAME {
        return Err(Error::Signaling);
    }
    let mut bytes = zeroize::Zeroizing::new(vec![0u8; n]);
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|_| Error::Signaling)?;
    serde_json::from_slice(&bytes).map_err(|_| Error::Signaling)
}
async fn write_frame<S: AsyncWrite + Unpin, T: Serialize>(stream: &mut S, value: &T) -> Result<()> {
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(value).map_err(|_| Error::Signaling)?);
    if bytes.len() > MAX_FRAME {
        return Err(Error::Signaling);
    }
    stream
        .write_u32(bytes.len() as u32)
        .await
        .map_err(|_| Error::Signaling)?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|_| Error::Signaling)?;
    stream.flush().await.map_err(|_| Error::Signaling)
}
/// Caller establishes TLS using a pinned CA and verified server name first.
/// The connection expires after 30 seconds; operations have a 5 second ceiling.
pub struct TlsSignalingClient<S> {
    tls: tokio::sync::Mutex<Option<tokio_rustls::client::TlsStream<S>>>,
    expires: Instant,
}
impl<S> TlsSignalingClient<S> {
    pub fn new(tls: tokio_rustls::client::TlsStream<S>) -> Self {
        Self {
            tls: tokio::sync::Mutex::new(Some(tls)),
            expires: Instant::now() + Duration::from_secs(30),
        }
    }
}
#[async_trait]
impl<S: AsyncRead + AsyncWrite + Unpin + Send> Signaling for TlsSignalingClient<S> {
    async fn exchange(
        &self,
        request: SignalingRequest,
        deadline: Instant,
    ) -> Result<SignalingReply> {
        let deadline = deadline
            .min(self.expires)
            .min(Instant::now() + Duration::from_secs(5));
        let mut guard = tokio::time::timeout_at(deadline, self.tls.lock())
            .await
            .map_err(|_| Error::Deadline)?;
        // Removing before I/O makes cancellation fail closed: a dropped exchange
        // cannot reuse a TLS byte stream whose frame boundaries may be incomplete.
        let mut tls = guard.take().ok_or(Error::Signaling)?;
        let result = tokio::time::timeout_at(deadline, async {
            write_frame(&mut tls, &request).await?;
            let reply: WireReply = read_frame(&mut tls).await?;
            reply.result()
        })
        .await
        .map_err(|_| Error::Deadline)?;
        if result.is_ok()
            || matches!(
                result,
                Err(Error::Admission | Error::Capacity | Error::Session)
            )
        {
            *guard = Some(tls);
        }
        result
    }
}

#[cfg(test)]
mod media_issuer_tests {
    use super::*;
    use crate::sfu_media::{FrameKind, ReceivedFrame};

    struct TestIssuer;
    impl MediaGrantIssuer for TestIssuer {
        fn issue_client(&self, descriptor: ProvisionedSession) -> Result<ProtectedMediaGrant> {
            descriptor
                .into_protected_client_grant(zeroize::Zeroizing::new(
                    "header.payload.signature".to_owned(),
                ))
                .map_err(media_error)
        }
    }

    #[tokio::test]
    async fn distinct_media_wire_requires_claim_and_consumes_each_role_once() {
        let client_key = AdmissionKey::from_bytes([1; 32]).unwrap();
        let intermediary_key = AdmissionKey::from_bytes([2; 32]).unwrap();
        let broker = OwnedBroker::new(
            client_key.clone(),
            intermediary_key.clone(),
            BrokerLimits::default(),
        )
        .unwrap();
        let end = Instant::now() + Duration::from_secs(2);
        assert!(matches!(
            broker
                .exchange(
                    SignalingRequest::new(Role::Client, client_key.clone(), Operation::MediaBegin,),
                    end,
                )
                .await,
            Err(Error::Admission)
        ));
        let SignalingReply::MediaSubmitted(session) = broker
            .exchange_media(
                SignalingRequest::new(Role::Client, client_key.clone(), Operation::MediaBegin),
                &TestIssuer,
                end,
            )
            .await
            .unwrap()
        else {
            panic!("distinct media begin required");
        };
        assert!(matches!(
            broker
                .exchange_media(
                    SignalingRequest::new(
                        Role::Client,
                        client_key.clone(),
                        Operation::MediaTake {
                            session,
                            claim: None,
                        },
                    ),
                    &TestIssuer,
                    end,
                )
                .await,
            Err(Error::Session)
        ));
        let SignalingReply::MediaOffered {
            session: offered,
            claim,
        } = broker
            .exchange_media(
                SignalingRequest::new(
                    Role::Intermediary,
                    intermediary_key.clone(),
                    Operation::MediaClaim,
                ),
                &TestIssuer,
                end,
            )
            .await
            .unwrap()
        else {
            panic!("intermediary claim required");
        };
        assert_eq!(offered, session);
        assert!(matches!(
            broker.take_claimed_media_v1(
                Role::Intermediary,
                &intermediary_key,
                session,
                Some(SessionId([3; 16])),
            ),
            Err(Error::Session)
        ));
        let SignalingReply::MediaGrant(grant) = broker
            .exchange_media(
                SignalingRequest::new(
                    Role::Client,
                    client_key.clone(),
                    Operation::MediaTake {
                        session,
                        claim: None,
                    },
                ),
                &TestIssuer,
                end,
            )
            .await
            .unwrap()
        else {
            panic!("broker must issue only protected client grant");
        };
        let (client, token) = grant.into_client().unwrap();
        assert_eq!(&*token, "header.payload.signature");
        let intermediary = broker
            .take_claimed_media_v1(Role::Intermediary, &intermediary_key, session, Some(claim))
            .unwrap();
        assert!(matches!(
            broker.take_claimed_media_v1(Role::Client, &client_key, session, None),
            Err(Error::Session)
        ));
        let (mut tx, _) = client.split().unwrap();
        let (_, mut rx) = intermediary.split().unwrap();
        let wire = tx.seal_next(FrameKind::Data, b"media wire").unwrap();
        assert!(matches!(rx.open(&wire), Ok(ReceivedFrame::Fresh(_))));
    }

    #[tokio::test]
    async fn accepted_answer_issues_once_per_authenticated_role() {
        let client_key = AdmissionKey::from_bytes([1; 32]).unwrap();
        let server_key = AdmissionKey::from_bytes([2; 32]).unwrap();
        let broker = OwnedBroker::new(
            client_key.clone(),
            server_key.clone(),
            BrokerLimits::default(),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let SignalingReply::Submitted(session) = broker
            .exchange(
                SignalingRequest::new(
                    Role::Client,
                    client_key.clone(),
                    Operation::Submit(Signal::offer("v=0".into()).unwrap()),
                ),
                deadline,
            )
            .await
            .unwrap()
        else {
            panic!("offer not submitted")
        };
        let SignalingReply::Offer { claim, .. } = broker
            .exchange(
                SignalingRequest::new(Role::Intermediary, server_key.clone(), Operation::Take),
                deadline,
            )
            .await
            .unwrap()
        else {
            panic!("offer not claimed")
        };
        assert!(matches!(
            broker.take_media(Role::Client, &client_key, session, None),
            Err(Error::Session)
        ));
        assert!(matches!(
            broker.answer_media_for_claim(
                &client_key,
                session,
                claim,
                Signal::answer("v=0".into()).unwrap()
            ),
            Err(Error::Admission)
        ));
        assert!(matches!(
            broker.answer_media_for_claim(
                &server_key,
                session,
                SessionId([3; 16]),
                Signal::answer("v=0".into()).unwrap()
            ),
            Err(Error::Session)
        ));
        broker
            .answer_media_for_claim(
                &server_key,
                session,
                claim,
                Signal::answer("v=0".into()).unwrap(),
            )
            .unwrap();
        let SignalingReply::Answer(_) = broker
            .exchange(
                SignalingRequest::new(Role::Client, client_key.clone(), Operation::Poll(session)),
                deadline,
            )
            .await
            .unwrap()
        else {
            panic!("answer not polled")
        };
        // Poll removed pending, yet the answer's issuer slot remains available.
        assert!(matches!(
            broker
                .exchange(
                    SignalingRequest::new(
                        Role::Client,
                        client_key.clone(),
                        Operation::Poll(session)
                    ),
                    deadline,
                )
                .await,
            Err(Error::Session)
        ));
        assert!(matches!(
            broker.take_media(
                Role::Intermediary,
                &server_key,
                session,
                Some(SessionId([3; 16]))
            ),
            Err(Error::Session)
        ));
        assert!(matches!(
            broker.take_media(Role::Client, &server_key, session, None),
            Err(Error::Admission)
        ));
        let client = broker
            .take_media(Role::Client, &client_key, session, None)
            .unwrap();
        let server = broker
            .take_media(Role::Intermediary, &server_key, session, Some(claim))
            .unwrap();
        assert!(matches!(
            broker.take_media(Role::Client, &client_key, session, None),
            Err(Error::Session)
        ));
        assert!(matches!(
            broker.take_media(Role::Intermediary, &server_key, session, Some(claim)),
            Err(Error::Session)
        ));
        let (mut tx, _) = client.split().unwrap();
        let (_, mut rx) = server.split().unwrap();
        let sealed = tx.seal_next(FrameKind::Data, b"broker-owned").unwrap();
        assert!(matches!(rx.open(&sealed), Ok(ReceivedFrame::Fresh(_))));
    }

    #[tokio::test]
    async fn cancel_before_and_after_poll_refuses_unissued_descriptors() {
        for cancel_first in [true, false] {
            let client_key = AdmissionKey::from_bytes([1; 32]).unwrap();
            let server_key = AdmissionKey::from_bytes([2; 32]).unwrap();
            let broker = OwnedBroker::new(
                client_key.clone(),
                server_key.clone(),
                BrokerLimits::default(),
            )
            .unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            let SignalingReply::Submitted(session) = broker
                .exchange(
                    SignalingRequest::new(
                        Role::Client,
                        client_key.clone(),
                        Operation::Submit(Signal::offer("v=0".into()).unwrap()),
                    ),
                    deadline,
                )
                .await
                .unwrap()
            else {
                panic!("offer not submitted")
            };
            let SignalingReply::Offer { claim, .. } = broker
                .exchange(
                    SignalingRequest::new(Role::Intermediary, server_key.clone(), Operation::Take),
                    deadline,
                )
                .await
                .unwrap()
            else {
                panic!("offer not claimed")
            };
            broker
                .answer_media_for_claim(
                    &server_key,
                    session,
                    claim,
                    Signal::answer("v=0".into()).unwrap(),
                )
                .unwrap();
            if cancel_first {
                assert!(matches!(
                    broker
                        .exchange(
                            SignalingRequest::new(
                                Role::Client,
                                client_key.clone(),
                                Operation::Cancel(session)
                            ),
                            deadline,
                        )
                        .await,
                    Ok(SignalingReply::Ok)
                ));
                assert!(matches!(
                    broker
                        .exchange(
                            SignalingRequest::new(
                                Role::Client,
                                client_key.clone(),
                                Operation::Poll(session)
                            ),
                            deadline,
                        )
                        .await,
                    Err(Error::Session)
                ));
            } else {
                assert!(matches!(
                    broker
                        .exchange(
                            SignalingRequest::new(
                                Role::Client,
                                client_key.clone(),
                                Operation::Poll(session)
                            ),
                            deadline,
                        )
                        .await,
                    Ok(SignalingReply::Answer(_))
                ));
                assert!(matches!(
                    broker
                        .exchange(
                            SignalingRequest::new(
                                Role::Client,
                                client_key.clone(),
                                Operation::Cancel(session)
                            ),
                            deadline,
                        )
                        .await,
                    Ok(SignalingReply::Ok)
                ));
            }
            assert!(matches!(
                broker.take_media(Role::Client, &client_key, session, None),
                Err(Error::Session)
            ));
            assert!(matches!(
                broker.take_media(Role::Intermediary, &server_key, session, Some(claim)),
                Err(Error::Session)
            ));
        }
    }
}
