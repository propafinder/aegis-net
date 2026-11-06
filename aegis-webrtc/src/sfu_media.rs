//! Inert SFU video-media frame seam. Product `sfu_media` still refuses setup.
//!
//! Only an owned broker may eventually construct a `ProvisionedSession`.
//! There is no session authority, LiveKit adapter, or runtime dispatch here.
//! The caller must copy the returned sealed bytes for retransmission; sealing
//! a new frame always consumes a fresh sequence and never reuses an AEAD nonce.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

const WIRE: usize = 64;
const HEADER: usize = 6;
const TAG: usize = 16;
const MAX_PLAIN: usize = WIRE - HEADER - TAG;
const GRID: usize = 256;
const CELLS: usize = 24;
const CELL: usize = 10;
const MARGIN: usize = 8;
const RGB_BYTES: usize = GRID * GRID * 3;
const PIXEL_WIRE: usize = 2 + 1 + WIRE + 4;
const DOMAIN: &[u8] = b"aegis-sfu-video-media-v1";
/// A grant is valid for at most 30 seconds. Consumed media has a separate
/// bounded lifetime; this never extends the grant or permits a second take.
pub const MAX_MEDIA_LIFETIME: Duration = Duration::from_secs(300);

/// Deliberately unavailable from config or an untrusted media participant.
/// A future owned-broker provisioner must mint this for both authenticated
/// roles over their existing protected signaling channel.
pub struct ProvisionedSession {
    role: Role,
    session_id: [u8; 16],
    room: String,
    client_track: String,
    intermediary_track: String,
    media_key: Zeroizing<[u8; 32]>,
    expires: Instant,
}

/// A single broker-TLS response for one admitted role. Its JWT and media key
/// are secret; callers must never persist or log the serialized response.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedMediaGrant {
    role: Role,
    session_id: [u8; 16],
    room: String,
    client_track: String,
    intermediary_track: String,
    media_key: [u8; 32],
    ttl_ms: u64,
    token: String,
}

impl std::fmt::Debug for ProtectedMediaGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProtectedMediaGrant([redacted])")
    }
}

impl Drop for ProtectedMediaGrant {
    fn drop(&mut self) {
        self.media_key.zeroize();
        self.token.zeroize();
    }
}

impl ProtectedMediaGrant {
    /// Consume the TLS response once. The short TTL is sampled at receipt;
    /// the signed SFU token also carries its original server-side expiry.
    pub fn into_client(self) -> Result<(ProvisionedSession, Zeroizing<String>), MediaError> {
        let mut grant = self;
        if grant.role != Role::Client
            || !(1..=30_000).contains(&grant.ttl_ms)
            || grant.token.len() > 4096
            || !grant.token.is_ascii()
            || grant
                .token
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b == 0)
        {
            return Err(MediaError::Descriptor);
        }
        let descriptor = ProvisionedSession::from_owned_broker(
            grant.role,
            grant.session_id,
            std::mem::take(&mut grant.room),
            std::mem::take(&mut grant.client_track),
            std::mem::take(&mut grant.intermediary_track),
            Zeroizing::new(grant.media_key),
            Instant::now() + Duration::from_millis(grant.ttl_ms),
        )?;
        let token = Zeroizing::new(std::mem::take(&mut grant.token));
        Ok((descriptor, token))
    }
}

impl std::fmt::Debug for ProvisionedSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProvisionedSession([redacted])")
    }
}

impl ProvisionedSession {
    /// Only a server-owned issuer may construct this from a descriptor that
    /// the broker has already consumed for the authenticated client role.
    pub fn into_protected_client_grant(
        self,
        mut token: Zeroizing<String>,
    ) -> Result<ProtectedMediaGrant, MediaError> {
        let ttl_ms = self
            .expires
            .saturating_duration_since(Instant::now())
            .as_millis();
        if self.role != Role::Client
            || !(1..=30_000).contains(&ttl_ms)
            || token.is_empty()
            || token.len() > 4096
            || !token.is_ascii()
            || token.bytes().any(|b| b.is_ascii_whitespace() || b == 0)
        {
            return Err(MediaError::Descriptor);
        }
        Ok(ProtectedMediaGrant {
            role: self.role,
            session_id: self.session_id,
            room: self.room,
            client_track: self.client_track,
            intermediary_track: self.intermediary_track,
            media_key: *self.media_key,
            ttl_ms: ttl_ms as u64,
            token: std::mem::take(&mut *token),
        })
    }
    // Kept crate-private until authenticated broker custody and LiveKit token
    // minting exist. RuntimeSettings::SfuMedia still returns UnsupportedSfu.
    #[allow(dead_code)]
    fn from_owned_broker(
        role: Role,
        session_id: [u8; 16],
        room: String,
        client_track: String,
        intermediary_track: String,
        media_key: Zeroizing<[u8; 32]>,
        expires: Instant,
    ) -> Result<Self, MediaError> {
        let now = Instant::now();
        if session_id == [0; 16]
            || *media_key == [0; 32]
            || !name_ok(&room)
            || !name_ok(&client_track)
            || !name_ok(&intermediary_track)
            || client_track == intermediary_track
            || expires <= now
            || expires > now + Duration::from_secs(30)
        {
            return Err(MediaError::Descriptor);
        }
        Ok(Self {
            role,
            session_id,
            room,
            client_track,
            intermediary_track,
            media_key,
            expires,
        })
    }

    /// Non-secret signing claims for the broker-owned, one-use descriptor.
    /// This does not expose the media key or create a public wire grant.
    pub fn room_for_issuer(&self) -> &str {
        &self.room
    }

    pub fn identity_for_issuer(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut identity = String::from("aegis_");
        for byte in self.session_id {
            identity.push(HEX[(byte >> 4) as usize] as char);
            identity.push(HEX[(byte & 15) as usize] as char);
        }
        identity.push_str(match self.role {
            Role::Client => "_client",
            Role::Intermediary => "_intermediary",
        });
        identity
    }

    pub fn remaining_for_issuer(&self) -> Duration {
        self.expires.saturating_duration_since(Instant::now())
    }

    /// Names are fixed by the owned broker, never supplied by an SFU peer.
    pub fn track_names(&self) -> (&str, &str) {
        (&self.client_track, &self.intermediary_track)
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn counterpart_identity_for_issuer(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut identity = String::from("aegis_");
        for byte in self.session_id {
            identity.push(HEX[(byte >> 4) as usize] as char);
            identity.push(HEX[(byte & 15) as usize] as char);
        }
        identity.push_str(match self.role {
            Role::Client => "_intermediary",
            Role::Intermediary => "_client",
        });
        identity
    }

    fn binding(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        hash.update(self.session_id);
        for name in [&self.room, &self.client_track, &self.intermediary_track] {
            hash.update((name.len() as u16).to_be_bytes());
            hash.update(name.as_bytes());
        }
        hash.finalize().into()
    }

    fn key(&self, direction: Direction) -> Result<Zeroizing<[u8; 32]>, MediaError> {
        if Instant::now() >= self.expires {
            return Err(MediaError::Expired);
        }
        let binding = self.binding();
        let hk = Hkdf::<Sha256>::new(Some(&binding), &self.media_key[..]);
        let mut out = Zeroizing::new([0u8; 32]);
        hk.expand(direction.label(), &mut out[..])
            .map_err(|_| MediaError::Descriptor)?;
        Ok(out)
    }

    /// Consumes the broker-owned descriptor so a role cannot reset its TX
    /// sequence by constructing another sender from the same capability.
    pub fn split(self) -> Result<(SendCodec, ReceiveCodec), MediaError> {
        if Instant::now() >= self.expires {
            return Err(MediaError::Expired);
        }
        let active_until = Instant::now() + MAX_MEDIA_LIFETIME;
        let (outbound, inbound) = match self.role {
            Role::Client => (
                Direction::ClientToIntermediary,
                Direction::IntermediaryToClient,
            ),
            Role::Intermediary => (
                Direction::IntermediaryToClient,
                Direction::ClientToIntermediary,
            ),
        };
        Ok((
            SendCodec {
                codec: MediaFrameCodec::new(&self, outbound, active_until)?,
                next_send: 0,
            },
            ReceiveCodec {
                codec: MediaFrameCodec::new(&self, inbound, active_until)?,
                window: ReceiveWindow::default(),
            },
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Role {
    Client,
    Intermediary,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    ClientToIntermediary,
    IntermediaryToClient,
}
impl Direction {
    fn label(self) -> &'static [u8] {
        match self {
            Self::ClientToIntermediary => b"client-to-intermediary",
            Self::IntermediaryToClient => b"intermediary-to-client",
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameKind {
    Data = 1,
    Ack = 2,
    Fin = 3,
    FinAck = 4,
    CloseReady = 5,
    CloseAck = 6,
    KeepAlive = 7,
}
impl FrameKind {
    fn parse(raw: u8) -> Result<Self, MediaError> {
        match raw {
            1 => Ok(Self::Data),
            2 => Ok(Self::Ack),
            3 => Ok(Self::Fin),
            4 => Ok(Self::FinAck),
            5 => Ok(Self::CloseReady),
            6 => Ok(Self::CloseAck),
            7 => Ok(Self::KeepAlive),
            _ => Err(MediaError::Frame),
        }
    }
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum MediaError {
    #[error("SFU descriptor rejected")]
    Descriptor,
    #[error("SFU descriptor expired")]
    Expired,
    #[error("SFU media frame rejected")]
    Frame,
    #[error("SFU media frame authentication failed")]
    Authentication,
    #[error("SFU media sequence exhausted")]
    Sequence,
    #[error("SFU issuance capacity exhausted")]
    Capacity,
    #[error("SFU issuance already consumed")]
    AlreadyIssued,
}

fn name_ok(s: &str) -> bool {
    (1..=96).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

struct MediaSlot {
    claim: [u8; 16],
    room: String,
    client_track: String,
    intermediary_track: String,
    expires: Instant,
    issue: u64,
    client_taken: bool,
    intermediary_taken: bool,
    cancelled: bool,
}
struct IssueState {
    next_issue: u64,
    slots: HashMap<[u8; 16], MediaSlot>,
}

/// Broker-owned, bounded issuance state. A slot is a tombstone until expiry:
/// it cannot be reserved again after either role takes its descriptor.
/// Across a broker restart a fresh CSPRNG master changes all derived keys.
pub(crate) struct MediaIssuer {
    master: Zeroizing<[u8; 32]>,
    max_slots: usize,
    state: Mutex<IssueState>,
}
impl MediaIssuer {
    pub(crate) fn new(max_slots: usize) -> Result<Self, MediaError> {
        if !(1..=64).contains(&max_slots) {
            return Err(MediaError::Descriptor);
        }
        let mut master = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng
            .try_fill_bytes(&mut master[..])
            .map_err(|_| MediaError::Descriptor)?;
        if *master == [0; 32] {
            return Err(MediaError::Descriptor);
        }
        Ok(Self {
            master,
            max_slots,
            state: Mutex::new(IssueState {
                next_issue: 0,
                slots: HashMap::new(),
            }),
        })
    }

    pub(crate) fn reserve(
        &self,
        session: [u8; 16],
        claim: [u8; 16],
        room: String,
        client_track: String,
        intermediary_track: String,
        expires: Instant,
    ) -> Result<(), MediaError> {
        let now = Instant::now();
        if session == [0; 16]
            || claim == [0; 16]
            || !name_ok(&room)
            || !name_ok(&client_track)
            || !name_ok(&intermediary_track)
            || client_track == intermediary_track
            || expires <= now
            || expires > now + Duration::from_secs(30)
        {
            return Err(MediaError::Descriptor);
        }
        let mut state = self.state.lock().map_err(|_| MediaError::Descriptor)?;
        state.slots.retain(|_, slot| slot.expires > now);
        if state.slots.contains_key(&session) {
            return Err(MediaError::AlreadyIssued);
        }
        if state.slots.len() >= self.max_slots {
            return Err(MediaError::Capacity);
        }
        let issue = state.next_issue;
        state.next_issue = state
            .next_issue
            .checked_add(1)
            .ok_or(MediaError::Sequence)?;
        state.slots.insert(
            session,
            MediaSlot {
                claim,
                room,
                client_track,
                intermediary_track,
                expires,
                issue,
                client_taken: false,
                intermediary_taken: false,
                cancelled: false,
            },
        );
        Ok(())
    }

    pub(crate) fn take(
        &self,
        role: Role,
        session: [u8; 16],
        claim: Option<[u8; 16]>,
    ) -> Result<ProvisionedSession, MediaError> {
        let now = Instant::now();
        let mut state = self.state.lock().map_err(|_| MediaError::Descriptor)?;
        state.slots.retain(|_, slot| slot.expires > now);
        let slot = state
            .slots
            .get_mut(&session)
            .ok_or(MediaError::Descriptor)?;
        if slot.cancelled {
            return Err(MediaError::Descriptor);
        }
        let taken = match role {
            Role::Client if claim.is_none() => &mut slot.client_taken,
            Role::Intermediary if claim == Some(slot.claim) => &mut slot.intermediary_taken,
            _ => return Err(MediaError::Descriptor),
        };
        if *taken {
            return Err(MediaError::AlreadyIssued);
        }
        let hk = Hkdf::<Sha256>::new(Some(&session), &self.master[..]);
        let mut info = [0u8; 32];
        info[..24].copy_from_slice(b"aegis-sfu-issue-key-v1!!");
        info[24..].copy_from_slice(&slot.issue.to_be_bytes());
        let mut key = Zeroizing::new([0u8; 32]);
        hk.expand(&info, &mut key[..])
            .map_err(|_| MediaError::Descriptor)?;
        let descriptor = ProvisionedSession::from_owned_broker(
            role,
            session,
            slot.room.clone(),
            slot.client_track.clone(),
            slot.intermediary_track.clone(),
            key,
            slot.expires,
        )?;
        *taken = true;
        Ok(descriptor)
    }

    pub(crate) fn cancel(&self, session: [u8; 16]) -> Result<(), MediaError> {
        if let Some(slot) = self
            .state
            .lock()
            .map_err(|_| MediaError::Descriptor)?
            .slots
            .get_mut(&session)
        {
            slot.cancelled = true;
        }
        Ok(())
    }
}

struct MediaFrameCodec {
    key: Zeroizing<[u8; 32]>,
    binding: [u8; 32],
    expires: Instant,
}
impl MediaFrameCodec {
    fn new(
        session: &ProvisionedSession,
        direction: Direction,
        active_until: Instant,
    ) -> Result<Self, MediaError> {
        Ok(Self {
            key: session.key(direction)?,
            binding: session.binding(),
            expires: active_until,
        })
    }

    fn nonce(sequence: u32) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[8..].copy_from_slice(&sequence.to_be_bytes());
        nonce
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new_from_slice(&self.key[..]).expect("fixed 32-byte media key")
    }

    fn seal(&self, sequence: u32, kind: FrameKind, plain: &[u8]) -> Result<[u8; WIRE], MediaError> {
        if Instant::now() >= self.expires {
            return Err(MediaError::Expired);
        }
        if plain.len() > MAX_PLAIN {
            return Err(MediaError::Frame);
        }
        let mut wire = [0u8; WIRE];
        wire[0] = kind as u8;
        wire[1..5].copy_from_slice(&sequence.to_be_bytes());
        wire[5] = (plain.len() + TAG) as u8;
        let mut aad = [0u8; 38];
        aad[..32].copy_from_slice(&self.binding);
        aad[32..].copy_from_slice(&wire[..HEADER]);
        let encrypted = self
            .cipher()
            .encrypt(
                Nonce::from_slice(&Self::nonce(sequence)),
                Payload {
                    msg: plain,
                    aad: &aad,
                },
            )
            .map_err(|_| MediaError::Authentication)?;
        wire[HEADER..HEADER + encrypted.len()].copy_from_slice(&encrypted);
        Ok(wire)
    }

    fn open(&self, wire: &[u8; WIRE]) -> Result<OpenedFrame, MediaError> {
        if Instant::now() >= self.expires {
            return Err(MediaError::Expired);
        }
        let kind = FrameKind::parse(wire[0])?;
        let sequence = u32::from_be_bytes(wire[1..5].try_into().map_err(|_| MediaError::Frame)?);
        let cipher_len = usize::from(wire[5]);
        if !(TAG..=WIRE - HEADER).contains(&cipher_len)
            || wire[HEADER + cipher_len..].iter().any(|b| *b != 0)
        {
            return Err(MediaError::Frame);
        }
        let mut aad = [0u8; 38];
        aad[..32].copy_from_slice(&self.binding);
        aad[32..].copy_from_slice(&wire[..HEADER]);
        let payload = self
            .cipher()
            .decrypt(
                Nonce::from_slice(&Self::nonce(sequence)),
                Payload {
                    msg: &wire[HEADER..HEADER + cipher_len],
                    aad: &aad,
                },
            )
            .map_err(|_| MediaError::Authentication)?;
        Ok(OpenedFrame {
            kind,
            sequence,
            payload,
        })
    }
}

/// A single-use sender capability. Retransmit the returned sealed frame;
/// sealing again always consumes a different sequence and nonce.
pub struct SendCodec {
    codec: MediaFrameCodec,
    next_send: u32,
}
impl SendCodec {
    #[cfg(any(test, feature = "sfu-media-vp8"))]
    pub(crate) fn active_until(&self) -> Instant {
        self.codec.expires
    }

    pub fn seal_next(&mut self, kind: FrameKind, plain: &[u8]) -> Result<[u8; WIRE], MediaError> {
        let sequence = self.next_send;
        self.next_send = self.next_send.checked_add(1).ok_or(MediaError::Sequence)?;
        self.codec.seal(sequence, kind, plain)
    }
}

/// AEAD verification and replay classification are inseparable for callers.
pub struct ReceiveCodec {
    codec: MediaFrameCodec,
    window: ReceiveWindow,
}
impl ReceiveCodec {
    pub fn open(&mut self, wire: &[u8; WIRE]) -> Result<ReceivedFrame, MediaError> {
        let frame = self.codec.open(wire)?;
        Ok(match self.window.record(&frame) {
            Reception::Fresh => ReceivedFrame::Fresh(frame),
            Reception::Duplicate => ReceivedFrame::Duplicate {
                kind: frame.kind,
                sequence: frame.sequence,
            },
            Reception::Stale => ReceivedFrame::Stale,
        })
    }
}

pub enum ReceivedFrame {
    Fresh(OpenedFrame),
    Duplicate { kind: FrameKind, sequence: u32 },
    Stale,
}

pub struct OpenedFrame {
    kind: FrameKind,
    sequence: u32,
    payload: Vec<u8>,
}
impl OpenedFrame {
    pub fn kind(&self) -> FrameKind {
        self.kind
    }

    pub fn sequence(&self) -> u32 {
        self.sequence
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// A 64-entry anti-replay window. Authenticated duplicates may be ACKed,
/// but only `Fresh` frames may be delivered to the application.
#[derive(Default)]
struct ReceiveWindow {
    highest: Option<u32>,
    seen: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Reception {
    Fresh,
    Duplicate,
    Stale,
}
impl ReceiveWindow {
    fn record(&mut self, frame: &OpenedFrame) -> Reception {
        let sequence = frame.sequence;
        let Some(highest) = self.highest else {
            self.highest = Some(sequence);
            self.seen = 1;
            return Reception::Fresh;
        };
        if sequence > highest {
            let shift = sequence - highest;
            self.seen = if shift >= 64 {
                1
            } else {
                (self.seen << shift) | 1
            };
            self.highest = Some(sequence);
            return Reception::Fresh;
        }
        let back = highest - sequence;
        if back >= 64 {
            return Reception::Stale;
        }
        let bit = 1u64 << back;
        if self.seen & bit != 0 {
            Reception::Duplicate
        } else {
            self.seen |= bit;
            Reception::Fresh
        }
    }
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// RGB24 pixel pattern used by the local R27 video track, before codec loss.
/// An outer CRC only filters damaged pixels; AEAD above is the trust boundary.
pub struct PixelGrid;
impl PixelGrid {
    pub fn encode(wire: &[u8; WIRE]) -> Vec<u8> {
        let mut packet = [0u8; PIXEL_WIRE];
        packet[..2].copy_from_slice(b"A8");
        packet[2] = WIRE as u8;
        packet[3..3 + WIRE].copy_from_slice(wire);
        packet[3 + WIRE..].copy_from_slice(&crc32(wire).to_be_bytes());
        let mut pixels = vec![127u8; RGB_BYTES];
        for (index, bit) in packet
            .iter()
            .flat_map(|b| (0..8).rev().map(move |shift| (b >> shift) & 1))
            .enumerate()
        {
            let row = index / CELLS;
            let col = index % CELLS;
            let y0 = MARGIN + row * CELL;
            let x0 = MARGIN + col * CELL;
            let value = if bit == 1 { 232 } else { 16 };
            for y in y0..y0 + CELL {
                for x in x0..x0 + CELL {
                    pixels[(y * GRID + x) * 3..(y * GRID + x) * 3 + 3].fill(value);
                }
            }
        }
        pixels
    }

    pub fn decode(pixels: &[u8]) -> Result<[u8; WIRE], MediaError> {
        if pixels.len() != RGB_BYTES {
            return Err(MediaError::Frame);
        }
        let mut packet = [0u8; PIXEL_WIRE];
        for index in 0..PIXEL_WIRE * 8 {
            let row = index / CELLS;
            let col = index % CELLS;
            let y0 = MARGIN + row * CELL;
            let x0 = MARGIN + col * CELL;
            let mut total = 0u32;
            for y in y0 + 3..y0 + 7 {
                for x in x0 + 3..x0 + 7 {
                    total += pixels[(y * GRID + x) * 3..(y * GRID + x) * 3 + 3]
                        .iter()
                        .map(|b| u32::from(*b))
                        .sum::<u32>();
                }
            }
            let bit = u8::from(total > 124 * 4 * 4 * 3);
            packet[index / 8] |= bit << (7 - index % 8);
        }
        if &packet[..2] != b"A8" || packet[2] != WIRE as u8 {
            return Err(MediaError::Frame);
        }
        let wire: [u8; WIRE] = packet[3..3 + WIRE]
            .try_into()
            .map_err(|_| MediaError::Frame)?;
        let expected = u32::from_be_bytes(
            packet[3 + WIRE..]
                .try_into()
                .map_err(|_| MediaError::Frame)?,
        );
        if crc32(&wire) != expected {
            return Err(MediaError::Frame);
        }
        Ok(wire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(role: Role, key: [u8; 32]) -> ProvisionedSession {
        ProvisionedSession::from_owned_broker(
            role,
            [7; 16],
            "aegis_fixture".into(),
            "client_track".into(),
            "server_track".into(),
            Zeroizing::new(key),
            Instant::now() + Duration::from_secs(20),
        )
        .unwrap()
    }

    #[test]
    fn pixel_roundtrip_and_integrated_replay() {
        let (mut client, _) = session(Role::Client, [3; 32]).split().unwrap();
        let (_, mut server) = session(Role::Intermediary, [3; 32]).split().unwrap();
        let wire = client.seal_next(FrameKind::Data, &[9; MAX_PLAIN]).unwrap();
        let pixels = PixelGrid::encode(&wire);
        let decoded = PixelGrid::decode(&pixels).unwrap();
        let ReceivedFrame::Fresh(opened) = server.open(&decoded).unwrap() else {
            panic!("first authenticated frame must be fresh");
        };
        assert_eq!(opened.kind(), FrameKind::Data);
        assert_eq!(opened.sequence(), 0);
        assert_eq!(opened.payload(), [9; MAX_PLAIN]);
        assert!(matches!(
            server.open(&decoded).unwrap(),
            ReceivedFrame::Duplicate {
                kind: FrameKind::Data,
                sequence: 0
            }
        ));
        assert_eq!(
            client.seal_next(FrameKind::Ack, b"ack").unwrap()[1..5],
            1u32.to_be_bytes()
        );
    }

    #[test]
    fn consumed_grant_has_distinct_bounded_media_lifetime_and_silence_frame() {
        let grant = session(Role::Client, [3; 32]);
        assert!(grant.remaining_for_issuer() <= Duration::from_secs(20));
        let (mut sender, _) = grant.split().unwrap();
        let (_, mut receiver) = session(Role::Intermediary, [3; 32]).split().unwrap();
        let remaining = sender
            .active_until()
            .saturating_duration_since(Instant::now());
        assert!(remaining > Duration::from_secs(30));
        assert!(remaining <= MAX_MEDIA_LIFETIME);
        let wire = sender.seal_next(FrameKind::KeepAlive, &[]).unwrap();
        let ReceivedFrame::Fresh(opened) = receiver.open(&wire).unwrap() else {
            panic!("authenticated silence frame must be fresh");
        };
        assert_eq!(opened.kind(), FrameKind::KeepAlive);
        assert!(opened.payload().is_empty());
        assert!(matches!(
            receiver.open(&wire).unwrap(),
            ReceivedFrame::Duplicate {
                kind: FrameKind::KeepAlive,
                sequence: 0
            }
        ));
        let mut expired = session(Role::Client, [3; 32]);
        expired.expires = Instant::now() - Duration::from_millis(1);
        assert!(matches!(expired.split(), Err(MediaError::Expired)));
    }

    #[test]
    fn protected_client_grant_is_role_bounded_redacted_and_tamper_closed() {
        let grant = session(Role::Client, [3; 32])
            .into_protected_client_grant(Zeroizing::new("header.payload.signature".into()))
            .unwrap();
        assert!(!format!("{grant:?}").contains("payload"));
        let encoded = serde_json::to_vec(&grant).unwrap();
        let parsed: ProtectedMediaGrant = serde_json::from_slice(&encoded).unwrap();
        let (descriptor, token) = parsed.into_client().unwrap();
        assert_eq!(descriptor.role(), Role::Client);
        assert_eq!(&*token, "header.payload.signature");
        assert!(matches!(
            session(Role::Intermediary, [3; 32])
                .into_protected_client_grant(Zeroizing::new("header.payload.signature".into())),
            Err(MediaError::Descriptor)
        ));
        let mut wrong_ttl = session(Role::Client, [3; 32])
            .into_protected_client_grant(Zeroizing::new("header.payload.signature".into()))
            .unwrap();
        wrong_ttl.ttl_ms = 30_001;
        assert!(matches!(
            wrong_ttl.into_client(),
            Err(MediaError::Descriptor)
        ));
        let mut wrong_key = session(Role::Client, [3; 32])
            .into_protected_client_grant(Zeroizing::new("header.payload.signature".into()))
            .unwrap();
        wrong_key.media_key = [0; 32];
        assert!(matches!(
            wrong_key.into_client(),
            Err(MediaError::Descriptor)
        ));
    }

    #[test]
    fn wrong_key_direction_and_visual_damage_refuse() {
        let (mut client, mut client_rx) = session(Role::Client, [3; 32]).split().unwrap();
        let wire = client.seal_next(FrameKind::Data, b"secret").unwrap();
        let (_, mut bad_server) = session(Role::Intermediary, [4; 32]).split().unwrap();
        assert!(matches!(
            bad_server.open(&wire),
            Err(MediaError::Authentication)
        ));
        assert!(matches!(
            client_rx.open(&wire),
            Err(MediaError::Authentication)
        ));
        let mut pixels = PixelGrid::encode(&wire);
        pixels[(MARGIN * GRID + MARGIN) * 3..(MARGIN * GRID + MARGIN) * 3 + 3].fill(255);
        assert!(PixelGrid::decode(&pixels).is_ok());
        pixels[(MARGIN * GRID + MARGIN) * 3..(MARGIN * GRID + MARGIN) * 3 + 3].fill(127);
        for y in MARGIN + 3..MARGIN + 7 {
            for x in MARGIN + 3..MARGIN + 7 {
                pixels[(y * GRID + x) * 3..(y * GRID + x) * 3 + 3].fill(255);
            }
        }
        assert!(matches!(PixelGrid::decode(&pixels), Err(MediaError::Frame)));
    }

    #[test]
    fn descriptor_sequence_and_stale_bounds_refuse() {
        assert!(matches!(
            ProvisionedSession::from_owned_broker(
                Role::Client,
                [0; 16],
                "room".into(),
                "a".into(),
                "b".into(),
                Zeroizing::new([3; 32]),
                Instant::now() + Duration::from_secs(5)
            ),
            Err(MediaError::Descriptor)
        ));
        let (mut sender, _) = session(Role::Client, [3; 32]).split().unwrap();
        let (_, mut receiver) = session(Role::Intermediary, [3; 32]).split().unwrap();
        let first = sender.seal_next(FrameKind::Data, b"first").unwrap();
        sender.next_send = 100;
        let distant = sender.seal_next(FrameKind::Data, b"distant").unwrap();
        assert!(matches!(
            receiver.open(&first).unwrap(),
            ReceivedFrame::Fresh(_)
        ));
        assert!(matches!(
            receiver.open(&distant).unwrap(),
            ReceivedFrame::Fresh(_)
        ));
        assert!(matches!(
            receiver.open(&first).unwrap(),
            ReceivedFrame::Stale
        ));
        sender.next_send = u32::MAX;
        assert_eq!(
            sender.seal_next(FrameKind::Data, b"x"),
            Err(MediaError::Sequence)
        );
    }

    #[test]
    fn descriptor_expiry_blocks_sender_and_receiver() {
        let (mut sender, _) = session(Role::Client, [3; 32]).split().unwrap();
        let (_, mut receiver) = session(Role::Intermediary, [3; 32]).split().unwrap();
        let wire = sender.seal_next(FrameKind::Data, b"x").unwrap();
        sender.codec.expires = Instant::now() - Duration::from_secs(1);
        receiver.codec.expires = Instant::now() - Duration::from_secs(1);
        assert_eq!(
            sender.seal_next(FrameKind::Data, b"x"),
            Err(MediaError::Expired)
        );
        assert!(matches!(receiver.open(&wire), Err(MediaError::Expired)));
    }

    #[test]
    fn issuer_rejects_duplicate_take_claim_and_cancelled_reissue() {
        let issuer = MediaIssuer::new(2).unwrap();
        let reserve = || {
            issuer.reserve(
                [8; 16],
                [9; 16],
                "room_1".into(),
                "client_1".into(),
                "server_1".into(),
                Instant::now() + Duration::from_secs(20),
            )
        };
        reserve().unwrap();
        assert_eq!(reserve(), Err(MediaError::AlreadyIssued));
        assert!(matches!(
            issuer.take(Role::Intermediary, [8; 16], Some([10; 16])),
            Err(MediaError::Descriptor)
        ));
        let client = issuer.take(Role::Client, [8; 16], None).unwrap();
        let server = issuer
            .take(Role::Intermediary, [8; 16], Some([9; 16]))
            .unwrap();
        assert!(matches!(
            issuer.take(Role::Client, [8; 16], None),
            Err(MediaError::AlreadyIssued)
        ));
        assert!(matches!(
            issuer.take(Role::Intermediary, [8; 16], Some([9; 16])),
            Err(MediaError::AlreadyIssued)
        ));
        let (mut tx, _) = client.split().unwrap();
        let (_, mut rx) = server.split().unwrap();
        let wire = tx.seal_next(FrameKind::Data, b"owned").unwrap();
        assert!(matches!(rx.open(&wire), Ok(ReceivedFrame::Fresh(_))));
        issuer.cancel([8; 16]).unwrap();
        assert!(matches!(
            issuer.take(Role::Client, [8; 16], None),
            Err(MediaError::Descriptor)
        ));
        assert_eq!(reserve(), Err(MediaError::AlreadyIssued));
    }

    #[test]
    fn issuer_reconnect_uses_new_key_even_if_session_id_reused_after_expiry() {
        let issuer = MediaIssuer::new(1).unwrap();
        let reserve = || {
            issuer.reserve(
                [8; 16],
                [9; 16],
                "room_1".into(),
                "client_1".into(),
                "server_1".into(),
                Instant::now() + Duration::from_secs(20),
            )
        };
        reserve().unwrap();
        let (mut first_tx, _) = issuer
            .take(Role::Client, [8; 16], None)
            .unwrap()
            .split()
            .unwrap();
        let first = first_tx.seal_next(FrameKind::Data, b"same").unwrap();
        issuer
            .state
            .lock()
            .unwrap()
            .slots
            .get_mut(&[8; 16])
            .unwrap()
            .expires = Instant::now() - Duration::from_secs(1);
        reserve().unwrap();
        let (mut second_tx, _) = issuer
            .take(Role::Client, [8; 16], None)
            .unwrap()
            .split()
            .unwrap();
        let second = second_tx.seal_next(FrameKind::Data, b"same").unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn issuer_cancel_blocks_unissued_roles_and_preserves_tombstones() {
        let issuer = MediaIssuer::new(2).unwrap();
        let expires = Instant::now() + Duration::from_secs(20);
        issuer
            .reserve(
                [8; 16],
                [9; 16],
                "room_1".into(),
                "client_1".into(),
                "server_1".into(),
                expires,
            )
            .unwrap();
        issuer.cancel([8; 16]).unwrap();
        assert!(matches!(
            issuer.take(Role::Client, [8; 16], None),
            Err(MediaError::Descriptor)
        ));
        assert!(matches!(
            issuer.take(Role::Intermediary, [8; 16], Some([9; 16])),
            Err(MediaError::Descriptor)
        ));
        assert_eq!(
            issuer.reserve(
                [8; 16],
                [9; 16],
                "room_1".into(),
                "client_1".into(),
                "server_1".into(),
                expires,
            ),
            Err(MediaError::AlreadyIssued)
        );

        issuer
            .reserve(
                [10; 16],
                [11; 16],
                "room_2".into(),
                "client_2".into(),
                "server_2".into(),
                expires,
            )
            .unwrap();
        let _client = issuer.take(Role::Client, [10; 16], None).unwrap();
        issuer.cancel([10; 16]).unwrap();
        assert!(matches!(
            issuer.take(Role::Intermediary, [10; 16], Some([11; 16])),
            Err(MediaError::Descriptor)
        ));
        // If take wins the mutex before cancel, its descriptor remains valid
        // until expiry; cancellation cannot retract an already issued key.
    }

    #[test]
    fn new_broker_master_changes_reissued_session_ciphertext() {
        let first = MediaIssuer::new(1).unwrap();
        let second = MediaIssuer::new(1).unwrap();
        for issuer in [&first, &second] {
            issuer
                .reserve(
                    [8; 16],
                    [9; 16],
                    "room_1".into(),
                    "client".into(),
                    "intermediary".into(),
                    Instant::now() + Duration::from_secs(20),
                )
                .unwrap();
        }
        let (mut first_tx, _) = first
            .take(Role::Client, [8; 16], None)
            .unwrap()
            .split()
            .unwrap();
        let (mut second_tx, _) = second
            .take(Role::Client, [8; 16], None)
            .unwrap()
            .split()
            .unwrap();
        assert_ne!(
            first_tx.seal_next(FrameKind::Data, b"same").unwrap(),
            second_tx.seal_next(FrameKind::Data, b"same").unwrap(),
        );
    }
}
