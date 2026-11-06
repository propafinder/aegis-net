//! Inert self-hosted SFU bootstrap input preflight.
//!
//! The server uses its existing trusted-parent private reader for both files.
//! This grants no room/token/media access; product `SfuMedia` remains
//! unavailable until an authenticated issuer and media worker exist.

use aegis_webrtc::{
    sfu_media::ProvisionedSession, AdmissionKey, OwnedBroker, Role, SessionId, Signal,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
#[cfg(feature = "sfu-media-vp8")]
use futures::SinkExt;
use futures::StreamExt;
use hmac::{Hmac, Mac};
use prost::Message as _;
use rand::RngCore;
use rustls::{pki_types::CertificateDer, pki_types::ServerName, ClientConfig, RootCertStore};
use serde::Deserialize;
use sha2::Sha256;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::{client::TlsStream, TlsConnector};
use tokio_tungstenite::tungstenite::protocol::{
    Message as WsMessage, Role as WsRole, WebSocketConfig,
};
use url::Url;
use zeroize::Zeroizing;

const MAX_KEY: usize = 128;
const MAX_SECRET: usize = 256;
const MAX_ROOT_DER: usize = 16 * 1024;
const TLS_DEADLINE: Duration = Duration::from_secs(5);
const SIGNAL_DEADLINE: Duration = Duration::from_secs(5);
const MAX_SIGNAL_MESSAGE: usize = 256 * 1024;
const MAX_JOIN_MESSAGE: usize = 64 * 1024;
const MAX_UPGRADE_HEADER: usize = 8 * 1024;
const MAX_UPGRADE_REQUEST: usize = 8 * 1024;
#[cfg(feature = "sfu-media-vp8")]
const MEDIA_NEGOTIATION_DEADLINE: Duration = Duration::from_secs(20);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SfuBootstrapSettings {
    pub endpoint: String,
    pub tls_name: String,
    /// Optional local numeric dial target. The WSS origin and TLS authority
    /// remain the exact DNS name above; only a loopback address is accepted.
    pub connect_addr: Option<SocketAddr>,
    pub api_key_file: PathBuf,
    pub api_secret_file: PathBuf,
    pub tls_root_der_file: PathBuf,
}

/// Candidate broker credentials. No product caller or token issuer uses them.
/// Debug deliberately omits the endpoint, file paths and secret material.
pub struct SfuBootstrap {
    endpoint: Url,
    tls_name: String,
    connect_addr: Option<SocketAddr>,
    api_key: Zeroizing<Vec<u8>>,
    api_secret: Zeroizing<Vec<u8>>,
    client_tls: Arc<ClientConfig>,
    issuer_id: [u8; 32],
}

/// Inert, protected result: token and media key stay together off wire.
/// No product transport or public signaling response can construct this.
#[allow(dead_code)]
pub struct IssuedMedia {
    token: Zeroizing<String>,
    descriptor: ProvisionedSession,
    issuer_id: [u8; 32],
}

/// A signal connection does not itself join media tracks. The descriptor is
/// retained with the socket so a future media worker cannot substitute one.
#[allow(dead_code)]
pub struct AuthenticatedSignal<S = TlsStream<tokio::net::TcpStream>> {
    socket: Option<tokio_tungstenite::WebSocketStream<S>>,
    descriptor: ProvisionedSession,
    terminated: bool,
}

// A narrow view of the published LiveKit SignalResponse.join schema. Unknown
// nested fields remain forward-compatible; critical fields are checked below.
#[derive(prost::Message)]
struct JoinResponseView {
    #[prost(message, optional, tag = "1")]
    room: Option<RoomView>,
    #[prost(message, optional, tag = "2")]
    participant: Option<ParticipantView>,
    #[prost(string, tag = "7")]
    alternative_url: String,
}

#[derive(prost::Message)]
struct RoomView {
    #[prost(string, tag = "1")]
    sid: String,
    #[prost(string, tag = "2")]
    name: String,
}

#[derive(prost::Message)]
struct ParticipantView {
    #[prost(string, tag = "1")]
    sid: String,
    #[prost(string, tag = "2")]
    identity: String,
}

#[derive(prost::Message)]
struct SessionDescriptionView {
    #[prost(string, tag = "1")]
    kind: String,
    #[prost(string, tag = "2")]
    sdp: String,
    #[prost(uint32, tag = "3")]
    id: u32,
    #[prost(map = "string, string", tag = "4")]
    mid_to_track_id: HashMap<String, String>,
}

#[derive(prost::Message)]
struct TrickleView {
    #[prost(string, tag = "1")]
    candidate_init: String,
    #[prost(int32, tag = "2")]
    target: i32,
    #[prost(bool, tag = "3")]
    final_candidate: bool,
}

#[derive(prost::Message)]
struct TrackInfoView {
    #[prost(string, tag = "1")]
    sid: String,
    #[prost(int32, tag = "2")]
    kind: i32,
    #[prost(string, tag = "3")]
    name: String,
    #[prost(uint32, tag = "5")]
    width: u32,
    #[prost(uint32, tag = "6")]
    height: u32,
    #[prost(int32, tag = "9")]
    source: i32,
}

#[derive(prost::Message)]
struct TrackPublishedView {
    #[prost(string, tag = "1")]
    cid: String,
    #[prost(message, optional, tag = "2")]
    track: Option<TrackInfoView>,
}

#[derive(prost::Message)]
struct ParticipantUpdateView {
    #[prost(message, repeated, tag = "1")]
    participants: Vec<ParticipantTracksView>,
}

#[derive(prost::Message)]
struct ParticipantTracksView {
    #[prost(string, tag = "1")]
    sid: String,
    #[prost(string, tag = "2")]
    identity: String,
    #[prost(message, repeated, tag = "4")]
    tracks: Vec<TrackInfoView>,
}

#[cfg(feature = "sfu-media-vp8")]
#[derive(prost::Message)]
struct AddVideoTrackView {
    #[prost(string, tag = "1")]
    cid: String,
    #[prost(string, tag = "2")]
    name: String,
    #[prost(int32, tag = "3")]
    kind: i32,
    #[prost(uint32, tag = "4")]
    width: u32,
    #[prost(uint32, tag = "5")]
    height: u32,
    #[prost(int32, tag = "8")]
    source: i32,
}

#[cfg(feature = "sfu-media-vp8")]
#[derive(prost::Message)]
struct SubscribeTrackView {
    #[prost(string, repeated, tag = "1")]
    track_sids: Vec<String>,
    #[prost(bool, tag = "2")]
    subscribe: bool,
}

/// A parsed SFU signal is still untrusted input. A future media worker must
/// validate path policy and selected ICE pair before applying it to a peer.
#[allow(dead_code)]
enum NegotiationSignal {
    PublisherAnswer(Zeroizing<String>),
    SubscriberOffer {
        sdp: Zeroizing<String>,
        id: u32,
        mid_to_track_id: HashMap<String, String>,
    },
    Trickle {
        candidate_init: Zeroizing<String>,
        target: i32,
        final_candidate: bool,
    },
    TrackPublished {
        cid: String,
        track: TrackInfoView,
    },
    ParticipantUpdate(ParticipantUpdateView),
    #[cfg(feature = "sfu-media-vp8")]
    ControlNotice(aegis_webrtc::sfu_peer::SfuControlNotice),
    /// LiveKit's token notice does not renew the issuer grant or deadline.
    RefreshToken,
    /// Terminal disconnect only. Resume and reconnect require a fresh grant.
    Leave,
}

#[cfg(feature = "sfu-media-vp8")]
fn observe_ready_signal(
    window: &mut aegis_webrtc::sfu_peer::SfuControlNoticeWindow,
    count: &mut usize,
    signal: NegotiationSignal,
) -> Result<(), BootstrapError> {
    if *count >= 32 {
        return Err(BootstrapError::Configuration);
    }
    *count += 1;
    match signal {
        NegotiationSignal::ControlNotice(notice) => window
            .observe(notice)
            .map_err(|_| BootstrapError::Configuration),
        NegotiationSignal::RefreshToken => Ok(()),
        _ => Err(BootstrapError::Configuration),
    }
}

impl std::fmt::Debug for NegotiationSignal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NegotiationSignal([redacted])")
    }
}

/// Require one complete length-delimited SignalResponse oneof field. Protobuf
/// decoders otherwise permit a later field to silently replace an earlier one.
fn signal_payload(message: &[u8]) -> Result<(u8, &[u8]), BootstrapError> {
    let (field, rest) = match message {
        // SignalResponse.refresh_token = field 16, wire type 2. Require its
        // canonical two-byte key; every supported lower field has one byte.
        [0x82, 0x01, rest @ ..] => (16, rest),
        [key, rest @ ..] if *key & 0x80 == 0 && *key & 7 == 2 => (*key >> 3, rest),
        _ => {
            if message.len() <= MAX_SIGNAL_MESSAGE {
                #[cfg(feature = "sfu-media-vp8")]
                eprintln!(
                    "sfu_signal_refused role=server field={}",
                    aegis_webrtc::sfu_peer::refused_signal_coordinate(message)
                );
            }
            return Err(BootstrapError::Configuration);
        }
    };
    if message.len() > MAX_SIGNAL_MESSAGE {
        return Err(BootstrapError::Configuration);
    }
    if !matches!(field, 2 | 3 | 4 | 5 | 6 | 8 | 16)
        && !(cfg!(feature = "sfu-media-vp8") && field == 15)
    {
        #[cfg(feature = "sfu-media-vp8")]
        eprintln!(
            "sfu_signal_refused role=server field={}",
            aegis_webrtc::sfu_peer::refused_signal_coordinate(message)
        );
        return Err(BootstrapError::Configuration);
    }
    let mut size = 0usize;
    let mut prefix = 0usize;
    for shift in [0, 7, 14] {
        let byte = *rest.get(prefix).ok_or(BootstrapError::Configuration)?;
        prefix += 1;
        size |= usize::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            let end = prefix
                .checked_add(size)
                .ok_or(BootstrapError::Configuration)?;
            if (size == 0 && field != 8) || end != rest.len() {
                return Err(BootstrapError::Configuration);
            }
            return Ok((field, &rest[prefix..end]));
        }
    }
    Err(BootstrapError::Configuration)
}

/// LeaveRequest action must not be discarded: RESUME and RECONNECT would need
/// a fresh issuer grant plus expiry and location revalidation. Until that
/// transaction exists, only an unambiguous terminal disconnect is accepted.
fn terminal_leave(payload: &[u8]) -> Result<NegotiationSignal, BootstrapError> {
    let mut remaining = payload;
    let mut seen = 0u8;
    let mut can_reconnect = false;
    let mut action = 0u32;
    while let Some((&field, rest)) = remaining.split_first() {
        let bit = match field {
            0x08 => 1, // can_reconnect, obsolete legacy hint
            0x10 => 2, // DisconnectReason
            0x18 => 4, // Action
            _ => return Err(BootstrapError::Configuration),
        };
        if seen & bit != 0 {
            return Err(BootstrapError::Configuration);
        }
        seen |= bit;
        remaining = rest;
        let mut value = 0u32;
        let mut complete = false;
        for shift in [0, 7, 14, 21, 28] {
            let (&byte, rest) = remaining
                .split_first()
                .ok_or(BootstrapError::Configuration)?;
            if shift == 28 && byte > 0x0f {
                return Err(BootstrapError::Configuration);
            }
            value |= u32::from(byte & 0x7f) << shift;
            remaining = rest;
            if byte & 0x80 == 0 {
                if shift != 0 && byte == 0 {
                    return Err(BootstrapError::Configuration);
                }
                complete = true;
                break;
            }
        }
        if !complete {
            return Err(BootstrapError::Configuration);
        }
        match field {
            0x08 if value <= 1 => can_reconnect = value == 1,
            0x10 if value <= 16 => {} // known DisconnectReason; no side effect
            0x18 if value <= 2 => action = value,
            _ => return Err(BootstrapError::Configuration),
        }
    }
    if can_reconnect || action != 0 {
        // Do not issue an implicit reconnect or reuse this one-use descriptor.
        return Err(BootstrapError::Configuration);
    }
    Ok(NegotiationSignal::Leave)
}

fn decode_negotiation_signal(message: &[u8]) -> Result<NegotiationSignal, BootstrapError> {
    let (field, payload) = signal_payload(message)?;
    match field {
        2 | 3 => {
            let sdp = SessionDescriptionView::decode(payload)
                .map_err(|_| BootstrapError::Configuration)?;
            let expected = if field == 2 { "answer" } else { "offer" };
            if sdp.kind != expected
                || !sdp.sdp.starts_with("v=0\r\n")
                || sdp.sdp.len() > 128 * 1024
                || sdp.sdp.bytes().any(|byte| byte == 0)
            {
                return Err(BootstrapError::Configuration);
            }
            if field == 2 {
                Ok(NegotiationSignal::PublisherAnswer(Zeroizing::new(sdp.sdp)))
            } else {
                Ok(NegotiationSignal::SubscriberOffer {
                    sdp: Zeroizing::new(sdp.sdp),
                    id: sdp.id,
                    mid_to_track_id: sdp.mid_to_track_id,
                })
            }
        }
        4 => {
            let trickle =
                TrickleView::decode(payload).map_err(|_| BootstrapError::Configuration)?;
            if !matches!(trickle.target, 0 | 1) || trickle.candidate_init.len() > 4096 {
                return Err(BootstrapError::Configuration);
            }
            if !trickle.final_candidate {
                let value: serde_json::Value = serde_json::from_str(&trickle.candidate_init)
                    .map_err(|_| BootstrapError::Configuration)?;
                let candidate = value
                    .get("candidate")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(BootstrapError::Configuration)?;
                if candidate.is_empty() || candidate.len() > 2048 {
                    return Err(BootstrapError::Configuration);
                }
            }
            Ok(NegotiationSignal::Trickle {
                candidate_init: Zeroizing::new(trickle.candidate_init),
                target: trickle.target,
                final_candidate: trickle.final_candidate,
            })
        }
        5 => {
            let update = ParticipantUpdateView::decode(payload)
                .map_err(|_| BootstrapError::Configuration)?;
            if update.participants.len() > 8
                || update.participants.iter().any(|p| p.tracks.len() > 8)
            {
                return Err(BootstrapError::Configuration);
            }
            Ok(NegotiationSignal::ParticipantUpdate(update))
        }
        6 => {
            let event =
                TrackPublishedView::decode(payload).map_err(|_| BootstrapError::Configuration)?;
            if event.cid.is_empty() || event.cid.len() > 96 {
                return Err(BootstrapError::Configuration);
            }
            Ok(NegotiationSignal::TrackPublished {
                cid: event.cid,
                track: event.track.ok_or(BootstrapError::Configuration)?,
            })
        }
        8 => terminal_leave(payload),
        #[cfg(feature = "sfu-media-vp8")]
        15 => Ok(NegotiationSignal::ControlNotice(
            aegis_webrtc::sfu_peer::parse_control_notice(field, payload)
                .map_err(|_| BootstrapError::Configuration)?,
        )),
        16 => {
            // Validate the protobuf string without allocating, retaining, or
            // logging the bearer. The descriptor remains authoritative.
            let token = std::str::from_utf8(payload).map_err(|_| BootstrapError::Configuration)?;
            if token.is_empty()
                || token.len() > 4096
                || !token.bytes().all(|b| b.is_ascii_graphic())
            {
                return Err(BootstrapError::Configuration);
            }
            Ok(NegotiationSignal::RefreshToken)
        }
        _ => Err(BootstrapError::Configuration),
    }
}

fn join_payload(message: &[u8]) -> Result<&[u8], BootstrapError> {
    // SignalResponse is a oneof. Require the first and only field to be join
    // (field 1, length-delimited); do not silently ignore a leave/redirect or
    // a second oneof alternative as a partial protobuf decoder would.
    if message.len() > MAX_JOIN_MESSAGE || message.first() != Some(&0x0a) {
        return Err(BootstrapError::Configuration);
    }
    let mut size = 0usize;
    let mut index = 1;
    for shift in [0, 7, 14] {
        let byte = *message.get(index).ok_or(BootstrapError::Configuration)?;
        index += 1;
        size |= usize::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            let end = index
                .checked_add(size)
                .ok_or(BootstrapError::Configuration)?;
            if size == 0 || end != message.len() {
                return Err(BootstrapError::Configuration);
            }
            return Ok(&message[index..end]);
        }
    }
    Err(BootstrapError::Configuration)
}

fn verify_join(message: &[u8], descriptor: &ProvisionedSession) -> Result<(), BootstrapError> {
    let join = JoinResponseView::decode(join_payload(message)?)
        .map_err(|_| BootstrapError::Configuration)?;
    let room = join.room.ok_or(BootstrapError::Configuration)?;
    let participant = join.participant.ok_or(BootstrapError::Configuration)?;
    if !join.alternative_url.is_empty()
        || room.sid.is_empty()
        || participant.sid.is_empty()
        || room.name != descriptor.room_for_issuer()
        || participant.identity != descriptor.identity_for_issuer()
    {
        return Err(BootstrapError::Configuration);
    }
    Ok(())
}

/// Parse only the bounded HTTP Upgrade response. No request header or bearer
/// material is passed to a logger, parser or error formatter here.
fn verify_upgrade_response(
    input: &[u8],
    expected_accept: &str,
) -> Result<Option<usize>, BootstrapError> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut response = httparse::Response::new(&mut headers);
    let end = match response
        .parse(input)
        .map_err(|_| BootstrapError::Configuration)?
    {
        httparse::Status::Partial => return Ok(None),
        httparse::Status::Complete(end) => end,
    };
    if response.version != Some(1) || response.code != Some(101) {
        return Err(BootstrapError::Configuration);
    }
    let mut upgrade = false;
    let mut connection = false;
    let mut accept = false;
    for header in response.headers.iter() {
        let value = std::str::from_utf8(header.value)
            .map_err(|_| BootstrapError::Configuration)?
            .trim();
        if header.name.eq_ignore_ascii_case("Upgrade") {
            if upgrade || !value.eq_ignore_ascii_case("websocket") {
                return Err(BootstrapError::Configuration);
            }
            upgrade = true;
        } else if header.name.eq_ignore_ascii_case("Connection") {
            if connection
                || !value
                    .split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
            {
                return Err(BootstrapError::Configuration);
            }
            connection = true;
        } else if header.name.eq_ignore_ascii_case("Sec-WebSocket-Accept") {
            if accept || value != expected_accept {
                return Err(BootstrapError::Configuration);
            }
            accept = true;
        } else if header.name.eq_ignore_ascii_case("Sec-WebSocket-Extensions")
            || header.name.eq_ignore_ascii_case("Sec-WebSocket-Protocol")
            || header.name.eq_ignore_ascii_case("Content-Length")
            || header.name.eq_ignore_ascii_case("Transfer-Encoding")
        {
            return Err(BootstrapError::Configuration);
        }
    }
    if upgrade && connection && accept {
        Ok(Some(end))
    } else {
        Err(BootstrapError::Configuration)
    }
}

impl<S> std::fmt::Debug for AuthenticatedSignal<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthenticatedSignal([redacted])")
    }
}

#[allow(dead_code)]
impl<S: AsyncRead + AsyncWrite + Unpin> AuthenticatedSignal<S> {
    /// One bounded post-Join signal read. This does not apply SDP or candidates,
    /// create a peer connection, or grant media readiness.
    async fn read_next_negotiation(
        &mut self,
        deadline: tokio::time::Instant,
    ) -> Result<NegotiationSignal, BootstrapError> {
        if self.terminated || self.socket.is_none() {
            return Err(BootstrapError::Configuration);
        }
        let result = async {
            if self.descriptor.remaining_for_issuer().is_zero() {
                return Err(BootstrapError::Configuration);
            }
            let limit = deadline.min(tokio::time::Instant::now() + SIGNAL_DEADLINE);
            let frame = tokio::time::timeout_at(
                limit,
                self.socket
                    .as_mut()
                    .ok_or(BootstrapError::Configuration)?
                    .next(),
            )
            .await
            .map_err(|_| BootstrapError::Configuration)?
            .ok_or(BootstrapError::Configuration)?
            .map_err(|_| BootstrapError::Configuration)?;
            if self.descriptor.remaining_for_issuer().is_zero() {
                return Err(BootstrapError::Configuration);
            }
            match frame {
                WsMessage::Binary(bytes) => decode_negotiation_signal(&bytes),
                _ => Err(BootstrapError::Configuration),
            }
        }
        .await;
        if result.is_err() || matches!(result, Ok(NegotiationSignal::Leave)) {
            // Terminal state is set before waiting for a bounded close handshake.
            // Even a peer that ignores close cannot induce another read/retry.
            self.terminated = true;
            if let Some(mut socket) = self.socket.take() {
                let _ = tokio::time::timeout(Duration::from_millis(250), socket.close(None)).await;
                // Drop even if the peer blocked the Close write or flush.
            }
        }
        result
    }
}

/// Server-internal transaction. The broker owns role/claim admission and the
/// one-use descriptor; the loaded private-file issuer owns the signing key.
/// No signaling wire operation constructs or returns this capability yet.
#[allow(dead_code)]
pub(crate) struct MediaTransaction<'a> {
    broker: &'a OwnedBroker,
    issuer: &'a SfuBootstrap,
}

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub(crate) enum MediaTransactionError {
    #[error("media admission refused")]
    Admission(#[from] aegis_webrtc::Error),
    #[error("media grant refused")]
    Issuer(#[from] BootstrapError),
}

#[allow(dead_code)]
impl<'a> MediaTransaction<'a> {
    pub(crate) fn new(broker: &'a OwnedBroker, issuer: &'a SfuBootstrap) -> Self {
        Self { broker, issuer }
    }

    /// Reserve both roles under the broker's pending lock before Answer is
    /// visible to Poll. A wrong key or claim does not spend either role.
    pub(crate) fn start(
        &self,
        key: &AdmissionKey,
        session: SessionId,
        claim: SessionId,
        answer: Signal,
    ) -> Result<(), MediaTransactionError> {
        self.broker.start_media_v1(key, session, claim, answer)?;
        Ok(())
    }

    /// Consume one role's broker descriptor before signing. If signing fails,
    /// the descriptor stays spent; no retry can reuse that issuance slot.
    pub(crate) fn take(
        &self,
        role: Role,
        key: &AdmissionKey,
        session: SessionId,
        claim: Option<SessionId>,
    ) -> Result<IssuedMedia, MediaTransactionError> {
        let descriptor = self.broker.take_media_v1(role, key, session, claim)?;
        Ok(self.issuer.issue_for_authenticated_v1(descriptor)?)
    }

    /// Consume the authenticated role before any network I/O. A TLS, WebSocket,
    /// or Join failure leaves the broker capability spent and cannot retry the
    /// same grant. This is signaling custody only; it does not enable media.
    pub(crate) async fn take_and_connect(
        &self,
        role: Role,
        key: &AdmissionKey,
        session: SessionId,
        claim: Option<SessionId>,
    ) -> Result<AuthenticatedSignal, MediaTransactionError> {
        let issued = self.take(role, key, session, claim)?;
        Ok(self.issuer.connect_authenticated_signal(issued).await?)
    }

    /// The only media construction path: spend the broker role, mint the
    /// short-lived room token, authenticate the pinned SFU Join, then consume
    /// the same descriptor into a real VP8 RTP peer. No caller may provide a
    /// room, track name, media key or JWT here.
    #[cfg(feature = "sfu-media-vp8")]
    pub(crate) async fn take_connect_media(
        &self,
        role: Role,
        key: &AdmissionKey,
        session: SessionId,
        claim: Option<SessionId>,
        path: aegis_webrtc::sfu_peer::SfuPath,
    ) -> Result<LiveMediaSession, MediaTransactionError> {
        path.validate()
            .map_err(|_| MediaTransactionError::Issuer(BootstrapError::Configuration))?;
        let descriptor = self
            .broker
            .take_claimed_media_v1(role, key, session, claim)?;
        let issued = self.issuer.issue_for_authenticated_v1(descriptor)?;
        let signal = self
            .issuer
            .connect_authenticated_signal_on_path(issued, Some(&path.allowed_sfu_ips))
            .await?;
        LiveMediaSession::from_authenticated(signal, path)
            .await
            .map_err(MediaTransactionError::Issuer)
    }
}

/// A joined, broker-owned LiveKit participant. This type is internal until a
/// device-authenticated installed server endpoint can bind both participant
/// roles to the existing inner TLS lease and expose a safe stream lifecycle.
#[cfg(feature = "sfu-media-vp8")]
pub(crate) struct LiveMediaSession {
    socket: tokio_tungstenite::WebSocketStream<TlsStream<tokio::net::TcpStream>>,
    peer: aegis_webrtc::sfu_peer::SfuMediaPeer,
    counterpart_identity: String,
    local_name: String,
    remote_name: String,
    remote_sid: Option<String>,
    control_notices: aegis_webrtc::sfu_peer::SfuControlNoticeWindow,
    deadline: tokio::time::Instant,
}

#[cfg(feature = "sfu-media-vp8")]
fn bounded_signal_field(
    field: u8,
    message: impl prost::Message,
) -> Result<Vec<u8>, BootstrapError> {
    let payload = message.encode_to_vec();
    if payload.is_empty() || payload.len() > MAX_SIGNAL_MESSAGE - 4 {
        return Err(BootstrapError::Configuration);
    }
    let mut wire = Vec::with_capacity(payload.len() + 4);
    wire.push(field);
    let mut length = payload.len();
    while length >= 0x80 {
        wire.push((length as u8 & 0x7f) | 0x80);
        length >>= 7;
    }
    wire.push(length as u8);
    wire.extend_from_slice(&payload);
    Ok(wire)
}

#[cfg(feature = "sfu-media-vp8")]
fn media_track_ok(track: &TrackInfoView, expected_name: &str) -> bool {
    !track.sid.is_empty()
        && track.sid.len() <= 96
        && track.sid.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && track.name == expected_name
        && track.kind == 1 // LiveKit TrackType::VIDEO
        && track.source == 1 // LiveKit TrackSource::CAMERA
        // LiveKit may acknowledge publication before the first 256px RTP
        // sample supplies dimensions. The decoder later requires 256x256.
        && (track.width == 0 || track.width == 256)
        && track.height == track.width
}

#[cfg(feature = "sfu-media-vp8")]
impl LiveMediaSession {
    async fn from_authenticated(
        signal: AuthenticatedSignal,
        path: aegis_webrtc::sfu_peer::SfuPath,
    ) -> Result<Self, BootstrapError> {
        if signal.terminated {
            return Err(BootstrapError::Configuration);
        }
        let remaining = signal.descriptor.remaining_for_issuer();
        if remaining.is_zero() {
            return Err(BootstrapError::Configuration);
        }
        let counterpart_identity = signal.descriptor.counterpart_identity_for_issuer();
        let local_name = match signal.descriptor.role() {
            aegis_webrtc::sfu_media::Role::Client => signal.descriptor.track_names().0.to_owned(),
            aegis_webrtc::sfu_media::Role::Intermediary => {
                signal.descriptor.track_names().1.to_owned()
            }
        };
        let remote_name = match signal.descriptor.role() {
            aegis_webrtc::sfu_media::Role::Client => signal.descriptor.track_names().1.to_owned(),
            aegis_webrtc::sfu_media::Role::Intermediary => {
                signal.descriptor.track_names().0.to_owned()
            }
        };
        let deadline = tokio::time::Instant::now() + remaining.min(MEDIA_NEGOTIATION_DEADLINE);
        let peer = aegis_webrtc::sfu_peer::SfuMediaPeer::new(signal.descriptor, path)
            .await
            .map_err(|_| BootstrapError::Configuration)?;
        Ok(Self {
            socket: signal.socket.ok_or(BootstrapError::Configuration)?,
            peer,
            counterpart_identity,
            local_name,
            remote_name,
            remote_sid: None,
            control_notices: aegis_webrtc::sfu_peer::SfuControlNoticeWindow::default(),
            deadline,
        })
    }

    async fn send_request(
        &mut self,
        field: u8,
        message: impl prost::Message,
    ) -> Result<(), BootstrapError> {
        let wire = bounded_signal_field(field, message)?;
        tokio::time::timeout_at(self.deadline, self.socket.send(WsMessage::Binary(wire)))
            .await
            .map_err(|_| BootstrapError::Configuration)?
            .map_err(|_| BootstrapError::Configuration)
    }

    async fn read_response(&mut self) -> Result<NegotiationSignal, BootstrapError> {
        let response = tokio::time::timeout_at(self.deadline, self.socket.next())
            .await
            .map_err(|_| BootstrapError::Configuration)?
            .ok_or(BootstrapError::Configuration)?
            .map_err(|_| BootstrapError::Configuration)?;
        match response {
            WsMessage::Binary(bytes) => {
                let decoded = decode_negotiation_signal(&bytes);
                if decoded.is_err() {
                    // Fixed local diagnostic only. No signaling payload or
                    // grant-derived material is written to a log.
                    let kind = match bytes.first() {
                        Some(0x12) => "publisher_answer",
                        Some(0x1a) => "subscriber_offer",
                        Some(0x22) => "trickle",
                        Some(0x2a) => "participant_update",
                        Some(0x32) => "track_published",
                        Some(0x42) => "leave",
                        Some(0x82) => "refresh_token",
                        _ => "unknown",
                    };
                    eprintln!("sfu_media_signal_refused role=server kind={kind}");
                }
                decoded
            }
            _ => {
                eprintln!("sfu_media_signal_refused role=server kind=nonbinary");
                Err(BootstrapError::Configuration)
            }
        }
    }

    /// Apply publisher Answer, subscriber Offer, bounded ICE trickle, and the
    /// opposite broker identity's exact video track. A media path is not ready
    /// until both selected RTP ICE pairs have been checked against the private
    /// numeric SFU allowlist by `SfuMediaPeer`.
    pub(crate) async fn negotiate(&mut self) -> Result<(), BootstrapError> {
        let mut step = "add_track";
        let result = self.negotiate_inner(&mut step).await;
        if result.is_err() {
            eprintln!("sfu_media_refused role=server step={step}");
        }
        result
    }

    async fn negotiate_inner(&mut self, step: &mut &'static str) -> Result<(), BootstrapError> {
        self.send_request(
            0x22,
            AddVideoTrackView {
                cid: self.local_name.clone(),
                name: self.local_name.clone(),
                kind: 1,
                width: 256,
                height: 256,
                source: 1,
            },
        )
        .await?;
        *step = "publisher_offer";
        let offer = self
            .peer
            .publisher_offer()
            .await
            .map_err(|_| BootstrapError::Configuration)?;
        *step = "send_publisher_offer";
        self.send_request(
            0x0a,
            SessionDescriptionView {
                kind: "offer".into(),
                sdp: offer,
                id: 0,
                mid_to_track_id: HashMap::new(),
            },
        )
        .await?;
        *step = "read_signal";
        let mut published = false;
        let mut publisher_answer = false;
        let mut subscriber_answer = false;
        let mut subscribed = false;
        let mut subscriber_offers = aegis_webrtc::sfu_peer::SubscriberOfferWindow::new();
        let mut pending_trickles = aegis_webrtc::sfu_peer::PendingTrickles::default();
        let mut control_notices = aegis_webrtc::sfu_peer::SfuControlNoticeWindow::default();
        for _ in 0..32 {
            if published
                && publisher_answer
                && subscriber_answer
                && subscribed
                && subscriber_offers.ready()
            {
                break;
            }
            let signal = self.read_response().await?;
            match signal {
                NegotiationSignal::TrackPublished { cid, track } => {
                    *step = "track_published";
                    if published
                        || cid != self.local_name
                        || !media_track_ok(&track, &self.local_name)
                    {
                        return Err(BootstrapError::Configuration);
                    }
                    published = true;
                }
                NegotiationSignal::PublisherAnswer(sdp) => {
                    *step = "publisher_answer";
                    if publisher_answer {
                        return Err(BootstrapError::Configuration);
                    }
                    self.peer
                        .apply_publisher_answer(sdp.to_string())
                        .await
                        .map_err(|_| BootstrapError::Configuration)?;
                    publisher_answer = true;
                    pending_trickles
                        .flush(&self.peer, true)
                        .await
                        .map_err(|_| BootstrapError::Configuration)?;
                }
                NegotiationSignal::SubscriberOffer {
                    sdp,
                    id,
                    mid_to_track_id,
                } => {
                    *step = "subscriber_offer";
                    subscriber_offers
                        .begin_offer(&sdp, id)
                        .map_err(|_| BootstrapError::Configuration)?;
                    if self.remote_sid.as_ref().is_some_and(|sid| {
                        !mid_to_track_id.is_empty()
                            && !aegis_webrtc::sfu_peer::approved_offer_video_mid(
                                &sdp,
                                &mid_to_track_id,
                                sid,
                            )
                    }) {
                        return Err(BootstrapError::Configuration);
                    }
                    let answer = self
                        .peer
                        .answer_subscriber_offer(sdp.to_string())
                        .await
                        .map_err(|_| BootstrapError::Configuration)?;
                    self.send_request(
                        0x12,
                        SessionDescriptionView {
                            kind: "answer".into(),
                            sdp: answer,
                            id,
                            mid_to_track_id: HashMap::new(),
                        },
                    )
                    .await?;
                    subscriber_answer = true;
                    pending_trickles
                        .flush(&self.peer, false)
                        .await
                        .map_err(|_| BootstrapError::Configuration)?;
                    let (count, video, receiver_identity) = self
                        .peer
                        .subscriber_receiver_state(
                            self.remote_sid.as_deref(),
                            &self.counterpart_identity,
                        )
                        .await;
                    if self.remote_sid.is_none() {
                        subscriber_offers
                            .defer_offer(sdp, mid_to_track_id, count, video)
                            .map_err(|_| BootstrapError::Configuration)?;
                        continue;
                    }
                    let approved_track = self.remote_sid.as_ref().is_some_and(|sid| {
                        aegis_webrtc::sfu_peer::approved_offer_track(
                            &sdp,
                            &mid_to_track_id,
                            sid,
                            receiver_identity,
                        )
                    });
                    subscriber_offers
                        .applied_offer(count, video, approved_track)
                        .map_err(|_| BootstrapError::Configuration)?;
                }
                NegotiationSignal::ParticipantUpdate(update) => {
                    *step = "participant_update";
                    for participant in update.participants {
                        if participant.identity != self.counterpart_identity {
                            continue;
                        }
                        for track in participant.tracks {
                            if !media_track_ok(&track, &self.remote_name) {
                                continue;
                            }
                            control_notices
                                .bind_remote(&participant.sid, &track.sid)
                                .map_err(|_| BootstrapError::Configuration)?;
                            if let Some(existing) = &self.remote_sid {
                                if existing != &track.sid {
                                    return Err(BootstrapError::Configuration);
                                }
                            } else {
                                self.remote_sid = Some(track.sid.clone());
                                self.send_request(
                                    0x32,
                                    SubscribeTrackView {
                                        track_sids: vec![track.sid],
                                        subscribe: true,
                                    },
                                )
                                .await?;
                                subscriber_offers
                                    .request_subscription()
                                    .map_err(|_| BootstrapError::Configuration)?;
                                subscribed = true;
                                let (count, video, receiver_identity) = self
                                    .peer
                                    .subscriber_receiver_state(
                                        self.remote_sid.as_deref(),
                                        &self.counterpart_identity,
                                    )
                                    .await;
                                subscriber_offers
                                    .resolve_pending(
                                        self.remote_sid
                                            .as_deref()
                                            .ok_or(BootstrapError::Configuration)?,
                                        count,
                                        video,
                                        receiver_identity,
                                    )
                                    .map_err(|_| BootstrapError::Configuration)?;
                            }
                        }
                    }
                }
                NegotiationSignal::Trickle {
                    candidate_init,
                    target,
                    final_candidate,
                } => {
                    *step = "trickle";
                    if final_candidate && candidate_init.is_empty() {
                        continue;
                    }
                    let publisher = target == 0;
                    if (publisher && !publisher_answer) || (!publisher && !subscriber_answer) {
                        pending_trickles
                            .queue(&self.peer, candidate_init, publisher)
                            .map_err(|_| BootstrapError::Configuration)?;
                    } else {
                        self.peer
                            .apply_trickle_json(&candidate_init, publisher)
                            .await
                            .map_err(|_| BootstrapError::Configuration)?;
                    }
                }
                NegotiationSignal::Leave => {
                    *step = "leave";
                    return Err(BootstrapError::Configuration);
                }
                NegotiationSignal::RefreshToken => {
                    // A server token notice cannot renew this issuer grant.
                }
                NegotiationSignal::ControlNotice(notice) => {
                    *step = "control_notice";
                    control_notices
                        .observe(notice)
                        .map_err(|_| BootstrapError::Configuration)?;
                }
            }
            *step = "read_signal";
        }
        *step = "required_signals";
        if !(published
            && publisher_answer
            && subscriber_answer
            && subscribed
            && subscriber_offers.ready())
        {
            return Err(BootstrapError::Configuration);
        }
        *step = "selected_ice";
        tokio::time::timeout_at(self.deadline, self.peer.wait_connected())
            .await
            .map_err(|_| BootstrapError::Configuration)?
            .map_err(|_| BootstrapError::Configuration)?;
        self.control_notices = control_notices;
        self.deadline = self.peer.media_deadline().into();
        Ok(())
    }

    pub(crate) async fn send_frame(
        &mut self,
        kind: aegis_webrtc::sfu_media::FrameKind,
        payload: &[u8],
    ) -> Result<[u8; 64], BootstrapError> {
        if self.remote_sid.is_none() || tokio::time::Instant::now() >= self.deadline {
            return Err(BootstrapError::Configuration);
        }
        self.peer
            .send_frame(kind, payload)
            .await
            .map_err(|_| BootstrapError::Configuration)
    }

    pub(crate) async fn retransmit(&mut self, wire: &[u8; 64]) -> Result<(), BootstrapError> {
        self.peer
            .retransmit(wire)
            .await
            .map_err(|_| BootstrapError::Configuration)
    }

    pub(crate) async fn receive_frame(
        &mut self,
    ) -> Result<aegis_webrtc::sfu_media::ReceivedFrame, BootstrapError> {
        let sid = self
            .remote_sid
            .as_deref()
            .ok_or(BootstrapError::Configuration)?;
        self.peer
            .receive_frame(sid, &self.counterpart_identity)
            .await
            .map_err(|_| BootstrapError::Configuration)
    }

    /// Adapt the authenticated video tracks to the existing inner TLS byte
    /// admission. This adapter is private and remains feature gated. The
    /// caller must await the worker result after `serve_device_carrier` ends;
    /// dropping the owner aborts it and closes both WebRTC peers.
    pub(crate) async fn into_inner_tls_carrier(
        mut self,
    ) -> Result<
        (
            tokio::io::DuplexStream,
            tokio::task::JoinHandle<Result<(), BootstrapError>>,
        ),
        BootstrapError,
    > {
        self.negotiate().await?;
        let (device_side, media_side) = tokio::io::duplex(64 * 1024);
        let worker = tokio::spawn(async move { self.pump_bytes(media_side).await });
        Ok((device_side, worker))
    }

    async fn pump_bytes(
        &mut self,
        media_side: tokio::io::DuplexStream,
    ) -> Result<(), BootstrapError> {
        use aegis_webrtc::sfu_media::{FrameKind, ReceivedFrame};
        let (mut outbound, mut inbound) = tokio::io::split(media_side);
        let mut buf = [0u8; 42];
        // (original sealed wire, kind, sequence, retry deadline, retry count)
        let mut pending: Option<([u8; 64], FrameKind, u32, tokio::time::Instant, u8)> = None;
        let mut outbound_eof = false;
        let mut inbound_eof = false;
        let mut fin_acked = false;
        let remote_sid = self
            .remote_sid
            .clone()
            .ok_or(BootstrapError::Configuration)?;
        let counterpart_identity = self.counterpart_identity.clone();
        let mut post_ready_notices = 0usize;
        let mut heartbeat = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_secs(2),
            Duration::from_secs(2),
        );
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        while tokio::time::Instant::now() < self.deadline {
            if outbound_eof && inbound_eof && fin_acked && pending.is_none() {
                return Ok(());
            }
            let retry_at = pending.as_ref().map_or(self.deadline, |p| p.3);
            tokio::select! {
                received = self.peer.receive_frame(&remote_sid, &counterpart_identity) => {
                    match received.map_err(|_| BootstrapError::Configuration)? {
                        ReceivedFrame::Fresh(frame) => match frame.kind() {
                            FrameKind::Data if !inbound_eof => {
                                tokio::time::timeout_at(self.deadline, inbound.write_all(frame.payload())).await
                                    .map_err(|_| BootstrapError::Configuration)?
                                    .map_err(|_| BootstrapError::Configuration)?;
                                let _ = self.send_frame(FrameKind::Ack, &frame.sequence().to_be_bytes()).await?;
                            }
                            FrameKind::Ack => {
                                if frame.payload().len() != 4 { return Err(BootstrapError::Configuration); }
                                let ack = u32::from_be_bytes(frame.payload().try_into().map_err(|_| BootstrapError::Configuration)?);
                                if pending.as_ref().is_some_and(|p| p.1 == FrameKind::Data && p.2 == ack) {
                                    pending = None;
                                }
                            }
                            FrameKind::Fin if !inbound_eof => {
                                inbound_eof = true;
                                tokio::time::timeout_at(self.deadline, inbound.shutdown()).await
                                    .map_err(|_| BootstrapError::Configuration)?
                                    .map_err(|_| BootstrapError::Configuration)?;
                                let _ = self.send_frame(FrameKind::FinAck, &frame.sequence().to_be_bytes()).await?;
                            }
                            FrameKind::FinAck => {
                                if frame.payload().len() != 4 { return Err(BootstrapError::Configuration); }
                                let ack = u32::from_be_bytes(frame.payload().try_into().map_err(|_| BootstrapError::Configuration)?);
                                if pending.as_ref().is_some_and(|p| p.1 == FrameKind::Fin && p.2 == ack) {
                                    pending = None;
                                    fin_acked = true;
                                }
                            }
                            FrameKind::KeepAlive if frame.payload().is_empty() => {}
                            _ => return Err(BootstrapError::Configuration),
                        },
                        ReceivedFrame::Duplicate { kind, sequence }
                            if matches!(kind, FrameKind::Data | FrameKind::Fin) => {
                            let response = if kind == FrameKind::Data { FrameKind::Ack } else { FrameKind::FinAck };
                            let _ = self.send_frame(response, &sequence.to_be_bytes()).await?;
                        }
                        ReceivedFrame::Duplicate { .. } => {},
                        // The authenticated replay window has already
                        // rejected this old sequence. It cannot reach the
                        // inner TLS stream or trigger an ACK.
                        ReceivedFrame::Stale => {},
                    }
                }
                signal = self.socket.next() => {
                    let message = signal.ok_or(BootstrapError::Configuration)?
                        .map_err(|_| BootstrapError::Configuration)?;
                    let WsMessage::Binary(bytes) = message else {
                        return Err(BootstrapError::Configuration);
                    };
                    observe_ready_signal(&mut self.control_notices, &mut post_ready_notices,
                        decode_negotiation_signal(&bytes)?)?;
                }
                read = outbound.read(&mut buf), if pending.is_none() && !outbound_eof => {
                    let count = read.map_err(|_| BootstrapError::Configuration)?;
                    if count == 0 { outbound_eof = true; }
                    let kind = if count == 0 { FrameKind::Fin } else { FrameKind::Data };
                    let wire = self.send_frame(kind, &buf[..count]).await?;
                    let sequence = u32::from_be_bytes(wire[1..5].try_into().map_err(|_| BootstrapError::Configuration)?);
                    pending = Some((wire, kind, sequence, tokio::time::Instant::now() + Duration::from_millis(500), 0));
                }
                _ = heartbeat.tick() => {
                    // A silent TCP application still publishes authenticated
                    // media. This does not grant a new target or renew expiry.
                    let _ = self.send_frame(FrameKind::KeepAlive, &[]).await?;
                }
                _ = tokio::time::sleep_until(retry_at), if pending.is_some() => {
                    let item = pending.as_mut().ok_or(BootstrapError::Configuration)?;
                    if item.4 >= 3 { return Err(BootstrapError::Configuration); }
                    self.retransmit(&item.0).await?;
                    item.4 += 1;
                    item.3 = tokio::time::Instant::now() + Duration::from_millis(500);
                }
            }
        }
        Err(BootstrapError::Configuration)
    }

    /// The broker/media key proves only media custody. The existing inner
    /// device TLS registry, revocation, lease and target authorization are
    /// still executed by the ordinary server path before target resolution.
    /// The SFU address is not attributed to the enrolled device for IP bans.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn serve_inner_tls(
        self,
        server: aegis_core::secure_channel::Server,
        policy: &crate::config::TargetPolicyConfig,
        rate_limiter: &crate::rate_limit::RateLimiter,
        privacy: Option<&aegis_core::carrier_runtime::PrivacySettings>,
        operational_log: crate::operational_log::OperationalLogPolicy,
    ) -> Result<(), BootstrapError> {
        let (carrier, mut worker) = self.into_inner_tls_carrier().await?;
        let admission = crate::session::serve_device_carrier_with_logging(
            carrier,
            server,
            policy,
            rate_limiter,
            None,
            || Ok(()),
            privacy,
            operational_log,
        )
        .await;
        if admission.is_err() {
            worker.abort();
            let _ = tokio::time::timeout(Duration::from_secs(2), &mut worker).await;
            return Err(BootstrapError::Configuration);
        }
        match tokio::time::timeout(Duration::from_secs(2), &mut worker).await {
            Ok(Ok(result)) => result,
            _ => {
                worker.abort();
                Err(BootstrapError::Configuration)
            }
        }
    }
}

impl std::fmt::Debug for IssuedMedia {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IssuedMedia([redacted])")
    }
}

fn bounded_ttl_seconds(remaining: Duration) -> Result<u64, BootstrapError> {
    let seconds = remaining.as_secs().min(30);
    if seconds == 0 {
        return Err(BootstrapError::Configuration);
    }
    Ok(seconds)
}

impl SfuBootstrap {
    /// Consume a broker-issued role and open LiveKit's signaling WebSocket
    /// through the exact pinned SFU TLS identity. No token is placed in a URL,
    /// error, or Debug output. No media track is published by this method.
    #[allow(dead_code)]
    pub async fn connect_authenticated_signal(
        &self,
        issued: IssuedMedia,
    ) -> Result<AuthenticatedSignal, BootstrapError> {
        self.connect_authenticated_signal_on_path(issued, None)
            .await
    }

    async fn connect_authenticated_signal_on_path(
        &self,
        issued: IssuedMedia,
        allowed_ips: Option<&[IpAddr]>,
    ) -> Result<AuthenticatedSignal, BootstrapError> {
        if issued.issuer_id != self.issuer_id || issued.descriptor.remaining_for_issuer().is_zero()
        {
            return Err(BootstrapError::Configuration);
        }
        let tls = self.dial_verified_wss_tls().await?;
        if let Some(allowed) = allowed_ips {
            let selected = tls
                .get_ref()
                .0
                .peer_addr()
                .map_err(|_| BootstrapError::Configuration)?
                .ip();
            if !allowed.contains(&selected) {
                return Err(BootstrapError::Configuration);
            }
        }
        let mut socket = self.upgrade_private_signal(tls, &issued).await?;
        Self::read_join(&mut socket, &issued.descriptor).await?;
        if issued.issuer_id != self.issuer_id || issued.descriptor.remaining_for_issuer().is_zero()
        {
            return Err(BootstrapError::Configuration);
        }
        Ok(AuthenticatedSignal {
            socket: Some(socket),
            descriptor: issued.descriptor,
            terminated: false,
        })
    }

    /// Form the secret-bearing upgrade in a zeroizing application buffer.
    /// The third-party handshake generator logs the fully serialized request
    /// at Trace and cannot be used with a bearer token.
    fn private_upgrade_request(
        &self,
        issued: &IssuedMedia,
    ) -> Result<(Zeroizing<Vec<u8>>, String), BootstrapError> {
        if issued.issuer_id != self.issuer_id || issued.descriptor.remaining_for_issuer().is_zero()
        {
            return Err(BootstrapError::Configuration);
        }
        let mut nonce = [0u8; 16];
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| BootstrapError::Configuration)?;
        let key = STANDARD.encode(nonce);
        let expected = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
        // Reserve the full bounded request before any bearer byte is copied.
        // Reallocation after appending the token could leave its old allocation
        // outside the zeroizing Vec's custody.
        let mut request = Zeroizing::new(Vec::with_capacity(MAX_UPGRADE_REQUEST));
        request.extend_from_slice(b"GET /rtc?protocol=9&sdk=rust&version=");
        request.extend_from_slice(env!("CARGO_PKG_VERSION").as_bytes());
        request.extend_from_slice(b" HTTP/1.1\r\nHost: ");
        let host = self
            .endpoint
            .host_str()
            .ok_or(BootstrapError::Configuration)?;
        request.extend_from_slice(host.as_bytes());
        if let Some(port) = self.endpoint.port() {
            request.push(b':');
            request.extend_from_slice(port.to_string().as_bytes());
        }
        request.extend_from_slice(b"\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ");
        request.extend_from_slice(key.as_bytes());
        request.extend_from_slice(b"\r\nAuthorization: Bearer ");
        if request
            .len()
            .checked_add(issued.token.len())
            .and_then(|len| len.checked_add(4))
            .filter(|&len| len <= MAX_UPGRADE_REQUEST)
            .is_none()
        {
            return Err(BootstrapError::Configuration);
        }
        request.extend_from_slice(issued.token.as_bytes());
        request.extend_from_slice(b"\r\n\r\n");
        if request.len() > MAX_UPGRADE_REQUEST {
            return Err(BootstrapError::Configuration);
        }
        Ok((request, expected))
    }

    async fn upgrade_private_signal<S>(
        &self,
        mut stream: S,
        issued: &IssuedMedia,
    ) -> Result<tokio_tungstenite::WebSocketStream<S>, BootstrapError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (request, expected) = self.private_upgrade_request(issued)?;
        let deadline = tokio::time::Instant::now() + SIGNAL_DEADLINE;
        tokio::time::timeout_at(deadline, stream.write_all(&request))
            .await
            .map_err(|_| BootstrapError::Configuration)?
            .map_err(|_| BootstrapError::Configuration)?;
        tokio::time::timeout_at(deadline, stream.flush())
            .await
            .map_err(|_| BootstrapError::Configuration)?
            .map_err(|_| BootstrapError::Configuration)?;
        drop(request);
        let mut response = [0u8; MAX_UPGRADE_HEADER];
        let mut used = 0usize;
        let header_end = loop {
            if let Some(end) = verify_upgrade_response(&response[..used], &expected)? {
                break end;
            }
            if used == response.len() {
                return Err(BootstrapError::Configuration);
            }
            let count = tokio::time::timeout_at(deadline, stream.read(&mut response[used..]))
                .await
                .map_err(|_| BootstrapError::Configuration)?
                .map_err(|_| BootstrapError::Configuration)?;
            if count == 0 {
                return Err(BootstrapError::Configuration);
            }
            used += count;
        };
        let config = WebSocketConfig {
            max_message_size: Some(MAX_SIGNAL_MESSAGE),
            max_frame_size: Some(MAX_SIGNAL_MESSAGE),
            max_write_buffer_size: MAX_SIGNAL_MESSAGE * 2,
            ..Default::default()
        };
        let trailing = response[header_end..used].to_vec();
        Ok(tokio_tungstenite::WebSocketStream::from_partially_read(
            stream,
            trailing,
            WsRole::Client,
            Some(config),
        )
        .await)
    }

    async fn read_join<S>(
        socket: &mut tokio_tungstenite::WebSocketStream<S>,
        descriptor: &ProvisionedSession,
    ) -> Result<(), BootstrapError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let frame = tokio::time::timeout(SIGNAL_DEADLINE, socket.next())
            .await
            .map_err(|_| BootstrapError::Configuration)?
            .ok_or(BootstrapError::Configuration)?
            .map_err(|_| BootstrapError::Configuration)?;
        match frame {
            WsMessage::Binary(bytes) => verify_join(&bytes, descriptor),
            _ => Err(BootstrapError::Configuration),
        }
    }

    /// Direct, bounded TLS to the configured self-hosted WSS origin. The
    /// private pinned root and exact DNS name are checked by rustls before a
    /// caller could send any token. This does not perform a WebSocket upgrade.
    #[allow(dead_code)]
    pub async fn dial_verified_wss_tls(
        &self,
    ) -> Result<TlsStream<tokio::net::TcpStream>, BootstrapError> {
        let host = self
            .endpoint
            .host_str()
            .ok_or(BootstrapError::Configuration)?;
        let port = self
            .endpoint
            .port_or_known_default()
            .ok_or(BootstrapError::Configuration)?;
        let stream = if let Some(addr) = self.connect_addr {
            tokio::time::timeout(TLS_DEADLINE, tokio::net::TcpStream::connect(addr))
                .await
                .map_err(|_| BootstrapError::Configuration)?
                .map_err(|_| BootstrapError::Configuration)?
        } else {
            tokio::time::timeout(TLS_DEADLINE, tokio::net::TcpStream::connect((host, port)))
                .await
                .map_err(|_| BootstrapError::Configuration)?
                .map_err(|_| BootstrapError::Configuration)?
        };
        self.verify_wss_tls(stream).await
    }

    /// Test seam for an already-connected stream. It retains the same pinned
    /// client configuration as the direct dialer and sends no bearer bytes.
    #[allow(dead_code)]
    async fn verify_wss_tls<S>(&self, stream: S) -> Result<TlsStream<S>, BootstrapError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let name = ServerName::try_from(self.tls_name.clone())
            .map_err(|_| BootstrapError::Configuration)?;
        tokio::time::timeout(
            TLS_DEADLINE,
            TlsConnector::from(self.client_tls.clone()).connect(name, stream),
        )
        .await
        .map_err(|_| BootstrapError::Configuration)?
        .map_err(|_| BootstrapError::Configuration)
    }

    /// Consume a broker-issued descriptor; never accept room, role or identity
    /// from the caller. The broker must have authenticated the role and claim.
    /// JWT issuance is not SFU one-use admission: replay remains possible until
    /// expiry, so the future transport still needs replay/room policy tests.
    #[allow(dead_code)]
    pub fn issue_for_authenticated_v1(
        &self,
        descriptor: ProvisionedSession,
    ) -> Result<IssuedMedia, BootstrapError> {
        // The production caller cannot choose or extend the token clock.
        let now = SystemTime::now();
        let seconds = bounded_ttl_seconds(descriptor.remaining_for_issuer())?;
        let issued = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| BootstrapError::Configuration)?
            .as_secs();
        let expires = issued
            .checked_add(seconds)
            .ok_or(BootstrapError::Configuration)?;
        let api_key =
            std::str::from_utf8(&self.api_key).map_err(|_| BootstrapError::Configuration)?;
        let identity = descriptor.identity_for_issuer();
        let payload = serde_json::json!({
            "iss": api_key,
            "sub": identity,
            "iat": issued,
            "nbf": issued,
            "exp": expires,
            "video": {
                "roomJoin": true,
                "room": descriptor.room_for_issuer(),
                "canPublish": true,
                "canSubscribe": true,
                "canPublishData": false,
                "canPublishSources": ["camera"],
                "canUpdateOwnMetadata": false
            }
        });
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let body = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).map_err(|_| BootstrapError::Configuration)?);
        let signing_input = format!("{header}.{body}");
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.api_secret)
            .map_err(|_| BootstrapError::Configuration)?;
        mac.update(signing_input.as_bytes());
        let signature = Zeroizing::new(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()));
        let token = Zeroizing::new(format!("{signing_input}.{}", signature.as_str()));
        Ok(IssuedMedia {
            token,
            descriptor,
            issuer_id: self.issuer_id,
        })
    }
}

impl std::fmt::Debug for SfuBootstrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SfuBootstrap([redacted])")
    }
}

#[cfg(feature = "sfu-media-vp8")]
impl aegis_webrtc::MediaGrantIssuer for SfuBootstrap {
    fn issue_client(
        &self,
        descriptor: ProvisionedSession,
    ) -> aegis_webrtc::Result<aegis_webrtc::sfu_media::ProtectedMediaGrant> {
        let issued = self
            .issue_for_authenticated_v1(descriptor)
            .map_err(|_| aegis_webrtc::Error::Signaling)?;
        issued
            .descriptor
            .into_protected_client_grant(issued.token)
            .map_err(|_| aegis_webrtc::Error::Signaling)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error("SFU bootstrap configuration rejected")]
    Configuration,
}

fn name_ok(name: &str) -> bool {
    if name.len() > 253 || name.is_empty() || !name.is_ascii() || name != name.to_ascii_lowercase()
    {
        return false;
    }
    if name.parse::<IpAddr>().is_ok() || !name.contains('.') {
        return false;
    }
    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    })
}

fn path_ok(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|part| !matches!(part, Component::CurDir | Component::ParentDir))
}

fn line(raw: &[u8], min: usize, max: usize) -> Result<&[u8], BootstrapError> {
    let value = raw.strip_suffix(b"\n").unwrap_or(raw);
    if !(min..=max).contains(&value.len()) || value.iter().any(|b| !b.is_ascii_graphic()) {
        return Err(BootstrapError::Configuration);
    }
    Ok(value)
}

impl SfuBootstrapSettings {
    /// Read only through Aegis's descriptor-checked secret-file owner. The
    /// exact endpoint TLS name still has to be checked by the future dialer.
    pub fn load(&self) -> Result<SfuBootstrap, BootstrapError> {
        if !name_ok(&self.tls_name)
            || !path_ok(&self.api_key_file)
            || !path_ok(&self.api_secret_file)
            || !path_ok(&self.tls_root_der_file)
            || self.api_key_file == self.api_secret_file
            || self.api_key_file == self.tls_root_der_file
            || self.api_secret_file == self.tls_root_der_file
        {
            return Err(BootstrapError::Configuration);
        }
        let endpoint = Url::parse(&self.endpoint).map_err(|_| BootstrapError::Configuration)?;
        if endpoint.scheme() != "wss"
            || endpoint.host_str() != Some(self.tls_name.as_str())
            || endpoint.username() != ""
            || endpoint.password().is_some()
            || endpoint.path() != "/"
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.origin().ascii_serialization() != self.endpoint
            || self.connect_addr.is_some_and(|addr| {
                !addr.ip().is_loopback() || Some(addr.port()) != endpoint.port_or_known_default()
            })
        {
            return Err(BootstrapError::Configuration);
        }
        aegis_core::secret_file::trusted_read_parent(&self.api_key_file)
            .map_err(|_| BootstrapError::Configuration)?;
        aegis_core::secret_file::trusted_read_parent(&self.api_secret_file)
            .map_err(|_| BootstrapError::Configuration)?;
        aegis_core::secret_file::trusted_read_parent(&self.tls_root_der_file)
            .map_err(|_| BootstrapError::Configuration)?;
        let mut api_key = aegis_core::secret_file::read(&self.api_key_file, (MAX_KEY + 2) as u64)
            .map_err(|_| BootstrapError::Configuration)?;
        let mut api_secret =
            aegis_core::secret_file::read(&self.api_secret_file, (MAX_SECRET + 2) as u64)
                .map_err(|_| BootstrapError::Configuration)?;
        let root_der = aegis_core::secret_file::read(&self.tls_root_der_file, MAX_ROOT_DER as u64)
            .map_err(|_| BootstrapError::Configuration)?;
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(root_der.to_vec()))
            .map_err(|_| BootstrapError::Configuration)?;
        let mut client_tls =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|_| BootstrapError::Configuration)?
                .with_root_certificates(roots)
                .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let key_len = line(&api_key, 8, MAX_KEY)?.len();
        let secret_len = line(&api_secret, 32, MAX_SECRET)?.len();
        api_key.truncate(key_len);
        api_secret.truncate(secret_len);
        if *api_key == *api_secret {
            return Err(BootstrapError::Configuration);
        }
        let mut issuer_id = [0u8; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut issuer_id)
            .map_err(|_| BootstrapError::Configuration)?;
        Ok(SfuBootstrap {
            endpoint,
            tls_name: self.tls_name.clone(),
            connect_addr: self.connect_addr,
            api_key,
            api_secret,
            client_tls: Arc::new(client_tls),
            issuer_id,
        })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[cfg(feature = "sfu-media-vp8")]
    #[test]
    fn permission_notice_is_typed_but_not_media_readiness() {
        let mut payload = vec![0x0a, 9];
        payload.extend_from_slice(b"PA_remote");
        payload.extend_from_slice(&[0x12, 9]);
        payload.extend_from_slice(b"TR_remote");
        payload.extend_from_slice(&[0x18, 1]);
        let mut frame = vec![0x7a, payload.len() as u8];
        frame.extend_from_slice(&payload);
        assert!(matches!(
            decode_negotiation_signal(&frame).unwrap(),
            NegotiationSignal::ControlNotice(_)
        ));
        frame[0] = 0x78;
        assert!(decode_negotiation_signal(&frame).is_err());
    }

    #[cfg(feature = "sfu-media-vp8")]
    #[test]
    fn ready_signaling_bounds_refresh_and_closes_on_permission_change() {
        let mut window = aegis_webrtc::sfu_peer::SfuControlNoticeWindow::default();
        window.bind_remote("PA_remote", "TR_remote").unwrap();
        let refresh = b"header.payload.signature";
        let mut frame = vec![0x82, 0x01, refresh.len() as u8];
        frame.extend_from_slice(refresh);
        let mut count = 0;
        for _ in 0..32 {
            observe_ready_signal(
                &mut window,
                &mut count,
                decode_negotiation_signal(&frame).unwrap(),
            )
            .unwrap();
        }
        assert!(observe_ready_signal(
            &mut window,
            &mut count,
            decode_negotiation_signal(&frame).unwrap()
        )
        .is_err());

        let mut permission = vec![0x7a, 24, 0x0a, 9];
        permission.extend_from_slice(b"PA_remote");
        permission.extend_from_slice(&[0x12, 9]);
        permission.extend_from_slice(b"TR_remote");
        permission.extend_from_slice(&[0x18, 1]);
        let mut count = 0;
        observe_ready_signal(
            &mut window,
            &mut count,
            decode_negotiation_signal(&permission).unwrap(),
        )
        .unwrap();
        assert!(observe_ready_signal(
            &mut window,
            &mut count,
            decode_negotiation_signal(&permission).unwrap()
        )
        .is_err());
        let mut wrong = permission.clone();
        wrong[7] = b'f';
        let mut fresh = aegis_webrtc::sfu_peer::SfuControlNoticeWindow::default();
        fresh.bind_remote("PA_remote", "TR_remote").unwrap();
        let mut count = 0;
        assert!(observe_ready_signal(
            &mut fresh,
            &mut count,
            decode_negotiation_signal(&wrong).unwrap()
        )
        .is_err());
        let last = permission.len() - 1;
        permission[last] = 0;
        assert!(decode_negotiation_signal(&permission).is_err());
    }
    use futures::SinkExt;
    use rcgen::generate_simple_self_signed;
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
        pin::Pin,
        sync::atomic::{AtomicBool, Ordering},
        task::{Context, Poll},
    };
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio_tungstenite::tungstenite::{
        client::IntoClientRequest,
        http::{header::AUTHORIZATION, HeaderValue},
    };

    struct StallWrite<S> {
        inner: S,
        stalled: Arc<AtomicBool>,
        dropped: Arc<AtomicBool>,
    }

    impl<S> Drop for StallWrite<S> {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    impl<S: AsyncRead + Unpin> AsyncRead for StallWrite<S> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for StallWrite<S> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.stalled.load(Ordering::SeqCst) {
                Poll::Pending
            } else {
                Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
            }
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            if self.stalled.load(Ordering::SeqCst) {
                Poll::Pending
            } else {
                Pin::new(&mut self.get_mut().inner).poll_flush(cx)
            }
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            if self.stalled.load(Ordering::SeqCst) {
                Poll::Pending
            } else {
                Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
            }
        }
    }

    fn fixture() -> (tempfile::TempDir, SfuBootstrapSettings) {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("api-key");
        let secret = dir.path().join("api-secret");
        let root = dir.path().join("tls-root.der");
        let cert = generate_simple_self_signed(vec!["sfu.example.org".into()]).unwrap();
        fs::write(&root, cert.cert.der().as_ref()).unwrap();
        fs::write(&key, b"fixture_key_12345\n").unwrap();
        fs::write(
            &secret,
            b"fixture_secret_abcdefghijklmnopqrstuvwxyz_123456\n",
        )
        .unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o600)).unwrap();
        (
            dir,
            SfuBootstrapSettings {
                endpoint: "wss://sfu.example.org".into(),
                tls_name: "sfu.example.org".into(),
                connect_addr: None,
                api_key_file: key,
                api_secret_file: secret,
                tls_root_der_file: root,
            },
        )
    }

    fn encoded_join(room: &str, identity: &str, alternative_url: &str) -> Vec<u8> {
        let join = JoinResponseView {
            room: Some(RoomView {
                sid: "RM_fixture".into(),
                name: room.into(),
            }),
            participant: Some(ParticipantView {
                sid: "PA_fixture".into(),
                identity: identity.into(),
            }),
            alternative_url: alternative_url.into(),
        };
        let payload = join.encode_to_vec();
        let mut response = vec![0x0a];
        let mut remaining = payload.len();
        while remaining >= 0x80 {
            response.push((remaining as u8 & 0x7f) | 0x80);
            remaining >>= 7;
        }
        response.push(remaining as u8);
        response.extend(payload);
        response
    }

    fn encoded_signal(tag: u8, payload: &[u8]) -> Vec<u8> {
        let mut response = vec![tag];
        let mut remaining = payload.len();
        while remaining >= 0x80 {
            response.push((remaining as u8 & 0x7f) | 0x80);
            remaining >>= 7;
        }
        response.push(remaining as u8);
        response.extend_from_slice(payload);
        response
    }

    #[test]
    fn refresh_notice_is_bounded_typed_and_cannot_change_authorization() {
        fn refresh_frame(payload: &[u8]) -> Vec<u8> {
            let mut response = vec![0x82, 0x01];
            let mut remaining = payload.len();
            while remaining >= 0x80 {
                response.push((remaining as u8 & 0x7f) | 0x80);
                remaining >>= 7;
            }
            response.push(remaining as u8);
            response.extend_from_slice(payload);
            response
        }
        let valid = refresh_frame(b"header.payload.signature");
        let decoded = decode_negotiation_signal(&valid).unwrap();
        assert!(matches!(&decoded, NegotiationSignal::RefreshToken));
        assert_eq!(format!("{decoded:?}"), "NegotiationSignal([redacted])");
        for invalid in [
            refresh_frame(b""),
            refresh_frame(&[0xff]),
            refresh_frame(b"header payload"),
            refresh_frame(&vec![b'a'; 4097]),
            [valid.clone(), valid.clone()].concat(),
            vec![0x80, 0x01, 0x01, b'x'], // field 16, wrong wire type
            vec![0x82, 0x81, 0x00, 0x01, b'x'], // noncanonical key
            vec![0x8a, 0x01, 0x01, b'x'], // unknown field 17
        ] {
            assert!(decode_negotiation_signal(&invalid).is_err());
        }
        // Every other official SignalResponse field remains fail closed.
        for field in (1..=31).filter(|field| !matches!(*field, 2..=6 | 8 | 16)) {
            let key = field * 8 + 2;
            let mut frame = if key < 128 {
                vec![key as u8]
            } else {
                vec![(key as u8 & 0x7f) | 0x80, (key >> 7) as u8]
            };
            frame.extend_from_slice(&[1, b'x']);
            assert!(decode_negotiation_signal(&frame).is_err(), "field {field}");
        }
        assert!(matches!(
            decode_negotiation_signal(&[0x42, 0x00]),
            Ok(NegotiationSignal::Leave)
        ));
        assert!(decode_negotiation_signal(&[0x42, 0x02, 0x18, 0x01]).is_err());
    }

    #[test]
    fn negotiation_signal_is_single_bounded_redacted_and_never_media_ready() {
        let answer = encoded_signal(
            0x12,
            &SessionDescriptionView {
                kind: "answer".into(),
                sdp: "v=0\r\na=mid:0\r\n".into(),
                ..Default::default()
            }
            .encode_to_vec(),
        );
        let offer = encoded_signal(
            0x1a,
            &SessionDescriptionView {
                kind: "offer".into(),
                sdp: "v=0\r\na=mid:1\r\n".into(),
                id: 11,
                mid_to_track_id: HashMap::from([("1".into(), "TR_approved".into())]),
            }
            .encode_to_vec(),
        );
        assert!(matches!(
            decode_negotiation_signal(&answer).unwrap(),
            NegotiationSignal::PublisherAnswer(_)
        ));
        match decode_negotiation_signal(&offer).unwrap() {
            NegotiationSignal::SubscriberOffer {
                id,
                mid_to_track_id,
                ..
            } => {
                assert_eq!(id, 11);
                assert_eq!(
                    mid_to_track_id.get("1").map(String::as_str),
                    Some("TR_approved")
                );
            }
            _ => panic!("wrong signal kind"),
        }
        let trickle = encoded_signal(
            0x22,
            &TrickleView {
                candidate_init: r#"{"candidate":"candidate:1 1 udp 1 127.0.0.1 7777 typ host"}"#
                    .into(),
                target: 0,
                final_candidate: false,
            }
            .encode_to_vec(),
        );
        let event = decode_negotiation_signal(&trickle).unwrap();
        assert_eq!(format!("{event:?}"), "NegotiationSignal([redacted])");
        assert!(matches!(
            event,
            NegotiationSignal::Trickle {
                target: 0,
                final_candidate: false,
                ..
            }
        ));
        assert!(matches!(
            decode_negotiation_signal(&[0x42, 0]).unwrap(),
            NegotiationSignal::Leave
        ));
        let mut duplicate = offer.clone();
        duplicate.extend_from_slice(&answer);
        assert!(decode_negotiation_signal(&duplicate).is_err());
        assert!(decode_negotiation_signal(&[0x0a, 0]).is_err());
        assert!(decode_negotiation_signal(&vec![0x12; MAX_SIGNAL_MESSAGE + 1]).is_err());
        assert!(decode_negotiation_signal(&encoded_signal(
            0x12,
            &SessionDescriptionView {
                kind: "offer".into(),
                sdp: "v=0\r\n".into(),
                ..Default::default()
            }
            .encode_to_vec(),
        ))
        .is_err());
        assert!(decode_negotiation_signal(&encoded_signal(
            0x22,
            &TrickleView {
                candidate_init: "{}".into(),
                target: 0,
                final_candidate: false
            }
            .encode_to_vec(),
        ))
        .is_err());
        assert!(decode_negotiation_signal(&encoded_signal(
            0x22,
            &TrickleView {
                candidate_init: String::new(),
                target: 2,
                final_candidate: true
            }
            .encode_to_vec(),
        ))
        .is_err());
    }

    #[test]
    fn leave_action_requires_fresh_authorization_and_rejects_ambiguous_payloads() {
        let leave = |payload: &[u8]| decode_negotiation_signal(&encoded_signal(0x42, payload));
        assert!(matches!(leave(&[]).unwrap(), NegotiationSignal::Leave));
        assert!(matches!(
            leave(&[0x10, 0x03, 0x18, 0x00]).unwrap(),
            NegotiationSignal::Leave
        ));
        // A legacy reconnect hint, RESUME and RECONNECT are all terminal
        // refusals until a newly authorized descriptor is issued and bound.
        for payload in [
            &[0x08, 0x01][..],
            &[0x18, 0x01],
            &[0x18, 0x02],
            &[0x18, 0x03],
            &[0x18, 0x01, 0x18, 0x00],
            &[0x18],
            &[0x18, 0x80, 0x00],
            &[0x18, 0x80, 0x80, 0x80, 0x80, 0x80],
            &[0x20, 0x00],
            &[0x22, 0x00], // regions need location revalidation
            &[0x10, 0x11], // unknown disconnect reason
            &[0x08, 0x02], // invalid bool
        ] {
            assert!(
                leave(payload).is_err(),
                "accepted leave payload {payload:?}"
            );
        }
    }

    async fn fixture_tls_handshake(
        bootstrap: &SfuBootstrap,
        certified: rcgen::CertifiedKey,
    ) -> bool {
        use rustls::{pki_types::PrivateKeyDer, ServerConfig};
        use tokio_rustls::TlsAcceptor;

        let server =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![certified.cert.der().clone()],
                    PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into()),
                )
                .unwrap();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let accept = TlsAcceptor::from(Arc::new(server));
        let (client, server) = tokio::join!(
            bootstrap.verify_wss_tls(client_io),
            tokio::time::timeout(TLS_DEADLINE, accept.accept(server_io))
        );
        client.is_ok() && server.is_ok_and(|result| result.is_ok())
    }

    #[tokio::test]
    async fn pinned_self_hosted_tls_accepts_only_exact_root_and_dns_name() {
        let (_dir, input) = fixture();
        let certified = generate_simple_self_signed(vec!["sfu.example.org".into()]).unwrap();
        fs::write(&input.tls_root_der_file, certified.cert.der().as_ref()).unwrap();
        let bootstrap = input.load().unwrap();
        assert!(fixture_tls_handshake(&bootstrap, certified).await);

        let attacker = generate_simple_self_signed(vec!["sfu.example.org".into()]).unwrap();
        assert!(!fixture_tls_handshake(&bootstrap, attacker).await);

        let wrong_name = generate_simple_self_signed(vec!["other.example.org".into()]).unwrap();
        fs::write(&input.tls_root_der_file, wrong_name.cert.der().as_ref()).unwrap();
        let wrong_name_bootstrap = input.load().unwrap();
        assert!(!fixture_tls_handshake(&wrong_name_bootstrap, wrong_name).await);
    }

    #[test]
    fn actual_private_reader_accepts_exact_files_and_redacts() {
        let (_dir, input) = fixture();
        let value = input.load().unwrap();
        assert_eq!(value.endpoint.as_str(), "wss://sfu.example.org/");
        assert_eq!(value.tls_name, "sfu.example.org");
        assert_eq!(&value.api_key[..], b"fixture_key_12345");
        assert!(value.api_secret.len() >= 32);
        assert_eq!(format!("{value:?}"), "SfuBootstrap([redacted])");
    }

    #[test]
    fn numeric_loopback_dial_keeps_exact_wss_dns_and_port() {
        let (_dir, mut input) = fixture();
        input.endpoint = "wss://sfu.example.org:18443".into();
        input.connect_addr = Some("[::1]:18443".parse().unwrap());
        let value = input.load().unwrap();
        assert_eq!(value.endpoint.host_str(), Some("sfu.example.org"));
        assert_eq!(value.tls_name, "sfu.example.org");
        assert_eq!(value.connect_addr, input.connect_addr);

        for bad in ["[::1]:18444", "192.0.2.1:18443", "[2001:db8::1]:18443"] {
            input.connect_addr = Some(bad.parse().unwrap());
            assert!(input.load().is_err(), "{bad}");
        }
        input.connect_addr = None;
        assert!(input.load().is_ok());
    }

    #[test]
    fn exact_origin_and_name_reject_ambiguous_or_untrusted_inputs() {
        let (_dir, mut input) = fixture();
        for endpoint in [
            "https://sfu.example.org",
            "ws://sfu.example.org",
            "wss://other.example.org",
            "wss://user@sfu.example.org",
            "wss://sfu.example.org/room",
            "wss://sfu.example.org?token=x",
            "wss://sfu.example.org#part",
            "wss://sfu.example.org/",
            "wss://sfu.example.org:443",
            "wss://127.0.0.1",
            "wss://sfu.example.org.evil.test",
        ] {
            input.endpoint = endpoint.into();
            assert!(input.load().is_err(), "{endpoint}");
        }
        input.endpoint = "wss://sfu.example.org".into();
        for name in [
            "*.example.org",
            "SFU.example.org",
            "sfu_example.org",
            "sfu.example.org.",
            "localhost",
            "127.0.0.1",
        ] {
            input.tls_name = name.into();
            assert!(input.load().is_err(), "{name}");
        }
    }

    #[test]
    fn actual_reader_refuses_unsafe_path_mode_symlink_and_content() {
        let (dir, mut input) = fixture();
        let secret = input.api_secret_file.clone();
        input.api_secret_file = PathBuf::from("relative/secret");
        assert!(input.load().is_err());
        input.api_secret_file = dir.path().join("../other");
        assert!(input.load().is_err());
        input.api_secret_file = input.api_key_file.clone();
        assert!(input.load().is_err());
        input.api_secret_file = secret.clone();
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(input.load().is_err());
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("api-secret-link");
        symlink(&secret, &link).unwrap();
        input.api_secret_file = link;
        assert!(input.load().is_err());
        input.api_secret_file = secret.clone();
        fs::write(&secret, b"secret-with-space 0123456789012345678901").unwrap();
        assert!(input.load().is_err());
        fs::write(&secret, vec![b's'; 257]).unwrap();
        assert!(input.load().is_err());
        fs::write(&secret, vec![b's'; 32]).unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(input.load().is_err());
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let root = input.tls_root_der_file.clone();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(input.load().is_err());
        fs::set_permissions(&root, fs::Permissions::from_mode(0o600)).unwrap();
        let root_link = dir.path().join("tls-root-link");
        symlink(&root, &root_link).unwrap();
        input.tls_root_der_file = root_link;
        assert!(input.load().is_err());
        input.tls_root_der_file = root.clone();
        fs::write(&root, b"not a certificate").unwrap();
        assert!(input.load().is_err());
        let cert = generate_simple_self_signed(vec!["sfu.example.org".into()]).unwrap();
        fs::write(&root, cert.cert.der().as_ref()).unwrap();
        assert!(input.load().is_ok());
    }

    #[tokio::test]
    async fn broker_role_and_claim_gate_private_token_issuer() {
        use aegis_webrtc::{
            AdmissionKey, BrokerLimits, Operation, OwnedBroker, Role, Signal, Signaling,
            SignalingReply, SignalingRequest,
        };
        use tokio::time::{Duration, Instant};

        let (_dir, input) = fixture();
        let certified = generate_simple_self_signed(vec!["sfu.example.org".into()]).unwrap();
        fs::write(&input.tls_root_der_file, certified.cert.der().as_ref()).unwrap();
        let issuer = input.load().unwrap();
        let client_key = AdmissionKey::from_bytes([11; 32]).unwrap();
        let intermediary_key = AdmissionKey::from_bytes([12; 32]).unwrap();
        let wrong_key = AdmissionKey::from_bytes([13; 32]).unwrap();
        let broker = OwnedBroker::new(
            client_key.clone(),
            intermediary_key.clone(),
            BrokerLimits::default(),
        )
        .unwrap();
        let transaction = MediaTransaction::new(&broker, &issuer);
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
            panic!("submit refused")
        };
        let SignalingReply::Offer { claim, .. } = broker
            .exchange(
                SignalingRequest::new(
                    Role::Intermediary,
                    intermediary_key.clone(),
                    Operation::Take,
                ),
                deadline,
            )
            .await
            .unwrap()
        else {
            panic!("claim refused")
        };
        assert!(transaction
            .start(
                &wrong_key,
                session,
                claim,
                Signal::answer("v=0".into()).unwrap(),
            )
            .is_err());
        assert!(transaction
            .take(Role::Client, &client_key, session, None)
            .is_err());
        transaction
            .start(
                &intermediary_key,
                session,
                claim,
                Signal::answer("v=0".into()).unwrap(),
            )
            .unwrap();
        assert!(transaction
            .start(
                &intermediary_key,
                session,
                claim,
                Signal::answer("v=0".into()).unwrap(),
            )
            .is_err());
        assert!(transaction
            .take(Role::Client, &wrong_key, session, None)
            .is_err());
        assert!(transaction
            .take(Role::Intermediary, &intermediary_key, session, None)
            .is_err());
        let issued = transaction
            .take(Role::Client, &client_key, session, None)
            .unwrap();
        assert!(transaction
            .take(Role::Client, &client_key, session, None)
            .is_err());
        assert_eq!(format!("{issued:?}"), "IssuedMedia([redacted])");
        let (request, _) = issuer.private_upgrade_request(&issued).unwrap();
        let other_issuer = input.load().unwrap();
        assert!(other_issuer.private_upgrade_request(&issued).is_err());
        let first_line = request.split(|byte| *byte == b'\n').next().unwrap();
        assert!(first_line.starts_with(b"GET /rtc?protocol=9&sdk=rust&version="));
        assert!(!first_line
            .windows(issued.token.len())
            .any(|w| w == issued.token.as_bytes()));
        assert!(request
            .windows(issued.token.len())
            .any(|w| w == issued.token.as_bytes()));
        drop(request);
        use rustls::{pki_types::PrivateKeyDer, ServerConfig};
        use tokio_rustls::TlsAcceptor;
        let server_tls =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![certified.cert.der().clone()],
                    PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into()),
                )
                .unwrap();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let accept = TlsAcceptor::from(Arc::new(server_tls));
        let expected = format!("Bearer {}", issued.token.as_str());
        let expected_room = issued.descriptor.room_for_issuer().to_owned();
        let expected_identity = issued.descriptor.identity_for_issuer().to_owned();
        let joined = encoded_join(&expected_room, &expected_identity, "");
        assert!(verify_join(&joined, &issued.descriptor).is_ok());
        assert!(verify_join(
            &encoded_join("wrong-room", &expected_identity, ""),
            &issued.descriptor
        )
        .is_err());
        assert!(verify_join(
            &encoded_join(&expected_room, "wrong-identity", ""),
            &issued.descriptor
        )
        .is_err());
        assert!(verify_join(
            &encoded_join(&expected_room, &expected_identity, "wss://attacker.invalid"),
            &issued.descriptor
        )
        .is_err());
        assert!(verify_join(&[], &issued.descriptor).is_err());
        assert!(verify_join(&[0x12, 0x00], &issued.descriptor).is_err());
        let mut extra_oneof = joined.clone();
        extra_oneof.extend([0x12, 0x00]);
        assert!(verify_join(&extra_oneof, &issued.descriptor).is_err());
        assert!(verify_join(&vec![0x0a; MAX_JOIN_MESSAGE + 1], &issued.descriptor).is_err());
        let (client_result, server_result) = tokio::time::timeout(TLS_DEADLINE, async {
            tokio::join!(
                async {
                    let tls = issuer.verify_wss_tls(client_io).await.unwrap();
                    let mut socket = issuer.upgrade_private_signal(tls, &issued).await.unwrap();
                    SfuBootstrap::read_join(&mut socket, &issued.descriptor).await.is_ok()
                },
                async {
                    let tls = accept.accept(server_io).await.unwrap();
                    let mut socket = tokio_tungstenite::accept_hdr_async_with_config(
                        tls,
                        #[expect(
                            clippy::result_large_err,
                            reason = "tungstenite's required handshake callback returns its large ErrorResponse type"
                        )]
                        move |request: &tokio_tungstenite::tungstenite::handshake::server::Request,
                              response: tokio_tungstenite::tungstenite::handshake::server::Response| {
                            assert_eq!(request.uri().path(), "/rtc");
                            assert_eq!(
                                request.uri().query(),
                                Some(concat!(
                                    "protocol=9&sdk=rust&version=",
                                    env!("CARGO_PKG_VERSION")
                                ))
                            );
                            assert!(!request.uri().to_string().contains("access_token"));
                            assert_eq!(
                                request.headers().get(AUTHORIZATION).unwrap().as_bytes(),
                                expected.as_bytes()
                            );
                            Ok(response)
                        },
                        Some(WebSocketConfig {
                            max_message_size: Some(MAX_SIGNAL_MESSAGE),
                            max_frame_size: Some(MAX_SIGNAL_MESSAGE),
                            ..Default::default()
                        }),
                    )
                    .await
                    .unwrap();
                    socket.send(WsMessage::Binary(joined)).await.is_ok()
                }
            )
        })
        .await
        .unwrap();
        assert!(client_result && server_result);
        assert!(issued.descriptor.identity_for_issuer().ends_with("_client"));
        let parts: Vec<_> = issued.token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["iss"], "fixture_key_12345");
        assert_eq!(claims["sub"], issued.descriptor.identity_for_issuer());
        assert_eq!(claims["video"]["room"], issued.descriptor.room_for_issuer());
        assert_eq!(claims["video"]["roomJoin"], true);
        assert_eq!(claims["video"]["canPublish"], true);
        assert_eq!(claims["video"]["canSubscribe"], true);
        assert_eq!(claims["video"]["canPublishData"], false);
        assert_eq!(
            claims["video"]["canPublishSources"],
            serde_json::json!(["camera"])
        );
        assert_eq!(claims["video"]["canUpdateOwnMetadata"], false);
        for forbidden in [
            "roomAdmin",
            "roomCreate",
            "roomList",
            "roomRecord",
            "ingressAdmin",
        ] {
            assert!(claims["video"].get(forbidden).is_none(), "{forbidden}");
        }
        assert!(claims.get("sip").is_none());
        assert_eq!(claims["nbf"], claims["iat"]);
        assert!(claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap() <= 30);
        let mut verifier = Hmac::<Sha256>::new_from_slice(&issuer.api_secret).unwrap();
        verifier.update(format!("{}.{}", parts[0], parts[1]).as_bytes());
        verifier
            .verify_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap())
            .unwrap();
        let second = transaction
            .take(Role::Intermediary, &intermediary_key, session, Some(claim))
            .unwrap();
        assert!(second
            .descriptor
            .identity_for_issuer()
            .ends_with("_intermediary"));
        assert_ne!(
            issued.descriptor.identity_for_issuer(),
            second.descriptor.identity_for_issuer()
        );
        assert_eq!(
            issued.descriptor.room_for_issuer(),
            second.descriptor.room_for_issuer()
        );
        assert!(transaction
            .take(Role::Intermediary, &intermediary_key, session, Some(claim))
            .is_err());

        // A signer failure after a valid take denies delivery and leaves that
        // role's broker descriptor spent, so retries cannot mint a second JWT.
        let SignalingReply::Submitted(failed_session) = broker
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
            panic!("second submit refused")
        };
        let SignalingReply::Offer {
            claim: failed_claim,
            ..
        } = broker
            .exchange(
                SignalingRequest::new(
                    Role::Intermediary,
                    intermediary_key.clone(),
                    Operation::Take,
                ),
                deadline,
            )
            .await
            .unwrap()
        else {
            panic!("second claim refused")
        };
        transaction
            .start(
                &intermediary_key,
                failed_session,
                failed_claim,
                Signal::answer("v=0".into()).unwrap(),
            )
            .unwrap();
        let (_bad_dir, bad_input) = fixture();
        let mut bad_issuer = bad_input.load().unwrap();
        bad_issuer.api_key = Zeroizing::new(vec![0xff]);
        let bad_transaction = MediaTransaction::new(&broker, &bad_issuer);
        assert!(matches!(
            bad_transaction.take(Role::Client, &client_key, failed_session, None),
            Err(MediaTransactionError::Issuer(BootstrapError::Configuration))
        ));
        assert!(transaction
            .take(Role::Client, &client_key, failed_session, None)
            .is_err());

        // The post-Join RESUME action must close the socket and permanently
        // consume this signal handle; it cannot trigger an implicit reconnect.
        let joined = encoded_join(
            issued.descriptor.room_for_issuer(),
            &issued.descriptor.identity_for_issuer(),
            "",
        );
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (client_socket, mut server_socket) = tokio::time::timeout(SIGNAL_DEADLINE, async {
            tokio::join!(
                async {
                    let mut socket = issuer
                        .upgrade_private_signal(client_io, &issued)
                        .await
                        .unwrap();
                    SfuBootstrap::read_join(&mut socket, &issued.descriptor)
                        .await
                        .unwrap();
                    socket
                },
                async {
                    let mut socket = tokio_tungstenite::accept_async(server_io).await.unwrap();
                    socket.send(WsMessage::Binary(joined)).await.unwrap();
                    socket
                        .send(WsMessage::Binary(encoded_signal(0x42, &[0x18, 0x01])))
                        .await
                        .unwrap();
                    socket
                }
            )
        })
        .await
        .unwrap();
        let mut signal = AuthenticatedSignal {
            socket: Some(client_socket),
            descriptor: issued.descriptor,
            terminated: false,
        };
        assert!(signal
            .read_next_negotiation(tokio::time::Instant::now() + SIGNAL_DEADLINE)
            .await
            .is_err());
        assert!(signal.terminated);
        assert!(signal.socket.is_none());
        assert!(signal
            .read_next_negotiation(tokio::time::Instant::now() + SIGNAL_DEADLINE)
            .await
            .is_err());
        assert!(matches!(
            tokio::time::timeout(SIGNAL_DEADLINE, server_socket.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            WsMessage::Close(_)
        ));

        // A peer can stop reading and make the Close write never complete.
        // The held transport must still be dropped after the close deadline.
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let stalled = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicBool::new(false));
        let watched_io = StallWrite {
            inner: client_io,
            stalled: Arc::clone(&stalled),
            dropped: Arc::clone(&dropped),
        };
        let mut client_socket = tokio_tungstenite::WebSocketStream::from_raw_socket(
            watched_io,
            tokio_tungstenite::tungstenite::protocol::Role::Client,
            None,
        )
        .await;
        let mut server_socket = tokio_tungstenite::WebSocketStream::from_raw_socket(
            server_io,
            tokio_tungstenite::tungstenite::protocol::Role::Server,
            None,
        )
        .await;
        server_socket
            .send(WsMessage::Binary(encoded_join(
                second.descriptor.room_for_issuer(),
                &second.descriptor.identity_for_issuer(),
                "",
            )))
            .await
            .unwrap();
        SfuBootstrap::read_join(&mut client_socket, &second.descriptor)
            .await
            .unwrap();
        server_socket
            .send(WsMessage::Binary(encoded_signal(0x42, &[0x18, 0x02])))
            .await
            .unwrap();
        stalled.store(true, Ordering::SeqCst);
        let mut signal = AuthenticatedSignal {
            socket: Some(client_socket),
            descriptor: second.descriptor,
            terminated: false,
        };
        let started = tokio::time::Instant::now();
        assert!(signal
            .read_next_negotiation(started + SIGNAL_DEADLINE)
            .await
            .is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(signal.terminated && signal.socket.is_none());
        assert!(dropped.load(Ordering::SeqCst));
        assert!(signal
            .read_next_negotiation(tokio::time::Instant::now() + SIGNAL_DEADLINE)
            .await
            .is_err());
    }

    #[test]
    fn expired_and_subsecond_descriptor_cannot_be_signed() {
        assert!(bounded_ttl_seconds(Duration::ZERO).is_err());
        assert!(bounded_ttl_seconds(Duration::from_millis(999)).is_err());
        assert_eq!(bounded_ttl_seconds(Duration::from_secs(1)).unwrap(), 1);
        assert_eq!(bounded_ttl_seconds(Duration::from_secs(31)).unwrap(), 30);
    }

    #[test]
    fn settings_schema_refuses_embedded_bearer_token() {
        let raw = serde_json::json!({
            "endpoint": "wss://sfu.example.org",
            "tls_name": "sfu.example.org",
            "api_key_file": "/private/owner/livekit-key",
            "api_secret_file": "/private/owner/livekit-secret",
            "room_token": "untrusted-token"
        });
        assert!(serde_json::from_value::<SfuBootstrapSettings>(raw).is_err());
    }

    #[tokio::test]
    async fn patched_dependency_trace_redacts_synthetic_bearer_and_frames() {
        fn contains_sentinel(logged: &str) -> bool {
            let logged = logged.to_ascii_lowercase();
            logged.contains("b08_test_sentinel_only")
                || logged.contains("4230385f544553545f53454e54494e454c5f4f4e4c59")
        }
        assert!(contains_sentinel("B08_TEST_SENTINEL_ONLY"));
        assert!(contains_sentinel(
            "payload: 4230385F544553545F53454E54494E454C5F4F4E4C59"
        ));
        struct Capture;
        static CAPTURE: Capture = Capture;
        static SAW_MARKER: AtomicBool = AtomicBool::new(false);
        static SAW_TRACE: AtomicBool = AtomicBool::new(false);
        impl log::Log for Capture {
            fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
                metadata.level() <= log::Level::Trace
            }
            fn log(&self, record: &log::Record<'_>) {
                if self.enabled(record.metadata()) && record.target().contains("tungstenite") {
                    SAW_TRACE.store(true, Ordering::SeqCst);
                    if contains_sentinel(&record.args().to_string()) {
                        SAW_MARKER.store(true, Ordering::SeqCst);
                    }
                }
            }
            fn flush(&self) {}
        }
        log::set_logger(&CAPTURE).unwrap();
        log::set_max_level(log::LevelFilter::Trace);
        let mut request = "wss://sfu.example.org/rtc".into_client_request().unwrap();
        let mut bearer = HeaderValue::from_static("Bearer B08_TEST_SENTINEL_ONLY");
        bearer.set_sensitive(true);
        assert!(!format!("{bearer:?}").contains("B08_TEST_SENTINEL_ONLY"));
        request.headers_mut().insert(AUTHORIZATION, bearer);
        let _ =
            tokio_tungstenite::tungstenite::handshake::client::generate_request(request).unwrap();
        let (client_io, server_io) = tokio::io::duplex(8192);
        let mut client =
            tokio_tungstenite::WebSocketStream::from_raw_socket(client_io, WsRole::Client, None)
                .await;
        let mut server =
            tokio_tungstenite::WebSocketStream::from_raw_socket(server_io, WsRole::Server, None)
                .await;
        client
            .send(WsMessage::Binary(b"B08_TEST_SENTINEL_ONLY".to_vec()))
            .await
            .unwrap();
        assert!(matches!(
            server.next().await,
            Some(Ok(WsMessage::Binary(_)))
        ));
        assert!(SAW_TRACE.load(Ordering::SeqCst));
        assert!(!SAW_MARKER.load(Ordering::SeqCst));
    }

    #[test]
    fn private_upgrade_response_requires_exact_bounded_websocket_acceptance() {
        let good = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Accept: expected\r\n\r\n";
        assert_eq!(
            verify_upgrade_response(&good[..good.len() - 1], "expected").unwrap(),
            None
        );
        assert_eq!(
            verify_upgrade_response(good, "expected").unwrap(),
            Some(good.len())
        );
        let mut combined = good.to_vec();
        combined.extend_from_slice(b"\x81\x00");
        assert_eq!(
            verify_upgrade_response(&combined, "expected").unwrap(),
            Some(good.len())
        );
        for bad in [
            "HTTP/1.0 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: expected\r\n\r\n",
            "HTTP/1.1 200 OK\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: expected\r\n\r\n",
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: expected\r\n\r\n",
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: keep-alive\r\nSec-WebSocket-Accept: expected\r\n\r\n",
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: wrong\r\n\r\n",
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: expected\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n",
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: expected\r\nContent-Length: 0\r\n\r\n",
        ] {
            assert!(verify_upgrade_response(bad.as_bytes(), "expected").is_err());
        }
    }

    #[tokio::test]
    async fn broker_take_connects_once_over_real_local_tls_websocket() {
        use aegis_webrtc::{BrokerLimits, Operation, Signaling, SignalingReply, SignalingRequest};
        use rustls::{pki_types::PrivateKeyDer, ServerConfig};
        use tokio_rustls::TlsAcceptor;

        tokio::time::timeout(Duration::from_secs(10), async {
            let (_dir, input) = fixture();
            let certified = generate_simple_self_signed(vec!["sfu.example.org".into()]).unwrap();
            fs::write(&input.tls_root_der_file, certified.cert.der().as_ref()).unwrap();
            let mut issuer = input.load().unwrap();
            let tls_config = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![certified.cert.der().clone()],
                PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into()),
            )
            .unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            // Test-only address injection: the production private-file loader
            // requires exact endpoint/name agreement before creating the issuer.
            issuer.endpoint = Url::parse(&format!("wss://127.0.0.1:{port}")).unwrap();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let tls = TlsAcceptor::from(Arc::new(tls_config))
                    .accept(stream)
                    .await
                    .unwrap();
                let observed = Arc::new(std::sync::Mutex::new(None::<(String, String)>));
                let capture = observed.clone();
                let mut ws = tokio_tungstenite::accept_hdr_async_with_config(
                    tls,
                    #[expect(
                        clippy::result_large_err,
                        reason = "tungstenite requires this callback error response"
                    )]
                    move |request: &tokio_tungstenite::tungstenite::handshake::server::Request,
                          response: tokio_tungstenite::tungstenite::handshake::server::Response| {
                        assert_eq!(request.uri().path(), "/rtc");
                        assert!(!request.uri().to_string().contains("token"));
                        let bearer = request
                            .headers()
                            .get(AUTHORIZATION)
                            .unwrap()
                            .to_str()
                            .unwrap();
                        let token = bearer.strip_prefix("Bearer ").unwrap();
                        let parts: Vec<_> = token.split('.').collect();
                        assert_eq!(parts.len(), 3);
                        let body = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
                        let claims: serde_json::Value = serde_json::from_slice(&body).unwrap();
                        let room = claims["video"]["room"].as_str().unwrap().to_owned();
                        let identity = claims["sub"].as_str().unwrap().to_owned();
                        *capture.lock().unwrap() = Some((room, identity));
                        Ok(response)
                    },
                    None,
                )
                .await
                .unwrap();
                let (room, identity) = observed.lock().unwrap().take().unwrap();
                ws.send(WsMessage::Binary(encoded_join(&room, &identity, "")))
                    .await
                    .unwrap();
                let _ = tokio::time::timeout(Duration::from_secs(1), ws.next()).await;
                // Keep the listener alive long enough to witness whether a
                // duplicate take opens a second TCP connection.
                assert!(
                    tokio::time::timeout(Duration::from_millis(250), listener.accept())
                        .await
                        .is_err()
                );
            });

            let client_key = AdmissionKey::from_bytes([11; 32]).unwrap();
            let intermediary_key = AdmissionKey::from_bytes([12; 32]).unwrap();
            let wrong_key = AdmissionKey::from_bytes([13; 32]).unwrap();
            let broker = OwnedBroker::new(
                client_key.clone(),
                intermediary_key.clone(),
                BrokerLimits::default(),
            )
            .unwrap();
            let transaction = MediaTransaction::new(&broker, &issuer);
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
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
                panic!("submit refused")
            };
            let SignalingReply::Offer { claim, .. } = broker
                .exchange(
                    SignalingRequest::new(
                        Role::Intermediary,
                        intermediary_key.clone(),
                        Operation::Take,
                    ),
                    deadline,
                )
                .await
                .unwrap()
            else {
                panic!("claim refused")
            };
            transaction
                .start(
                    &intermediary_key,
                    session,
                    claim,
                    Signal::answer("v=0".into()).unwrap(),
                )
                .unwrap();
            assert!(transaction
                .take_and_connect(Role::Client, &wrong_key, session, None)
                .await
                .is_err());
            let connected = transaction
                .take_and_connect(Role::Client, &client_key, session, None)
                .await
                .unwrap();
            assert!(!connected.terminated);
            assert!(connected.socket.is_some());
            assert!(transaction
                .take_and_connect(Role::Client, &client_key, session, None)
                .await
                .is_err());
            drop(connected);
            server.await.unwrap();
            // The intermediary's first take is authorized but the listener is
            // now closed. A failed dial must still consume that descriptor.
            assert!(transaction
                .take_and_connect(Role::Intermediary, &intermediary_key, session, Some(claim))
                .await
                .is_err());
            assert!(matches!(
                transaction.take(Role::Intermediary, &intermediary_key, session, Some(claim)),
                Err(MediaTransactionError::Admission(
                    aegis_webrtc::Error::Session
                ))
            ));
        })
        .await
        .unwrap();
    }
}
