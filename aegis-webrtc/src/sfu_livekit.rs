//! Client-side LiveKit VP8 media consumer for a broker-TLS one-use grant.
//! No DataChannel substitution or target opening before the inner device TLS.

use crate::{
    sfu_media::{FrameKind, ProvisionedSession, Role},
    sfu_peer::{
        approved_offer_track, approved_offer_video_mid, parse_control_notice,
        refused_signal_coordinate, CandidateAuthorizer, MediaTaskScope, PendingTrickles,
        SfuControlNotice, SfuControlNoticeWindow, SfuMediaPeer, SfuPath, SubscriberOfferWindow,
        UdpSocketBinder,
    },
    Error, Result,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use futures::{SinkExt, StreamExt};
use prost::Message as _;
use rand::RngCore;
use std::{collections::HashMap, future::Future, pin::Pin, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::tungstenite::protocol::{
    Message as WsMessage, Role as WsRole, WebSocketConfig,
};
use zeroize::Zeroizing;

const MAX_SIGNAL_MESSAGE: usize = 256 * 1024;
const MAX_JOIN_MESSAGE: usize = 64 * 1024;
const MAX_UPGRADE_HEADER: usize = 8 * 1024;
const MAX_UPGRADE_REQUEST: usize = 8 * 1024;
const MEDIA_NEGOTIATION_DEADLINE: Duration = Duration::from_secs(20);
const SIGNAL_DEADLINE: Duration = Duration::from_secs(5);

/// A session-owned media pump. The caller must poll it alongside the inner
/// device TLS/copy and drop it before releasing any filter or Store lease.
pub type MediaPump = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

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
    ControlNotice(SfuControlNotice),
    /// LiveKit may refresh its bearer after Join. This notice changes no
    /// issuer grant, room binding, deadline, or token used by this worker.
    RefreshToken,
    /// Terminal disconnect only. Resume and reconnect require a fresh grant.
    Leave,
}

// READY still consumes the authenticated signaling socket. A token notice
// cannot renew this session's issuer grant, identity, or media deadline.
fn observe_ready_signal(
    window: &mut SfuControlNoticeWindow,
    count: &mut usize,
    signal: NegotiationSignal,
) -> Result<()> {
    if *count >= 32 {
        return Err(Error::Signaling);
    }
    *count += 1;
    match signal {
        NegotiationSignal::ControlNotice(notice) => window.observe(notice),
        NegotiationSignal::RefreshToken => Ok(()),
        _ => Err(Error::Signaling),
    }
}

impl std::fmt::Debug for NegotiationSignal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NegotiationSignal([redacted])")
    }
}

/// Require one complete length-delimited SignalResponse oneof field. Protobuf
/// decoders otherwise permit a later field to silently replace an earlier one.
fn signal_payload(message: &[u8]) -> Result<(u8, &[u8])> {
    let (field, rest) = match message {
        // SignalResponse.refresh_token = field 16, wire type 2. Require its
        // canonical two-byte key; every supported lower field has one byte.
        [0x82, 0x01, rest @ ..] => (16, rest),
        [key, rest @ ..] if *key & 0x80 == 0 && *key & 7 == 2 => (*key >> 3, rest),
        _ => {
            if message.len() <= MAX_SIGNAL_MESSAGE {
                eprintln!(
                    "sfu_signal_refused role=client field={}",
                    refused_signal_coordinate(message)
                );
            }
            return Err(Error::Signaling);
        }
    };
    if message.len() > MAX_SIGNAL_MESSAGE {
        return Err(Error::Signaling);
    }
    if !matches!(field, 2 | 3 | 4 | 5 | 6 | 8 | 15 | 16) {
        eprintln!(
            "sfu_signal_refused role=client field={}",
            refused_signal_coordinate(message)
        );
        return Err(Error::Signaling);
    }
    let mut size = 0usize;
    let mut prefix = 0usize;
    for shift in [0, 7, 14] {
        let byte = *rest.get(prefix).ok_or(Error::Signaling)?;
        prefix += 1;
        size |= usize::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            let end = prefix.checked_add(size).ok_or(Error::Signaling)?;
            if (size == 0 && field != 8) || end != rest.len() {
                return Err(Error::Signaling);
            }
            return Ok((field, &rest[prefix..end]));
        }
    }
    Err(Error::Signaling)
}

/// LeaveRequest action must not be discarded: RESUME and RECONNECT would need
/// a fresh issuer grant plus expiry and location revalidation. Until that
/// transaction exists, only an unambiguous terminal disconnect is accepted.
fn terminal_leave(payload: &[u8]) -> Result<NegotiationSignal> {
    let mut remaining = payload;
    let mut seen = 0u8;
    let mut can_reconnect = false;
    let mut action = 0u32;
    while let Some((&field, rest)) = remaining.split_first() {
        let bit = match field {
            0x08 => 1, // can_reconnect, obsolete legacy hint
            0x10 => 2, // DisconnectReason
            0x18 => 4, // Action
            _ => return Err(Error::Signaling),
        };
        if seen & bit != 0 {
            return Err(Error::Signaling);
        }
        seen |= bit;
        remaining = rest;
        let mut value = 0u32;
        let mut complete = false;
        for shift in [0, 7, 14, 21, 28] {
            let (&byte, rest) = remaining.split_first().ok_or(Error::Signaling)?;
            if shift == 28 && byte > 0x0f {
                return Err(Error::Signaling);
            }
            value |= u32::from(byte & 0x7f) << shift;
            remaining = rest;
            if byte & 0x80 == 0 {
                if shift != 0 && byte == 0 {
                    return Err(Error::Signaling);
                }
                complete = true;
                break;
            }
        }
        if !complete {
            return Err(Error::Signaling);
        }
        match field {
            0x08 if value <= 1 => can_reconnect = value == 1,
            0x10 if value <= 16 => {} // known DisconnectReason; no side effect
            0x18 if value <= 2 => action = value,
            _ => return Err(Error::Signaling),
        }
    }
    if can_reconnect || action != 0 {
        // Do not issue an implicit reconnect or reuse this one-use descriptor.
        return Err(Error::Signaling);
    }
    Ok(NegotiationSignal::Leave)
}

fn decode_negotiation_signal(message: &[u8]) -> Result<NegotiationSignal> {
    let (field, payload) = signal_payload(message)?;
    match field {
        2 | 3 => {
            let sdp = SessionDescriptionView::decode(payload).map_err(|_| Error::Signaling)?;
            let expected = if field == 2 { "answer" } else { "offer" };
            if sdp.kind != expected
                || !sdp.sdp.starts_with("v=0\r\n")
                || sdp.sdp.len() > 128 * 1024
                || sdp.sdp.bytes().any(|byte| byte == 0)
            {
                return Err(Error::Signaling);
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
            let trickle = TrickleView::decode(payload).map_err(|_| Error::Signaling)?;
            if !matches!(trickle.target, 0 | 1) || trickle.candidate_init.len() > 4096 {
                return Err(Error::Signaling);
            }
            if !trickle.final_candidate {
                let value: serde_json::Value =
                    serde_json::from_str(&trickle.candidate_init).map_err(|_| Error::Signaling)?;
                let candidate = value
                    .get("candidate")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(Error::Signaling)?;
                if candidate.is_empty() || candidate.len() > 2048 {
                    return Err(Error::Signaling);
                }
            }
            Ok(NegotiationSignal::Trickle {
                candidate_init: Zeroizing::new(trickle.candidate_init),
                target: trickle.target,
                final_candidate: trickle.final_candidate,
            })
        }
        5 => {
            let update = ParticipantUpdateView::decode(payload).map_err(|_| Error::Signaling)?;
            if update.participants.len() > 8
                || update.participants.iter().any(|p| p.tracks.len() > 8)
            {
                return Err(Error::Signaling);
            }
            Ok(NegotiationSignal::ParticipantUpdate(update))
        }
        6 => {
            let event = TrackPublishedView::decode(payload).map_err(|_| Error::Signaling)?;
            if event.cid.is_empty() || event.cid.len() > 96 {
                return Err(Error::Signaling);
            }
            Ok(NegotiationSignal::TrackPublished {
                cid: event.cid,
                track: event.track.ok_or(Error::Signaling)?,
            })
        }
        8 => terminal_leave(payload),
        15 => Ok(NegotiationSignal::ControlNotice(parse_control_notice(
            field, payload,
        )?)),
        16 => {
            // Protobuf string wire type is validated here without creating a
            // String or retaining/logging the bearer. The existing one-use
            // descriptor and media deadline remain authoritative.
            let token = std::str::from_utf8(payload).map_err(|_| Error::Signaling)?;
            if token.is_empty()
                || token.len() > 4096
                || !token.bytes().all(|b| b.is_ascii_graphic())
            {
                return Err(Error::Signaling);
            }
            Ok(NegotiationSignal::RefreshToken)
        }
        _ => Err(Error::Signaling),
    }
}

fn join_payload(message: &[u8]) -> Result<&[u8]> {
    // SignalResponse is a oneof. Require the first and only field to be join
    // (field 1, length-delimited); do not silently ignore a leave/redirect or
    // a second oneof alternative as a partial protobuf decoder would.
    if message.len() > MAX_JOIN_MESSAGE || message.first() != Some(&0x0a) {
        return Err(Error::Signaling);
    }
    let mut size = 0usize;
    let mut index = 1;
    for shift in [0, 7, 14] {
        let byte = *message.get(index).ok_or(Error::Signaling)?;
        index += 1;
        size |= usize::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            let end = index.checked_add(size).ok_or(Error::Signaling)?;
            if size == 0 || end != message.len() {
                return Err(Error::Signaling);
            }
            return Ok(&message[index..end]);
        }
    }
    Err(Error::Signaling)
}

fn verify_join(message: &[u8], descriptor: &ProvisionedSession) -> Result<()> {
    let join = JoinResponseView::decode(join_payload(message)?).map_err(|_| Error::Signaling)?;
    let room = join.room.ok_or(Error::Signaling)?;
    let participant = join.participant.ok_or(Error::Signaling)?;
    if !join.alternative_url.is_empty()
        || room.sid.is_empty()
        || participant.sid.is_empty()
        || room.name != descriptor.room_for_issuer()
        || participant.identity != descriptor.identity_for_issuer()
    {
        return Err(Error::Signaling);
    }
    Ok(())
}

/// Parse only the bounded HTTP Upgrade response. No request header or bearer
/// material is passed to a logger, parser or error formatter here.
fn verify_upgrade_response(input: &[u8], expected_accept: &str) -> Result<Option<usize>> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut response = httparse::Response::new(&mut headers);
    let end = match response.parse(input).map_err(|_| Error::Signaling)? {
        httparse::Status::Partial => return Ok(None),
        httparse::Status::Complete(end) => end,
    };
    if response.version != Some(1) || response.code != Some(101) {
        return Err(Error::Signaling);
    }
    let mut upgrade = false;
    let mut connection = false;
    let mut accept = false;
    for header in response.headers.iter() {
        let value = std::str::from_utf8(header.value)
            .map_err(|_| Error::Signaling)?
            .trim();
        if header.name.eq_ignore_ascii_case("Upgrade") {
            if upgrade || !value.eq_ignore_ascii_case("websocket") {
                return Err(Error::Signaling);
            }
            upgrade = true;
        } else if header.name.eq_ignore_ascii_case("Connection") {
            if connection
                || !value
                    .split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
            {
                return Err(Error::Signaling);
            }
            connection = true;
        } else if header.name.eq_ignore_ascii_case("Sec-WebSocket-Accept") {
            if accept || value != expected_accept {
                return Err(Error::Signaling);
            }
            accept = true;
        } else if header.name.eq_ignore_ascii_case("Sec-WebSocket-Extensions")
            || header.name.eq_ignore_ascii_case("Sec-WebSocket-Protocol")
            || header.name.eq_ignore_ascii_case("Content-Length")
            || header.name.eq_ignore_ascii_case("Transfer-Encoding")
        {
            return Err(Error::Signaling);
        }
    }
    if upgrade && connection && accept {
        Ok(Some(end))
    } else {
        Err(Error::Signaling)
    }
}

pub struct SfuLiveKitClient {
    socket: tokio_tungstenite::WebSocketStream<TlsStream<tokio::net::TcpStream>>,
    peer: SfuMediaPeer,
    counterpart_identity: String,
    local_name: String,
    remote_name: String,
    remote_sid: Option<String>,
    control_notices: SfuControlNoticeWindow,
    deadline: tokio::time::Instant,
}

#[cfg(feature = "sfu-media-vp8")]
fn bounded_signal_field(field: u8, message: impl prost::Message) -> Result<Vec<u8>> {
    let payload = message.encode_to_vec();
    if payload.is_empty() || payload.len() > MAX_SIGNAL_MESSAGE - 4 {
        return Err(Error::Signaling);
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
impl SfuLiveKitClient {
    /// Consume an already name/CA-verified TLS connection. The bearer is
    /// written only from one preallocated zeroizing buffer, bypassing the
    /// dependency handshake path that traces serialized headers.
    pub async fn connect_verified(
        tls: TlsStream<tokio::net::TcpStream>,
        host: &str,
        token: Zeroizing<String>,
        descriptor: ProvisionedSession,
        path: SfuPath,
    ) -> Result<Self> {
        Self::connect_verified_with_authorizer(tls, host, token, descriptor, path, None).await
    }

    /// The macOS owner supplies an exact-candidate authorization callback
    /// before any verified remote SDP or trickle reaches the ICE backend.
    pub async fn connect_verified_with_authorizer(
        tls: TlsStream<tokio::net::TcpStream>,
        host: &str,
        token: Zeroizing<String>,
        descriptor: ProvisionedSession,
        path: SfuPath,
        candidate_authorizer: Option<CandidateAuthorizer>,
    ) -> Result<Self> {
        Self::connect_verified_with_network(
            tls,
            host,
            token,
            descriptor,
            path,
            candidate_authorizer,
            None,
        )
        .await
    }

    /// The physical path owner supplies both an exact candidate gate and
    /// per-socket binding. A candidate gate alone cannot bind ICE UDP to the
    /// selected interface, including after an ICE restart.
    pub async fn connect_verified_with_network(
        tls: TlsStream<tokio::net::TcpStream>,
        host: &str,
        token: Zeroizing<String>,
        descriptor: ProvisionedSession,
        path: SfuPath,
        candidate_authorizer: Option<CandidateAuthorizer>,
        socket_binder: Option<UdpSocketBinder>,
    ) -> Result<Self> {
        Self::connect_verified_with_network_scoped(
            tls,
            host,
            token,
            descriptor,
            path,
            candidate_authorizer,
            socket_binder,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)] // Each input binds a distinct media/session authority.
    pub async fn connect_verified_with_network_scoped(
        mut tls: TlsStream<tokio::net::TcpStream>,
        host: &str,
        token: Zeroizing<String>,
        descriptor: ProvisionedSession,
        path: SfuPath,
        candidate_authorizer: Option<CandidateAuthorizer>,
        socket_binder: Option<UdpSocketBinder>,
        scope: Option<MediaTaskScope>,
    ) -> Result<Self> {
        path.validate()?;
        if descriptor.role() != Role::Client
            || descriptor.remaining_for_issuer().is_zero()
            || host.is_empty()
            || host.len() > 253
            || !host.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b':')
            })
            || token.is_empty()
            || token.len() > 4096
            || token.bytes().any(|b| b.is_ascii_whitespace() || b == 0)
        {
            return Err(Error::Configuration);
        }
        let mut nonce = [0u8; 16];
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| Error::Configuration)?;
        let key = STANDARD.encode(nonce);
        let expected = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
        let mut request = Zeroizing::new(Vec::with_capacity(MAX_UPGRADE_REQUEST));
        request.extend_from_slice(b"GET /rtc?protocol=9&sdk=rust&version=0.1.0 HTTP/1.1\r\nHost: ");
        request.extend_from_slice(host.as_bytes());
        request.extend_from_slice(b"\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ");
        request.extend_from_slice(key.as_bytes());
        request.extend_from_slice(b"\r\nAuthorization: Bearer ");
        if request.len() + token.len() + 4 > MAX_UPGRADE_REQUEST {
            return Err(Error::Configuration);
        }
        request.extend_from_slice(token.as_bytes());
        request.extend_from_slice(b"\r\n\r\n");
        let deadline = tokio::time::Instant::now() + SIGNAL_DEADLINE;
        tokio::time::timeout_at(deadline, tls.write_all(&request))
            .await
            .map_err(|_| Error::Deadline)?
            .map_err(|_| Error::Signaling)?;
        tokio::time::timeout_at(deadline, tls.flush())
            .await
            .map_err(|_| Error::Deadline)?
            .map_err(|_| Error::Signaling)?;
        drop(request);
        let mut response = [0u8; MAX_UPGRADE_HEADER];
        let mut used = 0usize;
        let header_end = loop {
            if let Some(end) = verify_upgrade_response(&response[..used], &expected)? {
                break end;
            }
            if used == response.len() {
                return Err(Error::Signaling);
            }
            let count = tokio::time::timeout_at(deadline, tls.read(&mut response[used..]))
                .await
                .map_err(|_| Error::Deadline)?
                .map_err(|_| Error::Signaling)?;
            if count == 0 {
                return Err(Error::Signaling);
            }
            used += count;
        };
        let socket = tokio_tungstenite::WebSocketStream::from_partially_read(
            tls,
            response[header_end..used].to_vec(),
            WsRole::Client,
            Some(WebSocketConfig {
                max_message_size: Some(MAX_SIGNAL_MESSAGE),
                max_frame_size: Some(MAX_SIGNAL_MESSAGE),
                max_write_buffer_size: MAX_SIGNAL_MESSAGE * 2,
                ..Default::default()
            }),
        )
        .await;
        let mut socket = socket;
        let join = tokio::time::timeout(SIGNAL_DEADLINE, socket.next())
            .await
            .map_err(|_| Error::Deadline)?
            .ok_or(Error::Signaling)?
            .map_err(|_| Error::Signaling)?;
        let WsMessage::Binary(join) = join else {
            return Err(Error::Signaling);
        };
        verify_join(&join, &descriptor)?;
        Self::from_authenticated(
            socket,
            descriptor,
            path,
            candidate_authorizer,
            socket_binder,
            scope,
        )
        .await
    }

    async fn from_authenticated(
        socket: tokio_tungstenite::WebSocketStream<TlsStream<tokio::net::TcpStream>>,
        descriptor: ProvisionedSession,
        path: SfuPath,
        candidate_authorizer: Option<CandidateAuthorizer>,
        socket_binder: Option<UdpSocketBinder>,
        scope: Option<MediaTaskScope>,
    ) -> Result<Self> {
        let remaining = descriptor.remaining_for_issuer();
        if remaining.is_zero() {
            return Err(Error::Signaling);
        }
        let counterpart_identity = descriptor.counterpart_identity_for_issuer();
        let local_name = match descriptor.role() {
            Role::Client => descriptor.track_names().0.to_owned(),
            Role::Intermediary => descriptor.track_names().1.to_owned(),
        };
        let remote_name = match descriptor.role() {
            Role::Client => descriptor.track_names().1.to_owned(),
            Role::Intermediary => descriptor.track_names().0.to_owned(),
        };
        let deadline = tokio::time::Instant::now() + remaining.min(MEDIA_NEGOTIATION_DEADLINE);
        let peer = SfuMediaPeer::new_with_network_scoped(
            descriptor,
            path,
            candidate_authorizer,
            socket_binder,
            scope,
        )
        .await
        .map_err(|_| Error::Signaling)?;
        Ok(Self {
            socket,
            peer,
            counterpart_identity,
            local_name,
            remote_name,
            remote_sid: None,
            control_notices: SfuControlNoticeWindow::default(),
            deadline,
        })
    }

    async fn send_request(&mut self, field: u8, message: impl prost::Message) -> Result<()> {
        let wire = bounded_signal_field(field, message)?;
        tokio::time::timeout_at(self.deadline, self.socket.send(WsMessage::Binary(wire)))
            .await
            .map_err(|_| Error::Signaling)?
            .map_err(|_| Error::Signaling)
    }

    async fn read_response(&mut self) -> Result<NegotiationSignal> {
        let response = tokio::time::timeout_at(self.deadline, self.socket.next())
            .await
            .map_err(|_| Error::Signaling)?
            .ok_or(Error::Signaling)?
            .map_err(|_| Error::Signaling)?;
        match response {
            WsMessage::Binary(bytes) => {
                let decoded = decode_negotiation_signal(&bytes);
                if decoded.is_err() {
                    // Fixed local diagnostic only. Never print the signal,
                    // SDP, participant, candidate, or bearer bytes.
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
                    eprintln!("sfu_media_signal_refused role=client kind={kind}");
                }
                decoded
            }
            _ => {
                eprintln!("sfu_media_signal_refused role=client kind=nonbinary");
                Err(Error::Signaling)
            }
        }
    }

    /// Apply publisher Answer, subscriber Offer, bounded ICE trickle, and the
    /// opposite broker identity's exact video track. A media path is not ready
    /// until both selected RTP ICE pairs have been checked against the private
    /// numeric SFU allowlist by `SfuMediaPeer`.
    pub(crate) async fn negotiate(&mut self) -> Result<()> {
        let mut step = "add_track";
        let result = self.negotiate_inner(&mut step).await;
        if result.is_err() {
            eprintln!("sfu_media_refused role=client step={step}");
        }
        result
    }

    async fn negotiate_inner(&mut self, step: &mut &'static str) -> Result<()> {
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
            .map_err(|_| Error::Signaling)?;
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
        let mut subscriber_offers = SubscriberOfferWindow::new();
        let mut pending_trickles = PendingTrickles::default();
        let mut control_notices = SfuControlNoticeWindow::default();
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
                        return Err(Error::Signaling);
                    }
                    published = true;
                }
                NegotiationSignal::PublisherAnswer(sdp) => {
                    *step = "publisher_answer";
                    if publisher_answer {
                        return Err(Error::Signaling);
                    }
                    self.peer
                        .apply_publisher_answer(sdp.to_string())
                        .await
                        .map_err(|_| Error::Signaling)?;
                    publisher_answer = true;
                    pending_trickles
                        .flush(&self.peer, true)
                        .await
                        .map_err(|_| Error::Signaling)?;
                }
                NegotiationSignal::SubscriberOffer {
                    sdp,
                    id,
                    mid_to_track_id,
                } => {
                    *step = "subscriber_offer";
                    subscriber_offers.begin_offer(&sdp, id)?;
                    if self.remote_sid.as_ref().is_some_and(|sid| {
                        !mid_to_track_id.is_empty()
                            && !approved_offer_video_mid(&sdp, &mid_to_track_id, sid)
                    }) {
                        return Err(Error::Signaling);
                    }
                    let answer = self
                        .peer
                        .answer_subscriber_offer(sdp.to_string())
                        .await
                        .map_err(|_| Error::Signaling)?;
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
                        .map_err(|_| Error::Signaling)?;
                    let (count, video, receiver_identity) = self
                        .peer
                        .subscriber_receiver_state(
                            self.remote_sid.as_deref(),
                            &self.counterpart_identity,
                        )
                        .await;
                    if self.remote_sid.is_none() {
                        subscriber_offers.defer_offer(sdp, mid_to_track_id, count, video)?;
                        continue;
                    }
                    let approved_track = self.remote_sid.as_ref().is_some_and(|sid| {
                        approved_offer_track(&sdp, &mid_to_track_id, sid, receiver_identity)
                    });
                    subscriber_offers.applied_offer(count, video, approved_track)?;
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
                            control_notices.bind_remote(&participant.sid, &track.sid)?;
                            if let Some(existing) = &self.remote_sid {
                                if existing != &track.sid {
                                    return Err(Error::Signaling);
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
                                subscriber_offers.request_subscription()?;
                                subscribed = true;
                                let (count, video, receiver_identity) = self
                                    .peer
                                    .subscriber_receiver_state(
                                        self.remote_sid.as_deref(),
                                        &self.counterpart_identity,
                                    )
                                    .await;
                                subscriber_offers.resolve_pending(
                                    self.remote_sid.as_deref().ok_or(Error::Signaling)?,
                                    count,
                                    video,
                                    receiver_identity,
                                )?;
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
                            .map_err(|_| Error::Signaling)?;
                    } else {
                        self.peer
                            .apply_trickle_json(&candidate_init, publisher)
                            .await
                            .map_err(|_| Error::Signaling)?;
                    }
                }
                NegotiationSignal::Leave => {
                    *step = "leave";
                    return Err(Error::Signaling);
                }
                NegotiationSignal::RefreshToken => {
                    // LiveKit's token notice cannot renew an issuer grant.
                }
                NegotiationSignal::ControlNotice(notice) => {
                    *step = "control_notice";
                    control_notices.observe(notice)?;
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
            return Err(Error::Signaling);
        }
        *step = "selected_ice";
        tokio::time::timeout_at(self.deadline, self.peer.wait_connected())
            .await
            .map_err(|_| {
                eprintln!("sfu_selected_ice_refused reason=outer_deadline");
                Error::Signaling
            })?
            .map_err(|_| Error::Signaling)?;
        self.control_notices = control_notices;
        self.deadline = self.peer.media_deadline().into();
        Ok(())
    }

    pub(crate) async fn send_frame(&mut self, kind: FrameKind, payload: &[u8]) -> Result<[u8; 64]> {
        if self.remote_sid.is_none() || tokio::time::Instant::now() >= self.deadline {
            return Err(Error::Signaling);
        }
        self.peer
            .send_frame(kind, payload)
            .await
            .map_err(|_| Error::Signaling)
    }

    pub(crate) async fn retransmit(&mut self, wire: &[u8; 64]) -> Result<()> {
        self.peer
            .retransmit(wire)
            .await
            .map_err(|_| Error::Signaling)
    }

    /// Adapt the authenticated video tracks to the existing inner TLS byte
    /// admission. This adapter is private and remains feature gated. The
    /// caller must await the worker result after `serve_device_carrier` ends;
    /// dropping the owner aborts it and closes both WebRTC peers.
    pub async fn into_inner_tls_carrier(
        self,
    ) -> Result<(tokio::io::DuplexStream, tokio::task::JoinHandle<Result<()>>)> {
        let (device_side, pump) = self.into_inner_tls_carrier_unspawned().await?;
        Ok((device_side, tokio::spawn(pump)))
    }

    /// The NetworkExtension keeps this pump inside its WorkGate flow future;
    /// cancellation then drops media synchronously before the permit returns.
    pub async fn into_inner_tls_carrier_unspawned(
        mut self,
    ) -> Result<(tokio::io::DuplexStream, MediaPump)> {
        self.negotiate().await?;
        let (device_side, media_side) = tokio::io::duplex(64 * 1024);
        let pump: MediaPump = Box::pin(async move { self.pump_bytes(media_side).await });
        Ok((device_side, pump))
    }

    async fn pump_bytes(&mut self, media_side: tokio::io::DuplexStream) -> Result<()> {
        use crate::sfu_media::ReceivedFrame;
        let (mut outbound, mut inbound) = tokio::io::split(media_side);
        let mut buf = [0u8; 42];
        // (original sealed wire, kind, sequence, retry deadline, retry count)
        let mut pending: Option<([u8; 64], FrameKind, u32, tokio::time::Instant, u8)> = None;
        let mut outbound_eof = false;
        let mut inbound_eof = false;
        let mut fin_acked = false;
        let remote_sid = self.remote_sid.clone().ok_or(Error::Signaling)?;
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
                    match received.map_err(|_| Error::Signaling)? {
                        ReceivedFrame::Fresh(frame) => match frame.kind() {
                            FrameKind::Data if !inbound_eof => {
                                tokio::time::timeout_at(self.deadline, inbound.write_all(frame.payload())).await
                                    .map_err(|_| Error::Signaling)?
                                    .map_err(|_| Error::Signaling)?;
                                let _ = self.send_frame(FrameKind::Ack, &frame.sequence().to_be_bytes()).await?;
                            }
                            FrameKind::Ack => {
                                if frame.payload().len() != 4 { return Err(Error::Signaling); }
                                let ack = u32::from_be_bytes(frame.payload().try_into().map_err(|_| Error::Signaling)?);
                                if pending.as_ref().is_some_and(|p| p.1 == FrameKind::Data && p.2 == ack) {
                                    pending = None;
                                }
                            }
                            FrameKind::Fin if !inbound_eof => {
                                inbound_eof = true;
                                tokio::time::timeout_at(self.deadline, inbound.shutdown()).await
                                    .map_err(|_| Error::Signaling)?
                                    .map_err(|_| Error::Signaling)?;
                                let _ = self.send_frame(FrameKind::FinAck, &frame.sequence().to_be_bytes()).await?;
                            }
                            FrameKind::FinAck => {
                                if frame.payload().len() != 4 { return Err(Error::Signaling); }
                                let ack = u32::from_be_bytes(frame.payload().try_into().map_err(|_| Error::Signaling)?);
                                if pending.as_ref().is_some_and(|p| p.1 == FrameKind::Fin && p.2 == ack) {
                                    pending = None;
                                    fin_acked = true;
                                }
                            }
                            FrameKind::KeepAlive if frame.payload().is_empty() => {}
                            _ => return Err(Error::Signaling),
                        },
                        ReceivedFrame::Duplicate { kind, sequence }
                            if matches!(kind, FrameKind::Data | FrameKind::Fin) => {
                            let response = if kind == FrameKind::Data { FrameKind::Ack } else { FrameKind::FinAck };
                            let _ = self.send_frame(response, &sequence.to_be_bytes()).await?;
                        }
                        ReceivedFrame::Duplicate { .. } => {},
                        // The authenticated replay window has already
                        // classified this sequence as too old. Never deliver
                        // it to the inner TLS stream or acknowledge it.
                        ReceivedFrame::Stale => {},
                    }
                }
                signal = self.socket.next() => {
                    let message = signal.ok_or(Error::Signaling)?.map_err(|_| Error::Signaling)?;
                    let WsMessage::Binary(bytes) = message else { return Err(Error::Signaling); };
                    observe_ready_signal(&mut self.control_notices, &mut post_ready_notices,
                        decode_negotiation_signal(&bytes)?)?;
                }
                read = outbound.read(&mut buf), if pending.is_none() && !outbound_eof => {
                    let count = read.map_err(|_| Error::Signaling)?;
                    if count == 0 { outbound_eof = true; }
                    let kind = if count == 0 { FrameKind::Fin } else { FrameKind::Data };
                    let wire = self.send_frame(kind, &buf[..count]).await?;
                    let sequence = u32::from_be_bytes(wire[1..5].try_into().map_err(|_| Error::Signaling)?);
                    pending = Some((wire, kind, sequence, tokio::time::Instant::now() + Duration::from_millis(500), 0));
                }
                _ = heartbeat.tick() => {
                    // A silent TCP application still publishes authenticated
                    // media. This does not grant a new target or renew expiry.
                    let _ = self.send_frame(FrameKind::KeepAlive, &[]).await?;
                }
                _ = tokio::time::sleep_until(retry_at), if pending.is_some() => {
                    let item = pending.as_mut().ok_or(Error::Signaling)?;
                    if item.4 >= 3 { return Err(Error::Signaling); }
                    self.retransmit(&item.0).await?;
                    item.4 += 1;
                    item.3 = tokio::time::Instant::now() + Duration::from_millis(500);
                }
            }
        }
        Err(Error::Signaling)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        frame[0] = 0x78; // wrong protobuf wire type
        assert!(decode_negotiation_signal(&frame).is_err());
    }

    #[test]
    fn ready_signaling_bounds_refresh_and_refuses_permission_mutants() {
        use crate::sfu_peer::SfuControlNoticeWindow;
        let mut window = SfuControlNoticeWindow::default();
        window.bind_remote("PA_remote", "TR_remote").unwrap();
        let refresh = refresh_frame(b"header.payload.signature");
        let mut count = 0;
        for _ in 0..32 {
            observe_ready_signal(
                &mut window,
                &mut count,
                decode_negotiation_signal(&refresh).unwrap(),
            )
            .unwrap();
        }
        assert!(observe_ready_signal(
            &mut window,
            &mut count,
            decode_negotiation_signal(&refresh).unwrap()
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
        let mut foreign = permission.clone();
        foreign[7] = b'f';
        let mut fresh = SfuControlNoticeWindow::default();
        fresh.bind_remote("PA_remote", "TR_remote").unwrap();
        let mut count = 0;
        assert!(observe_ready_signal(
            &mut fresh,
            &mut count,
            decode_negotiation_signal(&foreign).unwrap()
        )
        .is_err());
        let last = permission.len() - 1;
        permission[last] = 0;
        assert!(decode_negotiation_signal(&permission).is_err());
    }

    #[test]
    fn subscriber_offer_keeps_optional_protocol_nine_id_and_mid_mapping() {
        let offer = SessionDescriptionView {
            kind: "offer".into(),
            sdp: "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:v0\r\n".into(),
            id: 7,
            mid_to_track_id: HashMap::from([("v0".into(), "TR_approved".into())]),
        }
        .encode_to_vec();
        assert!(offer.len() < 128);
        let mut frame = vec![0x1a, offer.len() as u8];
        frame.extend_from_slice(&offer);
        let decoded = decode_negotiation_signal(&frame).unwrap();
        assert_eq!(format!("{decoded:?}"), "NegotiationSignal([redacted])");
        match decoded {
            NegotiationSignal::SubscriberOffer {
                id,
                mid_to_track_id,
                ..
            } => {
                assert_eq!(id, 7);
                assert_eq!(
                    mid_to_track_id.get("v0").map(String::as_str),
                    Some("TR_approved")
                );
            }
            _ => panic!("wrong signal kind"),
        }
    }

    fn refresh_frame(payload: &[u8]) -> Vec<u8> {
        let mut message = vec![0x82, 0x01];
        let mut size = payload.len();
        while size >= 0x80 {
            message.push((size as u8 & 0x7f) | 0x80);
            size >>= 7;
        }
        message.push(size as u8);
        message.extend_from_slice(payload);
        message
    }

    #[test]
    fn refresh_notice_is_bounded_typed_and_cannot_change_authorization() {
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
    fn private_upgrade_and_signal_parser_refuse_untrusted_variants() {
        let expected = "fixture_accept";
        let valid = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: fixture_accept\r\n\r\n";
        assert_eq!(
            verify_upgrade_response(valid, expected).unwrap(),
            Some(valid.len())
        );
        let extension = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: fixture_accept\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n";
        assert!(verify_upgrade_response(extension, expected).is_err());
        assert!(verify_upgrade_response(valid, "wrong_accept").is_err());
        assert!(matches!(
            decode_negotiation_signal(&[0x42, 0x00]),
            Ok(NegotiationSignal::Leave)
        ));
        assert!(decode_negotiation_signal(&[0x42, 0x02, 0x18, 0x01]).is_err());
        assert!(decode_negotiation_signal(&[0x42, 0x00, 0x42, 0x00]).is_err());
    }
}
