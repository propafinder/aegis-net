//! One-use, role-bound VP8 WebRTC media peer for a self-hosted SFU.
//!
//! LiveKit's private signaling socket and signed token are owned by the
//! server's `MediaTransaction`. This peer receives only its broker descriptor
//! and numeric ICE allowlist. It creates real RTP video tracks, never DCEP.

use crate::{
    sfu_media::{
        FrameKind, MediaError, ProvisionedSession, ReceiveCodec, ReceivedFrame, Role, SendCodec,
    },
    sfu_vp8::Vp8GridCodec,
    Error, Result,
};
use async_trait::async_trait;
use bytes::Bytes;
use prost::Message as _;
use rtc::{
    interceptor::Registry,
    media::{io::sample_builder::SampleBuilder, Sample},
    media_stream::MediaStreamTrack,
    peer_connection::{
        configuration::{
            interceptor_registry::register_default_interceptors,
            media_engine::{MediaEngine, MIME_TYPE_VP8},
        },
        sdp::RTCSessionDescription,
        transport::RTCIceProtocol,
    },
    rtp::codec::vp8::Vp8Packet,
    rtp_transceiver::rtp_sender::{
        RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
        RtpCodecKind,
    },
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    future::Future,
    io,
    net::{IpAddr, SocketAddr, UdpSocket},
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, watch};
use webrtc::{
    data_channel::DataChannel,
    media_stream::{
        track_local::{static_sample::TrackLocalStaticSample, TrackLocal},
        track_remote::TrackRemote,
    },
    peer_connection::{
        PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCConfigurationBuilder,
        RTCIceCandidateInit, RTCIceGatheringState, RTCPeerConnectionState, SettingEngineBuilder,
    },
    runtime::{
        AsyncInterval, AsyncTcpListener, AsyncTcpStream, AsyncUdpSocket, JoinHandle, Runtime,
        TokioRuntime,
    },
};
use zeroize::Zeroizing;

const MAX_SDP: usize = 128 * 1024;

/// Static refusal coordinate for a SignalResponse key. Inspect at most the
/// canonical one- or two-byte protobuf key, never its payload. This does not
/// make an unhandled event admissible or assert that its message is valid.
pub fn refused_signal_coordinate(message: &[u8]) -> &'static str {
    let (key, width) = match message {
        [first, ..] if first & 0x80 == 0 => (u16::from(*first), 1),
        [first, second, ..] if first & 0x80 != 0 && second & 0x80 == 0 && *second != 0 => {
            (u16::from(*first & 0x7f) | (u16::from(*second) << 7), 2)
        }
        _ => return "invalid_key",
    };
    let field = key >> 3;
    let wire = key & 7;
    if (field < 16 && width != 1) || (field >= 16 && width != 2) {
        return "invalid_key";
    }
    if wire != if field == 18 { 0 } else { 2 } {
        return "invalid_wire";
    }
    match field {
        1 => "join_replay",
        2 | 3 | 4 | 5 | 6 | 8 | 16 => "known_field_malformed",
        7 => "unallocated_field",
        9 => "mute",
        10 => "speakers_changed",
        11 => "room_update",
        12 => "connection_quality",
        13 => "stream_state_update",
        14 => "subscribed_quality_update",
        15 => "subscription_permission_update",
        17 => "track_unpublished",
        18 => "pong_legacy",
        19 => "reconnect",
        20 => "pong_response",
        21 => "subscription_response",
        22 => "request_response",
        23 => "track_subscribed",
        24 => "room_moved",
        25 => "media_sections_requirement",
        26 => "subscribed_audio_codec_update",
        27 => "publish_data_track_response",
        28 => "unpublish_data_track_response",
        29 => "data_track_subscriber_handles",
        30 => "store_data_blob_response",
        31 => "get_data_blob_response",
        _ => "unallocated_field",
    }
}

// Exact LiveKit 1.13.9 / protocol a935cd67 control notices. They convey no
// authority to open a media path. A malformed, duplicate or foreign notice is
// a terminal signal refusal, including a permission revocation.
#[derive(prost::Message)]
struct PermissionUpdateWire {
    #[prost(string, tag = "1")]
    participant_sid: String,
    #[prost(string, tag = "2")]
    track_sid: String,
    #[prost(bool, tag = "3")]
    allowed: bool,
}

pub enum SfuControlNotice {
    Permission {
        participant_sid: String,
        track_sid: String,
    },
}

fn control_sid(sid: &str) -> bool {
    !sid.is_empty()
        && sid.len() <= 96
        && sid
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

pub fn parse_control_notice(field: u8, payload: &[u8]) -> Result<SfuControlNotice> {
    if payload.is_empty() || payload.len() > 512 {
        return Err(Error::Signaling);
    }
    match field {
        15 => {
            let notice = PermissionUpdateWire::decode(payload).map_err(|_| Error::Signaling)?;
            if notice.encode_to_vec() != payload
                || !notice.allowed
                || !control_sid(&notice.participant_sid)
                || !control_sid(&notice.track_sid)
            {
                return Err(Error::Signaling);
            }
            Ok(SfuControlNotice::Permission {
                participant_sid: notice.participant_sid,
                track_sid: notice.track_sid,
            })
        }
        _ => Err(Error::Signaling),
    }
}

#[derive(Default)]
pub struct SfuControlNoticeWindow {
    remote: Option<(String, String)>,
    permission: Option<(String, String)>,
}

impl SfuControlNoticeWindow {
    fn check_bound(&self) -> Result<()> {
        if let (Some((participant, track)), Some((noticed_participant, noticed_track))) =
            (&self.remote, &self.permission)
        {
            if participant != noticed_participant || track != noticed_track {
                return Err(Error::Signaling);
            }
        }
        Ok(())
    }

    pub fn bind_remote(&mut self, participant_sid: &str, track_sid: &str) -> Result<()> {
        if !control_sid(participant_sid)
            || !control_sid(track_sid)
            || self
                .remote
                .as_ref()
                .is_some_and(|(p, t)| p != participant_sid || t != track_sid)
        {
            return Err(Error::Signaling);
        }
        self.remote = Some((participant_sid.to_owned(), track_sid.to_owned()));
        self.check_bound()
    }

    pub fn observe(&mut self, notice: SfuControlNotice) -> Result<()> {
        match notice {
            SfuControlNotice::Permission {
                participant_sid,
                track_sid,
            } => {
                if self
                    .permission
                    .replace((participant_sid, track_sid))
                    .is_some()
                {
                    return Err(Error::Signaling);
                }
            }
        }
        self.check_bound()
    }
}

/// A SubscribeTrack write is only a request. LiveKit can first offer a
/// subscriber transport without the requested video, then offer that video
/// after subscription. Keep all offers on the same authenticated peer and
/// admit media only after an empty bootstrap offer followed by a distinct
/// approved video offer while the request is outstanding. This proves the
/// server-offered video path, not receipt timing of the request. The existing
/// signal-message and issuer deadlines apply to the entire window.
pub struct SubscriberOfferWindow {
    hashes: [[u8; 32]; 3],
    count: usize,
    last_id: u32,
    subscribe_requested: bool,
    empty_offer_seen: bool,
    video_ready: bool,
    pending: Vec<PendingSubscriberOffer>,
}

struct PendingSubscriberOffer {
    sdp: Zeroizing<String>,
    mid_to_track_id: HashMap<String, String>,
    receiver_count: usize,
    video_receiver: bool,
}

impl Default for SubscriberOfferWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl SubscriberOfferWindow {
    pub fn new() -> Self {
        Self {
            hashes: [[0; 32]; 3],
            count: 0,
            last_id: 0,
            subscribe_requested: false,
            empty_offer_seen: false,
            video_ready: false,
            pending: Vec::new(),
        }
    }

    pub fn request_subscription(&mut self) -> Result<()> {
        if self.subscribe_requested || self.video_ready {
            return Err(Error::Signaling);
        }
        self.subscribe_requested = true;
        Ok(())
    }

    pub fn begin_offer(&mut self, sdp: &str, id: u32) -> Result<()> {
        if self.video_ready || self.count == self.hashes.len() || sdp.len() > MAX_SDP {
            return Err(Error::Signaling);
        }
        // Protocol 9 can omit the optional offer ID. Once this server has
        // supplied an ID, however, an absent or stale ID is a downgrade.
        if self.count != 0 && self.last_id != 0 && id <= self.last_id {
            return Err(Error::Signaling);
        }
        let digest: [u8; 32] = Sha256::digest(sdp.as_bytes()).into();
        if self.hashes[..self.count].contains(&digest) {
            return Err(Error::Signaling);
        }
        self.hashes[self.count] = digest;
        self.count += 1;
        self.last_id = id;
        Ok(())
    }

    pub fn applied_offer(
        &mut self,
        receiver_count: usize,
        video_receiver: bool,
        approved_track: bool,
    ) -> Result<()> {
        if self.count == 0
            || receiver_count > 1
            || (receiver_count == 1 && (!video_receiver || !approved_track))
        {
            return Err(Error::Path);
        }
        if receiver_count == 0 {
            self.empty_offer_seen = true;
        } else if self.subscribe_requested && (self.empty_offer_seen || self.count == 1) {
            self.video_ready = true;
        } else {
            return Err(Error::Signaling);
        }
        Ok(())
    }

    pub fn ready(&self) -> bool {
        self.video_ready
    }

    /// SignalResponse.offer and ParticipantUpdate have no guaranteed relative
    /// order. Answer the offer on the held peer, but retain only this bounded
    /// provisional state until TrackInfo authenticates the counterpart SID.
    /// Nothing here marks media ready or authorizes a selected path.
    pub fn defer_offer(
        &mut self,
        sdp: Zeroizing<String>,
        mid_to_track_id: HashMap<String, String>,
        receiver_count: usize,
        video_receiver: bool,
    ) -> Result<()> {
        if self.pending.len() == self.hashes.len()
            || receiver_count > 1
            || (receiver_count == 1 && !video_receiver)
            || (receiver_count == 1 && self.pending.iter().any(|row| row.receiver_count == 1))
            || (receiver_count == 0 && self.pending.iter().any(|row| row.receiver_count == 1))
        {
            return Err(Error::Signaling);
        }
        self.pending.push(PendingSubscriberOffer {
            sdp,
            mid_to_track_id,
            receiver_count,
            video_receiver,
        });
        Ok(())
    }

    pub fn resolve_pending(
        &mut self,
        expected_sid: &str,
        current_receiver_count: usize,
        current_video_receiver: bool,
        current_receiver_identity: Option<bool>,
    ) -> Result<()> {
        if !self.subscribe_requested {
            return Err(Error::Signaling);
        }
        for row in std::mem::take(&mut self.pending) {
            if !row.mid_to_track_id.is_empty()
                && !approved_offer_video_mid(&row.sdp, &row.mid_to_track_id, expected_sid)
            {
                return Err(Error::Signaling);
            }
            if row.receiver_count == 1 && (current_receiver_count != 1 || !current_video_receiver) {
                return Err(Error::Path);
            }
            let approved = row.receiver_count == 1
                && approved_offer_track(
                    &row.sdp,
                    &row.mid_to_track_id,
                    expected_sid,
                    current_receiver_identity,
                );
            self.applied_offer(row.receiver_count, row.video_receiver, approved)?;
        }
        Ok(())
    }
}

/// The SignalResponse mapping must associate the single negotiated video MID
/// with the exact TrackInfo SID already authenticated for the counterpart.
/// No arbitrary substring of an SDP can name the approved track.
pub fn approved_offer_video_mid(
    sdp: &str,
    mid_to_track_id: &HashMap<String, String>,
    expected_sid: &str,
) -> bool {
    if expected_sid.is_empty() || expected_sid.len() > 96 || mid_to_track_id.len() != 1 {
        return false;
    }
    let Some((mid, sid)) = mid_to_track_id.iter().next() else {
        return false;
    };
    if mid.is_empty() || mid.len() > 32 || sid != expected_sid {
        return false;
    }
    let mut videos = sdp
        .split("\r\nm=")
        .skip(1)
        .filter(|section| section.starts_with("video "));
    let Some(video) = videos.next() else {
        return false;
    };
    if videos.next().is_some() {
        return false;
    }
    let expected_mid = format!("a=mid:{mid}");
    video
        .split("\r\n")
        .filter(|line| *line == expected_mid)
        .count()
        == 1
}

pub fn approved_offer_track(
    sdp: &str,
    mid_to_track_id: &HashMap<String, String>,
    expected_sid: &str,
    receiver_identity: Option<bool>,
) -> bool {
    if mid_to_track_id.is_empty() {
        // Protocol 9 can omit the optional MID mapping. In that form the
        // negotiated receiver itself must already carry the approved SID.
        receiver_identity == Some(true)
    } else {
        approved_offer_video_mid(sdp, mid_to_track_id, expected_sid)
            && receiver_identity != Some(false)
    }
}
const MAX_CANDIDATES: usize = 16;
const MAX_RTP_PAYLOAD: usize = 1200;
const MAX_ENCODED: usize = 1024 * 1024;

#[derive(Clone, Copy)]
enum SelectedIceRefusal {
    SenderZero,
    SenderMultiple,
    ReceiverZero,
    ReceiverMultiple,
    ReceiverNotVideo,
    TransportQuery,
    TransportAbsent,
    PairQuery,
    PairAbsent,
    LocalIpShape,
    RemoteIpShape,
    LocalBind,
    RemoteAllowlist,
    LocalProtocol,
    RemoteProtocol,
    LocalPort,
    RemotePort,
    PublisherDeadline,
    SubscriberDeadline,
    PublisherClosed,
    SubscriberClosed,
    PrecheckDeadline,
    PostcheckDeadline,
}

impl SelectedIceRefusal {
    fn fail(self, error: Error) -> Error {
        let reason = match self {
            Self::SenderZero => "sender_zero",
            Self::SenderMultiple => "sender_multiple",
            Self::ReceiverZero => "receiver_zero",
            Self::ReceiverMultiple => "receiver_multiple",
            Self::ReceiverNotVideo => "receiver_not_video",
            Self::TransportQuery => "transport_query",
            Self::TransportAbsent => "transport_absent",
            Self::PairQuery => "pair_query",
            Self::PairAbsent => "pair_absent",
            Self::LocalIpShape => "local_ip_shape",
            Self::RemoteIpShape => "remote_ip_shape",
            Self::LocalBind => "local_bind",
            Self::RemoteAllowlist => "remote_allowlist",
            Self::LocalProtocol => "local_protocol",
            Self::RemoteProtocol => "remote_protocol",
            Self::LocalPort => "local_port",
            Self::RemotePort => "remote_port",
            Self::PublisherDeadline => "publisher_deadline",
            Self::SubscriberDeadline => "subscriber_deadline",
            Self::PublisherClosed => "publisher_closed",
            Self::SubscriberClosed => "subscriber_closed",
            Self::PrecheckDeadline => "precheck_deadline",
            Self::PostcheckDeadline => "postcheck_deadline",
        };
        eprintln!("sfu_selected_ice_refused reason={reason}");
        error
    }
}

#[derive(Clone, Copy)]
enum TrickleRefusalPhase {
    Length,
    JsonShape,
    CandidatePolicy,
    RemoteDescription,
    PeerAdd,
    QueueCapacity,
}

impl TrickleRefusalPhase {
    fn report(self) {
        let phase = match self {
            Self::Length => "length",
            Self::JsonShape => "json_shape",
            Self::CandidatePolicy => "candidate_policy",
            Self::RemoteDescription => "remote_description_absent",
            Self::PeerAdd => "peer_add",
            Self::QueueCapacity => "queue_capacity",
        };
        // This enum is source-fixed. Never emit candidate, ufrag, SDP, or the
        // dependency's error string into logs or receipts.
        eprintln!("sfu_trickle_refused phase={phase}");
    }
}
const FRAME_PERIOD: Duration = Duration::from_millis(100);

/// Retains a caller-owned session lease until every WebRTC driver and peer
/// close task has actually dropped. The lease may be a platform WorkGate
/// permit; a task handle being aborted is not equivalent to task exit.
#[derive(Clone)]
pub struct MediaTaskScope {
    inner: Arc<MediaTaskScopeInner>,
}

struct MediaTaskScopeInner {
    _lease: Arc<dyn Send + Sync>,
    closing: watch::Sender<bool>,
}

pub struct MediaTaskOwner(MediaTaskScope);

struct ScopedTask {
    future: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    scope: Option<MediaTaskScope>,
}

impl Drop for ScopedTask {
    fn drop(&mut self) {
        // Also runs if Tokio aborts the wrapper before its first poll.
        drop(self.future.take());
        drop(self.scope.take());
    }
}

impl MediaTaskOwner {
    pub fn new(lease: Arc<dyn Send + Sync>) -> (Self, MediaTaskScope) {
        let (closing, _) = watch::channel(false);
        let scope = MediaTaskScope {
            inner: Arc::new(MediaTaskScopeInner {
                _lease: lease,
                closing,
            }),
        };
        (Self(scope.clone()), scope)
    }
}

impl Drop for MediaTaskOwner {
    fn drop(&mut self) {
        self.0.inner.closing.send_replace(true);
    }
}

impl MediaTaskScope {
    fn wrap(
        &self,
        future: Pin<Box<dyn Future<Output = ()> + Send>>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let mut task = ScopedTask {
            future: Some(future),
            scope: Some(self.clone()),
        };
        Box::pin(async move {
            let mut closing = task
                .scope
                .as_ref()
                .expect("scope held")
                .inner
                .closing
                .subscribe();
            if !*closing.borrow() {
                tokio::select! {
                    biased;
                    _ = closing.changed() => {},
                    () = task.future.as_mut().expect("future held").as_mut() => {},
                }
            }
            drop(closing);
            drop(task);
        })
    }
}

/// Explicit media listener and self-hosted SFU addresses. DNS/STUN defaults
/// and an unconstrained remote candidate are never admitted.
pub struct SfuPath {
    pub bind: SocketAddr,
    pub allowed_sfu_ips: Vec<IpAddr>,
}

/// The physical-network owner must admit every exact UDP tuple in one
/// bounded batch before the ICE backend receives an SDP or trickle. The
/// callback retains its own scoped filter leases until the media peer ends.
pub type CandidateAuthorizer = Arc<dyn Fn(&[SocketAddr]) -> Result<()> + Send + Sync>;

/// Invoked on each freshly bound ICE socket before the WebRTC reactor can
/// send or receive. The owner must bind its physical interface and verify
/// its local address and epoch; failure closes the socket before wrapping.
pub type UdpSocketBinder = Arc<dyn Fn(&UdpSocket) -> io::Result<()> + Send + Sync>;

struct BoundIceRuntime {
    binder: UdpSocketBinder,
    scope: Option<MediaTaskScope>,
}

impl std::fmt::Debug for BoundIceRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BoundIceRuntime")
    }
}

impl Runtime for BoundIceRuntime {
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) -> Box<dyn JoinHandle> {
        let guarded = match &self.scope {
            Some(scope) => scope.wrap(future),
            None => future,
        };
        Runtime::spawn(&TokioRuntime, guarded)
    }

    fn spawn_reactor(
        &self,
        reactor_pool_size: usize,
        future: Pin<Box<dyn Future<Output = ()> + Send>>,
    ) -> Box<dyn JoinHandle> {
        let guarded = match &self.scope {
            Some(scope) => scope.wrap(future),
            None => future,
        };
        Runtime::spawn_reactor(&TokioRuntime, reactor_pool_size, guarded)
    }

    fn wrap_udp_socket(&self, socket: UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        (self.binder)(&socket)?;
        Runtime::wrap_udp_socket(&TokioRuntime, socket)
    }

    fn wrap_tcp_listener(
        &self,
        _listener: std::net::TcpListener,
    ) -> io::Result<Arc<dyn AsyncTcpListener>> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "ICE TCP refused",
        ))
    }

    fn connect_tcp<'a>(
        &'a self,
        _remote_addr: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<Arc<dyn AsyncTcpStream>>> + Send + 'a>> {
        Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "ICE TCP refused",
            ))
        })
    }

    fn resolve_host<'a>(
        &'a self,
        host: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'a>> {
        Box::pin(async move {
            host.parse::<SocketAddr>()
                .map(|address| vec![address])
                .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "ICE DNS refused"))
        })
    }

    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        Runtime::sleep(&TokioRuntime, duration)
    }

    fn interval(&self, period: Duration) -> Box<dyn AsyncInterval> {
        Runtime::interval(&TokioRuntime, period)
    }

    fn block_on(&self, future: Pin<Box<dyn Future<Output = ()> + '_>>) {
        Runtime::block_on(&TokioRuntime, future)
    }
}

impl SfuPath {
    pub fn validate(&self) -> Result<()> {
        if self.bind.port() != 0
            || self.bind.ip().is_unspecified()
            || self.bind.ip().is_multicast()
            || self.allowed_sfu_ips.is_empty()
            || self.allowed_sfu_ips.len() > 8
            || self
                .allowed_sfu_ips
                .iter()
                .any(|ip| ip.is_unspecified() || ip.is_multicast())
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }

    fn candidate_addresses(&self, sdp: &str) -> Result<Vec<SocketAddr>> {
        if sdp.len() > MAX_SDP || !sdp.starts_with("v=0\r\n") || sdp.bytes().any(|b| b == 0) {
            return Err(Error::Path);
        }
        let mut addresses = Vec::new();
        for line in sdp.lines().filter(|line| line.starts_with("a=candidate:")) {
            if addresses.len() == MAX_CANDIDATES {
                return Err(Error::Path);
            }
            addresses.push(self.candidate_address(line.trim_start_matches("a="))?);
        }
        // LiveKit can trickle later; every trickled candidate is checked too.
        Ok(addresses)
    }

    fn check_candidate(&self, value: &str) -> Result<()> {
        self.candidate_address(value).map(|_| ())
    }

    fn candidate_address(&self, value: &str) -> Result<SocketAddr> {
        let fields: Vec<_> = value.split_ascii_whitespace().collect();
        if fields.len() < 8
            || !fields[0].starts_with("candidate:")
            || !fields[2].eq_ignore_ascii_case("udp")
            || fields[6] != "typ"
        {
            return Err(Error::Path);
        }
        let ip: IpAddr = fields[4].parse().map_err(|_| Error::Path)?;
        let port: u16 = fields[5].parse().map_err(|_| Error::Path)?;
        if port == 0 || !self.allowed_sfu_ips.contains(&ip) {
            return Err(Error::Path);
        }
        Ok(SocketAddr::new(ip, port))
    }
}

struct MediaHandler {
    gathered: watch::Sender<bool>,
    connected: watch::Sender<bool>,
    tracks: mpsc::Sender<Arc<dyn TrackRemote>>,
}
#[async_trait]
impl PeerConnectionEventHandler for MediaHandler {
    async fn on_ice_gathering_state_change(&self, state: RTCIceGatheringState) {
        if state == RTCIceGatheringState::Complete {
            self.gathered.send_replace(true);
        }
    }
    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        self.connected
            .send_replace(state == RTCPeerConnectionState::Connected);
    }
    async fn on_track(&self, track: Arc<dyn TrackRemote>) {
        let _ = self.tracks.try_send(track);
    }
    async fn on_data_channel(&self, channel: Arc<dyn DataChannel>) {
        let _ = tokio::time::timeout(Duration::from_secs(1), channel.close()).await;
    }
}

struct OwnedPeer(Arc<dyn PeerConnection>, Option<MediaTaskScope>);

// An aborted, not-yet-polled close future drops fields in declaration order:
// the peer (socket/keys) before its last possible gate-lease scope reference.
struct CloseOwnedPeer {
    peer: Option<Arc<dyn PeerConnection>>,
    scope: Option<MediaTaskScope>,
}

impl Drop for CloseOwnedPeer {
    fn drop(&mut self) {
        drop(self.peer.take());
        drop(self.scope.take());
    }
}

impl Drop for OwnedPeer {
    fn drop(&mut self) {
        let close = CloseOwnedPeer {
            peer: Some(self.0.clone()),
            scope: self.1.clone(),
        };
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = tokio::time::timeout(
                    Duration::from_secs(2),
                    close.peer.as_ref().expect("peer held").close(),
                )
                .await;
                drop(close);
            });
        }
    }
}

async fn make_peer(
    path: &SfuPath,
    binder: Option<UdpSocketBinder>,
    scope: Option<MediaTaskScope>,
) -> Result<(
    OwnedPeer,
    watch::Receiver<bool>,
    watch::Receiver<bool>,
    mpsc::Receiver<Arc<dyn TrackRemote>>,
)> {
    let (gathered_tx, gathered_rx) = watch::channel(false);
    let (connected_tx, connected_rx) = watch::channel(false);
    let (track_tx, track_rx) = mpsc::channel(1);
    let mut engine = MediaEngine::default();
    engine
        .register_codec(
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_VP8.to_owned(),
                    clock_rate: 90_000,
                    channels: 0,
                    sdp_fmtp_line: String::new(),
                    rtcp_feedback: vec![],
                },
                payload_type: 96,
            },
            RtpCodecKind::Video,
        )
        .map_err(|_| Error::Configuration)?;
    let interceptors = register_default_interceptors(Registry::new(), &mut engine)
        .map_err(|_| Error::Configuration)?;
    let setting = SettingEngineBuilder::new()
        .with_crypto_provider(Arc::new(
            webrtc::peer_connection::crypto::providers::RingProvider::new(),
        ))
        .with_multicast_dns_mode(rtc::ice::mdns::MulticastDnsMode::Disabled)
        .with_include_loopback_candidate(path.bind.ip().is_loopback())
        .build();
    let pc = PeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_setting_engine(setting)
        .with_media_engine(engine)
        .with_interceptor_registry(interceptors)
        .with_handler(Arc::new(MediaHandler {
            gathered: gathered_tx,
            connected: connected_tx,
            tracks: track_tx,
        }))
        .with_runtime(match binder {
            Some(binder) => Arc::new(BoundIceRuntime {
                binder,
                scope: scope.clone(),
            }) as Arc<dyn Runtime>,
            None => Arc::new(TokioRuntime),
        })
        .with_udp_addrs(vec![path.bind.to_string()])
        .build()
        .await
        .map_err(|_| Error::Negotiation)?;
    Ok((
        OwnedPeer(Arc::new(pc), scope),
        gathered_rx,
        connected_rx,
        track_rx,
    ))
}

/// One codec state per direction; a transport reconnect requires a new broker
/// issuance. No caller can reset the AEAD sequence within this owner.
pub struct SfuMediaPeer {
    publisher: OwnedPeer,
    subscriber: OwnedPeer,
    publisher_gathered: watch::Receiver<bool>,
    subscriber_gathered: watch::Receiver<bool>,
    publisher_connected: watch::Receiver<bool>,
    subscriber_connected: watch::Receiver<bool>,
    remote_tracks: mpsc::Receiver<Arc<dyn TrackRemote>>,
    remote_track: Option<Arc<dyn TrackRemote>>,
    remote_sid: Option<String>,
    sample_builder: SampleBuilder<Vp8Packet>,
    local_track: Arc<TrackLocalStaticSample>,
    local_ssrc: u32,
    local_name: String,
    remote_name: String,
    send: SendCodec,
    receive: ReceiveCodec,
    vp8: Vp8GridCodec,
    path: SfuPath,
    candidate_authorizer: Option<CandidateAuthorizer>,
    deadline: Instant,
    media_deadline: Instant,
}

impl SfuMediaPeer {
    pub async fn new(descriptor: ProvisionedSession, path: SfuPath) -> Result<Self> {
        Self::new_with_authorizer(descriptor, path, None).await
    }

    pub async fn new_with_authorizer(
        descriptor: ProvisionedSession,
        path: SfuPath,
        candidate_authorizer: Option<CandidateAuthorizer>,
    ) -> Result<Self> {
        Self::new_with_network(descriptor, path, candidate_authorizer, None).await
    }

    pub async fn new_with_network(
        descriptor: ProvisionedSession,
        path: SfuPath,
        candidate_authorizer: Option<CandidateAuthorizer>,
        socket_binder: Option<UdpSocketBinder>,
    ) -> Result<Self> {
        Self::new_with_network_scoped(descriptor, path, candidate_authorizer, socket_binder, None)
            .await
    }

    pub async fn new_with_network_scoped(
        descriptor: ProvisionedSession,
        path: SfuPath,
        candidate_authorizer: Option<CandidateAuthorizer>,
        socket_binder: Option<UdpSocketBinder>,
        scope: Option<MediaTaskScope>,
    ) -> Result<Self> {
        // A scoped owner cannot fall back to the library's untracked default
        // runtime, even for a transient negotiation peer.
        if scope.is_some() && socket_binder.is_none() {
            return Err(Error::Configuration);
        }
        path.validate()?;
        let (local_name, remote_name) = match descriptor.role() {
            Role::Client => (
                descriptor.track_names().0.to_owned(),
                descriptor.track_names().1.to_owned(),
            ),
            Role::Intermediary => (
                descriptor.track_names().1.to_owned(),
                descriptor.track_names().0.to_owned(),
            ),
        };
        let remaining = descriptor.remaining_for_issuer();
        if remaining.is_zero() {
            return Err(Error::Deadline);
        }
        let deadline = Instant::now() + remaining;
        let (send, receive) = descriptor.split().map_err(|_| Error::Admission)?;
        let media_deadline = send.active_until();
        let (publisher, publisher_gathered, publisher_connected, _) =
            make_peer(&path, socket_binder.clone(), scope.clone()).await?;
        let (subscriber, subscriber_gathered, subscriber_connected, remote_tracks) =
            make_peer(&path, socket_binder, scope).await?;
        let ssrc = rand::random::<u32>();
        if ssrc == 0 {
            return Err(Error::Configuration);
        }
        let codec = RTCRtpCodec {
            mime_type: MIME_TYPE_VP8.to_owned(),
            clock_rate: 90_000,
            channels: 0,
            sdp_fmtp_line: String::new(),
            rtcp_feedback: vec![],
        };
        let track = Arc::new(
            TrackLocalStaticSample::new(
                Instant::now(),
                MediaStreamTrack::new(
                    "aegis-sfu-video".to_owned(),
                    local_name.clone(),
                    local_name.clone(),
                    RtpCodecKind::Video,
                    vec![RTCRtpEncodingParameters {
                        rtp_coding_parameters: RTCRtpCodingParameters {
                            ssrc: Some(ssrc),
                            ..Default::default()
                        },
                        codec,
                        ..Default::default()
                    }],
                ),
            )
            .map_err(|_| Error::Negotiation)?,
        );
        publisher
            .0
            .add_track(track.clone() as Arc<dyn TrackLocal>)
            .await
            .map_err(|_| Error::Negotiation)?;
        Ok(Self {
            publisher,
            subscriber,
            publisher_gathered,
            subscriber_gathered,
            publisher_connected,
            subscriber_connected,
            remote_tracks,
            remote_track: None,
            remote_sid: None,
            sample_builder: SampleBuilder::new(16, Vp8Packet::default(), 90_000)
                .with_max_time_delay(Duration::from_millis(500)),
            local_track: track,
            local_ssrc: ssrc,
            local_name,
            remote_name,
            send,
            receive,
            vp8: Vp8GridCodec::new().map_err(|_| Error::Configuration)?,
            path,
            candidate_authorizer,
            deadline,
            media_deadline,
        })
    }

    pub fn local_track_name(&self) -> &str {
        &self.local_name
    }
    pub fn remote_track_name(&self) -> &str {
        &self.remote_name
    }

    pub async fn subscriber_receiver_state(
        &self,
        expected_sid: Option<&str>,
        expected_identity: &str,
    ) -> (usize, bool, Option<bool>) {
        let receivers = self.subscriber.0.get_receivers().await;
        if receivers.len() != 1 {
            return (receivers.len(), false, None);
        }
        let track = receivers[0].track();
        let video = track.kind().await == RtpCodecKind::Video;
        let track_id = track.track_id().await;
        let stream_id = track.stream_id().await;
        let identity = expected_sid.and_then(|sid| {
            if track_id.is_empty() && stream_id.is_empty() {
                None
            } else {
                Some(remote_track_sid_matches(
                    &track_id,
                    &stream_id,
                    sid,
                    expected_identity,
                ))
            }
        });
        (receivers.len(), video, identity)
    }

    /// Validate the actually nominated RTP ICE pair. A signed SDP and an
    /// allowlisted trickle candidate alone cannot establish the path used by
    /// the kernel after ICE nomination.
    pub async fn verify_selected_paths(&self) -> Result<()> {
        let senders = self.publisher.0.get_senders().await;
        let receivers = self.subscriber.0.get_receivers().await;
        if senders.is_empty() {
            return Err(SelectedIceRefusal::SenderZero.fail(Error::Path));
        }
        if senders.len() != 1 {
            return Err(SelectedIceRefusal::SenderMultiple.fail(Error::Path));
        }
        if receivers.is_empty() {
            return Err(SelectedIceRefusal::ReceiverZero.fail(Error::Path));
        }
        if receivers.len() != 1 {
            return Err(SelectedIceRefusal::ReceiverMultiple.fail(Error::Path));
        }
        if receivers[0].track().kind().await != RtpCodecKind::Video {
            return Err(SelectedIceRefusal::ReceiverNotVideo.fail(Error::Path));
        }
        for transport in [
            senders[0]
                .transport()
                .await
                .map_err(|_| SelectedIceRefusal::TransportQuery.fail(Error::Path))?,
            receivers[0]
                .transport()
                .await
                .map_err(|_| SelectedIceRefusal::TransportQuery.fail(Error::Path))?,
        ] {
            let dtls =
                transport.ok_or_else(|| SelectedIceRefusal::TransportAbsent.fail(Error::Path))?;
            let pair = dtls
                .ice_transport()
                .get_selected_candidate_pair()
                .await
                .map_err(|_| SelectedIceRefusal::PairQuery.fail(Error::Path))?
                .ok_or_else(|| SelectedIceRefusal::PairAbsent.fail(Error::Path))?;
            let local = pair.local();
            let remote = pair.remote();
            let local_ip: IpAddr = local
                .address
                .parse()
                .map_err(|_| SelectedIceRefusal::LocalIpShape.fail(Error::Path))?;
            let remote_ip: IpAddr = remote
                .address
                .parse()
                .map_err(|_| SelectedIceRefusal::RemoteIpShape.fail(Error::Path))?;
            if local_ip != self.path.bind.ip() {
                return Err(SelectedIceRefusal::LocalBind.fail(Error::Path));
            }
            if !self.path.allowed_sfu_ips.contains(&remote_ip) {
                return Err(SelectedIceRefusal::RemoteAllowlist.fail(Error::Path));
            }
            if local.protocol != RTCIceProtocol::Udp {
                return Err(SelectedIceRefusal::LocalProtocol.fail(Error::Path));
            }
            if remote.protocol != RTCIceProtocol::Udp {
                return Err(SelectedIceRefusal::RemoteProtocol.fail(Error::Path));
            }
            if local.port == 0 {
                return Err(SelectedIceRefusal::LocalPort.fail(Error::Path));
            }
            if remote.port == 0 {
                return Err(SelectedIceRefusal::RemotePort.fail(Error::Path));
            }
        }
        Ok(())
    }

    pub async fn wait_connected(&mut self) -> Result<()> {
        for (rx, deadline, closed) in [
            (
                &mut self.publisher_connected,
                SelectedIceRefusal::PublisherDeadline,
                SelectedIceRefusal::PublisherClosed,
            ),
            (
                &mut self.subscriber_connected,
                SelectedIceRefusal::SubscriberDeadline,
                SelectedIceRefusal::SubscriberClosed,
            ),
        ] {
            while !*rx.borrow_and_update() {
                tokio::time::timeout_at(self.deadline.into(), rx.changed())
                    .await
                    .map_err(|_| deadline.fail(Error::Deadline))?
                    .map_err(|_| closed.fail(Error::Negotiation))?;
            }
        }
        if Instant::now() >= self.deadline {
            return Err(SelectedIceRefusal::PrecheckDeadline.fail(Error::Deadline));
        }
        self.verify_selected_paths().await?;
        if Instant::now() >= self.deadline {
            return Err(SelectedIceRefusal::PostcheckDeadline.fail(Error::Deadline));
        }
        // SDP/ICE must finish within the short broker grant, but the already
        // authenticated media stream is governed by its own finite lifetime.
        self.deadline = self.media_deadline;
        Ok(())
    }

    pub fn media_deadline(&self) -> Instant {
        self.media_deadline
    }

    async fn wait_gathered(rx: &mut watch::Receiver<bool>, deadline: Instant) -> Result<()> {
        while !*rx.borrow_and_update() {
            tokio::time::timeout_at(deadline.into(), rx.changed())
                .await
                .map_err(|_| Error::Deadline)?
                .map_err(|_| Error::Negotiation)?;
        }
        Ok(())
    }

    pub async fn publisher_offer(&mut self) -> Result<String> {
        let mut step = "create_offer";
        let result = self.publisher_offer_inner(&mut step).await;
        if result.is_err() {
            // Fixed token only; never log SDP, ICE, peer identities, or the
            // underlying dependency error text.
            eprintln!("sfu_peer_refused phase=publisher_offer step={step}");
        }
        result
    }

    async fn publisher_offer_inner(&mut self, step: &mut &'static str) -> Result<String> {
        let offer = self
            .publisher
            .0
            .create_offer(None)
            .await
            .map_err(|_| Error::Negotiation)?;
        *step = "set_local_description";
        self.publisher
            .0
            .set_local_description(offer)
            .await
            .map_err(|_| Error::Negotiation)?;
        *step = "wait_gathered";
        Self::wait_gathered(&mut self.publisher_gathered, self.deadline).await?;
        *step = "local_description";
        let local = self
            .publisher
            .0
            .local_description()
            .await
            .ok_or(Error::Negotiation)?;
        *step = "sdp_bounds";
        if local.sdp.len() > MAX_SDP {
            return Err(Error::Path);
        }
        Ok(local.sdp)
    }

    pub async fn apply_publisher_answer(&self, sdp: String) -> Result<()> {
        self.authorize_remote_sdp(&sdp)?;
        let answer = RTCSessionDescription::answer(sdp).map_err(|_| Error::Negotiation)?;
        self.publisher
            .0
            .set_remote_description(answer)
            .await
            .map_err(|_| Error::Negotiation)
    }

    pub async fn answer_subscriber_offer(&mut self, sdp: String) -> Result<String> {
        self.authorize_remote_sdp(&sdp)?;
        let offer = RTCSessionDescription::offer(sdp).map_err(|_| Error::Negotiation)?;
        self.subscriber
            .0
            .set_remote_description(offer)
            .await
            .map_err(|_| Error::Negotiation)?;
        let answer = self
            .subscriber
            .0
            .create_answer(None)
            .await
            .map_err(|_| Error::Negotiation)?;
        self.subscriber
            .0
            .set_local_description(answer)
            .await
            .map_err(|_| Error::Negotiation)?;
        Self::wait_gathered(&mut self.subscriber_gathered, self.deadline).await?;
        let local = self
            .subscriber
            .0
            .local_description()
            .await
            .ok_or(Error::Negotiation)?;
        if local.sdp.len() > MAX_SDP {
            return Err(Error::Path);
        }
        Ok(local.sdp)
    }

    fn checked_trickle_json(&self, encoded: &str) -> Result<RTCIceCandidateInit> {
        if encoded.len() > 4096 {
            TrickleRefusalPhase::Length.report();
            return Err(Error::Path);
        }
        let candidate: RTCIceCandidateInit = serde_json::from_str(encoded).map_err(|_| {
            TrickleRefusalPhase::JsonShape.report();
            Error::Path
        })?;
        self.path
            .check_candidate(&candidate.candidate)
            .inspect_err(|_| {
                TrickleRefusalPhase::CandidatePolicy.report();
            })?;
        if let Some(authorize) = &self.candidate_authorizer {
            let socket = self.path.candidate_address(&candidate.candidate)?;
            authorize(&[socket])?;
        }
        Ok(candidate)
    }

    fn authorize_remote_sdp(&self, sdp: &str) -> Result<()> {
        let sockets = self.path.candidate_addresses(sdp)?;
        if let Some(authorize) = &self.candidate_authorizer {
            authorize(&sockets)?;
        }
        Ok(())
    }

    pub async fn apply_trickle_json(&self, encoded: &str, publisher: bool) -> Result<()> {
        let candidate = self.checked_trickle_json(encoded)?;
        let pc = if publisher {
            &self.publisher.0
        } else {
            &self.subscriber.0
        };
        let added = pc.add_ice_candidate(candidate).await;
        if added.is_err() {
            if pc.remote_description().await.is_none() {
                TrickleRefusalPhase::RemoteDescription.report();
            } else {
                TrickleRefusalPhase::PeerAdd.report();
            }
        }
        added.map_err(|_| Error::Negotiation)
    }

    pub async fn send_frame(&mut self, kind: FrameKind, payload: &[u8]) -> Result<[u8; 64]> {
        if Instant::now() >= self.deadline || !*self.publisher_connected.borrow() {
            return Err(Error::Deadline);
        }
        let sealed = self.send.seal_next(kind, payload).map_err(map_media)?;
        self.retransmit(&sealed).await?;
        Ok(sealed)
    }

    /// Retransmit the same AEAD wire. A fresh VP8 keyframe is allowed; a
    /// fresh AEAD nonce or sequence for retransmission is not.
    pub async fn retransmit(&mut self, sealed: &[u8; 64]) -> Result<()> {
        if Instant::now() >= self.deadline || !*self.publisher_connected.borrow() {
            return Err(Error::Deadline);
        }
        self.verify_selected_paths().await?;
        let encoded = self.vp8.encode_wire(sealed).map_err(map_media)?;
        if encoded.is_empty() || encoded.len() > MAX_ENCODED {
            return Err(Error::Channel);
        }
        let sample = Sample {
            data: Bytes::from(encoded),
            duration: FRAME_PERIOD,
            ..Sample::new(Instant::now())
        };
        tokio::time::timeout_at(
            self.deadline.into(),
            self.local_track
                .sample_writer(self.local_ssrc, 96)
                .write_sample(&sample),
        )
        .await
        .map_err(|_| Error::Deadline)?
        .map_err(|_| Error::Channel)
    }

    /// The remote SID must come from a verified LiveKit TrackPublished event
    /// for the opposite broker-bound CID. A self-declared track name is never
    /// sufficient to grant plaintext.
    pub async fn receive_frame(
        &mut self,
        expected_remote_sid: &str,
        expected_remote_identity: &str,
    ) -> Result<ReceivedFrame> {
        if expected_remote_sid.is_empty()
            || expected_remote_sid.len() > 96
            || expected_remote_identity.is_empty()
            || expected_remote_identity.len() > 96
            || expected_remote_identity.contains('|')
        {
            return Err(Error::Admission);
        }
        self.verify_selected_paths().await?;
        if let Some(sid) = &self.remote_sid {
            if sid != expected_remote_sid {
                return Err(Error::Admission);
            }
        } else {
            let track = tokio::time::timeout_at(self.deadline.into(), self.remote_tracks.recv())
                .await
                .map_err(|_| Error::Deadline)?
                .ok_or(Error::Channel)?;
            // LiveKit's media stream ID is normally packed as
            // "publisher-identity|TR...". Its client SDK checks that first,
            // then accepts a direct media-track ID. Bind either form to the
            // already verified counterpart identity and TrackInfo SID.
            let stream_id = track.stream_id().await;
            let track_id = track.track_id().await;
            if !remote_track_sid_matches(
                &track_id,
                &stream_id,
                expected_remote_sid,
                expected_remote_identity,
            ) {
                return Err(Error::Admission);
            }
            self.remote_sid = Some(expected_remote_sid.to_owned());
            self.remote_track = Some(track);
        }
        let track = self.remote_track.as_ref().ok_or(Error::Channel)?;
        while Instant::now() < self.deadline && *self.subscriber_connected.borrow() {
            match tokio::time::timeout_at(self.deadline.into(), track.poll())
                .await
                .map_err(|_| Error::Deadline)?
            {
                Some(webrtc::media_stream::track_remote::TrackRemoteEvent::OnRtpPacket(packet)) => {
                    if packet.payload.len() > MAX_RTP_PAYLOAD {
                        return Err(Error::Channel);
                    }
                    self.sample_builder.push(Instant::now(), packet);
                    if let Some(sample) = self.sample_builder.pop(Instant::now()) {
                        let wire = self.vp8.decode_wire(&sample.data).map_err(map_media)?;
                        return self.receive.open(&wire).map_err(map_media);
                    }
                }
                Some(webrtc::media_stream::track_remote::TrackRemoteEvent::OnError)
                | Some(webrtc::media_stream::track_remote::TrackRemoteEvent::OnEnded)
                | None => return Err(Error::Channel),
                _ => {}
            }
        }
        Err(Error::Deadline)
    }
}

/// A signal can carry a numeric allowlisted ICE candidate before the matching
/// remote SDP. The underlying RTC peer refuses that ordering. Validate at the
/// untrusted boundary, retain at most 16 secret-bearing candidates, then apply
/// only after that target's remote description is installed.
#[derive(Default)]
pub struct PendingTrickles {
    entries: Vec<(Zeroizing<String>, bool)>,
}

impl PendingTrickles {
    pub fn queue(
        &mut self,
        peer: &SfuMediaPeer,
        candidate_init: Zeroizing<String>,
        publisher: bool,
    ) -> Result<()> {
        peer.checked_trickle_json(&candidate_init)?;
        if self.entries.len() >= 16 {
            TrickleRefusalPhase::QueueCapacity.report();
            return Err(Error::Path);
        }
        self.entries.push((candidate_init, publisher));
        Ok(())
    }

    pub async fn flush(&mut self, peer: &SfuMediaPeer, publisher: bool) -> Result<()> {
        let mut other_target = Vec::new();
        for (candidate, target) in std::mem::take(&mut self.entries) {
            if target == publisher {
                peer.apply_trickle_json(&candidate, target).await?;
            } else {
                other_target.push((candidate, target));
            }
        }
        self.entries = other_target;
        Ok(())
    }
}

fn remote_track_sid_matches(
    track_id: &str,
    stream_id: &str,
    expected_sid: &str,
    expected_identity: &str,
) -> bool {
    if let Some((identity, sid)) = stream_id.split_once('|') {
        return identity == expected_identity && sid == expected_sid;
    }
    track_id == expected_sid
}

fn map_media(_: MediaError) -> Error {
    Error::Channel
}

#[cfg(test)]
mod tests {
    #[test]
    fn official_control_notices_bind_roles_without_granting_media() {
        use super::{parse_control_notice, PermissionUpdateWire, SfuControlNoticeWindow};
        use prost::Message as _;
        let permission = PermissionUpdateWire {
            participant_sid: "PA_remote".into(),
            track_sid: "TR_remote".into(),
            allowed: true,
        }
        .encode_to_vec();
        let mut pending = SfuControlNoticeWindow::default();
        pending
            .observe(parse_control_notice(15, &permission).unwrap())
            .unwrap();
        pending.bind_remote("PA_remote", "TR_remote").unwrap();

        let mut after = SfuControlNoticeWindow::default();
        after.bind_remote("PA_remote", "TR_remote").unwrap();
        after
            .observe(parse_control_notice(15, &permission).unwrap())
            .unwrap();
        assert!(after
            .observe(parse_control_notice(15, &permission).unwrap())
            .is_err());
    }

    #[test]
    fn control_notices_refuse_revocation_foreign_ids_errors_and_extra_wire() {
        use super::{parse_control_notice, PermissionUpdateWire, SfuControlNoticeWindow};
        use prost::Message as _;
        let denied = PermissionUpdateWire {
            participant_sid: "PA_remote".into(),
            track_sid: "TR_remote".into(),
            allowed: false,
        }
        .encode_to_vec();
        assert!(parse_control_notice(15, &denied).is_err());
        assert!(parse_control_notice(21, &[0x12, 0x01, b'x']).is_err());
        assert!(parse_control_notice(23, &[0x0a, 0x01, b'x']).is_err());
        let good = PermissionUpdateWire {
            participant_sid: "PA_foreign".into(),
            track_sid: "TR_remote".into(),
            allowed: true,
        }
        .encode_to_vec();
        let mut bound = SfuControlNoticeWindow::default();
        bound.bind_remote("PA_remote", "TR_remote").unwrap();
        assert!(bound
            .observe(parse_control_notice(15, &good).unwrap())
            .is_err());
        let mut pending = SfuControlNoticeWindow::default();
        pending
            .observe(parse_control_notice(15, &good).unwrap())
            .unwrap();
        assert!(pending.bind_remote("PA_remote", "TR_remote").is_err());
        let mut extra = good.clone();
        extra.extend_from_slice(&[0x20, 0x01]);
        assert!(parse_control_notice(15, &extra).is_err());
        assert!(parse_control_notice(25, &good).is_err());
        assert!(parse_control_notice(15, &[0xff; 513]).is_err());
    }

    #[test]
    fn refused_signal_coordinates_are_static_and_payload_blind() {
        use super::refused_signal_coordinate;
        // SignalResponse fields in the exact LiveKit 1.13.9 protocol module.
        assert_eq!(refused_signal_coordinate(&[0x4a, 0x01, 0xff]), "mute");
        assert_eq!(
            refused_signal_coordinate(&[0xaa, 0x01, 0x01, 0xff]),
            "subscription_response"
        );
        assert_eq!(
            refused_signal_coordinate(&[0xc2, 0x01, 0x01, 0xff]),
            "room_moved"
        );
        assert_eq!(
            refused_signal_coordinate(&[0x90, 0x01, 0x01]),
            "pong_legacy"
        );
        assert_eq!(
            refused_signal_coordinate(&[0xa8, 0x01, 0x01]),
            "invalid_wire"
        );
        assert_eq!(
            refused_signal_coordinate(&[0xaa, 0x00, 0x00]),
            "invalid_key"
        );
        assert_eq!(
            refused_signal_coordinate(&[0xff, 0xff, 0xff]),
            "invalid_key"
        );
    }

    #[test]
    fn mapped_video_before_track_update_stays_closed_until_exact_sid() {
        use super::{SubscriberOfferWindow, Zeroizing};
        use std::collections::HashMap;
        let sdp = "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:v0\r\n";
        let mapping = HashMap::from([("v0".to_owned(), "TR_approved".to_owned())]);
        let mut window = SubscriberOfferWindow::new();
        window.begin_offer(sdp, 0).unwrap();
        window
            .defer_offer(Zeroizing::new(sdp.to_owned()), mapping, 1, true)
            .unwrap();
        assert!(!window.ready());
        window.request_subscription().unwrap();
        assert!(!window.ready());
        assert!(window.resolve_pending("TR_wrong", 1, true, None).is_err());

        let mut valid = SubscriberOfferWindow::new();
        valid.begin_offer(sdp, 0).unwrap();
        valid
            .defer_offer(
                Zeroizing::new(sdp.to_owned()),
                HashMap::from([("v0".to_owned(), "TR_approved".to_owned())]),
                1,
                true,
            )
            .unwrap();
        valid.request_subscription().unwrap();
        assert!(!valid.ready());
        valid.resolve_pending("TR_approved", 1, true, None).unwrap();
        assert!(valid.ready());
    }

    #[test]
    fn early_empty_then_video_offer_resolves_after_track_update() {
        use super::{SubscriberOfferWindow, Zeroizing};
        use std::collections::HashMap;
        let empty = "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:v0\r\n";
        let video = "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:v1\r\n";
        let mut window = SubscriberOfferWindow::new();
        window.begin_offer(empty, 0).unwrap();
        window
            .defer_offer(
                Zeroizing::new(empty.to_owned()),
                HashMap::from([("v0".to_owned(), "TR_approved".to_owned())]),
                0,
                false,
            )
            .unwrap();
        window.begin_offer(video, 0).unwrap();
        window
            .defer_offer(
                Zeroizing::new(video.to_owned()),
                HashMap::from([("v1".to_owned(), "TR_approved".to_owned())]),
                1,
                true,
            )
            .unwrap();
        window.request_subscription().unwrap();
        assert!(!window.ready());
        window
            .resolve_pending("TR_approved", 1, true, None)
            .unwrap();
        assert!(window.ready());

        let mut repeat = SubscriberOfferWindow::new();
        repeat.begin_offer(video, 0).unwrap();
        repeat
            .defer_offer(Zeroizing::new(video.to_owned()), HashMap::new(), 1, true)
            .unwrap();
        assert!(repeat
            .defer_offer(Zeroizing::new(empty.to_owned()), HashMap::new(), 0, false)
            .is_err());
        repeat.request_subscription().unwrap();
        assert!(repeat
            .resolve_pending("TR_approved", 1, true, None)
            .is_err());
        assert!(!repeat.ready());
    }

    #[test]
    fn subscriber_offer_window_requires_distinct_approved_video_after_subscription() {
        use super::SubscriberOfferWindow;
        let mut window = SubscriberOfferWindow::new();
        window.begin_offer("v=0\r\na=mid:bootstrap\r\n", 0).unwrap();
        window.applied_offer(0, false, false).unwrap();
        assert!(!window.ready());
        window.request_subscription().unwrap();
        assert!(!window.ready());
        assert!(window.begin_offer("v=0\r\na=mid:bootstrap\r\n", 0).is_err());
        window.begin_offer("v=0\r\na=mid:video\r\n", 1).unwrap();
        window.applied_offer(1, true, true).unwrap();
        assert!(window.ready());
        assert!(window.begin_offer("v=0\r\na=mid:other\r\n", 2).is_err());
        assert!(window.request_subscription().is_err());
    }

    #[test]
    fn subscriber_offer_window_refuses_unapproved_or_unbounded_offers() {
        use super::SubscriberOfferWindow;
        let mut wrong_kind = SubscriberOfferWindow::new();
        wrong_kind
            .begin_offer("v=0\r\na=mid:bootstrap\r\n", 0)
            .unwrap();
        wrong_kind.applied_offer(0, false, false).unwrap();
        wrong_kind.request_subscription().unwrap();
        wrong_kind.begin_offer("v=0\r\na=mid:audio\r\n", 1).unwrap();
        assert!(wrong_kind.applied_offer(1, false, true).is_err());

        let mut multiple = SubscriberOfferWindow::new();
        multiple
            .begin_offer("v=0\r\na=mid:bootstrap\r\n", 0)
            .unwrap();
        multiple.applied_offer(0, false, false).unwrap();
        multiple.request_subscription().unwrap();
        multiple.begin_offer("v=0\r\na=mid:one\r\n", 1).unwrap();
        assert!(multiple.applied_offer(2, true, true).is_err());

        let mut no_video = SubscriberOfferWindow::new();
        no_video.request_subscription().unwrap();
        for number in 0..3 {
            no_video
                .begin_offer(&format!("v=0\r\na=mid:{number}\r\n"), number + 1)
                .unwrap();
            no_video.applied_offer(0, false, false).unwrap();
        }
        assert!(!no_video.ready());
        assert!(no_video.begin_offer("v=0\r\na=mid:four\r\n", 4).is_err());

        let mut wrong_track = SubscriberOfferWindow::new();
        wrong_track
            .begin_offer("v=0\r\na=mid:bootstrap\r\n", 0)
            .unwrap();
        wrong_track.applied_offer(0, false, false).unwrap();
        wrong_track.request_subscription().unwrap();
        wrong_track
            .begin_offer("v=0\r\na=mid:video\r\n", 1)
            .unwrap();
        assert!(wrong_track.applied_offer(1, true, false).is_err());

        let mut unsolicited_video = SubscriberOfferWindow::new();
        unsolicited_video
            .begin_offer("v=0\r\na=mid:video\r\n", 1)
            .unwrap();
        assert!(unsolicited_video.applied_offer(1, true, true).is_err());

        let mut stale_id = SubscriberOfferWindow::new();
        stale_id.begin_offer("v=0\r\na=mid:first\r\n", 4).unwrap();
        stale_id.applied_offer(0, false, false).unwrap();
        assert!(stale_id.begin_offer("v=0\r\na=mid:second\r\n", 4).is_err());
        assert!(stale_id.begin_offer("v=0\r\na=mid:second\r\n", 0).is_err());

        let mut protocol_nine = SubscriberOfferWindow::new();
        protocol_nine
            .begin_offer("v=0\r\na=mid:bootstrap\r\n", 0)
            .unwrap();
        protocol_nine.applied_offer(0, false, false).unwrap();
        protocol_nine.request_subscription().unwrap();
        protocol_nine
            .begin_offer("v=0\r\na=mid:video\r\n", 0)
            .unwrap();
        protocol_nine.applied_offer(1, true, true).unwrap();
        assert!(protocol_nine.ready());
    }

    #[test]
    fn subscriber_video_mid_requires_exact_approved_track_and_video_section() {
        use super::{approved_offer_track, approved_offer_video_mid};
        use std::collections::HashMap;
        let sdp = "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:v0\r\n";
        let mut mapping = HashMap::from([("v0".to_owned(), "TR_approved".to_owned())]);
        assert!(approved_offer_video_mid(sdp, &mapping, "TR_approved"));
        assert!(approved_offer_track(sdp, &mapping, "TR_approved", None));
        assert!(!approved_offer_track(
            sdp,
            &mapping,
            "TR_approved",
            Some(false)
        ));
        assert!(approved_offer_track(
            sdp,
            &HashMap::new(),
            "TR_approved",
            Some(true)
        ));
        assert!(!approved_offer_track(
            sdp,
            &HashMap::new(),
            "TR_approved",
            None
        ));
        assert!(!approved_offer_video_mid(sdp, &mapping, "TR_other"));
        assert!(!approved_offer_video_mid(
            "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:other\r\n",
            &mapping,
            "TR_approved"
        ));
        assert!(!approved_offer_video_mid(
            "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:v0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:v1\r\n",
            &mapping, "TR_approved"));
        assert!(!approved_offer_video_mid(
            "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:v0\r\n",
            &mapping,
            "TR_approved"
        ));
        mapping.insert("v1".into(), "TR_other".into());
        assert!(!approved_offer_video_mid(sdp, &mapping, "TR_approved"));
    }

    #[tokio::test]
    async fn scoped_reactor_retains_lease_until_future_is_dropped() {
        use super::*;
        use std::sync::atomic::{AtomicBool, Ordering};
        let lease = Arc::new(());
        let weak = Arc::downgrade(&lease);
        let (owner, scope) = MediaTaskOwner::new(lease.clone());
        drop(lease);
        let dropped = Arc::new(AtomicBool::new(false));
        struct OnDrop(Arc<AtomicBool>);
        impl Drop for OnDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let marker = OnDrop(dropped.clone());
        let (started, ready) = tokio::sync::oneshot::channel();
        let runtime = BoundIceRuntime {
            binder: Arc::new(|_| Ok(())),
            scope: Some(scope.clone()),
        };
        let handle = Runtime::spawn(
            &runtime,
            Box::pin(async move {
                let _marker = marker;
                let _ = started.send(());
                std::future::pending::<()>().await;
            }),
        );
        ready.await.unwrap();
        assert!(weak.upgrade().is_some());
        drop(owner);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !handle.is_finished() || !dropped.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        assert!(dropped.load(Ordering::SeqCst));
        drop(runtime);
        drop(scope);
        assert!(weak.upgrade().is_none());
    }

    #[tokio::test]
    async fn closing_scope_refuses_later_reactor_work() {
        use super::*;
        use std::sync::atomic::{AtomicBool, Ordering};
        let (owner, scope) = MediaTaskOwner::new(Arc::new(()));
        drop(owner);
        let executed = Arc::new(AtomicBool::new(false));
        let flag = executed.clone();
        scope
            .wrap(Box::pin(async move {
                flag.store(true, Ordering::SeqCst);
            }))
            .await;
        assert!(!executed.load(Ordering::SeqCst));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn queued_reactor_drops_secret_before_last_lease_on_initial_close() {
        use super::*;
        use std::sync::atomic::{AtomicBool, Ordering};
        let lease = Arc::new(());
        let weak = Arc::downgrade(&lease);
        let (owner, scope) = MediaTaskOwner::new(lease);
        let secret_dropped = Arc::new(AtomicBool::new(false));
        struct Secret(Arc<AtomicBool>);
        impl Drop for Secret {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let secret = Secret(secret_dropped.clone());
        let runtime = BoundIceRuntime {
            binder: Arc::new(|_| Ok(())),
            scope: Some(scope.clone()),
        };
        let handle = Runtime::spawn(
            &runtime,
            Box::pin(async move {
                let _secret = secret;
                panic!("closing scope polled queued reactor");
            }),
        );
        // A current-thread executor cannot poll the newly queued task until
        // this test yields. Cancellation therefore precedes its first poll.
        drop(owner);
        drop(scope);
        drop(runtime);
        assert!(weak.upgrade().is_some());
        tokio::time::timeout(Duration::from_secs(1), async {
            while !handle.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(secret_dropped.load(Ordering::SeqCst));
        assert!(weak.upgrade().is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn abort_before_first_poll_drops_secret_before_scope_lease() {
        use super::*;
        use std::sync::atomic::{AtomicBool, Ordering};
        let lease = Arc::new(());
        let weak = Arc::downgrade(&lease);
        let (owner, scope) = MediaTaskOwner::new(lease);
        let dropped = Arc::new(AtomicBool::new(false));
        struct Secret(Arc<AtomicBool>);
        impl Drop for Secret {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let secret = Secret(dropped.clone());
        let runtime = BoundIceRuntime {
            binder: Arc::new(|_| Ok(())),
            scope: Some(scope.clone()),
        };
        let handle = Runtime::spawn(
            &runtime,
            Box::pin(async move {
                let _secret = secret;
                std::future::pending::<()>().await;
            }),
        );
        handle.abort();
        drop(owner);
        drop(scope);
        drop(runtime);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !handle.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(dropped.load(Ordering::SeqCst));
        assert!(weak.upgrade().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocked_future_destructor_keeps_lease_until_exit() {
        use super::*;
        let lease = Arc::new(());
        let weak = Arc::downgrade(&lease);
        let (owner, scope) = MediaTaskOwner::new(lease);
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        struct SlowDrop {
            entered: Option<tokio::sync::oneshot::Sender<()>>,
            barrier: Arc<std::sync::Barrier>,
        }
        impl Drop for SlowDrop {
            fn drop(&mut self) {
                if let Some(entered) = self.entered.take() {
                    let _ = entered.send(());
                }
                self.barrier.wait();
            }
        }
        let slow = SlowDrop {
            entered: Some(entered_tx),
            barrier: barrier.clone(),
        };
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(scope.wrap(Box::pin(async move {
            let _slow = slow;
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        })));
        started_rx.await.unwrap();
        drop(owner);
        drop(scope);
        tokio::time::timeout(Duration::from_secs(1), entered_rx)
            .await
            .unwrap()
            .unwrap();
        let retained_during_drop = weak.upgrade().is_some();
        barrier.wait();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert!(retained_during_drop);
        assert!(weak.upgrade().is_none());
    }
    use super::*;

    #[test]
    fn remote_sdp_authorization_batch_contains_only_exact_verified_udp_tuples() {
        let path = SfuPath {
            bind: "127.0.0.1:0".parse().unwrap(),
            allowed_sfu_ips: vec!["192.0.2.20".parse().unwrap()],
        };
        let accepted = "v=0\r\na=candidate:1 1 udp 1234 192.0.2.20 45000 typ host\r\na=candidate:2 1 udp 1234 192.0.2.20 45001 typ host\r\n";
        assert_eq!(
            path.candidate_addresses(accepted).unwrap(),
            vec![
                "192.0.2.20:45000".parse::<SocketAddr>().unwrap(),
                "192.0.2.20:45001".parse::<SocketAddr>().unwrap()
            ]
        );
        let foreign = accepted.replace("192.0.2.20 45001", "192.0.2.21 45001");
        assert!(path.candidate_addresses(&foreign).is_err());
        let tcp = accepted.replace("udp 1234", "tcp 1234");
        assert!(path.candidate_addresses(&tcp).is_err());
    }

    #[test]
    fn livekit_camel_case_trickle_shapes_keep_numeric_udp_policy() {
        let path = SfuPath {
            bind: "127.0.0.1:0".parse().unwrap(),
            allowed_sfu_ips: vec!["127.0.0.1".parse().unwrap()],
        };
        let accepted = r#"{"candidate":"candidate:1 1 udp 1234 127.0.0.1 5555 typ host","sdpMid":"0","sdpMLineIndex":0,"usernameFragment":"private"}"#;
        let parsed: RTCIceCandidateInit = serde_json::from_str(accepted).unwrap();
        assert_eq!(parsed.sdp_mid.as_deref(), Some("0"));
        assert_eq!(parsed.sdp_mline_index, Some(0));
        assert!(path.check_candidate(&parsed.candidate).is_ok());
        // A repeated candidate receives the same path check. Runtime RTC
        // state still decides whether it can be added after remote SDP.
        assert!(path.check_candidate(&parsed.candidate).is_ok());
        for rejected in [
            "candidate:1 1 udp 1234 10.0.0.1 5555 typ host",
            "candidate:1 1 tcp 1234 127.0.0.1 5555 typ host",
            "candidate:1 1 udp 1234 host.local 5555 typ host",
        ] {
            assert!(path.check_candidate(rejected).is_err());
        }
        let negative_index = r#"{"candidate":"candidate:1 1 udp 1234 127.0.0.1 5555 typ host","sdpMid":"0","sdpMLineIndex":-1}"#;
        assert!(serde_json::from_str::<RTCIceCandidateInit>(negative_index).is_err());
    }

    #[tokio::test]
    async fn real_peer_rejects_allowlisted_trickle_before_remote_description() {
        let issuer = crate::sfu_media::MediaIssuer::new(1).unwrap();
        issuer
            .reserve(
                [17; 16],
                [18; 16],
                "early_trickle_room".into(),
                "client_track".into(),
                "server_track".into(),
                Instant::now() + Duration::from_secs(20),
            )
            .unwrap();
        let descriptor = issuer.take(Role::Client, [17; 16], None).unwrap();
        let path = SfuPath {
            bind: "127.0.0.1:0".parse().unwrap(),
            allowed_sfu_ips: vec!["127.0.0.1".parse().unwrap()],
        };
        let peer = SfuMediaPeer::new(descriptor, path).await.unwrap();
        let candidate =
            r#"{"candidate":"candidate:1 1 udp 1234 127.0.0.1 5555 typ host","sdpMid":"0"}"#;
        assert!(matches!(
            peer.apply_trickle_json(candidate, true).await,
            Err(Error::Negotiation)
        ));
        let mut pending = PendingTrickles::default();
        pending
            .queue(&peer, Zeroizing::new(candidate.to_owned()), true)
            .unwrap();
        assert_eq!(pending.entries.len(), 1);
        for rejected in [
            r#"{"candidate":"candidate:1 1 udp 1234 10.0.0.1 5555 typ host"}"#,
            r#"{"candidate":"candidate:1 1 tcp 1234 127.0.0.1 5555 typ host"}"#,
            r#"{"candidate":"candidate:1 1 udp 1234 host.local 5555 typ host"}"#,
        ] {
            assert!(matches!(
                pending.queue(&peer, Zeroizing::new(rejected.to_owned()), true),
                Err(Error::Path)
            ));
            assert_eq!(pending.entries.len(), 1);
        }
        for _ in 1..16 {
            pending
                .queue(&peer, Zeroizing::new(candidate.to_owned()), true)
                .unwrap();
        }
        assert!(matches!(
            pending.queue(&peer, Zeroizing::new(candidate.to_owned()), true),
            Err(Error::Path)
        ));
        assert_eq!(pending.entries.len(), 16);
    }

    #[tokio::test]
    async fn owned_loopback_publishers_gather_real_offers() {
        // Exercise the actual WebRTC publisher and ICE gathering path without
        // LiveKit or a target. The two one-use roles mirror the local media
        // fixture and must each produce an SDP admitted by the other role's
        // numeric ICE policy.
        let issuer = crate::sfu_media::MediaIssuer::new(1).unwrap();
        issuer
            .reserve(
                [7; 16],
                [8; 16],
                "room_1".into(),
                "client_track".into(),
                "server_track".into(),
                Instant::now() + Duration::from_secs(20),
            )
            .unwrap();
        let path = || SfuPath {
            bind: "127.0.0.1:0".parse().unwrap(),
            allowed_sfu_ips: vec!["127.0.0.1".parse().unwrap()],
        };
        let client = issuer.take(Role::Client, [7; 16], None).unwrap();
        let intermediary = issuer
            .take(Role::Intermediary, [7; 16], Some([8; 16]))
            .unwrap();
        let (mut client, mut intermediary) = tokio::try_join!(
            SfuMediaPeer::new(client, path()),
            SfuMediaPeer::new(intermediary, path())
        )
        .unwrap();
        let (client_offer, intermediary_offer) =
            tokio::time::timeout(Duration::from_secs(8), async {
                tokio::try_join!(client.publisher_offer(), intermediary.publisher_offer())
            })
            .await
            .expect("loopback ICE gathering deadline")
            .expect("both owned publishers create offers");
        for offer in [&client_offer, &intermediary_offer] {
            assert!(offer.starts_with("v=0\r\n"));
            assert!(offer.contains("m=video "));
            assert!(offer.contains("a=candidate:"));
            path().candidate_addresses(offer).unwrap();
        }
    }

    #[test]
    fn numeric_sfu_candidate_and_explicit_path_only() {
        let path = SfuPath {
            bind: "127.0.0.1:0".parse().unwrap(),
            allowed_sfu_ips: vec!["127.0.0.1".parse().unwrap()],
        };
        assert!(path.validate().is_ok());
        assert!(path
            .check_candidate("candidate:1 1 udp 1234 127.0.0.1 5555 typ host")
            .is_ok());
        assert!(path
            .check_candidate("candidate:1 1 udp 1234 10.0.0.1 5555 typ host")
            .is_err());
        assert!(path
            .check_candidate("candidate:1 1 tcp 1234 127.0.0.1 5555 typ host")
            .is_err());
        assert!(path
            .check_candidate("candidate:1 1 udp 1234 example.com 5555 typ host")
            .is_err());
        assert!(path
            .candidate_addresses("v=0\r\na=candidate:1 1 udp 1234 10.0.0.1 5555 typ host\r\n")
            .is_err());
    }

    #[test]
    fn owned_ice_runtime_refuses_socket_before_reactor_and_never_uses_tcp_or_dns() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let runtime = BoundIceRuntime {
            binder: Arc::new(move |socket| {
                observed.fetch_add(1, Ordering::SeqCst);
                assert!(socket.local_addr()?.ip().is_loopback());
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "epoch changed",
                ))
            }),
            scope: None,
        };
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(runtime.wrap_udp_socket(socket).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let reactor = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        reactor.block_on(async {
            assert!(runtime
                .connect_tcp("127.0.0.1:443".parse().unwrap())
                .await
                .is_err());
            assert!(runtime.resolve_host("sfu.example:443").await.is_err());
            assert_eq!(
                runtime.resolve_host("127.0.0.1:443").await.unwrap(),
                vec!["127.0.0.1:443".parse::<SocketAddr>().unwrap()]
            );
        });
    }

    #[test]
    fn livekit_stream_sid_requires_exact_counterpart_identity() {
        assert!(remote_track_sid_matches(
            "webrtc-track",
            "peer_a|TR_42",
            "TR_42",
            "peer_a"
        ));
        assert!(remote_track_sid_matches(
            "TR_42", "unpacked", "TR_42", "peer_a"
        ));
        assert!(!remote_track_sid_matches(
            "webrtc-track",
            "peer_b|TR_42",
            "TR_42",
            "peer_a"
        ));
        assert!(!remote_track_sid_matches(
            "webrtc-track",
            "peer_a|TR_43",
            "TR_42",
            "peer_a"
        ));
        assert!(!remote_track_sid_matches(
            "webrtc-track",
            "peer_a|TR_42|extra",
            "TR_42",
            "peer_a"
        ));
        assert!(!remote_track_sid_matches(
            "TR_42",
            "peer_b|TR_42",
            "TR_42",
            "peer_a"
        ));
    }
}
