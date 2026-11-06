use crate::{
    signaling::{Operation, SignalingReply, SignalingRequest},
    stream::WebRtcStream,
    AdmissionKey, Error, IcePolicy, Result, Role, Signal, Signaling,
};
use async_trait::async_trait;
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    sync::{mpsc, watch},
    time::Instant,
};
use webrtc::{
    data_channel::{DataChannel, DataChannelEvent, RTCDataChannelInit},
    peer_connection::{
        PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCConfigurationBuilder,
        RTCIceGatheringState, RTCSessionDescription, SettingEngineBuilder,
    },
    runtime::TokioRuntime,
};

pub(crate) const LABEL: &str = "aegis-byte-stream-v1";
pub(crate) const PROTOCOL: &str = "aegis-ordered-reliable-v1";
pub(crate) const CHUNK: usize = 8192;

#[derive(Clone)]
pub struct Cancellation(watch::Sender<bool>);
impl Default for Cancellation {
    fn default() -> Self {
        Self::new()
    }
}
impl Cancellation {
    pub fn new() -> Self {
        let (tx, _) = watch::channel(false);
        Self(tx)
    }
    pub fn cancel(&self) {
        self.0.send_replace(true);
    }
    pub fn is_cancelled(&self) -> bool {
        *self.0.borrow()
    }
    pub(crate) async fn cancelled(&self) {
        let mut rx = self.0.subscribe();
        if *rx.borrow_and_update() {
            return;
        }
        while rx.changed().await.is_ok() {
            if *rx.borrow_and_update() {
                return;
            }
        }
    }
}
/// Numeric local bind and explicit peer/TURN admission. No public STUN defaults.
pub struct CarrierConfig {
    pub bind: SocketAddr,
    pub ice: IcePolicy,
    pub connect_timeout: Duration,
    pub stall_timeout: Duration,
    pub max_lifetime: Duration,
}
impl CarrierConfig {
    pub fn loopback() -> Self {
        Self {
            bind: "127.0.0.1:0".parse().expect("literal"),
            ice: IcePolicy::Loopback,
            connect_timeout: Duration::from_secs(10),
            stall_timeout: Duration::from_secs(5),
            max_lifetime: Duration::from_secs(300),
        }
    }
    fn validate(&self) -> Result<()> {
        self.ice.validate(self.bind)?;
        if self.connect_timeout.is_zero()
            || self.connect_timeout > Duration::from_secs(30)
            || self.stall_timeout.is_zero()
            || self.stall_timeout > Duration::from_secs(30)
            || self.max_lifetime.is_zero()
            || self.max_lifetime > Duration::from_secs(3600)
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}
struct Handler {
    gathered: watch::Sender<bool>,
    channels: mpsc::Sender<Arc<dyn DataChannel>>,
    accepted: AtomicBool,
}
#[async_trait]
impl PeerConnectionEventHandler for Handler {
    async fn on_ice_gathering_state_change(&self, state: RTCIceGatheringState) {
        if state == RTCIceGatheringState::Complete {
            self.gathered.send_replace(true);
        }
    }
    async fn on_data_channel(&self, dc: Arc<dyn DataChannel>) {
        // The driver awaits this callback outside its core locks. Reject inline;
        // no peer can create detached close tasks through repeated DCEP OPENs.
        if self.accepted.swap(true, Ordering::AcqRel) {
            let _ = tokio::time::timeout(Duration::from_secs(1), dc.close()).await;
        } else if let Err(e) = self.channels.try_send(dc) {
            let _ = tokio::time::timeout(Duration::from_secs(1), e.into_inner().close()).await;
        }
    }
}
pub(crate) struct PeerOwner(pub(crate) Option<Arc<dyn PeerConnection>>);
impl PeerOwner {
    fn get(&self) -> &Arc<dyn PeerConnection> {
        self.0.as_ref().expect("live peer")
    }
    fn take(&mut self) -> Arc<dyn PeerConnection> {
        self.0.take().expect("live peer")
    }
}
impl Drop for PeerOwner {
    fn drop(&mut self) {
        if let Some(pc) = self.0.take() {
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    let _ = tokio::time::timeout(Duration::from_secs(2), pc.close()).await;
                });
            }
        }
    }
}
async fn peer(
    config: &CarrierConfig,
) -> Result<(
    PeerOwner,
    watch::Receiver<bool>,
    mpsc::Receiver<Arc<dyn DataChannel>>,
)> {
    let (gathered, rx) = watch::channel(false);
    let (channels, dc_rx) = mpsc::channel(1);
    let (policy, servers) = config.ice.rtc();
    let setting = SettingEngineBuilder::new()
        .with_crypto_provider(Arc::new(
            webrtc::peer_connection::crypto::providers::RingProvider::new(),
        ))
        .with_multicast_dns_mode(rtc::ice::mdns::MulticastDnsMode::Disabled)
        .with_include_loopback_candidate(config.bind.ip().is_loopback())
        .with_sctp_max_message_size(
            rtc::peer_connection::configuration::setting_engine::SctpMaxMessageSize::Bounded(
                (CHUNK + 1) as u32,
            ),
        )
        .with_sctp_max_receive_buffer_size(65536)
        .with_dcep_handshake_timeout(Some(config.connect_timeout))
        .build();
    let pc = PeerConnectionBuilder::new()
        .with_configuration(
            RTCConfigurationBuilder::new()
                .with_ice_servers(servers)
                .with_ice_transport_policy(policy)
                .build(),
        )
        .with_setting_engine(setting)
        .with_handler(Arc::new(Handler {
            gathered,
            channels,
            accepted: AtomicBool::new(false),
        }))
        .with_runtime(Arc::new(TokioRuntime))
        .with_udp_addrs(vec![config.bind.to_string()])
        .with_data_channel_send_buffer_limit(65536)
        .build()
        .await
        .map_err(|_| Error::Negotiation)?;
    Ok((PeerOwner(Some(Arc::new(pc))), rx, dc_rx))
}
async fn gather(rx: &mut watch::Receiver<bool>) -> Result<()> {
    if *rx.borrow_and_update() {
        return Ok(());
    }
    while rx.changed().await.is_ok() {
        if *rx.borrow_and_update() {
            return Ok(());
        }
    }
    Err(Error::Negotiation)
}
async fn opened(dc: &Arc<dyn DataChannel>) -> Result<()> {
    loop {
        match dc.poll().await {
            Some(DataChannelEvent::OnOpen) => break,
            Some(
                DataChannelEvent::OnBufferedAmountLow | DataChannelEvent::OnBufferedAmountHigh,
            ) => {}
            _ => return Err(Error::Channel),
        }
    }
    if dc.label().await.map_err(|_| Error::Channel)? != LABEL
        || dc.protocol().await.map_err(|_| Error::Channel)? != PROTOCOL
        || !dc.ordered().await.map_err(|_| Error::Channel)?
        || dc
            .max_packet_life_time()
            .await
            .map_err(|_| Error::Channel)?
            .is_some()
        || dc
            .max_retransmits()
            .await
            .map_err(|_| Error::Channel)?
            .is_some()
        || dc.negotiated().await.map_err(|_| Error::Channel)?
    {
        return Err(Error::Channel);
    }
    Ok(())
}
async fn evidence(
    pc: &Arc<dyn PeerConnection>,
    config: &CarrierConfig,
) -> Result<(crate::PathEvidence, std::net::IpAddr)> {
    let sctp = pc.sctp().await.ok_or(Error::Path)?;
    let pair = sctp
        .transport()
        .ice_transport()
        .get_selected_candidate_pair()
        .await
        .map_err(|_| Error::Path)?
        .ok_or(Error::Path)?;
    let path = config
        .ice
        .selected(pair.local(), pair.remote(), config.bind)?;
    let peer_ip = pair.remote().address.parse().map_err(|_| Error::Path)?;
    Ok((path, peer_ip))
}
async fn exchange(
    signaling: &Arc<dyn Signaling>,
    role: Role,
    key: &AdmissionKey,
    operation: Operation,
    deadline: Instant,
) -> Result<SignalingReply> {
    signaling
        .exchange(
            SignalingRequest::new(role, key.clone(), operation),
            deadline,
        )
        .await
}
/// Establish an ordered reliable ICE/DTLS/SCTP byte stream. Device mTLS must
/// still be established over the returned stream before any target forwarding.
pub async fn connect(
    config: CarrierConfig,
    signaling: Arc<dyn Signaling>,
    key: AdmissionKey,
    cancel: Cancellation,
) -> Result<WebRtcStream> {
    config.validate()?;
    let deadline = Instant::now() + config.connect_timeout;
    let mut session = None;
    let negotiation = async {
        exchange(&signaling, Role::Client, &key, Operation::Probe, deadline).await?;
        let (mut owner, mut gathered, _) = peer(&config).await?;
        let pc = owner.get();
        let dc = pc
            .create_data_channel(
                LABEL,
                Some(RTCDataChannelInit {
                    protocol: PROTOCOL.to_owned(),
                    ..Default::default()
                }),
            )
            .await
            .map_err(|_| Error::Negotiation)?;
        let offer = pc
            .create_offer(None)
            .await
            .map_err(|_| Error::Negotiation)?;
        pc.set_local_description(offer)
            .await
            .map_err(|_| Error::Negotiation)?;
        gather(&mut gathered).await?;
        let offer = pc.local_description().await.ok_or(Error::Negotiation)?;
        config.ice.check_local_sdp(&offer.sdp, config.bind)?;
        let reply = exchange(
            &signaling,
            Role::Client,
            &key,
            Operation::Submit(Signal::offer(offer.sdp)?),
            deadline,
        )
        .await?;
        let SignalingReply::Submitted(id) = reply else {
            return Err(Error::Signaling);
        };
        session = Some(id);
        let reply = exchange(
            &signaling,
            Role::Client,
            &key,
            Operation::Poll(id),
            deadline,
        )
        .await?;
        let SignalingReply::Answer(answer) = reply else {
            return Err(Error::Signaling);
        };
        answer.validate()?;
        if answer.offer {
            return Err(Error::Signaling);
        }
        config.ice.check_sdp(&answer.sdp)?;
        let description =
            RTCSessionDescription::answer(answer.sdp.clone()).map_err(|_| Error::Negotiation)?;
        pc.set_remote_description(description)
            .await
            .map_err(|_| Error::Negotiation)?;
        opened(&dc).await?;
        let (path, peer_ip) = evidence(pc, &config).await?;
        Ok(WebRtcStream::start(
            owner.take(),
            dc,
            path,
            peer_ip,
            config.stall_timeout,
            config.max_lifetime,
            cancel.clone(),
        ))
    };
    let result = tokio::select! {biased;_=cancel.cancelled()=>Err(Error::Cancelled),r=tokio::time::timeout_at(deadline,negotiation)=>r.unwrap_or(Err(Error::Deadline))};
    if result.is_err() {
        if let Some(id) = session {
            let _ = tokio::time::timeout(
                Duration::from_millis(200),
                exchange(
                    &signaling,
                    Role::Client,
                    &key,
                    Operation::Cancel(id),
                    Instant::now() + Duration::from_millis(200),
                ),
            )
            .await;
        }
    }
    result
}
/// Claim one admitted offer. Multiple concurrent calls have independent random
/// sessions and claim nonces; each offer can be answered only once.
pub async fn accept(
    config: CarrierConfig,
    signaling: Arc<dyn Signaling>,
    key: AdmissionKey,
    cancel: Cancellation,
) -> Result<WebRtcStream> {
    config.validate()?;
    let deadline = Instant::now() + config.connect_timeout;
    let negotiation = async {
        let reply = exchange(
            &signaling,
            Role::Intermediary,
            &key,
            Operation::Take,
            deadline,
        )
        .await?;
        let SignalingReply::Offer {
            session,
            claim,
            signal,
        } = reply
        else {
            return Err(Error::Signaling);
        };
        signal.validate()?;
        if !signal.offer {
            return Err(Error::Signaling);
        }
        config.ice.check_sdp(&signal.sdp)?;
        let (mut owner, mut gathered, mut channels) = peer(&config).await?;
        let pc = owner.get();
        let offer =
            RTCSessionDescription::offer(signal.sdp.clone()).map_err(|_| Error::Negotiation)?;
        pc.set_remote_description(offer)
            .await
            .map_err(|_| Error::Negotiation)?;
        let answer = pc
            .create_answer(None)
            .await
            .map_err(|_| Error::Negotiation)?;
        pc.set_local_description(answer)
            .await
            .map_err(|_| Error::Negotiation)?;
        gather(&mut gathered).await?;
        let answer = pc.local_description().await.ok_or(Error::Negotiation)?;
        config.ice.check_local_sdp(&answer.sdp, config.bind)?;
        exchange(
            &signaling,
            Role::Intermediary,
            &key,
            Operation::Answer {
                session,
                claim,
                signal: Signal::answer(answer.sdp)?,
            },
            deadline,
        )
        .await?;
        let dc = channels.recv().await.ok_or(Error::Channel)?;
        opened(&dc).await?;
        let (path, peer_ip) = evidence(pc, &config).await?;
        Ok(WebRtcStream::start(
            owner.take(),
            dc,
            path,
            peer_ip,
            config.stall_timeout,
            config.max_lifetime,
            cancel.clone(),
        ))
    };
    tokio::select! {biased;_=cancel.cancelled()=>Err(Error::Cancelled),r=tokio::time::timeout_at(deadline,negotiation)=>r.map_err(|_|Error::Deadline)?}
}
