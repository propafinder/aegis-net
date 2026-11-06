//! Held crypto preparation and an inert authenticated relay observation.
//! The provider factory and packet permit remain absent.
#[cfg(feature = "sfu-media-vp8")]
use crate::app_group::CapturedSfuSnapshot;
use crate::packet_engine::PacketEngineConfig;
use crate::{
    ack_conn::{ConnLive, LiveChannel},
    app_group::CapturedCryptoPayload,
    bound_relay_policy::BoundRelayPolicy,
    carrier_failover::{CarrierTicket, SessionCarriers},
    carrier_io::{own, InnerCarrier, OwnedCarrier},
    carrier_pool::{EchRedial, HeldCarrier, HeldCarriers},
    establish_limit::{
        auth_refused, conn_lost, exchange_auth_class, exchange_unanswered, handshake_auth_class,
        is_auth_refused, is_conn_lost, open_unanswered, tls_failure, EstablishPermit,
    },
    flow_log::Refusal,
    flow_pool::{
        ended_within, fails, ConnEnd, PooledCarrier, PooledConn, StreamBounds, StreamSlot,
        CONN_END_GRACE,
    },
    runtime_binding::SignedRuntimeTerms,
};
use aegis_client::{issuance_binding::IssuanceBinding, prepared_outer_tls::HeldH2Driver};
#[cfg(feature = "sfu-media-vp8")]
use aegis_core::carrier_program::SfuDeclaration;
use aegis_core::{
    carrier_program::{CarrierChannel, SECURE_WS_PATH},
    https_bridge::{Credential, Purpose},
    secure_channel::{self, Client, OpenRequest, Transport},
};
use std::{
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::{rustls::client::EchStatus, TlsConnector};

fn refused() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "prepared crypto refused")
}

/// An error whose whole chain can be judged (S16g).
pub(crate) trait Judged {
    fn judged(&self) -> &(dyn std::error::Error + 'static);
}
impl Judged for anyhow::Error {
    fn judged(&self) -> &(dyn std::error::Error + 'static) {
        let error: &(dyn std::error::Error + Send + Sync + 'static) = self.as_ref();
        error
    }
}
impl Judged for io::Error {
    fn judged(&self) -> &(dyn std::error::Error + 'static) {
        self
    }
}

/// The opaque refusal of a failed outer TLS/H2 or inner mTLS handshake:
/// authentication class (see `establish_limit`) only for a TLS error or an
/// explicit carrier refusal.
pub(crate) fn handshake_refusal(error: &impl Judged) -> io::Error {
    if handshake_auth_class(error.judged()) {
        auth_refused()
    } else {
        refused()
    }
}

/// The opaque refusal of a flow's failed Open exchange after the inner
/// handshake: authentication class for a TLS error (a delivered alert
/// refusing the device); an unanswered Open when the relay ended the channel
/// before its status, which aegis-server does both when it refuses the
/// device and when its session cap is full.
fn open_refusal(error: &impl Judged) -> io::Error {
    if exchange_auth_class(error.judged()) {
        auth_refused()
    } else if exchange_unanswered(error.judged()) {
        open_unanswered()
    } else {
        refused()
    }
}

/// The opaque refusal of a failed PolicyAck exchange: authentication class
/// only for a TLS error. aegis-server also ends the channel without a reply
/// when it refuses the ACK itself (which it does not count as an
/// authentication failure); the re-ACK schedule, its dial bound and the S17
/// rebuild backoff already pace the ACK path.
fn ack_refusal(error: &impl Judged) -> io::Error {
    if tls_failure(error.judged()) {
        auth_refused()
    } else {
        refused()
    }
}

#[allow(dead_code)]
pub(crate) struct PreparedCryptoInputs {
    // Settings still contain paths for the existing binary caller. They must
    // never be passed to its path-reopening dialer from a provider session.
    policy: BoundRelayPolicy,
    inner: Client,
    // v40 (CP-D3 M1): one held outer connector per pin of the signed pool.
    carriers: HeldCarriers,
    // v40: the one pin this session dials (`select_carrier`); the primary
    // until a session selects another.
    selected: usize,
    // v40: the selected pin's failover ticket, when the profile's pool has a
    // controller (`carrier_failover`).
    ticket: Option<Arc<CarrierTicket>>,
    bridge: Option<Credential>,
    web_credential: Option<aegis_web_carrier::Credential>,
    #[cfg(feature = "enrolled-quic")]
    quic: Option<Arc<aegis_client::prepared_enrolled_quic::PreparedQuicClient>>,
    #[cfg(feature = "sfu-media-vp8")]
    sfu_media: Option<(SfuDeclaration, Arc<CapturedSfuSnapshot>)>,
}

/// What keeps an ACK channel's connection going, resolving once that
/// connection ended for the channel: its own H2 driver, unspawned and polled
/// by whoever holds the channel, or (S16l) for a stream of the session's
/// persistent ACK connection, whose driver is a gate task, that
/// connection's end failing the channel's stream (`flow_pool::fails`).
type ChannelDriver = Pin<Box<dyn Future<Output = ()> + Send>>;

/// The pre-authenticated outer stream and its terminal H2 owner. The route
/// constructor keeps this pair together until the inner device TLS and ACK
/// hand it to the session gate; a failed build drops both at once.
#[must_use = "the outer stream and driver must stay in one session owner"]
pub(crate) enum HeldOuter {
    H2(Box<aegis_client::prepared_outer_tls::HeldH2Connection>),
    Ws(OwnedCarrier, HeldH2Driver),
    Web(OwnedCarrier, ChannelDriver),
    #[cfg(feature = "enrolled-quic")]
    Quic(OwnedCarrier, ChannelDriver),
}

/// A D5 target channel and the terminal watch of its own two-socket web
/// carrier. The packet service must poll both under its WorkGate permit;
/// dropping either ends the complete flow and withdraws the ingress pin.
#[must_use = "retain both target channel and carrier terminal owner"]
pub(crate) struct WebFlow {
    pub(crate) inner: InnerCarrier,
    pub(crate) terminal: ChannelDriver,
}

impl HeldOuter {
    fn into_parts(self) -> (OwnedCarrier, ChannelDriver) {
        match self {
            Self::H2(held) => {
                let (stream, driver) = (*held).into_parts();
                (own(stream), own_driver(driver))
            }
            Self::Ws(stream, driver) => (stream, own_driver(driver)),
            Self::Web(stream, driver) => (stream, driver),
            #[cfg(feature = "enrolled-quic")]
            Self::Quic(stream, driver) => (stream, driver),
        }
    }
}

/// Drop the web pump before withdrawing its exact ingress tuple.
struct GuardedWebStream {
    stream: aegis_web_carrier::WebStream,
    _ingress: crate::provider_session_body::WebIngressLease<'static>,
}

impl AsyncRead for GuardedWebStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for GuardedWebStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// A channel's own H2 driver; its result is the connection's end.
fn own_driver(held: HeldH2Driver) -> ChannelDriver {
    Box::pin(async move {
        let _ = held.await;
    })
}

/// S16l: the end of `conn` that fails stream `stream_id`; a closed watch is
/// a local close.
fn link_driver(conn: &PooledConn, stream_id: u32) -> ChannelDriver {
    let mut end = conn.end_watch();
    Box::pin(async move {
        let _ = end
            .wait_for(|ended| ended.is_some_and(|ended| fails(ended, stream_id)))
            .await;
    })
}

/// One observed channel. Neither this value nor its ACK grants packet capture.
/// The driver stays unspawned and dies with the authenticated stream.
#[must_use = "retain the stream and H2 driver with the protected Store owner"]
#[allow(dead_code)]
pub(crate) struct AuthenticatedRelayObservation {
    inner: InnerCarrier,
    driver: ChannelDriver,
    // The driver returned; it is never polled again.
    driver_done: bool,
    valid_until: tokio::time::Instant,
    // The PolicyAck round trip alone: request written to ACK verified.
    exchange_elapsed: Duration,
    // S16l: the ACK connection a stream channel rides, kept open while the
    // channel lives; dropped after the stream above it.
    conn: Option<Arc<PooledConn>>,
}

/// Phase (a) of an ACK: one authenticated channel (TCP to the held peer,
/// outer TLS and H2 from held material, inner mTLS; or, S16l, a carrier
/// stream of the session's persistent ACK connection and its inner mTLS) on
/// which no request has been sent. It grants nothing; only a verified
/// PolicyAck on it does. Its own driver stays unspawned and is polled by
/// whoever holds the channel.
#[must_use = "an idle authenticated channel is only useful for one PolicyAck"]
pub(crate) struct AckReadyChannel {
    inner: InnerCarrier,
    driver: ChannelDriver,
    driver_done: bool,
    // S16l: counted live on its ACK connection from its inner mTLS until its
    // exchange ends, as the relay counts an authenticated stream.
    live: Option<LiveChannel>,
    // S16l: the ACK connection and the stream this channel rides.
    conn: Option<(Arc<PooledConn>, u32)>,
}

impl AckReadyChannel {
    /// Poll the idle channel's H2 driver until the connection ends, and
    /// return at once if it already has. An ended channel is never used.
    /// Cancellation keeps the driver for the next poll.
    #[cfg(test)]
    pub(crate) async fn drive_idle(&mut self) {
        std::future::poll_fn(|cx| self.poll_idle(cx)).await
    }

    /// `drive_idle` as a poll: ready once the connection has ended.
    pub(crate) fn poll_idle(&mut self, cx: &mut std::task::Context<'_>) -> Poll<()> {
        if !self.driver_done {
            if std::future::Future::poll(self.driver.as_mut(), cx).is_pending() {
                return Poll::Pending;
            }
            self.driver_done = true;
        }
        Poll::Ready(())
    }

    /// Test hook: record the driver as ended while the connection still lives.
    #[cfg(test)]
    pub(crate) fn mark_ended_for_test(&mut self) {
        self.driver_done = true;
    }

    /// Test hook (S16m): write one targetless PolicyAck request on the
    /// channel and flush it, reading nothing: the relay's answer, when it
    /// comes, is inbound bytes of the connection that nobody awaits.
    #[cfg(test)]
    pub(crate) async fn request_ack_for_test(&mut self) -> io::Result<()> {
        use tokio::io::AsyncWriteExt;
        let request = aegis_core::secure_channel::policy_ack::PolicyAckRequest::new();
        aegis_core::secure_channel::policy_ack::write_request(&mut self.inner, &request).await?;
        self.inner.flush().await
    }

    /// S16l: the persistent ACK connection this channel is a stream of,
    /// and that stream's ID; None for a channel on its own connection.
    pub(crate) fn conn(&self) -> Option<(&Arc<PooledConn>, u32)> {
        self.conn
            .as_ref()
            .map(|(conn, stream_id)| (conn, *stream_id))
    }
}

impl AuthenticatedRelayObservation {
    pub(crate) fn valid_until(&self) -> tokio::time::Instant {
        self.valid_until
    }

    /// How long the PolicyAck request and its verified ACK took on the
    /// established channel, excluding TCP, outer TLS, H2 and inner TLS.
    pub(crate) fn exchange_elapsed(&self) -> Duration {
        self.exchange_elapsed
    }

    /// Drive the same H2 connection after ACK until it ends. Cancellation of
    /// this borrow preserves the pinned driver for the next owner poll; both
    /// clean EOF and protocol failure revoke the inert observation.
    pub(crate) async fn terminal_failure(&mut self) -> io::Error {
        self.drive_until_closed().await;
        refused()
    }

    /// Poll the ACK connection's H2 driver until it ends, cleanly or not, and
    /// return at once if it already has. The server shuts the inner stream
    /// right after the ACK, so for a session owner this end is not a failure:
    /// the ACK deadline alone bounds it. Cancellation keeps the driver.
    pub(crate) async fn drive_until_closed(&mut self) {
        if !self.driver_done {
            let _ = (&mut self.driver).await;
            self.driver_done = true;
        }
    }

    /// Keep the real H2 driver live while a containing Store owner performs
    /// periodic identity checks. The original ACK expiry never extends.
    pub(crate) async fn monitor_inert_until_terminal(
        &mut self,
        revalidate: impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.monitor_inert_until_terminal_inner(revalidate, None)
            .await
    }

    /// Start signal is sent only after the held Store/ACK check and one
    /// pending poll of the actual H2 driver. It grants no packet authority.
    pub(crate) async fn monitor_inert_until_terminal_ready(
        &mut self,
        revalidate: impl FnMut() -> io::Result<()>,
        ready: tokio::sync::oneshot::Sender<()>,
    ) -> io::Result<()> {
        self.monitor_inert_until_terminal_inner(revalidate, Some(ready))
            .await
    }

    async fn monitor_inert_until_terminal_inner(
        &mut self,
        mut revalidate: impl FnMut() -> io::Result<()>,
        ready: Option<tokio::sync::oneshot::Sender<()>>,
    ) -> io::Result<()> {
        revalidate()?;
        if let Some(ready) = ready {
            if self.driver_done {
                return Err(refused());
            }
            let pending = std::future::poll_fn(|cx| {
                let pending = self.driver.as_mut().poll(cx).is_pending();
                self.driver_done = !pending;
                Poll::Ready(pending)
            })
            .await;
            if !pending {
                return Err(refused());
            }
            // The initial check preceded the H2 poll. Revalidate the held
            // Store/ACK again after that actual pending poll before ready can
            // be observed by any future packet lease handoff.
            revalidate()?;
            ready.send(()).map_err(|_| refused())?;
        }
        let expiry = self.valid_until;
        loop {
            tokio::select! {
                _ = self.terminal_failure() => return Err(refused()),
                _ = tokio::time::sleep_until(expiry) => return Err(refused()),
                _ = tokio::time::sleep(Duration::from_millis(250)) => revalidate()?,
            }
        }
    }
}

#[allow(dead_code)]
impl PreparedCryptoInputs {
    /// Read the exact signed endpoint this session dials: its selected pin
    /// of the signed pool (the primary until another is selected). The
    /// caller still has to establish and verify the live TCP/H2/ACK path.
    pub(crate) fn pinned_peer(&self) -> io::Result<SocketAddr> {
        let peer = self.carrier().peer();
        self.direct_peer(peer)?;
        Ok(peer)
    }

    /// v40: the signed primary pin (the profile's `relay_server`), the one
    /// the saved manager intent names.
    pub(crate) fn primary_peer(&self) -> SocketAddr {
        self.carriers.primary().peer()
    }

    /// v40: every exact pin of the signed pool, in profile order: what the
    /// leak guard arms, and nothing else.
    pub(crate) fn carrier_pins(&self) -> Vec<SocketAddr> {
        self.carriers.pins()
    }

    /// The signed connect budget of one establishment.
    pub(crate) fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.policy.settings().relay.connect_timeout_ms)
    }

    /// v40: the pin this session dials and its held connector.
    pub(crate) fn carrier(&self) -> &HeldCarrier {
        self.carriers
            .get(self.selected)
            .unwrap_or_else(|| self.carriers.primary())
    }

    /// v40: the attempt order of one session build over the pool, from the
    /// profile's failover controller on `network` (profile order and no
    /// learning for a single pin).
    pub(crate) fn carrier_plan(
        &self,
        network: aegis_core::brain::carrier_failover::NetworkKey,
    ) -> io::Result<SessionCarriers> {
        let relay = &self.policy.settings().relay;
        #[cfg(feature = "sfu-media-vp8")]
        let ack_pins = self.carriers.len() - usize::from(self.sfu_media.is_some());
        #[cfg(not(feature = "sfu-media-vp8"))]
        let ack_pins = self.carriers.len();
        SessionCarriers::plan(
            crate::carrier_failover::profile_identity(self.policy.public_digest()),
            relay.carrier_failover.as_ref(),
            ack_pins,
            network,
        )
    }

    /// v40: make pin `index` this session's carrier, with its failover
    /// `ticket`. Only before the held crypto is shared with any opener,
    /// link or pool (the caller holds it uniquely), so every dial of one
    /// session goes to one pin.
    pub(crate) fn select_carrier(
        &mut self,
        index: usize,
        ticket: Option<Arc<CarrierTicket>>,
    ) -> io::Result<()> {
        if self.carriers.get(index).is_none() {
            return Err(refused());
        }
        self.selected = index;
        self.ticket = ticket;
        Ok(())
    }

    /// v40: the selected pin's failover ticket.
    pub(crate) fn carrier_ticket(&self) -> Option<&Arc<CarrierTicket>> {
        self.ticket.as_ref()
    }

    /// v40: a typed pre-authentication `signal` of a dial of this session's
    /// pin (see `CarrierTicket::fault`). Without a controller, nothing.
    pub(crate) fn carrier_fault(&self, signal: aegis_core::brain::carrier_failover::CarrierSignal) {
        if let Some(ticket) = &self.ticket {
            ticket.fault(signal);
        }
    }

    /// v40: a post-authentication degradation of this session's pin.
    pub(crate) fn carrier_degraded(
        &self,
        signal: aegis_core::brain::carrier_failover::CarrierSignal,
    ) {
        if let Some(ticket) = &self.ticket {
            ticket.degraded(signal);
        }
    }

    /// v40 (D2): a failed outer handshake of this session's pin, as an ECH
    /// rotation (`HeldCarriers::ech_rejected`).
    pub(crate) fn ech_rejected(&self, error: &(dyn std::error::Error + 'static)) -> EchRedial {
        self.carriers
            .ech_rejected(self.selected, error, self.policy.outer_ca())
    }

    /// v40 (D2): the one redial with admitted retry configs failed.
    pub(crate) fn forget_ech_rotation(&self) {
        self.carriers
            .forget_rotation(self.selected, self.policy.outer_ca());
    }

    /// Test-only: the held pool.
    #[cfg(test)]
    pub(crate) fn carriers_for_test(&self) -> &HeldCarriers {
        &self.carriers
    }
    /// The held profile's enrollment authority, for the renewal monitor's
    /// guard check (v31; S20b armed it in the leak guard).
    pub(crate) fn authority_address(&self) -> Option<SocketAddr> {
        self.policy.authority_address()
    }
    /// The held signed runtime terms of the signed pool's primary pin (the
    /// relay the saved manager intent names); v40: whichever pin a session
    /// selects, the terms name the primary.
    pub(crate) fn signed_runtime_terms(&self) -> io::Result<SignedRuntimeTerms<'_>> {
        let terms = self.policy.signed_runtime_terms()?;
        if terms.relay != self.primary_peer().ip() {
            return Err(refused());
        }
        Ok(terms)
    }
    /// The retained signed relay settings: the budgets held relay flows
    /// enforce, and what tests supply as the packet engine does.
    pub(crate) fn signed_relay(&self) -> &aegis_core::RelaySettings {
        &self.policy.settings().relay
    }
    pub(crate) fn relay_matches(&self, supplied: &aegis_core::RelaySettings) -> bool {
        // Only the signed, retained profile may supply a worker's relay policy.
        // The serialization comparison includes fields that are intentionally
        // unsupported by this direct-peer adapter, so any disagreement fails.
        matches!(
            (
                serde_json::to_vec(supplied),
                serde_json::to_vec(&self.policy.settings().relay)
            ),
            (Ok(actual), Ok(expected)) if actual == expected
        )
    }
    /// One flow's target channel on its pooled carrier stream (S16h). The
    /// inner mTLS and the Open request run until `bounds.handshake`, and
    /// the status read until `bounds.status`, both from when the carrier
    /// was requested (`StreamSlot::sent`), never from its 200; `slot`'s
    /// handshake place is freed once the inner connect returned, and
    /// `permit`, the flow's establishment permit, returns once the Open
    /// request is written (S16g). The relay's own deadline, inherited at
    /// its accept, also covers the target dial, so this side gives up first
    /// and a slow target is a timeout, never an unanswered Open.
    ///
    /// A failure is judged as `establish_limit` does, after two checks: a
    /// TLS error stays authentication class; a stream error on a connection
    /// whose end fails this stream, recorded now or within `CONN_END_GRACE`,
    /// is a connection loss (`conn_lost`), never an unanswered Open. A
    /// stream the relay ended in its inner handshake, judged neither,
    /// narrows its connection to one handshake at a time
    /// (`StreamSlot::capacity_refused`). The stream awaits the relay, for
    /// its connection's stall watchdog, until its status read ends
    /// (`StreamSlot::answered`); one whose handshake bound passed is judged
    /// at that watchdog's verdict (`watchdog_refusal`).
    pub(crate) async fn open_target_on_stream(
        &self,
        carrier: PooledCarrier,
        slot: &mut StreamSlot,
        transport: Transport,
        (host, port): (String, u16),
        permit: &mut EstablishPermit,
        bounds: StreamBounds,
    ) -> io::Result<InnerCarrier> {
        let PooledCarrier { io, stream_id } = carrier;
        let mut end = slot.conn().end_watch();
        let StreamBounds {
            handshake: watchdog,
            status: status_at,
        } = bounds;
        let connected = tokio::time::timeout_at(watchdog, self.inner.connect(io)).await;
        slot.handshake_done(matches!(connected, Ok(Ok(_))));
        let mut inner = match connected {
            Ok(Ok(inner)) => inner,
            Ok(Err(error)) => {
                let refusal = stream_refusal(&error, &mut end, stream_id, Step::Handshake).await;
                // Neither a TLS error nor its connection's end: the relay
                // ended the stream after its 200 and before the handshake
                // answered (a reset, or the stream closed under the
                // ClientHello), as its full handshake cap does (S16h-8c).
                if !is_auth_refused(&refusal) && !is_conn_lost(&refusal) {
                    slot.capacity_refused();
                    slot.note(Refusal::HsRefused);
                }
                return Err(refusal);
            }
            // The stream was dropped (reset) with the connect.
            Err(_) => return Err(watchdog_refusal(slot, stream_id).await),
        };
        let request = OpenRequest {
            transport,
            version: 1,
            host,
            port,
        };
        match tokio::time::timeout_at(watchdog, secure_channel::write_open(&mut inner, &request))
            .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                return Err(stream_refusal(&error, &mut end, stream_id, Step::Exchange).await)
            }
            Err(_) => {
                // Reset at once; only the verdict waits.
                drop(inner);
                return Err(watchdog_refusal(slot, stream_id).await);
            }
        }
        // The relay ended its handshake before it reads this request: a
        // slow target never holds an establishment permit.
        permit.request_written();
        let status = tokio::time::timeout_at(status_at, inner.read_u8()).await;
        slot.answered();
        match status {
            Ok(Ok(0)) => Ok(inner),
            Ok(Ok(_)) => {
                slot.note(Refusal::StatusRefused);
                Err(refused())
            }
            Ok(Err(error)) => {
                Err(stream_refusal(&error, &mut end, stream_id, Step::Exchange).await)
            }
            // No status in time: a timeout, never an unanswered Open.
            Err(_) => {
                slot.note(Refusal::StatusBudget);
                Err(refused())
            }
        }
    }

    /// S16h pooled outer sessions: the outer TLS connector prepared from the
    /// held CA (`explicit_h2_connector_from_pem`, as `connect_h2_from_held`
    /// builds it for every call). v40: the selected pin's.
    pub(crate) fn outer_connector(&self) -> TlsConnector {
        self.carrier().connector()
    }

    /// The inner mTLS client of the held device identity.
    pub(crate) fn inner_client(&self) -> &Client {
        &self.inner
    }

    #[cfg(feature = "sfu-media-vp8")]
    pub(crate) fn sfu_media_inputs(&self) -> Option<(&SfuDeclaration, Arc<CapturedSfuSnapshot>)> {
        self.sfu_media
            .as_ref()
            .map(|(signed, held)| (signed, held.clone()))
    }

    #[cfg(feature = "sfu-media-vp8")]
    pub(crate) fn has_sfu_media(&self) -> bool {
        self.sfu_media.is_some()
    }

    /// Test-only reference: aegis-client's own single-carrier outer session
    /// from the same held material, as every flow and ACK channel opens it.
    #[cfg(test)]
    pub(crate) async fn reference_carrier(
        &self,
        tcp: TcpStream,
    ) -> anyhow::Result<aegis_client::prepared_outer_tls::HeldH2Connection> {
        aegis_client::prepared_outer_tls::connect_h2_from_held(
            self.carrier().relay(),
            self.policy.outer_ca(),
            self.bridge_for(self.carrier()),
            Purpose::Traffic,
            tcp,
        )
        .await
    }

    pub(crate) fn packet_config(
        &self,
        saved_mtu: u16,
        saved_dns: &[IpAddr],
    ) -> io::Result<PacketEngineConfig> {
        self.policy.packet_config(saved_mtu, saved_dns)
    }

    /// Admit only the one exact, numeric TCP endpoint this session dials:
    /// v40, its selected pin of the signed pool (`HeldCarriers::from_held`
    /// admitted the pool: numeric pins, primary first, no endpoint bandit,
    /// Geneva or paired shaping, which have no provider owner).
    pub(crate) fn direct_peer(&self, peer: SocketAddr) -> io::Result<()> {
        let relay = &self.policy.settings().relay;
        if relay.outer_geneva.is_some()
            || relay.endpoint_bandit.is_some()
            || relay.authenticated_shaping.is_some()
            || relay.endpoints.len() != self.carriers.len()
            || self.carrier().peer() != peer
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Use the held CA, device identity and bridge credential on one existing
    /// TCP socket. One original deadline covers outer H2, inner TLS and the
    /// targetless PolicyAck; a terminal H2 driver aborts either pending step.
    pub(crate) async fn observe_ack(
        &self,
        tcp: TcpStream,
        expected: IssuanceBinding<'_>,
    ) -> io::Result<AuthenticatedRelayObservation> {
        self.direct_peer(tcp.peer_addr().map_err(|_| refused())?)
            .map_err(ack_stage("direct_peer"))?;
        let relay = &self.policy.settings().relay;
        let deadline =
            tokio::time::Instant::now() + Duration::from_millis(relay.connect_timeout_ms);
        tokio::time::timeout_at(deadline, async {
            let channel = self.establish_unbounded(tcp, ACK_STAGE).await?;
            exchange_on(channel, expected, ACK_STAGE).await
        })
        .await
        .map_err(ack_stage("ack_deadline"))?
    }

    /// S16m: `observe_ack`, abandoned (None) when `until` resolves while
    /// its outer TLS, H2 or inner mTLS is still running, before any
    /// PolicyAck is written. Once the inner mTLS completed (`established`
    /// runs then), the PolicyAck exchange runs to its end or the one
    /// deadline whatever `until` does: a request about to be written is at
    /// most its answer away, which a channel it would go back to cannot
    /// beat, and dropping it would throw that exchange away. A channel
    /// established in the same poll as `until` is kept.
    pub(crate) async fn observe_ack_or(
        &self,
        tcp: TcpStream,
        expected: IssuanceBinding<'_>,
        (until, established): (impl std::future::Future<Output = ()>, impl FnOnce()),
    ) -> Option<io::Result<AuthenticatedRelayObservation>> {
        let peer = match tcp.peer_addr() {
            Ok(peer) => peer,
            Err(_) => return Some(Err(refused())),
        };
        if let Err(error) = self.direct_peer(peer).map_err(ack_stage("direct_peer")) {
            return Some(Err(error));
        }
        let relay = &self.policy.settings().relay;
        let deadline =
            tokio::time::Instant::now() + Duration::from_millis(relay.connect_timeout_ms);
        let establish = tokio::time::timeout_at(deadline, async {
            tokio::select! {
                biased;
                channel = self.establish_unbounded(tcp, ACK_STAGE) => Some(channel),
                () = until => None,
            }
        });
        let channel = match establish.await {
            Err(elapsed) => return Some(Err(ack_stage("ack_deadline")(elapsed))),
            Ok(None) => return None,
            Ok(Some(Err(error))) => return Some(Err(error)),
            Ok(Some(Ok(channel))) => channel,
        };
        established();
        Some(
            tokio::time::timeout_at(deadline, exchange_on(channel, expected, ACK_STAGE))
                .await
                .map_err(ack_stage("ack_deadline"))
                .and_then(|observed| observed),
        )
    }

    /// Phase (a) alone, under its own `connect_timeout_ms` deadline: the
    /// held policy refuses any TCP peer but the signed relay before a byte
    /// is sent. Refusals log `event` with the step that refused.
    pub(crate) async fn establish_ack_channel(
        &self,
        tcp: TcpStream,
        event: &'static str,
    ) -> io::Result<AckReadyChannel> {
        self.direct_peer(tcp.peer_addr().map_err(|_| refused())?)
            .map_err(stage(event, "direct_peer"))?;
        let budget = Duration::from_millis(self.policy.settings().relay.connect_timeout_ms);
        tokio::time::timeout(budget, self.establish_unbounded(tcp, event))
            .await
            .map_err(stage(event, "establish_deadline"))?
    }

    /// Phase (b) alone: one targetless PolicyAck on `channel`, established
    /// earlier from this same held crypto, under a fresh deadline of
    /// `connect_timeout_ms` or `limit`, whichever is shorter, so a channel
    /// that went silent while idle leaves time for another. An ended channel
    /// is refused before any request is written.
    pub(crate) async fn exchange_ack(
        &self,
        channel: AckReadyChannel,
        expected: IssuanceBinding<'_>,
        limit: Duration,
        event: &'static str,
    ) -> io::Result<AuthenticatedRelayObservation> {
        let budget =
            Duration::from_millis(self.policy.settings().relay.connect_timeout_ms).min(limit);
        tokio::time::timeout(budget, exchange_on(channel, expected, event))
            .await
            .map_err(stage(event, "ack_deadline"))?
    }

    async fn establish_unbounded(
        &self,
        tcp: TcpStream,
        event: &'static str,
    ) -> io::Result<AckReadyChannel> {
        let held = self.held_carrier(tcp, event).await?;
        self.establish_on_held(held, event).await
    }

    /// v40: the outer carrier alone on one socket to this session's pin:
    /// outer TLS and ECH from the held CA, HTTP/2 and the carrier's 200
    /// (`connect_h2_from_held`), before any device identity. A typed
    /// pre-authentication failure is this pin's carrier fault.
    pub(crate) async fn held_carrier(
        &self,
        tcp: TcpStream,
        event: &'static str,
    ) -> io::Result<HeldOuter> {
        if self.selected_channel()? == CarrierChannel::HttpsWs {
            return self.held_ws_carrier(tcp, event).await;
        }
        aegis_client::prepared_outer_tls::connect_h2_from_held(
            self.carrier().relay(),
            self.policy.outer_ca(),
            self.bridge_for(self.carrier()),
            Purpose::Traffic,
            tcp,
        )
        .await
        .map(|held| HeldOuter::H2(Box::new(held)))
        .map_err(|error| {
            if let Some(signal) = crate::carrier_failover::outer_signal(error.judged()) {
                self.carrier_fault(signal);
            }
            handshake_stage(event, "outer_h2")(error)
        })
    }

    async fn held_ws_carrier(&self, tcp: TcpStream, event: &'static str) -> io::Result<HeldOuter> {
        let relay = self.carrier().relay();
        if relay.https_bridge.is_some()
            || tcp.peer_addr().map_err(|_| refused())? != self.carrier().peer()
        {
            return Err(refused());
        }
        let request = self.carrier_request(Purpose::Traffic)?;
        let authority = aegis_client::relay_endpoint_policy::relay_transport_authority(relay)
            .map_err(|_| refused())?;
        let deadline =
            tokio::time::Instant::now() + Duration::from_millis(relay.connect_timeout_ms);
        let result = tokio::time::timeout_at(deadline, async {
            let tls = self
                .outer_connector()
                .connect(authority.tls_server_name, tcp)
                .await
                .map_err(|_| refused())?;
            self.verify_outer_handshake(
                tls.get_ref().1.ech_status(),
                tls.get_ref().1.alpn_protocol(),
            )?;
            let (mut client, connection) = h2::client::Builder::new()
                .handshake::<_, bytes::Bytes>(tls)
                .await
                .map_err(|_| refused())?;
            let mut driver: HeldH2Driver = Box::pin(connection);
            let (response, send) = client.send_request(request, false).map_err(|_| refused())?;
            let response = tokio::select! {
                result = response => result.map_err(|_| refused())?,
                _ = &mut driver => return Err(refused()),
            };
            if response.status() != http::StatusCode::OK {
                return Err(refused());
            }
            let stream = aegis_core::h2_stream::H2Stream::new(send, response.into_body());
            let ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
                stream,
                tokio_tungstenite::tungstenite::protocol::Role::Client,
                Some(aegis_core::ws_io::bounded_config()),
            )
            .await;
            Ok(HeldOuter::Ws(own(aegis_core::ws_io::WsIo::new(ws)), driver))
        })
        .await
        .map_err(|_| refused())?;
        result.map_err(stage(event, "outer_ws"))
    }

    /// v40: the inner mTLS on an outer carrier `held_carrier` opened.
    async fn establish_on_held(
        &self,
        held: HeldOuter,
        event: &'static str,
    ) -> io::Result<AckReadyChannel> {
        let (carrier, mut driver) = held.into_parts();
        let inner = tokio::select! {
            result = self.inner.connect(carrier) => result.map_err(handshake_stage(event, "inner_tls"))?,
            _ = &mut driver => return Err(stage(event, "inner_driver_ended")(())),
        };
        Ok(AckReadyChannel {
            inner,
            driver,
            driver_done: false,
            live: None,
            conn: None,
        })
    }

    /// S16l: phase (a) on the session's persistent ACK connection: one
    /// carrier stream on `conn` (its request, the 200 and its content type,
    /// a GOAWAY or the connection's end judged as `PooledConn::open_carrier`
    /// does) and its inner mTLS, raced against `conn`'s end failing the
    /// stream, under `connect_timeout_ms`. The channel counts as live on
    /// `live` (the connection's) once authenticated. While it runs the
    /// connection's stall watchdog watches its quiet. Refusals log `event`
    /// with the refusing step; a TLS error or an explicit carrier refusal
    /// stays authentication class.
    pub(crate) async fn establish_ack_stream(
        &self,
        conn: Arc<PooledConn>,
        live: &Arc<ConnLive>,
        event: &'static str,
    ) -> io::Result<AckReadyChannel> {
        let budget = Duration::from_millis(self.policy.settings().relay.connect_timeout_ms);
        tokio::time::timeout(budget, self.establish_stream_unbounded(conn, live, event))
            .await
            .map_err(stage(event, "link_deadline"))?
    }

    async fn establish_stream_unbounded(
        &self,
        conn: Arc<PooledConn>,
        live: &Arc<ConnLive>,
        event: &'static str,
    ) -> io::Result<AckReadyChannel> {
        let _awaiting = conn.awaiting();
        let carrier = self.link_carrier_unbounded(&conn, event).await?;
        self.inner_on_link_carrier(conn, live, carrier, event).await
    }

    /// v40: one carrier stream on `conn` (its request, the 200 and its
    /// content type), a failure judged as before and noted as this pin's
    /// carrier fault (`note_outer_failure`, a stream).
    async fn link_carrier_unbounded(
        &self,
        conn: &PooledConn,
        event: &'static str,
    ) -> io::Result<PooledCarrier> {
        conn.open_carrier(self).await.map_err(|error| {
            self.note_outer_failure(error.judged(), false);
            handshake_stage(event, "link_carrier")(error)
        })
    }

    /// v40 (CP-D3 M1): the first ACK's carrier stream alone, on the ACK
    /// connection a session build brought up to one pin, under
    /// `connect_timeout_ms`: the 200 of the carrier before any device
    /// identity, so a pin whose edge refuses moves the build on. A timeout
    /// is the pin's establishment timeout.
    pub(crate) async fn open_link_carrier(
        &self,
        conn: &Arc<PooledConn>,
        event: &'static str,
    ) -> io::Result<PooledCarrier> {
        let budget = Duration::from_millis(self.policy.settings().relay.connect_timeout_ms);
        let _awaiting = conn.awaiting();
        match tokio::time::timeout(budget, self.link_carrier_unbounded(conn, event)).await {
            Ok(opened) => opened,
            Err(elapsed) => {
                self.carrier_fault(
                    aegis_core::brain::carrier_failover::CarrierSignal::EstablishmentTimeout,
                );
                Err(stage(event, "link_deadline")(elapsed))
            }
        }
    }

    /// v40: a failed outer step of this session's pin as its carrier fault.
    /// A dial (a fresh socket's outer TLS, HTTP/2 and carrier request) is
    /// classified in full (`carrier_failover::outer_signal`). A stream on a
    /// connection already up is, before the session opened, too; after it
    /// opened only an explicit carrier refusal is: a GOAWAY, a connection
    /// end or a reset under a stream is the pool's own retry, never a fault
    /// of the pin.
    pub(crate) fn note_outer_failure(&self, error: &(dyn std::error::Error + 'static), dial: bool) {
        let Some(ticket) = &self.ticket else {
            return;
        };
        let signal = if dial || !ticket.is_open() {
            crate::carrier_failover::outer_signal(error)
        } else {
            crate::carrier_failover::stream_refusal_signal(error)
        };
        if let Some(signal) = signal {
            ticket.fault(signal);
        }
    }

    /// v40: the inner mTLS on a carrier stream of `conn` opened before; the
    /// caller holds `conn`'s awaiting guard across it.
    async fn inner_on_link_carrier(
        &self,
        conn: Arc<PooledConn>,
        live: &Arc<ConnLive>,
        PooledCarrier { io, stream_id }: PooledCarrier,
        event: &'static str,
    ) -> io::Result<AckReadyChannel> {
        let mut driver = link_driver(&conn, stream_id);
        let inner = tokio::select! {
            result = self.inner.connect(io) => {
                result.map_err(handshake_stage(event, "link_inner_tls"))?
            }
            () = &mut driver => return Err(stage(event, "link_ended")(())),
        };
        Ok(AckReadyChannel {
            inner,
            driver,
            driver_done: false,
            live: Some(ConnLive::enter(live)),
            conn: Some((conn, stream_id)),
        })
    }

    /// S16l: a whole ACK on the persistent ACK connection: one stream
    /// channel (`establish_ack_stream`) and its targetless PolicyAck, under
    /// one deadline of `connect_timeout_ms` or `limit`, whichever is
    /// shorter.
    pub(crate) async fn observe_ack_on_link(
        &self,
        conn: Arc<PooledConn>,
        live: &Arc<ConnLive>,
        expected: IssuanceBinding<'_>,
        limit: Duration,
        event: &'static str,
    ) -> io::Result<AuthenticatedRelayObservation> {
        self.observe_ack_on_link_carrier(conn, live, None, expected, limit, event)
            .await
    }

    /// v40: `observe_ack_on_link`, on the carrier stream `carrier` when the
    /// session build already opened it (`open_link_carrier`): the inner
    /// mTLS and the PolicyAck under the same one deadline.
    pub(crate) async fn observe_ack_on_link_carrier(
        &self,
        conn: Arc<PooledConn>,
        live: &Arc<ConnLive>,
        carrier: Option<PooledCarrier>,
        expected: IssuanceBinding<'_>,
        limit: Duration,
        event: &'static str,
    ) -> io::Result<AuthenticatedRelayObservation> {
        let budget =
            Duration::from_millis(self.policy.settings().relay.connect_timeout_ms).min(limit);
        tokio::time::timeout(budget, async {
            let channel = match carrier {
                Some(carrier) => {
                    let _awaiting = conn.awaiting();
                    self.inner_on_link_carrier(conn.clone(), live, carrier, event)
                        .await?
                }
                None => self.establish_stream_unbounded(conn, live, event).await?,
            };
            exchange_on(channel, expected, event).await
        })
        .await
        .map_err(stage(event, "ack_deadline"))?
    }

    /// v40: `observe_ack` on the outer carrier `held` a session build
    /// already opened to its pin (`held_carrier`): the inner mTLS and the
    /// targetless PolicyAck by `deadline`, the one `connect_timeout_ms`
    /// deadline counted from that carrier's start.
    pub(crate) async fn observe_ack_on_held(
        &self,
        held: HeldOuter,
        expected: IssuanceBinding<'_>,
        deadline: tokio::time::Instant,
    ) -> io::Result<AuthenticatedRelayObservation> {
        tokio::time::timeout_at(deadline, async {
            let channel = self.establish_on_held(held, ACK_STAGE).await?;
            exchange_on(channel, expected, ACK_STAGE).await
        })
        .await
        .map_err(ack_stage("ack_deadline"))?
    }

    pub(crate) fn from_snapshot(
        #[allow(unused_mut)] // D6 feature takes the held private media owner.
        mut policy: BoundRelayPolicy,
        payload: CapturedCryptoPayload,
    ) -> io::Result<Self> {
        if policy.outer_ca() != payload.outer_ca
            || policy.inner_ca() != payload.inner_ca
            || !policy.bridge_matches(payload.bridge.as_ref())
            || !policy.web_matches(payload.web_response.as_ref())
        {
            return Err(refused());
        }
        let inner_settings = policy
            .settings()
            .relay
            .inner_tls
            .as_ref()
            .ok_or_else(refused)?;
        let inner = Client::from_captured_pem(
            inner_settings,
            &payload.inner_ca,
            &payload.certificate,
            &payload.private_key,
        )
        .map_err(|_| refused())?;
        // v40: one held outer connector per pin of the signed pool.
        let carriers = HeldCarriers::from_held(&policy.settings().relay, &payload.outer_ca)?;
        #[cfg(feature = "enrolled-quic")]
        let quic = if policy
            .settings()
            .relay
            .carrier_program
            .as_ref()
            .is_some_and(|program| {
                program
                    .routes
                    .iter()
                    .any(|route| route.channel == CarrierChannel::MasqueQuic)
            }) {
            Some(Arc::new(
                aegis_client::prepared_enrolled_quic::PreparedQuicClient::from_held(
                    &payload.outer_ca,
                    &payload.certificate,
                    &payload.private_key,
                )
                .map_err(|_| refused())?,
            ))
        } else {
            None
        };
        let bridge = match (
            policy.settings().relay.https_bridge.as_ref(),
            payload.bridge,
        ) {
            (None, None) => None,
            (Some(expected), Some(actual)) if *expected == actual.settings => Some(
                Credential::from_captured_bytes(actual.secret.as_slice()).map_err(|_| refused())?,
            ),
            _ => return Err(refused()),
        };
        let web_credential = match (
            policy.settings().relay.web_response.as_ref(),
            payload.web_response,
        ) {
            (None, None) => None,
            (Some(expected), Some(actual)) if *expected == actual.settings => Some(
                aegis_web_carrier::Credential::from_private_bytes(zeroize::Zeroizing::new(
                    actual.secret.to_vec(),
                ))
                .map_err(|_| refused())?,
            ),
            _ => return Err(refused()),
        };
        #[cfg(feature = "sfu-media-vp8")]
        let sfu_media = policy
            .take_sfu_media()
            .map(|(signed, held)| (signed, Arc::new(held)));
        let prepared = Self {
            policy,
            inner,
            carriers,
            selected: 0,
            ticket: None,
            bridge,
            web_credential,
            #[cfg(feature = "enrolled-quic")]
            quic,
            #[cfg(feature = "sfu-media-vp8")]
            sfu_media,
        };
        // Every pin's carrier request must build before any dial: its TLS
        // name and route (a held bridge must name each pin's authority).
        for index in 0..prepared.carriers.len() {
            let carrier = prepared.carriers.get(index).ok_or_else(refused)?;
            #[cfg(feature = "enrolled-quic")]
            if prepared.channel_for(index)? == CarrierChannel::MasqueQuic {
                if prepared.quic.is_none() {
                    return Err(refused());
                }
                continue;
            }
            if prepared.channel_for(index)? == CarrierChannel::WebResponse {
                if prepared.web_credential.is_none() || carrier.relay().web_response.is_none() {
                    return Err(refused());
                }
                continue;
            }
            #[cfg(feature = "sfu-media-vp8")]
            if prepared.channel_for(index)? == CarrierChannel::SfuMedia {
                if prepared.sfu_media.is_none() {
                    return Err(refused());
                }
                continue;
            }
            prepared.carrier_request_for(carrier, Purpose::Traffic)?;
        }
        Ok(prepared)
    }

    #[cfg(feature = "enrolled-quic")]
    pub(crate) async fn quic_carrier(
        &self,
        interface: &crate::relay_socket::RelayInterface,
        pins: &crate::provider_session_body::EpochPins,
        generation: u64,
        gate: &crate::held_relay_services::WorkGate,
    ) -> io::Result<HeldOuter> {
        if self.selected_channel()? != CarrierChannel::MasqueQuic {
            return Err(refused());
        }
        let carrier = self.carrier();
        self.direct_peer(carrier.peer())?;
        // The signed role admits direct enrolled H3 only. It cannot borrow
        // another carrier's bridge key, ECH configuration or legacy token.
        if carrier.relay().https_bridge.is_some()
            || !carrier.relay().auth_token.is_empty()
            || carrier.relay().ech_config_list.is_some()
            || carrier.relay().ech_config_list_base64.is_some()
            || carrier.relay().masque_server.is_some()
            || carrier.relay().masque_server_name.is_some()
        {
            return Err(refused());
        }
        let held = crate::quic_carrier::connect(
            self.quic.as_ref().ok_or_else(refused)?.as_ref(),
            carrier.peer(),
            &carrier.relay().server_name,
            interface,
            pins,
            generation,
            gate,
            Duration::from_millis(carrier.relay().connect_timeout_ms),
        )
        .await
        .map_err(|error| {
            if let Some(timed_out) =
                aegis_client::prepared_enrolled_quic::pre_auth_transport_failure(&error)
            {
                self.carrier_fault(crate::carrier_failover::dial_signal(timed_out));
            }
            handshake_refusal(&error)
        })?;
        let (stream, driver) = held.into_parts();
        let terminal: ChannelDriver = crate::quic_carrier::own_driver(driver, gate)?;
        Ok(HeldOuter::Quic(own(stream), terminal))
    }

    /// One target on its own authenticated H3 owner. No target or application
    /// byte is replayed, and this TCP fallback does not acquire UDP targets.
    #[cfg(feature = "enrolled-quic")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn open_target_on_quic(
        &self,
        interface: &crate::relay_socket::RelayInterface,
        pins: &crate::provider_session_body::EpochPins,
        generation: u64,
        gate: &crate::held_relay_services::WorkGate,
        transport: Transport,
        (host, port): (String, u16),
        permit: &mut EstablishPermit,
        deadline: tokio::time::Instant,
    ) -> io::Result<WebFlow> {
        if host.is_empty()
            || port == 0
            || transport != Transport::Tcp
            || self.selected_channel()? != CarrierChannel::MasqueQuic
        {
            return Err(refused());
        }
        let held = tokio::time::timeout_at(
            deadline,
            self.quic_carrier(interface, pins, generation, gate),
        )
        .await
        .map_err(|_| refused())??;
        let (stream, mut terminal) = held.into_parts();
        let mut inner = tokio::select! {
            connected = self.inner.connect(stream) => connected.map_err(|error| handshake_refusal(&error))?,
            () = &mut terminal => return Err(refused()),
            () = tokio::time::sleep_until(deadline) => return Err(refused()),
        };
        let request = OpenRequest {
            transport,
            version: 1,
            host,
            port,
        };
        tokio::select! {
            written = secure_channel::write_open(&mut inner, &request) => written.map_err(|_| refused())?,
            () = &mut terminal => return Err(refused()),
            () = tokio::time::sleep_until(deadline) => return Err(refused()),
        }
        permit.request_written();
        let status = tokio::select! {
            status = inner.read_u8() => status.map_err(|_| refused())?,
            () = &mut terminal => return Err(refused()),
            () = tokio::time::sleep_until(deadline) => return Err(refused()),
        };
        if status != 0 {
            return Err(refused());
        }
        Ok(WebFlow { inner, terminal })
    }

    fn verify_outer_handshake(&self, status: EchStatus, alpn: Option<&[u8]>) -> io::Result<()> {
        aegis_client::ech_policy::require_accepted_ech(self.carrier().relay(), status)
            .map_err(|_| refused())?;
        if alpn != Some(b"h2") {
            return Err(refused());
        }
        Ok(())
    }

    /// Prepare the H2 request from the same held credential and bound policy.
    /// A future dialer must first call `verify_outer_handshake` on its real TLS
    /// connection and retain Store/H2 ownership through terminal shutdown.
    pub(crate) fn carrier_request(&self, purpose: Purpose) -> io::Result<http::Request<()>> {
        self.carrier_request_for(self.carrier(), purpose)
    }

    /// The channel is bound to the selected signed endpoint, never inferred
    /// from an HTTP response or another endpoint with the same authority.
    pub(crate) fn selected_channel(&self) -> io::Result<CarrierChannel> {
        self.channel_for(self.selected)
    }

    fn channel_for(&self, index: usize) -> io::Result<CarrierChannel> {
        match &self.policy.settings().relay.carrier_program {
            None => Ok(
                if self
                    .carriers
                    .get(index)
                    .ok_or_else(refused)?
                    .relay()
                    .https_bridge
                    .is_some()
                {
                    CarrierChannel::OwnHttpsBridge
                } else {
                    CarrierChannel::DirectH2
                },
            ),
            Some(program) => program
                .routes
                .iter()
                .find(|route| route.endpoint_index == index)
                .map(|route| route.channel)
                .ok_or_else(refused),
        }
    }

    /// v40: the carrier request to `carrier`'s TLS name.
    fn carrier_request_for(
        &self,
        carrier: &HeldCarrier,
        purpose: Purpose,
    ) -> io::Result<http::Request<()>> {
        let index = self.carriers.index_of(carrier).ok_or_else(refused)?;
        if self.channel_for(index)? == CarrierChannel::HttpsWs {
            if purpose != Purpose::Traffic || carrier.relay().https_bridge.is_some() {
                return Err(refused());
            }
            let host = &carrier.relay().server_name;
            let authority = if host.parse::<std::net::Ipv6Addr>().is_ok() {
                format!("[{host}]")
            } else {
                host.clone()
            };
            let mut request = http::Request::builder()
                .method(http::Method::CONNECT)
                .uri(format!("https://{authority}{SECURE_WS_PATH}"))
                .header(http::header::SEC_WEBSOCKET_VERSION, "13")
                .body(())
                .map_err(|_| refused())?;
            request
                .extensions_mut()
                .insert(h2::ext::Protocol::from("websocket"));
            return Ok(request);
        }
        if !matches!(
            self.channel_for(index)?,
            CarrierChannel::DirectH2 | CarrierChannel::FrontedH2 | CarrierChannel::OwnHttpsBridge
        ) {
            return Err(refused());
        }
        let expected_path = carrier.relay().https_bridge.as_ref().map_or_else(
            || match purpose {
                Purpose::Traffic => secure_channel::GRPC_PATH,
                Purpose::Enrollment => secure_channel::enrollment_tls::GRPC_PATH,
            },
            |bridge| bridge.path(purpose),
        );
        let request = aegis_client::prepared_outer_tls::h2_carrier_request_from_held(
            carrier.relay(),
            self.bridge_for(carrier),
            purpose,
        )
        .map_err(|_| refused())?;
        if request.uri().path() != expected_path {
            return Err(refused());
        }
        Ok(request)
    }

    fn bridge_for(&self, carrier: &HeldCarrier) -> Option<&Credential> {
        carrier
            .relay()
            .https_bridge
            .as_ref()
            .and(self.bridge.as_ref())
    }

    /// D5's two-socket byte stream from held key material. The caller must
    /// supply a physically bound bootstrap socket. Only a descriptor from
    /// its verified H2 authority can name the ingress; the exact tuple is
    /// inserted into this epoch's TCP-only filter arm before the second
    /// physically bound socket connects. The packet service retains this
    /// stream and its exact ingress lease through the flow's terminal join.
    pub(crate) async fn web_response_carrier(
        &self,
        bootstrap_tcp: TcpStream,
        interface: &crate::relay_socket::RelayInterface,
        pins: &crate::provider_session_body::EpochPins,
        generation: u64,
    ) -> io::Result<HeldOuter> {
        if self.selected_channel()? != CarrierChannel::WebResponse {
            return Err(refused());
        }
        let bootstrap = self.carrier().peer();
        self.direct_peer(bootstrap_tcp.peer_addr().map_err(|_| refused())?)?;
        let private = self
            .carrier()
            .relay()
            .web_response
            .as_ref()
            .ok_or_else(refused)?;
        let credential = self.web_credential.as_ref().ok_or_else(refused)?.clone();
        let settings = aegis_client::device_web_response::client_settings(private);
        let limits = aegis_web_carrier::Limits::default();
        let deadline = tokio::time::Instant::now() + self.connect_timeout();
        tokio::time::timeout_at(deadline, async {
            let descriptor = aegis_web_carrier::Client::discover_on(
                self.outer_connector(),
                bootstrap_tcp,
                bootstrap,
                &settings,
                &credential,
                &limits,
            )
            .await
            .map_err(|_| refused())?;
            if !private
                .allowed_ingress_ips
                .contains(&descriptor.ingress.ip())
            {
                return Err(refused());
            }
            let ingress = descriptor.ingress;
            let socket = crate::relay_socket::bound_socket(ingress, interface)?;
            let lease = pins
                .authorize_web_ingress(generation, ingress)
                .ok_or_else(refused)?;
            let tcp = socket.connect(ingress).await.map_err(|_| refused())?;
            if tcp.peer_addr().map_err(|_| refused())? != ingress
                || crate::leak_guard::LEAK_GUARD.dial_refused(ingress)
            {
                return Err(refused());
            }
            let web = aegis_web_carrier::Client::connect_on(
                self.outer_connector(),
                tcp,
                &settings,
                descriptor,
                credential,
                limits,
            )
            .await
            .map_err(|_| refused())?;
            let mut terminal = web.terminal_watch();
            let driver: ChannelDriver = Box::pin(async move {
                if *terminal.borrow_and_update() {
                    return;
                }
                let _ = terminal.changed().await;
            });
            Ok(HeldOuter::Web(
                own(GuardedWebStream {
                    stream: web,
                    _ingress: lease,
                }),
                driver,
            ))
        })
        .await
        .map_err(|_| refused())?
    }

    /// Open one D5 target on a fresh authenticated web carrier. There is no
    /// pooled H2 fallback: each flow has a physically bound bootstrap and
    /// ingress socket, one inner device TLS identity, and its own Open.
    /// The caller holds a flow establishment permit from before the bootstrap
    /// dial through the Open write and retains `WebFlow` until its copy ends.
    #[allow(clippy::too_many_arguments)] // Exact bound owner API.
    pub(crate) async fn open_target_on_web(
        &self,
        bootstrap_tcp: TcpStream,
        interface: &crate::relay_socket::RelayInterface,
        pins: &crate::provider_session_body::EpochPins,
        generation: u64,
        transport: Transport,
        (host, port): (String, u16),
        permit: &mut EstablishPermit,
        deadline: tokio::time::Instant,
    ) -> io::Result<WebFlow> {
        if host.is_empty() || port == 0 || self.selected_channel()? != CarrierChannel::WebResponse {
            return Err(refused());
        }
        let held = tokio::time::timeout_at(
            deadline,
            self.web_response_carrier(bootstrap_tcp, interface, pins, generation),
        )
        .await
        .map_err(|_| refused())??;
        let (stream, mut terminal) = held.into_parts();
        let mut inner = tokio::select! {
            connected = self.inner.connect(stream) => connected.map_err(|_| refused())?,
            () = &mut terminal => return Err(refused()),
            () = tokio::time::sleep_until(deadline) => return Err(refused()),
        };
        let request = OpenRequest {
            transport,
            version: 1,
            host,
            port,
        };
        tokio::select! {
            written = secure_channel::write_open(&mut inner, &request) => written.map_err(|_| refused())?,
            () = &mut terminal => return Err(refused()),
            () = tokio::time::sleep_until(deadline) => return Err(refused()),
        }
        permit.request_written();
        let status = tokio::select! {
            status = inner.read_u8() => status.map_err(|_| refused())?,
            () = &mut terminal => return Err(refused()),
            () = tokio::time::sleep_until(deadline) => return Err(refused()),
        };
        if status != 0 {
            return Err(refused());
        }
        Ok(WebFlow { inner, terminal })
    }
}

/// Where a pooled flow's stream failed: in its inner handshake, or in its
/// Open exchange after it.
#[derive(Clone, Copy)]
enum Step {
    Handshake,
    Exchange,
}

/// The refusal of a pooled flow's failed stream. A TLS error stays
/// authentication class; else, when the stream's connection ended under it
/// (now or within `CONN_END_GRACE`), a connection loss; else the handshake
/// or Open-exchange class (`handshake_refusal`, `open_refusal`), so only a
/// stream-only end after mTLS and before the status is an unanswered Open.
async fn stream_refusal(
    error: &io::Error,
    end: &mut tokio::sync::watch::Receiver<Option<ConnEnd>>,
    stream_id: u32,
    step: Step,
) -> io::Error {
    if tls_failure(error) {
        return auth_refused();
    }
    if ended_within(end, stream_id, CONN_END_GRACE).await {
        return conn_lost();
    }
    match step {
        Step::Handshake => handshake_refusal(error),
        Step::Exchange => open_refusal(error),
    }
}

/// The refusal of a pooled flow whose handshake or Open write outlived
/// `HS_WATCHDOG` (S16j-1: or its flow's own deadline, which is earlier),
/// its stream already dropped (reset), long before the relay's deadline: a
/// connection loss when its connection ended, now or at its stall
/// watchdog's verdict (`PooledConn::lost_after_watchdog`), else a timeout
/// (`hs_inner`). The verdict is awaited past the flow's deadline too: a
/// stream lost after its 200 to a frozen path is a strike to record.
async fn watchdog_refusal(slot: &mut StreamSlot, stream_id: u32) -> io::Error {
    if slot.conn().lost_after_watchdog(Some(stream_id)).await {
        conn_lost()
    } else {
        // S16j-1: past its 200, unlike a carrier's own bound.
        slot.note(Refusal::HsInner);
        refused()
    }
}

/// One targetless PolicyAck on an established channel; a terminal H2 driver
/// aborts the pending exchange. The round trip is timed from just before the
/// request is written to the verified ACK.
async fn exchange_on(
    channel: AckReadyChannel,
    expected: IssuanceBinding<'_>,
    event: &'static str,
) -> io::Result<AuthenticatedRelayObservation> {
    let AckReadyChannel {
        mut inner,
        mut driver,
        mut driver_done,
        live,
        conn,
    } = channel;
    if driver_done {
        return Err(stage(event, "channel_ended")(()));
    }
    // S16l: on the ACK connection, its stall watchdog watches the wait.
    let awaiting = conn.as_ref().map(|(conn, _)| conn.awaiting());
    let conn = conn.map(|(conn, _)| conn);
    let started = tokio::time::Instant::now();
    let valid_until = {
        let exchange = aegis_client::policy_ack_exchange::exchange_on_authenticated_stream(
            &mut inner, expected, false,
        );
        tokio::pin!(exchange);
        tokio::select! {
            result = &mut exchange => result.map_err(exchange_stage(event, "ack_exchange"))?,
            _ = &mut driver => {
                // aegis-server shuts the inner stream right after
                // write_ack, and the connection may end with it. The
                // driver's last poll can read the ACK and that end in
                // one go: finish on the frames already received, under
                // the same deadline. Nothing further can arrive.
                driver_done = true;
                exchange.await.map_err(exchange_stage(event, "ack_after_close"))?
            }
        }
    };
    let exchange_elapsed = started.elapsed();
    // The relay ends the stream after its ACK: no longer live there.
    drop((awaiting, live));
    Ok(AuthenticatedRelayObservation {
        inner,
        driver,
        driver_done,
        valid_until,
        exchange_elapsed,
        conn,
    })
}

/// The first-ACK and fresh re-ACK log event.
const ACK_STAGE: &str = "ack_stage";

/// Logs the ACK step that refused under `event`, without the error text
/// (which may name peers or certificates), and returns the usual opaque
/// refusal.
fn stage<E>(event: &'static str, step: &'static str) -> impl FnOnce(E) -> io::Error {
    move |_| {
        crate::apple::log_code(event, step);
        refused()
    }
}

/// `stage` for a handshake step: the refusal keeps its authentication class.
fn handshake_stage<E: Judged>(
    event: &'static str,
    step: &'static str,
) -> impl FnOnce(E) -> io::Error {
    move |error| {
        crate::apple::log_code(event, step);
        handshake_refusal(&error)
    }
}

/// `stage` for the PolicyAck exchange after the inner handshake.
fn exchange_stage<E: Judged>(
    event: &'static str,
    step: &'static str,
) -> impl FnOnce(E) -> io::Error {
    move |error| {
        crate::apple::log_code(event, step);
        ack_refusal(&error)
    }
}

fn ack_stage<E>(step: &'static str) -> impl FnOnce(E) -> io::Error {
    stage(ACK_STAGE, step)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::{https_bridge::ClientSettings as BridgeSettings, RelaySettings};
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose, PKCS_ED25519,
    };
    use serde_json::json;
    use std::path::Path;
    use zeroize::Zeroizing;

    #[test]
    fn held_crypto_refusals_keep_their_class_and_one_opaque_text() {
        use crate::establish_limit::{is_auth_refused, is_open_unanswered};
        let alert = || {
            io::Error::new(
                io::ErrorKind::InvalidData,
                tokio_rustls::rustls::Error::AlertReceived(
                    tokio_rustls::rustls::AlertDescription::BadCertificate,
                ),
            )
        };
        // The Open exchange: a TLS error is authentication class, the relay
        // ending the channel an unanswered Open, anything else neither.
        assert!(is_auth_refused(&open_refusal(&alert())));
        for kind in [io::ErrorKind::UnexpectedEof, io::ErrorKind::ConnectionReset] {
            let refusal = open_refusal(&io::Error::from(kind));
            assert!(is_open_unanswered(&refusal), "{kind:?}");
            assert!(!is_auth_refused(&refusal), "{kind:?}");
        }
        for kind in [io::ErrorKind::TimedOut, io::ErrorKind::Other] {
            let refusal = open_refusal(&io::Error::from(kind));
            assert!(!is_open_unanswered(&refusal) && !is_auth_refused(&refusal));
        }
        // A handshake: only a TLS error or an explicit carrier refusal.
        assert!(is_auth_refused(&handshake_refusal(&alert())));
        let carrier = anyhow::anyhow!("secure carrier rejected with HTTP 403 Forbidden");
        assert!(is_auth_refused(&handshake_refusal(&carrier)));
        let ended = anyhow::anyhow!("H2 driver ended before carrier response: Ok(())");
        let ended = handshake_refusal(&ended);
        assert!(!is_auth_refused(&ended) && !is_open_unanswered(&ended));
        assert!(!is_auth_refused(&handshake_refusal(&io::Error::from(
            io::ErrorKind::UnexpectedEof
        ))));
        // The PolicyAck exchange: only a TLS error; never an unanswered Open.
        assert!(is_auth_refused(&ack_refusal(&alert())));
        let dropped = ack_refusal(&io::Error::from(io::ErrorKind::UnexpectedEof));
        assert!(!is_auth_refused(&dropped) && !is_open_unanswered(&dropped));
        // Every class reads the same to whoever sees the error.
        for refusal in [
            open_refusal(&alert()),
            open_refusal(&io::Error::from(io::ErrorKind::UnexpectedEof)),
            handshake_refusal(&ended),
        ] {
            assert_eq!(refusal.to_string(), refused().to_string());
            assert_eq!(refusal.kind(), refused().kind());
        }
    }

    #[test]
    fn held_nested_tls_observes_ack_and_terminal_h2_failure() {
        use aegis_client::{
            protected_identity_store::ProtectedIdentityStore,
            protected_online_expectation::ProtectedOnlineExpectation,
        };
        use std::{fs, os::unix::fs::PermissionsExt, sync::atomic::AtomicU64};
        static STORE_FIXTURE_ID: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "aegis-ne-ack-store-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            STORE_FIXTURE_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let identity = directory.join("identity");
        fs::create_dir_all(&identity).unwrap();
        fs::set_permissions(&identity, fs::Permissions::from_mode(0o700)).unwrap();
        for (name, bytes) in [(".lock", b"".as_slice()), ("identity.json", b"fixture")] {
            let path = identity.join(name);
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let store = ProtectedOnlineExpectation::open_existing(&identity, &"a".repeat(64)).unwrap();
        let held_identity = identity.clone();
        let mut owner =
            crate::store_last_thread::StoreLastThreadOwner::spawn(store, move |_store, _stop| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                runtime.block_on(held_nested_tls_body(held_identity));
                drop(runtime);
                Ok(())
            })
            .unwrap();
        owner.stop_and_join(Duration::from_secs(2)).unwrap();
        ProtectedIdentityStore::open_existing(&identity).unwrap();
        fs::remove_dir_all(directory).unwrap();
    }

    async fn held_nested_tls_body(store_identity: std::path::PathBuf) {
        use aegis_client::protected_identity_store::ProtectedIdentityStore;
        assert!(ProtectedIdentityStore::open_existing(&store_identity).is_err());
        use crate::bridge::{LeasedPacketBridge, PacketBridge, RevokeLeaseOnDrop};
        use crate::test_relay::{serve_one, AckReply, Behavior, RelayIdentity};
        use aegis_client::capture_lease_gate::CaptureLeaseDeadline;
        use aegis_core::secure_channel::public_certificate_chain_sha256;
        use sha2::{Digest, Sha256};
        use std::sync::{
            atomic::{AtomicU64, Ordering},
            Arc,
        };
        use tokio::net::{TcpListener, TcpStream};

        let outer = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut ca_params = CertificateParams::new(vec![]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let signed = |name: &str, usage| {
            let mut params = CertificateParams::new(vec![name.into()]).unwrap();
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![usage];
            let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
            let cert = params.signed_by(&key, &ca, &ca_key).unwrap();
            let raw_digest: [u8; 32] = Sha256::digest(cert.der().as_ref()).into();
            (
                cert.pem().into_bytes(),
                key.serialize_pem().into_bytes(),
                raw_digest,
            )
        };
        let (server_cert, server_key, _) =
            signed("inner.test", ExtendedKeyUsagePurpose::ServerAuth);
        let (device_cert, device_key, device_raw) =
            signed("device.test", ExtendedKeyUsagePurpose::ClientAuth);
        let directory = std::env::temp_dir().join(format!(
            "aegis-ne-ack-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let device_path = directory.join("device.pem");
        std::fs::write(&device_path, &device_cert).unwrap();
        let digest: String = public_certificate_chain_sha256(&device_path)
            .unwrap()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let relay = Arc::new(RelayIdentity::new(
            outer.cert.der().clone(),
            outer.key_pair.serialize_der(),
            &server_cert,
            &server_key,
            ca.pem().as_bytes(),
            device_raw
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let expiry = secure_channel::registry::unix_now().unwrap() + 60;
        let expected_digest = digest.clone();
        let reply = AckReply {
            certificate_sha256: digest,
            certificate_not_after_unix_secs: expiry,
            policy_not_after_unix_secs: expiry,
            generation: 7,
            snapshot_sha256: "c".repeat(64),
            effective_valid_for_ms: 3_000,
        };
        let (client_done, server_done) = tokio::sync::oneshot::channel();
        let (relay_events, _relay_steps) = std::sync::mpsc::channel();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            // Keep the H2 connection after the ACK until the client side says
            // so; the test then observes the terminal H2 driver.
            serve_one(
                tcp,
                relay,
                Behavior::AckThenHold(reply, server_done),
                relay_events,
            )
            .await;
        });
        let public = [
            serde_json::to_vec(&json!({
                "schema":"aegis_device_bundle_v4", "product_mode":"full-wide-tun", "udp":true,
                "relay_server":address.to_string(), "outer_server_name":"localhost",
                "inner_server_name":"inner.test",
                "relay_endpoints":[{"server":address.to_string(),"server_name":"localhost"}],
                "enrollment":{"protocol":"aegis-enrollment-v1", "authority_server":"127.0.0.1:8443",
                    "outer_server_name":"authority.test", "inner_server_name":"issuer.test",
                    "automatic_renewal":true, "renewal_policy":"same-key-v1"}
            }))
            .unwrap(),
            outer.cert.pem().into_bytes(),
            ca.pem().into_bytes(),
            ca.pem().into_bytes(),
        ];
        let policy = BoundRelayPolicy::from_snapshot(
            public,
            None,
            Path::new("/private/tmp/prepared-bundle"),
            Path::new("/private/tmp/prepared-identity"),
        )
        .unwrap();
        let prepared = PreparedCryptoInputs::from_snapshot(
            policy,
            CapturedCryptoPayload {
                outer_ca: outer.cert.pem().into_bytes(),
                inner_ca: ca.pem().into_bytes(),
                certificate: device_cert,
                private_key: Zeroizing::new(device_key),
                bridge: None,
                web_response: None,
            },
        )
        .unwrap();
        let expected = aegis_client::issuance_binding::IssuanceBinding {
            certificate_sha256: &expected_digest,
            not_after_unix_secs: expiry,
            issued_generation: Some(7),
            snapshot_sha256: Some(
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            ),
        };
        let tcp = TcpStream::connect(address).await.unwrap();
        let mut observed =
            tokio::time::timeout(Duration::from_secs(5), prepared.observe_ack(tcp, expected))
                .await
                .unwrap()
                .unwrap();
        assert!(ProtectedIdentityStore::open_existing(&store_identity).is_err());
        assert!(observed.valid_until() > tokio::time::Instant::now());
        let (denied_ready, denied_received) = tokio::sync::oneshot::channel();
        let changed_store = observed
            .monitor_inert_until_terminal_ready(|| Err(refused()), denied_ready)
            .await
            .expect_err("changed protected state was admitted");
        assert_eq!(changed_store.kind(), io::ErrorKind::PermissionDenied);
        assert!(denied_received.await.is_err());
        // A real ACK and pending H2 driver must not turn a stale second
        // Store/ACK recheck into a ready signal. This catches any handoff that
        // uses only the pre-poll check before packet lease construction.
        let (post_poll_ready, post_poll_received) = tokio::sync::oneshot::channel();
        let mut rechecks = 0;
        let stale_after_pending = observed
            .monitor_inert_until_terminal_ready(
                || {
                    rechecks += 1;
                    if rechecks == 1 {
                        Ok(())
                    } else {
                        Err(refused())
                    }
                },
                post_poll_ready,
            )
            .await
            .expect_err("post-poll stale ACK was admitted");
        assert_eq!(stale_after_pending.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(rechecks, 2);
        assert!(post_poll_received.await.is_err());
        let lease = CaptureLeaseDeadline::default();
        lease.replace(Some(20)).unwrap();
        let now = Arc::new(AtomicU64::new(10));
        let bridge = LeasedPacketBridge::with_clock(PacketBridge::default(), lease, move || {
            Ok(now.load(Ordering::SeqCst))
        });
        let revoke = RevokeLeaseOnDrop::new(bridge.clone());
        let mut packet = vec![0; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());
        bridge.from_os(&packet).unwrap();
        let closer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(350)).await;
            client_done.send(()).unwrap();
        });
        let mut rechecks = 0;
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let terminal_future = tokio::time::timeout(Duration::from_secs(2), async {
            // The same scope owns the active bridge and live H2 driver:
            // terminal return or future cancellation seals the bridge.
            let _revoke = revoke;
            observed
                .monitor_inert_until_terminal_ready(
                    || {
                        rechecks += 1;
                        Ok(())
                    },
                    ready_tx,
                )
                .await
        });
        let ready_future = tokio::time::timeout(Duration::from_secs(1), ready_rx);
        let (terminal, ready) = tokio::join!(terminal_future, ready_future);
        ready
            .expect("H2 monitor never reached its initial pending poll")
            .expect("H2 monitor ended before ready");
        let terminal = terminal
            .expect("H2 driver remained pending after the authenticated peer closed")
            .expect_err("terminal H2 was admitted");
        assert_eq!(terminal.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            rechecks >= 2,
            "held driver did not survive a periodic recheck"
        );
        assert!(bridge.from_os(&packet).is_err());
        assert!(bridge.to_os().is_err());
        drop(observed);
        closer.await.unwrap();
        server.await.unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn fixture() -> (BoundRelayPolicy, CapturedCryptoPayload) {
        fixture_profile(|_| {})
    }

    fn fixture_profile(
        edit: impl FnOnce(&mut serde_json::Value),
    ) -> (BoundRelayPolicy, CapturedCryptoPayload) {
        fixture_profile_with_bridge(edit, None)
    }

    fn fixture_profile_with_bridge(
        edit: impl FnOnce(&mut serde_json::Value),
        bridge: Option<crate::app_group::CapturedBridgeSnapshot>,
    ) -> (BoundRelayPolicy, CapturedCryptoPayload) {
        let mut ca_params = CertificateParams::new(vec![]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let mut device = CertificateParams::new(vec!["device.test".into()]).unwrap();
        device.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        device.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let device_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let device_cert = device.signed_by(&device_key, &ca, &ca_key).unwrap();
        let ca_pem = ca.pem().into_bytes();
        let mut profile = json!({
            "schema":"aegis_device_bundle_v4", "product_mode":"full-wide-tun", "udp":true,
            "relay_server":"127.0.0.1:443", "outer_server_name":"relay.test",
            "inner_server_name":"origin.test",
            "relay_endpoints":[{"server":"127.0.0.1:443","server_name":"relay.test"}],
            "enrollment":{"protocol":"aegis-enrollment-v1", "authority_server":"127.0.0.1:8443",
                "outer_server_name":"authority.test", "inner_server_name":"issuer.test",
                "automatic_renewal":true, "renewal_policy":"same-key-v1"}
        });
        edit(&mut profile);
        let public = [
            serde_json::to_vec(&profile).unwrap(),
            ca_pem.clone(),
            ca_pem.clone(),
            ca_pem.clone(),
        ];
        let policy_bridge = bridge
            .as_ref()
            .map(|held| crate::app_group::CapturedBridgeSnapshot {
                settings: held.settings.clone(),
                secret: held.secret.clone(),
            });
        let policy = BoundRelayPolicy::from_snapshot(
            public,
            policy_bridge,
            Path::new("/private/tmp/prepared-bundle"),
            Path::new("/private/tmp/prepared-identity"),
        )
        .unwrap();
        let payload = CapturedCryptoPayload {
            outer_ca: ca_pem.clone(),
            inner_ca: ca_pem,
            certificate: device_cert.pem().into_bytes(),
            private_key: Zeroizing::new(device_key.serialize_pem().into_bytes()),
            bridge,
            web_response: None,
        };
        (policy, payload)
    }

    #[test]
    fn mixed_direct_bridge_requests_keep_credential_on_bridge_pin_only() {
        let bridge = BridgeSettings {
            authority: "bridge.test".into(),
            path: "/private/stream".into(),
            enrollment_path: "/private/enroll".into(),
            credential_file: "/private/tmp/prepared-identity/bridge-credential".into(),
        };
        let held = crate::app_group::CapturedBridgeSnapshot {
            settings: bridge,
            secret: Zeroizing::new([b'a'; 64]),
        };
        let (policy, payload) = fixture_profile_with_bridge(
            |profile| {
                profile["relay_endpoints"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({
                        "server":"127.0.0.2:443", "server_name":"bridge.test"
                    }));
                profile["carrier_program"] = json!({
                    "routes":[
                        {"channel":"direct_h2","endpoint_index":0},
                        {"channel":"own_https_bridge","endpoint_index":1}
                    ],
                    "bridge":{"authority":"bridge.test","path":"/private/stream",
                        "enrollment_path":"/private/enroll"}
                });
            },
            Some(held),
        );
        let mut prepared = PreparedCryptoInputs::from_snapshot(policy, payload).unwrap();
        let direct = prepared.carrier_request(Purpose::Traffic).unwrap();
        assert_eq!(direct.uri().path(), secure_channel::GRPC_PATH);
        assert!(!direct
            .headers()
            .contains_key(aegis_core::https_bridge::KEY_HEADER));
        prepared.selected = 1;
        let bridged = prepared.carrier_request(Purpose::Traffic).unwrap();
        assert_eq!(bridged.uri().path(), "/private/stream");
        assert!(bridged
            .headers()
            .contains_key(aegis_core::https_bridge::KEY_HEADER));
    }

    #[test]
    fn selected_ws_pin_uses_only_signed_extended_connect() {
        let (policy, payload) = fixture_profile(|profile| {
            profile["relay_endpoints"]
                .as_array_mut()
                .unwrap()
                .push(json!({
                    "server":"127.0.0.2:443", "server_name":"ws.test"
                }));
            profile["carrier_program"] = json!({"routes":[
                {"channel":"direct_h2","endpoint_index":0},
                {"channel":"https_ws","endpoint_index":1}
            ]});
        });
        let mut prepared = PreparedCryptoInputs::from_snapshot(policy, payload).unwrap();
        assert_eq!(
            prepared.selected_channel().unwrap(),
            CarrierChannel::DirectH2
        );
        assert_eq!(
            prepared
                .carrier_request(Purpose::Traffic)
                .unwrap()
                .uri()
                .path(),
            secure_channel::GRPC_PATH
        );
        prepared.select_carrier(1, None).unwrap();
        assert_eq!(
            prepared.pinned_peer().unwrap(),
            "127.0.0.2:443".parse::<std::net::SocketAddr>().unwrap()
        );
        assert_eq!(
            prepared.selected_channel().unwrap(),
            CarrierChannel::HttpsWs
        );
        let request = prepared.carrier_request(Purpose::Traffic).unwrap();
        assert_eq!(request.method(), http::Method::CONNECT);
        assert_eq!(request.uri().path(), SECURE_WS_PATH);
        assert_eq!(request.uri().host(), Some("ws.test"));
        assert!(!request
            .headers()
            .contains_key(aegis_core::https_bridge::KEY_HEADER));
        assert!(request.extensions().get::<h2::ext::Protocol>().is_some());
        assert!(prepared.carrier_request(Purpose::Enrollment).is_err());
    }

    #[test]
    fn prepared_crypto_uses_held_bytes_without_opening_paths() {
        let (policy, payload) = fixture();
        let prepared = PreparedCryptoInputs::from_snapshot(policy, payload).unwrap();
        assert!(prepared
            .verify_outer_handshake(EchStatus::NotOffered, Some(b"h2"))
            .is_ok());
        assert!(prepared
            .verify_outer_handshake(EchStatus::NotOffered, Some(b"http/1.1"))
            .is_err());
        let traffic = prepared.carrier_request(Purpose::Traffic).unwrap();
        assert_eq!(traffic.uri().path(), secure_channel::GRPC_PATH);
        assert!(!traffic
            .headers()
            .contains_key(aegis_core::https_bridge::KEY_HEADER));
        let enrollment = prepared.carrier_request(Purpose::Enrollment).unwrap();
        assert_eq!(
            enrollment.uri().path(),
            secure_channel::enrollment_tls::GRPC_PATH
        );
        let (policy, mut payload) = fixture();
        payload.outer_ca = b"other CA".to_vec();
        assert!(PreparedCryptoInputs::from_snapshot(policy, payload).is_err());
        let (policy, mut payload) = fixture();
        payload.private_key.fill(0);
        assert!(PreparedCryptoInputs::from_snapshot(policy, payload).is_err());
    }

    #[test]
    fn direct_observation_requires_pinned_peer() {
        let (policy, payload) = fixture();
        let prepared = PreparedCryptoInputs::from_snapshot(policy, payload).unwrap();
        let pinned: SocketAddr = "127.0.0.1:443".parse().unwrap();
        assert!(prepared.direct_peer(pinned).is_ok());
        assert!(prepared
            .direct_peer("127.0.0.1:444".parse().unwrap())
            .is_err());
        let exact = prepared.policy.settings().relay.clone();
        assert!(prepared.relay_matches(&exact));
        let mut substituted = exact;
        substituted.server = "127.0.0.1:444".into();
        assert!(!prepared.relay_matches(&substituted));
    }

    #[test]
    fn signed_runtime_terms_need_packet_section_and_the_one_pinned_relay() {
        let packet = json!({"mtu":1400, "dns_servers":["198.19.255.2"],
            "dns_upstream":"198.19.255.2:53", "max_flows":64, "idle_ms":30_000});
        // A bundle without a macOS packet section authorizes no binding.
        let (policy, payload) = fixture();
        let prepared = PreparedCryptoInputs::from_snapshot(policy, payload).unwrap();
        assert!(prepared.signed_runtime_terms().is_err());
        let (policy, payload) = fixture_profile(|profile| {
            profile["macos_packet"] = packet.clone();
        });
        let digest = policy
            .signed_runtime_terms()
            .unwrap()
            .profile_sha256
            .to_owned();
        let prepared = PreparedCryptoInputs::from_snapshot(policy, payload).unwrap();
        let terms = prepared.signed_runtime_terms().unwrap();
        assert_eq!(terms.relay, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(terms.mtu, 1400);
        assert_eq!(terms.dns, ["198.19.255.2".parse::<IpAddr>().unwrap()]);
        assert_eq!(terms.profile_sha256, digest);
        // v40 (CP-D3 M1): a signed pool binds the primary pin's terms,
        // whichever pin a session selects (the saved intent names the
        // primary). Before v40 any second pin bound nothing.
        let (policy, payload) = fixture_profile(|profile| {
            profile["macos_packet"] = packet.clone();
            profile["relay_endpoints"]
                .as_array_mut()
                .unwrap()
                .push(json!({"server":"127.0.0.2:443","server_name":"relay.test"}));
        });
        assert!(policy.signed_runtime_terms().is_ok());
        let mut prepared = PreparedCryptoInputs::from_snapshot(policy, payload).unwrap();
        assert_eq!(
            prepared.signed_runtime_terms().unwrap().relay,
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
        prepared.select_carrier(1, None).unwrap();
        assert_eq!(
            prepared.signed_runtime_terms().unwrap().relay,
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn a_session_dials_only_its_selected_pin_with_that_pins_tls_name() {
        let (policy, payload) = fixture_profile(|profile| {
            profile["relay_endpoints"] = json!([
                {"server":"127.0.0.1:443","server_name":"relay.test"},
                {"server":"127.0.0.2:8443","server_name":"edge.fronted.test"},
                {"server":"127.0.0.3:443","server_name":"edge.fronted.test"}
            ]);
        });
        let mut prepared = PreparedCryptoInputs::from_snapshot(policy, payload).unwrap();
        let pins: Vec<SocketAddr> = ["127.0.0.1:443", "127.0.0.2:8443", "127.0.0.3:443"]
            .into_iter()
            .map(|pin| pin.parse().unwrap())
            .collect();
        assert_eq!(prepared.carrier_pins(), pins);
        assert_eq!(prepared.primary_peer(), pins[0]);
        // The primary until a session selects another pin.
        assert_eq!(prepared.pinned_peer().unwrap(), pins[0]);
        for (index, name) in [
            (1, "edge.fronted.test"),
            (2, "edge.fronted.test"),
            (0, "relay.test"),
        ] {
            prepared.select_carrier(index, None).unwrap();
            assert_eq!(prepared.pinned_peer().unwrap(), pins[index]);
            // Exactly the selected pin: every other pin, and any other
            // tuple, is refused before a byte is sent.
            for (other, pin) in pins.iter().enumerate() {
                assert_eq!(prepared.direct_peer(*pin).is_ok(), other == index);
            }
            assert!(prepared
                .direct_peer("127.0.0.2:443".parse().unwrap())
                .is_err());
            let request = prepared.carrier_request(Purpose::Traffic).unwrap();
            assert_eq!(request.uri().host(), Some(name));
            assert_eq!(request.uri().path(), secure_channel::GRPC_PATH);
            assert_eq!(prepared.carrier().relay().server_name, name);
            assert!(prepared.carrier().relay().carrier_failover.is_none());
        }
        assert!(prepared.select_carrier(3, None).is_err());
        // The pool's own policy is the profile's: a pool of two or more pins
        // carries the default failover policy.
        assert!(prepared.signed_relay().carrier_failover.is_some());
        // A plan of the profile's controller orders every pin once.
        let plan = prepared
            .carrier_plan(aegis_core::brain::carrier_failover::NetworkKey::UNKNOWN)
            .unwrap();
        let mut order = plan.order().to_vec();
        order.sort_unstable();
        assert_eq!(order, [0, 1, 2]);
        assert!(plan.ticket(0).is_some());
    }

    #[test]
    fn a_held_pool_with_a_name_pin_or_a_repeated_pin_is_refused() {
        for endpoints in [
            json!([
                {"server":"127.0.0.1:443","server_name":"relay.test"},
                {"server":"127.0.0.1:443","server_name":"relay.test"}
            ]),
            json!([
                {"server":"127.0.0.1:443","server_name":"relay.test"},
                {"server":"[::]:443","server_name":"relay.test"}
            ]),
        ] {
            let attempt = std::panic::catch_unwind(|| {
                fixture_profile(|profile| profile["relay_endpoints"] = endpoints.clone())
            });
            // Either the profile validator or the held pool refuses it.
            if let Ok((policy, payload)) = attempt {
                assert!(PreparedCryptoInputs::from_snapshot(policy, payload).is_err());
            }
        }
    }

    #[tokio::test]
    async fn target_opener_refuses_unpinned_peer_before_dial() {
        use crate::{
            flow_pool::FlowPool, held_relay_services::WorkGate, provider_session_body::EpochPins,
            relay_socket::RelayInterface,
        };
        let (policy, payload) = fixture();
        let prepared =
            std::sync::Arc::new(PreparedCryptoInputs::from_snapshot(policy, payload).unwrap());
        let limiter = crate::establish_limit::EstablishLimiter::new(Default::default());
        let permit = limiter
            .acquire(crate::establish_limit::Purpose::Flow, Duration::ZERO)
            .await
            .unwrap();
        // S16h: every flow's stream goes through the session's flow pool,
        // which is never built for a peer other than the signed relay.
        let error = FlowPool::new(
            "127.0.0.1:444".parse().unwrap(),
            RelayInterface::loopback_for_test(),
            prepared.clone(),
            (limiter.clone(), WorkGate::new()),
            (EpochPins::default(), 0),
        )
        .err()
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(FlowPool::new(
            "127.0.0.1:443".parse().unwrap(),
            RelayInterface::loopback_for_test(),
            prepared,
            (limiter.clone(), WorkGate::new()),
            (EpochPins::default(), 0),
        )
        .is_ok());
        // Refused before any request: the permit was never returned early.
        assert!(!permit.is_written());
        assert_eq!(limiter.active(), (0, 1));
        assert_eq!(limiter.unverified(), 0);
    }

    #[tokio::test]
    async fn held_services_refuse_datagrams_before_any_granted_lease() {
        use aegis_client::packet_engine::services::{EngineEvent, EventSink, RelayServices};
        struct NoEvents;
        impl EventSink for NoEvents {
            fn emit(&self, _: &'static str, _: EngineEvent, _: &'static str, _: serde_json::Value) {
            }
        }
        let (policy, payload) = fixture();
        let prepared =
            std::sync::Arc::new(PreparedCryptoInputs::from_snapshot(policy, payload).unwrap());
        let settings = prepared.policy.settings().relay.clone();
        let pool = crate::flow_pool::FlowPool::new(
            "127.0.0.1:443".parse().unwrap(),
            crate::relay_socket::RelayInterface::loopback_for_test(),
            prepared,
            (
                crate::establish_limit::EstablishLimiter::new(Default::default()),
                crate::held_relay_services::WorkGate::new(),
            ),
            (crate::provider_session_body::EpochPins::default(), 0),
        )
        .unwrap();
        // An open gate but a bridge that never saw an ACK-derived grant.
        let service = crate::held_relay_services::HeldRelayServices::new(
            std::sync::Arc::new(NoEvents),
            crate::bridge::LeasedPacketBridge::new(
                crate::bridge::PacketBridge::default(),
                aegis_client::capture_lease_gate::CaptureLeaseDeadline::default(),
            ),
            pool,
        )
        .unwrap();
        let target = aegis_client::relay_runtime_types::ConnectTarget {
            host: "example.org".into(),
            port: 443,
        };
        assert!(service
            .udp_once(&settings, target, b"no packet")
            .await
            .is_err());
        let (_tx, outbound) = tokio::sync::mpsc::channel(1);
        let (incoming, _rx) = tokio::sync::mpsc::channel(1);
        assert!(service
            .udp_flow(&settings, "example.org", 443, outbound, incoming)
            .await
            .is_err());
    }

    #[test]
    fn held_bridge_request_refuses_path_reload_and_missing_credential() {
        let settings = RelaySettings {
            server_name: "bridge.test".into(),
            https_bridge: Some(BridgeSettings {
                authority: "bridge.test".into(),
                path: "/private/stream".into(),
                enrollment_path: "/private/enroll".into(),
                credential_file: "/private/tmp/aegis-b06-r32-no-such-key".into(),
            }),
            ..RelaySettings::default()
        };
        let held = Credential::from_captured_bytes(&[b'a'; 64]).unwrap();
        assert!(settings
            .https_bridge
            .as_ref()
            .unwrap()
            .load_credential()
            .is_err());
        let traffic = aegis_client::prepared_outer_tls::h2_carrier_request_from_held(
            &settings,
            Some(&held),
            Purpose::Traffic,
        )
        .unwrap();
        assert_eq!(traffic.uri().path(), "/private/stream");
        assert!(traffic
            .headers()
            .get(aegis_core::https_bridge::KEY_HEADER)
            .unwrap()
            .is_sensitive());
        assert!(
            aegis_client::prepared_outer_tls::h2_carrier_request_from_held(
                &settings,
                None,
                Purpose::Traffic,
            )
            .is_err()
        );
    }
}
