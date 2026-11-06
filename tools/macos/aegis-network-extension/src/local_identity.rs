//! Local App Group identity custody for a future PacketTunnel owner.
//! This is neither an authenticated relay ACK nor permission to start capture.

use crate::packet_engine::PacketEngineConfig;
use crate::{
    ack_conn::{AckLink, ConnLive},
    bound_relay_policy::BoundRelayPolicy,
    establish_limit::{is_auth_refused, EstablishLimiter},
    flow_pool::{FlowPool, PooledConn},
    held_relay_services::{HeldRelayServices, WorkGate},
    prepared_crypto::{AckReadyChannel, AuthenticatedRelayObservation, PreparedCryptoInputs},
    provider_session_body::{EpochPins, Trace},
    relay_socket::{connect_bound, RelayInterface},
};
use crate::{
    app_group::CapturedAppGroupInputs,
    bridge::{LeasedPacketBridge, RevokeLeaseOnDrop},
};
use crate::{
    configuration::SavedProviderIntent,
    policy::FullWide,
    runtime_binding::{self, DerivedRuntimeBinding},
};
use aegis_client::{
    observed_policy_ack::ObservedPolicyAck,
    online_expectation::OnlineExpectation,
    packet_engine::services::EventSink,
    protected_online_expectation::ProtectedOnlineExpectation,
    public_profile_file::{profile_digest_bytes, read_public, MEMBERS},
};
use aegis_core::carrier_program::CarrierChannel;
use aegis_core::secure_channel::registry;
use std::{io, net::SocketAddr, path::Path, sync::Arc, time::Duration};
use tokio::net::TcpStream;

fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "local online identity admission refused",
    )
}

pub(crate) fn public_profile_digest(bundle: &Path) -> io::Result<String> {
    let payload = [
        read_public(&bundle.join(MEMBERS[0])).map_err(|_| refused())?,
        read_public(&bundle.join(MEMBERS[1])).map_err(|_| refused())?,
        read_public(&bundle.join(MEMBERS[2])).map_err(|_| refused())?,
        read_public(&bundle.join(MEMBERS[3])).map_err(|_| refused())?,
    ];
    Ok(profile_digest_bytes(&payload))
}

/// Owns both the signed App Group capture and the one protected Store lock.
/// The snapshot is an issuance floor for subsequent observations, not an ACK.
pub struct CapturedLocalIdentity {
    inputs: CapturedAppGroupInputs,
    online: Arc<ProtectedOnlineExpectation<'static>>,
    initial: OnlineExpectation,
    profile_sha256: String,
}

/// A prepared value cannot escape without retaining the Store and App Group
/// descriptors that produced it. It still grants no relay or packet authority.
#[allow(dead_code)]
pub(crate) struct PreparedLocalSession {
    identity: CapturedLocalIdentity,
    // Shared before the first ACK only with this session's own channel
    // openers; the observed session keeps this same allocation.
    crypto: Arc<PreparedCryptoInputs>,
}

/// Inert observation retaining the exact Store claim, inner TLS and H2 driver.
/// It cannot be used as a packet lease or registered provider factory.
#[must_use = "retain the observed channel and protected Store together"]
#[allow(dead_code)]
pub(crate) struct ObservedLocalSession {
    // Rust drops fields in declaration order: close inner TLS and H2 before
    // releasing the held crypto policy and protected Store claim.
    channel: AuthenticatedRelayObservation,
    ack: ObservedPolicyAck,
    prepared: Arc<PreparedCryptoInputs>,
    identity: CapturedLocalIdentity,
    saved: SavedProviderIntent,
    // Derived before the ACK request; every later derivation must equal it.
    binding: DerivedRuntimeBinding,
    peer: SocketAddr,
    // Every later relay socket of this session is bound to this interface.
    interface: RelayInterface,
}

/// One re-ACK request derived from a live observed session. It holds a clone
/// of the session's prepared crypto, the issuance bound just before the
/// request and the session's verified relay peer; it borrows nothing, so the
/// session keeps driving its own channel while this exchange runs.
#[must_use = "a re-ACK request is inert until observed and installed"]
pub(crate) struct ReackRequest {
    crypto: Arc<PreparedCryptoInputs>,
    before: OnlineExpectation,
    peer: SocketAddr,
    interface: RelayInterface,
    web_epoch: Option<(EpochPins, u64)>,
    #[cfg(feature = "enrolled-quic")]
    quic_gate: Option<Arc<WorkGate>>,
}

/// A fresh authenticated channel and ACK, not yet part of any session.
#[must_use = "install the re-ACK into the session it was requested from"]
pub(crate) struct ReackObservation {
    channel: AuthenticatedRelayObservation,
    before: OnlineExpectation,
}

/// Opens authenticated channels (phase a of an ACK) to a live session's
/// verified relay peer with its held crypto. It binds no issuance and sends
/// no request: a `ReackRequest` bound just before its request does.
#[derive(Clone)]
pub(crate) struct ChannelOpener {
    crypto: Arc<PreparedCryptoInputs>,
    peer: SocketAddr,
    interface: RelayInterface,
}

/// An authenticated channel opened in advance for the next re-ACK. It holds
/// the crypto that opened it, so only a request of that same session can use
/// it; it grants nothing until a verified PolicyAck on it is installed.
#[must_use = "a pre-warmed channel is only useful for its session's next re-ACK"]
pub(crate) struct PrewarmedChannel {
    channel: AckReadyChannel,
    crypto: Arc<PreparedCryptoInputs>,
}

impl ChannelOpener {
    /// The only endpoint this opener may dial: the session's verified peer.
    #[cfg(test)]
    pub(crate) fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Dial the session's verified peer over a socket bound to the session's
    /// relay interface; the caller bounds the connect. v40: a refused dial
    /// is the session pin's carrier fault (`connect_timed_out` for the
    /// caller's bound).
    pub(crate) async fn connect(&self) -> io::Result<TcpStream> {
        #[cfg(feature = "enrolled-quic")]
        if self.crypto.selected_channel()? == CarrierChannel::MasqueQuic {
            return Err(refused());
        }
        dial_pin(&self.crypto, self.peer, &self.interface).await
    }

    /// v40: the caller's bound ended this opener's connect.
    pub(crate) fn connect_timed_out(&self) {
        self.crypto
            .carrier_fault(crate::carrier_failover::dial_signal(true));
    }

    /// Outer TLS, H2 and inner mTLS on `tcp`; refusals log `event` with the
    /// refusing step. The held policy refuses any TCP peer but the signed
    /// relay before a byte is sent.
    pub(crate) async fn establish(
        self,
        tcp: TcpStream,
        event: &'static str,
    ) -> io::Result<PrewarmedChannel> {
        let channel = self.crypto.establish_ack_channel(tcp, event).await?;
        Ok(PrewarmedChannel {
            channel,
            crypto: self.crypto,
        })
    }

    /// S16l: a carrier stream and its inner mTLS on `link`'s connection
    /// `conn` (`PreparedCryptoInputs::establish_ack_stream`). A link of any
    /// other held crypto is refused before a byte is sent.
    pub(crate) async fn establish_on_link(
        self,
        link: &AckLink,
        (conn, live): (Arc<PooledConn>, Arc<ConnLive>),
        event: &'static str,
    ) -> io::Result<PrewarmedChannel> {
        if !Arc::ptr_eq(link.crypto(), &self.crypto) {
            crate::apple::log_code(event, "foreign_link");
            return Err(refused());
        }
        let channel = self.crypto.establish_ack_stream(conn, &live, event).await?;
        Ok(PrewarmedChannel {
            channel,
            crypto: self.crypto,
        })
    }
}

impl PrewarmedChannel {
    /// Poll the idle channel until its connection ends; see
    /// `AckReadyChannel::drive_idle`.
    #[cfg(test)]
    pub(crate) async fn drive_idle(&mut self) {
        self.channel.drive_idle().await
    }

    /// `drive_idle` as a poll: ready once the connection has ended.
    pub(crate) fn poll_idle(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        self.channel.poll_idle(cx)
    }

    #[cfg(test)]
    pub(crate) fn mark_ended_for_test(&mut self) {
        self.channel.mark_ended_for_test();
    }

    /// S16l: the ACK connection this channel is a stream of, and that
    /// stream's ID; None for a channel on its own connection.
    pub(crate) fn conn(&self) -> Option<(&Arc<PooledConn>, u32)> {
        self.channel.conn()
    }
}

impl ReackRequest {
    /// Dial the session's verified peer over a socket bound to the session's
    /// relay interface; the caller bounds the connect. v40: a refused dial
    /// is the session pin's carrier fault.
    pub(crate) async fn connect(&self) -> io::Result<TcpStream> {
        #[cfg(feature = "enrolled-quic")]
        if self.crypto.selected_channel()? == CarrierChannel::MasqueQuic {
            return Err(refused());
        }
        dial_pin(&self.crypto, self.peer, &self.interface).await
    }

    /// v40: the caller's bound ended this request's connect.
    pub(crate) fn connect_timed_out(&self) {
        self.crypto
            .carrier_fault(crate::carrier_failover::dial_signal(true));
    }

    /// Run outer H2, inner TLS and one targetless PolicyAck on `tcp` with the
    /// held crypto. The held policy refuses any TCP peer but the signed relay.
    #[cfg(test)]
    pub(crate) async fn observe(self, tcp: TcpStream) -> io::Result<ReackObservation> {
        match self.observe_or(tcp, (std::future::pending(), || ())).await {
            Ok(observed) => observed,
            Err(_) => Err(refused()),
        }
    }

    /// S16m: `observe`, abandoned when `until` resolves before the dial's
    /// inner mTLS completed (`PreparedCryptoInputs::observe_ack_or`): the
    /// dial is dropped with no PolicyAck written, and the request comes
    /// back unchanged (`Err`), under the same before-binding, for another
    /// channel. Once established (`established` runs), its PolicyAck is
    /// written and answered whatever `until` does.
    pub(crate) async fn observe_or(
        self,
        tcp: TcpStream,
        until: (impl std::future::Future<Output = ()>, impl FnOnce()),
    ) -> Result<io::Result<ReackObservation>, Self> {
        #[cfg(feature = "enrolled-quic")]
        match self.crypto.selected_channel() {
            Ok(CarrierChannel::MasqueQuic) | Err(_) => return Ok(Err(refused())),
            Ok(_) => {}
        }
        if self.crypto.selected_channel().ok() == Some(CarrierChannel::WebResponse) {
            let Some((pins, generation)) = self.web_epoch.as_ref() else {
                return Ok(Err(refused()));
            };
            let (pins, generation) = (pins.clone(), *generation);
            let crypto = self.crypto.clone();
            let interface = self.interface.clone();
            let deadline = tokio::time::Instant::now() + crypto.connect_timeout();
            let held = tokio::select! {
                held = crypto.web_response_carrier(tcp, &interface, &pins, generation) => held,
                () = until.0 => return Err(self),
            };
            let held = match held {
                Ok(held) => held,
                Err(error) => return Ok(Err(error)),
            };
            (until.1)();
            return Ok(self
                .crypto
                .observe_ack_on_held(held, self.before.binding(), deadline)
                .await
                .map(|channel| ReackObservation {
                    channel,
                    before: self.before,
                }));
        }
        let observed = self
            .crypto
            .observe_ack_or(tcp, self.before.binding(), until)
            .await;
        match observed {
            Some(Ok(channel)) => Ok(Ok(ReackObservation {
                channel,
                before: self.before,
            })),
            Some(Err(error)) => Ok(Err(error)),
            None => Err(self),
        }
    }

    /// A selected enrolled QUIC route opens its own scoped UDP carrier. The
    /// original request deadline covers outer QUIC, inner device TLS and the
    /// targetless PolicyAck; no TCP or H2 fallback is possible in this arm.
    #[cfg(feature = "enrolled-quic")]
    pub(crate) async fn observe_quic(self, limit: Duration) -> io::Result<ReackObservation> {
        if self.crypto.selected_channel()? != CarrierChannel::MasqueQuic {
            return Err(refused());
        }
        self.crypto.direct_peer(self.peer)?;
        let (pins, generation) = self.web_epoch.as_ref().ok_or_else(refused)?;
        let gate = self.quic_gate.as_ref().ok_or_else(refused)?;
        let deadline = tokio::time::Instant::now() + limit.min(self.crypto.connect_timeout());
        let channel = tokio::time::timeout_at(deadline, async {
            let held = self
                .crypto
                .quic_carrier(&self.interface, pins, *generation, gate)
                .await?;
            self.crypto
                .observe_ack_on_held(held, self.before.binding(), deadline)
                .await
        })
        .await
        .map_err(|_| io::ErrorKind::TimedOut)??;
        Ok(ReackObservation {
            channel,
            before: self.before,
        })
    }

    #[cfg(feature = "enrolled-quic")]
    pub(crate) fn selected_quic(&self) -> io::Result<bool> {
        Ok(self.crypto.selected_channel()? == CarrierChannel::MasqueQuic)
    }

    /// One targetless PolicyAck on a channel this session opened in
    /// advance: a single round trip, bounded by `limit` (and by
    /// `connect_timeout_ms`). A channel opened from any other held crypto is
    /// refused before a request is written. On any failure, the bound
    /// included, the request comes back unchanged, so the caller can carry it
    /// on another channel under the same before-binding.
    #[cfg(test)]
    pub(crate) async fn observe_on(
        self,
        prewarmed: PrewarmedChannel,
        limit: Duration,
        event: &'static str,
    ) -> Result<ReackObservation, Self> {
        self.observe_on_judged(prewarmed, limit, event)
            .await
            .map_err(|(request, _)| request)
    }

    /// S16l: a whole re-ACK on `link`'s connection `conn`: one carrier
    /// stream, its inner mTLS and one targetless PolicyAck, bounded by
    /// `limit` (and by `connect_timeout_ms`). A link of any other held
    /// crypto is refused before a byte is sent. On any failure the request
    /// comes back unchanged with the refusal, so the caller can carry it on a
    /// per-dial channel under the same before-binding.
    pub(crate) async fn observe_on_link(
        self,
        link: &AckLink,
        (conn, live): (Arc<PooledConn>, Arc<ConnLive>),
        limit: Duration,
        event: &'static str,
    ) -> Result<ReackObservation, (Self, io::Error)> {
        if !Arc::ptr_eq(link.crypto(), &self.crypto) {
            crate::apple::log_code(event, "foreign_link");
            return Err((self, refused()));
        }
        match self
            .crypto
            .observe_ack_on_link(conn, &live, self.before.binding(), limit, event)
            .await
        {
            Ok(channel) => Ok(ReackObservation {
                channel,
                before: self.before,
            }),
            Err(error) => Err((self, error)),
        }
    }

    /// `observe_on`, also telling whether a failure was authentication class
    /// (a TLS alert on the request's channel, S16g).
    pub(crate) async fn observe_on_judged(
        self,
        prewarmed: PrewarmedChannel,
        limit: Duration,
        event: &'static str,
    ) -> Result<ReackObservation, (Self, bool)> {
        let PrewarmedChannel { channel, crypto } = prewarmed;
        if !Arc::ptr_eq(&crypto, &self.crypto) {
            crate::apple::log_code(event, "foreign_channel");
            return Err((self, false));
        }
        drop(crypto);
        match self
            .crypto
            .exchange_ack(channel, self.before.binding(), limit, event)
            .await
        {
            Ok(channel) => Ok(ReackObservation {
                channel,
                before: self.before,
            }),
            Err(error) => Err((self, is_auth_refused(&error))),
        }
    }
}

impl ReackObservation {
    /// The new ACK deadline on the runtime clock that observed it.
    pub(crate) fn ack_valid_until(&self) -> tokio::time::Instant {
        self.channel.valid_until()
    }

    /// The PolicyAck round trip alone, on its established channel.
    pub(crate) fn exchange_elapsed(&self) -> Duration {
        self.channel.exchange_elapsed()
    }
}

/// Source-only custody: bridge revocation drops before the authenticated
/// channel and Store. No constructor here enables a packet lease or factory.
#[must_use = "retain the revocation guard with the observed online session"]
#[allow(dead_code)]
pub(crate) struct InertLeaseOwner {
    revoke: RevokeLeaseOnDrop,
    session: ObservedLocalSession,
}

/// Running source-only H2/Store observer. It owns the sole signed claim in its
/// task and grants neither a packet deadline nor a provider factory.
#[must_use = "keep the authenticated monitor task alive"]
#[allow(dead_code)]
pub(crate) struct InertActiveMonitor {
    task: Option<tokio::task::JoinHandle<io::Result<()>>>,
}

#[allow(dead_code)]
impl InertActiveMonitor {
    pub(crate) fn running(&self) -> bool {
        self.task.as_ref().is_some_and(|task| !task.is_finished())
    }

    pub(crate) async fn observe_terminal(mut self) -> io::Result<()> {
        let task = self.task.take().expect("monitor task retained");
        task.await.map_err(|_| refused())?
    }

    /// Abort and observe the exact monitor before a containing owner releases
    /// its protected Store. A timeout retains the JoinHandle for a later join;
    /// it must not be reported as a completed stop.
    pub(crate) async fn stop_and_join(&mut self, budget: Duration) -> io::Result<()> {
        if budget > Duration::from_secs(2) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let Some(task) = self.task.as_mut() else {
            return Ok(());
        };
        task.abort();
        let result = tokio::time::timeout(budget, task).await;
        let joined = match result {
            Ok(joined) => joined,
            Err(_) => return Err(io::ErrorKind::TimedOut.into()),
        };
        self.task.take();
        match joined {
            Ok(result) => result,
            Err(error) if error.is_cancelled() => Ok(()),
            Err(_) => Err(refused()),
        }
    }
}

impl Drop for InertActiveMonitor {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[allow(dead_code)]
impl InertLeaseOwner {
    pub(crate) fn new(session: ObservedLocalSession, bridge: LeasedPacketBridge) -> Self {
        Self {
            revoke: RevokeLeaseOnDrop::new(bridge),
            session,
        }
    }

    /// Own both values through the terminal loop; return and cancellation
    /// revoke the bridge before the session's Store claim can be released.
    pub(crate) async fn run(mut self) -> io::Result<()> {
        self.session.monitor_inert_until_terminal().await
    }
}

/// v40: one TCP dial of a session's channel to its pin `peer`; a refusal or
/// an unreachable pin (never a lost local interface) is the pin's carrier
/// fault.
async fn dial_pin(
    crypto: &PreparedCryptoInputs,
    peer: SocketAddr,
    interface: &RelayInterface,
) -> io::Result<TcpStream> {
    let dialed = connect_bound(peer, interface).await;
    if let Err(error) = &dialed {
        if !crate::relay_socket::interface_lost(error) {
            crypto.carrier_fault(crate::carrier_failover::dial_signal(
                error.kind() == io::ErrorKind::TimedOut,
            ));
        }
    }
    dialed
}

/// The saved manager intent names the signed pool's primary pin, and the
/// session dials `peer`, a pin of that pool (v40: the one it selected; for a
/// single-pin profile the primary itself, as before).
fn saved_peer_matches(
    saved: &SavedProviderIntent,
    crypto: &PreparedCryptoInputs,
    peer: SocketAddr,
) -> bool {
    saved.policy.relay() == crypto.primary_peer().ip() && crypto.carrier_pins().contains(&peer)
}

#[allow(dead_code)]
impl PreparedLocalSession {
    /// The admitted certificate's `(not_before, not_after)` (unix seconds):
    /// the validity window this admission checked. `not_after` is the
    /// Store's; `not_before` is the held receipt's, which S22 bound to the
    /// same certificate (`ensure_held_issuance`).
    pub(crate) fn admitted_window(&self) -> (u64, u64) {
        (
            self.identity.inputs.held_window().0,
            self.identity.initial.not_after_unix_secs,
        )
    }

    /// Retain the exact Store lock independently of the in-flight ACK future.
    /// An ACK error can consume this session, but cannot release the Store
    /// before the containing Tokio runtime has shut down.
    pub(crate) fn from_claim_with_store_guard(
        inputs: CapturedAppGroupInputs,
    ) -> io::Result<(Self, Arc<ProtectedOnlineExpectation<'static>>)> {
        let identity = CapturedLocalIdentity::from_claim(inputs)?;
        let guard = identity.online.clone();
        Ok((identity.prepare_crypto()?, guard))
    }
    pub(crate) fn pinned_peer(&self) -> io::Result<SocketAddr> {
        self.crypto.pinned_peer()
    }

    /// The held profile's enrollment authority, for the renewal monitor's
    /// guard check (v31; S20b armed it in the leak guard).
    pub(crate) fn authority_address(&self) -> Option<SocketAddr> {
        self.crypto.authority_address()
    }

    /// Test-only: the held crypto, for pooled outer sessions (S16h) dialed
    /// without a first ACK.
    #[cfg(test)]
    pub(crate) fn crypto_for_test(&self) -> Arc<PreparedCryptoInputs> {
        self.crypto.clone()
    }

    /// An opener for channels the first re-ACKs will use, taken before the
    /// first ACK so their setup overlaps its exchange. The Store, signed
    /// bundle and saved intent must derive this session's runtime binding
    /// now; that binding names the saved relay, so it refuses any saved
    /// relay but the signed one this opener dials, and the opener's channel
    /// setup refuses any TCP peer but that relay. It binds no issuance and
    /// grants nothing: a channel carries a request only for this session's
    /// own `ReackRequest`, bound once its live ACK is held.
    pub(crate) fn begin_first_prewarm(
        &mut self,
        saved: &SavedProviderIntent,
        interface: &RelayInterface,
    ) -> io::Result<ChannelOpener> {
        if self.crypto.selected_channel()? == CarrierChannel::WebResponse
            || cfg!(feature = "enrolled-quic")
                && self.crypto.selected_channel()? == CarrierChannel::MasqueQuic
        {
            return Err(refused());
        }
        let peer = self.crypto.pinned_peer()?;
        // Proof that the binding derives now; the ACK derives and keeps its own.
        let _current = self.derive_runtime(saved)?;
        Ok(ChannelOpener {
            crypto: self.crypto.clone(),
            peer,
            interface: interface.clone(),
        })
    }
    /// S16l: the session's persistent ACK connection to its pinned relay,
    /// over `interface`, dialed (by its first ACK and pre-warms) under
    /// `limiter`'s ACK-path permits with its driver in `gate`, current while
    /// the epoch's `pins` keep the generation the session was bound under.
    /// It dials nothing until asked.
    pub(crate) fn ack_link(
        &self,
        interface: &RelayInterface,
        (limiter, gate): (Arc<EstablishLimiter>, Arc<WorkGate>),
        pins: (EpochPins, u64),
        trace: Option<Trace>,
    ) -> io::Result<Arc<AckLink>> {
        if self.crypto.selected_channel()? == CarrierChannel::WebResponse
            || cfg!(feature = "enrolled-quic")
                && self.crypto.selected_channel()? == CarrierChannel::MasqueQuic
        {
            return Err(refused());
        }
        let peer = self.crypto.pinned_peer()?;
        AckLink::new(
            peer,
            interface.clone(),
            self.crypto.clone(),
            (limiter, gate),
            pins,
            trace,
        )
    }

    /// Consume the provider's one held App Group claim through Store and
    /// crypto preparation. No second signed claim is made on this path.
    /// This remains inert until a terminal composite owns the result.
    pub(crate) fn from_claim(inputs: CapturedAppGroupInputs) -> io::Result<Self> {
        CapturedLocalIdentity::from_claim(inputs)?.prepare_crypto()
    }

    pub(crate) fn revalidate(&mut self) -> io::Result<OnlineExpectation> {
        self.identity.revalidate()
    }

    /// Derive the runtime binding for `saved` from this held claim's signed
    /// bundle, profile digest and Store issuance. Nothing is dialed or read
    /// from a runtime record.
    pub(crate) fn derive_runtime(
        &mut self,
        saved: &SavedProviderIntent,
    ) -> io::Result<(DerivedRuntimeBinding, OnlineExpectation)> {
        self.identity
            .derive_runtime(&saved.generation, &saved.policy, &self.crypto)
    }

    /// Test access to the same re-derivation the observed session runs.
    #[cfg(test)]
    pub(crate) fn bind_runtime_for_test(
        &mut self,
        bound: &DerivedRuntimeBinding,
        saved: &SavedProviderIntent,
    ) -> io::Result<OnlineExpectation> {
        self.identity
            .bind_runtime(bound, &saved.generation, &saved.policy, &self.crypto)
    }

    /// The only ACK path requires an intent parsed from the saved native
    /// manager whose relay, DNS and MTU the held signed bundle names, and the
    /// same derived runtime binding and held Store before and after the real
    /// exchange. No runtime record is read. No packet authority is produced.
    /// Every later relay socket of the session is bound to `interface`.
    pub(crate) async fn observe_ack(
        mut self,
        saved: SavedProviderIntent,
        tcp: TcpStream,
        interface: RelayInterface,
    ) -> io::Result<ObservedLocalSession> {
        let peer = tcp.peer_addr().map_err(|_| refused())?;
        if !saved_peer_matches(&saved, &self.crypto, peer) {
            return Err(refused());
        }
        let (binding, before) = self.derive_runtime(&saved)?;
        let channel = self.crypto.observe_ack(tcp, before.binding()).await?;
        self.observed(saved, (binding, before), channel, peer, interface)
    }

    /// S16l: `observe_ack` over a stream of the session's persistent ACK
    /// connection `link` (`conn`, which `link` dialed to the pinned relay)
    /// instead of a socket of its own: the same saved relay, binding, Store
    /// and ACK checks before and after the exchange. A link of any other
    /// held crypto is refused before a byte is sent.
    pub(crate) async fn observe_ack_on_link(
        self,
        saved: SavedProviderIntent,
        link: &AckLink,
        (conn, live): (Arc<PooledConn>, Arc<ConnLive>),
        interface: RelayInterface,
    ) -> io::Result<ObservedLocalSession> {
        self.observe_ack_on_link_carrier(saved, link, (conn, live), None, interface, Duration::MAX)
            .await
    }

    /// v40: `observe_ack_on_link` on the first ACK's carrier stream when the
    /// session build already opened it (`carrier`, the 200 of its pin before
    /// any identity), within `limit` of that stream's request.
    pub(crate) async fn observe_ack_on_link_carrier(
        mut self,
        saved: SavedProviderIntent,
        link: &AckLink,
        (conn, live): (Arc<PooledConn>, Arc<ConnLive>),
        carrier: Option<crate::flow_pool::PooledCarrier>,
        interface: RelayInterface,
        limit: Duration,
    ) -> io::Result<ObservedLocalSession> {
        let peer = link.peer();
        if !saved_peer_matches(&saved, &self.crypto, peer)
            || !Arc::ptr_eq(link.crypto(), &self.crypto)
        {
            return Err(refused());
        }
        let (binding, before) = self.derive_runtime(&saved)?;
        let channel = self
            .crypto
            .observe_ack_on_link_carrier(conn, &live, carrier, before.binding(), limit, "ack_stage")
            .await?;
        self.observed(saved, (binding, before), channel, peer, interface)
    }

    /// v40: `observe_ack` on the outer carrier `held` the session build
    /// opened to its pin on its own socket (`held_carrier`): the same saved
    /// relay, binding, Store and ACK checks before and after the exchange,
    /// the inner mTLS and PolicyAck by `deadline`.
    pub(crate) async fn observe_ack_on_held(
        mut self,
        saved: SavedProviderIntent,
        held: crate::prepared_crypto::HeldOuter,
        peer: SocketAddr,
        interface: RelayInterface,
        deadline: tokio::time::Instant,
    ) -> io::Result<ObservedLocalSession> {
        if !saved_peer_matches(&saved, &self.crypto, peer) || self.crypto.direct_peer(peer).is_err()
        {
            return Err(refused());
        }
        let (binding, before) = self.derive_runtime(&saved)?;
        let channel = self
            .crypto
            .observe_ack_on_held(held, before.binding(), deadline)
            .await?;
        self.observed(saved, (binding, before), channel, peer, interface)
    }

    /// The signed connect budget of one establishment.
    pub(crate) fn connect_timeout(&self) -> Duration {
        self.crypto.connect_timeout()
    }

    #[cfg(feature = "enrolled-quic")]
    pub(crate) fn selected_quic(&self) -> io::Result<bool> {
        Ok(self.crypto.selected_channel()? == CarrierChannel::MasqueQuic)
    }

    #[cfg(feature = "enrolled-quic")]
    pub(crate) async fn quic_carrier(
        &self,
        interface: &RelayInterface,
        pins: &EpochPins,
        generation: u64,
        gate: &WorkGate,
    ) -> io::Result<crate::prepared_crypto::HeldOuter> {
        self.crypto
            .quic_carrier(interface, pins, generation, gate)
            .await
    }

    /// v40: the signed primary pin (the saved intent's relay).
    pub(crate) fn primary_peer(&self) -> SocketAddr {
        self.crypto.primary_peer()
    }

    /// v40: every exact pin of the signed pool, in profile order.
    pub(crate) fn carrier_pins(&self) -> Vec<SocketAddr> {
        self.crypto.carrier_pins()
    }

    /// v40: the attempt order of this session build over the pool.
    pub(crate) fn carrier_plan(
        &self,
        network: aegis_core::brain::carrier_failover::NetworkKey,
    ) -> io::Result<crate::carrier_failover::SessionCarriers> {
        self.crypto.carrier_plan(network)
    }

    /// v40: dial pin `index` of the pool, with its failover `ticket`: only
    /// while this session's held crypto is not shared with any opener, link
    /// or pool (refused otherwise, so one session never dials two pins).
    pub(crate) fn select_carrier(
        &mut self,
        index: usize,
        ticket: Option<Arc<crate::carrier_failover::CarrierTicket>>,
    ) -> io::Result<()> {
        Arc::get_mut(&mut self.crypto)
            .ok_or_else(refused)?
            .select_carrier(index, ticket)
    }

    /// v40: whether this build's attempt on its pin failed before
    /// authentication with a carrier signal (the build moves on).
    pub(crate) fn carrier_failed(&self) -> bool {
        self.crypto
            .carrier_ticket()
            .is_some_and(|ticket| ticket.failed())
    }

    /// v40: a typed pre-authentication signal of this build's own dial.
    pub(crate) fn carrier_fault(&self, signal: aegis_core::brain::carrier_failover::CarrierSignal) {
        self.crypto.carrier_fault(signal);
    }

    /// v40: the first ACK's carrier stream on the ACK connection `conn`
    /// (`PreparedCryptoInputs::open_link_carrier`).
    pub(crate) async fn open_link_carrier(
        &self,
        conn: &Arc<PooledConn>,
    ) -> io::Result<crate::flow_pool::PooledCarrier> {
        self.crypto.open_link_carrier(conn, "ack_stage").await
    }

    /// v40: the first ACK's outer carrier on its own socket `tcp`
    /// (`PreparedCryptoInputs::held_carrier`); any TCP peer but this
    /// session's pin is refused before a byte is sent.
    pub(crate) async fn held_carrier(
        &self,
        tcp: TcpStream,
        interface: &RelayInterface,
        pins: &EpochPins,
        generation: u64,
    ) -> io::Result<crate::prepared_crypto::HeldOuter> {
        self.crypto
            .direct_peer(tcp.peer_addr().map_err(|_| refused())?)
            .map_err(|_| refused())?;
        if self.crypto.selected_channel()? == CarrierChannel::WebResponse {
            return self
                .crypto
                .web_response_carrier(tcp, interface, pins, generation)
                .await;
        }
        self.crypto.held_carrier(tcp, "ack_stage").await
    }

    /// The observed session once its ACK `channel` arrived: the binding and
    /// Store again, the ACK retained and current.
    fn observed(
        mut self,
        saved: SavedProviderIntent,
        (binding, before): (DerivedRuntimeBinding, OnlineExpectation),
        channel: AuthenticatedRelayObservation,
        peer: SocketAddr,
        interface: RelayInterface,
    ) -> io::Result<ObservedLocalSession> {
        let after =
            self.identity
                .bind_runtime(&binding, &saved.generation, &saved.policy, &self.crypto)?;
        before.ensure_same_issuance(&after).map_err(|_| refused())?;
        let ack = ObservedPolicyAck::retain_observed(before.binding(), channel.valid_until())
            .map_err(|_| refused())?;
        ack.ensure_current(after.binding()).map_err(|_| refused())?;
        Ok(ObservedLocalSession {
            channel,
            ack,
            prepared: self.crypto,
            identity: self.identity,
            saved,
            binding,
            peer,
            interface,
        })
    }
}

#[allow(dead_code)]
impl ObservedLocalSession {
    /// Borrow and poll the actual H2 driver under the containing Store owner.
    /// Unlike `start_inert_monitor`, this creates no task whose Drop could
    /// detach the only terminal join handle.
    pub(crate) async fn monitor_borrowed_with_ready(
        &mut self,
        ready: tokio::sync::oneshot::Sender<()>,
    ) -> io::Result<()> {
        let identity = &mut self.identity;
        let saved = &self.saved;
        let ack = &self.ack;
        let binding = &self.binding;
        let prepared = &*self.prepared;
        self.channel
            .monitor_inert_until_terminal_ready(
                || {
                    let current = identity.bind_runtime(
                        binding,
                        &saved.generation,
                        &saved.policy,
                        prepared,
                    )?;
                    ack.ensure_current(current.binding()).map_err(|_| refused())
                },
                ready,
            )
            .await
    }

    /// Drive the ACK connection until it ends. Ending is not a failure: the
    /// server closes the inner stream after write_ack. Poll at most once to
    /// completion; the retained ACK deadline still bounds readiness.
    pub(crate) async fn drive_ack_transport(&mut self) {
        self.channel.drive_until_closed().await
    }

    /// The retained ACK deadline on the runtime clock that observed it.
    pub(crate) fn ack_valid_until(&self) -> tokio::time::Instant {
        self.ack.valid_until()
    }

    /// The live channel's PolicyAck round trip alone.
    pub(crate) fn ack_exchange_elapsed(&self) -> Duration {
        self.channel.exchange_elapsed()
    }

    /// An opener for the next re-ACK's channel. The session must still be
    /// current (Store, saved intent, live ACK) and its peer verified.
    pub(crate) fn begin_prewarm(&mut self) -> io::Result<ChannelOpener> {
        if self.prepared.selected_channel()? == CarrierChannel::WebResponse
            || cfg!(feature = "enrolled-quic")
                && self.prepared.selected_channel()? == CarrierChannel::MasqueQuic
        {
            return Err(refused());
        }
        let peer = self.verified_held_relay_peer()?;
        Ok(ChannelOpener {
            crypto: self.prepared.clone(),
            peer,
            interface: self.interface.clone(),
        })
    }

    /// Start a re-ACK over a fresh connection. The session must still be
    /// current (Store, saved intent, live ACK) and its peer verified; nothing
    /// is taken from it, so it stays whole whether the re-ACK succeeds or not.
    pub(crate) fn begin_reack(&mut self) -> io::Result<ReackRequest> {
        self.begin_reack_with_pins(None)
    }

    pub(crate) fn begin_reack_with_pins(
        &mut self,
        web_epoch: Option<(EpochPins, u64)>,
    ) -> io::Result<ReackRequest> {
        self.begin_reack_with_transport(web_epoch, None)
    }

    pub(crate) fn begin_reack_with_transport(
        &mut self,
        web_epoch: Option<(EpochPins, u64)>,
        #[cfg(feature = "enrolled-quic")] quic_gate: Option<Arc<WorkGate>>,
        #[cfg(not(feature = "enrolled-quic"))] _quic_gate: Option<Arc<WorkGate>>,
    ) -> io::Result<ReackRequest> {
        let channel = self.prepared.selected_channel()?;
        if (channel == CarrierChannel::WebResponse
            || cfg!(feature = "enrolled-quic") && channel == CarrierChannel::MasqueQuic)
            && web_epoch.is_none()
        {
            return Err(refused());
        }
        #[cfg(feature = "enrolled-quic")]
        if channel == CarrierChannel::MasqueQuic && quic_gate.is_none() {
            return Err(refused());
        }
        let peer = self.verified_held_relay_peer()?;
        let before = self.identity.bind_runtime(
            &self.binding,
            &self.saved.generation,
            &self.saved.policy,
            &self.prepared,
        )?;
        Ok(ReackRequest {
            crypto: self.prepared.clone(),
            before,
            peer,
            interface: self.interface.clone(),
            web_epoch,
            #[cfg(feature = "enrolled-quic")]
            quic_gate,
        })
    }

    /// Swap in a re-observed channel and ACK. The Store, saved intent and
    /// derived runtime binding must still bind the same issuance as before the request
    /// and as this session's own ACK, which must not have expired. Only then
    /// is the old channel dropped, on the caller's (its own) runtime. On any
    /// refusal the session is unchanged and the new channel is dropped.
    pub(crate) fn install_reack(&mut self, observed: ReackObservation) -> io::Result<()> {
        let ReackObservation { channel, before } = observed;
        let after = self.identity.bind_runtime(
            &self.binding,
            &self.saved.generation,
            &self.saved.policy,
            &self.prepared,
        )?;
        before.ensure_same_issuance(&after).map_err(|_| refused())?;
        self.ack
            .ensure_current(after.binding())
            .map_err(|_| refused())?;
        let ack = ObservedPolicyAck::retain_observed(before.binding(), channel.valid_until())
            .map_err(|_| refused())?;
        ack.ensure_current(after.binding()).map_err(|_| refused())?;
        let old = std::mem::replace(&mut self.channel, channel);
        self.ack = ack;
        drop(old);
        Ok(())
    }

    /// Close reactor-bound H2/TLS values while their runtime still exists,
    /// retaining the exact protected Store and descriptors through runtime
    /// shutdown. No packet worker or native callback is attached here.
    pub(crate) fn close_transport_keep_store(self) -> CapturedLocalIdentity {
        let Self {
            channel,
            ack,
            prepared,
            identity,
            saved,
            binding,
            peer: _,
            interface: _,
        } = self;
        drop(channel);
        drop(ack);
        drop(prepared);
        drop(saved);
        drop(binding);
        identity
    }
    /// Prepare the fixed-peer relay services for this session's verified
    /// peer, over its flow `pool` (S16h, `flow_pool`). They open flows only
    /// while the pool's gate is open and `bridge`'s ACK-derived lease is live
    /// on the bridge clock; the caller owns and stops that gate. A pool of
    /// another peer, interface or held crypto is refused.
    pub(crate) fn held_relay_services(
        &mut self,
        events: Arc<dyn EventSink>,
        bridge: LeasedPacketBridge,
        pool: Arc<FlowPool>,
    ) -> io::Result<Arc<HeldRelayServices>> {
        let peer = self.verified_held_relay_peer()?;
        if pool.peer() != peer
            || *pool.interface() != self.interface
            || !Arc::ptr_eq(pool.crypto(), &self.prepared)
        {
            return Err(refused());
        }
        Ok(Arc::new(HeldRelayServices::new(events, bridge, pool)?))
    }

    /// D5 uses the same verified ACK, Store and packet lease with a separate
    /// one-web-carrier-per-flow owner; no H2 pool is created for this route.
    pub(crate) fn held_web_relay_services(
        &mut self,
        events: Arc<dyn EventSink>,
        bridge: LeasedPacketBridge,
        (limiter, gate): (Arc<EstablishLimiter>, Arc<WorkGate>),
        pins: (EpochPins, u64),
    ) -> io::Result<Arc<HeldRelayServices>> {
        let peer = self.verified_held_relay_peer()?;
        Ok(Arc::new(HeldRelayServices::new_web(
            events,
            bridge,
            self.prepared.clone(),
            peer,
            self.interface.clone(),
            pins,
            (limiter, gate),
        )?))
    }

    #[cfg(feature = "sfu-media-vp8")]
    pub(crate) fn held_sfu_relay_services(
        &mut self,
        events: Arc<dyn EventSink>,
        bridge: LeasedPacketBridge,
        (limiter, gate): (Arc<EstablishLimiter>, Arc<WorkGate>),
        pins: (EpochPins, u64),
    ) -> io::Result<Arc<HeldRelayServices>> {
        let peer = self.verified_held_relay_peer()?;
        Ok(Arc::new(HeldRelayServices::new_sfu(
            events,
            bridge,
            self.prepared.clone(),
            peer,
            self.interface.clone(),
            pins,
            (limiter, gate),
        )?))
    }

    #[cfg(feature = "sfu-media-vp8")]
    pub(crate) fn has_sfu_media(&self) -> bool {
        self.prepared.has_sfu_media()
    }

    pub(crate) fn selected_channel(&self) -> io::Result<CarrierChannel> {
        self.prepared.selected_channel()
    }

    /// The flow pool (S16h) of this session: pooled outer connections to
    /// its verified peer over its relay interface, dialed under `limiter`
    /// with their drivers in `gate`, current while the epoch's `pins` keep
    /// the re-pin generation the session was bound under. It dials nothing
    /// until a flow reserves a stream.
    pub(crate) fn flow_pool(
        &self,
        (limiter, gate): (Arc<EstablishLimiter>, Arc<WorkGate>),
        pins: (EpochPins, u64),
    ) -> io::Result<Arc<FlowPool>> {
        FlowPool::new(
            self.peer,
            self.interface.clone(),
            self.prepared.clone(),
            (limiter, gate),
            pins,
        )
    }

    /// The only inert packet configuration accessor: signed bytes, saved
    /// native intent, original TCP peer and current Store/ACK must all agree.
    /// It does not supply a service adapter, lease or packet grant.
    pub(crate) fn verified_held_packet_config(&mut self) -> io::Result<PacketEngineConfig> {
        self.verified_held_relay_peer()?;
        self.prepared
            .packet_config(self.saved.policy.mtu(), self.saved.policy.dns())
    }

    /// Verify that the observed TCP peer still names the exact held signed
    /// relay profile and saved native manager. This returns only an endpoint,
    /// never path-based client settings or an arbitrary worker configuration.
    pub(crate) fn verified_held_relay_peer(&mut self) -> io::Result<SocketAddr> {
        self.revalidate_bound_ack()?;
        self.prepared.direct_peer(self.peer)?;
        if !saved_peer_matches(&self.saved, &self.prepared, self.peer) {
            return Err(refused());
        }
        Ok(self.peer)
    }
    /// Consume the exact held claim into an actively polled observer. A ready
    /// result requires Store/ACK revalidation and an initial pending H2 poll.
    /// No packet bridge is accepted or armed on this path.
    pub(crate) async fn start_inert_monitor(mut self) -> io::Result<InertActiveMonitor> {
        let (ready, received) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let identity = &mut self.identity;
            let saved = &self.saved;
            let ack = &self.ack;
            let binding = &self.binding;
            let prepared = &*self.prepared;
            self.channel
                .monitor_inert_until_terminal_ready(
                    || {
                        let current = identity.bind_runtime(
                            binding,
                            &saved.generation,
                            &saved.policy,
                            prepared,
                        )?;
                        ack.ensure_current(current.binding()).map_err(|_| refused())
                    },
                    ready,
                )
                .await
        });
        let ready = tokio::time::timeout(Duration::from_secs(2), received).await;
        if !matches!(ready, Ok(Ok(()))) || task.is_finished() {
            task.abort();
            return Err(refused());
        }
        Ok(InertActiveMonitor { task: Some(task) })
    }
    /// Recheck the saved intent, held Store and observed ACK. This is not a
    /// readiness token: a future packet owner must also poll the live H2
    /// driver, own capture and stop all traffic on terminal failure.
    pub(crate) fn revalidate_bound_ack(&mut self) -> io::Result<()> {
        let current = self.identity.bind_runtime(
            &self.binding,
            &self.saved.generation,
            &self.saved.policy,
            &self.prepared,
        )?;
        self.ack
            .ensure_current(current.binding())
            .map_err(|_| refused())
    }

    /// Keep H2 actively polled until transport exit, ACK expiry or changed
    /// manager intent, derived binding or Store. The containing owner must
    /// revoke its bridge.
    async fn monitor_inert_until_terminal(&mut self) -> io::Result<()> {
        let identity = &mut self.identity;
        let saved = &self.saved;
        let ack = &self.ack;
        let binding = &self.binding;
        let prepared = &*self.prepared;
        self.channel
            .monitor_inert_until_terminal(|| {
                let current =
                    identity.bind_runtime(binding, &saved.generation, &saved.policy, prepared)?;
                ack.ensure_current(current.binding()).map_err(|_| refused())
            })
            .await
    }

    /// Source-only path without any packet bridge or capture grant.
    pub(crate) async fn run_inert_until_terminal(mut self) -> io::Result<()> {
        self.monitor_inert_until_terminal().await
    }
}

impl CapturedLocalIdentity {
    /// Source-only preparation while the exact Store owner stays retained.
    /// A future terminal session must also own this value and a live ACK.
    pub(crate) fn prepare_crypto(mut self) -> io::Result<PreparedLocalSession> {
        let before = self.revalidate()?;
        let policy = BoundRelayPolicy::capture(&mut self.inputs)?;
        let payload = self.inputs.captured_crypto_payload()?;
        let prepared = PreparedCryptoInputs::from_snapshot(policy, payload)?;
        let after = self.revalidate()?;
        before.ensure_same_issuance(&after).map_err(|_| refused())?;
        Ok(PreparedLocalSession {
            identity: self,
            crypto: Arc::new(prepared),
        })
    }

    /// Consume the provider's already admitted descriptor claim. This opens
    /// the protected Store under that same claim; it never captures a second
    /// App Group generation. On any failure the claim is dropped with `inputs`.
    pub(crate) fn from_claim(mut inputs: CapturedAppGroupInputs) -> io::Result<Self> {
        let captured_digest = inputs.captured_public_profile_digest()?;
        let (online, initial, profile_sha256) =
            inputs.with_portable_paths(|bundle, identity| {
                let profile_sha256 = public_profile_digest(bundle)?;
                if profile_sha256 != captured_digest {
                    return Err(refused());
                }
                let online = ProtectedOnlineExpectation::open_existing(identity, &profile_sha256)
                    .map_err(|_| refused())?;
                let initial = online
                    .expectation_at(registry::unix_now().map_err(|_| refused())?)
                    .map_err(|_| refused())?;
                Ok((online, initial, profile_sha256))
            })?;
        // S22: the Store's issuance must be the held receipt's, and present.
        inputs.ensure_held_issuance(&initial)?;
        Ok(Self {
            inputs,
            online: Arc::new(online),
            initial,
            profile_sha256,
        })
    }

    /// Recheck path generation, four public bytes and the held private Store.
    /// A renewal that changes issuance requires a fresh owner and relay ACK.
    pub fn revalidate(&mut self) -> io::Result<OnlineExpectation> {
        if self.inputs.captured_public_profile_digest()? != self.profile_sha256 {
            return Err(refused());
        }
        let current = self.inputs.with_portable_paths(|bundle, _identity| {
            if public_profile_digest(bundle)? != self.profile_sha256 {
                return Err(refused());
            }
            let current = self
                .online
                .expectation_at(registry::unix_now().map_err(|_| refused())?)
                .map_err(|_| refused())?;
            self.initial
                .ensure_same_issuance(&current)
                .map_err(|_| refused())?;
            Ok(current)
        })?;
        self.inputs.ensure_held_issuance(&current)?;
        Ok(current)
    }

    /// Derive the provider's runtime binding from the saved manager intent,
    /// the held signed terms of `crypto` (prepared from this same claim), the
    /// held profile digest and the held Store, bracketed by revalidation. No
    /// runtime record is opened: a provider cannot read the host's container.
    /// This local binding remains only a prerequisite for a live relay ACK.
    pub(crate) fn derive_runtime(
        &mut self,
        generation: &str,
        policy: &FullWide,
        crypto: &PreparedCryptoInputs,
    ) -> io::Result<(DerivedRuntimeBinding, OnlineExpectation)> {
        let before = self.revalidate()?;
        let signed = crypto.signed_runtime_terms()?;
        let binding =
            runtime_binding::derive(generation, policy, &signed, &self.profile_sha256, &before)?;
        let after = self.revalidate()?;
        before.ensure_same_issuance(&after).map_err(|_| refused())?;
        Ok((binding, after))
    }

    /// Re-derive the binding and require the exact one retained in `bound`:
    /// a changed generation, relay, DNS, MTU, profile or issuance is refused.
    pub(crate) fn bind_runtime(
        &mut self,
        bound: &DerivedRuntimeBinding,
        generation: &str,
        policy: &FullWide,
        crypto: &PreparedCryptoInputs,
    ) -> io::Result<OnlineExpectation> {
        let (current, after) = self.derive_runtime(generation, policy, crypto)?;
        bound.ensure_same(&current)?;
        Ok(after)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[tokio::test]
    async fn inert_monitor_abort_joins_before_reporting_stop() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let child_dropped = dropped.clone();
        let (started, ready) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _guard = Dropped(child_dropped);
            let _ = started.send(());
            std::future::pending::<()>().await;
            Ok(())
        });
        ready.await.unwrap();
        let mut monitor = InertActiveMonitor { task: Some(task) };
        monitor.stop_and_join(Duration::from_secs(1)).await.unwrap();
        assert!(dropped.load(Ordering::Acquire));
        assert!(monitor.task.is_none());
        monitor.stop_and_join(Duration::ZERO).await.unwrap();
    }

    #[tokio::test]
    async fn inert_monitor_invalid_budget_retains_exact_join_owner() {
        let task = tokio::spawn(async { std::future::pending::<io::Result<()>>().await });
        let mut monitor = InertActiveMonitor { task: Some(task) };
        assert_eq!(
            monitor
                .stop_and_join(Duration::from_secs(3))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(monitor.running());
        monitor.stop_and_join(Duration::from_secs(1)).await.unwrap();
        assert!(monitor.task.is_none());
    }

    #[tokio::test]
    async fn inert_monitor_timeout_keeps_unfinished_join_handle() {
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let task = tokio::task::spawn_blocking(move || {
            let _ = started.send(());
            wait.recv().unwrap();
            Ok(())
        });
        ready.await.unwrap();
        let mut monitor = InertActiveMonitor { task: Some(task) };
        assert_eq!(
            monitor
                .stop_and_join(Duration::ZERO)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert!(monitor.task.is_some());
        release.send(()).unwrap();
        monitor.stop_and_join(Duration::from_secs(1)).await.unwrap();
        assert!(monitor.task.is_none());
    }

    #[test]
    fn four_public_files_digest_refuses_change_and_symlink() {
        let dir = std::env::temp_dir().join(format!(
            "aegis-ne-local-profile-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        for (name, bytes) in
            MEMBERS
                .into_iter()
                .zip([b"profile".as_slice(), b"outer", b"inner", b"device"])
        {
            let path = dir.join(name);
            std::fs::write(&path, bytes).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let first = public_profile_digest(&dir).unwrap();
        let path = dir.join(MEMBERS[1]);
        std::fs::write(&path, b"changed").unwrap();
        assert_ne!(public_profile_digest(&dir).unwrap(), first);
        std::fs::remove_file(&path).unwrap();
        symlink(dir.join(MEMBERS[2]), &path).unwrap();
        assert_eq!(
            public_profile_digest(&dir).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn saved_manager_relay_must_match_authenticated_tcp_peer() {
        // v40: the saved intent names the signed pool's primary; the peer
        // must be one exact pin of that pool.
        let primary: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let edge: SocketAddr = "127.0.0.1:8443".parse().unwrap();
        let tree = crate::test_fixture::ReadyTree::pooled(primary, &[edge]);
        let session = prepared(&tree);
        let saved = saved_for(tree.generation(), tree.policy().clone());
        assert!(saved_peer_matches(&saved, &session.crypto, primary));
        assert!(saved_peer_matches(&saved, &session.crypto, edge));
        for other in ["127.0.0.1:444", "127.0.0.2:443", "127.0.0.2:8443"] {
            assert!(!saved_peer_matches(
                &saved,
                &session.crypto,
                other.parse().unwrap()
            ));
        }
        // A saved relay other than the primary matches no pin.
        let elsewhere = saved_for(
            tree.generation(),
            FullWide::new(
                "192.0.2.5".parse::<IpAddr>().unwrap(),
                vec!["198.19.255.2".parse().unwrap()],
                1280,
            )
            .unwrap(),
        );
        assert!(!saved_peer_matches(&elsewhere, &session.crypto, primary));
        drop(session);
    }

    fn prepared(tree: &crate::test_fixture::ReadyTree) -> PreparedLocalSession {
        let inputs = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
        PreparedLocalSession::from_claim(inputs).unwrap()
    }

    fn saved_for(generation: &str, policy: FullWide) -> SavedProviderIntent {
        SavedProviderIntent {
            generation: generation.into(),
            policy,
        }
    }

    #[test]
    fn local_identity_derives_binding_without_runtime_record_and_refuses_unsigned_terms() {
        use crate::test_fixture::ReadyTree;
        let tree = ReadyTree::with_online_completed("127.0.0.1:443".parse().unwrap());
        assert!(!tree.root().join("Aegis/runtime.json").exists());
        let mut session = prepared(&tree);
        let saved = saved_for(tree.generation(), tree.policy().clone());
        let (bound, online) = session.derive_runtime(&saved).unwrap();
        assert_eq!(online.issued_generation, Some(7));
        session.bind_runtime_for_test(&bound, &saved).unwrap();
        let dns = tree.policy().dns().to_vec();
        let loopback = |dns: Vec<IpAddr>, mtu| {
            FullWide::for_test_loopback("127.0.0.1".parse().unwrap(), dns, mtu).unwrap()
        };
        // A saved relay, DNS list or MTU the held signed bundle does not name
        // is refused at derivation, before any ACK could be requested.
        for (name, policy) in [
            (
                "relay",
                FullWide::new("192.0.2.9".parse().unwrap(), dns.clone(), 1280).unwrap(),
            ),
            ("dns", loopback(vec![dns[0]], 1280)),
            ("dns order", loopback(vec![dns[1], dns[0]], 1280)),
            ("mtu", loopback(dns.clone(), 1400)),
        ] {
            let changed = saved_for(tree.generation(), policy);
            assert!(session.derive_runtime(&changed).is_err(), "{name}");
            assert!(
                session.bind_runtime_for_test(&bound, &changed).is_err(),
                "{name}"
            );
        }
        // A changed generation derives, but is never the retained binding.
        let other = saved_for("fixture-generation-2", tree.policy().clone());
        let (other_bound, _) = session.derive_runtime(&other).unwrap();
        assert!(bound.ensure_same(&other_bound).is_err());
        assert!(session.bind_runtime_for_test(&bound, &other).is_err());
        // The unchanged binding still holds after every refusal.
        session.bind_runtime_for_test(&bound, &saved).unwrap();
    }

    #[test]
    fn local_identity_binding_refuses_changed_issuance_profile_and_foreign_signed_terms() {
        use crate::test_fixture::ReadyTree;
        let tree = ReadyTree::with_online_completed("127.0.0.1:443".parse().unwrap());
        let saved = saved_for(tree.generation(), tree.policy().clone());
        // Signed terms of another tree's bundle never bind this identity: the
        // two held profile digests differ.
        let foreign = ReadyTree::new("127.0.0.1:443".parse().unwrap());
        let mut session = prepared(&tree);
        let mut other = prepared(&foreign);
        assert!(session
            .identity
            .derive_runtime(&saved.generation, &saved.policy, &other.crypto)
            .is_err());
        let (bound, _) = session.derive_runtime(&saved).unwrap();
        let (foreign_bound, _) = other.derive_runtime(&saved).unwrap();
        assert!(bound.ensure_same(&foreign_bound).is_err());
        drop(foreign_bound);
        drop(other);
        // A renewed issuance in the held Store is refused.
        tree.rewrite_issued_generation(8);
        assert!(session.bind_runtime_for_test(&bound, &saved).is_err());
        drop(session);
        let mut session = prepared(&tree);
        let (renewed, online) = session.derive_runtime(&saved).unwrap();
        assert_eq!(online.issued_generation, Some(8));
        assert!(bound.ensure_same(&renewed).is_err());
        // An edited public profile member is refused by the held tree.
        let member = tree.root().join("Aegis/bundle").join(MEMBERS[1]);
        let bytes = std::fs::read(&member).unwrap();
        std::fs::write(&member, [bytes.as_slice(), b"\n"].concat()).unwrap();
        assert!(session.bind_runtime_for_test(&renewed, &saved).is_err());
        assert!(session.derive_runtime(&saved).is_err());
    }

    #[test]
    fn local_identity_ignores_stale_runtime_record_that_names_other_terms() {
        use crate::{configuration::PROVIDER_ID, manager::ProfileIntent, test_fixture::ReadyTree};
        let tree = ReadyTree::with_online_completed("127.0.0.1:443".parse().unwrap());
        // A stale host-shaped record naming another relay, generation and
        // issuance sits in the provider container before capture.
        let hostile = ProfileIntent {
            provider_id: PROVIDER_ID.into(),
            owner_generation: "hostile-generation".into(),
            policy: FullWide::new(
                "192.0.2.9".parse().unwrap(),
                tree.policy().dns().to_vec(),
                1400,
            )
            .unwrap(),
        };
        let mut stale_online = tree.online().clone();
        stale_online.issued_generation = Some(99);
        let bytes =
            runtime_binding::render_for_host(&hostile, tree.profile_sha256(), &stale_online)
                .unwrap();
        let runtime = tree.root().join("Aegis/runtime.json");
        std::fs::write(&runtime, &bytes).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut session = prepared(&tree);
        // The record cannot authorize its terms: they are refused exactly as
        // without it, and the derived binding is the saved one.
        let named = saved_for(&hostile.owner_generation, hostile.policy.clone());
        assert!(session.derive_runtime(&named).is_err());
        let saved = saved_for(tree.generation(), tree.policy().clone());
        let (bound, online) = session.derive_runtime(&saved).unwrap();
        assert_eq!(online.issued_generation, Some(7));
        // Rewriting the record in place changes nothing the provider holds.
        std::fs::write(&runtime, b"{}").unwrap();
        session.bind_runtime_for_test(&bound, &saved).unwrap();
        // The binding is identical to one derived from a tree without it.
        drop(session);
        std::fs::remove_file(&runtime).unwrap();
        let mut clean = prepared(&tree);
        let (clean_bound, _) = clean.derive_runtime(&saved).unwrap();
        bound.ensure_same(&clean_bound).unwrap();
    }
}
