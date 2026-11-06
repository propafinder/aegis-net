//! B-06 S23: the provider's enrollment exchange for one renewal.
//!
//! Each attempt is one fresh connection, as aegis-client's `perform`: TCP to
//! the profile's numeric enrollment authority on a socket bound to the
//! epoch's pinned physical interface (S16f, so the provider's own tunnel
//! never captures it), the product outer TLS/ECH and H2 carrier from the
//! held outer CA and bridge credential (`connect_h2_from_held`,
//! `Purpose::Enrollment`), then the pinned inner enrollment TLS (TLS 1.3,
//! ALPN `aegis-enroll/1`, the held inner CA), a challenge, a signed request
//! and a response. Three attempts, 100 and 200 ms apart, each within
//! `ATTEMPT_BUDGET` and the step's remaining budget, so a stalled attempt
//! still leaves the next one its time; a busy, unavailable or broken attempt
//! switches a journaled request to receipt recovery, a rejected receipt to a
//! fresh authorization, and a rejected authorization or a required authority
//! recovery ends the step with the request kept (v32: the caller then parks
//! it, `identity_renewal`; v32 review: only when no request of it ever went
//! unanswered, [`Dials::unanswered`]).
//!
//! v32 (S23c): a parked request is resumed from `online-request.parked.json`
//! and renamed back to `online-request.json` (`RenewalJournal::unpark`)
//! once per step, after its proof is signed and before the request's first
//! byte. An issued receipt the journal refuses is `Outcome::Unaccepted`
//! with that check's code, never `Local`: the authority may already list
//! the successor, so the request stays journaled.
//!
//! Clock skew against the authority: a challenge our clock cannot sign yet
//! (the authority's clock leads ours) waits at most `CLOCK_WAIT` before the
//! request is journaled, and an issued successor whose signed `not_before`
//! is still ahead waits at most `CLOCK_WAIT` before it is accepted. Both
//! keep the library's own checks; only our clock is waited for.
//!
//! One refinement of the library order: with no journaled request, the
//! request is written only after the connection is up and its challenge
//! read, still before the first request byte. An unreachable authority then
//! leaves no journal, and the old certificate keeps carrying traffic.
//!
//! v31 (S23b): every connect attempt is counted ([`Dials`]). A TCP connect
//! that never completes (its own `CONNECT_BUDGET`, or an attempt's or the
//! step's budget ending during it) is `connect_timeout`; `timeout` is now
//! only a timeout after the connect. The caller asks for one connect
//! attempt instead of `ATTEMPTS` after a step whose every connect timed
//! out.
//!
//! The inner client mirrors aegis-core `enrollment_tls::Client::load`, built
//! from the held CA bytes instead of a path (that constructor is recorded as
//! a shared change for merge), with the same restricted crypto policy:
//! TLS 1.3 with ChaCha20-Poly1305 or AES-128-GCM, X25519 only.
use crate::{
    app_group::CapturedBridgeSnapshot,
    bound_relay_policy::BoundRelayPolicy,
    identity_renewal::FailureClass,
    relay_socket::{connect_bound, RelayInterface},
    renewal_journal::{Completion, RenewalJournal, RequestMaterial},
};
use aegis_core::{
    https_bridge::{Credential, Purpose},
    secure_channel::{
        enrollment::protocol::{ChallengeMessage, ProofPurpose, CHALLENGE_SECS},
        enrollment_wire::{self as wire, ExchangeResponse, FailureCode},
        registry,
    },
    RelaySettings,
};
use std::{
    cell::Cell,
    net::SocketAddr,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio_rustls::{
    rustls::{self, pki_types::ServerName},
    TlsConnector,
};

/// aegis-core `enrollment_tls` ALPN.
pub(crate) const ENROLLMENT_ALPN: &[u8] = b"aegis-enroll/1";
/// The relay dial's connect budget (provider_session_body `CONNECT_BUDGET`).
pub(crate) const CONNECT_BUDGET: Duration = Duration::from_secs(2);
/// aegis-core `enrollment_tls` handshake timeout.
const HANDSHAKE_BUDGET: Duration = Duration::from_secs(5);
/// aegis-core `enrollment_tls` session timeout: challenge to response.
const SESSION_BUDGET: Duration = Duration::from_secs(30);
/// aegis-client `OnlineProfile` carrier timeout (outer TLS, H2, carrier 200).
const CARRIER_TIMEOUT_MS: u64 = 5_000;
/// aegis-client `perform`: attempts per step.
pub(crate) const ATTEMPTS: u32 = 3;
/// The most one attempt may take, connect to response: a stalled attempt
/// leaves the next one (receipt recovery) its own time within the step.
pub(crate) const ATTEMPT_BUDGET: Duration = Duration::from_secs(8);
/// The most our clock is waited for, against an authority whose clock leads.
pub(crate) const CLOCK_WAIT: Duration = Duration::from_secs(3);
/// v45: the host's TCP connect budget for its first enrollment: a friend's
/// own network, before any tunnel.
pub(crate) const HOST_CONNECT_BUDGET: Duration = Duration::from_secs(6);
const CLOCK_POLL: Duration = Duration::from_millis(50);

/// Refusal of a challenge our clock cannot sign within `CLOCK_WAIT`.
pub(crate) const CLOCK_SKEW: &str = "renewal_clock_skew";

/// Refusal of an authority the held profile cannot name.
pub(crate) const AUTHORITY_REFUSED: &str = "renewal_authority_refused";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// aegis-core `secure_channel::provider()`, which `enrollment_tls::Client`
/// and the authority use: ChaCha20-Poly1305 and AES-128-GCM, X25519 only.
pub(crate) fn enrollment_provider() -> rustls::crypto::CryptoProvider {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites = vec![
        rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
    ];
    provider.kx_groups = vec![rustls::crypto::ring::kx_group::X25519];
    provider
}

/// Whether `sign_proof` admits `challenge` at our `now`.
fn signable(challenge: &ChallengeMessage, now: u64) -> bool {
    challenge.expires_at_unix_secs > now
        && challenge.expires_at_unix_secs <= now.saturating_add(CHALLENGE_SECS)
}

/// Our clock once it reaches `at`, waiting at most `CLOCK_WAIT`; the last
/// reading otherwise.
pub(crate) async fn clock_at_least(at: u64) -> Result<u64, &'static str> {
    let until = Instant::now() + CLOCK_WAIT;
    loop {
        let now = registry::unix_now().map_err(|_| "session_clock_failed")?;
        if now >= at || Instant::now() >= until {
            return Ok(now);
        }
        tokio::time::sleep(CLOCK_POLL).await;
    }
}

/// The held profile's `enrollment` section as JSON.
fn enrollment_metadata(profile: &[u8]) -> Result<serde_json::Value, &'static str> {
    let profile = aegis_client::device_bundle_profile::validate_profile(profile)
        .map_err(|_| AUTHORITY_REFUSED)?;
    serde_json::to_value(&profile.enrollment).map_err(|_| AUTHORITY_REFUSED)
}

fn metadata_field(metadata: &serde_json::Value, key: &str) -> Result<String, &'static str> {
    metadata
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or(AUTHORITY_REFUSED)
}

/// The numeric `enrollment.authority_server`: a port and a unicast,
/// specified address.
fn authority_from_metadata(metadata: &serde_json::Value) -> Result<SocketAddr, &'static str> {
    let address: SocketAddr = metadata_field(metadata, "authority_server")?
        .parse()
        .map_err(|_| AUTHORITY_REFUSED)?;
    if address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast() {
        return Err(AUTHORITY_REFUSED);
    }
    Ok(address)
}

/// The enrollment authority of one held public profile. S20b allowed it
/// beside the relay while the tunnel guards; v31 (S23b) does not: the
/// renewal step and its monitor compare it with the armed relay tuple
/// (`leak_guard::Gate::dial_refused`) and defer instead of dialing.
pub(crate) fn authority_address(profile: &[u8]) -> Result<SocketAddr, &'static str> {
    authority_from_metadata(&enrollment_metadata(profile)?)
}

/// The held profile's enrollment authority, ready to dial.
pub(crate) struct EnrollmentAuthority {
    address: SocketAddr,
    carrier: RelaySettings,
    outer_ca: Vec<u8>,
    bridge: Option<Credential>,
    inner: Arc<rustls::ClientConfig>,
    inner_name: ServerName<'static>,
    /// Test-only: the bound interface index of every socket dialed.
    #[cfg(test)]
    pub(crate) bound: Option<Arc<std::sync::Mutex<Vec<u32>>>>,
}

/// v31: the connect attempts of one renewal step, single-threaded (the
/// step's current-thread runtime).
#[derive(Debug, Default)]
pub(crate) struct Dials {
    started: Cell<u32>,
    connected: Cell<u32>,
    connect_timeouts: Cell<u32>,
    in_connect: Cell<bool>,
    // v32 review: requests whose first byte was about to be written, and
    // the answers read that settle one (anything but `Unavailable`, which
    // the authority sends when its signing job ended without an answer).
    sent: Cell<u32>,
    settled: Cell<u32>,
}

impl Dials {
    /// v32 review: a request's first byte is about to be written.
    fn sending(&self) {
        self.sent.set(self.sent.get().saturating_add(1));
    }

    /// v32 review: an answer that settles the request just sent: Issued,
    /// Rejected, RecoveryRequired or Busy (the authority's lock or quota,
    /// before any commit).
    fn settled(&self) {
        self.settled.set(self.settled.get().saturating_add(1));
    }

    /// v32 review: a request of this step went unanswered (its answer lost,
    /// a timeout or `Unavailable` after its first byte): the authority may
    /// have issued for it, so a later Rejected proves nothing about it.
    pub(crate) fn unanswered(&self) -> bool {
        self.sent.get() > self.settled.get()
    }

    fn begin(&self) {
        self.started.set(self.started.get().saturating_add(1));
        self.in_connect.set(true);
    }

    fn connected(&self) {
        self.in_connect.set(false);
        self.connected.set(self.connected.get().saturating_add(1));
    }

    fn refused(&self) {
        self.in_connect.set(false);
    }

    fn timed_out(&self) {
        self.in_connect.set(false);
        self.connect_timeouts
            .set(self.connect_timeouts.get().saturating_add(1));
    }

    /// A budget ended this attempt: during its connect it is a connect
    /// timeout, else a timeout once connected.
    fn cut(&self) -> FailureClass {
        if self.in_connect.get() {
            self.timed_out();
            FailureClass::ConnectTimeout
        } else {
            FailureClass::Timeout
        }
    }

    /// After the step: count a connect the step's own end cut short as a
    /// connect timeout. True when it did. v31 review: never called after a
    /// provider stop, which is no timeout (`identity_renewal::before_capture`).
    pub(crate) fn settle(&self) -> bool {
        let cut = self.in_connect.get();
        if cut {
            self.timed_out();
        }
        cut
    }

    /// Connect attempts started.
    pub(crate) fn started(&self) -> u32 {
        self.started.get()
    }

    /// Whether every connect attempt of the step timed out (`None`: none
    /// was made, which changes nothing).
    pub(crate) fn starved(&self) -> Option<bool> {
        let started = self.started.get();
        (started > 0).then(|| self.connected.get() == 0 && self.connect_timeouts.get() == started)
    }
}

/// One attempt's failure before a response.
pub(crate) enum AttemptError {
    Transport(FailureClass),
    Local(&'static str),
}

/// v32: which request a step resumes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Resume {
    /// None: a fresh request is written after the first challenge.
    None,
    /// The journaled `online-request.json`.
    Request,
    /// The parked request, unparked before its first byte.
    Parked,
}

/// How one renewal step ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Issued, verified and installed.
    Issued(Completion),
    /// The authority answered with a failure, or never answered.
    Failed(FailureClass),
    /// A local journal or Store check refused before a request byte of the
    /// failing attempt (stable code).
    Local(&'static str),
    /// v32: the authority issued a receipt the journal refused (its check's
    /// stable code, `renewal_journal::CHECKS`, or `session_clock_failed`).
    Unaccepted(&'static str),
}

fn transport(error: &anyhow::Error) -> FailureClass {
    if error.chain().any(|cause| {
        cause
            .downcast_ref::<tokio::time::error::Elapsed>()
            .is_some()
    }) {
        FailureClass::Timeout
    } else {
        FailureClass::Unavailable
    }
}

impl EnrollmentAuthority {
    /// From the four held public files and the held bridge snapshot: the
    /// profile's numeric `enrollment.authority_server`, its outer and inner
    /// TLS names, and the same signed carrier policy (ECH, bridge, outer CA)
    /// the relay dial uses, aimed at the authority.
    pub(crate) fn from_held(
        public: [Vec<u8>; 4],
        bridge: Option<CapturedBridgeSnapshot>,
        bundle: &Path,
        identity: &Path,
    ) -> Result<Self, &'static str> {
        let metadata = enrollment_metadata(&public[0])?;
        let field = |key: &str| metadata_field(&metadata, key);
        let address = authority_from_metadata(&metadata)?;
        let outer_name = field("outer_server_name")?;
        let inner_name =
            ServerName::try_from(field("inner_server_name")?).map_err(|_| AUTHORITY_REFUSED)?;
        let credential = bridge
            .as_ref()
            .map(|held| Credential::from_captured_bytes(held.secret.as_slice()))
            .transpose()
            .map_err(|_| AUTHORITY_REFUSED)?;
        let outer_ca = public[1].clone();
        let inner_ca = public[2].clone();
        let policy = BoundRelayPolicy::from_snapshot(public, bridge, bundle, identity)
            .map_err(|_| AUTHORITY_REFUSED)?;
        let mut carrier = policy.settings().relay.clone();
        carrier.server = address.to_string();
        carrier.server_name = outer_name;
        carrier.endpoints = Vec::new();
        // v40: one exchange is one single-carrier attempt to the authority,
        // as `relay_settings_for_endpoint` makes each pool attempt: the
        // pool's failover policy belongs to the pool (a v4 pool of two or
        // more pins carries one), and with the pool gone it would refuse
        // the held connector of every renewal dial.
        carrier.carrier_failover = None;
        carrier.endpoint_bandit = None;
        carrier.connect_timeout_ms = CARRIER_TIMEOUT_MS;
        // The carrier request must build for this authority before any dial.
        aegis_client::prepared_outer_tls::h2_carrier_request_from_held(
            &carrier,
            credential.as_ref(),
            Purpose::Enrollment,
        )
        .map_err(|_| AUTHORITY_REFUSED)?;
        let roots = aegis_core::secure_channel::trust_roots_from_pem(&inner_ca)
            .map_err(|_| AUTHORITY_REFUSED)?;
        let mut inner =
            rustls::ClientConfig::builder_with_provider(Arc::new(enrollment_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|_| AUTHORITY_REFUSED)?
                .with_root_certificates(roots)
                .with_no_client_auth();
        inner.alpn_protocols = vec![ENROLLMENT_ALPN.to_vec()];
        inner.resumption = rustls::client::Resumption::disabled();
        inner.enable_early_data = false;
        inner.key_log = Arc::new(rustls::NoKeyLog);
        Ok(Self {
            address,
            carrier,
            outer_ca,
            bridge: credential,
            inner: Arc::new(inner),
            inner_name,
            #[cfg(test)]
            bound: None,
        })
    }

    /// The authority's numeric pin: what a first start resolves its
    /// physical egress interface from.
    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    /// Test-only: the inner enrollment TLS client configuration.
    #[cfg(test)]
    pub(crate) fn inner_config(&self) -> &rustls::ClientConfig {
        &self.inner
    }

    #[cfg_attr(not(test), allow(unused_variables))]
    fn record_bound(&self, tcp: &tokio::net::TcpStream) {
        #[cfg(test)]
        if let Some(bound) = &self.bound {
            use std::os::fd::AsRawFd;
            let index = crate::relay_socket::bound_index(tcp.as_raw_fd(), self.address.is_ipv6())
                .unwrap_or(0);
            bound.lock().unwrap().push(index);
        }
    }

    /// One connection: challenge, (journal), proof, (v32: unpark), request,
    /// response. `unpark`: the resumed request is still parked.
    async fn attempt(
        &self,
        interface: &RelayInterface,
        journal: &RenewalJournal,
        material: &mut Option<RequestMaterial>,
        unpark: &mut bool,
        purpose: ProofPurpose,
        dials: &Dials,
    ) -> Result<ExchangeResponse, AttemptError> {
        dials.begin();
        let tcp = match tokio::time::timeout(CONNECT_BUDGET, connect_bound(self.address, interface))
            .await
        {
            Ok(Ok(tcp)) => {
                dials.connected();
                tcp
            }
            Ok(Err(_)) => {
                dials.refused();
                return Err(AttemptError::Transport(FailureClass::Unavailable));
            }
            Err(_) => {
                dials.timed_out();
                return Err(AttemptError::Transport(FailureClass::ConnectTimeout));
            }
        };
        self.record_bound(&tcp);
        let held = aegis_client::prepared_outer_tls::connect_h2_from_held(
            &self.carrier,
            &self.outer_ca,
            self.bridge.as_ref(),
            Purpose::Enrollment,
            tcp,
        )
        .await
        .map_err(|error| AttemptError::Transport(transport(&error)))?;
        let (io, mut driver) = held.into_parts();
        let connector = TlsConnector::from(self.inner.clone());
        let exchange = async move {
            let mut tls = match tokio::time::timeout(
                HANDSHAKE_BUDGET,
                connector.connect(self.inner_name.clone(), io),
            )
            .await
            {
                Ok(Ok(tls)) => tls,
                Ok(Err(_)) => return Err(AttemptError::Transport(FailureClass::Unavailable)),
                Err(_) => return Err(AttemptError::Transport(FailureClass::Timeout)),
            };
            if tls.get_ref().1.alpn_protocol() != Some(ENROLLMENT_ALPN) {
                return Err(AttemptError::Transport(FailureClass::Unavailable));
            }
            let session = async {
                let challenge = wire::read_challenge(&mut tls)
                    .await
                    .map_err(|_| AttemptError::Transport(FailureClass::Unavailable))?;
                // A challenge issued by a clock ahead of ours: wait for ours,
                // and journal nothing for one it can never sign.
                let now = clock_at_least(
                    challenge
                        .expires_at_unix_secs
                        .saturating_sub(CHALLENGE_SECS),
                )
                .await
                .map_err(AttemptError::Local)?;
                if !signable(&challenge, now) {
                    return Err(AttemptError::Local(CLOCK_SKEW));
                }
                let current = match material.as_ref() {
                    Some(current) => current.clone(),
                    None => {
                        // Durable before the request's first byte.
                        let begun = journal.begin_renew(now).map_err(AttemptError::Local)?;
                        *material = Some(begun.clone());
                        begun
                    }
                };
                let signature = journal
                    .sign(&current.binding, &challenge, purpose, now)
                    .map_err(AttemptError::Local)?;
                if *unpark {
                    // v32: durable before the request's first byte, as a
                    // fresh request: the journaled request again.
                    journal.unpark().map_err(AttemptError::Local)?;
                    *unpark = false;
                }
                let authorize = purpose == ProofPurpose::Authorize;
                let request = wire::ExchangeRequest {
                    binding: current.binding.clone(),
                    purpose,
                    csr_pem: current.csr_pem.clone(),
                    predecessor_certificate_pem: if authorize {
                        current.predecessor_certificate_pem.clone()
                    } else {
                        None
                    },
                    invitation: None,
                    signature: hex(&signature),
                };
                // v32 review: from here the authority may act on it.
                dials.sending();
                wire::write_request(&mut tls, &request)
                    .await
                    .map_err(|_| AttemptError::Transport(FailureClass::Unavailable))?;
                wire::read_response(&mut tls)
                    .await
                    .map_err(|_| AttemptError::Transport(FailureClass::Unavailable))
            };
            match tokio::time::timeout(SESSION_BUDGET, session).await {
                Ok(result) => result,
                Err(_) => Err(AttemptError::Transport(FailureClass::Timeout)),
            }
        };
        tokio::pin!(exchange);
        // The H2 driver is polled with the exchange. Once it ends, the
        // exchange can only fail on its own bounded reads.
        tokio::select! {
            result = &mut exchange => result,
            _ = &mut driver => exchange.await,
        }
    }

    /// v45: one connection of the host's first enrollment (`--enroll`,
    /// `host_enroll`): the same outer carrier, inner enrollment TLS,
    /// challenge, durable request before its first byte, proof and response
    /// as `attempt`, for the Redeem journal of a staged identity. The user's
    /// own process, before any tunnel (`host_enroll` refuses a live session
    /// first), still dials through the bound socket helper on the physical
    /// interface toward the authority, as every relay dial does. The
    /// invitation goes only into an Authorize request; its request copy is
    /// overwritten once written.
    pub(crate) async fn redeem_attempt(
        &self,
        interface: &RelayInterface,
        journal: &crate::enroll_journal::EnrollJournal,
        profile_sha256: &str,
        invitation: &str,
        material: &mut Option<crate::enroll_journal::RedeemMaterial>,
        purpose: ProofPurpose,
    ) -> Result<ExchangeResponse, AttemptError> {
        let tcp =
            match tokio::time::timeout(HOST_CONNECT_BUDGET, connect_bound(self.address, interface))
                .await
            {
                Ok(Ok(tcp)) => tcp,
                Ok(Err(_)) => return Err(AttemptError::Transport(FailureClass::Unavailable)),
                Err(_) => return Err(AttemptError::Transport(FailureClass::ConnectTimeout)),
            };
        let held = aegis_client::prepared_outer_tls::connect_h2_from_held(
            &self.carrier,
            &self.outer_ca,
            self.bridge.as_ref(),
            Purpose::Enrollment,
            tcp,
        )
        .await
        .map_err(|error| AttemptError::Transport(transport(&error)))?;
        let (io, mut driver) = held.into_parts();
        let connector = TlsConnector::from(self.inner.clone());
        let exchange = async move {
            let mut tls = match tokio::time::timeout(
                HANDSHAKE_BUDGET,
                connector.connect(self.inner_name.clone(), io),
            )
            .await
            {
                Ok(Ok(tls)) => tls,
                Ok(Err(_)) => return Err(AttemptError::Transport(FailureClass::Unavailable)),
                Err(_) => return Err(AttemptError::Transport(FailureClass::Timeout)),
            };
            if tls.get_ref().1.alpn_protocol() != Some(ENROLLMENT_ALPN) {
                return Err(AttemptError::Transport(FailureClass::Unavailable));
            }
            let session = async {
                let challenge = wire::read_challenge(&mut tls)
                    .await
                    .map_err(|_| AttemptError::Transport(FailureClass::Unavailable))?;
                let now = clock_at_least(
                    challenge
                        .expires_at_unix_secs
                        .saturating_sub(CHALLENGE_SECS),
                )
                .await
                .map_err(AttemptError::Local)?;
                if !signable(&challenge, now) {
                    return Err(AttemptError::Local(CLOCK_SKEW));
                }
                if material.is_none() {
                    // Durable before the request's first byte.
                    *material = Some(
                        journal
                            .begin_redeem(profile_sha256, invitation)
                            .map_err(AttemptError::Local)?,
                    );
                }
                let current = material
                    .as_ref()
                    .ok_or(AttemptError::Local(crate::enroll_journal::LOCAL))?;
                let signature = journal
                    .sign(profile_sha256, &current.binding, &challenge, purpose, now)
                    .map_err(AttemptError::Local)?;
                let authorize = purpose == ProofPurpose::Authorize;
                let mut request = wire::ExchangeRequest {
                    binding: current.binding.clone(),
                    purpose,
                    csr_pem: current.csr_pem.clone(),
                    predecessor_certificate_pem: None,
                    invitation: authorize.then(|| current.invitation.to_string()),
                    signature: hex(&signature),
                };
                let sent = wire::write_request(&mut tls, &request).await;
                if let Some(token) = request.invitation.as_mut() {
                    zeroize::Zeroize::zeroize(token);
                }
                sent.map_err(|_| AttemptError::Transport(FailureClass::Unavailable))?;
                wire::read_response(&mut tls)
                    .await
                    .map_err(|_| AttemptError::Transport(FailureClass::Unavailable))
            };
            match tokio::time::timeout(SESSION_BUDGET, session).await {
                Ok(result) => result,
                Err(_) => Err(AttemptError::Transport(FailureClass::Timeout)),
            }
        };
        tokio::pin!(exchange);
        tokio::select! {
            result = &mut exchange => result,
            _ = &mut driver => exchange.await,
        }
    }

    /// One renewal: up to `connects` (1 to `ATTEMPTS`) connections within
    /// `budget`, each counted in `dials`.
    /// `resume`: the request to resume (receipt recovery first), if any.
    /// `receipt_only`: only that request's receipt may be recovered, never a
    /// fresh authorization (the predecessor expired, or v32: the authority
    /// already issued for it).
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn perform(
        &self,
        journal: &RenewalJournal,
        interface: &RelayInterface,
        resume: Resume,
        receipt_only: bool,
        budget: Duration,
        connects: u32,
        dials: &Dials,
    ) -> Outcome {
        let connects = connects.clamp(1, ATTEMPTS);
        let deadline = tokio::time::Instant::now() + budget;
        let mut material = None;
        let mut unpark = resume == Resume::Parked;
        if resume != Resume::None {
            let now = match registry::unix_now() {
                Ok(now) => now,
                Err(_) => return Outcome::Local("session_clock_failed"),
            };
            match journal.begin_renew(now) {
                Ok(resumed) => material = Some(resumed),
                Err(code) => return Outcome::Local(code),
            }
        } else if receipt_only {
            return Outcome::Local(crate::renewal_journal::PREDECESSOR_EXPIRED);
        }
        let mut purpose = if material.is_some() {
            ProofPurpose::Receipt
        } else {
            ProofPurpose::Authorize
        };
        let mut last = FailureClass::Unavailable;
        for attempt in 0..connects {
            let share =
                ATTEMPT_BUDGET.min(deadline.saturating_duration_since(tokio::time::Instant::now()));
            let answered = match tokio::time::timeout(
                share,
                self.attempt(
                    interface,
                    journal,
                    &mut material,
                    &mut unpark,
                    purpose,
                    dials,
                ),
            )
            .await
            {
                Ok(answered) => answered,
                Err(_) => Err(AttemptError::Transport(dials.cut())),
            };
            if matches!(&answered, Ok(response) if !matches!(response, ExchangeResponse::Failed {
                code: FailureCode::Unavailable
            })) {
                dials.settled();
            }
            match answered {
                Ok(ExchangeResponse::Issued { receipt }) => {
                    let now = match registry::unix_now() {
                        Ok(now) => now,
                        Err(_) => return Outcome::Unaccepted("session_clock_failed"),
                    };
                    return match journal.accept(&receipt, now) {
                        Ok(done) => Outcome::Issued(done),
                        // Signed by a clock ahead of ours: wait for ours,
                        // then the same full verification again.
                        Err(crate::renewal_journal::NOT_YET_VALID) => {
                            match clock_at_least(receipt.not_before_unix_secs).await {
                                Ok(now) => journal
                                    .accept(&receipt, now)
                                    .map_or_else(Outcome::Unaccepted, Outcome::Issued),
                                Err(code) => Outcome::Unaccepted(code),
                            }
                        }
                        Err(code) => Outcome::Unaccepted(code),
                    };
                }
                Ok(ExchangeResponse::Failed {
                    code: FailureCode::Rejected,
                }) if purpose == ProofPurpose::Receipt && !receipt_only => {
                    purpose = ProofPurpose::Authorize;
                    last = FailureClass::Rejected;
                }
                Ok(ExchangeResponse::Failed {
                    code: FailureCode::Rejected,
                }) => return Outcome::Failed(FailureClass::Rejected),
                Ok(ExchangeResponse::Failed {
                    code: FailureCode::RecoveryRequired,
                }) => return Outcome::Failed(FailureClass::RecoveryRequired),
                Ok(ExchangeResponse::Failed {
                    code: FailureCode::Busy | FailureCode::Unavailable,
                }) => {
                    last = FailureClass::Unavailable;
                    if material.is_some() {
                        purpose = ProofPurpose::Receipt;
                    }
                }
                Err(AttemptError::Transport(class)) => {
                    last = class;
                    if material.is_some() {
                        purpose = ProofPurpose::Receipt;
                    }
                }
                Err(AttemptError::Local(code)) => return Outcome::Local(code),
            }
            if attempt + 1 < connects {
                tokio::time::sleep(Duration::from_millis(100 * u64::from(attempt + 1))).await;
            }
        }
        Outcome::Failed(last)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dials_classify_connect_timeouts_and_a_starved_step() {
        // Every connect timed out: starved, and the next step makes one.
        let dials = Dials::default();
        assert_eq!(dials.starved(), None, "no dial changes nothing");
        dials.begin();
        dials.timed_out();
        dials.begin();
        // An attempt's budget ended during its connect.
        assert_eq!(dials.cut(), FailureClass::ConnectTimeout);
        assert_eq!(dials.started(), 2);
        assert_eq!(dials.starved(), Some(true));
        assert!(!dials.settle(), "nothing left in a connect");
        // The step's own end during a connect counts as one too.
        dials.begin();
        assert!(dials.settle());
        assert_eq!(dials.starved(), Some(true));
        // Once connected, a budget's end is a timeout after the connect,
        // and the step is not starved.
        let dials = Dials::default();
        dials.begin();
        dials.connected();
        assert_eq!(dials.cut(), FailureClass::Timeout);
        assert_eq!(dials.starved(), Some(false));
        // A refused connect (RST, unreachable) is no timeout either.
        let dials = Dials::default();
        dials.begin();
        dials.refused();
        assert!(!dials.settle());
        assert_eq!(dials.starved(), Some(false));
        let dials = Dials::default();
        dials.begin();
        dials.timed_out();
        dials.begin();
        dials.refused();
        assert_eq!(dials.starved(), Some(false), "one refusal is an answer");
    }
}
