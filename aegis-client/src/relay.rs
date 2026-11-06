//! Relay/tunnel client transports.

mod byte_progress;
mod carrier_failover;
mod endpoint_bandit;
mod events;
#[cfg(feature = "legacy-challenge-v1")]
mod fresh_legacy;
mod geneva_outer;
mod grpc;
pub(crate) use geneva_outer::failure as outer_geneva_failure;
pub(crate) use geneva_outer::shutdown as shutdown_outer_geneva;
mod local_session;
pub(crate) mod masque;
pub(crate) mod masque_crypto;
mod policy;
mod secure;
pub(crate) use secure::open_enrollment;
pub(crate) use secure::policy_ack;
#[cfg(all(test, windows))]
pub(crate) use secure::tests::configs as secure_test_configs;
mod surface;
mod tls_backend;
#[cfg(any(test, windows))]
mod tls_read_fairness;
#[cfg(test)]
pub(crate) use tls_backend::inline_ech_fixture;
#[cfg(test)]
mod carrier_failover_tests;
#[cfg(test)]
pub(crate) mod latency_tests;
#[cfg(test)]
mod learning_tests;
#[cfg(test)]
mod timing_controls_tests;
#[cfg(test)]
mod udp_pool_tests;
mod websocket;

pub(crate) use aegis_client::relay_endpoint_policy::{
    effective_relay_endpoints, effective_relay_udp_endpoints, endpoint_runtime_ready,
    format_authority_host, relay_settings_for_endpoint, relay_transport_authority,
    transport_authority_for_host, EffectiveRelayEndpoint, RelayTransportAuthority,
};

use crate::ingress::UdpSessionControl;
use crate::{anyhow_error_chain_messages, anyhow_error_kind_code};
use aegis_core::carrier_program::CarrierChannel;
#[cfg(test)]
use aegis_core::mimicry::StackProfileId;
#[cfg(not(feature = "legacy-challenge-v1"))]
use aegis_core::tunnel::{
    encode_stream_frame, open_tunnel_response, read_stream_frame, seal_tunnel_request,
    MAX_TUNNEL_CONTROL_FRAME,
};
#[cfg(test)]
use aegis_core::RelayEndpointSettings;
#[cfg(test)]
use aegis_core::WireMimicryMode;
use aegis_core::{RelaySettings, TunnelRequest, TunnelStatus, TunnelTransportFamily};
use anyhow::Context;
use http::{HeaderMap, HeaderValue};
use rustls::pki_types::ServerName;
#[cfg(test)]
use serde_json::json;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::AtomicU64;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};

#[cfg(test)]
#[path = "relay_udp_failure_event_tests.rs"]
mod udp_failure_event_tests;

/// Per-attempt byte counters shared into a transport handler's relay loop so the
/// caller can tell whether the tunnel actually carried application data — the axis
/// that separates a genuine success from a session the DPI established then killed
/// before the app's request went through. Recording-only: used purely to classify
/// the outcome the Brain records; it does not change the Ok/Err control flow.
#[derive(Clone)]
pub(crate) struct RelaySessionCounters {
    // Retry safety is separate from recording-only byte evidence: once an
    // authenticated tunnel opens, this connection cannot be silently replayed.
    opened: Arc<AtomicBool>,
    /// Application bytes read from the local app and forwarded toward the relay.
    bytes_sent: Arc<AtomicU64>,
    /// Application response bytes observed from the relay. Some handlers count
    /// before the local write; this is not an application-delivery receipt.
    bytes_received: Arc<AtomicU64>,
    timing: Arc<RelayTimingObservations>,
}

struct RelayTimingObservations {
    started: Instant,
    opened_after: OnceLock<Duration>,
    first_response_after: OnceLock<Duration>,
}

impl Default for RelaySessionCounters {
    fn default() -> Self {
        Self::for_attempt(Instant::now())
    }
}

impl RelaySessionCounters {
    fn for_attempt(started: Instant) -> Self {
        Self {
            opened: Arc::default(),
            bytes_sent: Arc::default(),
            bytes_received: Arc::default(),
            timing: Arc::new(RelayTimingObservations {
                started,
                opened_after: OnceLock::new(),
                first_response_after: OnceLock::new(),
            }),
        }
    }

    pub(crate) fn mark_opened(&self) {
        self.opened.store(true, Ordering::Relaxed);
        self.timing
            .opened_after
            .get_or_init(|| self.timing.started.elapsed());
    }

    fn was_opened(&self) -> bool {
        self.opened.load(Ordering::Relaxed)
    }

    pub(crate) fn add_sent(&self, n: usize) {
        self.bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
    }
    pub(crate) fn add_received(&self, n: usize) {
        self.bytes_received.fetch_add(n as u64, Ordering::Relaxed);
        if n > 0 && self.was_opened() {
            self.timing
                .first_response_after
                .get_or_init(|| self.timing.started.elapsed());
        }
    }
    fn sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }
    fn received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }
}

/// Monotonic observations from the beginning of this transport attempt.
/// Opening includes authentication and target acceptance. First response is an
/// application read observation, including target think time, not RTT/delivery.
/// The entire attempt duration remains the classifier's original lifetime.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RelayAttemptTiming {
    pub attempt_duration: Duration,
    pub opened_after: Option<Duration>,
    pub first_response_after: Option<Duration>,
}

/// Learning requires either application-byte evidence or a genuine error.
/// A clean empty session supplies neither a success nor a failure sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelayLearningDisposition {
    NoApplicationTraffic,
    Recordable,
}

/// The outcome of one relay transport attempt, reported to the caller (main.rs)
/// so it can feed the Brain (`record_outcome`). Emitted once per attempt via the
/// optional sink passed to [`run_relay_tunnel`]; absent for callers that do not
/// opt in (the tun-adapter paths pass `None`).
///
/// Recording-only: the same classifier snapshot feeds the Brain and TCP
/// terminal telemetry without changing transport order or retry behavior.
/// Response-byte evidence is deliberately separate from the function's Ok/Err
/// and does not claim that the local application consumed or accepted a reply.
#[derive(Clone, Debug)]
pub struct RelayOutcome {
    pub transport: aegis_core::TunnelTransportFamily,
    pub signal: aegis_core::signals::FailSignal,
    pub(crate) learning: RelayLearningDisposition,
    pub bytes_sent: u64,
    pub bytes_received_observed: u64,
    pub timing: RelayAttemptTiming,
}

impl RelayOutcome {
    pub(crate) fn from_attempt(
        transport: TunnelTransportFamily,
        result: &anyhow::Result<()>,
        bytes_sent: u64,
        bytes_received: u64,
        elapsed: std::time::Duration,
        configured_timeout: std::time::Duration,
    ) -> Self {
        Self {
            transport,
            signal: classify_relay_attempt(
                result,
                bytes_sent,
                bytes_received,
                elapsed,
                configured_timeout,
            ),
            learning: if result.is_ok() && bytes_sent == 0 && bytes_received == 0 {
                RelayLearningDisposition::NoApplicationTraffic
            } else {
                RelayLearningDisposition::Recordable
            },
            bytes_sent,
            bytes_received_observed: bytes_received,
            timing: RelayAttemptTiming {
                attempt_duration: elapsed,
                ..Default::default()
            },
        }
    }

    fn with_observed_timing(mut self, counters: &RelaySessionCounters) -> Self {
        self.timing.opened_after = counters.timing.opened_after.get().copied();
        self.timing.first_response_after = counters.timing.first_response_after.get().copied();
        self
    }

    /// Future success samples use a measured opening only. Missing observations
    /// preserve existing EMAs; session lifetime never substitutes for opening.
    pub(crate) fn learning_opening_latency_ms(&self) -> Option<u64> {
        self.learning_signal()
            .filter(|signal| signal.is_success())?;
        self.timing
            .opened_after
            .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
    }

    pub(crate) fn learning_signal(&self) -> Option<&aegis_core::signals::FailSignal> {
        match self.learning {
            RelayLearningDisposition::NoApplicationTraffic => None,
            RelayLearningDisposition::Recordable => Some(&self.signal),
        }
    }
}

/// Recording-only terminal evidence for TCP. A successful function return is
/// not itself proof of a response, and must never trigger a retry to obtain one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelayTcpCompletion {
    ResponseObserved,
    NoResponseObserved,
    NoAttemptObserved,
    Failed,
}

impl RelayTcpCompletion {
    pub(crate) fn from_result(
        result: &anyhow::Result<()>,
        terminal: Option<&RelayOutcome>,
    ) -> Self {
        if result.is_err() {
            return Self::Failed;
        }
        match terminal {
            Some(outcome) if outcome.signal.is_success() && outcome.bytes_received_observed > 0 => {
                Self::ResponseObserved
            }
            Some(_) => Self::NoResponseObserved,
            None => Self::NoAttemptObserved,
        }
    }

    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::ResponseObserved => "response_observed",
            Self::NoResponseObserved => "no_response_observed",
            Self::NoAttemptObserved => "no_attempt_observed",
            Self::Failed => "transport_error",
        }
    }
}

/// Optional per-session sink for [`RelayOutcome`]s (one per transport attempted).
pub type RelayOutcomeSink = tokio::sync::mpsc::UnboundedSender<RelayOutcome>;

/// Classify a single relay transport attempt into a [`FailSignal`] for the Brain,
/// using observed application bytes and genuine errors:
/// - `Ok` + return data carried → `Success`.
/// - `Ok` + no application bytes → `Unknown` for terminal telemetry, paired with
///   typed `NoApplicationTraffic` so consumers skip learning. Clean local closure
///   alone cannot establish DPI interference or successful delivery.
/// - `Ok` + app sent, no reply → `SessionFreeze` (TSPU-style stall after request).
/// - `Err` → the shared `classify_outcome` model on the io error kind + real bytes.
///
/// Recording-only: this only shapes the `FailSignal` the Brain records; it does
/// NOT change the Ok/Err control flow (the in-session warm switch is a later,
/// live-validated brick).
fn classify_relay_attempt(
    result: &anyhow::Result<()>,
    bytes_sent: u64,
    bytes_received: u64,
    elapsed: std::time::Duration,
    configured_timeout: std::time::Duration,
) -> aegis_core::signals::FailSignal {
    use aegis_core::signals::{classify_outcome, FailSignal, OutcomeContext};
    match result {
        Ok(()) if bytes_received > 0 => FailSignal::Success,
        // Without a request, a clean close is not hostile-path evidence.
        Ok(()) if bytes_sent == 0 => FailSignal::Unknown,
        // App request went out but no reply came back before close.
        Ok(()) => FailSignal::SessionFreeze {
            bytes_before_stall: bytes_sent as usize,
        },
        Err(err) => {
            let io_error = err
                .chain()
                .find_map(|cause| cause.downcast_ref::<std::io::Error>())
                .map(|e| e.kind());
            let ctx = OutcomeContext {
                io_error,
                rst_ttl: None,
                rst_source: None,
                expected_ttl: None,
                bytes_sent: bytes_sent as usize,
                bytes_received: bytes_received as usize,
                syn_ack_seen: true,
                first_data_seen: bytes_received > 0,
                is_tls: true,
                elapsed,
                configured_timeout,
                freeze_threshold_bytes: 16384,
                degraded_latency_ms: 5000,
            };
            let signal = classify_outcome(false, &ctx);
            // App-layer / tunnel-handshake rejection. The attempt failed (Err) with
            // NO network-level signal — no io error and no timeout — and carried no
            // app data. That is the shape of a relay path/endpoint that answered the
            // tunnel handshake with a non-upgrade HTTP response (a 404 / block-page /
            // decoy), rather than an RST or drop. `classify_outcome` bottoms out at
            // `FailSignal::Unknown`, which the Brain barely penalizes (fitness delta
            // ~-0.1, counted in no block bucket) — so a transport that an app-layer
            // block keeps killing is never demoted (brick 2 stays inert against L7
            // blocking, even though it reacts correctly to RST/timeout). Reclassify
            // the pre-data `Unknown` as `HandshakeMismatch` (a real block signal) so
            // the adaptive reorder can learn it. Guarded on `bytes_received == 0` so a
            // transport that actually carried data before an odd close is left as-is;
            // the min-samples + EMA-decay guards still prevent thrash on a one-off.
            if matches!(signal, FailSignal::Unknown) && bytes_received == 0 {
                FailSignal::HandshakeMismatch
            } else {
                signal
            }
        }
    }
}

/// When the IPv6 full-wide-tun engine is active it captures ALL IPv6 (routes
/// `::/1` + `8000::/1` into the TUN). A relay leg dialed over IPv6 would then be
/// swallowed by that capture and loop back into itself — a silent, self-amplifying
/// relay loop the stall watchdog cannot see. While the tun engine runs we force
/// the relay TCP dial to IPv4, which the engine keeps off the capture with its
/// static `::ffff:0:0/96` exclude. This makes loop-avoidance STRUCTURAL rather
/// than dependent on a spawn-time DNS snapshot of relay IPs.
static RELAY_FORCE_IPV4: AtomicBool = AtomicBool::new(false);

/// Enable/disable forced-IPv4 relay dialing (see [`RELAY_FORCE_IPV4`]). Called by
/// the IPv6 tun engine launcher (Linux-only).
#[cfg(target_os = "linux")]
pub(crate) fn set_relay_force_ipv4(on: bool) {
    RELAY_FORCE_IPV4.store(on, Ordering::Relaxed);
}

/// Test-only record of every outer relay TCP dial target (bounded). Leak
/// oracles assert that a destination never appears here.
#[cfg(test)]
pub(crate) static TEST_DIAL_LOG: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

#[cfg(test)]
fn record_test_dial(server: &str) {
    if let Ok(mut log) = TEST_DIAL_LOG.lock() {
        if log.len() < 1_000_000 {
            log.push(server.to_owned());
        }
    }
}

/// Dial the relay TCP endpoint `server` ("host:port"), honoring
/// [`RELAY_FORCE_IPV4`]. When forced, resolve and connect the first IPv4 address;
/// if the host resolves to no IPv4 address, fail closed rather than dial IPv6
/// (which would loop under full-wide-tun). When not forced, behaves exactly like
/// `TcpStream::connect(server)`.
pub(crate) async fn connect_relay_tcp(server: &str) -> std::io::Result<TcpStream> {
    #[cfg(test)]
    record_test_dial(server);
    if RELAY_FORCE_IPV4.load(Ordering::Relaxed) {
        let mut last_err: Option<std::io::Error> = None;
        for addr in tokio::net::lookup_host(server).await? {
            if addr.is_ipv4() {
                match TcpStream::connect(addr).await {
                    Ok(s) => return Ok(s),
                    Err(e) => last_err = Some(e),
                }
            }
        }
        return Err(last_err.unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                format!(
                    "relay {server} has no IPv4 address; refusing IPv6 relay dial while \
                     full-wide-tun is active (would loop the capture)"
                ),
            )
        }));
    }
    TcpStream::connect(server).await
}

use events::{
    emit_relay_session_started, emit_relay_session_succeeded, emit_relay_transport_failed,
    emit_relay_transport_selected, emit_stealth_profile_rotated, RelaySessionStartedEvent,
};
#[cfg(test)]
use local_session::local_session_aborted;
#[cfg(unix)]
use local_session::local_session_aborted_fd;
use local_session::local_session_pre_open_aborted;
pub(crate) use policy::SurfaceBias;
use surface::legacy_tls_wire_alpn;
#[cfg(test)]
use surface::tls_profile_target_alpn_value;
pub(crate) use surface::RelayMimicryContext;
#[cfg(test)]
use surface::{
    maybe_add_relay_surface_fields, maybe_add_runtime_mimicry_fields,
    maybe_add_tls_wire_adapter_fields,
};
use tls_backend::connect_tls;
pub(crate) use tls_backend::load_roots;
#[cfg(test)]
pub(crate) use tls_backend::rustls_tls_connector as tls_connector;

#[cfg(unix)]
use std::os::fd::AsRawFd;

#[cfg(test)]
static TEST_UDP_DATAGRAM_FAILURES_REMAINING: AtomicUsize = AtomicUsize::new(0);

pub(crate) async fn diagnostic_tls_clienthello_probe(
    settings: &RelaySettings,
    addr: SocketAddr,
    verify_name: &str,
    alpn_protocols: &[Vec<u8>],
    enable_sni: bool,
) -> anyhow::Result<Option<String>> {
    let tcp = if settings.outer_geneva.is_some() {
        anyhow::ensure!(
            settings.server.parse::<SocketAddr>().ok() == Some(addr),
            "selected relay Geneva probe endpoint differs from the pinned relay"
        );
        geneva_outer::connect(settings)
            .await
            .context("connect protected probe tcp")?
    } else {
        TcpStream::connect(addr)
            .await
            .context("connect probe tcp")?
            .into()
    };
    let server_name = ServerName::try_from(verify_name.to_string()).context("probe server name")?;
    match tls_backend::connect_tls_with_alpn_protocols(
        settings,
        tcp,
        server_name,
        verify_name,
        alpn_protocols,
        enable_sni,
    )
    .await
    {
        Ok(_tls) => Ok(None),
        Err(err) => Ok(Some(err.to_string())),
    }
}

/// Classify a relay transport error as "endpoint is unreachable" vs
/// "transport-specific issue". Endpoint-unreachable errors mean further
/// transports against the same endpoint will fail in the same way, so
/// the caller can short-circuit to the next endpoint without burning
/// 4 × per-transport timeout budget on a provably-dead host.
///
/// Conservative kinds list — only errors that PROVE the underlying
/// transport (TCP for legacy_tls / https_ws / grpc_stream, UDP for
/// masque_derived) cannot reach the host. TLS / WebSocket / gRPC
/// protocol errors stay outside this set because they can be
/// transport-family-specific (the host may speak a different family
/// on the same port).
fn is_endpoint_unreachable_error(err: &anyhow::Error) -> bool {
    matches!(
        anyhow_error_kind_code(err),
        Some("connection_refused" | "timed_out" | "host_unreachable" | "network_unreachable")
    )
}

fn relay_tunnel_status_code(status: TunnelStatus) -> Option<&'static str> {
    match status {
        TunnelStatus::Ok => None,
        TunnelStatus::AuthFailed => Some("auth_failed"),
        TunnelStatus::BadTarget => Some("bad_target"),
        TunnelStatus::TransportUnavailable => Some("transport_unavailable"),
    }
}

#[derive(Debug, Clone, Error)]
#[error("{label}: {message}")]
pub(super) struct RelayTunnelResponseError {
    label: &'static str,
    pub status: TunnelStatus,
    pub message: String,
}

pub(super) fn tunnel_response_error(
    label: &'static str,
    status: TunnelStatus,
    message: String,
) -> anyhow::Error {
    anyhow::Error::new(RelayTunnelResponseError {
        label,
        status,
        message,
    })
}

pub(super) fn benign_io_close(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .map(|io| {
                matches!(
                    io.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::NotConnected
                )
            })
            .unwrap_or(false)
    })
}

fn relay_failure_scope(err: &anyhow::Error) -> &'static str {
    if let Some(err) = err
        .chain()
        .find_map(|cause| cause.downcast_ref::<RelayTunnelResponseError>())
    {
        return match err.status {
            TunnelStatus::BadTarget | TunnelStatus::TransportUnavailable => {
                "tunnel_level_target_error"
            }
            TunnelStatus::AuthFailed | TunnelStatus::Ok => "real_transport_outage",
        };
    }
    if benign_io_close(err) {
        return "benign_session_end";
    }
    "real_transport_outage"
}

pub(super) fn apply_transport_camouflage_headers(
    headers: &mut HeaderMap,
    profile: &policy::RelaySessionProfile,
) -> anyhow::Result<()> {
    insert_transport_header(headers, "user-agent", profile.user_agent)?;
    insert_transport_header(headers, "accept", profile.accept_header)?;
    if let Some(value) = profile.accept_language_header {
        insert_transport_header(headers, "accept-language", value)?;
    }
    if let Some(value) = profile.cache_control_header {
        insert_transport_header(headers, "cache-control", value)?;
    }
    order_headers_like_chrome(headers);
    Ok(())
}

/// Put ordinary headers in the Chrome profile's order. Names the profile does
/// not list keep their relative order after the listed ones.
pub(super) fn order_headers_like_chrome(headers: &mut HeaderMap) {
    let preferred = aegis_chrome_profile::chrome_stable()
        .http2
        .header_order
        .clone();
    let mut current: Option<http::HeaderName> = None;
    let mut indexed = Vec::new();
    for (index, (name, value)) in headers.drain().enumerate() {
        if let Some(name) = name {
            current = Some(name);
        }
        let Some(name) = current.clone() else {
            continue;
        };
        indexed.push((index, name, value));
    }
    indexed.sort_by(|(left_index, left_name, _), (right_index, right_name, _)| {
        let rank = |name: &http::HeaderName| {
            preferred
                .iter()
                .position(|wanted| wanted.eq_ignore_ascii_case(name.as_str()))
                .unwrap_or(usize::MAX)
        };
        rank(left_name)
            .cmp(&rank(right_name))
            .then(left_index.cmp(right_index))
    });
    for (_, name, value) in indexed {
        headers.append(name, value);
    }
}

pub(super) fn apply_websocket_request_shape_headers(
    headers: &mut HeaderMap,
    profile: &policy::RelaySessionProfile,
) -> anyhow::Result<()> {
    apply_transport_camouflage_headers(headers, profile)?;
    if let Some(value) = profile.websocket_origin_header.as_deref() {
        insert_transport_header(headers, "origin", value)?;
    }
    order_headers_like_chrome(headers);
    Ok(())
}

pub(super) fn apply_grpc_request_shape_headers(
    headers: &mut HeaderMap,
    profile: &policy::RelaySessionProfile,
) -> anyhow::Result<()> {
    apply_transport_camouflage_headers(headers, profile)?;
    if let Some(value) = profile.grpc_accept_encoding_header {
        insert_transport_header(headers, "grpc-accept-encoding", value)?;
    }
    if let Some(value) = profile.grpc_encoding_header {
        insert_transport_header(headers, "grpc-encoding", value)?;
    }
    if let Some(value) = profile.grpc_timeout_header {
        insert_transport_header(headers, "grpc-timeout", value)?;
    }
    if let Some(value) = profile.grpc_message_type_header {
        insert_transport_header(headers, "grpc-message-type", value)?;
    }
    order_headers_like_chrome(headers);
    Ok(())
}

pub(super) fn apply_masque_request_shape_headers(
    headers: &mut HeaderMap,
    profile: &policy::RelaySessionProfile,
) -> anyhow::Result<()> {
    apply_transport_camouflage_headers(headers, profile)?;
    if let Some(value) = profile.masque_alt_used_header.as_deref() {
        insert_transport_header(headers, "alt-used", value)?;
    }
    order_headers_like_chrome(headers);
    Ok(())
}

fn insert_transport_header(
    headers: &mut HeaderMap,
    name: &'static str,
    value: &str,
) -> anyhow::Result<()> {
    headers.insert(
        name,
        HeaderValue::from_str(value).with_context(|| format!("parse relay header {name}"))?,
    );
    Ok(())
}

fn relay_tunnel_status_from_error(err: &anyhow::Error) -> Option<&'static str> {
    err.chain()
        .find_map(|cause| cause.downcast_ref::<RelayTunnelResponseError>())
        .and_then(|err| relay_tunnel_status_code(err.status))
}

#[derive(Debug, Clone, Error)]
#[error("{message}")]
pub struct RelayTerminalFailure {
    pub message: String,
    pub error_kind: Option<&'static str>,
    pub error_chain: Vec<String>,
    pub target: Option<String>,
    pub port: Option<u16>,
    pub relay_server: String,
    pub relay_server_name: String,
    pub attempts_total: usize,
    pub planned_transports: Vec<String>,
    pub last_transport: Option<String>,
}

fn relay_terminal_error_details(
    error: Option<anyhow::Error>,
    fallback_message: &str,
) -> (String, Option<&'static str>, Vec<String>) {
    let Some(error) = error else {
        let message = fallback_message.to_string();
        return (message.clone(), None, vec![message]);
    };
    let error_kind = anyhow_error_kind_code(&error);
    let error_chain = anyhow_error_chain_messages(&error);
    let message = if error_chain.is_empty() {
        fallback_message.to_string()
    } else {
        error_chain.join(": ")
    };
    (message, error_kind, error_chain)
}

#[derive(Debug, Clone, Error)]
#[error("CONNECT-UDP tunnel failed for {target}:{port}: {message}")]
struct UdpAssociateTunnelFailure {
    target: String,
    port: u16,
    message: String,
}

fn udp_associate_tunnel_failure(err: &anyhow::Error) -> Option<&UdpAssociateTunnelFailure> {
    err.chain()
        .find_map(|cause| cause.downcast_ref::<UdpAssociateTunnelFailure>())
}

/// An application datagram may already have left this attempt. Never replay it
/// on another carrier/endpoint merely because the response failed to arrive.
#[derive(Debug, Error)]
#[error("UDP payload committed; automatic replay is disabled")]
struct UdpPayloadCommitted(#[source] anyhow::Error);

pub(super) fn udp_payload_committed(err: anyhow::Error) -> anyhow::Error {
    if udp_payload_was_committed(&err) {
        err
    } else {
        UdpPayloadCommitted(err).into()
    }
}

fn udp_payload_was_committed(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| cause.is::<UdpPayloadCommitted>())
}

struct RelayTransportFailureContext<'a> {
    session_kind: &'static str,
    target: Option<&'a str>,
    port: Option<u16>,
    settings: &'a RelaySettings,
    attempt_index: usize,
    attempts_total: usize,
    planned_transports: &'a [String],
}

/// Apply the per-session soft-wire socket plan to a freshly-connected
/// relay TCP stream, before TLS. Emits a `relay_soft_wire_applied`
/// runtime event recording the resolved plan and whether every
/// setsockopt succeeded. Best-effort: setsockopt failures are reported
/// but do not abort the session. When the configured mode is not
/// `SoftWireSocketOptions`, this function is a no-op (returns without
/// emitting) and leaves the kernel defaults in place.
pub(crate) fn apply_soft_wire_plan_to_stream(
    stream: &TcpStream,
    settings: &RelaySettings,
    target: Option<(&str, u16)>,
) {
    let Some(mut plan) =
        policy::relay_soft_wire_plan(settings, target, aegis_core::current_unix_secs())
    else {
        return;
    };
    let ttl_ok = stream.set_ttl(plan.ip_ttl as u32).is_ok();
    let nodelay_ok = stream.set_nodelay(plan.nodelay).is_ok();
    plan.applied = ttl_ok && nodelay_ok;
    events::emit_relay_soft_wire_applied(settings, target, plan, "tcp");
}

/// MASQUE/QUIC variant: applies IP_TTL to the underlying UDP socket of
/// the quinn::Endpoint and emits the resolved plan as a
/// relay_soft_wire_applied event. The keep-alive override is already
/// folded into the transport config by `masque_transport_config`;
/// emitting the plan here records the per-session UDP-layer choices.
pub(crate) fn apply_soft_wire_plan_to_masque_endpoint(
    endpoint: &quinn::Endpoint,
    settings: &RelaySettings,
    target: Option<(&str, u16)>,
    plan: Option<aegis_core::SoftWireRelaySocketPlan>,
) {
    let Some(mut plan) = plan else { return };
    // quinn::Endpoint::local_addr returns the bound UDP socket's address;
    // the kernel keeps the socket alive inside the endpoint and exposes
    // it via the runtime. We apply TTL by re-binding-by-fd through
    // socket2 if available, else best-effort skip and record applied=false.
    let ttl_ok = match endpoint.local_addr() {
        Ok(addr) => apply_udp_ttl_best_effort(addr, plan.ip_ttl),
        Err(_) => false,
    };
    plan.applied = ttl_ok;
    events::emit_relay_soft_wire_applied(settings, target, plan, "udp");
}

#[cfg(unix)]
fn apply_udp_ttl_best_effort(_local: std::net::SocketAddr, _ttl: u8) -> bool {
    // quinn 0.11 owns the bound UDP socket internally; there is no
    // public API to recover the std::net::UdpSocket from a live
    // Endpoint. Per-session TTL on the QUIC UDP socket therefore stays
    // a documented limitation of this release. The plan is still emitted
    // (applied=false, reason recorded in event) so evidence captures
    // show which sessions REQUESTED a TTL — useful for adapting the
    // implementation once quinn exposes the socket handle.
    false
}

#[cfg(not(unix))]
fn apply_udp_ttl_best_effort(_local: std::net::SocketAddr, _ttl: u8) -> bool {
    false
}

#[cfg(test)]
pub(crate) fn set_test_udp_datagram_failures_remaining(remaining: usize) {
    TEST_UDP_DATAGRAM_FAILURES_REMAINING.store(remaining, Ordering::SeqCst);
}

#[cfg(test)]
fn maybe_inject_test_udp_datagram_failure() -> Option<anyhow::Error> {
    let current = TEST_UDP_DATAGRAM_FAILURES_REMAINING.load(Ordering::SeqCst);
    if current == 0 {
        return None;
    }
    TEST_UDP_DATAGRAM_FAILURES_REMAINING.fetch_sub(1, Ordering::SeqCst);
    Some(anyhow::anyhow!(
        "test injected relay UDP datagram transport failure"
    ))
}

pub async fn run_relay_tunnel(
    mut local: TcpStream,
    settings: &RelaySettings,
    target_host: String,
    target_port: u16,
    initial_payload: Option<&[u8]>,
    mimicry_context: Option<RelayMimicryContext>,
    // Optional per-attempt outcome sink (Brick 1: feeds the Brain). Callers that
    // do not opt into adaptive-relay learning pass `None`.
    outcome_tx: Option<&RelayOutcomeSink>,
) -> anyhow::Result<()> {
    // Include the first pure optional graph admission in the same establishment clock.
    let endpoint_origin = settings
        .endpoint_bandit
        .as_ref()
        .map(|_| tokio::time::Instant::now());
    settings
        .validate_inner_tls_transport()
        .map_err(anyhow::Error::msg)?;
    // A speculative CONNECT that is already closed locally should not look like
    // a relay transport failure: there is no longer a live client session to
    // serve, so skip outbound relay attempts entirely.
    if local_session_pre_open_aborted(&local, initial_payload) {
        events::emit_relay_tcp_session_terminal(
            RelayTransportFailureContext {
                session_kind: "tcp_tunnel",
                target: Some(target_host.as_str()),
                port: Some(target_port),
                settings,
                attempt_index: 0,
                attempts_total: 0,
                planned_transports: &[],
            },
            None,
            None,
            mimicry_context,
        );
        return Ok(());
    }
    let endpoint_selection =
        endpoint_bandit::prepare_at(settings, &target_host, target_port, "tcp", endpoint_origin)?;
    let pool = effective_relay_endpoints(settings);
    // Carrier failover only reorders the explicit admitted pool; every
    // attempt keeps its own authentication and no-replay rules.
    let carrier_session = carrier_failover::Session::prepare(settings, &pool)?;
    let endpoints: Vec<(Option<usize>, EffectiveRelayEndpoint)> =
        match (&endpoint_selection, &carrier_session) {
            (Some(selection), _) => selection
                .rank(pool.into_iter().filter(endpoint_runtime_ready).collect())?
                .into_iter()
                .map(|endpoint| (None, endpoint))
                .collect(),
            (None, Some(session)) => session
                .order()
                .iter()
                .map(|index| (Some(*index), pool[*index].clone()))
                .filter(|(_, endpoint)| endpoint_runtime_ready(endpoint))
                .collect(),
            (None, None) => pool
                .into_iter()
                .filter(endpoint_runtime_ready)
                .map(|endpoint| (None, endpoint))
                .collect(),
        };
    let mut last_err = None;
    let mut last_transport = None;
    let mut last_relay_server = settings.server.clone();
    let mut last_relay_server_name = settings.server_name.clone();
    // Surface profile selection respects any Brain-derived SurfaceBias the
    // caller (typically `direct::run_relay_tunnel_with_direct_handoff`)
    // attached to the mimicry context. A neutral bias collapses to the
    // pre-2.5 deterministic mod-of-seed selection.
    let surface_bias = mimicry_context
        .map(|ctx| ctx.surface_bias)
        .unwrap_or_default();
    let session_profile = policy::build_session_profile_with_brain_bias(
        settings,
        Some((target_host.as_str(), target_port)),
        surface_bias,
    );
    let session_opened_at = aegis_core::current_unix_secs();
    let session_opened_profile_id: String = session_profile.profile_id.to_string();
    // The secure carrier uses standard H2 and its own fixed service route;
    // never report a legacy request-shape profile as having been applied.
    let observed_profile = settings.inner_tls.is_none().then_some(&session_profile);
    #[cfg(feature = "legacy-challenge-v1")]
    fresh_legacy::require_raw_tcp_order(
        settings.inner_tls.is_some(),
        &session_profile.transport_order,
    )?;
    let planned = session_profile.transport_order.clone();
    let planned_transports: Vec<String> = planned
        .iter()
        .map(|family| format!("{:?}", family))
        .collect();
    let attempts_total = endpoints.len().saturating_mul(planned.len());
    let session_started_instant = std::time::Instant::now();
    let mut prior_endpoint_failed_attempts = 0usize;
    let mut prior_endpoint_label: Option<String> = None;
    'endpoints: for (endpoint_index, (carrier_index, endpoint)) in endpoints.iter().enumerate() {
        let endpoint_ticket = match &endpoint_selection {
            Some(selection) => match selection.attempt(&endpoint.server)? {
                Some(ticket) => Some(ticket),
                None => continue,
            },
            None => None,
        };
        let carrier_ticket = carrier_session
            .as_ref()
            .zip(*carrier_index)
            .map(|(session, index)| session.ticket(index));
        let endpoint_settings = relay_settings_for_endpoint(settings, endpoint);
        last_relay_server = endpoint_settings.server.clone();
        last_relay_server_name = endpoint_settings.server_name.clone();
        emit_relay_session_started(RelaySessionStartedEvent {
            session_kind: "tcp_tunnel",
            settings: &endpoint_settings,
            target: Some(target_host.as_str()),
            port: Some(target_port),
            planned_transports: &planned_transports,
            attempts_total,
            profile: observed_profile,
            mimicry_context,
        });
        let endpoint_started_instant = std::time::Instant::now();
        let mut endpoint_short_circuited = false;
        for (transport_index, family) in planned.iter().copied().enumerate() {
            // After a TCP-unreachable short-circuit, skip remaining
            // TCP-family transports on this endpoint. MasqueDerived (UDP)
            // still gets a shot because (a) its dial target can be
            // overridden by settings.masque_server, and (b) UDP reachability
            // is independent of TCP reachability at the firewall layer.
            if endpoint_short_circuited && !matches!(family, TunnelTransportFamily::MasqueDerived) {
                continue;
            }
            let attempt_index = endpoint_index
                .saturating_mul(planned.len())
                .saturating_add(transport_index)
                .saturating_add(1);
            emit_relay_transport_selected(
                "tcp_tunnel",
                &endpoint_settings,
                Some(target_host.as_str()),
                Some(target_port),
                &planned_transports,
                family,
                attempt_index,
                attempts_total,
                observed_profile,
                mimicry_context,
            );
            let attempt_started = Instant::now();
            let session_counters = RelaySessionCounters::for_attempt(attempt_started);
            let attempt = match family {
                TunnelTransportFamily::LegacyTls => {
                    run_legacy_tls_tunnel(
                        &mut local,
                        &endpoint_settings,
                        &session_profile,
                        target_host.clone(),
                        target_port,
                        initial_payload,
                        &session_counters,
                    )
                    .await
                }
                TunnelTransportFamily::HttpsWs => {
                    websocket::run_websocket_tunnel(
                        &mut local,
                        &endpoint_settings,
                        &session_profile,
                        target_host.clone(),
                        target_port,
                        initial_payload,
                        &session_counters,
                    )
                    .await
                }
                TunnelTransportFamily::GrpcStream => {
                    if endpoint_settings.inner_tls.is_some() {
                        secure::run_with_endpoint(
                            &mut local,
                            &endpoint_settings,
                            target_host.clone(),
                            target_port,
                            initial_payload,
                            &session_counters,
                            endpoint_ticket.as_ref(),
                            endpoint.channel,
                            carrier_ticket.as_ref(),
                        )
                        .await
                    } else {
                        grpc::run_grpc_tunnel(
                            &mut local,
                            &endpoint_settings,
                            &session_profile,
                            target_host.clone(),
                            target_port,
                            initial_payload,
                            &session_counters,
                        )
                        .await
                    }
                }
                TunnelTransportFamily::GrpcDatagram => {
                    anyhow::bail!("grpc_datagram is UDP-only and cannot carry a TCP tunnel")
                }
                TunnelTransportFamily::MasqueDerived => {
                    masque::run_masque_tunnel(
                        &mut local,
                        &endpoint_settings,
                        &session_profile,
                        target_host.clone(),
                        target_port,
                        initial_payload,
                        &session_counters,
                    )
                    .await
                }
            };
            if let (Some(ticket), Err(error)) = (&endpoint_ticket, &attempt) {
                if !session_counters.was_opened() && secure::retryable_pre_auth_failure(error) {
                    ticket.pre_auth_failure();
                } else {
                    ticket.terminal_failure();
                }
            }
            if let (Some(ticket), Err(error)) = (&carrier_ticket, &attempt) {
                if !session_counters.was_opened() {
                    ticket.failed_before_open(error);
                }
            }
            // Report this transport attempt's outcome to the Brain sink (recording
            // only — transport order is unchanged). The app-byte counts (brick 3a)
            // separate observed application progress from clean empty closure;
            // genuine errors remain recordable even without application bytes.
            let elapsed = attempt_started.elapsed();
            let bytes_sent = session_counters.sent();
            let bytes_received = session_counters.received();
            let outcome = RelayOutcome::from_attempt(
                family,
                &attempt,
                bytes_sent,
                bytes_received,
                elapsed,
                std::time::Duration::from_millis(settings.connect_timeout_ms),
            )
            .with_observed_timing(&session_counters);
            if let Some(tx) = outcome_tx {
                let _ = tx.send(outcome.clone());
            }
            match attempt {
                Ok(()) => {
                    if let Some(prior) = prior_endpoint_label.as_deref() {
                        events::emit_relay_failover_recovery_observed(
                            &endpoint_settings,
                            Some((target_host.as_str(), target_port)),
                            prior,
                            session_started_instant.elapsed().as_millis() as u64,
                            prior_endpoint_failed_attempts,
                            &outcome,
                        );
                    }
                    events::emit_relay_tcp_session_terminal(
                        RelayTransportFailureContext {
                            session_kind: "tcp_tunnel",
                            settings: &endpoint_settings,
                            target: Some(target_host.as_str()),
                            port: Some(target_port),
                            planned_transports: &planned_transports,
                            attempt_index,
                            attempts_total,
                        },
                        Some(&outcome),
                        observed_profile,
                        mimicry_context,
                    );
                    // C3 intra-session drift signal: if the session lasted long
                    // enough that the catalog would now pick a different profile
                    // id for the same (target, port), emit stealth_profile_rotated.
                    // The event fires ONLY on real drift — short-lived sessions
                    // that stay inside a single epoch window do not trigger it.
                    let session_closed_at = aegis_core::current_unix_secs();
                    let current_profile = policy::build_session_profile_with_now_public(
                        settings,
                        Some((target_host.as_str(), target_port)),
                        session_closed_at,
                    );
                    if observed_profile.is_some()
                        && current_profile.profile_id != session_opened_profile_id.as_str()
                    {
                        emit_stealth_profile_rotated(
                            "tcp_tunnel",
                            Some(target_host.as_str()),
                            Some(target_port),
                            session_opened_profile_id.as_str(),
                            current_profile.profile_id,
                            session_closed_at.saturating_sub(session_opened_at),
                            settings.policy.drift_epoch_secs,
                        );
                    }
                    return Ok(());
                }
                Err(err) => {
                    emit_relay_transport_failed(
                        family,
                        RelayTransportFailureContext {
                            session_kind: "tcp_tunnel",
                            target: Some(target_host.as_str()),
                            port: Some(target_port),
                            settings: &endpoint_settings,
                            attempt_index,
                            attempts_total,
                            planned_transports: &planned_transports,
                        },
                        observed_profile,
                        mimicry_context,
                        &err,
                    );
                    last_transport = Some(format!("{:?}", family));
                    if session_counters.was_opened()
                        || (settings.inner_tls.is_some()
                            && !secure::retryable_pre_auth_failure(&err))
                    {
                        // Initial payload may already have been partially
                        // written even when counters are still zero. Only
                        // pre-open failures can safely advance this session.
                        // Inner TLS only retries typed failures before device
                        // authentication; later failures remain terminal.
                        last_err = Some(err);
                        break 'endpoints;
                    }
                    // First-fast-fail: if THIS TCP transport's error
                    // proves the endpoint is unreachable at the TCP
                    // layer, skip remaining TCP-family transports on
                    // this endpoint. MasqueDerived is UDP/QUIC and
                    // may dial a DIFFERENT address (settings.masque_server
                    // overrides settings.server), so it always gets to
                    // try even when TCP-on-same-endpoint failed. Only
                    // the FIRST transport per endpoint can short-circuit;
                    // subsequent TCP failures inside the same endpoint
                    // cycle stay informational because they may reflect
                    // transport-specific protocol issues.
                    let is_first_on_endpoint = transport_index == 0;
                    let was_tcp_family = !matches!(family, TunnelTransportFamily::MasqueDerived);
                    let remaining_planned = &planned[transport_index + 1..];
                    let remaining_tcp_count = remaining_planned
                        .iter()
                        .filter(|f| !matches!(f, TunnelTransportFamily::MasqueDerived))
                        .count();
                    if is_first_on_endpoint
                        && was_tcp_family
                        && is_endpoint_unreachable_error(&err)
                        && remaining_tcp_count > 0
                    {
                        let error_kind = anyhow_error_kind_code(&err).unwrap_or("other");
                        events::emit_relay_endpoint_short_circuit_fast_fail(
                            &endpoint_settings,
                            Some((target_host.as_str(), target_port)),
                            &format!("{:?}", family),
                            endpoint_started_instant.elapsed().as_millis() as u64,
                            remaining_tcp_count,
                            error_kind,
                        );
                        // Skip remaining TCP transports but let MasqueDerived
                        // (if still planned) take its shot — UDP/QUIC can
                        // survive TCP-layer unreachability when masque_server
                        // routes through a different host.
                        let masque_still_planned = remaining_planned
                            .iter()
                            .any(|f| matches!(f, TunnelTransportFamily::MasqueDerived));
                        if !masque_still_planned {
                            last_err = Some(err);
                            endpoint_short_circuited = true;
                            break;
                        }
                        // Continue the loop but mark the endpoint as
                        // having short-circuited TCP — the outer iteration
                        // skips the remaining TCP families explicitly below.
                        last_err = Some(err);
                        endpoint_short_circuited = true;
                        // Manually skip TCP transports: jump straight to
                        // the next MasqueDerived in planned[transport_index+1..].
                        // We achieve this by continuing iteration; the inner
                        // match below checks endpoint_short_circuited and
                        // skips non-MASQUE families.
                        continue;
                    }
                    last_err = Some(err);
                }
            }
        }
        // Endpoint exhausted (either all planned transports tried, or
        // short-circuited on first-transport unreachability). Record so
        // the next endpoint's success can emit
        // relay_failover_recovery_observed with accurate elapsed-ms.
        prior_endpoint_failed_attempts = if endpoint_short_circuited {
            1
        } else {
            planned.len()
        };
        prior_endpoint_label = Some(endpoint_settings.server.clone());
    }
    let (message, error_kind, error_chain) =
        relay_terminal_error_details(last_err, "no transport configured");
    Err(anyhow::Error::new(RelayTerminalFailure {
        message,
        error_kind,
        error_chain,
        target: Some(target_host),
        port: Some(target_port),
        relay_server: last_relay_server,
        relay_server_name: last_relay_server_name,
        attempts_total,
        planned_transports,
        last_transport,
    }))
}

pub fn runtime_fallback_ready(settings: &RelaySettings) -> bool {
    let endpoint_ready = effective_relay_endpoints(settings)
        .iter()
        .any(endpoint_runtime_ready);
    endpoint_ready
        && (settings.inner_tls.is_some() || !settings.auth_token.trim().is_empty())
        && settings.validate_inner_tls_transport().is_ok()
        && !policy::planned_transport_order(&settings.transport_priority, &settings.policy)
            .is_empty()
}

pub fn runtime_udp_fallback_ready(settings: &RelaySettings) -> bool {
    // The same executable plan feeds readiness and actual dispatch. This is
    // configuration readiness, not authenticated open or application egress.
    !udp_endpoint_attempts(settings, false).is_empty()
}

#[derive(Clone)]
struct UdpEndpointAttempt {
    settings: RelaySettings,
    family: TunnelTransportFamily,
    /// Index of the endpoint in the explicit pool (carrier failover identity).
    carrier: usize,
}

/// Endpoint-major ordering, with the policy's finite per-endpoint family
/// budget. Incidental duplicates of a shared direct override across TCP pool
/// entries are removed; explicitly repeated policy slots remain finite retries.
fn udp_endpoint_attempts(settings: &RelaySettings, associate: bool) -> Vec<UdpEndpointAttempt> {
    if (settings.inner_tls.is_none() && settings.auth_token.trim().is_empty())
        || settings.validate_inner_tls_transport().is_err()
    {
        return Vec::new();
    }
    let families = if associate {
        planned_udp_associate_transports(settings)
    } else {
        planned_fixed_udp_transports(settings)
    };
    let mut seen = std::collections::HashSet::new();
    let mut attempts = Vec::new();
    for (carrier, endpoint) in effective_relay_endpoints(settings)
        .into_iter()
        .enumerate()
        .filter(|(_, endpoint)| {
            matches!(
                endpoint.channel,
                None | Some(CarrierChannel::DirectH2 | CarrierChannel::OwnHttpsBridge)
            )
        })
    {
        let selected = relay_settings_for_endpoint(settings, &endpoint);
        for (policy_slot, family) in families.iter().copied().enumerate() {
            if family == TunnelTransportFamily::MasqueDerived
                && endpoint.masque_server.is_none()
                && settings.masque_server.is_some()
                && masque::masque_transport_authority(settings).is_err()
            {
                // A pool cannot repair an invalid global direct identity by
                // silently using a different TCP entry's certificate name.
                continue;
            }
            if !udp_transport_configured(&selected, family) {
                continue;
            }
            let (dial, authority) = match family {
                TunnelTransportFamily::MasqueDerived => (
                    selected
                        .masque_server
                        .as_deref()
                        .unwrap_or(&selected.server),
                    masque::masque_transport_authority(&selected)
                        .expect("configured authority checked above")
                        .authority_host,
                ),
                _ => (
                    selected.server.as_str(),
                    relay_transport_authority(&selected)
                        .expect("configured authority checked above")
                        .authority_host,
                ),
            };
            if seen.insert((
                format!("{family:?}"),
                policy_slot,
                dial.to_owned(),
                authority,
            )) {
                attempts.push(UdpEndpointAttempt {
                    settings: selected.clone(),
                    family,
                    carrier,
                });
            }
        }
    }
    attempts
}

fn planned_fixed_udp_transports(settings: &RelaySettings) -> Vec<TunnelTransportFamily> {
    policy::planned_udp_transport_order_with_seed(
        udp_transport_priority(settings),
        &settings.policy,
        0,
    )
}

fn udp_transport_configured(settings: &RelaySettings, family: TunnelTransportFamily) -> bool {
    match family {
        TunnelTransportFamily::GrpcDatagram => {
            !settings.server.trim().is_empty() && relay_transport_authority(settings).is_ok()
        }
        TunnelTransportFamily::MasqueDerived => {
            // QUIC dispatch parses this as SocketAddr; a hostname that only
            // the TCP resolver understands must not create UDP readiness.
            settings
                .masque_server
                .as_deref()
                .unwrap_or(&settings.server)
                .parse::<SocketAddr>()
                .is_ok()
                && masque::masque_transport_authority(settings).is_ok()
        }
        _ => false,
    }
}

fn planned_udp_associate_transports(settings: &RelaySettings) -> Vec<TunnelTransportFamily> {
    if settings.inner_tls.is_some() {
        return settings
            .udp_transport_priority
            .as_deref()
            .filter(|families| *families == [TunnelTransportFamily::GrpcDatagram])
            .unwrap_or_default()
            .to_vec();
    }
    // SOCKS ASSOCIATE is a multi-destination session. The gRPC datagram
    // implementation is fixed-destination only, so it must not consume the
    // attempt budget or be advertised as an executable ASSOCIATE transport.
    let supported: Vec<_> = udp_transport_priority(settings)
        .iter()
        .copied()
        .filter(|family| matches!(family, TunnelTransportFamily::MasqueDerived))
        .collect();
    policy::planned_udp_transport_order_with_seed(&supported, &settings.policy, 0)
}

pub fn runtime_udp_associate_ready(settings: &RelaySettings) -> bool {
    !udp_endpoint_attempts(settings, true).is_empty()
}

fn udp_transport_priority(settings: &RelaySettings) -> &[TunnelTransportFamily] {
    settings
        .udp_transport_priority
        .as_deref()
        .unwrap_or(&settings.transport_priority)
}

pub async fn run_relay_udp_associate(
    control: UdpSessionControl,
    udp_socket: UdpSocket,
    settings: &RelaySettings,
    client_ip: IpAddr,
) -> anyhow::Result<()> {
    let session_profile = policy::build_session_profile(settings, None);
    let planned = planned_udp_associate_transports(settings);
    let planned_transports: Vec<String> = planned
        .iter()
        .map(|family| format!("{:?}", family))
        .collect();
    let attempts_total = planned.len();
    let mut last_transport = None;
    emit_relay_session_started(RelaySessionStartedEvent {
        session_kind: "udp_associate",
        settings,
        target: None,
        port: None,
        planned_transports: &planned_transports,
        attempts_total,
        profile: settings.inner_tls.is_none().then_some(&session_profile),
        mimicry_context: None,
    });

    let Some(family) = planned.into_iter().next() else {
        let (message, error_kind, error_chain) =
            relay_terminal_error_details(None, "no UDP-capable transport configured");
        return Err(anyhow::Error::new(RelayTerminalFailure {
            message,
            error_kind,
            error_chain,
            target: None,
            port: None,
            relay_server: settings.server.clone(),
            relay_server_name: settings.server_name.clone(),
            attempts_total,
            planned_transports,
            last_transport,
        }));
    };

    emit_relay_transport_selected(
        "udp_associate",
        settings,
        None,
        None,
        &planned_transports,
        family,
        1,
        attempts_total,
        settings.inner_tls.is_none().then_some(&session_profile),
        None,
    );
    let attempt = match family {
        TunnelTransportFamily::MasqueDerived | TunnelTransportFamily::GrpcDatagram => {
            masque::run_udp_association(
                control,
                udp_socket,
                settings,
                &session_profile,
                family,
                client_ip,
            )
            .await
        }
        _ => anyhow::bail!("unsupported UDP relay transport {:?}", family),
    };
    match attempt {
        Ok(()) => {
            emit_relay_session_succeeded(
                "udp_associate",
                settings,
                None,
                None,
                &planned_transports,
                family,
                1,
                attempts_total,
                settings.inner_tls.is_none().then_some(&session_profile),
                None,
                None,
            );
            Ok(())
        }
        Err(err) => {
            let udp_tunnel_failure = udp_associate_tunnel_failure(&err);
            let failure_target = udp_tunnel_failure.map(|failure| failure.target.clone());
            let failure_port = udp_tunnel_failure.map(|failure| failure.port);
            emit_relay_transport_failed(
                family,
                RelayTransportFailureContext {
                    session_kind: "udp_associate",
                    target: failure_target.as_deref(),
                    port: failure_port,
                    settings,
                    attempt_index: 1,
                    attempts_total,
                    planned_transports: &planned_transports,
                },
                settings.inner_tls.is_none().then_some(&session_profile),
                None,
                &err,
            );
            last_transport = Some(format!("{:?}", family));
            let (message, error_kind, error_chain) =
                relay_terminal_error_details(Some(err), "UDP relay transport failed");
            Err(anyhow::Error::new(RelayTerminalFailure {
                message,
                error_kind,
                error_chain,
                target: failure_target,
                port: failure_port,
                relay_server: settings.server.clone(),
                relay_server_name: settings.server_name.clone(),
                attempts_total,
                planned_transports,
                last_transport,
            }))
        }
    }
}

/// Report one current CONNECT-UDP child attempt without terminating its
/// reusable SOCKS association. This describes only the selected single-family child;
/// it is not the association's fallback history or terminal outcome.
pub(super) fn emit_udp_associate_target_failure(
    settings: &RelaySettings,
    profile: &policy::RelaySessionProfile,
    family: TunnelTransportFamily,
    target: &crate::socks5::ConnectTarget,
    error: &anyhow::Error,
) {
    let planned_transports = [format!("{:?}", family)];
    emit_relay_transport_failed(
        family,
        RelayTransportFailureContext {
            session_kind: "udp_associate",
            target: Some(target.host.as_str()),
            port: Some(target.port),
            settings,
            attempt_index: 1,
            attempts_total: 1,
            planned_transports: &planned_transports,
        },
        settings.inner_tls.is_none().then_some(profile),
        None,
        error,
    );
}

#[cfg_attr(not(test), allow(dead_code))]
pub async fn run_relay_udp_datagram_once(
    settings: &RelaySettings,
    target: crate::socks5::ConnectTarget,
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let target_host = target.host.clone();
    let target_port = target.port;
    let session_profile =
        policy::build_session_profile(settings, Some((target_host.as_str(), target_port)));
    let (attempts, endpoint_selection, carrier_session) =
        learned_udp_attempts(settings, &target_host, target_port, false)?;
    let planned_transports: Vec<String> = attempts
        .iter()
        .map(|attempt| format!("{:?}", attempt.family))
        .collect();
    let attempts_total = attempts.len();
    let mut last_err = None;
    let mut last_transport = None;
    let mut last_settings = settings.clone();
    emit_relay_session_started(RelaySessionStartedEvent {
        session_kind: "udp_datagram_once",
        settings,
        target: Some(target_host.as_str()),
        port: Some(target_port),
        planned_transports: &planned_transports,
        attempts_total,
        profile: settings.inner_tls.is_none().then_some(&session_profile),
        mimicry_context: None,
    });

    for (attempt_index, plan) in attempts.into_iter().enumerate() {
        let endpoint_ticket = match &endpoint_selection {
            Some(selection) => match selection.attempt(&plan.settings.server)? {
                Some(ticket) => Some(ticket),
                None => continue,
            },
            None => None,
        };
        let carrier_ticket = carrier_session
            .as_ref()
            .map(|session| session.ticket(plan.carrier));
        let settings = &plan.settings;
        last_settings = settings.clone();
        let family = plan.family;
        let session_profile =
            policy::build_session_profile(settings, Some((target_host.as_str(), target_port)));
        emit_relay_transport_selected(
            "udp_datagram_once",
            settings,
            Some(target_host.as_str()),
            Some(target_port),
            &planned_transports,
            family,
            attempt_index + 1,
            attempts_total,
            settings.inner_tls.is_none().then_some(&session_profile),
            None,
        );
        #[cfg(test)]
        if let Some(err) = maybe_inject_test_udp_datagram_failure() {
            emit_relay_transport_failed(
                family,
                RelayTransportFailureContext {
                    session_kind: "udp_datagram_once",
                    target: Some(target_host.as_str()),
                    port: Some(target_port),
                    settings,
                    attempt_index: attempt_index + 1,
                    attempts_total,
                    planned_transports: &planned_transports,
                },
                settings.inner_tls.is_none().then_some(&session_profile),
                None,
                &err,
            );
            last_transport = Some(format!("{:?}", family));
            last_err = Some(err);
            continue;
        }
        let attempt = match family {
            TunnelTransportFamily::MasqueDerived => {
                masque::run_masque_udp_datagram_once(
                    settings,
                    &session_profile,
                    target.clone(),
                    payload,
                )
                .await
            }
            TunnelTransportFamily::GrpcDatagram => {
                if settings.inner_tls.is_some() {
                    secure::udp_once_with_endpoint(
                        settings,
                        &target,
                        payload,
                        endpoint_ticket.as_ref(),
                        carrier_ticket.as_ref(),
                    )
                    .await
                } else {
                    grpc::run_grpc_udp_datagram_once(
                        settings,
                        &session_profile,
                        target.clone(),
                        payload,
                    )
                    .await
                }
            }
            _ => anyhow::bail!("unsupported UDP relay transport {:?}", family),
        };
        if let (Some(ticket), Err(error)) = (&endpoint_ticket, &attempt) {
            if !udp_payload_was_committed(error) && secure::retryable_pre_auth_failure(error) {
                ticket.pre_auth_failure();
            } else {
                ticket.terminal_failure();
            }
        }
        if let (Some(ticket), Err(error)) = (&carrier_ticket, &attempt) {
            if !udp_payload_was_committed(error) {
                ticket.failed_before_open(error);
            }
        }
        match attempt {
            Ok(response) => {
                emit_relay_session_succeeded(
                    "udp_datagram_once",
                    settings,
                    Some(target_host.as_str()),
                    Some(target_port),
                    &planned_transports,
                    family,
                    attempt_index + 1,
                    attempts_total,
                    settings.inner_tls.is_none().then_some(&session_profile),
                    None,
                    None,
                );
                return Ok(response);
            }
            Err(err) => {
                emit_relay_transport_failed(
                    family,
                    RelayTransportFailureContext {
                        session_kind: "udp_datagram_once",
                        target: Some(target_host.as_str()),
                        port: Some(target_port),
                        settings,
                        attempt_index: attempt_index + 1,
                        attempts_total,
                        planned_transports: &planned_transports,
                    },
                    settings.inner_tls.is_none().then_some(&session_profile),
                    None,
                    &err,
                );
                last_transport = Some(format!("{:?}", family));
                let committed = udp_payload_was_committed(&err);
                last_err = Some(err);
                if committed
                    || (settings.inner_tls.is_some()
                        && !secure::retryable_pre_auth_failure(last_err.as_ref().unwrap()))
                {
                    break;
                }
            }
        }
    }

    let committed = last_err.as_ref().is_some_and(udp_payload_was_committed);
    let (message, error_kind, error_chain) =
        relay_terminal_error_details(last_err, "no UDP-capable transport configured");
    let error = anyhow::Error::new(RelayTerminalFailure {
        message,
        error_kind,
        error_chain,
        target: Some(target_host),
        port: Some(target_port),
        relay_server: last_settings.server,
        relay_server_name: last_settings.server_name,
        attempts_total,
        planned_transports,
        last_transport,
    });
    Err(if committed {
        udp_payload_committed(error)
    } else {
        error
    })
}

type LearnedUdpAttempts = (
    Vec<UdpEndpointAttempt>,
    Option<endpoint_bandit::Selection>,
    Option<carrier_failover::Session>,
);

fn learned_udp_attempts(
    settings: &RelaySettings,
    host: &str,
    port: u16,
    associate: bool,
) -> anyhow::Result<LearnedUdpAttempts> {
    let selection = endpoint_bandit::prepare(settings, host, port, "udp")?;
    let attempts = udp_endpoint_attempts(settings, associate);
    let Some(learner) = &selection else {
        // Carrier failover reorders the same planned attempts (one
        // grpc_datagram attempt per enrolled endpoint); it adds none.
        let carriers =
            carrier_failover::Session::prepare(settings, &effective_relay_endpoints(settings))?;
        let Some(session) = carriers else {
            return Ok((attempts, None, None));
        };
        let mut ordered = Vec::with_capacity(attempts.len());
        for index in session.order() {
            ordered.extend(
                attempts
                    .iter()
                    .filter(|attempt| attempt.carrier == *index)
                    .cloned(),
            );
        }
        return Ok((ordered, None, Some(session)));
    };
    let eligible = effective_relay_udp_endpoints(settings)
        .into_iter()
        .filter(|endpoint| {
            attempts.iter().any(|attempt| {
                attempt.settings.server == endpoint.server
                    && attempt.settings.server_name == endpoint.server_name
            })
        })
        .collect();
    let ranked = learner.rank(eligible)?;
    let mut result = Vec::new();
    for endpoint in ranked {
        result.extend(
            attempts
                .iter()
                .filter(|attempt| {
                    attempt.settings.server == endpoint.server
                        && attempt.settings.server_name == endpoint.server_name
                })
                .cloned(),
        );
    }
    Ok((result, selection, None))
}

/// Run a persistent full-wide UDP flow with policy-ordered transport failover.
/// MASQUE remains the preferred direct UDP path; `grpc_datagram` carries the
/// same datagram boundaries over fronted HTTP/2/TCP 443 when QUIC is blocked.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub async fn run_relay_udp_flow(
    settings: &RelaySettings,
    target_host: &str,
    target_port: u16,
    mut outbound_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    incoming_tx: tokio::sync::mpsc::Sender<crate::socks5::UdpPacket>,
) -> anyhow::Result<()> {
    let session_profile = policy::build_session_profile(settings, Some((target_host, target_port)));
    let (attempts, endpoint_selection, carrier_session) =
        learned_udp_attempts(settings, target_host, target_port, false)?;
    let planned_transports: Vec<String> = attempts
        .iter()
        .map(|attempt| format!("{:?}", attempt.family))
        .collect();
    let attempts_total = attempts.len();
    emit_relay_session_started(RelaySessionStartedEvent {
        session_kind: "udp_flow",
        settings,
        target: Some(target_host),
        port: Some(target_port),
        planned_transports: &planned_transports,
        attempts_total,
        profile: settings.inner_tls.is_none().then_some(&session_profile),
        mimicry_context: None,
    });
    let mut last_error = None;
    for (attempt_index, plan) in attempts.into_iter().enumerate() {
        let endpoint_ticket = match &endpoint_selection {
            Some(selection) => match selection.attempt(&plan.settings.server)? {
                Some(ticket) => Some(ticket),
                None => continue,
            },
            None => None,
        };
        let carrier_ticket = carrier_session
            .as_ref()
            .map(|session| session.ticket(plan.carrier));
        let settings = &plan.settings;
        let family = plan.family;
        let session_profile =
            policy::build_session_profile(settings, Some((target_host, target_port)));
        emit_relay_transport_selected(
            "udp_flow",
            settings,
            Some(target_host),
            Some(target_port),
            &planned_transports,
            family,
            attempt_index + 1,
            attempts_total,
            settings.inner_tls.is_none().then_some(&session_profile),
            None,
        );
        let attempt = match family {
            TunnelTransportFamily::MasqueDerived => {
                masque::run_masque_udp_flow_borrowed(
                    settings,
                    target_host,
                    target_port,
                    &mut outbound_rx,
                    &incoming_tx,
                )
                .await
            }
            TunnelTransportFamily::GrpcDatagram => {
                if settings.inner_tls.is_some() {
                    secure::udp_flow_with_endpoint(
                        settings,
                        &crate::socks5::ConnectTarget {
                            host: target_host.to_owned(),
                            port: target_port,
                        },
                        &mut outbound_rx,
                        &incoming_tx,
                        endpoint_ticket.as_ref(),
                        carrier_ticket.as_ref(),
                    )
                    .await
                } else {
                    grpc::run_grpc_udp_flow(
                        settings,
                        target_host,
                        target_port,
                        &mut outbound_rx,
                        &incoming_tx,
                    )
                    .await
                }
            }
            _ => continue,
        };
        if let (Some(ticket), Err(error)) = (&endpoint_ticket, &attempt) {
            if !udp_payload_was_committed(error) && secure::retryable_pre_auth_failure(error) {
                ticket.pre_auth_failure();
            } else {
                ticket.terminal_failure();
            }
        }
        if let (Some(ticket), Err(error)) = (&carrier_ticket, &attempt) {
            if !udp_payload_was_committed(error) {
                ticket.failed_before_open(error);
            }
        }
        match attempt {
            Ok(()) => {
                emit_relay_session_succeeded(
                    "udp_flow",
                    settings,
                    Some(target_host),
                    Some(target_port),
                    &planned_transports,
                    family,
                    attempt_index + 1,
                    attempts_total,
                    settings.inner_tls.is_none().then_some(&session_profile),
                    None,
                    None,
                );
                return Ok(());
            }
            Err(error) => {
                emit_relay_transport_failed(
                    family,
                    RelayTransportFailureContext {
                        session_kind: "udp_flow",
                        target: Some(target_host),
                        port: Some(target_port),
                        settings,
                        attempt_index: attempt_index + 1,
                        attempts_total,
                        planned_transports: &planned_transports,
                    },
                    settings.inner_tls.is_none().then_some(&session_profile),
                    None,
                    &error,
                );
                let committed = udp_payload_was_committed(&error);
                tracing::warn!(
                    transport = ?family,
                    target_port,
                    error = %error,
                    payload_committed = committed,
                    "persistent UDP relay transport failed"
                );
                let secure_terminal =
                    settings.inner_tls.is_some() && !secure::retryable_pre_auth_failure(&error);
                last_error = Some(error);
                if committed || secure_terminal {
                    break;
                }
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("no UDP-capable transport configured")))
}

/// SOCKS ASSOCIATE keeps a single client socket/control owner. Each target
/// opens only MASQUE-capable pool entries, and only before consuming payload
/// may it advance to the next entry. It does not turn fixed-target gRPC into
/// a multi-destination association.
async fn run_relay_udp_associate_flow(
    settings: RelaySettings,
    target: crate::socks5::ConnectTarget,
    outbound_rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
    incoming_tx: &tokio::sync::mpsc::Sender<crate::socks5::UdpPacket>,
) -> anyhow::Result<()> {
    let mut last_error = None;
    let (attempts, selection, carriers) =
        learned_udp_attempts(&settings, &target.host, target.port, true)?;
    for attempt in attempts {
        let ticket = match &selection {
            Some(selection) => match selection.attempt(&attempt.settings.server)? {
                Some(ticket) => Some(ticket),
                None => continue,
            },
            None => None,
        };
        let carrier_ticket = carriers
            .as_ref()
            .map(|session| session.ticket(attempt.carrier));
        if attempt.settings.inner_tls.is_some() {
            match secure::udp_flow_with_endpoint(
                &attempt.settings,
                &target,
                outbound_rx,
                incoming_tx,
                ticket.as_ref(),
                carrier_ticket.as_ref(),
            )
            .await
            {
                Ok(()) => return Ok(()),
                Err(error) => {
                    if let Some(carrier) = &carrier_ticket {
                        if !udp_payload_was_committed(&error) {
                            carrier.failed_before_open(&error);
                        }
                    }
                    if let Some(ticket) = &ticket {
                        if !udp_payload_was_committed(&error)
                            && secure::retryable_pre_auth_failure(&error)
                        {
                            ticket.pre_auth_failure();
                        } else {
                            ticket.terminal_failure();
                        }
                    }
                    if !secure::retryable_pre_auth_failure(&error) {
                        return Err(error);
                    }
                    last_error = Some(error);
                    continue;
                }
            }
        }
        let profile = policy::build_session_profile(
            &attempt.settings,
            Some((target.host.as_str(), target.port)),
        );
        match masque::run_single_connect_udp_tunnel(
            attempt.settings,
            profile,
            target.clone(),
            outbound_rx,
            incoming_tx,
        )
        .await
        {
            Ok(()) => return Ok(()),
            Err(error) => {
                let committed = udp_payload_was_committed(&error);
                last_error = Some(error);
                if committed {
                    break;
                }
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("no MASQUE-capable endpoint configured")))
}

async fn run_legacy_tls_tunnel(
    local: &mut TcpStream,
    settings: &RelaySettings,
    session_profile: &policy::RelaySessionProfile,
    target_host: String,
    target_port: u16,
    initial_payload: Option<&[u8]>,
    counters: &RelaySessionCounters,
) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now()
        .checked_add(std::time::Duration::from_millis(
            settings.connect_timeout_ms,
        ))
        .context("legacy TLS opening timeout is out of range")?;
    #[cfg(unix)]
    let local_fd = local.as_raw_fd();
    // The opening budget ends at authenticated acceptance, not at TCP connect
    // and not at the end of the long-lived application stream.
    let opened = tokio::time::timeout_at(deadline, async {
        let tcp = geneva_outer::connect(settings)
            .await
            .with_context(|| format!("connect relay {}", settings.server))?;
        apply_soft_wire_plan_to_stream(&tcp, settings, Some((target_host.as_str(), target_port)));
        let authority = relay_transport_authority(settings)?;
        let mut tls = connect_tls(
            settings,
            tcp,
            authority.tls_server_name,
            &authority.authority_host,
            legacy_tls_wire_alpn(session_profile),
            authority.send_sni,
        )
        .await?;

        if local_session_pre_open_aborted(local, initial_payload) {
            return Ok(None);
        }

        let req = TunnelRequest {
            host: target_host,
            port: target_port,
        };
        #[cfg(feature = "legacy-challenge-v1")]
        let resp = match aegis_core::tunnel::fresh_legacy::exchange_raw(
            &mut tls,
            &req,
            settings.auth_token.as_bytes(),
            deadline,
        )
        .await
        {
            Ok(response) => response,
            Err(error) => {
                if local_session_pre_open_aborted(local, initial_payload) {
                    return Ok(None);
                }
                return Err(fresh_legacy::opening_error(error, deadline).await);
            }
        };
        #[cfg(not(feature = "legacy-challenge-v1"))]
        let resp = {
            let frame = seal_tunnel_request(&req, settings.auth_token.as_bytes())?;
            if let Err(err) = tls.write_all(&encode_stream_frame(&frame)).await {
                let err = anyhow::Error::from(err);
                if local_session_pre_open_aborted(local, initial_payload) {
                    return Ok(None);
                }
                return Err(err);
            }

            let resp_frame = match read_stream_frame(&mut tls, MAX_TUNNEL_CONTROL_FRAME)
                .await
                .context("read tunnel response")
            {
                Ok(resp_frame) => resp_frame,
                Err(err) => {
                    if local_session_pre_open_aborted(local, initial_payload) {
                        return Ok(None);
                    }
                    return Err(err);
                }
            };
            let resp = open_tunnel_response(&resp_frame, settings.auth_token.as_bytes())?;
            resp
        };
        if resp.status != TunnelStatus::Ok {
            return Err(tunnel_response_error(
                "relay error",
                resp.status,
                resp.message,
            ));
        }
        counters.mark_opened();
        anyhow::Ok(Some(tls))
    })
    .await
    .with_context(|| {
        format!(
            "legacy TLS tunnel establishment timed out after {}ms",
            settings.connect_timeout_ms
        )
    })??;
    let Some(tls) = opened else {
        return Ok(());
    };

    let tls = byte_progress::ByteProgress::new(tls, counters);
    let (mut local_read, mut local_write) = tokio::io::split(local);
    let (mut tls_read, mut tls_write) = tokio::io::split(tls);
    policy::write_prefetched_payload(&mut tls_write, session_profile, initial_payload).await?;
    // Both directions are shaped by the same session profile so the wire
    // does not present an asymmetric "uplink paced / downlink bare-tokio"
    // signature. Each direction holds its own RNG (StdRng::from_entropy)
    // so up- and down-stream jitter samples are independent rather than
    // mirroring each other.
    let uplink = async {
        let bytes =
            policy::copy_with_policy(&mut local_read, &mut tls_write, session_profile).await?;
        tls_write.shutdown().await?;
        std::io::Result::Ok(bytes)
    };
    let downlink = async {
        let bytes =
            policy::copy_with_policy(&mut tls_read, &mut local_write, session_profile).await?;
        local_write.shutdown().await?;
        std::io::Result::Ok(bytes)
    };
    if let Err(err) = tokio::try_join!(uplink, downlink) {
        let err = anyhow::Error::from(err);
        #[cfg(unix)]
        if local_session_aborted_fd(local_fd) {
            return Ok(());
        }
        if benign_io_close(&err) {
            return Ok(());
        }
        return Err(err);
    }
    Ok(())
}

#[cfg(test)]
mod half_close_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::direct::direct_profile_family_for_time;

    #[test]
    fn quic_refusal_has_a_typed_kind_without_claiming_tcp_unreachable() {
        let closed = |code| {
            quinn::ConnectionError::ConnectionClosed(quinn::ConnectionClose {
                error_code: code,
                frame_type: None,
                reason: bytes::Bytes::from_static(b"synthetic private reason"),
            })
        };
        // An outer generic IO wrapper must not hide the typed QUIC reason.
        let error = anyhow::Error::new(std::io::Error::other(closed(
            quinn::TransportErrorCode::CONNECTION_REFUSED,
        )))
        .context("QUIC opening");
        assert_eq!(
            anyhow_error_kind_code(&error),
            Some("quic_connection_refused")
        );
        assert!(
            !is_endpoint_unreachable_error(&error),
            "a QUIC refusal does not prove other TCP families unreachable"
        );
        let other = anyhow::Error::new(closed(quinn::TransportErrorCode::INTERNAL_ERROR));
        assert_eq!(
            anyhow_error_kind_code(&other),
            None,
            "other protocol close codes must not be labelled refused"
        );
    }

    #[test]
    fn quic_timeout_has_a_closed_kind_without_tcp_reachability_claim() {
        let direct = anyhow::Error::new(quinn::ConnectionError::TimedOut);
        assert_eq!(anyhow_error_kind_code(&direct), Some("quic_timed_out"));
        let wrapped = anyhow::Error::new(std::io::Error::other(quinn::ConnectionError::TimedOut))
            .context("QUIC opening");
        assert_eq!(anyhow_error_kind_code(&wrapped), Some("quic_timed_out"));
        assert!(!is_endpoint_unreachable_error(&wrapped));
    }

    #[tokio::test]
    async fn relay_timeout_preserves_machine_kind_and_error_chain() {
        let elapsed = tokio::time::timeout(std::time::Duration::ZERO, std::future::pending::<()>())
            .await
            .expect_err("pending future must time out");
        let err = anyhow::Error::new(elapsed).context("connect grpc relay test.example:443");

        assert_eq!(anyhow_error_kind_code(&err), Some("timed_out"));
        assert!(
            is_endpoint_unreachable_error(&err),
            "connect timeout must short-circuit the remaining TCP transports on this endpoint"
        );
        assert_eq!(
            anyhow_error_chain_messages(&err),
            vec![
                "connect grpc relay test.example:443".to_string(),
                "deadline has elapsed".to_string(),
            ]
        );
        let (message, error_kind, error_chain) =
            relay_terminal_error_details(Some(err), "relay failed");
        assert_eq!(error_kind, Some("timed_out"));
        assert_eq!(
            error_chain,
            vec![
                "connect grpc relay test.example:443".to_string(),
                "deadline has elapsed".to_string(),
            ]
        );
        assert_eq!(
            message,
            "connect grpc relay test.example:443: deadline has elapsed"
        );
    }

    #[tokio::test]
    async fn relay_unreachable_io_kinds_preserve_machine_codes_and_fast_fail() {
        for (kind, expected) in [
            (
                std::io::ErrorKind::NetworkUnreachable,
                "network_unreachable",
            ),
            (std::io::ErrorKind::HostUnreachable, "host_unreachable"),
        ] {
            let err = anyhow::Error::new(std::io::Error::from(kind));
            assert_eq!(anyhow_error_kind_code(&err), Some(expected));
            assert!(is_endpoint_unreachable_error(&err));
        }

        let wrapped =
            std::io::Error::other(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
        let err = anyhow::Error::new(wrapped).context("outer transport wrapper");
        assert_eq!(
            anyhow_error_kind_code(&err),
            Some("connection_refused"),
            "a generic outer io error must not hide a specific nested endpoint cause"
        );
        assert!(is_endpoint_unreachable_error(&err));

        let elapsed = tokio::time::timeout(std::time::Duration::ZERO, std::future::pending::<()>())
            .await
            .expect_err("pending future must time out");
        let wrapped = std::io::Error::other(elapsed);
        let err = anyhow::Error::new(wrapped).context("outer transport wrapper");
        assert_eq!(anyhow_error_kind_code(&err), Some("timed_out"));
        assert!(is_endpoint_unreachable_error(&err));
    }

    // Relay-outcome classifier (brick 3a): byte counts separate a genuine success
    // from a clean session with no application traffic. Ok+return-data ->
    // Success; Ok+nothing-sent -> Unknown (not learned); Err(refused) ->
    // RemoteRefused via the shared model.
    #[test]
    fn classify_relay_attempt_uses_bytes_to_detect_block() {
        use aegis_core::signals::FailSignal;
        use std::time::Duration;
        let to = Duration::from_secs(20);
        let dt = Duration::from_millis(5);
        let ok: anyhow::Result<()> = Ok(());
        // carried return data -> success
        assert!(matches!(
            classify_relay_attempt(&ok, 100, 200, dt, to),
            FailSignal::Success
        ));
        // clean empty session supplies no failure evidence
        assert!(matches!(
            classify_relay_attempt(&ok, 0, 0, dt, to),
            FailSignal::Unknown
        ));
        let refused: anyhow::Result<()> = Err(anyhow::Error::new(std::io::Error::from(
            std::io::ErrorKind::ConnectionRefused,
        )));
        assert!(matches!(
            classify_relay_attempt(&refused, 0, 0, dt, to),
            FailSignal::RemoteRefused
        ));
    }

    #[test]
    fn tcp_terminal_evidence_agrees_with_classifier_without_changing_result() {
        use aegis_core::signals::FailSignal;
        use std::time::Duration;

        for (sent, received, expected) in [
            (0, 0, RelayTcpCompletion::NoResponseObserved),
            (7, 0, RelayTcpCompletion::NoResponseObserved),
            (0, 9, RelayTcpCompletion::ResponseObserved),
            (7, 9, RelayTcpCompletion::ResponseObserved),
        ] {
            let result = Ok(());
            let outcome = RelayOutcome {
                transport: TunnelTransportFamily::GrpcStream,
                signal: classify_relay_attempt(
                    &result,
                    sent,
                    received,
                    Duration::from_millis(1),
                    Duration::from_secs(1),
                ),
                learning: if sent == 0 && received == 0 {
                    RelayLearningDisposition::NoApplicationTraffic
                } else {
                    RelayLearningDisposition::Recordable
                },
                bytes_sent: sent,
                bytes_received_observed: received,
                timing: RelayAttemptTiming {
                    attempt_duration: Duration::from_millis(1),
                    ..Default::default()
                },
            };
            assert_eq!(
                RelayTcpCompletion::from_result(&result, Some(&outcome)),
                expected
            );
            assert_eq!(outcome.signal.is_success(), received > 0);
            assert!(
                result.is_ok(),
                "telemetry must not change retry/replay control flow"
            );
        }
        assert_eq!(
            RelayTcpCompletion::from_result(&Ok(()), None),
            RelayTcpCompletion::NoAttemptObserved
        );
        let partial = RelayOutcome {
            transport: TunnelTransportFamily::GrpcStream,
            signal: FailSignal::RemoteReset,
            learning: RelayLearningDisposition::Recordable,
            bytes_sent: 7,
            bytes_received_observed: 9,
            timing: RelayAttemptTiming {
                attempt_duration: Duration::from_millis(1),
                ..Default::default()
            },
        };
        assert_eq!(
            RelayTcpCompletion::from_result(
                &Err(anyhow::anyhow!("partial fixture error")),
                Some(&partial)
            ),
            RelayTcpCompletion::Failed
        );
    }

    #[tokio::test]
    async fn tcp_terminal_producer_suppresses_unverified_success_and_recovery() {
        use crate::runtime_events::RuntimeEventCode;
        use crate::tests::{ensure_runtime_jsonl_path, read_jsonl_records, RUNTIME_JSONL_LOCK};
        use aegis_core::signals::FailSignal;

        let _guard = RUNTIME_JSONL_LOCK.lock().await;
        let path = ensure_runtime_jsonl_path();
        let settings = sample_relay_settings();
        for (sent, received, signal) in [
            (0, 0, FailSignal::Unknown),
            (
                7,
                0,
                FailSignal::SessionFreeze {
                    bytes_before_stall: 7,
                },
            ),
            (7, 9, FailSignal::Success),
        ] {
            let outcome = RelayOutcome {
                transport: TunnelTransportFamily::GrpcStream,
                signal,
                learning: if sent == 0 && received == 0 {
                    RelayLearningDisposition::NoApplicationTraffic
                } else {
                    RelayLearningDisposition::Recordable
                },
                bytes_sent: sent,
                bytes_received_observed: received,
                timing: RelayAttemptTiming {
                    attempt_duration: Duration::from_millis(1),
                    ..Default::default()
                },
            };
            let start = read_jsonl_records(path).len();
            events::emit_relay_tcp_session_terminal(
                RelayTransportFailureContext {
                    session_kind: "tcp_tunnel",
                    target: Some("a03-terminal-fixture"),
                    port: Some(443),
                    settings: &settings,
                    attempt_index: 2,
                    attempts_total: 2,
                    planned_transports: &[],
                },
                Some(&outcome),
                None,
                None,
            );
            events::emit_relay_failover_recovery_observed(
                &settings,
                None,
                "prior-fixture",
                1,
                1,
                &outcome,
            );
            let records = read_jsonl_records(path);
            let records = &records[start..];
            let success = received > 0;
            let expected = if success {
                RuntimeEventCode::RelaySessionSucceeded
            } else {
                RuntimeEventCode::RelaySessionCompleted
            };
            assert_eq!(records.len(), if success { 2 } else { 1 });
            assert_eq!(records[0]["event_code"], expected.as_str());
            assert_eq!(
                records[0]["fields"]["application_response_observed"],
                success
            );
            assert_eq!(records[0]["fields"]["bytes_received_observed"], received);
            assert_eq!(
                records[0]["fields"]["classifier_signal"],
                json!(outcome.signal)
            );
            if success {
                assert_eq!(records[1]["event_code"], "relay_failover_recovery_observed");
            }
        }
    }

    #[tokio::test]
    async fn udp_response_success_does_not_require_tcp_byte_evidence() {
        use crate::tests::{ensure_runtime_jsonl_path, read_jsonl_records, RUNTIME_JSONL_LOCK};

        let _guard = RUNTIME_JSONL_LOCK.lock().await;
        let path = ensure_runtime_jsonl_path();
        let start = read_jsonl_records(path).len();
        // An empty UDP response is still a response message. Its producer has
        // no TCP byte counters and must retain the established event contract.
        emit_relay_session_succeeded(
            "udp_datagram_once",
            &sample_relay_settings(),
            Some("a03-udp-fixture"),
            Some(53),
            &[],
            TunnelTransportFamily::GrpcDatagram,
            1,
            1,
            None,
            None,
            None,
        );
        let records = read_jsonl_records(path);
        assert_eq!(records.len() - start, 1);
        assert_eq!(records[start]["event_code"], "relay_session_succeeded");
        assert_eq!(
            records[start]["fields"]["relay_session_kind"],
            "udp_datagram_once"
        );
        assert!(records[start]["fields"]
            .get("bytes_received_observed")
            .is_none());
    }

    #[tokio::test]
    async fn cancelled_tcp_attempt_cannot_emit_success_or_recovery() {
        use crate::tests::{ensure_runtime_jsonl_path, read_jsonl_records, RUNTIME_JSONL_LOCK};
        use std::time::Duration;

        let _guard = RUNTIME_JSONL_LOCK.lock().await;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let path = ensure_runtime_jsonl_path();
        let start = read_jsonl_records(path).len();
        tokio::time::timeout(Duration::from_secs(15), async {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("relay fixture bind");
            let app_listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("app fixture bind");
            let _peer = TcpStream::connect(app_listener.local_addr().expect("app fixture address"))
                .await
                .expect("app fixture connect");
            let (local, _) = app_listener.accept().await.expect("app fixture accept");
            let mut settings = sample_relay_settings();
            settings.server = listener
                .local_addr()
                .expect("relay fixture address")
                .to_string();
            // Keep cancellation after a real dial under each admitted feature contract.
            #[cfg(feature = "legacy-challenge-v1")]
            let family = TunnelTransportFamily::LegacyTls;
            #[cfg(not(feature = "legacy-challenge-v1"))]
            let family = TunnelTransportFamily::GrpcStream;
            settings.transport_priority = vec![family];
            settings.tls_backend = aegis_core::RelayTlsBackend::Rustls;
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            let session = tokio::spawn(async move {
                run_relay_tunnel(
                    local,
                    &settings,
                    "cancelled-fixture".into(),
                    443,
                    None,
                    None,
                    Some(&tx),
                )
                .await
            });
            let (mut transport_peer, _) =
                listener.accept().await.expect("relay attempt reached peer");
            session.abort();
            assert!(session.await.expect_err("cancelled session").is_cancelled());
            assert!(
                rx.recv().await.is_none(),
                "cancelled attempt must not invent a Brain outcome"
            );
            tokio::io::copy(&mut transport_peer, &mut tokio::io::sink())
                .await
                .expect("cancelled relay socket closes");
        })
        .await
        .expect("bounded cancellation fixture");
        let records = read_jsonl_records(path);
        for code in [
            "relay_session_succeeded",
            "relay_failover_recovery_observed",
        ] {
            assert!(!records
                .iter()
                .skip(start)
                .any(|record| record["event_code"] == code));
        }
    }

    #[test]
    fn classify_relay_attempt_treats_app_layer_reject_as_block() {
        use aegis_core::signals::FailSignal;
        use std::time::Duration;
        let to = Duration::from_secs(20);
        let dt = Duration::from_millis(5);

        // App-layer / tunnel-handshake rejection: a plain (non-io) error, fast (well
        // under the timeout), with no bytes carried — the shape of a relay endpoint
        // answering the tunnel handshake with a non-upgrade HTTP response
        // (404 / block-page / decoy). Must be a real block signal so the Brain can
        // demote the transport, NOT the near-neutral `Unknown` it used to bottom out
        // at (which left brick 2 inert against L7 blocking).
        let app_reject: anyhow::Result<()> = Err(anyhow::anyhow!(
            "relay handshake: unexpected HTTP status 404 (expected 101)"
        ));
        assert!(
            matches!(
                classify_relay_attempt(&app_reject, 0, 0, dt, to),
                FailSignal::HandshakeMismatch
            ),
            "app-layer relay reject must classify as a block, not Unknown"
        );

        // Guard: if the transport actually carried return data before the odd close,
        // the pre-data reclassification must NOT fire (no false demotion of a
        // transport that was working).
        let late_odd: anyhow::Result<()> = Err(anyhow::anyhow!("odd close after data"));
        assert!(!matches!(
            classify_relay_attempt(&late_odd, 128, 256, dt, to),
            FailSignal::HandshakeMismatch
        ));
    }

    // Forced-IPv4 relay dial (active under full-wide-tun): a relay endpoint that
    // resolves only to IPv6 must be refused fail-closed rather than dialed over
    // IPv6 (which would loop the tun capture). Uses a literal v6 so no network
    // resolution happens; force=true is benign for other tests (they dial v4
    // loopback). Linux-gated because set_relay_force_ipv4 is Linux-only.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn connect_relay_tcp_refuses_ipv6_when_force_ipv4() {
        set_relay_force_ipv4(true);
        let err = connect_relay_tcp("[::1]:9")
            .await
            .expect_err("IPv6-only relay must be refused while forced to IPv4");
        assert_eq!(err.kind(), std::io::ErrorKind::AddrNotAvailable);
        set_relay_force_ipv4(false); // reset the process-global for other tests
    }
    use http::HeaderMap;
    use std::collections::{BTreeMap, BTreeSet};
    use tokio::net::TcpListener;

    fn sample_relay_settings() -> RelaySettings {
        RelaySettings {
            server: "127.0.0.1:8443".into(),
            server_name: "localhost".into(),
            auth_token: "token".into(),
            ..RelaySettings::default()
        }
    }

    #[test]
    fn soft_wire_plan_only_sampled_when_mode_is_soft_wire_socket_options() {
        let mut settings = sample_relay_settings();
        settings.wire_mimicry_mode = aegis_core::WireMimicryMode::Disabled;
        assert!(
            policy::relay_soft_wire_plan(&settings, Some(("example.com", 443)), 10_000).is_none()
        );

        settings.wire_mimicry_mode = aegis_core::WireMimicryMode::LinuxExperimentalTtlPreface;
        assert!(
            policy::relay_soft_wire_plan(&settings, Some(("example.com", 443)), 10_000).is_none()
        );

        settings.wire_mimicry_mode = aegis_core::WireMimicryMode::SoftWireSocketOptions;
        let plan = policy::relay_soft_wire_plan(&settings, Some(("example.com", 443)), 10_000)
            .expect("soft wire plan present");
        assert!(matches!(plan.ip_ttl, 62 | 64 | 96 | 128));
        assert!(
            !plan.applied,
            "applied is set by the apply call, not from_seed"
        );
    }

    #[test]
    fn soft_wire_plan_varies_across_targets_inside_same_epoch() {
        let mut settings = sample_relay_settings();
        settings.wire_mimicry_mode = aegis_core::WireMimicryMode::SoftWireSocketOptions;
        let mut ttls = std::collections::HashSet::new();
        let mut nodelays = std::collections::HashSet::new();
        for port in 1..=64u16 {
            let plan = policy::relay_soft_wire_plan(&settings, Some(("example.com", port)), 10_000)
                .expect("plan present");
            ttls.insert(plan.ip_ttl);
            nodelays.insert(plan.nodelay);
        }
        assert!(
            ttls.len() >= 2,
            "expected multiple TTL values across targets, got {ttls:?}"
        );
        assert!(
            nodelays.len() >= 2,
            "expected both nodelay polarities across targets, got {nodelays:?}"
        );
    }

    #[test]
    fn relay_transport_authority_keeps_sni_for_dns_names() {
        let settings = sample_relay_settings();
        let authority = relay_transport_authority(&settings).expect("dns authority");
        assert!(authority.send_sni);
        assert_eq!(authority.authority_host, "localhost");
        assert!(matches!(authority.tls_server_name, ServerName::DnsName(_)));
    }

    #[test]
    fn relay_transport_authority_disables_sni_for_ip_authority() {
        let mut settings = sample_relay_settings();
        settings.server_name = "198.51.100.22".into();
        let authority = relay_transport_authority(&settings).expect("ip authority");
        assert!(!authority.send_sni);
        assert_eq!(authority.authority_host, "198.51.100.22");
        assert!(matches!(
            authority.tls_server_name,
            ServerName::IpAddress(_)
        ));
    }

    #[test]
    fn format_authority_host_wraps_ipv6() {
        assert_eq!(format_authority_host("2001:db8::1"), "[2001:db8::1]");
        assert_eq!(format_authority_host("example.org"), "example.org");
    }

    #[test]
    fn tls_connector_can_disable_sni_for_ip_fallback() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let connector = tls_connector(None, None, false).expect("connector");
        assert!(!connector.config().enable_sni);
        let connector = tls_connector(None, None, true).expect("connector");
        assert!(connector.config().enable_sni);
    }

    #[test]
    fn udp_fallback_ready_requires_udp_capable_transport() {
        let mut settings = sample_relay_settings();
        settings.transport_priority = vec![
            TunnelTransportFamily::HttpsWs,
            TunnelTransportFamily::GrpcStream,
            TunnelTransportFamily::LegacyTls,
        ];
        assert!(runtime_fallback_ready(&settings));
        assert!(!runtime_udp_fallback_ready(&settings));
    }

    #[test]
    fn dedicated_udp_transport_plan_keeps_fronted_tcp_grpc_only() {
        let mut settings = sample_relay_settings();
        settings.transport_priority = vec![TunnelTransportFamily::GrpcStream];
        settings.udp_transport_priority = Some(vec![TunnelTransportFamily::MasqueDerived]);

        assert!(runtime_fallback_ready(&settings));
        assert!(runtime_udp_fallback_ready(&settings));
        assert_eq!(
            policy::planned_transport_order(&settings.transport_priority, &settings.policy),
            vec![TunnelTransportFamily::GrpcStream]
        );
        assert_eq!(
            policy::planned_udp_transport_order(
                udp_transport_priority(&settings),
                &settings.policy
            ),
            vec![TunnelTransportFamily::MasqueDerived]
        );
    }

    #[test]
    fn udp_readiness_is_independent_of_tcp_transport_plan() {
        let mut settings = sample_relay_settings();
        settings.transport_priority.clear();
        settings.udp_transport_priority = Some(vec![TunnelTransportFamily::GrpcDatagram]);
        assert!(!runtime_fallback_ready(&settings));
        assert!(runtime_udp_fallback_ready(&settings));
        assert!(!runtime_udp_associate_ready(&settings));

        settings.udp_transport_priority = Some(vec![]);
        settings.transport_priority = vec![TunnelTransportFamily::MasqueDerived];
        assert!(!runtime_udp_fallback_ready(&settings));
        assert!(!runtime_udp_associate_ready(&settings));
    }

    #[test]
    fn udp_readiness_and_dispatch_share_endpoint_pool() {
        let mut settings = sample_relay_settings();
        settings.server.clear();
        settings.server_name.clear();
        settings.transport_priority = vec![TunnelTransportFamily::MasqueDerived];
        settings.endpoints = vec![RelayEndpointSettings {
            server: "127.0.0.1:8443".into(),
            server_name: "localhost".into(),
            masque_server: None,
            masque_server_name: None,
        }];
        assert!(runtime_fallback_ready(&settings));
        assert!(runtime_udp_fallback_ready(&settings));
        assert!(runtime_udp_associate_ready(&settings));
        let attempts = udp_endpoint_attempts(&settings, false);
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].settings.server, "127.0.0.1:8443");

        // An explicit top-level direct override is inherited by both plans.
        settings.masque_server = Some("127.0.0.1:8444".into());
        settings.masque_server_name = Some("localhost".into());
        assert!(runtime_udp_fallback_ready(&settings));
        assert!(runtime_udp_associate_ready(&settings));
    }

    #[test]
    fn udp_readiness_does_not_advertise_ignored_top_level_when_pool_is_unready() {
        let mut settings = sample_relay_settings();
        settings.transport_priority = vec![TunnelTransportFamily::MasqueDerived];
        settings.endpoints = vec![RelayEndpointSettings {
            server: String::new(),
            server_name: String::new(),
            masque_server: None,
            masque_server_name: None,
        }];
        assert!(!runtime_fallback_ready(&settings));
        assert!(!runtime_udp_fallback_ready(&settings));
        assert!(!runtime_udp_associate_ready(&settings));
        // A fully explicit shared UDP dial and authority are still executable.
        settings.masque_server = Some("127.0.0.1:8444".into());
        settings.masque_server_name = Some("localhost".into());
        assert!(runtime_udp_fallback_ready(&settings));
        assert!(runtime_udp_associate_ready(&settings));
    }

    #[test]
    fn udp_pool_deduplicates_shared_direct_leg_preserves_authority_and_order() {
        let mut settings = sample_relay_settings();
        settings.udp_transport_priority = Some(vec![
            TunnelTransportFamily::MasqueDerived,
            TunnelTransportFamily::GrpcDatagram,
        ]);
        settings.policy.rotate_transports_per_session = false;
        settings.policy.max_transport_attempts = 2;
        settings.masque_server = Some("127.0.0.1:8443".into());
        settings.masque_server_name = Some("direct.test".into());
        settings.endpoints = vec![
            RelayEndpointSettings {
                server: "127.0.0.1:4431".into(),
                server_name: "first.test".into(),
                masque_server: None,
                masque_server_name: None,
            },
            RelayEndpointSettings {
                server: "127.0.0.1:4432".into(),
                server_name: "second.test".into(),
                masque_server: None,
                masque_server_name: None,
            },
        ];
        let plan = udp_endpoint_attempts(&settings, false);
        assert_eq!(plan.len(), 3);
        assert_eq!(plan[0].family, TunnelTransportFamily::MasqueDerived);
        assert_eq!(
            plan[0].settings.masque_server_name.as_deref(),
            Some("direct.test")
        );
        assert_eq!(plan[1].settings.server_name, "first.test");
        assert_eq!(plan[2].settings.server_name, "second.test");
        assert_eq!(plan[2].family, TunnelTransportFamily::GrpcDatagram);
        assert!(plan
            .iter()
            .all(|attempt| attempt.settings.endpoints.is_empty()));
        assert_eq!(udp_endpoint_attempts(&settings, true).len(), 1);

        settings.endpoints[1].masque_server = Some("127.0.0.1:8444".into());
        let plan = udp_endpoint_attempts(&settings, true);
        assert_eq!(plan.len(), 2);
        assert_eq!(
            masque::masque_transport_authority(&plan[1].settings)
                .unwrap()
                .authority_host,
            "second.test"
        );
    }

    #[test]
    fn udp_committed_error_preserves_source_and_survives_context_without_replay() {
        let io = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::TimedOut));
        assert!(!udp_payload_was_committed(&io));
        let committed = udp_payload_committed(io).context("response failed");
        assert!(udp_payload_was_committed(&committed));
        assert_eq!(anyhow_error_kind_code(&committed), Some("timed_out"));
        let twice = udp_payload_committed(committed);
        assert_eq!(
            twice
                .chain()
                .filter(|cause| cause.is::<UdpPayloadCommitted>())
                .count(),
            1
        );
    }

    #[test]
    fn udp_pool_global_dial_keeps_global_implicit_authority() {
        let mut settings = sample_relay_settings();
        settings.server_name = "origin.test".into();
        settings.masque_server = Some("127.0.0.1:8443".into());
        settings.masque_server_name = None;
        settings.udp_transport_priority = Some(vec![TunnelTransportFamily::MasqueDerived]);
        settings.endpoints = ["first-front.test", "second-front.test"]
            .into_iter()
            .map(|name| RelayEndpointSettings {
                server: "127.0.0.1:443".into(),
                server_name: name.into(),
                masque_server: None,
                masque_server_name: None,
            })
            .collect();
        let plan = udp_endpoint_attempts(&settings, false);
        assert_eq!(plan.len(), 1);
        assert_eq!(
            masque::masque_transport_authority(&plan[0].settings)
                .unwrap()
                .authority_host,
            "origin.test"
        );
    }

    #[test]
    fn udp_pool_deduplicates_effective_not_raw_empty_authority() {
        let mut settings = sample_relay_settings();
        settings.udp_transport_priority = Some(vec![TunnelTransportFamily::MasqueDerived]);
        settings.endpoints = ["first.test", "second.test"]
            .into_iter()
            .map(|name| RelayEndpointSettings {
                server: "127.0.0.1:443".into(),
                server_name: name.into(),
                masque_server: Some("127.0.0.1:8443".into()),
                masque_server_name: Some(String::new()),
            })
            .collect();
        let plan = udp_endpoint_attempts(&settings, false);
        assert_eq!(plan.len(), 2);
        assert_eq!(
            masque::masque_transport_authority(&plan[1].settings)
                .unwrap()
                .authority_host,
            "second.test"
        );
    }

    #[test]
    fn udp_pool_invalid_global_authority_cannot_borrow_tcp_identity() {
        let mut settings = sample_relay_settings();
        settings.server_name.clear();
        settings.masque_server = Some("127.0.0.1:8443".into());
        settings.masque_server_name = None;
        settings.udp_transport_priority = Some(vec![TunnelTransportFamily::MasqueDerived]);
        settings.endpoints = vec![RelayEndpointSettings {
            server: "127.0.0.1:443".into(),
            server_name: "front.test".into(),
            masque_server: None,
            masque_server_name: None,
        }];
        assert!(!runtime_udp_fallback_ready(&settings));
        assert!(!runtime_udp_associate_ready(&settings));
        settings.udp_transport_priority = Some(vec![TunnelTransportFamily::GrpcDatagram]);
        assert!(
            runtime_udp_fallback_ready(&settings),
            "TCP/H2 pool identity is independently valid"
        );
    }

    #[test]
    fn udp_pool_preserves_explicit_policy_retries_but_not_incidental_pool_duplicates() {
        let mut settings = sample_relay_settings();
        settings.masque_server = Some("127.0.0.1:8443".into());
        settings.masque_server_name = Some("direct.test".into());
        settings.udp_transport_priority = Some(vec![TunnelTransportFamily::MasqueDerived; 2]);
        settings.policy.rotate_transports_per_session = false;
        settings.policy.max_transport_attempts = 2;
        settings.endpoints = ["first.test", "second.test"]
            .into_iter()
            .map(|name| RelayEndpointSettings {
                server: "127.0.0.1:443".into(),
                server_name: name.into(),
                masque_server: None,
                masque_server_name: None,
            })
            .collect();
        let plan = udp_endpoint_attempts(&settings, false);
        assert_eq!(
            plan.len(),
            2,
            "two explicit slots, not four incidental attempts"
        );
        assert!(plan
            .iter()
            .all(|attempt| attempt.family == TunnelTransportFamily::MasqueDerived));
    }

    #[test]
    fn udp_associate_filters_fixed_target_grpc_before_attempt_budget() {
        let mut settings = sample_relay_settings();
        settings.udp_transport_priority = Some(vec![
            TunnelTransportFamily::GrpcDatagram,
            TunnelTransportFamily::MasqueDerived,
        ]);
        settings.policy.max_transport_attempts = 1;
        assert_eq!(
            planned_fixed_udp_transports(&settings),
            vec![TunnelTransportFamily::GrpcDatagram]
        );
        assert_eq!(
            planned_udp_associate_transports(&settings),
            vec![TunnelTransportFamily::MasqueDerived]
        );
        assert!(runtime_udp_associate_ready(&settings));

        settings.udp_transport_priority = Some(vec![TunnelTransportFamily::GrpcDatagram]);
        assert!(runtime_udp_fallback_ready(&settings));
        assert!(!runtime_udp_associate_ready(&settings));
        assert!(planned_udp_associate_transports(&settings).is_empty());
    }

    #[test]
    fn udp_readiness_requires_actual_masque_address_authority_and_auth() {
        let mut settings = sample_relay_settings();
        settings.udp_transport_priority = Some(vec![TunnelTransportFamily::MasqueDerived]);
        settings.masque_server = Some("relay.example.invalid:8443".into());
        assert!(!runtime_udp_fallback_ready(&settings));
        assert!(!runtime_udp_associate_ready(&settings));

        settings.masque_server = Some("[::1]:8443".into());
        settings.masque_server_name = Some("bad authority/".into());
        assert!(!runtime_udp_associate_ready(&settings));
        settings.masque_server_name = Some("localhost".into());
        assert!(runtime_udp_fallback_ready(&settings));
        assert!(runtime_udp_associate_ready(&settings));
        settings.auth_token = "  ".into();
        assert!(!runtime_udp_fallback_ready(&settings));
        assert!(!runtime_udp_associate_ready(&settings));
    }

    #[test]
    fn fallback_ready_requires_any_transport_attempt() {
        let mut settings = sample_relay_settings();
        settings.transport_priority = vec![];
        assert!(!runtime_fallback_ready(&settings));
        assert!(!runtime_udp_fallback_ready(&settings));
    }

    #[test]
    fn fallback_ready_accepts_configured_relay_endpoint_pool() {
        let mut settings = sample_relay_settings();
        settings.server.clear();
        settings.server_name.clear();
        settings.endpoints = vec![RelayEndpointSettings {
            server: "relay-a.example.org:443".into(),
            server_name: "relay-a.example.org".into(),
            masque_server: Some("relay-a.example.org:443".into()),
            masque_server_name: None,
        }];
        assert!(runtime_fallback_ready(&settings));
        let endpoints = effective_relay_endpoints(&settings);
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].server, "relay-a.example.org:443");
        assert_eq!(endpoints[0].server_name, "relay-a.example.org");
    }

    #[test]
    fn endpoint_pool_inherits_global_direct_masque_override() {
        let mut settings = sample_relay_settings();
        settings.masque_server = Some("203.0.113.10:443".into());
        settings.masque_server_name = Some("masque-a.example.org".into());
        settings.endpoints = vec![RelayEndpointSettings {
            server: "front-a.example.org:443".into(),
            server_name: "front-a.example.org".into(),
            masque_server: None,
            masque_server_name: None,
        }];

        let endpoints = effective_relay_endpoints(&settings);
        let selected = relay_settings_for_endpoint(&settings, &endpoints[0]);
        assert_eq!(selected.server, "front-a.example.org:443");
        assert_eq!(selected.masque_server.as_deref(), Some("203.0.113.10:443"));
        assert_eq!(
            selected.masque_server_name.as_deref(),
            Some("masque-a.example.org")
        );
    }

    #[test]
    fn endpoint_specific_masque_override_wins_over_global_default() {
        let mut settings = sample_relay_settings();
        settings.masque_server = Some("203.0.113.10:443".into());
        settings.endpoints = vec![RelayEndpointSettings {
            server: "front-b.example.org:443".into(),
            server_name: "front-b.example.org".into(),
            masque_server: Some("203.0.113.11:443".into()),
            masque_server_name: Some("masque-b.example.org".into()),
        }];

        let endpoints = effective_relay_endpoints(&settings);
        let selected = relay_settings_for_endpoint(&settings, &endpoints[0]);
        assert_eq!(selected.masque_server.as_deref(), Some("203.0.113.11:443"));
        assert_eq!(
            selected.masque_server_name.as_deref(),
            Some("masque-b.example.org")
        );
    }

    #[test]
    fn fallback_ready_rejects_empty_relay_endpoint_pool() {
        let mut settings = sample_relay_settings();
        settings.server.clear();
        settings.server_name.clear();
        settings.endpoints = vec![RelayEndpointSettings {
            server: "   ".into(),
            server_name: "".into(),
            masque_server: None,
            masque_server_name: None,
        }];
        assert!(!runtime_fallback_ready(&settings));
    }

    #[test]
    fn udp_fallback_ready_keeps_masque_after_attempt_filtering() {
        let mut settings = sample_relay_settings();
        settings.transport_priority = vec![
            TunnelTransportFamily::HttpsWs,
            TunnelTransportFamily::MasqueDerived,
            TunnelTransportFamily::LegacyTls,
        ];
        settings.policy.max_transport_attempts = 1;
        assert!(runtime_udp_fallback_ready(&settings));
    }

    #[tokio::test]
    async fn native_udp_datagram_requires_udp_capable_transport() {
        let mut settings = sample_relay_settings();
        settings.transport_priority = vec![
            TunnelTransportFamily::HttpsWs,
            TunnelTransportFamily::GrpcStream,
            TunnelTransportFamily::LegacyTls,
        ];
        let err = run_relay_udp_datagram_once(
            &settings,
            crate::socks5::ConnectTarget {
                host: "1.1.1.1".into(),
                port: 53,
            },
            &[0x01, 0x02],
        )
        .await
        .expect_err("native UDP datagram should require UDP-capable transport");
        assert!(err
            .to_string()
            .contains("no UDP-capable transport configured"));
        let terminal = err
            .downcast_ref::<RelayTerminalFailure>()
            .expect("relay terminal failure");
        assert_eq!(terminal.attempts_total, 0);
        assert!(terminal.planned_transports.is_empty());
        assert!(terminal.last_transport.is_none());
    }

    #[tokio::test]
    async fn udp_associate_requires_udp_capable_transport() {
        let mut settings = sample_relay_settings();
        settings.transport_priority = vec![
            TunnelTransportFamily::HttpsWs,
            TunnelTransportFamily::GrpcStream,
            TunnelTransportFamily::LegacyTls,
        ];
        let udp_socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind udp socket");
        let err = run_relay_udp_associate(
            UdpSessionControl::Detached,
            udp_socket,
            &settings,
            "127.0.0.1".parse().expect("client ip"),
        )
        .await
        .expect_err("udp associate should require UDP-capable transport");
        assert!(err
            .to_string()
            .contains("no UDP-capable transport configured"));
        let terminal = err
            .downcast_ref::<RelayTerminalFailure>()
            .expect("relay terminal failure");
        assert!(terminal.target.is_none());
        assert!(terminal.port.is_none());
        assert_eq!(terminal.attempts_total, 0);
        assert!(terminal.planned_transports.is_empty());
        assert!(terminal.last_transport.is_none());
    }

    #[tokio::test]
    async fn grpc_only_udp_associate_returns_typed_terminal_before_dispatch() {
        let mut settings = sample_relay_settings();
        settings.udp_transport_priority = Some(vec![TunnelTransportFamily::GrpcDatagram]);
        let udp_socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("fixture socket");
        let err = run_relay_udp_associate(
            UdpSessionControl::Detached,
            udp_socket,
            &settings,
            "127.0.0.1".parse().expect("loopback"),
        )
        .await
        .expect_err("fixed-destination gRPC must not enter ASSOCIATE dispatch");
        let terminal = err
            .downcast_ref::<RelayTerminalFailure>()
            .expect("typed terminal");
        assert_eq!(terminal.attempts_total, 0);
        assert!(terminal.planned_transports.is_empty());
        assert!(terminal.last_transport.is_none());
    }

    #[tokio::test]
    async fn closed_local_peer_skips_relay_transport_attempts() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let peer = TcpStream::connect(addr).await.expect("connect peer");
        let (local, _) = listener.accept().await.expect("accept local");
        drop(peer);
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;

        let mut settings = sample_relay_settings();
        settings.server = "127.0.0.1:1".into();
        settings.transport_priority = vec![TunnelTransportFamily::LegacyTls];

        run_relay_tunnel(local, &settings, "127.0.0.1".into(), 443, None, None, None)
            .await
            .expect("closed local peer should skip relay attempts");
    }

    #[tokio::test]
    async fn local_session_aborted_detects_closed_peer() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let peer = TcpStream::connect(addr).await.expect("connect peer");
        let (local, _) = listener.accept().await.expect("accept local");
        drop(peer);
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;

        assert!(local_session_aborted(&local));
    }

    #[test]
    fn relay_failure_scope_distinguishes_tunnel_target_error() {
        let err = tunnel_response_error(
            "relay error",
            TunnelStatus::BadTarget,
            "connect 127.0.0.1:443: refused".into(),
        );
        assert_eq!(relay_failure_scope(&err), "tunnel_level_target_error");
        assert_eq!(relay_tunnel_status_from_error(&err), Some("bad_target"));
    }

    #[test]
    fn relay_failure_scope_keeps_benign_io_separate_from_outage() {
        let benign = anyhow::Error::from(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "peer closed",
        ));
        let outage = anyhow::Error::from(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out",
        ));

        assert_eq!(relay_failure_scope(&benign), "benign_session_end");
        assert_eq!(relay_failure_scope(&outage), "real_transport_outage");
    }

    #[test]
    fn transport_camouflage_headers_include_optional_variants() {
        let profile = policy::RelaySessionProfile {
            transport_order: vec![TunnelTransportFamily::HttpsWs],
            websocket_path: "/ws".into(),
            grpc_path: "/rpc".into(),
            masque_path: "/.well-known/masque/udp".into(),
            user_agent: "Mozilla/5.0",
            accept_header: "*/*",
            accept_language_header: Some("en-US,en;q=0.9"),
            cache_control_header: Some("max-age=0"),
            websocket_origin_header: Some("https://localhost".into()),
            grpc_accept_encoding_header: Some("identity"),
            grpc_encoding_header: Some("identity"),
            grpc_timeout_header: Some("15S"),
            grpc_message_type_header: Some("TunnelRequest"),
            masque_alt_used_header: Some("localhost".into()),
            tls_profile_target_class: Some("https_ws".into()),
            write_chunk_size: 1024,
            inter_chunk_delay_ms: 0,
            inter_chunk_jitter_ms_window: 0,
            surface_chunk_size_range: (0, 0),
            surface_delay_ms_range: (0, 0),
            surface_bias_applied: false,
            padding_probability_milli: 0,
            padding_split_ratio_milli_range: (0, 0),
            profile_id: "test",
        };
        let mut headers = HeaderMap::new();
        apply_transport_camouflage_headers(&mut headers, &profile).expect("insert headers");
        assert_eq!(headers["user-agent"], "Mozilla/5.0");
        assert_eq!(headers["accept"], "*/*");
        assert_eq!(headers["accept-language"], "en-US,en;q=0.9");
        assert_eq!(headers["cache-control"], "max-age=0");
    }

    #[test]
    fn websocket_request_shape_adds_origin_when_profile_requests_it() {
        let profile = policy::RelaySessionProfile {
            transport_order: vec![TunnelTransportFamily::HttpsWs],
            websocket_path: "/ws".into(),
            grpc_path: "/rpc".into(),
            masque_path: "/.well-known/masque/udp".into(),
            user_agent: "Mozilla/5.0",
            accept_header: "*/*",
            accept_language_header: Some("en-US,en;q=0.9"),
            cache_control_header: None,
            websocket_origin_header: Some("https://localhost".into()),
            grpc_accept_encoding_header: None,
            grpc_encoding_header: None,
            grpc_timeout_header: None,
            grpc_message_type_header: None,
            masque_alt_used_header: None,
            tls_profile_target_class: None,
            write_chunk_size: 1024,
            inter_chunk_delay_ms: 0,
            inter_chunk_jitter_ms_window: 0,
            surface_chunk_size_range: (0, 0),
            surface_delay_ms_range: (0, 0),
            surface_bias_applied: false,
            padding_probability_milli: 0,
            padding_split_ratio_milli_range: (0, 0),
            profile_id: "test",
        };
        let mut headers = HeaderMap::new();
        apply_websocket_request_shape_headers(&mut headers, &profile).expect("insert headers");
        assert_eq!(headers["origin"], "https://localhost");
        assert_eq!(headers["user-agent"], "Mozilla/5.0");
    }

    #[test]
    fn grpc_request_shape_adds_identity_metadata_when_enabled() {
        let profile = policy::RelaySessionProfile {
            transport_order: vec![TunnelTransportFamily::GrpcStream],
            websocket_path: "/ws".into(),
            grpc_path: "/rpc".into(),
            masque_path: "/.well-known/masque/udp".into(),
            user_agent: "Mozilla/5.0",
            accept_header: "*/*",
            accept_language_header: Some("en-US,en;q=0.9"),
            cache_control_header: None,
            websocket_origin_header: None,
            grpc_accept_encoding_header: Some("identity"),
            grpc_encoding_header: Some("identity"),
            grpc_timeout_header: Some("15S"),
            grpc_message_type_header: Some("TunnelRequest"),
            masque_alt_used_header: None,
            tls_profile_target_class: None,
            write_chunk_size: 1024,
            inter_chunk_delay_ms: 0,
            inter_chunk_jitter_ms_window: 0,
            surface_chunk_size_range: (0, 0),
            surface_delay_ms_range: (0, 0),
            surface_bias_applied: false,
            padding_probability_milli: 0,
            padding_split_ratio_milli_range: (0, 0),
            profile_id: "test",
        };
        let mut headers = HeaderMap::new();
        apply_grpc_request_shape_headers(&mut headers, &profile).expect("insert headers");
        assert_eq!(headers["grpc-accept-encoding"], "identity");
        assert_eq!(headers["grpc-encoding"], "identity");
        assert_eq!(headers["grpc-timeout"], "15S");
        assert_eq!(headers["grpc-message-type"], "TunnelRequest");
        assert_eq!(headers["user-agent"], "Mozilla/5.0");
    }

    #[test]
    fn relay_surface_fields_include_request_shape_variants() {
        let profile = policy::RelaySessionProfile {
            transport_order: vec![TunnelTransportFamily::GrpcStream],
            websocket_path: "/ws".into(),
            grpc_path: "/rpc".into(),
            masque_path: "/.well-known/masque/udp".into(),
            user_agent: "Mozilla/5.0",
            accept_header: "*/*",
            accept_language_header: Some("en-US,en;q=0.9"),
            cache_control_header: Some("max-age=0"),
            websocket_origin_header: Some("https://localhost".into()),
            grpc_accept_encoding_header: Some("identity"),
            grpc_encoding_header: Some("identity"),
            grpc_timeout_header: Some("15S"),
            grpc_message_type_header: Some("TunnelRequest"),
            masque_alt_used_header: Some("localhost".into()),
            tls_profile_target_class: Some("https_ws".into()),
            write_chunk_size: 1024,
            inter_chunk_delay_ms: 0,
            inter_chunk_jitter_ms_window: 0,
            surface_chunk_size_range: (0, 0),
            surface_delay_ms_range: (0, 0),
            surface_bias_applied: false,
            padding_probability_milli: 0,
            padding_split_ratio_milli_range: (0, 0),
            profile_id: "browser_like_balanced",
        };
        let mut fields = json!({});
        maybe_add_relay_surface_fields(&mut fields, Some(&profile));
        assert_eq!(fields["relay_surface_profile_id"], "browser_like_balanced");
        assert_eq!(fields["relay_surface_websocket_path"], "/ws");
        assert_eq!(fields["relay_surface_grpc_path"], "/rpc");
        assert_eq!(
            fields["relay_surface_masque_path"],
            "/.well-known/masque/udp"
        );
        assert_eq!(fields["relay_surface_accept_language"], "en-US,en;q=0.9");
        assert_eq!(fields["relay_surface_cache_control"], "max-age=0");
        assert_eq!(
            fields["relay_surface_websocket_origin"],
            "https://localhost"
        );
        assert_eq!(fields["relay_surface_grpc_accept_encoding"], "identity");
        assert_eq!(fields["relay_surface_grpc_encoding"], "identity");
        assert_eq!(fields["relay_surface_grpc_timeout"], "15S");
        assert_eq!(fields["relay_surface_grpc_message_type"], "TunnelRequest");
        assert_eq!(fields["relay_surface_masque_alt_used"], "localhost");
        assert_eq!(fields["relay_surface_write_chunk_size"], 1024);
        assert_eq!(fields["relay_surface_inter_chunk_delay_ms"], 0);
        assert_eq!(fields["relay_surface_tls_profile_target_class"], "https_ws");
        assert_eq!(
            fields["relay_surface_tls_profile_target_alpn"],
            json!(["h2", "http/1.1"])
        );
    }

    #[test]
    fn masque_request_shape_adds_alt_used_when_profile_requests_it() {
        let profile = policy::RelaySessionProfile {
            transport_order: vec![TunnelTransportFamily::MasqueDerived],
            websocket_path: "/ws".into(),
            grpc_path: "/rpc".into(),
            masque_path: "/.well-known/masque/udp".into(),
            user_agent: "Mozilla/5.0",
            accept_header: "*/*",
            accept_language_header: Some("en-US,en;q=0.9"),
            cache_control_header: None,
            websocket_origin_header: None,
            grpc_accept_encoding_header: None,
            grpc_encoding_header: None,
            grpc_timeout_header: None,
            grpc_message_type_header: None,
            masque_alt_used_header: Some("localhost".into()),
            tls_profile_target_class: Some("masque_derived".into()),
            write_chunk_size: 1024,
            inter_chunk_delay_ms: 0,
            inter_chunk_jitter_ms_window: 0,
            surface_chunk_size_range: (0, 0),
            surface_delay_ms_range: (0, 0),
            surface_bias_applied: false,
            padding_probability_milli: 0,
            padding_split_ratio_milli_range: (0, 0),
            profile_id: "test",
        };
        let mut headers = HeaderMap::new();
        apply_masque_request_shape_headers(&mut headers, &profile).expect("insert headers");
        assert_eq!(headers["alt-used"], "localhost");
        assert_eq!(headers["user-agent"], "Mozilla/5.0");
    }

    #[test]
    fn tls_profile_target_alpn_mapping_covers_primary_transports() {
        assert_eq!(
            tls_profile_target_alpn_value("legacy_tls"),
            json!(["http/1.1"])
        );
        assert_eq!(
            tls_profile_target_alpn_value("https_ws"),
            json!(["h2", "http/1.1"])
        );
        assert_eq!(tls_profile_target_alpn_value("grpc_stream"), json!(["h2"]));
        assert_eq!(
            tls_profile_target_alpn_value("masque_derived"),
            json!(["h3", "masque"])
        );
        assert_eq!(tls_profile_target_alpn_value("unknown"), json!([]));
    }

    #[test]
    fn legacy_tls_wire_alpn_is_opt_in_and_legacy_only() {
        let mut profile = policy::RelaySessionProfile {
            transport_order: vec![TunnelTransportFamily::LegacyTls],
            websocket_path: "/ws".into(),
            grpc_path: "/rpc".into(),
            masque_path: "/.well-known/masque/udp".into(),
            user_agent: "Mozilla/5.0",
            accept_header: "*/*",
            accept_language_header: None,
            cache_control_header: None,
            websocket_origin_header: None,
            grpc_accept_encoding_header: None,
            grpc_encoding_header: None,
            grpc_timeout_header: None,
            grpc_message_type_header: None,
            masque_alt_used_header: None,
            tls_profile_target_class: None,
            write_chunk_size: 1024,
            inter_chunk_delay_ms: 0,
            inter_chunk_jitter_ms_window: 0,
            surface_chunk_size_range: (0, 0),
            surface_delay_ms_range: (0, 0),
            surface_bias_applied: false,
            padding_probability_milli: 0,
            padding_split_ratio_milli_range: (0, 0),
            profile_id: "test",
        };
        // v0.3.8 close-nDPI-anomaly: ALPN is always sent on legacy_tls
        // regardless of profile.tls_profile_target_class — closes the
        // "TLS (probably) Not Carrying HTTPS" heuristic.
        assert_eq!(legacy_tls_wire_alpn(&profile), Some(b"http/1.1".as_slice()));

        profile.tls_profile_target_class = Some("https_ws".into());
        assert_eq!(legacy_tls_wire_alpn(&profile), Some(b"http/1.1".as_slice()));

        profile.tls_profile_target_class = Some("legacy_tls".into());
        assert_eq!(legacy_tls_wire_alpn(&profile), Some(b"http/1.1".as_slice()));
    }

    #[test]
    fn tls_wire_adapter_fields_cover_transport_specific_alpn() {
        let profile = policy::RelaySessionProfile {
            transport_order: vec![TunnelTransportFamily::LegacyTls],
            websocket_path: "/ws".into(),
            grpc_path: "/rpc".into(),
            masque_path: "/.well-known/masque/udp".into(),
            user_agent: "Mozilla/5.0",
            accept_header: "*/*",
            accept_language_header: None,
            cache_control_header: None,
            websocket_origin_header: None,
            grpc_accept_encoding_header: None,
            grpc_encoding_header: None,
            grpc_timeout_header: None,
            grpc_message_type_header: None,
            masque_alt_used_header: None,
            tls_profile_target_class: Some("legacy_tls".into()),
            write_chunk_size: 1024,
            inter_chunk_delay_ms: 0,
            inter_chunk_jitter_ms_window: 0,
            surface_chunk_size_range: (0, 0),
            surface_delay_ms_range: (0, 0),
            surface_bias_applied: false,
            padding_probability_milli: 0,
            padding_split_ratio_milli_range: (0, 0),
            profile_id: "test",
        };

        let mut legacy = json!({});
        maybe_add_tls_wire_adapter_fields(
            &mut legacy,
            TunnelTransportFamily::LegacyTls,
            Some(&profile),
        );
        assert_eq!(
            legacy["relay_surface_tls_wire_adapter"],
            "legacy_tls_target_http11"
        );
        assert_eq!(legacy["relay_surface_tls_wire_alpn"], json!(["http/1.1"]));

        let mut ws = json!({});
        maybe_add_tls_wire_adapter_fields(&mut ws, TunnelTransportFamily::HttpsWs, Some(&profile));
        assert_eq!(
            ws["relay_surface_tls_wire_adapter"],
            "websocket_h2_extended_connect_offer"
        );
        assert_eq!(ws["relay_surface_tls_wire_alpn"], json!(["h2", "http/1.1"]));

        let mut grpc = json!({});
        maybe_add_tls_wire_adapter_fields(
            &mut grpc,
            TunnelTransportFamily::GrpcStream,
            Some(&profile),
        );
        assert_eq!(grpc["relay_surface_tls_wire_adapter"], "grpc_h2_fixed");
        assert_eq!(grpc["relay_surface_tls_wire_alpn"], json!(["h2"]));

        let mut masque = json!({});
        maybe_add_tls_wire_adapter_fields(
            &mut masque,
            TunnelTransportFamily::MasqueDerived,
            Some(&profile),
        );
        assert_eq!(masque["relay_surface_tls_wire_adapter"], "masque_h3_fixed");
        assert_eq!(masque["relay_surface_tls_wire_alpn"], json!(["h3"]));
    }

    #[test]
    fn relay_mimicry_context_adds_runtime_only_baseline_fields() {
        let mut fields = json!({
            "relay_session_kind": "tcp_tunnel",
            "target": "198.51.100.20",
            "port": 443
        });
        maybe_add_runtime_mimicry_fields(
            &mut fields,
            Some(RelayMimicryContext {
                target_addr: "198.51.100.20:443".parse().expect("socket addr"),
                stack_profile: Some(StackProfileId::LinuxDesktop),
                wire_mode: WireMimicryMode::Disabled,
                surface_bias: policy::SurfaceBias::default(),
            }),
        );

        assert_eq!(
            fields["mimicry_capability_signal_origin"],
            "live_runtime_observation"
        );
        assert_eq!(
            fields["mimicry_capability_userspace_stack_profile"],
            "linux"
        );
        assert_eq!(
            fields["mimicry_capability_userspace_wiring_mode"],
            "profile_only"
        );
        assert_eq!(fields["mimicry_capability_stage"], "pre_wire_input_surface");
        assert_eq!(
            fields["mimicry_capability_readiness"],
            "runtime_only_baseline"
        );
        assert_eq!(fields["mimicry_capability_wire_requested"], false);
        assert_eq!(fields["mimicry_capability_wire_active"], false);
        assert_eq!(
            fields["mimicry_capability_wire_activation_reason"],
            "config_disabled"
        );
        assert!(fields["mimicry_capability_wire_scope"].is_null());
        assert!(fields["mimicry_capability_wire_runtime_slice"].is_null());
        assert!(fields["mimicry_capability_userspace_nodelay"].is_null());
    }

    #[test]
    fn relay_mimicry_context_enabled_wire_mode_stays_inactive_without_observation() {
        let mut fields = json!({
            "relay_session_kind": "tcp_tunnel",
            "target": "198.51.100.20",
            "port": 443
        });
        maybe_add_runtime_mimicry_fields(
            &mut fields,
            Some(RelayMimicryContext {
                target_addr: "198.51.100.20:443".parse().expect("socket addr"),
                stack_profile: Some(StackProfileId::LinuxDesktop),
                wire_mode: WireMimicryMode::LinuxExperimentalTtlPreface,
                surface_bias: policy::SurfaceBias::default(),
            }),
        );

        assert_eq!(fields["mimicry_capability_wire_requested"], true);
        assert_eq!(fields["mimicry_capability_wire_active"], false);
        assert_eq!(
            fields["mimicry_capability_observation_capture_confidence"],
            "runtime_only"
        );
        assert!(fields["mimicry_capability_wire_runtime_slice"].is_null());
        assert_eq!(
            fields["mimicry_capability_userspace_stack_profile"],
            "linux"
        );
        assert!(fields["mimicry_capability_wire_stage"].is_null());
        assert!(fields["mimicry_capability_userspace_scope"].is_null());
    }

    #[test]
    fn direct_and_relay_profiles_mix_without_one_to_one_lockstep() {
        let settings = sample_relay_settings();
        let now_secs = 10_000;
        let mut direct_to_relay: BTreeMap<&'static str, BTreeSet<&'static str>> = BTreeMap::new();
        let mut relay_to_direct: BTreeMap<&'static str, BTreeSet<&'static str>> = BTreeMap::new();

        for idx in 1..=256u16 {
            let direct = direct_profile_family_for_time(
                SocketAddr::from(([198, 51, 100, 77], idx)),
                None,
                now_secs,
            );
            let host = format!("edge-{idx}.example.org");
            let (relay_profile, _, _, _) =
                policy::relay_profile_signature_for_time(&settings, Some((&host, 443)), now_secs);
            direct_to_relay
                .entry(direct)
                .or_default()
                .insert(relay_profile);
            relay_to_direct
                .entry(relay_profile)
                .or_default()
                .insert(direct);
        }

        assert!(
            direct_to_relay.values().all(|profiles| profiles.len() >= 2),
            "direct families should map to multiple relay surfaces: {direct_to_relay:?}"
        );
        assert!(
            relay_to_direct.values().all(|families| families.len() >= 2),
            "relay surfaces should map to multiple direct families: {relay_to_direct:?}"
        );
    }
}
