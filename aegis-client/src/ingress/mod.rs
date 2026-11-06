pub mod broker;
pub mod preflight;
pub mod wide;

use crate::runtime_event_stream as runtime_jsonl;
use crate::runtime_events::RuntimeEventCode;
use crate::socks5::{self, ClientRequest, ConnectTarget};
use aegis_core::{IngressPrimary, IngressSettings, WidePlatformBackend, WideUdpCaptureContract};
use async_trait::async_trait;
use serde_json::json;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket as StdUdpSocket};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio::time::Instant;

fn stage_io_error(stage: &'static str, source: io::Error) -> io::Error {
    io::Error::new(source.kind(), format!("{stage}: {source}"))
}

async fn reply_for_request_read_error(
    response: IngressResponse,
    client: &mut TcpStream,
    source: &io::Error,
) -> io::Result<()> {
    // Preserve an honest wire contract for post-handshake request parse failures
    // before the listener surfaces the connection-level accept error internally.
    match socks5::classify_request_read_error(source) {
        socks5::RequestReadFailureReply::CommandNotSupported => {
            response.send_command_not_supported(client).await
        }
        socks5::RequestReadFailureReply::GeneralFailure => {
            response.send_general_failure(client).await
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressKind {
    WidePrimary,
    Socks5Fallback,
}

impl IngressKind {
    pub fn as_code(self) -> &'static str {
        match self {
            Self::WidePrimary => "wide_primary",
            Self::Socks5Fallback => "socks5_fallback",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveIngressBackend {
    WidePrimary,
    Socks5Fallback,
}

impl ActiveIngressBackend {
    pub fn as_code(self) -> &'static str {
        match self {
            Self::WidePrimary => "wide_primary",
            Self::Socks5Fallback => "socks5_fallback",
        }
    }
}

fn macos_system_wide_phase3_boundary_requested(settings: &IngressSettings) -> bool {
    cfg!(target_os = "macos")
        && settings.wide.platform_backend == WidePlatformBackend::MacosPf
        && settings.wide.capture_dns
        && settings.wide.udp_capture_contract == WideUdpCaptureContract::GenericCaptureUnstable
}

pub fn wide_unavailable_reason(settings: &IngressSettings) -> &'static str {
    if !settings.wide.enabled {
        "wide ingress is disabled in config"
    } else if macos_system_wide_phase3_boundary_requested(settings) {
        #[cfg(target_os = "macos")]
        {
            let report = crate::ingress::wide::macos::MacosWidePrimaryBackend::capability_report(
                &settings.wide,
            );
            if report.reason_code == "pf_system_wide_phase3_prepared_boundary_only" {
                "macos_pf system_wide_phase3 is currently prepared-boundary-only and falls back until a broader runtime path exists"
            } else {
                "macos_pf system_wide_phase3 is currently boundary-only and falls back until a broader runtime path exists"
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            "macos_pf system_wide_phase3 is currently boundary-only and falls back until a broader runtime path exists"
        }
    } else {
        "selected wide platform backend is unsupported on this platform"
    }
}

pub fn select_active_backend(
    settings: &IngressSettings,
    wide_available: bool,
) -> Result<ActiveIngressBackend, String> {
    match settings.primary {
        IngressPrimary::Wide if wide_available => Ok(ActiveIngressBackend::WidePrimary),
        IngressPrimary::Wide if settings.allow_fallback => Ok(ActiveIngressBackend::Socks5Fallback),
        IngressPrimary::Wide => Err(format!(
            "wide ingress is selected, but unavailable: {}",
            wide_unavailable_reason(settings)
        )),
        IngressPrimary::Socks5 => Ok(ActiveIngressBackend::Socks5Fallback),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IngressResponse {
    #[default]
    None,
    Socks5,
}

impl IngressResponse {
    async fn close_without_response(stream: &mut TcpStream) -> io::Result<()> {
        // Native wide ingress has no SOCKS reply surface, so explicit failure
        // paths should close the stream instead of relying on later drop timing.
        stream.shutdown().await
    }

    pub async fn send_connect_success(
        self,
        stream: &mut TcpStream,
        bind: SocketAddr,
    ) -> io::Result<()> {
        match self {
            Self::None => Ok(()),
            Self::Socks5 => socks5::send_success(stream, bind).await,
        }
    }

    pub async fn send_udp_success(
        self,
        stream: &mut TcpStream,
        bind: SocketAddr,
    ) -> io::Result<()> {
        match self {
            Self::None => Ok(()),
            Self::Socks5 => socks5::send_success(stream, bind).await,
        }
    }

    pub async fn send_command_not_supported(self, stream: &mut TcpStream) -> io::Result<()> {
        match self {
            Self::None => Self::close_without_response(stream).await,
            Self::Socks5 => socks5::send_command_not_supported(stream).await,
        }
    }

    pub async fn send_host_unreachable(self, stream: &mut TcpStream) -> io::Result<()> {
        match self {
            Self::None => Self::close_without_response(stream).await,
            Self::Socks5 => socks5::send_host_unreachable(stream).await,
        }
    }

    pub async fn send_general_failure(self, stream: &mut TcpStream) -> io::Result<()> {
        match self {
            Self::None => Self::close_without_response(stream).await,
            Self::Socks5 => socks5::send_general_failure(stream).await,
        }
    }
}

pub use aegis_client::relay_session_control::UdpSessionControl;

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug)]
pub enum UdpDatagramResponse {
    Detached,
    LocalUdp {
        socket: UdpSocket,
        peer: SocketAddr,
    },
    DeferredLocalUdp {
        bind_addr: SocketAddr,
        peer: SocketAddr,
    },
}

impl UdpDatagramResponse {
    pub fn action(&self) -> &'static str {
        match self {
            Self::Detached => "detached",
            Self::LocalUdp { .. } | Self::DeferredLocalUdp { .. } => "local_udp",
        }
    }

    pub async fn send(&self, payload: &[u8]) -> io::Result<()> {
        match self {
            Self::Detached => Ok(()),
            Self::LocalUdp { socket, peer } => {
                // Keep the final local-delivery hop observable because the
                // relay path may already have succeeded by the time a smoke
                // script still experiences an end-to-end timeout.
                tracing::info!(
                    event_code = RuntimeEventCode::IngressUdpDatagramResponseStage.as_str(),
                    stage = "local_udp_send_start",
                    peer = %peer,
                    response_action = "local_udp",
                    payload_len = payload.len(),
                    "ingress udp datagram response stage"
                );
                runtime_jsonl::emit(
                    "info",
                    RuntimeEventCode::IngressUdpDatagramResponseStage,
                    "ingress udp datagram response stage",
                    json!({
                        "stage": "local_udp_send_start",
                        "peer": peer.to_string(),
                        "response_action": "local_udp",
                        "payload_len": payload.len()
                    }),
                );
                // Wide Linux response sockets are pre-connected to the original
                // peer so they can safely share the preserved local target tuple.
                socket.send(payload).await?;
                tracing::info!(
                    event_code = RuntimeEventCode::IngressUdpDatagramResponseStage.as_str(),
                    stage = "local_udp_send_done",
                    peer = %peer,
                    response_action = "local_udp",
                    payload_len = payload.len(),
                    "ingress udp datagram response stage"
                );
                runtime_jsonl::emit(
                    "info",
                    RuntimeEventCode::IngressUdpDatagramResponseStage,
                    "ingress udp datagram response stage",
                    json!({
                        "stage": "local_udp_send_done",
                        "peer": peer.to_string(),
                        "response_action": "local_udp",
                        "payload_len": payload.len()
                    }),
                );
                Ok(())
            }
            Self::DeferredLocalUdp { bind_addr, peer } => {
                // TPROXY UDP must not occupy the original target tuple until
                // the relay has produced a response, otherwise same-gateway
                // targets can lose the request to this response socket.
                tracing::info!(
                    event_code = RuntimeEventCode::IngressUdpDatagramResponseStage.as_str(),
                    stage = "local_udp_bind_start",
                    peer = %peer,
                    bind_addr = %bind_addr,
                    response_action = "local_udp",
                    payload_len = payload.len(),
                    "ingress udp datagram response stage"
                );
                runtime_jsonl::emit(
                    "info",
                    RuntimeEventCode::IngressUdpDatagramResponseStage,
                    "ingress udp datagram response stage",
                    json!({
                        "stage": "local_udp_bind_start",
                        "peer": peer.to_string(),
                        "bind_addr": bind_addr.to_string(),
                        "response_action": "local_udp",
                        "payload_len": payload.len()
                    }),
                );
                let socket = bind_deferred_udp_response_socket(*bind_addr, *peer)?;
                tracing::info!(
                    event_code = RuntimeEventCode::IngressUdpDatagramResponseStage.as_str(),
                    stage = "local_udp_send_start",
                    peer = %peer,
                    bind_addr = %bind_addr,
                    response_action = "local_udp",
                    payload_len = payload.len(),
                    "ingress udp datagram response stage"
                );
                runtime_jsonl::emit(
                    "info",
                    RuntimeEventCode::IngressUdpDatagramResponseStage,
                    "ingress udp datagram response stage",
                    json!({
                        "stage": "local_udp_send_start",
                        "peer": peer.to_string(),
                        "bind_addr": bind_addr.to_string(),
                        "response_action": "local_udp",
                        "payload_len": payload.len()
                    }),
                );
                socket.send(payload).await?;
                tracing::info!(
                    event_code = RuntimeEventCode::IngressUdpDatagramResponseStage.as_str(),
                    stage = "local_udp_send_done",
                    peer = %peer,
                    bind_addr = %bind_addr,
                    response_action = "local_udp",
                    payload_len = payload.len(),
                    "ingress udp datagram response stage"
                );
                runtime_jsonl::emit(
                    "info",
                    RuntimeEventCode::IngressUdpDatagramResponseStage,
                    "ingress udp datagram response stage",
                    json!({
                        "stage": "local_udp_send_done",
                        "peer": peer.to_string(),
                        "bind_addr": bind_addr.to_string(),
                        "response_action": "local_udp",
                        "payload_len": payload.len()
                    }),
                );
                Ok(())
            }
        }
    }
}

fn bind_deferred_udp_response_socket(
    bind_addr: SocketAddr,
    peer: SocketAddr,
) -> io::Result<UdpSocket> {
    let domain = match bind_addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    if matches!(bind_addr, SocketAddr::V6(_)) {
        socket.set_only_v6(true)?;
    }
    configure_deferred_udp_response_transparent(&socket, bind_addr);
    socket.bind(&bind_addr.into())?;
    socket.connect(&peer.into())?;
    socket.set_nonblocking(true)?;
    let std_socket: StdUdpSocket = socket.into();
    UdpSocket::from_std(std_socket)
}

#[cfg(target_os = "linux")]
fn configure_deferred_udp_response_transparent(socket: &Socket, bind_addr: SocketAddr) {
    let fd = socket.as_raw_fd();
    let enabled: libc::c_int = 1;
    let value_ptr = &enabled as *const libc::c_int as *const libc::c_void;
    let value_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let (level, optname) = match bind_addr {
        SocketAddr::V4(_) => (libc::SOL_IP, libc::IP_TRANSPARENT),
        SocketAddr::V6(_) => (libc::SOL_IPV6, libc::IPV6_TRANSPARENT),
    };
    let _ = unsafe { libc::setsockopt(fd, level, optname, value_ptr, value_len) };
}

#[cfg(not(target_os = "linux"))]
fn configure_deferred_udp_response_transparent(_socket: &Socket, _bind_addr: SocketAddr) {}

pub struct IngressSessionIntent {
    pub kind: IngressKind,
    pub peer: SocketAddr,
    pub transport: IngressTransport,
}

impl IngressSessionIntent {
    /// The lease that keeps a TCP connect's recovered target bound. The
    /// caller holds it for the whole session: the broker consumes the intent
    /// before the relay session starts.
    pub fn take_target_lease(&mut self) -> Option<TargetLease> {
        match &mut self.transport {
            IngressTransport::TcpConnect(intent) => intent.target_lease.take(),
            IngressTransport::UdpAssociate(_) | IngressTransport::UdpDatagram(_) => None,
        }
    }

    pub fn is_tcp_connect(&self) -> bool {
        matches!(self.transport, IngressTransport::TcpConnect(_))
    }

    pub fn is_udp_associate(&self) -> bool {
        matches!(self.transport, IngressTransport::UdpAssociate(_))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn is_udp_datagram(&self) -> bool {
        matches!(self.transport, IngressTransport::UdpDatagram(_))
    }

    pub async fn reject_command_not_supported(&mut self) -> io::Result<()> {
        match &mut self.transport {
            IngressTransport::TcpConnect(intent) => {
                intent
                    .response
                    .send_command_not_supported(&mut intent.client)
                    .await
            }
            IngressTransport::UdpAssociate(intent) => match intent.control.as_socks_stream_mut() {
                Some(stream) => intent.response.send_command_not_supported(stream).await,
                None => Ok(()),
            },
            IngressTransport::UdpDatagram(intent) => match intent.control.as_socks_stream_mut() {
                Some(stream) => {
                    IngressResponse::None
                        .send_command_not_supported(stream)
                        .await
                }
                None => Ok(()),
            },
        }
    }

    pub async fn reject_general_failure(&mut self) -> io::Result<()> {
        match &mut self.transport {
            IngressTransport::TcpConnect(intent) => {
                intent
                    .response
                    .send_general_failure(&mut intent.client)
                    .await
            }
            IngressTransport::UdpAssociate(intent) => match intent.control.as_socks_stream_mut() {
                Some(stream) => intent.response.send_general_failure(stream).await,
                None => Ok(()),
            },
            IngressTransport::UdpDatagram(intent) => match intent.control.as_socks_stream_mut() {
                Some(stream) => IngressResponse::None.send_general_failure(stream).await,
                None => Ok(()),
            },
        }
    }
}

pub enum IngressTransport {
    TcpConnect(TcpConnectIntent),
    UdpAssociate(UdpAssociateIntent),
    #[cfg_attr(not(test), allow(dead_code))]
    UdpDatagram(UdpDatagramIntent),
}

pub struct TcpConnectIntent {
    pub client: TcpStream,
    pub target: ConnectTarget,
    pub response: IngressResponse,
    /// Keeps the binding `target` was recovered from (a Linux fake-IP
    /// address) bound to it; the session holds it until it ends.
    pub target_lease: Option<TargetLease>,
}

/// An opaque owner of whatever keeps a recovered target's meaning: the Linux
/// DNS preview's fake-IP lease, under which the address is never given to
/// another name. Dropping it ends the hold.
pub struct TargetLease {
    _owner: Box<dyn std::any::Any + Send + Sync>,
}

impl TargetLease {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn new(owner: impl std::any::Any + Send + Sync) -> Self {
        Self {
            _owner: Box::new(owner),
        }
    }
}

pub struct UdpAssociateIntent {
    pub control: UdpSessionControl,
    pub client_ip: IpAddr,
    pub response: IngressResponse,
}

#[cfg_attr(not(test), allow(dead_code))]
pub struct UdpDatagramIntent {
    pub control: UdpSessionControl,
    pub client_ip: IpAddr,
    pub target: ConnectTarget,
    pub payload: Vec<u8>,
    pub response: UdpDatagramResponse,
}

#[derive(Debug, Clone, Default)]
pub struct IngressBackendRuntimeStatus {
    pub wide_dns_capture_preview_status: Option<&'static str>,
    pub wide_dns_capture_preview_error_kind: Option<&'static str>,
    pub wide_dns_capture_preview_error: Option<String>,
    pub wide_backend_current_stage: Option<&'static str>,
    pub wide_backend_scope_target: Option<&'static str>,
    pub wide_backend_reason_code: Option<&'static str>,
    pub wide_udp_capture_contract: Option<&'static str>,
    pub wide_udp_capture_support_tier: Option<&'static str>,
    pub wide_udp_capture_policy: Option<&'static str>,
    pub wide_udp_capture_runtime_scope: Option<&'static str>,
    pub wide_udp_preview_policy: Option<&'static str>,
    pub wide_udp_preview_ports: Vec<u16>,
}

#[async_trait]
pub trait IngressBackend: Send + Sync {
    /// Required background listeners must wake the process supervisor even
    /// when no foreground connection arrives.
    async fn failure(&self) -> &'static str {
        std::future::pending().await
    }
    fn id(&self) -> &'static str;
    fn runtime_id(&self) -> &'static str {
        self.id()
    }
    fn kind(&self) -> IngressKind;
    fn is_available(&self) -> bool;
    fn listen_addr(&self) -> Option<SocketAddr> {
        None
    }
    fn runtime_status(&self) -> IngressBackendRuntimeStatus {
        IngressBackendRuntimeStatus::default()
    }
    async fn accept(&self) -> io::Result<IngressSessionIntent>;
    /// Stop owned background listeners before the enclosing runtime is dropped.
    async fn shutdown(&self) {}
}

const SOCKS_MAX_PENDING_NEGOTIATIONS: usize = 64;
const SOCKS_NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Socks5FallbackBackend {
    listener: TcpListener,
    auth: Option<crate::socks5::SocksAuthCfg>,
    require_loopback: bool,
    // Completed results count too: a stopped consumer cannot build an
    // unbounded queue of authenticated sockets. JoinSet aborts tasks on drop.
    pending: Mutex<JoinSet<io::Result<IngressSessionIntent>>>,
    max_pending_negotiations: usize,
    negotiation_timeout: Duration,
}

#[cfg(test)]
mod socks_admission_tests;

impl Socks5FallbackBackend {
    pub async fn bind(listen: SocketAddr) -> io::Result<Self> {
        Self::bind_with_auth(listen, None, Vec::new()).await
    }

    pub async fn bind_with_auth(
        listen: SocketAddr,
        auth: Option<crate::socks5::SocksAuthCfg>,
        allowed_uids: Vec<u32>,
    ) -> io::Result<Self> {
        if !allowed_uids.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "socks.allowed_uids is unsupported by the TCP listener; use SOCKS authentication",
            ));
        }
        Self::bind_with_policy(listen, auth, true).await
    }

    async fn bind_with_policy(
        listen: SocketAddr,
        auth: Option<crate::socks5::SocksAuthCfg>,
        require_loopback: bool,
    ) -> io::Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(listen).await?,
            auth,
            require_loopback,
            pending: Mutex::new(JoinSet::new()),
            max_pending_negotiations: SOCKS_MAX_PENDING_NEGOTIATIONS,
            negotiation_timeout: SOCKS_NEGOTIATION_TIMEOUT,
        })
    }

    /// Validate every configured protection before binding, including for
    /// callers that construct settings without using the config loader.
    pub async fn bind_from_settings(
        settings: &aegis_core::config_types::SocksSettings,
    ) -> io::Result<Self> {
        settings
            .validate_tcp_policy()
            .map_err(|message| io::Error::new(io::ErrorKind::Unsupported, message))?;
        let auth = settings.auth_token.as_deref().map(|tok| {
            crate::socks5::SocksAuthCfg::from_config(tok, settings.auth_user.as_deref())
        });
        Self::bind_with_policy(settings.listen, auth, settings.require_loopback).await
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}

fn check_socks_peer(require_loopback: bool, peer: SocketAddr) -> io::Result<()> {
    let is_loopback = match peer.ip() {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => {
            ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|ip| ip.is_loopback())
        }
    };
    if require_loopback && !is_loopback {
        return Err(stage_io_error(
            "socks5_peer_address_rejected",
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS peer must be loopback",
            ),
        ));
    }
    Ok(())
}

#[async_trait]
impl IngressBackend for Socks5FallbackBackend {
    fn id(&self) -> &'static str {
        "socks5_fallback"
    }

    fn kind(&self) -> IngressKind {
        IngressKind::Socks5Fallback
    }

    fn is_available(&self) -> bool {
        true
    }

    fn listen_addr(&self) -> Option<SocketAddr> {
        self.local_addr().ok()
    }

    async fn accept(&self) -> io::Result<IngressSessionIntent> {
        // Keep negotiations owned by the backend across cancellation of this
        // accept future (for example, a supervisor wakeup). Only bounded tasks
        // are spawned and ready results are drained before accepting more work.
        let mut pending = self.pending.lock().await;
        loop {
            tokio::select! {
                biased;
                completed = pending.join_next(), if !pending.is_empty() => {
                    return completed.expect("pending negotiation exists")
                        .map_err(|source| stage_io_error(
                            "socks5_negotiation_task",
                            io::Error::other(source),
                        ))?;
                }
                accepted = self.listener.accept() => {
                    let (client, peer) = accepted?;
                    // This deadline is captured at acceptance, not when the
                    // task is first scheduled, and never resets on progress.
                    let deadline = Instant::now() + self.negotiation_timeout;
                    check_socks_peer(self.require_loopback, peer)?;
                    if pending.len() >= self.max_pending_negotiations {
                        return Err(stage_io_error(
                            "socks5_negotiation_limit",
                            io::Error::new(io::ErrorKind::WouldBlock,
                                "pending SOCKS negotiations reached limit"),
                        ));
                    }
                    let auth = self.auth.clone();
                    pending.spawn(async move {
                        // timeout_at may poll an immediately ready inner future
                        // before its expired timer; also enforce the cutoff on
                        // completion so scheduling delay cannot extend admission.
                        match tokio::time::timeout_at(deadline, negotiate_socks_client(client, peer, auth)).await {
                            Ok(result) if Instant::now() < deadline => result,
                            _ => Err(stage_io_error(
                                "socks5_negotiation_deadline",
                                io::Error::new(io::ErrorKind::TimedOut,
                                    "SOCKS authentication/request deadline elapsed"),
                            )),
                        }
                    });
                }
            }
        }
    }

    async fn shutdown(&self) {
        let mut pending = self.pending.lock().await;
        pending.abort_all();
        while pending.join_next().await.is_some() {}
    }
}

// One caller-owned deadline wraps authentication, request parsing and any
// rejection reply; none of those phases can indefinitely retain admission.
async fn negotiate_socks_client(
    mut client: TcpStream,
    peer: SocketAddr,
    auth: Option<socks5::SocksAuthCfg>,
) -> io::Result<IngressSessionIntent> {
    socks5::handshake(&mut client, auth.as_ref())
        .await
        .map_err(|source| stage_io_error("socks5_handshake", source))?;
    let response = IngressResponse::Socks5;
    let request = match socks5::read_client_request(&mut client).await {
        Ok(request) => request,
        Err(source) => {
            reply_for_request_read_error(response, &mut client, &source)
                .await
                .map_err(|response_err| {
                    stage_io_error("socks5_request_reject_response", response_err)
                })?;
            return Err(stage_io_error("socks5_request_read", source));
        }
    };
    let transport = match request {
        ClientRequest::Connect(target) => IngressTransport::TcpConnect(TcpConnectIntent {
            client,
            target,
            response,
            target_lease: None,
        }),
        ClientRequest::UdpAssociate => {
            let client_ip = client.peer_addr()?.ip();
            IngressTransport::UdpAssociate(UdpAssociateIntent {
                control: UdpSessionControl::SocksControl(client),
                client_ip,
                response,
            })
        }
    };
    Ok(IngressSessionIntent {
        kind: IngressKind::Socks5Fallback,
        peer,
        transport,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpStream, UdpSocket};

    async fn tcp_connect(addr: SocketAddr) -> TcpStream {
        TcpStream::connect(addr).await.expect("connect client")
    }

    #[test]
    fn socks_peer_policy_checks_native_and_mapped_addresses() {
        for peer in [
            "127.0.0.1:1234",
            "127.31.2.3:1234",
            "[::1]:1234",
            "[::ffff:127.0.0.1]:1234",
        ] {
            assert!(check_socks_peer(true, peer.parse().unwrap()).is_ok());
        }
        for peer in [
            "192.0.2.17:1234",
            "10.0.0.1:1234",
            "0.0.0.0:1234",
            "[2001:db8::17]:1234",
            "[::ffff:192.0.2.17]:1234",
            "[::]:1234",
        ] {
            let peer = peer.parse().unwrap();
            assert_eq!(
                check_socks_peer(true, peer).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            assert!(check_socks_peer(false, peer).is_ok());
        }
    }

    #[tokio::test]
    async fn socks_unsupported_identity_policies_fail_before_bind_for_api_callers() {
        // This address is a documentation fixture, not a local interface; the
        // policy error must be returned without attempting to bind it.
        let listen = "192.0.2.17:1234".parse().unwrap();
        let error = Socks5FallbackBackend::bind_with_auth(listen, None, vec![0])
            .await
            .err()
            .expect("unsupported UID policy");
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        let mut settings = aegis_core::Settings::default().socks;
        settings.listen = listen;
        settings.allowed_uids = vec![0];
        let error = Socks5FallbackBackend::bind_from_settings(&settings)
            .await
            .err()
            .expect("unsupported configured UID policy");
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        settings.allowed_uids.clear();
        settings.unix_socket = Some("unused-test-socks.sock".into());
        let error = Socks5FallbackBackend::bind_from_settings(&settings)
            .await
            .err()
            .expect("unsupported configured UNIX listener");
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }

    #[tokio::test]
    async fn socks_wildcard_bind_preserves_explicit_peer_policy() {
        let mut settings = aegis_core::Settings::default().socks;
        settings.listen = "0.0.0.0:0".parse().unwrap();
        let backend = Socks5FallbackBackend::bind_from_settings(&settings)
            .await
            .unwrap();
        assert!(backend.require_loopback);
        assert!(backend.local_addr().unwrap().ip().is_unspecified());
        drop(backend);
        settings.require_loopback = false;
        let backend = Socks5FallbackBackend::bind_from_settings(&settings)
            .await
            .unwrap();
        assert!(!backend.require_loopback);
        drop(backend);
        let backend = Socks5FallbackBackend::bind(settings.listen).await.unwrap();
        assert!(
            backend.require_loopback,
            "short-form API keeps a safe default"
        );
    }

    #[test]
    fn prefers_wide_when_available() {
        let settings = IngressSettings::default();
        assert_eq!(
            select_active_backend(&settings, true),
            Ok(ActiveIngressBackend::WidePrimary)
        );
    }

    #[test]
    fn falls_back_to_socks_when_wide_is_unavailable() {
        let settings = IngressSettings::default();
        assert_eq!(
            select_active_backend(&settings, false),
            Ok(ActiveIngressBackend::Socks5Fallback)
        );
    }

    #[test]
    fn rejects_missing_wide_backend_without_fallback() {
        let settings = IngressSettings {
            allow_fallback: false,
            ..IngressSettings::default()
        };
        assert_eq!(
            select_active_backend(&settings, false).unwrap_err(),
            "wide ingress is selected, but unavailable: selected wide platform backend is unsupported on this platform"
        );
    }

    #[test]
    fn explains_disabled_wide_backend() {
        let settings = IngressSettings {
            wide: aegis_core::WideIngressSettings {
                enabled: false,
                ..aegis_core::WideIngressSettings::default()
            },
            ..IngressSettings::default()
        };
        assert_eq!(
            wide_unavailable_reason(&settings),
            "wide ingress is disabled in config"
        );
    }

    #[test]
    fn explains_macos_system_wide_phase3_boundary_backend() {
        #[cfg(target_os = "macos")]
        let _missing_helper_state =
            crate::ingress::wide::macos::fixture_env::MissingHelperStateFixture::new();
        let settings = IngressSettings {
            wide: aegis_core::WideIngressSettings {
                platform_backend: WidePlatformBackend::MacosPf,
                capture_dns: true,
                udp_capture_contract: WideUdpCaptureContract::GenericCaptureUnstable,
                ..aegis_core::WideIngressSettings::default()
            },
            ..IngressSettings::default()
        };
        #[cfg(target_os = "macos")]
        assert_eq!(
            wide_unavailable_reason(&settings),
            "macos_pf system_wide_phase3 is currently boundary-only and falls back until a broader runtime path exists"
        );
        #[cfg(not(target_os = "macos"))]
        assert_eq!(
            wide_unavailable_reason(&settings),
            "selected wide platform backend is unsupported on this platform"
        );
    }

    #[test]
    fn rejects_macos_system_wide_phase3_boundary_without_fallback() {
        #[cfg(target_os = "macos")]
        let _missing_helper_state =
            crate::ingress::wide::macos::fixture_env::MissingHelperStateFixture::new();
        let settings = IngressSettings {
            allow_fallback: false,
            wide: aegis_core::WideIngressSettings {
                platform_backend: WidePlatformBackend::MacosPf,
                listen: "0.0.0.0:15080".parse().expect("listen"),
                capture_dns: true,
                udp_capture_contract: WideUdpCaptureContract::GenericCaptureUnstable,
                ..aegis_core::WideIngressSettings::default()
            },
            ..IngressSettings::default()
        };
        #[cfg(target_os = "macos")]
        assert_eq!(
            select_active_backend(&settings, false).unwrap_err(),
            "wide ingress is selected, but unavailable: macos_pf system_wide_phase3 is currently boundary-only and falls back until a broader runtime path exists"
        );
        #[cfg(not(target_os = "macos"))]
        assert_eq!(
            select_active_backend(&settings, false).unwrap_err(),
            "wide ingress is selected, but unavailable: selected wide platform backend is unsupported on this platform"
        );
    }

    #[tokio::test]
    async fn unsupported_socks_command_receives_command_not_supported_reply() {
        let backend = Socks5FallbackBackend::bind("127.0.0.1:0".parse().expect("listen"))
            .await
            .expect("bind backend");
        let listen = backend.listener.local_addr().expect("listener addr");

        let server = tokio::spawn(async move {
            backend
                .accept()
                .await
                .err()
                .expect("accept should fail for unsupported command")
        });
        let mut client = tcp_connect(listen).await;
        client
            .write_all(b"\x05\x01\x00")
            .await
            .expect("write handshake");
        let mut handshake = [0u8; 2];
        client
            .read_exact(&mut handshake)
            .await
            .expect("read handshake");
        assert_eq!(handshake, [5, 0]);

        client
            .write_all(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
            .await
            .expect("write request");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.expect("read reply");
        assert_eq!(reply[0], 5);
        assert_eq!(reply[1], 7);

        let err = server.await.expect("join accept task");
        assert_eq!(
            err.to_string(),
            "socks5_request_read: unsupported socks5 command"
        );
    }

    #[tokio::test]
    async fn detached_udp_intent_rejects_without_control_socket() {
        let mut intent = IngressSessionIntent {
            kind: IngressKind::WidePrimary,
            peer: "127.0.0.1:5300".parse().expect("peer"),
            transport: IngressTransport::UdpAssociate(UdpAssociateIntent {
                control: UdpSessionControl::Detached,
                client_ip: "127.0.0.1".parse().expect("client ip"),
                response: IngressResponse::None,
            }),
        };

        intent
            .reject_command_not_supported()
            .await
            .expect("detached command_not_supported reject should be a no-op");
        intent
            .reject_general_failure()
            .await
            .expect("detached general_failure reject should be a no-op");
    }

    #[tokio::test]
    async fn detached_udp_datagram_intent_rejects_without_control_socket() {
        let mut intent = IngressSessionIntent {
            kind: IngressKind::WidePrimary,
            peer: "127.0.0.1:5301".parse().expect("peer"),
            transport: IngressTransport::UdpDatagram(UdpDatagramIntent {
                control: UdpSessionControl::Detached,
                client_ip: "127.0.0.1".parse().expect("client ip"),
                target: ConnectTarget {
                    host: "1.1.1.1".into(),
                    port: 53,
                },
                payload: vec![0xde, 0xad],
                response: UdpDatagramResponse::Detached,
            }),
        };

        assert!(intent.is_udp_datagram());
        intent
            .reject_command_not_supported()
            .await
            .expect("detached datagram command_not_supported reject should be a no-op");
        intent
            .reject_general_failure()
            .await
            .expect("detached datagram general_failure reject should be a no-op");
    }

    #[tokio::test]
    async fn udp_datagram_local_response_sink_sends_payload_to_peer() {
        let sink = UdpSocket::bind("127.0.0.1:0").await.expect("bind sink");
        let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
        let peer_addr = peer.local_addr().expect("peer addr");
        sink.connect(peer_addr).await.expect("connect sink");
        let response = UdpDatagramResponse::LocalUdp {
            socket: sink,
            peer: peer_addr,
        };
        response.send(b"dns-response").await.expect("send response");

        let mut buf = [0u8; 64];
        let (n, from) = peer.recv_from(&mut buf).await.expect("receive response");
        assert_eq!(&buf[..n], b"dns-response");
        assert!(from.ip().is_loopback());
    }

    #[tokio::test]
    async fn wide_primary_generic_udp_datagram_deferred_local_response_binds_on_send() {
        let reserved = StdUdpSocket::bind("127.0.0.1:0").expect("reserve response tuple");
        let bind_addr = reserved.local_addr().expect("reserved addr");
        drop(reserved);
        let peer = UdpSocket::bind("127.0.0.1:0").await.expect("bind peer");
        let peer_addr = peer.local_addr().expect("peer addr");
        let response = UdpDatagramResponse::DeferredLocalUdp {
            bind_addr,
            peer: peer_addr,
        };
        response
            .send(b"deferred-response")
            .await
            .expect("send deferred response");

        let mut buf = [0u8; 64];
        let (n, from) = peer.recv_from(&mut buf).await.expect("receive response");
        assert_eq!(&buf[..n], b"deferred-response");
        assert_eq!(from, bind_addr);
    }
}
