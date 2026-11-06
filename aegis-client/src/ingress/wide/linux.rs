use super::ancillary::{self, cmsg_space, ControlBuffer};
use crate::ingress::wide::dns_preview::{
    lease_target_host, resolve_target_host, spawn_dns_preview_gated, DnsPreviewListener, FakeIpMap,
};
use crate::ingress::wide::forward_gate::ForwardGate;
use crate::ingress::{
    IngressBackend, IngressBackendRuntimeStatus, IngressKind, IngressResponse,
    IngressSessionIntent, IngressTransport, TargetLease, TcpConnectIntent, UdpDatagramIntent,
    UdpDatagramResponse, UdpSessionControl,
};
use crate::runtime_event_stream as runtime_jsonl;
use crate::runtime_events::RuntimeEventCode;
use crate::socks5::ConnectTarget;
use aegis_core::{RelaySettings, WideIngressSettings, WidePlatformBackend, WideUdpCaptureContract};
use async_trait::async_trait;
use serde_json::json;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::mem::{size_of, zeroed};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket as StdUdpSocket};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const LISTEN_BACKLOG: i32 = 1024;
const SO_ORIGINAL_DST_LINUX: libc::c_int = 80;
const IP_RECVORIGDSTADDR_LINUX: libc::c_int = 20;
const IP_ORIGDSTADDR_LINUX: libc::c_int = 20;
fn stage_io_error(stage: &'static str, source: io::Error) -> io::Error {
    io::Error::new(source.kind(), format!("{stage}: {source}"))
}

pub struct LinuxWidePrimaryBackend {
    listener: TcpListener,
    udp_dns_socket: Option<AsyncFd<StdUdpSocket>>,
    udp_dns_preview_status: UdpDnsPreviewStatus,
    fake_ip_map: Option<Arc<FakeIpMap>>,
    dns_preview_listener: std::sync::Mutex<Option<DnsPreviewListener>>,
    dns_preview_failure: Option<tokio::sync::watch::Receiver<()>>,
    settings: WideIngressSettings,
}

#[derive(Debug, Clone)]
enum UdpDnsPreviewStatus {
    Disabled,
    Active,
    BindFailed {
        error_kind: &'static str,
        error: String,
    },
}

impl LinuxWidePrimaryBackend {
    #[cfg(test)]
    pub async fn bind(settings: WideIngressSettings) -> io::Result<Self> {
        Self::bind_with_relay(settings, None).await
    }

    #[cfg(test)]
    pub async fn bind_with_relay(
        settings: WideIngressSettings,
        relay: Option<RelaySettings>,
    ) -> io::Result<Self> {
        Self::bind_with_relay_gated(settings, relay, None).await
    }

    pub(crate) async fn bind_with_relay_gated(
        settings: WideIngressSettings,
        relay: Option<RelaySettings>,
        gate: Option<ForwardGate>,
    ) -> io::Result<Self> {
        let listener = bind_linux_listener(&settings)?;
        let mut settings = settings;
        // Preserve the actual bound listen address so later destination
        // recovery heuristics do not keep looking at a requested ":0" shape.
        settings.listen = listener.local_addr()?;
        // Narrow DNS-first preview stays best-effort so default capture_dns=true
        // does not suddenly convert wide startup into a hard failure.
        let (udp_dns_socket, udp_dns_preview_status) = bind_linux_udp_dns_socket(&settings);
        // DNS-preview fake-IP listener (resolver-based architecture). Only
        // spawned when settings.dns_preview_listen is Some — operator opt-in
        // via --dns=preview in aegis-wide-enable.sh, which writes the field
        // into aegis.toml before restart. Unlike the legacy capture socket,
        // this explicitly requested listener is required for backend startup.
        let dns_preview_listener = spawn_dns_preview_gated(&settings, relay, gate)
            .await
            .map_err(|source| stage_io_error("wide_dns_preview_listener", source))?;
        let fake_ip_map = dns_preview_listener
            .as_ref()
            .map(|listener| Arc::clone(&listener.map));
        let dns_preview_failure = dns_preview_listener
            .as_ref()
            .map(DnsPreviewListener::failure_receiver);
        Ok(Self {
            listener,
            udp_dns_socket,
            udp_dns_preview_status,
            fake_ip_map,
            dns_preview_listener: std::sync::Mutex::new(dns_preview_listener),
            dns_preview_failure,
            settings,
        })
    }

    pub fn listen_addr(&self) -> std::net::SocketAddr {
        self.settings.listen
    }

    pub fn fake_ip_map(&self) -> Option<Arc<FakeIpMap>> {
        self.fake_ip_map.clone()
    }

    pub fn supports_platform(settings: &WideIngressSettings) -> bool {
        if !settings.enabled {
            return false;
        }
        matches!(
            settings.platform_backend,
            WidePlatformBackend::Auto
                | WidePlatformBackend::LinuxRedirect
                | WidePlatformBackend::LinuxTproxy
        )
    }
}

#[async_trait]
impl IngressBackend for LinuxWidePrimaryBackend {
    async fn failure(&self) -> &'static str {
        if let Some(mut lifetime) = self.dns_preview_failure.clone() {
            let _ = lifetime.changed().await;
            "required_dns_preview_listener"
        } else {
            std::future::pending().await
        }
    }

    async fn shutdown(&self) {
        let listener = self
            .dns_preview_listener
            .lock()
            .expect("DNS listener owner")
            .take();
        if let Some(listener) = listener {
            listener.shutdown().await;
        }
    }

    fn id(&self) -> &'static str {
        "wide_primary_linux"
    }

    fn kind(&self) -> IngressKind {
        IngressKind::WidePrimary
    }

    fn is_available(&self) -> bool {
        Self::supports_platform(&self.settings)
            && self
                .dns_preview_failure
                .as_ref()
                .is_none_or(|lifetime| lifetime.has_changed().is_ok())
    }

    fn runtime_status(&self) -> IngressBackendRuntimeStatus {
        let wide_udp_capture_contract = configured_udp_capture_contract(&self.settings);
        let wide_udp_capture_support_tier = configured_udp_capture_support_tier(&self.settings);
        let wide_udp_capture_policy = configured_udp_capture_policy(&self.settings);
        let wide_udp_capture_runtime_scope = configured_udp_capture_runtime_scope(&self.settings);
        let wide_udp_preview_policy = configured_udp_preview_policy(&self.settings);
        IngressBackendRuntimeStatus {
            wide_dns_capture_preview_status: Some(self.udp_dns_preview_status.code()),
            wide_dns_capture_preview_error_kind: self.udp_dns_preview_status.error_kind(),
            wide_dns_capture_preview_error: self
                .udp_dns_preview_status
                .error()
                .map(ToOwned::to_owned),
            wide_backend_current_stage: None,
            wide_backend_scope_target: None,
            wide_backend_reason_code: None,
            wide_udp_capture_contract,
            wide_udp_capture_support_tier,
            wide_udp_capture_policy,
            wide_udp_capture_runtime_scope,
            wide_udp_preview_policy,
            wide_udp_preview_ports: configured_udp_preview_event_ports(&self.settings),
        }
    }

    async fn accept(&self) -> io::Result<IngressSessionIntent> {
        if let Some(udp_dns_socket) = &self.udp_dns_socket {
            tokio::select! {
                tcp = self.accept_tcp_intent() => tcp,
                udp = accept_dns_udp_intent(udp_dns_socket, &self.settings) => udp,
            }
        } else {
            self.accept_tcp_intent().await
        }
    }
}

impl LinuxWidePrimaryBackend {
    async fn accept_tcp_intent(&self) -> io::Result<IngressSessionIntent> {
        let (client, peer) = self
            .listener
            .accept()
            .await
            .map_err(|source| stage_io_error("wide_listener_accept", source))?;
        // Keep wide accept failures machine-readable enough for ingress_accept_failed:
        // listener issues and original-destination recovery failures need different operators actions.
        let original_dst = original_destination(
            &client,
            self.settings.listen,
            self.settings.platform_backend,
        )
        .map_err(|source| stage_io_error("wide_original_destination", source))?;
        tcp_connect_intent(client, peer, original_dst, self.fake_ip_map.as_deref())
    }
}

/// The relayed TCP session of an accepted connection to `original_dst`. A
/// destination in the fake-IP pool (IPv4, or IPv4-mapped on a dual-stack
/// listener) is relayed to the name it was answered for, and its binding is
/// leased for the session (`TcpConnectIntent::target_lease`): while the
/// session lives, and for the map's recycle idle after it ends, the address
/// never goes to another name, as in the packet engine and the UDP redirect
/// proxy.
fn tcp_connect_intent(
    client: TcpStream,
    peer: SocketAddr,
    original_dst: SocketAddr,
    fake_ip_map: Option<&FakeIpMap>,
) -> io::Result<IngressSessionIntent> {
    // DNS-preview fake-IP path: if the original destination IP belongs to
    // the configured fake-IP pool, recover the hostname from the shared
    // FakeIpMap and route the relay session against the hostname instead
    // of the fake IP. This lets the relay perform the real DNS lookup
    // (so we never connect to a fake IP externally), and emits runtime
    // events so observers can audit the substitution.
    let pooled = fake_ip_map.and_then(|map| {
        let ip = match original_dst.ip() {
            std::net::IpAddr::V4(ip) => ip,
            std::net::IpAddr::V6(ip) => ip.to_ipv4_mapped()?,
        };
        map.ip_in_pool(ip).then_some((map, ip))
    });
    let (target, lease) = match pooled {
        Some((map, fake_ip)) => match lease_target_host(original_dst, Some(map)) {
            Ok((hostname, lease)) => {
                runtime_jsonl::emit(
                    "info",
                    RuntimeEventCode::WideFakeIpHostnameRecovered,
                    "wide fake-ip target substituted with hostname",
                    json!({
                        "fake_ip": fake_ip.to_string(),
                        "hostname": hostname,
                        "port": original_dst.port(),
                    }),
                );
                (
                    ConnectTarget {
                        host: hostname,
                        port: original_dst.port(),
                    },
                    lease,
                )
            }
            Err(_) => {
                runtime_jsonl::emit(
                    "warn",
                    RuntimeEventCode::WideFakeIpHostnameMissing,
                    "wide fake-ip target has no mapping; rejecting",
                    json!({
                        "fake_ip": fake_ip.to_string(),
                        "port": original_dst.port(),
                    }),
                );
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "wide fake-ip {fake_ip} has no hostname mapping (DNS preview expired or unseen)"
                    ),
                ));
            }
        },
        None => (
            ConnectTarget {
                host: resolve_target_host(original_dst, fake_ip_map)?,
                port: original_dst.port(),
            },
            None,
        ),
    };
    Ok(IngressSessionIntent {
        kind: IngressKind::WidePrimary,
        peer,
        transport: IngressTransport::TcpConnect(TcpConnectIntent {
            client,
            target,
            response: IngressResponse::None,
            target_lease: lease.map(TargetLease::new),
        }),
    })
}

fn bind_linux_listener(settings: &WideIngressSettings) -> io::Result<TcpListener> {
    let domain = match settings.listen {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    // v0.3.8: explicit dual-stack on IPv6 listeners. Some Linux toolchains
    // default IPV6_V6ONLY=1 even when net.ipv6.bindv6only=0; setting it
    // here makes the dual-stack contract explicit and survives sysctl
    // drift. Without this, IPv6 nat REDIRECT'd connections to a v6
    // wildcard listener never get accepted (live drill on .197 confirmed
    // 12+8 SYN packets matched ip6tables but zero accepts).
    if matches!(domain, Domain::IPV6) {
        socket.set_only_v6(false)?;
    }
    configure_ip_transparent(&socket, settings)?;
    socket.bind(&settings.listen.into())?;
    socket.listen(LISTEN_BACKLOG)?;
    socket.set_nonblocking(true)?;
    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
}

fn bind_linux_udp_dns_socket(
    settings: &WideIngressSettings,
) -> (Option<AsyncFd<StdUdpSocket>>, UdpDnsPreviewStatus) {
    if !settings.capture_dns {
        return (None, UdpDnsPreviewStatus::Disabled);
    }
    let bind_result = match settings.listen {
        SocketAddr::V4(_) => bind_linux_udp_dns_socket_v4(settings),
        SocketAddr::V6(_) => bind_linux_udp_dns_socket_v6(settings),
    };
    match bind_result {
        Ok(socket) => (Some(socket), UdpDnsPreviewStatus::Active),
        Err(err) => (
            None,
            UdpDnsPreviewStatus::BindFailed {
                error_kind: io_error_kind_code(&err),
                error: err.to_string(),
            },
        ),
    }
}

fn bind_linux_udp_dns_socket_v4(
    settings: &WideIngressSettings,
) -> io::Result<AsyncFd<StdUdpSocket>> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    configure_ip_transparent(&socket, settings)?;
    enable_recv_original_dst_v4(&socket)?;
    socket.bind(&settings.listen.into())?;
    socket.set_nonblocking(true)?;
    let std_socket: StdUdpSocket = socket.into();
    // SAFETY: AsyncFd takes ownership of this socket. Its descriptor remains
    // open and unchanged until AsyncFd is dropped.
    unsafe { AsyncFd::register(std_socket) }.map_err(Into::into)
}

fn bind_linux_udp_dns_socket_v6(
    settings: &WideIngressSettings,
) -> io::Result<AsyncFd<StdUdpSocket>> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    // Scope the first IPv6 UDP pass to IPv6 traffic explicitly so the
    // runtime-scope field stays truthful instead of relying on dual-stack defaults.
    socket.set_only_v6(true)?;
    configure_ip_transparent(&socket, settings)?;
    enable_recv_original_dst_v6(&socket)?;
    socket.bind(&settings.listen.into())?;
    socket.set_nonblocking(true)?;
    let std_socket: StdUdpSocket = socket.into();
    // SAFETY: AsyncFd takes ownership of this socket. Its descriptor remains
    // open and unchanged until AsyncFd is dropped.
    unsafe { AsyncFd::register(std_socket) }.map_err(Into::into)
}

#[cfg_attr(not(test), allow(dead_code))]
fn bind_linux_udp_response_socket(
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
    configure_udp_response_ip_transparent(&socket, bind_addr);
    socket.bind(&bind_addr.into())?;
    // Keep the response socket pinned to the intercepted peer so Linux can
    // still route relay->target datagrams to the local smoke echo socket when
    // both sockets share the preserved target tuple via SO_REUSEADDR.
    socket.connect(&peer.into())?;
    socket.set_nonblocking(true)?;
    let std_socket: StdUdpSocket = socket.into();
    UdpSocket::from_std(std_socket)
}

fn configure_udp_response_ip_transparent(socket: &Socket, bind_addr: SocketAddr) {
    let _ = match bind_addr {
        SocketAddr::V4(_) => try_set_ip_transparent_v4(socket),
        SocketAddr::V6(_) => try_set_ip_transparent_v6(socket),
    };
}

fn configure_ip_transparent(socket: &Socket, settings: &WideIngressSettings) -> io::Result<()> {
    match try_set_ip_transparent(socket, settings.listen) {
        Ok(()) => Ok(()),
        Err(err) if requires_successful_ip_transparent(settings) => Err(io::Error::new(
            err.kind(),
            format!(
                "linux_tproxy backend requires successful IP_TRANSPARENT on {}: {}",
                settings.listen, err
            ),
        )),
        Err(_) => Ok(()),
    }
}

fn requires_successful_ip_transparent(settings: &WideIngressSettings) -> bool {
    settings.platform_backend == WidePlatformBackend::LinuxTproxy
}

#[cfg_attr(not(test), allow(dead_code))]
fn supports_narrow_dns_capture(settings: &WideIngressSettings) -> bool {
    settings.capture_dns
}

fn configured_udp_preview_ports(settings: &WideIngressSettings) -> Vec<u16> {
    let mut ports = vec![settings.dns_port];
    for port in &settings.udp_preview_ports {
        if *port != settings.dns_port && !ports.contains(port) {
            ports.push(*port);
        }
    }
    ports
}

fn configured_udp_capture_contract(settings: &WideIngressSettings) -> Option<&'static str> {
    if !settings.capture_dns {
        return None;
    }
    match settings.udp_capture_contract {
        WideUdpCaptureContract::PreviewAllowlistOnly => Some("preview_allowlist_only"),
        // This broader path is still Linux-only and intentionally marked unstable.
        WideUdpCaptureContract::GenericCaptureUnstable => Some("generic_capture_unstable"),
    }
}

fn configured_udp_capture_support_tier(settings: &WideIngressSettings) -> Option<&'static str> {
    if !settings.capture_dns {
        return None;
    }
    match settings.udp_capture_contract {
        // Keep the narrow DNS/allowlist path clearly marked as the supported baseline.
        WideUdpCaptureContract::PreviewAllowlistOnly => Some("supported_preview"),
        // Broader arbitrary-port interception remains intentionally guarded/lab-only.
        WideUdpCaptureContract::GenericCaptureUnstable => Some("guarded_unstable"),
    }
}

fn configured_udp_preview_policy(settings: &WideIngressSettings) -> Option<&'static str> {
    match settings.udp_capture_contract {
        WideUdpCaptureContract::PreviewAllowlistOnly if settings.capture_dns => {
            Some("allowlist_ports")
        }
        _ => None,
    }
}

fn configured_udp_capture_policy(settings: &WideIngressSettings) -> Option<&'static str> {
    if !settings.capture_dns {
        return None;
    }
    match settings.udp_capture_contract {
        WideUdpCaptureContract::PreviewAllowlistOnly => Some("allowlist_ports"),
        WideUdpCaptureContract::GenericCaptureUnstable => match settings.listen {
            SocketAddr::V4(_) => Some("any_target_port_linux_ipv4_unstable"),
            SocketAddr::V6(_) => Some("any_target_port_linux_ipv6_unstable"),
        },
    }
}

fn configured_udp_capture_runtime_scope(settings: &WideIngressSettings) -> Option<&'static str> {
    if !settings.capture_dns {
        return None;
    }
    match settings.listen {
        SocketAddr::V4(_) => Some("linux_ipv4_only"),
        SocketAddr::V6(_) => Some("linux_ipv6_only"),
    }
}

fn configured_udp_preview_event_ports(settings: &WideIngressSettings) -> Vec<u16> {
    if configured_udp_preview_policy(settings).is_some() {
        configured_udp_preview_ports(settings)
    } else {
        Vec::new()
    }
}

fn matches_udp_capture_target_port(settings: &WideIngressSettings, target_port: u16) -> bool {
    if !settings.capture_dns {
        return false;
    }
    match settings.udp_capture_contract {
        WideUdpCaptureContract::PreviewAllowlistOnly => {
            target_port == settings.dns_port || settings.udp_preview_ports.contains(&target_port)
        }
        WideUdpCaptureContract::GenericCaptureUnstable => true,
    }
}

fn io_error_kind_code(err: &io::Error) -> &'static str {
    use io::ErrorKind;

    match err.kind() {
        ErrorKind::NotFound => "not_found",
        ErrorKind::PermissionDenied => "permission_denied",
        ErrorKind::ConnectionRefused => "connection_refused",
        ErrorKind::ConnectionReset => "connection_reset",
        ErrorKind::ConnectionAborted => "connection_aborted",
        ErrorKind::NotConnected => "not_connected",
        ErrorKind::AddrInUse => "addr_in_use",
        ErrorKind::AddrNotAvailable => "addr_not_available",
        ErrorKind::BrokenPipe => "broken_pipe",
        ErrorKind::AlreadyExists => "already_exists",
        ErrorKind::WouldBlock => "would_block",
        ErrorKind::NotADirectory => "not_a_directory",
        ErrorKind::IsADirectory => "is_a_directory",
        ErrorKind::DirectoryNotEmpty => "directory_not_empty",
        ErrorKind::InvalidInput => "invalid_input",
        ErrorKind::InvalidData => "invalid_data",
        ErrorKind::TimedOut => "timed_out",
        ErrorKind::WriteZero => "write_zero",
        ErrorKind::Interrupted => "interrupted",
        ErrorKind::Unsupported => "unsupported",
        ErrorKind::UnexpectedEof => "unexpected_eof",
        _ => "other",
    }
}

impl UdpDnsPreviewStatus {
    fn code(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Active => "active",
            Self::BindFailed { .. } => "bind_failed",
        }
    }

    fn error_kind(&self) -> Option<&'static str> {
        match self {
            Self::BindFailed { error_kind, .. } => Some(*error_kind),
            _ => None,
        }
    }

    fn error(&self) -> Option<&str> {
        match self {
            Self::BindFailed { error, .. } => Some(error.as_str()),
            _ => None,
        }
    }
}

fn enable_recv_original_dst_v4(socket: &Socket) -> io::Result<()> {
    let fd = socket.as_raw_fd();
    let enabled: libc::c_int = 1;
    let value_ptr = &enabled as *const libc::c_int as *const libc::c_void;
    let value_len = size_of::<libc::c_int>() as libc::socklen_t;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_IP,
            IP_RECVORIGDSTADDR_LINUX,
            value_ptr,
            value_len,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn enable_recv_original_dst_v6(socket: &Socket) -> io::Result<()> {
    let fd = socket.as_raw_fd();
    let enabled: libc::c_int = 1;
    let value_ptr = &enabled as *const libc::c_int as *const libc::c_void;
    let value_len = size_of::<libc::c_int>() as libc::socklen_t;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_IPV6,
            libc::IPV6_RECVORIGDSTADDR,
            value_ptr,
            value_len,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn try_set_ip_transparent(socket: &Socket, listen: SocketAddr) -> io::Result<()> {
    match listen {
        SocketAddr::V4(_) => try_set_ip_transparent_v4(socket),
        SocketAddr::V6(_) => try_set_ip_transparent_v6(socket),
    }
}

fn try_set_ip_transparent_v4(socket: &Socket) -> io::Result<()> {
    let fd = socket.as_raw_fd();
    let enabled: libc::c_int = 1;
    let value_ptr = &enabled as *const libc::c_int as *const libc::c_void;
    let value_len = size_of::<libc::c_int>() as libc::socklen_t;
    // `IP_TRANSPARENT` is mandatory for explicit TPROXY mode, but `auto`
    // still tolerates a failure so the same Linux backend can work behind
    // REDIRECT-style NAT rules where `SO_ORIGINAL_DST` is enough.
    let ret =
        unsafe { libc::setsockopt(fd, libc::SOL_IP, libc::IP_TRANSPARENT, value_ptr, value_len) };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn try_set_ip_transparent_v6(socket: &Socket) -> io::Result<()> {
    let fd = socket.as_raw_fd();
    let enabled: libc::c_int = 1;
    let value_ptr = &enabled as *const libc::c_int as *const libc::c_void;
    let value_len = size_of::<libc::c_int>() as libc::socklen_t;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_IPV6,
            libc::IPV6_TRANSPARENT,
            value_ptr,
            value_len,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn original_destination(
    stream: &TcpStream,
    listener_addr: SocketAddr,
    backend: WidePlatformBackend,
) -> io::Result<SocketAddr> {
    let local_addr = stream.local_addr()?;
    match (local_addr, listener_addr) {
        (SocketAddr::V4(local), SocketAddr::V4(listener)) => {
            if use_preserved_local_destination_v4(backend, &local, &listener) {
                Ok(SocketAddr::V4(local))
            } else {
                original_destination_v4(stream)
            }
        }
        (SocketAddr::V6(local), SocketAddr::V6(listener)) => {
            if use_preserved_local_destination_v6(backend, &local, &listener) {
                Ok(SocketAddr::V6(local))
            } else {
                original_destination_v6(stream)
            }
        }
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "linux wide ingress listener/address family mismatch",
        )),
    }
}

fn use_preserved_local_destination_v4(
    backend: WidePlatformBackend,
    local: &SocketAddrV4,
    listener: &SocketAddrV4,
) -> bool {
    match backend {
        // NAT REDIRECT may yield a local address different from a scoped
        // listener. Only the kernel's original-destination socket option is
        // authoritative for this backend.
        WidePlatformBackend::LinuxRedirect => false,
        WidePlatformBackend::LinuxTproxy => !local.ip().is_unspecified(),
        WidePlatformBackend::Auto => prefers_preserved_local_destination(local, listener),
        _ => false,
    }
}

fn use_preserved_local_destination_v6(
    backend: WidePlatformBackend,
    local: &SocketAddrV6,
    listener: &SocketAddrV6,
) -> bool {
    match backend {
        WidePlatformBackend::LinuxRedirect => false,
        WidePlatformBackend::LinuxTproxy => !local.ip().is_unspecified(),
        WidePlatformBackend::Auto => prefers_preserved_local_destination_v6(local, listener),
        _ => false,
    }
}

fn prefers_preserved_local_destination(local: &SocketAddrV4, listener: &SocketAddrV4) -> bool {
    if local.ip().is_unspecified() {
        return false;
    }
    if !listener.ip().is_unspecified() {
        return local != listener;
    }
    !(local.ip().is_loopback() && local.port() == listener.port())
}

fn prefers_preserved_local_destination_v6(local: &SocketAddrV6, listener: &SocketAddrV6) -> bool {
    if local.ip().is_unspecified() {
        return false;
    }
    if !listener.ip().is_unspecified() {
        return local != listener;
    }
    !(local.ip().is_loopback() && local.port() == listener.port())
}

fn original_destination_v4(stream: &TcpStream) -> io::Result<SocketAddr> {
    let fd = stream.as_raw_fd();
    let mut addr: libc::sockaddr_in = unsafe { zeroed() };
    let mut len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            SO_ORIGINAL_DST_LINUX,
            &mut addr as *mut libc::sockaddr_in as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    if len < size_of::<libc::sockaddr_in>() as libc::socklen_t {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short SO_ORIGINAL_DST response",
        ));
    }
    let port = u16::from_be(addr.sin_port);
    let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
}

fn original_destination_v6(stream: &TcpStream) -> io::Result<SocketAddr> {
    let fd = stream.as_raw_fd();
    let mut addr: libc::sockaddr_in6 = unsafe { zeroed() };
    let mut len = size_of::<libc::sockaddr_in6>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IPV6,
            libc::IP6T_SO_ORIGINAL_DST,
            &mut addr as *mut libc::sockaddr_in6 as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    if len < size_of::<libc::sockaddr_in6>() as libc::socklen_t {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short IP6T_SO_ORIGINAL_DST response",
        ));
    }
    let port = u16::from_be(addr.sin6_port);
    let ip = std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr);
    Ok(SocketAddr::V6(SocketAddrV6::new(
        ip,
        port,
        addr.sin6_flowinfo,
        addr.sin6_scope_id,
    )))
}

struct ReceivedDnsDatagram {
    peer: SocketAddr,
    target: ConnectTarget,
    response_bind: SocketAddr,
    payload: Vec<u8>,
}

async fn accept_dns_udp_intent(
    udp_dns_socket: &AsyncFd<StdUdpSocket>,
    settings: &WideIngressSettings,
) -> io::Result<IngressSessionIntent> {
    loop {
        let datagram = recv_dns_datagram(udp_dns_socket)
            .await
            .map_err(|source| stage_io_error("wide_dns_recv", source))?;
        if !matches_udp_capture_target_port(settings, datagram.target.port) {
            let wide_udp_capture_contract = configured_udp_capture_contract(settings);
            let wide_udp_capture_support_tier = configured_udp_capture_support_tier(settings);
            let wide_udp_capture_policy = configured_udp_capture_policy(settings);
            let wide_udp_capture_runtime_scope = configured_udp_capture_runtime_scope(settings);
            let wide_udp_preview_policy = configured_udp_preview_policy(settings);
            let expected_udp_preview_ports = configured_udp_preview_event_ports(settings);
            let wide_udp_capture_drop_stage = "capture_policy_gate";
            let wide_udp_capture_drop_reason_code = "target_port_outside_capture_policy";
            tracing::info!(
                event_code = RuntimeEventCode::IngressUdpDatagramDropped.as_str(),
                peer = %datagram.peer,
                target_host = %datagram.target.host,
                target_port = datagram.target.port,
                payload_len = datagram.payload.len(),
                wide_udp_capture_contract = ?wide_udp_capture_contract,
                wide_udp_capture_support_tier = ?wide_udp_capture_support_tier,
                wide_udp_capture_policy = ?wide_udp_capture_policy,
                wide_udp_capture_runtime_scope = ?wide_udp_capture_runtime_scope,
                wide_udp_capture_drop_stage = wide_udp_capture_drop_stage,
                wide_udp_capture_drop_reason_code = wide_udp_capture_drop_reason_code,
                wide_udp_preview_policy = ?wide_udp_preview_policy,
                expected_dns_port = settings.dns_port,
                expected_udp_preview_ports = ?expected_udp_preview_ports,
                drop_reason_code = "target_port_not_udp_preview",
                "ingress udp datagram dropped"
            );
            runtime_jsonl::emit(
                "info",
                RuntimeEventCode::IngressUdpDatagramDropped,
                "ingress udp datagram dropped",
                json!({
                    "peer": datagram.peer.to_string(),
                    "startup_path_code": "wide_primary_started",
                    "startup_fallback_reason_code": null,
                    "startup_fallback_reason": null,
                    "startup_bind_error_code": null,
                    "target_host": datagram.target.host,
                    "target_port": datagram.target.port,
                    "payload_len": datagram.payload.len(),
                    "wide_udp_capture_contract": wide_udp_capture_contract,
                    "wide_udp_capture_support_tier": wide_udp_capture_support_tier,
                    "wide_udp_capture_policy": wide_udp_capture_policy,
                    "wide_udp_capture_runtime_scope": wide_udp_capture_runtime_scope,
                    "wide_udp_capture_drop_stage": wide_udp_capture_drop_stage,
                    "wide_udp_capture_drop_reason_code": wide_udp_capture_drop_reason_code,
                    "wide_udp_preview_policy": wide_udp_preview_policy,
                    "expected_dns_port": settings.dns_port,
                    "expected_udp_preview_ports": expected_udp_preview_ports,
                    "drop_reason_code": "target_port_not_udp_preview"
                }),
            );
            continue;
        }
        // Keep the return path anchored to the preserved original destination
        // instead of replying from the wide listener socket. Defer binding
        // the response socket until the relay has received a target response,
        // otherwise same-gateway UDP targets can lose the request to this
        // preserved-tuple response socket.
        return Ok(IngressSessionIntent {
            kind: IngressKind::WidePrimary,
            peer: datagram.peer,
            transport: IngressTransport::UdpDatagram(UdpDatagramIntent {
                control: UdpSessionControl::Detached,
                client_ip: datagram.peer.ip(),
                target: datagram.target,
                payload: datagram.payload,
                response: UdpDatagramResponse::DeferredLocalUdp {
                    bind_addr: datagram.response_bind,
                    peer: datagram.peer,
                },
            }),
        });
    }
}

async fn recv_dns_datagram(
    udp_dns_socket: &AsyncFd<StdUdpSocket>,
) -> io::Result<ReceivedDnsDatagram> {
    loop {
        let mut ready = udp_dns_socket.readable().await?;
        let recv = ready.try_io(|inner| recv_dns_datagram_once(inner.get_ref()));
        match recv {
            Ok(result) => return result,
            Err(_would_block) => continue,
        }
    }
}

fn recv_dns_datagram_once(socket: &StdUdpSocket) -> io::Result<ReceivedDnsDatagram> {
    match socket.local_addr()? {
        SocketAddr::V4(_) => recv_dns_datagram_once_v4(socket),
        SocketAddr::V6(_) => recv_dns_datagram_once_v6(socket),
    }
}

// `as usize` on msg_controllen/cmsg_len is a no-op on glibc (already usize) but
// REQUIRED on musl where these are socklen_t (u32). Keep the cast for musl cross
// builds (AlmaLinux/RHEL); allow the glibc-side unnecessary_cast lint.
#[allow(clippy::unnecessary_cast)]
fn recv_dns_datagram_once_v4(socket: &StdUdpSocket) -> io::Result<ReceivedDnsDatagram> {
    let fd = socket.as_raw_fd();
    let mut payload = [0u8; 4096];
    let mut peer_addr: libc::sockaddr_storage = unsafe { zeroed() };
    let mut control = ControlBuffer::<{ cmsg_space(size_of::<libc::sockaddr_in>()) }>::new();
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_name = &mut peer_addr as *mut libc::sockaddr_storage as *mut libc::c_void;
    msg.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr();
    msg.msg_controllen = control.len() as _;

    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let peer = parse_recv_peer_v4(&peer_addr, msg.msg_namelen)
        .map_err(|source| stage_io_error("wide_dns_peer", source))?;
    let target = parse_udp_original_destination_v4(
        control.received(msg.msg_controllen as usize, msg.msg_flags)?,
    )
    .map_err(|source| stage_io_error("wide_dns_original_destination", source))?;
    Ok(ReceivedDnsDatagram {
        peer,
        target: ConnectTarget {
            host: target.ip().to_string(),
            port: target.port(),
        },
        response_bind: SocketAddr::V4(target),
        payload: payload[..n as usize].to_vec(),
    })
}

#[allow(clippy::unnecessary_cast)] // glibc usize vs musl socklen_t(u32) — see v4
fn recv_dns_datagram_once_v6(socket: &StdUdpSocket) -> io::Result<ReceivedDnsDatagram> {
    let fd = socket.as_raw_fd();
    let mut payload = [0u8; 4096];
    let mut peer_addr: libc::sockaddr_storage = unsafe { zeroed() };
    let mut control = ControlBuffer::<{ cmsg_space(size_of::<libc::sockaddr_in6>()) }>::new();
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_name = &mut peer_addr as *mut libc::sockaddr_storage as *mut libc::c_void;
    msg.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr();
    msg.msg_controllen = control.len() as _;

    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let peer = parse_recv_peer_v6(&peer_addr, msg.msg_namelen)
        .map_err(|source| stage_io_error("wide_dns_peer", source))?;
    let target = parse_udp_original_destination_v6(
        control.received(msg.msg_controllen as usize, msg.msg_flags)?,
    )
    .map_err(|source| stage_io_error("wide_dns_original_destination", source))?;
    Ok(ReceivedDnsDatagram {
        peer,
        target: ConnectTarget {
            host: target.ip().to_string(),
            port: target.port(),
        },
        response_bind: SocketAddr::V6(target),
        payload: payload[..n as usize].to_vec(),
    })
}

fn parse_recv_peer_v4(
    peer_addr: &libc::sockaddr_storage,
    name_len: libc::socklen_t,
) -> io::Result<SocketAddr> {
    if name_len < size_of::<libc::sockaddr_in>() as libc::socklen_t {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short UDP peer sockaddr",
        ));
    }
    if peer_addr.ss_family as libc::c_int != libc::AF_INET {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "narrow DNS capture currently expects IPv4 UDP peers",
        ));
    }
    // SAFETY: the initialized sockaddr_storage and checked name length contain
    // the entire integer-only address. Copying avoids an aliased typed reference.
    let addr = unsafe {
        (peer_addr as *const libc::sockaddr_storage)
            .cast::<libc::sockaddr_in>()
            .read_unaligned()
    };
    let port = u16::from_be(addr.sin_port);
    let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
}

fn parse_recv_peer_v6(
    peer_addr: &libc::sockaddr_storage,
    name_len: libc::socklen_t,
) -> io::Result<SocketAddr> {
    if name_len < size_of::<libc::sockaddr_in6>() as libc::socklen_t {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short UDP peer sockaddr",
        ));
    }
    if peer_addr.ss_family as libc::c_int != libc::AF_INET6 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "linux IPv6 UDP capture currently expects IPv6 UDP peers",
        ));
    }
    // SAFETY: the initialized sockaddr_storage and checked name length contain
    // the entire integer-only address. Copying avoids an aliased typed reference.
    let addr = unsafe {
        (peer_addr as *const libc::sockaddr_storage)
            .cast::<libc::sockaddr_in6>()
            .read_unaligned()
    };
    let port = u16::from_be(addr.sin6_port);
    let ip = std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr);
    Ok(SocketAddr::V6(SocketAddrV6::new(
        ip,
        port,
        addr.sin6_flowinfo,
        addr.sin6_scope_id,
    )))
}

fn parse_udp_original_destination_v4(control: &[u8]) -> io::Result<SocketAddrV4> {
    ancillary::original_destination_v4(control, libc::SOL_IP, IP_ORIGDSTADDR_LINUX)
}

fn parse_udp_original_destination_v6(control: &[u8]) -> io::Result<SocketAddrV6> {
    ancillary::original_destination_v6(control, libc::SOL_IPV6, libc::IPV6_ORIGDSTADDR)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn required_dns_owner_loss_wakes_backend_and_revokes_readiness() {
        let settings = WideIngressSettings {
            listen: "127.0.0.1:0".parse().unwrap(),
            capture_dns: false,
            dns_preview_listen: Some("127.0.0.1:0".parse().unwrap()),
            ..Default::default()
        };
        let backend = LinuxWidePrimaryBackend::bind(settings).await.unwrap();
        assert!(backend.is_available());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), backend.failure())
                .await
                .is_err()
        );
        // Remove the real listener owner while the TCP listener stays bound;
        // an idle supervisor must wake without another connection or DNS query.
        let owner = backend.dns_preview_listener.lock().unwrap().take().unwrap();
        drop(owner);
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(1), backend.failure())
                .await
                .unwrap(),
            "required_dns_preview_listener"
        );
        assert!(!backend.is_available());
    }

    #[tokio::test]
    async fn disabled_dns_has_no_false_background_failure() {
        let backend = LinuxWidePrimaryBackend::bind(WideIngressSettings {
            listen: "127.0.0.1:0".parse().unwrap(),
            capture_dns: false,
            dns_preview_listen: None,
            ..Default::default()
        })
        .await
        .unwrap();
        assert!(backend.is_available());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), backend.failure())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn backend_dns_owner_shutdown_releases_bind_and_shares_map() {
        let settings = WideIngressSettings {
            listen: "127.0.0.1:0".parse().unwrap(),
            capture_dns: false,
            dns_preview_listen: Some("127.0.0.1:0".parse().unwrap()),
            ..Default::default()
        };
        let backend = LinuxWidePrimaryBackend::bind(settings.clone())
            .await
            .unwrap();
        let listen = {
            let owner = backend.dns_preview_listener.lock().unwrap();
            let listener = owner.as_ref().unwrap();
            assert!(Arc::ptr_eq(&backend.fake_ip_map().unwrap(), &listener.map));
            listener.listen
        };
        backend.shutdown().await;
        backend.shutdown().await; // idempotent owner take
        let settings = WideIngressSettings {
            dns_preview_listen: Some(listen),
            ..settings
        };
        let rebound = LinuxWidePrimaryBackend::bind(settings).await.unwrap();
        rebound.shutdown().await;
    }

    #[tokio::test]
    async fn cancelled_startup_drops_backend_dns_owner() {
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let startup = tokio::spawn(async move {
            let settings = WideIngressSettings {
                listen: "127.0.0.1:0".parse().unwrap(),
                capture_dns: false,
                dns_preview_listen: Some("127.0.0.1:0".parse().unwrap()),
                ..Default::default()
            };
            let backend = LinuxWidePrimaryBackend::bind(settings).await.unwrap();
            let listen = backend
                .dns_preview_listener
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .listen;
            let map = Arc::downgrade(backend.fake_ip_map.as_ref().unwrap());
            ready_tx.send((listen, map)).unwrap();
            // Simulate cancellation of a later startup stage after DNS bound.
            std::future::pending::<()>().await;
            drop(backend);
        });
        let (listen, map) = tokio::time::timeout(std::time::Duration::from_secs(2), ready_rx)
            .await
            .unwrap()
            .unwrap();
        startup.abort();
        assert!(startup.await.unwrap_err().is_cancelled());
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while map.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("DNS task releases shared map after cancellation");
        UdpSocket::bind(listen)
            .await
            .expect("cancelled startup releases DNS socket");
    }

    #[test]
    fn linux_backend_supports_auto_and_explicit_linux_modes() {
        let mut settings = WideIngressSettings::default();
        assert!(LinuxWidePrimaryBackend::supports_platform(&settings));
        settings.platform_backend = WidePlatformBackend::LinuxRedirect;
        assert!(LinuxWidePrimaryBackend::supports_platform(&settings));
        settings.platform_backend = WidePlatformBackend::LinuxTproxy;
        assert!(LinuxWidePrimaryBackend::supports_platform(&settings));
    }

    #[test]
    fn linux_backend_rejects_other_platform_modes() {
        let mut settings = WideIngressSettings {
            platform_backend: WidePlatformBackend::Windivert,
            ..WideIngressSettings::default()
        };
        assert!(!LinuxWidePrimaryBackend::supports_platform(&settings));
        settings.platform_backend = WidePlatformBackend::MacosPf;
        assert!(!LinuxWidePrimaryBackend::supports_platform(&settings));
    }

    #[test]
    fn preserved_local_destination_prefers_real_target_over_wildcard_listener() {
        let local = "93.184.216.34:443".parse::<SocketAddrV4>().unwrap();
        let listener = "0.0.0.0:15080".parse::<SocketAddrV4>().unwrap();
        assert!(prefers_preserved_local_destination(&local, &listener));
    }

    #[test]
    fn preserved_local_destination_rejects_loopback_redirect_shape() {
        let local = "127.0.0.1:15080".parse::<SocketAddrV4>().unwrap();
        let listener = "0.0.0.0:15080".parse::<SocketAddrV4>().unwrap();
        assert!(!prefers_preserved_local_destination(&local, &listener));
    }

    #[test]
    fn scoped_linux_redirect_requires_original_dst_even_if_local_differs() {
        let local = "10.231.81.1:15080".parse::<SocketAddrV4>().unwrap();
        let listener = "127.0.0.1:15080".parse::<SocketAddrV4>().unwrap();
        assert!(prefers_preserved_local_destination(&local, &listener));
        assert!(!use_preserved_local_destination_v4(
            WidePlatformBackend::LinuxRedirect,
            &local,
            &listener
        ));
        assert!(use_preserved_local_destination_v4(
            WidePlatformBackend::LinuxTproxy,
            &local,
            &listener
        ));
        assert!(use_preserved_local_destination_v4(
            WidePlatformBackend::Auto,
            &local,
            &listener
        ));
    }

    #[test]
    fn ipv6_redirect_and_tproxy_keep_distinct_destination_sources() {
        let local = "[2001:db8::1]:443".parse::<SocketAddrV6>().unwrap();
        let listener = "[::]:15080".parse::<SocketAddrV6>().unwrap();
        assert!(!use_preserved_local_destination_v6(
            WidePlatformBackend::LinuxRedirect,
            &local,
            &listener
        ));
        assert!(use_preserved_local_destination_v6(
            WidePlatformBackend::LinuxTproxy,
            &local,
            &listener
        ));
    }

    #[test]
    fn explicit_tproxy_backend_requires_ip_transparent() {
        let settings = WideIngressSettings {
            platform_backend: WidePlatformBackend::LinuxTproxy,
            ..WideIngressSettings::default()
        };
        assert!(requires_successful_ip_transparent(&settings));
    }

    #[test]
    fn auto_backend_tolerates_missing_ip_transparent() {
        let settings = WideIngressSettings::default();
        assert!(!requires_successful_ip_transparent(&settings));
    }

    #[test]
    fn preserved_ipv6_local_destination_prefers_real_target_over_wildcard_listener() {
        let local = "[2001:db8::1]:443".parse::<SocketAddrV6>().unwrap();
        let listener = "[::]:15080".parse::<SocketAddrV6>().unwrap();
        assert!(prefers_preserved_local_destination_v6(&local, &listener));
    }

    #[test]
    fn preserved_ipv6_local_destination_rejects_loopback_redirect_shape() {
        let local = "[::1]:15080".parse::<SocketAddrV6>().unwrap();
        let listener = "[::]:15080".parse::<SocketAddrV6>().unwrap();
        assert!(!prefers_preserved_local_destination_v6(&local, &listener));
    }

    #[test]
    fn dns_capture_preview_support_tracks_capture_flag() {
        let mut settings = WideIngressSettings::default();
        assert!(supports_narrow_dns_capture(&settings));
        settings.listen = "[::]:15080".parse().expect("ipv6 listen");
        assert!(supports_narrow_dns_capture(&settings));
        settings.listen = "0.0.0.0:15080".parse().expect("ipv4 listen");
        settings.capture_dns = false;
        assert!(!supports_narrow_dns_capture(&settings));
    }

    #[test]
    fn dns_preview_target_port_follows_configured_dns_port() {
        let mut settings = WideIngressSettings::default();
        assert!(matches_udp_capture_target_port(&settings, 53));
        settings.dns_port = 5353;
        assert!(matches_udp_capture_target_port(&settings, 5353));
        assert!(!matches_udp_capture_target_port(&settings, 53));
    }

    #[test]
    fn udp_preview_target_ports_include_extra_configured_ports() {
        let settings = WideIngressSettings {
            udp_preview_ports: vec![5353, 853, 53, 5353],
            ..WideIngressSettings::default()
        };

        assert_eq!(configured_udp_preview_ports(&settings), vec![53, 5353, 853]);
        assert!(matches_udp_capture_target_port(&settings, 53));
        assert!(matches_udp_capture_target_port(&settings, 5353));
        assert!(matches_udp_capture_target_port(&settings, 853));
        assert!(!matches_udp_capture_target_port(&settings, 12345));
    }

    #[test]
    fn generic_udp_capture_contract_accepts_arbitrary_target_ports() {
        let mut settings = WideIngressSettings {
            udp_capture_contract: WideUdpCaptureContract::GenericCaptureUnstable,
            ..WideIngressSettings::default()
        };

        assert!(matches_udp_capture_target_port(&settings, 53));
        assert!(matches_udp_capture_target_port(&settings, 5353));
        assert!(matches_udp_capture_target_port(&settings, 12345));
        assert_eq!(
            configured_udp_capture_contract(&settings),
            Some("generic_capture_unstable")
        );
        assert_eq!(
            configured_udp_capture_policy(&settings),
            Some("any_target_port_linux_ipv4_unstable")
        );
        settings.listen = "[::]:15080".parse().expect("ipv6 listen");
        assert_eq!(
            configured_udp_capture_policy(&settings),
            Some("any_target_port_linux_ipv6_unstable")
        );
        assert_eq!(
            configured_udp_capture_runtime_scope(&settings),
            Some("linux_ipv6_only")
        );
        assert_eq!(configured_udp_preview_policy(&settings), None);
        assert!(configured_udp_preview_event_ports(&settings).is_empty());
    }

    #[test]
    fn parses_udp_original_destination_v4_from_control_message() {
        let expected = "1.1.1.1:53".parse::<SocketAddrV4>().unwrap();
        let control = ancillary::tests::control_v4(expected, libc::SOL_IP, IP_ORIGDSTADDR_LINUX);
        assert_eq!(
            parse_udp_original_destination_v4(&control).unwrap(),
            expected
        );
    }

    #[test]
    fn parses_udp_original_destination_v6_from_control_message() {
        let expected = SocketAddrV6::new(std::net::Ipv6Addr::LOCALHOST, 5353, 7, 9);
        let control =
            ancillary::tests::control_v6(expected, libc::SOL_IPV6, libc::IPV6_ORIGDSTADDR);
        assert_eq!(
            parse_udp_original_destination_v6(&control).unwrap(),
            expected
        );
    }

    #[tokio::test]
    async fn bind_rejects_configured_dns_listener_conflict_before_ready() {
        let occupied = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("occupy loopback UDP port");
        let dns_listen = occupied.local_addr().expect("occupied address");
        for capture_dns in [false, true] {
            let settings = WideIngressSettings {
                listen: "127.0.0.1:0".parse().expect("listen"),
                dns_preview_listen: Some(dns_listen),
                capture_dns,
                ..WideIngressSettings::default()
            };

            let error = LinuxWidePrimaryBackend::bind(settings)
                .await
                .err()
                .expect("required DNS listener must prevent backend readiness");
            assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
            assert!(error.to_string().starts_with("wide_dns_preview_listener:"));
            assert!(error.to_string().contains(&dns_listen.to_string()));
        }
    }

    #[tokio::test]
    async fn bind_rejects_configured_dns_listener_invalid_pool_before_ready() {
        let settings = WideIngressSettings {
            listen: "127.0.0.1:0".parse().expect("listen"),
            capture_dns: false,
            dns_preview_listen: Some("127.0.0.1:0".parse().expect("DNS listen")),
            dns_preview_fake_ip_pool: "invalid-pool".to_string(),
            ..WideIngressSettings::default()
        };

        let error = LinuxWidePrimaryBackend::bind(settings)
            .await
            .err()
            .expect("required DNS pool must prevent backend readiness");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().starts_with("wide_dns_preview_listener:"));
        assert!(error.to_string().contains("pool invalid-pool"));
    }

    #[tokio::test]
    async fn bind_starts_configured_dns_listener_without_legacy_capture() {
        let settings = WideIngressSettings {
            listen: "127.0.0.1:0".parse().expect("listen"),
            capture_dns: false,
            dns_preview_listen: Some("127.0.0.1:0".parse().expect("DNS listen")),
            ..WideIngressSettings::default()
        };

        let backend = LinuxWidePrimaryBackend::bind(settings)
            .await
            .expect("bind backend and required DNS listener");
        assert!(backend.fake_ip_map.is_some());
        assert_eq!(
            backend.runtime_status().wide_dns_capture_preview_status,
            Some("disabled")
        );
    }

    #[tokio::test]
    async fn bind_keeps_legacy_dns_capture_conflict_best_effort() {
        let occupied = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("occupy loopback UDP port");
        let settings = WideIngressSettings {
            listen: occupied.local_addr().expect("occupied address"),
            capture_dns: true,
            dns_preview_listen: None,
            ..WideIngressSettings::default()
        };

        let backend = LinuxWidePrimaryBackend::bind(settings)
            .await
            .expect("legacy DNS capture remains best-effort");
        assert!(backend.fake_ip_map.is_none());
        assert_eq!(
            backend.runtime_status().wide_dns_capture_preview_status,
            Some("bind_failed")
        );
    }

    #[tokio::test]
    async fn bind_reports_active_dns_preview_status_for_ipv4_capture_dns() {
        let settings = WideIngressSettings {
            listen: "127.0.0.1:0".parse().expect("listen"),
            capture_dns: true,
            ..WideIngressSettings::default()
        };
        let backend = LinuxWidePrimaryBackend::bind(settings)
            .await
            .expect("bind backend");
        let status = backend.runtime_status();
        assert_eq!(status.wide_dns_capture_preview_status, Some("active"));
        assert_eq!(status.wide_dns_capture_preview_error_kind, None);
        assert_eq!(status.wide_dns_capture_preview_error, None);
        assert_eq!(
            status.wide_udp_capture_contract,
            Some("preview_allowlist_only")
        );
        assert_eq!(status.wide_udp_capture_policy, Some("allowlist_ports"));
        assert_eq!(
            status.wide_udp_capture_runtime_scope,
            Some("linux_ipv4_only")
        );
        assert_eq!(status.wide_udp_preview_policy, Some("allowlist_ports"));
        assert_eq!(status.wide_udp_preview_ports, vec![53]);
    }

    #[tokio::test]
    async fn bind_reports_generic_udp_capture_contract_for_unstable_mode() {
        let settings = WideIngressSettings {
            listen: "127.0.0.1:0".parse().expect("listen"),
            capture_dns: true,
            udp_capture_contract: WideUdpCaptureContract::GenericCaptureUnstable,
            ..WideIngressSettings::default()
        };
        let backend = LinuxWidePrimaryBackend::bind(settings)
            .await
            .expect("bind backend");
        let status = backend.runtime_status();
        assert_eq!(status.wide_dns_capture_preview_status, Some("active"));
        assert_eq!(
            status.wide_udp_capture_contract,
            Some("generic_capture_unstable")
        );
        assert_eq!(
            status.wide_udp_capture_policy,
            Some("any_target_port_linux_ipv4_unstable")
        );
        assert_eq!(
            status.wide_udp_capture_runtime_scope,
            Some("linux_ipv4_only")
        );
        assert_eq!(status.wide_udp_preview_policy, None);
        assert!(status.wide_udp_preview_ports.is_empty());
    }

    #[tokio::test]
    async fn udp_response_socket_binds_to_requested_local_target() {
        let socket = bind_linux_udp_response_socket(
            "127.0.0.1:0".parse().expect("bind addr"),
            "127.0.0.1:9".parse().expect("peer addr"),
        )
        .expect("bind response socket");
        assert!(socket.local_addr().expect("local addr").ip().is_loopback());
    }

    #[tokio::test]
    async fn bind_reports_active_dns_preview_status_for_ipv6_capture_dns() {
        let settings = WideIngressSettings {
            listen: "[::1]:0".parse().expect("listen"),
            capture_dns: true,
            ..WideIngressSettings::default()
        };
        let backend = LinuxWidePrimaryBackend::bind(settings)
            .await
            .expect("bind backend");
        let status = backend.runtime_status();
        assert_eq!(status.wide_dns_capture_preview_status, Some("active"));
        assert_eq!(status.wide_dns_capture_preview_error_kind, None);
        assert_eq!(status.wide_dns_capture_preview_error, None);
        assert_eq!(
            status.wide_udp_capture_contract,
            Some("preview_allowlist_only")
        );
        assert_eq!(status.wide_udp_capture_policy, Some("allowlist_ports"));
        assert_eq!(
            status.wide_udp_capture_runtime_scope,
            Some("linux_ipv6_only")
        );
        assert_eq!(status.wide_udp_preview_policy, Some("allowlist_ports"));
        assert_eq!(status.wide_udp_preview_ports, vec![53]);
    }

    #[tokio::test]
    async fn bind_reports_generic_udp_capture_contract_for_unstable_mode_ipv6() {
        let settings = WideIngressSettings {
            listen: "[::1]:0".parse().expect("listen"),
            capture_dns: true,
            udp_capture_contract: WideUdpCaptureContract::GenericCaptureUnstable,
            ..WideIngressSettings::default()
        };
        let backend = LinuxWidePrimaryBackend::bind(settings)
            .await
            .expect("bind backend");
        let status = backend.runtime_status();
        assert_eq!(status.wide_dns_capture_preview_status, Some("active"));
        assert_eq!(
            status.wide_udp_capture_contract,
            Some("generic_capture_unstable")
        );
        assert_eq!(
            status.wide_udp_capture_policy,
            Some("any_target_port_linux_ipv6_unstable")
        );
        assert_eq!(
            status.wide_udp_capture_runtime_scope,
            Some("linux_ipv6_only")
        );
        assert_eq!(status.wide_udp_preview_policy, None);
        assert!(status.wide_udp_preview_ports.is_empty());
    }

    #[tokio::test]
    async fn bind_reports_disabled_dns_preview_status_when_capture_dns_is_off() {
        let settings = WideIngressSettings {
            listen: "127.0.0.1:0".parse().expect("listen"),
            capture_dns: false,
            ..WideIngressSettings::default()
        };
        let backend = LinuxWidePrimaryBackend::bind(settings)
            .await
            .expect("bind backend");
        let status = backend.runtime_status();
        assert_eq!(status.wide_dns_capture_preview_status, Some("disabled"));
        assert_eq!(status.wide_dns_capture_preview_error_kind, None);
        assert_eq!(status.wide_dns_capture_preview_error, None);
        assert_eq!(status.wide_udp_capture_policy, None);
        assert_eq!(status.wide_udp_capture_runtime_scope, None);
        assert_eq!(status.wide_udp_preview_policy, None);
        assert!(status.wide_udp_preview_ports.is_empty());
    }

    #[tokio::test]
    async fn bind_reports_active_dns_preview_status_for_ipv6_anyaddr() {
        let settings = WideIngressSettings {
            listen: "[::]:0".parse().expect("listen"),
            capture_dns: true,
            ..WideIngressSettings::default()
        };
        let backend = LinuxWidePrimaryBackend::bind(settings)
            .await
            .expect("bind backend");
        let status = backend.runtime_status();
        assert_eq!(status.wide_dns_capture_preview_status, Some("active"));
        assert_eq!(status.wide_dns_capture_preview_error_kind, None);
        assert_eq!(status.wide_dns_capture_preview_error, None);
        assert_eq!(
            status.wide_udp_capture_contract,
            Some("preview_allowlist_only")
        );
        assert_eq!(status.wide_udp_capture_policy, Some("allowlist_ports"));
        assert_eq!(
            status.wide_udp_capture_runtime_scope,
            Some("linux_ipv6_only")
        );
        assert_eq!(status.wide_udp_preview_policy, Some("allowlist_ports"));
        assert_eq!(status.wide_udp_preview_ports, vec![53]);
    }

    #[tokio::test]
    async fn accept_prefixes_original_destination_failures_with_stage() {
        let settings = WideIngressSettings {
            listen: "127.0.0.1:0".parse().expect("listen"),
            ..WideIngressSettings::default()
        };
        let backend = LinuxWidePrimaryBackend::bind(settings)
            .await
            .expect("bind backend");
        let listen = backend.listener.local_addr().expect("listener addr");

        let server = tokio::spawn(async move { backend.accept().await });

        let client = TcpStream::connect(listen).await.expect("connect client");
        drop(client);

        match server.await.expect("join accept task") {
            Ok(intent) => {
                assert_eq!(intent.kind, IngressKind::WidePrimary);
                match intent.transport {
                    IngressTransport::TcpConnect(tcp) => {
                        assert_eq!(tcp.target.host, "127.0.0.1");
                        assert_eq!(tcp.target.port, listen.port());
                        assert_eq!(tcp.response, IngressResponse::None);
                    }
                    IngressTransport::UdpAssociate(_) => {
                        panic!("unexpected UDP transport for wide TCP accept")
                    }
                    IngressTransport::UdpDatagram(_) => {
                        panic!("unexpected native UDP datagram transport for wide TCP accept")
                    }
                }
            }
            Err(err) => {
                assert!(
                    err.to_string().starts_with("wide_original_destination:"),
                    "unexpected error: {err}"
                );
            }
        }
    }

    /// An accepted loopback connection and its peer.
    async fn accepted_loopback() -> (TcpStream, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let _app = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        listener.accept().await.unwrap()
    }

    /// A relayed TCP session to a fake IP holds its binding, as the packet
    /// engine and the UDP redirect proxy do: while it lives the address never
    /// goes to another name, and its idle time starts when it ends.
    #[tokio::test]
    async fn a_tcp_session_to_a_fake_ip_keeps_its_address_bound_until_it_ends() {
        // One usable address: another name can only get it by recycling.
        let map = FakeIpMap::new("198.19.255.252/30", std::time::Duration::from_secs(60)).unwrap();
        let (ip, _) = map.assign("old.test").unwrap();
        let (client, peer) = accepted_loopback().await;
        let intent =
            tcp_connect_intent(client, peer, SocketAddr::from((ip, 443)), Some(&map)).unwrap();
        match &intent.transport {
            IngressTransport::TcpConnect(tcp) => assert_eq!(
                tcp.target,
                ConnectTarget {
                    host: "old.test".into(),
                    port: 443
                }
            ),
            _ => panic!("a TCP connect"),
        }
        map.expire_mapping_for_test(ip);
        assert_eq!(
            map.assign("new.test"),
            None,
            "a live session's address went to another name"
        );
        drop(intent);
        assert_eq!(
            map.assign("new.test"),
            None,
            "the session's end restarts the idle time"
        );
        map.expire_mapping_for_test(ip);
        assert_eq!(map.assign("new.test"), Some((ip, true)));
    }

    /// A dual-stack listener sees an IPv4 connection to a fake IP as its
    /// IPv4-mapped address: the same binding, recovered and held the same way.
    #[tokio::test]
    async fn a_tcp_session_to_an_ipv4_mapped_fake_ip_holds_the_same_binding() {
        let map = FakeIpMap::new("198.19.255.252/30", std::time::Duration::from_secs(60)).unwrap();
        let (ip, _) = map.assign("old.test").unwrap();
        let (client, peer) = accepted_loopback().await;
        let mapped = SocketAddr::new(std::net::IpAddr::V6(ip.to_ipv6_mapped()), 443);
        let intent = tcp_connect_intent(client, peer, mapped, Some(&map)).unwrap();
        match &intent.transport {
            IngressTransport::TcpConnect(tcp) => assert_eq!(tcp.target.host, "old.test"),
            _ => panic!("a TCP connect"),
        }
        map.expire_mapping_for_test(ip);
        assert_eq!(
            map.assign("new.test"),
            None,
            "a live session's address went to another name"
        );
        drop(intent);
        map.expire_mapping_for_test(ip);
        assert_eq!(map.assign("new.test"), Some((ip, true)));
    }

    /// A pool address the preview never answered fails closed, IPv4 or
    /// IPv4-mapped.
    #[tokio::test]
    async fn a_tcp_connect_to_an_unanswered_fake_ip_fails_closed() {
        let map = FakeIpMap::new("198.18.0.0/29", std::time::Duration::from_secs(60)).unwrap();
        let unanswered = std::net::Ipv4Addr::new(198, 18, 0, 5);
        for destination in [
            SocketAddr::from((unanswered, 443)),
            SocketAddr::new(std::net::IpAddr::V6(unanswered.to_ipv6_mapped()), 443),
        ] {
            let (client, peer) = accepted_loopback().await;
            let error = tcp_connect_intent(client, peer, destination, Some(&map))
                .err()
                .expect("an unanswered fake IP is refused");
            assert_eq!(error.kind(), io::ErrorKind::NotFound, "{destination}");
        }
    }

    /// The session takes the lease before the broker consumes the intent
    /// (main.rs), so the binding outlives the intent; a numeric target needs
    /// none.
    #[tokio::test]
    async fn a_taken_target_lease_outlives_the_consumed_intent() {
        let map = FakeIpMap::new("198.19.255.252/30", std::time::Duration::from_secs(60)).unwrap();
        let (ip, _) = map.assign("old.test").unwrap();
        let (client, peer) = accepted_loopback().await;
        let mut intent =
            tcp_connect_intent(client, peer, SocketAddr::from((ip, 443)), Some(&map)).unwrap();
        let lease = intent.take_target_lease();
        assert!(lease.is_some());
        assert!(intent.take_target_lease().is_none(), "taken once");
        drop(intent);
        map.expire_mapping_for_test(ip);
        assert_eq!(map.assign("new.test"), None, "the lease holds the binding");
        drop(lease);
        map.expire_mapping_for_test(ip);
        assert_eq!(map.assign("new.test"), Some((ip, true)));
        let (client, peer) = accepted_loopback().await;
        let mut numeric =
            tcp_connect_intent(client, peer, "203.0.113.9:443".parse().unwrap(), Some(&map))
                .unwrap();
        assert!(numeric.take_target_lease().is_none());
    }

    /// The relay target host of a TCP connect intent.
    fn connect_host(intent: &IngressSessionIntent) -> &str {
        match &intent.transport {
            IngressTransport::TcpConnect(tcp) => &tcp.target.host,
            _ => panic!("a TCP connect"),
        }
    }

    /// A TCP session's lease ends in two steps: the last holder's drop takes
    /// the lease's count to zero, then its end takes the map lock and marks
    /// the binding used. An answer for another name that holds the lock in
    /// between must still see the binding held (402913b3). Otherwise it reads
    /// the use from before the session, here two idle hours ago, and gives
    /// the address to the other name the moment the session ends, while the
    /// application may still connect to it with its cached DNS answer. After
    /// the end the address stays its name's for the listener's recycle idle:
    /// past the answer's TTL and macOS's resolver grace a connect to it still
    /// reaches its name, and only an idle hour after the last session's end
    /// may it go to another name. IPv4 and IPv4-mapped destinations alike.
    #[tokio::test(start_paused = true)]
    async fn a_tcp_session_lease_end_never_hands_its_address_to_another_name() {
        use crate::ingress::wide::dns_preview::spawn_dns_preview;
        use std::time::Duration;
        let idle = aegis_client::packet_engine::engine::FAKE_IP_RECYCLE_IDLE;
        for mapped in [false, true] {
            // The map the Linux listener builds: one usable address, so
            // another name can only get it by recycling, and TTL 60 answers.
            let settings = WideIngressSettings {
                dns_preview_listen: Some("127.0.0.1:0".parse().unwrap()),
                dns_preview_fake_ip_pool: "198.19.255.252/30".into(),
                dns_preview_fake_ip_ttl_secs: 60,
                ..Default::default()
            };
            let listener = spawn_dns_preview(&settings, None).await.unwrap().unwrap();
            let map = Arc::clone(&listener.map);
            let (ip, _) = map.assign("old.test").unwrap();
            let destination = if mapped {
                SocketAddr::new(std::net::IpAddr::V6(ip.to_ipv6_mapped()), 443)
            } else {
                SocketAddr::from((ip, 443))
            };
            // The accept loop's session takes the lease before the broker
            // consumes the intent (main.rs) and holds it until it ends.
            let (client, peer) = accepted_loopback().await;
            let mut intent = tcp_connect_intent(client, peer, destination, Some(&map)).unwrap();
            assert_eq!(connect_host(&intent), "old.test");
            let lease = intent.take_target_lease().expect("a fake-IP session lease");
            drop(intent);
            tokio::time::advance(idle * 2).await;
            assert_eq!(
                map.assign("new.test"),
                None,
                "{destination}: a live session's address went to another name"
            );
            assert_eq!(
                map.recyclable_while_last_lease_ends_for_test(ip, lease)
                    .await,
                None,
                "{destination}: another name's answer could take the address as its session ended"
            );
            let mut since_end = 0;
            for at in [61, 77, 600, 3599] {
                tokio::time::advance(Duration::from_secs(at - since_end)).await;
                since_end = at;
                assert_eq!(
                    map.assign("new.test"),
                    None,
                    "{destination}: {at} s after the session's end its address went to new.test"
                );
            }
            // The application connects again with its cached answer.
            let (client, peer) = accepted_loopback().await;
            let again = tcp_connect_intent(client, peer, destination, Some(&map)).unwrap();
            assert_eq!(connect_host(&again), "old.test", "{destination}");
            drop(again);
            tokio::time::advance(idle - Duration::from_secs(1)).await;
            assert_eq!(
                map.assign("new.test"),
                None,
                "{destination}: new.test got the address within an idle hour of the session's end"
            );
            tokio::time::advance(Duration::from_secs(2)).await;
            assert_eq!(
                map.assign("new.test"),
                Some((ip, true)),
                "{destination}: an idle hour after the last session's end recycles the address"
            );
            listener.shutdown().await;
        }
    }

    #[tokio::test]
    async fn bind_replaces_ephemeral_request_with_actual_listener_addr() {
        let settings = WideIngressSettings {
            listen: "127.0.0.1:0".parse().expect("listen"),
            ..WideIngressSettings::default()
        };
        let backend = LinuxWidePrimaryBackend::bind(settings)
            .await
            .expect("bind backend");
        let actual = backend.listener.local_addr().expect("listener addr");
        assert_eq!(backend.settings.listen, actual);
        assert_ne!(backend.settings.listen.port(), 0);
    }
}
