//! Best-effort packet observation for an active IPv4/TCP flow.
//!
//! The runtime sees a single `start_packet_observer()` entrypoint, but the
//! implementation is backend-based so we can add a fuller `AF_PACKET`/BPF path
//! later without rewriting direct-mode execution.

use crate::fingerprint::ServerType;
#[cfg(any(test, all(target_os = "linux", feature = "raw-socket")))]
use crate::fingerprint::{from_tcp_snapshot, parse_tcp_header};
use crate::probe::estimated_hops;
#[cfg(any(test, all(target_os = "linux", feature = "raw-socket")))]
use crate::probe::RstProbe;
use crate::probe::RstSource;
use crate::raw_engine::{default_raw_engine, RawCapabilities};
use serde::{Deserialize, Serialize};
use std::io;
#[cfg(any(test, all(target_os = "linux", feature = "raw-socket")))]
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
#[cfg(all(target_os = "linux", feature = "raw-socket"))]
use std::time::Instant;
use tracing::trace;

#[cfg(any(test, all(target_os = "linux", feature = "raw-socket")))]
const IPV4_PROTO_TCP: u8 = 6;

#[derive(Debug, Clone, Default)]
pub struct PacketObservation {
    pub capture_status: PacketCaptureStatus,
    pub capture_backend: Option<PacketCaptureBackendKind>,
    pub capture_filter_applied: bool,
    pub capture_ring_layout: Option<PacketCaptureRingLayout>,
    pub capture_io_path: Option<PacketCaptureIoPath>,
    pub capture_wait_cycles: u32,
    pub downstream_dup_ack_count: u32,
    pub downstream_retransmit_count: u32,
    pub downstream_fin_after_data: bool,
    pub matched_packets: u32,
    pub syn_ack_ttl: Option<u8>,
    pub syn_ack_window: Option<u16>,
    pub syn_ack_mss: Option<u16>,
    pub syn_ack_window_scale: Option<u8>,
    pub syn_ack_sack_permitted: Option<bool>,
    pub syn_ack_timestamp_option: Option<bool>,
    pub syn_ack_server_hint: Option<ServerType>,
    pub first_data_ttl: Option<u8>,
    pub first_data_window: Option<u16>,
    pub first_data_payload_len: Option<usize>,
    pub first_data_flags: Option<u8>,
    pub first_data_server_hint: Option<ServerType>,
    pub first_packet_ttl: Option<u8>,
    pub first_packet_ip_tos: Option<u8>,
    pub first_packet_ip_id: Option<u16>,
    pub first_packet_ip_df: Option<bool>,
    pub first_packet_window: Option<u16>,
    pub first_packet_flags: Option<u8>,
    pub server_hint: Option<ServerType>,
    pub rst_ttl: Option<u8>,
    pub rst_source: Option<RstSource>,
    #[cfg(any(test, all(target_os = "linux", feature = "raw-socket")))]
    last_downstream_ack: Option<u32>,
    #[cfg(any(test, all(target_os = "linux", feature = "raw-socket")))]
    last_downstream_seq: Option<u32>,
    #[cfg(any(test, all(target_os = "linux", feature = "raw-socket")))]
    last_downstream_payload_seq: Option<u32>,
    #[cfg(any(test, all(target_os = "linux", feature = "raw-socket")))]
    last_downstream_payload_len: Option<usize>,
}

impl PacketObservation {
    pub fn with_capture_status(capture_status: PacketCaptureStatus) -> Self {
        Self {
            capture_status,
            ..Self::default()
        }
    }

    pub fn reference_path_hops(&self) -> Option<u8> {
        self.first_data_ttl
            .or(self.syn_ack_ttl)
            .or(self.first_packet_ttl)
            .map(estimated_hops)
    }

    pub fn rst_path_hops(&self) -> Option<u8> {
        self.rst_ttl.map(estimated_hops)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketCaptureBackendKind {
    LinuxAfPacket,
    LinuxRawBasic,
    /// Tier 2.3 scaffolding: macOS BPF (/dev/bpf*) backend.
    /// Currently `can_start` always returns false — live FFI
    /// implementation pending rooted Mac access (Tier 2.4 / future).
    /// Variant exists so call sites + telemetry already accept it
    /// before the backend impl lands, avoiding enum-churn later.
    MacosBpf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PacketCaptureStatus {
    #[default]
    NotAttempted,
    Active,
    UnsupportedPlatform,
    MissingCapability,
    UnsupportedFlow,
    BackendStartFailed,
}

impl PacketCaptureStatus {
    pub fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    pub fn is_explicit_absence(self) -> bool {
        matches!(
            self,
            Self::UnsupportedPlatform
                | Self::MissingCapability
                | Self::UnsupportedFlow
                | Self::BackendStartFailed
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketCaptureRingLayout {
    pub block_size: u32,
    pub block_nr: u32,
    pub frame_size: u32,
    pub frame_nr: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketCaptureIoPath {
    AfPacketRing,
    AfPacketRecv,
    RawBasicRecv,
}

pub struct RunningPacketObserver {
    backend: PacketCaptureBackendKind,
    stop: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<PacketObservation>,
}

impl RunningPacketObserver {
    pub fn backend_kind(&self) -> PacketCaptureBackendKind {
        self.backend
    }

    pub async fn finish(self) -> PacketObservation {
        self.stop.store(true, Ordering::Relaxed);
        self.task.await.unwrap_or_default()
    }
}

pub enum PacketObserverHandle {
    Running(RunningPacketObserver),
    Unavailable(PacketObservation),
}

impl PacketObserverHandle {
    pub async fn finish(self) -> PacketObservation {
        match self {
            Self::Running(observer) => observer.finish().await,
            Self::Unavailable(observation) => observation,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct PacketCaptureRequest {
    flow_local: SocketAddr,
    flow_remote: SocketAddr,
    timeout: Duration,
}

#[cfg(all(target_os = "linux", feature = "raw-socket"))]
#[derive(Debug, Clone)]
struct PacketCaptureBinding {
    interface_name: String,
    interface_index: i32,
}

#[cfg(all(target_os = "linux", feature = "raw-socket"))]
struct PacketCaptureSocket {
    fd: libc::c_int,
    ring: Option<PacketRxRing>,
}

#[cfg(all(target_os = "linux", feature = "raw-socket"))]
struct PacketRxRing {
    ptr: *mut u8,
    len: usize,
    block_size: usize,
    block_nr: usize,
    frame_size: usize,
    frame_nr: usize,
    current_frame: usize,
}

#[cfg(all(target_os = "linux", feature = "raw-socket"))]
// SAFETY: ownership of the AF_PACKET socket is moved into one blocking worker
// and never shared concurrently; the raw fd is managed by Drop.
unsafe impl Send for PacketCaptureSocket {}

#[cfg(all(target_os = "linux", feature = "raw-socket"))]
// SAFETY: the mapped ring buffer is owned by a single observer task and is not
// accessed from multiple threads at the same time.
unsafe impl Send for PacketRxRing {}

trait PacketCaptureBackend: Send + Sync {
    fn kind(&self) -> PacketCaptureBackendKind;
    fn can_start(&self, request: &PacketCaptureRequest, caps: RawCapabilities) -> bool;
    fn start(
        &self,
        request: PacketCaptureRequest,
        caps: RawCapabilities,
    ) -> io::Result<RunningPacketObserver>;
}

struct LinuxAfPacketBackend;
struct LinuxRawBasicBackend;

/// Tier 2.3 scaffolding: macOS BPF backend stub.
///
/// Currently `can_start` always returns false — registering this backend
/// in `packet_capture_backends()` is harmless on Linux (the can_start gate
/// short-circuits) and on macOS lets future code path-dispatch by enum
/// variant once the live ioctl/BIOCSETIF impl lands.
///
/// Implementation contract for the live slice (Tier 2.4 / future):
/// 1. Open `/dev/bpf<N>` (round-robin or first-available).
/// 2. ioctl(BIOCSETIF) bind the device to a chosen egress interface.
/// 3. ioctl(BIOCIMMEDIATE, 1) for low-latency reads.
/// 4. ioctl(BIOCSETF) install a flow-specific filter (5-tuple of the
///    target connection) so we don't drown in unrelated traffic.
/// 5. read(fd, &buf, BPF_BUF_SIZE) loop, advance via bpf_hdr->bh_hdrlen.
/// 6. Map captured frames into `PacketObservation` fields (TTL, ja3s
///    server-hello fingerprint, RST source classification).
/// 7. Permission failure → return PacketCaptureStatus::MissingCapability
///    (mirrors Linux CAP_NET_RAW absence).
struct MacosBpfBackend;

static LINUX_AF_PACKET_BACKEND: LinuxAfPacketBackend = LinuxAfPacketBackend;
static LINUX_RAW_BASIC_BACKEND: LinuxRawBasicBackend = LinuxRawBasicBackend;
static MACOS_BPF_BACKEND: MacosBpfBackend = MacosBpfBackend;

impl PacketCaptureBackend for MacosBpfBackend {
    fn kind(&self) -> PacketCaptureBackendKind {
        PacketCaptureBackendKind::MacosBpf
    }

    fn can_start(&self, _request: &PacketCaptureRequest, _caps: RawCapabilities) -> bool {
        // Tier 2.3 scaffolding: always false until the live BPF impl
        // (ioctl BIOCSETIF / BIOCIMMEDIATE / BIOCSETF + read loop) lands
        // in a slice that has rooted Mac access for verification.
        false
    }

    fn start(
        &self,
        _request: PacketCaptureRequest,
        _caps: RawCapabilities,
    ) -> io::Result<RunningPacketObserver> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "macos_bpf backend is scaffolded but not yet implemented",
        ))
    }
}

impl PacketCaptureBackend for LinuxAfPacketBackend {
    fn kind(&self) -> PacketCaptureBackendKind {
        PacketCaptureBackendKind::LinuxAfPacket
    }

    fn can_start(&self, request: &PacketCaptureRequest, caps: RawCapabilities) -> bool {
        caps.ipv4_packet_capture
            && cfg!(all(target_os = "linux", feature = "raw-socket"))
            && matches!(
                (request.flow_local, request.flow_remote),
                (SocketAddr::V4(_), SocketAddr::V4(_))
            )
    }

    fn start(
        &self,
        request: PacketCaptureRequest,
        caps: RawCapabilities,
    ) -> io::Result<RunningPacketObserver> {
        let (SocketAddr::V4(local), SocketAddr::V4(remote)) =
            (request.flow_local, request.flow_remote)
        else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "linux_af_packet supports only IPv4 flows",
            ));
        };
        #[cfg(all(target_os = "linux", feature = "raw-socket"))]
        let binding = resolve_interface_binding(*local.ip())?;
        #[cfg(all(target_os = "linux", feature = "raw-socket"))]
        let socket = open_packet_capture_socket(&binding, local, remote)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_task = stop.clone();
        let timeout = request.timeout;
        let task = tokio::task::spawn_blocking(move || {
            #[cfg(all(target_os = "linux", feature = "raw-socket"))]
            {
                observe_packet_socket_ipv4_flow(
                    socket, local, remote, timeout, caps, binding, stop_task,
                )
                .unwrap_or_default()
            }
            #[cfg(not(all(target_os = "linux", feature = "raw-socket")))]
            {
                let _ = (local, remote, timeout, caps, stop_task);
                PacketObservation::default()
            }
        });
        Ok(RunningPacketObserver {
            backend: self.kind(),
            stop,
            task,
        })
    }
}

impl PacketCaptureBackend for LinuxRawBasicBackend {
    fn kind(&self) -> PacketCaptureBackendKind {
        PacketCaptureBackendKind::LinuxRawBasic
    }

    fn can_start(&self, request: &PacketCaptureRequest, caps: RawCapabilities) -> bool {
        caps.ipv4_packet_capture
            && cfg!(all(target_os = "linux", feature = "raw-socket"))
            && matches!(
                (request.flow_local, request.flow_remote),
                (SocketAddr::V4(_), SocketAddr::V4(_))
            )
    }

    fn start(
        &self,
        request: PacketCaptureRequest,
        caps: RawCapabilities,
    ) -> io::Result<RunningPacketObserver> {
        let (SocketAddr::V4(local), SocketAddr::V4(remote)) =
            (request.flow_local, request.flow_remote)
        else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "linux_raw_basic supports only IPv4 flows",
            ));
        };
        let stop = Arc::new(AtomicBool::new(false));
        let stop_task = stop.clone();
        let timeout = request.timeout;
        let task = tokio::task::spawn_blocking(move || {
            observe_ipv4_flow(local, remote, timeout, caps, stop_task).unwrap_or_default()
        });
        Ok(RunningPacketObserver {
            backend: self.kind(),
            stop,
            task,
        })
    }
}

fn packet_capture_backends() -> [&'static dyn PacketCaptureBackend; 3] {
    // MacosBpfBackend.can_start currently always returns false, so on
    // Linux it's a free passthrough; on macOS it reserves the dispatch
    // slot for the future live impl without changing call-site arity.
    [
        &LINUX_AF_PACKET_BACKEND,
        &LINUX_RAW_BASIC_BACKEND,
        &MACOS_BPF_BACKEND,
    ]
}

pub fn maybe_start(
    flow_local: SocketAddr,
    flow_remote: SocketAddr,
    timeout: Duration,
) -> PacketObserverHandle {
    let caps = default_raw_engine().capabilities();
    let request = PacketCaptureRequest {
        flow_local,
        flow_remote,
        timeout,
    };
    let mut saw_start_error = false;
    for backend in packet_capture_backends() {
        if !backend.can_start(&request, caps) {
            continue;
        }
        match backend.start(request, caps) {
            Ok(observer) => return PacketObserverHandle::Running(observer),
            Err(error) => {
                saw_start_error = true;
                trace!(
                    backend = ?backend.kind(),
                    %error,
                    ?flow_local,
                    ?flow_remote,
                    "packet capture backend failed to start"
                );
            }
        }
    }
    PacketObserverHandle::Unavailable(PacketObservation {
        capture_status: unavailable_capture_status(&request, caps, saw_start_error),
        ..PacketObservation::default()
    })
}

fn unavailable_capture_status(
    request: &PacketCaptureRequest,
    caps: RawCapabilities,
    saw_start_error: bool,
) -> PacketCaptureStatus {
    if saw_start_error {
        return PacketCaptureStatus::BackendStartFailed;
    }
    // A compiled scaffold is not a runtime backend. macOS BPF still has an
    // intentionally inert `can_start`, so reporting MissingCapability there
    // would falsely imply that permissions alone can make capture work.
    let implemented_backend = cfg!(all(target_os = "linux", feature = "raw-socket"));
    if !implemented_backend {
        return PacketCaptureStatus::UnsupportedPlatform;
    }
    if !caps.ipv4_packet_capture {
        return PacketCaptureStatus::MissingCapability;
    }
    if !matches!(
        (request.flow_local, request.flow_remote),
        (SocketAddr::V4(_), SocketAddr::V4(_))
    ) {
        return PacketCaptureStatus::UnsupportedFlow;
    }
    PacketCaptureStatus::NotAttempted
}

fn observe_ipv4_flow(
    local: std::net::SocketAddrV4,
    remote: std::net::SocketAddrV4,
    timeout: Duration,
    caps: RawCapabilities,
    stop: Arc<AtomicBool>,
) -> io::Result<PacketObservation> {
    if !caps.ipv4_packet_capture {
        return Ok(PacketObservation::default());
    }
    #[cfg(all(target_os = "linux", feature = "raw-socket"))]
    {
        observe_ipv4_flow_linux(local, remote, timeout, stop)
    }
    #[cfg(not(all(target_os = "linux", feature = "raw-socket")))]
    {
        let _ = (local, remote, timeout, stop);
        Ok(PacketObservation::default())
    }
}

#[cfg(all(target_os = "linux", feature = "raw-socket"))]
const ETH_P_IP: u16 = 0x0800;

#[cfg(all(target_os = "linux", feature = "raw-socket"))]
fn observe_packet_socket_ipv4_flow(
    mut socket: PacketCaptureSocket,
    local: std::net::SocketAddrV4,
    remote: std::net::SocketAddrV4,
    timeout: Duration,
    caps: RawCapabilities,
    binding: PacketCaptureBinding,
    stop: Arc<AtomicBool>,
) -> io::Result<PacketObservation> {
    if !caps.ipv4_packet_capture {
        return Ok(PacketObservation::default());
    }
    let result = (|| {
        let deadline = Instant::now() + timeout + Duration::from_millis(150);
        let mut observed = PacketObservation {
            capture_status: PacketCaptureStatus::Active,
            capture_backend: Some(PacketCaptureBackendKind::LinuxAfPacket),
            capture_filter_applied: true,
            ..PacketObservation::default()
        };
        if let Some(ring) = socket.ring.as_mut() {
            // Persist the actual mmap ring shape so runtime/state can tell
            // whether AF_PACKET used ring capture or fell back to plain recv.
            observed.capture_ring_layout = Some(ring.layout());
            observed.capture_io_path = Some(PacketCaptureIoPath::AfPacketRing);
            observed =
                observe_ring_ipv4_flow(socket.fd, ring, local, remote, deadline, stop, observed)?;
        } else {
            observed.capture_io_path = Some(PacketCaptureIoPath::AfPacketRecv);
            observed = observe_fd_ipv4_flow(socket.fd, local, remote, deadline, stop, observed)?;
        }
        trace!(
            interface = binding.interface_name,
            matched_packets = observed.matched_packets,
            "linux_af_packet observer finished"
        );
        Ok(observed)
    })();

    drop(socket);
    result
}

#[cfg(all(target_os = "linux", feature = "raw-socket"))]
fn observe_ipv4_flow_linux(
    local: std::net::SocketAddrV4,
    remote: std::net::SocketAddrV4,
    timeout: Duration,
    stop: Arc<AtomicBool>,
) -> io::Result<PacketObservation> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let result = (|| {
        set_recv_timeout(fd, Duration::from_millis(100))?;
        let deadline = Instant::now() + timeout + Duration::from_millis(150);
        let mut buf = [0u8; 4096];
        let mut observed = PacketObservation {
            capture_status: PacketCaptureStatus::Active,
            capture_backend: Some(PacketCaptureBackendKind::LinuxRawBasic),
            capture_filter_applied: false,
            capture_io_path: Some(PacketCaptureIoPath::RawBasicRecv),
            ..PacketObservation::default()
        };
        while Instant::now() < deadline && !stop.load(Ordering::Relaxed) {
            let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n < 0 {
                let err = io::Error::last_os_error();
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) {
                    continue;
                }
                return Err(err);
            }
            if n == 0 {
                continue;
            }
            parse_packet_for_flow(&buf[..n as usize], local, remote, &mut observed);
            if observed.first_packet_ttl.is_some() && observed.rst_ttl.is_some() {
                break;
            }
        }
        Ok(observed)
    })();

    unsafe {
        libc::close(fd);
    }
    result
}

#[cfg(all(target_os = "linux", feature = "raw-socket"))]
fn set_recv_timeout(fd: libc::c_int, timeout: Duration) -> io::Result<()> {
    let tv = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: timeout.subsec_micros() as libc::suseconds_t,
    };
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of_val(&tv) as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(any(test, all(target_os = "linux", feature = "raw-socket")))]
fn parse_packet_for_flow(
    packet: &[u8],
    local: std::net::SocketAddrV4,
    remote: std::net::SocketAddrV4,
    observed: &mut PacketObservation,
) {
    let Some(parsed) = parse_ipv4_tcp_packet(packet) else {
        return;
    };
    if parsed.src_ip != *remote.ip()
        || parsed.dst_ip != *local.ip()
        || parsed.src_port != remote.port()
        || parsed.dst_port != local.port()
    {
        return;
    }
    observed.matched_packets = observed.matched_packets.saturating_add(1);

    if observed.first_packet_ttl.is_none() {
        observed.first_packet_ttl = Some(parsed.ttl);
        observed.first_packet_ip_tos = Some(parsed.tos);
        observed.first_packet_ip_id = Some(parsed.identification);
        observed.first_packet_ip_df = Some(parsed.dont_fragment);
        observed.first_packet_window = Some(parsed.window);
        observed.first_packet_flags = Some(parsed.flags);
        let fingerprint = from_tcp_snapshot(&parsed.header, Some(parsed.ttl));
        if fingerprint.server_type != ServerType::Unknown {
            observed.server_hint = Some(fingerprint.server_type);
        }
    }

    // Keep stage-specific hints separate so Brain/runtime can distinguish
    // handshake response from actual first application data.
    if parsed.flags & crate::TCP_FLAG_SYN != 0
        && parsed.flags & crate::TCP_FLAG_ACK != 0
        && observed.syn_ack_ttl.is_none()
    {
        observed.syn_ack_ttl = Some(parsed.ttl);
        observed.syn_ack_window = Some(parsed.window);
        observed.syn_ack_mss = parsed.header.tcp_options.mss;
        observed.syn_ack_window_scale = parsed.header.tcp_options.window_scale;
        observed.syn_ack_sack_permitted = Some(parsed.header.tcp_options.sack_permitted);
        observed.syn_ack_timestamp_option = Some(parsed.header.tcp_options.timestamps);
        let fingerprint = from_tcp_snapshot(&parsed.header, Some(parsed.ttl));
        if fingerprint.server_type != ServerType::Unknown {
            observed.syn_ack_server_hint = Some(fingerprint.server_type);
            observed.server_hint = observed.server_hint.or(Some(fingerprint.server_type));
        }
    }

    if parsed.payload_len > 0 && observed.first_data_ttl.is_none() {
        observed.first_data_ttl = Some(parsed.ttl);
        observed.first_data_window = Some(parsed.window);
        observed.first_data_payload_len = Some(parsed.payload_len);
        observed.first_data_flags = Some(parsed.flags);
        let fingerprint = from_tcp_snapshot(&parsed.header, Some(parsed.ttl));
        if fingerprint.server_type != ServerType::Unknown {
            observed.first_data_server_hint = Some(fingerprint.server_type);
            observed.server_hint = observed.server_hint.or(Some(fingerprint.server_type));
        }
    }

    let payload_after_first_data = observed.first_data_ttl.is_some() && parsed.payload_len > 0;
    if payload_after_first_data {
        if observed.last_downstream_payload_seq == Some(parsed.header.seq)
            && observed.last_downstream_payload_len == Some(parsed.payload_len)
        {
            // Repeated downstream payload with the same sequence window is a
            // stronger recovery/loss hint than ACK-only duplicate traffic.
            observed.downstream_retransmit_count =
                observed.downstream_retransmit_count.saturating_add(1);
        }
        observed.last_downstream_payload_seq = Some(parsed.header.seq);
        observed.last_downstream_payload_len = Some(parsed.payload_len);
    }

    if observed.first_data_ttl.is_some()
        && parsed.flags & crate::TCP_FLAG_FIN != 0
        && parsed.flags & crate::TCP_FLAG_RST == 0
    {
        observed.downstream_fin_after_data = true;
    }

    if observed.first_data_ttl.is_some()
        && parsed.payload_len == 0
        && parsed.window == 0
        && parsed.flags & crate::TCP_FLAG_ACK != 0
        && parsed.flags & crate::TCP_FLAG_RST == 0
    {
        // Preserve a stronger downstream stall signal if the server later advertises
        // a zero receive window after real application progress already happened.
        observed.first_data_window = Some(0);
    }

    let pure_ack_after_first_data = observed.first_data_ttl.is_some()
        && parsed.payload_len == 0
        && parsed.window > 0
        && parsed.flags & crate::TCP_FLAG_ACK != 0
        && parsed.flags & crate::TCP_FLAG_RST == 0
        && parsed.flags & crate::TCP_FLAG_SYN == 0
        && parsed.flags & crate::TCP_FLAG_FIN == 0;
    if pure_ack_after_first_data {
        if observed.last_downstream_ack == Some(parsed.header.ack)
            && observed.last_downstream_seq == Some(parsed.header.seq)
        {
            observed.downstream_dup_ack_count = observed.downstream_dup_ack_count.saturating_add(1);
        }
        observed.last_downstream_ack = Some(parsed.header.ack);
        observed.last_downstream_seq = Some(parsed.header.seq);
    }

    if parsed.flags & crate::TCP_FLAG_RST != 0 {
        observed.rst_ttl = Some(parsed.ttl);
        observed.rst_source = classify_rst_source(observed.rst_ttl, observed.first_packet_ttl);
    }
}

#[cfg(any(test, all(target_os = "linux", feature = "raw-socket")))]
fn classify_rst_source(rst_ttl: Option<u8>, expected_ttl: Option<u8>) -> Option<RstSource> {
    let expected = expected_ttl?;
    match RstProbe::from_ttl_pair(rst_ttl, expected) {
        RstProbe::LikelyRemote => Some(RstSource::Remote),
        RstProbe::PossiblyMiddlebox => Some(RstSource::Middlebox),
        RstProbe::Unknown => Some(RstSource::Unknown),
    }
}

#[cfg(any(test, all(target_os = "linux", feature = "raw-socket")))]
struct ParsedIpv4TcpPacket {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    ttl: u8,
    tos: u8,
    identification: u16,
    dont_fragment: bool,
    src_port: u16,
    dst_port: u16,
    window: u16,
    flags: u8,
    payload_len: usize,
    header: crate::TcpHeaderSnapshot,
}

#[cfg(any(test, all(target_os = "linux", feature = "raw-socket")))]
fn parse_ipv4_tcp_packet(packet: &[u8]) -> Option<ParsedIpv4TcpPacket> {
    if packet.len() < 40 || packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl + 20 || packet[9] != IPV4_PROTO_TCP {
        return None;
    }
    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let tcp = &packet[ihl..];
    let header = parse_tcp_header(tcp)?;
    Some(ParsedIpv4TcpPacket {
        src_ip,
        dst_ip,
        ttl: packet[8],
        tos: packet[1],
        identification: u16::from_be_bytes([packet[4], packet[5]]),
        dont_fragment: u16::from_be_bytes([packet[6], packet[7]]) & 0x4000 != 0,
        src_port: header.src_port,
        dst_port: header.dst_port,
        window: header.window,
        flags: tcp.get(13).copied()?,
        payload_len: packet.len().saturating_sub(ihl + header.data_offset_bytes),
        header,
    })
}

#[cfg(all(target_os = "linux", feature = "raw-socket"))]
fn resolve_interface_binding(local_ip: Ipv4Addr) -> io::Result<PacketCaptureBinding> {
    let mut addrs = std::ptr::null_mut();
    let ret = unsafe { libc::getifaddrs(&mut addrs) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    let result = (|| {
        let mut cursor = addrs;
        while !cursor.is_null() {
            let item = unsafe { &*cursor };
            let addr = item.ifa_addr;
            if !addr.is_null() && unsafe { (*addr).sa_family as i32 } == libc::AF_INET {
                let addr_in = unsafe { &*(addr as *const libc::sockaddr_in) };
                let candidate = Ipv4Addr::from(u32::from_be(addr_in.sin_addr.s_addr));
                if candidate == local_ip && !item.ifa_name.is_null() {
                    let interface_index = unsafe { libc::if_nametoindex(item.ifa_name) };
                    if interface_index != 0 {
                        let interface_name = unsafe { std::ffi::CStr::from_ptr(item.ifa_name) }
                            .to_string_lossy()
                            .into_owned();
                        return Ok(PacketCaptureBinding {
                            interface_name,
                            interface_index: interface_index as i32,
                        });
                    }
                }
            }
            cursor = item.ifa_next;
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no network interface found for local IPv4 address {local_ip}"),
        ))
    })();

    unsafe {
        libc::freeifaddrs(addrs);
    }
    result
}

#[cfg(all(target_os = "linux", feature = "raw-socket"))]
fn open_packet_capture_socket(
    binding: &PacketCaptureBinding,
    local: std::net::SocketAddrV4,
    remote: std::net::SocketAddrV4,
) -> io::Result<PacketCaptureSocket> {
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_DGRAM,
            i32::from(ETH_P_IP.to_be()),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let result = (|| {
        bind_packet_socket(fd, binding.interface_index, ETH_P_IP)?;
        attach_ipv4_tcp_flow_filter(fd, local, remote)?;
        let ring = match setup_rx_ring(fd) {
            Ok(ring) => Some(ring),
            Err(error) => {
                trace!(
                    interface = binding.interface_name,
                    %error,
                    "packet rx ring setup failed, falling back to recv path"
                );
                None
            }
        };
        set_recv_timeout(fd, Duration::from_millis(100))?;
        Ok(PacketCaptureSocket { fd, ring })
    })();

    if result.is_err() {
        unsafe {
            libc::close(fd);
        }
    }
    result
}

#[cfg(all(target_os = "linux", feature = "raw-socket"))]
fn setup_rx_ring(fd: libc::c_int) -> io::Result<PacketRxRing> {
    let version: libc::c_int = TPACKET_V2;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            SOL_PACKET,
            PACKET_VERSION,
            &version as *const _ as *const libc::c_void,
            std::mem::size_of_val(&version) as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return Err(io::Error::last_os_error());
    }
    let page_size = page_size as usize;
    let recv_buffer = socket_recv_buffer(fd, page_size).unwrap_or(page_size);
    let req = build_ring_request(page_size, recv_buffer);
    let ret = unsafe {
        libc::setsockopt(
            fd,
            SOL_PACKET,
            PACKET_RX_RING,
            &req as *const _ as *const libc::c_void,
            std::mem::size_of_val(&req) as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    let len = req.tp_block_size as usize * req.tp_block_nr as usize;
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        let _ = unsafe { libc::setsockopt(fd, SOL_PACKET, PACKET_RX_RING, std::ptr::null(), 0) };
        return Err(io::Error::last_os_error());
    }

    Ok(PacketRxRing {
        ptr: ptr as *mut u8,
        len,
        block_size: req.tp_block_size as usize,
        block_nr: req.tp_block_nr as usize,
        frame_size: req.tp_frame_size as usize,
        frame_nr: req.tp_frame_nr as usize,
        current_frame: 0,
    })
}

#[cfg(all(target_os = "linux", feature = "raw-socket"))]
fn socket_recv_buffer(fd: libc::c_int, min_value: usize) -> io::Result<usize> {
    let mut value: libc::c_int = 0;
    let mut len = std::mem::size_of_val(&value) as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &mut value as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value.max(min_value as libc::c_int) as usize)
}

#[cfg(any(test, all(target_os = "linux", feature = "raw-socket")))]
fn build_ring_request(page_size: usize, recv_buffer: usize) -> TpacketReq {
    let frame_size = page_size.max(TPACKET_ALIGNMENT as usize);
    let target_ring_bytes = recv_buffer.max(frame_size);
    // Prefer several page-aligned blocks for larger rings so AF_PACKET can
    // batch frames at the block level instead of pinning everything to one
    // oversized block.
    let preferred_block_size = align_up(target_ring_bytes.div_ceil(4).max(frame_size), page_size);
    let block_nr = target_ring_bytes.div_ceil(preferred_block_size).max(1);
    let block_size = align_up(
        target_ring_bytes.div_ceil(block_nr).max(frame_size),
        page_size,
    );
    let frame_nr = ((block_size / frame_size).max(1)) * block_nr;
    TpacketReq {
        tp_block_size: block_size as u32,
        tp_block_nr: block_nr as u32,
        tp_frame_size: frame_size as u32,
        tp_frame_nr: frame_nr as u32,
    }
}

#[cfg(any(test, all(target_os = "linux", feature = "raw-socket")))]
fn align_up(value: usize, alignment: usize) -> usize {
    if alignment <= 1 {
        return value;
    }
    let remainder = value % alignment;
    if remainder == 0 {
        value
    } else {
        value + (alignment - remainder)
    }
}

#[cfg(all(target_os = "linux", feature = "raw-socket"))]
fn observe_fd_ipv4_flow(
    fd: libc::c_int,
    local: std::net::SocketAddrV4,
    remote: std::net::SocketAddrV4,
    deadline: Instant,
    stop: Arc<AtomicBool>,
    mut observed: PacketObservation,
) -> io::Result<PacketObservation> {
    let mut buf = [0u8; 4096];
    while Instant::now() < deadline && !stop.load(Ordering::Relaxed) {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) {
                observed.capture_wait_cycles = observed.capture_wait_cycles.saturating_add(1);
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            observed.capture_wait_cycles = observed.capture_wait_cycles.saturating_add(1);
            continue;
        }
        parse_packet_for_flow(&buf[..n as usize], local, remote, &mut observed);
        if observed.first_packet_ttl.is_some() && observed.rst_ttl.is_some() {
            break;
        }
    }
    Ok(observed)
}

#[cfg(all(target_os = "linux", feature = "raw-socket"))]
fn observe_ring_ipv4_flow(
    fd: libc::c_int,
    ring: &mut PacketRxRing,
    local: std::net::SocketAddrV4,
    remote: std::net::SocketAddrV4,
    deadline: Instant,
    stop: Arc<AtomicBool>,
    mut observed: PacketObservation,
) -> io::Result<PacketObservation> {
    while Instant::now() < deadline && !stop.load(Ordering::Relaxed) {
        if ring.consume_next_packet(|packet| {
            parse_packet_for_flow(packet, local, remote, &mut observed);
        }) {
            if observed.first_packet_ttl.is_some() && observed.rst_ttl.is_some() {
                break;
            }
            continue;
        }
        observed.capture_wait_cycles = observed.capture_wait_cycles.saturating_add(1);
        poll_for_packet(fd, deadline)?;
    }
    Ok(observed)
}

#[cfg(all(target_os = "linux", feature = "raw-socket"))]
fn poll_for_packet(fd: libc::c_int, deadline: Instant) -> io::Result<()> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let timeout_ms = remaining.as_millis().min(100) as libc::c_int;
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms.max(0)) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "raw-socket"))]
fn bind_packet_socket(fd: libc::c_int, interface_index: i32, protocol: u16) -> io::Result<()> {
    let addr = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: protocol.to_be(),
        sll_ifindex: interface_index,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };
    let ret = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of_val(&addr) as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "raw-socket"))]
fn attach_ipv4_tcp_flow_filter(
    fd: libc::c_int,
    local: std::net::SocketAddrV4,
    remote: std::net::SocketAddrV4,
) -> io::Result<()> {
    let filter = build_ipv4_tcp_flow_filter(local, remote);
    let program = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut SockFilter,
    };
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &program as *const _ as *const libc::c_void,
            std::mem::size_of_val(&program) as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(any(test, all(target_os = "linux", feature = "raw-socket")))]
fn build_ipv4_tcp_flow_filter(
    local: std::net::SocketAddrV4,
    remote: std::net::SocketAddrV4,
) -> Vec<SockFilter> {
    vec![
        bpf_stmt(BPF_LD | BPF_B | BPF_ABS, 9),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, IPV4_PROTO_TCP as u32, 0, 12),
        bpf_stmt(BPF_LD | BPF_H | BPF_ABS, 6),
        bpf_jump(BPF_JMP | BPF_JSET | BPF_K, 0x1fff, 10, 0),
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 12),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, u32::from(*remote.ip()), 0, 8),
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 16),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, u32::from(*local.ip()), 0, 6),
        bpf_stmt(BPF_LDX | BPF_B | BPF_MSH, 0),
        bpf_stmt(BPF_LD | BPF_H | BPF_IND, 0),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, remote.port() as u32, 0, 3),
        bpf_stmt(BPF_LD | BPF_H | BPF_IND, 2),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, local.port() as u32, 0, 1),
        bpf_stmt(BPF_RET | BPF_K, u32::MAX),
        bpf_stmt(BPF_RET | BPF_K, 0),
    ]
}

#[cfg(any(test, all(target_os = "linux", feature = "raw-socket")))]
fn bpf_stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

#[cfg(any(test, all(target_os = "linux", feature = "raw-socket")))]
fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

#[cfg(any(test, all(target_os = "linux", feature = "raw-socket")))]
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[cfg(all(target_os = "linux", feature = "raw-socket"))]
#[repr(C)]
struct SockFprog {
    len: libc::c_ushort,
    filter: *mut SockFilter,
}

#[cfg(any(test, all(target_os = "linux", feature = "raw-socket")))]
#[repr(C)]
struct TpacketReq {
    tp_block_size: u32,
    tp_block_nr: u32,
    tp_frame_size: u32,
    tp_frame_nr: u32,
}

#[cfg(all(target_os = "linux", feature = "raw-socket"))]
#[repr(C)]
struct Tpacket2Hdr {
    tp_status: u32,
    tp_len: u32,
    tp_snaplen: u32,
    tp_mac: u16,
    tp_net: u16,
    tp_sec: u32,
    tp_nsec: u32,
    tp_vlan_tci: u16,
    tp_vlan_tpid: u16,
    tp_padding: [u8; 4],
}

#[cfg(all(target_os = "linux", feature = "raw-socket"))]
impl PacketRxRing {
    fn layout(&self) -> PacketCaptureRingLayout {
        PacketCaptureRingLayout {
            block_size: self.block_size as u32,
            block_nr: self.block_nr as u32,
            frame_size: self.frame_size as u32,
            frame_nr: self.frame_nr as u32,
        }
    }

    fn consume_next_packet(&mut self, mut consume: impl FnMut(&[u8])) -> bool {
        let frame = self.frame_ptr(self.current_frame);
        let header = unsafe { &mut *(frame as *mut Tpacket2Hdr) };
        if header.tp_status & TP_STATUS_USER == 0 {
            return false;
        }
        let packet_offset = usize::from(header.tp_mac);
        let packet_len = header.tp_snaplen as usize;
        // Bounds guard: `tp_mac`/`tp_snaplen` are kernel-supplied and normally
        // sane, but a malformed frame (driver quirk, snaplen > frame_size, or a
        // straddled offset) would make the slice run past this mmap-ring frame —
        // an out-of-bounds read / UB, not a catchable panic. Clamp to the frame:
        // only form the pointer when the offset is in-range, and cap the length
        // to what actually remains in the frame. A bad frame is dropped (its
        // status returned to the kernel) rather than read out of bounds.
        if packet_offset <= self.frame_size {
            let safe_len = packet_len.min(self.frame_size - packet_offset);
            let packet = unsafe { std::slice::from_raw_parts(frame.add(packet_offset), safe_len) };
            consume(packet);
        }
        header.tp_status = TP_STATUS_KERNEL;
        self.current_frame = (self.current_frame + 1) % self.frame_nr;
        true
    }

    fn frame_ptr(&self, index: usize) -> *mut u8 {
        unsafe { self.ptr.add(index * self.frame_size) }
    }
}

#[cfg(all(target_os = "linux", feature = "raw-socket"))]
impl Drop for PacketRxRing {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.len);
        }
    }
}

#[cfg(all(target_os = "linux", feature = "raw-socket"))]
impl Drop for PacketCaptureSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

#[cfg(any(test, all(target_os = "linux", feature = "raw-socket")))]
const BPF_LD: u16 = 0x00;
#[cfg(any(test, all(target_os = "linux", feature = "raw-socket")))]
const BPF_LDX: u16 = 0x01;
#[cfg(any(test, all(target_os = "linux", feature = "raw-socket")))]
const BPF_JMP: u16 = 0x05;
#[cfg(any(test, all(target_os = "linux", feature = "raw-socket")))]
const BPF_RET: u16 = 0x06;
#[cfg(any(test, all(target_os = "linux", feature = "raw-socket")))]
const BPF_W: u16 = 0x00;
#[cfg(any(test, all(target_os = "linux", feature = "raw-socket")))]
const BPF_H: u16 = 0x08;
#[cfg(any(test, all(target_os = "linux", feature = "raw-socket")))]
const BPF_B: u16 = 0x10;
#[cfg(any(test, all(target_os = "linux", feature = "raw-socket")))]
const BPF_ABS: u16 = 0x20;
#[cfg(any(test, all(target_os = "linux", feature = "raw-socket")))]
const BPF_IND: u16 = 0x40;
#[cfg(any(test, all(target_os = "linux", feature = "raw-socket")))]
const BPF_K: u16 = 0x00;
#[cfg(any(test, all(target_os = "linux", feature = "raw-socket")))]
const BPF_MSH: u16 = 0xa0;
#[cfg(any(test, all(target_os = "linux", feature = "raw-socket")))]
const BPF_JEQ: u16 = 0x10;
#[cfg(any(test, all(target_os = "linux", feature = "raw-socket")))]
const BPF_JSET: u16 = 0x40;
#[cfg(all(target_os = "linux", feature = "raw-socket"))]
const SOL_PACKET: libc::c_int = 263;
#[cfg(all(target_os = "linux", feature = "raw-socket"))]
const PACKET_RX_RING: libc::c_int = 5;
#[cfg(all(target_os = "linux", feature = "raw-socket"))]
const PACKET_VERSION: libc::c_int = 10;
#[cfg(all(target_os = "linux", feature = "raw-socket"))]
const TPACKET_V2: libc::c_int = 1;
#[cfg(all(target_os = "linux", feature = "raw-socket"))]
const TP_STATUS_KERNEL: u32 = 0;
#[cfg(all(target_os = "linux", feature = "raw-socket"))]
const TP_STATUS_USER: u32 = 1;
#[cfg(any(test, all(target_os = "linux", feature = "raw-socket")))]
const TPACKET_ALIGNMENT: u32 = 16;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        build_ipv4_tcp_packet, TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_FLAG_RST, TCP_FLAG_SYN,
    };
    use std::time::Duration;

    #[test]
    fn select_backend_requires_capture_capability() {
        let request = PacketCaptureRequest {
            flow_local: "10.0.0.2:50000".parse().unwrap(),
            flow_remote: "203.0.113.10:443".parse().unwrap(),
            timeout: Duration::from_secs(1),
        };
        let caps = RawCapabilities {
            ipv4_raw_send: false,
            ipv4_packet_capture: false,
            tcp_repair_query: false,
            ipv4_header_control: false,
            ipv4_fragmentation: false,
        };
        let selected = packet_capture_backends()
            .into_iter()
            .find(|backend| backend.can_start(&request, caps));
        assert!(selected.is_none());
    }

    #[test]
    fn select_backend_rejects_non_ipv4_flows() {
        let request = PacketCaptureRequest {
            flow_local: "[2001:db8::1]:50000".parse().unwrap(),
            flow_remote: "[2001:db8::2]:443".parse().unwrap(),
            timeout: Duration::from_secs(1),
        };
        let caps = RawCapabilities {
            ipv4_raw_send: false,
            ipv4_packet_capture: true,
            tcp_repair_query: false,
            ipv4_header_control: false,
            ipv4_fragmentation: false,
        };
        let selected = packet_capture_backends()
            .into_iter()
            .find(|backend| backend.can_start(&request, caps));
        assert!(selected.is_none());
    }

    #[test]
    fn select_backend_prefers_linux_af_packet_when_supported() {
        let request = PacketCaptureRequest {
            flow_local: "10.0.0.2:50000".parse().unwrap(),
            flow_remote: "203.0.113.10:443".parse().unwrap(),
            timeout: Duration::from_secs(1),
        };
        let caps = RawCapabilities {
            ipv4_raw_send: false,
            ipv4_packet_capture: true,
            tcp_repair_query: false,
            ipv4_header_control: false,
            ipv4_fragmentation: false,
        };
        let selected = packet_capture_backends()
            .into_iter()
            .find(|backend| backend.can_start(&request, caps))
            .map(|backend| backend.kind());
        #[cfg(all(target_os = "linux", feature = "raw-socket"))]
        assert_eq!(selected, Some(PacketCaptureBackendKind::LinuxAfPacket));
        #[cfg(not(all(target_os = "linux", feature = "raw-socket")))]
        assert_eq!(selected, None);
    }

    #[test]
    fn unavailable_capture_status_reports_runtime_capability_gap() {
        let request = PacketCaptureRequest {
            flow_local: "10.0.0.2:50000".parse().unwrap(),
            flow_remote: "203.0.113.10:443".parse().unwrap(),
            timeout: Duration::from_secs(1),
        };
        let caps = RawCapabilities {
            ipv4_raw_send: false,
            ipv4_packet_capture: false,
            tcp_repair_query: false,
            ipv4_header_control: false,
            ipv4_fragmentation: false,
        };
        let expected = if cfg!(all(target_os = "linux", feature = "raw-socket")) {
            PacketCaptureStatus::MissingCapability
        } else {
            PacketCaptureStatus::UnsupportedPlatform
        };
        assert_eq!(unavailable_capture_status(&request, caps, false), expected);
    }

    #[test]
    fn unavailable_capture_status_prioritizes_start_failures() {
        let request = PacketCaptureRequest {
            flow_local: "10.0.0.2:50000".parse().unwrap(),
            flow_remote: "203.0.113.10:443".parse().unwrap(),
            timeout: Duration::from_secs(1),
        };
        let caps = RawCapabilities {
            ipv4_raw_send: false,
            ipv4_packet_capture: true,
            tcp_repair_query: false,
            ipv4_header_control: false,
            ipv4_fragmentation: false,
        };
        assert_eq!(
            unavailable_capture_status(&request, caps, true),
            PacketCaptureStatus::BackendStartFailed
        );
    }

    #[tokio::test]
    async fn unavailable_packet_observer_handle_preserves_status() {
        let observation = PacketObservation {
            capture_status: PacketCaptureStatus::UnsupportedPlatform,
            ..PacketObservation::default()
        };
        let finished = PacketObserverHandle::Unavailable(observation.clone())
            .finish()
            .await;
        assert_eq!(finished.capture_status, observation.capture_status);
        assert_eq!(finished.capture_backend, observation.capture_backend);
    }

    #[test]
    fn parse_flow_observation_extracts_server_hint() {
        let local = "10.0.0.2:50000".parse::<SocketAddr>().unwrap();
        let remote = "203.0.113.10:443".parse::<SocketAddr>().unwrap();
        let packet = crate::packet::build_ipv4_tcp_packet_with_shaping(
            "203.0.113.10".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            443,
            50000,
            100,
            200,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
            65535,
            58,
            Some(crate::packet::Ipv4HeaderShaping {
                tos: 0x10,
                identification: 0x1234,
                dont_fragment: true,
            }),
            b"hello",
        )
        .unwrap();
        let mut observed = PacketObservation::default();
        parse_packet_for_flow(
            &packet,
            match local {
                SocketAddr::V4(v4) => v4,
                _ => unreachable!(),
            },
            match remote {
                SocketAddr::V4(v4) => v4,
                _ => unreachable!(),
            },
            &mut observed,
        );
        assert_eq!(observed.first_packet_ttl, Some(58));
        assert_eq!(observed.first_packet_ip_tos, Some(0x10));
        assert_eq!(observed.first_packet_ip_id, Some(0x1234));
        assert_eq!(observed.first_packet_ip_df, Some(true));
        assert_eq!(observed.first_packet_window, Some(65535));
        assert_eq!(
            observed.first_packet_flags,
            Some(TCP_FLAG_ACK | TCP_FLAG_PSH)
        );
        assert_eq!(observed.matched_packets, 1);
        assert_eq!(observed.server_hint, Some(ServerType::LikelyCdn));
        assert_eq!(observed.first_data_ttl, Some(58));
        assert_eq!(observed.first_data_window, Some(65535));
        assert_eq!(observed.first_data_payload_len, Some(5));
        assert_eq!(observed.first_data_flags, Some(TCP_FLAG_ACK | TCP_FLAG_PSH));
        assert_eq!(observed.first_data_server_hint, Some(ServerType::LikelyCdn));
    }

    #[test]
    fn parse_flow_observation_tracks_syn_ack_stage() {
        let local = "10.0.0.2:50000".parse::<SocketAddr>().unwrap();
        let remote = "203.0.113.10:443".parse::<SocketAddr>().unwrap();
        let packet = crate::packet::build_ipv4_tcp_packet_with_options(
            "203.0.113.10".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            443,
            50000,
            100,
            200,
            TCP_FLAG_SYN | TCP_FLAG_ACK,
            64240,
            52,
            &[
                2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2, 1, 3, 3, 8,
            ],
            &[],
        )
        .unwrap();
        let mut observed = PacketObservation::default();
        parse_packet_for_flow(
            &packet,
            match local {
                SocketAddr::V4(v4) => v4,
                _ => unreachable!(),
            },
            match remote {
                SocketAddr::V4(v4) => v4,
                _ => unreachable!(),
            },
            &mut observed,
        );
        assert_eq!(observed.syn_ack_ttl, Some(52));
        assert_eq!(observed.syn_ack_window, Some(64240));
        assert_eq!(observed.syn_ack_mss, Some(1460));
        assert_eq!(observed.syn_ack_window_scale, Some(8));
        assert_eq!(observed.syn_ack_sack_permitted, Some(true));
        assert_eq!(observed.syn_ack_timestamp_option, Some(true));
        assert!(observed.syn_ack_server_hint.is_some());
    }

    #[test]
    fn parse_flow_observation_extracts_rst_source() {
        let local = "10.0.0.2:50000".parse::<SocketAddr>().unwrap();
        let remote = "203.0.113.10:443".parse::<SocketAddr>().unwrap();
        let mut observed = PacketObservation {
            first_packet_ttl: Some(64),
            ..Default::default()
        };
        let packet = build_ipv4_tcp_packet(
            "203.0.113.10".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            443,
            50000,
            100,
            200,
            TCP_FLAG_RST | TCP_FLAG_ACK,
            4096,
            10,
            &[],
        )
        .unwrap();
        parse_packet_for_flow(
            &packet,
            match local {
                SocketAddr::V4(v4) => v4,
                _ => unreachable!(),
            },
            match remote {
                SocketAddr::V4(v4) => v4,
                _ => unreachable!(),
            },
            &mut observed,
        );
        assert_eq!(observed.rst_ttl, Some(10));
        assert_eq!(observed.rst_source, Some(RstSource::Middlebox));
        assert_eq!(observed.matched_packets, 1);
    }

    #[test]
    fn parse_flow_observation_marks_zero_window_after_first_data() {
        let local = "10.0.0.2:50000".parse::<SocketAddr>().unwrap();
        let remote = "203.0.113.10:443".parse::<SocketAddr>().unwrap();
        let mut observed = PacketObservation::default();
        let first_data_packet = build_ipv4_tcp_packet(
            "203.0.113.10".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            443,
            50000,
            100,
            200,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
            65535,
            58,
            b"hello",
        )
        .unwrap();
        parse_packet_for_flow(
            &first_data_packet,
            match local {
                SocketAddr::V4(v4) => v4,
                _ => unreachable!(),
            },
            match remote {
                SocketAddr::V4(v4) => v4,
                _ => unreachable!(),
            },
            &mut observed,
        );
        let zero_window_ack = build_ipv4_tcp_packet(
            "203.0.113.10".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            443,
            50000,
            105,
            205,
            TCP_FLAG_ACK,
            0,
            58,
            &[],
        )
        .unwrap();
        parse_packet_for_flow(
            &zero_window_ack,
            match local {
                SocketAddr::V4(v4) => v4,
                _ => unreachable!(),
            },
            match remote {
                SocketAddr::V4(v4) => v4,
                _ => unreachable!(),
            },
            &mut observed,
        );
        assert_eq!(observed.first_data_ttl, Some(58));
        assert_eq!(observed.first_data_window, Some(0));
        assert_eq!(observed.matched_packets, 2);
    }

    #[test]
    fn parse_flow_observation_counts_duplicate_acks_after_first_data() {
        let local = "10.0.0.2:50000".parse::<SocketAddr>().unwrap();
        let remote = "203.0.113.10:443".parse::<SocketAddr>().unwrap();
        let mut observed = PacketObservation::default();
        let first_data_packet = build_ipv4_tcp_packet(
            "203.0.113.10".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            443,
            50000,
            100,
            200,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
            65535,
            58,
            b"hello",
        )
        .unwrap();
        parse_packet_for_flow(
            &first_data_packet,
            match local {
                SocketAddr::V4(v4) => v4,
                _ => unreachable!(),
            },
            match remote {
                SocketAddr::V4(v4) => v4,
                _ => unreachable!(),
            },
            &mut observed,
        );
        let ack_packet = build_ipv4_tcp_packet(
            "203.0.113.10".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            443,
            50000,
            105,
            205,
            TCP_FLAG_ACK,
            4096,
            58,
            &[],
        )
        .unwrap();
        parse_packet_for_flow(
            &ack_packet,
            match local {
                SocketAddr::V4(v4) => v4,
                _ => unreachable!(),
            },
            match remote {
                SocketAddr::V4(v4) => v4,
                _ => unreachable!(),
            },
            &mut observed,
        );
        parse_packet_for_flow(
            &ack_packet,
            match local {
                SocketAddr::V4(v4) => v4,
                _ => unreachable!(),
            },
            match remote {
                SocketAddr::V4(v4) => v4,
                _ => unreachable!(),
            },
            &mut observed,
        );
        assert_eq!(observed.first_data_ttl, Some(58));
        assert_eq!(observed.downstream_dup_ack_count, 1);
        assert_eq!(observed.matched_packets, 3);
    }

    #[test]
    fn parse_flow_observation_counts_retransmitted_payload_after_first_data() {
        let local = "10.0.0.2:50000".parse::<SocketAddr>().unwrap();
        let remote = "203.0.113.10:443".parse::<SocketAddr>().unwrap();
        let mut observed = PacketObservation::default();
        let first_data_packet = build_ipv4_tcp_packet(
            "203.0.113.10".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            443,
            50000,
            100,
            200,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
            65535,
            58,
            b"hello",
        )
        .unwrap();
        parse_packet_for_flow(
            &first_data_packet,
            match local {
                SocketAddr::V4(v4) => v4,
                _ => unreachable!(),
            },
            match remote {
                SocketAddr::V4(v4) => v4,
                _ => unreachable!(),
            },
            &mut observed,
        );
        let retransmit_packet = build_ipv4_tcp_packet(
            "203.0.113.10".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            443,
            50000,
            100,
            200,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
            4096,
            58,
            b"hello",
        )
        .unwrap();
        parse_packet_for_flow(
            &retransmit_packet,
            match local {
                SocketAddr::V4(v4) => v4,
                _ => unreachable!(),
            },
            match remote {
                SocketAddr::V4(v4) => v4,
                _ => unreachable!(),
            },
            &mut observed,
        );
        assert_eq!(observed.first_data_ttl, Some(58));
        assert_eq!(observed.downstream_retransmit_count, 1);
        assert_eq!(observed.matched_packets, 2);
    }

    #[test]
    fn parse_flow_observation_marks_fin_after_first_data() {
        let local = "10.0.0.2:50000".parse::<SocketAddr>().unwrap();
        let remote = "203.0.113.10:443".parse::<SocketAddr>().unwrap();
        let mut observed = PacketObservation::default();
        let first_data_packet = build_ipv4_tcp_packet(
            "203.0.113.10".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            443,
            50000,
            100,
            200,
            TCP_FLAG_ACK | TCP_FLAG_PSH,
            65535,
            58,
            b"hello",
        )
        .unwrap();
        parse_packet_for_flow(
            &first_data_packet,
            match local {
                SocketAddr::V4(v4) => v4,
                _ => unreachable!(),
            },
            match remote {
                SocketAddr::V4(v4) => v4,
                _ => unreachable!(),
            },
            &mut observed,
        );
        let fin_packet = build_ipv4_tcp_packet(
            "203.0.113.10".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            443,
            50000,
            105,
            205,
            TCP_FLAG_ACK | TCP_FLAG_FIN,
            4096,
            58,
            &[],
        )
        .unwrap();
        parse_packet_for_flow(
            &fin_packet,
            match local {
                SocketAddr::V4(v4) => v4,
                _ => unreachable!(),
            },
            match remote {
                SocketAddr::V4(v4) => v4,
                _ => unreachable!(),
            },
            &mut observed,
        );
        assert_eq!(observed.first_data_ttl, Some(58));
        assert!(observed.downstream_fin_after_data);
        assert_eq!(observed.matched_packets, 2);
    }

    #[test]
    fn packet_observation_exposes_reference_and_rst_hops() {
        let observed = PacketObservation {
            syn_ack_ttl: Some(57),
            first_data_ttl: Some(58),
            first_packet_ttl: Some(56),
            rst_ttl: Some(50),
            ..Default::default()
        };
        assert_eq!(observed.reference_path_hops(), Some(2));
        assert_eq!(observed.rst_path_hops(), Some(10));
    }

    #[test]
    fn build_ipv4_tcp_flow_filter_matches_exact_flow_shape() {
        let local = "10.0.0.2:50000".parse().unwrap();
        let remote = "203.0.113.10:443".parse().unwrap();
        let filter = build_ipv4_tcp_flow_filter(local, remote);
        assert_eq!(filter.len(), 15);
        assert_eq!(filter[0].k, 9);
        assert_eq!(filter[4].k, 12);
        assert_eq!(filter[5].k, u32::from(*remote.ip()));
        assert_eq!(filter[7].k, u32::from(*local.ip()));
        assert_eq!(filter[10].k, remote.port() as u32);
        assert_eq!(filter[12].k, local.port() as u32);
    }

    #[test]
    fn build_ring_request_uses_page_aligned_dynamic_sizes() {
        let req = build_ring_request(4096, 20000);
        assert_eq!(req.tp_frame_size, 4096);
        assert_eq!(req.tp_block_nr, 3);
        assert_eq!(req.tp_block_size, 8192);
        assert_eq!(req.tp_frame_nr, 6);
    }

    #[test]
    fn build_ring_request_never_smaller_than_one_frame() {
        let req = build_ring_request(4096, 512);
        assert_eq!(req.tp_frame_size, 4096);
        assert_eq!(req.tp_block_size, 4096);
        assert_eq!(req.tp_block_nr, 1);
        assert_eq!(req.tp_frame_nr, 1);
    }

    #[test]
    fn build_ring_request_uses_multiple_blocks_for_larger_recv_buffers() {
        let req = build_ring_request(4096, 65536);
        assert!(req.tp_block_nr > 1);
        assert_eq!(req.tp_block_size % 4096, 0);
        assert_eq!(req.tp_frame_nr % req.tp_block_nr, 0);
    }
}
