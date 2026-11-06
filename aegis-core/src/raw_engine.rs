//! Raw engine: capability-aware layer for raw packet operations.
//!
//! Wraps `packet.rs` (IPv4/TCP builders + raw send) without duplicating logic.
//! On Linux, exact TCP seq/ack is queried through `TCP_REPAIR` + `TCP_QUEUE_SEQ`.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tracing::trace;

use crate::mimicry::{
    WireFragmentChoreographyPlan, WireIpv4HeaderShapingPreface, WireNegotiatedOptionsPreface,
};
use crate::packet::{
    build_ipv4_tcp_packet_with_options_and_shaping, build_ipv4_tcp_packet_with_shaping,
    build_ipv4_tcp_rst_packet, corrupt_ipv4_tcp_checksum, fragment_ipv4_packet_to_mtu,
    fragment_ipv4_packet_to_mtu_with_first_payload, fragment_ipv4_packet_with_overlap_to_mtu,
    linux_send_raw_ipv4_best_effort, linux_send_raw_ipv4_with_ttl_best_effort, Ipv4HeaderShaping,
    TCP_FLAG_ACK, TCP_FLAG_PSH,
};

const FALLBACK_RAW_IPV4_MTU: usize = 1280;

/// Platform capabilities detected at runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawCapabilities {
    /// Linux + `feature = "raw-socket"`: can attempt raw IPv4 send (needs CAP_NET_RAW).
    pub ipv4_raw_send: bool,
    /// Linux + `feature = "raw-socket"`: can observe IPv4/TCP packets for this process (needs CAP_NET_RAW).
    pub ipv4_packet_capture: bool,
    /// Linux path for exact seq/ack via `TCP_REPAIR` / `TCP_QUEUE_SEQ` exists.
    /// Runtime still needs `CAP_NET_ADMIN` on the process.
    pub tcp_repair_query: bool,
    /// IPv4 header fields (например, TTL) можно менять packet-by-packet.
    pub ipv4_header_control: bool,
    /// IPv4 fragmentation поддержана на уровне packet helpers.
    pub ipv4_fragmentation: bool,
}

/// TCP connection state extracted from kernel.
#[derive(Clone, Copy, Debug)]
pub struct TcpSeqState {
    pub snd_nxt: u32,
    pub rcv_nxt: u32,
    pub local_port: u16,
    pub remote_port: u16,
}

#[derive(Clone, Copy, Debug)]
struct TcpPacketContext {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    seq: u32,
    ack: u32,
    sport: u16,
    dport: u16,
    window: u16,
}

#[derive(Clone, Copy, Debug)]
pub struct OverlapDecoyPlan<'a> {
    pub dst: SocketAddr,
    pub ttl: u8,
    pub split_at: usize,
    pub overlap: usize,
    pub strategy_id: &'a str,
}

#[derive(Clone, Copy, Debug)]
pub struct FragmentDecoyPlan<'a> {
    pub dst: SocketAddr,
    pub ttl: u8,
    pub first_payload_len: usize,
    pub overlap: usize,
    pub strategy_id: &'a str,
}

#[derive(Clone, Copy, Debug)]
pub struct OrderedDecoyChoreography<'a> {
    pub dst: SocketAddr,
    pub ttl: u8,
    pub fragment_first_payload_len: usize,
    pub fragment_overlap: usize,
    pub disorder_split_at: usize,
    pub overlap: usize,
    pub strategy_id: &'a str,
}

/// Confirmed raw-wire work performed for one strategy effect. A successful
/// canonical TCP write is deliberately not part of this value: callers must
/// prove the raw effect and the user payload independently.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RawWireEffect {
    pub packets: usize,
    pub bytes: usize,
}

impl RawWireEffect {
    fn one(bytes: usize) -> Self {
        Self { packets: 1, bytes }
    }

    fn combine(self, other: Self) -> Self {
        Self {
            packets: self.packets + other.packets,
            bytes: self.bytes + other.bytes,
        }
    }
}

fn raw_stage_error(stage: &'static str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{stage}: {error}"))
}

#[cfg(target_os = "linux")]
fn connected_ipv4_path_mtu(stream: &tokio::net::TcpStream) -> io::Result<usize> {
    use std::mem;
    use std::os::fd::AsRawFd;

    let mut mtu: libc::c_int = 0;
    let mut len = mem::size_of_val(&mtu) as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MTU,
            (&mut mtu as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    usize::try_from(mtu)
        .ok()
        .filter(|value| (576..=u16::MAX as usize).contains(value))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid IPv4 path MTU"))
}

#[cfg(not(target_os = "linux"))]
fn connected_ipv4_path_mtu(_stream: &tokio::net::TcpStream) -> io::Result<usize> {
    Ok(FALLBACK_RAW_IPV4_MTU)
}

fn mtu_or_safe_fallback(
    engine: &(impl RawEngine + ?Sized),
    stream: &tokio::net::TcpStream,
) -> usize {
    match engine.ipv4_path_mtu(stream) {
        Ok(mtu) => mtu,
        Err(error) => {
            trace!(
                %error,
                fallback_mtu = FALLBACK_RAW_IPV4_MTU,
                "IPv4 path MTU query failed; using conservative fallback"
            );
            FALLBACK_RAW_IPV4_MTU
        }
    }
}

fn send_mtu_safe_ipv4_packet(
    engine: &(impl RawEngine + ?Sized),
    stream: &tokio::net::TcpStream,
    packet: &[u8],
    dst: Ipv4Addr,
    ttl: Option<u8>,
    plan_stage: &'static str,
    send_stage: &'static str,
) -> io::Result<RawWireEffect> {
    let mtu = mtu_or_safe_fallback(engine, stream);
    let packets = fragment_ipv4_packet_to_mtu(packet, mtu)
        .map_err(|error| raw_stage_error(plan_stage, error))?;
    let mut effect = RawWireEffect::default();
    for fragment in &packets {
        let bytes = match ttl {
            Some(ttl) => engine.send_raw_ipv4_with_ttl(fragment, dst, ttl),
            None => engine.send_raw_ipv4(fragment, dst),
        }
        .map_err(|error| raw_stage_error(send_stage, error))?;
        effect = effect.combine(RawWireEffect::one(bytes));
    }
    Ok(effect)
}

/// Raw engine for packet-level operations (RST injection, TTL tricks, IP fragmentation).
pub trait RawEngine: Send + Sync {
    fn capabilities(&self) -> RawCapabilities;

    /// Extract TCP seq/ack state from a connected TcpStream.
    /// Returns None if the platform does not support the query or the process
    /// lacks the required Linux capabilities.
    fn get_tcp_state(&self, stream: &tokio::net::TcpStream, dst: SocketAddr)
        -> Option<TcpSeqState>;

    /// Send a raw IPv4 packet (full packet including IP header).
    fn send_raw_ipv4(&self, packet: &[u8], dst: Ipv4Addr) -> io::Result<usize>;

    /// Send a raw IPv4 packet, patching TTL packet-by-packet before send.
    fn send_raw_ipv4_with_ttl(&self, packet: &[u8], dst: Ipv4Addr, ttl: u8) -> io::Result<usize>;

    /// Effective MTU for the connected IPv4 route used by raw packet plans.
    fn ipv4_path_mtu(&self, stream: &tokio::net::TcpStream) -> io::Result<usize> {
        connected_ipv4_path_mtu(stream)
    }

    fn try_send_fake_rst(
        &self,
        stream: &tokio::net::TcpStream,
        dst: SocketAddr,
        strategy_id: &str,
    ) -> io::Result<RawWireEffect> {
        let ctx = tcp_packet_context(self, stream, dst)
            .map_err(|error| raw_stage_error("raw_rst_context", error))?;

        let rst_packet = build_ipv4_tcp_rst_packet(
            ctx.src_ip, ctx.dst_ip, ctx.sport, ctx.dport, ctx.seq, ctx.ack,
        );
        let bytes = self
            .send_raw_ipv4(&rst_packet, ctx.dst_ip)
            .map_err(|error| raw_stage_error("raw_rst_send", error))?;
        trace!(strategy_id, bytes, ?dst, "fake RST sent");
        Ok(RawWireEffect::one(bytes))
    }

    fn try_send_ttl_desync_first_packet(
        &self,
        stream: &tokio::net::TcpStream,
        dst: SocketAddr,
        payload: &[u8],
        ttl: u8,
        ipv4_header_shaping: Option<&WireIpv4HeaderShapingPreface>,
        strategy_id: &str,
    ) -> io::Result<RawWireEffect> {
        let (ctx, packet) =
            build_first_payload_packet(self, stream, dst, payload, ipv4_header_shaping)
                .map_err(|error| raw_stage_error("ttl_desync_build", error))?;
        let effect = send_mtu_safe_ipv4_packet(
            self,
            stream,
            &packet,
            ctx.dst_ip,
            Some(ttl),
            "ttl_desync_mtu_plan",
            "ttl_desync_send",
        )?;
        trace!(strategy_id, ttl, ?effect, ?dst, "ttl_desync decoy sent");
        Ok(effect)
    }

    /// Emit a TTL-bounded TCP decoy at an exact offset from the kernel's
    /// current first-payload sequence number. Geneva uses this for live TCP
    /// fragmentation/segmentation trees, including reversed ordering. The
    /// canonical application write remains kernel-owned and is sent once.
    fn try_send_ttl_desync_first_packet_at_seq_offset(
        &self,
        stream: &tokio::net::TcpStream,
        dst: SocketAddr,
        payload: &[u8],
        ttl: u8,
        seq_offset: u32,
        strategy_id: &str,
    ) -> io::Result<RawWireEffect> {
        if payload.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Geneva TCP fragment decoy cannot have an empty payload",
            ));
        }
        let ctx = tcp_packet_context(self, stream, dst)
            .map_err(|error| raw_stage_error("geneva_segment_context", error))?;
        let packet =
            build_payload_packet_from_ctx(ctx, ctx.seq.wrapping_add(seq_offset), payload, None)
                .map_err(|error| raw_stage_error("geneva_segment_build", error))?;
        let effect = send_mtu_safe_ipv4_packet(
            self,
            stream,
            &packet,
            ctx.dst_ip,
            Some(ttl),
            "geneva_segment_mtu_plan",
            "geneva_segment_send",
        )?;
        trace!(
            strategy_id,
            ttl,
            seq_offset,
            ?effect,
            ?dst,
            "Geneva TCP fragment decoy sent"
        );
        Ok(effect)
    }

    #[allow(clippy::too_many_arguments)]
    fn try_send_ttl_window_preface_first_packet(
        &self,
        stream: &tokio::net::TcpStream,
        dst: SocketAddr,
        payload: &[u8],
        ttl: u8,
        window: u16,
        ipv4_header_shaping: Option<&WireIpv4HeaderShapingPreface>,
        strategy_id: &str,
    ) -> io::Result<RawWireEffect> {
        let (ctx, packet) = build_first_payload_packet_with_window(
            self,
            stream,
            dst,
            payload,
            window,
            ipv4_header_shaping,
        )
        .map_err(|error| raw_stage_error("ttl_window_preface_build", error))?;
        let effect = send_mtu_safe_ipv4_packet(
            self,
            stream,
            &packet,
            ctx.dst_ip,
            Some(ttl),
            "ttl_window_preface_mtu_plan",
            "ttl_window_preface_send",
        )?;
        trace!(
            strategy_id,
            ttl,
            window,
            ?effect,
            ?dst,
            "ttl_window_preface decoy sent"
        );
        Ok(effect)
    }

    #[allow(clippy::too_many_arguments)]
    fn try_send_ttl_window_options_preface_first_packet(
        &self,
        stream: &tokio::net::TcpStream,
        dst: SocketAddr,
        payload: &[u8],
        ttl: u8,
        window: u16,
        ipv4_header_shaping: Option<&WireIpv4HeaderShapingPreface>,
        strategy_id: &str,
    ) -> io::Result<RawWireEffect> {
        let (ctx, packet) = build_first_payload_packet_with_window_and_options(
            self,
            stream,
            dst,
            payload,
            window,
            ipv4_header_shaping,
        )
        .map_err(|error| raw_stage_error("ttl_window_options_preface_build", error))?;
        let effect = send_mtu_safe_ipv4_packet(
            self,
            stream,
            &packet,
            ctx.dst_ip,
            Some(ttl),
            "ttl_window_options_preface_mtu_plan",
            "ttl_window_options_preface_send",
        )?;
        trace!(
            strategy_id,
            ttl,
            window,
            ?effect,
            ?dst,
            "ttl_window_options_preface decoy sent"
        );
        Ok(effect)
    }

    #[allow(clippy::too_many_arguments)]
    fn try_send_ttl_window_negotiated_options_preface_first_packet(
        &self,
        stream: &tokio::net::TcpStream,
        dst: SocketAddr,
        payload: &[u8],
        ttl: u8,
        window: u16,
        ipv4_header_shaping: Option<&WireIpv4HeaderShapingPreface>,
        negotiated: &WireNegotiatedOptionsPreface,
        strategy_id: &str,
    ) -> io::Result<RawWireEffect> {
        let (ctx, packet) = build_first_payload_packet_with_window_and_negotiated_options(
            self,
            stream,
            dst,
            payload,
            window,
            ipv4_header_shaping,
            negotiated,
        )
        .map_err(|error| raw_stage_error("ttl_window_negotiated_preface_build", error))?;
        let effect = send_mtu_safe_ipv4_packet(
            self,
            stream,
            &packet,
            ctx.dst_ip,
            Some(ttl),
            "ttl_window_negotiated_preface_mtu_plan",
            "ttl_window_negotiated_preface_send",
        )?;
        trace!(
            strategy_id,
            ttl,
            window,
            negotiated_profile = negotiated.profile,
            ?effect,
            ?dst,
            "ttl_window_negotiated_options_preface decoy sent"
        );
        Ok(effect)
    }

    #[allow(clippy::too_many_arguments)]
    fn try_send_fragment_ordered_decoy_choreography_first_packet(
        &self,
        stream: &tokio::net::TcpStream,
        dst: SocketAddr,
        payload: &[u8],
        ttl: u8,
        ipv4_header_shaping: Option<&WireIpv4HeaderShapingPreface>,
        choreography: &WireFragmentChoreographyPlan,
        strategy_id: &str,
    ) -> io::Result<RawWireEffect> {
        let ordered = OrderedDecoyChoreography {
            dst,
            ttl,
            fragment_first_payload_len: choreography.fragment_first_payload_len,
            fragment_overlap: choreography.fragment_overlap,
            disorder_split_at: choreography.disorder_split_at,
            overlap: choreography.overlap_bytes,
            strategy_id,
        };
        let fragmented = self.try_send_fragmented_first_packet(
            stream,
            payload,
            ipv4_header_shaping,
            FragmentDecoyPlan {
                dst: ordered.dst,
                ttl: ordered.ttl,
                first_payload_len: ordered.fragment_first_payload_len,
                overlap: ordered.fragment_overlap,
                strategy_id: ordered.strategy_id,
            },
        )?;
        let disordered = self.try_send_disordered_first_packet(
            stream,
            ordered.dst,
            payload,
            ordered.ttl,
            ipv4_header_shaping,
            ordered.disorder_split_at,
            ordered.strategy_id,
        )?;
        let overlapping = self.try_send_overlapping_first_packet(
            stream,
            payload,
            ipv4_header_shaping,
            OverlapDecoyPlan {
                dst: ordered.dst,
                ttl: ordered.ttl,
                split_at: ordered.disorder_split_at,
                overlap: ordered.overlap,
                strategy_id: ordered.strategy_id,
            },
        )?;
        Ok(fragmented.combine(disordered).combine(overlapping))
    }

    fn try_send_fragmented_first_packet(
        &self,
        stream: &tokio::net::TcpStream,
        payload: &[u8],
        ipv4_header_shaping: Option<&WireIpv4HeaderShapingPreface>,
        plan: FragmentDecoyPlan<'_>,
    ) -> io::Result<RawWireEffect> {
        let (ctx, packet) =
            build_first_payload_packet(self, stream, plan.dst, payload, ipv4_header_shaping)
                .map_err(|error| raw_stage_error("ip_frag_build", error))?;
        let split =
            20usize.saturating_add(plan.first_payload_len.min(payload.len().saturating_sub(1)));
        let mtu = mtu_or_safe_fallback(self, stream);
        let frags = if plan.overlap == 0 {
            fragment_ipv4_packet_to_mtu_with_first_payload(&packet, split, mtu)
        } else {
            fragment_ipv4_packet_with_overlap_to_mtu(&packet, split, plan.overlap, mtu)
        }
        .map_err(|error| raw_stage_error("ip_frag_plan", error))?;
        let mut effect = RawWireEffect::default();
        for (idx, frag) in frags.iter().enumerate() {
            let bytes = self
                .send_raw_ipv4_with_ttl(frag, ctx.dst_ip, plan.ttl)
                .map_err(|error| raw_stage_error("ip_frag_send", error))?;
            trace!(
                plan.strategy_id,
                frag_idx = idx,
                ttl = plan.ttl,
                bytes,
                ?plan.dst,
                "ip_frag decoy sent"
            );
            effect = effect.combine(RawWireEffect::one(bytes));
        }
        Ok(effect)
    }

    #[allow(clippy::too_many_arguments)]
    fn try_send_disordered_first_packet(
        &self,
        stream: &tokio::net::TcpStream,
        dst: SocketAddr,
        payload: &[u8],
        ttl: u8,
        ipv4_header_shaping: Option<&WireIpv4HeaderShapingPreface>,
        split_at: usize,
        strategy_id: &str,
    ) -> io::Result<RawWireEffect> {
        let ctx = tcp_packet_context(self, stream, dst)
            .map_err(|error| raw_stage_error("fake_disorder_context", error))?;
        let split = normalize_split(payload.len(), split_at).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "fake_disorder requires at least two payload bytes",
            )
        })?;
        let tail = build_payload_packet_from_ctx(
            ctx,
            ctx.seq.wrapping_add(split as u32),
            &payload[split..],
            ipv4_header_shaping,
        );
        let head =
            build_payload_packet_from_ctx(ctx, ctx.seq, &payload[..split], ipv4_header_shaping);
        let tail = tail.map_err(|error| raw_stage_error("fake_disorder_tail_build", error))?;
        let head = head.map_err(|error| raw_stage_error("fake_disorder_head_build", error))?;
        let tail_effect = send_mtu_safe_ipv4_packet(
            self,
            stream,
            &tail,
            ctx.dst_ip,
            Some(ttl),
            "fake_disorder_tail_mtu_plan",
            "fake_disorder_tail_send",
        )?;
        trace!(
            strategy_id,
            ttl,
            ?tail_effect,
            ?dst,
            "fake_disorder tail sent"
        );
        let head_effect = send_mtu_safe_ipv4_packet(
            self,
            stream,
            &head,
            ctx.dst_ip,
            Some(ttl),
            "fake_disorder_head_mtu_plan",
            "fake_disorder_head_send",
        )?;
        trace!(
            strategy_id,
            ttl,
            ?head_effect,
            ?dst,
            "fake_disorder head sent"
        );
        Ok(tail_effect.combine(head_effect))
    }

    fn try_send_overlapping_first_packet(
        &self,
        stream: &tokio::net::TcpStream,
        payload: &[u8],
        ipv4_header_shaping: Option<&WireIpv4HeaderShapingPreface>,
        plan: OverlapDecoyPlan<'_>,
    ) -> io::Result<RawWireEffect> {
        let ctx = tcp_packet_context(self, stream, plan.dst)
            .map_err(|error| raw_stage_error("overlap_context", error))?;
        let split = normalize_split(payload.len(), plan.split_at).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "overlap requires at least two payload bytes",
            )
        })?;
        let overlap = plan
            .overlap
            .min(split)
            .min(payload.len().saturating_sub(split));
        if overlap == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "overlap requires a non-empty overlapping window",
            ));
        }
        let head =
            build_payload_packet_from_ctx(ctx, ctx.seq, &payload[..split], ipv4_header_shaping);
        let second_seq = ctx.seq.wrapping_add((split - overlap) as u32);
        let overlap_payload = build_conflicting_overlap_payload(payload, split, overlap);
        let second =
            build_payload_packet_from_ctx(ctx, second_seq, &overlap_payload, ipv4_header_shaping);
        let head = head.map_err(|error| raw_stage_error("overlap_head_build", error))?;
        let second = second.map_err(|error| raw_stage_error("overlap_tail_build", error))?;
        let head_effect = send_mtu_safe_ipv4_packet(
            self,
            stream,
            &head,
            ctx.dst_ip,
            Some(plan.ttl),
            "overlap_head_mtu_plan",
            "overlap_head_send",
        )?;
        trace!(
            plan.strategy_id,
            ttl = plan.ttl,
            ?head_effect,
            ?plan.dst,
            "overlap head sent"
        );
        let second_effect = send_mtu_safe_ipv4_packet(
            self,
            stream,
            &second,
            ctx.dst_ip,
            Some(plan.ttl),
            "overlap_tail_mtu_plan",
            "overlap_tail_send",
        )?;
        trace!(
            plan.strategy_id,
            ttl = plan.ttl,
            ?second_effect,
            ?plan.dst,
            "overlap conflicting tail sent"
        );
        Ok(head_effect.combine(second_effect))
    }

    fn try_send_bad_checksum_first_packet(
        &self,
        stream: &tokio::net::TcpStream,
        dst: SocketAddr,
        payload: &[u8],
        ttl: u8,
        strategy_id: &str,
    ) -> io::Result<RawWireEffect> {
        let (ctx, mut packet) = build_first_payload_packet(self, stream, dst, payload, None)
            .map_err(|error| raw_stage_error("checksum_trick_build", error))?;
        corrupt_ipv4_tcp_checksum(&mut packet)
            .map_err(|error| raw_stage_error("checksum_trick_patch", error))?;
        let ttl_override = if ttl == 64 { None } else { Some(ttl) };
        let effect = send_mtu_safe_ipv4_packet(
            self,
            stream,
            &packet,
            ctx.dst_ip,
            ttl_override,
            "checksum_trick_mtu_plan",
            "checksum_trick_send",
        )?;
        trace!(strategy_id, ttl, ?effect, ?dst, "checksum_trick decoy sent");
        Ok(effect)
    }
}

/// Create the default platform-aware raw engine.
pub fn default_raw_engine() -> Arc<dyn RawEngine> {
    Arc::new(PlatformRawEngine)
}

struct PlatformRawEngine;

fn env_override_bool(name: &str) -> Option<bool> {
    match std::env::var(name).ok()?.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn apply_test_capability_overrides(mut caps: RawCapabilities) -> RawCapabilities {
    // Test-only env seams let e2e/contract helpers exercise the wire requested/
    // active matrix without depending on the host running the suite with real
    // CAP_NET_RAW/CAP_NET_ADMIN privileges.
    if let Some(value) = env_override_bool("AEGIS_TEST_RAW_IPV4_SEND") {
        caps.ipv4_raw_send = value;
    }
    if let Some(value) = env_override_bool("AEGIS_TEST_RAW_PACKET_CAPTURE") {
        caps.ipv4_packet_capture = value;
    }
    if let Some(value) = env_override_bool("AEGIS_TEST_RAW_TCP_REPAIR") {
        caps.tcp_repair_query = value;
    }
    if let Some(value) = env_override_bool("AEGIS_TEST_RAW_IPV4_HEADER_CONTROL") {
        caps.ipv4_header_control = value;
    }
    if let Some(value) = env_override_bool("AEGIS_TEST_RAW_IPV4_FRAGMENTATION") {
        caps.ipv4_fragmentation = value;
    }
    caps
}

impl RawEngine for PlatformRawEngine {
    fn capabilities(&self) -> RawCapabilities {
        let raw = cfg!(all(target_os = "linux", feature = "raw-socket"))
            && process_has_linux_capability(CAP_NET_RAW_BIT);
        let repair = cfg!(target_os = "linux") && process_has_linux_capability(CAP_NET_ADMIN_BIT);
        apply_test_capability_overrides(RawCapabilities {
            ipv4_raw_send: raw,
            ipv4_packet_capture: raw,
            tcp_repair_query: repair,
            ipv4_header_control: raw,
            ipv4_fragmentation: raw,
        })
    }

    fn get_tcp_state(
        &self,
        stream: &tokio::net::TcpStream,
        dst: SocketAddr,
    ) -> Option<TcpSeqState> {
        if env_override_bool("AEGIS_TEST_RAW_TCP_STATE") == Some(true) {
            return Some(TcpSeqState {
                snd_nxt: 1,
                rcv_nxt: 1,
                local_port: stream.local_addr().ok()?.port(),
                remote_port: dst.port(),
            });
        }
        #[cfg(target_os = "linux")]
        {
            get_tcp_seq_linux(stream, dst)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (stream, dst);
            None
        }
    }

    fn send_raw_ipv4(&self, packet: &[u8], dst: Ipv4Addr) -> io::Result<usize> {
        // Integration tests can force the capability matrix active on an
        // otherwise unprivileged runner. Pair that seam with an explicit
        // no-op send so a loopback e2e tests orchestration deterministically
        // instead of depending on CAP_NET_RAW or injecting decoys into its
        // own canonical TCP stream. Real wire acceptance never sets this.
        if env_override_bool("AEGIS_TEST_RAW_SEND_NOOP") == Some(true) {
            return Ok(packet.len());
        }
        linux_send_raw_ipv4_best_effort(packet, dst)
    }

    fn send_raw_ipv4_with_ttl(&self, packet: &[u8], dst: Ipv4Addr, ttl: u8) -> io::Result<usize> {
        if env_override_bool("AEGIS_TEST_RAW_SEND_NOOP") == Some(true) {
            return Ok(packet.len());
        }
        linux_send_raw_ipv4_with_ttl_best_effort(packet, dst, ttl)
    }
}

fn normalize_split(len: usize, requested: usize) -> Option<usize> {
    if len < 2 {
        return None;
    }
    Some(requested.min(len - 1).max(1))
}

fn build_first_payload_packet(
    engine: &(impl RawEngine + ?Sized),
    stream: &tokio::net::TcpStream,
    dst: SocketAddr,
    payload: &[u8],
    ipv4_header_shaping: Option<&WireIpv4HeaderShapingPreface>,
) -> io::Result<(TcpPacketContext, Vec<u8>)> {
    let ctx = tcp_packet_context(engine, stream, dst)?;
    let packet = build_payload_packet_from_ctx(ctx, ctx.seq, payload, ipv4_header_shaping)?;
    Ok((ctx, packet))
}

fn build_first_payload_packet_with_window(
    engine: &(impl RawEngine + ?Sized),
    stream: &tokio::net::TcpStream,
    dst: SocketAddr,
    payload: &[u8],
    window: u16,
    ipv4_header_shaping: Option<&WireIpv4HeaderShapingPreface>,
) -> io::Result<(TcpPacketContext, Vec<u8>)> {
    let mut ctx = tcp_packet_context(engine, stream, dst)?;
    ctx.window = window;
    let packet = build_payload_packet_from_ctx(ctx, ctx.seq, payload, ipv4_header_shaping)?;
    Ok((ctx, packet))
}

fn build_first_payload_packet_with_window_and_options(
    engine: &(impl RawEngine + ?Sized),
    stream: &tokio::net::TcpStream,
    dst: SocketAddr,
    payload: &[u8],
    window: u16,
    ipv4_header_shaping: Option<&WireIpv4HeaderShapingPreface>,
) -> io::Result<(TcpPacketContext, Vec<u8>)> {
    let mut ctx = tcp_packet_context(engine, stream, dst)?;
    ctx.window = window;
    let packet =
        build_payload_packet_from_ctx_with_options(ctx, ctx.seq, payload, ipv4_header_shaping)?;
    Ok((ctx, packet))
}

fn build_first_payload_packet_with_window_and_negotiated_options(
    engine: &(impl RawEngine + ?Sized),
    stream: &tokio::net::TcpStream,
    dst: SocketAddr,
    payload: &[u8],
    window: u16,
    ipv4_header_shaping: Option<&WireIpv4HeaderShapingPreface>,
    negotiated: &WireNegotiatedOptionsPreface,
) -> io::Result<(TcpPacketContext, Vec<u8>)> {
    let mut ctx = tcp_packet_context(engine, stream, dst)?;
    ctx.window = window;
    let packet = build_payload_packet_from_ctx_with_negotiated_options(
        ctx,
        ctx.seq,
        payload,
        ipv4_header_shaping,
        negotiated,
    )?;
    Ok((ctx, packet))
}

fn build_payload_packet_from_ctx(
    ctx: TcpPacketContext,
    seq: u32,
    payload: &[u8],
    ipv4_header_shaping: Option<&WireIpv4HeaderShapingPreface>,
) -> io::Result<Vec<u8>> {
    build_ipv4_tcp_packet_with_shaping(
        ctx.src_ip,
        ctx.dst_ip,
        ctx.sport,
        ctx.dport,
        seq,
        ctx.ack,
        TCP_FLAG_ACK | TCP_FLAG_PSH,
        ctx.window,
        64,
        ipv4_header_shaping.map(ipv4_header_shaping_from_preface),
        payload,
    )
}

fn build_payload_packet_from_ctx_with_options(
    ctx: TcpPacketContext,
    seq: u32,
    payload: &[u8],
    ipv4_header_shaping: Option<&WireIpv4HeaderShapingPreface>,
) -> io::Result<Vec<u8>> {
    build_ipv4_tcp_packet_with_options_and_shaping(
        ctx.src_ip,
        ctx.dst_ip,
        ctx.sport,
        ctx.dport,
        seq,
        ctx.ack,
        TCP_FLAG_ACK | TCP_FLAG_PSH,
        ctx.window,
        64,
        ipv4_header_shaping.map(ipv4_header_shaping_from_preface),
        &ack_timestamp_preface_options(ctx),
        payload,
    )
}

fn build_payload_packet_from_ctx_with_negotiated_options(
    ctx: TcpPacketContext,
    seq: u32,
    payload: &[u8],
    ipv4_header_shaping: Option<&WireIpv4HeaderShapingPreface>,
    negotiated: &WireNegotiatedOptionsPreface,
) -> io::Result<Vec<u8>> {
    let options = syn_negotiated_options_preface_options(ctx, negotiated);
    build_ipv4_tcp_packet_with_options_and_shaping(
        ctx.src_ip,
        ctx.dst_ip,
        ctx.sport,
        ctx.dport,
        seq,
        ctx.ack,
        TCP_FLAG_ACK | TCP_FLAG_PSH,
        ctx.window,
        64,
        ipv4_header_shaping.map(ipv4_header_shaping_from_preface),
        &options,
        payload,
    )
}

fn ipv4_header_shaping_from_preface(shaping: &WireIpv4HeaderShapingPreface) -> Ipv4HeaderShaping {
    Ipv4HeaderShaping {
        tos: shaping.tos,
        identification: shaping.identification,
        dont_fragment: shaping.dont_fragment,
    }
}

fn ack_timestamp_preface_options(ctx: TcpPacketContext) -> [u8; 12] {
    // Keep the first options slice narrow and deterministic: a padded ACK
    // timestamp block derived from live seq/ack context for middlebox-path
    // shaping, not a claim of full negotiated TCP option impersonation.
    let tsval = ctx.seq ^ u32::from(ctx.window);
    let tsecr = ctx.ack;
    let mut options = [0u8; 12];
    options[0] = 1;
    options[1] = 1;
    options[2] = 8;
    options[3] = 10;
    options[4..8].copy_from_slice(&tsval.to_be_bytes());
    options[8..12].copy_from_slice(&tsecr.to_be_bytes());
    options
}

fn syn_negotiated_options_preface_options(
    ctx: TcpPacketContext,
    negotiated: &WireNegotiatedOptionsPreface,
) -> Vec<u8> {
    let mut options = Vec::with_capacity(negotiated.size_bytes as usize);
    options.extend_from_slice(&[2, 4]);
    options.extend_from_slice(&negotiated.mss.to_be_bytes());
    if negotiated.sack_permitted {
        options.extend_from_slice(&[4, 2]);
    } else {
        options.extend_from_slice(&[1, 1]);
    }
    if negotiated.timestamp_mode == "syn_timestamp_offer_layout20" {
        options.extend_from_slice(&[8, 10]);
        let tsval = ctx.seq
            ^ ctx.ack
            ^ u32::from(ctx.window)
            ^ u32::from(negotiated.mss)
            ^ u32::from(negotiated.window_scale);
        let tsecr = ctx.ack
            ^ if negotiated.sack_permitted {
                0x5a5a_0001
            } else {
                0
            };
        options.extend_from_slice(&tsval.to_be_bytes());
        options.extend_from_slice(&tsecr.to_be_bytes());
        options.push(1);
    }
    options.extend_from_slice(&[3, 3, negotiated.window_scale]);
    while options.len() % 4 != 0 {
        options.push(1);
    }
    options
}

fn build_conflicting_overlap_payload(payload: &[u8], split: usize, overlap: usize) -> Vec<u8> {
    let start = split - overlap;
    let mut overlapped = payload[start..].to_vec();
    for byte in &mut overlapped[..overlap] {
        // Flip bits in the overlap prefix so the second segment conflicts with
        // the earlier bytes while keeping the suffix shape/length intact.
        *byte ^= 0x5a;
    }
    overlapped
}

fn tcp_packet_context(
    engine: &(impl RawEngine + ?Sized),
    stream: &tokio::net::TcpStream,
    dst: SocketAddr,
) -> io::Result<TcpPacketContext> {
    let caps = engine.capabilities();
    if !caps.ipv4_raw_send {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "raw IPv4 send unavailable (need Linux + raw-socket feature)",
        ));
    }
    let SocketAddr::V4(dst_v4) = dst else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "packet-level raw strategies currently support only IPv4",
        ));
    };
    let Some(tcp) = engine.get_tcp_state(stream, dst) else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "exact TCP seq/ack unavailable (need Linux TCP_REPAIR + CAP_NET_ADMIN)",
        ));
    };
    let SocketAddr::V4(src_v4) = stream
        .local_addr()
        .map_err(|e| io::Error::new(e.kind(), "failed to read local_addr"))?
    else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "packet-level raw strategies currently support only IPv4 local socket",
        ));
    };
    Ok(TcpPacketContext {
        src_ip: *src_v4.ip(),
        dst_ip: *dst_v4.ip(),
        seq: tcp.snd_nxt,
        ack: tcp.rcv_nxt,
        sport: tcp.local_port,
        dport: tcp.remote_port,
        window: tcp_window_hint(stream),
    })
}

#[cfg(target_os = "linux")]
fn tcp_window_hint(stream: &tokio::net::TcpStream) -> u16 {
    use std::os::unix::io::AsRawFd;

    let fd = stream.as_raw_fd();
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
        return 4096;
    }
    value.clamp(1024, u16::MAX as libc::c_int) as u16
}

#[cfg(not(target_os = "linux"))]
fn tcp_window_hint(_stream: &tokio::net::TcpStream) -> u16 {
    4096
}

#[cfg(target_os = "linux")]
const CAP_NET_ADMIN_BIT: u32 = 12;
#[cfg(target_os = "linux")]
const CAP_NET_RAW_BIT: u32 = 13;
#[cfg(not(target_os = "linux"))]
const CAP_NET_ADMIN_BIT: u32 = 12;
#[cfg(not(target_os = "linux"))]
const CAP_NET_RAW_BIT: u32 = 13;

#[cfg(target_os = "linux")]
fn process_has_linux_capability(bit: u32) -> bool {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    parse_cap_eff(&status)
        .map(|caps| (caps & (1u64 << bit)) != 0)
        .unwrap_or(false)
}

#[cfg(not(target_os = "linux"))]
fn process_has_linux_capability(_bit: u32) -> bool {
    false
}

#[cfg(target_os = "linux")]
fn parse_cap_eff(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:\t"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
}

#[cfg(target_os = "linux")]
const TCP_REPAIR: libc::c_int = 19;
#[cfg(target_os = "linux")]
const TCP_REPAIR_QUEUE: libc::c_int = 20;
#[cfg(target_os = "linux")]
const TCP_QUEUE_SEQ: libc::c_int = 21;
#[cfg(target_os = "linux")]
const TCP_REPAIR_ON: libc::c_int = 1;
#[cfg(target_os = "linux")]
const TCP_REPAIR_OFF_NO_WP: libc::c_int = -1;
#[cfg(target_os = "linux")]
const TCP_RECV_QUEUE: libc::c_int = 1;
#[cfg(target_os = "linux")]
const TCP_SEND_QUEUE: libc::c_int = 2;

/// Linux: exact TCP seq/ack through repair mode.
#[cfg(target_os = "linux")]
fn get_tcp_seq_linux(stream: &tokio::net::TcpStream, dst: SocketAddr) -> Option<TcpSeqState> {
    use std::os::unix::io::AsRawFd;

    let fd = stream.as_raw_fd();
    let guard = TcpRepairGuard::enable(fd).ok()?;
    let snd_nxt = guard.read_queue_seq(TCP_SEND_QUEUE).ok()?;
    let rcv_nxt = guard.read_queue_seq(TCP_RECV_QUEUE).ok()?;

    let local_port = stream.local_addr().ok()?.port();
    let remote_port = dst.port();

    Some(TcpSeqState {
        snd_nxt,
        rcv_nxt,
        local_port,
        remote_port,
    })
}

#[cfg(target_os = "linux")]
struct TcpRepairGuard {
    fd: std::os::unix::io::RawFd,
}

#[cfg(target_os = "linux")]
impl TcpRepairGuard {
    fn enable(fd: std::os::unix::io::RawFd) -> io::Result<Self> {
        set_tcp_sockopt_int(fd, TCP_REPAIR, TCP_REPAIR_ON)?;
        Ok(Self { fd })
    }

    fn read_queue_seq(&self, queue: libc::c_int) -> io::Result<u32> {
        set_tcp_sockopt_int(self.fd, TCP_REPAIR_QUEUE, queue)?;
        get_tcp_sockopt_u32(self.fd, TCP_QUEUE_SEQ)
    }
}

#[cfg(target_os = "linux")]
impl Drop for TcpRepairGuard {
    fn drop(&mut self) {
        let _ = set_tcp_sockopt_int(self.fd, TCP_REPAIR, TCP_REPAIR_OFF_NO_WP);
    }
}

#[cfg(target_os = "linux")]
fn set_tcp_sockopt_int(
    fd: std::os::unix::io::RawFd,
    opt: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            opt,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn get_tcp_sockopt_u32(fd: std::os::unix::io::RawFd, opt: libc::c_int) -> io::Result<u32> {
    let mut value: u32 = 0;
    let mut len = std::mem::size_of_val(&value) as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            opt,
            &mut value as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MockRawEngine {
        calls: AtomicUsize,
        max_packet_len: AtomicUsize,
        fail_on_call: Option<usize>,
        mtu: usize,
    }

    impl MockRawEngine {
        fn new(fail_on_call: Option<usize>) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                max_packet_len: AtomicUsize::new(0),
                fail_on_call,
                mtu: 1500,
            }
        }

        fn with_mtu(mut self, mtu: usize) -> Self {
            self.mtu = mtu;
            self
        }

        fn record_send(&self, packet: &[u8]) -> io::Result<usize> {
            self.max_packet_len
                .fetch_max(packet.len(), Ordering::SeqCst);
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if self.fail_on_call == Some(call) {
                return Err(io::Error::other(format!(
                    "mock raw send failure on call {call}"
                )));
            }
            Ok(packet.len())
        }
    }

    impl RawEngine for MockRawEngine {
        fn capabilities(&self) -> RawCapabilities {
            RawCapabilities {
                ipv4_raw_send: true,
                ipv4_packet_capture: true,
                tcp_repair_query: true,
                ipv4_header_control: true,
                ipv4_fragmentation: true,
            }
        }

        fn get_tcp_state(
            &self,
            stream: &tokio::net::TcpStream,
            dst: SocketAddr,
        ) -> Option<TcpSeqState> {
            Some(TcpSeqState {
                snd_nxt: 100,
                rcv_nxt: 200,
                local_port: stream.local_addr().ok()?.port(),
                remote_port: dst.port(),
            })
        }

        fn send_raw_ipv4(&self, packet: &[u8], _dst: Ipv4Addr) -> io::Result<usize> {
            self.record_send(packet)
        }

        fn send_raw_ipv4_with_ttl(
            &self,
            packet: &[u8],
            _dst: Ipv4Addr,
            _ttl: u8,
        ) -> io::Result<usize> {
            self.record_send(packet)
        }

        fn ipv4_path_mtu(&self, _stream: &tokio::net::TcpStream) -> io::Result<usize> {
            Ok(self.mtu)
        }
    }

    async fn connected_ipv4_stream() -> (tokio::net::TcpStream, SocketAddr) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let dst = listener.local_addr().expect("listener address");
        let accept = tokio::spawn(async move { listener.accept().await.expect("accept").0 });
        let client = tokio::net::TcpStream::connect(dst)
            .await
            .expect("connect test stream");
        let _server = accept.await.expect("join accept");
        (client, dst)
    }

    #[test]
    fn capabilities_match_cfg() {
        let e = PlatformRawEngine;
        let c = e.capabilities();
        #[cfg(all(target_os = "linux", feature = "raw-socket"))]
        {
            assert_eq!(
                c.ipv4_raw_send,
                process_has_linux_capability(CAP_NET_RAW_BIT)
            );
            assert_eq!(c.ipv4_packet_capture, c.ipv4_raw_send);
            assert_eq!(c.ipv4_header_control, c.ipv4_raw_send);
            assert_eq!(c.ipv4_fragmentation, c.ipv4_raw_send);
        }
        #[cfg(not(all(target_os = "linux", feature = "raw-socket")))]
        {
            assert!(!c.ipv4_raw_send);
            assert!(!c.ipv4_packet_capture);
            assert!(!c.ipv4_header_control);
            assert!(!c.ipv4_fragmentation);
        }

        #[cfg(target_os = "linux")]
        assert_eq!(
            c.tcp_repair_query,
            process_has_linux_capability(CAP_NET_ADMIN_BIT)
        );
        #[cfg(not(target_os = "linux"))]
        assert!(!c.tcp_repair_query);
    }

    #[test]
    fn default_engine_is_send_sync() {
        let e = default_raw_engine();
        fn assert_send_sync<T: Send + Sync>(_: &T) {}
        assert_send_sync(&e);
    }

    #[test]
    fn normalize_split_requires_two_parts() {
        assert_eq!(normalize_split(0, 10), None);
        assert_eq!(normalize_split(1, 10), None);
        assert_eq!(normalize_split(2, 10), Some(1));
        assert_eq!(normalize_split(32, 7), Some(7));
    }

    #[test]
    fn conflicting_overlap_payload_mutates_only_overlap_prefix() {
        let payload = b"abcdefghijklmnop";
        let overlapped = build_conflicting_overlap_payload(payload, 8, 4);
        assert_eq!(overlapped.len(), payload.len() - 4);
        assert_ne!(&overlapped[..4], &payload[4..8]);
        assert_eq!(&overlapped[4..], &payload[8..]);
    }

    #[tokio::test]
    async fn ttl_decoy_propagates_raw_send_failure() {
        let (stream, dst) = connected_ipv4_stream().await;
        let engine = MockRawEngine::new(Some(1));
        let error = engine
            .try_send_ttl_desync_first_packet(&stream, dst, &[0x16; 128], 4, None, "contract")
            .expect_err("raw send failure must not become strategy success");
        assert!(error.to_string().contains("ttl_desync_send"));
        assert_eq!(engine.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn ttl_decoy_is_fragmented_to_path_mtu_before_raw_send() {
        let (stream, dst) = connected_ipv4_stream().await;
        let engine = MockRawEngine::new(None).with_mtu(576);
        let effect = engine
            .try_send_ttl_desync_first_packet(&stream, dst, &[0x16; 2000], 4, None, "contract")
            .expect("MTU-safe raw fragment plan");
        assert!(effect.packets >= 4);
        assert_eq!(effect.packets, engine.calls.load(Ordering::SeqCst));
        assert!(engine.max_packet_len.load(Ordering::SeqCst) <= 576);
    }

    #[tokio::test]
    async fn fragment_effect_is_complete_or_error() {
        let (stream, dst) = connected_ipv4_stream().await;
        let failing = MockRawEngine::new(Some(2));
        let error = failing
            .try_send_fragmented_first_packet(
                &stream,
                &[0x16; 128],
                None,
                FragmentDecoyPlan {
                    dst,
                    ttl: 4,
                    first_payload_len: 28,
                    overlap: 8,
                    strategy_id: "contract",
                },
            )
            .expect_err("partial fragment set must fail");
        assert!(error.to_string().contains("ip_frag_send"));
        assert_eq!(failing.calls.load(Ordering::SeqCst), 2);

        let successful = MockRawEngine::new(None);
        let effect = successful
            .try_send_fragmented_first_packet(
                &stream,
                &[0x16; 128],
                None,
                FragmentDecoyPlan {
                    dst,
                    ttl: 4,
                    first_payload_len: 28,
                    overlap: 8,
                    strategy_id: "contract",
                },
            )
            .expect("complete fragment set");
        assert_eq!(effect.packets, 2);
        assert_eq!(successful.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn syn_negotiated_options_follow_syn_style_layout() {
        let options = syn_negotiated_options_preface_options(
            TcpPacketContext {
                src_ip: Ipv4Addr::new(10, 0, 0, 1),
                dst_ip: Ipv4Addr::new(10, 0, 0, 2),
                seq: 11,
                ack: 22,
                sport: 1000,
                dport: 443,
                window: 4096,
            },
            &WireNegotiatedOptionsPreface {
                profile: "linux_negotiated_options_v1",
                source: "heuristic_profile_derived",
                mss: 1460,
                window_scale: 7,
                sack_permitted: true,
                timestamp_mode: "syn_timestamp_offer_layout20",
                size_bytes: 20,
            },
        );
        assert_eq!(options.len(), 20);
        assert_eq!(&options[..4], &[2, 4, 0x05, 0xb4]);
        assert_eq!(&options[4..6], &[4, 2]);
        assert_eq!(&options[6..8], &[8, 10]);
        assert_eq!(options[16], 1);
        assert_eq!(&options[17..20], &[3, 3, 7]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_cap_eff_from_status_text() {
        let status = "Name:\ttest\nCapEff:\t0000000000003000\n";
        let caps = parse_cap_eff(status).unwrap();
        assert_ne!(caps & (1u64 << CAP_NET_ADMIN_BIT), 0);
        assert_ne!(caps & (1u64 << CAP_NET_RAW_BIT), 0);
    }
}
