//! AEGIS-Client: SOCKS5, режимы Direct и Relay.

pub(crate) use aegis_client::brain_state;
mod carrier;
mod config;
mod device_bundle;
mod device_enrollment;
mod device_identity;
mod device_renewal;
mod direct;
#[cfg(test)]
mod fixture_ports;
mod ingress;
#[cfg(test)]
mod ingress_accept_tests;
#[cfg(target_os = "macos")]
mod macos_tunnel;
mod operator;
mod profile;
mod profile_auto;
#[cfg(target_os = "linux")]
mod profile_auto_capture;
#[cfg(target_os = "linux")]
mod profile_auto_guardian;
#[cfg(target_os = "linux")]
mod profile_auto_install_receipt;
#[cfg(target_os = "linux")]
mod profile_auto_launch_service;
#[cfg(target_os = "linux")]
mod profile_auto_prepare;
#[cfg(target_os = "linux")]
mod profile_auto_publication;
#[cfg(target_os = "linux")]
mod profile_auto_render;
#[cfg(target_os = "linux")]
mod profile_auto_runtime_identity;
#[cfg(target_os = "linux")]
mod profile_auto_runtime_publication;
#[cfg(target_os = "linux")]
mod profile_auto_runtime_state;
#[cfg(all(target_os = "linux", test))]
mod profile_auto_state_publication;
#[cfg(all(test, unix))]
mod profile_auto_stderr_drain;
#[cfg(target_os = "linux")]
mod profile_auto_stop_service;
#[cfg(target_os = "linux")]
mod profile_auto_stopped_service;
#[cfg(target_os = "linux")]
mod profile_auto_transaction;
#[cfg(target_os = "linux")]
mod profile_auto_transaction_cli;
#[cfg(target_os = "linux")]
mod profile_auto_unit_namespace;
#[cfg(target_os = "linux")]
mod profile_auto_unit_policy;
// Local CDN-like gRPC edge shared by fronted-carrier tests (one instance).
#[cfg(test)]
#[path = "../../tests/support/cdn_grpc_proxy.rs"]
mod test_cdn_edge;
#[cfg(not(target_os = "linux"))]
mod profile_auto_transaction_cli {
    #[derive(clap::Args, Clone, Debug)]
    pub(crate) struct Args {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        pub(crate) words: Vec<String>,
    }
    pub(crate) fn run(_: &[String]) -> Result<(), String> {
        Err("Administrative AUTO transaction requires Linux root authority".into())
    }
}
mod profile_relay_geneva;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod profile_relay_geneva_manager;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod profile_relay_geneva_role;
mod relay;
#[cfg(test)]
mod relay_ipv6_excludes_tests;
#[cfg(test)]
mod relay_learning_latency_tests;
#[cfg(test)]
mod relay_learning_tests;
mod runtime_calibration;
pub(crate) use aegis_client::runtime_event_stream;
pub(crate) use aegis_client::runtime_events;
mod service_ready;
mod socks5;
use aegis_client::runtime_errors::{
    anyhow_error_chain_messages, anyhow_error_kind_code, io_error_kind_code, ProfileCommandFailure,
};
mod state_key;
mod tls_probe;
#[cfg(feature = "webrtc-carrier")]
mod webrtc;
#[cfg(any(target_os = "linux", test))]
mod wide_workers;
#[cfg(windows)]
mod windows_service;
#[cfg(windows)]
mod windows_tunnel;
#[cfg(windows)]
mod windows_wide;

use crate::ingress::broker::{BrokeredSession, DefaultSessionBroker, SessionBroker};
use crate::ingress::{
    preflight::{FallbackReasonCode, IngressStartupReport, PreflightSeverity, RuntimeProbeCode},
    ActiveIngressBackend, IngressBackend, IngressTransport, Socks5FallbackBackend,
};
use crate::runtime_event_stream as runtime_jsonl;
use crate::runtime_events::RuntimeEventCode;
use aegis_core::ghost_lurk::GhostLurk;
use aegis_core::mimicry::StackProfileId;
use aegis_core::shield::{init_sentinel, SentinelConfig};
use aegis_core::{
    AsyncStateStore, Brain, ExternalCalibrationSnapshot, IngressPrimary, Mode, Settings,
    StrategyKey, TunnelTransportFamily, WidePlatformBackend, WideRolloutProfile,
    WideUdpCaptureContract,
};
use anyhow::Context;
use clap::Parser;
use serde_json::json;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::watch;
use tracing::{error, info, warn};

const BUILD_GIT_SHA: &str = env!("AEGIS_BUILD_GIT_SHA");
const BUILD_TIMESTAMP: &str = env!("AEGIS_BUILD_TIMESTAMP");
const BUILD_TARGET: &str = env!("AEGIS_BUILD_TARGET");
const BUILD_FEATURES: &str = env!("AEGIS_BUILD_FEATURES");
const CARGO_LOCK_SHA256: &str = env!("AEGIS_CARGO_LOCK_SHA256");

fn mode_code(mode: &Mode) -> &'static str {
    match mode {
        Mode::Direct => "direct",
        Mode::Relay => "relay",
        Mode::Auto => "auto",
    }
}

fn ingress_primary_code(primary: IngressPrimary) -> &'static str {
    match primary {
        IngressPrimary::Wide => "wide",
        IngressPrimary::Socks5 => "socks5",
    }
}

fn wide_platform_code(platform: WidePlatformBackend) -> &'static str {
    match platform {
        WidePlatformBackend::Auto => "auto",
        WidePlatformBackend::LinuxRedirect => "linux_redirect",
        WidePlatformBackend::LinuxTproxy => "linux_tproxy",
        WidePlatformBackend::LinuxNfqueueObserver => "linux_nfqueue_observer",
        WidePlatformBackend::Windivert => "windivert",
        WidePlatformBackend::WindowsWfpAle => "windows_wfp_ale",
        WidePlatformBackend::MacosPf => "macos_pf",
    }
}

fn wide_rollout_profile_code(profile: WideRolloutProfile) -> &'static str {
    match profile {
        WideRolloutProfile::OutputOnlySafe => "output_only_safe",
        WideRolloutProfile::PreroutingScoped => "prerouting_scoped",
        WideRolloutProfile::TransparentPrivileged => "transparent_privileged",
    }
}

fn wide_rollout_startup_context_requested(cfg: &Settings) -> bool {
    cfg.ingress.primary == IngressPrimary::Wide
}

fn configured_udp_preview_policy(cfg: &Settings) -> Option<&'static str> {
    match cfg.ingress.wide.udp_capture_contract {
        WideUdpCaptureContract::PreviewAllowlistOnly
            if cfg.ingress.wide.enabled && cfg.ingress.wide.capture_dns =>
        {
            Some("allowlist_ports")
        }
        _ => None,
    }
}

fn configured_udp_capture_policy(cfg: &Settings) -> Option<&'static str> {
    if !(cfg.ingress.wide.enabled && cfg.ingress.wide.capture_dns) {
        return None;
    }
    match cfg.ingress.wide.udp_capture_contract {
        WideUdpCaptureContract::PreviewAllowlistOnly => Some("allowlist_ports"),
        WideUdpCaptureContract::GenericCaptureUnstable => match cfg.ingress.wide.listen {
            SocketAddr::V4(_) => Some("any_target_port_linux_ipv4_unstable"),
            SocketAddr::V6(_) => Some("any_target_port_linux_ipv6_unstable"),
        },
    }
}

fn configured_udp_capture_runtime_scope(cfg: &Settings) -> Option<&'static str> {
    if !(cfg.ingress.wide.enabled && cfg.ingress.wide.capture_dns) {
        return None;
    }
    if cfg!(target_os = "macos")
        && cfg.ingress.wide.platform_backend == WidePlatformBackend::MacosPf
    {
        return match cfg.ingress.wide.listen {
            SocketAddr::V4(_) => Some("macos_ipv4_loopback_preview"),
            SocketAddr::V6(_) => Some("macos_ipv6_loopback_preview"),
        };
    }
    match cfg.ingress.wide.listen {
        SocketAddr::V4(_) => Some("linux_ipv4_only"),
        SocketAddr::V6(_) => Some("linux_ipv6_only"),
    }
}

fn configured_udp_capture_contract(cfg: &Settings) -> Option<&'static str> {
    if !(cfg.ingress.wide.enabled && cfg.ingress.wide.capture_dns) {
        return None;
    }
    match cfg.ingress.wide.udp_capture_contract {
        WideUdpCaptureContract::PreviewAllowlistOnly => Some("preview_allowlist_only"),
        // Linux-only broader UDP receive path exists now, but it is still intentionally unstable.
        WideUdpCaptureContract::GenericCaptureUnstable => Some("generic_capture_unstable"),
    }
}

fn configured_udp_capture_support_tier(cfg: &Settings) -> Option<&'static str> {
    if !(cfg.ingress.wide.enabled && cfg.ingress.wide.capture_dns) {
        return None;
    }
    match cfg.ingress.wide.udp_capture_contract {
        WideUdpCaptureContract::PreviewAllowlistOnly => Some("supported_preview"),
        WideUdpCaptureContract::GenericCaptureUnstable => Some("guarded_unstable"),
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ActiveWideUdpEventSurface {
    capture_contract: Option<&'static str>,
    capture_support_tier: Option<&'static str>,
    capture_policy: Option<&'static str>,
    capture_runtime_scope: Option<&'static str>,
    capture_match_kind: Option<&'static str>,
    capture_accept_reason_code: Option<&'static str>,
    preview_policy: Option<&'static str>,
    preview_match_kind: Option<&'static str>,
    preview_accept_reason_code: Option<&'static str>,
    preview_ports: Vec<u16>,
}

fn active_wide_udp_event_surface(
    cfg: &Settings,
    backend_kind_code: &str,
    target_port: u16,
) -> ActiveWideUdpEventSurface {
    if backend_kind_code != ActiveIngressBackend::WidePrimary.as_code() {
        return ActiveWideUdpEventSurface {
            capture_contract: None,
            capture_support_tier: None,
            capture_policy: None,
            capture_runtime_scope: None,
            capture_match_kind: None,
            capture_accept_reason_code: None,
            preview_policy: None,
            preview_match_kind: None,
            preview_accept_reason_code: None,
            preview_ports: Vec::new(),
        };
    }

    ActiveWideUdpEventSurface {
        capture_contract: configured_udp_capture_contract(cfg),
        capture_support_tier: configured_udp_capture_support_tier(cfg),
        capture_policy: configured_udp_capture_policy(cfg),
        capture_runtime_scope: configured_udp_capture_runtime_scope(cfg),
        capture_match_kind: configured_udp_capture_match_kind(cfg, target_port),
        capture_accept_reason_code: configured_udp_capture_accept_reason_code(cfg, target_port),
        preview_policy: configured_udp_preview_policy(cfg),
        preview_match_kind: configured_udp_preview_match_kind(cfg, target_port),
        preview_accept_reason_code: configured_udp_preview_accept_reason_code(cfg, target_port),
        preview_ports: configured_udp_preview_ports(cfg),
    }
}

fn configured_udp_preview_ports(cfg: &Settings) -> Vec<u16> {
    if configured_udp_preview_policy(cfg).is_none() {
        return Vec::new();
    }
    let mut ports = vec![cfg.ingress.wide.dns_port];
    for port in &cfg.ingress.wide.udp_preview_ports {
        if *port != cfg.ingress.wide.dns_port && !ports.contains(port) {
            ports.push(*port);
        }
    }
    ports
}

fn configured_udp_preview_match_kind(cfg: &Settings, target_port: u16) -> Option<&'static str> {
    let _policy = configured_udp_preview_policy(cfg)?;
    if target_port == cfg.ingress.wide.dns_port {
        Some("dns_port")
    } else if cfg.ingress.wide.udp_preview_ports.contains(&target_port) {
        Some("extra_udp_preview_port")
    } else {
        None
    }
}

fn configured_udp_preview_accept_reason_code(
    cfg: &Settings,
    target_port: u16,
) -> Option<&'static str> {
    match configured_udp_preview_match_kind(cfg, target_port)? {
        "dns_port" => Some("matched_dns_port_allowlist"),
        "extra_udp_preview_port" => Some("matched_extra_udp_preview_port_allowlist"),
        _ => None,
    }
}

fn configured_udp_capture_match_kind(cfg: &Settings, target_port: u16) -> Option<&'static str> {
    let _contract = configured_udp_capture_contract(cfg)?;
    match cfg.ingress.wide.udp_capture_contract {
        WideUdpCaptureContract::PreviewAllowlistOnly => {
            configured_udp_preview_match_kind(cfg, target_port)
        }
        // Generic mode currently means the Linux/IPv4 path accepted the
        // datagram via the broader contract rather than an explicit allowlist hit.
        WideUdpCaptureContract::GenericCaptureUnstable => Some("generic_capture_contract"),
    }
}

fn configured_udp_capture_accept_reason_code(
    cfg: &Settings,
    target_port: u16,
) -> Option<&'static str> {
    match cfg.ingress.wide.udp_capture_contract {
        WideUdpCaptureContract::PreviewAllowlistOnly => {
            configured_udp_preview_accept_reason_code(cfg, target_port)
        }
        WideUdpCaptureContract::GenericCaptureUnstable => {
            let _match_kind = configured_udp_capture_match_kind(cfg, target_port)?;
            Some("matched_generic_udp_capture_contract")
        }
    }
}

#[derive(clap::Subcommand, Clone, Debug)]
enum TopCommand {
    /// Run an explicitly configured owned HTTPS request/reply carrier.
    Carrier(crate::carrier::CarrierArgs),
    /// Run an owned WebRTC carrier through explicitly trusted TLS signaling.
    #[cfg(feature = "webrtc-carrier")]
    Webrtc(crate::webrtc::Args),
    /// Prepare or complete device-local certificate enrollment.
    Device(crate::device_identity::DeviceArgs),
    /// Generate a device key locally and a CSR for offline operator enrollment.
    DeviceCsr(crate::device_identity::DeviceCsrArgs),
    /// Inspect or migrate the key protecting local persisted state.
    StateKey(crate::state_key::StateKeyArgs),
    /// Linux operator mode selector: plan/apply/status/rollback a runtime mode.
    Operator(crate::operator::OperatorArgs),
    /// Show / list / resolve / switch the user-facing wide product profile.
    Profile(crate::profile::ProfileArgs),
    /// Wide capture runtime status (read-only).
    Wide(crate::profile::WideArgs),
    /// Environment diagnostics for wide modes (read-only).
    Doctor(crate::profile::DoctorArgs),
    /// Hidden diagnostic: open one TLS connection with a selected relay TLS backend.
    #[command(hide = true)]
    TlsProbe(crate::tls_probe::TlsProbeArgs),
}

#[derive(Parser, Clone, Debug)]
#[command(
    name = "aegis-client",
    about = "AEGIS local SOCKS5 node",
    disable_version_flag = true
)]
struct Args {
    /// Optional subcommand (e.g. `operator plan --mode wide-tproxy`). When
    /// absent, the binary runs as the normal client per the flags below.
    #[command(subcommand)]
    command: Option<TopCommand>,

    /// Experimental full packet capture on an isolated macOS VM (root).
    #[cfg(target_os = "macos")]
    #[arg(long, conflicts_with = "macos_utun_disconnect")]
    macos_utun: bool,
    #[cfg(target_os = "macos")]
    #[arg(
        long,
        requires = "macos_utun",
        conflicts_with = "macos_utun_disconnect"
    )]
    macos_utun_supervise: bool,
    /// Explicitly restore the prior DNS/PF policy after stopping the VM worker.
    #[cfg(target_os = "macos")]
    #[arg(long)]
    macos_utun_disconnect: bool,
    /// Restrict automated disconnect to this exact supervisor receipt owner.
    #[cfg(target_os = "macos")]
    #[arg(long, requires = "macos_utun_disconnect", value_name = "OWNER")]
    macos_utun_disconnect_owner: Option<macos_tunnel::ReceiptOwner>,
    #[cfg(target_os = "macos")]
    #[arg(long, default_value_t = 60)]
    macos_utun_seconds: u64,
    #[cfg(target_os = "macos")]
    #[arg(long)]
    macos_utun_service: Option<String>,

    /// Reviewed immutable public intent for the dedicated network worker.
    #[cfg(target_os = "macos")]
    #[arg(long, requires = "macos_utun")]
    macos_utun_worker_profile: Option<PathBuf>,
    #[cfg(target_os = "macos")]
    #[arg(long, requires = "macos_utun", value_parser = macos_tunnel::parent_runtime::parse_digest)]
    macos_utun_worker_profile_sha256: Option<[u8; 32]>,
    #[cfg(target_os = "macos")]
    #[arg(long, requires = "macos_utun", value_parser = macos_tunnel::parent_runtime::parse_digest)]
    macos_utun_worker_executable_sha256: Option<[u8; 32]>,
    #[cfg(target_os = "macos")]
    #[arg(long, requires = "macos_utun")]
    macos_utun_worker_account: Option<String>,

    /// Print version and build metadata.
    #[arg(long = "version", action = clap::ArgAction::SetTrue)]
    version: bool,

    #[arg(short, long, default_value = "aegis.toml")]
    config: PathBuf,
    /// Enable installed same-key renewal with an explicitly pinned public v3 bundle.
    #[arg(long)]
    device_online_bundle: Option<PathBuf>,
    /// Validate configuration and local identity files without starting the client.
    #[arg(long, conflicts_with_all = ["version", "ingress_preflight", "ingress_startup_probe", "apply_external_calibration_summary", "direct_active_probe_evidence"])]
    validate_config: bool,
    #[arg(long)]
    ingress_preflight: bool,
    #[arg(long, conflicts_with = "ingress_preflight")]
    ingress_startup_probe: bool,
    #[arg(long)]
    verbose: bool,
    #[arg(long)]
    json: bool,
    #[arg(long)]
    runtime_events_jsonl: Option<PathBuf>,
    /// Disable the on-disk runtime-events JSONL (other logs/state are separate).
    /// Overrides --runtime-events-jsonl. Useful on hostile/seizable hosts.
    #[arg(long)]
    no_runtime_events: bool,
    /// Forensic-safe mode for hostile/seizable hosts (also via AEGIS_FORENSIC_SAFE=1):
    /// disables runtime-events JSONL, keeps Brain state in RAM, and replaces
    /// arbitrary diagnostic text with a closed set of event/error codes.
    /// Does not erase existing logs.
    #[arg(long)]
    forensic_safe: bool,
    /// Include detailed logs, destinations and error chains for an explicit
    /// diagnostic session. Default logs contain only event/error codes.
    #[arg(long, conflicts_with = "forensic_safe")]
    diagnostic_logs: bool,
    #[arg(long, conflicts_with_all = ["ingress_preflight", "ingress_startup_probe"])]
    apply_external_calibration_summary: Option<PathBuf>,
    /// Load a public calibration summary/snapshot into Brain RAM for this run.
    #[arg(long, conflicts_with_all = ["version", "validate_config", "ingress_preflight", "ingress_startup_probe", "apply_external_calibration_summary", "direct_active_probe_evidence"])]
    runtime_external_calibration_summary: Option<PathBuf>,
    #[arg(long, conflicts_with_all = ["ingress_preflight", "ingress_startup_probe", "apply_external_calibration_summary"])]
    direct_active_probe_evidence: Option<SocketAddr>,
    #[arg(long)]
    exit_on_stdin_eof: bool,
    /// Linux NFQUEUE observer validation entrypoint: bind the given queue
    /// number, witness diverted TCP flows (IPv4/IPv6) as
    /// `wide_nfqueue_flow_observed` events, ACCEPT every packet, and run until
    /// interrupted. Requires root + divert rules feeding the queue. Hidden:
    /// used by the wide NFQUEUE backend validation, not a user-facing mode.
    #[cfg(target_os = "linux")]
    #[arg(long, hide = true)]
    nfqueue_observe: Option<u16>,
    /// Bidirectional generic-UDP redirect proxy entrypoint: bind the given local
    /// port, recover the original destination of REDIRECT-diverted UDP via
    /// IP_RECVORIGDSTADDR, carry the datagram over MASQUE direct CONNECT-UDP, and
    /// deliver the relay response back to the app from the original destination
    /// tuple (IP_TRANSPARENT reply). Bidirectional (not send-only). Fail-closed
    /// on any error — never a native UDP fallback. Requires root + a REDIRECT
    /// rule feeding this port and a reachable MASQUE endpoint in the relay
    /// config. Hidden: wired by the full-wide installer, not a user-facing mode.
    #[cfg(target_os = "linux")]
    #[arg(long, hide = true)]
    udp_redirect_proxy: Option<u16>,
    /// Opt-in: have the NFQUEUE lifecycle install scoped divert rules (IPv4
    /// and/or IPv6, queue-bypass, SSH excluded) before observing and remove
    /// them on exit via the watchdog. Without this, rules must be installed
    /// out-of-band.
    #[cfg(target_os = "linux")]
    #[arg(long, hide = true)]
    nfqueue_setup_rules: bool,
    /// Restrict the NFQUEUE lifecycle to IPv4 only (default: both families).
    #[cfg(target_os = "linux")]
    #[arg(long, hide = true)]
    nfqueue_ipv4_only: bool,
    /// Restrict the NFQUEUE lifecycle to IPv6 only (default: both families).
    #[cfg(target_os = "linux")]
    #[arg(long, hide = true)]
    nfqueue_ipv6_only: bool,
    /// Destination ports the NFQUEUE lifecycle diverts (never SSH/:22).
    #[cfg(target_os = "linux")]
    #[arg(long, hide = true, default_value = "80,443")]
    nfqueue_dports: String,
    /// full-wide-nfqueue: run the NFQUEUE backend in fail-closed ENFORCE mode
    /// (DROP blocked classes + any undecodable packet) instead of witness-only
    /// ACCEPT. The per-class blocks below select which classes are dropped.
    #[cfg(target_os = "linux")]
    #[arg(long, hide = true)]
    nfqueue_enforce: bool,
    /// Enforce: DROP generic (non-DNS) UDP (udp_policy = block/masque_direct/preview).
    #[cfg(target_os = "linux")]
    #[arg(long, hide = true)]
    nfqueue_udp_block: bool,
    /// Enforce + udp_policy=masque_direct: in addition to DROPping generic UDP
    /// (fail-closed; implies --nfqueue-udp-block), carry the send leg over
    /// MASQUE direct CONNECT-UDP. Requires a reachable MASQUE endpoint in the
    /// relay config. Send-only by design (NFQUEUE is verdict-only); never a
    /// native UDP fallback.
    #[cfg(target_os = "linux")]
    #[arg(long, hide = true)]
    nfqueue_udp_masque_direct: bool,
    /// Enforce: DROP DNS UDP/53 (dns_policy = block).
    #[cfg(target_os = "linux")]
    #[arg(long, hide = true)]
    nfqueue_dns_block: bool,
    /// Enforce: DROP every IPv6 packet (ipv6_policy = block or capture-fail-closed).
    #[cfg(target_os = "linux")]
    #[arg(long, hide = true)]
    nfqueue_ipv6_block: bool,
    /// wide-udp-direct: health-check the MASQUE direct CONNECT-UDP path against
    /// the given controlled UDP echo target (host:port). Connects, sends a nonce
    /// datagram, verifies the echo, emits masque_udp_health_succeeded/failed, and
    /// exits 0 (healthy) or non-zero (blocked — never a native UDP fallback).
    #[arg(long, hide = true)]
    masque_udp_health: Option<String>,
    /// Controlled IPv6 TUN route lab: create an AEGIS-owned TUN, install ONE
    /// controlled /128 route to the given IPv6 dst (never a default route),
    /// observe one IPv6 packet, then clean up. Lab only; not a production
    /// backend.
    #[cfg(target_os = "linux")]
    #[arg(long, hide = true)]
    tun_ipv6_route_lab: Option<std::net::Ipv6Addr>,
    /// Controlled IPv6 smoltcp TCP adapter lab: smoltcp owns the given /128 +
    /// listens; a real TCP handshake on a controlled flow establishes a
    /// userspace connection (echo). Lab only; not a production backend, no
    /// relay bridge. Use --tun-adapter-port.
    #[cfg(target_os = "linux")]
    #[arg(long, hide = true)]
    tun_ipv6_tcp_adapter_lab: Option<std::net::Ipv6Addr>,
    /// Listen port for the smoltcp TCP adapter lab.
    #[cfg(target_os = "linux")]
    #[arg(long, hide = true, default_value = "9999")]
    tun_adapter_port: u16,
    /// Controlled IPv6 packet-to-relay bridge lab: smoltcp terminates a
    /// controlled IPv6 TCP flow and bridges it to the existing relay tunnel
    /// (needs --tun-relay-config + --tun-relay-target). Lab only.
    #[cfg(target_os = "linux")]
    #[arg(long, hide = true)]
    tun_ipv6_relay_bridge_lab: Option<std::net::Ipv6Addr>,
    /// Controlled IPv6 UDP relay bridge lab: smoltcp captures an app IPv6 UDP
    /// datagram from the TUN, carries it over MASQUE direct to the target, and
    /// injects the response back through the TUN (bidirectional). Fail-closed on
    /// relay error (no native fallback). Needs --tun-relay-config +
    /// --tun-relay-target. Lab only.
    #[cfg(target_os = "linux")]
    #[arg(long, hide = true)]
    tun_ipv6_udp_relay_bridge_lab: Option<std::net::Ipv6Addr>,
    /// Relay client config (TOML) providing relay settings for the bridge lab.
    #[cfg(target_os = "linux")]
    #[arg(long, hide = true)]
    tun_relay_config: Option<PathBuf>,
    /// Relay target host:port for the bridge lab (e.g. 1.1.1.1:80).
    #[cfg(target_os = "linux")]
    #[arg(long, hide = true)]
    tun_relay_target: Option<String>,
    /// Relay/server IP kept on its normal route (excluded from the TUN).
    #[cfg(target_os = "linux")]
    #[arg(long, hide = true)]
    tun_relay_exclude: Option<std::net::IpAddr>,
    /// Controlled IPv6 prefix relay lab: install ONE controlled ULA prefix as a
    /// device route, prove peer1 relay egress + observe peer2 (multi-peer). Needs
    /// --tun-relay-config + --tun-relay-target + this prefix peer1 addr.
    #[cfg(target_os = "linux")]
    #[arg(long, hide = true)]
    tun_ipv6_prefix_relay_lab: Option<std::net::Ipv6Addr>,
    /// Controlled ULA prefix (CIDR) for the prefix relay lab, e.g. fd00:ae61::/64.
    #[cfg(target_os = "linux")]
    #[arg(long, hide = true, default_value = "fd00:ae61::/64")]
    tun_controlled_prefix: String,
    /// Second controlled peer inside the prefix (observed handshake).
    #[cfg(target_os = "linux")]
    #[arg(long, hide = true)]
    tun_peer2: Option<std::net::Ipv6Addr>,
    /// Guarded IPv6 default-route DRY-RUN: print the planned ::/0 capture +
    /// relay-loop prevention + rollback. Applies NOTHING. Artifact-only.
    #[cfg(target_os = "linux")]
    #[arg(long, hide = true)]
    tun_ipv6_default_route_dry_run: bool,
    /// GUARDED live IPv6 ::/0 capture: temporarily install the ::/1 + 8000::/1
    /// capture into the AEGIS TUN, relay this IPv6 target through the relay, then
    /// roll back (watchdog mandatory). Needs --guarded-default-route-confirm,
    /// --tun-relay-config, --tun-relay-target, --tun-max-runtime-seconds.
    #[cfg(target_os = "linux")]
    #[arg(long, hide = true)]
    tun_ipv6_default_route_guarded_lab: Option<std::net::Ipv6Addr>,
    /// Explicit confirmation for the guarded live ::/0 capture.
    #[cfg(target_os = "linux")]
    #[arg(long, hide = true)]
    guarded_default_route_confirm: bool,
    /// Hard cap (seconds) on the guarded capture window (watchdog). 1..=600.
    #[cfg(target_os = "linux")]
    #[arg(long, hide = true, default_value = "120")]
    tun_max_runtime_seconds: u64,
    #[cfg(windows)]
    #[arg(long)]
    windows_wide_listener: Option<SocketAddr>,
    #[cfg(windows)]
    #[arg(long)]
    windows_wide_original_dst: Option<SocketAddr>,
    #[cfg(windows)]
    #[arg(long, hide = true)]
    windows_service: bool,
}

#[cfg(windows)]
fn apply_windows_wide_cli_overrides(cfg: &mut Settings, args: &Args) -> anyhow::Result<()> {
    match (args.windows_wide_listener, args.windows_wide_original_dst) {
        (None, None) => Ok(()),
        (Some(listen), None) => {
            if !listen.ip().is_loopback() {
                anyhow::bail!("--windows-wide-listener must be loopback for the controlled proof");
            }
            cfg.mode = Mode::Relay;
            cfg.ingress.primary = IngressPrimary::Wide;
            cfg.ingress.allow_fallback = false;
            cfg.ingress.wide.enabled = true;
            cfg.ingress.wide.platform_backend = WidePlatformBackend::WindowsWfpAle;
            cfg.ingress.wide.listen = listen;
            cfg.ingress.wide.capture_dns = false;
            cfg.ingress.wide.controlled_tcp_target = None;
            Ok(())
        }
        (Some(listen), Some(original_dst)) => {
            if !listen.ip().is_loopback() {
                anyhow::bail!("--windows-wide-listener must be loopback for the controlled proof");
            }
            if !original_dst.is_ipv4() {
                anyhow::bail!("--windows-wide-original-dst must be IPv4 for the controlled proof");
            }
            cfg.mode = Mode::Relay;
            cfg.ingress.primary = IngressPrimary::Wide;
            cfg.ingress.allow_fallback = false;
            cfg.ingress.wide.enabled = true;
            cfg.ingress.wide.platform_backend = WidePlatformBackend::WindowsWfpAle;
            cfg.ingress.wide.listen = listen;
            cfg.ingress.wide.capture_dns = false;
            cfg.ingress.wide.controlled_tcp_target = Some(original_dst);
            Ok(())
        }
        (None, Some(_)) => {
            anyhow::bail!("--windows-wide-original-dst requires --windows-wide-listener")
        }
    }
}

fn spawn_stdin_eof_shutdown(exit_on_stdin_eof: bool) -> Option<tokio::sync::watch::Receiver<bool>> {
    if !exit_on_stdin_eof {
        return None;
    }
    let (tx, rx) = tokio::sync::watch::channel(false);
    // Sandboxed e2e runs cannot always signal spawned children, so tests use
    // stdin EOF as a deterministic shutdown path instead.
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin().lock();
        let mut buf = [0u8; 256];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => {
                    let _ = tx.send(true);
                    break;
                }
                Ok(_) => {}
            }
        }
    });
    Some(rx)
}

#[derive(Clone)]
enum RuntimeContext {
    Direct {
        brain: Arc<Brain>,
        ghost: Option<Arc<GhostLurk>>,
    },
    Relay {
        brain: Arc<Brain>,
        store: AsyncStateStore,
    },
    Auto {
        brain: Arc<Brain>,
        ghost: Option<Arc<GhostLurk>>,
    },
}

fn relay_transport_key(family: TunnelTransportFamily) -> &'static str {
    match family {
        TunnelTransportFamily::LegacyTls => "legacy_tls",
        TunnelTransportFamily::HttpsWs => "https_ws",
        TunnelTransportFamily::GrpcStream => "grpc_stream",
        TunnelTransportFamily::GrpcDatagram => "grpc_datagram",
        TunnelTransportFamily::MasqueDerived => "masque_derived",
    }
}

async fn learn_relay_outcomes(
    brain: &Brain,
    key: &StrategyKey,
    outcomes: &mut tokio::sync::mpsc::UnboundedReceiver<relay::RelayOutcome>,
) -> Option<relay::RelayOutcome> {
    let mut terminal_outcome = None;
    while let Some(outcome) = outcomes.recv().await {
        if let Some(signal) = outcome.learning_signal() {
            brain
                .record_outcome(
                    key,
                    relay_transport_key(outcome.transport),
                    signal.clone(),
                    outcome.learning_opening_latency_ms(),
                    outcome.bytes_sent as usize,
                    None,
                )
                .await;
        }
        // Only the final attempt can establish terminal response evidence.
        terminal_outcome = Some(outcome);
    }
    terminal_outcome
}

fn relay_transport_from_key(key: &str) -> Option<TunnelTransportFamily> {
    match key {
        "legacy_tls" => Some(TunnelTransportFamily::LegacyTls),
        "https_ws" => Some(TunnelTransportFamily::HttpsWs),
        "grpc_stream" => Some(TunnelTransportFamily::GrpcStream),
        "grpc_datagram" => Some(TunnelTransportFamily::GrpcDatagram),
        "masque_derived" => Some(TunnelTransportFamily::MasqueDerived),
        _ => None,
    }
}

fn relay_transport_order_keys(order: &[TunnelTransportFamily]) -> Vec<String> {
    order
        .iter()
        .copied()
        .map(relay_transport_key)
        .map(ToString::to_string)
        .collect()
}

async fn calibrated_relay_settings_for_session(
    settings: &aegis_core::RelaySettings,
    brain: &Brain,
    store: &AsyncStateStore,
    target_host: &str,
    target_port: u16,
    dst: SocketAddr,
) -> aegis_core::RelaySettings {
    let state = store.snapshot().await;
    let have_calibration = state.external_calibration.is_some();
    // Adaptive transport ordering (Brick 2): consult the Brain's learned reward
    // even without an external calibration snapshot when [relay].adaptive_transport
    // is enabled. The explicit recent-routes opt-in has its own bounded window
    // and cold-start rules. With none of these, use the configured order verbatim.
    let adaptive = settings.policy.adaptive_transport;
    if !have_calibration && !adaptive && !brain.recent_routes_enabled() {
        return settings.clone();
    }

    let original_order = settings.transport_priority.clone();
    let original_order_keys = relay_transport_order_keys(&original_order);
    let key = StrategyKey::for_target(
        dst,
        target_host,
        target_port,
        Some(target_host),
        target_port == 443,
    );
    let trace = brain.select_order_trace(&key).await;
    // Anti-thrash: without an external calibration snapshot, only trust the learned
    // reorder once at least one transport has accumulated real samples — a cold or
    // near-empty Brain would otherwise reorder on UCB1 exploration noise. Until
    // then, keep the configured order.
    const MIN_ADAPTIVE_TRIALS: f64 = 8.0;
    if !have_calibration && trace.recent_selection.is_none() {
        let max_trials = trace
            .ranked_candidates
            .iter()
            .map(|candidate| candidate.total_trials)
            .fold(0.0f64, f64::max);
        if max_trials < MIN_ADAPTIVE_TRIALS {
            return settings.clone();
        }
    }
    let mut calibrated_order = Vec::new();
    for strategy in &trace.reward_selected_order {
        if let Some(family) = relay_transport_from_key(strategy) {
            if original_order.contains(&family) && !calibrated_order.contains(&family) {
                calibrated_order.push(family);
            }
        }
    }
    // Calibration-backed baseline and recent selection can exclude hard blocks.
    // Preserve their selected set, including an empty all-blocked order. The
    // uncalibrated legacy path still only reorders configured families.
    if !have_calibration && trace.recent_selection.is_none() {
        for family in &original_order {
            if !calibrated_order.contains(family) {
                calibrated_order.push(*family);
            }
        }
    }
    let calibrated_order_keys = relay_transport_order_keys(&calibrated_order);
    let ranked_candidates = trace
        .ranked_candidates
        .iter()
        .map(|candidate| {
            json!({
                "strategy": candidate.strategy,
                "estimated_reward": candidate.estimated_reward,
                "estimated_trials": candidate.estimated_trials,
                "total_trials": candidate.total_trials,
                "selection_score": candidate.selection_score,
                "selection_score_reward_component": candidate.selection_score_reward_component,
                "selection_score_ucb_exploration_bonus": candidate.selection_score_ucb_exploration_bonus,
                "selection_score_probe_bias_component": candidate.selection_score_probe_bias_component,
                "belief_alpha": candidate.belief_alpha,
                "belief_beta": candidate.belief_beta,
                "belief_detection_risk": candidate.belief_detection_risk,
                "belief_latency_cost": candidate.belief_latency_cost,
                "belief_confidence": candidate.belief_confidence,
                "belief_freshness": candidate.belief_freshness,
                "belief_hard_blocked": candidate.belief_hard_blocked,
                "belief_source": candidate.belief_source,
                "cold_start_exploration": candidate.cold_start_exploration,
            })
        })
        .collect::<Vec<_>>();
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::BrainSelectOrderExplained,
        "brain selected relay transport order",
        json!({
            "calibration_snapshot_loaded": have_calibration,
            "adaptive_transport": adaptive,
            "runtime_surface": "relay_transport",
            "target": target_host,
            "port": target_port,
            "selector_mode": trace.selector_mode,
            "explainability_trace_source": trace.explainability_trace_source,
            "explainability_observation_source": trace.explainability_observation_source,
            "selection_model": if trace.recent_selection.is_some() {
                "recent_windowed_ucb_diversity"
            } else { "l1_l2_l3_adaptive_posterior" },
            "original_transport_order": original_order_keys,
            "reward_selected_order": trace.reward_selected_order,
            "calibrated_transport_order": calibrated_order_keys,
            "calibrated_order_applied": calibrated_order != original_order,
            "ranked_candidates": ranked_candidates,
            "ranked_candidates_scope": if trace.recent_selection.is_some() {
                "baseline_contextual_snapshot"
            } else { "selected_order_evidence" },
            "recent_selection": trace.recent_selection,
        }),
    );

    let mut adjusted = settings.clone();
    adjusted.transport_priority = calibrated_order;
    adjusted
}

#[derive(Clone)]
struct IngressLateRuntimeContext {
    backend_id: String,
    backend_runtime_id: String,
    backend_kind: String,
    backend_kind_code: &'static str,
    requested_primary: String,
    requested_primary_code: &'static str,
    mode: String,
    mode_code: &'static str,
    wide_supported: Option<bool>,
    wide_platform_family_supported: Option<bool>,
    wide_runtime_readiness: Option<crate::ingress::preflight::WideRuntimeReadiness>,
    rollout_profile: Option<String>,
    rollout_profile_code: Option<&'static str>,
    prerouting_interface: Option<String>,
    path_code: &'static str,
    fallback_reason_code: Option<FallbackReasonCode>,
    fallback_reason: Option<&'static str>,
    bind_error_code: Option<RuntimeProbeCode>,
}

#[cfg(test)]
#[path = "auto_dns_tests.rs"]
mod auto_dns_tests;

fn session_broker_for_mode(mode: &Mode) -> DefaultSessionBroker {
    DefaultSessionBroker {
        defer_relay_resolution: matches!(mode, Mode::Auto | Mode::Relay),
    }
}

async fn reject_tcp_connect_if_runtime_unready(
    intent: &mut ingress::IngressSessionIntent,
    cfg: &Settings,
    ingress_context: &IngressLateRuntimeContext,
) -> bool {
    if !(intent.is_tcp_connect()
        && matches!(cfg.mode, Mode::Relay)
        && !relay::runtime_fallback_ready(&cfg.relay))
    {
        return false;
    }

    let reject_reason_code = "tcp_connect_requires_runtime_ready_relay_transport";
    let reject_reason = "relay mode requires a runtime-ready relay transport";
    let request_kind = "TcpConnect";
    let reject_stage = "pre_broker_runtime_gate";
    let response_action = "send_general_failure";
    let response_reply_code = 1;
    if let Err(err) = intent.reject_general_failure().await {
        error!(
            event_code = RuntimeEventCode::IngressTcpConnectRejectResponseFailed.as_str(),
            peer = ?intent.peer,
            backend = %ingress_context.backend_id,
            backend_runtime_id = %ingress_context.backend_runtime_id,
            backend_kind = %ingress_context.backend_kind,
            requested_primary = %ingress_context.requested_primary,
            mode = %ingress_context.mode,
            wide_supported = ?ingress_context.wide_supported,
            wide_platform_family_supported = ?ingress_context.wide_platform_family_supported,
            wide_runtime_readiness = ?ingress_context.wide_runtime_readiness,
            rollout_profile = ?ingress_context.rollout_profile,
            prerouting_interface = ?ingress_context.prerouting_interface,
            startup_path_code = ingress_context.path_code,
            startup_fallback_reason_code = ?ingress_context.fallback_reason_code,
            startup_fallback_reason = ?ingress_context.fallback_reason,
            startup_bind_error_code = ?ingress_context.bind_error_code,
            reject_reason_code = reject_reason_code,
            reason = reject_reason,
            response_error_kind = io_error_kind_code(&err),
            "failed to reject TCP connect: {err}"
        );
        runtime_jsonl::emit(
            "error",
            RuntimeEventCode::IngressTcpConnectRejectResponseFailed,
            "failed to reject TCP connect response",
            json!({
                "peer": intent.peer.to_string(),
                "backend": ingress_context.backend_id.as_str(),
                "backend_runtime_id": ingress_context.backend_runtime_id.as_str(),
                "backend_kind": ingress_context.backend_kind.as_str(),
                "backend_kind_code": ingress_context.backend_kind_code,
                "requested_primary": ingress_context.requested_primary.as_str(),
                "requested_primary_code": ingress_context.requested_primary_code,
                "mode": ingress_context.mode.as_str(),
                "mode_code": ingress_context.mode_code,
                "wide_supported": ingress_context.wide_supported,
                "wide_platform_family_supported": ingress_context.wide_platform_family_supported,
                "wide_runtime_readiness": ingress_context.wide_runtime_readiness,
                "rollout_profile": ingress_context.rollout_profile.as_deref(),
                "rollout_profile_code": ingress_context.rollout_profile_code,
                "prerouting_interface": ingress_context.prerouting_interface.as_deref(),
                "startup_path_code": ingress_context.path_code,
                "startup_fallback_reason_code": ingress_context.fallback_reason_code,
                "startup_fallback_reason": ingress_context.fallback_reason,
                "startup_bind_error_code": ingress_context.bind_error_code,
                "request_kind": request_kind,
                "reject_stage": reject_stage,
                "response_action": response_action,
                "response_reply_code": response_reply_code,
                "reject_reason_code": reject_reason_code,
                "reason": reject_reason,
                "response_error_kind": io_error_kind_code(&err),
                "error": err.to_string()
            }),
        );
    }
    error!(
        event_code = RuntimeEventCode::IngressTcpConnectRejected.as_str(),
        peer = ?intent.peer,
        backend = %ingress_context.backend_id,
        backend_runtime_id = %ingress_context.backend_runtime_id,
        backend_kind = %ingress_context.backend_kind,
        requested_primary = %ingress_context.requested_primary,
        mode = %ingress_context.mode,
        wide_supported = ?ingress_context.wide_supported,
        wide_platform_family_supported = ?ingress_context.wide_platform_family_supported,
        wide_runtime_readiness = ?ingress_context.wide_runtime_readiness,
        rollout_profile = ?ingress_context.rollout_profile,
        prerouting_interface = ?ingress_context.prerouting_interface,
        startup_path_code = ingress_context.path_code,
        startup_fallback_reason_code = ?ingress_context.fallback_reason_code,
        startup_fallback_reason = ?ingress_context.fallback_reason,
        startup_bind_error_code = ?ingress_context.bind_error_code,
        reject_reason_code = reject_reason_code,
        reason = reject_reason,
        "tcp connect rejected"
    );
    runtime_jsonl::emit(
        "error",
        RuntimeEventCode::IngressTcpConnectRejected,
        "tcp connect rejected",
        json!({
            "peer": intent.peer.to_string(),
            "backend": ingress_context.backend_id.as_str(),
            "backend_runtime_id": ingress_context.backend_runtime_id.as_str(),
            "backend_kind": ingress_context.backend_kind.as_str(),
            "backend_kind_code": ingress_context.backend_kind_code,
            "requested_primary": ingress_context.requested_primary.as_str(),
            "requested_primary_code": ingress_context.requested_primary_code,
            "mode": ingress_context.mode.as_str(),
            "mode_code": ingress_context.mode_code,
            "wide_supported": ingress_context.wide_supported,
            "wide_platform_family_supported": ingress_context.wide_platform_family_supported,
            "wide_runtime_readiness": ingress_context.wide_runtime_readiness,
            "rollout_profile": ingress_context.rollout_profile.as_deref(),
            "rollout_profile_code": ingress_context.rollout_profile_code,
            "prerouting_interface": ingress_context.prerouting_interface.as_deref(),
            "startup_path_code": ingress_context.path_code,
            "startup_fallback_reason_code": ingress_context.fallback_reason_code,
            "startup_fallback_reason": ingress_context.fallback_reason,
            "startup_bind_error_code": ingress_context.bind_error_code,
            "request_kind": request_kind,
            "reject_stage": reject_stage,
            "response_action": response_action,
            "response_reply_code": response_reply_code,
            "reject_reason_code": reject_reason_code,
            "reason": reject_reason
        }),
    );
    true
}

async fn reject_udp_associate_if_runtime_unready(
    intent: &mut ingress::IngressSessionIntent,
    cfg: &Settings,
    ingress_context: &IngressLateRuntimeContext,
) -> bool {
    if !intent.is_udp_associate() {
        return false;
    }

    let (
        reject_reason_code,
        reject_reason,
        reject_command_not_supported,
        response_action,
        response_reply_code,
    ) = match cfg.mode {
        Mode::Direct => (
            "udp_associate_requires_relay_mode",
            "udp associate requires relay mode",
            true,
            "send_command_not_supported",
            7,
        ),
        Mode::Auto | Mode::Relay if !relay::runtime_udp_associate_ready(&cfg.relay) => (
            "udp_associate_requires_udp_capable_relay_transport",
            "udp associate requires a configured MASQUE relay; gRPC datagrams are fixed-destination only",
            false,
            "send_general_failure",
            1,
        ),
        _ => return false,
    };

    let request_kind = "UdpAssociate";
    let reject_stage = "pre_broker_runtime_gate";
    let reject_result = if reject_command_not_supported {
        intent.reject_command_not_supported().await
    } else {
        intent.reject_general_failure().await
    };
    if let Err(err) = reject_result {
        let response_message = if reject_command_not_supported {
            "failed to reject unsupported UDP associate response"
        } else {
            "failed to reject UDP associate response"
        };
        let response_error = if reject_command_not_supported {
            format!("failed to reject unsupported UDP associate: {err}")
        } else {
            format!("failed to reject UDP associate: {err}")
        };
        error!(
            event_code = RuntimeEventCode::IngressUdpAssociateRejectResponseFailed.as_str(),
            peer = ?intent.peer,
            backend = %ingress_context.backend_id,
            backend_runtime_id = %ingress_context.backend_runtime_id,
            backend_kind = %ingress_context.backend_kind,
            requested_primary = %ingress_context.requested_primary,
            mode = %ingress_context.mode,
            wide_supported = ?ingress_context.wide_supported,
            wide_platform_family_supported = ?ingress_context.wide_platform_family_supported,
            wide_runtime_readiness = ?ingress_context.wide_runtime_readiness,
            rollout_profile = ?ingress_context.rollout_profile,
            prerouting_interface = ?ingress_context.prerouting_interface,
            startup_path_code = ingress_context.path_code,
            startup_fallback_reason_code = ?ingress_context.fallback_reason_code,
            startup_fallback_reason = ?ingress_context.fallback_reason,
            startup_bind_error_code = ?ingress_context.bind_error_code,
            reject_reason_code = reject_reason_code,
            reason = reject_reason,
            response_error_kind = io_error_kind_code(&err),
            "{response_error}"
        );
        runtime_jsonl::emit(
            "error",
            RuntimeEventCode::IngressUdpAssociateRejectResponseFailed,
            response_message,
            json!({
                "peer": intent.peer.to_string(),
                "backend": ingress_context.backend_id.as_str(),
                "backend_runtime_id": ingress_context.backend_runtime_id.as_str(),
                "backend_kind": ingress_context.backend_kind.as_str(),
                "backend_kind_code": ingress_context.backend_kind_code,
                "requested_primary": ingress_context.requested_primary.as_str(),
                "requested_primary_code": ingress_context.requested_primary_code,
                "mode": ingress_context.mode.as_str(),
                "mode_code": ingress_context.mode_code,
                "wide_supported": ingress_context.wide_supported,
                "wide_platform_family_supported": ingress_context.wide_platform_family_supported,
                "wide_runtime_readiness": ingress_context.wide_runtime_readiness,
                "rollout_profile": ingress_context.rollout_profile.as_deref(),
                "rollout_profile_code": ingress_context.rollout_profile_code,
                "prerouting_interface": ingress_context.prerouting_interface.as_deref(),
                "startup_path_code": ingress_context.path_code,
                "startup_fallback_reason_code": ingress_context.fallback_reason_code,
                "startup_fallback_reason": ingress_context.fallback_reason,
                "startup_bind_error_code": ingress_context.bind_error_code,
                "request_kind": request_kind,
                "reject_stage": reject_stage,
                "response_action": response_action,
                "response_reply_code": response_reply_code,
                "reject_reason_code": reject_reason_code,
                "reason": reject_reason,
                "response_error_kind": io_error_kind_code(&err),
                "error": err.to_string()
            }),
        );
    }
    error!(
        event_code = RuntimeEventCode::IngressUdpAssociateRejected.as_str(),
        peer = ?intent.peer,
        backend = %ingress_context.backend_id,
        backend_runtime_id = %ingress_context.backend_runtime_id,
        backend_kind = %ingress_context.backend_kind,
        requested_primary = %ingress_context.requested_primary,
        mode = %ingress_context.mode,
        wide_supported = ?ingress_context.wide_supported,
        wide_platform_family_supported = ?ingress_context.wide_platform_family_supported,
        wide_runtime_readiness = ?ingress_context.wide_runtime_readiness,
        rollout_profile = ?ingress_context.rollout_profile,
        prerouting_interface = ?ingress_context.prerouting_interface,
        startup_path_code = ingress_context.path_code,
        startup_fallback_reason_code = ?ingress_context.fallback_reason_code,
        startup_fallback_reason = ?ingress_context.fallback_reason,
        startup_bind_error_code = ?ingress_context.bind_error_code,
        reject_reason_code = reject_reason_code,
        reason = reject_reason,
        "udp associate rejected"
    );
    runtime_jsonl::emit(
        "error",
        RuntimeEventCode::IngressUdpAssociateRejected,
        "udp associate rejected",
        json!({
            "peer": intent.peer.to_string(),
            "backend": ingress_context.backend_id.as_str(),
            "backend_runtime_id": ingress_context.backend_runtime_id.as_str(),
            "backend_kind": ingress_context.backend_kind.as_str(),
            "backend_kind_code": ingress_context.backend_kind_code,
            "requested_primary": ingress_context.requested_primary.as_str(),
            "requested_primary_code": ingress_context.requested_primary_code,
            "mode": ingress_context.mode.as_str(),
            "mode_code": ingress_context.mode_code,
            "wide_supported": ingress_context.wide_supported,
            "wide_platform_family_supported": ingress_context.wide_platform_family_supported,
            "wide_runtime_readiness": ingress_context.wide_runtime_readiness,
            "rollout_profile": ingress_context.rollout_profile.as_deref(),
            "rollout_profile_code": ingress_context.rollout_profile_code,
            "prerouting_interface": ingress_context.prerouting_interface.as_deref(),
            "startup_path_code": ingress_context.path_code,
            "startup_fallback_reason_code": ingress_context.fallback_reason_code,
            "startup_fallback_reason": ingress_context.fallback_reason,
            "startup_bind_error_code": ingress_context.bind_error_code,
            "request_kind": request_kind,
            "reject_stage": reject_stage,
            "response_action": response_action,
            "response_reply_code": response_reply_code,
            "reject_reason_code": reject_reason_code,
            "reason": reject_reason
        }),
    );
    true
}

impl RuntimeContext {
    #[cfg(test)]
    async fn from_settings(cfg: &Settings) -> anyhow::Result<Self> {
        Self::from_settings_with_calibration(cfg, None).await
    }

    async fn from_settings_with_calibration(
        cfg: &Settings,
        calibration: Option<&ExternalCalibrationSnapshot>,
    ) -> anyhow::Result<Self> {
        match cfg.mode {
            Mode::Direct | Mode::Auto => {
                let store = runtime_calibration::load_runtime(
                    &cfg.direct,
                    cfg.mode.clone(),
                    crate::runtime_event_stream::forensic_redact_enabled(),
                    calibration,
                )
                .await?;
                let brain = Arc::new(
                    Brain::new(cfg.direct.epsilon, cfg.direct.strategies.clone(), store)
                        .with_recent_routes(cfg.direct.recent_routes.as_ref())
                        .map_err(anyhow::Error::msg)?,
                );
                let ghost = cfg
                    .direct
                    .ghost_profile
                    .as_ref()
                    .map(|p| config::expand_tilde(p))
                    .and_then(|p| GhostLurk::from_file(&p).ok())
                    .map(Arc::new);
                if matches!(cfg.mode, Mode::Auto) {
                    Ok(Self::Auto { brain, ghost })
                } else {
                    Ok(Self::Direct { brain, ghost })
                }
            }
            Mode::Relay => {
                let store = runtime_calibration::load_runtime(
                    &cfg.direct,
                    cfg.mode.clone(),
                    crate::runtime_event_stream::forensic_redact_enabled(),
                    calibration,
                )
                .await?;
                let brain = Arc::new(
                    Brain::new(
                        cfg.direct.epsilon,
                        relay_transport_order_keys(&cfg.relay.transport_priority),
                        store.clone(),
                    )
                    .with_recent_routes(cfg.direct.recent_routes.as_ref())
                    .map_err(anyhow::Error::msg)?,
                );
                Ok(Self::Relay { brain, store })
            }
        }
    }

    async fn handle_session(
        &self,
        session: BrokeredSession,
        cfg: &Settings,
        ingress_context: IngressLateRuntimeContext,
    ) -> anyhow::Result<()> {
        match (self, session) {
            (Self::Direct { brain, ghost }, BrokeredSession::TcpConnect(session)) => {
                direct::handle_direct(
                    session.client,
                    session.target,
                    session.dst,
                    brain.clone(),
                    &cfg.direct,
                    direct::DirectFallbackContext {
                        relay: &cfg.relay,
                        terminal_policy: direct::DirectTerminalPolicy::PreserveDirectFailure,
                    },
                    ghost.clone(),
                )
                .await
            }
            (Self::Auto { brain, ghost }, BrokeredSession::TcpConnect(session)) => {
                direct::handle_auto(
                    session.client,
                    session.target,
                    session.dst,
                    brain.clone(),
                    &cfg.direct,
                    direct::DirectFallbackContext {
                        relay: &cfg.relay,
                        terminal_policy: if cfg.direct.hybrid_geneva {
                            direct::DirectTerminalPolicy::HybridRelayOrFailClosed
                        } else {
                            direct::DirectTerminalPolicy::RelayOrFailClosed
                        },
                    },
                    ghost.clone(),
                )
                .await
            }
            (Self::Relay { brain, store }, BrokeredSession::TcpConnect(session)) => {
                let stack_profile = cfg
                    .direct
                    .stack_profile
                    .as_deref()
                    .and_then(|value| value.parse::<StackProfileId>().ok());
                #[cfg(windows)]
                let windows_wide_tcp = session.ingress_kind
                    == crate::ingress::IngressKind::WidePrimary
                    && cfg.ingress.wide.platform_backend == WidePlatformBackend::WindowsWfpAle;
                #[cfg(windows)]
                if windows_wide_tcp {
                    crate::windows_wide::events::relay_session_started(
                        &cfg.relay.server,
                        session.dst,
                    );
                    crate::windows_wide::events::relay_transport_selected(
                        &cfg.relay.server,
                        "existing_relay_runtime",
                    );
                }
                let relay_settings = calibrated_relay_settings_for_session(
                    &cfg.relay,
                    brain,
                    store,
                    &session.target.host,
                    session.target.port,
                    session.dst,
                )
                .await;
                // Wide capture flow lifecycle events (cross-platform): a
                // captured no-proxy local TCP flow began/succeeded/failed its
                // relay leg. Only for the wide-primary ingress so SOCKS/relay
                // sessions are not mislabelled as wide.
                let wide_capture_tcp =
                    session.ingress_kind == crate::ingress::IngressKind::WidePrimary;
                let wide_flow_target = if wide_capture_tcp {
                    format!("{}:{}", session.target.host, session.target.port)
                } else {
                    String::new()
                };
                if wide_capture_tcp {
                    runtime_jsonl::emit(
                        "info",
                        crate::runtime_events::RuntimeEventCode::WideCaptureFlowStarted,
                        "wide capture flow started",
                        serde_json::json!({ "target": wide_flow_target, "dst": session.dst.to_string() }),
                    );
                }
                // Brick 1 (adaptive-relay learning): capture the Brain key before
                // `session` fields are moved into the call, plus an outcome sink so
                // each transport attempt's result feeds the Brain below. Recording
                // ONLY — transport order is unchanged (the reorder stays gated on
                // external calibration), so this changes no connectivity behaviour.
                let relay_key_host = session.target.host.clone();
                let relay_key_port = session.target.port;
                let relay_key_dst = session.dst;
                let (relay_outcome_tx, mut relay_outcome_rx) =
                    tokio::sync::mpsc::unbounded_channel::<relay::RelayOutcome>();
                let result = relay::run_relay_tunnel(
                    session.client,
                    &relay_settings,
                    session.target.host,
                    session.target.port,
                    None,
                    Some(relay::RelayMimicryContext {
                        target_addr: session.dst,
                        stack_profile,
                        wire_mode: cfg.direct.wire_mimicry_mode,
                        // The non-direct relay path through main.rs does
                        // not consult Brain advisory for surface bias —
                        // bias defaults to neutral, preserving pre-2.5
                        // deterministic mod-of-seed surface selection.
                        surface_bias: relay::SurfaceBias::default(),
                    }),
                    Some(&relay_outcome_tx),
                )
                .await;
                // Feed each per-transport outcome into the Brain so it learns which
                // relay transport is failing/blocked for this target. Symmetric with
                // the direct path (which already records per attempt).
                drop(relay_outcome_tx);
                let relay_key = StrategyKey::for_target(
                    relay_key_dst,
                    &relay_key_host,
                    relay_key_port,
                    Some(relay_key_host.as_str()),
                    relay_key_port == 443,
                );
                let terminal_outcome =
                    learn_relay_outcomes(brain, &relay_key, &mut relay_outcome_rx).await;
                if wide_capture_tcp {
                    emit_wide_tcp_terminal(&wide_flow_target, &result, terminal_outcome.as_ref());
                }
                #[cfg(windows)]
                if windows_wide_tcp {
                    crate::windows_wide::events::relay_session_terminal(
                        &cfg.relay.server,
                        &result,
                        terminal_outcome.as_ref(),
                    );
                }
                result
            }
            (Self::Relay { .. }, BrokeredSession::UdpAssociate(session)) => {
                relay::run_relay_udp_associate(
                    session.control,
                    session.udp_socket,
                    &cfg.relay,
                    session.client_ip,
                )
                .await
            }
            (Self::Relay { .. }, BrokeredSession::UdpDatagram(session)) => {
                let target_host = session.target.host.clone();
                let target_port = session.target.port;
                let wide_udp_surface = active_wide_udp_event_surface(
                    cfg,
                    ingress_context.backend_kind_code,
                    target_port,
                );
                let response = relay::run_relay_udp_datagram_once(
                    &cfg.relay,
                    session.target,
                    &session.payload,
                )
                .await?;
                let response_action = session.response.action();
                session.response.send(&response).await?;
                info!(
                    event_code = RuntimeEventCode::IngressUdpDatagramCompleted.as_str(),
                    ingress_kind = ?session.ingress_kind,
                    wide_udp_capture_contract = ?wide_udp_surface.capture_contract,
                    wide_udp_capture_support_tier = ?wide_udp_surface.capture_support_tier,
                    wide_udp_capture_policy = ?wide_udp_surface.capture_policy,
                    wide_udp_capture_runtime_scope = ?wide_udp_surface.capture_runtime_scope,
                    wide_udp_capture_match_kind = ?wide_udp_surface.capture_match_kind,
                    wide_udp_capture_accept_reason_code = ?wide_udp_surface.capture_accept_reason_code,
                    wide_udp_preview_policy = ?wide_udp_surface.preview_policy,
                    wide_udp_preview_match_kind = ?wide_udp_surface.preview_match_kind,
                    wide_udp_preview_accept_reason_code = ?wide_udp_surface.preview_accept_reason_code,
                    wide_udp_preview_ports = ?wide_udp_surface.preview_ports,
                    target_host = %target_host,
                    target_port = target_port,
                    response_len = response.len(),
                    response_action = response_action,
                    "ingress udp datagram completed"
                );
                runtime_jsonl::emit(
                    "info",
                    RuntimeEventCode::IngressUdpDatagramCompleted,
                    "ingress udp datagram completed",
                    json!({
                        "ingress_kind": format!("{:?}", session.ingress_kind),
                        "ingress_kind_code": session.ingress_kind.as_code(),
                        "backend": ingress_context.backend_id,
                        "backend_runtime_id": ingress_context.backend_runtime_id,
                        "backend_kind": ingress_context.backend_kind,
                        "backend_kind_code": ingress_context.backend_kind_code,
                        "requested_primary": ingress_context.requested_primary,
                        "requested_primary_code": ingress_context.requested_primary_code,
                        "mode": ingress_context.mode,
                        "mode_code": ingress_context.mode_code,
                        "wide_supported": ingress_context.wide_supported,
                        "wide_platform_family_supported": ingress_context.wide_platform_family_supported,
                        "wide_runtime_readiness": ingress_context.wide_runtime_readiness,
                        "rollout_profile": ingress_context.rollout_profile.as_deref(),
                        "rollout_profile_code": ingress_context.rollout_profile_code,
                        "prerouting_interface": ingress_context.prerouting_interface.as_deref(),
                        "startup_path_code": ingress_context.path_code,
                        "startup_fallback_reason_code": ingress_context.fallback_reason_code,
                        "startup_fallback_reason": ingress_context.fallback_reason,
                        "startup_bind_error_code": ingress_context.bind_error_code,
                        "wide_udp_capture_contract": wide_udp_surface.capture_contract,
                        "wide_udp_capture_support_tier": wide_udp_surface.capture_support_tier,
                        "wide_udp_capture_policy": wide_udp_surface.capture_policy,
                        "wide_udp_capture_runtime_scope": wide_udp_surface.capture_runtime_scope,
                        "wide_udp_capture_match_kind": wide_udp_surface.capture_match_kind,
                        "wide_udp_capture_accept_reason_code": wide_udp_surface.capture_accept_reason_code,
                        "wide_udp_preview_policy": wide_udp_surface.preview_policy,
                        "wide_udp_preview_match_kind": wide_udp_surface.preview_match_kind,
                        "wide_udp_preview_accept_reason_code": wide_udp_surface.preview_accept_reason_code,
                        "wide_udp_preview_ports": wide_udp_surface.preview_ports,
                        "target_host": target_host,
                        "target_port": target_port,
                        "response_len": response.len(),
                        "response_action": response_action
                    }),
                );
                Ok(())
            }
            (Self::Auto { .. }, BrokeredSession::UdpAssociate(session)) => {
                if !relay::runtime_udp_associate_ready(&cfg.relay) {
                    anyhow::bail!("udp associate in auto mode requires a configured MASQUE relay");
                }
                relay::run_relay_udp_associate(
                    session.control,
                    session.udp_socket,
                    &cfg.relay,
                    session.client_ip,
                )
                .await
            }
            (Self::Auto { .. }, BrokeredSession::UdpDatagram(session)) => {
                if !relay::runtime_udp_fallback_ready(&cfg.relay) {
                    anyhow::bail!(
                        "native udp datagram ingress requires a UDP-capable relay transport"
                    );
                }
                let target_host = session.target.host.clone();
                let target_port = session.target.port;
                let wide_udp_surface = active_wide_udp_event_surface(
                    cfg,
                    ingress_context.backend_kind_code,
                    target_port,
                );
                let response = relay::run_relay_udp_datagram_once(
                    &cfg.relay,
                    session.target,
                    &session.payload,
                )
                .await?;
                let response_action = session.response.action();
                session.response.send(&response).await?;
                info!(
                    event_code = RuntimeEventCode::IngressUdpDatagramCompleted.as_str(),
                    ingress_kind = ?session.ingress_kind,
                    wide_udp_capture_contract = ?wide_udp_surface.capture_contract,
                    wide_udp_capture_support_tier = ?wide_udp_surface.capture_support_tier,
                    wide_udp_capture_policy = ?wide_udp_surface.capture_policy,
                    wide_udp_capture_runtime_scope = ?wide_udp_surface.capture_runtime_scope,
                    wide_udp_capture_match_kind = ?wide_udp_surface.capture_match_kind,
                    wide_udp_capture_accept_reason_code = ?wide_udp_surface.capture_accept_reason_code,
                    wide_udp_preview_policy = ?wide_udp_surface.preview_policy,
                    wide_udp_preview_match_kind = ?wide_udp_surface.preview_match_kind,
                    wide_udp_preview_accept_reason_code = ?wide_udp_surface.preview_accept_reason_code,
                    wide_udp_preview_ports = ?wide_udp_surface.preview_ports,
                    target_host = %target_host,
                    target_port = target_port,
                    response_len = response.len(),
                    response_action = response_action,
                    "ingress udp datagram completed"
                );
                runtime_jsonl::emit(
                    "info",
                    RuntimeEventCode::IngressUdpDatagramCompleted,
                    "ingress udp datagram completed",
                    json!({
                        "ingress_kind": format!("{:?}", session.ingress_kind),
                        "ingress_kind_code": session.ingress_kind.as_code(),
                        "backend": ingress_context.backend_id,
                        "backend_runtime_id": ingress_context.backend_runtime_id,
                        "backend_kind": ingress_context.backend_kind,
                        "backend_kind_code": ingress_context.backend_kind_code,
                        "requested_primary": ingress_context.requested_primary,
                        "requested_primary_code": ingress_context.requested_primary_code,
                        "mode": ingress_context.mode,
                        "mode_code": ingress_context.mode_code,
                        "wide_supported": ingress_context.wide_supported,
                        "wide_platform_family_supported": ingress_context.wide_platform_family_supported,
                        "wide_runtime_readiness": ingress_context.wide_runtime_readiness,
                        "rollout_profile": ingress_context.rollout_profile.as_deref(),
                        "rollout_profile_code": ingress_context.rollout_profile_code,
                        "prerouting_interface": ingress_context.prerouting_interface.as_deref(),
                        "startup_path_code": ingress_context.path_code,
                        "startup_fallback_reason_code": ingress_context.fallback_reason_code,
                        "startup_fallback_reason": ingress_context.fallback_reason,
                        "startup_bind_error_code": ingress_context.bind_error_code,
                        "wide_udp_capture_contract": wide_udp_surface.capture_contract,
                        "wide_udp_capture_support_tier": wide_udp_surface.capture_support_tier,
                        "wide_udp_capture_policy": wide_udp_surface.capture_policy,
                        "wide_udp_capture_runtime_scope": wide_udp_surface.capture_runtime_scope,
                        "wide_udp_capture_match_kind": wide_udp_surface.capture_match_kind,
                        "wide_udp_capture_accept_reason_code": wide_udp_surface.capture_accept_reason_code,
                        "wide_udp_preview_policy": wide_udp_surface.preview_policy,
                        "wide_udp_preview_match_kind": wide_udp_surface.preview_match_kind,
                        "wide_udp_preview_accept_reason_code": wide_udp_surface.preview_accept_reason_code,
                        "wide_udp_preview_ports": wide_udp_surface.preview_ports,
                        "target_host": target_host,
                        "target_port": target_port,
                        "response_len": response.len(),
                        "response_action": response_action
                    }),
                );
                Ok(())
            }
            (Self::Direct { .. }, BrokeredSession::UdpAssociate(_)) => {
                anyhow::bail!("udp associate is only supported in relay mode")
            }
            (Self::Direct { .. }, BrokeredSession::UdpDatagram(_)) => {
                anyhow::bail!("native udp datagram ingress is not supported in direct mode")
            }
        }
    }
}

fn emit_wide_tcp_terminal(
    target: &str,
    result: &anyhow::Result<()>,
    terminal: Option<&relay::RelayOutcome>,
) {
    let completion = relay::RelayTcpCompletion::from_result(result, terminal);
    let (level, code, message) = match completion {
        relay::RelayTcpCompletion::ResponseObserved => (
            "info",
            RuntimeEventCode::WideCaptureFlowSucceeded,
            "wide capture flow observed a terminal relay response",
        ),
        relay::RelayTcpCompletion::Failed => (
            "warn",
            RuntimeEventCode::WideCaptureFlowFailed,
            "wide capture flow failed",
        ),
        relay::RelayTcpCompletion::NoResponseObserved
        | relay::RelayTcpCompletion::NoAttemptObserved => (
            "info",
            RuntimeEventCode::WideCaptureFlowCompleted,
            "wide capture flow completed without confirmed response evidence",
        ),
    };
    runtime_jsonl::emit(
        level,
        code,
        message,
        serde_json::json!({
            "target": target,
            "ok": completion == relay::RelayTcpCompletion::ResponseObserved,
            "transfer_result": if result.is_ok() { "ok" } else { "error" },
            "completion_reason": completion.reason(),
            "application_response_observed": terminal
                .is_some_and(|outcome| outcome.bytes_received_observed > 0),
            "bytes_sent_recorded": terminal.map_or(0, |outcome| outcome.bytes_sent),
            "bytes_received_observed": terminal.map_or(0, |outcome| outcome.bytes_received_observed),
            "classifier_signal": terminal.map(|outcome| &outcome.signal),
            "response_evidence_scope": "relay_response_observed_not_application_delivery",
        }),
    );
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    // This module is only event serialization (no WFP/OS APIs), so exercise
    // the exact Windows producer on every native CI host as well as Windows.
    #[allow(dead_code)]
    mod windows_event_fixture {
        include!("windows_wide/events.rs");
    }

    // Brick 2 adaptive transport ordering: once enough live outcomes have
    // accumulated, the Brain demotes a transport it has learned is failing/blocked
    // for a target (never dropping it). Also verifies the flag gate (off ->
    // configured order verbatim). Uses an ephemeral store + epsilon=0 Brain for
    // deterministic reward-only ordering.
    #[tokio::test]
    async fn adaptive_transport_demotes_learned_failing_transport() {
        use aegis_core::signals::FailSignal;
        use aegis_core::state_v2::AsyncStateStore;
        use aegis_core::TunnelTransportFamily::{GrpcStream, HttpsWs, LegacyTls, MasqueDerived};
        use aegis_core::{Brain, RelayPolicySettings, RelaySettings, StrategyKey};

        let order = vec![HttpsWs, GrpcStream, LegacyTls, MasqueDerived];
        let store = AsyncStateStore::ephemeral();
        let brain = Brain::new(0.0, relay_transport_order_keys(&order), store.clone());
        let dst: std::net::SocketAddr = "203.0.113.9:443".parse().unwrap();
        let host = "relay.example.invalid";
        let key = StrategyKey::for_target(dst, host, 443, Some(host), true);
        // grpc gets blocked (DropSuspected) while https carries fine; enough
        // samples to clear the min-trials guard.
        for _ in 0..10 {
            brain
                .record_outcome(
                    &key,
                    relay_transport_key(GrpcStream),
                    FailSignal::DropSuspected,
                    Some(50),
                    0,
                    None,
                )
                .await;
            brain
                .record_outcome(
                    &key,
                    relay_transport_key(HttpsWs),
                    FailSignal::Success,
                    Some(50),
                    0,
                    None,
                )
                .await;
        }

        let mut settings = RelaySettings {
            transport_priority: order.clone(),
            policy: RelayPolicySettings {
                adaptive_transport: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let adjusted =
            calibrated_relay_settings_for_session(&settings, &brain, &store, host, 443, dst).await;
        let pos = |f| {
            adjusted
                .transport_priority
                .iter()
                .position(|x| *x == f)
                .unwrap()
        };
        assert!(
            pos(HttpsWs) < pos(GrpcStream),
            "learned-failing grpc must be demoted below succeeding https_ws: {:?}",
            adjusted.transport_priority
        );
        assert_eq!(
            adjusted.transport_priority.len(),
            order.len(),
            "no transport is dropped, only reordered"
        );

        // Flag off -> configured order verbatim.
        settings.policy.adaptive_transport = false;
        let unchanged =
            calibrated_relay_settings_for_session(&settings, &brain, &store, host, 443, dst).await;
        assert_eq!(unchanged.transport_priority, order);
    }

    #[tokio::test]
    async fn recent_relay_selection_uses_progress_before_legacy_minimum_trials() {
        use aegis_core::brain::recent_routes::RecentRoutesSettings;
        use aegis_core::signals::FailSignal;
        use aegis_core::TunnelTransportFamily::{GrpcStream, HttpsWs};
        let order = vec![HttpsWs, GrpcStream];
        let store = AsyncStateStore::ephemeral();
        let recent_settings = RecentRoutesSettings {
            window_ms: 60_000,
            paper_algorithm: None,
            max_observations: 64,
            diversity_penalty: 0.0,
            failure_domains: Default::default(),
        };
        let brain = Brain::new(0.0, relay_transport_order_keys(&order), store.clone())
            .with_recent_routes(Some(&recent_settings))
            .unwrap();
        let host = "relay.example.invalid";
        let dst = "203.0.113.9:443".parse().unwrap();
        let key = StrategyKey::for_target(dst, host, 443, Some(host), true);
        brain
            .record_outcome(
                &key,
                relay_transport_key(HttpsWs),
                FailSignal::Success,
                None,
                0,
                None,
            )
            .await;
        brain
            .record_outcome(
                &key,
                relay_transport_key(GrpcStream),
                FailSignal::Success,
                None,
                128,
                None,
            )
            .await;
        let settings = aegis_core::RelaySettings {
            transport_priority: order.clone(),
            policy: aegis_core::RelayPolicySettings {
                adaptive_transport: false,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(!settings.policy.adaptive_transport);
        assert!(store.snapshot().await.external_calibration.is_none());
        let trace = brain.select_order_trace(&key).await;
        assert!(trace.ranked_candidates.iter().all(|r| r.total_trials < 8.0));
        let adjusted =
            calibrated_relay_settings_for_session(&settings, &brain, &store, host, 443, dst).await;
        assert_eq!(adjusted.transport_priority, vec![GrpcStream, HttpsWs]);
        let default = Brain::new(0.0, relay_transport_order_keys(&order), store.clone());
        let unchanged =
            calibrated_relay_settings_for_session(&settings, &default, &store, host, 443, dst)
                .await;
        assert_eq!(unchanged.transport_priority, order);
    }

    #[tokio::test]
    async fn recent_relay_selection_never_reappends_hard_blocked_candidates() {
        use aegis_core::brain::recent_routes::RecentRoutesSettings;
        use aegis_core::TunnelTransportFamily::{GrpcStream, HttpsWs};
        let store = AsyncStateStore::ephemeral();
        store
            .update(|snapshot| {
                snapshot.external_calibration = Some(aegis_core::ExternalCalibrationSnapshot {
                    schema_version: 1,
                    source: "controlled_test".into(),
                    generated_at_unix_ms: None,
                    freshness_half_life_secs: None,
                    witness: Vec::new(),
                    adversarial: Vec::new(),
                    knowledge: vec![aegis_core::ExternalKnowledgePrior {
                        target_class: "https_ws".into(),
                        region_id: None,
                        score: 0.0,
                        confidence: 0.9,
                        hard_excluded: true,
                        fail_closed: true,
                        generated_at_unix_ms: None,
                    }],
                    verdict: aegis_core::ExternalCalibrationVerdict {
                        status: "MEASURED".into(),
                        acceptance_degraded: false,
                        reasons: Vec::new(),
                    },
                });
            })
            .await;
        let recent_settings = RecentRoutesSettings {
            window_ms: 60_000,
            paper_algorithm: None,
            max_observations: 64,
            diversity_penalty: 0.0,
            failure_domains: Default::default(),
        };
        let brain = Brain::new(
            1.0,
            relay_transport_order_keys(&[HttpsWs, GrpcStream]),
            store.clone(),
        )
        .with_recent_routes(Some(&recent_settings))
        .unwrap();
        let host = "relay.example.invalid";
        let dst = "203.0.113.9:443".parse().unwrap();
        let mut settings = aegis_core::RelaySettings {
            transport_priority: vec![HttpsWs, GrpcStream],
            server: "127.0.0.1:8443".into(),
            server_name: "localhost".into(),
            auth_token: "controlled_test".into(),
            ..Default::default()
        };
        assert!(relay::runtime_fallback_ready(&settings));
        let adjusted =
            calibrated_relay_settings_for_session(&settings, &brain, &store, host, 443, dst).await;
        assert_eq!(adjusted.transport_priority, vec![GrpcStream]);
        // Even an epsilon-randomized baseline and a nonempty configured order
        // cannot restore the only route when current calibration excludes it.
        settings.transport_priority = vec![HttpsWs];
        let adjusted =
            calibrated_relay_settings_for_session(&settings, &brain, &store, host, 443, dst).await;
        assert!(adjusted.transport_priority.is_empty());
        assert!(!relay::runtime_fallback_ready(&adjusted));
    }

    async fn documentation_reconciliation_calibrated_legacy_brain(
        epsilon: f64,
        confidence: Option<f64>,
    ) -> (AsyncStateStore, Brain) {
        use aegis_core::TunnelTransportFamily::{GrpcStream, HttpsWs};
        let store = AsyncStateStore::ephemeral();
        store
            .update(|snapshot| {
                snapshot.external_calibration = Some(aegis_core::ExternalCalibrationSnapshot {
                    knowledge: confidence
                        .into_iter()
                        .map(|confidence| aegis_core::ExternalKnowledgePrior {
                            target_class: "https_ws".into(),
                            score: 0.0,
                            confidence,
                            hard_excluded: true,
                            fail_closed: true,
                            ..Default::default()
                        })
                        .collect(),
                    ..Default::default()
                });
            })
            .await;
        let brain = Brain::new(
            epsilon,
            relay_transport_order_keys(&[HttpsWs, GrpcStream]),
            store.clone(),
        );
        (store, brain)
    }

    #[tokio::test]
    async fn documentation_reconciliation_legacy_calibration_never_reappends_hard_block() {
        use aegis_core::TunnelTransportFamily::{GrpcStream, HttpsWs};
        let host = "relay.example.invalid";
        let dst = "203.0.113.9:443".parse().unwrap();
        let key = StrategyKey::for_target(dst, host, 443, Some(host), true);
        for epsilon in [0.0, 1.0] {
            let (store, brain) =
                documentation_reconciliation_calibrated_legacy_brain(epsilon, Some(0.9)).await;
            let trace = brain.select_order_trace(&key).await;
            assert!(trace.recent_selection.is_none());
            assert_eq!(trace.reward_selected_order, vec!["grpc_stream"]);
            if epsilon == 1.0 {
                assert!(trace.ranked_candidates.is_empty());
            }
            let mut settings = aegis_core::RelaySettings {
                transport_priority: vec![HttpsWs, GrpcStream],
                ..Default::default()
            };
            let adjusted =
                calibrated_relay_settings_for_session(&settings, &brain, &store, host, 443, dst)
                    .await;
            assert_eq!(adjusted.transport_priority, vec![GrpcStream]);

            // The only configured family is blocked. A different family in the
            // Brain order cannot expand admission, and the omitted one stays out.
            settings.transport_priority = vec![HttpsWs];
            let adjusted =
                calibrated_relay_settings_for_session(&settings, &brain, &store, host, 443, dst)
                    .await;
            assert!(adjusted.transport_priority.is_empty());
        }
    }

    #[tokio::test]
    async fn documentation_reconciliation_legacy_soft_or_empty_calibration_keeps_families() {
        use aegis_core::TunnelTransportFamily::{GrpcStream, HttpsWs};
        let host = "relay.example.invalid";
        let dst = "203.0.113.9:443".parse().unwrap();
        let settings = aegis_core::RelaySettings {
            transport_priority: vec![HttpsWs, GrpcStream],
            ..Default::default()
        };
        for epsilon in [0.0, 1.0] {
            for confidence in [None, Some(0.84)] {
                let (store, brain) =
                    documentation_reconciliation_calibrated_legacy_brain(epsilon, confidence).await;
                let adjusted = calibrated_relay_settings_for_session(
                    &settings, &brain, &store, host, 443, dst,
                )
                .await;
                assert_eq!(adjusted.transport_priority.len(), 2);
                assert!(adjusted.transport_priority.contains(&HttpsWs));
                assert!(adjusted.transport_priority.contains(&GrpcStream));
            }
        }
    }

    #[tokio::test]
    async fn documentation_reconciliation_legacy_cold_and_epsilon_guards_keep_configured_order() {
        use aegis_core::TunnelTransportFamily::{GrpcStream, HttpsWs};
        let host = "relay.example.invalid";
        let dst = "203.0.113.9:443".parse().unwrap();
        let key = StrategyKey::for_target(dst, host, 443, Some(host), true);
        let order = vec![HttpsWs, GrpcStream];
        for (epsilon, trials) in [(0.0, 0), (1.0, 10)] {
            let store = AsyncStateStore::ephemeral();
            store
                .update(|snapshot| {
                    if trials > 0 {
                        snapshot.strategy_stats.insert(
                            format!("{}|grpc_stream", key.hash_key()),
                            aegis_core::state_v2::StrategyStatsV2 {
                                trials,
                                successes: trials,
                                fitness_score: 1.0,
                                ..Default::default()
                            },
                        );
                    }
                })
                .await;
            let brain = Brain::new(
                epsilon,
                relay_transport_order_keys(&[GrpcStream, HttpsWs]),
                store.clone(),
            );
            let trace = brain.select_order_trace(&key).await;
            if epsilon == 0.0 {
                assert_eq!(trace.reward_selected_order, vec!["grpc_stream", "https_ws"]);
                assert!(trace
                    .ranked_candidates
                    .iter()
                    .all(|candidate| candidate.total_trials < 8.0));
            } else {
                assert!(trace.ranked_candidates.is_empty());
            }
            let settings = aegis_core::RelaySettings {
                transport_priority: order.clone(),
                policy: aegis_core::RelayPolicySettings {
                    adaptive_transport: true,
                    ..Default::default()
                },
                ..Default::default()
            };
            let adjusted =
                calibrated_relay_settings_for_session(&settings, &brain, &store, host, 443, dst)
                    .await;
            assert_eq!(adjusted.transport_priority, order);
        }
    }

    // Generic UDP + QUIC carry gate: the daemon spawns the UDP redirect proxy
    // ONLY when generic capture is requested, on the explicit port else
    // listen+1. Guards the wiring that activates generic UDP/QUIC (previously
    // reachable only via the standalone subcommand, so the daemon left it
    // fail-closed).
    #[cfg(target_os = "linux")]
    #[test]
    fn udp_redirect_proxy_port_gates_on_generic_capture() {
        let mut cfg = Settings::default();
        cfg.ingress.wide.enabled = true;
        cfg.ingress.wide.listen = "127.0.0.1:15080".parse().unwrap();

        // Default contract (preview-allowlist) → proxy NOT spawned.
        cfg.ingress.wide.udp_capture_contract = WideUdpCaptureContract::PreviewAllowlistOnly;
        assert_eq!(wide_udp_redirect_proxy_port(&cfg), None);

        // Generic capture, no explicit port → derive listen+1.
        cfg.ingress.wide.udp_capture_contract = WideUdpCaptureContract::GenericCaptureUnstable;
        assert_eq!(wide_udp_redirect_proxy_port(&cfg), Some(15081));

        // Explicit port wins.
        cfg.ingress.wide.udp_redirect_port = Some(15090);
        assert_eq!(wide_udp_redirect_proxy_port(&cfg), Some(15090));

        // Wide disabled → never spawn, even with generic capture requested.
        cfg.ingress.wide.enabled = false;
        assert_eq!(wide_udp_redirect_proxy_port(&cfg), None);
    }

    // IPv6 relay-loop avoidance: a relay reached over IPv6 (literal-IPv6 server or
    // an IPv6 fronting endpoint) must be collected so the IPv6 TUN engine pins it
    // off the ::/1+8000::/1 capture. IPv4 endpoints are covered by the engine's
    // ::ffff:0:0/96 mapped exclude and must NOT appear here. Uses bracketed
    // literals so resolution is deterministic (no network / DNS).
    #[cfg(target_os = "linux")]
    #[test]
    fn relay_ipv6_excludes_collects_only_v6_endpoints() {
        use aegis_core::RelayEndpointSettings;
        let mut relay = Settings::default().relay;

        // IPv4-only primary, no endpoints → nothing to exclude (mapped range covers it).
        relay.server = "1.2.3.4:443".to_string();
        relay.endpoints = Vec::new();
        assert!(relay_ipv6_excludes(&relay).is_empty());

        // Literal-IPv6 primary → excluded.
        relay.server = "[2606:4700:4700::1111]:443".to_string();
        assert_eq!(
            relay_ipv6_excludes(&relay),
            vec![IpAddr::V6("2606:4700:4700::1111".parse().unwrap())]
        );

        // IPv4 primary + IPv6 fronting endpoint → only the v6 endpoint.
        relay.server = "1.2.3.4:443".to_string();
        relay.endpoints = vec![RelayEndpointSettings {
            server: "[2001:db8::2]:8443".to_string(),
            server_name: "example.invalid".to_string(),
            masque_server: None,
            masque_server_name: None,
        }];
        assert_eq!(
            relay_ipv6_excludes(&relay),
            vec![IpAddr::V6("2001:db8::2".parse().unwrap())]
        );
    }

    use crate::ingress::broker::{BrokeredTcpConnect, BrokeredUdpDatagram};
    use crate::ingress::{
        IngressKind, IngressResponse, IngressSessionIntent, IngressTransport, TcpConnectIntent,
        UdpAssociateIntent, UdpDatagramResponse, UdpSessionControl,
    };
    use crate::socks5::ConnectTarget;
    use aegis_core::TunnelTransportFamily;
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use serde_json::Value;
    use socket2::SockRef;
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr, TcpListener as StdTcpListener, UdpSocket as StdUdpSocket};
    use std::path::{Path, PathBuf};
    use std::sync::OnceLock;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UdpSocket;
    use tokio::sync::Mutex;
    use tokio::task::JoinHandle;

    pub(crate) static RUNTIME_JSONL_LOCK: Mutex<()> = Mutex::const_new(());
    static RUNTIME_JSONL_PATH: OnceLock<PathBuf> = OnceLock::new();

    pub(crate) fn ensure_runtime_jsonl_path() -> &'static PathBuf {
        // This shared fixture verifies detailed operator event schemas. It
        // explicitly models --diagnostic-logs; production remains private by
        // default. Privacy formatter/default tests use isolated fixtures.
        runtime_jsonl::set_private_logs(false);
        RUNTIME_JSONL_PATH.get_or_init(|| {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let path = std::env::temp_dir().join(format!("aegis-main-runtime-{unique}.jsonl"));
            runtime_jsonl::init(Some(path.clone())).expect("init runtime jsonl");
            path
        })
    }

    pub(crate) fn read_jsonl_records(path: &Path) -> Vec<Value> {
        fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("parse jsonl record"))
            .collect()
    }

    async fn wait_for_event(path: &Path, start_index: usize, event_code: &'static str) -> Value {
        wait_for_event_matching(path, start_index, event_code, |_| true).await
    }

    async fn wait_for_event_matching(
        path: &Path,
        start_index: usize,
        event_code: &'static str,
        owns: impl Fn(&Value) -> bool,
    ) -> Value {
        for _ in 0..40 {
            if let Some(record) = read_jsonl_records(path)
                .into_iter()
                .skip(start_index)
                .find(|record| record["event_code"].as_str() == Some(event_code) && owns(record))
            {
                return record;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("missing runtime event {event_code}");
    }

    async fn wait_for_udp_completed_event(
        path: &Path,
        start_index: usize,
        target_port: u16,
    ) -> Value {
        // v0.3.7: bumped 40 → 200 (10s window vs 2s) для CI runner load.
        for _ in 0..200 {
            if let Some(record) =
                read_jsonl_records(path)
                    .into_iter()
                    .skip(start_index)
                    .find(|record| {
                        record["event_code"].as_str()
                            == Some(RuntimeEventCode::IngressUdpDatagramCompleted.as_str())
                            && record["fields"]["target_port"].as_u64() == Some(target_port as u64)
                    })
            {
                return record;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("missing ingress udp datagram completed event");
    }

    async fn wait_for_udp_response_stage_event(
        path: &Path,
        start_index: usize,
        stage: &'static str,
    ) -> Value {
        // v0.3.7: bumped 40 → 200 (10s window vs 2s) для CI runner load.
        for _ in 0..200 {
            if let Some(record) =
                read_jsonl_records(path)
                    .into_iter()
                    .skip(start_index)
                    .find(|record| {
                        record["event_code"].as_str()
                            == Some(RuntimeEventCode::IngressUdpDatagramResponseStage.as_str())
                            && record["fields"]["stage"].as_str() == Some(stage)
                    })
            {
                return record;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("missing ingress udp datagram response stage event {stage}");
    }

    fn assert_no_event_after(path: &Path, start_index: usize, event_code: &str) {
        let records = read_jsonl_records(path);
        assert!(
            !records
                .iter()
                .skip(start_index)
                .any(|record| record["event_code"].as_str() == Some(event_code)),
            "unexpected runtime event {event_code}: {records:?}"
        );
    }

    #[tokio::test]
    async fn apply_external_calibration_summary_writes_direct_state() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let td = std::env::temp_dir().join(format!("aegis-calibration-apply-test-{unique}"));
        fs::create_dir_all(&td).expect("create temp dir");
        let state_path = td.join("state.json");
        let config_path = td.join("aegis.toml");
        let summary_path = td.join("external-calibration-summary.json");
        #[cfg(windows)]
        aegis_core::windows_file::write_private_new(&config_path, b"", false).unwrap();
        fs::write(
            &config_path,
            format!(
                r#"
mode = "direct"

[direct]
state_path = '{}'
"#,
                state_path.display()
            ),
        )
        .expect("write config");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        fs::write(
            &summary_path,
            r#"
{
  "event": "external_calibration_summary",
  "schema_version": 1,
  "witness": {
    "labels": [
      {
        "label": "https_ws",
        "records": 2,
        "combined_avg": 0.7,
        "ja3_present_avg": 1.0,
        "alpn_match_avg": 0.75,
        "sni_structure_avg": 0.55
      }
    ]
  },
  "adversarial": {
    "transports": [
      {
        "transport": "https_ws",
        "records": 2,
        "measured": 2,
        "planned": 0,
        "passed": 1,
        "failed": 1,
        "pass_rate": 0.5,
        "threshold": 0.85
      }
    ]
  },
  "verdict": {
    "status": "MEASURED",
    "acceptance_degraded": false,
    "reasons": []
  }
}
"#,
        )
        .expect("write summary");
        let cfg = config::load_config(&config_path).expect("load config");

        let snapshot = apply_external_calibration_summary(&cfg, &summary_path)
            .await
            .expect("apply calibration summary");

        assert_eq!(snapshot.witness[0].label, "https_ws");
        let stored = AsyncStateStore::load(state_path)
            .await
            .expect("load written state")
            .snapshot()
            .await;
        let stored_calibration = stored
            .external_calibration
            .expect("external calibration stored");
        assert_eq!(stored_calibration.witness[0].combined_avg, 0.7);
        assert_eq!(stored_calibration.adversarial[0].pass_rate, Some(0.5));
        let _ = fs::remove_dir_all(td);
    }

    async fn tcp_pair() -> (
        tokio::net::TcpStream,
        tokio::net::TcpStream,
        std::net::SocketAddr,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let client = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect client");
        let (server, peer) = listener.accept().await.expect("accept peer");
        (client, server, peer)
    }

    fn force_reset(stream: &tokio::net::TcpStream) {
        SockRef::from(stream)
            .set_linger(Some(Duration::from_secs(0)))
            .expect("set linger");
    }

    fn reserve_udp_port() -> u16 {
        StdUdpSocket::bind("127.0.0.1:0")
            .expect("bind udp port")
            .local_addr()
            .expect("udp local addr")
            .port()
    }

    async fn start_udp_echo() -> (u16, JoinHandle<()>) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind udp echo");
        let port = socket.local_addr().expect("udp echo addr").port();
        let task = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                    break;
                };
                if socket.send_to(&buf[..n], peer).await.is_err() {
                    break;
                }
            }
        });
        (port, task)
    }

    pub(crate) async fn start_local_masque_server() -> (Settings, JoinHandle<()>) {
        start_local_masque_server_with_transport(aegis_server::config::TransportConfig::default())
            .await
    }

    async fn start_local_masque_server_with_transport(
        transport: aegis_server::config::TransportConfig,
    ) -> (Settings, JoinHandle<()>) {
        start_local_masque_server_with_ports(transport, Vec::new()).await
    }

    #[cfg(all(windows, feature = "windows-host-acceptance"))]
    pub(crate) async fn start_local_masque_server_for_ports(
        ports: Vec<u16>,
    ) -> (Settings, JoinHandle<()>) {
        start_local_masque_server_with_ports(Default::default(), ports).await
    }

    async fn start_local_masque_server_with_ports(
        transport: aegis_server::config::TransportConfig,
        ports: Vec<u16>,
    ) -> (Settings, JoinHandle<()>) {
        start_local_masque_server_with_controls(transport, ports, None, None).await
    }

    async fn start_local_masque_server_with_controls(
        transport: aegis_server::config::TransportConfig,
        ports: Vec<u16>,
        witness: Option<aegis_server::phase_witness::ServerPhaseWitness>,
        shutdown: Option<tokio::sync::oneshot::Receiver<()>>,
    ) -> (Settings, JoinHandle<()>) {
        let quic_port = reserve_udp_port();
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let cert_dir = std::env::temp_dir().join(format!("aegis-client-masque-test-{unique}"));
        fs::create_dir_all(&cert_dir).expect("create cert dir");
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).expect("generate cert");
        let cert_path = cert_dir.join("cert.pem");
        let key_path = cert_dir.join("key.pem");
        fs::write(&cert_path, cert.pem()).expect("write cert");
        #[cfg(not(windows))]
        fs::write(&key_path, key_pair.serialize_pem()).expect("write key");
        #[cfg(windows)]
        aegis_core::windows_file::write_private_new(
            &key_path,
            key_pair.serialize_pem().as_bytes(),
            false,
        )
        .expect("write private Windows key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let server_cfg = aegis_server::config::ServerConfig {
            // Report the address of the actual listener; no TCP reservation
            // is released between discovering a port and binding the server.
            listen: "127.0.0.1:0".into(),
            cert: cert_path.clone(),
            key: key_path,
            auth_token: "ac99c6bf1351492d50367daf9be01fc3dfd7bc33f5b9437dbf1b1fde632b87e1".into(),
            legacy_auth_tokens: Vec::new(),
            process_alias: None,
            logging: Default::default(),
            fallback: "close".into(),
            limits: Default::default(),
            rate_limit: Default::default(),
            target_policy: aegis_server::config::TargetPolicyConfig {
                profile: aegis_server::config::TargetPolicyProfile::FullVpnEgress,
                allowed_ports: ports,
            },
            transport: aegis_server::config::TransportConfig {
                quic_listen: Some(format!("127.0.0.1:{quic_port}")),
                ..transport
            },
            bundle_endpoint: Default::default(),
        };
        // Readiness is actual bound listener state, not target reachability.
        // Tests own shutdown; no process-global signal registration is needed.
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            let stopped = async move {
                if let Some(shutdown) = shutdown {
                    let _ = shutdown.await;
                } else {
                    std::future::pending::<()>().await;
                }
            };
            let result = if let Some(witness) = witness {
                aegis_server::run_server_with_bound_ready_shutdown_and_witness(
                    server_cfg, ready_tx, stopped, witness,
                )
                .await
            } else {
                aegis_server::run_server_with_bound_ready_and_shutdown(
                    server_cfg, ready_tx, stopped,
                )
                .await
            };
            // Keep diagnostics static: do not print configuration/key material.
            assert!(result.is_ok(), "fixture server returned an error");
        });
        let mut server_owner = AbortFixtureTask::new(server_task.abort_handle());
        let bound = tokio::time::timeout(Duration::from_secs(10), ready_rx)
            .await
            .expect("fixture server did not report TCP/QUIC readiness before deadline")
            .expect("fixture server stopped before TCP/QUIC readiness");

        let mut cfg = Settings {
            mode: Mode::Relay,
            ..Settings::default()
        };
        cfg.relay.server = bound.to_string();
        cfg.relay.server_name = "localhost".into();
        cfg.relay.auth_token =
            "ac99c6bf1351492d50367daf9be01fc3dfd7bc33f5b9437dbf1b1fde632b87e1".into();
        cfg.relay.ca_cert = Some(cert_path);
        // Loopback tests must never load or update the user's real Brain cache.
        cfg.direct.state_path = cert_dir.join("state.json");
        cfg.relay.transport_priority = vec![TunnelTransportFamily::MasqueDerived];
        cfg.relay.masque_server = Some(format!("127.0.0.1:{quic_port}"));
        cfg.ingress.wide.enabled = true;
        cfg.ingress.wide.capture_dns = true;
        cfg.ingress.wide.listen = "127.0.0.1:53080".parse().expect("wide listen");
        // Transfer cancellation ownership with the returned handle. The guard
        // above still cancels startup if readiness errors or times out.
        server_owner.disarm();
        (cfg, server_task)
    }

    fn sample_ingress_context() -> IngressLateRuntimeContext {
        IngressLateRuntimeContext {
            backend_id: "socks5_fallback".into(),
            backend_runtime_id: "socks5_fallback_runtime".into(),
            backend_kind: "Socks5Fallback".into(),
            backend_kind_code: "socks5_fallback",
            requested_primary: "Wide".into(),
            requested_primary_code: "wide",
            mode: "Relay".into(),
            mode_code: "relay",
            wide_supported: Some(true),
            wide_platform_family_supported: Some(true),
            wide_runtime_readiness: Some(crate::ingress::preflight::WideRuntimeReadiness::Ready),
            rollout_profile: Some("TransparentPrivileged".into()),
            rollout_profile_code: Some("transparent_privileged"),
            prerouting_interface: Some("lo".into()),
            path_code: "wide_bind_failed_fallback_started",
            fallback_reason_code: None,
            fallback_reason: None,
            bind_error_code: Some(RuntimeProbeCode::ListenerBusy),
        }
    }

    #[tokio::test]
    async fn relay_mode_closed_local_peer_skips_transport_failure_event() {
        let _guard = RUNTIME_JSONL_LOCK.lock().await;
        let path = ensure_runtime_jsonl_path();
        std::fs::write(path, "").expect("clear runtime jsonl");
        let start_index = read_jsonl_records(path).len();

        let (peer, local, _addr) = tcp_pair().await;
        drop(peer);

        let mut cfg = Settings {
            mode: Mode::Relay,
            ..Settings::default()
        };
        cfg.relay.server = "127.0.0.1:1".into();
        cfg.relay.server_name = "localhost".into();
        cfg.relay.auth_token = "token".into();
        cfg.relay.transport_priority = vec![TunnelTransportFamily::LegacyTls];
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let state_dir = std::env::temp_dir().join(format!("aegis-relay-context-test-{unique}"));
        fs::create_dir_all(&state_dir).expect("create relay context test state dir");
        cfg.direct.state_path = state_dir.join("state.json");

        // Build the relay context through the same path as production so tests
        // keep Brain/store wiring in sync with runtime behavior.
        RuntimeContext::from_settings(&cfg)
            .await
            .expect("relay runtime context")
            .handle_session(
                BrokeredSession::TcpConnect(BrokeredTcpConnect {
                    ingress_kind: IngressKind::WidePrimary,
                    client: local,
                    target: ConnectTarget {
                        host: "127.0.0.1".into(),
                        port: 443,
                    },
                    dst: "127.0.0.1:443".parse().expect("target socket addr"),
                }),
                &cfg,
                sample_ingress_context(),
            )
            .await
            .expect("closed local peer should not trigger relay transport failure");

        assert_no_event_after(path, start_index, "relay_transport_failed");
        assert_no_event_after(path, start_index, "relay_session_succeeded");
        assert_no_event_after(path, start_index, "relay_failover_recovery_observed");
        assert_no_event_after(path, start_index, "wide_capture_flow_succeeded");
        assert_no_event_after(path, start_index, "wide_capture_flow_failed");
        let completion = wait_for_event(path, start_index, "wide_capture_flow_completed").await;
        assert_eq!(
            completion["fields"]["completion_reason"],
            "no_attempt_observed"
        );
        assert_eq!(completion["fields"]["transfer_result"], "ok");
        assert_eq!(completion["fields"]["application_response_observed"], false);
    }

    #[tokio::test]
    async fn wide_tcp_terminal_events_use_only_terminal_response_evidence() {
        use aegis_core::signals::FailSignal;

        let _guard = RUNTIME_JSONL_LOCK.lock().await;
        let path = ensure_runtime_jsonl_path();
        let outcome = |signal, bytes_received_observed| relay::RelayOutcome {
            transport: TunnelTransportFamily::GrpcStream,
            signal,
            learning: relay::RelayLearningDisposition::Recordable,
            bytes_sent: 7,
            bytes_received_observed,
            timing: relay::RelayAttemptTiming {
                attempt_duration: std::time::Duration::from_millis(1),
                ..Default::default()
            },
        };
        let response = outcome(FailSignal::Success, 9);
        let no_response = outcome(
            FailSignal::SessionFreeze {
                bytes_before_stall: 7,
            },
            0,
        );
        let partial_error = outcome(FailSignal::RemoteReset, 9);
        let cases = [
            (Ok(()), None, "wide_capture_flow_completed", false),
            (
                Ok(()),
                Some(&no_response),
                "wide_capture_flow_completed",
                false,
            ),
            (Ok(()), Some(&response), "wide_capture_flow_succeeded", true),
            (
                Err(anyhow::anyhow!("fixture failure after response")),
                Some(&partial_error),
                "wide_capture_flow_failed",
                true,
            ),
        ];
        for (result, terminal, code, observed) in cases {
            let start = read_jsonl_records(path).len();
            emit_wide_tcp_terminal("a03-terminal-fixture", &result, terminal);
            let records = read_jsonl_records(path);
            let records = &records[start..];
            assert_eq!(records.len(), 1);
            assert_eq!(records[0]["event_code"], code);
            assert_eq!(
                records[0]["fields"]["application_response_observed"],
                observed
            );
            assert_eq!(
                records[0]["fields"]["ok"],
                code == "wide_capture_flow_succeeded"
            );
        }
        // Main retains the last channel item; earlier response evidence must
        // not override a later terminal completion without a response.
        let outcomes = [response, no_response];
        assert_eq!(
            relay::RelayTcpCompletion::from_result(&Ok(()), outcomes.last()),
            relay::RelayTcpCompletion::NoResponseObserved
        );
    }

    #[tokio::test]
    async fn windows_tcp_terminal_events_require_response_and_keep_egress_unknown() {
        use aegis_core::signals::FailSignal;

        let _guard = RUNTIME_JSONL_LOCK.lock().await;
        let path = ensure_runtime_jsonl_path();
        let empty = relay::RelayOutcome {
            transport: TunnelTransportFamily::GrpcStream,
            signal: FailSignal::Unknown,
            learning: relay::RelayLearningDisposition::NoApplicationTraffic,
            bytes_sent: 0,
            bytes_received_observed: 0,
            timing: relay::RelayAttemptTiming {
                attempt_duration: std::time::Duration::from_millis(1),
                ..Default::default()
            },
        };
        let response = relay::RelayOutcome {
            signal: FailSignal::Success,
            learning: relay::RelayLearningDisposition::Recordable,
            bytes_received_observed: 9,
            ..empty.clone()
        };
        for terminal in [None, Some(&empty), Some(&response)] {
            let start = read_jsonl_records(path).len();
            windows_event_fixture::relay_session_terminal("a03-relay-fixture", &Ok(()), terminal);
            let records = read_jsonl_records(path);
            let records = &records[start..];
            let success = terminal.is_some_and(|outcome| outcome.bytes_received_observed > 0);
            assert_eq!(records.len(), if success { 2 } else { 1 });
            assert_eq!(records[0]["fields"]["relay_egress_ip"], Value::Null);
            assert_eq!(
                records[0]["fields"]["application_response_observed"],
                success
            );
            assert_eq!(
                records[0]["event_code"],
                if success {
                    "windows_wide_relay_session_succeeded"
                } else {
                    "windows_wide_relay_session_completed"
                }
            );
            if success {
                assert_eq!(records[1]["event_code"], "windows_wide_flow_closed");
                assert_eq!(records[1]["fields"]["result"], "ok");
            }
        }
        let start = read_jsonl_records(path).len();
        windows_event_fixture::relay_session_terminal(
            "a03-relay-fixture",
            &Err(anyhow::anyhow!("partial fixture failure")),
            Some(&response),
        );
        assert_eq!(read_jsonl_records(path).len(), start);
    }

    fn fixture_relay_attempt_diagnostics(path: &std::path::Path, start: usize) -> Vec<Value> {
        read_jsonl_records(path)
            .into_iter()
            .skip(start)
            .filter(|record| {
                record["event_code"].as_str().is_some_and(|code| {
                    matches!(code, "relay_transport_selected" | "relay_transport_failed")
                })
            })
            .take(8)
            .map(|record| {
                serde_json::json!({
                    "event_code": record["event_code"],
                    "attempt_index": record["fields"]["attempt_index"],
                    "attempts_total": record["fields"]["attempts_total"],
                    "relay_server": record["fields"]["relay_server"],
                    "transport": record["fields"]["transport"],
                    "relay_error_kind": record["fields"]["relay_error_kind"],
                    "relay_failure_scope": record["fields"]["relay_failure_scope"],
                })
            })
            .collect()
    }

    /// Panic/cancellation owns the exact task; a JoinHandle alone detaches.
    struct AbortFixtureTask(Option<tokio::task::AbortHandle>);
    impl AbortFixtureTask {
        fn new(handle: tokio::task::AbortHandle) -> Self {
            Self(Some(handle))
        }
        fn disarm(&mut self) {
            self.0.take();
        }
    }
    impl Drop for AbortFixtureTask {
        fn drop(&mut self) {
            if let Some(handle) = self.0.take() {
                handle.abort();
            }
        }
    }

    // Match custody fixed before dialing, never the expected outcome or transport.
    // Relay events split host/port; the wide terminal event uses SocketAddr text.
    fn event_targets_socket(record: &Value, target: SocketAddr) -> bool {
        let fields = &record["fields"];
        fields["target"]
            .as_str()
            .and_then(|s| s.parse::<SocketAddr>().ok())
            == Some(target)
            || (fields["target"].as_str() == Some(target.ip().to_string().as_str())
                && fields["port"].as_u64() == Some(u64::from(target.port())))
    }

    async fn reserve_fixture_target() -> (Arc<tokio::net::TcpListener>, UdpSocket) {
        // JSONL target fields do not universally carry the L4 protocol. Keep
        // both namespaces owned. A TCP-selected ephemeral port may be denied
        // for UDP on Windows; the bounded fixture allocator retries it.
        let (tcp, udp) = fixture_ports::reserve_dual_protocol_target()
            .expect("reserve bounded dual-protocol fixture target");
        tcp.set_nonblocking(true).unwrap();
        udp.set_nonblocking(true).unwrap();
        (
            Arc::new(tokio::net::TcpListener::from_std(tcp).unwrap()),
            UdpSocket::from_std(udp).unwrap(),
        )
    }

    struct UnrelatedUdpEventFixture {
        settings: aegis_core::RelaySettings,
        target_port: u16,
        _server: AbortFixtureTask,
        _echo: AbortFixtureTask,
        refused: socket2::Socket,
        refused_address: SocketAddr,
    }

    impl UnrelatedUdpEventFixture {
        async fn new() -> Self {
            let (mut cfg, server) = start_local_masque_server().await;
            let server_owner = AbortFixtureTask::new(server.abort_handle());
            let (target_port, echo) = start_udp_echo().await;
            let echo_owner = AbortFixtureTask::new(echo.abort_handle());
            cfg.relay.udp_transport_priority = Some(vec![TunnelTransportFamily::GrpcDatagram]);
            cfg.relay.policy.adaptive_transport = false;
            cfg.relay.policy.rotate_transports_per_session = false;
            cfg.relay.connect_timeout_ms = 5_000;
            let refused = socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )
            .expect("create unrelated refusing fixture");
            refused
                .bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
                .unwrap();
            let refused_address = refused.local_addr().unwrap().as_socket().unwrap();
            Self {
                settings: cfg.relay,
                target_port,
                _server: server_owner,
                _echo: echo_owner,
                refused,
                refused_address,
            }
        }

        async fn exercise(&self) {
            tokio::time::timeout(Duration::from_secs(20), async {
                let target = || ConnectTarget {
                    host: "127.0.0.1".into(),
                    port: self.target_port,
                };
                let mut failed = self.settings.clone();
                failed.server = self.refused_address.to_string();
                failed.endpoints.clear();
                assert!(
                    relay::run_relay_udp_datagram_once(&failed, target(), b"unrelated-refusal")
                        .await
                        .is_err(),
                    "the actually bound non-listening endpoint must fail"
                );
                assert_eq!(
                    self.refused.local_addr().unwrap().as_socket(),
                    Some(self.refused_address)
                );
                let response = relay::run_relay_udp_datagram_once(
                    &self.settings,
                    target(),
                    b"unrelated-authenticated-echo",
                )
                .await
                .expect("independent authenticated UDP echo");
                assert_eq!(response, b"unrelated-authenticated-echo");
            })
            .await
            .expect("unrelated fixture exceeded its own bounded budget");
        }

        fn assert_both_outcomes(&self, records: &[Value]) {
            for (code, server) in [
                ("relay_transport_failed", self.refused_address.to_string()),
                ("relay_session_succeeded", self.settings.server.clone()),
            ] {
                assert!(
                    records.iter().any(|r| r["event_code"] == code
                        && r["fields"]["relay_server"].as_str() == Some(server.as_str())
                        && r["fields"]["port"].as_u64() == Some(u64::from(self.target_port))),
                    "actual unrelated {code} evidence missing"
                );
            }
        }
    }

    #[cfg(feature = "legacy-challenge-v1")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wide_no_response_grpc_carrier_is_refused_before_dial_in_raw_mode() {
        let _guard = RUNTIME_JSONL_LOCK.lock().await;
        let relay_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let target_listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        for listener in [&relay_listener, &target_listener] {
            listener.set_nonblocking(true).unwrap();
        }
        let masque_socket = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        masque_socket.set_nonblocking(true).unwrap();
        let mut cfg = Settings {
            mode: Mode::Relay,
            ..Settings::default()
        };
        cfg.relay.server = relay_listener.local_addr().unwrap().to_string();
        cfg.relay.masque_server = Some(masque_socket.local_addr().unwrap().to_string());
        cfg.relay.transport_priority = vec![TunnelTransportFamily::GrpcStream];
        cfg.relay.policy.adaptive_transport = false;
        cfg.relay.policy.rotate_transports_per_session = false;
        let (_application_client, local, _peer) = tcp_pair().await;
        let (outcome_tx, mut outcome_rx) = tokio::sync::mpsc::unbounded_channel();
        let error = tokio::time::timeout(
            Duration::from_secs(15),
            relay::run_relay_tunnel(
                local,
                &cfg.relay,
                "127.0.0.1".into(),
                target_listener.local_addr().unwrap().port(),
                Some(b"refusal-control"),
                None,
                Some(&outcome_tx),
            ),
        )
        .await
        .expect("bounded gRPC carrier admission")
        .expect_err("raw challenge mode must refuse the gRPC carrier");
        assert_eq!(error.to_string(), "legacy-challenge-v1 requires a raw legacy_tls-only TCP transport order; downgrade is refused");
        for listener in [&relay_listener, &target_listener] {
            assert!(
                matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
                "feature refusal must precede relay and target dialing"
            );
        }
        let mut packet = [0u8; 1];
        assert!(
            matches!(masque_socket.recv_from(&mut packet), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
            "feature refusal must precede QUIC dialing"
        );
        assert!(
            matches!(
                outcome_rx.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ),
            "pre-dial refusal must not invent a transport outcome"
        );
    }

    async fn assert_wide_tcp_no_response_is_neutral(
        payload: &'static [u8],
        failover: bool,
        unrelated_events: bool,
    ) {
        let _guard = RUNTIME_JSONL_LOCK.lock().await;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let path = ensure_runtime_jsonl_path();
        let start = read_jsonl_records(path).len();
        // Native trust enumeration belongs to fixture preparation, before
        // the network-stage watchdog (as in the transport lifecycle tests).
        relay::load_roots(None).expect("prepare native trust");
        let witness = aegis_server::phase_witness::ServerPhaseWitness::default();
        let run_witness = witness.clone();
        // Keep TCP and UDP ownership until all journal assertions finish.
        let (target_listener, _target_udp_reservation) = reserve_fixture_target().await;
        let target_addr = target_listener
            .local_addr()
            .expect("fixture target address");
        let unrelated = if unrelated_events {
            Some(UnrelatedUdpEventFixture::new().await)
        } else {
            None
        };
        let own_flow = tokio::time::timeout(Duration::from_secs(20), async {
            let (stop_server, stopped) = tokio::sync::oneshot::channel();
            let (mut cfg, server_task) = start_local_masque_server_with_controls(
                Default::default(),
                Vec::new(),
                Some(run_witness.clone()),
                Some(stopped),
            )
            .await;
            let _server_owner = AbortFixtureTask::new(server_task.abort_handle());
            // Fresh legacy mode admits only the raw carrier. Both feature
            // variants still reach the actual owned target and preserve the
            // same no-response completion, telemetry and Brain assertions.
            #[cfg(feature = "legacy-challenge-v1")]
            {
                cfg.relay.transport_priority = vec![TunnelTransportFamily::LegacyTls];
            }
            #[cfg(not(feature = "legacy-challenge-v1"))]
            {
                cfg.relay.transport_priority = vec![TunnelTransportFamily::GrpcStream];
            }
            cfg.relay.tls_backend = aegis_core::RelayTlsBackend::Rustls;
            cfg.relay.policy.adaptive_transport = false;
            cfg.relay.policy.rotate_transports_per_session = false;
            cfg.relay.policy.max_transport_attempts = 1;
            // This is a telemetry/replay test, not a startup benchmark. Native
            // trust-store loading can be cold on the first test in a process.
            cfg.relay.connect_timeout_ms = 10_000;
            let refused_socket = if failover {
                // Bind without listening, retaining ownership throughout the
                // attempt. Dropping a listener before dialing leaves this port
                // available for another fixture or the dial's own source port.
                let refused = socket2::Socket::new(
                    socket2::Domain::IPV4,
                    socket2::Type::STREAM,
                    Some(socket2::Protocol::TCP),
                )
                .expect("create refused fixture socket");
                refused
                    .bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
                    .expect("reserve refused fixture endpoint without listen");
                let refused_address = refused
                    .local_addr()
                    .expect("refused fixture address")
                    .as_socket()
                    .expect("refused fixture IP address");
                cfg.relay.endpoints = vec![
                    aegis_core::RelayEndpointSettings {
                        server: refused_address.to_string(),
                        server_name: "localhost".into(),
                        masque_server: None,
                        masque_server_name: None,
                    },
                    aegis_core::RelayEndpointSettings {
                        server: cfg.relay.server.clone(),
                        server_name: cfg.relay.server_name.clone(),
                        masque_server: None,
                        masque_server_name: None,
                    },
                ];
                Some(refused)
            } else {
                None
            };
            let store = AsyncStateStore::ephemeral();
            let brain_before = serde_json::to_value(store.snapshot().await)
                .expect("serialize complete pre-session Brain snapshot");
            let runtime = RuntimeContext::Relay {
                brain: Arc::new(Brain::new(
                    0.0,
                    relay_transport_order_keys(&cfg.relay.transport_priority),
                    store.clone(),
                )),
                store: store.clone(),
            };
            let target_listener = target_listener.clone();
            let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
            let target_task = tokio::spawn(async move {
                let (mut target, _) = target_listener
                    .accept()
                    .await
                    .expect("fixture target accept");
                let mut received = vec![0; payload.len()];
                target
                    .read_exact(&mut received)
                    .await
                    .expect("fixture request");
                assert_eq!(received, payload, "application request must arrive once");
                accepted_tx.send(()).expect("fixture target stage receiver");
                target
                    .shutdown()
                    .await
                    .expect("fixture target EOF without response");
            });
            let _target_owner = AbortFixtureTask::new(target_task.abort_handle());
            let (mut peer, local, _) = tcp_pair().await;
            let mut session = tokio::spawn(async move {
                runtime
                    .handle_session(
                        BrokeredSession::TcpConnect(BrokeredTcpConnect {
                            ingress_kind: IngressKind::WidePrimary,
                            client: local,
                            target: ConnectTarget {
                                host: "127.0.0.1".into(),
                                port: target_addr.port(),
                            },
                            dst: target_addr,
                        }),
                        &cfg,
                        sample_wide_primary_ingress_context("a03-loopback"),
                    )
                    .await
            });
            let _session_owner = AbortFixtureTask::new(session.abort_handle());
            peer.write_all(payload).await.expect("fixture app request");
            // Do not half-close until an actual relay attempt reaches the
            // target; otherwise a zero-byte case could only test pre-open abort.
            tokio::select! {
                // If acceptance and neutral completion are both ready, the
                // explicit target evidence must win over completion ordering.
                biased;
                accepted = accepted_rx => accepted.expect("fixture target was reached"),
                result = &mut session => {
                    let attempts = fixture_relay_attempt_diagnostics(path, start);
                    panic!("session ended before target acceptance: {result:?}; fixture_server_finished={}; server_phases={:?}; server_transport={:?}; attempts={attempts:?}",
                        server_task.is_finished(), run_witness.snapshot(), run_witness.transport_snapshot());
                },
            }
            peer.shutdown().await.expect("fixture app half-close");
            session
                .await
                .expect("fixture session task")
                .expect("no-response completion keeps its original Ok result");
            target_task.await.expect("fixture target task");
            drop(refused_socket);
            let _ = stop_server.send(());
            server_task
                .await
                .expect("fixture server joined after owned shutdown");
            let phases = run_witness.snapshot();
            #[cfg(feature = "legacy-challenge-v1")]
            let expected_phases = &["tcp_accepted", "outer_tls_accepted"][..];
            #[cfg(not(feature = "legacy-challenge-v1"))]
            let expected_phases = &[
                "tcp_accepted",
                "outer_tls_accepted",
                "h2_established",
                "h2_request_received",
                "grpc_open_received",
                "grpc_open_validated",
                "grpc_response_headers_queued",
                "target_dial_started",
                "tcp_session_finished",
            ][..];
            for &code in expected_phases {
                assert_eq!(
                    phases
                        .iter()
                        .find(|p| p.phase == code)
                        .unwrap()
                        .observations,
                    1,
                    "one admitted connection/request must witness {code}: {phases:?}"
                );
            }
            let snapshot = store.snapshot().await;
            if payload.is_empty() {
                assert!(!failover, "empty-session control has no failed attempt");
                assert_eq!(
                    serde_json::to_value(&snapshot).expect("serialize complete post-session Brain"),
                    brain_before,
                    "clean zero-byte completion must leave every Brain field unchanged"
                );
            } else {
                assert_eq!(snapshot.strategy_stats.len(), 1);
                let stats = snapshot
                    .strategy_stats
                    .values()
                    .next()
                    .expect("one Brain outcome");
                assert_eq!(
                    stats.trials,
                    if failover { 2 } else { 1 },
                    "neutral completion must not add a retry/replay"
                );
                assert_eq!(stats.successes, 0);
                let expected = aegis_core::signals::FailSignal::SessionFreeze {
                    bytes_before_stall: payload.len(),
                };
                assert_eq!(stats.last_signal.as_ref(), Some(&expected));
            }
        });
        if let Some(unrelated) = &unrelated {
            let (own, ()) = tokio::join!(own_flow, unrelated.exercise());
            own.unwrap_or_else(|_| {
                panic!(
                    "bounded no-response fixture expired; server_phases={:?}",
                    witness.snapshot()
                )
            });
        } else {
            own_flow.await.unwrap_or_else(|_| {
                panic!(
                    "bounded no-response fixture expired; server_phases={:?}",
                    witness.snapshot()
                )
            });
        }
        let all_records = read_jsonl_records(path);
        if let Some(unrelated) = &unrelated {
            unrelated.assert_both_outcomes(&all_records[start..]);
        }
        let records: Vec<_> = all_records
            .into_iter()
            .skip(start)
            .filter(|record| event_targets_socket(record, target_addr))
            .collect();
        for code in [
            "relay_session_succeeded",
            "relay_failover_recovery_observed",
            "wide_capture_flow_succeeded",
            "wide_capture_flow_failed",
        ] {
            assert!(
                !records.iter().any(|record| record["event_code"] == code),
                "unexpected {code}"
            );
        }
        assert_eq!(
            records
                .iter()
                .filter(|record| record["event_code"] == "relay_transport_failed")
                .count(),
            usize::from(failover)
        );
        for code in ["relay_session_completed", "wide_capture_flow_completed"] {
            let matching: Vec<_> = records
                .iter()
                .filter(|record| record["event_code"] == code)
                .collect();
            assert_eq!(matching.len(), 1);
            assert_eq!(
                matching[0]["fields"]["completion_reason"],
                "no_response_observed"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wide_no_response_event_custody_survives_actual_parallel_udp_outcomes() {
        assert_wide_tcp_no_response_is_neutral(b"a03-owned-request", true, true).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn no_response_fixture_witness_separates_tls_h2_preface_and_open() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let witness = aegis_server::phase_witness::ServerPhaseWitness::default();
        tokio::time::timeout(Duration::from_secs(20), async {
            let (stop_server, stopped) = tokio::sync::oneshot::channel();
            let (cfg, server) = start_local_masque_server_with_controls(
                Default::default(),
                Vec::new(),
                Some(witness.clone()),
                Some(stopped),
            )
            .await;
            let _server_owner = AbortFixtureTask::new(server.abort_handle());
            let connector =
                relay::tls_connector(cfg.relay.ca_cert.as_deref(), Some(b"h2"), true).unwrap();
            let tcp = tokio::net::TcpStream::connect(&cfg.relay.server)
                .await
                .unwrap();
            let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
            let mut tls = connector.connect(name, tcp).await.unwrap();
            let reached = |code: &'static str| {
                let witness = witness.clone();
                async move {
                    tokio::time::timeout(Duration::from_secs(2), async {
                        while !witness
                            .snapshot()
                            .iter()
                            .any(|p| p.phase == code && p.observations == 1)
                        {
                            tokio::time::sleep(Duration::from_millis(5)).await;
                        }
                    })
                    .await
                    .unwrap_or_else(|_| {
                        panic!(
                            "fixture phase {code} not witnessed: {:?}",
                            witness.snapshot()
                        )
                    });
                }
            };
            reached("outer_tls_accepted").await;
            tls.write_all(b"PRI ").await.unwrap();
            tls.flush().await.unwrap();
            assert_eq!(
                witness
                    .snapshot()
                    .iter()
                    .find(|p| p.phase == "h2_established")
                    .unwrap()
                    .observations,
                0,
                "a partial preface must not infer H2 admission"
            );
            tls.write_all(b"* HTTP/2.0\r\n\r\nSM\r\n\r\n")
                .await
                .unwrap();
            tls.flush().await.unwrap();
            reached("h2_established").await;
            for code in [
                "h2_request_received",
                "grpc_open_received",
                "grpc_open_validated",
                "target_dial_started",
            ] {
                assert_eq!(
                    witness
                        .snapshot()
                        .iter()
                        .find(|p| p.phase == code)
                        .unwrap()
                        .observations,
                    0,
                    "preface completion must not infer {code}"
                );
            }
            drop(tls);
            let _ = stop_server.send(());
            server.await.expect("owned witness fixture server joined");
            assert_eq!(
                witness
                    .snapshot()
                    .iter()
                    .find(|p| p.phase == "tcp_session_finished")
                    .unwrap()
                    .observations,
                1
            );
        })
        .await
        .unwrap_or_else(|_| panic!("owned phase fixture expired: {:?}", witness.snapshot()));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn no_response_fixture_timeout_cancels_owned_listener_and_preserves_foreign_listener() {
        let owned_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let owned_address = owned_listener.local_addr().unwrap();
        let foreign = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let foreign_address = foreign.local_addr().unwrap();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _listener = owned_listener;
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        started_rx.await.unwrap();
        let owner = AbortFixtureTask::new(task.abort_handle());
        assert!(tokio::time::timeout(Duration::from_millis(20), async move {
            let _owner = owner;
            std::future::pending::<()>().await;
        })
        .await
        .is_err());
        assert!(tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap_err()
            .is_cancelled());
        let rebound = tokio::net::TcpListener::bind(owned_address)
            .await
            .expect("joined cancellation must release exactly the fixture listener");
        assert_eq!(
            tokio::net::TcpListener::bind(foreign_address)
                .await
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::AddrInUse
        );
        drop(rebound);
        drop(foreign);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wide_tcp_zero_byte_close_completes_neutrally() {
        assert_wide_tcp_no_response_is_neutral(b"", false, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wide_tcp_request_without_response_completes_neutrally_without_retry() {
        assert_wide_tcp_no_response_is_neutral(b"a03-request", false, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wide_tcp_failover_without_response_does_not_claim_recovery() {
        assert_wide_tcp_no_response_is_neutral(b"a03-request", true, false).await;
    }

    fn sample_wide_primary_ingress_context(
        prerouting_interface: &str,
    ) -> IngressLateRuntimeContext {
        IngressLateRuntimeContext {
            backend_id: "wide_primary".into(),
            backend_runtime_id: "wide_primary_linux".into(),
            backend_kind: "WidePrimary".into(),
            backend_kind_code: "wide_primary",
            requested_primary: "Wide".into(),
            requested_primary_code: "wide",
            mode: "Relay".into(),
            mode_code: "relay",
            wide_supported: Some(true),
            wide_platform_family_supported: Some(true),
            wide_runtime_readiness: Some(crate::ingress::preflight::WideRuntimeReadiness::Ready),
            rollout_profile: Some("TransparentPrivileged".into()),
            rollout_profile_code: Some("transparent_privileged"),
            prerouting_interface: Some(prerouting_interface.into()),
            path_code: "wide_primary_started",
            fallback_reason_code: None,
            fallback_reason: None,
            bind_error_code: None,
        }
    }

    #[test]
    fn active_wide_udp_event_surface_is_empty_for_fallback_backend() {
        let mut cfg = Settings::default();
        cfg.ingress.wide.enabled = true;
        cfg.ingress.wide.capture_dns = true;
        cfg.ingress.wide.listen = "127.0.0.1:53080".parse().expect("wide listen");
        cfg.ingress.wide.dns_port = 53;
        cfg.ingress.wide.udp_preview_ports = vec![5300];

        let surface = active_wide_udp_event_surface(&cfg, "socks5_fallback", 53);
        assert_eq!(
            surface,
            ActiveWideUdpEventSurface {
                capture_contract: None,
                capture_support_tier: None,
                capture_policy: None,
                capture_runtime_scope: None,
                capture_match_kind: None,
                capture_accept_reason_code: None,
                preview_policy: None,
                preview_match_kind: None,
                preview_accept_reason_code: None,
                preview_ports: Vec::new(),
            }
        );
    }

    #[test]
    fn active_wide_udp_event_surface_keeps_wide_preview_fields_for_wide_backend() {
        let mut cfg = Settings::default();
        cfg.ingress.wide.enabled = true;
        cfg.ingress.wide.capture_dns = true;
        cfg.ingress.wide.listen = "127.0.0.1:53080".parse().expect("wide listen");
        cfg.ingress.wide.dns_port = 53;
        cfg.ingress.wide.udp_preview_ports = vec![5300];

        let surface = active_wide_udp_event_surface(&cfg, "wide_primary", 53);
        assert_eq!(surface.capture_contract, Some("preview_allowlist_only"));
        assert_eq!(surface.capture_support_tier, Some("supported_preview"));
        assert_eq!(surface.capture_policy, Some("allowlist_ports"));
        assert_eq!(surface.capture_runtime_scope, Some("linux_ipv4_only"));
        assert_eq!(surface.capture_match_kind, Some("dns_port"));
        assert_eq!(
            surface.capture_accept_reason_code,
            Some("matched_dns_port_allowlist")
        );
        assert_eq!(surface.preview_policy, Some("allowlist_ports"));
        assert_eq!(surface.preview_match_kind, Some("dns_port"));
        assert_eq!(
            surface.preview_accept_reason_code,
            Some("matched_dns_port_allowlist")
        );
        assert_eq!(surface.preview_ports, vec![53, 5300]);
    }

    // Regression for the former MASQUE UDP flake: client/server path pools
    // must agree, and CONNECT-UDP streams must stay open as datagram anchors.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn relay_udp_datagram_completed_keeps_passed_startup_context() {
        let _runtime_lock = RUNTIME_JSONL_LOCK.lock().await;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let jsonl_path = ensure_runtime_jsonl_path().clone();
        let start_index = read_jsonl_records(&jsonl_path).len();
        let (cfg, server_task) = start_local_masque_server().await;
        let (target_port, udp_echo_task) = start_udp_echo().await;
        let runtime = RuntimeContext::from_settings(&cfg)
            .await
            .expect("build runtime context");
        let payload = b"runtime-udp-context".to_vec();

        let result = runtime
            .handle_session(
                BrokeredSession::UdpDatagram(BrokeredUdpDatagram {
                    ingress_kind: IngressKind::WidePrimary,
                    control: UdpSessionControl::Detached,
                    client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    target: ConnectTarget {
                        host: "127.0.0.1".into(),
                        port: target_port,
                    },
                    payload: payload.clone(),
                    response: UdpDatagramResponse::Detached,
                }),
                &cfg,
                sample_ingress_context(),
            )
            .await;

        udp_echo_task.abort();
        server_task.abort();
        result.expect("udp datagram relay");

        let record = wait_for_udp_completed_event(&jsonl_path, start_index, target_port).await;
        let fields = &record["fields"];
        assert_eq!(fields["backend_kind_code"], "socks5_fallback");
        assert_eq!(fields["requested_primary_code"], "wide");
        assert_eq!(fields["mode_code"], "relay");
        assert_eq!(fields["rollout_profile_code"], "transparent_privileged");
        assert_eq!(
            fields["startup_path_code"],
            "wide_bind_failed_fallback_started"
        );
        assert_eq!(fields["startup_bind_error_code"], "listener_busy");
        assert_eq!(fields["prerouting_interface"], "lo");
        assert_eq!(fields["target_host"], "127.0.0.1");
        assert_eq!(fields["target_port"].as_u64(), Some(target_port as u64));
        assert_eq!(fields["response_action"], "detached");
        assert_eq!(fields["response_len"].as_u64(), Some(payload.len() as u64));
        assert_eq!(fields["wide_udp_capture_contract"], Value::Null);
        assert_eq!(fields["wide_udp_capture_support_tier"], Value::Null);
        assert_eq!(fields["wide_udp_capture_policy"], Value::Null);
        assert_eq!(fields["wide_udp_capture_runtime_scope"], Value::Null);
        assert_eq!(fields["wide_udp_capture_match_kind"], Value::Null);
        assert_eq!(fields["wide_udp_capture_accept_reason_code"], Value::Null);
        assert_eq!(fields["wide_udp_preview_policy"], Value::Null);
        assert_eq!(fields["wide_udp_preview_match_kind"], Value::Null);
        assert_eq!(fields["wide_udp_preview_accept_reason_code"], Value::Null);
        assert_eq!(fields["wide_udp_preview_ports"], json!([]));
    }

    // Regression for preview-allowlist local UDP response delivery over CONNECT-UDP.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wide_primary_udp_datagram_local_response_completes_product_path() {
        let _runtime_lock = RUNTIME_JSONL_LOCK.lock().await;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let jsonl_path = ensure_runtime_jsonl_path().clone();
        let start_index = read_jsonl_records(&jsonl_path).len();
        let (mut cfg, server_task) = start_local_masque_server().await;
        let (target_port, udp_echo_task) = start_udp_echo().await;
        cfg.ingress.wide.udp_preview_ports = vec![target_port];
        let runtime = RuntimeContext::from_settings(&cfg)
            .await
            .expect("build runtime context");
        let payload = b"wide-primary-product-path".to_vec();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("bind receiver");
        let receiver_addr = receiver.local_addr().expect("receiver addr");
        let recv_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 256];
            let (n, peer) = receiver
                .recv_from(&mut buf)
                .await
                .expect("receive udp response");
            (buf[..n].to_vec(), peer)
        });
        let response_socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind response socket");
        response_socket
            .connect(receiver_addr)
            .await
            .expect("connect response socket");

        let result = runtime
            .handle_session(
                BrokeredSession::UdpDatagram(BrokeredUdpDatagram {
                    ingress_kind: IngressKind::WidePrimary,
                    control: UdpSessionControl::Detached,
                    client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    target: ConnectTarget {
                        host: "127.0.0.1".into(),
                        port: target_port,
                    },
                    payload: payload.clone(),
                    response: UdpDatagramResponse::LocalUdp {
                        socket: response_socket,
                        peer: receiver_addr,
                    },
                }),
                &cfg,
                sample_wide_primary_ingress_context("aegisvh-product"),
            )
            .await;

        let (response, response_peer) = tokio::time::timeout(Duration::from_secs(30), recv_task)
            .await
            .expect("udp response timeout")
            .expect("udp recv task");
        udp_echo_task.abort();
        server_task.abort();
        result.expect("wide primary udp datagram relay");

        assert_eq!(response, payload);
        assert!(response_peer.ip().is_ipv4());

        let completed = wait_for_udp_completed_event(&jsonl_path, start_index, target_port).await;
        let response_stage =
            wait_for_udp_response_stage_event(&jsonl_path, start_index, "local_udp_send_done")
                .await;
        let fields = &completed["fields"];
        assert_eq!(fields["backend"], "wide_primary");
        assert_eq!(fields["backend_runtime_id"], "wide_primary_linux");
        assert_eq!(fields["backend_kind_code"], "wide_primary");
        assert_eq!(fields["requested_primary_code"], "wide");
        assert_eq!(fields["mode_code"], "relay");
        assert_eq!(fields["rollout_profile_code"], "transparent_privileged");
        assert_eq!(fields["prerouting_interface"], "aegisvh-product");
        assert_eq!(fields["startup_path_code"], "wide_primary_started");
        assert_eq!(fields["startup_bind_error_code"], Value::Null);
        assert_eq!(fields["target_host"], "127.0.0.1");
        assert_eq!(fields["target_port"].as_u64(), Some(target_port as u64));
        assert_eq!(fields["response_action"], "local_udp");
        assert_eq!(fields["response_len"].as_u64(), Some(payload.len() as u64));
        assert_eq!(
            fields["wide_udp_capture_contract"],
            "preview_allowlist_only"
        );
        assert_eq!(fields["wide_udp_capture_support_tier"], "supported_preview");
        assert_eq!(fields["wide_udp_capture_policy"], "allowlist_ports");
        assert_eq!(fields["wide_udp_capture_runtime_scope"], "linux_ipv4_only");
        assert_eq!(
            fields["wide_udp_capture_match_kind"],
            "extra_udp_preview_port"
        );
        assert_eq!(
            fields["wide_udp_capture_accept_reason_code"],
            "matched_extra_udp_preview_port_allowlist"
        );
        assert_eq!(fields["wide_udp_preview_policy"], "allowlist_ports");
        assert_eq!(
            fields["wide_udp_preview_match_kind"],
            "extra_udp_preview_port"
        );
        assert_eq!(
            fields["wide_udp_preview_accept_reason_code"],
            "matched_extra_udp_preview_port_allowlist"
        );
        assert_eq!(fields["wide_udp_preview_ports"], json!([53, target_port]));
        assert_eq!(response_stage["fields"]["stage"], "local_udp_send_done");
        assert_eq!(response_stage["fields"]["response_action"], "local_udp");
        assert_eq!(
            response_stage["fields"]["payload_len"].as_u64(),
            Some(payload.len() as u64)
        );
    }

    // Regression for local UDP response failure classification after CONNECT-UDP succeeds.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wide_primary_udp_datagram_local_response_failure_stops_before_completed_event() {
        let _runtime_lock = RUNTIME_JSONL_LOCK.lock().await;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let jsonl_path = ensure_runtime_jsonl_path().clone();
        let start_index = read_jsonl_records(&jsonl_path).len();
        let (mut cfg, server_task) = start_local_masque_server().await;
        let (target_port, udp_echo_task) = start_udp_echo().await;
        cfg.ingress.wide.udp_preview_ports = vec![target_port];
        let runtime = RuntimeContext::from_settings(&cfg)
            .await
            .expect("build runtime context");
        let payload = b"wide-primary-response-failure".to_vec();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("bind receiver");
        let receiver_addr = receiver.local_addr().expect("receiver addr");
        drop(receiver);
        let response_socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind unconnected response socket");

        let result = runtime
            .handle_session(
                BrokeredSession::UdpDatagram(BrokeredUdpDatagram {
                    ingress_kind: IngressKind::WidePrimary,
                    control: UdpSessionControl::Detached,
                    client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    target: ConnectTarget {
                        host: "127.0.0.1".into(),
                        port: target_port,
                    },
                    payload: payload.clone(),
                    response: UdpDatagramResponse::LocalUdp {
                        socket: response_socket,
                        peer: receiver_addr,
                    },
                }),
                &cfg,
                sample_wide_primary_ingress_context("aegisvh-product"),
            )
            .await;

        udp_echo_task.abort();
        server_task.abort();
        let err = result.expect_err("wide primary response send should fail");
        let error_text = format!("{err:#}");
        assert!(
            error_text.contains("Destination address required")
                || error_text.contains("destination address required")
                || error_text.contains("not connected")
                || error_text.contains("Not connected"),
            "{error_text}"
        );

        let response_stage =
            wait_for_udp_response_stage_event(&jsonl_path, start_index, "local_udp_send_start")
                .await;
        assert_eq!(response_stage["fields"]["response_action"], "local_udp");
        assert_eq!(
            response_stage["fields"]["payload_len"].as_u64(),
            Some(payload.len() as u64)
        );

        tokio::time::sleep(Duration::from_millis(150)).await;
        let records = read_jsonl_records(&jsonl_path);
        assert!(
            !records.iter().skip(start_index).any(|record| {
                record["event_code"] == RuntimeEventCode::IngressUdpDatagramCompleted.as_str()
                    && record["fields"]["target_port"].as_u64() == Some(target_port as u64)
            }),
            "unexpected completed event after response send failure: {records:?}"
        );
        assert!(
            !records.iter().skip(start_index).any(|record| {
                record["event_code"] == RuntimeEventCode::IngressUdpDatagramResponseStage.as_str()
                    && record["fields"]["stage"] == "local_udp_send_done"
            }),
            "unexpected local_udp_send_done stage after response send failure: {records:?}"
        );
    }

    // Regression for full-wide persistent CONNECT-UDP flow teardown.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn persistent_masque_udp_flow_closes_when_capture_flow_expires() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (cfg, server_task) = start_local_masque_server().await;
        let (target_port, udp_echo_task) = start_udp_echo().await;
        let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(4);
        let (incoming_tx, mut incoming_rx) = tokio::sync::mpsc::channel(4);
        let relay = cfg.relay.clone();
        let flow_task = tokio::spawn(async move {
            relay::masque::run_masque_udp_flow(
                &relay,
                "127.0.0.1",
                target_port,
                outbound_rx,
                incoming_tx,
            )
            .await
        });

        let payload = b"persistent-flow-close".to_vec();
        outbound_tx
            .send(payload.clone())
            .await
            .expect("send persistent UDP payload");
        let response = tokio::time::timeout(Duration::from_secs(15), incoming_rx.recv())
            .await
            .expect("persistent UDP response timeout")
            .expect("persistent UDP response channel closed");
        assert_eq!(response.payload, payload);

        // The wide capture layer drops this sender when its 30-second flow
        // entry expires. Before the fix the tunnel reached endpoint.wait_idle
        // with QUIC keepalive still enabled and never returned, leaving one
        // server permit and UDP socket behind for every expired flow.
        drop(outbound_tx);
        tokio::time::timeout(Duration::from_secs(2), flow_task)
            .await
            .expect("expired persistent MASQUE flow did not close")
            .expect("persistent MASQUE flow task panicked")
            .expect("persistent MASQUE flow teardown failed");

        udp_echo_task.abort();
        server_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn udp_plan_falls_back_from_unreachable_masque_to_grpc_datagram() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (mut cfg, server_task) = start_local_masque_server().await;
        let (target_port, udp_echo_task) = start_udp_echo().await;
        // Reserve and release a UDP port so the preferred QUIC dial has no
        // listener. The second plan entry must then use the TCP/H2 listener.
        let unreachable_quic_port = reserve_udp_port();
        cfg.relay.masque_server = Some(format!("127.0.0.1:{unreachable_quic_port}"));
        // This shared budget covers both the unavailable QUIC attempt and
        // the successful cold TCP/TLS/H2 connection on loaded Windows runners.
        cfg.relay.connect_timeout_ms = 5_000;
        cfg.relay.transport_priority = vec![TunnelTransportFamily::GrpcStream];
        cfg.relay.udp_transport_priority = Some(vec![
            TunnelTransportFamily::MasqueDerived,
            TunnelTransportFamily::GrpcDatagram,
        ]);

        let payload = b"masque-blocked-grpc-datagram-fallback";
        let response = tokio::time::timeout(
            Duration::from_secs(20),
            relay::run_relay_udp_datagram_once(
                &cfg.relay,
                ConnectTarget {
                    host: "127.0.0.1".into(),
                    port: target_port,
                },
                payload,
            ),
        )
        .await
        .expect("UDP fallback test timed out")
        .expect("gRPC datagram fallback failed");
        assert_eq!(response, payload);

        udp_echo_task.abort();
        server_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn persistent_full_wide_udp_flow_falls_back_to_grpc_datagram() {
        struct AbortFixture(tokio::task::AbortHandle);
        impl Drop for AbortFixture {
            fn drop(&mut self) {
                self.0.abort();
            }
        }
        let _runtime_lock = RUNTIME_JSONL_LOCK.lock().await;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let jsonl_path = ensure_runtime_jsonl_path().clone();
        let start_index = read_jsonl_records(&jsonl_path).len();
        let (mut cfg, server_task) = start_local_masque_server().await;
        let _server_owner = AbortFixture(server_task.abort_handle());
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_port = target.local_addr().unwrap().port();
        let delivered = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let target_delivered = delivered.clone();
        let udp_echo_task = tokio::spawn(async move {
            let mut bytes = [0; 2048];
            loop {
                let (n, peer) = target.recv_from(&mut bytes).await.unwrap();
                target_delivered.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                target.send_to(&bytes[..n], peer).await.unwrap();
            }
        });
        let _echo_owner = AbortFixture(udp_echo_task.abort_handle());
        // Real, owned QUIC ingress rejects the opening explicitly. A 300ms
        // blackhole deadline also constrained the successful TLS/H2 fallback,
        // turning this lifecycle/replay regression into a startup benchmark.
        // Keep timeout/blackhole behavior covered by the staged carrier tests.
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let quic = quinn::Endpoint::server(
            quinn::ServerConfig::with_single_cert(
                vec![cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into(),
            )
            .unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        cfg.relay.masque_server = Some(quic.local_addr().unwrap().to_string());
        cfg.relay.connect_timeout_ms = 5_000;
        let (refused_tx, refused_rx) = tokio::sync::oneshot::channel();
        let refused_task = tokio::spawn(async move {
            quic.accept().await.expect("actual QUIC opening").refuse();
            refused_tx.send(()).expect("QUIC refusal evidence receiver");
            // Retain ownership so the explicit rejection is delivered, and
            // the UDP port cannot be reused before the fallback has closed.
            std::future::pending::<()>().await;
        });
        let _refusal_owner = AbortFixture(refused_task.abort_handle());
        cfg.relay.transport_priority = vec![TunnelTransportFamily::GrpcStream];
        cfg.relay.udp_transport_priority = Some(vec![
            TunnelTransportFamily::MasqueDerived,
            TunnelTransportFamily::GrpcDatagram,
        ]);

        let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(4);
        let (incoming_tx, mut incoming_rx) = tokio::sync::mpsc::channel(4);
        let relay_settings = cfg.relay.clone();
        let mut flow_task = tokio::spawn(async move {
            relay::run_relay_udp_flow(
                &relay_settings,
                "127.0.0.1",
                target_port,
                outbound_rx,
                incoming_tx,
            )
            .await
        });
        let _flow_owner = AbortFixture(flow_task.abort_handle());
        let payload = b"persistent-full-wide-grpc-fallback".to_vec();
        outbound_tx
            .send(payload.clone())
            .await
            .expect("queue full-wide UDP payload");
        tokio::time::timeout(Duration::from_secs(6), refused_rx)
            .await
            .expect("preferred QUIC opening did not reach its owned endpoint")
            .expect("preferred QUIC endpoint stopped before explicit refusal");
        let response = tokio::time::timeout(Duration::from_secs(12), incoming_rx.recv())
            .await
            .expect("persistent UDP fallback timed out");
        let Some(response) = response else {
            let outcome = tokio::time::timeout(Duration::from_secs(1), &mut flow_task).await;
            let attempts = fixture_relay_attempt_diagnostics(&jsonl_path, start_index);
            panic!("persistent UDP response channel closed: worker={outcome:?}; fixture_server_finished={}; attempts={attempts:?}",
                server_task.is_finished());
        };
        assert_eq!(response.payload, payload);

        drop(outbound_tx);
        tokio::time::timeout(Duration::from_secs(3), flow_task)
            .await
            .expect("persistent gRPC UDP flow did not close")
            .expect("persistent gRPC UDP task panicked")
            .expect("persistent gRPC UDP teardown failed");
        refused_task.abort();
        assert!(refused_task
            .await
            .expect_err("owned refusing QUIC fixture cancelled")
            .is_cancelled());
        assert_eq!(
            delivered.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "pre-open failover must deliver the queued datagram exactly once"
        );

        let records = read_jsonl_records(&jsonl_path);
        let new_records = &records[start_index..];
        assert!(new_records.iter().any(|record| {
            record["event_code"] == RuntimeEventCode::RelayTransportFailed.as_str()
                && record["fields"]["relay_session_kind"] == "udp_flow"
                && record["fields"]["transport"] == "MasqueDerived"
                && record["fields"]["relay_error_kind"].as_str() == Some("quic_connection_refused")
        }));
        assert!(new_records.iter().any(|record| {
            record["event_code"] == RuntimeEventCode::RelayTransportSelected.as_str()
                && record["fields"]["relay_session_kind"] == "udp_flow"
                && record["fields"]["transport"] == "GrpcDatagram"
        }));
        assert!(new_records.iter().any(|record| {
            record["event_code"] == RuntimeEventCode::RelaySessionSucceeded.as_str()
                && record["fields"]["relay_session_kind"] == "udp_flow"
                && record["fields"]["chosen_transport"] == "GrpcDatagram"
        }));
        udp_echo_task.abort();
        assert!(udp_echo_task
            .await
            .expect_err("owned echo fixture cancelled")
            .is_cancelled());
        server_task.abort();
        assert!(server_task
            .await
            .expect_err("owned relay fixture cancelled")
            .is_cancelled());
    }

    // Regression for generic UDP capture local response delivery over CONNECT-UDP.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wide_primary_generic_udp_datagram_local_response_completes_product_path() {
        let _runtime_lock = RUNTIME_JSONL_LOCK.lock().await;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let jsonl_path = ensure_runtime_jsonl_path().clone();
        let start_index = read_jsonl_records(&jsonl_path).len();
        let (mut cfg, server_task) = start_local_masque_server().await;
        let (target_port, udp_echo_task) = start_udp_echo().await;
        cfg.ingress.wide.udp_capture_contract = WideUdpCaptureContract::GenericCaptureUnstable;
        let runtime = RuntimeContext::from_settings(&cfg)
            .await
            .expect("build runtime context");
        let payload = b"wide-primary-generic-product-path".to_vec();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("bind receiver");
        let receiver_addr = receiver.local_addr().expect("receiver addr");
        let recv_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 256];
            let (n, peer) = receiver
                .recv_from(&mut buf)
                .await
                .expect("receive udp response");
            (buf[..n].to_vec(), peer)
        });
        let response_socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind response socket");
        response_socket
            .connect(receiver_addr)
            .await
            .expect("connect response socket");

        let result = runtime
            .handle_session(
                BrokeredSession::UdpDatagram(BrokeredUdpDatagram {
                    ingress_kind: IngressKind::WidePrimary,
                    control: UdpSessionControl::Detached,
                    client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    target: ConnectTarget {
                        host: "127.0.0.1".into(),
                        port: target_port,
                    },
                    payload: payload.clone(),
                    response: UdpDatagramResponse::LocalUdp {
                        socket: response_socket,
                        peer: receiver_addr,
                    },
                }),
                &cfg,
                sample_wide_primary_ingress_context("aegisvh-generic"),
            )
            .await;

        let (response, response_peer) = tokio::time::timeout(Duration::from_secs(30), recv_task)
            .await
            .expect("udp response timeout")
            .expect("udp recv task");
        udp_echo_task.abort();
        server_task.abort();
        result.expect("wide primary generic udp datagram relay");

        assert_eq!(response, payload);
        assert!(response_peer.ip().is_ipv4());

        let completed = wait_for_udp_completed_event(&jsonl_path, start_index, target_port).await;
        let response_stage =
            wait_for_udp_response_stage_event(&jsonl_path, start_index, "local_udp_send_done")
                .await;
        let fields = &completed["fields"];
        assert_eq!(fields["backend"], "wide_primary");
        assert_eq!(fields["backend_runtime_id"], "wide_primary_linux");
        assert_eq!(fields["backend_kind_code"], "wide_primary");
        assert_eq!(fields["requested_primary_code"], "wide");
        assert_eq!(fields["mode_code"], "relay");
        assert_eq!(fields["rollout_profile_code"], "transparent_privileged");
        assert_eq!(fields["prerouting_interface"], "aegisvh-generic");
        assert_eq!(fields["startup_path_code"], "wide_primary_started");
        assert_eq!(fields["target_host"], "127.0.0.1");
        assert_eq!(fields["target_port"].as_u64(), Some(target_port as u64));
        assert_eq!(fields["response_action"], "local_udp");
        assert_eq!(fields["response_len"].as_u64(), Some(payload.len() as u64));
        assert_eq!(
            fields["wide_udp_capture_contract"],
            "generic_capture_unstable"
        );
        assert_eq!(fields["wide_udp_capture_support_tier"], "guarded_unstable");
        assert_eq!(
            fields["wide_udp_capture_policy"],
            "any_target_port_linux_ipv4_unstable"
        );
        assert_eq!(fields["wide_udp_capture_runtime_scope"], "linux_ipv4_only");
        assert_eq!(
            fields["wide_udp_capture_match_kind"],
            "generic_capture_contract"
        );
        assert_eq!(
            fields["wide_udp_capture_accept_reason_code"],
            "matched_generic_udp_capture_contract"
        );
        assert_eq!(fields["wide_udp_preview_policy"], Value::Null);
        assert_eq!(fields["wide_udp_preview_match_kind"], Value::Null);
        assert_eq!(fields["wide_udp_preview_accept_reason_code"], Value::Null);
        assert_eq!(fields["wide_udp_preview_ports"], json!([]));
        assert_eq!(response_stage["fields"]["stage"], "local_udp_send_done");
        assert_eq!(response_stage["fields"]["response_action"], "local_udp");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wide_primary_generic_udp_datagram_terminal_transport_failure_emits_runtime_event() {
        let _runtime_lock = RUNTIME_JSONL_LOCK.lock().await;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let jsonl_path = ensure_runtime_jsonl_path().clone();
        let start_index = read_jsonl_records(&jsonl_path).len();
        let mut cfg = Settings {
            mode: Mode::Relay,
            ..Settings::default()
        };
        cfg.ingress.wide.enabled = true;
        cfg.ingress.wide.capture_dns = true;
        cfg.ingress.wide.listen = "127.0.0.1:53080".parse().expect("wide listen");
        cfg.ingress.wide.udp_capture_contract = WideUdpCaptureContract::GenericCaptureUnstable;
        cfg.relay.server = "127.0.0.1:1".into();
        cfg.relay.server_name = "localhost".into();
        cfg.relay.auth_token =
            "ac99c6bf1351492d50367daf9be01fc3dfd7bc33f5b9437dbf1b1fde632b87e1".into();
        cfg.relay.connect_timeout_ms = 300;
        cfg.relay.transport_priority = vec![TunnelTransportFamily::MasqueDerived];
        let runtime = RuntimeContext::from_settings(&cfg)
            .await
            .expect("build runtime context");
        let payload = b"wide-primary-generic-terminal-transport".to_vec();

        let result = runtime
            .handle_session(
                BrokeredSession::UdpDatagram(BrokeredUdpDatagram {
                    ingress_kind: IngressKind::WidePrimary,
                    control: UdpSessionControl::Detached,
                    client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    target: ConnectTarget {
                        host: "127.0.0.1".into(),
                        port: 54321,
                    },
                    payload: payload.clone(),
                    response: UdpDatagramResponse::Detached,
                }),
                &cfg,
                sample_wide_primary_ingress_context("aegisvh-transport-fail"),
            )
            .await;

        let err = result.expect_err("wide primary generic udp transport should fail");
        let error_text = format!("{err:#}");
        assert!(
            error_text.contains("Connection refused")
                || error_text.contains("connection refused")
                || error_text.contains("connect relay")
                || error_text.contains("timeout")
                || error_text.contains("timed out"),
            "{error_text}"
        );
        let relay_terminal = err
            .downcast_ref::<relay::RelayTerminalFailure>()
            .expect("relay terminal failure");
        assert_eq!(relay_terminal.target.as_deref(), Some("127.0.0.1"));
        assert_eq!(relay_terminal.port, Some(54321));
        assert_eq!(relay_terminal.relay_server, "127.0.0.1:1");
        assert_eq!(relay_terminal.relay_server_name, "localhost");
        assert_eq!(relay_terminal.attempts_total, 1);
        assert_eq!(relay_terminal.planned_transports, vec!["MasqueDerived"]);
        assert_eq!(
            relay_terminal.last_transport.as_deref(),
            Some("MasqueDerived")
        );

        let relay_failed = wait_for_event(
            &jsonl_path,
            start_index,
            RuntimeEventCode::RelayTransportFailed.as_str(),
        )
        .await;
        assert_eq!(relay_failed["fields"]["transport"], "MasqueDerived");
        assert_eq!(relay_failed["fields"]["target"], "127.0.0.1");
        assert_eq!(relay_failed["fields"]["port"], 54321);
        assert_eq!(relay_failed["fields"]["relay_server"], "127.0.0.1:1");
        assert_eq!(relay_failed["fields"]["relay_server_name"], "localhost");
        assert_eq!(relay_failed["fields"]["attempt_index"], 1);
        assert_eq!(relay_failed["fields"]["attempts_total"], 1);
        assert_eq!(
            relay_failed["fields"]["planned_transports"],
            json!(["MasqueDerived"])
        );
        assert!(
            relay_failed["fields"]["relay_error_kind"] == "connection_refused"
                || relay_failed["fields"]["relay_error_kind"] == "timed_out"
                || relay_failed["fields"]["relay_error_kind"].is_null(),
            "{relay_failed:?}"
        );
        assert_eq!(
            relay_failed["fields"]["relay_failure_scope"],
            "real_transport_outage"
        );
        assert_eq!(relay_failed["fields"]["relay_tunnel_status"], Value::Null);

        tokio::time::sleep(Duration::from_millis(150)).await;
        let records = read_jsonl_records(&jsonl_path);
        assert!(
            !records.iter().skip(start_index).any(|record| {
                record["event_code"] == RuntimeEventCode::IngressUdpDatagramCompleted.as_str()
                    && record["fields"]["target_port"].as_u64() == Some(54321)
            }),
            "unexpected completed event after terminal transport failure: {records:?}"
        );
        assert!(
            !records.iter().skip(start_index).any(|record| {
                record["event_code"] == RuntimeEventCode::IngressUdpDatagramResponseStage.as_str()
            }),
            "unexpected response stage after terminal transport failure: {records:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn udp_associate_wrong_masque_path_reports_failure_not_success() {
        let _runtime_lock = RUNTIME_JSONL_LOCK.lock().await;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let jsonl_path = ensure_runtime_jsonl_path().clone();
        let start_index = read_jsonl_records(&jsonl_path).len();
        // Deliberately produce real foreign failure and success events first:
        // selecting the first generic failure would read GrpcDatagram here.
        let unrelated = UnrelatedUdpEventFixture::new().await;
        unrelated.exercise().await;
        unrelated.assert_both_outcomes(&read_jsonl_records(&jsonl_path)[start_index..]);
        let (mut cfg, server_task) = start_local_masque_server().await;
        let _server_owner = AbortFixtureTask::new(server_task.abort_handle());
        let owned_server = cfg.relay.server.clone();
        cfg.relay.masque_path = "/wrong-masque-path-test".into();
        cfg.relay.masque_path_pool.clear();
        cfg.relay.connect_timeout_ms = 500;
        cfg.relay.transport_priority = vec![TunnelTransportFamily::MasqueDerived];

        let relay_socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind relay udp socket");
        let relay_addr = relay_socket.local_addr().expect("relay udp addr");
        let client_socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind client udp socket");
        let client_ip = client_socket.local_addr().expect("client udp addr").ip();
        let target = ConnectTarget {
            host: "127.0.0.1".into(),
            port: 54321,
        };
        let packet = crate::socks5::encode_udp_packet(&target, b"wrong-masque-path")
            .expect("encode socks udp packet");
        let relay_settings = cfg.relay.clone();
        let mut relay_task = tokio::spawn(async move {
            relay::run_relay_udp_associate(
                UdpSessionControl::Detached,
                relay_socket,
                &relay_settings,
                client_ip,
            )
            .await
        });

        let _relay_owner = AbortFixtureTask::new(relay_task.abort_handle());

        client_socket
            .send_to(&packet, relay_addr)
            .await
            .expect("send socks udp packet");
        let relay_failed = wait_for_event_matching(
            &jsonl_path,
            start_index,
            RuntimeEventCode::RelayTransportFailed.as_str(),
            |record| record["fields"]["relay_server"].as_str() == Some(owned_server.as_str()),
        )
        .await;
        assert_eq!(relay_failed["fields"]["transport"], "MasqueDerived");
        assert_eq!(relay_failed["fields"]["target"], "127.0.0.1");
        assert_eq!(relay_failed["fields"]["port"], 54321);
        assert_eq!(
            relay_failed["fields"]["relay_surface_masque_path"],
            "/wrong-masque-path-test"
        );
        assert_eq!(
            relay_failed["fields"]["planned_transports"],
            json!(["MasqueDerived"])
        );
        assert!(
            relay_failed["fields"]["error"]
                .as_str()
                .unwrap_or_default()
                .contains("CONNECT-UDP tunnel failed for 127.0.0.1:54321"),
            "{relay_failed:?}"
        );
        assert!(
            !read_jsonl_records(&jsonl_path)
                .iter()
                .skip(start_index)
                .any(|record| record["event_code"]
                    == RuntimeEventCode::RelaySessionSucceeded.as_str()
                    && record["fields"]["relay_server"].as_str() == Some(owned_server.as_str())),
            "owned malformed MASQUE attempt must never report success"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut relay_task)
                .await
                .is_err(),
            "one target-flow failure must not terminate the reusable UDP association"
        );
        relay_task.abort();
        let stopped = tokio::time::timeout(Duration::from_secs(1), relay_task)
            .await
            .expect("owned UDP association cancellation deadline")
            .expect_err("aborted UDP association must not complete successfully");
        assert!(stopped.is_cancelled());
    }

    // Regression for generic UDP recovery after a forced first transport failure.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wide_primary_generic_udp_datagram_recovers_after_initial_transport_failure() {
        struct ResetInjectedUdpFailures;

        impl Drop for ResetInjectedUdpFailures {
            fn drop(&mut self) {
                crate::relay::set_test_udp_datagram_failures_remaining(0);
            }
        }

        let _runtime_lock = RUNTIME_JSONL_LOCK.lock().await;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let jsonl_path = ensure_runtime_jsonl_path().clone();
        let start_index = read_jsonl_records(&jsonl_path).len();
        let (mut cfg, server_task) = start_local_masque_server().await;
        let (target_port, udp_echo_task) = start_udp_echo().await;
        cfg.ingress.wide.udp_capture_contract = WideUdpCaptureContract::GenericCaptureUnstable;
        // This checks an explicitly repeated policy attempt, not opening latency.
        // The opening budget now includes trust-store/TLS/HTTP authentication,
        // so leave cold native trust discovery room in this end-to-end fixture.
        // Narrow, staged deadline regressions live in relay::masque::tests.
        cfg.relay.connect_timeout_ms = 5_000;
        cfg.relay.transport_priority = vec![
            TunnelTransportFamily::MasqueDerived,
            TunnelTransportFamily::MasqueDerived,
        ];
        cfg.relay.policy.rotate_transports_per_session = false;
        cfg.relay.policy.max_transport_attempts = 2;
        let runtime = RuntimeContext::from_settings(&cfg)
            .await
            .expect("build runtime context");
        let payload = b"wide-primary-generic-recovered-transport".to_vec();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("bind receiver");
        let receiver_addr = receiver.local_addr().expect("receiver addr");
        let recv_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 256];
            let (n, peer) = receiver
                .recv_from(&mut buf)
                .await
                .expect("receive udp response");
            (buf[..n].to_vec(), peer)
        });
        let response_socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind response socket");
        response_socket
            .connect(receiver_addr)
            .await
            .expect("connect response socket");

        let _reset_failures = ResetInjectedUdpFailures;
        crate::relay::set_test_udp_datagram_failures_remaining(1);
        let result = runtime
            .handle_session(
                BrokeredSession::UdpDatagram(BrokeredUdpDatagram {
                    ingress_kind: IngressKind::WidePrimary,
                    control: UdpSessionControl::Detached,
                    client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    target: ConnectTarget {
                        host: "127.0.0.1".into(),
                        port: target_port,
                    },
                    payload: payload.clone(),
                    response: UdpDatagramResponse::LocalUdp {
                        socket: response_socket,
                        peer: receiver_addr,
                    },
                }),
                &cfg,
                sample_wide_primary_ingress_context("aegisvh-generic-retry"),
            )
            .await;

        if let Err(error) = result {
            recv_task.abort();
            udp_echo_task.abort();
            server_task.abort();
            panic!("generic UDP recovery failed before response wait: {error:#}");
        }
        let (response, response_peer) = tokio::time::timeout(Duration::from_secs(30), recv_task)
            .await
            .expect("udp response timeout")
            .expect("udp recv task");
        udp_echo_task.abort();
        server_task.abort();

        assert_eq!(response, payload);
        assert!(response_peer.ip().is_ipv4());

        let relay_failed = wait_for_event(
            &jsonl_path,
            start_index,
            RuntimeEventCode::RelayTransportFailed.as_str(),
        )
        .await;
        let completed = wait_for_udp_completed_event(&jsonl_path, start_index, target_port).await;
        let response_stage =
            wait_for_udp_response_stage_event(&jsonl_path, start_index, "local_udp_send_done")
                .await;
        assert_eq!(relay_failed["fields"]["transport"], "MasqueDerived");
        assert_eq!(relay_failed["fields"]["target"], "127.0.0.1");
        assert_eq!(relay_failed["fields"]["port"], target_port);
        assert_eq!(relay_failed["fields"]["relay_server_name"], "localhost");
        assert_eq!(relay_failed["fields"]["attempt_index"], 1);
        assert_eq!(relay_failed["fields"]["attempts_total"], 2);
        assert_eq!(
            relay_failed["fields"]["planned_transports"],
            json!(["MasqueDerived", "MasqueDerived"])
        );
        assert!(
            relay_failed["fields"]["relay_error_kind"].is_null(),
            "{relay_failed:?}"
        );
        assert_eq!(
            relay_failed["fields"]["relay_failure_scope"],
            "real_transport_outage"
        );
        assert_eq!(relay_failed["fields"]["relay_tunnel_status"], Value::Null);
        assert_eq!(
            completed["fields"]["wide_udp_capture_contract"],
            "generic_capture_unstable"
        );
        assert_eq!(completed["fields"]["response_action"], "local_udp");
        assert_eq!(response_stage["fields"]["response_action"], "local_udp");

        tokio::time::sleep(Duration::from_millis(150)).await;
        let records = read_jsonl_records(&jsonl_path);
        assert!(
            !records.iter().skip(start_index).any(|record| {
                record["event_code"] == RuntimeEventCode::IngressSessionFailed.as_str()
            }),
            "unexpected terminal session failure after recovered UDP relay retry: {records:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wide_primary_tcp_connect_runtime_unready_rejection_keeps_product_context() {
        let _runtime_lock = RUNTIME_JSONL_LOCK.lock().await;
        let jsonl_path = ensure_runtime_jsonl_path().clone();
        let start_index = read_jsonl_records(&jsonl_path).len();
        let (client, server, peer) = tcp_pair().await;
        drop(client);
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut cfg = Settings {
            mode: Mode::Relay,
            ..Settings::default()
        };
        cfg.relay.auth_token.clear();
        cfg.relay.transport_priority.clear();
        let mut intent = IngressSessionIntent {
            kind: IngressKind::WidePrimary,
            peer,
            transport: IngressTransport::TcpConnect(TcpConnectIntent {
                client: server,
                target: ConnectTarget {
                    host: "127.0.0.1".into(),
                    port: 443,
                },
                response: IngressResponse::Socks5,
                target_lease: None,
            }),
        };

        assert!(
            reject_tcp_connect_if_runtime_unready(
                &mut intent,
                &cfg,
                &sample_wide_primary_ingress_context("aegisvh-transport"),
            )
            .await
        );
        let rejected = wait_for_event(
            &jsonl_path,
            start_index,
            RuntimeEventCode::IngressTcpConnectRejected.as_str(),
        )
        .await;
        let records = read_jsonl_records(&jsonl_path);
        assert!(
            !records.iter().skip(start_index).any(|record| {
                record["event_code"]
                    == RuntimeEventCode::IngressTcpConnectRejectResponseFailed.as_str()
            }),
            "unexpected reject response failure: {records:?}"
        );
        assert_eq!(rejected["fields"]["backend"], "wide_primary");
        assert_eq!(
            rejected["fields"]["backend_runtime_id"],
            "wide_primary_linux"
        );
        assert_eq!(rejected["fields"]["backend_kind_code"], "wide_primary");
        assert_eq!(rejected["fields"]["requested_primary_code"], "wide");
        assert_eq!(rejected["fields"]["mode_code"], "relay");
        assert_eq!(rejected["fields"]["wide_runtime_readiness"], "ready");
        assert_eq!(
            rejected["fields"]["rollout_profile_code"],
            "transparent_privileged"
        );
        assert_eq!(
            rejected["fields"]["prerouting_interface"],
            "aegisvh-transport"
        );
        assert_eq!(
            rejected["fields"]["startup_path_code"],
            "wide_primary_started"
        );
        assert_eq!(rejected["fields"]["request_kind"], "TcpConnect");
        assert_eq!(
            rejected["fields"]["reject_stage"],
            "pre_broker_runtime_gate"
        );
        assert_eq!(
            rejected["fields"]["response_action"],
            "send_general_failure"
        );
        assert_eq!(rejected["fields"]["response_reply_code"], 1);
        assert_eq!(
            rejected["fields"]["reject_reason_code"],
            "tcp_connect_requires_runtime_ready_relay_transport"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn wide_primary_tcp_connect_recovers_after_initial_transport_failure() {
        #[cfg(feature = "legacy-challenge-v1")]
        {
            // Exercise the real pre-dial runtime admission for this same carrier order.
            let _runtime_lock = RUNTIME_JSONL_LOCK.lock().await;
            let relay_listener =
                StdTcpListener::bind("127.0.0.1:0").expect("bind relay refusal witness");
            relay_listener
                .set_nonblocking(true)
                .expect("nonblocking relay witness");
            let target_listener =
                StdTcpListener::bind("127.0.0.1:0").expect("bind target refusal witness");
            target_listener
                .set_nonblocking(true)
                .expect("nonblocking target witness");
            let masque_socket =
                std::net::UdpSocket::bind("127.0.0.1:0").expect("bind MASQUE refusal witness");
            masque_socket
                .set_nonblocking(true)
                .expect("nonblocking MASQUE witness");
            let mut cfg = Settings {
                mode: Mode::Relay,
                ..Settings::default()
            };
            cfg.relay.server = relay_listener
                .local_addr()
                .expect("relay witness address")
                .to_string();
            cfg.relay.masque_server = Some(
                masque_socket
                    .local_addr()
                    .expect("MASQUE witness address")
                    .to_string(),
            );
            cfg.relay.server_name = "localhost".into();
            cfg.relay.auth_token =
                "ac99c6bf1351492d50367daf9be01fc3dfd7bc33f5b9437dbf1b1fde632b87e1".into();
            cfg.relay.transport_priority = vec![
                TunnelTransportFamily::LegacyTls,
                TunnelTransportFamily::MasqueDerived,
            ];
            cfg.relay.policy.rotate_transports_per_session = false;
            cfg.relay.policy.adaptive_transport = false;
            cfg.relay.policy.max_transport_attempts = 2;
            let (_application_client, local, _peer) = tcp_pair().await;
            let (outcome_tx, mut outcome_rx) = tokio::sync::mpsc::unbounded_channel();
            let error = tokio::time::timeout(
                Duration::from_secs(15),
                crate::relay::run_relay_tunnel(
                    local,
                    &cfg.relay,
                    "127.0.0.1".into(),
                    target_listener
                        .local_addr()
                        .expect("target witness address")
                        .port(),
                    Some(b"GET /feature-refusal HTTP/1.0\r\n\r\n"),
                    None,
                    Some(&outcome_tx),
                ),
            )
            .await
            .expect("bounded feature-on carrier refusal")
            .expect_err("fresh raw mode refuses this carrier order");
            assert_eq!(error.to_string(), "legacy-challenge-v1 requires a raw legacy_tls-only TCP transport order; downgrade is refused");
            assert!(
                matches!(relay_listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
                "refusal must precede relay TCP dialing"
            );
            assert!(
                matches!(target_listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
                "refusal must precede target TCP dialing"
            );
            let mut packet = [0u8; 1];
            assert!(
                matches!(masque_socket.recv_from(&mut packet), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
                "refusal must precede MASQUE QUIC dialing"
            );
            assert!(
                matches!(
                    outcome_rx.try_recv(),
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty)
                ),
                "refusal must not invent a transport outcome"
            );
        }
        #[cfg(not(feature = "legacy-challenge-v1"))]
        {
            let _runtime_lock = RUNTIME_JSONL_LOCK.lock().await;
            let _ = rustls::crypto::ring::default_provider().install_default();
            let jsonl_path = ensure_runtime_jsonl_path().clone();
            let start_index = read_jsonl_records(&jsonl_path).len();
            let (mut cfg, server_task) = start_local_masque_server().await;
            cfg.relay.server = "127.0.0.1:1".into();
            // This exercises recovery, not a subsecond opening deadline. The same
            // budget also covers trust discovery, QUIC and authenticated CONNECT
            // on the successful second transport (see relay::masque deadline tests).
            cfg.relay.connect_timeout_ms = 5_000;
            cfg.relay.transport_priority = vec![
                TunnelTransportFamily::LegacyTls,
                TunnelTransportFamily::MasqueDerived,
            ];
            cfg.relay.policy.rotate_transports_per_session = false;
            cfg.relay.policy.max_transport_attempts = 2;
            // The Brain reorders relay transports adaptively (Brick 2), so the
            // configured priority is only a prior. This test is about what happens
            // *after* the first transport fails, so it needs the configured order
            // honoured verbatim — otherwise MasqueDerived is sometimes tried first,
            // succeeds immediately, and no failure ever occurs. That was this
            // test's flakiness: it failed roughly two runs in three.
            cfg.relay.policy.adaptive_transport = false;

            let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind target listener");
            let target_addr = target_listener.local_addr().expect("target addr");
            let target_task = tokio::spawn(async move {
                let (mut conn, _) = target_listener.accept().await.expect("accept target");
                let mut request = [0u8; 256];
                let n = conn.read(&mut request).await.expect("read target request");
                assert!(
                    request[..n].starts_with(b"GET /wide-primary-retry HTTP/1.0\r\n\r\n"),
                    "unexpected request"
                );
                conn.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 13\r\n\r\nwide-recovery")
                    .await
                    .expect("write target response");
                conn.shutdown().await.expect("shutdown target");
            });

            let (mut client, server, _peer) = tcp_pair().await;
            let runtime = RuntimeContext::from_settings(&cfg)
                .await
                .expect("build runtime context");
            let session_task = tokio::spawn(async move {
                runtime
                    .handle_session(
                        BrokeredSession::TcpConnect(BrokeredTcpConnect {
                            ingress_kind: IngressKind::WidePrimary,
                            client: server,
                            target: ConnectTarget {
                                host: "127.0.0.1".into(),
                                port: target_addr.port(),
                            },
                            dst: target_addr,
                        }),
                        &cfg,
                        sample_wide_primary_ingress_context("aegisvh-transport-retry"),
                    )
                    .await
            });

            client
                .write_all(b"GET /wide-primary-retry HTTP/1.0\r\n\r\n")
                .await
                .expect("write client request");
            let mut response = vec![0u8; 256];
            let n = tokio::time::timeout(Duration::from_secs(15), client.read(&mut response))
                .await
                .expect("read client response timeout")
                .unwrap_or_else(|error| {
                    let records = read_jsonl_records(&jsonl_path);
                    panic!(
                        "read client response: {error}; recovery events: {:?}",
                        &records[start_index..]
                    )
                });
            assert!(
                response[..n].starts_with(b"HTTP/1.0 200 OK"),
                "unexpected response {:?}",
                &response[..n]
            );
            drop(client);

            let result = tokio::time::timeout(Duration::from_secs(5), session_task)
                .await
                .expect("session task timeout")
                .expect("session task join");
            target_task.await.expect("join target task");
            server_task.abort();
            result.expect("wide primary tcp connect should recover after retry");

            let terminal_records = read_jsonl_records(&jsonl_path);
            for code in ["relay_session_succeeded", "wide_capture_flow_succeeded"] {
                let successes: Vec<_> = terminal_records
                    .iter()
                    .skip(start_index)
                    .filter(|record| record["event_code"] == code)
                    .collect();
                assert_eq!(successes.len(), 1, "exactly one terminal {code}");
                assert_eq!(
                    successes[0]["fields"]["application_response_observed"],
                    true
                );
                assert!(
                    successes[0]["fields"]["bytes_received_observed"]
                        .as_u64()
                        .unwrap()
                        > 0
                );
            }
            assert!(!terminal_records
                .iter()
                .skip(start_index)
                .any(|record| record["event_code"] == "relay_session_completed"));

            let relay_failed = wait_for_event(
                &jsonl_path,
                start_index,
                RuntimeEventCode::RelayTransportFailed.as_str(),
            )
            .await;
            assert_eq!(relay_failed["fields"]["transport"], "LegacyTls");
            assert_eq!(relay_failed["fields"]["target"], "127.0.0.1");
            assert_eq!(relay_failed["fields"]["port"], target_addr.port());
            assert_eq!(relay_failed["fields"]["relay_server"], "127.0.0.1:1");
            assert_eq!(relay_failed["fields"]["relay_server_name"], "localhost");
            assert_eq!(relay_failed["fields"]["attempt_index"], 1);
            assert_eq!(relay_failed["fields"]["attempts_total"], 2);
            assert_eq!(
                relay_failed["fields"]["planned_transports"],
                json!(["LegacyTls", "MasqueDerived"])
            );
            assert_eq!(
                relay_failed["fields"]["relay_failure_scope"],
                "real_transport_outage"
            );
            assert_eq!(relay_failed["fields"]["relay_tunnel_status"], Value::Null);

            tokio::time::sleep(Duration::from_millis(150)).await;
            let records = read_jsonl_records(&jsonl_path);
            assert!(
                !records.iter().skip(start_index).any(|record| {
                    record["event_code"] == RuntimeEventCode::IngressSessionFailed.as_str()
                }),
                "unexpected terminal session failure after recovered relay retry: {records:?}"
            );
            assert!(
                !records.iter().skip(start_index).any(|record| {
                    record["event_code"] == RuntimeEventCode::IngressTcpConnectRejected.as_str()
                }),
                "unexpected tcp rejection after recovered relay retry: {records:?}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn wide_primary_masque_tcp_connect_survives_idle_gap_without_transport_failure() {
        #[cfg(feature = "legacy-challenge-v1")]
        {
            // Exercise the real pre-dial runtime admission for this same carrier order.
            let _runtime_lock = RUNTIME_JSONL_LOCK.lock().await;
            let relay_listener =
                StdTcpListener::bind("127.0.0.1:0").expect("bind relay refusal witness");
            relay_listener
                .set_nonblocking(true)
                .expect("nonblocking relay witness");
            let target_listener =
                StdTcpListener::bind("127.0.0.1:0").expect("bind target refusal witness");
            target_listener
                .set_nonblocking(true)
                .expect("nonblocking target witness");
            let masque_socket =
                std::net::UdpSocket::bind("127.0.0.1:0").expect("bind MASQUE refusal witness");
            masque_socket
                .set_nonblocking(true)
                .expect("nonblocking MASQUE witness");
            let mut cfg = Settings {
                mode: Mode::Relay,
                ..Settings::default()
            };
            cfg.relay.server = relay_listener
                .local_addr()
                .expect("relay witness address")
                .to_string();
            cfg.relay.masque_server = Some(
                masque_socket
                    .local_addr()
                    .expect("MASQUE witness address")
                    .to_string(),
            );
            cfg.relay.server_name = "localhost".into();
            cfg.relay.auth_token =
                "ac99c6bf1351492d50367daf9be01fc3dfd7bc33f5b9437dbf1b1fde632b87e1".into();
            cfg.relay.transport_priority = vec![TunnelTransportFamily::MasqueDerived];
            cfg.relay.policy.rotate_transports_per_session = false;
            cfg.relay.policy.adaptive_transport = false;
            cfg.relay.policy.max_transport_attempts = 1;
            let (_application_client, local, _peer) = tcp_pair().await;
            let (outcome_tx, mut outcome_rx) = tokio::sync::mpsc::unbounded_channel();
            let error = tokio::time::timeout(
                Duration::from_secs(5),
                crate::relay::run_relay_tunnel(
                    local,
                    &cfg.relay,
                    "127.0.0.1".into(),
                    target_listener
                        .local_addr()
                        .expect("target witness address")
                        .port(),
                    Some(b"GET /feature-refusal HTTP/1.0\r\n\r\n"),
                    None,
                    Some(&outcome_tx),
                ),
            )
            .await
            .expect("bounded feature-on carrier refusal")
            .expect_err("fresh raw mode refuses this carrier order");
            assert_eq!(error.to_string(), "legacy-challenge-v1 requires a raw legacy_tls-only TCP transport order; downgrade is refused");
            assert!(
                matches!(relay_listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
                "refusal must precede relay TCP dialing"
            );
            assert!(
                matches!(target_listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
                "refusal must precede target TCP dialing"
            );
            let mut packet = [0u8; 1];
            assert!(
                matches!(masque_socket.recv_from(&mut packet), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
                "refusal must precede MASQUE QUIC dialing"
            );
            assert!(
                matches!(
                    outcome_rx.try_recv(),
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty)
                ),
                "refusal must not invent a transport outcome"
            );
        }
        #[cfg(not(feature = "legacy-challenge-v1"))]
        {
            let _runtime_lock = RUNTIME_JSONL_LOCK.lock().await;
            let _ = rustls::crypto::ring::default_provider().install_default();
            let jsonl_path = ensure_runtime_jsonl_path().clone();
            let start_index = read_jsonl_records(&jsonl_path).len();
            let transport = aegis_server::config::TransportConfig {
                quic_keep_alive_interval_ms: 100,
                quic_max_idle_timeout_ms: 450,
                ..Default::default()
            };
            let (mut cfg, server_task) = start_local_masque_server_with_transport(transport).await;
            cfg.relay.transport_priority = vec![TunnelTransportFamily::MasqueDerived];
            cfg.relay.masque_keep_alive_interval_ms = 100;
            cfg.relay.masque_max_idle_timeout_ms = 450;

            let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind target listener");
            let target_addr = target_listener.local_addr().expect("target addr");
            let target_task = tokio::spawn(async move {
                let (mut conn, _) = target_listener.accept().await.expect("accept target");
                let mut request = [0u8; 256];
                let n = conn
                    .read(&mut request)
                    .await
                    .expect("read first target request");
                assert!(
                    request[..n].starts_with(b"GET /idle-1 HTTP/1.0\r\n\r\n"),
                    "unexpected first request"
                );
                conn.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nidle1")
                    .await
                    .expect("write first target response");

                let mut request = [0u8; 256];
                let n = conn
                    .read(&mut request)
                    .await
                    .expect("read second target request");
                assert!(
                    request[..n].starts_with(b"GET /idle-2 HTTP/1.0\r\n\r\n"),
                    "unexpected second request"
                );
                conn.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nidle2")
                    .await
                    .expect("write second target response");
                conn.shutdown().await.expect("shutdown target");
            });

            let (mut client, server, _peer) = tcp_pair().await;
            let runtime = RuntimeContext::from_settings(&cfg)
                .await
                .expect("build runtime context");
            let session_task = tokio::spawn(async move {
                runtime
                    .handle_session(
                        BrokeredSession::TcpConnect(BrokeredTcpConnect {
                            ingress_kind: IngressKind::WidePrimary,
                            client: server,
                            target: ConnectTarget {
                                host: "127.0.0.1".into(),
                                port: target_addr.port(),
                            },
                            dst: target_addr,
                        }),
                        &cfg,
                        sample_wide_primary_ingress_context("aegisvh-transport-idle"),
                    )
                    .await
            });

            client
                .write_all(b"GET /idle-1 HTTP/1.0\r\n\r\n")
                .await
                .expect("write first client request");
            let mut response = vec![0u8; 256];
            let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut response))
                .await
                .expect("read first client response timeout")
                .expect("read first client response");
            assert!(
                response[..n].starts_with(b"HTTP/1.0 200 OK"),
                "unexpected first response {:?}",
                &response[..n]
            );

            // This gap is longer than the old default QUIC idle timeout used in the
            // regression harness, so the second request proves the MASQUE tunnel
            // stayed alive instead of timing out in the background.
            tokio::time::sleep(Duration::from_millis(700)).await;

            client
                .write_all(b"GET /idle-2 HTTP/1.0\r\n\r\n")
                .await
                .expect("write second client request");
            let mut response = vec![0u8; 256];
            let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut response))
                .await
                .expect("read second client response timeout")
                .expect("read second client response");
            assert!(
                response[..n].starts_with(b"HTTP/1.0 200 OK"),
                "unexpected second response {:?}",
                &response[..n]
            );
            drop(client);

            let result = tokio::time::timeout(Duration::from_secs(5), session_task)
                .await
                .expect("session task timeout")
                .expect("session task join");
            target_task.await.expect("join target task");
            server_task.abort();
            result.expect("wide primary masque tcp connect should survive idle gap");

            tokio::time::sleep(Duration::from_millis(150)).await;
            let records = read_jsonl_records(&jsonl_path);
            assert!(
                !records.iter().skip(start_index).any(|record| {
                    record["event_code"] == RuntimeEventCode::RelayTransportFailed.as_str()
                }),
                "unexpected relay transport failure after idle MASQUE gap: {records:?}"
            );
            assert!(
                !records.iter().skip(start_index).any(|record| {
                    record["event_code"] == RuntimeEventCode::IngressSessionFailed.as_str()
                }),
                "unexpected terminal session failure after idle MASQUE gap: {records:?}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wide_primary_tcp_connect_tunnel_target_error_is_classified_separately() {
        let _runtime_lock = RUNTIME_JSONL_LOCK.lock().await;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let jsonl_path = ensure_runtime_jsonl_path().clone();
        let start_index = read_jsonl_records(&jsonl_path).len();
        let (mut cfg, server_task) = start_local_masque_server().await;
        // This tests target classification, not a TCP/TLS opening deadline.
        cfg.relay.connect_timeout_ms = 5_000;
        cfg.relay.transport_priority = vec![TunnelTransportFamily::LegacyTls];
        cfg.relay.policy.rotate_transports_per_session = false;
        cfg.relay.policy.max_transport_attempts = 1;

        let closed_target = StdTcpListener::bind("127.0.0.1:0").expect("bind closed target");
        let closed_port = closed_target
            .local_addr()
            .expect("closed target addr")
            .port();
        drop(closed_target);

        let (client, server, _peer) = tcp_pair().await;
        let runtime = RuntimeContext::from_settings(&cfg)
            .await
            .expect("build runtime context");
        let result = runtime
            .handle_session(
                BrokeredSession::TcpConnect(BrokeredTcpConnect {
                    ingress_kind: IngressKind::WidePrimary,
                    client: server,
                    target: ConnectTarget {
                        host: "127.0.0.1".into(),
                        port: closed_port,
                    },
                    dst: format!("127.0.0.1:{closed_port}")
                        .parse()
                        .expect("target socket addr"),
                }),
                &cfg,
                sample_wide_primary_ingress_context("aegisvh-target-error"),
            )
            .await;
        drop(client);
        server_task.abort();

        let err = result.expect_err("closed target should surface tunnel target error");
        let error_text = format!("{err:#}");
        assert!(
            error_text.contains("tunnel error")
                || error_text.contains("relay error: connect ")
                || error_text.contains("Connection refused")
                || error_text.contains("connection refused")
                || (cfg!(feature = "legacy-challenge-v1")
                    && error_text == "relay error: legacy target establishment failed"),
            "{error_text}"
        );

        let relay_failed = wait_for_event(
            &jsonl_path,
            start_index,
            RuntimeEventCode::RelayTransportFailed.as_str(),
        )
        .await;
        assert_eq!(relay_failed["fields"]["transport"], "LegacyTls");
        assert_eq!(relay_failed["fields"]["target"], "127.0.0.1");
        assert_eq!(relay_failed["fields"]["port"], closed_port);
        assert_eq!(
            relay_failed["fields"]["relay_failure_scope"],
            "tunnel_level_target_error"
        );
        assert_eq!(relay_failed["fields"]["relay_tunnel_status"], "bad_target");
        assert!(relay_failed["fields"]["relay_error_kind"].is_null());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn relay_tcp_reject_response_failed_emits_runtime_event() {
        let _runtime_lock = RUNTIME_JSONL_LOCK.lock().await;
        let jsonl_path = ensure_runtime_jsonl_path().clone();
        let start_index = read_jsonl_records(&jsonl_path).len();
        let (client, server, peer) = tcp_pair().await;
        force_reset(&client);
        drop(client);
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut cfg = Settings {
            mode: Mode::Relay,
            ..Settings::default()
        };
        cfg.relay.auth_token.clear();
        cfg.relay.transport_priority.clear();
        let mut intent = IngressSessionIntent {
            kind: IngressKind::Socks5Fallback,
            peer,
            transport: IngressTransport::TcpConnect(TcpConnectIntent {
                client: server,
                target: ConnectTarget {
                    host: "127.0.0.1".into(),
                    port: 443,
                },
                response: IngressResponse::Socks5,
                target_lease: None,
            }),
        };

        assert!(
            reject_tcp_connect_if_runtime_unready(&mut intent, &cfg, &sample_ingress_context())
                .await
        );
        let failed = wait_for_event(
            &jsonl_path,
            start_index,
            RuntimeEventCode::IngressTcpConnectRejectResponseFailed.as_str(),
        )
        .await;
        let rejected = wait_for_event(
            &jsonl_path,
            start_index,
            RuntimeEventCode::IngressTcpConnectRejected.as_str(),
        )
        .await;
        assert_eq!(failed["fields"]["request_kind"], "TcpConnect");
        assert_eq!(failed["fields"]["response_action"], "send_general_failure");
        assert_eq!(
            failed["fields"]["reject_reason_code"],
            "tcp_connect_requires_runtime_ready_relay_transport"
        );
        assert!(failed["fields"]["response_error_kind"].as_str().is_some());
        assert_eq!(rejected["fields"]["request_kind"], "TcpConnect");
        assert_eq!(
            rejected["fields"]["response_action"],
            "send_general_failure"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn direct_udp_reject_response_failed_emits_runtime_event() {
        let _runtime_lock = RUNTIME_JSONL_LOCK.lock().await;
        let jsonl_path = ensure_runtime_jsonl_path().clone();
        let start_index = read_jsonl_records(&jsonl_path).len();
        let (client, server, peer) = tcp_pair().await;
        force_reset(&client);
        drop(client);
        tokio::time::sleep(Duration::from_millis(50)).await;

        let cfg = Settings {
            mode: Mode::Direct,
            ..Settings::default()
        };
        let mut intent = IngressSessionIntent {
            kind: IngressKind::Socks5Fallback,
            peer,
            transport: IngressTransport::UdpAssociate(UdpAssociateIntent {
                control: UdpSessionControl::SocksControl(server),
                client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                response: IngressResponse::Socks5,
            }),
        };

        assert!(
            reject_udp_associate_if_runtime_unready(&mut intent, &cfg, &sample_ingress_context())
                .await
        );
        let failed = wait_for_event(
            &jsonl_path,
            start_index,
            RuntimeEventCode::IngressUdpAssociateRejectResponseFailed.as_str(),
        )
        .await;
        let rejected = wait_for_event(
            &jsonl_path,
            start_index,
            RuntimeEventCode::IngressUdpAssociateRejected.as_str(),
        )
        .await;
        assert_eq!(failed["fields"]["request_kind"], "UdpAssociate");
        assert_eq!(
            failed["fields"]["response_action"],
            "send_command_not_supported"
        );
        assert_eq!(
            failed["fields"]["reject_reason_code"],
            "udp_associate_requires_relay_mode"
        );
        assert!(failed["fields"]["response_error_kind"].as_str().is_some());
        assert_eq!(rejected["fields"]["request_kind"], "UdpAssociate");
        assert_eq!(
            rejected["fields"]["response_action"],
            "send_command_not_supported"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn grpc_only_udp_associate_is_rejected_before_broker_success() {
        let _runtime_lock = RUNTIME_JSONL_LOCK.lock().await;
        let (mut client, server, peer) = tcp_pair().await;
        let mut cfg = Settings {
            mode: Mode::Relay,
            ..Settings::default()
        };
        cfg.relay.server = "127.0.0.1:8443".into();
        cfg.relay.server_name = "localhost".into();
        cfg.relay.auth_token = "test-only".into();
        cfg.relay.udp_transport_priority = Some(vec![TunnelTransportFamily::GrpcDatagram]);
        assert!(relay::runtime_udp_fallback_ready(&cfg.relay));
        let mut intent = IngressSessionIntent {
            kind: IngressKind::Socks5Fallback,
            peer,
            transport: IngressTransport::UdpAssociate(UdpAssociateIntent {
                control: UdpSessionControl::SocksControl(server),
                client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                response: IngressResponse::Socks5,
            }),
        };
        assert!(
            reject_udp_associate_if_runtime_unready(&mut intent, &cfg, &sample_ingress_context())
                .await
        );
        let mut reply = [0u8; 10];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut reply))
            .await
            .expect("bounded SOCKS rejection")
            .expect("SOCKS response");
        assert_eq!(reply[0], 5);
        assert_eq!(
            reply[1], 1,
            "must reject before reporting a successful UDP bind"
        );
    }
}

fn log_ingress_startup_diagnostics(cfg: &Settings, report: &IngressStartupReport) {
    let wide_context_requested = wide_rollout_startup_context_requested(cfg);
    let wide_enabled = wide_context_requested.then_some(cfg.ingress.wide.enabled);
    let wide_supported = wide_context_requested.then_some(report.wide_supported());
    let wide_platform_family_supported =
        wide_context_requested.then_some(report.wide_platform_family_supported());
    let wide_runtime_readiness = wide_context_requested.then_some(report.wide_runtime_readiness());
    let wide_platform = wide_context_requested.then_some(cfg.ingress.wide.platform_backend);
    let wide_platform_code_value =
        wide_context_requested.then_some(wide_platform_code(cfg.ingress.wide.platform_backend));
    let wide_rollout_profile = wide_context_requested.then_some(cfg.ingress.wide.rollout_profile);
    let wide_rollout_profile_code_value = wide_context_requested
        .then_some(wide_rollout_profile_code(cfg.ingress.wide.rollout_profile));
    let wide_prerouting_interface = wide_context_requested
        .then_some(cfg.ingress.wide.prerouting_interface.as_deref())
        .flatten();
    let wide_listen = wide_context_requested.then_some(cfg.ingress.wide.listen.to_string());
    let wide_backend_current_stage = wide_context_requested
        .then_some(report.wide_backend_current_stage(cfg))
        .flatten();
    let wide_backend_scope_target = wide_context_requested
        .then_some(report.wide_backend_scope_target(cfg))
        .flatten();
    let wide_backend_reason_code = wide_context_requested
        .then_some(report.wide_backend_reason_code(cfg))
        .flatten();
    info!(
        event_code = RuntimeEventCode::IngressStartupPlanEvaluated.as_str(),
        requested_primary = ?cfg.ingress.primary,
        selected_backend = ?report.backend_choice(),
        fallback_reason_code = ?report.fallback_reason_code(),
        fallback_reason = report.fallback_reason(),
        allow_fallback = cfg.ingress.allow_fallback,
        wide_enabled = ?wide_enabled,
        wide_supported = ?wide_supported,
        wide_platform_family_supported = ?wide_platform_family_supported,
        wide_runtime_readiness = ?wide_runtime_readiness,
        wide_platform = ?wide_platform,
        wide_rollout_profile = ?wide_rollout_profile,
        wide_prerouting_interface = ?wide_prerouting_interface,
        wide_listen = ?wide_listen,
        socks_listen = %cfg.socks.listen,
        "evaluated ingress startup plan"
    );
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::IngressStartupPlanEvaluated,
        "evaluated ingress startup plan",
        json!({
            "requested_primary": format!("{:?}", cfg.ingress.primary),
            "requested_primary_code": ingress_primary_code(cfg.ingress.primary),
            "selected_backend": format!("{:?}", report.backend_choice()),
            "selected_backend_code": report.backend_choice().as_code(),
            "fallback_reason_code": report.fallback_reason_code(),
            "fallback_reason": report.fallback_reason(),
            "allow_fallback": cfg.ingress.allow_fallback,
            "wide_enabled": wide_enabled,
            "wide_supported": wide_supported,
            "wide_platform_family_supported": wide_platform_family_supported,
            "wide_runtime_readiness": wide_runtime_readiness,
            "wide_platform": wide_platform.map(|value| format!("{value:?}")),
            "wide_platform_code": wide_platform_code_value,
            "wide_rollout_profile": wide_rollout_profile.map(|value| format!("{value:?}")),
            "wide_rollout_profile_code": wide_rollout_profile_code_value,
            "wide_prerouting_interface": wide_prerouting_interface,
            "wide_backend_current_stage": wide_backend_current_stage,
            "wide_backend_scope_target": wide_backend_scope_target,
            "wide_backend_reason_code": wide_backend_reason_code,
            "wide_listen": wide_listen,
            "socks_listen": cfg.socks.listen.to_string()
        }),
    );

    for hint in report.hints() {
        match hint.severity {
            PreflightSeverity::Info => info!(
                event_code = RuntimeEventCode::IngressPreflightHint.as_str(),
                hint_code = ?hint.code,
                hint = hint.message,
                "ingress preflight"
            ),
            PreflightSeverity::Warn => warn!(
                event_code = RuntimeEventCode::IngressPreflightHint.as_str(),
                hint_code = ?hint.code,
                hint = hint.message,
                "ingress preflight"
            ),
        }
        runtime_jsonl::emit(
            match hint.severity {
                PreflightSeverity::Info => "info",
                PreflightSeverity::Warn => "warn",
            },
            RuntimeEventCode::IngressPreflightHint,
            "ingress preflight",
            json!({
                "hint_code": hint.code,
                "severity": match hint.severity {
                    PreflightSeverity::Info => "info",
                    PreflightSeverity::Warn => "warn",
                },
                "hint": hint.message
            }),
        );
    }

    if cfg.ingress.primary == IngressPrimary::Wide
        && matches!(
            report.backend_choice(),
            ActiveIngressBackend::Socks5Fallback
        )
    {
        warn!(
            event_code = RuntimeEventCode::IngressStartupFallbackSelected.as_str(),
            requested_primary = ?cfg.ingress.primary,
            listen = %cfg.socks.listen,
            fallback_reason_code = ?report.fallback_reason_code(),
            reason = report.fallback_reason().unwrap_or("wide ingress unavailable"),
            wide_enabled = cfg.ingress.wide.enabled,
            wide_supported = report.wide_supported(),
            wide_platform_family_supported = report.wide_platform_family_supported(),
            wide_runtime_readiness = ?report.wide_runtime_readiness(),
            wide_platform = ?cfg.ingress.wide.platform_backend,
            wide_rollout_profile = ?cfg.ingress.wide.rollout_profile,
            wide_prerouting_interface = ?cfg.ingress.wide.prerouting_interface,
            fallback_backend = "socks5_fallback",
            "wide ingress is unavailable during startup; using SOCKS5 fallback"
        );
        runtime_jsonl::emit(
            "warn",
            RuntimeEventCode::IngressStartupFallbackSelected,
            "wide ingress is unavailable during startup; using SOCKS5 fallback",
            json!({
                "requested_primary": format!("{:?}", cfg.ingress.primary),
                "requested_primary_code": ingress_primary_code(cfg.ingress.primary),
                "listen": cfg.socks.listen.to_string(),
                "fallback_reason_code": report.fallback_reason_code(),
                "reason": report.fallback_reason().unwrap_or("wide ingress unavailable"),
                "wide_enabled": cfg.ingress.wide.enabled,
                "wide_supported": report.wide_supported(),
                "wide_platform_family_supported": report.wide_platform_family_supported(),
                "wide_runtime_readiness": report.wide_runtime_readiness(),
                "wide_platform": format!("{:?}", cfg.ingress.wide.platform_backend),
                "wide_platform_code": wide_platform_code(cfg.ingress.wide.platform_backend),
                "wide_rollout_profile": format!("{:?}", cfg.ingress.wide.rollout_profile),
                "wide_rollout_profile_code": wide_rollout_profile_code(cfg.ingress.wide.rollout_profile),
                "wide_prerouting_interface": cfg.ingress.wide.prerouting_interface.as_deref(),
                "wide_backend_current_stage": report.wide_backend_current_stage(cfg),
                "wide_backend_scope_target": report.wide_backend_scope_target(cfg),
                "wide_backend_reason_code": report.wide_backend_reason_code(cfg),
                "fallback_backend": "socks5_fallback"
            }),
        );
    }
}

fn parse_external_calibration_snapshot(
    value: serde_json::Value,
) -> anyhow::Result<ExternalCalibrationSnapshot> {
    if value.get("event").and_then(serde_json::Value::as_str)
        == Some("external_calibration_summary")
    {
        return Ok(ExternalCalibrationSnapshot::from_summary_value(&value));
    }
    serde_json::from_value(value).context("parse external calibration snapshot")
}

async fn apply_external_calibration_summary(
    cfg: &Settings,
    summary_path: &Path,
) -> anyhow::Result<ExternalCalibrationSnapshot> {
    let summary_path = config::expand_tilde(summary_path);
    let value: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&summary_path)
            .with_context(|| format!("read external calibration {}", summary_path.display()))?,
    )
    .with_context(|| format!("parse external calibration {}", summary_path.display()))?;
    let snapshot = parse_external_calibration_snapshot(value)?;
    let state_path = config::expand_tilde(&cfg.direct.state_path);
    let store = AsyncStateStore::load(state_path.clone())
        .await
        .with_context(|| format!("state {}", state_path.display()))?;
    store
        .update(|state| {
            state.external_calibration = Some(snapshot.clone());
        })
        .await;
    store
        .flush()
        .await
        .with_context(|| format!("flush state {}", state_path.display()))?;
    runtime_jsonl::emit_external_calibration_applied(&snapshot);
    for prior in &snapshot.knowledge {
        runtime_jsonl::emit_knowledge_prior_applied(prior);
    }
    Ok(snapshot)
}

#[cfg(target_os = "linux")]
static NFQUEUE_STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(target_os = "linux")]
extern "C" fn nfqueue_stop_handler(_sig: libc::c_int) {
    NFQUEUE_STOP.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Opt-in entrypoint for the NFQUEUE observer backend lifecycle: preflight →
/// (optional) scoped rule setup → observer until SIGINT/SIGTERM → watchdog
/// teardown. ACCEPTs every packet (observer-only); the default Linux wide
/// backend stays TPROXY.
#[cfg(target_os = "linux")]
fn run_nfqueue_observer(queue: u16, args: &Args) -> anyhow::Result<()> {
    use crate::ingress::wide::nfqueue_lifecycle::{run_lifecycle_with_bridge, LifecycleOpts};
    use crate::ingress::wide::udp_masque_bridge::WideUdpMasqueBridge;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    // SAFETY: installing a trivial flag-setting signal handler.
    unsafe {
        libc::signal(
            libc::SIGINT,
            nfqueue_stop_handler as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            nfqueue_stop_handler as *const () as libc::sighandler_t,
        );
    }
    use crate::ingress::wide::nfqueue_socket::{NfqueueMode, NfqueuePolicy};
    let mut opts = LifecycleOpts::from_queue(queue);
    opts.setup_rules = args.nfqueue_setup_rules;
    opts.dports = args.nfqueue_dports.clone();
    if args.nfqueue_ipv4_only {
        opts.ipv6 = false;
    }
    if args.nfqueue_ipv6_only {
        opts.ipv4 = false;
    }
    // udp_policy = masque_direct implies the generic-UDP DROP (fail-closed)
    // plus an out-of-band MASQUE direct send leg.
    let udp_block = args.nfqueue_udp_block || args.nfqueue_udp_masque_direct;
    let mode_label = if args.nfqueue_enforce {
        opts.policy = NfqueuePolicy {
            mode: NfqueueMode::Enforce,
            udp_block,
            dns_block: args.nfqueue_dns_block,
            ipv6_block: args.nfqueue_ipv6_block,
        };
        "enforce (fail-closed)"
    } else {
        "observer-only"
    };

    // Build the MASQUE direct UDP send bridge only when explicitly selected and
    // generic UDP is being enforced (otherwise there is nothing to carry). If
    // the relay config cannot be loaded we fail-closed: UDP stays a plain DROP,
    // never a native fallback.
    let udp_masque_bridge: Option<WideUdpMasqueBridge> = if args.nfqueue_enforce
        && udp_block
        && args.nfqueue_udp_masque_direct
    {
        match config::load_config(config::expand_tilde(args.config.as_path())) {
            Ok(settings) => {
                let settings: Settings = settings;
                match WideUdpMasqueBridge::spawn(settings.relay) {
                    Ok(bridge) => {
                        eprintln!(
                            "aegis-client: nfqueue udp_policy=masque_direct (send-only carry; \
                                 generic UDP still fail-closed DROP; no native fallback)"
                        );
                        Some(bridge)
                    }
                    Err(e) => {
                        error!(error = %e, "masque_direct bridge unavailable; UDP remains fail-closed");
                        None
                    }
                }
            }
            Err(e) => {
                error!(error = %e, "masque_direct bridge config load failed; UDP remains fail-closed");
                None
            }
        }
    } else {
        None
    };
    eprintln!(
        "aegis-client: nfqueue lifecycle queue {queue} ({mode_label}; SIGINT/SIGTERM to stop)"
    );
    let stop = Arc::new(AtomicBool::new(false));
    // Bridge the C signal flag into the lifecycle stop flag.
    let stop_bridge = stop.clone();
    std::thread::spawn(move || loop {
        if NFQUEUE_STOP.load(std::sync::atomic::Ordering::SeqCst) {
            stop_bridge.store(true, std::sync::atomic::Ordering::SeqCst);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    });
    run_lifecycle_with_bridge(&opts, stop, udp_masque_bridge)
        .map_err(|reason| anyhow::anyhow!("nfqueue lifecycle: {reason}"))?;
    eprintln!("aegis-client: nfqueue lifecycle stopped cleanly");
    Ok(())
}

/// Entrypoint for the bidirectional generic-UDP redirect proxy. Loads the relay
/// config (for the MASQUE direct carry), binds the capture listener, and runs
/// until SIGINT/SIGTERM. If the relay config cannot be loaded we refuse to start
/// rather than risk a path that cannot carry — the firewall REDIRECT/DROP keeps
/// UDP fail-closed regardless, never native.
#[cfg(target_os = "linux")]
fn run_udp_redirect_proxy_cmd(port: u16, args: &Args) -> anyhow::Result<()> {
    use crate::ingress::wide::udp_redirect_proxy::{
        run_udp_redirect_proxy, UdpRedirectProxyConfig,
    };
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    // SAFETY: installing a trivial flag-setting signal handler (shared with the
    // nfqueue lifecycle stop flag).
    unsafe {
        libc::signal(
            libc::SIGINT,
            nfqueue_stop_handler as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            nfqueue_stop_handler as *const () as libc::sighandler_t,
        );
    }
    let settings: Settings = config::load_config(config::expand_tilde(args.config.as_path()))
        .with_context(|| format!("load config {}", args.config.display()))?;
    let listen_addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], port));
    let cfg = UdpRedirectProxyConfig::new(listen_addr, settings.relay);
    eprintln!(
        "aegis-client: udp redirect proxy on {listen_addr} (bidirectional MASQUE direct carry; \
         generic UDP fail-closed on error, never native; SIGINT/SIGTERM to stop)"
    );
    let stop = Arc::new(AtomicBool::new(false));
    let stop_bridge = stop.clone();
    std::thread::spawn(move || loop {
        if NFQUEUE_STOP.load(std::sync::atomic::Ordering::SeqCst) {
            stop_bridge.store(true, std::sync::atomic::Ordering::SeqCst);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    });
    run_udp_redirect_proxy(cfg, stop).map_err(|e| anyhow::anyhow!("udp redirect proxy: {e}"))?;
    eprintln!("aegis-client: udp redirect proxy stopped cleanly");
    Ok(())
}

/// Full-wide TUN profiles: launch the production IPv6 TUN+smoltcp engine on its
/// own thread alongside the v4 REDIRECT leg when
/// `[ingress.wide] ipv6_tun_carried=true`.
/// Carries IPv6 TCP+UDP to the relay (multi-target, fail-closed). The engine is
/// long-lived; on process exit the non-persistent TUN closes and the kernel
/// removes its `::/1`+`8000::/1` capture routes automatically, restoring the real
/// `::/0` (the in-engine RAII guard + stall watchdog cover an engine-only stop).
/// The IPv6 addresses the relay leg may dial (its primary `server` plus any
/// fronting-pool `endpoints`), collected so the IPv6 TUN engine can pin them off
/// the capture. Without this, a relay reached over IPv6 (a literal-IPv6 `server`,
/// or a hostname whose AAAA the dual-stack `TcpStream::connect` picks) lives
/// inside the `::/1`+`8000::/1` capture and the tunnel swallows its own egress
/// (relay loop). IPv4 endpoints are reached via the `::ffff:0:0/96` mapped range
/// the engine already excludes, so they are intentionally skipped here.
#[cfg(any(target_os = "linux", test))]
fn relay_ipv6_excludes(relay: &aegis_core::RelaySettings) -> Vec<std::net::IpAddr> {
    use std::net::{IpAddr, ToSocketAddrs};
    let mut hosts: Vec<&str> = Vec::new();
    if !relay.server.trim().is_empty() {
        hosts.push(relay.server.as_str());
    }
    for e in &relay.endpoints {
        if !e.server.trim().is_empty() {
            hosts.push(e.server.as_str());
        }
    }
    let mut out: Vec<IpAddr> = Vec::new();
    for h in hosts {
        // `server` is "host:port"; a literal IPv6 must be bracketed
        // ("[2606:4700::1]:443") to parse, which is exactly the relay-dial form.
        // to_socket_addrs resolves both A and AAAA via the system resolver.
        if let Ok(addrs) = h.to_socket_addrs() {
            for a in addrs {
                if let IpAddr::V6(v6) = a.ip() {
                    let ip = IpAddr::V6(v6);
                    if !out.contains(&ip) {
                        out.push(ip);
                    }
                }
            }
        }
    }
    // MASQUE direct overrides use SocketAddr literals in the actual dial path.
    // Include their IPv6 addresses without introducing another DNS lookup.
    for direct in relay.masque_server.iter().chain(
        relay
            .endpoints
            .iter()
            .filter_map(|endpoint| endpoint.masque_server.as_ref()),
    ) {
        if let Ok(address) = direct.parse::<SocketAddr>() {
            if let IpAddr::V6(v6) = address.ip() {
                let ip = IpAddr::V6(v6);
                if !out.contains(&ip) {
                    out.push(ip);
                }
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
async fn maybe_spawn_ipv6_tun_engine(
    cfg: &Settings,
    workers: &mut wide_workers::WideWorkers,
    forward_gate: crate::ingress::wide::forward_gate::ForwardGate,
) -> anyhow::Result<()> {
    use crate::ingress::wide::tun_smoltcp_engine::{run_tun_engine, TunEngineConfig};
    if !cfg.ingress.wide.ipv6_tun_carried {
        return Ok(());
    }
    // Structural loop-avoidance: while the TUN captures all IPv6, force the relay
    // TCP leg over IPv4 so it can never be dialed into the ::/1+8000::/1 capture
    // (a silent, self-amplifying loop the stall watchdog cannot see). The engine
    // already pins ::ffff:0:0/96 off the TUN, so an IPv4-dialed relay is exempt by
    // construction — no dependence on a spawn-time DNS snapshot of relay IPs.
    crate::relay::set_relay_force_ipv4(true);
    let mut engine_cfg = TunEngineConfig::new(cfg.relay.clone());
    engine_cfg.forward_gate = Some(forward_gate);
    // Belt-and-suspenders: also pin any literal/resolved IPv6 relay endpoint off
    // the TUN. With the forced-IPv4 dial above this is normally moot, but it keeps
    // the fail-closed refusal if a relay is ever reached over IPv6.
    engine_cfg.relay_excludes = relay_ipv6_excludes(&cfg.relay);
    workers
        .start(
            "aegis-tun-engine",
            std::time::Duration::from_secs(20),
            move |stop, ready| match run_tun_engine(engine_cfg, stop, ready) {
                Ok(stats) => eprintln!("aegis-client: ipv6 tun engine stopped: {stats:?}"),
                Err(e) => error!(error = %e, "ipv6 tun engine error"),
            },
        )
        .await
        .context("initialize required IPv6 capture worker")?;
    info!("ipv6 tun engine ready");
    Ok(())
}

/// The loopback port the generic-UDP redirect proxy should bind, or `None` when
/// generic UDP carry is not requested. Generic carry is opt-in via
/// `udp_capture_contract = generic_capture_unstable`; the port is the explicit
/// `udp_redirect_port`, else the wide `listen` port + 1.
#[cfg(target_os = "linux")]
fn wide_udp_redirect_proxy_port(cfg: &Settings) -> Option<u16> {
    if !cfg.ingress.wide.enabled
        || cfg.ingress.wide.udp_capture_contract != WideUdpCaptureContract::GenericCaptureUnstable
    {
        return None;
    }
    Some(
        cfg.ingress
            .wide
            .udp_redirect_port
            .unwrap_or_else(|| cfg.ingress.wide.listen.port().saturating_add(1)),
    )
}

/// Generic UDP + QUIC carry: when `udp_capture_contract=generic_capture_unstable`
/// the client must actually run the conntrack-based UDP redirect proxy (until
/// now it only ran as the standalone `--udp-redirect-proxy` subcommand, so the
/// daemon left generic UDP fail-closed). The wide firewall REDIRECTs generic UDP
/// (incl. QUIC/443, and DNS in carry mode) to this loopback port; the proxy
/// recovers the pre-NAT destination and carries each datagram through the
/// configured relay. Readiness requires a bound and configured listener;
/// subsequent worker exit fails the client.
#[cfg(target_os = "linux")]
async fn maybe_spawn_udp_redirect_proxy(
    cfg: &Settings,
    fake_ip_map: Option<Arc<crate::ingress::wide::dns_preview::FakeIpMap>>,
    workers: &mut wide_workers::WideWorkers,
    forward_gate: crate::ingress::wide::forward_gate::ForwardGate,
) -> anyhow::Result<()> {
    use crate::ingress::wide::udp_redirect_proxy::{
        run_udp_redirect_proxy_with_ready, UdpRedirectProxyConfig,
    };
    use std::net::SocketAddr;
    let Some(port) = wide_udp_redirect_proxy_port(cfg) else {
        return Ok(());
    };
    let listen_addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut proxy_cfg = UdpRedirectProxyConfig::new(listen_addr, cfg.relay.clone());
    proxy_cfg.fake_ip_map = fake_ip_map;
    proxy_cfg.forward_gate = Some(forward_gate);
    workers
        .start(
            "aegis-udp-proxy",
            std::time::Duration::from_secs(20),
            move |stop, ready| match run_udp_redirect_proxy_with_ready(proxy_cfg, stop, Some(ready))
            {
                Ok(()) => eprintln!("aegis-client: udp redirect proxy stopped"),
                Err(e) => error!(error = %e, "udp redirect proxy error"),
            },
        )
        .await
        .context("initialize required UDP capture worker")?;
    info!("udp redirect proxy ready");
    Ok(())
}

fn main() -> std::process::ExitCode {
    #[cfg(target_os = "linux")]
    {
        // Keep per-commit build identity in the executable crate. An unbound
        // development build may use ordinary CLI paths; native work refuses.
        let stamp = option_env!("AEGIS_BUILD_SOURCE_COMMIT").unwrap_or(BUILD_GIT_SHA);
        let _ = aegis_core::relay_geneva::linux::install_build_source_stamp(stamp);
    }
    #[cfg(target_os = "linux")]
    let _launch_lease = {
        let mut arguments = std::env::args_os().skip(1);
        if arguments.next().as_deref() == Some(std::ffi::OsStr::new("auto-owned-service")) {
            let Some(unit) = arguments.next() else {
                return std::process::ExitCode::FAILURE;
            };
            let Some(unit) = unit.to_str() else {
                return std::process::ExitCode::FAILURE;
            };
            match profile_auto_launch_service::acquire(unit) {
                Ok(lease) => Some(lease),
                Err(reason) => {
                    eprintln!("{reason}");
                    return std::process::ExitCode::FAILURE;
                }
            }
        } else {
            None
        }
    };
    #[cfg(target_os = "linux")]
    {
        let mut arguments = std::env::args_os().skip(1);
        let command = arguments.next();
        if matches!(command.as_deref(),
            Some(value) if value == std::ffi::OsStr::new("verify-retired-passive-successor")
                || value == std::ffi::OsStr::new("verify-passive-retirement-intent"))
        {
            if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--lock-fd")) {
                return std::process::ExitCode::FAILURE;
            }
            let Some(fd) = arguments.next().and_then(|value| {
                value.to_str().and_then(|value| {
                    if value.is_empty()
                        || value.len() > 10
                        || value.starts_with('0')
                        || !value.bytes().all(|byte| byte.is_ascii_digit())
                    {
                        return None;
                    }
                    value.parse::<i32>().ok().filter(|fd| *fd > 2)
                })
            }) else {
                return std::process::ExitCode::FAILURE;
            };
            if arguments.next().is_some() {
                return std::process::ExitCode::FAILURE;
            }
            let verified = if command.as_deref()
                == Some(std::ffi::OsStr::new("verify-passive-retirement-intent"))
            {
                profile_auto_transaction::verify_passive_retirement_intent_inherited(fd)
            } else {
                profile_auto_transaction::verify_retired_passive_successor_inherited(fd)
            };
            return match verified {
                Ok(bytes) => {
                    use std::io::Write;
                    if std::io::stdout().write_all(&bytes).is_ok() {
                        std::process::ExitCode::SUCCESS
                    } else {
                        std::process::ExitCode::FAILURE
                    }
                }
                Err(_) => {
                    eprintln!("AUTO passive retired successor verification refused");
                    std::process::ExitCode::FAILURE
                }
            };
        }
        if command.as_deref() == Some(std::ffi::OsStr::new("verify-retired-successor")) {
            fn descriptor(value: Option<std::ffi::OsString>) -> Option<i32> {
                let value = value?;
                let value = value.to_str()?;
                if value.is_empty()
                    || value.len() > 10
                    || value.starts_with('0')
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return None;
                }
                value.parse::<i32>().ok().filter(|fd| *fd > 2)
            }
            if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--lock-fd")) {
                return std::process::ExitCode::FAILURE;
            }
            let Some(install_fd) = descriptor(arguments.next()) else {
                return std::process::ExitCode::FAILURE;
            };
            if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--guard-fd")) {
                return std::process::ExitCode::FAILURE;
            }
            let Some(guard_fd) = descriptor(arguments.next()) else {
                return std::process::ExitCode::FAILURE;
            };
            if install_fd == guard_fd || arguments.next().is_some() {
                return std::process::ExitCode::FAILURE;
            }
            return match profile_auto_transaction::verify_retired_successor_inherited(
                install_fd, guard_fd,
            ) {
                Ok(bytes) => {
                    use std::io::Write;
                    if std::io::stdout().write_all(&bytes).is_ok() {
                        std::process::ExitCode::SUCCESS
                    } else {
                        std::process::ExitCode::FAILURE
                    }
                }
                Err(_) => {
                    eprintln!("AUTO retired successor verification refused");
                    std::process::ExitCode::FAILURE
                }
            };
        }
        if command.as_deref() == Some(std::ffi::OsStr::new("auto-launch-cold-recovery"))
            || command.as_deref() == Some(std::ffi::OsStr::new("auto-launch-cold-rollover"))
        {
            let stale_rollover =
                command.as_deref() == Some(std::ffi::OsStr::new("auto-launch-cold-rollover"));
            if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--retained-root")) {
                return std::process::ExitCode::FAILURE;
            }
            let Some(root) = arguments.next() else {
                return std::process::ExitCode::FAILURE;
            };
            if arguments.next().is_some() {
                return std::process::ExitCode::FAILURE;
            }
            let result = if stale_rollover {
                profile_auto_transaction::launch_cold_rollover(std::path::Path::new(&root))
            } else {
                profile_auto_transaction::launch_cold_recovery(std::path::Path::new(&root))
            };
            return match result {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(_) => {
                    eprintln!("AUTO cold launcher refused");
                    std::process::ExitCode::FAILURE
                }
            };
        }
        if command.as_deref() == Some(std::ffi::OsStr::new("auto-retire-cold-unpublished-stage")) {
            if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--retained-root")) {
                return std::process::ExitCode::FAILURE;
            }
            let Some(root) = arguments.next() else {
                return std::process::ExitCode::FAILURE;
            };
            let root = std::path::Path::new(&root);
            if !root.is_absolute()
                || arguments.next().as_deref()
                    != Some(std::ffi::OsStr::new("--prior-intent-sha256"))
            {
                return std::process::ExitCode::FAILURE;
            }
            let Some(prior) = arguments.next() else {
                return std::process::ExitCode::FAILURE;
            };
            let Some(prior) = prior.to_str() else {
                return std::process::ExitCode::FAILURE;
            };
            if prior.len() != 64
                || !prior
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                || arguments.next().is_some()
            {
                return std::process::ExitCode::FAILURE;
            }
            return match profile_auto_transaction::retire_cold_unpublished_stage(root, prior) {
                Ok(bytes) => {
                    use std::io::Write;
                    if std::io::stdout().write_all(&bytes).is_ok() {
                        std::process::ExitCode::SUCCESS
                    } else {
                        std::process::ExitCode::FAILURE
                    }
                }
                Err(_) => {
                    eprintln!("AUTO unpublished stage retirement refused");
                    std::process::ExitCode::FAILURE
                }
            };
        }
        if command.as_deref() == Some(std::ffi::OsStr::new("auto-complete-cold-orphan-head")) {
            if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--retained-root")) {
                return std::process::ExitCode::FAILURE;
            }
            let Some(root) = arguments.next() else {
                return std::process::ExitCode::FAILURE;
            };
            let root = std::path::Path::new(&root);
            if !root.is_absolute()
                || arguments.next().as_deref()
                    != Some(std::ffi::OsStr::new("--prior-intent-sha256"))
            {
                return std::process::ExitCode::FAILURE;
            }
            let Some(prior) = arguments.next() else {
                return std::process::ExitCode::FAILURE;
            };
            let Some(prior) = prior.to_str() else {
                return std::process::ExitCode::FAILURE;
            };
            if prior.len() != 64
                || !prior
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                || arguments.next().is_some()
            {
                return std::process::ExitCode::FAILURE;
            }
            return match profile_auto_transaction::complete_cold_orphan_head(root, prior) {
                Ok(bytes) => {
                    use std::io::Write;
                    if std::io::stdout().write_all(&bytes).is_ok() {
                        std::process::ExitCode::SUCCESS
                    } else {
                        std::process::ExitCode::FAILURE
                    }
                }
                Err(_) => {
                    eprintln!("AUTO orphan head completion refused");
                    std::process::ExitCode::FAILURE
                }
            };
        }
        if command.as_deref() == Some(std::ffi::OsStr::new("auto-retire-cold-prior-pointer")) {
            if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--retained-root")) {
                return std::process::ExitCode::FAILURE;
            }
            let Some(root) = arguments.next() else {
                return std::process::ExitCode::FAILURE;
            };
            let root = std::path::Path::new(&root);
            if !root.is_absolute()
                || arguments.next().as_deref()
                    != Some(std::ffi::OsStr::new("--prior-intent-sha256"))
            {
                return std::process::ExitCode::FAILURE;
            }
            let Some(prior) = arguments.next() else {
                return std::process::ExitCode::FAILURE;
            };
            let Some(prior) = prior.to_str() else {
                return std::process::ExitCode::FAILURE;
            };
            if prior.len() != 64
                || !prior
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                || arguments.next().is_some()
            {
                return std::process::ExitCode::FAILURE;
            }
            return match profile_auto_transaction::retire_cold_prior_pointer(root, prior) {
                Ok(bytes) => {
                    use std::io::Write;
                    if std::io::stdout().write_all(&bytes).is_ok() {
                        std::process::ExitCode::SUCCESS
                    } else {
                        std::process::ExitCode::FAILURE
                    }
                }
                Err(_) => {
                    eprintln!("AUTO prior pointer retirement refused");
                    std::process::ExitCode::FAILURE
                }
            };
        }
        if command.as_deref() == Some(std::ffi::OsStr::new("auto-verify-cold-stale"))
            || command.as_deref() == Some(std::ffi::OsStr::new("auto-verify-cold-stale-preretire"))
        {
            let preretire = command.as_deref()
                == Some(std::ffi::OsStr::new("auto-verify-cold-stale-preretire"));
            if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--retained-root")) {
                return std::process::ExitCode::FAILURE;
            }
            let Some(root) = arguments.next() else {
                return std::process::ExitCode::FAILURE;
            };
            let root = std::path::Path::new(&root);
            if !root.is_absolute()
                || arguments.next().as_deref()
                    != Some(std::ffi::OsStr::new("--prior-intent-sha256"))
            {
                return std::process::ExitCode::FAILURE;
            }
            let Some(prior) = arguments.next() else {
                return std::process::ExitCode::FAILURE;
            };
            let Some(prior) = prior.to_str() else {
                return std::process::ExitCode::FAILURE;
            };
            if prior.len() != 64
                || !prior
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                || arguments.next().is_some()
            {
                return std::process::ExitCode::FAILURE;
            }
            let result = if preretire {
                profile_auto_transaction::verify_cold_stale_preretire_fresh(root, prior)
            } else {
                profile_auto_transaction::verify_cold_stale_fresh(root, prior)
            };
            return match result {
                Ok(bytes) => {
                    use std::io::Write;
                    if std::io::stdout().write_all(&bytes).is_ok() {
                        std::process::ExitCode::SUCCESS
                    } else {
                        std::process::ExitCode::FAILURE
                    }
                }
                Err(_) => {
                    eprintln!("AUTO cold stale verification refused");
                    std::process::ExitCode::FAILURE
                }
            };
        }
        if command.as_deref() == Some(std::ffi::OsStr::new("auto-verify-cold-stale-inherited"))
            || command.as_deref()
                == Some(std::ffi::OsStr::new(
                    "auto-verify-cold-stale-preretire-inherited",
                ))
            || command.as_deref()
                == Some(std::ffi::OsStr::new("auto-verify-cold-attempt-inherited"))
        {
            let preretire = command.as_deref()
                == Some(std::ffi::OsStr::new(
                    "auto-verify-cold-stale-preretire-inherited",
                ));
            let attempt = command.as_deref()
                == Some(std::ffi::OsStr::new("auto-verify-cold-attempt-inherited"));
            fn descriptor(value: Option<std::ffi::OsString>) -> Option<i32> {
                let value = value?;
                let value = value.to_str()?;
                if value.is_empty()
                    || value.len() > 10
                    || value.starts_with('0')
                    || !value.bytes().all(|b| b.is_ascii_digit())
                {
                    return None;
                }
                value.parse::<i32>().ok().filter(|fd| *fd > 2)
            }
            if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--lock-fd")) {
                return std::process::ExitCode::FAILURE;
            }
            let Some(install_fd) = descriptor(arguments.next()) else {
                return std::process::ExitCode::FAILURE;
            };
            if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--guard-fd")) {
                return std::process::ExitCode::FAILURE;
            }
            let Some(guard_fd) = descriptor(arguments.next()) else {
                return std::process::ExitCode::FAILURE;
            };
            if install_fd == guard_fd
                || arguments.next().as_deref() != Some(std::ffi::OsStr::new("--retained-root"))
            {
                return std::process::ExitCode::FAILURE;
            }
            let Some(root) = arguments.next() else {
                return std::process::ExitCode::FAILURE;
            };
            let root = std::path::Path::new(&root);
            if !root.is_absolute() {
                return std::process::ExitCode::FAILURE;
            }
            let result = if attempt {
                if arguments.next().is_some() {
                    return std::process::ExitCode::FAILURE;
                }
                profile_auto_transaction::verify_cold_attempt_inherited(install_fd, guard_fd, root)
            } else {
                if arguments.next().as_deref()
                    != Some(std::ffi::OsStr::new("--prior-intent-sha256"))
                {
                    return std::process::ExitCode::FAILURE;
                }
                let Some(prior) = arguments.next() else {
                    return std::process::ExitCode::FAILURE;
                };
                let Some(prior) = prior.to_str() else {
                    return std::process::ExitCode::FAILURE;
                };
                if prior.len() != 64
                    || !prior
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                    || arguments.next().is_some()
                {
                    return std::process::ExitCode::FAILURE;
                }
                if preretire {
                    profile_auto_transaction::verify_cold_stale_preretire_inherited(
                        install_fd, guard_fd, root, prior,
                    )
                } else {
                    profile_auto_transaction::verify_cold_stale_inherited(
                        install_fd, guard_fd, root, prior,
                    )
                }
            };
            return match result {
                Ok(bytes) => {
                    use std::io::Write;
                    if std::io::stdout().write_all(&bytes).is_ok() {
                        std::process::ExitCode::SUCCESS
                    } else {
                        std::process::ExitCode::FAILURE
                    }
                }
                Err(_) => {
                    eprintln!("AUTO cold stale verification refused");
                    std::process::ExitCode::FAILURE
                }
            };
        }
        if command.as_deref()
            == Some(std::ffi::OsStr::new(
                "auto-verify-cold-history-archive-inherited",
            ))
        {
            fn descriptor(value: Option<std::ffi::OsString>) -> Option<i32> {
                let value = value?;
                let value = value.to_str()?;
                if value.is_empty()
                    || value.len() > 10
                    || value.starts_with('0')
                    || !value.bytes().all(|b| b.is_ascii_digit())
                {
                    return None;
                }
                value.parse::<i32>().ok().filter(|fd| *fd > 2)
            }
            if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--lock-fd")) {
                return std::process::ExitCode::FAILURE;
            }
            let Some(install_fd) = descriptor(arguments.next()) else {
                return std::process::ExitCode::FAILURE;
            };
            if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--guard-fd")) {
                return std::process::ExitCode::FAILURE;
            }
            let Some(guard_fd) = descriptor(arguments.next()) else {
                return std::process::ExitCode::FAILURE;
            };
            if install_fd == guard_fd
                || arguments.next().as_deref() != Some(std::ffi::OsStr::new("--retained-root"))
            {
                return std::process::ExitCode::FAILURE;
            }
            let Some(root) = arguments.next() else {
                return std::process::ExitCode::FAILURE;
            };
            let root = std::path::Path::new(&root);
            if !root.is_absolute()
                || arguments.next().as_deref()
                    != Some(std::ffi::OsStr::new("--ordinary-pending-sha256"))
            {
                return std::process::ExitCode::FAILURE;
            }
            let Some(pending) = arguments.next() else {
                return std::process::ExitCode::FAILURE;
            };
            let Some(pending) = pending.to_str() else {
                return std::process::ExitCode::FAILURE;
            };
            if pending.len() != 64
                || !pending
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                || arguments.next().is_some()
            {
                return std::process::ExitCode::FAILURE;
            }
            return match profile_auto_transaction::verify_cold_history_archive_inherited(
                install_fd, guard_fd, root, pending,
            ) {
                Ok(bytes) => {
                    use std::io::Write;
                    if std::io::stdout().write_all(&bytes).is_ok() {
                        std::process::ExitCode::SUCCESS
                    } else {
                        std::process::ExitCode::FAILURE
                    }
                }
                Err(_) => {
                    eprintln!("AUTO cold history archive verification refused");
                    std::process::ExitCode::FAILURE
                }
            };
        }
        if command.as_deref() == Some(std::ffi::OsStr::new("auto-verify-cold-retired-successor")) {
            fn descriptor(value: Option<std::ffi::OsString>) -> Option<i32> {
                let value = value?;
                let value = value.to_str()?;
                if value.is_empty()
                    || value.len() > 10
                    || value.starts_with('0')
                    || !value.bytes().all(|b| b.is_ascii_digit())
                {
                    return None;
                }
                value.parse::<i32>().ok().filter(|fd| *fd > 2)
            }
            if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--lock-fd")) {
                return std::process::ExitCode::FAILURE;
            }
            let Some(install_fd) = descriptor(arguments.next()) else {
                return std::process::ExitCode::FAILURE;
            };
            if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--guard-fd")) {
                return std::process::ExitCode::FAILURE;
            }
            let Some(guard_fd) = descriptor(arguments.next()) else {
                return std::process::ExitCode::FAILURE;
            };
            if install_fd == guard_fd
                || arguments.next().as_deref() != Some(std::ffi::OsStr::new("--retained-root"))
            {
                return std::process::ExitCode::FAILURE;
            }
            let Some(root) = arguments.next() else {
                return std::process::ExitCode::FAILURE;
            };
            let root = std::path::Path::new(&root);
            if arguments.next().is_some() || !root.is_absolute() {
                return std::process::ExitCode::FAILURE;
            }
            return match profile_auto_transaction::verify_cold_retired_successor_inherited(
                install_fd, guard_fd, root,
            ) {
                Ok(bytes) => {
                    use std::io::Write;
                    if std::io::stdout().write_all(&bytes).is_ok() {
                        std::process::ExitCode::SUCCESS
                    } else {
                        std::process::ExitCode::FAILURE
                    }
                }
                Err(_) => {
                    eprintln!("AUTO cold retired successor verification refused");
                    std::process::ExitCode::FAILURE
                }
            };
        }
        if command.as_deref() == Some(std::ffi::OsStr::new("auto-verify-cold-prebind-inherited"))
            || command.as_deref()
                == Some(std::ffi::OsStr::new(
                    "auto-verify-cold-transition-inherited",
                ))
        {
            let transition = command.as_deref()
                == Some(std::ffi::OsStr::new(
                    "auto-verify-cold-transition-inherited",
                ));
            fn descriptor(value: Option<std::ffi::OsString>) -> Option<i32> {
                let value = value?;
                let value = value.to_str()?;
                if value.is_empty()
                    || value.len() > 10
                    || value.starts_with('0')
                    || !value.bytes().all(|b| b.is_ascii_digit())
                {
                    return None;
                }
                value.parse::<i32>().ok().filter(|fd| *fd > 2)
            }
            if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--lock-fd")) {
                return std::process::ExitCode::FAILURE;
            }
            let Some(install_fd) = descriptor(arguments.next()) else {
                return std::process::ExitCode::FAILURE;
            };
            if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--guard-fd")) {
                return std::process::ExitCode::FAILURE;
            }
            let Some(guard_fd) = descriptor(arguments.next()) else {
                return std::process::ExitCode::FAILURE;
            };
            if install_fd == guard_fd
                || arguments.next().as_deref() != Some(std::ffi::OsStr::new("--retained-root"))
            {
                return std::process::ExitCode::FAILURE;
            }
            let Some(root) = arguments.next() else {
                return std::process::ExitCode::FAILURE;
            };
            if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--intent-sha256")) {
                return std::process::ExitCode::FAILURE;
            }
            let Some(sha) = arguments.next() else {
                return std::process::ExitCode::FAILURE;
            };
            let Some(sha) = sha.to_str() else {
                return std::process::ExitCode::FAILURE;
            };
            let root = std::path::Path::new(&root);
            if arguments.next().is_some()
                || !root.is_absolute()
                || sha.len() != 64
                || !sha
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return std::process::ExitCode::FAILURE;
            }
            let result = if transition {
                profile_auto_transaction::verify_cold_transition_inherited(
                    install_fd, guard_fd, root, sha,
                )
            } else {
                profile_auto_transaction::verify_cold_prebind_inherited(
                    install_fd, guard_fd, root, sha,
                )
            };
            return match result {
                Ok(bytes) => {
                    use std::io::Write;
                    if std::io::stdout().write_all(&bytes).is_ok() {
                        std::process::ExitCode::SUCCESS
                    } else {
                        std::process::ExitCode::FAILURE
                    }
                }
                Err(_) => {
                    eprintln!("AUTO inherited cold prebind verification refused");
                    std::process::ExitCode::FAILURE
                }
            };
        }
        if command.as_deref() == Some(std::ffi::OsStr::new("auto-retire-cold-successor")) {
            if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--retained-root")) {
                return std::process::ExitCode::FAILURE;
            }
            let Some(root) = arguments.next() else {
                return std::process::ExitCode::FAILURE;
            };
            if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--intent-sha256")) {
                return std::process::ExitCode::FAILURE;
            }
            let Some(sha) = arguments.next() else {
                return std::process::ExitCode::FAILURE;
            };
            let Some(sha) = sha.to_str() else {
                return std::process::ExitCode::FAILURE;
            };
            let root = std::path::Path::new(&root);
            if arguments.next().is_some()
                || !root.is_absolute()
                || sha.len() != 64
                || !sha
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return std::process::ExitCode::FAILURE;
            }
            return match profile_auto_transaction::retire_cold_successor(root, sha) {
                Ok(bytes) => {
                    use std::io::Write;
                    if std::io::stdout().write_all(&bytes).is_ok() {
                        std::process::ExitCode::SUCCESS
                    } else {
                        std::process::ExitCode::FAILURE
                    }
                }
                Err(_) => {
                    eprintln!("AUTO cold successor retirement refused");
                    std::process::ExitCode::FAILURE
                }
            };
        }
        if command.as_deref() == Some(std::ffi::OsStr::new("auto-verify-cold-prebind")) {
            if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--retained-root")) {
                return std::process::ExitCode::FAILURE;
            }
            let Some(root) = arguments.next() else {
                return std::process::ExitCode::FAILURE;
            };
            if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--intent-sha256")) {
                return std::process::ExitCode::FAILURE;
            }
            let Some(sha) = arguments.next() else {
                return std::process::ExitCode::FAILURE;
            };
            let Some(sha) = sha.to_str() else {
                return std::process::ExitCode::FAILURE;
            };
            let root = std::path::Path::new(&root);
            if arguments.next().is_some()
                || !root.is_absolute()
                || sha.len() != 64
                || !sha
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return std::process::ExitCode::FAILURE;
            }
            return match profile_auto_transaction::verify_cold_prebind(root, sha) {
                Ok(bytes) => {
                    use std::io::Write;
                    if std::io::stdout().write_all(&bytes).is_ok() {
                        std::process::ExitCode::SUCCESS
                    } else {
                        std::process::ExitCode::FAILURE
                    }
                }
                Err(_) => {
                    eprintln!("AUTO cold prebind verification refused");
                    std::process::ExitCode::FAILURE
                }
            };
        }
        if command.as_deref() == Some(std::ffi::OsStr::new("auto-begin-cold-first-arm")) {
            if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--retained-root")) {
                return std::process::ExitCode::FAILURE;
            }
            let Some(root) = arguments.next() else {
                return std::process::ExitCode::FAILURE;
            };
            let root = std::path::Path::new(&root);
            if arguments.next().is_some() || !root.is_absolute() {
                return std::process::ExitCode::FAILURE;
            }
            return match profile_auto_transaction::begin_cold_first_arm(root) {
                Ok(bytes) => {
                    use std::io::Write;
                    if std::io::stdout().write_all(&bytes).is_ok() {
                        std::process::ExitCode::SUCCESS
                    } else {
                        std::process::ExitCode::FAILURE
                    }
                }
                Err(_) => {
                    eprintln!("AUTO cold first-arm refused");
                    std::process::ExitCode::FAILURE
                }
            };
        }
        if command.as_deref() == Some(std::ffi::OsStr::new("auto-verify-cold-active")) {
            if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--retained-root")) {
                return std::process::ExitCode::FAILURE;
            }
            let Some(root) = arguments.next() else {
                return std::process::ExitCode::FAILURE;
            };
            if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--intent-sha256")) {
                return std::process::ExitCode::FAILURE;
            }
            let Some(sha) = arguments.next() else {
                return std::process::ExitCode::FAILURE;
            };
            let Some(sha) = sha.to_str() else {
                return std::process::ExitCode::FAILURE;
            };
            let root = std::path::Path::new(&root);
            if arguments.next().is_some()
                || !root.is_absolute()
                || sha.len() != 64
                || !sha
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return std::process::ExitCode::FAILURE;
            }
            return match profile_auto_transaction::verify_cold_active(root, sha) {
                Ok(bytes) => {
                    use std::io::Write;
                    if std::io::stdout().write_all(&bytes).is_ok() {
                        std::process::ExitCode::SUCCESS
                    } else {
                        std::process::ExitCode::FAILURE
                    }
                }
                Err(_) => {
                    eprintln!("AUTO cold active verification refused");
                    std::process::ExitCode::FAILURE
                }
            };
        }
        if command.as_deref() == Some(std::ffi::OsStr::new("auto-verify-current-socks")) {
            if arguments.next().is_some() {
                return std::process::ExitCode::FAILURE;
            }
            return match profile_auto_transaction::verify_current_socks_generation() {
                Ok(bytes) => {
                    use std::io::Write;
                    if std::io::stdout().write_all(&bytes).is_ok()
                        && std::io::stdout().write_all(b"\n").is_ok()
                    {
                        std::process::ExitCode::SUCCESS
                    } else {
                        std::process::ExitCode::FAILURE
                    }
                }
                Err(_) => std::process::ExitCode::FAILURE,
            };
        }
        if command.as_deref() == Some(std::ffi::OsStr::new("auto-passive-transition-status")) {
            if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--lock-fd")) {
                return std::process::ExitCode::FAILURE;
            }
            let Some(raw) = arguments.next() else {
                return std::process::ExitCode::FAILURE;
            };
            let Some(value) = raw.to_str() else {
                return std::process::ExitCode::FAILURE;
            };
            if value.is_empty()
                || value.len() > 10
                || value.starts_with('0')
                || !value.bytes().all(|byte| byte.is_ascii_digit())
                || arguments.next().is_some()
            {
                return std::process::ExitCode::FAILURE;
            }
            let Ok(fd) = value.parse::<i32>() else {
                return std::process::ExitCode::FAILURE;
            };
            if fd <= 2 {
                return std::process::ExitCode::FAILURE;
            }
            return match profile_auto_transaction::passive_transition_status_inherited(fd) {
                Ok(bytes) => {
                    use std::io::Write;
                    if std::io::stdout().write_all(&bytes).is_ok()
                        && std::io::stdout().write_all(b"\n").is_ok()
                    {
                        std::process::ExitCode::SUCCESS
                    } else {
                        std::process::ExitCode::FAILURE
                    }
                }
                Err(_) => std::process::ExitCode::FAILURE,
            };
        }
        if command.as_deref()
            == Some(std::ffi::OsStr::new(
                "auto-advance-completed-passive-transition",
            ))
        {
            if arguments.next().is_some() {
                return std::process::ExitCode::FAILURE;
            }
            return match profile_auto_transaction::advance_completed_passive_transition() {
                Ok(bytes) => {
                    use std::io::Write;
                    if std::io::stdout().write_all(&bytes).is_ok()
                        && std::io::stdout().write_all(b"\n").is_ok()
                    {
                        std::process::ExitCode::SUCCESS
                    } else {
                        std::process::ExitCode::FAILURE
                    }
                }
                Err(_) => std::process::ExitCode::FAILURE,
            };
        }
        if command.as_deref() == Some(std::ffi::OsStr::new("auto-verify-passive-compensated")) {
            if arguments.next().is_some() {
                return std::process::ExitCode::FAILURE;
            }
            return match profile_auto_transaction::verify_passive_compensated_stage() {
                Ok(bytes) => {
                    use std::io::Write;
                    if std::io::stdout().write_all(&bytes).is_ok()
                        && std::io::stdout().write_all(b"\n").is_ok()
                    {
                        std::process::ExitCode::SUCCESS
                    } else {
                        std::process::ExitCode::FAILURE
                    }
                }
                Err(_) => std::process::ExitCode::FAILURE,
            };
        }
        if command.as_deref() == Some(std::ffi::OsStr::new("auto-rollback-fresh-prebind")) {
            let (Some(stage), Some(flag), Some(root)) =
                (arguments.next(), arguments.next(), arguments.next())
            else {
                return std::process::ExitCode::FAILURE;
            };
            if flag != "--public-payload-root" || arguments.next().is_some() {
                return std::process::ExitCode::FAILURE;
            }
            return match profile_auto_transaction::rollback_fresh_prebind(
                Path::new(&stage),
                Path::new(&root),
            ) {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(_) => std::process::ExitCode::FAILURE,
            };
        }
        if command.as_deref() == Some(std::ffi::OsStr::new("auto-verify-fresh-rolled-back")) {
            let (Some(stage), Some(archive), Some(flag), Some(fd)) = (
                arguments.next(),
                arguments.next(),
                arguments.next(),
                arguments.next(),
            ) else {
                return std::process::ExitCode::FAILURE;
            };
            if flag != "--lock-fd" || arguments.next().is_some() {
                return std::process::ExitCode::FAILURE;
            }
            let Some(archive) = archive.to_str() else {
                return std::process::ExitCode::FAILURE;
            };
            let Some(fd) = fd.to_str().and_then(|value| {
                if value.is_empty()
                    || value.len() > 10
                    || value.starts_with('0')
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                {
                    None
                } else {
                    value.parse::<i32>().ok().filter(|fd| *fd > 2)
                }
            }) else {
                return std::process::ExitCode::FAILURE;
            };
            return match profile_auto_transaction::verify_fresh_rolled_back_inherited(
                Path::new(&stage),
                archive,
                fd,
            ) {
                Ok(bytes) => {
                    use std::io::Write;
                    if std::io::stdout().write_all(&bytes).is_ok()
                        && std::io::stdout().write_all(b"\n").is_ok()
                    {
                        std::process::ExitCode::SUCCESS
                    } else {
                        std::process::ExitCode::FAILURE
                    }
                }
                Err(_) => std::process::ExitCode::FAILURE,
            };
        }
        if command.as_deref() == Some(std::ffi::OsStr::new("auto-verify-passive-unsealed-stopped"))
        {
            if arguments.next().is_some() {
                return std::process::ExitCode::FAILURE;
            }
            return match profile_auto_transaction::verify_passive_unsealed_stopped_stage() {
                Ok(bytes) => {
                    use std::io::Write;
                    if std::io::stdout().write_all(&bytes).is_ok()
                        && std::io::stdout().write_all(b"\n").is_ok()
                    {
                        std::process::ExitCode::SUCCESS
                    } else {
                        std::process::ExitCode::FAILURE
                    }
                }
                Err(_) => std::process::ExitCode::FAILURE,
            };
        }
        if command.as_deref() == Some(std::ffi::OsStr::new("auto-resume-passive-unsealed-stopped"))
        {
            if arguments.next().is_some() {
                return std::process::ExitCode::FAILURE;
            }
            return match profile_auto_transaction::resume_passive_unsealed_stopped_stage() {
                Ok(bytes) => {
                    use std::io::Write;
                    if std::io::stdout().write_all(&bytes).is_ok()
                        && std::io::stdout().write_all(b"\n").is_ok()
                    {
                        std::process::ExitCode::SUCCESS
                    } else {
                        std::process::ExitCode::FAILURE
                    }
                }
                Err(_) => std::process::ExitCode::FAILURE,
            };
        }
        if command.as_deref() == Some(std::ffi::OsStr::new("auto-uninstall-observe-reboot")) {
            if arguments.next().is_some() {
                return std::process::ExitCode::FAILURE;
            }
            return match profile_auto_transaction::uninstall_observe_reboot() {
                Ok(bytes) => {
                    use std::io::Write;
                    if std::io::stdout().write_all(&bytes).is_ok()
                        && std::io::stdout().write_all(b"\n").is_ok()
                    {
                        std::process::ExitCode::SUCCESS
                    } else {
                        std::process::ExitCode::FAILURE
                    }
                }
                Err(_) => {
                    eprintln!("AUTO uninstall reboot observation refused");
                    std::process::ExitCode::FAILURE
                }
            };
        }
        if command.as_deref().is_some_and(|command| {
            command == "verify-stopped-generation" || command == "verify-stopped-successor"
        }) {
            if arguments.next().as_deref() != Some(std::ffi::OsStr::new("--lock-fd")) {
                return std::process::ExitCode::FAILURE;
            }
            let Some(raw) = arguments.next() else {
                return std::process::ExitCode::FAILURE;
            };
            let Some(value) = raw.to_str() else {
                return std::process::ExitCode::FAILURE;
            };
            if value.is_empty()
                || value.len() > 10
                || value.starts_with('0')
                || !value.bytes().all(|byte| byte.is_ascii_digit())
                || arguments.next().is_some()
            {
                return std::process::ExitCode::FAILURE;
            }
            let Ok(fd) = value.parse::<i32>() else {
                return std::process::ExitCode::FAILURE;
            };
            if fd <= 2 {
                return std::process::ExitCode::FAILURE;
            }
            let verified =
                if command.as_deref() == Some(std::ffi::OsStr::new("verify-stopped-successor")) {
                    profile_auto_transaction::verify_stopped_successor_inherited(fd)
                } else {
                    profile_auto_transaction::verify_stopped_generation_inherited(fd)
                };
            return match verified {
                Ok(bytes) => {
                    use std::io::Write;
                    if std::io::stdout().write_all(&bytes).is_ok() {
                        std::process::ExitCode::SUCCESS
                    } else {
                        std::process::ExitCode::FAILURE
                    }
                }
                Err(_) => {
                    eprintln!("AUTO stopped generation verification refused");
                    std::process::ExitCode::FAILURE
                }
            };
        }
        if command.as_deref().is_some_and(|command| {
            command == "auto-stop-service"
                || command == "auto-stop-service-clean"
                || command == "auto-bind-service"
                || command == "auto-stop-finalized"
                || command == "auto-stop-finalized-socks"
                || command == "auto-inspect-finalized-stage"
                || command == "auto-inspect-active-stage"
                || command == "auto-seal-generation"
                || command == "auto-seal-stopped-generation"
                || command == "auto-archive-stopped-generation"
                || command == "auto-uninstall-stop-and-archive"
                || command == "auto-seal-unsealed-stopped-recovery"
                || command == "auto-recover-rolled-back"
                || command == "auto-recover-unsealed-finalized"
        }) {
            let Some(argument) = arguments.next() else {
                return std::process::ExitCode::FAILURE;
            };
            if command.as_deref().is_some_and(|value| {
                value == "auto-seal-stopped-generation"
                    || value == "auto-seal-unsealed-stopped-recovery"
            }) {
                if arguments.next().is_some() {
                    return std::process::ExitCode::FAILURE;
                }
                let result = if command.as_deref()
                    == Some(std::ffi::OsStr::new("auto-seal-stopped-generation"))
                {
                    profile_auto_transaction::seal_stopped_generation(Path::new(&argument))
                } else {
                    profile_auto_transaction::seal_unsealed_stopped_recovery(Path::new(&argument))
                };
                return match result {
                    Ok(bytes) => {
                        use std::io::Write;
                        if std::io::stdout().write_all(&bytes).is_ok()
                            && std::io::stdout().write_all(b"\n").is_ok()
                        {
                            std::process::ExitCode::SUCCESS
                        } else {
                            std::process::ExitCode::FAILURE
                        }
                    }
                    Err(_) => {
                        eprintln!("AUTO stopped generation verification refused");
                        std::process::ExitCode::FAILURE
                    }
                };
            }
            if command.as_deref() == Some(std::ffi::OsStr::new("auto-inspect-active-stage")) {
                if arguments.next().is_some() {
                    return std::process::ExitCode::FAILURE;
                }
                return match profile_auto_transaction::inspect_active_finalized_stage(Path::new(
                    &argument,
                )) {
                    Ok(bytes) => {
                        use std::io::Write;
                        if std::io::stdout().write_all(&bytes).is_ok()
                            && std::io::stdout().write_all(b"\n").is_ok()
                        {
                            std::process::ExitCode::SUCCESS
                        } else {
                            std::process::ExitCode::FAILURE
                        }
                    }
                    Err(_) => {
                        eprintln!("AUTO active stage inspection refused");
                        std::process::ExitCode::FAILURE
                    }
                };
            }
            if command.as_deref() == Some(std::ffi::OsStr::new("auto-inspect-finalized-stage")) {
                let current = match arguments.next() {
                    None => false,
                    Some(flag) if flag == "--current" => true,
                    _ => return std::process::ExitCode::FAILURE,
                };
                if arguments.next().is_some() {
                    return std::process::ExitCode::FAILURE;
                }
                return match profile_auto_transaction::inspect_finalized_stage(
                    Path::new(&argument),
                    current,
                ) {
                    Ok(bytes) => {
                        use std::io::Write;
                        if std::io::stdout().write_all(&bytes).is_ok()
                            && std::io::stdout().write_all(b"\n").is_ok()
                        {
                            std::process::ExitCode::SUCCESS
                        } else {
                            std::process::ExitCode::FAILURE
                        }
                    }
                    Err(_) => {
                        eprintln!("AUTO finalized stage inspection refused");
                        std::process::ExitCode::FAILURE
                    }
                };
            }
            if arguments.next().is_some() {
                return std::process::ExitCode::FAILURE;
            }
            let result = match command.as_deref().and_then(std::ffi::OsStr::to_str) {
                Some("auto-recover-rolled-back") => {
                    profile_auto_transaction::recover_rolled_back_stage(Path::new(&argument))
                }
                Some("auto-recover-unsealed-finalized") => {
                    profile_auto_transaction::recover_unsealed_finalized_stage(Path::new(&argument))
                }
                Some("auto-archive-stopped-generation") => {
                    profile_auto_transaction::archive_stopped_generation_pointer(Path::new(
                        &argument,
                    ))
                }
                Some("auto-uninstall-stop-and-archive") => {
                    profile_auto_transaction::uninstall_stop_and_archive(Path::new(&argument))
                }
                Some("auto-seal-generation") => {
                    profile_auto_transaction::seal_active_generation(Path::new(&argument))
                }
                Some("auto-stop-finalized") => {
                    profile_auto_transaction::stop_finalized_stage(Path::new(&argument))
                }
                Some("auto-stop-finalized-socks") => {
                    profile_auto_transaction::stop_finalized_socks_stage(Path::new(&argument))
                }
                Some("auto-stop-service") => argument
                    .to_str()
                    .ok_or("AUTO unit encoding refused")
                    .and_then(profile_auto_stop_service::run)
                    .map_err(str::to_owned),
                Some("auto-stop-service-clean") => argument
                    .to_str()
                    .ok_or("AUTO unit encoding refused")
                    .and_then(profile_auto_stop_service::run_clean)
                    .map_err(str::to_owned),
                Some("auto-bind-service") => argument
                    .to_str()
                    .ok_or("AUTO unit encoding refused")
                    .and_then(profile_auto_stop_service::run_bind)
                    .map_err(str::to_owned),
                _ => unreachable!(),
            };
            return match result {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(_) => {
                    eprintln!("AUTO owned service operation requires native recovery");
                    std::process::ExitCode::FAILURE
                }
            };
        }
    }
    if std::env::args_os().skip(1).any(|arg| {
        arg == std::ffi::OsStr::new("--bundle-url")
            || arg
                .to_str()
                .is_some_and(|arg| arg.starts_with("--bundle-url="))
    }) {
        eprintln!("Inline bundle URLs are no longer accepted. Use --bundle-url-file with a private access record, or --bundle with an existing archive.");
        return std::process::ExitCode::FAILURE;
    }
    match start_client() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            // Rust's default Result termination prints the complete Debug
            // chain outside tracing, so protect that final boundary too.
            if runtime_jsonl::private_logs_enabled() {
                eprintln!(
                    "{}",
                    json!({
                        "level": "ERROR", "event_code": "client_failed",
                        "error_kind": anyhow_error_kind_code(&error).unwrap_or("unclassified"),
                        "diagnostics": "private"
                    })
                );
            } else {
                eprintln!("Error: {error:#}");
            }
            std::process::ExitCode::FAILURE
        }
    }
}

fn start_client() -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    if let Some(result) = macos_tunnel::worker_runtime::dispatch(std::env::args_os().skip(1)) {
        return result;
    }
    // The client binary also reaches rustls/quinn directly on relay paths, so
    // pick a process-wide provider explicitly instead of relying on tests.
    let _ = rustls::crypto::ring::default_provider().install_default();
    #[cfg(target_os = "linux")]
    let args = if std::env::args_os().nth(1).as_deref()
        == Some(std::ffi::OsStr::new("auto-owned-service"))
    {
        Args::parse_from(
            std::env::args_os()
                .take(1)
                .chain(std::env::args_os().skip(3)),
        )
    } else {
        Args::parse()
    };
    #[cfg(not(target_os = "linux"))]
    let args = Args::parse();
    #[cfg(target_os = "macos")]
    if args.macos_utun_disconnect {
        return macos_tunnel::disconnect(args.macos_utun_disconnect_owner.as_ref());
    }
    #[cfg(target_os = "macos")]
    if args.macos_utun_supervise {
        return tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(macos_tunnel::supervise(args.macos_utun_seconds));
    }
    #[cfg(target_os = "macos")]
    if args.macos_utun {
        runtime_jsonl::set_private_logs(true);
        runtime_jsonl::set_forensic_redact(true);
        return tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?
            .block_on(macos_tunnel::parent_runtime::run(&args));
    }

    let forensic_safe = cfg!(forensic_safe)
        || args.forensic_safe
        || matches!(
            std::env::var("AEGIS_FORENSIC_SAFE").ok().as_deref(),
            Some("1") | Some("true")
        );
    runtime_jsonl::set_forensic_redact(forensic_safe);
    runtime_jsonl::set_private_logs(forensic_safe || !args.diagnostic_logs);
    if args.validate_config {
        anyhow::ensure!(
            args.command.is_none(),
            "config validation cannot run a subcommand"
        );
        let cfg = config::load_config(config::expand_tilde(&args.config))?;
        device_renewal::validate(args.device_online_bundle.as_deref(), &cfg)?;
        IngressStartupReport::build(&cfg)
            .map_err(|_| anyhow::anyhow!("config_ingress_selection_invalid"))?;
        if args.json {
            println!(
                "{}",
                json!({"schema": "aegis_config_validation_v1", "valid": true})
            );
        } else {
            println!("Configuration valid");
        }
        return Ok(());
    }
    #[cfg(windows)]
    if args.windows_service {
        return windows_service::run(args);
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?
        .block_on(run_client(args, None))
}

async fn run_client(
    args: Args,
    external_shutdown: Option<watch::Receiver<bool>>,
) -> anyhow::Result<()> {
    // This owner outlives every inner startup/ingress return. Await cancelled
    // tasks so their protected TCP streams have actually dropped before native
    // quiescence; JoinSet::drop only requests cancellation.
    let mut selected_sessions = None;
    let mut result = run_client_inner(args, external_shutdown, &mut selected_sessions).await;
    if let Some(sessions) = selected_sessions.as_mut() {
        if let Err(cleanup) = drain_selected_sessions(sessions).await {
            result = Err(match result {
                Err(error) => error.context(format!("selected sessions: {cleanup}")),
                Ok(()) => anyhow::anyhow!("selected sessions: {cleanup}"),
            });
        }
    }
    let cleanup = relay::shutdown_outer_geneva().await;
    match (result, cleanup) {
        (Err(error), Err(cleanup)) => {
            Err(error.context(format!("relay Geneva terminal cleanup: {cleanup}")))
        }
        (Err(error), _) => Err(error),
        (Ok(()), Err(cleanup)) => Err(anyhow::anyhow!("relay Geneva terminal cleanup: {cleanup}")),
        (Ok(()), Ok(())) => Ok(()),
    }
}

// The same scope owns broker normalization and the complete TCP/UDP session.
// Revocation cancels pending sessions even while ingress shutdown is awaiting;
// the outer run_client owner subsequently joins every task before returning.
#[cfg(any(target_os = "linux", test))]
fn spawn_gated_owned_session<F>(
    sessions: &mut tokio::task::JoinSet<()>,
    gate: crate::ingress::wide::forward_gate::ForwardGate,
    session: F,
) where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    sessions.spawn(async move {
        let _ = gate.run(session).await;
    });
}

async fn drain_selected_sessions(sessions: &mut tokio::task::JoinSet<()>) -> anyhow::Result<()> {
    sessions.abort_all();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while sessions.join_next().await.is_some() {}
    })
    .await
    .map_err(|_| anyhow::anyhow!("selected relay task drain deadline exceeded"))
}

#[cfg(test)]
mod selected_shutdown_tests {
    use super::{drain_selected_sessions, spawn_gated_owned_session};
    use crate::ingress::wide::forward_gate::ForwardGate;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use tokio::io::AsyncReadExt;

    struct DropProof(Arc<AtomicBool>);
    impl Drop for DropProof {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[tokio::test]
    async fn cancellation_waits_for_actual_stream_owner_destructor() {
        let dropped = Arc::new(AtomicBool::new(false));
        let proof = Arc::clone(&dropped);
        let (ready, started) = tokio::sync::oneshot::channel();
        let mut sessions = tokio::task::JoinSet::new();
        sessions.spawn(async move {
            let _owner = DropProof(proof);
            ready.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        started.await.unwrap();
        drain_selected_sessions(&mut sessions).await.unwrap();
        assert!(dropped.load(Ordering::Acquire));
        assert!(sessions.is_empty());
    }

    #[tokio::test]
    async fn wide_revocation_drops_pending_io_before_delayed_backend_shutdown() {
        let gate = ForwardGate::closed();
        assert!(gate.open());
        let dropped = Arc::new(AtomicBool::new(false));
        let proof = DropProof(Arc::clone(&dropped));
        let (mut stream, _peer) = tokio::io::duplex(64);
        let (ready, started) = tokio::sync::oneshot::channel();
        let mut sessions = tokio::task::JoinSet::new();
        spawn_gated_owned_session(&mut sessions, gate.clone(), async move {
            let _owner = proof;
            ready.send(()).unwrap();
            let mut byte = [0];
            stream.read_exact(&mut byte).await.unwrap();
            panic!("revoked pending session completed network work");
        });
        started.await.unwrap();
        // The ingress terminal branch revokes before awaiting backend shutdown.
        // Hold that shutdown pending and require the I/O owner to retire meanwhile.
        gate.revoke();
        tokio::time::timeout(std::time::Duration::from_secs(1), sessions.join_next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(dropped.load(Ordering::Acquire));
        assert!(sessions.is_empty());
        drain_selected_sessions(&mut sessions).await.unwrap();
    }

    #[tokio::test]
    async fn wide_closed_gate_drops_accepted_owner_without_polling_session() {
        let gate = ForwardGate::closed();
        let dropped = Arc::new(AtomicBool::new(false));
        let proof = DropProof(Arc::clone(&dropped));
        let mut sessions = tokio::task::JoinSet::new();
        spawn_gated_owned_session(&mut sessions, gate, async move {
            let _owner = proof;
            panic!("closed accepted session was polled");
        });
        sessions.join_next().await.unwrap().unwrap();
        assert!(dropped.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn completed_and_empty_owners_have_checked_terminal_drain() {
        let mut sessions = tokio::task::JoinSet::new();
        sessions.spawn(async {});
        drain_selected_sessions(&mut sessions).await.unwrap();
        drain_selected_sessions(&mut sessions).await.unwrap();
        assert!(sessions.is_empty());
    }
}

fn profile_command_failure_kind(profile: &profile::ProfileArgs) -> &'static str {
    match &profile.action {
        profile::ProfileAction::RelayGeneva(geneva)
            if matches!(
                geneva.action,
                profile_relay_geneva::Action::GuardPrepare { .. }
                    | profile_relay_geneva::Action::GuardFinish { .. }
            ) =>
        {
            "selected_relay_guard_refused"
        }
        _ => "profile_command_failed",
    }
}

#[cfg(test)]
mod closed_profile_failure_tests {
    use super::*;

    #[test]
    fn selected_guard_failure_keeps_a_closed_private_class() {
        for action in [
            profile_relay_geneva::Action::GuardPrepare {
                grant_current: true,
                control_parent: true,
            },
            profile_relay_geneva::Action::GuardFinish {
                control_parent: true,
            },
        ] {
            let profile = profile::ProfileArgs {
                action: profile::ProfileAction::RelayGeneva(profile_relay_geneva::Args { action }),
            };
            let error = anyhow::Error::new(ProfileCommandFailure {
                kind: profile_command_failure_kind(&profile),
                message: "private fixture path".to_string(),
            });
            assert_eq!(
                anyhow_error_kind_code(&error),
                Some("selected_relay_guard_refused")
            );
        }
        let profile = profile::ProfileArgs {
            action: profile::ProfileAction::RelayGeneva(profile_relay_geneva::Args {
                action: profile_relay_geneva::Action::Inspect,
            }),
        };
        assert_eq!(
            profile_command_failure_kind(&profile),
            "profile_command_failed"
        );
    }
}

async fn run_client_inner(
    args: Args,
    external_shutdown: Option<watch::Receiver<bool>>,
    selected_sessions: &mut Option<tokio::task::JoinSet<()>>,
) -> anyhow::Result<()> {
    if args.version {
        println!("{}", version_string("aegis-client"));
        return Ok(());
    }
    if let Some(TopCommand::Operator(op)) = &args.command {
        match operator::run(op) {
            Ok(json) => {
                println!("{json}");
                return Ok(());
            }
            Err(e) => anyhow::bail!("{e}"),
        }
    }
    match &args.command {
        Some(TopCommand::Carrier(command)) => return carrier::run(command).await,
        #[cfg(feature = "webrtc-carrier")]
        Some(TopCommand::Webrtc(command)) => return webrtc::run(command).await,
        Some(TopCommand::DeviceCsr(command)) => return device_identity::run(command),
        Some(TopCommand::Device(command)) => return device_identity::run_device(command).await,
        Some(TopCommand::StateKey(command)) => {
            return state_key::run(command);
        }
        Some(TopCommand::Profile(p)) => {
            return profile::run_profile(p).map_err(|message| {
                anyhow::Error::new(ProfileCommandFailure {
                    kind: profile_command_failure_kind(p),
                    message,
                })
            });
        }
        Some(TopCommand::Wide(w)) => {
            return profile::run_wide(w).map_err(|e| anyhow::anyhow!("{e}"));
        }
        Some(TopCommand::Doctor(d)) => {
            return profile::run_doctor(d).map_err(|e| anyhow::anyhow!("{e}"));
        }
        Some(TopCommand::TlsProbe(p)) => {
            return tls_probe::run(p).await;
        }
        _ => {}
    }
    // Audit F1: forensic-safe mode (flag or AEGIS_FORENSIC_SAFE=1) redacts
    // visited hostnames/IPs from emitted events and never persists the JSONL.
    let forensic_safe = cfg!(forensic_safe)
        || args.forensic_safe
        || matches!(
            std::env::var("AEGIS_FORENSIC_SAFE").ok().as_deref(),
            Some("1") | Some("true")
        );
    runtime_jsonl::set_forensic_redact(forensic_safe);
    runtime_jsonl::set_private_logs(forensic_safe || !args.diagnostic_logs);
    // --no-runtime-events (or forensic-safe) forces zero on-disk events even if
    // a path was given (e.g. the systemd unit passes one); for seizable hosts.
    let events_path = if args.no_runtime_events || forensic_safe {
        None
    } else {
        args.runtime_events_jsonl
            .as_ref()
            .map(|path| config::expand_tilde(path.as_path()))
    };
    if let Some(path) = events_path {
        runtime_jsonl::init(Some(path))
            .with_context(|| "init runtime event jsonl stream".to_string())?;
    } else {
        runtime_jsonl::init(None)?;
    }
    // Default diagnostics are structured and destination-free. A separate
    // explicit flag is required to render arbitrary messages and error chains;
    // an inherited RUST_LOG only changes filtering, never this privacy policy.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new(if runtime_jsonl::private_logs_enabled() {
            "warn"
        } else {
            "info"
        })
    });
    if runtime_jsonl::private_logs_enabled() {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .event_format(runtime_jsonl::PrivateEventFormat)
            .with_writer(std::io::stderr)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .init();
    }

    // Branded startup line (flair). Suppressed for --json so machine output stays
    // clean, and via AEGIS_NO_BANNER for quiet runs.
    if !args.json && std::env::var("AEGIS_NO_BANNER").as_deref() != Ok("1") {
        eprintln!(
            "▌ AEGIS · by AEGIS contributors · v{} — adaptive censorship-resilient transport",
            env!("CARGO_PKG_VERSION")
        );
    }

    #[cfg(target_os = "linux")]
    if let Some(queue) = args.nfqueue_observe {
        return run_nfqueue_observer(queue, &args);
    }

    #[cfg(target_os = "linux")]
    if let Some(port) = args.udp_redirect_proxy {
        return run_udp_redirect_proxy_cmd(port, &args);
    }

    if let Some(target) = args.masque_udp_health.clone() {
        let (th, tp) = target
            .rsplit_once(':')
            .context("--masque-udp-health must be host:port")?;
        let port: u16 = tp.parse().context("--masque-udp-health port")?;
        let settings: Settings =
            config::load_config(config::expand_tilde(args.config.as_path()))
                .with_context(|| format!("load config {}", args.config.display()))?;
        let nonce = b"aegis-masque-udp-health";
        let health =
            crate::relay::masque::masque_udp_health_check(&settings.relay, th, port, nonce).await;
        println!(
            "{}",
            serde_json::json!({
                "masque_udp_health": health.ok,
                "target": health.target,
                "detail": health.detail,
                "no_native_fallback": true,
            })
        );
        if health.ok {
            return Ok(());
        }
        anyhow::bail!("masque udp health failed: {}", health.detail);
    }

    #[cfg(target_os = "linux")]
    if let Some(dst) = args.tun_ipv6_route_lab {
        use crate::ingress::wide::tun_smoltcp::{run_route_lab, LabOpts};
        let mut opts = LabOpts::new(dst);
        opts.relay_exclude = args.tun_relay_exclude;
        eprintln!(
            "aegis-client: tun ipv6 route lab dst={dst} (controlled /128; not a default route)"
        );
        let res = run_route_lab(&opts).map_err(|e| anyhow::anyhow!("tun ipv6 route lab: {e}"))?;
        println!("{}", serde_json::to_string(&res).unwrap_or_default());
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    if let Some(addr) = args.tun_ipv6_tcp_adapter_lab {
        use crate::ingress::wide::tun_smoltcp_adapter::{run_tcp_adapter_lab, AdapterOpts};
        let opts = AdapterOpts {
            listen_addr: smoltcp::wire::Ipv6Address::from(addr.octets()),
            listen_port: args.tun_adapter_port,
            ifname: "aegis-tun0".to_string(),
            run_secs: 30,
        };
        eprintln!(
            "aegis-client: tun ipv6 smoltcp tcp adapter lab addr={addr} port={} (controlled /128)",
            args.tun_adapter_port
        );
        let res = run_tcp_adapter_lab(&opts)
            .map_err(|e| anyhow::anyhow!("tun ipv6 tcp adapter lab: {e}"))?;
        println!("{}", serde_json::to_string(&res).unwrap_or_default());
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    if let Some(addr) = args.tun_ipv6_relay_bridge_lab {
        use crate::ingress::wide::tun_smoltcp_adapter::{run_relay_bridge_lab, AdapterOpts};
        let cfg_path = args
            .tun_relay_config
            .as_ref()
            .context("--tun-relay-config required for the relay bridge lab")?;
        let settings: Settings = config::load_config(config::expand_tilde(cfg_path.as_path()))
            .with_context(|| format!("load relay config {}", cfg_path.display()))?;
        let target = args
            .tun_relay_target
            .as_deref()
            .context("--tun-relay-target host:port required")?;
        let (th, tp) = target
            .rsplit_once(':')
            .context("--tun-relay-target must be host:port")?;
        let opts = AdapterOpts {
            listen_addr: smoltcp::wire::Ipv6Address::from(addr.octets()),
            listen_port: args.tun_adapter_port,
            ifname: "aegis-tun0".to_string(),
            run_secs: 30,
        };
        eprintln!("aegis-client: tun ipv6 relay bridge lab addr={addr} -> relay -> {target}");
        let res = run_relay_bridge_lab(
            &opts,
            settings.relay,
            th.to_string(),
            tp.parse().context("target port")?,
        )
        .await
        .map_err(|e| anyhow::anyhow!("tun ipv6 relay bridge lab: {e}"))?;
        println!("{}", serde_json::to_string(&res).unwrap_or_default());
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    if let Some(addr) = args.tun_ipv6_udp_relay_bridge_lab {
        use crate::ingress::wide::tun_smoltcp_adapter::{run_udp_relay_bridge_lab, AdapterOpts};
        let cfg_path = args
            .tun_relay_config
            .as_ref()
            .context("--tun-relay-config required for the udp relay bridge lab")?;
        let settings: Settings = config::load_config(config::expand_tilde(cfg_path.as_path()))
            .with_context(|| format!("load relay config {}", cfg_path.display()))?;
        let target = args
            .tun_relay_target
            .as_deref()
            .context("--tun-relay-target host:port required")?;
        let (th, tp) = target
            .rsplit_once(':')
            .context("--tun-relay-target must be host:port")?;
        let opts = AdapterOpts {
            listen_addr: smoltcp::wire::Ipv6Address::from(addr.octets()),
            listen_port: args.tun_adapter_port,
            ifname: "aegis-tun0".to_string(),
            run_secs: 30,
        };
        eprintln!("aegis-client: tun ipv6 UDP relay bridge lab addr={addr} -> relay -> {target}");
        let res = run_udp_relay_bridge_lab(
            &opts,
            settings.relay,
            th.to_string(),
            tp.parse().context("target port")?,
        )
        .await
        .map_err(|e| anyhow::anyhow!("tun ipv6 udp relay bridge lab: {e}"))?;
        println!("{}", serde_json::to_string(&res).unwrap_or_default());
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    if args.tun_ipv6_default_route_dry_run {
        use crate::ingress::wide::tun_route_policy::default_route_dry_run;
        let excludes: Vec<std::net::IpAddr> = args.tun_relay_exclude.into_iter().collect();
        eprintln!("aegis-client: tun ipv6 default-route DRY-RUN (applies nothing)");
        let res = default_route_dry_run("aegis-tun0", &excludes);
        println!("{}", serde_json::to_string(&res).unwrap_or_default());
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    if let Some(target) = args.tun_ipv6_default_route_guarded_lab {
        use crate::ingress::wide::tun_smoltcp_adapter::{
            run_guarded_default_route_lab, AdapterOpts,
        };
        if !args.guarded_default_route_confirm {
            anyhow::bail!(
                "BLOCKED_BY_ROUTE_POLICY: guarded ::/0 capture requires --guarded-default-route-confirm"
            );
        }
        let cfg_path = args
            .tun_relay_config
            .as_ref()
            .context("--tun-relay-config required for the guarded default-route lab")?;
        let settings: Settings = config::load_config(config::expand_tilde(cfg_path.as_path()))
            .with_context(|| format!("load relay config {}", cfg_path.display()))?;
        let tgt = args
            .tun_relay_target
            .as_deref()
            .context("--tun-relay-target host:port required")?;
        let (th_raw, tp) = tgt
            .rsplit_once(':')
            .context("--tun-relay-target must be host:port")?;
        // Strip brackets from an IPv6 literal host (e.g. "[2606:...]:80") so the
        // relay dials the bare address, not a bracketed string.
        let th = th_raw.trim_start_matches('[').trim_end_matches(']');
        let opts = AdapterOpts {
            listen_addr: smoltcp::wire::Ipv6Address::from(target.octets()),
            listen_port: args.tun_adapter_port,
            ifname: "aegis-tun0".to_string(),
            run_secs: args.tun_max_runtime_seconds,
        };
        let excludes: Vec<std::net::IpAddr> = args.tun_relay_exclude.into_iter().collect();
        eprintln!(
            "aegis-client: GUARDED tun ipv6 ::/0 capture target={target} max={}s (watchdog + rollback mandatory)",
            args.tun_max_runtime_seconds
        );
        let res = run_guarded_default_route_lab(
            &opts,
            smoltcp::wire::Ipv6Address::from(target.octets()),
            excludes,
            args.tun_max_runtime_seconds,
            settings.relay,
            th.to_string(),
            tp.parse().context("target port")?,
        )
        .await
        .map_err(|e| anyhow::anyhow!("guarded default-route lab: {e}"))?;
        println!("{}", serde_json::to_string(&res).unwrap_or_default());
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    if let Some(addr) = args.tun_ipv6_prefix_relay_lab {
        use crate::ingress::wide::tun_smoltcp_adapter::{run_prefix_relay_bridge_lab, AdapterOpts};
        let cfg_path = args
            .tun_relay_config
            .as_ref()
            .context("--tun-relay-config required for the prefix relay lab")?;
        let settings: Settings = config::load_config(config::expand_tilde(cfg_path.as_path()))
            .with_context(|| format!("load relay config {}", cfg_path.display()))?;
        let target = args
            .tun_relay_target
            .as_deref()
            .context("--tun-relay-target host:port required")?;
        let (th, tp) = target
            .rsplit_once(':')
            .context("--tun-relay-target must be host:port")?;
        let peer2 = args
            .tun_peer2
            .context("--tun-peer2 (second controlled peer) required")?;
        let opts = AdapterOpts {
            listen_addr: smoltcp::wire::Ipv6Address::from(addr.octets()),
            listen_port: args.tun_adapter_port,
            ifname: "aegis-tun0".to_string(),
            run_secs: 30,
        };
        eprintln!(
            "aegis-client: tun ipv6 prefix relay lab prefix={} peer1={addr} peer2={peer2} -> relay -> {target}",
            args.tun_controlled_prefix
        );
        let res = run_prefix_relay_bridge_lab(
            &opts,
            args.tun_controlled_prefix.clone(),
            smoltcp::wire::Ipv6Address::from(peer2.octets()),
            args.tun_relay_exclude,
            settings.relay,
            th.to_string(),
            tp.parse().context("target port")?,
        )
        .await
        .map_err(|e| anyhow::anyhow!("tun ipv6 prefix relay lab: {e}"))?;
        println!("{}", serde_json::to_string(&res).unwrap_or_default());
        return Ok(());
    }

    init_sentinel(&SentinelConfig {
        sleep_if_vm: true,
        exit_if_debugger: false,
    });
    let path = config::expand_tilde(args.config.as_path());
    #[cfg(windows)]
    windows_service::stage(10);
    let cfg: Settings =
        config::load_config(&path).with_context(|| format!("load config {}", path.display()))?;
    device_renewal::validate(args.device_online_bundle.as_deref(), &cfg)?;
    #[cfg(windows)]
    let cfg = {
        let mut cfg = cfg;
        apply_windows_wide_cli_overrides(&mut cfg, &args)?;
        cfg
    };
    // Publish the evolved Geneva strategy (direct.geneva_strategy) before any
    // planning happens. Failing here is deliberate: a malformed program must not
    // degrade into "running with no evasion" while the operator believes Geneva
    // is active. Unset config is a no-op and leaves the `geneva` id unselectable.
    aegis_core::strategies::configure_geneva(cfg.direct.geneva_strategy.as_deref())
        .map_err(|e| anyhow::anyhow!("direct.geneva_strategy: {e}"))?;
    // Validate explicit public input before listeners/workers start, then pass
    // the immutable snapshot into the live store without importing disk history.
    let runtime_calibration = args
        .runtime_external_calibration_summary
        .as_deref()
        .map(runtime_calibration::read_snapshot)
        .transpose()?;
    if let Some(summary_path) = args.apply_external_calibration_summary.as_deref() {
        let snapshot = apply_external_calibration_summary(&cfg, summary_path).await?;
        if args.json {
            println!(
                "{}",
                json!({
                    "status": "applied",
                    "schema_version": snapshot.schema_version,
                    "source": snapshot.source,
                    "witness_label_count": snapshot.witness.len(),
                    "adversarial_transport_count": snapshot.adversarial.len(),
                    "knowledge_prior_count": snapshot.knowledge.len(),
                    "verdict_status": snapshot.verdict.status,
                    "acceptance_degraded": snapshot.verdict.acceptance_degraded
                })
            );
        } else {
            println!(
                "Applied external calibration: source={} witness_labels={} adversarial_transports={} knowledge_priors={} verdict={} degraded={}",
                snapshot.source,
                snapshot.witness.len(),
                snapshot.adversarial.len(),
                snapshot.knowledge.len(),
                snapshot.verdict.status,
                snapshot.verdict.acceptance_degraded
            );
        }
        return Ok(());
    }
    if let Some(target) = args.direct_active_probe_evidence {
        let evidence = direct::run_active_stall_probe_runtime_evidence(target, &cfg.direct).await?;
        if args.json {
            println!("{}", evidence);
        } else {
            println!(
                "Direct active probe evidence finished: target={} status={}",
                target,
                evidence["status"].as_str().unwrap_or("unknown")
            );
        }
        return Ok(());
    }
    if let Some(alias) = cfg.process_alias.as_deref() {
        if let Err(err) = aegis_core::apply_process_alias(alias) {
            warn!(%err, alias, "failed to apply process alias");
        }
    }
    #[cfg(windows)]
    windows_service::stage(20);
    #[cfg(windows)]
    if cfg.windows_tunnel.is_some() {
        return windows_tunnel::run(cfg, &args, external_shutdown, &path).await;
    }
    let report = match IngressStartupReport::build(&cfg) {
        Ok(report) => report,
        Err(msg) => {
            if args.ingress_preflight || args.ingress_startup_probe {
                if args.json {
                    println!("{}", msg.render_json(&cfg));
                } else {
                    println!("{}", msg.render_text(&cfg));
                }
                let command = if args.ingress_preflight {
                    "ingress preflight failed"
                } else {
                    "ingress startup probe failed"
                };
                return Err(anyhow::anyhow!(command));
            }
            error!(
                event_code = RuntimeEventCode::IngressStartupSelectionFailed.as_str(),
                requested_primary = ?cfg.ingress.primary,
                selection_error_code = ?msg.code,
                selection_hint_code = ?msg.hint_code,
                reason = %msg.message,
                hint = msg.hint,
                allow_fallback = cfg.ingress.allow_fallback,
                wide_supported = msg.wide_supported,
                wide_platform_family_supported = msg.wide_platform_family_supported,
                wide_runtime_readiness = ?msg.wide_runtime_readiness,
                wide_platform = ?cfg.ingress.wide.platform_backend,
                wide_rollout_profile = ?cfg.ingress.wide.rollout_profile,
            wide_prerouting_interface = ?cfg.ingress.wide.prerouting_interface,
                "ingress startup selection failed"
            );
            runtime_jsonl::emit(
                "error",
                RuntimeEventCode::IngressStartupSelectionFailed,
                "ingress startup selection failed",
                json!({
                    "requested_primary": format!("{:?}", cfg.ingress.primary),
                    "requested_primary_code": ingress_primary_code(cfg.ingress.primary),
                    "selection_error_code": msg.code,
                    "selection_hint_code": msg.hint_code,
                    "reason": msg.message.as_str(),
                    "hint": msg.hint,
                    "allow_fallback": cfg.ingress.allow_fallback,
                    "wide_supported": msg.wide_supported,
                    "wide_platform_family_supported": msg.wide_platform_family_supported,
                    "wide_runtime_readiness": msg.wide_runtime_readiness,
                    "wide_platform": format!("{:?}", cfg.ingress.wide.platform_backend),
                    "wide_platform_code": wide_platform_code(cfg.ingress.wide.platform_backend),
                    "wide_rollout_profile": format!("{:?}", cfg.ingress.wide.rollout_profile),
                    "wide_rollout_profile_code": wide_rollout_profile_code(cfg.ingress.wide.rollout_profile),
                    "wide_prerouting_interface": cfg.ingress.wide.prerouting_interface.as_deref(),
                    "wide_backend_current_stage": msg.wide_backend_current_stage(&cfg),
                    "wide_backend_scope_target": msg.wide_backend_scope_target(&cfg),
                    "wide_backend_reason_code": msg.wide_backend_reason_code(&cfg),
                    "wide_udp_capture_contract_requested": configured_udp_capture_contract(&cfg),
                    "wide_udp_capture_support_tier_requested": configured_udp_capture_support_tier(&cfg),
                    "wide_udp_capture_contract": Option::<&str>::None,
                    "wide_udp_capture_support_tier": Option::<&str>::None,
                    "wide_udp_capture_policy": Option::<&str>::None,
                    "wide_udp_capture_runtime_scope": Option::<&str>::None
                }),
            );
            return Err(anyhow::anyhow!("{}. hint: {}", msg.message, msg.hint));
        }
    };
    if args.ingress_preflight {
        let runtime_checks = report.probe_runtime_readiness(&cfg).await;
        if args.json {
            println!(
                "{}",
                report.render_json_with_runtime_checks(&cfg, &runtime_checks)
            );
        } else {
            println!(
                "{}",
                report.render_text_with_runtime_checks(&cfg, &runtime_checks, args.verbose)
            );
        }
        if runtime_checks.iter().any(|check| check.fatal) {
            return Err(anyhow::anyhow!("ingress preflight runtime probe failed"));
        }
        return Ok(());
    }
    if args.ingress_startup_probe {
        let startup = report.probe_runtime_startup(&cfg).await;
        if args.json {
            println!("{}", report.render_startup_probe_json(&cfg, &startup));
        } else {
            println!("{}", report.render_startup_probe_text(&cfg, &startup));
        }
        if startup.is_fatal() {
            return Err(anyhow::anyhow!("ingress startup probe failed"));
        }
        return Ok(());
    }

    // Device issuance and its live authorization ACK precede any ingress bind.
    // The installed persistent guard remains in force during this bounded gate.
    let mut device_renewal =
        device_renewal::Supervisor::start(args.device_online_bundle.as_deref(), &cfg).await?;
    log_ingress_startup_diagnostics(&cfg, &report);
    #[cfg(windows)]
    windows_service::stage(30);
    let mut startup_path_code = "socks5_fallback_started";
    let mut startup_bind_error_code = None;
    #[cfg(target_os = "linux")]
    let mut wide_workers = wide_workers::WideWorkers::new();
    // Side workers can receive DNS, IPv6 and UDP before the main accept loop
    // starts. Keep them closed until the final live authorization and required
    // local-worker check finish; owner Drop revokes on every early return.
    #[cfg(target_os = "linux")]
    let wide_forward_owner = crate::ingress::wide::forward_gate::ForwardGateOwner::closed();
    let backend: Box<dyn IngressBackend> = match report.backend_choice() {
        ActiveIngressBackend::WidePrimary => {
            #[cfg(target_os = "linux")]
            let wide_bind = crate::ingress::wide::WidePrimaryBackend::bind_with_relay_gated(
                cfg.ingress.wide.clone(),
                Some(cfg.relay.clone()),
                Some(wide_forward_owner.gate()),
            )
            .await;
            #[cfg(not(target_os = "linux"))]
            let wide_bind = crate::ingress::wide::WidePrimaryBackend::bind_with_relay(
                cfg.ingress.wide.clone(),
                Some(cfg.relay.clone()),
            )
            .await;
            match wide_bind {
                Ok(backend) => {
                    startup_path_code = "wide_primary_started";
                    // full-wide-tun: launch the production IPv6 TUN+smoltcp engine
                    // alongside the v4 REDIRECT leg. Carries IPv6 TCP+UDP to the
                    // relay; fail-closed; non-persistent tun self-heals on exit.
                    #[cfg(target_os = "linux")]
                    maybe_spawn_ipv6_tun_engine(&cfg, &mut wide_workers, wide_forward_owner.gate())
                        .await?;
                    // Generic UDP + QUIC carry: activate the conntrack-based UDP
                    // redirect proxy when generic capture is requested (was only
                    // reachable via the standalone subcommand before).
                    #[cfg(target_os = "linux")]
                    maybe_spawn_udp_redirect_proxy(
                        &cfg,
                        backend.fake_ip_map(),
                        &mut wide_workers,
                        wide_forward_owner.gate(),
                    )
                    .await?;
                    Box::new(backend)
                }
                Err(err) if cfg.ingress.allow_fallback => {
                    startup_path_code = "wide_bind_failed_fallback_started";
                    startup_bind_error_code = Some(report.bind_error_code(&cfg, &err));
                    warn!(
                        event_code = RuntimeEventCode::IngressWideBindFallback.as_str(),
                        requested_primary = ?cfg.ingress.primary,
                        listen = %cfg.ingress.wide.listen,
                        wide_supported = report.wide_supported(),
                        wide_platform_family_supported = report.wide_platform_family_supported(),
                        wide_runtime_readiness = ?report.wide_runtime_readiness(),
                        platform_backend = ?cfg.ingress.wide.platform_backend,
                        rollout_profile = ?cfg.ingress.wide.rollout_profile,
                        prerouting_interface = ?cfg.ingress.wide.prerouting_interface,
                        fallback_backend = "socks5_fallback",
                        bind_error_code = ?report.bind_error_code(&cfg, &err),
                        bind_hint_code = ?report.bind_error_hint_code(&cfg, &err),
                        error = %err,
                        hint = report.bind_error_hint(&cfg, &err),
                        "wide ingress bind failed, falling back to SOCKS5 backend"
                    );
                    runtime_jsonl::emit(
                        "warn",
                        RuntimeEventCode::IngressWideBindFallback,
                        "wide ingress bind failed, falling back to SOCKS5 backend",
                        json!({
                            "requested_primary": format!("{:?}", cfg.ingress.primary),
                            "requested_primary_code": ingress_primary_code(cfg.ingress.primary),
                            "listen": cfg.ingress.wide.listen.to_string(),
                            "wide_supported": report.wide_supported(),
                            "wide_platform_family_supported": report.wide_platform_family_supported(),
                            "wide_runtime_readiness": report.wide_runtime_readiness(),
                            "platform_backend": format!("{:?}", cfg.ingress.wide.platform_backend),
                            "platform_backend_code": wide_platform_code(cfg.ingress.wide.platform_backend),
                            "rollout_profile": format!("{:?}", cfg.ingress.wide.rollout_profile),
                            "rollout_profile_code": wide_rollout_profile_code(cfg.ingress.wide.rollout_profile),
                            "prerouting_interface": cfg.ingress.wide.prerouting_interface.as_deref(),
                            "fallback_backend": "socks5_fallback",
                            "bind_error_code": report.bind_error_code(&cfg, &err),
                            "bind_hint_code": report.bind_error_hint_code(&cfg, &err),
                            "error": err.to_string(),
                            "hint": report.bind_error_hint(&cfg, &err)
                        }),
                    );
                    Box::new(Socks5FallbackBackend::bind_from_settings(&cfg.socks).await?)
                }
                Err(err) => return Err(anyhow::anyhow!(report.bind_failure_message(&cfg, &err))),
            }
        }
        ActiveIngressBackend::Socks5Fallback => {
            if cfg.ingress.primary != aegis_core::IngressPrimary::Socks5 {
                warn!(
                    event_code = RuntimeEventCode::IngressStartupFallbackSelected.as_str(),
                    requested_primary = ?cfg.ingress.primary,
                    listen = %cfg.socks.listen,
                    fallback_reason_code = ?report.fallback_reason_code(),
                    reason = report.fallback_reason().unwrap_or("wide ingress unavailable"),
                    wide_enabled = cfg.ingress.wide.enabled,
                    wide_supported = report.wide_supported(),
                    wide_platform_family_supported = report.wide_platform_family_supported(),
                    wide_runtime_readiness = ?report.wide_runtime_readiness(),
                    wide_platform = ?cfg.ingress.wide.platform_backend,
                    wide_rollout_profile = ?cfg.ingress.wide.rollout_profile,
                    wide_prerouting_interface = ?cfg.ingress.wide.prerouting_interface,
                    fallback_backend = "socks5_fallback",
                    "wide ingress unavailable, falling back to SOCKS5 backend"
                );
                runtime_jsonl::emit(
                    "warn",
                    RuntimeEventCode::IngressStartupFallbackSelected,
                    "wide ingress unavailable, falling back to SOCKS5 backend",
                    json!({
                        "requested_primary": format!("{:?}", cfg.ingress.primary),
                        "requested_primary_code": ingress_primary_code(cfg.ingress.primary),
                        "listen": cfg.socks.listen.to_string(),
                        "fallback_reason_code": report.fallback_reason_code(),
                        "reason": report.fallback_reason().unwrap_or("wide ingress unavailable"),
                        "wide_enabled": cfg.ingress.wide.enabled,
                        "wide_supported": report.wide_supported(),
                        "wide_platform_family_supported": report.wide_platform_family_supported(),
                        "wide_runtime_readiness": report.wide_runtime_readiness(),
                        "wide_platform": format!("{:?}", cfg.ingress.wide.platform_backend),
                        "wide_platform_code": wide_platform_code(cfg.ingress.wide.platform_backend),
                        "wide_rollout_profile": format!("{:?}", cfg.ingress.wide.rollout_profile),
                        "wide_rollout_profile_code": wide_rollout_profile_code(cfg.ingress.wide.rollout_profile),
                        "wide_prerouting_interface": cfg.ingress.wide.prerouting_interface.as_deref(),
                        "wide_backend_current_stage": report.wide_backend_current_stage(&cfg),
                        "wide_backend_scope_target": report.wide_backend_scope_target(&cfg),
                        "wide_backend_reason_code": report.wide_backend_reason_code(&cfg),
                        "fallback_backend": "socks5_fallback"
                    }),
                );
            }
            Box::new(Socks5FallbackBackend::bind_from_settings(&cfg.socks).await?)
        }
    };
    // Bind ingress before loading heavier runtime state so pure listener/config
    // failures fail fast without touching Direct/Brain initialization.
    let runtime =
        RuntimeContext::from_settings_with_calibration(&cfg, runtime_calibration.as_ref()).await?;
    #[cfg(target_os = "linux")]
    if let Some(failed_worker) = wide_workers.pending_failure() {
        backend.shutdown().await;
        anyhow::bail!("required capture worker {failed_worker} stopped before service readiness");
    }
    if !backend.is_available() {
        backend.shutdown().await;
        anyhow::bail!("required ingress listener stopped before service readiness");
    }
    if let Err(error) =
        service_ready::after_confirmation(device_renewal.confirm_before_ready(), || {
            #[cfg(target_os = "linux")]
            if let Some(failed_worker) = wide_workers.pending_failure() {
                anyhow::bail!(
                    "required capture worker {failed_worker} stopped before service readiness"
                );
            }
            anyhow::ensure!(
                backend.is_available(),
                "required ingress listener stopped before service readiness"
            );
            device_renewal.ensure_confirmation_current()
        })
        .await
    {
        backend.shutdown().await;
        return Err(error);
    }
    #[cfg(target_os = "linux")]
    if backend.kind() == crate::ingress::IngressKind::WidePrimary {
        if let Some(failed_worker) = wide_workers.pending_failure() {
            backend.shutdown().await;
            anyhow::bail!("required capture worker {failed_worker} stopped before forwarding");
        }
        if let Err(error) = device_renewal.ensure_confirmation_current() {
            backend.shutdown().await;
            return Err(error);
        }
        if !backend.is_available() || !wide_forward_owner.gate().open() {
            backend.shutdown().await;
            anyhow::bail!("required wide forwarding gate could not open");
        }
    }
    // Relay resolves by name. Auto leaves DNS to its selected route owner,
    // so a relay-only decision or failed direct lookup can still use that name.
    let broker = session_broker_for_mode(&cfg.mode);
    let backend_runtime_status = backend.runtime_status();
    let wide_dns_capture_preview_status = backend_runtime_status.wide_dns_capture_preview_status;
    let wide_dns_capture_preview_error_kind =
        backend_runtime_status.wide_dns_capture_preview_error_kind;
    let wide_dns_capture_preview_error = backend_runtime_status
        .wide_dns_capture_preview_error
        .clone();
    let wide_udp_capture_contract = backend_runtime_status.wide_udp_capture_contract;
    let wide_udp_capture_support_tier = backend_runtime_status.wide_udp_capture_support_tier;
    let wide_udp_capture_policy = backend_runtime_status.wide_udp_capture_policy;
    let wide_udp_capture_runtime_scope = backend_runtime_status.wide_udp_capture_runtime_scope;
    let wide_backend_current_stage =
        backend_runtime_status
            .wide_backend_current_stage
            .or_else(|| {
                (cfg.ingress.primary == IngressPrimary::Wide)
                    .then_some(report.wide_backend_current_stage(&cfg))
                    .flatten()
            });
    let wide_backend_scope_target =
        backend_runtime_status
            .wide_backend_scope_target
            .or_else(|| {
                (cfg.ingress.primary == IngressPrimary::Wide)
                    .then_some(report.wide_backend_scope_target(&cfg))
                    .flatten()
            });
    let wide_backend_reason_code = backend_runtime_status.wide_backend_reason_code.or_else(|| {
        (cfg.ingress.primary == IngressPrimary::Wide)
            .then_some(report.wide_backend_reason_code(&cfg))
            .flatten()
    });
    let wide_udp_preview_policy = backend_runtime_status.wide_udp_preview_policy;
    let wide_udp_preview_ports = backend_runtime_status.wide_udp_preview_ports.clone();
    let wide_dns_port = if wide_udp_capture_contract.is_some() || wide_udp_preview_policy.is_some()
    {
        Some(cfg.ingress.wide.dns_port)
    } else {
        None
    };
    info!(
        event_code = RuntimeEventCode::IngressBackendStarted.as_str(),
        backend = backend.id(),
        backend_runtime_id = backend.runtime_id(),
        kind = ?backend.kind(),
        listen = ?backend.listen_addr(),
        available = backend.is_available(),
        requested_primary = ?cfg.ingress.primary,
        startup_path_code = startup_path_code,
        startup_fallback_reason_code = ?report.fallback_reason_code(),
        startup_fallback_reason = report.fallback_reason(),
        startup_bind_error_code = ?startup_bind_error_code,
        wide_supported = report.wide_supported(),
        wide_platform_family_supported = report.wide_platform_family_supported(),
        wide_runtime_readiness = ?report.wide_runtime_readiness(),
        mode = ?cfg.mode,
        rollout_profile = ?cfg.ingress.wide.rollout_profile,
        prerouting_interface = ?cfg.ingress.wide.prerouting_interface,
        wide_dns_port = ?wide_dns_port,
        wide_udp_capture_contract = ?wide_udp_capture_contract,
        wide_udp_capture_support_tier = ?wide_udp_capture_support_tier,
        wide_udp_capture_policy = ?wide_udp_capture_policy,
        wide_udp_capture_runtime_scope = ?wide_udp_capture_runtime_scope,
        wide_udp_preview_policy = ?wide_udp_preview_policy,
        wide_udp_preview_ports = ?wide_udp_preview_ports,
        wide_dns_capture_preview_status = ?wide_dns_capture_preview_status,
        wide_dns_capture_preview_error_kind = ?wide_dns_capture_preview_error_kind,
        wide_dns_capture_preview_error = ?wide_dns_capture_preview_error,
        "client ingress backend started"
    );
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::IngressBackendStarted,
        "client ingress backend started",
        json!({
            "backend": backend.id(),
            "backend_runtime_id": backend.runtime_id(),
            "kind": format!("{:?}", backend.kind()),
            "kind_code": backend.kind().as_code(),
            "backend_kind": format!("{:?}", backend.kind()),
            "backend_kind_code": backend.kind().as_code(),
            "listen": backend.listen_addr().map(|listen| listen.to_string()),
            "available": backend.is_available(),
            "requested_primary": format!("{:?}", cfg.ingress.primary),
            "requested_primary_code": ingress_primary_code(cfg.ingress.primary),
            "startup_path_code": startup_path_code,
            "startup_fallback_reason_code": report.fallback_reason_code(),
            "startup_fallback_reason": report.fallback_reason(),
            "startup_bind_error_code": startup_bind_error_code,
            "wide_supported": report.wide_supported(),
            "wide_platform_family_supported": report.wide_platform_family_supported(),
            "wide_runtime_readiness": report.wide_runtime_readiness(),
            "mode": format!("{:?}", cfg.mode),
            "mode_code": mode_code(&cfg.mode),
            "rollout_profile": format!("{:?}", cfg.ingress.wide.rollout_profile),
            "rollout_profile_code": wide_rollout_profile_code(cfg.ingress.wide.rollout_profile),
            "prerouting_interface": cfg.ingress.wide.prerouting_interface.as_deref(),
            "wide_dns_port": wide_dns_port,
            "wide_udp_capture_contract": wide_udp_capture_contract,
            "wide_udp_capture_support_tier": wide_udp_capture_support_tier,
            "wide_udp_capture_policy": wide_udp_capture_policy,
            "wide_udp_capture_runtime_scope": wide_udp_capture_runtime_scope,
            "wide_backend_current_stage": wide_backend_current_stage,
            "wide_backend_scope_target": wide_backend_scope_target,
            "wide_backend_reason_code": wide_backend_reason_code,
            "wide_udp_preview_policy": wide_udp_preview_policy,
            "wide_udp_preview_ports": wide_udp_preview_ports,
            "wide_dns_capture_preview_status": wide_dns_capture_preview_status,
            "wide_dns_capture_preview_error_kind": wide_dns_capture_preview_error_kind,
            "wide_dns_capture_preview_error": wide_dns_capture_preview_error
        }),
    );
    // Linkability hardening (Drill J / Phase 3): a pinned surface profile
    // removes the per-epoch morphology drift. If the same pin is unique per
    // user/install it can become a stable wire-correlatable marker. Warn
    // once at startup — advisory only, no behavior change.
    if let Some(pinned) = cfg.relay.policy.surface_profile_id.as_deref() {
        warn!(
            event_code = RuntimeEventCode::SurfaceProfileIdPinnedWarning.as_str(),
            surface_profile_id = pinned,
            "explicit relay.policy.surface_profile_id is pinned; this removes \
             per-epoch morphology drift and may become a stable per-user marker \
             if unique per user/install — prefer adaptive sampling (see \
             docs/operator-guides/surface-profile-pin-warning.md)"
        );
        runtime_jsonl::emit(
            "warn",
            RuntimeEventCode::SurfaceProfileIdPinnedWarning,
            "explicit surface_profile_id may become a stable marker if unique per user/install",
            json!({
                "surface_profile_id": pinned,
                "severity": "operator_hardening",
                "behavior_changed": false,
                "guidance": "prefer adaptive morphology sampling; do not use surface_profile_id as a user/customer identifier",
            }),
        );
    }
    // Keep late session/broker failures self-contained without requiring
    // consumers to correlate them back to startup selection events.
    let backend_id = backend.id().to_string();
    let backend_runtime_id = backend.runtime_id().to_string();
    let backend_kind = format!("{:?}", backend.kind());
    let backend_kind_code = backend.kind().as_code();
    let requested_primary = format!("{:?}", cfg.ingress.primary);
    let requested_primary_code = ingress_primary_code(cfg.ingress.primary);
    let mode = format!("{:?}", cfg.mode);
    let mode_code = mode_code(&cfg.mode);
    let wide_context_requested = wide_rollout_startup_context_requested(&cfg);
    let wide_supported = wide_context_requested.then_some(report.wide_supported());
    let wide_platform_family_supported =
        wide_context_requested.then_some(report.wide_platform_family_supported());
    let wide_runtime_readiness = wide_context_requested.then_some(report.wide_runtime_readiness());
    let wide_rollout_profile =
        wide_context_requested.then_some(format!("{:?}", cfg.ingress.wide.rollout_profile));
    let wide_rollout_profile_code = wide_context_requested
        .then_some(wide_rollout_profile_code(cfg.ingress.wide.rollout_profile));
    let wide_prerouting_interface = if wide_context_requested {
        cfg.ingress.wide.prerouting_interface.clone()
    } else {
        None
    };
    let startup_path_code = startup_path_code;
    let startup_fallback_reason_code = report.fallback_reason_code();
    let startup_fallback_reason = report.fallback_reason();
    let startup_bind_error_code = startup_bind_error_code;
    // Keep one late-runtime ingress context bundle so success/failure tails stay
    // aligned on backend, rollout, and startup contract fields.
    let late_runtime_context = IngressLateRuntimeContext {
        backend_id: backend_id.clone(),
        backend_runtime_id: backend_runtime_id.clone(),
        backend_kind: backend_kind.clone(),
        backend_kind_code,
        requested_primary: requested_primary.clone(),
        requested_primary_code,
        mode: mode.clone(),
        mode_code,
        wide_supported,
        wide_platform_family_supported,
        wide_runtime_readiness,
        rollout_profile: wide_rollout_profile.clone(),
        rollout_profile_code: wide_rollout_profile_code,
        prerouting_interface: wide_prerouting_interface.clone(),
        path_code: startup_path_code,
        fallback_reason_code: startup_fallback_reason_code,
        fallback_reason: startup_fallback_reason,
        bind_error_code: startup_bind_error_code,
    };
    let stdin_shutdown = spawn_stdin_eof_shutdown(args.exit_on_stdin_eof);
    // Retain selected relay sessions and all accepted Linux wide sessions in
    // the outer run_client owner, which aborts and joins them on every return.
    let own_accepted_sessions = cfg.relay.outer_geneva.is_some();
    #[cfg(target_os = "linux")]
    let own_accepted_sessions =
        own_accepted_sessions || backend.kind() == crate::ingress::IngressKind::WidePrimary;
    *selected_sessions = own_accepted_sessions.then(tokio::task::JoinSet::new);
    #[cfg(target_os = "linux")]
    let selected_signals = if selected_sessions.is_some() {
        Some((
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?,
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?,
        ))
    } else {
        None
    };

    #[cfg(windows)]
    if args.windows_service {
        windows_service::ready();
    }

    run_ingress_owner(
        ClientIngressOwner {
            backend,
            cfg,
            runtime,
            broker,
            late_runtime_context,
            external_shutdown,
            stdin_shutdown,
            selected_sessions,
            device_renewal: &mut device_renewal,
            #[cfg(target_os = "linux")]
            wide_workers: &mut wide_workers,
            #[cfg(target_os = "linux")]
            wide_forward_gate: wide_forward_owner.gate(),
            #[cfg(target_os = "linux")]
            selected_signals,
        },
        emit_ingress_accept_failure,
        #[cfg(test)]
        |_| {},
    )
    .await
}

fn trace_ingress_accept_failure(err: &std::io::Error, context: &IngressLateRuntimeContext) {
    let backend_id = &context.backend_id;
    let backend_runtime_id = &context.backend_runtime_id;
    let backend_kind = &context.backend_kind;
    let requested_primary = &context.requested_primary;
    let mode = &context.mode;
    let wide_supported = context.wide_supported;
    let wide_platform_family_supported = context.wide_platform_family_supported;
    let wide_runtime_readiness = context.wide_runtime_readiness;
    let wide_rollout_profile = &context.rollout_profile;
    let wide_prerouting_interface = &context.prerouting_interface;
    let startup_path_code = context.path_code;
    let startup_fallback_reason_code = context.fallback_reason_code;
    let startup_fallback_reason = context.fallback_reason;
    let startup_bind_error_code = context.bind_error_code;
    warn!(
        event_code = RuntimeEventCode::IngressAcceptFailed.as_str(),
        backend = %backend_id,
        backend_runtime_id = %backend_runtime_id,
        backend_kind = %backend_kind,
        requested_primary = %requested_primary,
        mode = %mode,
        wide_supported = ?wide_supported,
        wide_platform_family_supported = ?wide_platform_family_supported,
        wide_runtime_readiness = ?wide_runtime_readiness,
        rollout_profile = ?wide_rollout_profile,
        prerouting_interface = ?wide_prerouting_interface,
        startup_path_code = startup_path_code,
        startup_fallback_reason_code = ?startup_fallback_reason_code,
        startup_fallback_reason = ?startup_fallback_reason,
        startup_bind_error_code = ?startup_bind_error_code,
        accept_error_kind = io_error_kind_code(err),
        "ingress accept failed: {err}"
    );
}

fn ingress_accept_failure_fields(
    err: &std::io::Error,
    context: &IngressLateRuntimeContext,
) -> serde_json::Value {
    let backend_id = &context.backend_id;
    let backend_runtime_id = &context.backend_runtime_id;
    let backend_kind = &context.backend_kind;
    let backend_kind_code = context.backend_kind_code;
    let requested_primary = &context.requested_primary;
    let requested_primary_code = context.requested_primary_code;
    let mode = &context.mode;
    let mode_code = context.mode_code;
    let wide_supported = context.wide_supported;
    let wide_platform_family_supported = context.wide_platform_family_supported;
    let wide_runtime_readiness = context.wide_runtime_readiness;
    let wide_rollout_profile = &context.rollout_profile;
    let wide_rollout_profile_code = context.rollout_profile_code;
    let wide_prerouting_interface = &context.prerouting_interface;
    let startup_path_code = context.path_code;
    let startup_fallback_reason_code = context.fallback_reason_code;
    let startup_fallback_reason = context.fallback_reason;
    let startup_bind_error_code = context.bind_error_code;
    json!({
        "backend": backend_id,
        "backend_runtime_id": backend_runtime_id,
        "backend_kind": backend_kind,
        "backend_kind_code": backend_kind_code,
        "requested_primary": requested_primary,
        "requested_primary_code": requested_primary_code,
        "mode": mode,
        "mode_code": mode_code,
        "wide_supported": wide_supported,
        "wide_platform_family_supported": wide_platform_family_supported,
        "wide_runtime_readiness": wide_runtime_readiness,
        "rollout_profile": wide_rollout_profile,
        "rollout_profile_code": wide_rollout_profile_code,
        "prerouting_interface": wide_prerouting_interface.as_deref(),
        "startup_path_code": startup_path_code,
        "startup_fallback_reason_code": startup_fallback_reason_code,
        "startup_fallback_reason": startup_fallback_reason,
        "startup_bind_error_code": startup_bind_error_code,
        "accept_error_kind": io_error_kind_code(err),
        "error": err.to_string()
    })
}

fn emit_ingress_accept_failure(err: &std::io::Error, context: &IngressLateRuntimeContext) {
    trace_ingress_accept_failure(err, context);
    runtime_jsonl::emit(
        "warn",
        RuntimeEventCode::IngressAcceptFailed,
        "ingress accept failed",
        ingress_accept_failure_fields(err, context),
    );
}

fn native_resource_accept_error(error: &std::io::Error) -> bool {
    let Some(raw) = error.raw_os_error() else {
        // Staged admission errors retain their existing policy, even when their
        // ErrorKind resembles a native resource failure.
        return false;
    };
    // ENOMEM, ENFILE, EMFILE and ENOBUFS from Darwin sys/errno.h.
    #[cfg(target_os = "macos")]
    const CODES: &[i32] = &[12, 23, 24, 55];
    // ENOBUFS is verified here only for these Linux architectures.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    const CODES: &[i32] = &[12, 23, 24, 105];
    #[cfg(all(
        target_os = "linux",
        not(any(target_arch = "x86_64", target_arch = "aarch64"))
    ))]
    const CODES: &[i32] = &[12, 23, 24];
    // WinSock WSAEMFILE and WSAENOBUFS, not Unix errno values.
    #[cfg(windows)]
    const CODES: &[i32] = &[10_024, 10_055];
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    const CODES: &[i32] = &[];
    CODES.contains(&raw)
}

// Post-startup owner shared by production and direct actual-owner regressions.
// Startup/readiness and the outer selected-session drain keep their original owners.
struct ClientIngressOwner<'a> {
    backend: Box<dyn IngressBackend>,
    cfg: Settings,
    runtime: RuntimeContext,
    broker: DefaultSessionBroker,
    late_runtime_context: IngressLateRuntimeContext,
    external_shutdown: Option<watch::Receiver<bool>>,
    stdin_shutdown: Option<watch::Receiver<bool>>,
    selected_sessions: &'a mut Option<tokio::task::JoinSet<()>>,
    device_renewal: &'a mut device_renewal::Supervisor,
    #[cfg(target_os = "linux")]
    wide_workers: &'a mut wide_workers::WideWorkers,
    #[cfg(target_os = "linux")]
    wide_forward_gate: crate::ingress::wide::forward_gate::ForwardGate,
    #[cfg(target_os = "linux")]
    selected_signals: Option<(tokio::signal::unix::Signal, tokio::signal::unix::Signal)>,
}

async fn run_ingress_owner<E>(
    owner: ClientIngressOwner<'_>,
    mut emit_accept_error: E,
    #[cfg(test)] mut observe_detached_session: impl FnMut(tokio::task::JoinHandle<()>) + Send,
) -> anyhow::Result<()>
where
    E: FnMut(&std::io::Error, &IngressLateRuntimeContext) + Send,
{
    let ClientIngressOwner {
        backend,
        cfg,
        runtime,
        broker,
        late_runtime_context,
        mut external_shutdown,
        mut stdin_shutdown,
        selected_sessions,
        device_renewal,
        #[cfg(target_os = "linux")]
        wide_workers,
        #[cfg(target_os = "linux")]
        wide_forward_gate,
        #[cfg(target_os = "linux")]
        mut selected_signals,
    } = owner;
    let backend_id = late_runtime_context.backend_id.clone();
    let backend_runtime_id = late_runtime_context.backend_runtime_id.clone();
    let backend_kind = late_runtime_context.backend_kind.clone();
    let backend_kind_code = late_runtime_context.backend_kind_code;
    let requested_primary = late_runtime_context.requested_primary.clone();
    let requested_primary_code = late_runtime_context.requested_primary_code;
    let mode = late_runtime_context.mode.clone();
    let mode_code = late_runtime_context.mode_code;
    let wide_supported = late_runtime_context.wide_supported;
    let wide_platform_family_supported = late_runtime_context.wide_platform_family_supported;
    let wide_runtime_readiness = late_runtime_context.wide_runtime_readiness;
    let wide_rollout_profile = late_runtime_context.rollout_profile.clone();
    let wide_rollout_profile_code = late_runtime_context.rollout_profile_code;
    let wide_prerouting_interface = late_runtime_context.prerouting_interface.clone();
    let startup_path_code = late_runtime_context.path_code;
    let startup_fallback_reason_code = late_runtime_context.fallback_reason_code;
    let startup_fallback_reason = late_runtime_context.fallback_reason;
    let startup_bind_error_code = late_runtime_context.bind_error_code;
    // These are per-owner recovery limits, independent of accepted sessions.
    // A false shutdown-watch wake must not renew an already armed deadline.
    let mut retry_at = None;
    let mut next_retry_ms = 50_u64;
    let mut next_resource_diagnostic_at = None;
    loop {
        #[cfg(target_os = "linux")]
        let worker_failure = wide_workers.failure();
        #[cfg(not(target_os = "linux"))]
        let worker_failure = std::future::pending::<&'static str>();
        let accept_or_shutdown = async {
            let accept = async {
                if let Some(deadline) = retry_at {
                    tokio::time::sleep_until(deadline).await;
                }
                backend.accept().await
            };
            if let Some(shutdown) = external_shutdown.as_mut() {
                tokio::select! {
                    biased;
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            return None;
                        }
                        Some(None)
                    }
                    accept_result = accept => Some(Some(accept_result)),
                }
            } else if let Some(shutdown) = stdin_shutdown.as_mut() {
                tokio::select! {
                    biased;
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            return None;
                        }
                        Some(None)
                    }
                    accept_result = accept => Some(Some(accept_result)),
                }
            } else {
                Some(Some(accept.await))
            }
        };
        #[cfg(target_os = "linux")]
        let selected_stop = async {
            if let Some((terminate, interrupt)) = selected_signals.as_mut() {
                tokio::select! { _ = terminate.recv() => (), _ = interrupt.recv() => () }
            } else {
                std::future::pending::<()>().await;
            }
        };
        #[cfg(not(target_os = "linux"))]
        let selected_stop = std::future::pending::<()>();
        let accept_result = tokio::select! {
            biased;
            reason = device_renewal.failure() => {
                #[cfg(target_os = "linux")]
                wide_forward_gate.revoke();
                backend.shutdown().await;
                anyhow::bail!("{reason}");
            }
            failed_listener = backend.failure() => {
                #[cfg(target_os = "linux")]
                wide_forward_gate.revoke();
                backend.shutdown().await;
                anyhow::bail!("required ingress listener {failed_listener} stopped; client must restart");
            }
            failed_worker = worker_failure => {
                #[cfg(target_os = "linux")]
                wide_forward_gate.revoke();
                backend.shutdown().await;
                anyhow::bail!("required capture worker {failed_worker} stopped; client must restart");
            }
            reason = relay::outer_geneva_failure(cfg.relay.outer_geneva.is_some()) => {
                #[cfg(target_os = "linux")]
                wide_forward_gate.revoke();
                backend.shutdown().await;
                anyhow::bail!("{reason}");
            }
            _ = selected_stop => {
                #[cfg(target_os = "linux")]
                wide_forward_gate.revoke();
                backend.shutdown().await;
                return Ok(());
            }
            outcome = accept_or_shutdown => match outcome {
                None => {
                    #[cfg(target_os = "linux")]
                    wide_forward_gate.revoke();
                    backend.shutdown().await;
                    return Ok(());
                }
                Some(None) => continue,
                Some(Some(result)) => result,
            },
        };
        let mut intent = match accept_result {
            Ok(intent) => {
                retry_at = None;
                next_retry_ms = 50;
                // Success resets recovery cadence, not diagnostic admission.
                intent
            }
            Err(err) => {
                if native_resource_accept_error(&err) {
                    let now = tokio::time::Instant::now();
                    retry_at = Some(now + std::time::Duration::from_millis(next_retry_ms));
                    next_retry_ms = next_retry_ms.saturating_mul(2).min(1_000);
                    if next_resource_diagnostic_at.is_none_or(|deadline| now >= deadline) {
                        next_resource_diagnostic_at = Some(now + std::time::Duration::from_secs(1));
                        // Admit before either tracing or JSON formats the error.
                        emit_accept_error(&err, &late_runtime_context);
                    }
                } else {
                    emit_accept_error(&err, &late_runtime_context);
                }
                continue;
            }
        };
        if let IngressTransport::UdpDatagram(datagram) = &intent.transport {
            let wide_udp_surface =
                active_wide_udp_event_surface(&cfg, backend_kind_code, datagram.target.port);
            let response_action = datagram.response.action();
            // Emit an explicit ingress-side marker so DNS preview timeouts can be
            // separated from later relay/bootstrap failures.
            info!(
                event_code = RuntimeEventCode::IngressUdpDatagramObserved.as_str(),
                peer = ?intent.peer,
                backend = %backend_id,
                backend_runtime_id = %backend_runtime_id,
                backend_kind = %backend_kind,
                requested_primary = %requested_primary,
                mode = %mode,
                wide_supported = ?wide_supported,
                wide_platform_family_supported = ?wide_platform_family_supported,
                wide_runtime_readiness = ?wide_runtime_readiness,
                rollout_profile = ?wide_rollout_profile,
                prerouting_interface = ?wide_prerouting_interface,
                wide_udp_capture_contract = ?wide_udp_surface.capture_contract,
                wide_udp_capture_support_tier = ?wide_udp_surface.capture_support_tier,
                wide_udp_capture_policy = ?wide_udp_surface.capture_policy,
                wide_udp_capture_runtime_scope = ?wide_udp_surface.capture_runtime_scope,
                wide_udp_capture_match_kind = ?wide_udp_surface.capture_match_kind,
                wide_udp_capture_accept_reason_code = ?wide_udp_surface.capture_accept_reason_code,
                wide_udp_preview_policy = ?wide_udp_surface.preview_policy,
                wide_udp_preview_match_kind = ?wide_udp_surface.preview_match_kind,
                wide_udp_preview_accept_reason_code = ?wide_udp_surface.preview_accept_reason_code,
                wide_udp_preview_ports = ?wide_udp_surface.preview_ports,
                target_host = %datagram.target.host,
                target_port = datagram.target.port,
                payload_len = datagram.payload.len(),
                response_action = response_action,
                "ingress udp datagram observed"
            );
            runtime_jsonl::emit(
                "info",
                RuntimeEventCode::IngressUdpDatagramObserved,
                "ingress udp datagram observed",
                json!({
                    "peer": intent.peer.to_string(),
                    "backend": backend_id,
                    "backend_runtime_id": backend_runtime_id,
                    "backend_kind": backend_kind,
                    "backend_kind_code": backend_kind_code,
                    "requested_primary": requested_primary,
                    "requested_primary_code": requested_primary_code,
                    "mode": mode,
                    "mode_code": mode_code,
                    "wide_supported": wide_supported,
                    "wide_platform_family_supported": wide_platform_family_supported,
                    "wide_runtime_readiness": wide_runtime_readiness,
                    "rollout_profile": wide_rollout_profile,
                    "rollout_profile_code": wide_rollout_profile_code,
                    "prerouting_interface": wide_prerouting_interface.as_deref(),
                    "startup_path_code": startup_path_code,
                    "startup_fallback_reason_code": startup_fallback_reason_code,
                    "startup_fallback_reason": startup_fallback_reason,
                    "startup_bind_error_code": startup_bind_error_code,
                    "wide_udp_capture_contract": wide_udp_surface.capture_contract,
                    "wide_udp_capture_support_tier": wide_udp_surface.capture_support_tier,
                    "wide_udp_capture_policy": wide_udp_surface.capture_policy,
                    "wide_udp_capture_runtime_scope": wide_udp_surface.capture_runtime_scope,
                    "wide_udp_capture_match_kind": wide_udp_surface.capture_match_kind,
                    "wide_udp_capture_accept_reason_code": wide_udp_surface.capture_accept_reason_code,
                    "wide_udp_preview_policy": wide_udp_surface.preview_policy,
                    "wide_udp_preview_match_kind": wide_udp_surface.preview_match_kind,
                    "wide_udp_preview_accept_reason_code": wide_udp_surface.preview_accept_reason_code,
                    "wide_udp_preview_ports": wide_udp_surface.preview_ports,
                    "target_host": datagram.target.host,
                    "target_port": datagram.target.port,
                    "payload_len": datagram.payload.len(),
                    "response_action": response_action
                }),
            );
        }
        // Reject paths that the runtime already knows it cannot service before
        // the broker emits a misleading SOCKS success reply.
        if reject_tcp_connect_if_runtime_unready(&mut intent, &cfg, &late_runtime_context).await {
            continue;
        }
        if reject_udp_associate_if_runtime_unready(&mut intent, &cfg, &late_runtime_context).await {
            continue;
        }

        let cfg = cfg.clone();
        let runtime = runtime.clone();
        let backend_id = backend_id.clone();
        let backend_runtime_id = backend_runtime_id.clone();
        let backend_kind = backend_kind.clone();
        let requested_primary = requested_primary.clone();
        let mode = mode.clone();
        let wide_rollout_profile = wide_rollout_profile.clone();
        let wide_prerouting_interface = wide_prerouting_interface.clone();
        let late_runtime_context = late_runtime_context.clone();
        let session = async move {
            // A target recovered from a fake IP stays bound to its name until
            // the session ends.
            let _target_lease = intent.take_target_lease();
            let peer = intent.peer;
            let ingress_kind = intent.kind;
            match broker.normalize(intent).await {
                Ok(session) => {
                    let session_kind = match &session {
                        BrokeredSession::TcpConnect(session) => session.ingress_kind,
                        BrokeredSession::UdpAssociate(session) => session.ingress_kind,
                        BrokeredSession::UdpDatagram(session) => session.ingress_kind,
                    };
                    if let Err(e) = runtime
                        .handle_session(session, &cfg, late_runtime_context)
                        .await
                    {
                        let direct_relay_handoff =
                            e.downcast_ref::<direct::DirectRelayHandoffTerminalFailure>();
                        let relay_terminal = direct_relay_handoff
                            .map(|failure| failure.relay())
                            .or_else(|| e.downcast_ref::<relay::RelayTerminalFailure>());
                        let relay_attempts_total =
                            relay_terminal.map(|failure| failure.attempts_total);
                        let relay_planned_transports =
                            relay_terminal.map(|failure| failure.planned_transports.clone());
                        let relay_last_transport =
                            relay_terminal.and_then(|failure| failure.last_transport.as_deref());
                        let session_error_kind = relay_terminal
                            .and_then(|failure| failure.error_kind)
                            .or_else(|| anyhow_error_kind_code(&e));
                        let session_error_chain = if runtime_jsonl::private_logs_enabled() {
                            runtime_jsonl::privacy::error_chain(&e)
                        } else {
                            relay_terminal
                                .map(|failure| failure.error_chain.clone())
                                .unwrap_or_else(|| anyhow_error_chain_messages(&e))
                        };
                        let session_error = runtime_jsonl::privacy::error_message(&e);
                        error!(
                            event_code = RuntimeEventCode::IngressSessionFailed.as_str(),
                            ?peer,
                            ?ingress_kind,
                            ?session_kind,
                            backend = %backend_id,
                            backend_runtime_id = %backend_runtime_id,
                            backend_kind = %backend_kind,
                            requested_primary = %requested_primary,
                            mode = %mode,
                            wide_supported = ?wide_supported,
                            wide_platform_family_supported = ?wide_platform_family_supported,
                            wide_runtime_readiness = ?wide_runtime_readiness,
                            rollout_profile = ?wide_rollout_profile,
                            prerouting_interface = ?wide_prerouting_interface,
                            startup_path_code = startup_path_code,
                            startup_fallback_reason_code = ?startup_fallback_reason_code,
                            startup_fallback_reason = ?startup_fallback_reason,
                            startup_bind_error_code = ?startup_bind_error_code,
                            relay_terminal = relay_terminal.is_some(),
                            direct_relay_handoff = direct_relay_handoff.is_some(),
                            direct_relay_handoff_path = ?direct_relay_handoff.map(|failure| failure.handoff_path()),
                            direct_relay_handoff_reason_code = ?direct_relay_handoff.map(|failure| failure.reason_code()),
                            relay_attempts_total = ?relay_attempts_total,
                            relay_last_transport = ?relay_last_transport,
                            session_error_kind = session_error_kind.unwrap_or("unclassified"),
                            session_error_chain = ?session_error_chain,
                            error = %session_error,
                            "ingress session failed"
                        );
                        runtime_jsonl::emit(
                            "error",
                            RuntimeEventCode::IngressSessionFailed,
                            "ingress session failed",
                            json!({
                                "peer": peer.to_string(),
                                "ingress_kind": format!("{:?}", ingress_kind),
                                "ingress_kind_code": ingress_kind.as_code(),
                                "session_kind": format!("{:?}", session_kind),
                                "session_kind_code": session_kind.as_code(),
                                "backend": backend_id,
                                "backend_runtime_id": backend_runtime_id,
                                "backend_kind": backend_kind,
                                "backend_kind_code": backend_kind_code,
                                "requested_primary": requested_primary,
                                "requested_primary_code": requested_primary_code,
                                "mode": mode,
                                "mode_code": mode_code,
                                "wide_supported": wide_supported,
                                "wide_platform_family_supported": wide_platform_family_supported,
                                "wide_runtime_readiness": wide_runtime_readiness,
                                "rollout_profile": wide_rollout_profile,
                                "rollout_profile_code": wide_rollout_profile_code,
                                "prerouting_interface": wide_prerouting_interface.as_deref(),
                                "startup_path_code": startup_path_code,
                                "startup_fallback_reason_code": startup_fallback_reason_code,
                                "startup_fallback_reason": startup_fallback_reason,
                                "startup_bind_error_code": startup_bind_error_code,
                                "relay_terminal": relay_terminal.is_some(),
                                "relay_target": relay_terminal.and_then(|failure| failure.target.as_deref()),
                                "relay_port": relay_terminal.and_then(|failure| failure.port),
                                "relay_server": relay_terminal.map(|failure| failure.relay_server.as_str()),
                                "relay_server_name": relay_terminal.map(|failure| failure.relay_server_name.as_str()),
                                "relay_attempts_total": relay_attempts_total,
                                "relay_planned_transports": relay_planned_transports,
                                "relay_last_transport": relay_last_transport,
                                "direct_relay_handoff": direct_relay_handoff.is_some(),
                                "direct_relay_handoff_path": direct_relay_handoff.map(|failure| failure.handoff_path()),
                                "direct_relay_handoff_reason_code": direct_relay_handoff.map(|failure| failure.reason_code()),
                                "direct_relay_handoff_retry_attempted": direct_relay_handoff.and_then(|failure| failure.active_stall_probe_retry_attempted()),
                                "session_error_kind": session_error_kind,
                                "error_chain": session_error_chain,
                                "error": session_error
                            }),
                        );
                    }
                }
                Err(e) => {
                    error!(
                        event_code = RuntimeEventCode::IngressSessionBrokerFailed.as_str(),
                        ?peer,
                        ?ingress_kind,
                        backend = %backend_id,
                        backend_runtime_id = %backend_runtime_id,
                        backend_kind = %backend_kind,
                        requested_primary = %requested_primary,
                        mode = %mode,
                        wide_supported = ?wide_supported,
                        wide_platform_family_supported = ?wide_platform_family_supported,
                        wide_runtime_readiness = ?wide_runtime_readiness,
                        rollout_profile = ?wide_rollout_profile,
                        prerouting_interface = ?wide_prerouting_interface,
                        startup_path_code = startup_path_code,
                        startup_fallback_reason_code = ?startup_fallback_reason_code,
                        startup_fallback_reason = ?startup_fallback_reason,
                        startup_bind_error_code = ?startup_bind_error_code,
                        broker_error_code = e.error_code(),
                        broker_source_error_kind = e.source_error_kind(),
                        "session broker: {:#}",
                        e
                    );
                    runtime_jsonl::emit(
                        "error",
                        RuntimeEventCode::IngressSessionBrokerFailed,
                        "session broker failed",
                        json!({
                            "peer": peer.to_string(),
                            "ingress_kind": format!("{:?}", ingress_kind),
                            "ingress_kind_code": ingress_kind.as_code(),
                            "backend": backend_id,
                            "backend_runtime_id": backend_runtime_id,
                            "backend_kind": backend_kind,
                            "backend_kind_code": backend_kind_code,
                            "requested_primary": requested_primary,
                            "requested_primary_code": requested_primary_code,
                            "mode": mode,
                            "mode_code": mode_code,
                            "wide_supported": wide_supported,
                            "wide_platform_family_supported": wide_platform_family_supported,
                            "wide_runtime_readiness": wide_runtime_readiness,
                            "rollout_profile": wide_rollout_profile,
                            "rollout_profile_code": wide_rollout_profile_code,
                            "prerouting_interface": wide_prerouting_interface.as_deref(),
                            "startup_path_code": startup_path_code,
                            "startup_fallback_reason_code": startup_fallback_reason_code,
                            "startup_fallback_reason": startup_fallback_reason,
                            "startup_bind_error_code": startup_bind_error_code,
                            "broker_error_code": e.error_code(),
                            "broker_source_error_kind": e.source_error_kind(),
                            "request_kind": e.request_kind(),
                            "broker_stage": e.broker_stage(),
                            "target_host": e.target_host(),
                            "target_port": e.target_port(),
                            "client_ip": e.client_ip().map(|ip| ip.to_string()),
                            "udp_bind_addr": e.bind_addr(),
                            "response_action": e.response_action(),
                            "error": format!("{:#}", e)
                        }),
                    );
                }
            }
        };
        if let Some(tasks) = selected_sessions.as_mut() {
            while tasks.try_join_next().is_some() {}
            #[cfg(target_os = "linux")]
            if backend.kind() == crate::ingress::IngressKind::WidePrimary {
                spawn_gated_owned_session(tasks, wide_forward_gate.clone(), session);
            } else {
                tasks.spawn(session);
            }
            #[cfg(not(target_os = "linux"))]
            tasks.spawn(session);
        } else {
            let _session = tokio::spawn(session);
            #[cfg(test)]
            observe_detached_session(_session);
        }
    }
}

fn version_string(binary: &str) -> String {
    format!(
        "{binary} {} (git {}, built {}, target {}, features {}, cargo-lock {})",
        env!("CARGO_PKG_VERSION"),
        BUILD_GIT_SHA,
        BUILD_TIMESTAMP,
        BUILD_TARGET,
        BUILD_FEATURES,
        CARGO_LOCK_SHA256,
    )
}
