use super::{
    ActiveIngressBackend, BackendNote, BackendNoteCode, FallbackReasonCode, PreflightHint,
    PreflightHintCode, PreflightSeverity, RuntimeProbeCode, SelectionErrorCode, SelectionHintCode,
    StartupHintCode, WideRuntimeReadiness,
};
use aegis_core::{
    IngressPrimary, Settings, WidePlatformBackend, WideRolloutProfile, WideUdpCaptureContract,
};
use std::io;
use std::net::SocketAddr;

pub(in crate::ingress::preflight) fn collect_preflight_hints(cfg: &Settings) -> Vec<PreflightHint> {
    let mut hints = Vec::new();
    if cfg.ingress.wide.listen == cfg.socks.listen {
        hints.push(PreflightHint {
            code: PreflightHintCode::SharedListeners,
            severity: PreflightSeverity::Warn,
            message:
                "wide and SOCKS5 listeners share the same address; use separate ports to keep fallback diagnostics unambiguous",
        });
    }
    if !cfg.socks.listen.ip().is_loopback() {
        hints.push(PreflightHint {
            code: PreflightHintCode::SocksListenerExposed,
            severity: PreflightSeverity::Warn,
            message:
                "SOCKS5 fallback listener is not loopback-scoped; keep socks.listen on localhost unless you intentionally expose it",
        });
    }
    if !wide_rollout_intent_requested(cfg) {
        return hints;
    }
    if cfg.ingress.wide.capture_dns {
        if cfg.ingress.wide.udp_capture_contract == WideUdpCaptureContract::GenericCaptureUnstable {
            if cfg!(target_os = "macos")
                && cfg.ingress.wide.platform_backend == WidePlatformBackend::MacosPf
            {
                hints.push(PreflightHint {
                    code: PreflightHintCode::GenericUdpCaptureContractRequested,
                    severity: PreflightSeverity::Warn,
                    message:
                        "ingress.wide.udp_capture_contract requests generic_capture_unstable, which for macos_pf now opens only a guarded system_wide_phase3 boundary; it does not activate a broader runtime capture path yet",
                });
                hints.push(PreflightHint {
                    code: PreflightHintCode::CaptureDnsPreviewOnly,
                    severity: PreflightSeverity::Warn,
                    message:
                        "ingress.wide.capture_dns with generic_capture_unstable on macos_pf is currently boundary-only: helper/preflight/runtime vocabulary is materialized for system_wide_phase3, but live broader UDP/system-wide interception still remains out of scope",
                });
            } else {
                hints.push(PreflightHint {
                    code: PreflightHintCode::GenericUdpCaptureContractRequested,
                    severity: PreflightSeverity::Warn,
                    message:
                        "ingress.wide.udp_capture_contract requests generic_capture_unstable, which now enables a broader Linux UDP receive path without the preview allowlist, but it remains unstable: non-Linux parity and broader production-hardened rollout coverage are still missing",
                });
                hints.push(PreflightHint {
                    code: PreflightHintCode::CaptureDnsPreviewOnly,
                    severity: PreflightSeverity::Warn,
                    message:
                        "ingress.wide.capture_dns with generic_capture_unstable now reaches a broader Linux UDP path with family-aware IPv4/IPv6 contract surfaces, explicit xtables/nft helper backend selection, hosted smoke coverage for nft-backed DNS/generic paths, and a richer-host validation lane, but generic UDP interception is still partial: non-Linux support and broader production-hardened operator rollout are not implemented yet",
                });
            }
        } else {
            hints.push(PreflightHint {
                code: PreflightHintCode::CaptureDnsPreviewOnly,
                severity: PreflightSeverity::Warn,
                message:
                    "ingress.wide.capture_dns is configured, but the current DNS capture path is still a narrow Linux preview: IPv6 DNS preview, explicit xtables/nft helper backend selection, hosted smoke coverage for nft-backed DNS/generic paths, and a richer-host validation lane now exist, yet generic UDP interception outside the selected contract, non-Linux support, and broad production-ready operator rollout are still not implemented",
            });
            hints.push(PreflightHint {
                code: PreflightHintCode::UdpPreviewAllowlistOnly,
                severity: PreflightSeverity::Warn,
                message:
                    "the current Linux UDP preview is allowlist-only: it accepts only ingress.wide.dns_port plus ingress.wide.udp_preview_ports, while non-listed UDP datagrams are dropped until a broader generic UDP capture contract exists",
            });
        }
        if cfg!(target_os = "linux")
            && cfg.ingress.wide.platform_backend == WidePlatformBackend::LinuxRedirect
        {
            hints.push(PreflightHint {
                code: PreflightHintCode::LinuxRedirectDnsPreviewNatLimited,
                severity: PreflightSeverity::Warn,
                message:
                    "linux_redirect + capture_dns is currently NAT-limited for UDP success-paths: REDIRECT rewrites the datagram destination to the local listener, so relay-backed DNS success should be validated with linux_tproxy while redirect remains a diagnostic/reproducer path",
            });
        }
    }

    match cfg.ingress.wide.platform_backend {
        WidePlatformBackend::Auto => hints.push(PreflightHint {
            code: PreflightHintCode::AutoUsesRedirectCompatibleStartup,
            severity: PreflightSeverity::Info,
            message:
                "wide auto backend keeps redirect-compatible startup semantics; prefer explicit linux_tproxy only for privileged transparent mode",
        }),
        WidePlatformBackend::LinuxRedirect if cfg!(target_os = "linux") => hints.push(PreflightHint {
            code: PreflightHintCode::RedirectOutputNeedsExemptUid,
            severity: PreflightSeverity::Info,
            message:
                "Linux REDIRECT rollout should exempt the aegis-client UID from OUTPUT capture to avoid self-looping its own sockets",
        }),
        WidePlatformBackend::LinuxTproxy => {
            hints.push(PreflightHint {
                code: PreflightHintCode::LinuxTproxyRequiresIpTransparent,
                severity: PreflightSeverity::Warn,
                message: "explicit linux_tproxy requires successful IP_TRANSPARENT on the listener",
            });
            if cfg.ingress.wide.default_mark == 0 {
                hints.push(PreflightHint {
                    code: PreflightHintCode::LinuxTproxyNeedsNonZeroMark,
                    severity: PreflightSeverity::Warn,
                    message:
                        "linux_tproxy usually expects a non-zero default_mark so policy routing can distinguish intercepted traffic",
                });
            }
        }
        _ => {}
    }

    match cfg.ingress.wide.rollout_profile {
        WideRolloutProfile::OutputOnlySafe => {
            hints.push(PreflightHint {
                code: PreflightHintCode::RolloutOutputOnlySafe,
                severity: PreflightSeverity::Info,
                message:
                    "output_only_safe rollout profile assumes local OUTPUT capture first; prefer auto or linux_redirect before broader interception",
            });
            if cfg.ingress.wide.platform_backend == WidePlatformBackend::LinuxTproxy {
                hints.push(PreflightHint {
                    code: PreflightHintCode::RolloutProfileBackendMismatch,
                    severity: PreflightSeverity::Warn,
                    message:
                        "output_only_safe rollout profile does not match explicit linux_tproxy; prefer auto/linux_redirect or switch rollout_profile to transparent_privileged",
                });
            }
        }
        WideRolloutProfile::PreroutingScoped => hints.push(PreflightHint {
            code: PreflightHintCode::RolloutPreroutingScoped,
            severity: PreflightSeverity::Info,
            message:
                "prerouting_scoped rollout profile expects interception to stay limited to an explicit interface scope rather than all ingress traffic",
        }),
        WideRolloutProfile::TransparentPrivileged => {
            hints.push(PreflightHint {
                code: PreflightHintCode::RolloutTransparentPrivileged,
                severity: PreflightSeverity::Warn,
                message:
                    "transparent_privileged rollout profile expects privileged transparent interception with policy routing and successful IP_TRANSPARENT",
            });
            if cfg.ingress.wide.platform_backend != WidePlatformBackend::LinuxTproxy {
                hints.push(PreflightHint {
                    code: PreflightHintCode::RolloutProfileBackendMismatch,
                    severity: PreflightSeverity::Warn,
                    message:
                        "transparent_privileged rollout profile usually expects platform_backend = linux_tproxy",
                });
            }
        }
    }
    if cfg.ingress.wide.rollout_profile == WideRolloutProfile::PreroutingScoped
        && configured_prerouting_interface(cfg).is_none()
    {
        hints.push(PreflightHint {
            code: PreflightHintCode::PreroutingInterfaceMissing,
            severity: PreflightSeverity::Warn,
            message:
                "prerouting_scoped rollout profile needs ingress.wide.prerouting_interface so PREROUTING capture does not silently expand to every interface",
        });
    }
    if detected_prerouting_interface_candidate(cfg).is_some() {
        hints.push(PreflightHint {
            code: PreflightHintCode::PreroutingInterfaceCandidateDetected,
            severity: PreflightSeverity::Info,
            message:
                "Linux routing suggests a candidate interface for PREROUTING scope; confirm it and keep ingress.wide.prerouting_interface aligned with AEGIS_WIDE_INTERFACE instead of relying on all-interface capture",
        });
    }
    if cfg!(target_os = "linux") && cfg.ingress.wide.platform_backend == WidePlatformBackend::Auto {
        hints.push(PreflightHint {
            code: PreflightHintCode::RedirectOutputNeedsExemptUid,
            severity: PreflightSeverity::Info,
            message:
                "Linux auto rollout typically starts with REDIRECT-compatible OUTPUT capture; exempt the aegis-client UID to avoid self-looping its own sockets",
        });
    }

    hints
}

fn wide_rollout_intent_requested(cfg: &Settings) -> bool {
    cfg.ingress.primary == IngressPrimary::Wide && cfg.ingress.wide.enabled
}

fn macos_system_wide_phase3_boundary_requested(_cfg: &Settings) -> bool {
    #[cfg(target_os = "macos")]
    {
        if _cfg.ingress.wide.platform_backend == WidePlatformBackend::MacosPf {
            let report = crate::ingress::wide::macos::MacosWidePrimaryBackend::capability_report(
                &_cfg.ingress.wide,
            );
            return report.scope_target
                == crate::ingress::wide::macos::MacosWideScopeTarget::SystemWidePhase3;
        }
    }
    false
}

pub(in crate::ingress::preflight) fn requested_udp_capture_contract(
    cfg: &Settings,
) -> Option<&'static str> {
    if !(cfg.ingress.wide.enabled && cfg.ingress.wide.capture_dns) {
        return None;
    }
    match cfg.ingress.wide.udp_capture_contract {
        WideUdpCaptureContract::PreviewAllowlistOnly => Some("preview_allowlist_only"),
        WideUdpCaptureContract::GenericCaptureUnstable => Some("generic_capture_unstable"),
    }
}

pub(in crate::ingress::preflight) fn requested_udp_capture_support_tier(
    cfg: &Settings,
) -> Option<&'static str> {
    if !(cfg.ingress.wide.enabled && cfg.ingress.wide.capture_dns) {
        return None;
    }
    match cfg.ingress.wide.udp_capture_contract {
        WideUdpCaptureContract::PreviewAllowlistOnly => Some("supported_preview"),
        WideUdpCaptureContract::GenericCaptureUnstable => Some("guarded_unstable"),
    }
}

pub(in crate::ingress::preflight) fn active_udp_capture_contract(
    cfg: &Settings,
    backend_choice: Option<ActiveIngressBackend>,
) -> Option<&'static str> {
    if !matches!(backend_choice, Some(ActiveIngressBackend::WidePrimary)) {
        return None;
    }
    if !(cfg.ingress.wide.enabled && cfg.ingress.wide.capture_dns) {
        return None;
    }
    match cfg.ingress.wide.udp_capture_contract {
        WideUdpCaptureContract::PreviewAllowlistOnly => Some("preview_allowlist_only"),
        WideUdpCaptureContract::GenericCaptureUnstable => Some("generic_capture_unstable"),
    }
}

pub(in crate::ingress::preflight) fn active_udp_capture_support_tier(
    cfg: &Settings,
    backend_choice: Option<ActiveIngressBackend>,
) -> Option<&'static str> {
    if !matches!(backend_choice, Some(ActiveIngressBackend::WidePrimary)) {
        return None;
    }
    requested_udp_capture_support_tier(cfg)
}

pub(in crate::ingress::preflight) fn active_udp_capture_policy(
    cfg: &Settings,
    backend_choice: Option<ActiveIngressBackend>,
) -> Option<&'static str> {
    if !matches!(backend_choice, Some(ActiveIngressBackend::WidePrimary)) {
        return None;
    }
    if !(cfg.ingress.wide.enabled && cfg.ingress.wide.capture_dns) {
        return None;
    }
    match cfg.ingress.wide.udp_capture_contract {
        WideUdpCaptureContract::PreviewAllowlistOnly => Some("allowlist_ports"),
        // Keep the first broader generic mode explicit instead of forcing automation
        // to infer it from missing preview-only fields.
        WideUdpCaptureContract::GenericCaptureUnstable => match cfg.ingress.wide.listen {
            SocketAddr::V4(_) => Some("any_target_port_linux_ipv4_unstable"),
            SocketAddr::V6(_) => Some("any_target_port_linux_ipv6_unstable"),
        },
    }
}

pub(in crate::ingress::preflight) fn active_udp_capture_runtime_scope(
    cfg: &Settings,
    backend_choice: Option<ActiveIngressBackend>,
) -> Option<&'static str> {
    if !matches!(backend_choice, Some(ActiveIngressBackend::WidePrimary)) {
        return None;
    }
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

pub(in crate::ingress::preflight) fn wide_backend_current_stage(
    _cfg: &Settings,
) -> Option<&'static str> {
    #[cfg(target_os = "macos")]
    {
        if _cfg.ingress.wide.platform_backend == WidePlatformBackend::MacosPf {
            let report = crate::ingress::wide::macos::MacosWidePrimaryBackend::capability_report(
                &_cfg.ingress.wide,
            );
            return Some(report.current_stage.as_code());
        }
    }
    None
}

pub(in crate::ingress::preflight) fn wide_backend_scope_target(
    _cfg: &Settings,
) -> Option<&'static str> {
    #[cfg(target_os = "macos")]
    {
        if _cfg.ingress.wide.platform_backend == WidePlatformBackend::MacosPf {
            let report = crate::ingress::wide::macos::MacosWidePrimaryBackend::capability_report(
                &_cfg.ingress.wide,
            );
            return Some(report.scope_target.as_code());
        }
    }
    None
}

pub(in crate::ingress::preflight) fn wide_backend_reason_code(
    _cfg: &Settings,
) -> Option<&'static str> {
    #[cfg(target_os = "macos")]
    {
        if _cfg.ingress.wide.platform_backend == WidePlatformBackend::MacosPf {
            let report = crate::ingress::wide::macos::MacosWidePrimaryBackend::capability_report(
                &_cfg.ingress.wide,
            );
            return Some(report.reason_code);
        }
    }
    None
}

pub(in crate::ingress::preflight) fn selection_error_hint(
    cfg: &Settings,
) -> (SelectionHintCode, &'static str) {
    if !cfg.ingress.wide.enabled {
        (
            SelectionHintCode::EnableWideOrSwitchPrimaryToSocks5,
            "enable [ingress.wide] or switch ingress.primary to socks5",
        )
    } else if macos_system_wide_phase3_boundary_requested(cfg) {
        #[cfg(target_os = "macos")]
        {
            let report = crate::ingress::wide::macos::MacosWidePrimaryBackend::capability_report(
                &cfg.ingress.wide,
            );
            if report.current_stage
                == crate::ingress::wide::macos::MacosWideCurrentStage::SystemWidePhase3PreparedBoundary
            {
                (
                    SelectionHintCode::UseSupportedBackendOrAllowFallback,
                    "macos_pf system_wide_phase3 is now in prepared-boundary mode; keep fallback enabled or continue operator acceptance while broader live interception remains out of scope",
                )
            } else {
                (
                    SelectionHintCode::UseSupportedBackendOrAllowFallback,
                    "macos_pf system_wide_phase3 is currently boundary-only; allow fallback or stay on the narrower tcp_only/dns_preview contours while testing",
                )
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            (
                SelectionHintCode::UseSupportedBackendOrAllowFallback,
                "macos_pf system_wide_phase3 is currently boundary-only; allow fallback or stay on the narrower tcp_only/dns_preview contours while testing",
            )
        }
    } else if cfg.ingress.wide.platform_backend == WidePlatformBackend::LinuxTproxy {
        (
            SelectionHintCode::UseSupportedPlatformBackendOrAllowFallbackWhileTesting,
            "use a supported platform backend for this OS, or allow SOCKS5 fallback while testing",
        )
    } else {
        (
            SelectionHintCode::UseSupportedBackendOrAllowFallback,
            "choose a supported wide backend for this platform, or allow SOCKS5 fallback",
        )
    }
}

pub(in crate::ingress::preflight) fn selection_error_code(cfg: &Settings) -> SelectionErrorCode {
    if !cfg.ingress.wide.enabled {
        SelectionErrorCode::WideDisabledInConfig
    } else if macos_system_wide_phase3_boundary_requested(cfg) {
        SelectionErrorCode::WideBackendBoundaryOnly
    } else {
        SelectionErrorCode::UnsupportedWideBackend
    }
}

pub(in crate::ingress::preflight) fn fallback_reason_code(cfg: &Settings) -> FallbackReasonCode {
    if !cfg.ingress.wide.enabled {
        FallbackReasonCode::WideDisabledInConfig
    } else if macos_system_wide_phase3_boundary_requested(cfg) {
        FallbackReasonCode::WideBackendBoundaryOnly
    } else {
        FallbackReasonCode::UnsupportedWideBackend
    }
}

pub(in crate::ingress::preflight) fn rollout_profile_selection_error(
    cfg: &Settings,
) -> Option<(SelectionErrorCode, String, SelectionHintCode, &'static str)> {
    match cfg.ingress.wide.rollout_profile {
        WideRolloutProfile::PreroutingScoped if configured_prerouting_interface(cfg).is_none() => {
            Some((
                SelectionErrorCode::RolloutProfilePrerequisites,
                "prerouting_scoped rollout profile requires ingress.wide.prerouting_interface"
                    .to_string(),
                SelectionHintCode::SetPreroutingInterfaceOrSwitchRolloutProfile,
                "set ingress.wide.prerouting_interface to the interface that should receive PREROUTING capture, or switch rollout_profile to output_only_safe",
            ))
        }
        WideRolloutProfile::OutputOnlySafe
            if cfg.ingress.wide.platform_backend == WidePlatformBackend::LinuxTproxy =>
        {
            Some((
                SelectionErrorCode::RolloutProfileBackendMismatch,
                "output_only_safe rollout profile does not support explicit linux_tproxy backend"
                    .to_string(),
                SelectionHintCode::UseRedirectBackendOrSwitchRolloutProfile,
                "use auto/linux_redirect for output_only_safe, or switch rollout_profile to transparent_privileged",
            ))
        }
        WideRolloutProfile::TransparentPrivileged
            if cfg.ingress.wide.platform_backend != WidePlatformBackend::LinuxTproxy =>
        {
            Some((
                SelectionErrorCode::RolloutProfileBackendMismatch,
                format!(
                    "transparent_privileged rollout profile requires linux_tproxy backend, got {:?}",
                    cfg.ingress.wide.platform_backend
                ),
                SelectionHintCode::UseTproxyBackendOrSwitchRolloutProfile,
                "set platform_backend = linux_tproxy for transparent_privileged rollout, or switch rollout_profile to output_only_safe/prerouting_scoped",
            ))
        }
        WideRolloutProfile::TransparentPrivileged if cfg.ingress.wide.default_mark == 0 => Some((
            SelectionErrorCode::RolloutProfilePrerequisites,
            "transparent_privileged rollout profile requires a non-zero default_mark".to_string(),
            SelectionHintCode::SetNonZeroDefaultMark,
            "set ingress.wide.default_mark to a non-zero fwmark so policy routing can distinguish intercepted traffic",
        )),
        _ => None,
    }
}

pub(in crate::ingress::preflight) fn configured_prerouting_interface(
    cfg: &Settings,
) -> Option<&str> {
    cfg.ingress
        .wide
        .prerouting_interface
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn rollout_expects_explicit_prerouting_scope(cfg: &Settings) -> bool {
    matches!(
        cfg.ingress.wide.rollout_profile,
        WideRolloutProfile::PreroutingScoped | WideRolloutProfile::TransparentPrivileged
    )
}

#[cfg(target_os = "linux")]
fn parse_linux_default_route_interface(route_table: &str) -> Option<String> {
    for line in route_table.lines().skip(1) {
        let mut columns = line.split_whitespace();
        let iface = columns.next()?;
        let destination = columns.next()?;
        let _gateway = columns.next()?;
        let flags = columns.next()?;
        if destination != "00000000" {
            continue;
        }
        let flags = u16::from_str_radix(flags, 16).ok()?;
        if (flags & 0x2) == 0 {
            continue;
        }
        if iface.trim().is_empty() {
            continue;
        }
        return Some(iface.to_string());
    }
    None
}

fn linux_default_route_interface() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let route_table = std::fs::read_to_string("/proc/net/route").ok()?;
        parse_linux_default_route_interface(&route_table)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

pub(in crate::ingress::preflight) fn detected_prerouting_interface_candidate(
    cfg: &Settings,
) -> Option<String> {
    if configured_prerouting_interface(cfg).is_some()
        || !rollout_expects_explicit_prerouting_scope(cfg)
    {
        return None;
    }
    linux_default_route_interface()
}

pub(in crate::ingress::preflight) fn wide_runtime_readiness(
    cfg: &Settings,
    wide_platform_family_supported: bool,
    wide_supported: bool,
) -> WideRuntimeReadiness {
    if !cfg.ingress.wide.enabled {
        return WideRuntimeReadiness::Disabled;
    }
    if rollout_profile_selection_error(cfg).is_some() {
        return WideRuntimeReadiness::ConfigError;
    }
    if macos_system_wide_phase3_boundary_requested(cfg) {
        #[cfg(target_os = "macos")]
        {
            let report = crate::ingress::wide::macos::MacosWidePrimaryBackend::capability_report(
                &cfg.ingress.wide,
            );
            if report.current_stage
                == crate::ingress::wide::macos::MacosWideCurrentStage::SystemWidePhase3PreparedBoundary
            {
                return WideRuntimeReadiness::PreparedBoundary;
            }
        }
        return WideRuntimeReadiness::BoundaryOnly;
    }
    if !wide_platform_family_supported || !wide_supported {
        return WideRuntimeReadiness::UnsupportedAdapter;
    }
    if cfg.ingress.wide.platform_backend == WidePlatformBackend::LinuxTproxy {
        return WideRuntimeReadiness::NeedsPrivilege;
    }
    WideRuntimeReadiness::Ready
}

pub(in crate::ingress::preflight) fn backend_notes(cfg: &Settings) -> &'static [BackendNote] {
    if !wide_rollout_intent_requested(cfg) {
        return &[];
    }
    match cfg.ingress.wide.platform_backend {
        WidePlatformBackend::Auto => &[BackendNote {
            code: BackendNoteCode::AutoUsesRedirectCompatibleStartup,
            message:
                "auto keeps redirect-compatible startup semantics and may still need fallback on platforms without a real wide adapter",
        }],
        WidePlatformBackend::LinuxRedirect => &[BackendNote {
            code: BackendNoteCode::LinuxRedirectExpectsOriginalDst,
            message:
                "linux_redirect expects REDIRECT-style NAT/original-destination recovery rather than transparent IP_TRANSPARENT delivery",
        }],
        WidePlatformBackend::LinuxTproxy => &[BackendNote {
            code: BackendNoteCode::LinuxTproxyRequiresIpTransparent,
            message:
                "linux_tproxy expects transparent delivery and successful IP_TRANSPARENT on the listener",
        }],
        WidePlatformBackend::LinuxNfqueueObserver => &[BackendNote {
            code: BackendNoteCode::LinuxNfqueueObserverOptInRuntime,
            message:
                "linux_nfqueue_observer is an opt-in live nfnetlink runtime with supervised rule lifecycle; observer mode accepts packets, while explicit enforce mode applies the configured fail-closed IPv4/IPv6/UDP policy",
        }],
        WidePlatformBackend::Windivert => &[BackendNote {
            code: BackendNoteCode::PlatformAdapterStub,
            message:
                "this platform backend currently maps to an explicit unsupported adapter surface in the open-source runtime",
        }],
        WidePlatformBackend::WindowsWfpAle => &[BackendNote {
            code: BackendNoteCode::PlatformAdapterStub,
            message:
                "windows_wfp_ale is the selected Windows wide MVP config surface, but the WFP redirect adapter is not implemented in this runtime",
        }],
        WidePlatformBackend::MacosPf => {
            #[cfg(target_os = "macos")]
            {
                let report =
                    crate::ingress::wide::macos::MacosWidePrimaryBackend::capability_report(
                        &cfg.ingress.wide,
                    );
                if report.scope_target
                    == crate::ingress::wide::macos::MacosWideScopeTarget::SystemWidePhase3
                {
                    if report.current_stage
                        == crate::ingress::wide::macos::MacosWideCurrentStage::SystemWidePhase3PreparedBoundary
                    {
                        &[BackendNote {
                            code: BackendNoteCode::MacosPfSystemWidePhase3PreparedBoundary,
                            message:
                                "the local macos_pf helper now materializes a prepared system_wide_phase3 boundary for broader operator acceptance, but broader capture still remains intentionally non-bind-capable and out of the active runtime path",
                        }]
                    } else {
                        &[BackendNote {
                            code: BackendNoteCode::MacosPfSystemWidePhase3Boundary,
                            message:
                                "the local macos_pf helper now materializes system_wide_phase3 only as a guarded boundary milestone; broader capture still remains intentionally non-bind-capable and requires a separate host-level acceptance step later",
                        }]
                    }
                } else if report.bind_capable && cfg.ingress.wide.capture_dns {
                    &[BackendNote {
                        code: BackendNoteCode::MacosPfDnsPreviewEpic,
                        message:
                            "the local macos_pf helper now enables a narrow DNS preview phase-2 contour above the active TCP path; broader UDP/system-wide capture still remains out of scope",
                    }]
                } else if report.bind_capable {
                    &[BackendNote {
                        code: BackendNoteCode::MacosPfTcpOnlyEpic,
                        message:
                            "the local macos_pf helper now enables a narrow TCP-only phase-1 contour; DNS preview and broader system-wide capture still remain out of scope",
                    }]
                } else if cfg.ingress.wide.capture_dns {
                    &[BackendNote {
                        code: BackendNoteCode::MacosPfDnsPreviewEpic,
                        message:
                            "the separate macos_pf epic now expects explicit helper-backed dns_preview_phase2 state; without it the runtime still stays on the degraded fallback story",
                    }]
                } else {
                    &[BackendNote {
                        code: BackendNoteCode::MacosPfTcpOnlyEpic,
                        message:
                            "the separate macos_pf epic now targets a helper-backed TCP-only first milestone; without that local helper state the runtime still stays on the degraded fallback story",
                    }]
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                &[
                    BackendNote {
                        code: BackendNoteCode::PlatformAdapterStub,
                        message:
                            "this platform backend currently maps to an explicit unsupported adapter surface in the open-source runtime",
                    },
                    BackendNote {
                        code: BackendNoteCode::MacosPfTcpOnlyEpic,
                        message:
                            "the separate macos_pf epic now targets helper-backed TCP-only and DNS-preview milestones with their own local PF harness before any broader system-wide claim",
                    },
                    BackendNote {
                        code: BackendNoteCode::MacosPfSystemWidePhase3Boundary,
                        message:
                            "system_wide_phase3 on macos_pf is now opened only as a boundary contract in helper/runtime/docs; it is not a finished broader capture implementation",
                    },
                ]
            }
        }
    }
}

pub(in crate::ingress::preflight) fn classify_bind_failure(
    cfg: &Settings,
    err: &io::Error,
) -> (RuntimeProbeCode, StartupHintCode, &'static str) {
    let address_in_use = err.kind() == io::ErrorKind::AddrInUse
        || matches!(err.raw_os_error(), Some(48 | 98 | 10048));
    let message = err.to_string();
    if address_in_use && cfg.ingress.wide.listen == cfg.socks.listen {
        (
            RuntimeProbeCode::ListenerConflict,
            StartupHintCode::UseDistinctWideAndSocksListeners,
            "wide.listen conflicts with socks.listen; use different addresses or ports",
        )
    } else if address_in_use {
        (
            RuntimeProbeCode::ListenerBusy,
            StartupHintCode::VerifyWideListenIsFree,
            "verify that the configured wide listen address/port is free",
        )
    } else if err.kind() == io::ErrorKind::PermissionDenied
        && cfg.ingress.wide.platform_backend == WidePlatformBackend::LinuxTproxy
    {
        (
            RuntimeProbeCode::NeedsCapNetAdmin,
            StartupHintCode::NeedsRootOrCapNetAdminForIpTransparent,
            "explicit linux_tproxy needs root or CAP_NET_ADMIN so IP_TRANSPARENT can be set",
        )
    } else if err.kind() == io::ErrorKind::Unsupported
        || message.contains("not implemented yet")
        || message.contains("not implemented")
    {
        (
            RuntimeProbeCode::UnsupportedAdapter,
            StartupHintCode::SelectedWideBackendUnsupportedAdapter,
            "selected wide backend has no supported runtime adapter on this platform yet",
        )
    } else {
        (
            RuntimeProbeCode::BackendPrerequisites,
            StartupHintCode::VerifyWideListenerSettingsAndBackendPrerequisites,
            "verify wide listener settings and backend-specific prerequisites",
        )
    }
}

pub(in crate::ingress::preflight) fn classify_socks_bind_failure(
    cfg: &Settings,
    err: &io::Error,
) -> (RuntimeProbeCode, StartupHintCode, &'static str) {
    let address_in_use = err.kind() == io::ErrorKind::AddrInUse
        || matches!(err.raw_os_error(), Some(48 | 98 | 10048));
    if address_in_use && cfg.ingress.wide.listen == cfg.socks.listen {
        (
            RuntimeProbeCode::ListenerConflict,
            StartupHintCode::UseDistinctSocksAndWideListeners,
            "socks.listen conflicts with wide.listen; use different addresses or ports",
        )
    } else if address_in_use {
        (
            RuntimeProbeCode::ListenerBusy,
            StartupHintCode::VerifySocksListenIsFree,
            "verify that the configured socks.listen address/port is free",
        )
    } else {
        (
            RuntimeProbeCode::SocksBindFailed,
            StartupHintCode::VerifySocksFallbackListenerSettings,
            "verify SOCKS5 fallback listener settings",
        )
    }
}

pub(in crate::ingress::preflight) fn ingress_primary_name(cfg: &Settings) -> &'static str {
    match cfg.ingress.primary {
        IngressPrimary::Wide => "wide",
        IngressPrimary::Socks5 => "socks5",
    }
}

pub(in crate::ingress::preflight) fn active_backend_name(
    backend: ActiveIngressBackend,
) -> &'static str {
    match backend {
        ActiveIngressBackend::WidePrimary => "wide_primary",
        ActiveIngressBackend::Socks5Fallback => "socks5_fallback",
    }
}

pub(in crate::ingress::preflight) fn wide_platform_name(cfg: &Settings) -> &'static str {
    match cfg.ingress.wide.platform_backend {
        WidePlatformBackend::Auto => "auto",
        WidePlatformBackend::LinuxRedirect => "linux_redirect",
        WidePlatformBackend::LinuxTproxy => "linux_tproxy",
        WidePlatformBackend::LinuxNfqueueObserver => "linux_nfqueue_observer",
        WidePlatformBackend::Windivert => "windivert",
        WidePlatformBackend::WindowsWfpAle => "windows_wfp_ale",
        WidePlatformBackend::MacosPf => "macos_pf",
    }
}

pub(in crate::ingress::preflight) fn wide_rollout_profile_name(cfg: &Settings) -> &'static str {
    match cfg.ingress.wide.rollout_profile {
        WideRolloutProfile::OutputOnlySafe => "output_only_safe",
        WideRolloutProfile::PreroutingScoped => "prerouting_scoped",
        WideRolloutProfile::TransparentPrivileged => "transparent_privileged",
    }
}

fn linux_validation_bootstrap_applicable(cfg: &Settings) -> bool {
    cfg!(target_os = "linux")
        && wide_rollout_intent_requested(cfg)
        && matches!(
            cfg.ingress.wide.platform_backend,
            WidePlatformBackend::Auto
                | WidePlatformBackend::LinuxRedirect
                | WidePlatformBackend::LinuxTproxy
        )
}

pub(in crate::ingress::preflight) fn linux_validation_bootstrap_check_command(
    cfg: &Settings,
) -> Option<&'static str> {
    linux_validation_bootstrap_applicable(cfg)
        .then_some("bash scripts/bootstrap-wide-linux-validation-host.sh --check --json")
}

pub(in crate::ingress::preflight) fn linux_validation_bootstrap_install_command(
    cfg: &Settings,
) -> Option<&'static str> {
    linux_validation_bootstrap_applicable(cfg)
        .then_some("bash scripts/bootstrap-wide-linux-validation-host.sh --install")
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use super::parse_linux_default_route_interface;

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_default_route_interface_returns_main_iface() {
        let sample = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
eth0\t00000000\t010011AC\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
eth1\t0008A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(
            parse_linux_default_route_interface(sample).as_deref(),
            Some("eth0")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_default_route_interface_ignores_missing_gateway_flag() {
        let sample = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
eth0\t00000000\t010011AC\t0001\t0\t0\t100\t00000000\t0\t0\t0\n";
        assert_eq!(parse_linux_default_route_interface(sample), None);
    }
}
