use crate::ingress::{
    IngressBackend, IngressBackendRuntimeStatus, IngressKind, IngressResponse,
    IngressSessionIntent, IngressTransport, TcpConnectIntent, UdpDatagramIntent,
    UdpDatagramResponse, UdpSessionControl,
};
use crate::socks5::ConnectTarget;
use aegis_core::{WideIngressSettings, WidePlatformBackend, WideUdpCaptureContract};
use async_trait::async_trait;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tokio::net::{TcpListener, UdpSocket};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosWideCurrentStage {
    ContractFallbackOnly,
    AdapterSkeleton,
    TcpOnlyPhase1Live,
    DnsPreviewPhase2Live,
    SystemWidePhase3Boundary,
    SystemWidePhase3PreparedBoundary,
    // B2 (Track B macOS PF phase-4): bind-capable system-wide live contour.
    // Difference от phase-3 boundary: PF rdr rules actually materialized on
    // the egress interface (not comment-only placeholder) и runtime_active=true.
    // Acceptance gate defined in B1 (schema v2 helper: build-macos-pf-operator-
    // acceptance-summary.sh with --phase4-dir).
    SystemWidePhase4Live,
}

impl MacosWideCurrentStage {
    pub fn as_code(self) -> &'static str {
        match self {
            Self::ContractFallbackOnly => "contract_fallback_only",
            Self::AdapterSkeleton => "adapter_skeleton",
            Self::TcpOnlyPhase1Live => "tcp_only_phase1_live",
            Self::DnsPreviewPhase2Live => "dns_preview_phase2_live",
            Self::SystemWidePhase3Boundary => "system_wide_phase3_boundary",
            Self::SystemWidePhase3PreparedBoundary => "system_wide_phase3_prepared_boundary",
            Self::SystemWidePhase4Live => "system_wide_phase4_live",
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosWideScopeTarget {
    TcpOnlyPhase1,
    DnsPreviewPhase2,
    SystemWidePhase3,
    SystemWidePhase4,
}

impl MacosWideScopeTarget {
    pub fn as_code(self) -> &'static str {
        match self {
            Self::TcpOnlyPhase1 => "tcp_only_phase1",
            Self::DnsPreviewPhase2 => "dns_preview_phase2",
            Self::SystemWidePhase3 => "system_wide_phase3",
            Self::SystemWidePhase4 => "system_wide_phase4",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacosWideCapabilityReport {
    pub platform_family_supported: bool,
    pub bind_capable: bool,
    pub current_stage: MacosWideCurrentStage,
    pub scope_target: MacosWideScopeTarget,
    pub reason_code: &'static str,
    pub reason: &'static str,
}

pub struct MacosWidePrimaryBackend {
    listener: TcpListener,
    udp_dns_socket: Option<UdpSocket>,
    contour: MacosPfContour,
    settings: WideIngressSettings,
}

impl MacosWidePrimaryBackend {
    pub fn capability_report(settings: &WideIngressSettings) -> MacosWideCapabilityReport {
        if !settings.enabled {
            return MacosWideCapabilityReport {
                platform_family_supported: false,
                bind_capable: false,
                current_stage: MacosWideCurrentStage::ContractFallbackOnly,
                scope_target: MacosWideScopeTarget::TcpOnlyPhase1,
                reason_code: "wide_disabled_in_config",
                reason: "macOS wide ingress is disabled in config",
            };
        }

        let family_supported = matches!(
            settings.platform_backend,
            WidePlatformBackend::Auto | WidePlatformBackend::MacosPf
        );
        if !family_supported {
            return MacosWideCapabilityReport {
                platform_family_supported: false,
                bind_capable: false,
                current_stage: MacosWideCurrentStage::ContractFallbackOnly,
                scope_target: MacosWideScopeTarget::TcpOnlyPhase1,
                reason_code: "unsupported_platform_backend",
                reason: "selected backend does not belong to the macOS wide adapter family",
            };
        }

        if system_wide_phase3_requested(settings) {
            let phase4_requested = system_wide_phase4_requested(settings);
            return match load_helper_contour(settings) {
                Ok(contour) if contour.system_wide.is_some() => {
                    let sw = contour.system_wide.as_ref().expect("is_some");
                    let prepared_boundary = sw.prepared_boundary;
                    let phase4_active = sw.phase4_active;
                    // B2 phase-4 bind-capable branch: both the env opt-in AND
                    // the helper state must agree. Env without helper state =
                    // misconfigured (operator forgot to run helper --phase4
                    // apply); helper state without env = safety default.
                    if phase4_requested && phase4_active {
                        return MacosWideCapabilityReport {
                            platform_family_supported: true,
                            bind_capable: true,
                            current_stage: MacosWideCurrentStage::SystemWidePhase4Live,
                            scope_target: MacosWideScopeTarget::SystemWidePhase4,
                            reason_code: "pf_system_wide_phase4_live",
                            reason:
                                "macOS PF helper state materializes bind-capable system_wide phase-4: PF rdr rules actively installed on the egress interface",
                        };
                    }
                    MacosWideCapabilityReport {
                        platform_family_supported: true,
                        bind_capable: false,
                        current_stage: if prepared_boundary {
                            MacosWideCurrentStage::SystemWidePhase3PreparedBoundary
                        } else {
                            MacosWideCurrentStage::SystemWidePhase3Boundary
                        },
                        scope_target: MacosWideScopeTarget::SystemWidePhase3,
                        reason_code: if prepared_boundary {
                            "pf_system_wide_phase3_prepared_boundary_only"
                        } else {
                            "pf_system_wide_phase3_boundary_only"
                        },
                        reason: if prepared_boundary {
                            "macOS PF helper state now materializes a prepared system_wide phase-3 boundary for broader operator acceptance, but a broader bind-capable runtime path still remains intentionally out of scope"
                        } else {
                            "macOS PF helper state materializes the guarded system_wide phase-3 boundary only; a broader bind-capable runtime path is still intentionally out of scope"
                        },
                    }
                }
                _ => MacosWideCapabilityReport {
                    platform_family_supported: true,
                    bind_capable: false,
                    current_stage: MacosWideCurrentStage::AdapterSkeleton,
                    scope_target: if phase4_requested {
                        MacosWideScopeTarget::SystemWidePhase4
                    } else {
                        MacosWideScopeTarget::SystemWidePhase3
                    },
                    reason_code: if phase4_requested {
                        "helper_state_missing_system_wide_phase4_or_invalid"
                    } else {
                        "helper_state_missing_system_wide_phase3_boundary_or_invalid"
                    },
                    reason: if phase4_requested {
                        "macOS PF system-wide phase-4 requires explicit helper-backed state materialized by scripts/macos-wide-pf.sh with PHASE4 enabled; without it the adapter stays boundary-only"
                    } else {
                        "the macOS PF system-wide phase-3 boundary requires explicit helper-backed state materialized by scripts/macos-wide-pf.sh apply/setup with system_wide_phase3 enabled"
                    },
                },
            };
        }

        if !listen_is_loopback(settings.listen) {
            return MacosWideCapabilityReport {
                platform_family_supported: true,
                bind_capable: false,
                current_stage: MacosWideCurrentStage::AdapterSkeleton,
                scope_target: MacosWideScopeTarget::TcpOnlyPhase1,
                reason_code: "tcp_only_phase1_requires_loopback_listener",
                reason:
                    "the macOS PF milestones stay scoped to a local loopback listener instead of a broader system-wide capture surface",
            };
        }

        if settings.capture_dns
            && settings.udp_capture_contract != WideUdpCaptureContract::PreviewAllowlistOnly
        {
            return MacosWideCapabilityReport {
                platform_family_supported: true,
                bind_capable: false,
                current_stage: MacosWideCurrentStage::AdapterSkeleton,
                scope_target: MacosWideScopeTarget::DnsPreviewPhase2,
                reason_code: "dns_preview_phase2_requires_preview_allowlist_only",
                reason:
                    "the macOS PF DNS preview remains limited to the preview_allowlist_only UDP contract instead of broader generic capture",
            };
        }

        if settings.capture_dns && !settings.udp_preview_ports.is_empty() {
            return MacosWideCapabilityReport {
                platform_family_supported: true,
                bind_capable: false,
                current_stage: MacosWideCurrentStage::AdapterSkeleton,
                scope_target: MacosWideScopeTarget::DnsPreviewPhase2,
                reason_code: "dns_preview_phase2_requires_dns_port_only",
                reason:
                    "the macOS PF DNS preview remains limited to ingress.wide.dns_port only; udp_preview_ports stays out of scope for phase-2",
            };
        }

        match load_helper_contour(settings) {
            Ok(contour) if settings.capture_dns && contour.dns_preview.is_some() => {
                MacosWideCapabilityReport {
                    platform_family_supported: true,
                    bind_capable: true,
                    current_stage: MacosWideCurrentStage::DnsPreviewPhase2Live,
                    scope_target: MacosWideScopeTarget::DnsPreviewPhase2,
                    reason_code: "pf_dns_preview_ready",
                    reason:
                        "macOS PF helper state is present and enables the narrow DNS preview phase-2 contour on top of the active TCP path",
                }
            }
            Ok(_contour) => MacosWideCapabilityReport {
                platform_family_supported: true,
                bind_capable: true,
                current_stage: MacosWideCurrentStage::TcpOnlyPhase1Live,
                scope_target: MacosWideScopeTarget::TcpOnlyPhase1,
                reason_code: "pf_tcp_only_ready",
                reason:
                    "macOS PF helper state is present and enables the controlled TCP-only phase-1 contour",
            },
            Err(_) => MacosWideCapabilityReport {
                platform_family_supported: true,
                bind_capable: false,
                current_stage: MacosWideCurrentStage::AdapterSkeleton,
                scope_target: if settings.capture_dns {
                    MacosWideScopeTarget::DnsPreviewPhase2
                } else {
                    MacosWideScopeTarget::TcpOnlyPhase1
                },
                reason_code: if settings.capture_dns {
                    "helper_state_missing_dns_preview_or_invalid"
                } else {
                    "helper_state_missing_or_invalid"
                },
                reason:
                    if settings.capture_dns {
                        "the macOS PF DNS preview requires a materialized helper state file with explicit dns_preview_phase2 data produced by scripts/macos-wide-pf.sh apply/setup"
                    } else {
                        "the first live macOS PF contour requires a materialized helper state file produced by scripts/macos-wide-pf.sh apply/setup"
                    },
            },
        }
    }

    pub async fn bind(settings: WideIngressSettings) -> io::Result<Self> {
        let report = Self::capability_report(&settings);
        if !report.bind_capable {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "macOS PF helper prerequisites are not satisfied (backend={:?}, listen={}, stage={:?}, scope_target={:?}, reason_code={})",
                    settings.platform_backend,
                    settings.listen,
                    report.current_stage,
                    report.scope_target,
                    report.reason_code
                ),
            ));
        }
        let contour = load_helper_contour(&settings)?;
        let listener = TcpListener::bind(settings.listen).await?;
        let udp_dns_socket = if contour.dns_preview.is_some() {
            Some(UdpSocket::bind(settings.listen).await?)
        } else {
            None
        };
        Ok(Self {
            listener,
            udp_dns_socket,
            contour,
            settings,
        })
    }

    pub fn supports_platform(settings: &WideIngressSettings) -> bool {
        Self::capability_report(settings).bind_capable
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.settings.listen
    }
}

#[async_trait]
impl IngressBackend for MacosWidePrimaryBackend {
    fn id(&self) -> &'static str {
        "wide_primary_macos"
    }

    fn kind(&self) -> IngressKind {
        IngressKind::WidePrimary
    }

    fn is_available(&self) -> bool {
        Self::supports_platform(&self.settings)
    }

    fn listen_addr(&self) -> Option<SocketAddr> {
        Some(self.listen_addr())
    }

    fn runtime_status(&self) -> IngressBackendRuntimeStatus {
        let report = Self::capability_report(&self.settings);
        if self.contour.dns_preview.is_some() {
            IngressBackendRuntimeStatus {
                wide_dns_capture_preview_status: Some("active"),
                wide_backend_current_stage: Some(report.current_stage.as_code()),
                wide_backend_scope_target: Some(report.scope_target.as_code()),
                wide_backend_reason_code: Some(report.reason_code),
                wide_udp_capture_contract: Some("preview_allowlist_only"),
                wide_udp_capture_support_tier: Some("supported_preview"),
                wide_udp_capture_policy: Some("allowlist_ports"),
                wide_udp_capture_runtime_scope: Some("macos_ipv4_loopback_preview"),
                wide_udp_preview_policy: Some("allowlist_ports"),
                wide_udp_preview_ports: vec![self.settings.dns_port],
                ..IngressBackendRuntimeStatus::default()
            }
        } else {
            IngressBackendRuntimeStatus {
                wide_dns_capture_preview_status: Some("disabled"),
                wide_backend_current_stage: Some(report.current_stage.as_code()),
                wide_backend_scope_target: Some(report.scope_target.as_code()),
                wide_backend_reason_code: Some(report.reason_code),
                ..IngressBackendRuntimeStatus::default()
            }
        }
    }

    async fn accept(&self) -> io::Result<IngressSessionIntent> {
        if let Some(udp_dns_socket) = &self.udp_dns_socket {
            tokio::select! {
                tcp = self.accept_tcp_intent() => tcp,
                udp = accept_dns_udp_intent(udp_dns_socket, &self.contour) => udp,
            }
        } else {
            self.accept_tcp_intent().await
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MacosPfContour {
    #[allow(dead_code)]
    state_path: PathBuf,
    #[allow(dead_code)]
    redirect_from: SocketAddr,
    tcp_target: ConnectTarget,
    dns_preview: Option<MacosPfDnsPreviewContour>,
    system_wide: Option<MacosPfSystemWideBoundaryContour>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MacosPfDnsPreviewContour {
    #[allow(dead_code)]
    redirect_from: SocketAddr,
    target: ConnectTarget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MacosPfSystemWideBoundaryContour {
    #[allow(dead_code)]
    redirect_from: SocketAddr,
    #[allow(dead_code)]
    target: ConnectTarget,
    prepared_boundary: bool,
    /// B2 phase-4: set when helper state claims `current_stage`=
    /// `system_wide_phase4_live` AND `runtime_active=true`. Indicates actual
    /// PF rdr rules are materialized on the egress interface.
    phase4_active: bool,
}

#[derive(Debug, Deserialize)]
struct MacosPfHelperState {
    runtime_active: bool,
    listen: String,
    redirect_from: String,
    target: String,
    #[serde(default)]
    dns_preview_enabled: bool,
    #[serde(default)]
    dns_redirect_from: Option<String>,
    #[serde(default)]
    dns_target: Option<String>,
    #[serde(default)]
    system_wide_enabled: bool,
    #[serde(default)]
    prepared_boundary_enabled: bool,
    /// B2 phase-4: when true, `scripts/macos-wide-pf.sh --phase4` has
    /// materialized active PF rdr rules on the egress interface (not just
    /// boundary-only placeholder). Coexists with `system_wide_enabled=true`
    /// and `runtime_active=true` (phase-4 lifts the phase-3 requirement
    /// that runtime_active must be false).
    #[serde(default)]
    phase4_enabled: bool,
    #[allow(dead_code)]
    current_stage: Option<String>,
    #[allow(dead_code)]
    scope_target: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedMacosPfContour {
    TcpOnlyPhase1,
    DnsPreviewPhase2,
    SystemWidePhase3,
}

impl ExpectedMacosPfContour {
    fn for_settings(settings: &WideIngressSettings) -> Self {
        if system_wide_phase3_requested(settings) {
            Self::SystemWidePhase3
        } else if settings.capture_dns {
            Self::DnsPreviewPhase2
        } else {
            Self::TcpOnlyPhase1
        }
    }

    fn current_stage(self, prepared_boundary: bool, phase4_active: bool) -> &'static str {
        match self {
            Self::TcpOnlyPhase1 => "tcp_only_phase1_live",
            Self::DnsPreviewPhase2 => "dns_preview_phase2_live",
            Self::SystemWidePhase3 => {
                if phase4_active {
                    "system_wide_phase4_live"
                } else if prepared_boundary {
                    "system_wide_phase3_prepared_boundary"
                } else {
                    "system_wide_phase3_boundary"
                }
            }
        }
    }

    fn scope_target_for(self, phase4_active: bool) -> &'static str {
        match self {
            Self::TcpOnlyPhase1 => "tcp_only_phase1",
            Self::DnsPreviewPhase2 => "dns_preview_phase2",
            Self::SystemWidePhase3 => {
                if phase4_active {
                    "system_wide_phase4"
                } else {
                    "system_wide_phase3"
                }
            }
        }
    }
}

fn helper_state_path() -> io::Result<PathBuf> {
    std::env::var_os("AEGIS_MACOS_PF_STATE_PATH")
        .map(PathBuf::from)
        .map(Ok)
        .unwrap_or_else(default_helper_state_path)
}

fn default_helper_state_path() -> io::Result<PathBuf> {
    let base = dirs::state_dir()
        .or_else(dirs::data_local_dir)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "macos_pf_state_dir_unavailable"))?;
    let helper_dir = base.join(".aegis").join("macos-pf");
    Ok(helper_dir.join(default_helper_state_basename(&helper_dir)))
}

fn default_helper_state_basename(helper_dir: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"aegis-macos-pf-state-v2");
    hasher.update(helper_dir.as_os_str().to_string_lossy().as_bytes());
    if let Some(home) = std::env::var_os("HOME") {
        hasher.update(home.to_string_lossy().as_bytes());
    }
    if let Some(user) = std::env::var_os("USER") {
        hasher.update(user.to_string_lossy().as_bytes());
    }
    let digest = hasher.finalize();
    let mut suffix = String::with_capacity(12);
    for byte in digest.iter().take(6) {
        let _ = write!(&mut suffix, "{byte:02x}");
    }
    format!(".pf-state-{suffix}.json")
}

fn load_helper_contour(settings: &WideIngressSettings) -> io::Result<MacosPfContour> {
    let system_wide_requested = system_wide_phase3_requested(settings);
    let expected_contour = ExpectedMacosPfContour::for_settings(settings);
    if !system_wide_requested && !listen_is_loopback(settings.listen) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "macos_pf_loopback_listener_required",
        ));
    }
    if !system_wide_requested
        && settings.capture_dns
        && settings.udp_capture_contract != WideUdpCaptureContract::PreviewAllowlistOnly
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "macos_pf_dns_preview_phase2_requires_preview_allowlist_only",
        ));
    }
    if !system_wide_requested && settings.capture_dns && !settings.udp_preview_ports.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "macos_pf_dns_preview_phase2_requires_dns_port_only",
        ));
    }

    let state_path = helper_state_path()?;
    let helper_state = read_helper_state(&state_path)?;
    if system_wide_requested {
        if !helper_state.system_wide_enabled {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "macos_pf_helper_system_wide_phase3_missing: helper state at {} is not marked system_wide_enabled",
                    state_path.display()
                ),
            ));
        }
    } else if !helper_state.runtime_active {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "macos_pf_helper_state_inactive: helper state at {} is not marked runtime_active",
                state_path.display()
            ),
        ));
    }
    validate_helper_state_contract(&helper_state, expected_contour, &state_path)?;

    let listen = parse_socket_addr(&helper_state.listen, "listen", &state_path)?;
    if listen != settings.listen {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "macos_pf_helper_listen_mismatch: config listen {} does not match helper listen {} from {}",
                settings.listen,
                listen,
                state_path.display()
            ),
        ));
    }
    let redirect_from =
        parse_socket_addr(&helper_state.redirect_from, "redirect_from", &state_path)?;
    if !system_wide_requested && !listen_is_loopback(redirect_from) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "macos_pf_helper_redirect_not_loopback: redirect_from {} from {} is outside the local phase-1 contour",
                redirect_from,
                state_path.display()
            ),
        ));
    }
    let target = parse_socket_addr(&helper_state.target, "target", &state_path)?;
    if !system_wide_requested && !listen_is_loopback(target) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "macos_pf_helper_target_not_loopback: target {} from {} is outside the local phase-1 contour",
                target,
                state_path.display()
            ),
        ));
    }

    let system_wide = if system_wide_requested {
        // Phase-4 lifts the phase-3 `runtime_active must be false` invariant.
        // For phase-4 (when helper state claims phase4_enabled), runtime_active
        // IS required to be true (actual PF rdr rules materialized). For
        // phase-3 boundary/prepared-boundary the original false-only check
        // still applies.
        if helper_state.phase4_enabled {
            if !helper_state.runtime_active {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "macos_pf_helper_system_wide_phase4_must_be_active: helper state at {} claims phase4_enabled=true but runtime_active=false — phase-4 requires materialized rdr rules",
                        state_path.display()
                    ),
                ));
            }
        } else if helper_state.runtime_active {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "macos_pf_helper_system_wide_phase3_must_stay_inactive: helper state at {} claims runtime_active=true for a boundary-only phase",
                    state_path.display()
                ),
            ));
        }
        Some(MacosPfSystemWideBoundaryContour {
            redirect_from,
            target: ConnectTarget {
                host: target.ip().to_string(),
                port: target.port(),
            },
            prepared_boundary: helper_state.prepared_boundary_enabled,
            phase4_active: helper_state.phase4_enabled,
        })
    } else {
        None
    };

    let dns_preview = if settings.capture_dns && !system_wide_requested {
        if !helper_state.dns_preview_enabled {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "macos_pf_helper_dns_preview_missing: helper state at {} is not marked dns_preview_enabled",
                    state_path.display()
                ),
            ));
        }
        let dns_redirect_from = parse_socket_addr(
            helper_state
                .dns_redirect_from
                .as_deref()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "macos_pf_helper_dns_preview_missing_redirect: helper state at {} is missing dns_redirect_from",
                            state_path.display()
                        ),
                    )
                })?,
            "dns_redirect_from",
            &state_path,
        )?;
        if !listen_is_loopback(dns_redirect_from) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "macos_pf_helper_dns_redirect_not_loopback: dns_redirect_from {} from {} is outside the local DNS preview contour",
                    dns_redirect_from,
                    state_path.display()
                ),
            ));
        }
        let dns_target = parse_socket_addr(
            helper_state
                .dns_target
                .as_deref()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "macos_pf_helper_dns_preview_missing_target: helper state at {} is missing dns_target",
                            state_path.display()
                        ),
                    )
                })?,
            "dns_target",
            &state_path,
        )?;
        if !listen_is_loopback(dns_target) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "macos_pf_helper_dns_target_not_loopback: dns_target {} from {} is outside the local DNS preview contour",
                    dns_target,
                    state_path.display()
                ),
            ));
        }
        if dns_target.port() != settings.dns_port {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "macos_pf_helper_dns_target_port_mismatch: config dns_port {} does not match helper dns_target {} from {}",
                    settings.dns_port,
                    dns_target,
                    state_path.display()
                ),
            ));
        }
        Some(MacosPfDnsPreviewContour {
            redirect_from: dns_redirect_from,
            target: ConnectTarget {
                host: dns_target.ip().to_string(),
                port: dns_target.port(),
            },
        })
    } else {
        None
    };

    Ok(MacosPfContour {
        state_path,
        redirect_from,
        tcp_target: ConnectTarget {
            host: target.ip().to_string(),
            port: target.port(),
        },
        dns_preview,
        system_wide,
    })
}

fn system_wide_phase3_requested(settings: &WideIngressSettings) -> bool {
    settings.capture_dns
        && settings.udp_capture_contract == WideUdpCaptureContract::GenericCaptureUnstable
}

/// B2 (Track B macOS PF phase-4): bind-capable system-wide mode.
///
/// Phase-4 is signalled by (a) the same `system_wide_phase3_requested` config
/// shape that triggers phase-3, PLUS (b) the explicit opt-in env var
/// `AEGIS_MACOS_PF_PHASE4=1`. The env-var gate keeps phase-4 strictly opt-in:
/// a deployment that upgrades binary без изменения env continues to see
/// phase-3 boundary behaviour. Operators who materialize phase-4 helper state
/// via `scripts/macos-wide-pf.sh --phase4 apply` are the only ones that set
/// this env var. Rationale: phase-4 actively installs PF rdr rules on the
/// egress interface (not just lo0), which is a privileged, more disruptive
/// surface than phase-3's boundary-only placeholder. Making it env-opt-in
/// prevents accidental activation.
fn system_wide_phase4_requested(settings: &WideIngressSettings) -> bool {
    if !system_wide_phase3_requested(settings) {
        return false;
    }
    matches!(
        std::env::var("AEGIS_MACOS_PF_PHASE4").ok().as_deref(),
        Some("1")
            | Some("true")
            | Some("TRUE")
            | Some("yes")
            | Some("YES")
            | Some("on")
            | Some("ON")
    )
}

fn validate_helper_state_contract(
    helper_state: &MacosPfHelperState,
    expected_contour: ExpectedMacosPfContour,
    path: &Path,
) -> io::Result<()> {
    let expected_current_stage = expected_contour.current_stage(
        helper_state.prepared_boundary_enabled,
        helper_state.phase4_enabled,
    );
    let expected_scope_target = expected_contour.scope_target_for(helper_state.phase4_enabled);
    if helper_state.current_stage.as_deref() != Some(expected_current_stage) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "macos_pf_helper_current_stage_mismatch: helper state at {} expected current_stage={} but saw {}",
                path.display(),
                expected_current_stage,
                helper_state.current_stage.as_deref().unwrap_or("<missing>")
            ),
        ));
    }
    if helper_state.scope_target.as_deref() != Some(expected_scope_target) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "macos_pf_helper_scope_target_mismatch: helper state at {} expected scope_target={} but saw {}",
                path.display(),
                expected_scope_target,
                helper_state.scope_target.as_deref().unwrap_or("<missing>")
            ),
        ));
    }

    match expected_contour {
        ExpectedMacosPfContour::TcpOnlyPhase1 => {
            if helper_state.prepared_boundary_enabled {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "macos_pf_helper_unexpected_prepared_boundary_state: helper state at {} embeds prepared_boundary state for a tcp_only_phase1 request",
                        path.display()
                    ),
                ));
            }
            if helper_state.system_wide_enabled {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "macos_pf_helper_unexpected_system_wide_state: helper state at {} embeds system_wide flags for a tcp_only_phase1 request",
                        path.display()
                    ),
                ));
            }
            if helper_state.dns_preview_enabled
                || helper_state.dns_redirect_from.is_some()
                || helper_state.dns_target.is_some()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "macos_pf_helper_unexpected_dns_preview_state: helper state at {} embeds dns_preview data for a tcp_only_phase1 request",
                        path.display()
                    ),
                ));
            }
        }
        ExpectedMacosPfContour::DnsPreviewPhase2 => {
            if helper_state.prepared_boundary_enabled {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "macos_pf_helper_unexpected_prepared_boundary_state: helper state at {} embeds prepared_boundary state for a dns_preview_phase2 request",
                        path.display()
                    ),
                ));
            }
            if helper_state.system_wide_enabled {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "macos_pf_helper_unexpected_system_wide_state: helper state at {} embeds system_wide flags for a dns_preview_phase2 request",
                        path.display()
                    ),
                ));
            }
        }
        ExpectedMacosPfContour::SystemWidePhase3 => {
            if helper_state.dns_preview_enabled
                || helper_state.dns_redirect_from.is_some()
                || helper_state.dns_target.is_some()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "macos_pf_helper_system_wide_phase3_must_not_embed_dns_preview: helper state at {} embeds dns_preview data for a boundary-only system_wide_phase3 request",
                        path.display()
                    ),
                ));
            }
        }
    }

    Ok(())
}

fn read_helper_state(path: &Path) -> io::Result<MacosPfHelperState> {
    let text = fs::read_to_string(path).map_err(|source| {
        io::Error::new(
            source.kind(),
            format!(
                "macos_pf_helper_state_missing: failed to read {}: {}",
                path.display(),
                source
            ),
        )
    })?;
    serde_json::from_str(&text).map_err(|source| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "macos_pf_helper_state_invalid: failed to parse {}: {}",
                path.display(),
                source
            ),
        )
    })
}

fn parse_socket_addr(value: &str, field: &str, path: &Path) -> io::Result<SocketAddr> {
    value.parse::<SocketAddr>().map_err(|source| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "macos_pf_helper_state_invalid_{field}: failed to parse {field}={} from {}: {}",
                value,
                path.display(),
                source
            ),
        )
    })
}

fn listen_is_loopback(addr: SocketAddr) -> bool {
    addr.ip().is_loopback()
}

impl MacosWidePrimaryBackend {
    async fn accept_tcp_intent(&self) -> io::Result<IngressSessionIntent> {
        let (client, peer) = self.listener.accept().await?;
        Ok(IngressSessionIntent {
            kind: IngressKind::WidePrimary,
            peer,
            transport: IngressTransport::TcpConnect(TcpConnectIntent {
                client,
                target: self.contour.tcp_target.clone(),
                response: IngressResponse::None,
                target_lease: None,
            }),
        })
    }
}

async fn accept_dns_udp_intent(
    udp_dns_socket: &UdpSocket,
    contour: &MacosPfContour,
) -> io::Result<IngressSessionIntent> {
    let dns_preview = contour.dns_preview.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "macos_pf_dns_preview_not_enabled_for_udp_accept",
        )
    })?;
    let mut payload = vec![0u8; 4096];
    let (n, peer) = udp_dns_socket.recv_from(&mut payload).await?;
    payload.truncate(n);
    let response_socket = bind_dns_response_socket(peer).await?;
    Ok(IngressSessionIntent {
        kind: IngressKind::WidePrimary,
        peer,
        transport: IngressTransport::UdpDatagram(UdpDatagramIntent {
            control: UdpSessionControl::Detached,
            client_ip: peer.ip(),
            target: dns_preview.target.clone(),
            payload,
            response: UdpDatagramResponse::LocalUdp {
                socket: response_socket,
                peer,
            },
        }),
    })
}

async fn bind_dns_response_socket(peer: SocketAddr) -> io::Result<UdpSocket> {
    let bind_addr = match peer {
        SocketAddr::V4(_) => "127.0.0.1:0",
        SocketAddr::V6(_) => "[::1]:0",
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    socket.connect(peer).await?;
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::WidePlatformBackend;
    use serde_json::Value;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::net::{TcpStream, UdpSocket};

    use super::fixture_env::{env_lock, HelperEnvOverride, MissingHelperStateFixture};

    fn unique_state_path(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "aegis-macos-wide-{name}-{}-{nonce}.json",
            std::process::id()
        ))
    }

    #[test]
    fn default_helper_state_basename_is_no_longer_legacy_static_name() {
        let helper_dir = Path::new("/Users/example/Library/Application Support/.aegis/macos-pf");
        let basename = default_helper_state_basename(helper_dir);
        assert!(basename.starts_with(".pf-state-"));
        assert!(basename.ends_with(".json"));
        assert_ne!(basename, ".pf-state.json");
    }

    #[test]
    fn helper_state_path_prefers_explicit_override() {
        let _guard = env_lock().lock().expect("lock env");
        let expected = unique_state_path("explicit-override");
        let old = std::env::var_os("AEGIS_MACOS_PF_STATE_PATH");
        std::env::set_var("AEGIS_MACOS_PF_STATE_PATH", &expected);
        let resolved = helper_state_path().expect("resolve helper state path");
        match old {
            Some(value) => std::env::set_var("AEGIS_MACOS_PF_STATE_PATH", value),
            None => std::env::remove_var("AEGIS_MACOS_PF_STATE_PATH"),
        }
        assert_eq!(resolved, expected);
    }

    #[test]
    fn absent_helper_reader_waits_for_actual_writer_and_overrides_restore_on_unwind() {
        use std::time::{Duration, Instant};

        struct OwnedFixtureChild(Option<std::process::Child>);
        impl Drop for OwnedFixtureChild {
            fn drop(&mut self) {
                if let Some(mut child) = self.0.take() {
                    if let Err(error) = child.kill() {
                        eprintln!("owned_env_fixture_cleanup kill_error={:?}", error.kind());
                    }
                    let deadline = Instant::now() + Duration::from_secs(2);
                    while Instant::now() < deadline {
                        match child.try_wait() {
                            Ok(Some(_)) => {
                                if Instant::now() < deadline {
                                    eprintln!("owned_env_fixture_cleanup outcome=REAPED");
                                } else {
                                    eprintln!("owned_env_fixture_cleanup outcome=REAPED_LATE");
                                }
                                return;
                            }
                            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
                            Err(error) => {
                                eprintln!(
                                    "owned_env_fixture_cleanup outcome=INCOMPLETE wait_error={:?}",
                                    error.kind()
                                );
                                return;
                            }
                        }
                    }
                    // A bounded owner cannot pretend a pending Child was reaped.
                    eprintln!("owned_env_fixture_cleanup outcome=INCOMPLETE reason=deadline");
                }
            }
        }
        let directory = tempfile::tempdir().expect("private caller state directory");
        let child = Command::new(std::env::current_exe().expect("current fixture executable"))
            .args([
                "--exact",
                "ingress::wide::macos::tests::fixture_missing_helper_state_environment_custody",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env(
                "AEGIS_MACOS_PF_STATE_PATH",
                directory.path().join("incoming-absent.json"),
            )
            .env("AEGIS_MACOS_PF_PHASE4", "1")
            .spawn()
            .expect("spawn exact owned environment fixture");
        let mut owned = OwnedFixtureChild(Some(child));
        // Fixture custody only: the isolated child preserves its original 3s
        // channel phases and cannot queue behind unrelated helper simulations.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(
                Instant::now() < deadline,
                "owned environment fixture expired"
            );
            let status = owned
                .0
                .as_mut()
                .unwrap()
                .try_wait()
                .expect("observe owned fixture");
            assert!(
                Instant::now() < deadline,
                "owned fixture exit observation was late"
            );
            if let Some(status) = status {
                assert!(status.success(), "owned environment fixture failed");
                owned.0.take();
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    #[ignore = "only launched by the owned environment-custody subprocess regression"]
    fn fixture_missing_helper_state_environment_custody() {
        use std::sync::{mpsc, TryLockError};
        use std::time::Duration;

        let writer_guard = env_lock().lock().expect("lock writer env");
        let original_path = std::env::var_os("AEGIS_MACOS_PF_STATE_PATH");
        let original_phase4 = std::env::var_os("AEGIS_MACOS_PF_PHASE4");
        let directory = tempfile::tempdir().expect("private writer fixture directory");
        let state_path = directory.path().join("valid-helper-state.json");
        let settings = WideIngressSettings {
            platform_backend: WidePlatformBackend::MacosPf,
            capture_dns: false,
            listen: "127.0.0.1:15080".parse().unwrap(),
            ..WideIngressSettings::default()
        };
        write_helper_state(
            &state_path,
            settings.listen,
            "127.0.0.1:18080".parse().unwrap(),
            "127.0.0.1:18081".parse().unwrap(),
            None,
            None,
            false,
            false,
        );
        let writer_environment = HelperEnvOverride::new(&state_path);
        // This actual production read proves why an unsynchronized absence
        // reader can report support while a valid writer fixture is active.
        assert!(MacosWidePrimaryBackend::supports_platform(&settings));
        let unwound = std::panic::catch_unwind(|| {
            let _environment = HelperEnvOverride::new(&directory.path().join("absent.json"));
            assert!(!MacosWidePrimaryBackend::supports_platform(&settings));
            panic!("intentional test-only environment override unwind");
        });
        assert!(unwound.is_err());
        assert_eq!(
            std::env::var_os("AEGIS_MACOS_PF_STATE_PATH"),
            Some(state_path.clone().into())
        );
        assert!(std::env::var_os("AEGIS_MACOS_PF_PHASE4").is_none());

        let (blocked_tx, blocked_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            assert!(matches!(
                env_lock().try_lock(),
                Err(TryLockError::WouldBlock)
            ));
            blocked_tx.send(()).unwrap();
            let _fixture = MissingHelperStateFixture::new();
            assert!(!MacosWidePrimaryBackend::supports_platform(&settings));
            let report = MacosWidePrimaryBackend::capability_report(&settings);
            assert_eq!(report.current_stage, MacosWideCurrentStage::AdapterSkeleton);
            assert_eq!(report.reason_code, "helper_state_missing_or_invalid");
            done_tx.send(()).unwrap();
        });
        blocked_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("actual reader observed held writer lock");
        assert!(matches!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
        drop(writer_environment);
        assert_eq!(std::env::var_os("AEGIS_MACOS_PF_STATE_PATH"), original_path);
        assert_eq!(std::env::var_os("AEGIS_MACOS_PF_PHASE4"), original_phase4);
        drop(writer_guard);
        done_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("missing-state reader completed after writer release");
        reader.join().expect("join actual missing-state reader");
    }

    #[allow(clippy::too_many_arguments)]
    fn write_helper_state(
        path: &Path,
        listen: SocketAddr,
        redirect_from: SocketAddr,
        target: SocketAddr,
        dns_redirect_from: Option<SocketAddr>,
        dns_target: Option<SocketAddr>,
        system_wide_enabled: bool,
        prepared_boundary_enabled: bool,
    ) {
        let dns_preview_enabled = dns_redirect_from.is_some() && dns_target.is_some();
        let json = serde_json::json!({
            "runtime_active": !system_wide_enabled,
            "current_stage": if system_wide_enabled {
                if prepared_boundary_enabled {
                    "system_wide_phase3_prepared_boundary"
                } else {
                    "system_wide_phase3_boundary"
                }
            } else if dns_preview_enabled {
                "dns_preview_phase2_live"
            } else {
                "tcp_only_phase1_live"
            },
            "scope_target": if system_wide_enabled {
                "system_wide_phase3"
            } else if dns_preview_enabled {
                "dns_preview_phase2"
            } else {
                "tcp_only_phase1"
            },
            "listen": listen.to_string(),
            "redirect_from": redirect_from.to_string(),
            "target": target.to_string(),
            "dns_preview_enabled": dns_preview_enabled,
            "dns_redirect_from": dns_redirect_from.map(|value| value.to_string()),
            "dns_target": dns_target.map(|value| value.to_string()),
            "system_wide_enabled": system_wide_enabled,
            "prepared_boundary_enabled": prepared_boundary_enabled,
        });
        fs::write(
            path,
            serde_json::to_vec_pretty(&json).expect("serialize helper state"),
        )
        .expect("write helper state");
    }

    fn rewrite_helper_state(path: &Path, mutate: impl FnOnce(&mut Value)) {
        let mut value: Value =
            serde_json::from_str(&fs::read_to_string(path).expect("read helper state"))
                .expect("parse helper state");
        mutate(&mut value);
        fs::write(
            path,
            serde_json::to_vec_pretty(&value).expect("serialize helper state"),
        )
        .expect("rewrite helper state");
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_helper_state_with_script(
        state_path: &Path,
        listen: &str,
        redirect_from: &str,
        target: &str,
        dns_redirect_from: Option<&str>,
        dns_target: Option<&str>,
        system_wide_enabled: bool,
        prepared_boundary_enabled: bool,
    ) {
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root");
        let helper = repo_root.join("scripts/macos-wide-pf.sh");
        let mut command = Command::new("bash");
        command
            .arg(helper)
            .arg("apply")
            .arg("--json")
            .env("AEGIS_MACOS_PF_HELPER_UNAME", "Darwin")
            .env("AEGIS_MACOS_PF_HELPER_APPLY_MODE", "simulate")
            .env("AEGIS_MACOS_PF_HELPER_PFCTL_BIN", "true")
            .env("AEGIS_MACOS_PF_HELPER_IFCONFIG_BIN", "true")
            .env("AEGIS_MACOS_PF_HELPER_ROUTE_BIN", "true")
            .env("AEGIS_MACOS_PF_STATE_PATH", state_path)
            .env("AEGIS_MACOS_PF_LISTEN", listen)
            .env("AEGIS_MACOS_PF_REDIRECT_FROM", redirect_from)
            .env("AEGIS_MACOS_PF_TARGET", target);
        if let Some(value) = dns_redirect_from {
            command.env("AEGIS_MACOS_PF_DNS_PREVIEW_ENABLED", "1");
            command.env("AEGIS_MACOS_PF_DNS_REDIRECT_FROM", value);
        }
        if let Some(value) = dns_target {
            command.env("AEGIS_MACOS_PF_DNS_TARGET", value);
        }
        if system_wide_enabled {
            command.env("AEGIS_MACOS_PF_SYSTEM_WIDE_ENABLED", "1");
        }
        if prepared_boundary_enabled {
            command.env("AEGIS_MACOS_PF_PREPARED_BOUNDARY_ENABLED", "1");
        }
        let output = command.output().expect("run helper script");
        if !output.status.success() {
            panic!(
                "helper apply failed: status={:?}\nstdout={}\nstderr={}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn macos_backend_is_not_reported_supported_until_adapter_exists() {
        let _fixture = MissingHelperStateFixture::new();
        let settings = WideIngressSettings::default();
        assert!(!MacosWidePrimaryBackend::supports_platform(&settings));
        assert_eq!(
            MacosWidePrimaryBackend::capability_report(&settings).current_stage,
            MacosWideCurrentStage::AdapterSkeleton
        );
    }

    #[test]
    fn macos_backend_still_rejects_explicit_backend_mode_without_adapter() {
        let _fixture = MissingHelperStateFixture::new();
        let settings = WideIngressSettings {
            platform_backend: WidePlatformBackend::MacosPf,
            capture_dns: false,
            listen: "127.0.0.1:15080".parse().expect("listen"),
            ..WideIngressSettings::default()
        };
        assert!(!MacosWidePrimaryBackend::supports_platform(&settings));
        let report = MacosWidePrimaryBackend::capability_report(&settings);
        assert!(report.platform_family_supported);
        assert_eq!(report.scope_target, MacosWideScopeTarget::TcpOnlyPhase1);
        assert_eq!(report.reason_code, "helper_state_missing_or_invalid");
    }

    #[test]
    fn macos_backend_accepts_helper_script_tcp_only_state() {
        let _guard = env_lock().lock().expect("lock env");
        let state_path = unique_state_path("script-tcp-only");
        apply_helper_state_with_script(
            &state_path,
            "127.0.0.1:25080",
            "127.0.0.1:28080",
            "127.0.0.1:28081",
            None,
            None,
            false,
            false,
        );
        unsafe {
            std::env::set_var("AEGIS_MACOS_PF_STATE_PATH", &state_path);
        }

        let settings = WideIngressSettings {
            platform_backend: WidePlatformBackend::MacosPf,
            capture_dns: false,
            listen: "127.0.0.1:25080".parse().expect("listen"),
            ..WideIngressSettings::default()
        };
        let report = MacosWidePrimaryBackend::capability_report(&settings);
        assert!(report.bind_capable);
        assert_eq!(
            report.current_stage,
            MacosWideCurrentStage::TcpOnlyPhase1Live
        );
        assert_eq!(report.reason_code, "pf_tcp_only_ready");

        unsafe {
            std::env::remove_var("AEGIS_MACOS_PF_STATE_PATH");
        }
        let _ = fs::remove_file(&state_path);
        let _ = fs::remove_file(format!("{}.anchor.conf", state_path.display()));
    }

    #[test]
    fn macos_backend_accepts_helper_script_dns_preview_state() {
        let _guard = env_lock().lock().expect("lock env");
        let state_path = unique_state_path("script-dns-preview");
        apply_helper_state_with_script(
            &state_path,
            "127.0.0.1:25081",
            "127.0.0.1:28082",
            "127.0.0.1:28083",
            Some("127.0.0.1:25353"),
            Some("127.0.0.1:26053"),
            false,
            false,
        );
        unsafe {
            std::env::set_var("AEGIS_MACOS_PF_STATE_PATH", &state_path);
        }

        let settings = WideIngressSettings {
            platform_backend: WidePlatformBackend::MacosPf,
            capture_dns: true,
            listen: "127.0.0.1:25081".parse().expect("listen"),
            dns_port: 26053,
            ..WideIngressSettings::default()
        };
        let report = MacosWidePrimaryBackend::capability_report(&settings);
        assert!(report.bind_capable);
        assert_eq!(
            report.current_stage,
            MacosWideCurrentStage::DnsPreviewPhase2Live
        );
        assert_eq!(report.reason_code, "pf_dns_preview_ready");

        unsafe {
            std::env::remove_var("AEGIS_MACOS_PF_STATE_PATH");
        }
        let _ = fs::remove_file(&state_path);
        let _ = fs::remove_file(format!("{}.anchor.conf", state_path.display()));
    }

    #[test]
    fn macos_backend_accepts_helper_script_system_wide_boundary_state() {
        let _guard = env_lock().lock().expect("lock env");
        let state_path = unique_state_path("script-system-wide-boundary");
        apply_helper_state_with_script(
            &state_path,
            "0.0.0.0:25082",
            "10.10.0.5:28084",
            "1.1.1.1:53",
            None,
            None,
            true,
            false,
        );
        unsafe {
            std::env::set_var("AEGIS_MACOS_PF_STATE_PATH", &state_path);
        }

        let settings = WideIngressSettings {
            platform_backend: WidePlatformBackend::MacosPf,
            capture_dns: true,
            listen: "0.0.0.0:25082".parse().expect("listen"),
            udp_capture_contract: WideUdpCaptureContract::GenericCaptureUnstable,
            ..WideIngressSettings::default()
        };
        let report = MacosWidePrimaryBackend::capability_report(&settings);
        assert!(!report.bind_capable);
        assert_eq!(
            report.current_stage,
            MacosWideCurrentStage::SystemWidePhase3Boundary
        );
        assert_eq!(report.reason_code, "pf_system_wide_phase3_boundary_only");

        unsafe {
            std::env::remove_var("AEGIS_MACOS_PF_STATE_PATH");
        }
        let _ = fs::remove_file(&state_path);
        let _ = fs::remove_file(format!("{}.anchor.conf", state_path.display()));
    }

    #[test]
    fn macos_backend_reports_unsupported_family_for_non_macos_backend() {
        let settings = WideIngressSettings {
            platform_backend: WidePlatformBackend::LinuxRedirect,
            ..WideIngressSettings::default()
        };
        let report = MacosWidePrimaryBackend::capability_report(&settings);
        assert!(!report.platform_family_supported);
        assert_eq!(report.reason_code, "unsupported_platform_backend");
    }

    #[test]
    fn macos_backend_requires_helper_dns_preview_state_for_capture_dns() {
        let _fixture = MissingHelperStateFixture::new();
        let settings = WideIngressSettings {
            platform_backend: WidePlatformBackend::MacosPf,
            capture_dns: true,
            listen: "127.0.0.1:15080".parse().expect("listen"),
            ..WideIngressSettings::default()
        };
        let report = MacosWidePrimaryBackend::capability_report(&settings);
        assert!(!report.bind_capable);
        assert_eq!(report.scope_target, MacosWideScopeTarget::DnsPreviewPhase2);
        assert_eq!(
            report.reason_code,
            "helper_state_missing_dns_preview_or_invalid"
        );
    }

    #[test]
    fn macos_backend_becomes_bind_capable_with_valid_helper_state() {
        let _guard = env_lock().lock().expect("lock env");
        let state_path = unique_state_path("capability");
        let listen = "127.0.0.1:15080".parse().expect("listen");
        let redirect_from = "127.0.0.1:18080".parse().expect("redirect");
        let target = "127.0.0.1:18081".parse().expect("target");
        write_helper_state(
            &state_path,
            listen,
            redirect_from,
            target,
            None,
            None,
            false,
            false,
        );
        unsafe {
            std::env::set_var("AEGIS_MACOS_PF_STATE_PATH", &state_path);
        }

        let settings = WideIngressSettings {
            platform_backend: WidePlatformBackend::MacosPf,
            capture_dns: false,
            listen,
            ..WideIngressSettings::default()
        };
        let report = MacosWidePrimaryBackend::capability_report(&settings);
        assert!(report.bind_capable);
        assert_eq!(
            report.current_stage,
            MacosWideCurrentStage::TcpOnlyPhase1Live
        );
        assert_eq!(report.reason_code, "pf_tcp_only_ready");

        unsafe {
            std::env::remove_var("AEGIS_MACOS_PF_STATE_PATH");
        }
        let _ = fs::remove_file(state_path);
    }

    #[test]
    fn macos_backend_rejects_tcp_only_helper_state_with_stage_drift() {
        let _guard = env_lock().lock().expect("lock env");
        let state_path = unique_state_path("tcp-only-stage-drift");
        let listen = "127.0.0.1:15080".parse().expect("listen");
        let redirect_from = "127.0.0.1:18080".parse().expect("redirect");
        let target = "127.0.0.1:18081".parse().expect("target");
        write_helper_state(
            &state_path,
            listen,
            redirect_from,
            target,
            None,
            None,
            false,
            false,
        );
        rewrite_helper_state(&state_path, |value| {
            value["current_stage"] = Value::String("dns_preview_phase2_live".into());
            value["scope_target"] = Value::String("dns_preview_phase2".into());
        });
        unsafe {
            std::env::set_var("AEGIS_MACOS_PF_STATE_PATH", &state_path);
        }

        let settings = WideIngressSettings {
            platform_backend: WidePlatformBackend::MacosPf,
            capture_dns: false,
            listen,
            ..WideIngressSettings::default()
        };
        let err = load_helper_contour(&settings).expect_err("stage drift must fail");
        assert!(err
            .to_string()
            .contains("macos_pf_helper_current_stage_mismatch"));

        unsafe {
            std::env::remove_var("AEGIS_MACOS_PF_STATE_PATH");
        }
        let _ = fs::remove_file(state_path);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn macos_backend_accepts_tcp_and_uses_helper_target() {
        let _guard = env_lock().lock().expect("lock env");
        let listen_probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe listen");
        let listen = listen_probe.local_addr().expect("listen addr");
        drop(listen_probe);
        let state_path = unique_state_path("accept");
        let redirect_from = "127.0.0.1:18082".parse().expect("redirect");
        let target = "127.0.0.1:18083".parse().expect("target");
        write_helper_state(
            &state_path,
            listen,
            redirect_from,
            target,
            None,
            None,
            false,
            false,
        );
        unsafe {
            std::env::set_var("AEGIS_MACOS_PF_STATE_PATH", &state_path);
        }

        let settings = WideIngressSettings {
            platform_backend: WidePlatformBackend::MacosPf,
            capture_dns: false,
            listen,
            ..WideIngressSettings::default()
        };
        let backend = MacosWidePrimaryBackend::bind(settings)
            .await
            .expect("bind backend");
        let accept_task = tokio::spawn(async move { backend.accept().await });

        let client = TcpStream::connect(listen).await.expect("connect listener");
        drop(client);

        let intent = accept_task
            .await
            .expect("join accept task")
            .expect("accept intent");
        assert_eq!(intent.kind, IngressKind::WidePrimary);
        match intent.transport {
            IngressTransport::TcpConnect(tcp) => {
                assert_eq!(tcp.target.host, "127.0.0.1");
                assert_eq!(tcp.target.port, 18083);
                assert_eq!(tcp.response, IngressResponse::None);
            }
            _ => panic!("unexpected ingress transport"),
        }

        unsafe {
            std::env::remove_var("AEGIS_MACOS_PF_STATE_PATH");
        }
        let _ = fs::remove_file(state_path);
    }

    #[test]
    fn macos_backend_dns_preview_requires_helper_dns_state() {
        let _guard = env_lock().lock().expect("lock env");
        let state_path = unique_state_path("dns-preview-report");
        let listen = "127.0.0.1:25053".parse().expect("listen");
        let redirect_from = "127.0.0.1:28053".parse().expect("redirect");
        let target = "127.0.0.1:28054".parse().expect("target");
        let dns_redirect_from = "127.0.0.1:25353".parse().expect("dns redirect");
        let dns_target = "127.0.0.1:26053".parse().expect("dns target");
        write_helper_state(
            &state_path,
            listen,
            redirect_from,
            target,
            Some(dns_redirect_from),
            Some(dns_target),
            false,
            false,
        );
        unsafe {
            std::env::set_var("AEGIS_MACOS_PF_STATE_PATH", &state_path);
        }

        let settings = WideIngressSettings {
            platform_backend: WidePlatformBackend::MacosPf,
            capture_dns: true,
            listen,
            dns_port: 26053,
            ..WideIngressSettings::default()
        };
        let report = MacosWidePrimaryBackend::capability_report(&settings);
        assert!(report.bind_capable);
        assert_eq!(
            report.current_stage,
            MacosWideCurrentStage::DnsPreviewPhase2Live
        );
        assert_eq!(report.scope_target, MacosWideScopeTarget::DnsPreviewPhase2);
        assert_eq!(report.reason_code, "pf_dns_preview_ready");

        unsafe {
            std::env::remove_var("AEGIS_MACOS_PF_STATE_PATH");
        }
        let _ = fs::remove_file(state_path);
    }

    #[test]
    fn macos_backend_rejects_dns_preview_helper_state_with_scope_drift() {
        let _guard = env_lock().lock().expect("lock env");
        let state_path = unique_state_path("dns-preview-scope-drift");
        let listen = "127.0.0.1:25053".parse().expect("listen");
        let redirect_from = "127.0.0.1:28053".parse().expect("redirect");
        let target = "127.0.0.1:28054".parse().expect("target");
        let dns_redirect_from = "127.0.0.1:25353".parse().expect("dns redirect");
        let dns_target = "127.0.0.1:26053".parse().expect("dns target");
        write_helper_state(
            &state_path,
            listen,
            redirect_from,
            target,
            Some(dns_redirect_from),
            Some(dns_target),
            false,
            false,
        );
        rewrite_helper_state(&state_path, |value| {
            value["scope_target"] = Value::String("tcp_only_phase1".into());
        });
        unsafe {
            std::env::set_var("AEGIS_MACOS_PF_STATE_PATH", &state_path);
        }

        let settings = WideIngressSettings {
            platform_backend: WidePlatformBackend::MacosPf,
            capture_dns: true,
            listen,
            dns_port: 26053,
            ..WideIngressSettings::default()
        };
        let err = load_helper_contour(&settings).expect_err("scope drift must fail");
        assert!(err
            .to_string()
            .contains("macos_pf_helper_scope_target_mismatch"));

        unsafe {
            std::env::remove_var("AEGIS_MACOS_PF_STATE_PATH");
        }
        let _ = fs::remove_file(state_path);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn macos_backend_accepts_dns_udp_and_uses_helper_dns_target() {
        let _guard = env_lock().lock().expect("lock env");
        let listen_probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe listen");
        let listen = listen_probe.local_addr().expect("listen addr");
        drop(listen_probe);
        let state_path = unique_state_path("dns-preview-accept");
        let redirect_from = "127.0.0.1:28153".parse().expect("redirect");
        let target = "127.0.0.1:28154".parse().expect("target");
        let dns_redirect_from = "127.0.0.1:25353".parse().expect("dns redirect");
        let dns_target = "127.0.0.1:26053".parse().expect("dns target");
        write_helper_state(
            &state_path,
            listen,
            redirect_from,
            target,
            Some(dns_redirect_from),
            Some(dns_target),
            false,
            false,
        );
        unsafe {
            std::env::set_var("AEGIS_MACOS_PF_STATE_PATH", &state_path);
        }

        let settings = WideIngressSettings {
            platform_backend: WidePlatformBackend::MacosPf,
            capture_dns: true,
            listen,
            dns_port: 26053,
            ..WideIngressSettings::default()
        };
        let backend = MacosWidePrimaryBackend::bind(settings)
            .await
            .expect("bind backend");
        let accept_task = tokio::spawn(async move { backend.accept().await });

        let client = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind udp client");
        client
            .send_to(b"\xaa\xbb\x01\x00", listen)
            .await
            .expect("send udp datagram");

        let intent = accept_task
            .await
            .expect("join accept task")
            .expect("accept intent");
        assert_eq!(intent.kind, IngressKind::WidePrimary);
        match intent.transport {
            IngressTransport::UdpDatagram(udp) => {
                assert_eq!(udp.target.host, "127.0.0.1");
                assert_eq!(udp.target.port, 26053);
                assert_eq!(udp.payload, b"\xaa\xbb\x01\x00");
                assert!(matches!(udp.control, UdpSessionControl::Detached));
                assert!(matches!(udp.response, UdpDatagramResponse::LocalUdp { .. }));
            }
            _ => panic!("unexpected ingress transport"),
        }

        unsafe {
            std::env::remove_var("AEGIS_MACOS_PF_STATE_PATH");
        }
        let _ = fs::remove_file(state_path);
    }

    #[test]
    fn macos_backend_system_wide_boundary_requires_helper_state() {
        let _fixture = MissingHelperStateFixture::new();
        let settings = WideIngressSettings {
            platform_backend: WidePlatformBackend::MacosPf,
            capture_dns: true,
            listen: "0.0.0.0:15080".parse().expect("listen"),
            udp_capture_contract: WideUdpCaptureContract::GenericCaptureUnstable,
            ..WideIngressSettings::default()
        };
        let report = MacosWidePrimaryBackend::capability_report(&settings);
        assert!(!report.bind_capable);
        assert_eq!(report.scope_target, MacosWideScopeTarget::SystemWidePhase3);
        assert_eq!(
            report.reason_code,
            "helper_state_missing_system_wide_phase3_boundary_or_invalid"
        );
    }

    #[test]
    fn macos_backend_reports_system_wide_phase3_boundary_with_helper_state() {
        let _guard = env_lock().lock().expect("lock env");
        let state_path = unique_state_path("system-wide-boundary");
        let listen = "0.0.0.0:15080".parse().expect("listen");
        let redirect_from = "10.10.0.5:28084".parse().expect("redirect");
        let target = "1.1.1.1:53".parse().expect("target");
        write_helper_state(
            &state_path,
            listen,
            redirect_from,
            target,
            None,
            None,
            true,
            false,
        );
        unsafe {
            std::env::set_var("AEGIS_MACOS_PF_STATE_PATH", &state_path);
        }

        let settings = WideIngressSettings {
            platform_backend: WidePlatformBackend::MacosPf,
            capture_dns: true,
            listen,
            udp_capture_contract: WideUdpCaptureContract::GenericCaptureUnstable,
            ..WideIngressSettings::default()
        };
        let report = MacosWidePrimaryBackend::capability_report(&settings);
        assert!(!report.bind_capable);
        assert_eq!(
            report.current_stage,
            MacosWideCurrentStage::SystemWidePhase3Boundary
        );
        assert_eq!(report.scope_target, MacosWideScopeTarget::SystemWidePhase3);
        assert_eq!(report.reason_code, "pf_system_wide_phase3_boundary_only");

        let bind_err = match tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(MacosWidePrimaryBackend::bind(settings))
        {
            Ok(_) => panic!("boundary-only phase should not bind"),
            Err(err) => err,
        };
        assert!(bind_err
            .to_string()
            .contains("pf_system_wide_phase3_boundary_only"));

        unsafe {
            std::env::remove_var("AEGIS_MACOS_PF_STATE_PATH");
        }
        let _ = fs::remove_file(state_path);
    }

    #[test]
    fn macos_backend_reports_system_wide_phase3_prepared_boundary_with_helper_state() {
        let _guard = env_lock().lock().expect("lock env");
        let state_path = unique_state_path("system-wide-prepared-boundary");
        let listen = "0.0.0.0:15081".parse().expect("listen");
        let redirect_from = "10.10.0.6:28085".parse().expect("redirect");
        let target = "8.8.8.8:53".parse().expect("target");
        write_helper_state(
            &state_path,
            listen,
            redirect_from,
            target,
            None,
            None,
            true,
            true,
        );
        unsafe {
            std::env::set_var("AEGIS_MACOS_PF_STATE_PATH", &state_path);
        }

        let settings = WideIngressSettings {
            platform_backend: WidePlatformBackend::MacosPf,
            capture_dns: true,
            listen,
            udp_capture_contract: WideUdpCaptureContract::GenericCaptureUnstable,
            ..WideIngressSettings::default()
        };
        let report = MacosWidePrimaryBackend::capability_report(&settings);
        assert!(!report.bind_capable);
        assert_eq!(
            report.current_stage,
            MacosWideCurrentStage::SystemWidePhase3PreparedBoundary
        );
        assert_eq!(report.scope_target, MacosWideScopeTarget::SystemWidePhase3);
        assert_eq!(
            report.reason_code,
            "pf_system_wide_phase3_prepared_boundary_only"
        );

        let bind_err = match tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(MacosWidePrimaryBackend::bind(settings))
        {
            Ok(_) => panic!("prepared boundary phase should not bind"),
            Err(err) => err,
        };
        assert!(bind_err
            .to_string()
            .contains("macOS PF helper prerequisites are not satisfied"));

        unsafe {
            std::env::remove_var("AEGIS_MACOS_PF_STATE_PATH");
        }
        let _ = fs::remove_file(state_path);
    }

    #[test]
    fn macos_backend_rejects_system_wide_boundary_state_with_embedded_dns_preview() {
        let _guard = env_lock().lock().expect("lock env");
        let state_path = unique_state_path("system-wide-mixed-state");
        let listen = "0.0.0.0:15080".parse().expect("listen");
        let redirect_from = "10.10.0.5:28084".parse().expect("redirect");
        let target = "1.1.1.1:53".parse().expect("target");
        write_helper_state(
            &state_path,
            listen,
            redirect_from,
            target,
            None,
            None,
            true,
            false,
        );
        rewrite_helper_state(&state_path, |value| {
            value["dns_preview_enabled"] = Value::Bool(true);
            value["dns_redirect_from"] = Value::String("127.0.0.1:15353".into());
            value["dns_target"] = Value::String("127.0.0.1:1053".into());
        });
        unsafe {
            std::env::set_var("AEGIS_MACOS_PF_STATE_PATH", &state_path);
        }

        let settings = WideIngressSettings {
            platform_backend: WidePlatformBackend::MacosPf,
            capture_dns: true,
            listen,
            udp_capture_contract: WideUdpCaptureContract::GenericCaptureUnstable,
            ..WideIngressSettings::default()
        };
        let err = load_helper_contour(&settings).expect_err("mixed boundary state must fail");
        assert!(err
            .to_string()
            .contains("macos_pf_helper_system_wide_phase3_must_not_embed_dns_preview"));

        unsafe {
            std::env::remove_var("AEGIS_MACOS_PF_STATE_PATH");
        }
        let _ = fs::remove_file(state_path);
    }

    #[test]
    fn macos_backend_rejects_tcp_only_state_with_unexpected_prepared_boundary_flag() {
        let _guard = env_lock().lock().expect("lock env");
        let state_path = unique_state_path("tcp-only-prepared-boundary-drift");
        let listen = "127.0.0.1:15080".parse().expect("listen");
        let redirect_from = "127.0.0.1:18080".parse().expect("redirect");
        let target = "127.0.0.1:18081".parse().expect("target");
        write_helper_state(
            &state_path,
            listen,
            redirect_from,
            target,
            None,
            None,
            false,
            false,
        );
        rewrite_helper_state(&state_path, |value| {
            value["prepared_boundary_enabled"] = Value::Bool(true);
        });
        unsafe {
            std::env::set_var("AEGIS_MACOS_PF_STATE_PATH", &state_path);
        }

        let settings = WideIngressSettings {
            platform_backend: WidePlatformBackend::MacosPf,
            capture_dns: false,
            listen,
            ..WideIngressSettings::default()
        };
        let err = load_helper_contour(&settings).expect_err("unexpected prepared flag must fail");
        assert!(err
            .to_string()
            .contains("macos_pf_helper_unexpected_prepared_boundary_state"));

        unsafe {
            std::env::remove_var("AEGIS_MACOS_PF_STATE_PATH");
        }
        let _ = fs::remove_file(state_path);
    }
}

#[cfg(test)]
pub(crate) mod fixture_env {
    use std::path::Path;
    use std::sync::{Mutex, OnceLock};

    pub(crate) fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    // Test-only overrides must restore caller state, including on assertion
    // unwind. Callers hold the same lock used by the actual helper writers.
    pub(super) struct HelperEnvOverride {
        state_path: Option<std::ffi::OsString>,
        phase4: Option<std::ffi::OsString>,
    }

    impl HelperEnvOverride {
        pub(super) fn new(path: &Path) -> Self {
            let previous = Self {
                state_path: std::env::var_os("AEGIS_MACOS_PF_STATE_PATH"),
                phase4: std::env::var_os("AEGIS_MACOS_PF_PHASE4"),
            };
            std::env::set_var("AEGIS_MACOS_PF_STATE_PATH", path);
            std::env::remove_var("AEGIS_MACOS_PF_PHASE4");
            previous
        }
    }

    impl Drop for HelperEnvOverride {
        fn drop(&mut self) {
            for (name, previous) in [
                ("AEGIS_MACOS_PF_STATE_PATH", &self.state_path),
                ("AEGIS_MACOS_PF_PHASE4", &self.phase4),
            ] {
                match previous {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }

    pub(crate) struct MissingHelperStateFixture {
        // Field drop order restores environment before removing its private
        // directory and, crucially, before releasing the shared writer lock.
        _environment: HelperEnvOverride,
        _directory: tempfile::TempDir,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl MissingHelperStateFixture {
        pub(crate) fn new() -> Self {
            let guard = env_lock().lock().expect("lock env");
            let directory = tempfile::tempdir().expect("private missing-state directory");
            let missing = directory.path().join("absent-helper-state.json");
            assert!(!missing.exists());
            Self {
                _environment: HelperEnvOverride::new(&missing),
                _directory: directory,
                _guard: guard,
            }
        }
    }
}
