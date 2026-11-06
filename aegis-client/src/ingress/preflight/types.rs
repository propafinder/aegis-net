use super::ActiveIngressBackend;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightSeverity {
    Info,
    Warn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightHintCode {
    SharedListeners,
    SocksListenerExposed,
    CaptureDnsPreviewOnly,
    UdpPreviewAllowlistOnly,
    GenericUdpCaptureContractRequested,
    LinuxRedirectDnsPreviewNatLimited,
    AutoUsesRedirectCompatibleStartup,
    RedirectOutputNeedsExemptUid,
    LinuxTproxyRequiresIpTransparent,
    LinuxTproxyNeedsNonZeroMark,
    RolloutOutputOnlySafe,
    RolloutPreroutingScoped,
    RolloutTransparentPrivileged,
    RolloutProfileBackendMismatch,
    PreroutingInterfaceMissing,
    PreroutingInterfaceCandidateDetected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionErrorCode {
    WideDisabledInConfig,
    UnsupportedWideBackend,
    WideBackendBoundaryOnly,
    RolloutProfileBackendMismatch,
    RolloutProfilePrerequisites,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionHintCode {
    EnableWideOrSwitchPrimaryToSocks5,
    UseSupportedBackendOrAllowFallback,
    UseSupportedPlatformBackendOrAllowFallbackWhileTesting,
    SetPreroutingInterfaceOrSwitchRolloutProfile,
    UseRedirectBackendOrSwitchRolloutProfile,
    UseTproxyBackendOrSwitchRolloutProfile,
    SetNonZeroDefaultMark,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackReasonCode {
    WideDisabledInConfig,
    UnsupportedWideBackend,
    WideBackendBoundaryOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeProbeCode {
    BindOk,
    FallbackBindOk,
    ListenerConflict,
    ListenerBusy,
    NeedsCapNetAdmin,
    UnsupportedAdapter,
    BackendPrerequisites,
    SocksBindFailed,
    WideDnsPreviewActive,
    WideDnsPreviewDisabled,
    WideDnsPreviewUnsupportedListenFamily,
    WideDnsPreviewBindFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupProbeStatus {
    Ok,
    Degraded,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupProbeCode {
    WidePrimaryStarted,
    WidePrimaryAlreadyRunning,
    WideBindFailedFallbackStarted,
    WideBindFailed,
    Socks5FallbackStarted,
    Socks5FallbackAlreadyRunning,
    SocksBindFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupHintCode {
    UseDistinctWideAndSocksListeners,
    VerifyWideListenIsFree,
    NeedsRootOrCapNetAdminForIpTransparent,
    SelectedWideBackendUnsupportedAdapter,
    VerifyWideListenerSettingsAndBackendPrerequisites,
    UseDistinctSocksAndWideListeners,
    VerifySocksListenIsFree,
    VerifySocksFallbackListenerSettings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WideRuntimeReadiness {
    Disabled,
    Ready,
    NeedsPrivilege,
    BoundaryOnly,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    PreparedBoundary,
    UnsupportedAdapter,
    ConfigError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendNoteCode {
    AutoUsesRedirectCompatibleStartup,
    LinuxRedirectExpectsOriginalDst,
    LinuxTproxyRequiresIpTransparent,
    LinuxNfqueueObserverOptInRuntime,
    PlatformAdapterStub,
    MacosPfTcpOnlyEpic,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    MacosPfDnsPreviewEpic,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    MacosPfSystemWidePhase3Boundary,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    MacosPfSystemWidePhase3PreparedBoundary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PreflightHint {
    pub code: PreflightHintCode,
    pub severity: PreflightSeverity,
    pub message: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BackendNote {
    pub code: BackendNoteCode,
    pub message: &'static str,
}

#[derive(Debug, Clone)]
pub struct IngressStartupReport {
    pub(in crate::ingress::preflight) wide_supported: bool,
    pub(in crate::ingress::preflight) wide_platform_family_supported: bool,
    pub(in crate::ingress::preflight) wide_runtime_readiness: WideRuntimeReadiness,
    pub(in crate::ingress::preflight) backend_choice: ActiveIngressBackend,
    pub(in crate::ingress::preflight) fallback_reason_code: Option<FallbackReasonCode>,
    pub(in crate::ingress::preflight) fallback_reason: Option<&'static str>,
    pub(in crate::ingress::preflight) hints: Vec<PreflightHint>,
}

#[derive(Debug, Clone)]
pub struct IngressStartupSelectionError {
    pub message: String,
    pub hint_code: SelectionHintCode,
    pub hint: &'static str,
    pub wide_supported: bool,
    pub wide_platform_family_supported: bool,
    pub wide_runtime_readiness: WideRuntimeReadiness,
    pub code: SelectionErrorCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeProbeSeverity {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeProbeCheck {
    pub target: &'static str,
    pub code: RuntimeProbeCode,
    pub severity: RuntimeProbeSeverity,
    pub fatal: bool,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StartupProbeResult {
    pub code: StartupProbeCode,
    pub started_backend: Option<&'static str>,
    pub failure_code: Option<RuntimeProbeCode>,
    pub hint_code: Option<StartupHintCode>,
    pub wide_dns_capture_preview_status: Option<&'static str>,
    pub wide_dns_capture_preview_error_kind: Option<&'static str>,
    pub wide_dns_capture_preview_error: Option<String>,
    pub wide_udp_capture_contract: Option<&'static str>,
    pub wide_udp_capture_support_tier: Option<&'static str>,
    pub wide_udp_capture_policy: Option<&'static str>,
    pub wide_udp_capture_runtime_scope: Option<&'static str>,
    pub wide_udp_preview_policy: Option<&'static str>,
    pub wide_udp_preview_ports: Vec<u16>,
    pub message: String,
    pub hint: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::ingress::preflight) enum JsonPreflightStatus {
    Ok,
    Error,
}

#[derive(Debug, Serialize)]
pub(in crate::ingress::preflight) struct JsonSelection<'a> {
    pub requested_primary: &'a str,
    pub selected_backend: &'a str,
    pub allow_fallback: bool,
    pub wide_enabled: bool,
    pub wide_supported: bool,
    pub wide_platform_family_supported: bool,
    pub wide_runtime_readiness: WideRuntimeReadiness,
    pub wide_platform: &'a str,
    pub wide_rollout_profile: &'a str,
    pub wide_prerouting_interface: Option<&'a str>,
    pub wide_prerouting_interface_candidate: Option<String>,
    pub wide_listen: String,
    pub wide_udp_capture_contract_requested: Option<&'static str>,
    pub wide_udp_capture_support_tier_requested: Option<&'static str>,
    pub wide_udp_capture_contract: Option<&'static str>,
    pub wide_udp_capture_support_tier: Option<&'static str>,
    pub wide_udp_capture_policy: Option<&'static str>,
    pub wide_udp_capture_runtime_scope: Option<&'static str>,
    pub wide_backend_current_stage: Option<&'static str>,
    pub wide_backend_scope_target: Option<&'static str>,
    pub wide_backend_reason_code: Option<&'static str>,
    pub wide_dns_port: u16,
    pub wide_udp_preview_ports: &'a [u16],
    pub socks_listen: String,
    pub fallback_reason_code: Option<FallbackReasonCode>,
    pub fallback_reason: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linux_validation_bootstrap_check_command: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linux_validation_bootstrap_install_command: Option<&'static str>,
    pub backend_notes: &'a [BackendNote],
}

#[derive(Debug, Serialize)]
pub(in crate::ingress::preflight) struct JsonErrorSelection<'a> {
    pub requested_primary: &'a str,
    pub allow_fallback: bool,
    pub wide_enabled: bool,
    pub wide_supported: bool,
    pub wide_platform_family_supported: bool,
    pub wide_runtime_readiness: WideRuntimeReadiness,
    pub wide_platform: &'a str,
    pub wide_rollout_profile: &'a str,
    pub wide_prerouting_interface: Option<&'a str>,
    pub wide_prerouting_interface_candidate: Option<String>,
    pub wide_listen: String,
    pub wide_udp_capture_contract_requested: Option<&'static str>,
    pub wide_udp_capture_support_tier_requested: Option<&'static str>,
    pub wide_udp_capture_contract: Option<&'static str>,
    pub wide_udp_capture_support_tier: Option<&'static str>,
    pub wide_udp_capture_policy: Option<&'static str>,
    pub wide_udp_capture_runtime_scope: Option<&'static str>,
    pub wide_backend_current_stage: Option<&'static str>,
    pub wide_backend_scope_target: Option<&'static str>,
    pub wide_backend_reason_code: Option<&'static str>,
    pub wide_dns_port: u16,
    pub wide_udp_preview_ports: &'a [u16],
    pub socks_listen: String,
    pub selection_error_code: SelectionErrorCode,
    pub selection_hint_code: SelectionHintCode,
    pub selection_error: &'a str,
    pub hint: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linux_validation_bootstrap_check_command: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linux_validation_bootstrap_install_command: Option<&'static str>,
    pub backend_notes: &'a [BackendNote],
}

#[derive(Debug, Serialize)]
pub(in crate::ingress::preflight) struct JsonPreflightReport<'a> {
    pub status: JsonPreflightStatus,
    pub selection: JsonSelection<'a>,
    pub hints: &'a [PreflightHint],
    pub runtime_checks: &'a [RuntimeProbeCheck],
}

#[derive(Debug, Serialize)]
pub(in crate::ingress::preflight) struct JsonPreflightError<'a> {
    pub status: JsonPreflightStatus,
    pub selection: JsonErrorSelection<'a>,
}

#[derive(Debug, Serialize)]
pub(in crate::ingress::preflight) struct JsonStartupProbeReport<'a> {
    pub status: StartupProbeStatus,
    pub selection: JsonSelection<'a>,
    pub hints: &'a [PreflightHint],
    pub startup: &'a StartupProbeResult,
}
