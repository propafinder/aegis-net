use super::{select_active_backend, wide_unavailable_reason, ActiveIngressBackend};
use aegis_core::{IngressPrimary, Settings};
use std::io;

#[path = "preflight/helpers.rs"]
mod helpers;
#[path = "preflight/runtime.rs"]
mod runtime;
#[path = "preflight/types.rs"]
mod types;

use helpers::{
    active_backend_name, active_udp_capture_contract, active_udp_capture_policy,
    active_udp_capture_runtime_scope, active_udp_capture_support_tier, backend_notes,
    classify_bind_failure, classify_socks_bind_failure, collect_preflight_hints,
    configured_prerouting_interface, detected_prerouting_interface_candidate, fallback_reason_code,
    ingress_primary_name, requested_udp_capture_contract, requested_udp_capture_support_tier,
    rollout_profile_selection_error, selection_error_code, selection_error_hint,
    wide_backend_current_stage, wide_backend_reason_code, wide_backend_scope_target,
    wide_platform_name, wide_rollout_profile_name, wide_runtime_readiness,
};
pub use types::{
    BackendNote, BackendNoteCode, FallbackReasonCode, IngressStartupReport,
    IngressStartupSelectionError, PreflightHint, PreflightHintCode, PreflightSeverity,
    RuntimeProbeCheck, RuntimeProbeCode, RuntimeProbeSeverity, SelectionErrorCode,
    SelectionHintCode, StartupHintCode, StartupProbeCode, StartupProbeResult, StartupProbeStatus,
    WideRuntimeReadiness,
};
use types::{
    JsonErrorSelection, JsonPreflightError, JsonPreflightReport, JsonPreflightStatus,
    JsonSelection, JsonStartupProbeReport,
};

impl IngressStartupReport {
    pub fn build(cfg: &Settings) -> Result<Self, IngressStartupSelectionError> {
        let wide_platform_family_supported =
            crate::ingress::wide::WidePrimaryBackend::supports_platform_family(&cfg.ingress.wide);
        let wide_supported =
            crate::ingress::wide::WidePrimaryBackend::supports_platform(&cfg.ingress.wide);
        let readiness = wide_runtime_readiness(cfg, wide_platform_family_supported, wide_supported);
        // Validate rollout intent before backend fallback so policy errors stay deterministic across OSes.
        if cfg.ingress.primary == IngressPrimary::Wide && cfg.ingress.wide.enabled {
            if let Some((code, message, hint_code, hint)) = rollout_profile_selection_error(cfg) {
                return Err(IngressStartupSelectionError {
                    message,
                    hint_code,
                    hint,
                    wide_supported,
                    wide_platform_family_supported,
                    wide_runtime_readiness: readiness,
                    code,
                });
            }
        }
        let backend_choice = match select_active_backend(&cfg.ingress, wide_supported) {
            Ok(choice) => choice,
            Err(message) => {
                let (hint_code, hint) = selection_error_hint(cfg);
                return Err(IngressStartupSelectionError {
                    message,
                    hint_code,
                    hint,
                    wide_supported,
                    wide_platform_family_supported,
                    wide_runtime_readiness: readiness,
                    code: selection_error_code(cfg),
                });
            }
        };

        let fallback_reason_code = (cfg.ingress.primary == IngressPrimary::Wide
            && matches!(backend_choice, ActiveIngressBackend::Socks5Fallback))
        .then(|| fallback_reason_code(cfg));
        let fallback_reason = fallback_reason_code.map(|_| wide_unavailable_reason(&cfg.ingress));

        Ok(Self {
            wide_supported,
            wide_platform_family_supported,
            wide_runtime_readiness: readiness,
            backend_choice,
            fallback_reason_code,
            fallback_reason,
            hints: collect_preflight_hints(cfg),
        })
    }

    pub fn wide_supported(&self) -> bool {
        self.wide_supported
    }

    pub fn wide_platform_family_supported(&self) -> bool {
        self.wide_platform_family_supported
    }

    pub fn wide_runtime_readiness(&self) -> WideRuntimeReadiness {
        self.wide_runtime_readiness
    }

    pub fn backend_choice(&self) -> ActiveIngressBackend {
        self.backend_choice
    }

    pub fn fallback_reason(&self) -> Option<&'static str> {
        self.fallback_reason
    }

    pub fn fallback_reason_code(&self) -> Option<FallbackReasonCode> {
        self.fallback_reason_code
    }

    pub fn wide_backend_current_stage(&self, cfg: &Settings) -> Option<&'static str> {
        wide_backend_current_stage(cfg)
    }

    pub fn wide_backend_scope_target(&self, cfg: &Settings) -> Option<&'static str> {
        wide_backend_scope_target(cfg)
    }

    pub fn wide_backend_reason_code(&self, cfg: &Settings) -> Option<&'static str> {
        wide_backend_reason_code(cfg)
    }

    pub fn hints(&self) -> &[PreflightHint] {
        &self.hints
    }

    pub fn bind_error_hint(&self, cfg: &Settings, err: &io::Error) -> &'static str {
        classify_bind_failure(cfg, err).2
    }

    pub fn bind_error_hint_code(&self, cfg: &Settings, err: &io::Error) -> StartupHintCode {
        classify_bind_failure(cfg, err).1
    }

    pub fn bind_error_code(&self, cfg: &Settings, err: &io::Error) -> RuntimeProbeCode {
        classify_bind_failure(cfg, err).0
    }

    pub fn bind_failure_message(&self, cfg: &Settings, err: &io::Error) -> String {
        format!(
            "wide ingress bind failed on {} (backend={:?}): {}. hint: {}",
            cfg.ingress.wide.listen,
            cfg.ingress.wide.platform_backend,
            err,
            self.bind_error_hint(cfg, err)
        )
    }
}

impl IngressStartupSelectionError {
    pub fn wide_backend_current_stage(&self, cfg: &Settings) -> Option<&'static str> {
        wide_backend_current_stage(cfg)
    }

    pub fn wide_backend_scope_target(&self, cfg: &Settings) -> Option<&'static str> {
        wide_backend_scope_target(cfg)
    }

    pub fn wide_backend_reason_code(&self, cfg: &Settings) -> Option<&'static str> {
        wide_backend_reason_code(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::{WidePlatformBackend, WideRolloutProfile, WideUdpCaptureContract};
    use std::net::TcpListener as StdTcpListener;
    #[cfg(target_os = "macos")]
    use std::sync::Mutex;

    fn default_wide_supported() -> bool {
        #[cfg(target_os = "linux")]
        {
            true
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    fn default_wide_platform_family_supported() -> bool {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        {
            true
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            false
        }
    }

    fn default_wide_runtime_readiness() -> WideRuntimeReadiness {
        #[cfg(target_os = "linux")]
        {
            WideRuntimeReadiness::Ready
        }
        #[cfg(not(target_os = "linux"))]
        {
            WideRuntimeReadiness::UnsupportedAdapter
        }
    }

    #[cfg(target_os = "macos")]
    fn env_lock() -> &'static Mutex<()> {
        crate::ingress::wide::macos::fixture_env::env_lock()
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_pf_system_wide_phase3_reports_boundary_only_readiness() {
        let _guard = env_lock().lock().expect("lock env");
        let mut cfg = Settings::default();
        cfg.ingress.allow_fallback = false;
        cfg.ingress.wide.platform_backend = WidePlatformBackend::MacosPf;
        cfg.ingress.wide.listen = "0.0.0.0:15080".parse().unwrap();
        cfg.ingress.wide.capture_dns = true;
        cfg.ingress.wide.udp_capture_contract = WideUdpCaptureContract::GenericCaptureUnstable;

        let state_path = std::env::temp_dir().join(format!(
            "aegis-preflight-macos-system-wide-missing-{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&state_path);
        unsafe {
            std::env::set_var("AEGIS_MACOS_PF_STATE_PATH", &state_path);
        }
        let err = IngressStartupReport::build(&cfg).unwrap_err();
        unsafe {
            std::env::remove_var("AEGIS_MACOS_PF_STATE_PATH");
        }

        assert_eq!(err.code, SelectionErrorCode::WideBackendBoundaryOnly);
        assert_eq!(
            err.wide_runtime_readiness,
            WideRuntimeReadiness::BoundaryOnly
        );
        assert!(err.wide_platform_family_supported);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_pf_system_wide_phase3_reports_prepared_boundary_readiness() {
        let _guard = env_lock().lock().expect("lock env");
        let mut cfg = Settings::default();
        cfg.ingress.allow_fallback = true;
        cfg.ingress.wide.platform_backend = WidePlatformBackend::MacosPf;
        cfg.ingress.wide.listen = "0.0.0.0:15081".parse().unwrap();
        cfg.ingress.wide.capture_dns = true;
        cfg.ingress.wide.udp_capture_contract = WideUdpCaptureContract::GenericCaptureUnstable;

        let state_path = std::env::temp_dir().join(format!(
            "aegis-preflight-macos-system-wide-prepared-{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&state_path);
        std::fs::write(
            &state_path,
            r#"{
  "runtime_active": false,
  "current_stage": "system_wide_phase3_prepared_boundary",
  "scope_target": "system_wide_phase3",
  "listen": "0.0.0.0:15081",
  "redirect_from": "10.10.0.6:28085",
  "target": "8.8.8.8:53",
  "dns_preview_enabled": false,
  "dns_redirect_from": null,
  "dns_target": null,
  "system_wide_enabled": true,
  "prepared_boundary_enabled": true
}"#,
        )
        .expect("write prepared state");
        unsafe {
            std::env::set_var("AEGIS_MACOS_PF_STATE_PATH", &state_path);
        }
        let report = IngressStartupReport::build(&cfg).expect("report");

        assert_eq!(
            report.fallback_reason_code(),
            Some(FallbackReasonCode::WideBackendBoundaryOnly)
        );
        assert_eq!(
            report.wide_runtime_readiness(),
            WideRuntimeReadiness::PreparedBoundary
        );
        assert!(report.wide_platform_family_supported());
        assert_eq!(
            report.wide_backend_current_stage(&cfg),
            Some("system_wide_phase3_prepared_boundary")
        );
        assert_eq!(
            report.wide_backend_reason_code(&cfg),
            Some("pf_system_wide_phase3_prepared_boundary_only")
        );
        unsafe {
            std::env::remove_var("AEGIS_MACOS_PF_STATE_PATH");
        }
        let _ = std::fs::remove_file(&state_path);
    }

    fn default_backend_choice() -> ActiveIngressBackend {
        #[cfg(target_os = "linux")]
        {
            ActiveIngressBackend::WidePrimary
        }
        #[cfg(not(target_os = "linux"))]
        {
            ActiveIngressBackend::Socks5Fallback
        }
    }

    fn default_backend_name() -> &'static str {
        match default_backend_choice() {
            ActiveIngressBackend::WidePrimary => "wide_primary",
            ActiveIngressBackend::Socks5Fallback => "socks5_fallback",
        }
    }

    #[test]
    fn report_warns_about_conflicting_listeners() {
        #[cfg(target_os = "macos")]
        let _missing_helper_state =
            crate::ingress::wide::macos::fixture_env::MissingHelperStateFixture::new();
        let mut cfg = Settings::default();
        cfg.ingress.wide.listen = cfg.socks.listen;
        let report = IngressStartupReport::build(&cfg).expect("report");
        assert!(report.hints().iter().any(|hint| {
            hint.code == PreflightHintCode::SharedListeners
                && hint.message
                    == "wide and SOCKS5 listeners share the same address; use separate ports to keep fallback diagnostics unambiguous"
        }));
    }

    #[test]
    fn report_warns_when_socks_listener_is_not_loopback_scoped() {
        #[cfg(target_os = "macos")]
        let _missing_helper_state =
            crate::ingress::wide::macos::fixture_env::MissingHelperStateFixture::new();
        let mut cfg = Settings::default();
        cfg.socks.listen = "0.0.0.0:1080".parse().unwrap();
        let report = IngressStartupReport::build(&cfg).expect("report");
        assert!(report.hints().iter().any(|hint| {
            hint.code == PreflightHintCode::SocksListenerExposed
                && hint.message
                    == "SOCKS5 fallback listener is not loopback-scoped; keep socks.listen on localhost unless you intentionally expose it"
        }));
    }

    #[test]
    fn report_warns_that_capture_dns_is_preview_only() {
        #[cfg(target_os = "macos")]
        let _missing_helper_state =
            crate::ingress::wide::macos::fixture_env::MissingHelperStateFixture::new();
        let cfg = Settings::default();
        let report = IngressStartupReport::build(&cfg).expect("report");
        assert!(report.hints().iter().any(|hint| {
            hint.code == PreflightHintCode::CaptureDnsPreviewOnly
                && hint.message.contains("still a narrow Linux preview")
        }));
        assert!(report.hints().iter().any(|hint| {
            hint.code == PreflightHintCode::UdpPreviewAllowlistOnly
                && hint.message.contains("allowlist-only")
        }));
    }

    #[test]
    fn report_warns_when_generic_udp_capture_contract_is_requested() {
        #[cfg(target_os = "macos")]
        let _missing_helper_state =
            crate::ingress::wide::macos::fixture_env::MissingHelperStateFixture::new();
        let mut cfg = Settings::default();
        cfg.ingress.wide.udp_capture_contract = WideUdpCaptureContract::GenericCaptureUnstable;
        let report = IngressStartupReport::build(&cfg).expect("report");
        assert!(report.hints().iter().any(|hint| {
            hint.code == PreflightHintCode::GenericUdpCaptureContractRequested
                && hint.message.contains("broader Linux UDP receive path")
        }));
        assert!(!report
            .hints()
            .iter()
            .any(|hint| hint.code == PreflightHintCode::UdpPreviewAllowlistOnly));
    }

    #[test]
    fn linux_redirect_warns_that_dns_preview_is_nat_limited() {
        let mut cfg = Settings::default();
        cfg.ingress.wide.platform_backend = WidePlatformBackend::LinuxRedirect;
        let report = IngressStartupReport::build(&cfg).expect("report");
        #[cfg(target_os = "linux")]
        assert!(report.hints().iter().any(|hint| {
            hint.code == PreflightHintCode::LinuxRedirectDnsPreviewNatLimited
                && hint.message.contains("NAT-limited")
        }));
        #[cfg(not(target_os = "linux"))]
        assert!(!report
            .hints()
            .iter()
            .any(|hint| hint.code == PreflightHintCode::LinuxRedirectDnsPreviewNatLimited));
    }

    #[test]
    fn linux_tproxy_warns_when_default_mark_is_zero() {
        let mut cfg = Settings::default();
        cfg.ingress.wide.rollout_profile = WideRolloutProfile::TransparentPrivileged;
        cfg.ingress.wide.platform_backend = WidePlatformBackend::LinuxTproxy;
        cfg.ingress.wide.default_mark = 0;
        let err = IngressStartupReport::build(&cfg).unwrap_err();
        assert_eq!(err.code, SelectionErrorCode::RolloutProfilePrerequisites);
        assert_eq!(
            err.message,
            "transparent_privileged rollout profile requires a non-zero default_mark"
        );
    }

    #[test]
    fn linux_auto_on_linux_adds_redirect_owner_exemption_hint() {
        #[cfg(target_os = "macos")]
        let _missing_helper_state =
            crate::ingress::wide::macos::fixture_env::MissingHelperStateFixture::new();
        let cfg = Settings::default();
        let report = IngressStartupReport::build(&cfg).expect("report");
        #[cfg(target_os = "linux")]
        assert!(report.hints().iter().any(|hint| {
            hint.code == PreflightHintCode::RedirectOutputNeedsExemptUid
                && hint.message.contains("exempt the aegis-client UID")
        }));
        #[cfg(not(target_os = "linux"))]
        assert!(!report
            .hints()
            .iter()
            .any(|hint| hint.code == PreflightHintCode::RedirectOutputNeedsExemptUid));
    }

    #[test]
    fn transparent_privileged_rollout_requires_tproxy_backend() {
        let mut cfg = Settings::default();
        cfg.ingress.wide.rollout_profile = WideRolloutProfile::TransparentPrivileged;
        cfg.ingress.wide.platform_backend = WidePlatformBackend::LinuxRedirect;
        let err = IngressStartupReport::build(&cfg).unwrap_err();
        assert_eq!(err.code, SelectionErrorCode::RolloutProfileBackendMismatch);
        assert_eq!(
            err.message,
            "transparent_privileged rollout profile requires linux_tproxy backend, got LinuxRedirect"
        );
    }

    #[test]
    fn output_only_safe_rollout_rejects_explicit_tproxy() {
        let mut cfg = Settings::default();
        cfg.ingress.wide.rollout_profile = WideRolloutProfile::OutputOnlySafe;
        cfg.ingress.wide.platform_backend = WidePlatformBackend::LinuxTproxy;
        let err = IngressStartupReport::build(&cfg).unwrap_err();
        assert_eq!(err.code, SelectionErrorCode::RolloutProfileBackendMismatch);
        assert_eq!(
            err.message,
            "output_only_safe rollout profile does not support explicit linux_tproxy backend"
        );
    }

    #[test]
    fn prerouting_scoped_rollout_requires_interface_scope() {
        #[cfg(target_os = "macos")]
        let _missing_helper_state =
            crate::ingress::wide::macos::fixture_env::MissingHelperStateFixture::new();
        let mut cfg = Settings::default();
        cfg.ingress.wide.rollout_profile = WideRolloutProfile::PreroutingScoped;
        let err = IngressStartupReport::build(&cfg).unwrap_err();
        assert_eq!(err.code, SelectionErrorCode::RolloutProfilePrerequisites);
        assert_eq!(
            err.message,
            "prerouting_scoped rollout profile requires ingress.wide.prerouting_interface"
        );
    }

    #[test]
    fn prerouting_scoped_rollout_accepts_interface_scope() {
        #[cfg(target_os = "macos")]
        let _missing_helper_state =
            crate::ingress::wide::macos::fixture_env::MissingHelperStateFixture::new();
        let mut cfg = Settings::default();
        cfg.ingress.wide.rollout_profile = WideRolloutProfile::PreroutingScoped;
        cfg.ingress.wide.prerouting_interface = Some("eth0".to_string());
        let report = IngressStartupReport::build(&cfg).expect("report");
        assert!(report.hints().iter().any(|hint| {
            hint.code == PreflightHintCode::RolloutPreroutingScoped
                && hint.message.contains("explicit interface scope")
        }));
    }

    #[test]
    fn report_exposes_fallback_reason_for_unavailable_wide() {
        let mut cfg = Settings::default();
        cfg.ingress.wide.enabled = false;
        let report = IngressStartupReport::build(&cfg).expect("report");
        assert_eq!(
            report.fallback_reason_code(),
            Some(FallbackReasonCode::WideDisabledInConfig)
        );
        assert_eq!(
            report.fallback_reason(),
            Some("wide ingress is disabled in config")
        );
    }

    #[test]
    fn macos_pf_selection_error_stays_machine_readable_without_fallback() {
        #[cfg(target_os = "macos")]
        let _missing_helper_state =
            crate::ingress::wide::macos::fixture_env::MissingHelperStateFixture::new();
        let mut cfg = Settings::default();
        cfg.ingress.allow_fallback = false;
        cfg.ingress.wide.platform_backend = WidePlatformBackend::MacosPf;
        let err = IngressStartupReport::build(&cfg).unwrap_err();
        let rendered = err.render_json(&cfg);
        assert_eq!(err.code, SelectionErrorCode::UnsupportedWideBackend);
        assert!(!err.wide_supported);
        assert_eq!(
            err.wide_runtime_readiness,
            WideRuntimeReadiness::UnsupportedAdapter
        );
        assert!(rendered
            .contains("\"wide_udp_capture_contract_requested\": \"preview_allowlist_only\""));
        assert!(rendered.contains("\"wide_udp_capture_contract\": null"));
        assert!(rendered.contains("\"wide_udp_capture_policy\": null"));
        assert!(rendered.contains("\"wide_udp_capture_runtime_scope\": null"));
        #[cfg(target_os = "macos")]
        assert!(err.wide_platform_family_supported);
        #[cfg(not(target_os = "macos"))]
        assert!(!err.wide_platform_family_supported);
    }

    #[test]
    fn macos_pf_fallback_reason_stays_unsupported_backend_with_fallback() {
        #[cfg(target_os = "macos")]
        let _missing_helper_state =
            crate::ingress::wide::macos::fixture_env::MissingHelperStateFixture::new();
        let mut cfg = Settings::default();
        cfg.ingress.allow_fallback = true;
        cfg.ingress.wide.platform_backend = WidePlatformBackend::MacosPf;
        let report = IngressStartupReport::build(&cfg).expect("report");
        assert_eq!(
            report.backend_choice(),
            ActiveIngressBackend::Socks5Fallback
        );
        assert_eq!(
            report.fallback_reason_code(),
            Some(FallbackReasonCode::UnsupportedWideBackend)
        );
        assert_eq!(
            report.fallback_reason(),
            Some("selected wide platform backend is unsupported on this platform")
        );
        assert!(!report.wide_supported());
        assert_eq!(
            report.wide_runtime_readiness(),
            WideRuntimeReadiness::UnsupportedAdapter
        );
        #[cfg(target_os = "macos")]
        assert!(report.wide_platform_family_supported());
        #[cfg(not(target_os = "macos"))]
        assert!(!report.wide_platform_family_supported());
    }

    #[test]
    fn macos_pf_system_wide_phase3_boundary_uses_boundary_reason_with_fallback() {
        #[cfg(target_os = "macos")]
        let _missing_helper_state =
            crate::ingress::wide::macos::fixture_env::MissingHelperStateFixture::new();
        let mut cfg = Settings::default();
        cfg.ingress.allow_fallback = true;
        cfg.ingress.wide.platform_backend = WidePlatformBackend::MacosPf;
        cfg.ingress.wide.listen = "0.0.0.0:15080".parse().unwrap();
        cfg.ingress.wide.capture_dns = true;
        cfg.ingress.wide.udp_capture_contract = WideUdpCaptureContract::GenericCaptureUnstable;
        let report = IngressStartupReport::build(&cfg).expect("report");
        #[cfg(target_os = "macos")]
        assert_eq!(
            report.fallback_reason_code(),
            Some(FallbackReasonCode::WideBackendBoundaryOnly)
        );
        #[cfg(not(target_os = "macos"))]
        assert_eq!(
            report.fallback_reason_code(),
            Some(FallbackReasonCode::UnsupportedWideBackend)
        );
        #[cfg(target_os = "macos")]
        assert_eq!(
            report.fallback_reason(),
            Some(
                "macos_pf system_wide_phase3 is currently boundary-only and falls back until a broader runtime path exists"
            )
        );
        #[cfg(not(target_os = "macos"))]
        assert_eq!(
            report.fallback_reason(),
            Some("selected wide platform backend is unsupported on this platform")
        );
        #[cfg(target_os = "macos")]
        assert_eq!(
            report.wide_runtime_readiness(),
            WideRuntimeReadiness::BoundaryOnly
        );
        #[cfg(not(target_os = "macos"))]
        assert_eq!(
            report.wide_runtime_readiness(),
            WideRuntimeReadiness::UnsupportedAdapter
        );
    }

    #[test]
    fn default_selection_tracks_runtime_supported_wide_backend() {
        #[cfg(target_os = "macos")]
        let _missing_helper_state =
            crate::ingress::wide::macos::fixture_env::MissingHelperStateFixture::new();
        let cfg = Settings::default();
        let report = IngressStartupReport::build(&cfg).expect("report");
        assert_eq!(report.wide_supported(), default_wide_supported());
        assert_eq!(
            report.wide_platform_family_supported(),
            default_wide_platform_family_supported()
        );
        assert_eq!(
            report.wide_runtime_readiness(),
            default_wide_runtime_readiness()
        );
        assert_eq!(report.backend_choice(), default_backend_choice());
    }

    #[test]
    fn valid_linux_tproxy_reports_privileged_runtime_readiness() {
        let mut cfg = Settings::default();
        cfg.ingress.wide.platform_backend = WidePlatformBackend::LinuxTproxy;
        cfg.ingress.wide.rollout_profile = WideRolloutProfile::TransparentPrivileged;
        cfg.ingress.wide.default_mark = 1;
        let report = IngressStartupReport::build(&cfg).expect("report");
        #[cfg(target_os = "linux")]
        {
            assert!(report.wide_platform_family_supported());
            assert!(report.wide_supported());
            assert_eq!(
                report.wide_runtime_readiness(),
                WideRuntimeReadiness::NeedsPrivilege
            );
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert!(!report.wide_supported());
            assert_eq!(
                report.wide_runtime_readiness(),
                WideRuntimeReadiness::UnsupportedAdapter
            );
        }
    }

    #[test]
    fn selection_error_hint_mentions_enabling_wide_or_switching_primary() {
        let mut cfg = Settings::default();
        cfg.ingress.allow_fallback = false;
        cfg.ingress.wide.enabled = false;
        let err = IngressStartupReport::build(&cfg).unwrap_err();
        assert_eq!(err.code, SelectionErrorCode::WideDisabledInConfig);
        assert_eq!(
            err.hint,
            "enable [ingress.wide] or switch ingress.primary to socks5"
        );
    }

    #[test]
    fn bind_hint_mentions_conflicting_listeners() {
        #[cfg(target_os = "macos")]
        let _missing_helper_state =
            crate::ingress::wide::macos::fixture_env::MissingHelperStateFixture::new();
        let mut cfg = Settings::default();
        cfg.ingress.wide.listen = cfg.socks.listen;
        let report = IngressStartupReport::build(&cfg).expect("report");
        let err = io::Error::from_raw_os_error(98);
        assert_eq!(
            classify_bind_failure(&cfg, &err).0,
            RuntimeProbeCode::ListenerConflict
        );
        assert_eq!(
            report.bind_error_hint(&cfg, &err),
            "wide.listen conflicts with socks.listen; use different addresses or ports"
        );
    }

    #[test]
    fn bind_hint_mentions_tproxy_capability_requirements() {
        let mut cfg = Settings::default();
        cfg.ingress.wide.rollout_profile = WideRolloutProfile::TransparentPrivileged;
        cfg.ingress.wide.platform_backend = WidePlatformBackend::LinuxTproxy;
        cfg.ingress.wide.default_mark = 1;
        let report = IngressStartupReport::build(&cfg).expect("report");
        let err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        assert_eq!(
            classify_bind_failure(&cfg, &err).0,
            RuntimeProbeCode::NeedsCapNetAdmin
        );
        assert_eq!(
            report.bind_error_hint(&cfg, &err),
            "explicit linux_tproxy needs root or CAP_NET_ADMIN so IP_TRANSPARENT can be set"
        );
    }

    #[test]
    fn socks_bind_failure_uses_listener_conflict_when_addresses_match() {
        let mut cfg = Settings::default();
        cfg.socks.listen = cfg.ingress.wide.listen;
        let err = io::Error::from_raw_os_error(98);
        assert_eq!(
            classify_socks_bind_failure(&cfg, &err).0,
            RuntimeProbeCode::ListenerConflict
        );
    }

    #[test]
    fn bind_failure_message_includes_hint_and_backend() {
        let mut cfg = Settings::default();
        cfg.ingress.wide.rollout_profile = WideRolloutProfile::TransparentPrivileged;
        cfg.ingress.wide.platform_backend = WidePlatformBackend::LinuxTproxy;
        cfg.ingress.wide.default_mark = 1;
        let report = IngressStartupReport::build(&cfg).expect("report");
        let err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        let message = report.bind_failure_message(&cfg, &err);
        assert!(message.contains("backend=LinuxTproxy"));
        assert!(message.contains("hint: explicit linux_tproxy needs root or CAP_NET_ADMIN"));
    }

    #[test]
    fn render_text_contains_selected_backend_and_hints() {
        #[cfg(target_os = "macos")]
        let _missing_helper_state =
            crate::ingress::wide::macos::fixture_env::MissingHelperStateFixture::new();
        let mut cfg = Settings::default();
        cfg.ingress.wide.listen = cfg.socks.listen;
        let report = IngressStartupReport::build(&cfg).expect("report");
        let rendered = report.render_text_with_runtime_checks(&cfg, &[], false);
        assert!(rendered.contains("[selection]"));
        assert!(rendered.contains(&format!(
            "requested_primary: {}",
            ingress_primary_name(&cfg)
        )));
        assert!(rendered.contains(&format!("selected_backend: {}", default_backend_name())));
        assert!(rendered.contains(&format!(
            "wide_runtime_readiness: {}",
            match default_wide_runtime_readiness() {
                WideRuntimeReadiness::Disabled => "disabled",
                WideRuntimeReadiness::Ready => "ready",
                WideRuntimeReadiness::NeedsPrivilege => "needs_privilege",
                WideRuntimeReadiness::BoundaryOnly => "boundary_only",
                WideRuntimeReadiness::PreparedBoundary => "prepared_boundary",
                WideRuntimeReadiness::UnsupportedAdapter => "unsupported_adapter",
                WideRuntimeReadiness::ConfigError => "config_error",
            }
        )));
        assert!(rendered.contains("wide_rollout_profile: output_only_safe"));
        #[cfg(target_os = "linux")]
        {
            assert!(rendered.contains(
                "linux_validation_bootstrap_check_command: bash scripts/bootstrap-wide-linux-validation-host.sh --check --json"
            ));
            assert!(rendered.contains(
                "linux_validation_bootstrap_install_command: bash scripts/bootstrap-wide-linux-validation-host.sh --install"
            ));
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert!(!rendered.contains("linux_validation_bootstrap_check_command:"));
            assert!(!rendered.contains("linux_validation_bootstrap_install_command:"));
        }
        assert!(rendered.contains("- [warn] wide and SOCKS5 listeners share the same address"));
        assert!(rendered.contains("- [warn] ingress.wide.capture_dns is configured"));
        assert!(rendered.contains("- [warn] the current Linux UDP preview is allowlist-only"));
        assert!(rendered.contains("[runtime_checks]\n(not run)"));
    }

    #[test]
    fn selection_error_render_contains_hint() {
        let mut cfg = Settings::default();
        cfg.ingress.allow_fallback = false;
        cfg.ingress.wide.enabled = false;
        let err = IngressStartupReport::build(&cfg).unwrap_err();
        let rendered = err.render_text(&cfg);
        assert!(rendered.contains("requested_primary: wide"));
        assert!(rendered.contains("wide_runtime_readiness: disabled"));
        assert!(rendered.contains("wide_rollout_profile: output_only_safe"));
        assert!(!rendered.contains("linux_validation_bootstrap_check_command:"));
        assert!(!rendered.contains("linux_validation_bootstrap_install_command:"));
        assert!(rendered.contains("selection_error: wide ingress is selected, but unavailable"));
        assert!(
            rendered.contains("hint: enable [ingress.wide] or switch ingress.primary to socks5")
        );
    }

    #[test]
    fn render_with_runtime_checks_includes_runtime_section() {
        #[cfg(target_os = "macos")]
        let _missing_helper_state =
            crate::ingress::wide::macos::fixture_env::MissingHelperStateFixture::new();
        let cfg = Settings::default();
        let report = IngressStartupReport::build(&cfg).expect("report");
        let rendered = report.render_text_with_runtime_checks(
            &cfg,
            &[RuntimeProbeCheck {
                target: "wide.listen",
                code: RuntimeProbeCode::BindOk,
                severity: RuntimeProbeSeverity::Pass,
                fatal: false,
                message: "wide bind probe succeeded".to_string(),
            }],
            true,
        );
        assert!(rendered.contains("[runtime_checks]"));
        assert!(rendered.contains("[pass] wide.listen: wide bind probe succeeded (fatal=false)"));
    }

    #[test]
    fn render_json_contains_structured_selection_and_checks() {
        #[cfg(target_os = "macos")]
        let _missing_helper_state =
            crate::ingress::wide::macos::fixture_env::MissingHelperStateFixture::new();
        let cfg = Settings::default();
        let report = IngressStartupReport::build(&cfg).expect("report");
        let rendered = report.render_json_with_runtime_checks(
            &cfg,
            &[RuntimeProbeCheck {
                target: "wide.listen",
                code: RuntimeProbeCode::BindOk,
                severity: RuntimeProbeSeverity::Pass,
                fatal: false,
                message: "wide bind probe succeeded".to_string(),
            }],
        );
        assert!(rendered.contains("\"status\": \"ok\""));
        assert!(rendered.contains(&format!(
            "\"selected_backend\": \"{}\"",
            default_backend_name()
        )));
        assert!(rendered.contains("\"runtime_checks\""));
        assert!(rendered.contains("\"code\": \"bind_ok\""));
        assert!(rendered.contains("\"backend_notes\""));
        assert!(rendered.contains("\"code\": \"auto_uses_redirect_compatible_startup\""));
        assert!(rendered.contains("\"code\": \"capture_dns_preview_only\""));
        assert!(rendered.contains("\"code\": \"udp_preview_allowlist_only\""));
        assert!(rendered.contains("\"wide_rollout_profile\": \"output_only_safe\""));
        assert!(rendered.contains("\"wide_prerouting_interface\": null"));
        assert!(rendered.contains("\"wide_prerouting_interface_candidate\": null"));
        assert!(rendered
            .contains("\"wide_udp_capture_contract_requested\": \"preview_allowlist_only\""));
        assert!(
            rendered.contains("\"wide_udp_capture_support_tier_requested\": \"supported_preview\"")
        );
        match default_backend_choice() {
            ActiveIngressBackend::WidePrimary => {
                assert!(
                    rendered.contains("\"wide_udp_capture_contract\": \"preview_allowlist_only\"")
                );
                assert!(
                    rendered.contains("\"wide_udp_capture_support_tier\": \"supported_preview\"")
                );
                assert!(rendered.contains("\"wide_udp_capture_policy\": \"allowlist_ports\""));
                assert!(
                    rendered.contains("\"wide_udp_capture_runtime_scope\": \"linux_ipv4_only\"")
                );
            }
            ActiveIngressBackend::Socks5Fallback => {
                assert!(rendered.contains("\"wide_udp_capture_contract\": null"));
                assert!(rendered.contains("\"wide_udp_capture_support_tier\": null"));
                assert!(rendered.contains("\"wide_udp_capture_policy\": null"));
                assert!(rendered.contains("\"wide_udp_capture_runtime_scope\": null"));
            }
        }
        assert!(rendered.contains("\"wide_dns_port\": 53"));
        assert!(rendered.contains("\"wide_udp_preview_ports\": []"));
        assert!(rendered.contains(&format!(
            "\"wide_supported\": {}",
            if default_wide_supported() {
                "true"
            } else {
                "false"
            }
        )));
        assert!(rendered.contains(&format!(
            "\"wide_platform_family_supported\": {}",
            if default_wide_platform_family_supported() {
                "true"
            } else {
                "false"
            }
        )));
        assert!(rendered.contains(&format!(
            "\"wide_runtime_readiness\": \"{}\"",
            match default_wide_runtime_readiness() {
                WideRuntimeReadiness::Disabled => "disabled",
                WideRuntimeReadiness::Ready => "ready",
                WideRuntimeReadiness::NeedsPrivilege => "needs_privilege",
                WideRuntimeReadiness::BoundaryOnly => "boundary_only",
                WideRuntimeReadiness::PreparedBoundary => "prepared_boundary",
                WideRuntimeReadiness::UnsupportedAdapter => "unsupported_adapter",
                WideRuntimeReadiness::ConfigError => "config_error",
            }
        )));
        #[cfg(target_os = "linux")]
        {
            assert!(rendered.contains(
                "\"linux_validation_bootstrap_check_command\": \"bash scripts/bootstrap-wide-linux-validation-host.sh --check --json\""
            ));
            assert!(rendered.contains(
                "\"linux_validation_bootstrap_install_command\": \"bash scripts/bootstrap-wide-linux-validation-host.sh --install\""
            ));
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert!(!rendered.contains("\"linux_validation_bootstrap_check_command\""));
            assert!(!rendered.contains("\"linux_validation_bootstrap_install_command\""));
        }
    }

    #[test]
    fn render_text_omits_linux_bootstrap_handoff_for_socks5_primary() {
        let mut cfg = Settings::default();
        cfg.ingress.primary = IngressPrimary::Socks5;
        let report = IngressStartupReport::build(&cfg).expect("report");
        let rendered = report.render_text_with_runtime_checks(&cfg, &[], false);
        assert!(rendered.contains("requested_primary: socks5"));
        assert!(!rendered.contains("linux_validation_bootstrap_check_command:"));
        assert!(!rendered.contains("linux_validation_bootstrap_install_command:"));
    }

    #[test]
    fn render_json_omits_linux_bootstrap_handoff_for_socks5_primary() {
        let mut cfg = Settings::default();
        cfg.ingress.primary = IngressPrimary::Socks5;
        let report = IngressStartupReport::build(&cfg).expect("report");
        let rendered = report.render_json_with_runtime_checks(&cfg, &[]);
        assert!(rendered.contains("\"requested_primary\": \"socks5\""));
        assert!(rendered
            .contains("\"wide_udp_capture_contract_requested\": \"preview_allowlist_only\""));
        assert!(
            rendered.contains("\"wide_udp_capture_support_tier_requested\": \"supported_preview\"")
        );
        assert!(rendered.contains("\"wide_udp_capture_contract\": null"));
        assert!(rendered.contains("\"wide_udp_capture_support_tier\": null"));
        assert!(rendered.contains("\"wide_udp_capture_policy\": null"));
        assert!(rendered.contains("\"wide_udp_capture_runtime_scope\": null"));
        assert!(!rendered.contains("\"linux_validation_bootstrap_check_command\""));
        assert!(!rendered.contains("\"linux_validation_bootstrap_install_command\""));
    }

    #[test]
    fn socks5_primary_omits_wide_rollout_hints_and_backend_notes() {
        let mut cfg = Settings::default();
        cfg.ingress.primary = IngressPrimary::Socks5;
        let report = IngressStartupReport::build(&cfg).expect("report");
        assert!(!report.hints().iter().any(|hint| {
            matches!(
                hint.code,
                PreflightHintCode::CaptureDnsPreviewOnly
                    | PreflightHintCode::UdpPreviewAllowlistOnly
                    | PreflightHintCode::GenericUdpCaptureContractRequested
                    | PreflightHintCode::LinuxRedirectDnsPreviewNatLimited
                    | PreflightHintCode::AutoUsesRedirectCompatibleStartup
                    | PreflightHintCode::RedirectOutputNeedsExemptUid
                    | PreflightHintCode::LinuxTproxyRequiresIpTransparent
                    | PreflightHintCode::LinuxTproxyNeedsNonZeroMark
                    | PreflightHintCode::RolloutOutputOnlySafe
                    | PreflightHintCode::RolloutPreroutingScoped
                    | PreflightHintCode::RolloutTransparentPrivileged
                    | PreflightHintCode::RolloutProfileBackendMismatch
                    | PreflightHintCode::PreroutingInterfaceMissing
                    | PreflightHintCode::PreroutingInterfaceCandidateDetected
            )
        }));
        let rendered = report.render_json_with_runtime_checks(&cfg, &[]);
        assert!(rendered.contains("\"backend_notes\": []"));
    }

    #[test]
    fn nfqueue_preflight_reports_the_live_opt_in_runtime_not_a_stub() {
        let mut cfg = Settings::default();
        cfg.ingress.primary = IngressPrimary::Wide;
        cfg.ingress.wide.enabled = true;
        cfg.ingress.wide.platform_backend = WidePlatformBackend::LinuxNfqueueObserver;
        let notes = backend_notes(&cfg);
        assert_eq!(notes.len(), 1);
        assert_eq!(
            notes[0].code,
            BackendNoteCode::LinuxNfqueueObserverOptInRuntime
        );
        assert!(!notes[0].message.contains("stub"));
        assert!(!notes[0].message.contains("next stage"));
    }

    #[test]
    fn render_json_can_encode_listener_conflict_runtime_check() {
        #[cfg(target_os = "macos")]
        let _missing_helper_state =
            crate::ingress::wide::macos::fixture_env::MissingHelperStateFixture::new();
        let cfg = Settings::default();
        let report = IngressStartupReport::build(&cfg).expect("report");
        let rendered = report.render_json_with_runtime_checks(
            &cfg,
            &[RuntimeProbeCheck {
                target: "socks.listen",
                code: RuntimeProbeCode::ListenerConflict,
                severity: RuntimeProbeSeverity::Fail,
                fatal: true,
                message: "SOCKS5 fallback bind probe failed".to_string(),
            }],
        );
        assert!(rendered.contains("\"code\": \"listener_conflict\""));
    }

    #[test]
    fn selection_error_json_contains_hint() {
        let mut cfg = Settings::default();
        cfg.ingress.allow_fallback = false;
        cfg.ingress.wide.enabled = false;
        let err = IngressStartupReport::build(&cfg).unwrap_err();
        let rendered = err.render_json(&cfg);
        assert!(rendered.contains("\"status\": \"error\""));
        assert!(rendered.contains("\"selection_error_code\": \"wide_disabled_in_config\""));
        assert!(rendered
            .contains("\"selection_hint_code\": \"enable_wide_or_switch_primary_to_socks5\""));
        assert!(rendered.contains("\"selection_error\""));
        assert!(rendered
            .contains("\"hint\": \"enable [ingress.wide] or switch ingress.primary to socks5\""));
        assert!(rendered.contains("\"wide_rollout_profile\": \"output_only_safe\""));
        assert!(rendered.contains("\"wide_prerouting_interface_candidate\": null"));
        assert!(rendered.contains("\"wide_udp_capture_contract_requested\": null"));
        assert!(rendered.contains("\"wide_udp_capture_support_tier_requested\": null"));
        assert!(rendered.contains("\"wide_udp_capture_contract\": null"));
        assert!(rendered.contains("\"wide_udp_capture_support_tier\": null"));
        assert!(rendered.contains("\"wide_udp_capture_runtime_scope\": null"));
        assert!(rendered.contains("\"wide_dns_port\": 53"));
        assert!(rendered.contains("\"wide_udp_preview_ports\": []"));
        assert!(rendered.contains("\"wide_runtime_readiness\": \"disabled\""));
        assert!(!rendered.contains("\"linux_validation_bootstrap_check_command\""));
        assert!(!rendered.contains("\"linux_validation_bootstrap_install_command\""));
    }

    #[test]
    fn generic_udp_capture_contract_json_contains_requested_and_active_contract() {
        #[cfg(target_os = "macos")]
        let _missing_helper_state =
            crate::ingress::wide::macos::fixture_env::MissingHelperStateFixture::new();
        let mut cfg = Settings::default();
        cfg.ingress.wide.udp_capture_contract = WideUdpCaptureContract::GenericCaptureUnstable;
        let rendered = match IngressStartupReport::build(&cfg) {
            Ok(report) => report.render_json_with_runtime_checks(&cfg, &[]),
            Err(err) => err.render_json(&cfg),
        };
        assert!(rendered
            .contains("\"wide_udp_capture_contract_requested\": \"generic_capture_unstable\""));
        assert!(
            rendered.contains("\"wide_udp_capture_support_tier_requested\": \"guarded_unstable\"")
        );
        #[cfg(target_os = "linux")]
        assert!(rendered.contains("\"status\": \"ok\""));
        #[cfg(not(target_os = "linux"))]
        assert!(rendered.contains("\"wide_runtime_readiness\": \"unsupported_adapter\""));
        #[cfg(target_os = "linux")]
        assert!(rendered.contains("\"wide_udp_capture_contract\": \"generic_capture_unstable\""));
        #[cfg(not(target_os = "linux"))]
        assert!(rendered.contains("\"wide_udp_capture_contract\": null"));
        #[cfg(target_os = "linux")]
        assert!(rendered.contains("\"wide_udp_capture_support_tier\": \"guarded_unstable\""));
        #[cfg(not(target_os = "linux"))]
        assert!(rendered.contains("\"wide_udp_capture_support_tier\": null"));
        #[cfg(target_os = "linux")]
        assert!(rendered
            .contains("\"wide_udp_capture_policy\": \"any_target_port_linux_ipv4_unstable\""));
        #[cfg(not(target_os = "linux"))]
        assert!(rendered.contains("\"wide_udp_capture_policy\": null"));
        #[cfg(target_os = "linux")]
        assert!(rendered.contains("\"wide_udp_capture_runtime_scope\": \"linux_ipv4_only\""));
        #[cfg(not(target_os = "linux"))]
        assert!(rendered.contains("\"wide_udp_capture_runtime_scope\": null"));
        assert!(rendered.contains("\"wide_runtime_readiness\":"));
    }

    #[test]
    fn ipv6_generic_udp_capture_contract_json_contains_ipv6_scope() {
        #[cfg(target_os = "macos")]
        let _missing_helper_state =
            crate::ingress::wide::macos::fixture_env::MissingHelperStateFixture::new();
        let mut cfg = Settings::default();
        cfg.ingress.wide.listen = "[::]:15080".parse().expect("listen");
        cfg.ingress.wide.udp_capture_contract = WideUdpCaptureContract::GenericCaptureUnstable;
        let rendered = match IngressStartupReport::build(&cfg) {
            Ok(report) => report.render_json_with_runtime_checks(&cfg, &[]),
            Err(err) => err.render_json(&cfg),
        };
        #[cfg(target_os = "linux")]
        assert!(rendered.contains("\"status\": \"ok\""));
        #[cfg(not(target_os = "linux"))]
        assert!(rendered.contains("\"wide_runtime_readiness\": \"unsupported_adapter\""));
        #[cfg(target_os = "linux")]
        assert!(rendered.contains("\"wide_udp_capture_contract\": \"generic_capture_unstable\""));
        #[cfg(not(target_os = "linux"))]
        assert!(rendered.contains("\"wide_udp_capture_contract\": null"));
        #[cfg(target_os = "linux")]
        assert!(rendered.contains("\"wide_udp_capture_support_tier\": \"guarded_unstable\""));
        #[cfg(not(target_os = "linux"))]
        assert!(rendered.contains("\"wide_udp_capture_support_tier\": null"));
        #[cfg(target_os = "linux")]
        assert!(rendered
            .contains("\"wide_udp_capture_policy\": \"any_target_port_linux_ipv6_unstable\""));
        #[cfg(not(target_os = "linux"))]
        assert!(rendered.contains("\"wide_udp_capture_policy\": null"));
        #[cfg(target_os = "linux")]
        assert!(rendered.contains("\"wide_udp_capture_runtime_scope\": \"linux_ipv6_only\""));
        #[cfg(not(target_os = "linux"))]
        assert!(rendered.contains("\"wide_udp_capture_runtime_scope\": null"));
    }

    #[test]
    fn rollout_profile_selection_error_json_contains_code() {
        let mut cfg = Settings::default();
        cfg.ingress.wide.platform_backend = WidePlatformBackend::LinuxTproxy;
        let err = IngressStartupReport::build(&cfg).unwrap_err();
        let rendered = err.render_json(&cfg);
        assert!(rendered.contains("\"selection_error_code\": \"rollout_profile_backend_mismatch\""));
        assert!(rendered.contains(
            "\"selection_hint_code\": \"use_redirect_backend_or_switch_rollout_profile\""
        ));
        assert!(rendered
            .contains("\"wide_udp_capture_contract_requested\": \"preview_allowlist_only\""));
        assert!(rendered.contains("\"wide_udp_capture_contract\": null"));
        assert!(rendered.contains("\"wide_udp_capture_policy\": null"));
        assert!(rendered.contains("\"wide_udp_capture_runtime_scope\": null"));
        assert!(rendered.contains("\"wide_rollout_profile\": \"output_only_safe\""));
        assert!(rendered.contains("\"wide_runtime_readiness\": \"config_error\""));
    }

    #[test]
    fn prerouting_scoped_json_contains_interface_scope() {
        #[cfg(target_os = "macos")]
        let _missing_helper_state =
            crate::ingress::wide::macos::fixture_env::MissingHelperStateFixture::new();
        let mut cfg = Settings::default();
        cfg.ingress.wide.rollout_profile = WideRolloutProfile::PreroutingScoped;
        cfg.ingress.wide.prerouting_interface = Some("eth0".to_string());
        cfg.ingress.wide.dns_port = 5353;
        cfg.ingress.wide.udp_preview_ports = vec![853];
        let rendered = match IngressStartupReport::build(&cfg) {
            Ok(report) => report.render_json_with_runtime_checks(&cfg, &[]),
            Err(err) => err.render_json(&cfg),
        };
        assert!(rendered.contains("\"wide_rollout_profile\": \"prerouting_scoped\""));
        assert!(rendered.contains("\"wide_prerouting_interface\": \"eth0\""));
        assert!(rendered.contains("\"wide_prerouting_interface_candidate\": null"));
        #[cfg(target_os = "linux")]
        assert!(rendered.contains("\"wide_udp_capture_contract\": \"preview_allowlist_only\""));
        #[cfg(not(target_os = "linux"))]
        assert!(rendered.contains("\"wide_udp_capture_contract\": null"));
        #[cfg(target_os = "linux")]
        assert!(rendered.contains("\"wide_udp_capture_support_tier\": \"supported_preview\""));
        #[cfg(not(target_os = "linux"))]
        assert!(rendered.contains("\"wide_udp_capture_support_tier\": null"));
        #[cfg(target_os = "linux")]
        assert!(rendered.contains("\"wide_udp_capture_runtime_scope\": \"linux_ipv4_only\""));
        #[cfg(not(target_os = "linux"))]
        assert!(rendered.contains("\"wide_udp_capture_runtime_scope\": null"));
        assert!(rendered.contains("\"wide_dns_port\": 5353"));
        assert!(rendered.contains("\"wide_udp_preview_ports\": ["));
        assert!(rendered.contains("853"));
    }

    #[test]
    fn prerouting_scope_error_json_keeps_requested_contract_but_clears_effective_fields() {
        #[cfg(target_os = "macos")]
        let _missing_helper_state =
            crate::ingress::wide::macos::fixture_env::MissingHelperStateFixture::new();
        let mut cfg = Settings::default();
        cfg.ingress.wide.rollout_profile = WideRolloutProfile::PreroutingScoped;
        let err = IngressStartupReport::build(&cfg).unwrap_err();
        let rendered = err.render_json(&cfg);
        assert!(rendered.contains("\"selection_error_code\": \"rollout_profile_prerequisites\""));
        assert!(rendered.contains(
            "\"selection_hint_code\": \"set_prerouting_interface_or_switch_rollout_profile\""
        ));
        assert!(rendered
            .contains("\"wide_udp_capture_contract_requested\": \"preview_allowlist_only\""));
        assert!(rendered.contains("\"wide_udp_capture_contract\": null"));
        assert!(rendered.contains("\"wide_udp_capture_policy\": null"));
        assert!(rendered.contains("\"wide_udp_capture_runtime_scope\": null"));
        assert!(rendered.contains("\"wide_prerouting_interface_candidate\":"));
    }

    #[tokio::test]
    async fn startup_probe_reports_socks_backend_started() {
        let mut cfg = Settings::default();
        cfg.ingress.primary = IngressPrimary::Socks5;
        cfg.socks.listen = "127.0.0.1:0".parse().unwrap();
        let report = IngressStartupReport::build(&cfg).expect("report");
        let startup = report.probe_runtime_startup(&cfg).await;
        assert_eq!(startup.status(), StartupProbeStatus::Ok);
        assert_eq!(startup.code, StartupProbeCode::Socks5FallbackStarted);
        assert_eq!(startup.started_backend, Some("socks5_fallback"));
        assert_eq!(startup.failure_code, None);
        assert_eq!(startup.hint_code, None);
        assert_eq!(startup.wide_dns_capture_preview_status, None);
        assert_eq!(startup.wide_dns_capture_preview_error_kind, None);
        assert_eq!(startup.wide_dns_capture_preview_error, None);
        assert_eq!(startup.wide_udp_capture_contract, None);
        assert_eq!(startup.wide_udp_capture_support_tier, None);
        assert_eq!(startup.wide_udp_capture_policy, None);
        assert_eq!(startup.wide_udp_capture_runtime_scope, None);
        assert_eq!(startup.wide_udp_preview_policy, None);
        assert!(startup.wide_udp_preview_ports.is_empty());
    }

    #[test]
    fn startup_probe_existing_listener_codes_are_operator_ok() {
        let wide_existing = StartupProbeResult {
            code: StartupProbeCode::WidePrimaryAlreadyRunning,
            started_backend: Some("wide_primary"),
            failure_code: Some(RuntimeProbeCode::ListenerBusy),
            hint_code: None,
            wide_dns_capture_preview_status: None,
            wide_dns_capture_preview_error_kind: None,
            wide_dns_capture_preview_error: None,
            wide_udp_capture_contract: None,
            wide_udp_capture_support_tier: None,
            wide_udp_capture_policy: None,
            wide_udp_capture_runtime_scope: None,
            wide_udp_preview_policy: None,
            wide_udp_preview_ports: Vec::new(),
            message: "existing wide listener is already owned by aegis-client".to_string(),
            hint: None,
        };
        let socks_existing = StartupProbeResult {
            code: StartupProbeCode::Socks5FallbackAlreadyRunning,
            started_backend: Some("socks5_fallback"),
            failure_code: Some(RuntimeProbeCode::ListenerBusy),
            hint_code: None,
            wide_dns_capture_preview_status: None,
            wide_dns_capture_preview_error_kind: None,
            wide_dns_capture_preview_error: None,
            wide_udp_capture_contract: None,
            wide_udp_capture_support_tier: None,
            wide_udp_capture_policy: None,
            wide_udp_capture_runtime_scope: None,
            wide_udp_preview_policy: None,
            wide_udp_preview_ports: Vec::new(),
            message: "existing socks listener is already owned by aegis-client".to_string(),
            hint: None,
        };

        assert_eq!(wide_existing.status(), StartupProbeStatus::Ok);
        assert!(!wide_existing.is_fatal());
        assert_eq!(socks_existing.status(), StartupProbeStatus::Ok);
        assert!(!socks_existing.is_fatal());
    }

    #[tokio::test]
    async fn startup_probe_reports_socks_bind_failure() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("listener");
        let busy_addr = listener.local_addr().expect("local addr");
        let mut cfg = Settings::default();
        cfg.ingress.primary = IngressPrimary::Socks5;
        cfg.socks.listen = busy_addr;
        let report = IngressStartupReport::build(&cfg).expect("report");
        let startup = report.probe_runtime_startup(&cfg).await;
        assert_eq!(startup.status(), StartupProbeStatus::Error);
        assert_eq!(startup.code, StartupProbeCode::SocksBindFailed);
        assert_eq!(startup.started_backend, None);
        assert_eq!(startup.failure_code, Some(RuntimeProbeCode::ListenerBusy));
        assert_eq!(
            startup.hint_code,
            Some(StartupHintCode::VerifySocksListenIsFree)
        );
    }

    #[tokio::test]
    async fn startup_probe_reports_fallback_started_after_wide_bind_failure() {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("listener");
        let busy_addr = listener.local_addr().expect("local addr");
        let mut cfg = Settings::default();
        cfg.ingress.allow_fallback = true;
        cfg.ingress.wide.listen = busy_addr;
        cfg.socks.listen = "127.0.0.1:0".parse().unwrap();
        #[cfg(target_os = "linux")]
        {
            cfg.ingress.wide.platform_backend = WidePlatformBackend::LinuxRedirect;
        }
        let report = IngressStartupReport::build(&cfg).expect("report");
        let startup = report.probe_runtime_startup(&cfg).await;
        #[cfg(target_os = "linux")]
        {
            assert_eq!(startup.status(), StartupProbeStatus::Degraded);
            assert_eq!(
                startup.code,
                StartupProbeCode::WideBindFailedFallbackStarted
            );
            assert_eq!(startup.started_backend, Some("socks5_fallback"));
            assert_eq!(startup.failure_code, Some(RuntimeProbeCode::ListenerBusy));
            assert_eq!(
                startup.hint_code,
                Some(StartupHintCode::VerifyWideListenIsFree)
            );
            assert_eq!(startup.wide_dns_capture_preview_status, None);
            assert_eq!(startup.wide_dns_capture_preview_error_kind, None);
            assert_eq!(startup.wide_dns_capture_preview_error, None);
            assert_eq!(startup.wide_udp_capture_contract, None);
            assert_eq!(startup.wide_udp_capture_support_tier, None);
            assert_eq!(startup.wide_udp_capture_policy, None);
            assert_eq!(startup.wide_udp_capture_runtime_scope, None);
            assert_eq!(startup.wide_udp_preview_policy, None);
            assert!(startup.wide_udp_preview_ports.is_empty());
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert_eq!(
                report.backend_choice(),
                ActiveIngressBackend::Socks5Fallback
            );
            assert_eq!(startup.status(), StartupProbeStatus::Ok);
            assert_eq!(startup.code, StartupProbeCode::Socks5FallbackStarted);
            assert_eq!(startup.started_backend, Some("socks5_fallback"));
            assert_eq!(startup.failure_code, None);
            assert_eq!(startup.hint_code, None);
        }
    }

    #[tokio::test]
    async fn startup_probe_reports_socks_fallback_for_macos_pf_contract() {
        #[cfg(target_os = "macos")]
        let _missing_helper_state =
            crate::ingress::wide::macos::fixture_env::MissingHelperStateFixture::new();
        let mut cfg = Settings::default();
        cfg.ingress.allow_fallback = true;
        cfg.ingress.wide.platform_backend = WidePlatformBackend::MacosPf;
        cfg.socks.listen = "127.0.0.1:0".parse().unwrap();
        let report = IngressStartupReport::build(&cfg).expect("report");
        let startup = report.probe_runtime_startup(&cfg).await;
        assert_eq!(startup.status(), StartupProbeStatus::Ok);
        assert_eq!(startup.code, StartupProbeCode::Socks5FallbackStarted);
        assert_eq!(startup.started_backend, Some("socks5_fallback"));
        assert_eq!(startup.failure_code, None);
        assert_eq!(startup.hint_code, None);
        #[cfg(target_os = "macos")]
        assert!(report.wide_platform_family_supported());
        #[cfg(not(target_os = "macos"))]
        assert!(!report.wide_platform_family_supported());
        assert_eq!(
            report.wide_runtime_readiness(),
            WideRuntimeReadiness::UnsupportedAdapter
        );
        assert_eq!(
            report.fallback_reason_code(),
            Some(FallbackReasonCode::UnsupportedWideBackend)
        );
    }

    #[tokio::test]
    async fn startup_probe_reports_dns_preview_status_for_wide_backend() {
        #[cfg(target_os = "macos")]
        let _missing_helper_state =
            crate::ingress::wide::macos::fixture_env::MissingHelperStateFixture::new();
        let mut cfg = Settings::default();
        cfg.ingress.wide.listen = "127.0.0.1:0".parse().unwrap();
        cfg.ingress.wide.capture_dns = true;
        let report = IngressStartupReport::build(&cfg).expect("report");
        let startup = report.probe_runtime_startup(&cfg).await;
        #[cfg(target_os = "linux")]
        {
            assert_eq!(startup.status(), StartupProbeStatus::Ok);
            assert_eq!(startup.code, StartupProbeCode::WidePrimaryStarted);
            assert_eq!(startup.started_backend, Some("wide_primary"));
            assert_eq!(startup.wide_dns_capture_preview_status, Some("active"));
            assert_eq!(startup.wide_dns_capture_preview_error_kind, None);
            assert_eq!(startup.wide_dns_capture_preview_error, None);
            assert_eq!(
                startup.wide_udp_capture_contract,
                Some("preview_allowlist_only")
            );
            assert_eq!(
                startup.wide_udp_capture_support_tier,
                Some("supported_preview")
            );
            assert_eq!(startup.wide_udp_capture_policy, Some("allowlist_ports"));
            assert_eq!(
                startup.wide_udp_capture_runtime_scope,
                Some("linux_ipv4_only")
            );
            assert_eq!(startup.wide_udp_preview_policy, Some("allowlist_ports"));
            assert_eq!(startup.wide_udp_preview_ports, vec![53]);
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert_eq!(startup.wide_dns_capture_preview_status, None);
            assert_eq!(startup.wide_udp_capture_contract, None);
            assert_eq!(startup.wide_udp_capture_support_tier, None);
            assert_eq!(startup.wide_udp_capture_policy, None);
            assert_eq!(startup.wide_udp_capture_runtime_scope, None);
            assert_eq!(startup.wide_udp_preview_policy, None);
            assert!(startup.wide_udp_preview_ports.is_empty());
        }
    }

    #[tokio::test]
    async fn startup_probe_reports_ipv6_dns_preview_status_for_wide_backend() {
        #[cfg(target_os = "macos")]
        let _missing_helper_state =
            crate::ingress::wide::macos::fixture_env::MissingHelperStateFixture::new();
        let mut cfg = Settings::default();
        cfg.ingress.wide.listen = "[::1]:0".parse().unwrap();
        cfg.ingress.wide.capture_dns = true;
        let report = IngressStartupReport::build(&cfg).expect("report");
        let startup = report.probe_runtime_startup(&cfg).await;
        #[cfg(target_os = "linux")]
        {
            assert_eq!(startup.status(), StartupProbeStatus::Ok);
            assert_eq!(startup.code, StartupProbeCode::WidePrimaryStarted);
            assert_eq!(startup.started_backend, Some("wide_primary"));
            assert_eq!(startup.wide_dns_capture_preview_status, Some("active"));
            assert_eq!(startup.wide_dns_capture_preview_error_kind, None);
            assert_eq!(startup.wide_dns_capture_preview_error, None);
            assert_eq!(
                startup.wide_udp_capture_contract,
                Some("preview_allowlist_only")
            );
            assert_eq!(
                startup.wide_udp_capture_support_tier,
                Some("supported_preview")
            );
            assert_eq!(startup.wide_udp_capture_policy, Some("allowlist_ports"));
            assert_eq!(
                startup.wide_udp_capture_runtime_scope,
                Some("linux_ipv6_only")
            );
            assert_eq!(startup.wide_udp_preview_policy, Some("allowlist_ports"));
            assert_eq!(startup.wide_udp_preview_ports, vec![53]);
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert_eq!(startup.wide_dns_capture_preview_status, None);
            assert_eq!(startup.wide_udp_capture_contract, None);
            assert_eq!(startup.wide_udp_capture_support_tier, None);
            assert_eq!(startup.wide_udp_capture_policy, None);
            assert_eq!(startup.wide_udp_capture_runtime_scope, None);
            assert_eq!(startup.wide_udp_preview_policy, None);
            assert!(startup.wide_udp_preview_ports.is_empty());
        }
    }

    #[tokio::test]
    async fn startup_probe_reports_generic_udp_capture_status_for_wide_backend() {
        #[cfg(target_os = "macos")]
        let _missing_helper_state =
            crate::ingress::wide::macos::fixture_env::MissingHelperStateFixture::new();
        let mut cfg = Settings::default();
        cfg.ingress.wide.listen = "127.0.0.1:0".parse().unwrap();
        cfg.ingress.wide.capture_dns = true;
        cfg.ingress.wide.udp_capture_contract = WideUdpCaptureContract::GenericCaptureUnstable;
        let report = IngressStartupReport::build(&cfg).expect("report");
        let startup = report.probe_runtime_startup(&cfg).await;
        #[cfg(target_os = "linux")]
        {
            assert_eq!(startup.status(), StartupProbeStatus::Ok);
            assert_eq!(startup.code, StartupProbeCode::WidePrimaryStarted);
            assert_eq!(startup.started_backend, Some("wide_primary"));
            assert_eq!(
                startup.wide_udp_capture_contract,
                Some("generic_capture_unstable")
            );
            assert_eq!(
                startup.wide_udp_capture_support_tier,
                Some("guarded_unstable")
            );
            assert_eq!(
                startup.wide_udp_capture_policy,
                Some("any_target_port_linux_ipv4_unstable")
            );
            assert_eq!(
                startup.wide_udp_capture_runtime_scope,
                Some("linux_ipv4_only")
            );
            assert_eq!(startup.wide_udp_preview_policy, None);
            assert!(startup.wide_udp_preview_ports.is_empty());
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert_eq!(startup.wide_udp_capture_contract, None);
            assert_eq!(startup.wide_udp_capture_support_tier, None);
            assert_eq!(startup.wide_udp_capture_policy, None);
            assert_eq!(startup.wide_udp_capture_runtime_scope, None);
            assert_eq!(startup.wide_udp_preview_policy, None);
            assert!(startup.wide_udp_preview_ports.is_empty());
        }
    }

    #[tokio::test]
    async fn startup_probe_reports_ipv6_udp_capture_status_for_wide_backend() {
        #[cfg(target_os = "macos")]
        let _missing_helper_state =
            crate::ingress::wide::macos::fixture_env::MissingHelperStateFixture::new();
        let mut cfg = Settings::default();
        cfg.ingress.wide.listen = "[::1]:0".parse().unwrap();
        cfg.ingress.wide.capture_dns = true;
        cfg.ingress.wide.udp_capture_contract = WideUdpCaptureContract::GenericCaptureUnstable;
        let report = IngressStartupReport::build(&cfg).expect("report");
        let startup = report.probe_runtime_startup(&cfg).await;
        #[cfg(target_os = "linux")]
        {
            assert_eq!(startup.status(), StartupProbeStatus::Ok);
            assert_eq!(startup.code, StartupProbeCode::WidePrimaryStarted);
            assert_eq!(startup.started_backend, Some("wide_primary"));
            assert_eq!(startup.wide_dns_capture_preview_status, Some("active"));
            assert_eq!(
                startup.wide_udp_capture_contract,
                Some("generic_capture_unstable")
            );
            assert_eq!(
                startup.wide_udp_capture_support_tier,
                Some("guarded_unstable")
            );
            assert_eq!(
                startup.wide_udp_capture_policy,
                Some("any_target_port_linux_ipv6_unstable")
            );
            assert_eq!(
                startup.wide_udp_capture_runtime_scope,
                Some("linux_ipv6_only")
            );
            assert_eq!(startup.wide_udp_preview_policy, None);
            assert!(startup.wide_udp_preview_ports.is_empty());
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert_eq!(startup.wide_udp_capture_contract, None);
            assert_eq!(startup.wide_udp_capture_support_tier, None);
            assert_eq!(startup.wide_udp_capture_policy, None);
            assert_eq!(startup.wide_udp_capture_runtime_scope, None);
            assert_eq!(startup.wide_udp_preview_policy, None);
            assert!(startup.wide_udp_preview_ports.is_empty());
        }
    }

    #[tokio::test]
    async fn runtime_readiness_probe_reports_dns_preview_check() {
        #[cfg(target_os = "macos")]
        let _missing_helper_state =
            crate::ingress::wide::macos::fixture_env::MissingHelperStateFixture::new();
        let mut cfg = Settings::default();
        cfg.ingress.wide.listen = "127.0.0.1:0".parse().unwrap();
        cfg.ingress.wide.capture_dns = true;
        let report = IngressStartupReport::build(&cfg).expect("report");
        let checks = report.probe_runtime_readiness(&cfg).await;
        #[cfg(target_os = "linux")]
        {
            assert!(checks.iter().any(|check| {
                check.target == "wide.dns_preview"
                    && check.code == RuntimeProbeCode::WideDnsPreviewActive
                    && check.severity == RuntimeProbeSeverity::Pass
                    && !check.fatal
            }));
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert!(!checks
                .iter()
                .any(|check| check.target == "wide.dns_preview"));
        }
    }

    #[test]
    fn startup_probe_json_contains_structured_runtime_fields() {
        #[cfg(target_os = "macos")]
        let _missing_helper_state =
            crate::ingress::wide::macos::fixture_env::MissingHelperStateFixture::new();
        let cfg = Settings::default();
        let report = IngressStartupReport::build(&cfg).expect("report");
        let startup = StartupProbeResult {
            code: StartupProbeCode::WideBindFailedFallbackStarted,
            started_backend: Some("socks5_fallback"),
            failure_code: Some(RuntimeProbeCode::ListenerBusy),
            hint_code: Some(StartupHintCode::VerifyWideListenIsFree),
            wide_dns_capture_preview_status: Some("bind_failed"),
            wide_dns_capture_preview_error_kind: Some("addr_in_use"),
            wide_dns_capture_preview_error: Some("Address already in use".to_string()),
            wide_udp_capture_contract: Some("preview_allowlist_only"),
            wide_udp_capture_support_tier: Some("supported_preview"),
            wide_udp_capture_policy: Some("allowlist_ports"),
            wide_udp_capture_runtime_scope: Some("linux_ipv4_only"),
            wide_udp_preview_policy: Some("allowlist_ports"),
            wide_udp_preview_ports: vec![53, 853],
            hint: Some("verify that the configured wide listen address/port is free"),
            message: "wide startup failed; fallback started".to_string(),
        };
        let rendered = report.render_startup_probe_json(&cfg, &startup);
        assert!(rendered.contains("\"status\": \"degraded\""));
        assert!(rendered.contains("\"code\": \"wide_bind_failed_fallback_started\""));
        assert!(rendered.contains("\"started_backend\": \"socks5_fallback\""));
        assert!(rendered.contains("\"failure_code\": \"listener_busy\""));
        assert!(rendered.contains("\"hint_code\": \"verify_wide_listen_is_free\""));
        assert!(rendered.contains("\"wide_runtime_readiness\""));
        assert!(rendered.contains("\"wide_dns_capture_preview_status\": \"bind_failed\""));
        assert!(rendered.contains("\"wide_dns_capture_preview_error_kind\": \"addr_in_use\""));
        assert!(rendered.contains("\"wide_udp_capture_contract\": \"preview_allowlist_only\""));
        assert!(rendered.contains("\"wide_udp_capture_support_tier\": \"supported_preview\""));
        assert!(rendered.contains("\"wide_udp_capture_policy\": \"allowlist_ports\""));
        assert!(rendered.contains("\"wide_udp_capture_runtime_scope\": \"linux_ipv4_only\""));
        assert!(rendered.contains("\"wide_udp_preview_policy\": \"allowlist_ports\""));
        assert!(rendered.contains("\"wide_dns_port\": 53"));
        assert!(rendered.contains("\"wide_udp_preview_ports\": ["));
        assert!(rendered.contains("853"));
        #[cfg(target_os = "linux")]
        {
            assert!(rendered.contains(
                "\"linux_validation_bootstrap_check_command\": \"bash scripts/bootstrap-wide-linux-validation-host.sh --check --json\""
            ));
            assert!(rendered.contains(
                "\"linux_validation_bootstrap_install_command\": \"bash scripts/bootstrap-wide-linux-validation-host.sh --install\""
            ));
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert!(!rendered.contains("\"linux_validation_bootstrap_check_command\""));
            assert!(!rendered.contains("\"linux_validation_bootstrap_install_command\""));
        }
    }

    #[test]
    fn startup_probe_text_uses_machine_readable_codes() {
        #[cfg(target_os = "macos")]
        let _missing_helper_state =
            crate::ingress::wide::macos::fixture_env::MissingHelperStateFixture::new();
        let cfg = Settings::default();
        let report = IngressStartupReport::build(&cfg).expect("report");
        let startup = StartupProbeResult {
            code: StartupProbeCode::WideBindFailedFallbackStarted,
            started_backend: Some("socks5_fallback"),
            failure_code: Some(RuntimeProbeCode::ListenerBusy),
            hint_code: Some(StartupHintCode::VerifyWideListenIsFree),
            wide_dns_capture_preview_status: None,
            wide_dns_capture_preview_error_kind: None,
            wide_dns_capture_preview_error: None,
            wide_udp_capture_contract: None,
            wide_udp_capture_support_tier: None,
            wide_udp_capture_policy: None,
            wide_udp_capture_runtime_scope: None,
            wide_udp_preview_policy: None,
            wide_udp_preview_ports: vec![],
            hint: Some("verify that the configured wide listen address/port is free"),
            message: "wide startup failed; fallback started".to_string(),
        };
        let rendered = report.render_startup_probe_text(&cfg, &startup);
        assert!(rendered.contains("requested_primary: wide"));
        assert!(rendered.contains(&format!("selected_backend: {}", default_backend_name())));
        assert!(rendered.contains(&format!(
            "wide_runtime_readiness: {}",
            match default_wide_runtime_readiness() {
                WideRuntimeReadiness::Disabled => "disabled",
                WideRuntimeReadiness::Ready => "ready",
                WideRuntimeReadiness::NeedsPrivilege => "needs_privilege",
                WideRuntimeReadiness::BoundaryOnly => "boundary_only",
                WideRuntimeReadiness::PreparedBoundary => "prepared_boundary",
                WideRuntimeReadiness::UnsupportedAdapter => "unsupported_adapter",
                WideRuntimeReadiness::ConfigError => "config_error",
            }
        )));
        assert!(rendered.contains("wide_platform: auto"));
        assert!(rendered.contains("wide_rollout_profile: output_only_safe"));
        #[cfg(target_os = "linux")]
        {
            assert!(rendered.contains(
                "linux_validation_bootstrap_check_command: bash scripts/bootstrap-wide-linux-validation-host.sh --check --json"
            ));
            assert!(rendered.contains(
                "linux_validation_bootstrap_install_command: bash scripts/bootstrap-wide-linux-validation-host.sh --install"
            ));
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert!(!rendered.contains("linux_validation_bootstrap_check_command:"));
            assert!(!rendered.contains("linux_validation_bootstrap_install_command:"));
        }
        assert!(rendered.contains("code: wide_bind_failed_fallback_started"));
        assert!(rendered.contains("failure_code: listener_busy"));
        assert!(rendered.contains("hint_code: verify_wide_listen_is_free"));
        assert!(!rendered.contains("WideBindFailedFallbackStarted"));
        assert!(!rendered.contains("ListenerBusy"));
        assert!(!rendered.contains("VerifyWideListenIsFree"));
    }

    #[test]
    fn startup_probe_omits_linux_bootstrap_handoff_for_socks5_primary() {
        let mut cfg = Settings::default();
        cfg.ingress.primary = IngressPrimary::Socks5;
        let report = IngressStartupReport::build(&cfg).expect("report");
        let startup = StartupProbeResult {
            code: StartupProbeCode::Socks5FallbackStarted,
            started_backend: Some("socks5_fallback"),
            failure_code: None,
            hint_code: None,
            wide_dns_capture_preview_status: None,
            wide_dns_capture_preview_error_kind: None,
            wide_dns_capture_preview_error: None,
            wide_udp_capture_contract: None,
            wide_udp_capture_support_tier: None,
            wide_udp_capture_policy: None,
            wide_udp_capture_runtime_scope: None,
            wide_udp_preview_policy: None,
            wide_udp_preview_ports: vec![],
            hint: None,
            message: "socks5 fallback listener started".to_string(),
        };
        let rendered_json = report.render_startup_probe_json(&cfg, &startup);
        let rendered_text = report.render_startup_probe_text(&cfg, &startup);
        assert!(rendered_json.contains("\"requested_primary\": \"socks5\""));
        assert!(rendered_json
            .contains("\"wide_udp_capture_contract_requested\": \"preview_allowlist_only\""));
        assert!(rendered_json
            .contains("\"wide_udp_capture_support_tier_requested\": \"supported_preview\""));
        assert!(rendered_json.contains("\"wide_udp_capture_contract\": null"));
        assert!(rendered_json.contains("\"wide_udp_capture_support_tier\": null"));
        assert!(rendered_json.contains("\"wide_udp_capture_policy\": null"));
        assert!(rendered_json.contains("\"wide_udp_capture_runtime_scope\": null"));
        assert!(!rendered_json.contains("\"linux_validation_bootstrap_check_command\""));
        assert!(!rendered_json.contains("\"linux_validation_bootstrap_install_command\""));
        assert!(rendered_text.contains("requested_primary: socks5"));
        assert!(
            rendered_text.contains("wide_udp_capture_contract_requested: preview_allowlist_only")
        );
        assert!(
            rendered_text.contains("wide_udp_capture_support_tier_requested: supported_preview")
        );
        assert!(rendered_text.contains("wide_udp_capture_contract: none"));
        assert!(rendered_text.contains("wide_udp_capture_support_tier: none"));
        assert!(rendered_text.contains("wide_udp_capture_policy: none"));
        assert!(rendered_text.contains("wide_udp_capture_runtime_scope: none"));
        assert!(!rendered_text.contains("linux_validation_bootstrap_check_command:"));
        assert!(!rendered_text.contains("linux_validation_bootstrap_install_command:"));
        assert!(!rendered_text.contains("ingress.wide.capture_dns is configured"));
        assert!(!rendered_text
            .contains("wide auto backend keeps redirect-compatible startup semantics"));
    }
}
