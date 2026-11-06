use super::helpers::{
    linux_validation_bootstrap_check_command, linux_validation_bootstrap_install_command,
};
use super::{
    active_backend_name, active_udp_capture_contract, active_udp_capture_policy,
    active_udp_capture_runtime_scope, active_udp_capture_support_tier, backend_notes,
    classify_bind_failure, classify_socks_bind_failure, configured_prerouting_interface,
    detected_prerouting_interface_candidate, ingress_primary_name, requested_udp_capture_contract,
    requested_udp_capture_support_tier, wide_platform_name, wide_rollout_profile_name,
    ActiveIngressBackend, IngressStartupReport, IngressStartupSelectionError, JsonErrorSelection,
    JsonPreflightError, JsonPreflightReport, JsonPreflightStatus, JsonSelection,
    JsonStartupProbeReport, PreflightSeverity, RuntimeProbeCheck, RuntimeProbeCode,
    RuntimeProbeSeverity, Settings, StartupProbeCode, StartupProbeResult, StartupProbeStatus,
};
use crate::ingress::IngressBackend;
use crate::ingress::Socks5FallbackBackend;
#[cfg(target_os = "linux")]
use std::net::IpAddr;
use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(test)]
use std::sync::{Mutex, OnceLock};

#[cfg(test)]
static TEST_EXISTING_AEGIS_LISTENER_OVERRIDE: OnceLock<Mutex<Option<bool>>> = OnceLock::new();

fn render_code<T: serde::Serialize>(value: T) -> String {
    match serde_json::to_value(value).expect("serialize preflight code value") {
        serde_json::Value::String(value) => value,
        other => other.to_string(),
    }
}

fn push_optional_line(lines: &mut Vec<String>, label: &str, value: Option<&str>) {
    if let Some(value) = value {
        lines.push(format!("{label}: {value}"));
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn set_test_existing_aegis_listener_override(value: Option<bool>) {
    let slot = TEST_EXISTING_AEGIS_LISTENER_OVERRIDE.get_or_init(|| Mutex::new(None));
    *slot.lock().expect("test existing listener override lock") = value;
}

fn existing_aegis_client_listener(addr: SocketAddr) -> bool {
    #[cfg(test)]
    if let Some(value) = TEST_EXISTING_AEGIS_LISTENER_OVERRIDE
        .get()
        .and_then(|slot| *slot.lock().expect("test existing listener override lock"))
    {
        return value;
    }

    if !listener_accepts_connections(addr) {
        return false;
    }

    #[cfg(target_os = "linux")]
    {
        linux_listener_owned_by_aegis_client(addr)
    }

    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

fn listener_accepts_connections(addr: SocketAddr) -> bool {
    let mut candidates = vec![addr];
    match addr {
        SocketAddr::V4(v4) if v4.ip().is_unspecified() => {
            candidates.insert(
                0,
                SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, v4.port())),
            );
        }
        SocketAddr::V6(v6) if v6.ip().is_unspecified() => {
            candidates.insert(
                0,
                SocketAddr::V6(std::net::SocketAddrV6::new(
                    std::net::Ipv6Addr::LOCALHOST,
                    v6.port(),
                    0,
                    0,
                )),
            );
        }
        _ => {}
    }

    candidates.into_iter().any(|candidate| {
        match std::net::TcpStream::connect_timeout(
            &candidate,
            std::time::Duration::from_millis(250),
        ) {
            Ok(stream) => {
                let _ = stream.shutdown(std::net::Shutdown::Both);
                true
            }
            Err(_) => false,
        }
    })
}

#[cfg(target_os = "linux")]
fn linux_listener_owned_by_aegis_client(addr: SocketAddr) -> bool {
    let Some(expected_local) = proc_tcp_local_address(addr) else {
        return false;
    };
    let mut inodes = Vec::new();
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        collect_listener_inodes(table, &expected_local, &mut inodes);
    }
    if inodes.is_empty() {
        return false;
    }
    proc_has_aegis_client_inode(&inodes)
}

#[cfg(target_os = "linux")]
fn proc_tcp_local_address(addr: SocketAddr) -> Option<String> {
    match addr.ip() {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            Some(format!(
                "{:02X}{:02X}{:02X}{:02X}:{:04X}",
                octets[3],
                octets[2],
                octets[1],
                octets[0],
                addr.port()
            ))
        }
        IpAddr::V6(_) => None,
    }
}

#[cfg(target_os = "linux")]
fn collect_listener_inodes(table_path: &str, expected_local: &str, inodes: &mut Vec<String>) {
    let Ok(contents) = std::fs::read_to_string(table_path) else {
        return;
    };
    for line in contents.lines().skip(1) {
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() <= 9 {
            continue;
        }
        if parts[1] != expected_local || parts[3] != "0A" {
            continue;
        }
        inodes.push(parts[9].to_string());
    }
}

#[cfg(target_os = "linux")]
fn proc_has_aegis_client_inode(inodes: &[String]) -> bool {
    let Ok(proc_dir) = std::fs::read_dir("/proc") else {
        return false;
    };
    for entry in proc_dir.flatten() {
        let file_name = entry.file_name();
        if file_name
            .to_str()
            .map(|name| name.chars().all(|ch| ch.is_ascii_digit()))
            != Some(true)
        {
            continue;
        }
        let pid_path = entry.path();
        let fd_dir = pid_path.join("fd");
        let Ok(fds) = std::fs::read_dir(&fd_dir) else {
            continue;
        };
        let mut matched_inode = false;
        for fd in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd.path()) else {
                continue;
            };
            let target = target.to_string_lossy();
            if inodes
                .iter()
                .any(|inode| target == format!("socket:[{inode}]"))
            {
                matched_inode = true;
                break;
            }
        }
        if matched_inode && pid_looks_like_aegis_client(&pid_path) {
            return true;
        }
    }
    false
}

#[cfg(target_os = "linux")]
fn pid_looks_like_aegis_client(pid_path: &Path) -> bool {
    if let Ok(exe) = std::fs::read_link(pid_path.join("exe")) {
        if exe
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| name == "aegis-client")
            == Some(true)
        {
            return true;
        }
    }
    let Ok(cmdline) = std::fs::read(pid_path.join("cmdline")) else {
        return false;
    };
    cmdline
        .split(|byte| *byte == 0)
        .filter(|segment| !segment.is_empty())
        .filter_map(|segment| std::str::from_utf8(segment).ok())
        .any(|segment| segment.ends_with("/aegis-client") || segment == "aegis-client")
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::listener_accepts_connections;

    #[test]
    fn listener_accepts_connections_handles_unspecified_ipv4_listen() {
        let listener = std::net::TcpListener::bind("0.0.0.0:0").expect("bind wildcard listener");
        let addr = listener.local_addr().expect("wildcard listener addr");
        assert!(listener_accepts_connections(addr));
    }
}

fn wide_dns_preview_runtime_probe(
    status: crate::ingress::IngressBackendRuntimeStatus,
) -> Option<RuntimeProbeCheck> {
    let code = match status.wide_dns_capture_preview_status? {
        "active" => RuntimeProbeCode::WideDnsPreviewActive,
        "disabled" => RuntimeProbeCode::WideDnsPreviewDisabled,
        "unsupported_listen_family" => RuntimeProbeCode::WideDnsPreviewUnsupportedListenFamily,
        "bind_failed" => RuntimeProbeCode::WideDnsPreviewBindFailed,
        _ => return None,
    };
    let severity = match code {
        RuntimeProbeCode::WideDnsPreviewActive => RuntimeProbeSeverity::Pass,
        RuntimeProbeCode::WideDnsPreviewDisabled
        | RuntimeProbeCode::WideDnsPreviewUnsupportedListenFamily => RuntimeProbeSeverity::Warn,
        RuntimeProbeCode::WideDnsPreviewBindFailed => RuntimeProbeSeverity::Warn,
        _ => RuntimeProbeSeverity::Warn,
    };
    let fatal = false;
    let mut message = match code {
        RuntimeProbeCode::WideDnsPreviewActive => {
            "wide DNS preview socket is active for the current startup profile".to_string()
        }
        RuntimeProbeCode::WideDnsPreviewDisabled => {
            "wide DNS preview socket is disabled because capture_dns is off".to_string()
        }
        RuntimeProbeCode::WideDnsPreviewUnsupportedListenFamily => {
            "wide DNS preview socket is unavailable for the configured listen family".to_string()
        }
        RuntimeProbeCode::WideDnsPreviewBindFailed => {
            "wide DNS preview socket could not be initialized; narrow DNS preview will stay inactive for this startup".to_string()
        }
        _ => return None,
    };
    if let Some(error_kind) = status.wide_dns_capture_preview_error_kind {
        message.push_str(&format!(" (error_kind={error_kind})"));
    }
    if let Some(error) = status.wide_dns_capture_preview_error {
        message.push_str(&format!(": {error}"));
    }
    Some(RuntimeProbeCheck {
        target: "wide.dns_preview",
        code,
        severity,
        fatal,
        message,
    })
}

impl IngressStartupReport {
    pub fn render_text_with_runtime_checks(
        &self,
        cfg: &Settings,
        runtime_checks: &[RuntimeProbeCheck],
        verbose: bool,
    ) -> String {
        let mut lines = vec![
            "AEGIS ingress preflight".to_string(),
            String::new(),
            "[selection]".to_string(),
            format!("requested_primary: {}", ingress_primary_name(cfg)),
            format!(
                "selected_backend: {}",
                active_backend_name(self.backend_choice)
            ),
            format!("allow_fallback: {}", cfg.ingress.allow_fallback),
            format!("wide_enabled: {}", cfg.ingress.wide.enabled),
            format!("wide_supported: {}", self.wide_supported),
            format!(
                "wide_platform_family_supported: {}",
                self.wide_platform_family_supported
            ),
            format!(
                "wide_runtime_readiness: {}",
                render_code(self.wide_runtime_readiness)
            ),
            format!("wide_platform: {}", wide_platform_name(cfg)),
            format!("wide_rollout_profile: {}", wide_rollout_profile_name(cfg)),
            format!(
                "wide_prerouting_interface: {}",
                configured_prerouting_interface(cfg).unwrap_or("none")
            ),
            format!(
                "wide_prerouting_interface_candidate: {}",
                detected_prerouting_interface_candidate(cfg)
                    .as_deref()
                    .unwrap_or("none")
            ),
            format!("wide_listen: {}", cfg.ingress.wide.listen),
            format!(
                "wide_udp_capture_contract_requested: {}",
                requested_udp_capture_contract(cfg).unwrap_or("none")
            ),
            format!(
                "wide_udp_capture_support_tier_requested: {}",
                requested_udp_capture_support_tier(cfg).unwrap_or("none")
            ),
            format!(
                "wide_udp_capture_contract: {}",
                active_udp_capture_contract(cfg, Some(self.backend_choice)).unwrap_or("none")
            ),
            format!(
                "wide_udp_capture_support_tier: {}",
                active_udp_capture_support_tier(cfg, Some(self.backend_choice)).unwrap_or("none")
            ),
            format!(
                "wide_udp_capture_policy: {}",
                active_udp_capture_policy(cfg, Some(self.backend_choice)).unwrap_or("none")
            ),
            format!(
                "wide_udp_capture_runtime_scope: {}",
                active_udp_capture_runtime_scope(cfg, Some(self.backend_choice)).unwrap_or("none")
            ),
            format!(
                "wide_backend_current_stage: {}",
                self.wide_backend_current_stage(cfg).unwrap_or("none")
            ),
            format!(
                "wide_backend_scope_target: {}",
                self.wide_backend_scope_target(cfg).unwrap_or("none")
            ),
            format!(
                "wide_backend_reason_code: {}",
                self.wide_backend_reason_code(cfg).unwrap_or("none")
            ),
            format!("wide_dns_port: {}", cfg.ingress.wide.dns_port),
            format!(
                "wide_udp_preview_ports: {}",
                if cfg.ingress.wide.udp_preview_ports.is_empty() {
                    "none".to_string()
                } else {
                    cfg.ingress
                        .wide
                        .udp_preview_ports
                        .iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                }
            ),
            format!("socks_listen: {}", cfg.socks.listen),
        ];

        if let Some(reason_code) = self.fallback_reason_code {
            lines.push(format!(
                "fallback_reason_code: {}",
                render_code(reason_code)
            ));
        }
        if let Some(reason) = self.fallback_reason {
            lines.push(format!("fallback_reason: {}", reason));
        }
        push_optional_line(
            &mut lines,
            "linux_validation_bootstrap_check_command",
            linux_validation_bootstrap_check_command(cfg),
        );
        push_optional_line(
            &mut lines,
            "linux_validation_bootstrap_install_command",
            linux_validation_bootstrap_install_command(cfg),
        );

        lines.push(String::new());
        lines.push("[hints]".to_string());
        if self.hints.is_empty() {
            lines.push("(none)".to_string());
        } else {
            for hint in &self.hints {
                let level = match hint.severity {
                    PreflightSeverity::Info => "info",
                    PreflightSeverity::Warn => "warn",
                };
                lines.push(format!("- [{}] {}", level, hint.message));
            }
        }

        lines.push(String::new());
        lines.push("[runtime_checks]".to_string());
        if runtime_checks.is_empty() {
            lines.push("(not run)".to_string());
        } else {
            for check in runtime_checks {
                let level = match check.severity {
                    RuntimeProbeSeverity::Pass => "pass",
                    RuntimeProbeSeverity::Warn => "warn",
                    RuntimeProbeSeverity::Fail => "fail",
                };
                if verbose {
                    lines.push(format!(
                        "- [{}] {}: {} (fatal={})",
                        level, check.target, check.message, check.fatal
                    ));
                } else {
                    lines.push(format!("- [{}] {}: {}", level, check.target, check.message));
                }
            }
        }

        lines.join("\n")
    }

    pub fn render_json_with_runtime_checks(
        &self,
        cfg: &Settings,
        runtime_checks: &[RuntimeProbeCheck],
    ) -> String {
        serde_json::to_string_pretty(&JsonPreflightReport {
            status: JsonPreflightStatus::Ok,
            selection: JsonSelection {
                requested_primary: ingress_primary_name(cfg),
                selected_backend: active_backend_name(self.backend_choice),
                allow_fallback: cfg.ingress.allow_fallback,
                wide_enabled: cfg.ingress.wide.enabled,
                wide_supported: self.wide_supported,
                wide_platform_family_supported: self.wide_platform_family_supported,
                wide_runtime_readiness: self.wide_runtime_readiness,
                wide_platform: wide_platform_name(cfg),
                wide_rollout_profile: wide_rollout_profile_name(cfg),
                wide_prerouting_interface: configured_prerouting_interface(cfg),
                wide_prerouting_interface_candidate: detected_prerouting_interface_candidate(cfg),
                wide_listen: cfg.ingress.wide.listen.to_string(),
                wide_udp_capture_contract_requested: requested_udp_capture_contract(cfg),
                wide_udp_capture_support_tier_requested: requested_udp_capture_support_tier(cfg),
                wide_udp_capture_contract: active_udp_capture_contract(
                    cfg,
                    Some(self.backend_choice),
                ),
                wide_udp_capture_support_tier: active_udp_capture_support_tier(
                    cfg,
                    Some(self.backend_choice),
                ),
                wide_udp_capture_policy: active_udp_capture_policy(cfg, Some(self.backend_choice)),
                wide_udp_capture_runtime_scope: active_udp_capture_runtime_scope(
                    cfg,
                    Some(self.backend_choice),
                ),
                wide_backend_current_stage: self.wide_backend_current_stage(cfg),
                wide_backend_scope_target: self.wide_backend_scope_target(cfg),
                wide_backend_reason_code: self.wide_backend_reason_code(cfg),
                wide_dns_port: cfg.ingress.wide.dns_port,
                wide_udp_preview_ports: &cfg.ingress.wide.udp_preview_ports,
                socks_listen: cfg.socks.listen.to_string(),
                fallback_reason_code: self.fallback_reason_code,
                fallback_reason: self.fallback_reason,
                linux_validation_bootstrap_check_command: linux_validation_bootstrap_check_command(
                    cfg,
                ),
                linux_validation_bootstrap_install_command:
                    linux_validation_bootstrap_install_command(cfg),
                backend_notes: backend_notes(cfg),
            },
            hints: &self.hints,
            runtime_checks,
        })
        .expect("serialize ingress preflight json")
    }

    pub fn render_startup_probe_text(
        &self,
        cfg: &Settings,
        startup: &StartupProbeResult,
    ) -> String {
        let mut lines = vec![
            "AEGIS ingress startup probe".to_string(),
            String::new(),
            "[selection]".to_string(),
            format!("requested_primary: {}", ingress_primary_name(cfg)),
            format!(
                "selected_backend: {}",
                active_backend_name(self.backend_choice)
            ),
            format!("allow_fallback: {}", cfg.ingress.allow_fallback),
            format!("wide_enabled: {}", cfg.ingress.wide.enabled),
            format!("wide_supported: {}", self.wide_supported),
            format!(
                "wide_platform_family_supported: {}",
                self.wide_platform_family_supported
            ),
            format!(
                "wide_runtime_readiness: {}",
                render_code(self.wide_runtime_readiness)
            ),
            format!("wide_platform: {}", wide_platform_name(cfg)),
            format!("wide_rollout_profile: {}", wide_rollout_profile_name(cfg)),
            format!(
                "wide_prerouting_interface: {}",
                configured_prerouting_interface(cfg).unwrap_or("none")
            ),
            format!(
                "wide_prerouting_interface_candidate: {}",
                detected_prerouting_interface_candidate(cfg)
                    .as_deref()
                    .unwrap_or("none")
            ),
            format!("wide_listen: {}", cfg.ingress.wide.listen),
            format!(
                "wide_udp_capture_contract_requested: {}",
                requested_udp_capture_contract(cfg).unwrap_or("none")
            ),
            format!(
                "wide_udp_capture_support_tier_requested: {}",
                requested_udp_capture_support_tier(cfg).unwrap_or("none")
            ),
            format!(
                "wide_udp_capture_contract: {}",
                active_udp_capture_contract(cfg, Some(self.backend_choice)).unwrap_or("none")
            ),
            format!(
                "wide_udp_capture_support_tier: {}",
                active_udp_capture_support_tier(cfg, Some(self.backend_choice)).unwrap_or("none")
            ),
            format!(
                "wide_udp_capture_policy: {}",
                active_udp_capture_policy(cfg, Some(self.backend_choice)).unwrap_or("none")
            ),
            format!(
                "wide_udp_capture_runtime_scope: {}",
                active_udp_capture_runtime_scope(cfg, Some(self.backend_choice)).unwrap_or("none")
            ),
            format!(
                "wide_backend_current_stage: {}",
                self.wide_backend_current_stage(cfg).unwrap_or("none")
            ),
            format!(
                "wide_backend_scope_target: {}",
                self.wide_backend_scope_target(cfg).unwrap_or("none")
            ),
            format!(
                "wide_backend_reason_code: {}",
                self.wide_backend_reason_code(cfg).unwrap_or("none")
            ),
            format!("socks_listen: {}", cfg.socks.listen),
        ];

        if let Some(reason_code) = self.fallback_reason_code {
            lines.push(format!(
                "fallback_reason_code: {}",
                render_code(reason_code)
            ));
        }
        if let Some(reason) = self.fallback_reason {
            lines.push(format!("fallback_reason: {}", reason));
        }
        push_optional_line(
            &mut lines,
            "linux_validation_bootstrap_check_command",
            linux_validation_bootstrap_check_command(cfg),
        );
        push_optional_line(
            &mut lines,
            "linux_validation_bootstrap_install_command",
            linux_validation_bootstrap_install_command(cfg),
        );

        lines.push(String::new());
        lines.push("[hints]".to_string());
        if self.hints.is_empty() {
            lines.push("(none)".to_string());
        } else {
            for hint in &self.hints {
                let level = match hint.severity {
                    PreflightSeverity::Info => "info",
                    PreflightSeverity::Warn => "warn",
                };
                lines.push(format!("- [{}] {}", level, hint.message));
            }
        }

        lines.push(String::new());
        lines.push("[startup]".to_string());
        lines.push(format!("code: {}", render_code(startup.code)));
        lines.push(format!(
            "started_backend: {}",
            startup.started_backend.unwrap_or("none")
        ));
        if let Some(status) = startup.wide_dns_capture_preview_status {
            lines.push(format!("wide_dns_capture_preview_status: {}", status));
        }
        if let Some(error_kind) = startup.wide_dns_capture_preview_error_kind {
            lines.push(format!(
                "wide_dns_capture_preview_error_kind: {}",
                error_kind
            ));
        }
        if let Some(error) = &startup.wide_dns_capture_preview_error {
            lines.push(format!("wide_dns_capture_preview_error: {}", error));
        }
        if let Some(contract) = startup.wide_udp_capture_contract {
            lines.push(format!("wide_udp_capture_contract: {}", contract));
        }
        if let Some(tier) = startup.wide_udp_capture_support_tier {
            lines.push(format!("wide_udp_capture_support_tier: {}", tier));
        }
        if let Some(policy) = startup.wide_udp_capture_policy {
            lines.push(format!("wide_udp_capture_policy: {}", policy));
        }
        if let Some(scope) = startup.wide_udp_capture_runtime_scope {
            lines.push(format!("wide_udp_capture_runtime_scope: {}", scope));
        }
        if let Some(policy) = startup.wide_udp_preview_policy {
            lines.push(format!("wide_udp_preview_policy: {}", policy));
        }
        lines.push(format!(
            "wide_udp_preview_ports: {}",
            if startup.wide_udp_preview_ports.is_empty() {
                "none".to_string()
            } else {
                startup
                    .wide_udp_preview_ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            }
        ));
        if let Some(failure_code) = startup.failure_code {
            lines.push(format!("failure_code: {}", render_code(failure_code)));
        }
        if let Some(hint_code) = startup.hint_code {
            lines.push(format!("hint_code: {}", render_code(hint_code)));
        }
        if let Some(hint) = startup.hint {
            lines.push(format!("hint: {}", hint));
        }
        lines.push(format!("message: {}", startup.message));

        lines.join("\n")
    }

    pub fn render_startup_probe_json(
        &self,
        cfg: &Settings,
        startup: &StartupProbeResult,
    ) -> String {
        serde_json::to_string_pretty(&JsonStartupProbeReport {
            status: startup.status(),
            selection: JsonSelection {
                requested_primary: ingress_primary_name(cfg),
                selected_backend: active_backend_name(self.backend_choice),
                allow_fallback: cfg.ingress.allow_fallback,
                wide_enabled: cfg.ingress.wide.enabled,
                wide_supported: self.wide_supported,
                wide_platform_family_supported: self.wide_platform_family_supported,
                wide_runtime_readiness: self.wide_runtime_readiness,
                wide_platform: wide_platform_name(cfg),
                wide_rollout_profile: wide_rollout_profile_name(cfg),
                wide_prerouting_interface: configured_prerouting_interface(cfg),
                wide_prerouting_interface_candidate: detected_prerouting_interface_candidate(cfg),
                wide_listen: cfg.ingress.wide.listen.to_string(),
                wide_udp_capture_contract_requested: requested_udp_capture_contract(cfg),
                wide_udp_capture_support_tier_requested: requested_udp_capture_support_tier(cfg),
                wide_udp_capture_contract: active_udp_capture_contract(
                    cfg,
                    Some(self.backend_choice),
                ),
                wide_udp_capture_support_tier: active_udp_capture_support_tier(
                    cfg,
                    Some(self.backend_choice),
                ),
                wide_udp_capture_policy: active_udp_capture_policy(cfg, Some(self.backend_choice)),
                wide_udp_capture_runtime_scope: active_udp_capture_runtime_scope(
                    cfg,
                    Some(self.backend_choice),
                ),
                wide_backend_current_stage: self.wide_backend_current_stage(cfg),
                wide_backend_scope_target: self.wide_backend_scope_target(cfg),
                wide_backend_reason_code: self.wide_backend_reason_code(cfg),
                wide_dns_port: cfg.ingress.wide.dns_port,
                wide_udp_preview_ports: &cfg.ingress.wide.udp_preview_ports,
                socks_listen: cfg.socks.listen.to_string(),
                fallback_reason_code: self.fallback_reason_code,
                fallback_reason: self.fallback_reason,
                linux_validation_bootstrap_check_command: linux_validation_bootstrap_check_command(
                    cfg,
                ),
                linux_validation_bootstrap_install_command:
                    linux_validation_bootstrap_install_command(cfg),
                backend_notes: backend_notes(cfg),
            },
            hints: &self.hints,
            startup,
        })
        .expect("serialize ingress startup probe json")
    }

    pub async fn probe_runtime_readiness(&self, cfg: &Settings) -> Vec<RuntimeProbeCheck> {
        match self.backend_choice {
            ActiveIngressBackend::WidePrimary => self.probe_wide_startup_path(cfg).await,
            ActiveIngressBackend::Socks5Fallback => vec![probe_socks_listener(cfg).await],
        }
    }

    pub async fn probe_runtime_startup(&self, cfg: &Settings) -> StartupProbeResult {
        match self.backend_choice {
            ActiveIngressBackend::WidePrimary => {
                match crate::ingress::wide::WidePrimaryBackend::bind_with_relay(
                    cfg.ingress.wide.clone(),
                    Some(cfg.relay.clone()),
                )
                .await
                {
                    Ok(backend) => {
                        let status = backend.runtime_status();
                        backend.shutdown().await;
                        StartupProbeResult {
                            code: StartupProbeCode::WidePrimaryStarted,
                            started_backend: Some(active_backend_name(
                                ActiveIngressBackend::WidePrimary,
                            )),
                            failure_code: None,
                            hint_code: None,
                            wide_dns_capture_preview_status: status.wide_dns_capture_preview_status,
                            wide_dns_capture_preview_error_kind: status
                                .wide_dns_capture_preview_error_kind,
                            wide_dns_capture_preview_error: status.wide_dns_capture_preview_error,
                            wide_udp_capture_contract: status.wide_udp_capture_contract,
                            wide_udp_capture_support_tier: status.wide_udp_capture_support_tier,
                            wide_udp_capture_policy: status.wide_udp_capture_policy,
                            wide_udp_capture_runtime_scope: status.wide_udp_capture_runtime_scope,
                            wide_udp_preview_policy: status.wide_udp_preview_policy,
                            wide_udp_preview_ports: status.wide_udp_preview_ports,
                            hint: None,
                            message: format!(
                                "started wide_primary backend {} on {}",
                                wide_platform_name(cfg),
                                cfg.ingress.wide.listen
                            ),
                        }
                    }
                    Err(err) => {
                        let (failure_code, hint_code, hint) = classify_bind_failure(cfg, &err);
                        if failure_code == RuntimeProbeCode::ListenerBusy
                            && existing_aegis_client_listener(cfg.ingress.wide.listen)
                        {
                            StartupProbeResult {
                                code: StartupProbeCode::WidePrimaryAlreadyRunning,
                                started_backend: Some(active_backend_name(
                                    ActiveIngressBackend::WidePrimary,
                                )),
                                failure_code: Some(failure_code),
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
                                hint: None,
                                message: format!(
                                    "wide_primary listener on {} is already owned by an active aegis-client process; treat this probe as already-started rather than fallback/degraded",
                                    cfg.ingress.wide.listen
                                ),
                            }
                        } else if cfg.ingress.allow_fallback {
                            match Socks5FallbackBackend::bind(cfg.socks.listen).await {
                                Ok(_backend) => StartupProbeResult {
                                    code: StartupProbeCode::WideBindFailedFallbackStarted,
                                    started_backend: Some(active_backend_name(
                                        ActiveIngressBackend::Socks5Fallback,
                                    )),
                                    failure_code: Some(failure_code),
                                    hint_code: Some(hint_code),
                                    wide_dns_capture_preview_status: None,
                                    wide_dns_capture_preview_error_kind: None,
                                    wide_dns_capture_preview_error: None,
                                    wide_udp_capture_contract: None,
                                    wide_udp_capture_support_tier: None,
                                    wide_udp_capture_policy: None,
                                    wide_udp_capture_runtime_scope: None,
                                    wide_udp_preview_policy: None,
                                    wide_udp_preview_ports: Vec::new(),
                                    hint: Some(hint),
                                    message: format!(
                                        "wide_primary startup failed for {} on {}: {}. started SOCKS5 fallback on {}",
                                        wide_platform_name(cfg),
                                        cfg.ingress.wide.listen,
                                        err,
                                        cfg.socks.listen
                                    ),
                                },
                                Err(socks_err) => {
                                    let (socks_code, socks_hint_code, socks_hint) =
                                        classify_socks_bind_failure(cfg, &socks_err);
                                    StartupProbeResult {
                                        code: StartupProbeCode::SocksBindFailed,
                                        started_backend: None,
                                        failure_code: Some(socks_code),
                                        hint_code: Some(socks_hint_code),
                                        wide_dns_capture_preview_status: None,
                                        wide_dns_capture_preview_error_kind: None,
                                        wide_dns_capture_preview_error: None,
                                        wide_udp_capture_contract: None,
                                        wide_udp_capture_support_tier: None,
                                        wide_udp_capture_policy: None,
                                        wide_udp_capture_runtime_scope: None,
                                        wide_udp_preview_policy: None,
                                        wide_udp_preview_ports: Vec::new(),
                                        hint: Some(socks_hint),
                                        message: format!(
                                            "wide_primary startup failed for {} on {}: {}. SOCKS5 fallback also failed on {}: {}",
                                            wide_platform_name(cfg),
                                            cfg.ingress.wide.listen,
                                            err,
                                            cfg.socks.listen,
                                            socks_err
                                        ),
                                    }
                                }
                            }
                        } else {
                            StartupProbeResult {
                                code: StartupProbeCode::WideBindFailed,
                                started_backend: None,
                                failure_code: Some(failure_code),
                                hint_code: Some(hint_code),
                                wide_dns_capture_preview_status: None,
                                wide_dns_capture_preview_error_kind: None,
                                wide_dns_capture_preview_error: None,
                                wide_udp_capture_contract: None,
                                wide_udp_capture_support_tier: None,
                                wide_udp_capture_policy: None,
                                wide_udp_capture_runtime_scope: None,
                                wide_udp_preview_policy: None,
                                wide_udp_preview_ports: Vec::new(),
                                hint: Some(hint),
                                message: format!(
                                    "wide_primary startup failed for {} on {}: {}",
                                    wide_platform_name(cfg),
                                    cfg.ingress.wide.listen,
                                    err
                                ),
                            }
                        }
                    }
                }
            }
            ActiveIngressBackend::Socks5Fallback => {
                match Socks5FallbackBackend::bind(cfg.socks.listen).await {
                    Ok(_backend) => StartupProbeResult {
                        code: StartupProbeCode::Socks5FallbackStarted,
                        started_backend: Some(active_backend_name(
                            ActiveIngressBackend::Socks5Fallback,
                        )),
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
                        wide_udp_preview_ports: Vec::new(),
                        hint: None,
                        message: format!("started SOCKS5 fallback backend on {}", cfg.socks.listen),
                    },
                    Err(err) => {
                        let (failure_code, hint_code, hint) =
                            classify_socks_bind_failure(cfg, &err);
                        if failure_code == RuntimeProbeCode::ListenerBusy
                            && existing_aegis_client_listener(cfg.socks.listen)
                        {
                            StartupProbeResult {
                                code: StartupProbeCode::Socks5FallbackAlreadyRunning,
                                started_backend: Some(active_backend_name(
                                    ActiveIngressBackend::Socks5Fallback,
                                )),
                                failure_code: Some(failure_code),
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
                                hint: None,
                                message: format!(
                                    "SOCKS5 fallback listener on {} is already owned by an active aegis-client process; treat this probe as already-started",
                                    cfg.socks.listen
                                ),
                            }
                        } else {
                            StartupProbeResult {
                                code: StartupProbeCode::SocksBindFailed,
                                started_backend: None,
                                failure_code: Some(failure_code),
                                hint_code: Some(hint_code),
                                wide_dns_capture_preview_status: None,
                                wide_dns_capture_preview_error_kind: None,
                                wide_dns_capture_preview_error: None,
                                wide_udp_capture_contract: None,
                                wide_udp_capture_support_tier: None,
                                wide_udp_capture_policy: None,
                                wide_udp_capture_runtime_scope: None,
                                wide_udp_preview_policy: None,
                                wide_udp_preview_ports: Vec::new(),
                                hint: Some(hint),
                                message: format!(
                                    "SOCKS5 fallback startup failed on {}: {}",
                                    cfg.socks.listen, err
                                ),
                            }
                        }
                    }
                }
            }
        }
    }

    async fn probe_wide_startup_path(&self, cfg: &Settings) -> Vec<RuntimeProbeCheck> {
        match crate::ingress::wide::WidePrimaryBackend::bind_with_relay(
            cfg.ingress.wide.clone(),
            Some(cfg.relay.clone()),
        )
        .await
        {
            Ok(backend) => {
                let mut checks = vec![RuntimeProbeCheck {
                    target: "wide.listen",
                    code: RuntimeProbeCode::BindOk,
                    severity: RuntimeProbeSeverity::Pass,
                    fatal: false,
                    message: format!(
                        "wide backend {} can bind {}",
                        wide_platform_name(cfg),
                        cfg.ingress.wide.listen
                    ),
                }];
                if let Some(preview_check) =
                    wide_dns_preview_runtime_probe(backend.runtime_status())
                {
                    checks.push(preview_check);
                }
                backend.shutdown().await;
                if cfg.ingress.allow_fallback || cfg.ingress.wide.listen == cfg.socks.listen {
                    checks.push(probe_socks_listener(cfg).await);
                }
                checks
            }
            Err(err) if cfg.ingress.allow_fallback => {
                let (code, _hint_code, hint) = classify_bind_failure(cfg, &err);
                let mut checks = vec![RuntimeProbeCheck {
                    target: "wide.listen",
                    code,
                    severity: RuntimeProbeSeverity::Warn,
                    fatal: false,
                    message: format!(
                        "wide bind probe failed for {} on {}: {}. hint: {}",
                        wide_platform_name(cfg),
                        cfg.ingress.wide.listen,
                        err,
                        hint
                    ),
                }];
                let socks_check = probe_socks_listener(cfg).await;
                checks.push(socks_check);
                checks
            }
            Err(err) => {
                let (code, _hint_code, hint) = classify_bind_failure(cfg, &err);
                vec![RuntimeProbeCheck {
                    target: "wide.listen",
                    code,
                    severity: RuntimeProbeSeverity::Fail,
                    fatal: true,
                    message: format!(
                        "wide bind probe failed for {} on {}: {}. hint: {}",
                        wide_platform_name(cfg),
                        cfg.ingress.wide.listen,
                        err,
                        hint
                    ),
                }]
            }
        }
    }
}

impl StartupProbeResult {
    pub fn status(&self) -> StartupProbeStatus {
        match self.code {
            StartupProbeCode::WidePrimaryStarted
            | StartupProbeCode::WidePrimaryAlreadyRunning
            | StartupProbeCode::Socks5FallbackStarted
            | StartupProbeCode::Socks5FallbackAlreadyRunning => StartupProbeStatus::Ok,
            StartupProbeCode::WideBindFailedFallbackStarted => StartupProbeStatus::Degraded,
            StartupProbeCode::WideBindFailed | StartupProbeCode::SocksBindFailed => {
                StartupProbeStatus::Error
            }
        }
    }

    pub fn is_fatal(&self) -> bool {
        self.status() == StartupProbeStatus::Error
    }
}

impl IngressStartupSelectionError {
    pub fn render_text(&self, cfg: &Settings) -> String {
        let mut lines = vec![
            "AEGIS ingress preflight".to_string(),
            String::new(),
            "[selection]".to_string(),
            format!("requested_primary: {}", ingress_primary_name(cfg)),
            format!("allow_fallback: {}", cfg.ingress.allow_fallback),
            format!("wide_enabled: {}", cfg.ingress.wide.enabled),
            format!("wide_supported: {}", self.wide_supported),
            format!(
                "wide_platform_family_supported: {}",
                self.wide_platform_family_supported
            ),
            format!(
                "wide_runtime_readiness: {}",
                render_code(self.wide_runtime_readiness)
            ),
            format!("wide_platform: {}", wide_platform_name(cfg)),
            format!("wide_rollout_profile: {}", wide_rollout_profile_name(cfg)),
            format!(
                "wide_prerouting_interface: {}",
                configured_prerouting_interface(cfg).unwrap_or("none")
            ),
            format!(
                "wide_prerouting_interface_candidate: {}",
                detected_prerouting_interface_candidate(cfg)
                    .as_deref()
                    .unwrap_or("none")
            ),
            format!("wide_listen: {}", cfg.ingress.wide.listen),
            format!(
                "wide_udp_capture_contract_requested: {}",
                requested_udp_capture_contract(cfg).unwrap_or("none")
            ),
            format!(
                "wide_udp_capture_support_tier_requested: {}",
                requested_udp_capture_support_tier(cfg).unwrap_or("none")
            ),
            format!(
                "wide_udp_capture_contract: {}",
                active_udp_capture_contract(cfg, None).unwrap_or("none")
            ),
            format!(
                "wide_udp_capture_support_tier: {}",
                active_udp_capture_support_tier(cfg, None).unwrap_or("none")
            ),
            format!(
                "wide_udp_capture_policy: {}",
                active_udp_capture_policy(cfg, None).unwrap_or("none")
            ),
            format!(
                "wide_udp_capture_runtime_scope: {}",
                active_udp_capture_runtime_scope(cfg, None).unwrap_or("none")
            ),
            format!(
                "wide_backend_current_stage: {}",
                self.wide_backend_current_stage(cfg).unwrap_or("none")
            ),
            format!(
                "wide_backend_scope_target: {}",
                self.wide_backend_scope_target(cfg).unwrap_or("none")
            ),
            format!(
                "wide_backend_reason_code: {}",
                self.wide_backend_reason_code(cfg).unwrap_or("none")
            ),
            format!("wide_dns_port: {}", cfg.ingress.wide.dns_port),
            format!(
                "wide_udp_preview_ports: {}",
                if cfg.ingress.wide.udp_preview_ports.is_empty() {
                    "none".to_string()
                } else {
                    cfg.ingress
                        .wide
                        .udp_preview_ports
                        .iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                }
            ),
            format!("socks_listen: {}", cfg.socks.listen),
        ];
        push_optional_line(
            &mut lines,
            "linux_validation_bootstrap_check_command",
            linux_validation_bootstrap_check_command(cfg),
        );
        push_optional_line(
            &mut lines,
            "linux_validation_bootstrap_install_command",
            linux_validation_bootstrap_install_command(cfg),
        );
        lines.push(format!("selection_error: {}", self.message));
        lines.push(format!("hint: {}", self.hint));
        lines.join("\n")
    }

    pub fn render_json(&self, cfg: &Settings) -> String {
        serde_json::to_string_pretty(&JsonPreflightError {
            status: JsonPreflightStatus::Error,
            selection: JsonErrorSelection {
                requested_primary: ingress_primary_name(cfg),
                allow_fallback: cfg.ingress.allow_fallback,
                wide_enabled: cfg.ingress.wide.enabled,
                wide_supported: self.wide_supported,
                wide_platform_family_supported: self.wide_platform_family_supported,
                wide_runtime_readiness: self.wide_runtime_readiness,
                wide_platform: wide_platform_name(cfg),
                wide_rollout_profile: wide_rollout_profile_name(cfg),
                wide_prerouting_interface: configured_prerouting_interface(cfg),
                wide_prerouting_interface_candidate: detected_prerouting_interface_candidate(cfg),
                wide_listen: cfg.ingress.wide.listen.to_string(),
                wide_udp_capture_contract_requested: requested_udp_capture_contract(cfg),
                wide_udp_capture_support_tier_requested: requested_udp_capture_support_tier(cfg),
                wide_udp_capture_contract: active_udp_capture_contract(cfg, None),
                wide_udp_capture_support_tier: active_udp_capture_support_tier(cfg, None),
                wide_udp_capture_policy: active_udp_capture_policy(cfg, None),
                wide_udp_capture_runtime_scope: active_udp_capture_runtime_scope(cfg, None),
                wide_backend_current_stage: self.wide_backend_current_stage(cfg),
                wide_backend_scope_target: self.wide_backend_scope_target(cfg),
                wide_backend_reason_code: self.wide_backend_reason_code(cfg),
                wide_dns_port: cfg.ingress.wide.dns_port,
                wide_udp_preview_ports: &cfg.ingress.wide.udp_preview_ports,
                socks_listen: cfg.socks.listen.to_string(),
                selection_error_code: self.code,
                selection_hint_code: self.hint_code,
                selection_error: &self.message,
                hint: self.hint,
                linux_validation_bootstrap_check_command: linux_validation_bootstrap_check_command(
                    cfg,
                ),
                linux_validation_bootstrap_install_command:
                    linux_validation_bootstrap_install_command(cfg),
                backend_notes: backend_notes(cfg),
            },
        })
        .expect("serialize ingress preflight error json")
    }
}

async fn probe_socks_listener(cfg: &Settings) -> RuntimeProbeCheck {
    let listen = cfg.socks.listen;
    match Socks5FallbackBackend::bind(listen).await {
        Ok(_backend) => RuntimeProbeCheck {
            target: "socks.listen",
            code: RuntimeProbeCode::FallbackBindOk,
            severity: RuntimeProbeSeverity::Pass,
            fatal: false,
            message: format!("SOCKS5 fallback can bind {}", listen),
        },
        Err(err) => {
            let (code, _hint_code, hint) = classify_socks_bind_failure(cfg, &err);
            RuntimeProbeCheck {
                target: "socks.listen",
                code,
                severity: RuntimeProbeSeverity::Fail,
                fatal: true,
                message: format!(
                    "SOCKS5 fallback bind probe failed on {}: {}. hint: {}",
                    listen, err, hint
                ),
            }
        }
    }
}
