//! Read-only installation planner. Host observations are prerequisites, never
//! evidence of a working tunnel. Only existing relay profiles are selected.

use std::path::{Path, PathBuf};

use aegis_core::wide_product::{WideProductMode, WideProductProfile};
use aegis_core::{Mode, Settings, TunnelTransportFamily};
use serde::Serialize;

#[derive(clap::Args, Clone, Debug)]
pub struct AutoArgs {
    /// Candidate client config; credentials are never printed.
    #[arg(long)]
    pub config: PathBuf,
    /// Exact administrator-owned installation metadata directory (no runtime fallback).
    #[arg(long)]
    pub state_dir: PathBuf,
    /// Explicit administrator choice for the current V2 SOCKS product.
    #[arg(long, value_parser = ["socks-only"])]
    pub requested_mode: Option<String>,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Default)]
struct Host {
    linux: bool,
    root: bool,
    net_admin: bool,
    systemd: bool,
    tun: bool,
    ipv6: bool,
    missing_commands: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct Plan {
    schema: &'static str,
    status: &'static str,
    product_mode: Option<WideProductMode>,
    profile: Option<WideProductProfile>,
    preserved_selection: bool,
    connectivity_verified: bool,
    message: &'static str,
    reasons: Vec<String>,
}

#[cfg(test)]
fn plan(host: &Host, previous: Option<WideProductMode>) -> Plan {
    plan_requested(host, previous, None)
}

fn plan_requested(
    host: &Host,
    previous: Option<WideProductMode>,
    requested: Option<WideProductMode>,
) -> Plan {
    let mut result = Plan {
        schema: "aegis_auto_install_plan_v1",
        status: "blocked",
        product_mode: None,
        profile: None,
        preserved_selection: previous.is_some(),
        connectivity_verified: false,
        message:
            "Installation prerequisites are incomplete; existing installation has not been changed.",
        reasons: Vec::new(),
    };
    if !host.linux {
        result
            .reasons
            .push("automatic installation currently requires Linux".into());
    }
    if requested == Some(WideProductMode::SocksOnly) {
        if previous.is_some_and(|mode| mode != WideProductMode::SocksOnly) {
            result.reasons.push("an existing system-wide selection cannot be changed to SOCKS by automatic installation".into());
        }
        if !host.root || !host.systemd {
            result.reasons.push(
                "current V2 SOCKS installation requires Linux root and a running systemd manager"
                    .into(),
            );
        }
    }
    // Never silently turn an ordinary host-wide installation into a per-app proxy.
    if previous != Some(WideProductMode::SocksOnly) && requested != Some(WideProductMode::SocksOnly)
    {
        if !host.root {
            result
                .reasons
                .push("run the installer with sudo for host-wide networking".into());
        }
        if !host.net_admin {
            result
                .reasons
                .push("CAP_NET_ADMIN is unavailable (common in restricted containers)".into());
        }
        if !host.systemd {
            result
                .reasons
                .push("a running systemd system manager is required".into());
        }
        for name in &host.missing_commands {
            result.reasons.push(format!("missing host command: {name}; run bootstrap-install.sh to install prerequisites on Ubuntu/Debian"));
        }
    }
    let mode = match (requested, previous) {
        (Some(WideProductMode::SocksOnly), None) => WideProductMode::SocksOnly,
        (Some(WideProductMode::SocksOnly), Some(WideProductMode::SocksOnly)) => {
            WideProductMode::SocksOnly
        }
        (Some(_), _) => {
            result
                .reasons
                .push("unsupported explicit automatic product selection".into());
            WideProductMode::WideRedirectSafe
        }
        (None, previous) => match previous {
            Some(WideProductMode::SocksOnly) => WideProductMode::SocksOnly,
            Some(WideProductMode::WideRedirectSafe) => WideProductMode::WideRedirectSafe,
            Some(WideProductMode::FullWideTun) => {
                if !host.tun || !host.ipv6 {
                    result.reasons.push("previous full-wide-tun selection requires /dev/net/tun and IPv6; refusing an automatic downgrade".into());
                }
                WideProductMode::FullWideTun
            }
            Some(_) => {
                result.reasons.push(
                    "existing advanced profile needs its explicit --profile and associated options"
                        .into(),
                );
                WideProductMode::WideRedirectSafe
            }
            None if host.tun && host.ipv6 => WideProductMode::FullWideTun,
            None => WideProductMode::WideRedirectSafe,
        },
    };
    if !result.reasons.is_empty() {
        return result;
    }
    result.status = "planned";
    result.product_mode = Some(mode);
    result.profile = Some(mode.default_profile());
    result.message = match mode {
        WideProductMode::FullWideTun => "System-wide relay selected. Connectivity will be checked after activation; UDP and IPv6 still need live validation.",
        WideProductMode::SocksOnly if previous.is_some() => "Keeping your per-application proxy selection. Other applications are outside its scope.",
        WideProductMode::SocksOnly => "Per-application proxy selected. Other applications are outside its scope.",
        _ => "Limited system-wide connection selected: TCP and DNS relayed; generic UDP and IPv6 blocked.",
    };
    if previous.is_none() && mode == WideProductMode::WideRedirectSafe {
        if !host.tun {
            result
                .reasons
                .push("TUN device unavailable; selecting the existing safe limited profile".into());
        }
        if !host.ipv6 {
            result
                .reasons
                .push("IPv6 is unavailable on this host".into());
        }
    }
    result
}

fn command_present(name: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|dir| {
            let Ok(meta) = dir.join(name).metadata() else {
                return false;
            };
            if !meta.is_file() {
                return false;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                meta.permissions().mode() & 0o111 != 0
            }
            #[cfg(not(unix))]
            {
                true
            }
        })
    })
}

fn has_net_admin(status: &str) -> bool {
    status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
        .is_some_and(|caps| caps & (1 << 12) != 0)
}

fn observe_host() -> Host {
    #[cfg(unix)]
    // SAFETY: geteuid has no arguments or memory effects.
    let root = unsafe { libc::geteuid() == 0 };
    #[cfg(not(unix))]
    let root = false;
    Host {
        linux: cfg!(target_os = "linux"),
        root,
        net_admin: has_net_admin(&std::fs::read_to_string("/proc/self/status").unwrap_or_default()),
        systemd: Path::new("/run/systemd/system").is_dir() && command_present("systemctl"),
        tun: Path::new("/dev/net/tun").exists(),
        ipv6: Path::new("/proc/net/if_inet6").exists(),
        missing_commands: [
            "ip",
            "iptables",
            "ip6tables",
            "curl",
            "getent",
            "python3",
            "systemd-run",
            "timeout",
        ]
        .into_iter()
        .filter(|name| !command_present(name))
        .collect(),
    }
}

fn previous_mode(state_dir: &Path) -> Result<Option<WideProductMode>, String> {
    let path = state_dir.join("wide-profile.json");
    let text = match crate::profile::read_install_metadata(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if state_dir.join("operator-mode.json").exists()
                || state_dir.join("install-manifest.json").exists()
            {
                return Err("Existing installation has no product profile; choose --profile explicitly to preserve its intended scope.".into());
            }
            return Ok(None);
        }
        Err(_) => return Err(
            "Cannot read the existing product profile; existing installation has not been changed."
                .into(),
        ),
    };
    parse_previous_mode(&text)
}

fn parse_previous_mode(text: &str) -> Result<Option<WideProductMode>, String> {
    let value: serde_json::Value = serde_json::from_str(text).map_err(|_| {
        "Existing product profile is invalid; choose --profile explicitly.".to_string()
    })?;
    let mode = value
        .get("product_mode")
        .and_then(|v| v.as_str())
        .and_then(WideProductMode::parse_str)
        .ok_or_else(|| {
            "Existing product mode is unknown; choose --profile explicitly.".to_string()
        })?;
    let defaults =
        serde_json::to_value(mode.default_profile()).map_err(|_| "Cannot resolve profile")?;
    for key in ["udp_policy", "dns_policy", "ipv6_policy"] {
        if let Some(policy) = value
            .get(key)
            .and_then(|v| v.as_str())
            .filter(|v| !v.is_empty())
        {
            if Some(policy) != defaults.get(key).and_then(|v| v.as_str()) {
                return Err("Existing custom traffic policies require explicit profile options; refusing to replace them automatically.".into());
            }
        }
    }
    Ok(Some(mode))
}
/// Pure AUTO admission shared by the portable planner and Linux transaction.
/// Inner TLS is an exclusive authenticated carrier; legacy needs its full token.
pub(crate) fn validate_auto_relay_auth(settings: &Settings) -> Result<(), &'static str> {
    if !matches!(settings.mode, Mode::Relay) {
        return Err("auto_relay_mode_required");
    }
    if settings.relay.inner_tls.is_some() {
        if !settings.relay.auth_token.is_empty() {
            return Err("auto_relay_mixed_auth_refused");
        }
        settings
            .relay
            .validate_inner_tls_transport()
            .map_err(|_| "auto_relay_inner_transport_invalid")?;
        settings
            .validate_inner_tls()
            .map_err(|_| "auto_relay_inner_policy_invalid")?;
    } else {
        aegis_core::auth_token::validate(&settings.relay.auth_token)
            .map_err(|_| "auto_relay_legacy_auth_invalid")?;
    }
    Ok(())
}

/// The installed wide witness has five seconds for an authenticated TCP echo.
/// Legacy HTTPS-WS/legacy TLS do not serve its reserved numeric tuple, so a
/// later gRPC fallback cannot be treated as the first ready capture carrier.
pub(crate) fn validate_auto_capture_tcp_carrier(settings: &Settings) -> Result<(), &'static str> {
    if settings.relay.inner_tls.is_none()
        && settings.relay.transport_priority.first() != Some(&TunnelTransportFamily::GrpcStream)
    {
        return Err("auto_capture_tcp_probe_carrier_unready");
    }
    Ok(())
}

fn validate_selected_capture_carrier(
    settings: &Settings,
    selected: WideProductMode,
) -> Result<(), &'static str> {
    if selected != WideProductMode::SocksOnly {
        validate_auto_capture_tcp_carrier(settings)?;
    }
    Ok(())
}

fn validate_config(text: &str) -> Result<(), String> {
    // Do not include TOML errors: those can echo a line containing credentials.
    let config: Settings = toml::from_str(text).map_err(|_| {
        "Client bundle configuration is invalid; obtain a fresh access bundle.".to_string()
    })?;
    if config.relay.server.trim().is_empty()
        || config.relay.server_name.trim().is_empty()
        || validate_auto_relay_auth(&config).is_err()
    {
        return Err(
            "Automatic installation requires a configured relay-only access bundle.".into(),
        );
    }
    Ok(())
}

/// Transaction-only planner: inputs were already captured under their distinct
/// config/administrator roles. Never opens the original config or metadata.
#[cfg(target_os = "linux")]
pub(crate) fn plan_captured(
    config: &[u8],
    previous_profile: Option<&[u8]>,
    prior_installation_markers: bool,
    requested_mode: Option<&str>,
) -> Result<serde_json::Value, String> {
    plan_captured_with_host(
        config,
        previous_profile,
        prior_installation_markers,
        requested_mode,
        &observe_host(),
    )
}

#[cfg(any(test, target_os = "linux"))]
fn plan_captured_with_host(
    config: &[u8],
    previous_profile: Option<&[u8]>,
    prior_installation_markers: bool,
    requested_mode: Option<&str>,
    host: &Host,
) -> Result<serde_json::Value, String> {
    let text =
        std::str::from_utf8(config).map_err(|_| "Captured config encoding refused".to_string())?;
    validate_config(text)?;
    let previous = match previous_profile {
        Some(bytes) => parse_previous_mode(
            std::str::from_utf8(bytes)
                .map_err(|_| "Captured metadata encoding refused".to_string())?,
        )?,
        None if prior_installation_markers => {
            return Err(
                "Existing installation has no captured administrative product profile".into(),
            )
        }
        None => None,
    };
    let requested = match requested_mode {
        Some("socks-only") => Some(WideProductMode::SocksOnly),
        Some(_) => return Err("Unsupported explicit automatic product selection".into()),
        None => None,
    };
    let selected = plan_requested(host, previous, requested);
    if selected.status != "planned" {
        return Err("Captured automatic installation prerequisites refused".into());
    }
    let selected_mode = selected
        .product_mode
        .ok_or_else(|| "Captured automatic installation mode refused".to_string())?;
    let settings: Settings =
        toml::from_str(text).map_err(|_| "Captured relay configuration refused".to_string())?;
    validate_selected_capture_carrier(&settings, selected_mode).map_err(|_| {
        "Automatic wide capture requires a first authenticated gRPC TCP carrier".to_string()
    })?;
    serde_json::to_value(selected).map_err(|_| "Captured plan serialization refused".into())
}

pub fn run(args: &AutoArgs) -> Result<(), String> {
    // Unsupported AUTO hosts refuse before any selected config/state I/O.
    // Keep this runtime entry guard separate from hidden AutoConfig dispatch.
    if !cfg!(target_os = "linux") {
        return Err("Automatic installation currently requires Linux".into());
    }
    #[cfg(target_os="linux")]
    let captured=crate::profile_auto_capture::read_standalone_config(&args.config)
        .map_err(|_|"Provide a readable access bundle with --bundle or --bundle-url before automatic installation.".to_string())?;
    #[cfg(target_os = "linux")]
    let text = captured
        .text()
        .map_err(|_| "Captured standalone configuration refused".to_string())?;
    #[cfg(not(target_os="linux"))]
    let text_owned = std::fs::read_to_string(&args.config)
        .map_err(|_| "Provide a readable access bundle with --bundle or --bundle-url before automatic installation.".to_string())?;
    #[cfg(not(target_os = "linux"))]
    let text = text_owned.as_str();
    validate_config(text)?;
    let requested = match args.requested_mode.as_deref() {
        Some("socks-only") => Some(WideProductMode::SocksOnly),
        Some(_) => return Err("Unsupported explicit automatic product selection".into()),
        None => None,
    };
    let result = plan_requested(&observe_host(), previous_mode(&args.state_dir)?, requested);
    if result.status == "planned" {
        let settings: Settings =
            toml::from_str(text).map_err(|_| "Captured relay configuration refused".to_string())?;
        let selected = result
            .product_mode
            .ok_or("Captured automatic installation mode refused")?;
        validate_selected_capture_carrier(&settings, selected).map_err(|_| {
            "Automatic wide capture requires a first authenticated gRPC TCP carrier"
        })?;
    }
    #[cfg(target_os = "linux")]
    captured
        .revalidate()
        .map_err(|_| "Standalone configuration generation changed".to_string())?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&result)
                .map_err(|_| "Cannot serialize installation plan")?
        );
    } else {
        println!("{}", result.message);
        for reason in &result.reasons {
            println!("  {reason}");
        }
    }
    if result.status == "blocked" {
        return Err("Automatic installation preflight blocked; no changes made.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn supported() -> Host {
        Host {
            linux: true,
            root: true,
            net_admin: true,
            systemd: true,
            tun: true,
            ipv6: true,
            missing_commands: vec![],
        }
    }
    #[test]
    fn supported_host_plans_full_without_claiming_connectivity() {
        let p = plan(&supported(), None);
        assert_eq!(p.product_mode, Some(WideProductMode::FullWideTun));
        assert!(!p.connectivity_verified);
    }
    #[test]
    fn explicit_current_v2_socks_is_fresh_or_preserved_only() {
        let socks = Some(WideProductMode::SocksOnly);
        let fresh = plan_requested(&supported(), None, socks);
        assert_eq!(fresh.status, "planned");
        assert_eq!(fresh.product_mode, socks);
        assert!(!fresh.preserved_selection);
        let preserved = plan_requested(&supported(), socks, socks);
        assert_eq!(preserved.status, "planned");
        assert!(preserved.preserved_selection);
        for previous in [
            WideProductMode::WideRedirectSafe,
            WideProductMode::FullWideTun,
        ] {
            let rejected = plan_requested(&supported(), Some(previous), socks);
            assert_eq!(rejected.status, "blocked");
            assert!(rejected.product_mode.is_none());
        }
        let no_root = Host {
            root: false,
            ..supported()
        };
        assert_eq!(plan_requested(&no_root, None, socks).status, "blocked");
        let no_systemd = Host {
            systemd: false,
            ..supported()
        };
        assert_eq!(plan_requested(&no_systemd, None, socks).status, "blocked");
        let no_capture = Host {
            net_admin: false,
            tun: false,
            ipv6: false,
            missing_commands: vec!["iptables"],
            ..supported()
        };
        assert_eq!(plan_requested(&no_capture, None, socks).product_mode, socks);
        assert_eq!(plan(&no_capture, None).status, "blocked");
        assert_eq!(
            plan(&supported(), None).product_mode,
            Some(WideProductMode::FullWideTun)
        );
    }
    #[test]
    fn unavailable_tun_selects_limited_but_never_native_or_per_app() {
        let p = plan(
            &Host {
                tun: false,
                ..supported()
            },
            None,
        );
        assert_eq!(p.product_mode, Some(WideProductMode::WideRedirectSafe));
        assert_eq!(p.profile.unwrap().ipv6_policy.as_str(), "block");
    }
    #[test]
    fn missing_prerequisites_block_instead_of_silently_downgrading() {
        for host in [
            Host {
                root: false,
                ..supported()
            },
            Host {
                linux: false,
                ..supported()
            },
            Host {
                net_admin: false,
                ..supported()
            },
            Host {
                systemd: false,
                ..supported()
            },
            Host {
                missing_commands: vec!["ip6tables"],
                ..supported()
            },
        ] {
            let p = plan(&host, None);
            assert_eq!(p.status, "blocked");
            assert!(p.product_mode.is_none());
        }
    }
    #[test]
    fn upgrade_preserves_scope_and_refuses_lost_capability() {
        let p = plan(&supported(), Some(WideProductMode::WideRedirectSafe));
        assert_eq!(p.product_mode, Some(WideProductMode::WideRedirectSafe));
        assert!(p.preserved_selection);
        assert_eq!(
            plan(
                &Host {
                    tun: false,
                    ..supported()
                },
                Some(WideProductMode::FullWideTun)
            )
            .status,
            "blocked"
        );
        for mode in [
            WideProductMode::FullWideHybridGeneva,
            WideProductMode::WideCompat,
            WideProductMode::GatewayTproxy,
        ] {
            assert_eq!(plan(&supported(), Some(mode)).status, "blocked");
        }
    }
    #[test]
    fn capabilities_are_effective_not_inferred_from_uid() {
        assert!(!has_net_admin("CapEff:\t0000000000000000"));
        assert!(!has_net_admin("CapPrm:\t0000000000001000"));
        assert!(has_net_admin("CapEff:\t0000000000001000"));
        assert!(!has_net_admin("CapEff: invalid"));
    }
    #[test]
    fn invalid_config_errors_do_not_echo_secrets() {
        let err = validate_config("mode = secret-token-123").unwrap_err();
        assert!(!err.contains("secret-token-123"));
        assert!(validate_config("mode = \"direct\"").is_err());
    }

    #[test]
    fn relay_bundle_is_valid_without_installing_its_ca_placeholder() {
        assert!(validate_config(
            r#"
mode = "relay"
[relay]
server = "relay.example:443"
server_name = "relay.example"
auth_token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
ca_cert = "__CLIENT_CA_CERT_PATH__"
"#
        )
        .is_ok());
    }

    #[test]
    fn planner_admits_exclusive_device_carrier_and_refuses_mixed_auth() {
        let device = "mode = 'relay'\n[relay]\nserver = '10.231.80.2:443'\nserver_name = 'relay.aegis.test'\nauth_token = ''\nca_cert = '/srv/ca.pem'\ntls_backend = 'rustls'\ntransport_priority = ['grpc_stream']\nudp_transport_priority = ['grpc_datagram']\n[relay.inner_tls]\nserver_name = 'origin.aegis.test'\nserver_ca = '/srv/inner-ca.pem'\ncert = '/srv/device.pem'\nkey = '/srv/device.key'\n";
        assert!(validate_config(device).is_ok());
        assert!(validate_config(&device.replace(
            "auth_token = ''",
            "auth_token = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'"
        ))
        .is_err());
        assert!(validate_config(&device.replace("['grpc_stream']", "['legacy_tls']")).is_err());
        assert!(
            plan_captured_with_host(device.as_bytes(), None, false, None, &supported()).is_ok()
        );
    }

    #[test]
    fn wide_auto_requires_first_authenticated_reserved_tcp_carrier() {
        let mut settings = Settings {
            mode: Mode::Relay,
            ..Settings::default()
        };
        settings.relay.transport_priority = vec![
            TunnelTransportFamily::HttpsWs,
            TunnelTransportFamily::GrpcStream,
            TunnelTransportFamily::LegacyTls,
            TunnelTransportFamily::MasqueDerived,
        ];
        for mode in [
            WideProductMode::FullWideTun,
            WideProductMode::WideRedirectSafe,
        ] {
            assert_eq!(
                validate_selected_capture_carrier(&settings, mode),
                Err("auto_capture_tcp_probe_carrier_unready")
            );
        }
        assert!(validate_selected_capture_carrier(&settings, WideProductMode::SocksOnly).is_ok());
        settings.relay.transport_priority = vec![TunnelTransportFamily::GrpcStream];
        for mode in [
            WideProductMode::FullWideTun,
            WideProductMode::WideRedirectSafe,
        ] {
            assert!(validate_selected_capture_carrier(&settings, mode).is_ok());
        }
    }

    #[test]
    fn captured_auto_plan_refuses_old_mixed_wide_and_keeps_socks_choice() {
        let base = format!(
            "mode = 'relay'\n[relay]\nserver = '192.0.2.4:443'\nserver_name = 'relay.example'\nauth_token = '{}'\ntransport_priority = ['grpc_stream']\n",
            "0123456789abcdef".repeat(4)
        );
        let old_mixed = base.replace(
            "transport_priority = ['grpc_stream']",
            "transport_priority = ['https_ws', 'grpc_stream', 'legacy_tls', 'masque_derived']",
        );
        assert!(plan_captured_with_host(base.as_bytes(), None, false, None, &supported()).is_ok());
        assert_eq!(
            plan_captured_with_host(old_mixed.as_bytes(), None, false, None, &supported()).err(),
            Some("Automatic wide capture requires a first authenticated gRPC TCP carrier".into())
        );
        let socks = plan_captured_with_host(
            old_mixed.as_bytes(),
            None,
            false,
            Some("socks-only"),
            &supported(),
        )
        .unwrap();
        assert_eq!(socks["product_mode"], "socks-only");
    }

    #[test]
    fn saved_state_is_fail_closed_and_scoped_to_the_requested_directory() {
        #[cfg(not(windows))]
        let dir = tempfile::tempdir().unwrap();
        #[cfg(windows)]
        let dir = tempfile::Builder::new()
            .prefix("AEGIS-profile-test-")
            .tempdir_in(std::env::var_os("ProgramData").unwrap())
            .unwrap();
        assert_eq!(previous_mode(dir.path()).unwrap(), None);
        let path = dir.path().join("wide-profile.json");
        #[cfg(windows)]
        aegis_core::windows_file::write_private_new(&path, b"", false).unwrap();
        std::fs::write(
            &path,
            r#"{"product_mode":"wide-redirect-safe","udp_policy":"block"}"#,
        )
        .unwrap();
        assert_eq!(
            previous_mode(dir.path()).unwrap(),
            Some(WideProductMode::WideRedirectSafe)
        );
        for text in [
            "broken json",
            r#"{"product_mode":"unknown"}"#,
            r#"{"product_mode":"wide-redirect-safe","udp_policy":"native"}"#,
        ] {
            std::fs::write(&path, text).unwrap();
            assert!(previous_mode(dir.path()).is_err());
        }
        std::fs::remove_file(path).unwrap();
        std::fs::write(dir.path().join("operator-mode.json"), "{}").unwrap();
        assert!(previous_mode(dir.path()).is_err());
    }
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_host_refuses_before_config_or_state_fifo() {
        let directory = tempfile::tempdir().expect("private unsupported-host fixture");
        let config = directory.path().join("config-input");
        let state_dir = directory.path().join("state-input");
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            // Actual FIFO: the old read_to_string blocks here before observing
            // the unsupported host. Root must own the exact test subprocess.
            for path in [&config, &state_dir] {
                let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            }
        }
        #[cfg(not(unix))]
        {
            // A directory is also invalid as config data; static host refusal
            // must win over the old config-read error, without special drivers.
            std::fs::create_dir(&config).unwrap();
            std::fs::create_dir(&state_dir).unwrap();
        }
        for json in [false, true] {
            #[cfg(unix)]
            {
                use std::os::unix::fs::FileTypeExt;
                assert!(config.symlink_metadata().unwrap().file_type().is_fifo());
                assert!(state_dir.symlink_metadata().unwrap().file_type().is_fifo());
                println!("unsupported_host_FIFO_actual_witness: two_real_FIFOs=true json={json} entering_actual_run=true");
            }
            let args = AutoArgs {
                config: config.clone(),
                state_dir: state_dir.clone(),
                requested_mode: None,
                json,
            };
            assert_eq!(
                run(&args).unwrap_err(),
                "Automatic installation currently requires Linux"
            );
        }
    }
}
