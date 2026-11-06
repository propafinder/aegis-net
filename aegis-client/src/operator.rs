//! Linux operator mode selector (plan / apply / status / rollback).
//!
//! A single, Rust-owned vocabulary for the runtime modes an operator can pick,
//! plus a planning verb that emits a machine-checkable `result.json`. The plan is
//! the source of truth: privilege requirements, the backend it activates, traffic
//! coverage, what is and is NOT claimed, the config template, the setup command,
//! and the rollback steps. `apply` only acts when explicitly confirmed and (for
//! privileged wide modes) running as root; `rollback` removes ONLY AEGIS-owned
//! state for the selected mode. Secrets (bundle tokens) are never printed.

use serde::Serialize;
use std::fmt;

/// What the operator wants to do with a mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum OperatorAction {
    /// Compute and print the plan (no side effects).
    Plan,
    /// Apply the plan (requires --apply-confirm; root for wide modes).
    Apply,
    /// Report the currently active mode/backend (best-effort, read-only).
    Status,
    /// Remove AEGIS-owned state created by the mode.
    Rollback,
    /// Switch a client install from one mode to another: plan, back up the old
    /// config, write the new config, restart the service, verify, with rollback.
    Switch,
}

/// The runtime modes an operator can select. Kebab-case on the CLI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum OperatorMode {
    /// Relay origin server.
    Server,
    /// Local SOCKS5 client (lowest privilege).
    #[clap(alias = "socks")]
    ClientSocks,
    /// Transparent Linux wide mode, single-host OUTPUT REDIRECT (capture this
    /// host's own outbound TCP). No per-app SOCKS config needed.
    #[clap(alias = "wide-redirect")]
    ClientWideRedirect,
    /// Transparent Linux wide mode, TPROXY backend (gateway / routed).
    #[clap(alias = "wide-tproxy")]
    ClientWideTproxy,
    /// NFQUEUE observer/policy/DPI-lab (NOT relay; opt-in advanced).
    #[clap(alias = "nfqueue-observer")]
    ClientWideNfqueueObserver,
    /// Controlled IPv6 TUN+smoltcp relay lab (NOT default; controlled route).
    #[clap(alias = "ipv6-tun-lab")]
    ClientIpv6TunLab,
    /// Production IPv6 TUN+smoltcp engine (full-wide-tun v6 leg: any IPv6
    /// destination, multi-flow, fail-closed). Runs alongside the v4 REDIRECT leg.
    #[clap(alias = "ipv6-tun-smoltcp")]
    ClientIpv6TunSmoltcp,
    /// Cloudflare-fronted transport profile (verified grpc_stream contour).
    CloudflareFronted,
    /// Direct MASQUE/QUIC scoped UDP (NOT via Cloudflare orange-cloud).
    MasqueDirect,
}

impl OperatorMode {
    pub fn slug(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::ClientSocks => "client-socks",
            Self::ClientWideRedirect => "client-wide-redirect",
            Self::ClientWideTproxy => "client-wide-tproxy",
            Self::ClientWideNfqueueObserver => "client-wide-nfqueue-observer",
            Self::ClientIpv6TunLab => "client-ipv6-tun-lab",
            Self::ClientIpv6TunSmoltcp => "client-ipv6-tun-smoltcp",
            Self::CloudflareFronted => "cloudflare-fronted",
            Self::MasqueDirect => "masque-direct",
        }
    }

    /// True for modes that install privileged netfilter/route state (need root).
    pub fn requires_root(self) -> bool {
        matches!(
            self,
            Self::ClientWideRedirect
                | Self::ClientWideTproxy
                | Self::ClientWideNfqueueObserver
                | Self::ClientIpv6TunLab
                | Self::ClientIpv6TunSmoltcp
        )
    }

    fn privilege(self) -> &'static str {
        if self.requires_root() {
            "root (CAP_NET_ADMIN)"
        } else {
            "unprivileged user"
        }
    }

    fn backend(self) -> &'static str {
        match self {
            Self::Server => "aegis-server (relay origin)",
            Self::ClientSocks => "socks5 local listener",
            Self::ClientWideRedirect => "linux_redirect (single-host OUTPUT capture)",
            Self::ClientWideTproxy => "linux_tproxy (gateway wide)",
            Self::ClientWideNfqueueObserver => "linux_nfqueue_observer (observe/policy only)",
            Self::ClientIpv6TunLab => "tun+smoltcp (controlled IPv6 relay lab)",
            Self::ClientIpv6TunSmoltcp => "tun+smoltcp (production IPv6 multi-flow relay)",
            Self::CloudflareFronted => "relay transport profile (CF-fronted)",
            Self::MasqueDirect => "relay transport profile (MASQUE direct)",
        }
    }

    fn coverage(self) -> &'static str {
        match self {
            Self::Server => "serves relay tunnels + bundle endpoint; no client ingress",
            Self::ClientSocks => "per-app/manual proxy (apps pointed at the SOCKS listener)",
            Self::ClientWideRedirect => {
                "transparent capture of THIS host's own outbound TCP (no app config)"
            }
            Self::ClientWideTproxy => {
                "transparent IPv4 TCP + DNS UDP/53 + scoped generic UDP (routed/GRE gateway)"
            }
            Self::ClientWideNfqueueObserver => {
                "observe/witness/ACCEPT IPv4+IPv6 matched flows (no termination)"
            }
            Self::ClientIpv6TunLab => "one controlled IPv6 flow terminated by smoltcp -> relay",
            Self::ClientIpv6TunSmoltcp => {
                "any IPv6 TCP+UDP destination terminated by smoltcp -> relay (multi-flow, fail-closed)"
            }
            Self::CloudflareFronted => "relay carried over verified CF-fronted grpc_stream",
            Self::MasqueDirect => "relay carried over direct MASQUE/QUIC (scoped UDP)",
        }
    }

    fn claimed(self) -> &'static str {
        match self {
            Self::Server => "relay origin works; signed bundle issue",
            Self::ClientSocks => "SOCKS5 TCP ingress (LIVE)",
            Self::ClientWideRedirect => {
                "single-host transparent OUTPUT TCP capture (fail-closed profile available)"
            }
            Self::ClientWideTproxy => {
                "production-like Linux wide TCP/IPv4 + DNS capture (LIVE, gateway)"
            }
            Self::ClientWideNfqueueObserver => "observe/witness only (LIVE, observer)",
            Self::ClientIpv6TunLab => "controlled IPv6 packet->smoltcp->relay->egress (LAB PASS)",
            Self::ClientIpv6TunSmoltcp => {
                "production IPv6 multi-flow TCP+UDP ->smoltcp->relay (full-wide-tun v6 leg)"
            }
            Self::CloudflareFronted => "grpc_stream fronting (LIVE, Full strict)",
            Self::MasqueDirect => "direct MASQUE/QUIC (scoped LIVE)",
        }
    }

    fn not_claimed(self) -> &'static [&'static str] {
        match self {
            Self::Server => &["broad anti-DPI", "browser-class TLS mimicry"],
            Self::ClientSocks => &["system-wide capture (per-app only)"],
            Self::ClientWideRedirect => &[
                "gateway/LAN capture (this host's own traffic only)",
                "IPv6 relay (blocked/native depending on profile)",
            ],
            Self::ClientWideTproxy => &[
                "IPv6 relay (fail-closed BLOCK in this mode)",
                "general UDP beyond scoped/preview",
            ],
            Self::ClientWideNfqueueObserver => &[
                "relay/tunnel role (observer-only)",
                "production default backend",
            ],
            Self::ClientIpv6TunLab => &[
                "production-wide IPv6",
                "default-route interception",
                "broad/system-wide capture",
            ],
            Self::ClientIpv6TunSmoltcp => &[
                "gateway/LAN IPv6 capture (this host's own IPv6 traffic only)",
                "IPv6 carried only with the v4 REDIRECT leg (full-wide-tun)",
            ],
            Self::CloudflareFronted => &[
                "RFC 8441 https_ws through the verified Cloudflare edge contour",
                "MASQUE/UDP through a normal orange-cloud proxy",
            ],
            Self::MasqueDirect => &["MASQUE via Cloudflare orange-cloud"],
        }
    }

    /// Relative path (from repo/install root) to the privileged setup command, if
    /// the mode needs one. None for config-only modes.
    fn setup_command(self) -> Option<&'static str> {
        match self {
            Self::Server => Some("install-server.sh"),
            Self::ClientWideRedirect => Some("scripts/setup-wide-linux-redirect.sh"),
            Self::ClientWideTproxy => Some("scripts/setup-wide-linux-tproxy.sh"),
            Self::ClientWideNfqueueObserver => Some("scripts/setup-wide-linux-nfqueue.sh"),
            Self::ClientIpv6TunLab => {
                Some("aegis-client --tun-ipv6-relay-bridge-lab <peer> --tun-relay-config <cfg>")
            }
            // full-wide-tun shares the v4 REDIRECT setup; the v6 TUN engine is
            // launched in-process by the client when ipv6_tun_carried=true.
            Self::ClientIpv6TunSmoltcp => Some("scripts/setup-wide-linux-redirect.sh"),
            Self::ClientSocks | Self::CloudflareFronted | Self::MasqueDirect => None,
        }
    }

    fn systemd_unit(self) -> &'static str {
        match self {
            Self::Server => "aegis-server.service",
            _ => "aegis-client.service",
        }
    }

    /// AEGIS-owned rollback steps for the mode (never touches non-AEGIS state).
    fn rollback_steps(self) -> Vec<String> {
        match self {
            Self::ClientWideRedirect => vec![
                "sudo bash /usr/local/lib/aegis/setup-wide-linux-redirect.sh teardown".into(),
                "systemctl stop aegis-client.service".into(),
            ],
            Self::ClientWideTproxy => vec![
                "sudo bash /usr/local/lib/aegis/setup-wide-linux-tproxy.sh teardown".into(),
                "flush AEGIS mangle/TPROXY chain only".into(),
                "systemctl stop aegis-client.service".into(),
            ],
            Self::ClientWideNfqueueObserver => vec![
                "remove AEGIS NFQUEUE divert rules (queue-bypass watchdog)".into(),
                "systemctl stop aegis-client.service".into(),
            ],
            Self::ClientIpv6TunLab => vec![
                "ip -6 addr/route del for the controlled AEGIS prefix/peer".into(),
                "ip link del aegis-tun0".into(),
            ],
            Self::ClientIpv6TunSmoltcp => vec![
                "sudo bash /usr/local/lib/aegis/setup-wide-linux-redirect.sh teardown".into(),
                "ip -6 route del ::/1 dev aegis-tun0; ip -6 route del 8000::/1 dev aegis-tun0"
                    .into(),
                "ip link del aegis-tun0  # non-persistent: also auto-removed on client exit".into(),
                "systemctl stop aegis-client.service".into(),
            ],
            Self::Server => vec!["systemctl stop aegis-server.service".into()],
            Self::ClientSocks | Self::CloudflareFronted | Self::MasqueDirect => {
                vec!["systemctl stop aegis-client.service".into()]
            }
        }
    }
}

impl fmt::Display for OperatorMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

/// Transport selection (matches relay.transport_priority entries + auto).
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
#[clap(rename_all = "snake_case")]
pub enum TransportChoice {
    Auto,
    HttpsWs,
    GrpcStream,
    LegacyTls,
    MasqueDirect,
}

impl TransportChoice {
    fn slug(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::HttpsWs => "https_ws",
            Self::GrpcStream => "grpc_stream",
            Self::LegacyTls => "legacy_tls",
            Self::MasqueDirect => "masque_direct",
        }
    }
}

/// Per-family / per-protocol policy knob.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
#[clap(rename_all = "kebab-case")]
pub enum PolicyChoice {
    Ipv4Wide,
    Ipv6Block,
    Ipv6Observe,
    Ipv6ControlledTun,
    DnsCapture,
    UdpScoped,
    UdpBlockOrFallback,
}

impl PolicyChoice {
    fn slug(self) -> &'static str {
        match self {
            Self::Ipv4Wide => "ipv4-wide",
            Self::Ipv6Block => "ipv6-block",
            Self::Ipv6Observe => "ipv6-observe",
            Self::Ipv6ControlledTun => "ipv6-controlled-tun",
            Self::DnsCapture => "dns-capture",
            Self::UdpScoped => "udp-scoped",
            Self::UdpBlockOrFallback => "udp-block-or-fallback",
        }
    }
}

/// CLI surface for `aegis-client operator <action> [flags]`.
#[derive(clap::Args, Clone, Debug)]
pub struct OperatorArgs {
    /// plan | apply | status | rollback
    #[arg(value_enum)]
    pub action: OperatorAction,
    /// Operator mode to plan/apply/status/rollback.
    #[arg(long, value_enum)]
    pub mode: Option<OperatorMode>,
    /// Relay transport selection (default: auto).
    #[arg(long, value_enum)]
    pub transport: Option<TransportChoice>,
    /// Policy knobs (repeatable), e.g. --policy ipv4-wide --policy dns-capture.
    #[arg(long, value_enum)]
    pub policy: Vec<PolicyChoice>,
    /// NFQUEUE number (nfqueue-observer mode).
    #[arg(long)]
    pub queue: Option<u16>,
    /// IPv4 family policy verb (observe|wide|block) — recorded into the plan.
    #[arg(long)]
    pub ipv4: Option<String>,
    /// IPv6 family policy verb (observe|block|controlled-tun) — recorded.
    #[arg(long)]
    pub ipv6: Option<String>,
    /// Controlled IPv6 prefix for ipv6-tun-lab (e.g. fd00:ae61::/64).
    #[arg(long)]
    pub controlled_prefix: Option<String>,
    /// Controlled IPv6 peer inside the prefix (e.g. fd00:ae61::100).
    #[arg(long)]
    pub controlled_peer: Option<std::net::Ipv6Addr>,
    /// Relay/server IP to keep on its normal route (excluded from the TUN).
    #[arg(long)]
    pub relay_exclude: Option<std::net::IpAddr>,
    /// Private access-URL record; only a redacted reference enters the plan.
    #[arg(long, conflicts_with = "bundle")]
    pub bundle_url_file: Option<std::path::PathBuf>,
    /// Existing bundle archive pathname (the planner does not open it).
    #[arg(long, conflicts_with = "bundle_url_file")]
    pub bundle: Option<std::path::PathBuf>,
    /// Server listen address (server mode).
    #[arg(long)]
    pub listen: Option<String>,
    /// Relay address advertised by the server bundle (server mode).
    #[arg(long)]
    pub relay_address: Option<String>,
    /// Required to actually apply/rollback privileged state (else plan-only).
    #[arg(long)]
    pub apply_confirm: bool,
    /// Emit JSON result to this path in addition to stdout.
    #[arg(long)]
    pub result_json: Option<std::path::PathBuf>,

    // --- switch ---
    /// Source mode for `operator switch`.
    #[arg(long, value_enum)]
    pub from: Option<OperatorMode>,
    /// Target mode for `operator switch`.
    #[arg(long, value_enum)]
    pub to: Option<OperatorMode>,
    /// Confirm a switch (else plan-only). `operator switch` ALSO accepts
    /// --apply-confirm (the flag used by `operator apply`), so the habitual
    /// flag is not a silent no-op. An `apply` command still never triggers a
    /// switch — the ACTION gates that, not the flag.
    #[arg(long)]
    pub confirm: bool,
    /// Client config path to back up + rewrite (default: standard client config).
    #[arg(long)]
    pub config_path: Option<std::path::PathBuf>,
    /// systemd unit to restart after the switch (default: aegis-client.service).
    #[arg(long)]
    pub service_name: Option<String>,

    // --- guarded IPv6 default route (PHASE 2) ---
    /// IPv6 route policy: controlled | prefix-lab | default-dry-run | default-guarded.
    #[arg(long)]
    pub ipv6_route_policy: Option<String>,
    /// Explicit confirmation required for a guarded live ::/0 default route.
    #[arg(long)]
    pub guarded_default_route_confirm: bool,
    /// Hard cap (seconds) on a guarded default-route window (watchdog).
    #[arg(long)]
    pub max_runtime_seconds: Option<u64>,
    /// Always roll back the guarded default route on exit (mandatory).
    #[arg(long)]
    pub rollback_on_exit: bool,
}

#[derive(Serialize)]
pub struct OperatorPlan {
    pub schema_version: u32,
    pub action: String,
    pub mode: String,
    pub privilege: String,
    pub requires_root: bool,
    pub backend: String,
    pub traffic_coverage: String,
    pub transport: String,
    pub policy: Vec<String>,
    pub config_template: String,
    pub systemd_unit: String,
    pub setup_command: Option<String>,
    pub rollback_steps: Vec<String>,
    pub claimed: String,
    pub not_claimed: Vec<String>,
    /// Redacted bundle reference; private URL contents and archive paths are omitted.
    pub bundle_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_route_policy: Option<serde_json::Value>,
}

#[derive(Serialize)]
pub struct OperatorResult {
    pub artifact: &'static str,
    pub verdict: String,
    pub applied: bool,
    pub plan: OperatorPlan,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_observed: Option<serde_json::Value>,
}

/// Keep only a remote authority without userinfo, path, query or fragment.
fn redact_bundle(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return "<bundle-file>".to_string();
    };
    if scheme == "file" {
        return "<bundle-file>".to_string();
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or("");
    format!("<bundle@{host}>")
}

fn bundle_reference(args: &OperatorArgs) -> Result<Option<String>, String> {
    match (&args.bundle_url_file, &args.bundle) {
        (Some(_), Some(_)) => Err("operator: select only one bundle input".to_string()),
        (Some(path), None) => {
            // Reuse the installed Rust private-descriptor boundary. Never put
            // the reader's diagnostics, path or private bytes into this error.
            let url = aegis_core::installer_secret::read_url(path)
                .map_err(|_| "operator: private bundle URL record refused".to_string())?;
            Ok(Some(redact_bundle(&url)))
        }
        (None, Some(path)) => {
            path.to_str()
                .filter(|text| {
                    !text.is_empty() && !text.chars().any(char::is_control) && !text.contains("://")
                })
                .ok_or_else(|| "operator: bundle archive pathname refused".to_string())?;
            Ok(Some("<bundle-file>".to_string()))
        }
        (None, None) => Ok(None),
    }
}

fn config_template_for(
    mode: OperatorMode,
    transport: TransportChoice,
    policy: &[String],
) -> String {
    let backend = match mode {
        OperatorMode::ClientWideRedirect => "linux_redirect",
        OperatorMode::ClientWideTproxy => "linux_tproxy",
        OperatorMode::ClientWideNfqueueObserver => "linux_nfqueue_observer",
        OperatorMode::ClientIpv6TunLab => "tun_smoltcp (lab)",
        // full-wide-tun: v4 leg is REDIRECT, the v6 TUN engine rides on top.
        OperatorMode::ClientIpv6TunSmoltcp => "linux_redirect",
        _ => "auto",
    };
    let ingress_primary = match mode {
        OperatorMode::ClientSocks => "socks5",
        OperatorMode::ClientWideRedirect
        | OperatorMode::ClientWideTproxy
        | OperatorMode::ClientWideNfqueueObserver
        | OperatorMode::ClientIpv6TunSmoltcp => "wide",
        _ => "socks5",
    };
    format!(
        "[ingress] primary=\"{ingress_primary}\"\n[ingress.wide] platform_backend=\"{backend}\"\n[relay] transport_priority first=\"{}\"\n# policy: {}",
        transport.slug(),
        if policy.is_empty() {
            "(defaults)".to_string()
        } else {
            policy.join(",")
        }
    )
}

/// Build the plan. Fails fast on invalid mode/flag combinations.
pub fn build_plan(args: &OperatorArgs) -> Result<OperatorPlan, String> {
    let mode = args
        .mode
        .ok_or_else(|| "operator: --mode is required (see `operator plan --help`)".to_string())?;
    let transport = match (mode, args.transport.unwrap_or(TransportChoice::Auto)) {
        (OperatorMode::CloudflareFronted, TransportChoice::Auto) => TransportChoice::GrpcStream,
        (_, selected) => selected,
    };

    // Fail fast on contradictory transport/mode combinations.
    if matches!(mode, OperatorMode::CloudflareFronted)
        && !matches!(transport, TransportChoice::GrpcStream)
    {
        return Err(
            "operator: cloudflare-fronted currently supports only grpc_stream; RFC 8441 https_ws and MASQUE do not pass the verified Cloudflare edge contour".into(),
        );
    }
    if matches!(mode, OperatorMode::ClientIpv6TunLab) {
        if let Some(prefix) = &args.controlled_prefix {
            if !prefix.contains('/') {
                return Err(format!(
                    "operator: --controlled-prefix must be CIDR (got {prefix})"
                ));
            }
            // Controlled labs must use a ULA (fd00::/8), never a global prefix.
            if !prefix.to_ascii_lowercase().starts_with("fd") {
                return Err(
                    "operator: ipv6-tun-lab --controlled-prefix must be a ULA (fd00::/8) — never a global/default prefix".into(),
                );
            }
        }
    }

    let policy: Vec<String> = args.policy.iter().map(|p| p.slug().to_string()).collect();

    let ipv6_route_policy = if matches!(mode, OperatorMode::ClientIpv6TunLab) {
        Some(serde_json::json!({
            "kind": "controlled",
            "controlled_prefix": args.controlled_prefix.clone().unwrap_or_else(|| "fd00:ae61::/64".into()),
            "controlled_peer": args.controlled_peer.map(|p| p.to_string()),
            "relay_excluded": args.relay_exclude.map(|p| p.to_string()),
            "default_route": "never (controlled lab)",
        }))
    } else {
        None
    };

    Ok(OperatorPlan {
        schema_version: 1,
        action: format!("{:?}", args.action).to_lowercase(),
        mode: mode.slug().to_string(),
        privilege: mode.privilege().to_string(),
        requires_root: mode.requires_root(),
        backend: mode.backend().to_string(),
        traffic_coverage: mode.coverage().to_string(),
        transport: transport.slug().to_string(),
        policy: policy.clone(),
        config_template: config_template_for(mode, transport, &policy),
        systemd_unit: mode.systemd_unit().to_string(),
        setup_command: mode.setup_command().map(|s| s.to_string()),
        rollback_steps: mode.rollback_steps(),
        claimed: mode.claimed().to_string(),
        not_claimed: mode.not_claimed().iter().map(|s| s.to_string()).collect(),
        bundle_ref: bundle_reference(args)?,
        ipv6_route_policy,
    })
}

#[cfg(unix)]
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}
#[cfg(not(unix))]
fn is_root() -> bool {
    false
}

/// Best-effort, read-only status of a mode's footprint.
fn observe_status(mode: OperatorMode) -> serde_json::Value {
    let unit = mode.systemd_unit();
    let active = std::process::Command::new("systemctl")
        .args(["is-active", unit])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    serde_json::json!({
        "mode": mode.slug(),
        "systemd_unit": unit,
        "systemd_active": active,
        "note": "read-only best-effort; does not modify state",
    })
}

#[derive(Serialize)]
pub struct SwitchResult {
    pub artifact: &'static str,
    pub verdict: String,
    pub from: String,
    pub to: String,
    pub transport: String,
    pub applied: bool,
    pub config_path: String,
    pub backup_path: Option<String>,
    pub service_name: String,
    pub service_active_after: Option<String>,
    pub steps: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub plan: OperatorPlan,
}

fn default_client_config_path() -> std::path::PathBuf {
    // Prefer the standard root install path; fall back to the user path.
    let root = std::path::PathBuf::from("/etc/aegis/client/aegis.toml");
    if root.exists() {
        return root;
    }
    if let Some(home) = dirs::home_dir() {
        let user = home.join(".config/aegis/client/aegis.toml");
        if user.exists() {
            return user;
        }
    }
    root
}

/// Mutate a loaded Settings to reflect the target mode + transport preference.
/// Secrets already in the file (auth_token, server) are preserved untouched.
fn apply_mode_to_settings(
    s: &mut aegis_core::Settings,
    to: OperatorMode,
    transport: TransportChoice,
) {
    use aegis_core::{IngressPrimary, Mode, TunnelTransportFamily, WidePlatformBackend};
    match to {
        OperatorMode::ClientSocks
        | OperatorMode::CloudflareFronted
        | OperatorMode::MasqueDirect
        | OperatorMode::ClientIpv6TunLab => {
            s.mode = Mode::Relay;
            s.ingress.primary = IngressPrimary::Socks5;
        }
        OperatorMode::ClientWideRedirect => {
            s.mode = Mode::Relay;
            s.ingress.primary = IngressPrimary::Wide;
            s.ingress.wide.enabled = true;
            s.ingress.wide.platform_backend = WidePlatformBackend::LinuxRedirect;
        }
        OperatorMode::ClientWideTproxy => {
            s.mode = Mode::Relay;
            s.ingress.primary = IngressPrimary::Wide;
            s.ingress.wide.enabled = true;
            s.ingress.wide.platform_backend = WidePlatformBackend::LinuxTproxy;
        }
        OperatorMode::ClientWideNfqueueObserver => {
            s.mode = Mode::Relay;
            s.ingress.primary = IngressPrimary::Wide;
            s.ingress.wide.enabled = true;
            s.ingress.wide.platform_backend = WidePlatformBackend::LinuxNfqueueObserver;
        }
        OperatorMode::ClientIpv6TunSmoltcp => {
            // full-wide-tun: v4 REDIRECT leg + the in-process IPv6 TUN engine,
            // gated by ipv6_tun_carried (the only mode that sets it true).
            s.mode = Mode::Relay;
            s.ingress.primary = IngressPrimary::Wide;
            s.ingress.wide.enabled = true;
            s.ingress.wide.platform_backend = WidePlatformBackend::LinuxRedirect;
            s.ingress.wide.ipv6_tun_carried = true;
        }
        OperatorMode::Server => {}
    }
    // Put the chosen transport first in the priority list (keep the rest).
    let chosen = match transport {
        TransportChoice::HttpsWs => Some(TunnelTransportFamily::HttpsWs),
        TransportChoice::GrpcStream => Some(TunnelTransportFamily::GrpcStream),
        TransportChoice::LegacyTls => Some(TunnelTransportFamily::LegacyTls),
        TransportChoice::MasqueDirect => Some(TunnelTransportFamily::MasqueDerived),
        TransportChoice::Auto => None,
    };
    if let Some(c) = chosen {
        s.relay.transport_priority.retain(|t| *t != c);
        s.relay.transport_priority.insert(0, c);
    }
}

/// Perform a client mode switch (plan → backup → rewrite → restart → verify).
fn run_switch(args: &OperatorArgs) -> Result<String, String> {
    let from = args
        .from
        .ok_or_else(|| "operator switch: --from <mode> is required".to_string())?;
    let to = args
        .to
        .ok_or_else(|| "operator switch: --to <mode> is required".to_string())?;
    let transport = args.transport.unwrap_or(TransportChoice::Auto);
    // Reuse the planner for the target mode (validates flag combinations).
    let plan = build_plan(&OperatorArgs {
        mode: Some(to),
        ..args.clone()
    })?;

    let cfg_path = args
        .config_path
        .clone()
        .unwrap_or_else(default_client_config_path);
    let service_name = args
        .service_name
        .clone()
        .unwrap_or_else(|| "aegis-client.service".to_string());

    let mut steps: Vec<String> = vec![format!("plan target={}", to.slug())];
    let mut backup_path: Option<String> = None;
    let mut service_active_after: Option<String> = None;
    let mut applied = false;
    let mut error: Option<String> = None;

    // A switch is confirmed by EITHER --confirm OR the --apply-confirm flag
    // operators reach for by habit (it is the confirmation verb for
    // `operator apply`). Accepting both removes the silent footgun where
    // `operator switch --apply-confirm ...` printed a plan and exited 0 without
    // changing anything. The "an apply command never triggers a switch"
    // invariant is upheld by the ACTION dispatch in run() (only ACTION=switch
    // reaches here), NOT by keeping the confirm flags distinct.
    let confirmed = args.confirm || args.apply_confirm;
    let verdict = if !confirmed {
        error = Some(
            "plan only — NOTHING was changed. Re-run with --apply-confirm to write the \
             config and restart the service."
                .to_string(),
        );
        "SWITCH_PLAN_ONLY".to_string()
    } else if matches!(to, OperatorMode::ClientIpv6TunLab)
        && args.ipv6_route_policy.as_deref() == Some("default-guarded")
        && !args.guarded_default_route_confirm
    {
        // Route-policy refusal takes precedence over the root check: a guarded
        // ::/0 must be explicitly confirmed before anything else is considered.
        error =
            Some("guarded ::/0 default route requires --guarded-default-route-confirm".to_string());
        "BLOCKED_BY_ROUTE_POLICY".to_string()
    } else if to.requires_root() && !is_root() {
        error = Some(format!("target mode {} requires root", to.slug()));
        "BLOCKED_NEEDS_ROOT".to_string()
    } else {
        // Confirmed + privilege satisfied. Back up + rewrite the config.
        match do_switch(&cfg_path, to, transport, &service_name, &mut steps) {
            Ok((bak, active)) => {
                backup_path = bak;
                service_active_after = active;
                applied = true;
                // A switch rewrites config + restarts the client (so it binds
                // the target ingress), but wide modes still need a separate
                // privileged capture step. Surface it so nobody believes wide
                // egress is live after a switch alone.
                if let Some(cmd) = to.setup_command() {
                    steps.push(format!("next_privileged_step: {cmd}"));
                }
                "SWITCH_APPLIED".to_string()
            }
            Err(e) => {
                error = Some(e);
                "SWITCH_FAILED".to_string()
            }
        }
    };

    let result = SwitchResult {
        artifact: "linux-operator-mode-switch",
        verdict,
        from: from.slug().to_string(),
        to: to.slug().to_string(),
        transport: transport.slug().to_string(),
        applied,
        config_path: cfg_path.display().to_string(),
        backup_path,
        service_name,
        service_active_after,
        steps,
        error,
        plan,
    };
    let json = serde_json::to_string_pretty(&result).map_err(|e| format!("serialize: {e}"))?;
    if let Some(path) = &args.result_json {
        std::fs::write(path, &json).map_err(|e| format!("write {}: {e}", path.display()))?;
    }
    // A CONFIRMED switch that did not end applied (blocked-needs-root, route
    // policy, or a failed rewrite/restart) is a HARD failure: return Err so the
    // command exits non-zero (main maps Err -> non-zero). This closes the
    // dangerous false-positive where a switch that changed nothing still exited
    // 0 and read as success. An intentional plan-only (no confirm) is NOT a
    // failure — it returns Ok and exits 0 with the "nothing changed" note.
    if confirmed && !applied {
        return Err(json);
    }
    Ok(json)
}

/// The privileged half of a switch: backup, rewrite, restart, verify. Returns
/// (backup_path, service_active_after). Never prints secrets.
fn do_switch(
    cfg_path: &std::path::Path,
    to: OperatorMode,
    transport: TransportChoice,
    service_name: &str,
    steps: &mut Vec<String>,
) -> Result<(Option<String>, Option<String>), String> {
    if !cfg_path.exists() {
        return Err(format!("config not found: {}", cfg_path.display()));
    }
    // 1) Back up the current config (timestamped).
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let bak = cfg_path.with_extension(format!("toml.bak.{ts}"));
    std::fs::copy(cfg_path, &bak).map_err(|e| format!("backup: {e}"))?;
    steps.push(format!("config_backed_up -> {}", bak.display()));

    // 2) Load, transform, write (secrets preserved; perms tightened to 0600).
    let raw = std::fs::read_to_string(cfg_path).map_err(|e| format!("read config: {e}"))?;
    let mut settings: aegis_core::Settings =
        toml::from_str(&raw).map_err(|e| format!("parse config: {e}"))?;
    apply_mode_to_settings(&mut settings, to, transport);
    let new_toml = toml::to_string(&settings).map_err(|e| format!("serialize config: {e}"))?;
    std::fs::write(cfg_path, new_toml).map_err(|e| format!("write config: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(cfg_path, std::fs::Permissions::from_mode(0o600));
    }
    steps.push(format!("config_written mode={}", to.slug()));

    // 3) Restart the service if the unit exists (best-effort, never fatal here).
    let unit_known = std::process::Command::new("systemctl")
        .args(["cat", service_name])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if unit_known {
        let restarted = std::process::Command::new("systemctl")
            .args(["restart", service_name])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        steps.push(format!("service_restarted={restarted}"));
    } else {
        steps.push("service_restart_skipped (unit not installed)".to_string());
    }

    // 4) Verify status.
    let active = std::process::Command::new("systemctl")
        .args(["is-active", service_name])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    steps.push(format!("verified active={:?}", active));
    Ok((Some(bak.display().to_string()), active))
}

/// Run the operator verb. Returns the result JSON string.
pub fn run(args: &OperatorArgs) -> Result<String, String> {
    if matches!(args.action, OperatorAction::Switch) {
        return run_switch(args);
    }
    let plan = build_plan(args)?;
    let mode = args.mode.expect("mode validated in build_plan");

    let (verdict, applied, error, status_observed) = match args.action {
        OperatorAction::Plan => ("PLAN_OK".to_string(), false, None, None),
        OperatorAction::Status => (
            "STATUS_OK".to_string(),
            false,
            None,
            Some(observe_status(mode)),
        ),
        OperatorAction::Apply | OperatorAction::Rollback => {
            if !args.apply_confirm {
                (
                    "PLAN_ONLY_NEEDS_CONFIRM".to_string(),
                    false,
                    Some("re-run with --apply-confirm to apply/rollback privileged state".into()),
                    None,
                )
            } else if mode.requires_root() && !is_root() {
                (
                    "BLOCKED_NEEDS_ROOT".to_string(),
                    false,
                    Some(format!(
                        "mode {} requires {} — re-run as root",
                        mode.slug(),
                        mode.privilege()
                    )),
                    None,
                )
            } else {
                // Confirmed + privilege satisfied, but this path is still a
                // planner/status helper. The actual privileged firewall/DNS
                // mutation is done by the installer or the explicit helper
                // named in setup_command / rollback_steps. Do not report
                // applied=true here; that made operators believe wide capture
                // was active when only a JSON plan had been printed.
                let v = if matches!(args.action, OperatorAction::Apply) {
                    "APPLY_PLAN_READY"
                } else {
                    "ROLLBACK_PLAN_READY"
                };
                (v.to_string(), false, None, Some(observe_status(mode)))
            }
        }
        // Switch is handled by the early return above.
        OperatorAction::Switch => unreachable!("switch handled before build_plan"),
    };

    let result = OperatorResult {
        artifact: "linux-operator-mode-action",
        verdict,
        applied,
        plan,
        error,
        status_observed,
    };
    let json = serde_json::to_string_pretty(&result).map_err(|e| format!("serialize: {e}"))?;
    if let Some(path) = &args.result_json {
        std::fs::write(path, &json).map_err(|e| format!("write {}: {e}", path.display()))?;
    }
    Ok(json)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(action: OperatorAction, mode: Option<OperatorMode>) -> OperatorArgs {
        OperatorArgs {
            action,
            mode,
            transport: None,
            policy: vec![],
            queue: None,
            ipv4: None,
            ipv6: None,
            controlled_prefix: None,
            controlled_peer: None,
            relay_exclude: None,
            bundle_url_file: None,
            bundle: None,
            listen: None,
            relay_address: None,
            apply_confirm: false,
            result_json: None,
            from: None,
            to: None,
            confirm: false,
            config_path: None,
            service_name: None,
            ipv6_route_policy: None,
            guarded_default_route_confirm: false,
            max_runtime_seconds: None,
            rollback_on_exit: false,
        }
    }

    #[test]
    fn plan_requires_mode() {
        let a = args(OperatorAction::Plan, None);
        assert!(build_plan(&a).is_err());
    }

    #[test]
    fn wide_modes_require_root() {
        assert!(OperatorMode::ClientWideTproxy.requires_root());
        assert!(OperatorMode::ClientWideNfqueueObserver.requires_root());
        assert!(OperatorMode::ClientIpv6TunLab.requires_root());
        assert!(!OperatorMode::ClientSocks.requires_root());
        assert!(!OperatorMode::CloudflareFronted.requires_root());
    }

    #[test]
    fn cloudflare_rejects_masque() {
        let mut a = args(OperatorAction::Plan, Some(OperatorMode::CloudflareFronted));
        a.transport = Some(TransportChoice::MasqueDirect);
        assert!(build_plan(&a).is_err());
    }

    #[test]
    fn tun_lab_rejects_global_prefix() {
        let mut a = args(OperatorAction::Plan, Some(OperatorMode::ClientIpv6TunLab));
        a.controlled_prefix = Some("2001:db8::/64".into());
        assert!(build_plan(&a).is_err());
        a.controlled_prefix = Some("fd00:ae61::/64".into());
        assert!(build_plan(&a).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn bundle_url_is_redacted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access-url");
        aegis_core::installer_secret::write_url(
            &path,
            "https://h.example.org/bundle.tar.gz?token=SECRET",
        )
        .unwrap();
        let mut a = args(OperatorAction::Plan, Some(OperatorMode::ClientSocks));
        a.bundle_url_file = Some(path);
        let plan = build_plan(&a).unwrap();
        let ref_ = plan.bundle_ref.unwrap();
        assert!(ref_.contains("h.example.org"));
        assert!(!ref_.contains("SECRET"));
    }

    #[cfg(unix)]
    #[test]
    fn actual_private_record_omits_userinfo_and_keeps_authority_port() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access-url");
        aegis_core::installer_secret::write_url(
            &path,
            "https://PRIVATE_USER:PRIVATE_PASSWORD@h.example.org:8443/private-path?token=PRIVATE_TOKEN#PRIVATE_FRAGMENT",
        ).unwrap();
        let mut a = args(OperatorAction::Plan, Some(OperatorMode::ClientSocks));
        a.bundle_url_file = Some(path);
        let output = run(&a).unwrap();
        assert!(output.contains("<bundle@h.example.org:8443>"));
        for private in [
            "PRIVATE_USER",
            "PRIVATE_PASSWORD",
            "private-path",
            "PRIVATE_TOKEN",
            "PRIVATE_FRAGMENT",
        ] {
            assert!(!output.contains(private));
        }
    }

    #[cfg(unix)]
    #[test]
    fn refused_private_record_creates_no_operator_output_and_preserves_sentinel() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access-url");
        let private = "https://h.example.org/?token=PRIVATE_SENTINEL";
        aegis_core::installer_secret::write_url(&path, private).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut a = args(OperatorAction::Plan, Some(OperatorMode::ClientSocks));
        a.bundle_url_file = Some(path.clone());
        let output = dir.path().join("operator-result.json");
        a.result_json = Some(output.clone());
        let refusal = run(&a).unwrap_err();
        assert_eq!(refusal, "operator: private bundle URL record refused");
        assert!(!output.exists());
        assert_eq!(std::fs::read_to_string(path).unwrap(), private);
    }

    #[test]
    fn opaque_archive_reference_does_not_open_or_echo_the_path() {
        let mut a = args(OperatorAction::Plan, Some(OperatorMode::ClientSocks));
        a.bundle = Some(std::path::PathBuf::from(
            "/unavailable/opaque-archive.tar.gz",
        ));
        assert_eq!(
            build_plan(&a).unwrap().bundle_ref.as_deref(),
            Some("<bundle-file>")
        );
        a.bundle_url_file = Some(std::path::PathBuf::from("/unavailable/access-url"));
        assert!(build_plan(&a).is_err());
    }

    #[test]
    fn apply_without_confirm_is_plan_only() {
        let a = args(OperatorAction::Apply, Some(OperatorMode::ClientSocks));
        let out = run(&a).unwrap();
        assert!(out.contains("PLAN_ONLY_NEEDS_CONFIRM"));
        assert!(out.contains("\"applied\": false"));
    }

    #[test]
    fn confirmed_apply_reports_plan_ready_not_applied_when_no_mutation_runs() {
        let mut a = args(OperatorAction::Apply, Some(OperatorMode::ClientSocks));
        a.apply_confirm = true;
        let out = run(&a).unwrap();
        assert!(out.contains("APPLY_PLAN_READY"));
        assert!(out.contains("\"applied\": false"));
        assert!(!out.contains("APPLY_READY"));
        assert!(!out.contains("\"applied\": true"));
    }

    #[test]
    fn switch_plan_only_without_confirm() {
        let mut a = args(OperatorAction::Switch, None);
        a.from = Some(OperatorMode::ClientSocks);
        a.to = Some(OperatorMode::CloudflareFronted);
        let out = run(&a).unwrap();
        assert!(out.contains("SWITCH_PLAN_ONLY"));
        assert!(out.contains("\"applied\": false"));
    }

    #[test]
    fn switch_requires_from_and_to() {
        let mut a = args(OperatorAction::Switch, None);
        a.confirm = true;
        assert!(run_switch(&a).is_err());
        a.from = Some(OperatorMode::ClientSocks);
        assert!(run_switch(&a).is_err());
    }

    #[test]
    fn switch_transform_reorders_transport_and_sets_backend() {
        use aegis_core::{Settings, TunnelTransportFamily, WidePlatformBackend};
        let mut s = Settings::default();
        apply_mode_to_settings(
            &mut s,
            OperatorMode::ClientWideTproxy,
            TransportChoice::GrpcStream,
        );
        assert_eq!(
            s.ingress.wide.platform_backend,
            WidePlatformBackend::LinuxTproxy
        );
        assert_eq!(
            s.relay.transport_priority.first(),
            Some(&TunnelTransportFamily::GrpcStream)
        );
    }

    // Regression: `do_switch` WRITES the config via `toml::to_string` and the
    // running client RE-PARSES it on restart. An in-memory `primary = Wide` is
    // useless if it does not survive that TOML round-trip — that is exactly the
    // "operator switch reports success but the client stays SOCKS-primary"
    // false-positive observed live. Assert the round-trip, not just memory.
    #[test]
    fn switch_wide_primary_survives_toml_roundtrip() {
        use aegis_core::{IngressPrimary, Settings};
        // Emulate a socks-primary install carrying real secrets.
        let mut s = Settings::default();
        s.ingress.primary = IngressPrimary::Socks5;
        s.ingress.wide.enabled = false;
        s.relay.server = "relay.example.org:443".into();
        s.relay.auth_token = "secret-token".into();

        apply_mode_to_settings(
            &mut s,
            OperatorMode::ClientWideRedirect,
            TransportChoice::Auto,
        );
        assert_eq!(
            s.ingress.primary,
            IngressPrimary::Wide,
            "in-memory transform"
        );

        // The exact write→read the switch performs.
        let serialized = toml::to_string(&s).expect("serialize config");
        let reparsed: Settings = toml::from_str(&serialized).expect("reparse config");

        assert_eq!(
            reparsed.ingress.primary,
            IngressPrimary::Wide,
            "ingress.primary reverted through the TOML write/read the switch does:\n{serialized}"
        );
        assert!(
            reparsed.ingress.wide.enabled,
            "ingress.wide.enabled lost through the round-trip:\n{serialized}"
        );
        assert_eq!(
            reparsed.relay.auth_token, "secret-token",
            "secret preserved"
        );
    }

    // Footgun regression: `operator switch --apply-confirm` (the confirmation
    // flag operators reach for by habit) must APPLY, not silently plan-only and
    // exit 0. Live, this false-positive read as "wide is active" when nothing
    // had changed.
    #[test]
    fn switch_accepts_apply_confirm_and_actually_applies() {
        use aegis_core::{IngressPrimary, Settings};
        let dir = std::env::temp_dir().join(format!(
            "aegis-switch-apply-confirm-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("aegis.toml");
        let mut s = Settings::default();
        s.ingress.primary = IngressPrimary::Socks5;
        s.relay.server = "relay.example.org:443".into();
        s.relay.auth_token = "tok".into();
        std::fs::write(&cfg, toml::to_string(&s).unwrap()).unwrap();

        let mut a = args(OperatorAction::Switch, None);
        a.from = Some(OperatorMode::ClientSocks);
        a.to = Some(OperatorMode::ClientSocks); // non-root target: applies anywhere
        a.confirm = false; // deliberately NOT --confirm ...
        a.apply_confirm = true; // ... only the habitual --apply-confirm
        a.config_path = Some(cfg.clone());

        let out = run_switch(&a).expect("apply-confirm switch must not error");
        assert!(
            out.contains("SWITCH_APPLIED"),
            "--apply-confirm must apply, not plan-only: {out}"
        );
        assert!(!out.contains("SWITCH_PLAN_ONLY"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // A confirmed switch that cannot apply must be a HARD failure (Err ->
    // non-zero exit), never a silent success.
    #[test]
    fn confirmed_switch_blocked_by_root_returns_err() {
        if is_root() {
            return; // can't exercise the needs-root block as root
        }
        let mut a = args(OperatorAction::Switch, None);
        a.from = Some(OperatorMode::ClientSocks);
        a.to = Some(OperatorMode::ClientWideTproxy); // requires root
        a.apply_confirm = true;
        let r = run_switch(&a);
        assert!(
            r.is_err(),
            "a confirmed switch blocked by missing root must return Err (non-zero exit)"
        );
        assert!(r.unwrap_err().contains("BLOCKED_NEEDS_ROOT"));
    }

    // A plan-only switch (no confirmation) is an intentional dry-run: Ok /
    // exit 0, but it must clearly say nothing changed.
    #[test]
    fn plan_only_switch_is_ok_but_says_nothing_changed() {
        let mut a = args(OperatorAction::Switch, None);
        a.from = Some(OperatorMode::ClientSocks);
        a.to = Some(OperatorMode::ClientSocks);
        a.confirm = false;
        a.apply_confirm = false;
        let out = run_switch(&a).expect("plan-only is not an error");
        assert!(out.contains("SWITCH_PLAN_ONLY"));
        assert!(out.contains("NOTHING was changed"));
    }

    #[test]
    fn known_mode_slugs_are_stable() {
        for (m, s) in [
            (OperatorMode::Server, "server"),
            (OperatorMode::ClientSocks, "client-socks"),
            (OperatorMode::ClientWideRedirect, "client-wide-redirect"),
            (OperatorMode::ClientWideTproxy, "client-wide-tproxy"),
            (
                OperatorMode::ClientWideNfqueueObserver,
                "client-wide-nfqueue-observer",
            ),
            (OperatorMode::ClientIpv6TunLab, "client-ipv6-tun-lab"),
            (
                OperatorMode::ClientIpv6TunSmoltcp,
                "client-ipv6-tun-smoltcp",
            ),
            (OperatorMode::CloudflareFronted, "cloudflare-fronted"),
            (OperatorMode::MasqueDirect, "masque-direct"),
        ] {
            assert_eq!(m.slug(), s);
        }
    }

    #[test]
    fn full_wide_tun_v6_mode_sets_ipv6_tun_carried() {
        let mut s = aegis_core::Settings::default();
        apply_mode_to_settings(
            &mut s,
            OperatorMode::ClientIpv6TunSmoltcp,
            TransportChoice::Auto,
        );
        assert!(s.ingress.wide.enabled);
        assert!(s.ingress.wide.ipv6_tun_carried);
        assert_eq!(s.ingress.primary, aegis_core::IngressPrimary::Wide);
        assert!(OperatorMode::ClientIpv6TunSmoltcp.requires_root());
    }
}
