//! `aegis-client profile | wide | doctor` — user-facing product-profile commands.
//!
//! These render and inspect the Rust-owned wide product model
//! ([`aegis_core::wide_product`]). The installer calls `profile resolve --json` to
//! print its post-install summary, so policy lives in exactly one place (Rust) and
//! Bash only orchestrates. Administrative metadata, installer transfer, and `profile switch`
//! can write their explicitly owned files. Switching records the product mode and prints commands
//! to enact it (it never silently mutates firewall/route state).

use std::path::{Path, PathBuf};

#[path = "profile_bundle_ca.rs"]
mod bundle_ca;
#[path = "profile_project_license.rs"]
mod project_license;
#[path = "profile_tproxy_diagnostics.rs"]
mod tproxy_diagnostics;

#[path = "profile_metadata.rs"]
mod metadata;
pub(crate) use metadata::read_install_metadata;
use metadata::{administrative_uid, write_install_metadata};

use aegis_core::wide_product::{
    WideDnsPolicy, WideIpv6Policy, WideProductMode, WideProductProfile, WideUdpPolicy,
};

/// `profile` subcommand group.
#[derive(clap::Args, Clone, Debug)]
pub struct ProfileArgs {
    #[command(subcommand)]
    pub action: ProfileAction,
}

#[derive(clap::Subcommand, Clone, Debug)]
pub enum ProfileAction {
    /// Administrative filesystem operations used by installed network helpers.
    #[command(hide = true)]
    Metadata(metadata::MetadataArgs),
    /// Owner-private access-file transfer used by the verified installer.
    #[command(hide = true)]
    InstallerSecret(InstallerSecretArgs),
    /// Private typed staging of the bundled MASQUE public CA.
    #[command(hide = true)]
    BundleCa(bundle_ca::Args),
    /// Closed, descriptor-anchored installation of authored public license texts.
    #[command(hide = true)]
    ProjectLicense(project_license::Args),
    /// Explicit installed relay outer Geneva profile administration.
    RelayGeneva(crate::profile_relay_geneva::Args),
    /// Resolve the minimum service privileges for the validated configuration.
    ServicePolicy(ServicePolicyArgs),
    /// Plan installation for this host without changing services or networking.
    Auto(crate::profile_auto::AutoArgs),
    /// Administrative configuration transaction; Linux root authority required.
    #[command(hide = true)]
    AutoConfig(crate::profile_auto_transaction_cli::Args),
    /// Read-only typed fields consumed by the installed Linux TPROXY helper.
    #[command(hide = true)]
    TproxyContract {
        #[arg(long)]
        config: PathBuf,
    },
    /// Read-only diagnostics shipped in the public client for the TPROXY helper.
    #[command(hide = true)]
    TproxyDiagnostics(tproxy_diagnostics::Args),
    /// Show the resolved profile for the recorded (or given) product mode.
    Show(ShowArgs),
    /// List every supported product mode and its one-line scope.
    List(JsonFlag),
    /// Resolve a mode (+ optional policy overrides) to a full profile. Used by
    /// the installer to render the post-install summary.
    Resolve(ResolveArgs),
    /// Record a product mode selection and print the commands to enact it.
    Switch(SwitchArgs),
}

#[derive(clap::Args, Clone, Debug)]
pub struct InstallerSecretArgs {
    #[command(subcommand)]
    pub action: InstallerSecretAction,
}
#[derive(clap::Subcommand, Clone, Debug)]
pub enum InstallerSecretAction {
    Version,
    #[command(hide = true)]
    CopyStdin {
        #[arg(long)]
        output: PathBuf,
    },
    Fetch {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 10)]
        connect_seconds: u64,
        #[arg(long, default_value_t = 120)]
        total_seconds: u64,
        #[arg(long)]
        pin: Option<String>,
        #[arg(long)]
        insecure: bool,
        #[arg(long)]
        local_only: bool,
        #[arg(long)]
        allow_local_path: bool,
    },
}
fn installer_secret(args: &InstallerSecretArgs) -> Result<(), String> {
    match &args.action {
        InstallerSecretAction::Version => {
            println!("installer-secret-v1");
            Ok(())
        }
        InstallerSecretAction::CopyStdin { output } => {
            aegis_core::installer_secret::copy_local_from_stdin(output)
                .map_err(|_| "private local copy failed".to_string())
        }
        InstallerSecretAction::Fetch {
            input,
            output,
            connect_seconds,
            total_seconds,
            pin,
            insecure,
            local_only,
            allow_local_path,
        } => {
            let worker = std::env::current_exe()
                .map_err(|_| "verified local worker unavailable".to_string())?;
            let result =
                aegis_core::installer_secret::fetch(aegis_core::installer_secret::Download {
                    input,
                    output,
                    connect_seconds: *connect_seconds,
                    total_seconds: *total_seconds,
                    pin: pin.as_deref(),
                    insecure: *insecure,
                    local_only: *local_only,
                    allow_local_path: *allow_local_path,
                    local_worker: &worker,
                });
            // The transfer owner concluded its bounded cleanup attempt. Keep
            // the original downloader status instead of converting every
            // finite transport failure into the client's generic exit1.
            if let Err(error) = result {
                eprintln!("{error}");
                std::process::exit(error.code.clamp(1, 255));
            }
            Ok(())
        }
    }
}

#[derive(clap::Args, Clone, Debug)]
pub struct ServicePolicyArgs {
    #[arg(long)]
    pub config: PathBuf,
    #[arg(long)]
    pub json: bool,
}

pub(crate) fn service_capabilities(config: &aegis_core::Settings) -> Option<Vec<&'static str>> {
    // The SOCKS backend never launches wide/TUN engines. Relay-only mode also
    // excludes the direct/raw strategy stack. Inner TLS identity provisioning
    // retains its explicit ownership gate until per-device service access is
    // configured; do not silently chown arbitrary credential paths here.
    if !matches!(config.mode, aegis_core::Mode::Relay)
        || config.ingress.primary != aegis_core::IngressPrimary::Socks5
        || config.relay.inner_tls.is_some()
    {
        return None;
    }
    Some(if config.socks.listen.port() < 1024 {
        vec!["CAP_NET_BIND_SERVICE"]
    } else {
        Vec::new()
    })
}

#[derive(clap::Args, Clone, Debug)]
pub struct ShowArgs {
    /// Product mode to show. Defaults to the recorded install mode if omitted.
    #[arg(long)]
    pub mode: Option<String>,
    #[arg(long)]
    pub json: bool,
}

#[derive(clap::Args, Clone, Debug)]
pub struct JsonFlag {
    #[arg(long)]
    pub json: bool,
}

#[derive(clap::Args, Clone, Debug)]
pub struct ResolveArgs {
    #[arg(long)]
    pub mode: String,
    /// Override UDP policy: native|block|masque_direct|preview_allowlist.
    #[arg(long)]
    pub udp: Option<String>,
    /// Override DNS policy: native|preview|block.
    #[arg(long)]
    pub dns: Option<String>,
    /// Override IPv6 policy: native|block|capture|tun_carried.
    #[arg(long)]
    pub ipv6: Option<String>,
    /// Egress interface to display in the summary (informational).
    #[arg(long)]
    pub interface: Option<String>,
    #[arg(long)]
    pub json: bool,
}

#[derive(clap::Args, Clone, Debug)]
pub struct SwitchArgs {
    /// Target product mode.
    #[arg(long = "to")]
    pub to: String,
    #[arg(long)]
    pub json: bool,
}

/// `wide status` — report wide capture runtime status (read-only, best-effort).
#[derive(clap::Args, Clone, Debug)]
pub struct WideArgs {
    #[command(subcommand)]
    pub action: WideAction,
}

#[derive(clap::Subcommand, Clone, Debug)]
pub enum WideAction {
    /// Print the current wide product mode + resolved policies + rule presence.
    Status(JsonFlag),
}

/// `doctor` — environment diagnostics for wide modes (read-only).
#[derive(clap::Args, Clone, Debug)]
pub struct DoctorArgs {
    #[arg(long)]
    pub json: bool,
}

fn parse_mode(s: &str) -> Result<WideProductMode, String> {
    WideProductMode::parse_str(s).ok_or_else(|| {
        let all: Vec<&str> = WideProductMode::all().iter().map(|m| m.as_str()).collect();
        format!(
            "unknown product mode '{s}'. Valid modes: {}",
            all.join(", ")
        )
    })
}

fn parse_udp(s: &str) -> Result<WideUdpPolicy, String> {
    WideUdpPolicy::parse_str(s).ok_or_else(|| format!("invalid udp policy '{s}'"))
}
fn parse_dns(s: &str) -> Result<WideDnsPolicy, String> {
    WideDnsPolicy::parse_str(s).ok_or_else(|| format!("invalid dns policy '{s}'"))
}
fn parse_ipv6(s: &str) -> Result<WideIpv6Policy, String> {
    WideIpv6Policy::parse_str(s).ok_or_else(|| format!("invalid ipv6 policy '{s}'"))
}

/// Candidate state directories the installer may use, in priority order.
fn state_dirs() -> Vec<PathBuf> {
    let mut v = vec![
        PathBuf::from("/var/lib/aegis-install/auto-client"),
        PathBuf::from("/var/lib/aegis-install/client"),
    ];
    if administrative_uid() == 0 {
        return v;
    }
    if let Ok(dir) = std::env::var("AEGIS_STATE_DIR") {
        if !dir.is_empty() {
            v.push(PathBuf::from(dir));
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        v.push(PathBuf::from(home).join(".local/state/aegis"));
    }
    v
}

/// Read the recorded product mode, if the installer wrote one.
fn recorded_product_mode() -> Option<WideProductMode> {
    for dir in state_dirs() {
        let p = dir.join("wide-profile.json");
        if let Ok(text) = read_install_metadata(&p) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                if let Some(m) = v.get("product_mode").and_then(|x| x.as_str()) {
                    if let Some(mode) = WideProductMode::parse_str(m) {
                        return Some(mode);
                    }
                }
            }
        }
    }
    None
}

fn profile_json(p: &WideProductProfile, interface: Option<&str>) -> serde_json::Value {
    let mut v = serde_json::to_value(p).unwrap_or(serde_json::Value::Null);
    if let (Some(obj), Some(iface)) = (v.as_object_mut(), interface) {
        obj.insert(
            "interface".into(),
            serde_json::Value::String(iface.to_string()),
        );
    }
    v
}

fn print_human_summary(p: &WideProductProfile, interface: Option<&str>) {
    let iface = interface.unwrap_or("(default route)");
    let socks = if p.socks_fallback {
        "available (per-app)"
    } else {
        "none"
    };
    println!("Active mode:   {}", p.mode);
    println!("Scope:         {}", p.scope.as_str());
    println!("TCP IPv4:      {}", p.tcp_ipv4);
    println!("DNS UDP/53:    {}", p.dns_policy.as_str());
    println!("Generic UDP:   {}", p.udp_policy.as_str());
    println!("QUIC/HTTP3:    {}", p.quic.as_str());
    println!("WebRTC UDP:    {}", p.webrtc);
    println!("IPv6:          {}", p.ipv6_policy.as_str());
    println!("Backend:       {:?}", p.platform_backend);
    println!("Interface:     {iface}");
    println!("SOCKS fallback:{socks}");
    println!("Leak risk:     {}", p.leak_risk.as_str());
    println!("Note:          {}", p.summary_note);
    if matches!(p.leak_risk, aegis_core::wide_product::WideLeakRisk::High) {
        println!();
        println!("  ⚠  HIGH LEAK RISK: UDP/DNS/IPv6 may egress natively in this mode.");
        println!("     Do NOT use on a hostile/censored network. Prefer wide-redirect-safe");
        println!("     or full-wide-nfqueue for fail-closed behaviour.");
    }
    println!();
    println!("Next commands:");
    println!("  aegis-client profile show");
    println!("  aegis-client wide status");
    println!("  aegis-client doctor");
}

/// Entry point: returns Ok(()) on success, Err(msg) on user/validation error.
pub fn run_profile(args: &ProfileArgs) -> Result<(), String> {
    match &args.action {
        ProfileAction::ServicePolicy(args) => {
            let config = crate::config::load_config(&args.config).map_err(|_| {
                "Service policy requires a valid, trusted client configuration".to_string()
            })?;
            let capabilities = service_capabilities(&config);
            let value = serde_json::json!({
                "schema": "aegis_client_service_policy_v1",
                "dedicated_uid": capabilities.is_some(),
                "capabilities": capabilities.unwrap_or_default(),
            });
            if args.json {
                println!("{value}");
            } else {
                println!("Service policy: {value}");
            }
            Ok(())
        }
        ProfileAction::RelayGeneva(a) => crate::profile_relay_geneva::run(a),
        ProfileAction::Metadata(a) => metadata::run(a).map_err(|e| e.to_string()),
        ProfileAction::InstallerSecret(a) => installer_secret(a),
        ProfileAction::BundleCa(a) => bundle_ca::run(a),
        ProfileAction::ProjectLicense(a) => project_license::run(a),
        ProfileAction::Auto(a) => crate::profile_auto::run(a),
        ProfileAction::AutoConfig(a) => crate::profile_auto_transaction_cli::run(&a.words),
        ProfileAction::TproxyContract { config } => tproxy_contract(config),
        ProfileAction::TproxyDiagnostics(args) => tproxy_diagnostics::run(args),
        ProfileAction::List(j) => {
            if j.json {
                let arr: Vec<serde_json::Value> = WideProductMode::all()
                    .iter()
                    .map(|m| profile_json(&m.default_profile(), None))
                    .collect();
                println!("{}", serde_json::to_string_pretty(&arr).unwrap());
            } else {
                println!("Supported wide product modes:");
                for m in WideProductMode::all() {
                    let p = m.default_profile();
                    println!(
                        "  {:<18} scope={:<10} leak_risk={:<8} {}",
                        m.as_str(),
                        p.scope.as_str(),
                        p.leak_risk.as_str(),
                        if p.safe_for_hostile_network {
                            "[safe]"
                        } else {
                            "[NOT for hostile networks]"
                        }
                    );
                }
            }
            Ok(())
        }
        ProfileAction::Show(s) => {
            let mode = match &s.mode {
                Some(m) => parse_mode(m)?,
                None => recorded_product_mode().ok_or_else(|| {
                    "no product mode recorded and none given; pass --mode <mode> \
                     (e.g. --mode full-wide-nfqueue)"
                        .to_string()
                })?,
            };
            let p = mode.default_profile();
            if s.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&profile_json(&p, None)).unwrap()
                );
            } else {
                print_human_summary(&p, None);
            }
            Ok(())
        }
        ProfileAction::Resolve(r) => {
            let mode = parse_mode(&r.mode)?;
            let udp = r.udp.as_deref().map(parse_udp).transpose()?;
            let dns = r.dns.as_deref().map(parse_dns).transpose()?;
            let ipv6 = r.ipv6.as_deref().map(parse_ipv6).transpose()?;
            let p = mode.resolve(udp, dns, ipv6)?;
            if r.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&profile_json(&p, r.interface.as_deref()))
                        .unwrap()
                );
            } else {
                print_human_summary(&p, r.interface.as_deref());
            }
            Ok(())
        }
        ProfileAction::Switch(sw) => {
            let mode = parse_mode(&sw.to)?;
            let p = mode.default_profile();
            record_product_mode(mode).map_err(|e| format!("record product mode: {e}"))?;
            if sw.json {
                let mut v = profile_json(&p, None);
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("recorded".into(), serde_json::Value::Bool(true));
                }
                println!("{}", serde_json::to_string_pretty(&v).unwrap());
            } else {
                println!("Recorded product mode: {}", mode.as_str());
                println!();
                print_human_summary(&p, None);
                println!();
                println!("To enact this mode, run the privileged steps for its backend:");
                for om in p.internal_operator_modes {
                    println!("  sudo aegis-client operator apply --mode {om} --apply-confirm");
                }
            }
            Ok(())
        }
    }
}

fn tproxy_contract(path: &Path) -> Result<(), String> {
    use aegis_core::{IngressPrimary, WideUdpCaptureContract};

    // Read through the same typed, owner-checked configuration path as the
    // installed client. Emit only fixed keys and bounded public policy values;
    // never render the configuration or its parse errors to operator output.
    let cfg = crate::config::load_config(path)
        .map_err(|_| "client config contract unavailable or invalid".to_string())?;
    let wide = &cfg.ingress.wide;
    let interface = wide.prerouting_interface.as_deref().unwrap_or("");
    if !interface.is_empty()
        && (interface.len() > 15
            || !interface.as_bytes()[0].is_ascii_alphanumeric()
            || !interface
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._@-".contains(&byte)))
    {
        return Err("client TPROXY interface scope invalid".to_string());
    }
    let backend = crate::wide_platform_code(wide.platform_backend);
    let profile = crate::wide_rollout_profile_code(wide.rollout_profile);
    let family = if wide.listen.is_ipv6() {
        "ipv6"
    } else {
        "ipv4"
    };
    let contract = match wide.udp_capture_contract {
        WideUdpCaptureContract::PreviewAllowlistOnly => "preview_allowlist_only",
        WideUdpCaptureContract::GenericCaptureUnstable => "generic_capture_unstable",
    };
    let support_tier = if contract == "generic_capture_unstable" {
        "guarded_unstable"
    } else {
        "supported_preview"
    };
    let capture_policy = if contract == "generic_capture_unstable" {
        if family == "ipv6" {
            "any_target_port_linux_ipv6_unstable"
        } else {
            "any_target_port_linux_ipv4_unstable"
        }
    } else {
        "allowlist_ports"
    };
    let runtime_scope = if family == "ipv6" {
        "linux_ipv6_only"
    } else {
        "linux_ipv4_only"
    };
    let mut preview_ports = Vec::new();
    for port in &wide.udp_preview_ports {
        if *port != wide.dns_port && !preview_ports.contains(port) {
            preview_ports.push(*port);
        }
    }
    let preview_ports = preview_ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");

    println!(
        "CFG_INGRESS_PRIMARY\t{}",
        match cfg.ingress.primary {
            IngressPrimary::Wide => "wide",
            IngressPrimary::Socks5 => "socks5",
        }
    );
    println!("CFG_WIDE_ENABLED\t{}", u8::from(wide.enabled));
    println!("CFG_WIDE_BACKEND\t{backend}");
    println!("CFG_WIDE_PROFILE\t{profile}");
    println!("CFG_WIDE_INTERFACE\t{interface}");
    println!("CFG_WIDE_LISTEN_PORT\t{}", wide.listen.port());
    println!("CFG_WIDE_LISTEN_FAMILY\t{family}");
    println!("CFG_CAPTURE_DNS\t{}", u8::from(wide.capture_dns));
    println!("CFG_UDP_CAPTURE_CONTRACT\t{contract}");
    if wide.capture_dns {
        println!("CFG_UDP_CAPTURE_SUPPORT_TIER\t{support_tier}");
        println!("CFG_UDP_CAPTURE_POLICY\t{capture_policy}");
        println!("CFG_UDP_CAPTURE_RUNTIME_SCOPE\t{runtime_scope}");
    }
    println!("CFG_DNS_PORT\t{}", wide.dns_port);
    println!("CFG_UDP_PREVIEW_PORTS\t{preview_ports}");
    println!("CFG_DEFAULT_MARK\t{}", wide.default_mark);
    Ok(())
}

/// Write the selected product mode to the first writable state dir.
fn record_product_mode(mode: WideProductMode) -> std::io::Result<()> {
    let p = mode.default_profile();
    let body = serde_json::json!({
        "product_mode": mode.as_str(),
        "udp_policy": p.udp_policy.as_str(),
        "dns_policy": p.dns_policy.as_str(),
        "ipv6_policy": p.ipv6_policy.as_str(),
        "leak_risk": p.leak_risk.as_str(),
        "is_wide": p.is_wide,
    });
    let text = serde_json::to_string_pretty(&body).unwrap();
    let mut last_err = std::io::Error::other("no writable state dir");
    for dir in state_dirs() {
        let path = dir.join("wide-profile.json");
        match write_install_metadata(&path, &text) {
            Ok(()) => return Ok(()),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

pub fn run_wide(args: &WideArgs) -> Result<(), String> {
    match &args.action {
        WideAction::Status(j) => {
            let mode = recorded_product_mode();
            let chains = detect_aegis_chains();
            if j.json {
                let v = serde_json::json!({
                    "product_mode": mode.map(|m| m.as_str()),
                    "resolved": mode.map(|m| profile_json(&m.default_profile(), None)),
                    "aegis_firewall_chains_present": chains,
                });
                println!("{}", serde_json::to_string_pretty(&v).unwrap());
            } else {
                match mode {
                    Some(m) => {
                        println!("Wide product mode: {}", m.as_str());
                        print_human_summary(&m.default_profile(), None);
                    }
                    None => println!(
                        "Wide product mode: (none recorded)\nRun: aegis-client profile switch --to <mode>"
                    ),
                }
                println!();
                println!(
                    "AEGIS firewall chains present: {}",
                    if chains.is_empty() {
                        "none detected".to_string()
                    } else {
                        chains.join(", ")
                    }
                );
            }
            Ok(())
        }
    }
}

/// Best-effort detection of AEGIS-owned firewall chains (read-only; no mutation).
fn detect_aegis_chains() -> Vec<String> {
    let mut found = Vec::new();
    let candidates = [
        ("iptables", "AEGIS_WIDE_OUTPUT"),
        ("iptables", "AEGIS_WIDE_NFQ"),
        ("iptables", "AEGIS_WIDE_TPROXY"),
        ("ip6tables", "AEGIS_WIDE_V6"),
        ("ip6tables", "AEGIS_WIDE_NFQ"),
    ];
    for (bin, chain) in candidates {
        if chain_exists(bin, chain) {
            found.push(format!("{bin}:{chain}"));
        }
    }
    found
}

fn chain_exists(bin: &str, chain: &str) -> bool {
    // `-S <chain>` lists rules in the chain; exit 0 means it exists. Requires
    // root in practice; on non-root this returns false (best-effort).
    std::process::Command::new(bin)
        .args(["-w", "2", "-S", chain])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn run_doctor(args: &DoctorArgs) -> Result<(), String> {
    let euid_root = is_root();
    let iptables = which("iptables");
    let ip6tables = which("ip6tables");
    let nft = which("nft");
    let nfqueue = nfqueue_available();
    let resolved_active = systemd_resolved_active();
    let proxy_env = proxy_env_set();
    let mode = recorded_product_mode();

    if args.json {
        let v = serde_json::json!({
            "euid_root": euid_root,
            "iptables_present": iptables,
            "ip6tables_present": ip6tables,
            "nft_present": nft,
            "nfqueue_available": nfqueue,
            "systemd_resolved_active": resolved_active,
            "proxy_env_set": proxy_env,
            "recorded_product_mode": mode.map(|m| m.as_str()),
        });
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
        return Ok(());
    }

    let ok = |b: bool| if b { "OK " } else { "WARN" };
    println!("AEGIS doctor — wide-mode environment checks");
    println!(
        "  [{}] running as root (needed for wide apply)",
        ok(euid_root)
    );
    println!("  [{}] iptables present", ok(iptables));
    println!(
        "  [{}] ip6tables present (IPv6 fail-closed/capture)",
        ok(ip6tables)
    );
    println!("  [{}] nft present (optional alt backend)", ok(nft));
    println!("  [{}] NFQUEUE available (nfnetlink_queue)", ok(nfqueue));
    println!(
        "  [INFO] systemd-resolved {}",
        if resolved_active {
            "active (DNS preview may need it stopped on :53)"
        } else {
            "inactive"
        }
    );
    println!(
        "  [{}] no proxy env vars set (wide proof must be no-proxy)",
        ok(!proxy_env)
    );
    match mode {
        Some(m) => println!("  [INFO] recorded product mode: {}", m.as_str()),
        None => println!("  [INFO] no product mode recorded yet"),
    }
    Ok(())
}

fn is_root() -> bool {
    // SAFETY: geteuid is always-safe (no args, no memory effects).
    #[cfg(unix)]
    unsafe {
        libc::geteuid() == 0
    }
    #[cfg(not(unix))]
    {
        false
    }
}

fn which(bin: &str) -> bool {
    std::process::Command::new(bin)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn nfqueue_available() -> bool {
    // Loaded module exposes this proc file; otherwise check the module file is
    // present (loadable) under the running kernel's module tree.
    if Path::new("/proc/net/netfilter/nfnetlink_queue").exists() {
        return true;
    }
    if let Ok(uname) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        let rel = uname.trim();
        let base = format!("/lib/modules/{rel}/kernel/net/netfilter");
        for ext in ["ko", "ko.zst", "ko.xz", "ko.gz"] {
            if Path::new(&format!("{base}/nfnetlink_queue.{ext}")).exists() {
                return true;
            }
        }
    }
    false
}

fn systemd_resolved_active() -> bool {
    std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", "systemd-resolved"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn proxy_env_set() -> bool {
    [
        "http_proxy",
        "https_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "all_proxy",
    ]
    .iter()
    .any(|k| std::env::var(k).map(|v| !v.is_empty()).unwrap_or(false))
}

/// Fixed selected-profile operational records; this seam cannot mutate arbitrary
/// paths or change the ordinary metadata API's file modes.
pub(crate) fn write_relay_geneva_record(name: &str, text: &str) -> std::io::Result<()> {
    if ![
        "relay-geneva-profile.json",
        "relay-geneva-guard-state.json",
        "relay-geneva-guard-intent.json",
        "relay-geneva-install-intent.json",
        "relay-geneva-teardown.json",
    ]
    .contains(&name)
    {
        return Err(std::io::Error::other(
            "selected profile record name refused",
        ));
    }
    let path = PathBuf::from("/var/lib/aegis-install/client").join(name);
    if matches!(
        name,
        "relay-geneva-profile.json"
            | "relay-geneva-install-intent.json"
            | "relay-geneva-teardown.json"
    ) {
        metadata::create_record(&path, text, 0o600)
    } else {
        metadata::write_record(&path, text, 0o600, false)
    }
}
#[cfg(target_os = "linux")]
pub(crate) fn remove_relay_geneva_intent() -> std::io::Result<()> {
    metadata::remove(Path::new(
        "/var/lib/aegis-install/client/relay-geneva-guard-intent.json",
    ))
}

pub(crate) fn archive_relay_geneva_record(text: &str) -> std::io::Result<()> {
    metadata::archive_relay_geneva_record(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mode_rejects_garbage() {
        assert!(parse_mode("nope").is_err());
        assert!(parse_mode("full-wide-nfqueue").is_ok());
    }

    #[test]
    fn service_policy_limits_socks_relay_capabilities() {
        let mut config = aegis_core::Settings {
            mode: aegis_core::Mode::Relay,
            ..Default::default()
        };
        config.ingress.primary = aegis_core::IngressPrimary::Socks5;
        config.socks.listen = "127.0.0.1:1080".parse().unwrap();
        assert_eq!(service_capabilities(&config), Some(vec![]));
        config.socks.listen = "127.0.0.1:443".parse().unwrap();
        assert_eq!(
            service_capabilities(&config),
            Some(vec!["CAP_NET_BIND_SERVICE"])
        );
        config.mode = aegis_core::Mode::Direct;
        assert_eq!(service_capabilities(&config), None);
        config.mode = aegis_core::Mode::Relay;
        config.ingress.primary = aegis_core::IngressPrimary::Wide;
        assert_eq!(service_capabilities(&config), None);
    }

    #[cfg(unix)]
    #[test]
    fn metadata_writer_replaces_inode_and_rejects_untrusted_paths() {
        use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("metadata").join("wide-profile.json");
        write_install_metadata(&path, "first").unwrap();
        let old_inode = std::fs::metadata(&path).unwrap().ino();
        write_install_metadata(&path, "second").unwrap();
        assert_eq!(read_install_metadata(&path).unwrap(), "second");
        assert_ne!(std::fs::metadata(&path).unwrap().ino(), old_inode);
        let link = directory.path().join("metadata").join("link");
        symlink(&path, &link).unwrap();
        assert!(read_install_metadata(&link).is_err());
        assert!(write_install_metadata(&link, "invalid").is_err());
        let parent_link = directory.path().join("parent-link");
        symlink(path.parent().unwrap(), &parent_link).unwrap();
        assert!(read_install_metadata(&parent_link.join("wide-profile.json")).is_err());
        std::fs::set_permissions(
            path.parent().unwrap(),
            std::fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        assert!(read_install_metadata(&path).is_err());
        assert!(write_install_metadata(&path, "invalid").is_err());
        std::fs::set_permissions(
            path.parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "second");
    }

    #[test]
    fn authoritative_install_metadata_excludes_runtime_state() {
        let dirs = state_dirs();
        assert_eq!(dirs[0], PathBuf::from("/var/lib/aegis-install/auto-client"));
        assert_eq!(dirs[1], PathBuf::from("/var/lib/aegis-install/client"));
        assert!(!dirs.contains(&PathBuf::from("/var/lib/aegis-client")));
        assert!(!dirs.contains(&PathBuf::from("/var/lib/aegis")));
    }

    #[test]
    fn resolve_safe_native_udp_is_error() {
        let r = ResolveArgs {
            mode: "wide-redirect-safe".into(),
            udp: Some("native".into()),
            dns: None,
            ipv6: None,
            interface: None,
            json: true,
        };
        let args = ProfileArgs {
            action: ProfileAction::Resolve(r),
        };
        assert!(run_profile(&args).is_err());
    }
}
