use aegis_server::bundle_tokens::{BundleTokenError, BundleTokenStore};
use anyhow::Context;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

const BUILD_GIT_SHA: &str = env!("AEGIS_BUILD_GIT_SHA");
const BUILD_TIMESTAMP: &str = env!("AEGIS_BUILD_TIMESTAMP");
const BUILD_TARGET: &str = env!("AEGIS_BUILD_TARGET");
const BUILD_FEATURES: &str = env!("AEGIS_BUILD_FEATURES");
const CARGO_LOCK_SHA256: &str = env!("AEGIS_CARGO_LOCK_SHA256");

#[derive(Parser, Debug)]
#[command(about = "AEGIS relay server (TLS tunnel)", disable_version_flag = true)]
struct Args {
    /// Print version and build metadata.
    #[arg(long = "version", action = clap::ArgAction::SetTrue)]
    version: bool,

    #[arg(short, long, default_value = "aegis-server.toml")]
    config: PathBuf,

    /// After config loads, print one local optimizer preparation aggregate when
    /// instrumented server startup reaches readiness or exits. No connection
    /// identity or per-client event is recorded.
    #[arg(long)]
    optimizer_startup_report: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run an explicitly configured owned web-response ingress with device mTLS.
    Carrier(aegis_server::carrier::CarrierArgs),
    /// Run an owned WebRTC intermediary with separate verified-TLS signaling.
    #[cfg(feature = "webrtc-carrier")]
    Webrtc(aegis_server::webrtc::Args),
    /// Offline per-device enrollment and revocation (operator workstation).
    Device(aegis_server::devices::DeviceArgs),
    /// Export or pull a bounded private authorization policy over pinned SSH.
    DevicePolicy(aegis_server::device_policy::PolicyArgs),
    /// Run or validate the separate invitation-authorized enrollment authority.
    Enrollment(aegis_server::enrollment_service::EnrollmentArgs),
    /// Render a client installer from an independently trusted release profile.
    InstallLauncher {
        #[arg(long)]
        pins: PathBuf,
        #[arg(long)]
        bundle_url_file: Option<PathBuf>,
    },
    /// Private installer input protocol; never uses inline secret arguments.
    #[command(hide = true)]
    InstallerSecret {
        #[command(subcommand)]
        action: InstallerSecretAction,
    },
    /// Parse and validate the server configuration without binding listeners
    /// or printing secrets. Used by staged credential rollouts.
    ConfigCheck,

    /// Manage client bundle tokens served via `/bundle?token=...`
    /// endpoint (v0.2.0 S3).
    #[command(subcommand)]
    BundleToken(BundleTokenCmd),
}

#[derive(Subcommand, Debug)]
enum BundleTokenCmd {
    /// Issue a new one-time token backed by a pre-built client bundle
    /// tarball. Writes its access URL to a fresh private output file.
    /// Plaintext cannot be recovered later; transfer the file privately.
    Issue {
        /// Absolute path к the client-bundle.tar.gz to serve when this
        /// token is redeemed.
        #[arg(long)]
        bundle_path: PathBuf,
        /// Fresh absolute owner-private access URL output; never stdout.
        #[arg(long)]
        url_output: PathBuf,

        /// Override the default TTL. `0` means: use config default.
        #[arg(long, default_value_t = 0)]
        ttl_secs: u64,

        /// Optional human-readable comment (e.g. "operator: alice's laptop").
        #[arg(long)]
        comment: Option<String>,

        /// Public host (FQDN или IP) to use when printing the client
        /// curl one-liner. Falls back to parsing `cfg.listen` if absent;
        /// `cfg.listen = 0.0.0.0:8443` would otherwise produce a
        /// non-routable URL. install.sh auto-passes this from the
        /// resolved RELAY_ADDRESS so the printed URL points at the
        /// public IP/FQDN that clients can actually reach.
        #[arg(long)]
        public_host: Option<String>,

        /// Public port matching `--public-host`. Defaults to the port
        /// in `cfg.listen` (or 8443 if listen is unparseable).
        #[arg(long)]
        public_port: Option<u16>,

        /// SPKI public-key fingerprint of the relay TLS cert (base64,
        /// no padding, no `sha256//` prefix — just the raw 32-byte hash
        /// base64-encoded). When provided, the printed bundle URL gets
        /// `&pin=sha256//<value>` query param. Client-side curl uses
        /// `--pinnedpubkey "sha256//<value>"` to validate the relay's
        /// public key WITHOUT needing the CA, breaking the chicken-and-
        /// egg of CA delivery: the CA is inside the bundle, the bundle
        /// requires TLS to download. install.sh server auto-passes this
        /// from `${cert_dir}/server.spki.b64` written by
        /// `generate-relay-materials.sh`.
        #[arg(long)]
        public_cacert_pin: Option<String>,
    },

    /// List all tokens currently в the store (sha256 prefix + status).
    List,

    /// Prune tokens that expired more than the given retention window
    /// ago. Default 0 means "remove all expired regardless of age".
    Prune {
        #[arg(long, default_value_t = 0)]
        retain_after_expiry_secs: u64,
    },

    /// v0.3.7: Revoke a token by sha256 prefix (from `list` output).
    /// Marks consumed_at = now so subsequent /bundle redeem returns
    /// AlreadyConsumed (HTTP 410). Does NOT delete from store —
    /// preserves audit trail. Prefix must be unambiguous (multiple
    /// matches → error; pass longer prefix).
    Revoke {
        /// sha256_prefix from `bundle-token list` (16 hex chars by default).
        prefix: String,
    },

    /// v0.3.7: Print aggregate counts (issued / active / consumed /
    /// expired). Все local-only — no HTTP endpoint exposes these.
    Stats,
}

#[derive(Subcommand, Debug)]
enum InstallerSecretAction {
    Version,
    ReadToken {
        #[arg(long)]
        path: PathBuf,
    },
    ReadUrl {
        #[arg(long)]
        path: PathBuf,
    },
    TokenStdin,
    WriteUrlStdin {
        #[arg(long)]
        output: PathBuf,
    },
}
fn installer_secret(action: InstallerSecretAction) -> anyhow::Result<()> {
    use aegis_core::installer_secret as private;
    use std::io::Write;
    let text = match action {
        InstallerSecretAction::Version => {
            println!("installer-secret-v1");
            return Ok(());
        }
        InstallerSecretAction::ReadToken { path } => private::read_token(&path)?,
        InstallerSecretAction::ReadUrl { path } => private::read_url(&path)?,
        InstallerSecretAction::TokenStdin => private::token_from_stdin(std::io::stdin().lock())?,
        InstallerSecretAction::WriteUrlStdin { output } => {
            private::write_url_from_stdin(&output, std::io::stdin().lock())?;
            return Ok(());
        }
    };
    // Intended for a shell-owned private pipe, never an installation summary.
    std::io::stdout().lock().write_all(text.as_bytes())?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::args_os().skip(1).any(|arg| {
        let arg = arg.to_string_lossy();
        arg == "--bundle-url"
            || arg.starts_with("--bundle-url=")
            || arg == "--auth-token"
            || arg.starts_with("--auth-token=")
    }) {
        eprintln!("Inline installer secrets are refused; use a private --bundle-url-file or --auth-token-file.");
        std::process::exit(2);
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("info".parse().unwrap()),
        )
        .init();
    // The server binary uses rustls directly, so select the process-wide
    // provider explicitly instead of relying on test-only initialization.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args = Args::parse();
    if args.version {
        println!("{}", version_string("aegis-server"));
        return Ok(());
    }

    match args.command {
        Some(Command::Carrier(command)) => aegis_server::carrier::run(&command).await,
        #[cfg(feature = "webrtc-carrier")]
        Some(Command::Webrtc(command)) => aegis_server::webrtc::run(&command).await,
        Some(Command::Device(command)) => aegis_server::devices::run(command),
        Some(Command::DevicePolicy(command)) => aegis_server::device_policy::run(command)
            .await
            .map_err(Into::into),
        Some(Command::Enrollment(command)) => aegis_server::enrollment_service::run(command).await,
        None => run_server(&args.config, args.optimizer_startup_report).await,
        Some(Command::ConfigCheck) => handle_config_check(&args.config),
        Some(Command::InstallerSecret { action }) => installer_secret(action),
        Some(Command::InstallLauncher {
            pins,
            bundle_url_file,
        }) => {
            let profile = aegis_core::bootstrap_launcher::LauncherPins::load(&pins)
                .map_err(anyhow::Error::msg)?;
            let rendered = match bundle_url_file {
                Some(path) => profile.render_command(&path),
                None => profile.render_script(),
            }
            .map_err(anyhow::Error::msg)?;
            println!("{rendered}");
            Ok(())
        }
        Some(Command::BundleToken(cmd)) => handle_bundle_token_cmd(&args.config, cmd),
    }
}

fn handle_config_check(config_path: &PathBuf) -> anyhow::Result<()> {
    let cfg = aegis_server::config::load(config_path)
        .with_context(|| format!("load {}", config_path.display()))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let active_legacy = cfg
        .legacy_auth_tokens
        .iter()
        .filter(|token| now < token.not_after_unix_secs)
        .count();
    println!(
        "config ok: current=1 legacy={} active_legacy={}",
        cfg.legacy_auth_tokens.len(),
        active_legacy
    );
    Ok(())
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

async fn run_server(config_path: &PathBuf, optimizer_startup_report: bool) -> anyhow::Result<()> {
    // Branded startup line (flair). Suppressed via AEGIS_NO_BANNER.
    if std::env::var("AEGIS_NO_BANNER").as_deref() != Ok("1") {
        eprintln!(
            "▌ AEGIS relay · by AEGIS contributors · v{} — adaptive censorship-resilient transport",
            env!("CARGO_PKG_VERSION")
        );
    }
    let cfg = aegis_server::config::load(config_path)
        .with_context(|| format!("load {}", config_path.display()))?;
    if let Some(alias) = cfg.process_alias.as_deref() {
        if let Err(err) = aegis_core::apply_process_alias(alias) {
            aegis_server::log_process_alias_failure(&cfg.logging, alias, &err);
        }
    }
    if !optimizer_startup_report {
        return aegis_server::run_server(cfg).await;
    }
    let witness = aegis_server::phase_witness::ServerPhaseWitness::default();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let server = aegis_server::run_server_with_ready_and_witness(cfg, ready_tx, witness.clone());
    tokio::pin!(server);
    tokio::select! {
        result = &mut server => {
            eprintln!("{}", optimizer_startup_report_line(witness.optimizer_startup_snapshot()));
            result
        }
        ready = ready_rx => {
            // A closed readiness sender also gets a snapshot. The server
            // result below remains the authority for the startup error.
            let _ = ready;
            eprintln!("{}", optimizer_startup_report_line(witness.optimizer_startup_snapshot()));
            server.await
        }
    }
}

fn optimizer_startup_report_line(
    snapshot: aegis_server::phase_witness::OptimizerStartupSnapshot,
) -> String {
    format!(
        "optimizer_startup attempts={} completed={} failures={} total_wall_us={} total_process_cpu_us={} process_cpu_samples={} scope=prebind_process_aggregate",
        snapshot.attempts,
        snapshot.completed,
        snapshot.failures,
        snapshot.total_wall_us,
        snapshot.total_process_cpu_us,
        snapshot.process_cpu_samples,
    )
}

fn handle_bundle_token_cmd(config_path: &PathBuf, cmd: BundleTokenCmd) -> anyhow::Result<()> {
    let cfg = aegis_server::config::load(config_path)
        .with_context(|| format!("load {}", config_path.display()))?;
    let endpoint = &cfg.bundle_endpoint;
    if !endpoint.enabled {
        eprintln!(
            "warning: bundle endpoint is disabled в {}. Operator CLI commands still work, \n\
             but issued tokens will not be redeemable until the server is running with \n\
             `[bundle_endpoint] enabled = true`.",
            config_path.display()
        );
    }

    let mut store = BundleTokenStore::load(&endpoint.token_store_path).with_context(|| {
        format!(
            "load bundle token store {}",
            endpoint.token_store_path.display()
        )
    })?;

    match cmd {
        BundleTokenCmd::Issue {
            bundle_path,
            url_output,
            ttl_secs,
            comment,
            public_host,
            public_port,
            public_cacert_pin,
        } => {
            let launcher_profile = std::env::var_os("AEGIS_CLIENT_LAUNCHER_PINS")
                .map(|path| {
                    aegis_core::bootstrap_launcher::LauncherPins::load(&PathBuf::from(path))
                        .map_err(anyhow::Error::msg)
                })
                .transpose()?;
            let ttl = if ttl_secs == 0 {
                endpoint.default_token_ttl_secs
            } else {
                ttl_secs
            };
            let plaintext = store
                .issue(bundle_path.clone(), ttl, comment.clone())
                .context("issue token")?;
            // `cfg.listen` is the bind address (often 0.0.0.0:8443) and
            // is unsuitable as the URL host for clients. Prefer explicit
            // --public-host / --public-port flags; fall back to listen
            // parsing only when the operator hasn't supplied them.
            let listen = &cfg.listen;
            let listen_host = listen
                .rsplit_once(':')
                .map(|(host, _)| host)
                .unwrap_or(listen);
            let listen_port = listen
                .rsplit_once(':')
                .map(|(_, port)| port)
                .unwrap_or("8443");
            let server_host: String = match public_host.as_deref() {
                Some(h) if !h.is_empty() => h.to_string(),
                _ => listen_host.to_string(),
            };
            let server_port: String = match public_port {
                Some(p) => p.to_string(),
                None => listen_port.to_string(),
            };
            let server_host = server_host.as_str();
            let server_port = server_port.as_str();
            let pin_suffix = match public_cacert_pin.as_deref() {
                Some(pin) if !pin.is_empty() => format!(
                    "&pin=sha256//{}",
                    pin.strip_prefix("sha256//").unwrap_or(pin)
                ),
                _ => String::new(),
            };
            let url = format!(
                "https://{server_host}:{server_port}{}?token={plaintext}{pin_suffix}",
                endpoint.path_prefix
            );
            // Issuance committed above. Refusal/post-write sync failure is
            // reported statically, without retry or claiming transaction undo.
            aegis_core::installer_secret::write_url(&url_output, &url)?;
            println!(
                "Bundle access URL saved privately: {}",
                url_output.display()
            );
            if let Some(profile) = launcher_profile {
                println!(
                    "Transfer that record to an absolute owner-private client path before running:"
                );
                println!(
                    "{}",
                    profile
                        .render_command(&url_output)
                        .map_err(anyhow::Error::msg)?
                );
            }
        }
        BundleTokenCmd::List => {
            if store.is_empty() {
                println!(
                    "Bundle token store is empty ({}).",
                    endpoint.token_store_path.display()
                );
                return Ok(());
            }
            println!(
                "{:<18} {:<12} {:<12} {:<12} bundle_path (comment)",
                "sha256_prefix", "issued_at", "expires_at", "consumed_at"
            );
            for (sha, record) in store.iter_records() {
                let prefix: String = sha.chars().take(16).collect();
                let consumed = record
                    .consumed_at
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| "-".into());
                let comment = record
                    .comment
                    .clone()
                    .map(|c| format!(" ({c})"))
                    .unwrap_or_default();
                println!(
                    "{:<18} {:<12} {:<12} {:<12} {}{}",
                    prefix,
                    record.issued_at,
                    record.expires_at,
                    consumed,
                    record.bundle_path.display(),
                    comment,
                );
            }
            println!();
            println!(
                "Total: {} token(s) in {}",
                store.len(),
                endpoint.token_store_path.display()
            );
        }
        BundleTokenCmd::Prune {
            retain_after_expiry_secs,
        } => {
            let removed = store.prune(retain_after_expiry_secs)?;
            println!(
                "Pruned {} expired token(s). {} remain.",
                removed,
                store.len()
            );
        }
        BundleTokenCmd::Revoke { prefix } => match store.revoke_by_prefix(&prefix) {
            Ok(sha) => {
                let display_prefix: String = sha.chars().take(16).collect();
                println!("Revoked token sha256_prefix={display_prefix} (full sha256={sha}).");
                println!("Subsequent /bundle redeem requests for this token return HTTP 410.");
            }
            Err(BundleTokenError::NotFound) => {
                eprintln!("no token matched prefix {prefix:?} (or ambiguous — pass longer prefix)");
                std::process::exit(2);
            }
            Err(BundleTokenError::AlreadyConsumed) => {
                eprintln!("token matching prefix {prefix:?} is already consumed/revoked");
                std::process::exit(3);
            }
            Err(err) => {
                return Err(err.into());
            }
        },
        BundleTokenCmd::Stats => {
            let stats = store.stats();
            println!(
                "Bundle token store: {}",
                endpoint.token_store_path.display()
            );
            println!("  Total issued:   {}", stats.total);
            println!(
                "  Active:         {}  (issued, not consumed, not expired)",
                stats.active
            );
            println!(
                "  Consumed:       {}  (redeemed or operator-revoked)",
                stats.consumed
            );
            println!("  Expired:        {}", stats.expired);
        }
    }

    Ok(())
}

#[cfg(test)]
mod optimizer_startup_report_tests {
    use super::*;

    #[test]
    fn report_is_explicitly_aggregate_and_has_no_client_fields() {
        let line =
            optimizer_startup_report_line(aegis_server::phase_witness::OptimizerStartupSnapshot {
                attempts: 2,
                completed: 2,
                failures: 1,
                total_wall_us: 17,
                total_process_cpu_us: 9,
                process_cpu_samples: 1,
            });
        assert_eq!(line, "optimizer_startup attempts=2 completed=2 failures=1 total_wall_us=17 total_process_cpu_us=9 process_cpu_samples=1 scope=prebind_process_aggregate");
        let args = Args::try_parse_from(["aegis-server", "--optimizer-startup-report"]).unwrap();
        assert!(args.optimizer_startup_report);
        let ordinary = Args::try_parse_from(["aegis-server"]).unwrap();
        assert!(!ordinary.optimizer_startup_report);
    }
}
