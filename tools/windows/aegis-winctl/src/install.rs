//! Fresh, private Windows installations. Upgrades use a new version directory;
//! the old installation is never overwritten or adopted implicitly.
#[cfg(test)]
#[path = "install_authenticode_tests.rs"]
mod authenticode_tests;
#[cfg(test)]
#[path = "install_native_tests.rs"]
mod native_tests;
mod operator;
mod reboot;
use super::{package, service, ServiceCommand, ServiceInstallArgs, ServiceNameArg, WinctlError};
use aegis_core::{windows_file, IngressPrimary, Mode, Settings};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

fn remove_verified_binary(path: &Path, deadline: Instant) -> std::io::Result<()> {
    loop {
        match fs::remove_file(path) {
            Ok(()) => return Ok(()),
            Err(error)
                if matches!(error.raw_os_error(), Some(5 | 32 | 33))
                    && Instant::now() < deadline =>
            {
                // Windows ARM's XtaCache can retain an x64 image after its
                // process exits. Only wait for transient access/sharing locks;
                // never stop system services, weaken ACLs or schedule deletion
                // of a pathname that might belong to a future installation.
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => {
                return Err(std::io::Error::new(
                    error.kind(),
                    format!(
                        "removing verified installed binary {}: {error}; file retained, retry uninstall after its holder releases it",
                        path.file_name().unwrap_or_default().to_string_lossy()
                    ),
                ));
            }
        }
    }
}

#[cfg(test)]
struct MachineFixture {
    path: PathBuf,
}
#[cfg(test)]
impl MachineFixture {
    fn new(label: &str) -> Self {
        assert!(
            super::is_elevated(),
            "Machine fixture requires an administrator"
        );
        let parent = ["ProgramData", "ProgramFiles"]
            .into_iter()
            .filter_map(std::env::var_os)
            .map(PathBuf::from)
            .find(|parent| windows_file::trusted_system_directory(parent).is_ok())
            .expect("Machine fixture requires an existing trusted ProgramData/ProgramFiles");
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = parent.join(format!(
            "AEGIS-Install-Fixture-{label}-{}-{nonce}",
            std::process::id()
        ));
        // Create a new child only. Existing parents are never adopted/re-ACLed.
        windows_file::create_machine_private_directory(&path).unwrap();
        let fixture = Self { path };
        windows_file::trusted_system_directory(fixture.path()).unwrap();
        fixture
    }

    fn path(&self) -> &Path {
        &self.path
    }
}
#[cfg(test)]
impl Drop for MachineFixture {
    fn drop(&mut self) {
        // The guard owns only the successfully create-new Machine child.
        if windows_file::trusted_system_directory(&self.path).is_ok() {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[derive(Args)]
pub(super) struct ClientArgs {
    #[command(subcommand)]
    command: ClientCommand,
}
#[derive(Subcommand)]
enum ClientCommand {
    /// Record and compare installed Wintun service state across a manual reboot.
    RebootCheck(reboot::RebootArgs),
    /// Import an existing relay profile into a private Windows system-tunnel profile.
    PrepareConfig(operator::PrepareArgs),
    /// Validate this installation and start its owned service.
    Connect {
        #[arg(long)]
        root: PathBuf,
    },
    /// Stop this installation and explicitly remove its tunnel protection.
    Disconnect {
        #[arg(long)]
        root: PathBuf,
    },
    /// Inspect integrity, configuration, service, adapter and protection without connecting.
    Doctor {
        #[arg(long)]
        root: PathBuf,
    },
    Install(InstallArgs),
    /// Stage a verified version and switch the existing service, retaining rollback.
    Upgrade {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        package: PathBuf,
        #[command(flatten)]
        trust: package::trust::TrustArgs,
        #[command(flatten)]
        authenticode: package::AuthenticodePolicyArgs,
        #[arg(long)]
        new_root: PathBuf,
    },
    /// Return the service to the verified installation recorded during upgrade.
    Rollback {
        #[arg(long)]
        root: PathBuf,
    },
    Status {
        #[arg(long)]
        root: PathBuf,
    },
    Uninstall {
        #[arg(long)]
        root: PathBuf,
    },
}
#[derive(Args)]
struct InstallArgs {
    #[arg(long)]
    package: PathBuf,
    #[command(flatten)]
    trust: package::trust::TrustArgs,
    #[command(flatten)]
    authenticode: package::AuthenticodePolicyArgs,
    #[arg(long)]
    config: PathBuf,
    /// Immutable v3 public profile; device identity remains outside version directories.
    #[arg(long)]
    device_online_bundle: Option<PathBuf>,
    /// New absolute directory. Existing installations are never overwritten.
    #[arg(long)]
    root: PathBuf,
    /// Register a managed service (LocalSystem for a system tunnel, otherwise LocalService).
    #[arg(long)]
    service: bool,
    #[arg(long, default_value = "AegisClient")]
    service_name: String,
    #[arg(long, requires = "service")]
    start: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: u32,
    manifest_sha256: String,
    #[serde(default)]
    publisher_signature_verified: bool,
    service: bool,
    binaries: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    license_files: BTreeMap<String, String>,
    #[serde(default)]
    system_tunnel: bool,
    #[serde(default)]
    managed_online: bool,
    #[serde(default = "default_service_name")]
    service_name: String,
    /// Recorded when staging; later elevation must never promote a User receipt.
    #[serde(default)]
    access_policy: Option<InstallAccess>,
}
impl Receipt {
    fn access(&self) -> Result<InstallAccess, WinctlError> {
        InstallAccess::for_receipt(self.service, self.system_tunnel, self.access_policy)
    }
}
fn default_service_name() -> String {
    "AegisClient".into()
}
fn invalid(message: &str) -> WinctlError {
    WinctlError::ArtifactValidation(message.into())
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InstallAccess {
    User,
    LocalService,
    Machine,
}
impl InstallAccess {
    fn for_profile(service: bool, system_tunnel: bool) -> Self {
        match (service, system_tunnel) {
            (true, true) => Self::Machine,
            (true, false) => Self::LocalService,
            (false, _) => Self::User,
        }
    }

    fn for_install(service: bool, system_tunnel: bool, elevated: bool) -> Self {
        if service {
            Self::for_profile(service, system_tunnel)
        } else if elevated {
            Self::Machine
        } else {
            Self::User
        }
    }

    fn for_receipt(
        service: bool,
        system_tunnel: bool,
        recorded: Option<Self>,
    ) -> Result<Self, WinctlError> {
        let legacy = Self::for_profile(service, system_tunnel);
        let access = recorded.unwrap_or(legacy);
        if (service && access != legacy)
            || (!service && access == Self::LocalService)
            || (system_tunnel && access != Self::Machine)
        {
            return Err(invalid("install access policy conflicts with profile"));
        }
        Ok(access)
    }

    fn validate_parent(self, root: &Path, elevated: bool) -> Result<(), WinctlError> {
        if self != Self::User || elevated {
            // A protected child can still be replaced through a writable
            // ancestor. LocalService SOCKS and LocalSystem tunnel services
            // therefore require the same administrator-owned ancestry.
            windows_file::trusted_system_directory(
                root.parent()
                    .ok_or_else(|| invalid("missing install parent"))?,
            )?;
        }
        Ok(())
    }

    fn validate_execution(self, root: &Path, elevated: bool) -> Result<(), WinctlError> {
        if self == Self::User && elevated {
            return Err(invalid(
                "elevated execution refuses a User-policy installation; stage a new Machine-policy installation",
            ));
        }
        self.validate_parent(root, elevated)?;
        for path in [root.to_path_buf(), root.join("bin"), root.join("config")] {
            if self != Self::User {
                windows_file::trusted_system_directory(&path)?;
            }
        }
        Ok(())
    }

    fn create_directory(self, path: &Path, service_write: bool) -> std::io::Result<()> {
        match self {
            Self::Machine => windows_file::create_machine_private_directory(path),
            Self::LocalService => windows_file::create_private_directory(path, true, service_write),
            Self::User => windows_file::create_private_directory(path, false, false),
        }
    }

    fn write_new(self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        if self == Self::Machine {
            use std::io::Write;
            let mut file = windows_file::create_machine_private_file(path)?;
            file.write_all(bytes)?;
            file.sync_all()
        } else {
            windows_file::write_private_new(path, bytes, self == Self::LocalService)
        }
    }

    fn replace(self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        if self == Self::Machine {
            windows_file::atomic_write_machine_private(path, bytes, true)
        } else {
            windows_file::atomic_write_private(path, bytes, true, self == Self::LocalService)
        }
    }

    fn validate_file(self, path: &Path) -> std::io::Result<()> {
        let file = fs::File::open(path)?;
        if self == Self::Machine {
            windows_file::validate_machine_private(&file)
        } else {
            windows_file::validate_private(&file, self == Self::LocalService)
        }
    }
}
fn validate_root(root: &Path) -> Result<(), WinctlError> {
    if !root.is_absolute() || root.parent().is_none() || root.to_string_lossy().contains('"') {
        return Err(invalid(
            "install root must be an absolute directory without quotes",
        ));
    }
    windows_file::reject_reparse_ancestry(root)?;
    Ok(())
}
type PreparedConfig = (Vec<u8>, BTreeMap<String, Vec<u8>>);
#[cfg(test)]
fn render_config(source: &Path, root: &Path) -> Result<PreparedConfig, WinctlError> {
    render_config_online(source, root, false)
}
fn render_config_online(
    source: &Path,
    root: &Path,
    online: bool,
) -> Result<PreparedConfig, WinctlError> {
    let raw = aegis_core::secret_file::read_config(source, 4 * 1024 * 1024)?;
    let text = std::str::from_utf8(&raw).map_err(|_| invalid("config encoding invalid"))?;
    let mut cfg: Settings = toml::from_str(text).map_err(|_| invalid("config parse invalid"))?;
    render_settings_online(
        &mut cfg,
        source.parent().unwrap_or_else(|| Path::new(".")),
        root,
        online,
    )
}
fn render_settings(
    cfg: &mut Settings,
    base: &Path,
    root: &Path,
) -> Result<PreparedConfig, WinctlError> {
    render_settings_online(cfg, base, root, false)
}
fn render_settings_online(
    cfg: &mut Settings,
    base: &Path,
    root: &Path,
    online: bool,
) -> Result<PreparedConfig, WinctlError> {
    // Scope is explicit. Do not silently turn a Linux-wide/direct installation
    // into a Windows SOCKS setup or relax an inner-authenticated profile.
    if !matches!(cfg.mode, Mode::Relay)
        || (cfg.windows_tunnel.is_none() && cfg.ingress.primary != IngressPrimary::Socks5)
        || cfg.ingress.allow_fallback
    {
        return Err(invalid("Windows installer requires mode=relay, ingress.primary=socks5 and allow_fallback=false"));
    }
    if let Some(tunnel) = cfg.windows_tunnel.as_mut() {
        tunnel.validate().map_err(|e| invalid(&e))?;
        tunnel.relay_pins(&cfg.relay).map_err(|e| invalid(&e))?;
        tunnel.driver = root.join("bin/wintun.dll");
    }
    if !cfg.socks.listen.ip().is_loopback() || !cfg.socks.require_loopback {
        return Err(invalid(
            "Windows SOCKS installation requires loopback-only access",
        ));
    }
    cfg.socks.validate_tcp_policy().map_err(|e| invalid(&e))?;
    if !cfg.relay.auth_token.is_empty() {
        aegis_core::auth_token::validate(&cfg.relay.auth_token).map_err(invalid)?;
    }
    cfg.validate_inner_tls().map_err(|e| invalid(&e))?;
    if cfg.relay.server.is_empty() {
        return Err(invalid("relay server is required"));
    }
    let resolve = |p: &Path| {
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            base.join(p)
        }
    };
    let mut credentials = BTreeMap::new();
    if let Some(ca) = &mut cfg.relay.ca_cert {
        credentials.insert(
            "outer-ca.pem".into(),
            package::read_regular(&resolve(ca), 1024 * 1024)?,
        );
        *ca = root.join("config/outer-ca.pem");
    }
    if let Some(ca) = &mut cfg.relay.masque_ca_cert {
        credentials.insert(
            "masque-ca.pem".into(),
            package::read_regular(&resolve(ca), 1024 * 1024)?,
        );
        *ca = root.join("config/masque-ca.pem");
    }
    if let Some(inner) = &mut cfg.relay.inner_tls {
        inner.resolve_paths(base);
        aegis_core::secure_channel::Client::load(inner)
            .map_err(|_| invalid("inner TLS identity or trust rejected"))?;
        credentials.insert(
            "inner-ca.pem".into(),
            package::read_regular(&inner.server_ca, 1024 * 1024)?,
        );
        if online {
            let identity = inner
                .key
                .parent()
                .ok_or_else(|| invalid("identity directory missing"))?;
            if !identity.is_absolute()
                || identity.starts_with(root)
                || inner.key != identity.join("device.key")
                || inner.cert != identity.join("device.pem")
            {
                return Err(invalid(
                    "online device identity must remain outside installation versions",
                ));
            }
            windows_file::trusted_system_directory(identity)?;
        } else {
            credentials.insert(
                "device.pem".into(),
                package::read_regular(&inner.cert, 1024 * 1024)?,
            );
            // Keep an existing device identity; never generate a second device key.
            credentials.insert(
                "device-key.pem".into(),
                // Match the Windows TLS loader's service-readable private-file
                // policy. SOCKS service keys grant LocalService read-only access;
                // owner-only reads would reject those keys on connect/upgrade.
                // The handle check still rejects world access and service writes.
                aegis_core::secret_file::read_config(&inner.key, 1024 * 1024)?.to_vec(),
            );
        }
        inner.server_ca = root.join("config/inner-ca.pem");
        if !online {
            inner.cert = root.join("config/device.pem");
            inner.key = root.join("config/device-key.pem");
        }
    }
    cfg.ingress.wide.enabled = false;
    cfg.direct.state_path = root.join("state/brain.json");
    let config = toml::to_string_pretty(cfg).map_err(|_| invalid("config rendering failed"))?;
    Ok((config.into_bytes(), credentials))
}
fn install(args: InstallArgs) -> Result<Value, WinctlError> {
    install_staged(args, true)
}
fn install_staged(args: InstallArgs, register: bool) -> Result<Value, WinctlError> {
    validate_root(&args.root)?;
    let elevated = super::is_elevated();
    if args.root.exists() {
        return Err(invalid(
            "install root already exists; use a new version directory",
        ));
    }
    if args.service && !elevated {
        return Err(invalid(
            "system service installation requires an administrator",
        ));
    }
    if register && args.service && service::query(&args.service_name)?["exists"] == true {
        return Err(invalid(
            "requested service already exists; preserve or uninstall it explicitly",
        ));
    }
    let (manifest_sha256, publisher_signature_verified) = args.trust.resolve(&args.package)?;
    let files =
        package::verify_for_install(&args.package, &manifest_sha256, args.authenticode.path())?;
    // Bind the typed license declaration to the same authenticated manifest,
    // never an independently mutable filename or inferred package path.
    let manifest_bytes = package::read_regular(&args.package.join("manifest.json"), 65536)?;
    if package::hash(&manifest_bytes) != manifest_sha256 {
        return Err(invalid("verified install manifest changed"));
    }
    let manifest: Value = serde_json::from_slice(&manifest_bytes)?;
    let project_licenses = match manifest.get("project_licenses") {
        None => false,
        Some(Value::Bool(value)) => *value,
        _ => return Err(invalid("installed project-license declaration rejected")),
    };
    let online = args.device_online_bundle.is_some();
    let (config, mut credentials) = render_config_online(&args.config, &args.root, online)?;
    if let Some(bundle) = &args.device_online_bundle {
        validate_root(bundle)?;
        if !args.service {
            return Err(invalid("online identity requires a managed service"));
        }
        for member in [
            "bundle.json",
            "outer-ca.pem",
            "inner-ca.pem",
            "device-ca.pem",
        ] {
            credentials.insert(
                format!("device-bundle/{member}"),
                package::read_regular(&bundle.join(member), 65536)?,
            );
        }
    }
    let rendered: Settings =
        toml::from_str(std::str::from_utf8(&config).map_err(|_| invalid("config encoding"))?)
            .map_err(|_| invalid("rendered config"))?;
    let system_tunnel = rendered.windows_tunnel.is_some();
    let access = InstallAccess::for_install(args.service, system_tunnel, elevated);
    if online && !system_tunnel {
        return Err(invalid(
            "managed Windows renewal requires a LocalSystem full tunnel",
        ));
    }
    access.validate_parent(&args.root, elevated)?;
    if system_tunnel
        && (!files.contains_key("wintun.dll") || !files.contains_key("WINTUN-LICENSE.txt"))
    {
        return Err(invalid(
            "system tunnel requires a package containing pinned Wintun and its license",
        ));
    }
    if system_tunnel && !elevated {
        return Err(invalid(
            "system tunnel installation requires administrator privileges",
        ));
    }
    let payload_plan =
        super::install_payload::plan(system_tunnel, project_licenses, &files).map_err(invalid)?;
    if payload_plan
        .license_names
        .iter()
        .any(|name| files[*name].len() > 65536)
    {
        return Err(invalid("installed project license exceeds its bound"));
    }
    // Validate all source bytes and scope before the first filesystem mutation.
    access.create_directory(&args.root, false)?;
    for name in ["bin", "config", "state"] {
        access.create_directory(&args.root.join(name), name == "state")?;
    }
    if online {
        access.create_directory(&args.root.join("config/device-bundle"), false)?;
    }
    let binary_names = payload_plan.binary_names;
    for name in binary_names {
        access.write_new(&args.root.join("bin").join(name), &files[*name])?;
    }
    if !payload_plan.license_names.is_empty() {
        access.create_directory(&args.root.join("licenses"), false)?;
        for name in payload_plan.license_names {
            access.write_new(&args.root.join("licenses").join(name), &files[*name])?;
        }
    }
    for (name, bytes) in credentials {
        access.write_new(&args.root.join("config").join(name), &bytes)?;
    }
    let config_path = args.root.join("config/aegis.toml");
    access.write_new(&config_path, &config)?;
    let client = args.root.join("bin/aegis-client.exe");
    // Once the verified files exist, retain their ownership receipt before
    // executing preflight. A failed executable/preflight must still be
    // removable with the normal uninstall command, preserving private data.
    let receipt = Receipt {
        schema: 1,
        manifest_sha256,
        publisher_signature_verified,
        service: args.service,
        system_tunnel,
        managed_online: online,
        service_name: args.service_name.clone(),
        access_policy: Some(access),
        license_files: payload_plan
            .license_names
            .iter()
            .map(|name| (name.to_string(), package::hash(&files[*name])))
            .collect(),
        binaries: binary_names
            .iter()
            .map(|name| (name.to_string(), package::hash(&files[*name])))
            .collect(),
    };
    access.write_new(
        &args.root.join("install.json"),
        &serde_json::to_vec_pretty(&receipt)?,
    )?;
    let mut preflight = Command::new(&client);
    preflight
        .arg("--config")
        .arg(&config_path)
        .args(["--ingress-preflight", "--json"]);
    if online {
        preflight
            .arg("--device-online-bundle")
            .arg(args.root.join("config/device-bundle"));
    }
    // Re-open the protected ancestry and owned files immediately before
    // executing staged bytes; staging-time checks are not execution checks.
    verify_installed(&args.root)?;
    let checked = preflight.output()?;
    if !checked.status.success() {
        return Err(invalid(
            "installed client preflight failed; private staging retained for client uninstall, service not registered",
        ));
    }
    if args.service && register {
        verify_installed(&args.root)?;
        let bundle = online.then(|| args.root.join("config/device-bundle"));
        let bin_path = service::command_line(&client, &config_path, bundle.as_deref())?;
        service::run(ServiceCommand::Install(ServiceInstallArgs {
            service_name: args.service_name.clone(),
            display_name: "AEGIS Client".into(),
            bin_path,
            start: if system_tunnel { "auto" } else { "demand" }.into(),
            system_tunnel,
        }))?;
        if args.start {
            verify_installed(&args.root)?;
            service::run(ServiceCommand::Start(ServiceNameArg {
                service_name: args.service_name.clone(),
            }))?;
        }
    }
    Ok(
        json!({"ok":true,"root":args.root,"profile":if system_tunnel{"system-tunnel"}else{"socks-relay"},"service":args.service,
        "config":config_path,"client":client,"signed_release":false,
        "custom_wfp_driver_installed":false,
        "kill_switch_active":args.start && rendered.windows_tunnel.as_ref().is_some_and(|t|t.kill_switch)}),
    )
}
fn verify_installed(root: &Path) -> Result<Receipt, WinctlError> {
    let value = receipt(root)?;
    let access = value.access()?;
    access.validate_execution(root, super::is_elevated())?;
    for name in ["install.json", "config/aegis.toml"] {
        access.validate_file(&root.join(name))?;
    }
    for (name, digest) in &value.binaries {
        access.validate_file(&root.join("bin").join(name))?;
        if package::hash(&package::read_regular(
            &root.join("bin").join(name),
            256 * 1024 * 1024,
        )?) != *digest
        {
            return Err(invalid("installed version integrity rejected"));
        }
    }
    for (name, digest) in &value.license_files {
        let path = root.join("licenses").join(name);
        access.validate_file(&path)?;
        if package::hash(&package::read_regular(&path, 65536)?) != *digest {
            return Err(invalid("installed project-license integrity rejected"));
        }
    }
    Ok(value)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rollback {
    schema: u32,
    previous_root: PathBuf,
    previous_manifest: String,
}
fn switch_service(from: &Path, to: &Path) -> Result<Value, WinctlError> {
    let old = verify_installed(from)?;
    let new = verify_installed(to)?;
    if !old.service
        || !new.service
        || old.system_tunnel != new.system_tunnel
        || old.managed_online != new.managed_online
        || old.service_name != new.service_name
    {
        return Err(invalid("version switch requires matching service profiles"));
    }
    service::require_binary_in(&old.service_name, &from.join("bin/aegis-client.exe"))?;
    let running = service::query(&old.service_name)?["state"] == "RUNNING";
    if old.system_tunnel {
        service::disable_then_stop(&old.service_name)?;
        // A stopped old service can still own committed relay host routes.
        // Drain its exact journal while it is the SCM owner; never let the
        // new root adopt or silently ignore those routes.
        let recovered = (|| -> Result<usize, WinctlError> {
            use aegis_core::windows_tunnel::lifecycle;
            let _exclusive = lifecycle::Exclusive::acquire()?;
            Ok(lifecycle::recover_routes(&lifecycle::journal_path(
                &from.join("config/aegis.toml"),
            ))?)
        })();
        if let Err(error) = recovered {
            if running {
                service::auto_start_then_start(&old.service_name)?;
            }
            return Err(error);
        }
    } else {
        service::run(ServiceCommand::Stop(ServiceNameArg {
            service_name: old.service_name.clone(),
        }))?;
    }
    if let Err(error) = service::replace_binary(
        &old.service_name,
        &to.join("bin/aegis-client.exe"),
        &to.join("config/aegis.toml"),
        new.managed_online
            .then(|| to.join("config/device-bundle"))
            .as_deref(),
    ) {
        if running && old.system_tunnel {
            service::auto_start_then_start(&old.service_name)?;
        }
        return Err(error);
    }
    if running {
        let start = if old.system_tunnel {
            service::auto_start_then_start(&old.service_name)
        } else {
            service::run(ServiceCommand::Start(ServiceNameArg {
                service_name: old.service_name.clone(),
            }))
        };
        if let Err(error) = start {
            if old.system_tunnel {
                service::disable_then_stop(&old.service_name)?;
            } else {
                service::run(ServiceCommand::Stop(ServiceNameArg {
                    service_name: old.service_name.clone(),
                }))?;
            }
            service::replace_binary(
                &old.service_name,
                &from.join("bin/aegis-client.exe"),
                &from.join("config/aegis.toml"),
                old.managed_online
                    .then(|| from.join("config/device-bundle"))
                    .as_deref(),
            )?;
            if old.system_tunnel {
                service::auto_start_then_start(&old.service_name)?;
            } else {
                service::run(ServiceCommand::Start(ServiceNameArg {
                    service_name: old.service_name.clone(),
                }))?;
            }
            return Err(invalid(&format!(
                "new version failed; previous service restored: {error}"
            )));
        }
    }
    Ok(
        json!({"ok":true,"active_root":to,"previous_root":from,"running":running,"previous_version_preserved":true}),
    )
}
fn receipt(root: &Path) -> Result<Receipt, WinctlError> {
    validate_root(root)?;
    let raw = aegis_core::secret_file::read_config(&root.join("install.json"), 65536)?;
    let receipt: Receipt = serde_json::from_slice(&raw)?;
    if receipt.schema != 1
        || receipt
            .binaries
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>()
            != if receipt.system_tunnel {
                vec![
                    "WINTUN-LICENSE.txt",
                    "aegis-client.exe",
                    "aegis-winctl.exe",
                    "wintun.dll",
                ]
            } else {
                vec!["aegis-client.exe", "aegis-winctl.exe"]
            }
    {
        return Err(invalid("install receipt rejected"));
    }
    super::install_payload::validate_license_receipt(&receipt.license_files).map_err(invalid)?;
    receipt.access()?;
    Ok(receipt)
}
pub(super) fn run(args: ClientArgs) -> Result<Value, WinctlError> {
    match args.command {
        ClientCommand::RebootCheck(args) => reboot::run(args),
        ClientCommand::PrepareConfig(args) => operator::prepare(args),
        ClientCommand::Connect { root } => operator::connect(&root),
        ClientCommand::Disconnect { root } => operator::disconnect(&root),
        ClientCommand::Doctor { root } => operator::doctor(&root),
        ClientCommand::Install(args) => install(args),
        ClientCommand::Upgrade {
            root,
            package,
            trust,
            authenticode,
            new_root,
        } => {
            let previous = verify_installed(&root)?;
            if !previous.service {
                return Err(invalid("managed upgrades require an installed service"));
            }
            service::require_binary_in(&previous.service_name, &root.join("bin/aegis-client.exe"))?;
            install_staged(
                InstallArgs {
                    package,
                    trust,
                    authenticode,
                    device_online_bundle: previous
                        .managed_online
                        .then(|| root.join("config/device-bundle")),
                    config: root.join("config/aegis.toml"),
                    root: new_root.clone(),
                    service: true,
                    start: false,
                    service_name: previous.service_name.clone(),
                },
                false,
            )?;
            let access = previous.access()?;
            let rollback = Rollback {
                schema: 1,
                previous_root: root.clone(),
                previous_manifest: previous.manifest_sha256,
            };
            access.write_new(
                &new_root.join("rollback.json"),
                &serde_json::to_vec(&rollback)?,
            )?;
            // Keep learned state in its existing protected location across
            // upgrades; both versions retain access during an explicit rollback.
            let old_config: Settings = toml::from_str(
                std::str::from_utf8(&aegis_core::secret_file::read_config(
                    &root.join("config/aegis.toml"),
                    4 * 1024 * 1024,
                )?)
                .map_err(|_| invalid("config encoding"))?,
            )
            .map_err(|_| invalid("config parse"))?;
            let next_config = new_root.join("config/aegis.toml");
            let mut next: Settings = toml::from_str(
                std::str::from_utf8(&aegis_core::secret_file::read_config(
                    &next_config,
                    4 * 1024 * 1024,
                )?)
                .map_err(|_| invalid("config encoding"))?,
            )
            .map_err(|_| invalid("config parse"))?;
            next.direct.state_path = old_config.direct.state_path;
            access.replace(
                &next_config,
                toml::to_string_pretty(&next)
                    .map_err(|_| invalid("config rendering"))?
                    .as_bytes(),
            )?;
            switch_service(&root, &new_root)
        }
        ClientCommand::Rollback { root } => {
            verify_installed(&root)?;
            let value: Rollback = serde_json::from_slice(&aegis_core::secret_file::read_config(
                &root.join("rollback.json"),
                65536,
            )?)?;
            if value.schema != 1
                || verify_installed(&value.previous_root)?.manifest_sha256
                    != value.previous_manifest
            {
                return Err(invalid("rollback identity rejected"));
            }
            switch_service(&root, &value.previous_root)
        }
        ClientCommand::Status { root } => {
            let receipt = receipt(&root)?;
            let mut binaries = BTreeMap::new();
            for (name, hash) in receipt.binaries {
                let valid = package::read_regular(&root.join("bin").join(&name), 256 * 1024 * 1024)
                    .map(|bytes| package::hash(&bytes) == hash)
                    .unwrap_or(false);
                binaries.insert(name, valid);
            }
            let mut license_files = BTreeMap::new();
            for (name, hash) in receipt.license_files {
                let valid = package::read_regular(&root.join("licenses").join(&name), 65536)
                    .map(|bytes| package::hash(&bytes) == hash)
                    .unwrap_or(false);
                license_files.insert(name, valid);
            }
            Ok(
                json!({"ok":true,"root":root,"binaries":binaries,"license_files":license_files,"service":if receipt.service { service::query(&receipt.service_name)? } else { Value::Null }}),
            )
        }
        ClientCommand::Uninstall { root } => {
            let receipt = receipt(&root)?;
            let mut removals = Vec::new();
            for (name, hash) in &receipt.binaries {
                let path = root.join("bin").join(name);
                if !path.try_exists()? {
                    continue;
                }
                if path.canonicalize()? == std::env::current_exe()?.canonicalize()? {
                    return Err(invalid("run uninstall with aegis-winctl from the original kit, outside the installed directory"));
                }
                if package::hash(&package::read_regular(&path, 256 * 1024 * 1024)?) != *hash {
                    return Err(invalid("installed binary changed; refusing removal"));
                }
                removals.push(path);
            }
            for (name, hash) in &receipt.license_files {
                let path = root.join("licenses").join(name);
                if !path.try_exists()? {
                    continue;
                }
                receipt.access()?.validate_file(&path)?;
                if package::hash(&package::read_regular(&path, 65536)?) != *hash {
                    return Err(invalid(
                        "installed project license changed; refusing removal",
                    ));
                }
                removals.push(path);
            }
            if receipt.service {
                // Verify ownership by the actual SCM executable path before
                // stopping a service with this shared historical name.
                service::require_binary_in(
                    &receipt.service_name,
                    &root.join("bin/aegis-client.exe"),
                )?;
                service::run(ServiceCommand::Uninstall(ServiceNameArg {
                    service_name: receipt.service_name.clone(),
                }))?;
            }
            if receipt.system_tunnel {
                use aegis_core::windows_tunnel::{firewall, lifecycle};
                let _exclusive = lifecycle::Exclusive::acquire()?;
                lifecycle::recover_routes(&lifecycle::journal_path(
                    &root.join("config/aegis.toml"),
                ))?;
                firewall::disconnect_owned(&root.join("bin/aegis-client.exe"))?;
            }
            let removal_deadline = Instant::now() + Duration::from_secs(60);
            for path in removals {
                remove_verified_binary(&path, removal_deadline)?;
            }
            Ok(json!({"ok":true,"root":root,"configuration_preserved":true,"state_preserved":true}))
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn install_access_matches_service_identity() {
        assert_eq!(
            InstallAccess::for_profile(false, false),
            InstallAccess::User
        );
        assert_eq!(InstallAccess::for_profile(false, true), InstallAccess::User);
        assert_eq!(
            InstallAccess::for_profile(true, false),
            InstallAccess::LocalService
        );
        assert_eq!(
            InstallAccess::for_profile(true, true),
            InstallAccess::Machine
        );
        assert_eq!(
            InstallAccess::for_install(false, false, false),
            InstallAccess::User
        );
        assert_eq!(
            InstallAccess::for_install(false, false, true),
            InstallAccess::Machine
        );
        assert_eq!(
            InstallAccess::for_install(true, false, true),
            InstallAccess::LocalService
        );
        assert_eq!(
            InstallAccess::for_install(true, true, true),
            InstallAccess::Machine
        );
    }

    #[test]
    fn receipt_access_is_explicit_and_legacy_user_execution_refuses_elevation() {
        let root = Path::new(r"C:\\synthetic\\aegis");
        let legacy_user = InstallAccess::for_receipt(false, false, None).unwrap();
        assert_eq!(legacy_user, InstallAccess::User);
        assert!(legacy_user.validate_execution(root, true).is_err());
        assert_eq!(
            InstallAccess::for_receipt(false, false, Some(InstallAccess::Machine)).unwrap(),
            InstallAccess::Machine
        );
        assert_eq!(
            InstallAccess::for_receipt(true, false, None).unwrap(),
            InstallAccess::LocalService
        );
        assert_eq!(
            InstallAccess::for_receipt(true, true, None).unwrap(),
            InstallAccess::Machine
        );
        assert!(InstallAccess::for_receipt(true, false, Some(InstallAccess::Machine)).is_err());
        assert!(InstallAccess::for_receipt(true, true, Some(InstallAccess::LocalService)).is_err());
        assert!(
            InstallAccess::for_receipt(false, false, Some(InstallAccess::LocalService)).is_err()
        );
    }

    #[test]
    fn receipt_access_policy_round_trips_and_legacy_service_receipts_remain_admissible() {
        for (service, system_tunnel, access) in [
            (false, false, InstallAccess::User),
            (false, false, InstallAccess::Machine),
            (true, false, InstallAccess::LocalService),
            (true, true, InstallAccess::Machine),
        ] {
            let receipt = Receipt {
                schema: 1,
                manifest_sha256: "a".repeat(64),
                publisher_signature_verified: false,
                service,
                binaries: BTreeMap::new(),
                license_files: BTreeMap::new(),
                system_tunnel,
                managed_online: false,
                service_name: default_service_name(),
                access_policy: Some(access),
            };
            let encoded = serde_json::to_value(&receipt).unwrap();
            let decoded: Receipt = serde_json::from_value(encoded.clone()).unwrap();
            assert_eq!(decoded.access().unwrap(), access);
            let mut legacy = encoded;
            legacy.as_object_mut().unwrap().remove("access_policy");
            let decoded: Receipt = serde_json::from_value(legacy.clone()).unwrap();
            assert_eq!(
                decoded.access().unwrap(),
                InstallAccess::for_profile(service, system_tunnel)
            );
            legacy["access_policy"] = json!("unrecognized_policy");
            assert!(serde_json::from_value::<Receipt>(legacy).is_err());
        }
    }

    #[test]
    #[ignore = "administrator; only synthetic ACL fixture files, no service or network mutation"]
    fn service_install_rejects_user_owned_parent_before_staging() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("user-owned-parent");
        windows_file::create_private_directory(&parent, false, false).unwrap();
        let root = parent.join("new-install");
        for access in [InstallAccess::LocalService, InstallAccess::Machine] {
            assert!(access.validate_parent(&root, true).is_err());
            assert!(!root.exists());
        }
        // The ordinary per-user SOCKS install retains its original boundary.
        InstallAccess::User.validate_parent(&root, false).unwrap();
        assert!(InstallAccess::User.validate_parent(&root, true).is_err());
    }

    #[test]
    #[ignore = "administrator; only synthetic ACL fixture files, no service or network mutation"]
    fn tunnel_install_files_exclude_shared_localservice_grants() {
        let temp = tempfile::tempdir().unwrap();
        for (name, access) in [
            ("socks", InstallAccess::LocalService),
            ("tunnel", InstallAccess::Machine),
        ] {
            let root = temp.path().join(name);
            access.create_directory(&root, false).unwrap();
            for member in ["config", "state"] {
                access
                    .create_directory(&root.join(member), member == "state")
                    .unwrap();
            }
            for member in [
                "config/device-key.pem",
                "config/aegis.toml",
                "rollback.json",
            ] {
                let path = root.join(member);
                access.write_new(&path, b"synthetic ACL fixture").unwrap();
                access.validate_file(&path).unwrap();
                let file = fs::File::open(&path).unwrap();
                assert_eq!(
                    windows_file::validate_machine_private(&file).is_ok(),
                    access == InstallAccess::Machine
                );
            }
            if access == InstallAccess::Machine {
                let config = root.join("config/aegis.toml");
                access
                    .replace(&config, b"synthetic upgrade fixture")
                    .unwrap_err();
                // Temp ancestry is intentionally per-user. A machine rewrite
                // must reject it rather than replace installed configuration.
                assert_eq!(fs::read(&config).unwrap(), b"synthetic ACL fixture");
            }
        }
    }

    #[test]
    #[ignore = "administrator; fresh Machine fixture directories/files only, no service or network mutation"]
    fn protected_install_parent_leaves_and_replacement_use_real_windows_acls() {
        let fixture = MachineFixture::new("acl-positive");
        for (name, service, tunnel, access) in [
            ("elevated-user", false, false, InstallAccess::Machine),
            ("socks", true, false, InstallAccess::LocalService),
            ("tunnel", true, true, InstallAccess::Machine),
        ] {
            let root = fixture.path().join(name);
            assert_eq!(InstallAccess::for_install(service, tunnel, true), access);
            access.validate_parent(&root, true).unwrap();
            access.create_directory(&root, false).unwrap();
            for member in ["bin", "config", "state"] {
                access
                    .create_directory(&root.join(member), member == "state")
                    .unwrap();
            }
            access.validate_execution(&root, true).unwrap();
            for member in [
                "bin/aegis-client.exe",
                "config/device-key.pem",
                "config/aegis.toml",
                "install.json",
            ] {
                let path = root.join(member);
                access
                    .write_new(&path, b"synthetic positive ACL fixture")
                    .unwrap();
                access.validate_file(&path).unwrap();
                let file = fs::File::open(&path).unwrap();
                assert_eq!(
                    windows_file::validate_machine_private(&file).is_ok(),
                    access == InstallAccess::Machine
                );
            }
            let config = root.join("config/aegis.toml");
            access
                .replace(&config, b"synthetic positive replacement")
                .unwrap();
            assert_eq!(
                fs::read(&config).unwrap(),
                b"synthetic positive replacement"
            );
            access.validate_file(&config).unwrap();
            access.validate_execution(&root, true).unwrap();
            assert_eq!(
                fs::read_dir(root.join("config")).unwrap().count(),
                2,
                "replacement leaves no temporary sidecar"
            );
        }
    }

    #[test]
    #[ignore = "administrator; synthetic profile-selected credential files only, no service or network mutation"]
    fn installed_inner_tls_identity_can_be_revalidated_and_upgraded() {
        let temp = MachineFixture::new("inner-tls");
        let identity = rcgen::generate_simple_self_signed(vec!["fixture.test".into()]).unwrap();
        let cert = temp.path().join("identity.pem");
        let key = temp.path().join("identity.key");
        let private_pem = identity.key_pair.serialize_pem();
        fs::write(&cert, identity.cert.pem()).unwrap();
        windows_file::write_private_new(&key, private_pem.as_bytes(), false).unwrap();
        for system_tunnel in [false, true] {
            let access = InstallAccess::for_profile(true, system_tunnel);
            let root = temp
                .path()
                .join(if system_tunnel { "tunnel" } else { "socks" });
            access.create_directory(&root, false).unwrap();
            access
                .create_directory(&root.join("config"), false)
                .unwrap();
            let mut cfg = Settings {
                mode: Mode::Relay,
                ..Default::default()
            };
            cfg.ingress.primary = IngressPrimary::Socks5;
            cfg.ingress.allow_fallback = false;
            cfg.relay.server = "127.0.0.1:443".into();
            cfg.relay.server_name = "fixture.test".into();
            cfg.relay.ca_cert = Some(cert.clone());
            cfg.relay.transport_priority = vec![aegis_core::TunnelTransportFamily::GrpcStream];
            cfg.relay.tls_backend = aegis_core::RelayTlsBackend::Rustls;
            cfg.relay.udp_transport_priority =
                Some(vec![aegis_core::TunnelTransportFamily::GrpcDatagram]);
            cfg.relay.inner_tls = Some(aegis_core::secure_channel::ClientSettings {
                server_name: "fixture.test".into(),
                server_ca: cert.clone(),
                cert: cert.clone(),
                key: key.clone(),
            });
            if system_tunnel {
                cfg.windows_tunnel = Some(Default::default());
            }
            let (config, credentials) = render_settings(&mut cfg, temp.path(), &root).unwrap();
            for (name, bytes) in credentials {
                access
                    .write_new(&root.join("config").join(name), &bytes)
                    .unwrap();
            }
            let config_path = root.join("config/aegis.toml");
            access.write_new(&config_path, &config).unwrap();
            let installed_key = root.join("config/device-key.pem");
            assert_eq!(
                aegis_core::secret_file::read(&installed_key, 1024 * 1024).is_ok(),
                system_tunnel
            );
            // Connect/doctor revalidate in place; upgrade renders into a new root.
            for destination in [&root, &root.join("next-version")] {
                let (_, copied) = render_config(&config_path, destination).unwrap();
                assert_eq!(copied["device-key.pem"], private_pem.as_bytes());
            }
        }
        // Service-readable does not mean service-writable: inherited LS full
        // control is rejected on the opened handle by the same read policy.
        let writable = temp.path().join("service-writable");
        windows_file::create_private_directory(&writable, true, true).unwrap();
        let unsafe_key = writable.join("key");
        fs::write(&unsafe_key, private_pem.as_bytes()).unwrap();
        assert!(aegis_core::secret_file::read_config(&unsafe_key, 1024 * 1024).is_err());
    }

    #[test]
    #[ignore = "requires AEGIS_TEST_WINCTL; invokes only a packaged test controller as an intentionally invalid client, without a service"]
    fn failed_preflight_retains_owned_uninstall_path() {
        let temp = MachineFixture::new("failed-preflight");
        let controller = PathBuf::from(std::env::var_os("AEGIS_TEST_WINCTL").unwrap());
        let kit = temp.path().join("kit");
        // This real PE accepts controller commands, not client preflight.
        // Its explicit test pin authenticates the fixture, not a release.
        let built = package::build(&controller, &controller, &kit, "0".repeat(40)).unwrap();
        let mut settings = Settings {
            mode: Mode::Relay,
            ..Default::default()
        };
        settings.ingress.primary = IngressPrimary::Socks5;
        settings.ingress.allow_fallback = false;
        settings.relay.server = "127.0.0.1:9".into();
        settings.relay.server_name = "fixture.test".into();
        settings.relay.tls_backend = aegis_core::RelayTlsBackend::Rustls;
        let source = temp.path().join("input.toml");
        windows_file::write_private_new(
            &source,
            toml::to_string(&settings).unwrap().as_bytes(),
            false,
        )
        .unwrap();
        let root = temp.path().join("failed-install");
        let error = install(InstallArgs {
            device_online_bundle: None,
            authenticode: Default::default(),
            package: kit,
            trust: package::trust::TrustArgs::pinned(
                built["manifest_sha256"].as_str().unwrap().into(),
            ),
            config: source,
            root: root.clone(),
            service: false,
            start: false,
            service_name: default_service_name(),
        })
        .unwrap_err();
        assert!(error.to_string().contains("preflight failed"), "{error}");
        assert!(root.join("install.json").exists());
        let config = fs::read(root.join("config/aegis.toml")).unwrap();
        run(ClientArgs {
            command: ClientCommand::Uninstall { root: root.clone() },
        })
        .unwrap();
        assert!(!root.join("bin/aegis-client.exe").exists());
        assert_eq!(fs::read(root.join("config/aegis.toml")).unwrap(), config);
    }

    #[test]
    #[ignore = "requires AEGIS_TEST_CLIENT and AEGIS_TEST_WINCTL built from this checkout"]
    fn real_package_install_start_and_uninstall_preserve_private_material() {
        let temp = MachineFixture::new("package-positive");
        let kit = temp.path().join("kit");
        let built = package::build(
            &PathBuf::from(std::env::var_os("AEGIS_TEST_CLIENT").unwrap()),
            &PathBuf::from(std::env::var_os("AEGIS_TEST_WINCTL").unwrap()),
            &kit,
            "0".repeat(40),
        )
        .unwrap();
        let source = temp.path().join("input.toml");
        let mut settings = Settings {
            mode: Mode::Relay,
            ..Default::default()
        };
        settings.ingress.primary = IngressPrimary::Socks5;
        settings.ingress.allow_fallback = false;
        settings.socks.listen = "127.0.0.1:0".parse().unwrap();
        settings.relay.server = "127.0.0.1:9".into();
        settings.relay.server_name = "fixture.test".into();
        settings.relay.auth_token = "0123456789abcdef".repeat(4);
        settings.relay.tls_backend = aegis_core::RelayTlsBackend::Rustls;
        windows_file::write_private_new(
            &source,
            toml::to_string(&settings).unwrap().as_bytes(),
            false,
        )
        .unwrap();
        let root = temp.path().join("installed");
        install(InstallArgs {
            device_online_bundle: None,
            authenticode: Default::default(),
            package: kit.clone(),
            trust: package::trust::TrustArgs::pinned(
                built["manifest_sha256"].as_str().unwrap().into(),
            ),
            config: source,
            root: root.clone(),
            service: false,
            start: false,
            service_name: default_service_name(),
        })
        .unwrap();
        let config = root.join("config/aegis.toml");
        let before = aegis_core::secret_file::read_config(&config, 1024 * 1024).unwrap();
        let started = Command::new(root.join("bin/aegis-client.exe"))
            .arg("--config")
            .arg(&config)
            .arg("--exit-on-stdin-eof")
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert!(started.status.success(), "installed client did not start");
        let state = root.join("state/preserve.bin");
        windows_file::write_private_new(&state, b"synthetic private state", false).unwrap();
        let observed = run(ClientArgs {
            command: ClientCommand::Status { root: root.clone() },
        })
        .unwrap();
        assert_eq!(observed["binaries"]["aegis-client.exe"], true);
        for _ in 0..2 {
            run(ClientArgs {
                command: ClientCommand::Uninstall { root: root.clone() },
            })
            .unwrap();
        }
        assert!(!root.join("bin/aegis-client.exe").exists());
        assert_eq!(
            *aegis_core::secret_file::read_config(&config, 1024 * 1024).unwrap(),
            *before
        );
        assert_eq!(
            *aegis_core::secret_file::read(&state, 1024).unwrap(),
            b"synthetic private state"
        );
        assert!(package::verify(&kit, built["manifest_sha256"].as_str().unwrap()).is_ok());
    }
    #[test]
    fn refuses_linux_wide_profile_before_install_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source.toml");
        windows_file::write_private_new(
            &source,
            b"mode='relay'\n[ingress]\nprimary='wide'\nallow_fallback=false\n",
            false,
        )
        .unwrap();
        let root = temp.path().join("new");
        assert!(render_config(&source, &root).is_err());
        assert!(!root.exists());
    }
    #[test]
    fn root_rejects_relative_and_parent_traversal() {
        assert!(validate_root(Path::new("relative")).is_err());
        assert!(validate_root(Path::new("C:\\AEGIS\\..\\Windows")).is_err());
    }
}
