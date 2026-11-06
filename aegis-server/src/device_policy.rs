//! Private policy delivery. SSH authenticates the authority; only the authority
//! refreshes validity. The replica adopts the existing durable registry floor.
use aegis_core::secure_channel::registry::{self, DeviceRegistry, MAX_REGISTRY_BYTES};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

#[path = "device_policy_ack.rs"]
mod ack;
pub use ack::RuntimeAckConfig;
#[path = "device_policy_authority.rs"]
mod authority;

const SSH: &str = "/usr/bin/ssh";
const HOST_ALIAS: &str = "aegis-device-policy-authority";
const REMOTE_COMMAND: &str = "aegis-device-policy-v1";
const CONFIG_BYTES: u64 = 16 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("device_policy_requires_unix_administrator")]
    AdministratorRequired,
    #[error("device_policy_invalid_config")]
    InvalidConfig,
    #[error("device_policy_unsafe_local_input")]
    UnsafeInput,
    #[error("device_policy_registry_unavailable")]
    RegistryUnavailable,
    #[error("device_policy_invalid_snapshot")]
    InvalidSnapshot,
    #[error("device_policy_expired_or_future_policy")]
    InvalidValidity,
    #[error("device_policy_noncanonical_snapshot")]
    NonCanonical,
    #[error("device_policy_output_too_large")]
    OutputTooLarge,
    #[error("device_policy_transport_failed")]
    TransportFailed,
    #[error("device_policy_transport_timeout")]
    Timeout,
    #[error("device_policy_durable_apply_failed")]
    ApplyFailed,
    #[error("device_policy_unexpected_ssh_command")]
    UnexpectedSshCommand,
    #[error("device_policy_runtime_ack_unavailable")]
    RuntimeAckUnavailable,
    #[error("device_policy_runtime_ack_mismatch")]
    RuntimeAckMismatch,
    #[error("device_policy_runtime_ack_requires_linux_systemd")]
    RuntimeAckUnsupported,
    #[error("device_policy_stage_busy")]
    StageBusy,
    #[error("device_policy_stage_io_failed")]
    StageIoFailed,
}

type Result<T> = std::result::Result<T, PolicyError>;

#[derive(Debug, Args)]
pub struct PolicyArgs {
    #[command(subcommand)]
    pub command: PolicyCommand,
}

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Refresh the issuer-owned registry into an inherited root-private stdout file.
    AuthorityRefreshExport {
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        ttl_secs: u64,
    },
    /// Publish an existing verified stage without extending its validity.
    PublishStaged {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        registry: PathBuf,
    },
    /// Write a verified current canonical registry to stdout, without renewing it.
    Export {
        #[arg(long)]
        registry: PathBuf,
        /// For an administrator-controlled OpenSSH forced command only.
        #[arg(long)]
        forced_ssh: bool,
    },
    /// Fetch from one pinned SSH authority and apply the existing durable floor.
    Sync {
        #[arg(long)]
        config: PathBuf,
    },
    /// Require a live process acknowledgement of the current durable policy.
    Health {
        #[arg(long)]
        config: PathBuf,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncConfig {
    pub schema: String,
    pub registry: PathBuf,
    pub authority_host: String,
    pub authority_port: u16,
    pub authority_user: String,
    pub identity_file: PathBuf,
    pub known_hosts_file: PathBuf,
    pub timeout_secs: u64,
    #[serde(default)]
    pub runtime_ack: Option<RuntimeAckConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SyncReceipt {
    event_code: &'static str,
    /// This receipt does not acknowledge adoption by a running relay.
    pub acknowledgement: &'static str,
    pub generation: u64,
    pub snapshot_sha256: String,
    pub issued_at_unix_secs: u64,
    pub expires_at_unix_secs: u64,
}

pub async fn run(args: PolicyArgs) -> Result<()> {
    match args.command {
        PolicyCommand::AuthorityRefreshExport { registry, ttl_secs } => {
            authority::refresh_export(&registry, ttl_secs)
        }
        PolicyCommand::PublishStaged { input, registry } => {
            let receipt = authority::publish_staged(&input, &registry)?;
            println!(
                "{}",
                serde_json::to_string(&receipt).map_err(|_| PolicyError::InvalidSnapshot)?
            );
            Ok(())
        }
        PolicyCommand::Export {
            registry,
            forced_ssh,
        } => {
            if forced_ssh {
                validate_original_command(std::env::var("SSH_ORIGINAL_COMMAND").ok().as_deref())?;
            }
            let bytes = export(&registry, now()?)?;
            std::io::stdout()
                .lock()
                .write_all(&bytes)
                .map_err(|_| PolicyError::TransportFailed)
        }
        PolicyCommand::Sync { config } => {
            require_administrator()?;
            let config = SyncConfig::load(&config)?;
            let receipt = sync(&config).await?;
            println!(
                "{}",
                serde_json::to_string(&receipt).map_err(|_| PolicyError::InvalidSnapshot)?
            );
            // Disk publication remains a separate, already completed fact
            // even when the configured runtime adoption requirement fails.
            if let Some(runtime) = &config.runtime_ack {
                let acknowledgement = ack::verify(runtime, &receipt).await?;
                println!(
                    "{}",
                    serde_json::to_string(&acknowledgement)
                        .map_err(|_| PolicyError::RuntimeAckUnavailable)?
                );
            }
            Ok(())
        }
        PolicyCommand::Health { config } => {
            require_administrator()?;
            let config = SyncConfig::load(&config)?;
            let runtime = config
                .runtime_ack
                .as_ref()
                .ok_or(PolicyError::InvalidConfig)?;
            // Health observes the current durable tuple for each strict ACK
            // attempt; Sync still acknowledges its exact published receipt.
            let deadline = tokio::time::Instant::now() + Duration::from_secs(runtime.timeout_secs);
            let acknowledgement =
                ack::verify_current_until(runtime, &config.registry, deadline).await?;
            println!(
                "{}",
                serde_json::to_string(&acknowledgement)
                    .map_err(|_| PolicyError::RuntimeAckUnavailable)?
            );
            Ok(())
        }
    }
}

fn require_administrator() -> Result<()> {
    #[cfg(unix)]
    // SAFETY: geteuid has no pointer or mutation effects.
    if unsafe { libc::geteuid() } == 0 {
        return Ok(());
    }
    Err(PolicyError::AdministratorRequired)
}

fn now() -> Result<u64> {
    registry::unix_now().map_err(|_| PolicyError::InvalidValidity)
}

#[cfg(any(target_os = "linux", all(test, unix)))]
async fn load_health_snapshot(
    path: &Path,
    deadline: tokio::time::Instant,
) -> Result<DeviceRegistry> {
    let mut lock_path = path.as_os_str().to_owned();
    lock_path.push(".lock");
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(PolicyError::RegistryUnavailable);
        }
        let lock = checked_file(Path::new(&lock_path), 0, false)
            .map_err(|_| PolicyError::RegistryUnavailable)?;
        match lock.try_lock_shared() {
            Ok(()) => {
                // As with Export, retain the shared lock across the pending
                // check and the core's verified snapshot/floor read.
                match std::fs::symlink_metadata(registry::pending_path(path)) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    _ => return Err(PolicyError::RegistryUnavailable),
                }
                let snapshot =
                    DeviceRegistry::load(path).map_err(|_| PolicyError::RegistryUnavailable)?;
                if tokio::time::Instant::now() >= deadline {
                    return Err(PolicyError::RegistryUnavailable);
                }
                return Ok(snapshot);
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                drop(lock);
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    return Err(PolicyError::RegistryUnavailable);
                }
                tokio::time::sleep(
                    deadline
                        .saturating_duration_since(now)
                        .min(Duration::from_millis(100)),
                )
                .await;
            }
            Err(std::fs::TryLockError::Error(_)) => {
                return Err(PolicyError::RegistryUnavailable);
            }
        }
    }
}

fn validate_original_command(command: Option<&str>) -> Result<()> {
    if command != Some(REMOTE_COMMAND) {
        return Err(PolicyError::UnexpectedSshCommand);
    }
    Ok(())
}

fn current_policy(snapshot: &DeviceRegistry, now: u64) -> Result<()> {
    snapshot
        .validate()
        .map_err(|_| PolicyError::InvalidSnapshot)?;
    let validity = snapshot.validity.ok_or(PolicyError::InvalidValidity)?;
    // Delivery is conservative about clock skew: wait for the authority's
    // issue time instead of importing future policy. Never invent a deadline.
    if snapshot.version != 2
        || now == 0
        || validity.issued_at_unix_secs > now
        || validity.expires_at_unix_secs <= now
    {
        return Err(PolicyError::InvalidValidity);
    }
    Ok(())
}

pub(crate) fn canonical(snapshot: &DeviceRegistry) -> Result<Vec<u8>> {
    snapshot
        .validate()
        .map_err(|_| PolicyError::InvalidSnapshot)?;
    let mut ordered = snapshot.clone();
    ordered
        .devices
        .sort_by(|a, b| a.device_id.cmp(&b.device_id));
    ordered
        .invitations
        .sort_by(|a, b| a.token_sha256.cmp(&b.token_sha256));
    let bytes = serde_json::to_vec(&ordered).map_err(|_| PolicyError::InvalidSnapshot)?;
    if bytes.len() as u64 > MAX_REGISTRY_BYTES {
        return Err(PolicyError::OutputTooLarge);
    }
    Ok(bytes)
}

/// The core verifies the floor and holds a read-only shared lock. No mutation,
/// refresh, CA key or invitation plaintext is needed by the forced exporter.
pub fn export(path: &Path, now: u64) -> Result<Vec<u8>> {
    let mut lock_path = path.as_os_str().to_owned();
    lock_path.push(".lock");
    let lock = checked_file(Path::new(&lock_path), 0, false)?;
    lock.try_lock_shared()
        .map_err(|_| PolicyError::RegistryUnavailable)?;
    // Keep this outer shared lock while checking pending and loading the pair.
    // A producer cannot create a pending publication between those reads.
    match std::fs::symlink_metadata(registry::pending_path(path)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(PolicyError::RegistryUnavailable),
    }
    let snapshot = DeviceRegistry::load(path).map_err(|_| PolicyError::RegistryUnavailable)?;
    current_policy(&snapshot, now)?;
    canonical(&snapshot)
}

fn decode(bytes: &[u8], now: u64) -> Result<DeviceRegistry> {
    if bytes.len() as u64 > MAX_REGISTRY_BYTES {
        return Err(PolicyError::OutputTooLarge);
    }
    let snapshot = serde_json::from_slice(bytes).map_err(|_| PolicyError::InvalidSnapshot)?;
    current_policy(&snapshot, now)?;
    if canonical(&snapshot)? != bytes {
        return Err(PolicyError::NonCanonical);
    }
    Ok(snapshot)
}

fn absolute(path: &Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
}

/// Metadata validation does not read or copy the node's SSH private key.
#[cfg(unix)]
pub(crate) fn checked_file(path: &Path, bound: u64, private: bool) -> Result<std::fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    if !absolute(path) {
        return Err(PolicyError::UnsafeInput);
    }
    // SAFETY: geteuid only reads the caller identity.
    let uid = unsafe { libc::geteuid() };
    for ancestor in path.parent().ok_or(PolicyError::UnsafeInput)?.ancestors() {
        let info = std::fs::symlink_metadata(ancestor).map_err(|_| PolicyError::UnsafeInput)?;
        let sticky_root = info.uid() == 0 && info.mode() & 0o1000 != 0;
        if !info.is_dir()
            || (info.uid() != 0 && info.uid() != uid)
            || (info.mode() & 0o022 != 0 && !sticky_root)
        {
            return Err(PolicyError::UnsafeInput);
        }
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| PolicyError::UnsafeInput)?;
    let info = file.metadata().map_err(|_| PolicyError::UnsafeInput)?;
    let forbidden = if private { 0o177 } else { 0o022 };
    if !info.is_file()
        || info.nlink() != 1
        || info.len() > bound
        || (info.uid() != 0 && info.uid() != uid)
        || info.mode() & forbidden != 0
    {
        return Err(PolicyError::UnsafeInput);
    }
    Ok(file)
}

#[cfg(not(unix))]
pub(crate) fn checked_file(_path: &Path, _bound: u64, _private: bool) -> Result<std::fs::File> {
    Err(PolicyError::AdministratorRequired)
}

fn read_private(path: &Path, bound: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    checked_file(path, bound, true)?
        .take(bound + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| PolicyError::UnsafeInput)?;
    if bytes.len() as u64 > bound {
        return Err(PolicyError::UnsafeInput);
    }
    Ok(bytes)
}

impl SyncConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let value: Self = serde_json::from_slice(&read_private(path, CONFIG_BYTES)?)
            .map_err(|_| PolicyError::InvalidConfig)?;
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<()> {
        if let Some(ack) = &self.runtime_ack {
            ack.validate()?;
        }
        let host = &self.authority_host;
        let hostname = !host.is_empty()
            && host.len() <= 253
            && host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label.as_bytes()[0].is_ascii_alphanumeric()
                    && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            });
        let user = &self.authority_user;
        if self.schema != "aegis_device_policy_ssh_v1"
            || (!hostname && host.parse::<std::net::IpAddr>().is_err())
            || self.authority_port == 0
            || !(1..=60).contains(&self.timeout_secs)
            || user.is_empty()
            || user.len() > 32
            || !user.as_bytes()[0].is_ascii_alphabetic()
            || !user
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || !absolute(&self.registry)
        {
            return Err(PolicyError::InvalidConfig);
        }
        // OpenSSH interprets tokens, environment expansions and whitespace in
        // these options. Require literal paths so validation and SSH open the
        // same pinned files, without introducing another path language.
        for file in [&self.identity_file, &self.known_hosts_file] {
            if !file.to_str().is_some_and(|text| {
                text.bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"/._-".contains(&byte))
            }) {
                return Err(PolicyError::InvalidConfig);
            }
        }
        aegis_core::secret_file::trusted_parent(&self.registry)
            .map_err(|_| PolicyError::UnsafeInput)?;
        checked_file(&self.identity_file, 64 * 1024, true)?;
        let hosts = read_private(&self.known_hosts_file, CONFIG_BYTES)?;
        let hosts = std::str::from_utf8(&hosts).map_err(|_| PolicyError::InvalidConfig)?;
        let fields: Vec<_> = hosts.split_whitespace().collect();
        if fields.len() != 3
            || fields[0] != HOST_ALIAS
            || fields[1] != "ssh-ed25519"
            || fields[2].len() > 128
            || fields[2].is_empty()
            || !fields[2]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b))
        {
            return Err(PolicyError::InvalidConfig);
        }
        Ok(())
    }

    fn command(&self) -> Command {
        self.configure_command(Command::new(SSH))
    }

    fn configure_command(&self, mut command: Command) -> Command {
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C");
        command.args(["-F", "/dev/null", "-T"]);
        for option in [
            "BatchMode=yes",
            "IdentitiesOnly=yes",
            "IdentityAgent=none",
            "PreferredAuthentications=publickey",
            "PubkeyAcceptedAlgorithms=ssh-ed25519",
            "CertificateFile=none",
            "PKCS11Provider=none",
            "AddKeysToAgent=no",
            "ForwardAgent=no",
            "ForwardX11=no",
            "Tunnel=no",
            "PasswordAuthentication=no",
            "KbdInteractiveAuthentication=no",
            "HostbasedAuthentication=no",
            "GSSAPIAuthentication=no",
            "NumberOfPasswordPrompts=0",
            "StrictHostKeyChecking=yes",
            "GlobalKnownHostsFile=/dev/null",
            "VerifyHostKeyDNS=no",
            "UpdateHostKeys=no",
            "HostKeyAlgorithms=ssh-ed25519",
            "ClearAllForwardings=yes",
            "PermitLocalCommand=no",
            "ProxyCommand=none",
            "ProxyJump=none",
            "ControlMaster=no",
            "ControlPath=none",
            "ControlPersist=no",
            "CanonicalizeHostname=no",
            "ConnectionAttempts=1",
        ] {
            command.arg("-o").arg(option);
        }
        command
            .arg("-o")
            .arg(format!("HostKeyAlias={HOST_ALIAS}"))
            .arg("-o")
            .arg(format!(
                "UserKnownHostsFile={}",
                self.known_hosts_file.display()
            ))
            .arg("-o")
            .arg(format!("ConnectTimeout={}", self.timeout_secs))
            .arg("-i")
            .arg(&self.identity_file)
            .arg("-l")
            .arg(&self.authority_user)
            .arg("-p")
            .arg(self.authority_port.to_string())
            .arg("--")
            .arg(&self.authority_host)
            .arg(REMOTE_COMMAND);
        command
    }
}

/// Keep the group leader unreaped until its whole owned group has been stopped.
/// In particular, cancellation must not leave an SSH child running. This guard
/// never signals an ID after reaping its leader, when the ID could be reused.
struct OwnedChild {
    child: tokio::process::Child,
    #[cfg(unix)]
    group_owned: bool,
}

impl OwnedChild {
    fn stop_group(&mut self) {
        #[cfg(unix)]
        if self.group_owned {
            if let Some(pid) = self.child.id() {
                // SAFETY: process_group(0) made our unreaped child the leader;
                // its positive PID reserves this group ID until child.wait().
                unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
            }
        }
        #[cfg(unix)]
        {
            self.group_owned = false;
        }
    }

    #[cfg(unix)]
    fn exited_unreaped(&mut self) -> Result<bool> {
        let pid = self.child.id().ok_or(PolicyError::TransportFailed)?;
        // Observe completion without reaping. EOF alone does not prove SSH
        // has exited, and reaping before group cleanup permits ID reuse.
        // SAFETY: waitid initializes this valid siginfo storage, addresses
        // only our child, and WNOWAIT leaves its status collectable by Tokio.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                return Ok(false);
            }
            if error.raw_os_error() == Some(libc::ECHILD) {
                // An unexpected external reaper means this ID is no longer
                // ours to signal. Fail rather than risk another process.
                self.group_owned = false;
            }
            return Err(PolicyError::TransportFailed);
        }
        // SAFETY: a successful waitid populated info; zero means pending.
        Ok(unsafe { info.si_pid() } != 0)
    }

    async fn wait(&mut self) -> Result<std::process::ExitStatus> {
        #[cfg(unix)]
        loop {
            if self.exited_unreaped()? {
                self.stop_group();
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        self.child
            .wait()
            .await
            .map_err(|_| PolicyError::TransportFailed)
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        self.stop_group();
        // Tokio schedules direct-child reaping on cancellation; any orphaned
        // descendants belong to OS init. Unix killing belongs to this guard,
        // so ECHILD cannot make a second kill_on_drop target a reused PID.
    }
}

async fn receive(command: Command, budget: Duration) -> Result<Vec<u8>> {
    receive_limit(command, budget, MAX_REGISTRY_BYTES).await
}

async fn receive_limit(mut command: Command, budget: Duration, limit: u64) -> Result<Vec<u8>> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.as_std_mut().process_group(0);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(cfg!(not(unix)));
    let mut child = OwnedChild {
        child: command.spawn().map_err(|_| PolicyError::TransportFailed)?,
        #[cfg(unix)]
        group_owned: true,
    };
    let mut output = child
        .child
        .stdout
        .take()
        .ok_or(PolicyError::TransportFailed)?;
    let transfer = async {
        let mut bytes = Vec::new();
        (&mut output)
            .take(limit + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| PolicyError::TransportFailed)?;
        if bytes.len() as u64 > limit {
            return Err(PolicyError::OutputTooLarge);
        }
        if !child.wait().await?.success() {
            return Err(PolicyError::TransportFailed);
        }
        Ok(bytes)
    };
    let result = match tokio::time::timeout(budget, transfer).await {
        Ok(result) => result,
        Err(_) => Err(PolicyError::Timeout),
    };
    if result.is_err() {
        child.stop_group();
        #[cfg(not(unix))]
        let _ = child.child.kill().await;
        let _ = child.child.wait().await;
    }
    result
}

fn apply(target: &Path, bytes: &[u8], now: u64) -> Result<SyncReceipt> {
    let snapshot = decode(bytes, now)?;
    // No local generation bump, expiry extension or received floor. A matching
    // pending snapshot can finish exact recovery through the same core API;
    // any different pending/floor identity remains a hard refusal.
    registry::publish_snapshot(target, &snapshot).map_err(|_| PolicyError::ApplyFailed)?;
    disk_receipt(&snapshot)
}

fn disk_receipt(snapshot: &DeviceRegistry) -> Result<SyncReceipt> {
    use sha2::{Digest, Sha256};
    let validity = snapshot.validity.ok_or(PolicyError::InvalidValidity)?;
    Ok(SyncReceipt {
        event_code: "device_policy_durable_apply",
        acknowledgement: "disk_only",
        generation: snapshot.generation,
        snapshot_sha256: hex::encode(Sha256::digest(canonical(snapshot)?)),
        issued_at_unix_secs: validity.issued_at_unix_secs,
        expires_at_unix_secs: validity.expires_at_unix_secs,
    })
}

pub async fn sync(config: &SyncConfig) -> Result<SyncReceipt> {
    config.validate()?;
    checked_file(Path::new(SSH), 32 * 1024 * 1024, false)?;
    let bytes = receive(config.command(), Duration::from_secs(config.timeout_secs)).await?;
    // Observe the clock after the bounded transfer, not before it.
    apply(&config.registry, &bytes, now()?)
}

#[cfg(all(test, unix))]
#[path = "device_policy_tests.rs"]
mod tests;
