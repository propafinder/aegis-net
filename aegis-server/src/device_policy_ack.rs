//! Linux system-unit ownership binds a local status reply to the live server.
use super::{PolicyError, Result, SyncReceipt};
use crate::device_policy_status::ProcessIdentity;
#[cfg(any(target_os = "linux", all(test, unix)))]
use crate::device_policy_status::Response;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAckConfig {
    #[serde(default = "default_service_unit")]
    pub service_unit: String,
    pub socket: PathBuf,
    pub service_uid: u32,
    pub service_gid: u32,
    pub timeout_secs: u64,
}

fn default_service_unit() -> String {
    "aegis-server.service".into()
}

impl RuntimeAckConfig {
    pub(super) fn validate(&self) -> Result<()> {
        let named_instance = self
            .service_unit
            .strip_prefix("aegis-server-")
            .and_then(|name| name.strip_suffix(".service"))
            .is_some_and(|name| {
                !name.is_empty()
                    && name.len() <= 32
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            });
        if !super::absolute(&self.socket)
            || (self.service_unit != "aegis-server.service" && !named_instance)
            || self.socket.as_os_str().as_encoded_bytes().len() > 100
            || !(1..=10).contains(&self.timeout_secs)
        {
            return Err(PolicyError::InvalidConfig);
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub(super) struct RuntimeAcknowledgement {
    event_code: &'static str,
    acknowledgement: &'static str,
    generation: u64,
    snapshot_sha256: String,
    issued_at_unix_secs: u64,
    expires_at_unix_secs: u64,
    effective_valid_for_ms: u64,
    process: ProcessIdentity,
    systemd_invocation_id: String,
}

#[cfg(not(target_os = "linux"))]
pub(super) async fn verify(
    _config: &RuntimeAckConfig,
    _expected: &SyncReceipt,
) -> Result<RuntimeAcknowledgement> {
    Err(PolicyError::RuntimeAckUnsupported)
}

#[cfg(not(target_os = "linux"))]
pub(super) async fn verify_current_until(
    _config: &RuntimeAckConfig,
    _registry: &std::path::Path,
    _deadline: tokio::time::Instant,
) -> Result<RuntimeAcknowledgement> {
    Err(PolicyError::RuntimeAckUnsupported)
}

#[cfg(any(target_os = "linux", all(test, unix)))]
#[derive(Debug, PartialEq, Eq)]
struct UnitIdentity {
    pid: u32,
    invocation: String,
    fragment: PathBuf,
    drop_ins: Vec<PathBuf>,
    control_group: String,
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn unit_identity(bytes: &[u8]) -> Result<UnitIdentity> {
    if bytes.len() > 16 * 1024 {
        return Err(PolicyError::RuntimeAckUnavailable);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| PolicyError::RuntimeAckUnavailable)?;
    let mut values = std::collections::HashMap::new();
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or(PolicyError::RuntimeAckUnavailable)?;
        if !matches!(
            key,
            "MainPID"
                | "ActiveState"
                | "InvocationID"
                | "FragmentPath"
                | "DropInPaths"
                | "ControlGroup"
        ) || values.insert(key, value).is_some()
        {
            return Err(PolicyError::RuntimeAckUnavailable);
        }
    }
    if values.len() != 6 || values.get("ActiveState") != Some(&"active") {
        return Err(PolicyError::RuntimeAckUnavailable);
    }
    let pid = values["MainPID"]
        .parse::<u32>()
        .map_err(|_| PolicyError::RuntimeAckUnavailable)?;
    let invocation = values["InvocationID"];
    let control_group = values["ControlGroup"];
    if pid == 0
        || invocation.len() != 32
        || !invocation
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(PolicyError::RuntimeAckUnavailable);
    }
    if control_group == "/"
        || control_group.len() > 512
        || !super::absolute(std::path::Path::new(control_group))
        || !control_group
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-@".contains(&b))
    {
        return Err(PolicyError::RuntimeAckUnavailable);
    }
    let fragment = PathBuf::from(values["FragmentPath"]);
    let drop_ins: Vec<PathBuf> = values["DropInPaths"]
        .split_ascii_whitespace()
        .map(PathBuf::from)
        .collect();
    if drop_ins.len() > 16 {
        return Err(PolicyError::RuntimeAckUnavailable);
    }
    for path in std::iter::once(&fragment).chain(&drop_ins) {
        if !super::absolute(path)
            || !path.to_str().is_some_and(|s| {
                s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/._-@".contains(&b))
            })
        {
            return Err(PolicyError::RuntimeAckUnavailable);
        }
    }
    Ok(UnitIdentity {
        pid,
        invocation: invocation.to_owned(),
        fragment,
        drop_ins,
        control_group: control_group.to_owned(),
    })
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn matches_live(
    expected: &SyncReceipt,
    response: Response,
    unit: &UnitIdentity,
    start_ticks: Option<u64>,
    elapsed_ms: u64,
) -> Result<RuntimeAcknowledgement> {
    let Response::Ready { policy, process } = response else {
        return Err(PolicyError::RuntimeAckUnavailable);
    };
    if process.pid != unit.pid
        || process.process_start_ticks != start_ticks
        || policy.generation != expected.generation
        || policy.snapshot_sha256 != expected.snapshot_sha256
        || policy.issued_at_unix_secs != expected.issued_at_unix_secs
        || policy.expires_at_unix_secs != expected.expires_at_unix_secs
        || policy.effective_valid_for_ms <= elapsed_ms
        || policy.effective_valid_for_ms > 3000
        || policy.effective_valid_for_ms > policy.policy_remaining_ms
        || policy.policy_remaining_ms
            > expected
                .expires_at_unix_secs
                .saturating_sub(expected.issued_at_unix_secs)
                .saturating_mul(1000)
    {
        return Err(PolicyError::RuntimeAckMismatch);
    }
    // Build metadata is informational and belongs to this credential-bound
    // process; it is not substituted for the signed release verifier.
    for text in [
        &process.version,
        &process.build_git,
        &process.build_target,
        &process.cargo_lock_sha256,
    ] {
        if text.is_empty()
            || text.len() > 128
            || !text
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-+".contains(&b))
        {
            return Err(PolicyError::RuntimeAckMismatch);
        }
    }
    Ok(RuntimeAcknowledgement {
        event_code: "device_policy_runtime_ack",
        acknowledgement: "live_process",
        generation: policy.generation,
        snapshot_sha256: policy.snapshot_sha256,
        issued_at_unix_secs: policy.issued_at_unix_secs,
        expires_at_unix_secs: policy.expires_at_unix_secs,
        effective_valid_for_ms: policy.effective_valid_for_ms - elapsed_ms,
        process,
        systemd_invocation_id: unit.invocation.clone(),
    })
}

#[cfg(target_os = "linux")]
async fn read_unit(service_unit: &str) -> Result<UnitIdentity> {
    use std::path::Path;
    super::checked_file(Path::new("/usr/bin/systemctl"), 32 * 1024 * 1024, false)?;
    let mut command = tokio::process::Command::new("/usr/bin/systemctl");
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .args([
            "--system",
            "show",
            "--no-pager",
            "--property=MainPID",
            "--property=ActiveState",
            "--property=InvocationID",
            "--property=FragmentPath",
            "--property=DropInPaths",
            "--property=ControlGroup",
            "--",
            service_unit,
        ]);
    let bytes = super::receive_limit(command, std::time::Duration::from_secs(2), 16 * 1024)
        .await
        .map_err(|_| PolicyError::RuntimeAckUnavailable)?;
    let identity = unit_identity(&bytes)?;
    for file in std::iter::once(&identity.fragment).chain(&identity.drop_ins) {
        super::checked_file(file, 64 * 1024, false)
            .map_err(|_| PolicyError::RuntimeAckUnavailable)?;
    }
    Ok(identity)
}

#[cfg(target_os = "linux")]
fn trusted_process(identity: &UnitIdentity) -> Result<Option<u64>> {
    use std::io::Read;
    let pid = identity.pid;
    let mut cgroup = String::new();
    std::fs::File::open(format!("/proc/{pid}/cgroup"))
        .and_then(|f| f.take(4097).read_to_string(&mut cgroup))
        .map_err(|_| PolicyError::RuntimeAckUnavailable)?;
    if cgroup.len() > 4096 || cgroup.trim_end() != format!("0::{}", identity.control_group) {
        return Err(PolicyError::RuntimeAckUnavailable);
    }
    // No /proc/PID/exe inspection: cross-UID reads need CAP_SYS_PTRACE. Kernel
    // credentials, unit ownership, invocation, cgroup and start ticks bind the
    // live process without granting that additional administrative capability.
    crate::device_policy_status::process_start_ticks(pid)
        .map_err(|_| PolicyError::RuntimeAckUnavailable)
}

#[cfg(target_os = "linux")]
async fn once(config: &RuntimeAckConfig, expected: &SyncReceipt) -> Result<RuntimeAcknowledgement> {
    let before = read_unit(&config.service_unit).await?;
    let start_ticks = trusted_process(&before)?;
    let queried_at = tokio::time::Instant::now();
    let response = crate::device_policy_status::query(
        &config.socket,
        config.service_uid,
        config.service_gid,
        before.pid,
    )
    .await
    .map_err(|_| PolicyError::RuntimeAckUnavailable)?;
    let after = read_unit(&config.service_unit).await?;
    if before != after || start_ticks != trusted_process(&after)? {
        return Err(PolicyError::RuntimeAckMismatch);
    }
    if expected.expires_at_unix_secs <= super::now()? {
        return Err(PolicyError::RuntimeAckUnavailable);
    }
    matches_live(
        expected,
        response,
        &after,
        start_ticks,
        queried_at.elapsed().as_millis() as u64,
    )
}

#[cfg(target_os = "linux")]
pub(super) async fn verify(
    config: &RuntimeAckConfig,
    expected: &SyncReceipt,
) -> Result<RuntimeAcknowledgement> {
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(config.timeout_secs);
    verify_until(config, expected, deadline).await
}

#[cfg(target_os = "linux")]
pub(super) async fn verify_until(
    config: &RuntimeAckConfig,
    expected: &SyncReceipt,
    deadline: tokio::time::Instant,
) -> Result<RuntimeAcknowledgement> {
    config.validate()?;
    tokio::time::timeout_at(deadline, async {
        loop {
            if let Ok(ack) = once(config, expected).await {
                return Ok(ack);
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| PolicyError::RuntimeAckUnavailable)?
}

#[cfg(target_os = "linux")]
pub(super) async fn verify_current_until(
    config: &RuntimeAckConfig,
    registry: &std::path::Path,
    deadline: tokio::time::Instant,
) -> Result<RuntimeAcknowledgement> {
    config.validate()?;
    health_until_with(registry, deadline, |expected| async move {
        once(config, &expected).await
    })
    .await
}

// The injected query is only the existing single strict live ACK attempt.
// Tests use the same durable reads, rotation decisions and original deadline.
#[cfg(any(target_os = "linux", all(test, unix)))]
async fn health_until_with<F, Fut>(
    registry: &std::path::Path,
    deadline: tokio::time::Instant,
    mut query: F,
) -> Result<RuntimeAcknowledgement>
where
    F: FnMut(SyncReceipt) -> Fut,
    Fut: std::future::Future<Output = Result<RuntimeAcknowledgement>>,
{
    tokio::time::timeout_at(deadline, async {
        loop {
            let snapshot = super::load_health_snapshot(registry, deadline).await?;
            super::current_policy(&snapshot, super::now()?)?;
            let expected = super::disk_receipt(&snapshot)?;
            if tokio::time::Instant::now() >= deadline {
                return Err(PolicyError::RuntimeAckUnavailable);
            }
            let attempt = query(expected.clone()).await;
            let acknowledged_at = tokio::time::Instant::now();
            let snapshot = super::load_health_snapshot(registry, deadline).await?;
            super::current_policy(&snapshot, super::now()?)?;
            let current = super::disk_receipt(&snapshot)?;
            if tokio::time::Instant::now() >= deadline {
                return Err(PolicyError::RuntimeAckUnavailable);
            }
            if matches!(
                &attempt,
                Err(PolicyError::InvalidConfig | PolicyError::RuntimeAckUnsupported)
            ) {
                return attempt;
            }
            if current != expected {
                // Only a valid newer durable publication can stale this
                // attempt. A rollback or same-generation change cannot.
                if current.generation <= expected.generation {
                    return Err(PolicyError::RuntimeAckMismatch);
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
            let mut acknowledgement = match attempt {
                Ok(acknowledgement) => acknowledgement,
                Err(_) => {
                    // The watcher may still be adopting this valid durable
                    // tuple. Keep the original ACK convergence tolerance,
                    // reloading the tuple before the next strict attempt.
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };
            // Round up, so sub-millisecond readback work cannot extend the
            // strict query's already-debited live lease.
            let readback_ms =
                u64::try_from(acknowledged_at.elapsed().as_nanos().div_ceil(1_000_000))
                    .map_err(|_| PolicyError::RuntimeAckUnavailable)?;
            acknowledgement.effective_valid_for_ms = acknowledgement
                .effective_valid_for_ms
                .checked_sub(readback_ms)
                .filter(|remaining| *remaining > 0)
                .ok_or(PolicyError::RuntimeAckUnavailable)?;
            if tokio::time::Instant::now() >= deadline {
                return Err(PolicyError::RuntimeAckUnavailable);
            }
            return Ok(acknowledgement);
        }
    })
    .await
    .map_err(|_| PolicyError::RuntimeAckUnavailable)?
}

#[cfg(all(test, unix))]
#[path = "device_policy_ack_tests.rs"]
mod tests;

#[cfg(all(test, unix))]
#[path = "device_policy_health_tests.rs"]
mod health_tests;
