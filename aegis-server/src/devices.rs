//! Offline device enrollment operator commands. No HTTP enrollment surface;
//! the daemon never needs the CA private key or the device private key.
use aegis_core::secure_channel::{
    enrollment,
    registry::{
        self, DeviceRegistry, InvitationPurpose, InvitationRecord,
        RegistryTransaction as Transaction,
    },
};
use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

#[derive(Debug, Args)]
pub struct DeviceArgs {
    #[arg(long)]
    pub registry: PathBuf,
    #[command(subcommand)]
    pub command: DeviceCommand,
}

#[derive(Debug, Subcommand)]
pub enum DeviceCommand {
    /// Create an empty authorization registry in an operator-owned directory.
    Init,
    /// Issue an expiring single-use invitation into a new private file.
    Invite {
        #[arg(long)]
        device_id: String,
        #[arg(long)]
        token_out: PathBuf,
        #[arg(long, default_value_t = 3600)]
        ttl_secs: u64,
    },
    /// Authorize one replacement certificate for a non-revoked device identity.
    RotateInvite {
        #[arg(long)]
        device_id: String,
        #[arg(long)]
        token_out: PathBuf,
        #[arg(long, default_value_t = 3600)]
        ttl_secs: u64,
    },
    /// Verify a client-generated CSR and consume an invitation while signing.
    Issue {
        #[arg(long)]
        csr: PathBuf,
        #[arg(long)]
        invitation_file: PathBuf,
        #[arg(long)]
        ca_cert: PathBuf,
        #[arg(long)]
        ca_key: PathBuf,
        #[arg(long)]
        certificate_out: PathBuf,
        #[arg(long, default_value_t = 86400)]
        lifetime_secs: u64,
    },
    /// Revoke one device; running relays close its existing authorized sessions.
    Revoke {
        #[arg(long)]
        device_id: String,
    },
    /// Permanently cancel one enrollment; publication/live ACK remain separate.
    CancelEnrollment {
        #[arg(long)]
        device_id: String,
        #[arg(long)]
        authority_config: PathBuf,
        /// Required for any already-published certificate; never adopt a prior ID.
        #[arg(long)]
        expected_certificate_sha256: Option<String>,
    },
    /// Inspect an exact cancellation target under an existing read-only lock.
    InspectCancellation {
        #[arg(long)]
        device_id: String,
        #[arg(long)]
        authority_config: PathBuf,
    },
    /// Cancel one inspected selection; a stale selection refuses without retry.
    CancelSelectedEnrollment {
        #[arg(long)]
        device_id: String,
        #[arg(long)]
        authority_config: PathBuf,
        #[arg(long)]
        expected_certificate_sha256: Option<String>,
        #[arg(long)]
        selection_sha256: String,
    },
    /// Apply a trusted authorization snapshot without decreasing its generation.
    ApplySnapshot {
        #[arg(long)]
        input: PathBuf,
    },
    /// Refresh policy validity or explicitly migrate a legacy registry.
    RefreshRegistry {
        #[arg(long, default_value_t = registry::DEFAULT_POLICY_TTL_SECS)]
        ttl_secs: u64,
    },
    /// Read generation, devices and aggregate invitation counts, without tokens.
    Status,
}

pub fn run(args: DeviceArgs) -> Result<()> {
    match args.command {
        DeviceCommand::Init => {
            initialize(&args.registry)?;
            println!("device registry initialized");
        }
        DeviceCommand::Invite {
            device_id,
            token_out,
            ttl_secs,
        } => {
            invite(
                &args.registry,
                &device_id,
                &token_out,
                ttl_secs,
                registry::unix_now()?,
            )?;
            println!("single-use device invitation written");
        }
        DeviceCommand::RotateInvite {
            device_id,
            token_out,
            ttl_secs,
        } => {
            rotate_invite(
                &args.registry,
                &device_id,
                &token_out,
                ttl_secs,
                registry::unix_now()?,
            )?;
            println!("single-use rotation invitation written; current certificate remains authorized until issue commits or expires");
        }
        DeviceCommand::Issue {
            csr,
            invitation_file,
            ca_cert,
            ca_key,
            certificate_out,
            lifetime_secs,
        } => {
            let record = issue(
                &args.registry,
                &csr,
                &invitation_file,
                &ca_cert,
                &ca_key,
                &certificate_out,
                lifetime_secs,
            )?;
            println!("{}", serde_json::to_string(&record)?);
        }
        DeviceCommand::Revoke { device_id } => {
            revoke(&args.registry, &device_id)?;
            println!("device revoked; relay reload must be observed separately");
        }
        DeviceCommand::CancelEnrollment {
            device_id,
            authority_config,
            expected_certificate_sha256,
        } => {
            crate::enrollment_service::cancel_enrollment(
                &authority_config,
                &args.registry,
                &device_id,
                expected_certificate_sha256.as_deref(),
            )?;
            println!("enrollment permanently cancelled; registry publication and live relay acknowledgement remain required");
        }
        DeviceCommand::InspectCancellation {
            device_id,
            authority_config,
        } => {
            let selection = crate::enrollment_service::inspect_cancellation(
                &authority_config,
                &args.registry,
                &device_id,
            )?;
            println!("{}", serde_json::to_string(&selection)?);
        }
        DeviceCommand::CancelSelectedEnrollment {
            device_id,
            authority_config,
            expected_certificate_sha256,
            selection_sha256,
        } => {
            let outcome = crate::enrollment_service::cancel_selected_enrollment(
                &authority_config,
                &args.registry,
                &device_id,
                expected_certificate_sha256.as_deref(),
                &selection_sha256,
            )?;
            println!("{}", serde_json::to_string(&outcome)?);
        }
        DeviceCommand::ApplySnapshot { input } => {
            registry::apply_snapshot(&args.registry, &input)
                .context("device registry snapshot application failed")?;
            println!("device registry snapshot applied; relay reload must be observed separately");
        }
        DeviceCommand::RefreshRegistry { ttl_secs } => {
            let registry = refresh_registry(&args.registry, ttl_secs)?;
            println!(
                "{}",
                serde_json::json!({"version": registry.version,
                    "generation": registry.generation, "validity": registry.validity})
            );
        }
        DeviceCommand::Status => {
            let registry = DeviceRegistry::load(&args.registry)?;
            let now = registry::unix_now()?;
            println!(
                "{}",
                serde_json::json!({"version":registry.version,"generation":registry.generation,
                "validity":registry.validity,"observed_at_unix_secs":now,"devices":registry.devices,
                "invitations": {"total":registry.invitations.len(), "active":registry.invitations.iter().filter(|i| !i.consumed && i.expires_unix_secs > now).count()}})
            );
        }
    }
    Ok(())
}

pub fn initialize(path: &Path) -> Result<()> {
    let transaction = Transaction::begin(path)?;
    let registry = DeviceRegistry::new(registry::unix_now()?, registry::DEFAULT_POLICY_TTL_SECS)?;
    transaction.save(path, &registry, true)?;
    Ok(())
}

pub fn refresh_registry(path: &Path, ttl_secs: u64) -> Result<DeviceRegistry> {
    refresh_registry_with_clock(path, ttl_secs, registry::unix_now)
}

fn refresh_registry_with_clock(
    path: &Path,
    ttl_secs: u64,
    clock: impl FnOnce() -> std::io::Result<u64>,
) -> Result<DeviceRegistry> {
    let transaction = Transaction::begin(path)?;
    let mut registry = transaction.load()?;
    registry.refresh_validity(clock()?, ttl_secs)?;
    transaction.save(path, &registry, false)?;
    Ok(registry)
}

fn advance(registry: &mut DeviceRegistry) -> Result<()> {
    registry.generation = registry
        .generation
        .checked_add(1)
        .context("device generation exhausted")?;
    Ok(())
}

pub fn invite(
    path: &Path,
    device_id: &str,
    token_out: &Path,
    ttl_secs: u64,
    now: u64,
) -> Result<()> {
    invite_with_purpose(path, device_id, token_out, ttl_secs, now, false)
}

pub fn rotate_invite(
    path: &Path,
    device_id: &str,
    token_out: &Path,
    ttl_secs: u64,
    now: u64,
) -> Result<()> {
    invite_with_purpose(path, device_id, token_out, ttl_secs, now, true)
}

fn invite_with_purpose(
    path: &Path,
    device_id: &str,
    token_out: &Path,
    ttl_secs: u64,
    now: u64,
    rotate: bool,
) -> Result<()> {
    registry::validate_device_id(device_id)?;
    anyhow::ensure!(
        (1..=86400).contains(&ttl_secs),
        "invitation lifetime must be 1 second..24 hours"
    );
    let transaction = Transaction::begin(path)?;
    let mut registry = transaction.load()?;
    anyhow::ensure!(
        transaction.enrollment_cancellation(device_id)?.is_none(),
        "device enrollment is permanently cancelled"
    );
    anyhow::ensure!(
        !registry
            .invitations
            .iter()
            .any(|i| i.device_id == device_id && !i.consumed && i.expires_unix_secs > now),
        "device already has an active invitation"
    );
    let existing = registry.devices.iter().find(|d| d.device_id == device_id);
    let purpose = if rotate {
        let existing = existing.context("rotation requires an existing device identity")?;
        anyhow::ensure!(
            !existing.revoked,
            "revoked device identities cannot be renewed"
        );
        // Explicit operator authorization can renew an expired certificate,
        // but never resurrect a revoked identity or replace an unexpected key.
        InvitationPurpose::Rotate {
            replaces_certificate_sha256: existing.certificate_sha256.clone(),
        }
    } else {
        anyhow::ensure!(
            existing.is_none(),
            "device id already registered; use rotate-invite explicitly"
        );
        InvitationPurpose::Enroll
    };
    let token = enrollment::new_invitation_token();
    registry.invitations.push(InvitationRecord {
        device_id: device_id.into(),
        token_sha256: hex::encode(Sha256::digest(token.as_bytes())),
        expires_unix_secs: now
            .checked_add(ttl_secs)
            .context("invitation expiry overflow")?,
        consumed: false,
        purpose,
    });
    advance(&mut registry)?;
    // A failed transaction leaves a harmless, unrecognized token file. Never
    // report success or expose an invitation before durable registration.
    enrollment::write_private_new(token_out, token.as_bytes())?;
    transaction.save(path, &registry, false)?;
    Ok(())
}

pub fn issue(
    path: &Path,
    csr: &Path,
    invitation_file: &Path,
    ca_cert: &Path,
    ca_key: &Path,
    certificate_out: &Path,
    lifetime_secs: u64,
) -> Result<registry::DeviceRecord> {
    issue_with_clock(
        path,
        csr,
        invitation_file,
        ca_cert,
        ca_key,
        certificate_out,
        lifetime_secs,
        registry::unix_now,
    )
}

#[allow(clippy::too_many_arguments)]
fn issue_with_clock(
    path: &Path,
    csr: &Path,
    invitation_file: &Path,
    ca_cert: &Path,
    ca_key: &Path,
    certificate_out: &Path,
    lifetime_secs: u64,
    clock: impl FnOnce() -> std::io::Result<u64>,
) -> Result<registry::DeviceRecord> {
    for input in [csr, invitation_file, ca_cert, ca_key] {
        enrollment::trusted_parent(input)?;
    }
    let token_bytes = aegis_core::secret_file::read(invitation_file, 256)?;
    let token = std::str::from_utf8(&token_bytes)
        .context("invitation encoding invalid")?
        .trim();
    aegis_core::auth_token::validate(token).map_err(anyhow::Error::msg)?;
    let token_hash = hex::encode(Sha256::digest(token.as_bytes()));
    let transaction = Transaction::begin(path)?;
    let mut registry = transaction.load()?;
    // Lock contention may outlast a short-lived invitation. Decide its
    // validity using the clock after obtaining the exclusive transaction.
    let now = clock()?;
    let invitation_index = registry
        .invitations
        .iter()
        .position(|i| i.token_sha256 == token_hash)
        .context("invitation unknown")?;
    let invitation = &registry.invitations[invitation_index];
    anyhow::ensure!(
        transaction
            .enrollment_cancellation(&invitation.device_id)?
            .is_none(),
        "device enrollment is permanently cancelled"
    );
    anyhow::ensure!(
        !invitation.consumed && invitation.expires_unix_secs > now,
        "invitation expired or already consumed"
    );
    let existing_index = registry
        .devices
        .iter()
        .position(|d| d.device_id == invitation.device_id);
    let replacement = match &invitation.purpose {
        InvitationPurpose::Enroll => {
            anyhow::ensure!(existing_index.is_none(), "device id already registered");
            None
        }
        InvitationPurpose::Rotate {
            replaces_certificate_sha256,
        } => {
            let index = existing_index.context("rotation device no longer exists")?;
            let existing = &registry.devices[index];
            anyhow::ensure!(
                !existing.revoked && existing.certificate_sha256 == *replaces_certificate_sha256,
                "rotation target revoked or superseded"
            );
            Some(index)
        }
    };
    let csr_bytes = read_public(csr)?;
    let ca_bytes = read_public(ca_cert)?;
    let key_bytes = aegis_core::secret_file::read(ca_key, 1024 * 1024)?;
    let issued = enrollment::sign_csr(
        &invitation.device_id,
        std::str::from_utf8(&csr_bytes).context("CSR encoding invalid")?,
        std::str::from_utf8(&ca_bytes).context("CA encoding invalid")?,
        std::str::from_utf8(&key_bytes).context("CA key encoding invalid")?,
        now,
        lifetime_secs,
    )?;
    registry.invitations[invitation_index].consumed = true;
    if let Some(index) = replacement {
        registry.devices[index] = issued.record.clone();
    } else {
        registry.devices.push(issued.record.clone());
    }
    advance(&mut registry)?;
    // Write the public certificate before consuming the invitation. An orphaned
    // certificate after commit failure is NOT in the authorization registry.
    enrollment::write_private_new(certificate_out, issued.certificate_pem.as_bytes())?;
    transaction.save(path, &registry, false)?;
    Ok(issued.record)
}

fn read_public(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file() && metadata.len() <= 1024 * 1024,
        "public credential must be a bounded regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid reads the operator identity only.
        let uid = unsafe { libc::geteuid() };
        anyhow::ensure!(
            (metadata.uid() == 0 || metadata.uid() == uid) && metadata.mode() & 0o022 == 0,
            "public enrollment input must be operator-owned and deny group/other writes"
        );
    }
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= 1024 * 1024,
        "public credential exceeds bound"
    );
    Ok(bytes)
}

pub fn revoke(path: &Path, device_id: &str) -> Result<()> {
    let transaction = Transaction::begin(path)?;
    let mut registry = transaction.load()?;
    let device = registry
        .devices
        .iter_mut()
        .find(|d| d.device_id == device_id)
        .context("device not found")?;
    if device.revoked {
        return Ok(());
    }
    device.revoked = true;
    advance(&mut registry)?;
    transaction.save(path, &registry, false)?;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests;
