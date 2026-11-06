//! Explicit same-binding recovery of a pending Redeem invitation.
//! The caller must first receive an authenticated Receipt rejection. This
//! module owns only the local Store transition, never issuer authorization.
use super::*;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

const MAX_REFRESH_PENDING: usize = 16 * 1024;
const MAX_REFRESH_JOURNAL: usize = 64 * 1024;

pub(crate) struct RefreshSnapshot {
    pub material: RequestMaterial,
    key_sha256: String,
    pending_raw: Zeroizing<Vec<u8>>,
}

fn absent(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Ok(_) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RefreshJournal {
    version: u8,
    binding: RequestBinding,
    device_id: String,
    key_sha256: String,
    old_pending_sha256: String,
    old_pending_hex: String,
    new_invitation_sha256: String,
    new_pending_sha256: String,
}
impl Drop for RefreshJournal {
    fn drop(&mut self) {
        self.old_pending_hex.zeroize();
    }
}

pub(crate) fn prepare_refresh(directory: &Path, profile_sha256: &str) -> Result<RefreshSnapshot> {
    ensure!(
        directory.is_absolute() && directory.canonicalize()? == directory,
        "refresh identity path must be canonical"
    );
    let store = Store::open(directory, false)?;
    let record = store.record()?;
    ensure!(
        record.phase == "prepared" && absent(&store.path("device.pem"))?,
        "refresh requires an unissued prepared identity"
    );
    ensure!(
        optional::<SavedResponse>(&store, RESPONSE)?.is_none(),
        "saved response must be completed before invitation refresh"
    );
    let pending_raw = read_large(&store, REQUEST)?;
    ensure!(
        pending_raw.len() <= MAX_REFRESH_PENDING,
        "pending request exceeds refresh bound"
    );
    let pending: Pending = serde_json::from_slice(&pending_raw)?;
    validate_pending(&store, &record, &pending)?;
    ensure!(
        pending.binding.operation == Operation::Redeem
            && pending.binding.profile_sha256 == profile_sha256,
        "refresh requires the exact pending Redeem profile"
    );
    let key_sha256 = sha(&store.read("device.key")?);
    let csr_pem = std::str::from_utf8(&store.read("device.csr")?)?.to_owned();
    ensure!(
        sha(csr_pem.as_bytes()) == pending.binding.csr_sha256,
        "refresh CSR differs from pending binding"
    );
    Ok(RefreshSnapshot {
        material: RequestMaterial {
            binding: pending.binding.clone(),
            csr_pem,
            predecessor_certificate_pem: None,
            invitation: pending
                .invitation
                .as_ref()
                .map(|v| Zeroizing::new(v.clone())),
            resume: true,
        },
        key_sha256,
        pending_raw,
    })
}

struct RecoveryDir {
    path: PathBuf,
    held: File,
    dev: u64,
    ino: u64,
}
impl RecoveryDir {
    fn revalidate(&self) -> Result<()> {
        let held = self.held.metadata()?;
        let named = fs::symlink_metadata(&self.path)?;
        ensure!(
            held.dev() == self.dev
                && held.ino() == self.ino
                && named.dev() == self.dev
                && named.ino() == self.ino
                && held.uid() == unsafe { libc::geteuid() }
                && named.uid() == held.uid()
                && held.mode() & 0o077 == 0
                && named.mode() & 0o077 == 0,
            "refresh recovery directory generation changed"
        );
        Ok(())
    }
    fn sync(&self) -> Result<()> {
        self.revalidate()?;
        self.held.sync_all()?;
        self.revalidate()
    }
}

fn recovery_parent(identity: &Path, recovery_out: &Path) -> Result<RecoveryDir> {
    ensure!(
        recovery_out.is_absolute()
            && !recovery_out
                .components()
                .any(|c| matches!(c, Component::ParentDir)),
        "refresh recovery output requires a clean absolute path"
    );
    let parent = recovery_out
        .parent()
        .context("refresh recovery parent missing")?;
    let import_root = identity.parent().context("refresh import root missing")?;
    ensure!(
        parent.canonicalize()? == parent
            && identity.canonicalize()? == identity
            && parent.parent() == import_root.parent()
            && parent != import_root
            && !parent.starts_with(import_root),
        "refresh recovery directory must be outside the exact import root"
    );
    let metadata = fs::symlink_metadata(parent)?;
    ensure!(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
        "refresh recovery directory requires owner-only custody"
    );
    ensure!(
        enrollment::trusted_parent(recovery_out)? == parent,
        "refresh recovery ancestry changed"
    );
    let held = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)?;
    let held_meta = held.metadata()?;
    let owner = RecoveryDir {
        path: parent.to_owned(),
        held,
        dev: held_meta.dev(),
        ino: held_meta.ino(),
    };
    owner.revalidate()?;
    Ok(owner)
}

fn read_journal(path: &Path) -> Result<Option<RefreshJournal>> {
    match read_private(path) {
        Ok(raw) => {
            ensure!(
                raw.len() <= MAX_REFRESH_JOURNAL,
                "refresh recovery journal exceeds bound"
            );
            Ok(Some(serde_json::from_slice(&raw)?))
        }
        Err(error) if is_missing(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

fn publish_journal(path: &Path, parent: &RecoveryDir, journal: &RefreshJournal) -> Result<()> {
    let bytes = Zeroizing::new(serde_json::to_vec(journal)?);
    ensure!(
        bytes.len() <= MAX_REFRESH_JOURNAL,
        "refresh recovery journal exceeds bound"
    );
    parent.revalidate()?;
    let mut stage = tempfile::NamedTempFile::new_in(&parent.path)?;
    stage.write_all(&bytes)?;
    stage.as_file().sync_all()?;
    stage.persist_noclobber(path).map_err(|error| error.error)?;
    parent.sync()?;
    Ok(())
}

/// Called only after a pinned authority returned Rejected to Receipt for the
/// same binding. A new Enroll token still requires ordinary server validation.
/// Archive publication precedes the one atomic Store replacement; each crash
/// point is recognized using the exact old/new private request bytes.
pub(crate) fn replace_refresh_invitation(
    directory: &Path,
    profile_sha256: &str,
    snapshot: &RefreshSnapshot,
    invitation_file: &Path,
    recovery_out: &Path,
) -> Result<RequestMaterial> {
    ensure!(
        invitation_file.is_absolute() && invitation_file.canonicalize()? == invitation_file,
        "refresh invitation path must be canonical"
    );
    let parent = recovery_parent(directory, recovery_out)?;
    let import_root = directory.parent().context("refresh import root missing")?;
    ensure!(
        invitation_file != recovery_out && !invitation_file.starts_with(import_root),
        "refresh invitation aliases import root or recovery output"
    );
    let token = token_input(invitation_file)?;
    let store = Store::open(directory, false)?;
    #[cfg(unix)]
    store.protected.revalidate()?;
    let record = store.record()?;
    ensure!(
        record.phase == "prepared"
            && absent(&store.path("device.pem"))?
            && optional::<SavedResponse>(&store, RESPONSE)?.is_none(),
        "refresh cannot replace an issued identity or saved response"
    );
    let current_raw = read_large(&store, REQUEST)?;
    ensure!(
        current_raw.len() <= MAX_REFRESH_PENDING,
        "pending request exceeds refresh bound"
    );
    let current: Pending = serde_json::from_slice(&current_raw)?;
    validate_pending(&store, &record, &current)?;
    ensure!(
        current.binding == snapshot.material.binding
            && current.binding.operation == Operation::Redeem
            && current.binding.profile_sha256 == profile_sha256
            && sha(&store.read("device.key")?) == snapshot.key_sha256
            && sha(&store.read("device.csr")?) == current.binding.csr_sha256,
        "refresh identity, key, CSR or binding changed"
    );
    ensure!(
        current_raw.as_slice() == snapshot.pending_raw.as_slice(),
        "refresh pending changed after authenticated receipt query"
    );
    let existing = read_journal(recovery_out)?;
    let old_raw = if let Some(journal) = &existing {
        let raw = Zeroizing::new(hex::decode(&journal.old_pending_hex)?);
        ensure!(
            raw.len() <= MAX_REFRESH_PENDING && sha(&raw) == journal.old_pending_sha256,
            "refresh recovery original bytes invalid"
        );
        raw
    } else {
        Zeroizing::new(snapshot.pending_raw.to_vec())
    };
    let old: Pending = serde_json::from_slice(&old_raw)?;
    validate_pending(&store, &record, &old)?;
    ensure!(
        old.binding == current.binding && old.invitation.as_deref() != Some(token.as_str()),
        "refresh token must differ from the original invitation"
    );
    let replacement = Pending {
        version: old.version,
        binding: old.binding.clone(),
        predecessor_certificate_pem: None,
        invitation: Some(token.to_string()),
    };
    let new_raw = Zeroizing::new(serde_json::to_vec(&replacement)?);
    let journal = RefreshJournal {
        version: 1,
        binding: old.binding.clone(),
        device_id: record.device_id.clone(),
        key_sha256: snapshot.key_sha256.clone(),
        old_pending_sha256: sha(&old_raw),
        old_pending_hex: hex::encode(old_raw.as_slice()),
        new_invitation_sha256: sha(token.as_bytes()),
        new_pending_sha256: sha(&new_raw),
    };
    if let Some(existing) = existing {
        ensure!(
            existing.version == journal.version
                && existing.binding == journal.binding
                && existing.device_id == journal.device_id
                && existing.key_sha256 == journal.key_sha256
                && existing.old_pending_sha256 == journal.old_pending_sha256
                && existing.old_pending_hex == journal.old_pending_hex
                && existing.new_invitation_sha256 == journal.new_invitation_sha256
                && existing.new_pending_sha256 == journal.new_pending_sha256,
            "refresh recovery journal conflicts with exact request"
        );
        // Complete a journal publication that may have preceded a crash.
        parent.sync()?;
    } else {
        ensure!(
            current_raw.as_slice() == old_raw.as_slice(),
            "refresh pending changed before recovery publication"
        );
        publish_journal(recovery_out, &parent, &journal)?;
    }
    parent.revalidate()?;
    if current_raw.as_slice() == old_raw.as_slice() {
        // Store.save uses a synced temporary file and an atomic replacement.
        save_large(&store, REQUEST, &replacement, true)?;
    } else {
        ensure!(
            current_raw.as_slice() == new_raw.as_slice(),
            "refresh pending is neither archived original nor replacement"
        );
        aegis_core::secret_file::sync_directory(&store.directory)?;
    }
    ensure!(
        read_large(&store, REQUEST)?.as_slice() == new_raw.as_slice()
            && sha(&store.read("device.key")?) == snapshot.key_sha256
            && sha(&store.read("device.csr")?) == snapshot.material.binding.csr_sha256,
        "refresh postflight identity differs"
    );
    #[cfg(unix)]
    store.protected.revalidate()?;
    Ok(RequestMaterial {
        binding: snapshot.material.binding.clone(),
        csr_pem: snapshot.material.csr_pem.clone(),
        predecessor_certificate_pem: None,
        invitation: Some(token),
        resume: false,
    })
}
