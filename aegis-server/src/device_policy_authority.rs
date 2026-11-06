//! A service manager passes one root-private inbox descriptor to the issuer UID.
//! The root publisher consumes that same inode under a shared lock. Neither side
//! grants the read-only SSH account access to issuer state or signing keys.
use super::*;
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io::{Seek, SeekFrom};

#[cfg(unix)]
fn validate_output(file: &File) -> Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    let info = file.metadata().map_err(|_| PolicyError::UnsafeInput)?;
    // SAFETY: F_GETFL only reads flags from the borrowed live file descriptor.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if !info.is_file()
        || info.uid() != 0
        || info.nlink() != 1
        || info.mode() & 0o7777 != 0o600
        || info.len() > MAX_REGISTRY_BYTES
        || flags < 0
        || flags & libc::O_APPEND != 0
        || flags & libc::O_ACCMODE == libc::O_RDONLY
    {
        return Err(PolicyError::UnsafeInput);
    }
    Ok(())
}

#[cfg(unix)]
pub(super) fn refresh_export(path: &Path, ttl_secs: u64) -> Result<()> {
    use std::os::fd::BorrowedFd;
    // SAFETY: stdout belongs to this process; the borrowed descriptor is used
    // only to obtain a CLOEXEC-owned duplicate, never to close descriptor 1.
    let descriptor = unsafe { BorrowedFd::borrow_raw(libc::STDOUT_FILENO) }
        .try_clone_to_owned()
        .map_err(|_| PolicyError::UnsafeInput)?;
    let mut output = File::from(descriptor);
    validate_output(&output)?;
    output.try_lock().map_err(|_| PolicyError::StageBusy)?;
    // Recheck after acquiring the inode lock, before any registry mutation.
    validate_output(&output)?;
    refresh_locked(&mut output, path, ttl_secs)
}

/// Called only after the output descriptor is validated and exclusively locked.
/// Separating the operation permits file-I/O fault tests without root privileges.
#[cfg(unix)]
fn refresh_locked(output: &mut File, path: &Path, ttl_secs: u64) -> Result<()> {
    if !absolute(path) || !(1..=registry::MAX_POLICY_TTL_SECS).contains(&ttl_secs) {
        return Err(PolicyError::InvalidConfig);
    }
    crate::devices::refresh_registry(path, ttl_secs)
        .map_err(|_| PolicyError::RegistryUnavailable)?;
    // Reload the verified pair after refresh: a concurrent issuance/pending
    // operation must not leak an incomplete or no-longer-current snapshot.
    let bytes = export(path, now()?)?;
    decode(&bytes, now()?)?;
    // Never truncate the last stage on a source/validity/refresh failure. If the
    // following I/O fails, a truncated canonical JSON prefix is not publishable.
    output
        .seek(SeekFrom::Start(0))
        .and_then(|_| output.set_len(0))
        .and_then(|_| output.write_all(&bytes))
        .and_then(|_| output.sync_all())
        .map_err(|_| PolicyError::StageIoFailed)
}

#[cfg(unix)]
pub(super) fn publish_staged(input: &Path, target: &Path) -> Result<SyncReceipt> {
    require_administrator()?;
    let file = checked_file(input, MAX_REGISTRY_BYTES, true)?;
    publish_file(file, target)
}

#[cfg(unix)]
fn publish_file(mut file: File, target: &Path) -> Result<SyncReceipt> {
    file.try_lock_shared().map_err(|_| PolicyError::StageBusy)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_REGISTRY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| PolicyError::StageIoFailed)?;
    // Keep the shared inode lock through validation and durable floor apply.
    // This is publication of the authority's deadline, never replica refresh.
    let receipt = apply(target, &bytes, now()?);
    drop(file);
    receipt
}

#[cfg(not(unix))]
pub(super) fn refresh_export(_path: &Path, _ttl_secs: u64) -> Result<()> {
    Err(PolicyError::AdministratorRequired)
}

#[cfg(not(unix))]
pub(super) fn publish_staged(_input: &Path, _target: &Path) -> Result<SyncReceipt> {
    Err(PolicyError::AdministratorRequired)
}

#[cfg(all(test, unix))]
#[path = "device_policy_authority_tests.rs"]
mod tests;
