//! A single explicit backend per state file. No automatic downgrade or backup
//! of an OS credential into an exportable adjacent key file.
use super::{ensure_private_parent_dir, key_file_path, parse_master_key, write_private_file};
use crate::{AegisError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateKeyStore {
    /// Compatibility backend: permissions only, not protection of a disk copy.
    #[default]
    PrivateFile,
    /// Native macOS Keychain / Windows Credential Store, never the mock backend.
    OsKeyring,
    /// Read-only credential provisioned by systemd. TPM policy belongs to systemd.
    SystemdCredential,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    schema: u8,
    backend: StateKeyStore,
}

#[derive(Debug, Serialize)]
pub struct StateKeyStoreStatus {
    pub backend: StateKeyStore,
    pub adjacent_key_file_present: bool,
    pub native_backend_available: bool,
    pub protection: &'static str,
}

fn error(code: &'static str) -> AegisError {
    AegisError::Config(code.into())
}

fn policy_path(path: &Path) -> PathBuf {
    key_file_path(path).with_extension("key-store.json")
}

fn policy(path: &Path) -> Result<StateKeyStore> {
    let bytes = match crate::secret_file::read(&policy_path(path), 1024) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(StateKeyStore::PrivateFile)
        }
        Err(e) => return Err(e.into()),
    };
    let policy: Policy =
        serde_json::from_slice(&bytes).map_err(|_| error("state_key_policy_invalid"))?;
    if policy.schema != 1 {
        return Err(error("state_key_policy_version"));
    }
    Ok(policy.backend)
}

pub fn key_store_status(path: &Path) -> Result<StateKeyStoreStatus> {
    let backend = policy(path)?;
    let available = match backend {
        StateKeyStore::OsKeyring => cfg!(any(target_os = "macos", windows)),
        StateKeyStore::SystemdCredential => cfg!(target_os = "linux"),
        StateKeyStore::PrivateFile => true,
    };
    Ok(StateKeyStoreStatus {
        backend,
        adjacent_key_file_present: std::fs::symlink_metadata(key_file_path(path)).is_ok(),
        native_backend_available: available,
        protection: match backend {
            StateKeyStore::PrivateFile => "file_permissions_only",
            StateKeyStore::OsKeyring => "os_credential_store",
            StateKeyStore::SystemdCredential => "systemd_credential_source_tpm_policy_not_inferred",
        },
    })
}

// Cooperating processes serialize policy migration and first-key creation.
// try_lock keeps a persist attempt bounded; Brain can retry a busy store later.
pub(super) fn lock(path: &Path) -> Result<std::fs::File> {
    let lock_path = key_file_path(path).with_extension("key-lock");
    ensure_private_parent_dir(&lock_path)?;
    #[cfg(windows)]
    {
        match crate::windows_file::create_private_file(&lock_path, false) {
            Ok(file) => drop(file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options
            .create(false)
            .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(&lock_path)?;
    #[cfg(windows)]
    crate::windows_file::validate_private(&file, false)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(error("state_key_lock_not_regular"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid only reads the process identity.
        let uid = unsafe { libc::geteuid() };
        if metadata.mode() & 0o077 != 0 || (metadata.uid() != 0 && metadata.uid() != uid) {
            return Err(error("state_key_lock_permissions"));
        }
    }
    file.try_lock().map_err(|_| error("state_key_store_busy"))?;
    Ok(file)
}

fn file_key(path: &Path) -> Result<Option<[u8; 32]>> {
    let bytes = match crate::secret_file::read(path, 128) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let text = std::str::from_utf8(&bytes).map_err(|_| error("state_key_encoding"))?;
    parse_master_key(text.trim()).map(Some)
}

trait ExternalStore {
    fn read(&self, path: &Path, backend: StateKeyStore) -> Result<Option<[u8; 32]>>;
    fn write(&self, path: &Path, backend: StateKeyStore, key: &[u8; 32]) -> Result<()>;
}

struct Native;

#[cfg(any(target_os = "macos", windows))]
fn entry(path: &Path) -> Result<keyring::Entry> {
    use sha2::{Digest, Sha256};
    let id = format!(
        "state-{}",
        hex::encode(&Sha256::digest(path.as_os_str().to_string_lossy().as_bytes())[..8])
    );
    keyring::Entry::new("io.aegis.state-cache", &id).map_err(|_| error("state_keyring_unavailable"))
}

impl ExternalStore for Native {
    fn read(&self, path: &Path, backend: StateKeyStore) -> Result<Option<[u8; 32]>> {
        match backend {
            StateKeyStore::PrivateFile => file_key(&key_file_path(path)),
            StateKeyStore::OsKeyring => {
                #[cfg(any(target_os = "macos", windows))]
                {
                    match entry(path)?.get_password() {
                        Ok(value) => parse_master_key(Zeroizing::new(value).trim()).map(Some),
                        Err(keyring::Error::NoEntry) => Ok(None),
                        Err(_) => Err(error("state_keyring_read_failed")),
                    }
                }
                #[cfg(not(any(target_os = "macos", windows)))]
                Err(error("state_native_keyring_not_supported"))
            }
            StateKeyStore::SystemdCredential => {
                if !cfg!(target_os = "linux") {
                    return Err(error("state_systemd_credential_not_supported"));
                }
                let dir = std::env::var_os("CREDENTIALS_DIRECTORY")
                    .ok_or_else(|| error("state_systemd_credential_missing"))?;
                let dir = PathBuf::from(dir);
                if !dir.is_absolute() {
                    return Err(error("state_systemd_credential_path"));
                }
                file_key(&dir.join("aegis-state-key"))?
                    .map(Some)
                    .ok_or_else(|| error("state_systemd_credential_missing"))
            }
        }
    }

    fn write(&self, path: &Path, backend: StateKeyStore, key: &[u8; 32]) -> Result<()> {
        match backend {
            StateKeyStore::PrivateFile => {
                let encoded = Zeroizing::new(hex::encode(key));
                write_private_file(&key_file_path(path), encoded.as_bytes())
            }
            StateKeyStore::OsKeyring => {
                #[cfg(any(target_os = "macos", windows))]
                {
                    let encoded = Zeroizing::new(hex::encode(key));
                    entry(path)?
                        .set_password(&encoded)
                        .map_err(|_| error("state_keyring_write_failed"))
                }
                #[cfg(not(any(target_os = "macos", windows)))]
                Err(error("state_native_keyring_not_supported"))
            }
            StateKeyStore::SystemdCredential => {
                let supplied = Zeroizing::new(
                    self.read(path, backend)?
                        .ok_or_else(|| error("state_systemd_credential_missing"))?,
                );
                if supplied.as_ref() != key {
                    return Err(error("state_systemd_credential_key_mismatch"));
                }
                Ok(())
            }
        }
    }
}

pub(super) fn load(path: &Path) -> Result<Option<[u8; 32]>> {
    Native.read(path, policy(path)?)
}

pub(super) fn store(path: &Path, key: &[u8; 32]) -> Result<()> {
    let backend = policy(path)?;
    Native.write(path, backend, key)?;
    let readback = Zeroizing::new(
        Native
            .read(path, backend)?
            .ok_or_else(|| error("state_key_readback_missing"))?,
    );
    if readback.as_ref() != key {
        return Err(error("state_key_readback_mismatch"));
    }
    Ok(())
}

/// Move an existing key after readback; no key bytes are returned to the CLI.
/// Stop the old runtime first: earlier binaries do not honor the policy marker.
pub fn migrate_key_store(path: &Path, backend: StateKeyStore) -> Result<StateKeyStoreStatus> {
    if std::env::var_os(super::ENV_STATE_KEY).is_some() {
        return Err(error(
            "state_key_migration_requires_environment_override_unset",
        ));
    }
    let _lock = lock(path)?;
    migrate_with(path, backend, &Native)?;
    key_store_status(path)
}

fn migrate_with(path: &Path, backend: StateKeyStore, native: &impl ExternalStore) -> Result<()> {
    if backend == StateKeyStore::PrivateFile {
        return Err(error("state_key_migration_to_plain_file_disallowed"));
    }
    let old = policy(path)?;
    // Migration across two external stores needs explicit revocation of the
    // previous store. This API only upgrades the legacy file, or retries its
    // cleanup; it must not silently leave a second native credential behind.
    if old != StateKeyStore::PrivateFile && old != backend {
        return Err(error("state_key_cross_store_migration_not_supported"));
    }
    let key = Zeroizing::new(
        native
            .read(path, old)?
            .ok_or_else(|| error("state_master_key_unavailable"))?,
    );
    // Native set_secret APIs overwrite existing credentials. Never destroy a
    // different recovery key merely because a stale adjacent file exists.
    let destination = native.read(path, backend)?.map(Zeroizing::new);
    match destination {
        Some(existing) if existing.as_ref() != key.as_ref() => {
            return Err(error("state_key_destination_conflict"));
        }
        Some(_) => {}
        None => native.write(path, backend, &key)?,
    }
    let verified = Zeroizing::new(
        native
            .read(path, backend)?
            .ok_or_else(|| error("state_key_readback_missing"))?,
    );
    if key.as_ref() != verified.as_ref() {
        return Err(error("state_key_readback_mismatch"));
    }
    // Commit the new backend before removing the old copy. If cleanup fails,
    // status reports the residue and repeating migration safely retries it.
    write_private_file(
        &policy_path(path),
        &serde_json::to_vec(&Policy { schema: 1, backend })
            .map_err(|_| error("state_key_policy_encode"))?,
    )?;
    match std::fs::remove_file(key_file_path(path)) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    #[cfg(unix)]
    std::fs::File::open(path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[cfg(any(target_os = "macos", windows))]
    #[test]
    #[ignore = "uses a temporary synthetic credential in the native OS store"]
    fn native_keyring_migration_preserves_ciphertext_without_adjacent_copy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("synthetic-state");
        let result = (|| -> Result<()> {
            let blob = super::super::seal_state_blob(&path, b"synthetic test state")?;
            write_private_file(&path, &blob)?;
            let status = migrate_key_store(&path, StateKeyStore::OsKeyring)?;
            if status.adjacent_key_file_present {
                return Err(error("fixture_key_copy_remains"));
            }
            let plaintext = super::super::maybe_decrypt_state_blob(&path, &blob)?;
            if plaintext.as_deref() != Some(b"synthetic test state") {
                return Err(error("fixture_migration_decrypt_failed"));
            }
            // A second entry is created inside every Native.read, so this
            // also fails if a feature regression selects keyring's mock store.
            if Native.read(&path, StateKeyStore::OsKeyring)?.is_none() {
                return Err(error("fixture_native_readback_failed"));
            }
            Ok(())
        })();
        let cleanup = entry(&path).and_then(|entry| {
            entry
                .delete_credential()
                .map_err(|_| error("fixture_native_cleanup_failed"))
        });
        result.unwrap();
        cleanup.unwrap();
    }

    #[test]
    fn malformed_policy_fails_closed_instead_of_falling_back_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache");
        Native
            .write(&path, StateKeyStore::PrivateFile, &[4; 32])
            .unwrap();
        write_private_file(
            &policy_path(&path),
            b"{\"schema\":2,\"backend\":\"os_keyring\"}",
        )
        .unwrap();
        assert!(load(&path).is_err());
        write_private_file(&policy_path(&path), b"{}").unwrap();
        assert!(load(&path).is_err());
        assert_eq!(file_key(&key_file_path(&path)).unwrap(), Some([4; 32]));
    }
    #[derive(Default)]
    struct Fixture {
        key: RefCell<Option<[u8; 32]>>,
        fail_readback: bool,
    }
    impl ExternalStore for Fixture {
        fn read(&self, path: &Path, backend: StateKeyStore) -> Result<Option<[u8; 32]>> {
            if backend == StateKeyStore::PrivateFile {
                return file_key(&key_file_path(path));
            }
            if self.fail_readback && self.key.borrow().is_some() {
                return Err(error("fixture_readback_failed"));
            }
            Ok(*self.key.borrow())
        }
        fn write(&self, _: &Path, _: StateKeyStore, key: &[u8; 32]) -> Result<()> {
            *self.key.borrow_mut() = Some(*key);
            Ok(())
        }
    }
    #[test]
    fn verified_migration_removes_disk_duplicate_and_selects_only_one_backend() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache");
        Native
            .write(&path, StateKeyStore::PrivateFile, &[9; 32])
            .unwrap();
        let fixture = Fixture::default();
        migrate_with(&path, StateKeyStore::OsKeyring, &fixture).unwrap();
        assert_eq!(policy(&path).unwrap(), StateKeyStore::OsKeyring);
        assert!(!key_file_path(&path).exists());
        assert_eq!(
            fixture.read(&path, policy(&path).unwrap()).unwrap(),
            Some([9; 32])
        );
        migrate_with(&path, StateKeyStore::OsKeyring, &fixture).unwrap();
    }
    #[test]
    fn readback_failure_keeps_original_policy_and_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache");
        Native
            .write(&path, StateKeyStore::PrivateFile, &[7; 32])
            .unwrap();
        let fixture = Fixture {
            fail_readback: true,
            ..Fixture::default()
        };
        assert!(migrate_with(&path, StateKeyStore::OsKeyring, &fixture).is_err());
        assert_eq!(policy(&path).unwrap(), StateKeyStore::PrivateFile);
        assert_eq!(file_key(&key_file_path(&path)).unwrap(), Some([7; 32]));
    }
    #[test]
    fn conflicting_native_key_is_not_overwritten_or_selected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache");
        Native
            .write(&path, StateKeyStore::PrivateFile, &[7; 32])
            .unwrap();
        let fixture = Fixture {
            key: RefCell::new(Some([8; 32])),
            ..Fixture::default()
        };
        let error = migrate_with(&path, StateKeyStore::OsKeyring, &fixture).unwrap_err();
        assert!(error.to_string().contains("state_key_destination_conflict"));
        assert_eq!(*fixture.key.borrow(), Some([8; 32]));
        assert_eq!(file_key(&key_file_path(&path)).unwrap(), Some([7; 32]));
        assert_eq!(policy(&path).unwrap(), StateKeyStore::PrivateFile);
    }
    #[test]
    fn file_backend_is_explicit_and_old_seed_loads_without_keyring() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache");
        Native
            .write(&path, StateKeyStore::PrivateFile, &[4; 32])
            .unwrap();
        assert_eq!(load(&path).unwrap(), Some([4; 32]));
        assert_eq!(
            key_store_status(&path).unwrap().protection,
            "file_permissions_only"
        );
        let _first = lock(&path).unwrap();
        assert!(lock(&path).is_err());
    }
}
