use crate::error::{AegisError, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

const SEALED_STATE_MAGIC: &[u8; 4] = b"AEGS";
const ENV_STATE_KEY: &str = "AEGIS_STATE_KEY";
const ENV_ALLOW_STATE_KEY: &str = "AEGIS_ALLOW_ENV_STATE_KEY";
const STATE_KDF_SALT: &[u8] = b"aegis-state-kdf-v2";
const STATE_KDF_INFO: &[u8] = b"aegis-state-v2";
mod key_store;
pub use key_store::{key_store_status, migrate_key_store, StateKeyStore, StateKeyStoreStatus};

pub(crate) fn ensure_private_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        #[cfg(unix)]
        let created_parent = !parent.exists();
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if created_parent {
                let mut perms = std::fs::metadata(parent)?.permissions();
                perms.set_mode(0o700);
                std::fs::set_permissions(parent, perms)?;
            }
        }
    }
    Ok(())
}

pub(crate) async fn ensure_private_parent_dir_async(path: &Path) -> Result<()> {
    let owned = path.to_path_buf();
    tokio::task::spawn_blocking(move || ensure_private_parent_dir(&owned))
        .await
        .map_err(|err| AegisError::Config(format!("private_dir_join_error: {err}")))?
}

pub(crate) fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    write_private_file_with_owner(path, contents, preserve_file_owner)
}

fn write_private_file_with_owner<F>(path: &Path, contents: &[u8], preserve_owner: F) -> Result<()>
where
    F: FnOnce(&std::fs::File, &std::fs::Metadata) -> std::io::Result<()>,
{
    ensure_private_parent_dir(path)?;
    // Atomic replacement requires a regular destination (or no destination).
    // Do not follow a final symlink for ownership and then silently replace
    // that link instead of its target. The parent remains a trusted state dir.
    let existing = match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => Some(metadata),
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "private state destination must be a regular file, not a symlink or special file",
            )
            .into());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    // Stage on the same filesystem. Readers see either the complete old blob
    // or the complete new one, never a truncated in-place encrypted snapshot.
    #[cfg(not(windows))]
    let mut staged = tempfile::Builder::new()
        .prefix(".aegis-state-write-")
        .tempfile_in(parent)?;
    #[cfg(windows)]
    let mut staged = tempfile::Builder::new()
        .prefix(".aegis-state-write-")
        .make_in(parent, |path| {
            crate::windows_file::create_private_file(path, false)
        })?;
    if let Some(existing) = existing {
        // Root maintenance writes must not turn a service-owned 0600 state
        // into an unreadable root-owned replacement. Failure leaves the old
        // inode intact; apply ownership to our open staging fd, never a path.
        preserve_owner(staged.as_file(), &existing)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        staged
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    staged.write_all(contents)?;
    staged.as_file().sync_all()?;
    staged
        .persist(path)
        .map_err(|error| AegisError::Io(error.error))?;
    #[cfg(unix)]
    {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn preserve_file_owner(
    staged: &std::fs::File,
    existing: &std::fs::Metadata,
) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;
        let current = staged.metadata()?;
        if (current.uid(), current.gid()) != (existing.uid(), existing.gid()) {
            // SAFETY: staged owns a valid descriptor, and uid/gid were read
            // from the existing regular destination. No path is followed.
            let result =
                unsafe { libc::fchown(staged.as_raw_fd(), existing.uid(), existing.gid()) };
            if result != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    #[cfg(not(unix))]
    let _ = (staged, existing);
    Ok(())
}

pub(crate) async fn write_private_file_async(
    path: &Path,
    contents: Vec<u8>,
    lease: tokio::sync::OwnedMutexGuard<()>,
) -> Result<tokio::sync::OwnedMutexGuard<()>> {
    write_private_file_async_with(path, contents, lease, write_private_file).await
}

async fn write_private_file_async_with<F>(
    path: &Path,
    contents: Vec<u8>,
    lease: tokio::sync::OwnedMutexGuard<()>,
    write: F,
) -> Result<tokio::sync::OwnedMutexGuard<()>>
where
    F: FnOnce(&Path, &[u8]) -> Result<()> + Send + 'static,
{
    let owned = path.to_path_buf();
    // Cancelling the awaiting async flush cannot release the writer lock while
    // its spawn_blocking operation still runs and might overwrite a newer flush.
    tokio::task::spawn_blocking(move || {
        write(&owned, &contents)?;
        Ok(lease)
    })
    .await
    .map_err(|err| AegisError::Config(format!("private_write_join_error: {err}")))?
}

pub(crate) fn maybe_decrypt_state_blob(path: &Path, bytes: &[u8]) -> Result<Option<Vec<u8>>> {
    if !bytes.starts_with(SEALED_STATE_MAGIC) {
        return Ok(None);
    }
    let mut key = load_existing_master_key(path)?;
    let plaintext = decrypt_with_key(&key, &bytes[SEALED_STATE_MAGIC.len()..]);
    key.zeroize();
    plaintext.map(Some)
}

pub(crate) fn seal_state_blob(path: &Path, plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut key = load_or_create_master_key(path)?;
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ciphertext = encrypt_with_key(&key, &nonce, plaintext);
    key.zeroize();
    let ciphertext = ciphertext?;
    let mut out = Vec::with_capacity(SEALED_STATE_MAGIC.len() + nonce.len() + ciphertext.len());
    out.extend_from_slice(SEALED_STATE_MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn load_existing_master_key(path: &Path) -> Result<[u8; 32]> {
    if let Some(env_key) = maybe_env_master_key()? {
        return Ok(env_key);
    }
    let _lock = key_store::lock(path)?;
    key_store::load(path)?.ok_or_else(|| AegisError::Config("state_master_key_unavailable".into()))
}

fn load_or_create_master_key(path: &Path) -> Result<[u8; 32]> {
    if let Some(env_key) = maybe_env_master_key()? {
        return Ok(env_key);
    }
    let _lock = key_store::lock(path)?;
    if let Some(key) = key_store::load(path)? {
        return Ok(key);
    }
    // A missing credential must never silently rotate the key protecting
    // existing ciphertext. External backends are provisioned by migration.
    if key_store::key_store_status(path)?.backend != StateKeyStore::PrivateFile
        || state_file_is_sealed(path)?
    {
        return Err(AegisError::Config("state_master_key_unavailable".into()));
    }
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    if let Err(error) = key_store::store(path, &key) {
        key.zeroize();
        return Err(error);
    }
    Ok(key)
}

fn state_file_is_sealed(path: &Path) -> Result<bool> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    if !file.metadata()?.is_file() {
        return Err(AegisError::Config("state_file_not_regular".into()));
    }
    let mut magic = [0; 4];
    match file.read_exact(&mut magic) {
        Ok(()) => Ok(&magic == SEALED_STATE_MAGIC),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e.into()),
    }
}

fn maybe_env_master_key() -> Result<Option<[u8; 32]>> {
    let Ok(raw) = std::env::var(ENV_STATE_KEY) else {
        return Ok(None);
    };
    if !(cfg!(debug_assertions)
        || matches!(
            std::env::var(ENV_ALLOW_STATE_KEY).ok().as_deref(),
            Some("1" | "true" | "TRUE")
        ))
    {
        return Ok(None);
    }
    Ok(Some(parse_master_key(raw.trim())?))
}

fn parse_master_key(value: &str) -> Result<[u8; 32]> {
    let mut decoded =
        hex::decode(value).map_err(|_| AegisError::Config("state_master_key_hex".into()))?;
    if decoded.len() != 32 {
        decoded.zeroize();
        return Err(AegisError::Config("state_master_key_length".into()));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    decoded.zeroize();
    Ok(key)
}

fn key_file_path(path: &Path) -> PathBuf {
    let digest = Sha256::digest(path.as_os_str().to_string_lossy().as_bytes());
    let file_name = format!(".{}.seed", hex::encode(&digest[..6]));
    path.parent()
        .unwrap_or_else(|| Path::new("."))
        .join(file_name)
}

fn derive_aead_key(master: &[u8; 32]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(STATE_KDF_SALT), master);
    let mut okm = [0u8; 32];
    hk.expand(STATE_KDF_INFO, &mut okm).map_err(|_| {
        okm.zeroize();
        AegisError::Config("state_key_expand".into())
    })?;
    Ok(okm)
}

fn encrypt_with_key(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut derived = derive_aead_key(key)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&derived)
        .map_err(|_| AegisError::Config("chacha_key".into()))?;
    let ciphertext = cipher
        .encrypt(
            nonce.into(),
            Payload {
                msg: plaintext,
                aad: b"",
            },
        )
        .map_err(|_| AegisError::Config("encrypt_state".into()));
    derived.zeroize();
    ciphertext
}

fn decrypt_with_key(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < 12 {
        return Err(AegisError::Config("short_sealed_state".into()));
    }
    let (nonce_bytes, ciphertext) = blob.split_at(12);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(nonce_bytes);
    let mut derived = derive_aead_key(key)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&derived)
        .map_err(|_| AegisError::Config("chacha_key".into()))?;
    let plaintext = cipher
        .decrypt(
            &nonce.into(),
            Payload {
                msg: ciphertext,
                aad: b"",
            },
        )
        .map_err(|_| AegisError::Config("decrypt_state".into()));
    derived.zeroize();
    plaintext
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn missing_key_never_rotates_existing_encrypted_state() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("cache");
        let blob = seal_state_blob(&path, b"synthetic persisted state").unwrap();
        write_private_file(&path, &blob).unwrap();
        std::fs::remove_file(key_file_path(&path)).unwrap();
        assert!(seal_state_blob(&path, b"replacement").is_err());
        assert!(!key_file_path(&path).exists());
        assert_eq!(std::fs::read(&path).unwrap(), blob);
    }

    #[tokio::test]
    async fn cancelling_started_blocking_write_keeps_lease_until_atomic_commit() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.json");
        let writer_lock = std::sync::Arc::new(tokio::sync::Mutex::new(()));
        let lease = writer_lock.clone().lock_owned().await;
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let first_path = path.clone();
        let first = tokio::spawn(async move {
            write_private_file_async_with(
                &first_path,
                b"older snapshot".to_vec(),
                lease,
                move |path, bytes| {
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    write_private_file(path, bytes)
                },
            )
            .await
        });
        started_rx.await.unwrap();
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        assert!(
            writer_lock.try_lock().is_err(),
            "started blocking writer still owns the lease"
        );
        let second_lock = writer_lock.clone();
        let second_path = path.clone();
        let second = tokio::spawn(async move {
            let lease = second_lock.lock_owned().await;
            write_private_file_async(&second_path, b"newer snapshot".to_vec(), lease).await
        });
        release_tx.send(()).unwrap();
        let lease = tokio::time::timeout(std::time::Duration::from_secs(5), second)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        drop(lease);
        assert_eq!(std::fs::read(path).unwrap(), b"newer snapshot");
        assert!(writer_lock.try_lock().is_ok());
    }

    #[test]
    fn private_atomic_replace_keeps_complete_old_reader_and_private_new_file() {
        use std::io::Read;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.json");
        write_private_file(&path, b"old complete snapshot").unwrap();
        let mut old_reader = std::fs::File::open(&path).unwrap();
        #[cfg(not(windows))]
        write_private_file(&path, b"new complete snapshot").unwrap();
        #[cfg(windows)]
        {
            // MoveFileEx refuses to replace a destination with an open reader.
            // Failure must leave the complete old snapshot and no staging file.
            assert!(write_private_file(&path, b"new complete snapshot").is_err());
            assert_eq!(std::fs::read(&path).unwrap(), b"old complete snapshot");
        }
        let mut old_bytes = Vec::new();
        old_reader.read_to_end(&mut old_bytes).unwrap();
        assert_eq!(old_bytes, b"old complete snapshot");
        drop(old_reader);
        #[cfg(windows)]
        write_private_file(&path, b"new complete snapshot").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new complete snapshot");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            1,
            "no staging residue"
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_atomic_replace_preserves_existing_owner_and_restricts_mode() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.json");
        std::fs::write(&path, b"old snapshot").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let before = std::fs::metadata(&path).unwrap();
        write_private_file(&path, b"new snapshot").unwrap();
        let after = std::fs::metadata(&path).unwrap();
        assert_eq!((after.uid(), after.gid()), (before.uid(), before.gid()));
        assert_eq!(after.mode() & 0o777, 0o600);
        assert_ne!(
            after.ino(),
            before.ino(),
            "the state was atomically replaced"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"new snapshot");
    }

    #[cfg(unix)]
    #[test]
    fn owner_preservation_failure_keeps_original_inode_and_removes_staging() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.json");
        std::fs::write(&path, b"original snapshot").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let before = std::fs::metadata(&path).unwrap();
        let result = write_private_file_with_owner(&path, b"not committed", |staged, existing| {
            assert_ne!(staged.metadata()?.ino(), existing.ino());
            assert_eq!(
                (existing.uid(), existing.gid()),
                (before.uid(), before.gid())
            );
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected staging ownership failure",
            ))
        });
        assert!(matches!(
            result,
            Err(AegisError::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied
        ));
        let after = std::fs::metadata(&path).unwrap();
        assert_eq!(after.ino(), before.ino());
        assert_eq!(
            (after.uid(), after.gid(), after.mode()),
            (before.uid(), before.gid(), before.mode())
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"original snapshot");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn private_atomic_write_rejects_terminal_symlink_without_touching_target() {
        use std::os::unix::fs::{symlink, MetadataExt};
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("actual-state.json");
        let path = dir.path().join("state.json");
        std::fs::write(&target, b"original target").unwrap();
        symlink(&target, &path).unwrap();
        let before = std::fs::symlink_metadata(&path).unwrap();
        let result = write_private_file(&path, b"not committed");
        assert!(matches!(
            result,
            Err(AegisError::Io(error)) if error.kind() == std::io::ErrorKind::InvalidInput
        ));
        assert_eq!(std::fs::read_link(&path).unwrap(), target);
        assert_eq!(
            std::fs::symlink_metadata(&path).unwrap().ino(),
            before.ino()
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"original target");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[test]
    fn private_atomic_write_rejects_non_regular_destination() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("destination-directory");
        std::fs::create_dir(&path).unwrap();
        assert!(write_private_file(&path, b"never committed").is_err());
        assert!(path.is_dir());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn failed_atomic_replace_removes_staging_without_modifying_destination() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state.json");
        let old = dir.path().join("old-state.json");
        std::fs::write(&path, b"original snapshot").unwrap();
        let result = write_private_file_with_owner(&path, b"never committed", |_, _| {
            // Inject a rename failure after the destination check and staging.
            // Only this fixture directory is changed; no live path is involved.
            std::fs::rename(&path, &old)?;
            std::fs::create_dir(&path)
        });
        assert!(result.is_err());
        assert!(path.is_dir());
        assert_eq!(std::fs::read(&old).unwrap(), b"original snapshot");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[test]
    fn private_keyfile_roundtrip_works() {
        let dir = TempDir::new().unwrap();
        let state_path = dir.path().join("state.json");
        let plaintext = br#"{"schema_version":2}"#;
        let sealed = seal_state_blob(&state_path, plaintext).unwrap();
        assert!(sealed.starts_with(SEALED_STATE_MAGIC));
        let reopened = maybe_decrypt_state_blob(&state_path, &sealed)
            .unwrap()
            .unwrap();
        assert_eq!(reopened, plaintext);
    }
}
