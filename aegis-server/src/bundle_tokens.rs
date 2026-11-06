//! Client bundle token store for the `/bundle` endpoint (v0.2.0 S3).
//!
//! Plaintext tokens are issued по CLI (`aegis-server bundle-token issue ...`),
//! their sha256 hashes stored в a JSON file on disk alongside the bundle
//! archive path, issuance timestamp, expiry, и consumption marker. The
//! `/bundle?token=<plaintext>` handler hashes the incoming token и looks
//! it up; on first successful redemption the entry is marked consumed
//! (one-time semantics) but kept in the store для audit trail until the
//! expiry lapses.
//!
//! Design constraints:
//! - Plaintext tokens never stored on disk — only their sha256 digests
//! - File layout: newline-delimited JSON is NOT used; single JSON object
//!   with a `tokens: { <sha256>: BundleTokenRecord }` map. Atomic rewrite
//!   on save (write to `.tmp`, rename).
//! - Default TTL: 24 hours. Rotations can emit new tokens while old ones
//!   stay valid until their own expiry.
//! - Every mutation reloads under a stable sidecar OS lock, including CLI
//!   callers with stale snapshots. Async callers offload these bounded
//!   synchronous transactions to a blocking worker.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
#[cfg(unix)]
use std::io::Read;
use std::io::Write;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::path::Component;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const BUNDLE_TOKEN_STORE_SCHEMA: &str = "aegis_bundle_token_store_v1";

#[cfg(test)]
pub(crate) fn test_tempdir() -> tempfile::TempDir {
    // The writer's no-follow parent walk intentionally rejects macOS /var.
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    tempfile::tempdir_in(workspace).unwrap()
}

pub const DEFAULT_BUNDLE_TOKEN_TTL_SECS: u64 = 24 * 60 * 60;
#[cfg(unix)]
const DEFAULT_SYSTEM_TOKEN_STORE_PATH: &str = "/var/lib/aegis/bundle-tokens.json";
#[cfg(unix)]
const DEFAULT_SERVICE_USER: &str = "aegis";
/// Plaintext token length в bytes before hex encoding → 64 hex chars.
const TOKEN_RANDOM_BYTES: usize = 32;
const STORE_LOCK_TIMEOUT: Duration = Duration::from_secs(2);

/// Never unlink this sidecar: all processes must continue locking the same
/// inode even when the JSON file is atomically replaced. Closing releases it.
struct StoreLock {
    _file: fs::File,
    #[cfg(unix)]
    _parent: fs::File,
    #[cfg(unix)]
    _store_leaf: std::ffi::CString,
    #[cfg(unix)]
    _lock_leaf: std::ffi::CString,
    #[cfg(unix)]
    _expected_owner: StoreOwner,
}

#[cfg(unix)]
fn open_parent_and_leaf(
    path: &Path,
    create_missing: bool,
) -> Result<(fs::File, std::ffi::CString)> {
    let leaf = path
        .file_name()
        .ok_or_else(|| anyhow!("missing store leaf"))?;
    let leaf = std::ffi::CString::new(leaf.as_bytes()).context("invalid store leaf")?;
    let mut parent = fs::File::open(if path.is_absolute() { "/" } else { "." })?;
    for part in path.parent().unwrap_or_else(|| Path::new("")).components() {
        match part {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => {
                let name =
                    std::ffi::CString::new(name.as_bytes()).context("invalid store parent")?;
                let mut fd = unsafe {
                    libc::openat(
                        parent.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if fd < 0
                    && create_missing
                    && std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound
                {
                    let made = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
                    if made < 0
                        && std::io::Error::last_os_error().kind()
                            != std::io::ErrorKind::AlreadyExists
                    {
                        return Err(std::io::Error::last_os_error()).context("create store parent");
                    }
                    fd = unsafe {
                        libc::openat(
                            parent.as_raw_fd(),
                            name.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    };
                }
                if fd < 0 {
                    return Err(std::io::Error::last_os_error()).context("open store parent");
                }
                parent = unsafe { fs::File::from_raw_fd(fd) };
            }
            _ => return Err(anyhow!("unsafe store parent component")),
        }
    }
    Ok((parent, leaf))
}

#[cfg(unix)]
fn verify_named_parent(path: &Path, held: &fs::File) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let (named, _) = open_parent_and_leaf(path, false)?;
    let a = held.metadata()?;
    let b = named.metadata()?;
    if (a.dev(), a.ino()) != (b.dev(), b.ino()) {
        return Err(anyhow!("bundle store parent changed"));
    }
    Ok(())
}

#[cfg(unix)]
fn stat_leaf(parent: &fs::File, leaf: &std::ffi::CString) -> Result<Option<libc::stat>> {
    let mut info = std::mem::MaybeUninit::<libc::stat>::uninit();
    let rc = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            leaf.as_ptr(),
            info.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc == 0 {
        return Ok(Some(unsafe { info.assume_init() }));
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::NotFound {
        Ok(None)
    } else {
        Err(error).context("stat store leaf")
    }
}

#[cfg(unix)]
fn verify_lock_leaf(
    parent: &fs::File,
    leaf: &std::ffi::CString,
    file: &fs::File,
    expected: StoreOwner,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let opened = file.metadata()?;
    let named = stat_leaf(parent, leaf)?.ok_or_else(|| anyhow!("bundle lock disappeared"))?;
    if !opened.is_file()
        || opened.nlink() != 1
        || opened.mode() & 0o7777 != 0o600
        || (opened.uid(), opened.gid()) != (expected.uid, expected.gid)
        || named.st_dev != opened.dev() as libc::dev_t
        || named.st_ino != opened.ino() as libc::ino_t
    {
        return Err(anyhow!("unsafe bundle token lock identity"));
    }
    Ok(())
}

#[cfg(unix)]
fn lock_owner_migration_allowed(
    created: bool,
    current: StoreOwner,
    expected: StoreOwner,
    root: bool,
) -> bool {
    created || current == expected || (root && current.uid == 0)
}

impl StoreLock {
    fn acquire(path: &Path, budget: Duration) -> Result<Self> {
        let mut lock_path = path.as_os_str().to_os_string();
        lock_path.push(".lock");
        let lock_path = PathBuf::from(lock_path);
        #[cfg(unix)]
        let (parent, store_leaf, lock_leaf, file, expected_owner) = {
            use std::os::unix::fs::MetadataExt;
            let (parent, store_leaf) = open_parent_and_leaf(path, false)?;
            let lock_leaf = std::ffi::CString::new(lock_path.file_name().unwrap().as_bytes())?;
            let flags = libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
            let first = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    lock_leaf.as_ptr(),
                    flags | libc::O_CREAT | libc::O_EXCL,
                    0o600,
                )
            };
            let created = first >= 0;
            let fd = if created {
                first
            } else if std::io::Error::last_os_error().kind() == std::io::ErrorKind::AlreadyExists {
                unsafe { libc::openat(parent.as_raw_fd(), lock_leaf.as_ptr(), flags) }
            } else {
                return Err(std::io::Error::last_os_error()).context("create bundle token lock");
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error()).context("open bundle token lock");
            }
            let file = unsafe { fs::File::from_raw_fd(fd) };
            let before = file.metadata()?;
            if !before.is_file()
                || before.nlink() != 1
                || (!created && before.mode() & 0o7777 != 0o600)
            {
                return Err(anyhow!("unsafe bundle token lock leaf"));
            }
            let owner =
                BundleTokenStore::desired_owner_for_root_write_at(path, &parent, &store_leaf)?;
            let expected_owner = if let Some(owner) = owner {
                owner
            } else {
                process_store_owner(&parent)?
            };
            let current_owner = StoreOwner {
                uid: before.uid(),
                gid: before.gid(),
            };
            if !lock_owner_migration_allowed(
                created,
                current_owner,
                expected_owner,
                BundleTokenStore::is_effective_root(),
            ) {
                return Err(anyhow!("foreign bundle token lock owner"));
            }
            if let Some(owner) = owner {
                BundleTokenStore::fchown_if_needed(&file, owner)?;
            }
            if created {
                set_private_permissions(&file)?;
            }
            verify_lock_leaf(&parent, &lock_leaf, &file, expected_owner)?;
            (parent, store_leaf, lock_leaf, file, expected_owner)
        };
        #[cfg(not(unix))]
        let file = {
            let mut options = fs::OpenOptions::new();
            options.read(true).write(true).create(true).truncate(false);
            let file = options
                .open(&lock_path)
                .context("open bundle token transaction lock")?;
            BundleTokenStore::apply_desired_store_owner(path, &file)?;
            set_private_permissions(&file)?;
            file
        };
        let started = Instant::now();
        loop {
            match file.try_lock() {
                Ok(()) => {
                    #[cfg(unix)]
                    {
                        verify_named_parent(path, &parent)?;
                        verify_lock_leaf(&parent, &lock_leaf, &file, expected_owner)?;
                    }
                    return Ok(Self {
                        _file: file,
                        #[cfg(unix)]
                        _parent: parent,
                        #[cfg(unix)]
                        _store_leaf: store_leaf,
                        #[cfg(unix)]
                        _lock_leaf: lock_leaf,
                        #[cfg(unix)]
                        _expected_owner: expected_owner,
                    });
                }
                Err(fs::TryLockError::WouldBlock) => {
                    let remaining = budget
                        .checked_sub(started.elapsed())
                        .filter(|d| !d.is_zero())
                        .ok_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "bundle token transaction lock timed out",
                            )
                        })?;
                    std::thread::sleep(remaining.min(Duration::from_millis(5)));
                }
                Err(fs::TryLockError::Error(error)) => {
                    return Err(error).context("lock bundle token transaction")
                }
            }
        }
    }
}

fn set_private_permissions(file: &fs::File) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = file;
    Ok(())
}

#[cfg(not(unix))]
struct StagedStore(PathBuf);

#[cfg(not(unix))]
impl Drop for StagedStore {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[cfg(unix)]
struct StagedStoreAt<'a> {
    parent: &'a fs::File,
    name: std::ffi::CString,
    dev: libc::dev_t,
    ino: libc::ino_t,
    active: bool,
}

#[cfg(unix)]
impl Drop for StagedStoreAt<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Ok(Some(named)) = stat_leaf(self.parent, &self.name) {
            if (named.st_dev, named.st_ino) == (self.dev, self.ino) {
                let _ = unsafe { libc::unlinkat(self.parent.as_raw_fd(), self.name.as_ptr(), 0) };
            }
        }
    }
}

#[cfg(unix)]
fn verify_staged_name(
    parent: &fs::File,
    name: &std::ffi::CString,
    file: &fs::File,
    owner: StoreOwner,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let named =
        stat_leaf(parent, name)?.ok_or_else(|| anyhow!("bundle token staging name disappeared"))?;
    let held = file.metadata()?;
    if (named.st_dev, named.st_ino) != (held.dev() as libc::dev_t, held.ino() as libc::ino_t)
        || named.st_mode & libc::S_IFMT != libc::S_IFREG
        || named.st_nlink != 1
        || named.st_mode & 0o7777 != 0o600
        || (named.st_uid, named.st_gid) != (owner.uid, owner.gid)
    {
        return Err(anyhow!("bundle token staging name changed"));
    }
    Ok(())
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StoreOwner {
    uid: libc::uid_t,
    gid: libc::gid_t,
}

#[cfg(unix)]
fn process_store_owner(parent: &fs::File) -> Result<StoreOwner> {
    use std::os::unix::fs::MetadataExt;
    let meta = parent.metadata()?;
    // Darwin/BSD open(2) inherits the directory's group even without setgid.
    // Linux inherits it only for a setgid directory. Never trust a leaf's gid
    // to choose the expected owner of an existing store or transaction lock.
    let directory_gid = cfg!(any(
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )) || meta.mode() & 0o2000 != 0;
    Ok(StoreOwner {
        uid: unsafe { libc::geteuid() },
        gid: if directory_gid {
            meta.gid()
        } else {
            unsafe { libc::getegid() }
        },
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleTokenRecord {
    /// Absolute path на disk к the client-bundle tarball served when this
    /// token is redeemed. The endpoint reads the file fresh on each
    /// request (no in-memory cache) so operators can rotate bundle
    /// contents without restarting the server.
    pub bundle_path: PathBuf,
    /// Unix seconds when the token was issued.
    pub issued_at: u64,
    /// Unix seconds when the token stops being redeemable.
    pub expires_at: u64,
    /// Unix seconds when the token was successfully redeemed; `None`
    /// means the token is still unused. Once set, further redemption
    /// attempts return `BundleTokenError::AlreadyConsumed`.
    #[serde(default)]
    pub consumed_at: Option<u64>,
    /// Human-readable comment; set via `aegis-server bundle-token issue
    /// --comment "..."` so operators can distinguish multiple tokens
    /// issued for different clients.
    #[serde(default)]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BundleTokenStoreFile {
    pub schema: String,
    #[serde(default)]
    pub tokens: BTreeMap<String, BundleTokenRecord>,
}

pub struct BundleTokenStore {
    path: PathBuf,
    file: BundleTokenStoreFile,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BundleTokenError {
    #[error("bundle token not found")]
    NotFound,
    #[error("bundle token has expired")]
    Expired,
    #[error("bundle token has already been consumed")]
    AlreadyConsumed,
    #[error("failed to persist bundle token consumed state: {0}")]
    PersistFailed(String),
}

/// v0.3.7: aggregate stats для operator-facing `bundle-token stats`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BundleTokenStats {
    pub total: usize,
    pub active: usize,
    pub consumed: usize,
    pub expired: usize,
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// sha256(plaintext) → lowercase hex string — key under which tokens are
/// stored on disk. Never writes the plaintext; operators who lose the
/// plaintext must rotate the token (issue a new one).
pub fn hash_token(plaintext: &str) -> String {
    let digest = Sha256::digest(plaintext.as_bytes());
    hex::encode(digest)
}

/// Issued plaintext is exactly 32 random bytes encoded as lowercase hex.
/// Reject malformed probes before entering any store transaction or I/O.
pub(crate) fn is_canonical_plaintext_token(plaintext: &str) -> bool {
    plaintext.len() == TOKEN_RANDOM_BYTES * 2
        && plaintext
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

impl BundleTokenStore {
    /// Load from disk or initialise an empty store if the file does not
    /// exist yet. A missing parent directory is auto-created with mode
    /// 0700 (restrictive). Invalid JSON returns `Err`.
    pub fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        #[cfg(unix)]
        {
            let (parent, leaf) = open_parent_and_leaf(&path, true)?;
            if path
                .parent()
                .is_some_and(|part| !part.as_os_str().is_empty())
            {
                Self::prepare_parent_at(&path, &parent)?;
            }
            let file = Self::read_file_at(&path, &parent, &leaf)?.unwrap_or_else(Self::empty_file);
            Ok(Self { path, file })
        }
        #[cfg(not(unix))]
        {
            if let Some(parent) = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                fs::create_dir_all(parent)
                    .with_context(|| format!("create parent dir for {}", path.display()))?;
                Self::repair_default_parent_owner(&path, parent)?;
                Self::restrict_dir_permissions(parent);
            }
            if !path.exists() {
                return Ok(Self {
                    path,
                    file: BundleTokenStoreFile {
                        schema: BUNDLE_TOKEN_STORE_SCHEMA.to_string(),
                        tokens: BTreeMap::new(),
                    },
                });
            }
            let bytes = fs::read(&path)
                .with_context(|| format!("read bundle token store {}", path.display()))?;
            let file: BundleTokenStoreFile = serde_json::from_slice(&bytes)
                .with_context(|| format!("parse bundle token store {}", path.display()))?;
            if file.schema != BUNDLE_TOKEN_STORE_SCHEMA {
                return Err(anyhow!(
                    "unknown bundle token store schema {} (expected {})",
                    file.schema,
                    BUNDLE_TOKEN_STORE_SCHEMA
                ));
            }
            Ok(Self { path, file })
        }
    }

    #[cfg(unix)]
    fn empty_file() -> BundleTokenStoreFile {
        BundleTokenStoreFile {
            schema: BUNDLE_TOKEN_STORE_SCHEMA.to_string(),
            tokens: BTreeMap::new(),
        }
    }

    #[cfg(unix)]
    fn prepare_parent_at(path: &Path, parent: &fs::File) -> Result<()> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        verify_named_parent(path, parent)?;
        let meta = parent.metadata()?;
        let euid = unsafe { libc::geteuid() };
        let desired = if euid == 0 && Self::is_default_system_store_path(path) {
            Self::lookup_user_owner(DEFAULT_SERVICE_USER)
        } else {
            None
        };
        if (euid != 0 && meta.uid() != euid) || meta.mode() & 0o022 != 0 {
            return Err(anyhow!("foreign bundle store parent"));
        }
        if let Some(owner) = desired {
            Self::fchown_if_needed(parent, owner)?;
        }
        parent.set_permissions(fs::Permissions::from_mode(0o700))?;
        verify_named_parent(path, parent)?;
        Ok(())
    }

    #[cfg(unix)]
    fn read_file_at(
        path: &Path,
        parent: &fs::File,
        leaf: &std::ffi::CString,
    ) -> Result<Option<BundleTokenStoreFile>> {
        use std::os::unix::fs::MetadataExt;
        verify_named_parent(path, parent)?;
        let Some(named) = stat_leaf(parent, leaf)? else {
            verify_named_parent(path, parent)?;
            return Ok(None);
        };
        if named.st_mode & libc::S_IFMT != libc::S_IFREG || named.st_nlink != 1 {
            return Err(anyhow!("unsafe bundle token store leaf"));
        }
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                leaf.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("open bundle store leaf");
        }
        let mut file = unsafe { fs::File::from_raw_fd(fd) };
        let meta = file.metadata()?;
        let expected = Self::desired_owner_for_root_write_at(path, parent, leaf)?;
        let owner = match expected {
            Some(owner) => owner,
            None => process_store_owner(parent)?,
        };
        let root_owned_legacy = Self::is_effective_root()
            && Self::is_default_system_store_path(path)
            && meta.uid() == 0
            && owner.uid != 0;
        if !meta.is_file()
            || meta.nlink() != 1
            || !matches!(meta.mode() & 0o7777, 0o400 | 0o600)
            || ((meta.uid(), meta.gid()) != (owner.uid, owner.gid) && !root_owned_legacy)
            || (named.st_dev, named.st_ino) != (meta.dev() as _, meta.ino() as _)
        {
            return Err(anyhow!("unsafe bundle token store identity"));
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let after = stat_leaf(parent, leaf)?
            .ok_or_else(|| anyhow!("bundle token store disappeared during read"))?;
        if (after.st_dev, after.st_ino) != (meta.dev() as _, meta.ino() as _) {
            return Err(anyhow!("bundle token store changed during read"));
        }
        verify_named_parent(path, parent)?;
        let decoded: BundleTokenStoreFile = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse bundle token store {}", path.display()))?;
        if decoded.schema != BUNDLE_TOKEN_STORE_SCHEMA {
            return Err(anyhow!(
                "unknown bundle token store schema {} (expected {})",
                decoded.schema,
                BUNDLE_TOKEN_STORE_SCHEMA
            ));
        }
        Ok(Some(decoded))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Re-read the on-disk JSON file into memory. Used by the
    /// `/bundle?token=...` endpoint before each redeem so tokens
    /// issued by the operator-side `bundle-token issue` CLI (which
    /// writes the JSON directly without notifying the running
    /// server) are visible. A malformed/unreadable store is an error; a missing
    /// store becomes empty, never stale authorization. Mutations call this
    /// themselves while holding the cross-process transaction lock.
    pub fn reload(&mut self) -> Result<()> {
        let path = self.path.clone();
        let reloaded = Self::load(path)?;
        self.file = reloaded.file;
        Ok(())
    }

    fn begin_transaction(&mut self) -> Result<StoreLock> {
        let lock = StoreLock::acquire(&self.path, STORE_LOCK_TIMEOUT)?;
        #[cfg(unix)]
        {
            self.file = Self::read_file_at(&self.path, &lock._parent, &lock._store_leaf)?
                .unwrap_or_else(Self::empty_file);
        }
        #[cfg(not(unix))]
        self.reload()?;
        Ok(lock)
    }

    pub fn is_empty(&self) -> bool {
        self.file.tokens.is_empty()
    }

    pub fn len(&self) -> usize {
        self.file.tokens.len()
    }

    /// Commit under the sidecar lock with same-directory private staging and
    /// file/directory sync. A failed commit is never reported as redemption.
    fn save(&self, lock: &StoreLock) -> Result<()> {
        #[cfg(unix)]
        {
            self.save_unix(lock)
        }
        #[cfg(not(unix))]
        {
            let _ = lock;
            let parent = self
                .path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let tmp = parent.join(format!(
                ".aegis-bundle-store-{:032x}.tmp",
                rand::random::<u128>()
            ));
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            let mut file = options
                .open(&tmp)
                .context("create bundle token staging file")?;
            let _staged = StagedStore(tmp.clone());
            Self::apply_desired_store_owner(&self.path, &file)?;
            set_private_permissions(&file)?;
            let bytes =
                serde_json::to_vec_pretty(&self.file).context("serialize bundle token store")?;
            file.write_all(&bytes)
                .context("write bundle token staging file")?;
            file.sync_all().context("sync bundle token staging file")?;
            drop(file);
            fs::rename(&tmp, &self.path).context("commit bundle token store")?;
            Ok(())
        }
    }

    #[cfg(unix)]
    fn save_unix(&self, lock: &StoreLock) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        verify_named_parent(&self.path, &lock._parent)?;
        verify_lock_leaf(
            &lock._parent,
            &lock._lock_leaf,
            &lock._file,
            lock._expected_owner,
        )?;
        Self::verify_store_commit_leaf(
            &self.path,
            &lock._parent,
            &lock._store_leaf,
            lock._expected_owner,
        )?;
        let name = std::ffi::CString::new(format!(
            ".aegis-bundle-store-{:032x}.tmp",
            rand::random::<u128>()
        ))?;
        let fd = unsafe {
            libc::openat(
                lock._parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("create bundle token staging file");
        }
        let mut file = unsafe { fs::File::from_raw_fd(fd) };
        let stage_meta = file.metadata()?;
        let mut staged = StagedStoreAt {
            parent: &lock._parent,
            name,
            dev: stage_meta.dev() as libc::dev_t,
            ino: stage_meta.ino() as libc::ino_t,
            active: true,
        };
        if !stage_meta.is_file() || stage_meta.nlink() != 1 {
            return Err(anyhow!("unsafe bundle token staging inode"));
        }
        Self::fchown_if_needed(&file, lock._expected_owner)?;
        set_private_permissions(&file)?;
        let prepared = file.metadata()?;
        if !prepared.is_file()
            || prepared.nlink() != 1
            || prepared.mode() & 0o7777 != 0o600
            || (prepared.uid(), prepared.gid())
                != (lock._expected_owner.uid, lock._expected_owner.gid)
        {
            return Err(anyhow!("unsafe bundle token staging owner or mode"));
        }
        let bytes =
            serde_json::to_vec_pretty(&self.file).context("serialize bundle token store")?;
        file.write_all(&bytes)
            .context("write bundle token staging file")?;
        file.sync_all().context("sync bundle token staging file")?;
        verify_named_parent(&self.path, &lock._parent)?;
        verify_lock_leaf(
            &lock._parent,
            &lock._lock_leaf,
            &lock._file,
            lock._expected_owner,
        )?;
        Self::verify_store_commit_leaf(
            &self.path,
            &lock._parent,
            &lock._store_leaf,
            lock._expected_owner,
        )?;
        verify_staged_name(&lock._parent, &staged.name, &file, lock._expected_owner)?;
        let moved = unsafe {
            libc::renameat(
                lock._parent.as_raw_fd(),
                staged.name.as_ptr(),
                lock._parent.as_raw_fd(),
                lock._store_leaf.as_ptr(),
            )
        };
        if moved < 0 {
            return Err(std::io::Error::last_os_error()).context("commit bundle token store");
        }
        staged.active = false;
        let named = stat_leaf(&lock._parent, &lock._store_leaf)?
            .ok_or_else(|| anyhow!("committed bundle token store disappeared"))?;
        if (named.st_dev, named.st_ino) != (staged.dev, staged.ino) {
            return Err(anyhow!("committed bundle token store identity changed"));
        }
        verify_named_parent(&self.path, &lock._parent)?;
        lock._parent
            .sync_all()
            .context("sync bundle token store directory")?;
        Ok(())
    }

    #[cfg(unix)]
    fn verify_store_commit_leaf(
        path: &Path,
        parent: &fs::File,
        leaf: &std::ffi::CString,
        owner: StoreOwner,
    ) -> Result<()> {
        let Some(info) = stat_leaf(parent, leaf)? else {
            return Ok(());
        };
        let root_owned_legacy = Self::is_effective_root()
            && Self::is_default_system_store_path(path)
            && info.st_uid == 0
            && owner.uid != 0;
        if info.st_mode & libc::S_IFMT != libc::S_IFREG
            || info.st_nlink != 1
            || !matches!(info.st_mode & 0o7777, 0o400 | 0o600)
            || ((info.st_uid, info.st_gid) != (owner.uid, owner.gid) && !root_owned_legacy)
        {
            return Err(anyhow!("unsafe bundle token store commit leaf"));
        }
        Ok(())
    }

    /// Generate a fresh random plaintext token (64 hex chars), store its
    /// sha256 digest alongside the bundle path + expiry. Caller receives
    /// the plaintext once and must distribute it out-of-band; subsequent
    /// calls into `redeem` only accept the plaintext.
    pub fn issue(
        &mut self,
        bundle_path: PathBuf,
        ttl_secs: u64,
        comment: Option<String>,
    ) -> Result<String> {
        if !bundle_path.is_absolute() {
            return Err(anyhow!(
                "bundle path must be absolute (got {})",
                bundle_path.display()
            ));
        }
        if !bundle_path.is_file() {
            return Err(anyhow!(
                "bundle path {} does not exist or is not a file",
                bundle_path.display()
            ));
        }
        let lock = self.begin_transaction()?;
        let plaintext = Self::generate_plaintext();
        let sha = hash_token(&plaintext);
        let now = current_unix_secs();
        let record = BundleTokenRecord {
            bundle_path,
            issued_at: now,
            expires_at: now
                .checked_add(ttl_secs)
                .context("bundle token expiry overflow")?,
            consumed_at: None,
            comment,
        };
        self.file.tokens.insert(sha.clone(), record);
        if let Err(error) = self.save(&lock) {
            self.file.tokens.remove(&sha);
            return Err(error);
        }
        Ok(plaintext)
    }

    /// Authorize acquisition from a current disk snapshot, without consuming.
    /// The commit must revalidate after the asynchronous file read.
    pub(crate) fn authorize_read(
        &mut self,
        plaintext: &str,
    ) -> std::result::Result<PathBuf, BundleTokenError> {
        if !is_canonical_plaintext_token(plaintext) {
            return Err(BundleTokenError::NotFound);
        }
        let _lock = self
            .begin_transaction()
            .map_err(|error| BundleTokenError::PersistFailed(error.to_string()))?;
        self.redeemable_path(plaintext)
    }

    /// Authorize reading installer input without consuming its one-time token.
    /// A caller must still call redeem before returning any bytes to the peer.
    fn redeemable_path(&self, plaintext: &str) -> std::result::Result<PathBuf, BundleTokenError> {
        let record = self
            .file
            .tokens
            .get(&hash_token(plaintext))
            .ok_or(BundleTokenError::NotFound)?;
        if record.consumed_at.is_some() {
            return Err(BundleTokenError::AlreadyConsumed);
        }
        if record.expires_at <= current_unix_secs() {
            return Err(BundleTokenError::Expired);
        }
        Ok(record.bundle_path.clone())
    }

    /// Look up by plaintext token, validate not-expired и not-consumed,
    /// mark consumed (one-time semantics), persist. Returns the bundle
    /// path to serve. Fails CLOSED: if the consumed marker cannot be
    /// durably persisted the delivery is aborted (`PersistFailed`). Failure
    /// before replacement leaves the token available; failure of directory
    /// sync after replacement may already have consumed it. The next locked
    /// transaction reloads disk state; callers must not promise automatic reuse.
    pub fn redeem(&mut self, plaintext: &str) -> std::result::Result<PathBuf, BundleTokenError> {
        self.redeem_after_read(plaintext, None)
    }

    /// Revalidate under the OS lock, including the path whose bytes were read.
    pub(crate) fn redeem_after_read(
        &mut self,
        plaintext: &str,
        expected_path: Option<&Path>,
    ) -> std::result::Result<PathBuf, BundleTokenError> {
        if !is_canonical_plaintext_token(plaintext) {
            return Err(BundleTokenError::NotFound);
        }
        let lock = self
            .begin_transaction()
            .map_err(|error| BundleTokenError::PersistFailed(error.to_string()))?;
        let bundle_path = self.redeemable_path(plaintext)?;
        if expected_path.is_some_and(|path| path != bundle_path) {
            return Err(BundleTokenError::PersistFailed(
                "bundle path changed during acquisition".into(),
            ));
        }
        let sha = hash_token(plaintext);
        let now = current_unix_secs();
        let record = self
            .file
            .tokens
            .get_mut(&sha)
            .ok_or(BundleTokenError::NotFound)?;
        if record.consumed_at.is_some() {
            return Err(BundleTokenError::AlreadyConsumed);
        }
        if record.expires_at <= now {
            return Err(BundleTokenError::Expired);
        }
        let bundle_path = record.bundle_path.clone();
        record.consumed_at = Some(now);
        // One-time credentials must fail CLOSED. The bundle endpoint calls
        // `reload()` before every redeem, and `reload()` replaces the whole
        // in-memory store with disk state — so a consumed marker that never
        // reached disk is silently reset on the next request, making the token
        // reusable. If the persist fails, roll the in-memory mark back (keeping
        // memory consistent with the still-unconsumed disk state) and refuse to
        // serve, instead of handing out a bundle whose one-time guarantee we
        // cannot keep. A post-rename directory-sync failure is ambiguous: disk
        // may already contain the consumed marker, so a later locked reload can
        // still report AlreadyConsumed. Never deliver bytes on this error.
        if let Err(err) = self.save(&lock) {
            if let Some(record) = self.file.tokens.get_mut(&sha) {
                record.consumed_at = None;
            }
            return Err(BundleTokenError::PersistFailed(err.to_string()));
        }
        Ok(bundle_path)
    }

    /// v0.3.7: Mark a token as revoked by sha256 prefix match. Operator
    /// passes a unique prefix from `bundle-token list` output (sha256_prefix
    /// column, 16 hex chars by default). Returns the matched record's full
    /// sha256 на success или an error variant on no match / ambiguous
    /// prefix / already-consumed/revoked.
    ///
    /// Revocation = setting `consumed_at = now` so subsequent /bundle
    /// redeem returns AlreadyConsumed (HTTP 410). Does NOT delete from
    /// store (preserves audit trail).
    pub fn revoke_by_prefix(
        &mut self,
        prefix: &str,
    ) -> std::result::Result<String, BundleTokenError> {
        self.revoke_with_save(prefix, |store, lock| store.save(lock))
    }

    fn revoke_with_save<F>(
        &mut self,
        prefix: &str,
        save: F,
    ) -> std::result::Result<String, BundleTokenError>
    where
        F: FnOnce(&Self, &StoreLock) -> Result<()>,
    {
        let lock = self
            .begin_transaction()
            .map_err(|error| BundleTokenError::PersistFailed(error.to_string()))?;
        if prefix.is_empty() {
            return Err(BundleTokenError::NotFound);
        }
        let matches: Vec<String> = self
            .file
            .tokens
            .keys()
            .filter(|sha| sha.starts_with(prefix))
            .cloned()
            .collect();
        if matches.is_empty() {
            return Err(BundleTokenError::NotFound);
        }
        if matches.len() > 1 {
            // Ambiguous: caller should pass longer prefix
            return Err(BundleTokenError::NotFound);
        }
        let sha = matches.into_iter().next().expect("len==1 checked");
        let record = self
            .file
            .tokens
            .get_mut(&sha)
            .ok_or(BundleTokenError::NotFound)?;
        if record.consumed_at.is_some() {
            return Err(BundleTokenError::AlreadyConsumed);
        }
        record.consumed_at = Some(current_unix_secs());
        if let Err(error) = save(self, &lock) {
            self.file
                .tokens
                .get_mut(&sha)
                .expect("matched record")
                .consumed_at = None;
            return Err(BundleTokenError::PersistFailed(error.to_string()));
        }
        Ok(sha)
    }

    /// v0.3.7: Aggregate counts for operator-facing `bundle-token stats`.
    /// All counts are local-only — no HTTP endpoint exposes them.
    pub fn stats(&self) -> BundleTokenStats {
        let now = current_unix_secs();
        let mut total = 0usize;
        let mut active = 0usize;
        let mut consumed = 0usize;
        let mut expired = 0usize;
        for record in self.file.tokens.values() {
            total += 1;
            if record.consumed_at.is_some() {
                consumed += 1;
            } else if record.expires_at <= now {
                expired += 1;
            } else {
                active += 1;
            }
        }
        BundleTokenStats {
            total,
            active,
            consumed,
            expired,
        }
    }

    /// Remove tokens that expired more than `retain_after_expiry_secs`
    /// seconds ago. Keeps recent expired/consumed tokens around for a
    /// short audit window by default.
    pub fn prune(&mut self, retain_after_expiry_secs: u64) -> Result<usize> {
        let lock = self.begin_transaction()?;
        let now = current_unix_secs();
        let before = self.file.tokens.clone();
        self.file
            .tokens
            .retain(|_, record| record.expires_at.saturating_add(retain_after_expiry_secs) > now);
        let removed = before.len() - self.file.tokens.len();
        if removed > 0 {
            if let Err(error) = self.save(&lock) {
                self.file.tokens = before;
                return Err(error);
            }
        }
        Ok(removed)
    }

    pub fn iter_records(&self) -> impl Iterator<Item = (&String, &BundleTokenRecord)> {
        self.file.tokens.iter()
    }

    fn generate_plaintext() -> String {
        use rand::RngCore;
        let mut buf = [0u8; TOKEN_RANDOM_BYTES];
        rand::thread_rng().fill_bytes(&mut buf);
        hex::encode(buf)
    }

    #[cfg(not(unix))]
    fn repair_default_parent_owner(_store_path: &Path, _parent: &Path) -> Result<()> {
        Ok(())
    }

    #[cfg(not(unix))]
    fn apply_desired_store_owner(_store_path: &Path, _file: &fs::File) -> Result<()> {
        Ok(())
    }

    #[cfg(unix)]
    fn desired_owner_for_root_write_at(
        store_path: &Path,
        parent: &fs::File,
        leaf: &std::ffi::CString,
    ) -> Result<Option<StoreOwner>> {
        use std::os::unix::fs::MetadataExt;
        if !Self::is_effective_root() {
            return Ok(None);
        }
        if Self::is_default_system_store_path(store_path) {
            if let Some(owner) = Self::lookup_user_owner(DEFAULT_SERVICE_USER) {
                return Ok(Some(owner));
            }
        }
        let parent_meta = parent.metadata()?;
        let parent_owner = Some(StoreOwner {
            uid: parent_meta.uid(),
            gid: parent_meta.gid(),
        });
        let file_owner = match stat_leaf(parent, leaf)? {
            None => None,
            Some(info) if info.st_mode & libc::S_IFMT == libc::S_IFREG && info.st_nlink == 1 => {
                Some(StoreOwner {
                    uid: info.st_uid,
                    gid: info.st_gid,
                })
            }
            Some(_) => return Err(anyhow!("unsafe bundle store owner leaf")),
        };
        Ok(Self::choose_owner_for_root_write(file_owner, parent_owner))
    }

    #[cfg(unix)]
    fn choose_owner_for_root_write(
        file_owner: Option<StoreOwner>,
        parent_owner: Option<StoreOwner>,
    ) -> Option<StoreOwner> {
        match (file_owner, parent_owner) {
            // If the parent is already owned by the service account, repair a
            // stale root-owned file by following the directory owner.
            (_, Some(parent)) if parent.uid != 0 => Some(parent),
            // Otherwise preserve an existing non-root file owner when possible.
            (Some(file), _) if file.uid != 0 => Some(file),
            (Some(file), _) => Some(file),
            (None, Some(parent)) => Some(parent),
            (None, None) => None,
        }
    }

    #[cfg(unix)]
    fn is_default_system_store_path(path: &Path) -> bool {
        path == Path::new(DEFAULT_SYSTEM_TOKEN_STORE_PATH)
    }

    #[cfg(unix)]
    fn is_effective_root() -> bool {
        // SAFETY: geteuid has no preconditions and does not modify memory.
        unsafe { libc::geteuid() == 0 }
    }

    #[cfg(unix)]
    fn lookup_user_owner(name: &str) -> Option<StoreOwner> {
        let name = std::ffi::CString::new(name).ok()?;
        // SAFETY: name is a NUL-terminated C string and getpwnam returns either
        // null or a pointer valid until the next passwd lookup in this process.
        let passwd = unsafe { libc::getpwnam(name.as_ptr()) };
        if passwd.is_null() {
            return None;
        }
        // SAFETY: passwd was checked for null above.
        let passwd = unsafe { &*passwd };
        Some(StoreOwner {
            uid: passwd.pw_uid,
            gid: passwd.pw_gid,
        })
    }

    #[cfg(unix)]
    fn fchown_if_needed(file: &fs::File, owner: StoreOwner) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let before = file.metadata()?;
        if (before.uid(), before.gid()) == (owner.uid, owner.gid) {
            return Ok(());
        }
        let rc = unsafe { libc::fchown(file.as_raw_fd(), owner.uid, owner.gid) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error()).context("fchown bundle store inode");
        }
        let after = file.metadata()?;
        if (after.uid(), after.gid()) != (owner.uid, owner.gid) {
            return Err(anyhow!("bundle store owner readback changed"));
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn restrict_dir_permissions(_path: &Path) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn relative_store_load_keeps_current_directory_mode() {
        use std::os::unix::fs::PermissionsExt;
        const CHILD_DIR: &str = "AEGIS_FIXTURE_BUNDLE_RELATIVE_DIR";
        if let Some(dir) = std::env::var_os(CHILD_DIR) {
            std::env::set_current_dir(dir).unwrap();
            let before = fs::metadata(".").unwrap().permissions().mode() & 0o7777;
            assert!(BundleTokenStore::load("tokens.json").unwrap().is_empty());
            assert_eq!(
                fs::metadata(".").unwrap().permissions().mode() & 0o7777,
                before
            );
            fs::write("relative-store-child.checked", before.to_string()).unwrap();
            return;
        }
        let dir = test_tempdir();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "bundle_tokens::tests::relative_store_load_keeps_current_directory_mode",
            ])
            .env(CHILD_DIR, dir.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "relative child assertion failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("relative-store-child.checked")).unwrap(),
            0o755.to_string()
        );
        assert_eq!(
            fs::metadata(dir.path()).unwrap().permissions().mode() & 0o7777,
            0o755
        );
    }

    #[cfg(unix)]
    #[test]
    fn replaced_staging_name_never_matches_held_inode() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = test_tempdir();
        let parent = fs::File::open(dir.path()).unwrap();
        let path = dir.path().join("stage.tmp");
        let name = std::ffi::CString::new("stage.tmp").unwrap();
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        set_private_permissions(&file).unwrap();
        let meta = file.metadata().unwrap();
        let owner = StoreOwner {
            uid: meta.uid(),
            gid: meta.gid(),
        };
        verify_staged_name(&parent, &name, &file, owner).unwrap();
        fs::rename(&path, dir.path().join("retired.tmp")).unwrap();
        fs::write(&path, b"replacement").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(verify_staged_name(&parent, &name, &file, owner).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"replacement");
    }

    #[cfg(unix)]
    #[test]
    fn store_load_refuses_symlink_without_touching_dummy_bytes() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = test_tempdir();
        let victim = dir.path().join("dummy-store");
        let bytes = br#"{"schema":"aegis_bundle_token_store_v1","tokens":{}}"#;
        fs::write(&victim, bytes).unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).unwrap();
        let alias = dir.path().join("tokens.json");
        symlink(&victim, &alias).unwrap();
        assert!(BundleTokenStore::load(&alias).is_err());
        assert_eq!(fs::read(&victim).unwrap(), bytes);
        assert_eq!(
            fs::metadata(&victim).unwrap().permissions().mode() & 0o7777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn store_load_refuses_hardlink_without_touching_dummy_bytes() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = test_tempdir();
        let victim = dir.path().join("dummy-store");
        let bytes = br#"{"schema":"aegis_bundle_token_store_v1","tokens":{}}"#;
        fs::write(&victim, bytes).unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).unwrap();
        let alias = dir.path().join("tokens.json");
        fs::hard_link(&victim, &alias).unwrap();
        assert!(BundleTokenStore::load(&alias).is_err());
        assert_eq!(fs::read(&victim).unwrap(), bytes);
        assert_eq!(fs::metadata(&victim).unwrap().nlink(), 2);
        assert_eq!(
            fs::metadata(&victim).unwrap().permissions().mode() & 0o7777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn store_load_refuses_symlinked_parent_before_creation() {
        use std::os::unix::fs::symlink;
        let dir = test_tempdir();
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        let alias = dir.path().join("alias");
        symlink(&real, &alias).unwrap();
        assert!(BundleTokenStore::load(alias.join("tokens.json")).is_err());
        assert!(!real.join("tokens.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn store_commit_refuses_parent_replacement_after_lock() {
        use std::os::unix::fs::symlink;
        let dir = test_tempdir();
        let parent = dir.path().join("owned");
        let moved = dir.path().join("moved");
        let foreign = dir.path().join("foreign");
        fs::create_dir(&parent).unwrap();
        fs::create_dir(&foreign).unwrap();
        let path = parent.join("tokens.json");
        let bundle = make_bundle(dir.path(), "bundle.tar.gz");
        let mut store = BundleTokenStore::load(&path).unwrap();
        let token = store.issue(bundle, 60, None).unwrap();
        let original = fs::read(&path).unwrap();
        let result = store.revoke_with_save(&hash_token(&token), |store, lock| {
            fs::rename(&parent, &moved)?;
            symlink(&foreign, &parent)?;
            store.save(lock)
        });
        assert!(matches!(result, Err(BundleTokenError::PersistFailed(_))));
        assert_eq!(fs::read(moved.join("tokens.json")).unwrap(), original);
        assert!(!foreign.join("tokens.json").exists());
    }

    fn make_bundle(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, b"dummy bundle contents").expect("write bundle");
        path
    }

    #[test]
    fn load_creates_empty_store_when_missing() {
        let tmp = test_tempdir();
        let store_path = tmp.path().join("sub").join("tokens.json");
        let store = BundleTokenStore::load(&store_path).expect("load");
        assert!(store.is_empty());
        assert_eq!(store.path(), store_path);
    }

    #[test]
    fn issue_rejects_relative_bundle_path() {
        let tmp = test_tempdir();
        let store_path = tmp.path().join("tokens.json");
        let mut store = BundleTokenStore::load(&store_path).expect("load");
        let relative = PathBuf::from("relative/path.tar.gz");
        let err = store.issue(relative, 3600, None);
        assert!(err.is_err());
    }

    #[test]
    fn issue_rejects_missing_bundle_file() {
        let tmp = test_tempdir();
        let store_path = tmp.path().join("tokens.json");
        let mut store = BundleTokenStore::load(&store_path).expect("load");
        let missing = tmp.path().join("nonexistent.tar.gz");
        let err = store.issue(missing, 3600, None);
        assert!(err.is_err());
    }

    #[test]
    fn issue_and_redeem_round_trip() {
        let tmp = test_tempdir();
        let store_path = tmp.path().join("tokens.json");
        let bundle = make_bundle(tmp.path(), "bundle.tar.gz");
        let mut store = BundleTokenStore::load(&store_path).expect("load");
        let plaintext = store
            .issue(bundle.clone(), 3600, Some("client-1".into()))
            .expect("issue");
        assert_eq!(plaintext.len(), TOKEN_RANDOM_BYTES * 2); // 64 hex chars
        let redeemed_path = store.redeem(&plaintext).expect("redeem");
        assert_eq!(redeemed_path, bundle);
        let second = store.redeem(&plaintext);
        assert_eq!(second, Err(BundleTokenError::AlreadyConsumed));
    }

    #[test]
    fn redeem_fails_closed_when_consumed_state_cannot_persist() {
        // Regression: a best-effort save let a failed persist slip through, and
        // because the endpoint reload()s the store from disk before each redeem,
        // an unpersisted consumed marker was silently reset → the one-time token
        // became reusable. redeem() must fail closed instead.
        let tmp = test_tempdir();
        let sub = tmp.path().join("store-dir");
        fs::create_dir(&sub).expect("mkdir sub");
        let store_path = sub.join("tokens.json");
        // Bundle lives OUTSIDE the store dir so removing the dir keeps it present.
        let bundle = make_bundle(tmp.path(), "bundle.tar.gz");
        let mut store = BundleTokenStore::load(&store_path).expect("load");
        let token = store.issue(bundle.clone(), 3600, None).expect("issue");
        let persisted = fs::read(&store_path).expect("persisted fixture");
        #[cfg(unix)]
        let persisted_permissions = fs::metadata(&store_path).unwrap().permissions();

        // Make the NEXT save() fail deterministically, independent of process uid:
        // remove the store's parent dir so the temp-file write hits ENOENT (not a
        // permission trick that root would bypass).
        fs::remove_dir_all(&sub).expect("rm store dir");
        match store.redeem(&token) {
            Err(BundleTokenError::PersistFailed(_)) => {}
            other => panic!("expected PersistFailed on unpersistable redeem, got {other:?}"),
        }

        // Fail-closed contract: the token was NOT burned. Once persistence
        // recovers it redeems exactly once — not reusable, not lost.
        fs::create_dir(&sub).expect("recreate store dir");
        // Restore the persisted fixture, never resurrect authorization from a
        // stale in-memory copy when the actual store has disappeared.
        fs::write(&store_path, persisted).expect("restore persisted fixture");
        #[cfg(unix)]
        fs::set_permissions(&store_path, persisted_permissions).unwrap();
        assert_eq!(
            store
                .redeem(&token)
                .expect("redeem after persistence recovers"),
            bundle
        );
        assert_eq!(store.redeem(&token), Err(BundleTokenError::AlreadyConsumed));
    }

    #[test]
    fn redeem_rejects_invalid_token() {
        let tmp = test_tempdir();
        let store_path = tmp.path().join("tokens.json");
        let mut store = BundleTokenStore::load(&store_path).expect("load");
        assert_eq!(store.redeem("bogus-token"), Err(BundleTokenError::NotFound));
    }

    #[test]
    fn redeem_rejects_expired_token() {
        let tmp = test_tempdir();
        let store_path = tmp.path().join("tokens.json");
        let bundle = make_bundle(tmp.path(), "bundle.tar.gz");
        let mut store = BundleTokenStore::load(&store_path).expect("load");
        let plaintext = store.issue(bundle, 0, None).expect("issue"); // ttl=0 → already expired
                                                                      // A tiny sleep isn't necessary: ttl=0 means expires_at == issued_at,
                                                                      // and redeem compares `expires_at <= now`, so immediate redeem
                                                                      // after issue returns Expired.
        assert_eq!(store.redeem(&plaintext), Err(BundleTokenError::Expired));
    }

    #[test]
    fn save_roundtrip_persists_records() {
        let tmp = test_tempdir();
        let store_path = tmp.path().join("tokens.json");
        let bundle = make_bundle(tmp.path(), "bundle.tar.gz");
        let plaintext_a;
        {
            let mut store = BundleTokenStore::load(&store_path).expect("load");
            plaintext_a = store
                .issue(bundle.clone(), 3600, Some("a".into()))
                .expect("issue a");
            let lock = store.begin_transaction().expect("transaction");
            store.save(&lock).expect("save");
        }
        // Reload
        let mut store = BundleTokenStore::load(&store_path).expect("reload");
        assert_eq!(store.len(), 1);
        let redeemed = store.redeem(&plaintext_a).expect("redeem after reload");
        assert_eq!(redeemed, bundle);
    }

    #[test]
    fn prune_removes_long_expired_tokens() {
        let tmp = test_tempdir();
        let store_path = tmp.path().join("tokens.json");
        let bundle = make_bundle(tmp.path(), "bundle.tar.gz");
        let mut store = BundleTokenStore::load(&store_path).expect("load");
        let _fresh = store
            .issue(bundle.clone(), 7200, None)
            .expect("issue fresh");
        // Synthesise an old entry directly in file state
        let old = BundleTokenRecord {
            bundle_path: bundle,
            issued_at: 1,
            expires_at: 2,
            consumed_at: None,
            comment: Some("stale".into()),
        };
        let lock = store.begin_transaction().expect("transaction");
        store.file.tokens.insert("deadbeef".repeat(8), old);
        store.save(&lock).expect("save");
        drop(lock);
        let removed = store.prune(0).expect("prune");
        assert_eq!(removed, 1);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn stale_cli_mutations_preserve_new_tokens_and_revocations() {
        let dir = test_tempdir();
        let path = dir.path().join("tokens.json");
        let bundle = make_bundle(dir.path(), "bundle.tar.gz");
        let mut first = BundleTokenStore::load(&path).unwrap();
        let mut stale = BundleTokenStore::load(&path).unwrap();
        let a = first.issue(bundle.clone(), 60, None).unwrap();
        let b = stale.issue(bundle, 60, None).unwrap();
        assert_eq!(BundleTokenStore::load(&path).unwrap().len(), 2);
        first.revoke_by_prefix(&hash_token(&a)).unwrap();
        assert_eq!(stale.redeem(&a), Err(BundleTokenError::AlreadyConsumed));
        assert!(stale.redeem(&b).is_ok());
        assert_eq!(BundleTokenStore::load(path).unwrap().stats().consumed, 2);
    }

    #[test]
    fn independent_store_redemptions_commit_only_once() {
        let dir = test_tempdir();
        let path = dir.path().join("tokens.json");
        let bundle = make_bundle(dir.path(), "bundle.tar.gz");
        let token = BundleTokenStore::load(&path)
            .unwrap()
            .issue(bundle, 60, None)
            .unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
        let tasks: Vec<_> = (0..4)
            .map(|_| {
                let mut stale = BundleTokenStore::load(&path).unwrap();
                let token = token.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    stale.redeem(&token)
                })
            })
            .collect();
        let results: Vec<_> = tasks.into_iter().map(|task| task.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(BundleTokenError::AlreadyConsumed)))
                .count(),
            3
        );
    }

    #[test]
    fn stale_prune_preserves_concurrently_issued_token() {
        let dir = test_tempdir();
        let path = dir.path().join("tokens.json");
        let bundle = make_bundle(dir.path(), "bundle.tar.gz");
        let mut writer = BundleTokenStore::load(&path).unwrap();
        writer.issue(bundle.clone(), 0, None).unwrap();
        let mut stale = BundleTokenStore::load(&path).unwrap();
        let live = writer.issue(bundle, 60, None).unwrap();
        assert_eq!(stale.prune(0).unwrap(), 1);
        assert!(BundleTokenStore::load(&path).unwrap().redeem(&live).is_ok());
    }

    #[test]
    fn revoke_persist_failure_is_fail_closed_and_retryable() {
        let dir = test_tempdir();
        let path = dir.path().join("tokens.json");
        let bundle = make_bundle(dir.path(), "bundle.tar.gz");
        let mut store = BundleTokenStore::load(&path).unwrap();
        let token = store.issue(bundle, 60, None).unwrap();
        let hash = hash_token(&token);
        let result = store.revoke_with_save(&hash, |_, _| Err(anyhow!("injected commit failure")));
        assert!(matches!(result, Err(BundleTokenError::PersistFailed(_))));
        assert_eq!(store.stats().active, 1);
        assert_eq!(BundleTokenStore::load(&path).unwrap().stats().active, 1);
        store.revoke_by_prefix(&hash).unwrap();
        assert_eq!(BundleTokenStore::load(path).unwrap().stats().consumed, 1);
    }

    #[test]
    fn missing_or_invalid_disk_store_never_resurrects_stale_token() {
        let dir = test_tempdir();
        let path = dir.path().join("tokens.json");
        let bundle = make_bundle(dir.path(), "bundle.tar.gz");
        let mut store = BundleTokenStore::load(&path).unwrap();
        let token = store.issue(bundle, 60, None).unwrap();
        fs::write(&path, b"not a token store").unwrap();
        assert!(matches!(
            store.redeem(&token),
            Err(BundleTokenError::PersistFailed(_))
        ));
        fs::remove_file(path).unwrap();
        assert_eq!(store.redeem(&token), Err(BundleTokenError::NotFound));
    }

    #[test]
    fn atomic_commit_keeps_complete_old_reader_and_private_files() {
        use std::io::Read;
        let dir = test_tempdir();
        let path = dir.path().join("tokens.json");
        let bundle = make_bundle(dir.path(), "bundle.tar.gz");
        let mut store = BundleTokenStore::load(&path).unwrap();
        let token = store.issue(bundle, 60, None).unwrap();
        let old_bytes = fs::read(&path).unwrap();
        let mut old_reader = fs::File::open(&path).unwrap();
        store.redeem(&token).unwrap();
        let mut still_old = Vec::new();
        old_reader.read_to_end(&mut still_old).unwrap();
        assert_eq!(still_old, old_bytes);
        assert_ne!(fs::read(&path).unwrap(), old_bytes);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for file in [&path, &dir.path().join("tokens.json.lock")] {
                assert_eq!(
                    fs::metadata(file).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
        assert_eq!(
            fs::read_dir(dir.path()).unwrap().count(),
            3,
            "bundle, store and stable lock only"
        );
    }

    #[test]
    fn failed_atomic_replacement_removes_staging_without_touching_destination() {
        let dir = test_tempdir();
        let path = dir.path().join("tokens.json");
        let bundle = make_bundle(dir.path(), "bundle.tar.gz");
        let mut store = BundleTokenStore::load(&path).unwrap();
        store.issue(bundle, 60, None).unwrap();
        let lock = store.begin_transaction().unwrap();
        fs::rename(&path, dir.path().join("original.json")).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(store.save(&lock).is_err());
        assert!(path.is_dir());
        assert!(!fs::read_dir(dir.path()).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".aegis-bundle-store-")));
    }

    #[test]
    fn transaction_lock_is_bounded_across_processes() {
        const CHILD_PATH: &str = "AEGIS_FIXTURE_BUNDLE_LOCK_PATH";
        if let Some(path) = std::env::var_os(CHILD_PATH) {
            let error = match StoreLock::acquire(Path::new(&path), Duration::from_millis(20)) {
                Ok(_) => panic!("parent transaction lock must exclude child"),
                Err(error) => error,
            };
            assert_eq!(
                error.downcast_ref::<std::io::Error>().unwrap().kind(),
                std::io::ErrorKind::TimedOut
            );
            return;
        }
        let dir = test_tempdir();
        let path = dir.path().join("tokens.json");
        let lock = StoreLock::acquire(&path, Duration::ZERO).unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "bundle_tokens::tests::transaction_lock_is_bounded_across_processes",
                "--nocapture",
            ])
            .env(CHILD_PATH, &path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child lock assertion failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        drop(lock);
        StoreLock::acquire(&path, Duration::ZERO).expect("release on close");
    }

    #[cfg(unix)]
    #[test]
    fn sidecar_symlink_refuses_before_chmod_or_locking_foreign_inode() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = test_tempdir();
        let store = dir.path().join("tokens.json");
        let victim = dir.path().join("dummy-victim");
        fs::write(&victim, b"unchanged dummy bytes").unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o644)).unwrap();
        symlink(&victim, dir.path().join("tokens.json.lock")).unwrap();
        assert!(StoreLock::acquire(&store, Duration::ZERO).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"unchanged dummy bytes");
        assert_eq!(
            fs::metadata(&victim).unwrap().permissions().mode() & 0o7777,
            0o644
        );
    }

    #[cfg(unix)]
    #[test]
    fn sidecar_hardlink_and_symlinked_parent_refuse_without_effects() {
        use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
        let dir = test_tempdir();
        let victim = dir.path().join("dummy-victim");
        fs::write(&victim, b"dummy").unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o644)).unwrap();
        fs::hard_link(&victim, dir.path().join("tokens.json.lock")).unwrap();
        assert!(StoreLock::acquire(&dir.path().join("tokens.json"), Duration::ZERO).is_err());
        assert_eq!(
            fs::metadata(&victim).unwrap().permissions().mode() & 0o7777,
            0o644
        );
        assert_eq!(fs::metadata(&victim).unwrap().nlink(), 2);
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        symlink(&real, dir.path().join("alias")).unwrap();
        assert!(StoreLock::acquire(&dir.path().join("alias/tokens.json"), Duration::ZERO).is_err());
        assert!(!real.join("tokens.json.lock").exists());
    }

    #[cfg(unix)]
    #[test]
    fn valid_sidecar_keeps_one_private_owned_inode_across_transactions() {
        use std::os::unix::fs::MetadataExt;
        let dir = test_tempdir();
        let store = dir.path().join("tokens.json");
        let sidecar = dir.path().join("tokens.json.lock");
        let lock = StoreLock::acquire(&store, Duration::ZERO).unwrap();
        let first = fs::symlink_metadata(&sidecar).unwrap();
        assert!(first.is_file());
        assert_eq!(first.mode() & 0o7777, 0o600);
        assert_eq!(first.nlink(), 1);
        assert_eq!(first.uid(), unsafe { libc::geteuid() });
        drop(lock);
        let _second = StoreLock::acquire(&store, Duration::ZERO).unwrap();
        let next = fs::symlink_metadata(&sidecar).unwrap();
        assert_eq!((first.dev(), first.ino()), (next.dev(), next.ino()));
    }

    #[cfg(unix)]
    #[test]
    fn held_sidecar_refuses_foreign_owner_and_replaced_name() {
        use std::os::unix::fs::MetadataExt;
        let dir = test_tempdir();
        let store = dir.path().join("tokens.json");
        let lock_path = dir.path().join("tokens.json.lock");
        let lock = StoreLock::acquire(&store, Duration::ZERO).unwrap();
        let leaf = std::ffi::CString::new("tokens.json.lock").unwrap();
        let metadata = lock._file.metadata().unwrap();
        let expected = StoreOwner {
            uid: metadata.uid(),
            gid: metadata.gid(),
        };
        let foreign = StoreOwner {
            uid: expected.uid.wrapping_add(1),
            gid: expected.gid,
        };
        assert!(verify_lock_leaf(&lock._parent, &leaf, &lock._file, foreign).is_err());
        fs::rename(&lock_path, dir.path().join("retired.lock")).unwrap();
        fs::write(&lock_path, b"").unwrap();
        assert!(verify_lock_leaf(&lock._parent, &leaf, &lock._file, expected).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn only_existing_root_lock_may_migrate_to_expected_service_owner() {
        let service = StoreOwner {
            uid: 1001,
            gid: 1001,
        };
        let root = StoreOwner { uid: 0, gid: 0 };
        let foreign = StoreOwner {
            uid: 2002,
            gid: 2002,
        };
        assert!(lock_owner_migration_allowed(false, root, service, true));
        assert!(lock_owner_migration_allowed(false, service, service, false));
        assert!(!lock_owner_migration_allowed(false, foreign, service, true));
        assert!(!lock_owner_migration_allowed(false, root, service, false));
    }

    #[test]
    fn hash_token_is_deterministic_hex64() {
        let a = hash_token("my-secret");
        let b = hash_token("my-secret");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        let c = hash_token("different");
        assert_ne!(a, c);
    }

    #[cfg(unix)]
    #[test]
    fn root_write_owner_prefers_non_root_parent_to_repair_root_file() {
        let root_file = StoreOwner { uid: 0, gid: 0 };
        let service_parent = StoreOwner {
            uid: 1001,
            gid: 1001,
        };
        assert_eq!(
            BundleTokenStore::choose_owner_for_root_write(Some(root_file), Some(service_parent)),
            Some(service_parent)
        );
    }

    #[cfg(unix)]
    #[test]
    fn root_write_owner_preserves_existing_non_root_file_when_parent_is_root() {
        let service_file = StoreOwner {
            uid: 1001,
            gid: 1001,
        };
        let root_parent = StoreOwner { uid: 0, gid: 0 };
        assert_eq!(
            BundleTokenStore::choose_owner_for_root_write(Some(service_file), Some(root_parent)),
            Some(service_file)
        );
    }

    #[cfg(unix)]
    #[test]
    fn root_write_owner_uses_parent_for_new_file() {
        let service_parent = StoreOwner {
            uid: 1001,
            gid: 1001,
        };
        assert_eq!(
            BundleTokenStore::choose_owner_for_root_write(None, Some(service_parent)),
            Some(service_parent)
        );
    }
}

#[cfg(test)]
#[path = "bundle_token_format_tests.rs"]
mod token_format_tests;
