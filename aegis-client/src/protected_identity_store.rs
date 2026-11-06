//! A concrete Unix owner for the existing device Store's lock and private reads.
//! This enforces file custody only. Parsing, certificate validation, online
//! issuance, authenticated relay ACK and packet authority remain separate.

use crate::protected_identity_file::{read_private, validate_file};
use aegis_core::secure_channel::enrollment;
use anyhow::{ensure, Context, Result};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Copy, Eq, PartialEq)]
struct Identity {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
}
impl Identity {
    fn of(meta: &fs::Metadata) -> Self {
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            uid: meta.uid(),
            gid: meta.gid(),
            mode: meta.mode(),
            links: meta.nlink(),
        }
    }

    fn same_directory(self, other: Self) -> bool {
        self.dev == other.dev
            && self.ino == other.ino
            && self.uid == other.uid
            && self.gid == other.gid
            && self.mode == other.mode
    }
}

pub struct ProtectedIdentityStore {
    directory: PathBuf,
    directory_file: File,
    directory_identity: Identity,
    lock: File,
    lock_identity: Identity,
}
impl ProtectedIdentityStore {
    /// Existing Store path only: never creates a directory or a lock sidecar.
    pub fn open_existing(directory: &Path) -> Result<Self> {
        ensure!(
            directory.is_absolute()
                && !directory
                    .components()
                    .any(|c| matches!(c, Component::ParentDir)),
            "identity directory requires an absolute path without parent traversal"
        );
        let directory = enrollment::trusted_parent(&directory.join("identity.json"))?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(directory.join(".lock"))?;
        Self::adopt(directory, lock)
    }

    /// Adopt the exact lock opened by the binary Store during creation.
    /// The supplied descriptor must still name `directory/.lock`.
    pub fn adopt(directory: PathBuf, lock: File) -> Result<Self> {
        let directory_file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&directory)?;
        let directory_meta = directory_file.metadata()?;
        ensure!(
            directory_meta.is_dir()
                && directory_meta.uid() == unsafe { libc::geteuid() }
                && directory_meta.mode() & 0o077 == 0,
            "identity directory requires owner-only access"
        );
        let lock_meta = lock.metadata()?;
        validate_file(&lock_meta)?;
        let directory_identity = Identity::of(&directory_meta);
        let lock_identity = Identity::of(&lock_meta);
        let owner = Self {
            directory,
            directory_file,
            directory_identity,
            lock,
            lock_identity,
        };
        owner.revalidate()?;
        owner
            .lock
            .try_lock()
            .context("device enrollment is busy or cannot be locked")?;
        owner.revalidate()?;
        Ok(owner)
    }

    pub fn revalidate(&self) -> Result<()> {
        ensure!(
            Identity::of(&self.directory_file.metadata()?).same_directory(self.directory_identity)
                && Identity::of(&fs::symlink_metadata(&self.directory)?)
                    .same_directory(self.directory_identity),
            "identity directory generation changed"
        );
        ensure!(
            Identity::of(&self.lock.metadata()?) == self.lock_identity
                && Identity::of(&fs::symlink_metadata(self.directory.join(".lock"))?)
                    == self.lock_identity,
            "identity Store lock generation changed"
        );
        Ok(())
    }

    /// Same held-lock generation, with the online journal's historical 256 KiB
    /// limit. Ordinary Store inputs retain their separate 64 KiB bound.
    pub fn read_online(&self, name: &str) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        const MAX_ONLINE: u64 = 256 * 1024;
        ensure!(
            matches!(
                Path::new(name).components().collect::<Vec<_>>().as_slice(),
                [Component::Normal(_)]
            ),
            "online Store read requires one file name"
        );
        self.revalidate()?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(self.directory.join(name))?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.len() <= MAX_ONLINE
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o077 == 0
                && metadata.nlink() == 1,
            "online identity state permissions, links or bound invalid"
        );
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        file.take(MAX_ONLINE + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_ONLINE,
            "online identity state exceeds bound"
        );
        self.revalidate()?;
        Ok(bytes)
    }

    pub fn read(&self, name: &str) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        ensure!(
            matches!(
                Path::new(name).components().collect::<Vec<_>>().as_slice(),
                [Component::Normal(_)]
            ),
            "identity Store read requires one file name"
        );
        self.revalidate()?;
        let result = read_private(&self.directory.join(name));
        self.revalidate()?;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn online_journal_retains_historical_256k_bound_under_same_lock() {
        let base = tempfile::tempdir().unwrap();
        let identity = base.path().join("identity");
        fs::create_dir(&identity).unwrap();
        fs::set_permissions(&identity, fs::Permissions::from_mode(0o700)).unwrap();
        for (name, bytes) in [
            (".lock", Vec::new()),
            ("journal.json", vec![b'x'; 70 * 1024]),
        ] {
            fs::write(identity.join(name), bytes).unwrap();
            fs::set_permissions(identity.join(name), fs::Permissions::from_mode(0o600)).unwrap();
        }
        let held = ProtectedIdentityStore::open_existing(&identity).unwrap();
        assert!(held.read("journal.json").is_err());
        assert_eq!(held.read_online("journal.json").unwrap().len(), 70 * 1024);
        fs::write(identity.join("journal.json"), vec![b'x'; 256 * 1024 + 1]).unwrap();
        assert!(held.read_online("journal.json").is_err());
    }

    #[test]
    fn actual_lock_read_and_replacement_fail_closed() {
        let base = tempfile::tempdir().unwrap();
        let identity = base.path().join("identity");
        fs::create_dir(&identity).unwrap();
        fs::set_permissions(&identity, fs::Permissions::from_mode(0o700)).unwrap();
        for (name, bytes) in [
            (".lock", b"".as_slice()),
            ("identity.json", b"fixture".as_slice()),
        ] {
            let path = identity.join(name);
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let owner = ProtectedIdentityStore::open_existing(&identity).unwrap();
        assert_eq!(owner.read("identity.json").unwrap().as_slice(), b"fixture");
        fs::write(identity.join("normal-write"), b"fixture").unwrap();
        assert_eq!(owner.read("identity.json").unwrap().as_slice(), b"fixture");
        assert!(owner.read("../identity.json").is_err());
        assert!(ProtectedIdentityStore::open_existing(&identity).is_err());
        fs::rename(identity.join(".lock"), identity.join("old-lock")).unwrap();
        fs::write(identity.join(".lock"), b"").unwrap();
        fs::set_permissions(identity.join(".lock"), fs::Permissions::from_mode(0o600)).unwrap();
        assert!(owner.read("identity.json").is_err());
        fs::remove_file(identity.join(".lock")).unwrap();
        symlink(identity.join("old-lock"), identity.join(".lock")).unwrap();
        assert!(ProtectedIdentityStore::open_existing(&identity).is_err());
    }
}
