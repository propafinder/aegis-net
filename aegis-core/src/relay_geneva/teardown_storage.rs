//! Private durable archive, exact opened-file identity and no-clobber removal.
//! Only public selected ownership records are callers; no recursive rm sweep.
use super::teardown::{FilePin, TeardownRecord};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
        io::AsRawFd,
    },
    path::{Path, PathBuf},
};
fn need(v: bool) -> io::Result<()> {
    if v {
        Ok(())
    } else {
        Err(io::Error::other("selected archive ownership refused"))
    }
}
fn owner() -> u32 {
    #[cfg(test)]
    {
        unsafe { libc::getuid() }
    }
    #[cfg(not(test))]
    {
        0
    }
}
fn parent(path: &Path) -> io::Result<()> {
    for p in path.ancestors() {
        let m = std::fs::symlink_metadata(p)?;
        need(
            m.is_dir()
                && !m.file_type().is_symlink()
                && (m.uid() == owner() || m.uid() == 0)
                && m.mode() & 0o022 == 0,
        )?;
    }
    Ok(())
}
#[derive(Clone)]
pub struct OpenedPublicFile {
    pub pin: FilePin,
    pub bytes: Vec<u8>,
    pub path: PathBuf,
}
pub fn open_public(path: &Path, max: usize) -> io::Result<OpenedPublicFile> {
    parent(
        path.parent()
            .ok_or_else(|| io::Error::other("missing archive parent"))?,
    )?;
    let before = std::fs::symlink_metadata(path)?;
    need(
        before.is_file()
            && !before.file_type().is_symlink()
            && before.uid() == owner()
            && before.nlink() == 1
            && before.mode() & 0o022 == 0
            && before.len() <= max as u64,
    )?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let opened = file.metadata()?;
    need(opened.dev() == before.dev() && opened.ino() == before.ino())?;
    let mut bytes = vec![];
    Read::by_ref(&mut file)
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)?;
    need(bytes.len() <= max)?;
    let after = std::fs::symlink_metadata(path)?;
    need(
        after.dev() == opened.dev()
            && after.ino() == opened.ino()
            && after.len() == opened.len()
            && after.mode() == opened.mode()
            && after.uid() == owner()
            && after.nlink() == 1,
    )?;
    let pin = FilePin {
        device: opened.dev(),
        inode: opened.ino(),
        sha256: hex::encode(Sha256::digest(&bytes)),
        size: bytes.len() as u64,
        mode: opened.mode() & 0o777,
    };
    pin.validate()?;
    Ok(OpenedPublicFile {
        pin,
        bytes,
        path: path.into(),
    })
}
pub fn unchanged(file: &OpenedPublicFile) -> io::Result<()> {
    need(open_public(&file.path, 18 * 1048576)?.pin == file.pin)
}
pub fn remove_exact(file: &OpenedPublicFile) -> io::Result<()> {
    unchanged(file)?;
    let p = file
        .path
        .parent()
        .ok_or_else(|| io::Error::other("missing unlink parent"))?;
    let name = file
        .path
        .file_name()
        .and_then(|x| x.to_str())
        .ok_or_else(|| io::Error::other("unlink name"))?;
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(p)?;
    let current = std::fs::symlink_metadata(p)?;
    need(dir.metadata()?.ino() == current.ino() && dir.metadata()?.dev() == current.dev())?;
    let name = std::ffi::CString::new(name).map_err(|_| io::Error::other("unlink CString"))?;
    // Ownership is bound again immediately before unlinkat, not inferred from
    // a historical pathname. Root-owned parents exclude unprivileged replacement.
    unchanged(file)?;
    if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    dir.sync_all()?;
    need(std::fs::symlink_metadata(&file.path).is_err_and(|e| e.kind() == io::ErrorKind::NotFound))
}
fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    parent(
        path.parent()
            .ok_or_else(|| io::Error::other("archive parent"))?,
    )?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    File::open(path.parent().unwrap())?.sync_all()
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveManifest {
    pub schema: String,
    pub token: String,
    pub source: String,
    pub files: BTreeMap<String, FilePin>,
}
pub struct VerifiedArchiveSnapshot {
    pub manifest_sha256: String,
    pub manifest: ArchiveManifest,
    pub files: BTreeMap<String, OpenedPublicFile>,
}
pub struct Archive {
    pub directory: PathBuf,
    identity: DirectoryPin,
}
impl Archive {
    pub fn identity(&self) -> io::Result<DirectoryPin> {
        let pin = directory_pin(&self.directory)?;
        need(pin == self.identity)?;
        Ok(pin)
    }
    pub fn write_extra(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        self.identity()?;
        need(
            !name.is_empty()
                && name.len() <= 128
                && bytes.len() <= 2 * 1048576
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)),
        )?;
        write_new(&self.directory.join(name), bytes)
    }
    pub fn verify_extra(&self, name: &str, expected: &[u8]) -> io::Result<()> {
        self.identity()?;
        need(
            !name.is_empty()
                && name.len() <= 128
                && expected.len() <= 2 * 1048576
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)),
        )?;
        let actual = open_public(&self.directory.join(name), 2 * 1048576)?;
        need(actual.bytes == expected)
    }
    pub fn create(root: &Path, token: &str) -> io::Result<Self> {
        need(
            token.len() == 32
                && token
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        )?;
        parent(
            root.parent()
                .ok_or_else(|| io::Error::other("history parent"))?,
        )?;
        match std::fs::DirBuilder::new().mode(0o700).create(root) {
            Ok(()) => File::open(root.parent().unwrap())?.sync_all()?,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        parent(root)?;
        need(std::fs::symlink_metadata(root)?.mode() & 0o777 == 0o700)?;
        let directory = root.join(token);
        std::fs::DirBuilder::new().mode(0o700).create(&directory)?;
        File::open(root)?.sync_all()?;
        Ok(Self {
            identity: directory_pin(&directory)?,
            directory,
        })
    }
    pub fn existing(root: &Path, token: &str) -> io::Result<Self> {
        need(
            token.len() == 32
                && token
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        )?;
        let directory = root.join(token);
        parent(&directory)?;
        need(std::fs::symlink_metadata(&directory)?.mode() & 0o777 == 0o700)?;
        Ok(Self {
            identity: directory_pin(&directory)?,
            directory,
        })
    }
    pub fn append(&self, index: usize, row: &TeardownRecord) -> io::Result<()> {
        self.identity()?;
        need(index <= 16)?;
        row.validate()?;
        write_new(
            &self.directory.join(format!("{index:08}-phase.json")),
            &serde_json::to_vec(row)?,
        )
    }
    pub fn copy(
        &self,
        token: &str,
        source: &str,
        files: &BTreeMap<String, OpenedPublicFile>,
    ) -> io::Result<String> {
        self.identity()?;
        need(files.len() <= 8500)?;
        let mut total = 0;
        let mut pins = BTreeMap::new();
        for (name, file) in files {
            need(Path::new(name) == file.path)?;
            unchanged(file)?;
            total += file.bytes.len();
            need(total <= 24 * 1048576)?;
            let leaf = format!("{}.public", hex::encode(Sha256::digest(name.as_bytes())));
            let dest = self.directory.join(leaf);
            match open_public(&dest, 18 * 1048576) {
                Ok(old) => need(old.bytes == file.bytes)?,
                Err(e) if e.kind() == io::ErrorKind::NotFound => write_new(&dest, &file.bytes)?,
                Err(e) => return Err(e),
            }
            need(open_public(&dest, 18 * 1048576)?.bytes == file.bytes)?;
            pins.insert(name.clone(), file.pin.clone());
        }
        let manifest = ArchiveManifest {
            schema: "aegis_selected_teardown_archive_v1".into(),
            token: token.into(),
            source: source.into(),
            files: pins,
        };
        let bytes = serde_json::to_vec(&manifest)?;
        need(bytes.len() <= 2 * 1048576)?;
        let manifest_path = self.directory.join("archive-manifest.json");
        match open_public(&manifest_path, 2 * 1048576) {
            Ok(old) => need(old.bytes == bytes)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => write_new(&manifest_path, &bytes)?,
            Err(e) => return Err(e),
        }
        File::open(&self.directory)?.sync_all()?;
        let digest = hex::encode(Sha256::digest(&bytes));
        need(self.verify()?.0 == digest)?;
        Ok(digest)
    }
    pub fn verified_snapshot(&self) -> io::Result<VerifiedArchiveSnapshot> {
        self.identity()?;
        parent(&self.directory)?;
        let bytes = open_public(&self.directory.join("archive-manifest.json"), 2 * 1048576)?.bytes;
        let manifest: ArchiveManifest = serde_json::from_value(
            super::recovery::parse_unique_public_metadata_bounded(&bytes, 2 * 1048576)?,
        )
        .map_err(|_| io::Error::other("archive JSON"))?;
        need(
            manifest.schema == "aegis_selected_teardown_archive_v1" && manifest.files.len() <= 8500,
        )?;
        let mut total = 0;
        let mut files = BTreeMap::new();
        for (name, pin) in &manifest.files {
            pin.validate()?;
            let leaf = format!("{}.public", hex::encode(Sha256::digest(name.as_bytes())));
            let file = open_public(&self.directory.join(leaf), 18 * 1048576)?;
            need(file.pin.sha256 == pin.sha256 && file.pin.size == pin.size)?;
            total += file.bytes.len();
            need(total <= 24 * 1048576)?;
            files.insert(name.clone(), file);
        }
        self.identity()?;
        let again = open_public(&self.directory.join("archive-manifest.json"), 2 * 1048576)?;
        need(again.bytes == bytes)?;
        Ok(VerifiedArchiveSnapshot {
            manifest_sha256: hex::encode(Sha256::digest(&bytes)),
            manifest,
            files,
        })
    }
    pub fn verified_snapshot_pinned(
        &self,
        expected_sha256: &str,
    ) -> io::Result<VerifiedArchiveSnapshot> {
        let snapshot = self.verified_snapshot()?;
        need(snapshot.manifest_sha256 == expected_sha256)?;
        Ok(snapshot)
    }
    pub fn verify(&self) -> io::Result<(String, ArchiveManifest)> {
        let snapshot = self.verified_snapshot()?;
        Ok((snapshot.manifest_sha256, snapshot.manifest))
    }
    pub fn original(&self, name: &Path) -> io::Result<Vec<u8>> {
        let (_, m) = self.verify()?;
        let name = name
            .to_str()
            .ok_or_else(|| io::Error::other("archive path"))?;
        let pin = m
            .files
            .get(name)
            .ok_or_else(|| io::Error::other("unowned archive path"))?;
        let leaf = format!("{}.public", hex::encode(Sha256::digest(name.as_bytes())));
        let f = open_public(&self.directory.join(leaf), 18 * 1048576)?;
        need(f.pin.sha256 == pin.sha256)?;
        Ok(f.bytes)
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryPin {
    pub device: u64,
    pub inode: u64,
    pub mode: u32,
}
pub fn directory_pin(path: &Path) -> io::Result<DirectoryPin> {
    parent(path)?;
    let m = std::fs::symlink_metadata(path)?;
    need(m.is_dir() && m.mode() & 0o777 == 0o700)?;
    Ok(DirectoryPin {
        device: m.dev(),
        inode: m.ino(),
        mode: m.mode() & 0o777,
    })
}
pub fn remove_empty_exact(path: &Path, pin: &DirectoryPin) -> io::Result<()> {
    need(directory_pin(path)? == *pin && std::fs::read_dir(path)?.next().is_none())?;
    let par = path
        .parent()
        .ok_or_else(|| io::Error::other("directory unlink parent"))?;
    let name = std::ffi::CString::new(
        path.file_name()
            .and_then(|x| x.to_str())
            .ok_or_else(|| io::Error::other("directory unlink name"))?,
    )
    .map_err(|_| io::Error::other("directory unlink name"))?;
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(par)?;
    need(directory_pin(path)? == *pin)?;
    if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(io::Error::last_os_error());
    }
    dir.sync_all()?;
    need(std::fs::symlink_metadata(path).is_err_and(|e| e.kind() == io::ErrorKind::NotFound))
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn root() -> tempfile::TempDir {
        // The production archive refuses every writable ancestor. Linux's
        // ordinary /tmp (1777) is intentionally not a trusted archive parent.
        // Keep fixtures in the protected, canonical test workspace instead;
        // do not weaken ownership checks, require root, or skip the tests.
        let base = std::fs::canonicalize(std::env::current_dir().unwrap()).unwrap();
        parent(&base).expect("archive tests require protected workspace ancestors");
        let d = tempfile::tempdir_in(base).unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        parent(d.path()).unwrap();
        d
    }
    #[test]
    fn writable_or_symlink_ancestor_refuses_before_archive_creation() {
        let d = root();
        let writable = d.path().join("writable");
        std::fs::create_dir(&writable).unwrap();
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o722)).unwrap();
        let file = writable.join("public");
        std::fs::write(&file, b"retained").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(open_public(&file, 100).is_err());
        let history = writable.join("history");
        assert!(Archive::create(&history, &"a".repeat(32)).is_err());
        assert!(!history.exists());
        assert_eq!(std::fs::read(&file).unwrap(), b"retained");

        let protected = d.path().join("protected");
        std::fs::create_dir(&protected).unwrap();
        std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o700)).unwrap();
        let public = protected.join("public");
        std::fs::write(&public, b"owned").unwrap();
        std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(open_public(&public, 100).is_ok());
        let alias = d.path().join("alias");
        std::os::unix::fs::symlink(&protected, &alias).unwrap();
        assert!(open_public(&alias.join("public"), 100).is_err());
        assert!(Archive::create(&alias.join("history"), &"a".repeat(32)).is_err());
        assert!(!protected.join("history").exists());
        assert_eq!(std::fs::read(public).unwrap(), b"owned");
    }
    #[test]
    fn archived_transition_marker_exact_bytes_required_before_resume() {
        let d = root();
        let archive = Archive::create(d.path(), &"a".repeat(32)).unwrap();
        let bytes =
            br#"{"schema":"public_marker","source":"pinned","initial_record_sha256":"pinned"}"#;
        archive.write_extra("teardown-marker.json", bytes).unwrap();
        archive.verify_extra("teardown-marker.json", bytes).unwrap();
        let mut rewritten = bytes.to_vec();
        rewritten.push(b'\n');
        std::fs::write(archive.directory.join("teardown-marker.json"), rewritten).unwrap();
        assert!(archive.verify_extra("teardown-marker.json", bytes).is_err());
        assert!(archive.write_extra("teardown-marker.json", bytes).is_err());
        assert!(archive.directory.exists());
    }
    #[test]
    fn bulk_snapshot_preserves_source_and_late_member_or_manifest_bytes_refuse() {
        let d = root();
        let p = d.path().join("original");
        std::fs::write(&p, b"original retained").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let source = open_public(&p, 100).unwrap();
        let files = BTreeMap::from([(p.to_str().unwrap().to_owned(), source.clone())]);
        let archive = Archive::create(d.path(), &"a".repeat(32)).unwrap();
        let digest = archive
            .copy(&"a".repeat(32), &"b".repeat(40), &files)
            .unwrap();
        let snapshot = archive.verified_snapshot_pinned(&digest).unwrap();
        assert_eq!(snapshot.files.len(), 1);
        assert_eq!(
            snapshot.files.values().next().unwrap().bytes,
            b"original retained"
        );
        let member = snapshot.files.values().next().unwrap().path.clone();
        std::fs::write(&member, b"late substitution").unwrap();
        assert!(archive.verified_snapshot_pinned(&digest).is_err());
        assert_eq!(std::fs::read(&p).unwrap(), b"original retained");
        std::fs::write(&member, b"original retained").unwrap();
        let manifest = archive.directory.join("archive-manifest.json");
        let bytes = std::fs::read(&manifest).unwrap();
        let mut whitespace = bytes.clone();
        whitespace.push(b'\n');
        std::fs::write(&manifest, &whitespace).unwrap();
        assert!(archive.verify().is_ok()); // typed contents unchanged; byte pin remains mandatory
        assert!(archive.verified_snapshot_pinned(&digest).is_err());
        assert_eq!(std::fs::read(&p).unwrap(), b"original retained");
    }
    #[test]
    fn archive_directory_replacement_and_unknown_child_refuse() {
        let d = root();
        let a = Archive::create(d.path(), &"a".repeat(32)).unwrap();
        let pin = a.identity().unwrap();
        let moved = d.path().join("retained");
        std::fs::rename(&a.directory, &moved).unwrap();
        std::fs::create_dir(&a.directory).unwrap();
        std::fs::set_permissions(&a.directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(a.write_extra("evidence.json", b"public").is_err());
        assert!(remove_empty_exact(&a.directory, &pin).is_err());
        let current = directory_pin(&a.directory).unwrap();
        std::fs::write(a.directory.join("foreign"), b"retain").unwrap();
        assert!(remove_empty_exact(&a.directory, &current).is_err());
        assert_eq!(
            std::fs::read(a.directory.join("foreign")).unwrap(),
            b"retain"
        );
        assert!(moved.exists());
    }
    #[test]
    fn hardlink_and_symlink_are_never_owned_public_files() {
        let d = root();
        let p = d.path().join("p");
        std::fs::write(&p, b"public").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&p, d.path().join("alias")).unwrap();
        assert!(open_public(&p, 10).is_err());
        std::os::unix::fs::symlink(&p, d.path().join("link")).unwrap();
        assert!(open_public(&d.path().join("link"), 10).is_err());
        assert_eq!(std::fs::read(&p).unwrap(), b"public");
    }
    #[test]
    fn pin_binds_real_open_file_not_same_name_replacement() {
        let d = root();
        let p = d.path().join("owned");
        std::fs::write(&p, b"one").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let first = open_public(&p, 10).unwrap();
        let replacement = d.path().join("replacement");
        std::fs::write(&replacement, b"two").unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::rename(replacement, &p).unwrap();
        assert!(unchanged(&first).is_err());
        assert!(remove_exact(&first).is_err());
        assert_eq!(std::fs::read(p).unwrap(), b"two");
    }
    #[test]
    fn actual_archive_refuses_overwrite_and_late_substitution() {
        let d = root();
        let p = d.path().join("owned");
        std::fs::write(&p, b"public-history").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let f = open_public(&p, 1024).unwrap();
        let a = Archive::create(&d.path().join("history"), &"a".repeat(32)).unwrap();
        let files = BTreeMap::from([(p.to_str().unwrap().to_string(), f.clone())]);
        let digest = a.copy(&"a".repeat(32), &"b".repeat(40), &files).unwrap();
        assert_eq!(a.verify().unwrap().0, digest);
        assert_eq!(a.original(&p).unwrap(), b"public-history");
        assert_eq!(
            a.copy(&"a".repeat(32), &"b".repeat(40), &files).unwrap(),
            digest
        );
        assert!(a.copy(&"a".repeat(32), &"c".repeat(40), &files).is_err());
        let leaf = a.directory.join(format!(
            "{}.public",
            hex::encode(Sha256::digest(p.to_str().unwrap().as_bytes()))
        ));
        std::fs::write(leaf, b"different").unwrap();
        assert!(a.verify().is_err());
        assert_eq!(std::fs::read(p).unwrap(), b"public-history");
    }
    #[test]
    fn exact_unlink_preserves_foreign_sibling() {
        let d = root();
        let p = d.path().join("owned");
        std::fs::write(&p, b"owned").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let sibling = d.path().join("foreign");
        std::fs::write(&sibling, b"keep").unwrap();
        let f = open_public(&p, 10).unwrap();
        remove_exact(&f).unwrap();
        assert!(!p.exists());
        assert_eq!(std::fs::read(sibling).unwrap(), b"keep");
    }
}
