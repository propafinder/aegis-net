//! Closed public-text installation using held directory descriptors.
//! This helper neither reads credentials nor changes runtime/network policy.
use std::path::PathBuf;

#[derive(clap::Args, Clone, Debug)]
pub struct Args {
    #[command(subcommand)]
    action: Action,
}
#[derive(clap::Subcommand, Clone, Debug)]
enum Action {
    Version,
    Check(Input),
    Install(Input),
}
#[derive(clap::Args, Clone, Debug)]
struct Input {
    #[arg(long)]
    home: PathBuf,
    #[arg(long)]
    owner_uid: u32,
    #[arg(long)]
    owner_gid: u32,
    #[arg(long)]
    leaf: String,
    #[arg(long)]
    expected_sha256: String,
}
pub(super) fn run(args: &Args) -> Result<(), String> {
    let result = match &args.action {
        Action::Version => {
            println!("project-license-v1");
            return Ok(());
        }
        Action::Check(input) => execute(input, false),
        Action::Install(input) => execute(input, true),
    };
    result.map_err(|_| "Public project text operation refused".to_string())
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn execute(_: &Input, _: bool) -> Result<(), ()> {
    Err(())
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn execute(input: &Input, install: bool) -> Result<(), ()> {
    use std::io::Read;
    // Bound and authenticate public bytes before even directory creation.
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    unix::operate(input, &bytes, install)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix {
    use super::Input;
    use sha2::{Digest, Sha256};
    use std::ffi::{CStr, CString};
    use std::fs::File;
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Component, Path};

    type Result<T> = std::result::Result<T, ()>;
    const SUFFIX: [&str; 4] = [".local", "share", "doc", "aegis"];
    fn c(value: &str) -> Result<CString> {
        CString::new(value).map_err(|_| ())
    }
    fn owned(fd: RawFd) -> Result<OwnedFd> {
        if fd < 0 {
            Err(())
        } else {
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    }
    fn stat(fd: RawFd) -> Result<libc::stat> {
        let mut out = std::mem::MaybeUninit::uninit();
        if unsafe { libc::fstat(fd, out.as_mut_ptr()) } != 0 {
            return Err(());
        }
        Ok(unsafe { out.assume_init() })
    }
    fn directory(parent: RawFd, name: &CStr) -> Result<OwnedFd> {
        owned(unsafe {
            libc::openat(
                parent,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        })
    }
    fn absent() -> bool {
        std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT)
    }
    fn base(home: &Path, uid: u32) -> Result<OwnedFd> {
        if !home.is_absolute() {
            return Err(());
        }
        // Resolve ONLY the admitted HOME base (e.g. /var/root system alias).
        // The fixed documentation suffix is never canonicalized.
        let physical = home.canonicalize().map_err(|_| ())?;
        let root = c("/")?;
        let mut fd = owned(unsafe {
            libc::open(
                root.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        })?;
        for part in physical.components() {
            match part {
                Component::RootDir => (),
                Component::Normal(name) => {
                    let name = CString::new(name.as_bytes()).map_err(|_| ())?;
                    fd = directory(fd.as_raw_fd(), &name)?;
                }
                _ => return Err(()),
            }
        }
        if stat(fd.as_raw_fd())?.st_uid != uid {
            return Err(());
        }
        Ok(fd)
    }
    fn validate(input: &Input, bytes: &[u8]) -> Result<()> {
        let euid = unsafe { libc::geteuid() };
        if euid != 0 && euid != input.owner_uid {
            return Err(());
        }
        if !matches!(
            input.leaf.as_str(),
            "LICENSE-MIT" | "LICENSE-APACHE" | "NOTICE"
        ) || bytes.is_empty()
            || bytes.len() > 65536
            || input.expected_sha256.len() != 64
            || !input
                .expected_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || format!("{:x}", Sha256::digest(bytes)) != input.expected_sha256
        {
            return Err(());
        }
        Ok(())
    }
    fn leaf_admitted(fd: RawFd, leaf: &CStr) -> Result<()> {
        let mut out = std::mem::MaybeUninit::<libc::stat>::uninit();
        let rc = unsafe {
            libc::fstatat(
                fd,
                leaf.as_ptr(),
                out.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            return if absent() { Ok(()) } else { Err(()) };
        }
        let out = unsafe { out.assume_init() };
        if out.st_mode & libc::S_IFMT != libc::S_IFREG || out.st_nlink != 1 {
            return Err(());
        }
        Ok(())
    }
    fn metadata_new(fd: RawFd, uid: u32, gid: u32, mode: libc::mode_t) -> Result<()> {
        if unsafe { libc::fchown(fd, uid, gid) } != 0 {
            return Err(());
        }
        if unsafe { libc::fchmod(fd, mode) } != 0 {
            return Err(());
        }
        Ok(())
    }
    fn random_name() -> String {
        let value: [u8; 16] = rand::random();
        let mut out = String::from(".aegis-project-");
        for byte in value {
            use std::fmt::Write;
            let _ = write!(&mut out, "{byte:02x}");
        }
        out
    }
    fn exclusive_publish(from: RawFd, old: &CStr, to: RawFd, new: &CStr) -> Result<()> {
        #[cfg(target_os = "linux")]
        let rc = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                from,
                old.as_ptr(),
                to,
                new.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        #[cfg(target_os = "macos")]
        let rc =
            unsafe { libc::renameatx_np(from, old.as_ptr(), to, new.as_ptr(), libc::RENAME_EXCL) };
        if rc == 0 {
            Ok(())
        } else {
            Err(())
        }
    }
    fn trusted_tmp() -> Result<OwnedFd> {
        let fd = base(Path::new("/tmp"), 0)?;
        if stat(fd.as_raw_fd())?.st_mode & libc::S_ISVTX == 0 {
            return Err(());
        }
        Ok(fd)
    }
    struct Stage {
        tmp: OwnedFd,
        fd: OwnedFd,
        name: CString,
    }
    impl Stage {
        fn new() -> Result<Self> {
            // /tmp may be a system alias; its physical root-owned sticky inode
            // is opened component-by-component. TMPDIR is intentionally unused.
            let tmp = trusted_tmp()?;
            let name = c(&random_name())?;
            if unsafe { libc::mkdirat(tmp.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                return Err(());
            }
            let fd = match directory(tmp.as_raw_fd(), &name) {
                Ok(fd) => fd,
                Err(()) => {
                    unsafe {
                        libc::unlinkat(tmp.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR);
                    }
                    return Err(());
                }
            };
            let meta = stat(fd.as_raw_fd())?;
            if meta.st_uid != unsafe { libc::geteuid() } || meta.st_mode & 0o7777 != 0o700 {
                unsafe {
                    libc::unlinkat(tmp.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR);
                }
                return Err(());
            }
            Ok(Self { tmp, fd, name })
        }
        fn publish_directory(
            &self,
            parent: RawFd,
            name: &CStr,
            uid: u32,
            gid: u32,
        ) -> Result<OwnedFd> {
            let child = c("new-directory")?;
            if unsafe { libc::mkdirat(self.fd.as_raw_fd(), child.as_ptr(), 0o700) } != 0 {
                return Err(());
            }
            let result = (|| {
                let fd = directory(self.fd.as_raw_fd(), &child)?;
                metadata_new(fd.as_raw_fd(), uid, gid, 0o755)?;
                // Exclusive rename: EEXIST/EXDEV refuse, never copying metadata
                // into a substituted user-controlled destination inode.
                exclusive_publish(self.fd.as_raw_fd(), &child, parent, name)?;
                Ok(fd)
            })();
            unsafe {
                libc::unlinkat(self.fd.as_raw_fd(), child.as_ptr(), libc::AT_REMOVEDIR);
            }
            result
        }
    }
    impl Drop for Stage {
        fn drop(&mut self) {
            unsafe {
                libc::unlinkat(self.tmp.as_raw_fd(), self.name.as_ptr(), libc::AT_REMOVEDIR);
            }
        }
    }
    fn destination(input: &Input, create: bool) -> Result<Option<OwnedFd>> {
        let mut fd = base(&input.home, input.owner_uid)?;
        let trusted = trusted_tmp()?;
        let device = stat(trusted.as_raw_fd())?.st_dev;
        if stat(fd.as_raw_fd())?.st_dev != device {
            return Err(());
        }
        let mut stage = None;
        for name in SUFFIX {
            let name = c(name)?;
            fd = match directory(fd.as_raw_fd(), &name) {
                Ok(next) => {
                    let meta = stat(next.as_raw_fd())?;
                    if meta.st_uid != input.owner_uid || meta.st_dev != device {
                        return Err(());
                    }
                    next
                }
                Err(()) if absent() => {
                    if !create {
                        return Ok(None);
                    }
                    if stage.is_none() {
                        stage = Some(Stage::new()?);
                    }
                    stage.as_ref().ok_or(())?.publish_directory(
                        fd.as_raw_fd(),
                        &name,
                        input.owner_uid,
                        input.owner_gid,
                    )?
                }
                Err(()) => return Err(()),
            };
        }
        leaf_admitted(fd.as_raw_fd(), &c(&input.leaf)?)?;
        Ok(Some(fd))
    }
    fn write_anchored(input: &Input, bytes: &[u8], parent: &OwnedFd) -> Result<()> {
        // Keep the source inode in an inaccessible held stage. A temporary
        // pathname in the user-writable destination could itself be replaced.
        let stage = Stage::new()?;
        let name = c(&random_name())?;
        let fd = owned(unsafe {
            libc::openat(
                stage.fd.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        })?;
        let result = (|| {
            let mut file = File::from(fd);
            file.write_all(bytes).map_err(|_| ())?;
            file.sync_all().map_err(|_| ())?;
            metadata_new(file.as_raw_fd(), input.owner_uid, input.owner_gid, 0o644)?;
            let leaf = c(&input.leaf)?;
            leaf_admitted(parent.as_raw_fd(), &leaf)?;
            if unsafe {
                libc::renameat(
                    stage.fd.as_raw_fd(),
                    name.as_ptr(),
                    parent.as_raw_fd(),
                    leaf.as_ptr(),
                )
            } != 0
            {
                return Err(());
            }
            Ok(())
        })();
        unsafe {
            libc::unlinkat(stage.fd.as_raw_fd(), name.as_ptr(), 0);
        }
        result
    }
    pub(super) fn operate(input: &Input, bytes: &[u8], install: bool) -> Result<()> {
        validate(input, bytes)?;
        let parent = destination(input, install)?;
        if install {
            write_anchored(input, bytes, &parent.ok_or(())?)?;
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::{symlink, PermissionsExt};
        struct Fixture(std::path::PathBuf);
        impl Fixture {
            fn new() -> Self {
                let path = std::env::temp_dir().join(random_name());
                std::fs::create_dir(&path).unwrap();
                Self(path)
            }
            fn input(&self) -> Input {
                Input {
                    home: self.0.clone(),
                    owner_uid: unsafe { libc::geteuid() },
                    owner_gid: unsafe { libc::getegid() },
                    leaf: "NOTICE".into(),
                    expected_sha256: format!("{:x}", Sha256::digest(b"public notice\n")),
                }
            }
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        const BYTES: &[u8] = b"public notice\n";
        #[test]
        fn public_text_install_and_atomic_replacement() {
            let fixture = Fixture::new();
            let input = fixture.input();
            operate(&input, BYTES, false).unwrap();
            assert!(!fixture.0.join(".local").exists());
            operate(&input, BYTES, true).unwrap();
            let leaf = fixture.0.join(".local/share/doc/aegis/NOTICE");
            let first = std::fs::metadata(&leaf).unwrap();
            assert_eq!(std::fs::read(&leaf).unwrap(), BYTES);
            assert_eq!(first.permissions().mode() & 0o777, 0o644);
            operate(&input, BYTES, true).unwrap();
            use std::os::unix::fs::MetadataExt;
            assert_ne!(first.ino(), std::fs::metadata(&leaf).unwrap().ino());
        }
        #[test]
        fn wrong_hash_owner_or_leaf_refuses_before_creation() {
            let fixture = Fixture::new();
            let mut input = fixture.input();
            input.expected_sha256 = "0".repeat(64);
            assert!(operate(&input, BYTES, true).is_err());
            input = fixture.input();
            input.owner_uid = input.owner_uid.wrapping_add(1);
            assert!(operate(&input, BYTES, true).is_err());
            assert!(base(&fixture.0, input.owner_uid).is_err());
            input = fixture.input();
            input.leaf = "../NOTICE".into();
            assert!(operate(&input, BYTES, true).is_err());
            assert!(!fixture.0.join(".local").exists());
        }
        #[test]
        fn source_bytes_bound_and_existing_metadata_preserved() {
            let fixture = Fixture::new();
            let input = fixture.input();
            std::fs::create_dir(fixture.0.join(".local")).unwrap();
            std::fs::set_permissions(
                fixture.0.join(".local"),
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            assert!(operate(&input, &vec![0; 65537], true).is_err());
            assert!(operate(&input, b"", true).is_err());
            operate(&input, BYTES, true).unwrap();
            assert_eq!(
                std::fs::metadata(fixture.0.join(".local"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        #[test]
        fn suffix_symlink_and_hardlinked_leaf_preserve_victim() {
            let fixture = Fixture::new();
            let outside = Fixture::new();
            let input = fixture.input();
            let victim = outside.0.join("NOTICE");
            std::fs::write(&victim, b"private victim").unwrap();
            symlink(&outside.0, fixture.0.join(".local")).unwrap();
            assert!(operate(&input, BYTES, false).is_err());
            assert!(operate(&input, BYTES, true).is_err());
            std::fs::remove_file(fixture.0.join(".local")).unwrap();
            operate(&input, BYTES, true).unwrap();
            let leaf = fixture.0.join(".local/share/doc/aegis/NOTICE");
            std::fs::remove_file(&leaf).unwrap();
            symlink(&victim, &leaf).unwrap();
            assert!(operate(&input, BYTES, true).is_err());
            std::fs::remove_file(&leaf).unwrap();
            std::fs::hard_link(&victim, &leaf).unwrap();
            assert!(operate(&input, BYTES, true).is_err());
            assert_eq!(std::fs::read(victim).unwrap(), b"private victim");
        }
        #[test]
        fn held_parent_survives_rename_and_symlink_substitution() {
            let fixture = Fixture::new();
            let outside = Fixture::new();
            let input = fixture.input();
            operate(&input, BYTES, true).unwrap();
            let parent = destination(&input, false).unwrap().unwrap();
            let path = fixture.0.join(".local/share/doc/aegis");
            let moved = fixture.0.join("retained");
            std::fs::rename(&path, &moved).unwrap();
            symlink(&outside.0, &path).unwrap();
            std::fs::write(outside.0.join("NOTICE"), b"private victim").unwrap();
            write_anchored(&input, BYTES, &parent).unwrap();
            assert_eq!(std::fs::read(moved.join("NOTICE")).unwrap(), BYTES);
            assert_eq!(
                std::fs::read(outside.0.join("NOTICE")).unwrap(),
                b"private victim"
            );
        }
        #[test]
        fn exclusive_directory_publish_preserves_existing_destination() {
            let fixture = Fixture::new();
            let input = fixture.input();
            let parent = base(&fixture.0, input.owner_uid).unwrap();
            std::fs::create_dir(fixture.0.join("taken")).unwrap();
            std::fs::write(fixture.0.join("taken/victim"), b"preserved").unwrap();
            let stage = Stage::new().unwrap();
            assert!(stage
                .publish_directory(
                    parent.as_raw_fd(),
                    &c("taken").unwrap(),
                    input.owner_uid,
                    input.owner_gid
                )
                .is_err());
            assert_eq!(
                std::fs::read(fixture.0.join("taken/victim")).unwrap(),
                b"preserved"
            );
        }
    }
}
