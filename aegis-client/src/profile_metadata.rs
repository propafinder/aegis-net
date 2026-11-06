//! Administrator-owned filesystem boundary for install and rollback metadata.
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

pub(super) fn administrative_uid() -> u32 {
    #[cfg(unix)]
    {
        // SAFETY: geteuid only reads the calling process identity.
        unsafe { libc::geteuid() }
    }
    #[cfg(not(unix))]
    {
        1
    }
}

/// Root planning must not read or write through a directory the runtime UID
/// controls. Once all ancestors are checked, unprivileged processes cannot
/// replace the path while this administrator creates an atomic record.
fn metadata_path(path: &Path, create: bool) -> io::Result<PathBuf> {
    let path = path.to_path_buf();
    #[cfg(target_os = "macos")]
    let path = {
        if let Some(text) = path.to_str().filter(|text| {
            ["/var/", "/tmp/", "/etc/"]
                .iter()
                .any(|p| text.starts_with(p))
        }) {
            PathBuf::from(format!("/private{text}"))
        } else {
            path
        }
    };
    if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(io::Error::other(
            "Installation metadata requires an absolute path",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("Missing metadata parent"))?;
    let mut checked = PathBuf::new();
    for component in parent.components() {
        if let Component::Normal(name) = component {
            checked.push(name);
            if create {
                #[cfg(not(windows))]
                let created = std::fs::create_dir(&checked);
                #[cfg(windows)]
                let created =
                    aegis_core::windows_file::create_private_directory(&checked, false, false);
                match created {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e),
                }
            }
            let metadata = std::fs::symlink_metadata(&checked)?;
            if !metadata.is_dir() {
                return Err(io::Error::other(
                    "Installation metadata directory must not be a link",
                ));
            }
            #[cfg(windows)]
            aegis_core::windows_file::trusted_directory(&checked)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let sticky_ancestor =
                    checked != parent && metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
                if ![0, administrative_uid()].contains(&metadata.uid())
                    || (metadata.mode() & 0o022 != 0 && !sticky_ancestor)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Runtime-owned installation metadata is not authoritative",
                    ));
                }
            }
        } else {
            checked.push(component.as_os_str());
        }
    }
    Ok(path)
}

pub(crate) fn read_install_metadata(path: &Path) -> io::Result<String> {
    let path = metadata_path(path, false)?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        aegis_core::windows_file::reject_reparse_ancestry(&path)?;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    #[cfg(windows)]
    aegis_core::windows_file::validate_private(&file, true)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > 65536 {
        return Err(io::Error::other(
            "Installation metadata must be a bounded regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if ![0, administrative_uid()].contains(&metadata.uid())
            || metadata.mode() & 0o022 != 0
            || metadata.nlink() != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Untrusted installation metadata",
            ));
        }
    }
    let mut text = String::new();
    file.take(65537).read_to_string(&mut text)?;
    if text.len() > 65536 {
        return Err(io::Error::other(
            "Installation metadata exceeds its size limit",
        ));
    }
    Ok(text)
}

pub(super) fn write_install_metadata(path: &Path, text: &str) -> io::Result<()> {
    write_record(path, text, 0o644, false)
}

pub(super) fn write_record(path: &Path, text: &str, mode: u32, preserve: bool) -> io::Result<()> {
    write_record_checked(path, text, mode, preserve, false)
}

pub(super) fn create_record(path: &Path, text: &str, mode: u32) -> io::Result<()> {
    write_record_checked(path, text, mode, false, true)
}

#[cfg(not(windows))]
fn persist_record(
    temporary: tempfile::NamedTempFile,
    path: &Path,
    exclusive: bool,
) -> io::Result<()> {
    if exclusive {
        temporary
            .persist_noclobber(path)
            .map_err(|error| error.error)?;
    } else {
        temporary.persist(path).map_err(|error| error.error)?;
    }
    Ok(())
}

fn write_record_checked(
    path: &Path,
    text: &str,
    mode: u32,
    preserve: bool,
    exclusive: bool,
) -> io::Result<()> {
    if exclusive && preserve {
        return Err(io::Error::other(
            "exclusive create cannot preserve an existing file",
        ));
    }
    #[cfg(not(unix))]
    let _ = (mode, preserve);
    if text.len() > 65536 {
        return Err(io::Error::other(
            "Installation metadata exceeds its size limit",
        ));
    }
    let path = metadata_path(path, true)?;
    if exclusive {
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "exclusive metadata target already exists",
                ))
            }
        }
    }
    match read_install_metadata(&path) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let parent = path.parent().unwrap();
    #[cfg(windows)]
    {
        let _ = parent;
        if exclusive {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "exclusive selected metadata creation requires Unix",
            ));
        }
        aegis_core::windows_file::atomic_write_private(&path, text.as_bytes(), true, false)
    }
    #[cfg(not(windows))]
    {
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        temporary.write_all(text.as_bytes())?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let mut mode = mode;
            if preserve {
                let original = std::fs::symlink_metadata(&path)?;
                mode = original.mode() & 0o777;
                // Ancestors and the existing regular file were validated above.
                // Keep the administrator UID while preserving service read access.
                if unsafe {
                    libc::fchown(
                        temporary.as_file().as_raw_fd(),
                        administrative_uid(),
                        original.gid(),
                    )
                } != 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
            temporary
                .as_file()
                .set_permissions(std::fs::Permissions::from_mode(mode))?;
        }
        temporary.as_file().sync_all()?;
        persist_record(temporary, &path, exclusive)?;
        std::fs::File::open(parent)?.sync_all()
    }
}

/// Content-addressed immutable selected-profile evidence. Existing bytes are
/// accepted only if identical; an operational retry cannot replace a failure.
pub(super) fn archive_relay_geneva_record(text: &str) -> io::Result<()> {
    use sha2::{Digest, Sha256};
    if text.len() > 65536 {
        return Err(io::Error::other("selected evidence bound"));
    }
    let digest = hex::encode(Sha256::digest(text.as_bytes()));
    let path = metadata_path(
        &PathBuf::from("/var/lib/aegis-install/client/relay-geneva-history")
            .join(format!("{digest}.json")),
        true,
    )?;
    let parent = path.parent().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    match read_install_metadata(&path) {
        Ok(old) if old == text => return Ok(()),
        Ok(_) => return Err(io::Error::other("selected immutable evidence differs")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    temporary.write_all(text.as_bytes())?;
    temporary.as_file().sync_all()?;
    if let Err(error) = temporary.persist_noclobber(&path) {
        if error.error.kind() != io::ErrorKind::AlreadyExists
            || read_install_metadata(&path)? != text
        {
            return Err(error.error);
        }
    }
    std::fs::File::open(parent)?.sync_all()
}
#[derive(clap::Args, Clone, Debug)]
pub struct MetadataArgs {
    #[command(subcommand)]
    action: Action,
}

#[derive(clap::Subcommand, Clone, Debug)]
enum Action {
    Validate {
        #[arg(long)]
        path: PathBuf,
    },
    Read {
        #[arg(long)]
        path: PathBuf,
    },
    Write {
        #[arg(long)]
        path: PathBuf,
        #[arg(long, default_value = "0600", value_parser = ["0600", "0640", "0644"])]
        mode: String,
        #[arg(long)]
        preserve_mode: bool,
        /// Refuse an existing target atomically, including concurrent creation.
        #[arg(long)]
        exclusive: bool,
    },
    Remove {
        #[arg(long)]
        path: PathBuf,
    },
    ResolverCheck {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        snapshot: PathBuf,
    },
    ResolverSave {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        snapshot: PathBuf,
    },
    ResolverRestore {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        snapshot: PathBuf,
    },
}

fn validate(path: &Path) -> io::Result<PathBuf> {
    let path = metadata_path(path, true)?;
    match read_install_metadata(&path) {
        Ok(_) => Ok(path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(path),
        Err(e) => Err(e),
    }
}

pub(super) fn remove(path: &Path) -> io::Result<()> {
    let path = validate(path)?;
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Resolver {
    File { contents: String },
    Link { target: PathBuf },
    Absent,
}

fn safe_resolver_link(target: &Path) -> bool {
    matches!(
        target.to_str(),
        Some(
            "../run/systemd/resolve/stub-resolv.conf"
                | "/run/systemd/resolve/stub-resolv.conf"
                | "../run/systemd/resolve/resolv.conf"
                | "/run/systemd/resolve/resolv.conf"
                | "../run/NetworkManager/resolv.conf"
                | "/run/NetworkManager/resolv.conf"
                | "../run/resolvconf/resolv.conf"
                | "/run/resolvconf/resolv.conf"
        )
    )
}

fn resolver_current(path: &Path) -> io::Result<Resolver> {
    let path = metadata_path(path, false)?;
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Resolver::Absent),
        Err(e) => Err(e),
        Ok(info) if info.file_type().is_symlink() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if info.uid() != administrative_uid() || info.nlink() != 1 {
                    return Err(io::Error::other("Untrusted resolver link owner"));
                }
            }
            let target = std::fs::read_link(path)?;
            if !safe_resolver_link(&target) {
                return Err(io::Error::other(
                    "Resolver link requires explicit operator migration",
                ));
            }
            Ok(Resolver::Link { target })
        }
        Ok(_) => read_install_metadata(&path).map(|contents| Resolver::File { contents }),
    }
}

fn load_resolver(snapshot: &Path) -> io::Result<Resolver> {
    let value: Resolver = serde_json::from_str(&read_install_metadata(snapshot)?)?;
    if let Resolver::Link { ref target } = value {
        if !safe_resolver_link(target) {
            return Err(io::Error::other("Untrusted resolver snapshot target"));
        }
    }
    Ok(value)
}

fn resolver_check(path: &Path, snapshot: &Path) -> io::Result<()> {
    validate(snapshot)?;
    resolver_current(path)?;
    if snapshot.exists() {
        load_resolver(snapshot)?;
    }
    Ok(())
}

fn restore_resolver(path: &Path, snapshot: &Path) -> io::Result<()> {
    resolver_check(path, snapshot)?;
    if !snapshot.exists() {
        return Ok(());
    }
    let value = load_resolver(snapshot)?;
    let path = metadata_path(path, false)?;
    let parent = path.parent().unwrap();
    let scratch = tempfile::tempdir_in(parent)?;
    let next = scratch.path().join("resolver");
    match value {
        Resolver::Absent => match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        },
        Resolver::File { contents } => {
            write_record(&next, &contents, 0o644, false)?;
            std::fs::rename(&next, &path)?;
        }
        Resolver::Link { target } => {
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(target, &next)?;
                std::fs::rename(&next, &path)?;
            }
            #[cfg(not(unix))]
            {
                let _ = target;
                return Err(io::Error::other("Resolver links require Unix"));
            }
        }
    }
    std::fs::File::open(parent)?.sync_all()?;
    remove(snapshot)
}

pub fn run(args: &MetadataArgs) -> io::Result<()> {
    match &args.action {
        Action::Validate { path } => {
            validate(path)?;
        }
        Action::Read { path } => {
            io::stdout().write_all(read_install_metadata(path)?.as_bytes())?;
        }
        Action::Write {
            path,
            mode,
            preserve_mode,
            exclusive,
        } => {
            let mut text = String::new();
            io::stdin().take(65537).read_to_string(&mut text)?;
            write_record_checked(
                path,
                &text,
                u32::from_str_radix(mode, 8).unwrap(),
                *preserve_mode,
                *exclusive,
            )?;
        }
        Action::Remove { path } => remove(path)?,
        Action::ResolverCheck { path, snapshot } => resolver_check(path, snapshot)?,
        Action::ResolverSave { path, snapshot } => {
            resolver_check(path, snapshot)?;
            if !snapshot.exists() {
                write_record(
                    snapshot,
                    &serde_json::to_string(&resolver_current(path)?)?,
                    0o600,
                    false,
                )?;
            }
        }
        Action::ResolverRestore { path, snapshot } => restore_resolver(path, snapshot)?,
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    #[test]
    fn exclusive_commit_refuses_concurrent_created_file_without_replacing_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("selected-helper");
        assert!(std::fs::symlink_metadata(&path).is_err());
        let mut prepared = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
        prepared.write_all(b"new owned helper").unwrap();
        prepared.as_file().sync_all().unwrap();
        // A competing creator wins after the absence check, before our commit.
        std::fs::write(&path, b"concurrent administrator bytes").unwrap();
        let inode = std::fs::metadata(&path).unwrap().ino();
        let error = persist_record(prepared, &path, true).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"concurrent administrator bytes"
        );
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
        assert!(create_record(&path, "refused", 0o600).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn records_reject_unsafe_files_and_preserve_read_group() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_record(&path, "token=\"fixture\"", 0o640, false).unwrap();
        let before = std::fs::metadata(&path).unwrap();
        write_record(&path, "updated", 0o600, true).unwrap();
        let after = std::fs::metadata(&path).unwrap();
        assert_eq!(before.gid(), after.gid());
        assert_eq!(after.mode() & 0o777, 0o640);
        assert_ne!(before.ino(), after.ino());
        std::fs::hard_link(&path, dir.path().join("hardlink")).unwrap();
        assert!(validate(&path).is_err());
        assert!(remove(&path).is_err());
        assert!(write_record(&path, "invalid", 0o600, false).is_err());
        std::fs::remove_file(dir.path().join("hardlink")).unwrap();
        let link = dir.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(validate(&link).is_err());
        assert!(remove(&link).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read_install_metadata(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn resolver_snapshot_is_private_data_and_preserves_managed_link() {
        let dir = tempfile::tempdir().unwrap();
        let resolver = dir.path().join("resolv.conf");
        let snapshot = dir.path().join("root").join("resolver.json");
        symlink("../run/systemd/resolve/stub-resolv.conf", &resolver).unwrap();
        let original = resolver_current(&resolver).unwrap();
        write_record(
            &snapshot,
            &serde_json::to_string(&original).unwrap(),
            0o600,
            false,
        )
        .unwrap();
        assert_eq!(std::fs::metadata(&snapshot).unwrap().mode() & 0o777, 0o600);
        assert!(!std::fs::symlink_metadata(&snapshot)
            .unwrap()
            .file_type()
            .is_symlink());
        std::fs::remove_file(&resolver).unwrap();
        write_record(&resolver, "nameserver 127.0.0.1\n", 0o644, false).unwrap();
        restore_resolver(&resolver, &snapshot).unwrap();
        assert_eq!(
            std::fs::read_link(&resolver).unwrap(),
            PathBuf::from("../run/systemd/resolve/stub-resolv.conf")
        );
        assert!(!snapshot.exists());
        std::fs::remove_file(&resolver).unwrap();
        symlink("/etc/shadow", &resolver).unwrap();
        assert!(resolver_current(&resolver).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn resolver_rejects_poisoned_snapshot_without_changing_current_file() {
        let dir = tempfile::tempdir().unwrap();
        let resolver = dir.path().join("resolv.conf");
        let snapshot = dir.path().join("snapshot.json");
        write_record(&resolver, "nameserver 127.0.0.1\n", 0o644, false).unwrap();
        write_record(
            &snapshot,
            r#"{"kind":"Link","target":"/etc/shadow"}"#,
            0o600,
            false,
        )
        .unwrap();
        assert!(restore_resolver(&resolver, &snapshot).is_err());
        assert_eq!(
            read_install_metadata(&resolver).unwrap(),
            "nameserver 127.0.0.1\n"
        );
        std::fs::remove_file(&snapshot).unwrap();
        symlink(&resolver, &snapshot).unwrap();
        assert!(restore_resolver(&resolver, &snapshot).is_err());
        assert!(read_install_metadata(&resolver).is_ok());
    }
}
