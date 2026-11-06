//! Bounded, descriptor-checked reads of local secrets. Parent directories are
//! part of the operator's trust boundary; final symlinks are never followed.
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

fn parent_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(not(any(unix, windows)))]
pub fn trusted_parent(_path: &Path) -> io::Result<PathBuf> {
    Err(io::Error::new(io::ErrorKind::Unsupported,
        "device enrollment file mutations require Unix permission enforcement; Windows ACL support is not implemented"))
}

#[cfg(unix)]
pub fn trusted_parent(path: &Path) -> io::Result<PathBuf> {
    checked_parent(path, true)
}
#[cfg(windows)]
pub fn trusted_parent(path: &Path) -> io::Result<PathBuf> {
    checked_parent(path, true)
}

/// Files are flushed before publishing. Windows publication uses the native
/// write-through rename; directory fsync itself has no Win32 equivalent.
pub fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(path)?.sync_all()
    }
    #[cfg(windows)]
    {
        crate::windows_file::trusted_directory(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// Validate parent ancestry for a root-owned registry read by a service UID.
pub fn trusted_read_parent(path: &Path) -> io::Result<PathBuf> {
    checked_parent(path, false)
}

/// Create an owner-private artifact without replacing an earlier attempt.
/// This is the enrollment writer's existing implementation, available without
/// the device-enrollment cryptographic feature.
pub fn write_private_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = trusted_parent(path)?;
    let path = parent.join(
        path.file_name()
            .ok_or_else(|| parent_error("enrollment output needs a file name"))?,
    );
    #[cfg(not(windows))]
    let mut options = std::fs::OpenOptions::new();
    #[cfg(not(windows))]
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(not(windows))]
    let mut file = options.open(&path)?;
    #[cfg(windows)]
    let mut file = crate::windows_file::create_private_file(&path, false)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    // The registry can commit on a different filesystem. Persist the output's
    // directory entry before its invitation/certificate becomes durable there.
    sync_directory(&parent)
}

fn checked_parent(path: &Path, operator_owned: bool) -> io::Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let absolute = if parent.is_absolute() {
        parent.to_owned()
    } else {
        std::env::current_dir()?.join(parent)
    };
    let canonical = absolute.canonicalize()?;
    #[cfg(windows)]
    crate::windows_file::trusted_directory(&absolute)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid reads process identity without pointer arguments.
        let uid = unsafe { libc::geteuid() };
        // Check both the user-supplied ancestry and the resolved ancestry. A
        // root-owned leaf directory below another UID's writable directory is
        // not a trusted root writer destination. Root-owned sticky temp roots
        // are permitted: their already checked private child cannot be renamed
        // by another UID. Symlinks are accepted only from trusted owners.
        for ancestor in absolute.ancestors().chain(canonical.ancestors()) {
            let metadata = std::fs::symlink_metadata(ancestor)?;
            if metadata.uid() != 0 && metadata.uid() != uid {
                return Err(parent_error(
                    "enrollment directory ancestry has an untrusted owner",
                ));
            }
            let sticky_root =
                metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
            if !metadata.file_type().is_symlink() && metadata.mode() & 0o022 != 0 && !sticky_root {
                return Err(parent_error(
                    "enrollment directory ancestry permits untrusted writes",
                ));
            }
        }
        let metadata = std::fs::metadata(&canonical)?;
        if (metadata.uid() != uid && (operator_owned || metadata.uid() != 0))
            || metadata.mode() & 0o022 != 0
        {
            return Err(parent_error("enrollment output directory must belong to the operator and deny group/other writes"));
        }
    }
    #[cfg(not(unix))]
    let _ = operator_owned;
    if !canonical.is_dir() {
        return Err(parent_error(
            "enrollment output requires an existing trusted directory",
        ));
    }
    Ok(canonical)
}

pub fn read(path: &Path, max_bytes: u64) -> io::Result<Zeroizing<Vec<u8>>> {
    read_with_policy(path, max_bytes, false)
}

/// A root-owned config may be readable by the service's primary group. The
/// service cannot modify it; world access and group writes remain forbidden.
pub fn read_config(path: &Path, max_bytes: u64) -> io::Result<Zeroizing<Vec<u8>>> {
    read_with_policy(path, max_bytes, true)
}

fn read_with_policy(
    path: &Path,
    max_bytes: u64,
    service_group: bool,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        };
        crate::windows_file::reject_reparse_ancestry(path)?;
        options
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    #[cfg(windows)]
    crate::windows_file::validate_private(&file, service_group)?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secret must be a bounded regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no pointer arguments or ownership effects.
        let uid = unsafe { libc::geteuid() };
        // SAFETY: getegid only reads the process's primary effective group.
        let gid = unsafe { libc::getegid() };
        let allowed_group =
            service_group && metadata.uid() == 0 && (uid == 0 || metadata.gid() == gid);
        let forbidden = if allowed_group { 0o037 } else { 0o077 };
        if (metadata.uid() != 0 && metadata.uid() != uid) || metadata.mode() & forbidden != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "secret requires owner-only access or a root-owned service-group config (0640)",
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = service_group;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secret exceeds size limit",
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    #[test]
    fn private_writer_is_available_without_enrollment_and_preserves_prior_output() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("report.json");
        super::write_private_new(&output, b"synthetic report").unwrap();
        assert_eq!(&**super::read(&output, 64).unwrap(), b"synthetic report");
        assert!(super::write_private_new(&output, b"replacement").is_err());
        assert_eq!(&**super::read(&output, 64).unwrap(), b"synthetic report");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(output).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn private_writer_rejects_output_symlink_and_writable_ancestry() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("preserved");
        super::write_private_new(&target, b"preserve").unwrap();
        let output = directory.path().join("link");
        symlink(&target, &output).unwrap();
        assert!(super::write_private_new(&output, b"replacement").is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"preserve");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let output = directory.path().join("blocked");
        assert!(super::write_private_new(&output, b"refused").is_err());
        assert!(!output.exists());
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn private_regular_file_is_bounded() {
        use std::io::Write;
        let directory = tempfile::tempdir().unwrap();
        #[cfg(windows)]
        let mut file = tempfile::Builder::new()
            .make_in(directory.path(), |path| {
                crate::windows_file::create_private_file(path, false)
            })
            .unwrap();
        #[cfg(not(windows))]
        let mut file = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
        file.write_all(b"synthetic secret").unwrap();
        // Release the write handle before exercising the restrictive reader.
        let path = file.into_temp_path();
        assert_eq!(&**super::read(&path, 16).unwrap(), b"synthetic secret");
        assert!(super::read(&path, 3).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn relaxed_permissions_are_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o644))
            .unwrap();
        assert_eq!(
            super::read(file.path(), 64).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }
}
