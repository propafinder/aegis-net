//! Bounded build-side public artifact custody; no interpreter or execution.
use std::{io, path::Path};
#[cfg(unix)]
fn parent_error(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
/// Build-side public operator artifacts: descriptor custody without interpreting
/// executable contents or executing an input. Does not relax secret reads.
#[cfg(unix)]
pub fn read_operator_artifact(
    path: &Path,
    max_bytes: u64,
    executable: bool,
) -> io::Result<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    if max_bytes == 0 || max_bytes > 512 * 1024 * 1024 {
        return Err(parent_error("operator capacity refused"));
    }
    let parent = crate::secret_file::trusted_parent(path)?;
    let name = path
        .file_name()
        .ok_or_else(|| parent_error("operator file name"))?;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(parent.join(name))?;
    let before = file.metadata()?;
    // SAFETY: geteuid only reads process identity.
    let uid = unsafe { libc::geteuid() };
    if !before.is_file()
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > max_bytes
        || (before.uid() != 0 && before.uid() != uid)
        || before.mode() & 0o022 != 0
        || (executable && before.mode() & 0o111 == 0)
    {
        return Err(parent_error("operator descriptor refused"));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 != before.len()
        || bytes.len() as u64 > max_bytes
        || (
            before.dev(),
            before.ino(),
            before.len(),
            before.mode(),
            before.uid(),
            before.gid(),
            before.nlink(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.mode(),
            after.uid(),
            after.gid(),
            after.nlink(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        )
    {
        return Err(parent_error("operator descriptor changed"));
    }
    Ok(bytes)
}
#[cfg(not(unix))]
pub fn read_operator_artifact(
    _path: &Path,
    _max_bytes: u64,
    _executable: bool,
) -> io::Result<Vec<u8>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Linux operator artifact descriptor custody requires Unix",
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires isolated Linux root; CI invokes explicitly"]
    fn linux_root_rejects_foreign_ancestor_and_accepts_isolated_output() {
        use std::ffi::CString;
        use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
        // SAFETY: geteuid only reads process identity. Never silently pass when
        // this explicit native contract is accidentally invoked without root.
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let foreign = root.path().join("foreign-runner");
        let leaf = foreign.join("root-built-bundle");
        std::fs::create_dir(&foreign).unwrap();
        std::fs::create_dir(&leaf).unwrap();
        for directory in [&foreign, &leaf] {
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let artifact = leaf.join("operator");
        std::fs::write(&artifact, b"inert artifact").unwrap();
        std::fs::set_permissions(&artifact, std::fs::Permissions::from_mode(0o700)).unwrap();
        let foreign_name = CString::new(foreign.as_os_str().as_bytes()).unwrap();
        // SAFETY: this live NUL-terminated path names only our synthetic fixture.
        assert_eq!(
            unsafe { libc::chown(foreign_name.as_ptr(), 65534, 65534) },
            0
        );
        assert_eq!(std::fs::metadata(&foreign).unwrap().uid(), 65534);
        assert_eq!(std::fs::metadata(&leaf).unwrap().uid(), 0);
        assert_eq!(std::fs::metadata(&artifact).unwrap().uid(), 0);
        let refusal = read_operator_artifact(&artifact, 14, true).unwrap_err();
        assert_eq!(refusal.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            refusal.to_string(),
            "enrollment directory ancestry has an untrusted owner"
        );
        let isolated = root.path().join("isolated-output");
        std::fs::create_dir(&isolated).unwrap();
        std::fs::set_permissions(&isolated, std::fs::Permissions::from_mode(0o700)).unwrap();
        let accepted = isolated.join("operator");
        std::fs::write(&accepted, b"inert artifact").unwrap();
        std::fs::set_permissions(&accepted, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            read_operator_artifact(&accepted, 14, true).unwrap(),
            b"inert artifact"
        );
        assert_eq!(std::fs::read(&artifact).unwrap(), b"inert artifact");
    }
    #[test]
    fn actual_regular_executable_is_read_from_checked_descriptor() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("tool");
        std::fs::write(&path, b"inert artifact").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            read_operator_artifact(&path, 14, true).unwrap(),
            b"inert artifact"
        );
        assert!(read_operator_artifact(&path, 13, true).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"inert artifact");
    }
    #[test]
    fn actual_links_nonexecutables_and_writable_owner_paths_refuse() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("tool");
        std::fs::write(&path, b"inert artifact").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_operator_artifact(&path, 14, true).is_err());
        let link = root.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(read_operator_artifact(&link, 14, false).is_err());
        let hard = root.path().join("hard");
        std::fs::hard_link(&path, &hard).unwrap();
        assert!(read_operator_artifact(&path, 14, false).is_err());
        std::fs::remove_file(&hard).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read_operator_artifact(&path, 14, false).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(read_operator_artifact(&path, 14, false).is_err());
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}
