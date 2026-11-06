//! Shared private-file validation for the installed device Store.
//! This is a file boundary only: no certificate, issuance or ACK authority.
use anyhow::{ensure, Result};
use std::{fs, path::Path};

pub const MAX_INPUT: u64 = 64 * 1024;

pub fn validate_file(metadata: &fs::Metadata) -> Result<()> {
    ensure!(
        metadata.is_file() && metadata.len() <= MAX_INPUT,
        "device enrollment input must be a bounded regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid only reads process identity.
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o077 == 0
                && metadata.nlink() == 1,
            "device enrollment file ownership, links or permissions invalid"
        );
    }
    Ok(())
}

pub fn read_private(path: &Path) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    validate_file(&fs::symlink_metadata(path)?)?;
    Ok(aegis_core::secret_file::read(path, MAX_INPUT)?)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{fs::File, io::Write, os::unix::fs::PermissionsExt};

    #[test]
    fn private_reader_refuses_link_alias_and_group_access() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("device.pem");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"example-private-input").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_private(&path).unwrap().as_slice(),
            b"example-private-input"
        );

        let link = directory.path().join("alias.pem");
        fs::hard_link(&path, &link).unwrap();
        assert!(read_private(&path).is_err());
        fs::remove_file(&link).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(read_private(&path).is_err());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let alias = directory.path().join("symlink.pem");
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        assert!(read_private(&alias).is_err());
    }

    #[test]
    fn private_reader_refuses_oversize_input() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("device.pem");
        fs::write(&path, vec![b'x'; MAX_INPUT as usize + 1]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_private(&path).is_err());
    }
}
