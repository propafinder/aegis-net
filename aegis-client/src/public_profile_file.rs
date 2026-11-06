//! Shared public four-member profile input and digest mechanics.
//! Digest equality alone does not validate profile policy or authorize a device.
use aegis_core::secure_channel::enrollment;
use anyhow::{ensure, Result};
use sha2::{Digest, Sha256};
use std::{fs::OpenOptions, io::Read, path::Path};

pub const MEMBERS: [&str; 4] = [
    "bundle.json",
    "outer-ca.pem",
    "inner-ca.pem",
    "device-ca.pem",
];
pub const MAX_PUBLIC_BYTES: u64 = 64 * 1024;

pub fn read_public(path: &Path) -> Result<Vec<u8>> {
    enrollment::trusted_parent(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        aegis_core::windows_file::reject_reparse_ancestry(path)?;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    #[cfg(windows)]
    aegis_core::windows_file::validate_private(&file, true)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= MAX_PUBLIC_BYTES,
        "public bundle file must be bounded and regular"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid only reads the effective process identity.
        let uid = unsafe { libc::geteuid() };
        ensure!(
            (metadata.uid() == 0 || metadata.uid() == uid)
                && metadata.mode() & 0o022 == 0
                && metadata.nlink() == 1,
            "public bundle file ownership, permissions or link count rejected"
        );
    }
    let mut bytes = Vec::new();
    file.take(MAX_PUBLIC_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_PUBLIC_BYTES,
        "public bundle file too large"
    );
    ensure!(
        !bytes
            .windows(b"PRIVATE KEY".len())
            .any(|v| v == b"PRIVATE KEY"),
        "private key material is forbidden in public bundles"
    );
    Ok(bytes)
}

pub fn profile_digest_bytes(payload: &[Vec<u8>; 4]) -> String {
    let mut digest = Sha256::new();
    for (member, bytes) in MEMBERS.into_iter().zip(payload) {
        digest.update(member.as_bytes());
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
    }
    hex::encode(digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn four_member_digest_binds_member_bytes_and_order() {
        let original = [
            b"profile".to_vec(),
            b"outer".to_vec(),
            b"inner".to_vec(),
            b"device".to_vec(),
        ];
        let first = profile_digest_bytes(&original);
        assert_eq!(first.len(), 64);
        assert_eq!(first, profile_digest_bytes(&original));
        let mut changed = original.clone();
        changed[1] = b"outer2".to_vec();
        assert_ne!(first, profile_digest_bytes(&changed));
        changed = original.clone();
        changed.swap(1, 2);
        assert_ne!(first, profile_digest_bytes(&changed));
    }
}
