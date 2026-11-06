//! Actual lexical credential-path policy shared by binary and relay library.
//! This leaf does not read a secret, attest credential custody or admit a device.
//! Core load_credential retains the trusted-parent/permission/reparse reader.
use anyhow::{ensure, Result};
use std::path::Path;

pub fn clean_absolute_directory(path: &Path) -> bool {
    #[cfg(windows)]
    let root_components = {
        use std::path::{Component, Prefix};
        let mut parts = path.components();
        if !matches!(parts.next(), Some(Component::Prefix(p))
            if matches!(p.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
            || !matches!(parts.next(), Some(Component::RootDir))
        {
            return false;
        }
        2
    };
    #[cfg(not(windows))]
    let root_components = 1;
    path.is_absolute()
        && path.parent().is_some()
        && path.components().skip(root_components).all(|c| match c {
            std::path::Component::Normal(name) => {
                // Win32 aliases (ADS and stripped trailing dots/spaces)
                // must not bypass the identity/config separation checks.
                !cfg!(windows)
                    || (!name.as_encoded_bytes().contains(&b':')
                        && !matches!(name.as_encoded_bytes().last(), Some(b'.' | b' ')))
            }
            _ => false,
        })
        && !path
            .as_os_str()
            .as_encoded_bytes()
            .split(|b| *b == b'/' || (cfg!(windows) && *b == b'\\'))
            .any(|component| component == b"." || component == b"..")
}

pub fn validate_https_bridge_credential_file(
    bridge: &aegis_core::https_bridge::ClientSettings,
) -> Result<()> {
    bridge
        .validate()
        .map_err(|_| anyhow::anyhow!("HTTPS bridge policy rejected"))?;
    ensure!(
        clean_absolute_directory(&bridge.credential_file),
        "HTTPS bridge credential rejected"
    );
    ensure!(
        bridge
            .credential_file
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| !["device.key", "device.pem", "https-bridge.toml"]
                .iter()
                .any(|reserved| name.eq_ignore_ascii_case(reserved))),
        "HTTPS bridge credential rejected"
    );
    // A second hard-link name must not alias a device key or certificate.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::symlink_metadata(&bridge.credential_file)
            .map_err(|_| anyhow::anyhow!("HTTPS bridge credential rejected"))?;
        ensure!(
            metadata.is_file() && metadata.nlink() == 1,
            "HTTPS bridge credential rejected"
        );
    }
    Ok(())
}
