//! Held web-response private policy prerequisites. This module grants no carrier.
use aegis_core::web_response_profile::WebResponseSettings;
use std::{io, path::Path};
use zeroize::Zeroizing;

fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "web-response custody refused",
    )
}

/// Parse one retained private sidecar and identify only a direct child leaf.
/// The caller opens that leaf through the already-held identity directory fd.
pub(crate) fn admit_sidecar(
    bytes: &[u8],
    held_identity_path: &Path,
) -> io::Result<(WebResponseSettings, String)> {
    let input = std::str::from_utf8(bytes).map_err(|_| refused())?;
    let mut settings: WebResponseSettings = toml::from_str(input).map_err(|_| refused())?;
    settings.validate().map_err(|_| refused())?;
    let file = settings.credential_file.as_path();
    let parent = file.parent().ok_or_else(refused)?;
    if parent != held_identity_path
        && !std::fs::canonicalize(parent).is_ok_and(|real| real == held_identity_path)
    {
        return Err(refused());
    }
    let leaf = file
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(refused)?;
    const RESERVED: &[&str] = &[
        "device.key",
        "device.pem",
        "device-ca.pem",
        "identity.json",
        "bundle-profile.sha256",
        "https-bridge.toml",
        "web-response.toml",
        ".lock",
    ];
    if RESERVED
        .iter()
        .any(|reserved| leaf.eq_ignore_ascii_case(reserved))
    {
        return Err(refused());
    }
    let leaf = leaf.to_owned();
    settings.credential_file = held_identity_path.join(&leaf);
    Ok((settings, leaf))
}

/// Copy a bounded, exact admission key directly into a zeroizing owner.
pub(crate) fn admit_key(raw: &[u8]) -> io::Result<Zeroizing<[u8; 64]>> {
    let value = raw.strip_suffix(b"\n").unwrap_or(raw);
    if value.len() != 64
        || value.iter().all(|b| *b == b'0')
        || value
            .iter()
            .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(b))
    {
        return Err(refused());
    }
    let mut secret = Zeroizing::new([0u8; 64]);
    secret.copy_from_slice(value);
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_identity_leaf_and_separate_key_are_required() {
        let identity = Path::new("/private/tmp/b06-web-identity");
        let valid = "authority='web.test'\ndescriptor_path='/descriptor'\nallowed_ingress_ips=['192.0.2.5']\ncredential_file='/private/tmp/b06-web-identity/web.key'\n";
        let (settings, leaf) = admit_sidecar(valid.as_bytes(), identity).unwrap();
        assert_eq!(leaf, "web.key");
        assert_eq!(settings.credential_file, identity.join("web.key"));
        for bad in [
            valid.replace("web.key", "device.key"),
            valid.replace("b06-web-identity", "other-identity"),
            valid.replace("192.0.2.5", "0.0.0.0"),
        ] {
            assert!(admit_sidecar(bad.as_bytes(), identity).is_err());
        }
        assert!(admit_key(&[b'a'; 64]).is_ok());
        assert!(admit_key(&[b'0'; 64]).is_err());
        assert!(admit_key(&[b'g'; 64]).is_err());
        assert!(admit_key(&[b'a'; 65]).is_err());
    }
}
