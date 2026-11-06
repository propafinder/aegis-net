//! Private SFU file names and bytes under an already held identity directory.
//! A public route or this parser alone never grants a media socket.
use aegis_core::carrier_program::SfuDeclaration;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, io, path::Path};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub(crate) const SIDECAR: &str = "sfu-media.toml";
pub(crate) const BROKER_KEY: &str = "sfu-broker-key";
pub(crate) const BROKER_CA: &str = "sfu-broker-ca.pem";
pub(crate) const MEDIA_CA: &str = "sfu-media-ca.pem";

fn refused() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "SFU custody refused")
}

/// The sidecar contains only the three exact provider-local file paths. The
/// signed public profile contains all destinations and CA byte digests.
pub(crate) fn admit_sidecar(bytes: &[u8], identity: &Path) -> io::Result<()> {
    let text = std::str::from_utf8(bytes).map_err(|_| refused())?;
    let parsed: toml::Table = text.parse().map_err(|_| refused())?;
    if parsed.keys().map(String::as_str).collect::<BTreeSet<_>>()
        != BTreeSet::from(["broker_key_file", "broker_ca_file", "media_ca_file"])
    {
        return Err(refused());
    }
    for (key, leaf) in [
        ("broker_key_file", BROKER_KEY),
        ("broker_ca_file", BROKER_CA),
        ("media_ca_file", MEDIA_CA),
    ] {
        let path = parsed
            .get(key)
            .and_then(toml::Value::as_str)
            .ok_or_else(refused)?;
        if Path::new(path) != identity.join(leaf) {
            return Err(refused());
        }
    }
    Ok(())
}

/// Import receives a whole authenticated source tree, then rewrites its
/// private paths into the provider container. It only accepts one clean
/// common absolute source parent and the three fixed distinct leaves.
pub(crate) fn admit_import_sidecar(bytes: &[u8]) -> io::Result<()> {
    let text = std::str::from_utf8(bytes).map_err(|_| refused())?;
    let parsed: toml::Table = text.parse().map_err(|_| refused())?;
    if parsed.keys().map(String::as_str).collect::<BTreeSet<_>>()
        != BTreeSet::from(["broker_key_file", "broker_ca_file", "media_ca_file"])
    {
        return Err(refused());
    }
    let broker = parsed
        .get("broker_key_file")
        .and_then(toml::Value::as_str)
        .ok_or_else(refused)?;
    let identity = Path::new(broker).parent().ok_or_else(refused)?;
    if !identity.is_absolute()
        || identity.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(refused());
    }
    admit_sidecar(bytes, identity)
}

pub(crate) fn relocated_sidecar(identity: &Path) -> String {
    format!(
        "broker_key_file = '{}'\nbroker_ca_file = '{}'\nmedia_ca_file = '{}'\n",
        identity.join(BROKER_KEY).display(),
        identity.join(BROKER_CA).display(),
        identity.join(MEDIA_CA).display(),
    )
}

pub(crate) fn admit_broker_key(raw: &[u8]) -> io::Result<Zeroizing<[u8; 64]>> {
    let bytes = raw.strip_suffix(b"\n").unwrap_or(raw);
    if bytes.len() != 64
        || bytes.iter().all(|b| *b == b'0')
        || bytes
            .iter()
            .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(b))
    {
        return Err(refused());
    }
    let mut key = Zeroizing::new([0; 64]);
    key.copy_from_slice(bytes);
    Ok(key)
}

pub(crate) fn admit_ca(raw: &[u8], signed_sha256: &str) -> io::Result<Vec<u8>> {
    if raw.is_empty() || raw.len() > 64 * 1024 || signed_sha256.len() != 64 {
        return Err(refused());
    }
    let actual = format!("{:x}", Sha256::digest(raw));
    if actual
        .as_bytes()
        .ct_eq(signed_sha256.as_bytes())
        .unwrap_u8()
        != 1
    {
        return Err(refused());
    }
    aegis_client::device_bundle_profile::validate_ca(raw).map_err(|_| refused())?;
    Ok(raw.to_vec())
}

pub(crate) fn admit_public_roots(
    broker: &[u8],
    media: &[u8],
    signed: &SfuDeclaration,
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    Ok((
        admit_ca(broker, &signed.broker_ca_sha256)?,
        admit_ca(media, &signed.media_ca_sha256)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sidecar_requires_exact_held_leaves_and_key_is_separate() {
        let identity = Path::new("/private/tmp/aegis-sfu-test/identity");
        let valid = relocated_sidecar(identity);
        admit_sidecar(valid.as_bytes(), identity).unwrap();
        assert!(
            admit_sidecar(valid.replace(BROKER_KEY, "device.key").as_bytes(), identity).is_err()
        );
        assert!(admit_sidecar(format!("{valid}unknown = true\n").as_bytes(), identity).is_err());
        assert!(
            admit_sidecar(valid.replace("/identity/", "/other/").as_bytes(), identity).is_err()
        );
        assert!(admit_broker_key(&[b'a'; 64]).is_ok());
        assert!(admit_broker_key(&[b'0'; 64]).is_err());
        assert!(admit_broker_key(&[b'g'; 64]).is_err());
    }
}
