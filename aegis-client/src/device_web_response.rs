//! Private installed web-response admission policy; public bundle contains no key.
use aegis_core::{secret_file, web_response_profile::WebResponseSettings};
use aegis_web_carrier::{ClientSettings, Credential};
use anyhow::{ensure, Result};
use std::path::Path;

pub const SIDECAR: &str = "web-response.toml";

pub fn credential(
    settings: &WebResponseSettings,
    identity_key: &Path,
    identity_cert: &Path,
) -> Result<Credential> {
    settings.validate().map_err(anyhow::Error::msg)?;
    ensure!(
        settings.credential_file.as_path() != identity_key
            && settings.credential_file.as_path() != identity_cert
            && settings
                .credential_file
                .file_name()
                .and_then(|s| s.to_str())
                != Some(SIDECAR),
        "web-response admission key aliases device identity"
    );
    secret_file::trusted_read_parent(&settings.credential_file)
        .map_err(|_| anyhow::anyhow!("web-response credential custody rejected"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::symlink_metadata(&settings.credential_file)
            .map_err(|_| anyhow::anyhow!("web-response credential custody rejected"))?;
        ensure!(
            m.is_file() && m.nlink() == 1,
            "web-response credential custody rejected"
        );
    }
    Credential::from_private_bytes(
        secret_file::read(&settings.credential_file, 65)
            .map_err(|_| anyhow::anyhow!("web-response credential custody rejected"))?,
    )
    .map_err(|_| anyhow::anyhow!("web-response credential rejected"))
}

pub fn client_settings(settings: &WebResponseSettings) -> ClientSettings {
    ClientSettings {
        authority: settings.authority.clone(),
        descriptor_path: settings.descriptor_path.clone(),
        credential_file: settings.credential_file.clone(),
    }
}

pub fn load(identity: &Path) -> Result<Option<WebResponseSettings>> {
    ensure!(
        identity.is_absolute() && crate::credential_path_policy::clean_absolute_directory(identity),
        "web-response sidecar rejected"
    );
    let path = identity.join(SIDECAR);
    secret_file::trusted_read_parent(&path)
        .map_err(|_| anyhow::anyhow!("web-response sidecar rejected"))?;
    let bytes = match secret_file::read(&path, 8192) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            secret_file::trusted_read_parent(&path)
                .map_err(|_| anyhow::anyhow!("web-response sidecar rejected"))?;
            return Ok(None);
        }
        Err(_) => return Err(anyhow::anyhow!("web-response sidecar rejected")),
    };
    let input = std::str::from_utf8(&bytes)
        .map_err(|_| anyhow::anyhow!("web-response sidecar rejected"))?;
    let settings: WebResponseSettings =
        toml::from_str(input).map_err(|_| anyhow::anyhow!("web-response sidecar rejected"))?;
    let key = identity.join("device.key");
    credential(&settings, &key, &identity.join("device.pem"))?;
    Ok(Some(settings))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_sidecar_is_required_exact_and_separate_from_device_key() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load(dir.path()).unwrap().is_none());
        let key = dir.path().join("device.key");
        let admission = dir.path().join("web.key");
        secret_file::write_private_new(&key, b"synthetic-device-key").unwrap();
        secret_file::write_private_new(&admission, &[b'a'; 64]).unwrap();
        let sidecar = dir.path().join(SIDECAR);
        let source = format!(
            "authority = 'web.example'\ndescriptor_path = '/private/descriptor'\nallowed_ingress_ips = ['192.0.2.10']\ncredential_file = '{}'\n",
            admission.display()
        );
        secret_file::write_private_new(&sidecar, source.as_bytes()).unwrap();
        let loaded = load(dir.path()).unwrap().unwrap();
        assert_eq!(
            loaded.allowed_ingress_ips,
            vec!["192.0.2.10".parse::<std::net::IpAddr>().unwrap()]
        );
        assert!(credential(&loaded, &key, &dir.path().join("device.pem")).is_ok());
        let mut alias = loaded.clone();
        alias.credential_file = key;
        assert!(credential(
            &alias,
            &dir.path().join("device.key"),
            &dir.path().join("device.pem")
        )
        .is_err());
        let mut foreign = loaded;
        foreign.allowed_ingress_ips = vec!["0.0.0.0".parse().unwrap()];
        assert!(foreign.validate().is_err());
    }
}
