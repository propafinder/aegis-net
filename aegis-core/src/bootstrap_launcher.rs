//! Generate the same authenticated client launcher for every onboarding entry.
//! Pins arrive in a local operator-controlled profile, never from a mirror.

use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    io::Read,
    path::{Component, Path, PathBuf},
};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestPins {
    pub manifest_sha256: String,
    pub signature_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LauncherPins {
    pub schema: String,
    /// Exact release tag, for example `v0.3.50-rc.18`.
    pub version: String,
    pub bootstrap_sha256: String,
    pub x86_64: ManifestPins,
    pub aarch64: ManifestPins,
    /// Ordered public HTTPS release bases, each ending in `/<version>`.
    pub sources: Vec<String>,
}

/// Shared staging boundary for all authenticated client launcher renderers.
pub const PRIVATE_STAGING: &str = include_str!("bootstrap_launcher_staging.sh");

type Result<T> = std::result::Result<T, String>;

impl LauncherPins {
    pub fn load(path: &Path) -> Result<Self> {
        let path = trusted_profile_path(path)?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options
            .open(&path)
            .map_err(|_| "Cannot open the trusted launcher profile".to_owned())?;
        let metadata = file
            .metadata()
            .map_err(|_| "Cannot inspect the trusted launcher profile".to_owned())?;
        if !metadata.is_file() || metadata.len() > 65536 {
            return Err("Launcher profile must be a regular file of at most 64 KiB".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // SAFETY: geteuid has no arguments or memory-safety preconditions.
            let uid = unsafe { libc::geteuid() };
            if ![0, uid].contains(&metadata.uid())
                || metadata.mode() & 0o022 != 0
                || metadata.nlink() != 1
            {
                return Err("Launcher profile must be installer-owned, unlinked, and not writable by group or others".into());
            }
        }
        let mut data = Vec::new();
        file.take(65537)
            .read_to_end(&mut data)
            .map_err(|_| "Cannot read the trusted launcher profile".to_owned())?;
        if data.len() > 65536 {
            return Err("Launcher profile exceeds 64 KiB".into());
        }
        let profile: Self = serde_json::from_slice(&data)
            .map_err(|_| "Invalid trusted launcher profile".to_owned())?;
        profile.validate()?;
        Ok(profile)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != "aegis_client_launcher_pins_v1"
            || !self.version.starts_with('v')
            || self.version.len() < 2
            || self.version.len() > 100
            || !self.version.as_bytes()[1].is_ascii_digit()
            || !self
                .version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
        {
            return Err("Launcher profile requires an exact release tag".into());
        }
        for digest in [
            &self.bootstrap_sha256,
            &self.x86_64.manifest_sha256,
            &self.x86_64.signature_sha256,
            &self.aarch64.manifest_sha256,
            &self.aarch64.signature_sha256,
        ] {
            if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("Launcher profile requires all five independent SHA-256 pins".into());
            }
        }
        if self.sources.is_empty() || self.sources.len() > 8 {
            return Err("Launcher profile requires one to eight public sources".into());
        }
        for source in &self.sources {
            let tail = source
                .strip_prefix("https://")
                .ok_or("Launcher sources must use HTTPS")?;
            let (host, _) = tail.split_once('/').ok_or("Missing release path")?;
            if host.is_empty()
                || !tail
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/:._-".contains(&b))
                || tail.contains("//")
                || tail.contains("/../")
                || tail.contains("/./")
                || !source.ends_with(&format!("/{}", self.version))
            {
                return Err(
                    "Launcher sources must be public bases for the exact release tag".into(),
                );
            }
        }
        Ok(())
    }

    pub fn render_script(&self) -> Result<String> {
        self.validate()?;
        let mut script = String::from("#!/usr/bin/env bash\nset -euo pipefail\numask 077\n");
        for (name, value) in [
            ("bootstrap_sha", &self.bootstrap_sha256),
            ("x86_manifest_sha", &self.x86_64.manifest_sha256),
            ("x86_signature_sha", &self.x86_64.signature_sha256),
            ("arm_manifest_sha", &self.aarch64.manifest_sha256),
            ("arm_signature_sha", &self.aarch64.signature_sha256),
        ] {
            script.push_str(&format!("{name}={}\n", shell_quote(&value.to_lowercase())));
        }
        script.push_str("sources=(");
        for source in &self.sources {
            script.push_str(&format!(" {}", shell_quote(source)));
        }
        script.push_str(" )\n");
        script.push_str(PRIVATE_STAGING);
        script.push_str(include_str!("bootstrap_launcher.sh"));
        Ok(script)
    }

    pub fn render_command(&self, bundle_url_file: &Path) -> Result<String> {
        let path = bundle_url_file
            .to_str()
            .ok_or("Private access file path must be UTF-8")?;
        if !bundle_url_file.is_absolute() || path.chars().any(char::is_control) {
            return Err("Use an absolute client-owned private --bundle-url-file path".into());
        }
        // This is a client-side path. The server must not read its contents or
        // embed private bytes into the authenticated public bootstrap command.
        Ok(format!(
            "bash -c {} -- --bundle-url-file {}",
            shell_quote(&self.render_script()?),
            shell_quote(path)
        ))
    }
}

fn trusted_profile_path(path: &Path) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| "Cannot determine profile directory")?
            .join(path)
    };
    #[cfg(target_os = "macos")]
    let path = if let Some(text) = path.to_str().filter(|text| {
        ["/var/", "/tmp/", "/etc/"]
            .iter()
            .any(|prefix| text.starts_with(prefix))
    }) {
        PathBuf::from(format!("/private{text}"))
    } else {
        path
    };
    if path
        .components()
        .any(|part| matches!(part, Component::ParentDir))
    {
        return Err("Launcher profile path must not contain parent traversal".into());
    }
    let parent = path.parent().ok_or("Missing launcher profile directory")?;
    let mut checked = PathBuf::from("/");
    for part in parent.components() {
        if let Component::Normal(part) = part {
            checked.push(part);
            let info = std::fs::symlink_metadata(&checked)
                .map_err(|_| "Cannot inspect launcher profile directory")?;
            if !info.is_dir() {
                return Err("Launcher profile directory must not be linked".into());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                // SAFETY: geteuid only reads the process identity.
                let uid = unsafe { libc::geteuid() };
                let sticky_ancestor =
                    checked != parent && info.uid() == 0 && info.mode() & 0o1000 != 0;
                if ![0, uid].contains(&info.uid()) || (info.mode() & 0o022 != 0 && !sticky_ancestor)
                {
                    return Err(
                        "Launcher profile directory must be administrator-owned and protected"
                            .into(),
                    );
                }
            }
        }
    }
    Ok(path)
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests;
