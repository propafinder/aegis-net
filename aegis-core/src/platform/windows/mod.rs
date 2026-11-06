use std::env;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsInstallScope {
    System,
    User,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsClientLayout {
    pub bin_dir: PathBuf,
    pub binary_path: PathBuf,
    pub config_dir: PathBuf,
    pub config_path: PathBuf,
    pub ca_cert_path: PathBuf,
    pub state_dir: PathBuf,
    pub log_dir: PathBuf,
    pub runtime_events_path: PathBuf,
    pub install_manifest_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsPathRoots {
    pub program_files: PathBuf,
    pub program_data: PathBuf,
    pub app_data: PathBuf,
    pub local_app_data: PathBuf,
}

impl WindowsPathRoots {
    pub fn from_env() -> Self {
        Self {
            program_files: env_path("ProgramFiles", r"C:\Program Files"),
            program_data: env_path("ProgramData", r"C:\ProgramData"),
            app_data: env_path("APPDATA", r"C:\Users\Default\AppData\Roaming"),
            local_app_data: env_path("LOCALAPPDATA", r"C:\Users\Default\AppData\Local"),
        }
    }
}

pub fn client_layout(scope: WindowsInstallScope) -> WindowsClientLayout {
    client_layout_from_roots(scope, &WindowsPathRoots::from_env())
}

pub fn client_layout_from_roots(
    scope: WindowsInstallScope,
    roots: &WindowsPathRoots,
) -> WindowsClientLayout {
    match scope {
        WindowsInstallScope::System => system_client_layout(roots),
        WindowsInstallScope::User => user_client_layout(roots),
    }
}

fn system_client_layout(roots: &WindowsPathRoots) -> WindowsClientLayout {
    let bin_dir = roots.program_files.join("AEGIS").join("bin");
    let config_dir = roots.program_data.join("AEGIS").join("client");
    let state_dir = roots.program_data.join("AEGIS").join("state");
    let log_dir = roots.program_data.join("AEGIS").join("logs");
    WindowsClientLayout {
        binary_path: bin_dir.join("aegis-client.exe"),
        config_path: config_dir.join("aegis.toml"),
        ca_cert_path: config_dir.join("ca.pem"),
        runtime_events_path: state_dir.join("runtime-events.jsonl"),
        install_manifest_path: state_dir.join("install-manifest.json"),
        bin_dir,
        config_dir,
        state_dir,
        log_dir,
    }
}

fn user_client_layout(roots: &WindowsPathRoots) -> WindowsClientLayout {
    let bin_dir = roots.local_app_data.join("AEGIS").join("bin");
    let config_dir = roots.app_data.join("AEGIS").join("config");
    let state_dir = roots.local_app_data.join("AEGIS").join("state");
    let log_dir = roots.local_app_data.join("AEGIS").join("logs");
    WindowsClientLayout {
        binary_path: bin_dir.join("aegis-client.exe"),
        config_path: config_dir.join("aegis.toml"),
        ca_cert_path: config_dir.join("ca.pem"),
        runtime_events_path: state_dir.join("runtime-events.jsonl"),
        install_manifest_path: state_dir.join("install-manifest.json"),
        bin_dir,
        config_dir,
        state_dir,
        log_dir,
    }
}

fn env_path(key: &str, fallback: &str) -> PathBuf {
    env::var_os(key)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(fallback).to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roots() -> WindowsPathRoots {
        WindowsPathRoots {
            program_files: PathBuf::from(r"C:\Program Files"),
            program_data: PathBuf::from(r"C:\ProgramData"),
            app_data: PathBuf::from(r"C:\Users\alice\AppData\Roaming"),
            local_app_data: PathBuf::from(r"C:\Users\alice\AppData\Local"),
        }
    }

    #[test]
    fn system_client_layout_uses_program_files_and_program_data() {
        let layout = client_layout_from_roots(WindowsInstallScope::System, &roots());

        assert_eq!(
            layout.bin_dir,
            PathBuf::from(r"C:\Program Files").join("AEGIS").join("bin")
        );
        assert_eq!(layout.binary_path, layout.bin_dir.join("aegis-client.exe"));
        assert_eq!(
            layout.config_path,
            PathBuf::from(r"C:\ProgramData")
                .join("AEGIS")
                .join("client")
                .join("aegis.toml")
        );
        assert_eq!(layout.ca_cert_path, layout.config_dir.join("ca.pem"));
        assert_eq!(
            layout.runtime_events_path,
            PathBuf::from(r"C:\ProgramData")
                .join("AEGIS")
                .join("state")
                .join("runtime-events.jsonl")
        );
        assert_eq!(
            layout.install_manifest_path,
            layout.state_dir.join("install-manifest.json")
        );
        assert_eq!(
            layout.log_dir,
            PathBuf::from(r"C:\ProgramData").join("AEGIS").join("logs")
        );
    }

    #[test]
    fn user_client_layout_uses_appdata_and_localappdata() {
        let layout = client_layout_from_roots(WindowsInstallScope::User, &roots());

        assert_eq!(
            layout.bin_dir,
            PathBuf::from(r"C:\Users\alice\AppData\Local")
                .join("AEGIS")
                .join("bin")
        );
        assert_eq!(
            layout.config_dir,
            PathBuf::from(r"C:\Users\alice\AppData\Roaming")
                .join("AEGIS")
                .join("config")
        );
        assert_eq!(layout.config_path, layout.config_dir.join("aegis.toml"));
        assert_eq!(layout.ca_cert_path, layout.config_dir.join("ca.pem"));
        assert_eq!(
            layout.state_dir,
            PathBuf::from(r"C:\Users\alice\AppData\Local")
                .join("AEGIS")
                .join("state")
        );
        assert_eq!(
            layout.runtime_events_path,
            layout.state_dir.join("runtime-events.jsonl")
        );
        assert_eq!(
            layout.install_manifest_path,
            layout.state_dir.join("install-manifest.json")
        );
        assert_eq!(
            layout.log_dir,
            PathBuf::from(r"C:\Users\alice\AppData\Local")
                .join("AEGIS")
                .join("logs")
        );
    }
}
