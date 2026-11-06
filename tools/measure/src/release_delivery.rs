use std::fs;
use std::io::Read;
use std::path::Path;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::artifact::{read_json, write_json};

#[allow(clippy::too_many_arguments)]
pub fn build_release_delivery_manifest(
    root: &Path,
    output_dir: &Path,
    channel: &str,
    prerelease: &str,
    rpm_status: &str,
    rpm_reason: &str,
    git_sha: &str,
    build_timestamp: &str,
    debian_revision: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let prerelease = match prerelease {
        "true" => true,
        "false" => false,
        other => return Err(format!("--prerelease must be true or false, got {other}").into()),
    };
    let arch = std::env::consts::ARCH;
    let version = server_version(root)?;
    let split_version = match debian_revision {
        None => version.clone(),
        Some(revision)
            if !revision.is_empty()
                && revision.len() <= 18
                && revision.as_bytes()[0] >= b'1'
                && revision.as_bytes()[0] <= b'9'
                && revision.bytes().all(|digit| digit.is_ascii_digit()) =>
        {
            format!("{version}-{revision}")
        }
        Some(_) => return Err("noncanonical Debian revision".into()),
    };
    let deb_arch = map_deb_arch(arch);
    let target_triple = target_triple(arch);
    let bundle_name = format!("aegis-{version}-linux-{arch}");
    let package_root_name = format!("aegis-package-root-{version}-linux-{arch}");

    let mut manifest = json!({
        "schema": "aegis_linux_release_manifest_v1",
        "version": version,
        "channel": channel,
        "git_sha": git_sha,
        "build_timestamp": build_timestamp,
        "prerelease": prerelease,
        "platform": "linux",
        "arch": arch,
        "target_triple": target_triple,
        "distribution": "private_administrative_operator",
        "delivery_contract": {
            "role_config_install_requires_bundle": true,
            "server_installer_entrypoint": "./install-server.sh",
            "bootstrap_installer_entrypoint": "./bootstrap-install.sh",
            "bundle_installer_entrypoint": "./install.sh",
        },
        "artifacts": {
            "bundle": {
                "status": "ready",
                "archive": {
                    "path": format!("{bundle_name}.tar.gz"),
                    "sha256_path": format!("{bundle_name}.tar.gz.sha256"),
                    "sha256": sha256_of(&output_dir.join(format!("{bundle_name}.tar.gz")))?,
                },
                "directory": bundle_name,
                "target_triple": target_triple,
            },
            "package_root": {
                "status": "ready",
                "archive": {
                    "path": format!("{package_root_name}.tar.gz"),
                    "sha256": sha256_of(&output_dir.join(format!("{package_root_name}.tar.gz")))?,
                },
                "directory": package_root_name,
                "manifest_path": format!("{package_root_name}/package-root.manifest.json"),
                "target_triple": target_triple,
            },
            "deb": {
                "status": "ready",
                "split_version": split_version,
                "combined": {
                    "path": format!("aegis_{version}_{deb_arch}.deb"),
                    "sha256_path": format!("aegis_{version}_{deb_arch}.deb.sha256"),
                    "sha256": sha256_of(&output_dir.join(format!("aegis_{version}_{deb_arch}.deb")))?,
                },
                "split": {
                    "server": {
                        "path": format!("aegis-server_{split_version}_{deb_arch}.deb"),
                        "sha256_path": format!("aegis-server_{split_version}_{deb_arch}.deb.sha256"),
                        "sha256": sha256_of(&output_dir.join(format!("aegis-server_{split_version}_{deb_arch}.deb")))?,
                    },
                    "client": {
                        "path": format!("aegis-client_{split_version}_{deb_arch}.deb"),
                        "sha256_path": format!("aegis-client_{split_version}_{deb_arch}.deb.sha256"),
                        "sha256": sha256_of(&output_dir.join(format!("aegis-client_{split_version}_{deb_arch}.deb")))?,
                    },
                },
                "manifest_path": "split-deb-packages.manifest.json",
                "target_triple": target_triple,
            },
            "rpm": {
                "status": rpm_status,
                "reason": if rpm_reason.is_empty() { Value::Null } else { json!(rpm_reason) },
                "manifest_path": if rpm_status == "ready" { json!("rpm-packages.manifest.json") } else { Value::Null },
            },
        },
        "install_matrix": {
            "bootstrap_default": {
                "artifact": "bundle",
                "reason": "role_aware_install_flow_lives_in_install_sh",
            },
            "debian_like": {
                "manual_package_artifacts": ["deb.split.server", "deb.split.client"],
                "fallback_artifact": "bundle",
            },
            "rhel_like": {
                "manual_package_artifacts": ["rpm.split.server", "rpm.split.client"],
                "fallback_artifact": "bundle",
            },
            "suse_like": {
                "manual_package_artifacts": ["rpm.split.server", "rpm.split.client"],
                "fallback_artifact": "bundle",
            },
            "generic_linux": {
                "fallback_artifact": "bundle",
            },
        },
    });

    let lock = sha256_of(&root.join("Cargo.lock"))?;
    manifest["artifacts"]["private_research"] =
        crate::private_research_delivery::linux_release_entry(
            output_dir,
            &version,
            git_sha,
            &lock,
            arch,
            &target_triple,
        )?;

    if rpm_status == "ready" {
        let rpm_manifest = read_json(&output_dir.join("rpm-packages.manifest.json"))?;
        manifest["artifacts"]["rpm"]["split"] = json!({
            "server": rpm_package_entry(output_dir, &rpm_manifest, "aegis-server")?,
            "client": rpm_package_entry(output_dir, &rpm_manifest, "aegis-client")?,
        });
    }

    let macos_arches = macos_client_artifacts(output_dir, &version)?;
    if macos_arches
        .as_object()
        .map(|items| !items.is_empty())
        .unwrap_or(false)
    {
        manifest["artifacts"]["macos_client"] = json!({
            "status": "ready",
            "split": macos_arches,
        });
        let manual_client_artifacts = manifest["artifacts"]["macos_client"]["split"]
            .as_object()
            .map(|items| {
                let mut keys = items.keys().cloned().collect::<Vec<_>>();
                keys.sort();
                keys.into_iter()
                    .map(|arch| format!("macos_client.split.{arch}"))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        manifest["install_matrix"]["macos"] = json!({
            "manual_client_artifacts": manual_client_artifacts,
            "recommended_entry": "manual_tarball_then_install_macos_client.sh",
        });
    } else {
        manifest["artifacts"]["macos_client"] = json!({
            "status": "unavailable",
            "reason": "macos_build_artifacts_not_present_in_output_dir",
        });
    }

    write_json(&output_dir.join("release.manifest.json"), &manifest)?;
    Ok(())
}

fn server_version(root: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let raw = fs::read_to_string(root.join("aegis-server/Cargo.toml"))?;
    let parsed = raw.parse::<toml::Value>()?;
    parsed
        .get("package")
        .and_then(|package| package.get("version"))
        .and_then(toml::Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| "aegis-server package version missing".into())
}

fn map_deb_arch(machine: &str) -> &str {
    match machine {
        "x86_64" => "amd64",
        "aarch64" | "arm64" => "arm64",
        "armv7l" => "armhf",
        other => other,
    }
}

fn target_triple(arch: &str) -> String {
    match arch {
        "x86_64" => "x86_64-unknown-linux-gnu".to_string(),
        "aarch64" | "arm64" => "aarch64-unknown-linux-gnu".to_string(),
        "armv7l" => "armv7-unknown-linux-gnueabihf".to_string(),
        other => format!("{other}-unknown-linux-gnu"),
    }
}

fn rpm_package_entry(
    output_dir: &Path,
    rpm_manifest: &Value,
    package: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let rpm_file = rpm_manifest["packages"][package]["rpm_file"]
        .as_str()
        .ok_or_else(|| format!("rpm file missing for {package}"))?;
    Ok(json!({
        "path": rpm_file,
        "sha256_path": format!("{rpm_file}.sha256"),
        "sha256": sha256_of(&output_dir.join(rpm_file))?,
    }))
}

fn macos_client_artifacts(
    output_dir: &Path,
    version: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let mut map = serde_json::Map::new();
    for (arch_name, archive_suffix, triple) in [
        ("x86_64", "macos-x86_64", "x86_64-apple-darwin"),
        ("aarch64", "macos-aarch64", "aarch64-apple-darwin"),
    ] {
        let archive_name = format!("aegis-client-{version}-{archive_suffix}.tar.gz");
        let archive = output_dir.join(&archive_name);
        if archive.is_file() {
            map.insert(
                arch_name.to_string(),
                json!({
                    "path": archive_name,
                    "sha256_path": format!("{archive_name}.sha256"),
                    "sha256": sha256_of(&archive)?,
                    "target_triple": triple,
                }),
            );
        }
    }
    Ok(Value::Object(map))
}

fn sha256_of(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1 << 20];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}
