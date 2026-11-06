use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::artifact::{read_json, write_json, write_text};

pub struct DebPackageContractInputs<'a> {
    pub deb_path: &'a Path,
    pub deb_sha256_path: &'a Path,
    pub manifest_path: &'a Path,
    pub extract_dir: &'a Path,
    pub control_dir: &'a Path,
    pub version: &'a str,
    pub deb_arch: &'a str,
}

pub struct SplitDebPackageContractInputs<'a> {
    pub server_deb: &'a Path,
    pub client_deb: &'a Path,
    pub server_sha256_path: &'a Path,
    pub client_sha256_path: &'a Path,
    pub manifest_path: &'a Path,
    pub server_extract_dir: &'a Path,
    pub server_control_dir: &'a Path,
    pub client_extract_dir: &'a Path,
    pub client_control_dir: &'a Path,
    pub version: &'a str,
    pub deb_arch: &'a str,
}

const HELPER_SCRIPTS: &[&str] = &[
    "scripts/lib/root-state.sh",
    "scripts/lib/aegis_installer_auto_v2.py",
    "scripts/lib/aegis_auto_uninstall_journal.py",
    "scripts/lib/aegis_auto_capture.py",
    "scripts/lib/aegis_auto_capture_topology.py",
    "scripts/lib/aegis_auto_endpoint.py",
    "scripts/lib/aegis_auto_guard_policy.py",
    "scripts/lib/aegis_auto_foreign_policy.py",
    "scripts/lib/aegis_auto_foreign_monitor.py",
    "scripts/lib/aegis_auto_ufw_pins.json",
    "scripts/lib/aegis_initrd_policy.py",
    "scripts/lib/aegis_initrd_classic.py",
    "scripts/lib/aegis_auto_guardian.py",
    "scripts/lib/aegis_auto_guardian_watchdog.py",
    "scripts/lib/aegis_auto_terminal_witness.py",
    "scripts/lib/aegis_auto_terminal_boot_store.py",
    "scripts/lib/aegis_auto_terminal_register.py",
    "scripts/lib/aegis_auto_boot_transition.py",
    "scripts/lib/aegis_auto_launch.py",
    "scripts/lib/aegis_auto_native_witness.py",
    "scripts/lib/aegis_auto_sink.py",
    "scripts/lib/aegis_auto_trace_rollback.py",
    "scripts/lib/aegis_auto_witness_topology.py",
    "scripts/aegis-device-egress-guard.sh",
    "scripts/aegis-relay-geneva-profile.sh",
    "scripts/bootstrap-wide-linux-validation-host.sh",
    "scripts/generate-relay-materials.sh",
    "scripts/render-client-bundle.sh",
    "scripts/package-client-bundle.sh",
    "scripts/issue-fronted-bundle.sh",
    "scripts/purge-installed-aegis.sh",
    "scripts/aegis-ubuntu-uninstall.sh",
    "scripts/aegis-origin-guard.sh",
    "scripts/aegis-wide-enable.sh",
    "scripts/aegis-wide-disable.sh",
    "scripts/aegis-wide-persist-install.sh",
    "scripts/janitor-wide-linux-tproxy.sh",
    "scripts/setup-wide-linux-redirect.sh",
    "scripts/setup-wide-linux-tproxy.sh",
    "scripts/setup-wide-linux-nfqueue.sh",
    "scripts/aegis-rpi-gateway.sh",
    "scripts/validate-debian-package-host.sh",
    "scripts/build-ubuntu-controlled-pilot-playbook.sh",
    "scripts/build-ubuntu-operator-reapply-canary.sh",
    "scripts/build-ubuntu-controlled-pilot-bundle.sh",
    "scripts/build-ubuntu-release-review.sh",
    "scripts/build-ubuntu-controlled-pilot-review-bundle.sh",
    "scripts/ubuntu-release-wave-status.sh",
    "scripts/build-ubuntu-release-wave-bundle.sh",
    "scripts/build-ubuntu-field-pilot-remote-bundle.sh",
    "scripts/build-post-release-stealth-wave-summary.sh",
    "scripts/mimicry-wire-validation-contract.sh",
    "scripts/build-mimicry-wire-witness-summary.sh",
    "scripts/validate-mimicry-wire-host.sh",
    "scripts/build-ubuntu-mimicry-next-contour.sh",
];

pub fn print_release_package_metadata(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", cargo_target_directory(root)?.display());
    println!("{}", server_version(root)?);
    Ok(())
}

pub fn print_macos_client_package_metadata(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", client_version(root)?);
    Ok(())
}

pub fn build_package_root_manifest(
    package_dir: &Path,
    rootfs_dir: &Path,
    version: &str,
    arch: &str,
    target_triple: &str,
    git_sha: &str,
    build_timestamp: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (files, checksums) = checksums_for_dir(rootfs_dir)?;
    let server_sha256 = sha256_of(&rootfs_dir.join("usr/local/bin/aegis-server"))?;
    let client_sha256 = sha256_of(&rootfs_dir.join("usr/local/bin/aegis-client"))?;
    let cargo_lock_sha256 =
        std::env::var("AEGIS_CARGO_LOCK_SHA256").unwrap_or_else(|_| "unknown".to_string());
    let release_max_glibc =
        std::env::var("AEGIS_RELEASE_MAX_GLIBC").unwrap_or_else(|_| "unknown".to_string());
    let server_required_glibc =
        std::env::var("AEGIS_SERVER_REQUIRED_GLIBC").unwrap_or_else(|_| "unknown".to_string());
    let client_required_glibc =
        std::env::var("AEGIS_CLIENT_REQUIRED_GLIBC").unwrap_or_else(|_| "unknown".to_string());
    write_text(
        &package_dir.join("SHA256SUMS"),
        &(checksums.join("\n") + "\n"),
    )?;
    let manifest = json!({
        "schema": "aegis_package_root_manifest_v2",
        "package_name": package_dir.file_name().and_then(|v| v.to_str()).unwrap_or_default(),
        "version": version,
        "git_sha": git_sha,
        "build_timestamp": build_timestamp,
        "platform": "linux",
        "arch": arch,
        "target_triple": target_triple,
        "cargo_lock_sha256": cargo_lock_sha256,
        "runtime_abi": {
            "libc_family": "glibc",
            "generic_linux_min_glibc": release_max_glibc,
            "binary_required_glibc": {
                "aegis-server": server_required_glibc,
                "aegis-client": client_required_glibc,
            },
        },
        "binaries": {
            "aegis-server": {
                "path": "rootfs/usr/local/bin/aegis-server",
                "sha256": server_sha256,
                "features": [],
            },
            "aegis-client": {
                "path": "rootfs/usr/local/bin/aegis-client",
                "sha256": client_sha256,
                "features": ["raw-socket", "chrome-like-tls", "chrome-like-quic"],
            },
        },
        "rootfs_dir": "rootfs",
        "runtime_paths": {
            "server_binary": "/usr/local/bin/aegis-server",
            "client_binary": "/usr/local/bin/aegis-client",
            "client_wide_helper_dir": "/usr/local/lib/aegis/helpers",
            "server_unit": "/usr/lib/systemd/system/aegis-server.service",
            "client_unit": "/usr/lib/systemd/system/aegis-client.service",
            "preset_policy": "/usr/lib/systemd/system-preset/90-aegis.preset",
            "server_preset_policy": "/usr/lib/systemd/system-preset/90-aegis-server.preset",
            "client_preset_policy": "/usr/lib/systemd/system-preset/90-aegis-client.preset",
            "server_sysusers": "/usr/lib/sysusers.d/aegis-server.conf",
            "server_tmpfiles": "/usr/lib/tmpfiles.d/aegis-server.conf",
            "client_tmpfiles": "/usr/lib/tmpfiles.d/aegis-client.conf",
            "server_env": "/etc/default/aegis-server",
            "client_env": "/etc/default/aegis-client",
            "server_config": "/etc/aegis/server/aegis-server.toml",
            "client_config": "/etc/aegis/client/aegis.toml",
        },
        "files": files,
    });
    write_json(&package_dir.join("package-root.manifest.json"), &manifest)?;
    Ok(())
}

pub fn build_release_bundle_manifest(
    bundle_dir: &Path,
    version: &str,
    arch: &str,
    target_triple: &str,
    git_sha: &str,
    build_timestamp: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    build_bundle_manifest(
        bundle_dir,
        version,
        arch,
        target_triple,
        git_sha,
        build_timestamp,
        None,
    )
}
pub fn build_administrative_bundle_manifest(
    bundle_dir: &Path,
    version: &str,
    arch: &str,
    target_triple: &str,
    git_sha: &str,
    build_timestamp: &str,
    producer_hash: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    build_bundle_manifest(
        bundle_dir,
        version,
        arch,
        target_triple,
        git_sha,
        build_timestamp,
        Some(producer_hash),
    )
}
fn build_bundle_manifest(
    bundle_dir: &Path,
    version: &str,
    arch: &str,
    target_triple: &str,
    git_sha: &str,
    build_timestamp: &str,
    administrative_producer: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let cargo_lock_sha256 = sha256_of(&bundle_dir.join("Cargo.lock"))?;
    let server_sha256 = sha256_of(&bundle_dir.join("bin/aegis-server"))?;
    let client_sha256 = sha256_of(&bundle_dir.join("bin/aegis-client"))?;
    let admin_measure = administrative_producer
        .map(|expected| {
            crate::private_research_delivery::admit_administrative(
                bundle_dir,
                arch,
                target_triple,
                expected,
            )
        })
        .transpose()?;
    let research = if admin_measure.is_some() {
        None
    } else {
        crate::research_operator_delivery::admit(
            bundle_dir,
            git_sha,
            &cargo_lock_sha256,
            arch,
            target_triple,
        )?
    };
    let (mut files, checksums) = checksums_for_dir(bundle_dir)?;
    if let Some(research) = &research {
        let leaves = research["leaf_sha256"]
            .as_object()
            .ok_or("research leaf inventory missing")?;
        for (path, digest) in leaves {
            let expected = format!(
                "{}  {path}",
                digest.as_str().ok_or("research digest missing")?
            );
            if !checksums.contains(&expected) {
                return Err("research snapshot differs from bundle checksums".into());
            }
        }
    }
    let release_max_glibc =
        std::env::var("AEGIS_RELEASE_MAX_GLIBC").unwrap_or_else(|_| "unknown".to_string());
    let server_required_glibc =
        std::env::var("AEGIS_SERVER_REQUIRED_GLIBC").unwrap_or_else(|_| "unknown".to_string());
    let client_required_glibc =
        std::env::var("AEGIS_CLIENT_REQUIRED_GLIBC").unwrap_or_else(|_| "unknown".to_string());
    write_text(
        &bundle_dir.join("SHA256SUMS"),
        &(checksums.join("\n") + "\n"),
    )?;
    files.push("SHA256SUMS".to_string());
    let mut manifest = json!({
        "schema": "aegis_release_bundle_manifest_v2",
        "bundle_name": bundle_dir.file_name().and_then(|v| v.to_str()).unwrap_or_default(),
        "version": version,
        "git_sha": git_sha,
        "build_timestamp": build_timestamp,
        "platform": "linux",
        "arch": arch,
        "target_triple": target_triple,
        "cargo_lock_sha256": cargo_lock_sha256,
        "runtime_abi": {
            "libc_family": "glibc",
            "generic_linux_min_glibc": release_max_glibc,
            "installer_preflight": "candidate --version before install-prefix mutation",
            "binary_required_glibc": {
                "aegis-server": server_required_glibc,
                "aegis-client": client_required_glibc,
            },
        },
        "binaries": {
            "aegis-server": {
                "path": "bin/aegis-server",
                "sha256": server_sha256,
                "features": [],
            },
            "aegis-client": {
                "path": "bin/aegis-client",
                "sha256": client_sha256,
                "features": ["raw-socket", "chrome-like-tls", "chrome-like-quic"],
            },
        },
        "install_entrypoints": [
            "./install.sh server",
            "./install.sh client --bundle /path/to/client-bundle",
        ],
        "contains_prebuilt_binaries": [
            "bin/aegis-server",
            "bin/aegis-client",
        ],
        "systemd_templates": [
            "packaging/systemd/aegis-server.service",
            "packaging/systemd/aegis-client.service",
            "packaging/systemd/aegis-auto-config.service",
            "packaging/systemd/aegis-auto-capture-topology.service",
            "packaging/systemd/aegis-auto-guardian-watchdog.service",
            "packaging/systemd/aegis-auto-guardian.service",
            "packaging/systemd/aegis-auto-terminal-a@.service",
            "packaging/systemd/aegis-auto-terminal-b@.service",
            "packaging/systemd/aegis-auto-terminal-observer.service",
            "packaging/systemd/aegis-auto-terminal-transition.service",
            "packaging/systemd/aegis-auto-trace-rollback-actor.service",
            "packaging/systemd/aegis-auto-trace-rollback.service",
            "packaging/systemd/aegis-auto-trace-rollback.timer",
            "packaging/systemd/aegis-auto-witness-topology.service",
            "packaging/systemd/aegis-foreign-policy-monitor.service",
            "packaging/systemd/aegis-auto-clean-shutdown.service",
            "packaging/systemd/aegis-device-dhcp-refresh.service",
            "packaging/systemd/aegis-device-dhcp-refresh.timer",
        ],
        "helper_scripts": HELPER_SCRIPTS,
        "files": files,
    });
    if let Some(digest) = admin_measure {
        manifest["distribution"] = json!("private_administrative_operator");
        manifest["binaries"]["aegis-measure"] = json!({"path":"bin/aegis-measure", "sha256":digest,
            "purpose":"administrative_host_and_release_commands", "exclusive_research_surface":false});
        manifest["contains_prebuilt_binaries"]
            .as_array_mut()
            .ok_or("binary inventory missing")?
            .push(json!("bin/aegis-measure"));
        manifest["runtime_abi"]["binary_required_glibc"]["aegis-measure"] =
            json!(std::env::var("AEGIS_ADMIN_MEASURE_REQUIRED_GLIBC")
                .unwrap_or_else(|_| "unknown".into()));
    }
    if let Some(research) = research {
        for info in research["tools"]
            .as_array()
            .ok_or("research tools missing")?
        {
            let name = info["tool"].as_str().ok_or("research role missing")?;
            manifest["binaries"][name] = json!({"path":format!("bin/{name}"),"sha256":info["binary_sha256"],"crate_version":info["crate_version"],"features":[],"build_info":info});
            manifest["contains_prebuilt_binaries"]
                .as_array_mut()
                .ok_or("binary inventory missing")?
                .push(json!(format!("bin/{name}")));
        }
        manifest["research_operators"] = research;
        manifest["runtime_abi"]["binary_required_glibc"]["aegis-measure"] = json!(std::env::var(
            "AEGIS_MEASURE_REQUIRED_GLIBC"
        )
        .unwrap_or_else(|_| "unknown".into()));
        manifest["runtime_abi"]["binary_required_glibc"]["aegis-transport-lab"] =
            json!(std::env::var("AEGIS_TRANSPORT_LAB_REQUIRED_GLIBC")
                .unwrap_or_else(|_| "unknown".into()));
    }
    let bridge = bundle_dir.join("bin/aegis-geneva-bridge");
    if bridge.exists() {
        manifest["binaries"]["aegis-geneva-bridge"] = json!({
            "path":"bin/aegis-geneva-bridge", "sha256":sha256_of(&bridge)?,
            "features":["live-linux"], "scope":"opt-in isolated Ethernet/IPv4 bridge",
        });
        manifest["runtime_abi"]["binary_required_glibc"]["aegis-geneva-bridge"] =
            json!(std::env::var("AEGIS_GENEVA_REQUIRED_GLIBC")
                .unwrap_or_else(|_| "unknown".to_string()));
        manifest["contains_prebuilt_binaries"]
            .as_array_mut()
            .ok_or("invalid binaries array")?
            .push(json!("bin/aegis-geneva-bridge"));
        manifest["install_entrypoints"]
            .as_array_mut()
            .ok_or("invalid install array")?
            .push(json!(
                "./install.sh geneva-bridge --prefix /absolute/new/prefix"
            ));
    }
    if bundle_dir
        .join("tools/geneva/install-relay-profile.sh")
        .exists()
    {
        manifest["install_entrypoints"]
            .as_array_mut()
            .ok_or("invalid install array")?
            .push(json!(
                "./install.sh relay-geneva-profile --manifest /root/accepted-public-profile.json"
            ));
        manifest["systemd_templates"]
            .as_array_mut()
            .ok_or("invalid template array")?
            .push(json!("packaging/systemd/25-relay-geneva-profile.conf"));
    }
    if bundle_dir
        .join("tools/geneva/uninstall-relay-profile.sh")
        .exists()
    {
        manifest["install_entrypoints"]
            .as_array_mut()
            .ok_or("invalid install array")?
            .push(json!(
                "./install.sh relay-geneva-profile-remove [--resume-token TOKEN]"
            ));
    }
    write_json(&bundle_dir.join("bundle.manifest.json"), &manifest)?;
    Ok(())
}

pub fn build_macos_client_tarball_manifest(
    bundle_dir: &Path,
    version: &str,
    arch: &str,
    target_triple: &str,
    git_sha: &str,
    build_timestamp: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let entries = file_entries_for_dir(bundle_dir)?;
    let manifest = json!({
        "schema": "aegis_macos_client_tarball_manifest_v1",
        "package": "aegis-client",
        "version": version,
        "git_sha": git_sha,
        "build_timestamp": build_timestamp,
        "platform": "macos",
        "arch": arch,
        "target_triple": target_triple,
        "entries": entries,
    });
    write_json(
        &bundle_dir.join("macos-client-bundle.manifest.json"),
        &manifest,
    )?;
    Ok(())
}

pub fn write_archive_sha256(
    archive: &Path,
    sha256_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let digest = sha256_of(archive)?;
    let name = archive
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    write_text(sha256_path, &format!("{digest}  {name}\n"))?;
    Ok(())
}

pub fn write_deb_md5sums(
    stage_dir: &Path,
    debian_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut paths = Vec::new();
    collect_files(stage_dir, stage_dir, &mut paths)?;
    paths.sort();
    let mut entries = Vec::new();
    for rel in paths {
        let path = stage_dir.join(&rel);
        if path.starts_with(debian_dir) {
            continue;
        }
        let digest = md5::compute(fs::read(&path)?);
        entries.push(format!("{digest:x}  {rel}"));
    }
    write_text(&debian_dir.join("md5sums"), &(entries.join("\n") + "\n"))?;
    Ok(())
}

pub fn build_split_deb_manifest(
    output_dir: &Path,
    version: &str,
    deb_arch: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = json!({
        "version": version,
        "deb_arch": deb_arch,
        "packages": {
            "aegis-server": {
                "deb_file": format!("aegis-server_{version}_{deb_arch}.deb"),
                "contains": [
                    "/usr/local/bin/aegis-server",
                    "/usr/lib/systemd/system/aegis-server.service",
                    "/usr/lib/sysusers.d/aegis-server.conf",
                    "/usr/lib/tmpfiles.d/aegis-server.conf",
                    "/etc/default/aegis-server",
                    "/usr/share/aegis/examples/aegis-server.toml.example",
                    "/usr/share/aegis/scripts/build-mimicry-wire-witness-summary.sh",
                    "/usr/share/aegis/scripts/build-post-release-stealth-wave-summary.sh",
                    "/usr/share/aegis/scripts/bootstrap-wide-linux-validation-host.sh",
                    "/usr/share/aegis/scripts/build-ubuntu-controlled-pilot-bundle.sh",
                    "/usr/share/aegis/scripts/build-ubuntu-controlled-pilot-playbook.sh",
                    "/usr/share/aegis/scripts/build-ubuntu-controlled-pilot-review-bundle.sh",
                    "/usr/share/aegis/scripts/build-ubuntu-field-pilot-remote-bundle.sh",
                    "/usr/share/aegis/scripts/build-ubuntu-mimicry-next-contour.sh",
                    "/usr/share/aegis/scripts/build-ubuntu-operator-reapply-canary.sh",
                    "/usr/share/aegis/scripts/build-ubuntu-release-review.sh",
                    "/usr/share/aegis/scripts/build-ubuntu-release-wave-bundle.sh",
                    "/usr/share/aegis/scripts/generate-relay-materials.sh",
                    "/usr/share/aegis/scripts/mimicry-wire-validation-contract.sh",
                    "/usr/share/aegis/scripts/package-client-bundle.sh",
                    "/usr/share/aegis/scripts/render-client-bundle.sh",
                    "/usr/share/aegis/scripts/setup-wide-linux-redirect.sh",
                    "/usr/share/aegis/scripts/setup-wide-linux-tproxy.sh",
                    "/usr/share/aegis/scripts/ubuntu-release-wave-status.sh",
                    "/usr/share/aegis/scripts/validate-debian-package-host.sh",
                    "/usr/share/aegis/scripts/validate-mimicry-wire-host.sh",
                    "/usr/lib/systemd/system-preset/90-aegis-server.preset",
                    "/usr/share/doc/aegis/README.server.Debian",
                ],
                "maintainer_policy": {
                    "postinst_preset_unit": "aegis-server.service",
                    "prerm_disable_unit": "aegis-server.service",
                    "postrm_purge_tmpfiles": "/usr/lib/tmpfiles.d/aegis-server.conf",
                },
            },
            "aegis-client": {
                "deb_file": format!("aegis-client_{version}_{deb_arch}.deb"),
                "contains": [
                    "/usr/local/bin/aegis-client",
                    "/usr/lib/systemd/system/aegis-client.service",
                    "/usr/lib/tmpfiles.d/aegis-client.conf",
                    "/usr/lib/systemd/system-preset/90-aegis-client.preset",
                    "/usr/share/doc/aegis/README.client.Debian",
                    "/etc/default/aegis-client",
                    "/usr/share/aegis/examples/config.example.toml",
                ],
                "maintainer_policy": {
                    "postinst_preset_unit": "aegis-client.service",
                    "prerm_disable_unit": "aegis-client.service",
                    "postrm_purge_tmpfiles": "/usr/lib/tmpfiles.d/aegis-client.conf",
                },
            },
        },
    });
    write_json(
        &output_dir.join("split-deb-packages.manifest.json"),
        &manifest,
    )?;
    Ok(())
}

pub fn build_deb_package_manifest(
    output_dir: &Path,
    deb_name: &str,
    version: &str,
    deb_arch: &str,
    rootfs_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = json!({
        "package_name": "aegis",
        "version": version,
        "deb_arch": deb_arch,
        "deb_file": deb_name,
        "contains_binaries": [
            "/usr/local/bin/aegis-server",
            "/usr/local/bin/aegis-client",
        ],
        "contains_units": [
            "/usr/lib/systemd/system/aegis-server.service",
            "/usr/lib/systemd/system/aegis-client.service",
        ],
        "contains_policy_assets": [
            "/usr/lib/systemd/system-preset/90-aegis.preset",
            "/usr/share/doc/aegis/README.Debian",
        ],
        "contains_service_metadata": [
            "/usr/lib/sysusers.d/aegis-server.conf",
            "/usr/lib/tmpfiles.d/aegis-server.conf",
            "/usr/lib/tmpfiles.d/aegis-client.conf",
        ],
        "maintainer_policy": {
            "postinst_preset_units": [
                "aegis-server.service",
                "aegis-client.service",
            ],
            "prerm_disable_units": [
                "aegis-server.service",
                "aegis-client.service",
            ],
            "postrm_purge_tmpfiles": [
                "/usr/lib/tmpfiles.d/aegis-server.conf",
                "/usr/lib/tmpfiles.d/aegis-client.conf",
            ],
        },
        "package_root_source": rootfs_dir.display().to_string(),
    });
    write_json(&output_dir.join("deb-package.manifest.json"), &manifest)?;
    Ok(())
}

pub fn build_rpm_packages_manifest(
    output_dir: &Path,
    version: &str,
    arch: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut packages = serde_json::Map::new();
    for package_name in ["aegis-server", "aegis-client"] {
        let rpm_name = find_rpm(output_dir, package_name, version, arch)?;
        let rpm_path = output_dir.join(&rpm_name);
        let sha_name = format!("{rpm_name}.sha256");
        write_archive_sha256(&rpm_path, &output_dir.join(&sha_name))?;
        packages.insert(
            package_name.to_string(),
            json!({
                "rpm_file": rpm_name,
                "sha256_file": sha_name,
                "maintainer_policy": {
                    "postinst_preset_unit": format!("{package_name}.service"),
                    "prerm_disable_unit": format!("{package_name}.service"),
                },
            }),
        );
    }
    let manifest = json!({
        "version": version,
        "arch": arch,
        "packages": packages,
    });
    write_json(&output_dir.join("rpm-packages.manifest.json"), &manifest)?;
    Ok(())
}

fn find_rpm(
    output_dir: &Path,
    package_name: &str,
    version: &str,
    arch: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let prefix = format!("{package_name}-{version}-1");
    let suffix = format!(".{arch}.rpm");
    let mut matches = fs::read_dir(output_dir)?
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.starts_with(&prefix) && name.ends_with(&suffix))
        .collect::<Vec<_>>();
    matches.sort();
    matches
        .into_iter()
        .next()
        .ok_or_else(|| format!("missing rpm for {package_name}").into())
}

fn cargo_target_directory(root: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let output = ProcessCommand::new("cargo")
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(root)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let metadata: Value = serde_json::from_slice(&output.stdout)?;
    metadata["target_directory"]
        .as_str()
        .map(PathBuf::from)
        .ok_or_else(|| "cargo metadata target_directory missing".into())
}

fn server_version(root: &Path) -> Result<String, Box<dyn std::error::Error>> {
    package_version(root, "aegis-server")
}

fn client_version(root: &Path) -> Result<String, Box<dyn std::error::Error>> {
    package_version(root, "aegis-client")
}

pub fn package_version(
    root: &Path,
    package_name: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let raw = fs::read_to_string(root.join(package_name).join("Cargo.toml"))?;
    let parsed = raw.parse::<toml::Value>()?;
    parsed
        .get("package")
        .and_then(|package| package.get("version"))
        .and_then(toml::Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| format!("{package_name} package version missing").into())
}

pub fn check_deb_package_contract_artifacts(
    inputs: DebPackageContractInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_release_contract(inputs.deb_path.is_file(), "missing deb package")?;
    ensure_release_contract(inputs.deb_sha256_path.is_file(), "missing deb checksum")?;
    ensure_release_contract(inputs.manifest_path.is_file(), "missing deb manifest")?;

    let expected_sha = sha256_of(inputs.deb_path)?;
    let stored_sha = fs::read_to_string(inputs.deb_sha256_path)?
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned();
    ensure_release_contract(expected_sha == stored_sha, "deb checksum mismatch")?;

    let manifest = read_json(inputs.manifest_path)?;
    ensure_json_str(&manifest, "package_name", "aegis")?;
    ensure_json_str(&manifest, "deb_arch", inputs.deb_arch)?;
    ensure_string_array_contains(
        &manifest,
        "contains_binaries",
        "/usr/local/bin/aegis-server",
    )?;
    ensure_string_array_contains(
        &manifest,
        "contains_units",
        "/usr/lib/systemd/system/aegis-server.service",
    )?;
    ensure_string_array_contains(
        &manifest,
        "contains_policy_assets",
        "/usr/lib/systemd/system-preset/90-aegis.preset",
    )?;
    ensure_string_array_contains(
        &manifest,
        "contains_policy_assets",
        "/usr/share/doc/aegis/README.Debian",
    )?;
    ensure_string_array_contains(
        &manifest,
        "contains_service_metadata",
        "/usr/lib/sysusers.d/aegis-server.conf",
    )?;
    ensure_string_array_contains(
        &manifest,
        "contains_service_metadata",
        "/usr/lib/tmpfiles.d/aegis-client.conf",
    )?;
    ensure_nested_string_array_eq(
        &manifest,
        &["maintainer_policy", "postinst_preset_units"],
        &["aegis-server.service", "aegis-client.service"],
    )?;
    ensure_nested_string_array_eq(
        &manifest,
        &["maintainer_policy", "prerm_disable_units"],
        &["aegis-server.service", "aegis-client.service"],
    )?;
    ensure_nested_string_array_contains(
        &manifest,
        &["maintainer_policy", "postrm_purge_tmpfiles"],
        "/usr/lib/tmpfiles.d/aegis-server.conf",
    )?;

    let control = fs::read_to_string(inputs.control_dir.join("control"))?;
    let postinst = fs::read_to_string(inputs.control_dir.join("postinst"))?;
    let prerm = fs::read_to_string(inputs.control_dir.join("prerm"))?;
    let postrm = fs::read_to_string(inputs.control_dir.join("postrm"))?;
    let server_unit = fs::read_to_string(
        inputs
            .extract_dir
            .join("usr/lib/systemd/system/aegis-server.service"),
    )?;
    let client_unit = fs::read_to_string(
        inputs
            .extract_dir
            .join("usr/lib/systemd/system/aegis-client.service"),
    )?;

    ensure_contains(&control, &format!("Version: {}", inputs.version))?;
    ensure_contains(&control, &format!("Architecture: {}", inputs.deb_arch))?;
    ensure_contains(&control, "Package: aegis")?;
    ensure_contains(&control, "Depends: systemd, ca-certificates")?;
    ensure_release_contract(
        !server_unit.contains("__AEGIS_"),
        "server unit has template marker",
    )?;
    ensure_release_contract(
        !client_unit.contains("__AEGIS_"),
        "client unit has template marker",
    )?;
    for path in [
        "usr/local/bin/aegis-server",
        "usr/local/bin/aegis-client",
        "usr/lib/systemd/system-preset/90-aegis.preset",
        "usr/lib/sysusers.d/aegis-server.conf",
        "usr/lib/tmpfiles.d/aegis-server.conf",
        "usr/lib/tmpfiles.d/aegis-client.conf",
        "usr/share/aegis/scripts/package-client-bundle.sh",
        "usr/share/doc/aegis/README.Debian",
    ] {
        ensure_release_contract(
            inputs.extract_dir.join(path).is_file(),
            format!("missing extracted file {path}"),
        )?;
    }
    for path in ["postinst", "prerm", "postrm", "md5sums", "conffiles"] {
        ensure_release_contract(
            inputs.control_dir.join(path).is_file(),
            format!("missing control file {path}"),
        )?;
    }
    for needle in [
        "systemd-sysusers /usr/lib/sysusers.d/aegis-server.conf",
        "systemd-tmpfiles --create /usr/lib/tmpfiles.d/aegis-server.conf",
        "systemctl preset aegis-server.service",
        "systemctl preset aegis-client.service",
    ] {
        ensure_contains(&postinst, needle)?;
    }
    for needle in [
        "systemctl --no-reload disable --now aegis-server.service",
        "systemctl --no-reload disable --now aegis-client.service",
    ] {
        ensure_contains(&prerm, needle)?;
    }
    for needle in [
        "systemd-tmpfiles --remove /usr/lib/tmpfiles.d/aegis-server.conf",
        "systemd-tmpfiles --remove /usr/lib/tmpfiles.d/aegis-client.conf",
    ] {
        ensure_contains(&postrm, needle)?;
    }
    Ok(())
}

pub fn check_split_deb_package_contract_artifacts(
    inputs: SplitDebPackageContractInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    for path in [
        inputs.server_deb,
        inputs.client_deb,
        inputs.server_sha256_path,
        inputs.client_sha256_path,
        inputs.manifest_path,
    ] {
        ensure_release_contract(
            path.is_file(),
            format!("missing split deb artifact {path:?}"),
        )?;
    }
    ensure_checksum_matches(inputs.server_deb, inputs.server_sha256_path)?;
    ensure_checksum_matches(inputs.client_deb, inputs.client_sha256_path)?;

    let manifest = read_json(inputs.manifest_path)?;
    ensure_json_str(&manifest, "deb_arch", inputs.deb_arch)?;
    ensure_release_contract(
        manifest
            .get("packages")
            .and_then(Value::as_object)
            .is_some_and(|packages| {
                packages.contains_key("aegis-server") && packages.contains_key("aegis-client")
            }),
        "split deb manifest must list aegis-server and aegis-client",
    )?;
    ensure_nested_json_str(
        &manifest,
        &[
            "packages",
            "aegis-server",
            "maintainer_policy",
            "postinst_preset_unit",
        ],
        "aegis-server.service",
    )?;
    ensure_nested_json_str(
        &manifest,
        &[
            "packages",
            "aegis-client",
            "maintainer_policy",
            "postinst_preset_unit",
        ],
        "aegis-client.service",
    )?;

    let server_control = fs::read_to_string(inputs.server_control_dir.join("control"))?;
    let client_control = fs::read_to_string(inputs.client_control_dir.join("control"))?;
    let server_postinst = fs::read_to_string(inputs.server_control_dir.join("postinst"))?;
    let server_prerm = fs::read_to_string(inputs.server_control_dir.join("prerm"))?;
    let server_postrm = fs::read_to_string(inputs.server_control_dir.join("postrm"))?;
    let client_postinst = fs::read_to_string(inputs.client_control_dir.join("postinst"))?;
    let client_prerm = fs::read_to_string(inputs.client_control_dir.join("prerm"))?;
    let client_postrm = fs::read_to_string(inputs.client_control_dir.join("postrm"))?;

    ensure_contains(&server_control, "Package: aegis-server")?;
    ensure_contains(&server_control, &format!("Version: {}", inputs.version))?;
    ensure_contains(
        &server_control,
        &format!("Architecture: {}", inputs.deb_arch),
    )?;
    ensure_file_present(inputs.server_extract_dir, "usr/local/bin/aegis-server")?;
    ensure_file_absent(inputs.server_extract_dir, "usr/local/bin/aegis-client")?;
    ensure_file_present(
        inputs.server_extract_dir,
        "usr/lib/systemd/system/aegis-server.service",
    )?;
    ensure_file_absent(
        inputs.server_extract_dir,
        "usr/lib/systemd/system/aegis-client.service",
    )?;
    ensure_file_present(
        inputs.server_extract_dir,
        "usr/lib/systemd/system-preset/90-aegis-server.preset",
    )?;
    ensure_file_absent(
        inputs.server_extract_dir,
        "usr/lib/systemd/system-preset/90-aegis-client.preset",
    )?;
    for path in [
        "usr/lib/sysusers.d/aegis-server.conf",
        "usr/lib/tmpfiles.d/aegis-server.conf",
        "usr/share/aegis/scripts/bootstrap-wide-linux-validation-host.sh",
        "usr/share/aegis/scripts/generate-relay-materials.sh",
        "usr/share/aegis/scripts/package-client-bundle.sh",
        "usr/share/aegis/scripts/setup-wide-linux-redirect.sh",
        "usr/share/aegis/scripts/validate-debian-package-host.sh",
        "usr/share/aegis/scripts/build-ubuntu-field-pilot-remote-bundle.sh",
        "usr/share/aegis/scripts/build-post-release-stealth-wave-summary.sh",
        "usr/share/aegis/scripts/build-ubuntu-mimicry-next-contour.sh",
        "usr/share/aegis/scripts/setup-wide-linux-tproxy.sh",
        "usr/share/doc/aegis/README.server.Debian",
        "usr/share/doc/aegis/README.md",
    ] {
        ensure_file_present(inputs.server_extract_dir, path)?;
    }
    ensure_file_absent(
        inputs.server_extract_dir,
        "usr/lib/tmpfiles.d/aegis-client.conf",
    )?;
    ensure_file_absent(
        inputs.server_extract_dir,
        "usr/share/doc/aegis/README.client.Debian",
    )?;
    for needle in [
        "systemd-sysusers /usr/lib/sysusers.d/aegis-server.conf",
        "systemd-tmpfiles --create /usr/lib/tmpfiles.d/aegis-server.conf",
        "systemctl preset aegis-server.service",
    ] {
        ensure_contains(&server_postinst, needle)?;
    }
    ensure_contains(
        &server_prerm,
        "systemctl --no-reload disable --now aegis-server.service",
    )?;
    ensure_contains(
        &server_postrm,
        "systemd-tmpfiles --remove /usr/lib/tmpfiles.d/aegis-server.conf",
    )?;
    ensure_file_text_eq(
        inputs.server_control_dir,
        "conffiles",
        "/etc/default/aegis-server\n",
    )?;

    ensure_contains(&client_control, "Package: aegis-client")?;
    ensure_contains(&client_control, &format!("Version: {}", inputs.version))?;
    ensure_contains(
        &client_control,
        &format!("Architecture: {}", inputs.deb_arch),
    )?;
    ensure_file_present(inputs.client_extract_dir, "usr/local/bin/aegis-client")?;
    ensure_file_absent(inputs.client_extract_dir, "usr/local/bin/aegis-server")?;
    ensure_file_present(
        inputs.client_extract_dir,
        "usr/lib/systemd/system/aegis-client.service",
    )?;
    ensure_file_absent(
        inputs.client_extract_dir,
        "usr/lib/systemd/system/aegis-server.service",
    )?;
    ensure_file_present(
        inputs.client_extract_dir,
        "usr/lib/systemd/system-preset/90-aegis-client.preset",
    )?;
    ensure_file_absent(
        inputs.client_extract_dir,
        "usr/lib/systemd/system-preset/90-aegis-server.preset",
    )?;
    ensure_file_present(
        inputs.client_extract_dir,
        "usr/lib/tmpfiles.d/aegis-client.conf",
    )?;
    ensure_file_absent(
        inputs.client_extract_dir,
        "usr/lib/sysusers.d/aegis-server.conf",
    )?;
    ensure_file_present(
        inputs.client_extract_dir,
        "usr/share/doc/aegis/README.client.Debian",
    )?;
    ensure_file_absent(
        inputs.client_extract_dir,
        "usr/share/doc/aegis/README.server.Debian",
    )?;
    for needle in [
        "systemd-tmpfiles --create /usr/lib/tmpfiles.d/aegis-client.conf",
        "systemctl preset aegis-client.service",
    ] {
        ensure_contains(&client_postinst, needle)?;
    }
    let prerm_roster = check_client_removal_handoff(
        &client_prerm,
        "prerm",
        inputs.client_extract_dir,
        inputs.version,
    )?;
    let postrm_roster = check_client_removal_handoff(
        &client_postrm,
        "postrm",
        inputs.client_extract_dir,
        inputs.version,
    )?;
    ensure_release_contract(
        prerm_roster == postrm_roster,
        "client removal hooks must bind the same protected payload",
    )?;
    for path in [
        "usr/share/aegis/scripts/generate-relay-materials.sh",
        "usr/share/aegis/scripts/bootstrap-wide-linux-validation-host.sh",
        "usr/share/aegis/scripts/setup-wide-linux-redirect.sh",
        "usr/share/aegis/scripts/setup-wide-linux-tproxy.sh",
        "usr/share/aegis/scripts/validate-debian-package-host.sh",
        "usr/share/doc/aegis/README.md",
    ] {
        ensure_file_absent(inputs.client_extract_dir, path)?;
    }
    ensure_file_text_eq(
        inputs.client_control_dir,
        "conffiles",
        "/etc/default/aegis-client\n",
    )?;
    Ok(())
}

const SPLIT_DEB_BUILDER: &str = include_str!("../../../scripts/build-split-deb-packages.sh");

fn client_removal_template() -> Result<String, Box<dyn std::error::Error>> {
    let source = SPLIT_DEB_BUILDER.replace("\r\n", "\n");
    let body = source
        .split_once("<<'PY_REMOVAL'\n")
        .and_then(|(_, rest)| rest.split_once("\nPY_REMOVAL\n"))
        .map(|(body, _)| body)
        .ok_or("authenticated client removal template missing")?;
    Ok(format!("{body}\n"))
}

fn client_removal_paths() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let source = SPLIT_DEB_BUILDER.replace("\r\n", "\n");
    let mut paths = vec!["usr/local/bin/aegis-client".to_owned()];
    for name in ["CLIENT_PROTECTED_HELPER_PATHS", "CLIENT_AUTO_UNIT_PATHS"] {
        let declaration = format!("\n{name}=(\n");
        let body = source
            .split_once(&declaration)
            .and_then(|(_, rest)| rest.split_once("\n)"))
            .map(|(body, _)| body)
            .ok_or("client protected package roster missing")?;
        for line in body.lines() {
            let path = line
                .strip_prefix("  \"")
                .and_then(|value| value.strip_suffix('"'))
                .ok_or("client protected package roster syntax changed")?;
            ensure_release_contract(
                !path.starts_with('/')
                    && !path.split('/').any(|part| part.is_empty() || part == "..")
                    && path
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"_./@-".contains(&byte))
                    && !paths.iter().any(|existing| existing == path),
                "invalid or duplicate protected package path",
            )?;
            paths.push(path.to_owned());
        }
    }
    Ok(paths)
}

fn client_payload_modes(path: &str) -> Result<(u64, u64), Box<dyn std::error::Error>> {
    if path == "usr/local/bin/aegis-client" {
        return Ok((0o755, 0o555));
    }
    if path.starts_with("etc/systemd/system/") {
        return Ok((0o644, 0o444));
    }
    let name = path
        .strip_prefix("usr/local/lib/aegis/helpers/")
        .ok_or("unexpected client protected payload path")?;
    let data = name.starts_with("lib/") && (name.ends_with(".py") || name.ends_with(".json"));
    let protected = name.starts_with("lib/aegis_auto_")
        || matches!(
            name,
            "lib/aegis_installer_auto_v2.py"
                | "lib/aegis_initrd_policy.py"
                | "lib/aegis_initrd_classic.py"
                | "lib/aegis-auto-terminal-hook"
        );
    let source_read_only = data
        || matches!(
            name,
            "lib/root-state.sh"
                | "lib/aegis-auto-terminal-hook"
                | "janitor-wide-linux-tproxy.sh"
                | "setup-wide-linux-tproxy.sh"
        );
    Ok((
        if protected { 0o500 } else { 0o755 },
        if source_read_only { 0o444 } else { 0o555 },
    ))
}

fn check_client_removal_handoff(
    script: &str,
    operation: &str,
    extracted: &Path,
    version: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    ensure_release_contract(
        matches!(operation, "prerm" | "postrm"),
        "unknown client removal hook",
    )?;
    let bindings: Vec<_> = script
        .lines()
        .filter(|line| line.starts_with("EXPECTED = json.loads("))
        .collect();
    ensure_release_contract(
        bindings.len() == 1,
        "client removal payload binding missing",
    )?;
    // The producer emits repr(canonical ASCII JSON), not executable input.
    // Parse JSON directly; never evaluate the hook or a Python expression.
    let raw = bindings[0]
        .strip_prefix("EXPECTED = json.loads('")
        .and_then(|value| value.strip_suffix("')"))
        .ok_or("client removal payload must be a literal JSON binding")?;
    ensure_release_contract(
        raw.len() <= 64 << 10 && !raw.contains(['\'', '\\', '\r', '\n']),
        "client removal payload literal refused",
    )?;
    let roster: Value = serde_json::from_str(raw)?;
    ensure_release_contract(
        serde_json::to_string(&roster)? == raw,
        "client removal payload must be canonical JSON without duplicate keys",
    )?;
    let hook = format!("HOOK = '{operation}'");
    ensure_release_contract(
        script.lines().filter(|line| *line == hook).count() == 1,
        "client removal hook operation mismatch",
    )?;
    let normalized = script
        .replacen(
            bindings[0],
            "EXPECTED = json.loads(AEGIS_INCOMING_ROSTER_JSON)",
            1,
        )
        .replacen(&hook, "HOOK = 'AEGIS_REMOVAL_HOOK'", 1);
    ensure_release_contract(
        normalized == client_removal_template()?,
        "client removal hook differs from the authenticated typed handoff",
    )?;
    let object = roster
        .as_object()
        .ok_or("client removal payload is not an object")?;
    let files = roster["files"]
        .as_object()
        .ok_or("client removal files missing")?;
    let paths = client_removal_paths()?;
    let install_sha = format!(
        "{:x}",
        Sha256::digest(include_bytes!("../../../install.sh"))
    );
    ensure_release_contract(
        object.len() == 3
            && roster["install_sha256"].as_str() == Some(install_sha.as_str())
            && roster["package_version"].as_str() == Some(version)
            && files.len() == paths.len(),
        "client removal source, version or protected roster mismatch",
    )?;
    for relative in paths {
        let entry = files
            .get(&relative)
            .and_then(Value::as_object)
            .ok_or("client removal protected file missing")?;
        let (mode, retained) = client_payload_modes(&relative)?;
        let path = extracted.join(&relative);
        let info = fs::symlink_metadata(&path)?;
        ensure_release_contract(
            info.file_type().is_file()
                && entry.len() == 3
                && entry.get("mode").and_then(Value::as_u64) == Some(mode)
                && entry.get("retained_mode").and_then(Value::as_u64) == Some(retained)
                && entry.get("sha256").and_then(Value::as_str) == Some(sha256_of(&path)?.as_str()),
            format!("client removal protected payload mismatch: {relative}"),
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            ensure_release_contract(
                u64::from(info.permissions().mode() & 0o7777) == mode && info.nlink() == 1,
                format!("client removal protected mode or link mismatch: {relative}"),
            )?;
        }
    }
    Ok(roster)
}

fn checksums_for_dir(
    root: &Path,
) -> Result<(Vec<String>, Vec<String>), Box<dyn std::error::Error>> {
    let mut paths = Vec::new();
    collect_files(root, root, &mut paths)?;
    paths.sort();
    let mut checksums = Vec::new();
    for rel in &paths {
        let digest = sha256_of(&root.join(rel))?;
        checksums.push(format!("{digest}  {rel}"));
    }
    Ok((paths, checksums))
}

fn ensure_release_contract(
    condition: bool,
    message: impl Into<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if condition {
        Ok(())
    } else {
        Err(format!("release artifact contract failed: {}", message.into()).into())
    }
}

fn ensure_contains(haystack: &str, needle: &str) -> Result<(), Box<dyn std::error::Error>> {
    ensure_release_contract(
        haystack.contains(needle),
        format!("expected text to contain {needle:?}"),
    )
}

fn ensure_json_str(
    value: &Value,
    field: &str,
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_release_contract(
        value.get(field).and_then(Value::as_str) == Some(expected),
        format!("{field} must equal {expected:?}"),
    )
}

fn ensure_nested_json_str(
    value: &Value,
    path: &[&str],
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_release_contract(
        nested_value(value, path).and_then(Value::as_str) == Some(expected),
        format!("{} must equal {expected:?}", path.join(".")),
    )
}

fn ensure_string_array_contains(
    value: &Value,
    field: &str,
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_release_contract(
        value
            .get(field)
            .and_then(Value::as_array)
            .map(|items| items.iter().any(|item| item.as_str() == Some(expected)))
            .unwrap_or(false),
        format!("{field} must contain {expected:?}"),
    )
}

fn ensure_nested_string_array_eq(
    value: &Value,
    path: &[&str],
    expected: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = nested_value(value, path)
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    ensure_release_contract(
        actual == expected,
        format!("{} must equal {expected:?}", path.join(".")),
    )
}

fn ensure_nested_string_array_contains(
    value: &Value,
    path: &[&str],
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_release_contract(
        nested_value(value, path)
            .and_then(Value::as_array)
            .map(|items| items.iter().any(|item| item.as_str() == Some(expected)))
            .unwrap_or(false),
        format!("{} must contain {expected:?}", path.join(".")),
    )
}

fn ensure_checksum_matches(
    deb_path: &Path,
    sha_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let expected_sha = sha256_of(deb_path)?;
    let stored_sha = fs::read_to_string(sha_path)?
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned();
    ensure_release_contract(
        expected_sha == stored_sha,
        format!("checksum mismatch for {}", deb_path.display()),
    )
}

fn ensure_file_present(base: &Path, rel: &str) -> Result<(), Box<dyn std::error::Error>> {
    ensure_release_contract(base.join(rel).is_file(), format!("missing file {rel}"))
}

fn ensure_file_absent(base: &Path, rel: &str) -> Result<(), Box<dyn std::error::Error>> {
    ensure_release_contract(!base.join(rel).exists(), format!("unexpected file {rel}"))
}

fn ensure_file_text_eq(
    base: &Path,
    rel: &str,
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = fs::read_to_string(base.join(rel))?;
    ensure_release_contract(actual == expected, format!("{rel} must equal {expected:?}"))
}

fn nested_value<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    Some(current)
}

fn collect_files(
    base: &Path,
    dir: &Path,
    files: &mut Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_files(base, &path, files)?;
        } else if path.is_file() {
            files.push(
                path.strip_prefix(base)?
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
    Ok(())
}

fn file_entries_for_dir(root: &Path) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    let mut paths = Vec::new();
    collect_files(root, root, &mut paths)?;
    paths.sort();
    let mut entries = Vec::new();
    for rel in paths {
        let path = root.join(&rel);
        let metadata = fs::metadata(&path)?;
        entries.push(json!({
            "path": rel,
            "size": metadata.len(),
            "sha256": sha256_of(&path)?,
            "mode": file_mode(&metadata),
        }));
    }
    Ok(entries)
}

#[cfg(unix)]
fn file_mode(metadata: &fs::Metadata) -> String {
    format!("{:#o}", metadata.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
fn file_mode(metadata: &fs::Metadata) -> String {
    if metadata.permissions().readonly() {
        "0o444".to_string()
    } else {
        "0o666".to_string()
    }
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

#[cfg(test)]
mod geneva_bridge_tests {
    use super::*;
    #[test]
    fn operator_manifest_and_file_sums_cover_optional_bridge_bytes() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "aegis-geneva-manifest-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("bin")).unwrap();
        for (name, data) in [
            ("Cargo.lock", b"fixture-lock".as_slice()),
            ("bin/aegis-server", b"fixture-server"),
            ("bin/aegis-client", b"fixture-client"),
            ("bin/aegis-geneva-bridge", b"fixture-bridge-one"),
        ] {
            fs::write(root.join(name), data).unwrap();
        }
        build_release_bundle_manifest(
            &root,
            "0.3.50",
            "x86_64",
            "x86_64-unknown-linux-gnu",
            "fixture-source",
            "fixture-time",
        )
        .unwrap();
        let first = read_json(&root.join("bundle.manifest.json")).unwrap();
        let sha = sha256_of(&root.join("bin/aegis-geneva-bridge")).unwrap();
        assert_eq!(first["binaries"]["aegis-geneva-bridge"]["sha256"], sha);
        assert!(fs::read_to_string(root.join("SHA256SUMS"))
            .unwrap()
            .contains(&format!("{sha}  bin/aegis-geneva-bridge")));
        assert!(first["files"]
            .as_array()
            .unwrap()
            .contains(&json!("bin/aegis-geneva-bridge")));
        fs::remove_file(root.join("bundle.manifest.json")).unwrap();
        fs::remove_file(root.join("SHA256SUMS")).unwrap();
        fs::write(root.join("bin/aegis-geneva-bridge"), b"fixture-bridge-two").unwrap();
        build_release_bundle_manifest(
            &root,
            "0.3.50",
            "x86_64",
            "x86_64-unknown-linux-gnu",
            "fixture-source",
            "fixture-time",
        )
        .unwrap();
        let second = read_json(&root.join("bundle.manifest.json")).unwrap();
        assert_ne!(
            first["binaries"]["aegis-geneva-bridge"]["sha256"],
            second["binaries"]["aegis-geneva-bridge"]["sha256"]
        );
        fs::remove_dir_all(&root).unwrap();
    }
}

#[cfg(test)]
mod systemd_template_tests {
    use super::*;

    // The release bundle copies all of packaging/, and the package root
    // installs exactly AUTO_SYSTEMD_UNITS. The manifest must name the same
    // units in the same order, so a unit added to the package cannot ship
    // without its template entry (the admin/research split contract checks
    // the bundle against this list).
    #[test]
    fn manifest_systemd_templates_are_the_packaged_auto_units() {
        let builder = include_str!("../../../scripts/build-package-root.sh").replace("\r\n", "\n");
        let declarations = builder
            .split_once("\nAUTO_SYSTEMD_UNITS=(\n")
            .expect("package-root AUTO unit roster missing")
            .1
            .split_once("\n)")
            .expect("package-root AUTO unit roster end missing")
            .0;
        let mut expected = vec![
            json!("packaging/systemd/aegis-server.service"),
            json!("packaging/systemd/aegis-client.service"),
        ];
        for line in declarations.lines() {
            let unit = line
                .strip_prefix("  \"")
                .and_then(|value| value.strip_suffix('"'))
                .expect("package-root AUTO unit declaration syntax changed");
            assert!(unit.starts_with("aegis-") && !unit.contains('/'));
            expected.push(json!(format!("packaging/systemd/{unit}")));
        }
        assert!(expected.contains(&json!(
            "packaging/systemd/aegis-auto-clean-shutdown.service"
        )));
        for terminal in [
            "packaging/systemd/aegis-auto-terminal-a@.service",
            "packaging/systemd/aegis-auto-terminal-b@.service",
            "packaging/systemd/aegis-auto-terminal-observer.service",
            "packaging/systemd/aegis-auto-terminal-transition.service",
        ] {
            assert!(expected.contains(&json!(terminal)));
        }
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        fs::create_dir(root.join("bin")).unwrap();
        for (name, data) in [
            ("Cargo.lock", b"controlled-lock".as_slice()),
            ("bin/aegis-server", b"controlled-server-metadata"),
            ("bin/aegis-client", b"controlled-client-metadata"),
        ] {
            fs::write(root.join(name), data).unwrap();
        }
        build_release_bundle_manifest(
            root,
            "controlled-version",
            "x86_64",
            "x86_64-unknown-linux-gnu",
            "controlled-source",
            "controlled-time",
        )
        .unwrap();
        let manifest = read_json(&root.join("bundle.manifest.json")).unwrap();
        assert_eq!(manifest["systemd_templates"], json!(expected));
    }
}

#[cfg(test)]
mod helper_inventory_tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    const HELPER_SOURCE_BYTES: &[(&str, &[u8])] = &[
        (
            "scripts/lib/root-state.sh",
            include_bytes!("../../../scripts/lib/root-state.sh"),
        ),
        (
            "scripts/lib/aegis_installer_auto_v2.py",
            include_bytes!("../../../scripts/lib/aegis_installer_auto_v2.py"),
        ),
        (
            "scripts/lib/aegis_auto_uninstall_journal.py",
            include_bytes!("../../../scripts/lib/aegis_auto_uninstall_journal.py"),
        ),
        (
            "scripts/lib/aegis_auto_capture.py",
            include_bytes!("../../../scripts/lib/aegis_auto_capture.py"),
        ),
        (
            "scripts/lib/aegis_auto_capture_topology.py",
            include_bytes!("../../../scripts/lib/aegis_auto_capture_topology.py"),
        ),
        (
            "scripts/lib/aegis_auto_endpoint.py",
            include_bytes!("../../../scripts/lib/aegis_auto_endpoint.py"),
        ),
        (
            "scripts/lib/aegis_auto_guard_policy.py",
            include_bytes!("../../../scripts/lib/aegis_auto_guard_policy.py"),
        ),
        (
            "scripts/lib/aegis_auto_foreign_policy.py",
            include_bytes!("../../../scripts/lib/aegis_auto_foreign_policy.py"),
        ),
        (
            "scripts/lib/aegis_auto_foreign_monitor.py",
            include_bytes!("../../../scripts/lib/aegis_auto_foreign_monitor.py"),
        ),
        (
            "scripts/lib/aegis_auto_ufw_pins.json",
            include_bytes!("../../../scripts/lib/aegis_auto_ufw_pins.json"),
        ),
        (
            "scripts/lib/aegis_initrd_policy.py",
            include_bytes!("../../../scripts/lib/aegis_initrd_policy.py"),
        ),
        (
            "scripts/lib/aegis_initrd_classic.py",
            include_bytes!("../../../scripts/lib/aegis_initrd_classic.py"),
        ),
        (
            "scripts/lib/aegis_auto_guardian.py",
            include_bytes!("../../../scripts/lib/aegis_auto_guardian.py"),
        ),
        (
            "scripts/lib/aegis_auto_guardian_watchdog.py",
            include_bytes!("../../../scripts/lib/aegis_auto_guardian_watchdog.py"),
        ),
        (
            "scripts/lib/aegis_auto_terminal_witness.py",
            include_bytes!("../../../scripts/lib/aegis_auto_terminal_witness.py"),
        ),
        (
            "scripts/lib/aegis_auto_terminal_boot_store.py",
            include_bytes!("../../../scripts/lib/aegis_auto_terminal_boot_store.py"),
        ),
        (
            "scripts/lib/aegis_auto_terminal_register.py",
            include_bytes!("../../../scripts/lib/aegis_auto_terminal_register.py"),
        ),
        (
            "scripts/lib/aegis_auto_boot_transition.py",
            include_bytes!("../../../scripts/lib/aegis_auto_boot_transition.py"),
        ),
        (
            "scripts/lib/aegis_auto_launch.py",
            include_bytes!("../../../scripts/lib/aegis_auto_launch.py"),
        ),
        (
            "scripts/lib/aegis_auto_native_witness.py",
            include_bytes!("../../../scripts/lib/aegis_auto_native_witness.py"),
        ),
        (
            "scripts/lib/aegis_auto_sink.py",
            include_bytes!("../../../scripts/lib/aegis_auto_sink.py"),
        ),
        (
            "scripts/lib/aegis_auto_trace_rollback.py",
            include_bytes!("../../../scripts/lib/aegis_auto_trace_rollback.py"),
        ),
        (
            "scripts/lib/aegis_auto_witness_topology.py",
            include_bytes!("../../../scripts/lib/aegis_auto_witness_topology.py"),
        ),
        (
            "scripts/aegis-device-egress-guard.sh",
            include_bytes!("../../../scripts/aegis-device-egress-guard.sh"),
        ),
        (
            "scripts/aegis-relay-geneva-profile.sh",
            include_bytes!("../../../scripts/aegis-relay-geneva-profile.sh"),
        ),
        (
            "scripts/bootstrap-wide-linux-validation-host.sh",
            include_bytes!("../../../scripts/bootstrap-wide-linux-validation-host.sh"),
        ),
        (
            "scripts/generate-relay-materials.sh",
            include_bytes!("../../../scripts/generate-relay-materials.sh"),
        ),
        (
            "scripts/render-client-bundle.sh",
            include_bytes!("../../../scripts/render-client-bundle.sh"),
        ),
        (
            "scripts/package-client-bundle.sh",
            include_bytes!("../../../scripts/package-client-bundle.sh"),
        ),
        (
            "scripts/issue-fronted-bundle.sh",
            include_bytes!("../../../scripts/issue-fronted-bundle.sh"),
        ),
        (
            "scripts/purge-installed-aegis.sh",
            include_bytes!("../../../scripts/purge-installed-aegis.sh"),
        ),
        (
            "scripts/aegis-ubuntu-uninstall.sh",
            include_bytes!("../../../scripts/aegis-ubuntu-uninstall.sh"),
        ),
        (
            "scripts/aegis-origin-guard.sh",
            include_bytes!("../../../scripts/aegis-origin-guard.sh"),
        ),
        (
            "scripts/aegis-wide-enable.sh",
            include_bytes!("../../../scripts/aegis-wide-enable.sh"),
        ),
        (
            "scripts/aegis-wide-disable.sh",
            include_bytes!("../../../scripts/aegis-wide-disable.sh"),
        ),
        (
            "scripts/aegis-wide-persist-install.sh",
            include_bytes!("../../../scripts/aegis-wide-persist-install.sh"),
        ),
        (
            "scripts/janitor-wide-linux-tproxy.sh",
            include_bytes!("../../../scripts/janitor-wide-linux-tproxy.sh"),
        ),
        (
            "scripts/setup-wide-linux-redirect.sh",
            include_bytes!("../../../scripts/setup-wide-linux-redirect.sh"),
        ),
        (
            "scripts/setup-wide-linux-tproxy.sh",
            include_bytes!("../../../scripts/setup-wide-linux-tproxy.sh"),
        ),
        (
            "scripts/setup-wide-linux-nfqueue.sh",
            include_bytes!("../../../scripts/setup-wide-linux-nfqueue.sh"),
        ),
        (
            "scripts/aegis-rpi-gateway.sh",
            include_bytes!("../../../scripts/aegis-rpi-gateway.sh"),
        ),
        (
            "scripts/validate-debian-package-host.sh",
            include_bytes!("../../../scripts/validate-debian-package-host.sh"),
        ),
        (
            "scripts/build-ubuntu-controlled-pilot-playbook.sh",
            include_bytes!("../../../scripts/build-ubuntu-controlled-pilot-playbook.sh"),
        ),
        (
            "scripts/build-ubuntu-operator-reapply-canary.sh",
            include_bytes!("../../../scripts/build-ubuntu-operator-reapply-canary.sh"),
        ),
        (
            "scripts/build-ubuntu-controlled-pilot-bundle.sh",
            include_bytes!("../../../scripts/build-ubuntu-controlled-pilot-bundle.sh"),
        ),
        (
            "scripts/build-ubuntu-release-review.sh",
            include_bytes!("../../../scripts/build-ubuntu-release-review.sh"),
        ),
        (
            "scripts/build-ubuntu-controlled-pilot-review-bundle.sh",
            include_bytes!("../../../scripts/build-ubuntu-controlled-pilot-review-bundle.sh"),
        ),
        (
            "scripts/ubuntu-release-wave-status.sh",
            include_bytes!("../../../scripts/ubuntu-release-wave-status.sh"),
        ),
        (
            "scripts/build-ubuntu-release-wave-bundle.sh",
            include_bytes!("../../../scripts/build-ubuntu-release-wave-bundle.sh"),
        ),
        (
            "scripts/build-ubuntu-field-pilot-remote-bundle.sh",
            include_bytes!("../../../scripts/build-ubuntu-field-pilot-remote-bundle.sh"),
        ),
        (
            "scripts/build-post-release-stealth-wave-summary.sh",
            include_bytes!("../../../scripts/build-post-release-stealth-wave-summary.sh"),
        ),
        (
            "scripts/mimicry-wire-validation-contract.sh",
            include_bytes!("../../../scripts/mimicry-wire-validation-contract.sh"),
        ),
        (
            "scripts/build-mimicry-wire-witness-summary.sh",
            include_bytes!("../../../scripts/build-mimicry-wire-witness-summary.sh"),
        ),
        (
            "scripts/validate-mimicry-wire-host.sh",
            include_bytes!("../../../scripts/validate-mimicry-wire-host.sh"),
        ),
        (
            "scripts/build-ubuntu-mimicry-next-contour.sh",
            include_bytes!("../../../scripts/build-ubuntu-mimicry-next-contour.sh"),
        ),
    ];

    // This checks the actual manifest emitter against the separately maintained
    // staging owner. Controlled binary bytes exercise metadata only; the retained
    // Linux archive contract still requires real ELF producers and all nine cases.
    #[test]
    fn actual_bundle_manifest_matches_staged_helpers_and_changed_file_sums() {
        let builder =
            include_str!("../../../scripts/build-release-bundle.sh").replace("\r\n", "\n");
        let declarations = builder
            .split_once("\nHELPER_SCRIPTS=(\n")
            .expect("actual builder helper inventory missing")
            .1
            .split_once("\n)")
            .expect("actual builder helper inventory end missing")
            .0;
        let expected: Vec<String> = declarations
            .lines()
            .map(|line| {
                let leaf = line
                    .strip_prefix("  \"")
                    .and_then(|value| value.strip_suffix('"'))
                    .expect("actual builder helper declaration syntax changed");
                assert!(
                    !leaf.starts_with('/')
                        && (leaf.ends_with(".sh")
                            || leaf.ends_with(".py")
                            || leaf == "lib/aegis_auto_ufw_pins.json")
                );
                assert!(leaf.split('/').all(|part| !part.is_empty() && part != ".."));
                format!("scripts/{leaf}")
            })
            .collect();
        assert_eq!(expected.len(), 55);
        assert_eq!(expected.iter().collect::<BTreeSet<_>>().len(), 55);
        assert!(expected
            .iter()
            .any(|leaf| leaf == "scripts/lib/aegis_installer_auto_v2.py"));
        assert!(expected
            .iter()
            .any(|leaf| leaf == "scripts/setup-wide-linux-nfqueue.sh"));
        let sources: BTreeMap<&str, &[u8]> = HELPER_SOURCE_BYTES.iter().copied().collect();
        assert_eq!(sources.len(), HELPER_SOURCE_BYTES.len());
        assert_eq!(
            sources.keys().copied().collect::<BTreeSet<_>>(),
            expected.iter().map(String::as_str).collect::<BTreeSet<_>>()
        );
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        fs::create_dir(root.join("bin")).unwrap();
        for (name, data) in [
            ("Cargo.lock", b"controlled-lock".as_slice()),
            ("bin/aegis-server", b"controlled-server-metadata"),
            ("bin/aegis-client", b"controlled-client-metadata"),
            ("bin/aegis-geneva-bridge", b"controlled-bridge-metadata"),
        ] {
            fs::write(root.join(name), data).unwrap();
        }
        let mut source_sums = Vec::new();
        for name in &expected {
            let bytes = sources[name.as_str()];
            assert!(!bytes.is_empty() && bytes.len() <= 8_388_608);
            let destination = root.join(name);
            fs::create_dir_all(destination.parent().unwrap()).unwrap();
            fs::write(&destination, bytes).unwrap();
            source_sums.push((name.clone(), sha256_of(&destination).unwrap()));
        }
        let emit = || {
            build_release_bundle_manifest(
                root,
                "controlled-version",
                "x86_64",
                "x86_64-unknown-linux-gnu",
                "controlled-source",
                "controlled-time",
            )
            .unwrap();
            read_json(&root.join("bundle.manifest.json")).unwrap()
        };
        let first = emit();
        let first_sums = fs::read_to_string(root.join("SHA256SUMS")).unwrap();
        let first_files = first["files"].as_array().unwrap();
        for (name, sum) in &source_sums {
            assert!(first_files.contains(&json!(name)));
            assert!(first_sums
                .lines()
                .any(|line| line == format!("{sum}  {name}")));
        }
        let bridge_sum = sha256_of(&root.join("bin/aegis-geneva-bridge")).unwrap();
        assert_eq!(
            first["binaries"]["aegis-geneva-bridge"]["sha256"],
            bridge_sum
        );
        assert!(first_sums
            .lines()
            .any(|line| line == format!("{bridge_sum}  bin/aegis-geneva-bridge")));
        // The same baseline/candidate fixture must establish complete source-bound
        // staging/checksum validity before its one manifest inventory assertion.
        eprintln!(
            "actual_bundle_helper_inventory_validity={}",
            json!({"staged_helpers":expected.len(),"source_bound_helper_sums":source_sums.len(),"original_bridge_sum_valid":true})
        );
        assert_eq!(first["helper_scripts"], json!(expected));

        // A changed staged helper must remain declared and receive a new actual
        // checksum, while every other source-bound helper remains unchanged.
        let changed = "scripts/lib/root-state.sh";
        let old_sum = sha256_of(&root.join(changed)).unwrap();
        fs::remove_file(root.join("bundle.manifest.json")).unwrap();
        fs::remove_file(root.join("SHA256SUMS")).unwrap();
        fs::write(root.join(changed), b"controlled changed helper bytes\n").unwrap();
        let second = emit();
        let new_sum = sha256_of(&root.join(changed)).unwrap();
        assert_ne!(old_sum, new_sum);
        assert_eq!(second["helper_scripts"], json!(expected));
        assert_eq!(first["files"], second["files"]);
        let second_sums = fs::read_to_string(root.join("SHA256SUMS")).unwrap();
        assert!(second_sums
            .lines()
            .any(|line| line == format!("{new_sum}  {changed}")));
        assert!(!second_sums
            .lines()
            .any(|line| line == format!("{old_sum}  {changed}")));
        for (name, sum) in &source_sums {
            if name != changed {
                assert!(second_sums
                    .lines()
                    .any(|line| line == format!("{sum}  {name}")));
            }
        }
        assert_eq!(first["binaries"], second["binaries"]);
    }
}

#[cfg(all(test, unix))]
mod client_removal_handoff_tests {
    use super::*;
    use std::os::unix::fs::symlink;

    const VERSION: &str = "controlled-package-version";
    const COORDINATOR: &str = "usr/local/lib/aegis/helpers/lib/aegis_installer_auto_v2.py";

    fn fixture() -> (tempfile::TempDir, Value) {
        let root = tempfile::tempdir().unwrap();
        let mut files = serde_json::Map::new();
        for relative in client_removal_paths().unwrap() {
            let path = root.path().join(&relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, relative.as_bytes()).unwrap();
            let (mode, retained) = client_payload_modes(&relative).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode as u32)).unwrap();
            files.insert(
                relative,
                json!({"mode": mode, "retained_mode": retained,
                                         "sha256": sha256_of(&path).unwrap()}),
            );
        }
        let roster = json!({"files": files, "package_version": VERSION,
            "install_sha256": format!("{:x}", Sha256::digest(include_bytes!("../../../install.sh")))});
        (root, roster)
    }

    fn hook(roster: &Value, operation: &str) -> String {
        client_removal_template()
            .unwrap()
            .replace(
                "AEGIS_INCOMING_ROSTER_JSON",
                &format!("'{}'", serde_json::to_string(roster).unwrap()),
            )
            .replace("AEGIS_REMOVAL_HOOK", operation)
    }

    #[test]
    fn both_authenticated_phases_bind_the_complete_protected_payload() {
        let (root, roster) = fixture();
        assert_eq!(roster["files"].as_object().unwrap().len(), 51);
        for operation in ["prerm", "postrm"] {
            assert_eq!(
                check_client_removal_handoff(
                    &hook(&roster, operation),
                    operation,
                    root.path(),
                    VERSION
                )
                .unwrap(),
                roster
            );
        }
    }

    #[test]
    fn authentication_teardown_and_cleanup_cannot_be_removed_or_faked() {
        let (root, roster) = fixture();
        for operation in ["prerm", "postrm"] {
            let good = hook(&roster, operation);
            for (before, after) in [
                ("coordinator.passive_package_prerm(EXPECTED)", "{}"),
                (
                    "coordinator.passive_package_postrm(EXPECTED, action)",
                    "None",
                ),
                (
                    "source_bytes(path, mode, EXPECTED['files'][relative]['sha256'])",
                    "path.read_bytes()",
                ),
                (
                    "coordinator._passive_removal_recheck_payload(EXPECTED)",
                    "None",
                ),
                ("'disable', '--now'", "'status'"),
                ("'--remove'", "'--create'"),
                ("sys.exit(1)", "sys.exit(0)"),
            ] {
                let bad = good.replace(before, after);
                assert_ne!(bad, good);
                assert!(
                    check_client_removal_handoff(&bad, operation, root.path(), VERSION).is_err(),
                    "accepted changed {operation}: {before}"
                );
            }
        }
    }

    #[test]
    fn source_version_paths_hashes_and_both_modes_are_required() {
        let (root, roster) = fixture();
        let mut bad = Vec::new();
        let mut value = roster.clone();
        value["install_sha256"] = json!("0".repeat(64));
        bad.push(value);
        let mut value = roster.clone();
        value["package_version"] = json!("other");
        bad.push(value);
        let mut value = roster.clone();
        value["files"].as_object_mut().unwrap().remove(COORDINATOR);
        bad.push(value);
        let mut value = roster.clone();
        value["files"]["/tmp/outside"] = value["files"][COORDINATOR].clone();
        bad.push(value);
        for key in ["mode", "retained_mode"] {
            let mut value = roster.clone();
            value["files"][COORDINATOR][key] = json!(0o777);
            bad.push(value);
        }
        let mut value = roster.clone();
        value["files"][COORDINATOR]["sha256"] = json!("0".repeat(64));
        bad.push(value);
        for value in bad {
            for operation in ["prerm", "postrm"] {
                assert!(check_client_removal_handoff(
                    &hook(&value, operation),
                    operation,
                    root.path(),
                    VERSION
                )
                .is_err());
            }
        }
    }

    #[test]
    fn changed_bytes_modes_symlinks_and_hardlinks_cannot_pass() {
        let (root, roster) = fixture();
        let path = root.path().join(COORDINATOR);
        let good = hook(&roster, "prerm");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, b"changed").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o500)).unwrap();
        assert!(check_client_removal_handoff(&good, "prerm", root.path(), VERSION).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, COORDINATOR).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(check_client_removal_handoff(&good, "prerm", root.path(), VERSION).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o500)).unwrap();
        let alias = root.path().join("alias");
        fs::hard_link(&path, &alias).unwrap();
        assert!(check_client_removal_handoff(&good, "prerm", root.path(), VERSION).is_err());
        fs::remove_file(&alias).unwrap();
        fs::rename(&path, &alias).unwrap();
        symlink(&alias, &path).unwrap();
        assert!(check_client_removal_handoff(&good, "prerm", root.path(), VERSION).is_err());
    }

    #[test]
    fn an_operation_mismatch_or_duplicate_json_binding_is_refused() {
        let (root, roster) = fixture();
        assert!(check_client_removal_handoff(
            &hook(&roster, "postrm"),
            "prerm",
            root.path(),
            VERSION
        )
        .is_err());
        assert!(check_client_removal_handoff(
            &hook(&roster, "prerm"),
            "other",
            root.path(),
            VERSION
        )
        .is_err());
        let good = hook(&roster, "prerm");
        let duplicate = good.replacen(
            "\"package_version\":",
            "\"package_version\":\"other\",\"package_version\":",
            1,
        );
        assert!(check_client_removal_handoff(&duplicate, "prerm", root.path(), VERSION).is_err());
        let expression = good.replacen(
            "EXPECTED = json.loads('",
            "EXPECTED = json.loads(compute('",
            1,
        );
        assert!(check_client_removal_handoff(&expression, "prerm", root.path(), VERSION).is_err());
    }

    #[test]
    fn retained_modes_match_source_execution_bits_and_policy_data_normalization() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for relative in client_removal_paths().unwrap() {
            if relative == "usr/local/bin/aegis-client" {
                continue;
            }
            let (source, data) = if let Some(name) = relative.strip_prefix("etc/systemd/system/") {
                (root.join("packaging/systemd").join(name), false)
            } else {
                let name = relative
                    .strip_prefix("usr/local/lib/aegis/helpers/")
                    .unwrap();
                let source = if name == "lib/aegis-auto-terminal-hook" {
                    root.join("packaging/systemd/system-shutdown/aegis-auto-terminal-hook")
                } else {
                    root.join("scripts").join(name)
                };
                (
                    source,
                    name.starts_with("lib/") && (name.ends_with(".py") || name.ends_with(".json")),
                )
            };
            let mode = fs::metadata(source).unwrap().permissions().mode();
            let expected = if data || mode & 0o111 == 0 {
                0o444
            } else {
                0o555
            };
            assert_eq!(
                client_payload_modes(&relative).unwrap().1,
                expected,
                "{relative}"
            );
        }
    }
}
