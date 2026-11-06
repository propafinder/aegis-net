use crate::artifact::{read_json, write_json, write_text};
use crate::cli::Command;
use crate::linux_live_audit_manifest::{
    build_linux_wide_live_audit_handoff_status, build_linux_wide_live_audit_manifest,
    linux_wide_live_audit_handoff_status_fixture_contract_check,
    linux_wide_live_audit_manifest_contract_check,
    linux_wide_live_audit_materialized_contract_check, linux_wide_live_audit_status_contract_check,
    load_linux_live_expected_topology, LinuxLiveAuditManifestInputs,
};
use crate::release_artifacts::{
    build_deb_package_manifest, build_macos_client_tarball_manifest, build_package_root_manifest,
    build_release_bundle_manifest, build_rpm_packages_manifest, build_split_deb_manifest,
    check_deb_package_contract_artifacts, check_split_deb_package_contract_artifacts,
    package_version, print_macos_client_package_metadata, print_release_package_metadata,
    write_archive_sha256, write_deb_md5sums, DebPackageContractInputs,
    SplitDebPackageContractInputs,
};
use crate::release_delivery::build_release_delivery_manifest;
use crate::release_opsec::{release_opsec_gate, ReleaseOpsecInputs};
use crate::release_parity::{
    release_latest_parity, release_latest_parity_markdown, ReleaseLatestParityInputs,
};

pub fn is_release(command: &Command) -> bool {
    matches!(
        command,
        Command::ReleaseLatestParity { .. }
            | Command::ReleaseOpsecGate { .. }
            | Command::HostArch
            | Command::BuildReleaseDeliveryManifest { .. }
            | Command::ReleasePackageMetadata { .. }
            | Command::MacosClientPackageMetadata { .. }
            | Command::PrintCargoPackageVersion { .. }
            | Command::BuildPackageRootManifest { .. }
            | Command::BuildPrivateResearchManifest { .. }
            | Command::BuildReleaseBundleManifest { .. }
            | Command::BuildPublicClientDelivery { .. }
            | Command::StagePublicClientMirror { .. }
            | Command::BuildMacosClientTarballManifest { .. }
            | Command::WriteArchiveSha256 { .. }
            | Command::WriteDebMd5Sums { .. }
            | Command::BuildSplitDebManifest { .. }
            | Command::BuildDebPackageManifest { .. }
            | Command::CheckDebPackageContractArtifacts { .. }
            | Command::CheckSplitDebPackageContractArtifacts { .. }
            | Command::BuildRpmPackagesManifest { .. }
            | Command::BuildLinuxWideLiveAuditManifest { .. }
            | Command::BuildLinuxWideLiveAuditHandoffStatus { .. }
            | Command::LinuxWideLiveAuditManifestContractCheck { .. }
            | Command::LinuxWideLiveAuditHandoffStatusContractCheck { .. }
            | Command::LinuxWideLiveAuditHandoffStatusFixtureContractCheck { .. }
            | Command::LinuxWideLiveAuditMaterializedContractCheck { .. }
    )
}

pub fn run(command: Command) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Command::BuildPublicClientDelivery {
            root,
            operator_bundle,
            output_dir,
            channel,
            prerelease,
        } => {
            crate::public_client_delivery::build(
                &root,
                &operator_bundle,
                &output_dir,
                &channel,
                prerelease,
            )?;
        }
        Command::StagePublicClientMirror {
            release_dir,
            output_dir,
            public_key,
            expected_source,
        } => {
            crate::public_client_delivery::stage(
                &release_dir,
                &output_dir,
                &public_key,
                &expected_source,
            )?;
        }
        Command::ReleaseLatestParity {
            server_result_json,
            client_result_json,
            negative_result_json,
            output_json,
            output_markdown,
        } => {
            let server_result_path = server_result_json.display().to_string();
            let client_result_path = client_result_json.display().to_string();
            let negative_result_path = negative_result_json.display().to_string();
            let result = release_latest_parity(
                &read_json(&server_result_json)?,
                &read_json(&client_result_json)?,
                &read_json(&negative_result_json)?,
                ReleaseLatestParityInputs {
                    server_result_json: &server_result_path,
                    client_result_json: &client_result_path,
                    negative_result_json: &negative_result_path,
                },
            );
            write_json(&output_json, &result)?;
            if let Some(path) = output_markdown {
                write_text(&path, &release_latest_parity_markdown(&result))?;
            }
            if result["status"].as_str() != Some("RELEASE_LATEST_PARITY_READY") {
                std::process::exit(1);
            }
        }
        Command::ReleaseOpsecGate {
            input,
            pattern,
            include_nm,
            output_json,
        } => {
            let report = release_opsec_gate(ReleaseOpsecInputs {
                inputs: input,
                patterns: pattern,
                include_nm,
            })?;
            if let Some(path) = output_json {
                write_json(&path, &report)?;
            } else {
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
            if report["status"].as_str() == Some("FAIL") {
                std::process::exit(1);
            }
        }
        Command::HostArch => {
            println!("{}", std::env::consts::ARCH);
        }
        Command::BuildReleaseDeliveryManifest {
            root,
            output_dir,
            channel,
            prerelease,
            rpm_status,
            rpm_reason,
            git_sha,
            build_timestamp,
            debian_revision,
        } => {
            build_release_delivery_manifest(
                &root,
                &output_dir,
                &channel,
                &prerelease,
                &rpm_status,
                &rpm_reason,
                &git_sha,
                &build_timestamp,
                debian_revision.as_deref(),
            )?;
        }
        Command::ReleasePackageMetadata { root } => {
            print_release_package_metadata(&root)?;
        }
        Command::MacosClientPackageMetadata { root } => {
            print_macos_client_package_metadata(&root)?;
        }
        Command::PrintCargoPackageVersion { root, package_name } => {
            println!("{}", package_version(&root, &package_name)?);
        }
        Command::BuildPackageRootManifest {
            package_dir,
            rootfs_dir,
            version,
            arch,
            target_triple,
            git_sha,
            build_timestamp,
        } => {
            build_package_root_manifest(
                &package_dir,
                &rootfs_dir,
                &version,
                &arch,
                &target_triple,
                &git_sha,
                &build_timestamp,
            )?;
        }
        Command::BuildPrivateResearchManifest {
            bundle_dir,
            version,
            arch,
            target_triple,
            git_sha,
            cargo_lock_sha256,
        } => {
            crate::private_research_delivery::build(&crate::private_research_delivery::Inputs {
                directory: &bundle_dir,
                version: &version,
                source: &git_sha,
                lock: &cargo_lock_sha256,
                arch: &arch,
                target: &target_triple,
            })?;
            let digest = crate::private_research_delivery::verify(
                &crate::private_research_delivery::Inputs {
                    directory: &bundle_dir,
                    version: &version,
                    source: &git_sha,
                    lock: &cargo_lock_sha256,
                    arch: &arch,
                    target: &target_triple,
                },
            )?;
            println!(
                "{}",
                serde_json::json!({"ok":true,"manifest_sha256":digest,"signed_release":false})
            );
        }
        Command::BuildReleaseBundleManifest {
            bundle_dir,
            version,
            arch,
            target_triple,
            git_sha,
            build_timestamp,
            administrative_measure_sha256,
            client_build_messages,
        } => {
            if let Some(messages) = client_build_messages {
                crate::shipping_client_inventory::write_build_record(
                    &messages,
                    &bundle_dir,
                    &target_triple,
                    &git_sha,
                )?;
            }
            if let Some(hash) = administrative_measure_sha256 {
                crate::release_artifacts::build_administrative_bundle_manifest(
                    &bundle_dir,
                    &version,
                    &arch,
                    &target_triple,
                    &git_sha,
                    &build_timestamp,
                    &hash,
                )?;
            } else {
                build_release_bundle_manifest(
                    &bundle_dir,
                    &version,
                    &arch,
                    &target_triple,
                    &git_sha,
                    &build_timestamp,
                )?;
            }
        }
        Command::BuildMacosClientTarballManifest {
            bundle_dir,
            version,
            arch,
            target_triple,
            git_sha,
            build_timestamp,
        } => {
            build_macos_client_tarball_manifest(
                &bundle_dir,
                &version,
                &arch,
                &target_triple,
                &git_sha,
                &build_timestamp,
            )?;
        }
        Command::WriteArchiveSha256 {
            archive,
            sha256_path,
        } => {
            write_archive_sha256(&archive, &sha256_path)?;
        }
        Command::WriteDebMd5Sums {
            stage_dir,
            debian_dir,
        } => {
            write_deb_md5sums(&stage_dir, &debian_dir)?;
        }
        Command::BuildSplitDebManifest {
            output_dir,
            version,
            deb_arch,
        } => {
            build_split_deb_manifest(&output_dir, &version, &deb_arch)?;
        }
        Command::BuildDebPackageManifest {
            output_dir,
            deb_name,
            version,
            deb_arch,
            rootfs_dir,
        } => {
            build_deb_package_manifest(&output_dir, &deb_name, &version, &deb_arch, &rootfs_dir)?;
        }
        Command::CheckDebPackageContractArtifacts {
            deb_path,
            deb_sha256_path,
            manifest_path,
            extract_dir,
            control_dir,
            version,
            deb_arch,
        } => {
            check_deb_package_contract_artifacts(DebPackageContractInputs {
                deb_path: &deb_path,
                deb_sha256_path: &deb_sha256_path,
                manifest_path: &manifest_path,
                extract_dir: &extract_dir,
                control_dir: &control_dir,
                version: &version,
                deb_arch: &deb_arch,
            })?;
        }
        Command::CheckSplitDebPackageContractArtifacts {
            server_deb,
            client_deb,
            server_sha256_path,
            client_sha256_path,
            manifest_path,
            server_extract_dir,
            server_control_dir,
            client_extract_dir,
            client_control_dir,
            version,
            deb_arch,
        } => {
            check_split_deb_package_contract_artifacts(SplitDebPackageContractInputs {
                server_deb: &server_deb,
                client_deb: &client_deb,
                server_sha256_path: &server_sha256_path,
                client_sha256_path: &client_sha256_path,
                manifest_path: &manifest_path,
                server_extract_dir: &server_extract_dir,
                server_control_dir: &server_control_dir,
                client_extract_dir: &client_extract_dir,
                client_control_dir: &client_control_dir,
                version: &version,
                deb_arch: &deb_arch,
            })?;
        }
        Command::BuildRpmPackagesManifest {
            output_dir,
            version,
            arch,
        } => {
            build_rpm_packages_manifest(&output_dir, &version, &arch)?;
        }
        Command::BuildLinuxWideLiveAuditManifest {
            manifest,
            output_dir,
            server_host,
            client_host,
            relay_address,
            runtime_events,
            preflight,
            startup_probe,
            wire_helper_stdout,
            witness_summary,
            witness_pcap,
            transient_runtime_events,
            wire_helper_runtime_events,
            wire_acceptance_summary,
            stealth_live_acceptance_bundle,
            stealth_live_acceptance_manifest,
            rerun_command,
            review_summary_command,
            review_manifest_command,
            handoff_status_json,
        } => {
            build_linux_wide_live_audit_manifest(LinuxLiveAuditManifestInputs {
                manifest,
                output_dir,
                server_host,
                client_host,
                relay_address,
                runtime_events,
                preflight,
                startup_probe,
                wire_helper_stdout,
                witness_summary,
                witness_pcap,
                transient_runtime_events,
                wire_helper_runtime_events,
                wire_acceptance_summary,
                stealth_live_acceptance_bundle,
                stealth_live_acceptance_manifest,
                rerun_command,
                review_summary_command,
                review_manifest_command,
                handoff_status_json,
            })?;
        }
        Command::BuildLinuxWideLiveAuditHandoffStatus { manifest, output } => {
            build_linux_wide_live_audit_handoff_status(&manifest, &output)?;
        }
        Command::LinuxWideLiveAuditManifestContractCheck {
            manifest,
            expect_fail,
        } => {
            for path in manifest {
                run_expected_check(expect_fail, || {
                    linux_wide_live_audit_manifest_contract_check(&path)
                })?;
            }
        }
        Command::LinuxWideLiveAuditHandoffStatusContractCheck {
            expected_topology_file,
            status_json,
            expect_fail,
        } => {
            let expected = load_linux_live_expected_topology(&expected_topology_file)?;
            for path in status_json {
                run_expected_check(expect_fail, || {
                    linux_wide_live_audit_status_contract_check(&path, &expected)
                })?;
            }
        }
        Command::LinuxWideLiveAuditHandoffStatusFixtureContractCheck {
            expected_topology_file,
            stealth_manifest,
            wire_manifest,
            green_manifest,
            stealth_status,
            wire_status,
            green_status,
        } => {
            let expected = load_linux_live_expected_topology(&expected_topology_file)?;
            linux_wide_live_audit_handoff_status_fixture_contract_check(
                &stealth_manifest,
                &wire_manifest,
                &green_manifest,
                &stealth_status,
                &wire_status,
                &green_status,
                &expected,
            )?;
        }
        Command::LinuxWideLiveAuditMaterializedContractCheck {
            expected_topology_file,
            dry_run_output,
            stealth_manifest,
            wire_manifest,
            green_manifest,
            dry_run_manifest,
        } => {
            let expected = load_linux_live_expected_topology(&expected_topology_file)?;
            linux_wide_live_audit_materialized_contract_check(
                &dry_run_output,
                &stealth_manifest,
                &wire_manifest,
                &green_manifest,
                &dry_run_manifest,
                &expected,
            )?;
        }
        _ => unreachable!("release dispatch received non-release command"),
    }
    Ok(())
}

fn run_expected_check<F>(expect_fail: bool, check: F) -> Result<(), Box<dyn std::error::Error>>
where
    F: FnOnce() -> Result<(), Box<dyn std::error::Error>>,
{
    match (expect_fail, check()) {
        (false, Ok(())) => Ok(()),
        (false, Err(err)) => Err(err),
        (true, Ok(())) => Err("expected contract check to fail, but it passed".into()),
        (true, Err(_)) => Ok(()),
    }
}
