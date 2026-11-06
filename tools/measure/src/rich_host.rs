use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::{json, Map, Value};

pub struct RichHostMatrixSummaryInputs<'a> {
    pub status_dir: &'a Path,
    pub artifact_dir: &'a Path,
    pub matrix_targets: &'a Path,
    pub matrix_results: &'a Path,
    pub matrix_summary: &'a Path,
    pub host_metadata: &'a Path,
    pub host_bootstrap: &'a Path,
}

pub struct RichHostValidationBundleInputs<'a> {
    pub output: &'a Path,
    pub artifact_dir: &'a Path,
    pub matrix_targets: &'a Path,
    pub matrix_results: &'a Path,
    pub matrix_summary: &'a Path,
    pub host_metadata: &'a Path,
    pub host_bootstrap: &'a Path,
    pub rerun_env: &'a Path,
    pub rerun_script: &'a Path,
    pub bootstrap_helper: &'a Path,
    pub validation_script: &'a Path,
    pub cargo_target_dir: &'a str,
    pub startup_wait_secs: u64,
    pub request_timeout_secs: u64,
    pub case_timeout_secs: u64,
}

pub struct RichHostValidationContractInputs<'a> {
    pub artifact_dir: &'a Path,
    pub repo_root: &'a Path,
    pub failed_artifact_dir: &'a Path,
    pub bootstrap_fail_artifact_dir: &'a Path,
    pub bootstrap_fail_output: &'a Path,
    pub bootstrap_broken_artifact_dir: &'a Path,
    pub bootstrap_broken_output: &'a Path,
}

pub fn build_rich_host_matrix_summary(
    inputs: RichHostMatrixSummaryInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let targets: Vec<Value> =
        serde_json::from_str(&std::fs::read_to_string(inputs.matrix_targets)?)?;
    let mut host_metadata = read_json_object_if_exists(inputs.host_metadata)?;
    let host_bootstrap = read_json_object_if_exists(inputs.host_bootstrap)?;

    let mut results = Vec::new();
    let mut summary_lines = vec![
        "# Rich Linux TPROXY Matrix".to_owned(),
        String::new(),
        "| Case | Shape | Tier | Release gate | Hosted subset | Hosted CI mirror | Status | Evidence |".to_owned(),
        "|------|-------|------|--------------|---------------|------------------|--------|----------|".to_owned(),
    ];

    for target in &targets {
        let case_id = str_field(target, "case_id");
        let status_path = inputs.status_dir.join(format!("{case_id}.txt"));
        let status = std::fs::read_to_string(&status_path)
            .map(|value| value.trim().to_owned())
            .unwrap_or_default();
        let contract_path = inputs.artifact_dir.join(format!("{case_id}.contract.json"));
        let runtime_path = inputs.artifact_dir.join(format!("{case_id}.runtime.jsonl"));
        let contract = read_json_object_if_exists(&contract_path)?;

        let mut result = target.as_object().cloned().unwrap_or_default();
        result.insert(
            "status".to_owned(),
            json!(if status.is_empty() {
                "missing"
            } else {
                &status
            }),
        );
        result.insert(
            "contract_artifact".to_owned(),
            path_if_exists(&contract_path),
        );
        result.insert("runtime_artifact".to_owned(), path_if_exists(&runtime_path));
        result.insert(
            "host_metadata_artifact".to_owned(),
            path_if_exists(inputs.host_metadata),
        );
        result.insert(
            "host_bootstrap_artifact".to_owned(),
            path_if_exists(inputs.host_bootstrap),
        );
        result.insert(
            "host_bootstrap_ready".to_owned(),
            host_bootstrap
                .as_ref()
                .and_then(|value| value.get("ready"))
                .cloned()
                .unwrap_or(Value::Null),
        );
        result.insert(
            "host_fingerprint".to_owned(),
            value_or_null(host_metadata.as_ref(), "fingerprint"),
        );
        result.insert(
            "host_os".to_owned(),
            value_or_null(host_metadata.as_ref(), "os_pretty_name"),
        );
        result.insert(
            "host_kernel_release".to_owned(),
            value_or_null(host_metadata.as_ref(), "kernel_release"),
        );
        for field in [
            "firewall_backend_effective",
            "wide_udp_capture_support_tier",
            "wide_udp_capture_policy",
            "wide_udp_capture_runtime_scope",
        ] {
            result.insert(field.to_owned(), value_or_null(contract.as_ref(), field));
        }
        results.push(Value::Object(result));

        let shape = format!(
            "{}/{}/{}",
            str_field(target, "backend"),
            str_field(target, "ip_family"),
            str_field(target, "smoke_class")
        );
        let evidence = if contract_path.exists() && runtime_path.exists() {
            "contract+runtime"
        } else {
            "status-only"
        };
        let hosted = if bool_field(target, "hosted_must_pass") {
            "must-pass"
        } else {
            "rich-host-only"
        };
        let hosted_ci_mirror = if bool_field(target, "hosted_must_pass") {
            case_id.clone()
        } else {
            "rich-host-only".to_owned()
        };
        let status_for_row = if status.is_empty() {
            "missing"
        } else {
            &status
        };
        summary_lines.push(format!(
            "| `{case_id}` | `{shape}` | `{}` | `{}` | `{hosted}` | `{hosted_ci_mirror}` | `{status_for_row}` | `{evidence}` |",
            str_field(target, "support_tier"),
            str_field(target, "product_release_gate")
        ));
    }

    let hosted_subset_cases = case_ids_where(&targets, |item| bool_field(item, "hosted_must_pass"));
    let rich_host_only_cases =
        case_ids_where(&targets, |item| !bool_field(item, "hosted_must_pass"));
    let product_required_cases = case_ids_where(&targets, |item| {
        str_field(item, "product_release_gate") == "product_required"
    });
    let guarded_evidence_cases = case_ids_where(&targets, |item| {
        str_field(item, "product_release_gate") == "guarded_evidence_only"
    });
    let rich_host_candidate_cases = case_ids_where(&targets, |item| {
        str_field(item, "product_release_gate") == "rich_host_candidate"
    });
    let failed_cases = result_case_ids_where(&results, |item| {
        str_field(item, "status").starts_with("failed:")
    });
    let skipped_cases = result_case_ids_where(&results, |item| {
        str_field(item, "status").starts_with("skipped:")
    });
    let passed_cases =
        result_case_ids_where(&results, |item| str_field(item, "status") == "passed");
    let capability_profile = capability_profile(&targets, &results);
    let capability_profile_order = capability_profile_order(&targets);

    std::fs::write(
        inputs.matrix_results,
        serde_json::to_string_pretty(&results)? + "\n",
    )?;

    if let Some(metadata) = host_metadata.as_mut() {
        set(
            metadata,
            "capability_profile",
            Value::Object(capability_profile.clone()),
        );
        set(metadata, "passed_case_count", json!(passed_cases.len()));
        set(metadata, "skipped_case_count", json!(skipped_cases.len()));
        set(metadata, "failed_case_count", json!(failed_cases.len()));
        set(
            metadata,
            "hosted_subset_case_count",
            json!(hosted_subset_cases.len()),
        );
        set(
            metadata,
            "rich_host_only_case_count",
            json!(rich_host_only_cases.len()),
        );
        set(
            metadata,
            "product_required_case_count",
            json!(product_required_cases.len()),
        );
        set(
            metadata,
            "guarded_evidence_case_count",
            json!(guarded_evidence_cases.len()),
        );
        set(
            metadata,
            "rich_host_candidate_case_count",
            json!(rich_host_candidate_cases.len()),
        );
        std::fs::write(
            inputs.host_metadata,
            serde_json::to_string_pretty(metadata)? + "\n",
        )?;
    }

    summary_lines.extend(summary_tail(
        &inputs,
        host_metadata.as_ref(),
        host_bootstrap.as_ref(),
        &targets,
        &hosted_subset_cases,
        &rich_host_only_cases,
        &product_required_cases,
        &guarded_evidence_cases,
        &rich_host_candidate_cases,
        &passed_cases,
        &skipped_cases,
        &failed_cases,
        &capability_profile_order,
    ));
    std::fs::write(inputs.matrix_summary, summary_lines.join("\n") + "\n")?;
    Ok(())
}

pub fn check_rich_host_validation_contract_artifacts(
    inputs: RichHostValidationContractInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    check_rich_host_green_artifact(inputs.artifact_dir, inputs.repo_root)?;
    check_rich_host_failed_artifact(inputs.failed_artifact_dir)?;
    check_rich_host_bootstrap_blocker_artifact(
        inputs.bootstrap_fail_artifact_dir,
        inputs.bootstrap_fail_output,
        BootstrapBlockerExpectation {
            error_code: None,
            helper_exit_code: None,
            missing_commands: &["cargo"],
            output_needles: &[
                "Missing richer-host validation prerequisites: cargo",
                "Remediation: bash scripts/bootstrap-wide-linux-validation-host.sh --install",
            ],
        },
    )?;
    check_rich_host_bootstrap_blocker_artifact(
        inputs.bootstrap_broken_artifact_dir,
        inputs.bootstrap_broken_output,
        BootstrapBlockerExpectation {
            error_code: Some("bootstrap_helper_invalid_json"),
            helper_exit_code: Some(1),
            missing_commands: &[],
            output_needles: &[
                "Missing richer-host validation prerequisites: bootstrap_helper_invalid_json",
                "Remediation: bash scripts/bootstrap-wide-linux-validation-host.sh --install",
            ],
        },
    )?;
    Ok(())
}

pub fn build_rich_host_metadata(
    output: &Path,
    host_bootstrap: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let bootstrap = read_json_object_if_exists(host_bootstrap)?;
    let os_release = parse_os_release();
    let os_pretty_name = os_release
        .field("PRETTY_NAME")
        .or_else(|| os_release.field("NAME"));
    let kernel_release = command_version("uname", &["-r"]);
    let kernel_version = command_version("uname", &["-v"]);
    let machine = command_version("uname", &["-m"]);
    let system = command_version("uname", &["-s"]);
    let fingerprint_parts = [
        os_release
            .field("ID")
            .or_else(|| system.as_ref().map(|value| value.to_lowercase()))
            .unwrap_or_else(|| "unknown".to_owned()),
        os_release
            .field("VERSION_ID")
            .unwrap_or_else(|| "unknown".to_owned()),
        kernel_release
            .clone()
            .unwrap_or_else(|| "unknown".to_owned()),
        machine.clone().unwrap_or_else(|| "unknown".to_owned()),
    ];
    let fingerprint = fingerprint_parts
        .iter()
        .map(|part| part.replace(' ', "_"))
        .collect::<Vec<_>>()
        .join(":");
    let sudo_non_interactive = Command::new("sudo")
        .args(["-n", "true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false);

    let payload = json!({
        "fingerprint": fingerprint,
        "hostname": command_version("hostname", &[]),
        "system": system,
        "kernel_release": kernel_release,
        "kernel_version": kernel_version,
        "machine": machine,
        "os_pretty_name": os_pretty_name,
        "os_id": os_release.field("ID"),
        "os_version_id": os_release.field("VERSION_ID"),
        "iproute2_version": command_version("ip", &["-Version"]),
        "iptables_version": command_version("iptables", &["--version"]),
        "ip6tables_version": command_version("ip6tables", &["--version"]),
        "nft_version": command_version("nft", &["--version"]),
        "cargo_version": command_version("cargo", &["--version"]),
        "sudo_non_interactive": sudo_non_interactive,
        "bootstrap_artifact": host_bootstrap.exists().then(|| host_bootstrap.display().to_string()),
        "bootstrap_ready": bootstrap_field(bootstrap.as_ref(), "ready"),
        "bootstrap_package_manager": bootstrap_field(bootstrap.as_ref(), "package_manager"),
        "bootstrap_missing_commands": bootstrap_field(bootstrap.as_ref(), "missing_commands"),
        "supported_product_contour": bootstrap_field(bootstrap.as_ref(), "supported_product_contour"),
        "supported_operator_scope": bootstrap_field(bootstrap.as_ref(), "supported_operator_scope"),
        "host_family_id": bootstrap_field(bootstrap.as_ref(), "host_family_id"),
        "host_family_validation_tier": bootstrap_field(bootstrap.as_ref(), "host_family_validation_tier"),
        "bootstrap_check_command": bootstrap_field(bootstrap.as_ref(), "bootstrap_check_command"),
        "bootstrap_install_command": bootstrap_field(bootstrap.as_ref(), "bootstrap_install_command"),
        "validation_command": bootstrap_field(bootstrap.as_ref(), "validation_command"),
        "upgrade_reapply_command": bootstrap_field(bootstrap.as_ref(), "upgrade_reapply_command"),
        "artifact_schema": "rich_host_metadata_v1",
    });
    std::fs::write(output, serde_json::to_string_pretty(&payload)? + "\n")?;
    Ok(())
}

pub fn build_rich_host_validation_bundle(
    inputs: RichHostValidationBundleInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let host_metadata = read_json_object_if_exists(inputs.host_metadata)?;
    let host_bootstrap = read_json_object_if_exists(inputs.host_bootstrap)?;
    let targets = read_json_array_if_exists(inputs.matrix_targets)?;
    let results = read_json_array_if_exists(inputs.matrix_results)?;
    let product_required_cases = case_ids_where(&targets, |item| {
        str_field(item, "product_release_gate") == "product_required"
    });
    let guarded_evidence_cases = case_ids_where(&targets, |item| {
        str_field(item, "product_release_gate") == "guarded_evidence_only"
    });
    let rich_host_candidate_cases = case_ids_where(&targets, |item| {
        str_field(item, "product_release_gate") == "rich_host_candidate"
    });

    let canonical_bootstrap_command = format!("bash {} --check", inputs.bootstrap_helper.display());
    let canonical_bootstrap_install_command =
        format!("bash {} --install", inputs.bootstrap_helper.display());
    let canonical_validation_command = format!(
        "sudo env HOME=\"$HOME\" PATH=\"$HOME/.cargo/bin:$PATH\" bash {}",
        inputs.validation_script.display()
    );
    let canonical_upgrade_reapply_command = format!(
        "{} && {}",
        canonical_bootstrap_install_command, canonical_validation_command
    );

    let manifest = json!({
        "artifact_schema": "wide_linux_tproxy_validation_bundle_v1",
        "generated_at": generated_at(),
        "artifact_dir": inputs.artifact_dir.display().to_string(),
        "bootstrap_helper_script": inputs.bootstrap_helper.display().to_string(),
        "validation_script": inputs.validation_script.display().to_string(),
        "bootstrap_artifact": optional_path(inputs.host_bootstrap),
        "host_metadata_artifact": optional_path(inputs.host_metadata),
        "matrix_targets_artifact": optional_path(inputs.matrix_targets),
        "matrix_results_artifact": optional_path(inputs.matrix_results),
        "matrix_summary_artifact": optional_path(inputs.matrix_summary),
        "rerun_env_artifact": optional_path(inputs.rerun_env),
        "rerun_script_artifact": optional_path(inputs.rerun_script),
        "canonical_bootstrap_command": canonical_bootstrap_command,
        "canonical_bootstrap_install_command": canonical_bootstrap_install_command,
        "canonical_validation_command": canonical_validation_command,
        "canonical_upgrade_reapply_command": canonical_upgrade_reapply_command,
        "rerun_command": format!("bash {}", inputs.rerun_script.display()),
        "cargo_target_dir": inputs.cargo_target_dir,
        "startup_wait_secs": inputs.startup_wait_secs,
        "request_timeout_secs": inputs.request_timeout_secs,
        "case_timeout_secs": inputs.case_timeout_secs,
        "case_count": targets.len(),
        "passed_case_count": results.iter().filter(|item| str_field(item, "status") == "passed").count(),
        "failed_case_count": results.iter().filter(|item| str_field(item, "status").starts_with("failed:")).count(),
        "skipped_case_count": results.iter().filter(|item| str_field(item, "status").starts_with("skipped:")).count(),
        "host_fingerprint": value_or_null(host_metadata.as_ref(), "fingerprint"),
        "host_os": value_or_null(host_metadata.as_ref(), "os_pretty_name"),
        "host_kernel_release": value_or_null(host_metadata.as_ref(), "kernel_release"),
        "host_family_id": value_or_null(host_metadata.as_ref(), "host_family_id"),
        "host_family_validation_tier": value_or_null(host_metadata.as_ref(), "host_family_validation_tier"),
        "bootstrap_ready": value_or_null(host_bootstrap.as_ref(), "ready"),
        "bootstrap_package_manager": value_or_null(host_bootstrap.as_ref(), "package_manager"),
        "supported_product_contour": value_or_null(host_bootstrap.as_ref(), "supported_product_contour"),
        "supported_operator_scope": value_or_null(host_bootstrap.as_ref(), "supported_operator_scope"),
        "supported_operator_flow": supported_operator_flow(&canonical_validation_command),
        "release_gate": {
            "product_required_cases": product_required_cases,
            "guarded_evidence_cases": guarded_evidence_cases,
            "rich_host_candidate_cases": rich_host_candidate_cases,
            "healthy_runtime_requirement": "helper events must keep startup_health=healthy and runtime_status=healthy",
            "notes": "Only product_required richer-host cases plus healthy helper/runtime status count toward the supported Linux product claim; guarded or richer-host-only cases remain diagnostics and expansion evidence.",
        },
        "documented_host_family_matrix": documented_host_families(),
    });
    std::fs::write(
        inputs.output,
        serde_json::to_string_pretty(&manifest)? + "\n",
    )?;
    Ok(())
}

fn read_json_object_if_exists(path: &Path) -> Result<Option<Value>, Box<dyn std::error::Error>> {
    if path.exists() {
        Ok(Some(serde_json::from_str(&std::fs::read_to_string(path)?)?))
    } else {
        Ok(None)
    }
}

fn read_json_array_if_exists(path: &Path) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    if path.exists() {
        Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
    } else {
        Ok(Vec::new())
    }
}

fn read_required_json(path: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn read_required_json_array(path: &Path) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn check_rich_host_green_artifact(
    artifact_dir: &Path,
    repo_root: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let targets = read_required_json_array(&artifact_dir.join("matrix.targets.json"))?;
    let results = read_required_json_array(&artifact_dir.join("matrix.results.json"))?;
    let summary = std::fs::read_to_string(artifact_dir.join("matrix-summary.md"))?;
    let host_metadata = read_required_json(&artifact_dir.join("host.metadata.json"))?;
    let host_bootstrap = read_required_json(&artifact_dir.join("host.bootstrap.json"))?;
    let bundle_manifest = read_required_json(&artifact_dir.join("bundle.manifest.json"))?;
    let rerun_env = std::fs::read_to_string(artifact_dir.join("rerun-rich-host.env"))?;
    let rerun_script = std::fs::read_to_string(artifact_dir.join("rerun-rich-host-validation.sh"))?;
    let workflow = std::fs::read_to_string(repo_root.join(".github/workflows/ci.yml"))?;

    ensure_rich_host_contract(targets.len() == 8, "expected 8 rich-host targets")?;
    assert_str_eq(&host_metadata, "artifact_schema", "rich_host_metadata_v1")?;
    ensure_rich_host_contract(
        !string_or_unknown(Some(&host_metadata), "fingerprint").is_empty(),
        "host metadata fingerprint must be present",
    )?;
    assert_str_ends_with(&host_metadata, "bootstrap_artifact", "host.bootstrap.json")?;
    assert_bool_eq(&host_metadata, "bootstrap_ready", true)?;
    assert_str_eq(&host_metadata, "bootstrap_package_manager", "stub-pkg")?;
    assert_str_eq(
        &host_metadata,
        "supported_product_contour",
        "linux_first_local_binary_operator",
    )?;
    assert_str_eq(
        &host_metadata,
        "supported_operator_scope",
        "supported_linux_tproxy_operator_path",
    )?;
    assert_str_eq(&host_metadata, "host_family_id", "debian-apt")?;
    assert_str_eq(
        &host_metadata,
        "host_family_validation_tier",
        "next_non_ubuntu_target",
    )?;
    assert_nested_str_eq(
        &host_metadata,
        &["capability_profile", "xtables_tproxy", "status"],
        "available",
    )?;
    assert_nested_str_eq(
        &host_metadata,
        &["capability_profile", "nft_tproxy", "status"],
        "unavailable",
    )?;
    assert_nested_str_eq(
        &host_metadata,
        &["capability_profile", "ipv6_ip6tables_tproxy", "status"],
        "available",
    )?;
    assert_nested_str_eq(
        &host_metadata,
        &["capability_profile", "ipv6_nft_tproxy", "status"],
        "unavailable",
    )?;

    assert_str_eq(
        &host_bootstrap,
        "artifact_schema",
        "wide_linux_validation_host_bootstrap_v1",
    )?;
    assert_str_eq(&host_bootstrap, "package_manager", "stub-pkg")?;
    assert_bool_eq(&host_bootstrap, "ready", true)?;
    assert_str_eq(
        &host_bootstrap,
        "supported_product_contour",
        "linux_first_local_binary_operator",
    )?;
    assert_str_eq(
        &host_bootstrap,
        "supported_operator_scope",
        "supported_linux_tproxy_operator_path",
    )?;
    assert_str_eq(&host_bootstrap, "host_family_id", "debian-apt")?;
    assert_str_eq(
        &host_bootstrap,
        "host_family_validation_tier",
        "next_non_ubuntu_target",
    )?;

    assert_str_eq(
        &bundle_manifest,
        "artifact_schema",
        "wide_linux_tproxy_validation_bundle_v1",
    )?;
    assert_usize_eq(&bundle_manifest, "case_count", 8)?;
    assert_usize_eq(&bundle_manifest, "passed_case_count", 4)?;
    assert_usize_eq(&bundle_manifest, "skipped_case_count", 4)?;
    assert_usize_eq(&bundle_manifest, "failed_case_count", 0)?;
    assert_bool_eq(&bundle_manifest, "bootstrap_ready", true)?;
    ensure_rich_host_contract(
        bundle_manifest.get("host_fingerprint") == host_metadata.get("fingerprint"),
        "bundle host fingerprint must match host metadata",
    )?;
    assert_str_ends_with(
        &bundle_manifest,
        "bootstrap_artifact",
        "host.bootstrap.json",
    )?;
    assert_str_ends_with(
        &bundle_manifest,
        "rerun_env_artifact",
        "rerun-rich-host.env",
    )?;
    assert_str_ends_with(
        &bundle_manifest,
        "rerun_script_artifact",
        "rerun-rich-host-validation.sh",
    )?;
    assert_str_eq(
        &bundle_manifest,
        "supported_product_contour",
        "linux_first_local_binary_operator",
    )?;
    assert_str_eq(
        &bundle_manifest,
        "supported_operator_scope",
        "supported_linux_tproxy_operator_path",
    )?;
    assert_str_eq(&bundle_manifest, "host_family_id", "debian-apt")?;
    assert_str_eq(
        &bundle_manifest,
        "host_family_validation_tier",
        "next_non_ubuntu_target",
    )?;
    assert_str_ends_with(
        &bundle_manifest,
        "canonical_bootstrap_install_command",
        " --install",
    )?;
    assert_str_starts_with(
        &bundle_manifest,
        "canonical_validation_command",
        "sudo env HOME=\"$HOME\" PATH=\"$HOME/.cargo/bin:$PATH\"",
    )?;
    assert_str_starts_with(
        &bundle_manifest,
        "canonical_upgrade_reapply_command",
        "bash ",
    )?;
    assert_nested_string_array_eq(
        &bundle_manifest,
        &["release_gate", "product_required_cases"],
        &["dns-xtables", "dns-nft", "dns-ipv6"],
    )?;
    assert_nested_string_array_eq(
        &bundle_manifest,
        &["release_gate", "guarded_evidence_cases"],
        &["generic-udp-xtables", "generic-udp-nft", "generic-udp-ipv6"],
    )?;
    assert_nested_string_array_eq(
        &bundle_manifest,
        &["release_gate", "rich_host_candidate_cases"],
        &["dns-ipv6-nft", "generic-udp-ipv6-nft"],
    )?;
    assert_operator_flow_edges(&bundle_manifest)?;
    ensure_rich_host_contract(
        array_field(&bundle_manifest, "documented_host_family_matrix")
            .iter()
            .any(|item| {
                str_field(item, "host_family_id") == "debian-apt"
                    && str_field(item, "validation_tier") == "next_non_ubuntu_target"
            }),
        "documented host family matrix must include debian-apt",
    )?;

    for needle in [
        "AEGIS_WIDE_RICH_HOST_SMOKE_STUB_SCRIPT",
        "AEGIS_WIDE_RICH_HOST_BOOTSTRAP_HELPER_SCRIPT",
    ] {
        assert_contains(&rerun_env, needle)?;
    }
    for needle in [
        "sudo env",
        "AEGIS_WIDE_RICH_HOST_ARTIFACT_DIR",
        "AEGIS_WIDE_RICH_HOST_SMOKE_STUB_SCRIPT",
    ] {
        assert_contains(&rerun_script, needle)?;
    }

    assert_target(
        &targets,
        "dns-nft",
        &[
            ("support_tier", "supported_preview"),
            ("product_release_gate", "product_required"),
        ],
        None,
    )?;
    assert_target(
        &targets,
        "generic-udp-nft",
        &[
            ("support_tier", "guarded_unstable"),
            ("product_release_gate", "guarded_evidence_only"),
        ],
        None,
    )?;
    assert_target(
        &targets,
        "dns-ipv6-nft",
        &[],
        Some(("hosted_must_pass", false)),
    )?;
    assert_target(
        &targets,
        "generic-udp-ipv6",
        &[],
        Some(("hosted_must_pass", true)),
    )?;
    assert_target(
        &targets,
        "dns-ipv6-nft",
        &[("product_release_gate", "rich_host_candidate")],
        None,
    )?;
    check_rich_host_workflow_matrix(&workflow, &targets)?;

    let by_case = case_map(&results);
    assert_case_status(&by_case, "dns-xtables", "passed")?;
    let dns_xtables = by_case
        .get("dns-xtables")
        .ok_or_else(|| rich_host_contract_error("missing dns-xtables result"))?;
    ensure_rich_host_contract(
        dns_xtables.get("host_fingerprint") == host_metadata.get("fingerprint"),
        "dns-xtables fingerprint must match metadata",
    )?;
    assert_str_ends_with(dns_xtables, "host_metadata_artifact", "host.metadata.json")?;
    assert_str_ends_with(
        dns_xtables,
        "host_bootstrap_artifact",
        "host.bootstrap.json",
    )?;
    assert_bool_eq(dns_xtables, "host_bootstrap_ready", true)?;
    assert_case_status(
        &by_case,
        "dns-nft",
        "skipped: nft TPROXY support is unavailable on this host",
    )?;
    assert_str_eq(
        by_case
            .get("generic-udp-xtables")
            .ok_or_else(|| rich_host_contract_error("missing generic-udp-xtables result"))?,
        "wide_udp_capture_support_tier",
        "guarded_unstable",
    )?;
    assert_str_eq(
        by_case
            .get("generic-udp-xtables")
            .ok_or_else(|| rich_host_contract_error("missing generic-udp-xtables result"))?,
        "product_release_gate",
        "guarded_evidence_only",
    )?;
    assert_str_eq(
        by_case
            .get("dns-ipv6")
            .ok_or_else(|| rich_host_contract_error("missing dns-ipv6 result"))?,
        "wide_udp_capture_runtime_scope",
        "linux_ipv6_only",
    )?;
    assert_case_status(
        &by_case,
        "dns-ipv6-nft",
        "skipped: IPv6 loopback or nft ip6 TPROXY support is unavailable on this host",
    )?;
    assert_case_status(
        &by_case,
        "generic-udp-ipv6-nft",
        "skipped: IPv6 loopback or nft ip6 TPROXY support is unavailable on this host",
    )?;

    for needle in [
        "| `generic-udp-ipv6` | `xtables/ipv6/generic_udp` | `guarded_unstable` | `guarded_evidence_only` | `must-pass` | `generic-udp-ipv6` | `passed` | `contract+runtime` |",
        "| `generic-udp-ipv6-nft` | `nft/ipv6/generic_udp` | `guarded_unstable` | `rich_host_candidate` | `rich-host-only` | `rich-host-only` | `skipped: IPv6 loopback or nft ip6 TPROXY support is unavailable on this host` | `status-only` |",
        "- Host metadata artifact: `",
        "- Host bootstrap artifact: `",
        "- Host bootstrap ready: `true`",
        "- Host bootstrap package manager: `stub-pkg`",
        "- Host family: `debian-apt`",
        "- Host family validation tier: `next_non_ubuntu_target`",
        "- Host OS: `",
        "- Host kernel: `",
        "- Host iproute2: `",
        "- Host capability profile: `xtables_tproxy=available, nft_tproxy=unavailable, ipv6_ip6tables_tproxy=available, ipv6_nft_tproxy=unavailable`",
        "- Product-required count: `3`",
        "- Guarded-evidence-only count: `3`",
        "- Rich-host-candidate count: `2`",
        "- Passed count: `4`",
        "- Skipped count: `4`",
        "- Failed count: `0`",
        "- Product-required cases: `dns-xtables, dns-nft, dns-ipv6`",
        "- Guarded-evidence-only cases: `generic-udp-xtables, generic-udp-nft, generic-udp-ipv6`",
        "- Rich-host-candidate cases: `dns-ipv6-nft, generic-udp-ipv6-nft`",
        "- Hosted subset cases: `dns-xtables, dns-nft, generic-udp-xtables, generic-udp-nft, dns-ipv6, generic-udp-ipv6`",
        "- Rich-host-only cases: `dns-ipv6-nft, generic-udp-ipv6-nft`",
        "- Failed cases: `none`",
    ] {
        assert_contains(&summary, needle)?;
    }
    assert_contains(
        &summary,
        &format!(
            "- Host fingerprint: `{}`",
            string_or_unknown(Some(&host_metadata), "fingerprint")
        ),
    )?;

    Ok(())
}

fn check_rich_host_failed_artifact(artifact_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let results = read_required_json_array(&artifact_dir.join("matrix.results.json"))?;
    let summary = std::fs::read_to_string(artifact_dir.join("matrix-summary.md"))?;
    let host_metadata = read_required_json(&artifact_dir.join("host.metadata.json"))?;
    let bundle_manifest = read_required_json(&artifact_dir.join("bundle.manifest.json"))?;
    let by_case = case_map(&results);

    assert_case_status(&by_case, "generic-udp-xtables", "failed:32")?;
    assert_case_status(&by_case, "dns-xtables", "passed")?;
    let generic_udp_xtables = by_case
        .get("generic-udp-xtables")
        .ok_or_else(|| rich_host_contract_error("missing generic-udp-xtables result"))?;
    ensure_rich_host_contract(
        generic_udp_xtables.get("host_fingerprint") == host_metadata.get("fingerprint"),
        "failed generic-udp-xtables fingerprint must match metadata",
    )?;
    assert_nested_str_eq(
        &host_metadata,
        &["capability_profile", "xtables_tproxy", "status"],
        "available",
    )?;
    assert_nested_str_eq(
        &host_metadata,
        &["capability_profile", "nft_tproxy", "status"],
        "unavailable",
    )?;
    assert_usize_eq(&bundle_manifest, "failed_case_count", 1)?;
    assert_usize_eq(&bundle_manifest, "passed_case_count", 3)?;
    for needle in [
        "- Failed count: `1`",
        "- Failed cases: `generic-udp-xtables`",
        "| `generic-udp-xtables` | `xtables/ipv4/generic_udp` | `guarded_unstable` | `guarded_evidence_only` | `must-pass` | `generic-udp-xtables` | `failed:32` | `contract+runtime` |",
    ] {
        assert_contains(&summary, needle)?;
    }
    Ok(())
}

struct BootstrapBlockerExpectation<'a> {
    error_code: Option<&'a str>,
    helper_exit_code: Option<i64>,
    missing_commands: &'a [&'a str],
    output_needles: &'a [&'a str],
}

fn check_rich_host_bootstrap_blocker_artifact(
    artifact_dir: &Path,
    output_path: &Path,
    expected: BootstrapBlockerExpectation<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let output = std::fs::read_to_string(output_path)?;
    let bootstrap = read_required_json(&artifact_dir.join("host.bootstrap.json"))?;
    let targets = read_required_json_array(&artifact_dir.join("matrix.targets.json"))?;

    ensure_rich_host_contract(targets.len() == 8, "expected 8 bootstrap blocker targets")?;
    assert_bool_eq(&bootstrap, "ready", false)?;
    if let Some(error_code) = expected.error_code {
        assert_str_eq(&bootstrap, "error_code", error_code)?;
    }
    if let Some(helper_exit_code) = expected.helper_exit_code {
        ensure_rich_host_contract(
            bootstrap.get("helper_exit_code").and_then(Value::as_i64) == Some(helper_exit_code),
            "bootstrap helper_exit_code mismatch",
        )?;
    }
    assert_string_array_eq(&bootstrap, "missing_commands", expected.missing_commands)?;
    assert_str_ends_with(&bootstrap, "remediation_command", "--install")?;
    ensure_rich_host_contract(
        !artifact_dir.join("matrix.results.json").exists(),
        "bootstrap blocker must not leave matrix.results.json",
    )?;
    ensure_rich_host_contract(
        !artifact_dir.join("host.metadata.json").exists(),
        "bootstrap blocker must not leave host.metadata.json",
    )?;
    for needle in expected.output_needles {
        assert_contains(&output, needle)?;
    }
    Ok(())
}

fn parse_os_release() -> Map<String, Value> {
    let Ok(raw) = std::fs::read_to_string("/etc/os-release") else {
        return Map::new();
    };
    raw.lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            Some((
                key.to_owned(),
                Value::String(value.trim().trim_matches('"').to_owned()),
            ))
        })
        .collect()
}

trait JsonObjectField {
    fn field(&self, key: &str) -> Option<String>;
}

impl JsonObjectField for Map<String, Value> {
    fn field(&self, key: &str) -> Option<String> {
        self.get(key)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    }
}

fn command_version(command: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(command).args(args).output().ok()?;
    let text = if output.stdout.is_empty() {
        String::from_utf8_lossy(&output.stderr).to_string()
    } else {
        String::from_utf8_lossy(&output.stdout).to_string()
    };
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_owned)
}

fn bootstrap_field(bootstrap: Option<&Value>, field: &str) -> Value {
    bootstrap
        .and_then(|value| value.get(field))
        .cloned()
        .unwrap_or(Value::Null)
}

fn optional_path(path: &Path) -> Value {
    if path.exists() {
        json!(path.display().to_string())
    } else {
        Value::Null
    }
}

fn generated_at() -> String {
    command_version("date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"]).unwrap_or_else(|| {
        format!(
            "unix:{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or(0)
        )
    })
}

fn supported_operator_flow(canonical_validation_command: &str) -> Value {
    json!([
        {
            "step": "bootstrap_check",
            "command": "bash scripts/bootstrap-wide-linux-validation-host.sh --check",
            "success_condition": "bootstrap_ready=true",
        },
        {
            "step": "repo_side_proofs",
            "command": "./scripts/audit.sh",
            "success_condition": "fmt/clippy/tests and contract self-tests are green",
        },
        {
            "step": "rich_host_validation",
            "command": canonical_validation_command,
            "success_condition": "product_required richer-host cases are passed",
        },
        {
            "step": "helper_doctor",
            "command": "AEGIS_CLIENT_CONFIG=<cfg> ./scripts/setup-wide-linux-tproxy.sh doctor",
            "success_condition": "helper contract and client config stay aligned",
        },
        {
            "step": "helper_probe",
            "command": "AEGIS_CLIENT_CONFIG=<cfg> ./scripts/setup-wide-linux-tproxy.sh probe",
            "success_condition": "startup path stays ready for supported linux_tproxy scope",
        },
        {
            "step": "helper_launch",
            "command": "AEGIS_CLIENT_CONFIG=<cfg> ./scripts/setup-wide-linux-tproxy.sh launch",
            "success_condition": "long-running client starts with runtime JSONL enabled",
        },
        {
            "step": "helper_events",
            "command": "AEGIS_RUNTIME_EVENTS_JSONL=<jsonl> ./scripts/setup-wide-linux-tproxy.sh events",
            "success_condition": "startup_health=healthy and runtime_status=healthy",
        },
    ])
}

fn documented_host_families() -> Value {
    json!([
        {
            "host_family_id": "ubuntu-apt",
            "validation_tier": "validated_baseline",
            "status": "supported_baseline",
            "notes": "current richer-host evidence is validated on Ubuntu hosts",
        },
        {
            "host_family_id": "debian-apt",
            "validation_tier": "next_non_ubuntu_target",
            "status": "next_target",
            "notes": "shortest-path non-Ubuntu validation target because bootstrap/install path already matches apt-based flow",
        },
        {
            "host_family_id": "rhel-dnf",
            "validation_tier": "planned_family",
            "status": "planned",
            "notes": "bootstrap helper already supports dnf/yum, but richer-host evidence is still pending",
        },
        {
            "host_family_id": "suse-zypper",
            "validation_tier": "planned_family",
            "status": "planned",
            "notes": "bootstrap helper already supports zypper, but richer-host evidence is still pending",
        },
    ])
}

fn path_if_exists(path: &Path) -> Value {
    if path.exists() {
        Value::String(path.display().to_string())
    } else {
        Value::Null
    }
}

fn value_or_null(value: Option<&Value>, field: &str) -> Value {
    value
        .and_then(|value| value.get(field))
        .cloned()
        .unwrap_or(Value::Null)
}

fn str_field(value: &Value, field: &str) -> String {
    value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn bool_field(value: &Value, field: &str) -> bool {
    value.get(field).and_then(Value::as_bool).unwrap_or(false)
}

fn array_field<'a>(value: &'a Value, field: &str) -> Vec<&'a Value> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(|items| items.iter().collect())
        .unwrap_or_default()
}

fn rich_host_contract_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    message.into().into()
}

fn ensure_rich_host_contract(
    condition: bool,
    message: impl Into<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if condition {
        Ok(())
    } else {
        Err(rich_host_contract_error(message))
    }
}

fn assert_contains(haystack: &str, needle: &str) -> Result<(), Box<dyn std::error::Error>> {
    ensure_rich_host_contract(
        haystack.contains(needle),
        format!("expected text to contain {needle:?}"),
    )
}

fn assert_str_eq(
    value: &Value,
    field: &str,
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = value.get(field).and_then(Value::as_str).unwrap_or_default();
    ensure_rich_host_contract(
        actual == expected,
        format!("field {field} expected {expected:?}, got {actual:?}"),
    )
}

fn assert_str_starts_with(
    value: &Value,
    field: &str,
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = value.get(field).and_then(Value::as_str).unwrap_or_default();
    ensure_rich_host_contract(
        actual.starts_with(expected),
        format!("field {field} expected prefix {expected:?}, got {actual:?}"),
    )
}

fn assert_str_ends_with(
    value: &Value,
    field: &str,
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = value.get(field).and_then(Value::as_str).unwrap_or_default();
    ensure_rich_host_contract(
        actual.ends_with(expected),
        format!("field {field} expected suffix {expected:?}, got {actual:?}"),
    )
}

fn assert_bool_eq(
    value: &Value,
    field: &str,
    expected: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = value.get(field).and_then(Value::as_bool);
    ensure_rich_host_contract(
        actual == Some(expected),
        format!("field {field} expected {expected}, got {actual:?}"),
    )
}

fn assert_usize_eq(
    value: &Value,
    field: &str,
    expected: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = value.get(field).and_then(Value::as_u64);
    ensure_rich_host_contract(
        actual == Some(expected as u64),
        format!("field {field} expected {expected}, got {actual:?}"),
    )
}

fn assert_nested_str_eq(
    value: &Value,
    path: &[&str],
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = nested_value(value, path)
        .and_then(Value::as_str)
        .unwrap_or_default();
    ensure_rich_host_contract(
        actual == expected,
        format!(
            "path {} expected {expected:?}, got {actual:?}",
            path.join(".")
        ),
    )
}

fn assert_string_array_eq(
    value: &Value,
    field: &str,
    expected: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = value
        .get(field)
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    ensure_rich_host_contract(
        actual == expected,
        format!("field {field} expected {expected:?}, got {actual:?}"),
    )
}

fn assert_nested_string_array_eq(
    value: &Value,
    path: &[&str],
    expected: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = nested_value(value, path)
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    ensure_rich_host_contract(
        actual == expected,
        format!(
            "path {} expected {expected:?}, got {actual:?}",
            path.join(".")
        ),
    )
}

fn nested_value<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    Some(current)
}

fn assert_operator_flow_edges(value: &Value) -> Result<(), Box<dyn std::error::Error>> {
    let flow = value
        .get("supported_operator_flow")
        .and_then(Value::as_array)
        .ok_or_else(|| rich_host_contract_error("supported_operator_flow must be an array"))?;
    let first = flow
        .first()
        .and_then(|item| item.get("step"))
        .and_then(Value::as_str);
    let last = flow
        .last()
        .and_then(|item| item.get("step"))
        .and_then(Value::as_str);
    ensure_rich_host_contract(
        first == Some("bootstrap_check") && last == Some("helper_events"),
        "supported operator flow edge steps mismatch",
    )
}

fn assert_target(
    targets: &[Value],
    case_id: &str,
    expected_strs: &[(&str, &str)],
    expected_bool: Option<(&str, bool)>,
) -> Result<(), Box<dyn std::error::Error>> {
    let matches = targets.iter().any(|item| {
        str_field(item, "case_id") == case_id
            && expected_strs
                .iter()
                .all(|(field, expected)| str_field(item, field) == *expected)
            && expected_bool
                .map(|(field, expected)| bool_field(item, field) == expected)
                .unwrap_or(true)
    });
    ensure_rich_host_contract(matches, format!("missing expected target {case_id}"))
}

fn case_map(results: &[Value]) -> std::collections::BTreeMap<String, Value> {
    results
        .iter()
        .map(|item| (str_field(item, "case_id"), item.clone()))
        .collect()
}

fn assert_case_status(
    by_case: &std::collections::BTreeMap<String, Value>,
    case_id: &str,
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = by_case
        .get(case_id)
        .map(|item| str_field(item, "status"))
        .unwrap_or_default();
    ensure_rich_host_contract(
        actual == expected,
        format!("case {case_id} expected status {expected:?}, got {actual:?}"),
    )
}

fn check_rich_host_workflow_matrix(
    workflow: &str,
    targets: &[Value],
) -> Result<(), Box<dyn std::error::Error>> {
    let matrix_case_ids = targets
        .iter()
        .map(|item| str_field(item, "case_id"))
        .collect::<std::collections::BTreeSet<_>>();
    let hosted_subset_ids = targets
        .iter()
        .filter(|item| bool_field(item, "hosted_must_pass"))
        .map(|item| str_field(item, "case_id"))
        .collect::<std::collections::BTreeSet<_>>();
    let rich_host_only_ids = matrix_case_ids
        .difference(&hosted_subset_ids)
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let workflow_matrix_steps = workflow
        .lines()
        .filter_map(|line| line.split_once("guarded_smoke_status_init"))
        .filter_map(|(_, rest)| rest.split_whitespace().next())
        .filter(|case_id| matrix_case_ids.contains(*case_id))
        .map(str::to_owned)
        .collect::<std::collections::BTreeSet<_>>();

    ensure_rich_host_contract(
        workflow_matrix_steps == hosted_subset_ids,
        format!(
            "workflow hosted subset mismatch: workflow={workflow_matrix_steps:?}, expected={hosted_subset_ids:?}"
        ),
    )?;
    ensure_rich_host_contract(
        workflow_matrix_steps.is_disjoint(&rich_host_only_ids),
        "workflow must not include rich-host-only cases",
    )?;
    for name in [
        "Guarded: Linux TPROXY DNS IPv6 smoke",
        "Guarded: Linux TPROXY generic UDP IPv6 smoke",
    ] {
        ensure_rich_host_contract(
            workflow_step_block_contains(workflow, name, "AEGIS_WIDE_SMOKE_CONTRACT_ARTIFACT"),
            format!("workflow step {name:?} must export AEGIS_WIDE_SMOKE_CONTRACT_ARTIFACT"),
        )?;
    }
    Ok(())
}

fn workflow_step_block_contains(workflow: &str, name: &str, needle: &str) -> bool {
    let marker = format!("- name: \"{name}\"");
    let Some(start) = workflow.find(&marker) else {
        return false;
    };
    let rest = &workflow[start + marker.len()..];
    let end = rest.find("\n      - name: ").unwrap_or(rest.len());
    rest[..end].contains(needle)
}

fn set(value: &mut Value, field: &str, new_value: Value) {
    if let Some(map) = value.as_object_mut() {
        map.insert(field.to_owned(), new_value);
    }
}

fn case_ids_where<F>(targets: &[Value], pred: F) -> Vec<String>
where
    F: Fn(&Value) -> bool,
{
    targets
        .iter()
        .filter(|item| pred(item))
        .map(|item| str_field(item, "case_id"))
        .collect()
}

fn result_case_ids_where<F>(results: &[Value], pred: F) -> Vec<String>
where
    F: Fn(&Value) -> bool,
{
    results
        .iter()
        .filter(|item| pred(item))
        .map(|item| str_field(item, "case_id"))
        .collect()
}

fn capability_profile(targets: &[Value], results: &[Value]) -> Map<String, Value> {
    let mut profile = Map::new();
    for target in targets {
        let probe = str_field(target, "capability_probe");
        if profile.contains_key(&probe) {
            continue;
        }
        let statuses = results
            .iter()
            .filter(|item| str_field(item, "capability_probe") == probe)
            .map(|item| str_field(item, "status"))
            .collect::<Vec<_>>();
        let available = statuses
            .iter()
            .filter(|status| !status.is_empty())
            .any(|status| !status.starts_with("skipped:"));
        let reason = if available {
            Value::Null
        } else {
            statuses
                .iter()
                .find_map(|status| {
                    status
                        .strip_prefix("skipped: ")
                        .map(|reason| Value::String(reason.trim().to_owned()))
                })
                .unwrap_or(Value::Null)
        };
        profile.insert(
            probe,
            json!({
                "available": available,
                "status": if available { "available" } else { "unavailable" },
                "reason": reason,
            }),
        );
    }
    profile
}

#[allow(clippy::too_many_arguments)]
fn summary_tail(
    inputs: &RichHostMatrixSummaryInputs<'_>,
    host_metadata: Option<&Value>,
    host_bootstrap: Option<&Value>,
    targets: &[Value],
    hosted_subset_cases: &[String],
    rich_host_only_cases: &[String],
    product_required_cases: &[String],
    guarded_evidence_cases: &[String],
    rich_host_candidate_cases: &[String],
    passed_cases: &[String],
    skipped_cases: &[String],
    failed_cases: &[String],
    capability_profile_order: &[String],
) -> Vec<String> {
    vec![
        String::new(),
        "Hosted CI mirrors the must-pass subset below; only `product_required` cases should be read as release-green Linux baseline proof.".to_owned(),
        "Cases marked `guarded_evidence_only` or `rich_host_candidate` still matter for diagnostics and future host-family expansion, but they do not widen the supported product claim by themselves.".to_owned(),
        String::new(),
        artifact_line("Host metadata artifact", inputs.host_metadata),
        artifact_line("Host bootstrap artifact", inputs.host_bootstrap),
        format!(
            "- Host bootstrap ready: `{}`",
            host_bootstrap
                .and_then(|value| value.get("ready"))
                .map(lower_json)
                .unwrap_or_else(|| "unknown".to_owned())
        ),
        format!(
            "- Host bootstrap package manager: `{}`",
            string_or_unknown(host_bootstrap, "package_manager")
        ),
        format!(
            "- Host family: `{}`",
            string_or_unknown(host_metadata, "host_family_id")
        ),
        format!(
            "- Host family validation tier: `{}`",
            string_or_unknown(host_metadata, "host_family_validation_tier")
        ),
        format!(
            "- Host fingerprint: `{}`",
            string_or_unknown(host_metadata, "fingerprint")
        ),
        format!("- Host OS: `{}`", host_os(host_metadata)),
        format!(
            "- Host kernel: `{}`",
            string_or_unknown(host_metadata, "kernel_release")
        ),
        format!(
            "- Host iproute2: `{}`",
            string_or_unknown(host_metadata, "iproute2_version")
        ),
        capability_profile_line(host_metadata, capability_profile_order),
        format!(
            "- Hosted subset count: `{}`",
            targets.iter().filter(|item| bool_field(item, "hosted_must_pass")).count()
        ),
        format!(
            "- Rich-host-only count: `{}`",
            targets.iter().filter(|item| !bool_field(item, "hosted_must_pass")).count()
        ),
        format!("- Product-required count: `{}`", product_required_cases.len()),
        format!("- Guarded-evidence-only count: `{}`", guarded_evidence_cases.len()),
        format!("- Rich-host-candidate count: `{}`", rich_host_candidate_cases.len()),
        format!("- Passed count: `{}`", passed_cases.len()),
        format!("- Skipped count: `{}`", skipped_cases.len()),
        format!("- Failed count: `{}`", failed_cases.len()),
        format!("- Product-required cases: `{}`", product_required_cases.join(", ")),
        format!("- Guarded-evidence-only cases: `{}`", guarded_evidence_cases.join(", ")),
        format!("- Rich-host-candidate cases: `{}`", rich_host_candidate_cases.join(", ")),
        format!("- Hosted subset cases: `{}`", hosted_subset_cases.join(", ")),
        format!("- Rich-host-only cases: `{}`", rich_host_only_cases.join(", ")),
        format!(
            "- Failed cases: `{}`",
            if failed_cases.is_empty() {
                "none".to_owned()
            } else {
                failed_cases.join(", ")
            }
        ),
        format!("- Targets: `{}`", inputs.matrix_targets.display()),
        format!("- Results: `{}`", inputs.matrix_results.display()),
    ]
}

fn artifact_line(label: &str, path: &Path) -> String {
    if path.exists() {
        format!("- {label}: `{}`", path.display())
    } else {
        format!("- {label}: `missing`")
    }
}

fn string_or_unknown(value: Option<&Value>, field: &str) -> String {
    value
        .and_then(|value| value.get(field))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
        .to_owned()
}

fn host_os(host_metadata: Option<&Value>) -> String {
    string_or_unknown(host_metadata, "os_pretty_name")
        .then_unknown_fallback(|| string_or_unknown(host_metadata, "system"))
}

trait UnknownFallback {
    fn then_unknown_fallback<F>(self, fallback: F) -> String
    where
        F: FnOnce() -> String;
}

impl UnknownFallback for String {
    fn then_unknown_fallback<F>(self, fallback: F) -> String
    where
        F: FnOnce() -> String,
    {
        if self == "unknown" {
            fallback()
        } else {
            self
        }
    }
}

fn lower_json(value: &Value) -> String {
    match value {
        Value::Bool(value) => value.to_string(),
        Value::String(value) => value.to_lowercase(),
        Value::Null => "none".to_owned(),
        value => value.to_string().to_lowercase(),
    }
}

fn capability_profile_line(host_metadata: Option<&Value>, probe_order: &[String]) -> String {
    let Some(profile) = host_metadata
        .and_then(|value| value.get("capability_profile"))
        .and_then(Value::as_object)
    else {
        return "- Host capability profile: `unknown`".to_owned();
    };
    if profile.is_empty() {
        return "- Host capability profile: `unknown`".to_owned();
    }
    let summary = probe_order
        .iter()
        .filter_map(|probe| {
            profile.get(probe).map(|details| {
                format!(
                    "{probe}={}",
                    details
                        .get("status")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                )
            })
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("- Host capability profile: `{summary}`")
}

fn capability_profile_order(targets: &[Value]) -> Vec<String> {
    let mut probes = Vec::new();
    for target in targets {
        let probe = str_field(target, "capability_probe");
        if !probes.contains(&probe) {
            probes.push(probe);
        }
    }
    probes
}
