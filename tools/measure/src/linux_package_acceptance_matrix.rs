use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::artifact::{read_json, write_json, write_text};

pub fn build_linux_package_acceptance_matrix(
    output_dir: &Path,
    evidence_paths: &[PathBuf],
) -> Result<(), Box<dyn std::error::Error>> {
    if evidence_paths.is_empty() {
        return Err("at least one evidence path is required".into());
    }

    let targets = target_matrix();
    let mut family_results = targets
        .iter()
        .map(|target| {
            let family = target["host_family_id"].as_str().unwrap_or_default();
            (
                family.to_string(),
                json!({
                    "host_family_id": family,
                    "package_family": target["package_family"].clone(),
                    "validation_tier": target["validation_tier"].clone(),
                    "status": "pending_live_evidence",
                    "evidence_path": Value::Null,
                    "artifact_schema": Value::Null,
                    "os_pretty_name": Value::Null,
                    "package_manager": Value::Null,
                    "supported_product_contour": Value::Null,
                    "supported_operator_scope": Value::Null,
                    "helper_exit_code": Value::Null,
                    "mode": Value::Null,
                    "notes": "No run-mode host evidence collected yet for this family.",
                }),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();

    for evidence_path in evidence_paths {
        let payload = read_json(evidence_path)?;
        let schema = payload["artifact_schema"].as_str().unwrap_or_default();
        let expected_package_family = match schema {
            "debian_package_host_validation_v1" => "deb",
            "rpm_package_host_validation_v1" => "rpm",
            _ => return Err(format!("Unsupported evidence schema: {schema}").into()),
        };
        let family_id = payload["host_family_id"].as_str().unwrap_or_default();
        let current = family_results
            .get(family_id)
            .ok_or_else(|| format!("Unexpected host family in evidence: {family_id}"))?;
        if current["package_family"].as_str() != Some(expected_package_family) {
            return Err(format!("Family/schema mismatch for {family_id}: {schema}").into());
        }

        let helper_exit_code = payload
            .get("helper_exit_code")
            .cloned()
            .unwrap_or(Value::Null);
        let mode = payload.get("mode").cloned().unwrap_or(Value::Null);
        let ready = payload["ready"].as_bool() == Some(true);
        let status =
            if mode.as_str() == Some("run") && ready && helper_exit_code.as_i64() == Some(0) {
                "passed"
            } else {
                "failed"
            };
        let notes = if status == "passed" {
            "run-mode validation helper passed on a live host"
        } else {
            "helper evidence did not confirm a clean live run"
        };

        family_results.insert(
            family_id.to_string(),
            json!({
                "host_family_id": family_id,
                "package_family": current["package_family"].clone(),
                "validation_tier": current["validation_tier"].clone(),
                "status": status,
                "evidence_path": display_path(evidence_path),
                "artifact_schema": schema,
                "os_pretty_name": payload.get("os_pretty_name").cloned().unwrap_or(Value::Null),
                "package_manager": payload.get("package_manager").cloned().unwrap_or(Value::Null),
                "supported_product_contour": payload.get("supported_product_contour").cloned().unwrap_or(Value::Null),
                "supported_operator_scope": payload.get("supported_operator_scope").cloned().unwrap_or(Value::Null),
                "helper_exit_code": helper_exit_code,
                "mode": mode,
                "notes": notes,
            }),
        );
    }

    let results = targets
        .iter()
        .map(|target| {
            let family = target["host_family_id"].as_str().unwrap_or_default();
            family_results[family].clone()
        })
        .collect::<Vec<_>>();
    let passed = family_ids_with_status(&results, "passed");
    let failed = family_ids_with_status(&results, "failed");
    let pending = family_ids_with_status(&results, "pending_live_evidence");
    let next_expansion_strategy = "first_unvalidated_family_in_documented_order";
    let next_expansion_candidate = targets.iter().find_map(|target| {
        let family = target["host_family_id"].as_str()?;
        if family_results[family]["status"].as_str() == Some("passed") {
            None
        } else {
            Some(family.to_string())
        }
    });
    let next_target = next_expansion_candidate.as_ref().and_then(|candidate| {
        targets
            .iter()
            .find(|target| target["host_family_id"].as_str() == Some(candidate.as_str()))
    });
    let next_expansion_helper_run_command =
        next_target.and_then(|target| target["helper_run_command"].as_str());
    let next_expansion_helper_run_json_command =
        next_target.and_then(|target| target["helper_run_json_command"].as_str());

    write_json(&output_dir.join("matrix.targets.json"), &json!(targets))?;
    write_json(&output_dir.join("matrix.results.json"), &json!(results))?;
    write_text(
        &output_dir.join("matrix-summary.md"),
        &render_markdown(
            &targets,
            &results,
            &passed,
            &failed,
            &pending,
            next_expansion_strategy,
            next_expansion_candidate.as_deref(),
        ),
    )?;

    let manifest = json!({
        "artifact_schema": "linux_package_acceptance_matrix_bundle_v1",
        "generated_at": generated_at(),
        "artifact_dir": display_path(output_dir),
        "matrix_targets_artifact": display_path(&output_dir.join("matrix.targets.json")),
        "matrix_results_artifact": display_path(&output_dir.join("matrix.results.json")),
        "matrix_summary_artifact": display_path(&output_dir.join("matrix-summary.md")),
        "case_count": targets.len(),
        "passed_case_count": passed.len(),
        "failed_case_count": failed.len(),
        "pending_case_count": pending.len(),
        "supported_product_contour": "linux_cross_distro_package_acceptance",
        "supported_operator_scope": "linux_package_acceptance_matrix",
        "release_claim_boundary": "ubuntu_first_only",
        "canonical_release_family": "debian-apt",
        "next_expansion_strategy": next_expansion_strategy,
        "next_expansion_candidate": next_expansion_candidate,
        "next_expansion_helper_run_command": next_expansion_helper_run_command,
        "next_expansion_helper_run_json_command": next_expansion_helper_run_json_command,
        "next_expansion_playbook_command": "bash scripts/build-linux-next-expansion-playbook.sh <output-dir> --matrix-manifest <bundle.manifest.json>",
        "next_expansion_review_bundle_command": "bash scripts/build-linux-next-expansion-review-bundle.sh <output-dir> --matrix-manifest <bundle.manifest.json> --target-evidence <host-validation.json>",
        "next_expansion_status_command": "bash scripts/linux-next-expansion-status.sh --matrix-manifest <bundle.manifest.json> --output <status.json> [--review-json <next-expansion-review.json>]",
        "next_expansion_wave_bundle_command": "bash scripts/build-linux-next-expansion-wave-bundle.sh <output-dir> --matrix-manifest <bundle.manifest.json> [--target-evidence <host-validation.json>]",
        "documented_host_family_matrix": targets,
        "passed_families": passed,
        "failed_families": failed,
        "pending_families": pending,
    });
    write_json(&output_dir.join("bundle.manifest.json"), &manifest)?;
    Ok(())
}

fn target_matrix() -> Vec<Value> {
    vec![
        json!({
            "host_family_id": "debian-apt",
            "package_family": "deb",
            "validation_tier": "packaging_validation_target",
            "status": "canonical_release_family",
            "helper_script": "scripts/validate-debian-package-host.sh",
            "helper_check_command": "bash scripts/validate-debian-package-host.sh --check",
            "helper_run_command": "sudo env HOME=\"$HOME\" PATH=\"$HOME/.cargo/bin:$PATH\" bash scripts/validate-debian-package-host.sh --run",
            "helper_run_json_command": "mkdir -p ./dist/linux-family-evidence/debian-apt && sudo env HOME=\"$HOME\" PATH=\"$HOME/.cargo/bin:$PATH\" bash scripts/validate-debian-package-host.sh --run --artifact-dir ./dist/linux-family-evidence/debian-apt/artifacts --json > ./dist/linux-family-evidence/debian-apt/host-validation.json",
            "success_contract": "split .deb packages install -> remove -> purge cleanly on a live apt-based host",
        }),
        json!({
            "host_family_id": "rhel-dnf",
            "package_family": "rpm",
            "validation_tier": "packaging_validation_target",
            "status": "next_expansion_candidate",
            "helper_script": "scripts/validate-rpm-package-host.sh",
            "helper_check_command": "bash scripts/validate-rpm-package-host.sh --check",
            "helper_run_command": "sudo env HOME=\"$HOME\" PATH=\"$HOME/.cargo/bin:$PATH\" bash scripts/validate-rpm-package-host.sh --run",
            "helper_run_json_command": "mkdir -p ./dist/linux-family-evidence/rhel-dnf && sudo env HOME=\"$HOME\" PATH=\"$HOME/.cargo/bin:$PATH\" bash scripts/validate-rpm-package-host.sh --run --artifact-dir ./dist/linux-family-evidence/rhel-dnf/artifacts --json > ./dist/linux-family-evidence/rhel-dnf/host-validation.json",
            "success_contract": "split .rpm packages install -> erase cleanly on a live dnf/yum host",
        }),
        json!({
            "host_family_id": "suse-zypper",
            "package_family": "rpm",
            "validation_tier": "packaging_validation_target",
            "status": "later_expansion_candidate",
            "helper_script": "scripts/validate-rpm-package-host.sh",
            "helper_check_command": "bash scripts/validate-rpm-package-host.sh --check",
            "helper_run_command": "sudo env HOME=\"$HOME\" PATH=\"$HOME/.cargo/bin:$PATH\" bash scripts/validate-rpm-package-host.sh --run",
            "helper_run_json_command": "mkdir -p ./dist/linux-family-evidence/suse-zypper && sudo env HOME=\"$HOME\" PATH=\"$HOME/.cargo/bin:$PATH\" bash scripts/validate-rpm-package-host.sh --run --artifact-dir ./dist/linux-family-evidence/suse-zypper/artifacts --json > ./dist/linux-family-evidence/suse-zypper/host-validation.json",
            "success_contract": "split .rpm packages install -> erase cleanly on a live zypper host",
        }),
    ]
}

fn family_ids_with_status(results: &[Value], status: &str) -> Vec<String> {
    results
        .iter()
        .filter(|item| item["status"].as_str() == Some(status))
        .filter_map(|item| item["host_family_id"].as_str())
        .map(ToString::to_string)
        .collect()
}

fn render_markdown(
    targets: &[Value],
    results: &[Value],
    passed: &[String],
    failed: &[String],
    pending: &[String],
    next_expansion_strategy: &str,
    next_expansion_candidate: Option<&str>,
) -> String {
    let mut lines = vec![
        "# Linux Package Acceptance Matrix".to_string(),
        String::new(),
        format!("- Generated at: `{}`", generated_at()),
        format!("- Total families: `{}`", targets.len()),
        format!("- Passed families: `{}`", passed.len()),
        format!("- Failed families: `{}`", failed.len()),
        format!("- Pending families: `{}`", pending.len()),
        format!("- Passed: `{}`", join_or_none(passed)),
        format!("- Failed: `{}`", join_or_none(failed)),
        format!("- Pending: `{}`", join_or_none(pending)),
        "- Canonical release family: `debian-apt`".to_string(),
        "- Release claim boundary: `ubuntu_first_only`".to_string(),
        format!("- Next expansion strategy: `{next_expansion_strategy}`"),
        format!(
            "- Next expansion candidate: `{}`",
            next_expansion_candidate.unwrap_or("none")
        ),
        String::new(),
        "| Host family | Package family | Status | Package manager | Evidence | Notes |"
            .to_string(),
        "| --- | --- | --- | --- | --- | --- |".to_string(),
    ];
    for item in results {
        lines.push(format!(
            "| `{}` | `{}` | `{}` | `{}` | `{}` | {} |",
            item["host_family_id"].as_str().unwrap_or("unknown"),
            item["package_family"].as_str().unwrap_or("unknown"),
            item["status"].as_str().unwrap_or("unknown"),
            item["package_manager"].as_str().unwrap_or("unknown"),
            item["evidence_path"].as_str().unwrap_or("none"),
            item["notes"].as_str().unwrap_or("")
        ));
    }
    lines.push(String::new());
    lines.join("\n")
}

fn join_or_none(items: &[String]) -> String {
    if items.is_empty() {
        "none".to_string()
    } else {
        items.join(", ")
    }
}

fn generated_at() -> String {
    format!("unix:{}", current_unix_secs())
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn display_path(path: &Path) -> String {
    path.components().collect::<PathBuf>().display().to_string()
}
