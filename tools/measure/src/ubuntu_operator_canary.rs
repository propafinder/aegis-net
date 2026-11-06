use std::path::Path;

use serde_json::{json, Value};

use crate::artifact::{read_json, write_json, write_text};

pub fn build_ubuntu_operator_reapply_canary(
    output_dir: &Path,
    pilot_inputs_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let pilot_inputs = read_json(pilot_inputs_path)?;
    let validation_summary_path = required_path(&pilot_inputs, "validation_summary_json")?;
    let release_summary_path = required_path(&pilot_inputs, "release_summary_json")?;
    let operator_loop_path = required_path(&pilot_inputs, "operator_loop_summary_json")?;

    for (path, label) in [
        (&validation_summary_path, "validation_summary_json"),
        (&release_summary_path, "release_summary_json"),
        (&operator_loop_path, "operator_loop_summary_json"),
    ] {
        if !path.is_file() {
            return Err(format!(
                "Pilot inputs do not point to a valid {label}: {}",
                path.display()
            )
            .into());
        }
    }

    let validation_summary = read_json(&validation_summary_path)?;
    let release_summary = read_json(&release_summary_path)?;
    let operator_loop = read_json(&operator_loop_path)?;

    let restart_checks = json!({
        "service_restart_passed": check_entry(
            phase_passed(&validation_summary, "service_restart"),
            "explicit systemctl restart must keep both services active",
            "service_restart_not_passed",
            phase_detail(&validation_summary, "service_restart"),
        ),
        "reboot_contract_passed": check_entry(
            phase_passed(&validation_summary, "reboot_contract"),
            "daemon-reload plus restart must keep the reboot-proximate contract healthy",
            "reboot_contract_not_passed",
            phase_detail(&validation_summary, "reboot_contract"),
        ),
        "service_health_green": check_entry(
            release_summary.get("service_health_verdict").and_then(Value::as_str) == Some("green"),
            "service health must stay green after restart/reboot-proximate steps",
            &format!(
                "service_health_verdict={}",
                release_summary
                    .get("service_health_verdict")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
            ),
            release_summary.get("service_health_verdict").cloned().unwrap_or(Value::Null),
        ),
    });
    let rollback_checks = json!({
        "remove_passed": check_entry(
            phase_passed(&validation_summary, "remove"),
            "package remove must preserve conffiles without leaving the host broken",
            "remove_not_passed",
            phase_detail(&validation_summary, "remove"),
        ),
        "reinstall_passed": check_entry(
            phase_passed(&validation_summary, "reinstall"),
            "package reinstall must restore the installed payload cleanly",
            "reinstall_not_passed",
            phase_detail(&validation_summary, "reinstall"),
        ),
    });
    let reapply_checks = json!({
        "upgrade_reapply_passed": check_entry(
            phase_passed(&validation_summary, "upgrade_reapply"),
            "same-version package reapply must keep the installed payload coherent",
            "upgrade_reapply_not_passed",
            phase_detail(&validation_summary, "upgrade_reapply"),
        ),
        "baseline_bypass_ready": check_entry(
            release_summary.get("baseline_bypass_ready").and_then(Value::as_bool) == Some(true),
            "baseline bypass must still be proven after the lifecycle canary",
            release_summary
                .get("baseline_bypass_blocker_reason")
                .and_then(Value::as_str)
                .unwrap_or("baseline_bypass_not_ready"),
            release_summary.get("baseline_bypass_verdict").cloned().unwrap_or(Value::Null),
        ),
        "operator_loop_green": check_entry(
            operator_loop.get("overall_status").and_then(Value::as_str) == Some("green"),
            "operator loop must remain green after restart/reapply flow",
            &format!(
                "operator_loop_status={}",
                operator_loop
                    .get("overall_status")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
            ),
            operator_loop.get("overall_status").cloned().unwrap_or(Value::Null),
        ),
    });

    let restart_failures = failed_check_ids(&restart_checks);
    let rollback_failures = failed_check_ids(&rollback_checks);
    let reapply_failures = failed_check_ids(&reapply_checks);
    let restart_canary_ready = restart_failures.is_empty();
    let rollback_canary_ready = rollback_failures.is_empty();
    let reapply_canary_ready = reapply_failures.is_empty();

    let all_failures = restart_failures
        .iter()
        .chain(rollback_failures.iter())
        .chain(reapply_failures.iter())
        .cloned()
        .collect::<Vec<_>>();
    let (operator_canary_verdict, next_required_action) =
        if restart_canary_ready && rollback_canary_ready && reapply_canary_ready {
            ("green", "none".to_string())
        } else if release_summary
            .get("service_health_verdict")
            .and_then(Value::as_str)
            == Some("red")
            || operator_loop.get("overall_status").and_then(Value::as_str) == Some("red")
        {
            (
                "red",
                all_failures
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "inspect_operator_canary".to_string()),
            )
        } else {
            (
                "degraded",
                all_failures
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "inspect_operator_canary".to_string()),
            )
        };

    let payload = json!({
        "artifact_schema": "ubuntu_operator_reapply_canary_v1",
        "supported_product_contour": "ubuntu_first_operator_reapply_canary",
        "supported_operator_scope": "ubuntu_restart_reapply_rollback_canary",
        "pilot_inputs_json": display_path(pilot_inputs_path),
        "validation_summary_json": display_path(&validation_summary_path),
        "release_summary_json": display_path(&release_summary_path),
        "operator_loop_summary_json": display_path(&operator_loop_path),
        "service_health_verdict": release_summary.get("service_health_verdict").cloned().unwrap_or(Value::Null),
        "baseline_bypass_ready": release_summary.get("baseline_bypass_ready").cloned().unwrap_or(Value::Null),
        "baseline_bypass_verdict": release_summary.get("baseline_bypass_verdict").cloned().unwrap_or(Value::Null),
        "bypass_support_tier": release_summary.get("bypass_support_tier").cloned().unwrap_or(Value::Null),
        "upgrade_reapply_mode": validation_summary.get("upgrade_reapply_mode").cloned().unwrap_or(Value::Null),
        "restart_canary_ready": restart_canary_ready,
        "rollback_canary_ready": rollback_canary_ready,
        "reapply_canary_ready": reapply_canary_ready,
        "operator_canary_verdict": operator_canary_verdict,
        "next_required_action": next_required_action,
        "canonical_operator_canary": [
            "service_restart",
            "reboot_contract",
            "remove",
            "reinstall",
            "upgrade_reapply",
        ],
        "restart_checks": restart_checks,
        "rollback_checks": rollback_checks,
        "reapply_checks": reapply_checks,
        "restart_failures": restart_failures,
        "rollback_failures": rollback_failures,
        "reapply_failures": reapply_failures,
        "validation_lifecycle_phases": validation_summary.get("lifecycle_phases").cloned().unwrap_or_else(|| json!([])),
        "required_runtime_artifacts": validation_summary.get("required_runtime_artifacts").cloned().unwrap_or_else(|| json!([])),
        "run_command_example": "sudo env HOME=\"$HOME\" PATH=\"$HOME/.cargo/bin:$PATH\" bash scripts/validate-debian-package-host.sh --run --artifact-dir ./dist/ubuntu-release",
    });

    write_json(
        &output_dir.join("ubuntu-operator-reapply-canary.json"),
        &payload,
    )?;
    write_text(
        &output_dir.join("ubuntu-operator-reapply-canary.md"),
        &render_markdown(&payload),
    )?;
    Ok(())
}

fn required_path(
    value: &Value,
    key: &str,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let path = value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("pilot inputs missing {key}"))?;
    Ok(path.into())
}

fn phase_passed(validation_summary: &Value, name: &str) -> bool {
    validation_summary
        .get("phase_results")
        .and_then(Value::as_array)
        .and_then(|items| {
            items
                .iter()
                .find(|item| item.get("name").and_then(Value::as_str) == Some(name))
        })
        .and_then(|item| item.get("status").and_then(Value::as_str))
        == Some("passed")
}

fn phase_detail(validation_summary: &Value, name: &str) -> Value {
    validation_summary
        .get("phase_results")
        .and_then(Value::as_array)
        .and_then(|items| {
            items
                .iter()
                .find(|item| item.get("name").and_then(Value::as_str) == Some(name))
        })
        .and_then(|item| item.get("detail"))
        .cloned()
        .unwrap_or(Value::Null)
}

fn check_entry(passed: bool, rule: &str, failure_reason: &str, detail: Value) -> Value {
    json!({
        "passed": passed,
        "rule": rule,
        "failure_reason": if passed { Value::Null } else { Value::String(failure_reason.to_string()) },
        "detail": detail,
    })
}

fn failed_check_ids(checks: &Value) -> Vec<String> {
    checks
        .as_object()
        .into_iter()
        .flat_map(|items| items.iter())
        .filter(|(_, data)| data.get("passed").and_then(Value::as_bool) != Some(true))
        .map(|(check_id, _)| check_id.to_string())
        .collect()
}

fn render_markdown(payload: &Value) -> String {
    let mut lines = vec![
        "# Ubuntu Operator Reapply Canary".to_string(),
        String::new(),
        format!(
            "- Operator canary verdict: `{}`",
            payload["operator_canary_verdict"].as_str().unwrap_or("")
        ),
        format!(
            "- Restart canary ready: `{}`",
            payload["restart_canary_ready"]
        ),
        format!(
            "- Rollback canary ready: `{}`",
            payload["rollback_canary_ready"]
        ),
        format!(
            "- Reapply canary ready: `{}`",
            payload["reapply_canary_ready"]
        ),
        format!(
            "- Service health verdict: `{}`",
            payload["service_health_verdict"].as_str().unwrap_or("")
        ),
        format!(
            "- Baseline bypass verdict: `{}`",
            payload["baseline_bypass_verdict"].as_str().unwrap_or("")
        ),
        format!(
            "- Next required action: `{}`",
            payload["next_required_action"].as_str().unwrap_or("")
        ),
        String::new(),
        "## Restart Checks".to_string(),
        String::new(),
    ];
    append_checks(&mut lines, &payload["restart_checks"]);
    lines.extend([
        String::new(),
        "## Rollback / Reinstall Checks".to_string(),
        String::new(),
    ]);
    append_checks(&mut lines, &payload["rollback_checks"]);
    lines.extend([
        String::new(),
        "## Reapply Checks".to_string(),
        String::new(),
    ]);
    append_checks(&mut lines, &payload["reapply_checks"]);
    lines.join("\n") + "\n"
}

fn append_checks(lines: &mut Vec<String>, checks: &Value) {
    if let Some(items) = checks.as_object() {
        for (check_id, data) in items {
            let detail = data.get("detail").and_then(Value::as_str).unwrap_or("n/a");
            lines.push(format!(
                "- `{check_id}`: passed=`{}` detail=`{detail}`",
                data.get("passed").and_then(Value::as_bool).unwrap_or(false)
            ));
        }
    }
}

fn display_path(path: &Path) -> String {
    path.display().to_string()
}
