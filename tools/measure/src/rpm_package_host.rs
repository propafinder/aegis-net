use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::artifact::read_json;

pub struct RpmPackageHostValidationReportInputs<'a> {
    pub mode: &'a str,
    pub os_pretty_name: &'a str,
    pub os_id: &'a str,
    pub os_version_id: Option<&'a str>,
    pub package_manager: Option<&'a str>,
    pub supported_product_contour: &'a str,
    pub supported_operator_scope: &'a str,
    pub host_family_id: &'a str,
    pub host_family_validation_tier: &'a str,
    pub ready: bool,
    pub command: &'a [String],
    pub missing_command: &'a [String],
    pub remediation_command: &'a str,
    pub run_command: &'a str,
    pub validation_root: &'a str,
    pub helper_exit_code: Option<i32>,
    pub error_code: Option<&'a str>,
}

pub struct RpmPackageHostContractJsonCaseInputs<'a> {
    pub scenario: &'a str,
    pub output: &'a Path,
    pub exit_status: i32,
}

pub struct RpmPackageHostContractRunModeInputs<'a> {
    pub output: &'a Path,
    pub validation_summary: &'a Path,
    pub rpm_log: &'a Path,
    pub exit_status: i32,
    pub validation_root: &'a Path,
}

pub struct RpmPackageHostContractScriptInputs<'a> {
    pub script: &'a Path,
}

pub fn build_rpm_package_host_validation_report(
    inputs: RpmPackageHostValidationReportInputs<'_>,
) -> Result<Value, Box<dyn std::error::Error>> {
    let commands = inputs
        .command
        .iter()
        .map(|entry| parse_command_entry(entry))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(json!({
        "artifact_schema": "rpm_package_host_validation_v1",
        "mode": inputs.mode,
        "os_pretty_name": inputs.os_pretty_name,
        "os_id": inputs.os_id,
        "os_version_id": non_empty_or_null(inputs.os_version_id),
        "package_manager": non_empty_or_null(inputs.package_manager),
        "supported_product_contour": inputs.supported_product_contour,
        "supported_operator_scope": inputs.supported_operator_scope,
        "host_family_id": inputs.host_family_id,
        "host_family_validation_tier": inputs.host_family_validation_tier,
        "ready": inputs.ready,
        "commands": commands,
        "missing_commands": inputs.missing_command,
        "remediation_command": inputs.remediation_command,
        "run_command": inputs.run_command,
        "validation_root": inputs.validation_root,
        "helper_exit_code": inputs.helper_exit_code,
        "error_code": non_empty_or_null(inputs.error_code),
    }))
}

pub fn build_rpm_package_host_run_summary(validation_root: &str) -> Value {
    json!({
        "artifact_schema": "rpm_package_host_run_summary_v1",
        "expected_packages": [
            "aegis-server",
            "aegis-client",
        ],
        "expected_units": [
            "aegis-server.service",
            "aegis-client.service",
        ],
        "lifecycle_phases": [
            "install",
            "erase",
            "reinstall",
            "upgrade_reapply",
            "final_erase",
        ],
        "validation_root": validation_root,
    })
}

pub fn check_rpm_package_host_contract_json_case(
    inputs: RpmPackageHostContractJsonCaseInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = read_json_maybe_wrapped(inputs.output)?;
    match inputs.scenario {
        "happy-check" => {
            expect_i32(inputs.exit_status, 0, "exit status")?;
            expect_string_field(
                &payload,
                "artifact_schema",
                "rpm_package_host_validation_v1",
            )?;
            expect_string_field(&payload, "mode", "check")?;
            expect_bool_field(&payload, "ready", true)?;
            expect_i64_field(&payload, "helper_exit_code", 0)?;
            expect_string_field(&payload, "host_family_id", "rhel-dnf")?;
            expect_empty_array_field(&payload, "missing_commands")?;
            expect_command_status(&payload, "rpmbuild", "ok")?;
            expect_string_field_suffix(&payload, "run_command", "--run")?;
        }
        "missing-cargo" => {
            expect_i32(inputs.exit_status, 1, "exit status")?;
            expect_bool_field(&payload, "ready", false)?;
            expect_string_array_field(&payload, "missing_commands", &["cargo"])?;
            expect_i64_field(&payload, "helper_exit_code", 1)?;
            expect_optional_empty_string_field(&payload, "error_code")?;
        }
        "unknown-argument" => {
            expect_i32(inputs.exit_status, 1, "exit status")?;
            expect_bool_field(&payload, "ready", false)?;
            expect_string_field(&payload, "error_code", "unknown_argument")?;
            expect_i64_field(&payload, "helper_exit_code", 1)?;
        }
        other => return Err(format!("unknown rpm package host contract scenario: {other}").into()),
    }
    Ok(())
}

pub fn check_rpm_package_host_contract_run_mode(
    inputs: RpmPackageHostContractRunModeInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = read_json_maybe_wrapped(inputs.output)?;
    let summary = read_json(inputs.validation_summary)?;
    let rpm_log = std::fs::read_to_string(inputs.rpm_log)?;
    let root = normalized_path_display(inputs.validation_root);

    expect_i32(inputs.exit_status, 0, "exit status")?;
    expect_string_field(&payload, "mode", "run")?;
    expect_bool_field(&payload, "ready", true)?;
    expect_i64_field(&payload, "helper_exit_code", 0)?;
    expect_string_field(&payload, "validation_root", &root)?;
    expect_string_field(
        &summary,
        "artifact_schema",
        "rpm_package_host_run_summary_v1",
    )?;
    expect_string_array_field(
        &summary,
        "lifecycle_phases",
        &[
            "install",
            "erase",
            "reinstall",
            "upgrade_reapply",
            "final_erase",
        ],
    )?;
    expect_string_field(&summary, "validation_root", &root)?;
    expect_text_contains(&rpm_log, "-Uvh")?;
    expect_text_contains(&rpm_log, "-Uvh --replacepkgs")?;
    expect_text_contains(&rpm_log, "-e aegis-client aegis-server")?;
    expect_path_absent(inputs.validation_root, "/etc/default/aegis-server")?;
    expect_path_absent(inputs.validation_root, "/etc/default/aegis-client")?;
    Ok(())
}

pub fn check_rpm_package_host_contract_script(
    inputs: RpmPackageHostContractScriptInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(inputs.script)?;
    for needle in [
        "if AEGIS_RPM_POSTINSTALL_NONCE=\"${nonce}\" run_rpm_mutation -Uvh \"$@\"; then",
        "install_rpms_checked first \"${server_rpm}\" \"${client_rpm}\"",
        "run_rpm_mutation -e aegis-client aegis-server",
        "install_rpms_checked reinstall \"${server_rpm}\" \"${client_rpm}\"",
        "install_rpms_checked reapply --replacepkgs \"${server_rpm}\" \"${client_rpm}\"",
        r#"if [[ "$(run_as_root cat -- "${receipt}/aegis-server.ok" 2>/dev/null || true)" == "${nonce}" ]]; then"#,
        r#"if [[ "$(run_as_root cat -- "${receipt}/aegis-client.ok" 2>/dev/null || true)" == "${nonce}" ]]; then"#,
        r#"if [[ "${server_status}" != confirmed || "${client_status}" != confirmed ]]; then"#,
        "fail_helper \"rpm_postinstall_unconfirmed\"",
        "--server-rpm",
        "--client-rpm",
        "verify_disabled_units",
        "validation-summary.json",
        "VALIDATION_ROOT=\"${AEGIS_RPM_HOST_VALIDATION_ROOT:-/}\"",
    ] {
        expect_text_contains(&text, needle)?;
    }
    Ok(())
}

fn read_json_maybe_wrapped(path: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string(path)?;
    match serde_json::from_str(&raw) {
        Ok(value) => Ok(value),
        Err(err) => {
            let Some(start) = raw.find('{') else {
                return Err(err.into());
            };
            let Some(end) = raw.rfind('}') else {
                return Err(err.into());
            };
            if end <= start {
                return Err(err.into());
            }
            Ok(serde_json::from_str(&raw[start..=end])?)
        }
    }
}

fn parse_command_entry(entry: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let mut parts = entry.splitn(3, '\t');
    let name = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| format!("invalid command entry missing name: {entry:?}"))?;
    let status = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| format!("invalid command entry missing status: {entry:?}"))?;
    let detail = parts
        .next()
        .ok_or_else(|| format!("invalid command entry missing detail: {entry:?}"))?;

    Ok(json!({
        "name": name,
        "status": status,
        "detail": detail,
    }))
}

fn non_empty_or_null(value: Option<&str>) -> Value {
    value
        .filter(|value| !value.is_empty())
        .map(Value::from)
        .unwrap_or(Value::Null)
}

fn installed_path(validation_root: &Path, relative: &str) -> PathBuf {
    validation_root.join(relative.trim_start_matches('/'))
}

fn expect_path_absent(
    validation_root: &Path,
    relative: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = installed_path(validation_root, relative);
    if path.exists() {
        return Err(format!("expected {} to be absent", path.display()).into());
    }
    Ok(())
}

fn expect_text_contains(text: &str, needle: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !text.contains(needle) {
        return Err(format!("expected text to contain {needle:?}").into());
    }
    Ok(())
}

fn expect_i32(actual: i32, expected: i32, label: &str) -> Result<(), Box<dyn std::error::Error>> {
    if actual != expected {
        return Err(format!("expected {label} {expected}, got {actual}").into());
    }
    Ok(())
}

fn expect_string_field(
    value: &Value,
    field: &str,
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = value.get(field).and_then(Value::as_str);
    if actual != Some(expected) {
        return Err(format!("expected {field}={expected:?}, got {actual:?}").into());
    }
    Ok(())
}

fn expect_string_field_suffix(
    value: &Value,
    field: &str,
    suffix: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = value.get(field).and_then(Value::as_str).unwrap_or("");
    if !actual.ends_with(suffix) {
        return Err(format!("expected {field} to end with {suffix:?}, got {actual:?}").into());
    }
    Ok(())
}

fn expect_optional_empty_string_field(
    value: &Value,
    field: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(actual)) if actual.is_empty() => Ok(()),
        Some(actual) => Err(format!("expected {field} to be null or empty, got {actual}").into()),
    }
}

fn expect_bool_field(
    value: &Value,
    field: &str,
    expected: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = value.get(field).and_then(Value::as_bool);
    if actual != Some(expected) {
        return Err(format!("expected {field}={expected}, got {actual:?}").into());
    }
    Ok(())
}

fn expect_i64_field(
    value: &Value,
    field: &str,
    expected: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = value.get(field).and_then(Value::as_i64);
    if actual != Some(expected) {
        return Err(format!("expected {field}={expected}, got {actual:?}").into());
    }
    Ok(())
}

fn expect_empty_array_field(value: &Value, field: &str) -> Result<(), Box<dyn std::error::Error>> {
    let actual = value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("expected {field} to be an array"))?;
    if !actual.is_empty() {
        return Err(format!("expected {field} to be empty, got {actual:?}").into());
    }
    Ok(())
}

fn expect_string_array_field(
    value: &Value,
    field: &str,
    expected: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("expected {field} to be an array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| format!("expected {field} entries to be strings"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if actual != expected {
        return Err(format!("expected {field}={expected:?}, got {actual:?}").into());
    }
    Ok(())
}

fn expect_command_status(
    value: &Value,
    name: &str,
    expected_status: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let commands = value
        .get("commands")
        .and_then(Value::as_array)
        .ok_or("expected commands array")?;
    if commands.iter().any(|command| {
        command.get("name").and_then(Value::as_str) == Some(name)
            && command.get("status").and_then(Value::as_str) == Some(expected_status)
    }) {
        return Ok(());
    }
    Err(format!("expected command {name:?} to have status {expected_status:?}").into())
}

fn normalized_path_display(path: &Path) -> String {
    path.components().collect::<PathBuf>().display().to_string()
}
