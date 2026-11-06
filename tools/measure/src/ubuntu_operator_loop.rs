use std::path::Path;

use serde_json::{json, Value};

use crate::artifact::{read_json, write_json};

pub struct UbuntuOperatorLoopSummaryInputs<'a> {
    pub output: &'a Path,
    pub client_config: &'a str,
    pub runtime_events_jsonl: &'a str,
    pub operator_evidence_json: &'a Path,
    pub doctor_log: &'a str,
    pub probe_log: &'a str,
    pub events_log: &'a str,
    pub doctor_status: i64,
    pub probe_status: i64,
    pub events_status: i64,
}

pub struct UbuntuOperatorLoopCheckReportInputs<'a> {
    pub mode: &'a str,
    pub supported_product_contour: &'a str,
    pub supported_operator_scope: &'a str,
    pub helper_script: &'a str,
    pub client_config: Option<&'a str>,
    pub runtime_events_jsonl: Option<&'a str>,
    pub operator_evidence_json: Option<&'a str>,
    pub artifact_dir: Option<&'a str>,
    pub ready: bool,
    pub requirement: &'a [String],
    pub missing_requirement: &'a [String],
    pub helper_exit_code: i32,
    pub error_code: Option<&'a str>,
}

pub fn build_ubuntu_operator_loop_check_report(
    inputs: UbuntuOperatorLoopCheckReportInputs<'_>,
) -> Result<Value, Box<dyn std::error::Error>> {
    let requirements = inputs
        .requirement
        .iter()
        .map(|entry| parse_requirement_entry(entry))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(json!({
        "artifact_schema": "ubuntu_product_operator_loop_v1",
        "mode": inputs.mode,
        "supported_product_contour": inputs.supported_product_contour,
        "supported_operator_scope": inputs.supported_operator_scope,
        "helper_script": inputs.helper_script,
        "client_config": non_empty_or_null(inputs.client_config),
        "runtime_events_jsonl": non_empty_or_null(inputs.runtime_events_jsonl),
        "operator_evidence_json": non_empty_or_null(inputs.operator_evidence_json),
        "artifact_dir": non_empty_or_null(inputs.artifact_dir),
        "ready": inputs.ready,
        "requirements": requirements,
        "missing_requirements": inputs.missing_requirement,
        "canonical_operator_loop": ["doctor", "probe", "events"],
        "helper_exit_code": inputs.helper_exit_code,
        "error_code": non_empty_or_null(inputs.error_code),
    }))
}

pub fn build_ubuntu_operator_loop_summary(
    inputs: UbuntuOperatorLoopSummaryInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let operator_payload = if inputs.operator_evidence_json.is_file() {
        Some(read_json(inputs.operator_evidence_json)?)
    } else {
        None
    };
    let product_verdict = string_field(operator_payload.as_ref(), "product_verdict");
    let startup_health = string_field(operator_payload.as_ref(), "startup_health");
    let runtime_status = string_field(operator_payload.as_ref(), "runtime_status");

    let overall_status = if operator_payload.is_none() {
        "red"
    } else if product_verdict.as_deref() == Some("green")
        && inputs.doctor_status == 0
        && inputs.probe_status == 0
        && inputs.events_status == 0
    {
        "green"
    } else if product_verdict.as_deref() == Some("red") {
        "red"
    } else {
        "degraded"
    };

    let payload = json!({
        "artifact_schema": "ubuntu_product_operator_loop_summary_v1",
        "supported_product_contour": "ubuntu_first_operator_loop",
        "supported_operator_scope": "ubuntu_first_doctor_probe_events",
        "client_config": inputs.client_config,
        "runtime_events_jsonl": inputs.runtime_events_jsonl,
        "operator_evidence_json": inputs.operator_evidence_json.display().to_string(),
        "overall_status": overall_status,
        "startup_health": startup_health,
        "runtime_status": runtime_status,
        "product_verdict": product_verdict,
        "actions": [
            {
                "name": "doctor",
                "exit_code": inputs.doctor_status,
                "log_path": inputs.doctor_log,
            },
            {
                "name": "probe",
                "exit_code": inputs.probe_status,
                "log_path": inputs.probe_log,
            },
            {
                "name": "events",
                "exit_code": inputs.events_status,
                "log_path": inputs.events_log,
            },
        ],
        "canonical_operator_loop": [
            "doctor",
            "probe",
            "events",
        ],
        "next_recommended_action": if overall_status == "green" {
            "none"
        } else {
            "inspect_doctor_probe_events_logs"
        },
    });
    write_json(inputs.output, &payload)?;
    Ok(())
}

fn string_field(payload: Option<&Value>, key: &str) -> Option<String> {
    payload
        .and_then(|value| value.get(key))
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn parse_requirement_entry(entry: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let mut parts = entry.splitn(3, '\t');
    let name = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| format!("invalid requirement entry missing name: {entry:?}"))?;
    let status = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| format!("invalid requirement entry missing status: {entry:?}"))?;
    let detail = parts
        .next()
        .ok_or_else(|| format!("invalid requirement entry missing detail: {entry:?}"))?;

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
