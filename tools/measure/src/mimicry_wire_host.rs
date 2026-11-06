use std::{collections::BTreeMap, fs, path::Path};

use serde_json::{json, Value};

use crate::artifact::{read_json, write_json};

const WINDOW_TOLERANCE_MS: i64 = 3000;

#[derive(Clone, Debug)]
struct RuntimeCandidate {
    event_code: Value,
    runtime_slice: Value,
    target: Value,
    port: Value,
    ts_unix_ms: Value,
    wire_signature: BTreeMap<&'static str, Value>,
}

type WitnessRuntimeMatch<'a> = (usize, usize, Vec<String>, Vec<Value>, &'a RuntimeCandidate);

pub struct MimicryWireHostAcceptanceInputs<'a> {
    pub runtime_events_jsonl: &'a Path,
    pub contract_json: &'a Path,
    pub capture_summary_json: &'a Path,
    pub host_summary_json: &'a Path,
    pub witness_summary_json: Option<&'a Path>,
}

pub struct MimicryWireHostHelperReportInputs<'a> {
    pub mode: &'a str,
    pub supported_operator_scope: &'a str,
    pub supported_product_contour: &'a str,
    pub ready: bool,
    pub runtime_events_jsonl: Option<&'a str>,
    pub witness_summary_json: Option<&'a str>,
    pub artifact_dir: Option<&'a str>,
    pub requirement: &'a [String],
    pub missing_requirement: &'a [String],
    pub helper_exit_code: i32,
    pub error_code: Option<&'a str>,
}

pub struct MimicryWireHostAcceptanceContractInputs<'a> {
    pub host_summary_json: &'a Path,
    pub capture_summary_json: Option<&'a Path>,
    pub stdout_json: Option<&'a Path>,
    pub expected_product_verdict: &'a str,
    pub expected_acceptance_status: &'a str,
    pub expected_verdict_reason: &'a str,
    pub expected_witness_status: Option<&'a str>,
    pub expected_hostile_path_ready: Option<bool>,
    pub expected_hostile_path_tier: Option<&'a str>,
    pub expected_witness_matched: Option<u64>,
    pub expected_witness_mismatched: Option<u64>,
    pub expected_mismatch_field: Option<&'a str>,
    pub expected_records_scanned: Option<u64>,
    pub expected_complete_records: Option<u64>,
    pub expected_active_ready_count: Option<u64>,
    pub expected_active_missing_count: Option<u64>,
}

pub fn build_mimicry_wire_host_helper_report(
    inputs: MimicryWireHostHelperReportInputs<'_>,
) -> Result<Value, Box<dyn std::error::Error>> {
    let requirements = inputs
        .requirement
        .iter()
        .map(|entry| parse_helper_requirement_entry(entry))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(json!({
        "artifact_schema": "wire_mimicry_host_helper_report_v1",
        "mode": inputs.mode,
        "supported_operator_scope": inputs.supported_operator_scope,
        "supported_product_contour": inputs.supported_product_contour,
        "ready": inputs.ready,
        "runtime_events_jsonl": non_empty_or_null(inputs.runtime_events_jsonl),
        "witness_summary_json": non_empty_or_null(inputs.witness_summary_json),
        "artifact_dir": non_empty_or_null(inputs.artifact_dir),
        "requirements": requirements,
        "missing_requirements": inputs.missing_requirement,
        "helper_exit_code": inputs.helper_exit_code,
        "error_code": non_empty_or_null(inputs.error_code),
    }))
}

pub fn check_mimicry_wire_host_helper_report_contract(
    report_json: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = read_json(report_json)?;
    ensure_helper_contract(
        payload["artifact_schema"].as_str() == Some("wire_mimicry_host_helper_report_v1"),
        "helper report artifact_schema",
    )?;
    ensure_helper_contract(
        payload["mode"].as_str() == Some("check"),
        "helper report mode",
    )?;
    ensure_helper_contract(
        payload["supported_operator_scope"].as_str()
            == Some("privileged_linux_wire_mimicry_acceptance"),
        "helper report supported_operator_scope",
    )?;
    ensure_helper_contract(
        payload["supported_product_contour"].as_str() == Some("future_packet_wire_linux_only"),
        "helper report supported_product_contour",
    )?;
    ensure_helper_contract(
        payload["ready"].as_bool() == Some(true),
        "helper report ready",
    )?;
    ensure_helper_contract(
        payload["helper_exit_code"].as_i64() == Some(0),
        "helper report helper_exit_code",
    )?;
    ensure_requirement(&payload, "linux_host", "ok")?;
    ensure_requirement_absent(&payload, "python3")?;
    ensure_requirement(&payload, "mimicry_wire_contract", "ok")?;
    ensure_requirement(&payload, "cargo", "ok")?;
    ensure_requirement(&payload, "CAP_NET_RAW", "ok")?;
    ensure_requirement(&payload, "CAP_NET_ADMIN", "ok")?;
    Ok(())
}

pub fn check_mimicry_wire_host_acceptance_contract(
    inputs: MimicryWireHostAcceptanceContractInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let host_payload = read_json(inputs.host_summary_json)?;
    let capture_payload = inputs.capture_summary_json.map(read_json).transpose()?;
    let stdout_payload = inputs.stdout_json.map(read_json).transpose()?;

    if let Some(stdout_payload) = stdout_payload.as_ref() {
        ensure_helper_contract(
            stdout_payload["artifact_schema"].as_str() == Some("wire_mimicry_host_acceptance_v1"),
            "stdout artifact_schema",
        )?;
    }
    ensure_helper_contract(
        host_payload["artifact_schema"].as_str() == Some("wire_mimicry_host_acceptance_v1"),
        "host artifact_schema",
    )?;
    if let Some(capture_payload) = capture_payload.as_ref() {
        ensure_helper_contract(
            capture_payload["artifact_schema"].as_str() == Some("wire_capture_replay_summary_v1"),
            "capture artifact_schema",
        )?;
    }

    assert_json_str(
        &host_payload,
        "product_verdict",
        inputs.expected_product_verdict,
    )?;
    assert_json_str(
        &host_payload,
        "acceptance_status",
        inputs.expected_acceptance_status,
    )?;
    assert_json_str(
        &host_payload,
        "verdict_reason",
        inputs.expected_verdict_reason,
    )?;
    if let Some(expected) = inputs.expected_witness_status {
        assert_json_str(
            &host_payload,
            "independent_witness_correlation_status",
            expected,
        )?;
        if let Some(capture_payload) = capture_payload.as_ref() {
            assert_json_str(
                capture_payload,
                "independent_witness_correlation_status",
                expected,
            )?;
        }
    }
    if let Some(expected) = inputs.expected_hostile_path_ready {
        assert_json_bool(&host_payload, "hostile_path_support_ready", expected)?;
    }
    if let Some(expected) = inputs.expected_hostile_path_tier {
        assert_json_str(&host_payload, "hostile_path_support_tier", expected)?;
    }
    if let Some(expected) = inputs.expected_records_scanned {
        let capture_payload = require_capture(capture_payload.as_ref())?;
        assert_json_u64(capture_payload, "records_scanned", expected)?;
    }
    if let Some(expected) = inputs.expected_complete_records {
        let capture_payload = require_capture(capture_payload.as_ref())?;
        assert_json_u64(
            capture_payload,
            "records_with_complete_wire_fields",
            expected,
        )?;
    }
    if let Some(expected) = inputs.expected_active_ready_count {
        let capture_payload = require_capture(capture_payload.as_ref())?;
        assert_nested_json_u64(
            capture_payload,
            &["active_runtime_records_with_required_ready_fields", "count"],
            expected,
        )?;
    }
    if let Some(expected) = inputs.expected_active_missing_count {
        let capture_payload = require_capture(capture_payload.as_ref())?;
        assert_nested_json_u64(
            capture_payload,
            &[
                "active_runtime_records_missing_required_ready_fields",
                "count",
            ],
            expected,
        )?;
    }
    if let Some(expected) = inputs.expected_witness_matched {
        assert_json_u64(
            &host_payload,
            "independent_witness_records_matched",
            expected,
        )?;
        if let Some(capture_payload) = capture_payload.as_ref() {
            assert_nested_json_u64(
                capture_payload,
                &["independent_witness_records_matched", "count"],
                expected,
            )?;
        }
    }
    if let Some(expected) = inputs.expected_witness_mismatched {
        assert_json_u64(
            &host_payload,
            "independent_witness_records_mismatched",
            expected,
        )?;
        if let Some(capture_payload) = capture_payload.as_ref() {
            assert_nested_json_u64(
                capture_payload,
                &["independent_witness_records_mismatched", "count"],
                expected,
            )?;
        }
    }
    if let Some(expected_field) = inputs.expected_mismatch_field {
        let capture_payload = require_capture(capture_payload.as_ref())?;
        let actual = capture_payload
            .pointer("/independent_witness_records_mismatched/events/0/field_mismatches/0/field")
            .and_then(Value::as_str);
        ensure_helper_contract(
            actual == Some(expected_field),
            "mismatch field must match expected witness diff",
        )?;
    }
    if inputs.expected_product_verdict == "green" {
        assert_runtime_state_matrix(&host_payload, capture_payload.as_ref())?;
    }
    Ok(())
}

pub fn build_mimicry_wire_host_acceptance(
    inputs: MimicryWireHostAcceptanceInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let contract = read_json(inputs.contract_json)?;
    let required_fields = string_array(&contract, "required_runtime_capability_fields")?;
    let required_active_ready_fields =
        string_array_or_empty(&contract, "required_active_runtime_ready_fields");
    let witness_schema = contract
        .get("witness_summary_schema")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let witness_correlation_fields = string_array_or_empty(&contract, "witness_correlation_fields");

    let records = parse_jsonl_lenient(inputs.runtime_events_jsonl)?;
    let mut complete_records = Vec::new();
    let mut requested_false = Vec::new();
    let mut requested_inactive = Vec::new();
    let mut requested_active = Vec::new();
    let mut activation_reasons: BTreeMap<String, u64> = BTreeMap::new();
    let mut runtime_slices: BTreeMap<String, u64> = BTreeMap::new();
    let mut active_ready_fields_ok = Vec::new();
    let mut active_ready_fields_missing = Vec::new();
    let mut active_runtime_candidates = Vec::new();

    for record in &records {
        let fields = wire_fields(record);
        if !required_fields
            .iter()
            .all(|name| fields.get(name).is_some())
        {
            continue;
        }
        complete_records.push(record.clone());

        let requested = truthy(fields.get("mimicry_capability_wire_requested"));
        let active = truthy(fields.get("mimicry_capability_wire_active"));
        let reason = clone_field(fields, "mimicry_capability_wire_activation_reason");
        if let Some(reason_text) = reason.as_str() {
            increment(&mut activation_reasons, reason_text);
        }
        let runtime_slice = clone_field(fields, "mimicry_capability_wire_runtime_slice");
        if let Some(slice_text) = runtime_slice.as_str() {
            increment(&mut runtime_slices, slice_text);
        }

        let event_ref = json!({
            "event_code": record.get("event_code").cloned().unwrap_or(Value::Null),
            "signal_origin": clone_field(fields, "mimicry_capability_signal_origin"),
            "activation_reason": reason,
            "runtime_slice": runtime_slice,
            "target": clone_field(fields, "target"),
            "port": clone_field(fields, "port"),
            "ts_unix_ms": record.get("ts_unix_ms").cloned().unwrap_or(Value::Null),
        });

        if !requested {
            requested_false.push(event_ref);
        } else if active {
            active_runtime_candidates.push(RuntimeCandidate {
                event_code: record.get("event_code").cloned().unwrap_or(Value::Null),
                runtime_slice: clone_field(fields, "mimicry_capability_wire_runtime_slice"),
                target: clone_field(fields, "target"),
                port: clone_field(fields, "port"),
                ts_unix_ms: record.get("ts_unix_ms").cloned().unwrap_or(Value::Null),
                wire_signature: normalize_runtime_signature(fields),
            });
            if required_active_ready_fields
                .iter()
                .all(|name| truthy(fields.get(name)))
            {
                active_ready_fields_ok.push(event_ref.clone());
            } else {
                let missing_ready_fields: Vec<Value> = required_active_ready_fields
                    .iter()
                    .filter(|name| !truthy(fields.get(*name)))
                    .map(|name| Value::String(name.clone()))
                    .collect();
                active_ready_fields_missing.push(merge_object(
                    event_ref.clone(),
                    "missing_ready_fields",
                    Value::Array(missing_ready_fields),
                ));
            }
            requested_active.push(event_ref);
        } else {
            requested_inactive.push(event_ref);
        }
    }

    let observed_states = json!({
        "requested_false": {
            "observed": !requested_false.is_empty(),
            "count": requested_false.len(),
            "events": requested_false,
        },
        "requested_true_inactive": {
            "observed": !requested_inactive.is_empty(),
            "count": requested_inactive.len(),
            "events": requested_inactive,
        },
        "requested_true_active": {
            "observed": !requested_active.is_empty(),
            "count": requested_active.len(),
            "events": requested_active,
        },
    });

    let all_states_observed = observed_states
        .as_object()
        .map(|states| {
            states
                .values()
                .all(|state| state.get("observed").and_then(Value::as_bool) == Some(true))
        })
        .unwrap_or(false);

    let (mut verdict, mut acceptance_status, mut verdict_reason) = if all_states_observed
        && !complete_records.is_empty()
        && !active_ready_fields_ok.is_empty()
    {
        (
            "green",
            "passed",
            "full_wire_state_matrix_with_privileged_active_runtime",
        )
    } else if all_states_observed && !complete_records.is_empty() {
        (
            "degraded",
            "degraded",
            "full_wire_state_matrix_without_privileged_active_runtime",
        )
    } else if !complete_records.is_empty()
        && observed_states.as_object().is_some_and(|states| {
            states
                .values()
                .any(|state| state.get("observed").and_then(Value::as_bool) == Some(true))
        })
    {
        ("degraded", "degraded", "partial_wire_state_matrix_only")
    } else {
        ("red", "failed", "wire_runtime_fields_missing")
    };

    let witness_summary = match inputs.witness_summary_json {
        Some(path) => {
            let summary = read_json(path)?;
            if let Some(schema) = witness_schema.as_deref() {
                let got = summary.get("artifact_schema").and_then(Value::as_str);
                if got != Some(schema) {
                    return Err(format!(
                        "witness summary schema mismatch: expected {schema}, got {}",
                        got.unwrap_or("<missing>")
                    )
                    .into());
                }
            }
            Some(summary)
        }
        None => None,
    };

    let witness_records = witness_records_from_summary(witness_summary.as_ref());
    let witness_correlations: Vec<Value> = witness_records
        .iter()
        .map(|record| {
            correlate_witness_record(
                record,
                &active_runtime_candidates,
                &witness_correlation_fields,
            )
        })
        .collect();
    let matched_witness: Vec<Value> = witness_correlations
        .iter()
        .filter(|item| item.get("status").and_then(Value::as_str) == Some("matched"))
        .cloned()
        .collect();
    let mismatched_witness: Vec<Value> = witness_correlations
        .iter()
        .filter(|item| item.get("status").and_then(Value::as_str) == Some("mismatched"))
        .cloned()
        .collect();
    let uncorrelated_witness: Vec<Value> = witness_correlations
        .iter()
        .filter(|item| {
            matches!(
                item.get("status").and_then(Value::as_str),
                Some("unmatched_runtime" | "insufficient_detail")
            )
        })
        .cloned()
        .collect();

    let witness_correlation_status = if witness_summary.is_none() {
        "not_provided"
    } else if !witness_records.is_empty() && matched_witness.len() == witness_records.len() {
        "matched"
    } else if !mismatched_witness.is_empty() {
        "mismatched"
    } else {
        "uncorrelated"
    };

    if witness_correlation_status == "matched" && verdict == "green" {
        verdict_reason = "full_wire_state_matrix_with_privileged_active_runtime_and_witness_match";
    } else if matches!(witness_correlation_status, "mismatched" | "uncorrelated")
        && verdict == "green"
    {
        verdict = "degraded";
        acceptance_status = "degraded";
        verdict_reason = "independent_witness_not_correlated_with_runtime";
    }

    let capture_summary = json!({
        "artifact_schema": "wire_capture_replay_summary_v1",
        "validation_strategy": contract["validation_strategy"],
        "runtime_events_jsonl": inputs.runtime_events_jsonl.display().to_string(),
        "records_scanned": records.len(),
        "records_with_complete_wire_fields": complete_records.len(),
        "required_runtime_capability_fields": required_fields,
        "observed_state_matrix": observed_states,
        "activation_reason_counts": activation_reasons,
        "runtime_slice_counts": runtime_slices,
        "required_active_runtime_ready_fields": required_active_ready_fields,
        "active_runtime_records_with_required_ready_fields": {
            "count": active_ready_fields_ok.len(),
            "events": active_ready_fields_ok,
        },
        "active_runtime_records_missing_required_ready_fields": {
            "count": active_ready_fields_missing.len(),
            "events": active_ready_fields_missing,
        },
        "independent_witness_summary_json": optional_path_string(inputs.witness_summary_json),
        "independent_witness_summary_schema": witness_summary.as_ref().and_then(|value| value.get("artifact_schema")).cloned().unwrap_or(Value::Null),
        "independent_witness_correlation_status": witness_correlation_status,
        "independent_witness_records_scanned": witness_records.len(),
        "independent_witness_records_matched": {
            "count": matched_witness.len(),
            "events": matched_witness,
        },
        "independent_witness_records_mismatched": {
            "count": mismatched_witness.len(),
            "events": mismatched_witness,
        },
        "independent_witness_records_uncorrelated": {
            "count": uncorrelated_witness.len(),
            "events": uncorrelated_witness,
        },
    });
    write_json(inputs.capture_summary_json, &capture_summary)?;

    let required_runtime_states = vec![
        "requested_false",
        "requested_true_inactive",
        "requested_true_active",
    ];
    let observed_runtime_states: Vec<&str> = required_runtime_states
        .iter()
        .copied()
        .filter(|name| {
            capture_summary["observed_state_matrix"][name]
                .get("observed")
                .and_then(Value::as_bool)
                == Some(true)
        })
        .collect();
    let hostile_path_support_ready = verdict == "green" && witness_correlation_status == "matched";

    let host_summary = json!({
        "artifact_schema": "wire_mimicry_host_acceptance_v1",
        "acceptance_contour": "privileged_linux_wire_mimicry_acceptance",
        "scope": contract["scope"],
        "separate_from_release_gate": contract["separate_from_release_gate"],
        "release_gate_dependency": contract["release_gate_dependency"],
        "runtime_events_jsonl": inputs.runtime_events_jsonl.display().to_string(),
        "capture_replay_summary_json": inputs.capture_summary_json.display().to_string(),
        "independent_witness_summary_json": optional_path_string(inputs.witness_summary_json),
        "host_artifact_path": inputs.host_summary_json.display().to_string(),
        "required_runtime_states": required_runtime_states,
        "observed_runtime_states": observed_runtime_states,
        "required_active_runtime_ready_fields": string_array_or_empty(&contract, "required_active_runtime_ready_fields"),
        "active_runtime_records_with_required_ready_fields": capture_summary["active_runtime_records_with_required_ready_fields"]["count"],
        "active_runtime_records_missing_required_ready_fields": capture_summary["active_runtime_records_missing_required_ready_fields"]["count"],
        "independent_witness_correlation_status": witness_correlation_status,
        "independent_witness_records_scanned": witness_records.len(),
        "independent_witness_records_matched": capture_summary["independent_witness_records_matched"]["count"],
        "independent_witness_records_mismatched": capture_summary["independent_witness_records_mismatched"]["count"],
        "independent_witness_records_uncorrelated": capture_summary["independent_witness_records_uncorrelated"]["count"],
        "independent_witness_required_for_hostile_path_claim": true,
        "hostile_path_support_ready": hostile_path_support_ready,
        "hostile_path_support_tier": if hostile_path_support_ready { "wire_level_supported_hostile_path" } else { "not_proven" },
        "records_scanned": records.len(),
        "records_with_complete_wire_fields": complete_records.len(),
        "product_verdict": verdict,
        "acceptance_status": acceptance_status,
        "verdict_reason": verdict_reason,
        "verdict_vocabulary": contract["verdict_vocabulary"],
    });
    write_json(inputs.host_summary_json, &host_summary)?;
    Ok(())
}

fn parse_jsonl_lenient(path: &Path) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    let mut records = Vec::new();
    for line in fs::read_to_string(path)?.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(payload) = serde_json::from_str::<Value>(trimmed) {
            records.push(payload);
        }
    }
    Ok(records)
}

fn wire_fields(record: &Value) -> &serde_json::Map<String, Value> {
    match record.get("fields").and_then(Value::as_object) {
        Some(fields) => fields,
        None => empty_map(),
    }
}

fn empty_map() -> &'static serde_json::Map<String, Value> {
    static EMPTY: std::sync::OnceLock<serde_json::Map<String, Value>> = std::sync::OnceLock::new();
    EMPTY.get_or_init(serde_json::Map::new)
}

fn clone_field(fields: &serde_json::Map<String, Value>, name: &str) -> Value {
    fields.get(name).cloned().unwrap_or(Value::Null)
}

fn truthy(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Bool(value)) => *value,
        Some(Value::Number(value)) => value.as_i64().is_some_and(|number| number != 0),
        Some(Value::String(value)) => !value.is_empty(),
        Some(Value::Array(value)) => !value.is_empty(),
        Some(Value::Object(value)) => !value.is_empty(),
        _ => false,
    }
}

fn increment(map: &mut BTreeMap<String, u64>, key: &str) {
    *map.entry(key.to_owned()).or_default() += 1;
}

fn merge_object(mut value: Value, key: &str, field_value: Value) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.insert(key.to_owned(), field_value);
    }
    value
}

fn string_array(value: &Value, key: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing array field: {key}"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{key} contains non-string value").into())
        })
        .collect()
}

fn string_array_or_empty(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn optional_path_string(path: Option<&Path>) -> Value {
    path.map(|path| Value::String(path.display().to_string()))
        .unwrap_or(Value::Null)
}

fn normalize_runtime_signature(
    fields: &serde_json::Map<String, Value>,
) -> BTreeMap<&'static str, Value> {
    BTreeMap::from([
        (
            "ttl_preface",
            clone_field(fields, "mimicry_capability_wire_ttl_preface"),
        ),
        (
            "window_preface",
            clone_field(fields, "mimicry_capability_wire_window_preface"),
        ),
        (
            "ipv4_header_shaping.tos",
            clone_field(fields, "mimicry_capability_wire_ipv4_header_shaping_tos"),
        ),
        (
            "ipv4_header_shaping.ip_id",
            clone_field(fields, "mimicry_capability_wire_ipv4_header_shaping_ip_id"),
        ),
        (
            "ipv4_header_shaping.dont_fragment",
            clone_field(
                fields,
                "mimicry_capability_wire_ipv4_header_shaping_dont_fragment",
            ),
        ),
        (
            "negotiated_options.mss",
            clone_field(fields, "mimicry_capability_wire_negotiated_options_mss"),
        ),
        (
            "negotiated_options.window_scale",
            clone_field(
                fields,
                "mimicry_capability_wire_negotiated_options_window_scale",
            ),
        ),
        (
            "negotiated_options.sack_permitted",
            clone_field(
                fields,
                "mimicry_capability_wire_negotiated_options_sack_permitted",
            ),
        ),
        (
            "negotiated_options.timestamp_mode",
            clone_field(
                fields,
                "mimicry_capability_wire_negotiated_options_timestamp_mode",
            ),
        ),
        (
            "fragment_choreography.first_payload_len",
            clone_field(
                fields,
                "mimicry_capability_wire_fragment_choreography_first_payload_len",
            ),
        ),
        (
            "fragment_choreography.disorder_split_at",
            clone_field(
                fields,
                "mimicry_capability_wire_fragment_choreography_disorder_split_at",
            ),
        ),
        (
            "fragment_choreography.overlap",
            clone_field(
                fields,
                "mimicry_capability_wire_fragment_choreography_overlap",
            ),
        ),
    ])
}

fn normalize_witness_signature(record: &Value) -> BTreeMap<&'static str, Value> {
    BTreeMap::from([
        (
            "ttl_preface",
            record.get("ttl_preface").cloned().unwrap_or(Value::Null),
        ),
        (
            "window_preface",
            record.get("window_preface").cloned().unwrap_or(Value::Null),
        ),
        (
            "ipv4_header_shaping.tos",
            nested_field(record, "ipv4_header_shaping", "tos"),
        ),
        (
            "ipv4_header_shaping.ip_id",
            nested_field(record, "ipv4_header_shaping", "ip_id"),
        ),
        (
            "ipv4_header_shaping.dont_fragment",
            nested_field(record, "ipv4_header_shaping", "dont_fragment"),
        ),
        (
            "negotiated_options.mss",
            nested_field(record, "negotiated_options", "mss"),
        ),
        (
            "negotiated_options.window_scale",
            nested_field(record, "negotiated_options", "window_scale"),
        ),
        (
            "negotiated_options.sack_permitted",
            nested_field(record, "negotiated_options", "sack_permitted"),
        ),
        (
            "negotiated_options.timestamp_mode",
            nested_field(record, "negotiated_options", "timestamp_mode"),
        ),
        (
            "fragment_choreography.first_payload_len",
            nested_field(record, "fragment_choreography", "first_payload_len"),
        ),
        (
            "fragment_choreography.disorder_split_at",
            nested_field(record, "fragment_choreography", "disorder_split_at"),
        ),
        (
            "fragment_choreography.overlap",
            nested_field(record, "fragment_choreography", "overlap"),
        ),
    ])
}

fn nested_field(record: &Value, group: &str, key: &str) -> Value {
    record
        .get(group)
        .and_then(Value::as_object)
        .and_then(|object| object.get(key))
        .cloned()
        .unwrap_or(Value::Null)
}

fn witness_records_from_summary(summary: Option<&Value>) -> Vec<Value> {
    match summary {
        Some(summary) => summary
            .get("records")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_else(|| vec![summary.clone()]),
        None => Vec::new(),
    }
}

fn witness_capture_window(record: &Value) -> (Option<i64>, Option<i64>) {
    let window = record.get("capture_window").and_then(Value::as_object);
    (
        window
            .and_then(|window| window.get("start_unix_ms"))
            .and_then(Value::as_i64),
        window
            .and_then(|window| window.get("end_unix_ms"))
            .and_then(Value::as_i64),
    )
}

fn witness_target_port_matches(runtime_record: &RuntimeCandidate, witness_record: &Value) -> bool {
    if witness_record.get("target") != Some(&runtime_record.target) {
        return false;
    }
    if witness_record.get("port") != Some(&runtime_record.port) {
        return false;
    }
    let witness_slice = witness_record
        .get("runtime_slice")
        .cloned()
        .unwrap_or(Value::Null);
    if !witness_slice.is_null() && witness_slice != runtime_record.runtime_slice {
        return false;
    }
    let (start_unix_ms, end_unix_ms) = witness_capture_window(witness_record);
    let runtime_ts = runtime_record.ts_unix_ms.as_i64();
    if let (Some(start), Some(runtime_ts)) = (start_unix_ms, runtime_ts) {
        if runtime_ts < start - WINDOW_TOLERANCE_MS {
            return false;
        }
    }
    if let (Some(end), Some(runtime_ts)) = (end_unix_ms, runtime_ts) {
        if runtime_ts > end + WINDOW_TOLERANCE_MS {
            return false;
        }
    }
    true
}

fn correlate_witness_record(
    witness_record: &Value,
    active_runtime_candidates: &[RuntimeCandidate],
    witness_correlation_fields: &[String],
) -> Value {
    let matching_runtime_records: Vec<&RuntimeCandidate> = active_runtime_candidates
        .iter()
        .filter(|runtime_record| witness_target_port_matches(runtime_record, witness_record))
        .collect();
    if matching_runtime_records.is_empty() {
        return json!({
            "status": "unmatched_runtime",
            "witness_target": witness_record.get("target").cloned().unwrap_or(Value::Null),
            "witness_port": witness_record.get("port").cloned().unwrap_or(Value::Null),
            "witness_runtime_slice": witness_record.get("runtime_slice").cloned().unwrap_or(Value::Null),
        });
    }

    let witness_signature = normalize_witness_signature(witness_record);
    let mut best: Option<WitnessRuntimeMatch<'_>> = None;
    for runtime_record in matching_runtime_records {
        let mut compared_fields = Vec::new();
        let mut mismatches = Vec::new();
        for field_name in witness_correlation_fields {
            let witness_value = witness_signature
                .get(field_name.as_str())
                .cloned()
                .unwrap_or(Value::Null);
            if witness_value.is_null() {
                continue;
            }
            let runtime_value = runtime_record
                .wire_signature
                .get(field_name.as_str())
                .cloned()
                .unwrap_or(Value::Null);
            if runtime_value.is_null() {
                continue;
            }
            compared_fields.push(field_name.clone());
            if runtime_value != witness_value {
                mismatches.push(json!({
                    "field": field_name,
                    "runtime_value": runtime_value,
                    "witness_value": witness_value,
                }));
            }
        }
        let candidate = (
            mismatches.len(),
            usize::MAX - compared_fields.len(),
            compared_fields,
            mismatches,
            runtime_record,
        );
        if best
            .as_ref()
            .is_none_or(|best| (candidate.0, candidate.1) < (best.0, best.1))
        {
            best = Some(candidate);
        }
    }

    let (_, _, compared_fields, mismatches, runtime_record) =
        best.expect("matching_runtime_records is not empty");
    if compared_fields.is_empty() {
        return json!({
            "status": "insufficient_detail",
            "witness_target": witness_record.get("target").cloned().unwrap_or(Value::Null),
            "witness_port": witness_record.get("port").cloned().unwrap_or(Value::Null),
            "runtime_event_code": runtime_record.event_code,
            "runtime_slice": runtime_record.runtime_slice,
        });
    }
    if !mismatches.is_empty() {
        return json!({
            "status": "mismatched",
            "witness_target": witness_record.get("target").cloned().unwrap_or(Value::Null),
            "witness_port": witness_record.get("port").cloned().unwrap_or(Value::Null),
            "runtime_event_code": runtime_record.event_code,
            "runtime_slice": runtime_record.runtime_slice,
            "compared_fields": compared_fields,
            "field_mismatches": mismatches,
        });
    }
    json!({
        "status": "matched",
        "witness_target": witness_record.get("target").cloned().unwrap_or(Value::Null),
        "witness_port": witness_record.get("port").cloned().unwrap_or(Value::Null),
        "runtime_event_code": runtime_record.event_code,
        "runtime_slice": runtime_record.runtime_slice,
        "compared_fields": compared_fields,
    })
}

fn parse_helper_requirement_entry(entry: &str) -> Result<Value, Box<dyn std::error::Error>> {
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

fn ensure_requirement(
    payload: &Value,
    name: &str,
    status: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_helper_contract(
        payload["requirements"]
            .as_array()
            .map(|requirements| {
                requirements.iter().any(|item| {
                    item["name"].as_str() == Some(name) && item["status"].as_str() == Some(status)
                })
            })
            .unwrap_or(false),
        &format!("helper report requirement {name}={status}"),
    )
}

fn ensure_requirement_absent(
    payload: &Value,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_helper_contract(
        payload["requirements"]
            .as_array()
            .map(|requirements| {
                !requirements
                    .iter()
                    .any(|item| item["name"].as_str() == Some(name))
            })
            .unwrap_or(false),
        &format!("helper report unexpected requirement {name}"),
    )
}

fn assert_json_str(
    value: &Value,
    field: &str,
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_helper_contract(
        value[field].as_str() == Some(expected),
        &format!("{field} must equal {expected}"),
    )
}

fn assert_json_bool(
    value: &Value,
    field: &str,
    expected: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_helper_contract(
        value[field].as_bool() == Some(expected),
        &format!("{field} must equal {expected}"),
    )
}

fn assert_json_u64(
    value: &Value,
    field: &str,
    expected: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_helper_contract(
        value[field].as_u64() == Some(expected),
        &format!("{field} must equal {expected}"),
    )
}

fn assert_nested_json_u64(
    value: &Value,
    path: &[&str],
    expected: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let actual = path
        .iter()
        .try_fold(value, |current, key| current.get(*key))
        .and_then(Value::as_u64);
    ensure_helper_contract(
        actual == Some(expected),
        &format!("{} must equal {expected}", path.join(".")),
    )
}

fn require_capture(value: Option<&Value>) -> Result<&Value, Box<dyn std::error::Error>> {
    value.ok_or_else(|| "capture summary is required for this contract check".into())
}

fn assert_runtime_state_matrix(
    host_payload: &Value,
    capture_payload: Option<&Value>,
) -> Result<(), Box<dyn std::error::Error>> {
    let required = sorted_string_array(&host_payload["required_runtime_states"]);
    let observed = sorted_string_array(&host_payload["observed_runtime_states"]);
    ensure_helper_contract(
        required
            == [
                "requested_false",
                "requested_true_active",
                "requested_true_inactive",
            ],
        "required runtime states mismatch",
    )?;
    ensure_helper_contract(
        observed
            == [
                "requested_false",
                "requested_true_active",
                "requested_true_inactive",
            ],
        "observed runtime states mismatch",
    )?;
    let capture_payload = require_capture(capture_payload)?;
    for state in [
        "requested_false",
        "requested_true_inactive",
        "requested_true_active",
    ] {
        ensure_helper_contract(
            capture_payload["observed_state_matrix"][state]["observed"].as_bool() == Some(true),
            &format!("{state} must be observed"),
        )?;
    }
    assert_nested_json_u64(
        capture_payload,
        &[
            "activation_reason_counts",
            "linux_experimental_ttl_preface_active",
        ],
        1,
    )?;
    assert_nested_json_u64(
        capture_payload,
        &["activation_reason_counts", "config_disabled"],
        1,
    )?;
    assert_nested_json_u64(
        capture_payload,
        &["activation_reason_counts", "raw_capabilities_missing"],
        1,
    )?;
    assert_nested_json_u64(
        capture_payload,
        &[
            "runtime_slice_counts",
            "linux_experimental_ipv4_fragment_ordered_decoy_choreography_preface",
        ],
        1,
    )?;
    Ok(())
}

fn sorted_string_array(value: &Value) -> Vec<String> {
    let mut values = value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    values.sort();
    values
}

fn ensure_helper_contract(ok: bool, message: &str) -> Result<(), Box<dyn std::error::Error>> {
    if ok {
        Ok(())
    } else {
        Err(format!("mimicry wire host helper contract failed: {message}").into())
    }
}
