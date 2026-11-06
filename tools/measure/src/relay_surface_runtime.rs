use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde_json::{json, Value};

use crate::artifact::{write_json, write_text};

const RELAY_EVENT_CODES: &[&str] = &[
    "relay_session_started",
    "relay_transport_selected",
    "relay_session_succeeded",
    "relay_transport_failed",
];

const REQUIRED_SURFACE_FIELDS: &[&str] = &[
    "relay_surface_profile_id",
    "relay_surface_websocket_path",
    "relay_surface_grpc_path",
    "relay_surface_masque_path",
    "relay_surface_accept_language",
    "relay_surface_cache_control",
    "relay_surface_websocket_origin",
    "relay_surface_grpc_accept_encoding",
    "relay_surface_grpc_encoding",
    "relay_surface_grpc_timeout",
    "relay_surface_grpc_message_type",
    "relay_surface_masque_alt_used",
];

#[derive(Default)]
struct SurfaceSets {
    profile_ids: BTreeSet<String>,
    websocket_paths: BTreeSet<String>,
    grpc_paths: BTreeSet<String>,
    masque_paths: BTreeSet<String>,
    accept_languages: BTreeSet<String>,
    cache_controls: BTreeSet<String>,
    websocket_origins: BTreeSet<String>,
    grpc_accept_encodings: BTreeSet<String>,
    grpc_encodings: BTreeSet<String>,
    grpc_timeouts: BTreeSet<String>,
    grpc_message_types: BTreeSet<String>,
    masque_alt_used: BTreeSet<String>,
}

pub fn build_relay_surface_runtime_summary(
    output_dir: &Path,
    runtime_events_jsonl: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let records = read_runtime_events_lenient(runtime_events_jsonl)?;
    let mut relay_records = 0usize;
    let mut complete_records = 0usize;
    let mut missing_records = Vec::new();
    let mut event_codes_seen = BTreeSet::new();
    let mut surfaces = SurfaceSets::default();

    for record in records
        .iter()
        .filter(|record| is_relay_event(record["event_code"].as_str()))
    {
        relay_records += 1;
        let event_code = record["event_code"].as_str().unwrap_or("");
        event_codes_seen.insert(event_code.to_string());
        let fields = record.get("fields").and_then(Value::as_object);
        let missing = REQUIRED_SURFACE_FIELDS
            .iter()
            .filter(|field| fields.is_none_or(|fields| !fields.contains_key(**field)))
            .map(|field| json!(field))
            .collect::<Vec<_>>();

        let event_ref = json!({
            "event_code": record.get("event_code").cloned().unwrap_or(Value::Null),
            "relay_session_kind": field_value(fields, "relay_session_kind"),
            "transport": field_value(fields, "transport").or_else(|| field_value(fields, "chosen_transport")),
            "target": field_value(fields, "target"),
            "port": field_value(fields, "port"),
            "ts_unix_ms": record.get("ts_unix_ms").cloned().unwrap_or(Value::Null),
        });

        if !missing.is_empty() {
            let mut missing_event = event_ref
                .as_object()
                .cloned()
                .ok_or("relay surface event ref must be object")?;
            missing_event.insert("missing_surface_fields".to_string(), Value::Array(missing));
            missing_records.push(Value::Object(missing_event));
            continue;
        }

        complete_records += 1;
        remember(
            &mut surfaces.profile_ids,
            fields,
            "relay_surface_profile_id",
        );
        remember(
            &mut surfaces.websocket_paths,
            fields,
            "relay_surface_websocket_path",
        );
        remember(&mut surfaces.grpc_paths, fields, "relay_surface_grpc_path");
        remember(
            &mut surfaces.masque_paths,
            fields,
            "relay_surface_masque_path",
        );
        remember(
            &mut surfaces.accept_languages,
            fields,
            "relay_surface_accept_language",
        );
        remember(
            &mut surfaces.cache_controls,
            fields,
            "relay_surface_cache_control",
        );
        remember(
            &mut surfaces.websocket_origins,
            fields,
            "relay_surface_websocket_origin",
        );
        remember(
            &mut surfaces.grpc_accept_encodings,
            fields,
            "relay_surface_grpc_accept_encoding",
        );
        remember(
            &mut surfaces.grpc_encodings,
            fields,
            "relay_surface_grpc_encoding",
        );
        remember(
            &mut surfaces.grpc_timeouts,
            fields,
            "relay_surface_grpc_timeout",
        );
        remember(
            &mut surfaces.grpc_message_types,
            fields,
            "relay_surface_grpc_message_type",
        );
        remember(
            &mut surfaces.masque_alt_used,
            fields,
            "relay_surface_masque_alt_used",
        );
    }

    let started_observed = event_codes_seen.contains("relay_session_started");
    let selected_observed = event_codes_seen.contains("relay_transport_selected");
    let terminal_observed = event_codes_seen.contains("relay_session_succeeded")
        || event_codes_seen.contains("relay_transport_failed");
    let surface_complete = relay_records > 0 && complete_records == relay_records;

    let (verdict, status, next_action) = if relay_records == 0 {
        (
            "red",
            "no_relay_runtime_events",
            "collect_runtime_events_with_relay_activity",
        )
    } else if surface_complete && started_observed && selected_observed && terminal_observed {
        (
            "green",
            "runtime_surface_green",
            "use_runtime_surface_summary_in_live_hostile_path_validation",
        )
    } else if complete_records > 0 {
        (
            "yellow",
            "runtime_surface_partial_lifecycle",
            "collect_full_relay_lifecycle_runtime_events",
        )
    } else {
        (
            "yellow",
            "runtime_surface_fields_missing",
            "restore_relay_surface_fields_on_runtime_events",
        )
    };

    let payload = json!({
        "artifact_schema": "relay_surface_runtime_summary_v1",
        "verdict": verdict,
        "status": status,
        "runtime_events_jsonl": runtime_events_jsonl.display().to_string(),
        "relay_events_scanned": relay_records,
        "relay_events_with_complete_surface": complete_records,
        "relay_events_missing_surface": missing_records.len(),
        "required_surface_fields": REQUIRED_SURFACE_FIELDS,
        "checks": {
            "relay_session_started_observed": started_observed,
            "relay_transport_selected_observed": selected_observed,
            "terminal_relay_outcome_observed": terminal_observed,
            "surface_fields_complete_on_all_relay_events": surface_complete,
        },
        "relay_surface": {
            "profile_ids_seen": to_values(&surfaces.profile_ids),
            "websocket_paths_seen": to_values(&surfaces.websocket_paths),
            "grpc_paths_seen": to_values(&surfaces.grpc_paths),
            "masque_paths_seen": to_values(&surfaces.masque_paths),
            "accept_language_variants_seen": to_values(&surfaces.accept_languages),
            "cache_control_variants_seen": to_values(&surfaces.cache_controls),
            "websocket_origin_variants_seen": to_values(&surfaces.websocket_origins),
            "grpc_accept_encoding_variants_seen": to_values(&surfaces.grpc_accept_encodings),
            "grpc_encoding_variants_seen": to_values(&surfaces.grpc_encodings),
            "grpc_timeout_variants_seen": to_values(&surfaces.grpc_timeouts),
            "grpc_message_type_variants_seen": to_values(&surfaces.grpc_message_types),
            "masque_alt_used_variants_seen": to_values(&surfaces.masque_alt_used),
        },
        "missing_surface_events": missing_records,
        "next_action": next_action,
    });

    write_json(
        &output_dir.join("relay-surface-runtime-summary.json"),
        &payload,
    )?;
    write_text(
        &output_dir.join("relay-surface-runtime-summary.md"),
        &relay_surface_runtime_markdown(&payload),
    )?;
    Ok(())
}

fn is_relay_event(event_code: Option<&str>) -> bool {
    event_code.is_some_and(|event_code| RELAY_EVENT_CODES.contains(&event_code))
}

fn read_runtime_events_lenient(path: &Path) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    let mut records = Vec::new();
    for line in fs::read_to_string(path)?.lines().map(str::trim) {
        if line.is_empty() {
            continue;
        }
        if let Ok(record) = serde_json::from_str::<Value>(line) {
            records.push(record);
        }
    }
    Ok(records)
}

fn field_value(fields: Option<&serde_json::Map<String, Value>>, field: &str) -> Option<Value> {
    fields.and_then(|fields| fields.get(field)).cloned()
}

fn remember(
    values: &mut BTreeSet<String>,
    fields: Option<&serde_json::Map<String, Value>>,
    field: &str,
) {
    let value = fields
        .and_then(|fields| fields.get(field))
        .and_then(Value::as_str)
        .unwrap_or("<none>");
    values.insert(value.to_string());
}

fn to_values(values: &BTreeSet<String>) -> Vec<Value> {
    values.iter().map(|value| json!(value)).collect()
}

fn relay_surface_runtime_markdown(payload: &Value) -> String {
    let checks = &payload["checks"];
    let surface = &payload["relay_surface"];
    let mut lines = vec![
        "# Relay Surface Runtime Summary".to_string(),
        "".to_string(),
        format!("- Verdict: `{}`", s(&payload["verdict"])),
        format!("- Status: `{}`", s(&payload["status"])),
        format!(
            "- Runtime events JSONL: `{}`",
            s(&payload["runtime_events_jsonl"])
        ),
        format!(
            "- Relay events scanned: `{}`",
            s(&payload["relay_events_scanned"])
        ),
        format!(
            "- Relay events with complete surface: `{}`",
            s(&payload["relay_events_with_complete_surface"])
        ),
        format!("- Next action: `{}`", s(&payload["next_action"])),
        "".to_string(),
        "## Checks".to_string(),
        "".to_string(),
    ];
    for key in [
        "relay_session_started_observed",
        "relay_transport_selected_observed",
        "terminal_relay_outcome_observed",
        "surface_fields_complete_on_all_relay_events",
    ] {
        lines.push(format!("- `{key}`: `{}`", s(&checks[key])));
    }
    lines.extend([
        "".to_string(),
        "## Relay Surface".to_string(),
        "".to_string(),
        format!(
            "- Profile ids: `{}`",
            join_values(&surface["profile_ids_seen"])
        ),
        format!(
            "- WebSocket origins: `{}`",
            join_values(&surface["websocket_origin_variants_seen"])
        ),
        format!(
            "- gRPC timeouts: `{}`",
            join_values(&surface["grpc_timeout_variants_seen"])
        ),
        format!(
            "- gRPC message types: `{}`",
            join_values(&surface["grpc_message_type_variants_seen"])
        ),
        format!(
            "- MASQUE Alt-Used: `{}`",
            join_values(&surface["masque_alt_used_variants_seen"])
        ),
    ]);
    lines.join("\n") + "\n"
}

fn join_values(value: &Value) -> String {
    value
        .as_array()
        .map(|values| values.iter().map(s).collect::<Vec<_>>().join(", "))
        .unwrap_or_default()
}

fn s(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::Null => "null".to_string(),
        _ => value.to_string(),
    }
}
