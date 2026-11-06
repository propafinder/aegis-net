use serde_json::{json, Value};

pub(super) fn event_field<'a>(event: &'a Value, field: &str) -> Option<&'a Value> {
    event
        .get(field)
        .or_else(|| event.get("fields").and_then(|fields| fields.get(field)))
}

pub(super) fn event_field_value(event: &Value, field: &str) -> Value {
    event_field(event, field).cloned().unwrap_or(Value::Null)
}

pub(super) fn require_string_field(event: &Value, field: &str, violations: &mut Vec<Value>) {
    if event_field(event, field).and_then(Value::as_str).is_none() {
        push_missing_field_violation(event, field, violations);
    }
}

pub(super) fn require_u64_field(event: &Value, field: &str, violations: &mut Vec<Value>) {
    if event_field(event, field).and_then(Value::as_u64).is_none() {
        push_missing_field_violation(event, field, violations);
    }
}

pub(super) fn require_array_field(event: &Value, field: &str, violations: &mut Vec<Value>) {
    if event_field(event, field)
        .and_then(Value::as_array)
        .is_none_or(Vec::is_empty)
    {
        push_missing_field_violation(event, field, violations);
    }
}

pub(super) fn ensure(condition: bool, message: &str) -> Result<(), Box<dyn std::error::Error>> {
    if condition {
        Ok(())
    } else {
        Err(format!("contract assertion failed: {message}").into())
    }
}

pub(super) fn string_array(value: &Value) -> Vec<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

pub(super) fn string_array_opt(value: Option<&Value>) -> Vec<String> {
    value.map(string_array).unwrap_or_default()
}

pub(super) fn join_strings(value: &Value) -> String {
    let values = value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    if values.is_empty() {
        "none".to_string()
    } else {
        values.join(", ")
    }
}

pub(super) fn compact_named_statuses(value: &Value) -> String {
    let values = value
        .as_array()
        .into_iter()
        .flatten()
        .map(|entry| {
            format!(
                "{}={}",
                entry["name"].as_str().unwrap_or("unknown"),
                entry["status"].as_str().unwrap_or("UNKNOWN"),
            )
        })
        .collect::<Vec<_>>();
    if values.is_empty() {
        "none".to_string()
    } else {
        values.join(", ")
    }
}

fn push_missing_field_violation(event: &Value, field: &str, violations: &mut Vec<Value>) {
    violations.push(json!({
        "reason": "missing-required-field",
        "event_code": event["event_code"].clone(),
        "field": field,
    }));
}
