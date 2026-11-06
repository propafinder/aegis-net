use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::artifact::{read_json, write_json, write_text};

const MANIFEST_SCHEMA: &str = "linux_wide_mimicry_live_audit_manifest_v1";
const HANDOFF_SCHEMA: &str = "linux_wide_live_audit_operator_handoff_v1";
const SUPPORTED_PRODUCT_CONTOUR: &str = "linux_wide_mimicry_live_audit";
const SUPPORTED_OPERATOR_SCOPE: &str = "post_run_handoff_triage";
const PRODUCER: &str = "aegis-measure build-linux-wide-live-audit-manifest";

#[cfg(test)]
#[path = "linux_live_audit_manifest_command_tests.rs"]
mod command_tests;

const EXPECTED_TOPOLOGY_SCHEMA: &str = "aegis_linux_live_expected_topology_v1";
const MAX_EXPECTED_TOPOLOGY_BYTES: u64 = 4096;

/// Independently configured reference, loaded before processing reported artifacts.
/// The private fields prevent callers from using a reported payload as an implicit
/// expectation. This configuration does not establish server/key trust provenance.
pub struct LinuxLiveExpectedTopology {
    server_host: String,
    client_host: String,
    relay_address: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedTopologyFile {
    schema: String,
    server_host: String,
    client_host: String,
    relay_address: String,
}

pub fn load_linux_live_expected_topology(
    path: &Path,
) -> Result<LinuxLiveExpectedTopology, Box<dyn std::error::Error>> {
    // Existing descriptor reader refuses symlinks/reparse points and uses
    // O_NONBLOCK on Unix before checking regular-file/private config metadata.
    // Its original bound applies to metadata and the completed descriptor read.
    let bytes = aegis_core::secret_file::read_config(path, MAX_EXPECTED_TOPOLOGY_BYTES)
        .map_err(|_| "expected topology unreadable, private or bounded file required")?;
    let input: ExpectedTopologyFile =
        serde_json::from_slice(&bytes).map_err(|_| "expected topology invalid JSON or fields")?;
    ensure(
        input.schema == EXPECTED_TOPOLOGY_SCHEMA,
        "expected topology unsupported schema",
    )?;
    for (value, limit) in [
        (&input.server_host, 255),
        (&input.client_host, 255),
        (&input.relay_address, 512),
    ] {
        ensure(
            !value.is_empty()
                && value.len() <= limit
                && !value.chars().any(|c| c.is_whitespace() || c.is_control()),
            "expected topology invalid identity",
        )?;
    }
    Ok(LinuxLiveExpectedTopology {
        server_host: input.server_host,
        client_host: input.client_host,
        relay_address: input.relay_address,
    })
}

fn check_expected_topology_fields(
    fields: &Value,
    expected: &LinuxLiveExpectedTopology,
) -> Result<(), Box<dyn std::error::Error>> {
    for (field, identity) in [
        ("server_host", expected.server_host.as_str()),
        ("client_host", expected.client_host.as_str()),
        ("relay_address", expected.relay_address.as_str()),
    ] {
        ensure(
            fields[field].as_str() == Some(identity),
            &format!("expected topology mismatch: {field}"),
        )?;
    }
    Ok(())
}

fn check_expected_status_topology(
    payload: &Value,
    expected: &LinuxLiveExpectedTopology,
) -> Result<(), Box<dyn std::error::Error>> {
    check_expected_topology_fields(&payload["operator_scope"], expected)?;
    check_expected_topology_fields(payload, expected)
}

fn check_expected_manifest_topology(
    payload: &Value,
    expected: &LinuxLiveExpectedTopology,
) -> Result<(), Box<dyn std::error::Error>> {
    check_expected_topology_fields(&payload["operator_handoff"]["operator_scope"], expected)?;
    check_expected_topology_fields(payload, expected)
}

pub struct LinuxLiveAuditManifestInputs {
    pub manifest: PathBuf,
    pub output_dir: String,
    pub server_host: String,
    pub client_host: String,
    pub relay_address: String,
    pub runtime_events: String,
    pub preflight: String,
    pub startup_probe: String,
    pub wire_helper_stdout: String,
    pub witness_summary: String,
    pub witness_pcap: String,
    pub transient_runtime_events: String,
    pub wire_helper_runtime_events: String,
    pub wire_acceptance_summary: PathBuf,
    pub stealth_live_acceptance_bundle: PathBuf,
    pub stealth_live_acceptance_manifest: String,
    pub rerun_command: String,
    pub review_summary_command: String,
    pub review_manifest_command: String,
    pub handoff_status_json: String,
}

pub fn build_linux_wide_live_audit_manifest(
    inputs: LinuxLiveAuditManifestInputs,
) -> Result<(), Box<dyn std::error::Error>> {
    let summary_md = inputs.manifest.with_file_name("live-audit-summary.md");
    let handoff_status_json = if inputs.handoff_status_json.is_empty() {
        inputs
            .manifest
            .with_file_name("live-audit-handoff-status.json")
            .display()
            .to_string()
    } else {
        inputs.handoff_status_json.clone()
    };

    let wire_acceptance_summary = read_json(&inputs.wire_acceptance_summary)?;
    let stealth_bundle = read_json(&inputs.stealth_live_acceptance_bundle)?;

    let review_wire_acceptance_command =
        review_json_command(&inputs.wire_acceptance_summary.display().to_string());
    let review_stealth_bundle_command =
        review_json_command(&inputs.stealth_live_acceptance_bundle.display().to_string());
    let review_runtime_events_command =
        format_command(&["sed", "-n", "1,160p", &inputs.runtime_events]);
    let review_handoff_status_command = review_json_command(&handoff_status_json);
    let review_wire_helper_stdout_command = review_json_command(&inputs.wire_helper_stdout);
    let review_preflight_command = review_json_command(&inputs.preflight);
    let review_startup_probe_command = review_json_command(&inputs.startup_probe);
    let review_transient_runtime_events_command =
        format_command(&["sed", "-n", "1,160p", &inputs.transient_runtime_events]);
    let review_wire_helper_runtime_events_command =
        format_command(&["sed", "-n", "1,160p", &inputs.wire_helper_runtime_events]);
    let review_stealth_manifest_command =
        review_json_command(&inputs.stealth_live_acceptance_manifest);
    let review_witness_summary_command = if inputs.witness_summary.is_empty() {
        Value::Null
    } else {
        json!(review_json_command(&inputs.witness_summary))
    };

    let review_targets = json!({
        "summary_md": summary_md.display().to_string(),
        "manifest_json": inputs.manifest.display().to_string(),
        "handoff_status_json": handoff_status_json,
        "client_preflight_json": inputs.preflight,
        "client_startup_probe_json": inputs.startup_probe,
        "wire_helper_stdout_json": inputs.wire_helper_stdout,
        "wire_acceptance_summary_json": inputs.wire_acceptance_summary.display().to_string(),
        "wire_witness_summary_json": none_if_empty(&inputs.witness_summary),
        "wire_witness_capture_pcapng": none_if_empty(&inputs.witness_pcap),
        "stealth_live_acceptance_bundle_json": inputs.stealth_live_acceptance_bundle.display().to_string(),
        "stealth_live_acceptance_manifest_json": inputs.stealth_live_acceptance_manifest,
        "runtime_events_jsonl": inputs.runtime_events,
        "client_transient_relay_wire_runtime_events_jsonl": inputs.transient_runtime_events,
        "wire_helper_runtime_events_jsonl": inputs.wire_helper_runtime_events,
    });

    let wire_green = lower_str(&wire_acceptance_summary, "product_verdict") == "green"
        && matches!(
            lower_str(&wire_acceptance_summary, "acceptance_status").as_str(),
            "passed" | "green" | "ready"
        );
    let stealth_green = lower_str(&stealth_bundle, "bundle_verdict") == "green";
    let primary_blocker = stealth_bundle
        .get("primary_blocker")
        .cloned()
        .unwrap_or(Value::Null);

    let acceptance_overview = if !stealth_green {
        json!({
            "overall_status": stealth_bundle.get("bundle_status").cloned().unwrap_or(Value::Null),
            "overall_next_action": stealth_bundle.get("next_action").cloned().unwrap_or(Value::Null),
            "primary_layer": "stealth",
            "wire_layer_verdict": wire_acceptance_summary.get("product_verdict").cloned().unwrap_or(Value::Null),
            "wire_layer_status": wire_acceptance_summary.get("acceptance_status").cloned().unwrap_or(Value::Null),
            "stealth_layer_verdict": stealth_bundle.get("bundle_verdict").cloned().unwrap_or(Value::Null),
            "stealth_layer_status": stealth_bundle.get("bundle_status").cloned().unwrap_or(Value::Null),
        })
    } else if !wire_green {
        json!({
            "overall_status": "blocked_on_wire_host_acceptance",
            "overall_next_action": "inspect_wire_host_acceptance_summary",
            "primary_layer": "wire",
            "wire_layer_verdict": wire_acceptance_summary.get("product_verdict").cloned().unwrap_or(Value::Null),
            "wire_layer_status": wire_acceptance_summary.get("acceptance_status").cloned().unwrap_or(Value::Null),
            "stealth_layer_verdict": stealth_bundle.get("bundle_verdict").cloned().unwrap_or(Value::Null),
            "stealth_layer_status": stealth_bundle.get("bundle_status").cloned().unwrap_or(Value::Null),
        })
    } else {
        json!({
            "overall_status": "acceptance_green",
            "overall_next_action": stealth_bundle.get("next_action").cloned().unwrap_or(json!("collect_next_live_validation_slice")),
            "primary_layer": "none",
            "wire_layer_verdict": wire_acceptance_summary.get("product_verdict").cloned().unwrap_or(Value::Null),
            "wire_layer_status": wire_acceptance_summary.get("acceptance_status").cloned().unwrap_or(Value::Null),
            "stealth_layer_verdict": stealth_bundle.get("bundle_verdict").cloned().unwrap_or(Value::Null),
            "stealth_layer_status": stealth_bundle.get("bundle_status").cloned().unwrap_or(Value::Null),
        })
    };

    let (next_action_id, next_action_reason, next_action_command, next_action_artifact) =
        match acceptance_overview["primary_layer"]
            .as_str()
            .unwrap_or("none")
        {
            "stealth" => {
                let blocker_id = primary_blocker
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("inspect_stealth_live_acceptance_bundle")
                    .to_string();
                (
                    blocker_id,
                    str_or(
                        &acceptance_overview,
                        "overall_next_action",
                        "inspect_stealth_bundle",
                    ),
                    review_stealth_bundle_command.clone(),
                    review_targets["stealth_live_acceptance_bundle_json"]
                        .as_str()
                        .unwrap_or("")
                        .to_string(),
                )
            }
            "wire" => (
                "inspect_wire_host_acceptance_summary".to_string(),
                str_or(
                    &acceptance_overview,
                    "overall_next_action",
                    "inspect_wire_acceptance",
                ),
                review_wire_acceptance_command.clone(),
                review_targets["wire_acceptance_summary_json"]
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
            ),
            _ => (
                "collect_next_live_validation_slice".to_string(),
                str_or(
                    &acceptance_overview,
                    "overall_next_action",
                    "collect_next_live_validation_slice",
                ),
                inputs.rerun_command.clone(),
                review_targets["summary_md"]
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
            ),
        };

    let next_action = json!({
        "id": next_action_id,
        "layer": acceptance_overview["primary_layer"].clone(),
        "reason": next_action_reason,
        "command": next_action_command,
        "artifact": next_action_artifact,
    });
    let next_action_context = json!({
        "overall_status": acceptance_overview["overall_status"].clone(),
        "overall_next_action": acceptance_overview["overall_next_action"].clone(),
        "primary_layer": acceptance_overview["primary_layer"].clone(),
        "wire_verdict": wire_acceptance_summary.get("product_verdict").cloned().unwrap_or(Value::Null),
        "wire_status": wire_acceptance_summary.get("acceptance_status").cloned().unwrap_or(Value::Null),
        "wire_witness_correlation_status": wire_acceptance_summary.get("independent_witness_correlation_status").cloned().unwrap_or(Value::Null),
        "stealth_verdict": stealth_bundle.get("bundle_verdict").cloned().unwrap_or(Value::Null),
        "stealth_status": stealth_bundle.get("bundle_status").cloned().unwrap_or(Value::Null),
        "primary_blocker_id": primary_blocker.get("id").and_then(Value::as_str),
    });
    let layer_status = json!({
        "wire": {
            "product_verdict": wire_acceptance_summary.get("product_verdict").cloned().unwrap_or(Value::Null),
            "acceptance_status": wire_acceptance_summary.get("acceptance_status").cloned().unwrap_or(Value::Null),
            "hostile_path_support_ready": wire_acceptance_summary.get("hostile_path_support_ready").cloned().unwrap_or(Value::Null),
            "independent_witness_correlation_status": wire_acceptance_summary.get("independent_witness_correlation_status").cloned().unwrap_or(Value::Null),
        },
        "stealth": {
            "bundle_verdict": stealth_bundle.get("bundle_verdict").cloned().unwrap_or(Value::Null),
            "bundle_status": stealth_bundle.get("bundle_status").cloned().unwrap_or(Value::Null),
            "primary_blocker": primary_blocker,
            "active_blockers": stealth_bundle.get("active_blockers").cloned().unwrap_or(Value::Null),
            "bundle_next_action": stealth_bundle.get("next_action").cloned().unwrap_or(Value::Null),
        },
    });
    let operator_scope = json!({
        "output_dir": inputs.output_dir,
        "server_host": inputs.server_host,
        "client_host": inputs.client_host,
        "relay_address": inputs.relay_address,
    });
    let handoff_commands = json!({
        "rerun_command": inputs.rerun_command,
        "review_summary_command": inputs.review_summary_command,
        "review_manifest_command": inputs.review_manifest_command,
        "review_handoff_status_command": review_handoff_status_command,
        "review_preflight_command": review_preflight_command,
        "review_startup_probe_command": review_startup_probe_command,
        "review_wire_helper_stdout_command": review_wire_helper_stdout_command,
        "review_witness_summary_command": review_witness_summary_command,
        "review_wire_acceptance_command": review_wire_acceptance_command,
        "review_stealth_bundle_command": review_stealth_bundle_command,
        "review_stealth_manifest_command": review_stealth_manifest_command,
        "review_runtime_events_command": review_runtime_events_command,
        "review_transient_runtime_events_command": review_transient_runtime_events_command,
        "review_wire_helper_runtime_events_command": review_wire_helper_runtime_events_command,
    });
    let operator_handoff = json!({
        "handoff_schema": HANDOFF_SCHEMA,
        "producer": PRODUCER,
        "source_manifest_schema": MANIFEST_SCHEMA,
        "supported_product_contour": SUPPORTED_PRODUCT_CONTOUR,
        "supported_operator_scope": SUPPORTED_OPERATOR_SCOPE,
        "summary_md": review_targets["summary_md"].clone(),
        "manifest_json": review_targets["manifest_json"].clone(),
        "handoff_status_json": handoff_status_json,
        "acceptance_overview": acceptance_overview,
        "operator_scope": operator_scope,
        "layer_status": layer_status,
        "review_targets": review_targets,
        "handoff_commands": handoff_commands,
        "next_action": next_action,
        "next_action_context": next_action_context,
    });

    let payload = json!({
        "artifact_schema": MANIFEST_SCHEMA,
        "output_dir": operator_handoff["operator_scope"]["output_dir"].clone(),
        "server_host": operator_handoff["operator_scope"]["server_host"].clone(),
        "client_host": operator_handoff["operator_scope"]["client_host"].clone(),
        "relay_address": operator_handoff["operator_scope"]["relay_address"].clone(),
        "client_runtime_events_jsonl": operator_handoff["review_targets"]["runtime_events_jsonl"].clone(),
        "client_transient_relay_wire_runtime_events_jsonl": operator_handoff["review_targets"]["client_transient_relay_wire_runtime_events_jsonl"].clone(),
        "wire_helper_runtime_events_jsonl": operator_handoff["review_targets"]["wire_helper_runtime_events_jsonl"].clone(),
        "client_preflight_json": operator_handoff["review_targets"]["client_preflight_json"].clone(),
        "client_startup_probe_json": operator_handoff["review_targets"]["client_startup_probe_json"].clone(),
        "wire_host_helper_stdout_json": operator_handoff["review_targets"]["wire_helper_stdout_json"].clone(),
        "wire_host_acceptance_summary_json": operator_handoff["review_targets"]["wire_acceptance_summary_json"].clone(),
        "wire_host_acceptance_product_verdict": wire_acceptance_summary.get("product_verdict").cloned().unwrap_or(Value::Null),
        "wire_host_acceptance_status": wire_acceptance_summary.get("acceptance_status").cloned().unwrap_or(Value::Null),
        "wire_host_acceptance_hostile_path_ready": wire_acceptance_summary.get("hostile_path_support_ready").cloned().unwrap_or(Value::Null),
        "wire_host_acceptance_witness_correlation_status": wire_acceptance_summary.get("independent_witness_correlation_status").cloned().unwrap_or(Value::Null),
        "wire_witness_summary_json": operator_handoff["review_targets"]["wire_witness_summary_json"].clone(),
        "wire_witness_capture_pcapng": operator_handoff["review_targets"]["wire_witness_capture_pcapng"].clone(),
        "stealth_live_acceptance_bundle_json": operator_handoff["review_targets"]["stealth_live_acceptance_bundle_json"].clone(),
        "stealth_live_acceptance_manifest_json": operator_handoff["review_targets"]["stealth_live_acceptance_manifest_json"].clone(),
        "stealth_live_acceptance_bundle_verdict": stealth_bundle.get("bundle_verdict").cloned().unwrap_or(Value::Null),
        "stealth_live_acceptance_bundle_status": stealth_bundle.get("bundle_status").cloned().unwrap_or(Value::Null),
        "stealth_live_acceptance_primary_blocker": stealth_bundle.get("primary_blocker").cloned().unwrap_or(Value::Null),
        "stealth_live_acceptance_active_blockers": stealth_bundle.get("active_blockers").cloned().unwrap_or(Value::Null),
        "acceptance_overview": operator_handoff["acceptance_overview"].clone(),
        "live_audit_summary_md": operator_handoff["summary_md"].clone(),
        "live_audit_handoff_status_json": operator_handoff["handoff_status_json"].clone(),
        "operator_handoff": operator_handoff,
        "review_targets": operator_handoff["review_targets"].clone(),
        "next_action": operator_handoff["next_action"].clone(),
        "next_action_context": operator_handoff["next_action_context"].clone(),
        "handoff_commands": {
            "next_action_command": operator_handoff["next_action"]["command"].clone(),
            "rerun_command": operator_handoff["handoff_commands"]["rerun_command"].clone(),
            "review_summary_command": operator_handoff["handoff_commands"]["review_summary_command"].clone(),
            "review_manifest_command": operator_handoff["handoff_commands"]["review_manifest_command"].clone(),
            "review_handoff_status_command": operator_handoff["handoff_commands"]["review_handoff_status_command"].clone(),
            "review_preflight_command": operator_handoff["handoff_commands"]["review_preflight_command"].clone(),
            "review_startup_probe_command": operator_handoff["handoff_commands"]["review_startup_probe_command"].clone(),
            "review_wire_helper_stdout_command": operator_handoff["handoff_commands"]["review_wire_helper_stdout_command"].clone(),
            "review_witness_summary_command": operator_handoff["handoff_commands"]["review_witness_summary_command"].clone(),
            "review_wire_acceptance_command": operator_handoff["handoff_commands"]["review_wire_acceptance_command"].clone(),
            "review_stealth_bundle_command": operator_handoff["handoff_commands"]["review_stealth_bundle_command"].clone(),
            "review_stealth_manifest_command": operator_handoff["handoff_commands"]["review_stealth_manifest_command"].clone(),
            "review_runtime_events_command": operator_handoff["handoff_commands"]["review_runtime_events_command"].clone(),
            "review_transient_runtime_events_command": operator_handoff["handoff_commands"]["review_transient_runtime_events_command"].clone(),
            "review_wire_helper_runtime_events_command": operator_handoff["handoff_commands"]["review_wire_helper_runtime_events_command"].clone(),
        },
        "next_action_artifact": operator_handoff["next_action"]["artifact"].clone(),
    });

    write_json(&inputs.manifest, &payload)?;
    write_text(&summary_md, &summary_markdown(&payload))?;
    Ok(())
}

pub fn linux_wide_live_audit_manifest_contract_check(
    manifest_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = read_json(manifest_path)?;
    check_manifest_contract(&payload)?;
    check_summary_contract(&payload)?;
    Ok(())
}

pub fn build_linux_wide_live_audit_handoff_status(
    manifest_path: &Path,
    output_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = read_json(manifest_path)?;
    write_json(output_path, &handoff_status_from_manifest(&manifest)?)
}

fn handoff_status_from_manifest(manifest: &Value) -> Result<Value, Box<dyn std::error::Error>> {
    let handoff = manifest
        .get("operator_handoff")
        .and_then(Value::as_object)
        .ok_or("live-audit manifest is missing canonical operator_handoff object")?;

    let handoff_schema = require_field(handoff, "operator_handoff", "handoff_schema")?;
    let handoff_producer = require_field(handoff, "operator_handoff", "producer")?;
    let source_manifest_schema =
        require_field(handoff, "operator_handoff", "source_manifest_schema")?;
    let supported_product_contour =
        require_field(handoff, "operator_handoff", "supported_product_contour")?;
    let supported_operator_scope =
        require_field(handoff, "operator_handoff", "supported_operator_scope")?;
    let summary_md = require_field(handoff, "operator_handoff", "summary_md")?;
    let manifest_json = require_field(handoff, "operator_handoff", "manifest_json")?;
    let handoff_status_json = require_field(handoff, "operator_handoff", "handoff_status_json")?;
    let acceptance_overview = require_mapping(handoff, "operator_handoff", "acceptance_overview")?;
    let layer_status = require_mapping(handoff, "operator_handoff", "layer_status")?;
    let operator_scope = require_mapping(handoff, "operator_handoff", "operator_scope")?;
    let next_action = require_mapping(handoff, "operator_handoff", "next_action")?;
    let next_action_context = require_mapping(handoff, "operator_handoff", "next_action_context")?;
    let handoff_commands = require_mapping(handoff, "operator_handoff", "handoff_commands")?;
    let review_targets = require_mapping(handoff, "operator_handoff", "review_targets")?;

    for field in ["output_dir", "server_host", "client_host", "relay_address"] {
        require_field(operator_scope, "operator_handoff.operator_scope", field)?;
    }

    let wire_layer = require_mapping(layer_status, "operator_handoff.layer_status", "wire")?;
    let stealth_layer = require_mapping(layer_status, "operator_handoff.layer_status", "stealth")?;
    for field in ["product_verdict", "acceptance_status"] {
        require_field(wire_layer, "operator_handoff.layer_status.wire", field)?;
    }
    for field in ["bundle_verdict", "bundle_status"] {
        require_field(
            stealth_layer,
            "operator_handoff.layer_status.stealth",
            field,
        )?;
    }

    for field in ["id", "layer", "reason", "command", "artifact"] {
        require_field(next_action, "operator_handoff.next_action", field)?;
    }
    for field in ["overall_status", "primary_layer"] {
        require_field(
            next_action_context,
            "operator_handoff.next_action_context",
            field,
        )?;
    }
    for field in [
        "rerun_command",
        "review_summary_command",
        "review_manifest_command",
        "review_handoff_status_command",
        "review_preflight_command",
        "review_startup_probe_command",
        "review_wire_helper_stdout_command",
        "review_wire_acceptance_command",
        "review_stealth_bundle_command",
        "review_stealth_manifest_command",
        "review_runtime_events_command",
        "review_transient_runtime_events_command",
        "review_wire_helper_runtime_events_command",
    ] {
        require_field(handoff_commands, "operator_handoff.handoff_commands", field)?;
    }
    for field in [
        "handoff_status_json",
        "client_preflight_json",
        "client_startup_probe_json",
        "wire_helper_stdout_json",
        "wire_acceptance_summary_json",
        "stealth_live_acceptance_bundle_json",
        "stealth_live_acceptance_manifest_json",
        "runtime_events_jsonl",
        "summary_md",
        "manifest_json",
        "client_transient_relay_wire_runtime_events_jsonl",
        "wire_helper_runtime_events_jsonl",
    ] {
        require_field(review_targets, "operator_handoff.review_targets", field)?;
    }

    ensure(
        summary_md == &review_targets["summary_md"],
        "operator_handoff.summary_md does not match review_targets.summary_md",
    )?;
    ensure(
        manifest_json == &review_targets["manifest_json"],
        "operator_handoff.manifest_json does not match review_targets.manifest_json",
    )?;
    ensure(
        handoff_status_json == &review_targets["handoff_status_json"],
        "operator_handoff.handoff_status_json does not match review_targets.handoff_status_json",
    )?;
    ensure(
        next_action["layer"] == next_action_context["primary_layer"],
        "operator_handoff next_action.layer does not match next_action_context.primary_layer",
    )?;
    ensure(
        next_action["layer"] == acceptance_overview["primary_layer"],
        "operator_handoff next_action.layer does not match acceptance_overview.primary_layer",
    )?;
    ensure(
        next_action_context["overall_status"] == acceptance_overview["overall_status"],
        "operator_handoff next_action_context.overall_status does not match acceptance_overview.overall_status",
    )?;
    ensure(
        next_action_context["overall_next_action"] == acceptance_overview["overall_next_action"],
        "operator_handoff next_action_context.overall_next_action does not match acceptance_overview.overall_next_action",
    )?;
    ensure(
        wire_layer["product_verdict"] == acceptance_overview["wire_layer_verdict"],
        "operator_handoff.layer_status.wire.product_verdict does not match acceptance_overview.wire_layer_verdict",
    )?;
    ensure(
        stealth_layer["bundle_status"] == acceptance_overview["stealth_layer_status"],
        "operator_handoff.layer_status.stealth.bundle_status does not match acceptance_overview.stealth_layer_status",
    )?;

    for (command_field, target_field) in [
        ("review_summary_command", "summary_md"),
        ("review_manifest_command", "manifest_json"),
        ("review_handoff_status_command", "handoff_status_json"),
        ("review_preflight_command", "client_preflight_json"),
        ("review_startup_probe_command", "client_startup_probe_json"),
        (
            "review_wire_helper_stdout_command",
            "wire_helper_stdout_json",
        ),
        (
            "review_wire_acceptance_command",
            "wire_acceptance_summary_json",
        ),
        (
            "review_stealth_bundle_command",
            "stealth_live_acceptance_bundle_json",
        ),
        (
            "review_stealth_manifest_command",
            "stealth_live_acceptance_manifest_json",
        ),
        ("review_runtime_events_command", "runtime_events_jsonl"),
        (
            "review_transient_runtime_events_command",
            "client_transient_relay_wire_runtime_events_jsonl",
        ),
        (
            "review_wire_helper_runtime_events_command",
            "wire_helper_runtime_events_jsonl",
        ),
    ] {
        require_command_targets_path(
            s(&handoff_commands[command_field]).as_str(),
            s(&review_targets[target_field]).as_str(),
            &format!("operator_handoff.handoff_commands.{command_field}"),
            &format!("operator_handoff.review_targets.{target_field}"),
        )?;
    }

    let witness_summary_target = &review_targets["wire_witness_summary_json"];
    let witness_summary_command = &handoff_commands["review_witness_summary_command"];
    if witness_summary_target.is_null() {
        ensure(
            witness_summary_command.is_null(),
            "operator_handoff.handoff_commands.review_witness_summary_command must be null when review_targets.wire_witness_summary_json is null",
        )?;
    } else {
        ensure(
            !witness_summary_command.is_null(),
            "operator_handoff.handoff_commands.review_witness_summary_command missing for review_targets.wire_witness_summary_json",
        )?;
        require_command_targets_path(
            s(witness_summary_command).as_str(),
            s(witness_summary_target).as_str(),
            "operator_handoff.handoff_commands.review_witness_summary_command",
            "operator_handoff.review_targets.wire_witness_summary_json",
        )?;
    }

    let next_action_layer = next_action["layer"].as_str().unwrap_or("");
    if !acceptance_overview["overall_next_action"].is_null() {
        ensure(
            next_action["reason"] == acceptance_overview["overall_next_action"],
            "operator_handoff.next_action.reason does not match acceptance_overview.overall_next_action",
        )?;
    }
    match next_action_layer {
        "stealth" => {
            ensure(
                next_action["artifact"] == review_targets["stealth_live_acceptance_bundle_json"],
                "operator_handoff.next_action.artifact does not match review_targets.stealth_live_acceptance_bundle_json",
            )?;
            ensure(
                next_action["command"] == handoff_commands["review_stealth_bundle_command"],
                "operator_handoff.next_action.command does not match handoff_commands.review_stealth_bundle_command",
            )?;
            let expected = next_action_context["primary_blocker_id"]
                .as_str()
                .filter(|value| !value.is_empty())
                .unwrap_or("inspect_stealth_live_acceptance_bundle");
            ensure(
                next_action["id"].as_str() == Some(expected),
                "operator_handoff.next_action.id does not match stealth-layer blocker semantics",
            )?;
        }
        "wire" => {
            ensure(
                next_action["artifact"] == review_targets["wire_acceptance_summary_json"],
                "operator_handoff.next_action.artifact does not match review_targets.wire_acceptance_summary_json",
            )?;
            ensure(
                next_action["command"] == handoff_commands["review_wire_acceptance_command"],
                "operator_handoff.next_action.command does not match handoff_commands.review_wire_acceptance_command",
            )?;
            ensure(
                next_action["id"].as_str() == Some("inspect_wire_host_acceptance_summary"),
                "operator_handoff.next_action.id does not match wire-layer handoff semantics",
            )?;
        }
        "none" => {
            ensure(
                next_action["artifact"] == review_targets["summary_md"],
                "operator_handoff.next_action.artifact does not match review_targets.summary_md",
            )?;
            ensure(
                next_action["command"] == handoff_commands["rerun_command"],
                "operator_handoff.next_action.command does not match handoff_commands.rerun_command",
            )?;
            ensure(
                next_action["id"].as_str() == Some("collect_next_live_validation_slice"),
                "operator_handoff.next_action.id does not match green-layer handoff semantics",
            )?;
        }
        _ => {}
    }

    let handoff_status = match next_action_layer {
        "stealth" => "blocked_on_stealth",
        "wire" => "blocked_on_wire",
        "none" => "ready_for_next_live_validation",
        _ => "handoff_needs_manual_review",
    };

    let payload = json!({
        "artifact_schema": "linux_wide_live_audit_handoff_status_v1",
        "operator_handoff_schema": handoff_schema,
        "operator_handoff_producer": handoff_producer,
        "source_manifest_schema": source_manifest_schema,
        "supported_product_contour": supported_product_contour,
        "supported_operator_scope": supported_operator_scope,
        "consumer_source": "operator_handoff",
        "live_audit_manifest_json": manifest_json,
        "live_audit_summary_md": summary_md,
        "operator_handoff_status_json": handoff_status_json,
        "operator_scope": operator_scope,
        "output_dir": operator_scope.get("output_dir").cloned().unwrap_or(Value::Null),
        "server_host": operator_scope.get("server_host").cloned().unwrap_or(Value::Null),
        "client_host": operator_scope.get("client_host").cloned().unwrap_or(Value::Null),
        "relay_address": operator_scope.get("relay_address").cloned().unwrap_or(Value::Null),
        "acceptance_overview": acceptance_overview,
        "layer_status": layer_status,
        "handoff_status": handoff_status,
        "next_required_action": next_action.get("id").cloned().unwrap_or(Value::Null),
        "next_action": next_action,
        "next_action_context": next_action_context,
        "rerun_command": handoff_commands.get("rerun_command").cloned().unwrap_or(Value::Null),
        "review_summary_command": handoff_commands.get("review_summary_command").cloned().unwrap_or(Value::Null),
        "review_manifest_command": handoff_commands.get("review_manifest_command").cloned().unwrap_or(Value::Null),
        "review_handoff_status_command": handoff_commands.get("review_handoff_status_command").cloned().unwrap_or(Value::Null),
        "review_preflight_command": handoff_commands.get("review_preflight_command").cloned().unwrap_or(Value::Null),
        "review_startup_probe_command": handoff_commands.get("review_startup_probe_command").cloned().unwrap_or(Value::Null),
        "review_wire_helper_stdout_command": handoff_commands.get("review_wire_helper_stdout_command").cloned().unwrap_or(Value::Null),
        "review_witness_summary_command": handoff_commands.get("review_witness_summary_command").cloned().unwrap_or(Value::Null),
        "review_wire_acceptance_command": handoff_commands.get("review_wire_acceptance_command").cloned().unwrap_or(Value::Null),
        "review_stealth_bundle_command": handoff_commands.get("review_stealth_bundle_command").cloned().unwrap_or(Value::Null),
        "review_stealth_manifest_command": handoff_commands.get("review_stealth_manifest_command").cloned().unwrap_or(Value::Null),
        "review_runtime_events_command": handoff_commands.get("review_runtime_events_command").cloned().unwrap_or(Value::Null),
        "review_transient_runtime_events_command": handoff_commands.get("review_transient_runtime_events_command").cloned().unwrap_or(Value::Null),
        "review_wire_helper_runtime_events_command": handoff_commands.get("review_wire_helper_runtime_events_command").cloned().unwrap_or(Value::Null),
        "handoff_status_json": review_targets.get("handoff_status_json").cloned().unwrap_or(Value::Null),
        "client_preflight_json": review_targets.get("client_preflight_json").cloned().unwrap_or(Value::Null),
        "client_startup_probe_json": review_targets.get("client_startup_probe_json").cloned().unwrap_or(Value::Null),
        "wire_helper_stdout_json": review_targets.get("wire_helper_stdout_json").cloned().unwrap_or(Value::Null),
        "wire_acceptance_summary_json": review_targets.get("wire_acceptance_summary_json").cloned().unwrap_or(Value::Null),
        "wire_witness_summary_json": review_targets.get("wire_witness_summary_json").cloned().unwrap_or(Value::Null),
        "wire_witness_capture_pcapng": review_targets.get("wire_witness_capture_pcapng").cloned().unwrap_or(Value::Null),
        "stealth_live_acceptance_bundle_json": review_targets.get("stealth_live_acceptance_bundle_json").cloned().unwrap_or(Value::Null),
        "stealth_live_acceptance_manifest_json": review_targets.get("stealth_live_acceptance_manifest_json").cloned().unwrap_or(Value::Null),
        "runtime_events_jsonl": review_targets.get("runtime_events_jsonl").cloned().unwrap_or(Value::Null),
        "client_transient_relay_wire_runtime_events_jsonl": review_targets.get("client_transient_relay_wire_runtime_events_jsonl").cloned().unwrap_or(Value::Null),
        "wire_helper_runtime_events_jsonl": review_targets.get("wire_helper_runtime_events_jsonl").cloned().unwrap_or(Value::Null),
    });
    Ok(payload)
}

pub fn linux_wide_live_audit_status_contract_check(
    status_path: &Path,
    expected: &LinuxLiveExpectedTopology,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = read_json(status_path)?;
    check_expected_status_topology(&payload, expected)?;
    ensure(
        payload["artifact_schema"].as_str() == Some("linux_wide_live_audit_handoff_status_v1"),
        "status.artifact_schema",
    )?;
    ensure(
        payload["operator_handoff_schema"].as_str() == Some(HANDOFF_SCHEMA),
        "status.operator_handoff_schema",
    )?;
    ensure(
        payload["operator_handoff_producer"].as_str() == Some(PRODUCER),
        "status.operator_handoff_producer",
    )?;
    ensure(
        payload["source_manifest_schema"].as_str() == Some(MANIFEST_SCHEMA),
        "status.source_manifest_schema",
    )?;
    ensure(
        payload["consumer_source"].as_str() == Some("operator_handoff"),
        "status.consumer_source",
    )?;
    ensure(
        s(&payload["live_audit_manifest_json"]).ends_with("live-audit.manifest.json"),
        "status.live_audit_manifest_json",
    )?;
    ensure(
        s(&payload["live_audit_summary_md"]).ends_with("live-audit-summary.md"),
        "status.live_audit_summary_md",
    )?;
    ensure(
        payload["operator_scope"]["relay_address"].as_str()
            == Some(expected.relay_address.as_str()),
        "status.operator_scope.relay_address",
    )?;
    ensure(
        payload["server_host"].as_str() == Some(expected.server_host.as_str()),
        "status.server_host",
    )?;
    ensure(
        payload["client_host"].as_str() == Some(expected.client_host.as_str()),
        "status.client_host",
    )?;
    ensure(
        matches!(
            payload["layer_status"]["wire"]["product_verdict"].as_str(),
            Some("green" | "yellow")
        ),
        "status.layer_status.wire.product_verdict",
    )?;
    ensure(
        matches!(
            payload["layer_status"]["stealth"]["bundle_verdict"].as_str(),
            Some("green" | "yellow")
        ),
        "status.layer_status.stealth.bundle_verdict",
    )?;
    for field in [
        "operator_handoff_status_json",
        "handoff_status_json",
        "rerun_command",
        "review_handoff_status_command",
        "review_preflight_command",
        "review_startup_probe_command",
        "review_wire_helper_stdout_command",
        "review_stealth_manifest_command",
        "next_action",
    ] {
        ensure(!payload[field].is_null(), &format!("status.{field}"))?;
    }
    for (field, suffix) in [
        ("wire_helper_stdout_json", "wire-helper.stdout.json"),
        ("client_preflight_json", "preflight.json"),
        ("client_startup_probe_json", "startup.json"),
        (
            "client_transient_relay_wire_runtime_events_jsonl",
            "transient-runtime-events.jsonl",
        ),
        (
            "wire_helper_runtime_events_jsonl",
            "wire-helper-runtime-events.jsonl",
        ),
        (
            "stealth_live_acceptance_manifest_json",
            "stealth-live-acceptance.manifest.json",
        ),
    ] {
        ensure(
            s(&payload[field]).ends_with(suffix),
            &format!("status.{field}"),
        )?;
    }
    ensure(
        !payload["next_action"]["command"].is_null()
            && !payload["next_action"]["artifact"].is_null()
            && !payload["next_action"]["reason"].is_null(),
        "status.next_action",
    )?;

    let summary = std::fs::read_to_string(
        payload["live_audit_summary_md"]
            .as_str()
            .ok_or("status.live_audit_summary_md missing")?,
    )?;
    let primary_blocker = payload["layer_status"]["stealth"]["primary_blocker"]
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("none");
    for expected in [
        format!("- Relay address: `{}`", s(&payload["relay_address"])),
        format!(
            "- Acceptance overall status: `{}`",
            s(&payload["acceptance_overview"]["overall_status"])
        ),
        format!(
            "- Acceptance next action: `{}`",
            s(&payload["acceptance_overview"]["overall_next_action"])
        ),
        format!(
            "- Acceptance primary layer: `{}`",
            s(&payload["acceptance_overview"]["primary_layer"])
        ),
        format!(
            "- Wire verdict/status: `{}` / `{}`",
            s(&payload["layer_status"]["wire"]["product_verdict"]),
            s(&payload["layer_status"]["wire"]["acceptance_status"])
        ),
        format!(
            "- Wire witness correlation: `{}`",
            s(&payload["layer_status"]["wire"]["independent_witness_correlation_status"])
        ),
        format!(
            "- Stealth verdict/status: `{}` / `{}`",
            s(&payload["layer_status"]["stealth"]["bundle_verdict"]),
            s(&payload["layer_status"]["stealth"]["bundle_status"])
        ),
        format!("- Stealth primary blocker: `{primary_blocker}`"),
        format!(
            "- Handoff status artifact: `{}`",
            s(&payload["operator_handoff_status_json"])
        ),
        format!(
            "- Handoff contour/scope: `{} / {}`",
            s(&payload["supported_product_contour"]),
            s(&payload["supported_operator_scope"])
        ),
        format!(
            "- Output dir: `{}`",
            s(&payload["operator_scope"]["output_dir"])
        ),
        format!("- Server host: `{}`", s(&payload["server_host"])),
        format!("- Client host: `{}`", s(&payload["client_host"])),
        format!("- Next action id: `{}`", s(&payload["next_action"]["id"])),
        format!(
            "- Next action reason: `{}`",
            s(&payload["next_action"]["reason"])
        ),
        format!(
            "- Next action command: `{}`",
            s(&payload["next_action"]["command"])
        ),
        format!(
            "- Next action artifact: `{}`",
            s(&payload["next_action"]["artifact"])
        ),
        format!(
            "- Next action context: `layer={}; wire={}/{}; stealth={}/{}; blocker={}`",
            s(&payload["next_action_context"]["primary_layer"]),
            s(&payload["next_action_context"]["wire_verdict"]),
            s(&payload["next_action_context"]["wire_status"]),
            s(&payload["next_action_context"]["stealth_verdict"]),
            s(&payload["next_action_context"]["stealth_status"]),
            s_or_none(&payload["next_action_context"]["primary_blocker_id"])
        ),
        format!(
            "- `live-audit.manifest.json`: `{}`",
            s(&payload["live_audit_manifest_json"])
        ),
        format!(
            "- `live-audit-handoff-status.json`: `{}`",
            s(&payload["operator_handoff_status_json"])
        ),
        format!(
            "- `preflight.json`: `{}`",
            s(&payload["client_preflight_json"])
        ),
        format!(
            "- `startup-probe.json`: `{}`",
            s(&payload["client_startup_probe_json"])
        ),
        format!(
            "- `transient-relay-wire-runtime-events.jsonl`: `{}`",
            s(&payload["client_transient_relay_wire_runtime_events_jsonl"])
        ),
        format!(
            "- `wire-helper-runtime-events.jsonl`: `{}`",
            s(&payload["wire_helper_runtime_events_jsonl"])
        ),
        format!(
            "- `wire-host-acceptance-summary.json`: `{}`",
            s(&payload["wire_acceptance_summary_json"])
        ),
        format!(
            "- `stealth-live-acceptance-bundle.json`: `{}`",
            s(&payload["stealth_live_acceptance_bundle_json"])
        ),
        format!(
            "- `stealth-live-acceptance.manifest.json`: `{}`",
            s(&payload["stealth_live_acceptance_manifest_json"])
        ),
    ] {
        ensure(
            summary.contains(&expected),
            &format!("status summary missing {expected}"),
        )?;
    }
    Ok(())
}

pub fn linux_wide_live_audit_handoff_status_fixture_contract_check(
    stealth_manifest: &Path,
    wire_manifest: &Path,
    green_manifest: &Path,
    stealth_status: &Path,
    wire_status: &Path,
    green_status: &Path,
    expected: &LinuxLiveExpectedTopology,
) -> Result<(), Box<dyn std::error::Error>> {
    let stealth = read_json(stealth_status)?;
    let wire = read_json(wire_status)?;
    let green = read_json(green_status)?;
    for status in [&stealth, &wire, &green] {
        check_expected_status_topology(status, expected)?;
    }

    ensure(
        stealth["handoff_status"].as_str() == Some("blocked_on_stealth"),
        "fixture stealth handoff_status",
    )?;
    ensure(
        stealth["next_required_action"].as_str() == Some("runtime_relay_surface_evidence"),
        "fixture stealth next_required_action",
    )?;
    ensure(
        stealth["next_action"]["reason"].as_str() == Some("inspect_runtime_relay_surface_evidence"),
        "fixture stealth next_action reason",
    )?;
    ensure(
        stealth["supported_product_contour"].as_str() == Some(SUPPORTED_PRODUCT_CONTOUR),
        "fixture stealth supported_product_contour",
    )?;
    ensure(
        stealth["acceptance_overview"]["primary_layer"].as_str() == Some("stealth"),
        "fixture stealth primary_layer",
    )?;
    ensure(
        stealth["layer_status"]["wire"]["independent_witness_correlation_status"].as_str()
            == Some("matched"),
        "fixture stealth witness correlation",
    )?;
    ensure(
        stealth["layer_status"]["stealth"]["bundle_status"].as_str()
            == Some("blocked_on_runtime_relay_surface_evidence"),
        "fixture stealth bundle_status",
    )?;
    ensure(
        stealth["next_action_context"]["primary_blocker_id"].as_str()
            == Some("runtime_relay_surface_evidence"),
        "fixture stealth primary_blocker_id",
    )?;
    ensure(
        s(&stealth["stealth_live_acceptance_bundle_json"]).ends_with("stealth-blocked.json"),
        "fixture stealth bundle artifact",
    )?;
    ensure(
        s(&stealth["wire_witness_summary_json"]).ends_with("wire-witness-summary.json"),
        "fixture stealth witness summary",
    )?;
    ensure(
        s(&stealth["wire_witness_capture_pcapng"]).ends_with("wire.pcapng"),
        "fixture stealth witness pcap",
    )?;
    ensure(
        !stealth["review_witness_summary_command"].is_null(),
        "fixture stealth witness command",
    )?;
    ensure(
        s(&stealth["review_transient_runtime_events_command"]).starts_with("sed -n"),
        "fixture stealth transient runtime command",
    )?;
    ensure(
        s(&stealth["review_wire_helper_runtime_events_command"]).starts_with("sed -n"),
        "fixture stealth wire helper runtime command",
    )?;
    ensure(
        Path::new(required_str(&stealth, "live_audit_manifest_json")?)
            .parent()
            .map(|path| path.join("live-audit-handoff-status.json"))
            .and_then(|path| {
                path.file_name()
                    .map(|name| name == "live-audit-handoff-status.json")
            })
            .unwrap_or(false),
        "fixture stealth handoff status filename",
    )?;

    ensure(
        wire["handoff_status"].as_str() == Some("blocked_on_wire"),
        "fixture wire handoff_status",
    )?;
    ensure(
        wire["next_required_action"].as_str() == Some("inspect_wire_host_acceptance_summary"),
        "fixture wire next_required_action",
    )?;
    ensure(
        wire["next_action"]["reason"].as_str() == Some("inspect_wire_host_acceptance_summary"),
        "fixture wire next_action reason",
    )?;
    ensure(
        wire["supported_operator_scope"].as_str() == Some(SUPPORTED_OPERATOR_SCOPE),
        "fixture wire supported_operator_scope",
    )?;
    ensure(
        wire["acceptance_overview"]["primary_layer"].as_str() == Some("wire"),
        "fixture wire primary_layer",
    )?;
    ensure(
        wire["layer_status"]["wire"]["acceptance_status"].as_str() == Some("needs_witness"),
        "fixture wire acceptance_status",
    )?;
    ensure(
        wire["layer_status"]["stealth"]["bundle_verdict"].as_str() == Some("green"),
        "fixture wire stealth verdict",
    )?;
    ensure(
        s(&wire["wire_acceptance_summary_json"]).ends_with("wire-blocked.json"),
        "fixture wire acceptance artifact",
    )?;
    ensure(
        wire["next_action_context"]["primary_layer"].as_str() == Some("wire"),
        "fixture wire next_action_context primary_layer",
    )?;
    ensure(
        wire["wire_witness_summary_json"].is_null(),
        "fixture wire witness summary null",
    )?;
    ensure(
        wire["wire_witness_capture_pcapng"].is_null(),
        "fixture wire witness pcap null",
    )?;
    ensure(
        wire["review_witness_summary_command"].is_null(),
        "fixture wire witness command null",
    )?;

    ensure(
        green["handoff_status"].as_str() == Some("ready_for_next_live_validation"),
        "fixture green handoff_status",
    )?;
    ensure(
        green["next_required_action"].as_str() == Some("collect_next_live_validation_slice"),
        "fixture green next_required_action",
    )?;
    ensure(
        green["next_action"]["reason"].as_str() == Some("collect_next_live_validation_slice"),
        "fixture green next_action reason",
    )?;
    ensure(
        green["acceptance_overview"]["overall_status"].as_str() == Some("acceptance_green"),
        "fixture green overall_status",
    )?;
    ensure(
        green["layer_status"]["wire"]["product_verdict"].as_str() == Some("green"),
        "fixture green wire verdict",
    )?;
    ensure(
        green["layer_status"]["stealth"]["bundle_status"].as_str() == Some("acceptance_green"),
        "fixture green stealth bundle_status",
    )?;
    ensure(
        s(&green["next_action"]["artifact"]).ends_with("live-audit-summary.md"),
        "fixture green next_action artifact",
    )?;
    ensure(
        s(&green["review_runtime_events_command"]).starts_with("sed -n"),
        "fixture green runtime command",
    )?;

    let mut broken_no_layer = read_json(green_manifest)?;
    if let Some(handoff) = broken_no_layer
        .get_mut("operator_handoff")
        .and_then(Value::as_object_mut)
    {
        handoff.remove("layer_status");
    }
    expect_handoff_build_error(
        green_manifest,
        &broken_no_layer,
        "broken-no-layer.manifest.json",
        "operator_handoff missing required field: layer_status",
    )?;

    let mut broken_no_next_action_command = read_json(green_manifest)?;
    if let Some(next_action) = broken_no_next_action_command
        .get_mut("operator_handoff")
        .and_then(|value| value.get_mut("next_action"))
        .and_then(Value::as_object_mut)
    {
        next_action.remove("command");
    }
    expect_handoff_build_error(
        green_manifest,
        &broken_no_next_action_command,
        "broken-no-next-action-command.manifest.json",
        "operator_handoff.next_action missing required field: command",
    )?;

    let mut broken_inconsistent_summary = read_json(green_manifest)?;
    broken_inconsistent_summary["operator_handoff"]["review_targets"]["summary_md"] =
        json!("/tmp/not-the-real-summary.md");
    expect_handoff_build_error(
        green_manifest,
        &broken_inconsistent_summary,
        "broken-inconsistent-summary.manifest.json",
        "operator_handoff.summary_md does not match review_targets.summary_md",
    )?;

    let mut broken_review_summary_command = read_json(green_manifest)?;
    broken_review_summary_command["operator_handoff"]["handoff_commands"]
        ["review_summary_command"] = json!("sed -n '1,160p' /tmp/wrong-summary.md");
    expect_handoff_build_error(
        green_manifest,
        &broken_review_summary_command,
        "broken-review-summary-command.manifest.json",
        "operator_handoff.handoff_commands.review_summary_command does not reference operator_handoff.review_targets.summary_md",
    )?;

    let mut broken_next_action_linkage = read_json(wire_manifest)?;
    broken_next_action_linkage["operator_handoff"]["next_action"]["command"] =
        broken_next_action_linkage["operator_handoff"]["handoff_commands"]
            ["review_stealth_bundle_command"]
            .clone();
    expect_handoff_build_error(
        green_manifest,
        &broken_next_action_linkage,
        "broken-next-action-linkage.manifest.json",
        "operator_handoff.next_action.command does not match handoff_commands.review_wire_acceptance_command",
    )?;

    let mut broken_next_action_reason = read_json(green_manifest)?;
    broken_next_action_reason["operator_handoff"]["next_action"]["reason"] = json!("broken_reason");
    expect_handoff_build_error(
        green_manifest,
        &broken_next_action_reason,
        "broken-next-action-reason.manifest.json",
        "operator_handoff.next_action.reason does not match acceptance_overview.overall_next_action",
    )?;

    let mut broken_next_action_id = read_json(stealth_manifest)?;
    broken_next_action_id["operator_handoff"]["next_action"]["id"] = json!("broken_blocker_id");
    expect_handoff_build_error(
        green_manifest,
        &broken_next_action_id,
        "broken-next-action-id.manifest.json",
        "operator_handoff.next_action.id does not match stealth-layer blocker semantics",
    )?;

    let summary_path = PathBuf::from(required_str(&green, "live_audit_summary_md")?);
    write_broken_status_summary_and_expect_fail(
        StatusSummarySource {
            expected,
            path: green_status,
        },
        &green,
        &summary_path,
        "broken-cross-surface-summary.md",
        &format!(
            "- Next action artifact: `{}`\n",
            s(&green["next_action"]["artifact"])
        ),
        "- Next action artifact: `/tmp/broken-artifact.md`\n",
        "broken-cross-surface-status.json",
    )?;
    write_broken_status_summary_and_expect_fail(
        StatusSummarySource {
            expected,
            path: green_status,
        },
        &green,
        &summary_path,
        "broken-context-summary.md",
        &format!(
            "- Acceptance overview: `status={}; next={}; layer={}`\n",
            s(&green["acceptance_overview"]["overall_status"]),
            s(&green["acceptance_overview"]["overall_next_action"]),
            s(&green["acceptance_overview"]["primary_layer"])
        ),
        "- Acceptance overview: `status=broken; next=broken; layer=wire`\n",
        "broken-context-status.json",
    )?;
    write_broken_status_summary_and_expect_fail(
        StatusSummarySource {
            expected,
            path: green_status,
        },
        &green,
        &summary_path,
        "broken-metadata-summary.md",
        &format!(
            "- Acceptance next action: `{}`\n",
            s(&green["acceptance_overview"]["overall_next_action"])
        ),
        "- Acceptance next action: `broken-next-action`\n",
        "broken-metadata-status.json",
    )?;
    write_broken_status_summary_and_expect_fail(
        StatusSummarySource {
            expected,
            path: green_status,
        },
        &green,
        &summary_path,
        "broken-key-artifacts-summary.md",
        &format!(
            "- `wire-helper-runtime-events.jsonl`: `{}`\n",
            s(&green["wire_helper_runtime_events_jsonl"])
        ),
        "- `wire-helper-runtime-events.jsonl`: `/tmp/broken-wire-helper-runtime-events.jsonl`\n",
        "broken-key-artifacts-status.json",
    )?;
    write_broken_status_summary_and_expect_fail(
        StatusSummarySource {
            expected,
            path: green_status,
        },
        &green,
        &summary_path,
        "broken-replay-hints-summary.md",
        &format!(
            "- Review stealth manifest command: `{}`\n",
            s(&green["review_stealth_manifest_command"])
        ),
        "- Review stealth manifest command: `cargo run -q -p aegis-measure -- pretty-json --input /tmp/broken-stealth-manifest.json`\n",
        "broken-replay-hints-status.json",
    )?;
    Ok(())
}

pub fn linux_wide_live_audit_materialized_contract_check(
    dry_run_output_path: &Path,
    stealth_manifest: &Path,
    wire_manifest: &Path,
    green_manifest: &Path,
    dry_run_manifest: &Path,
    expected: &LinuxLiveExpectedTopology,
) -> Result<(), Box<dyn std::error::Error>> {
    let dry_run_output = std::fs::read_to_string(dry_run_output_path)?;
    let stealth_payload = read_json(stealth_manifest)?;
    let wire_payload = read_json(wire_manifest)?;
    let green_payload = read_json(green_manifest)?;
    let dry_run_payload = read_json(dry_run_manifest)?;

    for payload in [
        &stealth_payload,
        &wire_payload,
        &green_payload,
        &dry_run_payload,
    ] {
        check_manifest_contract(payload)?;
        check_expected_manifest_topology(payload, expected)?;
        check_materialized_status_contract(payload)?;
        check_review_command_contract(payload)?;
        check_rerun_command_contract(payload)?;
        check_next_action_command_contract(payload)?;
        check_next_action_identity_contract(payload)?;
    }

    check_dry_run_plan(&dry_run_output)?;
    check_dry_run_materialized_rerun_parity(&dry_run_output, &dry_run_payload)?;
    check_dry_run_materialized_artifact_parity(&dry_run_output, &dry_run_payload)?;
    check_dry_run_materialized_review_parity(&dry_run_output, &dry_run_payload)?;
    check_dry_run_summary_parity(&dry_run_output, &dry_run_payload)?;

    ensure(
        stealth_payload["operator_handoff"]["next_action"]["layer"].as_str() == Some("stealth"),
        "stealth next_action layer",
    )?;
    ensure(
        stealth_payload["operator_handoff"]["handoff_schema"].as_str() == Some(HANDOFF_SCHEMA),
        "stealth handoff schema",
    )?;
    ensure(
        stealth_payload["operator_handoff"]["next_action"]["id"].as_str()
            == Some("runtime_relay_surface_evidence"),
        "stealth next_action id",
    )?;
    ensure(
        stealth_payload["operator_handoff"]["next_action"]["reason"].as_str()
            == Some("inspect_runtime_relay_surface_evidence"),
        "stealth next_action reason",
    )?;
    ensure(
        s(&stealth_payload["operator_handoff"]["next_action"]["artifact"])
            .ends_with("stealth-blocked.json"),
        "stealth next_action artifact",
    )?;
    ensure(
        stealth_payload["operator_handoff"]["acceptance_overview"]["primary_layer"].as_str()
            == Some("stealth"),
        "stealth primary layer",
    )?;
    ensure(
        stealth_payload["operator_handoff"]["layer_status"]["wire"]
            ["independent_witness_correlation_status"]
            .as_str()
            == Some("matched"),
        "stealth witness correlation",
    )?;
    ensure(
        stealth_payload["operator_handoff"]["layer_status"]["stealth"]["bundle_status"].as_str()
            == Some("blocked_on_runtime_relay_surface_evidence"),
        "stealth bundle status",
    )?;
    ensure(
        stealth_payload["operator_handoff"]["operator_scope"]["relay_address"].as_str()
            == Some(expected.relay_address.as_str()),
        "stealth relay address",
    )?;
    ensure(
        stealth_payload["operator_handoff"]["next_action_context"]["primary_blocker_id"].as_str()
            == Some("runtime_relay_surface_evidence"),
        "stealth primary blocker id",
    )?;
    ensure(
        s(&stealth_payload["operator_handoff"]["review_targets"]["wire_witness_summary_json"])
            .ends_with("wire-witness-summary.json"),
        "stealth witness summary target",
    )?;
    ensure(
        s(&stealth_payload["operator_handoff"]["review_targets"]["wire_witness_capture_pcapng"])
            .ends_with("wire.pcapng"),
        "stealth witness pcap target",
    )?;
    ensure(
        s(&stealth_payload["operator_handoff"]["review_targets"]["client_preflight_json"])
            .ends_with("preflight.json"),
        "stealth preflight target",
    )?;
    ensure(
        s(&stealth_payload["operator_handoff"]["review_targets"]["client_startup_probe_json"])
            .ends_with("startup.json"),
        "stealth startup target",
    )?;
    ensure(
        s(&stealth_payload["operator_handoff"]["review_targets"]
            ["client_transient_relay_wire_runtime_events_jsonl"])
        .ends_with("transient-runtime-events.jsonl"),
        "stealth transient runtime target",
    )?;
    ensure(
        s(&stealth_payload["operator_handoff"]["review_targets"]
            ["wire_helper_runtime_events_jsonl"])
        .ends_with("wire-helper-runtime-events.jsonl"),
        "stealth wire helper runtime target",
    )?;
    ensure(
        s(&stealth_payload["operator_handoff"]["review_targets"]
            ["stealth_live_acceptance_manifest_json"])
        .ends_with("stealth-live-acceptance.manifest.json"),
        "stealth manifest target",
    )?;
    for field in [
        "review_witness_summary_command",
        "review_preflight_command",
        "review_startup_probe_command",
        "review_stealth_manifest_command",
    ] {
        ensure(
            !stealth_payload["operator_handoff"]["handoff_commands"][field].is_null(),
            &format!("stealth {field}"),
        )?;
    }
    ensure(
        s(&stealth_payload["operator_handoff"]["handoff_commands"]
            ["review_transient_runtime_events_command"])
        .starts_with("sed -n"),
        "stealth transient runtime command",
    )?;
    ensure(
        s(&stealth_payload["operator_handoff"]["handoff_commands"]
            ["review_wire_helper_runtime_events_command"])
        .starts_with("sed -n"),
        "stealth wire helper runtime command",
    )?;

    ensure(
        wire_payload["operator_handoff"]["next_action"]["layer"].as_str() == Some("wire"),
        "wire next_action layer",
    )?;
    ensure(
        wire_payload["operator_handoff"]["supported_product_contour"].as_str()
            == Some(SUPPORTED_PRODUCT_CONTOUR),
        "wire supported product contour",
    )?;
    ensure(
        wire_payload["operator_handoff"]["next_action"]["id"].as_str()
            == Some("inspect_wire_host_acceptance_summary"),
        "wire next_action id",
    )?;
    ensure(
        wire_payload["operator_handoff"]["next_action"]["reason"].as_str()
            == Some("inspect_wire_host_acceptance_summary"),
        "wire next_action reason",
    )?;
    ensure(
        s(&wire_payload["operator_handoff"]["next_action"]["artifact"])
            .ends_with("wire-blocked.json"),
        "wire next_action artifact",
    )?;
    ensure(
        wire_payload["operator_handoff"]["acceptance_overview"]["primary_layer"].as_str()
            == Some("wire"),
        "wire primary layer",
    )?;
    ensure(
        wire_payload["operator_handoff"]["layer_status"]["wire"]["acceptance_status"].as_str()
            == Some("needs_witness"),
        "wire acceptance status",
    )?;
    ensure(
        wire_payload["operator_handoff"]["layer_status"]["stealth"]["bundle_verdict"].as_str()
            == Some("green"),
        "wire stealth verdict",
    )?;
    ensure(
        wire_payload["operator_handoff"]["next_action_context"]["primary_layer"].as_str()
            == Some("wire"),
        "wire next action primary layer",
    )?;
    ensure(
        wire_payload["operator_handoff"]["review_targets"]["wire_witness_summary_json"].is_null(),
        "wire witness summary null",
    )?;
    ensure(
        wire_payload["operator_handoff"]["review_targets"]["wire_witness_capture_pcapng"].is_null(),
        "wire witness pcap null",
    )?;
    ensure(
        wire_payload["operator_handoff"]["handoff_commands"]["review_witness_summary_command"]
            .is_null(),
        "wire witness command null",
    )?;

    ensure(
        green_payload["operator_handoff"]["next_action"]["layer"].as_str() == Some("none"),
        "green next_action layer",
    )?;
    ensure(
        green_payload["operator_handoff"]["supported_operator_scope"].as_str()
            == Some(SUPPORTED_OPERATOR_SCOPE),
        "green supported operator scope",
    )?;
    ensure(
        green_payload["operator_handoff"]["next_action"]["id"].as_str()
            == Some("collect_next_live_validation_slice"),
        "green next_action id",
    )?;
    ensure(
        green_payload["operator_handoff"]["next_action"]["reason"].as_str()
            == Some("collect_next_live_validation_slice"),
        "green next_action reason",
    )?;
    ensure(
        green_payload["operator_handoff"]["acceptance_overview"]["overall_status"].as_str()
            == Some("acceptance_green"),
        "green overall status",
    )?;
    ensure(
        green_payload["operator_handoff"]["layer_status"]["wire"]["product_verdict"].as_str()
            == Some("green"),
        "green wire verdict",
    )?;
    ensure(
        green_payload["operator_handoff"]["layer_status"]["stealth"]["bundle_status"].as_str()
            == Some("acceptance_green"),
        "green stealth bundle status",
    )?;
    ensure(
        green_payload["operator_handoff"]["next_action"]["command"]
            == green_payload["operator_handoff"]["handoff_commands"]["rerun_command"],
        "green next_action command",
    )?;
    ensure(
        green_payload["operator_handoff"]["next_action"]["artifact"]
            == green_payload["operator_handoff"]["summary_md"],
        "green next_action artifact",
    )?;

    // External materialized input is read-only. Mutation-based fixture checks
    // belong to the unit-test harness, never to paths supplied by a manifest.
    Ok(())
}

fn check_materialized_status_contract(payload: &Value) -> Result<(), Box<dyn std::error::Error>> {
    let status_path = PathBuf::from(required_str(payload, "live_audit_handoff_status_json")?);
    ensure(status_path.exists(), "materialized status missing")?;
    let materialized = read_json(&status_path)?;
    let referenced = read_json(Path::new(required_str(
        &payload["review_targets"],
        "manifest_json",
    )?))?;
    ensure(
        referenced == *payload,
        "materialized manifest differs from reviewed payload",
    )?;
    let regenerated = handoff_status_from_manifest(payload)?;
    ensure(
        materialized == regenerated,
        "materialized status does not match regenerated status",
    )?;
    ensure(
        materialized["live_audit_manifest_json"] == payload["review_targets"]["manifest_json"],
        "materialized status manifest target",
    )?;
    ensure(
        materialized["live_audit_summary_md"] == payload["live_audit_summary_md"],
        "materialized status summary target",
    )?;
    ensure(
        materialized["next_action"] == payload["next_action"],
        "materialized status next_action",
    )?;
    Ok(())
}

fn check_review_command_contract(payload: &Value) -> Result<(), Box<dyn std::error::Error>> {
    let commands = &payload["operator_handoff"]["handoff_commands"];
    check_json_review_command(
        required_str(commands, "review_manifest_command")?,
        required_str(&payload["review_targets"], "manifest_json")?,
    )?;
    check_json_review_command(
        required_str(commands, "review_handoff_status_command")?,
        required_str(payload, "live_audit_handoff_status_json")?,
    )?;
    check_text_review_command(
        required_str(commands, "review_summary_command")?,
        required_str(payload, "live_audit_summary_md")?,
    )?;
    check_json_review_command(
        required_str(commands, "review_preflight_command")?,
        required_str(payload, "client_preflight_json")?,
    )?;
    check_json_review_command(
        required_str(commands, "review_startup_probe_command")?,
        required_str(payload, "client_startup_probe_json")?,
    )?;
    check_json_review_command(
        required_str(commands, "review_wire_helper_stdout_command")?,
        required_str(payload, "wire_host_helper_stdout_json")?,
    )?;
    check_json_review_command(
        required_str(commands, "review_wire_acceptance_command")?,
        required_str(payload, "wire_host_acceptance_summary_json")?,
    )?;
    check_json_review_command(
        required_str(commands, "review_stealth_bundle_command")?,
        required_str(payload, "stealth_live_acceptance_bundle_json")?,
    )?;
    check_json_review_command(
        required_str(commands, "review_stealth_manifest_command")?,
        required_str(payload, "stealth_live_acceptance_manifest_json")?,
    )?;
    check_text_review_command(
        required_str(commands, "review_runtime_events_command")?,
        required_str(payload, "client_runtime_events_jsonl")?,
    )?;
    check_text_review_command(
        required_str(commands, "review_transient_runtime_events_command")?,
        required_str(payload, "client_transient_relay_wire_runtime_events_jsonl")?,
    )?;
    check_text_review_command(
        required_str(commands, "review_wire_helper_runtime_events_command")?,
        required_str(payload, "wire_helper_runtime_events_jsonl")?,
    )?;

    let witness_command = &commands["review_witness_summary_command"];
    let witness_path = &payload["wire_witness_summary_json"];
    if witness_command.is_null() {
        ensure(witness_path.is_null(), "witness command/path mismatch")?;
    } else {
        check_json_review_command(
            witness_command
                .as_str()
                .ok_or("review_witness_summary_command must be a string")?,
            witness_path
                .as_str()
                .ok_or("wire_witness_summary_json must be a string")?,
        )?;
    }

    let summary = std::fs::read_to_string(required_str(payload, "live_audit_summary_md")?)?;
    ensure(
        summary.starts_with("# Linux Wide Mimicry Live Audit\n"),
        "materialized summary heading",
    )?;
    ensure(
        summary.contains(&format!(
            "- Relay address: `{}`",
            s(&payload["relay_address"])
        )),
        "materialized summary relay address",
    )?;
    ensure(
        summary.contains(&format!(
            "- Review handoff status command: `{}`",
            s(&commands["review_handoff_status_command"])
        )),
        "materialized summary handoff status command",
    )?;
    ensure(
        summary.contains(&format!(
            "- Next action id: `{}`",
            s(&payload["operator_handoff"]["next_action"]["id"])
        )),
        "materialized summary next action id",
    )?;
    ensure(
        summary.contains(&format!(
            "- Next action command: `{}`",
            s(&payload["operator_handoff"]["next_action"]["command"])
        )),
        "materialized summary next action command",
    )?;
    Ok(())
}

fn check_rerun_command_contract(payload: &Value) -> Result<(), Box<dyn std::error::Error>> {
    let words = command_words(required_str(
        &payload["operator_handoff"]["handoff_commands"],
        "rerun_command",
    )?)?;
    ensure(
        words.len() >= 2
            && words[0] == "bash"
            && words[1] == "scripts/run-linux-wide-mimicry-live-audit.sh",
        "unexpected rerun program",
    )?;
    let mut options = std::collections::BTreeMap::new();
    let mut args = words[2..].iter();
    while let Some(flag) = args.next() {
        let value = match flag.as_str() {
            "--skip-redeploy" | "--phase-b-runtime-evidence-strict" => "true",
            "--server-host"
            | "--client-host"
            | "--ssh-user"
            | "--server-name"
            | "--relay-address"
            | "--output-dir"
            | "--server-port"
            | "--client-port"
            | "--server-private-key-path"
            | "--client-private-key-path"
            | "--manifest-url"
            | "--bootstrap-url"
            | "--client-audit-script"
            | "--server-audit-script"
            | "--remote-client-pcap"
            | "--remote-client-pcap-interface"
            | "--remote-runtime-events"
            | "--relay-transport-priority"
            | "--phase-b-baseline-json" => {
                args.next().ok_or("missing rerun option value")?.as_str()
            }
            _ => return Err("unexpected rerun option".into()),
        };
        ensure(
            !value.is_empty() && options.insert(flag.as_str(), value).is_none(),
            "empty or duplicate rerun option",
        )?;
    }
    for (flag, field) in [
        ("--server-host", "server_host"),
        ("--client-host", "client_host"),
        ("--relay-address", "relay_address"),
        ("--output-dir", "output_dir"),
    ] {
        ensure(
            options.get(flag).copied() == Some(required_str(payload, field)?),
            "rerun scope does not match manifest",
        )?;
    }
    for flag in ["--ssh-user", "--server-name"] {
        ensure(options.contains_key(flag), "incomplete rerun command")?;
    }
    for flag in ["--server-port", "--client-port"] {
        if let Some(port) = options.get(flag) {
            ensure(
                port.parse::<u16>().is_ok_and(|p| p != 0),
                "invalid rerun port",
            )?;
        }
    }
    Ok(())
}

fn check_dry_run_plan(output: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Check the supplied dry-run witness as data. Never rerun its command.
    for expected in [
        "Redeploy server and client from a clean purge",
        "Run server live audit script",
        "Run client live audit script",
        "Collect client runtime and service artifacts",
        "Harvest transient relay wire runtime",
        "Materialize local wire acceptance summary",
        "Materialize local stealth live acceptance bundle",
        "Write local audit manifest",
    ] {
        ensure(
            output.contains(expected),
            "dry-run witness is missing a required stage",
        )?;
    }
    Ok(())
}

fn check_next_action_command_contract(payload: &Value) -> Result<(), Box<dyn std::error::Error>> {
    let handoff = &payload["operator_handoff"];
    let next_action = &handoff["next_action"];
    match required_str(next_action, "layer")? {
        "stealth" | "wire" => {
            check_json_review_command(
                required_str(next_action, "command")?,
                required_str(next_action, "artifact")?,
            )?;
        }
        _ => {
            ensure(
                next_action["command"] == handoff["handoff_commands"]["rerun_command"],
                "next_action command does not match rerun command",
            )?;
            ensure(
                next_action["artifact"] == handoff["summary_md"],
                "next_action artifact does not match summary",
            )?;
            check_rerun_command_contract(payload)?;
        }
    }
    Ok(())
}

fn check_next_action_identity_contract(payload: &Value) -> Result<(), Box<dyn std::error::Error>> {
    let handoff = &payload["operator_handoff"];
    let next_action = &handoff["next_action"];
    let context = &handoff["next_action_context"];
    let overview = &handoff["acceptance_overview"];
    ensure(
        context["overall_next_action"] == overview["overall_next_action"],
        "next_action context overall_next_action",
    )?;
    ensure(
        next_action["reason"] == overview["overall_next_action"],
        "next_action reason",
    )?;
    let expected_id = match required_str(next_action, "layer")? {
        "stealth" => context["primary_blocker_id"]
            .as_str()
            .filter(|value| !value.is_empty())
            .unwrap_or("inspect_stealth_live_acceptance_bundle"),
        "wire" => "inspect_wire_host_acceptance_summary",
        _ => "collect_next_live_validation_slice",
    };
    ensure(
        next_action["id"].as_str() == Some(expected_id),
        "next_action id",
    )?;
    Ok(())
}

fn check_dry_run_materialized_rerun_parity(
    output: &str,
    payload: &Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let printed_rerun = extract_dry_run_rerun_command(output)?;
    ensure(
        printed_rerun == required_str(&payload["handoff_commands"], "rerun_command")?,
        "dry-run rerun command parity",
    )?;
    ensure(
        printed_rerun
            == required_str(
                &payload["operator_handoff"]["handoff_commands"],
                "rerun_command",
            )?,
        "dry-run operator rerun command parity",
    )?;
    assert_path_hint_in_output(
        required_str(&payload["review_targets"], "manifest_json")?,
        output,
    )?;
    assert_path_hint_in_output(required_str(payload, "live_audit_summary_md")?, output)?;
    assert_path_hint_in_output(
        required_str(payload, "live_audit_handoff_status_json")?,
        output,
    )?;
    Ok(())
}

fn check_dry_run_materialized_artifact_parity(
    output: &str,
    payload: &Value,
) -> Result<(), Box<dyn std::error::Error>> {
    check_path_eq(
        extract_dry_run_value(output, "[dry-run] write manifest to ")?,
        required_str(&payload["review_targets"], "manifest_json")?,
        "dry-run manifest path",
    )?;
    check_path_eq(
        extract_dry_run_value(output, "[dry-run] write summary to ")?,
        required_str(payload, "live_audit_summary_md")?,
        "dry-run summary path",
    )?;
    check_path_eq(
        extract_dry_run_value(output, "[dry-run] write handoff status to ")?,
        required_str(payload, "live_audit_handoff_status_json")?,
        "dry-run handoff status path",
    )?;
    check_path_eq(
        extract_dry_run_value(output, "[dry-run] manifest will link markdown summary ")?,
        required_str(&payload["review_targets"], "summary_md")?,
        "dry-run summary target",
    )?;
    check_path_eq(
        extract_dry_run_value(
            output,
            "[dry-run] manifest will summarize wire acceptance from ",
        )?,
        required_str(&payload["review_targets"], "wire_acceptance_summary_json")?,
        "dry-run wire summary target",
    )?;
    check_path_eq(
        extract_dry_run_value(
            output,
            "[dry-run] manifest will summarize stealth bundle from ",
        )?,
        required_str(
            &payload["review_targets"],
            "stealth_live_acceptance_bundle_json",
        )?,
        "dry-run stealth bundle target",
    )?;
    Ok(())
}

fn check_dry_run_materialized_review_parity(
    output: &str,
    payload: &Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let printed_review_summary =
        extract_dry_run_value(output, "[dry-run] review summary command: ")?;
    let printed_review_manifest =
        extract_dry_run_value(output, "[dry-run] review manifest command: ")?;
    let printed_review_handoff_status =
        extract_dry_run_value(output, "[dry-run] review handoff status command: ")?;
    let commands = &payload["handoff_commands"];
    let operator_commands = &payload["operator_handoff"]["handoff_commands"];

    ensure(
        normalized_review_words(printed_review_summary)?
            == normalized_review_words(required_str(commands, "review_summary_command")?)?,
        "dry-run review summary parity",
    )?;
    ensure(
        normalized_review_words(printed_review_manifest)?
            == normalized_review_words(required_str(commands, "review_manifest_command")?)?,
        "dry-run review manifest parity",
    )?;
    ensure(
        normalized_review_words(printed_review_handoff_status)?
            == normalized_review_words(required_str(commands, "review_handoff_status_command")?)?,
        "dry-run review handoff status parity",
    )?;
    ensure(
        normalized_review_words(printed_review_summary)?
            == normalized_review_words(required_str(operator_commands, "review_summary_command")?)?,
        "dry-run operator review summary parity",
    )?;
    ensure(
        normalized_review_words(printed_review_manifest)?
            == normalized_review_words(required_str(
                operator_commands,
                "review_manifest_command",
            )?)?,
        "dry-run operator review manifest parity",
    )?;
    ensure(
        normalized_review_words(printed_review_handoff_status)?
            == normalized_review_words(required_str(
                operator_commands,
                "review_handoff_status_command",
            )?)?,
        "dry-run operator review handoff status parity",
    )?;
    Ok(())
}

fn check_dry_run_summary_parity(
    output: &str,
    payload: &Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let summary = std::fs::read_to_string(required_str(payload, "live_audit_summary_md")?)?;
    ensure(
        summary.contains(&format!(
            "- Rerun command: `{}`",
            extract_dry_run_rerun_command(output)?
        )),
        "dry-run summary rerun command",
    )?;
    ensure(
        normalized_review_words(extract_dry_run_value(
            output,
            "[dry-run] review summary command: ",
        )?)? == normalized_review_words(extract_summary_value(
            &summary,
            "- Review summary command: ",
        )?)?,
        "dry-run summary review summary command",
    )?;
    ensure(
        normalized_review_words(extract_dry_run_value(
            output,
            "[dry-run] review manifest command: ",
        )?)? == normalized_review_words(extract_summary_value(
            &summary,
            "- Review manifest command: ",
        )?)?,
        "dry-run summary review manifest command",
    )?;
    ensure(
        normalized_review_words(extract_dry_run_value(
            output,
            "[dry-run] review handoff status command: ",
        )?)? == normalized_review_words(extract_summary_value(
            &summary,
            "- Review handoff status command: ",
        )?)?,
        "dry-run summary review handoff status command",
    )?;
    check_path_eq(
        extract_summary_value(&summary, "- Summary artifact: ")?,
        extract_dry_run_value(output, "[dry-run] write summary to ")?,
        "dry-run summary artifact",
    )?;
    check_path_eq(
        extract_summary_value(&summary, "- Manifest artifact: ")?,
        extract_dry_run_value(output, "[dry-run] write manifest to ")?,
        "dry-run manifest artifact",
    )?;
    check_path_eq(
        extract_summary_value(&summary, "- Handoff status artifact: ")?,
        extract_dry_run_value(output, "[dry-run] write handoff status to ")?,
        "dry-run handoff artifact",
    )?;
    check_path_eq(
        extract_summary_value(&summary, "- `wire-host-acceptance-summary.json`: ")?,
        extract_dry_run_value(
            output,
            "[dry-run] manifest will summarize wire acceptance from ",
        )?,
        "dry-run wire artifact",
    )?;
    check_path_eq(
        extract_summary_value(&summary, "- `stealth-live-acceptance-bundle.json`: ")?,
        extract_dry_run_value(
            output,
            "[dry-run] manifest will summarize stealth bundle from ",
        )?,
        "dry-run stealth artifact",
    )?;
    Ok(())
}

#[cfg(test)]
fn run_materialized_negative_checks(
    dry_run_output: &str,
    stealth_payload: &Value,
    wire_payload: &Value,
    green_payload: &Value,
    dry_run_payload: &Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let green_manifest = PathBuf::from(required_str(
        &green_payload["review_targets"],
        "manifest_json",
    )?);

    let mut broken_payload = green_payload.clone();
    broken_payload["handoff_commands"]["review_summary_command"] =
        json!("sed -n '1,160p' /tmp/wrong-summary.md");
    rust_manifest_expect_fail(
        &green_manifest,
        &broken_payload,
        "broken-handoff-command.manifest.json",
    )?;

    let mut broken_review_target_payload = stealth_payload.clone();
    broken_review_target_payload["wire_witness_summary_json"] =
        json!("/tmp/wrong-witness-summary.json");
    rust_manifest_expect_fail(
        &green_manifest,
        &broken_review_target_payload,
        "broken-witness-target.manifest.json",
    )?;

    let mut broken_runtime_alias_payload = green_payload.clone();
    broken_runtime_alias_payload["client_runtime_events_jsonl"] =
        json!("/tmp/wrong-runtime-events.jsonl");
    rust_manifest_expect_fail(
        &green_manifest,
        &broken_runtime_alias_payload,
        "broken-runtime-alias.manifest.json",
    )?;

    let summary_path = PathBuf::from(required_str(green_payload, "live_audit_summary_md")?);
    write_broken_summary_and_expect_fail(
        &green_manifest,
        green_payload,
        &summary_path,
        "broken-live-audit-summary.md",
        &format!(
            "- Next action command: `{}`\n",
            s(&green_payload["operator_handoff"]["next_action"]["command"])
        ),
        "- Next action command: `broken-command`\n",
        "broken-summary-command.manifest.json",
    )?;
    write_broken_summary_and_expect_fail(
        &green_manifest,
        green_payload,
        &summary_path,
        "broken-live-audit-summary-context.md",
        &format!(
            "- Next action context: `layer={}; wire={}/{}; stealth={}/{}; blocker={}`\n",
            s(&green_payload["operator_handoff"]["next_action_context"]["primary_layer"]),
            s(&green_payload["operator_handoff"]["next_action_context"]["wire_verdict"]),
            s(&green_payload["operator_handoff"]["next_action_context"]["wire_status"]),
            s(&green_payload["operator_handoff"]["next_action_context"]["stealth_verdict"]),
            s(&green_payload["operator_handoff"]["next_action_context"]["stealth_status"]),
            s_or_none(&green_payload["operator_handoff"]["next_action_context"]["primary_blocker_id"])
        ),
        "- Next action context: `layer=wire; wire=yellow/needs_witness; stealth=green/acceptance_green; blocker=broken`\n",
        "broken-summary-context.manifest.json",
    )?;
    write_broken_summary_and_expect_fail(
        &green_manifest,
        green_payload,
        &summary_path,
        "broken-live-audit-summary-metadata.md",
        &format!(
            "- Server host: `{}`\n",
            s(&green_payload["operator_handoff"]["operator_scope"]["server_host"])
        ),
        "- Server host: `broken-host`\n",
        "broken-summary-metadata.manifest.json",
    )?;
    write_broken_summary_and_expect_fail(
        &green_manifest,
        green_payload,
        &summary_path,
        "broken-live-audit-summary-key-artifacts.md",
        &format!(
            "- `startup-probe.json`: `{}`\n",
            s(&green_payload["client_startup_probe_json"])
        ),
        "- `startup-probe.json`: `/tmp/broken-startup.json`\n",
        "broken-summary-key-artifacts.manifest.json",
    )?;
    write_broken_summary_and_expect_fail(
        &green_manifest,
        green_payload,
        &summary_path,
        "broken-live-audit-summary-replay-hints.md",
        &format!(
            "- Review runtime events command: `{}`\n",
            s(&green_payload["handoff_commands"]["review_runtime_events_command"])
        ),
        "- Review runtime events command: `sed -n '1,1p' /tmp/broken-runtime-events.jsonl`\n",
        "broken-summary-replay-hints.manifest.json",
    )?;

    let status_path = PathBuf::from(required_str(
        green_payload,
        "live_audit_handoff_status_json",
    )?);
    let status_original = read_json(&status_path)?;
    let mut broken_status = status_original.clone();
    broken_status["next_action"]["artifact"] = json!("/tmp/broken-stale-artifact.md");
    write_json(&status_path, &broken_status)?;
    let stale_status_failed = check_materialized_status_contract(green_payload).is_err();
    write_json(&status_path, &status_original)?;
    ensure(stale_status_failed, "negative stale materialized status")?;

    let mut broken_review_status_payload = green_payload.clone();
    let truncated_status_command = format!(
        "sed -n '1,5p' {}",
        required_str(green_payload, "live_audit_handoff_status_json")?
    );
    broken_review_status_payload["handoff_commands"]["review_handoff_status_command"] =
        json!(truncated_status_command);
    broken_review_status_payload["operator_handoff"]["handoff_commands"]
        ["review_handoff_status_command"] =
        broken_review_status_payload["handoff_commands"]["review_handoff_status_command"].clone();
    ensure(
        check_review_command_contract(&broken_review_status_payload).is_err(),
        "negative truncated status review command",
    )?;

    let mut broken_review_summary_payload = green_payload.clone();
    let truncated_summary_command = format!(
        "sed -n '1,6p' {}",
        required_str(green_payload, "live_audit_summary_md")?
    );
    broken_review_summary_payload["handoff_commands"]["review_summary_command"] =
        json!(truncated_summary_command);
    broken_review_summary_payload["operator_handoff"]["handoff_commands"]
        ["review_summary_command"] =
        broken_review_summary_payload["handoff_commands"]["review_summary_command"].clone();
    ensure(
        check_review_command_contract(&broken_review_summary_payload).is_err(),
        "negative truncated summary review command",
    )?;

    let mut broken_review_runtime_payload = green_payload.clone();
    let truncated_runtime_command = format!(
        "sed -n '1,1p' {}",
        required_str(green_payload, "client_runtime_events_jsonl")?
    );
    broken_review_runtime_payload["handoff_commands"]["review_runtime_events_command"] =
        json!(truncated_runtime_command);
    broken_review_runtime_payload["operator_handoff"]["handoff_commands"]
        ["review_runtime_events_command"] =
        broken_review_runtime_payload["handoff_commands"]["review_runtime_events_command"].clone();
    ensure(
        check_review_command_contract(&broken_review_runtime_payload).is_err(),
        "negative truncated runtime review command",
    )?;

    let mut broken_rerun_payload = green_payload.clone();
    let incomplete_rerun = format!(
        "bash scripts/run-linux-wide-mimicry-live-audit.sh --server-host {}",
        required_str(green_payload, "server_host")?
    );
    broken_rerun_payload["handoff_commands"]["rerun_command"] = json!(incomplete_rerun);
    broken_rerun_payload["operator_handoff"]["handoff_commands"]["rerun_command"] =
        broken_rerun_payload["handoff_commands"]["rerun_command"].clone();
    ensure(
        check_rerun_command_contract(&broken_rerun_payload).is_err(),
        "negative incomplete rerun command",
    )?;

    let mut broken_next_action_payload = wire_payload.clone();
    broken_next_action_payload["next_action"]["command"] =
        broken_next_action_payload["handoff_commands"]["review_stealth_bundle_command"].clone();
    broken_next_action_payload["operator_handoff"]["next_action"]["command"] =
        broken_next_action_payload["next_action"]["command"].clone();
    ensure(
        check_next_action_command_contract(&broken_next_action_payload).is_err(),
        "negative next_action command drift",
    )?;

    let mut broken_next_action_reason_payload = green_payload.clone();
    broken_next_action_reason_payload["next_action"]["reason"] = json!("broken_reason");
    broken_next_action_reason_payload["operator_handoff"]["next_action"]["reason"] =
        broken_next_action_reason_payload["next_action"]["reason"].clone();
    ensure(
        check_next_action_identity_contract(&broken_next_action_reason_payload).is_err(),
        "negative next_action reason drift",
    )?;

    let mut broken_next_action_id_payload = stealth_payload.clone();
    broken_next_action_id_payload["next_action"]["id"] = json!("broken_blocker_id");
    broken_next_action_id_payload["operator_handoff"]["next_action"]["id"] =
        broken_next_action_id_payload["next_action"]["id"].clone();
    ensure(
        check_next_action_identity_contract(&broken_next_action_id_payload).is_err(),
        "negative next_action id drift",
    )?;

    let mut broken_dryrun_rerun_payload = dry_run_payload.clone();
    broken_dryrun_rerun_payload["handoff_commands"]["rerun_command"] =
        json!("bash scripts/run-linux-wide-mimicry-live-audit.sh --server-host 203.0.113.99 --output-dir /tmp/wrong");
    broken_dryrun_rerun_payload["operator_handoff"]["handoff_commands"]["rerun_command"] =
        broken_dryrun_rerun_payload["handoff_commands"]["rerun_command"].clone();
    ensure(
        check_dry_run_materialized_rerun_parity(dry_run_output, &broken_dryrun_rerun_payload)
            .is_err(),
        "negative dry-run rerun parity",
    )?;

    let mut broken_dryrun_artifact_payload = dry_run_payload.clone();
    broken_dryrun_artifact_payload["review_targets"]["wire_acceptance_summary_json"] =
        json!("/tmp/wrong-wire-summary.json");
    broken_dryrun_artifact_payload["operator_handoff"]["review_targets"]
        ["wire_acceptance_summary_json"] =
        broken_dryrun_artifact_payload["review_targets"]["wire_acceptance_summary_json"].clone();
    ensure(
        check_dry_run_materialized_artifact_parity(dry_run_output, &broken_dryrun_artifact_payload)
            .is_err(),
        "negative dry-run artifact parity",
    )?;

    let mut broken_dryrun_review_payload = dry_run_payload.clone();
    broken_dryrun_review_payload["handoff_commands"]["review_manifest_command"] =
        json!("cargo run -q -p aegis-measure -- pretty-json --input /tmp/wrong-manifest.json");
    broken_dryrun_review_payload["operator_handoff"]["handoff_commands"]
        ["review_manifest_command"] =
        broken_dryrun_review_payload["handoff_commands"]["review_manifest_command"].clone();
    ensure(
        check_dry_run_materialized_review_parity(dry_run_output, &broken_dryrun_review_payload)
            .is_err(),
        "negative dry-run review parity",
    )?;

    let dryrun_summary_path =
        PathBuf::from(required_str(dry_run_payload, "live_audit_summary_md")?);
    let mut broken_dryrun_summary_payload = dry_run_payload.clone();
    let broken_dryrun_summary_path =
        dryrun_summary_path.with_file_name("broken-dryrun-summary-parity.md");
    let dryrun_summary = std::fs::read_to_string(&dryrun_summary_path)?;
    write_text(
        &broken_dryrun_summary_path,
        &dryrun_summary.replace(
            &format!(
                "- `wire-host-acceptance-summary.json`: `{}`\n",
                s(&dry_run_payload["review_targets"]["wire_acceptance_summary_json"])
            ),
            "- `wire-host-acceptance-summary.json`: `/tmp/broken-wire-summary.json`\n",
        ),
    )?;
    broken_dryrun_summary_payload["live_audit_summary_md"] =
        json!(broken_dryrun_summary_path.display().to_string());
    broken_dryrun_summary_payload["review_targets"]["summary_md"] =
        broken_dryrun_summary_payload["live_audit_summary_md"].clone();
    broken_dryrun_summary_payload["operator_handoff"]["summary_md"] =
        broken_dryrun_summary_payload["live_audit_summary_md"].clone();
    broken_dryrun_summary_payload["operator_handoff"]["review_targets"]["summary_md"] =
        broken_dryrun_summary_payload["live_audit_summary_md"].clone();
    ensure(
        check_dry_run_summary_parity(dry_run_output, &broken_dryrun_summary_payload).is_err(),
        "negative dry-run summary parity",
    )?;

    Ok(())
}

#[cfg(test)]
fn write_broken_summary_and_expect_fail(
    manifest_path: &Path,
    payload: &Value,
    summary_path: &Path,
    broken_summary_filename: &str,
    from: &str,
    to: &str,
    broken_manifest_filename: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let broken_summary_path = summary_path.with_file_name(broken_summary_filename);
    let summary = std::fs::read_to_string(summary_path)?;
    write_text(&broken_summary_path, &summary.replace(from, to))?;
    let mut broken_payload = payload.clone();
    broken_payload["live_audit_summary_md"] = json!(broken_summary_path.display().to_string());
    broken_payload["operator_handoff"]["summary_md"] =
        broken_payload["live_audit_summary_md"].clone();
    broken_payload["review_targets"]["summary_md"] =
        broken_payload["live_audit_summary_md"].clone();
    rust_manifest_expect_fail(manifest_path, &broken_payload, broken_manifest_filename)
}

struct StatusSummarySource<'a> {
    expected: &'a LinuxLiveExpectedTopology,
    path: &'a Path,
}

fn write_broken_status_summary_and_expect_fail(
    source: StatusSummarySource<'_>,
    payload: &Value,
    summary_path: &Path,
    broken_summary_filename: &str,
    from: &str,
    to: &str,
    broken_status_filename: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let expected = source.expected;
    let status_path = source.path;
    let broken_summary_path = summary_path.with_file_name(broken_summary_filename);
    let summary = std::fs::read_to_string(summary_path)?;
    write_text(&broken_summary_path, &summary.replace(from, to))?;
    let mut broken_payload = payload.clone();
    broken_payload["live_audit_summary_md"] = json!(broken_summary_path.display().to_string());
    let broken_status_path = status_path.with_file_name(broken_status_filename);
    write_json(&broken_status_path, &broken_payload)?;
    ensure(
        linux_wide_live_audit_status_contract_check(&broken_status_path, expected).is_err(),
        &format!("negative status unexpectedly passed: {broken_status_filename}"),
    )
}

fn expect_handoff_build_error(
    source_manifest: &Path,
    payload: &Value,
    filename: &str,
    expected_error: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest_path = source_manifest.with_file_name(filename);
    let output_path = manifest_path.with_extension("status.json");
    write_json(&manifest_path, payload)?;
    match build_linux_wide_live_audit_handoff_status(&manifest_path, &output_path) {
        Ok(()) => Err(format!("negative handoff manifest unexpectedly passed: {filename}").into()),
        Err(error) => {
            let error = error.to_string();
            ensure(
                error.contains(expected_error),
                &format!("negative handoff error mismatch: {filename}: {error}"),
            )
        }
    }
}

#[cfg(test)]
fn rust_manifest_expect_fail(
    source_manifest: &Path,
    payload: &Value,
    filename: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = source_manifest.with_file_name(filename);
    write_json(&path, payload)?;
    ensure(
        linux_wide_live_audit_manifest_contract_check(&path).is_err(),
        &format!("negative manifest unexpectedly passed: {filename}"),
    )
}

fn normalized_review_words(command: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    normalized_review_words_for_workspace(
        command,
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml"),
    )
}

fn normalized_review_words_for_workspace(
    command: &str,
    workspace_manifest: &Path,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut words = command_words(command)?;
    // The checked-in producer optionally renders its absolute Cargo.toml.
    // It must refer to this workspace, not an externally selected Cargo project.
    if words.get(3).is_some_and(|word| word == "--manifest-path") {
        ensure(
            words[..3] == ["cargo", "run", "-q"],
            "unexpected review program",
        )?;
        let manifest = words.get(4).ok_or("missing review manifest path")?;
        ensure(
            std::fs::canonicalize(manifest)? == std::fs::canonicalize(workspace_manifest)?,
            "unexpected review Cargo manifest",
        )?;
        words.drain(3..5);
    }
    // The fixtures and producer can spell the same temporary directory through
    // a platform alias (for example /var and /private/var). Compare the selected
    // artifact, while still requiring the complete fixed program/argument form.
    let path_index = if words.len() == 9
        && words[..8]
            == [
                "cargo",
                "run",
                "-q",
                "-p",
                "aegis-measure",
                "--",
                "pretty-json",
                "--input",
            ] {
        8
    } else if words.len() == 4 && words[..3] == ["sed", "-n", "1,160p"] {
        3
    } else {
        return Err("unexpected review command structure".into());
    };
    words[path_index] = std::fs::canonicalize(&words[path_index])?
        .display()
        .to_string();
    Ok(words)
}

fn check_json_review_command(command: &str, path: &str) -> Result<(), Box<dyn std::error::Error>> {
    check_json_review_command_for_workspace(
        command,
        path,
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml"),
    )
}

fn check_json_review_command_for_workspace(
    command: &str,
    path: &str,
    workspace_manifest: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure(
        normalized_review_words_for_workspace(command, workspace_manifest)?
            == normalized_review_words_for_workspace(
                &review_json_command(path),
                workspace_manifest,
            )?,
        "unexpected JSON review command",
    )?;
    let _ = read_json(Path::new(path))?;
    Ok(())
}

fn check_text_review_command(command: &str, path: &str) -> Result<(), Box<dyn std::error::Error>> {
    ensure(
        normalized_review_words(command)?
            == normalized_review_words(&format_command(&["sed", "-n", "1,160p", path]))?,
        "unexpected text review command",
    )?;
    let expected = std::fs::read_to_string(path)?;
    // Preserve the old requirement that the displayed slice covers the whole
    // materialized artifact, rather than silently accepting truncation.
    ensure(
        expected.split_inclusive('\n').take(160).collect::<String>() == expected,
        "text review command truncates artifact",
    )
}

/// Decode only the inert quoting used by our command renderers. This is not a
/// shell evaluator: no expansion, substitution, operators, redirection or
/// control characters are accepted. Even accepted words are NEVER executed.
fn command_words(command: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    ensure(command.len() <= 65536, "command metadata is too large")?;
    let mut words = Vec::new();
    let mut word = String::new();
    let mut started = false;
    let mut quote = None;
    let mut chars = command.chars();
    while let Some(ch) = chars.next() {
        ensure(!ch.is_control(), "control character in command metadata")?;
        match quote {
            Some('\'') => {
                if ch == '\'' {
                    quote = None;
                } else {
                    word.push(ch);
                }
            }
            Some('"') => match ch {
                '"' => quote = None,
                '$' | '`' => return Err("shell expansion in command metadata".into()),
                '\\' => {
                    let escaped = chars.next().ok_or("unfinished command escape")?;
                    ensure(
                        matches!(escaped, '"' | '\\' | '$' | '`'),
                        "unsupported quoted escape",
                    )?;
                    word.push(escaped);
                }
                _ => word.push(ch),
            },
            None => match ch {
                ' ' => {
                    if started {
                        words.push(std::mem::take(&mut word));
                        started = false;
                    }
                }
                '\'' | '"' => {
                    quote = Some(ch);
                    started = true;
                }
                '\\' => {
                    let escaped = chars.next().ok_or("unfinished command escape")?;
                    ensure(!escaped.is_control(), "control character in command escape")?;
                    word.push(escaped);
                    started = true;
                }
                ';' | '&' | '|' | '<' | '>' | '(' | ')' | '$' | '`' | '#' | '~' | '*' | '?'
                | '[' | ']' | '{' | '}' => return Err("shell syntax in command metadata".into()),
                _ => {
                    word.push(ch);
                    started = true;
                }
            },
            _ => unreachable!(),
        }
    }
    ensure(quote.is_none(), "unfinished command quote")?;
    if started {
        words.push(word);
    }
    ensure(
        !words.is_empty() && words.len() <= 256,
        "invalid command word count",
    )?;
    Ok(words)
}

fn assert_path_hint_in_output(path: &str, output: &str) -> Result<(), Box<dyn std::error::Error>> {
    if output.contains(path) {
        return Ok(());
    }
    let resolved = canonical_string(path)?;
    ensure(output.contains(&resolved), "path hint missing from output")
}

fn check_path_eq(left: &str, right: &str, label: &str) -> Result<(), Box<dyn std::error::Error>> {
    ensure(canonical_string(left)? == canonical_string(right)?, label)
}

fn canonical_string(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(std::fs::canonicalize(path.trim_matches(['\'', '"']))?
        .display()
        .to_string())
}

fn extract_dry_run_rerun_command(output: &str) -> Result<&str, Box<dyn std::error::Error>> {
    extract_dry_run_value(output, "[dry-run] rerun command: ")
}

fn extract_dry_run_value<'a>(
    output: &'a str,
    prefix: &str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    output
        .lines()
        .find_map(|line| line.strip_prefix(prefix))
        .ok_or_else(|| format!("dry-run output missing prefix: {prefix}").into())
}

fn extract_summary_value<'a>(
    summary: &'a str,
    prefix: &str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    let value = summary
        .lines()
        .find_map(|line| line.strip_prefix(prefix))
        .ok_or_else(|| format!("summary missing prefix: {prefix}"))?;
    Ok(value
        .strip_prefix('`')
        .and_then(|inner| inner.strip_suffix('`'))
        .unwrap_or(value))
}

fn required_str<'a>(
    payload: &'a Value,
    field: &str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    payload[field]
        .as_str()
        .ok_or_else(|| format!("required string field missing: {field}").into())
}

fn check_manifest_contract(payload: &Value) -> Result<(), Box<dyn std::error::Error>> {
    ensure(
        payload["artifact_schema"].as_str() == Some(MANIFEST_SCHEMA),
        "artifact_schema",
    )?;
    let handoff = &payload["operator_handoff"];
    ensure(
        handoff["handoff_schema"].as_str() == Some(HANDOFF_SCHEMA),
        "operator_handoff.handoff_schema",
    )?;
    ensure(
        handoff["producer"].as_str() == Some(PRODUCER),
        "operator_handoff.producer",
    )?;
    ensure(
        handoff["source_manifest_schema"] == payload["artifact_schema"],
        "operator_handoff.source_manifest_schema",
    )?;
    ensure(
        handoff["supported_product_contour"].as_str() == Some(SUPPORTED_PRODUCT_CONTOUR),
        "operator_handoff.supported_product_contour",
    )?;
    ensure(
        handoff["supported_operator_scope"].as_str() == Some(SUPPORTED_OPERATOR_SCOPE),
        "operator_handoff.supported_operator_scope",
    )?;
    check_equal(handoff, "summary_md", payload, "live_audit_summary_md")?;
    ensure(
        handoff["manifest_json"] == payload["review_targets"]["manifest_json"],
        "operator_handoff.manifest_json",
    )?;
    check_equal(
        handoff,
        "handoff_status_json",
        payload,
        "live_audit_handoff_status_json",
    )?;
    check_equal(
        handoff,
        "acceptance_overview",
        payload,
        "acceptance_overview",
    )?;
    check_equal(handoff, "review_targets", payload, "review_targets")?;
    check_equal(handoff, "next_action", payload, "next_action")?;
    check_equal(
        handoff,
        "next_action_context",
        payload,
        "next_action_context",
    )?;

    let wire = &handoff["layer_status"]["wire"];
    check_equal(
        wire,
        "product_verdict",
        payload,
        "wire_host_acceptance_product_verdict",
    )?;
    check_equal(
        wire,
        "acceptance_status",
        payload,
        "wire_host_acceptance_status",
    )?;
    check_equal(
        wire,
        "hostile_path_support_ready",
        payload,
        "wire_host_acceptance_hostile_path_ready",
    )?;
    check_equal(
        wire,
        "independent_witness_correlation_status",
        payload,
        "wire_host_acceptance_witness_correlation_status",
    )?;

    let stealth = &handoff["layer_status"]["stealth"];
    check_equal(
        stealth,
        "bundle_verdict",
        payload,
        "stealth_live_acceptance_bundle_verdict",
    )?;
    check_equal(
        stealth,
        "bundle_status",
        payload,
        "stealth_live_acceptance_bundle_status",
    )?;
    check_equal(
        stealth,
        "primary_blocker",
        payload,
        "stealth_live_acceptance_primary_blocker",
    )?;
    check_equal(
        stealth,
        "active_blockers",
        payload,
        "stealth_live_acceptance_active_blockers",
    )?;

    let scope = &handoff["operator_scope"];
    check_equal(scope, "output_dir", payload, "output_dir")?;
    check_equal(scope, "server_host", payload, "server_host")?;
    check_equal(scope, "client_host", payload, "client_host")?;
    check_equal(scope, "relay_address", payload, "relay_address")?;

    let commands = &handoff["handoff_commands"];
    for field in SHARED_HANDOFF_COMMAND_FIELDS {
        ensure(
            commands[*field] == payload["handoff_commands"][*field],
            &format!("handoff_commands.{field}"),
        )?;
    }
    let targets = &handoff["review_targets"];
    ensure(
        targets["handoff_status_json"] == payload["live_audit_handoff_status_json"],
        "review_targets.handoff_status_json",
    )?;
    ensure(
        targets["wire_acceptance_summary_json"] == payload["wire_host_acceptance_summary_json"],
        "review_targets.wire_acceptance_summary_json",
    )?;
    ensure(
        targets["stealth_live_acceptance_bundle_json"]
            == payload["stealth_live_acceptance_bundle_json"],
        "review_targets.stealth_live_acceptance_bundle_json",
    )?;
    ensure(
        targets["client_preflight_json"] == payload["client_preflight_json"],
        "review_targets.client_preflight_json",
    )?;
    ensure(
        targets["client_startup_probe_json"] == payload["client_startup_probe_json"],
        "review_targets.client_startup_probe_json",
    )?;
    ensure(
        targets["runtime_events_jsonl"] == payload["client_runtime_events_jsonl"],
        "review_targets.runtime_events_jsonl",
    )?;
    ensure(
        targets["wire_helper_stdout_json"] == payload["wire_host_helper_stdout_json"],
        "review_targets.wire_helper_stdout_json",
    )?;
    ensure(
        targets["wire_witness_summary_json"] == payload["wire_witness_summary_json"],
        "review_targets.wire_witness_summary_json",
    )?;
    ensure(
        targets["wire_witness_capture_pcapng"] == payload["wire_witness_capture_pcapng"],
        "review_targets.wire_witness_capture_pcapng",
    )?;
    ensure(
        targets["client_transient_relay_wire_runtime_events_jsonl"]
            == payload["client_transient_relay_wire_runtime_events_jsonl"],
        "review_targets.client_transient_relay_wire_runtime_events_jsonl",
    )?;
    ensure(
        targets["wire_helper_runtime_events_jsonl"] == payload["wire_helper_runtime_events_jsonl"],
        "review_targets.wire_helper_runtime_events_jsonl",
    )?;
    ensure(
        targets["stealth_live_acceptance_manifest_json"]
            == payload["stealth_live_acceptance_manifest_json"],
        "review_targets.stealth_live_acceptance_manifest_json",
    )?;
    ensure(
        payload["handoff_commands"]["next_action_command"] == payload["next_action"]["command"],
        "handoff_commands.next_action_command",
    )?;
    ensure(
        payload["next_action_artifact"] == payload["next_action"]["artifact"],
        "next_action_artifact",
    )?;
    Ok(())
}

fn check_summary_contract(payload: &Value) -> Result<(), Box<dyn std::error::Error>> {
    let path = payload["live_audit_summary_md"]
        .as_str()
        .ok_or("live_audit_summary_md missing")?;
    let summary = std::fs::read_to_string(path)?;
    ensure(
        summary.starts_with("# Linux Wide Mimicry Live Audit\n"),
        "summary heading",
    )?;
    let handoff = &payload["operator_handoff"];
    let primary_blocker = payload["stealth_live_acceptance_primary_blocker"]
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("none");
    for expected in [
        format!("- Relay address: `{}`", s(&payload["relay_address"])),
        format!(
            "- Acceptance overall status: `{}`",
            s(&payload["acceptance_overview"]["overall_status"])
        ),
        format!(
            "- Acceptance next action: `{}`",
            s(&payload["acceptance_overview"]["overall_next_action"])
        ),
        format!(
            "- Acceptance primary layer: `{}`",
            s(&payload["acceptance_overview"]["primary_layer"])
        ),
        format!(
            "- Wire verdict/status: `{}` / `{}`",
            s(&payload["wire_host_acceptance_product_verdict"]),
            s(&payload["wire_host_acceptance_status"])
        ),
        format!(
            "- Wire witness correlation: `{}`",
            s(&payload["wire_host_acceptance_witness_correlation_status"])
        ),
        format!(
            "- Stealth verdict/status: `{}` / `{}`",
            s(&payload["stealth_live_acceptance_bundle_verdict"]),
            s(&payload["stealth_live_acceptance_bundle_status"])
        ),
        format!("- Stealth primary blocker: `{primary_blocker}`"),
        format!("- Handoff schema: `{}`", s(&handoff["handoff_schema"])),
        format!("- Handoff producer: `{}`", s(&handoff["producer"])),
        format!(
            "- Handoff contour/scope: `{} / {}`",
            s(&handoff["supported_product_contour"]),
            s(&handoff["supported_operator_scope"])
        ),
        format!(
            "- Output dir: `{}`",
            s(&handoff["operator_scope"]["output_dir"])
        ),
        format!(
            "- Server host: `{}`",
            s(&handoff["operator_scope"]["server_host"])
        ),
        format!(
            "- Client host: `{}`",
            s(&handoff["operator_scope"]["client_host"])
        ),
        format!(
            "- Acceptance overview: `status={}; next={}; layer={}`",
            s(&handoff["acceptance_overview"]["overall_status"]),
            s(&handoff["acceptance_overview"]["overall_next_action"]),
            s(&handoff["acceptance_overview"]["primary_layer"])
        ),
        format!(
            "- Layer status: `wire={}/{}; stealth={}/{}`",
            s(&handoff["layer_status"]["wire"]["product_verdict"]),
            s(&handoff["layer_status"]["wire"]["acceptance_status"]),
            s(&handoff["layer_status"]["stealth"]["bundle_verdict"]),
            s(&handoff["layer_status"]["stealth"]["bundle_status"])
        ),
        format!("- Summary artifact: `{}`", s(&handoff["summary_md"])),
        format!("- Manifest artifact: `{}`", s(&handoff["manifest_json"])),
        format!(
            "- Handoff status artifact: `{}`",
            s(&handoff["handoff_status_json"])
        ),
        format!("- Next action id: `{}`", s(&handoff["next_action"]["id"])),
        format!(
            "- Next action reason: `{}`",
            s(&handoff["next_action"]["reason"])
        ),
        format!(
            "- Next action command: `{}`",
            s(&handoff["next_action"]["command"])
        ),
        format!(
            "- Next action artifact: `{}`",
            s(&handoff["next_action"]["artifact"])
        ),
        format!(
            "- Next action context: `layer={}; wire={}/{}; stealth={}/{}; blocker={}`",
            s(&handoff["next_action_context"]["primary_layer"]),
            s(&handoff["next_action_context"]["wire_verdict"]),
            s(&handoff["next_action_context"]["wire_status"]),
            s(&handoff["next_action_context"]["stealth_verdict"]),
            s(&handoff["next_action_context"]["stealth_status"]),
            s_or_none(&handoff["next_action_context"]["primary_blocker_id"])
        ),
        format!(
            "- `live-audit.manifest.json`: `{}`",
            s(&payload["review_targets"]["manifest_json"])
        ),
        format!(
            "- `live-audit-handoff-status.json`: `{}`",
            s(&payload["live_audit_handoff_status_json"])
        ),
        format!(
            "- `preflight.json`: `{}`",
            s(&payload["client_preflight_json"])
        ),
        format!(
            "- `startup-probe.json`: `{}`",
            s(&payload["client_startup_probe_json"])
        ),
        format!(
            "- `transient-relay-wire-runtime-events.jsonl`: `{}`",
            s(&payload["client_transient_relay_wire_runtime_events_jsonl"])
        ),
        format!(
            "- `wire-helper-runtime-events.jsonl`: `{}`",
            s(&payload["wire_helper_runtime_events_jsonl"])
        ),
        format!(
            "- `wire-host-acceptance-summary.json`: `{}`",
            s(&payload["wire_host_acceptance_summary_json"])
        ),
        format!(
            "- `stealth-live-acceptance-bundle.json`: `{}`",
            s(&payload["stealth_live_acceptance_bundle_json"])
        ),
        format!(
            "- `stealth-live-acceptance.manifest.json`: `{}`",
            s(&payload["stealth_live_acceptance_manifest_json"])
        ),
    ] {
        ensure(
            summary.contains(&expected),
            &format!("summary missing {expected}"),
        )?;
    }

    let commands = &payload["handoff_commands"];
    for field in SHARED_HANDOFF_COMMAND_FIELDS {
        if *field == "review_witness_summary_command" && commands[*field].is_null() {
            ensure(
                !summary.contains("Review witness summary command"),
                "summary unexpected witness command",
            )?;
            continue;
        }
        let label = field
            .strip_prefix("review_")
            .unwrap_or(field)
            .replace('_', " ");
        let expected = format!("- Review {label}: `{}`", s(&commands[*field]));
        if *field == "rerun_command" {
            ensure(
                summary.contains(&format!("- Rerun command: `{}`", s(&commands[*field]))),
                "summary missing rerun command",
            )?;
        } else {
            ensure(
                summary.contains(&expected),
                &format!("summary missing {field}"),
            )?;
        }
    }
    Ok(())
}

const SHARED_HANDOFF_COMMAND_FIELDS: &[&str] = &[
    "rerun_command",
    "review_summary_command",
    "review_manifest_command",
    "review_handoff_status_command",
    "review_preflight_command",
    "review_startup_probe_command",
    "review_wire_helper_stdout_command",
    "review_witness_summary_command",
    "review_wire_acceptance_command",
    "review_stealth_bundle_command",
    "review_stealth_manifest_command",
    "review_runtime_events_command",
    "review_transient_runtime_events_command",
    "review_wire_helper_runtime_events_command",
];

fn check_equal(
    left: &Value,
    left_key: &str,
    right: &Value,
    right_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure(
        left[left_key] == right[right_key],
        &format!("{left_key} != {right_key}"),
    )
}

fn ensure(ok: bool, label: &str) -> Result<(), Box<dyn std::error::Error>> {
    if ok {
        Ok(())
    } else {
        Err(format!("linux live-audit manifest contract failed: {label}").into())
    }
}

fn require_field<'a>(
    mapping: &'a serde_json::Map<String, Value>,
    path: &str,
    field: &str,
) -> Result<&'a Value, Box<dyn std::error::Error>> {
    mapping
        .get(field)
        .filter(|value| !value.is_null())
        .ok_or_else(|| format!("{path} missing required field: {field}").into())
}

fn require_mapping<'a>(
    mapping: &'a serde_json::Map<String, Value>,
    path: &str,
    field: &str,
) -> Result<&'a serde_json::Map<String, Value>, Box<dyn std::error::Error>> {
    let value = require_field(mapping, path, field)?;
    value
        .as_object()
        .ok_or_else(|| format!("{path}.{field} must be an object").into())
}

fn require_command_targets_path(
    command: &str,
    target: &str,
    command_field: &str,
    target_field: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let target = target.trim_matches(['\'', '"']);
    let matches_target = command
        .split_whitespace()
        .map(|token| token.trim_matches(['\'', '"']))
        .any(|token| token == target);
    ensure(
        matches_target,
        &format!("{command_field} does not reference {target_field}"),
    )
}

fn summary_markdown(payload: &Value) -> String {
    let operator_handoff = &payload["operator_handoff"];
    let operator_scope = &operator_handoff["operator_scope"];
    let acceptance = &operator_handoff["acceptance_overview"];
    let layer_status = &operator_handoff["layer_status"];
    let next_action = &operator_handoff["next_action"];
    let next_action_context = &operator_handoff["next_action_context"];
    let commands = &operator_handoff["handoff_commands"];
    let targets = &operator_handoff["review_targets"];
    let primary_blocker_id = payload["stealth_live_acceptance_primary_blocker"]
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("none");

    let mut lines = vec![
        "# Linux Wide Mimicry Live Audit".to_string(),
        "".to_string(),
        format!("- Relay address: `{}`", s(&operator_scope["relay_address"])),
        format!(
            "- Acceptance overall status: `{}`",
            s(&acceptance["overall_status"])
        ),
        format!(
            "- Acceptance next action: `{}`",
            s(&acceptance["overall_next_action"])
        ),
        format!(
            "- Acceptance primary layer: `{}`",
            s(&acceptance["primary_layer"])
        ),
        format!(
            "- Wire verdict/status: `{}` / `{}`",
            s(&payload["wire_host_acceptance_product_verdict"]),
            s(&payload["wire_host_acceptance_status"])
        ),
        format!(
            "- Wire witness correlation: `{}`",
            s(&payload["wire_host_acceptance_witness_correlation_status"])
        ),
        format!(
            "- Stealth verdict/status: `{}` / `{}`",
            s(&payload["stealth_live_acceptance_bundle_verdict"]),
            s(&payload["stealth_live_acceptance_bundle_status"])
        ),
        format!("- Stealth primary blocker: `{primary_blocker_id}`"),
        "".to_string(),
        "## Replay Hints".to_string(),
        "".to_string(),
        format!("- Rerun command: `{}`", s(&commands["rerun_command"])),
        format!(
            "- Review summary command: `{}`",
            s(&commands["review_summary_command"])
        ),
        format!(
            "- Review manifest command: `{}`",
            s(&commands["review_manifest_command"])
        ),
        format!(
            "- Review handoff status command: `{}`",
            s(&commands["review_handoff_status_command"])
        ),
        format!(
            "- Review preflight command: `{}`",
            s(&commands["review_preflight_command"])
        ),
        format!(
            "- Review startup probe command: `{}`",
            s(&commands["review_startup_probe_command"])
        ),
        format!(
            "- Review wire helper stdout command: `{}`",
            s(&commands["review_wire_helper_stdout_command"])
        ),
    ];
    if !commands["review_witness_summary_command"].is_null() {
        lines.push(format!(
            "- Review witness summary command: `{}`",
            s(&commands["review_witness_summary_command"])
        ));
    }
    lines.extend([
        format!(
            "- Review wire acceptance command: `{}`",
            s(&commands["review_wire_acceptance_command"])
        ),
        format!(
            "- Review stealth bundle command: `{}`",
            s(&commands["review_stealth_bundle_command"])
        ),
        format!(
            "- Review stealth manifest command: `{}`",
            s(&commands["review_stealth_manifest_command"])
        ),
        format!(
            "- Review runtime events command: `{}`",
            s(&commands["review_runtime_events_command"])
        ),
        format!(
            "- Review transient runtime events command: `{}`",
            s(&commands["review_transient_runtime_events_command"])
        ),
        format!(
            "- Review wire helper runtime events command: `{}`",
            s(&commands["review_wire_helper_runtime_events_command"])
        ),
        "".to_string(),
        "## Operator Handoff".to_string(),
        "".to_string(),
        format!(
            "- Handoff schema: `{}`",
            s(&operator_handoff["handoff_schema"])
        ),
        format!("- Handoff producer: `{}`", s(&operator_handoff["producer"])),
        format!(
            "- Handoff contour/scope: `{} / {}`",
            s(&operator_handoff["supported_product_contour"]),
            s(&operator_handoff["supported_operator_scope"])
        ),
        format!("- Output dir: `{}`", s(&operator_scope["output_dir"])),
        format!("- Server host: `{}`", s(&operator_scope["server_host"])),
        format!("- Client host: `{}`", s(&operator_scope["client_host"])),
        format!("- Relay address: `{}`", s(&operator_scope["relay_address"])),
        format!(
            "- Acceptance overview: `status={}; next={}; layer={}`",
            s(&acceptance["overall_status"]),
            s(&acceptance["overall_next_action"]),
            s(&acceptance["primary_layer"])
        ),
        format!(
            "- Layer status: `wire={}/{}; stealth={}/{}`",
            s(&layer_status["wire"]["product_verdict"]),
            s(&layer_status["wire"]["acceptance_status"]),
            s(&layer_status["stealth"]["bundle_verdict"]),
            s(&layer_status["stealth"]["bundle_status"])
        ),
        format!(
            "- Summary artifact: `{}`",
            s(&operator_handoff["summary_md"])
        ),
        format!(
            "- Manifest artifact: `{}`",
            s(&operator_handoff["manifest_json"])
        ),
        format!(
            "- Handoff status artifact: `{}`",
            s(&operator_handoff["handoff_status_json"])
        ),
        format!("- Next action id: `{}`", s(&next_action["id"])),
        format!("- Next action reason: `{}`", s(&next_action["reason"])),
        format!("- Next action command: `{}`", s(&next_action["command"])),
        format!("- Next action artifact: `{}`", s(&next_action["artifact"])),
        format!(
            "- Next action context: `layer={}; wire={}/{}; stealth={}/{}; blocker={}`",
            s(&next_action_context["primary_layer"]),
            s(&next_action_context["wire_verdict"]),
            s(&next_action_context["wire_status"]),
            s(&next_action_context["stealth_verdict"]),
            s(&next_action_context["stealth_status"]),
            s_or_none(&next_action_context["primary_blocker_id"])
        ),
        "".to_string(),
        "## Key Artifacts".to_string(),
        "".to_string(),
        format!(
            "- `live-audit.manifest.json`: `{}`",
            s(&operator_handoff["manifest_json"])
        ),
        format!(
            "- `live-audit-handoff-status.json`: `{}`",
            s(&operator_handoff["handoff_status_json"])
        ),
        format!(
            "- `preflight.json`: `{}`",
            s(&targets["client_preflight_json"])
        ),
        format!(
            "- `startup-probe.json`: `{}`",
            s(&targets["client_startup_probe_json"])
        ),
        format!(
            "- `transient-relay-wire-runtime-events.jsonl`: `{}`",
            s(&targets["client_transient_relay_wire_runtime_events_jsonl"])
        ),
        format!(
            "- `wire-helper-runtime-events.jsonl`: `{}`",
            s(&targets["wire_helper_runtime_events_jsonl"])
        ),
        format!(
            "- `wire-host-acceptance-summary.json`: `{}`",
            s(&targets["wire_acceptance_summary_json"])
        ),
        format!(
            "- `stealth-live-acceptance-bundle.json`: `{}`",
            s(&targets["stealth_live_acceptance_bundle_json"])
        ),
        format!(
            "- `stealth-live-acceptance.manifest.json`: `{}`",
            s(&targets["stealth_live_acceptance_manifest_json"])
        ),
    ]);
    lines.join("\n") + "\n"
}

fn s(value: &Value) -> String {
    value
        .as_str()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| value.to_string())
}

fn s_or_none(value: &Value) -> String {
    value
        .as_str()
        .filter(|value| !value.is_empty())
        .unwrap_or("none")
        .to_string()
}

fn lower_str(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_lowercase()
}

fn str_or(value: &Value, key: &str, default: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or(default)
        .to_string()
}

fn none_if_empty(value: &str) -> Value {
    if value.is_empty() {
        Value::Null
    } else {
        json!(value)
    }
}

fn format_command(parts: &[&str]) -> String {
    parts
        .iter()
        .filter(|part| !part.is_empty())
        .map(|part| shell_quote(part))
        .collect::<Vec<_>>()
        .join(" ")
}

fn review_json_command(path: &str) -> String {
    format_command(&[
        "cargo",
        "run",
        "-q",
        "-p",
        "aegis-measure",
        "--",
        "pretty-json",
        "--input",
        path,
    ])
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || "_@%+=:./-".contains(ch))
    {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}
