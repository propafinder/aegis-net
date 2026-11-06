use std::path::Path;

use serde_json::{json, Value};

use crate::artifact::{read_optional_json_path, write_json};

const REQUIRED_PHASES: &[&str] = &[
    "install",
    "preset_policy",
    "service_start",
    "service_restart",
    "reboot_contract",
    "remove",
    "reinstall",
    "upgrade_reapply",
    "purge",
];

const REQUIRED_RUNTIME_ARTIFACTS: &[&str] = &[
    "validation-summary.json",
    "runtime/server-systemctl-status.log",
    "runtime/client-systemctl-status.log",
    "runtime/server-journal.log",
    "runtime/client-journal.log",
    "runtime/client-preflight.json",
    "runtime/client-startup-probe.json",
    "runtime/client-runtime-events-summary.json",
];

pub fn build_ubuntu_release_gate_status(
    host_summary: Option<&Path>,
    output_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let summary = read_optional_json_path(host_summary)?;
    let mut payload = json!({
        "artifact_schema": "ubuntu_release_gate_handoff_v1",
        "release_gate_name": "ubuntu_first_product_release_gate",
        "release_gate_scope": "ubuntu_first_product_candidate",
        "required_lifecycle_phases": REQUIRED_PHASES,
        "required_runtime_artifacts": REQUIRED_RUNTIME_ARTIFACTS,
        "repo_contract_status": "passed",
        "ubuntu_host_evidence_present": false,
        "ubuntu_host_summary_path": Value::Null,
        "ship_ready": false,
        "release_readiness": "repo_green_only",
        "ship_blocker_reason": "ubuntu_host_evidence_missing",
        "next_required_action": "sudo env HOME=\"$HOME\" PATH=\"$HOME/.cargo/bin:$PATH\" bash scripts/validate-debian-package-host.sh --run",
    });

    if let (Some(summary_path), Some(summary)) = (host_summary, summary.as_ref()) {
        payload["ubuntu_host_evidence_present"] = Value::Bool(true);
        payload["ubuntu_host_summary_path"] = json!(display_path(summary_path));
        payload["required_lifecycle_phases"] = summary
            .get("required_lifecycle_phases")
            .cloned()
            .unwrap_or_else(|| json!(REQUIRED_PHASES));
        payload["required_runtime_artifacts"] = summary
            .get("required_runtime_artifacts")
            .cloned()
            .unwrap_or_else(|| json!(REQUIRED_RUNTIME_ARTIFACTS));

        let gate_passed = summary["release_gate_status"].as_str() == Some("passed");
        let ship_decision = summary["ship_decision"].as_str() == Some("ship");
        let verdict_green = summary["product_verdict"].as_str() == Some("green");
        if gate_passed && ship_decision && verdict_green {
            payload["ship_ready"] = Value::Bool(true);
            payload["release_readiness"] = json!("ship_ready");
            payload["ship_blocker_reason"] = Value::Null;
            payload["next_required_action"] = json!("none");
        } else {
            payload["ship_ready"] = Value::Bool(false);
            payload["release_readiness"] = json!("blocked");
            payload["ship_blocker_reason"] = json!("ubuntu_host_evidence_not_green");
            payload["next_required_action"] = json!("inspect_validation_summary");
        }
    }

    write_json(output_path, &payload)?;
    Ok(())
}

fn display_path(path: &Path) -> String {
    path.components()
        .collect::<std::path::PathBuf>()
        .display()
        .to_string()
}
