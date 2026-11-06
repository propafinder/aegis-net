use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::artifact::{write_json, write_text};

/// Installation input metadata. A URL record path belongs to the target client;
/// this planner never opens its contents or acquires any bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BundleInput {
    Bundle { path: String },
    UrlFile { path: String },
}

fn refused_bundle_input() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "opaque bundle input refused",
    )
}

impl BundleInput {
    pub fn from_paths(
        bundle: Option<&Path>,
        url_file: Option<&Path>,
    ) -> Result<Self, std::io::Error> {
        let input = match (bundle, url_file) {
            (Some(_), Some(_)) => return Err(refused_bundle_input()),
            (None, None) => Self::Bundle {
                path: "/tmp/client-bundle.tar.gz".to_string(),
            },
            (Some(path), None) => Self::Bundle {
                path: path.to_str().ok_or_else(refused_bundle_input)?.to_string(),
            },
            (None, Some(path)) => Self::UrlFile {
                path: path.to_str().ok_or_else(refused_bundle_input)?.to_string(),
            },
        };
        input.validate()?;
        Ok(input)
    }

    pub fn from_artifact(value: &Value) -> Result<Self, std::io::Error> {
        // Legacy raw URL records are refused before the next writer runs.
        // Static errors do not reflect a rejected record or private value.
        if value
            .get("bundle_url_example")
            .is_some_and(|raw| !raw.is_null())
        {
            return Err(refused_bundle_input());
        }
        let raw = value.get("bundle_input").ok_or_else(refused_bundle_input)?;
        let input: Self =
            serde_json::from_value(raw.clone()).map_err(|_| refused_bundle_input())?;
        input.validate()?;
        Ok(input)
    }

    pub fn validate(&self) -> Result<(), std::io::Error> {
        let path = match self {
            Self::Bundle { path } | Self::UrlFile { path } => path,
        };
        if path.is_empty() || path.chars().any(char::is_control) || path.contains("://") {
            return Err(refused_bundle_input());
        }
        // This is an Ubuntu target pathname, irrespective of this planner's
        // host OS. Match the destination reader's absolute-path contract
        // without inspecting its remote filesystem or contents.
        if matches!(self, Self::UrlFile { .. }) && !path.starts_with('/') {
            return Err(refused_bundle_input());
        }
        Ok(())
    }

    fn installer_command(&self) -> String {
        let (flag, path) = match self {
            Self::Bundle { path } => ("--bundle", path),
            Self::UrlFile { path } => ("--bundle-url-file", path),
        };
        format!("./bootstrap-install.sh client {flag} {}", shell_quote(path))
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub fn build_ubuntu_controlled_pilot_playbook(
    output_dir: &Path,
    relay_host: &str,
    client_host: &str,
    blocked_shape: &str,
    bundle_input: &BundleInput,
) -> Result<(), Box<dyn std::error::Error>> {
    bundle_input.validate()?;
    let playbook = json!({
        "artifact_schema": "ubuntu_controlled_pilot_playbook_v1",
        "supported_product_contour": "ubuntu_first_controlled_pilot",
        "supported_operator_scope": "ubuntu_release_evidence_collection",
        "relay_host_label": relay_host,
        "client_host_label": client_host,
        "blocked_shape_label": blocked_shape,
        "bundle_url_example": null,
        "bundle_input": bundle_input,
        "pilot_gate_rules": {
            "green": "relay service active, client preflight/startup/runtime/operator evidence all healthy, baseline Ubuntu bypass proof is present",
            "fully_proven": "green plus blocked-shape evidence, correlated independent witness and green wire acceptance",
            "degraded": "pilot runs but release/runtime/hostile-path evidence remains incomplete without terminal startup failure",
            "red": "service/startup/operator surfaces fail or baseline bypass proof is missing",
        },
        "rollout_acceptance": {
            "must_pass_checks": [
                {"id": "server_service_active", "rule": "aegis-server.service must be active on the relay host"},
                {"id": "server_journal_present", "rule": "server journal evidence must be collected for the rollout window"},
                {"id": "client_preflight_ok", "rule": "client preflight must return status=ok"},
                {"id": "client_startup_probe_ok", "rule": "client startup probe must return status=ok"},
                {"id": "client_runtime_summary_healthy", "rule": "client runtime summary must stay healthy"},
                {"id": "client_operator_verdict_green", "rule": "client operator evidence must stay green"},
                {"id": "baseline_bypass_ready", "rule": "baseline Ubuntu bypass proof must be present for the pilot window"},
                {"id": "runtime_degradation_count_zero", "rule": "runtime_degradation_count must stay zero during the accepted pilot window"},
                {"id": "failover_count_zero", "rule": "failover_count must stay zero during the accepted pilot window"},
                {"id": "terminal_failure_count_zero", "rule": "terminal_failure_count must stay zero during the accepted pilot window"},
            ],
            "advisory_checks": [
                {"id": "dns_runtime_ready_when_requested", "rule": "if the selected pilot profile requests DNS support, DNS runtime evidence should also be ready"},
                {"id": "hostile_path_ready", "rule": "blocked-shape hostile-path evidence should be present for stronger pilot confidence"},
                {"id": "fully_proven", "rule": "correlated witness plus green wire acceptance upgrades the pilot to fully_proven"},
            ],
        },
        "required_release_artifacts": [
            "validation-summary.json",
            "ubuntu-release-gate-handoff.json",
            "ubuntu-product-release-summary.json",
            "ubuntu-controlled-pilot-inputs.json",
            "ubuntu-operator-reapply-canary.json",
            "field-pilot-remote-bundle.json",
            "runtime/client-operator-loop-summary.json",
            "runtime/client-operator-evidence.json",
            "optional wire-witness-summary.json",
            "optional wire-host-acceptance-summary.json",
        ],
        "steps": [
            {"host": relay_host, "phase": "server_install", "command": "./bootstrap-install.sh server --relay-address relay.example.org:8443 --server-name relay.example.org"},
            {"host": relay_host, "phase": "server_runtime", "command": "sudo systemctl daemon-reload && sudo systemctl enable --now aegis-server.service && sudo systemctl status --no-pager aegis-server.service"},
            {"host": relay_host, "phase": "bundle_handoff", "command": format!("scp /etc/aegis/server/client-bundle.tar.gz {client_host}:/tmp/client-bundle.tar.gz")},
            {"host": client_host, "phase": "client_install", "command": bundle_input.installer_command()},
            {"host": client_host, "phase": "client_validation", "command": "sudo env HOME=\"$HOME\" PATH=\"$HOME/.cargo/bin:$PATH\" ./scripts/validate-debian-package-host.sh --run --artifact-dir ./dist/ubuntu-release"},
            {"host": client_host, "phase": "operator_canary", "command": "./scripts/build-ubuntu-operator-reapply-canary.sh ./dist/ubuntu-operator-canary --pilot-inputs ./dist/ubuntu-release/ubuntu-controlled-pilot-inputs.json"},
            {"host": client_host, "phase": "pilot_bundle", "command": "./scripts/build-ubuntu-controlled-pilot-bundle.sh ./dist/ubuntu-pilot --pilot-inputs ./dist/ubuntu-release/ubuntu-controlled-pilot-inputs.json"},
            {"host": client_host, "phase": "release_review", "command": "./scripts/build-ubuntu-release-review.sh ./dist/ubuntu-review --release-summary ./dist/ubuntu-release/ubuntu-product-release-summary.json --pilot-bundle ./dist/ubuntu-pilot/pilot-summary.json"},
            {"host": client_host, "phase": "release_wave_bundle", "command": "./scripts/build-ubuntu-release-wave-bundle.sh ./dist/ubuntu-wave --pilot-inputs ./dist/ubuntu-release/ubuntu-controlled-pilot-inputs.json"},
            {"host": client_host, "phase": "field_pilot_remote_bundle", "command": "./scripts/build-ubuntu-field-pilot-remote-bundle.sh ./dist/ubuntu-field-pilot-remote --pilot-inputs ./dist/ubuntu-release/ubuntu-controlled-pilot-inputs.json"},
        ],
    });

    write_json(&output_dir.join("pilot-playbook.json"), &playbook)?;
    write_text(
        &output_dir.join("pilot-playbook.md"),
        &render_markdown(&playbook),
    )?;
    Ok(())
}

fn render_markdown(playbook: &Value) -> String {
    let mut lines = vec![
        "# Ubuntu Controlled Pilot Playbook".to_string(),
        String::new(),
        format!(
            "- Relay host: `{}`",
            playbook["relay_host_label"].as_str().unwrap_or("")
        ),
        format!(
            "- Client host: `{}`",
            playbook["client_host_label"].as_str().unwrap_or("")
        ),
        format!(
            "- Blocked shape: `{}`",
            playbook["blocked_shape_label"].as_str().unwrap_or("")
        ),
        format!(
            "- Bundle input (opaque pathname): `{}`",
            playbook["bundle_input"]["path"].as_str().unwrap_or("")
        ),
        String::new(),
        "## Gate Rules".to_string(),
        String::new(),
        format!(
            "- `green`: {}",
            playbook["pilot_gate_rules"]["green"].as_str().unwrap_or("")
        ),
        format!(
            "- `degraded`: {}",
            playbook["pilot_gate_rules"]["degraded"]
                .as_str()
                .unwrap_or("")
        ),
        format!(
            "- `red`: {}",
            playbook["pilot_gate_rules"]["red"].as_str().unwrap_or("")
        ),
        String::new(),
        "## Must-Pass Checks".to_string(),
        String::new(),
    ];
    append_id_rule_list(
        &mut lines,
        &playbook["rollout_acceptance"]["must_pass_checks"],
    );
    lines.extend([
        String::new(),
        "## Advisory Checks".to_string(),
        String::new(),
    ]);
    append_id_rule_list(
        &mut lines,
        &playbook["rollout_acceptance"]["advisory_checks"],
    );
    lines.extend([
        String::new(),
        "## Required Release Artifacts".to_string(),
        String::new(),
    ]);
    if let Some(artifacts) = playbook["required_release_artifacts"].as_array() {
        for artifact in artifacts {
            lines.push(format!("- `{}`", artifact.as_str().unwrap_or("")));
        }
    }
    lines.extend([String::new(), "## Steps".to_string(), String::new()]);
    if let Some(steps) = playbook["steps"].as_array() {
        for step in steps {
            lines.push(format!(
                "- `{}` on `{}`: `{}`",
                step["phase"].as_str().unwrap_or(""),
                step["host"].as_str().unwrap_or(""),
                step["command"].as_str().unwrap_or("")
            ));
        }
    }
    lines.join("\n") + "\n"
}

fn append_id_rule_list(lines: &mut Vec<String>, items: &Value) {
    if let Some(items) = items.as_array() {
        for item in items {
            lines.push(format!(
                "- `{}`: {}",
                item["id"].as_str().unwrap_or(""),
                item["rule"].as_str().unwrap_or("")
            ));
        }
    }
}

#[cfg(test)]
mod bundle_input_tests {
    use super::*;

    fn json_file(dir: &Path, name: &str, value: Value) -> std::path::PathBuf {
        let path = dir.join(name);
        write_json(&path, &value).unwrap();
        path
    }

    #[test]
    fn actual_default_archive_matches_existing_handoff() {
        let dir = tempfile::tempdir().unwrap();
        let input = BundleInput::from_paths(None, None).unwrap();
        build_ubuntu_controlled_pilot_playbook(dir.path(), "relay", "client", "shape", &input)
            .unwrap();
        let value: Value =
            crate::artifact::read_json(&dir.path().join("pilot-playbook.json")).unwrap();
        assert_eq!(value["bundle_url_example"], Value::Null);
        assert_eq!(
            value["bundle_input"],
            json!({"kind":"bundle","path":"/tmp/client-bundle.tar.gz"})
        );
        let steps = value["steps"].as_array().unwrap();
        let install = steps
            .iter()
            .find(|step| step["phase"] == "client_install")
            .unwrap();
        assert_eq!(
            install["command"],
            "./bootstrap-install.sh client --bundle '/tmp/client-bundle.tar.gz'"
        );
        assert!(steps
            .iter()
            .find(|step| step["phase"] == "bundle_handoff")
            .unwrap()["command"]
            .as_str()
            .unwrap()
            .contains(":/tmp/client-bundle.tar.gz"));
        assert_eq!(
            value["rollout_acceptance"]["must_pass_checks"][0]["id"],
            "server_service_active"
        );
    }

    #[test]
    fn actual_remote_private_path_is_not_opened_and_is_shell_quoted() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::path::PathBuf::from(format!(
            "/remote/{} missing record ' spaced",
            dir.path().file_name().unwrap().to_string_lossy()
        ));
        assert!(!path.exists());
        let input = BundleInput::from_paths(None, Some(&path)).unwrap();
        build_ubuntu_controlled_pilot_playbook(dir.path(), "relay", "client", "shape", &input)
            .unwrap();
        let value: Value =
            crate::artifact::read_json(&dir.path().join("pilot-playbook.json")).unwrap();
        assert_eq!(value["bundle_url_example"], Value::Null);
        assert_eq!(value["bundle_input"]["kind"], "url_file");
        assert_eq!(value["bundle_input"]["path"], path.to_str().unwrap());
        assert!(!path.exists());
        assert!(input.installer_command().contains("'\\''"));
        assert!(input
            .installer_command()
            .starts_with("./bootstrap-install.sh client --bundle-url-file '"));
    }

    #[test]
    fn artifact_record_requires_exact_typed_shape_and_legacy_null() {
        let valid = json!({"bundle_url_example":null,"bundle_input":{"kind":"url_file","path":"/remote/access-url"}});
        let typed = BundleInput::from_artifact(&valid).unwrap();
        assert_eq!(serde_json::to_value(&typed).unwrap(), valid["bundle_input"]);
        for invalid in [
            json!({"bundle_url_example":"PRIVATE_URL","bundle_input":{"kind":"url_file","path":"/remote/access-url"}}),
            json!({"bundle_url_example":null}),
            json!({"bundle_input":{"kind":"url_file","path":"/remote/access-url","extra":"PRIVATE_VALUE"}}),
            json!({"bundle_input":{"kind":"raw_url","path":"https://fixture.invalid/PRIVATE_VALUE"}}),
            json!({"bundle_input":{"kind":"url_file","path":"relative-path"}}),
            json!({"bundle_input":{"kind":"bundle","path":"file:///private/PRIVATE_VALUE"}}),
            json!({"bundle_input":{"kind":"bundle","path":"/private/path\nPRIVATE_VALUE"}}),
        ] {
            let error = BundleInput::from_artifact(&invalid).unwrap_err();
            assert_eq!(error.to_string(), "opaque bundle input refused");
        }
        assert!(BundleInput::from_paths(Some(Path::new("archive.tar.gz")), None).is_ok());
        assert!(BundleInput::from_paths(
            Some(Path::new("archive.tar.gz")),
            Some(Path::new("/private/access-url"))
        )
        .is_err());
    }

    #[test]
    fn actual_review_and_remote_consumers_preserve_typed_input() {
        let dir = tempfile::tempdir().unwrap();
        let input =
            BundleInput::from_paths(None, Some(Path::new("/remote/missing private record")))
                .unwrap();
        let playbook_dir = dir.path().join("playbook");
        build_ubuntu_controlled_pilot_playbook(&playbook_dir, "relay", "client", "shape", &input)
            .unwrap();
        let pilot_inputs = json_file(
            dir.path(),
            "inputs.json",
            json!({"release_summary_json":"/opaque/release.json"}),
        );
        let canary = json_file(
            dir.path(),
            "canary.json",
            json!({"operator_canary_verdict":"green"}),
        );
        let pilot = json_file(
            dir.path(),
            "pilot.json",
            json!({"pilot_verdict":"green","bypass_ready":true}),
        );
        let review = json_file(
            dir.path(),
            "review.json",
            json!({"ship_decision":"ship","fully_proven":true,"bypass_ready":true}),
        );
        let review_dir = dir.path().join("review");
        crate::ubuntu_controlled_pilot_review_bundle::build_ubuntu_controlled_pilot_review_bundle_manifest(
            &review_dir, &pilot_inputs, &playbook_dir.join("pilot-playbook.json"), &canary, &pilot, &review, None, None, None,
        ).unwrap();
        let review_manifest = review_dir.join("pilot-review.manifest.json");
        let review_value: Value = crate::artifact::read_json(&review_manifest).unwrap();
        assert_eq!(review_value["bundle_url_example"], Value::Null);
        assert_eq!(
            review_value["bundle_input"],
            serde_json::to_value(&input).unwrap()
        );
        assert_eq!(review_value["operator_canary_verdict"], "green");
        let wave_status = json_file(
            dir.path(),
            "status.json",
            json!({"bypass_ready":true,"fully_proven":true}),
        );
        let wave_manifest = json_file(dir.path(), "wave.json", json!({}));
        let remote_dir = dir.path().join("remote");
        crate::ubuntu_field_pilot_remote_bundle::build_ubuntu_field_pilot_remote_bundle_manifest(
            &remote_dir,
            &pilot_inputs,
            &review_manifest,
            &wave_status,
            &wave_manifest,
        )
        .unwrap();
        let remote: Value =
            crate::artifact::read_json(&remote_dir.join("field-pilot-remote-bundle.json")).unwrap();
        assert_eq!(remote["bundle_url_example"], Value::Null);
        assert_eq!(remote["bundle_input"], review_value["bundle_input"]);
        assert_eq!(
            remote["field_pilot_status"],
            "remote_shape_ready_for_live_evidence"
        );
        assert_eq!(remote["next_required_action"], "none");
    }

    #[test]
    fn actual_legacy_record_refuses_before_review_or_remote_output() {
        let dir = tempfile::tempdir().unwrap();
        let input = json_file(dir.path(), "inputs.json", json!({}));
        let legacy = json_file(
            dir.path(),
            "legacy.json",
            json!({"bundle_url_example":"https://fixture.invalid/?token=PRIVATE_VALUE"}),
        );
        let other = json_file(dir.path(), "other.json", json!({}));
        let review_dir = dir.path().join("review-output");
        let error = crate::ubuntu_controlled_pilot_review_bundle::build_ubuntu_controlled_pilot_review_bundle_manifest(
            &review_dir, &input, &legacy, &other, &other, &other, None, None, None,
        ).unwrap_err();
        assert_eq!(error.to_string(), "opaque bundle input refused");
        assert!(!review_dir.exists());
        let remote_dir = dir.path().join("remote-output");
        let error = crate::ubuntu_field_pilot_remote_bundle::build_ubuntu_field_pilot_remote_bundle_manifest(
            &remote_dir, &input, &legacy, &other, &other,
        ).unwrap_err();
        assert_eq!(error.to_string(), "opaque bundle input refused");
        assert!(!remote_dir.exists());
    }
}
