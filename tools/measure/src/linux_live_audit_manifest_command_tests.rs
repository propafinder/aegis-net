use super::*;

fn write_private_topology_json(path: &Path, payload: &Value) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(payload).expect("controlled topology fixture JSON");
    aegis_core::secret_file::write_private_new(path, &bytes)
}

fn fixture_expected_topology(root: &Path) -> LinuxLiveExpectedTopology {
    let path = root.join("expected-topology.json");
    if !path.exists() {
        write_private_topology_json(
            &path,
            &json!({"schema":EXPECTED_TOPOLOGY_SCHEMA,"server_host":"server.example",
                "client_host":"client.example","relay_address":"relay.example:8443"}),
        )
        .unwrap();
    }
    load_linux_live_expected_topology(&path).unwrap()
}

fn materialized_fixture(root: &Path) -> PathBuf {
    let _expected = fixture_expected_topology(root);
    let manifest = root.join("live-audit.manifest.json");
    let wire = root.join("wire.json");
    let stealth = root.join("stealth.json");
    write_json(
        &wire,
        &json!({"product_verdict":"green","acceptance_status":"passed"}),
    )
    .unwrap();
    write_json(
        &stealth,
        &json!({"bundle_verdict":"green","bundle_status":"acceptance_green"}),
    )
    .unwrap();
    let data = root.join("data.json");
    write_json(&data, &json!({})).unwrap();
    let text = root.join("events.jsonl");
    write_text(&text, "{}\n").unwrap();
    build_linux_wide_live_audit_manifest(LinuxLiveAuditManifestInputs {
        manifest: manifest.clone(),
        output_dir: root.display().to_string(),
        server_host: "server.example".into(),
        client_host: "client.example".into(),
        relay_address: "relay.example:8443".into(),
        runtime_events: text.display().to_string(),
        preflight: data.display().to_string(),
        startup_probe: data.display().to_string(),
        wire_helper_stdout: data.display().to_string(),
        witness_summary: String::new(),
        witness_pcap: String::new(),
        transient_runtime_events: text.display().to_string(),
        wire_helper_runtime_events: text.display().to_string(),
        wire_acceptance_summary: wire,
        stealth_live_acceptance_bundle: stealth,
        stealth_live_acceptance_manifest: data.display().to_string(),
        rerun_command: format_command(&[
            "bash",
            "scripts/run-linux-wide-mimicry-live-audit.sh",
            "--server-host",
            "server.example",
            "--client-host",
            "client.example",
            "--ssh-user",
            "operator",
            "--server-name",
            "relay.example",
            "--relay-address",
            "relay.example:8443",
            "--output-dir",
            &root.display().to_string(),
        ]),
        review_summary_command: format_command(&[
            "sed",
            "-n",
            "1,160p",
            &root.join("live-audit-summary.md").display().to_string(),
        ]),
        review_manifest_command: review_json_command(&manifest.display().to_string()),
        handoff_status_json: String::new(),
    })
    .unwrap();
    build_linux_wide_live_audit_handoff_status(
        &manifest,
        &root.join("live-audit-handoff-status.json"),
    )
    .unwrap();
    manifest
}

#[test]
fn external_materialized_manifest_command_never_executes_sentinel() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = materialized_fixture(tmp.path());
    let sentinel = tmp.path().join("command-executed");
    let mut payload = read_json(&manifest).unwrap();
    // Inert local exploit witness: only an owned temporary file is written.
    // The cat still produces precisely the expected JSON, so output equality
    // does not distinguish the malicious side effect from a valid review.
    let command = format!(
        "printf sentinel > {}; cat {}",
        shell_quote(&sentinel.display().to_string()),
        shell_quote(&manifest.display().to_string())
    );
    payload["handoff_commands"]["review_manifest_command"] = json!(command);
    payload["operator_handoff"]["handoff_commands"]["review_manifest_command"] = json!(command);
    write_json(&manifest, &payload).unwrap();
    build_linux_wide_live_audit_handoff_status(
        &manifest,
        &tmp.path().join("live-audit-handoff-status.json"),
    )
    .unwrap();
    let dry = tmp.path().join("dry-run.txt");
    write_text(&dry, "untrusted dry-run witness\n").unwrap();
    let result = linux_wide_live_audit_materialized_contract_check(
        &dry,
        &manifest,
        &manifest,
        &manifest,
        &manifest,
        &fixture_expected_topology(tmp.path()),
    );
    assert!(
        !sentinel.exists(),
        "external manifest command executed its sentinel side effect"
    );
    assert!(
        result.is_err(),
        "malicious materialized input must be refused"
    );
}

fn directory_contents(root: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    std::fs::read_dir(root)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let bytes = std::fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect()
}

fn dry_run_witness(payload: &Value) -> String {
    let commands = &payload["handoff_commands"];
    let targets = &payload["review_targets"];
    [
        ("rerun command: ", s(&commands["rerun_command"])),
        (
            "review summary command: ",
            s(&commands["review_summary_command"]),
        ),
        (
            "review manifest command: ",
            s(&commands["review_manifest_command"]),
        ),
        (
            "review handoff status command: ",
            s(&commands["review_handoff_status_command"]),
        ),
        ("write manifest to ", s(&targets["manifest_json"])),
        ("write summary to ", s(&targets["summary_md"])),
        (
            "write handoff status to ",
            s(&targets["handoff_status_json"]),
        ),
        (
            "manifest will link markdown summary ",
            s(&targets["summary_md"]),
        ),
        (
            "manifest will summarize wire acceptance from ",
            s(&targets["wire_acceptance_summary_json"]),
        ),
        (
            "manifest will summarize stealth bundle from ",
            s(&targets["stealth_live_acceptance_bundle_json"]),
        ),
    ]
    .map(|(label, value)| format!("[dry-run] {label}{value}\n"))
    .concat()
}

#[test]
fn generated_materialized_commands_and_status_are_checked_without_writes() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = materialized_fixture(tmp.path());
    let payload = read_json(&manifest).unwrap();
    // The old checker used this manifest-selected sibling as scratch output.
    let prior_output = tmp
        .path()
        .join("live-audit-handoff-status.regenerated.json");
    write_text(&prior_output, "preserve this existing file").unwrap();
    let before = directory_contents(tmp.path());
    check_materialized_status_contract(&payload).unwrap();
    check_review_command_contract(&payload).unwrap();
    check_rerun_command_contract(&payload).unwrap();
    check_next_action_command_contract(&payload).unwrap();
    check_next_action_identity_contract(&payload).unwrap();
    let witness = dry_run_witness(&payload);
    check_dry_run_materialized_rerun_parity(&witness, &payload).unwrap();
    check_dry_run_materialized_artifact_parity(&witness, &payload).unwrap();
    check_dry_run_materialized_review_parity(&witness, &payload).unwrap();
    check_dry_run_summary_parity(&witness, &payload).unwrap();
    assert_eq!(before, directory_contents(tmp.path()));
}

#[test]
fn review_metadata_refuses_shell_programs_and_malformed_quoting() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("data.json");
    write_json(&path, &json!({"read_only": true})).unwrap();
    let path = path.to_str().unwrap();
    let valid = review_json_command(path);
    for command in [
        format!("{valid}; printf injected"),
        format!("{valid} $(printf injected)"),
        format!("{valid} `printf injected`"),
        format!("{valid}\nprintf injected"),
        format!("{valid} > output"),
        format!("{valid} | cat"),
        format!("{valid} && true"),
        format!("env {valid}"),
        format!("cat {}", shell_quote(path)),
        format!("{valid} --extra"),
        format!("{valid} 'unfinished"),
    ] {
        assert!(check_json_review_command(&command, path).is_err());
    }
    assert!(check_json_review_command(&valid, path).is_ok());
    assert!(command_words(&"a ".repeat(257)).is_err());
    assert!(command_words(&"a".repeat(65537)).is_err());
}

#[test]
fn quoted_literal_paths_and_workspace_review_variant_are_inert() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("data ' $(unused); [literal].json");
    write_json(&path, &json!({"read_only": true})).unwrap();
    let path = path.to_str().unwrap();
    check_json_review_command(&review_json_command(path), path).unwrap();
    let workspace = tmp.path().join("workspace/Cargo.toml");
    std::fs::create_dir(workspace.parent().unwrap()).unwrap();
    write_text(&workspace, "[workspace]\n").unwrap();
    let explicit = format_command(&[
        "cargo",
        "run",
        "-q",
        "--manifest-path",
        workspace.to_str().unwrap(),
        "-p",
        "aegis-measure",
        "--",
        "pretty-json",
        "--input",
        path,
    ]);
    check_json_review_command_for_workspace(&explicit, path, &workspace).unwrap();
    assert_eq!(
        normalized_review_words_for_workspace(&explicit, &workspace).unwrap(),
        normalized_review_words_for_workspace(&review_json_command(path), &workspace).unwrap()
    );
    let foreign = tmp.path().join("Cargo.toml");
    write_text(&foreign, "[workspace]\n").unwrap();
    let foreign = explicit.replace(workspace.to_str().unwrap(), foreign.to_str().unwrap());
    assert!(check_json_review_command_for_workspace(&foreign, path, &workspace).is_err());
}

#[test]
fn review_parity_binds_canonical_artifact_without_running_it() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("data.json");
    write_json(&path, &json!({"read_only": true})).unwrap();
    let alternate = tmp.path().join(".").join("data.json");
    assert_eq!(
        normalized_review_words(&review_json_command(path.to_str().unwrap())).unwrap(),
        normalized_review_words(&review_json_command(alternate.to_str().unwrap())).unwrap()
    );
    assert!(normalized_review_words("printf same-output").is_err());
}

#[test]
fn rerun_metadata_requires_exact_scope_unique_known_options_and_valid_ports() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = materialized_fixture(tmp.path());
    let payload = read_json(&manifest).unwrap();
    let original = required_str(&payload["handoff_commands"], "rerun_command").unwrap();
    for command in [
        original.replace("server.example", "different.example"),
        format!("{original} --ssh-user duplicate"),
        format!("{original} --unexpected flag"),
        format!("{original} --server-port"),
        format!("{original} --server-port 0"),
        format!("{original} --client-port 65536"),
        format!("{original}; touch ignored"),
    ] {
        let mut invalid = payload.clone();
        invalid["operator_handoff"]["handoff_commands"]["rerun_command"] = json!(command);
        assert!(check_rerun_command_contract(&invalid).is_err());
    }
}

#[test]
fn text_review_refuses_truncation_and_status_failure_does_not_write() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = materialized_fixture(tmp.path());
    let payload = read_json(&manifest).unwrap();
    let text = tmp.path().join("long.txt");
    write_text(&text, &"line\n".repeat(161)).unwrap();
    let text = text.to_str().unwrap();
    assert!(
        check_text_review_command(&format_command(&["sed", "-n", "1,160p", text]), text).is_err()
    );
    write_text(Path::new(text), "one\n").unwrap();
    assert!(
        check_text_review_command(&format_command(&["sed", "-n", "1,1p", text]), text).is_err()
    );
    let status_path = Path::new(required_str(&payload, "live_audit_handoff_status_json").unwrap());
    let mut status = read_json(status_path).unwrap();
    status["next_action"]["artifact"] = json!("wrong");
    write_json(status_path, &status).unwrap();
    let before = directory_contents(tmp.path());
    assert!(check_materialized_status_contract(&payload).is_err());
    assert_eq!(before, directory_contents(tmp.path()));
}

#[test]
fn materialized_negative_fixtures_run_only_on_owned_test_inputs() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = materialized_fixture(tmp.path());
    let payload = read_json(&manifest).unwrap();
    run_materialized_negative_checks(
        &dry_run_witness(&payload),
        &payload,
        &payload,
        &payload,
        &payload,
    )
    .unwrap();
}

// Real producer/checker seam, no native network/capture or selected command runs.
// The reference is independently written before any reported output is produced.
struct Audit23TopologyFixture {
    expected: LinuxLiveExpectedTopology,
    manifest: [PathBuf; 4],
    status: [PathBuf; 4],
    dry_run: PathBuf,
}

fn audit23_reference(root: &Path, name: &str, tuple: [&str; 3]) -> PathBuf {
    let path = root.join(name);
    write_private_topology_json(
        &path,
        &json!({"schema":EXPECTED_TOPOLOGY_SCHEMA,
        "server_host":tuple[0],"client_host":tuple[1],"relay_address":tuple[2]}),
    )
    .unwrap();
    path
}

fn audit23_fixture(root: &Path, tuple: [&str; 3]) -> Audit23TopologyFixture {
    let reference = audit23_reference(root, "expected-topology.json", tuple);
    let expected = load_linux_live_expected_topology(&reference).unwrap();
    assert_eq!(expected.server_host, tuple[0]);
    assert_eq!(expected.client_host, tuple[1]);
    assert_eq!(expected.relay_address, tuple[2]);
    let reference_before = std::fs::read(&reference).unwrap();
    let wire_green = root.join("wire-green.json");
    let wire_blocked = root.join("wire-blocked.json");
    let stealth_green = root.join("stealth-green.json");
    let stealth_blocked = root.join("stealth-blocked.json");
    write_json(
        &wire_green,
        &json!({"artifact_schema":"wire_mimicry_host_acceptance_v1",
        "product_verdict":"green","acceptance_status":"passed",
        "hostile_path_support_ready":true,"independent_witness_correlation_status":"matched"}),
    )
    .unwrap();
    write_json(
        &wire_blocked,
        &json!({"artifact_schema":"wire_mimicry_host_acceptance_v1",
        "product_verdict":"yellow","acceptance_status":"needs_witness",
        "hostile_path_support_ready":false,"independent_witness_correlation_status":"missing"}),
    )
    .unwrap();
    write_json(&stealth_green, &json!({"artifact_schema":"stealth_live_acceptance_bundle_v1",
        "bundle_verdict":"green","bundle_status":"acceptance_green",
        "next_action":"collect_next_live_validation_slice","primary_blocker":null,"active_blockers":[]})).unwrap();
    write_json(
        &stealth_blocked,
        &json!({"artifact_schema":"stealth_live_acceptance_bundle_v1",
        "bundle_verdict":"yellow","bundle_status":"blocked_on_runtime_relay_surface_evidence",
        "next_action":"inspect_runtime_relay_surface_evidence",
        "primary_blocker":{"id":"runtime_relay_surface_evidence"},
        "active_blockers":[{"id":"runtime_relay_surface_evidence"}]}),
    )
    .unwrap();
    let data_names = [
        "preflight.json",
        "startup.json",
        "wire-helper.stdout.json",
        "wire-witness-summary.json",
        "stealth-live-acceptance.manifest.json",
    ];
    for name in data_names {
        write_json(&root.join(name), &json!({})).unwrap();
    }
    for name in [
        "runtime-events.jsonl",
        "transient-runtime-events.jsonl",
        "wire-helper-runtime-events.jsonl",
        "wire.pcapng",
    ] {
        write_text(&root.join(name), "").unwrap();
    }
    let mut manifest = Vec::new();
    let mut status = Vec::new();
    for (name, wire, stealth) in [
        ("stealth", &wire_green, &stealth_blocked),
        ("wire", &wire_blocked, &stealth_green),
        ("green", &wire_green, &stealth_green),
        ("dry-run", &wire_green, &stealth_green),
    ] {
        let output = root.join(name);
        std::fs::create_dir(&output).unwrap();
        let path = output.join("live-audit.manifest.json");
        let summary = output.join("live-audit-summary.md");
        let status_path = output.join("live-audit-handoff-status.json");
        let witness = if name == "stealth" {
            root.join("wire-witness-summary.json").display().to_string()
        } else {
            String::new()
        };
        let capture = if name == "stealth" {
            root.join("wire.pcapng").display().to_string()
        } else {
            String::new()
        };
        build_linux_wide_live_audit_manifest(LinuxLiveAuditManifestInputs {
            manifest: path.clone(),
            output_dir: output.display().to_string(),
            server_host: tuple[0].into(),
            client_host: tuple[1].into(),
            relay_address: tuple[2].into(),
            runtime_events: root.join("runtime-events.jsonl").display().to_string(),
            preflight: root.join("preflight.json").display().to_string(),
            startup_probe: root.join("startup.json").display().to_string(),
            wire_helper_stdout: root.join("wire-helper.stdout.json").display().to_string(),
            witness_summary: witness,
            witness_pcap: capture,
            transient_runtime_events: root
                .join("transient-runtime-events.jsonl")
                .display()
                .to_string(),
            wire_helper_runtime_events: root
                .join("wire-helper-runtime-events.jsonl")
                .display()
                .to_string(),
            wire_acceptance_summary: wire.clone(),
            stealth_live_acceptance_bundle: stealth.clone(),
            stealth_live_acceptance_manifest: root
                .join("stealth-live-acceptance.manifest.json")
                .display()
                .to_string(),
            rerun_command: format_command(&[
                "bash",
                "scripts/run-linux-wide-mimicry-live-audit.sh",
                "--server-host",
                tuple[0],
                "--client-host",
                tuple[1],
                "--relay-address",
                tuple[2],
                "--ssh-user",
                "operator",
                "--server-name",
                "relay.example",
                "--output-dir",
                &output.display().to_string(),
            ]),
            review_summary_command: format_command(&[
                "sed",
                "-n",
                "1,160p",
                &summary.display().to_string(),
            ]),
            review_manifest_command: review_json_command(&path.display().to_string()),
            handoff_status_json: status_path.display().to_string(),
        })
        .unwrap();
        build_linux_wide_live_audit_handoff_status(&path, &status_path).unwrap();
        manifest.push(path);
        status.push(status_path);
    }
    assert_eq!(std::fs::read(&reference).unwrap(), reference_before);
    let dry_payload = read_json(&manifest[3]).unwrap();
    let mut dry_witness = dry_run_witness(&dry_payload);
    for stage in [
        "Redeploy server and client from a clean purge",
        "Run server live audit script",
        "Run client live audit script",
        "Collect client runtime and service artifacts",
        "Harvest transient relay wire runtime",
        "Materialize local wire acceptance summary",
        "Materialize local stealth live acceptance bundle",
        "Write local audit manifest",
    ] {
        dry_witness.push_str(stage);
        dry_witness.push('\n');
    }
    let dry_run = root.join("dry-run.txt");
    write_text(&dry_run, &dry_witness).unwrap();
    Audit23TopologyFixture {
        expected,
        manifest: manifest.try_into().unwrap(),
        status: status.try_into().unwrap(),
        dry_run,
    }
}

fn audit23_validity(f: &Audit23TopologyFixture, case: &str) {
    for (manifest, status) in f.manifest.iter().zip(&f.status) {
        let payload = read_json(manifest).unwrap();
        check_manifest_contract(&payload).unwrap();
        check_summary_contract(&payload).unwrap();
        check_expected_manifest_topology(&payload, &f.expected).unwrap();
        check_materialized_status_contract(&payload).unwrap();
        check_review_command_contract(&payload).unwrap();
        check_rerun_command_contract(&payload).unwrap();
        check_next_action_command_contract(&payload).unwrap();
        check_next_action_identity_contract(&payload).unwrap();
        let actual_status = read_json(status).unwrap();
        assert_eq!(
            actual_status,
            handoff_status_from_manifest(&payload).unwrap()
        );
        check_expected_status_topology(&actual_status, &f.expected).unwrap();
    }
    let witness = std::fs::read_to_string(&f.dry_run).unwrap();
    let dry = read_json(&f.manifest[3]).unwrap();
    check_dry_run_plan(&witness).unwrap();
    check_dry_run_materialized_rerun_parity(&witness, &dry).unwrap();
    check_dry_run_materialized_artifact_parity(&witness, &dry).unwrap();
    check_dry_run_materialized_review_parity(&witness, &dry).unwrap();
    check_dry_run_summary_parity(&witness, &dry).unwrap();
    println!("AUDIT23_MEASURE_VALIDITY case={case} reported_artifacts=4 independent_reference=true commands_inert=true complete_original_structure=true");
}

fn audit23_positive(tuple: [&str; 3], case: &str) {
    let root = tempfile::tempdir().unwrap();
    let f = audit23_fixture(root.path(), tuple);
    audit23_validity(&f, case);
    let statuses: Vec<_> = f
        .status
        .iter()
        .map(|path| linux_wide_live_audit_status_contract_check(path, &f.expected))
        .collect();
    let materialized = linux_wide_live_audit_materialized_contract_check(
        &f.dry_run,
        &f.manifest[0],
        &f.manifest[1],
        &f.manifest[2],
        &f.manifest[3],
        &f.expected,
    );
    assert!(
        statuses.iter().all(Result::is_ok) && materialized.is_ok(),
        "independent configured topology must pass actual status and materialized checkers"
    );
}

#[test]
fn independently_configured_topology_a_passes_actual_contracts() {
    audit23_positive(
        ["192.0.2.10", "192.0.2.20", "192.0.2.30:8443"],
        "topology_a",
    );
}

#[test]
fn independently_configured_topology_b_passes_actual_contracts() {
    audit23_positive(
        ["203.0.113.10", "203.0.113.20", "203.0.113.30:9443"],
        "topology_b",
    );
}

fn audit23_mismatch(field: &str, index: usize) {
    let root = tempfile::tempdir().unwrap();
    let tuple = ["192.0.2.10", "192.0.2.20", "192.0.2.30:8443"];
    let f = audit23_fixture(root.path(), tuple);
    audit23_validity(&f, field);
    let mut other = tuple;
    other[index] = ["203.0.113.10", "203.0.113.20", "203.0.113.30:9443"][index];
    let reference = audit23_reference(root.path(), "different-independent-reference.json", other);
    let different = load_linux_live_expected_topology(&reference).unwrap();
    let target_error =
        format!("linux live-audit manifest contract failed: expected topology mismatch: {field}");
    for path in &f.status {
        assert_eq!(
            linux_wide_live_audit_status_contract_check(path, &different)
                .unwrap_err()
                .to_string(),
            target_error
        );
    }
    assert_eq!(
        linux_wide_live_audit_materialized_contract_check(
            &f.dry_run,
            &f.manifest[0],
            &f.manifest[1],
            &f.manifest[2],
            &f.manifest[3],
            &different
        )
        .unwrap_err()
        .to_string(),
        target_error
    );
}

#[test]
fn independently_expected_server_mismatch_refuses_consistent_reports() {
    audit23_mismatch("server_host", 0);
}
#[test]
fn independently_expected_client_mismatch_refuses_consistent_reports() {
    audit23_mismatch("client_host", 1);
}
#[test]
fn independently_expected_relay_mismatch_refuses_consistent_reports() {
    audit23_mismatch("relay_address", 2);
}

#[test]
fn invalid_expected_reference_refuses_before_artifact_mutation_or_execution() {
    use crate::cli::Command;
    let root = tempfile::tempdir().unwrap();
    let reference = root.path().join("expected-topology.json");
    let absent = root.path().join("unprocessed-artifact.json");
    let oversized = vec![b'x'; MAX_EXPECTED_TOPOLOGY_BYTES as usize + 1];
    let invalids: Vec<Option<Vec<u8>>> = vec![None,Some(b"{".to_vec()),Some(oversized),
        Some(br#"{"schema":"REJECTED_TOPOLOGY_CANARY","server_host":"a","client_host":"b","relay_address":"c:1"}"#.to_vec()),
        Some(br#"{"schema":"aegis_linux_live_expected_topology_v1","server_host":"a","client_host":"b","relay_address":"c:1","extra":"REJECTED_TOPOLOGY_CANARY"}"#.to_vec()),
        Some(br#"{"schema":"aegis_linux_live_expected_topology_v1","server_host":"a b","client_host":"b","relay_address":"c:1"}"#.to_vec())];
    let expected_errors = [
        "expected topology unreadable, private or bounded file required",
        "expected topology invalid JSON or fields",
        "expected topology unreadable, private or bounded file required",
        "linux live-audit manifest contract failed: expected topology unsupported schema",
        "expected topology invalid JSON or fields",
        "linux live-audit manifest contract failed: expected topology invalid identity",
    ];
    for (index, invalid) in invalids.into_iter().enumerate() {
        if reference.exists() {
            std::fs::remove_file(&reference).unwrap();
        }
        if let Some(bytes) = invalid {
            aegis_core::secret_file::write_private_new(&reference, &bytes).unwrap();
        }
        let before = directory_contents(root.path());
        println!("AUDIT23_MEASURE_VALIDITY case=invalid_reference_{index} expected_input_owned=true downstream_absent=true");
        for command in [
            Command::LinuxWideLiveAuditHandoffStatusContractCheck {
                expected_topology_file: reference.clone(),
                status_json: vec![absent.clone()],
                expect_fail: true,
            },
            Command::LinuxWideLiveAuditHandoffStatusFixtureContractCheck {
                expected_topology_file: reference.clone(),
                stealth_manifest: absent.clone(),
                wire_manifest: absent.clone(),
                green_manifest: absent.clone(),
                stealth_status: absent.clone(),
                wire_status: absent.clone(),
                green_status: absent.clone(),
            },
            Command::LinuxWideLiveAuditMaterializedContractCheck {
                expected_topology_file: reference.clone(),
                dry_run_output: absent.clone(),
                stealth_manifest: absent.clone(),
                wire_manifest: absent.clone(),
                green_manifest: absent.clone(),
                dry_run_manifest: absent.clone(),
            },
        ] {
            let error = crate::release_dispatch::run(command)
                .unwrap_err()
                .to_string();
            assert_eq!(error, expected_errors[index]);
            assert!(!error.contains("REJECTED_TOPOLOGY_CANARY"));
            assert_eq!(before, directory_contents(root.path()));
        }
    }
}
