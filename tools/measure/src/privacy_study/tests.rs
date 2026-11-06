use super::*;
use packet_rows::{Endpoint, Protocol};
use std::{
    fs,
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Fixture {
    root: PathBuf,
    manifest: Value,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn unit(policy: &str, trial: &str, capture: &str) -> Value {
    json!({"session_id":policy,"trial_id":trial,"network_id":"net","time_holdout_id":"eval",
        "capture_sha256":capture,"capture_started_unix_ms":1000,"capture_finished_unix_ms":1050})
}
fn private_reference(root: &Path, name: &str, bytes: &[u8]) -> Value {
    let file = root.join(name);
    aegis_core::secret_file::write_private_new(&file, bytes).unwrap();
    json!({"path":file,"sha256":digest(bytes)})
}
fn fixture() -> Fixture {
    let root = std::env::temp_dir().join(format!(
        "aegis-private-study-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let training = json!([{"session_id":"train","trial_id":"train","network_id":"net","time_holdout_id":"train",
        "capture_sha256":"a".repeat(64),"capture_started_unix_ms":100,"capture_finished_unix_ms":200}]);
    let typed_training: Vec<Unit> = serde_json::from_value(training.clone()).unwrap();
    let bins = json!({"schema_version":1,"statistic":"selected_captured_wire_frame_bytes","units":"bytes",
        "frozen_unix_ms":900,"training_units_sha256":json_digest(&typed_training).unwrap(),"upper_exclusive_edges":[150,250]});
    let bins = private_reference(&root, "bins.json", &serde_json::to_vec(&bins).unwrap());
    let mut policies = Vec::new();
    for (index, name) in ["base", "shape"].iter().enumerate() {
        let capture = if index == 0 {
            "b".repeat(64)
        } else {
            "c".repeat(64)
        };
        let mut rows = format!("{}\n", packet_rows::HEADER);
        let mut trials = Vec::new();
        let mut costs = Vec::new();
        for i in 0..4 {
            let id = format!("trial{i}");
            let start = 1_000_000 + i * 100;
            let total = if index == 0 && i % 2 == 0 { 100 } else { 200 };
            for (offset, first, second) in [
                (1, "192.0.2.1", "198.51.100.2"),
                (2, "198.51.100.2", "192.0.2.1"),
            ] {
                let (source_port, destination_port) = if offset == 1 {
                    (12000, 8443)
                } else {
                    (8443, 12000)
                };
                rows.push_str(&format!(
                    "{}\t{}\t{}\t{}\t{}\ttcp\t{}\t{}\n",
                    start + offset,
                    total / 2,
                    total / 2,
                    first,
                    second,
                    source_port,
                    destination_port
                ));
            }
            trials.push(json!({"unit":unit(name,&id,&capture),"label":i%2,"export_id":"export",
                "flow":{"protocol":"tcp","client":{"ip":"192.0.2.1","port":12000},"peer":{"ip":"198.51.100.2","port":8443}},
                "window_started_unix_us":start,"window_finished_unix_us":start+10}));
            costs.push(json!({"trial_id":id,"network_id":"net","time_holdout_id":"eval","added_bytes":index*100,"added_delay_ms":index as f64}));
        }
        let export = private_reference(&root, &format!("{name}.tsv"), rows.as_bytes());
        let costs = private_reference(
            &root,
            &format!("{name}-costs.json"),
            &serde_json::to_vec(&json!({"schema_version":1,"rows":costs})).unwrap(),
        );
        policies.push(json!({"name":name,"exports":[{"id":"export","file":export,"capture_sha256":capture,
            "network_id":"net","capture_started_unix_ms":1000,"capture_finished_unix_ms":1050}],"costs":costs,"trials":trials}));
    }
    Fixture {
        root,
        manifest: json!({"schema_version":1,"source_kind":"synthetic_fixture","bins":bins,"training_units":training,"policies":policies}),
    }
}
fn assembled(value: &Value) -> Result<Value, &'static str> {
    assemble(&serde_json::to_vec(value).unwrap())
}
fn replaced(fixture: &Fixture, pointer: &str, name: &str, value: &Value) -> Value {
    let mut manifest = fixture.manifest.clone();
    *manifest.pointer_mut(pointer).unwrap() =
        private_reference(&fixture.root, name, &serde_json::to_vec(value).unwrap());
    manifest
}
fn read_reference(manifest: &Value, pointer: &str) -> Value {
    let path = manifest.pointer(pointer).unwrap()["path"].as_str().unwrap();
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

#[test]
fn privacy_study_assembles_actual_bins_and_trial_wire_totals_into_native_frontier() {
    let fixture = fixture();
    let result = assembled(&fixture.manifest).unwrap();
    assert_eq!(
        result["assembled_input"]["policies"][0]["samples"][0]["feature"],
        0
    );
    assert_eq!(
        result["assembled_input"]["policies"][0]["samples"][1]["feature"],
        1
    );
    assert_eq!(
        result["trial_measurements"][0]["stats"]["selected_wire_frame_bytes"],
        100
    );
    assert_eq!(
        result["trial_measurements"][0]["stats"]["outgoing_wire_frame_bytes"],
        50
    );
    assert_eq!(
        result["trial_measurements"][0]["stats"]["incoming_wire_frame_bytes"],
        50
    );
    assert_eq!(
        result["content_bindings"]["exports"][0]["unselected_rows"],
        0
    );
    let reference =
        crate::privacy_frontier::privacy_frontier_report(&result["assembled_input"]).unwrap();
    assert_eq!(reference, result["frontier_report"]);
    assert_eq!(
        result["frontier_report"]["binary_hypothesis_diagnostics"]["status"],
        "declared_provenance_checked_empirical_only"
    );
    let diagnostics = &result["frontier_report"]["binary_hypothesis_diagnostics"]["policies"];
    assert_eq!(
        diagnostics[0]["diagnostic"]["empirical_total_variation"],
        1.0
    );
    assert_eq!(
        diagnostics[1]["diagnostic"]["empirical_total_variation"],
        0.0
    );
    assert_eq!(
        diagnostics[0]["diagnostic"]["empirical_plugin_minimum_sum_error"],
        0.0
    );
    assert_eq!(
        diagnostics[1]["diagnostic"]["empirical_plugin_minimum_sum_error"],
        1.0
    );
    assert_eq!(
        diagnostics[0]["diagnostic"]["kl_h0_to_h1"]["empirical_pinsker_minimum_sum_error"],
        Value::Null
    );
    assert_eq!(
        diagnostics[1]["diagnostic"]["kl_h0_to_h1"]["empirical_pinsker_minimum_sum_error"],
        1.0
    );
    assert_eq!(
        diagnostics[0]["diagnostic"]["kl_h0_to_h1"]["status"],
        "unknown_zero_observed_reference_support"
    );
    assert_eq!(
        diagnostics[0]["diagnostic"]["kl_h0_to_h1"]["empirical_nats"],
        Value::Null
    );
    for name in [
        "capture_contents_verified",
        "export_capture_correspondence_verified",
        "cost_wire_measurement_verified",
        "trusted_freeze_time_proven",
        "bin_training_origin_verified",
        "statistical_independence_proven",
        "delivery_proven",
        "beta_exit",
    ] {
        assert_eq!(result[name], false);
    }
    let text = result.to_string();
    assert!(!text.contains("192.0.2.1") && !text.contains("198.51.100.2"));
    assert!(!text.contains(fixture.root.to_str().unwrap()));
}

#[test]
fn privacy_study_refuses_mismatched_bin_export_and_cost_content_hashes() {
    let fixture = fixture();
    for pointer in [
        "/bins/sha256",
        "/policies/0/exports/0/file/sha256",
        "/policies/0/costs/sha256",
    ] {
        let mut changed = fixture.manifest.clone();
        *changed.pointer_mut(pointer).unwrap() = json!("0".repeat(64));
        assert_eq!(
            assembled(&changed).unwrap_err(),
            "study input content SHA-256 mismatch"
        );
    }
}

#[test]
fn privacy_study_validates_actual_bins_without_fitting_evaluation_data() {
    let fixture = fixture();
    let bins = read_reference(&fixture.manifest, "/bins");
    for (i, edges) in [
        json!([]),
        json!([0]),
        json!([150, 150]),
        json!([250, 150]),
        json!(vec![1; 256]),
    ]
    .into_iter()
    .enumerate()
    {
        let mut changed = bins.clone();
        changed["upper_exclusive_edges"] = edges;
        assert!(assembled(&replaced(
            &fixture,
            "/bins",
            &format!("badbins{i}.json"),
            &changed
        ))
        .is_err());
    }
    let mut changed = bins;
    changed["training_units_sha256"] = json!("d".repeat(64));
    assert!(assembled(&replaced(
        &fixture,
        "/bins",
        "wrong-training.json",
        &changed
    ))
    .is_err());
    let bins = FrozenBins {
        schema_version: 1,
        statistic: "selected_captured_wire_frame_bytes".into(),
        units: "bytes".into(),
        frozen_unix_ms: 1,
        training_units_sha256: "x".into(),
        upper_exclusive_edges: vec![150, 250],
    };
    assert_eq!(
        [
            bins.feature(149),
            bins.feature(150),
            bins.feature(249),
            bins.feature(250),
            bins.feature(u64::MAX)
        ],
        [0, 1, 1, 2, 2]
    );
}

#[test]
fn privacy_study_refuses_missing_null_duplicate_and_extra_cost_records() {
    let fixture = fixture();
    let costs = read_reference(&fixture.manifest, "/policies/0/costs");
    for i in 0..4 {
        let mut changed = costs.clone();
        match i {
            0 => {
                changed["rows"].as_array_mut().unwrap().pop();
            }
            1 => changed["rows"][0]["added_delay_ms"] = Value::Null,
            2 => changed["rows"][1] = changed["rows"][0].clone(),
            _ => changed["rows"][0]["trial_id"] = json!("missing"),
        }
        assert!(assembled(&replaced(
            &fixture,
            "/policies/0/costs",
            &format!("badcost{i}.json"),
            &changed
        ))
        .is_err());
    }
}

#[test]
fn privacy_study_keeps_insufficient_hypothesis_observations_unknown() {
    let fixture = fixture();
    let mut manifest = fixture.manifest.clone();
    for index in 0..2 {
        manifest["policies"][index]["trials"]
            .as_array_mut()
            .unwrap()
            .truncate(2);
        let mut costs = read_reference(&manifest, &format!("/policies/{index}/costs"));
        costs["rows"].as_array_mut().unwrap().truncate(2);
        *manifest
            .pointer_mut(&format!("/policies/{index}/costs"))
            .unwrap() = private_reference(
            &fixture.root,
            &format!("smallcost{index}.json"),
            &serde_json::to_vec(&costs).unwrap(),
        );
    }
    let result = assembled(&manifest).unwrap();
    let diagnostics =
        &result["frontier_report"]["binary_hypothesis_diagnostics"]["policies"][0]["diagnostic"];
    assert_eq!(diagnostics["status"], "unknown_insufficient_observations");
    assert_eq!(diagnostics["empirical_total_variation"], Value::Null);
    assert_eq!(
        result["content_bindings"]["exports"][0]["unselected_rows"],
        4
    );
}

#[test]
fn privacy_study_reuses_existing_pair_training_and_capture_consistency_gate() {
    let fixture = fixture();
    for i in 0..4 {
        let mut changed = fixture.manifest.clone();
        match i {
            0 => changed["policies"][1]["trials"][0]["label"] = json!(1),
            1 => {
                changed["policies"][1]["trials"][1]["unit"]["capture_finished_unix_ms"] =
                    json!(1040)
            }
            2 => changed["policies"][0]["trials"][0]["unit"]["session_id"] = json!("train"),
            _ => changed["policies"][0]["trials"][1]["unit"]["trial_id"] = json!("trial0"),
        }
        assert!(assembled(&changed).is_err());
    }
}

#[test]
fn privacy_study_refuses_missing_export_capture_mismatch_and_overlapping_selectors() {
    let fixture = fixture();
    for i in 0..4 {
        let mut changed = fixture.manifest.clone();
        match i {
            0 => changed["policies"][0]["trials"][0]["export_id"] = json!("absent"),
            1 => changed["policies"][0]["exports"][0]["network_id"] = json!("other"),
            2 => {
                changed["policies"][0]["trials"][1]["window_started_unix_us"] = json!(1_000_000);
                changed["policies"][0]["trials"][1]["window_finished_unix_us"] = json!(1_000_010);
            }
            _ => changed["policies"][0]["trials"][0]["window_finished_unix_us"] = json!(1_100_000),
        }
        assert!(assembled(&changed).is_err());
    }
}

#[test]
fn privacy_study_rejects_two_exports_for_one_capture_without_double_counting_trials() {
    let fixture = fixture();
    let mut manifest = fixture.manifest.clone();
    let mut duplicate = manifest["policies"][0]["exports"][0].clone();
    duplicate["id"] = json!("second");
    manifest["policies"][0]["exports"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    manifest["policies"][0]["trials"][1]["export_id"] = json!("second");
    assert_eq!(
        assembled(&manifest).unwrap_err(),
        "one declared capture must have exactly one retained export per policy"
    );
}

fn flow(ipv6: bool, protocol: Protocol) -> Flow {
    Flow {
        protocol,
        client: Endpoint {
            ip: if ipv6 { "2001:db8::1" } else { "192.0.2.1" }
                .parse()
                .unwrap(),
            port: 12000,
        },
        peer: Endpoint {
            ip: if ipv6 { "2001:db8::2" } else { "198.51.100.2" }
                .parse()
                .unwrap(),
            port: 8443,
        },
    }
}
#[test]
fn privacy_study_packet_rows_use_explicit_direction_ties_and_half_open_windows() {
    for ipv6 in [false, true] {
        for protocol in [Protocol::Tcp, Protocol::Udp] {
            let flow = flow(ipv6, protocol);
            let selected = Selection {
                flow,
                started_us: 1000,
                finished_us: 1010,
            };
            let rows = format!("{}\n1001\t60\t60\t{}\t{}\t{}\t12000\t8443\n1001\t40\t40\t{}\t{}\t{}\t8443\t12000\n1010\t50\t50\t{}\t{}\t{}\t12000\t8443\n",packet_rows::HEADER,
            flow.client.ip,flow.peer.ip,if protocol==Protocol::Tcp {"tcp"} else {"udp"},flow.peer.ip,flow.client.ip,
            if protocol==Protocol::Tcp {"tcp"} else {"udp"},flow.client.ip,flow.peer.ip,if protocol==Protocol::Tcp {"tcp"} else {"udp"});
            let (stats, count) =
                packet_rows::extract(rows.as_bytes(), &[selected], 1000, 1020, &mut 3).unwrap();
            assert_eq!(count, 3);
            assert_eq!(stats[0].selected_wire_frame_bytes, 100);
            assert_eq!(stats[0].outgoing_wire_frame_bytes, 60);
            assert_eq!(stats[0].incoming_wire_frame_bytes, 40);
        }
    }
}

#[test]
fn privacy_study_packet_rows_reject_malformed_truncated_order_and_row_budget() {
    let selected = Selection {
        flow: flow(false, Protocol::Tcp),
        started_us: 1000,
        finished_us: 1020,
    };
    let valid = "1001\t60\t60\t192.0.2.1\t198.51.100.2\ttcp\t12000\t8443";
    for row in [
        "",
        "1001\t60",
        "-1\t60\t60\t192.0.2.1\t198.51.100.2\ttcp\t12000\t8443",
        "1001\t60\t59\t192.0.2.1\t198.51.100.2\ttcp\t12000\t8443",
        "1001\t60\t60\t192.0.2.1\t198.51.100.2\tunknown\t12000\t8443",
        "1001\t60\t60\tbad-ip\t198.51.100.2\ttcp\t12000\t8443",
        "1001\t60\t60\t192.0.2.1\t198.51.100.2\ttcp\t0\t8443",
    ] {
        let rows = format!("{}\n{row}\n", packet_rows::HEADER);
        assert!(packet_rows::extract(rows.as_bytes(), &[selected], 1000, 1020, &mut 5).is_err());
    }
    let out_of_order = format!(
        "{}\n{}\n{}\n",
        packet_rows::HEADER,
        valid.replace("1001", "1002"),
        valid
    );
    assert!(
        packet_rows::extract(out_of_order.as_bytes(), &[selected], 1000, 1020, &mut 5).is_err()
    );
    let rows = format!("{}\n{valid}\n", packet_rows::HEADER);
    assert_eq!(
        packet_rows::extract(rows.as_bytes(), &[selected], 1000, 1020, &mut 0).unwrap_err(),
        "combined packet row budget exceeded"
    );
}

#[test]
fn privacy_study_admission_refuses_manifest_trial_and_file_budgets() {
    assert_eq!(
        assemble(&vec![b' '; MAX_MANIFEST as usize + 1]).unwrap_err(),
        "study manifest byte budget exceeded"
    );
    let fixture = fixture();
    let mut changed = fixture.manifest.clone();
    let trial = changed["policies"][0]["trials"][0].clone();
    changed["policies"][0]["trials"] = json!(vec![trial; MAX_TRIALS + 1]);
    assert!(assembled(&changed).is_err());
    let reference = private_reference(
        &fixture.root,
        "oversized.tsv",
        &vec![b' '; MAX_EXPORT as usize + 1],
    );
    let reference: FileRef = serde_json::from_value(reference).unwrap();
    assert!(read_bound(&reference, MAX_EXPORT).is_err());
}

#[test]
fn privacy_study_combined_budget_is_not_reset_between_actual_exports() {
    let fixture = fixture();
    let bytes = serde_json::to_vec(&fixture.manifest).unwrap();
    let first = fs::metadata(
        fixture.manifest["policies"][0]["exports"][0]["file"]["path"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
    .len() as usize;
    let second = fs::metadata(
        fixture.manifest["policies"][1]["exports"][0]["file"]["path"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
    .len() as usize;
    assert!(assemble_with_budget(&bytes, first + second, 16).is_ok());
    assert!(assemble_with_budget(&bytes, first + second - 1, 16).is_err());
    assert_eq!(
        assemble_with_budget(&bytes, first + second, 15).unwrap_err(),
        "combined packet row budget exceeded"
    );
}

#[test]
fn privacy_study_private_cli_writer_is_new_only_and_does_not_echo_input() {
    let fixture = fixture();
    let input = fixture.root.join("study.json");
    aegis_core::secret_file::write_private_new(
        &input,
        &serde_json::to_vec(&fixture.manifest).unwrap(),
    )
    .unwrap();
    let output = fixture.root.join("report.json");
    run(&input, &output).unwrap();
    let original = fs::read(&output).unwrap();
    assert!(run(&input, &output).is_err());
    assert_eq!(fs::read(&output).unwrap(), original);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(output).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[cfg(unix)]
#[test]
fn privacy_study_custody_rejects_symlink_public_input_and_writable_ancestry() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let fixture = fixture();
    let input = fixture.root.join("study.json");
    aegis_core::secret_file::write_private_new(
        &input,
        &serde_json::to_vec(&fixture.manifest).unwrap(),
    )
    .unwrap();
    let output = fixture.root.join("report.json");
    let link = fixture.root.join("link.json");
    symlink(&input, &link).unwrap();
    assert!(run(&link, &output).is_err());
    assert!(!output.exists());
    fs::set_permissions(&input, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(run(&input, &output).is_err());
    fs::set_permissions(&input, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(run(&input, &output).is_err());
    assert!(!output.exists());
    fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o700)).unwrap();
}
