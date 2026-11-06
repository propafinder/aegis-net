//! Actual copied delivered executable boundary. Owned benign files/child only.
use aegis_core::secret_file;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    fs, io,
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    time::Duration,
};
use tokio::{io::AsyncReadExt, process::Command, time::timeout};

const CAPABILITIES: [&str; 7] = [
    "private-control",
    "poisson-control",
    "poisson-insertion",
    "privacy-pcap-export",
    "privacy-study-assemble",
    "privacy-frontier",
    "brain-outcome-replay",
];
const MAX_OUTPUT: u64 = 64 * 1024;

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn private(path: &Path, bytes: &[u8]) {
    secret_file::write_private_new(path, bytes).unwrap();
}
fn delivered(dir: &Path) -> PathBuf {
    // Paired QA pins its explicit role; ordinary CI uses only Cargo's restricted bin.
    // Never substitute the full build-side executable if the named role is absent.
    let source = PathBuf::from(
        std::env::var_os("AEGIS_TEST_RESEARCH_OPERATOR_EXECUTABLE")
            .or_else(|| option_env!("CARGO_BIN_EXE_aegis-research-measure").map(OsString::from))
            .expect("compiled restricted research source or explicit paired source required"),
    );
    assert!(source.is_file(), "selected actual producer absent");
    let copy = dir.join(if cfg!(windows) {
        "aegis-measure.exe"
    } else {
        "aegis-measure"
    });
    assert!(!copy.exists());
    fs::copy(&source, &copy).unwrap();
    assert_eq!(
        digest(&fs::read(&copy).unwrap()),
        digest(&fs::read(&source).unwrap()),
        "copied producer identity changed"
    );
    copy
}

async fn run(
    exe: &Path,
    args: &[OsString],
    witness: Option<&Path>,
) -> (ExitStatus, Vec<u8>, Vec<u8>) {
    let mut command = Command::new(exe);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(path) = witness {
        command.env("AEGIS_TEST_RESEARCH_CHILD_WITNESS", path);
    }
    let mut child = command.spawn().expect("actual producer spawn required");
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let operation = async {
        let out = async {
            let mut bytes = Vec::new();
            stdout.take(MAX_OUTPUT + 1).read_to_end(&mut bytes).await?;
            Ok::<_, io::Error>(bytes)
        };
        let err = async {
            let mut bytes = Vec::new();
            stderr.take(MAX_OUTPUT + 1).read_to_end(&mut bytes).await?;
            Ok::<_, io::Error>(bytes)
        };
        let (out, err, status) = tokio::try_join!(out, err, child.wait())?;
        Ok::<_, io::Error>((status, out, err))
    };
    let result = timeout(Duration::from_secs(10), operation).await;
    // Child stays outside the timed operation. Refusal/timeout cannot bypass reap.
    let direct_joined = match child.try_wait() {
        Ok(Some(_)) => true,
        Ok(None) => {
            let _ = child.start_kill();
            matches!(
                timeout(Duration::from_secs(2), child.wait()).await,
                Ok(Ok(_))
            )
        }
        Err(_) => false,
    };
    assert!(direct_joined, "actual producer cleanup unconfirmed");
    let value = result
        .expect("actual producer operation exceeded 10 seconds")
        .expect("actual producer I/O failed");
    assert!(
        value.1.len() as u64 <= MAX_OUTPUT && value.2.len() as u64 <= MAX_OUTPUT,
        "actual producer output exceeded bound"
    );
    value
}
fn args(values: &[&OsStr]) -> Vec<OsString> {
    values.iter().map(|v| v.to_os_string()).collect()
}

#[test]
fn harmless_owned_child_witness() {
    if let Some(path) = std::env::var_os("AEGIS_TEST_RESEARCH_CHILD_WITNESS") {
        // Only invoked by the parent's exact helper selector with an owned path.
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        use std::io::Write;
        file.write_all(b"owned-child-executed\n").unwrap();
        file.sync_all().unwrap();
    }
}

#[tokio::test]
async fn copied_delivered_role_refuses_undeclared_child_before_dispatch() {
    let dir = tempfile::tempdir().unwrap();
    let exe = delivered(dir.path());
    let witness = dir.path().join("child-witness");
    let helper = std::env::current_exe().unwrap();
    let argv = args(&[
        OsStr::new("run-with-timeout"),
        OsStr::new("--timeout-secs"),
        OsStr::new("1"),
        OsStr::new("--"),
        helper.as_os_str(),
        OsStr::new("--exact"),
        OsStr::new("harmless_owned_child_witness"),
        OsStr::new("--test-threads=1"),
    ]);
    let (status, _, _) = run(&exe, &argv, Some(&witness)).await;
    let executed = witness.is_file();
    if executed {
        assert_eq!(fs::read(&witness).unwrap(), b"owned-child-executed\n");
    }
    println!("research_child_probe copied_valid=true producer_reaped=true command_success={} child_witness={}", status.success(), executed);
    assert!(!status.success(), "undeclared child command was admitted");
    assert!(!executed, "undeclared child reached actual dispatch");
}

#[tokio::test]
async fn copied_delivered_help_and_snapshot_match_exact_seven_actions() {
    let dir = tempfile::tempdir().unwrap();
    let exe = delivered(dir.path());
    let (status, out, _) = run(&exe, &args(&[OsStr::new("--help")]), None).await;
    assert!(status.success());
    let help = String::from_utf8(out).unwrap();
    let commands = help
        .split("Commands:\n")
        .nth(1)
        .expect("actual command inventory required")
        .split("\nOptions:")
        .next()
        .unwrap();
    let observed: BTreeSet<_> = commands
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    let expected: BTreeSet<_> = CAPABILITIES
        .into_iter()
        .chain(["research-build-info", "help"])
        .collect();
    println!(
        "research_command_inventory actual_actions_plus_scaffolding={}",
        observed.len()
    );
    assert_eq!(observed, expected);
    let (status, out, err) = run(&exe, &args(&[OsStr::new("research-build-info")]), None).await;
    assert!(status.success() && err.is_empty());
    let info: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(info["capabilities"], json!(CAPABILITIES));
    assert_eq!(info["binary_sha256"], digest(&fs::read(&exe).unwrap()));
    assert_eq!(info["tool"], "aegis-measure");
}

#[tokio::test]
async fn full_build_role_keeps_helpers_but_refuses_restricted_producer_claim() {
    let exe = Path::new(env!("CARGO_BIN_EXE_aegis-measure"));
    let (status, out, _) = run(exe, &args(&[OsStr::new("host-arch")]), None).await;
    assert!(status.success() && !out.is_empty());
    let (status, out, _) = run(exe, &args(&[OsStr::new("research-build-info")]), None).await;
    assert!(
        !status.success() && out.is_empty(),
        "full build tool claimed restricted research producer role"
    );
}

// A schema-shaped fixture borrowed from the existing retained-export tests.
// This serializable unit has the actual input-schema field order, not a report model.
#[derive(Serialize)]
struct StudyUnit<'a> {
    session_id: &'a str,
    trial_id: &'a str,
    network_id: &'a str,
    time_holdout_id: &'a str,
    capture_sha256: String,
    capture_started_unix_ms: u64,
    capture_finished_unix_ms: u64,
}
fn reference(dir: &Path, leaf: &str, bytes: &[u8]) -> Value {
    let path = dir.join(leaf);
    private(&path, bytes);
    json!({"path":path,"sha256":digest(bytes)})
}
fn study_input(dir: &Path) -> Value {
    let training = vec![StudyUnit {
        session_id: "train",
        trial_id: "train",
        network_id: "net",
        time_holdout_id: "train",
        capture_sha256: "a".repeat(64),
        capture_started_unix_ms: 100,
        capture_finished_unix_ms: 200,
    }];
    let bins = json!({"schema_version":1,"statistic":"selected_captured_wire_frame_bytes","units":"bytes","frozen_unix_ms":900,"training_units_sha256":digest(&serde_json::to_vec(&training).unwrap()),"upper_exclusive_edges":[150,250]});
    let bins = reference(dir, "bins.json", &serde_json::to_vec(&bins).unwrap());
    let first = std::net::Ipv4Addr::from([192, 0, 2, 1]).to_string();
    let second = std::net::Ipv4Addr::from([192, 0, 2, 2]).to_string();
    let mut policies = Vec::new();
    for (index, name) in ["base", "shape"].into_iter().enumerate() {
        let capture = if index == 0 {
            "b".repeat(64)
        } else {
            "c".repeat(64)
        };
        let mut rows = "timestamp_unix_us\tframe_length_bytes\tcaptured_length_bytes\tsrc_ip\tdst_ip\tprotocol\tsrc_port\tdst_port\n".to_owned();
        let mut trials = Vec::new();
        let mut costs = Vec::new();
        for i in 0..4 {
            let id = format!("trial{i}");
            let start = 1_000_000 + i * 100;
            let total = if index == 0 && i % 2 == 0 { 100 } else { 200 };
            rows.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\ttcp\t12000\t8443\n",
                start + 1,
                total / 2,
                total / 2,
                first,
                second
            ));
            rows.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\ttcp\t8443\t12000\n",
                start + 2,
                total / 2,
                total / 2,
                second,
                first
            ));
            trials.push(json!({"unit":{"session_id":name,"trial_id":id,"network_id":"net","time_holdout_id":"eval","capture_sha256":capture,"capture_started_unix_ms":1000,"capture_finished_unix_ms":1050},"label":i%2,"export_id":"export","flow":{"protocol":"tcp","client":{"ip":first,"port":12000},"peer":{"ip":second,"port":8443}},"window_started_unix_us":start,"window_finished_unix_us":start+10}));
            costs.push(json!({"trial_id":id,"network_id":"net","time_holdout_id":"eval","added_bytes":index*100,"added_delay_ms":index as f64}));
        }
        let export = reference(dir, &format!("{name}.tsv"), rows.as_bytes());
        let costs = reference(
            dir,
            &format!("{name}-costs.json"),
            &serde_json::to_vec(&json!({"schema_version":1,"rows":costs})).unwrap(),
        );
        policies.push(json!({"name":name,"exports":[{"id":"export","file":export,"capture_sha256":capture,"network_id":"net","capture_started_unix_ms":1000,"capture_finished_unix_ms":1050}],"costs":costs,"trials":trials}));
    }
    json!({"schema_version":1,"source_kind":"synthetic_fixture","bins":bins,"training_units":training,"policies":policies})
}

#[tokio::test]
async fn copied_delivered_offline_actions_execute_existing_handlers() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let exe = delivered(d);
    // One actual supported classic-PCAP raw-IP frame; no socket or capture.
    let mut pcap = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
    for word in [0u32, 0, 262144, 101] {
        pcap.extend_from_slice(&word.to_le_bytes());
    }
    let mut packet = vec![0u8; 50];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&50u16.to_be_bytes());
    packet[9] = 6;
    packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
    packet[16..20].copy_from_slice(&[192, 0, 2, 2]);
    packet[20..22].copy_from_slice(&12000u16.to_be_bytes());
    packet[22..24].copy_from_slice(&8443u16.to_be_bytes());
    packet[32] = 0x50;
    for word in [1u32, 1, 50, 50] {
        pcap.extend_from_slice(&word.to_le_bytes());
    }
    pcap.extend_from_slice(&packet);
    let input = d.join("capture.pcap");
    let tsv = d.join("packet-rows.tsv");
    private(&input, &pcap);
    let (status, out, _) = run(
        &exe,
        &args(&[
            OsStr::new("privacy-pcap-export"),
            OsStr::new("--input-pcap"),
            input.as_os_str(),
            OsStr::new("--output-tsv"),
            tsv.as_os_str(),
        ]),
        None,
    )
    .await;
    assert!(status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&out).unwrap()["rows_emitted"],
        1
    );
    assert!(tsv.is_file());
    let input = d.join("study.json");
    let output = d.join("study-report.json");
    private(&input, &serde_json::to_vec(&study_input(d)).unwrap());
    let (status, _, _) = run(
        &exe,
        &args(&[
            OsStr::new("privacy-study-assemble"),
            OsStr::new("--input-json"),
            input.as_os_str(),
            OsStr::new("--output-json"),
            output.as_os_str(),
        ]),
        None,
    )
    .await;
    assert!(status.success());
    let report: Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
    assert_eq!(
        report["assembled_input"]["policies"][0]["samples"][0]["feature"],
        0
    );
    let input = d.join("frontier.json");
    let output = d.join("frontier-report.json");
    private(&input,&serde_json::to_vec(&json!({"alphabet":{"labels":2,"features":2},"assume_iid_fixed_alphabet":false,"delta":0.05,"policies":[{"name":"measured","samples":[{"label":0,"feature":0,"added_bytes":32,"added_delay_ms":2.0}]}]})).unwrap());
    let (status, _, _) = run(
        &exe,
        &args(&[
            OsStr::new("privacy-frontier"),
            OsStr::new("--input-json"),
            input.as_os_str(),
            OsStr::new("--output-json"),
            output.as_os_str(),
        ]),
        None,
    )
    .await;
    assert!(status.success());
    let report: Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
    assert_eq!(report["formal_dp_accounting"], false);
    assert_eq!(report["automatic_policy_adoption"], false);
    let input = d.join("outcomes.jsonl");
    let meta = d.join("outcomes-source.json");
    let output = d.join("outcomes-report.json");
    let rows = [
        json!({"ts_unix_ms":10,"event_code":"direct_planner_order_selected","fields":{"target":"fixture.invalid","port":443,"planner_retry_attempt":0,"planner_ranked_candidates":[{"strategy":"one","estimated_reward":0.5,"belief_hard_blocked":false},{"strategy":"two","estimated_reward":0.25,"belief_hard_blocked":false}],"planner_resolved_order":["one","two"]}}),
        json!({"ts_unix_ms":20,"event_code":"direct_session_succeeded","fields":{"target":"fixture.invalid","port":443,"strategy":"one","signal":"Success","bytes_sent":85,"latency_ms":104,"retry_attempts_used":0,"observation_capture_confidence":"native_only"}}),
    ];
    let tape = rows
        .iter()
        .map(|row| serde_json::to_string(row).unwrap() + "\n")
        .collect::<String>();
    private(&input, tape.as_bytes());
    private(&meta,&serde_json::to_vec(&json!({"schema_version":1,"source_sha256":digest(tape.as_bytes()),"source_started_unix_ms":10,"source_finished_unix_ms":20,"source_kind":"synthetic_fixture","source_commit":null,"window_ms":100,"failure_cooldown_ms":20,"max_observations":16})).unwrap());
    let (status, _, _) = run(
        &exe,
        &args(&[
            OsStr::new("brain-outcome-replay"),
            OsStr::new("--input-jsonl"),
            input.as_os_str(),
            OsStr::new("--provenance-json"),
            meta.as_os_str(),
            OsStr::new("--output-json"),
            output.as_os_str(),
        ]),
        None,
    )
    .await;
    assert!(status.success());
    let report: Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
    assert_eq!(report["replay"]["observed_outcomes"], 1);
    assert_eq!(report["installed_acceptance"], false);
}
