//! Real copied administrative consumer selectors; no help/mock dispatch proof.
//! The paired driver explicitly selects the original restricted archive leaf or
//! candidate full administrative leaf. Normal CI uses Cargo's full build tool.
//! Linux archive layout is separately exercised by the real delivery contract.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{process::Command, time::timeout};

fn sha(path: &Path) -> String {
    let mut file = fs::File::open(path).unwrap();
    let mut digest = Sha256::new();
    let mut chunk = [0u8; 65536];
    let mut count = 0u64;
    loop {
        let n = file.read(&mut chunk).unwrap();
        if n == 0 {
            break;
        }
        count += n as u64;
        assert!(count <= 512 * 1024 * 1024);
        digest.update(&chunk[..n]);
    }
    assert!(count > 0);
    format!("{:x}", digest.finalize())
}
fn copied(directory: &Path) -> PathBuf {
    let source = PathBuf::from(
        std::env::var_os("AEGIS_TEST_ADMIN_MEASURE_EXECUTABLE")
            .unwrap_or_else(|| OsString::from(env!("CARGO_BIN_EXE_aegis-measure"))),
    );
    assert!(source.is_file(), "actual administrative producer required");
    let destination = directory.join(if cfg!(windows) {
        "administrative.exe"
    } else {
        "administrative"
    });
    assert!(!destination.exists());
    fs::copy(&source, &destination).unwrap();
    assert_eq!(
        sha(&source),
        sha(&destination),
        "copied input identity drift"
    );
    destination
}
fn input(path: &Path, bytes: &[u8]) {
    aegis_core::secret_file::write_private_new(path, bytes).unwrap();
}
async fn run(root: &Path, exe: &Path, args: &[OsString]) -> (bool, Vec<u8>) {
    let out_path = root.join("child.stdout");
    let err_path = root.join("child.stderr");
    input(&out_path, b"");
    input(&err_path, b"");
    let mut child = Command::new(exe)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(
            fs::OpenOptions::new().write(true).open(&out_path).unwrap(),
        ))
        .stderr(Stdio::from(
            fs::OpenOptions::new().write(true).open(&err_path).unwrap(),
        ))
        .kill_on_drop(true)
        .spawn()
        .expect("actual copied consumer child required");
    let result = timeout(Duration::from_secs(10), child.wait()).await;
    // Child is outside the timed operation. Always confirm this direct owner
    // before asserting; the independent outer QA supervisor owns group custody.
    let joined = match child.try_wait() {
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
    assert!(joined, "administrative direct child cleanup unconfirmed");
    let status = result
        .expect("administrative command original 10s deadline")
        .expect("administrative wait");
    for path in [&out_path, &err_path] {
        assert!(
            fs::metadata(path).unwrap().len() <= 65536,
            "bounded diagnostic output required"
        );
    }
    let output = fs::read(&out_path).unwrap();
    // Refusal bytes remain private and are not reflected by a failing assertion.
    let errors = fs::read(&err_path).unwrap();
    assert!(
        !status.success() || errors.is_empty(),
        "successful command unexpectedly emitted stderr"
    );
    (status.success(), output)
}
fn args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}
#[tokio::test]
async fn actual_staged_helper_startup_probe_selector_preserves_fields() {
    let owner = tempfile::tempdir().unwrap();
    let root = owner.path().canonicalize().unwrap();
    let exe = copied(&root);
    let stdout = root.join("probe.json");
    let stderr = root.join("probe.stderr");
    input(&stdout, &serde_json::to_vec(&json!({"status":"PASS","startup":{"code":"fixture_ready","started_backend":"fixture"}})).unwrap());
    input(&stderr, b"");
    let mut command = args(&["tproxy-startup-probe-fields", "--stdout"]);
    command.push(stdout.into());
    command.push("--stderr".into());
    command.push(stderr.into());
    let (ok, out) = run(&root, &exe, &command).await;
    assert!(ok, "actual startup helper command refused");
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "PROBE_STATUS\tPASS\nPROBE_CODE\tfixture_ready\nPROBE_STARTED_BACKEND\tfixture\n"
    );
}
#[tokio::test]
async fn actual_staged_helper_event_summary_selector_reads_real_record() {
    let owner = tempfile::tempdir().unwrap();
    let root = owner.path().canonicalize().unwrap();
    let exe = copied(&root);
    let events = root.join("events.jsonl");
    input(&events, b"{\"event_code\":\"ingress_backend_started\",\"level\":\"info\",\"message\":\"fixture\",\"fields\":{\"backend\":\"fixture\"}}\n");
    let mut command = args(&["tproxy-runtime-events-summary", "--runtime-events-jsonl"]);
    command.push(events.into());
    command.extend(args(&["--limit", "16"]));
    let (ok, out) = run(&root, &exe, &command).await;
    assert!(ok, "actual events helper command refused");
    let text = String::from_utf8(out).unwrap();
    assert!(text.lines().any(|line| line == "EVENTS_TOTAL\t1"));
    assert!(text.lines().any(|line| line == "EVENTS_BACKEND\tfixture"));
    assert!(text
        .lines()
        .any(|line| line == "EVENTS_STARTUP_HEALTH\thealthy"));
}
#[tokio::test]
async fn actual_staged_helper_evidence_selector_writes_original_schema() {
    let owner = tempfile::tempdir().unwrap();
    let root = owner.path().canonicalize().unwrap();
    let exe = copied(&root);
    let output = root.join("evidence.json");
    let events = root.join("events.jsonl");
    input(&events, b"{}\n");
    let mut command = args(&["write-tproxy-operator-evidence", "--output"]);
    command.push(output.clone().into());
    command.push("--runtime-events-jsonl".into());
    command.push(events.into());
    command.extend(args(&[
        "--events-total",
        "1",
        "--startup-health",
        "fixture",
        "--runtime-status",
        "fixture",
        "--product-verdict",
        "fixture",
        "--runtime-degradation-count",
        "0",
        "--failover-count",
        "0",
        "--terminal-failure-count",
        "0",
    ]));
    let (ok, _) = run(&root, &exe, &command).await;
    assert!(ok, "actual evidence helper command refused");
    let value: Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
    assert_eq!(value["artifact_schema"], "wide_linux_operator_evidence_v1");
    assert_eq!(value["records_scanned"], 1);
    assert_eq!(
        value["canonical_operator_loop"],
        json!(["doctor", "probe", "launch_or_run", "events", "evidence"])
    );
}
