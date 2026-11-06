#![cfg(any(unix, windows))]
//! Copied actual lab command surface; finite synthetic files and a direct owned child.
use aegis_core::secret_file;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

const ACTIONS: [&str; 6] = [
    "dependencies",
    "topology",
    "awgn",
    "poisson-channel",
    "privacy-channel",
    "bittraps-channel",
];
const MAX_OUTPUT: u64 = 64 * 1024;
const MAX_BINARY: u64 = 512 * 1024 * 1024;

fn hash_file(path: &Path) -> String {
    let file = File::open(path).unwrap();
    assert!(file.metadata().unwrap().is_file());
    let mut file = file.take(MAX_BINARY + 1);
    let mut hash = Sha256::new();
    let mut count = 0;
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        count += n as u64;
        assert!(count <= MAX_BINARY, "actual producer exceeds binary bound");
        hash.update(&buf[..n]);
    }
    assert!(count > 0);
    format!("{:x}", hash.finalize())
}
fn copied(dir: &Path) -> PathBuf {
    let source = std::env::var_os("AEGIS_TEST_TRANSPORT_LAB_EXECUTABLE")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_aegis-transport-lab").into());
    let source = PathBuf::from(source);
    let before = hash_file(&source);
    let copy = dir.join(if cfg!(windows) {
        "aegis-transport-lab.exe"
    } else {
        "aegis-transport-lab"
    });
    assert!(!copy.exists());
    fs::copy(&source, &copy).unwrap();
    assert_eq!(hash_file(&copy), before);
    assert_eq!(hash_file(&source), before);
    copy
}

struct Owner {
    child: Child,
    reaped: bool,
    kill_attempted: bool,
}
impl Owner {
    fn poll_until(&mut self, deadline: Instant) -> io::Result<Option<ExitStatus>> {
        loop {
            if let Some(status) = self.child.try_wait()? {
                self.reaped = true;
                return Ok(Some(status));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
    fn kill_once(&mut self) {
        if !self.reaped && !self.kill_attempted {
            self.kill_attempted = true;
            let _ = self.child.kill();
        }
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.kill_once();
        // Emergency request only. Failed/panicked cases require outer supervisor cleanup.
        let _ = self.child.try_wait();
    }
}
fn read_output(file: &mut File) -> Vec<u8> {
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut bytes = Vec::new();
    file.take(MAX_OUTPUT + 1).read_to_end(&mut bytes).unwrap();
    assert!(
        bytes.len() as u64 <= MAX_OUTPUT,
        "actual producer output exceeds bound"
    );
    bytes
}
fn run(dir: &Path, exe: &Path, args: &[&OsStr]) -> (ExitStatus, Vec<u8>, Vec<u8>) {
    // Exclusive owned descriptors avoid blocked stdin/pipe capture or reader threads.
    let mut stdout = tempfile::NamedTempFile::new_in(dir).unwrap();
    let mut stderr = tempfile::NamedTempFile::new_in(dir).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let child = Command::new(exe)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout.as_file().try_clone().unwrap()))
        .stderr(Stdio::from(stderr.as_file().try_clone().unwrap()))
        .spawn()
        .expect("actual lab producer spawn required");
    let mut owner = Owner {
        child,
        reaped: false,
        kill_attempted: false,
    };
    let operation = owner.poll_until(deadline);
    if !owner.reaped {
        owner.kill_once();
        let _ = owner.poll_until(Instant::now() + Duration::from_secs(2));
    }
    assert!(owner.reaped, "actual lab direct cleanup unconfirmed");
    let status = operation
        .expect("actual lab producer wait failed")
        .expect("actual lab producer exceeded 10-second operation");
    let out = read_output(stdout.as_file_mut());
    let err = read_output(stderr.as_file_mut());
    (status, out, err)
}
fn fixture() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let physical = dir.path().canonicalize().unwrap();
    (dir, physical)
}

#[test]
fn copied_lab_refuses_undeclared_demo_before_dispatch() {
    let (_owner, dir) = fixture();
    let exe = copied(&dir);
    let (status, out, err) = run(&dir, &exe, &[OsStr::new("demo")]);
    let demo = serde_json::from_slice::<Value>(&out)
        .ok()
        .is_some_and(|v| v["artifact_schema"] == "aegis_transport_lab_demo_v1");
    println!("lab_demo_probe copied_valid=true direct_reaped=true command_success={} demo_schema_match={}", status.success(), demo);
    assert!(
        !status.success(),
        "undeclared demo reached actual lab dispatch"
    );
    assert!(out.is_empty());
    assert!(String::from_utf8(err)
        .unwrap()
        .contains("expected a documented offline command; use --help"));
}

#[test]
fn copied_lab_inventory_and_snapshot_match_six_actions() {
    let (_owner, dir) = fixture();
    let exe = copied(&dir);
    let (status, out, err) = run(&dir, &exe, &[OsStr::new("--help")]);
    assert!(status.success() && err.is_empty());
    let help = String::from_utf8(out).unwrap();
    let observed: BTreeSet<_> = help
        .lines()
        .filter_map(|line| line.strip_prefix("aegis-transport-lab "))
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    assert_eq!(observed, ACTIONS.into_iter().collect());
    let (status, out, err) = run(&dir, &exe, &[OsStr::new("--build-info")]);
    assert!(status.success() && err.is_empty());
    let info: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(info["capabilities"], json!(ACTIONS));
    assert_eq!(info["tool"], "aegis-transport-lab");
    assert_eq!(info["binary_sha256"], hash_file(&exe));
}

#[test]
fn copied_lab_six_actions_keep_actual_bounded_handlers() {
    use aegis_transport_lab::research_covert_channels::{AwgnConfig, PoissonConfig};
    let (_owner, dir) = fixture();
    let exe = copied(&dir);
    let models = [
        (
            "dependencies",
            json!({"artifact_schema":"aegis_fleet_dependency_inventory_v1","dependencies":[{"id":1,"kind":"provider"}],"routes":[{"id":1,"provider":{"status":"known","dependency_ids":[1]},"dns":{"status":"not_required","dependency_ids":[]},"bootstrap":{"status":"unknown","dependency_ids":[]}}]}),
        ),
        (
            "topology",
            json!({"schema":"aegis_topology_papers_v1","provenance":{"kind":"synthetic","label":"cli_fixture"},"a":{"nodes":[0,1,2,3],"edges":[[0,1],[1,2],[2,3]]},"b":{"nodes":[0,1,2,3],"edges":[[0,1],[1,2],[2,3]]},"dependency_pairs":[[0,0],[1,1],[2,2],[3,3]],"failed_a":[0],"failed_b":[],"common_causes":[],"attack_removals":1,"seed":29}),
        ),
        (
            "awgn",
            serde_json::to_value(AwgnConfig {
                trials: 24,
                ..Default::default()
            })
            .unwrap(),
        ),
        (
            "poisson-channel",
            serde_json::to_value(PoissonConfig {
                trials: 24,
                ..Default::default()
            })
            .unwrap(),
        ),
        (
            "privacy-channel",
            json!({"model":"label_conditional_wasserstein","prior":[0.5,0.5],"features":2,"conditionals":[1.0,0.0,0.0,1.0],"metric":[0.0,1.0,1.0,0.0],"budget":0.5,"iterations":1000,"gap_bits":0.001,"timeout_ms":1000}),
        ),
        (
            "bittraps-channel",
            json!({"model":{"horizon":3,"arrival_sizes":[0,2],"initial":[0.5,0.5],"transition":[[0.8,0.2],[0.2,0.8]],"service":[[2,1.0]],"queue_cap":32,"padding":true},"candidates":[[[2,1.0]]],"max_padding":128.0,"max_queue_area":128.0,"max_tail":128.0}),
        ),
    ];
    for (index, (action, input)) in models.into_iter().enumerate() {
        let path = dir.join(format!("model-{index}.json"));
        let bytes = serde_json::to_vec(&input).unwrap();
        secret_file::write_private_new(&path, &bytes).unwrap();
        let (status, out, err) = run(&dir, &exe, &[OsStr::new(action), path.as_os_str()]);
        assert!(
            status.success() && err.is_empty(),
            "retained model action failed"
        );
        let report: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(fs::read(path).unwrap(), bytes);
        match action {
            "dependencies" => {
                assert_eq!(report["provenance"], "operator_declared_only");
                assert_eq!(report["provider_cuts"]["minimal_outage_sets"], json!([[1]]));
                assert_eq!(report["dependency_independence_verified"], false);
            }
            "topology" => {
                assert_eq!(report["schema"], "aegis_topology_papers_report_v1");
                assert_eq!(report["attacks"].as_array().unwrap().len(), 3);
                assert_eq!(report["evidence_authenticated"], false);
            }
            "awgn" => {
                assert_eq!(report["config"]["trials"], 24);
                assert_eq!(report["fresh_codebook_per_trial"], true);
                assert_eq!(report["numerical_not_exact_distribution_proof"], true);
            }
            "poisson-channel" => {
                assert_eq!(report["config"]["trials"], 24);
                assert_eq!(report["fresh_codebook_per_transmission"], true);
                assert_eq!(
                    report["queue_started_empty_not_stationary_burke_claim"],
                    true
                );
            }
            "privacy-channel" => {
                assert_eq!(report["model"], "label_conditional_wasserstein_theory_only");
                assert_eq!(report["installed_runtime"], false);
                assert_eq!(report["rigorous_interval_certificate"], false);
            }
            "bittraps-channel" => {
                assert_eq!(report["schema"], "aegis_bittraps_finite_stream_grid_v1");
                assert_eq!(report["selected_candidate"], 0);
                assert_eq!(report["installed_runtime"], false);
            }
            _ => unreachable!(),
        }
        println!(
            "lab_retained_action ordinal={} actual_handler_success=true direct_reaped=true",
            index + 1
        );
    }
}
