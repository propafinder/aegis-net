//! Actual producer, protected seal, and backend CLI phase dispatch on isolated
//! filesystem paths. No fake Publication/Context/renderer proof is used.
//! Explicitly ignored: requires disposable root Linux with genuine planner
//! prerequisites (CAP_NET_ADMIN/systemd/tun/IPv6/tools) and owned rollback.
//! The worker can publish unit policy and reload PID1; never run on a live host.
use super::worker_successor_tests::{response, spawn, OwnedChild};
use super::*;
use crate::profile_auto_transaction::receipt_store::{self, PrepareInputs};
use std::{
    fs,
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, PermissionsExt},
    },
};

/// Frozen acceptance selectors require the actual installed release payload.
/// Missing paths are a hard setup failure, never a synthetic substitute.
fn installed_input(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).expect("native installed payload input required"))
}
fn admit_installed_receipt(stage: &Path) {
    let public_payload_root = installed_input("AEGIS_AUTO_TEST_PUBLIC_PAYLOAD_ROOT");
    let candidate_binary = installed_input("AEGIS_AUTO_TEST_CANDIDATE_BINARY");
    let installed_binary = installed_input("AEGIS_AUTO_TEST_INSTALLED_BINARY");
    let mut guard = StageGuard::admit(Store::reopen(stage, 0).unwrap()).unwrap();
    receipt_store::admit_prepare(
        &mut guard,
        PrepareInputs {
            public_payload_root: &public_payload_root,
            candidate_binary: &candidate_binary,
            installed_binary: &installed_binary,
            source_manifest_url: None,
            source_release_channel: None,
        },
    )
    .unwrap();
}

use crate::profile_auto_stderr_drain::{drain_worker_stderr, WorkerStderrSummary};

struct WorkerStderrDrain {
    thread: Option<std::thread::JoinHandle<()>>,
    result: std::sync::mpsc::Receiver<std::io::Result<WorkerStderrSummary>>,
}
impl WorkerStderrDrain {
    fn start(child: &mut OwnedChild) -> Self {
        let stderr = child.0.stderr.take().expect("worker stderr pipe required");
        let (sender, result) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::spawn(move || {
            let _ = sender.send(drain_worker_stderr(stderr));
        });
        Self {
            thread: Some(thread),
            result,
        }
    }
    fn finish(&mut self) -> bool {
        let Some(thread) = self.thread.take() else {
            return true;
        };
        match self.result.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(Ok(summary)) => {
                if thread.join().is_err() {
                    eprintln!("AUTO_FIXTURE_WORKER_STDERR thread_panic");
                    return false;
                }
                eprintln!(
                    "AUTO_FIXTURE_WORKER_STDERR bytes={} sha256={} tags={}",
                    summary.bytes,
                    summary.sha256,
                    summary.tags.join(",")
                );
                true
            }
            Ok(Err(_)) => {
                let _ = thread.join();
                eprintln!("AUTO_FIXTURE_WORKER_STDERR read_error");
                false
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                eprintln!("AUTO_FIXTURE_WORKER_STDERR drain_timeout");
                false
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                let _ = thread.join();
                eprintln!("AUTO_FIXTURE_WORKER_STDERR thread_panic");
                false
            }
        }
    }
}
impl Drop for WorkerStderrDrain {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

/// The frozen selectors keep their positive assertions while routing their
/// commands through one actual worker holding the same InstallLock.
struct ActualWorker {
    stage: PathBuf,
    child: OwnedChild,
    stderr: WorkerStderrDrain,
}
impl ActualWorker {
    fn new(stage: &Path) -> Self {
        admit_installed_receipt(stage);
        let mut child = spawn(stage);
        let stderr = WorkerStderrDrain::start(&mut child);
        let worker = Self {
            stage: stage.into(),
            child,
            stderr,
        };
        assert_eq!(response(&worker.child)["status"], "ready");
        worker
    }
    fn resume(stage: &Path) -> Self {
        let mut child = spawn(stage);
        let stderr = WorkerStderrDrain::start(&mut child);
        let worker = Self {
            stage: stage.into(),
            child,
            stderr,
        };
        assert_eq!(response(&worker.child)["status"], "ready");
        worker
    }
    fn finish_terminal(&mut self) {
        self.child.finish_terminal();
        assert!(self.stderr.finish(), "worker stderr drain refused");
    }
    fn finish_nonterminal(&mut self) {
        use std::time::{Duration, Instant};
        drop(self.child.0.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.child.0.try_wait().unwrap() {
                assert!(!status.success(), "nonterminal worker must refuse");
                break;
            }
            assert!(Instant::now() < deadline, "bounded worker exit deadline");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(self.stderr.finish(), "worker stderr drain refused");
    }
    fn command(&mut self, args: CommandArgs) -> Result<Option<String>> {
        let (stage, words): (&Path, Vec<&str>) = match &args {
            CommandArgs::Inspect {
                stage,
                field: InspectField::ProductMode,
            } => (stage, vec!["inspect", "--field", "product-mode"]),
            CommandArgs::Verify {
                stage,
                phase: VerifyPhase::BeforeCustody,
            } => (stage, vec!["verify", "--phase", "before-custody"]),
            CommandArgs::Verify {
                stage,
                phase: VerifyPhase::PublishedConfig,
            } => (stage, vec!["verify", "--phase", "published-config"]),
            CommandArgs::Verify {
                stage,
                phase: VerifyPhase::BeforeActivation,
            } => (stage, vec!["verify", "--phase", "before-activation"]),
            CommandArgs::BindRuntimeService {
                stage,
                service_user: ServiceUser::Root,
            } => (
                stage,
                vec!["bind-runtime-service", "--service-user", "root"],
            ),
            CommandArgs::BindRuntimeService {
                stage,
                service_user: ServiceUser::AegisSvc,
            } => (
                stage,
                vec!["bind-runtime-service", "--service-user", "aegis-svc"],
            ),
            CommandArgs::CommitCustody {
                stage,
                service_user: ServiceUser::Root,
                was_active: false,
            } => (
                stage,
                vec![
                    "commit-custody",
                    "--service-user",
                    "root",
                    "--was-active",
                    "0",
                ],
            ),
            CommandArgs::CommitCustody {
                stage,
                service_user: ServiceUser::AegisSvc,
                was_active: false,
            } => (
                stage,
                vec![
                    "commit-custody",
                    "--service-user",
                    "aegis-svc",
                    "--was-active",
                    "0",
                ],
            ),
            CommandArgs::CommitState { stage } => (stage, vec!["commit-state"]),
            CommandArgs::CommitConfig { stage } => (stage, vec!["commit-config"]),
            CommandArgs::SealInstallReceipt { stage } => (stage, vec!["seal-install-receipt"]),
            CommandArgs::PublishServicePolicy { stage } => (stage, vec!["publish-service-policy"]),
            CommandArgs::ReloadServicePolicy { stage } => (stage, vec!["reload-service-policy"]),
            CommandArgs::PublishMetadata { stage } => (stage, vec!["publish-metadata"]),
            CommandArgs::BeginCapture { stage } => (stage, vec!["begin-capture"]),
            CommandArgs::Finalize { stage } => (stage, vec!["finalize"]),
            _ => return Err(super::super::refuse()),
        };
        if stage != self.stage {
            return Err(super::super::refuse());
        }
        // This parent-only label goes to the selected test's captured stderr,
        // never the undrained child stderr pipe. All words come from the fixed
        // command mapping above; no config, path, or worker error is printed.
        let command_started = std::time::Instant::now();
        eprintln!("AUTO_FIXTURE_STEP {} begin", words[0]);
        let frame = serde_json::to_vec(&serde_json::json!({"command": words})).map_err(fail)?;
        let input = self
            .child
            .0
            .stdin
            .as_mut()
            .ok_or_else(super::super::refuse)?;
        input.write_all(&frame).map_err(fail)?;
        input.write_all(b"\n").map_err(fail)?;
        let answer = response(&self.child);
        eprintln!(
            "AUTO_FIXTURE_STEP {} {} elapsed_ms={}",
            words[0],
            if answer["status"] == "ok" {
                "ok"
            } else {
                "error"
            },
            command_started.elapsed().as_millis()
        );
        if words[0] == "begin-capture" && answer["status"] == "error" {
            fixture_begin_capture_diagnostic(&answer);
        }
        if words[0] == "bind-runtime-service" && answer["status"] == "error" {
            fixture_bind_runtime_diagnostic(&answer);
        }
        if words[0] == "reload-service-policy" && answer["status"] == "error" {
            fixture_reload_diagnostic(&answer);
        }
        if matches!(words[0], "commit-state" | "begin-capture" | "finalize")
            || answer["status"] != "ok"
        {
            fixture_header_state(stage);
        }
        match answer["status"].as_str() {
            Some("ok") => match answer.get("value") {
                Some(serde_json::Value::Null) => Ok(None),
                Some(serde_json::Value::String(value)) => Ok(Some(value.clone())),
                _ => Err(super::super::refuse()),
            },
            Some("error") => Err(answer["reason"]
                .as_str()
                .ok_or_else(super::super::refuse)?
                .to_owned()),
            _ => Err(super::super::refuse()),
        }
    }
}

fn fixture_step(mode: AutoMode, step: &'static str) {
    eprintln!("AUTO_FIXTURE_MODE {} {step}", mode.name());
}

/// Only the production worker's closed, typed error fields reach this test log.
/// Never print a raw worker response, path, config value, or error string.
fn fixture_begin_capture_diagnostic(answer: &serde_json::Value) {
    let step = answer
        .get("begin_capture_step")
        .and_then(serde_json::Value::as_str)
        .filter(|value| BEGIN_CAPTURE_STEPS.contains(value))
        .unwrap_or("unknown");
    eprintln!("AUTO_FIXTURE_BEGIN_CAPTURE_STEP {step}");

    if let Some(diagnostic) = answer.get("diagnostic").filter(|_| step == "pid1_start") {
        if let (Some(phase), Some(cause), Some(errno)) = (
            diagnostic.get("phase").and_then(serde_json::Value::as_str),
            diagnostic.get("cause").and_then(serde_json::Value::as_str),
            diagnostic.get("errno").and_then(serde_json::Value::as_u64),
        ) {
            let encoded = format!("AUTO PID1 start requires recovery:{phase}:{cause}:{errno}");
            if crate::profile_auto_stopped_service::pid1::start_failure_diagnostic(&encoded)
                .as_ref()
                == Some(diagnostic)
            {
                eprintln!("AUTO_FIXTURE_PID1_DIAGNOSTIC phase={phase} cause={cause} errno={errno}");
            }
        }
    }
    if let Some(refusal) = answer
        .get("capture_refusal")
        .filter(|_| step == "capture_ready")
    {
        if let (Some(reason), Some(source), Some(line)) = (
            refusal.get("reason").and_then(serde_json::Value::as_str),
            refusal.get("source").and_then(serde_json::Value::as_str),
            refusal.get("line").and_then(serde_json::Value::as_u64),
        ) {
            let encoded = format!("{CAPTURE_FAILURE_PREFIX}{reason}:{source}:{line}");
            if capture_failure_diagnostic(&encoded).as_ref() == Some(refusal) {
                eprintln!(
                    "AUTO_FIXTURE_CAPTURE_REFUSAL reason={reason} source={source} line={line}"
                );
            }
        }
    }
}

/// Only the production worker's closed BindRuntimeService coordinate reaches
/// this test log; anything else prints the fixed label "unknown".
fn fixture_bind_runtime_diagnostic(answer: &serde_json::Value) {
    let step = answer
        .get("bind_runtime_step")
        .and_then(serde_json::Value::as_str)
        .filter(|value| BIND_RUNTIME_STEPS.contains(value))
        .unwrap_or("unknown");
    eprintln!("AUTO_FIXTURE_BIND_RUNTIME_STEP {step}");
}

/// The worker already reports a closed reload coordinate. Keep it when the
/// fixture rejects a phase; raw responses and unknown strings stay private.
fn fixture_reload_diagnostic(answer: &serde_json::Value) {
    let step = answer
        .get("reload_failure")
        .and_then(serde_json::Value::as_str)
        .filter(|value| reload_failure_label(value))
        .unwrap_or("unknown");
    eprintln!("AUTO_FIXTURE_RELOAD_FAILURE {step}");
}

/// Diagnostics read only typed, bounded protected stage facts. A failed read
/// produces one fixed label and cannot turn a refused product phase into PASS.
fn fixture_header_state(stage: &Path) {
    let snapshot = (|| -> Result<(Phase, bool, bool, bool, bool, bool)> {
        let store = Store::reopen(stage, 0)?;
        let bytes = store.read(Path::new("header.json"))?;
        let header: Header = serde_json::from_slice(&bytes).map_err(fail)?;
        Ok((
            header.phase,
            header.capture_started,
            header.pending.is_some(),
            header.unit_pending.is_some(),
            store
                .read(Path::new("receipts/activation-owner/terminal.json"))
                .is_ok(),
            store
                .read(Path::new("receipts/activation-owner/stop-completed.json"))
                .is_ok(),
        ))
    })();
    match snapshot {
        Ok((phase, captured, pending, unit_pending, terminal, stopped)) => {
            let phase = match phase {
                Phase::Prepared => "prepared",
                Phase::Custody => "custody",
                Phase::State => "state",
                Phase::Config => "config",
                Phase::Metadata => "metadata",
                Phase::Finalized => "finalized",
                Phase::RolledBack => "rolled_back",
                Phase::NativeRecoveryRequired => "recovery_required",
            };
            eprintln!(
                "AUTO_FIXTURE_HEADER phase_{phase} captured_{captured} pending_{pending} unit_pending_{unit_pending} terminal_readable_{terminal} stop_completed_readable_{stopped}"
            );
        }
        Err(_) => eprintln!("AUTO_FIXTURE_HEADER unavailable"),
    }
}

/// Supplemental manager readback after the typed owner has durably recorded a
/// CompletedStop. PID 1 may collect a stopped transient unit before this
/// separate query, so the authenticated stop receipt remains the authority.
fn observe_private_unit_stopped(unit: &str) {
    let suffix = unit
        .strip_prefix("aegis-auto@")
        .and_then(|name| name.strip_suffix(".service"))
        .expect("private unit template refused");
    assert!(suffix.len() == 64 && suffix.bytes().all(|b| b.is_ascii_hexdigit()));
    let mut child = match std::process::Command::new("/usr/bin/systemctl")
        .args([
            "show",
            unit,
            "-p",
            "LoadState",
            "-p",
            "ActiveState",
            "-p",
            "MainPID",
            "-p",
            "ControlPID",
            "-p",
            "ControlGroup",
            "--no-pager",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => {
            eprintln!("AUTO_FIXTURE_STOP manager_readback_unavailable");
            return;
        }
    };
    let shown = (|| -> Option<Vec<u8>> {
        let mut stdout = child.stdout.take()?;
        let fd = stdout.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return None;
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut output = Vec::new();
        let mut status = None;
        let mut eof = false;
        while std::time::Instant::now() < deadline {
            let mut buffer = [0u8; 512];
            match stdout.read(&mut buffer) {
                Ok(0) => eof = true,
                Ok(size) if output.len() + size <= 4096 => {
                    output.extend_from_slice(&buffer[..size])
                }
                Ok(_) => return None,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => return None,
            }
            if status.is_none() {
                status = child.try_wait().ok().flatten();
            }
            if eof && status.is_some() {
                return status.filter(|value| value.success()).map(|_| output);
            }
            let mut ready = libc::pollfd {
                fd,
                events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                revents: 0,
            };
            let _ = unsafe { libc::poll(&mut ready, 1, 20) };
        }
        None
    })();
    if shown.is_none() {
        let _ = child.kill();
    }
    let _ = child.wait();
    let Some(shown) = shown else {
        eprintln!("AUTO_FIXTURE_STOP manager_readback_unavailable");
        return;
    };
    let Ok(text) = String::from_utf8(shown) else {
        eprintln!("AUTO_FIXTURE_STOP manager_readback_unavailable");
        return;
    };
    let value = |key: &str| -> Option<&str> {
        text.lines()
            .find_map(|line| line.strip_prefix(&format!("{key}=")))
    };
    if value("LoadState") == Some("not-found") {
        eprintln!("AUTO_FIXTURE_STOP manager_collected");
        return;
    }
    if value("ActiveState") != Some("inactive")
        || value("MainPID") != Some("0")
        || value("ControlPID") != Some("0")
    {
        eprintln!("AUTO_FIXTURE_STOP manager_readback_changed");
        return;
    }
    if let Some(cgroup) = value("ControlGroup").filter(|value| !value.is_empty()) {
        if cgroup != format!("/system.slice/{unit}") {
            eprintln!("AUTO_FIXTURE_STOP cgroup_name_changed");
            return;
        }
        let dir = Path::new("/sys/fs/cgroup").join(cgroup.trim_start_matches('/'));
        match fs::read(dir.join("cgroup.procs")) {
            Ok(bytes) if bytes.is_empty() => {}
            Ok(_) => {
                eprintln!("AUTO_FIXTURE_STOP named_cgroup_populated");
                return;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                eprintln!("AUTO_FIXTURE_STOP cgroup_readback_unavailable");
                return;
            }
        }
    }
    eprintln!("AUTO_FIXTURE_STOP manager_collected_or_inactive");
}

fn assert_compensated_wide(guard: &StageGuard) {
    let terminal_leaf = Path::new("receipts/activation-owner/terminal.json");
    let submitted_leaf = Path::new("receipts/activation-owner/stop-submitted.json");
    let completed_leaf = Path::new("receipts/activation-owner/stop-completed.json");
    let terminal_bytes = guard.store.read(terminal_leaf).unwrap();
    let submitted_bytes = guard.store.read(submitted_leaf).unwrap();
    let completed_bytes = guard.store.read(completed_leaf).unwrap();
    for (leaf, bytes) in [
        (terminal_leaf, terminal_bytes.as_slice()),
        (submitted_leaf, submitted_bytes.as_slice()),
        (completed_leaf, completed_bytes.as_slice()),
    ] {
        assert!(guard.header.leaves.get(leaf) == Some(&digest(bytes)));
    }
    let terminal: serde_json::Value = serde_json::from_slice(&terminal_bytes).unwrap();
    let submitted: serde_json::Value = serde_json::from_slice(&submitted_bytes).unwrap();
    let completed: serde_json::Value = serde_json::from_slice(&completed_bytes).unwrap();
    let submitted_sha = digest(&submitted_bytes);
    let completed_sha = digest(&completed_bytes);
    assert!(terminal["outcome"] == "compensated-failure");
    assert!(terminal["stop_submitted_sha256"].as_str() == Some(submitted_sha.as_str()));
    assert!(terminal["stop_completed_sha256"].as_str() == Some(completed_sha.as_str()));
    assert!(terminal["native_inverse_sha256"]
        .as_str()
        .is_some_and(|value| value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())));
    assert!(terminal["post_deny_policy_sha256"]
        .as_str()
        .is_some_and(|value| value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())));
    assert!(submitted["unit"] == completed["unit"]);
    assert!(submitted["job_id"] == completed["job_id"]);
    assert!(submitted["job_path"] == completed["job_path"]);
    assert!(completed["stop_submitted_sha256"].as_str() == Some(submitted_sha.as_str()));
    assert!(terminal["private_unit"] == completed["unit"]);
    let unit = completed["unit"]
        .as_str()
        .expect("private stop unit absent");
    observe_private_unit_stopped(unit);
}
fn private_write(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn formatter_replace_preserving_metadata(path: &Path, bytes: &[u8]) {
    let original = fs::symlink_metadata(path).unwrap();
    assert!(original.file_type().is_file());
    assert_eq!(original.nlink(), 1);
    let replacement = path.with_file_name("formatter-new");
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&replacement)
        .unwrap();
    output.write_all(bytes).unwrap();
    std::os::unix::fs::chown(&replacement, Some(original.uid()), Some(original.gid())).unwrap();
    fs::set_permissions(
        &replacement,
        fs::Permissions::from_mode(original.mode() & 0o7777),
    )
    .unwrap();
    output.sync_all().unwrap();
    drop(output);
    fs::rename(&replacement, path).unwrap();
    let current = fs::symlink_metadata(path).unwrap();
    assert!(current.file_type().is_file());
    assert_ne!(current.ino(), original.ino());
    assert_eq!(
        (current.uid(), current.gid(), current.mode() & 0o7777),
        (original.uid(), original.gid(), original.mode() & 0o7777)
    );
}
// Public deterministic diagnostic inputs, never issued or used for networking.
// The fixture must satisfy the actual relay format and explicit SOCKS schema.
fn actual_fixture_settings() -> String {
    if let Some(path) = std::env::var_os("AEGIS_AUTO_TEST_RELAY_FIXTURE_CONFIG") {
        let path = PathBuf::from(path);
        assert!(path.is_absolute());
        let info = fs::symlink_metadata(&path).unwrap();
        assert!(info.file_type().is_file());
        assert_eq!(info.uid(), 0);
        assert_eq!(info.nlink(), 1);
        assert_eq!(info.mode() & 0o777, 0o600);
        assert!(info.len() > 0 && info.len() <= 1 << 20);
        let text = fs::read_to_string(&path).unwrap();
        let accepted: aegis_core::Settings = toml::from_str(&text).unwrap();
        validate_actual_fixture(&accepted);
        assert_eq!(accepted.relay.server, "10.231.80.2:443");
        assert_eq!(accepted.relay.server_name, "relay.aegis.test");
        assert_eq!(
            accepted.relay.udp_transport_priority,
            Some(vec![aegis_core::TunnelTransportFamily::GrpcDatagram])
        );
        return text;
    }
    format!(
        "mode = 'relay'\n[relay]\nserver = '127.0.0.1:443'\nserver_name = 'localhost'\nauth_token = '{}'\ntransport_priority = ['grpc_stream']\n[ingress]\nprimary = 'socks5'\n[socks]\nlisten = '127.0.0.1:0'\nauth_token = '{}'\n[direct]\npersist_state = false\n",
        "0123456789abcdef".repeat(4),
        "fedcba9876543210".repeat(4)
    )
}
const QA_REDIRECT_INTERFACE: &str = "aegisacp0";
const QA_REDIRECT_LISTEN: &str = "10.231.81.1:15080";

fn append_qa_redirect_scope(text: &mut String) {
    // This source-built native fixture owns the ingress peer. Production
    // callers must supply their own explicitly scoped interface.
    text.push_str("[ingress.wide]\nrollout_profile = 'prerouting_scoped'\n");
    text.push_str("prerouting_interface = 'aegisacp0'\n");
    text.push_str("listen = '10.231.81.1:15080'\n");
}

fn qa_redirect_scope(settings: &aegis_core::Settings) -> bool {
    settings.ingress.wide.rollout_profile == aegis_core::WideRolloutProfile::PreroutingScoped
        && settings.ingress.wide.prerouting_interface.as_deref() == Some(QA_REDIRECT_INTERFACE)
        && settings.ingress.wide.listen.to_string() == QA_REDIRECT_LISTEN
}

fn validate_actual_fixture(settings: &aegis_core::Settings) {
    assert!(matches!(
        settings.ingress.primary,
        aegis_core::IngressPrimary::Socks5
    ));
    settings.validate_privacy_plan().unwrap();
    settings.socks.validate_tcp_policy().unwrap();
    settings.validate_inner_tls().unwrap();
    if settings.relay.inner_tls.is_some() {
        assert!(settings.relay.auth_token.is_empty());
    } else {
        aegis_core::auth_token::validate(&settings.relay.auth_token).unwrap();
    }
}
fn native_retain_root_validated() -> bool {
    static RETAIN: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *RETAIN.get_or_init(|| {
        let Some(root) = std::env::var_os("AEGIS_AUTO_TEST_RETAIN_STAGE_ROOT") else {
            return false;
        };
        let root = PathBuf::from(root);
        let parent = root.parent().expect("native retention parent required");
        assert_eq!(
            root.file_name(),
            Some(std::ffi::OsStr::new("retained-stages"))
        );
        assert_eq!(parent.parent(), Some(Path::new("/tmp")));
        assert!(parent
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("aegis-auto-fs-owned-"));
        for path in [parent, root.as_path()] {
            let metadata = fs::symlink_metadata(path).expect("native retention anchor required");
            assert!(metadata.file_type().is_dir());
            assert_eq!(metadata.uid(), 0);
            assert_eq!(metadata.gid(), 0);
            assert_eq!(metadata.mode() & 0o7777, 0o700);
        }
        true
    })
}

struct NativeFixtureDir {
    directory: Option<tempfile::TempDir>,
    retain: bool,
}
impl NativeFixtureDir {
    fn path(&self) -> &Path {
        self.directory.as_ref().unwrap().path()
    }

    // Native cohort custody keeps the actual protected stage and every path
    // referenced by its published fixed unit.  This is only a locator: the
    // later read-only inspector must authenticate the stage and unit history.
    fn retain_after_terminal(&mut self) {
        if !self.retain {
            return;
        }
        let directory = self.directory.take().unwrap();
        let _ = directory.keep();
    }
}
impl Drop for NativeFixtureDir {
    fn drop(&mut self) {
        if std::thread::panicking() {
            if let Some(directory) = self.directory.take() {
                let _ = directory.keep();
            }
        }
    }
}
fn actual_prepared(mode: AutoMode) -> (NativeFixtureDir, PathBuf, PathBuf) {
    actual_prepared_state(mode, false, false)
}
fn actual_prepared_state(
    mode: AutoMode,
    custom_state: bool,
    existing_default: bool,
) -> (NativeFixtureDir, PathBuf, PathBuf) {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "requires disposable root Linux; never silently skip"
    );
    // The fixed systemd unit has PrivateTmp=true. Its actual process cannot
    // read a fixture beneath the controller's /tmp, even though the root
    // worker can. Keep the fixture on the real service-visible /var/lib mount.
    let visible_parent = Path::new("/var/lib");
    let metadata = fs::symlink_metadata(visible_parent).unwrap();
    assert!(metadata.file_type().is_dir());
    assert_eq!(std::os::unix::fs::MetadataExt::uid(&metadata), 0);
    assert_eq!(metadata.permissions().mode() & 0o022, 0);
    let tmp = NativeFixtureDir {
        directory: Some(
            tempfile::Builder::new()
                .prefix("aegis-auto-native-")
                .tempdir_in(visible_parent)
                .unwrap(),
        ),
        retain: native_retain_root_validated(),
    };
    let runtime_user = if mode == AutoMode::FullWideTun {
        ServiceUser::Root
    } else {
        ServiceUser::AegisSvc
    };
    if runtime_user == ServiceUser::AegisSvc {
        let policy = if mode == AutoMode::SocksOnly {
            crate::profile_auto_runtime_identity::RuntimePolicy::DedicatedNone
        } else {
            crate::profile_auto_runtime_identity::RuntimePolicy::DedicatedBind
        };
        let binding =
            crate::profile_auto_runtime_identity::resolve_runtime_binding(runtime_user, policy)
                .expect("installed dedicated runtime account required");
        std::os::unix::fs::chown(tmp.path(), Some(0), Some(binding.identity().gid())).unwrap();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o750)).unwrap();
    } else {
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let config = tmp.path().join("config");
    let metadata = tmp.path().join("metadata");
    let state = tmp.path().join("state");
    for p in [&config, &metadata] {
        fs::create_dir(p).unwrap();
        fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut text = actual_fixture_settings();
    // The installed relay keeps its identity tree private. The public CA is
    // copied into the selected config source so publication can assign the
    // dedicated runtime identity without exposing relay keys or token files.
    let selected: aegis_core::Settings = toml::from_str(&text).unwrap();
    if let Some(source_ca) = selected.relay.ca_cert.as_ref() {
        assert!(source_ca.is_absolute());
        let local_ca = config.join("ca.pem");
        private_write(&local_ca, &fs::read(source_ca).unwrap());
        let original_line = format!(
            "ca_cert = {}\n",
            toml::Value::String(source_ca.to_str().unwrap().to_owned())
        );
        assert_eq!(text.matches(&original_line).count(), 1);
        text = text.replacen(
            &original_line,
            &format!(
                "ca_cert = {}\n",
                toml::Value::String(local_ca.to_str().unwrap().to_owned())
            ),
            1,
        );
    }
    if let Some(inner) = selected.relay.inner_tls.as_ref() {
        // The issued client identity is captured under this fixture boundary.
        // The real publisher then assigns its key to the bound Main identity;
        // neither Main nor its renderer needs access to the private relay tree.
        for (key, leaf, source) in [
            ("server_ca", "inner-ca.pem", &inner.server_ca),
            ("cert", "device.pem", &inner.cert),
            ("key", "device.key", &inner.key),
        ] {
            assert!(source.is_absolute());
            let local = config.join(leaf);
            private_write(&local, &fs::read(source).unwrap());
            let original_line = format!(
                "{key} = {}\n",
                toml::Value::String(source.to_str().unwrap().to_owned())
            );
            assert_eq!(text.matches(&original_line).count(), 1);
            text = text.replacen(
                &original_line,
                &format!(
                    "{key} = {}\n",
                    toml::Value::String(local.to_str().unwrap().to_owned())
                ),
                1,
            );
        }
    }
    if custom_state {
        let prior = tmp.path().join("external-prior-state.json");
        private_write(&prior, b"synthetic prior state bytes");
        text.push_str(&format!(
            "state_path = {}\n",
            toml::Value::String(prior.to_str().unwrap().to_string())
        ));
    }
    if existing_default {
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        private_write(
            &state.join("state.json"),
            b"existing default state preserved",
        );
    }
    if mode == AutoMode::WideRedirectSafe {
        append_qa_redirect_scope(&mut text);
    }
    // Actual product schema admission is required before the producer path.
    let accepted: aegis_core::Settings = toml::from_str(&text).unwrap();
    validate_actual_fixture(&accepted);
    let wide_interface = if mode == AutoMode::WideRedirectSafe {
        assert!(qa_redirect_scope(&accepted));
        accepted.ingress.wide.prerouting_interface.clone()
    } else {
        None
    };
    assert!(!accepted.direct.persist_state);
    private_write(&config.join("aegis.toml"), text.as_bytes());
    private_write(
        &metadata.join("wide-profile.json"),
        &serde_json::to_vec(&serde_json::json!({"product_mode":mode.name()})).unwrap(),
    );
    let prepared = prepare::prepare(prepare::Request {
        config_root: config.clone(),
        state_target: state,
        metadata_target: metadata,
        bundle: None,
        service_uid: 0,
        operator_uid: 0,
        admitted_home: Some(tmp.path().to_path_buf()),
        wide_interface,
        relay_pin: None,
        masque_server: None,
        explicit_masque_ca: None,
        prior_native_markers: true,
        requested_mode: None,
    })
    .unwrap();
    assert_eq!(prepared.mode, mode.name());
    // Store::create requires its immediate parent to remain administrative
    // root:root 0700. The outer fixture boundary is root:service-group 0750
    // so the dedicated Main can reach its published config and state.
    let admin = tmp.path().join("admin");
    fs::create_dir(&admin).unwrap();
    fs::set_permissions(&admin, fs::Permissions::from_mode(0o700)).unwrap();
    let stage = seal(&admin, &prepared, 0, 0, None, Path::new("/dev/null"), None).unwrap();
    (tmp, stage, config)
}
fn assert_old_fixed_actor(expected: ServiceUser) {
    let shown = std::process::Command::new("/usr/bin/systemctl")
        .args([
            "show",
            "aegis-client.service",
            "-p",
            "LoadState",
            "-p",
            "ActiveState",
            "-p",
            "SubState",
            "-p",
            "MainPID",
            "-p",
            "ControlPID",
            "-p",
            "User",
            "-p",
            "Group",
            "--no-pager",
        ])
        .output()
        .unwrap();
    assert!(shown.status.success());
    let text = String::from_utf8(shown.stdout).unwrap();
    let value = |key: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(&format!("{key}=")))
            .unwrap()
    };
    assert_eq!(value("LoadState"), "loaded");
    assert_eq!(value("ActiveState"), "inactive");
    assert_eq!(value("SubState"), "dead");
    assert_eq!(value("MainPID"), "0");
    assert_eq!(value("ControlPID"), "0");
    let name = if expected == ServiceUser::Root {
        ""
    } else {
        "aegis-svc"
    };
    assert_eq!(value("User"), name);
    assert_eq!(value("Group"), name);
}
fn actual_before_formatter(
    worker: &mut ActualWorker,
    stage: &Path,
    mode: AutoMode,
    old_service_user: ServiceUser,
) {
    fixture_step(mode, "preformatter_begin");
    let service_user = if mode == AutoMode::FullWideTun {
        ServiceUser::Root
    } else {
        ServiceUser::AegisSvc
    };
    assert_eq!(
        worker
            .command(CommandArgs::Inspect {
                stage: stage.into(),
                field: InspectField::ProductMode
            })
            .unwrap()
            .as_deref(),
        Some(mode.name())
    );
    worker
        .command(CommandArgs::Verify {
            stage: stage.into(),
            phase: VerifyPhase::BeforeCustody,
        })
        .unwrap();
    worker
        .command(CommandArgs::BindRuntimeService {
            stage: stage.into(),
            service_user,
        })
        .unwrap();
    // Custody still observes the original fixed service, which runs as root.
    // The new private runtime is bound independently above.
    worker
        .command(CommandArgs::CommitCustody {
            stage: stage.into(),
            service_user: old_service_user,
            was_active: false,
        })
        .unwrap();
    worker
        .command(CommandArgs::CommitState {
            stage: stage.into(),
        })
        .unwrap();
    worker
        .command(CommandArgs::CommitConfig {
            stage: stage.into(),
        })
        .unwrap();
    worker
        .command(CommandArgs::SealInstallReceipt {
            stage: stage.into(),
        })
        .unwrap();
    worker
        .command(CommandArgs::PublishServicePolicy {
            stage: stage.into(),
        })
        .unwrap();
    worker
        .command(CommandArgs::ReloadServicePolicy {
            stage: stage.into(),
        })
        .unwrap();
    worker
        .command(CommandArgs::Verify {
            stage: stage.into(),
            phase: VerifyPhase::PublishedConfig,
        })
        .unwrap();
    worker
        .command(CommandArgs::PublishMetadata {
            stage: stage.into(),
        })
        .unwrap();
    worker
        .command(CommandArgs::Verify {
            stage: stage.into(),
            phase: VerifyPhase::BeforeActivation,
        })
        .unwrap();
    if mode != AutoMode::SocksOnly {
        worker
            .command(CommandArgs::BeginCapture {
                stage: stage.into(),
            })
            .unwrap();
    }
    fixture_step(mode, "preformatter_complete");
}
#[test]
#[ignore = "disposable root Linux with genuine all-three-mode planner prerequisites"]
fn actual_backend_all_three_modes_formatter_finalize_and_exact_reentry() {
    let method_started = std::time::Instant::now();
    for (mode, old_service_user) in [
        (AutoMode::SocksOnly, ServiceUser::Root),
        (AutoMode::WideRedirectSafe, ServiceUser::AegisSvc),
        (AutoMode::FullWideTun, ServiceUser::AegisSvc),
    ] {
        fixture_step(mode, "positive_iteration_begin");
        assert_old_fixed_actor(old_service_user);
        let (mut tmp, stage, config) = actual_prepared(mode);
        let mut worker = ActualWorker::new(&stage);
        actual_before_formatter(&mut worker, &stage, mode, old_service_user);
        if mode != AutoMode::SocksOnly {
            fixture_step(mode, "formatter_replace_begin");
            let before = fs::read(config.join("aegis.toml")).unwrap();
            let value: toml::Value = toml::from_str(std::str::from_utf8(&before).unwrap()).unwrap();
            let normalized = toml::to_string_pretty(&value).unwrap();
            assert_ne!(normalized.as_bytes(), before);
            // Real atomic formatter replacement, not merely a forced timestamp.
            formatter_replace_preserving_metadata(
                &config.join("aegis.toml"),
                normalized.as_bytes(),
            );
            fixture_step(mode, "formatter_replace_complete");
        }
        fixture_step(mode, "finalize_begin");
        worker
            .command(CommandArgs::Finalize {
                stage: stage.clone(),
            })
            .unwrap();
        fixture_step(mode, "finalize_complete");
        worker.finish_terminal();
        fixture_step(mode, "terminal_worker_exited");
        let guard = StageGuard::admit(Store::reopen(&stage, 0).unwrap()).unwrap();
        assert!(guard.header.phase == Phase::Finalized);
        assert!(guard.header.pending.is_none());
        let restored = PreparedRender::restore_private_recipe(&guard).unwrap();
        assert_eq!(restored.context.logical_final_base, config);
        let parsed: toml::Value = toml::from_str(
            std::str::from_utf8(&fs::read(config.join("aegis.toml")).unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(parsed["direct"]["persist_state"].as_bool(), Some(false));
        drop(guard);
        drop(worker.child);
        fixture_step(mode, "fresh_worker_begin");
        let mut worker = ActualWorker::resume(&stage);
        worker
            .command(CommandArgs::Verify {
                stage: stage.clone(),
                phase: VerifyPhase::PublishedConfig,
            })
            .unwrap();
        drop(worker);
        fixture_step(mode, "fresh_stop_begin");
        crate::profile_auto_transaction::stop_finalized_stage(&stage).unwrap();
        fixture_step(mode, "fresh_stop_complete");
        tmp.retain_after_terminal();
    }
    eprintln!(
        "AUTO_FIXTURE_TIMING selector=36 success elapsed_ms={}",
        method_started.elapsed().as_millis()
    );
}
#[test]
#[ignore = "disposable root Linux with genuine wide planner prerequisites"]
fn actual_backend_formatter_unknown_field_refuses_without_projected_receipt() {
    for (mode, old_service_user) in [
        (AutoMode::WideRedirectSafe, ServiceUser::Root),
        (AutoMode::FullWideTun, ServiceUser::AegisSvc),
    ] {
        fixture_step(mode, "negative_iteration_begin");
        assert_old_fixed_actor(old_service_user);
        let (mut tmp, stage, config) = actual_prepared(mode);
        let mut worker = ActualWorker::new(&stage);
        actual_before_formatter(&mut worker, &stage, mode, old_service_user);
        fixture_step(mode, "unknown_formatter_replace_begin");
        let before = fs::read(config.join("aegis.toml")).unwrap();
        let mut parsed: toml::Value =
            toml::from_str(std::str::from_utf8(&before).unwrap()).unwrap();
        // Introduce unknown data only AFTER accepted prepare and publication.
        let mut extension = toml::map::Map::new();
        extension.insert(
            "preserve".into(),
            toml::Value::String("forbidden unknown change".into()),
        );
        parsed
            .as_table_mut()
            .unwrap()
            .insert("future".into(), toml::Value::Table(extension));
        formatter_replace_preserving_metadata(
            &config.join("aegis.toml"),
            toml::to_string_pretty(&parsed).unwrap().as_bytes(),
        );
        fixture_step(mode, "unknown_formatter_replace_complete");
        fixture_step(mode, "expected_refusal_begin");
        assert_eq!(
            worker
                .command(CommandArgs::Finalize {
                    stage: stage.clone()
                })
                .unwrap_err(),
            "projection_semantics_changed",
            "only the formatter's complete-semantics refusal counts"
        );
        fixture_step(mode, "expected_refusal_received");
        worker.finish_nonterminal();
        fixture_step(mode, "compensated_worker_exited");
        let guard = StageGuard::admit(Store::reopen(&stage, 0).unwrap()).unwrap();
        assert!(guard.header.phase == Phase::Metadata);
        assert!(guard.header.pending.is_none());
        assert!(!guard
            .header
            .current_records
            .values()
            .any(|r| r.phase == "projection"));
        assert!(!guard
            .header
            .leaves
            .contains_key(Path::new("accepted/final-render-recipe.json")));
        assert_compensated_wide(&guard);
        fixture_step(mode, "compensated_stop_verified");
        drop(guard);
        tmp.retain_after_terminal();
    }
}

#[test]
#[ignore = "disposable root Linux; real producer/custody/state dispatcher on isolated paths"]
fn actual_backend_custom_preserved_state_copies_prior_only_to_absent_default() {
    for existing in [false, true] {
        eprintln!(
            "AUTO_FIXTURE_STATE {} begin",
            if existing { "existing" } else { "absent" }
        );
        let old_service_user = if existing {
            ServiceUser::AegisSvc
        } else {
            ServiceUser::Root
        };
        assert_old_fixed_actor(old_service_user);
        let (mut tmp, stage, config) = actual_prepared_state(AutoMode::SocksOnly, true, existing);
        let mut worker = ActualWorker::new(&stage);
        let original = tmp.path().join("external-prior-state.json");
        let sink = tmp.path().join("state/state.json");
        let captured = fs::read(&original).unwrap();
        worker
            .command(CommandArgs::Verify {
                stage: stage.clone(),
                phase: VerifyPhase::BeforeCustody,
            })
            .unwrap();
        worker
            .command(CommandArgs::BindRuntimeService {
                stage: stage.clone(),
                service_user: ServiceUser::AegisSvc,
            })
            .unwrap();
        worker
            .command(CommandArgs::CommitCustody {
                stage: stage.clone(),
                service_user: old_service_user,
                was_active: false,
            })
            .unwrap();
        worker
            .command(CommandArgs::CommitState {
                stage: stage.clone(),
            })
            .unwrap();
        eprintln!("AUTO_FIXTURE_STATE state_commit_complete");
        assert_eq!(fs::read(&original).unwrap(), captured);
        if existing {
            assert_eq!(
                fs::read(&sink).unwrap(),
                b"existing default state preserved"
            );
        } else {
            assert_eq!(fs::read(&sink).unwrap(), captured);
        }
        let runtime = crate::profile_auto_runtime_identity::resolve_runtime_binding(
            ServiceUser::AegisSvc,
            crate::profile_auto_runtime_identity::RuntimePolicy::DedicatedNone,
        )
        .unwrap();
        let state_root = fs::symlink_metadata(sink.parent().unwrap()).unwrap();
        let state_leaf = fs::symlink_metadata(&sink).unwrap();
        assert!(state_root.file_type().is_dir());
        assert!(state_leaf.file_type().is_file());
        assert!(state_leaf.nlink() == 1);
        assert!(state_root.uid() == runtime.identity().uid());
        assert!(state_root.gid() == runtime.identity().gid());
        assert!(state_root.permissions().mode() & 0o7777 == 0o700);
        assert!(state_leaf.uid() == runtime.identity().uid());
        assert!(state_leaf.gid() == runtime.identity().gid());
        assert!(state_leaf.permissions().mode() & 0o7777 == 0o600);
        worker
            .command(CommandArgs::CommitConfig {
                stage: stage.clone(),
            })
            .unwrap();
        worker
            .command(CommandArgs::SealInstallReceipt {
                stage: stage.clone(),
            })
            .unwrap();
        worker
            .command(CommandArgs::PublishServicePolicy {
                stage: stage.clone(),
            })
            .unwrap();
        worker
            .command(CommandArgs::ReloadServicePolicy {
                stage: stage.clone(),
            })
            .unwrap();
        let parsed: toml::Value = toml::from_str(
            std::str::from_utf8(&fs::read(config.join("aegis.toml")).unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(parsed["direct"]["state_path"].as_str(), original.to_str());
        worker
            .command(CommandArgs::PublishMetadata {
                stage: stage.clone(),
            })
            .unwrap();
        worker
            .command(CommandArgs::Verify {
                stage: stage.clone(),
                phase: VerifyPhase::BeforeActivation,
            })
            .unwrap();
        worker
            .command(CommandArgs::Finalize {
                stage: stage.clone(),
            })
            .unwrap();
        eprintln!("AUTO_FIXTURE_STATE finalize_complete");
        worker.finish_terminal();
        eprintln!("AUTO_FIXTURE_STATE terminal_worker_exited");
        let admitted = StageGuard::admit(Store::reopen(&stage, 0).unwrap()).unwrap();
        assert!(admitted.header.phase == Phase::Finalized);
        assert_eq!(fs::read(&original).unwrap(), captured);
        drop(admitted);
        drop(worker);
        eprintln!("AUTO_FIXTURE_STATE fresh_stop_begin");
        crate::profile_auto_transaction::stop_finalized_stage(&stage).unwrap();
        eprintln!("AUTO_FIXTURE_STATE fresh_stop_complete");
        tmp.retain_after_terminal();
    }
}

#[test]
fn backend_fixture_relay_auth_and_listener_follow_actual_schema_and_renderer() {
    use crate::profile_auto_render::{self as render, InputKind, Options, SelectedMode};
    let text = actual_fixture_settings();
    let accepted: aegis_core::Settings = toml::from_str(&text).unwrap();
    validate_actual_fixture(&accepted);
    assert_eq!(
        accepted.socks.listen,
        "127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap()
    );
    for mode in [
        SelectedMode::SocksOnly,
        SelectedMode::WideRedirectSafe,
        SelectedMode::FullWideTun,
    ] {
        let mut mode_text = text.clone();
        if matches!(mode, SelectedMode::WideRedirectSafe) {
            append_qa_redirect_scope(&mut mode_text);
        }
        let mode_settings: aegis_core::Settings = toml::from_str(&mode_text).unwrap();
        let wide_interface = if matches!(mode, SelectedMode::WideRedirectSafe) {
            assert!(qa_redirect_scope(&mode_settings));
            mode_settings.ingress.wide.prerouting_interface.clone()
        } else {
            assert_eq!(mode_text, text);
            None
        };
        let options = Options {
            mode,
            input: InputKind::ExistingUpgrade,
            final_ca: "/fixture/config/ca.pem".into(),
            final_state: "/fixture/state/state.json".into(),
            logical_original_base: "/fixture/config".into(),
            logical_final_base: "/fixture/config".into(),
            fresh_local_token: None,
            masque_server: None,
            final_masque_ca: None,
            captured_bundle_ca: None,
            captured_masque_ca: None,
            captured_previous_state: None,
            relay_pin: None,
            state_path_needs_relocation: false,
            wide_interface: wide_interface.clone(),
        };
        let rendered = render::render(mode_text.as_bytes(), &options).unwrap();
        let published: aegis_core::Settings = toml::from_str(&rendered.bytes).unwrap();
        if matches!(mode, SelectedMode::WideRedirectSafe) {
            assert!(qa_redirect_scope(&published));
            assert_eq!(wide_interface.as_deref(), Some(QA_REDIRECT_INTERFACE));
            assert_eq!(
                published.ingress.wide.listen.to_string(),
                QA_REDIRECT_LISTEN
            );
            for (source, expected) in [
                (
                    mode_text.replace("listen = '10.231.81.1:15080'\n", ""),
                    "auto_render_scoped_listen_explicit_required",
                ),
                (
                    mode_text.replace(QA_REDIRECT_LISTEN, "0.0.0.0:15080"),
                    "auto_render_scoped_listen_invalid",
                ),
                (
                    mode_text.replace(QA_REDIRECT_LISTEN, "127.0.0.1:15080"),
                    "auto_render_scoped_listen_invalid",
                ),
                (
                    mode_text.replace(QA_REDIRECT_INTERFACE, "foreign0"),
                    "auto_render_scoped_binding_mismatch",
                ),
            ] {
                assert_eq!(
                    render::render(source.as_bytes(), &options).err(),
                    Some(expected)
                );
            }
            for unscoped in [
                text.clone(),
                mode_text.replace(QA_REDIRECT_INTERFACE, "foreign0"),
            ] {
                let parsed: aegis_core::Settings = toml::from_str(&unscoped).unwrap();
                assert!(!qa_redirect_scope(&parsed));
            }
        } else {
            assert!(!qa_redirect_scope(&published));
            assert!(wide_interface.is_none());
        }
        if matches!(mode, SelectedMode::SocksOnly) {
            // The old fixture parsed successfully but selected core's Wide
            // default. ExistingUpgrade must not silently change that scope.
            let old = text.replace("[ingress]\nprimary = 'socks5'\n", "");
            let old_settings: aegis_core::Settings = toml::from_str(&old).unwrap();
            assert!(matches!(
                old_settings.ingress.primary,
                aegis_core::IngressPrimary::Wide
            ));
            assert_eq!(
                render::render(old.as_bytes(), &options).err(),
                Some("auto_render_selected_socks_scope_mismatch")
            );
        }
    }
}
#[test]
fn backend_old_fixture_missing_listener_and_textual_relay_auth_refuse() {
    let no_listener = actual_fixture_settings().replace("listen = '127.0.0.1:0'\n", "");
    assert!(toml::from_str::<aegis_core::Settings>(&no_listener).is_err());
    let mut accepted: aegis_core::Settings = toml::from_str(&actual_fixture_settings()).unwrap();
    accepted.relay.auth_token = "synthetic-relay-fixture-only".into();
    assert_eq!(
        aegis_core::auth_token::validate(&accepted.relay.auth_token),
        Err("auth_token_requires_32_random_bytes_encoded_as_64_hex_characters")
    );
}

#[test]
fn backend_custom_state_transfer_uses_captured_spelling_without_relocation() {
    use crate::profile_auto_capture::{CaptureLimits, CapturedTree, InputRole};
    use crate::profile_auto_render::{self as render, InputKind, Options, SelectedMode};
    let original = Path::new("/fixture/external-prior-state.json");
    let captured = b"synthetic prior state bytes";
    let source = format!(
        "{}state_path = '{}'\n",
        actual_fixture_settings(),
        original.display()
    );
    let mut options = Options {
        mode: SelectedMode::SocksOnly,
        input: InputKind::ExistingUpgrade,
        final_ca: "/fixture/config/ca.pem".into(),
        final_state: "/fixture/state/state.json".into(),
        logical_original_base: "/fixture/config".into(),
        logical_final_base: "/fixture/config".into(),
        fresh_local_token: None,
        masque_server: None,
        final_masque_ca: None,
        captured_bundle_ca: None,
        captured_masque_ca: None,
        captured_previous_state: Some(original.into()),
        relay_pin: None,
        state_path_needs_relocation: false,
        wide_interface: None,
    };
    // The installed device fixture carries four real references. Capture each
    // through the same role-specific input API used by PREPARE; a path string
    // alone cannot grant access to the private key.
    let settings: aegis_core::Settings = toml::from_str(&source).unwrap();
    let mut public = Vec::new();
    for path in settings.relay.ca_cert.iter().chain(
        settings
            .relay
            .inner_tls
            .iter()
            .flat_map(|inner| [&inner.server_ca, &inner.cert]),
    ) {
        assert!(path.is_absolute());
        let tree = CapturedTree::capture_file(
            path,
            path.parent().unwrap().to_path_buf(),
            InputRole::AdministratorMetadata {
                administrator_uid: 0,
            },
            CaptureLimits::default(),
        )
        .unwrap();
        public.push((path.clone(), tree));
    }
    let private = settings.relay.inner_tls.as_ref().map(|inner| {
        let path = &inner.key;
        assert!(path.is_absolute());
        let tree = CapturedTree::capture_file(
            path,
            path.parent().unwrap().to_path_buf(),
            InputRole::PrivateCredential { expected_uid: 0 },
            CaptureLimits::default(),
        )
        .unwrap();
        (path.clone(), tree)
    });
    let private_cap = private.as_ref().map(|(path, tree)| {
        tree.private_reference(Path::new(path.file_name().unwrap()), 0)
            .unwrap()
    });
    let mut entries: Vec<_> = public
        .iter()
        .map(|(path, tree)| {
            render::CapturedReference::public_certificate(
                path,
                path,
                tree.bytes(Path::new(path.file_name().unwrap())).unwrap(),
            )
        })
        .collect();
    if let (Some((path, _)), Some(cap)) = (&private, &private_cap) {
        entries.push(render::CapturedReference::private_credential(path, cap));
    }
    let refs = render::ReferenceSet { entries: &entries };
    let validators = render::RuntimeCapturedValidators {
        logical_final_base: options.logical_final_base.clone(),
    };
    let transfer = || render::StateTransfer {
        original_logical_path: original,
        captured,
        final_relative_leaf: Path::new("state.json"),
    };
    // Actual PREPARE renderer, schema admission and captured validators. The
    // producer requests a transfer only when the default state leaf is absent.
    for absent_default in [true, false] {
        let prepared = render::prepare_render(
            Path::new("aegis.toml"),
            source.as_bytes(),
            None,
            absent_default.then(transfer),
            &options,
            &refs,
            &validators,
        )
        .unwrap();
        assert_eq!(prepared.context.final_state.as_path(), original);
        assert!(prepared.config.previous_state_reference.is_none());
        let parsed: toml::Value = toml::from_str(&prepared.config.bytes).unwrap();
        assert_eq!(parsed["direct"]["state_path"].as_str(), original.to_str());
        if absent_default {
            let state = prepared.state_transfer.as_ref().unwrap();
            assert_eq!(state.relative_leaf.as_path(), Path::new("state.json"));
            assert_eq!(state.bytes.as_slice(), captured);
        } else {
            assert!(prepared.state_transfer.is_none());
        }
    }
    if let Some(inner) = settings.relay.inner_tls.as_ref() {
        // A preserved spelling still needs the exact captured key capability.
        assert_eq!(
            render::prepare_render(
                Path::new("aegis.toml"),
                source.as_bytes(),
                None,
                Some(transfer()),
                &options,
                &render::ReferenceSet {
                    entries: &entries[..entries.len() - 1],
                },
                &validators,
            )
            .err(),
            Some("auto_render_reference_not_captured")
        );
        let original_key = format!(
            "key = {}",
            toml::Value::String(inner.key.display().to_string())
        );
        assert_eq!(source.matches(&original_key).count(), 1);
        let changed_key = source.replacen(
            &original_key,
            "key = '/fixture/config/different-device.key'",
            1,
        );
        assert_eq!(
            render::prepare_render(
                Path::new("aegis.toml"),
                changed_key.as_bytes(),
                None,
                Some(transfer()),
                &options,
                &refs,
                &validators,
            )
            .err(),
            Some("auto_render_reference_not_captured")
        );
    }
    options.captured_previous_state = None;
    assert_eq!(
        render::prepare_render(
            Path::new("aegis.toml"),
            source.as_bytes(),
            None,
            Some(transfer()),
            &options,
            &refs,
            &validators,
        )
        .err(),
        Some("auto_render_state_not_captured")
    );
    options.captured_previous_state = Some(original.into());
    let mismatch = source.replace(original.to_str().unwrap(), "/fixture/different-state.json");
    assert_eq!(
        render::prepare_render(
            Path::new("aegis.toml"),
            mismatch.as_bytes(),
            None,
            Some(transfer()),
            &options,
            &refs,
            &validators,
        )
        .err(),
        Some("auto_render_state_reference_mismatch")
    );
    assert_eq!(
        render::prepare_render(
            Path::new("aegis.toml"),
            actual_fixture_settings().as_bytes(),
            None,
            Some(transfer()),
            &options,
            &refs,
            &validators,
        )
        .err(),
        Some("auto_render_unexpected_state_transfer")
    );
}

// Test-only child entry invokes the ACTUAL worker, not a mocked phase handler.
// Root supervises this ignored fixture as a separate bounded Rust test process.
#[test]
#[ignore = "owned child entry; only invoked by the disposable-root worker regression"]
fn worker_actual_dispatch_child_entry() {
    let path = std::env::var_os("AEGIS_AUTO_TEST_WORKER_STAGE").expect("owned stage required");
    super::worker(Path::new(&path)).unwrap();
}

#[test]
#[ignore = "requires disposable root Linux and actual planner/worker prerequisites"]
fn actual_worker_releases_initial_stage_lock_before_first_dispatch() {
    use std::{
        io::Write,
        os::fd::AsRawFd,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let (_tmp, stage, _config) = actual_prepared(AutoMode::SocksOnly);
    struct Owned {
        child: std::process::Child,
        reaped: bool,
    }
    impl Drop for Owned {
        fn drop(&mut self) {
            if !self.reaped {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
    }
    let mut owned=Owned{child:Command::new(std::env::current_exe().unwrap())
        .args(["--exact","profile_auto_transaction::backend::actual_backend_integration_tests::worker_actual_dispatch_child_entry","--ignored","--nocapture","--test-threads=1"])
        .env("AEGIS_AUTO_TEST_WORKER_STAGE",&stage).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap(),reaped:false};
    let mut input = owned.child.stdin.take().unwrap();
    let output = owned.child.stdout.take().unwrap();
    // Inspect dispatch spawns no service/capture helper. Initial manager
    // admission, if present in the final provider, must finish before ready.
    fn response(fd: i32) -> serde_json::Value {
        let start = Instant::now();
        let mut line = Vec::new();
        let mut total = 0usize;
        loop {
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "owned worker reply deadline"
            );
            let mut poll = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let n = unsafe { libc::poll(&mut poll, 1, 100) };
            if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            assert!(n >= 0);
            if n == 0 {
                continue;
            }
            let mut byte = 0u8;
            let got = unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) };
            assert_eq!(got, 1, "worker ended before real reply");
            total += 1;
            assert!(total <= 32768, "bounded harness and worker output");
            if byte == b'\n' {
                if let Some(pos) = line.iter().position(|b| *b == b'{') {
                    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&line[pos..]) {
                        return value;
                    }
                }
                line.clear();
            } else {
                line.push(byte);
                assert!(line.len() <= 16384);
            }
        }
    }
    assert_eq!(response(output.as_raw_fd())["status"], "ready");
    for _ in 0..2 {
        input
            .write_all(b"{\"command\":[\"inspect\",\"--field\",\"product-mode\"]}\n")
            .unwrap();
        input.flush().unwrap();
        let actual = response(output.as_raw_fd());
        assert_eq!(actual["status"], "ok");
        assert_eq!(actual["value"], "socks-only");
    }
    drop(input);
    let refused = response(output.as_raw_fd());
    assert_eq!(refused["status"], "error");
    assert_eq!(refused["reason"], "coordinator_disconnected");
    let retained = StageGuard::admit(Store::reopen(&stage, 0).unwrap()).unwrap();
    assert!(retained.header.phase == Phase::Prepared);
    drop(retained);
    // After the two read-only requests the worker creates no descendants;
    // wait is bounded and reaped status is latched before RAII cleanup.
    let start = Instant::now();
    loop {
        if let Some(status) = owned.child.try_wait().unwrap() {
            owned.reaped = true;
            assert!(
                !status.success(),
                "EOF before a terminal command must refuse"
            );
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "owned worker exit deadline"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
#[ignore = "requires authorized disposable root Linux PID1; real daemon-reload, no service or routing effect"]
fn actual_prepared_socks_worker_reopens_after_pid1_daemon_reload_then_rolls_back() {
    use std::process::{Command, Stdio};

    assert_eq!(unsafe { libc::geteuid() }, 0, "root PID1 fixture required");
    assert_eq!(
        std::env::var("AEGIS_AUTO_TEST_PID1_RELOAD").as_deref(),
        Ok("authorized-root-qa"),
        "explicit daemon-reload QA gate required"
    );
    let (_tmp, stage, config) = actual_prepared(AutoMode::SocksOnly);
    let config_properties = |path: &Path| {
        let info = fs::symlink_metadata(path).unwrap();
        (info.uid(), info.gid(), info.mode() & 0o7777)
    };
    let original_config_properties = config_properties(&config);
    let original_config_files = fs::read_dir(&config)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let info = fs::symlink_metadata(&path).unwrap();
            assert!(info.file_type().is_file());
            assert_eq!(info.nlink(), 1);
            (
                path.file_name().unwrap().to_os_string(),
                (fs::read(&path).unwrap(), config_properties(&path)),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert!(!original_config_files.is_empty());
    let mut first = ActualWorker::new(&stage);
    assert_eq!(
        first
            .command(CommandArgs::Inspect {
                stage: stage.clone(),
                field: InspectField::ProductMode,
            })
            .unwrap()
            .as_deref(),
        Some("socks-only")
    );
    let (original_namespace_leaf, original_namespace_hash, original_namespace_bytes) = {
        let sealed = StageGuard::admit(Store::reopen(&stage, 0).unwrap()).unwrap();
        assert!(sealed.header.phase == Phase::Prepared);
        let leaf = sealed.header.old_unit_namespace.clone().unwrap();
        let hash = sealed.header.leaves.get(&leaf).unwrap().clone();
        let bytes = sealed.store.read(&leaf).unwrap();
        assert_eq!(digest(&bytes), hash);
        (leaf, hash, bytes)
    };
    first
        .command(CommandArgs::Verify {
            stage: stage.clone(),
            phase: VerifyPhase::BeforeCustody,
        })
        .unwrap();
    first
        .command(CommandArgs::BindRuntimeService {
            stage: stage.clone(),
            service_user: ServiceUser::AegisSvc,
        })
        .unwrap();
    first
        .command(CommandArgs::CommitCustody {
            stage: stage.clone(),
            service_user: ServiceUser::Root,
            was_active: false,
        })
        .unwrap();
    first.finish_nonterminal();
    drop(first);
    let sealed = StageGuard::admit(Store::reopen(&stage, 0).unwrap()).unwrap();
    assert!(sealed.header.phase == Phase::Custody);
    assert_eq!(
        sealed.header.old_unit_namespace.as_ref(),
        Some(&original_namespace_leaf)
    );
    assert_eq!(
        sealed.header.leaves.get(&original_namespace_leaf),
        Some(&original_namespace_hash)
    );
    assert!(
        sealed.store.read(&original_namespace_leaf).unwrap() == original_namespace_bytes,
        "sealed original namespace bytes changed after custody"
    );
    assert!(sealed.header.new_unit_namespace.is_none());
    let custody_leaf = sealed.header.active_records.get("config").unwrap().clone();
    let custody = sealed.header.current_records.get(&custody_leaf).unwrap();
    assert_eq!(custody.role, "config");
    assert_eq!(custody.phase, "custody");
    assert!(custody.predecessor_sha256.is_none());
    let custody_sha = custody.sha256.clone();
    assert!(sealed.header.pending.is_none());
    assert!(sealed.header.unit_pending.is_none());
    assert!(!sealed.header.capture_started);
    drop(sealed);

    // Real PID1 reload is between workers after owned config custody. No
    // service, guard or capture actor is started by this fixture.
    let runtime_paths = [
        "/run/systemd/generator",
        "/run/systemd/generator.early",
        "/run/systemd/generator.late",
        "/run/systemd/transient",
    ];
    let runtime_directory = |path: &str| {
        let info = match fs::symlink_metadata(path) {
            Ok(info) => info,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
            Err(error) => panic!("PID1 runtime directory lstat refused for {path}: {error}"),
        };
        assert!(
            info.file_type().is_dir(),
            "PID1 runtime path is not a directory: {path}"
        );
        Some((
            info.dev(),
            info.ino(),
            info.uid(),
            info.gid(),
            info.mode() & 0o7777,
        ))
    };
    let runtime_before = runtime_paths.map(|path| (path, runtime_directory(path)));
    let reload = Command::new("/usr/bin/timeout")
        .args([
            "--signal=TERM",
            "--kill-after=1s",
            "10s",
            "/usr/bin/systemctl",
            "daemon-reload",
        ])
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(reload.success(), "bounded real PID1 reload refused");
    let runtime_after = runtime_paths.map(|path| (path, runtime_directory(path)));
    let mut inode_changed = false;
    for ((before_path, before), (after_path, after)) in
        runtime_before.iter().zip(runtime_after.iter())
    {
        assert_eq!(before_path, after_path);
        match (before, after) {
            (Some(before), Some(after)) => {
                eprintln!(
                    "AUTO_FIXTURE_RELOAD_DIR {before_path} before_dev={} before_ino={} after_dev={} after_ino={}",
                    before.0, before.1, after.0, after.1
                );
                assert_eq!(
                    (before.0, before.2, before.3, before.4),
                    (after.0, after.2, after.3, after.4),
                    "PID1 runtime directory properties changed: {before_path}"
                );
                inode_changed |= before.1 != after.1;
            }
            (None, None) => eprintln!("AUTO_FIXTURE_RELOAD_DIR {before_path} absent"),
            _ => panic!("PID1 runtime directory roster changed: {before_path}"),
        }
    }
    assert!(
        inode_changed,
        "PID1 daemon-reload did not change an admitted runtime directory inode"
    );

    let mut second = ActualWorker::resume(&stage);
    let input = second.child.0.stdin.as_mut().unwrap();
    input
        .write_all(b"{\"command\":[\"rollback\",\"--capture-started\",\"0\"]}\n")
        .unwrap();
    input.flush().unwrap();
    let rollback_reply = response(&second.child);
    assert_eq!(
        rollback_reply["status"], "ok",
        "actual worker rollback refused: {rollback_reply}"
    );
    second.finish_terminal();
    let terminal = StageGuard::admit(Store::reopen(&stage, 0).unwrap()).unwrap();
    assert!(terminal.header.phase == Phase::RolledBack);
    assert_eq!(
        terminal.header.old_unit_namespace.as_ref(),
        Some(&original_namespace_leaf)
    );
    assert_eq!(
        terminal.header.leaves.get(&original_namespace_leaf),
        Some(&original_namespace_hash)
    );
    assert!(
        terminal.store.read(&original_namespace_leaf).unwrap() == original_namespace_bytes,
        "sealed original namespace bytes changed after rollback"
    );
    assert!(terminal.header.new_unit_namespace.is_none());
    assert!(terminal.header.pending.is_none());
    assert!(terminal.header.unit_pending.is_none());
    assert!(!terminal.header.capture_started);
    assert_eq!(
        terminal
            .header
            .current_records
            .get(&custody_leaf)
            .unwrap()
            .sha256,
        custody_sha
    );
    assert_eq!(terminal.header.active_records.len(), 1);
    let restored_leaf = terminal.header.active_records.get("config").unwrap();
    let restored = terminal.header.current_records.get(restored_leaf).unwrap();
    assert_eq!(restored.role, "config");
    assert_eq!(restored.phase, "rollback");
    assert_eq!(
        restored.predecessor_sha256.as_deref(),
        Some(custody_sha.as_str())
    );
    assert!(terminal.header.unit_forward_transitions.is_empty());
    assert!(terminal.header.unit_restorations.is_empty());
    drop(terminal);
    assert_eq!(config_properties(&config), original_config_properties);
    let restored_config_files = fs::read_dir(&config)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let info = fs::symlink_metadata(&path).unwrap();
            assert!(info.file_type().is_file());
            assert_eq!(info.nlink(), 1);
            (
                path.file_name().unwrap().to_os_string(),
                (fs::read(&path).unwrap(), config_properties(&path)),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert!(
        restored_config_files == original_config_files,
        "restored config bytes/properties mismatch"
    );
}

#[path = "profile_auto_receipt_admission_tests.rs"]
mod receipt_admission_regressions;

#[test]
#[ignore = "requires disposable root Linux; actual prepare/Store/RootContext/lock admission"]
fn actual_root_context_recovery_purpose_requires_admitted_pending_source_before_dropin_route() {
    let (_tmp, stage, _config) = actual_prepared(AutoMode::SocksOnly);
    let lock = crate::profile_auto_stopped_service::InstallLock::acquire().unwrap();
    let reader = super::super::v2_state_reader::PublishedState;
    let admitted = StageGuard::admit(Store::reopen(&stage, 0).unwrap()).unwrap();
    assert!(
        super::super::store_context::RootContext::from_stage_with_lock(
            admitted,
            &reader,
            Some(&lock),
            Some(crate::profile_auto_stopped_service::PreparedOperation::StaticRollback),
            Some(super::super::store_context::UnitOperation::RecoverPendingPublish),
        )
        .is_err()
    );
    let admitted = StageGuard::admit(Store::reopen(&stage, 0).unwrap()).unwrap();
    let context = super::super::store_context::RootContext::from_stage_with_lock(
        admitted,
        &reader,
        Some(&lock),
        Some(crate::profile_auto_stopped_service::PreparedOperation::StaticRollback),
        Some(super::super::store_context::UnitOperation::Rollback),
    )
    .unwrap();
    assert!(context.recovering_publication_role().is_err());
    assert!(context.admit_dropin_publication_record(true).is_err());
    // Actual producer, protected Store and actual RootContext entry/route, with
    // no fabricated phase/source/Context. Positive installed fixed-unit recovery
    // followed by rollback still requires the separate native lifecycle cohort.
}
