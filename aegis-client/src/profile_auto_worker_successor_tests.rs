//! B-02 successor preflight, separate from the frozen 39 native selectors.
//! Exercises the real worker and protected receipt admission. This deliberately
//! stops before custody, service publication, native capture, or finalization.
use super::*;
use crate::profile_auto_transaction::receipt_store::{self, PrepareInputs};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    os::{fd::AsRawFd, unix::fs::PermissionsExt},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

fn private_write(path: &Path, bytes: &[u8], mode: u32) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn stage(mode: AutoMode) -> (tempfile::TempDir, PathBuf) {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let config = root.path().join("config");
    let metadata = root.path().join("metadata");
    for path in [&config, &metadata] {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let text = format!(
        "mode = 'relay'\n[relay]\nserver = '127.0.0.1:443'\nserver_name = 'localhost'\nauth_token = '{}'\ntransport_priority = ['grpc_stream']\n[ingress]\nprimary = 'socks5'\n[socks]\nlisten = '127.0.0.1:0'\nauth_token = '{}'\n[direct]\npersist_state = false\n",
        "0123456789abcdef".repeat(4),
        "fedcba9876543210".repeat(4)
    );
    let parsed: aegis_core::Settings = toml::from_str(&text).unwrap();
    parsed.validate_privacy_plan().unwrap();
    private_write(&config.join("aegis.toml"), text.as_bytes(), 0o600);
    private_write(
        &metadata.join("wide-profile.json"),
        &serde_json::to_vec(&serde_json::json!({"product_mode": mode.name()})).unwrap(),
        0o600,
    );
    let prepared = prepare::prepare(prepare::Request {
        config_root: config,
        state_target: root.path().join("state"),
        metadata_target: metadata,
        bundle: None,
        service_uid: 0,
        operator_uid: 0,
        admitted_home: Some(root.path().to_path_buf()),
        wide_interface: None,
        relay_pin: None,
        masque_server: None,
        explicit_masque_ca: None,
        prior_native_markers: true,
        requested_mode: None,
    })
    .unwrap();
    assert_eq!(
        prepared.mode,
        mode.name(),
        "planner must select requested mode"
    );
    let stage = seal(
        root.path(),
        &prepared,
        0,
        0,
        None,
        Path::new("/dev/null"),
        None,
    )
    .unwrap();
    let guard = StageGuard::admit(Store::reopen(&stage, 0).unwrap()).unwrap();
    assert!(
        guard.header.mode == mode,
        "sealed mode must match planner mode"
    );
    (root, stage)
}

fn admit_synthetic_public_receipt(stage: &Path) -> tempfile::TempDir {
    // This public fixture is a source-shape test input. It is never installed.
    let public = tempfile::Builder::new()
        .prefix("aegis-worker-successor-")
        .tempdir_in("/root")
        .unwrap();
    let bin = public.path().join("bin");
    fs::create_dir(&bin).unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).unwrap();
    let candidate = bin.join("aegis-client");
    let bytes = b"synthetic-file-data-never-executed";
    private_write(&candidate, bytes, 0o700);
    private_write(
        &public.path().join("bundle.manifest.json"),
        &serde_json::to_vec(&serde_json::json!({
            "schema":"aegis_client_release_bundle_manifest_v2",
            "version":"synthetic-public-source", "git_sha":"unknown",
            "platform":"linux", "arch":"x86_64",
            "binaries":{"aegis-client":{"path":"bin/aegis-client",
                "sha256":format!("{:x}", Sha256::digest(bytes))}}
        }))
        .unwrap(),
        0o600,
    );
    let mut guard = StageGuard::admit(Store::reopen(stage, 0).unwrap()).unwrap();
    receipt_store::admit_prepare(
        &mut guard,
        PrepareInputs {
            public_payload_root: public.path(),
            candidate_binary: &candidate,
            installed_binary: &public.path().join("install-bin/aegis-client"),
            source_manifest_url: None,
            source_release_channel: None,
        },
    )
    .unwrap();
    public
}

pub(super) struct OwnedChild(pub(super) Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl OwnedChild {
    /// A terminal worker must exit on its own after its acknowledged reply.
    /// Keep the existing five-second child-exit bound and leave Drop as the
    /// final reap safeguard if a regression makes the worker linger.
    pub(super) fn finish_terminal(&mut self) {
        drop(self.0.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                assert!(status.success(), "terminal worker exit refused");
                return;
            }
            assert!(
                Instant::now() < deadline,
                "bounded terminal worker exit deadline"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

pub(super) fn response(child: &OwnedChild) -> serde_json::Value {
    let fd = child.0.stdout.as_ref().unwrap().as_raw_fd();
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut line = Vec::new();
    loop {
        assert!(
            Instant::now() < deadline,
            "bounded worker response deadline"
        );
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut poll, 1, 100) };
        if ready < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        assert!(ready >= 0);
        if ready == 0 {
            continue;
        }
        let mut byte = 0u8;
        assert_eq!(
            unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) },
            1
        );
        if byte == b'\n' {
            if let Some(pos) = line.iter().position(|b| *b == b'{') {
                if let Ok(value) = serde_json::from_slice(&line[pos..]) {
                    return value;
                }
            }
            line.clear();
        } else {
            line.push(byte);
            assert!(line.len() <= 16384, "bounded worker response");
        }
    }
}

pub(super) fn spawn(stage: &Path) -> OwnedChild {
    OwnedChild(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "profile_auto_transaction::backend::actual_backend_integration_tests::worker_actual_dispatch_child_entry", "--ignored", "--nocapture", "--test-threads=1"])
        .env("AEGIS_AUTO_TEST_WORKER_STAGE", stage)
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().unwrap())
}

pub(super) fn finish_nonterminal(child: &mut OwnedChild) {
    drop(child.0.stdin.take());
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "bounded worker exit deadline");
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(!status.success(), "nonterminal worker must refuse");
    let mut stderr = Vec::new();
    child
        .0
        .stderr
        .take()
        .unwrap()
        .take(65537)
        .read_to_end(&mut stderr)
        .unwrap();
    assert!(stderr.len() <= 65536, "bounded retained child stderr");
}

#[test]
#[ignore = "disposable root Linux; actual planner, protected receipt, worker and systemd admission"]
fn actual_socks_worker_admits_protected_preflight_without_custody() {
    let (_root, stage) = stage(AutoMode::SocksOnly);
    let _public = admit_synthetic_public_receipt(&stage);
    let mut child = spawn(&stage);
    assert_eq!(response(&child)["status"], "ready");
    child
        .0
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"{\"command\":[\"verify\",\"--phase\",\"before-custody\"]}\n")
        .unwrap();
    assert_eq!(response(&child)["status"], "ok");
    finish_nonterminal(&mut child);
    let guard = StageGuard::admit(Store::reopen(&stage, 0).unwrap()).unwrap();
    assert!(guard.header.phase == Phase::Prepared);
    assert!(guard
        .header
        .leaves
        .contains_key(Path::new("input/install-receipt/inputs.json")));
    assert!(guard.header.active_records.is_empty());
}

#[test]
#[ignore = "disposable root Linux; actual planner, protected receipt, worker and systemd admission"]
fn actual_wide_worker_refuses_capture_without_native_witness() {
    let (_root, stage) = stage(AutoMode::WideRedirectSafe);
    let _public = admit_synthetic_public_receipt(&stage);
    let mut child = spawn(&stage);
    assert_eq!(response(&child)["status"], "ready");
    child
        .0
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"{\"command\":[\"verify\",\"--phase\",\"before-custody\"]}\n")
        .unwrap();
    assert_eq!(response(&child)["status"], "ok");
    child
        .0
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"{\"command\":[\"begin-capture\"]}\n")
        .unwrap();
    let refused = response(&child);
    assert_eq!(refused["status"], "error");
    assert_eq!(refused["reason"], "native_capture_guard_not_ready");
    finish_nonterminal(&mut child);
    let guard = StageGuard::admit(Store::reopen(&stage, 0).unwrap()).unwrap();
    assert!(guard.header.phase == Phase::Prepared);
    assert!(!guard.header.capture_started);
    assert!(guard.header.active_records.is_empty());
}

#[test]
#[ignore = "disposable root Linux; actual worker must refuse unowned activation"]
fn actual_socks_worker_refuses_finalize_without_owned_actor() {
    let (_root, stage) = stage(AutoMode::SocksOnly);
    let _public = admit_synthetic_public_receipt(&stage);
    let mut child = spawn(&stage);
    assert_eq!(response(&child)["status"], "ready");
    child
        .0
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"{\"command\":[\"verify\",\"--phase\",\"before-custody\"]}\n")
        .unwrap();
    assert_eq!(response(&child)["status"], "ok");
    child
        .0
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"{\"command\":[\"finalize\"]}\n")
        .unwrap();
    let refused = response(&child);
    assert_eq!(refused["status"], "error");
    assert_eq!(refused["reason"], "activation_owner_unavailable");
    finish_nonterminal(&mut child);
    let guard = StageGuard::admit(Store::reopen(&stage, 0).unwrap()).unwrap();
    assert!(guard.header.phase == Phase::Prepared);
    assert!(guard.header.pending.is_none());
    assert!(!guard.header.capture_started);
    assert!(guard.header.active_records.is_empty());
}

#[test]
#[ignore = "disposable root Linux; three real planner modes through protected worker preflight"]
fn actual_all_three_modes_worker_preflight_preserves_selected_scope() {
    for mode in [
        AutoMode::SocksOnly,
        AutoMode::WideRedirectSafe,
        AutoMode::FullWideTun,
    ] {
        let (_root, stage) = stage(mode);
        let _public = admit_synthetic_public_receipt(&stage);
        let mut child = spawn(&stage);
        assert_eq!(response(&child)["status"], "ready", "{}", mode.name());
        child
            .0
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"{\"command\":[\"verify\",\"--phase\",\"before-custody\"]}\n")
            .unwrap();
        assert_eq!(response(&child)["status"], "ok", "{}", mode.name());
        finish_nonterminal(&mut child);
        let guard = StageGuard::admit(Store::reopen(&stage, 0).unwrap()).unwrap();
        assert!(guard.header.mode == mode);
        assert!(guard.header.phase == Phase::Prepared);
        assert!(guard.header.pending.is_none());
        assert!(!guard.header.capture_started);
        assert!(guard.header.active_records.is_empty());
    }
}
