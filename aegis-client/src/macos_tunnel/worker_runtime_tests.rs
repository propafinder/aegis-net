use super::*;
use aegis_client::{
    capture_lease_gate::{CaptureLeaseDeadline, CaptureLeaseGate},
    PacketIo,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn exact_internal_selector_has_no_free_arguments_or_alias() {
    assert!(selector([OsString::from(SELECTOR)]).unwrap().is_ok());
    for args in [
        vec![OsString::from(format!("{SELECTOR}=true"))],
        vec![OsString::from(SELECTOR), OsString::from("--config")],
        vec![OsString::from("--help"), OsString::from(SELECTOR)],
    ] {
        assert!(selector(args).unwrap().is_err());
    }
    assert!(selector([OsString::from("--help")]).is_none());
}
#[test]
fn profile_parser_rejects_oversize_unknown_and_partial_without_store_access() {
    for bytes in [
        vec![b'a'; MAX_PROFILE as usize + 1],
        b"{".to_vec(),
        b"{\"version\":1,\"unexpected\":true}".to_vec(),
    ] {
        let mut file = tempfile::tempfile().unwrap();
        std::io::Write::write_all(&mut file, &bytes).unwrap();
        assert!(WorkerRuntimeProfile::read(&mut file).is_err());
    }
}
#[test]
fn ungranted_gate_never_consumes_packets_and_expired_gate_denies_both_directions() {
    let mut file = tempfile::tempfile().unwrap();
    std::io::Write::write_all(&mut file, b"fixture").unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let _entered = runtime.enter();
    let (parts, _control, mut parent) =
        worker_launch::local_runtime_fixture("/fixture".into(), file);
    let lease = CaptureLeaseDeadline::default();
    let mut gate = CaptureLeaseGate::new(parts.port, lease.clone(), worker_launch::monotonic_ns);
    let mut packet = vec![0; 40];
    packet[0] = 0x60;
    parent.send(&packet).unwrap();
    assert!(gate.receive().unwrap().is_none());
    assert_eq!(
        gate.send(&packet).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    lease
        .replace(Some(
            worker_launch::monotonic_deadline(Duration::from_secs(1)).unwrap(),
        ))
        .unwrap();
    assert_eq!(gate.receive().unwrap().unwrap(), packet);
    lease
        .replace(Some(worker_launch::monotonic_ns().unwrap() - 1))
        .unwrap();
    assert_eq!(
        gate.receive().unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        gate.send(&packet).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
}
#[tokio::test]
async fn real_unix_control_rejects_eof_partial_oversize_and_wrong_version() {
    for bytes in [
        vec![],
        vec![b'A', b'W', 1],
        vec![b'A', b'W', 2, 1, 0, 0, 32, 1],
        vec![b'A', b'W', 3, 1, 0, 0, 0, 1, b'x'],
    ] {
        let file = tempfile::tempfile().unwrap();
        let (mut parts, mut parent, _port) =
            worker_launch::local_runtime_fixture("/fixture".into(), file);
        parent.write_all(&bytes).await.unwrap();
        parent.shutdown().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), parts.control.unexpected())
                .await
                .unwrap()
                .is_err()
        );
    }
}
#[tokio::test]
async fn partial_control_cancellation_owns_socket_and_does_not_resume_as_a_new_frame() {
    let file = tempfile::tempfile().unwrap();
    let (mut parts, mut parent, _port) =
        worker_launch::local_runtime_fixture("/fixture".into(), file);
    parent.write_all(b"AW\x02").await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), parts.control.unexpected())
            .await
            .is_err()
    );
    drop(parts.control);
    let mut byte = [0];
    assert_eq!(parent.read(&mut byte).await.unwrap(), 0);
}

#[tokio::test]
async fn startup_select_cancellation_retains_partial_parser_and_requires_idle_transition() {
    let file = tempfile::tempfile().unwrap();
    let (mut parts, mut parent, _) = worker_launch::local_runtime_fixture("/fixture".into(), file);
    parent.write_all(b"AW\x02").await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), parts.control.unexpected())
            .await
            .is_err()
    );
    assert!(parts.control.require_idle().is_err());
    drop(parts.control);
    let mut byte = [0];
    assert_eq!(parent.read(&mut byte).await.unwrap(), 0);
}
#[test]
fn positive_near_deadline_gate_and_expiry_use_the_same_native_clock() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let _entered = runtime.enter();
    let file = tempfile::tempfile().unwrap();
    let (parts, _control, mut parent) =
        worker_launch::local_runtime_fixture("/fixture".into(), file);
    let until = worker_launch::monotonic_deadline(Duration::from_millis(50)).unwrap();
    let lease = CaptureLeaseDeadline::default();
    lease.replace(Some(until)).unwrap();
    let mut gate = CaptureLeaseGate::new(parts.port, lease, worker_launch::monotonic_ns);
    let mut packet = vec![0; 40];
    packet[0] = 0x60;
    parent.send(&packet).unwrap();
    assert_eq!(gate.receive().unwrap().unwrap(), packet);
    std::thread::sleep(Duration::from_millis(60));
    assert_eq!(
        gate.receive().unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
}

#[test]
#[ignore = "only invoked by owned no-bootstrap subprocess regression"]
fn fixture_plain_selector_without_capabilities() {
    assert!(tokio::runtime::Handle::try_current().is_err());
    assert!(dispatch([OsString::from(SELECTOR)]).unwrap().is_err());
    assert!(tokio::runtime::Handle::try_current().is_err());
}
#[test]
fn actual_owned_process_plain_selector_cannot_launch_worker_or_create_runtime() {
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "macos_tunnel::worker_runtime::tests::fixture_plain_selector_without_capabilities",
            "--ignored",
            "--test-threads=1",
        ])
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                assert!(status.success());
                break;
            }
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(2))
            }
            result => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("owned selector fixture did not exit: {result:?}");
            }
        }
    }
}

#[test]
fn parsed_public_profile_privacy_refusal_precedes_custody_or_native_policy() {
    let settings = Settings {
        privacy_plan: Some(aegis_core::traffic_privacy::plan::PrivacyPlan {
            packet_modifiers: vec![aegis_core::traffic_privacy::plan::PacketModifier::MecControl],
            ..Default::default()
        }),
        ..Default::default()
    };
    // Intentionally invalid custody and runtime fields: pure privacy admission
    // must refuse first, without opening those paths or constructing policy.
    let envelope = Envelope {
        version: 0,
        identity: "absent-key-custody".into(),
        online_bundle: "absent-bundle".into(),
        authority_server: "127.0.0.1:1".parse().unwrap(),
        renewal: RenewalPolicy::ExistingLeaseOnly,
        settings,
        run_seconds: 0,
        max_flows: 0,
        idle_seconds: 0,
        mtu: 0,
        dns_upstream: "127.0.0.1:1".parse().unwrap(),
    };
    let mut file = tempfile::tempfile().unwrap();
    std::io::Write::write_all(&mut file, &serde_json::to_vec(&envelope).unwrap()).unwrap();
    let error = match WorkerRuntimeProfile::read(&mut file) {
        Ok(_) => panic!("unsupported installed MEC admitted"),
        Err(e) => e.to_string(),
    };
    assert!(error.starts_with("privacy_plan:"), "{error}");
    assert!(error.contains("no installed runtime emitter"), "{error}");
}

#[test]
fn active_worker_cannot_adopt_same_certificate_new_issuance_between_acks() {
    let admitted = store::OnlineExpectation {
        certificate_sha256: "same-certificate".into(),
        not_after_unix_secs: 10_000,
        issued_generation: Some(7),
        snapshot_sha256: Some("snapshot-seven".into()),
    };
    let same = || store::OnlineExpectation {
        certificate_sha256: "same-certificate".into(),
        not_after_unix_secs: 10_000,
        issued_generation: Some(7),
        snapshot_sha256: Some("snapshot-seven".into()),
    };
    assert!(same_session_issuance(&admitted, &same()).is_ok());
    let mut generation = same();
    generation.issued_generation = Some(8);
    let mut snapshot = same();
    snapshot.snapshot_sha256 = Some("snapshot-eight".into());
    let mut removed = same();
    removed.issued_generation = None;
    removed.snapshot_sha256 = None;
    let mut expiry = same();
    expiry.not_after_unix_secs += 1;
    let mut certificate = same();
    certificate.certificate_sha256 = "replacement".into();
    for changed in [generation, snapshot, removed, expiry, certificate] {
        // The pre-existing refresh compared a freshly read expectation only
        // to itself and therefore accepted this unchanged certificate.
        assert!(same_session_issuance(&changed, &changed).is_ok());
        assert!(same_session_issuance(&admitted, &changed).is_err());
    }
}
