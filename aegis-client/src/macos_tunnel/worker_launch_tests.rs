//! Native subprocess tests execute at the current UID and deliberately bypass
//! production account/custody admission. They do NOT prove privilege drop.
use super::*;
use crate::ingress::wide::ip_tunnel::PacketIo;
const FIXTURE: &str = "macos_tunnel::worker_launch::tests::";

fn fixture(name: &str, profile_path: &str) -> OwnedNetworkWorker {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(b"public-source-fixture").unwrap();
    use std::io::Seek;
    file.rewind().unwrap();
    let bootstrap = Bootstrap::new(
        "_aegis_current_uid_fixture",
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        Path::new("/source-fixture/private-metadata-only"),
        Path::new(profile_path),
        Sha256::digest(b"public-source-fixture").into(),
    )
    .unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.env(
        "AEGIS_WORKER_PARENT_SENTINEL",
        "source-only-public-sentinel",
    );
    command.args([
        "--exact",
        &format!("{FIXTURE}{name}"),
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ]);
    let mut owner =
        spawn_capabilities(command, file, bootstrap, Duration::from_secs(3), false).unwrap();
    // These wire/ownership fixtures do not exercise native identity readiness.
    owner.relay_permitted = true;
    owner
}
fn child_fixture() -> (Bootstrap, UnixStream, PacketPort, File) {
    // macOS can synthesize environment metadata during process startup. The
    // test's explicitly supplied parent sentinel must not survive env_clear.
    assert!(
        std::env::var_os("AEGIS_WORKER_PARENT_SENTINEL").is_none(),
        "launcher leaked inherited parent environment"
    );
    let mut control = unsafe { UnixStream::from_raw_fd(CONTROL_FD) };
    control.set_nonblocking(true).unwrap();
    let bootstrap: Bootstrap =
        receive(&mut control, budget(Duration::from_secs(3)).unwrap()).unwrap();
    bootstrap.validate().unwrap();
    let packet = unsafe { UnixStream::from_raw_fd(bootstrap.packet_fd) };
    let mut profile = unsafe { File::from_raw_fd(bootstrap.profile_fd) };
    let mut contents = String::new();
    profile.read_to_string(&mut contents).unwrap();
    assert_eq!(contents, "public-source-fixture");
    assert_eq!(
        (bootstrap.uid, bootstrap.gid),
        (unsafe { libc::geteuid() }, unsafe { libc::getegid() })
    );
    let (port, _) = PacketPort::new(packet, Role::Worker, Limits::default()).unwrap();
    send(
        &mut control,
        &Report::Started {
            pid: std::process::id(),
            uid: bootstrap.uid,
            gid: bootstrap.gid,
            nonce: bootstrap.nonce.clone(),
        },
        budget(Duration::from_secs(1)).unwrap(),
    )
    .unwrap();
    (bootstrap, control, port, profile)
}
fn ipv6() -> Vec<u8> {
    let mut packet = vec![0; 40];
    packet[0] = 0x60;
    packet
}
fn wait_packet(port: &mut PacketPort) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match port.receive() {
            Ok(Some(packet)) => return packet,
            Ok(None) => poll_pause(deadline).unwrap(),
            Err(e) => panic!("packet fixture failed: {e}"),
        }
    }
}

#[test]
#[ignore = "only launched by owned current-UID subprocess regressions"]
fn fixture_packets() {
    let (_boot, mut control, mut port, _profile) = child_fixture();
    let packet = wait_packet(&mut port);
    port.send(&packet).unwrap();
    port.flush_pending().unwrap();
    let mut bytes = [0; 1];
    let deadline = Instant::now() + Duration::from_secs(4);
    while control
        .read(&mut bytes)
        .is_err_and(|e| e.kind() == io::ErrorKind::WouldBlock)
    {
        poll_pause(deadline).unwrap();
    }
}
#[test]
#[ignore = "only launched by owned current-UID subprocess regressions"]
fn fixture_engine_no_ack() {
    let (boot, mut control, _port, _profile) = child_fixture();
    send(
        &mut control,
        &Report::EngineConstructed {
            pid: std::process::id(),
            nonce: boot.nonce,
        },
        budget(Duration::from_secs(1)).unwrap(),
    )
    .unwrap();
    let _: CaptureChallenge =
        receive(&mut control, budget(Duration::from_secs(1)).unwrap()).unwrap();
    // A live initialized engine without actual ACK must never admit capture.
    std::thread::sleep(Duration::from_secs(3));
}
#[test]
#[ignore = "only launched by owned current-UID subprocess regressions"]
fn fixture_wrong_challenge() {
    let (boot, mut control, _port, _profile) = child_fixture();
    send(
        &mut control,
        &Report::EngineConstructed {
            pid: std::process::id(),
            nonce: boot.nonce.clone(),
        },
        budget(Duration::from_secs(1)).unwrap(),
    )
    .unwrap();
    let _: CaptureChallenge =
        receive(&mut control, budget(Duration::from_secs(5)).unwrap()).unwrap();
    send(
        &mut control,
        &Report::PolicyConfirmed {
            pid: std::process::id(),
            nonce: boot.nonce,
            challenge: "00".repeat(16),
            certificate_sha256: "ab".repeat(32),
            remaining_ms: 5000,
            valid_until_ns: monotonic_deadline(Duration::from_secs(1)).unwrap(),
        },
        budget(Duration::from_secs(1)).unwrap(),
    )
    .unwrap();
    std::thread::sleep(Duration::from_secs(3));
}
#[test]
#[ignore = "only launched by owned current-UID subprocess regressions"]
fn fixture_expired_transit() {
    let (boot, mut control, _port, _profile) = child_fixture();
    send(
        &mut control,
        &Report::EngineConstructed {
            pid: std::process::id(),
            nonce: boot.nonce.clone(),
        },
        budget(Duration::from_secs(1)).unwrap(),
    )
    .unwrap();
    let CaptureChallenge {
        challenge,
        deadline_ns: _,
    } = receive(&mut control, budget(Duration::from_secs(5)).unwrap()).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    // Synthetic control contract only, not a successful relay ACK. The stale
    // 10ms grant must not be extended by the 50ms control transit.
    send(
        &mut control,
        &Report::PolicyConfirmed {
            pid: std::process::id(),
            nonce: boot.nonce,
            challenge,
            certificate_sha256: "ab".repeat(32),
            remaining_ms: 10,
            valid_until_ns: monotonic_ns().unwrap() - 1,
        },
        budget(Duration::from_secs(1)).unwrap(),
    )
    .unwrap();
    std::thread::sleep(Duration::from_secs(3));
}
#[test]
#[ignore = "only launched by owned current-UID subprocess regressions"]
fn fixture_no_inherited_extra_fd() {
    let (boot, _control, _port, _profile) = child_fixture();
    let fd: RawFd = boot
        .profile_path
        .strip_prefix("/fixture/leak/")
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
}
#[test]
#[ignore = "only launched by owned current-UID subprocess regressions"]
fn fixture_lowered_limits_launch() {
    let (_boot, _control, _port, _profile) = child_fixture();
    let file = tempfile::tempfile().unwrap();
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 256) };
    assert!(fd >= 256);
    let _owned = unsafe { OwnedFd::from_raw_fd(fd) };
    // Change both resource limits only inside this owned helper process. An
    // already-open descriptor survives above both new limits on Darwin.
    let limits = libc::rlimit {
        rlim_cur: 128,
        rlim_max: 128,
    };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limits) }, 0);
    assert_eq!(unsafe { libc::getdtablesize() }, 128);
    assert!(unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0);
    let mut worker = fixture(
        "fixture_no_inherited_extra_fd",
        &format!("/fixture/leak/{fd}"),
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(status) = worker.child.as_mut().unwrap().try_wait().unwrap() {
            assert!(
                status.success(),
                "retained high descriptor escaped filtering"
            );
            break;
        }
        poll_pause(deadline).unwrap();
    }
    worker.cancel(Duration::from_secs(1)).unwrap();
}
#[test]
#[ignore = "only launched by owned current-UID subprocess regressions"]
fn fixture_exit() {
    let _ = child_fixture();
}

#[test]
#[ignore = "only launched by owned current-UID subprocess regressions"]
fn fixture_packet_eof_held_alive() {
    let (_boot, _control, port, _profile) = child_fixture();
    drop(port);
    // Closing the packet capability is deliberately not a process-exit event.
    // Retain the other capabilities without reacting to control shutdown. This
    // test-only custody watchdog also bounds orphan lifetime if the parent dies.
    let deadline = Instant::now() + Duration::from_secs(10);
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        std::thread::park_timeout(remaining);
    }
}

#[test]
fn actual_owned_current_uid_packet_roundtrip_and_cancellation_do_not_kill_other_worker() {
    let mut worker = fixture("fixture_packets", "/fixture/public");
    let mut unrelated = fixture("fixture_packets", "/fixture/public");
    worker.port.send(&ipv6()).unwrap();
    assert_eq!(wait_packet(&mut worker.port), ipv6());
    worker.cancel(Duration::from_secs(2)).unwrap();
    assert!(worker.child.is_none());
    assert_eq!(
        worker.port.receive().unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert!(unrelated
        .child
        .as_mut()
        .unwrap()
        .try_wait()
        .unwrap()
        .is_none());
    unrelated.cancel(Duration::from_secs(2)).unwrap();
}
// A persistent owned spectator demonstrates that refusal affects only the
// tested Child. The 15s bound is fixture custody, not a transport deadline.
#[test]
#[ignore = "only launched by owned current-UID refusal regressions"]
fn fixture_refusal_spectator() {
    let (_boot, mut control, mut port, _profile) = child_fixture();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let mut bytes = [0; 1];
        match control.read(&mut bytes) {
            Ok(0) => return,
            Ok(_) => panic!("spectator received unexpected control bytes"),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("spectator control refused: {:?}", error.kind()),
        }
        if let Some(packet) = port.receive().unwrap() {
            port.send(&packet).unwrap();
            port.flush_pending().unwrap();
        }
        poll_pause(deadline).unwrap();
    }
}

fn refusal_phase(case: &'static str, phase: &'static str) {
    eprintln!("worker_refusal_fixture case={case} phase={phase}");
}

// This is test-only setup of an already constructed engine. It consumes a real
// child event and checks the held Child PID and bootstrap generation. It does
// not retest the production EngineConstructed parsing branch: the existing
// online/initial-admission tests cover that branch. The normal admission method
// still emits the fresh challenge and parses the real malformed response.
fn await_refusal_fixture_engine(worker: &mut OwnedNetworkWorker, case: &'static str) {
    refusal_phase(case, "engine_readiness_started");
    let report: Report = receive(&mut worker.control, budget(Duration::from_secs(3)).unwrap())
        .unwrap_or_else(|error| {
            panic!(
                "worker_refusal_fixture case={case} phase=engine_readiness kind={:?}",
                error.kind()
            )
        });
    let Report::EngineConstructed { pid, nonce } = report else {
        panic!("worker_refusal_fixture case={case} phase=engine_readiness unexpected_report");
    };
    assert!(pid == worker.id(), "engine event has foreign owned PID");
    assert!(nonce == worker.nonce, "engine event has foreign generation");
    assert!(worker.engine.is_none());
    assert!(worker.child.as_mut().unwrap().try_wait().unwrap().is_none());
    worker.engine = Some(EngineConstructed { pid });
    refusal_phase(case, "engine_readiness_confirmed");
}

fn assert_owned_refusal(
    worker: &mut OwnedNetworkWorker,
    spectator: &mut OwnedNetworkWorker,
    case: &'static str,
    timeout: Duration,
    expected: io::ErrorKind,
) {
    let (pid, nonce, uid, gid) = (worker.id(), worker.nonce.clone(), worker.uid, worker.gid);
    refusal_phase(case, "admission_started");
    let error = match worker.await_capture_admission(timeout) {
        Ok(_) => panic!("worker_refusal_fixture case={case} phase=admission unexpectedly_admitted"),
        Err(error) => error,
    };
    assert_eq!(
        error.kind(),
        expected,
        "worker_refusal_fixture case={case} phase=admission unexpected_error_kind"
    );
    refusal_phase(case, "expected_refusal_observed");
    assert!(worker.child.is_none(), "refused exact Child was not reaped");
    let exit = worker.cancel_owned(Duration::from_secs(1)).unwrap();
    assert!(exit.matches_binding(pid, &nonce));
    assert_eq!((exit.uid, exit.gid), (uid, gid));
    assert!(worker.exit.is_none(), "owned exit receipt was not consumed");
    refusal_phase(case, "owned_exit_confirmed");
    assert!(spectator
        .child
        .as_mut()
        .unwrap()
        .try_wait()
        .unwrap()
        .is_none());
    spectator.port.send(&ipv6()).unwrap();
    assert_eq!(wait_packet(&mut spectator.port), ipv6());
    refusal_phase(case, "spectator_roundtrip_after_refusal");
    spectator.cancel(Duration::from_secs(2)).unwrap();
}

fn refusal_spectator(case: &'static str) -> OwnedNetworkWorker {
    let mut spectator = fixture("fixture_refusal_spectator", "/fixture/public");
    spectator.port.send(&ipv6()).unwrap();
    assert_eq!(wait_packet(&mut spectator.port), ipv6());
    refusal_phase(case, "spectator_roundtrip_before_refusal");
    spectator
}

#[test]
fn actual_owned_current_uid_engine_without_ack_refuses_capture_on_original_deadline() {
    let case = "missing_ack";
    let mut spectator = refusal_spectator(case);
    let mut worker = fixture("fixture_engine_no_ack", "/fixture/public");
    // Original no-response deadline stays 180ms, including engine admission.
    assert_owned_refusal(
        &mut worker,
        &mut spectator,
        case,
        Duration::from_millis(180),
        io::ErrorKind::TimedOut,
    );
}

#[test]
fn actual_owned_current_uid_wrong_challenge_refuses_capture_after_engine_readiness() {
    let case = "wrong_challenge";
    let mut spectator = refusal_spectator(case);
    let mut worker = fixture("fixture_wrong_challenge", "/fixture/public");
    await_refusal_fixture_engine(&mut worker, case);
    // Payload validation has a separate finite transport budget. This is not
    // the no-response timing assertion or a production deadline extension.
    assert_owned_refusal(
        &mut worker,
        &mut spectator,
        case,
        Duration::from_secs(1),
        io::ErrorKind::InvalidData,
    );
}

#[test]
fn actual_owned_current_uid_stale_grant_refuses_capture_after_engine_readiness() {
    let case = "stale_grant";
    let mut spectator = refusal_spectator(case);
    let mut worker = fixture("fixture_expired_transit", "/fixture/public");
    await_refusal_fixture_engine(&mut worker, case);
    // Child retains its actual 50ms transit and native already-expired grant;
    // no fake wall clock or accepting TimedOut as stale-payload evidence.
    assert_owned_refusal(
        &mut worker,
        &mut spectator,
        case,
        Duration::from_secs(1),
        io::ErrorKind::InvalidData,
    );
}
#[test]
fn actual_owned_current_uid_eof_and_drop_close_capability_and_reap() {
    let mut worker = fixture("fixture_exit", "/fixture/public");
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match worker.port.receive() {
            Err(e) => {
                assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
                break;
            }
            Ok(None) => poll_pause(deadline).unwrap(),
            Ok(Some(_)) => panic!("unexpected packet"),
        }
    }
    // The fixture drops its packet FD before the libtest process has exited.
    // Observe the actual held Child within the same original EOF phase budget;
    // only then may cancellation retain an already-successful terminal status.
    loop {
        assert!(Instant::now() < deadline, "graceful exit phase expired");
        let status = worker.child.as_mut().unwrap().try_wait().unwrap();
        assert!(
            Instant::now() < deadline,
            "graceful exit observation was late"
        );
        if let Some(status) = status {
            assert!(status.success(), "graceful fixture exited unsuccessfully");
            break;
        }
        poll_pause(deadline).unwrap();
    }
    let (pid, nonce, uid, gid) = (worker.id(), worker.nonce.clone(), worker.uid, worker.gid);
    let exit = worker.cancel_owned(Duration::from_secs(1)).unwrap();
    assert!(exit.matches_binding(pid, &nonce));
    assert_eq!((exit.uid, exit.gid), (uid, gid));
    assert!(exit.status().success());
    assert!(worker.child.is_none());
    assert!(worker.exit.is_none());
    let worker = fixture("fixture_packets", "/fixture/public");
    let pid = worker.id();
    drop(worker);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if unsafe { libc::kill(pid as libc::pid_t, 0) } < 0 {
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
            break;
        }
        poll_pause(deadline).unwrap();
    }
}

#[test]
fn actual_packet_eof_before_child_exit_requires_owned_force_reap_only() {
    use std::os::unix::process::ExitStatusExt;

    let mut spectator = refusal_spectator("packet_eof_before_exit");
    let mut worker = fixture("fixture_packet_eof_held_alive", "/fixture/public");
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match worker.port.receive() {
            Err(error) => {
                assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
                break;
            }
            Ok(None) => poll_pause(deadline).unwrap(),
            Ok(Some(_)) => panic!("unexpected packet from EOF-held fixture"),
        }
    }
    assert!(
        Instant::now() < deadline,
        "EOF-held observation phase expired"
    );
    assert!(worker.child.as_mut().unwrap().try_wait().unwrap().is_none());
    assert!(Instant::now() < deadline, "EOF-held observation was late");
    let (pid, nonce, uid, gid) = (worker.id(), worker.nonce.clone(), worker.uid, worker.gid);
    let exit = worker.cancel_owned(Duration::from_secs(1)).unwrap();
    assert!(exit.matches_binding(pid, &nonce));
    assert_eq!((exit.uid, exit.gid), (uid, gid));
    assert!(!exit.status().success());
    assert_eq!(exit.status().signal(), Some(libc::SIGKILL));
    assert!(worker.child.is_none(), "exact held Child was not reaped");
    assert!(worker.exit.is_none(), "owned receipt was not consumed");
    assert_eq!(
        worker.port.receive().unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    assert!(spectator
        .child
        .as_mut()
        .unwrap()
        .try_wait()
        .unwrap()
        .is_none());
    spectator.port.send(&ipv6()).unwrap();
    assert_eq!(wait_packet(&mut spectator.port), ipv6());
    spectator.cancel(Duration::from_secs(2)).unwrap();
    assert!(spectator.child.is_none());
}
#[test]
fn actual_owned_subprocess_does_not_inherit_unrelated_open_file_capability() {
    let file = tempfile::tempfile().unwrap();
    let highest = unsafe { libc::getdtablesize() } - 1;
    assert!((64..1_048_576).contains(&highest));
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, highest) };
    assert_eq!(fd, highest);
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut worker = fixture(
        "fixture_no_inherited_extra_fd",
        &format!("/fixture/leak/{fd}"),
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    let status = loop {
        if let Some(status) = worker.child.as_mut().unwrap().try_wait().unwrap() {
            break status;
        }
        poll_pause(deadline).unwrap();
    };
    assert!(status.success());
    worker.cancel(Duration::from_secs(1)).unwrap();
    drop(owned);
}
#[test]
fn actual_owned_child_lowered_soft_and_hard_limits_do_not_escape_inheritance_filter() {
    let mut helper = fixture("fixture_lowered_limits_launch", "/fixture/public");
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        if let Some(status) = helper.child.as_mut().unwrap().try_wait().unwrap() {
            assert!(status.success(), "owned lowered-limit helper failed");
            break;
        }
        poll_pause(deadline).unwrap();
    }
    helper.cancel(Duration::from_secs(1)).unwrap();
}
#[test]
fn retained_descriptor_inventory_extends_kernel_bound_and_refuses_unsafe_or_truncated_facts() {
    let entry = |fd| libc::proc_fdinfo {
        proc_fd: fd,
        proc_fdtype: 0,
    };
    assert_eq!(
        descriptor_bound_from_inventory(128, 128, &[entry(256)]).unwrap(),
        257
    );
    assert_eq!(
        descriptor_bound_from_inventory(92160, 512, &[entry(256)]).unwrap(),
        92160
    );
    assert_eq!(
        descriptor_bound_from_inventory(128, 1024, &[entry(256)]).unwrap(),
        1024
    );
    for bound in [-1, 0, MAX_DESCRIPTOR + 1] {
        assert!(descriptor_bound_from_inventory(bound, 512, &[entry(256)]).is_err());
    }
    for capacity in [0, MAX_DESCRIPTOR as usize + 1] {
        assert!(descriptor_bound_from_inventory(128, capacity, &[entry(256)]).is_err());
    }
    assert!(descriptor_bound_from_inventory(128, 512, &[]).is_err());
    for fd in [-1, MAX_DESCRIPTOR] {
        assert!(descriptor_bound_from_inventory(128, 512, &[entry(fd)]).is_err());
    }
    assert!(
        descriptor_bound_from_inventory(128, 512, &vec![entry(3); MAX_RETAINED_DESCRIPTORS])
            .is_err()
    );
}
#[test]
fn capture_admission_is_bound_to_worker_generation_even_if_numeric_pid_matches() {
    let mut worker = fixture("fixture_packets", "/fixture/public");
    // Synthetic token construction tests only the ownership predicate; it is
    // not a real relay ACK or an attempt to force actual native PID reuse.
    let valid_until_ns = monotonic_deadline(Duration::from_secs(2)).unwrap();
    let same_generation = CaptureAdmission {
        pid: worker.id(),
        nonce: worker.nonce.clone(),
        valid_until_ns,
    };
    assert!(same_generation.is_current_for(&mut worker).unwrap());
    let mut other_nonce = worker.nonce.clone();
    other_nonce.replace_range(
        ..1,
        if other_nonce.starts_with('a') {
            "b"
        } else {
            "a"
        },
    );
    let other_generation = CaptureAdmission {
        pid: worker.id(),
        nonce: other_nonce,
        valid_until_ns,
    };
    assert!(!other_generation.is_current_for(&mut worker).unwrap());
    worker.cancel(Duration::from_secs(1)).unwrap();
    assert!(!same_generation.is_current_for(&mut worker).unwrap());
}
#[test]
fn bounded_control_refuses_partial_oversize_unknown_fields_and_invalid_versions() {
    for malformed in 0..5 {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        receiver.set_nonblocking(true).unwrap();
        let bytes = match malformed {
            0 => vec![b'A', b'W', 1],
            1 => {
                let mut b = vec![b'A', b'W', 2, 1];
                b.extend_from_slice(&((MAX_CONTROL + 1) as u32).to_be_bytes());
                b
            }
            2 => vec![b'A', b'W', 3, 1, 0, 0, 0, 1, b'{'],
            3 => {
                let body = br#"{"challenge":"00","extra":1}"#;
                let mut b = vec![b'A', b'W', 2, 1];
                b.extend_from_slice(&(body.len() as u32).to_be_bytes());
                b.extend_from_slice(body);
                b
            }
            _ => vec![b'A', b'W', 2, 1, 0, 0, 0, 3, b'{'],
        };
        sender.write_all(&bytes).unwrap();
        drop(sender);
        assert!(receive::<CaptureChallenge>(
            &mut receiver,
            budget(Duration::from_secs(1)).unwrap()
        )
        .is_err());
    }
}
#[test]
fn real_production_prepare_refuses_untrusted_paths_and_missing_account_before_spawn_or_policy() {
    for path in [
        "relative",
        "/private/var/../tmp/program",
        "/private/tmp/program",
    ] {
        assert!(open_trusted(Path::new(path), true, &[0; 32]).is_err());
    }
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("program");
    fs::write(&file, b"not approved executable").unwrap();
    assert!(open_trusted(&file, true, &[0; 32]).is_err());
    let alias = directory.path().join("alias");
    std::os::unix::fs::symlink(&file, &alias).unwrap();
    assert!(open_trusted(&alias, true, &[0; 32]).is_err());
    assert!(VerifiedLaunch::prepare(
        "_aegis_absent_worker_source_fixture",
        &file,
        [0; 32],
        directory.path(),
        &file,
        [0; 32]
    )
    .is_err());
    for duration in [Duration::ZERO, Duration::from_secs(6)] {
        assert!(budget(duration).is_err());
    }
}

#[test]
fn real_native_system_executable_requires_reviewed_digest_and_read_only_ancestry() {
    let path = Path::new("/usr/bin/true");
    let expected: [u8; 32] = Sha256::digest(fs::read(path).unwrap()).into();
    assert!(open_trusted(path, true, &expected).is_ok());
    assert!(open_trusted(path, true, &[0u8; 32]).is_err());
}

#[test]
fn public_profile_admission_refuses_root_only_permissions_before_spawn() {
    // These production predicates apply to every ancestor and final file both
    // at prepare and immediately before spawn. No native permission is changed.
    for mode in [0o700, 0o710, 0o740, 0o750, 0o777] {
        assert!(!public_directory_permissions(mode), "directory {mode:o}");
    }
    assert!(public_directory_permissions(0o755));
    for mode in [0o600, 0o640, 0o660, 0o4444, 0o666] {
        assert!(!public_file_permissions(mode, false), "profile {mode:o}");
    }
    assert!(public_file_permissions(0o644, false));
    for mode in [0o700, 0o750, 0o4755, 0o777] {
        assert!(!public_file_permissions(mode, true), "executable {mode:o}");
    }
    assert!(public_file_permissions(0o755, true));
    let path = Path::new("/usr/bin/true");
    let expected: [u8; 32] = Sha256::digest(fs::read(path).unwrap()).into();
    assert!(open_trusted(path, false, &expected).is_ok());
}

#[tokio::test]
async fn actual_policy_ack_constructor_refuses_unauthenticated_profile_without_capture_token() {
    let expected = crate::device_identity::store::OnlineExpectation {
        certificate_sha256: "ab".repeat(32),
        issued_generation: None,
        snapshot_sha256: None,
        not_after_unix_secs: u64::MAX,
    };
    assert!(
        AuthenticatedPolicyAck::confirm(&aegis_core::RelaySettings::default(), &expected)
            .await
            .is_err()
    );
}

#[test]
#[ignore = "only launched by owned current-UID subprocess regressions"]
fn fixture_shared_clock() {
    let (_boot, _control, mut port, _profile) = child_fixture();
    let mut packet = ipv6();
    packet[8..16].copy_from_slice(&monotonic_ns().unwrap().to_be_bytes());
    port.send(&packet).unwrap();
    port.flush_pending().unwrap();
    std::thread::sleep(Duration::from_secs(3));
}
#[test]
fn native_monotonic_epoch_is_shared_with_exact_owned_child() {
    let before = monotonic_ns().unwrap();
    let mut worker = fixture("fixture_shared_clock", "/fixture/public");
    let packet = wait_packet(&mut worker.port);
    let observed = u64::from_be_bytes(packet[8..16].try_into().unwrap());
    let after = monotonic_ns().unwrap();
    assert!(before <= observed && observed <= after);
    worker.cancel(Duration::from_secs(1)).unwrap();
}
#[test]
#[ignore = "only launched by owned current-UID subprocess regressions"]
fn fixture_phase_refresh() {
    let (boot, mut control, _port, _profile) = child_fixture();
    let challenge = "cd".repeat(16);
    send(
        &mut control,
        &Report::IdentityPrepared {
            pid: std::process::id(),
            nonce: boot.nonce.clone(),
            challenge: challenge.clone(),
        },
        budget(Duration::from_secs(1)).unwrap(),
    )
    .unwrap();
    let permission: RelayPermission =
        receive(&mut control, budget(Duration::from_secs(2)).unwrap()).unwrap();
    assert_eq!(permission.challenge, challenge);
    send(
        &mut control,
        &Report::EngineConstructed {
            pid: std::process::id(),
            nonce: boot.nonce.clone(),
        },
        budget(Duration::from_secs(1)).unwrap(),
    )
    .unwrap();
    for _ in 0..2 {
        let request: CaptureChallenge =
            receive(&mut control, budget(Duration::from_secs(2)).unwrap()).unwrap();
        // Synthetic reports prove strict parent ownership/wire transitions only.
        // Actual live ACK+packet behavior is in the separate online fixture.
        send(
            &mut control,
            &Report::PolicyConfirmed {
                pid: std::process::id(),
                nonce: boot.nonce.clone(),
                challenge: request.challenge,
                certificate_sha256: "ab".repeat(32),
                remaining_ms: 1000,
                valid_until_ns: request
                    .deadline_ns
                    .min(monotonic_deadline(Duration::from_secs(1)).unwrap()),
            },
            budget(Duration::from_secs(1)).unwrap(),
        )
        .unwrap();
    }
    std::thread::sleep(Duration::from_secs(3));
}
#[test]
fn parent_phase_permission_requires_owned_event_then_refresh_uses_same_engine() {
    let mut worker = fixture("fixture_phase_refresh", "/fixture/public");
    worker.relay_permitted = false;
    assert!(worker
        .await_capture_admission(Duration::from_secs(1))
        .is_err());
    let prepared = worker
        .await_identity_prepared(Duration::from_secs(2))
        .unwrap();
    assert!(prepared.is_current_for(&mut worker).unwrap());
    worker
        .permit_relay(&prepared, Duration::from_secs(1))
        .unwrap();
    assert!(!prepared.is_current_for(&mut worker).unwrap());
    let first = worker
        .await_capture_admission(Duration::from_secs(2))
        .unwrap();
    assert!(first.is_current_for(&mut worker).unwrap());
    let second = worker
        .await_capture_admission(Duration::from_secs(2))
        .unwrap();
    assert!(second.is_current_for(&mut worker).unwrap());
    worker.cancel(Duration::from_secs(1)).unwrap();
    assert!(!second.is_current_for(&mut worker).unwrap());
}

#[test]
fn confirmed_exit_is_only_exact_child_reaped_generation_not_a_drop_status() {
    let mut worker = fixture("fixture_packets", "/fixture/public");
    let pid = worker.id();
    let nonce = worker.generation_nonce().to_owned();
    let token = worker.cancel_owned(Duration::from_secs(1)).unwrap();
    assert!(token.matches_binding(pid, &nonce));
    assert!(!token.matches_binding(pid, &"ff".repeat(16)));
    assert!(!token.matches_binding(pid.wrapping_add(1), &nonce));
    assert!(worker.cancel_owned(Duration::from_secs(1)).is_err());
}

#[test]
fn phase_failure_internal_reap_preserves_one_owned_exit_receipt_for_parent() {
    let mut worker = fixture("fixture_wrong_challenge", "/fixture/public");
    let pid = worker.id();
    let nonce = worker.generation_nonce().to_owned();
    assert!(worker
        .await_capture_admission(Duration::from_secs(2))
        .is_err());
    assert!(worker.child.is_none());
    let receipt = worker.cancel_owned(Duration::from_secs(1)).unwrap();
    assert!(receipt.matches_binding(pid, &nonce));
    assert!(!receipt.matches_binding(pid, &"ff".repeat(16)));
    assert!(worker.cancel_owned(Duration::from_secs(1)).is_err());
}

#[tokio::test]
async fn actual_unix_control_supports_full_capture_refresh_budget_and_refuses_replay_or_overflow() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn write_frame<T: Serialize>(stream: &mut tokio::net::UnixStream, value: &T) {
        let bytes = serde_json::to_vec(value).unwrap();
        let mut header = [b'A', b'W', 2, 1, 0, 0, 0, 0];
        header[4..].copy_from_slice(&(bytes.len() as u32).to_be_bytes());
        stream.write_all(&header).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
    }
    async fn read_report(stream: &mut tokio::net::UnixStream) -> Report {
        let mut header = [0; 8];
        stream.read_exact(&mut header).await.unwrap();
        assert_eq!(header[..4], [b'A', b'W', 2, 1]);
        let length = u32::from_be_bytes(header[4..].try_into().unwrap()) as usize;
        assert!((1..=MAX_CONTROL).contains(&length));
        let mut body = vec![0; length];
        stream.read_exact(&mut body).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    // Actual Unix framing/control transitions and shared native cutoffs. These
    // rapid requests test a bounded history; they are not live ACKs or a 300s
    // installed capture. Duplicate refusal is checked after crossing old 256.
    tokio::time::timeout(Duration::from_secs(5), async {
        for (accepted, replay) in [(257, true), (512, false)] {
            let file = tempfile::tempfile().unwrap();
            let (mut parts, mut parent, _packets) =
                local_runtime_fixture("/fixture".into(), file);
            let phase = parts.control.identity_prepared().await.unwrap();
            assert!(matches!(read_report(&mut parent).await, Report::IdentityPrepared { challenge, .. } if challenge == phase));
            write_frame(&mut parent, &RelayPermission { challenge: phase.clone() }).await;
            parts.control.relay_permission(&phase).await.unwrap();
            parts.control.engine_constructed().await.unwrap();
            assert!(matches!(read_report(&mut parent).await, Report::EngineConstructed { .. }));
            for index in 0..accepted {
                let tag = format!("{index:032x}");
                let deadline_ns = monotonic_deadline(Duration::from_secs(5)).unwrap();
                write_frame(&mut parent, &CaptureChallenge { challenge: tag.clone(), deadline_ns }).await;
                let challenge = parts.control.challenge().await.unwrap();
                assert_eq!(challenge.challenge, tag);
                assert_eq!(challenge.deadline_ns, deadline_ns);
            }
            assert_eq!(parts.control.challenges.len(), accepted);
            let tag = format!("{:032x}", if replay { accepted - 1 } else { accepted });
            write_frame(&mut parent, &CaptureChallenge {
                challenge: tag,
                deadline_ns: monotonic_deadline(Duration::from_secs(5)).unwrap(),
            }).await;
            assert_eq!(parts.control.challenge().await.err().unwrap().kind(), io::ErrorKind::InvalidData);
            assert_eq!(parts.control.challenges.len(), accepted);
        }
    }).await.unwrap();
}
