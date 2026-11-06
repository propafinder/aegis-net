use super::*;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use std::fs;

struct Fixture {
    _dir: tempfile::TempDir,
    registry: PathBuf,
    csr: PathBuf,
    invitation: PathBuf,
    ca: PathBuf,
    ca_key: PathBuf,
    output: PathBuf,
    now: u64,
}

fn fixture(ttl: u64) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let registry = dir.path().join("registry.json");
    initialize(&registry).unwrap();
    let invitation = dir.path().join("invitation.txt");
    let now = registry::unix_now().unwrap();
    invite(&registry, "device-a", &invitation, ttl, now).unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let ca_cert = params.self_signed(&key).unwrap();
    let ca = dir.path().join("ca.pem");
    enrollment::write_private_new(&ca, ca_cert.pem().as_bytes()).unwrap();
    let ca_key = dir.path().join("ca.key");
    enrollment::write_private_new(&ca_key, key.serialize_pem().as_bytes()).unwrap();
    let material = enrollment::generate_csr("device-a").unwrap();
    let csr = dir.path().join("device.csr");
    enrollment::write_private_new(&csr, material.csr_pem.as_bytes()).unwrap();
    enrollment::write_private_new(
        &dir.path().join("device.key"),
        material.private_key_pem.as_bytes(),
    )
    .unwrap();
    let output = dir.path().join("device.pem");
    Fixture {
        _dir: dir,
        registry,
        csr,
        invitation,
        ca,
        ca_key,
        output,
        now,
    }
}

fn issue_fixture(f: &Fixture, now: u64, output: &Path) -> Result<registry::DeviceRecord> {
    issue_with_clock(
        &f.registry,
        &f.csr,
        &f.invitation,
        &f.ca,
        &f.ca_key,
        output,
        3600,
        || Ok(now),
    )
}

fn policy_validity(path: &Path) -> serde_json::Value {
    serde_json::to_value(DeviceRegistry::load(path).unwrap().validity).unwrap()
}

#[test]
fn device_enrollment_consumes_invitation_once_and_revoke_is_persistent() {
    let f = fixture(300);
    let original_validity = policy_validity(&f.registry);
    let record = issue_fixture(&f, f.now, &f.output).unwrap();
    assert_eq!(policy_validity(&f.registry), original_validity);
    assert_eq!(record.device_id, "device-a");
    assert_eq!(record.not_after_unix_secs, f.now + 3600);
    let snapshot = DeviceRegistry::load(&f.registry).unwrap();
    assert!(snapshot.invitations[0].consumed);
    assert_eq!(snapshot.devices.len(), 1);
    assert!(issue_fixture(&f, f.now, &f._dir.path().join("replay.pem")).is_err());
    assert_eq!(
        DeviceRegistry::load(&f.registry).unwrap().generation,
        snapshot.generation
    );
    let token = fs::read_to_string(&f.invitation).unwrap();
    let serialized = fs::read_to_string(&f.registry).unwrap();
    assert!(!serialized.contains(&token));
    assert!(!serialized.contains("PRIVATE KEY"));
    let certificate =
        CertificateParams::from_ca_cert_pem(&fs::read_to_string(&f.output).unwrap()).unwrap();
    assert_eq!(
        certificate.extended_key_usages,
        vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth]
    );
    assert_eq!(
        certificate.key_usages,
        vec![KeyUsagePurpose::DigitalSignature]
    );
    assert!(matches!(certificate.is_ca, IsCa::NoCa));
    assert!(certificate.subject_alt_names.is_empty());
    revoke(&f.registry, "device-a").unwrap();
    let revoked = DeviceRegistry::load(&f.registry).unwrap();
    assert_eq!(policy_validity(&f.registry), original_validity);
    assert!(revoked.devices[0].revoked);
    assert!(revoked.generation > snapshot.generation);
    revoke(&f.registry, "device-a").unwrap();
    assert_eq!(
        DeviceRegistry::load(&f.registry).unwrap().generation,
        revoked.generation
    );
    invite(
        &f.registry,
        "device-b",
        &f._dir.path().join("device-b.invitation"),
        300,
        f.now + 1,
    )
    .unwrap();
    assert_eq!(policy_validity(&f.registry), original_validity);
}

#[test]
fn expired_invitation_and_invalid_csr_do_not_consume_authorization() {
    let f = fixture(1);
    assert!(issue_fixture(&f, f.now + 1, &f.output).is_err());
    assert!(!DeviceRegistry::load(&f.registry).unwrap().invitations[0].consumed);
    fs::write(&f.csr, b"invalid CSR fixture").unwrap();
    assert!(issue_fixture(&f, f.now, &f.output).is_err());
    assert!(!DeviceRegistry::load(&f.registry).unwrap().invitations[0].consumed);
    assert!(!f.output.exists());
}

#[test]
fn invitation_expiring_while_issue_waits_for_lock_is_not_consumed() {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{mpsc, Arc};
    use std::time::Duration;

    let f = Arc::new(fixture(1));
    let original_registry = fs::read(&f.registry).unwrap();
    let original_floor = fs::read(registry_floor(&f.registry)).unwrap();
    let clock = Arc::new(AtomicU64::new(f.now));
    let transaction = Transaction::begin(&f.registry).unwrap();
    let (started_tx, started_rx) = mpsc::channel();
    let (observed_tx, observed_rx) = mpsc::channel();
    let worker = {
        let f = f.clone();
        let clock = clock.clone();
        std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            issue_with_clock(
                &f.registry,
                &f.csr,
                &f.invitation,
                &f.ca,
                &f.ca_key,
                &f.output,
                3600,
                || {
                    let now = clock.load(Ordering::SeqCst);
                    observed_tx.send(now).unwrap();
                    Ok(now)
                },
            )
        })
    };
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(matches!(
        observed_rx.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    // Advance the injected clock while the real registry lock is still held;
    // invitation expiry never depends on sleeping until a wall-clock second.
    clock.store(f.now + 1, Ordering::SeqCst);
    drop(transaction);
    assert_eq!(
        observed_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        f.now + 1
    );
    let error = worker.join().unwrap().unwrap_err();
    assert!(error.to_string().contains("invitation expired"));
    assert!(!f.output.exists());
    assert!(!registry::pending_path(&f.registry).exists());
    assert_eq!(fs::read(&f.registry).unwrap(), original_registry);
    assert_eq!(
        fs::read(registry_floor(&f.registry)).unwrap(),
        original_floor
    );
    assert!(!DeviceRegistry::load(&f.registry).unwrap().invitations[0].consumed);
}

#[test]
fn incorrect_ca_key_and_existing_output_fail_without_consuming_invitation() {
    let f = fixture(300);
    let other = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let original = fs::read(&f.ca_key).unwrap();
    fs::write(&f.ca_key, other.serialize_pem()).unwrap();
    assert!(issue_fixture(&f, f.now, &f.output).is_err());
    assert!(!DeviceRegistry::load(&f.registry).unwrap().invitations[0].consumed);
    fs::write(&f.ca_key, original).unwrap();
    enrollment::write_private_new(&f.output, b"existing user file").unwrap();
    assert!(issue_fixture(&f, f.now, &f.output).is_err());
    assert_eq!(fs::read(&f.output).unwrap(), b"existing user file");
    assert!(!DeviceRegistry::load(&f.registry).unwrap().invitations[0].consumed);
}

#[test]
fn concurrent_issuance_has_one_durable_winner() {
    let f = std::sync::Arc::new(fixture(300));
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|index| {
            let f = f.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                issue_fixture(&f, f.now, &f._dir.path().join(format!("cert-{index}.pem"))).is_ok()
            })
        })
        .collect();
    let successes = workers
        .into_iter()
        .map(|w| usize::from(w.join().unwrap()))
        .sum::<usize>();
    assert_eq!(successes, 1);
    let registry = DeviceRegistry::load(&f.registry).unwrap();
    assert!(registry.invitations[0].consumed);
    assert_eq!(registry.devices.len(), 1);
}

#[test]
fn explicit_rotation_renews_expired_identity_once_and_preserves_old_until_commit() {
    let mut f = fixture(300);
    let original_validity = policy_validity(&f.registry);
    let old = issue_fixture(&f, f.now, &f.output).unwrap();
    f.now = old.not_after_unix_secs + 1;
    f.invitation = f._dir.path().join("rotation.invitation");
    assert!(invite(&f.registry, "device-a", &f.invitation, 300, f.now).is_err());
    rotate_invite(&f.registry, "device-a", &f.invitation, 300, f.now).unwrap();
    assert_eq!(policy_validity(&f.registry), original_validity);
    assert_eq!(
        DeviceRegistry::load(&f.registry).unwrap().devices[0].certificate_sha256,
        old.certificate_sha256
    );
    let replacement = enrollment::generate_csr("device-a").unwrap();
    fs::write(&f.csr, replacement.csr_pem).unwrap();
    // Failed output must not retire the old identity or consume authorization.
    assert!(issue_fixture(&f, f.now, &f.output).is_err());
    let pending = DeviceRegistry::load(&f.registry).unwrap();
    assert_eq!(
        pending.devices[0].certificate_sha256,
        old.certificate_sha256
    );
    assert!(!pending.invitations[1].consumed);
    let renewed = issue_fixture(&f, f.now, &f._dir.path().join("renewed.pem")).unwrap();
    assert_eq!(policy_validity(&f.registry), original_validity);
    let committed = DeviceRegistry::load(&f.registry).unwrap();
    assert_eq!(committed.devices.len(), 1);
    assert_ne!(renewed.certificate_sha256, old.certificate_sha256);
    assert!(renewed.not_after_unix_secs > old.not_after_unix_secs);
    assert_eq!(
        committed.devices[0].certificate_sha256,
        renewed.certificate_sha256
    );
    assert!(committed.invitations[1].consumed);
    assert!(issue_fixture(&f, f.now, &f._dir.path().join("replayed.pem")).is_err());
}

#[test]
fn rotation_does_not_resurrect_revoked_or_superseded_identity() {
    for revoked in [true, false] {
        let mut f = fixture(300);
        issue_fixture(&f, f.now, &f.output).unwrap();
        f.invitation = f._dir.path().join("rotation.invitation");
        rotate_invite(&f.registry, "device-a", &f.invitation, 300, f.now).unwrap();
        if revoked {
            revoke(&f.registry, "device-a").unwrap();
        } else {
            // An operator replaced the current key through another lifecycle.
            let transaction = Transaction::begin(&f.registry).unwrap();
            let mut registry = transaction.load().unwrap();
            registry.devices[0].certificate_sha256 = "ab".repeat(32);
            advance(&mut registry).unwrap();
            transaction.save(&f.registry, &registry, false).unwrap();
        }
        assert!(issue_fixture(&f, f.now, &f._dir.path().join("forbidden.pem")).is_err());
        assert!(!DeviceRegistry::load(&f.registry).unwrap().invitations[1].consumed);
        if revoked {
            assert!(rotate_invite(
                &f.registry,
                "device-a",
                &f._dir.path().join("new.invitation"),
                300,
                f.now + 301
            )
            .is_err());
        }
    }
}

#[test]
fn operator_cli_parses_registry_commands_before_file_access() {
    #[derive(clap::Parser)]
    struct Cli {
        #[command(flatten)]
        device: DeviceArgs,
    }
    use clap::Parser;
    let parsed = Cli::try_parse_from([
        "device",
        "--registry",
        "fixture.json",
        "rotate-invite",
        "--device-id",
        "device-a",
        "--token-out",
        "fixture.invitation",
    ])
    .unwrap();
    assert!(matches!(
        parsed.device.command,
        DeviceCommand::RotateInvite { .. }
    ));
    assert!(Cli::try_parse_from(["device", "init"]).is_err());
    let parsed = Cli::try_parse_from([
        "device",
        "--registry",
        "replica.json",
        "apply-snapshot",
        "--input",
        "trusted-snapshot.json",
    ])
    .unwrap();
    assert_eq!(parsed.device.registry, PathBuf::from("replica.json"));
    assert!(matches!(
        parsed.device.command,
        DeviceCommand::ApplySnapshot { input } if input == Path::new("trusted-snapshot.json")
    ));
    assert!(
        Cli::try_parse_from(["device", "--registry", "replica.json", "apply-snapshot"]).is_err()
    );
    let parsed =
        Cli::try_parse_from(["device", "--registry", "replica.json", "refresh-registry"]).unwrap();
    assert!(matches!(
        parsed.device.command,
        DeviceCommand::RefreshRegistry { ttl_secs: 900 }
    ));
    let parsed = Cli::try_parse_from([
        "device",
        "--registry",
        "replica.json",
        "refresh-registry",
        "--ttl-secs",
        "1800",
    ])
    .unwrap();
    assert!(matches!(
        parsed.device.command,
        DeviceCommand::RefreshRegistry { ttl_secs: 1800 }
    ));
}

fn registry_floor(path: &Path) -> PathBuf {
    let mut floor = path.as_os_str().to_os_string();
    floor.push(".floor");
    PathBuf::from(floor)
}

fn trusted_snapshot(path: &Path, generation: u64, revoked: bool) {
    let snapshot = DeviceRegistry {
        generation,
        devices: vec![registry::DeviceRecord {
            device_id: "snapshot-device".into(),
            certificate_sha256: "ab".repeat(32),
            not_after_unix_secs: 4_000_000_000,
            revoked,
        }],
        ..Default::default()
    };
    enrollment::write_private_new(path, &serde_json::to_vec_pretty(&snapshot).unwrap()).unwrap();
}

fn apply_snapshot_command(target: &Path, input: &Path) -> Result<()> {
    run(DeviceArgs {
        registry: target.to_owned(),
        command: DeviceCommand::ApplySnapshot {
            input: input.to_owned(),
        },
    })
}

#[test]
fn operator_init_creates_private_floor_and_refuses_overwrite() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("registry.json");
    let before = registry::unix_now().unwrap();
    run(DeviceArgs {
        registry: path.clone(),
        command: DeviceCommand::Init,
    })
    .unwrap();
    let after = registry::unix_now().unwrap();
    let floor = registry_floor(&path);
    let original_registry = fs::read(&path).unwrap();
    let original_floor = fs::read(&floor).unwrap();
    assert!(!original_floor.is_empty());
    for private in [&path, &floor] {
        assert_eq!(
            fs::metadata(private).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let initialized = DeviceRegistry::load(&path).unwrap();
    assert_eq!(initialized.version, 2);
    assert_eq!(initialized.generation, 1);
    let validity = initialized.validity.unwrap();
    assert!((before..=after).contains(&validity.issued_at_unix_secs));
    assert_eq!(
        validity.expires_at_unix_secs - validity.issued_at_unix_secs,
        900
    );
    assert!(run(DeviceArgs {
        registry: path.clone(),
        command: DeviceCommand::Init,
    })
    .is_err());
    assert_eq!(fs::read(&path).unwrap(), original_registry);
    assert_eq!(fs::read(&floor).unwrap(), original_floor);
}

#[test]
fn snapshot_command_accepts_new_target_replay_and_newer_revocation() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("replica.json");
    let initial = dir.path().join("generation-7.json");
    trusted_snapshot(&initial, 7, false);
    assert!(!registry_floor(&initial).exists());

    apply_snapshot_command(&target, &initial).unwrap();
    let loaded = DeviceRegistry::load(&target).unwrap();
    assert_eq!(loaded.generation, 7);
    assert!(!loaded.devices[0].revoked);
    let accepted_registry = fs::read(&target).unwrap();
    let accepted_floor = fs::read(registry_floor(&target)).unwrap();
    apply_snapshot_command(&target, &initial).unwrap();
    assert_eq!(fs::read(&target).unwrap(), accepted_registry);
    assert_eq!(fs::read(registry_floor(&target)).unwrap(), accepted_floor);

    let revoked = dir.path().join("generation-8.json");
    trusted_snapshot(&revoked, 8, true);
    apply_snapshot_command(&target, &revoked).unwrap();
    let loaded = DeviceRegistry::load(&target).unwrap();
    assert_eq!(loaded.generation, 8);
    assert!(loaded.devices[0].revoked);
}

#[test]
fn snapshot_command_rejects_rollback_and_same_generation_changes_without_writes() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("replica.json");
    let accepted = dir.path().join("accepted.json");
    trusted_snapshot(&accepted, 8, true);
    apply_snapshot_command(&target, &accepted).unwrap();
    let accepted_registry = fs::read(&target).unwrap();
    let accepted_floor = fs::read(registry_floor(&target)).unwrap();

    for (name, generation) in [("older", 7), ("changed", 8)] {
        let rejected = dir.path().join(format!("{name}.json"));
        trusted_snapshot(&rejected, generation, false);
        assert!(apply_snapshot_command(&target, &rejected).is_err());
        assert_eq!(fs::read(&target).unwrap(), accepted_registry);
        assert_eq!(fs::read(registry_floor(&target)).unwrap(), accepted_floor);
        assert!(DeviceRegistry::load(&target).unwrap().devices[0].revoked);
    }
}

#[test]
fn snapshot_command_recovers_interrupted_publication_only_from_exact_floor_snapshot() {
    for missing_registry in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("replica.json");
        let old = dir.path().join("old.json");
        let accepted = dir.path().join("accepted.json");
        let changed = dir.path().join("changed.json");
        let newer = dir.path().join("newer.json");
        trusted_snapshot(&old, 7, false);
        trusted_snapshot(&accepted, 8, true);
        trusted_snapshot(&changed, 8, false);
        trusted_snapshot(&newer, 9, true);
        apply_snapshot_command(&target, &old).unwrap();
        let old_registry = fs::read(&target).unwrap();
        apply_snapshot_command(&target, &accepted).unwrap();
        let accepted_registry = fs::read(&target).unwrap();
        let accepted_floor = fs::read(registry_floor(&target)).unwrap();

        // Reproduce the observable state after the floor became durable but
        // the corresponding registry replacement did not finish.
        if missing_registry {
            fs::remove_file(&target).unwrap();
        } else {
            fs::write(&target, &old_registry).unwrap();
        }
        assert!(DeviceRegistry::load(&target).is_err());
        for rejected in [&old, &changed, &newer] {
            assert!(apply_snapshot_command(&target, rejected).is_err());
            assert_eq!(fs::read(registry_floor(&target)).unwrap(), accepted_floor);
            if missing_registry {
                assert!(!target.exists());
            } else {
                assert_eq!(fs::read(&target).unwrap(), old_registry);
            }
        }

        apply_snapshot_command(&target, &accepted).unwrap();
        assert_eq!(fs::read(&target).unwrap(), accepted_registry);
        assert_eq!(fs::read(registry_floor(&target)).unwrap(), accepted_floor);
        let loaded = DeviceRegistry::load(&target).unwrap();
        assert_eq!(loaded.generation, 8);
        assert!(loaded.devices[0].revoked);
    }
}

#[test]
fn pending_snapshot_blocks_operator_changes_until_explicit_snapshot_recovery() {
    let f = fixture(300);
    issue_fixture(&f, f.now, &f.output).unwrap();
    let mut intended = DeviceRegistry::load(&f.registry).unwrap();
    intended.generation += 1;
    intended.devices[0].revoked = true;
    let pending = registry::pending_path(&f.registry);
    let pending_bytes = serde_json::to_vec_pretty(&intended).unwrap();
    let original_registry = fs::read(&f.registry).unwrap();
    let original_floor = fs::read(registry_floor(&f.registry)).unwrap();

    // The durable pending snapshot exists, but neither the old floor nor the
    // current authorization registry has been replaced yet.
    enrollment::write_private_new(&pending, &pending_bytes).unwrap();
    let new_invitation = f._dir.path().join("another-device.invitation");
    assert!(invite(&f.registry, "device-b", &new_invitation, 300, f.now).is_err());
    assert!(!new_invitation.exists());
    assert_eq!(fs::read(&f.registry).unwrap(), original_registry);
    assert_eq!(
        fs::read(registry_floor(&f.registry)).unwrap(),
        original_floor
    );
    assert_eq!(fs::read(&pending).unwrap(), pending_bytes);
    assert!(revoke(&f.registry, "device-a").is_err());
    assert_eq!(fs::read(&f.registry).unwrap(), original_registry);
    assert_eq!(
        fs::read(registry_floor(&f.registry)).unwrap(),
        original_floor
    );
    assert_eq!(fs::read(&pending).unwrap(), pending_bytes);

    apply_snapshot_command(&f.registry, &pending).unwrap();
    assert!(!pending.exists());
    assert!(!new_invitation.exists());
    let recovered = DeviceRegistry::load(&f.registry).unwrap();
    assert_eq!(recovered.generation, intended.generation);
    assert!(recovered.devices[0].revoked);
    assert_eq!(recovered.invitations.len(), intended.invitations.len());
}

#[test]
fn refresh_explicitly_migrates_a_legacy_registry_with_its_durable_floor() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("legacy-input.json");
    let target = dir.path().join("registry.json");
    trusted_snapshot(&input, 7, false);
    apply_snapshot_command(&target, &input).unwrap();
    let legacy = DeviceRegistry::load(&target).unwrap();
    assert_eq!(legacy.version, 1);
    assert!(legacy.validity.is_none());
    invite(
        &target,
        "legacy-device",
        &dir.path().join("legacy.invitation"),
        60,
        1000,
    )
    .unwrap();
    let legacy = DeviceRegistry::load(&target).unwrap();
    assert_eq!(legacy.version, 1);
    assert!(legacy.validity.is_none());

    let refreshed = refresh_registry_with_clock(&target, 900, || Ok(1000)).unwrap();
    assert_eq!(refreshed.version, 2);
    assert_eq!(refreshed.generation, legacy.generation + 1);
    let validity = refreshed.validity.as_ref().unwrap();
    assert_eq!(validity.issued_at_unix_secs, 1000);
    assert_eq!(validity.expires_at_unix_secs, 1900);
    assert_eq!(
        serde_json::to_value(&refreshed.devices).unwrap(),
        serde_json::to_value(&legacy.devices).unwrap()
    );
    assert_eq!(
        serde_json::to_value(&refreshed.invitations).unwrap(),
        serde_json::to_value(&legacy.invitations).unwrap()
    );
    assert_eq!(
        serde_json::to_value(DeviceRegistry::load(&target).unwrap()).unwrap(),
        serde_json::to_value(refreshed).unwrap()
    );
    assert!(!registry::pending_path(&target).exists());
}

#[test]
fn refresh_does_not_migrate_a_legacy_registry_without_its_floor() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("registry.json");
    trusted_snapshot(&target, 7, false);
    let original = fs::read(&target).unwrap();
    assert!(refresh_registry_with_clock(&target, 900, || Ok(1000)).is_err());
    assert_eq!(fs::read(&target).unwrap(), original);
    assert!(!registry_floor(&target).exists());
    assert!(!registry::pending_path(&target).exists());
}

#[test]
fn refresh_can_renew_an_expired_v2_registry_administratively() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("registry.json");
    let expired = DeviceRegistry::new(1000, 60).unwrap();
    registry::publish_snapshot(&target, &expired).unwrap();
    assert_eq!(
        DeviceRegistry::load(&target)
            .unwrap()
            .validity
            .unwrap()
            .expires_at_unix_secs,
        1060
    );

    let refreshed = refresh_registry_with_clock(&target, 120, || Ok(1100)).unwrap();
    assert_eq!(refreshed.version, 2);
    assert_eq!(refreshed.generation, expired.generation + 1);
    let validity = refreshed.validity.as_ref().unwrap();
    assert_eq!(validity.issued_at_unix_secs, 1100);
    assert_eq!(validity.expires_at_unix_secs, 1220);
    assert_eq!(
        serde_json::to_value(DeviceRegistry::load(&target).unwrap()).unwrap(),
        serde_json::to_value(refreshed).unwrap()
    );
}

#[test]
fn refresh_command_rejects_invalid_ttl_and_generation_overflow_without_writes() {
    for (generation, ttl_secs) in [(1, 0), (1, 3601), (u64::MAX, 900)] {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("registry.json");
        let original = DeviceRegistry {
            generation,
            ..DeviceRegistry::new(1000, 900).unwrap()
        };
        registry::publish_snapshot(&target, &original).unwrap();
        let original_registry = fs::read(&target).unwrap();
        let original_floor = fs::read(registry_floor(&target)).unwrap();

        assert!(run(DeviceArgs {
            registry: target.clone(),
            command: DeviceCommand::RefreshRegistry { ttl_secs },
        })
        .is_err());
        assert_eq!(fs::read(&target).unwrap(), original_registry);
        assert_eq!(fs::read(registry_floor(&target)).unwrap(), original_floor);
        assert!(!registry::pending_path(&target).exists());
    }
}
