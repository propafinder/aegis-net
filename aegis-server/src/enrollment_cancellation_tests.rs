//! Authored source regressions; use the real transaction/cancel/finish/recover
//! paths and deterministic publication barriers, never elapsed sleep ordering.
use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};

fn recovery(f: &Fixture) -> Issuer {
    Issuer::open_cancellation(&f.issuer.config).unwrap()
}

fn intent_path(f: &Fixture, device: &str) -> PathBuf {
    let mut path = f.issuer.config.registry.as_os_str().to_os_string();
    path.push(format!(".enrollment-cancel-{device}.json"));
    path.into()
}

#[test]
fn cancellation_before_late_issue_preserves_other_ids_policy_and_consumes_invitation() {
    let f = Fixture::new();
    let before = {
        let tx = RegistryTransaction::begin(&f.issuer.config.registry).unwrap();
        let mut current = tx.load().unwrap();
        current.devices.push(registry::DeviceRecord {
            device_id: "prior_device".into(),
            certificate_sha256: "cd".repeat(32),
            not_after_unix_secs: f.now + 900,
            revoked: false,
        });
        current.generation += 1;
        tx.save(&f.issuer.config.registry, &current, false).unwrap();
        current
    };
    // No signer is needed to cancel; a missing CA key does not become a reason
    // to re-sign, repair the authority, or borrow a different key.
    fs::remove_file(&f.issuer.config.ca_key).unwrap();
    recovery(&f).cancel_enrollment("device_a", None).unwrap();
    let after = DeviceRegistry::load(&f.issuer.config.registry).unwrap();
    assert_eq!(
        serde_json::to_value(&after.devices).unwrap(),
        serde_json::to_value(&before.devices).unwrap()
    );
    assert_eq!(after.validity, before.validity);
    assert_eq!(after.generation, before.generation + 1);
    assert!(after
        .invitations
        .iter()
        .filter(|row| row.device_id == "device_a")
        .all(|row| row.consumed));
    let invitation = f._dir.path().join("new-invitation");
    assert!(crate::devices::invite(
        &f.issuer.config.registry,
        "device_a",
        &invitation,
        60,
        f.now
    )
    .is_err());
    assert!(!invitation.exists());
    // Even a trusted later snapshot that accidentally reintroduces the old
    // invitation cannot bypass the separate exact-ID tombstone.
    {
        let tx = RegistryTransaction::begin(&f.issuer.config.registry).unwrap();
        let mut current = tx.load().unwrap();
        for invitation in current
            .invitations
            .iter_mut()
            .filter(|row| row.device_id == "device_a")
        {
            invitation.consumed = false;
        }
        current.generation += 1;
        tx.save(&f.issuer.config.registry, &current, false).unwrap();
    }
    let (request, mut challenge) =
        f.request(Operation::Redeem, ProofPurpose::Authorize, 1, None, f.now);
    assert!(f
        .issuer
        .exchange_with_clock(&request, &mut challenge, || Ok(f.now))
        .err()
        .expect("cancelled enrollment must refuse issuance")
        .to_string()
        .contains("permanently cancelled"));
    let csr = f._dir.path().join("late.csr");
    let token = f._dir.path().join("late.token");
    enrollment::write_private_new(&csr, f.key.csr_pem.as_bytes()).unwrap();
    enrollment::write_private_new(&token, f.token.as_bytes()).unwrap();
    assert!(crate::devices::issue(
        &f.issuer.config.registry,
        &csr,
        &token,
        &f.issuer.config.ca_cert,
        &f.issuer.config.ca_key,
        &f._dir.path().join("late.pem"),
        90
    )
    .unwrap_err()
    .to_string()
    .contains("permanently cancelled"));
    recovery(&f).cancel_enrollment("device_a", None).unwrap();
    let bytes = fs::read(&f.issuer.config.registry).unwrap();
    recovery(&f).cancel_enrollment("device_a", None).unwrap();
    assert_eq!(
        fs::read(&f.issuer.config.registry).unwrap(),
        bytes,
        "exact replay cannot renew validity/generation"
    );
}

#[test]
fn cancellation_published_certificate_requires_exact_cas_and_receipt_replay_refuses() {
    let f = Fixture::new();
    let receipt = f.issue();
    let registry = fs::read(&f.issuer.config.registry).unwrap();
    let floor = fs::read(registry::floor_path(&f.issuer.config.registry)).unwrap();
    for expected in [None, Some("ff".repeat(32))] {
        assert!(recovery(&f)
            .cancel_enrollment("device_a", expected.as_deref())
            .is_err());
        assert_eq!(fs::read(&f.issuer.config.registry).unwrap(), registry);
        assert_eq!(
            fs::read(registry::floor_path(&f.issuer.config.registry)).unwrap(),
            floor
        );
        assert!(!intent_path(&f, "device_a").exists());
    }
    recovery(&f)
        .cancel_enrollment("device_a", Some(&receipt.certificate_sha256))
        .unwrap();
    let current = DeviceRegistry::load(&f.issuer.config.registry).unwrap();
    let row = current
        .devices
        .iter()
        .find(|row| row.device_id == "device_a")
        .unwrap();
    assert!(row.revoked);
    assert_eq!(row.certificate_sha256, receipt.certificate_sha256);
    for purpose in [ProofPurpose::Receipt, ProofPurpose::Authorize] {
        let (request, mut challenge) = f.request(Operation::Redeem, purpose, 1, None, f.now + 1);
        assert!(f
            .issuer
            .exchange_with_clock(&request, &mut challenge, || Ok(f.now + 1))
            .is_err());
    }
    assert!(
        recovery(&f).cancel_enrollment("device_a", None).is_err(),
        "replay cannot remove original CAS"
    );
}

#[test]
fn cancellation_absent_id_without_invitation_blocks_later_invite_and_issue() {
    let f = Fixture::new();
    let old_invitation = {
        let tx = RegistryTransaction::begin(&f.issuer.config.registry).unwrap();
        let mut current = tx.load().unwrap();
        let invitation = current.invitations.remove(0);
        current.generation += 1;
        tx.save(&f.issuer.config.registry, &current, false).unwrap();
        invitation
    };
    let before = DeviceRegistry::load(&f.issuer.config.registry).unwrap();
    assert!(before.devices.is_empty() && before.invitations.is_empty());
    recovery(&f).cancel_enrollment("device_a", None).unwrap();
    let cancelled = DeviceRegistry::load(&f.issuer.config.registry).unwrap();
    assert_eq!(cancelled.generation, before.generation + 1);
    assert_eq!(cancelled.validity, before.validity);
    let token_out = f._dir.path().join("forbidden-new-invitation");
    assert!(
        crate::devices::invite(&f.issuer.config.registry, "device_a", &token_out, 60, f.now)
            .unwrap_err()
            .to_string()
            .contains("permanently cancelled")
    );
    assert!(!token_out.exists());
    // An independently trusted but mistaken delivery may reintroduce an old
    // invitation. It cannot turn the private exact-ID cancellation into a grant.
    {
        let tx = RegistryTransaction::begin(&f.issuer.config.registry).unwrap();
        let mut current = tx.load().unwrap();
        current.invitations.push(old_invitation);
        current.generation += 1;
        tx.save(&f.issuer.config.registry, &current, false).unwrap();
    }
    let (request, mut challenge) =
        f.request(Operation::Redeem, ProofPurpose::Authorize, 1, None, f.now);
    assert!(f
        .issuer
        .exchange_with_clock(&request, &mut challenge, || Ok(f.now))
        .err()
        .expect("cancelled enrollment must refuse issuance")
        .to_string()
        .contains("permanently cancelled"));
    let csr = f._dir.path().join("absent-id.csr");
    let token = f._dir.path().join("absent-id.token");
    enrollment::write_private_new(&csr, f.key.csr_pem.as_bytes()).unwrap();
    enrollment::write_private_new(&token, f.token.as_bytes()).unwrap();
    let certificate = f._dir.path().join("forbidden.pem");
    assert!(crate::devices::issue(
        &f.issuer.config.registry,
        &csr,
        &token,
        &f.issuer.config.ca_cert,
        &f.issuer.config.ca_key,
        &certificate,
        90
    )
    .unwrap_err()
    .to_string()
    .contains("permanently cancelled"));
    assert!(!certificate.exists());
    recovery(&f).cancel_enrollment("device_a", None).unwrap();
    let settled = fs::read(&f.issuer.config.registry).unwrap();
    recovery(&f).cancel_enrollment("device_a", None).unwrap();
    assert_eq!(fs::read(&f.issuer.config.registry).unwrap(), settled);
    assert_eq!(
        DeviceRegistry::load(&f.issuer.config.registry)
            .unwrap()
            .validity,
        before.validity
    );
}

#[test]
fn cancellation_all_original_journal_crash_cuts_are_revoked_before_barrier_is_removed() {
    for cut in 0..=4 {
        let f = Fixture::new();
        let receipt = interrupted(&f, cut);
        assert!(DeviceRegistry::load(&f.issuer.config.registry).is_err());
        let expected = (cut >= 3).then_some(receipt.certificate_sha256.as_str());
        let mut observations = 0;
        recovery(&f)
            .cancel_enrollment_with("device_a", expected, || {
                observations += 1;
                assert!(registry::issuance_pending_path(&f.issuer.config.registry).exists());
                assert!(
                    DeviceRegistry::load(&f.issuer.config.registry).is_err(),
                    "active authorization cannot escape the lock/barrier"
                );
                Ok(())
            })
            .unwrap();
        assert!(observations >= 2);
        let current = DeviceRegistry::load(&f.issuer.config.registry).unwrap();
        assert_eq!(current.generation, receipt.issued_generation + 1);
        assert!(
            current
                .devices
                .iter()
                .find(|row| row.device_id == "device_a")
                .unwrap()
                .revoked
        );
        assert!(!registry::issuance_pending_path(&f.issuer.config.registry).exists());
        assert!(!registry::pending_path(&f.issuer.config.registry).exists());
        let intent = fs::read(intent_path(&f, "device_a")).unwrap();
        recovery(&f)
            .cancel_enrollment("device_a", expected)
            .unwrap();
        assert_eq!(fs::read(intent_path(&f, "device_a")).unwrap(), intent);
    }
}

#[test]
fn cancellation_failure_at_each_finish_boundary_recovers_only_revoked_publication() {
    for failed_boundary in 1..=3 {
        let f = Fixture::new();
        let receipt = interrupted(&f, 0);
        let mut observations = 0;
        assert!(recovery(&f)
            .cancel_enrollment_with("device_a", None, || {
                observations += 1;
                assert!(DeviceRegistry::load(&f.issuer.config.registry).is_err());
                if observations == failed_boundary {
                    Err(rejected("deterministic cancellation crash cut"))
                } else {
                    Ok(())
                }
            })
            .is_err());
        assert!(registry::issuance_pending_path(&f.issuer.config.registry).exists());
        assert!(DeviceRegistry::load(&f.issuer.config.registry).is_err());
        recovery(&f).recover_pending().unwrap();
        let current = DeviceRegistry::load(&f.issuer.config.registry).unwrap();
        assert_eq!(current.generation, receipt.issued_generation + 1);
        assert!(
            current
                .devices
                .iter()
                .find(|row| row.device_id == "device_a")
                .unwrap()
                .revoked
        );
        let (request, mut challenge) =
            f.request(Operation::Redeem, ProofPurpose::Receipt, 1, None, f.now + 1);
        assert!(f
            .issuer
            .exchange_with_clock(&request, &mut challenge, || Ok(f.now + 1))
            .is_err());
    }
}

#[test]
fn cancellation_revoked_floor_before_snapshot_recovers_exactly_without_original_floor_rollback() {
    let f = Fixture::new();
    interrupted(&f, 0);
    let mut observations = 0;
    assert!(recovery(&f)
        .cancel_enrollment_with("device_a", None, || {
            observations += 1;
            if observations == 2 {
                Err(rejected("retain revoked snapshot/floor crash cut"))
            } else {
                Ok(())
            }
        })
        .is_err());
    let cancelled = DeviceRegistry::load_snapshot(&f.issuer.config.registry).unwrap();
    let pending: Pending = f.issuer.pending().unwrap().unwrap();
    let cancelled_floor = fs::read(registry::floor_path(&f.issuer.config.registry)).unwrap();
    fs::write(
        &f.issuer.config.registry,
        serde_json::to_vec(&pending.successor).unwrap(),
    )
    .unwrap();
    enrollment::write_private_new(
        &registry::pending_path(&f.issuer.config.registry),
        &serde_json::to_vec(&cancelled).unwrap(),
    )
    .unwrap();
    assert!(DeviceRegistry::load(&f.issuer.config.registry).is_err());
    recovery(&f).recover_pending().unwrap();
    assert_eq!(
        fs::read(registry::floor_path(&f.issuer.config.registry)).unwrap(),
        cancelled_floor
    );
    assert!(
        DeviceRegistry::load(&f.issuer.config.registry)
            .unwrap()
            .devices[0]
            .revoked
    );
}

#[test]
fn cancellation_standalone_pair_crash_cuts_never_restore_active_authorization() {
    for cut in 0..=3 {
        let f = Fixture::new();
        let receipt = f.issue();
        let old = fs::read(&f.issuer.config.registry).unwrap();
        let old_floor = fs::read(registry::floor_path(&f.issuer.config.registry)).unwrap();
        recovery(&f)
            .cancel_enrollment("device_a", Some(&receipt.certificate_sha256))
            .unwrap();
        let cancelled = fs::read(&f.issuer.config.registry).unwrap();
        let cancelled_floor = fs::read(registry::floor_path(&f.issuer.config.registry)).unwrap();
        let intent = fs::read(intent_path(&f, "device_a")).unwrap();
        // Retain the real intent while reconstructing deterministic cuts after
        // intent, pending, floor, and snapshot durability respectively.
        if cut < 3 {
            fs::write(&f.issuer.config.registry, &old).unwrap();
        }
        if cut < 2 {
            fs::write(registry::floor_path(&f.issuer.config.registry), &old_floor).unwrap();
        }
        if cut > 0 {
            enrollment::write_private_new(
                &registry::pending_path(&f.issuer.config.registry),
                &cancelled,
            )
            .unwrap();
        }
        if cut < 3 {
            assert!(
                DeviceRegistry::load(&f.issuer.config.registry).is_err(),
                "durable intent must deny the old active record even before the floor advances"
            );
        } else {
            assert!(
                DeviceRegistry::load(&f.issuer.config.registry)
                    .unwrap()
                    .devices[0]
                    .revoked
            );
        }
        assert!(!registry::issuance_pending_path(&f.issuer.config.registry).exists());
        recovery(&f)
            .cancel_enrollment("device_a", Some(&receipt.certificate_sha256))
            .unwrap();
        assert_eq!(fs::read(&f.issuer.config.registry).unwrap(), cancelled);
        assert_eq!(
            fs::read(registry::floor_path(&f.issuer.config.registry)).unwrap(),
            cancelled_floor
        );
        assert_eq!(fs::read(intent_path(&f, "device_a")).unwrap(), intent);
        assert!(!registry::pending_path(&f.issuer.config.registry).exists());
        assert!(
            DeviceRegistry::load(&f.issuer.config.registry)
                .unwrap()
                .devices[0]
                .revoked
        );
    }
}

#[test]
fn cancellation_does_not_adopt_an_unrelated_interrupted_snapshot() {
    let f = Fixture::new();
    let receipt = f.issue();
    let original = DeviceRegistry::load(&f.issuer.config.registry).unwrap();
    let old_bytes = fs::read(&f.issuer.config.registry).unwrap();
    let old_floor = fs::read(registry::floor_path(&f.issuer.config.registry)).unwrap();
    recovery(&f)
        .cancel_enrollment("device_a", Some(&receipt.certificate_sha256))
        .unwrap();
    let mut foreign = original;
    foreign.generation += 1;
    foreign.devices.push(registry::DeviceRecord {
        device_id: "prior_other".into(),
        certificate_sha256: "ef".repeat(32),
        not_after_unix_secs: f.now + 900,
        revoked: false,
    });
    let pending = serde_json::to_vec(&foreign).unwrap();
    fs::write(&f.issuer.config.registry, &old_bytes).unwrap();
    fs::write(registry::floor_path(&f.issuer.config.registry), &old_floor).unwrap();
    enrollment::write_private_new(&registry::pending_path(&f.issuer.config.registry), &pending)
        .unwrap();
    assert!(recovery(&f)
        .cancel_enrollment("device_a", Some(&receipt.certificate_sha256))
        .is_err());
    assert_eq!(fs::read(&f.issuer.config.registry).unwrap(), old_bytes);
    assert_eq!(
        fs::read(registry::floor_path(&f.issuer.config.registry)).unwrap(),
        old_floor
    );
    assert_eq!(
        fs::read(registry::pending_path(&f.issuer.config.registry)).unwrap(),
        pending
    );
    assert!(DeviceRegistry::load(&f.issuer.config.registry).is_err());
}

#[test]
fn cancellation_pending_renewal_requires_the_published_predecessor_cas() {
    let f = Fixture::new();
    let old_receipt = f.issue();
    let predecessor = DeviceRegistry::load(&f.issuer.config.registry).unwrap();
    let old_bytes = fs::read(&f.issuer.config.registry).unwrap();
    let old_floor = fs::read(registry::floor_path(&f.issuer.config.registry)).unwrap();
    let (request, mut challenge) = f.request(
        Operation::Renew,
        ProofPurpose::Authorize,
        2,
        Some(&old_receipt),
        f.now + 61,
    );
    let renewed = f
        .issuer
        .exchange_with_clock(&request, &mut challenge, || Ok(f.now + 61))
        .unwrap();
    let successor = DeviceRegistry::load(&f.issuer.config.registry).unwrap();
    let stored = f
        .issuer
        .receipt(&renewed.binding.request_id)
        .unwrap()
        .unwrap();
    let pending = Pending {
        version: 1,
        predecessor_generation: predecessor.generation,
        predecessor_sha256: hex::encode(registry::registry_digest(&predecessor).unwrap()),
        successor,
        stored,
    };
    fs::write(&f.issuer.config.registry, old_bytes).unwrap();
    fs::write(registry::floor_path(&f.issuer.config.registry), old_floor).unwrap();
    write_new(
        &registry::issuance_pending_path(&f.issuer.config.registry),
        &serialize(&pending, MAX_JOURNAL).unwrap(),
    )
    .unwrap();
    assert!(recovery(&f)
        .cancel_enrollment("device_a", Some(&renewed.certificate_sha256))
        .is_err());
    assert!(!intent_path(&f, "device_a").exists());
    let mut boundaries = 0;
    assert!(recovery(&f)
        .cancel_enrollment_with("device_a", Some(&old_receipt.certificate_sha256), || {
            boundaries += 1;
            if boundaries == 2 {
                Err(rejected("pending renewal revoked-floor cut"))
            } else {
                Ok(())
            }
        })
        .is_err());
    let cancelled = DeviceRegistry::load_snapshot(&f.issuer.config.registry).unwrap();
    let cancelled_floor = fs::read(registry::floor_path(&f.issuer.config.registry)).unwrap();
    fs::write(
        &f.issuer.config.registry,
        serde_json::to_vec(&pending.successor).unwrap(),
    )
    .unwrap();
    enrollment::write_private_new(
        &registry::pending_path(&f.issuer.config.registry),
        &serde_json::to_vec(&cancelled).unwrap(),
    )
    .unwrap();
    assert!(DeviceRegistry::load(&f.issuer.config.registry).is_err());
    recovery(&f).recover_pending().unwrap();
    assert_eq!(
        fs::read(registry::floor_path(&f.issuer.config.registry)).unwrap(),
        cancelled_floor
    );
    let current = DeviceRegistry::load(&f.issuer.config.registry).unwrap();
    let row = current
        .devices
        .iter()
        .find(|row| row.device_id == "device_a")
        .unwrap();
    assert!(row.revoked);
    assert_eq!(row.certificate_sha256, renewed.certificate_sha256);
    assert_eq!(current.generation, renewed.issued_generation + 1);
    for (operation, id, predecessor) in [
        (Operation::Redeem, 1, None),
        (Operation::Renew, 2, Some(&old_receipt)),
    ] {
        let (request, mut challenge) = f.request(
            operation,
            ProofPurpose::Receipt,
            id,
            predecessor,
            f.now + 62,
        );
        assert!(f
            .issuer
            .exchange_with_clock(&request, &mut challenge, || Ok(f.now + 62))
            .is_err());
    }
    recovery(&f)
        .cancel_enrollment("device_a", Some(&old_receipt.certificate_sha256))
        .unwrap();
}

#[test]
fn cancellation_unrelated_pending_and_missing_floor_refuse_without_new_intent() {
    let f = Fixture::new();
    interrupted(&f, 0);
    let journal = fs::read(registry::issuance_pending_path(&f.issuer.config.registry)).unwrap();
    assert!(recovery(&f).cancel_enrollment("prior_other", None).is_err());
    assert!(!intent_path(&f, "prior_other").exists());
    assert_eq!(
        fs::read(registry::issuance_pending_path(&f.issuer.config.registry)).unwrap(),
        journal
    );
    fs::remove_file(registry::floor_path(&f.issuer.config.registry)).unwrap();
    assert!(recovery(&f).cancel_enrollment("device_a", None).is_err());
    assert!(!intent_path(&f, "device_a").exists());
    assert_eq!(
        fs::read(registry::issuance_pending_path(&f.issuer.config.registry)).unwrap(),
        journal
    );
}

#[test]
fn cancellation_corrupt_foreign_links_and_permissions_refuse_without_registry_changes() {
    for problem in 0..5 {
        let f = Fixture::new();
        recovery(&f).cancel_enrollment("device_a", None).unwrap();
        let path = intent_path(&f, "device_a");
        let original = fs::read(&path).unwrap();
        let registry = fs::read(&f.issuer.config.registry).unwrap();
        let floor = fs::read(registry::floor_path(&f.issuer.config.registry)).unwrap();
        match problem {
            0 => {
                fs::write(&path, b"malformed").unwrap();
            }
            1 => {
                let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
                value["device_id"] = "prior_other".into();
                fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            }
            2 => {
                let other = f._dir.path().join("foreign-intent");
                fs::rename(&path, &other).unwrap();
                symlink(&other, &path).unwrap();
            }
            3 => {
                fs::hard_link(&path, f._dir.path().join("alias")).unwrap();
            }
            _ => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            }
        }
        assert!(recovery(&f).cancel_enrollment("device_a", None).is_err());
        assert_eq!(fs::read(&f.issuer.config.registry).unwrap(), registry);
        assert_eq!(
            fs::read(registry::floor_path(&f.issuer.config.registry)).unwrap(),
            floor
        );
    }
}

// Compatible with the original 370d cancellation API. Root can run this
// unchanged test before copying the protocol repair and retain the failure.
#[test]
fn cancel_recovers_exact_pending_revocation_before_floor_commit() {
    let f = Fixture::new();
    let receipt = interrupted(&f, 3);
    let active = DeviceRegistry::load_snapshot(&f.issuer.config.registry).unwrap();
    let active_floor = fs::read(registry::floor_path(&f.issuer.config.registry)).unwrap();
    let tx = RegistryTransaction::begin_issuance(&f.issuer.config.registry).unwrap();
    tx.record_enrollment_cancellation(
        "device_a",
        Some(&receipt.certificate_sha256),
        Some(&receipt.certificate_sha256),
        &active,
    )
    .unwrap();
    let intent = tx.enrollment_cancellation("device_a").unwrap().unwrap();
    let cancelled = intent.cancelled_snapshot(&active).unwrap().unwrap();
    // Exact crash cut after apply(C)'s pending write, before its floor write.
    enrollment::write_private_new(
        &registry::pending_path(&f.issuer.config.registry),
        &serde_json::to_vec(&cancelled).unwrap(),
    )
    .unwrap();
    drop(tx);
    assert_eq!(
        fs::read(registry::floor_path(&f.issuer.config.registry)).unwrap(),
        active_floor
    );
    assert!(DeviceRegistry::load(&f.issuer.config.registry).is_err());
    recovery(&f)
        .cancel_enrollment("device_a", Some(&receipt.certificate_sha256))
        .unwrap();
    let result = DeviceRegistry::load(&f.issuer.config.registry).unwrap();
    assert_eq!(
        registry::registry_digest(&result).unwrap(),
        registry::registry_digest(&cancelled).unwrap()
    );
    assert!(
        result
            .devices
            .iter()
            .find(|d| d.device_id == "device_a")
            .unwrap()
            .revoked
    );
    assert!(!registry::issuance_pending_path(&f.issuer.config.registry).exists());
    assert!(!registry::pending_path(&f.issuer.config.registry).exists());
}
