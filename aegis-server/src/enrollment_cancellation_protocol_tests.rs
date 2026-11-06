//! Authored-only protocol regressions. Root must compile/run these actual APIs.
use super::*;
use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;

fn context() -> String {
    "cd".repeat(32)
}
fn recovery(f: &Fixture) -> Issuer {
    Issuer::open_cancellation(&f.issuer.config).unwrap()
}
fn intent_path(f: &Fixture, id: &str) -> PathBuf {
    let mut path = f.issuer.config.registry.as_os_str().to_os_string();
    path.push(format!(".enrollment-cancel-{id}.json"));
    path.into()
}

// Exclude OS read-atime: this verifies no create/write/chmod/fsync/recovery or
// replacement by inspection, including existing lock and directory metadata.
type FileIdentity = (Vec<u8>, u32, u32, u64, u64, i64, i64, i64, i64);
type Inventory = BTreeMap<PathBuf, FileIdentity>;
fn inventory(root: &Path) -> Inventory {
    fn visit(root: &Path, out: &mut Inventory) {
        let m = fs::symlink_metadata(root).unwrap();
        let bytes = if m.is_file() {
            fs::read(root).unwrap()
        } else {
            Vec::new()
        };
        out.insert(
            root.to_owned(),
            (
                bytes,
                m.mode(),
                m.uid(),
                m.ino(),
                m.nlink(),
                m.mtime(),
                m.mtime_nsec(),
                m.ctime(),
                m.ctime_nsec(),
            ),
        );
        if m.is_dir() {
            for entry in fs::read_dir(root).unwrap() {
                visit(&entry.unwrap().path(), out);
            }
        }
    }
    let mut out = BTreeMap::new();
    visit(root, &mut out);
    out
}
fn inspect_unchanged(f: &Fixture, id: &str) -> CancellationSelection {
    let before = inventory(f._dir.path());
    let result = recovery(f).inspect_cancellation(id, &context()).unwrap();
    assert_eq!(before, inventory(f._dir.path()));
    assert_eq!(
        result,
        recovery(f).inspect_cancellation(id, &context()).unwrap()
    );
    assert_eq!(before, inventory(f._dir.path()));
    assert_eq!(result.schema, SELECTION_DOMAIN);
    assert_eq!(result.version, 1);
    result
}
fn selected(f: &Fixture, s: &CancellationSelection) -> CancellationOutcome {
    recovery(f)
        .cancel_selected_enrollment(
            &s.target.device_id,
            s.target.expected_published_certificate_sha256.as_deref(),
            &s.selection_sha256,
            &context(),
        )
        .unwrap()
}
fn assert_outcome(f: &Fixture, s: &CancellationSelection, outcome: &CancellationOutcome) {
    let snapshot = DeviceRegistry::load(&f.issuer.config.registry).unwrap();
    assert_eq!(
        outcome.expected_published_certificate_sha256,
        s.target.expected_published_certificate_sha256
    );
    assert_eq!(
        outcome.authenticated_cancelled_certificate_sha256,
        s.target.authenticated_cancelled_certificate_sha256
    );
    assert_eq!(outcome.registry_generation, snapshot.generation);
    assert_eq!(outcome.selection_sha256, s.selection_sha256);
    assert_eq!(
        outcome.canonical_public_policy_sha256,
        hex::encode(Sha256::digest(
            crate::device_policy::export(
                &fs::canonicalize(&f.issuer.config.registry).unwrap(),
                f.now
            )
            .unwrap()
        ))
    );
    assert!(
        !outcome.distribution_confirmed
            && !outcome.live_relay_acknowledgements_confirmed
            && !outcome.installed_acceptance
            && !outcome.readiness_authorization
    );
    assert!(snapshot
        .devices
        .iter()
        .filter(|d| d.device_id == s.target.device_id)
        .all(|d| d.revoked));
    assert!(snapshot
        .invitations
        .iter()
        .filter(|i| i.device_id == s.target.device_id)
        .all(|i| i.consumed));
    assert!(!registry::issuance_pending_path(&f.issuer.config.registry).exists());
    assert!(!registry::pending_path(&f.issuer.config.registry).exists());
}

#[test]
fn cancellation_protocol_inspection_is_read_only_for_initial_and_every_issuance_cut() {
    let initial = Fixture::new();
    fs::remove_file(&initial.issuer.config.ca_key).unwrap();
    let s = inspect_unchanged(&initial, "device_a");
    assert_eq!(s.target.expected_published_certificate_sha256, None);
    assert_eq!(s.target.authenticated_cancelled_certificate_sha256, None);
    let outcome = selected(&initial, &s);
    assert_outcome(&initial, &s, &outcome);
    let consumed = inspect_unchanged(&initial, "device_a");
    let replay = selected(&initial, &consumed);
    assert_outcome(&initial, &consumed, &replay);
    assert_eq!(outcome.registry_generation, replay.registry_generation);
    for cut in 0..=4 {
        let f = Fixture::new();
        let receipt = interrupted(&f, cut);
        fs::remove_file(&f.issuer.config.ca_key).unwrap();
        let s = inspect_unchanged(&f, "device_a");
        assert_eq!(
            s.target
                .authenticated_cancelled_certificate_sha256
                .as_deref(),
            Some(receipt.certificate_sha256.as_str())
        );
        assert_eq!(
            s.target.expected_published_certificate_sha256.as_deref(),
            (cut >= 3).then_some(receipt.certificate_sha256.as_str())
        );
        assert!(DeviceRegistry::load(&f.issuer.config.registry).is_err());
        let outcome = selected(&f, &s);
        assert_outcome(&f, &s, &outcome);
    }
}

fn pending_renewal(f: &Fixture) -> (EnrollmentReceipt, EnrollmentReceipt) {
    let old = f.issue();
    let predecessor = DeviceRegistry::load(&f.issuer.config.registry).unwrap();
    let original = fs::read(&f.issuer.config.registry).unwrap();
    let floor = fs::read(registry::floor_path(&f.issuer.config.registry)).unwrap();
    let (request, mut challenge) = f.request(
        Operation::Renew,
        ProofPurpose::Authorize,
        2,
        Some(&old),
        f.now + 61,
    );
    let renewed = f
        .issuer
        .exchange_with_clock(&request, &mut challenge, || Ok(f.now + 61))
        .unwrap();
    let journal = Pending {
        version: 1,
        predecessor_generation: predecessor.generation,
        predecessor_sha256: hex::encode(registry::registry_digest(&predecessor).unwrap()),
        successor: DeviceRegistry::load(&f.issuer.config.registry).unwrap(),
        stored: f
            .issuer
            .receipt(&renewed.binding.request_id)
            .unwrap()
            .unwrap(),
    };
    fs::write(&f.issuer.config.registry, original).unwrap();
    fs::write(registry::floor_path(&f.issuer.config.registry), floor).unwrap();
    write_new(
        &registry::issuance_pending_path(&f.issuer.config.registry),
        &serialize(&journal, MAX_JOURNAL).unwrap(),
    )
    .unwrap();
    (old, renewed)
}

#[test]
fn cancellation_protocol_pending_renewal_distinguishes_cas_a_from_target_b() {
    let f = Fixture::new();
    let (a, b) = pending_renewal(&f);
    let s = inspect_unchanged(&f, "device_a");
    assert_eq!(
        s.target.expected_published_certificate_sha256.as_deref(),
        Some(a.certificate_sha256.as_str())
    );
    assert_eq!(
        s.target
            .authenticated_cancelled_certificate_sha256
            .as_deref(),
        Some(b.certificate_sha256.as_str())
    );
    assert_ne!(a.certificate_sha256, b.certificate_sha256);
    assert!(recovery(&f)
        .cancel_selected_enrollment(
            "device_a",
            Some(&b.certificate_sha256),
            &s.selection_sha256,
            &context()
        )
        .is_err());
    assert!(!intent_path(&f, "device_a").exists());
    let original_validity = DeviceRegistry::load_snapshot(&f.issuer.config.registry)
        .unwrap()
        .validity;
    let outcome = selected(&f, &s);
    assert_outcome(&f, &s, &outcome);
    assert_eq!(
        serde_json::to_value(
            DeviceRegistry::load(&f.issuer.config.registry)
                .unwrap()
                .validity
        )
        .unwrap(),
        serde_json::to_value(original_validity).unwrap()
    );
    let replay = inspect_unchanged(&f, "device_a");
    assert_eq!(
        replay.target.expected_published_certificate_sha256,
        s.target.expected_published_certificate_sha256
    );
    assert_eq!(
        replay.target.authenticated_cancelled_certificate_sha256,
        s.target.authenticated_cancelled_certificate_sha256
    );
    let again = selected(&f, &replay);
    assert_outcome(&f, &replay, &again);
    assert_eq!(outcome.registry_generation, again.registry_generation);
}

#[test]
fn cancellation_protocol_journal_intent_supports_exact_pre_and_post_c_floor_cuts() {
    for cut in 0..=2 {
        let f = Fixture::new();
        let (a, b) = pending_renewal(&f);
        let journal = recovery(&f).pending().unwrap().unwrap();
        let tx = RegistryTransaction::begin_issuance(&f.issuer.config.registry).unwrap();
        let predecessor = tx
            .load_cancellation_snapshot(
                journal.predecessor_generation,
                &journal.predecessor_sha256,
                &journal.successor,
            )
            .unwrap();
        tx.record_enrollment_cancellation(
            "device_a",
            Some(&a.certificate_sha256),
            Some(&b.certificate_sha256),
            &predecessor,
        )
        .unwrap();
        let intent = tx.enrollment_cancellation("device_a").unwrap().unwrap();
        tx.apply_issuance_snapshot(&journal.successor).unwrap();
        let active_floor = fs::read(registry::floor_path(&f.issuer.config.registry)).unwrap();
        let cancelled = intent
            .cancelled_snapshot(&journal.successor)
            .unwrap()
            .unwrap();
        tx.apply_issuance_snapshot(&cancelled).unwrap();
        drop(tx);
        if cut < 2 {
            fs::write(
                &f.issuer.config.registry,
                serde_json::to_vec(&journal.successor).unwrap(),
            )
            .unwrap();
            if cut == 0 {
                fs::write(
                    registry::floor_path(&f.issuer.config.registry),
                    active_floor,
                )
                .unwrap();
            }
            enrollment::write_private_new(
                &registry::pending_path(&f.issuer.config.registry),
                &serde_json::to_vec(&cancelled).unwrap(),
            )
            .unwrap();
        }
        // cut0 floorS/snapshotS/pendingC; cut1 floorC/snapshotS/pendingC;
        // cut2 floorC/snapshotC with authenticated J still retained.
        assert!(DeviceRegistry::load(&f.issuer.config.registry).is_err());
        let s = inspect_unchanged(&f, "device_a");
        assert_eq!(
            s.target.expected_published_certificate_sha256.as_deref(),
            Some(a.certificate_sha256.as_str())
        );
        assert_eq!(
            s.target
                .authenticated_cancelled_certificate_sha256
                .as_deref(),
            Some(b.certificate_sha256.as_str())
        );
        let outcome = selected(&f, &s);
        assert_outcome(&f, &s, &outcome);
        assert_eq!(outcome.registry_generation, cancelled.generation);
    }
}

#[test]
fn cancellation_protocol_standalone_intent_supports_all_i_c_cuts_without_writes_on_inspect() {
    for cut in 0..=3 {
        let f = Fixture::new();
        let receipt = f.issue();
        let initial = fs::read(&f.issuer.config.registry).unwrap();
        let initial_floor = fs::read(registry::floor_path(&f.issuer.config.registry)).unwrap();
        recovery(&f)
            .cancel_enrollment("device_a", Some(&receipt.certificate_sha256))
            .unwrap();
        let cancelled = DeviceRegistry::load(&f.issuer.config.registry).unwrap();
        if cut < 3 {
            fs::write(&f.issuer.config.registry, initial).unwrap();
            if cut < 2 {
                fs::write(
                    registry::floor_path(&f.issuer.config.registry),
                    initial_floor,
                )
                .unwrap();
            }
            if cut > 0 {
                enrollment::write_private_new(
                    &registry::pending_path(&f.issuer.config.registry),
                    &serde_json::to_vec(&cancelled).unwrap(),
                )
                .unwrap();
            }
            assert!(DeviceRegistry::load(&f.issuer.config.registry).is_err());
        }
        let s = inspect_unchanged(&f, "device_a");
        let outcome = selected(&f, &s);
        assert_outcome(&f, &s, &outcome);
        assert_eq!(outcome.registry_generation, cancelled.generation);
    }
}

#[test]
fn cancellation_protocol_stale_selection_or_wrong_context_refuses_before_new_intent() {
    let f = Fixture::new();
    let s = inspect_unchanged(&f, "device_a");
    let first = f.issue();
    let before = fs::read(&f.issuer.config.registry).unwrap();
    let floor = fs::read(registry::floor_path(&f.issuer.config.registry)).unwrap();
    assert!(recovery(&f)
        .cancel_selected_enrollment("device_a", None, &s.selection_sha256, &context())
        .is_err());
    assert!(!intent_path(&f, "device_a").exists());
    assert_eq!(before, fs::read(&f.issuer.config.registry).unwrap());
    assert_eq!(
        floor,
        fs::read(registry::floor_path(&f.issuer.config.registry)).unwrap()
    );
    let s = inspect_unchanged(&f, "device_a");
    assert!(recovery(&f)
        .cancel_selected_enrollment(
            "device_a",
            Some(&first.certificate_sha256),
            &s.selection_sha256,
            &"ee".repeat(32)
        )
        .is_err());
    assert!(!intent_path(&f, "device_a").exists());
    assert_eq!(before, fs::read(&f.issuer.config.registry).unwrap());
}

#[test]
fn cancellation_protocol_missing_unsafe_floor_pending_or_lock_never_gets_an_inspection() {
    for problem in 0..7 {
        let f = Fixture::new();
        interrupted(&f, 0);
        match problem {
            0 => {
                fs::remove_file(registry::floor_path(&f.issuer.config.registry)).unwrap();
            }
            1 => {
                fs::write(registry::floor_path(&f.issuer.config.registry), b"{}").unwrap();
            }
            2 => {
                let mut foreign = DeviceRegistry::load_snapshot(&f.issuer.config.registry).unwrap();
                foreign.generation += 10;
                enrollment::write_private_new(
                    &registry::pending_path(&f.issuer.config.registry),
                    &serde_json::to_vec(&foreign).unwrap(),
                )
                .unwrap();
            }
            3 => {
                let mut path = f.issuer.config.registry.as_os_str().to_os_string();
                path.push(".lock");
                fs::remove_file(PathBuf::from(path)).unwrap();
            }
            4 => {
                let mut path = f.issuer.config.registry.as_os_str().to_os_string();
                path.push(".lock");
                let lock = PathBuf::from(path);
                fs::remove_file(&lock).unwrap();
                std::os::unix::fs::symlink(&f.issuer.config.registry, lock).unwrap();
            }
            5 => {
                fs::write(
                    registry::floor_path(&f.issuer.config.registry),
                    serde_json::to_vec(&serde_json::json!({
                        "version":1,"generation":1,"snapshot_sha256":"99".repeat(32)
                    }))
                    .unwrap(),
                )
                .unwrap();
            }
            _ => {
                enrollment::write_private_new(&intent_path(&f, "device_a"), &serde_json::to_vec(&serde_json::json!({
                    "version":1,"device_id":"other_device", "expected_certificate_sha256":null,
                    "cancelled_certificate_sha256":null,"predecessor_generation":1,"predecessor_sha256":"99".repeat(32)
                })).unwrap()).unwrap();
            }
        }
        let before = inventory(f._dir.path());
        assert!(recovery(&f)
            .inspect_cancellation("device_a", &context())
            .is_err());
        assert_eq!(before, inventory(f._dir.path()));
        assert_eq!(intent_path(&f, "device_a").exists(), problem == 6);
    }
    let f = Fixture::new();
    interrupted(&f, 0);
    let before = inventory(f._dir.path());
    assert!(recovery(&f)
        .inspect_cancellation("other_device", &context())
        .is_err());
    assert_eq!(before, inventory(f._dir.path()));
}

#[test]
fn cancellation_protocol_existing_shared_lock_is_nonblocking_and_cannot_create_or_mutate() {
    let f = Fixture::new();
    let tx = RegistryTransaction::begin_issuance(&f.issuer.config.registry).unwrap();
    let before = inventory(f._dir.path());
    let error = recovery(&f)
        .inspect_cancellation("device_a", &context())
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert_eq!(before, inventory(f._dir.path()));
    drop(tx);
    inspect_unchanged(&f, "device_a");
}

#[test]
fn cancellation_protocol_no_outcome_at_durability_failure_and_replay_keeps_original_target() {
    for boundary in 1..=3 {
        let f = Fixture::new();
        let receipt = interrupted(&f, 0);
        let s = inspect_unchanged(&f, "device_a");
        let mut reached = 0;
        let outcome = recovery(&f).cancel_selected_with(
            "device_a",
            None,
            &s.selection_sha256,
            &context(),
            || {
                reached += 1;
                if reached == boundary {
                    Err(rejected("deterministic publication failure"))
                } else {
                    Ok(())
                }
            },
        );
        assert!(outcome.is_err());
        assert_eq!(reached, boundary);
        assert!(registry::issuance_pending_path(&f.issuer.config.registry).exists());
        assert!(DeviceRegistry::load(&f.issuer.config.registry).is_err());
        let replay = inspect_unchanged(&f, "device_a");
        assert_eq!(replay.target.expected_published_certificate_sha256, None);
        assert_eq!(
            replay
                .target
                .authenticated_cancelled_certificate_sha256
                .as_deref(),
            Some(receipt.certificate_sha256.as_str())
        );
        let outcome = selected(&f, &replay);
        assert_outcome(&f, &replay, &outcome);
    }
}

#[test]
fn cancellation_protocol_own_id_only_preserves_other_rows_and_policy_validity() {
    let f = Fixture::new();
    let path = f._dir.path().join("other.token");
    crate::devices::invite(
        &f.issuer.config.registry,
        "other_device",
        &path,
        3600,
        f.now,
    )
    .unwrap();
    {
        let tx = RegistryTransaction::begin(&f.issuer.config.registry).unwrap();
        let mut registry = tx.load().unwrap();
        registry.devices.push(registry::DeviceRecord {
            device_id: "other_device".to_owned(),
            certificate_sha256: "77".repeat(32),
            not_after_unix_secs: f.now + 3600,
            revoked: false,
        });
        registry.generation += 1;
        tx.save(&f.issuer.config.registry, &registry, false)
            .unwrap();
    }
    let before = DeviceRegistry::load(&f.issuer.config.registry).unwrap();
    let s = inspect_unchanged(&f, "device_a");
    let outcome = selected(&f, &s);
    assert_outcome(&f, &s, &outcome);
    let after = DeviceRegistry::load(&f.issuer.config.registry).unwrap();
    assert_eq!(
        serde_json::to_value(after.validity).unwrap(),
        serde_json::to_value(before.validity).unwrap()
    );
    assert_eq!(
        serde_json::to_value(
            after
                .devices
                .iter()
                .filter(|d| d.device_id == "other_device")
                .collect::<Vec<_>>()
        )
        .unwrap(),
        serde_json::to_value(
            before
                .devices
                .iter()
                .filter(|d| d.device_id == "other_device")
                .collect::<Vec<_>>()
        )
        .unwrap()
    );
    assert_eq!(
        serde_json::to_value(
            after
                .invitations
                .iter()
                .filter(|i| i.device_id == "other_device")
                .collect::<Vec<_>>()
        )
        .unwrap(),
        serde_json::to_value(
            before
                .invitations
                .iter()
                .filter(|i| i.device_id == "other_device")
                .collect::<Vec<_>>()
        )
        .unwrap()
    );
    let absent = inspect_unchanged(&f, "never_invited");
    assert_eq!(absent.target.expected_published_certificate_sha256, None);
    assert_eq!(
        absent.target.authenticated_cancelled_certificate_sha256,
        None
    );
    let outcome = selected(&f, &absent);
    assert_outcome(&f, &absent, &outcome);
    let replay = inspect_unchanged(&f, "device_a");
    selected(&f, &replay);
}

#[test]
fn cancellation_protocol_strict_json_refuses_unknown_and_missing_nullable_facts() {
    let f = Fixture::new();
    let s = inspect_unchanged(&f, "device_a");
    let mut value = serde_json::to_value(&s).unwrap();
    value["target"]
        .as_object_mut()
        .unwrap()
        .insert("invented".to_owned(), serde_json::json!(true));
    assert!(serde_json::from_value::<CancellationSelection>(value).is_err());
    let mut value = serde_json::to_value(&s).unwrap();
    value["target"]
        .as_object_mut()
        .unwrap()
        .remove("authenticated_cancelled_certificate_sha256");
    assert!(serde_json::from_value::<CancellationSelection>(value).is_err());
    for (field, bad) in [
        ("schema", serde_json::json!("foreign")),
        ("version", serde_json::json!(2)),
    ] {
        let mut value = serde_json::to_value(&s).unwrap();
        value[field] = bad;
        assert!(serde_json::from_value::<CancellationSelection>(value).is_err());
    }
    let outcome = selected(&f, &s);
    let mut value = serde_json::to_value(outcome).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .remove("expected_published_certificate_sha256");
    assert!(serde_json::from_value::<CancellationOutcome>(value).is_err());
}
