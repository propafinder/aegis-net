//! Fresh completed-archive observations; retained JSON never grants an operation.
use super::*;
use aegis_core::relay_geneva::teardown::{FilePin, Phase, TeardownRecord};
use std::collections::BTreeMap;

fn exact_token(token: &str) -> io::Result<()> {
    need(
        token.len() == 32
            && token
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
    )
}

pub(super) fn completed_metadata(
    row: &TeardownRecord,
    source: &str,
    token: &str,
    device: u64,
    inode: u64,
) -> io::Result<()> {
    exact_token(token)?;
    row.validate()?;
    need(
        row.phase == Phase::Complete
            && row.source == source
            && row.token == token
            && row.archive_device == device
            && row.archive_inode == inode,
    )
}

fn installation_metadata(
    intent: &InstallIntent,
    source: &str,
    profile_sha256: &str,
    helper_sha256: &str,
    drop_in_sha256: &str,
) -> io::Result<()> {
    need(
        intent.schema == "aegis_relay_geneva_install_intent_v1"
            && intent.source == source
            && intent.manifest_sha256 == profile_sha256
            && intent.recovery_helper_sha256 == helper_sha256
            && intent.drop_in_sha256 == drop_in_sha256
            && intent.helper_path == RECOVERY_HELPER
            && intent.drop_in_path == DROP_IN
            && intent.initial_service_stopped
            && intent.initial_files_absent,
    )
}

fn recheck_custody(
    expected: &BTreeMap<PathBuf, FilePin>,
    mut read: impl FnMut(&Path) -> io::Result<FilePin>,
) -> io::Result<()> {
    for (path, pin) in expected {
        need(read(path)? == *pin)?;
    }
    Ok(())
}

// Private ordering only, not a public observation or authority constructor.
// Format/hash all return bytes before the second genuine observation. A late
// transform, second-read drift/failure or final inherited deadline cannot pass.
fn observe_then_format_then_recheck<T: Eq>(
    mut observe: impl FnMut() -> io::Result<T>,
    format: impl FnOnce(&T) -> io::Result<String>,
    mut live: impl FnMut() -> io::Result<()>,
) -> io::Result<String> {
    live()?;
    let first = observe()?;
    live()?;
    let output = format(&first)?;
    live()?;
    let second = observe()?;
    need(first == second)?;
    live()?;
    Ok(output)
}

#[cfg(target_os = "linux")]
pub(super) fn run(token: &str) -> io::Result<String> {
    use aegis_core::relay_geneva::{
        linux::recovery::teardown as native,
        operation_deadline,
        teardown::DeviceBlockPolicy,
        teardown_storage::{self as store, Archive},
    };
    use teardown::{HISTORY, NATIVE, ORIGINAL_BINDINGS};

    operation_deadline::check()?;
    exact_token(token)?;
    absent(&Path::new(DIR).join(TEARDOWN))?;
    let archive = Archive::existing(Path::new(HISTORY), token)?;
    let row = teardown::completed_record(&archive, token)?;
    let initial = archive
        .verified_snapshot_pinned(row.archive_manifest_sha256.as_deref().ok_or_else(refused)?)?;
    need(
        initial.manifest.files == row.owned_files
            && initial.manifest.source == row.source
            && initial.manifest.token == token,
    )?;
    let saved: BTreeMap<PathBuf, Vec<u8>> = initial
        .files
        .iter()
        .map(|(name, file)| (PathBuf::from(name), file.bytes.clone()))
        .collect();
    let saved_bytes = |path: &Path| -> io::Result<&[u8]> {
        saved.get(path).map(Vec::as_slice).ok_or_else(refused)
    };
    for path in [
        Path::new(DIR).join(PROFILE),
        Path::new(DIR).join(STATE),
        Path::new(DIR).join(INSTALL_INTENT),
        RECOVERY_HELPER.into(),
        DROP_IN.into(),
        DEVICE_STATE.into(),
    ] {
        need(
            row.owned_files
                .contains_key(path.to_str().ok_or_else(refused)?),
        )?;
    }
    let raw =
        std::str::from_utf8(saved_bytes(&Path::new(DIR).join(PROFILE))?).map_err(|_| refused())?;
    let i = input_profile(raw.into(), false)?;
    need(hex::encode(i.profile_bytes_sha256) == row.profile_sha256)?;
    let helper_sha256 = hex::encode(Sha256::digest(saved_bytes(Path::new(RECOVERY_HELPER))?));
    let drop_in_sha256 = hex::encode(Sha256::digest(saved_bytes(Path::new(DROP_IN))?));
    need(
        helper_sha256 == i.profile.recovery_helper_sha256
            && i.profile
                .role
                .drop_in_paths_to_sha256
                .get(Path::new(DROP_IN))
                == Some(&drop_in_sha256),
    )?;
    let install_intent: InstallIntent = serde_json::from_value(parse_unique_public_metadata(
        saved_bytes(&Path::new(DIR).join(INSTALL_INTENT))?,
    )?)
    .map_err(|_| refused())?;
    installation_metadata(
        &install_intent,
        source()?,
        &row.profile_sha256,
        &helper_sha256,
        &drop_in_sha256,
    )?;
    need(
        row.selected_netdev_digest
            == hex::encode(
                aegis_core::relay_geneva::installed_guard::canonical_table_digest(
                    &aegis_core::relay_geneva::installed_guard::expected(&i.profile.policy, None)?,
                )?,
            ),
    )?;
    let state: OwnedGuardState = serde_json::from_value(parse_unique_public_metadata(
        saved_bytes(&Path::new(DIR).join(STATE))?,
    )?)
    .map_err(|_| refused())?;
    need(
        state.schema == "aegis_relay_geneva_guard_state_v1"
            && state.policy_sha256 == hex::encode(i.profile.policy.digest()?)
            && state.table_present
            && state.active_binding.is_none(),
    )?;
    let inet = DeviceBlockPolicy::from_state(
        std::str::from_utf8(saved_bytes(Path::new(DEVICE_STATE))?).map_err(|_| refused())?,
    )?;
    need(hex::encode(inet.verify(&inet.expected())?) == row.original_inet_digest)?;
    let request = i.config.relay.outer_geneva.as_ref().ok_or_else(refused)?;
    let lease = native::GuardLease::acquire()?;

    #[derive(PartialEq, Eq)]
    struct Observed {
        archive_files: BTreeMap<PathBuf, FilePin>,
        retained_files: BTreeMap<PathBuf, FilePin>,
        inet_sha256: [u8; 32],
    }
    let observe = || -> io::Result<Observed> {
        operation_deadline::check()?;
        teardown::same_input(&i, raw)?;
        teardown::inactive(&i, true)?;
        need(teardown::completed_record(&archive, token)? == row)?;
        let snapshot = archive.verified_snapshot_pinned(initial.manifest_sha256.as_str())?;
        need(
            snapshot.manifest.files == row.owned_files
                && snapshot.manifest.source == row.source
                && snapshot.manifest.token == token,
        )?;
        need(snapshot.files.len() == initial.files.len())?;
        for (name, file) in &snapshot.files {
            need(
                initial
                    .files
                    .get(name)
                    .is_some_and(|old| old.pin == file.pin),
            )?;
        }
        let mut archive_files = BTreeMap::new();
        for file in snapshot.files.values() {
            operation_deadline::check()?;
            archive_files.insert(file.path.clone(), file.pin.clone());
        }
        // Pin all seven actual phase records and exact archived marker/manifest,
        // rather than accepting unchanged parsed metadata with changed bytes.
        for index in 0..=6 {
            let path = archive.directory.join(format!("{index:08}-phase.json"));
            let file = store::open_public(&path, 2 * 1048576)?;
            archive_files.insert(path, file.pin);
        }
        for name in [
            "archive-manifest.json",
            "teardown-marker.json",
            "directories.json",
        ] {
            let path = archive.directory.join(name);
            let file = store::open_public(&path, 2 * 1048576)?;
            if name == "directories.json" {
                need(file.pin.sha256 == row.directory_manifest_sha256)?;
            }
            archive_files.insert(path, file.pin);
        }
        let mut retained_files = BTreeMap::new();
        for (path, pin) in &row.owned_files {
            operation_deadline::check()?;
            if path == DEVICE_STATE || ORIGINAL_BINDINGS.contains(&path.as_str()) {
                let file = store::open_public(Path::new(path), 65536)?;
                need(file.pin == *pin)?;
                retained_files.insert(PathBuf::from(path), file.pin);
            } else {
                absent(Path::new(path))?;
            }
        }
        let absent_selected = || -> io::Result<()> {
            for path in ORIGINAL_BINDINGS {
                if !row.owned_files.contains_key(path) {
                    absent(Path::new(path))?;
                }
            }
            for name in [PROFILE, STATE, INTENT, INSTALL_INTENT, TEARDOWN] {
                absent(&Path::new(DIR).join(name))?;
            }
            for path in [RECOVERY_HELPER, DROP_IN, NATIVE] {
                absent(Path::new(path))?;
            }
            absent(&Path::new(DIR).join("relay-geneva-history"))?;
            Ok(())
        };
        absent_selected()?;
        native::quiet_archived(
            request,
            &i.endpoints,
            &i.profile.role.executable_sha256,
            &saved,
        )?;
        let inet_sha256 = lease.verify_inet(&inet)?;
        need(hex::encode(inet_sha256) == row.original_inet_digest)?;
        need(!native::super_selected_exists()?)?;
        // Reject archive/public-file drift during the native queries, including
        // byte-identical replacement of an owned inode. These are readonly
        // checked reads, not a lease/cgroup authority constructor.
        need(teardown::completed_record(&archive, token)? == row)?;
        recheck_custody(&archive_files, |path| {
            operation_deadline::check()?;
            let file = store::open_public(path, 18 * 1048576)?;
            operation_deadline::check()?;
            Ok(file.pin)
        })?;
        recheck_custody(&retained_files, |path| {
            operation_deadline::check()?;
            let file = store::open_public(path, 65536)?;
            operation_deadline::check()?;
            Ok(file.pin)
        })?;
        for path in row.owned_files.keys() {
            if path != DEVICE_STATE && !ORIGINAL_BINDINGS.contains(&path.as_str()) {
                absent(Path::new(path))?;
            }
        }
        absent_selected()?;
        // Finish each native round with the genuine stopped role and protected
        // config/device source checks; neither substitutes for cgroup emptiness.
        teardown::same_input(&i, raw)?;
        teardown::inactive(&i, true)?;
        operation_deadline::check()?;
        Ok(Observed {
            archive_files,
            retained_files,
            inet_sha256,
        })
    };
    observe_then_format_then_recheck(
        observe,
        |observed| {
            let custody = serde_json::to_vec(&observed.archive_files).map_err(|_| refused())?;
            serde_json::to_string(&json!({
                "schema":"aegis_selected_teardown_current_verification_v1",
                "source":source()?, "archive_token":token,
                "archive_manifest_sha256":initial.manifest_sha256,
                "archive_custody_sha256":hex::encode(Sha256::digest(custody)),
                "profile_sha256":row.profile_sha256,
                "policy_sha256":hex::encode(i.profile.policy.digest()?),
                "original_inet_sha256":hex::encode(observed.inet_sha256),
                "completed_archive_verified":true,
                "original_inet_guard_armed_blocked":true,
                "selected_admission_absent":true,
                "owned_native_owners_quiet":true,
                "fresh_kernel_or_unit_observations":true,
                "whole_operation_cgroup_empty_proven":false,
                "operational_grant":false,
                "physical_capture_verified":false,
                "installed_lifecycle_acceptance":false
            }))
            .map_err(|_| refused())
        },
        operation_deadline::check,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::relay_geneva::teardown::FilePin;
    use std::cell::Cell;
    use std::collections::BTreeMap;
    fn row() -> TeardownRecord {
        TeardownRecord {
            schema: "aegis_selected_teardown_v1".into(),
            token: "a".repeat(32),
            source: "b".repeat(40),
            phase: Phase::Complete,
            profile_sha256: "c".repeat(64),
            directory_manifest_sha256: "d".repeat(64),
            archive_device: 1,
            archive_inode: 2,
            archive_manifest_sha256: Some("e".repeat(64)),
            original_inet_digest: "f".repeat(64),
            initial_original_inet_digest: "f".repeat(64),
            initial_manager_identity_sha256: None,
            initial_manager_binding_sha256: None,
            selected_netdev_digest: "0".repeat(64),
            owned_files: BTreeMap::from([(
                "/owned/public".into(),
                FilePin {
                    device: 1,
                    inode: 2,
                    sha256: "1".repeat(64),
                    size: 1,
                    mode: 0o600,
                },
            )]),
        }
    }
    #[test]
    fn completed_metadata_refuses_noncomplete_stale_or_wrong_archive_identity() {
        let good = row();
        assert!(completed_metadata(&good, &good.source, &good.token, 1, 2).is_ok());
        for field in 0..6 {
            let mut bad = good.clone();
            match field {
                0 => bad.phase = Phase::GateRemoved,
                1 => bad.source = "2".repeat(40),
                2 => bad.token = "3".repeat(32),
                3 => bad.archive_device = 9,
                4 => bad.archive_inode = 9,
                5 => bad.archive_manifest_sha256 = None,
                _ => unreachable!(),
            }
            assert!(completed_metadata(&bad, &good.source, &good.token, 1, 2).is_err());
        }
    }
    #[test]
    fn archived_installation_refuses_foreign_source_hash_paths_or_initial_state() {
        let intent = || InstallIntent {
            schema: "aegis_relay_geneva_install_intent_v1".into(),
            source: "b".repeat(40),
            manifest_sha256: "c".repeat(64),
            recovery_helper_sha256: "d".repeat(64),
            drop_in_sha256: "e".repeat(64),
            helper_path: RECOVERY_HELPER.into(),
            drop_in_path: DROP_IN.into(),
            initial_service_stopped: true,
            initial_files_absent: true,
        };
        let valid = intent();
        let check = |v: &InstallIntent| {
            installation_metadata(
                v,
                &valid.source,
                &valid.manifest_sha256,
                &valid.recovery_helper_sha256,
                &valid.drop_in_sha256,
            )
        };
        assert!(check(&valid).is_ok());
        for field in 0..9 {
            let mut bad = intent();
            match field {
                0 => bad.schema.push('x'),
                1 => bad.source = "f".repeat(40),
                2 => bad.manifest_sha256 = "f".repeat(64),
                3 => bad.recovery_helper_sha256 = "f".repeat(64),
                4 => bad.drop_in_sha256 = "f".repeat(64),
                5 => bad.helper_path.push('x'),
                6 => bad.drop_in_path.push('x'),
                7 => bad.initial_service_stopped = false,
                8 => bad.initial_files_absent = false,
                _ => unreachable!(),
            }
            assert!(check(&bad).is_err());
        }
    }
    #[test]
    fn token_refuses_path_case_short_or_nonhex_before_any_archive_read() {
        for token in [
            "",
            "../history",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "0123456789abcdef0123456789abcdef0",
            "gggggggggggggggggggggggggggggggg",
        ] {
            assert!(exact_token(token).is_err());
        }
    }
    #[cfg(unix)]
    #[test]
    fn post_native_custody_recheck_refuses_real_owned_file_drift_and_replacement() {
        use std::os::unix::fs::MetadataExt;
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("owned-public");
        std::fs::write(&path, b"original").unwrap();
        let pin = |p: &Path| -> io::Result<FilePin> {
            let meta = std::fs::metadata(p)?;
            Ok(FilePin {
                device: meta.dev(),
                inode: meta.ino(),
                sha256: hex::encode(Sha256::digest(std::fs::read(p)?)),
                size: meta.len(),
                mode: meta.mode() & 0o777,
            })
        };
        let expected = BTreeMap::from([(path.clone(), pin(&path).unwrap())]);
        recheck_custody(&expected, pin).unwrap();
        std::fs::write(&path, b"different").unwrap();
        assert!(recheck_custody(&expected, pin).is_err());
        let replacement = temp.path().join("replacement");
        std::fs::write(&replacement, b"original").unwrap();
        std::fs::rename(replacement, &path).unwrap();
        assert!(
            recheck_custody(&expected, pin).is_err(),
            "same bytes do not preserve owned inode"
        );
    }
    #[test]
    fn custody_failure_during_second_observation_never_returns_prepared_output() {
        let reads = Cell::new(0);
        let expected = BTreeMap::from([(
            PathBuf::from("/inert/public"),
            FilePin {
                device: 1,
                inode: 2,
                sha256: "1".repeat(64),
                size: 1,
                mode: 0o600,
            },
        )]);
        let result = observe_then_format_then_recheck(
            || {
                reads.set(reads.get() + 1);
                if reads.get() == 2 {
                    recheck_custody(&expected, |_| {
                        Err(io::Error::new(
                            io::ErrorKind::NotFound,
                            "late owned file absent",
                        ))
                    })?;
                }
                Ok(7)
            },
            |_| Ok("must not return".into()),
            || Ok(()),
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
        assert_eq!(reads.get(), 2);
    }
    #[test]
    fn output_transform_precedes_second_observation_and_last_deadline_check() {
        let phase = Cell::new(0);
        let result = observe_then_format_then_recheck(
            || {
                let n = phase.get();
                assert!(n == 0 || n == 2);
                phase.set(n + 1);
                Ok(7)
            },
            |_| {
                assert_eq!(phase.get(), 1);
                phase.set(2);
                Ok("already constructed".into())
            },
            || Ok(()),
        );
        assert_eq!(phase.get(), 3);
        assert_eq!(result.unwrap(), "already constructed");
    }
    #[test]
    fn expired_during_output_transform_cannot_reach_second_observation_or_return() {
        let expired = Cell::new(false);
        let reads = Cell::new(0);
        let result = observe_then_format_then_recheck(
            || {
                reads.set(reads.get() + 1);
                Ok(7)
            },
            |_| {
                expired.set(true);
                Ok("late".into())
            },
            || {
                if expired.get() {
                    Err(io::Error::new(io::ErrorKind::TimedOut, "original budget"))
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(reads.get(), 1);
    }
    #[test]
    fn second_observation_drift_or_surviving_resource_refuses_constructed_success() {
        for failure in 0..3 {
            let reads = Cell::new(0);
            let result = observe_then_format_then_recheck(
                || {
                    reads.set(reads.get() + 1);
                    if reads.get() == 1 {
                        Ok(7)
                    } else {
                        match failure {
                            0 => Ok(8),
                            1 => Err(refused()),
                            _ => Err(io::Error::other("native quiet failed")),
                        }
                    }
                },
                |_| Ok("must not return".into()),
                || Ok(()),
            );
            assert!(result.is_err());
            assert_eq!(reads.get(), 2);
        }
    }
    #[test]
    fn expiry_after_final_observation_cannot_return() {
        let reads = Cell::new(0);
        let result = observe_then_format_then_recheck(
            || {
                reads.set(reads.get() + 1);
                Ok(7)
            },
            |_| Ok("must not return".into()),
            || {
                if reads.get() == 2 {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "late native observation",
                    ))
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }
    #[test]
    fn failed_first_observation_preserves_primary_and_never_formats() {
        let formatted = Cell::new(false);
        let result = observe_then_format_then_recheck(
            || {
                Err::<u8, _>(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "original refusal",
                ))
            },
            |_| {
                formatted.set(true);
                Ok("no".into())
            },
            || Ok(()),
        );
        assert_eq!(result.unwrap_err().to_string(), "original refusal");
        assert!(!formatted.get());
    }
}
