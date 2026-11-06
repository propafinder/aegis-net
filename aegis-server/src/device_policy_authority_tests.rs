use super::*;
use aegis_core::secure_channel::registry::DeviceRecord;
use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

fn path(dir: &tempfile::TempDir, name: &str) -> PathBuf {
    dir.path().canonicalize().unwrap().join(name)
}

fn inbox(path: &Path, bytes: &[u8]) -> File {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    file
}

fn snapshot() -> DeviceRegistry {
    let at = now().unwrap();
    let mut value = DeviceRegistry::new(at, 900).unwrap();
    value.devices.push(DeviceRecord {
        device_id: "synthetic-neighbor".into(),
        certificate_sha256: "ab".repeat(32),
        not_after_unix_secs: at + 3600,
        revoked: false,
    });
    value
}

#[test]
fn refresh_then_publish_changes_only_authority_deadline_and_replay_is_exact() {
    let dir = tempfile::tempdir().unwrap();
    let authority = path(&dir, "authority.json");
    let target = path(&dir, "published.json");
    let stage = path(&dir, "stage.json");
    let original = snapshot();
    registry::publish_snapshot(&authority, &original).unwrap();
    let mut output = inbox(
        &stage,
        b"previous incomplete stage is replaced after validation",
    );
    output.try_lock().unwrap();
    refresh_locked(&mut output, &authority, 300).unwrap();
    let refreshed = DeviceRegistry::load(&authority).unwrap();
    assert_eq!(refreshed.generation, original.generation + 1);
    assert_eq!(
        refreshed.validity.unwrap().expires_at_unix_secs
            - refreshed.validity.unwrap().issued_at_unix_secs,
        300
    );
    assert_eq!(fs::read(&stage).unwrap(), canonical(&refreshed).unwrap());
    drop(output);
    let receipt = publish_file(File::open(&stage).unwrap(), &target).unwrap();
    assert_eq!(receipt.acknowledgement, "disk_only");
    assert_eq!(receipt.generation, refreshed.generation);
    let before = (
        fs::read(&target).unwrap(),
        fs::read(registry::floor_path(&target)).unwrap(),
    );
    let repeated = publish_file(File::open(&stage).unwrap(), &target).unwrap();
    assert_eq!(receipt.snapshot_sha256, repeated.snapshot_sha256);
    assert_eq!(receipt.expires_at_unix_secs, repeated.expires_at_unix_secs);
    assert_eq!(
        before,
        (
            fs::read(&target).unwrap(),
            fs::read(registry::floor_path(&target)).unwrap()
        )
    );
}

#[test]
fn failed_refresh_or_pending_issuance_preserves_inbox_and_source() {
    for barrier in [None, Some("issuance"), Some("registry")] {
        let dir = tempfile::tempdir().unwrap();
        let authority = path(&dir, "authority.json");
        let stage = path(&dir, "stage.json");
        registry::publish_snapshot(&authority, &snapshot()).unwrap();
        let before = fs::read(&authority).unwrap();
        match barrier {
            Some("issuance") => {
                inbox(
                    &registry::issuance_pending_path(&authority),
                    b"synthetic pending marker",
                );
            }
            Some(_) => {
                inbox(
                    &registry::pending_path(&authority),
                    b"synthetic pending marker",
                );
            }
            None => {}
        }
        let mut output = inbox(&stage, b"untouched previous stage");
        output.try_lock().unwrap();
        let ttl = if barrier.is_none() { 0 } else { 300 };
        assert!(refresh_locked(&mut output, &authority, ttl).is_err());
        assert_eq!(fs::read(&stage).unwrap(), b"untouched previous stage");
        assert_eq!(fs::read(&authority).unwrap(), before);
    }
}

#[test]
fn inode_lock_prevents_reading_a_partial_writer_and_blocks_another_writer() {
    let dir = tempfile::tempdir().unwrap();
    let stage = path(&dir, "stage.json");
    let target = path(&dir, "published.json");
    let output = inbox(&stage, b"{partial");
    output.try_lock().unwrap();
    assert_eq!(
        publish_file(File::open(&stage).unwrap(), &target).unwrap_err(),
        PolicyError::StageBusy
    );
    let other_writer = fs::OpenOptions::new().write(true).open(&stage).unwrap();
    assert!(other_writer.try_lock().is_err());
    assert!(!target.exists());
    drop(output);
    assert_eq!(
        publish_file(File::open(&stage).unwrap(), &target).unwrap_err(),
        PolicyError::InvalidSnapshot
    );
    let reader = File::open(&stage).unwrap();
    reader.try_lock_shared().unwrap();
    assert!(other_writer.try_lock().is_err());
}

#[test]
fn publication_refuses_partial_corrupt_noncanonical_oversize_expired_and_private_fields() {
    let dir = tempfile::tempdir().unwrap();
    let target = path(&dir, "published.json");
    let value = snapshot();
    registry::publish_snapshot(&target, &value).unwrap();
    let before = (
        fs::read(&target).unwrap(),
        fs::read(registry::floor_path(&target)).unwrap(),
    );
    let bytes = canonical(&value).unwrap();
    let expired = DeviceRegistry::new(now().unwrap() - 10, 1).unwrap();
    let mut private = serde_json::to_value(&value).unwrap();
    private["private_key"] = serde_json::json!("synthetic rejected field");
    for (index, bad) in [
        vec![],
        b"corrupt".to_vec(),
        bytes[..bytes.len() - 1].to_vec(),
        serde_json::to_vec_pretty(&value).unwrap(),
        vec![b'x'; MAX_REGISTRY_BYTES as usize + 1],
        canonical(&expired).unwrap(),
        serde_json::to_vec(&private).unwrap(),
    ]
    .into_iter()
    .enumerate()
    {
        let stage = path(&dir, &format!("bad-{index}.json"));
        drop(inbox(&stage, &bad));
        assert!(publish_file(File::open(&stage).unwrap(), &target).is_err());
        assert_eq!(
            before,
            (
                fs::read(&target).unwrap(),
                fs::read(registry::floor_path(&target)).unwrap()
            )
        );
    }
}

#[test]
fn publication_rejects_stale_floor_and_equivocation_and_recovers_exact_pending() {
    let dir = tempfile::tempdir().unwrap();
    let target = path(&dir, "published.json");
    let original = snapshot();
    let mut newer = original.clone();
    newer.generation += 1;
    newer.devices[0].revoked = true;
    registry::publish_snapshot(&target, &newer).unwrap();
    let before = fs::read(registry::floor_path(&target)).unwrap();
    for (name, bad) in [
        ("older", original),
        ("equivocation", {
            let mut altered = newer.clone();
            altered.devices[0].revoked = false;
            altered
        }),
    ] {
        let stage = path(&dir, name);
        drop(inbox(&stage, &canonical(&bad).unwrap()));
        assert_eq!(
            publish_file(File::open(&stage).unwrap(), &target).unwrap_err(),
            PolicyError::ApplyFailed
        );
        assert_eq!(before, fs::read(registry::floor_path(&target)).unwrap());
    }
    // A retained exact pending is resolved only by the core's normal floor API.
    drop(inbox(
        &registry::pending_path(&target),
        &canonical(&newer).unwrap(),
    ));
    let stage = path(&dir, "recovery");
    drop(inbox(&stage, &canonical(&newer).unwrap()));
    publish_file(File::open(&stage).unwrap(), &target).unwrap();
    assert!(!registry::pending_path(&target).exists());
    assert_eq!(before, fs::read(registry::floor_path(&target)).unwrap());
}

#[test]
fn output_descriptor_rejects_read_only_append_links_modes_size_and_non_regular() {
    let dir = tempfile::tempdir().unwrap();
    let stage = path(&dir, "stage");
    let file = inbox(&stage, b"unchanged");
    // Under an ordinary user even this otherwise safe descriptor must fail:
    // only the later actual cross-UID fixture exercises root-owned handoff.
    if unsafe { libc::geteuid() } != 0 {
        assert_eq!(validate_output(&file), Err(PolicyError::UnsafeInput));
    } else {
        validate_output(&file).unwrap();
    }
    assert_eq!(
        validate_output(&File::open(&stage).unwrap()),
        Err(PolicyError::UnsafeInput)
    );
    let append = fs::OpenOptions::new().append(true).open(&stage).unwrap();
    assert_eq!(validate_output(&append), Err(PolicyError::UnsafeInput));
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o640)).unwrap();
    assert_eq!(validate_output(&file), Err(PolicyError::UnsafeInput));
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(&stage, path(&dir, "linked")).unwrap();
    assert_eq!(validate_output(&file), Err(PolicyError::UnsafeInput));
    fs::remove_file(path(&dir, "linked")).unwrap();
    file.set_len(MAX_REGISTRY_BYTES + 1).unwrap();
    assert_eq!(validate_output(&file), Err(PolicyError::UnsafeInput));
    let device = fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .unwrap();
    assert_eq!(validate_output(&device), Err(PolicyError::UnsafeInput));
}

#[test]
fn public_entry_rejects_untrusted_input_path_before_target_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let stage = path(&dir, "stage");
    let target = path(&dir, "target");
    drop(inbox(&stage, &canonical(&snapshot()).unwrap()));
    let symlink = path(&dir, "symlink");
    std::os::unix::fs::symlink(&stage, &symlink).unwrap();
    assert!(publish_staged(&symlink, &target).is_err());
    assert!(!target.exists());
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(publish_staged(&stage, &target).is_err());
    assert!(!target.exists());
}
