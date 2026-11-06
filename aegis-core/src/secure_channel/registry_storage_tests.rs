use super::super::{unix_now, DeviceRecord, RuntimeRegistry, MAX_STALENESS};
use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::atomic::Ordering;

fn snapshot(generation: u64) -> DeviceRegistry {
    DeviceRegistry {
        generation,
        devices: vec![
            DeviceRecord {
                device_id: "a".into(),
                certificate_sha256: "11".repeat(32),
                not_after_unix_secs: unix_now().unwrap() + 3600,
                revoked: false,
            },
            DeviceRecord {
                device_id: "b".into(),
                certificate_sha256: "22".repeat(32),
                not_after_unix_secs: unix_now().unwrap() + 3600,
                revoked: false,
            },
        ],
        ..DeviceRegistry::new(unix_now().unwrap(), super::super::DEFAULT_POLICY_TTL_SECS).unwrap()
    }
}

fn publish_floor_only(transaction: &RegistryTransaction, registry: &DeviceRegistry) {
    let metadata = read_file(&transaction.path, MAX_REGISTRY_BYTES).unwrap().1;
    transaction
        .atomic_write(
            &floor_path(&transaction.path),
            &serde_json::to_vec(&RegistryFloor::for_snapshot(registry).unwrap()).unwrap(),
            Some(&metadata),
            false,
        )
        .unwrap();
}

#[test]
fn restarted_reader_requires_matching_floor_and_canonical_replay_preserves_inodes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("registry.json");
    let first = snapshot(1);
    publish_snapshot(&path, &first).unwrap();
    let floor = floor_path(&path);
    let inodes = (
        fs::metadata(&path).unwrap().ino(),
        fs::metadata(&floor).unwrap().ino(),
    );
    let mut reordered = first.clone();
    reordered.devices.reverse();
    publish_snapshot(&path, &reordered).unwrap();
    assert_eq!(
        inodes,
        (
            fs::metadata(&path).unwrap().ino(),
            fs::metadata(&floor).unwrap().ino()
        )
    );
    RuntimeRegistry::load(&path).unwrap();
    let mut second = first.clone();
    second.generation = 2;
    second.devices[0].revoked = true;
    publish_snapshot(&path, &second).unwrap();
    // A separately restarted reader cannot accept an old snapshot beside the
    // current floor. Exact redelivery restores the committed authorization.
    fs::write(&path, serde_json::to_vec(&first).unwrap()).unwrap();
    assert!(RuntimeRegistry::load(&path).is_err());
    assert!(publish_snapshot(&path, &first).is_err());
    publish_snapshot(&path, &second).unwrap();
    assert!(DeviceRegistry::load(&path).unwrap().devices[0].revoked);
    fs::remove_file(&floor).unwrap();
    assert!(RuntimeRegistry::load(&path).is_err());
    assert!(
        publish_snapshot(&path, &second).is_err(),
        "never recreate a missing floor beside an existing snapshot"
    );
}

#[tokio::test(start_paused = true)]
async fn shared_reader_does_not_revoke_neighbor_during_floor_first_publication() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("registry.json");
    let first = snapshot(1);
    publish_snapshot(&path, &first).unwrap();
    let runtime = RuntimeRegistry::load(&path).unwrap();
    runtime.0.watching.store(true, Ordering::Release);
    let revoked_lease = runtime.lease([0x11; 32]).unwrap();
    let neighbor = runtime.lease([0x22; 32]).unwrap();
    let mut second = first.clone();
    second.generation = 2;
    second.devices[0].revoked = true;
    let transaction = RegistryTransaction::begin(&path).unwrap();
    publish_floor_only(&transaction, &second);
    let busy = DeviceRegistry::load(&path).err().unwrap();
    assert_eq!(busy.kind(), io::ErrorKind::WouldBlock);
    runtime.publish(Err(busy));
    assert!(runtime.lease([0x22; 32]).is_ok());
    assert!(
        tokio::time::timeout(Duration::from_millis(100), neighbor.revoked())
            .await
            .is_err()
    );
    // Complete exactly the second half of the transaction under the same lock.
    let metadata = fs::metadata(&path).unwrap();
    transaction
        .atomic_write(
            &path,
            &serde_json::to_vec(&second).unwrap(),
            Some(&metadata),
            false,
        )
        .unwrap();
    drop(transaction);
    runtime.publish(DeviceRegistry::load(&path));
    assert_eq!(
        revoked_lease.revoked().await.kind(),
        io::ErrorKind::PermissionDenied
    );
    assert!(runtime.lease([0x22; 32]).is_ok());
    assert!(
        tokio::time::timeout(Duration::from_millis(100), neighbor.revoked())
            .await
            .is_err()
    );
    // Busy checks do not renew trust forever: a stuck writer closes sessions
    // at the local refresh deadline, not at a remote distribution SLA.
    let _stuck = RegistryTransaction::begin(&path).unwrap();
    runtime.publish(DeviceRegistry::load(&path));
    tokio::time::advance(MAX_STALENESS).await;
    assert_eq!(
        neighbor.revoked().await.kind(),
        io::ErrorKind::PermissionDenied
    );
}

#[test]
fn interrupted_floor_commit_requires_exact_recovery_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("registry.json");
    let first = snapshot(1);
    publish_snapshot(&path, &first).unwrap();
    let mut second = first.clone();
    second.generation = 2;
    second.devices[0].revoked = true;
    {
        let transaction = RegistryTransaction::begin(&path).unwrap();
        publish_floor_only(&transaction, &second);
        // Simulate process death after floor fsync and before registry rename.
    }
    assert!(RuntimeRegistry::load(&path).is_err());
    assert!(publish_snapshot(&path, &first).is_err());
    let mut third = second.clone();
    third.generation = 3;
    assert!(publish_snapshot(&path, &third).is_err());
    let mut altered = second.clone();
    altered.devices[0].revoked = false;
    assert!(publish_snapshot(&path, &altered).is_err());
    publish_snapshot(&path, &second).unwrap();
    RuntimeRegistry::load(&path).unwrap();
    assert!(DeviceRegistry::load(&path).unwrap().devices[0].revoked);
}

#[test]
fn pending_snapshot_recovers_each_durable_cut_without_overwrite_or_floor_reset() {
    for fresh in [false, true] {
        // 0: pending persisted; 1: floor persisted; 2: snapshot persisted.
        for cut in 0..=2 {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("registry.json");
            let first = snapshot(1);
            if !fresh {
                publish_snapshot(&path, &first).unwrap();
            }
            let mut candidate = first.clone();
            if !fresh {
                candidate.generation = 2;
            }
            candidate.devices[0].revoked = true;
            let pending = pending_path(&path);
            {
                let transaction = RegistryTransaction::begin(&path).unwrap();
                transaction
                    .atomic_write(
                        &pending,
                        &serde_json::to_vec(&candidate).unwrap(),
                        None,
                        true,
                    )
                    .unwrap();
                if cut >= 1 {
                    let floor = RegistryFloor::for_snapshot(&candidate).unwrap();
                    transaction
                        .atomic_write(
                            &floor_path(&path),
                            &serde_json::to_vec(&floor).unwrap(),
                            None,
                            fresh,
                        )
                        .unwrap();
                }
                if cut >= 2 {
                    transaction
                        .atomic_write(&path, &serde_json::to_vec(&candidate).unwrap(), None, fresh)
                        .unwrap();
                }
                // Drop exactly the process-owned lock, retaining durable files.
            }
            assert_eq!(fs::metadata(&pending).unwrap().mode() & 0o777, 0o600);
            let pending_before = fs::read(&pending).unwrap();
            let pair_before = (fs::read(&path).ok(), fs::read(floor_path(&path)).ok());
            let mut conflict = candidate.clone();
            conflict.generation += 1;
            assert!(publish_snapshot(&path, &conflict).is_err());
            assert_eq!(fs::read(&pending).unwrap(), pending_before);
            assert_eq!(
                (fs::read(&path).ok(), fs::read(floor_path(&path)).ok()),
                pair_before
            );
            assert!(RegistryTransaction::begin(&path).unwrap().load().is_err());
            assert_eq!(
                RuntimeRegistry::load(&path).is_ok(),
                cut == 2 || (!fresh && cut == 0)
            );
            apply_snapshot(&path, &pending).unwrap();
            assert!(!pending.exists());
            assert!(path.with_file_name("registry.json.lock").exists());
            let recovered = DeviceRegistry::load(&path).unwrap();
            assert_eq!(recovered.generation, candidate.generation);
            assert!(recovered.devices[0].revoked);
            RuntimeRegistry::load(&path).unwrap();
        }
    }
}

#[test]
fn floor_and_lock_reject_unsafe_aliases_and_bounded_input() {
    for suffix in [".floor", ".lock"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.json");
        let first = snapshot(1);
        publish_snapshot(&path, &first).unwrap();
        let sidecar = PathBuf::from(format!("{}{suffix}", path.display()));
        let alias = dir.path().join("alias");
        fs::hard_link(&sidecar, &alias).unwrap();
        assert!(DeviceRegistry::load(&path).is_err());
        assert!(publish_snapshot(&path, &first).is_err());
        fs::remove_file(&sidecar).unwrap();
        std::os::unix::fs::symlink(&alias, &sidecar).unwrap();
        assert!(DeviceRegistry::load(&path).is_err());
        assert!(publish_snapshot(&path, &first).is_err());
    }
    for bytes in [
        vec![],
        b"{}".to_vec(),
        vec![b' '; MAX_FLOOR_BYTES as usize + 1],
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.json");
        publish_snapshot(&path, &snapshot(1)).unwrap();
        fs::write(floor_path(&path), bytes).unwrap();
        assert!(DeviceRegistry::load(&path).is_err());
        assert!(publish_snapshot(&path, &snapshot(2)).is_err());
    }
}

#[test]
fn atomic_publish_preserves_reader_permissions_and_lock_inode() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("registry.json");
    publish_snapshot(&path, &snapshot(1)).unwrap();
    let lock = PathBuf::from(format!("{}.lock", path.display()));
    let lock_inode = fs::metadata(&lock).unwrap().ino();
    // Root CI also exercises an actual distinct service group, not a chmod stub.
    let root = unsafe { libc::geteuid() } == 0;
    let mode = if root { 0o640 } else { 0o600 };
    if root {
        use std::os::fd::AsRawFd;
        let file = File::open(&path).unwrap();
        assert_eq!(unsafe { libc::fchown(file.as_raw_fd(), 0, 65534) }, 0);
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    let original = fs::metadata(&path).unwrap();
    publish_snapshot(&path, &snapshot(2)).unwrap();
    for file in [&path, &floor_path(&path), &lock] {
        let metadata = fs::metadata(file).unwrap();
        assert_eq!(
            (metadata.uid(), metadata.gid(), metadata.mode() & 0o777),
            (original.uid(), original.gid(), mode)
        );
    }
    assert_eq!(fs::metadata(&lock).unwrap().ino(), lock_inode);
    assert_eq!(DeviceRegistry::load(&path).unwrap().generation, 2);
}

#[cfg(feature = "device-enrollment")]
#[test]
fn issuance_barrier_blocks_runtime_and_every_ordinary_writer_without_floor_reset() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("registry.json");
    let first = snapshot(1);
    publish_snapshot(&path, &first).unwrap();
    crate::secure_channel::enrollment::write_private_new(
        &issuance_pending_path(&path),
        b"private issuer journal",
    )
    .unwrap();
    assert!(DeviceRegistry::load(&path).is_err());
    assert!(RuntimeRegistry::load(&path).is_err());
    assert!(RegistryTransaction::begin(&path).is_err());
    assert!(publish_snapshot(&path, &first).is_err());
    let transaction = RegistryTransaction::begin_issuance(&path).unwrap();
    assert_eq!(transaction.load_published_issuance().unwrap().generation, 1);
    let mut second = first.clone();
    second.generation = 2;
    second.devices[0].revoked = true;
    transaction.apply_issuance_snapshot(&second).unwrap();
    drop(transaction);
    assert!(
        DeviceRegistry::load(&path).is_err(),
        "publishing is not allowed to clear the issuer's receipt barrier"
    );
    assert!(floor_path(&path).exists());
    assert!(issuance_pending_path(&path).exists());
    fs::remove_file(issuance_pending_path(&path)).unwrap();
    assert!(DeviceRegistry::load(&path).unwrap().devices[0].revoked);
    assert!(publish_snapshot(&path, &first).is_err());
}

#[cfg(feature = "device-enrollment")]
#[test]
fn held_issuance_lock_still_requires_retained_journal_and_exact_floor_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("registry.json");
    let first = snapshot(1);
    publish_snapshot(&path, &first).unwrap();
    let transaction = RegistryTransaction::begin_issuance(&path).unwrap();
    let mut second = first.clone();
    second.generation = 2;
    assert!(transaction.apply_issuance_snapshot(&second).is_err());
    crate::secure_channel::enrollment::write_private_new(
        &issuance_pending_path(&path),
        b"private issuer journal",
    )
    .unwrap();
    publish_floor_only(&transaction, &second);
    assert!(transaction.load_published_issuance().is_err());
    let mut wrong = second.clone();
    wrong.devices[0].revoked = true;
    assert!(transaction.apply_issuance_snapshot(&wrong).is_err());
    assert!(issuance_pending_path(&path).exists());
    transaction.apply_issuance_snapshot(&second).unwrap();
    assert_eq!(transaction.load_published_issuance().unwrap().generation, 2);
}

#[test]
fn startup_registry_read_waits_for_os_publication_lock_and_adopts_verified_floor() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("registry.json");
    publish_snapshot(&path, &snapshot(1)).unwrap();
    let transaction = RegistryTransaction::begin(&path).unwrap();
    let mut second = snapshot(2);
    second.devices[0].revoked = true;
    // A reader must not accept the old still-readable snapshot when the
    // authoritative floor is already committed but publication is incomplete.
    publish_floor_only(&transaction, &second);
    let (send, recv) = std::sync::mpsc::channel();
    let reader_path = path.clone();
    let worker = std::thread::spawn(move || {
        send.send(RuntimeRegistry::load_startup_with_limits(
            &reader_path,
            Duration::from_secs(2),
            Duration::from_millis(10),
            201,
        ))
        .unwrap();
    });
    assert!(recv.recv_timeout(Duration::from_millis(60)).is_err());
    transaction.apply(&second).unwrap();
    drop(transaction);
    let runtime = recv.recv_timeout(Duration::from_secs(2)).unwrap().unwrap();
    worker.join().unwrap();
    assert!(runtime.lease([0x11; 32]).is_err());
    assert!(
        runtime.lease([0x22; 32]).is_err(),
        "authorization remains gated until watcher starts"
    );
    let state = runtime.0.state.read().unwrap();
    assert_eq!(state.generation, 2);
    let active = state.active.as_ref().unwrap();
    assert!(!active.contains_key(&[0x11; 32]));
    assert!(active.contains_key(&[0x22; 32]));
}

#[test]
fn startup_registry_read_has_real_deadline_and_attempt_bound() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("registry.json");
    publish_snapshot(&path, &snapshot(1)).unwrap();
    let _transaction = RegistryTransaction::begin(&path).unwrap();
    let start = std::time::Instant::now();
    let error = RuntimeRegistry::load_startup_with_limits(
        &path,
        Duration::from_millis(70),
        Duration::from_millis(10),
        100,
    )
    .err()
    .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert!(start.elapsed() >= Duration::from_millis(70));
    assert!(start.elapsed() < Duration::from_secs(2));
    let start = std::time::Instant::now();
    let error = RuntimeRegistry::load_startup_with_limits(
        &path,
        Duration::from_secs(5),
        Duration::from_secs(1),
        1,
    )
    .err()
    .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert!(start.elapsed() < Duration::from_millis(500));
    assert_eq!(
        RuntimeRegistry::load(&path).err().unwrap().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn startup_registry_read_does_not_retry_or_accept_unverified_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("registry.json");
    publish_snapshot(&path, &snapshot(1)).unwrap();
    fs::write(&path, b"malformed registry").unwrap();
    let start = std::time::Instant::now();
    let error = RuntimeRegistry::load_startup_with_limits(
        &path,
        Duration::from_secs(5),
        Duration::from_secs(1),
        101,
    )
    .err()
    .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(start.elapsed() < Duration::from_millis(500));
    fs::write(&path, serde_json::to_vec(&snapshot(2)).unwrap()).unwrap();
    assert_eq!(
        RuntimeRegistry::load_for_startup(&path)
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::InvalidData,
        "startup never adopts a generation without its committed floor"
    );
    fs::remove_file(&path).unwrap();
    let start = std::time::Instant::now();
    assert_eq!(
        RuntimeRegistry::load_for_startup(&path)
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::NotFound
    );
    assert!(start.elapsed() < Duration::from_millis(500));
}
