use super::*;

fn runtime(now: u64, ttl: u64) -> (tempfile::TempDir, RuntimeRegistry, DeviceRegistry) {
    let dir = tempfile::tempdir().unwrap();
    let snapshot = DeviceRegistry::new(now, ttl).unwrap();
    let path = dir.path().join("registry.json");
    publish_snapshot(&path, &snapshot).unwrap();
    let runtime = RuntimeRegistry::load_at(&path, now).unwrap();
    runtime.0.watching.store(true, Ordering::Release);
    (dir, runtime, snapshot)
}

#[test]
fn status_comes_from_live_state_even_when_disk_contains_a_newer_policy() {
    let now = unix_now().unwrap();
    let (_dir, runtime, mut snapshot) = runtime(now, 900);
    let first = runtime.status_at(now).unwrap();
    let checked = runtime.0.state.read().unwrap().checked;
    snapshot.refresh_validity(now + 1, 900).unwrap();
    publish_snapshot(&runtime.0.path, &snapshot).unwrap();
    let status = runtime.status_at(now).unwrap();
    assert_eq!(status.generation, first.generation);
    assert_eq!(status.snapshot_sha256, first.snapshot_sha256);
    assert_eq!(runtime.0.state.read().unwrap().checked, checked);
    runtime.publish_at(Ok(snapshot.clone()), Ok(now + 1));
    let status = runtime.status_at(now + 1).unwrap();
    assert_eq!(status.generation, 2);
    assert_eq!(
        status.snapshot_sha256,
        hex::encode(registry_digest(&snapshot).unwrap())
    );
}

#[tokio::test(start_paused = true)]
async fn repeated_status_does_not_renew_watcher_staleness_or_policy_deadline() {
    let now = unix_now().unwrap();
    let (_dir, runtime, snapshot) = runtime(now, 4);
    let initial = runtime.0.state.read().unwrap().policy_deadline;
    tokio::time::advance(Duration::from_millis(2900)).await;
    assert_eq!(runtime.status_at(now).unwrap().effective_valid_for_ms, 100);
    tokio::time::advance(Duration::from_millis(100)).await;
    assert!(runtime.status_at(now).is_err());
    assert!(runtime.expiry(&[1; 32], now).is_err());
    runtime.publish_at(Ok(snapshot), Ok(now));
    assert_eq!(runtime.0.state.read().unwrap().policy_deadline, initial);
    assert_eq!(runtime.status_at(now).unwrap().policy_remaining_ms, 1000);
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(runtime.status_at(now).is_err());
}

#[test]
fn status_forward_clock_observation_cannot_be_undone_by_clock_rollback() {
    let now = unix_now().unwrap();
    let (_dir, runtime, _) = runtime(now, 30);
    assert!(runtime.status_at(now + 31).is_err());
    assert!(runtime.status_at(now).is_err());
    assert!(runtime.expiry(&[1; 32], now).is_err());
}

#[test]
fn missing_watcher_and_invalid_publication_refuse_status_like_authorization() {
    let now = unix_now().unwrap();
    let (_dir, runtime, _) = runtime(now, 30);
    runtime.0.watching.store(false, Ordering::Release);
    assert!(runtime.status_at(now).is_err());
    runtime.0.watching.store(true, Ordering::Release);
    runtime.publish_at(Err(invalid("fixture unreadable")), Ok(now));
    assert!(runtime.status_at(now).is_err());
    assert!(runtime.expiry(&[1; 32], now).is_err());
}

#[test]
fn summary_contains_only_policy_identity_and_effective_validity() {
    let now = unix_now().unwrap();
    let (_dir, runtime, _) = runtime(now, 30);
    let value = serde_json::to_value(runtime.status_at(now).unwrap()).unwrap();
    let mut keys: Vec<_> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "effective_valid_for_ms",
            "expires_at_unix_secs",
            "generation",
            "issued_at_unix_secs",
            "policy_remaining_ms",
            "snapshot_sha256"
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn device_policy_ack_uses_same_live_snapshot_and_does_not_extend_authorization() {
    let now = unix_now().unwrap();
    let (_dir, runtime, mut snapshot) = runtime(now, 900);
    snapshot.generation += 1;
    snapshot.devices.push(DeviceRecord {
        device_id: "test-a".into(),
        certificate_sha256: "11".repeat(32),
        not_after_unix_secs: now + 600,
        revoked: false,
    });
    runtime.publish_at(Ok(snapshot.clone()), Ok(now));
    let lease = runtime.lease([0x11; 32]).unwrap();
    let nonce = "01".repeat(32);
    let old = lease.policy_ack(&nonce).unwrap();
    let checked = runtime.0.state.read().unwrap().checked;
    snapshot.generation += 1;
    publish_snapshot(&runtime.0.path, &snapshot).unwrap();
    let still_live = lease.policy_ack(&nonce).unwrap();
    assert_eq!(still_live.generation, old.generation);
    assert_eq!(still_live.snapshot_sha256, old.snapshot_sha256);
    assert_eq!(runtime.0.state.read().unwrap().checked, checked);
    tokio::time::advance(MAX_STALENESS).await;
    assert!(lease.policy_ack(&nonce).is_err());
    runtime.publish_at(Ok(snapshot.clone()), Ok(now));
    assert_eq!(
        lease.policy_ack(&nonce).unwrap().generation,
        snapshot.generation
    );
    snapshot.generation += 1;
    snapshot.devices[0].revoked = true;
    runtime.publish_at(Ok(snapshot), Ok(now));
    assert!(lease.policy_ack(&nonce).is_err());
    assert!(AuthorizationLease::static_allowlist()
        .policy_ack(&nonce)
        .is_err());
}

#[tokio::test(start_paused = true)]
async fn device_policy_ack_refuses_expired_lease_even_if_new_snapshot_extends_record() {
    let now = unix_now().unwrap();
    let (_dir, runtime, mut snapshot) = runtime(now, 900);
    snapshot.generation += 1;
    snapshot.devices.push(DeviceRecord {
        device_id: "test-a".into(),
        certificate_sha256: "11".repeat(32),
        not_after_unix_secs: now + 60,
        revoked: false,
    });
    runtime.publish_at(Ok(snapshot.clone()), Ok(now));
    let lease = runtime.lease([0x11; 32]).unwrap();
    tokio::time::advance(Duration::from_secs(60)).await;
    snapshot.generation += 1;
    snapshot.devices[0].not_after_unix_secs += 100;
    runtime.publish_at(Ok(snapshot), Ok(now));
    assert!(lease.policy_ack(&"01".repeat(32)).is_err());
}
