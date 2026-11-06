use super::*;

fn snapshot(now: u64, ttl: u64) -> DeviceRegistry {
    DeviceRegistry {
        devices: vec![DeviceRecord {
            device_id: "device-a".into(),
            certificate_sha256: "11".repeat(32),
            not_after_unix_secs: now + 10_000,
            revoked: false,
        }],
        ..DeviceRegistry::new(now, ttl).unwrap()
    }
}

fn runtime(path: &Path, registry: &DeviceRegistry, now: u64) -> RuntimeRegistry {
    publish_snapshot(path, registry).unwrap();
    let runtime = RuntimeRegistry::load_at(path, now).unwrap();
    runtime.0.watching.store(true, Ordering::Release);
    runtime
}

#[test]
fn legacy_identity_is_preserved_but_runtime_requires_explicit_v2_policy() {
    let legacy = DeviceRegistry::default();
    let json = serde_json::to_vec(&legacy).unwrap();
    assert_eq!(
        json,
        br#"{"version":1,"generation":1,"devices":[],"invitations":[]}"#
    );
    assert_eq!(
        registry_digest(&legacy).unwrap(),
        <[u8; 32]>::from(Sha256::digest(&json))
    );
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("registry.json");
    publish_snapshot(&path, &legacy).unwrap();
    assert_eq!(DeviceRegistry::load(&path).unwrap().version, 1);
    assert!(RuntimeRegistry::load(&path).is_err());

    for json in [
        r#"{"version":2,"generation":1,"devices":[],"invitations":[]}"#,
        r#"{"version":2,"generation":1,"validity":null,"devices":[],"invitations":[]}"#,
        r#"{"version":3,"generation":1,"devices":[],"invitations":[]}"#,
    ] {
        let invalid: DeviceRegistry = serde_json::from_str(json).unwrap();
        assert!(invalid.validate().is_err());
        assert!(invalid.policy_remaining(unix_now().unwrap()).is_err());
    }
    assert!(serde_json::from_str::<DeviceRegistry>(
        r#"{"version":2,"generation":1,"validity":{"issued_at_unix_secs":100,"expires_at_unix_secs":200,"renew_on_read":true},"devices":[],"invitations":[]}"#
    ).is_err());

    let now = unix_now().unwrap();
    let mut migrated = DeviceRegistry::load(&path).unwrap();
    migrated
        .refresh_validity(now, DEFAULT_POLICY_TTL_SECS)
        .unwrap();
    publish_snapshot(&path, &migrated).unwrap();
    assert_eq!(migrated.generation, 2);
    RuntimeRegistry::load(&path).unwrap();
}

#[test]
fn policy_bounds_expiry_future_skew_and_failed_refresh_are_fail_closed() {
    let now = unix_now().unwrap();
    assert_eq!(
        DeviceRegistry::new(now, DEFAULT_POLICY_TTL_SECS)
            .unwrap()
            .validity
            .unwrap()
            .expires_at_unix_secs,
        now + 900
    );
    for ttl in [0, MAX_POLICY_TTL_SECS + 1, u64::MAX] {
        assert!(DeviceRegistry::new(now, ttl).is_err());
    }
    assert!(DeviceRegistry::new(u64::MAX, 1).is_err());
    assert!(DeviceRegistry::new(0, 1).is_err());
    for (issued, expires) in [(0, 1), (now, now), (now, now - 1), (now, now + 3601)] {
        let mut invalid = snapshot(now, 1);
        invalid.validity = Some(RegistryValidity {
            issued_at_unix_secs: issued,
            expires_at_unix_secs: expires,
        });
        assert!(invalid.validate().is_err());
        assert!(registry_digest(&invalid).is_err());
    }
    let dir = tempfile::tempdir().unwrap();
    for (offset, accepted) in [(60, true), (61, false)] {
        let path = dir.path().join(format!("future-{offset}.json"));
        let registry = snapshot(now + offset, MAX_POLICY_TTL_SECS);
        publish_snapshot(&path, &registry).unwrap();
        let result = RuntimeRegistry::load_at(&path, now);
        assert_eq!(result.is_ok(), accepted);
        if let Ok(runtime) = result {
            assert!(
                runtime
                    .0
                    .state
                    .read()
                    .unwrap()
                    .policy_deadline
                    .duration_since(Instant::now())
                    <= Duration::from_secs(MAX_POLICY_TTL_SECS)
            );
        }
    }
    let expired = snapshot(now - 2, 1);
    expired.validate().unwrap(); // Administrative repair/renewal remains possible.
    assert!(expired.policy_remaining(now).is_err());
    let mut exhausted = expired.clone();
    exhausted.generation = u64::MAX;
    let before = registry_digest(&exhausted).unwrap();
    assert!(exhausted.refresh_validity(now, 900).is_err());
    assert_eq!(registry_digest(&exhausted).unwrap(), before);
    let mut renewal = expired;
    renewal.refresh_validity(now, 900).unwrap();
    assert_eq!(renewal.generation, 2);
    assert_eq!(renewal.devices.len(), 1);
    assert!(renewal.policy_remaining(now).is_ok());
}

#[tokio::test(start_paused = true)]
async fn continuously_readable_snapshot_expires_despite_reloads_and_clock_rollback() {
    let now = unix_now().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("registry.json");
    let original = snapshot(now, 4);
    let runtime = runtime(&path, &original, now);
    // Keep this paused-time test on one controlled wall-clock timeline.
    // lease() reads the real wall clock: crossing a second during disk I/O
    // legitimately shortens the policy before the simulated advances below.
    assert!(runtime.expiry(&[0x11; 32], now).unwrap().is_some());
    let lease = AuthorizationLease(Some(Lease {
        registry: runtime.clone(),
        fingerprint: [0x11; 32],
        expires: Instant::now() + Duration::from_secs(10_000),
    }));
    let deadline = runtime.0.state.read().unwrap().policy_deadline;
    for elapsed in 1..=4 {
        tokio::time::advance(Duration::from_secs(1)).await;
        runtime.publish_at(DeviceRegistry::load(&path), Ok(now - 100));
        let state = runtime.0.state.read().unwrap();
        assert!(state.policy_deadline <= deadline);
        assert_eq!(state.checked.elapsed(), Duration::ZERO);
        drop(state);
        assert_eq!(
            runtime
                .expiry(&[0x11; 32], now - 100)
                .is_ok_and(|expiry| expiry.is_some()),
            elapsed < 4
        );
    }
    assert_eq!(
        lease.revoked().await.kind(),
        io::ErrorKind::PermissionDenied
    );
    assert!(DeviceRegistry::load(&path).is_ok());
    assert!(RuntimeRegistry::load_at(&path, now + 4).is_err());
    // Another successful read cannot resurrect the expired in-process policy.
    runtime.publish_at(DeviceRegistry::load(&path), Ok(now - 1000));
    assert!(runtime.expiry(&[0x11; 32], now - 1000).is_err());
}

#[tokio::test(start_paused = true)]
async fn ordinary_higher_generation_does_not_renew_policy_but_explicit_refresh_does() {
    let now = unix_now().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("registry.json");
    let mut snapshot = snapshot(now, 2);
    let runtime = runtime(&path, &snapshot, now);
    let existing = runtime.lease([0x11; 32]).unwrap();
    let deadline = runtime.0.state.read().unwrap().policy_deadline;
    tokio::time::advance(Duration::from_secs(1)).await;
    snapshot.generation += 1;
    publish_snapshot(&path, &snapshot).unwrap();
    runtime.publish_at(DeviceRegistry::load(&path), Ok(now - 100));
    assert_eq!(runtime.0.state.read().unwrap().policy_deadline, deadline);

    // The explicit operator renewal is a new canonical snapshot. Existing
    // sessions can continue while the certificate's own deadline stays fixed.
    snapshot.refresh_validity(now + 1, 10).unwrap();
    publish_snapshot(&path, &snapshot).unwrap();
    runtime.publish_at(DeviceRegistry::load(&path), Ok(now + 1));
    tokio::time::advance(Duration::from_secs(1)).await;
    runtime.publish_at(DeviceRegistry::load(&path), Ok(now + 2));
    assert!(runtime.lease([0x11; 32]).is_ok());
    assert!(
        tokio::time::timeout(Duration::from_millis(100), existing.revoked())
            .await
            .is_err()
    );

    snapshot.devices[0].revoked = true;
    snapshot.generation += 1;
    publish_snapshot(&path, &snapshot).unwrap();
    runtime.publish_at(DeviceRegistry::load(&path), Ok(now + 2));
    assert_eq!(
        existing.revoked().await.kind(),
        io::ErrorKind::PermissionDenied
    );
    snapshot.refresh_validity(now + 2, 20).unwrap();
    publish_snapshot(&path, &snapshot).unwrap();
    runtime.publish_at(DeviceRegistry::load(&path), Ok(now + 2));
    assert!(
        runtime.lease([0x11; 32]).is_err(),
        "renewal must preserve revocation"
    );
}

#[tokio::test(start_paused = true)]
async fn forward_clock_expiry_cannot_be_undone_by_backwards_clock_or_new_generation() {
    let now = unix_now().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("registry.json");
    let mut snapshot = snapshot(now, 20);
    let runtime = runtime(&path, &snapshot, now);
    runtime.publish_at(DeviceRegistry::load(&path), Ok(now + 20));
    assert!(runtime.lease([0x11; 32]).is_err());
    snapshot.generation += 1;
    publish_snapshot(&path, &snapshot).unwrap();
    runtime.publish_at(DeviceRegistry::load(&path), Ok(now));
    assert!(runtime.lease([0x11; 32]).is_err());
    snapshot.refresh_validity(now + 20, 20).unwrap();
    publish_snapshot(&path, &snapshot).unwrap();
    runtime.publish_at(DeviceRegistry::load(&path), Ok(now));
    assert!(runtime.lease([0x11; 32]).is_ok());
}

#[tokio::test(start_paused = true)]
async fn authorization_clock_expiry_is_irreversible_without_a_publication() {
    let now = unix_now().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("registry.json");
    let snapshot = snapshot(now, 20);
    let runtime = runtime(&path, &snapshot, now);
    let lease = runtime.lease([0x11; 32]).unwrap();
    let checked = runtime.0.state.read().unwrap().checked;

    assert!(runtime.expiry(&[0x11; 32], now + 20).is_err());
    // Neither a watcher publication nor monotonic advancement occurs between
    // observing expiry and observing the clock move backwards.
    assert!(runtime.expiry(&[0x11; 32], now).is_err());
    assert!(runtime.lease([0x11; 32]).is_err());
    assert_eq!(runtime.0.state.read().unwrap().checked, checked);
    assert_eq!(
        lease.revoked().await.kind(),
        io::ErrorKind::PermissionDenied
    );
}

#[tokio::test(start_paused = true)]
async fn authorization_forward_observation_shortens_the_monotonic_deadline() {
    let now = unix_now().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("registry.json");
    let snapshot = snapshot(now, 20);
    let runtime = runtime(&path, &snapshot, now);
    assert!(runtime.expiry(&[0x11; 32], now + 19).unwrap().is_some());
    assert!(runtime.expiry(&[0x11; 32], now).unwrap().is_some());
    tokio::time::advance(Duration::from_secs(1)).await;
    // The old policy has now expired even though the disk check is younger
    // than MAX_STALENESS and wall time has returned to its initial value.
    assert!(runtime.expiry(&[0x11; 32], now).is_err());
}
