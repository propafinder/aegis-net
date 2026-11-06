//! Owned durable registry fixtures and an injected single strict ACK query.
//! No systemd, status socket, external process or live relay is used here.
use super::*;
use aegis_core::secure_channel::registry::{self, DeviceRegistry, RuntimePolicyStatus};
use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::time::Instant;

fn fixture() -> (tempfile::TempDir, PathBuf, DeviceRegistry) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().canonicalize().unwrap().join("replica.json");
    let snapshot = DeviceRegistry::new(registry::unix_now().unwrap(), 900).unwrap();
    registry::publish_snapshot(&path, &snapshot).unwrap();
    (dir, path, snapshot)
}

fn unit() -> UnitIdentity {
    UnitIdentity {
        pid: 42,
        invocation: "a".repeat(32),
        fragment: "/etc/systemd/system/aegis-server.service".into(),
        drop_ins: vec![],
        control_group: "/system.slice/aegis-server.service".into(),
    }
}

fn response(expected: &SyncReceipt, lease_ms: u64) -> Response {
    Response::Ready {
        policy: RuntimePolicyStatus {
            generation: expected.generation,
            snapshot_sha256: expected.snapshot_sha256.clone(),
            issued_at_unix_secs: expected.issued_at_unix_secs,
            expires_at_unix_secs: expected.expires_at_unix_secs,
            policy_remaining_ms: 60_000,
            effective_valid_for_ms: lease_ms,
        },
        process: ProcessIdentity {
            pid: 42,
            process_start_ticks: Some(99),
            version: "0.3.50".into(),
            build_git: "b".repeat(40),
            build_target: "aarch64-unknown-linux-gnu".into(),
            cargo_lock_sha256: "c".repeat(64),
        },
    }
}

fn acknowledged(expected: &SyncReceipt, lease_ms: u64) -> Result<RuntimeAcknowledgement> {
    matches_live(expected, response(expected, lease_ms), &unit(), Some(99), 0)
}

struct PublicationBarrier {
    start: oneshot::Sender<()>,
    locked: oneshot::Receiver<()>,
    release: oneshot::Sender<()>,
    published: oneshot::Receiver<SyncReceipt>,
}

impl PublicationBarrier {
    async fn publish(self, path: &Path) -> SyncReceipt {
        self.start.send(()).unwrap();
        self.locked.await.unwrap();
        // The real exclusive publication lock is held at this barrier.
        assert_eq!(
            DeviceRegistry::load(path).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        self.release.send(()).unwrap();
        self.published.await.unwrap()
    }
}

fn publication_barrier(
    path: &Path,
    mut snapshot: DeviceRegistry,
) -> (PublicationBarrier, tokio::task::JoinHandle<()>) {
    snapshot
        .refresh_validity(registry::unix_now().unwrap(), 900)
        .unwrap();
    let path = path.to_owned();
    let (start, started) = oneshot::channel();
    let (locked, lock_acquired) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let (published, publication) = oneshot::channel();
    let task = tokio::spawn(async move {
        started.await.unwrap();
        let transaction = registry::RegistryTransaction::begin(&path).unwrap();
        locked.send(()).unwrap();
        released.await.unwrap();
        transaction.save(&path, &snapshot, false).unwrap();
        drop(transaction);
        published
            .send(super::super::disk_receipt(&snapshot).unwrap())
            .unwrap();
    });
    (
        PublicationBarrier {
            start,
            locked: lock_acquired,
            release,
            published: publication,
        },
        task,
    )
}

async fn rotation_case(ack_before_publication: bool) {
    let (_dir, path, snapshot) = fixture();
    let (barrier, publisher) = publication_barrier(&path, snapshot);
    let mut barrier = Some(barrier);
    let calls = std::cell::RefCell::new(Vec::new());
    let ack = health_until_with(&path, Instant::now() + Duration::from_secs(5), |expected| {
        calls.borrow_mut().push(expected.generation);
        let barrier = barrier.take();
        let path = path.clone();
        async move {
            if let Some(barrier) = barrier {
                let earlier = acknowledged(&expected, 2500);
                let current = barrier.publish(&path).await;
                if ack_before_publication {
                    earlier
                } else {
                    matches_live(&expected, response(&current, 2500), &unit(), Some(99), 0)
                }
            } else {
                acknowledged(&expected, 2500)
            }
        }
    })
    .await
    .unwrap();
    publisher.await.unwrap();
    assert_eq!(*calls.borrow(), [1, 2]);
    let durable = super::super::disk_receipt(&DeviceRegistry::load(&path).unwrap()).unwrap();
    assert_eq!(ack.generation, durable.generation);
    assert_eq!(ack.snapshot_sha256, durable.snapshot_sha256);
    assert_eq!(ack.process.pid, 42);
    assert_eq!(ack.process.process_start_ticks, Some(99));
    assert_eq!(ack.systemd_invocation_id, "a".repeat(32));
    assert!(ack.effective_valid_for_ms > 0 && ack.effective_valid_for_ms < 2500);
}

#[tokio::test]
async fn health_reloads_after_publication_between_durable_read_and_live_ack() {
    rotation_case(false).await;
}

#[tokio::test]
async fn health_retries_when_successful_ack_is_staled_by_final_readback() {
    rotation_case(true).await;
}

#[tokio::test]
async fn health_current_tuple_requires_only_one_strict_query() {
    let (_dir, path, snapshot) = fixture();
    let expected = super::super::disk_receipt(&snapshot).unwrap();
    let calls = Cell::new(0);
    let ack = health_until_with(&path, Instant::now() + Duration::from_secs(5), |current| {
        calls.set(calls.get() + 1);
        assert_eq!(current, expected);
        std::future::ready(acknowledged(&current, 2500))
    })
    .await
    .unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(ack.generation, expected.generation);
    assert_eq!(ack.snapshot_sha256, expected.snapshot_sha256);
    assert!(ack.effective_valid_for_ms > 0 && ack.effective_valid_for_ms < 2500);
}

#[tokio::test]
async fn health_stable_durable_tuple_waits_for_exact_runtime_adoption() {
    let (_dir, path, mut snapshot) = fixture();
    let old = super::super::disk_receipt(&snapshot).unwrap();
    snapshot
        .refresh_validity(registry::unix_now().unwrap(), 900)
        .unwrap();
    registry::publish_snapshot(&path, &snapshot).unwrap();
    let calls = std::cell::RefCell::new(Vec::new());
    let ack = health_until_with(&path, Instant::now() + Duration::from_secs(5), |expected| {
        let response = if calls.borrow().is_empty() {
            response(&old, 2500)
        } else {
            response(&expected, 2500)
        };
        let Response::Ready { policy, .. } = &response else {
            unreachable!()
        };
        calls
            .borrow_mut()
            .push((expected.generation, policy.generation));
        std::future::ready(matches_live(&expected, response, &unit(), Some(99), 0))
    })
    .await
    .unwrap();
    assert_eq!(*calls.borrow(), [(2, 1), (2, 2)]);
    assert_eq!(ack.generation, 2);
    assert_eq!(DeviceRegistry::load(&path).unwrap().generation, 2);
}

#[tokio::test]
async fn health_never_retries_unsupported_or_invalid_config_query_errors() {
    for error in [
        PolicyError::RuntimeAckUnsupported,
        PolicyError::InvalidConfig,
    ] {
        let (_dir, path, _) = fixture();
        let mut error = Some(error);
        let calls = Cell::new(0);
        let result = health_until_with(&path, Instant::now() + Duration::from_secs(5), |_| {
            calls.set(calls.get() + 1);
            std::future::ready(Err(error.take().unwrap()))
        })
        .await;
        assert!(matches!(
            result,
            Err(PolicyError::RuntimeAckUnsupported | PolicyError::InvalidConfig)
        ));
        assert_eq!(calls.get(), 1);
    }
}

#[tokio::test]
async fn health_persistent_wrong_digest_pid_or_start_ticks_exhausts_original_budget() {
    let changes: [fn(&mut RuntimePolicyStatus, &mut ProcessIdentity); 3] = [
        |policy, _| policy.snapshot_sha256 = "d".repeat(64),
        |_, process| process.pid += 1,
        |_, process| process.process_start_ticks = Some(100),
    ];
    for change in changes {
        let (_dir, path, _) = fixture();
        let calls = Cell::new(0);
        let deadline = Instant::now() + Duration::from_secs(1);
        let error = health_until_with(&path, deadline, |expected| {
            calls.set(calls.get() + 1);
            let Response::Ready {
                mut policy,
                mut process,
            } = response(&expected, 2500)
            else {
                unreachable!()
            };
            change(&mut policy, &mut process);
            let result = matches_live(
                &expected,
                Response::Ready { policy, process },
                &unit(),
                Some(99),
                0,
            );
            let exhaust = calls.get() >= 3;
            async move {
                if exhaust {
                    // Explicit deadline exhaustion after strict refusals;
                    // this timer is not publication ordering evidence.
                    tokio::time::sleep_until(deadline).await;
                }
                result
            }
        })
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            PolicyError::RuntimeAckUnavailable | PolicyError::RegistryUnavailable
        ));
        assert!(calls.get() >= 2);
    }
}

fn invalidate(path: &Path, kind: &str) {
    match kind {
        "snapshot" => fs::write(path, b"not-json").unwrap(),
        "floor-json" => fs::write(registry::floor_path(path), b"not-json").unwrap(),
        "floor" => {
            let floor = registry::floor_path(path);
            let mut value: serde_json::Value =
                serde_json::from_slice(&fs::read(&floor).unwrap()).unwrap();
            value["generation"] = serde_json::json!(2);
            fs::write(floor, serde_json::to_vec(&value).unwrap()).unwrap();
        }
        "missing" => fs::remove_file(path).unwrap(),
        "pending" | "issuance" => {
            use std::os::unix::fs::PermissionsExt;
            let pending = if kind == "pending" {
                registry::pending_path(path)
            } else {
                registry::issuance_pending_path(path)
            };
            fs::write(&pending, b"recovery-required").unwrap();
            fs::set_permissions(pending, fs::Permissions::from_mode(0o600)).unwrap();
        }
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn health_refuses_invalid_durable_inputs_before_query_and_after_ack() {
    for kind in [
        "snapshot",
        "floor-json",
        "floor",
        "missing",
        "pending",
        "issuance",
    ] {
        for after_ack in [false, true] {
            let (_dir, path, _) = fixture();
            if !after_ack {
                invalidate(&path, kind);
            }
            let calls = Cell::new(0);
            let error =
                health_until_with(&path, Instant::now() + Duration::from_secs(5), |expected| {
                    calls.set(calls.get() + 1);
                    assert!(after_ack);
                    let ack = acknowledged(&expected, 2500);
                    invalidate(&path, kind);
                    std::future::ready(ack)
                })
                .await
                .unwrap_err();
            assert_eq!(
                error,
                PolicyError::RegistryUnavailable,
                "{kind}/{after_ack}"
            );
            assert_eq!(calls.get(), usize::from(after_ack));
        }
    }
}

#[tokio::test]
async fn health_refuses_expired_and_future_durable_policy_before_query() {
    for snapshot in [
        DeviceRegistry::new(1, 1).unwrap(),
        DeviceRegistry::new(registry::unix_now().unwrap() + 3600, 900).unwrap(),
    ] {
        let (_dir, path, _) = fixture();
        // An owned fixture installs the exact matching durable pair, without
        // changing the production publication or validity predicates.
        fs::remove_file(&path).unwrap();
        fs::remove_file(registry::floor_path(&path)).unwrap();
        registry::publish_snapshot(&path, &snapshot).unwrap();
        let calls = Cell::new(0);
        let error = health_until_with(&path, Instant::now() + Duration::from_secs(5), |_| {
            calls.set(calls.get() + 1);
            std::future::ready(Err(PolicyError::RuntimeAckUnavailable))
        })
        .await
        .unwrap_err();
        assert_eq!(error, PolicyError::InvalidValidity);
        assert_eq!(calls.get(), 0);
    }
}

#[tokio::test]
async fn health_final_readback_refuses_expired_or_future_successor() {
    for invalid in [
        DeviceRegistry::new(1, 1).unwrap(),
        DeviceRegistry::new(registry::unix_now().unwrap() + 3600, 900).unwrap(),
    ] {
        let (_dir, path, _) = fixture();
        let calls = Cell::new(0);
        let error = health_until_with(&path, Instant::now() + Duration::from_secs(5), |expected| {
            calls.set(calls.get() + 1);
            let ack = acknowledged(&expected, 2500);
            let mut successor = invalid.clone();
            successor.generation = expected.generation + 1;
            registry::publish_snapshot(&path, &successor).unwrap();
            std::future::ready(ack)
        })
        .await
        .unwrap_err();
        assert_eq!(error, PolicyError::InvalidValidity);
        assert_eq!(calls.get(), 1);
    }
}

#[tokio::test]
async fn health_refuses_already_exhausted_original_deadline_before_query() {
    let (_dir, path, _) = fixture();
    let calls = Cell::new(0);
    assert!(health_until_with(&path, Instant::now(), |_| {
        calls.set(calls.get() + 1);
        std::future::ready(Err(PolicyError::RuntimeAckUnavailable))
    })
    .await
    .is_err());
    assert_eq!(calls.get(), 0);
}

#[tokio::test]
async fn health_rotation_never_resets_the_original_deadline() {
    let (_dir, path, snapshot) = fixture();
    let (barrier, publisher) = publication_barrier(&path, snapshot);
    let mut barrier = Some(barrier);
    let deadline = Instant::now() + Duration::from_secs(1);
    let calls = Cell::new(0);
    assert!(health_until_with(&path, deadline, |expected| {
        calls.set(calls.get() + 1);
        let barrier = barrier.take().unwrap();
        let path = path.clone();
        async move {
            let current = barrier.publish(&path).await;
            // The publication ordering is proved by the channels above.
            // This timer deliberately exhausts the budget, not an ordering sleep.
            tokio::time::sleep_until(deadline).await;
            matches_live(&expected, response(&current, 2500), &unit(), Some(99), 0)
        }
    })
    .await
    .is_err());
    publisher.await.unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(DeviceRegistry::load(&path).unwrap().generation, 2);
}

#[tokio::test]
async fn health_final_readback_debits_and_can_exhaust_the_live_ack_lease() {
    let (_dir, path, _) = fixture();
    let mut release = None;
    let calls = Cell::new(0);
    let error = health_until_with(&path, Instant::now() + Duration::from_secs(5), |expected| {
        calls.set(calls.get() + 1);
        let ack = acknowledged(&expected, 1);
        // Hold the real publication lock before returning the ACK. A
        // deliberate lease-expiry timer releases it; no publication occurs.
        let transaction = registry::RegistryTransaction::begin(&path).unwrap();
        let release_at = Instant::now() + Duration::from_millis(20);
        release = Some(tokio::spawn(async move {
            tokio::time::sleep_until(release_at).await;
            drop(transaction);
        }));
        std::future::ready(ack)
    })
    .await
    .unwrap_err();
    release.unwrap().await.unwrap();
    assert_eq!(error, PolicyError::RuntimeAckUnavailable);
    assert_eq!(calls.get(), 1);
    assert_eq!(DeviceRegistry::load(&path).unwrap().generation, 1);
}

#[cfg(not(target_os = "linux"))]
#[tokio::test]
async fn health_unsupported_platform_refuses_without_registry_io_or_wait() {
    let config = RuntimeAckConfig {
        service_unit: default_service_unit(),
        socket: "/run/aegis/status.sock".into(),
        service_uid: 123,
        service_gid: 123,
        timeout_secs: 10,
    };
    let result = tokio::time::timeout(
        Duration::ZERO,
        verify_current_until(
            &config,
            Path::new("/nonexistent-health-fixture/registry"),
            Instant::now() + Duration::from_secs(10),
        ),
    )
    .await
    .expect("unsupported Health must complete on its first poll");
    assert_eq!(result.unwrap_err(), PolicyError::RuntimeAckUnsupported);
}
