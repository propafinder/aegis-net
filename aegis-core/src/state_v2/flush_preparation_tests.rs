use super::*;
use std::sync::{mpsc, Mutex};
use std::thread;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::oneshot;

const FIXTURE_BOUND: Duration = Duration::from_secs(5);
const GATE_BOUND: Duration = Duration::from_secs(2);

async fn dirty_store(path: PathBuf) -> AsyncStateStore {
    let store = AsyncStateStore::load(path).await.unwrap();
    store
        .update(|snapshot| {
            snapshot
                .strategy_stats
                .insert("fixture-before".into(), Default::default());
        })
        .await;
    store
}

async fn private_writer(
    path: PathBuf,
    out: Vec<u8>,
    lease: tokio::sync::OwnedMutexGuard<()>,
) -> Result<tokio::sync::OwnedMutexGuard<()>, AegisError> {
    write_private_file_async(&path, out, lease).await
}

#[tokio::test(flavor = "current_thread")]
async fn actual_flush_preparation_runs_off_runtime_and_roundtrips() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.json");
    let store = dirty_store(path.clone()).await;
    let runtime_thread = thread::current().id();
    let phases = Arc::new(Mutex::new(Vec::new()));
    let observed = phases.clone();
    store
        .flush_with_preparation_observer(private_writer, move |phase| {
            observed
                .lock()
                .unwrap()
                .push((phase, thread::current().id()));
        })
        .await
        .unwrap();
    assert!(!store.is_dirty());
    let loaded = AsyncStateStore::load(path).await.unwrap().snapshot().await;
    assert!(loaded.strategy_stats.contains_key("fixture-before"));
    let phases = phases.lock().unwrap();
    assert_eq!(phases.len(), 2);
    assert!(phases[0].0 == FlushPreparationPhase::Serialize);
    assert!(phases[1].0 == FlushPreparationPhase::Seal);
    assert!(
        phases.iter().all(|(_, owner)| *owner != runtime_thread),
        "actual serialization and key/seal preparation must leave the runtime thread"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn actual_held_preparation_allows_runtime_control_progress() {
    let dir = TempDir::new().unwrap();
    let store = dirty_store(dir.path().join("state.json")).await;
    let (phase_tx, phase_rx) = mpsc::channel();
    let (heartbeat_tx, heartbeat_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (started_tx, started_rx) = oneshot::channel();
    let watchdog = thread::spawn(move || {
        phase_rx.recv_timeout(GATE_BOUND).unwrap();
        let progressed = heartbeat_rx.recv_timeout(Duration::from_secs(1)).is_ok();
        let _ = release_tx.send(());
        progressed
    });
    let mut started_tx = Some(started_tx);
    let flushing = tokio::spawn(async move {
        store
            .flush_with_preparation_observer(private_writer, move |phase| {
                if phase == FlushPreparationPhase::Serialize {
                    phase_tx.send(()).unwrap();
                    started_tx.take().unwrap().send(()).unwrap();
                    let _ = release_rx.recv_timeout(GATE_BOUND);
                }
            })
            .await
    });
    let result = tokio::time::timeout(FIXTURE_BOUND, async {
        started_rx.await.unwrap();
        let _ = heartbeat_tx.send(());
        flushing.await.unwrap().unwrap();
    })
    .await;
    let progressed = watchdog.join().unwrap();
    result.unwrap();
    assert!(
        progressed,
        "runtime control must run while actual preparation is held"
    );
}

type PhaseObserver = Box<dyn FnMut(FlushPreparationPhase) + Send>;
struct PhaseGate {
    observer: PhaseObserver,
    started: oneshot::Receiver<()>,
    release: mpsc::Sender<()>,
    active: Arc<AtomicBool>,
}

fn gate_phase(wanted: FlushPreparationPhase) -> PhaseGate {
    let (started_tx, started) = oneshot::channel();
    let (release, release_rx) = mpsc::channel();
    let active = Arc::new(AtomicBool::new(false));
    let observing = active.clone();
    let mut started_tx = Some(started_tx);
    let observer = Box::new(move |phase| {
        if phase == wanted {
            observing.store(true, Ordering::Release);
            let _ = started_tx.take().unwrap().send(());
            let _ = release_rx.recv_timeout(GATE_BOUND);
            observing.store(false, Ordering::Release);
        }
    });
    PhaseGate {
        observer,
        started,
        release,
        active,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn actual_cancelled_preparation_keeps_lease_until_worker_finishes() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.json");
    let store = dirty_store(path.clone()).await;
    let PhaseGate {
        observer,
        started,
        release,
        active,
    } = gate_phase(FlushPreparationPhase::Seal);
    let first_store = store.clone();
    let first = tokio::spawn(async move {
        first_store
            .flush_with_preparation_observer(private_writer, observer)
            .await
    });
    tokio::time::timeout(FIXTURE_BOUND, started)
        .await
        .unwrap()
        .unwrap();
    let held_at_start = active.load(Ordering::Acquire);
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    let lease_retained = store.inner.flush_lock.try_lock().is_err();
    store
        .update(|snapshot| {
            snapshot
                .strategy_stats
                .insert("fixture-after".into(), Default::default());
        })
        .await;
    let second_store = store.clone();
    let second = tokio::spawn(async move { second_store.flush().await });
    tokio::task::yield_now().await;
    let next_waits = !second.is_finished();
    let _ = release.send(());
    tokio::time::timeout(FIXTURE_BOUND, second)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    // Acquiring the same lease also waits for any abandoned preparation result
    // to drop, rather than treating an observer's exit as worker completion.
    let lease = tokio::time::timeout(FIXTURE_BOUND, store.inner.flush_lock.lock())
        .await
        .unwrap();
    drop(lease);
    let loaded = AsyncStateStore::load(path).await.unwrap().snapshot().await;
    assert!(loaded.strategy_stats.contains_key("fixture-after"));
    assert!(!store.is_dirty());
    assert!(
        held_at_start,
        "control must run before actual preparation releases its gate"
    );
    assert!(
        lease_retained,
        "cancelled waiter must not release a running worker's lease"
    );
    assert!(
        next_waits,
        "next flush must await the original preparation lease"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn actual_update_during_seal_keeps_original_revision_dirty() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.json");
    let store = dirty_store(path.clone()).await;
    let PhaseGate {
        observer,
        started,
        release,
        active,
    } = gate_phase(FlushPreparationPhase::Seal);
    let flushing_store = store.clone();
    let flushing = tokio::spawn(async move {
        flushing_store
            .flush_with_preparation_observer(private_writer, observer)
            .await
    });
    tokio::time::timeout(FIXTURE_BOUND, started)
        .await
        .unwrap()
        .unwrap();
    store
        .update(|snapshot| {
            snapshot
                .strategy_stats
                .insert("fixture-during".into(), Default::default());
        })
        .await;
    let update_during_seal = active.load(Ordering::Acquire);
    let original_revision = store.inner.revision.load(Ordering::Relaxed);
    let _ = release.send(());
    tokio::time::timeout(FIXTURE_BOUND, flushing)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let older = AsyncStateStore::load(path.clone())
        .await
        .unwrap()
        .snapshot()
        .await;
    assert!(!older.strategy_stats.contains_key("fixture-during"));
    assert!(store.is_dirty());
    assert_eq!(original_revision, 2);
    store.flush().await.unwrap();
    let newer = AsyncStateStore::load(path).await.unwrap().snapshot().await;
    assert!(newer.strategy_stats.contains_key("fixture-during"));
    assert!(!store.is_dirty());
    assert!(
        update_during_seal,
        "update must progress while actual seal preparation is held"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn actual_clean_and_ephemeral_flush_skip_preparation() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("never-written.json");
    let clean = AsyncStateStore::load(path.clone()).await.unwrap();
    clean
        .flush_with_preparation_observer(private_writer, |_| panic!("clean prep"))
        .await
        .unwrap();
    let ephemeral = AsyncStateStore::ephemeral();
    ephemeral.update(|_| {}).await;
    ephemeral
        .flush_with_preparation_observer(private_writer, |_| panic!("ephemeral prep"))
        .await
        .unwrap();
    assert!(ephemeral.is_dirty());
    assert!(!path.exists());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn actual_writer_failure_keeps_dirty_revision_and_previous_blob() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.json");
    let original = serde_json::to_vec(&StateSnapshot::default()).unwrap();
    tokio::fs::write(&path, &original).await.unwrap();
    let store = dirty_store(path.clone()).await;
    let revision = store.inner.revision.load(Ordering::Relaxed);
    let failed = store
        .flush_with_preparation_observer(
            |_path, _out, _lease| async {
                Err(AegisError::Io(std::io::Error::other(
                    "fixture write refusal",
                )))
            },
            |_| {},
        )
        .await;
    assert!(failed.is_err());
    assert!(store.is_dirty());
    assert_eq!(store.inner.revision.load(Ordering::Relaxed), revision);
    assert!(tokio::fs::read(&path).await.unwrap() == original);
    assert!(store.inner.flush_lock.try_lock().is_ok());
    store.flush().await.unwrap();
    assert!(!store.is_dirty());
}
