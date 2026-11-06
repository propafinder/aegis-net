//! Actual watcher/verified registry-read lifetime controls. The owned read
//! callback gates its entered blocking task; it does not simulate kernel I/O
//! cancellation. All assertions run after release and bounded cleanup attempts.

use super::*;
use std::sync::atomic::AtomicUsize;
use std::sync::{Condvar, Mutex};

const ENTER: Duration = Duration::from_secs(2);
const STOP: Duration = Duration::from_millis(500);
const CLEANUP: Duration = Duration::from_secs(2);
const READ_WATCHDOG: Duration = Duration::from_secs(5);

#[derive(Default)]
struct Gate {
    released: Mutex<bool>,
    changed: Condvar,
    entered: AtomicUsize,
    actual_reads: AtomicUsize,
    verified_reads: AtomicUsize,
    exited: AtomicUsize,
}

impl Gate {
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.changed.notify_all();
    }

    fn read(&self, path: PathBuf) -> io::Result<DeviceRegistry> {
        self.entered.fetch_add(1, Ordering::SeqCst);
        struct Exited<'a>(&'a Gate);
        impl Drop for Exited<'_> {
            fn drop(&mut self) {
                self.0.exited.fetch_add(1, Ordering::SeqCst);
            }
        }
        let _exited = Exited(self);
        let released = self.released.lock().unwrap();
        let (released, wait) = self
            .changed
            .wait_timeout_while(released, READ_WATCHDOG, |released| !*released)
            .unwrap();
        if wait.timed_out() && !*released {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "fixture read watchdog",
            ));
        }
        drop(released);
        // This is the real production storage/floor reader, after the
        // controlled callback hold. No fake snapshot is returned by the seam.
        let result = DeviceRegistry::load(&path);
        self.actual_reads.fetch_add(1, Ordering::SeqCst);
        if result.is_ok() {
            self.verified_reads.fetch_add(1, Ordering::SeqCst);
        }
        result
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    runtime: RuntimeRegistry,
    watcher: Option<RegistryWatcher>,
    gate: Arc<Gate>,
}

impl Fixture {
    fn held() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.json");
        let now = unix_now().unwrap();
        let registry = DeviceRegistry {
            devices: vec![DeviceRecord {
                device_id: "reader-lifetime-fixture".into(),
                certificate_sha256: "11".repeat(32),
                not_after_unix_secs: now + 60,
                revoked: false,
            }],
            ..DeviceRegistry::new(now, DEFAULT_POLICY_TTL_SECS).unwrap()
        };
        publish_snapshot(&path, &registry).unwrap();
        let runtime = RuntimeRegistry::load(&path).unwrap();
        let gate = Arc::new(Gate::default());
        let reader = gate.clone();
        let watcher = runtime
            .start_watcher_with_reader(move |path| reader.read(path))
            .unwrap();
        Self {
            _dir: dir,
            runtime,
            watcher: Some(watcher),
            gate,
        }
    }

    async fn entered(&self) -> bool {
        tokio::time::timeout(ENTER, async {
            while self.gate.entered.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .is_ok()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // A panic never strands a deliberately held blocking task. This
        // releases the test gate only; it does not count as joined cleanup.
        self.gate.release();
    }
}

#[tokio::test]
async fn entered_registry_read_timeout_retains_original_handle_and_refuses_false_join() {
    let mut f = Fixture::held();
    let entered = f.entered().await;
    let original = f.watcher.as_ref().unwrap().readers.handle_id();
    let stop = f
        .watcher
        .as_mut()
        .unwrap()
        .stop_and_join_read_until(Instant::now() + STOP)
        .await;
    let retained = f.watcher.as_ref().unwrap().readers.handle_id();
    let watcher_joined_before_release = f.watcher.as_ref().unwrap().task.is_none();
    let fail_closed = f.runtime.lease([0x11; 32]).is_err();
    let before_release = f.gate.exited.load(Ordering::SeqCst);
    f.gate.release();
    let cleanup_cutoff = Instant::now() + CLEANUP;
    let cleanup = f
        .watcher
        .as_mut()
        .unwrap()
        .stop_and_join_read_until(cleanup_cutoff)
        .await;
    // Common exterior reader authority drains the actual handle even in the
    // watcher-only counterfactual. Validity/cleanup precede the causal assert.
    let reader_cleanup = f
        .watcher
        .as_ref()
        .unwrap()
        .readers
        .join_until(cleanup_cutoff)
        .await;
    cleanup.expect("fixture retained watcher cleanup unconfirmed");
    reader_cleanup.expect("fixture retained reader cleanup unconfirmed");
    assert_eq!(
        f.gate.verified_reads.load(Ordering::SeqCst),
        1,
        "actual verified reader positive required"
    );
    assert_eq!(
        f.gate.exited.load(Ordering::SeqCst),
        1,
        "entered reader must be terminal before assertions"
    );
    assert!(
        entered && original.is_some(),
        "actual blocking reader must have entered"
    );
    assert!(
        watcher_joined_before_release,
        "async watcher join must precede reader causal assertion"
    );
    assert_eq!(
        stop.err().map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut),
        "entered read must refuse watcher-only false join"
    );
    assert_eq!(retained, original, "same original blocking handle retained");
    assert_eq!(before_release, 0, "held callback must remain active");
    assert!(fail_closed, "stopping watcher cannot retain authorization");
    assert_eq!(f.gate.actual_reads.load(Ordering::SeqCst), 1);
    assert_eq!(f.gate.exited.load(Ordering::SeqCst), 1);
    assert!(f.watcher.as_ref().unwrap().readers.handle_id().is_none());
}

#[tokio::test]
async fn cancelling_borrowed_stop_preserves_join_authority_and_original_cutoff() {
    let mut f = Fixture::held();
    let entered = f.entered().await;
    let original = f.watcher.as_ref().unwrap().readers.handle_id();
    let cutoff = Instant::now() + CLEANUP;
    let unexpectedly_completed = {
        let stopping = f.watcher.as_mut().unwrap().stop_and_join_read_until(cutoff);
        tokio::pin!(stopping);
        tokio::select! {
            _ = &mut stopping => true,
            _ = tokio::time::sleep(Duration::from_millis(25)) => false,
        }
    };
    let retained = f.watcher.as_ref().unwrap().readers.handle_id();
    let watcher_joined_before_release = f.watcher.as_ref().unwrap().task.is_none();
    f.gate.release();
    // The original captured cutoff is reused; cancellation does not rearm it.
    let cleanup = f
        .watcher
        .as_mut()
        .unwrap()
        .stop_and_join_read_until(cutoff)
        .await;
    let reader_cleanup = f.watcher.as_ref().unwrap().readers.join_until(cutoff).await;
    cleanup.expect("fixture cancelled-stop watcher cleanup unconfirmed");
    reader_cleanup.expect("fixture cancelled-stop reader cleanup unconfirmed");
    assert_eq!(
        f.gate.verified_reads.load(Ordering::SeqCst),
        1,
        "actual verified reader positive required"
    );
    assert_eq!(f.gate.exited.load(Ordering::SeqCst), 1);
    assert!(entered && original.is_some());
    assert!(
        watcher_joined_before_release,
        "async watcher join must precede cancelled reader wait"
    );
    assert!(
        !unexpectedly_completed,
        "held read cannot complete the borrowed stop"
    );
    assert_eq!(retained, original);
    assert_eq!(f.gate.actual_reads.load(Ordering::SeqCst), 1);
    assert_eq!(f.gate.exited.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn stopped_reader_admission_refuses_before_actual_spawn() {
    let owner = reader_owner::ReaderOwner::new();
    let calls = Arc::new(AtomicUsize::new(0));
    owner.close();
    let callback_calls = calls.clone();
    let result = owner.start(move || {
        callback_calls.fetch_add(1, Ordering::SeqCst);
        Err(io::Error::other("fixture callback must not run"))
    });
    let cleanup = owner.join_until(Instant::now() + CLEANUP).await;
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(io::ErrorKind::BrokenPipe)
    );
    cleanup.expect("empty stopped reader owner cleanup unconfirmed");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(owner.handle_id().is_none());
}

#[tokio::test]
async fn actual_verified_read_completes_then_repeated_stop_is_terminal_once() {
    let mut f = Fixture::held();
    let entered = f.entered().await;
    f.gate.release();
    let observed = tokio::time::timeout(ENTER, async {
        while f.gate.actual_reads.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .is_ok();
    let cutoff = Instant::now() + CLEANUP;
    let cleanup = f
        .watcher
        .as_mut()
        .unwrap()
        .stop_and_join_read_until(cutoff)
        .await;
    let repeated = f
        .watcher
        .as_mut()
        .unwrap()
        .stop_and_join_read_until(cutoff)
        .await;
    let reader_cleanup = f.watcher.as_ref().unwrap().readers.join_until(cutoff).await;
    reader_cleanup.expect("fixture actual-read exterior cleanup unconfirmed");
    assert_eq!(
        f.gate.verified_reads.load(Ordering::SeqCst),
        1,
        "actual verified reader positive required"
    );
    assert!(entered && observed);
    cleanup.expect("fixture actual reader cleanup unconfirmed");
    repeated.expect("fixture terminal watcher repolled incorrectly");
    assert_eq!(f.gate.actual_reads.load(Ordering::SeqCst), 1);
    assert_eq!(f.gate.exited.load(Ordering::SeqCst), 1);
    assert!(f.watcher.as_ref().unwrap().readers.handle_id().is_none());
}

#[tokio::test]
async fn consuming_compatibility_stop_refuses_unfinished_read_without_false_join() {
    let mut f = Fixture::held();
    let entered = f.entered().await;
    let watcher = f.watcher.take().unwrap();
    // Test-only exterior retention permits cleanup after exercising the
    // consuming compatibility API. Production consumers have no such clone.
    let test_cleanup_owner = watcher.readers.clone();
    let original = test_cleanup_owner.handle_id();
    let result = watcher.stop_and_join_until(Instant::now() + STOP).await;
    let async_join_unconfirmed = result
        .as_ref()
        .err()
        .is_some_and(|error| error.to_string() == "registry watcher terminal unconfirmed");
    let retained = test_cleanup_owner.handle_id();
    let before_release = f.gate.exited.load(Ordering::SeqCst);
    f.gate.release();
    let cleanup = test_cleanup_owner
        .join_until(Instant::now() + CLEANUP)
        .await;
    cleanup.expect("fixture consuming-stop exterior reader cleanup unconfirmed");
    assert_eq!(
        f.gate.verified_reads.load(Ordering::SeqCst),
        1,
        "actual verified reader positive required"
    );
    assert_eq!(f.gate.exited.load(Ordering::SeqCst), 1);
    assert!(entered && original.is_some());
    assert!(
        !async_join_unconfirmed,
        "async watcher join must precede consuming reader causal assertion"
    );
    assert_eq!(
        result.err().map(|error| error.kind()),
        Some(io::ErrorKind::TimedOut),
        "consuming stop cannot claim an unfinished blocking read was joined"
    );
    assert_eq!(retained, original);
    assert_eq!(before_release, 0);
    assert_eq!(f.gate.actual_reads.load(Ordering::SeqCst), 1);
    assert_eq!(f.gate.exited.load(Ordering::SeqCst), 1);
}
