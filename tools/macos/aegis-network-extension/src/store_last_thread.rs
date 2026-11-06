//! Store-last thread lifetime primitive for a future composite owner.
//! The worker owns the claim; dropping the controller never aborts that thread.
//! This module creates no packet bridge, relay service, or provider factory.

use std::{
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const MAX_JOIN: Duration = Duration::from_secs(2);

#[derive(Debug)]
struct RetainedError(Arc<io::Error>);
impl std::fmt::Display for RetainedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}
impl std::error::Error for RetainedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

/// A non-cloneable owner of one thread that retains the exact protected Store
/// claim until its synchronous work finishes. A timed-out join retains the
/// JoinHandle; controller Drop requests stop but lets that same thread run to
/// terminal completion with its claim. This does not join any child that the
/// supplied work might spawn, so it is not a packet or H2 admission owner.
#[must_use = "retain the owner until stop_and_join completes"]
#[allow(dead_code)]
pub(crate) struct StoreLastThreadOwner {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<io::Result<()>>>,
    terminal: Option<Result<(), Arc<io::Error>>>,
    panicked: bool,
}

#[allow(dead_code)]
impl StoreLastThreadOwner {
    /// Move the claim into the worker. The closure only borrows it; the worker
    /// drops it after `run` returns. A future call site must create its Tokio
    /// runtime and all reactor-bound channels on this thread, then join every
    /// child before `run` returns. No caller currently uses this in production.
    pub(crate) fn spawn<T, F>(claim: T, run: F) -> io::Result<Self>
    where
        T: Send + 'static,
        F: FnOnce(&mut T, Arc<AtomicBool>) -> io::Result<()> + Send + 'static,
    {
        let stop = Arc::new(AtomicBool::new(false));
        let child_stop = stop.clone();
        let worker = thread::Builder::new()
            .name("aegis-ne-store-last".into())
            .spawn(move || {
                let mut claim = claim;
                let result = run(&mut claim, child_stop);
                drop(claim);
                result
            })?;
        Ok(Self {
            stop,
            worker: Some(worker),
            terminal: None,
            panicked: false,
        })
    }

    /// The worker thread has returned or unwound; a join will not wait.
    pub(crate) fn finished(&self) -> bool {
        self.worker.as_ref().is_none_or(JoinHandle::is_finished)
    }

    /// The joined worker unwound. Its owners were dropped, not joined, so a
    /// containing owner must not report that thread's children as terminal.
    pub(crate) fn worker_panicked(&self) -> bool {
        self.panicked
    }

    pub(crate) fn stop_and_join(&mut self, budget: Duration) -> io::Result<()> {
        if budget > MAX_JOIN {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.as_ref() {
            let deadline = Instant::now() + budget;
            while !worker.is_finished() {
                if Instant::now() >= deadline {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                thread::sleep(
                    Duration::from_millis(2)
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
            }
        }
        if let Some(worker) = self.worker.take() {
            self.terminal = Some(match worker.join() {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => Err(Arc::new(error)),
                Err(_) => {
                    self.panicked = true;
                    Err(Arc::new(io::Error::other("Store worker panicked")))
                }
            });
        }
        match self
            .terminal
            .as_ref()
            .expect("terminal join result retained")
        {
            Ok(()) => Ok(()),
            Err(error) => Err(io::Error::new(error.kind(), RetainedError(error.clone()))),
        }
    }
}

impl Drop for StoreLastThreadOwner {
    fn drop(&mut self) {
        // Detaching a *thread* does not cancel its work or drop its Store.
        // If it cannot stop, it retains the Store indefinitely in this
        // process. A future live owner must synchronously seal all I/O first.
        self.stop.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_client::protected_identity_store::ProtectedIdentityStore;
    use aegis_client::protected_online_expectation::ProtectedOnlineExpectation;
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, sync::mpsc};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "aegis-ne-store-last-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let identity = dir.join("identity");
            fs::create_dir_all(&identity).unwrap();
            fs::set_permissions(&identity, fs::Permissions::from_mode(0o700)).unwrap();
            for (name, data) in [(".lock", b"".as_slice()), ("identity.json", b"fixture")] {
                let path = identity.join(name);
                fs::write(&path, data).unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            Self(identity)
        }
        fn identity(&self) -> &std::path::Path {
            &self.0
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(self.0.parent().unwrap());
        }
    }

    #[test]
    fn actual_protected_store_lock_survives_timeout_and_owner_drop() {
        fn assert_send<T: Send>() {}
        assert_send::<ProtectedOnlineExpectation<'static>>();
        assert_send::<crate::local_identity::ObservedLocalSession>();

        let fixture = Fixture::new();
        let profile = "a".repeat(64);
        let claim =
            ProtectedOnlineExpectation::open_existing(fixture.identity(), &profile).unwrap();
        let (started, ready) = mpsc::sync_channel(1);
        let (release, wait) = mpsc::channel();
        let mut owner = StoreLastThreadOwner::spawn(claim, move |_claim, _stop| {
            started.send(()).unwrap();
            wait.recv().unwrap();
            Ok(())
        })
        .unwrap();
        ready.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(
            owner.stop_and_join(Duration::ZERO).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(ProtectedIdentityStore::open_existing(fixture.identity()).is_err());
        drop(owner);
        assert!(ProtectedIdentityStore::open_existing(fixture.identity()).is_err());
        release.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match ProtectedIdentityStore::open_existing(fixture.identity()) {
                Ok(reopened) => {
                    drop(reopened);
                    break;
                }
                Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(2)),
                Err(error) => panic!("Store lock not released after worker exit: {error}"),
            }
        }
    }

    #[test]
    fn terminal_worker_error_is_stable_across_repeated_join() {
        let mut owner = StoreLastThreadOwner::spawn((), |_, _| {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "fixture denial",
            ))
        })
        .unwrap();
        let first = owner.stop_and_join(Duration::from_secs(1)).unwrap_err();
        let second = owner.stop_and_join(Duration::ZERO).unwrap_err();
        assert_eq!(first.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(second.kind(), first.kind());
        assert!(second.to_string().contains("fixture denial"));
    }
}
