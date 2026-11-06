//! Source-only authenticated H2/ACK observation constructed inside its owned
//! Store thread and Tokio runtime. No packet lease, FACTORY or native callback.

#![allow(dead_code)]

use crate::{
    app_group::CapturedAppGroupInputs,
    configuration::SavedProviderIntent,
    intent_wire::decode_public_intent,
    local_identity::PreparedLocalSession,
    relay_socket::{connect_bound, resolve_relay_interface},
    store_last_thread::StoreLastThreadOwner,
};
use std::{
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    time::Duration,
};
use tokio::{runtime::Builder, sync::oneshot};

const MAX_READY: Duration = Duration::from_secs(2);

fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "authenticated observation refused",
    )
}

fn report(ready: &mut Option<mpsc::SyncSender<io::Result<()>>>, result: io::Result<()>) {
    if let Some(sender) = ready.take() {
        let _ = sender.send(result);
    }
}

async fn wait_stop(stop: &AtomicBool) {
    while !stop.load(Ordering::Acquire) {
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

fn run_claim(
    claim: CapturedAppGroupInputs,
    saved: SavedProviderIntent,
    stop: Arc<AtomicBool>,
    mut ready: Option<mpsc::SyncSender<io::Result<()>>>,
) -> io::Result<()> {
    let result = (|| -> io::Result<()> {
        // Open the Store and capture held crypto before any Tokio I/O. This
        // thread owns the claim for the entire authenticated observation.
        let (prepared, store_guard) = PreparedLocalSession::from_claim_with_store_guard(claim)?;
        let peer = prepared.pinned_peer()?;
        if peer.ip() != saved.policy.relay() || stop.load(Ordering::Acquire) {
            return Err(refused());
        }
        // S16f: the relay socket is bound to the physical egress interface.
        let interface = resolve_relay_interface(peer).map_err(|_| refused())?;
        let runtime = Builder::new_current_thread().enable_all().build()?;
        let connected = runtime.block_on(async {
            tokio::select! {
                biased;
                _ = wait_stop(&stop) => Err(io::ErrorKind::Interrupted.into()),
                connected = tokio::time::timeout(MAX_READY, connect_bound(peer, &interface)) => {
                    connected.map_err(|_| io::ErrorKind::TimedOut.into()).and_then(|result| result)
                }
            }
        });
        let tcp = connected?;
        let mut observed = runtime.block_on(async {
            tokio::select! {
                biased;
                _ = wait_stop(&stop) => Err(io::ErrorKind::Interrupted.into()),
                observed = prepared.observe_ack(saved, tcp, interface) => observed,
            }
        })?;
        let (signal, received) = oneshot::channel();
        let terminal = runtime.block_on(async {
            let monitor = observed.monitor_borrowed_with_ready(signal);
            tokio::pin!(monitor);
            tokio::select! {
                biased;
                _ = wait_stop(&stop) => return Err(io::ErrorKind::Interrupted.into()),
                ended = &mut monitor => return ended.and(Err(refused())),
                became_ready = received => became_ready.map_err(|_| refused())?,
            }
            report(&mut ready, Ok(()));
            tokio::select! {
                biased;
                ended = &mut monitor => ended.and(Err(refused())),
                _ = wait_stop(&stop) => Ok(()),
            }
        });
        // The H2/TLS stream and pinned driver close on their original runtime.
        // Retain the exact Store claim while that runtime shuts down.
        let identity = observed.close_transport_keep_store();
        // A timed runtime shutdown could detach pending tasks and return while
        // they still hold transport work. Blocking shutdown is fail-closed:
        // the controller's join is bounded, but this thread keeps the Store.
        drop(runtime);
        drop(identity);
        drop(store_guard);
        terminal
    })();
    if let Err(error) = &result {
        report(
            &mut ready,
            Err(io::Error::new(error.kind(), error.to_string())),
        );
    }
    result
}

#[must_use = "retain the H2/ACK observation until terminal join"]
pub(crate) struct StoreScopedObservationOwner {
    supervisor: StoreLastThreadOwner,
    ready: mpsc::Receiver<io::Result<()>>,
}

impl StoreScopedObservationOwner {
    fn from_worker<T, F>(claim: T, run: F) -> io::Result<Self>
    where
        T: Send + 'static,
        F: FnOnce(
                &mut T,
                Arc<AtomicBool>,
                Option<mpsc::SyncSender<io::Result<()>>>,
            ) -> io::Result<()>
            + Send
            + 'static,
    {
        let (sender, ready) = mpsc::sync_channel(1);
        let supervisor =
            StoreLastThreadOwner::spawn(claim, move |claim, stop| run(claim, stop, Some(sender)))?;
        Ok(Self { supervisor, ready })
    }

    pub(crate) fn spawn(
        claim: CapturedAppGroupInputs,
        saved: SavedProviderIntent,
    ) -> io::Result<Self> {
        Self::from_worker(Some(claim), move |claim, stop, ready| {
            run_claim(
                claim.take().expect("single Store claim"),
                saved,
                stop,
                ready,
            )
        })
    }

    /// Child-only source seam: decode public manager intent, capture the
    /// child's exact signed App Group role, and hand the one claim to the
    /// existing Store-last H2/ACK worker. XPC still needs an authenticated
    /// source/epoch binding; this method grants no packet lease or FACTORY.
    #[allow(dead_code)] // fixed child executable is not linked yet
    pub(crate) fn spawn_child_from_public_wire(wire: &[u8]) -> io::Result<Self> {
        let decoded = decode_public_intent(wire).map_err(|_| refused())?;
        let claim = CapturedAppGroupInputs::capture_observation_child_claim()?;
        Self::spawn(
            claim,
            SavedProviderIntent {
                generation: decoded.generation,
                policy: decoded.policy,
            },
        )
    }

    pub(crate) fn wait_ready(&self, budget: Duration) -> io::Result<()> {
        if budget > MAX_READY {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        match self.ready.recv_timeout(budget) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => Err(io::ErrorKind::TimedOut.into()),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }

    pub(crate) fn stop_and_join(&mut self, budget: Duration) -> io::Result<()> {
        self.supervisor.stop_and_join(budget)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_client::{
        protected_identity_store::ProtectedIdentityStore,
        protected_online_expectation::ProtectedOnlineExpectation,
    };
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        sync::atomic::AtomicU64,
        thread,
        time::Instant,
    };

    static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn child_observer_refuses_malformed_wire_and_unsigned_role_before_store() {
        // The test process has no approved ObserveChild signature. The first
        // call must fail in the bounded codec, the second at role capture;
        // neither can create the Store worker or open a network connection.
        assert!(StoreScopedObservationOwner::spawn_child_from_public_wire(b"bad").is_err());
        let policy = crate::policy::FullWide::new(
            "192.0.2.1".parse().unwrap(),
            vec!["198.51.100.53".parse().unwrap()],
            1280,
        )
        .unwrap();
        let wire = crate::intent_wire::encode_public_intent("generation-1", &policy).unwrap();
        assert!(StoreScopedObservationOwner::spawn_child_from_public_wire(&wire).is_err());
    }

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "aegis-ne-observed-owner-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                FIXTURE_ID.fetch_add(1, Ordering::Relaxed)
            ));
            let identity = root.join("identity");
            fs::create_dir_all(&identity).unwrap();
            fs::set_permissions(&identity, fs::Permissions::from_mode(0o700)).unwrap();
            for (name, bytes) in [(".lock", b"".as_slice()), ("identity.json", b"fixture")] {
                let path = identity.join(name);
                fs::write(&path, bytes).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            Self(identity)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(self.0.parent().unwrap());
        }
    }

    #[test]
    fn descriptor_claim_is_send_to_owned_runtime() {
        fn assert_send<T: Send>() {}
        assert_send::<CapturedAppGroupInputs>();
        assert_send::<SavedProviderIntent>();
    }

    #[test]
    fn owner_timeout_and_drop_keep_store_until_pending_runtime_returns() {
        let fixture = Fixture::new();
        let store =
            ProtectedOnlineExpectation::open_existing(fixture.path(), &"b".repeat(64)).unwrap();
        let (release, wait) = mpsc::channel();
        let mut owner =
            StoreScopedObservationOwner::from_worker(store, move |_claim, _stop, mut ready| {
                let runtime = Builder::new_current_thread().enable_all().build()?;
                report(&mut ready, Ok(()));
                // Controlled unresponsive observation: the controller must not
                // drop its Store when its bounded stop budget expires.
                runtime.block_on(async { wait.recv().map_err(|_| io::ErrorKind::BrokenPipe) })?;
                drop(runtime);
                Ok(())
            })
            .unwrap();
        owner.wait_ready(Duration::from_secs(1)).unwrap();
        assert!(ProtectedIdentityStore::open_existing(fixture.path()).is_err());
        assert_eq!(
            owner.stop_and_join(Duration::ZERO).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        drop(owner);
        assert!(ProtectedIdentityStore::open_existing(fixture.path()).is_err());
        release.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match ProtectedIdentityStore::open_existing(fixture.path()) {
                Ok(reopened) => {
                    drop(reopened);
                    break;
                }
                Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(2)),
                Err(error) => panic!("observation Store did not reopen after worker: {error}"),
            }
        }
    }

    #[test]
    fn owner_stop_joins_runtime_before_store_reopens() {
        let fixture = Fixture::new();
        let store =
            ProtectedOnlineExpectation::open_existing(fixture.path(), &"c".repeat(64)).unwrap();
        let mut owner =
            StoreScopedObservationOwner::from_worker(store, move |_claim, stop, mut ready| {
                let runtime = Builder::new_current_thread().enable_all().build()?;
                report(&mut ready, Ok(()));
                runtime.block_on(wait_stop(&stop));
                drop(runtime);
                Ok(())
            })
            .unwrap();
        owner.wait_ready(Duration::from_secs(1)).unwrap();
        assert!(ProtectedIdentityStore::open_existing(fixture.path()).is_err());
        owner.stop_and_join(Duration::from_secs(2)).unwrap();
        ProtectedIdentityStore::open_existing(fixture.path()).unwrap();
    }
}
