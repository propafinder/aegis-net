//! Ownership and bounded cleanup for server background tasks.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use tokio::task::{JoinHandle, JoinSet};

pub(crate) struct OwnedTask<T>(pub(crate) JoinHandle<T>);

impl<T> Drop for OwnedTask<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) fn shutdown_signal() -> std::io::Result<impl Future<Output = ()>> {
    // Register SIGTERM before binding/announcing readiness. The default
    // systemd stop signal must enter the same drain path as interactive Ctrl-C.
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    Ok(async move {
        #[cfg(unix)]
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
    })
}

/// Return false after the grace period and cancel/join every remaining task.
pub(crate) async fn drain_tasks(
    tasks: &mut JoinSet<()>,
    grace: Duration,
    operational_log: crate::operational_log::OperationalLogPolicy,
) -> bool {
    let drained = tokio::time::timeout(grace, async {
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result {
                crate::operational_log::warn_join_failure(
                    operational_log,
                    "server_session_task_failed",
                    &error,
                    "server session task ended abnormally while draining",
                );
            }
        }
    })
    .await
    .is_ok();
    if !drained {
        tasks.shutdown().await;
    }
    drained
}

#[derive(Debug)]
struct SharedTaskState {
    closed: bool,
    tasks: JoinSet<()>,
    operational_log: crate::operational_log::OperationalLogPolicy,
}

/// Cancellation-safe join authority shared with a longer-lived outer owner.
/// No mutex guard is held across await, and join handles stay in the shared set.
#[derive(Clone, Debug)]
pub(crate) struct SharedTaskGroup(Arc<Mutex<SharedTaskState>>);

impl SharedTaskGroup {
    pub(crate) fn new(operational_log: crate::operational_log::OperationalLogPolicy) -> Self {
        Self(Arc::new(Mutex::new(SharedTaskState {
            closed: false,
            tasks: JoinSet::new(),
            operational_log,
        })))
    }

    pub(crate) fn spawn(&self, future: impl Future<Output = ()> + Send + 'static) {
        let mut state = self.0.lock().unwrap_or_else(|err| err.into_inner());
        if state.closed {
            drop(state);
            return;
        }
        while let Some(result) = state.tasks.try_join_next() {
            if let Err(error) = result {
                crate::operational_log::warn_join_failure(
                    state.operational_log,
                    "owned_async_task_failed",
                    &error,
                    "owned async task ended abnormally",
                );
            }
        }
        state.tasks.spawn(future);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .tasks
            .is_empty()
    }

    pub(crate) async fn join_next(&self) -> Option<Result<(), tokio::task::JoinError>> {
        std::future::poll_fn(|cx| {
            self.0
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .tasks
                .poll_join_next(cx)
        })
        .await
    }

    pub(crate) async fn drain(&self, grace: Duration) -> bool {
        if tokio::time::timeout(grace, async { while self.join_next().await.is_some() {} })
            .await
            .is_ok()
        {
            return true;
        }
        self.shutdown().await;
        false
    }

    pub(crate) fn abort_all(&self) {
        let mut state = self.0.lock().unwrap_or_else(|err| err.into_inner());
        state.closed = true;
        state.tasks.abort_all();
    }

    pub(crate) async fn shutdown(&self) {
        self.abort_all();
        while self.join_next().await.is_some() {}
    }

    fn reap_closed(&self, budget: usize) -> bool {
        let mut state = self.0.lock().unwrap_or_else(|err| err.into_inner());
        for _ in 0..budget {
            if state.tasks.try_join_next().is_none() {
                break;
            }
        }
        state.closed && state.tasks.is_empty()
    }
}

const GROUP_PRUNE_BUDGET: usize = 32;

struct GroupRegistryState {
    closed: bool,
    groups: VecDeque<SharedTaskGroup>,
    operational_log: crate::operational_log::OperationalLogPolicy,
}

impl GroupRegistryState {
    fn prune(&mut self) {
        for _ in 0..self.groups.len().min(GROUP_PRUNE_BUDGET) {
            let group = self.groups.pop_front().expect("bounded registry iteration");
            if !group.reap_closed(GROUP_PRUNE_BUDGET) {
                self.groups.push_back(group);
            }
        }
    }
}

/// Clonable registration handle; only the separate owner shuts down all groups.
#[derive(Clone)]
pub(crate) struct TaskGroupRegistry(Arc<Mutex<GroupRegistryState>>);

impl TaskGroupRegistry {
    pub(crate) fn register(&self) -> RegisteredTaskGroup {
        let tasks = SharedTaskGroup::new(
            self.0
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .operational_log,
        );
        let mut state = self.0.lock().unwrap_or_else(|err| err.into_inner());
        state.prune();
        if state.closed {
            tasks.abort_all();
        } else {
            state.groups.push_back(tasks.clone());
        }
        RegisteredTaskGroup {
            tasks,
            registry: Arc::downgrade(&self.0),
        }
    }
}

/// One connection's request subset. Drop cancels only this subset; the server
/// registry retains join authority until every cancelled child is destroyed.
pub(crate) struct RegisteredTaskGroup {
    tasks: SharedTaskGroup,
    registry: Weak<Mutex<GroupRegistryState>>,
}

impl RegisteredTaskGroup {
    fn prune(&self) {
        if let Some(registry) = self.registry.upgrade() {
            registry
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .prune();
        }
    }

    pub(crate) fn spawn(&self, future: impl Future<Output = ()> + Send + 'static) {
        self.prune();
        self.tasks.spawn(future);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    pub(crate) async fn join_next(&self) -> Option<Result<(), tokio::task::JoinError>> {
        self.tasks.join_next().await
    }

    pub(crate) async fn shutdown(&self) {
        self.tasks.shutdown().await;
    }
}

impl Drop for RegisteredTaskGroup {
    fn drop(&mut self) {
        self.tasks.abort_all();
        self.prune();
    }
}

pub(crate) struct TaskGroupRegistryOwner {
    registry: TaskGroupRegistry,
}

impl TaskGroupRegistryOwner {
    pub(crate) fn new(operational_log: crate::operational_log::OperationalLogPolicy) -> Self {
        Self {
            registry: TaskGroupRegistry(Arc::new(Mutex::new(GroupRegistryState {
                closed: false,
                groups: VecDeque::new(),
                operational_log,
            }))),
        }
    }

    pub(crate) fn registry(&self) -> TaskGroupRegistry {
        self.registry.clone()
    }

    pub(crate) async fn shutdown(&mut self) {
        let groups = {
            let mut state = self
                .registry
                .0
                .lock()
                .unwrap_or_else(|err| err.into_inner());
            state.closed = true;
            for group in &state.groups {
                group.abort_all();
            }
            state.groups.iter().cloned().collect::<Vec<_>>()
        };
        // Keep registry entries until the join completes, so cancellation of
        // this await still leaves Drop with authority to abort every child.
        for group in groups {
            group.shutdown().await;
        }
        self.registry
            .0
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .groups
            .clear();
    }
}

impl Drop for TaskGroupRegistryOwner {
    fn drop(&mut self) {
        let mut state = self
            .registry
            .0
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        state.closed = true;
        for group in &state.groups {
            group.abort_all();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Clone, Default)]
    struct LogCapture(Arc<Mutex<Vec<u8>>>);

    struct LogWriter(Arc<Mutex<Vec<u8>>>);

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapture {
        type Writer = LogWriter;
        fn make_writer(&'a self) -> Self::Writer {
            LogWriter(self.0.clone())
        }
    }

    impl io::Write for LogWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    async fn capture_real_join_failures(
        policy: crate::operational_log::OperationalLogPolicy,
    ) -> (String, bool) {
        let capture = LogCapture::default();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(capture.clone())
            .finish();
        let dispatch = tracing::Dispatch::new(subscriber);
        let _guard = tracing::dispatcher::set_default(&dispatch);

        let mut sessions = JoinSet::new();
        sessions.spawn(async { panic!("synthetic-drain-panic-marker") });
        let drained = drain_tasks(&mut sessions, Duration::from_secs(1), policy).await;

        let group = SharedTaskGroup::new(policy);
        let panicked = Arc::new(AtomicBool::new(false));
        let task_panicked = panicked.clone();
        group.spawn(async move {
            task_panicked.store(true, Ordering::SeqCst);
            panic!("synthetic-reap-panic-marker")
        });
        while !panicked.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
        tokio::task::yield_now().await;
        group.spawn(async {});
        group.shutdown().await;
        let output = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        (output, drained)
    }

    #[tokio::test]
    async fn actual_join_error_emitters_are_private_by_default_and_diagnostic_only_by_opt_in() {
        let (private, drained) = capture_real_join_failures(Default::default()).await;
        assert!(drained);
        assert!(!private.contains("synthetic-drain-panic-marker"));
        assert!(!private.contains("synthetic-reap-panic-marker"));
        assert!(private.contains("server_session_task_failed"));
        assert!(private.contains("owned_async_task_failed"));

        let (diagnostic, drained) =
            capture_real_join_failures(crate::operational_log::OperationalLogPolicy::new(true))
                .await;
        assert!(drained);
        assert!(diagnostic.contains("synthetic-drain-panic-marker"));
        assert!(diagnostic.contains("synthetic-reap-panic-marker"));
    }

    struct TrackedTarget {
        socket: Option<tokio::net::TcpStream>,
        destroyed: Arc<AtomicBool>,
    }

    impl Drop for TrackedTarget {
        fn drop(&mut self) {
            // Publish destruction only after releasing the actual target FD.
            drop(self.socket.take());
            self.destroyed.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn cancelled_connection_target_is_destroyed_before_outer_shutdown_returns() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let socket = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let _peer = listener.accept().await.unwrap();
            let destroyed = Arc::new(AtomicBool::new(false));
            let target = TrackedTarget {
                socket: Some(socket),
                destroyed: destroyed.clone(),
            };
            let mut owner = TaskGroupRegistryOwner::new(Default::default());
            let connection = owner.registry().register();
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            connection.spawn(async move {
                let _target = target;
                started_tx.send(()).unwrap();
                std::future::pending::<()>().await;
            });
            started_rx.await.unwrap();
            // This is the TCP handler's destructor boundary. On this
            // single-thread runtime the child cannot run between these lines.
            drop(connection);
            assert!(
                !destroyed.load(Ordering::SeqCst),
                "abort alone is not destruction"
            );
            owner.shutdown().await;
            assert!(
                destroyed.load(Ordering::SeqCst),
                "FD destroyed before shutdown returns"
            );
            assert!(owner.registry.0.lock().unwrap().groups.is_empty());
        })
        .await
        .expect("bounded strict target ownership regression");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn zero_grace_parent_cancel_joins_target_before_registry_shutdown_returns() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let socket = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let _peer = listener.accept().await.unwrap();
            let destroyed = Arc::new(AtomicBool::new(false));
            let target = TrackedTarget {
                socket: Some(socket),
                destroyed: destroyed.clone(),
            };
            let mut owner = TaskGroupRegistryOwner::new(Default::default());
            let registry = owner.registry();
            let mut parents = JoinSet::new();
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            parents.spawn(async move {
                let connection = registry.register();
                connection.spawn(async move {
                    let _target = target;
                    started_tx.send(()).unwrap();
                    std::future::pending::<()>().await;
                });
                std::future::pending::<()>().await;
                drop(connection);
            });
            started_rx.await.unwrap();
            assert!(!drain_tasks(&mut parents, Duration::ZERO, Default::default()).await);
            owner.shutdown().await;
            assert!(
                destroyed.load(Ordering::SeqCst),
                "cancelled parent's target FD was joined"
            );
        })
        .await
        .expect("bounded multithread zero-grace ownership regression");
    }

    #[tokio::test]
    async fn interrupted_registry_join_retains_children_for_later_shutdown() {
        let mut owner = TaskGroupRegistryOwner::new(Default::default());
        let connection = owner.registry().register();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
        connection.spawn(async move {
            struct SignalOnDrop(Option<tokio::sync::oneshot::Sender<()>>);
            impl Drop for SignalOnDrop {
                fn drop(&mut self) {
                    let _ = self.0.take().unwrap().send(());
                }
            }
            let _signal = SignalOnDrop(Some(dropped_tx));
            started_tx.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        started_rx.await.unwrap();
        let mut shutdown = Box::pin(owner.shutdown());
        assert!(futures::poll!(shutdown.as_mut()).is_pending());
        drop(shutdown);
        assert_eq!(owner.registry.0.lock().unwrap().groups.len(), 1);
        tokio::time::timeout(Duration::from_secs(1), owner.shutdown())
            .await
            .unwrap();
        dropped_rx.await.expect("retained child was joined");
    }

    #[tokio::test]
    async fn registry_prunes_connection_churn_without_forgetting_live_empty_groups() {
        let mut owner = TaskGroupRegistryOwner::new(Default::default());
        let registry = owner.registry();
        let active: Vec<_> = (0..64).map(|_| registry.register()).collect();
        for _ in 0..4096 {
            drop(registry.register());
        }
        assert!(registry.0.lock().unwrap().groups.len() <= active.len() + GROUP_PRUNE_BUDGET);
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel::<()>();
        // This connection was empty throughout pruning but is still live.
        active[0].spawn(async move {
            let _sender = dropped_tx;
            std::future::pending::<()>().await;
        });
        tokio::time::timeout(Duration::from_secs(1), owner.shutdown())
            .await
            .unwrap();
        assert!(
            dropped_rx.await.is_err(),
            "live empty group retained cancellation authority"
        );
        assert!(registry.0.lock().unwrap().groups.is_empty());
    }

    #[tokio::test]
    async fn bounded_drain_cancels_and_joins_stalled_sessions() {
        let mut tasks = JoinSet::new();
        tasks.spawn(std::future::pending::<()>());
        assert!(!drain_tasks(&mut tasks, Duration::ZERO, Default::default()).await);
        assert!(tasks.is_empty());
    }

    #[tokio::test]
    async fn completed_sessions_drain_without_forced_abort() {
        let mut tasks = JoinSet::new();
        tasks.spawn(async {});
        assert!(drain_tasks(&mut tasks, Duration::from_secs(1), Default::default()).await);
        assert!(tasks.is_empty());
    }

    #[tokio::test]
    async fn owned_task_is_cancelled_when_its_owner_is_dropped() {
        let task = OwnedTask(tokio::spawn(std::future::pending::<()>()));
        let aborted = task.0.abort_handle();
        drop(task);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !aborted.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("owned task stopped");
    }
}
