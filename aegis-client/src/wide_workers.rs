//! Required capture workers must acknowledge initialization and remain alive.
//! This supervises the process; persistent firewall protection is a separate
//! prerequisite and must survive the resulting service exit/restart.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

#[derive(Clone)]
pub(crate) struct WorkerFailure {
    name: &'static str,
    tx: mpsc::UnboundedSender<&'static str>,
}

impl WorkerFailure {
    pub(crate) fn report(&self) {
        let _ = self.tx.send(self.name);
    }
}

struct ReportExit(WorkerFailure);

struct CancelStartup(Option<Arc<AtomicBool>>);

impl Drop for CancelStartup {
    fn drop(&mut self) {
        if let Some(stop) = &self.0 {
            stop.store(true, Ordering::SeqCst);
        }
    }
}

impl Drop for ReportExit {
    fn drop(&mut self) {
        self.0.report();
    }
}

pub(crate) struct WorkerReady {
    ready: oneshot::Sender<()>,
    failure: WorkerFailure,
    stop: Arc<AtomicBool>,
}

impl WorkerReady {
    pub(crate) fn failure_signal(&self) -> WorkerFailure {
        self.failure.clone()
    }

    pub(crate) fn signal(self) -> io::Result<()> {
        if self.stop.load(Ordering::SeqCst) || self.ready.send(()).is_err() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "capture startup cancelled",
            ));
        }
        Ok(())
    }
}

pub(crate) struct WideWorkers {
    stops: Vec<Arc<AtomicBool>>,
    // Keep a sender so an empty group waits rather than reporting a false exit.
    failure_tx: mpsc::UnboundedSender<&'static str>,
    failure_rx: mpsc::UnboundedReceiver<&'static str>,
}

impl WideWorkers {
    pub(crate) fn new() -> Self {
        let (failure_tx, failure_rx) = mpsc::unbounded_channel();
        Self {
            stops: Vec::new(),
            failure_tx,
            failure_rx,
        }
    }

    pub(crate) async fn start<F>(
        &mut self,
        name: &'static str,
        timeout: Duration,
        run: F,
    ) -> io::Result<()>
    where
        F: FnOnce(Arc<AtomicBool>, WorkerReady) + Send + 'static,
    {
        let stop = Arc::new(AtomicBool::new(false));
        let mut cancel = CancelStartup(Some(stop.clone()));
        self.stops.push(stop.clone());
        let (ready_tx, ready_rx) = oneshot::channel();
        let failure = WorkerFailure {
            name,
            tx: self.failure_tx.clone(),
        };
        let ready = WorkerReady {
            ready: ready_tx,
            failure: failure.clone(),
            stop: stop.clone(),
        };
        let thread_stop = stop.clone();
        std::thread::Builder::new()
            .name(name.into())
            .spawn(move || {
                // Also notifies on an unwinding panic. Release panic=abort terminates
                // the whole client directly, which likewise cannot look healthy.
                let _exit = ReportExit(failure);
                run(thread_stop, ready);
            })?;
        match tokio::time::timeout(timeout, ready_rx).await {
            Ok(Ok(())) => {
                cancel.0 = None;
                Ok(())
            }
            Ok(Err(_)) => {
                stop.store(true, Ordering::SeqCst);
                Err(io::Error::other(format!(
                    "required capture worker {name} exited before readiness"
                )))
            }
            Err(_) => {
                stop.store(true, Ordering::SeqCst);
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("required capture worker {name} readiness timed out"),
                ))
            }
        }
    }

    pub(crate) async fn failure(&mut self) -> &'static str {
        self.failure_rx
            .recv()
            .await
            .expect("group owns failure sender")
    }

    pub(crate) fn pending_failure(&mut self) -> Option<&'static str> {
        self.failure_rx.try_recv().ok()
    }
}

impl Drop for WideWorkers {
    fn drop(&mut self) {
        for stop in &self.stops {
            stop.store(true, Ordering::SeqCst);
        }
        // Do not block the async runtime joining a worker that may be wedged.
        // The caller terminates the client on failure; systemd owns its cgroup.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_group_does_not_report_success_or_failure() {
        let mut workers = WideWorkers::new();
        assert!(workers.pending_failure().is_none());
        assert!(
            tokio::time::timeout(Duration::from_millis(10), workers.failure())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn initialization_failure_never_acknowledges_readiness() {
        let mut workers = WideWorkers::new();
        assert!(workers
            .start("bad-bind", Duration::from_secs(1), |_, _| {})
            .await
            .is_err());
        assert_eq!(workers.failure().await, "bad-bind");
    }

    #[tokio::test]
    async fn worker_exit_after_ready_wakes_an_idle_supervisor() {
        let mut workers = WideWorkers::new();
        let (release, wait) = std::sync::mpsc::channel();
        workers
            .start("udp", Duration::from_secs(1), move |_, ready| {
                ready.signal().unwrap();
                wait.recv().unwrap();
            })
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), workers.failure())
                .await
                .is_err()
        );
        release.send(()).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), workers.failure())
                .await
                .unwrap(),
            "udp"
        );
    }

    #[tokio::test]
    async fn watchdog_can_report_failure_before_worker_returns() {
        let mut workers = WideWorkers::new();
        let (release, wait) = std::sync::mpsc::channel();
        workers
            .start("tun", Duration::from_secs(1), move |_, ready| {
                let watchdog = ready.failure_signal();
                ready.signal().unwrap();
                watchdog.report();
                wait.recv().unwrap();
            })
            .await
            .unwrap();
        assert_eq!(workers.failure().await, "tun");
        release.send(()).unwrap();
    }

    #[tokio::test]
    async fn completed_worker_is_detected_before_service_notification() {
        let mut workers = WideWorkers::new();
        let (released, observed) = oneshot::channel();
        workers
            .start("already-exited", Duration::from_secs(1), move |_, ready| {
                let failure = ready.failure_signal();
                ready.signal().unwrap();
                failure.report();
                released.send(()).unwrap();
            })
            .await
            .unwrap();
        observed.await.unwrap();
        assert_eq!(workers.pending_failure(), Some("already-exited"));
    }

    #[tokio::test]
    async fn late_readiness_after_timeout_is_refused_and_stop_requested() {
        let mut workers = WideWorkers::new();
        let (release, wait) = std::sync::mpsc::channel();
        let (receipt, observed) = oneshot::channel();
        let error = workers
            .start("slow", Duration::from_millis(10), move |stop, ready| {
                wait.recv().unwrap();
                receipt
                    .send((stop.load(Ordering::SeqCst), ready.signal().is_err()))
                    .unwrap();
            })
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        release.send(()).unwrap();
        assert_eq!(observed.await.unwrap(), (true, true));
    }

    #[tokio::test]
    async fn partial_startup_failure_stops_previously_ready_worker() {
        let mut workers = WideWorkers::new();
        let (receipt, observed) = oneshot::channel();
        workers
            .start("first", Duration::from_secs(1), move |stop, ready| {
                ready.signal().unwrap();
                while !stop.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(1));
                }
                receipt.send(()).unwrap();
            })
            .await
            .unwrap();
        assert!(workers
            .start("second", Duration::from_secs(1), |_, _| {})
            .await
            .is_err());
        drop(workers);
        tokio::time::timeout(Duration::from_secs(1), observed)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn cancelling_start_future_stops_worker_while_group_remains_alive() {
        let mut workers = WideWorkers::new();
        let (started_tx, started_rx) = oneshot::channel();
        let (stopped_tx, stopped_rx) = oneshot::channel();
        let startup = workers.start("cancelled", Duration::from_secs(20), move |stop, _ready| {
            started_tx.send(()).unwrap();
            while !stop.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(1));
            }
            stopped_tx.send(()).unwrap();
        });
        {
            tokio::pin!(startup);
            tokio::select! {
                result = &mut startup => panic!("unexpected completion: {result:?}"),
                _ = started_rx => {}
            }
        }
        tokio::time::timeout(Duration::from_secs(1), stopped_rx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(workers.failure().await, "cancelled");
    }
}
