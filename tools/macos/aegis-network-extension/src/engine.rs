//! Actual owned thread cancellation and join. A factory still owns credential
//! admission; this type does not grant authority to a profile or executable.
use crate::bridge::{EngineOwner, PacketBridge};
use std::{
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
const STOP_BUDGET: Duration = Duration::from_secs(2);
pub struct ThreadEngine {
    stop: Arc<AtomicBool>,
    bridge: PacketBridge,
    worker: Option<JoinHandle<io::Result<()>>>,
    ready: mpsc::Receiver<()>,
    is_ready: bool,
}
impl ThreadEngine {
    // The source-integrated engine closure must use the actual run_ready
    // callback, retain admitted credential/renewal owners, and honor cancellation.
    pub fn spawn(
        bridge: PacketBridge,
        run: impl FnOnce(PacketBridge, Arc<AtomicBool>, mpsc::SyncSender<()>) -> io::Result<()>
            + Send
            + 'static,
    ) -> io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let port = bridge.clone();
        let (tx, rx) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("aegis-ne-engine".into())
            .spawn(move || run(port, flag, tx))?;
        Ok(Self {
            stop,
            bridge,
            worker: Some(worker),
            ready: rx,
            is_ready: false,
        })
    }
    pub fn wait_constructed(&mut self, budget: Duration) -> io::Result<()> {
        if budget > Duration::from_secs(2) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // A worker that returned or unwound before its ready callback dropped
        // the sender: that is a terminal failure, never a timeout to retry.
        self.ready
            .recv_timeout(budget)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => io::ErrorKind::TimedOut,
                mpsc::RecvTimeoutError::Disconnected => io::ErrorKind::BrokenPipe,
            })?;
        if self.worker.as_ref().is_none_or(|w| w.is_finished()) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        self.is_ready = true;
        Ok(())
    }
    pub fn constructed(&self) -> bool {
        self.is_ready && self.worker.as_ref().is_some_and(|w| !w.is_finished())
    }
    pub fn joined(&self) -> bool {
        self.worker.is_none()
    }
    pub fn cancel(&self) {
        self.bridge.stop();
        self.stop.store(true, Ordering::Release);
    }
    pub fn try_join(&mut self, budget: Duration) -> io::Result<()> {
        self.cancel();
        if budget > STOP_BUDGET {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let deadline = Instant::now() + budget;
        while self.worker.as_ref().is_some_and(|w| !w.is_finished()) {
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            thread::sleep(
                Duration::from_millis(2).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        self.is_ready = false;
        worker
            .join()
            .map_err(|_| io::Error::other("owned engine panicked"))?
    }
}
impl EngineOwner for ThreadEngine {
    fn constructed(&self) -> bool {
        self.is_ready && self.worker.as_ref().is_some_and(|w| !w.is_finished())
    }
    fn stop_and_observe_terminal(&mut self) -> io::Result<()> {
        self.try_join(STOP_BUDGET)
    }
    fn terminal(&self) -> bool {
        self.worker.as_ref().is_none_or(|w| w.is_finished())
    }
}
impl Drop for ThreadEngine {
    fn drop(&mut self) {
        self.cancel();
        // Never join an unfinished thread in Drop or pretend it stopped. A
        // provider retains this object after timeout; disposal is not recovery.
        if self.worker.as_ref().is_some_and(|w| w.is_finished()) {
            if let Some(w) = self.worker.take() {
                let _ = w.join();
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancelled_owned_thread_is_joined() {
        let mut e = ThreadEngine::spawn(PacketBridge::default(), |_, stop, ready| {
            ready.send(()).unwrap();
            while !stop.load(Ordering::Acquire) {
                thread::sleep(Duration::from_millis(1));
            }
            Ok(())
        })
        .unwrap();
        e.wait_constructed(Duration::from_secs(1)).unwrap();
        e.try_join(Duration::from_secs(1)).unwrap();
        assert!(e.worker.is_none());
    }
    #[test]
    fn worker_gone_before_ready_is_broken_pipe_not_timeout() {
        let mut e = ThreadEngine::spawn(PacketBridge::default(), |_, _, _ready| Ok(())).unwrap();
        while e.worker.as_ref().is_some_and(|w| !w.is_finished()) {
            thread::sleep(Duration::from_millis(1));
        }
        let started = Instant::now();
        assert_eq!(
            e.wait_constructed(Duration::from_secs(2))
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        // Returned on the disconnect, not on the 2 s budget.
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(!e.constructed());
        e.try_join(Duration::from_secs(1)).unwrap();
    }
    #[test]
    fn timeout_retains_original_join_owner() {
        let (release, wait) = mpsc::channel();
        let mut e = ThreadEngine::spawn(PacketBridge::default(), move |_, _, ready| {
            ready.send(()).unwrap();
            wait.recv().unwrap();
            Ok(())
        })
        .unwrap();
        e.wait_constructed(Duration::from_secs(1)).unwrap();
        assert_eq!(
            e.try_join(Duration::ZERO).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(e.worker.is_some());
        release.send(()).unwrap();
        e.try_join(Duration::from_secs(1)).unwrap();
    }
}
