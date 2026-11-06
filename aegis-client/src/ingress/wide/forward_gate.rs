//! One-shot pre-forward authority for explicitly controlled Linux workers.
//! Closed workers discard input; revocation cannot be undone by a later opener.
use std::future::Future;
use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc,
};
use tokio::sync::watch;

#[derive(Clone, Debug)]
pub(crate) struct ForwardGate {
    state: Arc<AtomicU8>,
    changed: watch::Sender<()>,
}

/// The activation scope retains this owner; unwinding or any early return revokes.
#[derive(Debug)]
pub(crate) struct ForwardGateOwner(ForwardGate);
impl ForwardGateOwner {
    pub(crate) fn closed() -> Self {
        Self(ForwardGate::closed())
    }
    pub(crate) fn gate(&self) -> ForwardGate {
        self.0.clone()
    }
}
impl Drop for ForwardGateOwner {
    fn drop(&mut self) {
        self.0.revoke();
    }
}

impl ForwardGate {
    pub(crate) fn closed() -> Self {
        let (changed, _) = watch::channel(());
        Self {
            state: Arc::new(AtomicU8::new(0)),
            changed,
        }
    }

    pub(crate) fn open(&self) -> bool {
        if self
            .state
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return false;
        }
        self.changed.send_replace(());
        true
    }

    pub(crate) fn revoke(&self) {
        self.state.store(2, Ordering::SeqCst);
        self.changed.send_replace(());
    }

    pub(crate) fn is_open(&self) -> bool {
        self.state.load(Ordering::SeqCst) == 1
    }

    /// Refuse admission after revocation; an already executing synchronous step
    /// may finish. Worker teardown is separately owned by the caller.
    pub(crate) fn with_open<T>(&self, action: impl FnOnce() -> T) -> Option<T> {
        self.is_open().then(action)
    }

    /// Refuse initial polling while closed and cancel pending owned I/O on revoke.
    /// An already executing poll may finish; this is not syscall-atomic teardown.
    pub(crate) async fn run<F: Future>(&self, future: F) -> Option<F::Output> {
        let mut changed = self.changed.subscribe();
        tokio::pin!(future);
        if !self.is_open() {
            return None;
        }
        loop {
            tokio::select! {
                biased;
                _ = changed.changed() => {
                    if !self.is_open() { return None; }
                }
                output = &mut future => return self.is_open().then_some(output),
            }
        }
    }
}

pub(crate) async fn run_optional<F: Future>(
    gate: Option<&ForwardGate>,
    future: F,
) -> Option<F::Output> {
    match gate {
        Some(gate) => gate.run(future).await,
        None => Some(future.await),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn reentrant_revocation_during_future_poll_does_not_deadlock() {
        let owner = ForwardGateOwner::closed();
        let gate = owner.gate();
        assert!(gate.open());
        let revoke = gate.clone();
        assert!(gate
            .run(async move {
                revoke.revoke();
            })
            .await
            .is_none());
        assert!(!gate.open());
    }
    #[tokio::test]
    async fn activation_scope_drop_cancels_pending_future() {
        let owner = ForwardGateOwner::closed();
        let gate = owner.gate();
        assert!(gate.open());
        let child = gate.clone();
        let task = tokio::spawn(async move { child.run(std::future::pending::<()>()).await });
        tokio::task::yield_now().await;
        drop(owner);
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap()
                .is_none()
        );
        assert!(!gate.is_open());
    }
    #[tokio::test]
    async fn closed_and_revoked_gate_never_polls_network_work() {
        let gate = ForwardGate::closed();
        for _ in 0..2 {
            assert!(gate
                .run(async { panic!("network future polled without authority") })
                .await
                .is_none());
            gate.revoke();
        }
        assert!(!gate.open());
    }
    #[tokio::test]
    async fn revocation_drops_pending_owned_flow_and_refuses_successor() {
        struct Owner(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Owner {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let gate = ForwardGate::closed();
        assert!(gate.open());
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let owner = Owner(dropped.clone());
        let child_gate = gate.clone();
        let task = tokio::spawn(async move {
            child_gate
                .run(async move {
                    let _owner = owner;
                    std::future::pending::<()>().await
                })
                .await
        });
        tokio::task::yield_now().await;
        gate.revoke();
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap()
                .is_none()
        );
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
        assert!(!gate.open());
    }
}
