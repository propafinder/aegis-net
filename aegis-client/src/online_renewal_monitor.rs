//! Owned lifetime for the protected online-issuance monitor. The caller
//! supplies the actual protected-store check and retains credential custody.
//! A monitor is neither an ACK nor a packet-capture permit.

use anyhow::{Context, Result};
use std::time::Duration;
use tokio::{sync::oneshot, task::JoinHandle};

const CHECK_INTERVAL: Duration = Duration::from_secs(5);
const MAX_JOIN_BUDGET: Duration = Duration::from_secs(2);

pub struct OnlineRenewalMonitor {
    failure: oneshot::Receiver<&'static str>,
    task: Option<JoinHandle<()>>,
}

impl OnlineRenewalMonitor {
    /// `check` must re-open protected status and issuance from its owner;
    /// the monitor does not trust a status captured before the sleep.
    pub fn spawn(check: impl Fn() -> Option<&'static str> + Send + 'static) -> Self {
        Self::spawn_with_interval(CHECK_INTERVAL, check)
    }

    fn spawn_with_interval(
        interval: Duration,
        check: impl Fn() -> Option<&'static str> + Send + 'static,
    ) -> Self {
        let (failure_tx, failure) = oneshot::channel();
        let task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                if let Some(reason) = check() {
                    let _ = failure_tx.send(reason);
                    break;
                }
            }
        });
        Self {
            failure,
            task: Some(task),
        }
    }

    pub async fn failure(&mut self) -> &'static str {
        (&mut self.failure)
            .await
            .unwrap_or("online renewal monitor stopped")
    }

    /// Abort and observe this exact task within a bounded window. A panic or
    /// unobserved stop is an error; the handle stays owned after a timeout.
    pub async fn stop_and_join(&mut self) -> Result<()> {
        let Some(mut task) = self.task.take() else {
            return Ok(());
        };
        task.abort();
        match tokio::time::timeout(MAX_JOIN_BUDGET, &mut task).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) if error.is_cancelled() => Ok(()),
            Ok(Err(error)) => Err(error).context("online renewal monitor task failed"),
            Err(_) => {
                self.task = Some(task);
                Err(anyhow::anyhow!("online renewal monitor stop unconfirmed"))
            }
        }
    }
}

impl Drop for OnlineRenewalMonitor {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[tokio::test]
    async fn protected_check_failure_is_reported_and_joined() {
        let checks = Arc::new(AtomicUsize::new(0));
        let observed = checks.clone();
        let mut owner =
            OnlineRenewalMonitor::spawn_with_interval(Duration::from_millis(1), move || {
                observed.fetch_add(1, Ordering::SeqCst);
                Some("protected issuance changed")
            });
        assert_eq!(owner.failure().await, "protected issuance changed");
        owner.stop_and_join().await.unwrap();
        assert_eq!(checks.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn stop_joins_without_another_protected_check() {
        let checks = Arc::new(AtomicUsize::new(0));
        let observed = checks.clone();
        let mut owner =
            OnlineRenewalMonitor::spawn_with_interval(Duration::from_secs(60), move || {
                observed.fetch_add(1, Ordering::SeqCst);
                None
            });
        owner.stop_and_join().await.unwrap();
        assert_eq!(checks.load(Ordering::SeqCst), 0);
        assert_eq!(owner.failure().await, "online renewal monitor stopped");
    }
}
