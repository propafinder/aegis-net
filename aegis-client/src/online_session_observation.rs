//! Owns the retained live-ACK observation and protected-identity monitor.
//! The caller still owns authenticated transport, identity validation and
//! renewal. This object is not an admission token or packet-capture permit.

use crate::{
    issuance_binding::IssuanceBinding, observed_policy_ack::ObservedPolicyAck,
    online_renewal_monitor::OnlineRenewalMonitor,
};
use anyhow::{Context, Result};
use std::sync::{Arc, Mutex};
use tokio::time::Instant;

type ProtectedCheck = Arc<dyn Fn() -> Option<&'static str> + Send + Sync>;

pub struct OnlineSessionObservation {
    acknowledgement: Mutex<ObservedPolicyAck>,
    protected_check: ProtectedCheck,
    monitor: OnlineRenewalMonitor,
}

impl OnlineSessionObservation {
    /// The callback must re-open protected status and issuance each time. It
    /// is used both before synchronous readiness and by the periodic monitor.
    /// Supplying a callback is not proof that it performs those checks.
    pub fn new(
        acknowledgement: ObservedPolicyAck,
        check: impl Fn() -> Option<&'static str> + Send + Sync + 'static,
    ) -> Self {
        let protected_check: ProtectedCheck = Arc::new(check);
        let monitor_check = protected_check.clone();
        let monitor = OnlineRenewalMonitor::spawn(move || monitor_check());
        Self {
            acknowledgement: Mutex::new(acknowledgement),
            protected_check,
            monitor,
        }
    }

    fn check_protected(&self) -> Result<()> {
        if let Some(reason) = (self.protected_check)() {
            anyhow::bail!(reason);
        }
        Ok(())
    }

    /// `next` must follow a fresh authenticated ACK and protected-store check
    /// performed by the caller. A wait on this mutex may outlive its deadline.
    pub fn replace_observed(
        &self,
        next: ObservedPolicyAck,
        expected: IssuanceBinding<'_>,
    ) -> Result<()> {
        let mut retained = self
            .acknowledgement
            .lock()
            .map_err(|_| anyhow::anyhow!("online acknowledgement owner failed"))?;
        self.check_protected()?;
        next.ensure_current(expected)?;
        *retained = next;
        Ok(())
    }

    /// Re-run the caller's protected-store check before each readiness check.
    pub fn ensure_current(&self, current: IssuanceBinding<'_>) -> Result<()> {
        self.check_protected()?;
        self.acknowledgement
            .lock()
            .map_err(|_| anyhow::anyhow!("online acknowledgement owner failed"))?
            .ensure_current(current)
    }

    pub fn valid_until_checked(&self, current: IssuanceBinding<'_>) -> Result<Instant> {
        self.check_protected()?;
        let retained = self
            .acknowledgement
            .lock()
            .map_err(|_| anyhow::anyhow!("retained ACK lock failed"))?;
        retained.ensure_current(current)?;
        Ok(retained.valid_until())
    }

    pub async fn failure(&mut self) -> &'static str {
        self.monitor.failure().await
    }

    pub async fn stop_and_join(&mut self) -> Result<()> {
        self.monitor
            .stop_and_join()
            .await
            .context("online session monitor stop unconfirmed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    fn issuance<'a>(certificate: &'a str, generation: u64) -> IssuanceBinding<'a> {
        IssuanceBinding {
            certificate_sha256: certificate,
            not_after_unix_secs: 100,
            issued_generation: Some(generation),
            snapshot_sha256: Some("snapshot"),
        }
    }

    #[tokio::test]
    async fn replacement_refuses_changed_issuance_and_preserves_original() {
        let deadline = Instant::now() + Duration::from_secs(3600);
        let first = ObservedPolicyAck::retain_observed(issuance("cert", 7), deadline).unwrap();
        let mut owner = OnlineSessionObservation::new(first, || None);
        let changed = ObservedPolicyAck::retain_observed(issuance("cert", 8), deadline).unwrap();
        assert!(owner
            .replace_observed(changed, issuance("cert", 7))
            .is_err());
        assert!(owner.ensure_current(issuance("cert", 7)).is_ok());
        assert!(owner.ensure_current(issuance("cert", 8)).is_err());
        owner.stop_and_join().await.unwrap();
    }

    #[tokio::test]
    async fn replacement_accepts_same_issuance_and_owns_monitor_join() {
        let first_deadline = Instant::now() + Duration::from_secs(3600);
        let first =
            ObservedPolicyAck::retain_observed(issuance("cert", 7), first_deadline).unwrap();
        let mut owner = OnlineSessionObservation::new(first, || None);
        let next_deadline = first_deadline + Duration::from_secs(1);
        let next = ObservedPolicyAck::retain_observed(issuance("cert", 7), next_deadline).unwrap();
        owner.replace_observed(next, issuance("cert", 7)).unwrap();
        assert_eq!(
            owner.valid_until_checked(issuance("cert", 7)).unwrap(),
            next_deadline
        );
        owner.stop_and_join().await.unwrap();
        assert_eq!(owner.failure().await, "online renewal monitor stopped");
    }

    #[tokio::test]
    async fn changed_protected_status_blocks_readiness_and_replacement() {
        let allowed = Arc::new(AtomicBool::new(true));
        let observed = allowed.clone();
        let deadline = Instant::now() + Duration::from_secs(3600);
        let first = ObservedPolicyAck::retain_observed(issuance("cert", 7), deadline).unwrap();
        let mut owner = OnlineSessionObservation::new(first, move || {
            (!observed.load(Ordering::Acquire)).then_some("protected issuance changed")
        });
        assert!(owner.ensure_current(issuance("cert", 7)).is_ok());
        allowed.store(false, Ordering::Release);
        assert!(owner.ensure_current(issuance("cert", 7)).is_err());
        let next = ObservedPolicyAck::retain_observed(issuance("cert", 7), deadline).unwrap();
        assert!(owner.replace_observed(next, issuance("cert", 7)).is_err());
        assert!(owner.valid_until_checked(issuance("cert", 7)).is_err());
        owner.stop_and_join().await.unwrap();
    }
}
