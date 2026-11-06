//! Ordered pre/post protected-identity checks around one caller-owned relay
//! ACK future. The caller must supply the real protected Store read and the
//! authenticated targetless relay exchange. Closures can be fabricated, so
//! this helper itself grants no capture, relay or device authority.

use crate::{observed_policy_ack::ObservedPolicyAck, online_expectation::OnlineExpectation};
use anyhow::Result;
use std::future::Future;
use tokio::time::Instant;

#[derive(Debug)]
pub enum ObservationFailure {
    BeforeRead(anyhow::Error),
    BeforeChanged(anyhow::Error),
    Ack(anyhow::Error),
    After(anyhow::Error),
    AfterChanged(anyhow::Error),
}

/// Retain an ACK only if the same protected issuance was current before and
/// after the awaited exchange. local failures must stop admission; only an
/// `Ack` transport/authentication failure can be retried by the caller.
pub async fn observe_policy_ack<Read, Ack, Fut>(
    expected: &OnlineExpectation,
    mut read_current: Read,
    mut authenticated_ack: Ack,
) -> std::result::Result<ObservedPolicyAck, ObservationFailure>
where
    Read: FnMut() -> Result<OnlineExpectation>,
    Ack: FnMut(OnlineExpectation) -> Fut,
    Fut: Future<Output = Result<Instant>>,
{
    let before = read_current().map_err(ObservationFailure::BeforeRead)?;
    expected
        .ensure_same_issuance(&before)
        .map_err(ObservationFailure::BeforeChanged)?;
    let deadline = authenticated_ack(before.clone())
        .await
        .map_err(ObservationFailure::Ack)?;
    let after = read_current().map_err(ObservationFailure::After)?;
    before
        .ensure_same_issuance(&after)
        .map_err(ObservationFailure::AfterChanged)?;
    let observed = ObservedPolicyAck::retain_observed(after.binding(), deadline)
        .map_err(ObservationFailure::After)?;
    observed
        .ensure_current(expected.binding())
        .map_err(ObservationFailure::After)?;
    Ok(observed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, time::Duration};

    fn expected() -> OnlineExpectation {
        OnlineExpectation {
            certificate_sha256: "certificate".into(),
            not_after_unix_secs: 100,
            issued_generation: Some(7),
            snapshot_sha256: Some("snapshot".into()),
        }
    }

    #[tokio::test]
    async fn stable_protected_issuance_and_live_ack_are_retained() {
        let expected = expected();
        let calls = Cell::new(0);
        let deadline = Instant::now() + Duration::from_secs(1);
        let observed = observe_policy_ack(
            &expected,
            || {
                calls.set(calls.get() + 1);
                Ok(expected.clone())
            },
            |_| async { Ok(deadline) },
        )
        .await;
        assert!(observed.is_ok());
        assert_eq!(calls.get(), 2);
        observed
            .unwrap()
            .ensure_current(expected.binding())
            .unwrap();
    }

    #[tokio::test]
    async fn changed_pre_ack_issuance_never_calls_relay() {
        let expected = expected();
        let attempted = Cell::new(false);
        let result = observe_policy_ack(
            &expected,
            || {
                let mut current = expected.clone();
                current.snapshot_sha256 = Some("changed".into());
                Ok(current)
            },
            |_| {
                attempted.set(true);
                async { Ok(Instant::now() + Duration::from_secs(1)) }
            },
        )
        .await;
        assert!(matches!(result, Err(ObservationFailure::BeforeChanged(_))));
        assert!(!attempted.get());
    }

    #[tokio::test]
    async fn changed_post_ack_issuance_refuses_retention() {
        let expected = expected();
        let calls = Cell::new(0);
        let result = observe_policy_ack(
            &expected,
            || {
                calls.set(calls.get() + 1);
                let mut current = expected.clone();
                if calls.get() == 2 {
                    current.issued_generation = Some(8);
                }
                Ok(current)
            },
            |_| async { Ok(Instant::now() + Duration::from_secs(1)) },
        )
        .await;
        assert!(matches!(result, Err(ObservationFailure::AfterChanged(_))));
        assert_eq!(calls.get(), 2);
    }

    #[tokio::test]
    async fn expired_ack_and_transport_failure_remain_distinct() {
        let expected = expected();
        let expired = observe_policy_ack(
            &expected,
            || Ok(expected.clone()),
            |_| async { Ok(Instant::now()) },
        )
        .await;
        assert!(matches!(expired, Err(ObservationFailure::After(_))));
        let transport = observe_policy_ack(
            &expected,
            || Ok(expected.clone()),
            |_| async {
                anyhow::bail!("inert relay error");
            },
        )
        .await;
        assert!(matches!(transport, Err(ObservationFailure::Ack(_))));
    }
}
