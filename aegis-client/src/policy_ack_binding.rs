//! Bind an ACK observed inside the existing authenticated relay channel to
//! the locally validated issuance. This validator does not open a channel or
//! grant a capture lease; callers retain transport and identity custody.

use crate::issuance_binding::IssuanceBinding;
use aegis_core::secure_channel::policy_ack::RuntimePolicyAck;
use anyhow::{ensure, Result};
use std::time::Duration;

pub fn verify_observed_ack(
    ack: &RuntimePolicyAck,
    nonce: &str,
    expected: IssuanceBinding<'_>,
    now_unix_secs: u64,
    elapsed: Duration,
) -> Result<Duration> {
    ensure!(
        expected.issued_generation.is_some() == expected.snapshot_sha256.is_some(),
        "incomplete local issuance expectation"
    );
    let minimum = expected.issued_generation.zip(expected.snapshot_sha256);
    ack.verify(
        nonce,
        expected.certificate_sha256,
        minimum,
        now_unix_secs,
        elapsed,
    )?;
    ensure!(
        ack.certificate_not_after_unix_secs == expected.not_after_unix_secs,
        "runtime policy acknowledgement expired or certificate lifetime differs"
    );
    Ok(Duration::from_millis(ack.effective_valid_for_ms))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CERT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const SNAPSHOT: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn expected() -> IssuanceBinding<'static> {
        IssuanceBinding {
            certificate_sha256: CERT,
            not_after_unix_secs: 200,
            issued_generation: Some(7),
            snapshot_sha256: Some(SNAPSHOT),
        }
    }

    fn ack() -> RuntimePolicyAck {
        RuntimePolicyAck {
            version: 1,
            nonce: NONCE.into(),
            generation: 7,
            snapshot_sha256: SNAPSHOT.into(),
            certificate_sha256: CERT.into(),
            policy_not_after_unix_secs: 300,
            certificate_not_after_unix_secs: 200,
            effective_valid_for_ms: 3000,
        }
    }

    #[test]
    fn exact_issuance_and_unexpired_nonce_return_original_deadline_duration() {
        assert_eq!(
            verify_observed_ack(&ack(), NONCE, expected(), 100, Duration::from_millis(10)).unwrap(),
            Duration::from_millis(3000)
        );
    }

    #[test]
    fn incomplete_or_changed_issuance_and_replay_refuse() {
        let mut incomplete = expected();
        incomplete.snapshot_sha256 = None;
        assert!(verify_observed_ack(&ack(), NONCE, incomplete, 100, Duration::ZERO).is_err());
        let mut changed = ack();
        changed.certificate_not_after_unix_secs = 201;
        assert!(verify_observed_ack(&changed, NONCE, expected(), 100, Duration::ZERO).is_err());
        changed = ack();
        changed.snapshot_sha256 =
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into();
        assert!(verify_observed_ack(&changed, NONCE, expected(), 100, Duration::ZERO).is_err());
        assert!(verify_observed_ack(&ack(), CERT, expected(), 100, Duration::ZERO).is_err());
        assert!(
            verify_observed_ack(&ack(), NONCE, expected(), 100, Duration::from_secs(3)).is_err()
        );
    }
}
