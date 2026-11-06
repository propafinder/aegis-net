//! Retain the exact issuance and deadline returned by an observed policy ACK.
//! The caller still owns the authenticated transport, protected identity store,
//! renewal monitor and capture lease. This value alone grants no capture.

use crate::issuance_binding::{same_issuance, IssuanceBinding};
use anyhow::{ensure, Result};
use tokio::time::Instant;

struct OwnedIssuance {
    certificate_sha256: String,
    not_after_unix_secs: u64,
    issued_generation: Option<u64>,
    snapshot_sha256: Option<String>,
}

impl OwnedIssuance {
    fn from_binding(binding: IssuanceBinding<'_>) -> Self {
        Self {
            certificate_sha256: binding.certificate_sha256.to_owned(),
            not_after_unix_secs: binding.not_after_unix_secs,
            issued_generation: binding.issued_generation,
            snapshot_sha256: binding.snapshot_sha256.map(str::to_owned),
        }
    }

    fn binding(&self) -> IssuanceBinding<'_> {
        IssuanceBinding {
            certificate_sha256: &self.certificate_sha256,
            not_after_unix_secs: self.not_after_unix_secs,
            issued_generation: self.issued_generation,
            snapshot_sha256: self.snapshot_sha256.as_deref(),
        }
    }
}

/// A retained observation, not an admission token. Only a caller that has
/// already verified a live targetless ACK on its authenticated stream may
/// supply the deadline. Every readiness use must also re-open protected
/// identity state and compare its current issuance against this observation.
pub struct ObservedPolicyAck {
    issuance: OwnedIssuance,
    valid_until: Instant,
}

impl ObservedPolicyAck {
    pub fn retain_observed(issuance: IssuanceBinding<'_>, valid_until: Instant) -> Result<Self> {
        Self::retain_observed_at(issuance, valid_until, Instant::now())
    }

    fn retain_observed_at(
        issuance: IssuanceBinding<'_>,
        valid_until: Instant,
        now: Instant,
    ) -> Result<Self> {
        ensure!(
            issuance.issued_generation.is_some() == issuance.snapshot_sha256.is_some(),
            "incomplete local issuance expectation"
        );
        ensure!(
            now < valid_until,
            "policy acknowledgement expired before readiness"
        );
        Ok(Self {
            issuance: OwnedIssuance::from_binding(issuance),
            valid_until,
        })
    }

    pub fn ensure_current(&self, current: IssuanceBinding<'_>) -> Result<()> {
        self.ensure_current_at(current, Instant::now())
    }

    fn ensure_current_at(&self, current: IssuanceBinding<'_>, now: Instant) -> Result<()> {
        ensure!(
            same_issuance(self.issuance.binding(), current),
            "online issuance changed; authenticated restart required"
        );
        ensure!(
            now < self.valid_until,
            "policy acknowledgement expired before readiness"
        );
        Ok(())
    }

    pub fn valid_until(&self) -> Instant {
        self.valid_until
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn issuance<'a>(
        certificate: &'a str,
        generation: Option<u64>,
        snapshot: Option<&'a str>,
    ) -> IssuanceBinding<'a> {
        IssuanceBinding {
            certificate_sha256: certificate,
            not_after_unix_secs: 100,
            issued_generation: generation,
            snapshot_sha256: snapshot,
        }
    }

    #[test]
    fn retained_observation_requires_live_deadline_and_complete_floor() {
        let now = Instant::now();
        assert!(ObservedPolicyAck::retain_observed_at(
            issuance("cert", Some(7), Some("snapshot")),
            now,
            now
        )
        .is_err());
        assert!(ObservedPolicyAck::retain_observed_at(
            issuance("cert", Some(7), None),
            now + Duration::from_secs(1),
            now
        )
        .is_err());
        assert!(ObservedPolicyAck::retain_observed_at(
            issuance("cert", None, Some("snapshot")),
            now + Duration::from_secs(1),
            now
        )
        .is_err());
    }

    #[test]
    fn retained_observation_seals_on_deadline_and_every_issuance_field() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(1);
        let ack = ObservedPolicyAck::retain_observed_at(
            issuance("cert", Some(7), Some("snapshot")),
            deadline,
            now,
        )
        .unwrap();
        assert_eq!(ack.valid_until(), deadline);
        assert!(ack
            .ensure_current_at(issuance("cert", Some(7), Some("snapshot")), now)
            .is_ok());
        assert!(ack
            .ensure_current_at(issuance("cert", Some(7), Some("snapshot")), deadline)
            .is_err());
        assert!(ack
            .ensure_current_at(issuance("other", Some(7), Some("snapshot")), now)
            .is_err());
        assert!(ack
            .ensure_current_at(issuance("cert", Some(8), Some("snapshot")), now)
            .is_err());
        assert!(ack
            .ensure_current_at(issuance("cert", Some(7), Some("other")), now)
            .is_err());
        assert!(ack
            .ensure_current_at(issuance("cert", None, None), now)
            .is_err());
        let changed_expiry = IssuanceBinding {
            not_after_unix_secs: 101,
            ..issuance("cert", Some(7), Some("snapshot"))
        };
        assert!(ack.ensure_current_at(changed_expiry, now).is_err());
    }
}
