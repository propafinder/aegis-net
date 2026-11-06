//! Exact owned issuance expectation produced by the protected online Store.
//! The value is data, not evidence that a caller read the Store, received an
//! authenticated ACK, or owns a packet-capture lease. A validated offline
//! identity can have no issuance floor; a live ACK still binds its certificate.

use crate::issuance_binding::{same_issuance, IssuanceBinding};
use anyhow::{ensure, Result};

#[derive(Clone, Debug)]
pub struct OnlineExpectation {
    pub certificate_sha256: String,
    pub not_after_unix_secs: u64,
    pub issued_generation: Option<u64>,
    pub snapshot_sha256: Option<String>,
}

impl OnlineExpectation {
    pub fn binding(&self) -> IssuanceBinding<'_> {
        IssuanceBinding {
            certificate_sha256: &self.certificate_sha256,
            not_after_unix_secs: self.not_after_unix_secs,
            issued_generation: self.issued_generation,
            snapshot_sha256: self.snapshot_sha256.as_deref(),
        }
    }

    pub fn ensure_same_issuance(&self, current: &Self) -> Result<()> {
        ensure!(
            same_issuance(self.binding(), current.binding()),
            "online issuance changed; authenticated restart required"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expectation() -> OnlineExpectation {
        OnlineExpectation {
            certificate_sha256: "certificate".into(),
            not_after_unix_secs: 100,
            issued_generation: Some(7),
            snapshot_sha256: Some("snapshot".into()),
        }
    }

    #[test]
    fn exact_issuance_comparison_refuses_every_changed_field() {
        let first = expectation();
        first.ensure_same_issuance(&first).unwrap();
        let mut changed = expectation();
        changed.certificate_sha256 = "other".into();
        assert!(first.ensure_same_issuance(&changed).is_err());
        changed = expectation();
        changed.not_after_unix_secs = 101;
        assert!(first.ensure_same_issuance(&changed).is_err());
        changed = expectation();
        changed.issued_generation = Some(8);
        assert!(first.ensure_same_issuance(&changed).is_err());
        changed = expectation();
        changed.snapshot_sha256 = Some("other".into());
        assert!(first.ensure_same_issuance(&changed).is_err());
        changed = expectation();
        changed.issued_generation = None;
        changed.snapshot_sha256 = None;
        assert!(first.ensure_same_issuance(&changed).is_err());
    }
}
