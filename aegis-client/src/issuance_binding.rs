//! Exact comparison of an already validated online issuance across awaits.
//! This is a borrowed observation, never an identity, ACK or capture permit.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IssuanceBinding<'a> {
    pub certificate_sha256: &'a str,
    pub not_after_unix_secs: u64,
    pub issued_generation: Option<u64>,
    pub snapshot_sha256: Option<&'a str>,
}

pub fn same_issuance(expected: IssuanceBinding<'_>, current: IssuanceBinding<'_>) -> bool {
    expected == current
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_four_issuance_fields_must_remain_exact() {
        let expected = IssuanceBinding {
            certificate_sha256: "certificate",
            not_after_unix_secs: 100,
            issued_generation: Some(7),
            snapshot_sha256: Some("snapshot"),
        };
        assert!(same_issuance(expected, expected));
        for changed in [
            IssuanceBinding {
                certificate_sha256: "other",
                ..expected
            },
            IssuanceBinding {
                not_after_unix_secs: 101,
                ..expected
            },
            IssuanceBinding {
                issued_generation: Some(8),
                ..expected
            },
            IssuanceBinding {
                snapshot_sha256: Some("other"),
                ..expected
            },
            IssuanceBinding {
                issued_generation: None,
                ..expected
            },
            IssuanceBinding {
                snapshot_sha256: None,
                ..expected
            },
        ] {
            assert!(!same_issuance(expected, changed));
        }
    }
}
