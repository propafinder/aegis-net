//! What a censor model has to answer.
//!
//! Two questions, and they are not the same one: *did the censor notice?* and
//! *did the payload still arrive?* A strategy that hides from the censor by
//! corrupting the stream is not an evasion — it is an outage — so the harness
//! insists on both.

use crate::packet::model::Packet;

/// The result of pushing a packet stream past a censor.
#[derive(Clone, Debug, PartialEq)]
pub struct Outcome {
    /// True if the censor detected the forbidden content and would act on it.
    pub censored: bool,
    /// How much of the forbidden content the censor saw contiguously, 0.0-1.0.
    /// `1.0` implies `censored`. Used to give the trainer a gradient instead of
    /// a cliff.
    pub exposure: f64,
    /// Payload bytes the censor saw that never reached the server.
    ///
    /// This is the *mechanism* every decoy evasion is built on: content shown
    /// only to the middlebox. Reporting it lets the trainer be rewarded for
    /// discovering the mechanism before it has assembled a complete evasion —
    /// without it the landscape is flat and the search is blind (measured: zero
    /// of 200,000 random strategies scored above the do-nothing baseline
    /// against a fully reassembling censor).
    pub decoy_bytes: usize,
    /// The payload bytes the *server* actually reconstructs.
    pub delivered: Vec<u8>,
}

impl Outcome {
    /// The only outcome that counts as success: the censor missed it *and* the
    /// server got exactly what was sent.
    pub fn is_success(&self, intended: &[u8]) -> bool {
        !self.censored && self.delivered == intended
    }
}

/// A model of a censor sitting between the client and the server.
pub trait Censor {
    fn evaluate(&self, packets: &[Packet]) -> Outcome;

    /// A short name for logs and reports.
    fn name(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_needs_both_evasion_and_delivery() {
        let intended = b"GET /secret";
        assert!(Outcome {
            censored: false,
            exposure: 0.0,
            decoy_bytes: 0,
            delivered: intended.to_vec()
        }
        .is_success(intended));

        // Noticed.
        assert!(!Outcome {
            censored: true,
            exposure: 1.0,
            decoy_bytes: 0,
            delivered: intended.to_vec()
        }
        .is_success(intended));

        // Evaded, but broke the connection — not a win.
        assert!(!Outcome {
            censored: false,
            exposure: 0.0,
            decoy_bytes: 0,
            delivered: b"GET /sec".to_vec()
        }
        .is_success(intended));
    }
}
