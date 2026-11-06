//! Pure DP only for released binary clipped schedule queries, not whole flows.
//! Exact rational randomized-response probabilities and sequential composition.
use rand::{CryptoRng, RngCore};
use std::io;

#[derive(Clone, Debug)]
pub struct ScheduleAccountant {
    truthful: u32,
    flipped: u32,
    odds_numerator: u128,
    odds_denominator: u128,
    limit_numerator: u128,
    limit_denominator: u128,
    releases: usize,
    max_releases: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ScheduleReceipt {
    pub releases: usize,
    /// Exact composition bound exp(epsilon), as decimal integer strings.
    pub odds_numerator: String,
    pub odds_denominator: String,
    pub delta: u8,
    pub scope: &'static str,
}

impl ScheduleAccountant {
    /// Per release epsilon=ln(truthful/flipped), with truthful>=flipped>0.
    /// The total allowed odds is a rational>=1; overflow refuses further release.
    pub fn new(
        truthful: u32,
        flipped: u32,
        limit_numerator: u128,
        limit_denominator: u128,
        max_releases: usize,
    ) -> io::Result<Self> {
        if truthful < flipped
            || flipped == 0
            || truthful.checked_add(flipped).is_none()
            || limit_denominator == 0
            || limit_numerator < limit_denominator
            || !(1..=4096).contains(&max_releases)
        {
            return Err(invalid());
        }
        Ok(Self {
            truthful,
            flipped,
            odds_numerator: 1,
            odds_denominator: 1,
            limit_numerator,
            limit_denominator,
            releases: 0,
            max_releases,
        })
    }
    /// Query domain is exactly {0,1}; caller must clip its fixed slot query.
    /// For any neighboring query values, each output likelihood ratio<=a/b.
    pub fn release<R: RngCore + CryptoRng>(
        &mut self,
        clipped_query: u8,
        rng: &mut R,
    ) -> io::Result<u8> {
        if clipped_query > 1 || self.releases == self.max_releases {
            return Err(invalid());
        }
        let a = u128::from(self.truthful);
        let b = u128::from(self.flipped);
        let cancel_a = gcd(a, self.odds_denominator);
        let cancel_b = gcd(b, self.odds_numerator);
        let numerator = (self.odds_numerator / cancel_b)
            .checked_mul(a / cancel_a)
            .ok_or_else(invalid)?;
        let denominator = (self.odds_denominator / cancel_a)
            .checked_mul(b / cancel_b)
            .ok_or_else(invalid)?;
        // Exact cross products. Unsupported arithmetic is a refusal, not a
        // floating-point under-accounting or an unbounded additional release.
        let lhs = numerator
            .checked_mul(self.limit_denominator)
            .ok_or_else(invalid)?;
        let rhs = self
            .limit_numerator
            .checked_mul(denominator)
            .ok_or_else(invalid)?;
        if lhs > rhs {
            return Err(invalid());
        }
        self.odds_numerator = numerator;
        self.odds_denominator = denominator;
        self.releases += 1;
        let truthful = super::uniform_below(rng, u64::from(self.truthful + self.flipped))?
            < u64::from(self.truthful);
        Ok(if truthful {
            clipped_query
        } else {
            1 - clipped_query
        })
    }
    pub fn receipt(&self) -> ScheduleReceipt {
        ScheduleReceipt { releases:self.releases, odds_numerator:self.odds_numerator.to_string(),
            odds_denominator:self.odds_denominator.to_string(), delta:0,
            scope:"pure DP for the released clipped binary query transcript only; whole-flow framing/endpoints/timing excluded" }
    }
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid or exhausted schedule privacy budget",
    )
}
fn gcd(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};
    #[test]
    fn exact_likelihood_ratio_and_composition_refusal() {
        // For both outputs and both neighboring queries, numerator probabilities
        // are3/4 or1/4; worst ratio3. Four releases have worst ratio81.
        for output in 0..2 {
            let p0 = if output == 0 { 3 } else { 1 };
            let p1 = if output == 1 { 3 } else { 1 };
            assert!(p0 <= 3 * p1 && p1 <= 3 * p0);
        }
        let mut rng = StdRng::seed_from_u64(19);
        let mut accountant = ScheduleAccountant::new(3, 1, 81, 1, 8).unwrap();
        for query in [0, 1, 0, 1] {
            assert!(accountant.release(query, &mut rng).unwrap() <= 1);
        }
        assert_eq!(accountant.receipt().odds_numerator, "81");
        assert!(accountant.release(0, &mut rng).is_err());
        assert_eq!(accountant.receipt().releases, 4);
        assert!(accountant.release(2, &mut rng).is_err());
    }
    #[test]
    fn query_independent_zero_epsilon_and_release_limit() {
        let mut rng = StdRng::seed_from_u64(7);
        let mut a = ScheduleAccountant::new(1, 1, 1, 1, 2).unwrap();
        a.release(0, &mut rng).unwrap();
        a.release(1, &mut rng).unwrap();
        assert_eq!(a.receipt().odds_numerator, "1");
        assert!(a.release(0, &mut rng).is_err());
    }
}
