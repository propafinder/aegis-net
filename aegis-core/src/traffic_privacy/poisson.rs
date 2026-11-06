//! Opt-in exponential pacing proposals with a public finite gap bound.
//! This is not a covert timing codebook or a Poisson cover-law guarantee.
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{io, time::Duration};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoissonPacing {
    /// Caller-declared experimental mean, not inferred from a traffic average.
    pub mean_interval_us: u64,
    /// Tail proposals refuse the owned stream; never clamp, resample or fallback.
    pub max_gap_us: u64,
}
impl PoissonPacing {
    pub fn validate(&self) -> io::Result<()> {
        if !(1_000..=1_000_000).contains(&self.mean_interval_us)
            || !(self.mean_interval_us..=1_000_000).contains(&self.max_gap_us)
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn max_gap(&self) -> Duration {
        Duration::from_micros(self.max_gap_us)
    }
    /// Quantized inverse-CDF proposal. The finite uniform grid and timer
    /// resolution are explicit; accepted sessions do not retain an exact
    /// unconditioned Poisson law after tail/lifetime/error admission.
    pub fn next_gap<R: RngCore + CryptoRng>(&self, rng: &mut R) -> io::Result<Duration> {
        self.validate()?;
        let mut bytes = [0; 8];
        rng.try_fill_bytes(&mut bytes)
            .map_err(|_| io::Error::other("pacing entropy unavailable"))?;
        // 52 bits ensure both endpoints are strictly inside (0,1) in f64.
        let numerator = (u64::from_le_bytes(bytes) >> 12) + 1;
        let uniform = numerator as f64 / ((1u64 << 52) + 1) as f64;
        let nanos = -uniform.ln() * self.mean_interval_us as f64 * 1_000.0;
        if !nanos.is_finite() || nanos > self.max_gap_us as f64 * 1_000.0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "pacing proposal exceeds public gap bound",
            ));
        }
        // At most one nanosecond quantization, not a tail clamp.
        Ok(Duration::from_nanos(nanos.ceil().max(1.0) as u64))
    }
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid exponential pacing profile",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};
    #[test]
    fn proposals_are_positive_variable_and_finite() {
        let p = PoissonPacing {
            mean_interval_us: 1_000,
            max_gap_us: 1_000_000,
        };
        let mut r = StdRng::seed_from_u64(21);
        let gaps: Vec<_> = (0..64).map(|_| p.next_gap(&mut r).unwrap()).collect();
        assert!(gaps.iter().all(|g| !g.is_zero() && *g <= p.max_gap()));
        assert!(gaps.windows(2).any(|p| p[0] != p[1]));
    }
    struct Low;
    impl RngCore for Low {
        fn next_u32(&mut self) -> u32 {
            panic!("infallible RNG forbidden")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("infallible RNG forbidden")
        }
        fn fill_bytes(&mut self, _: &mut [u8]) {
            panic!("infallible RNG forbidden")
        }
        fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand::Error> {
            bytes.fill(0);
            Ok(())
        }
    }
    impl CryptoRng for Low {}
    #[test]
    fn extreme_tail_is_refusal_without_clamping_or_resampling() {
        let p = PoissonPacing {
            mean_interval_us: 1_000,
            max_gap_us: 1_000,
        };
        assert_eq!(
            p.next_gap(&mut Low).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
    struct Broken;
    impl RngCore for Broken {
        fn next_u32(&mut self) -> u32 {
            panic!("infallible RNG forbidden")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("infallible RNG forbidden")
        }
        fn fill_bytes(&mut self, _: &mut [u8]) {
            panic!("infallible RNG forbidden")
        }
        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand::Error> {
            Err(rand::Error::new(io::Error::other(
                "controlled entropy failure",
            )))
        }
    }
    impl CryptoRng for Broken {}
    #[test]
    fn entropy_failure_is_terminal_without_deterministic_fallback() {
        let p = PoissonPacing {
            mean_interval_us: 1_000,
            max_gap_us: 1_000_000,
        };
        assert_eq!(
            p.next_gap(&mut Broken).unwrap_err().kind(),
            io::ErrorKind::Other
        );
    }
    #[test]
    fn invalid_rate_and_gap_contract_refuses() {
        for p in [
            PoissonPacing {
                mean_interval_us: 0,
                max_gap_us: 1_000,
            },
            PoissonPacing {
                mean_interval_us: 1_000,
                max_gap_us: 999,
            },
            PoissonPacing {
                mean_interval_us: 1_000,
                max_gap_us: 1_000_001,
            },
        ] {
            assert!(p.validate().is_err());
        }
    }
}
