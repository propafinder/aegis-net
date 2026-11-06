//! Opt-in bounded framing and finite-alphabet privacy measurements.
//! These mechanisms do not supply differential privacy or network reachability.
pub mod adaptive_channel;
pub mod binary_hypothesis;
pub mod bittraps;
pub mod coupling;
pub mod cover_control;
pub mod cover_stream;
pub mod general_coupling;
#[cfg(test)]
mod idle_receive_gate_support;
pub mod leakage;
pub mod netshaper;
pub mod network_calculus_guard;
mod optimizer_admission;
#[cfg(test)]
mod optimizer_admission_ownership_tests;
#[cfg(test)]
mod optimizer_admission_test_support;
pub mod plan;
pub mod poisson;
pub mod poisson_channel;
pub mod poisson_insertion;
pub mod rate_distortion;
pub mod schedule_dp;
pub mod schedule_emission;
pub mod shaper;
#[cfg(windows)]
mod windows_timer_resolution;
pub(crate) mod worker_owner;

/// Unbiased finite draw using fallible cryptographic entropy. Bounded rejection
/// affects availability only; the failure event is independent of message/query.
fn uniform_below<R: rand::RngCore + rand::CryptoRng>(
    rng: &mut R,
    upper: u64,
) -> std::io::Result<u64> {
    if upper == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "empty random alphabet",
        ));
    }
    let threshold = upper.wrapping_neg() % upper;
    for _ in 0..128 {
        let mut bytes = [0; 8];
        rng.try_fill_bytes(&mut bytes)
            .map_err(|_| std::io::Error::other("cryptographic entropy unavailable"))?;
        let draw = u64::from_le_bytes(bytes);
        if draw >= threshold {
            return Ok(draw % upper);
        }
    }
    Err(std::io::Error::other(
        "cryptographic sampling budget exhausted",
    ))
}

#[cfg(test)]
mod tests {
    use rand::{CryptoRng, RngCore};
    struct Broken;
    impl RngCore for Broken {
        fn next_u32(&mut self) -> u32 {
            panic!("infallible entropy API must not be called")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("infallible entropy API must not be called")
        }
        fn fill_bytes(&mut self, _: &mut [u8]) {
            panic!("infallible entropy API must not be called")
        }
        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand::Error> {
            Err(rand::Error::new(std::io::Error::other(
                "controlled entropy failure",
            )))
        }
    }
    impl CryptoRng for Broken {}
    #[test]
    fn entropy_failure_is_a_refusal_for_both_exact_codecs() {
        let mec = super::coupling::MinimumEntropyCoupling::new(vec![1, 1], 1).unwrap();
        assert!(mec.encode(0, &mut Broken).is_err());
        let mut accountant = super::schedule_dp::ScheduleAccountant::new(3, 1, 3, 1, 1).unwrap();
        assert!(accountant.release(0, &mut Broken).is_err());
        assert_eq!(accountant.receipt().releases, 1); // conservative spending on failed release
    }
}

pub mod liu_channel;
