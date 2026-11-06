//! Scoring a strategy against a censor.
//!
//! The score deliberately makes breaking the connection *worse* than being
//! caught. Evolution will otherwise converge on `drop` — a strategy that no
//! censor ever flags because nothing ever arrives — and report it as a triumph.

use rand::Rng;

use crate::censor::Censor;
use crate::engine;
use crate::packet::model::Packet;
use crate::syntax::strategy::Strategy;

/// A scenario to evolve against: the packets a client wants to send, and the
/// payload the server must end up with.
pub struct Scenario {
    pub packets: Vec<Packet>,
    pub intended_payload: Vec<u8>,
}

impl Scenario {
    /// One outbound TCP packet carrying `payload`.
    pub fn single(payload: &[u8]) -> Self {
        Scenario {
            packets: vec![Packet::tcp_data(payload)],
            intended_payload: payload.to_vec(),
        }
    }
}

/// Score components, kept separate so a run can be explained rather than just
/// ranked.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Score {
    /// The censor did not detect the content.
    pub evaded: bool,
    /// The server received exactly the intended payload.
    pub delivered: bool,
    /// Node count across the strategy, the simplicity tie-breaker.
    pub size: usize,
    pub value: f64,
}

impl Score {
    pub fn is_success(&self) -> bool {
        self.evaded && self.delivered
    }
}

/// Weights, named rather than magic numbers scattered through the code.
const DELIVERY_WEIGHT: f64 = 100.0;
const EVASION_WEIGHT: f64 = 100.0;
const SIZE_PENALTY: f64 = 0.5;
/// Small, deliberately smaller than either of the above: showing the censor
/// content the server never gets is *progress towards* an evasion, not an
/// evasion. It exists so the search has a step to climb — see
/// `Outcome::decoy_bytes`.
const DECOY_WEIGHT: f64 = 10.0;

/// Score `strategy` against `censor` on `scenario`.
pub fn score<C: Censor + ?Sized, R: Rng + ?Sized>(
    strategy: &Strategy,
    censor: &C,
    scenario: &Scenario,
    rng: &mut R,
) -> Score {
    let emitted = engine::run(strategy, scenario.packets.clone(), rng);
    let outcome = censor.evaluate(&emitted);

    let delivered = outcome.delivered == scenario.intended_payload;
    let evaded = !outcome.censored;

    // Delivery is scored first and unconditionally: a strategy that does not
    // deliver cannot win, however invisible it is.
    let mut value = 0.0;
    if delivered {
        value += DELIVERY_WEIGHT;
        // Graded, not binary: a strategy that leaves the censor seeing half the
        // keyword scores above one that leaves it seeing all of it, so the
        // search has somewhere to climb.
        value += EVASION_WEIGHT * (1.0 - outcome.exposure.clamp(0.0, 1.0));
        if !scenario.intended_payload.is_empty() {
            let ratio = outcome.decoy_bytes as f64 / scenario.intended_payload.len() as f64;
            value += DECOY_WEIGHT * ratio.min(1.0);
        }
    } else {
        // Partial credit for getting *some* of the payload through, so the
        // search has a gradient to climb instead of a cliff.
        let progress = if scenario.intended_payload.is_empty() {
            0.0
        } else {
            outcome.delivered.len() as f64 / scenario.intended_payload.len() as f64
        };
        value += DELIVERY_WEIGHT * progress.min(1.0) * 0.5;
    }
    value -= SIZE_PENALTY * strategy.size() as f64;

    Score {
        evaded,
        delivered,
        size: strategy.size(),
        value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::censor::inspection::Inspector;
    use crate::censor::PathCensor;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn rng() -> StdRng {
        StdRng::seed_from_u64(5)
    }

    fn per_packet_censor() -> PathCensor {
        PathCensor {
            name: "per-packet".into(),
            censor_hops: 3,
            server_hops: 10,
            inspector: Inspector::per_packet(b"secret"),
        }
    }

    #[test]
    fn the_identity_strategy_gets_caught() {
        let s = Strategy::identity();
        let score = score(
            &s,
            &per_packet_censor(),
            &Scenario::single(b"GET /secret"),
            &mut rng(),
        );
        assert!(score.delivered);
        assert!(!score.evaded);
        assert!(!score.is_success());
    }

    #[test]
    fn dropping_everything_scores_worse_than_being_caught() {
        let scenario = Scenario::single(b"GET /secret");
        let censor = per_packet_censor();
        let caught = score(&Strategy::identity(), &censor, &scenario, &mut rng());
        let dropped = score(
            &Strategy::parse("[IP:ttl:64]-drop-| \\/").unwrap(),
            &censor,
            &scenario,
            &mut rng(),
        );
        assert!(dropped.evaded, "nothing arrives, so nothing is detected");
        assert!(!dropped.delivered);
        assert!(
            dropped.value < caught.value,
            "breaking the connection must not outrank being caught"
        );
    }

    #[test]
    fn a_working_evasion_outranks_everything_else() {
        let scenario = Scenario::single(b"GET /secret");
        let censor = per_packet_censor();
        // Split the payload so no single packet holds the keyword.
        let evasion = Strategy::parse("[IP:ttl:64]-fragment{TCP:8:in-order}(,)-| \\/").unwrap();
        let good = score(&evasion, &censor, &scenario, &mut rng());
        assert!(good.is_success(), "expected evasion+delivery, got {good:?}");
        assert!(good.value > score(&Strategy::identity(), &censor, &scenario, &mut rng()).value);
    }

    #[test]
    fn the_simpler_of_two_equal_strategies_wins() {
        let scenario = Scenario::single(b"GET /secret");
        let censor = per_packet_censor();
        let simple = Strategy::parse("[IP:ttl:64]-fragment{TCP:8:in-order}(,)-| \\/").unwrap();
        // Same effect, more nodes.
        let bloated =
            Strategy::parse("[IP:ttl:64]-fragment{TCP:8:in-order}(,duplicate(,drop))-| \\/")
                .unwrap();
        let a = score(&simple, &censor, &scenario, &mut rng());
        let b = score(&bloated, &censor, &scenario, &mut rng());
        assert!(a.is_success() && b.is_success());
        assert!(a.value > b.value, "complexity must cost something");
    }

    /// A decoy alone is not an evasion, but it must outrank doing nothing, or
    /// the search can never find its way to one.
    #[test]
    fn a_decoy_scores_above_the_baseline_but_below_a_real_evasion() {
        use crate::censor::PathCensor;
        let scenario = Scenario::single(b"GET /secret HTTP/1.1");
        let censor = PathCensor::typical(b"secret"); // reassembles everything

        let baseline = score(&Strategy::identity(), &censor, &scenario, &mut rng());
        // Sends a short-lived copy, but with the same bytes: no evasion.
        let decoy_only =
            Strategy::parse("[TCP:flags:PA]-duplicate(tamper{IP:ttl:replace:5}(),)-| \\/").unwrap();
        // The same, with the decoy's payload replaced: a real evasion.
        let full = Strategy::parse(
            "[TCP:flags:PA]-duplicate(tamper{IP:ttl:replace:5}(tamper{TCP:load:corrupt}()),)-| \\/",
        )
        .unwrap();

        let d = score(&decoy_only, &censor, &scenario, &mut rng());
        let f = score(&full, &censor, &scenario, &mut rng());
        assert!(!d.is_success(), "a bare decoy must not count as an evasion");
        assert!(f.is_success(), "expected a full evasion, got {f:?}");
        assert!(
            d.value > baseline.value,
            "decoy {d:?} vs baseline {baseline:?}"
        );
        assert!(f.value > d.value);
    }

    #[test]
    fn partial_delivery_scores_above_none() {
        let scenario = Scenario::single(b"GET /secret");
        let censor = per_packet_censor();
        // Deliver only the first half.
        let half = Strategy::parse("[IP:ttl:64]-fragment{TCP:5:in-order}(,drop)-| \\/").unwrap();
        let nothing = Strategy::parse("[IP:ttl:64]-drop-| \\/").unwrap();
        assert!(
            score(&half, &censor, &scenario, &mut rng()).value
                > score(&nothing, &censor, &scenario, &mut rng()).value
        );
    }
}
