//! The evolution loop.
//!
//! Generational, elitist, tournament-selected. Nothing exotic: the interesting
//! part of Geneva is the representation and the fitness function, not the
//! search. Everything is driven by a caller-supplied RNG, so a run is exactly
//! reproducible from its seed — which matters when the output is a strategy
//! someone will later have to justify.

use rand::seq::SliceRandom;
use rand::Rng;

use crate::censor::Censor;
use crate::syntax::strategy::Strategy;

use super::crossover::crossover;
use super::fitness::{score, Scenario, Score};
use super::mutate::mutate;
use super::random::random_strategy;

#[derive(Clone, Debug)]
pub struct Params {
    pub population: usize,
    pub generations: usize,
    /// Individuals carried into the next generation untouched.
    pub elites: usize,
    /// Candidates per selection tournament.
    pub tournament: usize,
    pub mutation_rate: f64,
    /// Maximum depth for freshly generated trees.
    pub initial_depth: usize,
    /// Fresh random individuals injected each generation.
    ///
    /// Without this the population collapses onto the identity strategy — it
    /// scores 100 for delivering the payload, while nearly every random
    /// strategy breaks delivery and scores less, so elitism plus tournament
    /// selection wipes out diversity in a few generations and the search never
    /// recovers. Measured: with no immigrants a 50x30 run never left the
    /// baseline; with 10% immigrants the same budget finds an evasion.
    pub immigrants: usize,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            population: 40,
            generations: 30,
            elites: 2,
            tournament: 3,
            mutation_rate: 0.7,
            initial_depth: 3,
            immigrants: 4,
        }
    }
}

/// One scored individual.
#[derive(Clone, Debug)]
pub struct Evaluated {
    pub strategy: Strategy,
    pub score: Score,
}

/// The outcome of a run.
#[derive(Clone, Debug)]
pub struct Report {
    pub best: Evaluated,
    /// Best score value per generation, for plotting or for noticing that a run
    /// never went anywhere.
    pub history: Vec<f64>,
    pub generations_run: usize,
}

/// Evolve a strategy against `censor` on `scenario`.
pub fn evolve<C: Censor + ?Sized, R: Rng + ?Sized>(
    censor: &C,
    scenario: &Scenario,
    params: &Params,
    rng: &mut R,
) -> Report {
    // The identity strategy is seeded into the population so a run can never
    // report something *worse* than doing nothing as its best find.
    // Triggers are seeded from the traffic being optimised for, so rules fire
    // by construction and selection can act on the action trees.
    let samples = &scenario.packets;

    let mut population: Vec<Strategy> = vec![Strategy::identity()];
    while population.len() < params.population {
        population.push(random_strategy(samples, rng, params.initial_depth));
    }

    let mut history = Vec::with_capacity(params.generations);
    let mut best = evaluate_all(&population, censor, scenario, rng)
        .into_iter()
        .max_by(|a, b| a.score.value.total_cmp(&b.score.value))
        .expect("population is never empty");

    let mut generations_run = 0;
    for _ in 0..params.generations {
        generations_run += 1;
        let mut scored = evaluate_all(&population, censor, scenario, rng);
        scored.sort_by(|a, b| b.score.value.total_cmp(&a.score.value));

        if scored[0].score.value > best.score.value {
            best = scored[0].clone();
        }
        history.push(scored[0].score.value);

        let mut next: Vec<Strategy> = scored
            .iter()
            .take(params.elites.min(scored.len()))
            .map(|e| e.strategy.clone())
            .collect();

        // Fresh blood, before the rest of the slots go to offspring.
        for _ in 0..params
            .immigrants
            .min(params.population.saturating_sub(next.len()))
        {
            next.push(random_strategy(samples, rng, params.initial_depth));
        }

        while next.len() < params.population {
            let a = tournament(&scored, params.tournament, rng);
            let b = tournament(&scored, params.tournament, rng);
            let mut child = crossover(&a.strategy, &b.strategy, rng);
            if rng.gen_bool(params.mutation_rate) {
                child = mutate(&child, samples, rng);
            }
            next.push(child);
        }
        population = next;
    }

    Report {
        best,
        history,
        generations_run,
    }
}

fn evaluate_all<C: Censor + ?Sized, R: Rng + ?Sized>(
    population: &[Strategy],
    censor: &C,
    scenario: &Scenario,
    rng: &mut R,
) -> Vec<Evaluated> {
    population
        .iter()
        .map(|strategy| Evaluated {
            strategy: strategy.clone(),
            score: score(strategy, censor, scenario, rng),
        })
        .collect()
}

fn tournament<'a, R: Rng + ?Sized>(
    scored: &'a [Evaluated],
    size: usize,
    rng: &mut R,
) -> &'a Evaluated {
    let mut best: Option<&Evaluated> = None;
    for _ in 0..size.max(1) {
        let candidate = scored.choose(rng).expect("population is never empty");
        if best.is_none_or(|b| candidate.score.value > b.score.value) {
            best = Some(candidate);
        }
    }
    best.expect("at least one round")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::censor::inspection::Inspector;
    use crate::censor::PathCensor;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn per_packet_censor() -> PathCensor {
        PathCensor {
            name: "per-packet".into(),
            censor_hops: 3,
            server_hops: 10,
            inspector: Inspector::per_packet(b"secret"),
        }
    }

    fn fast_params() -> Params {
        // Small enough to stay a unit test (everything is in memory), large
        // enough to be a fair search.
        Params {
            population: 50,
            generations: 30,
            immigrants: 5,
            ..Params::default()
        }
    }

    /// A budget small enough that the whole suite stays quick in a debug build.
    fn tiny_params() -> Params {
        Params {
            population: 20,
            generations: 10,
            immigrants: 3,
            ..Params::default()
        }
    }

    /// The headline claim: given only the primitives and a censor model, the
    /// search finds a working evasion on its own — nobody wrote the strategy.
    #[test]
    fn evolution_discovers_a_working_evasion() {
        let censor = per_packet_censor();
        let scenario = Scenario::single(b"GET /secret HTTP/1.1");
        let mut rng = StdRng::seed_from_u64(20260731);

        let report = evolve(&censor, &scenario, &fast_params(), &mut rng);
        assert!(
            report.best.score.is_success(),
            "no evasion found; best was {} scoring {:?}",
            report.best.strategy,
            report.best.score
        );
        // And it must be a real strategy, not the do-nothing baseline.
        assert!(!report.best.strategy.is_identity());
    }

    /// Expensive deterministic proof that the trainer can assemble the full
    /// construction against a censor that reassembles like the server: a
    /// payload-altered duplicate whose TTL lands between censor and server plus
    /// an unchanged canonical branch. This used to fail because the random TTL
    /// generator omitted the entire useful 4..=10 band for this path model.
    /// It remains ignored only because the 200x200 release run is expensive:
    ///
    /// ```text
    /// cargo test --release -p aegis-geneva \
    ///   evolution_beats_a_reassembling_censor_using_payload_tampering \
    ///   -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "expensive deterministic 200x200 reassembling-censor evolution proof"]
    fn evolution_beats_a_reassembling_censor_using_payload_tampering() {
        let censor = PathCensor::typical(b"secret");
        let scenario = Scenario::single(b"GET /secret HTTP/1.1");
        let params = Params {
            population: 200,
            generations: 200,
            immigrants: 25,
            ..Params::default()
        };
        let report = evolve(&censor, &scenario, &params, &mut StdRng::seed_from_u64(11));
        assert!(
            report.best.score.is_success(),
            "no evasion found; best was {} scoring {:?}",
            report.best.strategy,
            report.best.score
        );
    }

    /// What the trainer *can* do against that censor: climb off the do-nothing
    /// baseline by discovering the decoy mechanism.
    ///
    /// Measured, 8 seeds each: 0/8 at 60x50, 2/8 at 100x80, 3/8 at 150x120.
    /// Eight sequential runs at that size can take hours even in a release
    /// build, so this remains a statistical research check rather than a
    /// release gate. Run it by its exact filter rather than running every
    /// ignored test:
    ///
    /// ```text
    /// cargo test --release -p aegis-geneva \
    ///   evolution_finds_the_decoy_mechanism_against_a_reassembling_censor \
    ///   -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "expensive: 8 evolution runs — run with --release --ignored"]
    fn evolution_finds_the_decoy_mechanism_against_a_reassembling_censor() {
        let censor = PathCensor::typical(b"secret");
        let scenario = Scenario::single(b"GET /secret HTTP/1.1");
        let params = Params {
            population: 150,
            generations: 120,
            immigrants: 18,
            ..Params::default()
        };
        // Several seeds: at this budget an individual run may or may not get
        // there, so the claim is about the search, not about one lucky seed.
        let above = (0..8u64)
            .filter(|seed| {
                evolve(
                    &censor,
                    &scenario,
                    &params,
                    &mut StdRng::seed_from_u64(*seed),
                )
                .best
                .score
                .value
                    > 100.0
            })
            .count();
        assert!(
            above >= 2,
            "the search stayed at the baseline in {}/8 seeds",
            8 - above
        );
    }

    #[test]
    fn a_run_is_reproducible_from_its_seed() {
        let censor = per_packet_censor();
        let scenario = Scenario::single(b"GET /secret");
        let params = tiny_params();
        let a = evolve(&censor, &scenario, &params, &mut StdRng::seed_from_u64(4));
        let b = evolve(&censor, &scenario, &params, &mut StdRng::seed_from_u64(4));
        assert_eq!(a.best.strategy, b.best.strategy);
        assert_eq!(a.history, b.history);
    }

    #[test]
    fn the_best_never_scores_below_doing_nothing() {
        let censor = per_packet_censor();
        let scenario = Scenario::single(b"GET /secret");
        let mut rng = StdRng::seed_from_u64(99);
        let baseline = score(
            &Strategy::identity(),
            &censor,
            &scenario,
            &mut StdRng::seed_from_u64(99),
        );
        let report = evolve(&censor, &scenario, &tiny_params(), &mut rng);
        assert!(report.best.score.value >= baseline.value);
    }

    #[test]
    fn a_reported_best_actually_reproduces_when_re_scored() {
        // A strategy whose success depended on a lucky RNG draw would be a lie.
        let censor = per_packet_censor();
        let scenario = Scenario::single(b"GET /secret HTTP/1.1");
        let mut rng = StdRng::seed_from_u64(20260731);
        let report = evolve(&censor, &scenario, &fast_params(), &mut rng);

        for seed in [1u64, 2, 3, 4, 5] {
            let again = score(
                &report.best.strategy,
                &censor,
                &scenario,
                &mut StdRng::seed_from_u64(seed),
            );
            assert_eq!(
                again.is_success(),
                report.best.score.is_success(),
                "re-scoring with seed {seed} disagreed: {}",
                report.best.strategy
            );
        }
    }

    /// Without immigrants the population collapses onto identity; this pins
    /// that the knob is doing what its doc-comment claims.
    #[test]
    fn immigrants_keep_the_population_from_collapsing() {
        let censor = per_packet_censor();
        let scenario = Scenario::single(b"GET /secret HTTP/1.1");
        let with = evolve(
            &censor,
            &scenario,
            &tiny_params(),
            &mut StdRng::seed_from_u64(20260731),
        );
        let without = evolve(
            &censor,
            &scenario,
            &Params {
                immigrants: 0,
                ..tiny_params()
            },
            &mut StdRng::seed_from_u64(20260731),
        );
        assert!(with.best.score.value >= without.best.score.value);
    }

    #[test]
    fn history_is_recorded_per_generation() {
        let censor = per_packet_censor();
        let scenario = Scenario::single(b"GET /secret");
        let params = Params {
            generations: 5,
            population: 10,
            ..Params::default()
        };
        let report = evolve(&censor, &scenario, &params, &mut StdRng::seed_from_u64(1));
        assert_eq!(report.history.len(), 5);
        assert_eq!(report.generations_run, 5);
    }

    #[test]
    fn a_zero_generation_run_still_reports_a_baseline() {
        let censor = per_packet_censor();
        let scenario = Scenario::single(b"GET /secret");
        let params = Params {
            generations: 0,
            population: 5,
            ..Params::default()
        };
        let report = evolve(&censor, &scenario, &params, &mut StdRng::seed_from_u64(1));
        assert!(report.history.is_empty());
        assert_eq!(report.generations_run, 0);
    }
}
