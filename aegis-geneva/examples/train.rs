//! Evolve a strategy against a censor model and print what it found.
//!
//! ```text
//! cargo run --release -p aegis-geneva --example train
//! ```
//!
//! The censor here is a *model*, so a win means "worth testing for real", not
//! "works against a real censor". The run is seeded, so the same seed always
//! produces the same strategy.

use aegis_geneva::censor::inspection::Inspector;
use aegis_geneva::censor::PathCensor;
use aegis_geneva::evolve::fitness::Scenario;
use aegis_geneva::evolve::ga::{evolve, Params};
use rand::rngs::StdRng;
use rand::SeedableRng;

fn main() {
    let seed: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(20260731);

    let scenarios = [
        (
            "per-packet censor",
            PathCensor {
                name: "per-packet".into(),
                censor_hops: 3,
                server_hops: 10,
                inspector: Inspector::per_packet(b"secret"),
            },
        ),
        ("reassembling censor", PathCensor::typical(b"secret")),
    ];

    for (label, censor) in scenarios {
        let scenario = Scenario::single(b"GET /secret HTTP/1.1");
        let mut rng = StdRng::seed_from_u64(seed);
        let report = evolve(&censor, &scenario, &Params::default(), &mut rng);

        println!("== {label} (seed {seed}) ==");
        println!("  best     : {}", report.best.strategy);
        println!(
            "  score    : {:.1}  evaded={} delivered={} size={}",
            report.best.score.value,
            report.best.score.evaded,
            report.best.score.delivered,
            report.best.score.size
        );
        if !report.best.score.is_success() {
            println!(
                "  NOTE: no full evasion found in {} generations",
                report.generations_run
            );
        }
        println!();
    }
}
