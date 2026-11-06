# aegis-core/src/brain/recent_routes

Optional recent-route estimators and teacher-forced offline replay.

## Contract

paper_bandit.rs implements bounded paper-derived ranking over verified outcomes. offline_replay.rs reuses logged observations even when an alternate rank would differ; it cannot invent counterfactual rewards or transfer a regret theorem to the runtime. Retirement tests exercise ordinary in-memory consumers.

## Key files

- [paper_bandit.rs](paper_bandit.rs)
- [offline_replay.rs](offline_replay.rs)
- [offline_replay_tests.rs](offline_replay_tests.rs)
- [retirement_tests.rs](retirement_tests.rs)

The enclosing module is [recent_routes.rs](../recent_routes.rs); this directory contains its split implementation or test modules.

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-core --lib brain::recent_routes
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-core](../../../README.md).

[Repository overview](../../../../README.md) · [Parent directory](../README.md)
