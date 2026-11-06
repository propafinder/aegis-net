# Bounded adaptive state contracts

`bounds_tests.rs` calls the actual store and Brain producers. The same seven test bodies were frozen before repair: six failed against the original implementation, while the exact 16 MiB positive passed. All seven pass with the bounded owner. Synthetic keys and owned temporary files exercise the contract without a deployed state, endpoint or private history.

The policy is 4,096 rows each for registry, observation, stall probe and hybrid maps; 16,384 strategy rows; 128 transport rows. The snapshot and ephemeral recency metadata share one write lock. Each successful update normalizes all six maps, increments the original revision once and marks dirty. Actual Brain producers mark each changed row, including existing evidence. Public opaque updates discover new entries; they cannot infer a write to an existing value. Historical rows start at recency zero. Eviction uses current touches, then write order, then lexical key order. Base and enriched aliases remain separate rows; orphan v1 strategy rows remain compatible. Evicted evidence returns to existing cold-start behavior.

Each update scans the bounded maps and retention metadata; overflow additionally sorts eviction candidates. Metadata contains only retained rows. An arbitrary update closure can allocate more before it returns, and individual strings or calibration vectors have no exact heap ceiling here. Snapshot cloning still consumes CPU and allocation; serialization/sealing and startup key lookup/AEAD now execute in owned blocking workers. Offloading does not eliminate those costs or establish an exact heap or blocking-pool budget.

The actual descriptor reader accepts at most 16 MiB and probes one additional byte to refuse an oversized or growing input. It does not trust metadata size alone. Loaded v1/v2 state is normalized in RAM with revision 0 and dirty false; clean flush does not rewrite historical disk bytes. The existing missing-master-key quarantine policy is unchanged. Flush separately checks serialized plaintext before key/seal work and checks the sealed envelope before invoking the existing private writer. Refusal preserves the old blob, dirty flag and revision.

`retention_tests.rs` covers real eviction during an owned writer lease, a refreshed existing Brain key at saturation, both output size refusals, nonterminating reader custody, deterministic metadata removal and recency rollover. Existing persistence revision/cancellation and private atomic writer controls also pass. No fsync, writer lease, key policy or consent gate was replaced.

Run from the repository root:

```sh
cargo test --offline --locked -p aegis-core --lib bounds_tests
cargo test --offline --locked -p aegis-core --lib retention_tests
cargo test --offline --locked -p aegis-core --lib state_v2::persist::tests
cargo test --offline --locked -p aegis-core --lib brain::
cargo test --offline --locked -p aegis-core --lib state_secret::tests
cargo clippy --offline --locked -p aegis-core --lib --tests -- -D warnings
```

The current client consent tests still require the integrated candidate check. Local Darwin store tests are not native Linux/Windows release, deployed-state, historical privacy or beta acceptance. Broader finding 19 remains partial for full clones, map scans, transient allocation, native provider duration and global blocking admission; finding 12 remains open for opted-in stable host/SNI history.

[State module](../README.md) · [Actual Brain producer tests](../../brain/bounds_tests.rs)
