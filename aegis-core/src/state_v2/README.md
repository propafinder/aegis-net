# aegis-core/src/state_v2

Runtime state schema and asynchronous batched persistence.

## Contract

StateSnapshot and per-key observations are the current store vocabulary; the parent state.rs remains for legacy compatibility and migration. Persisted route and wire observations are context-dependent evidence, not transferable access guarantees. Coordinate schema and migration changes with Brain and encrypted-state handling.

The store bounds each registry, observation, probe and hybrid map to 4,096 rows, strategy rows to 16,384 and transport rows to 128. Ephemeral write recency and lexical ties select eviction; actual Brain producers retain the rows they touch. These are entry limits, not exact heap limits. Load reads at most 16 MiB plus one refusal byte from the actual descriptor, trims historical state in RAM and leaves its disk file clean and unchanged. Flush refuses oversized plaintext or sealed output before replacing the old file. Serialization, revision capture and sealing run in one blocking worker with the original owned flush lease; the live read guard is dropped before sealing, and the original asynchronous private writer clears dirty state only against the same live revision. Cancelling the waiter does not abort a started blocking worker or release its lease early. Startup key lookup and AEAD decryption now run in a blocking worker owning the path and original bounded input, before the separate parse/retention worker. Its original crypto result returns to the async caller, which alone applies missing-key quarantine; other crypto/I/O failures remain fatal. A started worker is not abortable and never performs state quarantine or state writes. This establishes placement, not a native key-provider latency, heap or blocking-pool admission guarantee. Snapshot clones, update/selector scans, transient allocation and cross-store blocking admission remain separate limitations. Six actual preparation/progress/write/load/cancellation tests pass; they do not measure native key-provider latency.

## Key files

- [mod.rs](mod.rs)
- [schema.rs](schema.rs)
- [persist.rs](persist.rs)
- [Flush preparation and ownership tests](flush_preparation_tests.rs)
- [Decrypt-entry placement regressions](decrypt_preparation_tests.rs) — two actual failures on the original synchronous baseline become three candidate passes, including the unchanged tampered-blob control. Root's final local suite passes 70 state-v2 and 14 secret-state methods; one native key-store method stays ignored. Actual owned-input borrow and synthetic PrivateFile AEAD check placement, not OS-key-provider latency; exact-commit CI remains required. Key-store contention uses nonblocking `try_lock`, so an independently held lock is not evidence of async lock-wait starvation.
- [bounds.rs](bounds.rs)
- [Bounds and retention tests](bounds_tests/README.md)

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-core --lib state_v2
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-core](../../README.md).

[Repository overview](../../../README.md) · [Parent directory](../README.md)
