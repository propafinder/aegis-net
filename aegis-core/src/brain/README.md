# aegis-core/src/brain

Adaptive strategy ordering, observations, failure beliefs, health, probing and
explanations for direct connections, hybrid Geneva product routes and configured
relay transport ordering.

## Contract

StrategyKey supplies context for learned state. Selection is constrained by admitted capabilities and configured candidates; a high score cannot create a working route or authorize a target. Keep explanatory traces consistent with the observation and retry decisions that produced them.

The baseline combines bounded Beta-shaped trust smoothing with a UCB-style
bonus and probe bias; `posterior`/`ucb1` event names are compatibility labels,
not a classical statistical guarantee. Capture trust reduces confidence trial
mass; the exploration denominator uses context-weighted observed trials before
capture trust, so lower trust does not inflate that bonus by itself. Traces
retain the trust-weighted estimated trial count and actual exploration bonus.
The corrected baseline source excludes
snapshot hard blocks from epsilon and exploitation selected orders, retaining
blocked exploitation diagnostics. The legacy relay ordering leaf preserves the
calibration-backed selected set, including an empty all-blocked order, while
uncalibrated cold/epsilon guards retain the configured order. These source
repairs require exact-commit regression/CI evidence and do not establish
installed acceptance. The optional recent-route selector has its own exclusion policy.
See [actual scoring and admission](../../../docs/architecture/27-knowledge-architecture.md)
for the thresholds, global trial guard and independent seed-corpus boundary.

The installed client constructs runtime state in RAM by default. Its
`[direct] persist_state` opt-in enables disk learning only in direct/auto mode;
relay and forensic modes remain RAM-only. This policy is applied before state
paths are opened. Library callers choosing `AsyncStateStore::load` themselves
still own persistence and retention. See [private diagnostics](../../../docs/operations/private-diagnostics.md)
for destination-history and key-storage limits.

## Key files

- [mod.rs](mod.rs)
- [carrier_failover.rs](carrier_failover.rs) — ordered carrier failover (CP-D3)
- [key.rs](key.rs)
- [observation.rs](observation.rs)
- [selection.rs](selection.rs)
- [scoring.rs](scoring.rs)
- [probe.rs](probe.rs)
- [recent_routes.rs](recent_routes.rs)
- [tests.rs](tests.rs)
- [bounds_tests.rs](bounds_tests.rs)
- [retention_tests.rs](retention_tests.rs)

## Bounded learning state

Brain records explicit touches for the rows its real producers update. The
store keeps recency under the same snapshot lock, so current observations
survive bounded eviction while the existing revision/dirty and writer-lease
rules remain. Recency starts over after loading; it is neither persisted LRU
nor a destination expiry policy. Collection/file limits and serialization
limitations belong to [state_v2](../state_v2/README.md). The controls exercise
actual Brain updates and current-key retention rather than a separate model.

## Directories

| Directory | Responsibility |
| --- | --- |
| [recent_routes/](recent_routes/README.md) | Optional recent-route estimators and teacher-forced offline replay. |

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-core --lib brain
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-core](../../README.md).

[Repository overview](../../../README.md) · [Parent directory](../README.md)

## Policy before hostname resolution

[hybrid_route_learning.rs](hybrid_route_learning.rs) exposes a read-only
hostname-independent relay advisory. It reuses capability and fresh classifier
policy from the normal route selector without fabricating a destination key,
recording an attempt or persisting state. Address-family and learned per-address
decisions still follow resolution. The caller owns credential/transport
admission; an advisory does not authorize a target or prove delivery.

## Ordered carrier failover

[carrier_failover.rs](carrier_failover.rs) is a pure per-network circuit
breaker over a profile's explicit ordered carrier pool: usable carriers in
profile order, a single-flight trial for an expired preferred carrier,
carriers in cooldown kept as last resort, bounded exponential backoff and an
LRU-bounded per-network memory keyed by an opaque salted digest. It does not
add carriers, choose transport families, authorize targets or produce a
native-egress outcome. Runtime glue and the signal mapping live in the client
relay module; see [the design](../../../docs/transports/brain-failover-design.md).
