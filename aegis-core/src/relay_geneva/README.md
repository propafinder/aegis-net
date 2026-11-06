# aegis-core/src/relay_geneva

Relay-only Geneva validation and Linux adapters for owned NFQUEUE traffic, durable guard transitions, recovery and selected teardown.

## Contract

Validated batches replace a dropped original; worker or validation failure closes the owned relay path instead of sending an untransformed fallback. Pure ownership models live beside privileged adapters. Recovery requires independent absence and exact policy proofs; names alone never authorize deletion or adoption. A deadline limits work but grants no authority.

## Key files

- [linux.rs](linux.rs)
- [linux_policy.rs](linux_policy.rs)
- [queue.rs](queue.rs)
- [stream.rs](stream.rs)
- [installed_guard.rs](installed_guard.rs)
- [installed_profile.rs](installed_profile.rs)
- [recovery.rs](recovery.rs)
- [teardown.rs](teardown.rs)

The enclosing module is [relay_geneva.rs](../relay_geneva.rs); this directory contains its split implementation or test modules.

## Directories

| Directory | Responsibility |
| --- | --- |
| [test-fixtures/](test-fixtures/README.md) | Public nftables JSON fixture for canonical policy comparison. |

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-core --lib relay_geneva
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-core](../../README.md).

[Repository overview](../../../README.md) · [Parent directory](../README.md)
