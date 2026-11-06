# aegis-client/src/relay/endpoint_bandit

Tests of optional admitted numeric endpoint-pool learning.

## Contract

The parent endpoint_bandit.rs records explicit attempts and verified outcomes under bounded context/lifetime state. It performs no probing or authentication replay. Tests must preserve cooldown, fail-closed state, retirement and one-observation-per-attempt behavior; synthetic outcomes are not field acceptance.

## Key files

- [tests.rs](tests.rs)

The enclosing module is [endpoint_bandit.rs](../endpoint_bandit.rs); this directory contains its split implementation or test modules.

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-client --bin aegis-client relay::endpoint_bandit
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-client](../../../README.md).

[Repository overview](../../../../README.md) · [Parent directory](../README.md)
