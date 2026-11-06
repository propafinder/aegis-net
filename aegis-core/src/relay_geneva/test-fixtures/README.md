# aegis-core/src/relay_geneva/test-fixtures

Public nftables JSON fixture for canonical policy comparison.

## Contract

nft-tcp-dependency-elided-1.0.9.json captures a representation where redundant TCP dependencies are elided. Its addresses and objects are test inputs, not installation instructions. Keep semantic rule/expression order intact when updating readback normalization tests.

## Key files

- [nft-tcp-dependency-elided-1.0.9.json](nft-tcp-dependency-elided-1.0.9.json)

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-core --lib relay_geneva::test-fixtures
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-core](../../../README.md).

[Repository overview](../../../../README.md) · [Parent directory](../README.md)
