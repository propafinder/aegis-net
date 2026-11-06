# aegis-geneva/src/censor

Deterministic inspection and path-distance censor models for offline scoring.

## Contract

model.rs separates detection from payload arrival; inspection.rs varies reassembly, checksum and RST handling; path.rs supplies hop-distance visibility. These are assumptions of an experiment, not measured deployment facts. A strategy must hide the forbidden content while delivering the required endpoint payload.

## Key files

- [mod.rs](mod.rs)
- [model.rs](model.rs)
- [inspection.rs](inspection.rs)
- [path.rs](path.rs)

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-geneva --lib censor
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-geneva](../../README.md).

[Repository overview](../../../README.md) · [Parent directory](../README.md)
