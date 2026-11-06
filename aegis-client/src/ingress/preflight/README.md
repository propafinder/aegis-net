# aegis-client/src/ingress/preflight

Typed startup reports, hints, backend selection diagnostics and runtime probes.

## Contract

types.rs is the report vocabulary; helpers.rs maps platform/configuration decisions; runtime.rs owns probes. Validate rollout intent before selecting fallback so policy errors remain deterministic across OSes. Keep JSON reason codes aligned with public startup diagnostics.

## Key files

- [types.rs](types.rs)
- [helpers.rs](helpers.rs)
- [runtime.rs](runtime.rs)

The enclosing module is [preflight.rs](../preflight.rs); this directory contains its split implementation or test modules.

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-client --bin aegis-client ingress::preflight
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-client](../../../README.md).

[Repository overview](../../../../README.md) · [Parent directory](../README.md)
