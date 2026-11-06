# aegis-core/tests/common

Synthetic ClientHello construction shared by integration tests.

## Contract

mod.rs builds a minimal TLS ClientHello carrying SNI. This deliberately small fixture is for byte parsing/editing regressions, not a Chrome capture or a complete handshake. Change expected record lengths with the fixture when extending it.

## Key files

- [mod.rs](mod.rs)

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-core --tests
```

Shared support directories are included by their parent suites, not standalone Cargo test targets.

For dependency features and launch procedures, see [aegis-core](../../README.md).

[Repository overview](../../../README.md) · [Parent directory](../README.md)
