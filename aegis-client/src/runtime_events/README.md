# aegis-client/src/runtime_events

Regression tests for the client event-code catalog.

## Contract

The parent runtime_events.rs maps fixed event enums to public codes and surfaces. Keep mappings unique and stable because reports and automation consume them. Event names describe runtime observations; they are not independent evidence that a packet reached its destination.

## Key files

- [tests.rs](tests.rs)

The enclosing module is [runtime_events.rs](../runtime_events.rs); this directory contains its split implementation or test modules.

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-client --bin aegis-client runtime_events
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-client](../../README.md).

[Repository overview](../../../README.md) · [Parent directory](../README.md)
