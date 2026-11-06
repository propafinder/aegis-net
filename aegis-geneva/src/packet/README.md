# aegis-geneva/src/packet

Offline packet model, TCP flag helpers and typed PROTO:field addressing.

## Contract

model.rs represents headers and payload rather than raw wire bytes. field.rs is the single reviewable field vocabulary shared by triggers and tamper actions. Keep absent-layer behavior explicit; serialization and real checksum semantics belong to the execution adapter.

## Key files

- [mod.rs](mod.rs)
- [model.rs](model.rs)
- [field.rs](field.rs)

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-geneva --lib packet
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-geneva](../../README.md).

[Repository overview](../../../README.md) · [Parent directory](../README.md)
