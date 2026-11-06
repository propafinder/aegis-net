# aegis-geneva/src/actions

Pure duplicate, fragment, header tamper and payload tamper primitives.

## Contract

Every primitive operates on packet models with explicit randomness where required. IP fragmentation differs from TCP segmentation; sequence numbers and headers must reflect the selected layer. Drop is represented by no output in the engine. A decoy that damages real server delivery cannot be scored as success.

## Key files

- [mod.rs](mod.rs)
- [duplicate.rs](duplicate.rs)
- [fragment.rs](fragment.rs)
- [tamper.rs](tamper.rs)
- [payload.rs](payload.rs)

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-geneva --lib actions
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-geneva](../../README.md).

[Repository overview](../../../README.md) · [Parent directory](../README.md)
