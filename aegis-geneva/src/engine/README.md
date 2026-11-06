# aegis-geneva/src/engine

Pure packets-in/packets-out strategy evaluator with explicit RNG.

## Contract

apply.rs caps expansion so nested duplication cannot emit an unbounded burst. Reproduce a result using its packet input, strategy and RNG seed. Model execution follows the offline first-match contract; use live/program.rs for original-image multiple-tree wire execution.

## Key files

- [mod.rs](mod.rs)
- [apply.rs](apply.rs)

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-geneva --lib engine
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-geneva](../../README.md).

[Repository overview](../../../README.md) · [Parent directory](../README.md)
