# aegis-core/src/signals

Connection outcome classification and runtime metric vocabulary consumed by Brain.

## Contract

classify.rs turns an explicit OutcomeContext into FailSignal; metrics.rs tracks observed events. Classification is a runtime interpretation of observations, not a censor identity or reachability proof. Keep failure categories stable for their selection and event consumers.

## Key files

- [mod.rs](mod.rs)
- [classify.rs](classify.rs)
- [metrics.rs](metrics.rs)

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-core --lib signals
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-core](../../README.md).

[Repository overview](../../../README.md) · [Parent directory](../README.md)
