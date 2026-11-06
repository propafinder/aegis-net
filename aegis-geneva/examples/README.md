# aegis-geneva/examples

Seeded offline strategy training against a configured censor model.

## Contract

train.rs prints the evolved strategy and modeled score. Model parameters and required payload delivery are part of the experiment; a hidden or broken stream is not a successful evasion. Repeatability is tied to the supplied RNG seed and model, not a guarantee on live networks.

## Key files

- [train.rs](train.rs)

## Development and checks

Run from the repository root:

```sh
cargo build --locked -p aegis-geneva --examples
```

Building an example does not run it. Read the example entrypoint before executing an offline or native experiment.

For dependency features and launch procedures, see [aegis-geneva](../README.md).

[Repository overview](../../README.md) · [Parent directory](../README.md)
