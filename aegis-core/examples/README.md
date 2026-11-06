# aegis-core/examples

A controlled native relay-Geneva probe, separate from normal client traffic.

## Contract

relay_geneva_native_probe.rs exercises an explicitly owned native path without an application target, identity or fallback dial. Treat its native prerequisites and bounded operation as a lab procedure; compiling this example does not activate it or establish network acceptance.

## Key files

- [relay_geneva_native_probe.rs](relay_geneva_native_probe.rs)

## Development and checks

Run from the repository root:

```sh
cargo build --locked -p aegis-core --examples
```

Building an example does not run it. Read the example entrypoint before executing an offline or native experiment.

For dependency features and launch procedures, see [aegis-core](../README.md).

[Repository overview](../../README.md) · [Parent directory](../README.md)
