# aegis-geneva

Geneva-style strategy DSL, pure packet actions, modeled censors, seeded genetic training and opt-in Linux wire bridge.

## Contract

Offline engine/trainer runs without socket I/O. The live-linux feature enables a separate bounded AF_PACKET bridge; it does not replace client wide interception. A model win means a candidate for controlled testing, not evidence of a real censor bypass.

## Key files

- [Cargo.toml](Cargo.toml)
- [src/lib.rs](src/lib.rs)
- [examples/train.rs](examples/train.rs)
- [src/bin/bridge.rs](src/bin/bridge.rs)

## Directories

| Directory | Responsibility |
| --- | --- |
| [examples/](examples/README.md) | Seeded offline strategy training against a configured censor model. |
| [src/](src/README.md) | Offline Geneva library and bounded pure execution over explicit wire images. |

## Dependencies

Default library dependencies are rand and thiserror. live-linux adds libc for the separate Linux bridge binary. The offline packet engine and trainer do not need a network service.

## Offline development

Run from the repository root:

```sh
cargo test --locked -p aegis-geneva
cargo run --locked --release -p aegis-geneva --example train
cargo build --locked -p aegis-geneva --features live-linux --bin aegis-geneva-bridge
```

The training example is offline and seeded. The final command only builds the optional executable; a native bridge run requires explicitly prepared isolated Linux interfaces and a reviewed bounded strategy. Review [Geneva roadmap](../docs/GENEVA-ROADMAP.md) and the [relay integration](../aegis-core/src/relay_geneva/README.md) before changing wire behavior.

[Repository overview](../README.md)

## Documentation responsibility

This README owns this module’s purpose and entrypoints. Shared procedures live
in the [focused guide](../docs/transports/README.md); cross-component boundaries are in
[component ownership](../docs/architecture/OWNERSHIP.md). Link to those documents
when changing a shared contract; do not duplicate their instructions here.
