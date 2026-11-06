# aegis-geneva/src

Offline Geneva library and bounded pure execution over explicit wire images.

## Contract

lib.rs exposes packet, syntax, actions, engine, censor and evolve. live/ has pure finite byte transforms, while only bin/bridge.rs owns sockets. The historical model runner uses first-match semantics; the live Program evaluates every matching tree against the original image, so do not conflate these execution contracts.

## Key files

- [lib.rs](lib.rs)
- [error.rs](error.rs)

## Directories

| Directory | Responsibility |
| --- | --- |
| [actions/](actions/README.md) | Pure duplicate, fragment, header tamper and payload tamper primitives. |
| [bin/](bin/README.md) | Opt-in Linux AF_PACKET bridge executable. |
| [censor/](censor/README.md) | Deterministic inspection and path-distance censor models for offline scoring. |
| [engine/](engine/README.md) | Pure packets-in/packets-out strategy evaluator with explicit RNG. |
| [evolve/](evolve/README.md) | Bounded random generation, mutation, crossover, model fitness and generational search. |
| [live/](live/README.md) | Bounded pure transforms over explicit Ethernet/IPv4 wire images and finite local strategy loading. |
| [packet/](packet/README.md) | Offline packet model, TCP flag helpers and typed PROTO:field addressing. |
| [syntax/](syntax/README.md) | Strategy value types, triggers, action trees, parser and printer. |

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-geneva --lib
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-geneva](../README.md).

[Repository overview](../../README.md) · [Parent directory](../README.md)
