# aegis-geneva/src/syntax

Strategy value types, triggers, action trees, parser and printer.

## Contract

strategy.rs holds outbound and inbound rule lists; parse.rs reports malformed DSL locations. Offline application is ordered first-match with unmatched pass-through. Live program execution has a separate multiple-match contract; a parser change must keep representation and both consumers consistent.

## Key files

- [mod.rs](mod.rs)
- [strategy.rs](strategy.rs)
- [action.rs](action.rs)
- [trigger.rs](trigger.rs)
- [parse.rs](parse.rs)

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-geneva --lib syntax
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-geneva](../../README.md).

[Repository overview](../../../README.md) · [Parent directory](../README.md)
