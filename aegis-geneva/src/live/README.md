# aegis-geneva/src/live

Bounded pure transforms over explicit Ethernet/IPv4 wire images and finite local strategy loading.

## Contract

program.rs keeps live forest state and evaluates matching trees on the original image. wire.rs preserves deliberate checksum/data-offset tampering and refuses unsupported expansion. dns.rs and options.rs bound representable edits; input.rs refuses symlink/FIFO/device strategy inputs. Socket I/O belongs exclusively to the opt-in executable.

## Key files

- [mod.rs](mod.rs)
- [program.rs](program.rs)
- [wire.rs](wire.rs)
- [dns.rs](dns.rs)
- [options.rs](options.rs)
- [values.rs](values.rs)
- [input.rs](input.rs)

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-geneva --lib live
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-geneva](../../README.md).

[Repository overview](../../../README.md) · [Parent directory](../README.md)
