# aegis-server/src/phase_witness

Fixed aggregate I/O observations for explicitly owned server diagnostics.

## Contract

io_progress.rs counts API polls, readiness, bytes and error kinds. It records no payload or peer identity and does not prove wire delivery or a total event order. Retain bounded aggregate state and cancellation behavior when adding witness wrappers.

## Key files

- [io_progress.rs](io_progress.rs)
- [io_progress_tests.rs](io_progress_tests.rs)

The enclosing module is [phase_witness.rs](../phase_witness.rs); this directory contains its split implementation or test modules.

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-server --lib phase_witness
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-server](../../README.md).

[Repository overview](../../../README.md) · [Parent directory](../README.md)
