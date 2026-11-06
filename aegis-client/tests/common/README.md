# aegis-client/tests/common

Shared local subprocess, socket, TOML, private-file and readiness fixtures.

## Contract

The synthetic token and locally generated material are test-only. write_private_file mirrors credential-custody rules, including Windows permissions. Preserve child teardown and bounded waits so a failed test cannot leave a listening process behind.

## Key files

- [mod.rs](mod.rs)

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-client --tests
```

Shared support directories are included by their parent suites, not standalone Cargo test targets.

For dependency features and launch procedures, see [aegis-client](../../README.md).

[Repository overview](../../../README.md) · [Parent directory](../README.md)
