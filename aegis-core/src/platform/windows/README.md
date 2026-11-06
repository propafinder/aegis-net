# aegis-core/src/platform/windows

Windows user/system installation paths and layout helpers.

## Contract

WindowsPathRoots separates environment-derived roots from deterministic layout construction. Test or review layout changes with explicit roots; do not infer that a path choice provides filesystem permissions or service authorization.

## Key files

- [mod.rs](mod.rs)

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-core --lib platform::windows
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

Native Windows code is target-gated; a non-Windows test run does not cover native APIs.

For dependency features and launch procedures, see [aegis-core](../../../README.md).

[Repository overview](../../../../README.md) · [Parent directory](../README.md)
