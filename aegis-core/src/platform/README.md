# aegis-core/src/platform

Cross-platform installation layout vocabulary, currently containing the Windows layout implementation.

## Contract

These types locate client binaries, configuration, state and event files; they do not install services or configure networking. Keep installation scope explicit because user and system layouts have different roots.

## Key files

- [mod.rs](mod.rs)

## Directories

| Directory | Responsibility |
| --- | --- |
| [windows/](windows/README.md) | Windows user/system installation paths and layout helpers. |

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-core --lib platform
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-core](../../README.md).

[Repository overview](../../../README.md) · [Parent directory](../README.md)
