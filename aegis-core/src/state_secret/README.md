# aegis-core/src/state_secret

The explicit storage backend for encrypted Brain-state keys.

## Contract

key_store.rs supports private files, native OS credential stores and systemd-provided credentials. It never silently downgrades or backs up an OS credential into an adjacent exportable file. Private-file permissions are not protection of a copied disk. The parent state_secret.rs owns encryption and key derivation.

## Key files

- [key_store.rs](key_store.rs)

The enclosing module is [state_secret.rs](../state_secret.rs); this directory contains its split implementation or test modules.

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-core --lib state_secret
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-core](../../README.md).

[Repository overview](../../../README.md) · [Parent directory](../README.md)
