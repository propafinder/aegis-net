# QUIC crypto and handshake provider

Rust QUIC key handling and a feature-gated AWS-LC/BoringSSL handshake adapter for quinn-proto. The default feature set is empty.

### Contracts and limits

RFC 9001 crypto correctness and ClientHello fingerprint configuration are separate concerns. The boring feature enables handshake/config/FFI code; a successful build or JA4 comparison does not certify all browser behavior or a live censorship path.

### Entry points and maintenance

Start at src/lib.rs. The library separates crypto, config, session, ffi and fingerprint parsing; examples and tests document capture and comparison formats.

### Local map

- [Cargo.toml](Cargo.toml)
- [examples/](examples/README.md)
- [src/](src/README.md)
- [tests/](tests/README.md)

### Workspace build

From the repository root, with the locked dependencies and the required target toolchain available:

```bash
cargo check --locked -p aegis-quic-boring
cargo check --locked -p aegis-quic-boring --features boring
```

The second command enables the native AWS-LC handshake dependency. Default-feature checks exercise a narrower surface; browser comparison tests require their separate browser and feature prerequisites.

## Documentation responsibility

This README owns this module’s purpose and entrypoints. Shared procedures live
in the [focused guide](../docs/transports/README.md); cross-component boundaries are in
[component ownership](../docs/architecture/OWNERSHIP.md). Link to those documents
when changing a shared contract; do not duplicate their instructions here.
