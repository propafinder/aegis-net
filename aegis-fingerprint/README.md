# TLS fingerprint helpers

A thin Rust facade over aegis-core TLS parsing, consumed by [witness tooling](../tools/witness/README.md). `tools/witness/Cargo.toml` is the only workspace consumer manifest that declares this crate; no calibration-tool dependency is declared. It exposes ClientHello material, JA3 helpers, GREASE sampling and a legacy TLS 1.2 audit.

### Contracts and limits

Fingerprints describe parsed structure. Matching JA3 or a browser-like extension list does not demonstrate identical browser behavior, DPI resistance or origin authentication. SNI and ALPN can be sensitive metadata.

### Entry points and maintenance

Use classify_tls_client_hello for an optional parsed result and is_tls_client_hello as a structural heuristic. Source tests live beside each implementation.

### Local map

- [Cargo.toml](Cargo.toml)
- [src/](src/README.md)

### Workspace build

From the repository root, with the locked dependencies and the required target toolchain available:

```bash
cargo check --locked -p aegis-fingerprint
cargo test --locked -p aegis-fingerprint
```

## Documentation responsibility

This README owns this module’s purpose and entrypoints. Shared procedures live
in the [focused guide](../docs/testing/README.md); cross-component boundaries are in
[component ownership](../docs/architecture/OWNERSHIP.md). Link to those documents
when changing a shared contract; do not duplicate their instructions here.
