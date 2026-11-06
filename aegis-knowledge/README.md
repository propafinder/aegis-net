# aegis-knowledge

`aegis-knowledge` is an independent seed corpus and static-prior tool.
No other workspace crate declares it as a dependency, and the runtime has no
adapter that calls `Knowledge::priors_for` to feed its corpus into Brain.
Brain can consume independently supplied `ExternalCalibrationSnapshot.knowledge`
entries; that path does not automatically import this crate's corpus. See the
[knowledge architecture](../docs/architecture/27-knowledge-architecture.md)
for the separate boundaries.

Current scope:

- load an embedded seed browser fingerprint corpus,
- load embedded DPI signature documents as opaque regional evidence,
- verify all embedded corpus files against `data/manifest.json`,
- produce deterministic prior scores for a transport/region descriptor.

The initial data is deliberately conservative and marked as seed corpus data.
It is not a censorship-resistance claim by itself; it is the structure that
future reviewed corpus refreshes will fill.

## Local source and maintenance guide

Versioned embedded data and conservative static priors, kept independent of live relay/session code.

### Contracts and limits

Manifest hashes bind corpus bytes, not accuracy or freshness of regional DPI claims. Static priors need actual runtime outcomes and cannot certify censorship resistance.

### Entry points and maintenance

Use `Knowledge::load_embedded`; the CLI exports and validates refresh dry-run and JA3-target artifacts through `refresh-dry-run`, `validate-refresh-dry-run`, `export-ja3-targets` and `validate-ja3-targets`.

Use a built executable to inspect the command surface or build identity:

```text
aegis-knowledge refresh-dry-run
```

### Local map

- [Cargo.toml](Cargo.toml)
- [data/](data/README.md)
- [src/](src/README.md)
- [tests/](tests/README.md)

### Workspace build

From the repository root, with the locked dependencies and the required target toolchain available:

```bash
cargo check --locked -p aegis-knowledge
cargo test --locked -p aegis-knowledge
```

## Documentation responsibility

This README owns this module’s purpose and entrypoints. Shared procedures live
in the [focused guide](../docs/architecture/27-knowledge-architecture.md); cross-component boundaries are in
[component ownership](../docs/architecture/OWNERSHIP.md). Link to those documents
when changing a shared contract; do not duplicate their instructions here.
