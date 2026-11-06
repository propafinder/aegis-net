# Knowledge data and manifest

Browser JA3 targets, reference timing and regional DPI YAML documents are embedded by the crate and described by manifest.json.

### Contracts and limits

A corpus edit requires matching integrity metadata and review of schema, IDs, weights and provenance. Regional labels are reference material, not current verified network observations. Never place device credentials or captured user content here.

### Entry points and maintenance

Read the parent README and src/manifest.rs, src/integrity.rs and src/corpus.rs before changing data. tests/knowledge.rs covers loading and integrity behavior.

### Local map

- [dpi-signatures-cn.yaml](dpi-signatures-cn.yaml)
- [dpi-signatures-ir.yaml](dpi-signatures-ir.yaml)
- [dpi-signatures-ru.yaml](dpi-signatures-ru.yaml)
- [ja3-browser-corpus.json](ja3-browser-corpus.json)
- [manifest.json](manifest.json)
- [reference-timing.json](reference-timing.json)

See the [parent guide](../README.md) for the enclosing component and runtime scope.
