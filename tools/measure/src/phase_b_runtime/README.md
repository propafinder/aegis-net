# Phase B runtime evidence reviews

manifest.rs enumerates runtime evidence paths; reviews.rs inspects TLS-wire, relay-shape and related event streams; support.rs centralizes event field access.

### Contracts and limits

Runtime JSONL, wire witness data and correlation are separate evidence. A shape-diversity record is not packet capture, browser equivalence or proof against DPI. Preserve unknown/missing artifacts and correlation constraints.

### Entry points and maintenance

Called through ../phase_b_runtime.rs and the Phase B dispatcher. Keep each manifest path’s role and JSON schema stable when extending reviews.

### Local map

- [manifest.rs](manifest.rs)
- [reviews.rs](reviews.rs)
- [support.rs](support.rs)

See the [parent guide](../README.md) for the enclosing component and runtime scope.
