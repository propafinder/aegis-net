# Phase C relay and delivery evidence

These files assemble and render multi-relay, bundle-mirror and delivery-related evidence from supplied manifests, hashes and archives.

### Contracts and limits

Archive entries and a bundle hash establish content facts, not mirror availability or current network access. Multi-relay observations must not be inferred from a list of configured hosts. A report does not publish files or provision a pool.

### Entry points and maintenance

evidence.rs contains builders; evidence_support.rs reads bundle/hash details; reviews.rs consumes the resulting evidence; output modules render it. Follow ../phase_c.rs and its dispatcher for commands.

### Local map

- [evidence.rs](evidence.rs)
- [evidence_output.rs](evidence_output.rs)
- [evidence_support.rs](evidence_support.rs)
- [reviews.rs](reviews.rs)
- [support.rs](support.rs)

See the [parent guide](../README.md) for the enclosing component and runtime scope.
