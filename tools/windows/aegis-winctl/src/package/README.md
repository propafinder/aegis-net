# Kit, adapter and research-tool trust

trust.rs verifies publisher policy/signatures; adapter.rs holds and validates reviewed adapter entry custody; research.rs validates the paired research-operator inventory and build metadata.

### Contracts and limits

Ed25519 delivery trust is distinct from Authenticode. Adapter entry custody does not freeze arbitrary imported modules or a remote signing provider. For signed research tools retain the unsigned producer hash→original candidate→provider-attested signed output relation; signed and unsigned hashes differ.

### Entry points and maintenance

The parent ../package.rs validates complete kits. Preserve legacy schema compatibility while enforcing the complete research pair, exact source/lock/target/tool versions and capabilities for the newer research schemas.

### Local map

- [adapter.rs](adapter.rs)
- [research.rs](research.rs)
- [trust.rs](trust.rs)

See the [parent guide](../README.md) for the enclosing component and runtime scope.
