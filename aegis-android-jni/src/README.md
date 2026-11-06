# JNI exports and status contract

lib.rs owns opaque JNI pointer types, exported symbol names, the static C status string and host-testable AndroidReachStatus.

### Contracts and limits

Opaque pointers do not provide JNIEnv string allocation. Preserve null/0 behavior until a real JNI bridge is implemented, and update callers and evidence together rather than setting readiness booleans.

### Entry points and maintenance

The parent Cargo.toml selects library outputs. Inline tests assert the proof-only status fields; they do not execute Android or VpnService.

### Local map

- [lib.rs](lib.rs)

See the [parent guide](../README.md) for the enclosing component and runtime scope.
