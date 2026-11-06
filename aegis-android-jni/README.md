# Android JNI proof surface

A minimal Rust library exporting the JNI C ABI names expected by an Android bridge. It builds as cdylib and rlib; its pure Rust status helpers can be exercised on a host.

### Contracts and limits

The Java string entrypoints currently return null, and nativeVpnServiceFlowReady returns 0. The status explicitly reports no VpnService flow and no production Android claim. Loading symbols is not a working VPN, Kotlin bridge or packaged Android application.

### Entry points and maintenance

Start at src/lib.rs and its inline status tests. Consumers must not interpret rust_jni_core_compiles as successful Android networking.

### Local map

- [Cargo.toml](Cargo.toml)
- [src/](src/README.md)

### Workspace build

From the repository root, with the locked dependencies and the required target toolchain available:

```bash
cargo check --locked -p aegis-android-jni
cargo test --locked -p aegis-android-jni
```

A host build/test checks the Rust proof contract; it does not produce an accepted Android app or exercise VpnService. Android cross-compilation and the Java/Kotlin integration are separate work.

## Documentation responsibility

This README owns this module’s purpose and entrypoints. Shared procedures live
in the [focused guide](../docs/platforms/android/README.md); cross-component boundaries are in
[component ownership](../docs/architecture/OWNERSHIP.md). Link to those documents
when changing a shared contract; do not duplicate their instructions here.
