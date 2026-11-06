# BoringSSL callback ownership

Private bindings, SSL RAII and QUIC callbacks bridge the native handshake to Rust-owned session state when boring is enabled.

### Contracts and limits

Unsafe code must retain the lifetime of ex_data/session pointers and buffers for each callback. The process-wide ex_data index is not a session owner. Do not let native callbacks outlive SSL/session custody or export borrowed pointers.

### Entry points and maintenance

Read ssl.rs, ex_data.rs and quic_method.rs together with session/tls_session.rs before altering callback order or error handling.

### Local map

- [ex_data.rs](ex_data.rs)
- [mod.rs](mod.rs)
- [quic_method.rs](quic_method.rs)
- [ssl.rs](ssl.rs)

See the [parent guide](../README.md) for the enclosing component and runtime scope.
