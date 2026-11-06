# QUIC module boundaries

lib.rs exposes crypto, fingerprint, packet levels and session interfaces, and gates config and private FFI behind boring.

### Contracts and limits

Keep RFC crypto primitives usable without the handshake feature. Historical milestone text in source is not a current release acceptance receipt. Configuration must retain certificate validation independently of browser-like extensions.

### Entry points and maintenance

Follow the local module READMEs for crypto vectors, ClientHello configuration, unsafe callback ownership, fingerprint extraction and session transitions.

### Local map

- [error.rs](error.rs)
- [level.rs](level.rs)
- [lib.rs](lib.rs)
- [config/](config/README.md)
- [crypto/](crypto/README.md)
- [ffi/](ffi/README.md)
- [fingerprint/](fingerprint/README.md)
- [session/](session/README.md)

See the [parent guide](../README.md) for the enclosing component and runtime scope.
