# QUIC TLS session adapter

Client configuration and handshake-data/state helpers drive the TLS session and feed keys and crypto data to quinn-proto.

### Contracts and limits

Keep handshake state, key installation and certificate checks synchronized. Native-handshake implementation is feature-gated; a default-feature build does not exercise the BoringSSL driver. Dropping a session must retain its native resource ownership.

### Entry points and maintenance

client_config.rs chooses configuration, tls_session.rs drives the handshake, state.rs tracks keys and handshake_data.rs exposes negotiated information.

### Local map

- [client_config.rs](client_config.rs)
- [handshake_data.rs](handshake_data.rs)
- [mod.rs](mod.rs)
- [state.rs](state.rs)
- [tls_session.rs](tls_session.rs)

See the [parent guide](../README.md) for the enclosing component and runtime scope.
