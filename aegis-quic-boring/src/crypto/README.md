# RFC 9001 packet cryptography

Initial secrets, HKDF derivation, packet keys, header protection, Retry integrity and subsequent key material are implemented separately from the BoringSSL handshake.

### Contracts and limits

These standard algorithms are common to QUIC stacks and do not determine a Chrome fingerprint. Preserve checked key lengths, packet-number handling and secret disposal; never use successful vector tests as a wire-privacy claim.

### Entry points and maintenance

initial.rs, hkdf.rs and keys.rs define derivation; packet.rs/header.rs perform protection and retry.rs covers Retry. Inline tests include RFC-vector checks.

### Local map

- [header.rs](header.rs)
- [hkdf.rs](hkdf.rs)
- [initial.rs](initial.rs)
- [keys.rs](keys.rs)
- [mod.rs](mod.rs)
- [packet.rs](packet.rs)
- [retry.rs](retry.rs)
- [secrets.rs](secrets.rs)
- [suite.rs](suite.rs)

See the [parent guide](../README.md) for the enclosing component and runtime scope.
