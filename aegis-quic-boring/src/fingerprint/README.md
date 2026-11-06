# QUIC Initial fingerprint extraction

initial_packet.rs handles public Initial packet processing, clienthello.rs parses recovered handshake material and ja4.rs builds structural fingerprint output.

### Contracts and limits

Initial secrets derive from the public destination connection ID. This tooling provides no access to later application secrets, and fingerprint equality alone is not proof of full Chrome equivalence. Malformed/truncated input must remain a refusal.

### Entry points and maintenance

Used by the capture example and the QUIC comparison tests; separate the captured bytes and their provenance from parser output.

### Local map

- [clienthello.rs](clienthello.rs)
- [initial_packet.rs](initial_packet.rs)
- [ja4.rs](ja4.rs)
- [mod.rs](mod.rs)

See the [parent guide](../README.md) for the enclosing component and runtime scope.
