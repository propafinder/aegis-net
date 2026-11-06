# aegis-core/src/protocols

TLS handshake parsing and editing, JA3/JA3S helpers and limited QUIC Initial inspection.

## Contract

These modules work with protocol bytes. Preserve structural length checks and distinguish TLS record edits from a complete TLS implementation. QUIC padding/coalescing helpers and fingerprint strings are observations or heuristics, not proof of browser equivalence or a negotiated connection.

`tls_modify` rewrites one complete ClientHello occupying the first TLS record.
It checks every extension and all resulting lengths before changing bytes;
an error preserves the input. Handshakes fragmented across records or sharing
the first record with another handshake are rejected. Later records remain
unchanged. This is structural validation, not a TLS implementation or reassembly.

## Key files

- [mod.rs](mod.rs)
- [tls.rs](tls.rs)
- [tls_parse.rs](tls_parse.rs)
- [tls_modify.rs](tls_modify.rs)
- [ja3.rs](ja3.rs)
- [quic.rs](quic.rs)

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-core --lib protocols
cargo test --locked -p aegis-core --test tls_modify_tests
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-core](../../README.md).

[Repository overview](../../../README.md) · [Parent directory](../README.md)
