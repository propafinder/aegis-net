# Fingerprint implementation

lib.rs combines the core ClientHello parser with groups, SNI, ALPN and JA3; grease.rs provides RFC 8701 values; legacy_tls12_audit.rs checks legacy-extension expectations.

### Contracts and limits

Keep malformed-record refusal and GREASE handling aligned with the core parser. The MD5 value is a JA3 identifier, not a cryptographic integrity or authentication mechanism.

### Entry points and maintenance

Public consumers import the parent crate. Inline fixtures check deterministic parsing and audits; they are not independent captures.

### Local map

- [grease.rs](grease.rs)
- [legacy_tls12_audit.rs](legacy_tls12_audit.rs)
- [lib.rs](lib.rs)

See the [parent guide](../README.md) for the enclosing component and runtime scope.
