# ClientHello and trust configuration

The boring-gated context builder selects cipher suites, groups, extension behavior, certificate compression, GREASE and platform trust handling.

### Contracts and limits

Browser-like configuration does not replace certificate verification. trust_anchor_hint carries a protocol hint rather than installing trust; Windows native CA paths need the existing Unicode handling. Certificate decompression must retain resource limits.

### Entry points and maintenance

mod.rs and ctx.rs connect these helpers to session configuration. Changes need actual first-flight comparison in addition to unit-level cipher/group checks.

### Local map

- [cert_compression.rs](cert_compression.rs)
- [ciphers.rs](ciphers.rs)
- [ctx.rs](ctx.rs)
- [extensions.rs](extensions.rs)
- [groups.rs](groups.rs)
- [mod.rs](mod.rs)
- [trust_anchor_hint.rs](trust_anchor_hint.rs)
- [windows_trust.rs](windows_trust.rs)

See the [parent guide](../README.md) for the enclosing component and runtime scope.

## TrustAnchorID platform policy

The production QUIC and TCP contexts omit the draft TrustAnchorID hint
(`0xca34`) on every platform while using locked AWS-LC 0.44. Its general custom
extension API appends the hint after the built-in permutation, so registering
it only on Windows produces a stable platform difference. The existing
`trust_anchor_hint.rs` helper and its malformed-response validator are retained
for future work; production context builders do not register that helper.

Omission gives this one extension a common policy. It does not establish
Chrome 152 fingerprint parity, native TrustAnchorID negotiation or resistance
to a network classifier. Enabling the hint requires a supported native API
that participates in permutation, protocol-response validation, and fresh
TCP/QUIC first-flight and browser captures on the supported platforms. A
custom-extension fallback must not be enabled silently.

Normal configured CA, hostname and IP verification remains required. The hint
never installs a trust anchor or substitutes for certificate verification.
The first-flight tests inspect the real adapter's emitted bytes; they do not
complete a trusted handshake or change a system trust store.
