# aegis-client/src/relay/masque_crypto

Required-ECH QUIC TLS handshake tests for the MASQUE crypto builder.

## Contract

ech_tests.rs drives real TLS handshake state against an in-memory AWS-LC ECH server using the production builder. It requires chrome-like-tls and writes only public fixture certificates. GREASE acceptance and permissive verifiers must not substitute for required-ECH acceptance.

## Key files

- [ech_tests.rs](ech_tests.rs)

The enclosing module is [masque_crypto.rs](../masque_crypto.rs); this directory contains its split implementation or test modules.

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-client --features chrome-like-tls --bin aegis-client relay::masque_crypto
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

Enable `chrome-like-tls` to cover the optional AWS-LC/ECH implementation; Windows-specific modules additionally require Windows.

For dependency features and launch procedures, see [aegis-client](../../../README.md).

[Repository overview](../../../../README.md) · [Parent directory](../README.md)


## Explicit configured anchors

`relay.masque_trust_mode = "configured_ca_only"` requires a nonempty usable
public PEM CA bundle at `masque_ca_cert`, or `ca_cert` when the MASQUE-specific
path is absent. The MASQUE Rustls builder reads a fresh regular descriptor with
a 4 MiB input ceiling and rejects missing, empty, oversized, unparsable or
unusable anchors before connecting. Chrome QUIC uses its existing `CaFile`
policy; any Rustls backend fallback keeps only the configured anchors. Platform
roots are excluded in this mode. Omission, or `"system_and_configured_ca"`,
preserves the existing platform-plus-configured-CA selection. TCP trust is
unchanged.

[configured_anchor_tests.rs](configured_anchor_tests.rs) exercises the actual
crypto builders with owned loopback TLS 1.3/H3 peers, sealed CONNECT-UDP
credentials and distinct bidirectional markers. A controlled loader supplies
an unrelated owned platform anchor for the policy comparison; it does not
install certificates or measure native store enumeration. The Chrome-specific
control directly constructs that backend so Rustls fallback cannot stand in
for Chrome verification. Generated private fixture keys remain in memory.
Direct task handles are aborted and awaited within a separate two-second
cleanup allowance after the ten-second exchange bound. An owned outer QA
process is still required for transport descendants and unexpected panics.

Each call creates fresh roots, QUIC client config, token store and endpoint;
there is no association cache or trust snapshot shared across children. A
replaced public CA file affects the next configuration, while existing
connections keep their established verification result. File opens, metadata
and reads remain synchronous; the byte limit is not a kernel latency bound.
Chrome reopens the configured CA path after prevalidation, so concurrent file
replacement has no atomic same-descriptor guarantee. The mode is explicit
because narrowing trust can reject previously accepted public certificates.
See [association testing](../../../../docs/operations/masque-association-testing.md).
