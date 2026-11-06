# aegis-client/src/relay/tls_backend/aws_lc

Windows-specific AWS-LC TLS transport using Tokio-owned Winsock and memory BIOs.

## Contract

windows.rs crosses the FFI boundary with ciphertext buffers. SOCKET is pointer-sized and must never be cast to an OpenSSL file descriptor. Keep SSL/context ownership and cancellation explicit; this implementation requires the chrome-like-tls feature and Windows target.

## Key files

- [windows.rs](windows.rs)

The enclosing module is [aws_lc.rs](../aws_lc.rs); this directory contains its split implementation or test modules.

## Directories

| Directory | Responsibility |
| --- | --- |
| [windows/](windows/README.md) | Windows AWS-LC adapter regression tests. |

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-client --features chrome-like-tls --bin aegis-client relay::tls_backend::aws_lc
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

Enable `chrome-like-tls` to cover the optional AWS-LC/ECH implementation; Windows-specific modules additionally require Windows.

For dependency features and launch procedures, see [aegis-client](../../../../README.md).

[Repository overview](../../../../../README.md) · [Parent directory](../README.md)

## Unix setup ownership

The Unix backend owns SSL_CTX and SSL immediately after each successful allocation. Every subsequent setup error releases SSL before its context; successful construction retains both until stream destruction and drops the socket last. Regression tests observe actual AWS-LC destructor callbacks for malformed setup input and a failed descriptor-registration boundary. They do not establish a live TLS handshake, provider equivalence or external memory-safety review. Windows has its own ownership implementation.

## TrustAnchorID platform policy

Both Unix and Windows production TCP contexts omit the draft `0xca34` hint,
matching the [QUIC configuration policy](../../../../../aegis-quic-boring/src/config/README.md).
The locked AWS-LC custom-extension API appends this hint outside the built-in
permutation. The Windows-only registration is therefore disabled until a
native permuted implementation and fresh platform captures can be accepted.
This is containment of a platform difference, not Chrome 152 parity.

The shared `actual_tcp_first_flight_omits_custom_trust_anchor_hint` regression
captures the production adapter's first TLS record through an owned loopback
peer. It covers only emitted first-flight shape. Certificate rejection,
Unicode CA loading and actual platform trust still require their independent
negative and native acceptance checks; those verifiers are unchanged.
