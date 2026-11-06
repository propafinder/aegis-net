# aegis-client/src/relay/tls_backend

Optional AWS-LC outer TLS implementation beneath the backend selection seam.

## Contract

The parent tls_backend.rs reports the compiled/effective backend separately from the configured preference. Without chrome-like-tls, the Chrome-like implementation is absent and selection can use rustls. Trust verification must remain enforced by the actual backend; backend naming is not browser equivalence evidence. Required real ECH and device inner TLS require `tls_backend=rustls`. The AWS-LC client supplies ECH GREASE, which does not encrypt the inner ClientHello or satisfy a real-ECH request. AWS-LC ECH server helpers belong to controlled tests, not a client ECH implementation.

## Key files

- [aws_lc.rs](aws_lc.rs)

The enclosing module is [tls_backend.rs](../tls_backend.rs); this directory contains its split implementation or test modules.

## Directories

| Directory | Responsibility |
| --- | --- |
| [aws_lc/](aws_lc/README.md) | Windows-specific AWS-LC TLS transport using Tokio-owned Winsock and memory BIOs. |

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-client --features chrome-like-tls --bin aegis-client relay::tls_backend
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

Enable `chrome-like-tls` to cover the optional AWS-LC client and controlled ECH-server helpers; Windows-specific modules additionally require Windows.

For dependency features and launch procedures, see [aegis-client](../../../README.md).

[Repository overview](../../../../README.md) · [Parent directory](../README.md)
