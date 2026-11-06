# aegis-web-carrier/tests

Real loopback TCP, verified outer TLS and HTTP/2 carrier tests.

## Contract

network.rs exercises actual local networking, and support/inner_mtls.rs checks the independent device gate. Loopback verification covers admission, framing and lifetime behavior only; it does not show public intermediary reachability or resistance to traffic classification.

## Key files

- [network.rs](network.rs)

## Directories

| Directory | Responsibility |
| --- | --- |
| [support/](support/README.md) | Synthetic inner-mTLS integration fixtures and carrier authorization tests. |

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-web-carrier --tests
```

Integration targets are the Rust files directly in this tests directory.

For dependency features and launch procedures, see [aegis-web-carrier](../README.md).

[Repository overview](../../README.md) · [Parent directory](../README.md)
