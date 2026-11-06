# aegis-server/tests

Local integration coverage for configuration, transports, bundles, lifecycle and authorization convergence.

## Contract

device_pool_lifecycle.rs uses a bounded three-process local controller, not a production registry distributor. opaque_carrier_auth.rs verifies actual local device/target admission for byte carriers. TLS/gRPC/QUIC lifecycle suites exercise owned task shutdown; local outcomes do not establish field reachability or fleet release acceptance.


The TLS relay smoke fixture performs real TLS authentication with both current
and migration keys. Ordinary builds retain the encrypted legacy frame exchange;
`legacy-challenge-v1` builds use the existing fresh challenge/proof exchange,
without accepting the old frame as a downgrade. It owns a port-zero relay
listener, waits for actual bound readiness and requests/join-checks shutdown.
Fresh exchanges use the existing configured opening budget from before each
TCP/TLS open; this does not increase server deadlines. The original wrong-dialect
feature failure is retained; exact ordinary/fresh positive runs and successor
CI remain required. These local fixtures are not native or field acceptance.

## Key files

- [config_parse.rs](config_parse.rs)
- [tls_relay_smoke.rs](tls_relay_smoke.rs)
- [tunnel_transports_smoke.rs](tunnel_transports_smoke.rs)
- [server_lifecycle.rs](server_lifecycle.rs)
- [grpc_lifecycle.rs](grpc_lifecycle.rs)
- [quic_lifecycle.rs](quic_lifecycle.rs)
- [device_pool_lifecycle.rs](device_pool_lifecycle.rs)
- [opaque_carrier_auth.rs](opaque_carrier_auth.rs)

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-server --tests
```

Integration targets are the Rust files directly in this tests directory.

For dependency features and launch procedures, see [aegis-server](../README.md).

[Repository overview](../../README.md) · [Parent directory](../README.md)
