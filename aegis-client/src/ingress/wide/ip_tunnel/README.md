# aegis-client/src/ingress/wide/ip_tunnel

Dual-stack packet engine internals shared by macOS utun and Windows Wintun paths.

## Contract

fragments.rs owns fragment handling; the parent ip_tunnel.rs integrates smoltcp with relay streams and packet I/O. OS route/firewall policy is owned elsewhere. Keep reassembly, queue limits, backpressure and progress deadlines consistent with bounded engine operation.

## Key files

- [fragments.rs](fragments.rs)
- [tests.rs](tests.rs)

The enclosing module is [ip_tunnel.rs](../ip_tunnel.rs); this directory contains its split implementation or test modules.

## Directories

| Directory | Responsibility |
| --- | --- |
| [tests/](tests/README.md) | Packet-engine deadline, Windows soak and explicit host-acceptance test modules. |

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-client --bin aegis-client ingress::wide::ip_tunnel
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

Native Windows/utun paths need the matching target; `windows-host-acceptance` is an explicit separate disruptive test gate.

For dependency features and launch procedures, see [aegis-client](../../../../README.md).

[Repository overview](../../../../../README.md) · [Parent directory](../README.md)
