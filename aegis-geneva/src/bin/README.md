# aegis-geneva/src/bin

Opt-in Linux AF_PACKET bridge executable.

## Contract

bridge.rs is built only with live-linux. It connects two explicitly configured ports and does not alter routes, namespaces, addresses, iptables or sysctls. Stopping the bridge disconnects those ports. Review its bounded inputs and operation limits before any isolated native run.

## Key files

- [bridge.rs](bridge.rs)

## Development and checks

Run from the repository root:

```sh
cargo build --locked -p aegis-geneva --features live-linux --bin aegis-geneva-bridge
```

This builds the optional bridge only; native execution has separate explicit Linux prerequisites.

For dependency features and launch procedures, see [aegis-geneva](../../README.md).

[Repository overview](../../../README.md) · [Parent directory](../README.md)
