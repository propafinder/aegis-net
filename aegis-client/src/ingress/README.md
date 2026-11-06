# aegis-client/src/ingress

Ingress interfaces and session broker for SOCKS5 fallback and platform-wide capture.

## Contract

The broker converts accepted intent into a session while response handling preserves the SOCKS5 wire contract. Preflight reports configuration/support selection; startup probes test runtime prerequisites. A report is not evidence that intercepted traffic reached its target.

## Key files

- [mod.rs](mod.rs)
- [broker.rs](broker.rs)
- [preflight.rs](preflight.rs)

## Directories

| Directory | Responsibility |
| --- | --- |
| [preflight/](preflight/README.md) | Typed startup reports, hints, backend selection diagnostics and runtime probes. |
| [wide/](wide/README.md) | Platform-wide ingress adapters, transparent TCP pumps, DNS preview and explicit UDP/TUN paths. |

## SOCKS admission

The backend accepts handshakes concurrently in an owned task set, capped at 64 pending results. One ten-second deadline starts at socket acceptance and covers negotiation, authentication, request parsing and rejection writes. Cancelling an accept wait preserves pending handshakes; backend shutdown aborts and joins them. A stalled unauthenticated client does not serialize later valid clients. Saturation rejects the new socket and remains a capacity failure, not proof of bad credentials. UDP peer custody and resolver limits have separate open audit findings.

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-client --bin aegis-client ingress
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-client](../../README.md).

[Repository overview](../../../README.md) · [Parent directory](../README.md)

## Hostname resolution ownership

The installed Auto and Relay brokers preserve hostnames for their route owner.
Relay resolves remotely; Auto invokes local DNS only when its selected route
needs a direct address. IP literals remain concrete without a lookup. Direct
retains its original lookup and host-unreachable refusal behavior.

[auto_dns_tests.rs](../auto_dns_tests.rs) exercises the installed mode selector,
deferred names, the unchanged Direct refusal and literal addresses. An
unspecified SOCKS bound address is advisory; it is never a resolved direct
destination.
