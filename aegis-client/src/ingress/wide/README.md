# aegis-client/src/ingress/wide

Platform-wide ingress adapters, transparent TCP pumps, DNS preview and explicit UDP/TUN paths.

## Contract

Compilation selects Linux, macOS and Windows adapters separately. NFQUEUE observation, relay-only replacement and generic capture have distinct contracts. Preserve original-destination metadata, bounded buffers and half-close/backpressure behavior; never turn a failed UDP relay into native UDP fallback. Support-tier labels must reflect the active backend.

The DNS allocator and leased-target parser are shared by the packet engine on
Linux, macOS and Windows. The standalone DNS listener and unleased TCP
resolver are Linux adapters; their inert unit tests also compile on other
targets. A platform gate must preserve those shared packet-engine paths.

## Key files

- [mod.rs](mod.rs)
- [linux.rs](linux.rs)
- [macos.rs](macos.rs)
- [windows.rs](windows.rs)
- [tcp_stream_pump.rs](tcp_stream_pump.rs)
- [tun_smoltcp.rs](tun_smoltcp.rs)
- [udp_redirect_proxy.rs](udp_redirect_proxy.rs)
- [udp_conntrack.rs](udp_conntrack.rs) — typed original-tuple parsing shared by the Linux proxy and portable parser regressions.
- [udp_conntrack_lookup.rs](udp_conntrack_lookup.rs) — fresh destination ownership, bounded acquisition and complete native-dump validation.
- [dns_preview.rs](dns_preview.rs)

## Directories

| Directory | Responsibility |
| --- | --- |
| [ip_tunnel/](ip_tunnel/README.md) | Dual-stack packet engine internals shared by macOS utun and Windows Wintun paths. |

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-client --bin aegis-client ingress::wide
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-client](../../../README.md).

## Linux UDP original destination

The conntrack parser matches the exact original source address, source port and
UDP protocol. Reply-tuple fields, address/port prefixes and conflicting original
destinations cannot select a route. A malformed matching record refuses the
lookup; it cannot be converted into an absent record that enables fallback.

Run `cargo test --locked -p aegis-client --bin aegis-client udp_conntrack::tests::`
and confirm that all 14 tests are selected. These portable parser tests do not
exercise Linux REDIRECT, the kernel dump or the installed client.

The REDIRECT recovery path now looks up each datagram independently. It cannot
reuse a prior peer-only destination after conntrack eviction or peer reuse.
A complete proc table may provide a unique original destination; only an
unavailable or complete absent table may select the native fallback. Partial,
ambiguous or malformed input refuses the datagram. A native dump publishes its
result only after valid completion, with the selected sequence, kernel sender
and consistent original destinations checked.

One new 400 ms lookup cutoff covers proc acquisition and the complete native
operation. It is separate from the existing 400 ms receive interval and leaves
the 30 s relay idle default unchanged. Each source accepts at most 1 MiB of
input; the native dump also caps messages at 8192. Its nonblocking descriptor is
owned and closed by the lookup. Polling checks stop in requested slices of at
most 20 ms, and late results are refused. These checks cannot preempt a kernel
filesystem call or guarantee a hard wall-time bound or an atomic snapshot.

Run `cargo test --locked -p aegis-client --bin aegis-client udp_conntrack_lookup::tests::`
and confirm all 15 tests are selected alongside the original 14 parser tests.
The controlled original cache/scanner pair reproduces six failures, then all
29 tests pass with the corrected owners; the integrated local client also
passes both groups and strict checks. Native Linux syscall, REDIRECT routing,
large-table availability and installed-client acceptance still require the
exact successor CI and platform tests. Conntrack eviction now drops later
datagrams instead of reusing an unverified cached route.

[Repository overview](../../../../README.md) · [Parent directory](../README.md)
