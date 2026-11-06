# aegis-client/src/ingress/wide/ip_tunnel/tests

Packet-engine deadline, Windows soak and explicit host-acceptance test modules.

## Contract

progress_deadline.rs checks bounded progress. full_host.rs and owned_process.rs compile only on Windows with windows-host-acceptance; these are disruptive explicit current-host tests and must not be included in ordinary kits or assumed to run on macOS/Linux. soak.rs is Windows-gated.

## Key files

- [progress_deadline.rs](progress_deadline.rs)
- [full_host.rs](full_host.rs)
- [owned_process.rs](owned_process.rs)
- [soak.rs](soak.rs)
- [native_byte_diagnostics.rs](native_byte_diagnostics.rs): exact byte-comparison and bounded native TCP stage observations.

The native Windows socket fixture reports aggregate echo/application byte
counts, read EOF and write/shutdown completion stages. It keeps the original
2 MiB request, 16 KiB read buffers, deadlines and exact response equality.
Mismatch output contains lengths and the first differing index, without a
payload dump. The single report owner emits during ordinary return or unwind;
it cannot promise output after process abort, termination or blocking cleanup.
Relaxed snapshots and completed shutdown calls do not prove wire FIN delivery
or individual accepted write bytes. These observations diagnose a failed
transfer; they do not establish its cause or supply native acceptance.

The enclosing module is [tests.rs](../tests.rs); this directory contains its split implementation or test modules.

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-client --bin aegis-client ingress::wide::ip_tunnel::tests
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

Native Windows/utun paths need the matching target; `windows-host-acceptance` is an explicit separate disruptive test gate.

For dependency features and launch procedures, see [aegis-client](../../../../../README.md).

[Repository overview](../../../../../../README.md) · [Parent directory](../README.md)
