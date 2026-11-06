# aegis-web-carrier/src

Client/server byte-stream adapters, bounded request/reply protocol and explicit carrier settings.

## Contract

Client/WebStream and Server/AcceptedSession expose opaque streams. AuthenticationHandle extends an accepted carrier lifetime after device authentication; it must not grant target access. protocol.rs enforces frame bounds and FIN/CANCEL semantics. Keep cancellation, session limits and H2 flow control consistent with the inner channel owner.

## Key files

- [lib.rs](lib.rs)
- [settings.rs](settings.rs)
- [protocol.rs](protocol.rs)
- [client.rs](client.rs)
- [server.rs](server.rs)
- [server_accept_tests.rs](server_accept_tests.rs) — actual accept-loop retry, cancellation and fatal cleanup regressions.

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-web-carrier --lib
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-web-carrier](../README.md).

[Repository overview](../../README.md) · [Parent directory](../README.md)

## Listener error ownership

The server retries `Interrupted`, `ConnectionAborted` and `WouldBlock` after an absolute 50 ms delay. It uses the same delay for explicitly recognized native resource errors: macOS `ENOMEM` (12), `ENFILE` (23), `EMFILE` (24) and `ENOBUFS` (55); Linux `ENOMEM` (12), `ENFILE` (23) and `EMFILE` (24), plus `ENOBUFS` (105) on x86_64/aarch64; Windows WinSock `WSAEMFILE` (10024) and `WSAENOBUFS` (10055). Other platforms and unlisted native codes retain fatal behavior. An `OutOfMemory` error without a recognized raw code does not enable retries.

Existing connections keep their ownership, and cancellation, cleanup and completed children remain selectable during the delay. Unknown accept errors retain their original kind and raw OS error after the outer connection tasks are aborted and joined. `ServerStats` adds a saturating resource-error count and the last recognized native code. These are independent numeric observations across the server's listeners, not a coherent count/code pair, a health indicator or operator logging. The refusal path performs no formatting or blocking output.

The seven portable accept regressions remain unchanged. Six additional macOS actual-owner regressions changed from 0/6 before repair to 6/6 after repair with the same final test bodies. The four native-errno retention cases each retain an actual inner TLS 1.3 device channel authorized through `accept_with_lease`, verify distinct bidirectional markers before and after the error, and admit the next actual TLS/H2 OPEN. The two other controls use actual outer TLS/H2 anonymous OPEN: sustained errors keep exact 49 ms/1 ms retry boundaries and immediate cancellation, while the expiry control preserves the anonymous session's original deadline. Final scoped checks passed 20 library tests, all 13 unchanged network controls and strict Clippy. These inject accept results without exhausting host resources.

Workspace-local receipts are in `artifacts/testing/2026-10-10/audit20-carrier-resource-source-r1/`; failed fixture attempts and corrected baseline/repair runs remain separate. Finding 63 stays partial in the [tracked audit register](../../docs/operations/security-audit-2026-10-10-findings.md). Bounded operator logging, awaited indirect worker cleanup and native resource-pressure behavior remain open. Joining the outer connection tasks does not prove completion of every indirectly aborted worker, and emergency fixture `Drop` aborts do not prove awaited cleanup. Platform, publication/CI and installed lifecycle acceptance require separate evidence.
