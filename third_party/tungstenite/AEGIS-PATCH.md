# tungstenite 0.24.0 privacy patch

AEGIS carries the exact crates.io 0.24.0 release with four logging-only source edits. The upstream `handshake/client.rs` Trace log serializes the full HTTP Upgrade request and therefore prints a bearer token even when `HeaderValue::set_sensitive(true)` was used. The frame and message logs in `protocol/frame/mod.rs` and `protocol/mod.rs` print WebSocket payloads, including SDP/ICE or echoed token material. `client.rs` logs full redirect/contact URIs, which could expose a future query token. The four local deltas replace secret-bearing debug/trace values with constant event labels or request length. No parsing, framing or wire behavior is intentionally changed.

`UPSTREAM.json` binds the crates.io archive and every archive file. Each `AEGIS-PATCH-*.diff` is an independently reversible unified diff for one source path; its hash and both source hashes are recorded. `scripts/audit-vendored-dependencies.sh` verifies exact inventory, restores every original source file and projects the upstream identity into cargo-audit. Review the four diffs again on every upstream update.

The application additionally builds its bearer-bearing WebSocket Upgrade in a bounded zeroizing buffer, over the already pinned TLS stream. It validates the response before attaching `WebSocketStream::from_partially_read`. It does not call tungstenite's request generator for the real bearer path. The vendored logging patch protects future uses and post-Join signaling frames.

This patch does not implement SFU media, publisher/subscriber tracks, remote deployment, privacy endurance or release acceptance. B-08 remains NO-GO until those gates pass.

## Standalone lockfile security overlay, 2026-10-20

The original release archive's `Cargo.lock` remains recorded, byte for byte,
in `UPSTREAM.json`. `AEGIS-LOCK-PATCH.diff` separately records the local
dependency metadata update. It selects `rustls` 0.23.46,
`rustls-pki-types` 1.15.1 and the upstream patched `rustls-webpki` 0.103.16
for RUSTSEC-2026-0382. The reversible diff must reconstruct the original
release lockfile. No tungstenite source or manifest API is changed by this
overlay.

The upstream package manifest still states Rust 1.63. The resolved optional
TLS graph now requires Rust 1.71 through `rustls` and `rustls-webpki`; Aegis
product and CI use pinned Rust 1.97.1. The stated upstream package MSRV must
not be mistaken for the MSRV of this complete standalone TLS lockfile.

The fourth tracked lockfile passes the repository's required `--locked`
metadata check. A full standalone vulnerability audit is still open: with the
locally cached advisory database it reports seven earlier vulnerabilities and
three denied warnings in older unrelated dependencies. This overlay fixes the
new `rustls-webpki` advisory only. It does not make that full audit a PASS or
add an advisory exception.
