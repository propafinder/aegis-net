# h2 0.4.16, vendored for one reason

Upstream source, unmodified except for the delta below. The lockfile has a
separate dependency security overlay recorded later in this document.

## The delta

`src/frame/headers.rs`, in `impl Iterator for Iter` — `:authority` is drained
before `:scheme`.

Upstream drains `Pseudo` in struct-field order, which puts `:scheme` second:

    :method  :scheme  :authority  :path      <- upstream h2
    :method  :authority  :scheme  :path      <- Chrome, and now us

## Why it is worth vendoring a dependency

This patch removes one known HTTP/2 ordering difference from the selected
browser profile. It does not establish that the complete ClientHello,
SETTINGS, connection behavior or traffic distribution matches a browser.
Those claims require captures of the exact release and a stated comparison
profile. Matching pseudo-header order alone does not prove DPI resistance.

The order is hardcoded in the iterator. There is no builder option, no feature
flag, and no trait to implement. Owning the source is the only lever.

## HEADERS priority, 2026-11-06

Chrome 157 still sets the PRIORITY flag on request HEADERS: exclusive, stream
dependency 0, weight octet 109. Upstream h2 parses that prefix and never writes
it. `Headers::set_measured_chrome_priority` and the encode path in
`src/frame/headers.rs`, the prefix helper in `src/frame/priority.rs`, and the
call in `src/client.rs` add it. The numbers are also in
`aegis-chrome-profile/chrome-stable.toml`; this crate does not depend on that
file. A client test checks the bytes against the profile.

RFC 9113 §6.3 requires pseudo-header fields to precede regular fields but does
not constrain their order relative to each other, so this stays conformant. It
does not change HPACK correctness either: the static-table indices are
per-name, not positional.

## Re-applying this when bumping h2

1. Copy the new upstream release over `third_party/h2`.
2. Re-apply the swap in `frame::headers::Iter`.
3. Run `scripts/test-h2-pseudo-header-order-contract.sh`.
4. Re-measure on the wire — the contract is textual and cannot prove the bytes.
   `artifacts/live/2026-08-11/http2-pseudo-header-order` has the method.

The contract fails loudly if the patch is missing, so a bump that forgets it
cannot merge quietly. That is the whole point: this exact class of regression
is how the macOS tarball shipped without its TLS feature.

## Security maintenance, 2026-09-10

Upgraded to upstream 0.4.16 for RUSTSEC-2026-0258. The existing local
pseudo-header ordering delta is preserved; no new wire-shaping change is added.
UPSTREAM.json records the official crate checksum and upstream file hashes.
The vendored advisory CI gate projects the recorded upstream package identity
into a separate registry lockfile; the production lockfile remains path-based.

## Integrity and patch custody, 2026-10-10

`UPSTREAM.json` keeps the original release hashes in `upstream_files_sha256`.
The original `src/frame/headers.rs` hash is
`a7630564280006b29488c2fb399d52a70d8d7ccc6d1276fd291410b329d038c5`.
The intentionally patched file is recorded separately in `local_patches`,
with its own hash, the hash of `AEGIS-PATCH.diff`, and this documentation.
The diff reverses exactly to the recorded original hash; modified bytes must
never be recorded as an unmodified upstream release.

`scripts/audit-vendored-dependencies.sh` checks every recorded upstream file,
the exact patched bytes, the diff and documentation, and rejects unrecorded,
missing or symlinked files. It reconstructs each patched file's upstream bytes
from the recorded diff and checks the original hash before running the separate
upstream-identity advisory audit. `UPSTREAM.json` is the sole self-exempt metadata
file; its changes and all `third_party/` changes have the repository CODEOWNER.
This source ownership rule does not prove an independent review took place.

For an upstream bump, verify the downloaded archive against its recorded crate
checksum, record the unmodified file hashes before patching, regenerate the diff
and separate local hashes, and run both vendored contracts plus the header-order
contract. The offline integrity check verifies the checked-in records and patch
relationship; it does not fetch or independently authenticate the crate archive.

## Lockfile security overlay, 2026-10-15

The release archive's `Cargo.lock` stays recorded at its original SHA-256 in
`UPSTREAM.json`. `AEGIS-LOCK-PATCH.diff` records the checked-in lockfile update
for the rustls 0.23.46 advisory fix and its compatible aws-lc-rs, aws-lc-sys,
and rustls-webpki versions. This is dependency metadata only; no h2 source
change is implied. The integrity auditor reverses the patch to the recorded
upstream lockfile and also verifies the exact patched bytes. Run the independent
`third_party/h2` advisory audit on the updated lockfile.

## Certificate distrust overlay, 2026-10-20

RUSTSEC-2026-0382 identifies certificate paths accepted through distrusted
intermediate public keys in `rustls-webpki` 0.103.15. The checked-in standalone
lockfile now selects the upstream patched 0.103.16. `AEGIS-LOCK-PATCH.diff` is
regenerated against the same recorded upstream `Cargo.lock`; its original hash
in `UPSTREAM.json` is unchanged. This adds no h2 source or wire change.

The upstream package manifest still states Rust 1.63. This standalone lockfile's
optional TLS graph includes `rustls` and `rustls-webpki` requiring Rust 1.71;
the Aegis product and CI use pinned Rust 1.97.1. The upstream manifest and its
archive identity have not been relabelled to claim a lower resolved TLS MSRV.

## Bundled root distrust overlay, 2026-10-20

RUSTSEC-2026-0381 identifies a distrusted emSign root in `webpki-roots`
1.0.9. The standalone h2 lockfile now selects the upstream patched 1.0.10.
`AEGIS-LOCK-PATCH.diff` is regenerated against the same recorded upstream
`Cargo.lock`, preserving its original SHA-256 and all source files. This is
lockfile metadata only; it does not establish a product trust-store change.

## Tokio I/O safety overlay, 2026-10-25

RUSTSEC-2026-0386 affects the standalone lockfile's Tokio 1.53.1. It now
selects upstream Tokio 1.53.3. The existing lockfile overlay is regenerated
against the same recorded upstream bytes; the original upstream checksum,
h2 source and advisory policy remain unchanged.

## Per-stream receive window, 2026-10-27

A second source delta, for the macOS pool's adaptive receive window (B-06
v34). Upstream h2 0.4.16 re-opens only what was received:
`FlowControl::release_capacity` refuses more than was consumed
(`ReleaseCapacityTooBig`), so no stream window can ever exceed
SETTINGS_INITIAL_WINDOW_SIZE, and there is no builder option or trait for it.
The delta only adds code; no upstream line is changed or removed. It touches
three files, each with its own single-file diff, as the integrity auditor
requires:

| File | Diff |
|---|---|
| `src/share.rs` | `AEGIS-WINDOW-PATCH-1.diff` |
| `src/proto/streams/streams.rs` | `AEGIS-WINDOW-PATCH-2.diff` |
| `src/proto/streams/recv.rs` | `AEGIS-WINDOW-PATCH-3.diff` |

`AEGIS-PATCH.diff` and the header-order delta are unchanged.

Three public `FlowControl` methods, marked `AEGIS PATCH (receive window)`:

- `grow_window(sz)` assigns `sz` of new credit to this stream only. No
  connection capacity is released and no connection WINDOW_UPDATE follows.
  The stream is queued and the connection task woken exactly as
  `release_capacity` does, at the same half-window threshold; a smaller growth
  rides on the next update.
- `shrink_window(sz)` lowers what the stream re-opens to. Nothing is sent and
  credit already announced is not revoked: releases refill the difference
  before the next stream WINDOW_UPDATE, so the peer's credit falls to the
  lowered window as it sends. Connection capacity is released as before.
- `peer_window_size()` reads the stream window the peer was told and has not
  used, an upper bound on what it may still send.

Guards. Both refuse a stream that no longer receives (`STREAM_CLOSED`).
`grow_window` refuses with `FLOW_CONTROL_ERROR` when the window would pass
2^31-1 counting received bytes not yet released, and `shrink_window` refuses
more than the window it re-opens to. Nothing changes on a refusal. A mutation
run without the 2^31-1 guard accepted a growth that ignored unreleased bytes,
and the next `release_capacity` then failed its `debug_assert!(_res.is_ok())`;
a release build would silently lose that capacity. The `inc_window(..).expect()`
in `send_stream_window_updates` stays unreachable through these methods,
because window arithmetic is checked `i32` and 2^31-1 is `i32::MAX`. A
mutation run without the wake failed four of the seven delta tests: the
update was never sent. One residual is left to callers: a later local
SETTINGS_INITIAL_WINDOW_SIZE increase adds to a grown window, so growth plus
any initial window still to be set must stay within 2^31-1. Aegis sends its
SETTINGS once, and the v34 macOS pool design caps a stream at 1 MiB.

Wire. Nothing changes unless a caller uses these methods. When one does, the
only new frames are stream WINDOW_UPDATEs whose increments the caller chose.
SETTINGS and the connection window stay whatever the caller configured.

Reach. The root `[patch.crates-io]` applies this source to the whole
workspace and the NetworkExtension workspace patches the same path, so
`aegis-server` (the relay) and the Linux, Windows and macOS `aegis-client`
compile these bytes even where nothing calls the new methods. Record the h2
byte change at the next relay deploy.

Tests. In-crate unit tests in `recv.rs` (`aegis_*`) and wire tests in
`share.rs` (`aegis_receive_window_tests`) drive a real h2 client and server
and record every frame between them. Run them on a copy of this directory
with its own `Cargo.lock`: `cargo test --locked --offline --lib`. On that
copy 57 tests pass. The 382 `hpack::test::fixture` tests fail on this delta
and on the unmodified copy alike, because the crate archive excludes
`fixtures/`. They are evidence of neither.

When bumping h2, first check whether upstream gained per-stream window growth;
if it has, drop this delta. Otherwise re-apply the three diffs, regenerate
them with zero context against the new upstream files, record the hashes, and
run the tests above, `scripts/audit-vendored-dependencies.sh` and
`scripts/test-h2-pseudo-header-order-contract.sh`.
