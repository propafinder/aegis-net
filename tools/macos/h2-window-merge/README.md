# v34 merge recipe: the h2 receive-window delta onto the Linux lane's h2 custody

B-06 v34 adds a second documented delta to the vendored h2 (per-stream
receive-window growth and shrink, `third_party/h2/AEGIS-PATCH.md`,
"Per-stream receive window, 2026-10-27"). The Linux lane changed the same
custody files in parallel. This recipe is for the merge of `main` into the
B-06 branch after B-02/B-03 reach `main` (the lane order). It was proved on
27 October 2026 in a scratch export (below); this copy and its helper,
[record_window_delta.py](record_window_delta.py), are kept in the branch
because the proof's scratch directory is temporary. They are not under
`third_party/h2`: an unrecorded file there fails the integrity inventory.

Parent: [macOS source tools](../README.md).

## What meets at merge time

| Side | Commit | h2 custody state |
|---|---|---|
| B-06 v34 | `51a7f1bb` h2 delta and custody, `24e17ae5` advisory-coverage pin, `21518fca` aegis-core policy, on `degree/b06-v34-20261027` (base `b9adfe19`); review fixes `29cdae6c` (aegis-core `RecvWindow::unreleased`) and `660c2877` (the NE tokio dev-dependency) | lock overlay of 2026-10-15; adds the "Per-stream receive window, 2026-10-27" delta |
| Linux lane | `d73eb212` on `degree/b03-postrouting-20261022` (contains relay commit `83b48386`) | adds the RUSTSEC-2026-0382, RUSTSEC-2026-0381 and RUSTSEC-2026-0386 lockfile overlays (2026-10-20, 2026-10-20, 2026-10-25) |

Files that differ between `b9adfe19` and `d73eb212`, as checked with
`git rev-parse <commit>:<path>`:

- Linux side only: `third_party/h2/Cargo.lock`,
  `third_party/h2/AEGIS-LOCK-PATCH.diff`, root `Cargo.toml`, root
  `Cargo.lock`, the tungstenite custody, and the NE's normal tokio pin
  (`tools/macos/aegis-network-extension/Cargo.toml`, `=1.53.3`) with its
  `Cargo.lock`. Take the Linux side.
- v34 side only, with identical bases: `third_party/h2/src/share.rs`,
  `third_party/h2/src/proto/streams/streams.rs`,
  `third_party/h2/src/proto/streams/recv.rs`, the new
  `third_party/h2/AEGIS-WINDOW-PATCH-{1,2,3}.diff`,
  `aegis-core/src/h2_stream.rs` and
  `scripts/test-vendored-advisory-coverage-contract.sh`. Take the v34
  side. `scripts/audit-vendored-dependencies.sh`,
  `scripts/test-vendored-integrity-contract.sh` and
  `scripts/test-h2-pseudo-header-order-contract.sh` are the same on both
  sides.
- Both sides changed: `third_party/h2/AEGIS-PATCH.md` (each appends
  sections at the end) and `third_party/h2/UPSTREAM.json` (hash-pinned).
  Keeping both sides of the JSON conflict does not work. Rebuild it as
  described below.
- The NE `Cargo.toml` merges without a textual conflict (the two sides
  change different hunks). Before `660c2877` the result failed Cargo
  resolution: the v34 dev-dependency pinned `tokio = "=1.53.2"` beside
  `main`'s normal `=1.53.3`. It is now `tokio = { version = "1", features
  = ["test-util"] }`, which follows the normal pin; a scratch crate with
  exactly the merged pins resolves to one tokio 1.53.3 (`cargo
  generate-lockfile --offline`).

## Steps (lane order: B-02/B-03 merge first; then `main` is merged into the B-06 branch)

1. `git merge main` on the B-06 branch. In that merge "ours" is B-06 and
   "theirs" is `main`.
2. `third_party/h2/AEGIS-PATCH.md`: take `main`'s file verbatim
   (`git checkout --theirs`), then append the v34 section once after its
   last section, keeping the sections in date order. The section is the 72
   lines that `git diff b9adfe19 51a7f1bb -- third_party/h2/AEGIS-PATCH.md`
   adds, starting with a blank line and then
   `## Per-stream receive window, 2026-10-27`.
3. `third_party/h2/UPSTREAM.json`: take `main`'s file verbatim
   (`git checkout --theirs`), then run
   `python3 -I tools/macos/h2-window-merge/record_window_delta.py third_party/h2 <dir holding the three upstream files>`.
   For the upstream files, use `git archive b9adfe19 third_party/h2`
   extracted anywhere (pass its `third_party/h2` directory). The script
   checks each copy against `upstream_files_sha256` before using it. It
   appends the three files to `local_modifications`, adds their
   `local_patches` records, rewrites the three `AEGIS-WINDOW-PATCH-*.diff`
   byte-identically, and recomputes the `AEGIS-PATCH.md` hash. It leaves
   every other key, value and order as they were.
4. Take the v34 side for the other files listed above. Keep the Linux
   side's lockfiles, `AEGIS-LOCK-PATCH.diff`, root `Cargo.toml` and the
   NE's normal tokio pin unchanged.
5. The NE lock: `cargo tree --locked --offline --all-features -e normal,dev
   --manifest-path tools/macos/aegis-network-extension/Cargo.toml` must
   resolve against `main`'s NE `Cargo.lock` with one tokio. If `--locked`
   refuses, stop: every `Cargo.lock` is the Codex lane's to change, so the
   lock owner regenerates it; never edit it in the merge.
6. Stage everything first. The integrity contract reads `git ls-files`.
   Then run:
   - `bash scripts/audit-vendored-dependencies.sh` (offline:
     `CARGO_NET_OFFLINE=true AEGIS_CARGO_AUDIT_DB=$HOME/.cargo/advisory-db`)
   - `bash scripts/test-vendored-integrity-contract.sh`
   - `bash scripts/test-vendored-advisory-coverage-contract.sh`
   - `bash scripts/test-h2-pseudo-header-order-contract.sh` and
     `bash scripts/test-h2-pseudo-header-order-manifest-contract.sh`
   - h2's own tests on a copy of `third_party/h2` outside the workspace,
     with its lockfile: `cargo test --locked --offline --lib`. Expect 57
     passed, including the 7 `aegis` tests. The 382 `hpack::test::fixture`
     tests fail because the crate archive has no `fixtures/`. They fail on
     the unmodified copy too. If you reuse a target directory, touch the
     copy's `src/` first. Cargo otherwise reuses a binary built from
     another copy with the same relative path; that happened once in the
     proof and that run was discarded.
   - `cargo test --locked -p aegis-core --lib h2_stream` (8 passed since
     the v34 review's `the_window_counts_what_h2_holds_unreleased`; the
     proof ran 7)
   - the NE tests, `nice -n 10 cargo test --locked --features apple --lib
     -j 4` in `tools/macos/aegis-network-extension`, under the lanes'
     timing rules
   - the single batch CI, which must include the Linux and Windows jobs.
     The root patch compiles these bytes into every build.

## Values the proof produced (merged tree = `d73eb212` filtered + v34 delta)

| Path | SHA-256 |
|---|---|
| `src/share.rs` (patched) | `cd11deb2c38444f5076768547cb2d79b3d2494fd0fec97ea668461a0a6231590` |
| `src/proto/streams/streams.rs` (patched) | `1517e60a0dca6946e52992cdc57d6614df5bd8a7e125871659fe9b5b586d3244` |
| `src/proto/streams/recv.rs` (patched) | `dc6ad3c24619dc6e4966007a5e175b1601f29c43870456c486d6f133e6ba311a` |
| `AEGIS-WINDOW-PATCH-1.diff` | `f1249fca57ea3e519b4273f793fb2e0812da7541f3a827ae7d855cef579b83af` |
| `AEGIS-WINDOW-PATCH-2.diff` | `260053594c9be7542de793a465b630a1f62e2c67c899ee5d63721ae40c133828` |
| `AEGIS-WINDOW-PATCH-3.diff` | `912d8765247d7232dda075fa4213304cdb3ff372df748dbba81d16cafc18c8dd` |
| merged `AEGIS-PATCH.md` | `6b5e12795923c226e846febfe26b5808ff91cb6fd76d3e8f895411dfb17a3b33` |
| merged `UPSTREAM.json` | `a4e01cdb36d1c3e894e43db722cc4b0d2fcb548362a7b0dd036c89a257badbf3` |

The v34 review changed no h2 file, so these still hold. The source and
diff hashes are the same on both sides. The two merged metadata hashes
hold only if `main`'s `AEGIS-PATCH.md` is still `d73eb212`'s. If `main`
gained another section, recompute them with step 3.

The merged `UPSTREAM.json` differs from `d73eb212`'s only by the three
appended `local_modifications`, the three `local_patches` records and the
`AEGIS-PATCH.md` hash. It differs from the v34 branch's only by the Linux
side's `Cargo.lock` `patched_sha256` and `patch_sha256` and the
`AEGIS-PATCH.md` hash.

## What the proof ran (27 October 2026, local, offline)

Its logs and intermediate files were kept in the session scratchpad
(`b06/v34-impl/merge-proof/`), which is temporary; they are not retained
here.

- Export: `git archive d73eb212`, excluding `artifacts/`, `target/` and
  `.scratch-*` at every depth; none of those paths was in the member list.
  Nothing was checked out and the Linux lane's worktree was not touched.
- Applied the v34-side source (`git diff b9adfe19 21518fca` limited to the
  v34-side files) with `git apply --check`, then `git apply`. Then steps 2
  and 3.
- `audit-vendored-dependencies.sh`: PASS (h2: 67 upstream files, 5 local
  patches; tungstenite: 35, 5; advisory DB `21d909e4`, 2026-10-24,
  `--no-fetch`).
- `test-vendored-integrity-contract.sh`: PASS, 15 isolated cases, in a
  scratch Git repository of the merged tree. `third_party/h2/.gitignore`
  ignores `Cargo.lock`, so it and one `tools/measure` fixture had to be
  added with `git add -f`, as the real repository tracks them. The tracked
  inventory then equals `d73eb212`'s plus the three new diffs.
- Advisory-coverage, pseudo-header order and manifest contracts: PASS. The
  provenance half of `scripts/security/check-supply-chain.sh` was run
  standalone and passed. cargo-deny 0.20.2 is not installed here, so its
  licence/ban/source half was not run.
- h2 lib tests with the Linux side's lockfile (tokio 1.53.3): 57 passed,
  0 non-fixture failures.
- `cargo test -p aegis-core --lib h2_stream` on the merged workspace
  (tokio 1.53.3): 7 passed. The pinned v33 WINDOW_UPDATE sequences still
  hold under that tokio.
- `cargo check -p aegis-server -p aegis-client -p aegis-transport-lab
  --all-targets` on the merged workspace: OK.
- An independent review (28 October) re-checked the bases and hashes
  against `d73eb212` and the branch, re-ran the integrity (15 cases) and
  advisory-coverage contracts on the merged tree (PASS), and found the NE
  tokio pin conflict above, since fixed.

## Deploy note

The root `Cargo.toml` `[patch.crates-io]` makes the whole workspace compile
`third_party/h2`. That includes `aegis-server` (the relay) and
`aegis-client` on Linux, Windows and macOS. The NetworkExtension workspace
has its own patch to the same path. No code outside the macOS pool calls
the new methods, so the relay's wire behaviour is unchanged. Its h2 source
bytes are not. Record this h2 byte change (three files, lines added only)
at the next relay deploy. The relay deployed at `83b48386` was not touched.
