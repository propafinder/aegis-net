# Vendored dependencies

[h2](h2/README.md) is an upstream HTTP/2 crate patched through the root
`[patch.crates-io]`. [AEGIS-PATCH.md](h2/AEGIS-PATCH.md) records the local
pseudo-header emission-order delta. Preserve upstream README, license, tests and
source layout; they are not AEGIS-authored directories needing new module READMEs.

The uncommitted B-08 privacy candidate also vendors `tungstenite` 0.24.0
through the root Cargo patch. Its `UPSTREAM.json` records the upstream archive
identity and four local logging patches. Review and commit this source with
the matching Cargo lock, supply-chain checks and AUTO pins; it is not yet a
tracked release dependency.

When updating upstream, reapply and inspect the documented patch, update the lockfile
and run `scripts/test-h2-pseudo-header-order-contract.sh` and
`scripts/audit-vendored-dependencies.sh` as appropriate. The latter checks both
vendored crates and can require
network advisory data. [The directory index](../docs/PROJECT-MAP.md)
catalogues all vendored subdirectories without modifying them.
