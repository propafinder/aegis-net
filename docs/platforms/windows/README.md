# Windows

Native Wintun/WFP/SCM and separate SOCKS engineering-kit guidance. Source owners: [aegis-client](../../../aegis-client/README.md) and [aegis-winctl](../../../tools/windows/aegis-winctl/README.md). Production signing belongs to [the signing handoff](../../operations/windows-authenticode-release.md).

## Local documents

- [Шифрование Windows-клиента](windows-encryption.md)
- [Windows client developer kit](windows-install-runbook.md)
- [Windows system tunnel](windows-system-tunnel.md)

Parent: [documentation](../../README.md). Source/design documents and procedures
do not establish installed-client, field or release acceptance.

## Local Windows ARM64 cross-check after B-08 R7, 15 October

The read-only source-bound receipt (`evidence-archive/testing/2026-10-15/CI-windows-R7-cross-r1/receipt.md`), SHA-256 `0830543b636735f1115e0efb1d9f7896e00e9383562f95a9f2a3efd9a1d3f4d9`, records an exact Windows ARM64 MSVC `cargo check --offline --locked --target aarch64-pc-windows-msvc` of user-mode `aegis-client`, `aegis-server` and `aegis-winctl` with client Chrome-like TLS/QUIC/WebRTC and server WebRTC features. It bound B-08 R7 `aegis-server/src/sfu_bootstrap.rs` SHA-256 `09a5df53911c3a6b9ebf42cecb981ce7644af5dc70dbbb52fcc19e2a1f8e648a` and `Cargo.lock` SHA-256 `5ef24f15b896af2e3a8539099d03ae73b081b14f49bde9a2db1524809f437edf`. Attempts 01–03 failed respectively because LLVM 21 `clang-cl` was absent from PATH, xwin SDK/CRT include directories were missing for bindgen, and CMake selected an unavailable Visual Studio generator. After correcting those local build settings, attempt 04 (`evidence-archive/testing/2026-10-15/CI-windows-R7-cross-r1/attempt04.log`), SHA-256 `c651cdcc046815d6a17f108903506e605812560c3bfb3d76d89ebd76fb207dea`, completed **exit 0**. This source typecheck neither links nor executes native Windows code and is not hosted exact-final-commit `windows-rust` CI. Windows product work remains frozen; installed acceptance is open.

## Local Windows ARM64 cross-check after B-08 R8, 15 October

The R8 receipt (`evidence-archive/testing/2026-10-15/CI-windows-R8-cross-r1/receipt.md`), SHA-256 `bf5db89eaeec192974d868373eea08bf37c1264c6de3367076f527a3b08562be`, binds uncommitted `aegis-server/src/sfu_bootstrap.rs` SHA-256 `bf23f7a78b39bf4b69b854d02c750d6f5a4ff2a27756b453f0bbfaec7552e85d` and `Cargo.lock` SHA-256 `4d92846d169a0f476369f2f78ccb8db9d7430da39275cf86c9a8aaeb0ba10177`. Exact user-mode Windows ARM64 MSVC `cargo check --offline --locked` for client, server and winctl, including locked `prost`/`prost-derive 0.14.4`, completed **exit 0** (raw log (`evidence-archive/testing/2026-10-15/CI-windows-R8-cross-r1/attempt01.log`), SHA-256 `d8b01d92046cfe3eafaeb51bb4cab5ad02123e26a2f3823f1dfed483d8ff0c04`). This is a local target typecheck; it does not link or execute Windows binaries, establish installed behavior or turn hosted final-commit `windows-rust` green. Windows product work remains frozen.
## Current-tree Windows ARM64 cross preflight, 16 October

The local receipt (`evidence-archive/testing/2026-10-16/CI-windows-current-cross-r1/receipt.md`), SHA-256 `185355c8746e6617643b956637b46d6c222905704b99c7f44453fccc02ca4f57`, binds uncommitted current-tree source hashes. Offline locked ARM64 MSVC user-mode `cargo check` for client/server/winctl passed (raw SHA-256 `627fc1fb5be0074ae9fb29fd77f446f83172418b7151fa63a490315b2736e170`); strict all-target Clippy for client/winctl/QUIC passed (raw SHA-256 `8abfcc5454660a5e2a685eec9a28c8a6e8d1d678c9c8a7309d37176bf90cc16e`). The first Clippy attempt failed E0463 when ambient Homebrew `clippy-driver` lacked Windows `std`; the retry selected pinned rustup 1.97.1. No Windows binary ran, and the required hosted `windows-rust` result for the eventual final commit is pending. Windows product work remains frozen.
