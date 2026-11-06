# Windows client developer kit

The complete IPv4/IPv6 system tunnel, DNS, kill switch, enrollment and upgrade
workflow is documented in [Windows system tunnel](windows-system-tunnel.md).
The instructions below retain the separate SOCKS developer profile.

Updated: 2026-09-13. This is a Windows x64 development build, separate from the
signed Linux release. Windows 10/11 with NTFS is the intended platform.

## Implemented scope

- Foreground loopback SOCKS5 relay client, using the existing transport core.
- Fresh installations with a hash-verified, exact client-only kit.
- Native SCM registration as LocalService, start/stop/restart, bounded transitions
  and honest initialization failures. The installer uses manual startup.
- Private configuration and imported identity use explicit ACLs before secret
  bytes are written. Persisted encrypted learning state is opt-in for direct/auto;
  relay mode stays in RAM even when disk consent is configured. Links/reparse points and broad
  grants are rejected. The service can read config and write its state directory.
- Uninstall verifies binary hashes and SCM ownership, removes registered service
  and known binaries, and preserves configuration, identity and state.

This installer does not provision a relay, enroll a new device, install a WFP
driver, enable system proxy settings, capture system-wide DNS/UDP/IPv6, or provide
a signed production release. Applications must use the SOCKS listener explicitly.
The portable build uses Rustls; Chrome fingerprint features are not included.

## Build and package

Use the repository-pinned Rust toolchain and Visual Studio C++ build tools:

```powershell
cargo build --locked --release -p aegis-client -p aegis-winctl --no-default-features
$source = git rev-parse HEAD
.\target\release\aegis-winctl.exe package build `
  --client .\target\release\aegis-client.exe `
  --winctl .\target\release\aegis-winctl.exe `
  --output C:\AEGIS-kit --source-commit $source
```

The output directory must be new. The kit contains exactly `aegis-client.exe`,
`aegis-winctl.exe`, `README.txt`, and `manifest.json`. It contains no configuration,
credentials, server executable, source tree or driver. Build output includes the
manifest SHA-256. Transfer that pin through an authenticated channel independently
of the package. Hash verification detects modification; it is not a publisher
signature. `source_commit` is the builder's supplied provenance, so package only
a clean, reviewed checkout for distribution.

```powershell
C:\AEGIS-kit\aegis-winctl.exe package verify `
  --package C:\AEGIS-kit --manifest-sha256 <independent-sha256>
```

## Configuration and fresh install

Import an existing private client configuration and credentials. Required scope:

```toml
mode = 'relay'
[ingress]
primary = 'socks5'
allow_fallback = false
[socks]
listen = '127.0.0.1:1080'
require_loopback = true
[relay]
# Use your existing authenticated relay settings and trust material.
tls_backend = 'rustls'
```

This fragment is not a complete access configuration. Keep existing relay token
or inner TLS authentication, CA and device identity. The installer copies the
specified existing identity; it never generates a replacement key. Original
source material remains under the operator's control. Config and private-key
source files must be accessible only to their owner, SYSTEM and Administrators;
a system-owned config may also grant LocalService read access. Do not relax
permissions to Everyone/Users to work around a rejected import.

For a service install, run elevated PowerShell and choose a new version directory
under ProgramData. User-profile/TEMP ancestry may deny access to LocalService:

```powershell
C:\AEGIS-kit\aegis-winctl.exe client install `
  --package C:\AEGIS-kit --manifest-sha256 <independent-sha256> `
  --config C:\Private\aegis.toml --root C:\ProgramData\AEGIS-Windows-v1 `
  --service --start
```

The source config is validated before writes; imported paths are relocated to
`config`, state to `state/brain.json`, and binaries to `bin`. Existing roots or an
existing `AegisClient` service are refused. Failed setup retains protected staging
for diagnosis. Use a new version directory for upgrades and explicitly manage the
old installation; there is no implicit adoption or overwrite.

For a per-user foreground install, omit `--service --start` and choose a new root
under your local application data directory. Start the installed executable with
`--config <root>\config\aegis.toml`.

## Status and lifecycle

```powershell
C:\AEGIS-kit\aegis-winctl.exe client status --root C:\ProgramData\AEGIS-Windows-v1
C:\AEGIS-kit\aegis-winctl.exe service status --service-name AegisClient
C:\AEGIS-kit\aegis-winctl.exe service stop --service-name AegisClient
C:\AEGIS-kit\aegis-winctl.exe service start --service-name AegisClient
C:\AEGIS-kit\aegis-winctl.exe client uninstall --root C:\ProgramData\AEGIS-Windows-v1
```

Invoke uninstall using winctl from the external kit, not the installed directory.
It preserves `config`, `state`, and the install receipt. Deletion can wait for
external SCM handles to close. It refuses binaries that changed or a service
belonging to another installation.

SCM states use numeric Win32 APIs, independently of Windows display language.
The service reports Running only after ingress initialization. Failure uses Win32
1066 and a non-sensitive service-specific stage: 1=early initialization,
10=config, 20=ingress selection, 30=listener/runtime initialization, 50=runtime.
No raw error file is created in ProgramData. Opt-in diagnostic logs remain private
operational material. For direct/auto disk-state opt-in, state replacement on
Windows fails safely while a reader holds the old file open; it never truncates the old snapshot.

## Development verification

```powershell
cargo test --locked -p aegis-core --lib
cargo test --locked -p aegis-client --no-default-features --bin aegis-client -- --test-threads=1
cargo test --locked -p aegis-winctl
cargo clippy --locked -p aegis-client -p aegis-winctl --all-targets --no-default-features -- -D warnings
```

Two opt-in tests use actual built binaries. The SCM test requires elevation and
creates/removes only a unique `AEGIS-Development-Test-*` service in ProgramData:

```powershell
cargo build --locked -p aegis-client -p aegis-winctl --no-default-features
$env:AEGIS_SCM_TEST_CLIENT = (Resolve-Path target\debug\aegis-client.exe).Path
$env:AEGIS_TEST_CLIENT = $env:AEGIS_SCM_TEST_CLIENT
$env:AEGIS_TEST_WINCTL = (Resolve-Path target\debug\aegis-winctl.exe).Path
cargo test --locked -p aegis-winctl -- --include-ignored
```

See Windows WFP development (archived: `docs/archive/design-baselines/windows-wide-capture-plan.md`) for the separate
controlled IPv4 TCP lab. Historical reboot/browser receipts do not establish a
current-build system-wide or reboot acceptance result.
