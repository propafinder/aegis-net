# Windows scripts

The active build, install and uninstall scripts are thin wrappers over
`aegis-winctl`. See [the current runbook](../../docs/platforms/windows/windows-install-runbook.md)
for prerequisites, exact arguments, ACL policy and evidence limits.

- `build-windows-package.ps1`: `-OutputDir`, `-SourceCommit`, optional
  `-ClientExePath` and `-WinctlExePath` (release binaries by default).
- `install-windows-client.ps1`: `-PackagePath`, `-ManifestSha256`, `-ConfigPath`,
  `-Root`, optional `-WinctlExePath`, `-Service`, `-StartService`.
- `uninstall-windows-client.ps1`: `-Root`, `-WinctlExePath` from the external kit.

Rust owns validation, package integrity, native SCM operations and installation
receipts. Wrappers propagate its exit code. The old `-Force`, `-InstallScope`,
`-CaPath` and implicit existing-install overwrite interfaces are retired.

The `run-wfp-*` and older service/network proof scripts are historical, opt-in
proof scaffolds. They are not the normal installation path and may target earlier
binary/driver interfaces.
WFP API 2 requires matching current controller and driver builds. Do not infer
live capture, reboot success or signed-driver availability from script presence.
The Rust proof commands retain explicit scope and distinguish a prepared receipt
from an actual post-reboot observation.

## Current contract tests and kit construction

`test-authenticode-*.ps1`, `test-research-*.ps1` and `test-kit-cargo-feature-scope.ps1` are active build/signing-boundary contracts, not historical live-proof entry points. Their synthetic metadata, mocked adapters and local file-sharing cases have different prerequisites; adapter-custody tests require actual Windows. CI selects PowerShell 5.1 and/or PowerShell 7 explicitly. A mocked signing contract does not provision a production signer or prove a valid signature.

The full candidate builder is [tools/windows/build-kit.ps1](../../tools/windows/build-kit.ps1); the thin `build-windows-package.ps1` wrapper above exposes a smaller packaging interface. Consult [workflow documentation](../../.github/workflows/README.md) and the [Authenticode runbook](../../docs/operations/windows-authenticode-release.md) before constructing or promoting a kit. Production provider inputs and private client configuration remain separately supplied.

Choose fresh artifact directories and review hardcoded defaults before any historical proof. Many proofs change native filtering, services, routing or listener state and require an authorized disposable Windows host with independent recovery access. A Prepare result is not VerifyAfterReboot. This directory's documentation does not assert that a particular candidate passed native, leak, timing or beta acceptance.

## Retired legacy service installer

`install-windows-service.ps1` now refuses immediately, including `-WhatIf`,
`-Force` and `-StartService`. Its former configuration copy could write private
material before establishing an exclusive ACL. The refusal does not stop,
remove, adopt or modify an existing installation.

For a fresh service installation, use the external, verified kit's
`aegis-winctl.exe client install --help` and follow the
[current runbook](../../docs/platforms/windows/windows-install-runbook.md).
Supply the independently authenticated manifest SHA-256 and an existing private
configuration; choose a new root. The supported installer refuses an existing
root or service, so this is not an automatic migration of an old installation.
Historical proof scripts that call the retired entry point now refuse too; they
are not silently redirected to a different service or credential layout.

The refusal contract invokes the complete script with inert path-callback
recording before any native operation. It does not establish actual host ACLs,
LocalService access, service lifecycle, leak, timing or release acceptance.

## Retired WFP driver deployment script

`install-wfp-proof.ps1` refuses before path queries, artifact writes, signing or
service operations. Its old flow could stop/delete an existing kernel service
and start a driver copied into an ambient artifact directory without protected
machine staging and pinned signature/hash custody. Parameter names remain
available, but their retired defaults no longer evaluate path cmdlets.
Existing drivers, services and installations are not modified or removed.

This is legacy containment only. The current `aegis-winctl` WFP commands do not
provide a protected signed-driver staging/load workflow. Do not redirect this
script to generic service installation, relax ACLs, adopt an existing service,
or select an automatic signing certificate. A reviewed Rust staging/load owner
and separately authorized native driver validation are still required.
Historical WFP proof scripts that invoke this installer now deliberately refuse;
normal Rust client installation is a separate workflow and does not deploy this
legacy WFP driver.

The whole-script refusal contract supplies explicit owned paths and records the
old first directory-write boundary without executing it. It establishes no
native driver ACL, signer provenance, Code Integrity, WFP filtering, reboot,
rollback, full-wide or release acceptance. Previously installed service paths
are not repaired by this refusal.
