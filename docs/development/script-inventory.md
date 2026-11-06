# Script Inventory

Status: initial classification for maintainability planning. This inventory is
not exhaustive; it identifies the first obvious buckets.

## KEEP_SHELL_THIN

These scripts are expected to remain shell/PowerShell wrappers around system
commands or Rust tools:

- `scripts/build-phase-d-reach-gate.sh`
- `scripts/build-phase-d-windows-reach-evidence.sh`
- `scripts/build-phase-d-macos-reach-evidence.sh`
- `scripts/build-phase-d-android-reach-evidence.sh`
- `scripts/build-master-plan-handoff.sh`
- `scripts/build-release-latest-parity-gate.sh`
- `scripts/run-macos-utun-w5-controlled-external-relay-path.sh`
- `scripts/test-build-release-latest-parity-gate-contract.sh`
- `scripts/test-release-latest-parity-contract.sh`
- `scripts/windows/install-windows-service.ps1`
- `scripts/windows/uninstall-windows-service.ps1`
- `scripts/windows/install-wfp-proof.ps1`
- `scripts/windows/run-windows-wide-service-reboot-proof.ps1`

## MIGRATE_TO_RUST

These areas should move product truth toward Rust over time:

- release manifest validation scripts;
- bundle verification scripts;
- installer validation summary scripts;
- artifact status aggregation still expressed primarily in shell;
- repeated redaction and secret scan snippets.

Candidate examples:

- `scripts/validate-debian-package-host.sh`
- `scripts/validate-wide-linux-tproxy-rich-host.sh`
- `scripts/build-macos-client-tarball.sh`
- `scripts/build-ubuntu-controlled-pilot-bundle.sh`

Recently migrated examples:

- Release/latest parity verdict logic now lives in
  `aegis-measure release-latest-parity`; shell only selects input artifacts,
  writes command/environment sidecars, and preserves the Rust result.
- Release opsec scanning now lives in `aegis-measure release-opsec-gate`; shell
  is a thin compatibility wrapper.
- Linux wide live-audit manifest/summary generation now lives in
  `aegis-measure build-linux-wide-live-audit-manifest`; shell is a thin
  compatibility wrapper.

## HISTORICAL_ARTIFACT

These should be preserved unless they block current contracts:

- old live audit runners under Phase A/B/C;
- historical macOS PF proof scripts;
- historical Linux mimicry and validation scripts tied to committed artifacts.

## UNKNOWN

Large shell scripts that need a focused audit before refactor:

- `scripts/setup-wide-linux-tproxy.sh`
- `scripts/smoke-wide-linux-tproxy.sh`
- `scripts/run-linux-wide-mimicry-live-audit.sh`
- `scripts/test-wide-linux-tproxy-firewall-contract.sh`
- `scripts/test-run-linux-wide-mimicry-live-audit-contract.sh`

First audit result:

- The 11 October 2026 inventory includes 49 standalone `.py` files under
  `scripts/` and `tools/`, including bounded device/VM controllers and CI/contract
  helpers. This is a dated file count, not a claim that all files are active
  product code.
- Inventory each actual consumer and side effect before migration. Product
  runtime remains Rust; orchestration and evidence helpers have separate
  ownership in [the shell policy](shell-orchestration-policy.md).

## Policy

Scripts may orchestrate host state. Rust should own verdicts, schemas,
thresholds, scoring, and overclaim prevention.
