# Shell Orchestration Policy

Status: maintainability policy for scripts.

AEGIS is a Rust-first product and evidence codebase with thin shell and
PowerShell orchestration. Existing scripts are not automatically wrong, but new
truth-bearing logic should move toward Rust validators.

## Rust Owns Product Truth

Rust should own:

- Brain and strategy selection.
- Calibration, priors, posterior logic, and scoring.
- Runtime-events schema and validation helpers.
- `result.json` schema and artifact validation.
- Evidence gates and master-plan handoff checks.
- Classifier and witness interpretation.
- Release, bundle, and manifest validators.
- Redaction and secret-scan logic where feasible.

## Shell Owns Host Orchestration

Shell may own:

- independently pinned launcher/bootstrap entrypoints.
- Package install orchestration.
- `systemctl`, `launchctl`, `pfctl`, `iptables`, `nft`, `route`, `tcpdump`,
  `dig`, `curl`, and SSH/VPS commands.
- Calling Rust tools.
- Moving files into artifact directories.

Shell should not own:

- hidden thresholds;
- final product PASS/FAIL logic when Rust can own it;
- duplicated JSON schema;
- transport scoring;
- classifier interpretation;
- overclaim-prone status aggregation.

## PowerShell Owns Windows Orchestration

PowerShell may own:

- Windows service install/start/stop/uninstall orchestration.
- WFP proof runner orchestration.
- Windows host commands.
- Calling Rust tools and low-level helper binaries.

PowerShell should not silently claim:

- broad Windows wide capture;
- DNS capture;
- UDP capture;
- IPv6 capture;
- production driver support.

## C Boundary

C is allowed only for:

- low-level Windows WFP helper boundaries;
- tiny OS helper surfaces where Rust FFI would be worse right now.

C helper behavior must be wrapped by Rust/PowerShell evidence logic and
documented in platform plans.

## Migration Classes

Script inventory should classify scripts as:

- `KEEP_SHELL_THIN`: orchestration is appropriate.
- `MIGRATE_TO_RUST`: product truth, schema, scoring, or validation should move.
- `HISTORICAL_ARTIFACT`: old proof script preserved for reproducibility.
- `UNKNOWN`: needs audit before changes.

## First Migration Targets

Preferred future migration targets:

- artifact/result engine;
- release manifest validator;
- bundle verifier;
- installer validation summaries;
- shared redaction/secret scan.

Do not migrate all scripts at once. Each migration must preserve behavior and
keep wrappers available when operators need system command orchestration.

## Current Reduction Status

The active `scripts/` and `tools/` trees contain Python helpers for laboratory,
CI contracts and bounded device/capture orchestration. Examples include
`scripts/lib/device_candidate_acceptance.py`, `device_candidate_verify.py`,
`device_candidate_vm.py` and `device_fullwide_acceptance.py`. These do not move
production transport or algorithm logic out of Rust. Inventory the actual
consumer and side effects before classifying a helper; Python is not confined
to historical artifacts or inline snippets. Product/evidence truth continues
moving to focused Rust commands where the existing contract can be preserved.

Recent Rust-first migrations:

- `scripts/release-opsec-gate.sh` now calls
  `aegis-measure release-opsec-gate`; the former Python opsec scanner was
  removed from the active tree.
- `scripts/build-linux-wide-live-audit-manifest.sh` now calls
  `aegis-measure build-linux-wide-live-audit-manifest`; the former Python live
  audit manifest writer was removed from the active tree.

Next reduction targets:

- Move repeated inline JSON assertion blocks from shell contracts into focused
  Rust contract-check commands where the check is product/evidence truth.
- Keep live/VPS scripts as shell while moving manifest, verdict, threshold, and
  overclaim-prevention logic into `aegis-measure`.
- Audit the largest Linux wide scripts in small slices instead of reducing shell
  line count by deleting operational safety checks.
- Keep CI resource workarounds, temporary directory setup, package installation,
  and `sudo` host cleanup in workflow/shell layers; these are orchestration
  responsibilities, not product truth.
