# Dependency security checks

`cargo-audit.toml` owns the checked RustSec exception and deny-warning policy.
`audit-dependencies.sh` copies that policy into an isolated temporary audit
working directory and checks the workspace's exact `Cargo.lock`. It does not
use a developer's ignored `.cargo/` files or replace the vendored-source audit.

From the repository root:

```sh
bash scripts/test-cargo-audit-policy-contract.sh
bash scripts/security/audit-dependencies.sh
```

The policy contract rejects the exception if `proc-macro-error2` enters the
active all-feature/all-target dependency graph. Remove the exception when the
lockfile no longer retains that package. The workflow pins cargo-audit 0.22.2.

Parent: [scripts](../README.md); [development guidance](../../docs/development/README.md).

## Tracked evidence containment

`check-tracked-evidence-secrets.py` scans tracked evidence text up to 2 MiB per
file, including BOM-marked Windows UTF-16 logs. Complete valid TOML and JSON
are parsed with Python 3.11+ so quoted/escaped keys and multiline credential
values receive the same check. Logs and invalid historical fragments use the
narrow lexical check. It rejects detected relay credential literals, private-key
headers and non-redacted private bundle URL files.
Diagnostics contain paths and finding classes only. Explicit redaction markers
and whole shell variable templates are admitted; embedded literal prefixes are
not. Run its synthetic diagnostic-boundary contracts with:

```sh
python3 -I scripts/security/test_tracked_evidence_secrets.py
python3 -I scripts/security/check-tracked-evidence-secrets.py
```

CI runs this narrow gate independently of the Rust build. It reports excluded
binary/large/other files; it does not inspect Git history or archives, recognize
every possible credential encoding, verify revocation or replace a full secret
audit. It inventories the retained evidence fixtures under
`scripts/tests/fixtures/evidence/`; other evidence stays outside Git (see the
[evidence archive](../../docs/operations/evidence-archive.md)). A fixture enters
the tree only after review and must contain no credentials or raw private
captures. See the [October security repair record](../../docs/operations/security-audit-2026-10-10.md).

## Separately staged public source verification

`check-public-source-tree.py` verifies an independently prepared candidate text
tree against a mandatory, nonempty JSON file allowlist and a mandatory private
JSON denylist. It does not assemble an export. Inputs must remain outside the
candidate tree; symlinks, unlisted or missing files, VCS metadata, unreadable
files, unsupported text/binary data and size-limit violations fail the gate.
It checks exact denied strings in paths and content and adds narrow credential
form checks, private PGP key blocks, globally routable IPv4 literals and
unapproved domain-shaped strings. Diagnostics use opaque finding indices,
never paths, matched values or reversible unsalted path hashes. See
[input formats, limits and interpretation](../../docs/development/public-source-boundary.md#verification-gate).
Run only the inert temporary fixture contracts during private development:

```sh
python3 -I scripts/security/test_public_source_tree.py
```

A fixture-suite PASS establishes the gate's tested behavior. It does not attest
that the private repository, any export candidate or Git history is clean.

The standalone `public-source-boundary.yml` workflow runs these inert contracts
on pull requests and branch pushes. Its manual job verifies only separately
prepared candidate/control artifacts with explicit IDs; missing inputs fail.
The private denylist is still a mandatory owner-maintained input, never a
committed operational inventory. This job neither exports nor publishes code.
See the boundary guide for domain approvals and manual artifact preparation.

## Offline grant-preparation verification

`check-grant-register.py` reads the grant register and verifies all 37 original
IDs exactly once in table first cells. It refuses omissions, duplicates and
malformed/unknown IDs while ignoring prose and fenced examples. It checks ID
coverage only, not full Markdown syntax or the truth of a row's claim.

`check-study-receipt.py` reads one bounded regular JSON file without collecting
data, running a study or making a network request. The strict
[schema](../../docs/grants/study-receipt.schema.json) and cross-field checks
distinguish no-run/refusal/failure/completion, run and capture readiness,
independent full capture duration and total traffic including cover/overhead.
Output contains fixed codes and aggregate state, without input IDs or paths.
A valid record never certifies consent, real measurements or privacy acceptance.

```sh
python3 -B -m unittest discover -s scripts/security -p 'test_grant_register.py' -v
python3 -B -m unittest discover -s scripts/security -p 'test_study_receipt.py' -v
python3 scripts/security/check-grant-register.py docs/operations/grant-readiness-2026-10-11.md
python3 scripts/security/check-study-receipt.py docs/grants/study-receipt-example.json
```

The [grant-preparation workflow](../../.github/workflows/grant-preparation.yml)
runs these synthetic checks and the not-run example. The
[field protocol](../../docs/grants/field-study-protocol.md) retains consent,
capture/rollback, retention and actual field-evidence gates separately.

## Nested ring notice policy

The [client notice collector](../../tools/measure/src/public_client_delivery.rs)
includes `third_party/fiat/LICENSE` and `src/polyfill/once_cell/LICENSE-MIT`
for reachable crates.io `ring` 0.17.14. Fixed package/version/source checks and
non-symlink package-relative components require nonempty UTF-8 regular text up
to 64 KiB per leaf. Each leaf is read into owned bytes once and rendered from
that snapshot; the existing top-level discovery and feature/reachability graph
are unchanged. Unknown versions or sources require another policy review.
The checksum-verified immutable Cargo cache and its ancestors outside the
package remain trusted inputs; these checks do not resist hostile concurrent
cache changes or authenticate an arbitrary local cache. The general collector
also rejects absolute/traversing `license_file` values and resolves each notice
candidate under its package directory, except for the three reviewed workspace
leaves. On Unix the collector opens each absolute anchor component from `/`
with no-follow flags, then opens each package-relative component from held
directory descriptors and reads the validated regular file descriptor. This
also covers the two nested `ring` notices, reviewed workspace leaves and member
manifest text used for inherited-license decisions. A concurrent symlink swap
in an ancestor or child path cannot redirect that read. Cargo metadata and the
contents of in-scope files still need trusted, stable provenance; a hostile
writer can replace a real directory or edit a permitted file. The non-Unix
fallback uses canonical path checks followed by pathname reads and requires
immutable build inputs.

Private production-module fixtures passed 14 tests; locked offline Cargo
metadata checks passed for x86_64/aarch64 Linux and Darwin, and x86_64 Windows.
The production Cargo target and strict Clippy checks are recorded separately
in the incident log. These checks exercise build-side collection, without target
compilation or installed-client acceptance. It does not accept actual release packaging, full dependency
notices, SBOM, legal completeness, native behavior or signing. See the
[incident record](../../CHANGELOG.md) for preserved
RED/INVALID evidence and the outstanding exact-commit CI gate.

## Source SBOM and shipping inventory scopes

`generate-sbom.sh NEW_OUTPUT_DIRECTORY TARGET_TRIPLE` uses pinned
cargo-cyclonedx 0.5.9 for two complete matching CycloneDX 1.5 workspace-default
Cargo metadata inventories. Inputs are locked and source-pinned; the outputs
remain private verification evidence. This standalone recipe does not bind
shipping features, delivered binary bytes, a complete native payload or an
independent reproducible build.

The separate [Rust shipping inventory producer](../../tools/measure/src/shipping_client_inventory.rs)
and [public delivery contract](../../docs/operations/public-client-delivery.md#shipping-client-cargo-inventory)
now bind the Linux client's explicit producer recipe, actual compiler-artifact
root features, target, revision, lock and staged binary hash to its selected
Cargo graph. The public v3 archive carries that JSON inventory, not the old
workspace-default CycloneDX files. Transitive features remain metadata union;
local identities hash manifests, not complete source code. Native/non-Cargo
components, delivered Windows DLL/license/source provenance, compiler linkage,
independent binary builds and final signed release acceptance remain separate
gates. The grant register's P1.9 stays Partial.

## Linux AUTO filesystem verification

`run-installer-auto-native-ci.py` owns the fixed source/selection bindings,
explicit native Linux build, compiled test-list admission and exactly 39
root filesystem component methods. The controller and selection remain
verification tools; the product transaction is Rust. The separately owned
[QA lane](../qa/auto-native/README.md) supplies bounded supervision and an
explicit failed-diagnostic allowlist in disposable GitHub Ubuntu runners.
No installed activation, native capture, signing or beta acceptance follows
from compilation or these filesystem tests.
