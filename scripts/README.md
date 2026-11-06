# Build, test and operator scripts

This directory orchestrates the Rust client, server and measurement tools, host utilities and release packaging. It contains build wrappers, local contracts and operations that change real networking. A `test-`, `proof-` or `run-` prefix alone does not identify a harmless command. Read the selected script's argument handling and the linked runbook before execution; some historical scripts carry old endpoint or artifact-directory defaults.

## Entry points

| Task | Entry points and dependencies |
| --- | --- |
| Linux private release | `build-release-delivery.sh`, `build-release-bundle.sh`, `build-container-release-delivery.sh`; pinned Rust, native build tools and the selected Linux ABI builder. |
| Native package layout | `build-package-root.sh`, `build-deb-package.sh`, `build-split-deb-packages.sh`, `build-rpm-packages.sh`; templates in [packaging](../packaging/README.md). |
| Project license packaging verification | [test-project-license-packaging.py](test-project-license-packaging.py) runs actual shell packager copies with inert tools, checking exact project texts, archive/hash inventories, disjoint role paths, explicit target fixtures and unique private compiler logs; no compiler, genuine DEB/RPM or installation acceptance. |
| Windows manifest handoff verification | [test-windows-manifest-signing-handoff.py](test-windows-manifest-signing-handoff.py) exercises the actual offline verifier using inert ZIP data; PowerShell runtime and Authenticode signing are separate gates. |
| macOS client archive | `build-macos-client-tarball.sh`; explicit Darwin target, pinned toolchain and native TLS/QUIC dependencies. |
| macOS utun lab main identity | `macos-utun-main-launch.sh` supplies direct non-root child UID/PID to four lab wrappers; `test-macos-utun-main-launch-inert.sh` checks only synthetic child/argument preservation. See the [lab boundaries](../tools/macos-utun-lab/README.md); native execution and full-wide acceptance remain separate. |
| macOS W0 installed helper selection | `run-macos-utun-helper-fd-loop-lab.sh` requires an absolute regular executable with no final-component symlink from `AEGIS_MACOS_UTUN_HELPER` or its installed default before Cargo/output writes; automatic `/tmp` executable copying is removed. `test-macos-utun-helper-selection-inert.sh` passed all six actual early-entry cases, stopping at inert Cargo; `test-macos-relay-reference-contract.sh` passed 114 source/reference controls with actual launcher/account prerequisites and inert helper data. Darwin CI selects these with main-launch checks in an early one-minute step; exact-commit CI remains pending. Path checks do not establish executable provenance or native acceptance. |
| Device bundle and acceptance | `render-device-client-bundle.sh` delegates typed public-bundle validation to a trusted installed client; `run-device-candidate-acceptance.sh` and `run-device-fullwide-acceptance.sh` are explicit lab controllers. |
| Linux routing lifecycle | `aegis-wide-enable.sh`, `aegis-wide-disable.sh`, `aegis-wide-persist-install.sh`, `setup-wide-linux-*`; reviewed interface, client profile, host privileges and recovery access are required. |
| Evidence summaries | `build-phase-*`, `build-*-summary.sh`, `*-status.sh`; many delegate to `aegis-measure` and consume existing evidence. A generated report is not a new live observation. |
| Contracts | Individual `test-*` scripts and `run-unwired-contracts.sh`; the latter dispatches contracts not already named in CI, with explicit exclusions. |

`test-private-nfqueue-packaging-contract.sh` checks the private helper inventories
and an extracted local copy function with temporary files. It verifies helper
bytes and executable mode, public-style absence and copy failure without
executing a helper, builder or network operation. CI discovers this contract
through `run-unwired-contracts.sh`. See [private NFQUEUE delivery](../docs/operations/linux-nfqueue-packaging.md)
for the remaining package, consumer and native acceptance boundaries.

The project-license fixture passed six methods; the Windows handoff fixture
passed eighteen. Python here implements verification only. Private Linux tar
delivery includes `LICENSE-MIT`, `LICENSE-APACHE` and `NOTICE` at archive root;
combined rootfs uses `/usr/share/doc/aegis`, while split DEB/RPM roles use
`/usr/share/doc/aegis-server` and `/usr/share/doc/aegis-client`. See
[packaging responsibilities](../packaging/README.md#authored-project-license-texts)
for byte/inventory scope and the outstanding third-party/native/signing limits.

[Shared helpers](lib/README.md), [Windows wrappers and contracts](windows/README.md), [Android evidence](android/README.md), [macOS NetworkExtension evidence](macos/README.md) and [test fixtures](tests/README.md) have separate ownership and prerequisites.

## Selecting a command

Run repository wrappers from the repository root unless their usage says otherwise. Bash, Python 3, Rust/Cargo or platform utilities are required only by the selected path; release scripts additionally enforce toolchain/lock/ABI constraints. For a non-mutating usage example, `bash scripts/build-release-bundle.sh --help` prints the bundle interface. Do not assume every script implements `--help` before doing work: `dev-setup.sh`, for example, generates local development key material when invoked.

`audit.sh` runs broad formatter/compiler/test checks; it is not a documentation check. Some shell contracts build binaries, use root networking or require a disposable OS. Use the actual job in [CI](../.github/workflows/README.md) to understand the relevant lane instead of running all scripts indiscriminately. Preserve failed artifacts and give retries distinct output locations.

The product is Rust-first. Python files here include disposable-VM controllers, capture parsers and contract helpers; their presence does not mean the client data path has moved to Python. Follow [orchestration ownership](../docs/development/shell-orchestration-policy.md), [candidate acceptance](../docs/operations/device-candidate-acceptance.md), [full-wide acceptance](../docs/operations/device-fullwide-acceptance.md) and [release operations](../docs/operator-guides/release-runbook.md). Public archives, private device access, signing inputs and provider administration remain separate. Never copy credentials, invitations or private keys into reports, public bundles or mirrors. Local/source checks do not establish release signing, installed lifecycle, restricted-network behavior, DPI resistance or beta exit.

## Server upgrade and client purge scope

`install.sh` refuses an existing selected server service environment or unit
path during an ordinary upgrade without `--force` or explicit reinstall,
before the server entry point's first binary preflight. Cancellation, explicit
reinstall's existing purge/force path and `--force` overwrite permission retain
their existing meaning; later input, custody and writer checks remain required.
`test-installer-server-upgrade-preflight-contract.sh` checks that early entry
point with temporary assets and inert callbacks.

`aegis-ubuntu-uninstall.sh` verifies its listed client installation paths, units
and networking checks; `purge-installed-aegis.sh` reports the selected
installation-residue scope. Both name standard retained device identity and
release-floor entries using metadata only. Custom identity locations and
per-user state are not scanned. Scoped success does not claim full erasure or
device revocation. `test-client-purge-retained-state-contract.sh` checks temporary
removal and exact synthetic retained-state bytes; its generic native cleanup
callback is explicitly inert, and the original uninstall/purge contracts remain
separate checks. These fixtures do not accept native service/network teardown.
See [installation records](../docs/operations/verified-installation.md#installation-records).

The ordinary Linux contract discovery in `run-unwired-contracts.sh` selects
explicit shell wrappers. Their Python companions are QA; these contracts also
exercise the Bash installers and uninstall/purge wrappers. Production transport,
routing and algorithm logic is Rust; installation orchestration includes shell
and embedded Python. Selection and source checks do not establish a completed CI or native
acceptance result.

## Documentation responsibility

Contracts that extract installer Python must require its isolated `python3 -I`
invocation. The provenance, host assessment, NetworkManager validator and relay
pinning fixtures execute that boundary with their original policy cases and
deadlines. NetworkManager adapts the marker only in its owned temporary test
copy; this does not assert isolation of the guard's separate Python commands.

This README owns this module’s purpose and entrypoints. Shared procedures live
in the [focused guide](../docs/development/shell-orchestration-policy.md); cross-component boundaries are in
[component ownership](../docs/architecture/OWNERSHIP.md). Link to those documents
when changing a shared contract; do not duplicate their instructions here.

## macOS installer contracts

`test-macos-release-toolchain-preparation-contract.sh` executes the actual
macOS builder with inert compiler, client and manifest-writer tools. Its three
positive and ten negative scenarios retain the original compiler pin, target
preparation, parallel-worker and failure-before-output assertions. The isolated
checkout stages the actual three project texts and maps real `shasum` and `mv`;
positive archives must contain those exact bytes and their expected hashes in
the rendered installer. GNU-style external gzip is also exercised. This is
build orchestration evidence, without native Rust compilation, installation or
release-authenticity acceptance.

`test-macos-bundled-masque-ca-contract.sh` retains six generated-installer CA
cases and adds six missing/tampered project-text refusals, destination refusal
before purge and actual Rust descriptor CLI controls. The synthetic checkout
runs the actual macOS shell builder with an inert compiler; a pinned actual
Rust manifest writer checks the produced archive. The compiled client, bounded
public stdin and temporary filesystem operations are real. Foreground mode,
local archives and inert OS tools avoid starting services or modifying the real
Keychain or proxy. Darwin CI checks and runs all eight existing CA tests and six
private-filesystem descriptor regressions before this contract, retaining its
10-minute bound. Root UID0, native installed lifecycle, cross-filesystem mounts
and release authenticity are separate gates. See [CA installation and evidence
limits](../docs/operations/masque-association-testing.md) and
[project-text packaging](../packaging/README.md#authored-project-license-texts).

## Dependency security

[Security helpers](security/README.md) own the versioned RustSec policy and
isolated dependency audit; ignored editor and local Cargo settings are not CI inputs.

`test-installer-python-isolation-contract.sh` exercises the actual standalone
bootstrap download helpers against harmless modules placed in the working
directory and `PYTHONPATH`, including their child interpreter. This contract
checks the bootstrap Python isolation boundary; private access acquisition
uses the verified Rust client and has no urllib HTTP(S) fallback. Relative file arguments keep their
existing meaning; isolation does not establish trust in a replaced interpreter
or in system-wide Python libraries.

`test-installer-wide-activation-preflight-contract.sh` exercises the actual
installer activation and client caller with 29 temporary, inert fixtures.
Requested legacy capture modes reject missing privileges or required setup
assets before the explicit installation reaches a mutation checkpoint. Valid
assets, noncapture modes and cancellation retain their existing admission
behavior. For admitted automatic selection, configuration custody still precedes
the planner and can affect an existing service. The two deterministic AUTO
refusals below now occur before custody. These checks do not execute capture helpers or establish
native routing, activation or leak prevention.

`test-installer-auto-refusal-before-custody-contract.sh` extracts the actual
client installer entry and records inert boundaries against temporary synthetic
configuration. AUTO reinstall without a bundle, existing configuration without
a managed product profile, and a custom systemd directory refuse before
configuration custody. A managed-upgrade control preserves binary
authentication/ABI admission, then custody, then planner ordering. It stops at
the inert planner and does not accept migration, restart or installation.
Planner and selected-capture refusals still occur after validated custody;
their whole-transaction ordering remains outside this narrow repair.

`test-auto-native-capture-witness-contract.sh` runs the backend's pure
`BeginCapture` preflight on the host and checks that dispatch invokes it before
stage admission. It also rejects any path that marks capture started from
service READY alone. This is source-level refusal evidence, not a native Linux
capture, guard, activation or installed lifecycle test.

`test-vendored-integrity-contract.sh` first compares the vendored package's
provenance inventory with tracked Git paths, so ignored local files cannot make
its fixture copy pass when a fresh CI checkout would fail. The upstream h2
lockfile is intentionally tracked despite its unchanged upstream ignore rule.
Original upstream checksums, the exact local patch, tamper rejection and the
advisory audit remain separate required checks.

`test-legacy-tun-guard-lifecycle-contract.sh` extracts the actual legacy
activation function together with its `preflight_wide_capture` dependency.
Its rebased activation retains privilege/helper admission before configuration
changes; guard unit, nft rule, restart, failure and explicit disconnect checks
run against inert administrative commands. This fixture does not accept native
firewall, boot ordering or installed-client leak prevention.

`test-wide-config-staging-contract.py` exercises the actual DNS-preview config
fragment and installed Rust metadata writer. Config-bearing records use
exclusive0600 files in a fresh0700 staging directory before rendering or
publication. Missing installed config, unknown service identity or an older
writer/rollback helper refuses before capture. A late failure uses independent
disable and preserves or exclusively restores the exact original backup; an
unverifiable restore retains its private recovery snapshot. Ordinary disable
still removes its backup. Thirty-one local cases pass; service/root identity
and system/firewall callbacks are recording seams, not native rollback proof.
The unchanged no-section warning/removal case proves output compatibility,
not that a DNS listener is configured.

`test-wide-linux-redirect-cgroup-contract.sh` extracts both actual preflight and
activation, using an executable fixture-owned inert helper. Existing unsupported
kernel-match and managed/no-cgroup assertions remain. Local fixture success does
not accept privileged native cgroup/firewall/routing behavior.

`generate-relay-materials.sh` now uses the supplied deployment identity for its
private CA subject. The real OpenSSL contract retains SAN, chain, key-mode and
SPKI controls. The [TLS material guide](../docs/operations/relay-tls-materials.md)
owns issuance, existing-client trust/pin migration and deployment boundaries;
no live certificate rotation is implied by a generator source change.

## Native device guard emitted-batch QA

`test-device-egress-guard-native.py` explicitly runs the pinned v1 production
renderer through native nft check/apply and 20 isolated local IPv4/IPv6 DNS/data
outcomes. Read [its prerequisites, command and evidence limits](../docs/operations/device-egress-guard-native-smoke.md)
before execution. Linux user/network/PID/mount namespaces and native tools are
required; no existing VM, installed client or host routing mutation is used.
The driver never escalates itself; CI explicitly selects one `sudo -n` invocation
while preserving fresh namespaces and all source/tool pins.
`deviceguard-native-private-stage.py` stages only pinned inputs outside the
runner workspace and exports bounded evidence after owned child cleanup.
It preserves the private stage and records export completion or failure
separately from the native result. The separate
`handoff-deviceguard-ci-evidence.py` transfers only the verified current attempt's
private files to the CI uploader. `test-deviceguard-ci-privilege-contract.sh` and
`test-deviceguard-evidence-handoff-contract.sh` and
`test-deviceguard-private-stage-contract.sh` use mocks and temporary files;
they do not execute sudo or native operations. These are Python QA tools, with
no client data-path implementation.
CI selects it directly and retains unique failed attempts. The general shell
contract dispatcher does not discover this `.py` file. Source integration alone
does not establish native, full lifecycle or beta acceptance.


## Dedicated service account refusal

`test-installer-service-privileges.sh` retains capability rendering controls and
adds 25 inert regressions for the selected account resolver, profile writer and
client-service boundary. Account commands, ownership changes and activation are
stubbed in private temporary directories; it does not run the installer entry
point or native systemd.

Required dedicated-account selection refuses UID0, malformed IDs and unsafe
fallback IDs, and verifies the account after creation. Resolver, ownership,
mode, directory, profile write/unlink and prior-profile backup-copy errors return
before required client activation. The base unit is published after required
privilege-profile preparation. Existing capability policy remains unchanged.

All 25 candidate cases and retained rendering controls passed locally against
the extracted source. The original had 19 assertion failures and six controls;
the malformed-primary case checks controlled refusal diagnostics. Early resolver
refusal preserves existing unit/profile files. Earlier installation work and
late partial file changes are not a whole-installer transaction. Native Linux
account policy, lifecycle/rollback and exact-final CI remain required; the
[change log](../CHANGELOG.md) records those limits.

## Vendored h2 source contract

`test-h2-pseudo-header-order-contract.sh` parses the actual Cargo
`[patch.crates-io]` table with Python's standard-library `tomllib` (Python 3.11+),
then checks the reviewed vendored header marker and textual drain order.
`test-h2-pseudo-header-order-manifest-contract.sh` exercises the actual script
with temporary manifests and inert header fixtures, including version/key-order
changes, explicit h2 package naming, and wrong-package/comment/other-section false positives. The new shell wrapper is
selected by `run-unwired-contracts.sh`; no new workflow exclusion is required.
These are source/configuration contracts, not HTTP/2 wire or upstream test
acceptance. Exact-commit CI remains a separate result.


## Shipping client inventory checks

The release builder and Rust measure tool emit the versioned Linux client
Cargo inventory described in [public delivery](../docs/operations/public-client-delivery.md#shipping-client-cargo-inventory).
`test-shipping-client-inventory-consumers-contract.sh` executes the actual
embedded installer/bootstrap and offline controller/CI verification bodies
on inert inputs. `test-public-client-bootstrap-contract.sh` separately checks
real test signatures and versioned public/private archive admission, executing
only an inert installer marker. Both contract wrappers are selected by the
existing CI contract runner. Python here verifies release metadata; the client
and inventory producer remain Rust. Full native lifecycle and shipping SBOM
acceptance are separate.
