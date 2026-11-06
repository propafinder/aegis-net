# Shared orchestration and lab helpers

These helpers are dependencies of selected scripts, not a single command suite. Shell libraries are generally sourced by a caller that supplies context. Python controllers are lab tooling; Rust code here is a small shared build-time validator. Read the parent wrapper before invoking a helper directly.

| Surface | Responsibility |
| --- | --- |
| `host-arch.sh`, `release-toolchain.sh`, `release-abi.sh` | Canonical architecture names, exact compiler checks and Linux GLIBC requirements. `test-host-release-abi.sh` is explicitly for local test fixtures, not production release admission. |
| `root-state.sh` | Validates administrator-owned installed executables and dispatches protected metadata operations. It is a production trust boundary, not a test-path override. |
| `smoke-root-state-client.py` / `.sh` | Stages explicitly pinned executables for disposable Linux smoke tests and tracks owned cleanup. It does not authenticate an arbitrary supplied build. |
| `device_candidate_verify.py`, `device_candidate_acceptance.py`, `device_candidate_vm.py` | Offline signed-input verification, marked disposable-guest lifecycle tests and owned KVM clone control. Use the parent `run-device-*` wrappers and their runbooks. |
| `shipping_client_inventory.py` | Offline verification glue for the Rust producer's v3 client Cargo inventory. Device controllers import it; standalone bootstrap/install and CI use the same bounded verifier contract. It checks archive-bound inventory graph and source/target/lock/features/binary bindings without Cargo, compilation, network activity or runtime transport logic. |
| `device_fullwide_acceptance.py` | Explicit activation/recovery of an installed original profile; it does not install, enroll or issue credentials. |
| ClientHello capture and conversion helpers | One-shot local listeners and raw-record conversion; canonical JA4 comparison requires the same tshark interpretation on both sides. |
| `rotate-auth-token-remote.py`, `stage-legacy-auth-token-remote.py` | Credential-handling remote operations with bounded legacy-key semantics. These are not generic local test commands. |
| `aegis-measure-run.sh`, `guarded-smoke-status.sh`, `smoke-preflight-exit-codes.sh` | Bounded evidence-tool invocation and stable orchestration status reporting. |
| `research_build_target.rs` | Structural validation of Cargo target strings used by research-tool build hooks. |

Prerequisites depend on the caller: Bash/Python 3, Cargo, platform commands, capture permissions, or a specifically authorized disposable Linux host. Do not source this whole directory. For example, the [candidate wrapper](../run-device-candidate-acceptance.sh) forwards arguments to its documented controller; the [acceptance runbook](../../docs/operations/device-candidate-acceptance.md) defines its trust inputs. Companion `test_*.py` files use controlled fixtures; they do not establish guest or release acceptance.

Preserve owned resource identities, original deadlines and failed receipts. Never put protected configuration, tokens or keys into shell arguments or public output as a convenience. [Full-wide acceptance](../../docs/operations/device-fullwide-acceptance.md) and the [script guide](../README.md) distinguish production networking from test orchestration.

## Versioned shipping inventory

New public client archives use `aegis_client_release_bundle_manifest_v3` with the
single additional `client-cargo-inventory.json` leaf. V1/v2 inventories retain
their exact earlier closures; explicit v3 admission does not change a
controller's historical default schema selection. The bounded JSON verifier
requires producer-observed root-feature consistency and rejects native/linkage
completeness claims. It cannot reconstruct compiler units or independently
prove that a signed producer described every native dependency. Keep this
verification module synchronized with the Rust producer and all standalone
embedded consumers. See [public delivery](../../docs/operations/public-client-delivery.md#shipping-client-cargo-inventory).
