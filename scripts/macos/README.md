# macOS NetworkExtension evidence wrapper

`run-networkextension-system-wide-proof.sh` prepares the Phase D Packet Tunnel proof shape. It accepts an artifact directory, expected egress, a signed host application and an extension bundle. This path is distinct from the SOCKS client, PF operator helpers and utun experiments in the parent script directory.

The wrapper deliberately reports BLOCKED without the required macOS/Xcode tooling, signing material, approved VPN configuration and actual Packet Tunnel runtime proof. Its first-argument `--help` prints usage and exits 2. Inspect that interface before preparing a disposable test environment; a prepared receipt or a bundle on disk is not an active extension or observed system-wide traffic.

The companion [source contract](../test-macos-networkextension-system-wide-proof-contract.sh) checks this reporting boundary. [Phase D aggregation](../build-phase-d-macos-reach-evidence.sh) consumes evidence, while the macOS wide runbook (archived: `docs/archive/design-baselines/08-macos-wide-runbook.md`) covers separate platform contours. Certificates, entitlements and provider approval remain operator inputs. Do not interpret a local contract pass as Apple signing/notarization, installed lifecycle, independent capture or beta acceptance.
