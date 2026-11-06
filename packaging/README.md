# Installation and service templates

This tree supplies package payload documentation, environment examples and OS service/state templates. Build and install code selects and renders these files; this is not a directory to copy wholesale onto a host. `__AEGIS_*__` placeholders must be resolved by the appropriate installer before a service is loaded.

| Directory | Consumer and purpose |
| --- | --- |
| [client](client/README.md) | Public Linux client package instructions; private access is delivered separately. |
| [debian](debian/README.md) | Combined/client/server role instructions used by Debian packages. |
| [env](env/README.md) | Optional client/server environment examples. |
| [systemd](systemd/README.md) | Linux runtime, device-policy, enrollment and optional operator units. |
| [systemd-preset](systemd-preset/README.md) | Explicit disabled-by-default package role presets. |
| [launchd](launchd/README.md) | User LaunchAgent and explicitly selected dedicated-user LaunchDaemon templates. |
| [sysusers](sysusers/README.md), [tmpfiles](tmpfiles/README.md), [tmpfiles.d](tmpfiles.d/README.md) | Role accounts, runtime/config directories and the separate enrollment-transfer template. |
| [nftables](nftables/README.md) | Narrow private deployment firewall additions. |
| [journald](journald/README.md) | Optional host-wide volatile-journal policy. |

The [package-root builder](../scripts/build-package-root.sh), [release bundle builder](../scripts/build-release-bundle.sh) and [installer](../install.sh) define actual payload paths. Private operator files can appear in an operator archive without belonging in the public client archive. Consult [release operations](../docs/operator-guides/release-runbook.md) and the role's runbook before installation.

## Authored project license texts

The private Linux release tar includes the root `LICENSE-MIT`, `LICENSE-APACHE`
and `NOTICE` verbatim. The combined package root places these three files in
`/usr/share/doc/aegis/`. Split Debian and RPM packages instead use their own
`/usr/share/doc/aegis-server/` or `/usr/share/doc/aegis-client/` paths, so the new
license files do not collide between roles. RPM lists them explicitly as
`%license` files; the old payload lists retain their separate scope.

The macOS software tar also carries these exact root texts, with hashes emitted
by the actual Rust manifest writer and embedded in its generated installer.
The installer snapshots and checks all three before fetching access material
or purging an existing installation. Documentation belongs in
`~/.local/share/doc/aegis/`, separate from private configuration and state. A
typed Rust helper binds the physical HOME to the exact target UID, traverses
the fixed suffix through held directory descriptors, and atomically publishes
fresh public-text files. It does not chmod or chown existing documentation
directories. Existing symlinks/hardlinked leaves are refused. HOME and existing
suffix directories must share the trusted staging filesystem; incompatible
filesystems are refused before purge. This is a narrow documentation-write
boundary, not a transaction or security review of the whole installer.

The Windows installer separately retains the declared texts in private
`licenses/` with receipt hashes outside the executable inventory. Legacy
packages retain their former closed payload list. Native Windows installation,
root macOS installation and whole-client lifecycle remain acceptance gates.

The [Linux functional fixture](../scripts/test-project-license-packaging.py)
passed six methods running copies of the actual shell packagers with inert
compiler, ABI and package-format tools. It checks produced archive bytes,
checksums, role-specific paths and missing-text refusals. This is not genuine
DEB/RPM construction, installation, compiler/ABI acceptance or signing evidence.
The [Windows handoff fixture](../scripts/test-windows-manifest-signing-handoff.py)
passed eighteen methods against the actual offline verifier with inert ZIP
data. PowerShell runtime and native Authenticode signing remain unaccepted by
these local checks. The three project files and NOTICE attribution index do not
establish complete third-party notices or redistribution clearance for a release.
The vendored h2 LICENSE is copied byte for byte into the release bundle and
package-root `third-party/h2/` documentation, then into both role-specific
DEB and RPM documentation trees. The inert functional fixture checks archive
bytes, modes, DEB md5sums and RPM `%license` entries. Other dependency notices
and exact built-package acceptance remain open.

The private Linux research operators use
[research-operator-guides.txt](research-operator-guides.txt) as their bounded guide
allowlist. The release builder copies those guides, and the Rust manifest writer
requires and hashes the same files. When changing an included guide's local
links, update that allowlist and the package closure checks together; never add
source, evidence, profiles or credentials to this documentation payload. See
[private operator delivery](../docs/research/private-operator-delivery.md).

Package construction and source contracts validate layout; they do not activate a host or prove service health, signed release delivery, independent capture, target-network performance or beta readiness. Keep identity keys, invitations and provider credentials outside these templates and public outputs. Do not overwrite administrator configuration when adding documentation or regenerating a package.

## Documentation responsibility

This README owns this module’s purpose and entrypoints. Shared procedures live
in the [focused guide](../docs/operator-guides/README.md); cross-component boundaries are in
[component ownership](../docs/architecture/OWNERSHIP.md). Link to those documents
when changing a shared contract; do not duplicate their instructions here.
