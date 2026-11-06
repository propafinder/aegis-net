# Fresh installation and reboot review

operator.rs handles retained operator context around installed clients; reboot.rs consumes explicit checkpoints and evidence for the reboot contract.

### Contracts and limits

Installation owns a fresh private version directory rather than overwriting/adopting an arbitrary existing tree. Reboot review does not itself reboot or infer unobserved early-boot behavior. Keep client/control inputs and credentials private.

### Entry points and maintenance

The caller is ../install.rs. Preserve ownership/readback/refusal ordering and separate preparation, activation, recovery and observed reboot evidence.

### Local map

- [operator.rs](operator.rs)
- [reboot.rs](reboot.rs)

See the [parent guide](../README.md) for the enclosing component and runtime scope.

## Installed identity and ancestry

LocalSystem tunnel installations and elevated installations without a service
use the machine-private file policy for binaries, configuration, imported
credentials, state and renewal bundles. SOCKS services retain their LocalService
read/write distinctions; ordinary non-elevated per-user installs use User policy.
Service and Machine installations require existing trusted administrator-owned
ancestry, rechecked immediately before preflight, registration and start.

`install.json` records the selected `access_policy`. Verification and upgrades
use that recorded policy; later elevation cannot promote a User installation.
Elevated execution of a User receipt is refused. Legacy service receipts retain
their profile-derived policy, but existing tunnel files with shared LocalService
grants are rejected. Stage a fresh version under trusted ancestry; the installer
does not adopt or change permissions on an existing tree.

Native tests use fresh protected fixture directories and retain separate
user-owned-parent refusal cases. Extracted source-policy tests do not substitute
for actual Windows compilation, ACL behavior or installed lifecycle acceptance.
