# Rust Windows control plane

aegis-winctl validates packages and implements Windows client installation, service/tunnel lifecycle, controlled WFP operations and artifact/proof reports.

### Contracts and limits

Package parsing can run separately from Windows-native actions; install/service/tunnel modules are Windows-gated. A valid development kit is not a production signature, and proof/artifact reports do not independently establish reboot or whole-host coverage.

### Project license payload

New package builds copy the exact root [LICENSE-MIT](../../../LICENSE-MIT),
[LICENSE-APACHE](../../../LICENSE-APACHE) and [NOTICE](../../../NOTICE) bytes into
the kit and pin each file in `manifest.json`. The optional `project_licenses`
field is a Boolean: missing or `false` retains the exact legacy inventory;
`true` requires all three project texts in the closed inventory. A partial set,
an unmanifested extra, a missing file or bytes differing from their manifest
hashes are rejected. Manifest pins and publisher signatures retain their
existing independently provisioned trust requirements.

Schemas 1–5, Wintun and its separate license, research-tool admission and
Authenticode rules retain their existing policy. For a licensed package, the
installer copies the three bounded project texts into a private `licenses/`
directory beside `bin/`. A separately authenticated manifest determines the
closed install inventory; an absent or false flag preserves older packages.
The receipt keeps license hashes separate from executable hashes. Installation,
execution verification and uninstall check the relevant ACLs; status reports
license hash matches only. Uninstall removes only the owned, unchanged license
files, preserving configuration and state. These files do not complete
third-party or vendored notices, runtime dependency inventory, SBOM acceptance
or production signing.

The eight portable package tests and three installed-inventory tests passed
locally, with strict portable lint and format checks. They cover package
builder/readback, missing/tampered texts, legacy inventory compatibility and
closed receipt names/digests. The Windows-gated installer body was not compiled
or executed on the local macOS host. PowerShell 5.1 and 7 finalizer fixtures
passed in parent `1e39981e` CI using mock native/signature inputs; that result
does not establish Authenticode or installed-client acceptance. The successor's
Windows compilation, native lifecycle and exact required CI remain separate
gates.

### Entry points and maintenance

src/main.rs defines commands; src/package owns trusted kit validation;
src/install_payload.rs plans the closed portable install inventory;
src/install.rs owns Windows-native private installation. service.rs and
tunnel.rs implement native controls. Use command help/parser definitions to
distinguish status/planning from mutating actions.

Use a built executable to inspect the command surface or build identity:

```text
aegis-winctl --help
```

### Local map

- [Cargo.toml](Cargo.toml)
- [src/](src/README.md)

### Workspace build

From the repository root, with the locked dependencies and the required target toolchain available:

```bash
cargo build --locked -p aegis-winctl
```

Use a supported Windows target for native client/service/tunnel operations; a host build on another platform does not exercise those gated modules.

### Explicit Authenticode policy at installation

A signed Windows kit requires an independently provisioned v2 Authenticode policy.
Supply its path with `client install --authenticode-policy POLICY` or
`client upgrade --authenticode-policy POLICY`, in addition to the existing manifest
pin or publisher signature. The package never supplies this trust anchor implicitly.
Unsigned development kits retain their existing independent-manifest admission.
Missing production certificate, timestamp and provider inputs remain separate
release blockers; these arguments do not create or substitute signing credentials.

The native verifier stages the unchanged static verification script as a create-new
private file under a validated temporary directory and invokes PowerShell with
`-File` and separate literal arguments. Script and reviewed adapter entry leases
remain held across the child wait. Script custody is verified before lease release;
the private static script is deliberately retained, including failed or partial
writes. There is no unlink by pathname after the file and ancestry leases end.
The script contains no dynamic package, policy or credential values. This leaves
one small private file per invocation; it does not claim cleanup or a native
handle-based deletion implementation. This does not seal imported verifier code or
prove signer/provider acceptance. The existing synchronous child invocation needs
an external operation bound; filesystem and native process calls have no new hard
kernel deadline.
