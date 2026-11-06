# AEGIS macOS NetworkExtension package

This standalone Rust package (it is not a member of the top-level Cargo
workspace) builds the macOS containing app (`aegis-ne-host`, a menu-bar app
with a command-line interface) and the Packet Tunnel system extension
(`aegis-ne-provider`). The runtime is Rust with objc2/block2 bindings to the
Apple frameworks; the Python scripts here are packaging and test tooling.

User and operator documentation for the installed client (approvals, host
commands, enrollment and invitations, logs, troubleshooting and known limits)
is in [docs/platforms/macos](../../../docs/platforms/macos/README.md).

## Requirements

- macOS 14.4 or later and an SDK that supports it
- Rust 1.97.1 (the repository pin)
- for signing and installation: an Apple Developer account with the Network
  Extension and App Groups capabilities, and Developer ID provisioning
  profiles for both bundle identifiers

## Building and testing

From this directory:

```sh
export MACOSX_DEPLOYMENT_TARGET=14.4
cargo check --locked --features apple --all-targets
cargo clippy --locked --features apple --all-targets -- -D warnings
cargo test --locked --features apple --lib
python3 -I -B tests/test_assemble_observe_staging.py
```

`assemble-unsigned.py` assembles an unsigned bundle for inspection.
`packaging/build-sign-notarize.sh` builds, assembles, signs, notarizes and
staples the product bundle, and `packaging/install-app.sh` /
`packaging/uninstall-app.sh` install and remove it; see
[packaging/README.md](packaging/README.md).

## Apple Team ID

The App Group, the provider's Mach service name, the code-signing
requirements checked over XPC and the entitlements all contain the Apple
Developer Team ID. In this source tree it is the placeholder `TEAMID0000`,
so the source builds and its tests run, but a signed build needs your own
Team ID. Replace the placeholder everywhere before building a signed bundle,
for example:

```sh
team=ABCDE12345   # your 10-character Team ID
git grep -l TEAMID0000 | xargs perl -pi -e "s/TEAMID0000/${team}/g"
cargo test --locked --features apple --lib   # from this directory
```

The bundle identifiers (`dev.aegis.macos`, `dev.aegis.macos.PacketTunnel`)
must also match App IDs registered to that team; change them consistently in
the same way if you use different identifiers. The notarization step expects
a `notarytool` keychain profile; its name is set in
`packaging/build-sign-notarize.sh`.

## Invitations

`../relay-ops/make-invite.py` is the operator-side script that mints a
one-time invitation on a relay over SSH and writes the `.aegis-invite` file a
Mac joins with (`aegis-ne-host --enroll`, or "Join with Invitation..." in the
menu). `src/invite_package.rs` defines the package format the host admits.
An invitation is a secret until it is redeemed: deliver it privately and never
commit or log it.

## Layout

| Path | Contents |
|---|---|
| `src/bin/host.rs`, `src/bin/host/` | containing app, menu and command-line interface |
| `src/bin/provider.rs` | Packet Tunnel provider entry point |
| `src/` | library: policy, queues, carriers, enrollment, renewal, XPC, diagnostics |
| `packaging/` | build, sign, notarize, install and uninstall scripts; entitlements |
| `diagnostics/` | diagnostic observe helper and XPC custody checks |
| `legal/` | license resources placed into the app bundle |
| `tests/` | packaging and assembly tests |
