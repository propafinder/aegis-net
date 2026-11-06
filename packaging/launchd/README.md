# macOS launchd templates

`dev.aegis.client.plist` is the user LaunchAgent template. `dev.aegis.client.daemon.plist` is the explicitly selected system-domain LaunchDaemon template with `UserName` and `GroupName` placeholders for a dedicated client account. Both share the service label and include executable, configuration, state and log-path placeholders.

The macOS installer renders the selected model; raw templates are not ready for `launchctl bootstrap`. Choose one intended service model for the installation, resolve every placeholder and verify directory ownership before loading it. The daemon's system launchd domain does not imply the client should run as root; its dedicated-user settings remain part of the contract.

See [build-macos-client-tarball.sh](../../scripts/build-macos-client-tarball.sh), [install.sh](../../install.sh) and macOS wide operations (archived: `docs/archive/design-baselines/08-macos-wide-runbook.md`). The templates describe process persistence, not NetworkExtension entitlement, system-wide capture, notarization or tested reboot recovery. Source service-model contracts cannot substitute for observations from the selected installed macOS contour.

The generated installer supports the macOS system Bash 3.2 when its optional
bundled-CA purge arguments are empty. The
[browser credential privacy contract](../../scripts/test-macos-browser-proxy-privacy-contract.sh)
and [bundled MASQUE CA contract](../../scripts/test-macos-bundled-masque-ca-contract.sh)
invoke generated installer children through `/bin/bash`, so an ambient Homebrew
Bash does not hide compatibility failures. The original child deadlines,
credential checks and CA admission rules are preserved. Local controlled passes
use the real packaged Rust client with mocked OS callbacks; they do not accept
native Keychain, service activation, CA trust or network behavior. Exact
successor-commit CI remains required.
