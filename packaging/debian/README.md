# Debian role documentation

`README.Debian` describes the combined package, while `README.client.Debian` and `README.server.Debian` describe the split client/server packages. The common contract is explicit role selection: installation does not automatically enable either service. Configuration and identity material must be prepared for the intended host before the operator enables the selected unit.

[scripts/build-deb-package.sh](../../scripts/build-deb-package.sh) and [scripts/build-split-deb-packages.sh](../../scripts/build-split-deb-packages.sh) consume the package layout and documentation. The [preset files](../systemd-preset/README.md) retain the disabled defaults, and [systemd templates](../systemd/README.md) describe the services to be rendered.

Build on the supported Linux/package-toolchain path, with the pinned compiler and required native dependencies. Package layout/maintainer-script contracts are separate from an actual install, reboot or uninstall on a disposable Debian-family host. Do not infer cross-distribution acceptance or publish private configuration from these text files. Preserve the existing role-specific instructions instead of replacing them with a generic one-command activation example.
