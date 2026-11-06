# Optional service environment examples

`aegis-client.env.example` and `aegis-server.env.example` supply a minimal `RUST_LOG=info` example. They accompany the rendered systemd units' optional environment files; they are not complete client/server configuration or a credential store.

The installer pins executable and configuration paths in the unit itself. Review the role and destination selected by [install.sh](../../install.sh) or the [package-root builder](../../scripts/build-package-root.sh) before creating `/etc/default` files. Do not replace administrator-owned files blindly, inject shell fragments or place access tokens in these public examples.

Environment changes affect a service only after the applicable systemd reload/restart procedure; editing a template is not a live-health observation. See the [systemd guide](../systemd/README.md), and use the appropriate installer contract for template/layout changes. Native service privileges, traffic capture and forensic behavior require their own runtime checks.
