# Relay service account template

`aegis-server.conf` declares the `aegis` system user with `/var/lib/aegis-server` as its home/state location. The installed server unit and directory templates rely on a consistent selected account. This file defines an account record, not credentials or enrollment identity.

Package construction and installation decide where to install and apply the sysusers template. Applying it uses host account-management privileges and should be part of the chosen role's installation, not a standalone experiment on a shared machine. The enrollment authority uses separate account/state provisioning; do not infer that this template creates every policy role.

Read the [server tmpfiles contract](../tmpfiles/README.md) and [systemd guide](../systemd/README.md) together. A parsed sysusers entry or generated package proves neither account ownership on a target host nor service startup, capability confinement or accepted relay traffic.
