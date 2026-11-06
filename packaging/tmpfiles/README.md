# Client and relay directory templates

`aegis-client.conf` creates client state/config directories without overriding their existing mode, owner or group; the installer owns those V2 permissions. The client log directory remains root-owned with mode 0755. `aegis-server.conf` defines relay state as `aegis:aegis` mode 0750 and server configuration as `root:aegis` mode 0750. These directory permissions do not specify the permissions of every file later placed inside them.

The package builder and installer render/select runtime locations and provision matching service accounts. Apply tmpfiles only as part of that reviewed installation. Private keys, tokens and client identity files still require their dedicated owner-only file controls; a public directory template is not a safe place to embed credentials.

The separate [tmpfiles.d transfer template](../tmpfiles.d/README.md) belongs to enrollment-policy staging and has stricter root-owned inbox semantics. See [sysusers](../sysusers/README.md) and [systemd](../systemd/README.md) for dependent roles. Layout tests are distinct from native installed ownership and lifecycle observations.
