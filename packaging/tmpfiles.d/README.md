# Enrollment-policy transfer inbox template

`aegis-enrollment-policy.conf` is an inactive administrator-reviewed template. It defines a root-owned transfer directory with mode 0700 and a root-owned `snapshot.json` with mode 0600 under `/var/lib/aegis-device-policy-transfer`. Its file directive does not truncate existing content.

The stage service manager opens the precreated transfer file; the Rust writer validates and updates it under its own lock, and the publication service consumes the staged policy. Do not replace this boundary with a world-readable file or a shell redirection that truncates before validation. Account/service provisioning and authorization remain separate prerequisites.

Read [systemd policy roles](../systemd/README.md) and [device-policy operations](../../docs/operations/device-policy-ssh-pull.md) before applying the template. This directory is separate from the general [client/server tmpfiles](../tmpfiles/README.md). Template presence does not establish a current snapshot, valid lease, successful publication or live runtime adoption.
