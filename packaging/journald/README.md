# Optional volatile journal policy

`forensic.conf` sets `Storage=volatile` and `RuntimeMaxUse=32M` for systemd-journald. It is an explicit host-wide operational choice: when installed under `/etc/systemd/journald.conf.d/`, it affects journal storage for all services, not just Aegis.

Review incident-retention needs and the complete effective journald configuration before applying this template. Reloading or restarting journald changes future storage behavior; this file does not erase existing persistent journals, other applications' logs, remote collectors, swap, captures or backups. It therefore is not proof that a disk contains no historical metadata.

The separate [client forensic drop-in](../systemd/aegis-client.service.d/README.md) controls Aegis application behavior. Both files are optional templates and do not run themselves. Validate intended settings on an authorized test host and distinguish configuration inspection from actual logging/storage observations. Return to the [packaging guide](../README.md) for deployment ownership.
