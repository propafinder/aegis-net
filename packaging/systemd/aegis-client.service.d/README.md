# Optional client forensic mode

`forensic.conf` adds `AEGIS_FORENSIC_SAFE=1` to the installed client service. The source describes allowlisted runtime/tracing output and RAM-only client state in that mode. It is an application behavior setting, separate from OS journal retention.

Install the selected drop-in only through an administrator-reviewed procedure for the actual client service. Loading it requires a systemd reload and a client restart; that restart can affect live connections and must respect the installed profile's recovery procedure. Copying the file or reading an environment variable is not verification of all resulting I/O.

The optional [journald template](../../journald/README.md) affects the whole host and does not erase existing logs. No template here guarantees removal of metadata from external applications, captures, the kernel or backups. See the [systemd guide](../README.md) and [runtime privacy contract](../../../scripts/test-runtime-privacy-redaction-contract.sh) for source checks, keeping native observations distinct.
