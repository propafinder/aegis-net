# Restore the local legacy-proxy exception

`aegis-local-proxy.conf` adds an `ExecStartPost` call to `/usr/sbin/nft -f /etc/aegis-v3/legacy-loopback.nft`. It restores the narrow local exception after the existing origin guard recreates its table. The rule file and nft executable must exist at the reviewed paths.

The [rule source](../../../../nftables/profiles/inner-tls/README.md) allows only IPv4 loopback source `127.0.0.1` to legacy TCP port 443. This is not a public ingress allowlist or a replacement for the guard. Do not manually repeat an insert intended for a freshly recreated table.

The [parent runbook](../README.md) records selected historical deployment roles and distinguishes this pair from the recovery-only role auditor. A file hash match does not demonstrate loaded rule order or successful local proxy traffic. Applying or restarting the guard is an authorized host-network change, with independent recovery access required.
