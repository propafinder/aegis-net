# Diagnose and recover a Linux client

Begin with read-only checks. Save the exact failed command's exit code, release
identity, time and bounded receipt under a new attempt name. Check the current
service and network state before another install, reboot or purge:

```sh
sudo systemctl --no-pager status aegis-client.service aegis-auto-guardian.service
sudo journalctl -b -u aegis-client.service -u aegis-auto-guardian.service --no-pager
sudo test -f /var/lib/aegis-install/client/install-manifest.json
```

Logs and receipts can contain private endpoint or identity details. Keep the
raw files in the operator's protected channel; share only a sanitized refusal
code and exact release identity in a public report.

| What you see | What it means and what to do |
| --- | --- |
| `reboot_required_kernel_changed` (exit 75) | The default boot kernel changed while another kernel is running. Stop the install, schedule a normal reboot through the operator's host procedure, and recheck the running/default kernel and guard before retrying. If it persists, the boot image or initrd needs operator assessment. |
| `cloud_init_early_network_unverified` (exit 78) | cloud-init is active, or its configuration enables ephemeral DHCP, so networking can start before the protected guard. The installer refuses full-wide. The `detail` names only the datasource class or the configuration file. Use a reviewed local-root image without cloud-init, or follow the cloud-init marker procedure in [install](install.md) exactly (independent console access, one normal reboot), then retry. |
| `cloud_init_disabled_profile_unproved` (exit 78) | A cloud-init disable marker exists, but this boot does not prove the reviewed disabled profile: for example the marker is a link, on another filesystem or created after this boot started, or a cloud-init unit is edited, masked, has a drop-in, ran in this boot or is not the stock layout. Do not edit units or the marker to pass the check. Restore the stock units, recreate the marker with the documented `install` command if it is wrong, reboot normally and retry. |
| `foreign_policy_drift` | A firewall, route, unit or boot-policy readback no longer matches the sealed owner. Traffic stays closed. Preserve the receipt and ask the operator to inspect the exact changed object and use the authenticated recovery transaction. Do not clear the marker, flush nft/UFW or restart repeatedly. |
| Capture readiness or relay TLS refusal | Check the approved relay identity, current CA, reachability and package/bundle generation. A stale CA or unreachable relay is a failed installation, not permission to bypass the guard. |
| Passive/rotation refusal after an interrupted update | Preserve old and new receipts. The predecessor guardian may be intentionally holding denial. Use the operator's protected abort, resume or purge-and-fresh plan; never manually replace a guardian or its unit. |

After a successful reboot, inspect the installed manifest, guard and service
again. Verify actual application TCP and DNS and the UDP/IPv6 legs declared by
the selected profile. If the service is running but traffic is denied, treat
that as an unresolved guarded failure until the operator confirms the reason.
For remote hosts, keep independent management access and a timed rollback
before any authorized live repair.
