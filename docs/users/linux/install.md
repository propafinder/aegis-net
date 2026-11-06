# Install, update and remove the Linux client

## Before you begin

Use an exact, approved client release and an independently trusted digest or
signing pin for its bootstrap. The operator supplies a private access bundle or
a root-owned `0600` file containing its one-use URL. The URL, device identity,
certificate and local proxy credential are different secrets. Keep them out of
shell history, tickets and shared logs. A checksum fetched from the same
untrusted server as the installer is not an independent trust pin.

The host needs the privileges and packages selected by its profile. The AUTO
planner checks systemd, TUN, IPv6 and capture prerequisites before changing an
existing installation. On cloud images, full-wide also checks early boot
networking and the running/default kernel; see [recovery](recovery.md).

## Cloud images with cloud-init (full-wide only)

An active cloud-init can bring networking up and run provider-supplied root
code early in every boot, before AEGIS can guard traffic. Full-wide
installation therefore refuses any host where cloud-init runs, with
`cloud_init_early_network_unverified`. Either use a reviewed local-root image
without cloud-init, or disable cloud-init with the procedure below. Other
modes do not need it.

The reviewed scope is exact: Ubuntu 24.04 with its stock 9-file cloud-init
unit profile (cloud-init 26.1 or 26.2) and Ubuntu 26.04 with its stock 10-file
cloud-init 26.2 profile. Every other cloud-init layout is refused, even with
the marker.

What you lose: provider metadata no longer updates SSH keys, users, hostname
or network; there is no disk growth on resize, no user-data or per-boot
scripts and no network hotplug; the provider's password or key reset stops
working, and provider boot scripts (for example Lima's) stop. Keep the
provider's own network configuration; AEGIS does not replace it.

Before you start you need independent console access to the host (a provider
or hypervisor console that does not depend on the host's network), because a
mistake can leave the host unreachable. Then run, in this order:

```sh
sudo timeout 900 cloud-init status --wait
```

The command must print `status: done` and exit **0 or 2** before you continue.
Exit 2 reports recoverable diagnostics (for example deprecated provider
configuration keys); retain and inspect those warnings. See the
[cloud-init status contract](https://docs.cloud-init.io/en/latest/reference/cli.html#status).
Stop if there is no completed `done` status, if the status is `running`,
`error` or `degraded` without `done`, or if the exit code is anything except
0 or 2, including a timeout.

For the reviewed Ubuntu 24.04 **arm64 classic** profile, prepare its exact
signed distro packages now, before creating the marker. Retain these update
receipts and the ordinary image backup. Stop on any package-manager failure;
the boot-policy command checks this package base and never upgrades it itself:

```sh
sudo timeout 120 apt-get update
sudo timeout 180 apt-get install --no-install-recommends --yes coreutils=9.4-3ubuntu6.3 libssl3t64=3.0.13-0ubuntu3.16 openssl=3.0.13-0ubuntu3.16
sudo timeout 300 update-initramfs -u -k all
dpkg-query -W -f='${Package}:${Architecture}=${Version}\n' coreutils libssl3t64 openssl
```

The final query must report exactly those three arm64 package versions. The
ordinary vendor images must regenerate successfully before the marker reboot.

Then run:

```sh
sudo test ! -e /etc/cloud/cloud-init.disabled
sudo test ! -L /etc/cloud/cloud-init.disabled
sudo install -o root -g root -m 0644 /dev/null /etc/cloud/cloud-init.disabled
sudo systemctl reboot
```

The two `test` commands must succeed: the marker must not exist yet and must not
be a link. `install` creates it as a regular root-owned file even where a link
was planted (`touch` would follow a link). Do not edit, mask or add drop-ins to
cloud-init units, do not use the `cloud-init=disabled` kernel option and do
not create the marker through cloud-config. Only one normal reboot makes the
marker effective: cloud-init must not have run in the boot that installs
AEGIS.

After the reboot, from the console or a new SSH session:

```sh
cloud-init status --long
sudo bash /trusted/aegis-release/install.sh initrd-policy prepare-cloud --opt-in
sudo bash /trusted/aegis-release/install.sh initrd-policy detect
```

`cloud-init status --long` must show `status: disabled` and
`boot_status_code: disabled-by-marker-file`. On the reviewed Ubuntu image,
`prepare-cloud` detaches only the stock dependency from `cloud-final.service`
to `snapd.seeded.service`: systemd can queue a dependency even when its parent's
marker condition skips its start. The command requires an inactive client and
guard, preserves a root-private restoration journal, reloads PID1 and checks the
entire disabled profile. A failure restores the original link. An unknown link,
override or unit is refused; do not remove it by hand. If the reviewed host has
no such dependency, the command checks the strict profile and returns
`not_needed` without writing a journal or changing the host. The detector must print
`"class": "local_provable"`; a typed refusal names what is missing (see
[recovery](recovery.md)). Continue with the networkless boot policy below
before installing full-wide.

## Networkless boot policy after cloud preparation

This proves the current root profile. Before installing
full-wide, explicitly build the recurring networkless boot barrier from the
same trusted administrative bundle:

On the reviewed Noble Cloud Image, first disable its external overlay configuration disk:

```sh
sudo bash /trusted/aegis-release/install.sh initrd-policy prepare-classic --opt-in
```

This accepts only the exact qualified Cloud Image override, retains its original
bytes and a private recovery journal, and replaces it with literal disabled
settings. Other local overlay settings refuse. Active AUTO or an unfinished
boot-policy inverse also refuses. Keep the backup. After a complete boot-policy
rollback or uninstall, the separate `initrd-policy restore-classic --opt-in`
command restores the original configuration; it verifies ordinary images and
refuses while any owned networkless image or hook remains.

```sh
# Reviewed Ubuntu 24.04 arm64, initramfs-tools-core 0.142ubuntu25.8:
sudo bash /trusted/aegis-release/install.sh initrd-policy apply --backend classic --opt-in
# On the separately reviewed Ubuntu 26.04 dracut110 profile, use instead:
# sudo bash /trusted/aegis-release/install.sh initrd-policy apply --backend dracut --opt-in
sudo systemctl reboot
```

The qualified classic factory uses the GNU ELF payloads from signed Ubuntu
`coreutils 9.4-3ubuntu6.3`, `libssl3t64 3.0.13-0ubuntu3.16` and
`initramfs-tools-core 0.142ubuntu25.8`. Prepare those reviewed distro packages
before the marker procedure, so its normal reboot uses the corresponding
ordinary vendor image. The boot-policy command does not upgrade packages. An
older or changed payload refuses; do not add a digest from a failed guest to
make it pass. Keep the update receipts and the ordinary image backup.

Choose exactly the backend for the reviewed host. Unknown framework revisions,
architectures, factory files or local boot configurations refuse. Keep console
access and all private backups. `apply` preserves the ordinary images and does
not authorize the current boot. After this second normal reboot, verify:

```sh
sudo bash /trusted/aegis-release/install.sh initrd-policy verify --boot
```

The verifier must prove the exact source-owned image, fresh build nonce and
changed boot. `cloud_init_switch_root_unverified` means that a disabled marker
alone cannot admit installation; finish this boot-policy procedure. Then install
as below. Keep the marker and owned boot policy while full-wide is installed.
The classic implementation is undergoing installed boot qualification; its
filesystem-component results do not approve a release or an unattended rollout.

The networkless initrd checks the marker, complete pinned cloud-init profile and
dependency graph on the mounted root at every switch-root. A removed marker,
new dependency, mask, drop-in or changed vendor unit refuses the transition;
independent console access remains essential. The full client purge restores
the detached stock dependency after AUTO teardown. If preparation was performed
without installing the client, use the same trusted bundle's
`initrd-policy restore-cloud --opt-in`. Keep its private journal. To re-enable
cloud-init, uninstall AEGIS first, confirm restoration, then remove the marker
from the console and reboot.

## First installation

The operator may supply a verified bootstrap and exact release manifest. Use
the approved tag and private URL record from the release receipt:

```sh
sudo bash /trusted/bootstrap-install.sh client \
  --source https://github.com/propafinder/aegis-release/releases/download/EXACT_TAG/client-release.manifest.json \
  --bundle-url-file /root/aegis-access/client-access-url.txt \
  --profile auto
```

`EXACT_TAG` is a placeholder, not a channel selector. For a verified offline
administrative bundle already extracted to a private directory, first install
its exact matching client DEB. `EXACT_CLIENT_DEB.deb` below is the one file named
and hashed by that bundle's signed or independently verified manifest; use its
actual version and host architecture. This step installs inactive package files.
The subsequent AUTO command authenticates that pristine package before touching
device enrollment or capture. Running only the administrative script on a host
without its matching package is not the packaged AUTO entry point.

```sh
sudo dpkg --install /trusted/aegis-release/packages/EXACT_CLIENT_DEB.deb
sudo bash /trusted/aegis-release/install.sh client --upgrade \
  --bundle /root/aegis-access/client-bundle --profile auto
```

Here `--upgrade` admits the just-installed, never-active package as a fresh AUTO
installation. A changed package, existing configuration or interrupted owner
requires its authenticated recovery path; do not delete those records to retry.

The `--bundle` path names a directory, not a tar archive. Do not use
`--reinstall` for a first attempt. After installation, check the process and
receipt before sending private traffic:

```sh
sudo systemctl --no-pager status aegis-client.service
sudo test -f /var/lib/aegis-install/client/install-manifest.json
sudo aegis-client --version
```

Compare the receipt's release identity and selected mode with the operator's
approved manifest. A ready service alone does not prove all TCP, UDP, DNS and
IPv6 legs are carried; use the selected profile's acceptance check.

## Update and version rollback

Use the successor's exact verified bundle with `--upgrade`; this preserves
the existing installation state and credentials while the installer checks
the selected mode and protected transition:

```sh
sudo bash /trusted/next-release/install.sh client --upgrade \
  --bundle /root/aegis-access/next-client-bundle --profile auto
```

Keep the prior verified bundle and its receipt until the new version has
passed the operator's post-install and reboot checks. If an update refuses,
preserve its failure receipt and inspect the running service and guard before
retrying. An older bundle may be refused by the protected release floor or an
enrolled full-wide policy. Do not bypass those checks or replace binaries by
hand. Request an operator-approved rollback package/transition tied to the
installed identity; a blind `--reinstall` can destroy configuration and still
leave protected identity and release-floor state.

## Interrupted installation and removal

An interrupted AUTO installation may leave a guarded passive phase for
authenticated recovery. Check current service and receipt state before
repeating the same command. Use the same exact bundle and the operator's
recovery plan; do not delete a guard, state directory or systemd unit to make
the installer proceed. A never-active first preparation has a dedicated
`--abort-fresh-passive` path, but its preconditions are strict and it is not a
generic rollback switch.

The supplied Ubuntu/Debian uninstaller can inspect scoped residue without
changing it, then purge the client role:

```sh
sudo bash /trusted/scripts/aegis-ubuntu-uninstall.sh verify
sudo bash /trusted/scripts/aegis-ubuntu-uninstall.sh purge
sudo bash /trusted/scripts/aegis-ubuntu-uninstall.sh verify
```

Use the uninstaller from the exact installed/release bundle. Purge may remove
client packages, units, configuration and runtime state; back up data you
intend to retain first. It preserves device identity and release-floor state,
so successful verification means *client installation residue removed*, not
full erasure. A co-located server role is outside this client purge.


## Cloud-init package changes after installation

Full-wide admission binds the reviewed cloud-init unit and generator versions.
If a package update changes those files, the next boot assessment refuses with
exit78 and the protected client stays stopped. Read the closed boot reason:

```sh
sudo journalctl -b -t aegis-initrd-policy --no-pager -o cat
```

`cloud_init_disabled_profile_unproved` means the current boot or vendor files
no longer match the reviewed disabled profile. `cloud_init_early_network_unverified`
means cloud-init may have started networking. Use independent console access and
the [recovery procedure](#interrupted-installation-and-removal). A maintainer must
review the new vendor files, update Aegis's source pins and test the disabled
profile through a normal reboot before that vendor version can be admitted.
Keep the current deny while selecting a supported Aegis/vendor combination or
performing the protected rollback/removal procedure. Package holding and local
hash acceptance are never performed automatically. The journal record contains
only the fixed refusal code and recovery action.
