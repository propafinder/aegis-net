# AEGIS on Linux

These instructions are for an operator-supplied, exact AEGIS release. AEGIS is
still a controlled beta: a file named `latest`, an unsigned source checkout, or
an old package is not an approved release. Obtain the release identity, trusted
verification pins, private access bundle and chosen profile through the
operator's authenticated channel before installing.

1. [Install, update, remove](install.md) explains the approved-input and
   client lifecycle, and how to disable cloud-init on a cloud image before a
   full-wide installation.
2. [Choose a mode](modes.md) describes application SOCKS, IPv4 redirect and
   full-wide capture.
3. [Diagnose and recover](recovery.md) covers refused installations, kernel
   updates, reboot and a closed foreign-policy guard.

The installer receipt for a standard root client is
`/var/lib/aegis-install/client/install-manifest.json`. Keep it private. It
identifies the installed version and selected profile; a successful command
without a matching receipt is not an accepted installation.

For a relay/server installation, use the separately supplied server facade and
operator procedure. A public client bundle is not a server package.
