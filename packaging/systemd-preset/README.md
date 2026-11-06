# Disabled-by-default service presets

`90-aegis.preset` disables both client and server services. `90-aegis-client.preset` and `90-aegis-server.preset` preserve that policy for split packages. The files describe package defaults; they do not remove configuration or automatically choose which role belongs on a host.

The package builders install the appropriate preset alongside rendered service templates. Operators prepare the chosen role's private configuration and dependencies before explicitly enabling it. Do not replace these files with a blanket enable rule merely to make a fresh package appear active.

See [Debian role instructions](../debian/README.md), [systemd templates](../systemd/README.md) and [build-package-root.sh](../../scripts/build-package-root.sh). Preset/layout contracts are source-level checks. Existing administrator enablement, actual loaded service state, successful reboot and network behavior require distinct host observations; a disabled package default is not a runtime-health verdict.
