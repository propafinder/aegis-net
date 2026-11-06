# Private systemd deployment profiles

This directory groups drop-ins for existing private service topologies. [inner-tls](inner-tls/README.md) is the recovery profile for the separated authority, relay and ingress roles. It assumes those units and their configuration already exist; it does not create certificates, listener addresses or admission policy.

Select files by host role rather than copying the tree wholesale. A relay retry setting, an authority timer and an ingress target have different dependencies. In particular, an active ingress target can restart its upheld services, so explicit rollback must address that target as described by the profile.

The source contract and disposable native recovery tests cover specific configurations. They do not prove that another host has loaded the same bytes or passed traffic/reboot acceptance. Follow the [systemd guide](../README.md), retain per-host deployment evidence, and keep production credentials and provider setup outside this tree.
