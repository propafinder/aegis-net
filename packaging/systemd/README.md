# Linux runtime and policy units

This directory contains service/timer templates and explicit operator drop-ins. The client/server base units contain `__AEGIS_*__` placeholders rendered by installation. Device-policy and enrollment units use fixed operator paths and require their own account, identity and state provisioning; do not enable every unit as a bundle.

| Units | Purpose and prerequisites |
| --- | --- |
| `aegis-client.service`, `aegis-server.service` | Installed runtime processes; the client may need selected network capabilities, while the server uses its dedicated account and low-port capability. |
| `aegis-origin-guard.service` | Optional pinned local nftables source-range guard, ordered before a co-started relay without forcing the guard onto direct relays. |
| `aegis-device-policy-sync.*`, `aegis-device-policy-health.*` | Pull a pinned private authority snapshot and require actual runtime adoption through the configured local status interface. Replica sync does not renew authority validity. |
| `aegis-device-policy-refresh.*` | Explicit authoritative policy refresh; it is a different role from replica synchronization. |
| `aegis-enrollment-authority.service`, `aegis-enrollment-policy-stage.*`, `aegis-enrollment-policy-publish.service` | Separated enrollment ownership, private transfer inbox and authoritative publication. |
| `aegis-calibration-refresh.*` | Optional summary refresh from separately collected evidence; shipped disabled and not a permission to perturb production networking. |
| `25-relay-geneva-profile.conf` | Explicit privileged relay/Geneva profile with owned recovery state; not a base-unit default. |

[Client forensic configuration](aegis-client.service.d/README.md), [private recovery profiles](profiles/README.md), [disabled presets](../systemd-preset/README.md) and [state templates](../tmpfiles/README.md) are separate pieces. Read [device-policy SSH pull](../../docs/operations/device-policy-ssh-pull.md) and [enrollment operations](../../docs/operations/device-online-enrollment.md) before provisioning those roles.

Render and inspect the chosen unit/drop-ins before `daemon-reload` or activation. Those operations require Linux/systemd and suitable host authority; native recovery/timer contracts use explicitly disposable resources. Source validation does not establish loaded state, policy freshness, service health, reboot recovery or traffic acceptance. Private registry and key material never belongs in public package templates.
