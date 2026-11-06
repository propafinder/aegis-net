# Existing inner-TLS deployment recovery profile

These files are the source of truth for the recovery changes first exercised on
the September 2026 private fleet. They are operator deployment files, not public
client distribution files. Install selected files below `/etc/systemd/system/`
with the same relative paths, root ownership and mode0644, then daemon-reload.
Review the resulting configuration before activating anything. Copying these
files does not authorize public routing or installation on every machine.

| Role | Files |
| --- | --- |
| Every isolated relay | `aegis-device-policy-sync.timer.d/onboarding.conf`, `aegis-server-v3.service.d/recovery.conf` |
| Enrollment authority | `aegis-enrollment-policy-stage.timer.d/onboarding.conf` |
| CDN ingress with recovery | `aegis-v3-online.target`, both `ingress-recovery.conf` drop-ins |

The ingress profile requires systemd with `Upholds` support and the existing
frontend, dispatch and inner-relay services. It does not replace their certificate,
listener, binary or firewall configuration. `BindsTo` withdraws dispatch when a
dependency disappears; the active target re-establishes it after recovery.
An explicit stop or rollback **must stop `aegis-v3-online.target` as well as
`aegis-v3-dispatch.service` and `aegis-front-v3.service`**. Do not enable the target
until the retained public cutover has been accepted.

Empty monotonic timer assignments reset every monotonic trigger. These overrides
restore both initial activation and repeat-after-completion. Never reduce them to
an empty assignment followed only by `OnUnitActiveSec`.

Run `scripts/test-ingress-recovery-native.sh` as root on an authorized disposable
Linux host. It uses these actual drop-ins with isolated dummy services, exercises
both process crashes and explicit stop, and removes its temporary units. It does
not touch the real relay, routing or firewall. Source contract checks run in CI.

Deployment drift is recorded separately from source test success. As of the first
import, ingress recovery is deployed only on origin; the two other public relays
must not be reported as having it merely because these files exist in Git.

Compare selected deployed roles with `python3 scripts/audit-inner-tls-profile.py
--role relay` (add `--role authority` or `--role ingress` only where deployed).
The read-only JSON report contains hashes, not unit contents or credentials. A
missing or modified file returns failure. This checks configuration bytes, not
service health, loaded systemd state, enablement or public traffic acceptance.

The existing CDN legacy-proxy repair also has a source counterpart:
`aegis-origin-guard.service.d/aegis-local-proxy.conf` reloads
`packaging/nftables/profiles/inner-tls/legacy-loopback.nft`, installed as
`/etc/aegis-v3/legacy-loopback.nft` (root:root0644). This rule is restricted to
IPv4 loopback, source127.0.0.1 and legacy TCP443. The existing origin guard must
create its table/input chain first. The drop-in restores the rule after that
service recreates its table. Do not repeatedly apply the insert file manually:
it is intended for a freshly recreated guard table. This repair is deployed on
origin/r77/relay-c; extra is not a public legacy-proxy node. The role auditor above
checks recovery profiles only; compare both legacy-proxy files separately.

## Directory guide

The [relay retry drop-in](aegis-server-v3.service.d/README.md), [replica sync timer](aegis-device-policy-sync.timer.d/README.md), [authority stage timer](aegis-enrollment-policy-stage.timer.d/README.md), [frontend membership](aegis-front-v3.service.d/README.md), [dispatch dependencies](aegis-v3-dispatch.service.d/README.md) and [local legacy proxy restoration](aegis-origin-guard.service.d/README.md) describe their individual prerequisites. These directory guides do not change the historical deployment observations above or claim a fresh fleet readback.
