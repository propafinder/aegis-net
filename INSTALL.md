# Installing and running AEGIS

Use an **approved exact package and profile** for the host you intend to test.
AEGIS remains a controlled beta. Source builds, unsigned engineering kits and
historical published packages have different trust and acceptance scopes.
For source exploration use [local development](docs/development/local-development.md).

## Choose the role and platform

| Role / platform | Procedure | Boundary |
|---|---|---|
| Linux relay | Verified server facade or approved operator archive | Requires reachable listener, private TLS material and explicit target policy |
| Linux client | Authenticated launcher / offline client kit | SOCKS and privileged full-wide profiles are separate choices |
| Windows x64 client | [System tunnel guide](docs/platforms/windows/windows-system-tunnel.md), [controller](tools/windows/aegis-winctl/README.md) | Wintun/WFP/SCM source exists; production Authenticode signing is not provisioned |
| macOS client | Experimental SOCKS test kit or [VM lab](docs/operations/macos-utun-vm.md) | Use an exact explicitly approved test package; this is not an accepted product release or signed accepted NetworkExtension |
| Android | [JNI source](aegis-android-jni/README.md) | Proof surface; not a supported installation flow |

The public binary repository is `propafinder/aegis-release`. Private source and
operator packages belong in their authorized private channels. The presence of
an asset in a release does not establish trust in a new profile or current
installed-host acceptance. Do not choose `latest` implicitly for a controlled test.

## Carrier and ingress choice

| Goal | Mode | Boundary |
|---|---|---|
| Cloudflare HTTP fronting | `grpc_stream` | Forced HTTPS/H2 carrier; not RFC 8441 WebSocket or CDN MASQUE |
| Application-only proxy | SOCKS | Applications must select the configured local proxy |
| Full-wide capture | Selected native profile | Platform-specific privilege, lifecycle and capture acceptance |

## Before installation

Obtain these through an authenticated operator channel:

1. Exact version/source and package manifest, signature and independently trusted
   verification pins appropriate to the platform.
2. The host's private access bundle/profile and enrollment scope. Invitation
   tokens, device keys and local proxy passwords are distinct from OS login passwords.
3. The selected ingress profile, expected egress and bounded lifecycle/recovery
   plan. Stop an existing ingress only as instructed by that plan.

Validate the signed package and archive checksums before executing its installer.
A checksum downloaded from the same untrusted endpoint is not an independent
trust root. A Windows unsigned kit's hash verification is not Authenticode.
See [signing and freshness](docs/operations/release-signing-and-freshness.md).

## Linux client

The authenticated launcher contract is documented in
[verified installation](docs/operations/verified-installation.md). The operator
renders a Linux launcher from an independently trusted pin profile:

```sh
aegis-server install-launcher --pins /trusted/client-launcher-pins.json > install-client.sh
```

This command renders a launcher; it does not enroll or install a device. Deliver
it over the authenticated channel. Use its exact package pins and the separately
supplied private URL record. The record must be an absolute, owner-controlled
regular file with mode `0600`; inline `--bundle-url` is refused. See
[private installer inputs](docs/operations/private-installer-inputs.md).

For an already authenticated current bootstrap, an exact public client release
can be selected explicitly. The selected signed manifest must include a valid
`aegis_release_policy_v1` policy: matching release identity/authority and sequence,
issue time and unexpired validity of at most 30 days. The current bootstrap
requires this policy by default; a historical RC18 manifest is not automatically
eligible merely because its signature is valid.

```sh
sudo bash /trusted/bootstrap-install.sh client \
  --source https://github.com/propafinder/aegis-release/releases/download/EXACT_TAG/client-release.manifest.json \
  --bundle-url-file /root/aegis-access/client-access-url.txt \
  --profile auto
```

Obtain the bootstrap digest and exact source/policy pins independently before
trusting `/trusted/bootstrap-install.sh`. Replace `EXACT_TAG` from the approved
receipt; a release URL alone does not authenticate the first script. Root must
own the private URL record and its trusted private parent directories. Remote
bundle acquisition requires HTTPS; an explicit insecure acquisition also requires
an independently authenticated SPKI pin and a downloader that can enforce it.

For an offline client software kit, follow
[offline delivery](docs/operations/public-client-delivery.md#offline-delivery).
Individual certificate enrollment has its separate
[offline device procedure](docs/operations/offline-device-installation.md).
The selected installer owns configuration and state locations; check the
resulting install receipt instead of assuming a historical path. Root Linux
receipts use `/var/lib/aegis-install/client/install-manifest.json`.

Choose the profile before activation:

- [Linux profiles](docs/operator-guides/ubuntu-install-profiles.md): available
  profiles and dependency requirements.
- [Full-wide TUN](docs/operator-guides/full-wide-tun.md): privileged capture,
  fail-closed routing and scoped DNS/UDP limits.
- Historical operator modes (archived: `docs/archive/design-baselines/linux-operator-modes.md`):
  earlier design vocabulary; use the selected current profile and installed helpers
  for activation and rollback.
- [Reboot persistence](docs/operator-guides/wide-mode-reboot-persistence.md):
  service lifecycle and recovery, separate from a foreground connectivity check.

Do not enable a wide profile to fix an application's proxy settings. SOCKS routes
only traffic from applications configured to use it.

## Linux relay

The server facade itself must already be trusted. Supply an independently
obtained bootstrap digest and an exact release base, as required by
[the facade contract](docs/operations/verified-installation.md):

```sh
sudo bash /trusted/install-server.sh \
  --release-base 'https://operator-downloads.example.org/EXACT_TAG' \
  --bootstrap-sha256 INDEPENDENT_BOOTSTRAP_SHA256
```

`EXACT_TAG`, the private operator release base and the digest come from the approved
receipt. That base must serve the signed operator `release.manifest.json`, the
matching bootstrap and server archive; the public client-only repository cannot
satisfy this server procedure. Installation can provision a service and private credentials; use the
operator's selected options. Validate the actual private configuration before
starting a manually prepared relay:

```sh
aegis-server --config /absolute/private/server.toml config-check
```

For device authority roles and enrollment use
[device enrollment](docs/operations/device-enrollment-v1.md) and
[online enrollment](docs/operations/device-online-enrollment.md). Keep authority,
relay and client credentials separate. Owned HTTPS uses its own
[bridge procedure](docs/operations/https-bridge.md); Cloudflare is optional and
has [specific carrier constraints](docs/cloudflare-fronted-operator-guide.md).

## Windows and macOS

Windows's complete source tunnel path is documented separately from the older
[SOCKS developer kit](docs/platforms/windows/windows-install-runbook.md). Match the kit's source,
feature set, manifest pin and driver trust to the chosen profile. Do not disable
platform verification to present an unsigned engineering kit as production.

On macOS, the OS login/Keychain authorization prompt and local proxy authentication
serve different purposes. A repeated browser proxy prompt must be diagnosed
against the generated proxy credentials and Keychain custody, not by repeatedly
entering the OS password. See the [macOS worker runtime](docs/operations/macos-worker-runtime.md),
[parent capture](docs/operations/macos-parent-capture.md) and VM procedure.
A lab system tunnel does not inherit signed NetworkExtension acceptance.

## Verify, then test the lifecycle

Check installed `--version` build metadata and the installation receipt, validate
the actual profile, and confirm ingress readiness. For a SOCKS profile, set the
application's proxy to the configured loopback listener and use its actual
private credentials through the documented credential interface. Then compare
application egress and the authenticated relay outcome.

A changed IP does not prove all native services are captured. Test TCP, DNS,
UDP, IPv6, failure, restart, revocation and recovery only within the selected
profile's approved scope. The [candidate acceptance procedure](docs/operations/device-candidate-acceptance.md)
and [full-wide acceptance](docs/operations/device-fullwide-acceptance.md) keep
producer, observer, exact package and capture interval distinct.

## Stop, upgrade and recover

Use the installed profile's service/controller and owned rollback procedure.
Preserve credentials and state for an upgrade; reinstall/purge can intentionally
remove them and must use their explicit operator mode. Do not recursively remove
project `target/`: it can hold VM disks and source worktrees.

For diagnostics retain private bounded logs and the failed attempt under a new
artifact name. Never publish bundle URLs, keys or raw private diagnostics.
[Private diagnostics](docs/operations/private-diagnostics.md) explains custody.
The archived earlier guide (archived: `docs/archive/installation-guide-before-directory-audit.md`)
retains old examples but is not current onboarding.
