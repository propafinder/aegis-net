# macOS: install, enable and enroll

This page covers the AEGIS macOS client as it exists on the B-06 flow-pool
line (installed build v24): a containing app `dev.aegis.macos` with the
Packet Tunnel system extension `dev.aegis.macos.PacketTunnel`. The S20b
leak-guard packet filter, which runs in the same system extension, is in
source and needs build v25 or later; it has not been installed yet. B-06 is still
**NO-GO** for release; see [known limits](known-limits.md) before relying on
it. Day-to-day behaviour and logs are in [operate](operate.md), failures in
[troubleshooting](troubleshooting.md).

The command reference below is checked against `src/bin/host.rs` and
`src/host_lifecycle.rs` of the
[source package](../../../tools/macos/aegis-network-extension/README.md#explicit-future-host-commands).
Exit codes are listed in the [entrypoint notes](../../../tools/macos/aegis-network-extension/src/bin/README.md)
(the four filter verbs in its S20b entry); the filter verbs' codes are also
under [leak-guard packet filter](#leak-guard-packet-filter-s20b) below.

## What the owner has to approve

macOS requires a person at the Mac for four approvals (the content filter
only with S20b, build v25 or later; the administrator prompt only with the
security-audit fixes, build v26 or later). No script can give
them, and every AEGIS tool reports the wait instead of working around it.

| Approval | When it appears | Where |
| --- | --- | --- |
| System extension | First activation of the Packet Tunnel extension (`--request-activation`, or `install-app.sh --activate`). A replacement by a newer CFBundleVersion of an already enabled extension did not ask again on v8-v24. | macOS 15 and later: **System Settings → General → Login Items & Extensions → Network Extensions**, switch AEGIS on. macOS 14: **System Settings → Privacy & Security**, *Allow* for the blocked system software from AEGIS. |
| VPN configuration | First `--save-profile` that creates a profile ("AEGIS would like to Add VPN Configurations"). An in-place `--save-profile … --replace-existing` did not prompt. | The system dialog; macOS may ask for the login password or Touch ID. |
| Administrator prompt (security audit, source only, v26 or later) | Every `$H --import`, `$H --forget-identity` and `$H --renew` (they change the identity the provider uses), and every `$H --disable-filter` and `$H --remove-filter` (they weaken the leak guard), including those `uninstall-app.sh` and the uninstall/reinstall harness run. Every run prompts again; reading and enabling the filter never prompt. | The macOS authorization dialog "aegis-ne-host is trying to change the AEGIS VPN device identity" (or "... to turn off or remove the AEGIS leak guard"): an administrator's name and password, or Touch ID. The host waits at most 120 s; cancelled, denied or unanswered is exit 67 with nothing sent or changed. See [provider queries](#provider-queries-one-xpc-exchange-10-s-bound). |
| Content filter (S20b, source only, v25 or later) | First `$H --enable-filter` (or `install-app.sh --enable-filter`) that saves the leak-guard packet filter, which blocks pre-tunnel residue ([known limits](known-limits.md#pre-tunnel-connections-on-the-physical-interface)). Both installed r2 provisioning profiles already carry the content-filter entitlement; nothing changes in the developer portal. | The macOS alert "AEGIS would like to filter network content": click **Allow**. The host waits at most 120 s; a declined alert is exit 35 (`permission_denied`). See [leak-guard packet filter](#leak-guard-packet-filter-s20b). |

The activation request waits at most 120 s. If the approval is given later,
the request was withdrawn when the host exited (exit 14); approve, then run
the activation again (below).

## Install a notarized build

Builds come from `packaging/build-sign-notarize.sh` as a stapled ZIP with a
run receipt (see [packaging](../../../tools/macos/aegis-network-extension/packaging/README.md)).
Install as the logged-in user, never as root:

```sh
P=tools/macos/aegis-network-extension/packaging
$P/install-app.sh --stapled-zip /abs/path/AEGIS-stapled.zip \
    --approve-sha256 <stapled ZIP SHA-256> --receipt /abs/path/receipt.json \
    [--replace] [--activate] [--enable-filter]
```

The script re-checks the signature, stapled ticket and Gatekeeper
(`source=Notarized Developer ID`, Team TEAMID0000), copies the app to
`/Applications`, keeps the previous app under
`~/Library/Application Support/aegis-packaging/install/backups/` and, with
`--activate`, runs the host activation. `--replace` accepts only a strictly
newer CFBundleVersion; the backup restores the app only, never the active
extension.

From v26 (source only) the script refuses to install build v25: its host has
`--disable-filter` and `--remove-filter` without the administrator prompt.
After a verified install it removes the host executable from every kept
v25 copy under `backups/` and `uninstalled/`, and keeps its SHA-256 in
`Contents/MacOS/aegis-ne-host.removed` beside it. The receipt records the
copies in `weak_hosts_disarmed`. Such a copy cannot be moved back as a
rollback; the v25 build stays in its stapled ZIP. `uninstall-app.sh` does the
same for an uninstalled v25 copy (`uninstalled_host_disarm`).

v30 review (source only): the same now holds for v26 to v29. Their
`--disable-filter` and `--remove-filter` ask for
`dev.aegis.macos.leak-guard-weaken`, whose prompt offers Touch ID (one
resting touch approved two v29 prompts), and the host changes the filter
by itself, so the leak guard is only as strong as the weakest signed host
that can still run. The script refuses to install v26 to v29 and, after a
verified install of v30 or later, removes the host executable of every
kept v25 to v29 copy, for example the v26, v27, v28 and v29 backups that the
upgrades left (`pipeline.py disarm-weak-host`, `LEAK_GUARD_PASSWORD_MIN`
30). A copy that macOS App Management protects is reported and left
unchanged: move it to the Trash in Finder. A copy kept outside the state
directory is not seen.

`--enable-filter` (S20b, v25 or later; only with `--activate` or
`--activate-installed`) runs the host's bounded `--enable-filter` after a
completed activation and records the `enable-filter` stage; the owner
clicks **Allow** in the "filter network content" alert. When the activation
is still pending (reboot or approval), the follow-up command the script
prints keeps `--enable-filter`.

To repeat only the activation (after a late approval or a reboot):

```sh
$P/install-app.sh --activate-installed --receipt /abs/path/receipt.json [--enable-filter]
```

Check the result read-only with `systemextensionsctl list`: the provider
must appear once as `dev.aegis.macos.PacketTunnel (0.1.0/<version>)
[activated enabled]`. Older versions stay listed as `terminated waiting to
uninstall on reboot` until the next reboot; that is normal.

## Host commands

All commands run the host binary inside the installed app as the logged-in
user:

```sh
H=/Applications/AEGIS.app/Contents/MacOS/aegis-ne-host
P=dev.aegis.macos.PacketTunnel
```

The provider id is the only accepted `PROVIDER_ID`; any other is a usage
error (exit 2, `provider_id_mismatch`). `RELAY_IP` is a numeric IPv4 or IPv6
address without a port. `OWNER_GENERATION` is the UUID printed by
`--save-profile` and shown by `--list`.

### Extension lifecycle

| Command | What it does | Result |
| --- | --- | --- |
| `$H --request-activation $P` | Asks macOS to activate the extension; waits up to 120 s. | One `activation_result=` line. Exit 0 completed, 10 completes after reboot, 11 failed, 12 cancelled, 13 replacement declined (not newer), 14 approval still pending at 120 s, 75 timeout. |
| `$H --deactivate [$P]` | Asks macOS to deactivate the extension; waits up to 120 s. | One `deactivation_result=` line. Exit 0 completed, 20 after reboot, 21 failed, 22 cancelled, 23 not found, 24 approval pending, 25 timeout. |

Use `packaging/uninstall-app.sh` rather than a bare `--deactivate`: it stops
the tunnel, removes the profile, removes the S20b packet filter and verifies
it is absent, forgets and verifies the identity, then deactivates and moves
the app aside (nothing is deleted). A filter removal that fails, or a filter
still configured, stops the run before anything is forgotten; a host older
than v25 is recorded as `filter_removal=unsupported_by_host`. See
[uninstall](../../../tools/macos/aegis-network-extension/packaging/README.md#uninstall-b-06-s21-source-only-not-yet-run-installed).

### Leak-guard packet filter (S20b)

Source only, build v25 or later; not yet installed. An
`NEFilterPacketProvider` (`AegisFilterPacketProvider`) runs in the Packet
Tunnel system extension. While a tunnel session can have its settings
applied (Applying, Running, Reasserting) it drops every packet on a
physical interface except the provider's own relay TCP and the link
control a network needs (ARP, EAPOL, DHCP, IPv6 ND and MLD, ICMP errors
that quote a relay flow). v25 to v30 also allowed the enrollment
authority's TCP; from v31 the provider dials no other tuple while the
filter is armed and renews at Connect instead
([known limits](known-limits.md#certificate-renewal-while-connected-v31)). Tunnel (`utun<n>`,
`ipsec<n>`) and loopback interfaces are always allowed, so everything the
tunnel itself writes back to applications passes. With no tunnel session
the filter allows everything.

| Command | What it does | Bound |
| --- | --- | --- |
| `$H --enable-filter` | Saves the reviewed configuration (packets only, no sockets, packet provider `dev.aegis.macos.PacketTunnel`, description "AEGIS leak guard", enabled), reloads it and checks every field. The first save shows the **Allow** alert. | 120 s |
| `$H --filter-status` | Reads the configuration and, only when it is exact and enabled, the provider's `filter-status` (attached, pid match, mode, `armed_token`, counters). | 30 s |
| `$H --disable-filter` | Keeps the configuration with enabled=false. From v26 an administrator approves it first at the system prompt. | 30 s, after the prompt (at most 120 s) |
| `$H --remove-filter` | Removes the configuration and verifies none remains. From v26 an administrator approves it first at the system prompt. | 30 s, after the prompt (at most 120 s) |

Each verb takes no operand (any operand is `filter_operand_refused`, exit
2) and prints one result line `filter_result=NAME exit_code=N ...`; the
status line adds `attached= pid_match= mode= armed_token= dropped= allowed=`
(counts only, never an address). When the provider answers,
`--filter-status` prints a second line: the provider's JSON `filter-status`
reply (`attached`, `pid_match`, `mode`, `armed_token`, `relay_armed`,
`authority_armed` (always false from v31), `udp_relay_allowed` and every
per-reason `allow_*` (`allow_authority` always 0 from v31) and
`drop_*` counter, plus `torn_snapshot`, which is not a verdict; never an
address). `dropped=` and `allowed=` on the first
line are the sums of those `drop_*` and `allow_*` counters. Read the result
by its `filter_result=` prefix, as the AEGIS scripts do, not as the only
stdout line. Exit codes: 0 `ok`, 30 `not_configured`, 31
`disabled`, 32 `field_mismatch`, 33 `not_attached`, 34 `failed`, 35
`permission_denied` (the Allow was declined), 36 `timeout`, 37
`removal_incomplete`, 67 `authorization_refused` (v26: `--disable-filter`
or `--remove-filter` without an administrator's approval; the line is
`filter_result=authorization_refused exit_code=67 filter_changed=false`
and nothing was changed), 69 `provider_unavailable`, 2 usage.

v27 (S20f) observability (source only). A v27 provider's reply adds one
key, `observability`, and nothing else changes: a v26 provider's reply
without it still decodes, and a v26 host refuses a v27 reply as
`reply_malformed` (host and provider ship in one app, so this only shows
with mixed copies). It holds counts and bounded tokens only, never an
address, port or payload byte:

- `arm_seq` (arms of the leak guard in the provider process), `disarms`
  (disarms that opened it), `armed_ms_total` (milliseconds guarded, the
  current span included), `armed_for_ms` (age of the current arm, null
  while Open), `open_while_applied` (Open intervals that began while a
  tunnel epoch's settings may have been applied: a transient disarm) and
  `applied_epochs`. The milliseconds count awake time only.
- `primary_iface`: the epoch's pinned relay interface as a macOS driver
  name such as `en7` (any other name is a hash `h:` plus 8 hex digits),
  null before the first arm.
- `drops`: drops by the interface class the packet was presented on,
  `primary` (the pinned interface), `en_other`, `awdl_llw`,
  `bridge_ap_anpi` and `other`, each split into `in`, `out` and `any`.
- `ring`: the last 64 drops. `next` counts records written so far,
  `skipped` those whose slot was busy (a writer never waits), `torn` slots
  read inconsistently and left out. Each of `entries`, oldest first, has
  `index`, `arm_seq`, `ms` (milliseconds since that arm), `class`,
  `iface` (`en7`, `h:` hash or `none`), `dir` (`in`, `out`, `any`),
  `family` (`v4`, `v6`, `none`), `proto`, `tcp` (`syn`, `syn_ack`,
  `ack_only`, `data`, `fin`, `rst`, `other`, or `none` when not TCP) and
  `reason` (a `drop_*` counter name).

The first line then ends with a summary of it: `arm_seq= disarms=
open_while_applied= applied_epochs= armed_ms_total= armed_for_ms=
primary_if= in_drops= out_drops= any_drops= ring=next:,skipped:,torn:
recent=` (the last four ring records as `iface:dir:tcp:reason@ms`).

v29 (S20h) outbound observability (source only). A v29 provider's
`observability` adds one key, `outbound`, and nothing else changes: a v27
or v28 provider's reply without it still decodes. A v28 (or v27) host
refuses a v29 reply as `reply_malformed`, because its decoder accepts
exactly the keys it knows; host and provider ship in one app, so this only
shows with mixed copies. No key was renamed. Still counts and bounded
tokens only:

- `mark_sport_first` and `mark_sport_count`: the provider's marker, the
  TCP source ports `47000` to `47031` (`32` ports). An outbound TCP drop
  from a port of that range is counted as marked, whatever its TTL. The
  positive control's pre-existing sockets bind there
  (`harness/net_probe.py` `presock`), so the filter's drops of their
  segments and kernel keepalives can be told from every other socket's.
  (A TTL cannot mark them: XNU gives a keepalive the system's default
  TTL, never the socket's `IP_TTL`.) The marker is a constant of the
  provider, never a port of an observed flow. The two keys replace the
  first v29 draft's `mark_hop_limit`, which no build carried.
- `kinds`: the outbound drops by interface class (the classes of `drops`)
  and kind: `syn`, `syn_ack`, `ack_only` (a bare ACK, keepalives among
  them), `data`, `fin`, `rst`, `other` (an unreadable TCP header or a
  later fragment of a TCP packet) and `non_tcp`. Inbound and `any`
  drops are never in it.
- `marked`: the same table for the marked drops only.
- `ring`: the last 64 **outbound** drops, kept apart from the v27 ring,
  so an inbound flood never overwrites them (the v27 ring still records
  every drop). `next`, `skipped`, `torn` and `entries` as in the v27 ring;
  each entry has the v27 entry's keys (`index`, `arm_seq`, `ms`, `class`,
  `iface`, `dir`, always `out`, `family`, `proto`, `tcp`, `reason`) and
  `marked` (`true` when it carried the marker).

The first line then also ends with `out_kinds=` (the non-zero outbound
drops as `class:kind:n`), `out_marked=` (the same for the marked ones),
`mark=sport` (the marker is a range of TCP source ports; the line never
names them),
`out_ring=next:,skipped:,torn:` and `out_recent=` (the last four
outbound records as `iface:tcp:reason@ms`, `:m` when marked); `none` for
an empty table or ring.

The tunnel does not depend on the filter: with the filter disabled or
removed (also in System Settings) before a connect, the tunnel still
connects, without the guard. From v26 (source only) a filter that stops
while a tunnel session is guarded (Applying, Running, Reasserting) fails
that session closed. The cause can be `--disable-filter`, `--remove-filter`
from any host build, or System Settings. The tunnel then cancels instead of
running unguarded, with provider log `leak_guard filter_stopped_while_guarding`
and `session_failed leak_guard_filter_stopped`. The provider checks this, so
it also holds for a host without the administrator prompt. Disconnect before
disabling or removing the filter. What `--filter-status` exits with, per
filter state:

| Filter state | Exit |
| --- | --- |
| Removed or never saved | 30 `not_configured` |
| Saved but disabled | 31 `disabled` |
| Saved and enabled, filter not attached in the provider (or the provider refused) | 33 `not_attached` |
| Saved and enabled, provider unreachable (no XPC reply) | 69 `provider_unavailable` |
| Saved, enabled and attached | 0 `ok` |

The provider is asked only about an exact, enabled configuration, so a
disabled or removed filter never gives 33 or 69.
`harness/real-relay-window.sh` reads `--filter-status` before connecting
and after the disconnect; with `FILTER_REQUIRED=1` (the default when
`LEAK_CAPTURE=1`, in every mode including `SLEEP=1` and `IFSWITCH=1`) a
filter that is not configured, enabled and attached refuses the window
before anything connects.

### Provider queries (one XPC exchange, 10 s bound)

| Command | Output |
| --- | --- |
| `$H --ping` | One JSON line: `euid`, `sandboxed`, the App Group container and its admission (`container_open.admitted`), `loopback_listen`, `session_phase`, `identity_present`. |
| `$H --status` | `session_phase` (`none`, `constructing`, `ready`, `sealed`, `joined`) and `session_refusal`, the last refusal code. |
| `$H --profile-terms` | The held relay endpoint, DNS servers, MTU and public profile digest. |
| `$H --cert-status` | Certificate renewal state: `state`, `not_before`, `not_after`, `renew_at`, `attempts`, `last_attempt_at`, `next_attempt_at`, `last_failure` (see [operate](operate.md#certificate-renewal)). Refused `no_epoch` while no tunnel session exists. |
| `$H --renew` | Asks the running provider to renew a due certificate now: `renew_scheduled`, or refused `renewal_not_due`, `identity_expired`, `identity_unknown`, `no_epoch`. |
| `$H --forget-identity` | Removes the imported identity from the provider's container; `key_material_removed=true` on success. Refused `session_live` while a tunnel session runs. |
| `$H --identity-gate` | v30: whether an identity verb could be admitted now: the peer, the identity rule, Apple's proof rule and the provider's sandbox probe. Read-only, no prompt; exit 0 open, 65 closed. |

Exit codes: 0 answered, 65 provider refusal or malformed reply, 69 provider
unavailable or its signer refused, 74 a forget left key material, 75 no
reply within 10 s.

`--forget-identity`, `--import` and `--renew` are identity verbs: the
provider accepts them only from the console user who is an administrator
(v30: and not in Setup Assistant's group). From v26 (security audit) that is
not enough: any process of that user can run the signed host, so each
identity verb first shows the system administrator prompt (every run
prompts again, at most 120 s) and sends the provider a one-use approval that
it checks without interaction. On an installed v26 to v29 that check always
fails (the provider's sandbox forbids it: `provider_refused
identity_authorization_denied`, see [troubleshooting](troubleshooting.md)).
From v30 (source only, not yet installed) the prompt is password only (no
Touch ID) under the right `dev.aegis.macos.identity-change`, names the
change (forget, import with the folder's name, renew), and the provider
checks the approval for Apple's `system.services.systemconfiguration.network`
right, the one its sandbox allows; a v26 to v29 host is refused
`identity_authorization_host_outdated`. The host writes `administrator
approval required for this identity change; ...` on stderr first. Exit 67
means no administrator approved (cancelled, denied, unanswered, a rule
other than the host registers, or Authorization Services unavailable);
nothing was sent and an import source is kept. `--disable-filter` and
`--remove-filter` prompt the same way (banner `... for this leak-guard
change; ...`; v30: password only, right `dev.aegis.macos.leak-guard-change`).

`$H --identity-gate` (v30) asks the provider, read-only and with no prompt,
whether an identity verb could be admitted now. It prints the reply and one
line `identity_gate=open|closed peer= identity_rule= proof_rule=
proof_probe=` and exits 0 only when open (65 when closed, with
`identity_gate_closed <check>` on stderr; 69 provider unavailable).
`uninstall-app.sh` runs it before anything changes.

### Identity import

```sh
$H --import /Users/<you>/aegis-enroll [--remove-source]
```

The directory is the private tree from [enrollment](#enrollment-from-a-bundle-and-an-invitation).
The host checks it before sending anything: an absolute canonical path with
no symlink, mode `0700`, owned by you, containing exactly `bundle/` and
`identity/` (both with no group or other permission bits), only the expected
files plus the identity store's empty `.lock`, each a regular single-link
file. Required files:

- `bundle/`: `bundle.json`, `outer-ca.pem`, `inner-ca.pem`, `device-ca.pem`;
- `identity/`: `identity.json`, `device.key`, `device.csr`, `device.pem`,
  `device-ca.pem`, `bundle-profile.sha256`, `online-completed.json`;
- optional pair: `identity/https-bridge.toml` with `identity/bridge-credential`.

The provider commits the files into its own container and echoes a
manifest; the host compares it with what it sent. Output is one line, codes
and counts only, for example
`import_result=committed manifest_match=true committed_files=12 …`.

| Exit | Meaning | Source directory |
| --- | --- | --- |
| 0 | Committed (and removed, when asked) | removed only with `--remove-source` |
| 66 | Refused before sending (`import_source_*` code on stderr) | kept |
| 65 | Provider refused before its commit (for example `session_live`) | kept |
| 69 | The request cannot have reached the provider | kept |
| 73 | Committed, but the source was not completely removed | partly kept |
| 74 | Committed, but the provider kept the replaced tree | kept |
| 75 / 77 | No reply, or delivered with unknown commit state: `import_result=unknown` | kept |
| 76 | Manifest mismatch | kept |

Disconnect before importing; the provider refuses an import while a session
is live. After an expired certificate, disconnect first, enroll and import
the new identity, then connect again: a blocked tunnel leaves the Mac with no
network for the online enrollment ([operate](operate.md#certificate-renewal)).
Keep the source
(omit `--remove-source`) until the new identity has carried traffic: the
uninstall/reinstall cycle re-imports from it.

### VPN profile

Every profile verb is bounded by one 30 s deadline.

```sh
$H --save-profile $P RELAY_IP [--replace-existing]
$H --list
$H --connect    $P OWNER_GENERATION RELAY_IP
$H --disconnect $P OWNER_GENERATION RELAY_IP
$H --status     $P OWNER_GENERATION RELAY_IP
$H --emergency-stop
$H --remove-profile
```

- `--save-profile` first asks the provider for its profile terms; `RELAY_IP`
  must equal the held relay host (else `profile_relay_mismatch`, exit 2).
  DNS and MTU always come from the provider. The saved profile has
  `includeAllNetworks=true`, every exclusion off, on-demand off. stdout
  always names the owner generation:
  `owner_generation=<uuid> saved=true profile_sha256=… native_vpn_status=…`,
  or `saved=false` (nothing saved) or `saved=unknown` (the save may be
  durable; check `--list`). Without `--replace-existing` an existing AEGIS
  profile refuses the save (`existing_provider_profile_refused`). With it,
  the one existing profile must be idle (Disconnected or Invalid) and is
  rewritten in place with a fresh owner generation.
- `--list` prints one line per profile:
  `profile index=0 owner_generation=<uuid> scutil_service_id=<uuid> intent_valid=true enabled=true on_demand_enabled=false native_vpn_status=1`,
  then `profiles=N`. stderr adds a `profile_diag` line with the persisted
  flags. `native_vpn_status` is Apple's NEVPNStatus: 0 invalid,
  1 disconnected, 2 connecting, 3 connected, 4 reasserting,
  5 disconnecting. `intent_valid=false` means the saved profile does not
  match what the provider accepts; repair it with `--replace-existing`.
- `--connect` starts the tunnel of the profile whose owner generation and
  relay match exactly. A printed status is the status at that moment, not
  relay health.
- `--disconnect` and four-argument `--status` act on the saved profile
  alone and make no provider query, so they work while the provider is
  unreachable or has no identity.
- `--emergency-stop` requests a stop on every AEGIS profile regardless of
  generation and prints `emergency_stop_requested=N disconnected=unknown`.
  A requested stop is not an observed disconnect: check
  `scutil --nc status <service id>`.
- `--remove-profile` removes every AEGIS profile and exits 0 only when none
  remains.

`--repair-runtime` is a legacy verb for the old host `runtime.json`; the
provider no longer reads that file and normal operation does not need it.

## Enrollment from a bundle and an invitation

The relay owner provides the four public bundle files and a one-time
**Enroll** invitation through a private channel (a `0600` file). Enrollment
runs with a macOS build of `aegis-client` and must complete **online**: the
provider imports only an identity with `identity/online-completed.json`, the
receipt of an online issuance. A certificate issued offline and installed
with `device complete` is refused by design (`import_source_missing`), and
the deployed authority's online Redeem accepts only Enroll invitations, not
Rotate. The general procedure is in
[online device enrollment](../../operations/device-online-enrollment.md).

```sh
umask 077
mkdir -m 700 ~/aegis-enroll ~/aegis-enroll/bundle
cp bundle.json outer-ca.pem inner-ca.pem device-ca.pem ~/aegis-enroll/bundle/
chmod 700 ~/aegis-enroll/bundle

aegis-client device prepare --device-id <device-id> \
    --identity-dir ~/aegis-enroll/identity \
    --device-ca ~/aegis-enroll/bundle/device-ca.pem

aegis-client device bundle-inspect --bundle-dir ~/aegis-enroll/bundle \
    --identity-dir ~/aegis-enroll/identity --json

aegis-client device redeem --identity-dir ~/aegis-enroll/identity \
    --bundle-dir ~/aegis-enroll/bundle \
    --invitation-file /path/to/private/invitation
```

- `prepare` creates the device key and CSR in the identity directory (mode
  `0700`), or resumes the same ones.
- `bundle-inspect --identity-dir` pins the exact four-file profile digest
  (`bundle-profile.sha256`) before the request.
- `redeem` stores the request privately, contacts the enrollment authority
  and writes `device.pem` and `online-completed.json`. After an ambiguous
  failure, run the same `redeem` again without `--invitation-file` to resume
  the saved request; do not prepare a new identity. Do not import while a
  pending request (`online-request.json`) is still in the directory: the
  host refuses unexpected files (`import_source_unexpected_entry`).

Treat the whole directory as secret. The CLI does not delete the original
invitation file; remove it once the import has succeeded. Never print or
commit the invitation, key or certificate.

## First connection, in order

1. Install and activate; approve the system extension; check
   `systemextensionsctl list`. With v25 or later, also
   `$H --enable-filter` (click **Allow**) and check that
   `$H --filter-status` exits 0.
2. `$H --ping`: `container_open.admitted=true`, `identity_present=false`.
3. Enroll (above) and `$H --import ~/aegis-enroll`; `$H --ping` now shows
   `identity_present=true`.
4. `$H --profile-terms` to read the held relay; then
   `$H --save-profile $P <relay host>` and approve the VPN configuration
   within the 30 s budget. Note the printed `owner_generation`.
5. `$H --list`: exactly one profile with `intent_valid=true` and
   `on_demand_enabled=false`.
6. `$H --connect $P <owner_generation> <relay host>`; follow the
   provider log ([operate](operate.md#reading-the-provider-log)) until
   `start tunnel_running`.
7. `$H --disconnect $P <owner_generation> <relay host>`, and confirm with
   `scutil --nc status <scutil_service_id>` that it reads `Disconnected`.

Parent: [macOS documentation](README.md).
