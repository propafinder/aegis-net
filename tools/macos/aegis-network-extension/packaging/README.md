# Two-role product packaging (B-06 S09)

`build-sign-notarize.sh` builds, assembles, signs, verifies, zips, notarizes,
staples and assesses the product bundle: the host app `dev.aegis.macos` and
its PacketTunnel system extension `dev.aegis.macos.PacketTunnel`. The
diagnostic ObserveHelper/ObserveChild are never part of this bundle; the
diagnostic `assemble-unsigned.py --helper-binary/--child-binary` path is
unchanged.

Stages are selected with `--stages` and always run in this order:

| Stage | Action |
| --- | --- |
| `build` | `nice -n 10 rustup run 1.97.1 cargo build --locked --release -j 4 --features apple --target-dir <package>/target` (with `CARGO_TARGET_DIR` unset) for the host and provider binaries only; only together with `assemble`; output goes to `logs/build.log` and both binaries must be newer than the build start |
| `assemble` | `assemble-unsigned.py --product` under umask 022 plus `chmod -R u=rwX,go=rX`; the version, profile, signer and entitlement checks and the version reservation run before `build`, so a failed build still leaves a receipt; embeds both Developer ID profiles after `security cms -D` field checks; refuses if HEAD or the dirty state changed during the build. The next candidate additionally hashes the committed `NOTICE`, both project licenses and full `THIRD-PARTY-NOTICES` before opening output, then places their exact bytes in `AEGIS.app/Contents/Resources/Legal` and records hashes in `assembly.json`. This is a reviewed Cargo graph superset, not a complete native/system SBOM. |
| `sign` | `codesign --force --options runtime --timestamp` with `entitlements/provider.entitlements` on the system extension, then `entitlements/host.entitlements` on the app, using only the certificate pinned at assembly (`profile_signer_sha1`); refuses when HEAD, the entitlement files, the pipeline scripts or a clean tree changed since assembly |
| `verify` | `codesign --verify --strict` (and `--deep --strict` for the app), Developer ID Application (TEAMID0000) authority/chain, runtime flag and timestamp; the extracted leaf certificate of each role must be the pinned one and listed in that role's embedded profile; signed entitlements must equal the committed file and every profile-gated claim must be explicitly authorized by the embedded profile; every bundle directory is 0755 and every file 0644/0755 |
| `zip` | rechecks the signed binaries and both `CodeResources` against the hashes recorded at verify, then `ditto -c -k --sequesterRsrc --keepParent`; checks the stored modes; prints the ZIP SHA-256 |
| `notarize` | `xcrun notarytool submit --keychain-profile aegis-notary --wait`; refuses without `--approve-zip-sha256` equal to the ZIP, when binaries were not produced by the `build` stage of the same run, when the tree was dirty at assembly or is dirty now, when the version rule used a test ledger/installed-app override, or when the run is already notarized; each attempt keeps `logs/notary-submit-<n>.json`, `logs/notary-log-<n>.json` and an entry in `notary_submissions` |
| `staple` | `xcrun stapler staple` + `validate`, then a stapled ZIP |
| `assess` | requires a current `staple`; `spctl -a -vv -t exec`; requires `source=Notarized Developer ID` |

A stage runs only when its predecessor's latest real result is `ok` and no
earlier stage ran again after it (`--stage-status` reports `stale`), so a
re-sign needs a new verify and zip. Dry-run entries never satisfy or block a
gate. `--stages` is one comma list without spaces; unknown, empty or
duplicate entries are refused.

The CFBundleVersion must be greater than the historical `1`, every receipt in
the artifacts directory (failed ones included), every entry of the version
ledger `~/Library/Application Support/aegis-packaging/version-ledger` (shared
by all worktrees and checkouts, written at reservation, stand-in runs
included) and the installed `/Applications/AEGIS.app`. The
`AEGIS_PACKAGING_LEDGER`/`AEGIS_INSTALLED_APP` overrides exist for tests;
such runs cannot be notarized.

`--dry-run` prints the exact commands. The profile paths come from
`--host-profile/--provider-profile` (or `AEGIS_HOST_PROFILE`,
`AEGIS_PROVIDER_PROFILE`) and must be outside this checkout and untracked.
The signer defaults to the unique `Developer ID Application: ... (TEAMID0000)`
identity (`--identity SHA1` overrides). `--host-binary/--provider-binary` accept
prebuilt stand-ins for packaging tests; such runs are recorded as
`binaries_source: stand-in` and cannot be notarized.

Receipts (`receipts/<run-id>.json`: commit, dirty flag, version, input/signed
binary, entitlement, profile, Info.plist, ZIP SHA-256 values, signer,
submission id and per-stage status) and run directories (`runs/<run-id>/`)
go to `packaging/artifacts/` (gitignored) or `--artifacts-dir`. Receipts,
logs and run directories are owner-only; only the bundle and its ZIPs use
distributable modes. A retry of assembly is a new run with a new version;
failed receipts stay, and an existing ZIP is kept as `*.superseded-<utc>`
(or refused once Apple received the run).

Sign, notarize and staple contact Apple and refuse while a capture window is
open (`AEGIS_CAPTURE_WINDOW` set, `<artifacts>/capture-window.active` present,
or a running `tcpdump`/`dumpcap`/`tshark`).

Entitlements: both roles carry the Team-prefixed application identifier,
Team identifier, `packet-tunnel-provider-systemextension` and the App Group
`group.TEAMID0000.dev.aegis.macos`; the host adds
`com.apple.developer.system-extension.install`. The provider is sandboxed
with `network.client` (relay) and `network.server` (the per-flow
`127.0.0.1` bridge listener in `aegis-client/src/packet_engine/engine.rs`,
`stream_pair`). These three sandbox keys are not profile-gated, so the
profile check covers every other claim.

`install-app.sh --stapled-zip ZIP --approve-sha256 HEX` extracts the
approved stapled ZIP, rechecks the modes, signature, stapled ticket and
Gatekeeper, refuses an existing install unless `--replace` and the new
CFBundleVersion is greater, copies into `/Applications` and reruns
`spctl -a -vv`. The previous app is kept in
`~/Library/Application Support/aegis-packaging/install/backups/` (`--state-dir`),
not in `$TMPDIR`, and is restored automatically when the post-install
assessment fails. `--receipt` must be the receipt of this exact stapled ZIP
(`stapled_zip_sha256`, `bundle_version`, current `staple` and `assess`).
The version order for `--replace` is `pipeline.py compare-version` (the same
strict grammar as the build ledger). Activation is a separate `--activate` host
request that the user approves in System Settings. Since B-06 S11 the host
stops its run loop on the finish/failure callback and gives up after 120 s
(the script's 150 s watchdog only catches a broken bound); the script maps the
host's exit code with `pipeline.py activation-outcome` and records
`activation_outcome`, `activation_exit_code`, the host's `activation_result=`
line and the log: 0 completed (stage `ok`), 10 completes after reboot (stage
`pending-reboot`), 11 failed, 12 cancelled, 13 replacement declined, 14 timeout
while approval was pending, 75 timeout, 2 usage, 142 watchdog; every other
code is `host-unknown-exit`. A host-reported code counts only when the host's
last `activation_result=` line names that outcome and `exit_code`; otherwise
(for example an exec failure, which the watchdog wrapper turns into exit 127
instead of perl's errno) it is `host-unknown-exit`. The install also records
the host and provider CDHashes of the verified extracted app and refuses (and
restores the previous app) when the installed copy differs.

Apple withdraws a request still awaiting approval when the host exits. After
approving, or after the reboot for exit 10, run
`install-app.sh --activate-installed --receipt R` (same `--dest`/`--state-dir`):
it re-checks that the installed app is the one this receipt installed (current
`install` stage, `installed_path`, `installed_zip_sha256`, `bundle_version`,
both CDHashes, strict signature, stapled ticket and Gatekeeper team), then runs
the same bounded activation and appends a new `activate` stage to the receipt
of this exact stapled ZIP.

`--replace --activate` is allowed: the host's replacement delegate returns
Replace only when the incoming CFBundleVersion is numerically newer than the
active extension's, otherwise Cancel (exit 13). The `--replace` backup restores
only the app; moving it back does not change the active system extension, and
the host never activates an equal or older provider over a newer one. This
tooling has no extension rollback: the script prints and records this as
`rollback_note`, and warns when a non-completed (or not yet requested)
activation leaves the new host beside the previously active provider. Undoing
an extension replacement needs a deliberate deactivation of the newer
extension first (Apple documents that deleting the app in Finder uninstalls its
system extensions; not exercised before S12), then a fresh install and
activation of the older build. `--activation-timeout` was removed. The script
never calls `systemextensionsctl` or `sudo`.

v26 review: a host above `FILTER_MIN_PRIOR=24` and below
`WEAKEN_PROMPT_MIN=26` (v25) has `--disable-filter` and `--remove-filter`
without the administrator prompt. Any process of the console user could run
a kept signed copy to weaken the leak guard. The script refuses to install
such a ZIP. After a verified install (never before: the replaced app is the
rollback of a failed one) it runs `pipeline.py disarm-weak-host` on every
`<state>/backups/AEGIS.app.replaced-*` and
`<state>/uninstalled/AEGIS.app.uninstalled-*` copy. A v25 copy loses
`Contents/MacOS/aegis-ne-host`, and its SHA-256 goes to
`aegis-ne-host.removed` beside it. Every other copy is unchanged, and an
unreadable one is reported. The receipt lists the disarmed copies in
`weak_hosts_disarmed`.

v30 review: the bound is now `LEAK_GUARD_PASSWORD_MIN=30`, the first host
whose filter verbs ask for the password-only right
`dev.aegis.macos.leak-guard-change`. v26 to v29 ask for
`dev.aegis.macos.leak-guard-weaken`, whose prompt offers Touch ID (one
resting touch approved two v29 prompts), and their filter verbs need no
provider, so a kept copy could still remove the installed build's leak
guard with one touch. The script refuses to install v26 to v29 (its own
message, apart from v25's), and every kept v25 to v29 copy loses its host
executable; the removal note names why (`predate the v26 administrator
prompt` or `ask for an administrator at a prompt that offers Touch ID`).

`tests/test_assemble_observe_staging.py` runs this script for real (not
`--dry-run`) against fake `ditto`/`codesign`/`xcrun`/`spctl` and a fake host
that exits with each code; that proves only the script's handling of host
results, never an Apple activation.

## Uninstall (B-06 S21, source only; not yet run installed)

`uninstall-app.sh [--dest DIR] [--state-dir DIR] [--artifacts-dir DIR] [--identity-unverified] [--dry-run]`
stops and removes the installed app in a fixed order; each step is bounded by
an outer watchdog over the host's own bound, and any refusal stops the run
before the next step:

| Stage | Action and gate |
| --- | --- |
| `verify` | `AEGIS.app` is a directory (not a link) with the product identifiers, the PacketTunnel extension and equal versions; `codesign --verify --deep --strict`; `spctl` reports `Notarized Developer ID` of TEAMID0000; both CDHashes recorded. Then a parse-only probe `--deactivate capability-probe` must exit 2 with `provider_id_mismatch` and a usage text naming `--deactivate [PROVIDER_ID]`: a host without the verb (every build installed before S21 answers `unknown_command`) is refused here, before the irreversible forget. No other host verb runs otherwise |
| `identity-gate` | v30: host `--identity-gate` (read-only, no prompt, 20 s watchdog) before anything with an effect: exit 0 with `identity_gate=open ...` passes (recorded as `identity_gate`); 69 (provider unavailable) passes, and the forget step decides; a closed gate (65) or any other answer stops the run with "nothing was stopped, removed or forgotten" and advice by code (`provider_refused unknown_verb`: the active provider predates v30, activate the build first). A host that answers `unknown_command` is older than v30: below v26 its forget has no administrator gate (`skipped`, `predates-audit`); from v26 to v29 its forget can never be approved while its provider answers (`--ping` exit 69 skips, anything else stops: install v30 first). v30 review: `proof_probe_denied` names the sandbox; `proof_probe_failed` or `_unavailable` (an Authorization Services error, which the provider no longer keeps) says to run the script again |
| `emergency-stop` | host `--emergency-stop`; exit 0 and `emergency_stop_requested=N disconnected=unknown` |
| `remove-profile` | host `--remove-profile`; exit 0 and `removal_failed=0 profiles_remaining=0` |
| `remove-filter` | S20b: a parse-only probe `--remove-filter capability-probe` (exit 2 `filter_operand_refused`; an older host's `unknown_command` records `filter_removal=unsupported_by_host` and skips both filter stages), then host `--remove-filter` (180 s watchdog: from v26 the host first shows the system administrator prompt, at most 120 s, then its 30 s operation); exit 0 and `filter_result=ok exit_code=0 filter_found=[01] filter_remaining=0`. 67 (no administrator approval) stops the run: nothing is forgotten or deactivated |
| `verify-filter-absent` | host `--filter-status`; exit 30 and `filter_result=not_configured exit_code=30 configured=false` |
| `forget-identity` | host `--forget-identity` (150 s watchdog: the host first shows the system administrator prompt, at most 120 s, and the owner types an administrator password (v30: password only); every attempt prompts again); exit 0 and a reply (`pipeline.py forget-reply`, exact shape) with `key_material_removed=true`. Only `provider_refused session_live` is retried (5 attempts, 2 s apart); 74, 67 (no administrator approval: cancelled, denied or unanswered; nothing was sent) or any other refusal stops. 69 (provider unavailable: the extension was never activated, is already inactive or is unreachable) stops with the two ways out unless a marker of this app applies (below) or `--identity-unverified` was given. Failure details quote the first host stderr line after its `administrator approval required ...` banner, so the refusal or XPC code is named |
| `verify-identity-absent` | host `--ping` (`pipeline.py ping-identity`): `identity_present=false` below an admitted container (`container_open.admitted=true`); a present identity or an unadmitted/absent container refuses, so nothing is deactivated. A pass writes `<state>/uninstall/identity-absent.txt` before deactivation is requested |
| `deactivate` | host `--deactivate dev.aegis.macos.PacketTunnel` (bounded 120 s, 150 s watchdog), mapped by `pipeline.py deactivation-outcome` only with the host's matching `deactivation_result=` line: 0 completed (`ok`), 20 after reboot (`pending-reboot`; the app stays, reboot and run again), 21 failed, 22 cancelled, 23 not found (never read as deactivated while the provider answered; accepted as `already-inactive` only when the provider is unavailable and identity absence was verified earlier or waived by `--identity-unverified`), 24 approval pending, 25 timeout, 2 usage, 142 watchdog, else `host-unknown-exit` |
| `move-app` | `mv` of `AEGIS.app` to `<state>/uninstalled/AEGIS.app.uninstalled-<version>-<utc>[.N]` (Trash-equivalent; never deleted, path recorded as `uninstalled_app_path`). v26: `pipeline.py disarm-weak-host` then removes the host executable of a v25 copy (v30 review: of a v25 to v29 copy; `uninstalled_host_disarm`, as for `install-app.sh` above) |
| `report-container` | the user-side App Group container `~/Library/Group Containers/group.TEAMID0000.dev.aegis.macos` (from earlier host publication) is reported with its presence and left in place for the owner |

Exit 67 (v26 review): the failure message is chosen by the refusal code.
Only `*_authorization_cancelled`, `*_denied` and `*_timeout` (a prompt was
shown) say to run the script again and approve it.
`*_authorization_right_inadmissible` names
`sudo security authorizationdb remove <right>`. `*_right_unregistered` and
`*_unavailable` name `security authorizationdb read <right>`. Each of these
three says that running the script again will not help, since no prompt was
shown.

`--state-dir` defaults to the install state directory
(`~/Library/Application Support/aegis-packaging/install`). Each run writes one
receipt `<artifacts>/uninstall/receipts/<run-id>.json` (stage list,
`uninstall_result`, host result lines and parsed replies; never key material)
and keeps every host stdout/stderr in `<artifacts>/uninstall/runs/<run-id>/`;
`<artifacts>` defaults to `$AEGIS_PACKAGING_ARTIFACTS` or the gitignored
`packaging/artifacts`. Receipts, logs and the uninstalled directory are
owner-only; one run at a time holds `<state>/uninstall/.lock`.

Idempotence: with no `AEGIS.app` the run executes no host verb, records every
step `skipped` and `uninstall_result=already-absent`, names the latest
uninstalled copy (`pipeline.py latest-uninstalled`: newest by the UTC stamp
and retry suffix of the name, not by a text sort where version 10 precedes 9)
and reports the container.

Resume markers in `<state>/uninstall/`, each bound to both CDHashes and to
the digest of the host's identity import journal
(`~/Library/Application Support/dev.aegis.macos/identity-import-journal`,
appended by every host `--import` before it sends; read before this run's
forget, `none` while absent, never matching when it is a link, not a regular
file or another user's), owned by the user, never a link, and honoured only
while the provider is unavailable (a probe `--ping` exits 69); a reachable
provider, a marker of another app or one written before a later import
retires them (`*-stale-<utc>.txt`) and every step runs again:

- `identity-absent.txt` (after `verify-identity-absent` passed): forget and
  verification are recorded `done-earlier` and `--deactivate` is requested
  again; `completed`, after-reboot or `not-found` (Apple already finished it,
  for example after the approval that exit 24 asks for, a 25 timeout or a
  142 watchdog) let the run continue. `identity_absence=verified-earlier`.
- `deactivated.txt` (after a completed or after-reboot deactivation of a
  verified forget): forget, verification and deactivation are `done-earlier`.

A successful move consumes both (`deactivated-consumed-<utc>.txt`,
`identity-absent-consumed-<utc>.txt`).

With the provider unavailable and no marker of this app (never activated,
for example `install-app.sh` without `--activate` or with approval pending,
or deactivated outside the script), the run stops at `forget-identity`
without requesting deactivation and names the two ways out: activate the
extension and run again, or run again with `--identity-unverified`. That flag
acts only on forget exit 69: forget and verification are recorded
`unverified`, deactivation is requested (`not-found` accepted as
`already-inactive`), the app is moved and the receipt records
`identity_absence=unverified`; no marker is written, so a rerun needs the
flag again. A reachable provider still runs the forget and its verification,
and any other forget refusal still stops.

`--dry-run` reads only the Info.plists and prints every command; it executes
no tool or host verb and creates no file or directory. The script never
calls `systemextensionsctl` or `sudo`.

`tests/test_assemble_observe_staging.py` (`UninstallBehaviorTests`) runs the
script for real against fake `codesign`/`spctl` and a fake host answering each
verb; that proves only the script's order, gates and records, never an Apple
deactivation or a provider forget.
