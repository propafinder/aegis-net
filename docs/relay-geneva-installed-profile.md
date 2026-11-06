# Explicit installed relay Geneva profile

This operator-only profile selects the Rust relay-outer implementation. It
requires an already installed, stopped `aegis-client.service`, an armed v2 device
guard, authenticated inner TLS and gRPC outer transport, literal IPv4 relay
endpoints, and a configuration with explicit `relay.outer_geneva`. Every selected product-client dial requires the complete installed sidecar;
absence always refuses. The controlled standalone core example remains separate.
The default installer/profile behavior without selected outer Geneva is unchanged. IPv6 and QUIC outer transports are refused before packet activation.

## Managed full-wide device selection

`device bundle-render` accepts the paired `--relay-geneva-request` and
`--relay-geneva-request-sha256` options. The root-private host-local JSON has
schema `aegis_relay_geneva_managed_request_v1`, `profile_sha256` (the existing
named four-member public bundle digest), and `request` containing exactly the
existing `RelayOuterGenevaSettings` fields. The public bundle remains unchanged;
strategy text, interface, local address/MACs, queues, socket mark and bounded
duration are local settings. Unknown fields, wrong raw-byte hash or profile,
unsafe files, incompatible mode or endpoints are refused before writing a
profile pin or configuration. The selected path requires Linux `full-wide-tun`,
inner TLS, gRPC and the complete literal IPv4 relay pool. This transforms the
outer relay connection; it never substitutes a direct destination connection.

`--validate-only` performs the same read-only configuration validation before
enrollment without writing an identity pin or output. When the manifest pair is
supplied, this also checks its strict schema, compiled source, selected policy,
standard role paths, source helper hashes and online public-member pins. Future
executable/configuration/unit/guard hashes and the stopped service are attested
later against the actual installed files. No guard manifest is staged by this
read-only check. The ordinary render still needs a new private output and its
protected parent directory.

For a first standard device installation, pass all four installer options:
`--relay-geneva-request`, `--relay-geneva-request-sha256`,
`--relay-geneva-profile-manifest` and `--relay-geneva-profile-sha256`.
The separate installed-profile manifest described below must already pin the
prospective exact source, final injected configuration, unit/drop-ins, helpers,
public bundle when online, and assessed v2 guard. The installer does not invent
these operator grants or select a strategy automatically. It validates the
request and prospective manifest before any key/enrollment request, refuses a
legacy installation or interrupted recovery at that boundary, preserves both
supplied inputs in a private handoff directory, and passes the pinned request to
every configuration render. Failed handoff snapshots remain for explicit
recovery.

After final configuration and ordinary IPv6 drop-in are durable, the installer
supplies the selected helper's fixed parent-root prerequisites and invokes the
existing stopped-profile installer before the first client start. Existing
selected state, intent, helper, drop-in, teardown or native journal path refuses
before replacement of pinned assets. This is not automatic selected upgrade or
adoption; use explicit stopped recovery/teardown first. A failed selected stage
or service start retains the armed block and any refusing selected gate. The
default install without these options selects no Geneva implementation.

After verifying the exact signed operator archive, source CI, and file hashes,
prepare a root-owned public JSON manifest and run:

```
./install.sh relay-geneva-profile --manifest /root/accepted-public-profile.json
```

The manifest uses `aegis_relay_geneva_installed_profile_v1`, with `policy`, `role`
and `recovery_helper_sha256`. `policy` pins the exact compiled source, physical
interface, local IPv4, socket mark, complete sorted IPv4 relay endpoint set and
the current `device-guard.conf` SHA256. `role` pins canonical executable and its
argument path, canonical private configuration and its argument path, runtime
events path, unit fragment, the entire exact drop-in path-to-SHA256 map including
`25-relay-geneva-profile.conf`, and the original device-guard control helper.
For an online device service, `role.online_bundle` is a typed optional object
with `argument_path` and `members_sha256` for exactly `bundle.json`,
`outer-ca.pem`, `inner-ca.pem` and `device-ca.pem`. Each canonical root-protected
member joins the existing before/after file-hash attestation. Online argv must
be exactly `binary --device-online-bundle path --config config
--runtime-events-jsonl events`; the pinned unit fragment and every argument
must match. Missing, reordered or additional arguments refuse. Omitting the
object retains the original exact five-argument offline role. Authenticated
same-key renewal validation remains in the client; the new role grant does not
authorize an arbitrary public bundle or key. The selected drop-in deliberately
sets `Restart=no`. A selected request has a bounded runtime lease, at most one
hour; lease termination or a renewal boundary that exits the client leaves it
stopped and blocked. Unattended renewal/restart is not implemented for this
selection. A fresh start requires explicit stopped recovery and renewed exact
authorization under an independent controller.
Private config, identity keys, strategy text, tokens and certificates are not
copied into the public manifest. Root administrative pins supplement, and do not
replace, verified release-signature provenance.

Before either new helper or drop-in is written, the Rust CLI records immutable
public installation intent with exact new-file hashes and checks the old unit is
loaded/inactive/dead with no main/control PID and unchanged existing file pins.
Neither an existing selected file nor an unknown table is adopted or overwritten.
The new drop-in is created exclusively and loaded before the new helper; both
new-file commits use atomic no-clobber creation. A competing administrator file
is never replaced, including creation after an absence check. A partial installer
failure retains intent and created bytes. If the drop-in
exists without a complete sidecar, its recovery pre-start hook fails and the
original ExecStart is not reached. No automatic rollback deletes unknown files.
Generic client/all purge, Ubuntu uninstall and inet-only recover/release refuse
before mutation while any exact selected
sidecar, installation/guard intent, state, helper, drop-in or native journal path
exists, including a dangling symlink. Explicit selected teardown is not yet an
accepted installed operation.

Stage verifies the complete new unit/file map and creates its sidecar exclusively.
The installer remains stopped; the `recover` command runs only in the service
pre-start cgroup. Independent stopped recovery uses the separate administrative
`recover-stopped` command described below. The device-guard helper commits
both the original inet guard and selected netdev guard in one nft transaction.
Initial selected authority is blocked. After reboot, durable prior state can
create only a fresh blocked table once a complete typed inventory proves exact
absence; no prior binding is reused and no deletion is generated on absence.
Wrong-family, duplicate, malformed or unknown same-name tables refuse. Its next systemd start first recovers
only old, source/boot/namespace/executable-owned journals whose process, socket
inodes and private TUN are absent. Exact canonical table ownership is checked
again before any deletion. Unknown ownership or a live old owner refuses startup.
Historical journals, failed transitions and recovery receipts remain private.

The selected service receives only the existing three networking capabilities;
the drop-in preserves default kernel/global hardening. The native worker changes
only its new TUN via verified netlink messages, never existing interface sysctls.
Runtime authorization permits only a qualified self-MainPID activating/start to
active/running READY handoff with every other observed identity and file pin
unchanged. Administrative stop requires strict active/running state. Current
service authorization checks exact MainPID, opened executable FD,
configuration hash, cgroup inode, boot and invocation. The netdev rule itself
matches the selected mark and raw local-to-relay tuple; it does **not** implement
per-packet cgroup authorization.

Blocking happens before signaling an exact re-attested main PID through pidfd.
The stop barrier waits for that PID's exit and leaves the kernel block intact
on failure. It does not claim cancellation of frames that passed the hook earlier.
Physical quiet evidence must cover the full recording interval and start any
post-barrier acceptance interval only after checked terminal shutdown/drain.

Source/pure tests, cross typechecks and a standalone namespace backend test do
not establish installed full-wide behavior, independent privacy capture, target
DPI performance, signed delivery or beta exit. The exact installed candidate
still requires native systemd lifecycle, capture, guard-block, reboot, crash
recovery and independent rollback evidence before release acceptance.


## Read-only selected guard verification

Run `aegis-client profile relay-geneva verify-current` as root to verify an
already active selected client, or add `--require-blocked` to require a loaded,
inactive/dead client and the retained blocked NETDEV table. The command refuses
missing state, any pending guard transition, stale source or policy, changed unit
or process ownership, and missing, extra or drifted selected kernel rules.
It rechecks protected inputs, durable state and role identity around two complete
native kernel observations. It does not stage a profile, prepare a transition,
write state, change NFT rules, stop a process or grant a new binding.

The public JSON result includes the exact compiled source, profile/policy/table
hashes, blocked mode and current binding. Its selected kernel verification covers
only the complete selected NETDEV policy at the observed snapshots. It does not
assert the original INET policy, continuous state between snapshots, physical
quiet or full installed lifecycle acceptance. `physical_capture_verified` and
`installed_lifecycle_acceptance` remain false. Live acceptance must use a signed
candidate built from the source that contains this command, with independent
rollback and capture already ready.


## Explicit stopped teardown

Use `./install.sh relay-geneva-profile-remove`, or resume its exact durable token
with `--resume-token TOKEN`. This source path requires the installed selected
client already inactive/dead, exact protected role/config/unit/public ownership
pins and canonical blocked NETDEV policy. It does not stop or kill a client.
An exclusive teardown marker immediately refuses runtime admission and grants.
The original INET guard is independently rendered as armed BLOCK, applied and
verified against the complete observed policy. All original selected records,
history, native public journals and directory/file identities are durably
archived under `/var/lib/aegis-relay-geneva-history/TOKEN` before any removal.
Private config, tokens and keys are never copied into that archive.

Only historical native owners proven absent by PID/start ticks, every socket
inode and owned TUN absence may have their exact canonical IP table removed.
The known 25 drop-in is removed and daemon-reload/stopped role is verified against
the trusted unit map minus only that entry. Exact archived payload files and
empty owned directories are removed without recursive deletion. The NETDEV
barrier is removed last, after selected admission files are absent and the
original armed INET BLOCK and old-owner absence are freshly verified again.
The durable phase chain supports exact resume; foreign/drifted resources refuse.
A completed token without a marker returns historical-record-only status,
without asserting current kernel or unit state. Original INET remains armed;
normal recovery/purge is a separate explicit operation after selected completion.

This implementation is source preparation. Actual signed final-candidate
installed removal, quiet physical capture and reboot lifecycle remain pending;
pure filesystem or cross-target compile checks do not establish those results.
The 80-second native GuardLease budget covers its native helper operations,
not the entire administrative CLI wall time. Manager observations each have a
separate three-second budget. Setup, filesystem reads and a fresh later lease
are outside the first lease deadline; a few original-member reads still verify
the complete bounded archive. A real installed attempt needs its independently
armed outer rollback deadline and retained failure evidence.

The original INET table must match the complete unbound BLOCK recipe or the
exact original manager DHCP recipe before any flush or operational intent.
The manager variant requires its strict public binding, current boot, loaded
active service, PID/start ticks, opened executable identity, invocation, complete
protected unit/drop-in files and the exact cgroup2 directory FD/inode. The loaded
User must be empty/root for UID0 or systemd-network for the networkd role, with
DynamicUser=no. A stable protected local /etc/passwd opened FD binds the unique
configured account name to its unique UID; all four process UIDs must equal that exact
UID. Other configured users, dynamic accounts, local mapping/UID mismatch or
account-file drift refuse; no network or NSS resolver is used. Only
NetworkManager.service and systemd-networkd.service are supported. Safe custom
Slice paths remain exact through the receipt, current ControlGroup, rule level
and marker; unsupported paths or other roles refuse. Current root-protected
manager executable hashes are observed administrative metadata, not external
release approval. The binding identity and full initial policy digest are retained
in the first durable record and freshly rechecked before the atomic transition
to unbound BLOCK; the manager itself is neither stopped nor modified.

Bash removes all trailing LF bytes when computing the original binding state
hash. This exact convention is separate from the retained full raw file SHA and
inode; CR and other whitespace are not trimmed. Optional strict public original
client/manager binding receipts are archived and preserved in their guard
locations. Unknown, malformed, drifted or extra policy is refused without adoption.
The public inert original-render fixture binds the exact helper recipe and LF
convention. It does not establish actual nft parser/readback compatibility or
installed removal; those remain final-candidate runtime checks.

Bulk archive reading is linear in member count. Every phase validation compares
actual archive-manifest bytes with the SHA carried by the durable phase chain;
identical parsed JSON with changed bytes is refused. The exact new marker is
archived before publishing its installed exclusive record, checked on resume,
and its original inode/hash is checked again before final marker removal.


## Independent stopped recovery

After an independent controller has blocked both guards and verified that the
loaded selected client is inactive/dead with no main or control PID, it may run
`aegis-client profile relay-geneva recover-stopped` as root. The existing `recover`
command retains its service-prestart cgroup restriction; calling it from an
independent guardian is not an administrative recovery path.

The command binds protected profile/configuration/device-state files, refuses a
pending guard transition or teardown, and keeps the original INET and selected
NETDEV blocks intact. It holds the existing administrative lock and recovers only
exact source/executable/boot/namespace-owned journals whose process, all recorded
socket inodes and TUN are absent. Each confirmed deletion keeps a durable private
recovery receipt; journals and earlier receipts remain. An unknown or live owner
refuses. No profile, installer file or guard state is removed or rewritten.

Fresh stopped-role checks surround recovery. Complete selected kernel readback
and original INET verification occur before and after it, with a final native
quiet check. The command's original 80-second limit starts before protected input
reads and is inherited by native helpers, lock acquisition and stopped-role
attestation. It checks late results before reporting success. This synchronous
deadline does not preempt blocked filesystem I/O or cross threads; a parent
controller must retain its independent outer deadline and cleanup.

The result reports owned recovery and snapshot checks only. It grants no active
binding and does not establish installed lifecycle, physical capture, full host
rollback, target-network performance, independent HUMAN review or beta exit.
Existing guardian artifacts require explicit source/candidate rebinding to this
new command; their old-source `recover` argv is not silently reinterpreted.


## Fresh completed-teardown verification

`aegis-client profile relay-geneva verify-teardown --archive-token TOKEN`
observes one exact current-source completed archive under the fixed
`/var/lib/aegis-relay-geneva-history` root. The token must be exactly 32 lower-case
hexadecimal characters. Run only with the accepted signed candidate and protected
operator inputs ready. This command does not resume, repair or remove anything.
The historical `teardown --resume-token` response keeps its retained-record-only
meaning.
This verifies completed **selected** teardown before generic client uninstall:
the protected base unit, client executable/private configuration and original
device guard must still be installed. Their later absence refuses this oracle;
it is not generic whole-client removal acceptance. An archive from an older
candidate source is refused rather than carried into the new candidate.

The verifier requires the entire ordered completed phase chain, original marker,
archive identity and manifest/member pins. It uses the saved public profile and
guard state while rereading the protected current private configuration. It
checks all selected operational records, helper, drop-in and native directory
absent, the exact original guard state/bindings preserved, the loaded service
inactive/dead with zero main/control PID, the complete original INET BLOCK policy
and absent selected NETDEV admission. Existing native quiet checks cover every
archived original owner, recorded socket inode, TUN and owned table. All checks
and actual archive-file custody are repeated after constructing the return JSON.
No rules, unit, process, ownership record or persistent file is changed; the
existing protected guard-file lock is held for the observations.

One inherited synchronous 80-second deadline covers the new command's inputs,
archive reads, formatting and native observations. Local helper deadlines may
shorten it. This refuses late results; it cannot preempt filesystem/kernel I/O or
prove that every escaped helper descendant is gone. The result explicitly keeps
`whole_operation_cgroup_empty_proven`, `operational_grant`,
`physical_capture_verified` and `installed_lifecycle_acceptance` false. It is a
fresh scoped observation, not continuous-state, independent capture or full
installed lifecycle evidence. Existing controller factories remain disabled; an
exact candidate/native acceptance and an independent rollback remain required.
