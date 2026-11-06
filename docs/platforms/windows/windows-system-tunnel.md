# Windows system tunnel

The Windows x64 client uses the existing Linux relay transports, authenticated
inner TLS, fake-IP allocator and lossless TCP pump. Its OS boundary uses signed
Wintun 0.14.1, native IP Helper and Windows Filtering Platform APIs. It does not
require the historical unsigned AEGIS callout driver or test-signing mode.

This is a developer distribution. AEGIS executables do not have a publisher
Authenticode signature. Wintun is the unmodified, independently pinned upstream
signed driver. Windows 10/11 with NTFS is the target; actual acceptance evidence
belongs to the tested Windows 11 candidate `592ecdf8` on 13 September 2026
(acceptance report (archived: `docs/audit/windows-system-tunnel-2026-09-13.md`)). It does
not certify the current source. Its 923-test result is separate from the later
`f198d09` current-host local/remote checks linked below. The [10 October audit](../../operations/security-audit-2026-10-10.md)
records open Windows MASQUE and positive Poisson CI failures; current native
lifecycle acceptance and a publisher-signed AEGIS package remain gates.

For the 12 October source wave, the published Windows CI job failed strict
Clippy and one BIT-TRAPS timing test. Its separately committed in-memory
BIT-TRAPS repair passed the exact focused method 1/1 on a macOS host with
unchanged source bytes. That check neither executes the Windows target nor
establishes the production 10 ms cutoff, Wintun/WFP lifecycle or installed
traffic behavior; see the [beta-exit roadmap](../../ROADMAP.md)
and the retained `Windows-local-committed-recheck-r1` receipt.

The 13 October B-04 source successor writes a private schema-v2 route journal
before native creation, records each route as pending, and commits ownership
only after the native create call succeeds. It refuses to adopt an existing
route, including an identical row. Cleanup is sequenced through the journal:
the `removing` transition is durably written before a native delete. After an
interruption, recovery refuses automatic deletion if a pending or removing
route still exists; only an absent route can clear that ambiguous record.
Schema-v1 and malformed journals also refuse automatic recovery. Targeted
formatting and diff checks passed. The new local journal unit methods did not
run because this host lacks Windows SDK headers; zero native Windows tests ran.
A matching route substituted between native readback and deletion remains a
residual race, so installed recovery, the production 10 ms cutoff and signed
Wintun/WFP lifecycle are still open.

A read-only UTM readiness retry on 13 October exited -6 while the Mac was
locked. Its distinct receipt (`evidence-archive/testing/2026-10-13/b04-windows-utm-readiness-r1/receipt.json`)
contains the command and outcome. No Windows guest method was executed in
that retry; native route identity and timing acceptance remain open.

A distinct UTM readiness R2 (`evidence-archive/testing/2026-10-13/b04-windows-utm-readiness-r2/receipt.md`)
read-only retry successfully listed the VMs with authorized local access and
observed one Windows VM in `started` state. Its guest IP query returned an RPC
timeout with no address, so the guest agent is not ready by this evidence. No
guest command, Windows SDK check, package inspection or native test ran; the
VM was not rebooted. The earlier sandbox `-6` attempt remains a separate
failure.

The separate UTM readiness R3 (`evidence-archive/testing/2026-10-13/b04-windows-utm-readiness-r3/receipt.md`)
first failed to find `utmctl` on Python's `PATH`; the absolute-path IP query
then returned an empty address and an RPC timeout (`OSStatus -2700`) despite
a subprocess exit code of zero. It ran no guest command or native test and did
not alter or reboot the VM. Guest readiness remains unestablished.

A separate UTM native-readiness R1 (`evidence-archive/testing/2026-10-13/B04-windows-utm-native-r1/receipt.md`)
used the user-authorized stopped Windows VM while leaving the already-started
VM untouched. `utmctl start --disposable` returned process exit zero, but QEMU
reported `OSStatus -2700` and an EFI image-in-use error. Immediate readback
showed the target still stopped; the already-started VM remained started. No
guest boot, SDK inspection or native Windows test ran. The image relationship
was not resolved, and this attempt is **NO-GO** for Windows acceptance.

After the owner reported that Windows was open, the separate [UTM readiness
R4](evidence-archive/testing/2026-10-13/B04-windows-utm-readiness-r4/receipt.md)
again found `utmctl ip-address` exiting zero while its guest RPC timed out.
The VM window still displayed a 10 October clock and did not visibly react to
Escape; capture was released. A [bounded restart
R1](evidence-archive/testing/2026-10-13/B04-windows-utm-restart-r1/receipt.md)
sent one `utmctl stop --request` to the already-started VM, then verified that
it remained started after 30 seconds. Automatic approval review rejected the
proposed forced power-off before execution because it could discard unsaved
guest work. Neither Windows VM was stopped or restarted. No guest command,
Windows SDK check or native Aegis method ran; B-04 installed Windows acceptance
is still **NO-GO**.

With explicit owner approval, [UTM restart
R2](evidence-archive/testing/2026-10-13/B04-windows-utm-restart-r2/receipt.md)
force-stopped the frozen VM, but the first start failed despite `utmctl` exit
zero because a configured Windows installer ISO in Downloads was missing. A
first settings repair (`evidence-archive/testing/2026-10-13/B04-windows-utm-settings-repair-r1/receipt.md`)
cleared media in the wrong of two UTM registrations, retried once and failed,
then exactly rolled back an unintended config UUID rewrite. Read-only
registry analysis proved that both registrations point to one physical
`Windows.utm` bundle. The intended UUID is
`01CE95DE-D79D-4570-82CA-3CF17251E840`.

The second settings repair (`evidence-archive/testing/2026-10-13/B04-windows-utm-settings-repair-r2/receipt.md`)
detached only the missing installer ISO from that intended registry entry,
while retaining its existing UTM guest-tools ISO and NVMe disk. Structured
before/after preferences readback found no other registry change; the bundle
config SHA and UUID remained unchanged. One start booted Windows, and after a
bounded wait the guest agent returned an IP while the UI showed a fresh
desktop. This establishes guest readiness for scoped diagnostics only.
Guest-agent `utmctl exec` returns misleading zero/empty output, so commands
must write uniquely named scratch results for `utmctl file pull`; host exit
alone cannot mark a native method PASS. No B-04/B-10 native Aegis test had run
at this checkpoint. The stale alias remains stopped and must not be started
concurrently with the intended UUID.

A separate [scoped Windows Journal native
receipt](evidence-archive/testing/2026-10-13/B04-windows-journal-native-r1/receipt.md)
bound a PE32+ x86-64 test executable SHA-256
`a6cbc30b4449230d708c1dda8904bde56bf6f0bad45db15b518b92d77fe82399`
to unchanged canonical `aegis-core/src/windows_tunnel/lifecycle.rs` SHA-256
`dd9f512fa5750baf6cc3414bcf187e6347c13fb8be3f4d92afb4d4cfb4d58b43`.
Guest `certutil` matched the PE hash. Real guest libtest `--list` showed the
three exact intended Journal methods; each exact filter passed 1/1 with
`EXIT=0`, totaling **3/3 selected PASS** under Windows ARM64 x64 emulation.
The harness copies the pure Journal shape and stubs native route and file
operations, so these checks do not exercise IP Helper, protected journal
writes, installed recovery, native ARM64 code or the route identity race.
Raw guest output was pulled before deleting the uniquely named test exe and
result files; cleanup readback found only cleanup markers. The intended VM
remained started and guest-agent IP-ready, with the duplicate alias stopped.

A distinct native ARM64 Journal run (`evidence-archive/testing/2026-10-13/B04-windows-journal-arm64-native-r1/receipt.md`)
used the same canonical `lifecycle.rs` SHA-256
`dd9f512fa5750baf6cc3414bcf187e6347c13fb8be3f4d92afb4d4cfb4d58b43`
and a PE32+ Aarch64 test executable SHA-256
`2da6213fd228beba9c4d8734b140b959722dc90b9389bbba5b43c472c6e00af5`.
The guest hash matched; actual `--list` showed exactly three expected methods,
and each exact filter passed 1/1 with guest `EXIT=0` (**3/3**). Scratch files
were removed after output pull with exact-path readback. This establishes
native ARM64 execution of those pure in-memory Journal transitions; route
and file operations remain stubbed.

A separate full canonical client cross-build (`evidence-archive/testing/2026-10-13/B04-windows-full-cross-r1/receipt.md`)
at commit `51c036f57ec0a79b0f90a1943e606340a04a9e24` passed offline locked
`aegis-client` x64 Windows GNU test-source typecheck and linked a PE32+ x86-64
client SHA-256
`8aeaf103d2a4895ba34d73b8f71328d570bbcabdf13712e7534e9efa151238ad`.
The first check failed on a compiler target flag and the first link failed on
import-library resolution; both attempts are retained. The full client PE
was not run, signed or installed in Windows. Real IP Helper/Wintun/WFP route
lifecycle, protected journal writes, recovery, 10 ms timing and route identity
race remain unaccepted.

A later native ARM64 protected-file lifecycle run (`evidence-archive/testing/2026-10-13/B04-windows-file-lifecycle-native-r2/receipt.md`)
included the exact canonical Journal, Windows private-file and secret-file
source in one harness. Its selected method passed **1/1** on the Windows guest:
real global mutex, ACL-protected private journal creation, no-replace refusal,
read/ACL validation, pending and committed replacement, then empty recovery.
The first R1 method failed because the harness held an external validation
handle across replacement; the corrected R2 source and both receipts remain.
Guest PE hash matched, scratch was removed, and `route print` before/after
matched byte-for-byte. Route operations remained fail-closed stubs; no actual
IP Helper/Wintun/WFP, installed recovery or timing gate was exercised.

A distinct R3 native ARM64 route-read and pending-recovery run (`evidence-archive/testing/2026-10-13/B04-windows-route-read-native-r3/receipt.md`)
used exact canonical `lifecycle.rs`, `network.rs`, `windows_file.rs` and
`secret_file.rs` from isolated worktree commit `d3e373371`; the test PE
SHA-256 was `a92bf8cb238f79a73ba46b21e16e24983def1aae4b5d8e20f8b0a53555ca58a1`.
One exact guest method passed **1/1**, 11 filtered, `EXIT=0`: real IP Helper
`GetBestRoute2` resolved the path to `198.18.0.79`, and `GetIpForwardEntry2`
confirmed that exact host route was absent before protected pending-journal
creation and `recover_routes` cleared it. Guest hash matched; the private
child was removed and `route print` before/after was byte-identical. No
route creation/deletion, Wintun, WFP or service command ran. The R1 failed
file test and R2 corrected file pass remain separate; installed route
lifecycle, timing, identity-race and signed package gates remain open.

A read-only installed inventory (`evidence-archive/testing/2026-10-13/B04-windows-route-read-native-r3/receipt.md`)
then found `AegisClient` service absent (`sc` 1060), no `C:\AEGIS-kit` or
`C:\Program Files\Aegis` directory, and no `wintun.dll` in the checked
Windows Temp path. This is a limited path check, not a whole-disk inventory.
The later source change pins both AMD64 and ARM64 Wintun DLLs; a native ARM64
installed route/service run still needs a compatible signed kit and driver.
The inventory scratch file was removed after evidence pull;
no install, service or network mutation occurred.

## Network behavior

| Linux responsibility | Windows implementation |
|---|---|
| nftables/TUN capture | Wintun, IPv4 and IPv6 capture routes |
| Transparent TCP | smoltcp and the shared lossless TCP/half-close pump |
| Persistent UDP | Existing gRPC datagram transport; MASQUE remains available in split profiles |
| DNS preview | Same fake-IP allocator and hostname leases; UDP and framed TCP DNS |
| IPv6 and large UDP | Bounded fragment reassembly and response fragmentation for both families |
| Firewall backstop | Persistent WFP ALE blocks and boot-time packet rules; a dynamic interface permit lives only with the tunnel process |
| Relay loop exclusion | Numeric relay host routes and executable/endpoint WFP exceptions |
| systemd and restart | Native SCM LocalSystem service, auto-start, crash recovery |
| Resolver/route recovery | Only tunnel DNS is configured; owned routes have a private durable journal |
| Network changes | Physical default-route changes rebuild capture and relay pins under protection |
| Enrollment | Existing CSR, certificate and device identity workflow with Windows ACLs |
| Upgrade/rollback | Verified new version directory, SCM switch, retained previous version and state |
| Chrome-like TLS/QUIC | AWS-LC memory BIOs with Tokio/Winsock, Windows trust store and Unicode CA paths |
| Operator commands | `client prepare-config`, `connect`, `disconnect`, `doctor`, `upgrade`, `rollback` |
| Publisher verification | Native Ed25519 manifest verification using the existing AEGIS publisher key |

The complete profile carries TCP, UDP and DNS; raw ICMP applications and protocols
other than TCP/UDP are not relay transports. Link-local IPv6 discovery and DHCP
have narrow firewall exceptions. Loopback remains local. Physical LAN routes
are not overwritten: unmatched direct LAN traffic is blocked by full protection.

Full mode requires `grpc_datagram` first for UDP. QUIC DATAGRAM's transport size
limit cannot carry arbitrary fragmented UDP datagrams; full mode rejects a
MASQUE-first profile instead of silently dropping that support. The gRPC path
is tested with 65,000-byte UDP payloads and 2 MiB TCP streams after client FIN.

For complete TCP half-close support, upgrade both client and relay to a build
containing the September 14 directional EOF fixes. WebSocket negotiates
`half-close-v1` through the authenticated tunnel response; older peers retain
their previous behavior and cannot satisfy request-after-FIN acceptance. The
relay also needs the MASQUE response-drain fix in `00beb77` or later.
See the TCP EOF regression report (archived: `docs/audit/windows-half-close-2026-09-14.md`).

## Build a complete kit

Use the pinned Rust toolchain and Visual Studio C++ build tools. WDK is not needed
for the Wintun product path. AWS-LC SSL requires CMake and libclang. The bootstrap
below installs pinned build tools only under `target/windows-build-tools`;
it does not change system Python. NASM uses the pinned AWS-LC crate's prebuilt
x64 non-FIPS objects. Commit the source first so distribution provenance is exact.

```powershell
./tools/windows/build-kit.ps1 -Bootstrap -Output C:\AEGIS-kit
```

The new output directory contains exactly six files: the two AEGIS executables,
`wintun.dll`, `WINTUN-LICENSE.txt`, `README.txt`, and `manifest.json`. It contains no
configuration or credentials. Obtain the manifest hash through an authenticated
channel independently of the kit. Both the archive and DLL have fixed SHA-256
pins; downloading the DLL from another site is unnecessary. The fetch script
also verifies its Authenticode signature.

`build-kit.ps1` also creates a ZIP and a separate delivery JSON with source,
binary feature provenance and hashes. The manual **Windows candidate package**
workflow builds the same kit and runs native lifecycle checks before uploading it.
It does not publish a stable release or possess a signing key.

## Use the existing relay and identity

Keep the actual relay addresses, TLS authorities, CA files and device identity
from the existing configuration. Do not substitute the example hostname or
generate a replacement device key during installation. Import a locally exported
Linux relay configuration and its existing credential files:

```powershell
C:\AEGIS-kit\aegis-winctl.exe client prepare-config `
  --config C:\Private\linux-aegis.toml --output C:\Private\Windows-profile `
  --resolve-relay --udp-transport grpc_datagram
```

The command writes private credential copies, including a separate MASQUE CA,
and preserves the input. It resolves TCP relay hostnames into an endpoint pool
before capture, preserving IPv4/IPv6 alternatives and TLS authorities. A relay
address family without a physical route fails its bounded dial and permits the
existing endpoint fallback; it is never recursively carried into the tunnel.
`--udp-transport` is an explicit selection requiring
matching server support. Direct/Geneva/hybrid profiles are rejected rather than
misrepresented as equivalent relay profiles. Linux absolute credential paths
must refer to available local copies before import. The generated config is
`C:\Private\Windows-profile\config\aegis.toml`.

For manual configuration, add these settings:

```toml
mode = 'relay'

[ingress]
primary = 'wide'
allow_fallback = false

[windows_tunnel]
adapter_name = 'AEGIS'
kill_switch = true
configure_dns = true
dns_upstream = '9.9.9.9:53'
mtu = 1280
max_flows = 256
idle_timeout_secs = 60
# An absent or empty include_routes captures both complete IP families.

[relay]
# Retain the existing server, server_name, auth and TLS identity settings.
# The dial addresses must be numeric; TLS server_name remains a hostname.
tls_backend = 'chrome_like_experimental'
transport_priority = ['grpc_stream']
udp_transport_priority = ['grpc_datagram']
```

The example is a fragment, not a complete credential-bearing configuration.
`include_routes` can define a deliberate split profile. Only split profiles can
disable `kill_switch` or `configure_dns`, useful for isolated tests. Relative
driver paths resolve beside the executable; the installer sets an absolute path.

Run from an elevated PowerShell:

```powershell
C:\AEGIS-kit\aegis-winctl.exe client install `
  --package C:\AEGIS-kit --manifest-sha256 <independent-sha256> `
  --config C:\Private\aegis.toml --root C:\ProgramData\AEGIS-v1 --service --start
```

For a manifest signed by the established AEGIS release publisher, replace
`--manifest-sha256` with `--manifest-signature C:\Private\manifest.json.sig`.
The signature is a detached Ed25519 signature over the exact `manifest.json`
bytes and stays outside the six-file kit. It is verified before trusting any
manifest field. A public key supplied inside a downloaded package is never used.
This authenticates the manifest; it does not supply Windows Authenticode or turn
an unaccepted candidate into a stable release.

```powershell
C:\AEGIS-kit\aegis-winctl.exe client doctor --root C:\ProgramData\AEGIS-v1
C:\AEGIS-kit\aegis-winctl.exe client connect --root C:\ProgramData\AEGIS-v1
C:\AEGIS-kit\aegis-winctl.exe client disconnect --root C:\ProgramData\AEGIS-v1
```

These commands verify installed binaries and SCM executable ownership.
`doctor` reports configuration, adapter and filter state without exposing
credentials. Service RUNNING and filter presence alone are not relay health.

To test TLS independently of relay authentication, use the client diagnostic
with `--require-handshake` (otherwise capture probes intentionally tolerate a
listener closing after ClientHello). `--ca-cert` adds an explicit CA bundle.
Neither flag disables chain or hostname verification:

```powershell
C:\AEGIS-kit\aegis-client.exe tls-probe --addr '[2001:db8::7]:443' `
  --server-name relay.example --backend chrome_like_experimental `
  --require-handshake --json
```

The root must be new. A system service requires administrator-owned parent
directories; a user-writable parent is rejected. `--service-name` defaults to
`AegisClient`; choose a different explicit name for an isolated test installation.
If the installed executable fails preflight, the verified file receipt remains
available: run `client uninstall --root <failed-root>` from the external kit.
This removes only matching installed binaries and retains configuration/state;
the failure does not register a service. A corrected install uses a new root.
Only one machine-wide tunnel may run at a time. Existing services are never
adopted just because their names match. SOCKS profiles still use LocalService;
the system tunnel uses LocalSystem for adapter, route and firewall management.

`--ingress-preflight --json` checks configuration and driver integrity without
network mutations. `--ingress-startup-probe --json` creates an isolated adapter
and checks interface setup without installing capture routes or firewall policy.
SCM Running means the capture engine is ready, not that the remote relay has
passed an application health check.

## Stop, recover, upgrade and remove

Stopping or crashing the client retains the kill switch. This is intentional:
only an explicit disconnect restores ordinary direct networking.
If an interrupted shutdown leaves the named Wintun adapter present, the next
service start reopens that adapter before configuring it; a clean first start
still creates a new adapter. This prevents a reboot recovery loop on an adapter
name that survived the previous process.
The tunnel interface exception is removed on normal shutdown and process death,
before its interface identity can be reused. It is not persisted across reboot.
`client doctor` and `tunnel status` distinguish persistent blocks, boot blocks
and live interface permits; an object count alone does not prove packet delivery.

```powershell
C:\AEGIS-kit\aegis-winctl.exe tunnel status
C:\AEGIS-kit\aegis-winctl.exe tunnel disconnect `
  --config C:\ProgramData\AEGIS-v1\config\aegis.toml --service-name AegisClient
```

For a foreground client, stop it first. `tunnel recover --config <path>` repairs
only confirmed journal-owned routes and retains protection. An existing pending
or removing route, or an invalid/old journal, refuses automatic recovery for
manual inspection. A failed removal keeps the journal available for a retry.
Physical adapter DNS and default
routes are not changed. Uninstalling an inactive old version does not remove
another version's WFP protection.

```powershell
C:\AEGIS-kit\aegis-winctl.exe client upgrade `
  --root C:\ProgramData\AEGIS-v1 --new-root C:\ProgramData\AEGIS-v2 `
  --package C:\AEGIS-new-kit --manifest-sha256 <new-independent-sha256>
C:\AEGIS-kit\aegis-winctl.exe client rollback --root C:\ProgramData\AEGIS-v2
C:\AEGIS-kit\aegis-winctl.exe client uninstall --root C:\ProgramData\AEGIS-v1
```

Upgrade validates every kit member before staging. It retains the old files and
learned state, changes SCM only after preflight, and restores the old service if
the new service cannot become ready. Rollback checks the recorded previous
manifest and executable hashes. Run uninstall from an external kit; it preserves
configuration, identity, state and receipts. Do not delete those directories to
simulate uninstall.

## Check the installed service across a reboot

Use a dedicated Windows test machine with console access. The checkpoint commands
are read-only apart from creating their private evidence directory. They never
restart Windows or start/stop a service, and do not depend on the historical
AEGIS callout driver. Prepare while the installed service is running:

```powershell
C:\AEGIS-kit\aegis-winctl.exe client reboot-check prepare `
  --root C:\ProgramData\AEGIS-v1 --output C:\ProgramData\AEGIS-reboot
# Restart the test machine from its console, then run:
C:\AEGIS-kit\aegis-winctl.exe client reboot-check verify `
  --root C:\ProgramData\AEGIS-v1 --checkpoint C:\ProgramData\AEGIS-reboot
```

Prepare from an elevated administrator session under a protected system parent.
The new checkpoint directory and file are administrator-owned, so a later SYSTEM
task can validate them without trusting a user-writable file. User-writable
ancestry is rejected. Checkpoints from older kits that used the preparing user's
ACL must be prepared again with the corrected kit; do not relax their ACL checks.

Verification requires a later stored Windows boot timestamp, the same machine,
installation, manifest and configuration, plus a running full-tunnel service,
its adapter and owned persistent/boot blocks with live interface permits. The
same boot or a changed profile fails with a nonzero exit code. The result only
establishes post-boot service state: proving no leakage during early boot still
requires an external packet capture, and relay payload egress needs an authenticated
end-to-end test. The JSON explicitly keeps these unmeasured gates false.

The lifecycle follows [Microsoft's WFP object lifetime contract](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management).
Boot evidence uses the stored [Win32_OperatingSystem.LastBootUpTime](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem),
not a subtraction of the current wall clock and uptime.

## Explicit current-host acceptance

After explicit operator authorization for brief machine-wide capture, the
ignored `current_host_full_tunnel` test can exercise the shipped candidate in a
separate private installation. Build its harness with the additional
`windows-host-acceptance` feature; do not include that feature in release EXEs.
Set `AEGIS_TEST_WINCTL` to the control EXE in an independently verified six-file
kit and `AEGIS_ALLOW_MACHINE_WIDE_TEST=1`. First set
`AEGIS_HOST_PREPARE_ONLY=1` to rehearse recovery without capture. Then set it to
`0` for the actual run. Invoke only this ignored test with one test thread.

```powershell
cargo test --locked -p aegis-client --bin aegis-client `
  --features chrome-like-tls,chrome-like-quic,windows-host-acceptance `
  current_host_full_tunnel -- --ignored --nocapture --test-threads=1
```

The gate refuses existing product protection, preserves the original service,
and uses synthetic local relay credentials. It arms an independent 60-second
watchdog before connecting, bounds payload work to 35 seconds, restores ordinary
networking, and confirms both recovery paths before uninstalling its own service.
Private fixture directories remain for inspection. It never reboots the machine.

`AEGIS_HOST_INJECT_FAILURE=1` is an explicit recovery fault-injection mode: its
payload test must fail while both recovery paths still finish. Leave it unset
for ordinary acceptance. A separately authorized temporary remote fixture can
be selected with `AEGIS_HOST_REMOTE_FIXTURE`, pointing to a protected test-only
JSON file. This never discovers or loads the existing user's production profile.
See current-host evidence (archived: `docs/audit/windows-current-host-2026-09-13.md`) for the
measured `f198d09` candidate and the distinction between local, remote and reboot
checks. Later source must pass its own exact-commit CI and native acceptance;
these historical receipts do not transfer across revisions.

The same `aegis-client device prepare/complete/status` and public bundle commands
are available for offline enrollment. The private key stays in its managed local
identity directory. Secret files and atomic staging have protected ACLs before
the first secret bytes are written. Shared writable temporary directories are
deliberately unsuitable for enrollment.

## Managed online certificates

The full system-tunnel runtime now uses the online renewal supervisor. The
installer accepts `--device-online-bundle` with the immutable four-file v3 public
bundle and an already enrolled, SYSTEM-compatible identity. The profile requires
`full-wide-tun`, UDP, DNS capture and the kill switch; split routes and fallback
are rejected. Follow the [online enrollment contract](../../operations/device-online-enrollment.md)
for authority provisioning and the independent public-bundle trust pin.

Keep `device.key` and `device.pem` in one protected identity directory outside
all installation/version directories. The service runs as LocalSystem; its
identity directory must be owned by SYSTEM or Administrators with the enforced
private ACLs. An ordinary per-user prepared identity is not silently adopted or
made service-accessible. The explicit `device prepare-system` command creates a
new machine-owned identity from elevated PowerShell, without running the command
as SYSTEM or changing an existing user's identity ACLs. Its files grant no
LocalService access. Live source4bc acceptance used an elevated interactive
administrator to prepare/enroll, then LocalSystem for automatic renewal,
authority outage/recovery and a cross-build switch/rollback. The key stayed in
place and machine ACLs survived renewal. This verifies the explicit command
sequence; a graphical enrollment/install flow is not claimed. See the
machine identity report (archived: `docs/audit/windows-machine-identity-2026-09-19.md`).

```powershell
C:\AEGIS-kit\aegis-client.exe device prepare-system `
  --device-id <assigned-device-id> `
  --identity-dir C:\ProgramData\AEGIS-Identity\device `
  --device-ca C:\Private\device-v3\device-ca.pem
C:\AEGIS-kit\aegis-client.exe device bundle-inspect `
  --identity-dir C:\ProgramData\AEGIS-Identity\device `
  --bundle-dir C:\Private\device-v3 --json
C:\AEGIS-kit\aegis-client.exe device redeem `
  --identity-dir C:\ProgramData\AEGIS-Identity\device `
  --bundle-dir C:\Private\device-v3 `
  --invitation-file C:\Private\device-invitation
```

Use an independently authenticated public bundle and protected invitation file.
The invitation is not a command-line token. These preparation/enrollment commands
do not install capture or start the service; install the resulting profile below.

For this canonical online profile set `ingress.primary = 'socks5'`,
`ingress.allow_fallback = false`, and `ingress.wide.enabled = false`; the
`windows_tunnel` section selects actual full-system capture. The primary field
does not open a SOCKS listener in Windows tunnel mode. Supply the exact numeric
relay/authority endpoints and inner TLS trust from the bound public bundle.

```powershell
C:\AEGIS-kit\aegis-winctl.exe client install `
  --package C:\AEGIS-kit --manifest-sha256 <independent-sha256> `
  --config C:\Private\aegis-online.toml `
  --device-online-bundle C:\Private\device-v3 `
  --root C:\ProgramData\AEGIS-v1 --service --start
```

The installer copies public trust material and preserves the external identity
paths. Upgrades and rollbacks keep the online bundle flag and the same identity;
they do not make a stale certificate/key copy inside a version directory.
Before recovery or renewal, persistent WFP protection permits only the client's
exact relay/authority control endpoints. A due certificate stops capture; SCM
restarts the client, which renews or resumes its pending request using the same
key. Capture and readiness require a fresh acknowledgement from the live relay.
An unavailable authority leaves the client blocked. Explicit disconnect/uninstall
removes the owned protection; normal stop or failure retains it.

Offline certificate installation remains separate. Candidate test receipts and
production fleet activation must be checked independently; this source support
does not enable online enrollment on an existing server pool.

CI retains `windows-native-lifecycle` and the candidate workflow retains
`windows-candidate-native-evidence`. A lifecycle PASS records installation,
SCM connection, process crash/restart, route-change recovery, upgrade/rollback,
and uninstall with configuration/state retention. Its exact executable hashes
are included. This isolated service test uses split routes and the same package
for the version-switch transaction; its JSON explicitly does not claim relay
payload, global kill-switch or reboot acceptance. The separate Wintun soak
records actual synthetic TCP/UDP/DNS payload and inner-TLS outage recovery.

The 13 October `windows-rust` CI run on commit `115135398` failed before four
adapter tests executed: an ignored native test constructed `NetworkGuard`
through its now-private cleanup field. A reviewed source repair adds a
route-only constructor that resolves the real interface index and retains
route cleanup on Drop, and updates that test. Formatting and source review
passed; the next exact-head Windows CI must compile and run the four tests.
This source repair is not installed tunnel or route-change acceptance.

The B-04 ARM64 Wintun source receipt (`evidence-archive/testing/2026-10-13/B04-wintun-arm64-source-r1/receipt.md`)
binds the signed Wintun 0.14.1 ARM64 DLL to its exact hash and retains the
existing AMD64 pin. The revised fetch verifier checks the pinned archive,
both DLL hashes and Authenticode signatures; the exact script ran with exit 0
in the Windows ARM64 guest and retained the legacy AMD64 JSON fields. The
changed Rust module typechecked for both Windows architectures. Earlier
toolchain and readback failures remain separate. This was source and fetch
preparation; no ARM64 Wintun load, adapter, route or service was accepted.

The B-04 ARM64 unsigned-kit proposal receipt (`evidence-archive/testing/2026-10-13/B04-arm64-unsigned-kit-proposal-r1/receipt.md`)
records source support for an **unsigned engineering kit**: client, winctl,
manifest platform and the pinned Wintun DLL must all match ARM64. The Rust
package tests passed 9/9, ARM64 `aegis-winctl` cross-check passed, and a
synthetic eight-file ARM64 kit passed the native Windows unsigned validator.
The executable fixtures were inert 128-byte PE headers, so this is not a
working client or installed-kit PASS. A mixed-machine negative was rejected.
An independent review found that the first proposal could reach the existing
x64-only signing flow. The corrected signer and finalizer reject ARM64 before
provider/adapters, private snapshot or output; their native guest negative
checks returned the exact platform errors with no output. The signer also
rechecks the immutable snapshot. A separate x64 regression reached the
expected missing-policy check; its first finalizer harness lacked one script
(`EXIT=1`), and the corrected R4 rerun reached the expected policy check
(`EXIT=0`). All failed attempts and guest cleanup are retained in the receipt.
The release signer, finalizer, `build-kit.ps1` and installed route/service
lifecycle remain x64-oriented. The first committed guard at `ce2300657`
caused the hosted Windows adapter-custody test to fail: for an absent candidate,
it read `manifest.json` before the intentionally wrong adapter pin could be
rejected. The custody ordering receipt (`evidence-archive/testing/2026-10-13/B04-custody-ci-order-r1/receipt.md`)
retains that CI failure and the two unchanged-test UTM retries, both of which
stopped earlier in the QGA SYSTEM `SystemTemp` fixture's canonical-handle check.
An R3 guest-only test with one fixed fixture path exercised the custody
assertions and passed; separate exact patched signer and finalizer checks
rejected an existing synthetic ARM64 candidate before output. The two-script
fix only defers the early platform read when input is absent, preserving the
wrong-pin refusal order. The unchanged hosted custody test on the final commit
still determines CI acceptance.

The real-binary diagnostic receipt (`evidence-archive/testing/2026-10-13/B04-arm64-real-kit-ce-r1/receipt.md`)
binds a **no-feature** ARM64 client and winctl build to exact committed source
`ce2300657`. In the Windows ARM64 guest, the client printed `--help` with exit
0, winctl built an unsigned schema-2 kit using those two binaries and the
pinned ARM64 Wintun DLL, and the native unsigned validator checked all eight
files with exit 0. The manifest SHA-256 is
`811ef75bc170b98c7a6fbb0bc15dff73ea2e2173c0e18b8af57722661e0bce56`.
Earlier full-feature attempts failed while cross-building external
`aws-lc-sys` C code with the available Clang, CMake and MSVC import libraries;
the first exact-source no-feature retries also retained toolchain failures.
The diagnostic kit does not establish a working Chrome-like TLS/QUIC client,
signed release, installed kit, driver, adapter or route lifecycle.

The later full-feature R16 diagnostic (`evidence-archive/testing/2026-10-13/B04-arm64-full-feature-f786-r1/receipt-r16.md`)
cross-built the original `aws-lc-sys 0.44` on clean exact `f786ba4ce` plus a
reviewed, SHA-pinned toolchain helper now adopted in source. Both full-feature
native ARM64 client and winctl PE hashes matched in the Windows guest. Client
`--version` reported embedded Git, timestamp, target, feature set and lockfile
identity; client and winctl `--help` and an unsigned schema-2 eight-file kit
validation each exited 0. The receipt retains R1–R15 failed attempts and guest
cleanup. This establishes a reproducible unsigned diagnostic build and basic
guest execution; it does not establish signing, installed Wintun/service,
route add/delete, authenticated transfer or recovery. The newly adopted helper
has not run in exact-commit CI yet.

The proposed B-04 Wintun OpenAdapter R1 diagnostic (`evidence-archive/testing/2026-10-13/B04-arm64-adapter-readonly-proposal-r1/receipt.md`)
linked an ARM64 PE but ran **zero guest methods**. Its read-only premise was
rejected before execution: upstream `WintunOpenAdapter` unconditionally queues
orphaned-device cleanup, which can remove problematic Wintun adapter instances
even when the requested name is absent. R1 also accepted any nonzero Win32
error as proof of absence, which could mask an API or access failure. The
The R2 DLL-load/export proposal (`evidence-archive/testing/2026-10-13/B04-arm64-adapter-export-proposal-r2/receipt.md`)
was also rejected before guest execution:
Wintun 0.14.1 performs legacy-device cleanup from its `DllMain` process-attach
path, so `LoadLibraryExW` can remove devices without any explicit Wintun API
call. Its earlier script hashes were corrected in the retained rejected
receipt. The R3 static successor (`evidence-archive/testing/2026-10-13/B04-arm64-wintun-static-r3/receipt.md`)
inspects the pinned ARM64 PE headers, certificate
table presence and exports as file data on the host only. It does not validate
the signature cryptographically or execute native code. Installed Windows
acceptance remains **NO-GO**; an actual DLL load or Open/Create test needs an
isolated disposable guest, an exact baseline and independent rollback.

The B-04 unsigned kit handoff R2 receipt (`evidence-archive/testing/2026-10-13/B04-kit-handoff-r2/receipt.md`)
binds the reviewed source patch SHA-256 `a3ef0cf20b29e9138082fc844795bc512fe43e83063ed32981ef61cc3b2f27b0`.
The first R1 proposal (`evidence-archive/testing/2026-10-13/B04-kit-handoff-r1/review.md`)
was rejected with P2 because it checked the staged kit before ZIP creation but
recorded the later ZIP without inspecting members. R2 checks the created ZIP's
exact member set, bounded sizes, manifest identity and each payload digest,
then records the digest computed from the inspected open archive. Its Windows
read handle denies concurrent writes and replacement during that inspection.
The corrected Authenticode source contract passed locally, and inert ZIP
tamper controls passed 8/9 with one Windows-only held-file test skipped on
macOS. No native Windows builder, held-file test, signing or installed method
ran in this R2 round; exact successor CI is pending. The delivery record is
unsigned, while the policy remains unprovisioned and the signing/finalization
and signed-package admission paths remain x64-only. B-04 installed acceptance
remains **NO-GO**.

The current-source ARM64 cross-check and strict Clippy receipt (`evidence-archive/testing/2026-10-13/B04-current-cross-clippy-r1/receipt.md`)
SHA-256 `d1a52ecd90143d965f4a6ff3856144576a29ab61407f3ab7307c9cd7bee2e3ce`
binds base `c1d204d5` plus exact working-file and lockfile hashes. With the
existing xwin SDK/CRT and matching Rust 1.97.1/LLVM toolchain, offline locked
`cargo check` and all-target `cargo clippy ... -- -D warnings` passed for the
native ARM64 Windows target across `aegis-webrtc`, `aegis-client`, `aegis-winctl`
and `aegis-quic-boring`, including client Chrome-like TLS/QUIC and WebRTC.
Earlier local setup attempts failed on target sysroot, `lib.exe` and Clippy
driver selection; their logs remain in the receipt. This is type/lint evidence:
no new guest method, signed kit, installer, service lifecycle, Wintun load or
route transition ran. Exact `dc2f89be5` hosted `windows-rust` ended
**FAILURE** at strict Clippy, the selected owned Poisson UDP positive and one
fresh TLS/UDP method in the 874/875 core suite; the terminal failure receipt (`evidence-archive/testing/2026-10-13/B04-current-cross-clippy-r1/hosted-dc2f-windows-failure-r1.md`)
preserves the distinct causes. Installed acceptance remains **NO-GO**.

The reviewed Poisson control source now uses v3 admission and exporter labels
with five authenticated timestamp samples; sender and receiver perform the
same fixed rounds, selecting the smallest valid uncertainty under the
unchanged 10,000 µs cap. A v2 peer cannot communicate with v3, so both peers
must update together. The bound assumes negligible relative monotonic-clock
drift through the later public start and supplies no drift proof. The isolated
source patch SHA-256 is
`146145a80b18d4b7c72e97d352964969c0ace8f223991b2a9e26bbde7d10efe5`;
Mac positive/negative checks and strict core Clippy passed, and independent
final review found no P1/P2. Windows CI now runs unchanged strict Clippy
immediately before the unchanged exact owned Poisson SDK UDP positive; both
precede Wintun/WFP activity as a host-load-order mitigation hypothesis. The
Poisson step retains its `!cancelled` guard, so Clippy failure does not hide
its verdict. Its selector and 10 ms cutoff are unchanged. Neither
change has run its Windows native method or exact final-commit hosted CI;
signed installed Windows acceptance remains **NO-GO**.

A separate native timer and cross-Clippy receipt (`evidence-archive/testing/2026-10-13/B04-windows-timer-order-r1/receipt.md`)
SHA-256 `8b6f371493b7a685caefec69a708f34152dd11bde7c50235550da1fba544299a`
records the exact **dc2f** fixed-seed SDK UDP method running twice in a
disposable Windows ARM64 guest: both passed, and the second captured
`RUN_EXIT=0`, 491/491 packets sent, zero retained and guest scratch cleanup.
The earlier hosted x64 dc2f run remains failed; the guest rerun neither tests
v3 nor proves that CI ordering caused the hosted delay. Current working-source
ARM64 Windows strict cross-Clippy also passed with `-D warnings` across
`aegis-core`, `aegis-webrtc`, `aegis-client`, `aegis-winctl` and
`aegis-quic-boring`, including the v3 source and selected Chrome-like TLS/QUIC
and WebRTC features. Two earlier tool setup attempts failed before linting;
the passing log SHA-256 is
`de29168aa6b20ae4819f9c89da5dfdb3e6828d627491190f4ebb0b4c21cf9f4e`.
The final combined workflow patch is retained beside the receipt, SHA-256
`feae98bf4bad5829c32cfad05a96d16c563ca7c964ae8b99277717450fdee243`.
Exact final-commit hosted CI and signed installed service acceptance remain
**NO-GO**.

If an outage outlasts the certificate and no successor receipt was committed,
the service stays blocked after the authority returns. Use the explicit
[operator recovery procedure](../../operations/windows-expired-device-recovery.md);
its verified reinstall deliberately disconnects protection and is not an
unattended, uninterrupted repair.

## Exact 79b5 hosted Windows timer result

[General CI attempt 1 in run 38406585333](https://github.com/example-org/aegis/actions/runs/38406585333) on commit `79b5d1b8613ccb6b3140b9cd28f323811a3a562a` finished **FAILURE**. `windows-rust` strict Clippy succeeded, while the unchanged exact owned Poisson SDK UDP positive refused after a 975100 ns requested wait took 18084500 ns: 17109400 ns wake overshoot and 13911942 ns point lateness exceeded the unchanged 10 ms limit. It accepted 491 packets, sent 237 and retained 254. The CI receipt (private evidence path `evidence-archive/testing/2026-10-13/CI-79b5-final-r1/receipt.md`) preserves raw-log hashes. An older dc2f ARM64 guest passed this method 2/2; it does not override the exact 79b5 hosted x64 failure. No Windows installed or B-04 positive acceptance follows. A second hosted attempt is pending its own terminal receipt.

The same-commit [Windows job attempt 2](https://github.com/example-org/aegis/actions/runs/38406585333/job/115339372275) (`115339372275`) finished terminal **SUCCESS** at 2026-10-13T14:41:43Z: 50 successful, 0 failed and 2 skipped steps. Strict Clippy, the unchanged exact SDK UDP Poisson 10 ms positive (1/1, 491/491 sent, zero retained), ACL/secret/transport, Poisson operators and private release kit succeeded. The separately frozen private receipt `evidence-archive/testing/2026-10-13/CI-79b5-final-attempt2-r1/receipt.md` has SHA-256 `129be39f46c31be5fabff0ebd0cb3ca1a1808305edd4a3cbab69e6d01e386ceb`; raw job log SHA-256 is `5940ff25e4fb91422181376f5521d9650b1f835af487b3d037c7e0b1114f30b2`. Attempt 1's timer refusal remains failed, and the overall general run remains **FAILURE** because the Rust guide test failed. The successful hosted x64 job is not installed B-04 timing acceptance.

A distinct exact-79b5 Windows ARM64 UTM guest run passed two source-bound native Poisson methods from hash-verified PE binaries: authenticated v3 TLS/UDP **1/1** with 734 accepted/sent packets and no retained packets, and the unchanged SDK UDP 10 ms positive **1/1** with 491/491 accepted/sent and no retained packets. The original 10,000,000 ns allowance was not relaxed. Build/setup and first result-pull failures, guest exit markers and cleanup are retained in private `evidence-archive/testing/2026-10-13/Windows-poisson-native-79b5-r1/receipt.md`, SHA-256 `477cabad8883c3b4a4a3b95651dcf68e682580010d1fa33cae93354c89a8e745`. These are selected loopback methods on Windows ARM64; hosted x64 attempt 1 remains a failed timer result, hosted x64 attempt 2 later finished **SUCCESS** as recorded above, and no installed B-04 acceptance follows.

## Exact fcfec6e hosted test refusal and test-only successor, 15 October

Required `windows-rust` job `116495676450` on pushed `fcfec6e` passed 877 core methods, then failed two Poisson fixture methods. One authenticated TLS/UDP positive refused `source_starvation` after 48 accepted/sent/received packets; the other `strict_failed_postwrite_keeps_known_send_prefix_and_never_reuses_sockets` refused `windows_timer_after_wait_cutoff` **before** the intended postwrite path when a requested 0.981 ms native wait took 22.416 ms. The unchanged 10 ms cutoff produced the safe refusal; it did not prove the test's postwrite claim. The exact terminal receipt (`evidence-archive/testing/2026-10-15/CI-fcfec6e-exact-r1/receipt.md`), SHA-256 `66cc295ff7f2cde9da6028eba3c604961e32878e689b12c46bc4dbc3523a0ddf`, retains the raw job log. Both exact-fcf failures remain failures, and this job is not a Windows PASS.

The reviewed postwrite fixture candidate (`evidence-archive/testing/2026-10-15/CI-fcfec6e-windows-postwrite-r1/canonical-addendum.md`) retries only that exact prewrite refusal on fresh sockets after verifying zero send, retained packet, joined actor, no delivery and consumed custody. It still requires the original real postwrite refusal and known delivered prefix, with no cutoff or product change; eight prewrite refusals fail. A selected macOS loopback run passed **1/1** after preserving shared-cache `E0514` and sandbox `EPERM` attempts. A separate TLS/UDP source fixture candidate (`evidence-archive/testing/2026-10-15/CI-fcfec6e-windows-fixture-r1/receipt.md`) passed four selected local macOS runs and independent review; its Windows execution is pending. Windows product work remains frozen. Exact successor `windows-rust` and signed installed B-04 acceptance are still **NO-GO**.

## 25 October 2026 — current full-wide installed batch preparation

The owner ordering prerequisite was met by package67 local18 and exact B-03
CI40170285734, all six jobs SUCCESS on `f5eb11283c05ddbb001c8e8cb56bd341cc506364`.
The previously licensed xwin0.10.0 SDK10.0.26100/CRT14.44.17.14 was restored
and its full tree SHA `cdd054f54d7784052bac93e6cf1326515c9862852c2c265d78c518896de5d702`
matched. From a clean detached f5 checkout outside the user Cargo ancestry,
the locked offline native ARM64 full-feature build completed in143.861s,
with Chrome-like TLS/QUIC. Client PE SHA `ff6cf46066fe2a9ada5371a17f26ddc51855feeb98f269dfc878b628d9206108`;
winctl PE SHA `3b416d533982e7977348361d5886c4c2fe7e5949a068c77fbc5bd66e820afce8`.
SDK/build receipts are under `evidence-archive/testing/2026-10-25/B04-fullwide-f5-r1/`;
executables and caches remain in private disposable storage outside evidence.

Both aliases of the owned Windows UTM bundle were freshly observed stopped.
Source-bound rollback templates and real disposable launchd recovery trials
precede installed changes. QA-only tool descendants retain the f5 PE producer
identity separately. Engineering kit trust may use the explicit independently
pinned manifest digest; it cannot grant publisher-signed release acceptance.
No new guest install, route/WFP, packet or lifecycle PASS is claimed here.

## 25 October 2026 — continuous full-wide QA and detached clock repair

The QA batch uses one immutable 3600-second VM window, a 3000-second work
cutoff and a 600-second disk/config restore reserve. Fixed producers cover
online enrollment and live relay policy adoption, native service/Wintun/WFP,
TCP/UDP/DNS over IPv4/IPv6, a scoped relay outage, service restart, guest reboot,
uninstall and stock readback. QEMU full-frame capture observes the Windows
virtio interface before NAT; Mac physical-frame attribution and final signed
B-04 acceptance remain open. The f5 PE producer and its hashes are unchanged.

The original Windows VM was never booted in the disposable rollback trials.
Trial949 exceeded its parent completion wait while the detached restore
continued. Trial90 exposed different process monotonic origins between
Homebrew Python3.14 and Xcode Python3.9; operator-triggered inverse restored
the disposable disk/config, with original disk/config hashes unchanged.
Both attempts remain failed. The source correction pins the resolved Python
path, SHA and version, requires3.10+, and verifies shared clocks across an
actual detached restart. Source42 passed24 offline tests; the first actual
read-only UTM launchd trial timed out while the Mac was locked, and retained
its failure. These observations do not qualify detached VM recovery.

The new batch also separates issuer/relay registries, requires live PolicyAck,
and checks relay-c expiry on relay-c while Mac deadlines use its pinned monotonic
clock. Independent relay/packet inverses and typed failure cleanup remain.
Source checkpoint and filtered custody precede all further QA; a real
detached recovery trial and installed execution are still required.

Actual source9df detached read-only/restart and disposable disk/config trials
then passed (inverse receipt SHA `ead5dc44ceb90e698c080aefd9a90dfc2e5c065fa2e4b3059646049b2d4507d4`).
The original VM remained stopped with unchanged disk/config hashes. The next
QA child binds actual private/public guest input transfer, exact precomputed
f5 kit bytes, one device identity through reboot/uninstall, and continuous
PCAP review from install intent to explicit uninstall intent. Stock traffic
is diagnostic; installed reboot still requires zero protected egress and
paired postboot traffic. Installed execution and final CI remain pending.


### 25 October 2026 — isolated relay startup repair before installed B04

The source2c97 fixture generation `2179a406f0f845d48803ffedbcbb5d40`
refused at `start private device policy status`: its immediate socket directory
was 0700; the product requires root:root 0750. Windows was not booted. The
failed unit and inverse were closed, stock firewall and original permanent relay
were checked unchanged, and fresh SSH ×2 passed on both sides of Stop. See
`evidence-archive/testing/2026-10-25/B04-fullwide-f5-r1/relay2179-failed-start-closed01.json`.

The reproducible QA repair keeps secrets below a 0700 generation root and gives
only a separate status directory 0750. It also journals exact unit launch intent
before systemd-run, waits boundedly for startup, and retires exact failed units.
A transient unit unloaded before the detached inverse is accepted as gone only
when its recorded PID/start-time pair is absent. Product checks remain strict;
product producer f5 and Linux fixture producer67 are unchanged. Offline
regressions and the installed retry are pending on the committed QA child.


### 25 October 2026 — real UTM setter and launch refusals retained

Two preboot attempts closed with exact disk/config restore and no installed
acceptance. The source81 diagnostic identified AppleScript `mode` as an UTM
property inside `tell`; c7 repairs it with a handler-local `updateMode`. Its
actual setter/readback then passed, but the first boot stopped before QGA with
an internal SPICE error and no PCAP. The full sourcec7 inverse and relay closure
passed; receipts `relayfix01-preboot-window-closed01.json`,
`relayfix02-preboot-window-closed01.json` and `relayfix03-boot-window-closed01.json`
are retained in B04-fullwide-f5-r1.

The directory-resource retry also failed before QGA and closed with exact stock
disk/config restoration. Disposable probes isolated the QEMU error as PCAP
`Operation not permitted`. The earlier resource hypothesis was incomplete:
UTM4.7.5 `parsedUserArguments` keeps only strings, discarding supplied file URLs;
configuration save also prunes unreferenced files from Data. An absolute App Group
path additionally splits at its space. The corrected QA actor creates one owned
0600 PCAP inode in the pinned QEMU App Group and passes a unique relative basename.
Probe08 (`c7ff39f8`) stayed started and wrote full Ethernet frames; its clone was
then stopped under the detached inverse. It is diagnostic, with zero installed
acceptance. Fifteen rollback tests (including repeated seal after retention) and
semantic negative checks pass; full installed execution and one final CI remain
pending. Receipt: `B04-fullwide-f5-r1/capture-startup-repair01.json`.

Primary implementation references: UTM v4.7.5
[`parsedUserArguments` and `socketURL`](https://github.com/utmapp/UTM/blob/v4.7.5/Configuration/UTMQemuConfiguration%2BArguments.swift),
[launch working directory](https://github.com/utmapp/UTM/blob/v4.7.5/Services/UTMQemuVirtualMachine.swift),
and [Data cleanup](https://github.com/utmapp/UTM/blob/v4.7.5/Configuration/UTMConfiguration.swift).


### 25 October 2026 — current B-04 preflight and old guest fixture closure

Typed QGA execution replaced `utmctl exec` returning false zero/empty marker
results. The stock ARM64 root volume uses the exact TrustedInstaller SID;
the narrow QA fix keeps ProgramData/stage protected owner/DACL and no-reparse
checks. OpenSSH FoD initially failed `0x8024402c`; numeric TCP returned
`WSAEACCES`. Inventory found old October 8 `AegisLive2026100891c3f37f` stopped
with automatic startup and persistent WFP protection. This guest image is not
a clean installation baseline.

Source `019b00e713555b240b52c450307b14a3798b3e7c` pins historical source,
manifest, installed client/winctl, receipt SHA, full SCM command, protected
paths and absent legacy route journal. Old `client doctor` proved ownership
before standard `client disconnect`: filters 16→0, exact service Stopped/Disabled,
and numeric direct TCP succeeded. Old files were preserved; the outer disk
inverse restores the original installation. The earlier PowerShell `$args`
wrapper refusal remains retained separately.

The subsequent FoD download exceeded the former PCAP size guard at
310,201,962 bytes (306,497 full frames), triggering rollback before any current
product installation. A kernel App Group rename wait delayed capture retention;
stock disk/config were ultimately restored and the failed current disk retained.
The successor restores stock before capture copying, keeps the original private
source inode and binds the distinct retained inode by full SHA. QEMU capture is
bounded at 1 GiB/one million frames; relay remains 128 MiB/250,000 frames and
all truncation, protected interval, nonce and leak checks remain in force.
The FoD successor uses one protected nonce-owned SYSTEM task, 480-second task
limit, 700-second phase and exact terminal retirement. Rollback 16/16, FoD
4/4 and full-frame/oversize/parser negative checks passed locally.

Secret-free milestone receipt:
`evidence-archive/testing/2026-10-25/B04-fullwide-f5-r1/preexisting-fixture-and-recovery01.json`.
PE producer remains `f5eb11283c05ddbb001c8e8cb56bd341cc506364`.
Current install/traffic/outage/restart/reboot/uninstall and final CI remain pending.


### 25 October 2026 — retained dependency refusals and detached access admission

There are still **zero accepted installed outcomes** in the current B-04 batch. The native ARM64 engineering PE producer remains `f5eb11283c05ddbb001c8e8cb56bd341cc506364`; the following changes concern QA and recovery. Failed receipts, disk images and raw captures remain in private execution storage, with hashes in `evidence-archive/testing/2026-10-25/B04-fullwide-f5-r1/`.

| Attempt | Actual observation and retained refusal |
| --- | --- |
| 08 | The private host source-custody JSON was 0644; admission refused before guest boot. |
| 09 | Cold UTM startup raised an AppKit failure before QGA; App Group/TCC access delayed its inverse. |
| 10 | An empty guest file pull returned host rc 0. Pull readiness now rejects that result and retries boundedly. |
| 11 | Microsoft OpenSSH FoD was still running at the former 480-second task limit. The exact task was retired and stock restored. |
| 12 | FoD completed; the 44 MB kit push exceeded its former 40-second transfer limit. |
| 13 | Kit stage passed in 106.8 seconds and FoD completed; SSH arm returned 1 before its receipt. Its terminal marker was unavailable before stop; the failed disk is BitLocker encrypted. The exact inner cause is unknown. |
| 14 | FoD was Installed, but Windows 11 supplied display name `OpenSSH SSH Server (sshd)` instead of the older pinned label. Admission refused. Post-restore hashing also exceeded a 60-second wrapper limit; the independent fallback completed. |
| 15 | Real QGA readiness and ancestor inventory succeeded; the nested boot reader returned 1 with stderr lost. The actual guest cause is unknown. UTM then retained `stopping` while QEMU remained alive. Exact UUID/disk/capture/process identity was checked before SIGTERM and a normal UTM restart; TCC delayed the detached inverse for approximately 27 minutes. |
| 16 | The strengthened detached file-open check caught another macOS AppData prompt before arming, capture changes or VM start. After the owner answered, the failed preparation was retired with stock unchanged; no armed or rolled-back window is invented. |

Attempts 08–15 have exact stock disk/config and actor closure. Attempt 14 closure SHA-256 is `bb0d20bb26587405a3084a1b68f0849303017d15a5774334890784e9771cb120`; attempt 15 closure is `d69e94ffae62f365a1471857db56f4475e8675c64916628590d0b131bd31bcb8`. Their secret-free summaries are OpenSSH label refusal (`evidence-archive/testing/2026-10-25/B04-fullwide-f5-r1/openssh-label14-closed01.json`), SHA-256 `b87037f86da2b0b02fafe2cba4dd44ddfeccb6b8c4046c16363bda60cbd8fa84`, and boot refusal closure (`evidence-archive/testing/2026-10-25/B04-fullwide-f5-r1/guest-boot15-closed01.json`), SHA-256 `c38d1c4846fb0e0ff48196ddc9d386ec72deb00dd6b3fd36e294f86163ebdb51`. The pre-arm 16 retirement summary (`evidence-archive/testing/2026-10-25/B04-fullwide-f5-r1/prearm16-retired01.json`), SHA-256 `9e9b74e6b2ce4cf0e7cd21ef426e83aaccc79cdffb95b2ec86fc7fb8ee522930`, binds its distinct retirement receipt `2195a8b13091331621580dca0aea5eea0f389a692b0036ef8bd953ca0fb3c2ad`.

A read-only stock probe found 36 program/package-scoped inbound TCP/Any-port Allows, all three firewall profiles enabled with default inbound Block, and no OpenSSH rule or host key. Source `e0f942908c1ce6bc003c80dad5574266b580e872` preserves these foreign rules. It binds the new default rule to a fresh same-window FoD proof, accepts the two observed Microsoft labels, and pins the actual label through SSH setup and inverse. Before `sshd` starts, the broad default rule is disabled and the exact executable receives a host-only Allow plus explicit complement Blocks for all other IPv4 and all IPv6 addresses. Block-override rules are refused. The independent guest inverse is registered first. Host keys are checked after first service start; the inverse stops the service before removing owned rules and restoring the pinned FoD rule. Label transport uses Base64 through the existing strict argument gate. See Microsoft's [OpenSSH first-use behavior](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse) and [firewall precedence](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules).

Source `e10f44f428f6cf38702dc63a9dbc592e7f255d34` adds bounded private boot diagnostics, a bounded `stopping` fallback that still requires actual `stopped`, and detached read-open proof for the exact config and disk before watcher readiness. Source `df1482e487293b4f5bd9f21f68f255227f6c4d8a` adds source-bound retirement of unchanged pre-arm cases and a bounded 300-second preparation wait for a system response; the immutable installed window remains 3600 seconds with 3000 seconds of work and 600 seconds reserved for restoration. Cleanup hashing has a 180-second wrapper bound. Root checks passed 13 at `f93ad64b`, 5 at `e0f94290`, 27 at `e10f44f4` and 6 at `df1482e4`; these overlapping checkpoint checks are not installed acceptance. PE bytes, full-frame captures, protected intervals, nonce checks and leak criteria are unchanged. Full installed traffic, outage, restart/reboot, uninstall and the single exact-final CI remain pending. Signing, physical and endurance gates remain open.


### 25 October 2026 — pre-arm coordination, terminal observation and capture capacity

Installed outcomes remain **0**. Product PE producer is still `f5eb11283c05ddbb001c8e8cb56bd341cc506364`; these changes concern the QA operators. All failed receipts and private execution files are preserved.

| Attempt | Actual observation | Evidence |
| --- | --- | --- |
| 17 | Relay freshness admission refused after the detached AppData wait; the guest never booted. The successor orders committed `vm_disk_rollback.py arm` and `arm-filter` before `relay/operate.py prepare/start/invite`, then fetch and plan admission; the 2700-second freshness gate is unchanged. | closed relay-budget refusal (`evidence-archive/testing/2026-10-25/B04-fullwide-f5-r1/relay-budget17-closed01.json`), SHA-256 `6efc206672096d7f751c0d1874b7e431b437d5633fd987e5e3c9f4ea90c9062c` |
| 18 | A review incorrectly equated the historical GUID-suffixed `Aegis-Live-...-v1` root with `C:\ProgramData\AEGIS-v1`. The claim was corrected; no root-mapping patch was applied. Preparation retired with stock unchanged and no VM/relay start. | independent correction (`evidence-archive/testing/2026-10-25/B04-fullwide-f5-r1/prearm18-corrected-review01.json`), SHA-256 `165fe442061c4436ee593acdf4a3fdb58b6f990bfb6241a7a419e6a5aa0f3159` |
| 19 | The physical AppData response arrived after the 300-second pre-arm wait. Preparation retired with stock unchanged and no VM/relay start. | pre-arm retirement (`evidence-archive/testing/2026-10-25/B04-fullwide-f5-r1/prearm19-retired01.json`), SHA-256 `4459bac015851e469a3565059b87d6f8911724834dd032c91c0111ef9e4dcb80` |
| 20 | Guest boot, old fixture closure and kit staging completed. Microsoft FoD returned SUCCESS/Installed at 15:13:45.714 UTC. Its subsequent read-only task inspection returned adapter 125; the exact nested cause was not retained and is unknown. No Aegis install intent occurred; disk/config, original relay and actor are closed. | closed FoD terminal refusal (`evidence-archive/testing/2026-10-25/B04-fullwide-f5-r1/openssh-terminal20-closed01.json`), SHA-256 `d58fc15d00a4b70a85f70ed94b645419977b0c4430c9838225172a5e31d7abd3` |

Source `4ae2bbc422be62f3b774db1d27cc5e51866955bc` extends only the pre-arm AppData preparation wait to 1800 seconds; three readiness checks passed (bounded wait checks (`evidence-archive/testing/2026-10-25/B04-fullwide-f5-r1/offline-prearm30m01.json`), SHA-256 `77935928aba40b05e8bce16e2eaff20ee713ba689e1522021541c34e268b9212`). Source `c267698baa0e60fdf626c390be06eee505a26948` gives fixed public task inspection up to 35 seconds and retries only read-only adapter failures within its existing terminal deadline. Positive proof still requires the exact task, typed `Ready`/result 0 and a timely response; guest errors and invalid metadata refuse. Eight regression checks passed (terminal observation checks (`evidence-archive/testing/2026-10-25/B04-fullwide-f5-r1/offline-sshterminal01.json`), SHA-256 `be4c885d5d270e8be778fa21f418b52bd74757e4aec83c6a8170b645df00e8bd`).

The retained attempt20 PCAP is 896,942,643 bytes / 868,575 frames. It showed that the prior 1 GiB/one-million-frame budget was insufficient for background Windows update traffic. Source `6d9bbaf1ed0b3f136cf2259d7779cd95da0d3e9c` uses a stable read-only mapped file, streaming hash and a single all-frame QEMU aggregation instead of a full-file byte copy and per-frame list. The finite full-wide limit is now 8 GiB/eight million frames; the older optional diagnostic inventory keeps its separate 1 GiB/one-million-frame limit. Live pressure reserves 30 GiB plus the growing capture and 1 GiB headroom; stopped retention requires the exact copy size plus 30 GiB and verifies the floor after copying. Every full-frame, timestamp, protected-interval, MAC, nonce and egress policy check remains required. The finalizer has a bounded 500-second step with at most 240 seconds per child, admitted before the earlier actor/relay work cutoff.

At `6d9bbaf1`, 27 focused tests plus the capture-budget and existing semantic negative scripts passed. A diagnostic scan of the actual stopped attempt20 file counted all 868,575 frames with 8,367 bytes of traced Python peak allocation in 12.940 seconds; its scope was deliberately outside all recorded frames, so it establishes no installed leak result. Evidence: streaming and copy-reserve checks (`evidence-archive/testing/2026-10-25/B04-fullwide-f5-r1/offline-packetcapacity01.json`), SHA-256 `0a5ec664612d9751e9f9fe1b6b8fe3b5444c887f0f8dc586b13b4e05ff80076e`. The installed window stays 3600 seconds, with 3000 seconds of work and 600 seconds for restoration. Full installation/traffic/outage/restart/reboot/uninstall and one exact-final CI remain pending; signed, physical, independent and endurance gates stay open.


### 25 October 2026 — exact SSH fence and early Windows provider check

The native Windows ARM64 engineering PE producer is unchanged at `f5eb11283c05ddbb001c8e8cb56bd341cc506364`. Installed acceptance remains **0**. Failed attempts and distinct pre-arm retirements are retained.

| Attempt | Actual outcome | Secret-free E04 receipt SHA-256 |
| --- | --- | --- |
| 21 | Physical AppData response missed the pre-arm deadline; unchanged stock retirement, no test window. | `prearm21-retired01.json`: `1664caa115398c1804e49e97d672053f17ca1fc13e93aab3099cc8de3ae401b8` |
| 22 | Kit/FoD/management passed; absent authorized keys produced null `Array.Copy` input before install. Stock/relay restored. | `fullwide22-terminal-summary01.json`: `2b21f7e56324354ec6bc44612a7f73b2186e21db7567f40a004cfa73f0e977c2` |
| 23 | Source gate rejected the temporary workflow change before plan/boot. Stock/relay restored. | `sourcegate23-closed01.json`: `5d66d12cc4588c98e333405bb88333b80c2024ffd0513d62b7c3b6bc1e1094f3` |
| 24 | Real PS5 absent/empty/nonempty byte assembly and restore fixture passed. SSH Block creation rejected its RemoteAddress array (`0x80070057`) before Aegis install. Stock/relay restored. | `firewall24-closed01.json`: `5eef76dd87cbacfa748d344ad76998db419d92154b65edf4105d5bb4ecbc373b` |

QA `d31b9d62` fixes byte assembly and pins QEMU backend `net0` to `queue=rx` guest egress, including foreign-MAC and otherwise unreviewed IP protocol refusal. Its 16 rollback, three streaming, two diagnostic tests and semantic negative script passed (`offline-egresskeys01.json`, SHA `2df17d008ceb3e609b70aa59d4ba699668d4ece87426c670bcab21e4da28fc84`). The added CI-only step was reverted by `b0be1186`; producer workflow identity and the source gate were preserved. QA `b89d32f3` executes the source-bound PS5 byte fixture in the protected guest and retains its transport; three diagnostics/source gate passed (`offline-psfixture01.json`, SHA `48fd702847a554bf39b2aa32264ff561e2b7a5a60c2bff72c3faf9d95059806e`).

Source `e07543b452c1bc5fa75e0f875cb3d4dc87e36491` / `f37ac7862fb123d010d0f2f62571cd7111721fc1` replaces all three rejected address tokens by 32 disjoint IPv4 CIDRs excluding only `192.168.64.1`, plus `::/1` and `8000::/1`. The exact source-address coverage regression and source gate passed (`offline-cidrpreflight02.json`, SHA `4b8ab729a4d0eb6767a7c8cc6c8bd8d697a5bdc70624ca8bbb1bdde391c1e73b`). This proves address-set equivalence, not Windows parser acceptance. The new early check uses one nonce-owned Disabled Block rule, checks exact typed readback, removes that rule and retains public provider diagnostics before starting FoD. ACL, management Allow, foreign rules and immutable 3600/3000/600 timing remain required. Actual Windows provider validation, full installed cycle and one exact-final CI remain pending. Signed, physical, independent and endurance gates remain open.


### 25 October 2026 — pre-arm response and provider representation

The Windows ARM64 engineering PE producer remains f5 and installed acceptance remains **0**. Attempts25 and27 were distinct unarmed preparations whose physical system responses arrived after the original 1800-second wait. Source-bound retirement confirmed unchanged stock and no VM, relay or plan; neither is a rolled-back installed window. E04 `prearm25-retired01.json` SHA `d3b099308c47e4390fe672411e2ff759698301d4950dc99ec7907e57e283d35c`; `prearm27-retired01.json` SHA `a13022a3f2f386d76011d3a1e555697b02d2ffc90e6159bb2c8e662d0bdbf440`.

Attempt26's early Windows check created and removed the Disabled Block rule. All34 requested and returned networks were equal by exact address set, but the provider returned IPv4 dotted masks and a bare /32 host. The strict textual comparison refused before FoD or install; stock disk/config and relay were restored. E04 `preflight26-closed01.json` SHA `cb73fcd405c458c28d1e7084c214df73a07fd99b16f8166011e5c210d3c64543`, actor closure `5128f857378369469928b7e28ebb876ffea12f5d7e2eaf2fa081826a38683d5d`. Source `1978bfeac015e8006d1c50012566ceb0b1d3a41e` changes only requested IPv4 literals to this observed form; two IPv6 halves and exact checks remain unchanged. Its source gate and exact-complement test passed: `offline-providerform01.json` SHA `0c58b5eff5f4e6a0a02a3beea0cc8e83a57d4098631d4525fe4501e7c574725f`.

Source `e57dffff3de9d9286d4d2b7f4821cfb65df8c241` bounds physical-response preparation at7200 seconds, before any test-window timestamps, and freshly rechecks capture-copy/30GiB reserve immediately before arm. Four readiness tests plus16 rollback tests passed, including a reserve drop while waiting that leaves the case prepared: `offline-prearm2h01.json` SHA `4cd66dcd47b89708d2fcfab48eec60bfccfd3bd80ca5fb5b4b132cbe5f56ef95`. The same-clock proof, stopped-VM checks and immutable3600/3000/600 test/work/restore window are unchanged. Full installed cycle and one exact-final CI remain pending; signed, physical, independent and endurance gates remain open.

### 26 October 2026 — service refusal and CLI argument preflight

Attempt 28 used Windows 11 ARM64 build 26200 / UTM 4.7.5, QA
`11bbe9fa7d193eed8573c2de7e17d08a2fcf2438`, and unchanged engineering PE
producer `f5eb11283c05ddbb001c8e8cb56bd341cc506364`. The AppData response
arrived within the two-hour preparation bound. The actual window started at
2026-10-26T00:30:32Z: 3000 seconds of work and 600 for restoration.

Real disabled firewall address preflight, kit staging, FoD, fresh SSH, online
Enroll, config rendering, policy publish/status and the installation command
passed. Service refused with nested Python rc=1. Its parent discarded stderr,
and no guest marker was retained before rollback: the exact guest cause is
unknown. Traffic, outage, restart, reboot and uninstall were not executed.
Stock disk/config, actor and relay were closed; this does not prove uninstall.

Terminal summary (`evidence-archive/testing/2026-10-25/B04-fullwide-f5-r1/fullwide28-terminal-summary01.json`)
SHA `8aa53365a77d52b6c4cf8d2fea62967e03a296415a1281be497179e68a040597`
binds closure SHA
`0bd2af56a7a1a67f267dadd6bffcb91be362c355a9437dda804c19bc6e3501a8`.
The retained 25,114,364-byte capture is diagnostic: no full capture seal or
eight-phase acceptance exists. Earlier failures and pre-arm retirements remain.

QA `aacb2c12638d8e9f94fd2b2532f808c281254232` fixes a separately reproduced
argument-binding defect: `Read-B04Guest.ps1` now uses `CliArguments` rather
than automatic `$Args`, including all six call sites. A pre-FoD fixture executes
the SHA-verified actual function with a synthetic CLI, checking four exact
argument arrays and nonzero-exit refusal. It will run on guest PowerShell 5
before the long system-component installation. Fixed public exit markers and
bounded nested service streams remain only in the private 0700 case/0600 files;
public receipts expose hashes, sizes and typed status. Acceptance and deadline
gates are unchanged.

Source custody SHA
`fc92ab7c5459bad39490f5328ddb6f81bb0af43bdafd80205e25f83b140d3041`
binds archive SHA
`69b60c1f59b1668f8cd0eeaa192b5d704ec788d1caa5086a429c2adcb800166f`.
Offline check (`evidence-archive/testing/2026-10-25/B04-fullwide-f5-r1/offline-jsoncli29a01.json`)
SHA `d414c09001caeed1c190348e5e88c6a6797e3d71a7345d43672f34ebcb74ab30`
records five diagnostic tests, source admission and the actual-function fixture
on official portable PowerShell 7.6.9. This is not PowerShell 5 execution or a
confirmed explanation of the lost guest error. The short-SHA custody and doc
precheck refusals are retained separately; neither changed host or guest state.

**Disposition:** zero complete installed cycles. One exact-final CI is pending.
Signed release, physical capture, independent cases and endurance remain open.

### 26 October 2026 — bounded physical response wait

Preparation 29 on `7a3eb5b5881cf691306a896c879e72ac9a238fba` exceeded its
7200-second owner-response bound. The system response arrived at about 07:53Z;
no arm, VM start, relay preparation or plan occurred. The exact watchdog was
unregistered after stock disk/config checks. Retirement summary (`evidence-archive/testing/2026-10-25/B04-fullwide-f5-r1/prearm29-retired01.json`)
SHA `878ea1a986629ea549d22278801f1eda9adeb1a428bdfb397a5d1f83719ee1a4`
binds retirement SHA
`5d80d866921f80592e55493c41627e347fbebe64e362c37e6fd6da469aafe658`.
This is an unarmed retirement, not a completed or rolled-back installed window.

QA `9f81adc319edfd6c18e442a48abca9a8a57ce29d` permits a finite 43200-second
preparation wait and explicitly refuses a marker arriving after that limit.
The actual 3600-second installed window still begins only after the unchanged
readiness PID/runtime/clock, stopped-VM and fresh Data reserve gates; 3000 seconds
of work and 600 of restoration remain. The driver uses a 43400-second arm cap
and a PID-bound 50400-second awake cap. This does not extend any installed run.

Offline receipt (`evidence-archive/testing/2026-10-25/B04-fullwide-f5-r1/offline-prearm12h30b01.json`)
SHA `e3d46f2cf99e35db3a9dfc8bc65f4cb91b1bcd901d7ef46c36c57fd5a55c69e1`
records five readiness and sixteen rollback tests, including simulated 8-hour
response, 12-hour expiry, late 13-hour marker and fresh reserve refusal. The
initial wrong-glob zero-test refusal remains separately retained. Source custody
SHA `c81498ae4e4e327dbc388f5388410a8f890d4c7f53adb75496864c91e2d06d91`
binds filtered archive SHA
`faa48a87c7295ccafb8f1c3926aa59711c3488d14837607a285e4de371e20867`.
No new installed acceptance or CI outcome follows from these offline checks.

### 26 October 2026 — SSH completion and Python permission

Attempt 30 used QA `1519a112b8464e8228fa83680b149ba20189daaf` and the unchanged
engineering PE producer `f5eb11283c05ddbb001c8e8cb56bd341cc506364`. Its actual
Windows PowerShell 5 fixture passed four exact CLI argument arrays and nonzero
refusal; kit, real firewall provider check and FoD also passed. During fresh SSH
preparation, the single arm command left `EXIT=0`, but its guest-exec adapter
returned 125. The exact adapter subtype was not retained. Installation and
traffic never began. Stock disk/config, actor, relay and owned locks were closed.

Terminal summary (`evidence-archive/testing/2026-10-25/B04-fullwide-f5-r1/fullwide30-terminal-summary01.json`)
SHA `6429b5b9f1077f54a49df4c78890c9ea42fd1d230275da95079f7b5e6fc7f320`
binds closure SHA
`ff696876ec7e6271b7ef478cc8e25aa678e5d36a04567557d3fd0e05c34ddc9e`.
Its 48,834,545-byte retained capture is diagnostic, without a full seal or
accepted eight-phase proof. Earlier refusals and distinct unarmed retirements
remain preserved.

QA `e0966ffc41f18125fdefef91743d38f0237b531b` adds an opt-in completion check
only for exact `Prepare-B04OpenSSH.ps1` arm bytes and a fresh protected-stage
nonce. If the one mutating exec returns adapter 125, a nonce-specific terminal
marker must contain exactly one `EXIT=0`; script hash-after and protected-stage
ACL/generation verification must also pass. The existing typed arm readback and
two independent SSH channels remain required. Other return codes, default callers,
missing/duplicate/nonzero markers, changed scripts or failed stage checks refuse.
The mutation is not replayed. Bounded private diagnostics now retain the exact
adapter failure class/reason and stream hashes; raw failure streams stay only
in the 0700 case as capped 0600 files. Time and leak-protection gates are unchanged.

Offline receipt (`evidence-archive/testing/2026-10-25/B04-fullwide-f5-r1/offline-adapter31a01.json`)
SHA `44d498b8386cf760dd086dab06b0e601dc20778ed750fe8c1f159f7fa32578b8`
records 14 tests plus source admission. Source custody SHA
`c12ea056d472827a44585e823c51fc8b3e03381966e90d615929db3cdba7614a`
binds filtered archive SHA
`822f53fa840fa7529bae6b4bc72f476515e8f2d88ada222cd733420c2d80c99e`.
This is offline QA evidence, not an installed-cycle PASS.

The owner explicitly requested persistent Python permission and completed macOS
Touch ID authentication. System Settings now shows Full Disk Access enabled for
`/opt/homebrew/Cellar/python@3.14/3.14.6/Frameworks/Python.framework/Versions/3.14/bin/python3.14`,
SHA `4f00ea2ad53d62437a6a3946b73c73614a97e8accdc5b96dc095ea1a0d9c6a56`.
A new detached launchd process opened the UTM config/disk read-only without a
prompt and its temporary job was removed. Permission observation (`evidence-archive/testing/2026-10-25/B04-fullwide-f5-r1/python-fda-detached-read01.json`)
SHA `07efaea6671445f695b49211cde75627bb85c474b8b7980026763b3d58b2cf40`
binds that probe to source `1519a112`; no direct TCC database edits or interpreter
changes were made. Full Disk Access has the broad file scope shown by macOS;
this operational permission does not change Windows network acceptance.

During FoD, only regenerable `target/debug/deps` was removed after checking that
no Cargo/rustc process was active and retaining source custody. Free space rose
32.2 to 42.2 GiB; VM/PCAP/evidence files stayed retained (cleanup receipt SHA
`dcfec9a3b93e1713ad68a5c2a4da6f453f941c222a8fd1fc64df45e35da84d15`).
A complete installed lifecycle and one terminal exact-final CI remain pending;
signed release, physical capture, independent cases and endurance remain open.


### 26 October 2026 — closed attempt 31 and session handoff

Attempt 31 used QA `f357fc83049801b7b3981306b996f02de0fd4849` and unchanged
engineering PE producer `f5eb11283c05ddbb001c8e8cb56bd341cc506364`.
The actual detached watchdog armed without a permission prompt after the owner
configured persistent Python access. Kit, actual Windows PS5 argument fixture,
FoD, firewall provider checks and two fresh SSH channels passed. The online
Enroll child then returned 1. Its parent lifecycle wrapper did not retain child
stderr, so the inner refusal is unknown; earlier QGA boot failures precede this
phase and do not establish a cause. No product install or traffic executed.

Terminal summary (`evidence-archive/testing/2026-10-25/B04-fullwide-f5-r1/fullwide31-terminal-summary01.json`)
SHA `b02aa7f82b45e22b6366abf085f78cadf211755c271401c9adf279729610f762`
binds stock disk/config restoration, closure SHA
`44b66ab3ace9ee2a45256852f8c6800764dd8b1dd7b8efacdbc6a7c4dcf770e1`
and complete actor cleanup. Relay inverse passed with two fresh SSH checks.
The 23,723,892-byte capture is diagnostic only, without a seal or accepted
phase proof. Attempts 30 and 31 are both closed; their original receipts remain.

At the owner's session handoff request, no new long operation was started.
The next source batch must retain capped private lifecycle child diagnostics
and terminal evidence before another unique full-cycle attempt; it must not
infer a relay or product cause from child code 1. Complete installed cycles
remain zero. B-04 source is unpushed and no final B-04 CI was dispatched.
The final lifecycle, exact-final CI, signed release, physical host, independent
cases and endurance remain open; no acceptance or timeout gate was relaxed.

### 26 October 2026 — installed packet fixture topology refusal

QA checkpoints `90ef594d`, `ee25efd9`, `db4b0741`, `e6d85eb3`, `da39997f` and `34d38610` added bounded private child/guest failure custody, exact source/admission/custody gating, outer-source admission and failure cleanup. All 88 local B-04 tests passed on `34d38610`; its filtered archive SHA is `baf088fb42eff56b994a973c111c8f05197850ff9d900a33b342cccbfbd0156a` and custody SHA is `7c5c65027a5806f8356b50bf66c6a1e004fb7cab2a550b69c3424cd56790a241`. The first archive filter attempt refused a tracked excluded `artifacts/` member and is retained separately; the corrected archive omits 6942 excluded entries at every depth and contains 2621 verified source members. Admission and rollback render for case 37 passed.

Attempts 32–37 have distinct receipts. Attempt 32 refused pre-arm on an import error. Attempt 33 reached online Enroll and failed during redemption. Attempt 34 refused before guest boot on stale source admission. Attempt 35 passed Enroll/install/service/routes/WFP but observer start refused because the independently observed outer source was absent from the fixture allowlist; its exact packet fixture was then stopped with two fresh SSH checks. Attempt 36 passed observer start and failed at `packet_six`; without private guest marker the exact cause remained unknown. Its automatic failure path sealed the observer, stopped the fixture and online relay, and restored stock. All failed receipts remain retained.

Attempt 37 used the same f5 engineering PE product and QA `34d386101f65db78dac83689ffa04bfe39f109c7`. It passed 21/36 steps through real online Enroll, live policy status, install, service, installed routes and WFP inventory, and observer start. The first TCP/IPv4 probe returned Windows `SocketException` at `EndConnect` with socket access denied. Its controlled fixture IPv4 is identical to the pinned online relay IPv4. Product source installs a native relay host route and WFP permits direct control only for pinned executable/endpoint tuples; this fixture port therefore cannot be used as a tunneled payload target. This is a source-and-receipt inference about the causal path; no accepted packet delivery is claimed. The unchanged WFP block is the safe outcome. The private marker SHA is `05a064f307ac0905af2d54b73fc1ebdf03966efaa0a56afdd172f16bd8b46a51`. Terminal summary (`evidence-archive/testing/2026-10-25/B04-fullwide-f5-r1/fullwide37-terminal-summary01.json`) SHA `29c1202c6924e0ad541c8cec4782aa5bcbdc11a40329d46193b98fc1e4f6a000` binds stock disk/config restoration, observer and fixture stop, online relay closure, actor cleanup and two fresh original-relay SSH checks.

The next source batch must place IPv4 and IPv6 controlled endpoints on a distinct existing test host, preserve independent rollback and source custody on each host, and bind inner traffic plus outer relay traffic to full-frame captures. It must fail closed if an endpoint aliases any pinned relay address. Then repeat one unique installed case without weakening WFP. Outage, restart, reboot, uninstall, exact-final CI, signed release, physical egress, independent runs and endurance remain open; complete installed cycles remain zero.

### 28 October 2026 — exact-source Windows cross-check

Branch `degree/b04-windows-20261028` starts from the latest B-04 base, `18f918e43b4f4aa569d68ca9594490e9a1cf9acb`. The historical 12 October Windows CI 32 strict Clippy diagnostics were fixed by `27a1bfa7`; its BIT-TRAPS agreement/FIFO test and redundant elapsed-tick wait were addressed by `27a1bfa7` and `08b51a49`. No new product code change was needed. A filtered 2,622-file source SHA-256 manifest excludes tracked `artifacts/`, `target/` and `.scratch-*` at every depth.

Local Rust 1.97.1 Windows GNU checks passed on that SHA: core strict Clippy; client/winctl default check and strict Clippy; full-feature core/client/winctl/QUIC check and strict Clippy with all targets and `-D warnings`. The full-feature C dependency cross build used Zig Windows headers and `AWS_LC_SYS_NO_ASM=1` because NASM was absent on this Mac. Separately, the exact in-memory BIT-TRAPS agreement/FIFO test passed 1/1 on macOS; its original allowance/no-wire refusal and the analogous NetShaper test passed 2/2. Local cross setup failures and successful logs, with hashes, are preserved in `~/.aegis-local/handoff/codex-b04-windows-20261028/receipt.md`.

This did not execute a Windows test binary or native 10 ms timing gate. No VM, installed cycle, CI, or push ran. B-04 remains NO-GO; the distinct controlled endpoint host, lifecycle, signed and physical gates remain open.

### 28 October 2026 — B-04 worktree-bound batch preparation

The 36-step `run_window.py` entrypoint and its 47 Python child/operator files previously used `/Users/developer/Documents/Projects/Aegis` as a fixed source root. That would admit or execute the canonical checkout instead of Codex's committed B-04 worktree. Source `3ba7ad05` makes each helper derive its repository root from its own file path; kit staging retains the explicitly canonical historical artifact path. A failing-first source-root regression rejected the old controller and all 47 old literals. On exact `3ba7ad05`, 90 offline B-04 tests, Python compileall and diff check passed. The filtered 2,624-file source manifest digest is `eebc439606e63f2f5a8630f9fcce1a3e6b98027c6b74f52baa021a0ce54842f2`; no executable was retained in evidence.

This fixes source selection for a later unique case; no VM or host changed. The one-command 36-step installed runner still needs an exact native Windows timing runner for BIT-TRAPS/NetShaper, plus a distinct controlled packet endpoint before an accepted 36-step cycle. These remain open and are not inferred from the 90 offline tests.

### 28 October 2026 — B-04 source repairs before native acceptance

Branch `degree/b04-worktree-batch-20261028` adds separate failing-first regressions and source fixes for reviewed Windows defects: inbound WFP receive/accept filtering (`21cbe018`); an acquired and released 1 ms timer resolution while BIT-TRAPS and NetShaper send (`672f73b7`); machine-private route journal writes in trusted system directories (`c1111f4f`); disabling SCM before an intentional disconnect (`346cd2db`); draining the old root's journal before version handoff (`0fa79a37`); and a fixed namespace, name-derived RFC 4122 v5 Wintun adapter GUID (`30c0df43`, with lock/test corrections through `bf544686`). The inbound permit is limited to the tunnel interface; the relay exception remains outbound. The test SSH port needs a separate QA-only WFP provider, not a product exception.

On exact source `bf544686331f416db275c2163a969d4b45efef53`, the filtered 2,631-file source manifest digest is `2948e986c901c6fdee208826e136faa223034a90d258c4b6d03be1866592f0df`. Windows GNU strict Clippy for core and winctl with all targets and `-D warnings` passed, as did 96/96 offline B-04 Python controls. Logs and manifest are retained under `/private/tmp/aegis-b04-batch-bf54-r1/`; the failing-first logs remain separately retained. These checks compiled Windows code but did not execute a Windows binary.

The route identity race still needs a per-install generation/ownership protocol with a durable owner record; a route matching by destination/gateway alone must not be deleted as if it were owned. Native ingress, SSH QA provider, actual 10 ms timing, signed recovery, complete installed 36-step lifecycle and exact-final CI remain open. The queue forbids starting a Windows VM until the explicit capacity signal; no VM or host changed in this source batch. B-04 remains NO-GO.
