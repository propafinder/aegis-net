# Private HTTPS bridge

This opt-in native Rust carrier serves a public page and admitted HTTP/2 streams
on the same TLS listener. It requires no Cloudflare account or CDN proxy.
It retains the existing inner device TLS protocol, authorization leases, TCP
target policy, fixed-target UDP framing and live policy acknowledgements.
The separate enrollment authority retains its own issuer, challenges and
idempotent receipt recovery; an admission key alone cannot enroll a device or
open an egress target.

This is an Aegis HTTPS/H2 carrier, not an implementation of Tor WebTunnel or
HTTPT. It does not reproduce a browser's TLS fingerprint. Endpoint IPs remain
visible, and neither ordinary HTTPS nor a website guarantees admission through
an IP allowlist. Real target-network effectiveness and installed release
acceptance require their own evidence.

## Local device custody

Provision an owner-readable-only `https-bridge.toml` in the **final existing
device identity directory**, alongside the device journal, **after** device
preparation has finished. The identity store rejects extra files during its
initial setup. Provision its key in
a separate protected regular file, outside the public bundle and configuration
snapshot directories. The key contains exactly 64 lowercase hexadecimal
characters representing 32 independently random bytes, optionally followed by
one newline. Do not reuse a device key, invitation, issuer key or legacy token.
Unix files require owner-only permissions; Windows requires the private ACL
enforced by the existing secret reader. Symlink/reparse credentials are refused.

Example sidecar (the paths and names are operator inputs):

```toml
authority = "bridge.example.org"
path = "/private/stream"
enrollment_path = "/private/enroll"
credential_file = "/var/lib/aegis-device/bridge-admission.key"
```

The public device bundle still has exactly four members and contains no key or
sidecar. A v4 `carrier_program.bridge` declaration signs the public authority,
traffic path and enrollment path; it contains no credential path or key. Public
profile inspection and its digest include this declaration but never serialize
the private overlay. Native bundle rendering and online redeem/renew load the same sidecar;
managed runtime checks that the rendered traffic policy still equals it before
network access or readiness. Invalid or inaccessible sidecars cannot mean
"bridge disabled". Pre-enrollment `--validate-only` with a not-yet-existing
identity directory validates the signed bridge contract without reading a
credential or writing a config. Provision the actual sidecar before enrollment
to require a bridge at that stage.

Re-rendering an existing identity preserves its overlay; changing or removing
it is an explicit private operator policy change requiring a matching render.
The current integration does not distribute admission credentials, migrate
public profile schemas or accept secrets as command-line arguments. Operators
must provision both protected files before an actual bridge installation.

## Relay configuration

Use a valid outer TLS certificate for `bridge.example.org` and pin its issuer
in the public bundle's outer CA. Inner device trust remains separate. Every
`own_https_bridge` endpoint in the signed route program must use this one
authority; direct/fronted H2 pins can have their own TLS names and receive no
bridge admission key. If the enrollment authority uses the bridge sidecar,
its public outer name must equal the bridge authority. Cross-authority
credential reuse is rejected before dial; per-authority bridge credentials
and automatic discovery are outside this version.

Add this to an already valid exclusive inner TLS relay configuration:

```toml
auth_token = ""
fallback = "close"

[transport]
quic_required = false

[transport.https_bridge]
site_html = "<!doctype html><html lang=\"en\"><title>Status</title><p>Service available.</p></html>"

[transport.https_bridge.carrier]
authority = "bridge.example.org"
path = "/private/stream"
enrollment_path = "/private/enroll"
credential_file = "/var/lib/aegis-relay/bridge-admission.key"
```

Keep the existing `[transport.inner_tls]` device registry, certificate and key.
Remove legacy tokens and explicit QUIC listeners; the old bundle endpoint must
be disabled or moved to a separate distribution listener. Configuration rejects
proxy fallback and missing inner TLS. Bridge startup loads its private admission
key before binding. Combined and standalone QUIC entry points do not open UDP
ingress in bridge mode.

The enrollment authority is a separate process/listener with its own private
issuer state, not a relay route. Its optional `[https_bridge]` and
`[https_bridge.carrier]` tables have the same fields. Its public pinned
`authority_server` must reach that listener, with a certificate for the same
outer authority. The relay admits only `path`; the authority admits only
`enrollment_path`. Do not copy the issuer key to a relay to combine these roles.

## Admission and resource contract

Only a POST with exact HTTPS authority, exact role path without query, exactly
one gRPC content type and exactly one valid private header reaches the existing
inner handshake. The client marks the header sensitive to prevent HPACK dynamic
indexing and emits it after explicit outer certificate verification. Ordinary
root GET/HEAD serves the configured public HTML over HTTP/1.1 and H2. Other
complete requests receive a common 404, including the old fixed secure route,
WebSocket, bundle paths and the other role's route. HTTP/1 cannot open a tunnel.

Public HTML is explicit inline content limited to 64 KiB; no arbitrary file
serving or forwarding occurs. HTTP headers are limited to 8 KiB. The relay
bounds H2 admission and idle public connections; the authority retains its
existing connection and issuance deadlines. Inner traffic uses the established
idle deadlines, flow-control bounds and owned cancellation tasks.

The relay's five-second public-connection deadline is fixed; site requests do
not extend it. A response requested near expiry can therefore be interrupted.
Only successfully authenticated device leases suspend or renew that deadline.
Public response writes also have a finite five-second flow-control deadline;
a reader that never opens its receive window is closed without reporting a
completed response. Bridge custody fails closed outside Unix/Windows.

Local policy/key errors and outer certificate failures are terminal. Existing
pool retry remains restricted to failures before inner identity authentication;
application TCP/UDP is not replayed after an ambiguous write. Enrollment receipt
recovery remains the separate existing same-request protocol.

## Manual installed-client preparation

The following commands are templates with operator-supplied paths and device
IDs. Verify the exact candidate and four-member public bundle first. Keep any
invitation in a protected file; never put its contents in an argument. Finish
identity preparation before provisioning the sidecar. Directory or key-file
existence alone does not establish the `prepared` phase.

### Linux

As root, prepare and pin the final persistent identity before invoking the
online installer:

```sh
<candidate>/bin/aegis-client device prepare --device-id <id> --identity-dir /var/lib/aegis-identity/client --device-ca <public>/device-ca.pem
<candidate>/bin/aegis-client device bundle-inspect --bundle-dir <public> --identity-dir /var/lib/aegis-identity/client --json
```

Provision the sidecar in that prepared identity and the separate credential
under an operator-managed directory such as `/var/lib/aegis-bridge`. Use root
ownership, private containing directories and file mode `0600`. Keep both
outside `/etc/aegis/client`, `/var/lib/aegis-client`, install-state purge roots
and public bundles. The systemd service must be able to read their final paths.

Then use the existing local-bundle installer:

```sh
sudo bash <candidate>/install.sh client --bundle <public> --device-id <id> --identity-dir /var/lib/aegis-identity/client --device-invitation-file <protected-invitation>
```

The saved bundle pin selects local recovery, preserving the prepared identity
and overlay before initial redeem. A fresh online install has no pause for
bridge provisioning. An already ready identity or saved request resumes without
an invitation-file argument; ambiguous request recovery must retain the original
request and key. Existing configuration requires the installer's explicit
force/reinstall choice. Standard online systemd paths remain required. Do not
enroll from an unbound shell while an existing device guard is armed.

### Windows

Use the native machine-identity path from elevated PowerShell:

```powershell
C:\AEGIS-kit\aegis-client.exe device prepare-system --device-id <id> --identity-dir C:\ProgramData\AEGIS-Identity\device --device-ca <public>\device-ca.pem
C:\AEGIS-kit\aegis-client.exe device bundle-inspect --identity-dir C:\ProgramData\AEGIS-Identity\device --bundle-dir <public> --json
```

After the prepared phase, provision the sidecar and a separate credential in
machine-controlled directories. Protect ancestry before writing bytes. The
owner must be SYSTEM or Administrators, with a protected DACL granting only
SYSTEM and Administrators; LocalSystem needs access. Ordinary elevated-user
creation or a current-user metadata write does not establish service custody.
Do not widen permissions to Users, Everyone or LocalService to fix a refusal.

Use native `device redeem` with the protected invitation file, or resume its
retained request without that argument. Stage `outer-ca.pem` as `ca.pem` and
`inner-ca.pem` in a protected configuration directory, then run `device
bundle-render` with the final identity, public bundle, configuration directory
and a fresh private output path. Existing render outputs are never overwritten.

Install that configuration through direct winctl, supplying an independently
authenticated manifest digest:

```powershell
C:\AEGIS-kit\aegis-winctl.exe client install --package C:\AEGIS-kit --manifest-sha256 <independent-sha256> --config <new-private-toml> --device-online-bundle <public> --root C:\ProgramData\AEGIS-v1 --service --start
```

Managed online installation requires the full LocalSystem tunnel and an unused
version root/service. It retains the external identity and copies only public
bundle members. The convenience `install-windows-client.ps1` wrapper has no
managed-online parameter; `client prepare-config` follows the offline identity
copy path. Use the native sequence above. Production Authenticode and installed
service/reboot acceptance remain separate requirements.

## Validation and rollout

Source regressions cover the private overlay, native client carrier, website
responses, hidden legacy routes, inner identity enforcement, UDP, policy ACK,
enrollment proof and receipt recovery. Local loopback/memory-carrier results and
CI are source evidence. They do not accept real commercial/state DPI,
independent packet capture, production Windows signing, installed lifecycle,
24-hour durability or human approval of the exact release.

Before live rollout, complete exact-commit CI, privately build and verify the
candidate, provision independent credential custody, prepare an independent
bounded rollback, and establish fresh capture readiness where required. Keep
the accepted deployed ingress until the exact new candidate is operationally
accepted. This change does not itself deploy a bridge or change beta gates.


The 2026-10-11 documentation reconciliation retained these source/evidence
boundaries without independently inspecting or rerunning protected gRPC bodies,
native tests or Audit15. Historical local/CI claims above remain scoped to
their recorded candidates and do not supply a new acceptance result.
