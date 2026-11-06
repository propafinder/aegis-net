# Cloudflare-fronted operator guide

Current profile guidance, reconciled 2026-10-11. Cloudflare proxying supplies an
outer HTTPS path; it does not establish general DPI resistance or admission
through a destination-IP/domain allowlist. Historical provider acceptance below
belongs to the legacy shared-token profile. Device-enrolled delivery through a
real CDN still needs separate exact-candidate acceptance.

## Profile and trust boundaries

| Profile | TCP / UDP | Client outer trust | Authentication |
| --- | --- | --- | --- |
| Legacy shared-token, fronted | Explicit `grpc_stream`; optional UDP `grpc_datagram`. Direct MASQUE requires a separate opt-in origin leg. | Public edge certificate validated against system roots or an explicitly supplied edge CA bundle | Shared relay token; no inner device TLS |
| Device-enrolled, `inner_tls` | `grpc_stream` only; UDP disabled or `grpc_datagram` only | Explicit `outer-ca.pem` from the authenticated, pinned public device profile | Separate inner relay CA and individual device certificate; Rustls, disabled wire mimicry, no legacy fallback |

The current `https_ws` client offers `h2,http/1.1` and uses RFC 8441 Extended
CONNECT. The audited Cloudflare edge did not advertise that capability. Ordinary
HTTP/1.1 WebSocket support does not accept this client contour. Keep these
fronted profiles gRPC-only. Normal orange-cloud proxying does not carry direct
MASQUE/QUIC UDP, and `legacy_tls` is a direct framed stream rather than an HTTP
carrier.

The TLS connections are separate: client to edge, edge to origin, and (for
enrolled devices) client to the inner relay identity. Cloudflare Full (strict)
validates the origin certificate. A Cloudflare Origin CA certificate is not the
client's public-edge trust anchor. Enrolled `outer-ca.pem` must authenticate the
edge name; `inner-ca.pem` authenticates the inner relay, and `device-ca.pem`
authenticates the device issuer.

## Topology and zone settings

```text
client -> relay.example.com:443 (Cloudflare edge)
       -> origin VPS: <ORIGIN_IP>:443 -> aegis-server -> destination
```

Use operator-owned placeholder replacements. Keep DNS proxying enabled for each
client-facing authority, Full (strict), HTTP/2, and gRPC enabled. The origin
certificate must cover the authority Cloudflare uses. Multiple fronted names
provide endpoint choices; an adversary can block the operator's names or other
observable traffic features. A pool does not require blocking Cloudflare as a
whole.

## Install an exact origin package

Obtain the exact approved **private server distribution**, its signed manifest,
and an independently trusted bootstrap digest through the operator's trusted
channel. Public client releases do not contain the server package. Select the
host architecture explicitly when using a local manifest. From the verified
server distribution, for an x86_64 package staged at the example location:

```bash
sudo /private/operator/aegis-kit/install-server.sh \
  --release-base file:///private/operator/aegis-vEXACT \
  --bootstrap-sha256 '<INDEPENDENTLY_TRUSTED_BOOTSTRAP_SHA256>' \
  --listen 0.0.0.0:443 \
  --relay-address relay.example.com:443 \
  --server-name relay.example.com \
  --relay-transport-priority grpc_stream
```

`aegis-vEXACT` denotes one approved distribution directory, not a moving release
alias. This installer creates a legacy server; it does not configure device
enrollment. Configure exclusive inner TLS and device enrollment through
[inner TLS](operations/inner-tls-v1.md) and
[device enrollment](operations/device-enrollment-v1.md) for the enrolled profile.
Fresh installation generates a certificate signed by a local private CA. It
does not provision a Cloudflare-trusted origin certificate or configure the
zone's Full (strict) setting. Before distributing fronted access, obtain a
Cloudflare Origin CA certificate or other Cloudflare-trusted origin certificate
covering the configured authority, and its matching key, through the zone
operator's authenticated procedure. In a reviewed maintenance window, stop the
origin service and install that pair at the `cert` and `key` paths in the actual
server configuration. For the standard root installation these paths are
`/etc/aegis/server/certs/server.pem` and `server-key.pem`; preserve the installer's
`root:aegis` ownership, directory mode `0750` and file mode `0640`. Validate the
actual configuration before the authorized service restart, then verify the
edge-to-origin path with Full (strict) enabled. An origin trust failure can
produce Cloudflare 526; the installation command alone is not a working
Cloudflare deployment.

An upgrade without `--force` preserves existing certificate materials only when
`server.pem`, `server-key.pem` and `ca.pem` all exist. Keep the outer origin pair
separate from the enrolled inner relay/device CA materials. The installer also
attempts to issue a direct-access record using its generated materials; do not
distribute that record as fronted access. Retain and reconcile its issuance
receipt before generating the separate fronted record below.

Check the installed service and binary version using the normal private
operator diagnostics. A version string alone does not prove the selected
transport, certificate inventory, or acceptance of this exact candidate.

## Legacy fronted bundle delivery

`scripts/issue-fronted-bundle.sh` reads the configured **shared token**. It is a
legacy renderer and cannot enroll a device or authenticate to an exclusive
inner-TLS relay. The selected profile uses forced Cloudflare-fronted transport:
`grpc_stream`. Generate it without editing generated TOML. Use an exact reviewed
operator kit in an administrator-controlled location readable by the `aegis`
service user; the example `/opt/aegis-operator-kit-EXACT` must be replaced by that
kit's actual path. The installed config must be readable by the same service
user, and `/var/lib/aegis` must retain the installer's `aegis:aegis 0700` custody.
Choose a fresh unused `NEW` output for each attempt, and stop on any failure:

```bash
sudo -u aegis -g aegis bash /opt/aegis-operator-kit-EXACT/scripts/issue-fronted-bundle.sh \
  --config /etc/aegis/server/aegis-server.toml \
  --primary relay.example.com --failover r1.example.com \
  --out /var/lib/aegis/client-bundle-fronted-NEW.tar.gz \
  --server-bin /usr/local/bin/aegis-server \
  --transport-priority grpc_stream --issue-token --ttl-secs 3600
```

The helper and issuer now share the service UID: the archive is service-owned
`0600`, and the optional token step writes its private access record beside
`--out` as `client-bundle-fronted-NEW.tar.gz.access-url.txt`. It does not print
the record. Running this helper as root under the service-owned state directory
is refused by the private writer; root OS access does not relax its owner checks.
A separately root-packaged `0600` archive is also unreadable by a service-user
issuer. For an already prepared archive, first establish service-readable private
custody; then issue as the service user to a fresh service-owned output:

```bash
sudo -u aegis -g aegis /usr/local/bin/aegis-server \
  --config /etc/aegis/server/aegis-server.toml bundle-token issue \
  --bundle-path /var/lib/aegis/client-bundle-fronted-NEW.tar.gz \
  --url-output /var/lib/aegis/client-access-NEW.txt \
  --public-host relay.example.com --public-port 443 --ttl-secs 3600
```

Use one issuance path, not both. Token persistence precedes URL-file writing;
a failed write may already have committed the token. Preserve the failed
issuance files/store and inspect the result before retrying under a new name.

A root client installer cannot consume the service-owned record directly. On
the origin, transfer custody through the verified private reader/writer, using
a fresh root-owned directory. For the helper's adjacent record:

```bash
sudo install -d -o root -g root -m 0700 /etc/aegis/server/client-access-export-NEW
sudo -u aegis -g aegis /usr/local/bin/aegis-server installer-secret read-url \
  --path /var/lib/aegis/client-bundle-fronted-NEW.tar.gz.access-url.txt |
sudo /usr/local/bin/aegis-server installer-secret write-url-stdin \
  --output /etc/aegis/server/client-access-export-NEW/access-url.txt
```

For the alternative issuer command, use its `client-access-NEW.txt` as the
reader's path. The writer creates an owner-private `0600` record. Keep the
service-owned source if transfer fails or is uncertain; do not mint another
token merely to retry file transfer. Transfer the resulting root-owned record
through an authenticated private channel and install it on the client as
root-owned `0600` under a root-owned private directory. The example
`/root/aegis-access/client-access-NEW.txt` must already exist there. From an
independently verified exact client distribution whose signed freshness policy
is still valid, install with that record:

```bash
sudo /private/client/aegis-kit/bootstrap-install.sh client \
  --manifest-url file:///private/client/aegis-vEXACT/client-release.manifest.json \
  --bundle-url-file /root/aegis-access/client-access-NEW.txt --profile socks-only
```

For a local, operator-generated legacy bundle directory, the verified bundled
installer also supports:

```bash
sudo /private/client/aegis-kit/install.sh client \
  --bundle /private/client/client-bundle-fronted --profile socks-only
```

Use the matching ARM64 manifest/package on ARM64 hosts. Keep bundle credentials
out of command arguments, terminal output, journals, and Git. If a network cannot
reach the release distributor, stage the exact verified client package and
bundle locally; receiving a tarball through `/bundle` alone does not verify its
release authenticity.

## Device-enrolled fronted origin (source; not deployed)

The `[transport.fronted_origin]` relay mode admits only requests carrying a
CDN-injected origin key to inner device TLS and, optionally, forwards
enrollment and renewal to a loopback authority on the same public authority
and port ("variant B"). Direct origin hits, RFC 8441 and HTTP/1.1 receive the
decoy. The prepared, unexecuted deployment procedure with zone tool and
rollback is the
[fronted enrolled runbook](operations/cloudflare-fronted-enrolled-runbook.md);
the design and local evidence are in
[cloudflare-enrolled-design.md](transports/cloudflare-enrolled-design.md).
Real Cloudflare acceptance of this mode remains open.

## Device-enrolled delivery

Use the four public files `bundle.json`, `outer-ca.pem`, `inner-ca.pem`, and
`device-ca.pem`, pinned through an authenticated operator channel. The device
creates and retains its own private key. Use the applicable
[offline installation procedure](operations/offline-device-installation.md) or
[online enrollment procedure](operations/device-online-enrollment.md).
Do not use the legacy shared-token bundle issuer for this profile. Explicit ECH
is described in [public-profile-ech.md](transports/public-profile-ech.md); it
requires Rustls and adds no default routing or automatic discovery.

## Diagnostics and evidence

Missing, invalid, or consumed bundle credentials and unknown HTTP paths can
receive the process's web decoy status: **403, 404, or 410**. The old pre-v0.3.24
h2 bundle-dispatch failure is historical; a bare `/bundle` returning 404 does
not distinguish it from a healthy current relay. The configured bundle prefix
and a controlled redemption of a fresh valid credential distinguish routing
from authentication. Access records must remain in protected files, using the
verified installer for redemption. Do not put a token in a diagnostic command.

A successful TLS handshake/ALPN `h2` proves only the outer connection. A plain
GET to a tunnel path, including `/tunnel.v1.Channel/Connect` for enrolled gRPC,
is not an authenticated tunnel proof. The private HTTPS bridge instead uses
its explicitly provisioned path and admission credential.

| Symptom | Interpretation / next check |
| --- | --- |
| Cloudflare 526 / 525 | Inspect origin certificate trust or the edge-to-origin TLS handshake |
| Cloudflare 521 | Inspect origin service, firewall and edge-to-origin reachability |
| 403 / 404 / 410 from an unauthenticated request | Can be a normal decoy response; inspect the configured route and private authorized control |
| Forced `https_ws` Extended CONNECT rejection | Expected audited edge boundary; keep the fronted profile gRPC-only |
| gRPC establishment failure | Check zone gRPC, origin h2, selected profile trust/authentication and exact candidate |
| Egress still uses local host | Check the selected ingress and authenticated session events |

Runtime `relay_transport_selected` and `relay_session_succeeded` identify the
selected carrier; pair them with a controlled egress check. Diagnostic files
are private operational evidence. Current forensic settings may suppress the
JSONL sink, so its absence alone does not prove a failed tunnel.

The retained Cloudflare acceptance covers **legacy forced `grpc_stream`**.
The current RFC 8441 `https_ws` path is not accepted by the audited edge, and
MASQUE-through-orange-cloud is outside the claim. Historical receipts retain
their original build/date/profile scope:

- Provider constraints (archived: `docs/archive/checkpoints/fronted-provider-constraints-cloudflare.md`)
- Historical status (archived: `docs/archive/pre-0.3.49/STATUS.md`)
- Historical work log (archived: `docs/archive/checkpoints/WORKLOG.md`)

This reconciliation checks documentation, installer arguments and configuration
metadata. Protected gRPC implementation/native tests and real CDN acceptance
were not independently revalidated here.
