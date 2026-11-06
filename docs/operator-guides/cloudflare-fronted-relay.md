# Cloudflare-fronted relay runbook

Current profile guidance, reconciled 2026-10-11. Clients reach an operator-owned
hostname through the Cloudflare edge. Retained provider acceptance covers the
legacy shared-token forced gRPC contour. Device-enrolled real-CDN acceptance
requires separate evidence for the exact candidate. This topology does not
establish general DPI or allowlist resilience.

See the [operator guide](../cloudflare-fronted-operator-guide.md) for exact private
server delivery, bundle issuance, and verified client installation.

## Architecture and trust

```text
client -> relay.example.com:443 (proxied edge) -> <ORIGIN_IP>:443 -> destination
```

Legacy clients validate the edge certificate with system roots or an explicit
edge CA bundle and authenticate with a shared token. Device-enrolled clients
require the pinned public `outer-ca.pem`, Rustls, TCP `grpc_stream`, and separate
inner relay/device certificate trust. Enrolled UDP is disabled or `grpc_datagram`
only; MASQUE and legacy fallback are unavailable. Cloudflare Origin CA belongs
to the edge-to-origin Full (strict) connection; it is not client edge trust.

The audited RFC 8441 `https_ws` client offers `h2,http/1.1`; the edge rejected
Extended CONNECT. Normal Cloudflare WebSocket support does not accept this
contour. Fronted gRPC requires zone gRPC and HTTP/2-to-origin. Dated RC11/RC12
telemetry and promotion statements do not describe the current release gate.

## DNS and zone settings

| Record | Target | Proxy | Purpose |
| --- | --- | --- | --- |
| `relay.example.com` | `<ORIGIN_IP>` | Proxied | Primary client authority |
| `r1.example.com` | `<SECOND_ORIGIN_IP>` | Proxied | Explicit alternate authority |
| `origin.example.com` | `<ORIGIN_IP>` | DNS only | Optional private diagnostic route; exposes an origin address |

Set Full (strict), an origin certificate trusted by Cloudflare, HTTP/2, and
gRPC. Bypass cache for the configured bundle prefix. Endpoint pools provide
alternatives; the operator's names and visible traffic remain blockable.

## Legacy bundle delivery

This shared-token renderer does not create an enrolled profile. Use an exact
reviewed operator kit readable by the installed `aegis` service user. Keep
`/var/lib/aegis` service-owned and private (`aegis:aegis 0700`). The same service
UID must package the archive and issue its access record; root access does not
override the private writer's owner checks. Replace the example kit path and
choose a fresh unused `NEW` output for each attempt:

```bash
sudo -u aegis -g aegis bash /opt/aegis-operator-kit-EXACT/scripts/issue-fronted-bundle.sh \
  --config /etc/aegis/server/aegis-server.toml \
  --primary relay.example.com --failover r1.example.com \
  --out /var/lib/aegis/client-bundle-fronted-NEW.tar.gz \
  --server-bin /usr/local/bin/aegis-server \
  --transport-priority grpc_stream --issue-token --ttl-secs 3600
```

The issuer saves a service-owned private access record beside the archive.
Before a root client installation, use the primary guide's
[private custody transfer](../cloudflare-fronted-operator-guide.md#legacy-fronted-bundle-delivery)
to export that existing record as root-owned `0600` in a root-private directory,
then transfer it through an authenticated private channel. A root client cannot
consume the service-owned source record directly. An independently authenticated
exact bootstrap with a valid signed freshness policy can then use
`--bundle-url-file /root/aegis-access/client-access-NEW.txt` with an explicit
profile. A separately root-packaged `0600` archive cannot be read by a
service-user issuer without an explicit private custody handoff.

Token persistence precedes access-file writing. If issuance fails, preserve its
receipt and files and inspect whether a token already exists before retrying;
do not reissue merely to retry file transfer. The renderer does not automate
this root/service handoff.

Alternatively stage an exact verified client distribution and authenticated,
privately unpacked local bundle. The installer accepts
`--bundle /absolute/private/client-bundle`, a directory containing the bundle
files, not `--bundle` pointing to a tar archive. See the primary guide for the
complete privileged client command. A tarball delivered by the bundle endpoint
still needs release verification.
For enrolled devices use authenticated four-file public-profile delivery and
[device enrollment](../operations/device-enrollment-v1.md), with an explicit
outer CA and a device-owned private key.

## Troubleshooting

| Symptom | Meaning / next check |
| --- | --- |
| 526 | Inspect Cloudflare trust of the origin certificate |
| 525 | Inspect the edge-to-origin TLS handshake and cert/key pair |
| 521 | Inspect origin service, firewall, and reachability |
| Bare `/bundle` or unknown HTTP path gives 403 / 404 / 410 | Can be the normal process decoy; it does not diagnose h2 dispatch or version |
| Authorized fresh bundle redemption fails | Check configured prefix, credential lifetime/consumption and exact origin build through private operator diagnostics |
| gRPC establishment fails | Check zone gRPC, origin h2 and the selected profile's outer/inner authentication |
| Forced `https_ws` Extended CONNECT fails | Expected audited edge limitation; do not treat ordinary h1 WebSockets as a fallback |
| Egress remains local | Check ingress, selected carrier and authenticated-session evidence |

The enrolled gRPC path is fixed at `/tunnel.v1.Channel/Connect`; legacy paths
come from the explicitly accepted catalog. Neither a plain GET to a tunnel path
nor ALPN h2 alone proves authenticated session delivery.

Direct MASQUE/UDP is an explicit legacy origin connection, exposes source/origin
addresses, and conflicts with a guard accepting only Cloudflare ingress. Normal
orange-cloud proxying supplies no MASQUE leg. Protected gRPC bodies/native tests
were not independently revalidated during this documentation reconciliation.

See [transport profiles](protocols-and-transports.md),
[secret handling](secret-handling.md), and [release runbook](release-runbook.md).
