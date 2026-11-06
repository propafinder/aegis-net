# Explicit ECH in a pinned public device profile

Current profile guidance, reconciled 2026-10-11. `bundle.json` accepts an optional
`ech_config_list` string containing standard padded base64 of a public binary
ECHConfigList. This is an explicit request for real ECH rather than GREASE.
The decoded list is limited to 16 KiB and must contain a configuration usable
by Rustls HPKE. Null, empty, malformed and oversized inputs are rejected before
rendering or profile pinning.

The device bundle contains exactly `bundle.json`, `outer-ca.pem`, `inner-ca.pem`
and `device-ca.pem`. Its four-file profile digest includes the ECH bytes.
Changing them after preparation requires explicit profile migration; ordinary
rendering or renewal cannot replace the pin. Release signatures authenticate
software artifacts; profile pinning does not add a signature to an untrusted
operator profile.

Rendering copies public bytes into `relay.ech_config_list_base64`, mutually
exclusive with the `relay.ech_config_list` file setting. It creates no extra
file or caller-selected path. Absence does not enable ECH.

## Device-enrolled carrier

The data and online-enrollment carriers retain the required ECH request, use
Rustls, and pin the DNS outer server name. A relay pool must preserve that name.
The enrolled profile permits only `grpc_stream` for TCP and disabled UDP or
`grpc_datagram`; MASQUE is unavailable with inner TLS. The ordinary data path
is fixed at `/tunnel.v1.Channel/Connect`; a paired opt-in HTTPS bridge has its
explicitly provisioned path. Outer ECH does not replace the separate inner
relay CA, device issuer CA, or device authentication.

The retained channel contract requires accepted real ECH before H2 or inner
authentication traffic, without a cleartext/GREASE downgrade. Protected gRPC
implementation/native tests were not independently revalidated by this
documentation reconciliation. Enrolled installed-client and real-CDN acceptance
remain separate from a parser/configuration contract.

## Explicit legacy MASQUE scope

A separately configured **legacy shared-token** profile may require real ECH
for direct MASQUE/QUIC. It also requires Rustls and the same pinned DNS authority;
TLS 1.3 with resumption and 0-RTT disabled precedes HTTP/3 and CONNECT credentials.
A failed real ECH request cannot be cleared by a compatible-carrier retry or
replaced by GREASE. This is a direct origin leg, not MASQUE through an orange-cloud
proxy, and is not part of the enrolled public-device profile. The AWS-LC client
backend supplies ECH GREASE, not this real-ECH path.

The operator distributes public ECH bytes through an authenticated trusted
process. This option adds no DNS discovery, DNSSEC verification, refresh timer,
automatic deployment or default change. Structural parser acceptance does not
prove deployed ECH acceptance, DPI resistance, or IP/domain allowlist admission.

## Rotation through authenticated retry configs (source, 2 November 2026)

A pinned list fixes the ECH `public_name`. When a CDN edge no longer holds the
pinned key, it rejects ECH after authenticating the outer handshake for that
public name under the profile's explicit outer CA and returns
`retry_configs` (RFC 9849 section 6.1.6). The enrolled carrier admits them
only if every config keeps a pinned public name and one is usable, caches
them in memory for the same outer authority and pin (at most 6 hours), and
redials exactly once; a second rejection fails closed and clears them. A
rejected handshake carries no H2 preface, identity, invitation or target. The
operator command `aegis-client device ech-from-https-record` extracts a list
from one DNS HTTPS record for pinning; the device itself still performs no DNS
discovery. Design and local evidence:
[cloudflare-enrolled-design.md](cloudflare-enrolled-design.md). No deployed
Cloudflare ECH acceptance exists.
