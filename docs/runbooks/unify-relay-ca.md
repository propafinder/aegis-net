# DO NOT RUN — kept as a record of a wrong conclusion

This runbook proposed unifying the relay CA across the fleet. **Running it
breaks production.** It is kept because the reasoning error is worth seeing.

## What it got wrong

In the recorded August 2026 topology, direct relays and fronted origins used
different trust chains. This is dated incident context, not a current fleet
inventory. The conclusion that the fronted origins "serve nobody" and need
reissuing was wrong. Actual endpoint and egress identities are redacted in this
summary; example addresses/domains below are illustrative substitutions. The
original private incident evidence remains unchanged.

Those hosts were **Cloudflare-fronted origins**. They serve a Cloudflare Origin
CA certificate, which is what the edge validates, and they carry an
`aegis_origin_guard` nftables table admitting new connections on 443 only from
Cloudflare address ranges. Direct access is refused **by design**, including
from the host itself, which is why `connect()` to `127.0.0.1:443` times out
while the socket is listening.

They do not need the direct client's CA, because no client reaches them
directly. The fronted client validates Cloudflare; Cloudflare validates the
Origin certificate. A Cloudflare-only origin guard drops UDP `:443`, so direct
MASQUE requires a separately reachable, explicitly authorized endpoint and
exposes its client peer; it is not covered by fronted-TCP origin hiding.

## What running it did

Replacing the Origin certificates left Cloudflare unable to validate the
origins. The two private fronted authorities (represented here by
`relay-a.example.org` and `relay-b.example.org`) went from 404 — the decoy
answering correctly through the edge — to **526**, Cloudflare's
invalid-origin-certificate error. Restored from the backups the change itself
had written.

## What to do instead

Preserve each selected topology's trust chain. These examples represent the
recorded legacy paths; they do not identify deployable or measured endpoints:

- direct relay A: `192.0.2.10` — client pins the AEGIS Relay CA
- direct relay B: `192.0.2.20` — client pins the AEGIS Relay CA
- fronted authorities: `relay-a.example.org`, `relay-b.example.org` — legacy
  public edge trust, no direct-origin pin

The private 12 August 2026 receipt recorded 3/3 successful requests through its
actual fronted authority without a direct-origin `ca_cert`. The authority and
egress address are redacted here. An illustrative configuration would use
`server = relay-a.example.org:443` and `server_name = relay-a.example.org`;
an illustrative egress transcript would use `ip=198.51.100.30`. These
replacement spellings were not the measured authority or egress.

## The lesson

A host that cannot be reached the way you expect is not evidence that it is
broken. The `aegis_origin_guard` table appeared in an `nft list tables` output
before any of this and went unread; reading it would have ended the
investigation immediately and prevented the outage.
