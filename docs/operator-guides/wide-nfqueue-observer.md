# NFQUEUE observation and enforcement (Linux source-only laboratory)

The source contains both the NFQUEUE observer and the enforce consumer. The old
"consumer not yet" scaffold description is superseded. This is a reviewed source
laboratory procedure: `setup-wide-linux-nfqueue.sh` remains absent from the public
client package. Current source includes it in the private operator bundle,
package-root and installer helper-copy paths; see
[private helper delivery](../operations/linux-nfqueue-packaging.md). Source
inclusion is not evidence of a built/signed package or a ready native consumer. A named
`full-wide-nfqueue` profile in the CLI does not prove that its queue layer was
installed. Use [public installation profiles](ubuntu-install-profiles.md) to
choose a package-supported profile.

## Two distinct modes

NFQUEUE is a packet observation/verdict layer, not a TCP relay. `full-wide-nfqueue`
uses the separate REDIRECT relay for IPv4 TCP. Its queue layer witnesses and
blocks generic UDP/QUIC and IPv6 according to the resolved policy; DNS preview
uses its separate listener.

| Mode | Helper selection | No consumer | Intended scope |
|---|---|---|---|
| Observe | `AEGIS_NFQ_MODE=observe` (default) | `--queue-bypass` permits traffic | Explicit packet-witness lab, fail-open |
| Enforce | `AEGIS_NFQ_MODE=enforce` | No bypass; queued traffic drops | Reviewed fail-closed policy lab |

Observation requires explicit diagnostics if detailed destination-bearing events
are needed; normal private event logging does not publish every packet's tuple.
Missing consumer, firewall prerequisites or helper must be recorded as failure,
not converted into a completed profile. The current installer can warn and retain
its separate REDIRECT/firewall policy when the optional NFQUEUE layer is absent.

## Before applying a queue

Use a disposable authorized Linux host, independent recovery access, supported
netfilter and an approved exact client binary with `--nfqueue-observe` and
`--nfqueue-enforce`. Review the selected checkout helper and prepare the exempt
client UID plus numeric relay endpoint exclusions before routing. Do not enqueue
the client's own relay leg. The helper supports `apply`, `teardown`, `status`,
`--queue-num=N`, `--dport=...` and `--dry-run`; it has no `--mode` flag.

A non-mutating rendering example, from the reviewed repository root:

```sh
AEGIS_NFQ_MODE=observe AEGIS_EXEMPT_UID=CLIENT_UID \
  bash scripts/setup-wide-linux-nfqueue.sh apply --queue-num=100 --dry-run
```

`CLIENT_UID` is a placeholder for a numeric UID. Enforce rendering instead sets
`AEGIS_NFQ_MODE=enforce`; TCP/UDP/IPv6 divert defaults differ by mode. Inspect the
actual rules and recovery plan before any privileged apply. For a source-profile
installation, the installer derives the queue consumer block flags from the
resolved UDP/DNS/IPv6 policy and invokes `aegis-client --nfqueue-observe QUEUE
--nfqueue-enforce`; a standalone witness is not that complete installation.

## Inspect and remove a source-lab queue

```sh
sudo bash scripts/setup-wide-linux-nfqueue.sh status --queue-num=100
sudo bash scripts/setup-wide-linux-nfqueue.sh teardown --queue-num=100
```

Stop only the consumer/service created by your lab and verify the owned firewall
chains, queue and networking after removal. The installed public profile's
normal disconnect is `/usr/local/lib/aegis/helpers/aegis-wide-disable.sh`;
low-level queue teardown is not a substitute for disarming an independent
full-wide/device deny guard.

## Evidence boundaries

Decoder and isolated helper fixtures do not establish installed queue behavior,
consumer readiness, packet capture, reboot/crash safety or restricted-network
acceptance. Retain failed attempts with distinct names. Earlier June scaffold
and later policy proofs are dated evidence; they do not certify a newly selected
package. The historical roadmap (archived: `docs/archive/pre-0.3.49/08-active-roadmap.md`) is
preserved planning history, not today's readiness ledger.

See [current Linux profiles](ubuntu-install-profiles.md), [full-wide TUN](full-wide-tun.md)
and [private diagnostics](../operations/private-diagnostics.md) for their separate
capture, release and destination-logging contracts.
