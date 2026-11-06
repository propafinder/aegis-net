# Operator guide: `full-wide-tun` (host-wide incl. IPv6)

> Current source contract: local-host IPv4/IPv6 TCP, DNS and UDP capture.
> Historical five-leg Linux and later CDN proofs are scoped to their dated
> candidates and legacy topology. Current enrolled/guard changes still require
> exact signed-package, native reboot/crash and restricted-network acceptance.

`full-wide-tun` combines IPv4 REDIRECT and IPv6 TUN+smoltcp capture. Its UDP
wire transport depends on the authenticated relay profile; "full-wide" does not
select direct MASQUE for an enrolled device or certify every installation.

## What it does

- **IPv4 TCP** — REDIRECT to the selected relay stream.
- **DNS** — local fake-IP A recovery; other record types use the configured UDP
  relay plan.
- **IPv6 TCP** — the TUN+smoltcp flow engine recovers original destinations. It
  installs AEGIS-owned split capture routes (`::/1` and `8000::/1`); current
  fronted/enrolled traffic uses `grpc_stream`. `https_ws` is eligible only in
  explicitly compatible legacy/direct profiles; the audited Cloudflare edge
  rejects the current RFC 8441 path.
- **IPv4/IPv6 UDP** — captured per flow and carried bidirectionally. Enrolled
  inner-TLS profiles use `grpc_datagram` (or refuse UDP when the profile disables
  it); direct MASQUE is unavailable with inner TLS. The capture-policy ID
  `masque_direct` does not mean that an enrolled packet uses MASQUE on the wire.
- **Legacy shared-token UDP** — an explicitly configured direct endpoint may
  use `["masque_derived", "grpc_datagram"]`, trying direct MASQUE before H2/TCP.
  With no direct endpoint the legacy plan can use `grpc_datagram` only. A direct
  leg exposes the origin and the client's peer relationship; a Cloudflare-only
  origin guard drops UDP `:443`, so it cannot serve that MASQUE leg. H2 fallback
  preserves datagram boundaries but inherits TCP head-of-line blocking.

Per-flow UDP session reuse and earlier carried traffic are dated evidence, not
universal QUIC/HTTP3, real-time performance or current fleet acceptance. See
[transport contracts](protocols-and-transports.md) and the exact candidate's
retained acceptance receipts.

Within the selected source capture policy, IPv6 traffic routes into the TUN
and a failed relay flow is dropped. Installed guard, reboot and crash-loop
behavior require the separate acceptance below. `aegis-tun0` is non-persistent, so on
process exit the kernel removes it and its capture routes automatically (a SIGKILL-safe
`ExecStopPost` drop-in is also installed).

The legacy installer now stages an independent `inet aegis_legacy_tun_guard` deny
policy before restarting the wide client. Its early boot unit precedes
`network-pre.target`; the supported root-OS network-manager units require it.
Stopping, restarting or exhausting the client's restart limit removes capture
but retains the IPv4/IPv6 output and forwarding drop policy. Native TCP, UDP and
DNS stay blocked. A current service cgroup can create relay sockets; capture
traffic can reach loopback and the IPv6 TUN. Incoming SSH replies on the
configured `AEGIS_WIDE_SSH_SAFE_PORTS` (default `22`) and narrow DHCP broadcast,
DHCPv6 multicast and IPv6 neighbour-discovery packets remain permitted.
SSH replies are admitted only on a connection whose client has sent a packet
since the guard loaded: that inbound packet marks the flow. A session that is
silent across the guard load, such as non-interactive automation without
keepalives, receives no output, exit status or close until its client sends
again. Arm over SSH with `ssh -o ServerAliveInterval=15` or an active session.
The device guard of enrolled profiles behaves the same way.

Legacy capture uses privileged local TCP/UDP ports `980/981`. The installer
checks that `net.ipv4.ip_unprivileged_port_start` protects those ports and that
the nft cgroup matcher can validate the actual client cgroup. It refuses to arm
the new policy when these checks fail. Modern enrolled device profiles retain
their separate device guard and existing port mapping.

These are source and isolated lifecycle-fixture guarantees. Kernel nft behavior,
installed systemd ordering, network-manager DHCP renewal, initramfs networking
and native reboot/crash-loop captures still require controlled Linux acceptance
before deployment. The guard begins in the root OS; it does not certify traffic
from an initramfs or a separate packet-socket networking stack.

## Install

Use the authenticated exact client package from [INSTALL](../../INSTALL.md).
Supply an already unpacked private bundle directory or owner-controlled URL record; there is no
numbered interactive mode menu.

```sh
# Legacy private bundle, fronted stream/datagram configuration supplied by operator:
sudo bash /trusted/install.sh client --profile full-wide-tun \
  --bundle-url-file /root/aegis-access/client-access-url.txt

# Legacy-only direct MASQUE preference, with explicitly reachable direct endpoint:
sudo bash /trusted/install.sh client --profile full-wide-tun \
  --bundle /root/aegis-access/client-bundle \
  --masque-server 192.0.2.10:443 --masque-ca /root/aegis-access/origin-ca.pem
```

`--bundle` accepts a directory, not a `.tar.gz` file. If the operator delivered
an archive, verify it and unpack it privately before selecting the directory
containing `aegis-client.toml` and `ca.pem`. URL-file acquisition performs its own
archive extraction. These paths must already exist with
[trusted custody](../operations/private-installer-inputs.md).
`192.0.2.10` is an example address, not a deployable relay. A root invocation
requires a root-owned mode-`0600` URL record with trusted private ancestors;
remote acquisition requires HTTPS and authenticated CA/SPKI trust.

For an enrolled device, use the v2 offline or v3/v4 online public profile
procedure instead: [offline enrollment](../operations/offline-device-installation.md)
and [online enrollment](../operations/device-online-enrollment.md). The trusted
public profile determines full-wide scope; do not add MASQUE/Geneva overrides.

The client runs as root (the TUN engine needs `CAP_NET_ADMIN` for `/dev/net/tun` + `ip` route
changes). The installer sets `[ingress.wide] ipv6_tun_carried = true`, applies the v4 REDIRECT
firewall with the IPv6 backstop exempting the tun (WAN-bound IPv6 is rejected, tun-bound IPv6 is
carried), and installs the teardown drop-in. With `--masque-server`/`--masque-ca` it also writes
`relay.masque_server` + `relay.masque_server_name` + `relay.masque_ca_cert` so the MASQUE/UDP leg
dials and validates the direct origin independently of the Cloudflare TCP authority.

An in-place legacy full-wide upgrade keeps the independent deny policy while
the installer replaces capture. To switch away from legacy `full-wide-tun` or
perform a destructive legacy reinstall while its guard is armed, first explicitly disconnect with
`sudo /usr/local/lib/aegis/helpers/aegis-wide-disable.sh`. The disconnect restores
the resolver and SOCKS configuration, verifies capture cleanup, durably disarms
the guard, removes its service dependencies and finally deletes its nft table.
A failed disconnect retains the block and recovery files. A console rescue can
run the same command; retain the installed client/helper and
`/var/lib/aegis-install/client/legacy-tun-guard.conf` until it succeeds. Running
the low-level helper's `teardown` or stopping the client releases capture only.
`sudo aegis-client profile switch --to <mode>` updates the root install metadata and prints privileged
enactment steps; it does not perform this disconnect or activate a new profile.
The wide-disable command disarms the **legacy** guard only. An enrolled device
retains `device-guard.conf` and `inet aegis_device_guard`; use its
[profile-specific recovery procedure](../operations/device-online-enrollment.md#installed-renewal-and-explicit-migration)
and preserve its helpers and ownership records until that procedure succeeds.

For a Cloudflare-fronted TCP bundle, keep `relay.transport_priority =
["grpc_stream"]`. Legacy shared-token clients write a separate
`relay.udp_transport_priority = ["masque_derived", "grpc_datagram"]` when a direct
`--masque-server` is configured. For that legacy profile this prevents the direct, origin-exposing
MASQUE path from becoming eligible for ordinary TCP sessions. A bundle may
carry `masque-ca.pem`; the installer detects it automatically, while an explicit
`--masque-ca` takes precedence. `masque_server_name` defaults to the host/IP from
`--masque-server` when the installer writes the config; `relay.server_name`
remains the Cloudflare hostname. If the field is omitted in a hand-written or
older config, the client preserves the backward-compatible `relay.server_name`.

## Verify

- `ip link show aegis-tun0` and `ip -6 route show | grep '::/1'` — capture is up.
- `ip -6 route get 2606:4700:4700::1111` — shows `dev aegis-tun0` (no native leak).
- `curl -6 https://[2606:4700:4700::1111]/` — carried through the relay.
- Retain private event codes and independent packet/egress observations. Detailed
  destination fields require explicit bounded diagnostics; normal logging omits them.
- The source lab entry `scripts/run-fullwide-tun-live-proof.sh` requires review,
  sole test ownership and authorized recovery. It is not a public installer or
  proof of current installed guard/reboot acceptance.

## Boundaries

- Cloudflare-fronted UDP fallback is `grpc_datagram`, not MASQUE. It preserves
  datagram boundaries but inherits TCP head-of-line blocking.
- Earlier signed legacy CDN datagram receipts are dated scoped evidence; the
  source is no longer accurately described as an "unreleased" fallback. They
  do not certify the enrolled profile or the intended restricted access network.
- A policy named per-session rotation follows drift epochs; it must not be
  interpreted as a fresh TLS fingerprint on every connection.
- Loop avoidance: IPv4-mapped IPv6 (`::ffff:0:0/96`, the relay's own leg to a v4 relay) is pinned
  to the native path so the capture never swallows the relay's egress.
- Single-host scope; throughput/soak and geo/ASN-diverse relays are follow-ups.


## Foreign policy and early-boot boundary (B-03-FINAL, qualification pending)

The four-chain inet guard covers normal IPv4/IPv6 OUTPUT and POSTROUTING.
Foreign policy admission refuses route/NAT/queue/packet mutation, legacy rules,
forwarding and detected TC/XDP/TCX/netkit attachments. UFW filtering accepts
cannot override the later guard DROP; a UFW DROP can prevent the functional
witness and therefore refuse access. Active UFW is intended for FullTun and
local OUTPUT Redirect; scoped LAN Redirect remains refused.

Residual channels remain outside this guarantee: AF_PACKET/raw L2 and XDP_TX;
undetected netpoll/netconsole; firmware networking before the kernel; root
moving a process into an exempt cgroup; deletion/flushing of guard during the
monitor event/poll gap; legacy or BPF/TCX changes during the poll window;
unlisted BPF types (including sockmap/sk_msg/cgroup/skb) and arbitrary kernel
modules; TC/BPF on other interfaces; a newly introduced redirect outside
netfilter; a console actor selecting an unverified boot image; and cloud-init
raw ephemeral DHCP if a future policy admits it. Detection of a bypass reports
`leak_possible` and revokes the client; it does not claim that retaining inet
DROP neutralizes a bypass outside netfilter. The target poll interval is1s;
its actual latency and event-loss behaviour require native qualification.

The explicit local-root initrd policy retains private recovery images outside
/boot and requires a new boot and the exact image nonce before grant. It does
not protect a pre-PID1 boot failure: installed testing requires an independent
hypervisor/console recovery path. Unknown storage/unlock/boot configurations
refuse admission. These new paths remain unqualified until the detailed B-03
register records exact source/package/boot/packet evidence.
