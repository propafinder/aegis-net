# TPROXY gateway topology — operator warning and safe deployment patterns

**Status:** operator-side deployment guidance.
**Scope:** `mode=tproxy` (wide TPROXY gateway) on Linux/Ubuntu.
**Closes:** the operational gap flagged in
`evidence-archive/live/2026-05-19/full-ubuntu-acceptance/summary.md` and
`evidence-archive/live/2026-05-19/tproxy-forwarded-kernel-investigation/`.

## TL;DR

Do **not** run `aegis-wide-enable.sh --mode=tproxy` on a host whose external
NIC has a publicly routable IP address that accepts unsolicited inbound TCP.
The TPROXY PREROUTING hook will redirect that scan traffic into your AEGIS
relay path, which:

1. Pollutes your relay event stream with attacker-driven sessions.
2. Wastes relay credit on traffic that was never yours.
3. In the worst case, can be used to relay-amplify scanners against
   third parties.

Use one of the safe topologies below instead.

## Why mixed-role TPROXY is unsafe

`mode=tproxy` installs `iptables -t mangle -A AEGIS_WIDE_TPROXY -i <iface> -p tcp -j TPROXY` on PREROUTING.

On a publicly-reachable host the public interface (`eth0`, `ens3`, etc.)
constantly receives unsolicited TCP packets:

- :22 SSH brute-force scanners
- :445 SMB worm scans
- :23 telnet scans
- :3389 RDP scans
- Random opportunistic recon

Every one of those SYNs is matched by the TPROXY rule and handed to the
AEGIS wide listener. The listener cannot tell scan traffic from genuine
forwarded traffic — it sees a TCP connection arriving on a transparent
socket and opens a relay session.

**Observed in the 2026-05-19 acceptance drill on a private Ubuntu VPS
(its actual public address is redacted here):** 66 `relay_session_started`
events in a 10-minute window targeted that host's own public IP after external
scans; 0 events had the intended test target. The forwarded path was dominated
by scan-noise relay sessions. An illustrative transcript would use
`target=192.0.2.10`; that reserved documentation address is a replacement for
the private endpoint, not the address on which the measurement ran. The dated
private evidence remains unchanged.

## Safe deployment patterns

### Pattern A — dedicated `--interface=` on a tunnel device (RECOMMENDED)

This is the pattern used by `scripts/aegis-gre-gateway-setup.sh` for the
two-VPS GRE recipe, and it works for any tunnel device (GRE, WireGuard,
VXLAN, etc.).

```
# Set up a tunnel device that ONLY carries forwarded traffic from your
# downstream client(s) — never raw external scan traffic.
ip link add aegis-gre0 type gre local 10.0.0.1 remote 10.0.0.2 ...
ip addr add 10.255.0.1/30 dev aegis-gre0
ip link set aegis-gre0 up

# Apply TPROXY ONLY to the tunnel device.
sudo bash scripts/aegis-wide-enable.sh \
    --mode=tproxy \
    --interface=aegis-gre0 \
    --dns=off \
    --ipv6=block
```

`--interface=aegis-gre0` attaches `AEGIS_WIDE_TPROXY` to PREROUTING on
the tunnel only. The public NIC remains untouched; scan traffic on
`eth0` is not seen by AEGIS.

### Pattern B — RFC1918 internal interface only

Operator has a LAN-side NIC (`eth1`, `lan0`, …) on `10.0.0.0/8`,
`172.16.0.0/12`, or `192.168.0.0/16` and downstream clients use it as
their default gateway.

```
sudo bash scripts/aegis-wide-enable.sh \
    --mode=tproxy \
    --interface=eth1 \
    --dns=off \
    --ipv6=block
```

The public NIC is excluded. External scans cannot enter the AEGIS path.

### Pattern C — local-only redirect (no gateway role)

Single host wants its own outbound captured but does **not** forward for
downstream clients.

```
sudo bash scripts/aegis-wide-enable.sh \
    --mode=redirect \
    --dns=off \
    --ipv6=block
```

`mode=redirect` uses OUTPUT-chain `nat REDIRECT`, which only matches
locally-originated traffic. Scan-driven inbound SYNs are not affected.
This is the safe default for a workstation or single-VPS client.

## Unsafe pattern — DO NOT USE

```
# DO NOT:
sudo bash scripts/aegis-wide-enable.sh \
    --mode=tproxy
    # no --interface= argument
    # default = auto-detect from default route = public NIC
```

This is the configuration that produced the scan-noise relay sessions in
the 2026-05-19 drill. The TPROXY hook attaches to the host's default-route
interface, which on a typical VPS is the public NIC.

## Detecting the symptom

If you suspect a deployed gateway is running unsafely, check the relay
event stream:

```
# Stream relay sessions in real time.
journalctl -u aegis-client -f -o cat | grep relay_session_started
```

Indicators of scan-driven sessions:

- `target=<your_host_public_ip>` — scanners hitting your own public IP
- `target=<peer>:445`, `:23`, `:3389` — opportunistic ports
- Rapid arrival rate from many distinct peers
- No matching outbound traffic from your real client population

If you see this, run `sudo bash scripts/aegis-wide-disable.sh` immediately
and redeploy with one of the safe patterns above.

## Why the GRE recipe is the canonical multi-host gateway

`scripts/aegis-gre-gateway-setup.sh` solves a second problem on top of
the scan-noise issue: most cloud fabrics (AWS, GCP, OVH, Hetzner, DO,
Vultr, Linode, …) enforce L2 source-IP anti-spoofing. A bare-routed
forwarded-traffic gateway tries to send replies with a spoofed inner
source IP (the upstream target) and the cloud fabric drops them.

The GRE tunnel wraps the spoofed inner reply inside an outer IP header
that carries the gateway's REAL assigned IP, which passes anti-spoof.
See `evidence-archive/live/2026-05-19/tproxy-gre-tunnel-gateway-pass/summary.md`
for the full diagnosis and live evidence.

The two-host GRE recipe is the only multi-host TPROXY gateway pattern
that AEGIS currently claims as `LIVE PASS`. Single-host patterns B and C
above are also `LIVE PASS` but do not forward for a separate downstream.

## Cleanup symmetry

All three safe patterns clean up via the same disable command:

```
sudo bash scripts/aegis-wide-disable.sh
```

For pattern A you additionally teardown the tunnel:

```
sudo bash scripts/aegis-gre-gateway-setup.sh teardown
```

Both leave the host in a clean state (no `AEGIS_WIDE_*` chains, no
`fwmark` rules, no `table 100`/`table 202` entries, SSH reachable).

## Cross-references

- `scripts/aegis-wide-enable.sh` — `--interface=NAME` CLI argument
- `scripts/aegis-gre-gateway-setup.sh` — GRE two-host recipe
- `evidence-archive/live/2026-05-19/tproxy-gre-tunnel-gateway-pass/summary.md` — multi-host PASS evidence
- `evidence-archive/live/2026-05-19/final-tproxy-ipv6-closure/summary.md` — IPv6 BLOCK in tproxy mode
- `evidence-archive/live/2026-05-19/full-ubuntu-acceptance/summary.md` — origin of this warning
