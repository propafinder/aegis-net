# Wide-mode IPv6 capture (`--ipv6=capture`)

**Status:** IPv6 capture path is wired end-to-end through the existing
TPROXY helper.
**Closes:** the long-standing "IPv6 capture: not implemented; only BLOCK
PASS" gap on historical roadmap (archived: `docs/archive/pre-0.3.49/08-active-roadmap.md`).
**Scope:** Linux/Ubuntu hosts running `--mode=tproxy`. The IPv4 REDIRECT
path is unchanged.

## TL;DR

```
sudo bash scripts/aegis-wide-enable.sh \
    --mode=tproxy --dns=off --ipv6=capture
```

That single flag flips the wide-mode plane from IPv4 to IPv6:

- The wide listener binds on `[::]:15080` instead of `127.0.0.1:15080`.
- The TPROXY helper runs `ip6tables` instead of `iptables`, installs
  the chain on `mangle/PREROUTING` with `-j TPROXY --on-ip ::`, adds
  `ip -6 rule add fwmark N lookup T` and `ip -6 route add local ::/0
  dev lo table T`.
- The IPv6 BLOCK chain (`AEGIS_WIDE_TPROXY_V6_BLOCK`) is NOT installed:
  capture mode intentionally lets v6 traffic through the AEGIS path
  instead of dropping it.
- IPv4 traffic on this host is **not** captured by this wide-mode
  apply — operators wanting both must run a second wide-mode instance
  with `--ipv6=block` (default) on the v4 plane, or wait for the
  dual-stack listener which is a separate follow-up.

## Why IPv6 capture is its own flag, not an automatic upgrade

The historical pre-`v0.3.14` default was `--ipv6=block` because:

1. The wide listener was IPv4-only on most operator hosts (the Rust
   v6 bind path existed but wasn't wired up by the wrapper).
2. Silent v6 leaks past an IPv4-only AEGIS path were a real privacy
   risk — drop-closed v6 was the safe default.

After this batch the wire-up is present and the operator can
explicitly opt in to v6 capture. The default remains `block` because
the safe-by-default contract should NOT flip without explicit operator
intent — adding a new family to the captured plane is a real change
to what the host sees.

## Requirements

- `--mode=tproxy` is required. The REDIRECT path is **rejected
  immediately** by `aegis-wide-enable.sh` if `--ipv6=capture` is
  combined with `--mode=redirect`: NAT-based v6 REDIRECT either
  doesn't exist on the kernel or doesn't preserve original-dst.
- `ip6tables` (or `nft` with the inet/ip6 family) must be available
  on the host.
- The kernel must have `CONFIG_IP6_NF_TARGET_TPROXY` plus
  `IPV6_TRANSPARENT` socket option support (kernel ≥3.7; standard
  on every supported Ubuntu LTS).
- Operator must have weighed up the
  [mixed-role TPROXY topology warning](tproxy-gateway-topology-warning.md).
  IPv6 capture amplifies the scan-noise concern: many cloud fabrics
  route bogus inbound v6 to public hosts without rDNS, and TPROXY
  will accept them too.

## Side-by-side: what gets installed

For `--ipv6=block` (default):

```
ip6tables -t filter -N AEGIS_WIDE_TPROXY_V6_BLOCK
ip6tables -t filter -A AEGIS_WIDE_TPROXY_V6_BLOCK -j DROP
ip6tables -t filter -I OUTPUT  1 -j AEGIS_WIDE_TPROXY_V6_BLOCK
ip6tables -t filter -I FORWARD 1 -j AEGIS_WIDE_TPROXY_V6_BLOCK
```

For `--ipv6=capture`:

```
# listener: bind [::]:15080 with IPV6_TRANSPARENT
ip6tables -t mangle -N AEGIS_WIDE_TPROXY
ip6tables -t mangle -A AEGIS_WIDE_TPROXY -p tcp -j TPROXY --on-ip :: --on-port 15080 --tproxy-mark N/N
ip6tables -t mangle -I PREROUTING -i <iface> -j AEGIS_WIDE_TPROXY
ip -6 rule add fwmark N lookup T
ip -6 route add local ::/0 dev lo table T
# no DROP chain — v6 packets flow through the AEGIS path
```

## Operator workflow

```
$ sudo bash scripts/aegis-wide-enable.sh --mode=tproxy --dns=off --ipv6=capture
============================================================
AEGIS wide-mode activation summary
------------------------------------------------------------
mode:               tproxy
outbound iface:     eth0
wide listen port:   15080
IPv6 policy:        capture
...
Apply now? (yes/no): yes
...
============================================================
AEGIS wide mode ACTIVE on interface eth0
- mode:        tproxy
- listen:      :15080
- DNS:         off
- IPv6:        capture
VERIFY YOUR SSH SESSION STILL WORKS, then RUN within 60s:
    sudo touch /run/aegis-wide-confirmed
```

Verification that v6 capture is live (after `aegis-wide-confirmed`):

```
$ curl -6 -sS --max-time 10 https://[2606:4700:4700::1111]/cdn-cgi/trace | grep '^ip='
ip=EXPECTED_RELAY_EGRESS    # compare privately with the selected relay receipt
```

If you see the host's own v6 address rather than the relay IP, the
`ip -6 route` policy-routing path is not loading the marked packets
through the TPROXY chain — check `sudo ip -6 rule show | grep fwmark`
and `sudo ip -6 route show table <N>`.

## Teardown

`aegis-wide-disable.sh` is symmetric — it tears down whichever family
was applied. No flag change required to roll back v6 capture.

```
$ sudo bash scripts/aegis-wide-disable.sh
... (removes AEGIS_WIDE_TPROXY chain on the active family,
    fwmark rule, table, persistent sysctl, etc.)
```

## What's still NOT in scope after this batch

- **This TPROXY procedure is single-family.** The separate current
  [full-wide-tun profile](full-wide-tun.md) combines IPv4 REDIRECT and IPv6
  TUN capture, including UDP under its selected relay policy. Its source
  contract and exact-package installed acceptance are separate from these
  historical single-family TPROXY receipts.
- **IPv6 UDP capture parity.** v6 TCP capture is wired; v6 UDP/53 +
  generic-UDP capture follows the same TPROXY pattern but each
  operator deployment is currently single-family. Cross-family DNS
  (operator runs v4-capture but apps use AAAA) is handled by the
  resolver-based fake-IP DNS path documented in
  `evidence-archive/live/2026-05-19/final-linux-wide-closure/summary.md` —
  fake IPs in `198.18.0.0/15` synthesize v4 substitutes for v6
  hostnames at the resolver layer.

## Cross-references

- `scripts/aegis-wide-enable.sh` — `--ipv6=capture` flag
- `scripts/setup-wide-linux-tproxy.sh` — v6 TPROXY chain implementation
- `scripts/test-aegis-wide-ipv6-capture-contract.sh` — contract test
- `aegis-client/src/ingress/wide/linux.rs` — `bind_linux_udp_dns_socket_v6`,
  `enable_recv_original_dst_v6` (existing v6 listener bind path)
- `docs/operator-guides/tproxy-gateway-topology-warning.md` — mixed-role
  warning, applies equally to v6 capture
- `evidence-archive/live/2026-04-30/linux-wide-ipv6-policy-live/` — historical
  IPv6 BLOCK PASS evidence
