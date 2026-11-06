# Ubuntu wide install profiles

AEGIS installs with one explicit **product profile** that decides, for ordinary
local app traffic (no SOCKS/proxy configured), whether each traffic class is
**carried** by AEGIS or **fail-closed** with explicit policy. No safe profile
silently leaks native traffic.

Policy lives in exactly one place — the Rust model
(`aegis-core::wide_product`) — and is rendered by `aegis-client profile`. The Bash
installer only orchestrates it.

## Choosing a profile

```
sudo ./install.sh client --profile <mode> --bundle-url-file /root/aegis-access/client-access-url.txt
# or:  --mode <mode>   (accepts the same product modes)
# env: AEGIS_INSTALL_PROFILE / AEGIS_INSTALL_MODE
#      AEGIS_WIDE_UDP_POLICY / AEGIS_WIDE_DNS_POLICY / AEGIS_WIDE_IPV6_POLICY (overrides)
#      AEGIS_WIDE_INTERFACE (informational)
```

Use the verified installer from an approved exact client release, as described in
[INSTALL](../../INSTALL.md) and [private installer inputs](../operations/private-installer-inputs.md).
The URL record must already exist with mode `0600`, root ownership for a root
invocation, and trusted private ancestors. An already unpacked local access
bundle can instead use `--bundle /absolute/private/client-bundle`. The path must
name the bundle directory, not a tar archive; verify and unpack a delivered
archive privately first. Explicit profiles remain
available only when their required helpers are present in the selected package.

<a id="automatic-installation-rc14"></a>
<a id="automatic-installation-rc15"></a>

## Automatic installation

Run the signed bootstrap as root with the operator-provided access bundle. In
current source, omitting `--profile` is equivalent to `--profile auto` and
does not open a technical mode picker. The bootstrap installs missing download,
signature-verification and networking command packages through `apt-get` on
Ubuntu/Debian or `dnf` on its recognized RHEL/Fedora/CentOS/Rocky/Alma family.
Other families require those packages to be present already. Offline and
download-only modes stop if prerequisites are missing instead of installing OS
packages. This package-manager support is not native acceptance of every family.

The RC15 lifecycle audit (archived: `docs/audit/linux-rc15-adaptive-installer-2026-09-07.md`) records
signed full and limited Ubuntu installation. A reused full-profile bundle has
stale TUN/generic-UDP flags cleared before service activation in limited mode.
A later upgrade preserves that limited scope. The historical RC14 defect and
separate source-patch test remain in its dated audit.

After acquiring the bundle and checking the exact candidate binary's ABI, the
installer asks the Rust planner to inspect Linux, effective CAP_NET_ADMIN,
systemd, networking commands, TUN and IPv6. Before changing an existing service,
firewall, config or binary, it chooses:

| Situation | Automatic result |
|---|---|
| Supported system with TUN and IPv6 | `full-wide-tun`, using the existing relay paths |
| TUN or IPv6 unavailable | `wide-redirect-safe`; clearly reports blocked generic UDP and IPv6 |
| Missing privilege, systemd or required commands | Stops with a specific prerequisite explanation |
| Existing standard product selection | Preserves its scope; lost requirements stop the upgrade |
| Existing advanced/custom/unknown selection | Requires explicit profile options before changing it |
| Invalid access bundle or invalid planner output | Stops before replacing the existing installation |

The planner is read-only and can be inspected independently:

```bash
sudo aegis-client profile auto --config /path/to/bundle/aegis-client.toml \
  --state-dir /var/lib/aegis-install/client --json
```

Its `connectivity_verified: false` is intentional: host prerequisites cannot
prove connectivity. `--state-dir` here names the exact administrator-owned
installer metadata directory, not the service's runtime state. A standard root
installation saves `auto-install-plan.json` in `/var/lib/aegis-install/client`,
beside `install-manifest.json`; custom root runtime paths use their separate
`.install-metadata` sibling. The installer applies the existing capture
lifecycle, then runs TCP and DNS checks.
A failed activation remains an installation failure and invokes the existing
rollback path. The plan alone does not certify UDP/IPv6 connectivity or successful
rollback; those require separate live observations.

Runtime transport recovery continues to use the existing configured endpoint
and relay fallback mechanisms. This installer does not add a daemon that
changes the host's traffic scope when the network changes. Advanced modes remain
explicit through `--profile`; automatic mode rejects manual policy overrides.

## Manual profiles

| Profile | TCP IPv4 | DNS UDP/53 | Generic UDP | QUIC/HTTP3 | IPv6 | Leak risk |
|---|---|---|---|---|---|---|
| `socks-only` | per-app SOCKS | native | native | native | native | not wide (per-app) |
| `wide-redirect-safe` | REDIRECT relay | preview | **block** | **block** (→TCP) | **block** | low |
| `wide-udp-direct` | REDIRECT relay | preview | MASQUE direct **bidirectional** (IPv4) or **block** | MASQUE or block | **block** | low |
| `gateway-tproxy` | TPROXY (downstream) | preview | preview allowlist | block | block | low |
| `full-wide-nfqueue` (source-only) | REDIRECT relay | preview | **block** (NFQUEUE) | **block** | observe + **fail-closed** | helper excluded from public package |
| `full-wide-tun` | REDIRECT relay | preview | enrolled: `grpc_datagram`; legacy: configured MASQUE/H2 plan | same UDP plan | **TCP+UDP carried** (TUN+smoltcp) | fail-closed within selected profile |
| `full-wide-hybrid-geneva` (experimental, operator-only) | full-wide + direct IPv4 Geneva | preview | direct MASQUE required | direct MASQUE | TUN carried | origin/source exposed by direct leg |
| `wide-compat` | REDIRECT relay | **native** | **native** | **native** | **native** | **HIGH** |

`full-wide-tun` is the **all-carried** mode: every no-proxy leg (TCP IPv4, DNS,
IPv4 UDP, IPv6 TCP, IPv6 UDP) is carried through AEGIS — the only mode where IPv6
UDP is carried bidirectionally rather than fail-closed. It combines the REDIRECT
backend (v4) and the TUN+smoltcp backend (v6); fail-closed on relay error (no
native leak within the selected capture contract). June 2026 five-leg proofs on
Ubuntu 26.04 (`evidence-archive/live/2026-06-07/ubuntu-full-wide-ready/`) are dated
legacy-topology evidence. They do not accept the current enrolled runtime,
changed guard, signed package or installed reboot/crash lifecycle.

For enrolled `full-wide-tun`, UDP travels over inner-TLS `grpc_datagram`;
`masque_direct` in a capture-policy record is not a wire-transport name. Legacy
shared-token profiles may opt into direct MASQUE with gRPC datagram fallback.
Direct MASQUE bypasses Cloudflare, exposes the origin/client peer relationship
and requires matching firewall reachability. The experimental hybrid profile
requires an explicit reviewed Geneva strategy and direct MASQUE settings.
`full-wide-nfqueue` requires a reviewed source checkout and its queue consumer;
its helper is absent from the public client package, so it is not a public
release installation choice.

- **block** = fail-closed REJECT/DROP (not tunnelling) — the app gets no native egress.
- `wide-compat` prints a **HIGH LEAK RISK** warning and is not for hostile networks.
- Safe profiles **cannot** be silently downgraded to a native policy; an override
  like `--udp-policy native` on a safe profile is rejected. Use `wide-compat` if
  you genuinely accept native UDP/DNS/IPv6.

## Historical NFQUEUE evidence (June 2026)

The following evidence predates the current TUN profile. Its lab-only IPv6
limitations describe that NFQUEUE contour, not today's `full-wide-tun` source.
The 11 September state checkpoint (archived: `docs/archive/checkpoints/STATE.md`) records historical
release decisions. Use [current readiness](../../README.md#readiness) and the
[change log](../../CHANGELOG.md) for later gates.

`full-wide-nfqueue` is a **PARTIAL** profile:

- **TCP IPv4** is carried by the **REDIRECT** relay path (egress flips to the relay).
- **Generic UDP / QUIC** are **fail-closed** (NFQUEUE DROP + firewall REJECT) in
  this profile. They are relayed only if you opt into `wide-udp-direct`: there a
  REDIRECT proxy carries IPv4 generic UDP **bidirectionally** over MASQUE direct
  (the app receives the response — live-proven on Ubuntu 26.04,
  `evidence-archive/live/2026-06-08/.../udp-bidirectional-live/`, verdict
  `BIDIRECTIONAL_UDP_PASS`), falling **fail-closed** (no native egress) when the
  relay is unreachable. IPv6 generic UDP is **not** carried (stays fail-closed).
- **IPv6** in `full-wide-nfqueue` is **observed** by NFQUEUE and then
  **fail-closed (DROP)**. Separately, **IPv6 TCP can now be carried** via the
  TUN+smoltcp relay-bridge path (an ordinary `curl -6` flow is captured and
  carried through the relay; the app receives the response — live-proven on
  Ubuntu 26.04, `evidence-archive/live/2026-06-07/.../ipv6-carried-live/`, verdict
  `IPV6_TCP_CARRIED_PASS`, real `::/0` not touched). At that June checkpoint,
  this carry was a controlled CLI lab (`--tun-ipv6-relay-bridge-lab`), **not yet a turnkey install
  profile**, and **IPv6 generic UDP is not carried** (TCP-only) — it stays
  fail-closed.
- NFQUEUE is the **policy/verdict** layer; it never terminates/relays a TCP
  connection. If the NFQUEUE consumer is absent, the divert rules carry **no**
  `--queue-bypass`, so the kernel **drops** the blocked classes — fail-closed.

No traffic class leaks natively. As of 2026-06-08 all four network legs have a
live carried/PASS proof — TCP, DNS, generic UDP (MASQUE direct, bidirectional)
and **IPv6 TCP** (TUN+smoltcp → relay). The gate is **STRONG_PARTIAL** (not
READY) for two honest reasons: IPv6 carry is still a controlled CLI lab rather
than a turnkey install profile, and **IPv6 generic UDP** is not carried (TCP-only)
so it stays fail-closed. READY additionally needs a from-release-asset install
proof and a soak.

## Inspecting and switching after install

```
aegis-client profile show            # resolved profile for the recorded mode
aegis-client profile list            # all modes + scope + leak risk
aegis-client wide status             # recorded mode + AEGIS firewall chains present
aegis-client doctor                  # root? iptables/ip6tables/nft? NFQUEUE? proxy env?
sudo aegis-client profile switch --to <mode>   # update root install metadata + print enact steps
```

`profile switch` records the choice and prints commands; it does not activate
the replacement or disconnect a guard. For a standard root installation, run
metadata-changing commands as root so they update the authoritative record
instead of a user fallback. Before a destructive legacy reinstall or
switching away from legacy `full-wide-tun` while its guard is armed, complete the
legacy disconnect below. An in-place legacy full-wide upgrade retains the guard.
Enrolled migration uses the separate device procedure, not this metadata command.

## Teardown

```
sudo /usr/local/lib/aegis/helpers/aegis-wide-disable.sh   # legacy capture/guard disconnect
```

For a source-only NFQUEUE lab, use its reviewed checkout helper and separately
stop the consumer you created. Do not assume that helper or a service named
`aegis-nfqueue` exists in a public installation. Low-level capture teardown and
stopping the client leave the independent deny guard armed. The wide-disable
command explicitly disarms only the legacy guard. It does not disarm an enrolled
device's `device-guard.conf` or `inet aegis_device_guard`. Follow the installed
device's [recovery/migration procedure](../operations/device-online-enrollment.md#installed-renewal-and-explicit-migration)
and retain its helpers and ownership records until that procedure succeeds.

## What AEGIS does NOT claim here

Not full AEGIS completion, not universal anti-DPI, not browser-equivalent
mimicry, not UDP/MASQUE through a normal Cloudflare orange-cloud proxy, and not
IPv6/UDP *relay* in `full-wide-nfqueue` (those are fail-closed).
