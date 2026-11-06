# Choose a Linux traffic mode

`--profile auto` is the normal first choice. It examines the host and selects
a supported mode before installation. Use a named profile only when the
operator has approved its scope and prerequisites. A selected mode can carry
some traffic and deliberately block other traffic; a changed public IP alone
does not prove the whole device is protected.

| Mode | What it captures | DNS, UDP and IPv6 boundary |
| --- | --- | --- |
| `socks-only` | Only applications explicitly configured for the local SOCKS proxy | Other applications use their normal host route. Configure each app and its DNS behavior deliberately. |
| `wide-redirect-safe` | Supported local IPv4 TCP through the guarded redirect | Selected DNS preview is scoped; generic UDP and IPv6 are blocked by the selected safe policy, rather than sent directly. |
| `full-wide-tun` | Selected IPv4 and IPv6 TCP/UDP through the guarded redirect/TUN path | Enrolled UDP uses authenticated `grpc_datagram`; DNS and all declared families need separate observed acceptance. Missing relay or guard authority closes traffic. |

The AUTO planner does not prove Internet connectivity. A machine without the
required privileges, systemd, TUN, IPv6 or trusted boot policy can refuse
instead of silently dropping to a weaker mode. An enrolled full-wide device
cannot be downgraded by host planning. Do not change profile to work around a
refusal until the operator has checked the protected transition.

The gateway/TPROXY profile is a separate, unaccepted LAN-host design. It does
not turn this workstation into a protected LAN gateway. SOCKS is an
application setting; full-wide is a privileged host policy with a guard and
recovery lifecycle.
