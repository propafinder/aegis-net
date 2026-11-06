# Wide-mode reboot persistence — opt-in operator path

**Status:** opt-in operator-side persistence for wide-mode activation.
**Scope:** Linux/Ubuntu hosts where the operator wants `aegis-wide-enable.sh`
to re-apply automatically after reboot.

## TL;DR

Default behaviour: `aegis-wide-enable.sh` is per-session. After a reboot
the host returns to its non-wide default and SOCKS5 stays available as
the always-on default ingress.

If you want wide mode (REDIRECT or TPROXY) sticky across reboots, install
the opt-in systemd unit via:

```
sudo bash scripts/aegis-wide-persist-install.sh \
    --mode=redirect --dns=off --ipv6=block
```

…or for a GRE-tunnel gateway:

```
sudo bash scripts/aegis-wide-persist-install.sh \
    --mode=tproxy --dns=off --ipv6=block --interface=aegis-gre0
```

To roll back:

```
sudo bash scripts/aegis-wide-persist-install.sh uninstall
```

## What it installs

`/etc/systemd/system/aegis-wide.service`:

```
[Unit]
Description=AEGIS wide-mode reapply on boot (opt-in operator persistence)
After=network-online.target aegis-client.service systemd-resolved.service
Wants=network-online.target aegis-client.service

[Service]
Type=oneshot
RemainAfterExit=yes
Environment=AEGIS_WIDE_DISABLE_FROM_UNIT=1
ExecStartPre=/bin/sh -c 'mkdir -p /run && touch /run/aegis-wide-confirmed'
ExecStart=/usr/local/lib/aegis/helpers/aegis-wide-enable.sh -y --no-rollback \
    --mode=<MODE> --ssh-safe-ports=<PORTS> --dns=<DNS> --ipv6=<IPV6> --udp=<UDP> \
    [--interface=<IFACE>]
ExecStop=/usr/local/lib/aegis/helpers/aegis-wide-disable.sh
TimeoutStartSec=120
TimeoutStopSec=60

[Install]
WantedBy=multi-user.target
```

The installer resolves helpers under `/usr/local/lib/aegis/helpers` first and
retains `/scripts` compatibility. Inspect the actual generated unit for its
resolved paths; the example is illustrative, not a unit to copy manually.

The unit has these lifecycle properties:

1. **Ordering and soft `Wants=aegis-client.service`** request client startup.
   `Requires=` is deliberately absent because wide-enable may restart the client
   after DNS configuration. This is not a guarantee that the client remains
   running or that capture is continuously safe; inspect service readiness and
   the selected profile's independent guard/lifecycle evidence.
2. **`ExecStartPre` pre-creates `/run/aegis-wide-confirmed`** — this is
   the same sentinel `aegis-wide-enable.sh` watches at runtime to decide
   whether to roll back. By installing this unit you've already committed
   to sticky mode, so the auto-rollback timer is suppressed for the
   boot-time apply.
3. **`ExecStop=aegis-wide-disable.sh`** — `systemctl stop aegis-wide` or
   `disable --now` removes all chains and restores the host. The
   teardown is symmetric with the runtime enable path.

The sysctl persistence written by `aegis-wide-enable.sh` itself
(`/etc/sysctl.d/99-aegis-wide.conf`, see
`scripts/test-aegis-wide-sysctl-persistence-contract.sh`) survives reboot
independently of this unit, so kernel-level prerequisites are already
sticky.

## When NOT to use this

- You are evaluating wide mode and want easy rollback. The default
  per-session behaviour is exactly what you want — reboot equals reset.
- You are on a publicly-reachable VPS and considering `--mode=tproxy`
  without `--interface=<tunnel>`. **Do not enable persistence for this
  configuration** — see `docs/operator-guides/tproxy-gateway-topology-warning.md`
  for the relay-amplification scan-noise risk.
- DNS-preview operators should also persist the `[ingress.wide]`
  `dns_preview_*` lines in `/etc/aegis/client/aegis.toml` manually
  (the runtime enable adds them then strips them on disable). See the
  fake-IP architecture diagnosis in
  `evidence-archive/live/2026-05-19/final-linux-wide-closure/summary.md`.

## Verification

```
$ sudo bash scripts/aegis-wide-persist-install.sh verify
verify=present unit=aegis-wide.service path=/etc/systemd/system/aegis-wide.service

$ systemctl status aegis-wide.service
● aegis-wide.service - AEGIS wide-mode reapply on boot (opt-in operator persistence)
     Loaded: loaded (/etc/systemd/system/aegis-wide.service; enabled)
     Active: active (exited) ...
```

At boot the unit requests `aegis-wide-enable.sh -y --no-rollback` with the
recorded flags (including UDP policy). The sentinel and explicit no-rollback
option suppress the ordinary confirmation timer. Native boot activation,
service readiness and guarded failure/cleanup must still be measured on the
exact installed package; an enabled unit or `active (exited)` alone is not
continuous-capture or successful-recovery acceptance.

## Uninstall

```
sudo bash scripts/aegis-wide-persist-install.sh uninstall
```

The helper:

1. `systemctl disable --now aegis-wide.service` (triggers `ExecStop` →
   `aegis-wide-disable.sh`).
2. Removes `/etc/systemd/system/aegis-wide.service`.
3. `systemctl daemon-reload`.

After successful teardown, verify the resolver, owned routes/firewall and
service state before asserting restoration. A failed cleanup retains its
recovery evidence and may leave protection armed.

## Cross-references

- `scripts/aegis-wide-enable.sh` — the per-session activator
- `scripts/aegis-wide-disable.sh` — symmetric teardown
- `scripts/aegis-wide-persist-install.sh` — this opt-in installer
- `scripts/test-aegis-wide-persist-install-contract.sh` — contract test
- `scripts/test-aegis-wide-sysctl-persistence-contract.sh` — sysctl persistence test
- `docs/operator-guides/tproxy-gateway-topology-warning.md` — must-read before persisting `--mode=tproxy`
