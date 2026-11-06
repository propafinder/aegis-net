# AEGIS user quickstart (hostile / RKN network)

> Historical RC15 procedure. Release, host and delivery claims below belong to
> that checkpoint; they do not select the current candidate. For current package
> selection and installation prerequisites, start with [INSTALL](../../INSTALL.md).
> Commands below are historical and no longer valid for current onboarding:
> inline bundle URLs are refused, credentials are not printed, and helper paths
> and transport policy must come from the current exact package.

This is the end-user install path for a Linux (Ubuntu) client on a censored
network. It assumes an operator has a running AEGIS relay fronted by Cloudflare
(see `cloudflare-fronted-operator-guide.md`).

## What AEGIS is (and is not)

AEGIS is an adaptive censorship-resilient **transport**: a client tunnels traffic
to your own relay over one of several camouflaged transports (`https_ws`,
`grpc_stream`, `legacy_tls`, `masque_derived`; signed RC11 adds
`grpc_datagram` for fixed-destination UDP), choosing per session. The audited
Cloudflare path proves forced `grpc_stream`; it does not prove the current
`https_ws` contour.

It is **not** a universal anti-DPI tool, not browser-equivalent mimicry, and it
does **not** carry MASQUE/UDP through a normal Cloudflare proxy. RC11's
`grpc_datagram` is a separate H2/TCP fallback. RC11 is not an onboarding
candidate because its persistent-UDP transport telemetry is false. RC15 is now
signed and its delivery independently verified. It includes the RC13 reliability
corrections, the adaptive installer and its limited-bundle flag cleanup. Wider
onboarding still depends on the remaining acceptance gates recorded at that date in the
11 September state checkpoint (archived: `docs/archive/checkpoints/STATE.md`). Current gates
are in [README readiness](../../README.md#readiness) and the change log.

RC15 provides [automatic installation](ubuntu-install-profiles.md#automatic-installation-rc15).
With the signed bootstrap and access bundle, omitting `--profile` checks the
host and chooses the supported profile. The explicit profiles below remain
available when an operator intentionally chooses the traffic scope.

## The two delivery problems on a fully censored box

1. **The relay endpoint** must be reachable. Solution: a Cloudflare-fronted
   authority (e.g. `relay.example.org`) plus a failover pool, so the direct origin IP
   is never the primary. The persistent tunnel rides Cloudflare.
2. **The install assets** (client binary + `install.sh`) are normally on GitHub —
   which may be DNS-blocked (`Could not resolve host: github.com`). Solution: the
   relay's bundle endpoint serves **any** tarball through Cloudflare, so the
   operator hands out the release tarball the same way as the config bundle. No
   GitHub dependency.

Both require the relay to run **v0.3.24+** (the HTTP/2 `/bundle` fix); on older
relays `/bundle` 404s through Cloudflare and you must deliver out-of-band.

## Operator: issue the two tokens

On the relay (tokens are one-time, short-lived; the auth token is never printed):

```bash
# 1) Fronted config bundle (primary + failover pool, system-trust CA, no origin IP)
sudo bash scripts/issue-fronted-bundle.sh \
  --config /etc/aegis/server/aegis-server.toml \
  --primary relay.example.org --failover relay-a.example.org --failover relay-b.example.org \
  --issue-token --ttl-secs 3600
#  -> prints CONFIG_BUNDLE_URL (https://relay.example.org/bundle?token=...)

# 2) Release tarball (binary + install.sh) for GitHub-blocked clients
sudo -u aegis aegis-server --config /etc/aegis/server/aegis-server.toml \
  bundle-token issue \
  --bundle-path /var/lib/aegis/bundles/aegis-<ver>-linux-x86_64.tar.gz \
  --ttl-secs 3600 --public-host relay.example.org --public-port 443
#  -> prints RELEASE_URL (https://relay.example.org/bundle?token=...)
```

Hand `CONFIG_BUNDLE_URL` and `RELEASE_URL` to the user over a trusted channel.

## Command 1 — primary host-wide (wide-redirect-safe)

Carries **all host TCP** through the fronted relay; DNS preview; generic UDP /
QUIC / IPv6 are **fail-closed** (no native leak). Run as root on the client:

```bash
# fetch the release tarball through Cloudflare (no GitHub needed)
curl -fsS '<RELEASE_URL>' -o /tmp/aegis.tgz
mkdir -p /tmp/aegis && tar -xzf /tmp/aegis.tgz -C /tmp/aegis
# install, host-wide, pulling the fronted config bundle through Cloudflare
sudo "$(find /tmp/aegis -name install.sh | head -1)" client \
  --profile wide-redirect-safe --bundle-url '<CONFIG_BUNDLE_URL>'
```

Verify:
```bash
curl https://api.ipify.org        # no proxy flags: host TCP already tunnelled
#  -> prints the relay egress IP
aegis-client wide status
aegis-client profile show
```

## Command 2 — safe fallback (socks-only, per-app)

If host-wide capture cannot be set up (no root, restricted kernel), install
per-app SOCKS. This is **not** host-wide — only apps pointed at the listener are
carried; everything else stays native.

```bash
curl -fsS '<RELEASE_URL>' -o /tmp/aegis.tgz
mkdir -p /tmp/aegis && tar -xzf /tmp/aegis.tgz -C /tmp/aegis
sudo "$(find /tmp/aegis -name install.sh | head -1)" client \
  --profile socks-only --bundle-url '<CONFIG_BUNDLE_URL>'
```

Verify (the SOCKS user:password is printed by the installer):
```bash
curl --socks5-hostname 127.0.0.1:1080 --proxy-user 'aegis:<printed>' https://api.ipify.org
```

## Uninstall / cleanup

```bash
sudo bash /usr/local/lib/aegis/setup-wide-linux-redirect.sh teardown   # wide TCP rules
sudo "$(find /tmp/aegis -name purge-installed-aegis.sh | head -1)"     # full removal
# or: sudo systemctl disable --now aegis-client.service && sudo rm -rf ~/.config/aegis
```

## Honest status

- **Command 1 (wide-redirect-safe)** and **Command 2 (socks-only)** are real,
  turnkey, noninteractive install modes — no manual TOML edits.
- **`full-wide-tun`** is a turnkey privileged Linux installer profile. All five
  legs require `--udp-carry`, a direct `--masque-server`, and its scoped
  `--masque-ca` (or a bundle containing `masque-ca.pem`). TCP can remain on a
  Cloudflare-fronted transport; UDP/MASQUE is direct and exposes the origin IP.
  Activation probes TCP and DNS and rolls back on failure; operators must still
  verify both UDP families from the deployed client.
- The Cloudflare delivery of both tokens requires the relay on **v0.3.24+**.
- MASQUE/UDP through normal Cloudflare is **not** claimed.
