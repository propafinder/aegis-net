# Operator profile procedures

Choose an approved exact package in [INSTALL](../../INSTALL.md) before selecting
a profile. Platform-specific behavior is indexed in [platforms](../platforms/README.md).
Authority and release trust belong to the focused operations guides, not these
profile selectors.

## Install and choose a profile

- [Historical RC15 Cloudflare-fronted quickstart — not current onboarding](user-quickstart.md)
- [Ubuntu wide install profiles](ubuntu-install-profiles.md)
- [Operator guide: `full-wide-tun` (host-wide incl. IPv6)](full-wide-tun.md)
- [AEGIS transports & protocols](protocols-and-transports.md)

## Native routing, topology and lifecycle

- [Wide-mode reboot persistence — opt-in operator path](wide-mode-reboot-persistence.md)
- [Wide-mode IPv6 capture (`--ipv6=capture`)](wide-ipv6-capture.md)
- [Wide-mode NFQUEUE observer backend — scaffold + decoder](wide-nfqueue-observer.md)
- [TPROXY gateway topology — operator warning and safe deployment patterns](tproxy-gateway-topology-warning.md)

## Carrier and TLS surface choice

- [Cloudflare-fronted relay runbook](cloudflare-fronted-relay.md)
- [Pre-TLS HAProxy front — closing the plain-HTTP probe gap](pre-tls-haproxy-front.md)
- [Mimicry foundation: per-session GREASE sampler + legacy-1.2 audit](mimicry-grease-and-legacy-tls12-audit.md)
- [Operator warning — `relay.policy.surface_profile_id` pinning](surface-profile-pin-warning.md)

## Local privacy and secret handling

- [AEGIS secret handling](secret-handling.md)
- [Seizure resistance (journalist / at-risk deployments)](seizure-resistance.md)

## Release operator procedure

- [AEGIS release runbook](release-runbook.md)

Parent: [documentation](../README.md). Read each guide’s source, host and
acceptance scope; an instruction is not proof of execution.
