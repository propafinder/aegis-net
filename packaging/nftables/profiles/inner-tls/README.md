# Inner-TLS legacy loopback exception

`legacy-loopback.nft` inserts one accept rule into `inet aegis_origin_guard input`. It is restricted to interface `lo`, IPv4 source `127.0.0.1` and TCP destination port 443, with the `aegis-v3-local-legacy` comment. It does not admit arbitrary public source addresses, IPv6 traffic or other listener ports.

The existing origin guard must create its table and chain first. The paired [origin-guard drop-in](../../../systemd/profiles/inner-tls/aegis-origin-guard.service.d/README.md) loads the installed file at `/etc/aegis-v3/legacy-loopback.nft` after guard startup. It is intended for a newly recreated guard table; repeated manual insertion is not idempotent.

Follow the [complete recovery-profile runbook](../../../systemd/profiles/inner-tls/README.md) for role selection, ownership and activation constraints. Editing this fragment does not change a live firewall. Source comparison, loaded-rule inspection and traffic checks have distinct scopes; none of these template files establishes fleet-wide deployment or beta acceptance.
