# Firewall deployment profiles

Profiles group firewall fragments by an existing private deployment topology. [inner-tls](inner-tls/README.md) currently contains the legacy IPv4 loopback exception used after origin-guard table creation. This parent directory has no executable dispatcher and does not select a profile automatically.

Keep each profile paired with its systemd/configuration prerequisites. A fragment that names an existing table or chain must not be treated as a standalone firewall reset, and a role accepted on one host is not implicitly accepted on every relay. The [packaging guide](../../README.md) distinguishes operator templates from public client payloads.

Before an authorized deployment, compare intended source bytes, loaded service configuration and actual rule state. Preserve rollback and record per-host differences in the change log. A directory's presence or a source contract pass does not prove that a rule is installed or that traffic is protected.
