# Private nftables additions

This tree contains narrowly scoped deployment rules, currently under [profiles](profiles/README.md). They supplement an existing guard design; they are not a complete general firewall or a public client installation entry point.

The current [inner-TLS rule](profiles/inner-tls/README.md) depends on an existing named table/input chain and is paired with a systemd post-start drop-in. Applying it in the wrong order fails; repeatedly inserting it into the same live chain duplicates state. Use the reviewed role-specific deployment procedure and preserve independent recovery access for authorized firewall changes.

Read the rule source and its [systemd profile](../systemd/profiles/inner-tls/README.md) before any host mutation. Source bytes and a successful syntax inspection do not demonstrate loaded rules, endpoint reachability, relay authorization or release acceptance. Credentials and host-specific public/private listener configuration belong outside this template tree.
