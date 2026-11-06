# Placeholder adversarial rule packs

`iptables-string-like.sh` prints `action=not-applied`; it does not create an iptables rule. `suricata-generic-like.rules` contains a generic TLS alert placeholder with SID 4200001, not a validated censorship signature or a drop rule. These files reserve testbed wiring without claiming a real adversary model.

Read the rule text before any lab integration. Installing a reviewed replacement requires the applicable firewall/IDS tooling, an authorized disposable gateway and a cleanup plan. Do not execute every file in this directory or treat the presence of a Suricata rule as proof that packets were blocked.

The [testbed guide](../README.md) and [network profiles](../network-profiles/README.md) keep placeholders separate from observed live behavior. A useful measured result must identify the actual active policy, traffic path and captures; these source fixtures alone provide none of those observations and cannot serve as a production acceptance gate.
