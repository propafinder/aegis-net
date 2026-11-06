# Documentation: choose the responsibility

| You need to… | Start here | Owner / location |
|---|---|---|
| Check current product scope and open acceptance | [Product README](../README.md), [92-finding security register](operations/security-audit-2026-10-10-findings.md), [change log](../CHANGELOG.md) | Source repairs and exact-package/native acceptance remain separate; no security finding is fully closed |
| Understand which component owns a behavior | [Responsibility map](architecture/OWNERSHIP.md) | Runtime module boundaries, not named personnel |
| Find source files | [Project map](PROJECT-MAP.md), [directory index](PROJECT-MAP.md) | Local README in each authored source directory |
| Build, launch or review source | [Development](development/README.md) | Compiler, tests, scripts and contribution rules |
| Install an approved package | [INSTALL](../INSTALL.md), [operator guides](operator-guides/README.md) | Host/profile selection and lifecycle |
| Work on a specific OS | [Platforms](platforms/README.md) | Linux, Windows, macOS and Android scope |
| Configure relay/authentication/delivery | [Operations](operations/README.md) | Authority, relay, client and release roles |
| Understand carrier tradeoffs | [Transports](transports/README.md) | Carrier implementation and trust boundaries |
| Check privacy and threat assumptions | [Security](security/README.md), [research](research/README.md) | Security requirements versus mathematical model premises |
| Run controlled experiments | [Testing](testing/README.md) | Lab topology, observers and evidence methods |
| Read an accepted past result | [Audits](operations/evidence-archive.md), [releases](releases/README.md) | Exact source/package/date; no transfer to newer source |
| Read old plans/status | [Archive](operations/evidence-archive.md) | Historical checkpoints and superseded design baselines |

The [canonical threat model](security/22-threat-model.md) defines current
adversarial scope. The retained RKN matrix and archived designs have their own
stated boundaries. The [eleven-model research matrix](research/implementation-and-composition.md)
records implementation and assumptions without blanket native or beta acceptance.

Do not put a second copy of a guide into every crate. A module README owns its
purpose, code entrypoints and links to the single relevant guide. Broader
cross-component contracts belong to the responsibility map; host procedures
belong to their platform or operations guide.

The remaining substantive root documents have stable package/contract paths or
hash custody. Six short compatibility links preserve old audit citations.
[Compatibility paths](COMPATIBILITY.md) explains every exception. Other old
root guides have been physically moved into their topic folders.

[Documentation policy](development/documentation-maintenance.md) defines where
new material belongs. [Evidence vocabulary](DOCUMENTATION-MAP.md) distinguishes
source behavior, procedure, design and exact measured acceptance.
[AI contribution rules](development/ai-contributions.md),
[security reporting](../SECURITY.md) and [governance](../GOVERNANCE.md) define
review and responsibility. [The public source boundary](development/public-source-boundary.md)
records publication prerequisites without authorizing an export.
