# Stable documentation addresses

These paths are deliberately retained; do not replace content-grepped or
package-embedded guides with redirects when reorganizing the repository.

| Path | Why it stays |
|---|---|
| [GENEVA-ROADMAP.md](GENEVA-ROADMAP.md) | Installer/readme contracts read substantive content. |
| [RELEASE-NOTES-0.3.50.md](RELEASE-NOTES-0.3.50.md) | Release-version lookup computes this path. |
| [cloudflare-fronted-operator-guide.md](cloudflare-fronted-operator-guide.md) | gRPC-only carrier contract and installer messages refer here. |
| [geneva-live-bridge.md](geneva-live-bridge.md) | Operator archive copies full instructions to this address. |
| [relay-geneva-installed-profile.md](relay-geneva-installed-profile.md) | Operator archive and package allowlist require full instructions. |
| [threat-model-rkn-tspu.md](threat-model-rkn-tspu.md) | Threat-model status contract reads actual content; subordinate scoped RKN matrix under [the canonical security model](security/22-threat-model.md). |
| ARCHITECTURE-AS-IS-2026-09-05.md (archived: `docs/ARCHITECTURE-AS-IS-2026-09-05.md`) | Historical source snapshot and sidecar hash remain byte-identical. |

## Historical link compatibility

These six addresses contain only a link to the relocated single document. They
remain so immutable audit records still resolve without rewriting the audit.

| Old address | Canonical document |
|---|---|
| [PLAN.md](ROADMAP.md) | docs/archive/checkpoints/PLAN.md (archived: `docs/archive/checkpoints/PLAN.md`) |
| [TRANSPORT-RESILIENCE-ROADMAP.md](ROADMAP.md) | docs/archive/design-baselines/TRANSPORT-RESILIENCE-ROADMAP.md (archived: `docs/archive/design-baselines/TRANSPORT-RESILIENCE-ROADMAP.md`) |
| windows-current-host-reboot-plan.md (archived: `docs/windows-current-host-reboot-plan.md`) | docs/archive/checkpoints/windows-current-host-reboot-plan.md (archived: `docs/archive/checkpoints/windows-current-host-reboot-plan.md`) |
| [windows-encryption.md](windows-encryption.md) | [docs/platforms/windows/windows-encryption.md](platforms/windows/windows-encryption.md) |
| [windows-install-runbook.md](windows-install-runbook.md) | [docs/platforms/windows/windows-install-runbook.md](platforms/windows/windows-install-runbook.md) |
| [windows-system-tunnel.md](windows-system-tunnel.md) | [docs/platforms/windows/windows-system-tunnel.md](platforms/windows/windows-system-tunnel.md) |

The `operations/https-bridge.md` guide is also embedded by the Windows package
builder. The web-response, WebRTC and traffic-privacy guides keep stable operator
archive addresses. Their full instructions remain there; category hubs link to
them. Root navigation maps are entrypoints rather than duplicated runtime guides.
