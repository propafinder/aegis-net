# Component responsibilities

This is an ownership map of code responsibilities, not personnel assignments.
Use the listed module's README when changing behavior; update its focused guide
and actual callers rather than duplicating implementation instructions globally.

| Component | Owns | Boundary / does not own |
|---|---|---|
| [aegis-client](../../aegis-client/README.md) | CLI/config, ingress, profile selection, identity lifecycle and local OS workers | Relay authority policy, signing or proof of field efficacy |
| [aegis-server](../../aegis-server/README.md) | Relay forwarding/target policy and separate enrollment/policy command roles | Client host routing; relay access is not administration access |
| [aegis-core](../../aegis-core/README.md) | Shared framing, trust/crypto helpers, Brain, strategies and bounded research consumers | Platform installation or granting a live deployment permission |
| [aegis-geneva](../../aegis-geneva/README.md) | Offline grammar/model/training and explicit guarded bridge backend | Automatically capturing every installed application's traffic |
| [aegis-quic-boring](../../aegis-quic-boring/README.md) | QUIC crypto adapter and native dependency boundary | MASQUE admission/policy or guaranteed browser parity on a target network |
| [aegis-web-carrier](../../aegis-web-carrier/README.md) | Owned response framing and admission primitives | Enrollment authority or third-party web-service access |
| [aegis-webrtc](../../aegis-webrtc/README.md) | Optional owned DataChannel integration | Deployed Snowflake/SFU service or independent signaling availability |
| [aegis-fingerprint](../../aegis-fingerprint/README.md) | Fingerprint data/comparison primitives | Network capture or proving censorship resistance |
| [aegis-knowledge](../../aegis-knowledge/README.md) | Knowledge/evidence representation | Replacing observed runtime outcome with a paper claim |
| [aegis-android-jni](../../aegis-android-jni/README.md) | JNI proof integration surface | An accepted Android VPN/VpnService product |
| [tools/measure](../../tools/measure/README.md) | Measurements, validators and bounded model reports | Upgrading a short test into installed/field acceptance |
| [tools/transport-lab](../../tools/transport-lab/README.md) | Controlled carrier and middlebox experiments | Production service deployment |
| [tools/witness](../../tools/witness/README.md) | Observer interpretation and packet/feature evidence | Owning the tunnel producer it observes |
| [tools/macos-utun-lab](../../tools/macos-utun-lab/README.md) | Explicit macOS lab controller | Signed NetworkExtension acceptance |
| [tools/windows/aegis-winctl](../../tools/windows/aegis-winctl/README.md) | Package verification, client/service/native lifecycle orchestration | A publisher certificate, signing provider or universal host acceptance |
| [scripts](../../scripts/README.md) / [packaging](../../packaging/README.md) | Host/build wrappers and package/service templates | Production algorithm decisions outside their Rust owner |
| [.github](../../.github/README.md) | Target-specific source/build/contract workflows | Manual release approval or installed field acceptance |

## Shared boundaries

- Ingress captures or admits application traffic; the carrier transports it;
  inner authentication and target policy independently authorize forwarding.
- Device authority issues/revokes client access. The relay enforces the current
  policy. The client manages its identity and stopped-ingress recovery.
- Native route/firewall/controller state belongs to the selected platform worker.
  A carrier change is not permission to reconfigure the host.
- Research selects an explicit compatible owner/profile before credentials or
  sockets. [The composition matrix](../research/implementation-and-composition.md)
  records consumer bindings and mathematical assumptions.
- Producer, observer and release verifier have separate responsibilities. A
  source test result does not stand in for independent capture or exact release approval.

## Where a document belongs

| Document | Home |
|---|---|
| Module files, API and local constraints | The module's own README |
| Cross-module contract / event ownership | `docs/architecture/` |
| Build/review/language/cache workflow | `docs/development/` |
| Native OS behavior or install profile | `docs/platforms/<os>/` / operator guide |
| Enrollment, relay, delivery or privileged operational procedure | `docs/operations/` |
| Model premises, algorithms and controlled research | `docs/research/` |
| Exact dated result | Existing audit/artifact path; preserve original bytes |
| Superseded status/spec | `docs/archive/`, with its date and original scope |

Parent: [documentation](../README.md).
