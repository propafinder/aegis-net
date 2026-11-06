# AEGIS Threat Model

**Canonical current security and privacy model, reconciled 2026-10-11.** This
model defines adversarial scope and evidence boundaries; it does not claim that
AEGIS defeats every listed attack. The [RKN/TSPU summary](../threat-model-rkn-tspu.md)
is a compatibility view of this model. The archived design model is historical.

The [October 10 security disposition register](../operations/security-audit-2026-10-10-findings.md)
and [repair/acceptance record](../operations/security-audit-2026-10-10.md) track all
92 findings. Source repair, controlled proof, deployed acceptance and release
approval are separate states. This documentation update closes none of those
findings, the eleven research acceptance gates, or beta exit.

The September 9 privacy review (archived: `docs/audit/user-data-protection-2026-09-09.md`) and
September 10 source audit (archived: `docs/audit/comprehensive-security-audit-2026-09-10.md`)
are historical checkpoints. September 11 remediation (archived: `docs/audit/security-remediation-2026-09-11.md`)
records successor source changes, including whole-stream inner TLS (F05),
device credentials/revocation (F07), selected state-key storage (F09), private
diagnostics (F10) and bootstrap freshness (F11). Older defects in those reviews
must be read with their successor evidence, not as current behavior for every
profile. The current register retains remaining acceptance requirements.

## Assets

- Ability to establish a relay session and recover after an endpoint fails.
- Application contents and destinations; timing, volume and endpoint metadata.
- Device private keys, legacy relay credentials and one-time issuance links.
- Local configuration, state, diagnostics and backups.
- Authentic installation and release selection, rollback/recovery safety.
- Operator evidence with a known source, configuration and measured boundary.

## Current trust and implementation boundaries

- **Client host:** local malware, an administrator or kernel access can inspect
  the process and its usable keys. File permissions, key stores and zeroization
  do not remove that trust assumption. Disk encryption remains host policy.
- **Access network:** observers can see outer endpoints, client handshake
  metadata, sizes and timing; they can block domains/IP ranges and inject loss,
  delay or resets. Routing through a CDN does not make a client handshake a
  browser handshake.
- **Terminating CDN:** outer TLS ends at the CDN. The enrolled inner TLS 1.3/mTLS
  channel is implemented for TCP and UDP application streams, including the
  destination and control exchange. Its application encryption ends at the
  relay. The CDN still sees outer addresses, hostname/route and traffic metadata.
  Legacy profiles without inner TLS retain the earlier application-stream
  confidentiality gap; application HTTPS supplies its own independent protection.
- **Enrolled device identity:** the device generates its private key locally;
  enrolled settings clear the legacy `auth_token`. Issuance, renewal, durable
  policy delivery and revocation are implemented in source. Dated local and fleet
  observations establish only their recorded configuration and lifecycle, not
  current acceptance of every relay/device or an automatic rollout. See
  [online enrollment](../operations/device-online-enrollment.md).
- **Relay administrator:** the relay terminates inner TLS and sees destinations,
  timing/volume and application protocols without their own encryption. AEGIS
  provides neither anonymity from its relay nor end-to-end secrecy to the final
  destination beyond the application's protocol.
- **Legacy issuance:** a legacy private bundle may contain a shared long-term
  relay key; a CDN delivering it is in that secret-delivery boundary. Expiring a
  URL does not revoke an already installed shared key. This historical risk is
  distinct from enrolled device-local keys and per-device revocation.
- **Legacy admission freshness:** the default v3 control codec authenticates a
  random client nonce and target with the shared secret, but does not check a
  server challenge, timestamp or consumed-nonce history. Random nonces alone do
  not reject a captured authenticated request replayed to another connection.
  This is distinct from confidentiality (T12) and application retry policy (T4).
  The opt-in `legacy-challenge-v1` feature implements raw-legacy v4 server
  challenge/proof with an admission deadline. Client/server default feature sets
  are empty: its presence in source does not protect the default v3 path or
  every carrier. The feature requires matching builds and the supported raw
  `legacy_tls`-only TCP profile; enrolled inner TLS is a separate identity and
  freshness boundary. Current installed-profile and fleet acceptance remain open.
- **Local storage:** normal runtime state is RAM-only unless the supported
  persistence option is explicitly enabled; relay/forensic state policy remains
  RAM-only. Persisted Brain state uses encrypted storage with one selected key
  backend. Compatibility `private_file` leaves an adjacent private key file;
  copying both ciphertext and key defeats that boundary. Explicit native-keyring
  migration verifies readback and removes the adjacent file rather than always
  duplicating a successful keyring write. It does not erase old snapshots, and
  systemd encryption/TPM provisioning remains operator policy. See
  [state-key storage](../operations/state-key-storage.md).
- **Diagnostics and forensic mode:** private defaults emit allowed event/error
  codes rather than raw destinations, fields or spans. An explicit JSONL path
  can persist those private codes; the supplied Linux service sets such a path.
  Runtime/build forensic policy does not initialize the event sink and constrains
  diagnostic/state behavior. Logging constructors, stderr/journal, existing
  files, OS metadata and other applications remain. This is not complete forensic
  privacy or a no-trace guarantee. See [private diagnostics](../operations/private-diagnostics.md).
- **Initial bootstrap:** authenticate the launcher/key/checker independently.
  Later signatures and hashes cannot repair an attacker-replaced initial trust
  anchor. Signed freshness/minimum-sequence and highest-seen-floor checks are
  implemented; they are not a full TUF/root-rotation architecture.
- **Shield helpers:** environment strings use repeating-key XOR decoding, which
  is obfuscation and provides no cryptographic secrecy. The current client calls
  the startup sentinel with debugger exit disabled; its debugger/VM observations
  warn. These helpers do not protect keys, a seized disk, or network metadata.

## Deployment and field risks

Multiple configured relays do not prove independent failure domains. Shared
provider/range, DNS, discovery, authority and ingress dependencies can disable a
whole pool together. Target-network availability, sustained delivered traffic,
recovery and current fleet identity/default-deny acceptance must be measured for
the exact deployed profiles. Dated lab or smoke results do not establish lasting
availability under commercial or state DPI, IP allowlists or CDN-wide blocks.

## Handshake, endpoint and classifier scope

An operator-owned hostname behind Cloudflare can keep an origin address out of
that client endpoint. Clear `SNI=<OPERATOR_DOMAIN>` remains a deployment marker
and can be filtered by domain; this does not impose a half-CDN blocking cost.
Direct-origin paths and historical address disclosure remain separate exposure.

The legacy feature-enabled AWS-LC/BoringSSL-family TCP and QUIC paths have
dated canonical JA4 (`evidence-archive/live/2026-08-10/chrome-canonical-ja4-parity/result.json`)
and QUIC JA4 (`evidence-archive/live/2026-08-11/quic-masque-ja4-parity`)
observations against live Chrome. The earlier custom cipher/extension hash
omitted signature algorithms and is superseded by the canonical observation.
Matching a JA4 string is not proof of byte-identical ClientHello or a whole
browser session. The configuration enum defaults to `chrome_like_experimental`,
but a featureless client build falls back to Rustls; enrolled profiles explicitly
choose Rustls. No current enrolled ClientHello/JA4 parity capture is recorded
(finding #30). HTTP/2/QUIC transport behavior and flow shape require their own
path-specific evidence.

Opt-in pinned ECH is implemented with fail-closed acceptance and requires
Rustls. Enrolled profiles may carry the pinned outer ECH configuration; this
does not combine ECH with the measured Chrome-like backend. QUIC/MASQUE ECH is
only a legacy path: MASQUE is not an inner-TLS enrolled fallback. ECH discovery,
configuration deployment and target-network availability remain separate gates.

The decoy keeps one stable identity per process and handles HEAD. The retained
active-probe artifact (`evidence-archive/live/2026-08-11/active-probe-resistance/result.json`)
records **0.375 against a 0.8 target, FAIL** (five of eight probes distinguished
its chosen control). Later notes identify control/metric instability and
individual fixes; they do not establish a passing adversarial gate. Current
branded primary paths remain finding #8. Active-probe resistance is **PARTIAL**.

Compatibility shaping changes application write sizes and timing; probabilistic
legacy write splitting does not insert padding or guarantee TLS-record splits.
[Opt-in traffic-privacy mechanisms](../operations/traffic-privacy.md) and the
[composition matrix](../research/implementation-and-composition.md) have distinct
source/runtime contracts. Inner application records and controlled local
composition do not prove fixed physical packets, trained-classifier immunity,
whole-flow differential privacy or target-network acceptance.

## Attack Matrix

The last column describes required evidence or its current boundary. It is not
an assertion that a named test currently passes.

| ID | Attack | Detection / Test | Mitigation and current boundary | Evidence gate |
|---|---|---|---|---|
| T1 | Static TLS fingerprint classification | Path-specific client handshake/witness capture | Legacy feature-enabled JA4 observations; enrolled Rustls parity unmeasured | Current exact-profile capture plus independent classifier evidence; no whole-session claim |
| T2 | DPI signature blocking | Adversarial rules and target-network trials | Transport selection and optional shaping; handshake/flow metadata remain | Reproducible adversarial result with declared classifier and distribution |
| T3 | Active probing against relay | Probe scenarios with justified controls | Stable per-process decoy; retained 0.375 FAIL and branded-path gap | PARTIAL; current justified corpus and reproducible passing result required |
| T4 | TCP reset injection | Bounded RST/failover scenario | Retry and failure classification subject to authenticated no-replay policy | Exact-profile recovery and delivery evidence |
| T5 | QUIC/MASQUE disruption | Fragmentation/loss/UDP-policy scenario | Legacy MASQUE and admitted fallback; inner TLS does not use MASQUE | Path-specific disruption and authenticated refusal evidence |
| T6 | Primary relay block | Runtime endpoint block test | Admitted pool and health/recent-outcome selection | Recovery KPI with independent delivered-application evidence |
| T7 | Primary bundle host block | Blocked-host fixture and dated mirror readback | `file://` fallback mechanism; public RC18 Yandex mirror, both architectures/nine files | Public distribution observation is separate from private enrollment and current reachability |
| T8 | Client binary string fingerprinting | Exact release-artifact opsec gate | Scanner is wired before signing/publication; bounded denylist coverage | Exact artifact PASS; does not prove no discoverable signature |
| T9 | Runtime log fingerprinting | Event/free-text and installed-unit review | Private default codes; explicit JSONL and forensic sink policy | Source policy implemented; retained data/journal/native acceptance separate |
| T10 | Platform-specific wide-capture regression | Exact native platform lifecycle gates | Protected platform capture, DNS, persistence and rollback boundaries | Current platform/package-specific acceptance; historical proof is insufficient |
| T11 | Malicious mirror substitutes a release | Signature and negative-integrity checks | Pinned Ed25519 signature verified before manifest fields; unsigned manifests refused even with `AEGIS_INSTALL_ALLOW_UNSIGNED=1` | Authenticated initial trust plus exact artifact/signature and negative evidence |
| T12 | Terminating CDN reads application bytes or access material | Profile and trust-boundary review | Inner TLS whole-stream protection/device-local key implemented for enrolled TCP/UDP; legacy gap remains | Source implemented; current issued profile, CDN/fleet and installed acceptance remain required |
| T13 | Offline disk copy exposes configuration, key and history | Actual backend, permissions and disk review | Selected key backend/migration implemented; private-file compatibility and old data remain | PARTIAL; host disk policy and native storage/lifecycle evidence required |
| T14 | One installed device's access must be revoked | Issuance/policy/rotation/revocation lifecycle | Per-device credentials and durable policy implemented; legacy shared keys require separate rotation | Source implemented and scoped observations exist; exact current rollout/lifecycle acceptance required |
| T15 | Diagnostics or history retain user activity | Source defaults, service and persisted-file inspection | Private codes/RAM defaults and forensic policy implemented; JSONL may be enabled by unit | PARTIAL; existing files, stderr/journal, detailed opt-in and native lifecycle remain separate |
| T17 | Replay of a captured legacy authenticated admission request | Exact-profile replay rejection and freshness checks | Default v3 codec has no server challenge/time/consumed-nonce check; opt-in raw-legacy v4 challenge/proof is separate and default-off | Source implementation is not default-path or fleet acceptance; A7 maps here, not to T12 |
| T16 | Initial bootstrap/verifier replacement or valid-old-release replay | Independent launcher pins, freshness/floor and recovery checks | Authenticated entry procedure plus signed freshness/minimum/highest-seen policy implemented | Source and controlled evidence; root rotation, trusted delivery and exact installed-release acceptance remain separate |

Tor is not a shipped or measured T7 fallback channel. Public mirrors, offline
kits and enrollment each need evidence of their own acquisition and trust path;
a transport name alone does not establish bootstrap resilience.

## Current evidence mapping

- Measurements live in `tools/witness/`, `tests/adversarial/`,
  `tools/measure/` and `scripts/build-external-calibration-summary.sh`;
  `aegis-knowledge/` contains priors, not independent proof of current behavior.
- Release opsec checks are integrated before signing and publication. Their
  bounded scanning does not remove endpoint metadata from history or establish
  complete public-tree sanitization. Privileged release acceptance is separate.
- [Windows encryption/endurance evidence](../platforms/windows/windows-encryption.md)
  records 42 controlled TCP/UDP/DNS Wintun cycles and eight induced relay breaks
  with synthetic material in September. It is broader than the earlier WFP TCP
  proof, but does not accept current package, reboot, IPv6, whole-machine capture
  or the current working relay pool.
- macOS source/lab capture and Linux source/lifecycle evidence have their own
  platform gates. Current native acceptance cannot be inferred from a historical
  SOCKS, PF, WFP, unit fixture or a later source change.

## Linkability minimization

DPI evasion and linkability are separate goals. A deployment can share a
classifier-visible family marker while avoiding a stable per-user marker. The
requirement is to avoid an unnecessary stable per-user/per-device/per-install
wire-visible identifier; it is an evidence gate, not a universal unlinkability
claim. Operators can create individual markers through isolated per-user relays,
pinned profiles or distinguishable configuration.

Drill J on 2026-05-31 examined a shared-relay topology
(`evidence-archive/live/2026-05-31/stable-wire-identity-audit/`). Its historical report
found no persistent `auth_key_id`-class per-user marker in the measured direct
and Cloudflare-fronted sessions. It reported no server resumption ticket or
QUIC NEW_TOKEN, fresh session CIDs, local-only fake-IP state, and a remaining
profile-pinning risk. These are dated observations of those profiles, not proof
of every current enrolled/legacy wire surface or current privacy acceptance.

The historical fronted capture included `SNI=<OPERATOR_DOMAIN>`, an endpoint
marker. That marker can be blocked or correlated, and endpoint isolation can
make a deployment marker user-specific. Historical legacy issuance also trusted
the delivering CDN with the bundled shared key; current enrolled device-local
key custody is a different boundary. Neither linkability observations nor
matching JA4 closes confidentiality, credentials, storage or forensic gates.

## Acceptance rule

Stronger README/operator claims require the relevant exact-profile independent
witness result, adversarial result, recovery/delivery measurement, bootstrap
survival, native platform lifecycle and exact-release checks. Source changes and
dated results must retain their own scope. All required CI jobs must finish
successfully for the exact final commit; in-progress, cancelled and failed runs
are not PASS. Documentation alignment alone is not security or beta acceptance.
