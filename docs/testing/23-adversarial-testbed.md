# Adversarial Testbed

The adversarial testbed is the Phase A2 measurement layer for AEGIS. Its purpose
is to test transports against explicit middlebox rules, network profiles, and
packet capture, then emit JSONL evidence that can be compared with witness
classification output.

## Current Boundary

The current repository state has a dry-run scaffold plus a bounded measured
command path:

- Scenario metadata is under `tests/adversarial/scenarios/`.
- Network profiles are under `tests/adversarial/network-profiles/`.
- Placeholder rule packs are under `tests/adversarial/rules/`.
- `cargo run -p aegis-measure -- adversarial-runner --dry-run` validates matrix wiring and emits
  `adversarial_scenario_planned` JSONL events.
- `cargo run -p aegis-measure -- adversarial-runner --live-command ... --scenario ... --network-profile ...`
  executes one selected operator probe and emits
  `adversarial_scenario_measured` JSONL events with `PASS`, `FAIL`, or
  `TIMEOUT`.
- `cargo run -p aegis-measure -- adversarial-runner --live-command ... --live-matrix` executes the
  bounded probe across the selected/default scenario/profile matrix.
- `scripts/run-adversarial-evasion-test.sh --dry-run` is the operator wrapper.
- `scripts/run-adversarial-evasion-test.sh --live-command ...` is the bounded
  measured operator wrapper.
- `scripts/run-adversarial-gateway-docker.sh` builds the gateway Docker image
  and runs the bounded measured command path inside it.

This is not DPI bypass proof by itself. A live claim requires the measured
command to run in a real gateway topology with packet capture, runtime events,
and an artifact under `evidence-archive/live/`.

## Historical release transport evidence (May 2026)

The then-selected `v0.3.7-windows-mvp-20260508` release had release-binary
Cloudflare HTTP-like proof in
`evidence-archive/live/2026-05-03/release-latest-cloudflare-fronted-live/`:
`https_ws` PASS and `grpc_stream` PASS. This does not claim MASQUE/UDP through
normal Cloudflare proxying, and it does not count `legacy_tls` as HTTP-like
camouflage. These May receipts do not certify the current RFC 8441 `https_ws`
implementation: the audited Cloudflare edge does not advertise that protocol.
Current fronted TCP uses forced `grpc_stream`; select current exact packages
and gates through [INSTALL](../../INSTALL.md).

## Adding A Scenario

Add `tests/adversarial/scenarios/<name>.toml`:

```toml
name = "legacy_tls"
transport = "legacy_tls"
description = "Legacy TLS adversarial dry-run scenario"
expected_threshold_key = "legacy_tls"
```

Then add or reuse a threshold in `tests/adversarial/expected.toml`.

## Dry Run

```bash
scripts/run-adversarial-evasion-test.sh \
  --dry-run \
  --scenario legacy_tls \
  --network-profile clean-fiber \
  --output-jsonl /tmp/aegis-adversarial.jsonl
```

## Bounded Measured Command

```bash
scripts/run-adversarial-evasion-test.sh \
  --scenario legacy_tls \
  --network-profile clean-fiber \
  --live-command "curl -fsS https://example.org/" \
  --output-jsonl /tmp/aegis-adversarial-measured.jsonl
```

This writes measured JSONL events, but the evidence boundary depends on where
the command runs. Localhost execution is command-health evidence only; gateway
execution with packet capture can become live adversarial evidence.

For a full bounded matrix run:

```bash
scripts/run-adversarial-evasion-test.sh \
  --live-matrix \
  --live-command "curl -fsS https://example.org/" \
  --output-jsonl /tmp/aegis-adversarial-measured-matrix.jsonl
```

An already archived A2 event stream can be imported into the Phase A gate:

```bash
scripts/run-phase-a-measure-gate.sh \
  --output-dir evidence-archive/live/YYYY-MM-DD/phase-a-measure-gate-imported \
  --witness-input-hex <tls-record-hex> \
  --adversarial-events-jsonl evidence-archive/live/YYYY-MM-DD/<a2>/events.jsonl
```

Imported evidence inherits its boundary from the source artifact. If the A2
events include `packet_evidence_status=present`, the gate review reports the
number of packet-backed records separately.

## Docker Gateway Wrapper

```bash
scripts/run-adversarial-gateway-docker.sh \
  --output-dir evidence-archive/live/YYYY-MM-DD/adversarial-gateway-smoke \
  --scenario legacy_tls \
  --network-profile clean-fiber \
  --live-command "curl -fsS https://example.org/"
```

This builds `tests/adversarial/Dockerfile.dpi-gateway`, runs the selected
scenario/profile in the container, and writes `events.jsonl` plus Docker logs.
The command must still exercise real AEGIS traffic before the artifact can be
used as live adversarial evidence.

## Wide Smoke Runtime Bridge

Linux wide/TPROXY smoke artifacts can be converted into A2 measured JSONL when
they include a healthy `contract.json` and `runtime-events.jsonl`:

```bash
scripts/build-adversarial-events-from-wide-smoke.sh \
  --contract-json evidence-archive/live/YYYY-MM-DD/<smoke>/contract.json \
  --runtime-events-jsonl evidence-archive/live/YYYY-MM-DD/<smoke>/runtime-events.jsonl \
  --packet-capture evidence-archive/live/YYYY-MM-DD/<smoke>/packets.pcap \
  --tcpdump-log evidence-archive/live/YYYY-MM-DD/<smoke>/debug/tcpdump.log \
  --output-jsonl evidence-archive/live/YYYY-MM-DD/<smoke>/adversarial-events.jsonl
```

The bridge requires runtime evidence for `ingress_udp_datagram_observed`,
`relay_session_succeeded`, and `ingress_udp_datagram_completed`; unhealthy smoke
contracts emit a failed measured event and return non-zero. When
`--packet-capture` is provided, the bridge also requires a non-empty pcap file
so A2 evidence can be tied to both runtime events and captured network traffic.
The emitted event includes `packet_evidence_status`,
`packet_capture_size_bytes`, `tcpdump_packets_captured`, and
`tcpdump_packets_dropped_by_kernel` for downstream gate review.

## Hostile Classifier Summary

The Phase A gate writes a hostile classifier summary for every run:

```bash
scripts/build-hostile-classifier-summary.sh \
  --adversarial-jsonl evidence-archive/live/YYYY-MM-DD/<a2>/events.jsonl \
  --classifier-jsonl evidence-archive/live/YYYY-MM-DD/<classifier>/verdicts.jsonl \
  --output-json evidence-archive/live/YYYY-MM-DD/<gate>/classifier/summary.json \
  --output-markdown evidence-archive/live/YYYY-MM-DD/<gate>/classifier/summary.md
```

Classifier verdict records use `event=hostile_classifier_verdict` and a
`status`/`verdict` such as `NO_ALERT`, `CLEAN`, `ALERT`, or `BLOCKED`. If no
classifier JSONL is provided, the summary status is `NOT_RUN`; that is an
explicit open gate, not a pass. `run-phase-a-measure-gate.sh` accepts
`--hostile-classifier-jsonl` and reports the classifier status next to A2 packet
evidence.

For archived pcaps, the operator wrapper runs Suricata and nDPI and writes
verdict JSONL:

```bash
scripts/run-hostile-classifier-pcap.sh \
  --pcap evidence-archive/live/YYYY-MM-DD/<smoke>/packets.pcap \
  --output-dir evidence-archive/live/YYYY-MM-DD/<classifier> \
  --scenario masque_derived \
  --transport masque_derived
```

When the capture is Linux cooked v2 (`tcpdump -i any`, link type 276), the
wrapper keeps the original pcap for Suricata and derives a raw-IP copy for
`ndpiReader`, which does not support that datalink in the tested 4.2 builds.

> Suricata availability (corrected 2026-06-02): Suricata ships in **Ubuntu
> 24.04 universe** (`apt install suricata` → 7.0.3); an earlier note that it
> was "not in the default repo" was wrong. Latest witness pass
> (`evidence-archive/live/2026-05-31/phase5-witness-adversarial-matrix/`): Suricata
> 7.0.3 with the `suricata-update` ET-open ruleset (66269 rules) over the two
> CF-fronted TCP witness pcaps (`https_ws`, `grpc_stream`) produced **0 alerts
> and 0 anomaly events**; all flows parsed as TLS 1.3 with the correct SNI, and
> client JA3 was distinct across all 5 sessions per transport (per-handshake
> extension-order randomization — no stable per-user TLS fingerprint).

## Phase A Exit Review

The gate review describes the current evidence bundle. The stricter exit review
decides whether Phase A is actually ready to close:

```bash
scripts/build-phase-a-exit-review.sh \
  --gate-review-json evidence-archive/live/YYYY-MM-DD/<gate>/phase-a-gate-review.json \
  --calibration-json evidence-archive/live/YYYY-MM-DD/<gate>/calibration/summary.json \
  --classifier-json evidence-archive/live/YYYY-MM-DD/<gate>/classifier/summary.json \
  --threat-model docs/security/22-threat-model.md \
  --knowledge-architecture docs/architecture/27-knowledge-architecture.md \
  --output-json evidence-archive/live/YYYY-MM-DD/<gate>/phase-a-exit-review.json \
  --output-markdown evidence-archive/live/YYYY-MM-DD/<gate>/phase-a-exit-review.md
```

It requires witness combined score `>=0.70` and adversarial pass rate `>=0.85`
for `legacy_tls`, `https_ws`, and `masque_derived`, plus hostile classifier
`PASS`, knowledge `PASS`, applied Brain calibration, and the required docs.
Until all are true, the status is `NOT_EXIT_READY`.

## Phase B Baseline Review

Once Phase A exits, materialize the optimization baseline before changing
traffic-shape knobs:

```bash
scripts/build-phase-b-baseline-review.sh \
  --phase-a-exit-json evidence-archive/live/YYYY-MM-DD/<gate>/phase-a-exit-review.json \
  --calibration-json evidence-archive/live/YYYY-MM-DD/<gate>/calibration/summary.json \
  --gate-review-json evidence-archive/live/YYYY-MM-DD/<gate>/phase-a-gate-review.json \
  --classifier-json evidence-archive/live/YYYY-MM-DD/<gate>/classifier/summary.json \
  --output-json evidence-archive/live/YYYY-MM-DD/<gate>/phase-b-baseline-review.json \
  --output-markdown evidence-archive/live/YYYY-MM-DD/<gate>/phase-b-baseline-review.md
```

This is the first Phase B control surface. It requires Phase A `EXIT_READY`,
applied Brain calibration, hostile classifier `PASS`, witness combined score
`>=0.50`, and adversarial pass rate `>=0.70` for primary transports.

Relay request-shape diversity is held separately by:

```bash
scripts/test-phase-b-relay-surface-contract.sh
```

That contract samples the Rust relay surface catalog and checks profile
coverage, path-pool coverage, request header axes, and bounded distribution.

JA3/browser profile targets are exported from the reviewed knowledge corpus:

```bash
scripts/build-phase-b-ja3-targets.sh \
  --output evidence-archive/live/YYYY-MM-DD/<gate>/phase-b-ja3-targets.json
```

The target artifact is a tuning input for later TLS/profile work; it does not
change runtime TLS behavior by itself.

The runtime/config telemetry surface for selecting a target class is guarded by:

```bash
scripts/test-phase-b-tls-profile-target-contract.sh
```

`relay.tls_profile_target_class` is advisory in this slice. It is emitted in
relay surface runtime fields as `relay_surface_tls_profile_target_class` plus
`relay_surface_tls_profile_target_alpn` so a later TLS adapter can be measured
against the exported JA3 target artifact.
The same relay surface events publish `relay_surface_write_chunk_size` and
`relay_surface_inter_chunk_delay_ms`, which make the existing chunk/timing
shape observable in Phase B artifacts.

Chunk/timing shape evidence can be reviewed with:

```bash
cargo run -q -p aegis-measure -- phase-b-relay-shape-review \
  --runtime-events-jsonl <runtime-events.jsonl> \
  --output-json <phase-b-relay-shape-review.json>
```

For the `legacy_tls` target class, the first wire adapter is opt-in: when the
target class is explicitly `legacy_tls`, the legacy TLS connector offers
`http/1.1` ALPN. Other target classes keep legacy TLS wire behavior unchanged
until their adapters are added and tested. Transport selected/succeeded/failed
events also publish the actual wire surface as `relay_surface_tls_wire_adapter`
and `relay_surface_tls_wire_alpn`, so Phase B can compare requested target ALPN
against the transport adapter that was actually used.

Runtime evidence can be reviewed with:

```bash
cargo run -q -p aegis-measure -- phase-b-tls-wire-review \
  --runtime-events-jsonl <runtime-events.jsonl> \
  --output-json <phase-b-tls-wire-review.json>
```

Active stall-probe evidence can be reviewed with:

```bash
cargo run -q -p aegis-measure -- phase-b-active-probe-review \
  --runtime-events-jsonl <runtime-events.jsonl> \
  --output-json <phase-b-active-probe-review.json>
```

For live two-VPS runtime evidence, `aegis-client` also exposes a bounded Rust
evidence command that runs the active stall-probe executor directly against a
real target and writes the normal active-probe JSONL events:

```bash
aegis-client \
  --config /etc/aegis/client/aegis.toml \
  --runtime-events-jsonl /tmp/direct-active-probe-runtime-events.jsonl \
  --direct-active-probe-evidence <target-ip:port> \
  --json
```

The Phase B live evidence aggregator combines the baseline, TLS wire,
relay-shape, and active-probe reviews:

```bash
scripts/build-phase-b-live-evidence-review.sh \
  --baseline-json <phase-b-baseline-review.json> \
  --tls-wire-json <phase-b-tls-wire-review.json> \
  --relay-shape-json <phase-b-relay-shape-review.json> \
  --active-probe-json <phase-b-active-probe-review.json> \
  --output-json <phase-b-live-evidence-review.json>
```

For a runtime artifact directory, the convenience bundle builder materializes
the runtime-derived Phase B reviews and the aggregate verdict:

```bash
scripts/build-phase-b-runtime-evidence-bundle.sh \
  --baseline-json <phase-b-baseline-review.json> \
  --runtime-events-jsonl <runtime-events.jsonl> \
  --output-dir <artifact-dir>/phase-b-runtime-evidence \
  --require-relay-shape-diversity \
  --require-finished-probe
```

If the live artifact already contains `phase-b-baseline-review.json` and
`runtime-events.jsonl`, the shorter form is:

```bash
scripts/build-phase-b-runtime-evidence-bundle.sh \
  --artifact-dir <artifact-dir> \
  --require-relay-shape-diversity \
  --require-finished-probe
```

The bundle writes `phase-b-runtime-evidence.manifest.json` and `.md` beside the
individual review artifacts. The manifest is the compact artifact-level status
to hand off after a live run.
It also writes `phase-b-master-plan-status.json` and `.md`, which maps runtime
evidence back to the Phase B master-plan areas while keeping Phase B exit
explicitly `EXIT_NOT_CLAIMED` until score and parity gates are satisfied.
For live evidence capture, pass `--allow-review-failures` when the operator
needs a complete blocked bundle rather than an early fail-fast stop. The default
mode remains fail-fast for release/contract gates.

The canonical two-VPS live wrapper can also materialize the Phase B runtime
bundle as part of the clean purge/redeploy audit:

```bash
scripts/run-linux-wide-mimicry-live-audit.sh \
  --server-host <relay-vps> \
  --client-host <client-vps> \
  --ssh-user <user> \
  --output-dir <artifact-dir> \
  --phase-b-baseline-json <phase-b-baseline-review.json>
```

This writes the usual `live-audit.manifest.json` / `live-audit-summary.md` /
`live-audit-handoff-status.json` artifacts plus
`phase-b-runtime-evidence/phase-b-master-plan-status.json`. If live runtime
evidence is incomplete, the Phase B status is materialized as blocked instead
of being lost behind an orchestration failure.
The wrapper's transient runtime harvest includes multiple relay-shape scenarios
for strict diversity and the Rust direct active-probe evidence command above
for `--phase-b-runtime-evidence-strict`.
For witness-correlated hostile-path validation, provide both a remote pcap path
and the client egress interface:

```bash
scripts/run-linux-wide-mimicry-live-audit.sh \
  --server-host <relay-vps> \
  --client-host <client-vps> \
  --ssh-user <user> \
  --output-dir <artifact-dir> \
  --phase-b-baseline-json <phase-b-baseline-review.json> \
  --phase-b-runtime-evidence-strict \
  --remote-client-pcap /tmp/aegis-wire-witness.pcapng \
  --remote-client-pcap-interface eth0
```

The wrapper starts tcpdump before transient relay/direct evidence, stops it
before download, builds `client/wire-witness-summary.json` against the merged
wire-helper runtime JSONL, then feeds that witness summary into wire and stealth
acceptance.

After witness-correlated stealth acceptance is green, materialize the transport
camouflage validation gate with the live manifest, stealth bundle, wire
acceptance, relay-surface runtime summary, hostile classifier summary, and the
witness pcap:

```bash
scripts/build-transport-camouflage-validation.sh \
  --live-manifest-json <artifact-dir>/live-audit.manifest.json \
  --stealth-bundle-json <artifact-dir>/stealth-live-acceptance/stealth-live-acceptance-bundle.json \
  --wire-acceptance-json <artifact-dir>/client/wire-host-acceptance-summary.json \
  --relay-surface-json <artifact-dir>/stealth-live-acceptance/hostile-path-acceptance/relay-surface-runtime/relay-surface-runtime-summary.json \
  --classifier-summary-json <artifact-dir>/transport-camouflage/classifier-summary.json \
  --witness-pcap <artifact-dir>/client/wire-witness-capture.pcapng \
  --output-json <artifact-dir>/transport-camouflage/transport-camouflage-validation.json \
  --output-markdown <artifact-dir>/transport-camouflage/transport-camouflage-validation.md
```

This gate is intentionally stricter than stealth acceptance. It requires the
previous live/wire/relay layers to remain green and also requires hostile
classifier status `PASS`; missing Suricata or `ndpiReader` verdicts produce a
`BLOCKED` artifact with next action
`run_or_install_hostile_classifiers_for_witness_pcap`.
For nDPI, the classifier verdict path also parses `Risk stats`; a completed
`ndpiReader` run with risk entries is downgraded from `CLEAN` to `DETECTED`,
and transport camouflage validation points the next action at
`tune_transport_camouflage_until_hostile_classifiers_pass`.
Use a relay-only pcap for this gate. The wire witness capture intentionally
includes direct active-probe traffic for the wire matrix; classify a pcap
filtered to the relay port when measuring relay transport camouflage, otherwise
HTTP direct-probe traffic can create false transport-surface blockers. DNS
`relay.server_name` is the SNI/HTTP authority; keep `relay.server` as the IP
dial target when testing IP fallback with DNS SNI.
For the HTTP-like camouflage acceptance gate, run the live audit with
`--relay-transport-priority https_ws,grpc_stream,masque_derived` so the witness
pcap excludes the legacy/raw TLS path. Full rotation with `legacy_tls` remains
a stricter tuning surface; if nDPI reports `TLS (probably) Not Carrying HTTPS`
there, keep that result as a separate blocker instead of weakening the
HTTP-like gate or overriding classifier evidence.

The manifest can be checked after copying or archiving with:

```bash
cargo run -q -p aegis-measure -- phase-b-runtime-evidence-manifest-check \
  --manifest-json <phase-b-runtime-evidence.manifest.json>
```

After transport camouflage validation is `READY`, materialize the Phase B
score/parity gate:

```bash
scripts/build-phase-b-score-parity-gate.sh \
  --baseline-json <phase-b-baseline-review.json> \
  --runtime-manifest-json <artifact-dir>/phase-b-runtime-evidence/phase-b-runtime-evidence.manifest.json \
  --transport-camouflage-validation-json <artifact-dir>/transport-camouflage/transport-camouflage-validation.json \
  --witness-wire-correlation-json <artifact-dir>/client/wire-host-acceptance-summary.json \
  --two-vps-parity-json <artifact-dir>/two-vps-parity-evidence.json \
  --classifier-summary-json <artifact-dir>/transport-camouflage/classifier-summary.json \
  --live-manifest-json <artifact-dir>/live-audit.manifest.json \
  --output-json <artifact-dir>/phase-b-score-parity-gate.json \
  --output-markdown <artifact-dir>/phase-b-score-parity-gate.md
```

This gate does not override the score formula or add a hard-coded calibration
weight. It treats calibration as baseline evidence, requires witness combined
score `>=0.70`, adversarial pass rate `>=0.85`, runtime evidence `BUNDLE_READY`,
transport camouflage `READY`, hostile classifier summary `PASS`, green live
acceptance, witness correlation `matched`, active-probe evidence, two distinct
VPS hosts, and explicit server/client platform evidence. The HTTP-like
camouflage scope must also prove `legacy_tls_included=false`; legacy/raw TLS
classifier tuning stays separate and is not silently counted as green here.

The local Phase B evidence plumbing contract is:

```bash
scripts/test-phase-b-evidence-contract.sh
scripts/test-phase-b-score-parity-gate-contract.sh
```

## Phase C Resilience Gate

After Phase B score/parity is `EXIT_READY`, Phase C opens with an explicit
resilience gate:

```bash
scripts/build-phase-c-resilience-gate.sh \
  --phase-b-score-parity-json <artifact-dir>/phase-b-score-parity-gate.json \
  --multi-relay-json <phase-c-multi-relay-evidence.json> \
  --bundle-mirrors-json <phase-c-bundle-mirrors-evidence.json> \
  --fronted-transport-json <phase-c-fronted-transport-evidence.json> \
  --output-json <artifact-dir>/phase-c-resilience-gate.json \
  --output-markdown <artifact-dir>/phase-c-resilience-gate.md
```

The Phase C evidence inputs are optional so the gate can materialize a
blocked artifact at entry. It requires multi-relay primary-block recovery
`median <30s`, mid-session survival, single-relay backward compatibility, at
least two observed relay endpoints in `observed_relay_servers`, bundle
mirror/voucher/signed-bundle evidence, and fronted MASQUE pass rate `>=0.95`
with documented provider constraints. Missing evidence remains
`PHASE_C_RESILIENCE_BLOCKED`; it is not inferred from Phase B success.

Multi-relay evidence can be reviewed directly from relay runtime JSONL:

```bash
scripts/build-phase-c-multi-relay-evidence.sh \
  --runtime-events-jsonl <runtime-events.jsonl> \
  --single-relay-backward-compatible \
  --output-json <artifact-dir>/phase-c-multi-relay-evidence.json \
  --output-markdown <artifact-dir>/phase-c-multi-relay-evidence.md
```

For current-build two-VPS live slices, endpoint-pool bundles can be installed
without remote config surgery by passing repeated `--relay-endpoint` values and
an optional scoped relay priority:

```bash
scripts/redeploy-two-vps-current-bundle.sh \
  --bundle-archive <aegis-linux-x86_64.tar.gz> \
  --relay-endpoint <blocked-primary,server-name> \
  --relay-endpoint <working-secondary,server-name> \
  --relay-transport-priority https_ws,grpc_stream \
  ...
```

The strict HTTP-like failover slice should keep `legacy_tls` out of the scoped
transport priority; legacy/raw TLS remains a separate tuning target.

Bundle mirror/voucher evidence is reviewed separately before feeding Phase C:

```bash
scripts/build-phase-c-bundle-mirrors-evidence.sh \
  --primary-fetch-json <primary-fetch-blocked.json> \
  --mirror-fetch-json <mirror-fetch-pass.json> \
  --voucher-flow-json <voucher-expiry-revoke.json> \
  --bundle-archive <signed-bundle.tar.gz> \
  --bundle-sha256 <signed-bundle.tar.gz.sha256> \
  --operator-doc <mirror-voucher-runbook.md> \
  --output-json <artifact-dir>/phase-c-bundle-mirrors-evidence.json \
  --output-markdown <artifact-dir>/phase-c-bundle-mirrors-evidence.md
```

The reviewer requires the primary bundle host to be blocked while mirror fetch
still passes with the expected checksum, voucher semantics to prove issue,
single-use reject, expiry reject, and revoke reject, the bundle archive to keep
its manifest/checksum verification surface, and operator docs to mention both
mirror and voucher handling.

> **Tor fallback was removed.** In the RKN/ТСПУ threat model Tor is
> counterproductive — its traffic is DPI-classified on sight and Russian ISPs
> block the public exit-node set — so a Tor bundle fetch fails exactly where it
> is needed and its use is itself a flag. Bootstrap resilience is measured
> through fronted CDN delivery, signed mirrors, and the voucher flow only.

CDN/fronted transport evidence is reviewed from measured attempts:

```bash
scripts/build-phase-c-fronted-provider-preflight.sh \
  --front-authority <provider-fronted-authority> \
  --front-masque-server <provider-edge-or-fronted-host:443> \
  --origin-relay-address <origin-relay-host:443> \
  --provider-doc <fronted-provider-constraints.md> \
  --output-json <artifact-dir>/phase-c-fronted-provider-preflight.json \
  --output-markdown <artifact-dir>/phase-c-fronted-provider-preflight.md

scripts/build-phase-c-fronted-transport-evidence.sh \
  --attempts-jsonl <fronted-transport-attempts.jsonl> \
  --provider-doc <fronted-provider-constraints.md> \
  --output-json <artifact-dir>/phase-c-fronted-transport-evidence.json \
  --output-markdown <artifact-dir>/phase-c-fronted-transport-evidence.md
```

The reviewer requires fronted transport pass rate `>=0.95`, documented provider
constraints, coverage for a normal fronted scenario (`normal_fronted_https_ws`,
`normal_fronted_grpc_stream`, or the legacy `normal_fronted_masque` fixture),
`primary_path_blocked`, and `provider_edge_rotation`, and explicit
provider-boundary metadata proving the front authority is not a raw IP and the
fronted provider endpoint is not the origin relay host. It does not infer
CDN/fronted readiness from relay-only, multi-relay, or same-VPS self-fronting
success.
The live runner executes the same Rust preflight before any fresh purge/redeploy
so invalid provider inputs fail before touching the VPS pair.

For a real two-VPS run, use the live runner only after a provider/fronted
HTTP-like authority and edge target are configured:

```bash
scripts/run-phase-c-fronted-transport-two-vps-live.sh \
  --artifact-dir <artifact-dir> \
  --server-host <ubuntu-server-vps> \
  --client-host <debian-client-vps> \
  --ssh-user root \
  --bundle-archive <current-linux-bundle.tar.gz> \
  --front-authority <provider-fronted-authority> \
  --front-edge-server <provider-edge-or-fronted-host:443> \
  --front-transport-scope https_ws \
  --provider-doc <fronted-provider-constraints.md> \
  --phase-b-score-parity-json <phase-b-score-parity-gate.json> \
  --multi-relay-json <phase-c-multi-relay-evidence.json> \
  --bundle-mirrors-json <phase-c-bundle-mirrors-evidence.json>
```

The runner deliberately starts with `redeploy-two-vps-current-bundle.sh`, so it
purges previous AEGIS installs/tests from both VPS hosts before measuring. For
Cloudflare HTTP proxy proof it preserves the Origin CA certificate/key outside
`/etc/aegis` before the destructive purge, restores them after redeploy,
restarts `aegis-server`, and compares the served certificate fingerprint to the
preserved fingerprint before measuring. If the cert/key are missing, it stops
before purge with `BLOCKED_BY_ORIGIN_CERT_MISSING`; if restore or served
fingerprint verification fails, it stops with `ORIGIN_CERT_RESTORE_FAILED`.

For fronted HTTP-like proof, the generated client bundle must dial the provider
edge host first, for example `relay.example.org:443`, while the origin relay address
is recorded as provider-boundary evidence. The runner records the three required
attempt scenarios, builds `phase-c-fronted-transport-evidence.json`, and
refreshes the Phase C gate when the other gate inputs are provided.

Historical Cloudflare Phase C live result (3 May 2026; current `https_ws` is
not accepted by the audited edge). The endpoint and egress spellings in the
summary below are redacted placeholders representing private measured values.
They are illustrative replacements, not literal transcripts or measurements
of example addresses/domains. Original private artifacts remain unchanged:

- Artifact:
  `evidence-archive/live/2026-05-03/phase-c-cloudflare-https-ws-fronted-live/`.
- `https_ws`: PASS through Cloudflare HTTP proxy. Runtime events show
  `relay_server = <PRIVATE_FRONTED_AUTHORITY>:443`, selected transport `HttpsWs`, and
  `relay_session_succeeded`.
- SOCKS egress proof: `https://api.ipify.org` through the client SOCKS proxy
  returned the private relay egress address (`<PRIVATE_RELAY_EGRESS>` here).
- Cloudflare Full strict: PASS; no `526` after Origin CA restore.
- `grpc_stream`: PASS through Cloudflare HTTP proxy. Runtime events in
  `evidence-archive/live/2026-05-03/phase-c-cloudflare-grpc-stream-fronted-live/`
  show planned transports `["GrpcStream"]`, selected transport `GrpcStream`,
  and `relay_session_succeeded`; SOCKS egress returned the private relay egress address (`<PRIVATE_RELAY_EGRESS>` here).
- MASQUE/UDP through normal Cloudflare orange-cloud proxy, Cloudflare Spectrum,
  and `legacy_tls` HTTP-like camouflage PASS are not claimed.

The reviewer requires at least two observed `relay_server` values, a
`relay_transport_failed` followed by `relay_session_succeeded` on a different
relay, median recovery `<30s`, and explicit single-relay compatibility evidence.
Single-relay runs are useful evidence, but they remain `FAIL` for the
multi-relay Phase C gate.

Server-side bundle generation can include endpoint pools for current-build
multi-relay tests:

```bash
./install.sh server \
  --relay-address relay-a.example.org:443 \
  --server-name relay-a.example.org \
  --relay-endpoint relay-a.example.org:443,relay-a.example.org \
  --relay-endpoint relay-b.example.org:443,relay-b.example.org,relay-b.example.org:443
```

This writes `relay.endpoints = [...]` into both generated client profiles.
Omit `--relay-endpoint` to keep the backward-compatible single-relay config.

## Phase D Reach Gate

Phase D can be prepared while Phase C is still blocked, but it cannot exit
until Phase C is `EXIT_READY` and platform reach evidence avoids overstated
capture claims:

```bash
scripts/build-phase-d-reach-gate.sh \
  --phase-c-resilience-json <phase-c-resilience-gate.json> \
  --windows-reach-json <windows-reach-evidence.json> \
  --macos-reach-json <macos-reach-evidence.json> \
  --android-reach-json <android-reach-evidence.json> \
  --output-json <artifact-dir>/phase-d-reach-gate.json \
  --output-markdown <artifact-dir>/phase-d-reach-gate.md
```

The gate distinguishes `PHASE_D_PREP_READY` from `PHASE_D_EXIT_READY`.
Windows controlled WFP evidence is not broad Windows capture; macOS PF evidence
is not system-wide macOS capture; Android remains PoC-only until a Rust/JNI
build and VpnService flow are proven.

Windows service reach evidence requires more than a successful SOCKS probe. The
Rust reviewer only counts the service baseline when the artifact proves the
service was installed, started, the SOCKS listener was verified, SOCKS egress
worked, and no broad Windows capture claim is hidden behind the service result.
Optional Windows exit proofs are not accepted from generic `status=PASS` JSON:
each proof artifact must also carry its specific boolean key, such as
`dns_policy_proven=true`, `udp_policy_proven=true`, `ipv6_policy_proven=true`,
`service_persistence_proven=true`, or `rollback_matrix_proven=true`.

Android PoC prep evidence can be materialized by the Rust `aegis-measure`
reviewer from the Rust JNI crate:

```bash
scripts/build-phase-d-android-reach-evidence.sh \
  --output-json <artifact-dir>/android-reach-evidence.json \
  --output-markdown <artifact-dir>/android-reach-evidence.md
```

This only proves the Rust-owned JNI surface compiles and tests. It keeps
`vpnservice_basic_flow_proven=false` unless an explicit measured VpnService
flow artifact is provided with both `status=PASS` or `verdict=PASS` and
`vpnservice_basic_flow_proven=true`. The artifact must also identify
`feature=android_vpnservice_basic_flow`, `platform=Android`,
`scope=vpnservice_poc`, `tun_packet_flow_observed=true`,
`relay_session_succeeded=true`, and no production claim; a handwritten PASS
flag alone is rejected.

The current Android runtime proof runner is:

```bash
scripts/android/run-vpnservice-basic-flow-proof.sh \
  <artifact-dir> \
  --expected-egress <relay-egress-ip>
```

It is deliberately blocking-first: without `adb`, a connected Android device,
an installed AEGIS Android package, and an app-side VpnService runtime harness,
it writes `status=BLOCKED` and `vpnservice_basic_flow_proven=false`.

macOS reach evidence must be materialized from measured PF/SOCKS/LaunchDaemon
utun W0 lab and NetworkExtension artifacts, not from handwritten status JSON:

```bash
scripts/build-phase-d-macos-reach-evidence.sh \
  --pf-artifact <macos-pf-apply-cleanup-artifact> \
  --foreground-socks-artifact <macos-foreground-socks-artifact> \
  --launchdaemon-socks-artifact <macos-launchdaemon-socks-artifact> \
  --utun-lab-artifact <macos-utun-helper-fd-loop-lab-artifact> \
  --utun-w1-artifact <macos-utun-w1-controlled-route-proof-lab-artifact> \
  --utun-w2-artifact <macos-utun-w2-stateful-tcp-edge-proof-lab-artifact> \
  --utun-w3-artifact <macos-utun-w3-local-relay-bridge-proof-lab-artifact> \
  --utun-w4-artifact <macos-utun-w4-policy-cleanup-matrix-lab-artifact> \
  --utun-w5-artifact <macos-utun-w5-controlled-external-relay-path-lab-artifact> \
  --network-extension-artifact <macos-networkextension-artifact> \
  --output-json <artifact-dir>/macos-reach-evidence.json \
  --output-markdown <artifact-dir>/macos-reach-evidence.md
```

PF apply/cleanup proof and SOCKS/LaunchDaemon proof are prep evidence only.
macOS utun W0-W4 proofs are LAB evidence only. W0 proves privileged helper
creation, `SCM_RIGHTS` FD transfer to the non-root client, the 4-byte utun
family header, packet observation, and cleanup. W1 proves one controlled IPv4
`/32` route with relay IP exclusion and route cleanup. W2/W2.1 prove the lab
TCP packet-to-flow edge through SYN/SYN-ACK/ACK. W3 proves a local AEGIS relay
bridge trigger. W4 records the explicit policy and cleanup matrix: controlled
TCP IPv4 is captured only for the lab `/32` route, DNS/UDP/IPv6 are
`OUT_OF_SCOPE`, the default route is unchanged, and cleanup removes only
AEGIS-owned route/interface state. W5 adds a controlled external IPv4 `/32`
route plus existing Cloudflare `https_ws` relay path linkage, while preserving
relay IP exclusion, cleanup, and no default-route claim. These are not
NetworkExtension replacements,
not product-ready macOS wide, not default-route capture, and not broad
DNS/UDP/IPv6 capture claims. The current accepted W4 lab artifact is
`evidence-archive/live/2026-05-03/macos-utun-w4-policy-cleanup-matrix-lab/`.
The current accepted W5 lab artifact is
`evidence-archive/live/2026-05-03/macos-utun-w5-controlled-external-relay-path-lab/`.
NetworkExtension must have signed runtime system-wide proof before macOS can
be counted as Phase D exit-ready. The accepted NetworkExtension artifact must
identify `feature=macos_networkextension_system_wide_proof`,
`platform=macOS`, `scope=networkextension_packet_tunnel_ipv4_tcp`, signed
app/extension proof, NetworkExtension entitlement proof, approved VPN
configuration, observed packet-tunnel runtime, relay session success, no manual
proxy use, and cleanup restoring the direct path. A handwritten
`network_extension_system_wide_proven=true` flag alone is rejected.

The current macOS NetworkExtension proof runner is:

```bash
scripts/macos/run-networkextension-system-wide-proof.sh \
  <artifact-dir> \
  --expected-egress <relay-egress-ip> \
  --host-app <signed-host-app-path> \
  --extension-bundle <signed-packet-tunnel-extension-path>
```

It is deliberately blocking-first and writes `status=BLOCKED` until the signed
Packet Tunnel runtime path exists and is observed live.

## Master Plan Handoff

The current Phase C/Phase D gate pair can be reduced to one operator handoff
artifact:

```bash
scripts/build-master-plan-handoff.sh \
  --phase-c-resilience-json <phase-c-resilience-gate.json> \
  --phase-d-reach-json <phase-d-reach-gate.json> \
  --artifact-dir <artifact-dir>/master-plan-current-handoff \
  --output-json <artifact-dir>/master-plan-current-handoff/master-plan-handoff.json \
  --output-markdown <artifact-dir>/master-plan-current-handoff/master-plan-handoff.md

cargo run -q -p aegis-measure -- master-plan-handoff-check \
  --handoff-json <artifact-dir>/master-plan-current-handoff/master-plan-handoff.json
```

The handoff gives one primary layer, next action id, reason, command template,
expected artifact, and, when applicable, a follow-up command plus expected
follow-up artifact. When a Phase C gate includes artifact paths for already
green prerequisites, the follow-up command reuses those exact paths; placeholders
remain only for the still-missing provider/VPS inputs. If Phase C is still
blocked by CDN/fronted transport, the handoff keeps Phase C ahead of Phase D
reach work so platform prep does not hide the unresolved resilience exit gate.
It also reports `prerequisites.phase_c_fronted_followup.*.exists`, making it
clear whether the non-provider inputs needed by the next live runner are already
present on disk. `external_inputs.phase_c_fronted_live` lists the still-missing
operator/provider values such as VPS hosts, bundle archive, front authority,
provider edge, provider constraints doc, and origin relay address.

After `release-latest-parity-gate/result.json` is `PASS` /
`RELEASE_LATEST_PARITY_READY`, the handoff must not point back at
`release_latest_parity`, but it also must not mark desktop/core complete. The
current post-release handoff first advanced to
`ubuntu_wide_tproxy_latest_stable_release_proof`; after that proof passed for
the current latest/stable release, the active blocker became
`implement_traffic_shape_scoring_and_per_transport_relay_only_pcap_matrix`.
Ubuntu wide latest/stable is now PASS. The HTTP-like mimicry matrix now has
multi-profile relay-only witness evidence for `https_ws` and `grpc_stream`, with
per-transport pcap, nDPI/Suricata counts, timing/ratio summaries, runtime
linkage, measured JA3/JA4, and Rust witness scores. It remains PARTIAL because
separate controlled WebSocket/gRPC reference endpoints now have Cloudflare-fronted
`clean_fiber` pcaps only; AEGIS tunnel traffic is not reused as the only reference
baseline. Brain operational runtime
loop remains not complete.
Phase C remains `EXIT_READY`; Phase D remains `PHASE_D_PREP_READY`, not
`EXIT_READY`, because macOS NetworkExtension is externally blocked and Android
remains deferred optional platform reach.

The traffic-shape matrix must not infer full mimicry from classifier-clean
evidence alone. The current PARTIAL witness matrix is based on isolated runtime transport
selection, `relay_session_succeeded`, relay-only pcap, nDPI risk count,
Suricata alert count, timing/ratio evidence, witness scoring, and no
fallback/mixed transport attempts for each scoped transport/profile. Full PASS
requires adverse reference profile coverage and JA3/JA4/timing comparison;
JA3/JA4 are now measured from pcap ClientHello for the current matrix and the
Cloudflare-fronted reference captures.

## Next Live Gate

The next implementation slice should start the gateway, apply a selected network
profile, run one transport scenario through `--live-command`, collect tcpdump
output, run hostile classifier verdicts over the capture, and write a live
artifact. After Phase B baseline review, traffic-shape optimization slices must
compare against the baseline artifact rather than prose-only claims.

## 2026-05-31 — nDPI scoped witness (critical-beta-hardening)

Live scoped nDPI pass over CF-fronted `https_ws` and `grpc_stream`
(evidence-archive/live/2026-05-31/phase5-witness-adversarial-matrix/):

- Both transports classified by nDPI as plain `TLS` (confidence DPI), ALPN
  differentiates correctly (`http/1.1` vs `h2`). No protocol-shape anomaly,
  no "Not Carrying HTTPS", no self-signed flag.
- The dated nDPI receipt recorded **"Suspicious DGA Domain name"** on the
  original private operator domain string, redacted here as
  `<PRIVATE_FRONTED_AUTHORITY>`. The observation belongs to that original name;
  it is not a finding about a replacement hostname such as `relay.example.org`.
  The recorded interpretation was a family-wide name heuristic false positive,
  rather than a per-user protocol/linkability finding. Domain selection remained
  an operator hardening item for that topology.

Suricata-based adversarial_evasion_pass_rate is **BLOCKED**: Suricata is not
in the default Debian/Ubuntu repo on the origin host (only `fever` /
rule-parser); needs a PPA or manual build before the adversarial runner can
score. Full 5×5 netem witness matrix not rebuilt this session (prior matrix
at evidence-archive/live/2026-05-03/mimicry-http-like-witness-matrix/).
