# AEGIS knowledge and runtime scoring

Status: current source description, reconciled 2026-10-11. External evidence,
runtime observations and the independent seed corpus have different owners.
None supplies a calibrated probability of success against a real censor.

## Signal layers and their actual connection

| Layer | Source | Current connection to Brain |
| --- | --- | --- |
| L1 seed priors | `aegis-knowledge/` embedded corpus | Independent crate. No production `StrategyKey` → `StrategyDescriptor` adapter or dependency connects its `priors_for` output to Brain. |
| L1 snapshot priors | Explicit `ExternalCalibrationSnapshot.knowledge` entries | The client validates and installs the supplied snapshot; Brain matches entries by normalized strategy/transport label. These entries are not automatically generated from the seed corpus. |
| L2 calibration | `tools/measure/src/external_calibration.rs`, witness and `aegis-measure adversarial-runner` output | The measurement summary supplies witness/adversarial rows; `scripts/build-external-calibration-summary.sh` wraps the summary command. |
| L3 runtime | Brain strategy/transport observations | Exact and context-similar state contributes a bounded runtime reward and confidence. Hybrid product-route evidence has a separate record and selector. |

The summary parser in `aegis-core/src/external_calibration.rs` initializes
`knowledge` to an empty vector. An explicitly supplied full snapshot can contain
knowledge rows. `aegis-client/src/runtime_calibration.rs` loads that public signal
into the runtime store and emits its application events; this path is already
implemented. It does not silently fetch or refresh a corpus.

## Baseline scoring implemented in core

`aegis-core/src/brain/scoring.rs` starts with `alpha = beta = 1`. For runtime,
one matching knowledge row and a combined L2 score, each available source adds
at most one fractional pseudo-observation:

```text
weight = clamp(confidence * freshness, 0, 1)
alpha += clamp(score, 0, 1) * weight
beta  += (1 - clamp(score, 0, 1)) * weight
belief_mean = alpha / (alpha + beta)
reward = clamp(belief_mean - 0.35 * detection_risk - 0.10 * latency_cost, 0, 1)
```

There are no fixed 0.2/0.3/0.5 layer weights. Witness and adversarial L2 scores
are combined using their record confidence, capped at 20 records. Runtime
confidence saturates at eight weighted trials. Freshness decays exponentially;
the defaults are six hours for runtime/prior timestamps and 24 hours for a
calibration snapshot, which may declare its own half-life. These are heuristic
trust scores with Beta-shaped smoothing, rather than accumulated
Beta–Bernoulli trial counts. With runtime evidence alone the mean remains in
`[1/3, 2/3]`, even after many trials. Existing event strings containing
`posterior` retain their compatibility spelling and do not strengthen that model.

The baseline exploitation order adds a UCB-style exploration bonus and probe
history bias. Its total trial count is summed across all keys for each strategy.
The exploration denominator counts observed trials using exact-key and
context-similarity weights before capture-trust scaling. An untried candidate
gets a finite `+1` bonus. This differs from classical UCB1 and from the separate
opt-in D-UCB/SW-UCB estimators described in the
[research matrix](../research/implementation-and-composition.md).

`estimation.rs` applies the same observation-reuse trust to the reward
numerator, reward denominator and confidence trial mass, for exact and similar
keys. Lower-trust evidence reduces confidence without treating an otherwise
identical successful observation as failure. It does not increase exploration
merely by shrinking that confidence mass. The trace retains the trust-weighted
estimated trial count and reports the actual exploration bonus; the
strategy-global trial total remains separate. These narrow source corrections
require their own exact-commit regression/CI receipts; documentation review
alone is not a PASS.

## Hard-block and admission boundary

A matching snapshot prior sets `hard_blocked` only if `hard_excluded` or
`fail_closed` is true, its score is at most `0.05`, its effective confidence
(`confidence * prior_freshness`) is at least `0.85`, and prior freshness is at
least `0.75`. Otherwise it contributes a soft pseudo-observation. The regional
seed-prior confidence cap of `0.65` cannot meet this threshold.

The corrected baseline source excludes snapshot hard-blocked candidates before
epsilon randomization and from its exploitation order. All blocked produces an
empty order. Exploitation traces retain the blocked rows for explanation; epsilon
traces retain their existing empty ranked-candidate shape. The optional
recent-route selector has its own exclusion check; hybrid route selection
separately respects a fresh classifier hard block. The legacy relay ordering
leaf now preserves calibration-backed selected sets and never appends their
omitted configured families; an all-blocked configured set returns an empty
transport order. Uncalibrated legacy ordering still only reorders configured
families. The narrow source regressions and caller repair require their own
exact-commit validation receipts; source preparation is not installed acceptance.
Independent configuration/capability/credential admission still limits the
available routes: a Brain score cannot authorize an otherwise refused profile.

Without external calibration, legacy relay adaptation applies its eight-trial
guard to the per-strategy total across all keys, rather than to this target.
An epsilon trace has no ranked candidates, so that guard preserves the configured
relay order. With calibration present the randomized order can be applied.

## Independent seed corpus and review

`aegis-knowledge` exposes `Knowledge::load_embedded()`,
`Knowledge::verify_integrity()` and `Knowledge::priors_for(&StrategyDescriptor)`.
The descriptor is crate-local; a production adapter remains unimplemented.
Embedded inputs remain separately reviewable:

- `aegis-knowledge/data/ja3-browser-corpus.json`
- `aegis-knowledge/data/dpi-signatures-cn.yaml`
- `aegis-knowledge/data/dpi-signatures-ru.yaml`
- `aegis-knowledge/data/dpi-signatures-ir.yaml`
- `aegis-knowledge/data/reference-timing.json`
- `aegis-knowledge/data/manifest.json`

The browser corpus is explicitly `version = "seed"`:
every JA3 hash is `placeholder-*-ja3`, and it contains no `grpc_stream` fingerprint.
These are structural test/export targets, not reviewed browser measurements or
an accepted Cloudflare transport policy.

Corpus changes remain explicit and reviewable:

- `scripts/check-knowledge-corpus.sh` checks the dry-run refresh path and corpus
  contracts.
- `scripts/build-phase-b-ja3-targets.sh` exports the placeholder seed targets for
  the tuning workflow; an export does not make them measured fingerprints.
- `.github/workflows/knowledge-corpus.yml` uses PR/push/manual events without a
  timer trigger.
- `aegis-knowledge/data/manifest.json` binds the embedded bytes.

The calibration wrapper accepts witness JSONL and output from the measure
adversarial runner, and emits JSON plus a review table. The former calibration/adversarial directory labels did not name existing
producer directories.

## Runtime ownership and retention

The installed client keeps learned destination/route state in RAM by default.
`[direct] persist_state = true` enables disk state only in direct/auto mode;
relay and forensic modes remain RAM-only even when the option is set. Importing
an explicit public calibration snapshot does not authorize loading old learned
destination state. See [private diagnostics](../operations/private-diagnostics.md).

The Ghost-LURK observed-IPG EMA blend helpers in
`aegis-core/src/ghost_lurk.rs` have only test callers; they are not a runtime
feedback loop. Historical module maps that label that blending as working do
not establish current integration. Runtime strategy selection, recent-route
paper estimators and transport framing each retain their own narrower source
and acceptance scope.
