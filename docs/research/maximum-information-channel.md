# Finite maximum-information adaptive channels

Aegis implements the two distinct objectives in Calmon and Fawaz, [Privacy Against Statistical Inference](https://arxiv.org/pdf/1210.2123), §IV-B/C. The existing default minimizes **mean mutual information**. The optional maximum-information objective limits **the greatest entropy reduction after one supported output**: `max_u [H(S) - H(S|U=u)]`. This is not Sibson maximal leakage, maximum posterior KL divergence, or differential privacy.

The training input is an explicitly supplied finite joint count table for secret labels and public length bins. Runtime emission receives only the actual length bin. It never needs the secret label. The resulting claim is conditional on this table and log-loss adversary model; it does not establish a bound for an unknown traffic population, packetization, multiple correlated records, or a complete VPN flow.

## Installed adaptive profile

Within the existing authenticated `adaptive_channel` profile, omission of `objective` retains the old solver, serialized settings, profile descriptor, and sampler. A present objective is strict, bounded, and included in the full authenticated descriptor and managed public profile. Null, unknown fields, excessive work, and inadmissible parameters refuse before optimization/emission. For example:

```json
"objective": {
  "kind": "maximum_information",
  "leakage_cap_millibits": 500,
  "cost_gap": 1
}
```

This selects the §IV-C fixed-cap minimum-cost convex program. `cost_gap` is an absolute gap in the existing padding-byte plus declared delay-cost units. `optimizer_gap_millibits` continues to control only the default mean-MI solver.

The alternative `kind: minimax_information` takes `leakage_gap_millibits`, `cost_gap`, and `cap_programs`. It searches caps at the existing `cost_budget`. The entire search shares the original establishment deadline and one pre-reserved total iteration/work budget. A certified minimum cost above budget advances the infeasible bracket; an ambiguous or nonconverged solve refuses instead of manufacturing a lower bound.

## Numerical admission

With `q(s,u)=Σ_z P(s,z)K(u|z)`, `m(u)=Σ_s q(s,u)`, and `δ=H(S)-ε ln2` in nats, each convex constraint is `δ m(u)+Σ_s q(s,u) ln(q(s,u)/m(u)) ≤ 0`. Zero-mass outputs impose no posterior condition; every positive-mass output is checked, however rare.

Bounded convex penalty continuation proposes kernels. Admission independently checks the unsmoothed final kernel and a nonnegative-multiplier Lagrangian cost lower bound. Smoothing is used only for finite optimization gradients, with an explicit conditional-entropy continuity allowance subtracted from the bound. It is never applied to emission. Numerical failures and inability to achieve the declared gap return no channel. Ordinary IEEE diagnostics explicitly have `rigorous_interval_certificate: false`.

The maximum mode quantizes the kernel to exact 53-bit integer sampler thresholds and checks the objective/cost on that actual sampler matrix. A small aggregate CDF error alone cannot protect a worst-posterior metric at a rare output. Uniform CSPRNG bits remain a computational assumption. The mean-MI sampler is unchanged.

`Certificate.maximum_information` carries the maximum-output entropy reduction, cap, cost lower bound, cost gap, perspective residual and, for minimax search, the feasible cap interval. Legacy mean-MI fields do not certify the new objective; their broad `H(S)` mean-gap bound is only a trivial auxiliary statement.

## Scope

The same owned adaptive stream, FIFO payload framing, authenticated profile agreement, cancellation, original I/O/session deadlines, and one-owner composition rules are used. No new carrier, discovery, DNS policy, credentials, automatic fallback, or whole-flow privacy assertion is introduced. Source tests and local duplex controls are engineering evidence; exact release CI, installed-client and field acceptance remain separate.
