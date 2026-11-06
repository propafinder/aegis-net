# Finite privacy/utility channel optimizer

Primary sources checked directly on 9 October 2026:

- Calmon and Fawaz, [Privacy Against Statistical Inference, arXiv:1210.2123v1](https://arxiv.org/html/1210.2123v1), theorem 1, equations 14–17.
- Liu et al., [Rate-Distortion Function for Encrypted Traffic Side-Channel Defense, arXiv:2607.17889v1](https://arxiv.org/html/2607.17889v1), definitions 1–5 and proposition 1. This is a preprint; its claims do not certify Aegis.

`rate_distortion::Problem::label_blind` solves a finite convex problem over a
new stochastic channel K(Y|Z), minimizing I(S;Y) under p(S,Z), a single
expected-cost budget and an explicit allowed-action mask. The channel sees an
observable bin, never the secret label. An installed causal actuator must bind
these bins/actions to actual padding and delay; physically impossible actions
must be excluded. Expected cost is not a per-packet maximum. A trained unseen
bin refuses rather than silently choosing an unmeasured policy.

`Problem::label_conditional_wasserstein` is a separate finite label-conditioned
model with an opt-in [Liu runtime consumer](liu-runtime-channel.md). It uses
transport kernels K(Y|S,Z) with a finite normalized metric. Optimizing their
expected transport cost realizes the finite W1 formulation over Q(Y|S): for
each label, minimizing over couplings with fixed original P(Z|S) is precisely
W1. The metric is checked for nonnegativity, symmetry, zero diagonal, positive
off-diagonal and triangle inequality. This model requires the secret label;
`sample_observable` refuses it. The label-blind feasible class is generally
smaller, so its optimum must not be called Liu's exact Pareto frontier. Neither
model's abstract W1 cost is automatically physical latency or bandwidth.
The runtime obtains a class through an explicit operator-declared target/purpose
mapping, admits the complete causal kernel and calls `sample_label_conditional`.
That source integration does not prove the mapping or training distribution is
representative, or transfer the memoryless model to outer packets/whole flows.

The solver uses Frank–Wolfe and a one-constraint product-simplex linear oracle.
The oracle minimizes each row's gradient plus lambda times weighted cost;
bounded lambda bisection brackets two deterministic extreme channels and
mixes them to meet the budget. At the minimum possible budget it optimizes
directly over the minimum-cost face. An arbitrary nonnegative lambda supplies
a dual lower bound, even if bisection is approximate. Convex line search keeps
the old feasible point and both endpoints as candidates.

For zero support, 0 log 0 is evaluated as zero. Only the optimization objective
is smoothed: its joint output is mixed with tau times an independent uniform
output conditional on the same prior. Emission uses the original K. The
smoothed gradient is finite. If B is the independent mixture indicator,
I(S;Y) - I(S;Y_mixed) <= h2(tau) + tau log2(min(|S|,|Y|)). Combining this with
the smoothed convex tangent/LP dual yields a bound on original-objective
suboptimality. The reported bound is an IEEE-754 numerical diagnostic;
`rigorous_interval_certificate=false`. There is no directed-rounding theorem
certificate. Nonconvergence yields an error and **no channel**.

Input probabilities within 1e-10 of unit sum are explicitly normalized.
Strictly positive joint masses smaller than 1e-15 refuse as outside numerical
scope, while exact zero masses remain supported. Dimensions, iterations and
work are bounded; deadline and cancellation are polled throughout iteration,
oracle and objective work. Running this synchronous solver on an async reactor
is inappropriate; the owner should train offline or use an owned blocking
task. No network/kernel deadline or cancellability guarantee follows.

Runtime adaptive/Liu preparation has a
[shared admission policy](implementation-and-composition.md#optimizer-preparation-admission):
four owned queued/running blocking jobs and 32 waiting callers per process.
This is wrapper availability admission, not a change to this synchronous solver,
its iterations, numerical gap, cancellation checks or returned channel. Queue
waiting consumes the already captured original cutoff; saturation/expiry yields
no channel or fallback. Direct offline solver calls are outside this owner pool.
The constants do not prove a global CPU/heap bound or strengthen a DP/certificate
claim. Actual wrapper ownership regressions and their limits are recorded in
the operator contract; native capacity acceptance remains open.

Runtime sampling uses fresh fallible CSPRNG bytes and a 53-bit CDF draw. Finite
CDF discretization has at most |Y|/2^53 total-variation error per row in
exact arithmetic, plus floating CDF roundoff; each sampled row is normalized. Entropy
failure refuses. This is a finite numerical stochastic policy, not ideal
continuous randomness, differential privacy or perfect steganography.

The tests include the analytic binary Hamming rate/distortion curve, asymmetric
padding-only constraints and actual sampling, distinct label-blind versus W1
optima, the binary W1 critical-cost endpoint, sparse/zero support, independent
finite-difference gradients and brute linear-program comparison. Invalid,
infeasible, cancelled, expired, entropy-failed and unconverged cases refuse.
These are source/numerical tests; they do not establish installed adoption,
wire distribution, causal QoS, real DPI resistance or beta acceptance.

## Numerical consistency refusal

A valid finite problem may have a large common cost offset and tiny action-cost
differences. IEEE arithmetic can then lose gradient discrimination in the linear
oracle or cancellation can reverse its purported dual bound. An actual binary
case with costs near 10^12 reproduced a lower bound 0.001630121932 bits ABOVE the
primal while the former gap clamp reported about 0.000000290181 bits. Its channel
happened to be optimal; the numerical certificate was inconsistent.

The optimizer now rejects a linear-oracle lower bound exceeding the current
feasible linear value, or a smoothed lower bound exceeding its primal, by more
than a fixed 10^-12 nats allowance. The allowance is in objective units and is
never scaled by the cost budget or its common offset. Only excess within that
explicit tiny allowance is clamped down to the primal. This is a consistency
check, not directed rounding or a rigorous theorem certificate. Such ill-
conditioned inputs can return NumericalFailure; no successful channel or fallback
policy is substituted. The original frozen implementation and actual standalone
reproduction remain retained in private QA artifacts.
