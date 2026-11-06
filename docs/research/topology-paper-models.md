# Finite topology and interdependency simulations

`aegis_core::research_topology` implements two distinct research
mechanisms in Rust. It operates on explicit undirected graphs and dependency
pairs; it does not inspect the live fleet or infer shared providers from names.
Existing route AND/OR dependency-cut analysis remains a separate model.

## Albert, Jeong and Barabási

The [2000 Nature paper](https://www.nature.com/articles/35019019) and
[author manuscript](https://arxiv.org/pdf/cond-mat/0008064) compare random vertex
failures and high-degree attacks. The implementation computes each removal
prefix, largest-component fraction, fragment sizes and mean finite shortest-path
distance. Random attacks use a seeded permutation without replacement. Two
explicit degree policies avoid ambiguity: `initial_degree` sorts original
degrees once; `adaptive_degree` recalculates surviving degrees after each
removal. Degree ties use increasing numeric vertex ID. They are reported as
distinct experiments, not asserted to give identical paper curves.

Global efficiency is an additional engineering metric: ordered surviving
pairs contribute `1/distance`, unreachable and removed pairs contribute zero,
and the denominator remains original `N(N-1)`. Reachable-pair count accompanies
the finite-path mean so that fragmentation cannot appear as improvement merely
by excluding unreachable paths. A one-node graph has efficiency zero and no
finite-pair mean. Empty nonlargest-fragment sets have no mean.

Seeded Erdos–Rényi rational-probability and preferential-attachment generators
are executable. The latter starts with a clique of `m+1`, then adds `m` distinct
existing endpoints sampled by current degree. These are finite experiments,
not estimates of critical thresholds or proofs that Aegis is scale-free.
The [2001 correction](https://www.nature.com/articles/35054111) concerns the
original exponential-network random-failure curves; this code does not reproduce
or depend on those published numerical curves.

## Buldyrev and colleagues

The [2010 Nature paper](https://www.nature.com/articles/nature08932) and
[author manuscript](https://arxiv.org/pdf/0907.1182), sections II–III, motivate
reciprocal dependency failure and alternating connectivity loss. `Interdependent`
implements the equal-size, symmetric one-to-one variant with an explicitly
provided complete bijection. Unknown, duplicate, missing and many-to-one pairs
are rejected. Network A and B can have unrelated IDs and distinct edges.

Initial failures propagate across the bijection. Each cycle keeps A's largest
connected surviving component and propagates its removed vertices to B; then
keeps B's largest component and propagates back to A. Cycles continue until an
entire A/B cycle changes neither survivor set. Every connectivity/dependency
removal and survivor set is retained in the report. Survivors never reappear.
The strict-decrease argument bounds execution to at most `N+1` cycles.

Finite largest-component ties use the lexicographically smallest sorted ID set.
This is an explicit finite operational policy, not a uniqueness theorem. A
singleton remainder is retained and reported as `1/N`; it is not mislabeled an
extensive giant component or rounded to total collapse. The paper also discusses
all mutually connected clusters and thermodynamic analytical solutions; this
largest-functional-component simulator does not implement those generating-
function solutions or claim their phase thresholds for a measured fleet.

## Input, bounds and consumer contract

`analyze(Request)` validates schema `aegis_topology_papers_v1`, both graph inputs,
complete dependency pairs, failure IDs, common-cause memberships and attack count.
Each common cause is an explicit distinct numeric ID with one or both nonempty
failed-ID lists; it runs as a separate counterfactual, not an inferred real cause
or an accumulated sequence. A caller wishing to combine causes must explicitly
provide their validated union as initial failures.

`synthetic` provenance accepts a short public label. `observed_input` requires
the syntax of a lowercase SHA-256 evidence reference. Syntax is not verification:
reports always retain `evidence_authenticated=false`,
`target_network_measured=false`, and `beta_exit=false`. An external inventory
consumer must independently verify any referenced evidence and map its actual
semantics to undirected edges and reciprocal pairs. Merely supplying a hash
cannot establish a provider relationship or applicability of the model.

Hard limits are 128 vertices per layer, 4096 unique undirected edges per layer,
16 independent common causes, and at most N attacked vertices. The complete
128-node graph has 8128 edges and is explicitly refused; generators never trim
edges silently. BFS distances are at most 127; pair counts and distance sums fit
the bounded integer domain. Efficiency and means use floating-point arithmetic
in stable ID order and carry no exact-real theorem. Each attack has at most 129
metric samples; each cascade has at most 258 connectivity phases. Complexity is
bounded by `O(N^2(N+E))` per complete attack trace and `O(N(N+E))` per cascade,
plus final all-pairs metrics. No sockets, files, secrets, system policy or native
fleet actions occur in the model.

Simulation randomness uses fully specified SplitMix64 and rejection-based
bounded sampling (128 draws maximum), then Fisher–Yates for random attacks.
The seed is public and reproducible; it is not cryptographic randomness or
evidence of unbiased independent physical failures. Graph generation parameters,
seed, topology and failure policies must accompany any externally published
comparison. The input-file CLI reexports this shared core module. A separate
opt-in endpoint caller consumes its checked connectivity/cascade operation to
narrow an already admitted numeric pool using an operator-declared policy. It
does not run attack experiments, infer failures, discover nodes or override
authorization. See [conditional dependency admission](live-dependency-admission.md)
for its stricter 32-node/128-edge limits, anchor policy, original establishment
clock, current cooldown and conservative exclusion semantics.
