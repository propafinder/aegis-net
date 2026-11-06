# Conditional relay dependency admission

`aegis_core::research_topology::LiveDependencyPolicy` shares the graph and
interdependent-cascade algorithms with `aegis-transport-lab topology`. This is a
bounded policy primitive. Its relay caller must still bind the complete policy to
the installed public profile and ordered numeric pool before using it.

The operator supplies two explicit graphs, a complete one-to-one dependency
mapping and one unique node in graph A for each relay, in the exact pool order.
Both declared anchor nodes must survive. Inputs are limited to 32 nodes and 128
edges per graph and 2–16 relays. Unknown nodes, duplicate declarations, malformed
edges, incomplete mappings and excessive dimensions refuse.

The caller first applies transport authorization, hard blocks and its bounded
pre-auth outage exclusions. It passes only the remaining endpoint indices to
`admit`. The policy removes excluded endpoints' nodes from graph A, combines them
with the operator's explicit unavailable nodes, and runs the checked alternating
connectivity/dependency cascade to a fixed point. The result is an ordered subset
of the caller's input; it cannot create an endpoint or authorize a target.

This policy deliberately uses the bijective giant-component model. At each
connectivity step only the largest component remains; equal-size ties use the
existing deterministic node ordering. A connected component containing an anchor
can therefore be discarded if another component wins. An endpoint excluded by a
local hard block or cooldown is treated as absent in the declared model; this can
conservatively exclude other endpoints. Neither behaviour is evidence that an
actual infrastructure dependency failed. Operators must choose this rule and
graph explicitly; it is not a general Internet reachability algorithm.

The policy does not discover providers, DNS, control services or dependencies,
and does not authenticate the completeness or freshness of the supplied graph.
Binding its bytes into the admitted public profile protects that configuration;
it does not turn declarations into measured fleet evidence. Actual dependency
inventory, controlled fault experiments and target-network validation remain
separate requirements.

The live caller must preserve its original establishment deadline across policy
validation and ranking, check cancellation before dialing, and retain the
existing no-retry boundary after authorization failure or committed application
data. Authentication failures cannot be converted into an outage-based retry.
Without an explicitly admitted policy, existing relay behaviour must remain
unchanged. Source tests and model outputs do not certify an installed release or
beta exit.

The numeric relay pool client now consumes this policy through the optional
`relay.endpoint_bandit.dependency_policy`. It validates the graph and exact ordered
endpoint mapping before public certificate identity reads or device key loading.
The whole policy is included in the profile identity and managed bundle raw-byte
pin; changing it starts fresh learning state. The renderer preserves the nested
policy, and online startup compares it against the accepted public profile before
reading a private overlay. Absence preserves the existing bandit path and builds
no graph. The endpoint bandit itself remains opt-in.

At rank, the client freezes the actual hard-eligible pool subset, removes active
pre-auth cooldowns, applies the cascade, and ranks only survivors. Before each
attempt it recomputes the same cascade using that frozen subset and current
cooldowns. This matters when an earlier pre-auth failure invalidates a shared
anchor: a previously ranked backup is then skipped before dialing. Eligibility
cannot be rebound to a larger set, and graph work consumes the original absolute
establishment deadline. Authentication-fatal and committed application failures
retain their existing terminal/no-replay behavior; the graph authorizes nothing.

For example, an operator may map two pool entries to A nodes `[0,2]`, with both
layers forming `0—1—2`, bijective pairs `[[0,0],[1,1],[2,2]]`, and anchors `1/1`.
Declaring B node 0 unavailable excludes the first entry; declaring B anchor 1
unavailable refuses both. This is the model's conservative operator policy,
not an automatically observed dependency or a statement that the public Internet
uses a bijective dependency graph. No discovery, background probe or fleet change
is performed. Local paired TLS/loopback tests exercise this caller; they do not
constitute installed or target-network acceptance.
