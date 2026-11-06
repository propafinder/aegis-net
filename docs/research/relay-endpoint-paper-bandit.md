# Explicit relay endpoint experiments

The optional `relay.endpoint_bandit` applies the existing Garivier–Moulines D-UCB or SW-UCB estimator to concrete entries in an explicitly admitted numeric relay pool. It does not discover, resolve, probe, enroll or create endpoints. Absence preserves existing pool order and creates no learner state or additional certificate reads.

```toml
[relay.endpoint_bandit]
max_profiles = 16
max_contexts_per_profile = 16
pre_auth_block_ms = 1000

[relay.endpoint_bandit.algorithm]
algorithm = "sliding_window"
rounds = 32
xi = 1.0
```

Alternatively use `algorithm = "discounted"`, `gamma = 0.9`, `xi = 1.0` in the nested algorithm table. These are public experimental policy choices. The v4 public bundle can include the same typed `endpoint_bandit` object; the raw four-member profile digest covers it, the renderer preserves it, and online startup refuses a substituted policy before private identity/overlay access. PublicProfile itself is not a standalone signed object.

Admission requires 2–16 distinct numeric socket pins, valid explicit TLS names, device inner TLS, explicit outer trust, empty legacy token, standard authenticated gRPC stream/datagram transport and a 1–60000 ms establishment budget. MASQUE overrides, DNS endpoints, unsupported transports and invalid estimator/state limits refuse. Selected internal endpoint copies disable the pool selector; the original admitted pool and policy own selection. Typed authenticated shaping and all target/device checks remain unchanged.

Only existing eligible endpoints reach the ranker. An observed pre-auth dial/carrier outage records reward 0 and a bounded public cooldown; current cooldown excludes that endpoint before ranking. Authentication, target admission or committed application failures remain terminal for the current connection. Ranking never authorizes retry after those failures or changes the shape to obtain connectivity.

A successful observation is binary: reward 1 is recorded once after the authenticated stream accepted positive outbound application bytes and a positive inbound response was observed. TLS, Open, target ACK, enrollment and policy ACK are not rewards. TCP observes this while the flow is live. Fixed-target UDP requires a completed positive datagram write and positive reply; channel flows also require the reply to be accepted into the existing response channel. Per-attempt atomic direction evidence also handles a received response becoming observable before the sender future completes; neither direction alone earns a reward. Stream acceptance/observed bytes are not remote acknowledgements, local application-delivery receipts or whole-flow completion. A terminal failure without an earlier successful observation records 0. A failure after a positive observation cannot add another trial; the existing outcome sink still retains its terminal failure evidence. Cancellation alone records no fabricated outcome.

The opt-in establishment clock begins before public-certificate identity reads and selection. Every pre-auth candidate uses this same absolute cutoff; post-Open matching trust/deadline observation must succeed before any application write. Configuration plus ordered pool, shaping, public CA/device-certificate chains and target/port/transport identify the bounded in-memory state. Certificate rotation, pool reorder or policy change creates a fresh profile. Public certificate reads use the existing bounded trusted reader, with no private-key digest or export. These file observations do not assert atomic filesystem immutability during arbitrary privileged replacement.

The process retains at most 16 profiles, a configured per-profile context cap of 1–64, and a universal cap of 64 contexts. On new demand, only registry-owned inactive contexts (strong Arc count exactly one) and fully inactive profiles may be retired. Every active selection or attempt holds a strong owner, so live scores cannot be removed or upgraded through a weak handle. Retired identities start fresh if admitted again; old scores never transfer. This bounds memory without permanently refusing the next sequential host. All-live capacity exhaustion refuses without changing authentication or silently using fixed fallback. An estimator refusal is sticky. Arms remain bounded by the admitted pool; no detached probe or scoring task is spawned.

This is a runtime experiment on authenticated relay selection. The binary traffic-dependent rewards and changing available arms do not transfer the paper's regret assumptions into a verified claim about a censored network, adversarial privacy or complete observed fleet dependencies. Loopback regressions demonstrate implementation behavior, not installed or target-network acceptance.
