# NetShaper queue-query runtime

This Rust implementation provides a finite authenticated queue shaper, an integer Gaussian reference sampler, and exact rational privacy-budget accounting. It is an opt-in research transport. Passing its tests does not establish a whole-network privacy theorem or a beta-exit criterion.

## Scientific model and adaptation

[NetShaper, USENIX Security 2024](https://www.usenix.org/system/files/usenixsecurity24-sabzi.pdf), §3.1 and Appendix C, defines neighbors through the maximum windowed L1 distance between coarse arrival-byte counts. It queries queued bytes periodically and adds Gaussian noise. Its queue-sensitivity argument requires bounded residence of all queued data. Its paper and [author artifact](https://github.com/ubc-systopia/netshaper/tree/release/sec24) are references, not executable setup instructions for Aegis.

Aegis does not infer timely Internet delivery from a timer or force-release an expired secret backlog. Each public epoch has a fixed number of slots, a fixed cadence and a public queue bound C. The actual query always lies in [0,C]. Thus its conditional sensitivity is at most C for any two queue states, including states with arbitrary prior arrivals. This conservative bound also covers the paper's neighbors. Holding an output-size transcript fixed makes each dequeue `q ↦ max(0,q−released)` nonexpansive. Exhaustive integer tests check this relation. The epoch is no longer than its configured public neighboring window; this is a resource limit, not a claimed remote delivery bound.

For integer queries, [Canonne, Kamath and Steinke, NeurIPS 2020](https://proceedings.neurips.cc/paper/2020/file/b53b3a3d6ab90ce0268229151c9bde11-Paper.pdf), Theorem 4 and Algorithms 1–2, supply the discrete-Gaussian reference law and concentrated-DP accounting. [The author implementation](https://github.com/IBM/discrete-gaussian-differential-privacy/blob/master/discretegauss.py) permits checking its rational Bernoulli and rejection construction. Aegis independently implements those arithmetic steps in Rust, without floating-point noise or exponential evaluation.

## Accounting and owned I/O

For the unbounded independent-draw reference, a slot spends `rho=C²/(2 sigma²)` and the public horizon reserves `slots*rho`. All admission comparisons use checked `u128` cross-products. Spending precedes entropy, input reads and output; an error has no refund. A floating-point epsilon conversion is informational and cannot admit a configuration.

The real sampler shares one public fuel limit, checked arithmetic and the original slot clock across every rejection. Entropy failure, exhaustion, overflow and lateness refuse. There is no approximate or deterministic fallback. Conditioning on bounded sampler success may change the reference law. No bound on that change, failure probability or observation of computation time is silently charged as delta. A full operational privacy theorem still requires that analysis, independent CSPRNG assumptions and a specified observation model.

The sender owns a bounded FIFO and emits exactly the public number of authenticated records, including padding after input EOF. It never emits a secret-dependent END or extra drain. AEAD binds the complete profile descriptor, slot index and selected public capacity; only a complete authenticated frame releases application bytes. A fresh, non-Clone, zeroized key/prefix is consumed for each direction/epoch. Backup/restart uniqueness and accounting across epochs belong to credential provisioning, not a Rust type claim.

Caller deadlines remain original; late synchronous completion is refused. Cancellation drops owned input, carrier and material. Unserved payload is a local diagnostic, not evidence of delivery. The installed duplex adapter refuses clean EOF if a tail remains or no actual source EOF was observed; an empty FIFO alone cannot prove that its source finished. Errors, stalls, scheduling jitter, endpoints, TLS/QUIC metadata and application bypass traffic remain outside the reference query theorem. Both-direction integration must preserve these boundaries.


## Already elapsed public tick

The sender waits after input collection only while its unchanged public tick is
still in the future. A newly polled Tokio Sleep can yield or register a rounded
timer even after the tick has elapsed. Avoiding this redundant await changes
neither Gaussian sampling/accounting nor the public schedule. The original
write allowance and absolute deadline checks remain at the caller; an actual
late wake beyond the allowance still refuses before wire emission. Deterministic
real-Tokio elapsed/future-tick controls are source evidence, not a claim that an
observed BIT-TRAPS platform failure proves a NetShaper failure, nor a promise of
host latency, whole-flow DP or platform acceptance.
