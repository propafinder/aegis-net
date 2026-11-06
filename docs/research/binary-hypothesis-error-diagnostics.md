# Binary hypothesis error diagnostics

The private measurement path is `privacy-pcap-export` →
`privacy-study-assemble` → `privacy-frontier` → the shared Rust
`traffic_privacy::binary_hypothesis` module. The assembler verifies retained
export and frozen-bin contents, explicit trial flow windows, paired evaluation
units and separation from training declarations before emitting diagnostics.
It does not establish that a declared capture was independent, that its origin
was authentic, or that sampled observations follow a population model.

For separately normalized observed histograms `P0` and `P1`, the module reports
`empirical_plugin_minimum_sum_error = 1 - TV(P0, P1)`. This is the minimum
**unweighted** sum of false-positive and false-negative probabilities for a
test of those two finite observed distributions. It is not the performance of
a trained classifier, a weighted Bayes risk, or an error guarantee on unseen
traffic.

Each finite directional KL, using natural logarithms, also reports
`empirical_pinsker_minimum_sum_error = max(0, 1 - sqrt(KL / 2))`. This diagnostic
uses floating-point arithmetic and is not an interval-certified bound. Missing
observed reference support leaves KL and its Pinsker value unknown; the code
does not add pseudocounts or infer a zero population probability. Fewer than two
observations in either class leave all error diagnostics unknown. That refusal
floor does not imply statistical power.

These formulas implement the general hypothesis-testing apparatus discussed
by [Bash, Goeckel and Towsley](https://arxiv.org/abs/1202.6423). The article's
AWGN channel model and square-root limit do not describe an IP tunnel. The
separate Gaussian experiment remains a finite laboratory model. Neither
consumer invents an AWGN physical channel, independence, a whole-flow privacy
guarantee, automatic adoption of a policy, or beta acceptance.

Regressions use analytical distributions to distinguish the two KL directions,
normalize unequal class counts, retain unknown support and sample states, and
verify that private packet-field ingestion reaches the same diagnostics without
exposing flow addresses or private input paths. Those fixtures are explicitly
synthetic; genuine retained captures remain separately identified inputs.
