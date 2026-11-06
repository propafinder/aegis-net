# Conditional covert-channel experiments

`aegis-transport-lab::research_covert_channels` contains executable Rust encoders, receivers, detectors and a packet queue simulator. `run_awgn(AwgnConfig)` and `run_poisson(PoissonConfig)` return serializable reports. They consume a deterministic numerical seed. They do not send network traffic or install a transport.

The reference papers are [Bash, Goeckel and Towsley, *Limits of Reliable Communication with Low Probability of Detection on AWGN Channels*](https://arxiv.org/pdf/1202.6423) (Theorem 1.1) and [Soltani, Goeckel, Towsley and Houmansadr, *Covert Communications on Poisson Packet Channels*](https://arxiv.org/pdf/1610.00381) (§§II–IV). These models require assumptions that a generic Internet connection does not establish.

## AWGN experiment

Each trial creates a new secret Gaussian codebook, chooses a message, transmits its actual vector, adds independent Gaussian receiver/warden noise, and decodes with minimum squared distance. The warden receives independent H0 and H1 observations and applies the equal-prior Gaussian variance likelihood ratio. This detector describes the fresh secret-codebook ensemble; revealing or reusing the codebook changes that experiment.

For `n` channel uses, symbol variance is `P = power_coefficient / sqrt(n)`. The implementation computes the reference quantities

```
expected energy = n P
D(P0 || P1) = n/2 [log(1 + P/variance_w) - P/(variance_w + P)]
reference sum-error lower bound = max(0, 1 - sqrt(D/2))
Gaussian capacity reference = n/2 log2(1 + P/variance_b)
```

The report contains actual mean transmitted energy, actual Bob block errors, false alarms, misses, and both mean log likelihood ratios. It reports message bits divided by `sqrt(n)`, so separate configured sizes can be compared without silently replacing a finite codebook with an asymptotic capacity-achieving construction. Both noise variances must be positive. The configured warden variance is a model assumption, not an inferred physical noise lower bound.

## Poisson insertion and timing experiment

Insertion runs an independent overt Poisson clock and an independent insertion clock, merges the actual timestamps causally, and preserves the overt packets. Its count likelihood ratio and Poisson KL use the configured rates and observation horizon. Encoded insertion payload bits are recovered through an ideal origin/authentication oracle: this is the first scenario's explicit assumption, not a implemented cryptographic discriminator hidden from a real warden.

The separate timing construction never invents packets. During the first public phase it scales original arrival times by `lambda / (lambda - delta)`, where `delta = coefficient sqrt(2 lambda / buffering_time)`. It tracks each actual arrival and forwarding event against a finite buffer. A fresh codebook consists of independent Poisson point processes over the second public phase. The selected timestamps are released only if their original FIFO packets already exist. Starvation and capacity failures retain their observed emission prefix and count as failures; no replacement delay repairs a failed codeword.

The forwarded timestamps enter a physical FIFO exponential-service queue:

```
d_i = max(a_i, d_(i-1)) + Exp(mu), mu > lambda
```

Bob evaluates each candidate's service density, using `s_i = d_i - max(a_i, d_(i-1))`. A negative service time or incompatible packet count has zero likelihood. The previous phase's last departure and the phase/packet boundary are explicit receiver side information. The implementation reports actual decode errors, queue waiting time, backlog, unforwarded original packets, and finite drain refusals. It computes `lambda log(mu/lambda)` as a capacity reference, without substituting that capacity for observed finite-codebook throughput. The queue starts empty: no stationary Burke theorem for its finite departures is asserted.

## Statistical and resource boundaries

Every error frequency has its sample count and a two-sided Hoeffding 95% reference interval. Distribution diagnostics compare actual trial counts with a Poisson CDF and one uniformly selected timestamp per nonempty trial with a uniform CDF. Planned codewords and actually emitted prefixes are checked separately. Their DKW 95% reference radius is explicit. A passing diagnostic is neither a joint-distribution proof nor a guarantee against other detectors. These are marginal confidence statements under ideal independent experiments, not a simultaneous family-wise certificate.

The numerical generator is a domain-separated SHA-256 counter stream with finite midpoint uniforms. Gaussian Box–Muller and exponential transforms use floating arithmetic with finite tails. Seeds reproduce experiments; they are not secret session keys or exact mathematical randomness. Reports qualify the ideal analytical references accordingly.

Validation bounds codebook sizes, trials, event counts, worst-case work, clock resolution and finite numeric inputs. Each Poisson clock has a hard event limit and message selection has a bounded rejection limit; exceeding either refuses the experiment rather than changing its distribution. The bound is on finite computational work, not a hard real-time OS scheduling guarantee. Buffer/clock/service/network errors, finite-horizon termination and payload authentication require separate analysis before any product-channel privacy claim.

No IP-arrival Poisson assumption, AWGN-to-packet identification, commercial-DPI result, installed-client guarantee, or beta acceptance follows from these experiments.

### Actual first-phase refusal accounting

The first-phase count detector consumes the actual `first_sent` prefix after causal replay. Planned rate/KL/missed-detection/backlog quantities are separate `planned_*` references. If capacity refuses before the public phase boundary, no initial backlog at that boundary is invented: `mean_initial_backlog` is absent when no trial reaches it, and otherwise averages only the explicitly counted `phase_one_completed_trials`. Later phase-two failure preserves an already established actual first-phase backlog. The Poisson-reference LRT remains a diagnostic applied to actual prefixes; it is not claimed optimal for a refusal-distorted alternative distribution.
