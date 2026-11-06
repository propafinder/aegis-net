# Native paper-bandit context lifetime

The opt-in native Brain D-UCB/SW-UCB selector retains at most 64 target-context
histories. Completing a 65th distinct target no longer poisons every context until
restart. Before inserting a valid new completion, it constructs and observes a
fresh estimator, then removes the history with the earliest last successful
completion and its matching recent observations. Equal completion instants use
lexical context order. Ranking an unseen context allocates nothing and does not
refresh recency. Invalid inputs cannot cause eviction.

The selector owns these histories under its existing mutable API and runtime
mutex; no transport, authentication lease, stream or external history handle is
retired. An older operation can complete after its history was evicted. That is
one legitimate present-time completion sample for the exact target key in a new
estimator, without restoration of its old trials or scores. Separate baseline
Brain evidence and priors remain as before. A monotonic successful-paper-completion
marker survives observation expiration and retirement. Real estimator refusal
stays sticky; capacity retirement does not clear it or authorize a fallback.

The 64-history boundary therefore resets learning for infrequent targets. It does
not preserve an infinite-history regret theorem across resets. Existing admission,
hard blocks, clock validation, observation window and opt-out behaviour remain.
Public configuration and wire format gain no fields. The separate relay endpoint
selector has its own pinned-profile ownership and retirement contract.

The regression with 100 target keys exercises the actual native Brain API with
synthetic completion outcomes. It is one test, not 100 tests, and does not assert
network delivery, installed acceptance, DPI resistance or beta exit.
