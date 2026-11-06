# QUIC comparison tests

chrome_quic_clienthello.rs checks the generated QUIC first flight; chrome_live_ja4.rs supports an actual Chrome comparison against a controlled local UDP endpoint.

### Contracts and limits

Environment/feature-gated browser checks require their declared local prerequisites. A skipped or ignored case is not a passed live comparison, and a local browser result is not a target-network or independent-capture proof.

### Entry points and maintenance

Inspect test attributes and environment requirements before running. Keep raw datagram input and version provenance with any comparison receipt.

### Local map

- [chrome_live_ja4.rs](chrome_live_ja4.rs)
- [chrome_quic_clienthello.rs](chrome_quic_clienthello.rs)

See the [parent guide](../README.md) for the enclosing component and runtime scope.
