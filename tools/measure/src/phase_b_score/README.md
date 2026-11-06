# Phase B scoring reviews

reviews.rs compares declared baseline targets, observations and witness-wire correlation; support.rs provides report string helpers.

### Contracts and limits

Scoring concerns supplied observations and target definitions. A high score does not demonstrate deployability, real browser equivalence or censorship resistance; missing correlation remains a separate failure/unknown.

### Entry points and maintenance

The caller is ../phase_b_score.rs. Maintain the distinction between target review, observation parity and independently obtained wire evidence.

### Local map

- [reviews.rs](reviews.rs)
- [support.rs](support.rs)

See the [parent guide](../README.md) for the enclosing component and runtime scope.
