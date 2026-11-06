# Phase A input and report support

input.rs reads supplied JSON/JSONL and classifies document status; output.rs renders Phase A exit/measurement gate reports.

### Contracts and limits

These helpers review supplied artifacts; they do not perform capture or independently verify the origin of a witness. Absent files and invalid streams must not become completed measurement gates.

### Entry points and maintenance

The parent ../phase_a.rs defines aggregation and ../phase_a_dispatch.rs exposes commands. Keep report language narrower than the evidence actually ingested.

### Local map

- [input.rs](input.rs)
- [output.rs](output.rs)

See the [parent guide](../README.md) for the enclosing component and runtime scope.
