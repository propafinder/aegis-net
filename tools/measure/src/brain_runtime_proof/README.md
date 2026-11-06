# Brain calibration proof fixtures

snapshots.rs constructs fresh, stale and weak-penalty calibration snapshots; support.rs reads candidate fields from Brain traces for the parent runtime-proof command.

### Contracts and limits

This is a controlled API/trace regression, not a measurement of a target route. Synthetic timestamps and declared calibration provenance must not become current network evidence. Preserve stale/refusal and hard-block controls beside positive ranking cases.

### Entry points and maintenance

The caller is ../brain_runtime_proof.rs. Changes should keep fixture construction separate from report assertions and retain the caller’s intended policy scope.

### Local map

- [snapshots.rs](snapshots.rs)
- [support.rs](support.rs)

See the [parent guide](../README.md) for the enclosing component and runtime scope.
