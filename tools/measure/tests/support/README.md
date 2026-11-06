# Operator fixture diagnostics

poisson_refusal.rs projects content-free failure JSON, poisson_source_witness.rs records parent-relative source activity, and poisson_windows_source.rs implements an owned Windows fixture timer.

### Contracts and limits

These helpers do not alter channel admission or turn refusal into PASS. Parent READY-relative ticks and send return values do not establish the child’s actual arrival/departure times. The Windows timer affects the test application source, not channel cutoffs.

### Entry points and maintenance

Only the paired integration tests consume these modules. Preserve metadata redaction, original-grid/missed-tick behavior and honest offered-versus-accepted counts.

### Local map

- [poisson_refusal.rs](poisson_refusal.rs)
- [poisson_source_witness.rs](poisson_source_witness.rs)
- [poisson_windows_source.rs](poisson_windows_source.rs)

See the [parent guide](../README.md) for the enclosing component and runtime scope.
