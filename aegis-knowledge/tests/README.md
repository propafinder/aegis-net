# Knowledge regression fixtures

knowledge.rs exercises the embedded knowledge contract using repository fixtures.

### Contracts and limits

These tests validate loading, integrity and prior/export behavior; they do not contact DPI systems or establish that corpus annotations are current. Preserve refusal cases when adding corpus entries.

### Entry points and maintenance

Run through the aegis-knowledge Cargo package in a suitable workspace. This README records test scope, not a claim that checks were run for a particular release.

### Local map

- [knowledge.rs](knowledge.rs)

See the [parent guide](../README.md) for the enclosing component and runtime scope.
