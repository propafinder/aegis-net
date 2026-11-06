# Laboratory integration controls

These tests cover bounded dependency inventory CLI behavior, HTTPS adversarial cases, rotation, secure carrier interoperability and source-level regressions.

### Contracts and limits

Local TLS interoperability checks use controlled resources; synthetic model tests do not operate a CDN, signaling broker, service relay or independent fleet. A transport fixture passing is not target-network acceptance.

### Entry points and maintenance

Keep negative authorization/rotation/ownership cases paired with positives. Each test’s source defines its required feature/platform/resource scope.

### Local map

- [fleet_inventory_cli.rs](fleet_inventory_cli.rs)
- [https_adversarial.rs](https_adversarial.rs)
- [rotation_adversarial.rs](rotation_adversarial.rs)
- [secure_carrier_interop.rs](secure_carrier_interop.rs)
- [source_regressions.rs](source_regressions.rs)

See the [parent guide](../README.md) for the enclosing component and runtime scope.
