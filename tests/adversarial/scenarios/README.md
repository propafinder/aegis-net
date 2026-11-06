# Adversarial transport scenarios

The four TOML files identify `legacy_tls`, `https_ws`, `masque_derived` and `grpc_stream` scenarios. Each declares a name, transport, description and `expected_threshold_key`. Threshold values live separately in [expected.toml](../expected.toml); the scenario file is not a full client profile.

The [Rust adversarial runner](../../../tools/measure/src/adversarial_runner.rs) consumes these fixtures for dry-run plans or an explicitly selected live command. Keep names and threshold keys coherent when adding a scenario. A valid TOML document or planned command is not an observed connection or measured pass rate.

Runtime identities, relay addresses and private configuration must be provided through the appropriate lab/installation path rather than committed here. Match the selected [network profile](../network-profiles/README.md) to actual gateway state, and retain failures and timeouts. Refer to the [parent guide](../README.md) before interpreting any result as live or target-network evidence.
