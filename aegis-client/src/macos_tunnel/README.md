# aegis-client/src/macos_tunnel

Experimental macOS VM utun supervisor and dedicated non-root network worker.

## Contract

The privileged parent owns native device/policy; the dedicated child owns private identity and relay processing. Immutable launch contracts, worker IPC and receipt ownership bind the roles. Cancellation is installed before mutation or child spawn. This is an explicit isolated-VM path, not an accepted general macOS host tunnel.

Production uses the dedicated `WorkerPolicy`. The older generic policy is a
test-only refusal function and cannot prepare a native tunnel. Account proof
methods remain within this module, matching the verified-account boundary.

## Key files

- [parent_runtime.rs](parent_runtime.rs)
- [launch_contract.rs](launch_contract.rs)
- [policy.rs](policy.rs)
- [worker_launch.rs](worker_launch.rs)
- [worker_ipc.rs](worker_ipc.rs)
- [worker_policy.rs](worker_policy.rs)
- [worker_runtime.rs](worker_runtime.rs)
- [worker_pump.rs](worker_pump.rs)

The enclosing module is [macos_tunnel.rs](../macos_tunnel.rs); this directory contains its split implementation or test modules.

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-client --bin aegis-client macos_tunnel
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

This module is macOS-gated. Ordinary tests are separate from the explicit VM-only supervisor and online fixtures.

For dependency features and launch procedures, see [aegis-client](../../README.md).

[Repository overview](../../../README.md) · [Parent directory](../README.md)
