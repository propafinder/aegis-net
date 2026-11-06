# AEGIS Adversarial Testbed

This directory is the Phase A2 scaffold for adversarial DPI measurement. It is
not DPI bypass proof by itself. The runnable surfaces are:

- a Rust dry-run runner that loads scenarios, network profiles, and thresholds, then
  emits JSONL plan events;
- a bounded Rust `--live-command` runner that executes one selected operator probe
  or a full scenario/profile matrix and emits measured PASS/FAIL/TIMEOUT
  events.

## Current Boundary

- `cargo run -p aegis-measure -- adversarial-runner --dry-run` validates scenario/profile wiring.
- `cargo run -p aegis-measure -- adversarial-runner --live-command ... --scenario ... --network-profile ...` records
  measured command results. When run inside a prepared gateway container, that
  command is the gateway probe.
- `cargo run -p aegis-measure -- adversarial-runner --live-command ... --live-matrix` records measured command results
  across the default scenario/profile matrix.
- No censorship-resistance claim is produced unless the command ran in a real
  gateway topology with packet capture and artifact evidence.

## Layout

- `scenarios/` contains per-transport scenario metadata.
- `network-profiles/` contains shell profiles intended for gateway setup.
- `rules/` contains placeholder rule packs for later Suricata/string matching.
- `expected.toml` contains pass-rate thresholds.

## Inputs and execution limits

The [network-profile scripts](network-profiles/README.md) currently print declared conditions; invoking them does not apply `tc`/netem. The [rule files](rules/README.md) are placeholders. A live command must verify whatever network impairment or rule installation the prepared gateway actually uses. [Scenario files](scenarios/README.md) identify transports and threshold keys without supplying credentials or a complete client configuration.

`Dockerfile.dpi-gateway` installs gateway utilities and builds `aegis-measure`; it requires a container build context containing the repository and accesses package/build dependencies. `Vagrantfile` provisions a VirtualBox Ubuntu fixture. Neither is a harmless parser-only entry point or proof that a capture occurred. Inspect [run-adversarial-gateway-docker.sh](../../scripts/run-adversarial-gateway-docker.sh) and [the testbed design](../../docs/testing/23-adversarial-testbed.md) before choosing a disposable topology. Dry-run output remains a plan; measured exit status, observed impairment, independent capture and target-network scope remain distinct.
