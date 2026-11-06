# Contributing to AEGIS

Thank you for your interest. Start with the [README](README.md), the
[source map](docs/PROJECT-MAP.md) and the README of the component you are
changing. [Local development](docs/development/local-development.md) covers
builds, configuration validation and platform-specific checks.
Participation follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Change workflow

1. Open an issue first for larger changes so the approach can be agreed.
2. Make the smallest coherent change on a branch of your fork.
3. Add a regression test for a behavioral defect or a security boundary.
4. Run `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`
   and the tests for the crates you touched.
5. Open a pull request that explains the problem, the resulting behavior,
   how you validated it and what remains open. CI must pass on the final commit.

## Runtime design rules

- Preserve fail-closed decisions and target policy. Do not add a native network
  fallback when a required carried leg fails.
- Validate mutually incompatible profiles before opening sockets or sending
  credentials. Pair client and relay configuration explicitly.
- Bound queues, work, retries and shutdown. Cancel and join owned tasks.
- Keep protocol framing, model assumptions and real-world measurements
  separate. Do not change test thresholds merely to make a job pass.
- Never log secret tokens, private keys, payloads or externally supplied error
  text in diagnostics.

## Dependencies and licensing

Contributions are accepted under the project's dual MIT / Apache-2.0 license.
Dependency changes must update `Cargo.lock`, keep upstream licenses and keep
the vendored crates under `third_party/` consistent with their recorded
upstream and patches.

## What not to submit

Do not include credentials, device keys, invitation files, relay addresses of
real deployments, packet captures of real users or any other personal data in
issues, pull requests, tests or fixtures.
