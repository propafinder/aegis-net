# Local development and source launch

These instructions describe development inputs from this checkout. They do not
install a signed release, enroll a device or enable OS routing. Use
[INSTALL.md](../../INSTALL.md) for an approved package.

## Prepare the correct checkout

Run commands from the repository root. Read `AGENTS.md`; inspect branch and
working-tree state before editing. Rust is pinned to **1.97.1** with rustfmt and
Clippy in [rust-toolchain.toml](../../rust-toolchain.toml). Keep `Cargo.lock` intact
and use `--locked` for builds and tests.

A Rust toolchain plus a native C/C++ toolchain is needed for crypto dependencies.
Browser-like TLS/QUIC builds also require the native tools used in the relevant
[CI lane](../../.github/workflows/ci.yml), including CMake/Clang/Ninja where named.
Linux packet contracts need additional host tools such as tshark; privileged
namespace/routing suites require a disposable Linux host. Windows and Darwin
have their own native feature sets and contract runners; a cross build does not
replace them.

Use an isolated compiler cache when this checkout shares a project with VM
homes or other worktrees:

```sh
export CARGO_TARGET_DIR="$PWD/.build-cache"
cargo build --locked -p aegis-client -p aegis-server --bins
cargo run --locked -p aegis-client -- --help
cargo run --locked -p aegis-server -- --help
```

`.build-cache/` is ignored by the repository. It must contain only generated
build products; keep credentials and evidence elsewhere. Default builds have
no optional Cargo features. For example, Windows's explicit native source lane
uses `chrome-like-tls,chrome-like-quic`; owned WebRTC uses `webrtc-carrier`.
Check each crate's manifest before adding features; `--all-features` is not a
universal cross-platform deployment profile.

## Validate before launch

Obtain a private client profile and relay profile for your authorized test
scope. Do not blindly copy `config.example.toml`: it selects direct/wide
behavior and its placeholder credentials/certificate paths are not usable.
The server example requires private certificate/key files and deployment choices.

```sh
cargo run --locked -p aegis-client -- --config /absolute/private/client.toml --validate-config
cargo run --locked -p aegis-server -- --config /absolute/private/server.toml config-check
```

Client validation parses configuration without starting the ingress. Server
`config-check` validates without binding listeners or printing secrets. Refer to
[client configuration](../../aegis-client/README.md) and the selected platform
runbook for file paths, trust material and supported profile combinations.

For an approved, non-disruptive SOCKS profile, start the relay and client in
separate terminals after validation:

```sh
cargo run --locked -p aegis-server -- --config /absolute/private/server.toml
cargo run --locked -p aegis-client -- --config /absolute/private/client.toml
```

The profile owns the listener address, transport and device authorization.
Configure the test application to use that listener. Check the client events,
relay policy result and egress; a listening socket alone is not success. Wide
profiles, enrollment, capture and firewall changes require their own runbook and
readiness, not these foreground commands. Shut down foreground processes normally;
service and routing rollback follow the relevant platform guide.

## Checks by change scope

```sh
cargo fmt --all -- --check
cargo test --locked -p aegis-core --lib -- --test-threads=1
cargo clippy --locked -p aegis-core --all-targets -- -D warnings
```

Replace the package with the one you changed; test dependent callers when their
contract changes. For the Linux workspace lane in a suitable disposable host:

```sh
cargo test --locked --workspace --all-features -- --test-threads=1
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
# Some host contracts execute target/debug paths directly. Use their expected
# cache rather than the dedicated Cargo cache exported above.
unset CARGO_TARGET_DIR
bash scripts/run-unwired-contracts.sh
```

Some existing host contracts build with Cargo and execute hardcoded
`target/debug` paths. Unset the custom cache before that suite and use a clean,
correct checkout; do not let it execute binaries retained from another source.
The contract aggregator can build binaries and invoke host tools; inspect its
exclusions and prerequisites first. Native Darwin, Windows and ARM64 results are
separate required jobs. Follow [.github's guide](../../.github/README.md) for lane
ownership. Do not label local or short checks as independent review, installed
lifecycle, physical capture, external DPI or a day-long run.

## Troubleshooting

| Symptom | First check |
|---|---|
| Wrong binary/profile | `--version` build metadata, intended commit and feature set |
| Configuration rejected | Validate the same absolute profile path; check incompatible modes and trust requirements |
| SOCKS works but browser IP is unchanged | Browser proxy settings; SOCKS does not capture other applications |
| Proxy password keeps prompting on macOS | Local proxy credentials versus macOS login/Keychain permissions; see the macOS worker guide, never use the login password as a proxy credential by assumption |
| Build consumes disk | Dedicated cache and [storage management](storage-management.md); preserve VM disks and worktrees |
| QUIC/UDP unavailable | Selected carrier policy, reachable UDP endpoint and fail-closed reason; no silent native fallback |

## Dependency audit policy

Run `bash scripts/test-cargo-audit-policy-contract.sh` and
`bash scripts/security/audit-dependencies.sh` from this checkout. The latter uses
[the versioned policy](../../scripts/security/cargo-audit.toml) in an isolated
working directory; local `.cargo/` or editor settings are not CI inputs.
