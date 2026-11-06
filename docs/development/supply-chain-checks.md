# Dependency policy and source SBOM checks

The [supply-chain workflow](../../.github/workflows/supply-chain.yml) checks the
locked Cargo graph and generates two CycloneDX 1.5 source inventories using
workspace default features for `x86_64-unknown-linux-gnu`. It does not compile or
execute AEGIS native or SDK targets. This is concrete grant preparation, with
acceptance still dependent on the exact commit's workflow result.

Install the reviewed tool versions in an isolated verification environment:

```sh
cargo install cargo-deny --version '=0.20.2' --locked
cargo install cargo-audit --version '=0.22.2' --locked
cargo install cargo-cyclonedx --version '=0.5.9' --locked
cargo fetch --locked
bash scripts/security/check-supply-chain.sh
mkdir -p target
bash scripts/security/generate-sbom.sh target/sbom-new-attempt x86_64-unknown-linux-gnu
```

The output directory must be new, its parent must exist, and symlink ancestry is
rejected. Offline generation requires the dependencies already cached. Each run
uses a unique temporary filename next to the workspace manifests and preserves
the generated files in its attempt directory. Interrupted runs may leave those
uniquely named files; retain them as failed evidence rather than overwriting them.

`deny.toml` rejects unrecognized license expressions and registry/Git origins.
The wrapper also rejects missing registry checksums or unknown local dependency
identities and verifies byte provenance of the vendored h2 and uncommitted
B-08 tungstenite sources without executing them.
Private workspace crates are checked. The narrow, version-specific exceptions
are `option-ext` 0.2.0 (MPL-2.0) and `zlib-rs` 0.6.7 (Zlib); each requires retention
of its upstream notices. These exceptions are policy choices for dependency
assessment, not legal clearance of a binary release. Vulnerability checks retain
the existing [RustSec policy](../../scripts/security/cargo-audit.toml); no new
advisory ignore is introduced.

The SBOM wrapper pins cargo-cyclonedx 0.5.9, records manifest and lock hashes,
sets `SOURCE_DATE_EPOCH` from the commit unless explicitly supplied, and compares
two complete JSON models after sorting object keys only. Missing workspace
outputs, changed inputs or any model difference fail the check. It never removes
identities or dependencies to make the outputs match. Raw attempts and hashes are
retained. This demonstrates repeatability of this metadata inventory, not
reproducible compiled binaries, and does not certify other targets or feature
sets. Generate and assess each release's actual target/feature graph separately.

Cargo metadata alone does not inventory external Wintun DLLs, dracut fixtures,
system libraries, native build inputs or every bundled license text. [NOTICE](../../NOTICE)
identifies these boundaries, including ring's actual 0.17.14 notices. Shipping
acceptance still requires a payload inventory, architecture-specific hashes,
complete upstream license texts, corresponding-source obligations where
applicable, independent license review, and a signed release/provenance receipt.
No current source SBOM is advertised as complete shipping-artifact coverage.

Primary tool documentation:

- [cargo-deny license policy](https://embarkstudios.github.io/cargo-deny/checks/licenses/cfg.html).
- [cargo-deny source policy](https://embarkstudios.github.io/cargo-deny/checks/sources/cfg.html).
- [cargo-cyclonedx 0.5.9 usage](https://docs.rs/crate/cargo-cyclonedx/0.5.9/source/README.md).
- [SOURCE_DATE_EPOCH support in 0.5.9](https://docs.rs/crate/cargo-cyclonedx/0.5.9/source/CHANGELOG.md).
