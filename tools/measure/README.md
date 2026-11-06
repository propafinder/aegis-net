# Measurement and private operator CLI

The normal `aegis-measure` build tool combines retained-artifact review, package/release evidence assembly, controlled platform operations and real paired private research-control commands. The separate `aegis-research-measure` target registers only seven research actions and their build-info/help/version entrypoints. The separate private research-only archives on Linux and Windows copy that target under the `aegis-measure` leaf name. The existing Linux administrative operator archive retains the full normal measure tool for its 33 helpers; it is explicitly administrative and carries no exclusive research-surface claim.

### Contracts and limits

Not every subcommand is read-only. private-control, poisson-control and poisson-insertion operate real owned network resources; platform smoke/helper and live-command paths may change local state or execute supplied programs. Artifact PASS fields are scoped to their producer/input and are not release, field or beta acceptance.

The Linux live-audit materialized contract checker treats manifest command
strings as inert metadata. It validates their fixed command grammar, referenced
files and regenerated status in memory; it does not execute them, rerun a shell
or write sibling fixtures. Its PASS establishes consistency of retained inputs,
not a fresh live run. The separate explicit `--live-command` interface remains
an operator-controlled execution path.

### Private reference targets

The master-plan handoff emits `<reference-origin-address>` and
`<reference-authority>` placeholders rather than a bundled operational endpoint.
The operator must choose a separate observer and supply the approved reference
origin and authority in private execution inputs. These generated instructions
are inert metadata, not a connection attempt or a complete live command.

### Entry points and maintenance

Start with src/cli/command.rs and src/dispatch.rs for the normal build tool. The restricted target uses src/research_main.rs and src/research_command.rs. Both invoke the same existing seven handlers with their original arguments, authentication and clocks. Only the restricted target reports `research-build-info`; the normal tool refuses that producer claim while retaining its build-side validators, notices and legacy operators. Research-only delivery requires the named restricted source on both platforms and has no fallback to the normal tool. `private_research_delivery.rs` admits the exact research tree and Linux archive; the normal builder keeps administrative inputs outside that tree. Metadata and hashes complement the compiled command inventory; they do not establish the command boundary alone.

Use a built executable to inspect the command surface or build identity:

```text
aegis-measure --help
aegis-research-measure --help
aegis-research-measure research-build-info
```

### Local map

- [Cargo.toml](Cargo.toml)
- [build.rs](build.rs)
- [src/](src/README.md)
- [tests/](tests/README.md)

### Workspace build

From the repository root, with the locked dependencies and the required target toolchain available:

```bash
cargo build --locked -p aegis-measure --bins
```

`default-run = "aegis-measure"` preserves existing build-side `cargo run -p aegis-measure -- ...` callers. Select `--bin aegis-research-measure` explicitly when building or running the restricted target. Restricting the delivered target does not make its real network actions read-only or accept installed/native research behaviour.

## Linux smoke artifact publication

Smoke summaries use a new staging file and atomic rename in an existing operator-owned directory. The writer rejects linked, shared-writable, nonregular and foreign-owned destinations and does not create or loosen parent directories. Summaries are published as mode 0644 to allow read-only inspection after privileged operations; they are not a private credential store. Repeated updates replace the directory entry without opening the prior inode. A directory-sync error can follow publication, so inspect the retained result before retrying. This file contract does not establish native firewall or installed-client acceptance.

## Separate private delivery roles

The actual Linux producer check consumes the retained `build-release-bundle.sh` output without another build. Its nine cases include three real administrative helper commands, the actual restricted pair and exact archive inventory, plus extra administrative/helper leaf refusals. The portable integration fixture `tests/private_research_archive.rs` executes the same three administrative selectors on a copied compiled input; a synthetic ELF admission fixture is a separate source contract and cannot substitute for a real Linux producer. Missing producer inputs refuse. These checks do not accept signed/native release or a hostile archive sandbox.

The administrative bundle manifest declares the same 33 helper paths staged by `scripts/build-release-bundle.sh`, including `scripts/lib/root-state.sh`. The manifest-emitter regression compares the independent staging inventory with emitted helper names, file entries and SHA-256 checksums, and checks checksum changes after a helper changes. Its controlled binary bytes prove metadata behaviour only; the retained nine-case Linux archive check still requires real compiled Linux producers and all 33 regular helper files.

## Poisson refusal diagnostics

The operator test support projects an optional `service_cutoff` only from the
existing post-send cutoff phase. Its closed numeric object contains one event
ordinal and five related durations; malformed, overflowing or out-of-range
values are omitted. Unknown payload fields are never copied. Absence preserves
the previous output shape; consumers that reject new JSON fields need a schema
update. This is a diagnostic observation, not a receiver ACK, physical-packet
timestamp or proof that the underlying native failure is repaired.

## Linux shipping inventory ownership

[src/shipping_client_inventory.rs](src/shipping_client_inventory.rs) owns the
Linux build-record and selected Cargo graph contracts. The normal
`build-release-bundle-manifest` command accepts `--client-build-messages` for the
just-built client's Cargo JSON stream. The established
[release builder](../../scripts/build-release-bundle.sh) supplies this argument
automatically after its fixed explicit-target build; operators should use that
producer rather than manufacture a record for an arbitrary executable.

The existing `build-public-client-delivery` command requires the operator's
build record and produces v3 with `client-cargo-inventory.json`. Its
[archive verifier](src/public_client_delivery.rs) checks this record against
source, target, lock, feature and client-byte provenance. Older operators without
the new record cannot produce v3. This does not add an inventory command to the
restricted research executable or change its seven-action surface.

New inventory reads have regular-file and byte bounds before allocation. Git,
rustc and Cargo metadata subprocesses use argv-only bounded pipe capture and
owned process-group cleanup; failed captures are retained privately. These
checks do not contain descendants that escape their group. Requested flags and
default features rely on the fixed producer recipe; only the client root's
resolved features are compared with the actual compiler-artifact message.
Transitive features remain metadata union, and local component identities hash
manifests rather than full source trees. Native completeness and compiler
linkage stay explicitly unproven. See the [delivery contract](../../docs/operations/public-client-delivery.md#shipping-client-cargo-inventory).

## Workspace license texts in delivery notices

The public client and private research notice collector includes the actual
workspace-root `LICENSE-MIT`, `LICENSE-APACHE` and `NOTICE` bytes for local
workspace members whose manifest declares `license.workspace = true`. Cargo's
metadata workspace root must match the explicitly reviewed root; membership,
local source and canonical manifest containment are checked separately. The
collector reads only those three fixed root leaves, with bounded file reads.
Missing required text, a mismatched workspace root, or a root text escaping the
reviewed directory causes refusal.

Dependency traversal and third-party crate-local license discovery remain
unchanged. Eight measure notice/delivery checks passed in the retained
`project-licenses-rust-qa-r2/complete-r2.json` receipt. This scoped verification
does not establish complete third-party attribution for every payload or SBOM
completeness.
