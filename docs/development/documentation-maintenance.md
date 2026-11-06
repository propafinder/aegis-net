# Documentation maintenance

## Three kinds of documentation

- **Source guides** describe the current implementation, entrypoints and module
  boundaries. Link to code and state the source snapshot when facts depend on it.
- **Operator runbooks** explain a scoped procedure, prerequisites, privileges,
  verification, shutdown and recovery. A runbook is not evidence that it was run.
- **Dated evidence/design history** retains exact attempts, source hashes,
  assumptions and outcomes. Do not rewrite it into a current capability claim.

## Directory README contract

Every authored source directory should explain its purpose, important files,
parent/consumer relationship and local constraints. Add build/test commands only
where the directory owns a runnable target; nested modules should link to their
crate's instructions instead of inventing standalone commands.

Use relative Markdown links so documentation works in a clone and on GitHub.
Link the parent README and focused operational/design guides. Keep source
configuration, privileged commands, model assumptions and acceptance status
explicit. Do not duplicate secret examples or spread changing release versions
across every README.

Evidence stays outside Git: local evidence directories are Git-ignored and the
historical evidence tree is in the [evidence archive](../operations/evidence-archive.md).
A dated local receipt path is a workspace-only locator; only a reviewed fixture
that a CI check reads enters `scripts/tests/fixtures/`. Mark this scope near the register;
do not describe a local link, file hash or local test as hosted/public evidence.
Do not force-add an entire evidence tree or publish raw captures, credentials,
private source or operator diagnostics. For the final release, curate a small
secret-free summary only after the exact final commit and required CI complete:
record the commit SHA, completed job/run identifiers and outcomes, artifact
hashes, platform and feature scope, failed attempts and remaining NO-GO gates.
Review that summary and its dependencies before explicitly tracking it.

The [directory index](../PROJECT-MAP.md) classifies tracked directories as
AEGIS-authored, immutable evidence or upstream/vendor inputs. Evidence and
vendor trees are centrally indexed; do not insert new files into a previously
hashed capture/archive or edit upstream fixtures to meet a documentation count.
Generated/ignored local directories have different lifetimes and are covered by
[storage management](storage-management.md).

## Review checklist

1. Check file/link existence and CLI spelling against source (`--help` when a
   suitable binary exists). Specify working directory, platform and feature set.
2. Avoid declaring a current release/CI result from a dated note. CI acceptance
   belongs to an exact commit; deployment acceptance belongs to an exact package.
3. Keep original image assets and upstream license/provenance files unchanged.
4. Update this map and the local README when adding/moving a module. Keep old
   audit references readable; use an archive banner rather than silently
   changing the meaning of retained historical material.
5. Save documentation coverage and broken-link findings separately from runtime
   test evidence. An accepted documentation check does not close beta gates.

## Placement and ownership

Use [the responsibility map](../architecture/OWNERSHIP.md) before creating a
document. A local module README describes its API/code boundaries; cross-module
design goes to architecture, build/review policy to development, native guidance
to platforms, authority/delivery procedures to operations, and model premises to
research. Old plans/status go to archive with their original date.

Maintain one substantive guide per topic. Category READMEs link to it rather than
copying instructions. Preserve [stable package and audit addresses](../COMPATIBILITY.md);
a compatibility link is safe only when consumers need an address, not embedded
guide text. Never regenerate a mismatching historical checksum during cleanup.
