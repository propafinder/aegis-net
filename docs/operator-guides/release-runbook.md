# AEGIS release runbook

How a release is built and published. The release workflow
(`.github/workflows/release.yml`) may build unsigned private artifacts on `v*`
tag pushes. Assembly, signing and publication require an eligible manual
dispatch from protected `main`; `build_only=true` retains unsigned private test
inputs without those later jobs. Signing and publication to `propafinder/aegis-release` require
`workflow_dispatch` from protected `main`, matching channel metadata and the
[external governance and OPSEC contract](../operations/release-governance-and-opsec.md).
The workflow refuses missing protection or secret isolation; it does not configure
GitHub settings or migrate credentials itself.

> Operational hold recorded 10 October 2026: `Release` is disabled pending
> independent review and credential scope. The steps below are the procedure
> after authorized restoration, not a claim that dispatch is currently available.
> See the [hold](../operations/release-governance-and-opsec.md#temporary-operational-hold--10-october-2026).

## Steps

1. **Branch + code.** Land changes on a feature branch; open a PR to `main`.
2. **Version bump.** Bump `version` in `aegis-server/Cargo.toml`, `aegis-core/Cargo.toml`,
   `aegis-client/Cargo.toml`, `aegis-geneva/Cargo.toml` and
   `aegis-quic-boring/Cargo.toml`; all five release crates must agree. Refresh
   `Cargo.lock` and add `docs/RELEASE-NOTES-<version>.md` for the same version.
   The release-version contract checks these five packages and the notes.
   `tools/measure` versions independently — leave unless it changed. A new RC
   number within the same version does not require a Cargo version bump.
3. **PR CI green.** Required jobs are `rust`, `linux-arm64`, `darwin-contract`,
   `windows-rust` and `dependency-security`; the corpus workflow is separate. Required CI also runs for
   docs-only changes: protected `main` requires the same check contexts, so
   suppressing that workflow would leave the PR permanently blocked.
   Before merge, update README's capability/platform table and dated readiness
   snapshot for changed behavior, with evidence and open gates. Preserve prior
   proofs as history; verify documentation links and update the documentation map
   when an entry point moves. Source implementation, signed artifact integrity
   and installed or network acceptance require separate statements.
4. **Merge to `main`** after green and the required independent review. Verify that the external main protection is actually configured; a runbook does not enforce it.
5. **Exact main CI, then approved release trigger.** Wait for successful
   `push/main` CI on the exact source SHA, including extended Linux steps.
   PR/manual CI is not a substitute. Recheck the selected source before dispatch
   and the release run's `head_sha` after dispatch.
   For every signed release, dispatch the workflow from `main` with the chosen
   tag and matching channel/prerelease metadata. RC/nightly uses `channel=rc` or
   `nightly` and `prerelease=true`; stable requires its separate acceptance and
   approval. `include_macos=false` selects Linux-only delivery. Tag pushes do
   not sign or publish.
   Set `publish_release=false` to retain a signed private candidate without
   changing the public repository; `build_only=true` produces unsigned private
   build outputs only. Publication defaults to true for an eligible manual run.
6. **Release workflow** assembles unsigned delivery, checks exact-source main CI
   and scans the public archives. A separate metadata-only governance job must
   pass before environment `release` can release the isolated signer. It signs
   four manifests using its environment-scoped key and fixed bootstrap anchor.
   Secret-free preparation verifies the signatures and scans the exact public
   delivery. A second governance job and the separately reviewed `publish`
   environment precede publication. Required reviewers, restricted deployment
   branches and isolated secret scopes must already exist in GitHub.

## Judging the result

The optional macOS build is nonblocking for Linux delivery. Signing and
publication still require every mandatory predecessor and their own successful
job results; cancelled, skipped or failed jobs are not evidence of publication.
Check the exact run/source and actual published asset inventory. A macOS failure
must remain recorded even when an otherwise eligible Linux publication succeeds.

Read-only inspection after an authorized release:

```bash
gh run view <run-id> --repo example-org/aegis --json jobs
gh release view <tag> --repo propafinder/aegis-release --json tagName,isPrerelease,isDraft,assets
```

Use the explicit tag for prereleases; `/releases/latest` is not a prerelease
lookup. Public delivery has exactly nine files: `bootstrap-install.sh`, the two
`client-release.manifest*.json` files and their signatures, and two Linux client
archives (x86_64/aarch64) with their `.sha256` files. Server/operator archives,
packages, Rust sources and access credentials are not public release assets.
Private operator delivery is retained separately in the source workflow.

Both public manifests' `git_sha` values must match the reviewed source and its
successful exact-main CI. The public distribution repository's tag points at
that repository's main; its commit is not the source identity. Independently
verify signatures against the bootstrap pin, downloaded digests and contents.
Neither publication nor OPSEC fixtures establish native/restricted-network or
stable release acceptance.

## Deploying an exact private operator release to a relay

Use the authenticated operator delivery, not the public client mirror. Verify
its signed `release.manifest.json`, source/architecture, bootstrap pin and server
archive checksums before execution. Preserve the selected binary/config/certificate
metadata and an independent per-host rollback before any service change. Keep
private key/token bytes out of the deployment journal.

```sh
sudo bash /trusted/install-server.sh \
  --release-base https://operator-downloads.example.org/EXACT_TAG \
  --bootstrap-sha256 INDEPENDENT_BOOTSTRAP_SHA256
```

Replace the example base, exact tag and pin from the approved private receipt.
The facade requires `release.manifest.json` and the matching bootstrap/server
archive at that base. On an existing installation, an ordinary reapply may
refuse its selected unit/environment paths; add `--force` only for a separately
planned explicit overwrite after preserving the current configuration diff and
rollback. A repeated installer invocation is not release validation.

Validate the actual private configuration with `aegis-server --config
/absolute/private/server.toml config-check`, inspect the installed version and
receipt, and measure listener/readiness plus authorized client traffic. Record
service downtime and failed attempts as observed; do not promise a fixed restart
duration. Use the per-host recovery plan if readiness fails. Current source CI,
signature verification and historical lifecycle receipts do not certify a new
live relay. This procedure requires explicit per-host deployment authorization.

## Boundaries

- Tag / release / `main` push are **approval-gated** — never without explicit go.
- Never print the signing key, `auth_token`, or CF token. See
  [secret-handling.md](secret-handling.md).
