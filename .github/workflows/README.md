# Workflows

| Workflow | What it runs |
| --- | --- |
| `ci.yml` | On pushes to `main`, pull requests and manual dispatch: formatting, repository hygiene and dependency audits (cargo-audit, cargo-deny, vendored-crate integrity); the Linux x86_64 build with strict Clippy and the workspace tests (with a disposable PostgreSQL 16 service for the session-fence tests); Linux ARM64 tests; the macOS build, client and NetworkExtension tests; and the Windows build, strict Clippy and tests (Wintun, WFP and service lifecycle on the disposable runner). |
| `knowledge-corpus.yml` | Path-filtered changes to `aegis-knowledge/`: the corpus integrity check. |
| `chrome-profile-refresh.yml` | Weekly schedule and manual dispatch only (never pushes or pull requests): measures Chrome stable in a read-only job and, when the checked-in profile drifted, a separate job opens a pull request with the two measured files. `scripts/test-chrome-profile-refresh-safety-contract.sh` checks the isolated browser launch. |

All jobs use GitHub-hosted runners and no repository secrets. `ci.yml` and
`knowledge-corpus.yml` use a read-only `GITHUB_TOKEN` with
`persist-credentials: false`, upload no artifacts and do not sign, notarize,
publish or deploy anything. Only the pull-request job of
`chrome-profile-refresh.yml` can write, to push its branch and open the pull
request.

Read the actual `on`, job and step `if` conditions before interpreting a run.
A green run belongs to the exact commit it ran on.
