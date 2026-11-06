# Storage management

AEGIS's project `target/` is a mixed-use tree. In addition to Cargo output it
can hold worktrees, VM homes/disks, staged packages and retained test evidence.
A broad `cargo clean` or recursive deletion of this tree can destroy work that
is not reproducible from source.

## Classify before deleting

| Data | Treatment |
|---|---|
| Cargo `.fingerprint`, `incremental`, `deps`, `build` in an identified inactive cache | Rebuildable; remove only after checking active compiler/build processes and needed binaries |
| `target/worktrees/<name>` | Real source checkouts; inspect Git state and preserve uncommitted/unpushed work before archival/removal |
| VM home, `.qcow2`, `.raw`, `.img`, `.utm` or guest state | User data; verify ownership, usage and explicit removal scope, not just whether a process is stopped |
| Local evidence directories (receipts, logs, signed packages, failed attempts) and the [evidence archive](../operations/evidence-archive.md) | Evidence; preserve originals and references; never add to Git |
| Normal `.git` packs, indexes, refs and worktree metadata | Git history; never treat as build cache |
| `.git/objects/pack/tmp_pack_*` | Potential interrupted operation output; only consider removal after no Git operation/lock/open file and unchanged normal indexed packs are established |

On 10 October 2026, a scoped cleanup removed 17 inactive temporary pack files
and 252 unique Cargo cache directories, preserving source checkouts, VM homes,
current binaries and evidence. The initial remover stopped at a duplicate
inventory entry after those unique cache removals; its failure record remains.
A separate read-only reconciliation verified the removals and preservation, and
Git's connectivity check passed. This history is not permission to reuse that
list against today's filesystem.

## Future builds

Use a dedicated cache directory for a checkout; do not mix VM homes into it.
Record the cache's purpose and confirm no build is active before removing it.
Use `git worktree list` to identify source checkouts and the app's archive flow
for app-managed worktrees. Keep storage receipts outside the paths being deleted.
Deduplicate inventories, compare file metadata immediately before removal and
record both intended actions and observed postconditions.

A connectivity-only Git check validates object reachability, not every blob's
content. Keep that limitation in the cleanup receipt. Never replace a failed
attempt with a later PASS record.
