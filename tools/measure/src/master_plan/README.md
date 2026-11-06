# Master-plan handoff review

output.rs emits/checks a master-plan handoff; support.rs extracts declared artifact gate results and validates placeholder-free values.

### Contracts and limits

A handoff summarizes retained evidence and blockers. It does not run missing platform tests, create signatures, grant authority or turn unknown/absent evidence into success. Paths and textual labels are not authenticated provenance on their own.

### Entry points and maintenance

The parent ../master_plan.rs builds the report and ../master_dispatch.rs selects the CLI operations. Preserve JSON/Markdown consistency and explicit missing-state behavior.

The public observer instruction contains operator placeholders, including
`<reference-origin-address>` and `<reference-authority>`. It is inert report
metadata, not an executed command. `placeholder_free` scans named or empty
angle-bracket placeholders even inside an argument or before punctuation;
ordinary spaced shell redirection is allowed. A remaining placeholder keeps
the corresponding readiness flag false. The full-span path prerequisite
checker retains its narrower contract. Two pure parser regressions and the
complete handoff contract passed locally; this does not establish a public-tree
cleanup or an observer run on the target network.

### Local map

- [output.rs](output.rs)
- [support.rs](support.rs)

See the [parent guide](../README.md) for the enclosing component and runtime scope.
