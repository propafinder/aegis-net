# Knowledge loading and exports

lib.rs loads the embedded corpus; corpus.rs and manifest.rs define typed data, integrity.rs checks bytes, prior.rs derives conservative strategy priors, and main.rs handles artifact exports.

### Contracts and limits

Keep parsing and integrity errors distinct from observed route failures. refresh-dry-run does not update remote data or deploy a new corpus. Exported target ordering is deterministic and is not an acceptance score.

### Entry points and maintenance

The crate CLI includes refresh-dry-run, validate-refresh-dry-run, export-ja3-targets and validate-ja3-targets. Consult main.rs for exact file arguments and other commands.

### Local map

- [corpus.rs](corpus.rs)
- [error.rs](error.rs)
- [integrity.rs](integrity.rs)
- [lib.rs](lib.rs)
- [main.rs](main.rs)
- [manifest.rs](manifest.rs)
- [prior.rs](prior.rs)

See the [parent guide](../README.md) for the enclosing component and runtime scope.
