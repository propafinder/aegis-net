# Command schema

command.rs defines the Clap subcommand enum and public argument shapes for aegis-measure.

### Contracts and limits

The parser is the source of truth for names/defaults; accepting arguments does not admit an operation. Keep capability/build-info commands separate from commands that load identities, start paired sessions, execute host tools or assemble release evidence. Never put secret values into examples.

### Entry points and maintenance

Follow ../dispatch.rs and the relevant domain dispatcher to understand actual behavior before documenting or adding a command.

### Local map

- [command.rs](command.rs)

See the [parent guide](../README.md) for the enclosing component and runtime scope.
