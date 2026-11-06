# Transport review rendering

output.rs renders the parent camouflage validation report as Markdown, including blockers, witness correlation and live/stealth status.

### Contracts and limits

Rendering supplied statuses is not running a transport or validating a DPI claim. Preserve explicit blockers and unknown evidence rather than letting prose imply a broader acceptance than JSON.

### Entry points and maintenance

The computation/caller lives in ../transport_camouflage.rs and the transport dispatcher. Update JSON and Markdown together when a field’s meaning changes.

### Local map

- [output.rs](output.rs)

See the [parent guide](../README.md) for the enclosing component and runtime scope.
