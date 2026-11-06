# Privacy and diagnostic boundaries

This describes current source policy for AEGIS beta software, not a deployed
operator's privacy notice, an anonymity guarantee or a universal no-logs claim.
The responsible legal operator, contact, processing purpose, retention periods
and deletion/request procedure require owner confirmation before public service
intake. Configured installations and older packages may behave differently.

## Client diagnostics and learning

Normal executable startup uses private event formatting and a `warn` fallback
when `RUST_LOG` is absent. The Linux installer supplies `RUST_LOG=info` through
its environment file. Severity and permitted event fields are separate policies.
An explicit diagnostic session can expose destinations and error chains.

The executable has no runtime JSONL sink unless a path is supplied; ordinary
Linux service units supply a runtime-events path. Disabling that sink does not
disable OS service journals. Forensic policy disables the runtime JSONL sink and
keeps newly used Brain state in RAM. It does not remove older logs, state files,
backups or OS metadata.

Normal client learning is RAM-only. Direct/auto operators may explicitly opt
into persistence; relay mode and forensic policy remain RAM-only. Opted-in state
can identify destination history: hashes may be guessed and a file key stored
on the same disk does not establish protection against disk seizure.

These rules are implemented in
[client startup](aegis-client/src/main.rs),
[Brain state admission](aegis-client/src/brain_state.rs) and the
[direct configuration](aegis-core/src/config_types.rs). See
[private diagnostics](docs/operations/private-diagnostics.md) for exact flags and
configuration distinctions. Installed-host verification remains separate.

## Operators and third parties

Relay, reverse proxy, authority, hosting provider and OS logs have separate
settings. Their actual retention and access controls are not established by this
source document. Enrollment and authorization require credentials and device
identity; operators must document their processing and retention separately.
Transport peers can observe connection metadata. Encryption and traffic shaping
do not prove that a destination, timing pattern or relay address is unobservable.

Explicit measurement, doctor, calibration and export commands create requested
reports; handle them as private operational data. Before sharing, remove tokens,
keys, invitations, real endpoint inventories, destination histories and unrelated
traffic. Preserve originals privately when required for evidence, and publish
only an approved redacted derivative. GitHub issue attachments are not a private
reporting channel. Use [SECURITY.md](SECURITY.md) for vulnerability reporting.
