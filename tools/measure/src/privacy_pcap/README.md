# Classic PCAP export regressions

tests.rs exercises the private metadata-only exporter defined in ../privacy_pcap.rs with synthetic packet records.

### Contracts and limits

The exporter reads retained classic PCAP under bounded private-file custody; it is not a live collector or PCAPNG converter and does not export payloads. Tests cover supported/malformed cases, not capture permission or actual packet provenance.

### Entry points and maintenance

Use the privacy-pcap-export command through the parent dispatcher; refer to parent constants for current file/record/output caps rather than treating fixtures as supported unbounded input.

### Local map

- [tests.rs](tests.rs)

See the [parent guide](../README.md) for the enclosing component and runtime scope.
