# Frozen study inputs and packet rows

frozen_bins.rs validates the declared bin definition, packet_rows.rs ingests the exact metadata TSV format and selects flows, and tests.rs exercises private content-bound study assembly.

### Contracts and limits

Packet rows are retained exports, not raw PCAP parsing. Frozen training bins and evaluation trials must keep their distinct provenance. Hashes do not prove collector authenticity, source costs, independent holdouts or field representativeness.

### Entry points and maintenance

The parent ../privacy_study.rs owns manifest limits and assembly. Keep the exact TSV header, numeric units, flow selection and new-private-output refusal cases synchronized.

### Local map

- [frozen_bins.rs](frozen_bins.rs)
- [packet_rows.rs](packet_rows.rs)
- [tests.rs](tests.rs)

See the [parent guide](../README.md) for the enclosing component and runtime scope.
