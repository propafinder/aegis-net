# Witness parser and summary controls

classify.rs, pcap.rs and summary.rs exercise TLS fixture classification, supported/malformed classic PCAP extraction and event aggregation.

### Contracts and limits

Fixtures establish parser/report behavior only. They do not grant capture permission, measure a real censor, authenticate capture origin or establish all TCP-stream behavior. Keep malformed/truncated inputs and multiple-event cases beside positives.

### Entry points and maintenance

The tests consume the public witness library. Any real witness report needs separate retained-input provenance and the exact tool/source version.

### Local map

- [classify.rs](classify.rs)
- [pcap.rs](pcap.rs)
- [summary.rs](summary.rs)

See the [parent guide](../README.md) for the enclosing component and runtime scope.


### Audit 68 controls

pcap.rs retains the original complete IPv4/TCP ClientHello controls and adds
synthetic admission cases for empty/ACK-only input, SLL2/IPv6/mixed captures,
split handshakes, retransmission and reversed segment order, TLS framing,
IPv4 TCP fragmentation and malformed headers. Actual CLI subprocess controls assert
that refusal creates no outputs and preserves pre-existing evidence leaves.
These cases do not collect packets, prove TCP reassembly, or qualify independent
capture provenance. Run them with the exact candidate executable and keep a
separate receipt for baseline and candidate outcomes.


Refusal controls compare the complete existing error Display, including packet
index and precise cause, without importing candidate-only enum variants. CLI
controls select the Cargo-provided package binary, wait for its direct child,
require exactly exit 1 and the complete SLL2 Debug error, and inspect all output
leaves. Their runtime receipt is a direct-child fixture result, not process-tree
or native capture custody. Both CLI cases cover the early SLL2 refusal; the late
mixed-frame case remains a library/source-order control. R1 substring and
any-nonzero CLI oracles were rejected during peer preparation and were not run
as valid QA; R2 preserves that frozen attempt.
