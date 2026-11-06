# TLS witness parsing and reports

capture.rs selects supplied input sources; pcap.rs/tcp.rs extract retained classic-PCAP IPv4 TCP records; classify_tls.rs and score.rs produce structural classifications and report.rs/summary.rs format events and summaries.

### Contracts and limits

Each extracted record can produce a separate event. --output-jsonl appends events; summary destinations are rewritten. The parser is not a live collector or a general TCP reassembly/privacy proof, and addresses/hostnames remain private analysis inputs.

### Entry points and maintenance

main.rs owns witness input parsing and fixture generation; lib.rs exposes parser/report helpers. The separate bin/ executable launches local probes and synthesizes a PCAP wrapper, so it has additional process/browser prerequisites.

### Local map

- [baseline.rs](baseline.rs)
- [capture.rs](capture.rs)
- [classify_tls.rs](classify_tls.rs)
- [fixture.rs](fixture.rs)
- [lib.rs](lib.rs)
- [main.rs](main.rs)
- [pcap.rs](pcap.rs)
- [report.rs](report.rs)
- [score.rs](score.rs)
- [summary.rs](summary.rs)
- [tcp.rs](tcp.rs)
- [bin/](bin/README.md)

See the [parent guide](../README.md) for the enclosing component and runtime scope.


### Conservative PCAP refusal

capture.rs validates every supported packet before returning any records.
tcp.rs exposes a checked decoder that distinguishes malformed/unsupported frames
from supported non-TCP traffic. The ingestion path explicitly refuses empty,
IPv6/SLL2, TCP-fragmented, multi-segment, retransmitted, or incomplete/coalesced TLS
inputs. It has no TCP stream reassembler; a report is limited to complete TLS
records that each fit one payload and one directional flow occurrence. The
optional compatibility extractor is not the report-admission authority.


The checked decoder still skips unrelated Ethernet EtherTypes, non-TCP IPv4 and
empty TCP payloads. Explicit unsupported/malformed refusal and discarded traffic
are distinct scopes; neither establishes complete packet coverage or absence of
leaks. The conservative directional-flow restriction is not reassembly.
