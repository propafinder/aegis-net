# AEGIS Witness

`aegis-witness` is the Phase A witness classifier foundation. It produces
JSONL classification events from TLS ClientHello bytes and is intentionally
conservative: current output is structural witness evidence, not a censorship
resistance claim.

## Current Inputs

- `--input-hex <HEX>` for a TLS record encoded as hex.
- `--input-file <PATH>` for raw TLS record bytes.
- `--input-pcap <PATH>` for the conservative classic-PCAP scope described below.
- `--stdin` for raw TLS record bytes from standard input.

`--interface <IFACE>` on the Rust binary remains reserved for native capture.
For live host capture today, use `scripts/run-hostile-witness-audit.sh`; it
records a PCAP with `tcpdump` and then feeds that PCAP into `aegis-witness`.

## Example

```bash
cargo run -p aegis-witness -- --input-file clienthello.bin --output-jsonl witness.jsonl
```

```bash
cargo run -p aegis-witness -- --input-pcap capture.pcap --output-jsonl witness.jsonl
```

```bash
cargo run -p aegis-witness -- \
  --input-pcap capture.pcap \
  --output-jsonl witness.jsonl \
  --summary-json witness-summary.json \
  --summary-markdown witness-summary.md
```

## Output

Each extracted TLS record emits one JSONL event; a PCAP input can produce multiple events. Each event contains:

- TLS ClientHello classification status.
- SNI, ALPN, JA3 string, and JA3 MD5 when available.
- A bounded structural score used only as an initial witness signal.

When `--summary-json` or `--summary-markdown` is passed, the tool also writes
per-label averages for JA3 presence, ALPN match, SNI structure, extension
structure, and combined score.

## Boundary

This tool does not prove DPI bypass. It creates external classification evidence
that can later feed adversarial scoring and Brain calibration.

## Local source and maintenance guide

aegis-witness classifies supplied TLS records and retained classic PCAP, emits JSONL and summarizes existing streams. The separate aegis-clienthello-compare executable launches controlled local AEGIS and Chrome probes.

### Contracts and limits

--interface is reserved and explicitly unsupported; this executable does not perform live capture. Output may include SNI/ALPN and other sensitive metadata. Heuristic scores or matching fingerprints do not prove browser equivalence or DPI resistance.

### Entry points and maintenance

The detailed existing guide below describes inputs. A PCAP run may produce multiple JSONL events, one per extracted record; --summarize-jsonl instead reads existing events and emits selected summaries.

Use a built executable to inspect the command surface or build identity:

```text
aegis-witness --help
aegis-clienthello-compare --help
```

### Local map

- [Cargo.toml](Cargo.toml)
- [src/](src/README.md)
- [tests/](tests/README.md)

### Workspace build

From the repository root, with the locked dependencies and the required target toolchain available:

```bash
cargo build --locked -p aegis-witness
```


### Classic-PCAP admission boundary (Audit 68)

PCAP ingestion accepts Ethernet (including one VLAN tag) or Raw IPv4, with one
nonempty TCP payload per directional address/port tuple. Each such payload must
contain exactly one complete TLS record; a handshake record must contain exactly
one complete handshake message. Empty captures, ACK-only captures, unsupported
link types (including Linux SLL2), IPv6, IPv4 TCP fragments, malformed supported
headers, multiple payload segments, retransmissions, out-of-order streams,
opaque payloads, and split/coalesced TLS framing return explicit errors. A mixed
capture containing a frame classified as unsupported by the checked decoder
refuses the whole input before writing
classification events or summaries; earlier output files remain unchanged.

This intentionally narrow decoder does not implement TCP/IP/TLS reassembly,
prove that capture started before a handshake, validate network checksums, or
establish absence of leaked traffic. Captures requiring those features remain
unsupported rather than yielding successful empty reports or TLS-negative
observations. Raw hex/file/stdin inputs retain the general byte-classifier scope.
The compatibility `extract_tcp_ipv4_payload` helper still has its optional API;
report ingestion uses the checked helper and does not discard its errors.

Synthetic parser and CLI controls are separate from an independently collected
capture and its provenance. No production Linux/Windows/macOS capture acceptance
or DPI result follows from these controls. Preserve the input and failed receipt
when a real capture is refused; do not filter unsupported packets to manufacture
an accepted report.


Non-IPv4 Ethernet EtherTypes other than explicitly rejected IPv6/VLAN cases,
non-TCP IPv4 packets, and empty TCP payloads are skipped as outside this decoder's
TLS-over-TCP scope. Thus input refusal is not a complete all-packet coverage or
no-leak proof. The IPv4 fragmentation refusal covers TCP fragments; non-TCP IPv4
is skipped first. TLS checks validate framing lengths/type/legacy major version,
not full TLS semantics. Complete application-data or non-ClientHello handshake
records may still classify as not-clienthello; this does not establish absence
of an unobserved handshake or leaked traffic.

The two CLI preservation controls exercise SLL2 rejection before
packet decoding; later mixed IPv4/IPv6 refusal has a library control and source
ordering, not a separate actual late-refusal CLI measurement. Exact CLI controls
verify the Cargo-provided binary's observed bytes before/after its direct-child
wait, code 1 and the complete SLL2 error; this does not seal an executable handle
or establish process-tree custody. Existing output contents and metadata are
checked; Unix controls also compare device/inode. No native Windows file-identity
or capture-provenance acceptance follows from this fixture.
