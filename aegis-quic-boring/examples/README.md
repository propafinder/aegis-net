# QUIC capture parsing example

parse_capture.rs demonstrates extracting ClientHello/JA4 material from recorded raw QUIC datagrams.

### Contracts and limits

Its input uses a big-endian u32 length followed by that many raw UDP payload bytes. It is not a PCAP or PCAPNG reader. Parsing public Initial protection is not decrypting application traffic.

### Entry points and maintenance

Read the example argument parser before preparing input; see src/fingerprint for the reusable parser. Retain capture provenance separately from the printed comparison.

### Local map

- [parse_capture.rs](parse_capture.rs)
