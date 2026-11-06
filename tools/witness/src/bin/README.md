# ClientHello comparison executable

clienthello_compare.rs defines aegis-clienthello-compare. It launches an AEGIS cargo-run TLS probe and headless Chrome against owned localhost TCP listeners, retains the first TLS records, synthesizes PCAP wrappers and optionally decodes fields with tshark.

### Contracts and limits

This command executes child programs and creates temporary browser/profile and output files; it is not a retained-input-only parser. The PCAP is synthesized from received record bytes, not an independent packet capture. Browser certificate-error suppression belongs only to this controlled comparison and is not production trust policy. Fingerprint similarity does not establish full browser equivalence or DPI resistance.

### Entry points and maintenance

The parser requires --output-dir and accepts --repo-root, --chrome-bin, --tshark-bin, --host, --alpn and --timeout-ms. Inspect capture_from_listener and cleanup paths before an explicitly authorized run; preserve the local-versus-independent-capture distinction.

### Local map

- [clienthello_compare.rs](clienthello_compare.rs)

See the [parent guide](../README.md) for the enclosing component and runtime scope.
