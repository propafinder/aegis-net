# Developer and operator tools

This tree contains measurement/artifact helpers, TLS witnesses, offline transport models and platform-specific development or release tools.

### Contracts and limits

Tools are not interchangeable: an offline analysis result, an actual localhost exchange, a privileged platform operation and a signed delivery each establish different facts. Commands that install, capture, change routes or start services need their real prerequisites and owned rollback.

### Entry points and maintenance

measure is the operator/evidence CLI; witness parses retained TLS/PCAP; transport-lab hosts bounded models and controlled fixtures; geneva, macos, macos-utun-lab and windows contain platform-specific operations.

### Local map

- [geneva/](geneva/README.md)
- [macos/](macos/README.md)
- [macos-utun-lab/](macos-utun-lab/README.md)
- [measure/](measure/README.md)
- [transport-lab/](transport-lab/README.md)
- [windows/](windows/README.md)
- [witness/](witness/README.md)

## Documentation responsibility

This README owns this module’s purpose and entrypoints. Shared procedures live
in the [focused guide](../docs/testing/README.md); cross-component boundaries are in
[component ownership](../docs/architecture/OWNERSHIP.md). Link to those documents
when changing a shared contract; do not duplicate their instructions here.
