# Native drivers

Native driver source is separated from Rust application code and its userspace control tools. The authored driver tree currently contains Windows WFP code.

### Contracts and limits

A kernel driver has separate build, signing, installation and live acceptance requirements. Source availability or a userspace fixture does not establish a loaded production driver or whole-system traffic coverage.

### Entry points and maintenance

Follow windows/README.md and windows/aegis-wfp/README.md. Userspace controls are under ../../tools/windows.

### Local map

- [windows/](windows/README.md)
