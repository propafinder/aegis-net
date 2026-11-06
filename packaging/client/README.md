# Public client package instructions

[README.txt](README.txt) is the end-user text included in the public Linux client payload. It describes prebuilt installation, offline prerequisites, separately issued private access and the optional owned HTTPS bridge. Preserve its public-only scope when changing package contents.

The text is consumed by release packaging, not executed. Package recipients do not need Cargo, a source checkout or a GitHub connection when their operator supplies the verified complete release and prerequisites. A public release artifact alone is not a usable private identity or admission credential.

Maintain the detailed protocol and custody instructions in [HTTPS bridge operations](../../docs/operations/https-bridge.md) and [offline device installation](../../docs/operations/offline-device-installation.md). The bridge still needs reachable infrastructure and does not guarantee passage through an IP allowlist. The [packaging guide](../README.md) explains how private operator files and public runtime payloads are separated. Changes to this README do not constitute lifecycle or release acceptance.
