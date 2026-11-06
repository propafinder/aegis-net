# macOS source tools

This directory contains the local SOCKS proxy credential helper and the opt-in Rust NetworkExtension host/provider source package. Their authority and readiness are separate.

## Proxy credential helper

proxy-keychain.rs prepares only the credential item for the local SOCKS proxy using Security/CoreFoundation APIs.

### Contracts and limits

The password arrives through stdin rather than arguments or output. This helper does not set a global Keychain ACL and does not implement a system-wide tunnel. Keychain/UI authorization and the proxy application are separate runtime prerequisites.

### Entry points and maintenance

Read the fixed trusted-application list and credential input limits in the source before use. The helper is platform-specific standalone source, not a Cargo package in this directory.

### Local map

- [proxy-keychain.rs](proxy-keychain.rs)

## NetworkExtension source

[aegis-network-extension](aegis-network-extension/README.md) builds native host/provider binaries outside the ordinary Cargo workspace. Its bounded queues and worker now have an opt-in adapter to the actual shared Aegis packet engine, with scoped native source tests. Since B-06 S07 the provider registers one composite session factory (Store claim, authenticated PolicyAck with continuous re-ACK, held relay services and packet engine) and applies network settings only after that session is Ready. It has not been signed, notarized, installed or run with real traffic, and certificate renewal is not performed in the provider; it is not an installed full-wide client.

## v34 h2 merge recipe

[h2-window-merge](h2-window-merge/README.md) holds the steps, the expected hashes and the helper ([record_window_delta.py](h2-window-merge/record_window_delta.py)) for merging B-06 v34's vendored-h2 receive-window delta with the Linux lane's h2 custody when `main` is merged into the B-06 branch. It is a merge-time procedure, not a build or install step.
