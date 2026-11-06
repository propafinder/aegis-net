# Legacy fallback decoy tests

[The test module](../legacy_fallback_decoy_tests.rs) exercises the actual legacy session handler through bounded in-memory Tokio streams. Malformed framed input must receive the shared process identity, a Date header and the generic HTTP 400 body. Valid current and active legacy synthetic keys must retain their encrypted, matched-key BadTarget responses. Target port zero is refused before lookup or connection. An unread output stream verifies that fallback cannot renew the original admission deadline.

The malformed encrypted-input body is distinct from the cleartext-on-TLS explanatory page. These source regressions do not establish browser, DPI, captured wire, deployed or native-platform equivalence.

From the repository root, run the focused module with:

```sh
cargo test --offline --locked -p aegis-server --lib legacy_fallback_decoy_tests -- --test-threads=1
```

See [the parent module](../README.md) for session contracts. Baseline and repair evidence are retained in `artifacts/testing/2026-10-10/audit08-legacy-fallback-r1`.
