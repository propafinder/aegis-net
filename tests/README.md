# Repository-level test assets

This tree contains the [adversarial testbed](adversarial/README.md): transport scenario metadata, declared network profiles, placeholder rule packs and container/VM scaffolding. [`support/cdn_grpc_proxy.rs`](support/cdn_grpc_proxy.rs) is a local CDN-like gRPC edge included by the fronted-origin tests of `aegis-server` and `aegis-client`; it models documented Cloudflare gRPC proxying behaviour and is not Cloudflare. Rust unit and integration tests also live beside their owning crates; this is not a complete inventory of the workspace's tests.

The adversarial runner is implemented in [tools/measure/src/adversarial_runner.rs](../tools/measure/src/adversarial_runner.rs). Its dry-run validates/plans inputs, while a live command must be explicitly selected and run in a prepared topology. The directory itself does not start a gateway or install network rules.

Choose the matching [CI lane](../.github/workflows/README.md) or documented operator procedure. Building containers, provisioning VMs and running privileged networking tests have different prerequisites from reading scenario TOML. Preserve raw failure/timeout records and keep private host configuration out of committed fixtures. Synthetic thresholds and placeholder profiles are not field measurements, DPI-bypass proof, installed release acceptance or beta-exit evidence.
