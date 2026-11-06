# aegis-client/src/windows_wide

Windows wide-listener session targeting and original-destination vocabulary.

## Contract

listener.rs accepts a socket and constructs a session target; original_dst.rs distinguishes an explicitly configured controlled target from WFP redirect context. Do not treat a controlled-target fixture as proof of arbitrary original-destination capture. System-tunnel policy is owned by windows_tunnel.rs and aegis-core/windows_tunnel/.

## Key files

- [mod.rs](mod.rs)
- [listener.rs](listener.rs)
- [original_dst.rs](original_dst.rs)
- [session.rs](session.rs)
- [events.rs](events.rs)

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-client --bin aegis-client windows_wide
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

Native Windows/utun paths need the matching target; `windows-host-acceptance` is an explicit separate disruptive test gate.

For dependency features and launch procedures, see [aegis-client](../../README.md).

[Repository overview](../../../README.md) · [Parent directory](../README.md)
