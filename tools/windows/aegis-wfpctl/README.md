# aegis-wfpctl

Minimal user-mode helper for the AEGIS WFP proof callout.

Commands:

```powershell
aegis-wfpctl.exe install <remote-ip> <remote-port> <redirect-port> <redirect-pid> [match-pid] [app-path]
aegis-wfpctl.exe cleanup
```

`match-pid` is optional. When non-zero, the kernel callout permits the
controlled target tuple for every other process and redirects only the matching
process ID.

`app-path` is optional and adds a WFP `ALE_APP_ID` filter condition for the
given executable path. Browser proofs use this instead of PID-only matching
because modern browsers may move network sockets across same-image child
processes.

The helper owns only these WFP objects:

- `AEGIS WFP proof provider`
- `AEGIS WFP proof sublayer`
- `AEGIS ALE connect redirect v4 callout`
- `AEGIS WFP proof runtime config`
- `AEGIS WFP proof controlled redirect filter`

It is intentionally not the production relay controller.

## Local source and maintenance guide

The C controller creates/removes the companion experiment’s AEGIS WFP provider, sublayer, callout and controlled redirect filters.

### Contracts and limits

Its controlled target/PID/application filtering is not a universal system tunnel. Cleanup must remain scoped to owned objects. Running install/cleanup changes local WFP state and requires the actual companion driver and administrative prerequisites.

### Entry points and maintenance

Keep the detailed existing guide below; the companion source is drivers/windows/aegis-wfp. The Rust winctl wrapper is a separate control plane.

### Local map

- [aegis_wfpctl.c](aegis_wfpctl.c)
