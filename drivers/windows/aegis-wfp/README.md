# AEGIS WFP ALE connect redirect proof driver

This directory contains the minimal Windows WFP proof driver scaffold for the
live `windows-wfp-redirect-live-proof` artifact.

Scope:

- Registers one `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4` callout.
- Intended to match one controlled IPv4 TCP target only.
- Redirect target is `127.0.0.1:18080`.
- Runtime proof state is installed by `tools/windows/aegis-wfpctl`.
- Cleanup must remove only AEGIS-owned WFP provider, sublayer, callout, provider
  context, and filter state.

This is not the wide relay implementation. It is a primitive proof scaffold.
AEGIS relay/VPS integration remains blocked until the live proof artifact is
PASS.

## Local source and maintenance guide

A minimal ALE_CONNECT_REDIRECT_V4 kernel callout for a controlled target and local proxy experiment.

### Contracts and limits

The scope is a controlled IPv4 TCP redirect. It is not an independently accepted system-wide policy or proof for UDP/IPv6/DNS, and it has its own kernel signing/WDK prerequisites. Cleanup must identify only the AEGIS-owned WFP objects.

### Entry points and maintenance

The existing guide below explains the experiment and companion controller. Treat historical proof prerequisites as experiment instructions rather than a current beta-exit receipt.

### Local map

- [aegis-wfp.vcxproj](aegis-wfp.vcxproj)
- [aegis_wfp.c](aegis_wfp.c)
- [aegis_wfp.h](aegis_wfp.h)
- [aegis_wfp.inf](aegis_wfp.inf)
