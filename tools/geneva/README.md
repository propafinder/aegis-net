# Selected Geneva relay operations

Shell installation for the standalone Linux AF_PACKET bridge, plus separate
selected relay-profile installers and native capture/lifecycle orchestration.

### Contracts and limits

`install-bridge.sh` installs only `PREFIX/bin/aegis-geneva-bridge` under a fresh
prefix. It verifies and copies a bundled executable when present, otherwise
builds the source with the lockfile and `live-linux` feature. It starts no
daemon/service and changes no networking; the operator explicitly invokes the
[standalone isolated bridge](../../docs/geneva-live-bridge.md).

`install-relay-profile.sh` is separate: it expects an existing stopped client
and a prepared device/guard context for the
[selected outer-relay profile](../../docs/relay-geneva-installed-profile.md).
That source path does not activate the default full-wide profile or provide a
generic operator bootstrap. Native orchestration can mutate nftables,
namespaces and capture state; its existence is not native acceptance evidence.

### Entry points and maintenance

Use the install/uninstall scripts as a paired reviewed operation. relay-native-ci.py, relay_capture_observer.py and relay_native_diagnostics.py coordinate evidence; test-*-inert.py use ordinary fixtures and do not establish native firewall or capture acceptance.

### Local map

- [install-bridge.sh](install-bridge.sh)
- [install-relay-profile.sh](install-relay-profile.sh)
- [relay-native-ci.py](relay-native-ci.py)
- [relay_capture_observer.py](relay_capture_observer.py)
- [relay_native_diagnostics.py](relay_native_diagnostics.py)
- [test-relay-capture-observer-inert.py](test-relay-capture-observer-inert.py)
- [test-relay-native-capture-protocol-r2-inert.py](test-relay-native-capture-protocol-r2-inert.py)
- [test-relay-native-ci-inert.py](test-relay-native-ci-inert.py)
- [test-relay-native-ci-terminal-inert.py](test-relay-native-ci-terminal-inert.py)
- [test-relay-native-diagnostics-inert.py](test-relay-native-diagnostics-inert.py)
- [test-relay-native-host-config-inert.py](test-relay-native-host-config-inert.py)
- [test-relay-native-nft-failure-inert.py](test-relay-native-nft-failure-inert.py)
- [test-relay-profile-install-inert.py](test-relay-profile-install-inert.py)
- [test-relay-profile-teardown-inert.py](test-relay-profile-teardown-inert.py)
- [uninstall-relay-profile.sh](uninstall-relay-profile.sh)
