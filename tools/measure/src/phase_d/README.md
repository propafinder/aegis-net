# Platform reach evidence reviews

Android, macOS and Windows modules assemble platform reach reports from separate supplied runtime, policy and cleanup artifacts.

### Contracts and limits

The predicates intentionally distinguish JNI proof from VpnService, SOCKS from system-wide coverage, utun lab stages from Network Extension, and controlled WFP TCP from DNS/UDP/IPv6/reboot evidence. A missing optional proof must not be promoted from another platform or a broader label.

### Entry points and maintenance

Read each platform’s aggregator and predicates/optional helpers together with its output module. These report consumers do not themselves install a driver, start a VM, grant capture access or complete live tests.

### Local map

- [android.rs](android.rs)
- [android_output.rs](android_output.rs)
- [macos.rs](macos.rs)
- [macos_output.rs](macos_output.rs)
- [macos_predicates.rs](macos_predicates.rs)
- [windows.rs](windows.rs)
- [windows_optional.rs](windows_optional.rs)
- [windows_output.rs](windows_output.rs)

See the [parent guide](../README.md) for the enclosing component and runtime scope.
