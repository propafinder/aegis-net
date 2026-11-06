# Android VpnService evidence wrapper

`run-vpnservice-basic-flow-proof.sh` prepares the Phase D Android proof artifact. Its inputs are an artifact directory, an optional `adb` executable, the application package identifier and an expected relay egress IP. It uses an actual Android runtime/application path when available and reports a blocker rather than manufacturing `vpnservice_basic_flow_proven=true`.

Read the usage block before selecting a device. The wrapper accepts `--help` as its first argument and returns usage with exit code 2; that is not a successful proof. An operational run requires ADB, an authorized device or emulator, the matching installed application and separately supplied runtime configuration. Merely having ADB or an APK is not VpnService traffic evidence.

The source contract is [test-android-vpnservice-basic-flow-proof-contract.sh](../test-android-vpnservice-basic-flow-proof-contract.sh); invoking a contract may build its dependencies. Phase D aggregation lives in [build-phase-d-android-reach-evidence.sh](../build-phase-d-android-reach-evidence.sh). Keep device identity and capture material private. This wrapper does not confer production Android release, system-wide acceptance or target-network acceptance. Return to the [script guide](../README.md) for other platforms.
