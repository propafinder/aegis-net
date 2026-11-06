#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: scripts/macos/run-networkextension-system-wide-proof.sh <artifact-dir> [options]

Options:
  --expected-egress <ip>       Expected relay egress IP for a future PASS proof.
  --host-app <path>            Signed macOS host app path to inspect.
  --extension-bundle <path>    Signed Packet Tunnel extension bundle path.

This runner is deliberately blocking-first. It creates the Phase D macOS
NetworkExtension proof artifact shape, but it reports BLOCKED unless it is run
on macOS with Xcode tooling, signing material, approved VPN configuration, and
a real Packet Tunnel runtime proof. It never fabricates
network_extension_system_wide_proven=true.
EOF
}

artifact_dir="${1:-}"
if [[ -z "${artifact_dir}" || "${artifact_dir}" == "--help" || "${artifact_dir}" == "-h" ]]; then
  usage
  exit 2
fi
shift || true

expected_egress="${AEGIS_EXPECTED_RELAY_EGRESS:-}"
host_app=""
extension_bundle=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --expected-egress)
      expected_egress="${2:?missing --expected-egress value}"
      shift 2
      ;;
    --host-app)
      host_app="${2:?missing --host-app value}"
      shift 2
      ;;
    --extension-bundle)
      extension_bundle="${2:?missing --extension-bundle value}"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

mkdir -p "${artifact_dir}"

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  printf '%s' "${value}"
}

write_result() {
  local status="$1"
  local blocker="$2"
  cat >"${artifact_dir}/result.json" <<EOF
{
  "status": "$(json_escape "${status}")",
  "feature": "macos_networkextension_system_wide_proof",
  "platform": "macOS",
  "scope": "networkextension_packet_tunnel_ipv4_tcp",
  "expected_relay_egress_ip": "$(json_escape "${expected_egress}")",
  "host_app": "$(json_escape "${host_app}")",
  "extension_bundle": "$(json_escape "${extension_bundle}")",
  "network_extension_system_wide_proven": false,
  "packet_tunnel_runtime_proven": false,
  "signed_app_and_extension": false,
  "network_extension_entitlement_present": false,
  "vpn_configuration_approved": false,
  "no_manual_proxy_used": false,
  "relay_session_succeeded": false,
  "cleanup_restored_direct_path": false,
  "pf_system_wide_capture_claimed": false,
  "networkextension_sdk": {
    "framework_in_xcode_sdk": false,
    "packet_tunnel_provider_typecheck": "NOT_RUN"
  },
  "blocker": "$(json_escape "${blocker}")"
}
EOF
}

{
  echo "artifact_dir=${artifact_dir}"
  echo "expected_egress=${expected_egress}"
  echo "host_app=${host_app}"
  echo "extension_bundle=${extension_bundle}"
  echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"${artifact_dir}/commands.txt"

{
  uname -a || true
  echo "PATH=${PATH}"
} >"${artifact_dir}/environment.txt"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "not macOS: $(uname -s)" >"${artifact_dir}/platform.log"
  write_result "BLOCKED" "requires_macos_host"
  exit 2
fi

if ! command -v xcodebuild >/dev/null 2>&1; then
  echo "xcodebuild not found" >"${artifact_dir}/xcodebuild.log"
  write_result "BLOCKED" "xcodebuild_not_found"
  exit 2
fi

xcodebuild -version >"${artifact_dir}/xcodebuild.log" 2>&1 || true
xcrun --show-sdk-path --sdk macosx >"${artifact_dir}/sdk-path.log" 2>&1 || true

if ! command -v security >/dev/null 2>&1; then
  write_result "BLOCKED" "security_tool_not_found"
  exit 2
fi

security find-identity -v -p codesigning >"${artifact_dir}/codesign-identities.log" 2>&1 || true
if ! grep -Eq '^[[:space:]]*[0-9]+\)' "${artifact_dir}/codesign-identities.log"; then
  write_result "BLOCKED" "codesigning_identity_missing"
  exit 2
fi

if [[ -z "${host_app}" || -z "${extension_bundle}" ]]; then
  write_result "BLOCKED" "signed_host_app_or_extension_missing"
  exit 2
fi

codesign -dv --entitlements :- "${host_app}" >"${artifact_dir}/host-app-entitlements.plist" 2>&1 || true
codesign -dv --entitlements :- "${extension_bundle}" >"${artifact_dir}/extension-entitlements.plist" 2>&1 || true

if ! grep -q 'com.apple.developer.networking.networkextension' \
  "${artifact_dir}/extension-entitlements.plist"; then
  write_result "BLOCKED" "networkextension_entitlement_missing"
  exit 2
fi

cat >"${artifact_dir}/README.md" <<EOF
# macOS NetworkExtension System-Wide Proof

This artifact reached macOS signing/entitlement inspection, but the runtime
Packet Tunnel proof harness is not implemented in this repository yet.

The artifact is intentionally BLOCKED and must not be counted as Phase D PASS.
EOF

write_result "BLOCKED" "packet_tunnel_runtime_harness_not_implemented"
exit 2
